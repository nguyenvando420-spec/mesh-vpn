//! Signed Netmap offline cache (`netmap-cache.json`) with SHA-256 tamper rejection (`US-033`).

use std::fs;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use mesh_core::{AppError, AppResult, ErrorKind, Port};
use mesh_crypto::{ct_eq_bytes, sha256_hex};
use mesh_proto::netmap::NetmapSnapshot;

use crate::config::write_private_file_atomic;

/// Current schema version for `netmap-cache.json`.
pub(crate) const NETMAP_CACHE_SCHEMA_VERSION: u16 = 1;

/// Default offline P2P survivability grace window in hours (`US-033 AC2`).
pub(crate) const DEFAULT_OFFLINE_GRACE_HOURS: u64 = 168;

/// Offline cache payload written atomically with a canonical SHA-256 checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetmapCacheFile {
    /// On-disk schema version (`1`).
    pub(crate) schema_version: u16,
    /// Bound `MagicSocket` UDP port persisted for roaming continuity (`US-035`).
    pub(crate) local_udp_port: u16,
    /// UTC timestamp when the snapshot was cached in milliseconds.
    pub(crate) cached_at_ms: u64,
    /// Configured offline survivability grace window in hours.
    pub(crate) offline_grace_hours: u64,
    /// Lowercase SHA-256 hex digest over canonical serialized snapshot metadata.
    pub(crate) payload_sha256: String,
    /// Last validated network map received over verified Control TLS.
    pub(crate) netmap: NetmapSnapshot,
}

impl NetmapCacheFile {
    /// Verifies `payload_sha256` against canonical snapshot contents using constant-time equality.
    pub(crate) fn verify_integrity(&self) -> AppResult<()> {
        if self.schema_version != NETMAP_CACHE_SCHEMA_VERSION {
            return Err(AppError::new(
                ErrorKind::InvalidArgument,
                format!(
                    "unsupported netmap cache schema_version {}",
                    self.schema_version
                ),
            ));
        }
        let expected = compute_payload_sha256(
            self.local_udp_port,
            self.cached_at_ms,
            self.offline_grace_hours,
            &self.netmap,
        )?;
        let actual_lower = self.payload_sha256.trim().to_ascii_lowercase();
        if actual_lower.len() != 64 || !ct_eq_bytes(actual_lower.as_bytes(), expected.as_bytes()) {
            return Err(AppError::new(
                ErrorKind::InvalidArgument,
                "netmap-cache.json SHA-256 integrity check failed",
            ));
        }
        Ok(())
    }

    /// Returns `true` while `now_unix_ms` remains inside `cached_at_ms + offline_grace_hours`.
    #[must_use]
    pub(crate) fn is_within_offline_grace(&self, now_unix_ms: u64) -> bool {
        let grace_ms = self.offline_grace_hours.saturating_mul(3_600_000);
        self.cached_at_ms.saturating_add(grace_ms) >= now_unix_ms
    }
}

#[derive(Serialize)]
struct CanonicalCacheDigestView<'a> {
    schema_version: u16,
    local_udp_port: u16,
    cached_at_ms: u64,
    offline_grace_hours: u64,
    netmap: &'a NetmapSnapshot,
}

fn compute_payload_sha256(
    local_udp_port: u16,
    cached_at_ms: u64,
    offline_grace_hours: u64,
    netmap: &NetmapSnapshot,
) -> AppResult<String> {
    let view = CanonicalCacheDigestView {
        schema_version: NETMAP_CACHE_SCHEMA_VERSION,
        local_udp_port,
        cached_at_ms,
        offline_grace_hours,
        netmap,
    };
    let canonical = serde_json::to_vec(&view).map_err(|err| {
        AppError::internal(format!("failed canonicalizing netmap cache digest: {err}"))
    })?;
    Ok(sha256_hex(&canonical))
}

/// Fail-closed persistence manager for `netmap-cache.json`.
#[derive(Debug, Clone)]
pub(crate) struct NetmapCacheStore {
    path: PathBuf,
}

impl NetmapCacheStore {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "netmap_cache:ready"
    }

    /// Creates a store targeting `path`.
    #[must_use]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the filesystem path to `netmap-cache.json`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Reads and verifies `netmap-cache.json`; returns `Ok(None)` only when absent.
    pub(crate) fn load_verified(&self) -> AppResult<Option<NetmapCacheFile>> {
        match fs::read_to_string(&self.path) {
            Ok(raw) => {
                let parsed: NetmapCacheFile = serde_json::from_str(&raw).map_err(|err| {
                    AppError::new(
                        ErrorKind::InvalidArgument,
                        format!("corrupt netmap cache JSON {}: {err}", self.path.display()),
                    )
                })?;
                parsed.verify_integrity()?;
                Ok(Some(parsed))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(AppError::internal(format!(
                "failed reading netmap cache {}: {err}",
                self.path.display()
            ))),
        }
    }

    /// Computes canonical SHA-256 and atomically persists `netmap-cache.json` (`0600`).
    pub(crate) fn save_atomic(
        &self,
        local_udp_port: Port,
        netmap: &NetmapSnapshot,
        cached_at_ms: u64,
    ) -> AppResult<NetmapCacheFile> {
        let port_u16 = local_udp_port.get();
        let digest =
            compute_payload_sha256(port_u16, cached_at_ms, DEFAULT_OFFLINE_GRACE_HOURS, netmap)?;
        let record = NetmapCacheFile {
            schema_version: NETMAP_CACHE_SCHEMA_VERSION,
            local_udp_port: port_u16,
            cached_at_ms,
            offline_grace_hours: DEFAULT_OFFLINE_GRACE_HOURS,
            payload_sha256: digest,
            netmap: netmap.clone(),
        };
        let encoded = serde_json::to_vec_pretty(&record)
            .map_err(|err| AppError::internal(format!("failed serializing netmap cache: {err}")))?;
        write_private_file_atomic(&self.path, &encoded)?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use mesh_core::{ErrorKind, NodeId, Port, SpkiPin};
    use mesh_proto::netmap::{NetmapSnapshot, PinSetDto, RelayMap};
    use tempfile::tempdir;

    use super::{DEFAULT_OFFLINE_GRACE_HOURS, NetmapCacheStore};

    fn sample_snapshot(ver: u64) -> NetmapSnapshot {
        NetmapSnapshot {
            netmap_version: ver,
            generated_at_ms: 1_700_000_000_000,
            overlay_cidr: "100.115.0.0/16".parse().expect("cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: vec!["203.0.113.10:3479".to_owned()],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([7; 32]),
                next_pin: None,
            },
            peers: Vec::new(),
        }
    }

    #[test]
    fn test_netmap_cache_roundtrip_and_tamper_rejection() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let store = NetmapCacheStore::new(dir.path().join("netmap-cache.json"));
        let port = Port::from_u16(41641u16).expect("port");
        let snap = sample_snapshot(42);
        let _unused = NodeId::new_v7(1_700_000_000_000);

        // Act
        let saved = store
            .save_atomic(port, &snap, 1_700_000_100_000)
            .expect("save cache");
        let loaded = store
            .load_verified()
            .expect("load verified")
            .expect("some cache");

        let mut tampered_json = std::fs::read_to_string(store.path()).expect("read raw");
        tampered_json = tampered_json.replace("41641", "41642");
        std::fs::write(store.path(), tampered_json).expect("write tampered");
        let tamper_err = store.load_verified();

        // Assert
        assert_eq!(loaded, saved);
        assert!(loaded.is_within_offline_grace(1_700_000_100_000 + 1000));
        assert!(!loaded.is_within_offline_grace(
            1_700_000_100_000 + DEFAULT_OFFLINE_GRACE_HOURS * 3_600_000 + 1
        ));
        assert!(matches!(
            tamper_err,
            Err(err) if err.kind() == ErrorKind::InvalidArgument
        ));
    }
}
