//! Signed Netmap offline cache (`netmap-cache.json`) with SHA-256 tamper rejection (`US-033`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use mesh_core::{AppError, AppResult, ErrorKind, Port};
use mesh_crypto::{ct_eq_bytes, sha256_hex};
use mesh_proto::netmap::NetmapSnapshot;

use crate::config::write_private_file_atomic;

/// Current schema version for `netmap-cache.json`.
pub const NETMAP_CACHE_SCHEMA_VERSION: u16 = 1;

/// Default offline P2P survivability grace window in hours (`US-033 AC2`).
pub const DEFAULT_OFFLINE_GRACE_HOURS: u64 = 168;

/// Default offline grace period (hours) before expired WireGuard keys stop offline forwarding (`US-031 AC4`).
pub const DEFAULT_KEY_EXPIRY_GRACE_HOURS: u64 = 24;

/// Configurable override env var for offline netmap survivability grace hours (`US-033`).
const ENV_OFFLINE_GRACE_HOURS: &str = "MESH_OFFLINE_GRACE_HOURS";

/// Resolves offline survivability grace hours from `MESH_OFFLINE_GRACE_HOURS` or `168 h` default.
#[must_use]
pub fn configured_offline_grace_hours() -> u64 {
    std::env::var(ENV_OFFLINE_GRACE_HOURS)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&h| h > 0)
        .unwrap_or(DEFAULT_OFFLINE_GRACE_HOURS)
}

/// Offline cache payload written atomically with a canonical SHA-256 checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetmapCacheFile {
    /// On-disk schema version (`1`).
    pub schema_version: u16,
    /// Bound `MagicSocket` UDP port persisted for roaming continuity (`US-035`).
    pub local_udp_port: u16,
    /// UTC timestamp when the snapshot was cached in milliseconds.
    pub cached_at_ms: u64,
    /// Configured offline survivability grace window in hours.
    pub offline_grace_hours: u64,
    /// Optional local node identity key expiry timestamp in UTC milliseconds (`US-031 AC4`).
    #[serde(default)]
    pub local_key_expires_at_ms: Option<u64>,
    /// Lowercase SHA-256 hex digest over canonical serialized snapshot metadata.
    pub payload_sha256: String,
    /// Last validated network map received over verified Control TLS.
    pub netmap: NetmapSnapshot,
}

impl NetmapCacheFile {
    /// Builds a signed [`NetmapCacheFile`] using [`configured_offline_grace_hours`].
    pub fn new_signed(
        local_udp_port: Port,
        netmap: NetmapSnapshot,
        cached_at_ms: u64,
        local_key_expires_at_ms: Option<u64>,
    ) -> AppResult<Self> {
        let grace_hours = configured_offline_grace_hours();
        let port_u16 = local_udp_port.get();
        let digest = compute_payload_sha256(
            port_u16,
            cached_at_ms,
            grace_hours,
            local_key_expires_at_ms,
            &netmap,
        )?;
        Ok(Self {
            schema_version: NETMAP_CACHE_SCHEMA_VERSION,
            local_udp_port: port_u16,
            cached_at_ms,
            offline_grace_hours: grace_hours,
            local_key_expires_at_ms,
            payload_sha256: digest,
            netmap,
        })
    }

    /// Recomputes `payload_sha256` after an authorized local field adjustment such as UDP port rebind.
    pub fn with_updated_udp_port(mut self, new_port: Port, updated_at_ms: u64) -> AppResult<Self> {
        let port_u16 = new_port.get();
        if self.local_udp_port == port_u16 {
            return Ok(self);
        }
        let digest = compute_payload_sha256(
            port_u16,
            updated_at_ms,
            self.offline_grace_hours,
            self.local_key_expires_at_ms,
            &self.netmap,
        )?;
        self.local_udp_port = port_u16;
        self.cached_at_ms = updated_at_ms;
        self.payload_sha256 = digest;
        Ok(self)
    }

    /// Verifies `payload_sha256` against canonical snapshot contents using constant-time equality.
    pub fn verify_integrity(&self) -> AppResult<()> {
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
            self.local_key_expires_at_ms,
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
    pub fn is_within_offline_grace(&self, now_unix_ms: u64) -> bool {
        let grace_ms = self.offline_grace_hours.saturating_mul(3_600_000);
        self.cached_at_ms.saturating_add(grace_ms) >= now_unix_ms
    }

    /// Returns `true` if `key_expires_at_ms` has not elapsed beyond `key_grace_hours` (`US-031 AC4`).
    #[must_use]
    pub fn is_key_usable_offline(
        key_expires_at_ms: Option<u64>,
        now_unix_ms: u64,
        key_grace_hours: u64,
    ) -> bool {
        let Some(exp_ms) = key_expires_at_ms else {
            return true;
        };
        let grace_ms = key_grace_hours.saturating_mul(3_600_000);
        exp_ms.saturating_add(grace_ms) >= now_unix_ms
    }

    /// Extracts an offline-recoverable snapshot enforcing both snapshot grace (`168 h`) and peer
    /// key-expiry grace (`24 h` per `US-031 AC4`), returning `None` if cache grace expired.
    #[must_use]
    pub fn snapshot_for_offline_recovery(
        &self,
        now_unix_ms: u64,
        local_key_expires_at_ms: Option<u64>,
        key_grace_hours: u64,
    ) -> Option<NetmapSnapshot> {
        if !self.is_within_offline_grace(now_unix_ms) {
            return None;
        }
        if !Self::is_key_usable_offline(local_key_expires_at_ms, now_unix_ms, key_grace_hours) {
            return None;
        }
        let mut filtered = self.netmap.clone();
        filtered.peers.retain(|p| {
            Self::is_key_usable_offline(p.key_expires_at_ms, now_unix_ms, key_grace_hours)
        });
        Some(filtered)
    }
}

#[derive(Serialize)]
struct CanonicalCacheDigestView<'a> {
    schema_version: u16,
    local_udp_port: u16,
    cached_at_ms: u64,
    offline_grace_hours: u64,
    local_key_expires_at_ms: Option<u64>,
    netmap: &'a NetmapSnapshot,
}

fn compute_payload_sha256(
    local_udp_port: u16,
    cached_at_ms: u64,
    offline_grace_hours: u64,
    local_key_expires_at_ms: Option<u64>,
    netmap: &NetmapSnapshot,
) -> AppResult<String> {
    let view = CanonicalCacheDigestView {
        schema_version: NETMAP_CACHE_SCHEMA_VERSION,
        local_udp_port,
        cached_at_ms,
        offline_grace_hours,
        local_key_expires_at_ms,
        netmap,
    };
    let canonical = serde_json::to_vec(&view).map_err(|err| {
        AppError::internal(format!("failed canonicalizing netmap cache digest: {err}"))
    })?;
    Ok(sha256_hex(&canonical))
}

/// Fail-closed file persistence manager for `netmap-cache.json`.
#[derive(Debug, Clone)]
pub struct NetmapCacheStore {
    path: PathBuf,
}

impl NetmapCacheStore {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub const fn status_label() -> &'static str {
        "netmap_cache:ready"
    }

    /// Creates a store targeting `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the filesystem path to `netmap-cache.json`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads and verifies `netmap-cache.json`; returns `Ok(None)` only when absent.
    pub fn load_verified(&self) -> AppResult<Option<NetmapCacheFile>> {
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

    /// Safely reads and verifies `netmap-cache.json`, logging a `WARN` and returning `None` on
    /// corruption/truncation instead of crashing boot (`US-033 AC3`).
    #[must_use]
    pub fn load_verified_safe(&self) -> Option<NetmapCacheFile> {
        match self.load_verified() {
            Ok(opt) => opt,
            Err(err) => {
                tracing::warn!(
                    component = "mesh_client.netmap_cache",
                    event = "netmap_cache_rejected",
                    path = %self.path.display(),
                    error = %err,
                    "ignoring corrupted or tampered netmap-cache.json; entering waiting_for_control state"
                );
                None
            }
        }
    }

    /// Writes a pre-signed [`NetmapCacheFile`] atomically (`0600`) after re-verifying integrity.
    pub fn write_verified(&self, record: &NetmapCacheFile) -> AppResult<()> {
        record.verify_integrity()?;
        let encoded = serde_json::to_vec_pretty(record)
            .map_err(|err| AppError::internal(format!("failed serializing netmap cache: {err}")))?;
        write_private_file_atomic(&self.path, &encoded)
    }

    /// Computes canonical SHA-256 including `local_key_expires_at_ms` and persists atomically (`0600`).
    pub fn save_atomic(
        &self,
        local_udp_port: Port,
        netmap: &NetmapSnapshot,
        cached_at_ms: u64,
        local_key_expires_at_ms: Option<u64>,
    ) -> AppResult<NetmapCacheFile> {
        let record = NetmapCacheFile::new_signed(
            local_udp_port,
            netmap.clone(),
            cached_at_ms,
            local_key_expires_at_ms,
        )?;
        self.write_verified(&record)?;
        Ok(record)
    }

    /// Re-persists the cached netmap atomically with an updated `local_udp_port` (`US-019`, `US-033`).
    pub fn update_udp_port(
        &self,
        new_port: Port,
        updated_at_ms: u64,
    ) -> AppResult<Option<NetmapCacheFile>> {
        let Some(existing) = self.load_verified()? else {
            return Ok(None);
        };
        if existing.local_udp_port == new_port.get() {
            return Ok(Some(existing));
        }
        let updated = existing.with_updated_udp_port(new_port, updated_at_ms)?;
        self.write_verified(&updated)?;
        Ok(Some(updated))
    }

    /// Deletes `netmap-cache.json` cleanly when leaving the mesh (`mesh down` / revoke).
    pub fn clear(&self) -> AppResult<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(AppError::internal(format!(
                "failed removing netmap cache {}: {err}",
                self.path.display()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::Ipv4Addr;

    use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, Port, PublicKey, SpkiPin};
    use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};
    use tempfile::tempdir;

    use super::{DEFAULT_KEY_EXPIRY_GRACE_HOURS, NetmapCacheStore};

    fn sample_netmap(peer_exp: Option<u64>) -> NetmapSnapshot {
        let cidr = OverlayCidr::parse("100.115.0.0/16").expect("cidr");
        let pin = SpkiPin::parse(&format!("sha256:{}", "a".repeat(64))).expect("pin");
        NetmapSnapshot {
            netmap_version: 5,
            generated_at_ms: 1_700_000_000_000,
            overlay_cidr: cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 2,
                control_tcp_endpoint: "127.0.0.1:8443".to_owned(),
                relay_tcp_endpoint: "127.0.0.1:8443".to_owned(),
                stun_udp_endpoints: vec!["127.0.0.1:3478".to_owned()],
            },
            pin_set: PinSetDto {
                active_pin: pin,
                next_pin: None,
            },
            peers: vec![PeerEntry {
                node_id: NodeId::new_v7(1_700_000_000_000),
                name: NodeName::parse("laptop").expect("name"),
                fqdn: "laptop.mesh.internal".to_owned(),
                overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 2)).expect("ip"),
                node_pubkey: PublicKey::from_bytes([7u8; 32]).expect("pubkey"),
                disco_pubkey: PublicKey::from_bytes([8u8; 32]).expect("pubkey"),
                endpoints: Vec::new(),
                relay_home: "127.0.0.1:8443".to_owned(),
                key_expires_at_ms: peer_exp,
                online: true,
            }],
        }
    }

    #[test]
    fn test_netmap_cache_tamper_rejected_and_key_expiry_grace_enforced() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let store = NetmapCacheStore::new(dir.path().join("netmap-cache.json"));
        let port = Port::from_u16(51820).expect("port");
        let exp_ms = 1_000_000_u64;
        let snap = sample_netmap(Some(exp_ms));

        // Act
        let saved = store
            .save_atomic(port, &snap, exp_ms, Some(exp_ms + 72_000_000))
            .expect("save");
        let within_grace = saved.snapshot_for_offline_recovery(
            exp_ms + DEFAULT_KEY_EXPIRY_GRACE_HOURS * 3_600_000,
            None,
            DEFAULT_KEY_EXPIRY_GRACE_HOURS,
        );
        let past_grace = saved.snapshot_for_offline_recovery(
            exp_ms + DEFAULT_KEY_EXPIRY_GRACE_HOURS * 3_600_000 + 1,
            None,
            DEFAULT_KEY_EXPIRY_GRACE_HOURS,
        );

        let raw = fs::read_to_string(store.path()).expect("read");
        fs::write(store.path(), raw.replacen("100.115.0.2", "100.115.0.99", 1)).expect("tamper");
        let tampered = store.load_verified_safe();

        // Assert
        assert_eq!(within_grace.expect("within grace").peers.len(), 1);
        assert_eq!(past_grace.expect("past peer grace").peers.len(), 0);
        assert!(tampered.is_none());
    }
}
