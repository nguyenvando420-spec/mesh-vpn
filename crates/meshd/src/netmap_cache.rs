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

/// Default offline grace period (hours) before expired WireGuard keys stop offline forwarding (`US-031 AC4`).
pub(crate) const DEFAULT_KEY_EXPIRY_GRACE_HOURS: u64 = 24;

/// Configurable override env var for offline netmap survivability grace hours (`US-033`).
const ENV_OFFLINE_GRACE_HOURS: &str = "MESH_OFFLINE_GRACE_HOURS";

fn configured_offline_grace_hours() -> u64 {
    std::env::var(ENV_OFFLINE_GRACE_HOURS)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&h| h > 0)
        .unwrap_or(DEFAULT_OFFLINE_GRACE_HOURS)
}

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
    /// Optional local node identity key expiry timestamp in UTC milliseconds (`US-031 AC4`).
    #[serde(default)]
    pub(crate) local_key_expires_at_ms: Option<u64>,
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
    pub(crate) fn is_within_offline_grace(&self, now_unix_ms: u64) -> bool {
        let grace_ms = self.offline_grace_hours.saturating_mul(3_600_000);
        self.cached_at_ms.saturating_add(grace_ms) >= now_unix_ms
    }

    /// Returns `true` if `key_expires_at_ms` has not elapsed beyond `key_grace_hours` (`US-031 AC4`).
    #[must_use]
    pub(crate) fn is_key_usable_offline(
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
    pub(crate) fn snapshot_for_offline_recovery(
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

    /// Safely reads and verifies `netmap-cache.json`, logging a `WARN` and returning `None` on
    /// corruption/truncation instead of crashing daemon boot (`US-033 AC3`).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn load_verified_safe(&self) -> Option<NetmapCacheFile> {
        match self.load_verified() {
            Ok(opt) => opt,
            Err(err) => {
                tracing::warn!(
                    component = "meshd.netmap_cache",
                    event = "netmap_cache_rejected",
                    path = %self.path.display(),
                    error = %err,
                    "ignoring corrupted or tampered netmap-cache.json; daemon will enter waiting_for_control state"
                );
                None
            }
        }
    }

    /// Computes canonical SHA-256 including `local_key_expires_at_ms` and persists atomically (`0600`).
    pub(crate) fn save_atomic(
        &self,
        local_udp_port: Port,
        netmap: &NetmapSnapshot,
        cached_at_ms: u64,
        local_key_expires_at_ms: Option<u64>,
    ) -> AppResult<NetmapCacheFile> {
        let grace_hours = configured_offline_grace_hours();
        let port_u16 = local_udp_port.get();
        let digest = compute_payload_sha256(
            port_u16,
            cached_at_ms,
            grace_hours,
            local_key_expires_at_ms,
            netmap,
        )?;
        let record = NetmapCacheFile {
            schema_version: NETMAP_CACHE_SCHEMA_VERSION,
            local_udp_port: port_u16,
            cached_at_ms,
            offline_grace_hours: grace_hours,
            local_key_expires_at_ms,
            payload_sha256: digest,
            netmap: netmap.clone(),
        };
        let encoded = serde_json::to_vec_pretty(&record)
            .map_err(|err| AppError::internal(format!("failed serializing netmap cache: {err}")))?;
        write_private_file_atomic(&self.path, &encoded)?;
        Ok(record)
    }

    /// Re-persists the cached netmap atomically with an updated `local_udp_port` (`US-019`, `US-033`).
    pub(crate) fn update_udp_port(
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
        let updated = self.save_atomic(
            new_port,
            &existing.netmap,
            updated_at_ms,
            existing.local_key_expires_at_ms,
        )?;
        Ok(Some(updated))
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
            .save_atomic(port, &snap, 1_700_000_100_000, None)
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

    // Traces: US-033 AC2/AC3, US-031 AC4
    #[test]
    fn test_netmap_cache_truncated_fails_safely_and_key_expiry_24h_grace_enforced() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let store = NetmapCacheStore::new(dir.path().join("netmap-cache.json"));
        let port = Port::from_u16(51820).expect("port");
        let mut snap = sample_snapshot(7);
        let kp_valid = mesh_crypto::NodeKeypair::generate();
        let kp_expired = mesh_crypto::NodeKeypair::generate();
        let dk = mesh_crypto::DiscoKeypair::generate();
        let cached_at = 1_700_000_000_000u64;
        let peer_exp_at = cached_at + 10_000;

        snap.peers.push(mesh_proto::netmap::PeerEntry {
            node_id: NodeId::from_bytes([1u8; 16]),
            name: mesh_core::NodeName::parse("valid-peer").expect("name"),
            fqdn: "valid-peer.mesh.internal".to_owned(),
            overlay_ip: mesh_core::OverlayIp::from_ipv4(std::net::Ipv4Addr::new(100, 115, 0, 2))
                .expect("ip1"),
            node_pubkey: kp_valid.public_key(),
            disco_pubkey: dk.public_key(),
            endpoints: vec![],
            relay_home: "203.0.113.10:8443".to_owned(),
            key_expires_at_ms: Some(cached_at + 72 * 3_600_000),
            online: true,
        });
        snap.peers.push(mesh_proto::netmap::PeerEntry {
            node_id: NodeId::from_bytes([2u8; 16]),
            name: mesh_core::NodeName::parse("expired-peer").expect("name"),
            fqdn: "expired-peer.mesh.internal".to_owned(),
            overlay_ip: mesh_core::OverlayIp::from_ipv4(std::net::Ipv4Addr::new(100, 115, 0, 3))
                .expect("ip2"),
            node_pubkey: kp_expired.public_key(),
            disco_pubkey: dk.public_key(),
            endpoints: vec![],
            relay_home: "203.0.113.10:8443".to_owned(),
            key_expires_at_ms: Some(peer_exp_at),
            online: true,
        });

        let saved = store
            .save_atomic(port, &snap, cached_at, Some(peer_exp_at))
            .expect("save");
        let new_port = Port::from_u16(51821).expect("new port");
        let rebound = store
            .update_udp_port(new_port, cached_at + 1_000)
            .expect("update port")
            .expect("cache exists");
        assert_eq!(rebound.local_udp_port, 51821);
        assert_eq!(rebound.local_key_expires_at_ms, Some(peer_exp_at));

        // Inside 24h after peer_exp_at -> both peers recoverable offline!
        let within_24h = peer_exp_at + super::DEFAULT_KEY_EXPIRY_GRACE_HOURS * 3_600_000 - 1;
        let recovered_ok = saved
            .snapshot_for_offline_recovery(within_24h, None, super::DEFAULT_KEY_EXPIRY_GRACE_HOURS)
            .expect("within grace");
        assert_eq!(recovered_ok.peers.len(), 2);

        // Past 24h after peer_exp_at -> expired peer filtered out; valid peer preserved!
        let past_24h = peer_exp_at + super::DEFAULT_KEY_EXPIRY_GRACE_HOURS * 3_600_000 + 1;
        let recovered_pruned = saved
            .snapshot_for_offline_recovery(past_24h, None, super::DEFAULT_KEY_EXPIRY_GRACE_HOURS)
            .expect("within netmap grace");
        assert_eq!(recovered_pruned.peers.len(), 1);
        assert_eq!(
            recovered_pruned.peers.first().map(|p| p.name.as_str()),
            Some("valid-peer")
        );

        // Local node expired >24h ago while offline -> stop offline forwarding completely!
        assert!(
            saved
                .snapshot_for_offline_recovery(
                    past_24h,
                    Some(peer_exp_at),
                    super::DEFAULT_KEY_EXPIRY_GRACE_HOURS,
                )
                .is_none()
        );

        // Truncated file returns None safely without panicking
        let raw = std::fs::read_to_string(store.path()).expect("raw");
        let truncated = raw.get(..raw.len() / 2).unwrap_or("{");
        std::fs::write(store.path(), truncated).expect("write truncated");
        assert!(store.load_verified_safe().is_none());
    }
}
