//! Live Control WebSocket subscriber hub (`/v1/netmap/stream`) managing Netmap snapshots,
//! Disco `CallMeMaybe` relays, non-version-bumping heartbeats (`US-009`), and Gate 2 policy (b)
//! connection termination (`US-029`, `US-074`, `WP-S1-01`).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use mesh_core::brand::DEFAULT_DOMAIN_SUFFIX;
use mesh_core::{AppResult, NodeId, PublicKey};
use mesh_proto::control::{ServerControlFrame, TerminationReason};
use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, RelayMap};
use mesh_store::{ControlStore, NodeStatus};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Maximum queued outbound control frames per subscriber stream before backpressure drop.
pub const NETMAP_SUBSCRIBER_QUEUE: usize = 64;

/// Heartbeat interval pushed over active Control WebSockets (`25 seconds`).
pub const CONTROL_HEARTBEAT_INTERVAL_SECS: u64 = 25;

/// Active WebSocket subscription registration handle returned when a node connects.
#[derive(Debug)]
pub struct NetmapSubscription {
    /// Connected node UUID.
    pub node_id: NodeId,
    /// Per-connection session sequence identifier preventing stale disconnects from removing newer streams.
    pub session_seq: u64,
    /// Bounded receiver for outbound [`ServerControlFrame`] messages.
    pub rx: mpsc::Receiver<ServerControlFrame>,
    /// Per-stream cancellation token triggered on revocation, shutdown, or Gate 2(b) re-auth reset.
    pub cancel: CancellationToken,
}

#[derive(Debug)]
struct ActiveSubscriber {
    session_seq: u64,
    tx: mpsc::Sender<ServerControlFrame>,
    cancel: CancellationToken,
    acked_endpoint_version: u64,
    last_seen_at_ms: u64,
}

#[derive(Debug, Clone)]
struct EndpointMapConfig {
    endpoint_version: u64,
    control_tcp_endpoint: String,
    relay_tcp_endpoint: String,
    stun_udp_endpoints: Vec<String>,
    domain_suffix: String,
}

/// Manages active `/v1/netmap/stream` subscribers and monotonic Netmap snapshot broadcasts.
#[derive(Debug)]
pub struct NetmapHub {
    store: Arc<ControlStore>,
    next_seq: AtomicU64,
    subscribers: Mutex<HashMap<NodeId, ActiveSubscriber>>,
    endpoint_cfg: Mutex<EndpointMapConfig>,
}

impl NetmapHub {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "netmap_hub:ready"
    }

    /// Creates a new [`NetmapHub`] backed by [`ControlStore`].
    #[must_use]
    pub fn new(
        store: Arc<ControlStore>,
        control_tcp_endpoint: String,
        relay_tcp_endpoint: String,
        stun_udp_endpoints: Vec<String>,
        domain_suffix: String,
    ) -> Self {
        Self {
            store,
            next_seq: AtomicU64::new(1),
            subscribers: Mutex::new(HashMap::new()),
            endpoint_cfg: Mutex::new(EndpointMapConfig {
                endpoint_version: 1,
                control_tcp_endpoint,
                relay_tcp_endpoint,
                stun_udp_endpoints,
                domain_suffix,
            }),
        }
    }

    /// Registers a new `/v1/netmap/stream` subscriber, cancelling any superseded stream for `node_id`.
    pub fn subscribe(&self, node_id: NodeId, now_unix_ms: u64) -> NetmapSubscription {
        let session_seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(NETMAP_SUBSCRIBER_QUEUE);
        let cancel = CancellationToken::new();

        if let Ok(mut guard) = self.subscribers.lock()
            && let Some(prev) = guard.insert(
                node_id,
                ActiveSubscriber {
                    session_seq,
                    tx,
                    cancel: cancel.clone(),
                    acked_endpoint_version: 0,
                    last_seen_at_ms: now_unix_ms,
                },
            )
        {
            prev.cancel.cancel();
        }

        NetmapSubscription {
            node_id,
            session_seq,
            rx,
            cancel,
        }
    }

    /// Removes subscriber entry only if `session_seq` matches the currently active stream.
    pub fn unsubscribe(&self, node_id: NodeId, session_seq: u64) {
        if let Ok(mut guard) = self.subscribers.lock()
            && let Some(current) = guard.get(&node_id)
            && current.session_seq == session_seq
        {
            guard.remove(&node_id);
        }
    }

    /// Updates node in-memory `last_seen_at_ms` when a heartbeat arrives WITHOUT advancing `netmap_version`
    /// (`US-009`: heartbeats MUST NOT bump `netmap_version`!).
    pub fn record_heartbeat(&self, node_id: NodeId, session_seq: u64, now_unix_ms: u64) {
        if let Ok(mut guard) = self.subscribers.lock()
            && let Some(entry) = guard.get_mut(&node_id)
            && entry.session_seq == session_seq
        {
            entry.last_seen_at_ms = now_unix_ms;
        }
    }

    /// Records a peer's acknowledgment of migrated Control/Relay/STUN endpoints (`US-074 AC7`).
    pub fn record_acked_endpoint_version(&self, node_id: NodeId, acked_version: u64) {
        if let Ok(mut guard) = self.subscribers.lock()
            && let Some(entry) = guard.get_mut(&node_id)
        {
            entry.acked_endpoint_version = entry.acked_endpoint_version.max(acked_version);
        }
    }

    /// Returns `(total_online, acked_current_endpoint_version, current_endpoint_version)` counts for `US-074` cutover checks.
    #[must_use]
    pub fn migration_ack_progress(&self) -> (usize, usize, u64) {
        let current_ep_ver = self
            .endpoint_cfg
            .lock()
            .map(|c| c.endpoint_version)
            .unwrap_or(1);
        let guard = match self.subscribers.lock() {
            Ok(g) => g,
            Err(_) => return (0, 0, current_ep_ver),
        };
        let total = guard.len();
        let acked = guard
            .values()
            .filter(|sub| sub.acked_endpoint_version >= current_ep_ver)
            .count();
        (total, acked, current_ep_ver)
    }

    /// Returns `(online, last_seen_at_ms, acked_endpoint_version)` snapshot for `node_id`.
    #[must_use]
    pub fn node_runtime_info(&self, node_id: NodeId) -> Option<(u64, u64)> {
        self.subscribers.lock().ok().and_then(|g| {
            g.get(&node_id)
                .map(|s| (s.last_seen_at_ms, s.acked_endpoint_version))
        })
    }

    /// Lists names of currently online peers whose `acked_endpoint_version` lags `current_ep_ver`.
    #[must_use]
    pub fn unacked_migration_nodes(&self, nodes: &[mesh_store::StoredNodeRecord]) -> Vec<String> {
        let current_ep_ver = self
            .endpoint_cfg
            .lock()
            .map(|c| c.endpoint_version)
            .unwrap_or(1);
        let Ok(guard) = self.subscribers.lock() else {
            return Vec::new();
        };
        nodes
            .iter()
            .filter(|n| {
                guard
                    .get(&n.node_id)
                    .is_some_and(|s| s.acked_endpoint_version < current_ep_ver)
            })
            .map(|n| n.node_name.clone())
            .collect()
    }

    /// Current `(endpoint_version, control_tcp_endpoint, stun_udp_endpoints)` tuple.
    #[must_use]
    pub fn current_endpoints(&self) -> (u64, String, Vec<String>) {
        self.endpoint_cfg
            .lock()
            .map(|c| {
                (
                    c.endpoint_version,
                    c.control_tcp_endpoint.clone(),
                    c.stun_udp_endpoints.clone(),
                )
            })
            .unwrap_or_else(|_| (1, String::new(), Vec::new()))
    }

    /// Updates advertised Control/Relay/STUN endpoints cleanly (`US-074`) and returns new `endpoint_version`.
    pub fn update_advertised_endpoints(
        &self,
        control_tcp_endpoint: Option<String>,
        relay_tcp_endpoint: Option<String>,
        stun_udp_endpoints: Option<Vec<String>>,
    ) -> u64 {
        if let Ok(mut cfg) = self.endpoint_cfg.lock() {
            cfg.endpoint_version = cfg.endpoint_version.saturating_add(1);
            if let Some(ctrl) = control_tcp_endpoint {
                cfg.control_tcp_endpoint = ctrl;
            }
            if let Some(relay) = relay_tcp_endpoint {
                cfg.relay_tcp_endpoint = relay;
            }
            if let Some(stuns) = stun_udp_endpoints {
                cfg.stun_udp_endpoints = stuns;
            }
            cfg.endpoint_version
        } else {
            1
        }
    }

    /// Builds a consistent [`NetmapSnapshot`] using current `netmap_version` and active RAM online set.
    pub fn build_snapshot(&self, netmap_version: Option<u64>) -> AppResult<NetmapSnapshot> {
        let now_ms = self.store.clock().now_unix_ms();
        let version = netmap_version.unwrap_or_else(|| self.store.current_netmap_version());
        let cidr = self.store.load_overlay_cidr()?;
        let identity = self.store.load_active_identity()?;
        let pin_set = identity.to_pin_set_dto(now_ms);
        let nodes = self.store.list_nodes()?;
        let online_ids: HashSet<NodeId> = self
            .subscribers
            .lock()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default();

        let ep_cfg = self
            .endpoint_cfg
            .lock()
            .map(|c| c.clone())
            .unwrap_or_else(|_| EndpointMapConfig {
                endpoint_version: 1,
                control_tcp_endpoint: String::new(),
                relay_tcp_endpoint: String::new(),
                stun_udp_endpoints: Vec::new(),
                domain_suffix: DEFAULT_DOMAIN_SUFFIX.to_owned(),
            });

        let mut peers = Vec::new();
        for rec in nodes {
            if rec.status != NodeStatus::Active || rec.is_key_expired_at(now_ms) {
                continue;
            }
            if self.store.is_node_revoked_ram(rec.node_id) {
                continue;
            }
            let Some(overlay_ip) = rec.overlay_ip else {
                continue;
            };
            let Ok(node_pubkey) = PublicKey::from_bytes(rec.pubkey) else {
                continue;
            };
            if self.store.is_pubkey_revoked_ram(&node_pubkey) {
                continue;
            }
            let Ok(disco_pubkey) = PublicKey::from_bytes(rec.disco_pubkey) else {
                continue;
            };
            let Ok(name) = mesh_core::NodeName::parse(&rec.node_name) else {
                continue;
            };
            let fqdn = format!("{}.{}", rec.node_name, ep_cfg.domain_suffix);
            let is_online = online_ids.contains(&rec.node_id);
            peers.push(PeerEntry {
                node_id: rec.node_id,
                name,
                fqdn,
                overlay_ip,
                node_pubkey,
                disco_pubkey,
                endpoints: rec.endpoints,
                relay_home: ep_cfg.relay_tcp_endpoint.clone(),
                key_expires_at_ms: rec.key_expires_at_ms,
                online: is_online,
            });
        }

        Ok(NetmapSnapshot {
            netmap_version: version,
            generated_at_ms: now_ms,
            overlay_cidr: cidr,
            domain_suffix: ep_cfg.domain_suffix,
            relay_map: RelayMap {
                endpoint_version: ep_cfg.endpoint_version,
                control_tcp_endpoint: ep_cfg.control_tcp_endpoint,
                relay_tcp_endpoint: ep_cfg.relay_tcp_endpoint,
                stun_udp_endpoints: ep_cfg.stun_udp_endpoints,
            },
            pin_set,
            peers,
        })
    }

    /// Broadcasts a newly persisted [`NetmapSnapshot`] to all currently connected active peers.
    pub fn broadcast_snapshot(&self, netmap_version: u64) -> AppResult<usize> {
        let snapshot = self.build_snapshot(Some(netmap_version))?;
        let now_ms = snapshot.generated_at_ms;
        let frame = ServerControlFrame::NetmapSnapshot {
            sent_at_ms: now_ms,
            netmap: Box::new(snapshot),
        };
        let mut sent = 0_usize;
        if let Ok(guard) = self.subscribers.lock() {
            for sub in guard.values() {
                if sub.tx.try_send(frame.clone()).is_ok() {
                    sent = sent.saturating_add(1);
                }
            }
        }
        Ok(sent)
    }

    /// Relays a bounded Disco `CallMeMaybe` hint directly to `dst_node_id` (`US-021`).
    pub fn relay_call_me_maybe(
        &self,
        src_node_id: NodeId,
        src_node_pubkey: PublicKey,
        dst_node_id: NodeId,
        disco_frame_b64: String,
    ) -> bool {
        let now_ms = self.store.clock().now_unix_ms();
        let Ok(guard) = self.subscribers.lock() else {
            return false;
        };
        let Some(dst) = guard.get(&dst_node_id) else {
            return false;
        };
        dst.tx
            .try_send(ServerControlFrame::CallMeMaybeRelay {
                src_node_id,
                src_node_pubkey,
                disco_frame_b64,
                sent_at_ms: now_ms,
            })
            .is_ok()
    }

    /// Sends application heartbeats to all live subscribers WITHOUT touching `netmap_version` (`US-009`).
    pub fn broadcast_heartbeats(&self, now_unix_ms: u64) -> usize {
        let frame = ServerControlFrame::Heartbeat {
            sent_at_ms: now_unix_ms,
        };
        let mut sent = 0_usize;
        if let Ok(guard) = self.subscribers.lock() {
            for sub in guard.values() {
                if sub.tx.try_send(frame.clone()).is_ok() {
                    sent = sent.saturating_add(1);
                }
            }
        }
        sent
    }

    /// Delivers [`ServerControlFrame::IdentityTerminated`] and disconnects `node_id` (`US-029`, `US-031`).
    pub fn terminate_node_stream(
        &self,
        node_id: NodeId,
        reason: TerminationReason,
        public_msg: &str,
        now_unix_ms: u64,
    ) {
        let sub = self
            .subscribers
            .lock()
            .ok()
            .and_then(|mut g| g.remove(&node_id));
        if let Some(s) = sub {
            if let Err(err) = s.tx.try_send(ServerControlFrame::IdentityTerminated {
                error_kind: reason,
                public_msg: public_msg.to_owned(),
                occurred_at_ms: now_unix_ms,
            }) {
                tracing::debug!(
                    component = "netmap_hub",
                    event = "terminate_frame_dropped",
                    error = %err,
                    "dropping identity_terminated frame on closing subscriber channel"
                );
            }
            s.cancel.cancel();
        }
    }

    /// Enforces **Gate 2 policy (b)**: when dual `EIO` collides with an exhausted version lease,
    /// closes EVERY open peer Control WebSocket stream to force reconnect & full challenge re-auth
    /// without emitting an unpersisted `netmap_version`.
    pub fn close_all_streams_for_reauth(&self) -> usize {
        let drained: Vec<ActiveSubscriber> = self
            .subscribers
            .lock()
            .map(|mut g| g.drain().map(|(_, v)| v).collect())
            .unwrap_or_default();
        let count = drained.len();
        for sub in drained {
            sub.cancel.cancel();
        }
        count
    }

    /// Number of currently connected online control streams (`GET /metrics` & status).
    #[must_use]
    pub fn active_stream_count(&self) -> usize {
        self.subscribers.lock().map(|g| g.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mesh_core::{FakeClock, KeyId, NodeId, NodeName, PublicKey};
    use mesh_proto::control::{ServerControlFrame, TerminationReason};
    use mesh_store::{
        ControlStore, ControlStoreConfig, CreatePreAuthKeyInput, DEFAULT_NODE_KEY_TTL_MS,
        RegisterNodeInput,
    };
    use tempfile::TempDir;

    use super::NetmapHub;

    #[test]
    fn test_heartbeat_never_bumps_netmap_version_and_gate2b_closes_all_streams() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now = 1_762_958_151_000_u64;
        let clock = Arc::new(FakeClock::new(now));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock,
            )
            .expect("open store"),
        );

        let token_hash = [0x12_u8; 32];
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now),
                    token_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: None,
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now,
                },
                "admin",
            )
            .expect("create key");
        let (reg, ver_after_reg) = store
            .register_node(&RegisterNodeInput {
                pubkey: PublicKey::from_bytes([0x31_u8; 32]).expect("pk"),
                disco_pubkey: PublicKey::from_bytes([0x32_u8; 32]).expect("dpk"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("laptop").expect("name"),
                preauth_token_hash: token_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "darwin/arm64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now,
            })
            .expect("register");

        let hub = NetmapHub::new(
            store.clone(),
            "203.0.113.10:8443".to_owned(),
            "203.0.113.10:8443".to_owned(),
            vec!["203.0.113.10:3478".to_owned()],
            "mesh.internal".to_owned(),
        );
        let mut sub1 = hub.subscribe(reg.record.node_id, now);
        let peer2_id = NodeId::new_v7(now + 1);
        let sub2 = hub.subscribe(peer2_id, now);

        // Act: heartbeat must NOT advance `netmap_version`
        hub.record_heartbeat(reg.record.node_id, sub1.session_seq, now + 25_000);
        let sent_hb = hub.broadcast_heartbeats(now + 25_000);
        assert_eq!(sent_hb, 2);
        assert_eq!(store.current_netmap_version(), ver_after_reg);

        let hb_frame = sub1.rx.try_recv().expect("heartbeat frame");
        assert!(matches!(hb_frame, ServerControlFrame::Heartbeat { .. }));

        // Gate 2 policy (b): close all open streams cleanly
        let closed = hub.close_all_streams_for_reauth();
        assert_eq!(closed, 2);
        assert!(sub1.cancel.is_cancelled());
        assert!(sub2.cancel.is_cancelled());

        hub.terminate_node_stream(
            reg.record.node_id,
            TerminationReason::NodeRevoked,
            "revoked",
            now,
        );
    }

    #[test]
    fn test_build_snapshot_excludes_ram_revoked_and_clock_expired_nodes() {
        // Arrange: two nodes remain `Active` in `redb`; one revoked via RAM/EmergencySlot on EIO,
        // and the second past its `key_expires_at_ms` TTL (`HR-W21-12`).
        let dir = TempDir::new().expect("tempdir");
        let now = 1_762_958_151_000_u64;
        let clock = Arc::new(FakeClock::new(now));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                Arc::clone(&clock) as Arc<dyn mesh_core::Clock>,
            )
            .expect("open store"),
        );
        store
            .ensure_or_init_identity(&["203.0.113.10".to_owned()], 365)
            .expect("init id");

        let token_hash = [0x44_u8; 32];
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now),
                    token_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: true,
                    max_uses: Some(5),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now,
                },
                "admin",
            )
            .expect("create key");

        let (reg_healthy, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: PublicKey::from_bytes([0x51_u8; 32]).expect("pk1"),
                disco_pubkey: PublicKey::from_bytes([0x52_u8; 32]).expect("dpk1"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("healthy-node").expect("name1"),
                preauth_token_hash: token_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: 86_400_000,
                now_unix_ms: now,
            })
            .expect("register healthy");
        let (reg_degraded_rev, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: PublicKey::from_bytes([0x53_u8; 32]).expect("pk2"),
                disco_pubkey: PublicKey::from_bytes([0x54_u8; 32]).expect("dpk2"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("degraded-rev-node").expect("name2"),
                preauth_token_hash: token_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: 86_400_000,
                now_unix_ms: now,
            })
            .expect("register degraded rev");
        let (_reg_short_ttl, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: PublicKey::from_bytes([0x55_u8; 32]).expect("pk3"),
                disco_pubkey: PublicKey::from_bytes([0x56_u8; 32]).expect("dpk3"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("ttl-expired-node").expect("name3"),
                preauth_token_hash: token_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: 10_000,
                now_unix_ms: now,
            })
            .expect("register ttl expired");

        // Act: revoke node 2 while redb write fails (stays Active in redb, blocked in RAM) and advance
        // clock past node 3's key_expires_at_ms without running DB sweeper yet.
        store.inject_redb_failure(false, true);
        let rev_res = store
            .revoke_node(reg_degraded_rev.record.node_id, "admin")
            .expect("emergency revoke");
        assert_eq!(
            rev_res.persistence_tier,
            mesh_proto::admin_ipc::PersistenceTier::EmergencySlot
        );
        store.inject_redb_failure(false, false);
        clock.advance(20_000);

        let hub = NetmapHub::new(
            store,
            "203.0.113.10:8443".to_owned(),
            "203.0.113.10:8443".to_owned(),
            vec!["203.0.113.10:3478".to_owned()],
            "mesh.internal".to_owned(),
        );
        let snapshot = hub.build_snapshot(None).expect("snapshot");

        // Assert: ONLY healthy-node remains visible to connected peers
        let peer_ids: Vec<_> = snapshot.peers.iter().map(|p| p.node_id).collect();
        assert_eq!(peer_ids, vec![reg_healthy.record.node_id]);
    }
}
