//! Blind HTTPS/WebSocket Relay hub (`/v1/relay`, `US-024`, `US-025`, `US-027`, `WP-S1-01`).
//!
//! Enforces strict opaque forwarding (`0x01` -> `0x02` stamping verified `src_pubkey`), bounded
//! `mpsc::channel(256)` queues with non-blocking `try_send()` drop-tail, per-node `20 Mbps`
//! rate limiting, and `<= 2048 B` frame bounds.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use mesh_core::defaults::{MAX_FRAME_SIZE, RELAY_QUEUE_CAPACITY};
use mesh_core::{NodeId, PublicKey};
use mesh_proto::relay::{RelayFrame, RelayNoticeCode};
use mesh_store::ControlStore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::rate_limit::TokenBucket;

/// Registered `/v1/relay` connection handle passed to the socket pump task.
#[derive(Debug)]
pub struct RelaySessionHandle {
    /// Authenticated node UUID.
    pub node_id: NodeId,
    /// Authenticated WireGuard static Curve25519 public key.
    pub pubkey: PublicKey,
    /// Monotonic session sequence number preventing stale teardown races.
    pub session_seq: u64,
    /// Bounded outbound binary WebSocket frame queue (`capacity = 256`).
    pub rx: mpsc::Receiver<Bytes>,
    /// Cancellation token fired on replacement, revocation, or graceful shutdown.
    pub cancel: CancellationToken,
}

const MAX_TRACKED_NODE_BYTE_STATS: usize = 10_000;
const THROTTLE_NOTICE_COOLDOWN_MS: u64 = 200;

#[derive(Debug)]
struct RelayPeerSession {
    pubkey: PublicKey,
    session_seq: u64,
    tx: mpsc::Sender<Bytes>,
    cancel: CancellationToken,
    tx_bucket: TokenBucket,
    last_throttle_notice_ms: u64,
}

/// Outcome returned when processing an inbound WebSocket binary frame from a connected node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayForwardOutcome {
    /// Packet forwarded to connected destination queue (or keepalive processed).
    Forwarded,
    /// Destination peer offline or destination queue full (`try_send` drop-tail).
    Dropped,
    /// Sender exceeded `20 Mbps` or global relay cap; `ControlNotice::Throttled` emitted.
    Throttled,
    /// Malformed or oversized frame (`> 2048 B`), or source revoked — caller closes WebSocket.
    Disconnect,
}

/// Thread-safe Blind Relay session router with zero shared blocking queues across peers (`US-025 AC6`).
#[derive(Debug)]
pub struct RelayHub {
    store: Arc<ControlStore>,
    per_node_bps: u64,
    global_bucket: Mutex<TokenBucket>,
    next_seq: AtomicU64,
    state: Mutex<RelayRouterState>,
    metrics: RelayMetrics,
}

#[derive(Debug, Default)]
struct RelayRouterState {
    by_node_id: HashMap<NodeId, RelayPeerSession>,
    pubkey_index: HashMap<[u8; 32], NodeId>,
    forwarded_bytes_by_node: HashMap<NodeId, u64>,
}

#[derive(Debug, Default)]
struct RelayMetrics {
    forwarded_bytes_total: AtomicU64,
    forwarded_packets_total: AtomicU64,
    dropped_packets_total: AtomicU64,
    dropped_dest_offline_total: AtomicU64,
    dropped_dest_queue_full_total: AtomicU64,
    dropped_oversized_total: AtomicU64,
    dropped_unauthenticated_total: AtomicU64,
    throttled_packets_total: AtomicU64,
    throttled_bytes_per_node_total: AtomicU64,
    throttled_bytes_global_total: AtomicU64,
}

/// Snapshot of Blind Relay counters exported via `/metrics` and `alert_worker`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayMetricsSnapshot {
    /// Active concurrent `/v1/relay` WebSocket connections.
    pub active_sessions: usize,
    /// Total forwarded payload bytes.
    pub forwarded_bytes_total: u64,
    /// Total forwarded frames.
    pub forwarded_packets_total: u64,
    /// Total tail-dropped or rejected frames across all reasons.
    pub dropped_packets_total: u64,
    /// Frames dropped because destination peer is offline or revoked (`reason="dest_offline"`).
    pub dropped_dest_offline_total: u64,
    /// Frames dropped because destination queue (`256`) was full (`reason="dest_queue_full"`).
    pub dropped_dest_queue_full_total: u64,
    /// Frames dropped because wire length exceeded `MAX_FRAME_SIZE` (`reason="oversized"`).
    pub dropped_oversized_total: u64,
    /// Frames dropped due to unregistered or revoked source (`reason="unauthenticated"`).
    pub dropped_unauthenticated_total: u64,
    /// Total sender frames rejected by `20 Mbps` or global cap.
    pub throttled_packets_total: u64,
    /// Total payload bytes throttled by per-node `20 Mbps` bucket (`scope="per_node"`).
    pub throttled_bytes_per_node_total: u64,
    /// Total payload bytes throttled by global VPS cap (`scope="global"`).
    pub throttled_bytes_global_total: u64,
}

impl RelayHub {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "relay_hub:ready"
    }

    /// Constructs a new [`RelayHub`] with per-node and global throughput caps.
    #[must_use]
    pub fn new(store: Arc<ControlStore>, per_node_bps: u64, global_bps: u64) -> Self {
        let now_ms = store.clock().now_unix_ms();
        let safe_per_node_bps = per_node_bps.max(MAX_FRAME_SIZE as u64);
        let safe_global_bps = global_bps.max(MAX_FRAME_SIZE as u64);
        let global_burst = (safe_global_bps / 4).max(MAX_FRAME_SIZE as u64);
        Self {
            store,
            per_node_bps: safe_per_node_bps,
            global_bucket: Mutex::new(TokenBucket::new(global_burst, safe_global_bps, now_ms)),
            next_seq: AtomicU64::new(1),
            state: Mutex::new(RelayRouterState::default()),
            metrics: RelayMetrics::default(),
        }
    }

    /// Registers a relay WebSocket session for `node_id` / `pubkey`, replacing & closing any prior session.
    pub fn register_session(
        &self,
        node_id: NodeId,
        pubkey: PublicKey,
        now_ms: u64,
    ) -> RelaySessionHandle {
        let session_seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);
        let cancel = CancellationToken::new();
        let per_node_burst = (self.per_node_bps / 4).max(MAX_FRAME_SIZE as u64);

        let session = RelayPeerSession {
            pubkey,
            session_seq,
            tx,
            cancel: cancel.clone(),
            tx_bucket: TokenBucket::new(per_node_burst, self.per_node_bps, now_ms),
            last_throttle_notice_ms: 0,
        };

        if let Ok(mut guard) = self.state.lock() {
            if let Some(prev) = guard.by_node_id.insert(node_id, session) {
                guard.pubkey_index.remove(prev.pubkey.as_bytes());
                prev.cancel.cancel();
            }
            guard.pubkey_index.insert(*pubkey.as_bytes(), node_id);
        }

        RelaySessionHandle {
            node_id,
            pubkey,
            session_seq,
            rx,
            cancel,
        }
    }

    /// Removes session state only if `session_seq` matches the currently active connection.
    pub fn remove_session(&self, node_id: NodeId, session_seq: u64) {
        if let Ok(mut guard) = self.state.lock()
            && let Some(existing) = guard.by_node_id.get(&node_id)
            && existing.session_seq == session_seq
            && let Some(removed) = guard.by_node_id.remove(&node_id)
        {
            guard.pubkey_index.remove(removed.pubkey.as_bytes());
        }
    }

    /// Validates, stamps `src_pubkey`, rate-limits, and forwards an inbound frame strictly via `try_send()`.
    pub fn handle_inbound_frame(
        &self,
        src_node_id: NodeId,
        src_pubkey: PublicKey,
        raw_frame: &[u8],
        now_ms: u64,
    ) -> RelayForwardOutcome {
        if raw_frame.len() > MAX_FRAME_SIZE {
            self.metrics
                .dropped_oversized_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .dropped_packets_total
                .fetch_add(1, Ordering::Relaxed);
            return RelayForwardOutcome::Disconnect;
        }
        if self.store.is_node_revoked_ram(src_node_id) {
            self.metrics
                .dropped_unauthenticated_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .dropped_packets_total
                .fetch_add(1, Ordering::Relaxed);
            return RelayForwardOutcome::Disconnect;
        }
        let Ok(decoded) = RelayFrame::decode(raw_frame) else {
            self.metrics
                .dropped_packets_total
                .fetch_add(1, Ordering::Relaxed);
            return RelayForwardOutcome::Disconnect;
        };

        match decoded {
            RelayFrame::ClientToPeerPacket {
                dst_pubkey,
                ciphertext,
            } => {
                self.forward_client_packet(src_node_id, src_pubkey, dst_pubkey, ciphertext, now_ms)
            }
            RelayFrame::KeepAlive { sent_at_ms } => {
                let sender = self
                    .state
                    .lock()
                    .ok()
                    .and_then(|g| g.by_node_id.get(&src_node_id).map(|s| s.tx.clone()));
                if let Some(src_tx) = sender {
                    if let Ok(encoded) = (RelayFrame::KeepAlive { sent_at_ms }).encode()
                        && let Err(err) = src_tx.try_send(encoded)
                    {
                        tracing::trace!(
                            component = "relay_hub",
                            event = "keepalive_echo_dropped",
                            node_id = %src_node_id,
                            error = %err,
                            "dropped KeepAlive echo on busy or closed relay queue"
                        );
                    }
                    RelayForwardOutcome::Forwarded
                } else {
                    self.metrics
                        .dropped_unauthenticated_total
                        .fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .dropped_packets_total
                        .fetch_add(1, Ordering::Relaxed);
                    RelayForwardOutcome::Disconnect
                }
            }
            RelayFrame::RelayToClientPacket { .. } | RelayFrame::ControlNotice { .. } => {
                self.metrics
                    .dropped_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                RelayForwardOutcome::Disconnect
            }
        }
    }

    fn forward_client_packet(
        &self,
        src_node_id: NodeId,
        src_pubkey: PublicKey,
        dst_pubkey: PublicKey,
        ciphertext: Bytes,
        now_ms: u64,
    ) -> RelayForwardOutcome {
        let payload_len = u64::try_from(ciphertext.len()).unwrap_or(u64::MAX);
        let charge_bytes = payload_len.max(1);

        // Step 1: Reject unregistered sessions and check per-node bucket BEFORE global bucket so an
        // abusive node hitting its own 20 Mbps cap never drains the shared VPS quota (`US-027 AC2`).
        {
            let Ok(mut guard) = self.state.lock() else {
                return RelayForwardOutcome::Dropped;
            };
            let Some(src_sess) = guard.by_node_id.get_mut(&src_node_id) else {
                self.metrics
                    .dropped_unauthenticated_total
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .dropped_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                return RelayForwardOutcome::Disconnect;
            };
            if !src_sess.tx_bucket.can_consume(charge_bytes, now_ms) {
                self.metrics
                    .throttled_bytes_per_node_total
                    .fetch_add(charge_bytes, Ordering::Relaxed);
                self.metrics
                    .throttled_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                send_debounced_throttle_notice(src_sess, now_ms);
                return RelayForwardOutcome::Throttled;
            }
        }

        // Step 2: Check global VPS cap (`US-027 AC3`).
        if let Ok(mut g_bucket) = self.global_bucket.lock()
            && !g_bucket.try_consume(charge_bytes, now_ms)
        {
            self.metrics
                .throttled_bytes_global_total
                .fetch_add(charge_bytes, Ordering::Relaxed);
            self.metrics
                .throttled_packets_total
                .fetch_add(1, Ordering::Relaxed);
            if let Ok(mut guard) = self.state.lock()
                && let Some(src_sess) = guard.by_node_id.get_mut(&src_node_id)
            {
                send_debounced_throttle_notice(src_sess, now_ms);
            }
            return RelayForwardOutcome::Throttled;
        }

        // Step 3: Debit per-node token bucket and resolve active destination session.
        let dst_tx_opt = {
            let Ok(mut guard) = self.state.lock() else {
                return RelayForwardOutcome::Dropped;
            };
            let Some(src_sess) = guard.by_node_id.get_mut(&src_node_id) else {
                self.metrics
                    .dropped_unauthenticated_total
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .dropped_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                return RelayForwardOutcome::Disconnect;
            };
            if !src_sess.tx_bucket.try_consume(charge_bytes, now_ms) {
                self.metrics
                    .throttled_bytes_per_node_total
                    .fetch_add(charge_bytes, Ordering::Relaxed);
                self.metrics
                    .throttled_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                send_debounced_throttle_notice(src_sess, now_ms);
                return RelayForwardOutcome::Throttled;
            }
            guard
                .pubkey_index
                .get(dst_pubkey.as_bytes())
                .copied()
                .filter(|dst_id| !self.store.is_node_revoked_ram(*dst_id))
                .and_then(|dst_id| guard.by_node_id.get(&dst_id).map(|s| s.tx.clone()))
        };

        let Some(dst_tx) = dst_tx_opt else {
            self.metrics
                .dropped_dest_offline_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .dropped_packets_total
                .fetch_add(1, Ordering::Relaxed);
            return RelayForwardOutcome::Dropped;
        };

        let outbound = RelayFrame::RelayToClientPacket {
            src_pubkey,
            ciphertext,
        };
        let Ok(encoded) = outbound.encode() else {
            self.metrics
                .dropped_packets_total
                .fetch_add(1, Ordering::Relaxed);
            return RelayForwardOutcome::Dropped;
        };

        // Non-blocking `try_send` prevents head-of-line blocking across peers (`US-025 AC6`).
        match dst_tx.try_send(encoded) {
            Ok(()) => {
                self.metrics
                    .forwarded_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .forwarded_bytes_total
                    .fetch_add(payload_len, Ordering::Relaxed);
                if let Ok(mut guard) = self.state.lock()
                    && (guard.forwarded_bytes_by_node.contains_key(&src_node_id)
                        || guard.forwarded_bytes_by_node.len() < MAX_TRACKED_NODE_BYTE_STATS)
                {
                    let total = guard
                        .forwarded_bytes_by_node
                        .entry(src_node_id)
                        .or_insert(0);
                    *total = total.saturating_add(payload_len);
                }
                RelayForwardOutcome::Forwarded
            }
            Err(_) => {
                self.metrics
                    .dropped_dest_queue_full_total
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .dropped_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                RelayForwardOutcome::Dropped
            }
        }
    }

    /// Notifies connected peers that server endpoints are migrating cleanly (`US-074 AC4`).
    pub fn broadcast_migrating_notice(&self) {
        let Ok(encoded) = (RelayFrame::ControlNotice {
            code: RelayNoticeCode::ServerMigratingPort,
        })
        .encode() else {
            return;
        };
        if let Ok(guard) = self.state.lock() {
            for session in guard.by_node_id.values() {
                if let Err(err) = session.tx.try_send(encoded.clone()) {
                    tracing::trace!(
                        component = "relay_hub",
                        event = "migrating_notice_dropped",
                        error = %err,
                        "dropped server_migrating_port notice on full relay queue"
                    );
                }
            }
        }
    }

    /// Delivers a revocation/expiry notice if queued and shuts down `node_id`'s relay session.
    pub fn disconnect_node(&self, node_id: NodeId, code: RelayNoticeCode) {
        let removed = self.state.lock().ok().and_then(|mut g| {
            let sess = g.by_node_id.remove(&node_id)?;
            g.pubkey_index.remove(sess.pubkey.as_bytes());
            Some(sess)
        });
        if let Some(sess) = removed {
            if let Ok(encoded) = (RelayFrame::ControlNotice { code }).encode()
                && let Err(err) = sess.tx.try_send(encoded)
            {
                tracing::trace!(
                    component = "relay_hub",
                    event = "disconnect_notice_dropped",
                    error = %err,
                    "dropped disconnect notice on closing relay queue"
                );
            }
            sess.cancel.cancel();
        }
    }

    /// Closes ALL relay sessions immediately (Gate 2 policy (b) & graceful shutdown).
    pub fn close_all_sessions(&self) -> usize {
        let sessions: Vec<RelayPeerSession> = self
            .state
            .lock()
            .map(|mut g| {
                g.pubkey_index.clear();
                g.by_node_id.drain().map(|(_, s)| s).collect()
            })
            .unwrap_or_default();
        let count = sessions.len();
        for s in sessions {
            s.cancel.cancel();
        }
        count
    }

    /// Snapshot of Blind Relay runtime metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> RelayMetricsSnapshot {
        let active_sessions = self.state.lock().map(|g| g.by_node_id.len()).unwrap_or(0);
        RelayMetricsSnapshot {
            active_sessions,
            forwarded_bytes_total: self.metrics.forwarded_bytes_total.load(Ordering::Relaxed),
            forwarded_packets_total: self.metrics.forwarded_packets_total.load(Ordering::Relaxed),
            dropped_packets_total: self.metrics.dropped_packets_total.load(Ordering::Relaxed),
            dropped_dest_offline_total: self
                .metrics
                .dropped_dest_offline_total
                .load(Ordering::Relaxed),
            dropped_dest_queue_full_total: self
                .metrics
                .dropped_dest_queue_full_total
                .load(Ordering::Relaxed),
            dropped_oversized_total: self.metrics.dropped_oversized_total.load(Ordering::Relaxed),
            dropped_unauthenticated_total: self
                .metrics
                .dropped_unauthenticated_total
                .load(Ordering::Relaxed),
            throttled_packets_total: self.metrics.throttled_packets_total.load(Ordering::Relaxed),
            throttled_bytes_per_node_total: self
                .metrics
                .throttled_bytes_per_node_total
                .load(Ordering::Relaxed),
            throttled_bytes_global_total: self
                .metrics
                .throttled_bytes_global_total
                .load(Ordering::Relaxed),
        }
    }

    /// Snapshot of forwarded payload bytes broken down per `NodeId` (`US-048`).
    #[must_use]
    pub fn per_node_forwarded_bytes(&self) -> Vec<(NodeId, u64)> {
        let mut entries: Vec<(NodeId, u64)> = self
            .state
            .lock()
            .map(|g| {
                g.forwarded_bytes_by_node
                    .iter()
                    .map(|(id, bytes)| (*id, *bytes))
                    .collect()
            })
            .unwrap_or_default();
        entries.sort_by_key(|(id, _)| id.to_string());
        entries
    }
}

fn send_debounced_throttle_notice(session: &mut RelayPeerSession, now_ms: u64) {
    if session.last_throttle_notice_ms != 0
        && now_ms.saturating_sub(session.last_throttle_notice_ms) < THROTTLE_NOTICE_COOLDOWN_MS
    {
        return;
    }
    session.last_throttle_notice_ms = now_ms;
    if let Ok(encoded) = (RelayFrame::ControlNotice {
        code: RelayNoticeCode::Throttled,
    })
    .encode()
        && let Err(err) = session.tx.try_send(encoded)
    {
        tracing::trace!(
            component = "relay_hub",
            event = "throttle_notice_dropped",
            error = %err,
            "dropped throttle notice because outbound queue is full"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mesh_core::defaults::RELAY_QUEUE_CAPACITY;
    use mesh_core::{FakeClock, NodeId, PublicKey};
    use mesh_proto::relay::RelayFrame;
    use mesh_store::{ControlStore, ControlStoreConfig};
    use tempfile::TempDir;

    use super::{RelayForwardOutcome, RelayHub};

    #[test]
    fn test_relay_try_send_drops_slow_peer_without_blocking_and_replaces_duplicate_session() {
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
        let hub = RelayHub::new(store, 100_000_000, 200_000_000);

        let src_id = NodeId::new_v7(now);
        let src_pk = PublicKey::from_bytes([0x11_u8; 32]).expect("src pk");
        let slow_id = NodeId::new_v7(now + 1);
        let slow_pk = PublicKey::from_bytes([0x22_u8; 32]).expect("slow pk");

        let old_src = hub.register_session(src_id, src_pk, now);
        let new_src = hub.register_session(src_id, src_pk, now);
        assert!(old_src.cancel.is_cancelled());
        assert!(!new_src.cancel.is_cancelled());

        let mut slow_sess = hub.register_session(slow_id, slow_pk, now);
        let wire_pkt = RelayFrame::ClientToPeerPacket {
            dst_pubkey: slow_pk,
            ciphertext: vec![0xAB_u8; 64].into(),
        }
        .encode()
        .expect("encode");

        // Act: saturate slow destination queue (`256`) then send one more packet
        for _ in 0..RELAY_QUEUE_CAPACITY {
            assert_eq!(
                hub.handle_inbound_frame(src_id, src_pk, &wire_pkt, now),
                RelayForwardOutcome::Forwarded
            );
        }
        let overflow_outcome = hub.handle_inbound_frame(src_id, src_pk, &wire_pkt, now);

        // Assert: drops non-blockingly and rewrites `0x01` -> `0x02` stamping verified `src_pubkey`
        assert_eq!(overflow_outcome, RelayForwardOutcome::Dropped);
        assert_eq!(hub.metrics_snapshot().dropped_packets_total, 1);

        let received = slow_sess.rx.try_recv().expect("queued frame");
        let decoded = RelayFrame::decode(&received).expect("decode relay-to-client");
        assert_eq!(
            decoded,
            RelayFrame::RelayToClientPacket {
                src_pubkey: src_pk,
                ciphertext: vec![0xAB_u8; 64].into(),
            }
        );
    }

    #[test]
    fn test_relay_per_node_20mbps_and_global_fair_throttling_and_split_metrics() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now = 1_762_958_160_000_u64;
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
        // 20 Mbps per node (`2_500_000 B/s`) and 32 Mbps global cap (`4_000_000 B/s`)
        let hub = RelayHub::new(Arc::clone(&store), 2_500_000, 4_000_000);
        let a_id = NodeId::new_v7(now);
        let a_pk = PublicKey::from_bytes([0x31_u8; 32]).expect("a pk");
        let b_id = NodeId::new_v7(now + 1);
        let b_pk = PublicKey::from_bytes([0x32_u8; 32]).expect("b pk");
        let dst_id = NodeId::new_v7(now + 2);
        let dst_pk = PublicKey::from_bytes([0x33_u8; 32]).expect("dst pk");

        let mut a_sess = hub.register_session(a_id, a_pk, now);
        let _b_sess = hub.register_session(b_id, b_pk, now);
        let mut dst_sess = hub.register_session(dst_id, dst_pk, now);

        // Unregistered node rejected before forwarding any byte (`US-027 AC1`)
        let rogue_id = NodeId::new_v7(now + 9);
        let rogue_pk = PublicKey::from_bytes([0x99_u8; 32]).expect("rogue pk");
        let pkt = RelayFrame::ClientToPeerPacket {
            dst_pubkey: dst_pk,
            ciphertext: vec![0xCD_u8; 1_024].into(),
        }
        .encode()
        .expect("encode");
        assert_eq!(
            hub.handle_inbound_frame(rogue_id, rogue_pk, &pkt, now),
            RelayForwardOutcome::Disconnect
        );

        // Saturate node A's 20 Mbps burst bucket without draining B's fair access or overflowing global bucket
        let mut throttled_count = 0_u64;
        for _step in 0..700_u64 {
            while dst_sess.rx.try_recv().is_ok() {}
            let outcome = hub.handle_inbound_frame(a_id, a_pk, &pkt, now);
            if outcome == RelayForwardOutcome::Throttled {
                throttled_count += 1;
            }
        }
        assert!(throttled_count > 0);
        assert_eq!(
            hub.handle_inbound_frame(b_id, b_pk, &pkt, now + 1),
            RelayForwardOutcome::Forwarded
        );

        let snap = hub.metrics_snapshot();
        assert!(snap.throttled_bytes_per_node_total > 0);
        assert_eq!(snap.throttled_bytes_global_total, 0);
        assert_eq!(snap.dropped_unauthenticated_total, 1);
        let notice_bytes = a_sess.rx.try_recv().expect("throttle notice frame");
        assert_eq!(
            RelayFrame::decode(&notice_bytes).expect("decode notice"),
            RelayFrame::ControlNotice {
                code: mesh_proto::relay::RelayNoticeCode::Throttled,
            }
        );

        // Verify global cap saturation hits global metric cleanly while per-node bucket still has capacity
        let global_hub = RelayHub::new(Arc::clone(&store), 2_500_000, 40_000);
        let _ga = global_hub.register_session(a_id, a_pk, now);
        let _gd = global_hub.register_session(dst_id, dst_pk, now);
        let mut global_throttled = 0_u64;
        for _ in 0..25 {
            if global_hub.handle_inbound_frame(a_id, a_pk, &pkt, now)
                == RelayForwardOutcome::Throttled
            {
                global_throttled += 1;
            }
        }
        assert!(global_throttled > 0);
        let g_snap = global_hub.metrics_snapshot();
        assert_eq!(g_snap.throttled_bytes_per_node_total, 0);
        assert!(g_snap.throttled_bytes_global_total > 0);

        // Disconnect revoked node drops session and notices cleanly
        hub.disconnect_node(b_id, mesh_proto::relay::RelayNoticeCode::NodeRevoked);
        assert_eq!(
            hub.handle_inbound_frame(b_id, b_pk, &pkt, now + 5),
            RelayForwardOutcome::Disconnect
        );
    }

    // Traces: US-025 AC2, US-028
    #[test]
    fn test_relay_keepalive_echoes_frame_back_to_sender_and_rejects_unregistered() {
        // Arrange
        let dir = TempDir::new().ok();
        assert!(dir.is_some());
        let Some(dir) = dir else {
            return;
        };
        let now = 1_762_958_200_000_u64;
        let clock = Arc::new(FakeClock::new(now));
        let store = ControlStore::open_with_clock(
            ControlStoreConfig {
                db_path: dir.path().join("control.redb"),
                emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
            },
            "10.100.0.0/24",
            clock,
        );
        assert!(store.is_ok());
        let Ok(store) = store else {
            return;
        };
        let hub = RelayHub::new(Arc::new(store), 100_000_000, 200_000_000);

        let a_id = NodeId::new_v7(now);
        let a_pk_res = PublicKey::from_bytes([0x33_u8; 32]);
        assert!(a_pk_res.is_ok());
        let Ok(a_pk) = a_pk_res else {
            return;
        };
        let mut a_sess = hub.register_session(a_id, a_pk, now);

        let unreg_id = NodeId::new_v7(now + 1);
        let unreg_pk_res = PublicKey::from_bytes([0x44_u8; 32]);
        assert!(unreg_pk_res.is_ok());
        let Ok(unreg_pk) = unreg_pk_res else {
            return;
        };

        let ka_res = (RelayFrame::KeepAlive {
            sent_at_ms: now + 123,
        })
        .encode();
        assert!(ka_res.is_ok());
        let Ok(ka_bytes) = ka_res else {
            return;
        };

        // Act
        let ok_outcome = hub.handle_inbound_frame(a_id, a_pk, &ka_bytes, now + 125);
        let echoed = a_sess.rx.try_recv();
        let reject_outcome = hub.handle_inbound_frame(unreg_id, unreg_pk, &ka_bytes, now + 125);

        // Assert
        assert_eq!(ok_outcome, RelayForwardOutcome::Forwarded);
        assert_eq!(echoed.as_ref().ok(), Some(&ka_bytes));
        assert_eq!(reject_outcome, RelayForwardOutcome::Disconnect);
    }
}
