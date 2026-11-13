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

#[derive(Debug)]
struct RelayPeerSession {
    pubkey: PublicKey,
    session_seq: u64,
    tx: mpsc::Sender<Bytes>,
    cancel: CancellationToken,
    tx_bucket: TokenBucket,
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
}

#[derive(Debug, Default)]
struct RelayMetrics {
    forwarded_bytes_total: AtomicU64,
    forwarded_packets_total: AtomicU64,
    dropped_packets_total: AtomicU64,
    throttled_packets_total: AtomicU64,
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
    /// Total tail-dropped frames when destination queues (`256`) were full or peer was offline.
    pub dropped_packets_total: u64,
    /// Total sender frames rejected by `20 Mbps` or global cap.
    pub throttled_packets_total: u64,
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
        Self {
            store,
            per_node_bps: per_node_bps.max(MAX_FRAME_SIZE as u64),
            global_bucket: Mutex::new(TokenBucket::new(
                global_bps.max(MAX_FRAME_SIZE as u64),
                global_bps.max(MAX_FRAME_SIZE as u64),
                now_ms,
            )),
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

        let session = RelayPeerSession {
            pubkey,
            session_seq,
            tx,
            cancel: cancel.clone(),
            tx_bucket: TokenBucket::new(self.per_node_bps, self.per_node_bps, now_ms),
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
        if raw_frame.len() > MAX_FRAME_SIZE || self.store.is_node_revoked_ram(src_node_id) {
            return RelayForwardOutcome::Disconnect;
        }
        let Ok(decoded) = RelayFrame::decode(raw_frame) else {
            return RelayForwardOutcome::Disconnect;
        };

        match decoded {
            RelayFrame::ClientToPeerPacket {
                dst_pubkey,
                ciphertext,
            } => {
                self.forward_client_packet(src_node_id, src_pubkey, dst_pubkey, ciphertext, now_ms)
            }
            RelayFrame::KeepAlive { .. } => RelayForwardOutcome::Forwarded,
            RelayFrame::RelayToClientPacket { .. } | RelayFrame::ControlNotice { .. } => {
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
        if let Ok(mut g_bucket) = self.global_bucket.lock()
            && !g_bucket.try_consume(payload_len.max(1), now_ms)
        {
            self.send_throttle_notice(src_node_id);
            return RelayForwardOutcome::Throttled;
        }

        let dst_tx_opt = {
            let Ok(mut guard) = self.state.lock() else {
                return RelayForwardOutcome::Dropped;
            };
            let allowed = guard
                .by_node_id
                .get_mut(&src_node_id)
                .is_some_and(|s| s.tx_bucket.try_consume(payload_len.max(1), now_ms));
            if !allowed {
                if let Some(sender) = guard.by_node_id.get(&src_node_id) {
                    let notice = RelayFrame::ControlNotice {
                        code: RelayNoticeCode::Throttled,
                    };
                    if let Ok(encoded) = notice.encode()
                        && let Err(err) = sender.tx.try_send(encoded)
                    {
                        tracing::trace!(
                            component = "relay_hub",
                            event = "throttle_notice_dropped",
                            error = %err,
                            "dropped throttle notice because outbound queue is full"
                        );
                    }
                }
                self.metrics
                    .throttled_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                return RelayForwardOutcome::Throttled;
            }
            guard
                .pubkey_index
                .get(dst_pubkey.as_bytes())
                .copied()
                .and_then(|dst_id| guard.by_node_id.get(&dst_id).map(|s| s.tx.clone()))
        };

        let Some(dst_tx) = dst_tx_opt else {
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
                RelayForwardOutcome::Forwarded
            }
            Err(_) => {
                self.metrics
                    .dropped_packets_total
                    .fetch_add(1, Ordering::Relaxed);
                RelayForwardOutcome::Dropped
            }
        }
    }

    fn send_throttle_notice(&self, src_node_id: NodeId) {
        self.metrics
            .throttled_packets_total
            .fetch_add(1, Ordering::Relaxed);
        if let Ok(guard) = self.state.lock()
            && let Some(sender) = guard.by_node_id.get(&src_node_id)
            && let Ok(encoded) = (RelayFrame::ControlNotice {
                code: RelayNoticeCode::Throttled,
            })
            .encode()
            && let Err(err) = sender.tx.try_send(encoded)
        {
            tracing::trace!(
                component = "relay_hub",
                event = "throttle_notice_dropped",
                error = %err,
                "dropped throttle notice because outbound queue is full"
            );
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
            throttled_packets_total: self.metrics.throttled_packets_total.load(Ordering::Relaxed),
        }
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
}
