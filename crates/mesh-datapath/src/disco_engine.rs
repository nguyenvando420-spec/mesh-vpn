//! Authenticated Disco NAT hole-punching, anti-poisoning provenance checks, and keepalive state machine.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{info, warn};

use mesh_core::{AppResult, NodeId, PublicKey};
use mesh_crypto::{
    DiscoKeypair, DiscoSealParams, open_disco_packet, peek_outer_sender_pubkey, random_bytes,
    seal_disco_packet,
};
use mesh_net::endpoint_filter::{CandidateFilterContext, is_valid_candidate_endpoint};
use mesh_proto::disco::{DiscoBody, IngressSource, MAX_DISCO_ENDPOINTS};
use mesh_proto::netmap::{CandidateSource, NatMappingKind};

use crate::peer_map::{PeerActivePath, PeerMap, PeerSendTarget};

/// Pending `DiscoPing` transaction TTL in milliseconds (`10 s`, single-use anti-replay).
pub const DISCO_PING_TTL_MS: u64 = 10_000;
/// Active probe timeout before counting a direct ping probe as missed (`3 s`, `<= 10 s` 3-strike failover).
pub const DISCO_PROBE_TIMEOUT_MS: u64 = 3_000;
/// Consecutive missed Direct `DiscoPong` replies before immediate Blind Relay failover (`US-022`).
pub const DISCO_MAX_MISSED_PONGS: u8 = 3;
/// On-demand keepalive ping interval while a direct peer has active or warm traffic (`25 s`).
pub const DISCO_KEEPALIVE_INTERVAL_MS: u64 = 25_000;
/// Fast probe cadence (`1 s`) used while a Direct path is suspected unhealthy (`HR-S1-06`).
pub const DISCO_SUSPECT_PROBE_INTERVAL_MS: u64 = 1_000;
/// Fast probe timeout (`1.8 s`) for suspect pings so 3 strikes fail over in `4.5-8 s` (`<= 10 s`).
pub const DISCO_SUSPECT_PROBE_TIMEOUT_MS: u64 = 1_800;
/// Asymmetric TX stall window (`2 s`): TX beyond verified RX by `> 2 s` enables Fast Suspect Probe.
pub const DISCO_ASYMMETRIC_TRAFFIC_THRESHOLD_MS: u64 = 2_000;
/// Default idle traffic window after which keepalives pause to stay `<= 1 KB/s` (`3 min`, `US-022`).
pub const DISCO_DEFAULT_IDLE_WINDOW_MS: u64 = 180_000;
/// Minimum configurable idle window (`3 min`).
pub const DISCO_MIN_IDLE_WINDOW_MS: u64 = 180_000;
/// Maximum configurable idle window (`5 min`).
pub const DISCO_MAX_IDLE_WINDOW_MS: u64 = 300_000;
/// Initial re-punch backoff interval for failed/hard-NAT peers (`30 s`).
pub const HARD_NAT_BACKOFF_INITIAL_MS: u64 = 30_000;
/// Maximum re-punch backoff interval (`5 min`).
pub const HARD_NAT_BACKOFF_MAX_MS: u64 = 300_000;
/// Maximum `CallMeMaybe` triggers accepted/sent per peer per 60-second window.
pub const CALL_ME_MAYBE_RATE_LIMIT_PER_MIN: u32 = 10;
const CALL_ME_MAYBE_WINDOW_MS: u64 = 60_000;

/// Configuration parameters for [`DiscoEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoConfig {
    /// On-demand keepalive interval in milliseconds (`25_000` default).
    pub keepalive_interval_ms: u64,
    /// Idle traffic duration after which keepalives suspend (`180_000..=300_000` ms).
    pub idle_window_ms: u64,
    /// Single `DiscoPing` probe timeout before counting a missed pong.
    pub probe_timeout_ms: u64,
}

impl Default for DiscoConfig {
    fn default() -> Self {
        Self {
            keepalive_interval_ms: DISCO_KEEPALIVE_INTERVAL_MS,
            idle_window_ms: DISCO_DEFAULT_IDLE_WINDOW_MS,
            probe_timeout_ms: DISCO_PROBE_TIMEOUT_MS,
        }
    }
}

impl DiscoConfig {
    /// Validates and clamps the idle keepalive window within `3..=5` minutes (`US-022`).
    #[must_use]
    pub fn with_idle_window_ms(mut self, idle_window_ms: u64) -> Self {
        self.idle_window_ms =
            idle_window_ms.clamp(DISCO_MIN_IDLE_WINDOW_MS, DISCO_MAX_IDLE_WINDOW_MS);
        self
    }
}

/// Outbound network packet produced by `DiscoEngine` without performing blocking I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundDiscoPacket {
    /// Target peer UUID.
    pub peer_id: NodeId,
    /// Delivery channel (`Direct(addr)` or `Relay(node_pubkey)`).
    pub target: PeerSendTarget,
    /// Encrypted Disco wire packet (`b"MESHDS"` + version + payload >= 172 B).
    pub bytes: Vec<u8>,
}

/// Domain event returned when handling an incoming `Disco` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoEvent {
    /// Answered an incoming `DiscoPing` via the exact matching ingress path.
    RepliedPong {
        /// Remote peer that sent the Ping.
        peer_id: NodeId,
        /// Delivery target matching ingress provenance.
        target: PeerSendTarget,
    },
    /// Verified `DiscoPong` via `DirectUdp` promoted or confirmed peer's Direct UDP endpoint.
    DirectPathVerified {
        /// Peer whose direct path succeeded.
        peer_id: NodeId,
        /// Kernel-verified UDP remote address (`IngressSource::DirectUdp`).
        addr: SocketAddr,
        /// Measured RTT in milliseconds.
        rtt_ms: u64,
    },
    /// Verified `DiscoPong` via `Relay` measured Relay RTT WITHOUT altering `direct_addr`.
    RelayRttMeasured {
        /// Peer that responded over Blind Relay.
        peer_id: NodeId,
        /// Measured Relay RTT in milliseconds.
        rtt_ms: u64,
    },
    /// Received `CallMeMaybe` and scheduled simultaneous hole-punching Pings.
    HolePunchTriggered {
        /// Peer requesting hole punching.
        peer_id: NodeId,
        /// Number of valid candidate endpoints pinged.
        candidates_pinged: usize,
    },
    /// Packet dropped due to crypto/provenance/anti-reflection validation failure.
    Rejected {
        /// Machine-readable reason label.
        reason: &'static str,
    },
}

/// Physical delivery path over which an interactive `mesh ping` `DiscoPong` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingProbePath {
    /// Received directly over peer UDP socket.
    Direct {
        /// Remote UDP address from which the matching `DiscoPong` arrived.
        addr: SocketAddr,
    },
    /// Received via the Blind Relay WebSocket server.
    Relay,
    /// No matching `DiscoPong` arrived before the per-probe timeout elapsed.
    Timeout,
}

/// Measured outcome of a single end-to-end encrypted `DiscoPing`/`DiscoPong` probe (`BLK-W12-02`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingProbeOutcome {
    /// Observed delivery path or timeout.
    pub path: PingProbePath,
    /// Monotonic round-trip time in milliseconds when a matching `DiscoPong` arrived.
    pub rtt_ms: Option<f64>,
}

/// Parameters controlling an interactive end-to-end `mesh ping` probe (`BLK-W12-02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InteractivePingRequest {
    /// Destination peer identifier.
    pub peer_id: NodeId,
    /// Probe peer's Direct UDP candidate endpoints even if currently active on Relay.
    pub force_direct: bool,
    /// Local UTC timestamp in milliseconds.
    pub now_ms: u64,
    /// Probe timeout budget in milliseconds.
    pub timeout_ms: u64,
}

/// Metrics snapshot exposed for `mesh-server` / `/metrics` observability (`api-design.md §6.2`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscoMetricsSnapshot {
    /// Total invalid/spoofed/replayed Disco packets rejected (`mesh_agent_disco_invalid_packets_total`).
    pub invalid_packets: u64,
    /// Total encrypted DiscoPing packets transmitted.
    pub pings_sent: u64,
    /// Total Direct UDP DiscoPong responses accepted.
    pub direct_pongs_accepted: u64,
    /// Total Relay DiscoPong responses accepted (RTT only, no Direct promotion).
    pub relay_pongs_accepted: u64,
    /// Total Relay-sourced packets attempting mismatched `src_pubkey` or path poisoning.
    pub relay_poison_attempts_blocked: u64,
    /// Total Direct->Relay failovers triggered by missed Pongs / timeout.
    pub direct_failovers: u64,
}

#[derive(Debug, Default)]
struct DiscoMetrics {
    invalid_packets: AtomicU64,
    pings_sent: AtomicU64,
    direct_pongs_accepted: AtomicU64,
    relay_pongs_accepted: AtomicU64,
    relay_poison_attempts_blocked: AtomicU64,
    direct_failovers: AtomicU64,
}

impl DiscoMetrics {
    fn snapshot(&self) -> DiscoMetricsSnapshot {
        DiscoMetricsSnapshot {
            invalid_packets: self.invalid_packets.load(Ordering::Relaxed),
            pings_sent: self.pings_sent.load(Ordering::Relaxed),
            direct_pongs_accepted: self.direct_pongs_accepted.load(Ordering::Relaxed),
            relay_pongs_accepted: self.relay_pongs_accepted.load(Ordering::Relaxed),
            relay_poison_attempts_blocked: self
                .relay_poison_attempts_blocked
                .load(Ordering::Relaxed),
            direct_failovers: self.direct_failovers.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeTransport {
    addr: SocketAddr,
    source: CandidateSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingPing {
    peer_id: NodeId,
    sent_at_ms: u64,
    timeout_ms: u64,
    expires_at_ms: u64,
    transport: ProbeTransport,
    counted_miss: bool,
    count_toward_failover: bool,
}

#[derive(Debug, Clone, Default)]
struct PeerDiscoTracker {
    missed_direct_pongs: u8,
    last_keepalive_sent_ms: u64,
    last_direct_probe_ms: u64,
    last_direct_pong_ms: u64,
    next_retry_at_ms: u64,
    backoff_ms: u64,
    call_me_maybe_window_start_ms: u64,
    call_me_maybe_count: u32,
    relay_rtt_ms: Option<u64>,
}

/// Candidate filtering inputs passed into [`DiscoEngine`] operations.
#[derive(Debug, Clone, Copy)]
pub struct DiscoFilterContext<'a> {
    /// Local network boundary constraints (overlay CIDR, optional Control/STUN sockets).
    pub candidates: &'a CandidateFilterContext,
    /// Active UDP STUN server endpoints excluded from P2P candidate sets.
    pub excluded_stun: &'a [SocketAddr],
}

#[derive(Debug, Clone, Copy)]
struct DirectKeepaliveTarget {
    peer_id: NodeId,
    disco_pk: PublicKey,
    addr: SocketAddr,
    source: CandidateSource,
    last_tx_at_ms: u64,
    last_rx_at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct PingParams {
    peer_id: NodeId,
    recipient_disco_pubkey: PublicKey,
    transport: ProbeTransport,
    target: PeerSendTarget,
    now_ms: u64,
    timeout_ms: u64,
    count_toward_failover: bool,
}

#[derive(Debug, Clone, Copy)]
struct AuthenticatedPeerInfo {
    peer_id: NodeId,
    node_pubkey: PublicKey,
    disco_pubkey: PublicKey,
}

#[derive(Debug, Clone, Copy)]
struct PongContext {
    peer_id: NodeId,
    tx_id: [u8; 12],
    ingress: IngressSource,
    now_ms: u64,
}

/// Sans-I/O Authenticated Disco hole-punching, anti-poisoning, and keepalive engine (`US-021`, `US-022`).
#[derive(Debug)]
pub struct DiscoEngine {
    local_keypair: DiscoKeypair,
    config: DiscoConfig,
    nat_mapping: NatMappingKind,
    pending_pings: HashMap<[u8; 12], PendingPing>,
    per_peer: HashMap<NodeId, PeerDiscoTracker>,
    metrics: DiscoMetrics,
    #[cfg(test)]
    allow_loopback_candidates: bool,
}

impl DiscoEngine {
    /// Creates a new `DiscoEngine` bound to the local node's Disco keypair.
    #[must_use]
    pub fn new(local_keypair: DiscoKeypair, config: DiscoConfig) -> Self {
        Self {
            local_keypair,
            config,
            nat_mapping: NatMappingKind::Unknown,
            pending_pings: HashMap::new(),
            per_peer: HashMap::new(),
            metrics: DiscoMetrics::default(),
            #[cfg(test)]
            allow_loopback_candidates: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn enable_loopback_for_tests(&mut self) {
        self.allow_loopback_candidates = true;
    }

    fn is_endpoint_allowed(&self, addr: SocketAddr, filter: &DiscoFilterContext<'_>) -> bool {
        if filter.excluded_stun.contains(&addr) {
            return false;
        }
        #[cfg(test)]
        if self.allow_loopback_candidates && addr.ip().is_loopback() {
            return filter
                .candidates
                .stun_udp_endpoint
                .is_none_or(|stun| stun != addr);
        }
        is_valid_candidate_endpoint(addr, None, filter.candidates)
    }

    /// Updates local NAT classification so hard NAT uses conservative backoff (`US-019`, `US-022`).
    pub fn set_nat_mapping(&mut self, nat_mapping: NatMappingKind) {
        self.nat_mapping = nat_mapping;
    }

    /// Immediately removes per-peer backoff, rate-limit, and pending probe state when peers are cut (`US-030`).
    pub fn remove_peers(&mut self, peer_ids: &[NodeId]) {
        if peer_ids.is_empty() {
            return;
        }
        for id in peer_ids {
            self.per_peer.remove(id);
        }
        self.pending_pings
            .retain(|_, pending| !peer_ids.contains(&pending.peer_id));
    }

    /// Returns an immutable metrics snapshot.
    #[must_use]
    pub fn metrics_snapshot(&self) -> DiscoMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Builds a rate-limited `CallMeMaybe` packet via Relay when `our_endpoints` is non-empty.
    pub fn maybe_build_call_me_maybe(
        &mut self,
        peer_map: &PeerMap,
        peer_id: NodeId,
        our_endpoints: &[SocketAddr],
        now_ms: u64,
    ) -> Option<OutboundDiscoPacket> {
        let peer = peer_map.get(&peer_id)?;
        if our_endpoints.is_empty() || !self.allow_call_me_maybe(peer_id, now_ms) {
            return None;
        }
        let bounded: Vec<SocketAddr> = our_endpoints
            .iter()
            .copied()
            .take(MAX_DISCO_ENDPOINTS)
            .collect();
        self.seal_packet(
            peer.disco_pubkey,
            &DiscoBody::CallMeMaybe { endpoints: bounded },
            random_bytes::<12>(),
            now_ms,
        )
        .ok()
        .map(|bytes| OutboundDiscoPacket {
            peer_id,
            target: PeerSendTarget::Relay(peer.node_pubkey),
            bytes,
        })
    }

    /// Builds encrypted `DiscoPing` packets with unique transaction IDs for interactive `mesh ping`
    /// without altering background Direct->Relay 3-strike failover counters (`BLK-W12-02`).
    pub fn build_interactive_probes(
        &mut self,
        peer_map: &PeerMap,
        filter: &DiscoFilterContext<'_>,
        req: InteractivePingRequest,
    ) -> Vec<([u8; 12], OutboundDiscoPacket)> {
        let Some(peer) = peer_map.get(&req.peer_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let PeerActivePath::Direct { addr, source, .. } = &peer.active_path {
            if self.is_endpoint_allowed(*addr, filter)
                && let Some(built) = self.build_ping_with_tx(PingParams {
                    peer_id: req.peer_id,
                    recipient_disco_pubkey: peer.disco_pubkey,
                    transport: ProbeTransport {
                        addr: *addr,
                        source: *source,
                    },
                    target: PeerSendTarget::Direct(*addr),
                    now_ms: req.now_ms,
                    timeout_ms: req.timeout_ms,
                    count_toward_failover: false,
                })
            {
                out.push(built);
            }
            return out;
        }
        if req.force_direct {
            for ep in &peer.endpoints {
                if !self.is_endpoint_allowed(ep.addr, filter) {
                    continue;
                }
                if let Some(built) = self.build_ping_with_tx(PingParams {
                    peer_id: req.peer_id,
                    recipient_disco_pubkey: peer.disco_pubkey,
                    transport: ProbeTransport {
                        addr: ep.addr,
                        source: ep.source,
                    },
                    target: PeerSendTarget::Direct(ep.addr),
                    now_ms: req.now_ms,
                    timeout_ms: req.timeout_ms,
                    count_toward_failover: false,
                }) {
                    out.push(built);
                }
            }
            return out;
        }
        let unspecified = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        if let Some(built) = self.build_ping_with_tx(PingParams {
            peer_id: req.peer_id,
            recipient_disco_pubkey: peer.disco_pubkey,
            transport: ProbeTransport {
                addr: unspecified,
                source: CandidateSource::Reflexive,
            },
            target: PeerSendTarget::Relay(peer.node_pubkey),
            now_ms: req.now_ms,
            timeout_ms: req.timeout_ms,
            count_toward_failover: false,
        }) {
            out.push(built);
        }
        out
    }

    /// Initiates simultaneous NAT hole punching toward `peer_id` by generating encrypted
    /// `DiscoCallMeMaybe` (via Relay) and direct `DiscoPing` packets to valid endpoints.
    pub fn initiate_hole_punch(
        &mut self,
        peer_map: &PeerMap,
        peer_id: NodeId,
        our_endpoints: &[SocketAddr],
        filter: &DiscoFilterContext<'_>,
        now_ms: u64,
    ) -> Vec<OutboundDiscoPacket> {
        let Some(peer) = peer_map.get(&peer_id) else {
            return Vec::new();
        };

        let mut packets = Vec::new();
        if let Some(call_me) =
            self.maybe_build_call_me_maybe(peer_map, peer_id, our_endpoints, now_ms)
        {
            packets.push(call_me);
        }

        let valid_targets: Vec<(SocketAddr, CandidateSource)> = peer
            .endpoints
            .iter()
            .filter(|ep| self.is_endpoint_allowed(ep.addr, filter))
            .map(|ep| (ep.addr, ep.source))
            .collect();
        for (addr, source) in valid_targets {
            if let Some(ping) = self.build_ping(PingParams {
                peer_id,
                recipient_disco_pubkey: peer.disco_pubkey,
                transport: ProbeTransport { addr, source },
                target: PeerSendTarget::Direct(addr),
                now_ms,
                timeout_ms: self.config.probe_timeout_ms,
                count_toward_failover: true,
            }) {
                packets.push(ping);
            }
        }

        packets
    }

    /// Handles an incoming demultiplexed Disco packet and returns any authenticated Pong `tx_id`.
    pub fn handle_incoming_tracked(
        &mut self,
        raw_packet: &[u8],
        ingress: IngressSource,
        peer_map: &mut PeerMap,
        filter: &DiscoFilterContext<'_>,
        now_ms: u64,
    ) -> (DiscoEvent, Option<[u8; 12]>, Vec<OutboundDiscoPacket>) {
        self.prune_expired_pings(now_ms);
        let (peer_id, peer_node_pk, peer_disco_pk, tx_id, body) =
            match self.authenticate_and_decode(raw_packet, ingress, peer_map) {
                Ok(parsed) => parsed,
                Err(reason) => return (DiscoEvent::Rejected { reason }, None, Vec::new()),
            };

        let peer = AuthenticatedPeerInfo {
            peer_id,
            node_pubkey: peer_node_pk,
            disco_pubkey: peer_disco_pk,
        };
        match body {
            DiscoBody::Ping => {
                let (ev, pkts) = self.handle_ping(peer, tx_id, ingress, now_ms);
                (ev, None, pkts)
            }
            DiscoBody::Pong { observed_addr: _ } => {
                let (ev, pkts) = self.handle_pong(
                    PongContext {
                        peer_id,
                        tx_id,
                        ingress,
                        now_ms,
                    },
                    peer_map,
                    filter,
                );
                let matched_tx = matches!(
                    ev,
                    DiscoEvent::DirectPathVerified { .. } | DiscoEvent::RelayRttMeasured { .. }
                )
                .then_some(tx_id);
                (ev, matched_tx, pkts)
            }
            DiscoBody::CallMeMaybe { endpoints } => {
                let (ev, pkts) =
                    self.handle_call_me_maybe(peer_id, peer_disco_pk, &endpoints, filter, now_ms);
                (ev, None, pkts)
            }
        }
    }

    /// Handles an incoming demultiplexed Disco packet from either `DirectUdp` or `Relay` (`HR-G2-04`).
    pub fn handle_incoming(
        &mut self,
        raw_packet: &[u8],
        ingress: IngressSource,
        peer_map: &mut PeerMap,
        filter: &DiscoFilterContext<'_>,
        now_ms: u64,
    ) -> (DiscoEvent, Vec<OutboundDiscoPacket>) {
        let (ev, _, pkts) =
            self.handle_incoming_tracked(raw_packet, ingress, peer_map, filter, now_ms);
        (ev, pkts)
    }

    fn authenticate_and_decode(
        &mut self,
        raw_packet: &[u8],
        ingress: IngressSource,
        peer_map: &PeerMap,
    ) -> Result<(NodeId, PublicKey, PublicKey, [u8; 12], DiscoBody), &'static str> {
        let outer_sender = peek_outer_sender_pubkey(raw_packet, &self.local_keypair.public_key())
            .map_err(|r| {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            r.metric_label()
        })?;
        if peer_map.get_by_disco_pubkey(&outer_sender).is_none() {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return Err("unknown_sender_disco_pubkey");
        }

        let opened = open_disco_packet(raw_packet, &self.local_keypair).map_err(|reason| {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            warn!(
                component = "datapath.disco_engine",
                event = "disco_packet_rejected",
                reason = reason.metric_label(),
                "dropped invalid/unauthenticated Disco packet"
            );
            reason.metric_label()
        })?;

        let Some(peer_session) = peer_map.get_by_disco_pubkey(&opened.sender_disco_pubkey) else {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return Err("unknown_sender_disco_pubkey");
        };

        if let IngressSource::Relay {
            verified_src_node_pubkey,
        } = ingress
            && peer_session.node_pubkey != verified_src_node_pubkey
        {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .relay_poison_attempts_blocked
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                component = "datapath.disco_engine",
                event = "relay_pubkey_mismatch_blocked",
                peer_id = %peer_session.node_id,
                "blocked Disco packet over Relay with mismatched verified_src_node_pubkey"
            );
            return Err("relay_src_pubkey_mismatch");
        }

        let Ok(body) = DiscoBody::decode(opened.msg_type, &opened.body) else {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return Err("malformed_body");
        };

        Ok((
            peer_session.node_id,
            peer_session.node_pubkey,
            peer_session.disco_pubkey,
            opened.tx_id,
            body,
        ))
    }

    /// Evaluates per-peer probe timeouts, 3-strike Direct->Relay failover, on-demand 25 s keepalive
    /// (with 3-5 min idle pause), and hard-NAT background re-punch scheduling (`US-022`).
    pub fn tick(&mut self, peer_map: &mut PeerMap, now_ms: u64) -> Vec<OutboundDiscoPacket> {
        let mut outbound = Vec::new();
        self.check_probe_timeouts(peer_map, now_ms);
        self.prune_expired_pings(now_ms);

        let peer_snapshot: Vec<_> = peer_map
            .iter()
            .map(|(&id, s)| {
                let cands: Vec<(SocketAddr, CandidateSource)> =
                    s.endpoints.iter().map(|c| (c.addr, c.source)).collect();
                (
                    id,
                    s.disco_pubkey,
                    s.active_path.clone(),
                    s.last_tx_at_ms,
                    s.last_rx_at_ms,
                    cands,
                )
            })
            .collect();

        for (peer_id, disco_pk, active_path, last_tx_at_ms, last_rx_at_ms, candidates) in
            peer_snapshot
        {
            let last_activity = last_tx_at_ms.max(last_rx_at_ms);
            let is_idle = last_activity == 0
                || now_ms.saturating_sub(last_activity) > self.config.idle_window_ms;
            if is_idle {
                continue;
            }
            match active_path {
                PeerActivePath::Direct { addr, source, .. } => {
                    self.tick_direct_keepalive(
                        DirectKeepaliveTarget {
                            peer_id,
                            disco_pk,
                            addr,
                            source,
                            last_tx_at_ms,
                            last_rx_at_ms,
                        },
                        now_ms,
                        &mut outbound,
                    );
                }
                PeerActivePath::Relay => {
                    self.tick_relay_repunch(peer_id, disco_pk, &candidates, now_ms, &mut outbound);
                }
            }
        }
        outbound
    }

    fn tick_direct_keepalive(
        &mut self,
        target: DirectKeepaliveTarget,
        now_ms: u64,
        outbound: &mut Vec<OutboundDiscoPacket>,
    ) {
        let tracker = self.per_peer.entry(target.peer_id).or_default();
        let effective_rx_ms = target.last_rx_at_ms.max(tracker.last_direct_pong_ms);
        let asymmetric_stall = target.last_tx_at_ms
            > effective_rx_ms.saturating_add(DISCO_ASYMMETRIC_TRAFFIC_THRESHOLD_MS);
        let suspect = tracker.missed_direct_pongs >= 1 || asymmetric_stall;
        let (interval_ms, timeout_ms) = if suspect {
            (
                self.config
                    .keepalive_interval_ms
                    .min(DISCO_SUSPECT_PROBE_INTERVAL_MS),
                self.config
                    .probe_timeout_ms
                    .min(DISCO_SUSPECT_PROBE_TIMEOUT_MS),
            )
        } else {
            (
                self.config.keepalive_interval_ms,
                self.config.probe_timeout_ms,
            )
        };
        if now_ms.saturating_sub(tracker.last_keepalive_sent_ms) < interval_ms {
            return;
        }
        tracker.last_keepalive_sent_ms = now_ms;
        if let Some(pkt) = self.build_ping(PingParams {
            peer_id: target.peer_id,
            recipient_disco_pubkey: target.disco_pk,
            transport: ProbeTransport {
                addr: target.addr,
                source: target.source,
            },
            target: PeerSendTarget::Direct(target.addr),
            now_ms,
            timeout_ms,
            count_toward_failover: true,
        }) {
            outbound.push(pkt);
        }
    }

    fn tick_relay_repunch(
        &mut self,
        peer_id: NodeId,
        disco_pk: PublicKey,
        candidates: &[(SocketAddr, CandidateSource)],
        now_ms: u64,
        outbound: &mut Vec<OutboundDiscoPacket>,
    ) {
        if candidates.is_empty() {
            return;
        }
        let initial = self.initial_retry_backoff_ms();
        let tracker = self.per_peer.entry(peer_id).or_default();
        if tracker.backoff_ms == 0 {
            tracker.backoff_ms = initial;
        }
        if now_ms < tracker.next_retry_at_ms {
            return;
        }
        tracker.next_retry_at_ms = now_ms.saturating_add(tracker.backoff_ms);
        tracker.backoff_ms = tracker
            .backoff_ms
            .saturating_mul(2)
            .min(HARD_NAT_BACKOFF_MAX_MS);
        for &(addr, source) in candidates.iter().take(4) {
            if let Some(pkt) = self.build_ping(PingParams {
                peer_id,
                recipient_disco_pubkey: disco_pk,
                transport: ProbeTransport { addr, source },
                target: PeerSendTarget::Direct(addr),
                now_ms,
                timeout_ms: self.config.probe_timeout_ms,
                count_toward_failover: true,
            }) {
                outbound.push(pkt);
            }
        }
    }

    fn handle_ping(
        &mut self,
        peer: AuthenticatedPeerInfo,
        tx_id: [u8; 12],
        ingress: IngressSource,
        now_ms: u64,
    ) -> (DiscoEvent, Vec<OutboundDiscoPacket>) {
        let (observed_addr, target) = match ingress {
            IngressSource::DirectUdp(addr) => (addr, PeerSendTarget::Direct(addr)),
            IngressSource::Relay { .. } => (
                SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
                PeerSendTarget::Relay(peer.node_pubkey),
            ),
        };

        let body = DiscoBody::Pong { observed_addr };
        match self.seal_packet(peer.disco_pubkey, &body, tx_id, now_ms) {
            Ok(bytes) => (
                DiscoEvent::RepliedPong {
                    peer_id: peer.peer_id,
                    target,
                },
                vec![OutboundDiscoPacket {
                    peer_id: peer.peer_id,
                    target,
                    bytes,
                }],
            ),
            Err(err) => {
                warn!(
                    component = "datapath.disco_engine",
                    event = "disco_pong_seal_failed",
                    peer_id = %peer.peer_id,
                    error = %err,
                    "failed to seal DiscoPong reply"
                );
                (
                    DiscoEvent::Rejected {
                        reason: "seal_failed",
                    },
                    Vec::new(),
                )
            }
        }
    }

    fn handle_pong(
        &mut self,
        ctx: PongContext,
        peer_map: &mut PeerMap,
        filter: &DiscoFilterContext<'_>,
    ) -> (DiscoEvent, Vec<OutboundDiscoPacket>) {
        let Some(pending) = self.pending_pings.remove(&ctx.tx_id) else {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return (
                DiscoEvent::Rejected {
                    reason: "unknown_or_replayed_tx_id",
                },
                Vec::new(),
            );
        };
        if pending.peer_id != ctx.peer_id || ctx.now_ms > pending.expires_at_ms {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return (
                DiscoEvent::Rejected {
                    reason: "expired_or_wrong_peer_tx_id",
                },
                Vec::new(),
            );
        }

        let rtt_ms = ctx.now_ms.saturating_sub(pending.sent_at_ms);

        match ctx.ingress {
            IngressSource::Relay { .. } => {
                // CRITICAL (HR-G2-04): Relay Pong ONLY measures Relay RTT and NEVER touches direct_addr!
                self.metrics
                    .relay_pongs_accepted
                    .fetch_add(1, Ordering::Relaxed);
                let tracker = self.per_peer.entry(ctx.peer_id).or_default();
                tracker.relay_rtt_ms = Some(rtt_ms);
                (
                    DiscoEvent::RelayRttMeasured {
                        peer_id: ctx.peer_id,
                        rtt_ms,
                    },
                    Vec::new(),
                )
            }
            IngressSource::DirectUdp(remote_addr) => {
                if !self.is_endpoint_allowed(remote_addr, filter) {
                    self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    return (
                        DiscoEvent::Rejected {
                            reason: "invalid_direct_endpoint",
                        },
                        Vec::new(),
                    );
                }
                self.metrics
                    .direct_pongs_accepted
                    .fetch_add(1, Ordering::Relaxed);

                let source = pending.transport.source;
                if should_promote_candidate(peer_map.get(&ctx.peer_id), source, remote_addr, rtt_ms)
                    && peer_map.set_direct_path(
                        &ctx.peer_id,
                        remote_addr,
                        source,
                        rtt_ms,
                        ctx.now_ms,
                    )
                {
                    info!(
                        component = "datapath.disco_engine",
                        event = "direct_path_verified",
                        peer_id = %ctx.peer_id,
                        remote_addr = %remote_addr,
                        rtt_ms,
                        source = ?source,
                        "verified Direct UDP path via authenticated DiscoPong"
                    );
                }

                let tracker = self.per_peer.entry(ctx.peer_id).or_default();
                tracker.missed_direct_pongs = 0;
                tracker.backoff_ms = 0;
                tracker.last_direct_probe_ms = ctx.now_ms;
                tracker.last_direct_pong_ms = ctx.now_ms;

                (
                    DiscoEvent::DirectPathVerified {
                        peer_id: ctx.peer_id,
                        addr: remote_addr,
                        rtt_ms,
                    },
                    Vec::new(),
                )
            }
        }
    }

    fn handle_call_me_maybe(
        &mut self,
        peer_id: NodeId,
        peer_disco_pubkey: PublicKey,
        endpoints: &[SocketAddr],
        filter: &DiscoFilterContext<'_>,
        now_ms: u64,
    ) -> (DiscoEvent, Vec<OutboundDiscoPacket>) {
        if !self.allow_call_me_maybe(peer_id, now_ms) {
            self.metrics.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return (
                DiscoEvent::Rejected {
                    reason: "call_me_maybe_rate_limited",
                },
                Vec::new(),
            );
        }

        let mut packets = Vec::new();
        for &addr in endpoints.iter().take(MAX_DISCO_ENDPOINTS) {
            if !self.is_endpoint_allowed(addr, filter) {
                continue;
            }
            let src = classify_addr_source(addr);
            if let Some(pkt) = self.build_ping(PingParams {
                peer_id,
                recipient_disco_pubkey: peer_disco_pubkey,
                transport: ProbeTransport { addr, source: src },
                target: PeerSendTarget::Direct(addr),
                now_ms,
                timeout_ms: self.config.probe_timeout_ms,
                count_toward_failover: true,
            }) {
                packets.push(pkt);
            }
        }

        let count = packets.len();
        (
            DiscoEvent::HolePunchTriggered {
                peer_id,
                candidates_pinged: count,
            },
            packets,
        )
    }

    fn check_probe_timeouts(&mut self, peer_map: &mut PeerMap, now_ms: u64) {
        let initial_backoff = self.initial_retry_backoff_ms();
        for pending in self.pending_pings.values_mut() {
            if !pending.count_toward_failover || pending.counted_miss {
                continue;
            }
            if !matches!(pending.transport, ProbeTransport { .. }) {
                continue;
            }
            if now_ms.saturating_sub(pending.sent_at_ms) < pending.timeout_ms {
                continue;
            }
            pending.counted_miss = true;

            let Some(session) = peer_map.get(&pending.peer_id) else {
                continue;
            };
            let active_matches = matches!(
                &session.active_path,
                PeerActivePath::Direct { addr, .. } if pending.transport.addr == *addr
            );
            if !active_matches {
                continue;
            }

            let tracker = self.per_peer.entry(pending.peer_id).or_default();
            tracker.missed_direct_pongs = tracker.missed_direct_pongs.saturating_add(1);
            if tracker.missed_direct_pongs >= DISCO_MAX_MISSED_PONGS
                && peer_map.fallback_to_relay(&pending.peer_id, "missed 3 consecutive direct Pongs")
            {
                tracker.missed_direct_pongs = 0;
                tracker.backoff_ms = initial_backoff;
                tracker.next_retry_at_ms = now_ms.saturating_add(tracker.backoff_ms);
                self.metrics
                    .direct_failovers
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn prune_expired_pings(&mut self, now_ms: u64) {
        self.pending_pings
            .retain(|_, ping| ping.expires_at_ms > now_ms);
    }

    fn allow_call_me_maybe(&mut self, peer_id: NodeId, now_ms: u64) -> bool {
        let tracker = self.per_peer.entry(peer_id).or_default();
        if now_ms.saturating_sub(tracker.call_me_maybe_window_start_ms) >= CALL_ME_MAYBE_WINDOW_MS {
            tracker.call_me_maybe_window_start_ms = now_ms;
            tracker.call_me_maybe_count = 0;
        }
        if tracker.call_me_maybe_count >= CALL_ME_MAYBE_RATE_LIMIT_PER_MIN {
            return false;
        }
        tracker.call_me_maybe_count = tracker.call_me_maybe_count.saturating_add(1);
        true
    }

    fn build_ping(&mut self, req: PingParams) -> Option<OutboundDiscoPacket> {
        self.build_ping_with_tx(req).map(|(_, pkt)| pkt)
    }

    fn build_ping_with_tx(&mut self, req: PingParams) -> Option<([u8; 12], OutboundDiscoPacket)> {
        let tx_id = random_bytes::<12>();
        let bytes = match self.seal_packet(
            req.recipient_disco_pubkey,
            &DiscoBody::Ping,
            tx_id,
            req.now_ms,
        ) {
            Ok(pkt) => pkt,
            Err(err) => {
                warn!(
                    component = "datapath.disco_engine",
                    event = "disco_ping_seal_failed",
                    peer_id = %req.peer_id,
                    error = %err,
                    "failed to seal DiscoPing"
                );
                return None;
            }
        };

        let ttl = DISCO_PING_TTL_MS.max(req.timeout_ms);
        self.pending_pings.insert(
            tx_id,
            PendingPing {
                peer_id: req.peer_id,
                sent_at_ms: req.now_ms,
                timeout_ms: req.timeout_ms,
                expires_at_ms: req.now_ms.saturating_add(ttl),
                transport: req.transport,
                counted_miss: false,
                count_toward_failover: req.count_toward_failover,
            },
        );
        self.metrics.pings_sent.fetch_add(1, Ordering::Relaxed);
        Some((
            tx_id,
            OutboundDiscoPacket {
                peer_id: req.peer_id,
                target: req.target,
                bytes,
            },
        ))
    }

    fn seal_packet(
        &self,
        recipient_disco_pubkey: PublicKey,
        body: &DiscoBody,
        tx_id: [u8; 12],
        now_ms: u64,
    ) -> AppResult<Vec<u8>> {
        let encoded_body = body.encode()?;
        let params = DiscoSealParams {
            recipient_pubkey: recipient_disco_pubkey,
            msg_type: body.msg_type() as u8,
            tx_id,
            sent_at_ms: now_ms,
            body: &encoded_body,
        };
        seal_disco_packet(&self.local_keypair, &params)
    }

    fn initial_retry_backoff_ms(&self) -> u64 {
        match self.nat_mapping {
            NatMappingKind::PortDependent => HARD_NAT_BACKOFF_INITIAL_MS,
            NatMappingKind::EimOrAdm | NatMappingKind::Unknown => 10_000,
        }
    }
}

fn should_promote_candidate(
    session: Option<&crate::peer_map::PeerSession>,
    new_source: CandidateSource,
    new_addr: SocketAddr,
    new_rtt_ms: u64,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    match session.active_path {
        PeerActivePath::Relay => true,
        PeerActivePath::Direct {
            addr,
            source,
            rtt_ms,
            ..
        } => {
            if addr == new_addr {
                return true;
            }
            if new_source < source {
                return true;
            }
            new_source == source && new_rtt_ms.saturating_add(10) < rtt_ms
        }
    }
}

fn classify_addr_source(addr: SocketAddr) -> CandidateSource {
    if addr.is_ipv6() {
        return CandidateSource::Ipv6;
    }
    match addr.ip() {
        IpAddr::V4(v4) if v4.is_private() => CandidateSource::Lan,
        _ => CandidateSource::Reflexive,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use mesh_core::{NodeName, OverlayCidr, OverlayIp, SpkiPin};
    use mesh_crypto::{DISCO_PROTOCOL_VERSION, NodeKeypair};
    use mesh_proto::netmap::{CandidateEndpoint, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};
    use mesh_proto::{DemuxPacket, MIN_DISCO_PACKET_LEN, demux_packet};

    use super::*;

    fn test_filter_ctx() -> CandidateFilterContext {
        CandidateFilterContext {
            overlay_cidr: "10.100.0.0/16".parse::<OverlayCidr>().expect("cidr"),
            control_tcp_endpoint: None,
            stun_udp_endpoint: Some("203.0.113.250:13478".parse().expect("stun")),
        }
    }

    fn setup_pair(
        remote_ep: SocketAddr,
    ) -> (
        PeerMap,
        DiscoEngine,
        PeerMap,
        DiscoEngine,
        NodeId,
        NodeId,
        PublicKey,
        PublicKey,
    ) {
        let kp_a = NodeKeypair::generate();
        let kp_b = NodeKeypair::generate();
        let dk_a = DiscoKeypair::generate();
        let dk_b = DiscoKeypair::generate();
        let id_a = NodeId::from_bytes([1; 16]);
        let id_b = NodeId::from_bytes([2; 16]);

        let entry_b = PeerEntry {
            node_id: id_b,
            name: NodeName::parse("peer-b").expect("name"),
            fqdn: "peer-b.mesh.internal".to_owned(),
            overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 3)).expect("ip"),
            node_pubkey: kp_b.public_key(),
            disco_pubkey: dk_b.public_key(),
            endpoints: vec![CandidateEndpoint {
                addr: remote_ep,
                source: CandidateSource::Reflexive,
            }],
            relay_home: "127.0.0.1:14430".to_owned(),
            key_expires_at_ms: None,
            online: true,
        };
        let entry_a = PeerEntry {
            node_id: id_a,
            name: NodeName::parse("peer-a").expect("name"),
            fqdn: "peer-a.mesh.internal".to_owned(),
            overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 2)).expect("ip"),
            node_pubkey: kp_a.public_key(),
            disco_pubkey: dk_a.public_key(),
            endpoints: vec![],
            relay_home: "127.0.0.1:14430".to_owned(),
            key_expires_at_ms: None,
            online: true,
        };

        let snap = |peers| NetmapSnapshot {
            netmap_version: 1,
            generated_at_ms: 1_000,
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "127.0.0.1:14430".to_owned(),
                relay_tcp_endpoint: "127.0.0.1:14430".to_owned(),
                stun_udp_endpoints: vec![],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([1; 32]),
                next_pin: None,
            },
            peers,
        };

        let pub_a = kp_a.public_key();
        let pub_b = kp_b.public_key();
        let mut map_a = PeerMap::new(id_a, kp_a);
        let mut map_b = PeerMap::new(id_b, kp_b);
        map_a.apply_diff(&snap(vec![entry_b]));
        map_b.apply_diff(&snap(vec![entry_a]));

        let disco_a = DiscoEngine::new(dk_a, DiscoConfig::default());
        let disco_b = DiscoEngine::new(dk_b, DiscoConfig::default());
        (map_a, disco_a, map_b, disco_b, id_a, id_b, pub_a, pub_b)
    }

    // Traces: US-021, HR-G2-04, Codex #2
    #[test]
    fn test_disco_pong_via_relay_never_updates_direct_addr_and_direct_udp_upgrades() {
        // Arrange
        let b_ep: SocketAddr = "198.51.100.42:51820".parse().expect("ep");
        let (mut map_a, mut disco_a, mut map_b, mut disco_b, _id_a, id_b, pub_a, pub_b) =
            setup_pair(b_ep);
        let ctx = test_filter_ctx();

        // Act 1: A sends direct DiscoPing to b_ep, but B answers back ONLY via Relay with a spoofed
        // inner observed_addr (attacker or asymmetric path trying to poison direct_addr via Relay)
        let filter = DiscoFilterContext {
            candidates: &ctx,
            excluded_stun: &[],
        };
        let pings = disco_a.initiate_hole_punch(&map_a, id_b, &[], &filter, 1_000);
        let first_ping = pings.first().expect("1 ping");
        let (_, b_replies) = disco_b.handle_incoming(
            &first_ping.bytes,
            IngressSource::Relay {
                verified_src_node_pubkey: pub_a,
            },
            &mut map_b,
            &filter,
            1_010,
        );
        let first_reply = b_replies.first().expect("1 reply");
        let (event_relay, _) = disco_a.handle_incoming(
            &first_reply.bytes,
            IngressSource::Relay {
                verified_src_node_pubkey: pub_b,
            },
            &mut map_a,
            &filter,
            1_025,
        );

        // Assert 1: Relay Pong measured RTT ONLY and peer stays strictly on Relay!
        assert_eq!(
            event_relay,
            DiscoEvent::RelayRttMeasured {
                peer_id: id_b,
                rtt_ms: 25
            }
        );
        assert_eq!(
            map_a.get(&id_b).expect("b").active_path,
            PeerActivePath::Relay
        );

        // Act 2: Replayed tx_id over DirectUdp MUST be rejected; fresh DirectUdp ping -> Pong upgrades!
        let (replay_ev, _) = disco_a.handle_incoming(
            &first_reply.bytes,
            IngressSource::DirectUdp(b_ep),
            &mut map_a,
            &filter,
            1_030,
        );
        assert!(matches!(replay_ev, DiscoEvent::Rejected { .. }));

        let fresh = disco_a.initiate_hole_punch(&map_a, id_b, &[], &filter, 1_100);
        let fresh_ping = fresh.first().expect("fresh ping");
        let (_, b_direct_replies) = disco_b.handle_incoming(
            &fresh_ping.bytes,
            IngressSource::DirectUdp("198.51.100.10:51820".parse().expect("a")),
            &mut map_b,
            &filter,
            1_110,
        );
        let (event_direct, _) = disco_a.handle_incoming(
            &b_direct_replies.first().expect("direct reply").bytes,
            IngressSource::DirectUdp(b_ep),
            &mut map_a,
            &filter,
            1_120,
        );

        // Assert 2: DirectUdp Pong upgraded path to Direct(b_ep)
        assert_eq!(
            event_direct,
            DiscoEvent::DirectPathVerified {
                peer_id: id_b,
                addr: b_ep,
                rtt_ms: 20
            }
        );
        assert!(matches!(
            map_a.get(&id_b).expect("b").active_path,
            PeerActivePath::Direct { addr, .. } if addr == b_ep
        ));
    }

    // Traces: US-022
    #[test]
    fn test_disco_failover_after_three_missed_pongs_and_idle_keepalive_rest() {
        // Arrange
        let b_ep: SocketAddr = "198.51.100.42:51820".parse().expect("ep");
        let (mut map_a, mut disco_a, _map_b, _disco_b, _id_a, id_b, _pub_a, _pub_b) =
            setup_pair(b_ep);

        assert!(map_a.set_direct_path(&id_b, b_ep, CandidateSource::Reflexive, 10, 1_000));
        map_a.get_mut(&id_b).expect("b").last_tx_at_ms = 2_000;

        // Act: trigger 3 pings while traffic is active and advance past probe timeout without Pong
        for idx in 0..3u64 {
            let t = 30_000 + idx * 26_000;
            map_a.get_mut(&id_b).expect("b").last_tx_at_ms = t - 100;
            let sent = disco_a.tick(&mut map_a, t);
            assert_eq!(sent.len(), 1);
            drop(disco_a.tick(&mut map_a, t + DISCO_PROBE_TIMEOUT_MS + 1));
        }

        // Assert: failed over to Relay after 3 consecutive missed Pongs
        assert_eq!(
            map_a.get(&id_b).expect("b").active_path,
            PeerActivePath::Relay
        );
        assert_eq!(disco_a.metrics_snapshot().direct_failovers, 1);

        // Act: advance past idle window (180s) -> keepalive / background probes pause
        let idle_sent = disco_a.tick(&mut map_a, 500_000);
        assert!(idle_sent.is_empty());
    }

    // Traces: US-022, REL-02, HR-S1-06
    #[test]
    fn test_disco_fast_suspect_failover_completes_within_10_seconds() {
        // Arrange: asymmetric TX/RX blackout with production 25 s keepalive cadence
        let b_ep: SocketAddr = "198.51.100.44:51820".parse().expect("ep");
        let (mut map_a, mut disco_a, _map_b, _disco_b, _id_a, id_b, _pub_a, _pub_b) =
            setup_pair(b_ep);
        assert!(map_a.set_direct_path(&id_b, b_ep, CandidateSource::Reflexive, 12, 10_000));
        {
            let sess = map_a.get_mut(&id_b).expect("b");
            sess.last_tx_at_ms = 10_000;
            sess.last_rx_at_ms = 10_000;
        }

        // Act: step 250 ms Disco ticks while outbound TX continues and RX stalls at t=10_000
        let blackout_start_ms = 10_000u64;
        let mut failover_at_ms = None;
        let mut now_ms = blackout_start_ms + 250;
        while now_ms <= blackout_start_ms + 10_000 {
            map_a.get_mut(&id_b).expect("b").last_tx_at_ms = now_ms;
            drop(disco_a.tick(&mut map_a, now_ms));
            if map_a.get(&id_b).expect("b").active_path == PeerActivePath::Relay {
                failover_at_ms = Some(now_ms);
                break;
            }
            now_ms += 250;
        }

        // Assert: asymmetric traffic triggers Fast Suspect Probe failover in <= 10 s (4.5-8 s)
        let tripped_at = failover_at_ms.expect("fast suspect failover should fire within 10 s");
        let elapsed_ms = tripped_at.saturating_sub(blackout_start_ms);
        assert!(
            elapsed_ms <= 10_000,
            "elapsed {elapsed_ms} ms exceeded 10 s"
        );
        assert!(elapsed_ms >= 4_500, "elapsed {elapsed_ms} ms too short");
        assert_eq!(disco_a.metrics_snapshot().direct_failovers, 1);

        // Arrange part 2: once missed_direct_pongs >= 1 even without TX asymmetry, fast probes run
        let (mut map_2, mut disco_2, _map_b2, _disco_b2, _ia2, id_b2, _pa2, _pb2) =
            setup_pair(b_ep);
        assert!(map_2.set_direct_path(&id_b2, b_ep, CandidateSource::Reflexive, 12, 1_000));
        {
            let sess = map_2.get_mut(&id_b2).expect("b2");
            sess.last_tx_at_ms = 25_000;
            sess.last_rx_at_ms = 25_000;
        }
        let first_ping = disco_2.tick(&mut map_2, 25_000);
        assert_eq!(first_ping.len(), 1);
        let mut second_failover_at = None;
        let mut t = 25_250u64;
        while t <= 35_000 {
            drop(disco_2.tick(&mut map_2, t));
            if map_2.get(&id_b2).expect("b2").active_path == PeerActivePath::Relay {
                second_failover_at = Some(t);
                break;
            }
            t += 250;
        }
        let elapsed_second = second_failover_at
            .expect("missed_direct_pongs >= 1 fast suspect failover must fire <= 10 s")
            .saturating_sub(25_000);
        assert!(
            elapsed_second <= 10_000,
            "second elapsed {elapsed_second} ms exceeded 10 s"
        );
    }

    // Traces: US-021 AC3
    proptest! {
        #[test]
        fn test_proptest_demux_and_disco_engine_never_panic_on_fuzzed_packets(
            payload in proptest::collection::vec(any::<u8>(), 0..=2048)
        ) {
            let dk = DiscoKeypair::generate();
            let kp = NodeKeypair::generate();
            let mut peer_map = PeerMap::new(NodeId::from_bytes([9; 16]), kp);
            let mut disco = DiscoEngine::new(dk, DiscoConfig::default());
            let ctx = test_filter_ctx();
            let remote: SocketAddr = "198.51.100.77:51820".parse().expect("ep");

            let demuxed = demux_packet(&payload);
            let starts_with_disco = payload.len() >= MIN_DISCO_PACKET_LEN
                && payload.get(..6) == Some(b"MESHDS".as_slice())
                && payload.get(6).copied() == Some(DISCO_PROTOCOL_VERSION);

            if starts_with_disco {
                prop_assert!(matches!(demuxed, DemuxPacket::Disco(_)));
            }
            if matches!(demuxed, DemuxPacket::WireGuard(_)) {
                prop_assert!(!starts_with_disco);
            }

            let filter = DiscoFilterContext {
                candidates: &ctx,
                excluded_stun: &[],
            };
            let (_event, _outbound) = disco.handle_incoming(
                &payload,
                IngressSource::DirectUdp(remote),
                &mut peer_map,
                &filter,
                50_000,
            );
        }
    }

    // Traces: BLK-W12-02
    #[test]
    fn test_interactive_probes_do_not_trigger_direct_failover_and_track_pong_tx_id() {
        // Arrange
        let remote_ep: SocketAddr = "203.0.113.45:51820".parse().expect("ep");
        let (mut map_a, mut disco_a, mut map_b, mut disco_b, id_a, id_b, _, _) =
            setup_pair(remote_ep);
        let ctx = test_filter_ctx();
        let filter = DiscoFilterContext {
            candidates: &ctx,
            excluded_stun: &[],
        };

        // Promote B to Direct on A via normal hole punch.
        let punch = disco_a.initiate_hole_punch(&map_a, id_b, &[], &filter, 1_000);
        let ping_pkt = punch
            .into_iter()
            .find(|p| matches!(p.target, PeerSendTarget::Direct(_)))
            .expect("direct punch");
        let (_, pong_out) = disco_b.handle_incoming(
            &ping_pkt.bytes,
            IngressSource::DirectUdp(remote_ep),
            &mut map_b,
            &filter,
            1_010,
        );
        let pong = pong_out.first().expect("pong");
        let _ignored = disco_a.handle_incoming(
            &pong.bytes,
            IngressSource::DirectUdp(remote_ep),
            &mut map_a,
            &filter,
            1_020,
        );
        assert!(matches!(
            map_a.get(&id_b).expect("peer b").active_path,
            PeerActivePath::Direct { .. }
        ));

        // Act 1: issue 5 timed-out interactive probes -> MUST NOT fail over Direct -> Relay.
        for step in 0..5u64 {
            let built = disco_a.build_interactive_probes(
                &map_a,
                &filter,
                InteractivePingRequest {
                    peer_id: id_b,
                    force_direct: false,
                    now_ms: 2_000 + step * 5_000,
                    timeout_ms: 1_000,
                },
            );
            assert_eq!(built.len(), 1);
            let _ticks = disco_a.tick(&mut map_a, 3_500 + step * 5_000);
        }
        assert!(matches!(
            map_a.get(&id_b).expect("peer b").active_path,
            PeerActivePath::Direct { .. }
        ));

        // Act 2: build 1 interactive probe and deliver Pong -> handle_incoming_tracked returns Some(tx_id).
        let live = disco_a.build_interactive_probes(
            &map_a,
            &filter,
            InteractivePingRequest {
                peer_id: id_b,
                force_direct: false,
                now_ms: 30_000,
                timeout_ms: 1_000,
            },
        );
        let (expected_tx_id, outbound_ping) = live.first().expect("live ping");
        let (_, pong_pkts) = disco_b.handle_incoming(
            &outbound_ping.bytes,
            IngressSource::DirectUdp(remote_ep),
            &mut map_b,
            &filter,
            30_010,
        );
        let (ev, matched_tx, _) = disco_a.handle_incoming_tracked(
            &pong_pkts.first().expect("pong").bytes,
            IngressSource::DirectUdp(remote_ep),
            &mut map_a,
            &filter,
            30_025,
        );

        // Assert
        assert!(matches!(
            ev,
            DiscoEvent::DirectPathVerified { peer_id, .. } if peer_id == id_b
        ));
        assert_eq!(matched_tx, Some(*expected_tx_id));
        let _unused = id_a;
    }

    // Traces: US-030
    #[test]
    fn test_disco_remove_peers_purges_trackers_and_pending_pings() {
        // Arrange
        let dk_a = DiscoKeypair::generate();
        let dk_b = DiscoKeypair::generate();
        let id_a = NodeId::from_bytes([11u8; 16]);
        let id_b = NodeId::from_bytes([22u8; 16]);
        let mut map_a = PeerMap::new(id_a, NodeKeypair::generate());
        let ep: SocketAddr = "198.51.100.12:51820".parse().expect("ep");
        map_a.apply_diff(&NetmapSnapshot {
            netmap_version: 1,
            generated_at_ms: 1000,
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: mesh_proto::netmap::RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: vec![],
            },
            pin_set: mesh_proto::netmap::PinSetDto {
                active_pin: mesh_core::SpkiPin::from_sha256_bytes([1u8; 32]),
                next_pin: None,
            },
            peers: vec![PeerEntry {
                node_id: id_b,
                name: NodeName::parse("peer-b").expect("name"),
                fqdn: "peer-b.mesh.internal".to_owned(),
                overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 2)).expect("ip"),
                node_pubkey: NodeKeypair::generate().public_key(),
                disco_pubkey: dk_b.public_key(),
                endpoints: vec![CandidateEndpoint {
                    addr: ep,
                    source: CandidateSource::Reflexive,
                }],
                relay_home: "203.0.113.10:8443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            }],
        });

        let mut disco_a = DiscoEngine::new(dk_a, DiscoConfig::default());
        let cand_ctx = CandidateFilterContext {
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            control_tcp_endpoint: None,
            stun_udp_endpoint: None,
        };
        let filter = DiscoFilterContext {
            candidates: &cand_ctx,
            excluded_stun: &[],
        };
        let built = disco_a.build_interactive_probes(
            &map_a,
            &filter,
            InteractivePingRequest {
                peer_id: id_b,
                force_direct: true,
                now_ms: 1_000,
                timeout_ms: 500,
            },
        );
        assert_eq!(built.len(), 1);
        disco_a.per_peer.entry(id_b).or_default();
        assert!(!disco_a.pending_pings.is_empty());

        // Act
        disco_a.remove_peers(&[id_b]);

        // Assert
        assert!(!disco_a.per_peer.contains_key(&id_b));
        assert!(disco_a.pending_pings.is_empty());
    }
}
