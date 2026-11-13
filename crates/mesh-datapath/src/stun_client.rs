//! Shared-socket RFC 5389 STUN client, honest NAT classification, and endpoint candidate filtering.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::lookup_host;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use mesh_core::AppResult;
use mesh_core::clock::Clock;
use mesh_crypto::random_bytes;
use mesh_net::endpoint_filter::{
    CandidateFilterContext, DiscoveredInterfaceEndpoint, is_valid_candidate_endpoint,
    is_virtual_interface_name,
};
use mesh_proto::DemuxPacket;
use mesh_proto::disco::MAX_DISCO_ENDPOINTS;
use mesh_proto::netmap::{CandidateEndpoint, CandidateSource, NatMappingKind, RelayMap};
use mesh_proto::stun::{STUN_BINDING_SUCCESS_RESPONSE, encode_binding_request, parse_stun_packet};

use crate::magic_socket::{MAGIC_SOCKET_BUFFER_SIZE, MagicSocket, PacketBuffer};

/// Default STUN probe timeout (`<= 5 s` per `US-019 AC3`).
pub const DEFAULT_STUN_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum allowed STUN probe timeout per `US-019 AC3`.
pub const MAX_STUN_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration parameters for [`StunClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunClientConfig {
    /// Total timeout waiting for responses from `stun_udp_endpoints` (capped at `<= 5 s`).
    pub probe_timeout: Duration,
}

impl Default for StunClientConfig {
    fn default() -> Self {
        Self {
            probe_timeout: DEFAULT_STUN_PROBE_TIMEOUT,
        }
    }
}

impl StunClientConfig {
    /// Creates a config with bounded STUN timeout (`<= 5 s`).
    #[must_use]
    pub fn with_timeout(probe_timeout: Duration) -> Self {
        let clamped = if probe_timeout > MAX_STUN_PROBE_TIMEOUT {
            MAX_STUN_PROBE_TIMEOUT
        } else {
            probe_timeout
        };
        Self {
            probe_timeout: clamped,
        }
    }
}

/// Outbound STUN transaction tracked until matched once or expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingStunTx {
    target_endpoint: SocketAddr,
    sent_at_ms: u64,
    expires_at_ms: u64,
}

/// Single verified STUN reflexive mapping observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunObservation {
    /// STUN server UDP endpoint that returned the Binding Response.
    pub server_endpoint: SocketAddr,
    /// Reflexive IP:port reported by that STUN endpoint.
    pub mapped_addr: SocketAddr,
    /// Measured round-trip time in milliseconds.
    pub rtt_ms: u64,
}

/// Result of evaluating NAT reachability and mapping behavior across `stun_udp_endpoints`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunProbeReport {
    /// True when UDP STUN received no valid answers (`US-019 AC3`: fall back to Blind Relay).
    pub udp_blocked: bool,
    /// Honest NAT mapping behavior derived from collected observations (`US-019 AC2`).
    pub nat_mapping: NatMappingKind,
    /// True when all configured/responding STUN endpoints share one IP (cannot distinguish EIM/ADM).
    pub single_stun_ip_mode: bool,
    /// Human-readable note describing caveats such as `single_stun_ip_mode` or UDP block.
    pub nat_note: String,
    /// All verified reflexive observations collected in the current probe round.
    pub observations: Vec<StunObservation>,
    /// Deduplicated valid reflexive `SocketAddr`s discovered in this round.
    pub reflexive_addrs: Vec<SocketAddr>,
    /// Minimum observed STUN RTT in milliseconds, if any STUN server replied.
    pub best_rtt_ms: Option<u64>,
}

impl Default for StunProbeReport {
    fn default() -> Self {
        Self {
            udp_blocked: true,
            nat_mapping: NatMappingKind::Unknown,
            single_stun_ip_mode: true,
            nat_note: "stun probe not yet executed".to_owned(),
            observations: Vec::new(),
            reflexive_addrs: Vec::new(),
            best_rtt_ms: None,
        }
    }
}

/// Stateful sans-I/O STUN probe tracker and shared-socket async probe runner (`US-019`, `US-020`).
#[derive(Debug)]
pub struct StunClient {
    config: StunClientConfig,
    raw_endpoints: Vec<String>,
    resolved_endpoints: Vec<SocketAddr>,
    pending_txs: HashMap<[u8; 12], PendingStunTx>,
    current_round_observations: Vec<StunObservation>,
    last_report: StunProbeReport,
}

impl StunClient {
    /// Creates a `StunClient` with default bounded timeouts (`<= 5 s`).
    #[must_use]
    pub fn new(config: StunClientConfig) -> Self {
        Self {
            config,
            raw_endpoints: Vec::new(),
            resolved_endpoints: Vec::new(),
            pending_txs: HashMap::new(),
            current_round_observations: Vec::new(),
            last_report: StunProbeReport::default(),
        }
    }

    /// Returns the most recent completed NAT/STUN report.
    #[must_use]
    pub fn last_report(&self) -> &StunProbeReport {
        &self.last_report
    }

    /// Returns the currently resolved STUN UDP endpoints derived from `RelayMap`.
    #[must_use]
    pub fn tracked_endpoints(&self) -> &[SocketAddr] {
        &self.resolved_endpoints
    }

    /// Synchronizes STUN UDP targets from literal `ip:port` strings in `RelayMap` without DNS I/O.
    ///
    /// Returns `true` if `stun_udp_endpoints` changed and callers should run a fresh STUN probe.
    pub fn sync_relay_map(&mut self, relay_map: &RelayMap) -> bool {
        if self.raw_endpoints == relay_map.stun_udp_endpoints {
            return false;
        }
        self.raw_endpoints.clone_from(&relay_map.stun_udp_endpoints);
        let mut parsed = Vec::new();
        for raw in &relay_map.stun_udp_endpoints {
            if let Ok(addr) = raw.parse::<SocketAddr>()
                && !parsed.contains(&addr)
            {
                parsed.push(addr);
            }
        }
        self.apply_resolved_endpoints(parsed);
        true
    }

    /// Returns `true` if `endpoints` contains any non-literal hostname requiring background DNS lookup.
    #[must_use]
    pub fn has_unresolved_hostnames(endpoints: &[String]) -> bool {
        endpoints
            .iter()
            .any(|raw| raw.parse::<SocketAddr>().is_err())
    }

    /// Applies background-resolved DNS `SocketAddr`s only when `raw_endpoints` still matches the
    /// active `RelayMap` list, returning `true` when `tracked_endpoints` changed (`HR-W21-07`).
    pub fn apply_resolved_endpoints_for_raw(
        &mut self,
        raw_endpoints: &[String],
        resolved: Vec<SocketAddr>,
    ) -> bool {
        if self.raw_endpoints != raw_endpoints {
            return false;
        }
        if self.resolved_endpoints == resolved {
            return false;
        }
        self.apply_resolved_endpoints(resolved);
        true
    }

    /// Resolves hostnames/ports in `relay_map.stun_udp_endpoints` asynchronously (bounded to 5 s).
    pub async fn sync_and_resolve_relay_map(&mut self, relay_map: &RelayMap) -> bool {
        let changed = self.raw_endpoints != relay_map.stun_udp_endpoints;
        if !changed
            && (!self.resolved_endpoints.is_empty()
                || !Self::has_unresolved_hostnames(&self.raw_endpoints))
        {
            return false;
        }
        self.raw_endpoints.clone_from(&relay_map.stun_udp_endpoints);
        let resolved = resolve_endpoint_strings(&relay_map.stun_udp_endpoints).await;
        self.apply_resolved_endpoints(resolved);
        changed
    }

    fn apply_resolved_endpoints(&mut self, resolved: Vec<SocketAddr>) {
        self.resolved_endpoints = resolved;
        let active_set: HashSet<SocketAddr> = self.resolved_endpoints.iter().copied().collect();
        self.pending_txs
            .retain(|_, tx| active_set.contains(&tx.target_endpoint));
        info!(
            component = "datapath.stun_client",
            event = "stun_endpoints_updated",
            count = self.resolved_endpoints.len(),
            "updated tracked STUN UDP endpoints from RelayMap"
        );
    }

    /// Prepares one STUN Binding Request per resolved endpoint for sans-I/O transmission.
    pub fn start_probe_round(
        &mut self,
        relay_map: &RelayMap,
        now_ms: u64,
    ) -> Vec<(SocketAddr, [u8; 28])> {
        let _ = self.sync_relay_map(relay_map);
        self.start_probe_for_resolved(now_ms)
    }

    /// Prepares a STUN Binding Request round over already-tracked resolved endpoints without
    /// altering cached raw `RelayMap` strings (`HR-W21-07`).
    pub fn start_probe_round_tracked(&mut self, now_ms: u64) -> Vec<(SocketAddr, [u8; 28])> {
        self.start_probe_for_resolved(now_ms)
    }

    fn start_probe_for_resolved(&mut self, now_ms: u64) -> Vec<(SocketAddr, [u8; 28])> {
        self.pending_txs.clear();
        self.current_round_observations.clear();

        let timeout_ms = u64::try_from(self.config.probe_timeout.as_millis()).unwrap_or(5_000);
        let expires_at_ms = now_ms.saturating_add(timeout_ms);
        let mut outbound = Vec::with_capacity(self.resolved_endpoints.len());

        for &endpoint in &self.resolved_endpoints {
            let tx_id: [u8; 12] = random_bytes::<12>();
            let packet = encode_binding_request(tx_id);
            self.pending_txs.insert(
                tx_id,
                PendingStunTx {
                    target_endpoint: endpoint,
                    sent_at_ms: now_ms,
                    expires_at_ms,
                },
            );
            outbound.push((endpoint, packet));
        }

        outbound
    }

    /// Processes a demultiplexed STUN packet arriving from `remote_addr` (`sans-I/O`).
    ///
    /// Consumes matching `tx_id` once to prevent replay or unsolicited spoofing.
    pub fn handle_incoming_stun(
        &mut self,
        packet: &[u8],
        remote_addr: SocketAddr,
        now_ms: u64,
    ) -> Option<StunObservation> {
        let parsed = match parse_stun_packet(packet) {
            Ok(msg) => msg,
            Err(err) => {
                warn!(
                    component = "datapath.stun_client",
                    event = "malformed_stun_dropped",
                    remote = %remote_addr,
                    error = %err,
                    "dropping malformed STUN packet"
                );
                return None;
            }
        };

        if parsed.msg_type != STUN_BINDING_SUCCESS_RESPONSE {
            return None;
        }

        let tx = self.pending_txs.remove(&parsed.tx_id)?;
        if now_ms > tx.expires_at_ms {
            return None;
        }
        if tx.target_endpoint != remote_addr {
            warn!(
                component = "datapath.stun_client",
                event = "stun_source_mismatch",
                expected = %tx.target_endpoint,
                observed = %remote_addr,
                "dropping STUN response from unexpected source endpoint"
            );
            return None;
        }

        let mapped_addr = parsed.xor_mapped_addr?;
        let rtt_ms = now_ms.saturating_sub(tx.sent_at_ms);
        let obs = StunObservation {
            server_endpoint: remote_addr,
            mapped_addr,
            rtt_ms,
        };
        self.current_round_observations.push(obs);
        Some(obs)
    }

    /// Evicts expired pending STUN transactions and finalizes the current `StunProbeReport`.
    pub fn finish_probe_round(&mut self, now_ms: u64) -> StunProbeReport {
        self.pending_txs.retain(|_, tx| tx.expires_at_ms > now_ms);
        let report =
            classify_observations(&self.current_round_observations, &self.resolved_endpoints);
        self.last_report = report.clone();
        if report.udp_blocked {
            warn!(
                component = "datapath.stun_client",
                event = "stun_udp_blocked",
                endpoints = self.resolved_endpoints.len(),
                "no STUN Binding Response received before timeout; marking UDP unavailable and using Relay"
            );
        }
        report
    }

    /// Returns true while one or more STUN transactions in the active round remain unanswered.
    #[must_use]
    pub fn has_pending_requests(&self) -> bool {
        !self.pending_txs.is_empty()
    }

    /// Returns `true` when every STUN transaction has either answered or reached `expires_at_ms` (`HR-S1-08`).
    #[must_use]
    pub fn is_probe_round_ready(&self, now_ms: u64) -> bool {
        self.pending_txs.is_empty()
            || self
                .pending_txs
                .values()
                .all(|tx| now_ms >= tx.expires_at_ms)
    }

    /// Runs a standalone bounded STUN probe over `magic_socket` (`<= 5 s`) without blocking on
    /// UDP-blackholed networks (`US-019 AC3`).
    pub async fn probe_blocking(
        &mut self,
        magic_socket: &MagicSocket,
        relay_map: &RelayMap,
        clock: &dyn Clock,
    ) -> AppResult<StunProbeReport> {
        let _ = self.sync_and_resolve_relay_map(relay_map).await;
        let requests = self.start_probe_for_resolved(clock.now_unix_ms());
        if requests.is_empty() {
            return Ok(self.finish_probe_round(clock.now_unix_ms()));
        }

        for (target, pkt) in requests {
            if let Err(err) = magic_socket.send_to(&pkt, target).await {
                warn!(
                    component = "datapath.stun_client",
                    event = "stun_send_failed",
                    target = %target,
                    error = %err,
                    "failed to send STUN Binding Request"
                );
            }
        }

        let deadline = Instant::now() + self.config.probe_timeout;
        let mut buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];

        while self.has_pending_requests() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            match tokio::time::timeout(remaining, magic_socket.recv_demuxed(&mut buf)).await {
                Ok(Ok((peer, DemuxPacket::Stun(raw)))) => {
                    let _ = self.handle_incoming_stun(raw, peer, clock.now_unix_ms());
                }
                Ok(Ok(_non_stun)) => {}
                Ok(Err(err)) => {
                    warn!(
                        component = "datapath.stun_client",
                        event = "stun_recv_error",
                        error = %err,
                        "UDP receive error during STUN probe"
                    );
                    break;
                }
                Err(_elapsed) => break,
            }
        }

        Ok(self.finish_probe_round(clock.now_unix_ms()))
    }
}

/// Resolves `stun_udp_endpoints` concurrently with an overall `<= 5 s` deadline and immediate
/// cooperative cancellation via `cancel` (`HR-W21-07`).
pub(crate) async fn resolve_stun_endpoints_cancellable(
    endpoints: &[String],
    cancel: &CancellationToken,
) -> Vec<SocketAddr> {
    let mut resolved = Vec::new();
    let mut hostnames = Vec::new();
    for raw in endpoints {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        } else {
            hostnames.push(raw.clone());
        }
    }
    if hostnames.is_empty() {
        return resolved;
    }

    let mut join_set = JoinSet::new();
    for host in hostnames {
        let child = cancel.child_token();
        join_set.spawn(async move {
            tokio::select! {
                () = child.cancelled() => Vec::new(),
                res = tokio::time::timeout(MAX_STUN_PROBE_TIMEOUT, lookup_host(host)) => {
                    match res {
                        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
                        _ => Vec::new(),
                    }
                }
            }
        });
    }

    let deadline = tokio::time::sleep(MAX_STUN_PROBE_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                join_set.abort_all();
                break;
            }
            () = &mut deadline => {
                join_set.abort_all();
                break;
            }
            next = join_set.join_next() => {
                match next {
                    Some(Ok(addrs)) => {
                        for addr in addrs {
                            if !resolved.contains(&addr) {
                                resolved.push(addr);
                            }
                        }
                    }
                    Some(Err(_)) => {}
                    None => break,
                }
            }
        }
    }
    resolved
}

async fn resolve_endpoint_strings(endpoints: &[String]) -> Vec<SocketAddr> {
    let cancel = CancellationToken::new();
    resolve_stun_endpoints_cancellable(endpoints, &cancel).await
}

/// Classifies NAT mapping honestly from STUN observations (`US-019 AC2`).
#[must_use]
pub fn classify_observations(
    observations: &[StunObservation],
    configured_endpoints: &[SocketAddr],
) -> StunProbeReport {
    if observations.is_empty() {
        return StunProbeReport {
            udp_blocked: true,
            nat_mapping: NatMappingKind::Unknown,
            single_stun_ip_mode: has_at_most_one_unique_ip(
                configured_endpoints.iter().map(|s| s.ip()),
            ),
            nat_note: "UDP unreachable or all STUN probes timed out; Relay path active".to_owned(),
            observations: Vec::new(),
            reflexive_addrs: Vec::new(),
            best_rtt_ms: None,
        };
    }

    let unique_responder_ips: HashSet<IpAddr> = observations
        .iter()
        .map(|o| o.server_endpoint.ip())
        .collect();
    let single_stun_ip_mode = unique_responder_ips.len() <= 1;

    let mut unique_reflexive: Vec<SocketAddr> = Vec::new();
    let mut best_rtt_ms: Option<u64> = None;
    for obs in observations {
        if !unique_reflexive.contains(&obs.mapped_addr) {
            unique_reflexive.push(obs.mapped_addr);
        }
        best_rtt_ms = Some(best_rtt_ms.map_or(obs.rtt_ms, |best| best.min(obs.rtt_ms)));
    }

    let (nat_mapping, nat_note) = if unique_reflexive.len() > 1 {
        let qualifier = if single_stun_ip_mode {
            "single_stun_ip_mode: multiple ports mapped to different external ports (hard NAT)"
        } else {
            "distinct STUN servers observed different mapped ports (hard NAT / symmetric)"
        };
        (NatMappingKind::PortDependent, qualifier.to_owned())
    } else if single_stun_ip_mode {
        (
            NatMappingKind::EimOrAdm,
            "single_stun_ip_mode: cannot distinguish EIM vs ADM with one STUN IP".to_owned(),
        )
    } else {
        (
            NatMappingKind::EimOrAdm,
            "multi-IP STUN probes returned consistent reflexive mapping (EIM)".to_owned(),
        )
    };

    StunProbeReport {
        udp_blocked: false,
        nat_mapping,
        single_stun_ip_mode,
        nat_note,
        observations: observations.to_vec(),
        reflexive_addrs: unique_reflexive,
        best_rtt_ms,
    }
}

fn has_at_most_one_unique_ip(ips: impl Iterator<Item = IpAddr>) -> bool {
    let mut seen: HashSet<IpAddr> = HashSet::new();
    for ip in ips {
        seen.insert(ip);
        if seen.len() > 1 {
            return false;
        }
    }
    true
}

/// Collects, filters, deduplicates, and sorts local LAN, IPv6, and STUN reflexive candidates
/// in priority order `Lan > Ipv6 > Reflexive` (`US-020`).
#[must_use]
pub fn collect_and_sort_candidates(
    interface_endpoints: &[DiscoveredInterfaceEndpoint],
    reflexive_addrs: &[SocketAddr],
    excluded_stun_endpoints: &[SocketAddr],
    filter_ctx: &CandidateFilterContext,
) -> Vec<CandidateEndpoint> {
    let mut lan = Vec::new();
    let mut ipv6 = Vec::new();
    let mut reflexive = Vec::new();
    let mut seen = HashSet::new();

    for item in interface_endpoints {
        if let Some(ref name) = item.interface_name
            && is_virtual_interface_name(name)
        {
            continue;
        }
        if excluded_stun_endpoints.contains(&item.endpoint)
            || !is_valid_candidate_endpoint(
                item.endpoint,
                item.interface_name.as_deref(),
                filter_ctx,
            )
        {
            continue;
        }
        if !seen.insert(item.endpoint) {
            continue;
        }
        if item.endpoint.is_ipv6() {
            ipv6.push(CandidateEndpoint {
                addr: item.endpoint,
                source: CandidateSource::Ipv6,
            });
        } else {
            lan.push(CandidateEndpoint {
                addr: item.endpoint,
                source: CandidateSource::Lan,
            });
        }
    }

    for &addr in reflexive_addrs {
        if excluded_stun_endpoints.contains(&addr)
            || !is_valid_candidate_endpoint(addr, None, filter_ctx)
        {
            continue;
        }
        if !seen.insert(addr) {
            continue;
        }
        reflexive.push(CandidateEndpoint {
            addr,
            source: CandidateSource::Reflexive,
        });
    }

    let mut ordered = Vec::with_capacity(MAX_DISCO_ENDPOINTS);
    for candidate in lan.into_iter().chain(ipv6).chain(reflexive) {
        if ordered.len() >= MAX_DISCO_ENDPOINTS {
            break;
        }
        ordered.push(candidate);
    }
    ordered
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use mesh_core::clock::FakeClock;
    use mesh_core::{OverlayCidr, Port};
    use mesh_proto::stun::encode_binding_success_response;

    use super::*;
    use crate::magic_socket::MagicSocketConfig;

    fn sample_relay_map(stun_endpoints: Vec<SocketAddr>) -> RelayMap {
        RelayMap {
            endpoint_version: 1,
            control_tcp_endpoint: "127.0.0.1:14430".to_owned(),
            relay_tcp_endpoint: "127.0.0.1:14430".to_owned(),
            stun_udp_endpoints: stun_endpoints.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    fn filter_ctx(
        stun_udp_endpoint: Option<SocketAddr>,
        control_tcp: Option<SocketAddr>,
    ) -> CandidateFilterContext {
        CandidateFilterContext {
            overlay_cidr: "10.100.0.0/16".parse::<OverlayCidr>().expect("cidr"),
            stun_udp_endpoint,
            control_tcp_endpoint: control_tcp,
        }
    }

    // Traces: US-019 AC2/AC3
    #[tokio::test]
    async fn test_stun_client_udp_blocked_times_out_cleanly_without_blocking() {
        // Arrange: bind an unused UDP port that never responds
        let blackhole = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("bind blackhole");
        let blackhole_addr = blackhole.local_addr().expect("blackhole addr");
        drop(blackhole);

        let client_sock = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("bind client");
        let clock = FakeClock::new(10_000);
        let mut stun = StunClient::new(StunClientConfig::with_timeout(Duration::from_millis(80)));
        let relay_map = sample_relay_map(vec![blackhole_addr]);

        // Act
        let report = stun
            .probe_blocking(&client_sock, &relay_map, &clock)
            .await
            .expect("probe returns");

        // Assert
        assert!(report.udp_blocked);
        assert_eq!(report.nat_mapping, NatMappingKind::Unknown);
        assert!(report.reflexive_addrs.is_empty());
    }

    // Traces: US-019 AC2/AC5
    #[tokio::test]
    async fn test_stun_client_probes_local_mock_stun_and_detects_single_ip_hard_nat() {
        // Arrange: two STUN UDP server ports on the same IP returning distinct mapped ports
        let srv1 = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("srv1");
        let srv2 = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("srv2");
        let addr1 = srv1.local_addr().expect("addr1");
        let addr2 = srv2.local_addr().expect("addr2");

        let client_sock = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("client sock");

        let srv_task = tokio::spawn(async move {
            let mut b1 = [0u8; 256];
            let (n1, src1) = srv1.recv_from(&mut b1).await.expect("recv1");
            let msg1 = parse_stun_packet(b1.get(..n1).expect("slice1")).expect("stun1");
            let rsp1 = encode_binding_success_response(
                msg1.tx_id,
                SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 40_001)),
            );
            srv1.send_to(&rsp1, src1).await.expect("send1");

            let mut b2 = [0u8; 256];
            let (n2, src2) = srv2.recv_from(&mut b2).await.expect("recv2");
            let msg2 = parse_stun_packet(b2.get(..n2).expect("slice2")).expect("stun2");
            let rsp2 = encode_binding_success_response(
                msg2.tx_id,
                SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 40_002)),
            );
            srv2.send_to(&rsp2, src2).await.expect("send2");
        });

        let clock = FakeClock::new(20_000);
        let mut stun = StunClient::new(StunClientConfig::with_timeout(Duration::from_secs(1)));
        let rmap = sample_relay_map(vec![addr1, addr2]);

        // Act
        let report = stun
            .probe_blocking(&client_sock, &rmap, &clock)
            .await
            .expect("probe ok");
        srv_task.await.expect("server task ok");

        // Assert
        assert!(!report.udp_blocked);
        assert!(report.single_stun_ip_mode);
        assert_eq!(report.nat_mapping, NatMappingKind::PortDependent);
        assert!(report.nat_note.contains("single_stun_ip_mode"));
        assert_eq!(report.reflexive_addrs.len(), 2);

        // Act & Assert dynamic RelayMap update triggers refresh
        let rmap_updated = sample_relay_map(vec![addr1]);
        assert!(stun.sync_relay_map(&rmap_updated));
        assert!(!stun.sync_relay_map(&rmap_updated));
    }

    // Traces: US-020
    #[test]
    fn test_candidate_collection_orders_lan_ipv6_reflexive_and_allows_tcp_control_port() {
        // Arrange
        let stun_ep = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 13478));
        let control_tcp = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 14430));
        let ctx = filter_ctx(Some(stun_ep), Some(control_tcp));

        let interfaces = vec![
            DiscoveredInterfaceEndpoint {
                interface_name: Some("utun3".to_owned()),
                endpoint: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 50), 51820)),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 51820)),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::from((Ipv4Addr::new(192, 168, 1, 20), 51820)),
            },
        ];
        // Note: matching control TCP port (14430) on different IP is NOT a STUN UDP endpoint
        let reflexive = vec![
            stun_ep,
            SocketAddr::from((
                Ipv4Addr::new(198, 51, 100, 99),
                Port::from_u16(14430).expect("p").get(),
            )),
        ];

        // Act
        let ordered = collect_and_sort_candidates(&interfaces, &reflexive, &[stun_ep], &ctx);

        // Assert: order is Lan > Ipv6 > Reflexive; utun3 and stun_ep were filtered out
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered.first().expect("0").source, CandidateSource::Lan);
        assert_eq!(ordered.get(1).expect("1").source, CandidateSource::Ipv6);
        let reflexive_cand = ordered.get(2).expect("2");
        assert_eq!(reflexive_cand.source, CandidateSource::Reflexive);
        assert_eq!(reflexive_cand.addr.port(), 14430);
    }

    // Traces: US-019, HR-S1-08
    #[test]
    fn test_stun_slow_400ms_reply_not_truncated_by_250ms_ticks_and_populates_report() {
        // Arrange
        let stun_ep: SocketAddr = "203.0.113.55:13478".parse().expect("stun ep");
        let mapped: SocketAddr = "198.51.100.77:42000".parse().expect("mapped");
        let rmap = sample_relay_map(vec![stun_ep]);
        let mut stun = StunClient::new(StunClientConfig::with_timeout(Duration::from_secs(2)));

        let requests = stun.start_probe_round(&rmap, 10_000);
        assert_eq!(requests.len(), 1);
        let req_bytes = &requests.first().expect("req").1;
        let parsed_req = parse_stun_packet(req_bytes).expect("valid stun req");

        // Act & Assert 1: 250 ms tick is too early to abort a pending 2 s STUN probe round
        assert!(stun.has_pending_requests());
        assert!(!stun.is_probe_round_ready(10_250));

        // Act & Assert 2: 400 ms delayed STUN response matches cleanly and clears pending set
        let rsp = encode_binding_success_response(parsed_req.tx_id, mapped);
        let obs = stun
            .handle_incoming_stun(&rsp, stun_ep, 10_400)
            .expect("400 ms STUN reply accepted");
        assert_eq!(obs.rtt_ms, 400);
        assert_eq!(obs.mapped_addr, mapped);
        assert!(!stun.has_pending_requests());
        assert!(stun.is_probe_round_ready(10_400));

        let report = stun.finish_probe_round(10_400);
        assert!(!report.udp_blocked);
        assert_eq!(report.reflexive_addrs, vec![mapped]);
        assert_eq!(report.best_rtt_ms, Some(400));
        assert_eq!(report.nat_mapping, NatMappingKind::EimOrAdm);

        // Act & Assert 3: unresponsive probe waits full 2 s timeout before declaring udp_blocked
        drop(stun.start_probe_round(&rmap, 20_000));
        assert!(!stun.is_probe_round_ready(21_999));
        assert!(stun.is_probe_round_ready(22_000));
        let timed_out_report = stun.finish_probe_round(22_000);
        assert!(timed_out_report.udp_blocked);
        assert!(!stun.has_pending_requests());
    }
}
