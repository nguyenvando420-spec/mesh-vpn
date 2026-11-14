//! Full WireGuard/Disco/Relay data-plane runtime loop and `DatapathEngine` (`US-026`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use mesh_core::clock::Clock;
use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, AppResult, NodeId, OverlayCidr, OverlayIp, PublicKey};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use mesh_net::endpoint_filter::CandidateFilterContext;
use mesh_net::tun::TunDevice;
use mesh_proto::disco::IngressSource;
use mesh_proto::netmap::{NatMappingKind, NetmapSnapshot};
use mesh_proto::{DemuxPacket, demux_packet};

use crate::cryptokey::{CryptokeyMetricsSnapshot, CryptokeyValidator, PacketFilterPolicy};
use crate::disco_engine::{
    DiscoConfig, DiscoEngine, DiscoEvent, DiscoFilterContext, DiscoMetricsSnapshot,
    InteractivePingRequest, PingProbeOutcome, PingProbePath,
};
use crate::magic_socket::{MAGIC_SOCKET_BUFFER_SIZE, MagicSocket, MagicSocketConfig, PacketBuffer};
use crate::peer_map::{ApplyDiffReport, PeerActivePath, PeerMap, PeerSendTarget};
use crate::rebind::{RebindCommand, RebindOutcome, SocketRebinder};
use crate::relay_client::{RelayClientHandle, RelayConnectionState, RelayEvent};
use crate::stun_client::{
    StunClient, StunClientConfig, StunProbeReport, resolve_stun_endpoints_cancellable,
};

const DEFAULT_WG_TIMER_INTERVAL: Duration = Duration::from_millis(250);
const DEFAULT_DISCO_TICK_INTERVAL: Duration = Duration::from_millis(250);
const DATAPATH_COMMAND_CAPACITY: usize = 64;
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Runtime configuration for [`DatapathEngine`].
pub struct DatapathConfig {
    /// Local node UUID.
    pub local_node_id: NodeId,
    /// Local overlay IPv4 address.
    pub local_overlay_ip: OverlayIp,
    /// Mesh overlay IPv4 CIDR block.
    pub overlay_cidr: OverlayCidr,
    /// Local WireGuard keypair.
    pub node_keypair: NodeKeypair,
    /// Local Disco traversal keypair.
    pub disco_keypair: DiscoKeypair,
    /// MagicSocket binding and MTU settings.
    pub socket_config: MagicSocketConfig,
    /// STUN client timeout configuration (`<= 5 s`).
    pub stun_config: StunClientConfig,
    /// Disco probe/keepalive/backoff configuration.
    pub disco_config: DiscoConfig,
    /// Optional Control HTTPS socket address for candidate filter allowlist (`US-020`).
    pub control_tcp_endpoint: Option<SocketAddr>,
    /// Periodic interval driving WireGuard handshake/keepalive timers (`250 ms`).
    pub wg_timer_interval: Duration,
    /// Periodic interval driving Disco timeout & keepalive ticks (`250 ms`).
    pub disco_tick_interval: Duration,
}

impl std::fmt::Debug for DatapathConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatapathConfig")
            .field("local_node_id", &self.local_node_id)
            .field("local_overlay_ip", &self.local_overlay_ip)
            .field("overlay_cidr", &self.overlay_cidr)
            .field("mtu", &self.socket_config.mtu)
            .finish_non_exhaustive()
    }
}

/// Snapshot of a single peer's active route and byte counters exported for IPC `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatapathPeerStatus {
    /// Peer unique UUID.
    pub node_id: NodeId,
    /// Peer assigned overlay IPv4.
    pub overlay_ip: OverlayIp,
    /// Active forwarding path (`Relay` or `Direct`).
    pub active_path: PeerActivePath,
    /// Total plaintext bytes sent toward this peer.
    pub tx_bytes: u64,
    /// Total validated plaintext bytes received from this peer.
    pub rx_bytes: u64,
}

/// Full immutable diagnostic snapshot of [`DatapathEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatapathStatusSnapshot {
    /// Local UDP socket address currently bound by `MagicSocket`.
    pub local_udp_addr: Option<SocketAddr>,
    /// Current Blind Relay WebSocket state.
    pub relay_state: RelayConnectionState,
    /// Latest applied Netmap snapshot version.
    pub netmap_version: u64,
    /// Observed NAT mapping classification.
    pub nat_mapping: NatMappingKind,
    /// Most recent completed STUN probe report for Control/netcheck consumption (`HR-S1-08`).
    pub last_stun_report: Option<StunProbeReport>,
    /// Cryptokey routing drop counters.
    pub cryptokey_metrics: CryptokeyMetricsSnapshot,
    /// Disco protocol metrics counters.
    pub disco_metrics: DiscoMetricsSnapshot,
    /// Per-peer active path and traffic status.
    pub peers: Vec<DatapathPeerStatus>,
}

/// Control-plane & IPC commands processed inside [`DatapathEngine`]'s single event loop.
#[derive(Debug)]
pub enum DatapathCommand {
    /// Applies a new atomic `NetmapSnapshot` diff to `PeerMap` and syncs STUN targets.
    ApplyNetmap {
        /// New network map snapshot.
        snapshot: Box<NetmapSnapshot>,
        /// Optional completion channel returning `ApplyDiffReport`.
        reply: Option<oneshot::Sender<ApplyDiffReport>>,
    },
    /// Updates advertised local candidate addresses sent inside outgoing `CallMeMaybe` messages.
    SetAdvertisedEndpoints(Vec<SocketAddr>),
    /// Immediately starts an asynchronous STUN probe round across `RelayMap` STUN endpoints.
    TriggerStunProbe,
    /// Atomically replaces the active `CryptokeyValidator` packet filter policy (`US-018`).
    SetPacketFilter(PacketFilterPolicy),
    /// Atomically parses and reloads inbound filter rules, preserving previous policy if invalid (`US-018`).
    TryReloadPacketFilterSpec {
        /// Rule specification such as `"3389,tcp:8080"` or `"allow-all"`.
        spec: String,
        /// Reply returning validation result.
        reply: oneshot::Sender<AppResult<()>>,
    },
    /// Triggers immediate simultaneous NAT hole punching toward a peer (`US-021`, `US-026`).
    InitiateHolePunch(NodeId),
    /// Sends an end-to-end encrypted `DiscoPing` probe (`Direct` or `Relay`) and waits up to
    /// `timeout_ms` for the matching `DiscoPong` (`BLK-W12-02`).
    SendPingProbe {
        /// Destination peer UUID.
        peer_id: NodeId,
        /// Probe Direct UDP candidate endpoints even if currently active on Relay.
        force_direct: bool,
        /// Kick simultaneous NAT hole punching on initial Relay ping so subsequent pings upgrade.
        kick_hole_punch: bool,
        /// Maximum time to wait for a matching `DiscoPong`.
        timeout_ms: u64,
        /// Completion channel returning measured RTT & path or `PingProbePath::Timeout`.
        reply: oneshot::Sender<PingProbeOutcome>,
    },
    /// Delivers an authenticated `CallMeMaybeRelay` Disco frame received via Control WS (`BLK-W12-04`).
    HandleRelayedDisco {
        /// Authenticated peer UUID.
        src_node_id: NodeId,
        /// Server-verified sender WireGuard public key.
        verified_src_pubkey: PublicKey,
        /// Complete `MESHDS` encrypted frame payload.
        packet: Bytes,
    },
    /// Marks direct UDP egress blocked while preparing a physical interface rebind (`HR-W21-08`).
    BeginRebind,
    /// Synchronously rebinds `MagicSocket` onto a new physical interface before reprobing (`HR-W21-08`).
    RebindUnderlay {
        /// Physical interface name for diagnostics.
        interface_name: String,
        /// Optional physical interface index (`IP_UNICAST_IF` / `IP_BOUND_IF`).
        if_index: Option<u32>,
        /// Whether underlay uses IPv6.
        is_ipv6: bool,
        /// Completion reply yielding `Ok(bound_local_port)` or `Err(err)`.
        reply: oneshot::Sender<AppResult<u16>>,
    },
    /// Queries an immutable snapshot of data-plane metrics and active peer paths.
    QueryStatus(oneshot::Sender<DatapathStatusSnapshot>),
}

/// Clonable handle sending bounded commands to [`DatapathEngine`].
#[derive(Debug, Clone)]
pub struct DatapathHandle {
    tx: mpsc::Sender<DatapathCommand>,
    stun_report_tx: watch::Sender<Option<StunProbeReport>>,
}

impl DatapathHandle {
    /// Subscribes to completed STUN probe reports published by [`DatapathEngine`].
    #[must_use]
    pub fn subscribe_stun_reports(&self) -> watch::Receiver<Option<StunProbeReport>> {
        self.stun_report_tx.subscribe()
    }
}

impl DatapathHandle {
    /// Sends a command asynchronously over the bounded engine command channel.
    pub async fn send(&self, cmd: DatapathCommand) -> AppResult<()> {
        self.tx
            .send(cmd)
            .await
            .map_err(|_| AppError::unavailable("datapath engine command channel closed"))
    }

    /// Queries the current data-plane status snapshot.
    pub async fn query_status(&self) -> AppResult<DatapathStatusSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.send(DatapathCommand::QueryStatus(tx)).await?;
        rx.await
            .map_err(|_| AppError::unavailable("datapath status query canceled during shutdown"))
    }

    /// Applies an atomic `NetmapSnapshot` diff and waits for `ApplyDiffReport`.
    pub async fn apply_netmap(&self, snapshot: NetmapSnapshot) -> AppResult<ApplyDiffReport> {
        let (tx, rx) = oneshot::channel();
        self.send(DatapathCommand::ApplyNetmap {
            snapshot: Box::new(snapshot),
            reply: Some(tx),
        })
        .await?;
        rx.await
            .map_err(|_| AppError::unavailable("datapath netmap diff reply dropped"))
    }

    /// Sends one interactive encrypted `DiscoPing` probe and measures actual RTT (`BLK-W12-02`).
    pub async fn send_ping_probe(
        &self,
        peer_id: NodeId,
        force_direct: bool,
        kick_hole_punch: bool,
        timeout_ms: u64,
    ) -> AppResult<PingProbeOutcome> {
        let (tx, rx) = oneshot::channel();
        self.send(DatapathCommand::SendPingProbe {
            peer_id,
            force_direct,
            kick_hole_punch,
            timeout_ms,
            reply: tx,
        })
        .await?;
        rx.await
            .map_err(|_| AppError::unavailable("datapath ping probe canceled during shutdown"))
    }

    /// Feeds an authenticated `CallMeMaybeRelay` Disco frame from Control WS (`BLK-W12-04`).
    pub async fn handle_relayed_disco(
        &self,
        src_node_id: NodeId,
        verified_src_pubkey: PublicKey,
        packet: Bytes,
    ) -> AppResult<()> {
        self.send(DatapathCommand::HandleRelayedDisco {
            src_node_id,
            verified_src_pubkey,
            packet,
        })
        .await
    }

    /// Atomically parses and applies an inbound packet filter rule specification (`US-018`).
    ///
    /// Preserves the previous valid policy intact if `spec` fails validation.
    pub async fn try_reload_packet_filter_spec(&self, spec: &str) -> AppResult<()> {
        let (tx, rx) = oneshot::channel();
        self.send(DatapathCommand::TryReloadPacketFilterSpec {
            spec: spec.to_owned(),
            reply: tx,
        })
        .await?;
        rx.await
            .map_err(|_| AppError::unavailable("packet filter reload canceled during shutdown"))?
    }

    /// Blocks direct UDP sends while an interface transition rebind is in progress (`HR-W21-08`).
    pub async fn begin_rebind(&self) -> AppResult<()> {
        self.send(DatapathCommand::BeginRebind).await
    }

    /// Synchronously rebinds `MagicSocket` and awaits confirmation with the bound UDP port (`HR-W21-08`).
    pub async fn rebind_underlay(
        &self,
        interface_name: String,
        if_index: Option<u32>,
        is_ipv6: bool,
    ) -> AppResult<u16> {
        let (tx, rx) = oneshot::channel();
        self.send(DatapathCommand::RebindUnderlay {
            interface_name,
            if_index,
            is_ipv6,
            reply: tx,
        })
        .await?;
        rx.await.map_err(|_| {
            AppError::unavailable("datapath underlay rebind canceled during shutdown")
        })?
    }
}

struct PendingPingWaiter {
    peer_id: NodeId,
    started_at: tokio::time::Instant,
    expires_at: tokio::time::Instant,
    force_direct: bool,
    slot: Arc<std::sync::Mutex<Option<oneshot::Sender<PingProbeOutcome>>>>,
}

struct SendPingProbeCmd {
    peer_id: NodeId,
    force_direct: bool,
    kick_hole_punch: bool,
    timeout_ms: u64,
    reply: oneshot::Sender<PingProbeOutcome>,
}

/// Non-blocking WireGuard/Disco/STUN/Relay coordinator wired to a [`TunDevice`] and [`MagicSocket`].
pub struct DatapathEngine {
    config: DatapathConfig,
    tun: Arc<dyn TunDevice>,
    magic_socket: MagicSocket,
    peer_map: PeerMap,
    cryptokey: CryptokeyValidator,
    stun_client: StunClient,
    last_stun_report: Option<StunProbeReport>,
    stun_report_tx: watch::Sender<Option<StunProbeReport>>,
    disco: DiscoEngine,
    advertised_endpoints: Vec<SocketAddr>,
    pending_ping_waiters: HashMap<[u8; 12], PendingPingWaiter>,
    relay_handle: Option<RelayClientHandle>,
    relay_state: RelayConnectionState,
    clock: Arc<dyn Clock>,
    cmd_tx: mpsc::Sender<DatapathCommand>,
    cmd_rx: mpsc::Receiver<DatapathCommand>,
    direct_udp_blocked: bool,
    stun_dns_cancel: Option<CancellationToken>,
    #[cfg(test)]
    injected_rebind_failures: std::collections::VecDeque<AppError>,
}

impl std::fmt::Debug for DatapathEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatapathEngine")
            .field("local_node_id", &self.config.local_node_id)
            .field("local_overlay_ip", &self.config.local_overlay_ip)
            .field("relay_state", &self.relay_state)
            .finish_non_exhaustive()
    }
}

impl DatapathEngine {
    /// Initializes a [`DatapathEngine`] bound to `tun` and a freshly bound [`MagicSocket`].
    pub async fn bind(
        config: DatapathConfig,
        tun: Arc<dyn TunDevice>,
        clock: Arc<dyn Clock>,
        relay_handle: Option<RelayClientHandle>,
    ) -> AppResult<Self> {
        let magic_socket = MagicSocket::bind(config.socket_config.clone()).await?;
        let peer_map = PeerMap::new(config.local_node_id, config.node_keypair.clone_keypair());
        let disco = DiscoEngine::new(
            config.disco_keypair.clone_keypair(),
            config.disco_config.clone(),
        );
        let stun_client = StunClient::new(config.stun_config.clone());
        let (cmd_tx, cmd_rx) = mpsc::channel(DATAPATH_COMMAND_CAPACITY);
        let (stun_report_tx, _) = watch::channel(None);

        let local_addr = magic_socket.local_addr().ok();
        let advertised_endpoints = local_addr
            .into_iter()
            .filter(|addr| !addr.ip().is_unspecified() && !addr.ip().is_loopback())
            .collect();

        Ok(Self {
            config,
            tun,
            magic_socket,
            peer_map,
            cryptokey: CryptokeyValidator::new(),
            stun_client,
            last_stun_report: None,
            stun_report_tx,
            disco,
            advertised_endpoints,
            pending_ping_waiters: HashMap::new(),
            relay_handle,
            relay_state: RelayConnectionState::Disconnected,
            clock,
            cmd_tx,
            cmd_rx,
            direct_udp_blocked: false,
            stun_dns_cancel: None,
            #[cfg(test)]
            injected_rebind_failures: std::collections::VecDeque::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn inject_rebind_failure_for_tests(&mut self, err: AppError) {
        self.injected_rebind_failures.push_back(err);
    }

    /// Returns a clonable handle to issue runtime commands and status queries.
    #[must_use]
    pub fn handle(&self) -> DatapathHandle {
        DatapathHandle {
            tx: self.cmd_tx.clone(),
            stun_report_tx: self.stun_report_tx.clone(),
        }
    }

    /// Returns the local UDP socket address bound by `MagicSocket`.
    pub fn local_udp_addr(&self) -> AppResult<SocketAddr> {
        self.magic_socket.local_addr()
    }

    /// Returns the most recent completed STUN probe report, if any probe round has finished.
    #[must_use]
    pub fn last_stun_report(&self) -> Option<&StunProbeReport> {
        self.last_stun_report.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn enable_loopback_disco_for_tests(&mut self) {
        self.disco.enable_loopback_for_tests();
    }

    /// Runs the single-loop data-plane coordinator inside `TaskTracker` until `shutdown` fires,
    /// completing cleanup within `<= 5 s`.
    pub async fn run(
        mut self,
        mut relay_events_rx: mpsc::Receiver<RelayEvent>,
        mut rebind_rx: mpsc::Receiver<RebindCommand>,
        shutdown: CancellationToken,
    ) -> AppResult<()> {
        let tracker = TaskTracker::new();
        let (stun_dns_tx, mut stun_dns_rx) = mpsc::channel::<(Vec<String>, Vec<SocketAddr>)>(8);
        let (mut wg_tick, mut disco_tick) = self.build_tick_intervals();
        let mut udp_rx_buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut tun_rx_buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut wg_tx_buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut wg_rx_buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];

        info!(
            component = "datapath.engine",
            event = "datapath_started",
            overlay_ip = %self.config.local_overlay_ip,
            tun = %self.tun.interface_name(),
            "DatapathEngine event loop running"
        );

        loop {
            let next_ping_deadline = self.earliest_ping_waiter_expiry();
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = wait_optional_deadline(next_ping_deadline) => {
                    self.expire_ping_waiters();
                }
                udp_res = self.magic_socket.recv_from(&mut udp_rx_buf) => {
                    self.handle_udp_recv_result(udp_res, &udp_rx_buf, &mut wg_rx_buf).await;
                }
                tun_res = self.tun.read_packet(&mut tun_rx_buf) => {
                    if self.handle_tun_read_result(tun_res, &tun_rx_buf, &mut wg_tx_buf, &shutdown).await {
                        break;
                    }
                }
                maybe_relay = relay_events_rx.recv() => {
                    if let Some(relay_ev) = maybe_relay {
                        self.process_relay_event(relay_ev, &mut wg_rx_buf).await;
                    }
                }
                maybe_cmd = self.cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => self.process_command(cmd, &tracker, &shutdown, &stun_dns_tx).await,
                        None => break,
                    }
                }
                maybe_rebind = rebind_rx.recv() => {
                    if let Some(cmd) = maybe_rebind {
                        self.process_rebind_command(&cmd).await;
                    }
                }
                maybe_stun_dns = stun_dns_rx.recv() => {
                    if let Some((raw_endpoints, resolved)) = maybe_stun_dns
                        && self.stun_client.apply_resolved_endpoints_for_raw(&raw_endpoints, resolved)
                    {
                        self.reprobe_tracked_stun_endpoints().await;
                    }
                }
                _ = wg_tick.tick() => self.step_wg_timers(&mut wg_tx_buf).await,
                _ = disco_tick.tick() => self.step_disco_tick().await,
            }
        }

        self.shutdown_cleanup(tracker).await;
        Ok(())
    }

    fn build_tick_intervals(&self) -> (tokio::time::Interval, tokio::time::Interval) {
        let wg_interval = if self.config.wg_timer_interval.is_zero() {
            DEFAULT_WG_TIMER_INTERVAL
        } else {
            self.config.wg_timer_interval
        };
        let disco_interval = if self.config.disco_tick_interval.is_zero() {
            DEFAULT_DISCO_TICK_INTERVAL
        } else {
            self.config.disco_tick_interval
        };
        let mut wg_tick = tokio::time::interval(wg_interval);
        wg_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut disco_tick = tokio::time::interval(disco_interval);
        disco_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        (wg_tick, disco_tick)
    }

    async fn handle_udp_recv_result(
        &mut self,
        udp_res: AppResult<(usize, SocketAddr)>,
        udp_rx_buf: &PacketBuffer,
        wg_rx_buf: &mut PacketBuffer,
    ) {
        match udp_res {
            Ok((len, remote_addr)) => {
                if let Some(pkt) = udp_rx_buf.get(..len) {
                    self.process_udp_datagram(remote_addr, pkt, wg_rx_buf).await;
                }
            }
            Err(err) => warn!(
                component = "datapath.engine",
                event = "udp_recv_error",
                error = %err,
                "MagicSocket recv_from failed"
            ),
        }
    }

    async fn handle_tun_read_result(
        &mut self,
        tun_res: AppResult<usize>,
        tun_rx_buf: &PacketBuffer,
        wg_tx_buf: &mut PacketBuffer,
        shutdown: &CancellationToken,
    ) -> bool {
        match tun_res {
            Ok(len) => {
                if let Some(pkt) = tun_rx_buf.get(..len) {
                    self.process_tun_packet(pkt, wg_tx_buf).await;
                }
                false
            }
            Err(err) => {
                if shutdown.is_cancelled() {
                    return true;
                }
                warn!(
                    component = "datapath.engine",
                    event = "tun_read_error",
                    error = %err,
                    "TUN device read failed"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
                false
            }
        }
    }

    async fn step_wg_timers(&mut self, wg_tx_buf: &mut PacketBuffer) {
        let timer_pkts = self.peer_map.tick_timers(wg_tx_buf);
        for (_, target, bytes) in timer_pkts {
            self.dispatch_send(target, &bytes).await;
        }
    }

    async fn step_disco_tick(&mut self) {
        let now_ms = self.clock.now_unix_ms();
        if self.stun_client.has_pending_requests() && self.stun_client.is_probe_round_ready(now_ms)
        {
            let report = self.stun_client.finish_probe_round(now_ms);
            self.record_stun_report(report);
        }
        let disco_pkts = self.disco.tick(&mut self.peer_map, now_ms);
        for pkt in disco_pkts {
            self.dispatch_send(pkt.target, &pkt.bytes).await;
        }
    }

    async fn shutdown_cleanup(&mut self, tracker: TaskTracker) {
        if let Some(cancel) = self.stun_dns_cancel.take() {
            cancel.cancel();
        }
        self.drain_ping_waiters_as_timeout();
        if tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, self.tun.close())
            .await
            .is_err()
        {
            warn!(
                component = "datapath.engine",
                event = "tun_close_timeout",
                "timed out closing TUN device during graceful shutdown"
            );
        }
        tracker.close();
        if tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, tracker.wait())
            .await
            .is_err()
        {
            warn!(
                component = "datapath.engine",
                event = "tracker_wait_timeout",
                "timed out waiting for background tasks during shutdown"
            );
        }
        info!(
            component = "datapath.engine",
            event = "datapath_stopped",
            "DatapathEngine exited cleanly"
        );
    }

    async fn process_udp_datagram(
        &mut self,
        remote_addr: SocketAddr,
        datagram: &[u8],
        wg_rx_buf: &mut PacketBuffer,
    ) {
        let now_ms = self.clock.now_unix_ms();
        match demux_packet(datagram) {
            DemuxPacket::WireGuard(wg_bytes) => {
                if let Some(dec) =
                    self.peer_map
                        .decapsulate_from_udp(remote_addr, wg_bytes, wg_rx_buf, now_ms)
                {
                    self.deliver_decapsulated(dec, wg_rx_buf).await;
                }
            }
            DemuxPacket::Disco(disco_bytes) => {
                self.handle_disco_bytes(disco_bytes, IngressSource::DirectUdp(remote_addr))
                    .await;
            }
            DemuxPacket::Stun(stun_bytes) => {
                if let Some(_obs) =
                    self.stun_client
                        .handle_incoming_stun(stun_bytes, remote_addr, now_ms)
                    && self.stun_client.is_probe_round_ready(now_ms)
                {
                    let report = self.stun_client.finish_probe_round(now_ms);
                    self.record_stun_report(report);
                }
            }
            DemuxPacket::Unknown => {}
        }
    }

    async fn process_tun_packet(&mut self, packet: &[u8], wg_tx_buf: &mut PacketBuffer) {
        let header = match self.cryptokey.validate_outbound(
            self.config.local_overlay_ip,
            self.config.overlay_cidr,
            packet,
        ) {
            Ok(h) => h,
            Err(_) => return,
        };
        let Ok(dst_ip) = OverlayIp::from_ipv4(header.dst_ip) else {
            return;
        };
        if dst_ip == self.config.local_overlay_ip {
            return;
        }

        let now_ms = self.clock.now_unix_ms();
        let should_kick_punch = self.peer_map.get_by_overlay_ip(dst_ip).is_some_and(|s| {
            matches!(s.active_path, PeerActivePath::Relay) && s.last_tx_at_ms == 0
        });

        match self
            .peer_map
            .encapsulate_to_overlay_ip(dst_ip, packet, wg_tx_buf, now_ms)
        {
            Ok(Some((peer_id, send_target, len))) => {
                if let Some(wg_payload) = wg_tx_buf.get(..len) {
                    self.dispatch_send(send_target, wg_payload).await;
                }
                if should_kick_punch {
                    self.initiate_hole_punch_for_peer(peer_id, now_ms).await;
                }
            }
            Ok(None) => {
                if should_kick_punch && let Some(peer) = self.peer_map.get_by_overlay_ip(dst_ip) {
                    let peer_id = peer.node_id;
                    self.initiate_hole_punch_for_peer(peer_id, now_ms).await;
                }
            }
            Err(_) => {}
        }
    }

    async fn process_relay_event(&mut self, event: RelayEvent, wg_rx_buf: &mut PacketBuffer) {
        match event {
            RelayEvent::StateChanged(state) => {
                self.relay_state = state;
            }
            RelayEvent::NoticeReceived(_) => {}
            RelayEvent::PacketReceived {
                src_pubkey,
                ciphertext,
            } => {
                let now_ms = self.clock.now_unix_ms();
                match demux_packet(&ciphertext) {
                    DemuxPacket::WireGuard(wg_bytes) => {
                        if let Some(dec) = self
                            .peer_map
                            .decapsulate_from_relay(src_pubkey, wg_bytes, wg_rx_buf, now_ms)
                        {
                            self.deliver_decapsulated(dec, wg_rx_buf).await;
                        }
                    }
                    DemuxPacket::Disco(disco_bytes) => {
                        self.handle_disco_bytes(
                            disco_bytes,
                            IngressSource::Relay {
                                verified_src_node_pubkey: src_pubkey,
                            },
                        )
                        .await;
                    }
                    DemuxPacket::Stun(_) | DemuxPacket::Unknown => {}
                }
            }
        }
    }

    async fn process_command(
        &mut self,
        cmd: DatapathCommand,
        tracker: &TaskTracker,
        shutdown: &CancellationToken,
        stun_dns_tx: &mpsc::Sender<(Vec<String>, Vec<SocketAddr>)>,
    ) {
        match cmd {
            DatapathCommand::ApplyNetmap { snapshot, reply } => {
                let report = self.peer_map.apply_diff(&snapshot);
                if !report.removed_peer_ids.is_empty() {
                    self.disco.remove_peers(&report.removed_peer_ids);
                    self.fail_ping_waiters_for_peers(&report.removed_peer_ids);
                }
                if !report.removed_node_pubkeys.is_empty()
                    && let Some(relay) = &self.relay_handle
                {
                    relay.remove_peer_queues(&report.removed_node_pubkeys);
                }
                let stun_changed = self.stun_client.sync_relay_map(&snapshot.relay_map);
                if let Some(tx) = reply
                    && tx.send(report).is_err()
                {
                    debug!(
                        component = "datapath.engine",
                        "apply_netmap reply receiver closed"
                    );
                }
                if stun_changed {
                    if !self.stun_client.tracked_endpoints().is_empty() {
                        self.reprobe_tracked_stun_endpoints().await;
                    }
                    if StunClient::has_unresolved_hostnames(&snapshot.relay_map.stun_udp_endpoints)
                    {
                        if let Some(prev_cancel) = self.stun_dns_cancel.take() {
                            prev_cancel.cancel();
                        }
                        let dns_cancel = shutdown.child_token();
                        self.stun_dns_cancel = Some(dns_cancel.clone());
                        let endpoints = snapshot.relay_map.stun_udp_endpoints.clone();
                        let dns_tx = stun_dns_tx.clone();
                        tracker.spawn(async move {
                            let resolved =
                                resolve_stun_endpoints_cancellable(&endpoints, &dns_cancel).await;
                            if !dns_cancel.is_cancelled()
                                && dns_tx.send((endpoints, resolved)).await.is_err()
                            {
                                debug!(
                                    component = "datapath.engine",
                                    "background stun dns result receiver closed"
                                );
                            }
                        });
                    } else if let Some(prev_cancel) = self.stun_dns_cancel.take() {
                        prev_cancel.cancel();
                    }
                }
            }
            DatapathCommand::SetAdvertisedEndpoints(endpoints) => {
                let mut merged = endpoints;
                if let Some(report) = &self.last_stun_report {
                    for &addr in &report.reflexive_addrs {
                        if !merged.contains(&addr) {
                            merged.push(addr);
                        }
                    }
                }
                self.advertised_endpoints = merged;
            }
            DatapathCommand::TriggerStunProbe => {
                self.reprobe_tracked_stun_endpoints().await;
            }
            DatapathCommand::SetPacketFilter(policy) => {
                self.cryptokey.set_policy(policy);
            }
            DatapathCommand::TryReloadPacketFilterSpec { spec, reply } => {
                let res = self.cryptokey.try_reload_policy_spec(&spec);
                if reply.send(res).is_err() {
                    debug!(
                        component = "datapath.engine",
                        "try_reload_packet_filter_spec reply receiver closed"
                    );
                }
            }
            DatapathCommand::InitiateHolePunch(peer_id) => {
                let now_ms = self.clock.now_unix_ms();
                self.initiate_hole_punch_for_peer(peer_id, now_ms).await;
            }
            DatapathCommand::SendPingProbe {
                peer_id,
                force_direct,
                kick_hole_punch,
                timeout_ms,
                reply,
            } => {
                self.handle_send_ping_probe(SendPingProbeCmd {
                    peer_id,
                    force_direct,
                    kick_hole_punch,
                    timeout_ms,
                    reply,
                })
                .await;
            }
            DatapathCommand::HandleRelayedDisco {
                src_node_id,
                verified_src_pubkey,
                packet,
            } => {
                self.handle_relayed_disco_cmd(src_node_id, verified_src_pubkey, &packet)
                    .await;
            }
            DatapathCommand::BeginRebind => {
                self.direct_udp_blocked = true;
            }
            DatapathCommand::RebindUnderlay {
                interface_name,
                if_index,
                is_ipv6,
                reply,
            } => {
                self.direct_udp_blocked = true;
                let rebind_cmd = RebindCommand::RebindInterface {
                    interface_name,
                    if_index,
                    is_ipv6,
                };
                let res = match self.execute_socket_rebind(&rebind_cmd) {
                    Ok(RebindOutcome::Rebound { local_addr, .. }) => {
                        self.direct_udp_blocked = false;
                        Ok(local_addr.port())
                    }
                    Ok(_) => {
                        self.direct_udp_blocked = false;
                        self.magic_socket.local_addr().map(|addr| addr.port())
                    }
                    Err(err) => {
                        warn!(
                            component = "datapath.engine",
                            event = "rebind_underlay_failed",
                            error = %err,
                            "underlay socket rebind failed; keeping direct UDP egress blocked until retry succeeds"
                        );
                        Err(err)
                    }
                };
                if reply.send(res).is_err() {
                    debug!(
                        component = "datapath.engine",
                        "rebind_underlay reply receiver closed"
                    );
                }
            }
            DatapathCommand::QueryStatus(reply) => {
                let status = self.build_status_snapshot();
                if reply.send(status).is_err() {
                    debug!(
                        component = "datapath.engine",
                        "query_status reply receiver closed"
                    );
                }
            }
        }
    }

    async fn reprobe_tracked_stun_endpoints(&mut self) {
        if self.direct_udp_blocked {
            debug!(
                component = "datapath.engine",
                event = "stun_probe_blocked_during_rebind",
                "skipped STUN probe while direct UDP is blocked during interface rebind"
            );
            return;
        }
        let now_ms = self.clock.now_unix_ms();
        let requests = self.stun_client.start_probe_round_tracked(now_ms);
        self.send_stun_probe_requests(requests).await;
    }

    async fn handle_disco_bytes(&mut self, disco_bytes: &[u8], ingress: IngressSource) {
        let now_ms = self.clock.now_unix_ms();
        let ctx = self.filter_context();
        let excluded = self.stun_client.tracked_endpoints().to_vec();
        let filter = DiscoFilterContext {
            candidates: &ctx,
            excluded_stun: &excluded,
        };
        let (event, matched_tx, replies) = self.disco.handle_incoming_tracked(
            disco_bytes,
            ingress,
            &mut self.peer_map,
            &filter,
            now_ms,
        );
        if let Some(tx_id) = matched_tx {
            self.resolve_ping_waiter(tx_id, &event);
        }
        for pkt in replies {
            self.dispatch_send(pkt.target, &pkt.bytes).await;
        }
    }

    async fn handle_relayed_disco_cmd(
        &mut self,
        src_node_id: NodeId,
        verified_src_pubkey: PublicKey,
        packet: &[u8],
    ) {
        if let Some(peer) = self.peer_map.get(&src_node_id)
            && peer.node_pubkey != verified_src_pubkey
        {
            warn!(
                component = "datapath.engine",
                event = "control_relayed_disco_pubkey_mismatch",
                %src_node_id,
                "dropped CallMeMaybeRelay with mismatched source public key"
            );
            return;
        }
        if let DemuxPacket::Disco(disco_bytes) = demux_packet(packet) {
            self.handle_disco_bytes(
                disco_bytes,
                IngressSource::Relay {
                    verified_src_node_pubkey: verified_src_pubkey,
                },
            )
            .await;
        }
    }

    async fn handle_send_ping_probe(&mut self, cmd: SendPingProbeCmd) {
        let now_ms = self.clock.now_unix_ms();
        let Some(peer) = self.peer_map.get(&cmd.peer_id) else {
            send_ping_reply(
                cmd.reply,
                PingProbeOutcome {
                    path: PingProbePath::Timeout,
                    rtt_ms: None,
                },
            );
            return;
        };
        let is_relay = matches!(peer.active_path, PeerActivePath::Relay);

        if cmd.force_direct && is_relay {
            if let Some(call_me) = self.disco.maybe_build_call_me_maybe(
                &self.peer_map,
                cmd.peer_id,
                &self.advertised_endpoints,
                now_ms,
            ) {
                self.dispatch_send(call_me.target, &call_me.bytes).await;
            }
        } else if !cmd.force_direct && cmd.kick_hole_punch && is_relay {
            self.initiate_hole_punch_for_peer(cmd.peer_id, now_ms).await;
        }

        let probes = {
            let ctx = self.filter_context();
            let excluded = self.stun_client.tracked_endpoints().to_vec();
            let filter = DiscoFilterContext {
                candidates: &ctx,
                excluded_stun: &excluded,
            };
            self.disco.build_interactive_probes(
                &self.peer_map,
                &filter,
                InteractivePingRequest {
                    peer_id: cmd.peer_id,
                    force_direct: cmd.force_direct,
                    now_ms,
                    timeout_ms: cmd.timeout_ms.max(1),
                },
            )
        };
        if probes.is_empty() {
            send_ping_reply(
                cmd.reply,
                PingProbeOutcome {
                    path: PingProbePath::Timeout,
                    rtt_ms: None,
                },
            );
            return;
        }

        let started_at = tokio::time::Instant::now();
        let expires_at = started_at + Duration::from_millis(cmd.timeout_ms.max(1));
        let slot = Arc::new(std::sync::Mutex::new(Some(cmd.reply)));
        for (tx_id, pkt) in probes {
            self.pending_ping_waiters.insert(
                tx_id,
                PendingPingWaiter {
                    peer_id: cmd.peer_id,
                    started_at,
                    expires_at,
                    force_direct: cmd.force_direct,
                    slot: Arc::clone(&slot),
                },
            );
            self.dispatch_send(pkt.target, &pkt.bytes).await;
        }
    }

    fn earliest_ping_waiter_expiry(&self) -> Option<tokio::time::Instant> {
        self.pending_ping_waiters
            .values()
            .map(|waiter| waiter.expires_at)
            .min()
    }

    fn resolve_ping_waiter(&mut self, tx_id: [u8; 12], event: &DiscoEvent) {
        let Some(waiter) = self.pending_ping_waiters.remove(&tx_id) else {
            return;
        };
        let path = match event {
            DiscoEvent::DirectPathVerified { addr, .. } => PingProbePath::Direct { addr: *addr },
            DiscoEvent::RelayRttMeasured { .. } if !waiter.force_direct => PingProbePath::Relay,
            DiscoEvent::RelayRttMeasured { .. } => {
                self.pending_ping_waiters.insert(tx_id, waiter);
                return;
            }
            _ => return,
        };
        let rtt_ms = waiter.started_at.elapsed().as_secs_f64() * 1000.0;
        if let Ok(mut guard) = waiter.slot.lock()
            && let Some(tx) = guard.take()
        {
            send_ping_reply(
                tx,
                PingProbeOutcome {
                    path,
                    rtt_ms: Some(rtt_ms),
                },
            );
        }
        self.pending_ping_waiters
            .retain(|_, other| !Arc::ptr_eq(&other.slot, &waiter.slot));
    }

    fn expire_ping_waiters(&mut self) {
        let now = tokio::time::Instant::now();
        let expired: Vec<[u8; 12]> = self
            .pending_ping_waiters
            .iter()
            .filter_map(|(&tx_id, w)| (w.expires_at <= now).then_some(tx_id))
            .collect();
        for tx_id in expired {
            if let Some(waiter) = self.pending_ping_waiters.remove(&tx_id)
                && let Ok(mut guard) = waiter.slot.lock()
                && let Some(tx) = guard.take()
            {
                send_ping_reply(
                    tx,
                    PingProbeOutcome {
                        path: PingProbePath::Timeout,
                        rtt_ms: None,
                    },
                );
            }
        }
    }

    fn fail_ping_waiters_for_peers(&mut self, peer_ids: &[NodeId]) {
        if peer_ids.is_empty() || self.pending_ping_waiters.is_empty() {
            return;
        }
        let matching: Vec<[u8; 12]> = self
            .pending_ping_waiters
            .iter()
            .filter_map(|(&tx_id, waiter)| peer_ids.contains(&waiter.peer_id).then_some(tx_id))
            .collect();
        for tx_id in matching {
            if let Some(waiter) = self.pending_ping_waiters.remove(&tx_id)
                && let Ok(mut guard) = waiter.slot.lock()
                && let Some(tx) = guard.take()
            {
                send_ping_reply(
                    tx,
                    PingProbeOutcome {
                        path: PingProbePath::Timeout,
                        rtt_ms: None,
                    },
                );
            }
        }
    }

    fn drain_ping_waiters_as_timeout(&mut self) {
        let waiters: Vec<PendingPingWaiter> = self
            .pending_ping_waiters
            .drain()
            .map(|(_, waiter)| waiter)
            .collect();
        for waiter in waiters {
            if let Ok(mut guard) = waiter.slot.lock()
                && let Some(tx) = guard.take()
            {
                send_ping_reply(
                    tx,
                    PingProbeOutcome {
                        path: PingProbePath::Timeout,
                        rtt_ms: None,
                    },
                );
            }
        }
    }

    fn execute_socket_rebind(&mut self, cmd: &RebindCommand) -> AppResult<RebindOutcome> {
        #[cfg(test)]
        if matches!(cmd, RebindCommand::RebindInterface { .. })
            && let Some(err) = self.injected_rebind_failures.pop_front()
        {
            return Err(err);
        }
        SocketRebinder::apply_command(
            &mut self.magic_socket,
            cmd,
            self.config.socket_config.linux_fwmark,
        )
    }

    async fn process_rebind_command(&mut self, cmd: &RebindCommand) {
        if matches!(cmd, RebindCommand::RebindInterface { .. }) {
            self.direct_udp_blocked = true;
        }
        match self.execute_socket_rebind(cmd) {
            Ok(RebindOutcome::Rebound { .. }) => {
                self.direct_udp_blocked = false;
                self.reprobe_tracked_stun_endpoints().await;
            }
            Ok(RebindOutcome::RefreshCandidatesRequested) => {
                if !self.direct_udp_blocked {
                    self.reprobe_tracked_stun_endpoints().await;
                }
            }
            Ok(RebindOutcome::WakeRelayRequested) => {
                if let Some(relay) = &self.relay_handle {
                    relay.wake_reconnect();
                }
            }
            Err(err) => {
                warn!(
                    component = "datapath.engine",
                    event = "rebind_failed",
                    error = %err,
                    "failed executing RebindCommand against MagicSocket; direct UDP stays blocked"
                );
            }
        }
    }

    async fn deliver_decapsulated(
        &self,
        dec: crate::peer_map::DecapsulateResult,
        wg_rx_buf: &PacketBuffer,
    ) {
        for pkt in dec.outbound_network_packets {
            self.dispatch_send(dec.send_target, &pkt).await;
        }
        if let Some(len) = dec.tunnel_payload_len
            && let Some(plain_ipv4) = wg_rx_buf.get(..len)
            && self
                .cryptokey
                .validate_inbound(
                    dec.peer_overlay_ip,
                    Some(self.config.local_overlay_ip),
                    self.config.overlay_cidr,
                    plain_ipv4,
                )
                .is_ok()
            && let Err(err) = self.tun.write_packet(plain_ipv4).await
        {
            warn!(
                component = "datapath.engine",
                event = "tun_write_error",
                peer_id = %dec.peer_id,
                error = %err,
                "failed writing decapsulated IPv4 packet to TUN"
            );
        }
    }

    async fn dispatch_send(&self, target: PeerSendTarget, payload: &[u8]) {
        if payload.len() > MAX_FRAME_SIZE {
            return;
        }
        match target {
            PeerSendTarget::Direct(addr) => {
                if self.direct_udp_blocked {
                    debug!(
                        component = "datapath.engine",
                        event = "direct_udp_blocked_during_rebind",
                        target = %addr,
                        "blocked direct UDP datagram over stale NIC while rebinding"
                    );
                    return;
                }
                if let Err(err) = self.magic_socket.send_to(payload, addr).await {
                    warn!(
                        component = "datapath.engine",
                        event = "direct_udp_send_failed",
                        target = %addr,
                        error = %err,
                        "failed sending UDP datagram via MagicSocket"
                    );
                }
            }
            PeerSendTarget::Relay(dst_pubkey) => {
                if let Some(ref relay) = self.relay_handle
                    && !relay.try_send_packet(dst_pubkey, Bytes::copy_from_slice(payload))
                {
                    debug!(
                        component = "datapath.engine",
                        event = "relay_queue_saturated",
                        dst_pubkey = %dst_pubkey,
                        "dropped outbound packet on full per-peer Blind Relay queue"
                    );
                }
            }
        }
    }

    async fn initiate_hole_punch_for_peer(&mut self, peer_id: NodeId, now_ms: u64) {
        let ctx = self.filter_context();
        let excluded = self.stun_client.tracked_endpoints().to_vec();
        let filter = DiscoFilterContext {
            candidates: &ctx,
            excluded_stun: &excluded,
        };
        let packets = self.disco.initiate_hole_punch(
            &self.peer_map,
            peer_id,
            &self.advertised_endpoints,
            &filter,
            now_ms,
        );
        for pkt in packets {
            self.dispatch_send(pkt.target, &pkt.bytes).await;
        }
    }

    async fn send_stun_probe_requests(&mut self, requests: Vec<(SocketAddr, [u8; 28])>) {
        if self.direct_udp_blocked {
            debug!(
                component = "datapath.engine",
                event = "stun_probe_blocked_during_rebind",
                "skipped STUN probe transmission while direct UDP is blocked"
            );
            return;
        }
        for (target, pkt) in requests {
            if let Err(err) = self.magic_socket.send_to(&pkt, target).await {
                debug!(
                    component = "datapath.engine",
                    event = "stun_probe_send_failed",
                    target = %target,
                    error = %err,
                    "failed sending STUN probe packet"
                );
            }
        }
        self.disco
            .set_nat_mapping(self.stun_client.last_report().nat_mapping);
    }

    fn record_stun_report(&mut self, report: StunProbeReport) {
        self.disco.set_nat_mapping(report.nat_mapping);
        if let Some(prev) = &self.last_stun_report {
            self.advertised_endpoints
                .retain(|addr| !prev.reflexive_addrs.contains(addr));
        }
        for &addr in &report.reflexive_addrs {
            if !self.advertised_endpoints.contains(&addr) {
                self.advertised_endpoints.push(addr);
            }
        }
        let prev_report = self.stun_report_tx.send_replace(Some(report.clone()));
        drop(prev_report);
        self.last_stun_report = Some(report);
    }

    fn filter_context(&self) -> CandidateFilterContext {
        CandidateFilterContext {
            overlay_cidr: self.config.overlay_cidr,
            control_tcp_endpoint: self.config.control_tcp_endpoint,
            stun_udp_endpoint: self.stun_client.tracked_endpoints().first().copied(),
        }
    }

    fn build_status_snapshot(&self) -> DatapathStatusSnapshot {
        let peers = self
            .peer_map
            .iter()
            .map(|(&node_id, s)| DatapathPeerStatus {
                node_id,
                overlay_ip: s.overlay_ip,
                active_path: s.active_path.clone(),
                tx_bytes: s.tx_bytes,
                rx_bytes: s.rx_bytes,
            })
            .collect();

        DatapathStatusSnapshot {
            local_udp_addr: self.magic_socket.local_addr().ok(),
            relay_state: self.relay_state,
            netmap_version: self.peer_map.netmap_version(),
            nat_mapping: self
                .last_stun_report
                .as_ref()
                .map_or(self.stun_client.last_report().nat_mapping, |r| {
                    r.nat_mapping
                }),
            last_stun_report: self.last_stun_report.clone(),
            cryptokey_metrics: self.cryptokey.metrics_snapshot(),
            disco_metrics: self.disco.metrics_snapshot(),
            peers,
        }
    }
}

async fn wait_optional_deadline(deadline: Option<tokio::time::Instant>) {
    if let Some(target) = deadline {
        tokio::time::sleep_until(target).await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn send_ping_reply(tx: oneshot::Sender<PingProbeOutcome>, outcome: PingProbeOutcome) {
    if tx.send(outcome).is_err() {
        debug!(
            component = "datapath.engine",
            "ping probe waiter receiver closed"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::sleep;
    use tokio_tungstenite::tungstenite::{Error as WsError, Message, accept};

    use mesh_core::NodeId;
    use mesh_core::clock::SystemClock;
    use mesh_core::{NodeName, PublicKey, SpkiPin};
    use mesh_crypto::open_disco_packet;
    use mesh_net::tun::{FakeTunDevice, TunConfig};
    use mesh_proto::netmap::{CandidateEndpoint, CandidateSource, PeerEntry, PinSetDto, RelayMap};
    use mesh_proto::relay::RelayFrame;
    use mesh_proto::stun::{encode_binding_success_response, parse_stun_packet};

    use super::*;
    use crate::rebind::RebindHandle;
    use crate::relay_client::{
        ConnectedRelayTransport, RelayClient, RelayClientConfig, RelayConnector,
    };

    struct TestWsConnector {
        addr: SocketAddr,
    }

    impl RelayConnector for TestWsConnector {
        fn connect<'a>(
            &'a self,
            _config: &'a RelayClientConfig,
        ) -> Pin<Box<dyn Future<Output = AppResult<ConnectedRelayTransport>> + Send + 'a>> {
            let addr = self.addr;
            Box::pin(async move {
                let stream = TcpStream::connect(addr)
                    .await
                    .map_err(|e| AppError::unavailable(format!("test connect failed: {e}")))?;
                Ok(ConnectedRelayTransport {
                    stream: Box::new(stream),
                    tls_exporter_binding: None,
                })
            })
        }
    }

    fn build_ipv4_udp_msg(src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Vec<u8> {
        let total = 28usize.saturating_add(body.len());
        let total_u16 = u16::try_from(total).expect("ipv4 packet fits in u16");
        let udp_u16 = u16::try_from(8usize.saturating_add(body.len())).expect("udp fits in u16");
        let mut pkt = vec![0u8; total];
        if let Some(first) = pkt.first_mut() {
            *first = 0x45;
        }
        pkt.get_mut(2..4)
            .expect("totlen")
            .copy_from_slice(&total_u16.to_be_bytes());
        if let Some(proto) = pkt.get_mut(9) {
            *proto = 17;
        }
        pkt.get_mut(12..16)
            .expect("src")
            .copy_from_slice(&src.octets());
        pkt.get_mut(16..20)
            .expect("dst")
            .copy_from_slice(&dst.octets());
        pkt.get_mut(20..22)
            .expect("sport")
            .copy_from_slice(&4000u16.to_be_bytes());
        pkt.get_mut(22..24)
            .expect("dport")
            .copy_from_slice(&4001u16.to_be_bytes());
        pkt.get_mut(24..26)
            .expect("ulen")
            .copy_from_slice(&udp_u16.to_be_bytes());
        pkt.get_mut(28..).expect("body").copy_from_slice(body);
        pkt
    }

    fn mk_netmap(version: u64, peers: Vec<PeerEntry>, relay_ep: SocketAddr) -> NetmapSnapshot {
        NetmapSnapshot {
            netmap_version: version,
            generated_at_ms: 100_000,
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: relay_ep.to_string(),
                relay_tcp_endpoint: relay_ep.to_string(),
                stun_udp_endpoints: vec![],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([1u8; 32]),
                next_pin: None,
            },
            peers,
        }
    }

    fn mk_peer_entry(
        node_id: NodeId,
        name: &str,
        overlay_ip: OverlayIp,
        node_pubkey: PublicKey,
        disco_pubkey: PublicKey,
        hub_addr: SocketAddr,
    ) -> PeerEntry {
        PeerEntry {
            node_id,
            name: NodeName::parse(name).expect("peer name"),
            fqdn: format!("{name}.mesh.internal"),
            overlay_ip,
            node_pubkey,
            disco_pubkey,
            endpoints: vec![],
            relay_home: hub_addr.to_string(),
            key_expires_at_ms: None,
            online: true,
        }
    }

    fn serve_single_relay_peer(
        std_sock: std::net::TcpStream,
        my_pk: PublicKey,
        routes: Arc<Mutex<HashMap<PublicKey, mpsc::Sender<RelayFrame>>>>,
    ) {
        let mut ws = accept(std_sock).expect("accept ws");
        ws.get_mut()
            .set_read_timeout(Some(Duration::from_millis(5)))
            .expect("read timeout");
        let (tx, mut rx) = mpsc::channel::<RelayFrame>(64);
        if let Ok(mut map) = routes.lock() {
            map.insert(my_pk, tx);
        }
        loop {
            while let Ok(frame) = rx.try_recv() {
                if let Ok(bin) = frame.encode()
                    && ws.send(Message::Binary(bin)).is_err()
                {
                    return;
                }
            }
            match ws.read() {
                Ok(Message::Binary(raw)) => {
                    if let Ok(RelayFrame::ClientToPeerPacket {
                        dst_pubkey,
                        ciphertext,
                    }) = RelayFrame::decode(&raw)
                        && let Ok(map) = routes.lock()
                        && let Some(dst_tx) = map.get(&dst_pubkey)
                    {
                        drop(dst_tx.try_send(RelayFrame::RelayToClientPacket {
                            src_pubkey: my_pk,
                            ciphertext,
                        }));
                    }
                }
                Ok(Message::Close(_)) => return,
                Err(WsError::Io(err))
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return,
                _ => {}
            }
        }
    }

    async fn spawn_two_peer_relay_hub(
        pk_a: PublicKey,
        pk_b: PublicKey,
        shutdown: CancellationToken,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind hub");
        let hub_addr = listener.local_addr().expect("hub addr");
        let routes = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(async move {
            let mut conn_idx = 0usize;
            loop {
                let next = tokio::select! {
                    () = shutdown.cancelled() => break,
                    acc = listener.accept() => acc,
                };
                let Ok((tcp, _)) = next else { break };
                let my_pk = if conn_idx == 0 { pk_a } else { pk_b };
                conn_idx = conn_idx.saturating_add(1);
                let std_sock = tcp.into_std().expect("std sock");
                std_sock.set_nonblocking(false).expect("blocking sock");
                let routes_clone = Arc::clone(&routes);
                tokio::task::spawn_blocking(move || {
                    serve_single_relay_peer(std_sock, my_pk, routes_clone);
                });
            }
        });

        hub_addr
    }

    async fn spawn_udp_toggle_proxy(
        addr_a: SocketAddr,
        addr_b: SocketAddr,
        allow_udp: Arc<AtomicBool>,
        shutdown: CancellationToken,
    ) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp toggle proxy");
        let proxy_addr = sock.local_addr().expect("proxy addr");
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_FRAME_SIZE];
            loop {
                let recv = tokio::select! {
                    () = shutdown.cancelled() => break,
                    res = sock.recv_from(&mut buf) => res,
                };
                let Ok((n, src)) = recv else { break };
                if !allow_udp.load(Ordering::Relaxed) {
                    continue;
                }
                let dst = if src == addr_a { addr_b } else { addr_a };
                if let Some(slice) = buf.get(..n)
                    && let Err(err) = sock.send_to(slice, dst).await
                {
                    debug!(component = "datapath.engine.test", error = %err, "proxy send error");
                }
            }
        });
        proxy_addr
    }

    struct TestNodeParams {
        node_id: NodeId,
        tun_name: &'static str,
        overlay_ip: OverlayIp,
        cidr: OverlayCidr,
        node_keypair: NodeKeypair,
        disco_keypair: DiscoKeypair,
        hub_addr: SocketAddr,
        clock: Arc<dyn Clock>,
        disco_config: DiscoConfig,
        tick_interval: Duration,
        shutdown: CancellationToken,
    }

    struct TestNodeHarness {
        tun: Arc<FakeTunDevice>,
        handle: DatapathHandle,
        udp_addr: SocketAddr,
        _rebind_handle: RebindHandle,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    async fn spawn_test_node(params: TestNodeParams) -> TestNodeHarness {
        let relay_cfg = RelayClientConfig {
            endpoint: params.hub_addr.to_string(),
            server_name_override: None,
            pin_set: None,
            underlay_if_index: None,
            linux_fwmark: None,
            require_challenge_auth: false,
            agent_version: "0.1.0-test".to_owned(),
        };
        let relay = RelayClient::with_connector(
            relay_cfg,
            params.node_keypair.clone_keypair(),
            params.disco_keypair.clone_keypair(),
            Arc::new(TestWsConnector {
                addr: params.hub_addr,
            }),
        );
        let relay_handle = relay.handle();
        let (ev_tx, mut ev_rx) = mpsc::channel(64);
        let (fwd_tx, fwd_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel::<()>();

        let relay_task =
            tokio::spawn(relay.run(Arc::clone(&params.clock), ev_tx, params.shutdown.clone()));
        let fwd_task = tokio::spawn(async move {
            let mut tx_opt = Some(ready_tx);
            while let Some(ev) = ev_rx.recv().await {
                if matches!(
                    ev,
                    RelayEvent::StateChanged(RelayConnectionState::Connected)
                ) && let Some(tx) = tx_opt.take()
                    && tx.send(()).is_err()
                {
                    debug!(
                        component = "datapath.engine.test",
                        "relay test readiness receiver closed"
                    );
                }
                if fwd_tx.send(ev).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(3), ready_rx)
            .await
            .expect("relay connected in time")
            .expect("ready channel open");

        let tun = Arc::new(FakeTunDevice::new(
            TunConfig::with_default_mtu(params.tun_name, params.overlay_ip, params.cidr)
                .expect("valid test tun config"),
        ));
        let tun_dyn: Arc<dyn TunDevice> = Arc::clone(&tun) as Arc<dyn TunDevice>;
        let mut engine = DatapathEngine::bind(
            DatapathConfig {
                local_node_id: params.node_id,
                local_overlay_ip: params.overlay_ip,
                overlay_cidr: params.cidr,
                node_keypair: params.node_keypair,
                disco_keypair: params.disco_keypair,
                socket_config: MagicSocketConfig::default()
                    .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                stun_config: StunClientConfig::default(),
                disco_config: params.disco_config,
                control_tcp_endpoint: None,
                wg_timer_interval: params.tick_interval,
                disco_tick_interval: params.tick_interval,
            },
            tun_dyn,
            params.clock,
            Some(relay_handle),
        )
        .await
        .expect("engine binds");
        engine.enable_loopback_disco_for_tests();

        let handle = engine.handle();
        let udp_addr = engine.local_udp_addr().expect("udp addr");
        let (rebind_handle, rebind_rx) = RebindHandle::channel();
        let shutdown = params.shutdown;
        let engine_task = tokio::spawn(async move {
            engine
                .run(fwd_rx, rebind_rx, shutdown)
                .await
                .expect("engine clean exit");
        });

        TestNodeHarness {
            tun,
            handle,
            udp_addr,
            _rebind_handle: rebind_handle,
            tasks: vec![relay_task, fwd_task, engine_task],
        }
    }

    async fn await_tun_packet(tun: &FakeTunDevice, expected: &[u8]) {
        for _ in 0..80 {
            let drained = tun.drain_outbound_packets().await;
            if drained.iter().any(|pkt| pkt.as_slice() == expected) {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for expected plaintext packet on TUN");
    }

    async fn await_peer_path(handle: &DatapathHandle, want_direct: Option<SocketAddr>) {
        for _ in 0..80 {
            let st = handle.query_status().await.expect("status");
            let current = st.peers.first().map(|p| &p.active_path);
            let matched = match (want_direct, current) {
                (None, Some(PeerActivePath::Relay)) => true,
                (Some(expected), Some(PeerActivePath::Direct { addr, .. })) => *addr == expected,
                _ => false,
            };
            if matched {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for peer active_path={want_direct:?}");
    }

    fn base_test_identity() -> (
        NodeKeypair,
        NodeKeypair,
        DiscoKeypair,
        DiscoKeypair,
        NodeId,
        NodeId,
        OverlayIp,
        OverlayIp,
        OverlayCidr,
    ) {
        (
            NodeKeypair::generate(),
            NodeKeypair::generate(),
            DiscoKeypair::generate(),
            DiscoKeypair::generate(),
            NodeId::from_bytes([1u8; 16]),
            NodeId::from_bytes([2u8; 16]),
            OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 2)).expect("ip a"),
            OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 3)).expect("ip b"),
            "10.100.0.0/16".parse().expect("cidr"),
        )
    }

    // Traces: US-026, US-021, US-010
    #[tokio::test]
    async fn test_engine_relay_first_then_direct_udp_upgrade() {
        // Arrange
        let (kp_a, kp_b, dk_a, dk_b, id_a, id_b, ip_a, ip_b, cidr) = base_test_identity();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let shutdown = CancellationToken::new();
        let hub_addr =
            spawn_two_peer_relay_hub(kp_a.public_key(), kp_b.public_key(), shutdown.clone()).await;
        let disco_cfg = DiscoConfig {
            keepalive_interval_ms: 150,
            idle_window_ms: 180_000,
            probe_timeout_ms: 120,
        };
        let node_a = spawn_test_node(TestNodeParams {
            node_id: id_a,
            tun_name: "mesh-a",
            overlay_ip: ip_a,
            cidr,
            node_keypair: kp_a.clone_keypair(),
            disco_keypair: dk_a.clone_keypair(),
            hub_addr,
            clock: Arc::clone(&clock),
            disco_config: disco_cfg.clone(),
            tick_interval: Duration::from_millis(50),
            shutdown: shutdown.clone(),
        })
        .await;
        let node_b = spawn_test_node(TestNodeParams {
            node_id: id_b,
            tun_name: "mesh-b",
            overlay_ip: ip_b,
            cidr,
            node_keypair: kp_b.clone_keypair(),
            disco_keypair: dk_b.clone_keypair(),
            hub_addr,
            clock,
            disco_config: disco_cfg,
            tick_interval: Duration::from_millis(50),
            shutdown: shutdown.clone(),
        })
        .await;

        let mut entry_b = mk_peer_entry(
            id_b,
            "node-b",
            ip_b,
            kp_b.public_key(),
            dk_b.public_key(),
            hub_addr,
        );
        let mut entry_a = mk_peer_entry(
            id_a,
            "node-a",
            ip_a,
            kp_a.public_key(),
            dk_a.public_key(),
            hub_addr,
        );
        node_a
            .handle
            .apply_netmap(mk_netmap(1, vec![entry_b.clone()], hub_addr))
            .await
            .expect("nm A");
        node_b
            .handle
            .apply_netmap(mk_netmap(1, vec![entry_a.clone()], hub_addr))
            .await
            .expect("nm B");

        // Act & Assert Phase 1: Relay-first delivers packet without UDP candidates
        let pkt_ab = build_ipv4_udp_msg(ip_a.as_ipv4(), ip_b.as_ipv4(), b"via-relay-first");
        node_a
            .tun
            .inject_inbound_packet(pkt_ab.clone())
            .await
            .expect("inject A");
        await_tun_packet(&node_b.tun, &pkt_ab).await;
        await_peer_path(&node_a.handle, None).await;

        // Act & Assert Phase 2: Publish Direct UDP endpoints -> upgrades smoothly -> B->A Direct!
        entry_b.endpoints = vec![CandidateEndpoint {
            addr: node_b.udp_addr,
            source: CandidateSource::Reflexive,
        }];
        entry_a.endpoints = vec![CandidateEndpoint {
            addr: node_a.udp_addr,
            source: CandidateSource::Reflexive,
        }];
        node_a
            .handle
            .send(DatapathCommand::SetAdvertisedEndpoints(vec![
                node_a.udp_addr,
            ]))
            .await
            .expect("ep A");
        node_b
            .handle
            .send(DatapathCommand::SetAdvertisedEndpoints(vec![
                node_b.udp_addr,
            ]))
            .await
            .expect("ep B");
        node_a
            .handle
            .apply_netmap(mk_netmap(2, vec![entry_b], hub_addr))
            .await
            .expect("nm2 A");
        node_b
            .handle
            .apply_netmap(mk_netmap(2, vec![entry_a], hub_addr))
            .await
            .expect("nm2 B");
        node_a
            .handle
            .send(DatapathCommand::InitiateHolePunch(id_b))
            .await
            .expect("punch");

        await_peer_path(&node_a.handle, Some(node_b.udp_addr)).await;
        let pkt_ba = build_ipv4_udp_msg(ip_b.as_ipv4(), ip_a.as_ipv4(), b"via-direct-udp");
        node_b
            .tun
            .inject_inbound_packet(pkt_ba.clone())
            .await
            .expect("inject B");
        await_tun_packet(&node_a.tun, &pkt_ba).await;

        shutdown.cancel();
        for t in node_a.tasks.into_iter().chain(node_b.tasks) {
            t.await.expect("node task exited");
        }
    }

    // Traces: US-022, US-026
    #[tokio::test]
    async fn test_engine_direct_to_relay_failover_continues_forwarding() {
        // Arrange: direct UDP flows via toggleable loopback proxy; blocking UDP triggers 3-miss failover
        let (kp_a, kp_b, dk_a, dk_b, id_a, id_b, ip_a, ip_b, cidr) = base_test_identity();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let shutdown = CancellationToken::new();
        let hub_addr =
            spawn_two_peer_relay_hub(kp_a.public_key(), kp_b.public_key(), shutdown.clone()).await;
        let disco_cfg = DiscoConfig {
            keepalive_interval_ms: 40,
            idle_window_ms: 180_000,
            probe_timeout_ms: 60,
        };
        let node_a = spawn_test_node(TestNodeParams {
            node_id: id_a,
            tun_name: "mesh-fo-a",
            overlay_ip: ip_a,
            cidr,
            node_keypair: kp_a.clone_keypair(),
            disco_keypair: dk_a.clone_keypair(),
            hub_addr,
            clock: Arc::clone(&clock),
            disco_config: disco_cfg.clone(),
            tick_interval: Duration::from_millis(20),
            shutdown: shutdown.clone(),
        })
        .await;
        let node_b = spawn_test_node(TestNodeParams {
            node_id: id_b,
            tun_name: "mesh-fo-b",
            overlay_ip: ip_b,
            cidr,
            node_keypair: kp_b.clone_keypair(),
            disco_keypair: dk_b.clone_keypair(),
            hub_addr,
            clock,
            disco_config: disco_cfg,
            tick_interval: Duration::from_millis(20),
            shutdown: shutdown.clone(),
        })
        .await;

        let allow_udp = Arc::new(AtomicBool::new(true));
        let proxy_addr = spawn_udp_toggle_proxy(
            node_a.udp_addr,
            node_b.udp_addr,
            Arc::clone(&allow_udp),
            shutdown.clone(),
        )
        .await;

        let mut entry_b = mk_peer_entry(
            id_b,
            "node-b",
            ip_b,
            kp_b.public_key(),
            dk_b.public_key(),
            hub_addr,
        );
        let mut entry_a = mk_peer_entry(
            id_a,
            "node-a",
            ip_a,
            kp_a.public_key(),
            dk_a.public_key(),
            hub_addr,
        );
        entry_b.endpoints = vec![CandidateEndpoint {
            addr: proxy_addr,
            source: CandidateSource::Reflexive,
        }];
        entry_a.endpoints = vec![CandidateEndpoint {
            addr: proxy_addr,
            source: CandidateSource::Reflexive,
        }];
        node_a
            .handle
            .apply_netmap(mk_netmap(1, vec![entry_b], hub_addr))
            .await
            .expect("nm A");
        node_b
            .handle
            .apply_netmap(mk_netmap(1, vec![entry_a], hub_addr))
            .await
            .expect("nm B");
        node_a
            .handle
            .send(DatapathCommand::InitiateHolePunch(id_b))
            .await
            .expect("punch");
        await_peer_path(&node_a.handle, Some(proxy_addr)).await;

        // Warm WireGuard handshake over Direct first
        let pkt_direct = build_ipv4_udp_msg(ip_a.as_ipv4(), ip_b.as_ipv4(), b"warm-direct");
        node_a
            .tun
            .inject_inbound_packet(pkt_direct.clone())
            .await
            .expect("inject warm");
        await_tun_packet(&node_b.tun, &pkt_direct).await;

        // Act: block UDP -> active traffic + 3 missed Disco Pongs triggers failover back to Blind Relay
        allow_udp.store(false, Ordering::Relaxed);
        await_peer_path(&node_a.handle, None).await;
        let st_after = node_a.handle.query_status().await.expect("status");
        assert!(st_after.disco_metrics.direct_failovers >= 1);

        // Assert: encrypted traffic still flows over Blind Relay without session drop
        let pkt_failover =
            build_ipv4_udp_msg(ip_a.as_ipv4(), ip_b.as_ipv4(), b"via-relay-failover");
        node_a
            .tun
            .inject_inbound_packet(pkt_failover.clone())
            .await
            .expect("inject failover");
        await_tun_packet(&node_b.tun, &pkt_failover).await;

        shutdown.cancel();
        for t in node_a.tasks.into_iter().chain(node_b.tasks) {
            t.await.expect("node task exited");
        }
    }

    // Traces: US-019, HR-S1-08
    #[tokio::test]
    async fn test_engine_stun_probe_400ms_rtt_not_truncated_by_250ms_ticks_and_populates_status_report()
     {
        // Arrange: local STUN server delays >= 360 ms and gates reply on Notify after 320 ms assert
        let stun_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stun");
        let stun_addr = stun_sock.local_addr().expect("stun addr");
        let mapped_addr: SocketAddr = "198.51.100.88:44444".parse().expect("mapped");
        let shutdown = CancellationToken::new();
        let stun_shutdown = shutdown.clone();
        let release_reply = Arc::new(tokio::sync::Notify::new());
        let release_reply_srv = Arc::clone(&release_reply);

        let stun_task = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let recv_res = tokio::select! {
                () = stun_shutdown.cancelled() => return,
                res = stun_sock.recv_from(&mut buf) => res,
            };
            let Ok((n, src)) = recv_res else { return };
            let req = parse_stun_packet(buf.get(..n).expect("slice")).expect("valid stun");
            sleep(Duration::from_millis(360)).await;
            tokio::select! {
                () = stun_shutdown.cancelled() => return,
                () = release_reply_srv.notified() => {}
            }
            let rsp = encode_binding_success_response(req.tx_id, mapped_addr);
            drop(stun_sock.send_to(&rsp, src).await);
        });

        let cidr: OverlayCidr = "10.100.0.0/16".parse().expect("cidr");
        let overlay_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 10)).expect("ip");
        let tun = Arc::new(FakeTunDevice::new(
            TunConfig::with_default_mtu("mesh-stun-test", overlay_ip, cidr).expect("tun cfg"),
        ));
        let engine = DatapathEngine::bind(
            DatapathConfig {
                local_node_id: NodeId::from_bytes([0x55; 16]),
                local_overlay_ip: overlay_ip,
                overlay_cidr: cidr,
                node_keypair: NodeKeypair::generate(),
                disco_keypair: DiscoKeypair::generate(),
                socket_config: MagicSocketConfig::default()
                    .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                stun_config: StunClientConfig::with_timeout(Duration::from_secs(2)),
                disco_config: DiscoConfig::default(),
                control_tcp_endpoint: None,
                wg_timer_interval: Duration::from_millis(250),
                disco_tick_interval: Duration::from_millis(250),
            },
            Arc::clone(&tun) as Arc<dyn TunDevice>,
            Arc::new(SystemClock::new()),
            None,
        )
        .await
        .expect("bind engine");
        let handle = engine.handle();
        let (_ev_tx, ev_rx) = mpsc::channel(16);
        let (_reb_tx, reb_rx) = mpsc::channel(8);
        let run_shutdown = shutdown.clone();
        let engine_task = tokio::spawn(async move {
            engine.run(ev_rx, reb_rx, run_shutdown).await.expect("run");
        });

        // Act: trigger STUN probe via ApplyNetmap while reply is held behind Notify barrier
        let mut netmap = mk_netmap(1, vec![], stun_addr);
        netmap.relay_map.stun_udp_endpoints = vec![stun_addr.to_string()];
        handle.apply_netmap(netmap).await.expect("apply netmap");

        // After 320 ms (>= one 250 ms disco tick), probe MUST still be pending (NOT truncated)
        sleep(Duration::from_millis(320)).await;
        let mid_status = handle.query_status().await.expect("mid status");
        assert!(
            mid_status.last_stun_report.is_none(),
            "250 ms tick prematurely finalized a pending 2 s STUN probe round"
        );

        // Release the delayed STUN Binding Response and poll for DatapathStatusSnapshot update
        release_reply.notify_one();
        let mut final_report = None;
        for _ in 0..30 {
            let st = handle.query_status().await.expect("poll status");
            if let Some(report) = st.last_stun_report {
                final_report = Some(report);
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }

        shutdown.cancel();
        engine_task.await.expect("engine exit");
        stun_task.await.expect("stun exit");

        // Assert
        let report = final_report.expect("slow STUN probe should populate report");
        assert!(!report.udp_blocked);
        assert_eq!(report.nat_mapping, NatMappingKind::EimOrAdm);
        assert_eq!(report.reflexive_addrs, vec![mapped_addr]);
        assert!(
            report.best_rtt_ms.is_some_and(|rtt| rtt >= 300),
            "expected >= 300 ms RTT, got {:?}",
            report.best_rtt_ms
        );
    }

    // Traces: BLK-W12-02
    #[tokio::test]
    async fn test_datapath_send_ping_probe_returns_timeout_when_peer_offline_despite_relay_connected()
     {
        // Arrange: Node A is connected to Blind Relay, but Node B never connects (offline peer).
        let (kp_a, kp_b, dk_a, dk_b, id_a, id_b, ip_a, ip_b, cidr) = base_test_identity();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let shutdown = CancellationToken::new();
        let hub_addr =
            spawn_two_peer_relay_hub(kp_a.public_key(), kp_b.public_key(), shutdown.clone()).await;
        let node_a = spawn_test_node(TestNodeParams {
            node_id: id_a,
            tun_name: "mesh-ping-offline-a",
            overlay_ip: ip_a,
            cidr,
            node_keypair: kp_a.clone_keypair(),
            disco_keypair: dk_a.clone_keypair(),
            hub_addr,
            clock: Arc::clone(&clock),
            disco_config: DiscoConfig::default(),
            tick_interval: Duration::from_millis(50),
            shutdown: shutdown.clone(),
        })
        .await;

        let entry_b = mk_peer_entry(
            id_b,
            "offline-peer",
            ip_b,
            kp_b.public_key(),
            dk_b.public_key(),
            hub_addr,
        );
        node_a
            .handle
            .apply_netmap(mk_netmap(1, vec![entry_b], hub_addr))
            .await
            .expect("apply netmap");

        let mut connected = false;
        for _ in 0..30 {
            if matches!(
                node_a
                    .handle
                    .query_status()
                    .await
                    .expect("status")
                    .relay_state,
                RelayConnectionState::Connected
            ) {
                connected = true;
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(connected);

        // Act: probe offline peer while local Relay is Connected -> MUST timeout (100% loss).
        let outcome = node_a
            .handle
            .send_ping_probe(id_b, false, false, 120)
            .await
            .expect("probe completes");

        shutdown.cancel();
        for t in node_a.tasks {
            t.await.expect("node task exited");
        }

        // Assert
        assert_eq!(outcome.path, PingProbePath::Timeout);
        assert_eq!(outcome.rtt_ms, None);
    }

    // Traces: BLK-W12-02, BLK-W12-04
    #[tokio::test]
    async fn test_datapath_send_ping_probe_and_handle_relayed_disco_return_measured_rtt() {
        // Arrange
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer udp");
        let peer_udp_addr = peer_sock.local_addr().expect("peer addr");
        let peer_id = NodeId::from_bytes([0x72; 16]);
        let peer_kp = NodeKeypair::generate();
        let peer_dk = DiscoKeypair::from_secret_bytes([0x52; 32]).expect("peer dk");
        let local_kp = NodeKeypair::generate();
        let local_dk = DiscoKeypair::generate();
        let local_disco_pub = local_dk.public_key();
        let peer_dk_responder = DiscoKeypair::from_secret_bytes([0x52; 32]).expect("peer dk resp");

        let shutdown = CancellationToken::new();
        let peer_shutdown = shutdown.clone();
        let peer_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut saw_ping = false;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while tokio::time::Instant::now() < deadline && !peer_shutdown.is_cancelled() {
                let recv = tokio::select! {
                    () = peer_shutdown.cancelled() => break,
                    res = peer_sock.recv_from(&mut buf) => res,
                };
                let Ok((len, src_addr)) = recv else {
                    continue;
                };
                if let Some(pkt) = buf.get(..len)
                    && let Ok(opened) = open_disco_packet(pkt, &peer_dk_responder)
                    && let Ok(mesh_proto::disco::DiscoBody::Ping) =
                        mesh_proto::disco::DiscoBody::decode(opened.msg_type, &opened.body)
                {
                    saw_ping = true;
                    let body = mesh_proto::disco::DiscoBody::Pong {
                        observed_addr: src_addr,
                    }
                    .encode()
                    .expect("encode pong");
                    let pong = mesh_crypto::seal_disco_packet(
                        &peer_dk_responder,
                        &mesh_crypto::DiscoSealParams {
                            recipient_pubkey: local_disco_pub,
                            msg_type: mesh_proto::disco::DiscoBody::Pong {
                                observed_addr: src_addr,
                            }
                            .msg_type() as u8,
                            tx_id: opened.tx_id,
                            sent_at_ms: 100_000,
                            body: &body,
                        },
                    )
                    .expect("seal pong");
                    peer_sock.send_to(&pong, src_addr).await.expect("send pong");
                }
            }
            saw_ping
        });

        let cidr = "10.100.0.0/16".parse().expect("cidr");
        let overlay_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 1)).expect("ip1");
        let tun = Arc::new(FakeTunDevice::new(
            TunConfig::with_default_mtu("utun-ping-live", overlay_ip, cidr).expect("tun cfg"),
        ));
        let mut engine = DatapathEngine::bind(
            DatapathConfig {
                local_node_id: NodeId::from_bytes([0x71; 16]),
                local_overlay_ip: overlay_ip,
                overlay_cidr: cidr,
                node_keypair: local_kp,
                disco_keypair: local_dk,
                socket_config: MagicSocketConfig::default()
                    .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                stun_config: StunClientConfig::default(),
                disco_config: DiscoConfig::default(),
                control_tcp_endpoint: None,
                wg_timer_interval: Duration::from_millis(250),
                disco_tick_interval: Duration::from_millis(250),
            },
            Arc::clone(&tun) as Arc<dyn TunDevice>,
            Arc::new(SystemClock::new()),
            None,
        )
        .await
        .expect("bind engine");
        engine.enable_loopback_disco_for_tests();
        let handle = engine.handle();
        let (_ev_tx, ev_rx) = mpsc::channel(8);
        let (_reb_tx, reb_rx) = mpsc::channel(8);
        let run_shutdown = shutdown.clone();
        let engine_task = tokio::spawn(async move {
            engine.run(ev_rx, reb_rx, run_shutdown).await.expect("run");
        });

        let mut peer_entry = mk_peer_entry(
            peer_id,
            "live-peer",
            OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 2)).expect("ip2"),
            peer_kp.public_key(),
            peer_dk.public_key(),
            peer_udp_addr,
        );
        peer_entry.endpoints = vec![CandidateEndpoint {
            addr: peer_udp_addr,
            source: CandidateSource::Lan,
        }];
        handle
            .apply_netmap(mk_netmap(1, vec![peer_entry], peer_udp_addr))
            .await
            .expect("apply netmap");

        // Act 1: deliver Control CallMeMaybeRelay -> engine must respond with Direct UDP DiscoPing!
        let call_me_body = mesh_proto::disco::DiscoBody::CallMeMaybe {
            endpoints: vec![peer_udp_addr],
        }
        .encode()
        .expect("call me");
        let call_me_pkt = mesh_crypto::seal_disco_packet(
            &peer_dk,
            &mesh_crypto::DiscoSealParams {
                recipient_pubkey: local_disco_pub,
                msg_type: mesh_proto::disco::DiscoBody::CallMeMaybe {
                    endpoints: vec![peer_udp_addr],
                }
                .msg_type() as u8,
                tx_id: [0x33; 12],
                sent_at_ms: 100_000,
                body: &call_me_body,
            },
        )
        .expect("seal call me");
        handle
            .handle_relayed_disco(peer_id, peer_kp.public_key(), Bytes::from(call_me_pkt))
            .await
            .expect("handle relayed disco");

        // Act 2: send interactive direct probe and verify true measured Direct outcome!
        let outcome = handle
            .send_ping_probe(peer_id, true, false, 1500)
            .await
            .expect("probe completes");

        shutdown.cancel();
        engine_task.await.expect("engine exit");
        let responder_saw_ping = peer_task.await.expect("peer responder exit");

        // Assert
        assert!(responder_saw_ping);
        assert_eq!(
            outcome.path,
            PingProbePath::Direct {
                addr: peer_udp_addr
            }
        );
        assert!(outcome.rtt_ms.is_some());
    }

    // Traces: US-030, US-018
    #[tokio::test]
    async fn test_engine_live_revoked_peer_cut_within_2_seconds_and_packet_filter_enforced() {
        // Arrange: spin up A <-> B live WireGuard Direct UDP + Relay tunnel
        let (kp_a, kp_b, dk_a, dk_b, id_a, id_b, ip_a, ip_b, cidr) = base_test_identity();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let shutdown = CancellationToken::new();
        let hub_addr =
            spawn_two_peer_relay_hub(kp_a.public_key(), kp_b.public_key(), shutdown.clone()).await;
        let disco_cfg = DiscoConfig {
            keepalive_interval_ms: 150,
            idle_window_ms: 180_000,
            probe_timeout_ms: 120,
        };
        let node_a = spawn_test_node(TestNodeParams {
            node_id: id_a,
            tun_name: "mesh-cut-a",
            overlay_ip: ip_a,
            cidr,
            node_keypair: kp_a.clone_keypair(),
            disco_keypair: dk_a.clone_keypair(),
            hub_addr,
            clock: Arc::clone(&clock),
            disco_config: disco_cfg.clone(),
            tick_interval: Duration::from_millis(25),
            shutdown: shutdown.clone(),
        })
        .await;
        let node_b = spawn_test_node(TestNodeParams {
            node_id: id_b,
            tun_name: "mesh-cut-b",
            overlay_ip: ip_b,
            cidr,
            node_keypair: kp_b.clone_keypair(),
            disco_keypair: dk_b.clone_keypair(),
            hub_addr,
            clock,
            disco_config: disco_cfg,
            tick_interval: Duration::from_millis(25),
            shutdown: shutdown.clone(),
        })
        .await;

        let mut entry_b = mk_peer_entry(
            id_b,
            "peer-b-live",
            ip_b,
            kp_b.public_key(),
            dk_b.public_key(),
            hub_addr,
        );
        entry_b.endpoints = vec![CandidateEndpoint {
            addr: node_b.udp_addr,
            source: CandidateSource::Lan,
        }];
        let mut entry_a = mk_peer_entry(
            id_a,
            "peer-a-live",
            ip_a,
            kp_a.public_key(),
            dk_a.public_key(),
            hub_addr,
        );
        entry_a.endpoints = vec![CandidateEndpoint {
            addr: node_a.udp_addr,
            source: CandidateSource::Lan,
        }];

        node_a
            .handle
            .apply_netmap(mk_netmap(1, vec![entry_b], hub_addr))
            .await
            .expect("nm1 A");
        node_b
            .handle
            .apply_netmap(mk_netmap(1, vec![entry_a], hub_addr))
            .await
            .expect("nm1 B");

        // Promote to live Direct UDP path and prove bidirectional tunnel traffic works
        node_a
            .handle
            .send(DatapathCommand::SetAdvertisedEndpoints(vec![
                node_a.udp_addr,
            ]))
            .await
            .expect("adv A");
        node_b
            .handle
            .send(DatapathCommand::SetAdvertisedEndpoints(vec![
                node_b.udp_addr,
            ]))
            .await
            .expect("adv B");
        node_a
            .handle
            .send(DatapathCommand::InitiateHolePunch(id_b))
            .await
            .expect("punch");
        await_peer_path(&node_a.handle, Some(node_b.udp_addr)).await;

        // Exercise US-018 fail-safe filter reload while tunnel is live (block port 3389, allow 5001)
        node_a
            .handle
            .try_reload_packet_filter_spec("tcp:3389,udp:3389")
            .await
            .expect("valid blocklist");
        assert!(
            node_a
                .handle
                .try_reload_packet_filter_spec("bad:syntax:99999")
                .await
                .is_err()
        );

        let blocked_pkt =
            build_ipv4_udp_msg_with_port(ip_b.as_ipv4(), ip_a.as_ipv4(), 3389, b"blocked-3389");
        node_b
            .tun
            .inject_inbound_packet(blocked_pkt)
            .await
            .expect("inject blocked");
        sleep(Duration::from_millis(80)).await;
        assert!(node_a.tun.drain_outbound_packets().await.is_empty());

        let allowed_pkt =
            build_ipv4_udp_msg_with_port(ip_b.as_ipv4(), ip_a.as_ipv4(), 5001, b"live-allowed");
        node_b
            .tun
            .inject_inbound_packet(allowed_pkt.clone())
            .await
            .expect("inject allowed");
        await_tun_packet(&node_a.tun, &allowed_pkt).await;

        // Act (US-030): revoke peer B from node A's netmap while tunnel is active!
        let cut_started = std::time::Instant::now();
        let report = node_a
            .handle
            .apply_netmap(mk_netmap(2, vec![], hub_addr))
            .await
            .expect("apply cut netmap");
        let cut_elapsed = cut_started.elapsed();
        assert!(
            cut_elapsed <= Duration::from_secs(2),
            "peer cut exceeded 2s budget: {cut_elapsed:?}"
        );
        assert_eq!(report.removed, 1);
        assert_eq!(report.removed_peer_ids, vec![id_b]);
        assert!(
            node_a
                .handle
                .query_status()
                .await
                .expect("status")
                .peers
                .is_empty()
        );

        // B (whose local map was not yet updated) keeps blasting encrypted WireGuard packets -> A MUST drop 100%!
        let _drain = node_a.tun.drain_outbound_packets().await;
        for seq in 0..5u8 {
            let after_cut =
                build_ipv4_udp_msg_with_port(ip_b.as_ipv4(), ip_a.as_ipv4(), 5001, &[b'x', seq]);
            node_b
                .tun
                .inject_inbound_packet(after_cut)
                .await
                .expect("inject after cut");
        }
        sleep(Duration::from_millis(180)).await;
        let leaked = node_a.tun.drain_outbound_packets().await;
        assert!(
            leaked.is_empty(),
            "post-cut packets from revoked peer MUST be dropped 100%, got {} packets",
            leaked.len()
        );

        shutdown.cancel();
        for t in node_a.tasks.into_iter().chain(node_b.tasks) {
            t.await.expect("node task exited");
        }
    }

    fn build_ipv4_udp_msg_with_port(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut pkt = Vec::with_capacity(total);
        pkt.extend_from_slice(&[0x45, 0]);
        pkt.extend_from_slice(&(u16::try_from(total).unwrap_or(28)).to_be_bytes());
        pkt.extend_from_slice(&[0; 5]);
        pkt.push(17);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(&5000u16.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&((8 + u16::try_from(payload.len()).unwrap_or(0)).to_be_bytes()));
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(payload);
        pkt
    }

    // Traces: HR-W21-07 (`US-030 AC1`)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_apply_netmap_unblocked_by_stun_dns_completes_under_200ms_and_purges_peers() {
        // Arrange
        let (kp_a, kp_b, dk_a, dk_b, id_a, id_b, ip_a, ip_b, cidr) = base_test_identity();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let shutdown = CancellationToken::new();
        let hub_addr: SocketAddr = "127.0.0.1:49999".parse().expect("dummy hub addr");
        let tun = Arc::new(FakeTunDevice::new(
            TunConfig::with_default_mtu("mesh-dns-test", ip_a, cidr)
                .expect("valid test tun config"),
        ));
        let cfg = DatapathConfig {
            local_node_id: id_a,
            local_overlay_ip: ip_a,
            overlay_cidr: cidr,
            node_keypair: kp_a,
            disco_keypair: dk_a,
            socket_config: MagicSocketConfig::default()
                .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: Duration::from_millis(250),
            disco_tick_interval: Duration::from_millis(250),
        };
        let engine = DatapathEngine::bind(cfg, tun, clock, None)
            .await
            .expect("bind engine");
        let handle = engine.handle();
        let (_relay_tx, relay_rx) = mpsc::channel(8);
        let (_rebind_handle, rebind_rx) = RebindHandle::channel();
        let engine_task = tokio::spawn(engine.run(relay_rx, rebind_rx, shutdown.clone()));

        let mut peer_b = mk_peer_entry(
            id_b,
            "peer-b",
            ip_b,
            kp_b.public_key(),
            dk_b.public_key(),
            hub_addr,
        );
        peer_b.endpoints.push(CandidateEndpoint {
            addr: "127.0.0.1:51822".parse().expect("valid cand addr"),
            source: CandidateSource::Lan,
        });
        let snap_v1 = mk_netmap(1, vec![peer_b], hub_addr);
        let rep_v1 = handle.apply_netmap(snap_v1).await.expect("apply v1");
        assert_eq!(rep_v1.added, 1);

        // Act: revoke peer_b AND include an unresolved/invalid STUN hostname in v2
        let mut snap_v2 = mk_netmap(2, vec![], hub_addr);
        snap_v2.relay_map.stun_udp_endpoints = vec![
            "stun-hang-1.invalid.mesh.test.:3479".to_owned(),
            "stun-hang-2.invalid.mesh.test.:3480".to_owned(),
        ];
        let started = tokio::time::Instant::now();
        let rep_v2 = tokio::time::timeout(Duration::from_millis(800), handle.apply_netmap(snap_v2))
            .await
            .expect("apply_netmap MUST NOT block on STUN DNS lookup")
            .expect("apply v2 result");
        let elapsed = started.elapsed();

        // Assert
        assert!(
            elapsed < Duration::from_millis(800),
            "apply_netmap took {elapsed:?}, expected < 800ms"
        );
        assert_eq!(rep_v2.removed_peer_ids, vec![id_b]);
        assert!(
            handle
                .query_status()
                .await
                .expect("status")
                .peers
                .is_empty(),
            "revoked peer MUST be purged immediately"
        );

        shutdown.cancel();
        let shutdown_res = tokio::time::timeout(Duration::from_secs(2), engine_task).await;
        assert!(
            shutdown_res.is_ok(),
            "engine shutdown MUST cancel in-flight STUN DNS lookup cleanly"
        );
    }

    // Traces: HR-W21-08 (`US-035`, `US-036`)
    #[tokio::test]
    async fn test_rebind_underlay_blocks_direct_udp_on_failure_and_recovers_on_retry() {
        // Arrange
        let (kp_a, kp_b, dk_a, dk_b, id_a, id_b, ip_a, ip_b, cidr) = base_test_identity();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let shutdown = CancellationToken::new();
        let probe_receiver = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp probe sink");
        let probe_sink_addr = probe_receiver.local_addr().expect("sink addr");

        let tun = Arc::new(FakeTunDevice::new(
            TunConfig::with_default_mtu("mesh-rebind-test", ip_a, cidr)
                .expect("valid test tun config"),
        ));
        let cfg = DatapathConfig {
            local_node_id: id_a,
            local_overlay_ip: ip_a,
            overlay_cidr: cidr,
            node_keypair: kp_a,
            disco_keypair: dk_a,
            socket_config: MagicSocketConfig::default()
                .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: Duration::from_millis(250),
            disco_tick_interval: Duration::from_millis(250),
        };
        let mut engine = DatapathEngine::bind(cfg, tun, clock, None)
            .await
            .expect("bind engine");
        engine.enable_loopback_disco_for_tests();
        engine.inject_rebind_failure_for_tests(AppError::unavailable(
            "simulated transient NIC bind failure",
        ));
        let handle = engine.handle();
        let (_relay_tx, relay_rx) = mpsc::channel(8);
        let (_rebind_handle, rebind_rx) = RebindHandle::channel();
        let engine_task = tokio::spawn(engine.run(relay_rx, rebind_rx, shutdown.clone()));

        let mut peer_b = mk_peer_entry(
            id_b,
            "peer-b",
            ip_b,
            kp_b.public_key(),
            dk_b.public_key(),
            probe_sink_addr,
        );
        peer_b.endpoints.push(CandidateEndpoint {
            addr: probe_sink_addr,
            source: CandidateSource::Lan,
        });
        let mut snap = mk_netmap(1, vec![peer_b], probe_sink_addr);
        snap.relay_map.stun_udp_endpoints = vec![probe_sink_addr.to_string()];
        handle
            .apply_netmap(snap)
            .await
            .expect("apply initial netmap");

        // Drain initial STUN probe triggered by netmap application
        let mut recv_buf = [0u8; 256];
        let initial_recv = tokio::time::timeout(
            Duration::from_secs(2),
            probe_receiver.recv_from(&mut recv_buf),
        )
        .await;
        assert!(initial_recv.is_ok(), "initial STUN probe should arrive");
        while probe_receiver.try_recv_from(&mut recv_buf).is_ok() {}

        // Act 1: rebind fails -> MUST return Err AND block direct UDP egress
        let fail_res = handle.rebind_underlay("eth0".to_owned(), None, false).await;
        assert!(fail_res.is_err(), "first rebind MUST return Err");

        handle
            .send(DatapathCommand::TriggerStunProbe)
            .await
            .expect("queue stun probe");
        handle
            .send(DatapathCommand::InitiateHolePunch(id_b))
            .await
            .expect("queue hole punch");
        let _status_barrier = handle.query_status().await.expect("status barrier");
        let blocked_recv = tokio::time::timeout(
            Duration::from_millis(120),
            probe_receiver.recv_from(&mut recv_buf),
        )
        .await;
        assert!(
            blocked_recv.is_err(),
            "direct UDP probes MUST be blocked while rebind is failed"
        );

        // Act 2: retry rebind succeeds -> unblocks UDP TX and returns bound port
        let rebound_port = handle
            .rebind_underlay("eth0".to_owned(), None, false)
            .await
            .expect("retry rebind MUST succeed");
        assert!(rebound_port > 0);
        handle
            .send(DatapathCommand::TriggerStunProbe)
            .await
            .expect("queue stun probe after recovery");
        let after_recv = tokio::time::timeout(
            Duration::from_secs(2),
            probe_receiver.recv_from(&mut recv_buf),
        )
        .await;
        assert!(
            after_recv.is_ok(),
            "STUN probe MUST transmit once rebind succeeds"
        );

        shutdown.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), engine_task)
                .await
                .is_ok()
        );
    }
}
