//! Shared non-secret runtime state coordinated across Control, Datapath, Roaming, and Platform
//! hooks (`US-033`, `US-039`, `ADR-015`, `ADR-016`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::{RwLock, watch};

use mesh_core::clock::{Clock as _, SystemClock};
use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp};
use mesh_datapath::{
    DatapathHandle, DatapathStatusSnapshot, PeerActivePath, RebindHandle, RelayClientHandle,
    RelayConnectionState, TimerMode,
};
use mesh_net::nat64::Nat64Prefix;
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentPeerStatus, AgentStatusResponse, DaemonState, SelfNetworkStatus,
    ServerConnectionStatus,
};
use mesh_proto::netmap::{CandidateEndpoint, CandidateSource, NatMappingKind, NetmapSnapshot};

use crate::config::{
    BootstrapConfig, SplitTunnelRoutePlan, compute_split_tunnel_routes, derive_overlay_dns_ip,
};
use crate::hooks::ClientStateStore;
use crate::netmap_cache::{DEFAULT_KEY_EXPIRY_GRACE_HOURS, NetmapCacheFile};

/// Mutable client runtime state guarded by an async [`RwLock`] (`0` blocking locks across `.await`).
#[derive(Debug)]
pub struct ClientRuntimeData {
    /// Current lifecycle state (`Stopped`, `Connected`, `Degraded`, `ProtocolIncompatible`, etc.).
    pub daemon_state: DaemonState,
    /// Persistent bootstrap configuration (`server_endpoint`, SPKI pins, node identity metadata).
    pub bootstrap: BootstrapConfig,
    /// OS-neutral storage backend (`keys.json`, `bootstrap.toml`, `netmap-cache.json`).
    pub state_store: Arc<dyn ClientStateStore>,
    /// Active TUN interface name (`utunN`, `tun0`, `MeshVPN`).
    pub tun_interface_name: Option<String>,
    /// Configured TUN MTU.
    pub tun_mtu: u16,
    /// Active bound local WireGuard/Disco UDP port.
    pub local_udp_port: u16,
    /// Registered node UUID.
    pub node_id: Option<NodeId>,
    /// Registered RFC 1123 node label.
    pub node_name: Option<NodeName>,
    /// Registered mesh FQDN.
    pub fqdn: Option<String>,
    /// Assigned local overlay IPv4.
    pub overlay_ip: Option<OverlayIp>,
    /// Active overlay IPv4 subnet CIDR.
    pub overlay_cidr: Option<OverlayCidr>,
    /// Derived collision-free overlay Split-DNS resolver IP (`ADR-015`).
    pub overlay_dns_ip: Option<OverlayIp>,
    /// Current active RFC 6052 NAT64 synthesis prefix observed on the physical network.
    pub nat64_prefix: Option<Nat64Prefix>,
    /// Underlay DNS resolvers reported by the OS physical network (`LinkProperties` / system).
    pub underlay_dns_servers: Vec<IpAddr>,
    /// Local node identity key expiry timestamp in UTC ms.
    pub key_expires_at_ms: Option<u64>,
    /// Latest validated or offline-recovered Netmap snapshot.
    pub latest_netmap: Option<NetmapSnapshot>,
    /// Whether the Control TLS/WS stream is currently online.
    pub control_connected: bool,
    /// Measured Blind Relay RTT in milliseconds.
    pub relay_rtt_ms: Option<u64>,
    /// Most recent human-readable operational error.
    pub last_error: Option<String>,
    /// Set to `true` when Control or Relay rejected the agent with HTTP `400 ProtocolIncompatible`.
    pub protocol_incompatible: bool,
    /// Pending Control endpoint port migration target.
    pub migration_pending_endpoint: Option<String>,
    /// Active physical interface name (`en0`, `wlan0`, `Ethernet`).
    pub bound_physical_interface: Option<String>,
    /// Active physical interface OS index (`IP_BOUND_IF` / `IP_UNICAST_IF`).
    pub underlay_if_index: Option<u32>,
    /// Linux policy routing `SO_MARK` value when active.
    pub linux_fwmark: Option<u32>,
    /// Subnet/CGNAT conflict warning (`US-037`).
    pub overlay_conflict_warning: Option<String>,
    /// macOS Application Firewall warning (`US-036`).
    pub macos_firewall_warning: Option<String>,
    /// Android VPN Lockdown Mode warning (`ADR-015`).
    pub lockdown_warning: Option<String>,
    /// Android Strict Private DNS warning (`ADR-015`).
    pub private_dns_warning: Option<String>,
    /// Filtered local candidate UDP endpoints advertised to Control.
    pub local_candidates: Vec<CandidateEndpoint>,
    /// Active timer cadence mode (`Responsive` or `IdleAware`).
    pub timer_mode: TimerMode,
    /// Running Datapath engine control handle.
    pub datapath_handle: Option<DatapathHandle>,
    /// Running UDP socket rebind handle.
    pub rebind_handle: Option<RebindHandle>,
    /// Running Blind Relay client control handle.
    pub relay_handle: Option<RelayClientHandle>,
}

/// Shared non-secret runtime coordinator queried by IPC/FFI and updated by Control/Datapath tasks.
#[derive(Debug)]
pub struct ClientRuntimeState {
    /// Async read-write lock over mutable session state.
    pub inner: RwLock<ClientRuntimeData>,
    ws_close_tx: watch::Sender<bool>,
    timer_mode_tx: watch::Sender<TimerMode>,
}

impl ClientRuntimeState {
    /// Creates a [`ClientRuntimeState`] evaluating offline cache grace using [`SystemClock`].
    #[must_use]
    pub fn new(
        bootstrap: BootstrapConfig,
        state_store: Arc<dyn ClientStateStore>,
        cached: Option<&NetmapCacheFile>,
        tun_mtu: u16,
        timer_mode: TimerMode,
    ) -> Self {
        Self::new_with_now(
            bootstrap,
            state_store,
            cached,
            tun_mtu,
            timer_mode,
            SystemClock::new().now_unix_ms(),
        )
    }

    /// Creates a [`ClientRuntimeState`] evaluating offline cache grace at `now_unix_ms` (`HR-W21-13`).
    #[must_use]
    pub fn new_with_now(
        bootstrap: BootstrapConfig,
        state_store: Arc<dyn ClientStateStore>,
        cached: Option<&NetmapCacheFile>,
        tun_mtu: u16,
        timer_mode: TimerMode,
        now_unix_ms: u64,
    ) -> Self {
        let (ws_close_tx, _) = watch::channel(false);
        let (timer_mode_tx, _) = watch::channel(timer_mode);
        let cache_self_exp = cached.and_then(|c| {
            c.local_key_expires_at_ms.or_else(|| {
                bootstrap.node_id.and_then(|nid| {
                    c.netmap
                        .peers
                        .iter()
                        .find(|p| p.node_id == nid)
                        .and_then(|p| p.key_expires_at_ms)
                })
            })
        });
        let local_key_expires_at_ms = bootstrap.key_expires_at_ms.or(cache_self_exp);
        let initial_netmap = cached.and_then(|c| {
            c.snapshot_for_offline_recovery(
                now_unix_ms,
                local_key_expires_at_ms,
                DEFAULT_KEY_EXPIRY_GRACE_HOURS,
            )
        });
        let initial_udp_port = cached.map_or(0, |c| c.local_udp_port);
        let overlay_cidr = initial_netmap.as_ref().map(|n| n.overlay_cidr);
        let node_id = bootstrap.node_id;
        let node_name = bootstrap.node_name.clone();
        let overlay_ip = bootstrap.overlay_ip;
        let fqdn = bootstrap
            .fqdn
            .clone()
            .or_else(|| match (&node_name, &initial_netmap) {
                (Some(name), Some(nm)) => Some(format!("{name}.{}", nm.domain_suffix)),
                _ => None,
            });
        let overlay_dns_ip = initial_netmap
            .as_ref()
            .and_then(|nm| derive_overlay_dns_ip(nm.overlay_cidr, overlay_ip, &nm.peers, &[]).ok());

        Self {
            inner: RwLock::new(ClientRuntimeData {
                daemon_state: DaemonState::Stopped,
                bootstrap,
                state_store,
                tun_interface_name: None,
                tun_mtu,
                local_udp_port: initial_udp_port,
                node_id,
                node_name,
                fqdn,
                overlay_ip,
                overlay_cidr,
                overlay_dns_ip,
                nat64_prefix: None,
                underlay_dns_servers: Vec::new(),
                key_expires_at_ms: local_key_expires_at_ms,
                latest_netmap: initial_netmap,
                control_connected: false,
                relay_rtt_ms: None,
                last_error: None,
                protocol_incompatible: false,
                migration_pending_endpoint: None,
                bound_physical_interface: None,
                underlay_if_index: None,
                linux_fwmark: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                lockdown_warning: None,
                private_dns_warning: None,
                local_candidates: Vec::new(),
                timer_mode,
                datapath_handle: None,
                rebind_handle: None,
                relay_handle: None,
            }),
            ws_close_tx,
            timer_mode_tx,
        }
    }

    /// Broadcasts an immediate WebSocket Close notification (`T + <= 1 s` on shutdown).
    pub fn notify_ws_close(&self) {
        if let Err(err) = self.ws_close_tx.send(true) {
            tracing::debug!(
                component = "mesh_client.state",
                event = "ws_close_watch_no_receivers",
                error = %err,
                "no active Control stream receivers during ws_close notify"
            );
        }
    }

    /// Resets WebSocket close watch before starting a new tunnel session.
    pub fn reset_ws_close(&self) {
        if let Err(err) = self.ws_close_tx.send(false) {
            tracing::debug!(
                component = "mesh_client.state",
                event = "ws_close_reset_no_receivers",
                error = %err,
                "no active Control stream receivers during ws_close reset"
            );
        }
    }

    /// Subscribes to shutdown WS-close notifications.
    #[must_use]
    pub fn subscribe_ws_close(&self) -> watch::Receiver<bool> {
        self.ws_close_tx.subscribe()
    }

    /// Subscribes to live [`TimerMode`] updates (`Responsive` <-> `IdleAware`).
    #[must_use]
    pub fn subscribe_timer_mode(&self) -> watch::Receiver<TimerMode> {
        self.timer_mode_tx.subscribe()
    }

    /// Updates active [`TimerMode`] across Control, Datapath, and Blind Relay handles (`ADR-016`).
    pub async fn set_timer_mode(&self, mode: TimerMode) {
        let (datapath, relay) = {
            let mut g = self.inner.write().await;
            g.timer_mode = mode;
            (g.datapath_handle.clone(), g.relay_handle.clone())
        };
        if let Err(err) = self.timer_mode_tx.send(mode) {
            tracing::debug!(
                component = "mesh_client.state",
                event = "timer_mode_watch_no_receivers",
                error = %err,
                "no active Control stream receivers during timer_mode broadcast"
            );
        }
        if let Some(dp) = datapath
            && let Err(err) = dp.set_timer_mode(mode).await
        {
            tracing::debug!(
                component = "mesh_client.state",
                event = "datapath_timer_mode_update_skipped",
                error = %err,
                "datapath ignored timer_mode update"
            );
        }
        if let Some(rl) = relay {
            rl.set_timer_mode(mode);
        }
    }

    /// Updates the active NAT64 synthesis prefix across Datapath and Blind Relay (`ADR-015`).
    pub async fn set_nat64_prefix(&self, prefix: Option<Nat64Prefix>) {
        let (datapath, relay) = {
            let mut g = self.inner.write().await;
            g.nat64_prefix = prefix;
            (g.datapath_handle.clone(), g.relay_handle.clone())
        };
        if let Some(dp) = datapath
            && let Err(err) = dp.set_nat64_prefix(prefix).await
        {
            tracing::debug!(
                component = "mesh_client.state",
                event = "datapath_nat64_update_skipped",
                error = %err,
                "datapath ignored nat64_prefix update"
            );
        }
        if let Some(rl) = relay {
            rl.set_nat64_prefix(prefix);
        }
    }

    /// Returns whether Control/Relay triggered an unrecoverable HTTP `400` `ProtocolIncompatible` stop.
    pub async fn is_protocol_incompatible(&self) -> bool {
        self.inner.read().await.protocol_incompatible
    }

    /// Computes the current split-tunnel route plan (`OQ-MOB-04`) from live Netmap & underlay DNS.
    pub async fn current_split_tunnel_plan(&self) -> Option<SplitTunnelRoutePlan> {
        let g = self.inner.read().await;
        let cidr = g.overlay_cidr?;
        let self_ip = g.overlay_ip?;
        let peers = g
            .latest_netmap
            .as_ref()
            .map_or(&[][..], |n| n.peers.as_slice());
        let dns_ip = g.overlay_dns_ip.or_else(|| {
            derive_overlay_dns_ip(cidr, Some(self_ip), peers, &g.underlay_dns_servers).ok()
        })?;
        let conflict = g.overlay_conflict_warning.is_some();
        compute_split_tunnel_routes(
            cidr,
            self_ip,
            dns_ip,
            peers,
            &g.underlay_dns_servers,
            conflict,
        )
        .ok()
    }

    /// Resolves a peer reference by UUID, short name, FQDN, or overlay IP.
    pub async fn find_peer(&self, target: &str) -> Option<(NodeId, NodeName, OverlayIp, bool)> {
        let trimmed = target.trim();
        let guard = self.inner.read().await;
        let netmap = guard.latest_netmap.as_ref()?;
        for peer in &netmap.peers {
            let id_match = peer.node_id.to_string().eq_ignore_ascii_case(trimmed);
            let name_match = peer.name.as_str().eq_ignore_ascii_case(trimmed);
            let fqdn_match = peer.fqdn.eq_ignore_ascii_case(trimmed);
            let ip_match = peer.overlay_ip.to_string() == trimmed;
            if id_match || name_match || fqdn_match || ip_match {
                return Some((
                    peer.node_id,
                    peer.name.clone(),
                    peer.overlay_ip,
                    peer.online,
                ));
            }
        }
        None
    }

    /// Builds a redacted [`AgentStatusResponse`] containing zero cryptographic secrets (`US-039`).
    pub async fn build_status_response(&self) -> AgentStatusResponse {
        let snap = StatusReadSnapshot::capture(self).await;
        let dp_snapshot = match snap.datapath_handle {
            Some(ref handle) => handle.query_status().await.ok(),
            None => None,
        };
        assemble_status_response(snap, dp_snapshot.as_ref())
    }

    /// Resets in-memory identity, bootstrap, Netmap, and error fields to an unconfigured
    /// `Stopped` baseline while keeping `meshd` IPC listeners and underlay handles alive
    /// (`ADR-024`, `US-101`).
    pub async fn reset_identity_state(&self) {
        let mut g = self.inner.write().await;
        g.daemon_state = DaemonState::Stopped;
        g.bootstrap = BootstrapConfig::default();
        g.tun_interface_name = None;
        g.local_udp_port = 0;
        g.node_id = None;
        g.node_name = None;
        g.fqdn = None;
        g.overlay_ip = None;
        g.overlay_cidr = None;
        g.overlay_dns_ip = None;
        g.key_expires_at_ms = None;
        g.latest_netmap = None;
        g.control_connected = false;
        g.relay_rtt_ms = None;
        g.last_error = None;
        g.protocol_incompatible = false;
        g.migration_pending_endpoint = None;
        g.overlay_conflict_warning = None;
        g.macos_firewall_warning = None;
        g.lockdown_warning = None;
        g.private_dns_warning = None;
        g.local_candidates.clear();
        g.datapath_handle = None;
        g.rebind_handle = None;
        g.relay_handle = None;
    }
}

struct StatusReadSnapshot {
    daemon_state: DaemonState,
    node_id: Option<NodeId>,
    node_name: Option<NodeName>,
    fqdn: Option<String>,
    overlay_ip: Option<OverlayIp>,
    overlay_cidr: Option<OverlayCidr>,
    tun_interface_name: Option<String>,
    tun_mtu: u16,
    local_udp_port: u16,
    key_expires_at_ms: Option<u64>,
    bootstrap: BootstrapConfig,
    latest_netmap: Option<NetmapSnapshot>,
    control_connected: bool,
    relay_rtt_ms: Option<u64>,
    last_error: Option<String>,
    migration_pending_endpoint: Option<String>,
    bound_physical_interface: Option<String>,
    overlay_conflict_warning: Option<String>,
    macos_firewall_warning: Option<String>,
    local_candidates: Vec<CandidateEndpoint>,
    datapath_handle: Option<DatapathHandle>,
}

impl StatusReadSnapshot {
    async fn capture(state: &ClientRuntimeState) -> Self {
        let g = state.inner.read().await;
        Self {
            daemon_state: g.daemon_state,
            node_id: g.node_id,
            node_name: g.node_name.clone(),
            fqdn: g.fqdn.clone(),
            overlay_ip: g.overlay_ip,
            overlay_cidr: g.overlay_cidr,
            tun_interface_name: g.tun_interface_name.clone(),
            tun_mtu: g.tun_mtu,
            local_udp_port: g.local_udp_port,
            key_expires_at_ms: g.key_expires_at_ms,
            bootstrap: g.bootstrap.clone(),
            latest_netmap: g.latest_netmap.clone(),
            control_connected: g.control_connected,
            relay_rtt_ms: g
                .relay_handle
                .as_ref()
                .and_then(RelayClientHandle::last_rtt_ms)
                .or(g.relay_rtt_ms),
            last_error: g.last_error.clone(),
            migration_pending_endpoint: g.migration_pending_endpoint.clone(),
            bound_physical_interface: g.bound_physical_interface.clone(),
            overlay_conflict_warning: g.overlay_conflict_warning.clone(),
            macos_firewall_warning: g.macos_firewall_warning.clone(),
            local_candidates: g.local_candidates.clone(),
            datapath_handle: g.datapath_handle.clone(),
        }
    }
}

fn assemble_status_response(
    snap: StatusReadSnapshot,
    dp_snapshot: Option<&DatapathStatusSnapshot>,
) -> AgentStatusResponse {
    let resolved_udp_port = dp_snapshot
        .and_then(|s| s.local_udp_addr.map(|a| a.port()))
        .filter(|&p| p > 0)
        .unwrap_or(snap.local_udp_port);

    let nat_type = dp_snapshot.map_or(NatMappingKind::Unknown, |s| s.nat_mapping);
    let nat_note =
        dp_snapshot.and_then(|s| s.last_stun_report.as_ref().map(|r| r.nat_note.clone()));

    let server_connection = snap.bootstrap.server_endpoint.as_ref().map(|ctrl_ep| {
        let relay_ep = snap.latest_netmap.as_ref().map_or_else(
            || ctrl_ep.clone(),
            |n| {
                crate::session::resolve_effective_remote_endpoint(
                    ctrl_ep,
                    &n.relay_map.relay_tcp_endpoint,
                )
            },
        );
        let stun_eps = snap
            .latest_netmap
            .as_ref()
            .map_or_else(Vec::new, |n| n.relay_map.stun_udp_endpoints.clone());
        let relay_connected =
            dp_snapshot.is_some_and(|s| matches!(s.relay_state, RelayConnectionState::Connected));
        ServerConnectionStatus {
            control_endpoint: ctrl_ep.clone(),
            relay_endpoint: relay_ep,
            stun_endpoints: stun_eps,
            tls_auth_mode: snap.bootstrap.tls_auth_mode,
            active_pin: snap.bootstrap.active_pin,
            next_pin: snap.bootstrap.next_pin,
            control_connected: snap.control_connected,
            relay_connected,
            relay_rtt_ms: snap.relay_rtt_ms,
            migration_pending_endpoint: snap.migration_pending_endpoint,
            last_error: snap.last_error,
        }
    });

    let peers = build_agent_peers(snap.latest_netmap.as_ref(), dp_snapshot);
    let netmap_version = dp_snapshot
        .map(|s| s.netmap_version)
        .or_else(|| snap.latest_netmap.as_ref().map(|n| n.netmap_version))
        .unwrap_or(0);

    AgentStatusResponse {
        daemon_state: snap.daemon_state,
        node_id: snap.node_id,
        node_name: snap.node_name,
        fqdn: snap.fqdn,
        overlay_ip: snap.overlay_ip,
        overlay_cidr: snap.overlay_cidr,
        tun_interface_name: snap.tun_interface_name,
        tun_mtu: snap.tun_mtu,
        netmap_version,
        key_expires_at_ms: snap.key_expires_at_ms,
        server_connection,
        self_network: SelfNetworkStatus {
            local_udp_port: resolved_udp_port,
            bound_physical_interface: snap.bound_physical_interface,
            nat_type,
            nat_classification_note: nat_note,
            overlay_conflict_warning: snap.overlay_conflict_warning,
            macos_firewall_warning: snap.macos_firewall_warning,
            candidates: merge_local_and_reflexive_candidates(
                &snap.local_candidates,
                dp_snapshot
                    .and_then(|s| s.last_stun_report.as_ref())
                    .map_or(&[], |r| r.reflexive_addrs.as_slice()),
            ),
        },
        peers,
    }
}

/// Appends unique STUN reflexive socket addresses onto filtered local candidate endpoints.
#[must_use]
pub fn merge_local_and_reflexive_candidates(
    local: &[CandidateEndpoint],
    reflexive_addrs: &[SocketAddr],
) -> Vec<CandidateEndpoint> {
    let mut combined: Vec<CandidateEndpoint> = local.to_vec();
    for &addr in reflexive_addrs {
        if !combined.iter().any(|existing| existing.addr == addr) {
            combined.push(CandidateEndpoint {
                addr,
                source: CandidateSource::Reflexive,
            });
        }
    }
    combined
}

fn build_agent_peers(
    netmap: Option<&NetmapSnapshot>,
    dp: Option<&DatapathStatusSnapshot>,
) -> Vec<AgentPeerStatus> {
    let Some(snapshot) = netmap else {
        return Vec::new();
    };
    snapshot
        .peers
        .iter()
        .map(|entry| {
            let live = dp.and_then(|s| s.peers.iter().find(|p| p.node_id == entry.node_id));
            let (active_path, direct_endpoint, rtt_ms, last_handshake_at_ms, rx_bytes, tx_bytes) =
                match live {
                    Some(p) => match &p.active_path {
                        PeerActivePath::Direct {
                            addr,
                            rtt_ms,
                            confirmed_at_ms,
                            ..
                        } => (
                            ActivePathKind::Direct,
                            Some(addr.to_string()),
                            Some(*rtt_ms),
                            Some(*confirmed_at_ms),
                            p.rx_bytes,
                            p.tx_bytes,
                        ),
                        PeerActivePath::Relay => (
                            ActivePathKind::Relay,
                            None,
                            None,
                            None,
                            p.rx_bytes,
                            p.tx_bytes,
                        ),
                    },
                    None => (ActivePathKind::None, None, None, None, 0, 0),
                };
            AgentPeerStatus {
                node_id: entry.node_id,
                name: entry.name.clone(),
                fqdn: entry.fqdn.clone(),
                overlay_ip: entry.overlay_ip,
                online: entry.online,
                active_path,
                direct_endpoint,
                rtt_ms,
                last_handshake_at_ms,
                rx_bytes,
                tx_bytes,
            }
        })
        .collect()
}
