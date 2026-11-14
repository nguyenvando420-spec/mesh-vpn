//! Verified TLS 1.3 Control-plane client, challenge proof signer, Netmap stream consumer,
//! and hosts synchronization loop (`US-003`, `US-004`, `US-033`, `US-034`, `US-074`).

use std::collections::{HashSet, VecDeque};
use std::io::{self, ErrorKind as IoErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::handshake::HandshakeError;
use tokio_tungstenite::tungstenite::handshake::client::ClientHandshake;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::{WebSocket, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message as WsMessage};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mesh_core::backoff::{BackoffConfig, ExponentialBackoff};
use mesh_core::clock::Clock;
use mesh_core::defaults::{
    BACKOFF_INITIAL_MS, BACKOFF_NETWORK_MAX_MS, BACKOFF_TLS_MAX_MS, CONNECT_TIMEOUT_MS,
    DEFAULT_OVERLAY_CIDR, HEARTBEAT_TIMEOUT_MS, MAX_FRAME_SIZE, MAX_HTTP_BODY_BYTES,
};
use mesh_core::error::{ErrorKind, ErrorResponse};
use mesh_core::{AppError, AppResult, NodeId, NodeName, OverlayCidr, OverlayIp, Port, PublicKey};
use mesh_crypto::{
    NodeKeypair, ProofPayload, classify_rustls_error, extract_tls_exporter_binding, seal_proof,
    sha256_hex,
};
use mesh_datapath::{
    DatapathCommand, DatapathHandle, PeerActivePath, RebindHandle, RelayClientConfig,
    RelayClientHandle, connect_bound_tcp_with_timeout,
};
use mesh_net::endpoint_filter::{
    CandidateFilterContext, DiscoveredInterfaceEndpoint, filter_candidate_endpoints,
};
use mesh_net::hosts::{FileHostsEditor, HostsEditor, HostsEntry};
use mesh_net::ledger::ResourceLedger;
use mesh_net::netmon::NetworkChangeEvent;
use mesh_net::sysexec::{AllowedBinary, CommandExecutor, StdCommandExecutor};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentPeerStatus, AgentStatusResponse, DaemonState, SelfNetworkStatus,
    ServerConnectionStatus,
};
use mesh_proto::control::{
    ChallengeRequest, ChallengeResponse, ClientControlFrame, HEADER_AUTH_PROOF, HEADER_BOX_NONCE,
    HEADER_CHALLENGE_ID, HEADER_NODE_PUBKEY, RegisterNodeRequest, RegisterNodeResponse,
    ServerControlFrame, TargetArch, TargetOs, TerminationReason,
};
use mesh_proto::netmap::{CandidateEndpoint, CandidateSource, NatMappingKind, NetmapSnapshot};

use crate::config::{
    BootstrapConfig, BootstrapStore, load_inbound_filter_spec, split_host_port,
    validate_tls_trust_policy,
};
use crate::netmap_cache::{DEFAULT_KEY_EXPIRY_GRACE_HOURS, NetmapCacheStore};

const CONTROL_PROTOCOL_VERSION: u16 = 1;
const STABLE_SESSION_RESET_THRESHOLD: Duration = Duration::from_secs(60);
const CONTROL_HTTP_BODY_LINE_LIMIT: usize = 256;
const MAX_CONTROL_WS_FRAME_BYTES: usize = 4 * 1024 * 1024;
const CONTROL_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(25);
const WS_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const ENV_NETMAP_CHURN_WARN_PERCENT: &str = "MESH_NETMAP_CHURN_WARN_PERCENT";
const DEFAULT_NETMAP_CHURN_WARN_PERCENT: u8 = 50;

/// Signal sent by `supervisor` when endpoint config changes or daemon initiates shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlWakeSignal {
    /// Server endpoint or SPKI pins changed (`mesh set` / port migration).
    ConfigUpdated,
    /// Graceful shutdown requested: send WebSocket `Close` within `<= 1 s`.
    GracefulShutdown,
}

/// Mutable runtime state protected by an async-aware [`RwLock`] (`0` blocking locks across `.await`).
#[derive(Debug)]
pub(crate) struct DaemonRuntimeData {
    pub(crate) daemon_state: DaemonState,
    pub(crate) bootstrap: BootstrapConfig,
    pub(crate) bootstrap_store: BootstrapStore,
    pub(crate) netmap_cache: NetmapCacheStore,
    pub(crate) tun_interface_name: Option<String>,
    pub(crate) tun_mtu: u16,
    pub(crate) local_udp_port: u16,
    pub(crate) node_id: Option<NodeId>,
    pub(crate) node_name: Option<NodeName>,
    pub(crate) fqdn: Option<String>,
    pub(crate) overlay_ip: Option<OverlayIp>,
    pub(crate) overlay_cidr: Option<OverlayCidr>,
    pub(crate) key_expires_at_ms: Option<u64>,
    pub(crate) latest_netmap: Option<NetmapSnapshot>,
    pub(crate) control_connected: bool,
    pub(crate) relay_rtt_ms: Option<u64>,
    pub(crate) last_error: Option<String>,
    pub(crate) migration_pending_endpoint: Option<String>,
    pub(crate) bound_physical_interface: Option<String>,
    pub(crate) underlay_if_index: Option<u32>,
    pub(crate) linux_fwmark: Option<u32>,
    pub(crate) overlay_conflict_warning: Option<String>,
    pub(crate) macos_firewall_warning: Option<String>,
    pub(crate) local_candidates: Vec<CandidateEndpoint>,
    pub(crate) datapath_handle: Option<DatapathHandle>,
    pub(crate) rebind_handle: Option<RebindHandle>,
    pub(crate) relay_handle: Option<RelayClientHandle>,
}

/// Shared non-secret runtime coordinator queried by IPC and updated by Control/Datapath tasks.
#[derive(Debug)]
pub(crate) struct DaemonRuntimeState {
    pub(crate) inner: RwLock<DaemonRuntimeData>,
    ws_close_tx: watch::Sender<bool>,
}

impl DaemonRuntimeState {
    /// Creates an initialized [`DaemonRuntimeState`] using the current wall clock.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(
        bootstrap: BootstrapConfig,
        bootstrap_store: BootstrapStore,
        netmap_cache: NetmapCacheStore,
        cached: Option<&crate::netmap_cache::NetmapCacheFile>,
        tun_mtu: u16,
    ) -> Self {
        Self::new_with_now(
            bootstrap,
            bootstrap_store,
            netmap_cache,
            cached,
            tun_mtu,
            mesh_core::clock::SystemClock::new().now_unix_ms(),
        )
    }

    /// Creates an initialized [`DaemonRuntimeState`] evaluating offline grace at `now_unix_ms` (`HR-W21-13`).
    #[must_use]
    pub(crate) fn new_with_now(
        bootstrap: BootstrapConfig,
        bootstrap_store: BootstrapStore,
        netmap_cache: NetmapCacheStore,
        cached: Option<&crate::netmap_cache::NetmapCacheFile>,
        tun_mtu: u16,
        now_unix_ms: u64,
    ) -> Self {
        let (ws_close_tx, _) = watch::channel(false);
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

        Self {
            inner: RwLock::new(DaemonRuntimeData {
                daemon_state: DaemonState::Stopped,
                bootstrap,
                bootstrap_store,
                netmap_cache,
                tun_interface_name: None,
                tun_mtu,
                local_udp_port: initial_udp_port,
                node_id,
                node_name,
                fqdn,
                overlay_ip,
                overlay_cidr,
                key_expires_at_ms: local_key_expires_at_ms,
                latest_netmap: initial_netmap,
                control_connected: false,
                relay_rtt_ms: None,
                last_error: None,
                migration_pending_endpoint: None,
                bound_physical_interface: None,
                underlay_if_index: None,
                linux_fwmark: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                local_candidates: Vec::new(),
                datapath_handle: None,
                rebind_handle: None,
                relay_handle: None,
            }),
            ws_close_tx,
        }
    }

    /// Broadcasts an immediate WebSocket Close notification (`T + <= 1 s` on shutdown).
    pub(crate) fn notify_ws_close(&self) {
        let _ignored = self.ws_close_tx.send(true);
    }

    /// Resets WebSocket close watch before starting a new tunnel session.
    pub(crate) fn reset_ws_close(&self) {
        let _ignored = self.ws_close_tx.send(false);
    }

    /// Subscribes to shutdown WS-close notifications.
    #[must_use]
    pub(crate) fn subscribe_ws_close(&self) -> watch::Receiver<bool> {
        self.ws_close_tx.subscribe()
    }

    /// Resolves a peer reference by UUID, short name, FQDN, or overlay IP.
    pub(crate) async fn find_peer(
        &self,
        target: &str,
    ) -> Option<(NodeId, NodeName, OverlayIp, bool)> {
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
    pub(crate) async fn build_status_response(&self) -> AgentStatusResponse {
        let (
            daemon_state,
            node_id,
            node_name,
            fqdn,
            overlay_ip,
            overlay_cidr,
            tun_interface_name,
            tun_mtu,
            local_udp_port,
            key_expires_at_ms,
            bootstrap,
            latest_netmap,
            control_connected,
            relay_rtt_ms,
            last_error,
            migration_pending_endpoint,
            bound_physical_interface,
            overlay_conflict_warning,
            macos_firewall_warning,
            local_candidates,
            datapath_opt,
        ) = {
            let g = self.inner.read().await;
            (
                g.daemon_state,
                g.node_id,
                g.node_name.clone(),
                g.fqdn.clone(),
                g.overlay_ip,
                g.overlay_cidr,
                g.tun_interface_name.clone(),
                g.tun_mtu,
                g.local_udp_port,
                g.key_expires_at_ms,
                g.bootstrap.clone(),
                g.latest_netmap.clone(),
                g.control_connected,
                g.relay_rtt_ms,
                g.last_error.clone(),
                g.migration_pending_endpoint.clone(),
                g.bound_physical_interface.clone(),
                g.overlay_conflict_warning.clone(),
                g.macos_firewall_warning.clone(),
                g.local_candidates.clone(),
                g.datapath_handle.clone(),
            )
        };

        let dp_snapshot = match datapath_opt {
            Some(ref handle) => handle.query_status().await.ok(),
            None => None,
        };

        let resolved_udp_port = dp_snapshot
            .as_ref()
            .and_then(|s| s.local_udp_addr.map(|a| a.port()))
            .filter(|&p| p > 0)
            .unwrap_or(local_udp_port);

        let nat_type = dp_snapshot
            .as_ref()
            .map_or(NatMappingKind::Unknown, |s| s.nat_mapping);
        let nat_note = dp_snapshot
            .as_ref()
            .and_then(|s| s.last_stun_report.as_ref().map(|r| r.nat_note.clone()));

        let server_connection = bootstrap.server_endpoint.as_ref().map(|ctrl_ep| {
            let relay_ep = latest_netmap.as_ref().map_or_else(
                || ctrl_ep.clone(),
                |n| n.relay_map.relay_tcp_endpoint.clone(),
            );
            let stun_eps = latest_netmap
                .as_ref()
                .map_or_else(Vec::new, |n| n.relay_map.stun_udp_endpoints.clone());
            let relay_connected = dp_snapshot.as_ref().is_some_and(|s| {
                matches!(
                    s.relay_state,
                    mesh_datapath::RelayConnectionState::Connected
                )
            });
            ServerConnectionStatus {
                control_endpoint: ctrl_ep.clone(),
                relay_endpoint: relay_ep,
                stun_endpoints: stun_eps,
                tls_auth_mode: bootstrap.tls_auth_mode,
                active_pin: bootstrap.active_pin,
                next_pin: bootstrap.next_pin,
                control_connected,
                relay_connected,
                relay_rtt_ms,
                migration_pending_endpoint,
                last_error,
            }
        });

        let peers = build_agent_peers(latest_netmap.as_ref(), dp_snapshot.as_ref());
        let netmap_version = dp_snapshot
            .as_ref()
            .map(|s| s.netmap_version)
            .or_else(|| latest_netmap.as_ref().map(|n| n.netmap_version))
            .unwrap_or(0);

        AgentStatusResponse {
            daemon_state,
            node_id,
            node_name,
            fqdn,
            overlay_ip,
            overlay_cidr,
            tun_interface_name,
            tun_mtu,
            netmap_version,
            key_expires_at_ms,
            server_connection,
            self_network: SelfNetworkStatus {
                local_udp_port: resolved_udp_port,
                bound_physical_interface,
                nat_type,
                nat_classification_note: nat_note,
                overlay_conflict_warning,
                macos_firewall_warning,
                candidates: local_candidates,
            },
            peers,
        }
    }
}

fn build_agent_peers(
    netmap: Option<&NetmapSnapshot>,
    dp: Option<&mesh_datapath::DatapathStatusSnapshot>,
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

/// Dependencies running the persistent Control-plane loop for an enrolled node session.
pub(crate) struct ControlLoopContext {
    pub(crate) state: Arc<DaemonRuntimeState>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) node_keypair: NodeKeypair,
    pub(crate) disco_pubkey: PublicKey,
    pub(crate) agent_version: String,
    pub(crate) hosts_override: Option<PathBuf>,
    pub(crate) ledger: Arc<Mutex<ResourceLedger>>,
    pub(crate) roaming_rx: Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>,
    pub(crate) wake_rx: mpsc::Receiver<ControlWakeSignal>,
    pub(crate) termination_tx: Option<mpsc::Sender<(TerminationReason, String)>>,
    pub(crate) shutdown: CancellationToken,
}

/// Manages TLS 1.3 Control-plane registration, `/v1/netmap/stream`, and backoff recovery.
#[derive(Debug)]
pub(crate) struct ControlLoop;

impl ControlLoop {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "control_loop:ready"
    }

    /// Executes `POST /v1/auth/challenge` + signed `POST /v1/nodes/register` over verified TLS 1.3.
    pub(crate) async fn register_node(
        bootstrap: &BootstrapConfig,
        node_keypair: &NodeKeypair,
        req: &RegisterNodeRequest,
        agent_version: &str,
        underlay: (Option<u32>, Option<u32>),
    ) -> AppResult<RegisterNodeResponse> {
        let endpoint = bootstrap.server_endpoint.as_deref().ok_or_else(|| {
            AppError::invalid_argument("missing server_endpoint for node registration")
        })?;
        let tls_cfg = bootstrap.build_tls_client_config()?;
        let (mut tls, exporter) = connect_control_tls(endpoint, tls_cfg, underlay).await?;
        let challenge = execute_challenge(
            &mut tls,
            endpoint,
            &ChallengeRequest {
                node_pubkey: req.node_pubkey,
                disco_pubkey: req.disco_pubkey,
                protocol_version: CONTROL_PROTOCOL_VERSION,
                agent_version: agent_version.to_owned(),
                os: current_target_os(),
                arch: current_target_arch(),
            },
        )
        .await?;

        let body = serde_json::to_vec(req).map_err(|err| {
            AppError::internal(format!("failed serializing RegisterNodeRequest: {err}"))
        })?;
        let headers = build_signed_headers(
            node_keypair,
            req.disco_pubkey,
            &challenge,
            ("POST", "/v1/nodes/register", &body),
            exporter,
        )?;
        let resp: RegisterNodeResponse = send_signed_http_json(
            &mut tls,
            endpoint,
            ("POST", "/v1/nodes/register", &body),
            &headers,
        )
        .await?;
        let _ignored = tls.shutdown().await;
        Ok(resp)
    }

    /// Runs the resilient Control-plane WebSocket loop until `shutdown` or verified server revocation.
    pub(crate) async fn run(mut ctx: ControlLoopContext) {
        let mut net_backoff = ExponentialBackoff::new(BackoffConfig {
            initial_ms: BACKOFF_INITIAL_MS,
            max_ms: BACKOFF_NETWORK_MAX_MS,
            factor: 2,
        });
        let mut tls_backoff = ExponentialBackoff::new(BackoffConfig {
            initial_ms: BACKOFF_INITIAL_MS,
            max_ms: BACKOFF_TLS_MAX_MS,
            factor: 2,
        });

        info!(
            component = "meshd.control_loop",
            event = "control_loop_started",
            "Control-plane synchronization loop started"
        );

        loop {
            if ctx.shutdown.is_cancelled() {
                break;
            }
            if let Some(msg) =
                check_offline_key_grace_expired(&ctx.state, ctx.clock.now_unix_ms()).await
            {
                handle_terminal_revocation(&ctx.state, TerminationReason::NodeKeyExpired, &msg)
                    .await;
                if let Some(ref tx) = ctx.termination_tx {
                    let _ignored = tx.send((TerminationReason::NodeKeyExpired, msg)).await;
                }
                break;
            }
            let outcome = run_single_control_session(&mut ctx).await;
            {
                let mut g = ctx.state.inner.write().await;
                g.control_connected = false;
            }
            if outcome
                .established_duration
                .is_some_and(|dur| dur >= STABLE_SESSION_RESET_THRESHOLD)
            {
                net_backoff.reset();
                tls_backoff.reset();
            }

            match outcome.exit {
                ControlSessionExit::Shutdown => break,
                ControlSessionExit::Terminated { reason, message } => {
                    handle_terminal_revocation(&ctx.state, reason, &message).await;
                    if let Some(ref tx) = ctx.termination_tx {
                        let _ignored = tx.send((reason, message)).await;
                    }
                    break;
                }
                ControlSessionExit::ReconnectImmediately => {
                    net_backoff.reset();
                    tls_backoff.reset();
                }
                ControlSessionExit::Retry { err, tls_capped } => {
                    if let Some(msg) =
                        check_offline_key_grace_expired(&ctx.state, ctx.clock.now_unix_ms()).await
                    {
                        handle_terminal_revocation(
                            &ctx.state,
                            TerminationReason::NodeKeyExpired,
                            &msg,
                        )
                        .await;
                        if let Some(ref tx) = ctx.termination_tx {
                            let _ignored = tx.send((TerminationReason::NodeKeyExpired, msg)).await;
                        }
                        break;
                    }
                    let delay =
                        advance_retry_backoff(&mut net_backoff, &mut tls_backoff, tls_capped, &err);
                    set_degraded_or_connecting(&ctx.state, &err.to_string()).await;
                    match wait_backoff_or_wake(&mut ctx, delay).await {
                        BackoffWaitOutcome::Shutdown => break,
                        BackoffWaitOutcome::KeyGraceExpired(msg) => {
                            handle_terminal_revocation(
                                &ctx.state,
                                TerminationReason::NodeKeyExpired,
                                &msg,
                            )
                            .await;
                            if let Some(ref tx) = ctx.termination_tx {
                                let _ignored =
                                    tx.send((TerminationReason::NodeKeyExpired, msg)).await;
                            }
                            break;
                        }
                        BackoffWaitOutcome::WakeSignal => {
                            net_backoff.reset();
                            tls_backoff.reset();
                        }
                        BackoffWaitOutcome::TimerExpired => {}
                    }
                }
            }
        }

        info!(
            component = "meshd.control_loop",
            event = "control_loop_stopped",
            "Control-plane synchronization loop exited"
        );
    }
}

fn advance_retry_backoff(
    net_backoff: &mut ExponentialBackoff,
    tls_backoff: &mut ExponentialBackoff,
    tls_capped: bool,
    err: &AppError,
) -> Duration {
    if tls_capped || is_tls_or_pin_error(err) {
        let delay = tls_backoff.next_delay();
        warn!(
            component = "meshd.control_loop",
            event = "control_tls_or_portal_retry_backoff",
            error_kind = ?err.kind(),
            retry_delay_ms = delay.as_millis(),
            error = %err,
            "Control TLS/Pin/ClockSkew/Captive-Portal failure; continuing retry with 5m cap without sending secrets"
        );
        delay
    } else {
        net_backoff.next_delay()
    }
}

#[derive(Debug)]
struct ControlSessionOutcome {
    exit: ControlSessionExit,
    established_duration: Option<Duration>,
}

#[derive(Debug)]
enum ControlSessionExit {
    Shutdown,
    ReconnectImmediately,
    Terminated {
        reason: TerminationReason,
        message: String,
    },
    Retry {
        err: AppError,
        tls_capped: bool,
    },
}

/// Formats the `/v1/netmap/stream` request target with optional `?known_version=<u64>` (`IMP-W12-01`).
#[must_use]
pub(crate) fn build_netmap_stream_target(known_version: Option<u64>) -> String {
    match known_version {
        Some(v) if v > 0 => format!("/v1/netmap/stream?known_version={v}"),
        _ => "/v1/netmap/stream".to_owned(),
    }
}

async fn run_single_control_session(ctx: &mut ControlLoopContext) -> ControlSessionOutcome {
    let (bootstrap, underlay, known_version) = {
        let g = ctx.state.inner.read().await;
        (
            g.bootstrap.clone(),
            (g.underlay_if_index, g.linux_fwmark),
            g.latest_netmap.as_ref().map(|n| n.netmap_version),
        )
    };
    let Some(endpoint) = bootstrap.server_endpoint.clone() else {
        return ControlSessionOutcome {
            exit: ControlSessionExit::Shutdown,
            established_duration: None,
        };
    };
    let tls_cfg = match bootstrap.build_tls_client_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            return ControlSessionOutcome {
                exit: ControlSessionExit::Retry {
                    err,
                    tls_capped: true,
                },
                established_duration: None,
            };
        }
    };

    let (mut tls, exporter) = match connect_control_tls(&endpoint, tls_cfg, underlay).await {
        Ok(pair) => pair,
        Err(err) => {
            let tls_capped = is_tls_or_pin_error(&err);
            return ControlSessionOutcome {
                exit: ControlSessionExit::Retry { err, tls_capped },
                established_duration: None,
            };
        }
    };

    // TLS handshake + SPKI Pin / System CA verified! Any NodeRevoked/NodeKeyExpired returned
    // from this point onward came from the verified server (`US-034`).
    let challenge = match execute_challenge(
        &mut tls,
        &endpoint,
        &ChallengeRequest {
            node_pubkey: ctx.node_keypair.public_key(),
            disco_pubkey: ctx.disco_pubkey,
            protocol_version: CONTROL_PROTOCOL_VERSION,
            agent_version: ctx.agent_version.clone(),
            os: current_target_os(),
            arch: current_target_arch(),
        },
    )
    .await
    {
        Ok(c) => c,
        Err(err) => {
            return ControlSessionOutcome {
                exit: map_verified_tls_http_error(err),
                established_duration: None,
            };
        }
    };

    let headers = match build_signed_headers(
        &ctx.node_keypair,
        ctx.disco_pubkey,
        &challenge,
        ("GET", "/v1/netmap/stream", b""),
        exporter,
    ) {
        Ok(h) => h,
        Err(err) => {
            return ControlSessionOutcome {
                exit: ControlSessionExit::Retry {
                    err,
                    tls_capped: false,
                },
                established_duration: None,
            };
        }
    };

    let stream_target = build_netmap_stream_target(known_version);
    let mut ws_stream = match tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        connect_control_ws(tls, &endpoint, &stream_target, &headers),
    )
    .await
    {
        Ok(Ok(ws)) => ws,
        Ok(Err(exit)) => {
            return ControlSessionOutcome {
                exit,
                established_duration: None,
            };
        }
        Err(_) => {
            return ControlSessionOutcome {
                exit: ControlSessionExit::Retry {
                    err: AppError::unavailable("timed out upgrading /v1/netmap/stream WebSocket"),
                    tls_capped: false,
                },
                established_duration: None,
            };
        }
    };

    {
        let mut g = ctx.state.inner.write().await;
        g.control_connected = true;
        g.daemon_state = DaemonState::Connected;
        g.last_error = None;
    }

    let connected_at = tokio::time::Instant::now();
    let exit = pump_control_ws_stream(ctx, &mut ws_stream).await;
    ControlSessionOutcome {
        exit,
        established_duration: Some(connected_at.elapsed()),
    }
}

struct BridgeStream<S> {
    async_stream: S,
    rx_buf: VecDeque<u8>,
    tx_buf: Vec<u8>,
}

impl<S> BridgeStream<S> {
    fn new(async_stream: S) -> Self {
        Self {
            async_stream,
            rx_buf: VecDeque::with_capacity(4096),
            tx_buf: Vec::with_capacity(4096),
        }
    }

    fn push_rx(&mut self, bytes: &[u8]) {
        self.rx_buf.extend(bytes.iter().copied());
    }
}

impl<S: AsyncWrite + Unpin> BridgeStream<S> {
    async fn flush_tx_async(&mut self) -> io::Result<()> {
        if !self.tx_buf.is_empty() {
            self.async_stream.write_all(&self.tx_buf).await?;
            self.tx_buf.clear();
        }
        self.async_stream.flush().await
    }
}

impl<S> Read for BridgeStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_buf.is_empty() {
            return Err(io::Error::from(IoErrorKind::WouldBlock));
        }
        Read::read(&mut self.rx_buf, buf)
    }
}

impl<S> Write for BridgeStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn connect_control_ws<S>(
    stream: S,
    endpoint: &str,
    path: &str,
    headers: &[(String, String)],
) -> Result<WebSocket<BridgeStream<S>>, ControlSessionExit>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let uri = format!("wss://{endpoint}{path}");
    let mut req = uri
        .into_client_request()
        .map_err(|err| ControlSessionExit::Retry {
            err: AppError::invalid_argument(format!("invalid Control WS URI: {err}")),
            tls_capped: false,
        })?;
    for (name, val) in headers {
        let Ok(hdr_name) = HeaderName::from_bytes(name.as_bytes()) else {
            return Err(ControlSessionExit::Retry {
                err: AppError::invalid_argument("invalid Control header name"),
                tls_capped: false,
            });
        };
        let Ok(hdr_val) = HeaderValue::from_str(val) else {
            return Err(ControlSessionExit::Retry {
                err: AppError::invalid_argument("invalid Control header value"),
                tls_capped: false,
            });
        };
        req.headers_mut().insert(hdr_name, hdr_val);
    }

    let mut ws_cfg = WebSocketConfig::default();
    ws_cfg.max_message_size = Some(MAX_CONTROL_WS_FRAME_BYTES);
    ws_cfg.max_frame_size = Some(MAX_CONTROL_WS_FRAME_BYTES);

    let mut handshake = ClientHandshake::start(BridgeStream::new(stream), req, Some(ws_cfg))
        .map_err(|err| ControlSessionExit::Retry {
            err: AppError::unavailable(format!("control WS handshake start failed: {err}")),
            tls_capped: false,
        })?;

    let mut scratch = [0_u8; 4096];
    loop {
        handshake
            .get_mut()
            .get_mut()
            .flush_tx_async()
            .await
            .map_err(|err| ControlSessionExit::Retry {
                err: AppError::unavailable(format!("control WS write failed: {err}")),
                tls_capped: false,
            })?;
        match handshake.handshake() {
            Ok((mut ws, _resp)) => {
                if let Err(err) = ws.get_mut().flush_tx_async().await {
                    return Err(ControlSessionExit::Retry {
                        err: AppError::unavailable(format!("control WS tail flush failed: {err}")),
                        tls_capped: false,
                    });
                }
                return Ok(ws);
            }
            Err(HandshakeError::Interrupted(mut mid)) => {
                let n = mid
                    .get_mut()
                    .get_mut()
                    .async_stream
                    .read(&mut scratch)
                    .await
                    .map_err(|err| ControlSessionExit::Retry {
                        err: AppError::unavailable(format!(
                            "control WS upgrade read failed: {err}"
                        )),
                        tls_capped: false,
                    })?;
                if n == 0 {
                    return Err(ControlSessionExit::Retry {
                        err: AppError::unavailable("control server closed during WS upgrade"),
                        tls_capped: false,
                    });
                }
                if let Some(bytes) = scratch.get(..n) {
                    mid.get_mut().get_mut().push_rx(bytes);
                }
                handshake = mid;
            }
            Err(HandshakeError::Failure(err)) => return Err(map_ws_handshake_error(err)),
        }
    }
}

async fn pump_control_ws_stream<S>(
    ctx: &mut ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
) -> ControlSessionExit
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hb_tick = tokio::time::interval(CONTROL_HEARTBEAT_INTERVAL);
    hb_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ws_close_rx = ctx.state.subscribe_ws_close();
    let mut last_rx = tokio::time::Instant::now();
    let idle_limit = Duration::from_millis(HEARTBEAT_TIMEOUT_MS);
    let mut scratch = [0_u8; 4096];

    loop {
        if let Some(exit) = drain_control_ws_messages(ctx, ws, &mut last_rx).await {
            return exit;
        }
        if *ws_close_rx.borrow() || ctx.shutdown.is_cancelled() {
            close_ws_gracefully(ws).await;
            return ControlSessionExit::Shutdown;
        }
        let idle_sleep = tokio::time::sleep_until(last_rx + idle_limit);
        tokio::pin!(idle_sleep);

        tokio::select! {
            () = ctx.shutdown.cancelled() => {
                close_ws_gracefully(ws).await;
                return ControlSessionExit::Shutdown;
            }
            res = ws_close_rx.changed() => {
                if res.is_ok() && *ws_close_rx.borrow() {
                    close_ws_gracefully(ws).await;
                    return ControlSessionExit::Shutdown;
                }
            }
            maybe_wake = ctx.wake_rx.recv() => {
                match maybe_wake {
                    Some(ControlWakeSignal::GracefulShutdown) | None => {
                        close_ws_gracefully(ws).await;
                        return ControlSessionExit::Shutdown;
                    }
                    Some(ControlWakeSignal::ConfigUpdated) => {
                        close_ws_gracefully(ws).await;
                        return ControlSessionExit::ReconnectImmediately;
                    }
                }
            }
            maybe_roam = recv_shared_roaming(&ctx.roaming_rx) => {
                if maybe_roam.is_some()
                    && let Err(err) = send_endpoint_update_over_ws(ctx, ws).await
                {
                    return ControlSessionExit::Retry { err, tls_capped: false };
                }
            }
            _ = hb_tick.tick() => {
                let acked_netmap = {
                    let g = ctx.state.inner.read().await;
                    g.latest_netmap.as_ref().map_or(0, |n| n.netmap_version)
                };
                let frame = ClientControlFrame::Heartbeat {
                    sent_at_ms: ctx.clock.now_unix_ms(),
                    acked_netmap_version: acked_netmap,
                };
                if let Err(err) = send_client_control_frame(ws, &frame).await {
                    return ControlSessionExit::Retry { err, tls_capped: false };
                }
            }
            () = &mut idle_sleep => {
                return ControlSessionExit::Retry {
                    err: AppError::unavailable("control stream heartbeat timeout exceeded (60s)"),
                    tls_capped: false,
                };
            }
            read_res = ws.get_mut().async_stream.read(&mut scratch) => {
                match read_res {
                    Ok(0) => {
                        return ControlSessionExit::Retry {
                            err: AppError::unavailable("control stream closed by server"),
                            tls_capped: false,
                        };
                    }
                    Ok(n) => {
                        if let Some(bytes) = scratch.get(..n) {
                            ws.get_mut().push_rx(bytes);
                        }
                    }
                    Err(err) => {
                        return ControlSessionExit::Retry {
                            err: AppError::unavailable(format!("control WS read error: {err}")),
                            tls_capped: false,
                        };
                    }
                }
            }
        }
    }
}

async fn drain_control_ws_messages<S>(
    ctx: &ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
    last_rx: &mut tokio::time::Instant,
) -> Option<ControlSessionExit>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match ws.read() {
            Ok(WsMessage::Text(txt)) => {
                *last_rx = tokio::time::Instant::now();
                if let Some(exit) = handle_server_control_text(ctx, ws, txt.as_str()).await {
                    return Some(exit);
                }
            }
            Ok(WsMessage::Ping(payload)) => {
                *last_rx = tokio::time::Instant::now();
                if ws.send(WsMessage::Pong(payload)).is_ok() {
                    let _flushed = ws.get_mut().flush_tx_async().await;
                }
            }
            Ok(WsMessage::Pong(_) | WsMessage::Binary(_)) => {
                *last_rx = tokio::time::Instant::now();
            }
            Ok(WsMessage::Close(_)) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {
                return Some(ControlSessionExit::Retry {
                    err: AppError::unavailable("control stream closed by server"),
                    tls_capped: false,
                });
            }
            Ok(WsMessage::Frame(_)) => {}
            Err(WsError::Io(io_err)) if io_err.kind() == IoErrorKind::WouldBlock => {
                let _flushed = ws.get_mut().flush_tx_async().await;
                return None;
            }
            Err(err) => {
                return Some(ControlSessionExit::Retry {
                    err: AppError::unavailable(format!("control WS protocol error: {err}")),
                    tls_capped: false,
                });
            }
        }
    }
}

async fn close_ws_gracefully<S>(ws: &mut WebSocket<BridgeStream<S>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let close_fut = async {
        if ws.close(None).is_ok() {
            let _flushed = ws.get_mut().flush_tx_async().await;
        }
    };
    if tokio::time::timeout(WS_CLOSE_TIMEOUT, close_fut)
        .await
        .is_err()
    {
        debug!(
            component = "meshd.control_loop",
            event = "ws_close_timeout",
            "control WebSocket graceful close timed out within 1 s budget"
        );
    }
}

async fn handle_server_control_text<S>(
    ctx: &ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
    raw_txt: &str,
) -> Option<ControlSessionExit>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(frame) = serde_json::from_str::<ServerControlFrame>(raw_txt) else {
        debug!(
            component = "meshd.control_loop",
            event = "ignored_unknown_server_frame",
            "ignored unrecognized server control frame"
        );
        return None;
    };

    match frame {
        ServerControlFrame::Heartbeat { .. } => None,
        ServerControlFrame::IdentityTerminated {
            error_kind,
            public_msg,
            ..
        } => Some(ControlSessionExit::Terminated {
            reason: error_kind,
            message: public_msg,
        }),
        ServerControlFrame::CallMeMaybeRelay {
            src_node_id,
            src_node_pubkey,
            disco_frame_b64,
            ..
        } => {
            forward_relayed_disco_frame(&ctx.state, src_node_id, src_node_pubkey, &disco_frame_b64)
                .await;
            None
        }
        ServerControlFrame::NetmapSnapshot { netmap, .. } => {
            if apply_netmap_update(ctx, *netmap).await {
                close_ws_gracefully(ws).await;
                return Some(ControlSessionExit::ReconnectImmediately);
            }
            if let Err(err) = send_endpoint_update_over_ws(ctx, ws).await {
                warn!(
                    component = "meshd.control_loop",
                    event = "endpoint_update_send_failed",
                    error = %err,
                    "failed sending post-netmap endpoint advertisement over Control WebSocket"
                );
            }
            None
        }
    }
}

async fn recv_shared_roaming(
    rx: &Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>,
) -> Option<NetworkChangeEvent> {
    let mut guard = rx.lock().await;
    guard.recv().await
}

async fn forward_relayed_disco_frame(
    state: &DaemonRuntimeState,
    src_node_id: NodeId,
    src_node_pubkey: PublicKey,
    disco_frame_b64: &str,
) {
    let dp = { state.inner.read().await.datapath_handle.clone() };
    let Some(handle) = dp else {
        return;
    };
    let raw = match BASE64_STANDARD.decode(disco_frame_b64.as_bytes()) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_FRAME_SIZE => bytes,
        Ok(bytes) => {
            warn!(
                component = "meshd.control_loop",
                event = "relayed_disco_frame_invalid_len",
                src_node_id = %src_node_id,
                len = bytes.len(),
                "dropped empty or oversized CallMeMaybeRelay Disco frame"
            );
            return;
        }
        Err(err) => {
            warn!(
                component = "meshd.control_loop",
                event = "relayed_disco_frame_bad_base64",
                src_node_id = %src_node_id,
                error = %err,
                "dropped invalid base64 CallMeMaybeRelay Disco frame"
            );
            return;
        }
    };
    if let Err(err) = handle
        .handle_relayed_disco(src_node_id, src_node_pubkey, Bytes::from(raw))
        .await
    {
        debug!(
            component = "meshd.control_loop",
            event = "call_me_maybe_relay_dispatch_failed",
            src_node_id = %src_node_id,
            error = %err,
            "datapath handle closed before forwarding relayed Disco frame"
        );
    }
}

/// Builds a synchronized [`RelayClientConfig`] from current bootstrap trust policy and underlay hints.
pub(crate) fn build_relay_client_config_for_runtime(
    bootstrap: &BootstrapConfig,
    relay_endpoint: String,
    underlay: (Option<u32>, Option<u32>),
    agent_version: String,
) -> AppResult<RelayClientConfig> {
    let sni_host = match bootstrap.server_endpoint.as_deref() {
        Some(ctrl_ep) => split_host_port(ctrl_ep)?.0,
        None => split_host_port(&relay_endpoint)?.0,
    };
    Ok(RelayClientConfig {
        endpoint: relay_endpoint,
        server_name_override: Some(sni_host),
        pin_set: bootstrap.pin_set(),
        underlay_if_index: underlay.0,
        linux_fwmark: underlay.1,
        require_challenge_auth: true,
        agent_version,
    })
}

struct NetmapRuntimeUpdate {
    datapath_opt: Option<DatapathHandle>,
    bootstrap_save: Option<(BootstrapStore, BootstrapConfig)>,
    relay_update: Option<(RelayClientHandle, RelayClientConfig)>,
    migration_candidate: Option<(String, u64)>,
    cache_store: NetmapCacheStore,
    udp_port: Option<Port>,
    self_overlay_ip: Option<OverlayIp>,
    key_expires_at_ms: Option<u64>,
}

#[must_use]
fn configured_churn_warn_percent() -> u8 {
    std::env::var(ENV_NETMAP_CHURN_WARN_PERCENT)
        .ok()
        .and_then(|v| v.trim().parse::<u8>().ok())
        .filter(|&p| (1..=100).contains(&p))
        .unwrap_or(DEFAULT_NETMAP_CHURN_WARN_PERCENT)
}

fn is_valid_peer_candidate_addr(
    addr: SocketAddr,
    overlay_cidr: OverlayCidr,
    control_sock: Option<SocketAddr>,
    relay_sock: Option<SocketAddr>,
) -> bool {
    if addr.port() == 0 {
        return false;
    }
    let ip = addr.ip();
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if let IpAddr::V4(v4) = ip
        && overlay_cidr.contains_subnet_ip(v4)
    {
        return false;
    }
    if control_sock == Some(addr) || relay_sock == Some(addr) {
        return false;
    }
    true
}

/// Validates and sanitizes an incoming `NetmapSnapshot` before any daemon state mutation (`US-011`).
///
/// Returns `Ok(true)` when accepted, `Ok(false)` when stale/non-increasing version should be ignored,
/// and `Err(reason)` when the entire snapshot must be rejected safely.
pub(crate) fn validate_and_sanitize_netmap_snapshot(
    snapshot: &mut NetmapSnapshot,
    prev_version: Option<u64>,
    prev_peer_ids: &HashSet<NodeId>,
    self_node_id: Option<NodeId>,
    self_pubkey: PublicKey,
    self_overlay_ip: Option<OverlayIp>,
) -> Result<bool, String> {
    if let Some(prev) = prev_version
        && snapshot.netmap_version <= prev
    {
        return Ok(false);
    }

    let mut seen_ids = HashSet::with_capacity(snapshot.peers.len());
    let mut seen_ips = HashSet::with_capacity(snapshot.peers.len());
    let mut seen_pubkeys = HashSet::with_capacity(snapshot.peers.len());

    let control_sock = snapshot
        .relay_map
        .control_tcp_endpoint
        .parse::<SocketAddr>()
        .ok();
    let relay_sock = snapshot
        .relay_map
        .relay_tcp_endpoint
        .parse::<SocketAddr>()
        .ok();
    let mut stripped_endpoints = 0usize;

    for peer in &mut snapshot.peers {
        if !snapshot.overlay_cidr.contains_usable_host(peer.overlay_ip) {
            return Err(format!(
                "peer {} overlay_ip {} is outside usable host range of {}",
                peer.node_id, peer.overlay_ip, snapshot.overlay_cidr
            ));
        }
        if !seen_ids.insert(peer.node_id) {
            return Err(format!("duplicate peer node_id {}", peer.node_id));
        }
        if !seen_ips.insert(peer.overlay_ip) {
            return Err(format!("duplicate peer overlay_ip {}", peer.overlay_ip));
        }
        if !seen_pubkeys.insert(peer.node_pubkey) {
            return Err(format!("duplicate peer node_pubkey {}", peer.node_pubkey));
        }
        if Some(peer.node_id) != self_node_id
            && (Some(peer.overlay_ip) == self_overlay_ip || peer.node_pubkey == self_pubkey)
        {
            return Err(format!(
                "peer {} collides with local node overlay identity",
                peer.node_id
            ));
        }

        let before = peer.endpoints.len();
        peer.endpoints.retain(|ep| {
            is_valid_peer_candidate_addr(ep.addr, snapshot.overlay_cidr, control_sock, relay_sock)
        });
        stripped_endpoints =
            stripped_endpoints.saturating_add(before.saturating_sub(peer.endpoints.len()));
    }

    if stripped_endpoints > 0 {
        debug!(
            component = "meshd.control_loop",
            event = "netmap_peer_endpoints_sanitized",
            netmap_version = snapshot.netmap_version,
            stripped_count = stripped_endpoints,
            "stripped invalid or overlay/control-colliding peer candidate endpoints"
        );
    }

    if !prev_peer_ids.is_empty() {
        let removed = prev_peer_ids
            .iter()
            .filter(|id| !seen_ids.contains(id))
            .count();
        let added = seen_ids
            .iter()
            .filter(|id| !prev_peer_ids.contains(id))
            .count();
        let changed = removed.saturating_add(added);
        let churn_pct = changed.saturating_mul(100) / prev_peer_ids.len().max(1);
        let warn_pct = configured_churn_warn_percent();
        if churn_pct > usize::from(warn_pct) {
            warn!(
                component = "meshd.control_loop",
                event = "netmap_abnormal_churn_warning",
                netmap_version = snapshot.netmap_version,
                prev_peers = prev_peer_ids.len(),
                new_peers = snapshot.peers.len(),
                changed_peers = changed,
                churn_percent = churn_pct,
                threshold_percent = warn_pct,
                "abnormal Netmap peer churn exceeds configured threshold"
            );
        }
    }

    Ok(true)
}

async fn apply_netmap_update(ctx: &ControlLoopContext, mut snapshot: NetmapSnapshot) -> bool {
    let (prev_version, prev_peer_ids, self_node_id, self_overlay_ip, state_dir) = {
        let g = ctx.state.inner.read().await;
        let prev_ver = g.latest_netmap.as_ref().map(|n| n.netmap_version);
        let prev_ids: HashSet<NodeId> = g
            .latest_netmap
            .as_ref()
            .map(|n| n.peers.iter().map(|p| p.node_id).collect())
            .unwrap_or_default();
        let dir = g
            .bootstrap_store
            .path()
            .parent()
            .map(std::path::Path::to_path_buf);
        (prev_ver, prev_ids, g.node_id, g.overlay_ip, dir)
    };

    match validate_and_sanitize_netmap_snapshot(
        &mut snapshot,
        prev_version,
        &prev_peer_ids,
        self_node_id,
        ctx.node_keypair.public_key(),
        self_overlay_ip,
    ) {
        Ok(true) => {}
        Ok(false) => {
            debug!(
                component = "meshd.control_loop",
                event = "netmap_stale_version_ignored",
                incoming_version = snapshot.netmap_version,
                prev_version = prev_version,
                "ignoring non-increasing NetmapSnapshot version"
            );
            return false;
        }
        Err(reason) => {
            warn!(
                component = "meshd.control_loop",
                event = "netmap_sanity_rejected",
                incoming_version = snapshot.netmap_version,
                reason = %reason,
                "rejecting malformed NetmapSnapshot; preserving prior valid topology"
            );
            return false;
        }
    }

    let now_ms = ctx.clock.now_unix_ms();
    let update = record_netmap_in_runtime(ctx, &snapshot).await;

    if let Some((store, cfg)) = update.bootstrap_save
        && let Err(err) = store.save_atomic(&cfg)
    {
        warn!(
            component = "meshd.control_loop",
            event = "bootstrap_pin_persist_failed",
            error = %err,
            "failed persisting updated SPKI pin set to bootstrap.toml"
        );
    }

    if let Some(port) = update.udp_port
        && let Err(err) =
            update
                .cache_store
                .save_atomic(port, &snapshot, now_ms, update.key_expires_at_ms)
    {
        warn!(
            component = "meshd.control_loop",
            event = "netmap_cache_persist_failed",
            error = %err,
            "failed saving netmap-cache.json"
        );
    }

    if let Some((relay_handle, relay_cfg)) = update.relay_update {
        relay_handle.update_config(relay_cfg);
    }

    if let Some(handle) = update.datapath_opt {
        if let Err(err) = handle.apply_netmap(snapshot.clone()).await {
            warn!(
                component = "meshd.control_loop",
                event = "datapath_apply_netmap_failed",
                error = %err,
                "failed applying NetmapSnapshot diff to DatapathEngine"
            );
        }
        if let Some(spec) = load_inbound_filter_spec(state_dir.as_deref())
            && let Err(err) = handle.try_reload_packet_filter_spec(&spec).await
        {
            warn!(
                component = "meshd.control_loop",
                event = "inbound_filter_reload_failed",
                error = %err,
                "invalid inbound packet filter configuration rejected fail-safely; keeping active rules"
            );
        }
    }

    sync_hosts_entries(ctx, &snapshot, update.self_overlay_ip).await;

    if let Some((cand_ep, ep_ver)) = update.migration_candidate {
        return stage_and_apply_control_migration(ctx, &cand_ep, ep_ver).await;
    }
    false
}

async fn record_netmap_in_runtime(
    ctx: &ControlLoopContext,
    snapshot: &NetmapSnapshot,
) -> NetmapRuntimeUpdate {
    let mut g = ctx.state.inner.write().await;
    let prev_relay_ep = g
        .latest_netmap
        .as_ref()
        .map(|n| n.relay_map.relay_tcp_endpoint.clone());
    let prev_pin_set = g.bootstrap.pin_set();
    let pins_changed = g
        .bootstrap
        .apply_netmap_pins(snapshot.pin_set.active_pin, snapshot.pin_set.next_pin);

    let ep_ver = snapshot.relay_map.endpoint_version;
    let server_ep = snapshot.relay_map.control_tcp_endpoint.clone();
    let same_control_ep = g.bootstrap.server_endpoint.as_ref() == Some(&server_ep);
    let mut acked_changed = false;
    let mut migration_candidate = None;
    if same_control_ep {
        if ep_ver > g.bootstrap.acked_endpoint_version {
            g.bootstrap.acked_endpoint_version = ep_ver;
            acked_changed = true;
        }
        g.migration_pending_endpoint = None;
    } else if g.bootstrap.server_endpoint.is_some() {
        g.migration_pending_endpoint = Some(server_ep.clone());
        migration_candidate = Some((server_ep, ep_ver));
    }

    if g.overlay_cidr.is_none() {
        g.overlay_cidr = Some(snapshot.overlay_cidr);
    }
    if let (Some(name), None) = (&g.node_name, &g.fqdn) {
        g.fqdn = Some(format!("{name}.{}", snapshot.domain_suffix));
    }
    let mut key_exp_changed = false;
    if let Some(local_nid) = g.node_id
        && let Some(self_peer) = snapshot.peers.iter().find(|p| p.node_id == local_nid)
        && g.key_expires_at_ms != self_peer.key_expires_at_ms
    {
        g.key_expires_at_ms = self_peer.key_expires_at_ms;
        g.bootstrap.key_expires_at_ms = self_peer.key_expires_at_ms;
        key_exp_changed = true;
    }
    g.latest_netmap = Some(snapshot.clone());

    let bootstrap_save = if pins_changed || acked_changed || key_exp_changed {
        Some((g.bootstrap_store.clone(), g.bootstrap.clone()))
    } else {
        None
    };

    let relay_changed = prev_relay_ep.as_ref() != Some(&snapshot.relay_map.relay_tcp_endpoint)
        || pins_changed
        || g.bootstrap.pin_set() != prev_pin_set;
    let relay_update = if relay_changed
        && let Some(ref rh) = g.relay_handle
        && let Ok(cfg) = build_relay_client_config_for_runtime(
            &g.bootstrap,
            snapshot.relay_map.relay_tcp_endpoint.clone(),
            (g.underlay_if_index, g.linux_fwmark),
            ctx.agent_version.clone(),
        ) {
        Some((rh.clone(), cfg))
    } else {
        None
    };

    NetmapRuntimeUpdate {
        datapath_opt: g.datapath_handle.clone(),
        bootstrap_save,
        relay_update,
        migration_candidate,
        cache_store: g.netmap_cache.clone(),
        udp_port: Port::from_u16(g.local_udp_port.max(1)).ok(),
        self_overlay_ip: g.overlay_ip,
        key_expires_at_ms: g.key_expires_at_ms,
    }
}

/// Tests TLS 1.3 + `POST /v1/auth/challenge` on `candidate_ep` before committing `bootstrap.toml` (`HR-W12-01`).
pub(crate) async fn stage_and_apply_control_migration(
    ctx: &ControlLoopContext,
    candidate_ep: &str,
    ep_ver: u64,
) -> bool {
    let (mut probe_bootstrap, underlay) = {
        let g = ctx.state.inner.read().await;
        (g.bootstrap.clone(), (g.underlay_if_index, g.linux_fwmark))
    };
    probe_bootstrap.server_endpoint = Some(candidate_ep.to_owned());

    if let Err(err) = probe_control_endpoint_tls(
        &probe_bootstrap,
        &ctx.node_keypair,
        ctx.disco_pubkey,
        &ctx.agent_version,
        underlay,
    )
    .await
    {
        warn!(
            component = "meshd.control_loop",
            event = "control_migration_probe_failed",
            candidate = %candidate_ep,
            target_version = ep_ver,
            error = %err,
            "candidate Control endpoint failed verification; preserving existing bootstrap endpoint and acked_endpoint_version"
        );
        let mut g = ctx.state.inner.write().await;
        g.last_error = Some(format!("Control migration to {candidate_ep} failed: {err}"));
        return false;
    }

    let (store, persisted, relay_update) = {
        let mut g = ctx.state.inner.write().await;
        g.bootstrap.server_endpoint = Some(candidate_ep.to_owned());
        g.bootstrap.acked_endpoint_version = g.bootstrap.acked_endpoint_version.max(ep_ver);
        g.migration_pending_endpoint = None;
        g.last_error = None;
        let relay_ep = g.latest_netmap.as_ref().map_or_else(
            || candidate_ep.to_owned(),
            |n| n.relay_map.relay_tcp_endpoint.clone(),
        );
        let relay_update = g.relay_handle.as_ref().and_then(|rh| {
            build_relay_client_config_for_runtime(
                &g.bootstrap,
                relay_ep,
                (g.underlay_if_index, g.linux_fwmark),
                ctx.agent_version.clone(),
            )
            .ok()
            .map(|cfg| (rh.clone(), cfg))
        });
        (g.bootstrap_store.clone(), g.bootstrap.clone(), relay_update)
    };

    if let Err(err) = store.save_atomic(&persisted) {
        warn!(
            component = "meshd.control_loop",
            event = "migration_bootstrap_persist_failed",
            candidate = %candidate_ep,
            error = %err,
            "failed persisting migrated server_endpoint and acked_endpoint_version"
        );
        return false;
    }
    if let Some((rh, cfg)) = relay_update {
        rh.update_config(cfg);
    }
    info!(
        component = "meshd.control_loop",
        event = "control_migration_verified",
        endpoint = %candidate_ep,
        acked_endpoint_version = ep_ver,
        "verified candidate Control endpoint via TLS+challenge; committed bootstrap.toml and reconnecting"
    );
    true
}

async fn probe_control_endpoint_tls(
    bootstrap: &BootstrapConfig,
    node_keypair: &NodeKeypair,
    disco_pubkey: PublicKey,
    agent_version: &str,
    underlay: (Option<u32>, Option<u32>),
) -> AppResult<()> {
    let endpoint = bootstrap.server_endpoint.as_deref().ok_or_else(|| {
        AppError::invalid_argument("missing candidate server_endpoint during migration")
    })?;
    validate_tls_trust_policy(endpoint, bootstrap.tls_auth_mode, bootstrap.active_pin)?;
    let tls_cfg = bootstrap.build_tls_client_config()?;
    let (mut tls, _exporter) = connect_control_tls(endpoint, tls_cfg, underlay).await?;
    let _challenge = execute_challenge(
        &mut tls,
        endpoint,
        &ChallengeRequest {
            node_pubkey: node_keypair.public_key(),
            disco_pubkey,
            protocol_version: CONTROL_PROTOCOL_VERSION,
            agent_version: agent_version.to_owned(),
            os: current_target_os(),
            arch: current_target_arch(),
        },
    )
    .await?;
    let _ignored = tls.shutdown().await;
    Ok(())
}

async fn sync_hosts_entries(
    ctx: &ControlLoopContext,
    snapshot: &NetmapSnapshot,
    self_overlay_ip: Option<OverlayIp>,
) {
    let mut entries = Vec::with_capacity(snapshot.peers.len() + 1);
    let self_name_opt = { ctx.state.inner.read().await.node_name.clone() };
    if let (Some(ip), Some(name)) = (self_overlay_ip, self_name_opt)
        && let Ok(entry) = HostsEntry::new(
            ip,
            name,
            &snapshot.domain_suffix,
            Some(&snapshot.relay_map.control_tcp_endpoint),
        )
    {
        entries.push(entry);
    }
    for peer in &snapshot.peers {
        if let Ok(entry) = HostsEntry::new(
            peer.overlay_ip,
            peer.name.clone(),
            &snapshot.domain_suffix,
            Some(&snapshot.relay_map.control_tcp_endpoint),
        ) {
            entries.push(entry);
        }
    }

    let public_host = split_host_port(&snapshot.relay_map.control_tcp_endpoint)
        .map(|(h, _)| h)
        .ok();

    if let Some(ref custom_path) = ctx.hosts_override {
        let editor = FileHostsEditor::new(custom_path.clone());
        let mut ledger = ctx.ledger.lock().await;
        if let Err(err) = ledger.record_hosts_before_activate(custom_path.display().to_string()) {
            warn!(
                component = "meshd.control_loop",
                event = "hosts_ledger_record_failed",
                error = %err,
                "failed recording override hosts path into ResourceLedger"
            );
        }
        if let Err(err) = editor.apply(&entries, public_host.as_deref()) {
            warn!(
                component = "meshd.control_loop",
                event = "hosts_sync_failed",
                error = %err,
                "failed syncing managed hosts entries"
            );
        }
        return;
    }

    sync_platform_hosts_entries(&entries, public_host.as_deref(), &ctx.ledger).await;
}

#[cfg(target_os = "windows")]
async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = match mesh_net::hosts_windows::WindowsHostsEditor::system_default() {
        Ok(e) => e,
        Err(err) => {
            warn!(
                component = "meshd.control_loop",
                event = "windows_hosts_init_failed",
                error = %err,
                "failed resolving Windows hosts file path"
            );
            return;
        }
    };
    if let Ok(path) = mesh_net::hosts_windows::windows_hosts_path() {
        let mut guard = ledger.lock().await;
        if let Err(err) = guard.record_hosts_before_activate(path.display().to_string()) {
            warn!(
                component = "meshd.control_loop",
                event = "windows_hosts_ledger_record_failed",
                error = %err,
                "failed recording Windows hosts path into ResourceLedger"
            );
        }
    }
    if let Err(err) = editor
        .apply_with_public_host_async(entries, public_host)
        .await
    {
        warn!(
            component = "meshd.control_loop",
            event = "windows_hosts_sync_failed",
            error = %err,
            "failed syncing Windows hosts managed block"
        );
    }
}

#[cfg(target_os = "macos")]
async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = mesh_net::hosts_macos::macos_hosts_editor();
    let mut guard = ledger.lock().await;
    if let Err(err) = mesh_net::hosts_macos::apply_macos_hosts_with_ledger(
        &editor,
        entries,
        public_host,
        &mut guard,
    ) {
        warn!(
            component = "meshd.control_loop",
            event = "macos_hosts_sync_failed",
            error = %err,
            "failed syncing macOS hosts managed block"
        );
    }
}

#[cfg(target_os = "linux")]
async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = mesh_net::hosts_linux::linux_hosts_editor();
    let mut guard = ledger.lock().await;
    if let Err(err) = mesh_net::hosts_linux::apply_linux_hosts_with_ledger(
        &editor,
        entries,
        public_host,
        &mut guard,
    ) {
        warn!(
            component = "meshd.control_loop",
            event = "linux_hosts_sync_failed",
            error = %err,
            "failed syncing Linux hosts managed block"
        );
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = FileHostsEditor::default_system();
    let mut guard = ledger.lock().await;
    if let Ok(Some(real)) = editor.canonical_real_path()
        && let Err(err) = guard.record_hosts_before_activate(real.display().to_string())
    {
        warn!(
            component = "meshd.control_loop",
            event = "hosts_ledger_record_failed",
            error = %err,
            "failed recording hosts file path into ResourceLedger"
        );
    }
    if let Err(err) = editor.apply(entries, public_host) {
        warn!(
            component = "meshd.control_loop",
            event = "hosts_sync_failed",
            error = %err,
            "failed syncing managed hosts entries"
        );
    }
}

async fn send_endpoint_update_over_ws<S>(
    ctx: &ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (datapath_opt, acked_ep_ver, overlay_opt, control_ep, tun_ifname, stun_ep, cached_port) = {
        let g = ctx.state.inner.read().await;
        let overlay = g
            .overlay_cidr
            .or_else(|| g.latest_netmap.as_ref().map(|n| n.overlay_cidr));
        let control_ep = g
            .bootstrap
            .server_endpoint
            .as_deref()
            .and_then(|s| s.parse::<SocketAddr>().ok());
        let stun_ep = g
            .latest_netmap
            .as_ref()
            .and_then(|n| n.relay_map.stun_udp_endpoints.first())
            .and_then(|s| s.parse::<SocketAddr>().ok());
        (
            g.datapath_handle.clone(),
            g.bootstrap.acked_endpoint_version,
            overlay,
            control_ep,
            g.tun_interface_name.clone(),
            stun_ep,
            g.local_udp_port,
        )
    };
    let filter_overlay = match overlay_opt {
        Some(cidr) => cidr,
        None => OverlayCidr::parse(DEFAULT_OVERLAY_CIDR)?,
    };

    let mut nat_type = NatMappingKind::Unknown;
    let mut active_udp_port = cached_port;
    let mut reflexive_addrs = Vec::new();
    if let Some(ref handle) = datapath_opt
        && let Ok(snap) = handle.query_status().await
    {
        nat_type = snap.nat_mapping;
        if let Some(local_addr) = snap.local_udp_addr
            && local_addr.port() > 0
        {
            active_udp_port = local_addr.port();
        }
        if let Some(report) = snap.last_stun_report {
            reflexive_addrs = report.reflexive_addrs;
        }
    }

    let filter_ctx = CandidateFilterContext {
        overlay_cidr: filter_overlay,
        control_tcp_endpoint: control_ep,
        stun_udp_endpoint: stun_ep,
    };
    let local_candidates =
        discover_filtered_local_candidates(active_udp_port, tun_ifname.as_deref(), &filter_ctx)
            .await;
    let cache_store_opt = {
        let mut g = ctx.state.inner.write().await;
        g.local_candidates = local_candidates.clone();
        if active_udp_port > 0 {
            g.local_udp_port = active_udp_port;
            if active_udp_port != cached_port {
                Some(g.netmap_cache.clone())
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(cache_store) = cache_store_opt
        && let Ok(port) = Port::from_u16(active_udp_port)
        && let Err(err) = cache_store.update_udp_port(port, ctx.clock.now_unix_ms())
    {
        debug!(
            component = "meshd.control_loop",
            event = "netmap_cache_port_persist_failed",
            port = active_udp_port,
            error = %err,
            "failed updating persisted UDP port in netmap-cache.json"
        );
    }

    let endpoints = merge_local_and_reflexive_candidates(&local_candidates, &reflexive_addrs);
    if let Some(handle) = datapath_opt {
        let advertised_addrs: Vec<SocketAddr> = endpoints.iter().map(|c| c.addr).collect();
        if let Err(err) = handle
            .send(DatapathCommand::SetAdvertisedEndpoints(advertised_addrs))
            .await
        {
            debug!(
                component = "meshd.control_loop",
                event = "set_advertised_endpoints_failed",
                error = %err,
                "failed forwarding discovered endpoints to DatapathEngine"
            );
        }
    }

    let frame = ClientControlFrame::EndpointUpdate {
        endpoints,
        nat_type,
        acked_endpoint_version: acked_ep_ver,
    };
    send_client_control_frame(ws, &frame).await
}

fn merge_local_and_reflexive_candidates(
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

async fn discover_filtered_local_candidates(
    udp_port: u16,
    tun_interface_name: Option<&str>,
    filter_ctx: &CandidateFilterContext,
) -> Vec<CandidateEndpoint> {
    if udp_port == 0 {
        return Vec::new();
    }
    let discovered =
        match tokio::task::spawn_blocking(move || discover_raw_local_interface_endpoints(udp_port))
            .await
        {
            Ok(items) => items,
            Err(_) => probe_udp_routing_candidates(udp_port),
        };
    filter_local_candidate_list(&discovered, tun_interface_name, filter_ctx)
}

fn filter_local_candidate_list(
    discovered: &[DiscoveredInterfaceEndpoint],
    tun_interface_name: Option<&str>,
    filter_ctx: &CandidateFilterContext,
) -> Vec<CandidateEndpoint> {
    let without_tun: Vec<DiscoveredInterfaceEndpoint> = discovered
        .iter()
        .filter(|item| match (&item.interface_name, tun_interface_name) {
            (Some(iface), Some(tun)) => !iface.eq_ignore_ascii_case(tun),
            _ => true,
        })
        .cloned()
        .collect();
    filter_candidate_endpoints(&without_tun, filter_ctx)
        .into_iter()
        .map(|addr| CandidateEndpoint {
            addr,
            source: if addr.is_ipv6() {
                CandidateSource::Ipv6
            } else {
                CandidateSource::Lan
            },
        })
        .collect()
}

fn discover_raw_local_interface_endpoints(udp_port: u16) -> Vec<DiscoveredInterfaceEndpoint> {
    let mut items = Vec::new();
    let exec = StdCommandExecutor::new();
    if cfg!(target_os = "linux") {
        let args = [
            "-o".to_owned(),
            "addr".to_owned(),
            "show".to_owned(),
            "scope".to_owned(),
            "global".to_owned(),
        ];
        for bin in [AllowedBinary::LinuxIpUsrSbin, AllowedBinary::LinuxIpSbin] {
            if let Ok(spec) = mesh_net::sysexec::CommandSpec::new(bin, args.clone())
                && let Ok(out) = exec.execute(&spec)
                && out.success()
            {
                items.extend(parse_linux_ip_addr_output(&out.stdout, udp_port));
                break;
            }
        }
    } else if cfg!(target_os = "macos")
        && let Ok(spec) = mesh_net::sysexec::CommandSpec::new(
            AllowedBinary::MacOsIfconfig,
            std::iter::empty::<String>(),
        )
        && let Ok(out) = exec.execute(&spec)
        && out.success()
    {
        items.extend(parse_macos_ifconfig_output(&out.stdout, udp_port));
    }
    items.extend(probe_udp_routing_candidates(udp_port));
    items
}

fn parse_linux_ip_addr_output(stdout: &str, udp_port: u16) -> Vec<DiscoveredInterfaceEndpoint> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(raw_iface) = parts.get(1) else {
            continue;
        };
        let Some(family) = parts.get(2) else {
            continue;
        };
        let Some(cidr_token) = parts.get(3) else {
            continue;
        };
        if *family != "inet" && *family != "inet6" {
            continue;
        }
        let iface = raw_iface.split('@').next().unwrap_or(raw_iface).trim();
        let Some(ip_str) = cidr_token.split('/').next() else {
            continue;
        };
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            out.push(DiscoveredInterfaceEndpoint {
                interface_name: Some(iface.to_owned()),
                endpoint: SocketAddr::new(ip, udp_port),
            });
        }
    }
    out
}

fn parse_macos_ifconfig_output(stdout: &str, udp_port: u16) -> Vec<DiscoveredInterfaceEndpoint> {
    let mut out = Vec::new();
    let mut current_iface: Option<String> = None;
    for raw_line in stdout.lines() {
        if !raw_line.starts_with(char::is_whitespace) && !raw_line.is_empty() {
            current_iface = raw_line
                .split(':')
                .next()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty());
            continue;
        }
        let trimmed = raw_line.trim_start();
        let candidate_token = trimmed
            .strip_prefix("inet ")
            .or_else(|| trimmed.strip_prefix("inet6 "))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|tok| tok.split('%').next());
        if let Some(ip_str) = candidate_token
            && let Ok(ip) = ip_str.parse::<IpAddr>()
        {
            out.push(DiscoveredInterfaceEndpoint {
                interface_name: current_iface.clone(),
                endpoint: SocketAddr::new(ip, udp_port),
            });
        }
    }
    out
}

fn probe_udp_routing_candidates(udp_port: u16) -> Vec<DiscoveredInterfaceEndpoint> {
    const PROBE_TARGETS: [(&str, &str); 5] = [
        ("0.0.0.0:0", "1.1.1.1:80"),
        ("0.0.0.0:0", "10.255.255.254:80"),
        ("0.0.0.0:0", "172.16.0.1:80"),
        ("0.0.0.0:0", "192.168.0.1:80"),
        ("[::]:0", "[2606:4700:4700::1111]:80"),
    ];
    let mut out = Vec::new();
    for (bind_addr, remote) in PROBE_TARGETS {
        if let Ok(sock) = StdUdpSocket::bind(bind_addr)
            && sock.connect(remote).is_ok()
            && let Ok(local_addr) = sock.local_addr()
        {
            out.push(DiscoveredInterfaceEndpoint {
                interface_name: None,
                endpoint: SocketAddr::new(local_addr.ip(), udp_port),
            });
        }
    }
    out
}

async fn send_client_control_frame<S>(
    ws: &mut WebSocket<BridgeStream<S>>,
    frame: &ClientControlFrame,
) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let json = serde_json::to_string(frame).map_err(|err| {
        AppError::internal(format!("failed serializing ClientControlFrame: {err}"))
    })?;
    ws.send(WsMessage::Text(json.into()))
        .map_err(|err| AppError::unavailable(format!("control WS send failed: {err}")))?;
    tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        ws.get_mut().flush_tx_async(),
    )
    .await
    .map_err(|_| AppError::unavailable("timed out writing control WS frame"))?
    .map_err(|err| AppError::unavailable(format!("control WS flush failed: {err}")))
}

async fn handle_terminal_revocation(
    state: &DaemonRuntimeState,
    reason: TerminationReason,
    message: &str,
) {
    let new_state = match reason {
        TerminationReason::NodeRevoked => DaemonState::Revoked,
        TerminationReason::NodeKeyExpired => DaemonState::ReauthRequired,
    };
    warn!(
        component = "meshd.control_loop",
        event = "identity_terminated_by_verified_server",
        reason = ?reason,
        message = %message,
        "halting Control retries due to verified server termination signal"
    );
    let mut g = state.inner.write().await;
    g.daemon_state = new_state;
    g.control_connected = false;
    g.last_error = Some(message.to_owned());
}

async fn set_degraded_or_connecting(state: &DaemonRuntimeState, err_msg: &str) {
    let mut g = state.inner.write().await;
    if g.latest_netmap.is_some() && g.datapath_handle.is_some() {
        g.daemon_state = DaemonState::Degraded;
        g.last_error = Some(err_msg.to_owned());
    } else {
        g.daemon_state = DaemonState::Connecting;
        g.last_error = Some(if err_msg.starts_with("waiting_for_control") {
            err_msg.to_owned()
        } else {
            format!("waiting_for_control: {err_msg}")
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackoffWaitOutcome {
    TimerExpired,
    WakeSignal,
    KeyGraceExpired(String),
    Shutdown,
}

const OFFLINE_KEY_CHECK_INTERVAL: Duration = Duration::from_secs(15);

/// Checks if an offline node's identity key has exceeded its 24h (`86_400_000 ms`) grace period (`US-031 AC4`).
pub(crate) async fn check_offline_key_grace_expired(
    state: &DaemonRuntimeState,
    now_unix_ms: u64,
) -> Option<String> {
    let g = state.inner.read().await;
    if g.control_connected {
        return None;
    }
    if crate::netmap_cache::NetmapCacheFile::is_key_usable_offline(
        g.key_expires_at_ms,
        now_unix_ms,
        DEFAULT_KEY_EXPIRY_GRACE_HOURS,
    ) {
        return None;
    }
    Some(
        "local node identity key exceeded 24h offline grace window; re-authentication required"
            .to_owned(),
    )
}

async fn next_offline_key_check_delay(
    state: &DaemonRuntimeState,
    now_unix_ms: u64,
) -> Option<Duration> {
    let key_exp = state.inner.read().await.key_expires_at_ms?;
    let grace_deadline_ms =
        key_exp.saturating_add(DEFAULT_KEY_EXPIRY_GRACE_HOURS.saturating_mul(3_600_000));
    let remaining_ms = grace_deadline_ms
        .saturating_sub(now_unix_ms)
        .saturating_add(1);
    Some(Duration::from_millis(remaining_ms).min(OFFLINE_KEY_CHECK_INTERVAL))
}

async fn wait_backoff_or_wake(ctx: &mut ControlLoopContext, delay: Duration) -> BackoffWaitOutcome {
    let timer = tokio::time::sleep(delay);
    tokio::pin!(timer);
    loop {
        if let Some(msg) =
            check_offline_key_grace_expired(&ctx.state, ctx.clock.now_unix_ms()).await
        {
            return BackoffWaitOutcome::KeyGraceExpired(msg);
        }
        let expiry_poll = next_offline_key_check_delay(&ctx.state, ctx.clock.now_unix_ms()).await;
        tokio::select! {
            () = ctx.shutdown.cancelled() => return BackoffWaitOutcome::Shutdown,
            maybe_wake = ctx.wake_rx.recv() => {
                match maybe_wake {
                    Some(ControlWakeSignal::ConfigUpdated) => return BackoffWaitOutcome::WakeSignal,
                    Some(ControlWakeSignal::GracefulShutdown) | None => {
                        return BackoffWaitOutcome::Shutdown;
                    }
                }
            }
            maybe_roam = recv_shared_roaming(&ctx.roaming_rx) => {
                if maybe_roam.is_some() {
                    return BackoffWaitOutcome::WakeSignal;
                }
            }
            () = async {
                match expiry_poll {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                if let Some(msg) =
                    check_offline_key_grace_expired(&ctx.state, ctx.clock.now_unix_ms()).await
                {
                    return BackoffWaitOutcome::KeyGraceExpired(msg);
                }
            }
            () = &mut timer => return BackoffWaitOutcome::TimerExpired,
        }
    }
}

fn map_verified_tls_http_error(err: AppError) -> ControlSessionExit {
    match err.kind() {
        ErrorKind::NodeRevoked => ControlSessionExit::Terminated {
            reason: TerminationReason::NodeRevoked,
            message: err.to_string(),
        },
        ErrorKind::NodeKeyExpired => ControlSessionExit::Terminated {
            reason: TerminationReason::NodeKeyExpired,
            message: err.to_string(),
        },
        _ => {
            let tls_capped = is_tls_or_pin_error(&err);
            ControlSessionExit::Retry { err, tls_capped }
        }
    }
}

fn map_ws_handshake_error(ws_err: tokio_tungstenite::tungstenite::Error) -> ControlSessionExit {
    if let tokio_tungstenite::tungstenite::Error::Http(resp) = &ws_err {
        let parsed = map_http_error_response(
            resp.status().as_u16(),
            resp.body().as_deref().unwrap_or(&[]),
        );
        return map_verified_tls_http_error(parsed);
    }
    ControlSessionExit::Retry {
        err: AppError::unavailable(format!("control WebSocket handshake failed: {ws_err}")),
        tls_capped: false,
    }
}

fn is_tls_or_pin_error(err: &AppError) -> bool {
    if matches!(
        err.kind(),
        ErrorKind::PinMismatch | ErrorKind::ClockSkew | ErrorKind::Unauthenticated
    ) {
        return true;
    }
    let msg = err.public_message();
    msg.starts_with("TLS ")
        || msg.starts_with("Control TLS ")
        || msg.starts_with("Control captive portal ")
}

pub(crate) async fn connect_control_tls(
    endpoint: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    underlay: (Option<u32>, Option<u32>),
) -> AppResult<(TlsStream<TcpStream>, [u8; 32])> {
    let (host, port) = split_host_port(endpoint)?;
    let addrs = tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        lookup_host((host.as_str(), port.get())),
    )
    .await
    .map_err(|_| AppError::unavailable(format!("timed out resolving Control host '{host}'")))?
    .map_err(|err| AppError::unavailable(format!("Control DNS lookup failed: {err}")))?;

    let mut tcp_opt = None;
    let mut last_err = AppError::unavailable("no IP addresses resolved for Control server");
    for addr in addrs {
        match connect_tcp_with_timeout(addr, underlay.0, underlay.1).await {
            Ok(stream) => {
                tcp_opt = Some(stream);
                break;
            }
            Err(err) => last_err = err,
        }
    }
    let tcp_stream = tcp_opt.ok_or(last_err)?;

    let server_name = ServerName::try_from(host.clone()).map_err(|_| {
        AppError::invalid_argument(format!("invalid Control TLS SNI host '{host}'"))
    })?;
    let connector = TlsConnector::from(tls_cfg);
    let tls_stream = tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .map_err(|_| AppError::unavailable("Control TLS 1.3 handshake timed out"))?
    .map_err(|io_err| classify_tls_io_error(&io_err))?;

    let exporter = extract_tls_exporter_binding(tls_stream.get_ref().1)?;
    Ok((tls_stream, exporter))
}

async fn connect_tcp_with_timeout(
    addr: SocketAddr,
    if_index: Option<u32>,
    fwmark: Option<u32>,
) -> AppResult<TcpStream> {
    let stream = connect_bound_tcp_with_timeout(
        addr,
        if_index,
        fwmark,
        Duration::from_millis(CONNECT_TIMEOUT_MS),
    )
    .await?;
    if let Err(err) = stream.set_nodelay(true) {
        debug!(
            component = "meshd.control_loop",
            event = "tcp_nodelay_failed",
            error = %err,
            "failed setting TCP_NODELAY on Control socket"
        );
    }
    Ok(stream)
}

fn classify_tls_io_error(io_err: &std::io::Error) -> AppError {
    if let Some(inner) = io_err.get_ref()
        && let Some(rustls_err) = inner.downcast_ref::<rustls::Error>()
    {
        return classify_rustls_error(rustls_err);
    }
    AppError::unavailable(format!("Control TLS handshake failed: {io_err}"))
}

async fn execute_challenge<S>(
    stream: &mut S,
    host_header: &str,
    req: &ChallengeRequest,
) -> AppResult<ChallengeResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let body = serde_json::to_vec(req)
        .map_err(|err| AppError::internal(format!("failed serializing ChallengeRequest: {err}")))?;
    send_signed_http_json(
        stream,
        host_header,
        ("POST", "/v1/auth/challenge", &body),
        &[],
    )
    .await
}

fn build_signed_headers(
    keypair: &NodeKeypair,
    disco_pubkey: PublicKey,
    challenge: &ChallengeResponse,
    req_meta: (&str, &str, &[u8]),
    tls_exporter: [u8; 32],
) -> AppResult<Vec<(String, String)>> {
    let (method, path, body) = req_meta;
    let payload = ProofPayload {
        challenge_id: challenge.challenge_id,
        challenge_nonce: challenge.challenge_nonce.clone(),
        method: method.to_owned(),
        path: path.to_owned(),
        body_sha256: sha256_hex(body),
        node_pubkey: keypair.public_key(),
        disco_pubkey,
        timestamp_at_ms: challenge.server_time_at_ms,
        tls_exporter_binding: BASE64_STANDARD.encode(tls_exporter),
    };
    let sealed = seal_proof(&payload, &challenge.server_eph_pubkey, keypair)?;
    Ok(vec![
        (
            HEADER_CHALLENGE_ID.to_owned(),
            challenge.challenge_id.to_string(),
        ),
        (
            HEADER_NODE_PUBKEY.to_owned(),
            BASE64_STANDARD.encode(keypair.public_key().as_bytes()),
        ),
        (
            HEADER_BOX_NONCE.to_owned(),
            BASE64_STANDARD.encode(sealed.box_nonce),
        ),
        (
            HEADER_AUTH_PROOF.to_owned(),
            BASE64_STANDARD.encode(&sealed.ciphertext),
        ),
    ])
}

async fn send_signed_http_json<S, Resp>(
    stream: &mut S,
    host_header: &str,
    req_meta: (&str, &str, &[u8]),
    extra_headers: &[(String, String)],
) -> AppResult<Resp>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Resp: DeserializeOwned,
{
    let (method, path, body) = req_meta;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
        body.len()
    );
    for (name, val) in extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(val);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");

    tokio::time::timeout(Duration::from_millis(CONNECT_TIMEOUT_MS), async {
        stream.write_all(head.as_bytes()).await?;
        if !body.is_empty() {
            stream.write_all(body).await?;
        }
        stream.flush().await
    })
    .await
    .map_err(|_| AppError::unavailable("timed out writing Control HTTP request"))?
    .map_err(|err| AppError::unavailable(format!("Control HTTP write failed: {err}")))?;

    let (status, resp_body) = read_http_response_exact(stream).await?;
    if !(200..300).contains(&status) {
        return Err(map_http_error_response(status, &resp_body));
    }
    if looks_like_html_captive_portal(&resp_body) {
        return Err(AppError::unavailable(
            "Control captive portal HTML page intercepted HTTPS response",
        ));
    }
    serde_json::from_slice(&resp_body).map_err(|err| {
        AppError::internal(format!("malformed Control JSON response for {path}: {err}"))
    })
}

async fn read_http_response_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> AppResult<(u16, Vec<u8>)> {
    read_http_response_with_timeout(stream, Duration::from_millis(CONNECT_TIMEOUT_MS)).await
}

async fn read_http_response_with_timeout<S: AsyncRead + Unpin>(
    stream: &mut S,
    budget: Duration,
) -> AppResult<(u16, Vec<u8>)> {
    tokio::time::timeout(budget, read_http_response_inner(stream))
        .await
        .map_err(|_| AppError::unavailable("timed out reading Control HTTP response"))?
}

async fn read_http_response_inner<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> AppResult<(u16, Vec<u8>)> {
    let mut raw_head = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    loop {
        let n = stream.read(&mut byte).await.map_err(|err| {
            AppError::unavailable(format!("Control HTTP header read failed: {err}"))
        })?;
        if n == 0 {
            return Err(AppError::unavailable(
                "Control HTTP connection closed before headers",
            ));
        }
        if let Some(&first) = byte.first() {
            raw_head.push(first);
        }
        if raw_head.ends_with(b"\r\n\r\n") {
            break;
        }
        if raw_head.len() > MAX_HTTP_HEADER_BYTES {
            return Err(AppError::invalid_argument(
                "Control HTTP response headers exceeded 16 KiB limit",
            ));
        }
    }

    let head_str = std::str::from_utf8(&raw_head)
        .map_err(|_| AppError::unavailable("non-UTF8 Control HTTP response headers"))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| AppError::unavailable("malformed Control HTTP status line"))?;

    let mut content_len: usize = 0;
    let mut is_chunked = false;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_len = val.trim().parse::<usize>().map_err(|_| {
                    AppError::unavailable("invalid Content-Length in Control HTTP response")
                })?;
            } else if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    if is_chunked {
        let body = read_chunked_body(stream).await?;
        return Ok((status, body));
    }
    if content_len > MAX_HTTP_BODY_BYTES {
        return Err(AppError::invalid_argument(format!(
            "Control HTTP body ({content_len} bytes) exceeded limit"
        )));
    }
    let mut body = vec![0_u8; content_len];
    if content_len > 0 {
        stream.read_exact(&mut body).await.map_err(|err| {
            AppError::unavailable(format!("Control HTTP body read failed: {err}"))
        })?;
    }
    Ok((status, body))
}

async fn read_chunked_body<S: AsyncRead + Unpin>(stream: &mut S) -> AppResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut line_buf = Vec::with_capacity(32);
    loop {
        line_buf.clear();
        read_crlf_line(stream, &mut line_buf).await?;
        let line_str = std::str::from_utf8(&line_buf)
            .map_err(|_| AppError::unavailable("invalid UTF-8 chunk size"))?;
        let hex_len = line_str.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_len, 16)
            .map_err(|_| AppError::unavailable("invalid HTTP chunk size"))?;
        if chunk_len == 0 {
            let mut trailer = [0_u8; 2];
            if let Err(err) = stream.read_exact(&mut trailer).await {
                debug!(
                    component = "meshd.control_loop",
                    event = "chunked_trailer_eof",
                    error = %err,
                    "chunked HTTP response terminated before trailing CRLF"
                );
            }
            break;
        }
        if out.len().saturating_add(chunk_len) > MAX_HTTP_BODY_BYTES {
            return Err(AppError::invalid_argument(
                "chunked Control body exceeded limit",
            ));
        }
        let prev_len = out.len();
        out.resize(prev_len + chunk_len, 0);
        if let Some(slice) = out.get_mut(prev_len..) {
            stream
                .read_exact(slice)
                .await
                .map_err(|err| AppError::unavailable(format!("chunked body read failed: {err}")))?;
        }
        let mut crlf = [0_u8; 2];
        stream
            .read_exact(&mut crlf)
            .await
            .map_err(|err| AppError::unavailable(format!("missing chunk CRLF: {err}")))?;
    }
    Ok(out)
}

async fn read_crlf_line<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> AppResult<()> {
    let mut b = [0_u8; 1];
    loop {
        let n = stream
            .read(&mut b)
            .await
            .map_err(|err| AppError::unavailable(format!("HTTP line read failed: {err}")))?;
        if n == 0 {
            return Err(AppError::unavailable("unexpected EOF reading chunk line"));
        }
        if let Some(&byte) = b.first() {
            buf.push(byte);
        }
        if buf.ends_with(b"\r\n") {
            buf.truncate(buf.len().saturating_sub(2));
            return Ok(());
        }
        if buf.len() > CONTROL_HTTP_BODY_LINE_LIMIT {
            return Err(AppError::invalid_argument(
                "HTTP chunk header line too long",
            ));
        }
    }
}

fn looks_like_html_captive_portal(raw_body: &[u8]) -> bool {
    let prefix_len = raw_body.len().min(512);
    let trimmed = String::from_utf8_lossy(raw_body.get(..prefix_len).unwrap_or(&[]))
        .trim_start()
        .to_ascii_lowercase();
    trimmed.starts_with("<!doctype html")
        || trimmed.starts_with("<html")
        || (trimmed.starts_with('<') && (trimmed.contains("<html") || trimmed.contains("<title")))
}

fn map_http_error_response(status: u16, raw_body: &[u8]) -> AppError {
    if let Ok(env) = serde_json::from_slice::<ErrorResponse>(raw_body) {
        return AppError::new(env.error.kind, env.error.message);
    }
    if (300..=399).contains(&status) || status == 511 || looks_like_html_captive_portal(raw_body) {
        return AppError::unavailable(format!(
            "Control captive portal HTTP {status} detected; keeping secrets local and retrying"
        ));
    }
    let msg = String::from_utf8_lossy(raw_body);
    match status {
        401 => AppError::unauthenticated("authentication failed"),
        403 => AppError::permission_denied(if msg.is_empty() {
            "permission denied".to_owned()
        } else {
            msg.into_owned()
        }),
        404 => AppError::not_found(msg.into_owned()),
        400 => AppError::invalid_argument(msg.into_owned()),
        _ => AppError::unavailable(format!("Control HTTP {status}: {msg}")),
    }
}

#[must_use]
pub(crate) const fn current_target_os() -> TargetOs {
    if cfg!(target_os = "macos") {
        TargetOs::Darwin
    } else if cfg!(target_os = "windows") {
        TargetOs::Windows
    } else {
        TargetOs::Linux
    }
}

#[must_use]
pub(crate) const fn current_target_arch() -> TargetArch {
    if cfg!(target_arch = "aarch64") {
        TargetArch::Arm64
    } else {
        TargetArch::Amd64
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use mesh_core::backoff::{BackoffConfig, ExponentialBackoff};
    use mesh_core::clock::{Clock, SystemClock};
    use mesh_core::defaults::{
        BACKOFF_INITIAL_MS, BACKOFF_NETWORK_MAX_MS, BACKOFF_TLS_MAX_MS, DEFAULT_OVERLAY_CIDR,
    };
    use mesh_core::{AppError, ErrorKind, NodeId, OverlayCidr, PublicKey};
    use mesh_crypto::{
        DiscoKeypair, NodeKeypair, build_rustls_server_config_from_der, generate_ip_pinned_cert,
    };
    use mesh_net::endpoint_filter::CandidateFilterContext;
    use mesh_net::ledger::{FakeLedgerCleanupOps, ResourceLedger};
    use mesh_net::netmon::NetworkChangeEvent;
    use mesh_proto::agent_ipc::{DaemonState, TlsAuthMode};
    use mesh_proto::control::{ChallengeResponse, TerminationReason};
    use mesh_proto::netmap::{CandidateEndpoint, CandidateSource};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex, mpsc};
    use tokio_rustls::TlsAcceptor;
    use tokio_util::sync::CancellationToken;

    use super::{
        BackoffWaitOutcome, ControlLoopContext, ControlSessionExit, ControlWakeSignal,
        DaemonRuntimeState, advance_retry_backoff, build_netmap_stream_target,
        filter_local_candidate_list, forward_relayed_disco_frame, handle_terminal_revocation,
        map_verified_tls_http_error, merge_local_and_reflexive_candidates,
        parse_linux_ip_addr_output, parse_macos_ifconfig_output, read_http_response_with_timeout,
        stage_and_apply_control_migration, wait_backoff_or_wake,
    };
    use crate::config::{BootstrapConfig, BootstrapStore};
    use crate::netmap_cache::NetmapCacheStore;

    fn test_control_context(
        state: Arc<DaemonRuntimeState>,
        dir: &std::path::Path,
        roaming_rx: Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>,
        wake_rx: mpsc::Receiver<ControlWakeSignal>,
        shutdown: CancellationToken,
    ) -> Option<ControlLoopContext> {
        let ledger = ResourceLedger::load_or_init(dir.join("ledger.json")).ok()?;
        Some(ControlLoopContext {
            state,
            clock: Arc::new(SystemClock::new()),
            node_keypair: NodeKeypair::generate(),
            disco_pubkey: DiscoKeypair::generate().public_key(),
            agent_version: "0.1.0-test".to_owned(),
            hosts_override: Some(dir.join("hosts")),
            ledger: Arc::new(Mutex::new(ledger)),
            roaming_rx,
            wake_rx,
            termination_tx: None,
            shutdown,
        })
    }

    #[tokio::test]
    async fn test_control_loop_halts_only_on_verified_tls_revocation() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let state = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            BootstrapStore::new(dir.path().join("bootstrap.toml")),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
        ));

        // Act: non-revocation TLS pin mismatch stays Retry { tls_capped: true }, never Terminated.
        let pin_exit =
            map_verified_tls_http_error(AppError::new(ErrorKind::PinMismatch, "SPKI mismatch"));
        let revoked_exit =
            map_verified_tls_http_error(AppError::new(ErrorKind::NodeRevoked, "revoked"));
        handle_terminal_revocation(&state, TerminationReason::NodeRevoked, "node revoked").await;
        let status = state.build_status_response().await;

        // Assert
        assert!(matches!(
            pin_exit,
            ControlSessionExit::Retry {
                tls_capped: true,
                ..
            }
        ));
        assert!(matches!(
            revoked_exit,
            ControlSessionExit::Terminated {
                reason: TerminationReason::NodeRevoked,
                ..
            }
        ));
        assert_eq!(status.daemon_state, DaemonState::Revoked);
        assert!(serde_json::to_string(&status).is_ok());
    }

    #[tokio::test]
    async fn test_control_backoff_progresses_to_caps_and_resets_only_on_wake() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let state = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            BootstrapStore::new(dir.path().join("bootstrap.toml")),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
        ));
        let (roam_tx, roam_rx) = mpsc::channel(4);
        let (_wake_tx, wake_rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let Some(mut ctx) = test_control_context(
            state,
            dir.path(),
            Arc::new(Mutex::new(roam_rx)),
            wake_rx,
            shutdown,
        ) else {
            return;
        };

        let mut net_backoff = ExponentialBackoff::new(BackoffConfig {
            initial_ms: BACKOFF_INITIAL_MS,
            max_ms: BACKOFF_NETWORK_MAX_MS,
            factor: 2,
        });
        let mut tls_backoff = ExponentialBackoff::new(BackoffConfig {
            initial_ms: BACKOFF_INITIAL_MS,
            max_ms: BACKOFF_TLS_MAX_MS,
            factor: 2,
        });

        // Act: simulate repeated TimerExpired retries WITHOUT resetting backoffs (`BLK-W12-03`).
        let mut observed_net = Vec::new();
        for _ in 0..8 {
            observed_net.push(advance_retry_backoff(
                &mut net_backoff,
                &mut tls_backoff,
                false,
                &AppError::unavailable("transient connect failure"),
            ));
        }
        let mut observed_tls = Vec::new();
        for _ in 0..11 {
            observed_tls.push(advance_retry_backoff(
                &mut net_backoff,
                &mut tls_backoff,
                true,
                &AppError::pin_mismatch("wrong pin"),
            ));
        }
        let timer_outcome = wait_backoff_or_wake(&mut ctx, Duration::from_millis(5)).await;
        assert_eq!(timer_outcome, BackoffWaitOutcome::TimerExpired);
        // After TimerExpired, next delay remains at the higher attempt ceiling (not reset to 500 ms).
        assert_eq!(tls_backoff.attempts(), 11);

        // Sending roaming wake produces WakeSignal so caller resets backoffs.
        let send_res = roam_tx
            .send(NetworkChangeEvent::AddressChanged {
                interface: "en0".to_owned(),
            })
            .await;
        assert!(send_res.is_ok());
        let wake_outcome = wait_backoff_or_wake(&mut ctx, Duration::from_secs(5)).await;
        assert_eq!(wake_outcome, BackoffWaitOutcome::WakeSignal);
        net_backoff.reset();
        tls_backoff.reset();

        // Assert
        assert_eq!(net_backoff.attempts(), 0);
        assert_eq!(tls_backoff.attempts(), 0);
        assert_eq!(observed_net.len(), 8);
        assert_eq!(observed_tls.len(), 11);
        let net_last = observed_net.last().copied().unwrap_or_default();
        assert!(net_last <= Duration::from_millis(BACKOFF_NETWORK_MAX_MS));
        let tls_last = observed_tls.last().copied().unwrap_or_default();
        assert!(tls_last <= Duration::from_millis(BACKOFF_TLS_MAX_MS));
        // Clean ledger handle unused import guard
        let _ops = FakeLedgerCleanupOps::new();
    }

    #[test]
    fn test_parse_and_filter_local_candidates_excludes_virtual_and_overlay_ips() {
        // Arrange
        let linux_out = "\
1: lo    inet 127.0.0.1/8 scope host lo\\ valid_lft forever preferred_lft forever
2: eth0    inet 192.168.10.25/24 brd 192.168.10.255 scope global eth0\\ valid_lft forever
3: mesh0    inet 100.115.0.5/16 scope global mesh0\\ valid_lft forever
4: docker0    inet 172.17.0.1/16 scope global docker0\\ valid_lft forever
5: eth0    inet6 2001:db8::5/64 scope global dynamic\\ valid_lft forever
";
        let mac_out = "\
lo0: flags=8049<UP,LOOPBACK> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
utun4: flags=8051<UP,POINTOPOINT> mtu 1280
\tinet 100.115.0.9 --> 100.115.0.9 netmask 0xffff0000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500
\tinet 10.20.30.40 netmask 0xffffff00 broadcast 10.20.30.255
\tinet6 fe80::1234%en0 prefixlen 64 secured scopeid 0x4
";
        let Ok(overlay_cidr) = DEFAULT_OVERLAY_CIDR.parse::<OverlayCidr>() else {
            return;
        };
        let filter_ctx = CandidateFilterContext {
            overlay_cidr,
            control_tcp_endpoint: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                443,
            )),
            stun_udp_endpoint: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                3478,
            )),
        };

        // Act
        let mut raw = parse_linux_ip_addr_output(linux_out, 51820);
        raw.extend(parse_macos_ifconfig_output(mac_out, 51820));
        let filtered = filter_local_candidate_list(&raw, Some("mesh0"), &filter_ctx);
        let merged = merge_local_and_reflexive_candidates(
            &filtered,
            &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 41234),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 25)), 51820),
            ],
        );

        // Assert
        let expected_local = vec![
            CandidateEndpoint {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 25)), 51820),
                source: CandidateSource::Lan,
            },
            CandidateEndpoint {
                addr: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 5)),
                    51820,
                ),
                source: CandidateSource::Ipv6,
            },
            CandidateEndpoint {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)), 51820),
                source: CandidateSource::Lan,
            },
        ];
        assert_eq!(filtered, expected_local);
        assert_eq!(merged.len(), 4);
        assert_eq!(
            merged.last().map(|c| c.source),
            Some(CandidateSource::Reflexive)
        );
    }

    #[test]
    fn test_build_netmap_stream_target_formats_known_version_query() {
        // Arrange & Act & Assert
        assert_eq!(build_netmap_stream_target(None), "/v1/netmap/stream");
        assert_eq!(build_netmap_stream_target(Some(0)), "/v1/netmap/stream");
        assert_eq!(
            build_netmap_stream_target(Some(42)),
            "/v1/netmap/stream?known_version=42"
        );
    }

    #[tokio::test]
    async fn test_read_http_response_with_timeout_rejects_stalled_chunked_body() {
        // Arrange
        let (mut client, mut server) = tokio::io::duplex(512);
        let server_task = tokio::spawn(async move {
            let partial = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
            let _ignored = server.write_all(partial).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        // Act
        let res = read_http_response_with_timeout(&mut client, Duration::from_millis(40)).await;
        server_task.abort();

        // Assert
        assert!(matches!(res, Err(err) if err.kind() == ErrorKind::Unavailable));
    }

    #[tokio::test]
    async fn test_staged_control_migration_rolls_back_on_failure_and_commits_on_verified_tls() {
        // Arrange: start real local TLS 1.3 Challenge responder with SPKI Pin.
        let clock = SystemClock::new();
        let now_ms = clock.now_unix_ms();
        let now_secs = now_ms / 1000;
        let Ok(cert) = generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 30, now_secs) else {
            return;
        };
        let Ok(server_tls) = build_rustls_server_config_from_der(
            vec![cert.cert_der.clone()],
            &cert.key_pkcs8_der,
            vec![b"http/1.1".to_vec()],
        ) else {
            return;
        };
        let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(good_addr) = listener.local_addr() else {
            return;
        };
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));
        let server_task = tokio::spawn(async move {
            let srv_clock = SystemClock::new();
            if let Ok((tcp, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(tcp).await
            {
                let mut buf = [0_u8; 2048];
                let _ignored = tls.read(&mut buf).await;
                let srv_ms = srv_clock.now_unix_ms();
                let challenge = ChallengeResponse {
                    challenge_id: NodeId::new_v7(srv_ms),
                    server_eph_pubkey: DiscoKeypair::generate().public_key(),
                    challenge_nonce: "dGVzdC1ub25jZS0xMjM0NTY3ODkwMTIzNDU2Nzg5MA==".to_owned(),
                    server_time_at_ms: srv_ms,
                    expires_at_ms: srv_ms.saturating_add(60_000),
                };
                if let Ok(json) = serde_json::to_vec(&challenge) {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        json.len()
                    );
                    let _ignored = tls.write_all(head.as_bytes()).await;
                    let _ignored = tls.write_all(&json).await;
                    let _ignored = tls.shutdown().await;
                }
            }
        });

        let Ok(closed_listener) = TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(dead_addr) = closed_listener.local_addr() else {
            return;
        };
        drop(closed_listener);

        let Ok(dir) = tempdir() else {
            return;
        };
        let initial_bootstrap = BootstrapConfig {
            server_endpoint: Some("127.0.0.1:1".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(cert.spki_pin),
            next_pin: None,
            node_id: Some(NodeId::new_v7(now_ms)),
            acked_endpoint_version: 1,
            ..BootstrapConfig::default()
        };
        let bootstrap_store = BootstrapStore::new(dir.path().join("bootstrap.toml"));
        let _ignored = bootstrap_store.save_atomic(&initial_bootstrap);

        let state = Arc::new(DaemonRuntimeState::new(
            initial_bootstrap,
            bootstrap_store.clone(),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
        ));
        let (_rtx, rrx) = mpsc::channel(4);
        let (_wtx, wrx) = mpsc::channel(4);
        let Some(ctx) = test_control_context(
            Arc::clone(&state),
            dir.path(),
            Arc::new(Mutex::new(rrx)),
            wrx,
            CancellationToken::new(),
        ) else {
            return;
        };

        // Act 1: failing candidate MUST NOT commit server_endpoint or acked_endpoint_version.
        let bad_ep = dead_addr.to_string();
        let failed = stage_and_apply_control_migration(&ctx, &bad_ep, 2).await;
        assert!(!failed);
        let persisted_after_fail = bootstrap_store.load_or_default().ok();
        assert_eq!(
            persisted_after_fail
                .as_ref()
                .and_then(|b| b.server_endpoint.as_deref()),
            Some("127.0.0.1:1")
        );
        assert_eq!(
            persisted_after_fail
                .as_ref()
                .map(|b| b.acked_endpoint_version),
            Some(1)
        );

        // Act 2: verified TLS + Challenge candidate commits server_endpoint & acked_endpoint_version.
        let good_ep = good_addr.to_string();
        let succeeded = stage_and_apply_control_migration(&ctx, &good_ep, 3).await;
        server_task.abort();

        // Assert
        assert!(succeeded);
        let persisted_after_ok = bootstrap_store.load_or_default().ok();
        assert_eq!(
            persisted_after_ok
                .as_ref()
                .and_then(|b| b.server_endpoint.as_deref()),
            Some(good_ep.as_str())
        );
        assert_eq!(
            persisted_after_ok
                .as_ref()
                .map(|b| b.acked_endpoint_version),
            Some(3)
        );
        let g = state.inner.read().await;
        assert_eq!(g.migration_pending_endpoint, None);
    }

    #[tokio::test]
    async fn test_forward_relayed_disco_frame_ignores_malformed_safely() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let state = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            BootstrapStore::new(dir.path().join("bootstrap.toml")),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
        ));
        let node_id = NodeId::new_v7(1_700_000_000_000);
        let Ok(pk) = PublicKey::from_bytes([7_u8; 32]) else {
            return;
        };

        // Act & Assert
        forward_relayed_disco_frame(&state, node_id, pk, "not-valid-base64!!!").await;
    }

    #[tokio::test]
    async fn test_netmap_sanity_rejects_bad_cidr_duplicates_and_local_collision_preserves_valid() {
        use mesh_core::{NodeName, OverlayCidr, OverlayIp, SpkiPin};
        use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};
        use std::collections::HashSet;

        let cidr = OverlayCidr::parse("100.115.0.0/16").expect("cidr");
        let self_kp = NodeKeypair::generate();
        let self_id = NodeId::new_v7(1_700_000_000_001);
        let self_ip = OverlayIp::from_ipv4("100.115.0.10".parse().expect("v4")).expect("self ip");

        let make_peer =
            |ts: u64, name: &str, ip_str: &str, eps: Vec<CandidateEndpoint>| PeerEntry {
                node_id: NodeId::new_v7(ts),
                name: NodeName::parse(name).expect("name"),
                fqdn: format!("{name}.mesh.internal"),
                overlay_ip: OverlayIp::from_ipv4(ip_str.parse().expect("v4")).expect("ip"),
                node_pubkey: NodeKeypair::generate().public_key(),
                disco_pubkey: DiscoKeypair::generate().public_key(),
                endpoints: eps,
                relay_home: "203.0.113.10:8443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            };

        let make_snap = |ver: u64, peers: Vec<PeerEntry>| NetmapSnapshot {
            netmap_version: ver,
            generated_at_ms: 1_700_000_100_000 + ver,
            overlay_cidr: cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: vec!["203.0.113.10:3478".to_owned()],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([1_u8; 32]),
                next_pin: None,
            },
            peers,
        };

        // Out-of-CIDR IP rejects entire snapshot (`US-011 AC1`).
        let mut bad_cidr_snap = make_snap(
            2,
            vec![make_peer(
                1_700_000_000_100,
                "peer-a",
                "192.168.1.5",
                vec![],
            )],
        );
        let err_cidr = super::validate_and_sanitize_netmap_snapshot(
            &mut bad_cidr_snap,
            Some(1),
            &HashSet::new(),
            Some(self_id),
            self_kp.public_key(),
            Some(self_ip),
        );
        assert!(err_cidr.is_err());

        // Duplicate overlay IP rejects entire snapshot.
        let mut dup_ip_snap = make_snap(
            3,
            vec![
                make_peer(1_700_000_000_101, "peer-a", "100.115.0.20", vec![]),
                make_peer(1_700_000_000_102, "peer-b", "100.115.0.20", vec![]),
            ],
        );
        assert!(
            super::validate_and_sanitize_netmap_snapshot(
                &mut dup_ip_snap,
                Some(1),
                &HashSet::new(),
                Some(self_id),
                self_kp.public_key(),
                Some(self_ip),
            )
            .is_err()
        );

        // Local self overlay IP collision rejects snapshot.
        let mut self_col_snap = make_snap(
            4,
            vec![make_peer(
                1_700_000_000_103,
                "spoof",
                "100.115.0.10",
                vec![],
            )],
        );
        assert!(
            super::validate_and_sanitize_netmap_snapshot(
                &mut self_col_snap,
                Some(1),
                &HashSet::new(),
                Some(self_id),
                self_kp.public_key(),
                Some(self_ip),
            )
            .is_err()
        );

        // Non-increasing version is safely ignored (`Ok(false)`).
        let mut stale_snap = make_snap(1, vec![]);
        assert_eq!(
            super::validate_and_sanitize_netmap_snapshot(
                &mut stale_snap,
                Some(5),
                &HashSet::new(),
                Some(self_id),
                self_kp.public_key(),
                Some(self_ip),
            ),
            Ok(false)
        );

        // Valid snapshot with mixed candidate endpoints strips overlay & Control sockets cleanly.
        let bad_overlay_ep = CandidateEndpoint {
            addr: "100.115.0.77:51820".parse().expect("addr"),
            source: CandidateSource::Lan,
        };
        let bad_ctrl_ep = CandidateEndpoint {
            addr: "203.0.113.10:8443".parse().expect("addr"),
            source: CandidateSource::Reflexive,
        };
        let good_ep = CandidateEndpoint {
            addr: "198.51.100.42:51820".parse().expect("addr"),
            source: CandidateSource::Reflexive,
        };
        let mut ok_snap = make_snap(
            6,
            vec![make_peer(
                1_700_000_000_200,
                "peer-ok",
                "100.115.0.30",
                vec![bad_overlay_ep, bad_ctrl_ep, good_ep],
            )],
        );
        let prev_ids: HashSet<NodeId> = [NodeId::new_v7(1_700_000_000_999)].into_iter().collect();
        let accepted = super::validate_and_sanitize_netmap_snapshot(
            &mut ok_snap,
            Some(5),
            &prev_ids,
            Some(self_id),
            self_kp.public_key(),
            Some(self_ip),
        );
        assert_eq!(accepted, Ok(true));
        let first_peer = ok_snap.peers.first().expect("sanitized peer present");
        assert_eq!(first_peer.endpoints.len(), 1);
        assert_eq!(
            first_peer.endpoints.first().expect("kept endpoint").addr,
            "198.51.100.42:51820"
                .parse::<std::net::SocketAddr>()
                .expect("addr")
        );
    }

    #[tokio::test]
    async fn test_captive_portal_and_tls_errors_use_5m_backoff_and_surface_waiting_for_control() {
        use mesh_core::ErrorKind;

        let portal_redirect = super::map_http_error_response(302, b"Found");
        let portal_511 = super::map_http_error_response(511, b"Network Authentication Required");
        let portal_html =
            super::map_http_error_response(200, b"<!DOCTYPE html><html>Wi-Fi Login</html>");
        let tls_issuer = AppError::unavailable("TLS certificate signed by unknown issuer");
        let clock_skew = AppError::new(ErrorKind::ClockSkew, "clock skew");

        for err in [
            portal_redirect,
            portal_511,
            portal_html,
            tls_issuer,
            clock_skew,
        ] {
            assert!(
                super::is_tls_or_pin_error(&err),
                "expected tls_capped=true for {err}"
            );
            let exit = map_verified_tls_http_error(err);
            assert!(matches!(
                exit,
                ControlSessionExit::Retry {
                    tls_capped: true,
                    ..
                }
            ));
        }

        let dir = tempdir().expect("tempdir");
        let state = DaemonRuntimeState::new(
            BootstrapConfig::default(),
            BootstrapStore::new(dir.path().join("bootstrap.toml")),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
        );
        super::set_degraded_or_connecting(&state, "Control TLS handshake failed").await;
        let g = state.inner.read().await;
        assert_eq!(g.daemon_state, DaemonState::Connecting);
        assert!(
            g.last_error
                .as_deref()
                .is_some_and(|e| e.starts_with("waiting_for_control: "))
        );
    }

    #[tokio::test]
    async fn test_rotate_key_network_failure_preserves_existing_identity_and_bootstrap() {
        // Arrange: persist valid bootstrap & node identity before rotation attempt
        let dir = tempdir().expect("tempdir");
        let bootstrap_path = dir.path().join("bootstrap.toml");
        let store = BootstrapStore::new(bootstrap_path);
        let old_id = NodeId::new_v7(1_700_000_000_555);
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let dead_ep = dead_listener.local_addr().expect("addr").to_string();
        drop(dead_listener);

        let bootstrap = BootstrapConfig {
            node_id: Some(old_id),
            server_endpoint: Some(dead_ep),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(mesh_core::SpkiPin::from_sha256_bytes([9_u8; 32])),
            acked_endpoint_version: 2,
            ..BootstrapConfig::default()
        };
        store.save_atomic(&bootstrap).expect("save old bootstrap");

        let old_kp = NodeKeypair::generate();
        let new_kp = NodeKeypair::generate();
        let req = mesh_proto::control::RegisterNodeRequest {
            node_pubkey: new_kp.public_key(),
            disco_pubkey: DiscoKeypair::generate().public_key(),
            preauth_key: "mpk_rotate_test_secret".to_owned(),
            node_name: mesh_core::NodeName::parse("rotate-test-node").expect("node name"),
            previous_node_pubkey: Some(old_kp.public_key()),
        };

        // Act: mid-rotation network connection failure
        let res = super::ControlLoop::register_node(
            &bootstrap,
            &new_kp,
            &req,
            "0.1.0-test",
            (None, None),
        )
        .await;

        // Assert: failed safely without touching persisted bootstrap node_id / endpoint
        assert!(res.is_err());
        let after = store.load_or_default().expect("load preserved bootstrap");
        assert_eq!(after.node_id, Some(old_id));
        assert_eq!(after.acked_endpoint_version, 2);
    }

    #[tokio::test]
    async fn test_control_loop_run_tears_down_when_offline_key_grace_exceeds_24h() {
        // Arrange (`HR-W21-13`)
        let Ok(dir) = tempdir() else {
            return;
        };
        let t0: u64 = 1_700_000_000_000;
        let key_expiry_ms = t0 + 5_000;
        let clock = Arc::new(mesh_core::clock::FakeClock::new(t0));

        let Ok(dead_listener) = TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(dead_addr) = dead_listener.local_addr() else {
            return;
        };
        drop(dead_listener);

        let Ok(node_name) = mesh_core::NodeName::parse("offline-grace-node") else {
            return;
        };
        let Ok(overlay_ip) = "100.115.0.44"
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| ())
            .and_then(|v4| mesh_core::OverlayIp::from_ipv4(v4).map_err(|_| ()))
        else {
            return;
        };
        let node_id = NodeId::new_v7(t0);
        let bootstrap = BootstrapConfig {
            node_id: Some(node_id),
            node_name: Some(node_name),
            overlay_ip: Some(overlay_ip),
            fqdn: Some("offline-grace-node.mesh.internal".to_owned()),
            server_endpoint: Some(dead_addr.to_string()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(mesh_core::SpkiPin::from_sha256_bytes([3_u8; 32])),
            key_expires_at_ms: Some(key_expiry_ms),
            ..BootstrapConfig::default()
        };
        let store = BootstrapStore::new(dir.path().join("bootstrap.toml"));
        assert!(store.save_atomic(&bootstrap).is_ok());

        let state = Arc::new(DaemonRuntimeState::new_with_now(
            bootstrap,
            store,
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
            t0,
        ));
        assert!(
            super::check_offline_key_grace_expired(&state, t0 + 86_400_000)
                .await
                .is_none()
        );

        let Ok(ledger) =
            mesh_net::ledger::ResourceLedger::load_or_init(dir.path().join("ledger.json"))
        else {
            return;
        };
        let ledger = Arc::new(tokio::sync::Mutex::new(ledger));
        let (_roaming_tx, roaming_rx) = mpsc::channel(4);
        let (wake_tx, wake_rx) = mpsc::channel(8);
        let (term_tx, mut term_rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();

        let kp = NodeKeypair::generate();
        let disco = DiscoKeypair::generate();
        let ctx = super::ControlLoopContext {
            state: Arc::clone(&state),
            clock: Arc::clone(&clock) as Arc<dyn mesh_core::clock::Clock>,
            node_keypair: kp,
            disco_pubkey: disco.public_key(),
            agent_version: "0.1.0-test".to_owned(),
            hosts_override: None,
            ledger,
            roaming_rx: Arc::new(tokio::sync::Mutex::new(roaming_rx)),
            wake_rx,
            termination_tx: Some(term_tx),
            shutdown: shutdown.clone(),
        };

        let loop_handle = tokio::spawn(super::ControlLoop::run(ctx));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(term_rx.try_recv().is_err());

        // Act: advance offline clock past key expiry + 24h and wake loop
        clock.set_wall_ms(key_expiry_ms + 86_400_000 + 1_000);
        assert!(
            wake_tx
                .send(super::ControlWakeSignal::ConfigUpdated)
                .await
                .is_ok()
        );

        // Assert: ControlLoop terminates session with NodeKeyExpired and ReauthRequired
        let term = tokio::time::timeout(Duration::from_secs(5), term_rx.recv()).await;
        assert!(matches!(
            term,
            Ok(Some((
                mesh_proto::control::TerminationReason::NodeKeyExpired,
                _
            )))
        ));
        let status = state.build_status_response().await;
        assert_eq!(status.daemon_state, DaemonState::ReauthRequired);
        shutdown.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), loop_handle)
                .await
                .is_ok()
        );
    }
}
