//! OS-neutral verified TLS 1.3 Control-plane client, challenge proof signer, Netmap stream
//! consumer, NAT64/`SocketProtector` candidate probe, and `ProtocolIncompatible` guard
//! (`US-003`, `US-004`, `US-033`, `US-034`, `US-074`, `ADR-015`, `ADR-016`).

use std::collections::{HashSet, VecDeque};
use std::io::{self, ErrorKind as IoErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::{Mutex, mpsc};
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
use mesh_core::{AppError, AppResult, NodeId, OverlayCidr, OverlayIp, Port, PublicKey};
use mesh_crypto::{
    NodeKeypair, ProofPayload, classify_rustls_error, extract_tls_exporter_binding, seal_proof,
    sha256_hex,
};
use mesh_datapath::{
    DatapathCommand, DatapathHandle, RelayClientConfig, RelayClientHandle,
    connect_bound_tcp_with_protector, is_protocol_incompatible_error, resolve_relay_target_addrs,
};
use mesh_net::endpoint_filter::{
    CandidateFilterContext, DiscoveredInterfaceEndpoint, filter_candidate_endpoints,
};
use mesh_net::nat64::{Nat64Prefix, Nat64Synthesizer, NoopSocketProtector, SocketProtector};
use mesh_net::netmon::NetworkChangeEvent;
use mesh_proto::agent_ipc::DaemonState;
use mesh_proto::control::{
    ChallengeRequest, ChallengeResponse, ClientControlFrame, HEADER_AUTH_PROOF, HEADER_BOX_NONCE,
    HEADER_CHALLENGE_ID, HEADER_NODE_PUBKEY, RegisterNodeRequest, RegisterNodeResponse,
    ServerControlFrame, TerminationReason,
};
use mesh_proto::netmap::{CandidateEndpoint, CandidateSource, NatMappingKind, NetmapSnapshot};

use crate::config::{
    BootstrapConfig, ClientRuntimeConfig, current_target_arch, current_target_os,
    derive_overlay_dns_ip, split_host_port, validate_tls_trust_policy,
};
use crate::hooks::{ClientPlatformHooks, ClientStateStore};
use crate::netmap_cache::{DEFAULT_KEY_EXPIRY_GRACE_HOURS, NetmapCacheFile};
use crate::state::{ClientRuntimeState, merge_local_and_reflexive_candidates};

const CONTROL_PROTOCOL_VERSION: u16 = 1;
const STABLE_SESSION_RESET_THRESHOLD: Duration = Duration::from_secs(60);
const WS_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const ENV_NETMAP_CHURN_WARN_PERCENT: &str = "MESH_NETMAP_CHURN_WARN_PERCENT";
const DEFAULT_NETMAP_CHURN_WARN_PERCENT: u8 = 50;
const OFFLINE_KEY_CHECK_INTERVAL: Duration = Duration::from_secs(15);
const PROTOCOL_INCOMPATIBLE_PREFIX: &str = "protocol incompatible (agent upgrade required)";

/// Signal sent when endpoint config changes or the session initiates graceful shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlWakeSignal {
    /// Server endpoint or SPKI pins changed (`mesh set` / port migration).
    ConfigUpdated,
    /// Graceful shutdown requested: send WebSocket `Close` within `<= 1 s`.
    GracefulShutdown,
}

/// Reason a single [`ControlLoop`] session terminated.
#[derive(Debug)]
pub enum ControlSessionExit {
    /// Clean shutdown triggered by supervisor/UI.
    Shutdown,
    /// Verified server revoked or expired node identity (`US-034`).
    Terminated {
        /// Verified termination reason.
        reason: TerminationReason,
        /// Server-provided human-readable message.
        message: String,
    },
    /// Verified server returned HTTP `400` `ProtocolIncompatible` (agent upgrade required).
    ProtocolIncompatible {
        /// Diagnostic error detail from verified Control endpoint.
        message: String,
    },
    /// Server endpoint migrated or config updated; reconnect immediately without backoff.
    ReconnectImmediately,
    /// Transient transport, TLS, captive-portal, or server error; retry with capped backoff.
    Retry {
        /// Underlying failure.
        err: AppError,
        /// Whether backoff uses the 5-minute TLS/pin/portal cap (`BACKOFF_TLS_MAX_MS`).
        tls_capped: bool,
    },
}

/// Dependencies running the persistent Control-plane loop for an enrolled node session.
pub struct ControlLoopContext {
    /// Shared client runtime state.
    pub state: Arc<ClientRuntimeState>,
    /// Monotonic + wall clock source.
    pub clock: Arc<dyn Clock>,
    /// Local node identity keypair for signed proofs.
    pub node_keypair: NodeKeypair,
    /// Local Disco traversal public key.
    pub disco_pubkey: PublicKey,
    /// Parameterized runtime config (`max_ws_frame_bytes`, heartbeat cadence, etc.).
    pub runtime_cfg: ClientRuntimeConfig,
    /// Platform abstraction hooks (`DnsUpstreamHook`, `SocketProtector`, candidate discovery).
    pub platform_hooks: Arc<dyn ClientPlatformHooks>,
    /// Shared receiver for debounced roaming events from [`crate::roaming_loop::RoamingLoop`].
    pub roaming_rx: Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>,
    /// Control loop config-update / graceful-shutdown wake channel.
    pub wake_rx: mpsc::Receiver<ControlWakeSignal>,
    /// Optional channel notified on verified revocation or key expiration (`US-034`).
    pub termination_tx: Option<mpsc::Sender<(TerminationReason, String)>>,
    /// Optional channel notified immediately on HTTP `400` `ProtocolIncompatible` (`§4.3`).
    pub protocol_incompatible_tx: Option<mpsc::Sender<String>>,
    /// Session shutdown cancellation token.
    pub shutdown: CancellationToken,
}

impl std::fmt::Debug for ControlLoopContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlLoopContext")
            .field("runtime_cfg", &self.runtime_cfg)
            .field("disco_pubkey", &self.disco_pubkey)
            .finish_non_exhaustive()
    }
}

/// Network dial options for protected TLS 1.3 Control plane connections.
#[derive(Clone, Copy)]
pub struct ControlDialOptions<'a> {
    /// Underlay interface index and Linux fwmark binding tuple `(ifindex, fwmark)`.
    pub underlay: (Option<u32>, Option<u32>),
    /// Optional active NAT64 synthesis prefix.
    pub nat64_prefix: Option<Nat64Prefix>,
    /// Socket protector callback invoked fail-closed prior to socket `connect`.
    pub protector: &'a dyn SocketProtector,
}

impl std::fmt::Debug for ControlDialOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlDialOptions")
            .field("underlay", &self.underlay)
            .field("nat64_prefix", &self.nat64_prefix)
            .finish_non_exhaustive()
    }
}

/// Manages TLS 1.3 Control-plane registration, `/v1/netmap/stream`, and backoff recovery.
#[derive(Debug)]
pub struct ControlLoop;

impl ControlLoop {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub const fn status_label() -> &'static str {
        "control_loop:ready"
    }

    /// Executes `POST /v1/auth/challenge` + signed `POST /v1/nodes/register` over verified TLS 1.3.
    pub async fn register_node(
        bootstrap: &BootstrapConfig,
        node_keypair: &NodeKeypair,
        req: &RegisterNodeRequest,
        agent_version: &str,
        underlay: (Option<u32>, Option<u32>),
    ) -> AppResult<RegisterNodeResponse> {
        Self::register_node_protected(
            bootstrap,
            node_keypair,
            req,
            agent_version,
            ControlDialOptions {
                underlay,
                nat64_prefix: None,
                protector: &NoopSocketProtector,
            },
        )
        .await
    }

    /// Executes challenge + registration guarded by NAT64 synthesis and fail-closed `SocketProtector`.
    pub async fn register_node_protected(
        bootstrap: &BootstrapConfig,
        node_keypair: &NodeKeypair,
        req: &RegisterNodeRequest,
        agent_version: &str,
        dial: ControlDialOptions<'_>,
    ) -> AppResult<RegisterNodeResponse> {
        let endpoint = bootstrap.server_endpoint.as_deref().ok_or_else(|| {
            AppError::invalid_argument("missing server_endpoint for node registration")
        })?;
        let tls_cfg = bootstrap.build_tls_client_config()?;
        let (mut tls, exporter) = connect_control_tls_with_protector(
            endpoint,
            tls_cfg,
            dial.underlay,
            dial.nat64_prefix,
            dial.protector,
        )
        .await?;
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
        drop(tls.shutdown().await);
        Ok(resp)
    }

    /// Runs the resilient Control-plane WebSocket loop until `shutdown`, server termination, or
    /// `ProtocolIncompatible`.
    pub async fn run(mut ctx: ControlLoopContext) {
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
            component = "mesh_client.control_loop",
            event = "control_loop_started",
            max_ws_frame_bytes = ctx.runtime_cfg.max_ws_frame_bytes,
            "Control-plane synchronization loop started"
        );

        loop {
            if ctx.shutdown.is_cancelled() {
                break;
            }
            if let Some(msg) =
                check_offline_key_grace_expired(&ctx.state, ctx.clock.now_unix_ms()).await
            {
                emit_terminal_revocation(&ctx, TerminationReason::NodeKeyExpired, msg).await;
                break;
            }
            let outcome = run_single_control_session(&mut ctx).await;
            ctx.state.inner.write().await.control_connected = false;
            if outcome
                .established_duration
                .is_some_and(|dur| dur >= STABLE_SESSION_RESET_THRESHOLD)
            {
                net_backoff.reset();
                tls_backoff.reset();
            }

            if !handle_session_exit(&mut ctx, outcome.exit, &mut net_backoff, &mut tls_backoff)
                .await
            {
                break;
            }
        }

        info!(
            component = "mesh_client.control_loop",
            event = "control_loop_stopped",
            "Control-plane synchronization loop exited"
        );
    }
}

async fn handle_session_exit(
    ctx: &mut ControlLoopContext,
    exit: ControlSessionExit,
    net_backoff: &mut ExponentialBackoff,
    tls_backoff: &mut ExponentialBackoff,
) -> bool {
    match exit {
        ControlSessionExit::Shutdown => false,
        ControlSessionExit::Terminated { reason, message } => {
            emit_terminal_revocation(ctx, reason, message).await;
            false
        }
        ControlSessionExit::ProtocolIncompatible { message } => {
            emit_protocol_incompatible(ctx, message).await;
            false
        }
        ControlSessionExit::ReconnectImmediately => {
            net_backoff.reset();
            tls_backoff.reset();
            true
        }
        ControlSessionExit::Retry { err, tls_capped } => {
            if let Some(msg) =
                check_offline_key_grace_expired(&ctx.state, ctx.clock.now_unix_ms()).await
            {
                emit_terminal_revocation(ctx, TerminationReason::NodeKeyExpired, msg).await;
                return false;
            }
            let delay = advance_retry_backoff(net_backoff, tls_backoff, tls_capped, &err);
            set_degraded_or_connecting(&ctx.state, &err.to_string()).await;
            match wait_backoff_or_wake(ctx, delay).await {
                BackoffWaitOutcome::Shutdown => false,
                BackoffWaitOutcome::KeyGraceExpired(msg) => {
                    emit_terminal_revocation(ctx, TerminationReason::NodeKeyExpired, msg).await;
                    false
                }
                BackoffWaitOutcome::WakeSignal => {
                    net_backoff.reset();
                    tls_backoff.reset();
                    true
                }
                BackoffWaitOutcome::TimerExpired => true,
            }
        }
    }
}

async fn emit_terminal_revocation(
    ctx: &ControlLoopContext,
    reason: TerminationReason,
    message: String,
) {
    handle_terminal_revocation(&ctx.state, reason, &message).await;
    if let Some(ref tx) = ctx.termination_tx {
        drop(tx.send((reason, message)).await);
    }
}

async fn emit_protocol_incompatible(ctx: &ControlLoopContext, message: String) {
    warn!(
        component = "mesh_client.control_loop",
        event = "protocol_incompatible_halted",
        message = %message,
        "halting Control auto-retry after verified HTTP 400 ProtocolIncompatible; preserving netmap cache"
    );
    {
        let mut g = ctx.state.inner.write().await;
        g.protocol_incompatible = true;
        g.daemon_state = DaemonState::Stopped;
        g.control_connected = false;
        g.last_error = Some(message.clone());
    }
    if let Some(ref tx) = ctx.protocol_incompatible_tx {
        drop(tx.send(message).await);
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
            component = "mesh_client.control_loop",
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

/// Builds `/v1/netmap/stream` target path preserving incremental `known_version` when present.
#[must_use]
pub fn build_netmap_stream_target(known_version: Option<u64>) -> String {
    match known_version {
        Some(v) if v > 0 => format!("/v1/netmap/stream?known_version={v}"),
        _ => "/v1/netmap/stream".to_owned(),
    }
}

async fn run_single_control_session(ctx: &mut ControlLoopContext) -> ControlSessionOutcome {
    let (bootstrap, underlay, known_version, nat64_prefix) = {
        let g = ctx.state.inner.read().await;
        (
            g.bootstrap.clone(),
            (g.underlay_if_index, g.linux_fwmark),
            g.latest_netmap.as_ref().map(|n| n.netmap_version),
            g.nat64_prefix.or_else(|| ctx.platform_hooks.nat64_prefix()),
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

    let hook_protector = ctx.platform_hooks.socket_protector();
    let protector: &dyn SocketProtector = hook_protector.as_deref().unwrap_or(&NoopSocketProtector);
    let (mut tls, exporter) = match connect_control_tls_with_protector(
        &endpoint,
        tls_cfg,
        underlay,
        nat64_prefix,
        protector,
    )
    .await
    {
        Ok(pair) => pair,
        Err(err) => {
            let tls_capped = is_tls_or_pin_error(&err);
            return ControlSessionOutcome {
                exit: ControlSessionExit::Retry { err, tls_capped },
                established_duration: None,
            };
        }
    };

    let challenge = match execute_challenge(
        &mut tls,
        &endpoint,
        &ChallengeRequest {
            node_pubkey: ctx.node_keypair.public_key(),
            disco_pubkey: ctx.disco_pubkey,
            protocol_version: CONTROL_PROTOCOL_VERSION,
            agent_version: ctx.runtime_cfg.agent_version.clone(),
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

    let Ok(headers) = build_signed_headers(
        &ctx.node_keypair,
        ctx.disco_pubkey,
        &challenge,
        ("GET", "/v1/netmap/stream", b""),
        exporter,
    ) else {
        return ControlSessionOutcome {
            exit: ControlSessionExit::Retry {
                err: AppError::internal("failed sealing Control WS authentication proof"),
                tls_capped: false,
            },
            established_duration: None,
        };
    };

    let stream_target = build_netmap_stream_target(known_version);
    let max_ws_bytes = ctx.runtime_cfg.max_ws_frame_bytes;
    let mut ws_stream = match tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        connect_control_ws(tls, &endpoint, &stream_target, &headers, max_ws_bytes),
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
    max_ws_frame_bytes: usize,
) -> Result<WebSocket<BridgeStream<S>>, ControlSessionExit>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = build_ws_upgrade_request(endpoint, path, headers)?;
    let mut ws_cfg = WebSocketConfig::default();
    ws_cfg.max_message_size = Some(max_ws_frame_bytes);
    ws_cfg.max_frame_size = Some(max_ws_frame_bytes);

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
                ws.get_mut()
                    .flush_tx_async()
                    .await
                    .map_err(|err| ControlSessionExit::Retry {
                        err: AppError::unavailable(format!("control WS tail flush failed: {err}")),
                        tls_capped: false,
                    })?;
                return Ok(ws);
            }
            Err(HandshakeError::Interrupted(mut mid)) => {
                drive_ws_handshake_step(&mut mid, &mut scratch).await?;
                handshake = mid;
            }
            Err(HandshakeError::Failure(err)) => return Err(map_ws_handshake_error(err)),
        }
    }
}

fn build_ws_upgrade_request(
    endpoint: &str,
    path: &str,
    headers: &[(String, String)],
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, ControlSessionExit> {
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
    Ok(req)
}

async fn drive_ws_handshake_step<S: AsyncRead + AsyncWrite + Unpin>(
    mid: &mut tokio_tungstenite::tungstenite::handshake::MidHandshake<
        ClientHandshake<BridgeStream<S>>,
    >,
    scratch: &mut [u8],
) -> Result<(), ControlSessionExit> {
    mid.get_mut()
        .get_mut()
        .flush_tx_async()
        .await
        .map_err(|err| ControlSessionExit::Retry {
            err: AppError::unavailable(format!("control WS handshake flush failed: {err}")),
            tls_capped: false,
        })?;
    let n = mid
        .get_mut()
        .get_mut()
        .async_stream
        .read(scratch)
        .await
        .map_err(|err| ControlSessionExit::Retry {
            err: AppError::unavailable(format!("control WS upgrade read failed: {err}")),
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
    Ok(())
}

async fn pump_control_ws_stream<S>(
    ctx: &mut ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
) -> ControlSessionExit
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut timer_mode_rx = ctx.state.subscribe_timer_mode();
    let initial_mode = *timer_mode_rx.borrow();
    let mut hb_tick =
        build_heartbeat_interval(ctx.runtime_cfg.control_heartbeat_ms_for(initial_mode));
    let mut ws_close_rx = ctx.state.subscribe_ws_close();
    let mut stun_rx = ctx
        .state
        .inner
        .read()
        .await
        .datapath_handle
        .as_ref()
        .map(DatapathHandle::subscribe_stun_reports);
    let mut last_rx = tokio::time::Instant::now();
    let idle_limit = Duration::from_millis(HEARTBEAT_TIMEOUT_MS);
    let mut initial_stream_snapshot_pending = true;
    let mut scratch = [0_u8; 4096];

    loop {
        if let Some(exit) =
            drain_control_ws_messages(ctx, ws, &mut last_rx, &mut initial_stream_snapshot_pending)
                .await
        {
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
            res = timer_mode_rx.changed() => {
                if res.is_ok() {
                    let mode = *timer_mode_rx.borrow();
                    hb_tick = build_heartbeat_interval(ctx.runtime_cfg.control_heartbeat_ms_for(mode));
                }
            }
            res = recv_stun_changed(stun_rx.as_mut()) => {
                match res {
                    Ok(()) => {
                        if let Err(err) = send_endpoint_update_over_ws(ctx, ws).await {
                            return ControlSessionExit::Retry { err, tls_capped: false };
                        }
                    }
                    Err(_) => stun_rx = None,
                }
            }
            maybe_wake = ctx.wake_rx.recv() => {
                if let Some(exit) = map_wake_signal(ws, maybe_wake).await {
                    return exit;
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
                if let Err(err) = send_control_heartbeat(ctx, ws).await {
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
                if let Some(exit) = handle_ws_raw_read(ws, &scratch, read_res) {
                    return exit;
                }
            }
        }
    }
}

fn build_heartbeat_interval(interval_ms: u64) -> tokio::time::Interval {
    let mut tick = tokio::time::interval(Duration::from_millis(interval_ms.max(1_000)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick
}

async fn recv_stun_changed(
    rx: Option<&mut tokio::sync::watch::Receiver<Option<mesh_datapath::StunProbeReport>>>,
) -> Result<(), tokio::sync::watch::error::RecvError> {
    match rx {
        Some(watch_rx) => watch_rx.changed().await,
        None => std::future::pending().await,
    }
}

async fn map_wake_signal<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocket<BridgeStream<S>>,
    maybe_wake: Option<ControlWakeSignal>,
) -> Option<ControlSessionExit> {
    match maybe_wake {
        Some(ControlWakeSignal::GracefulShutdown) | None => {
            close_ws_gracefully(ws).await;
            Some(ControlSessionExit::Shutdown)
        }
        Some(ControlWakeSignal::ConfigUpdated) => {
            close_ws_gracefully(ws).await;
            Some(ControlSessionExit::ReconnectImmediately)
        }
    }
}

async fn send_control_heartbeat<S: AsyncRead + AsyncWrite + Unpin>(
    ctx: &ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
) -> AppResult<()> {
    let acked_netmap = {
        let g = ctx.state.inner.read().await;
        g.latest_netmap.as_ref().map_or(0, |n| n.netmap_version)
    };
    let frame = ClientControlFrame::Heartbeat {
        sent_at_ms: ctx.clock.now_unix_ms(),
        acked_netmap_version: acked_netmap,
    };
    send_client_control_frame(ws, &frame).await
}

fn handle_ws_raw_read<S>(
    ws: &mut WebSocket<BridgeStream<S>>,
    scratch: &[u8],
    read_res: io::Result<usize>,
) -> Option<ControlSessionExit> {
    match read_res {
        Ok(0) => Some(ControlSessionExit::Retry {
            err: AppError::unavailable("control stream closed by server"),
            tls_capped: false,
        }),
        Ok(n) => {
            if let Some(bytes) = scratch.get(..n) {
                ws.get_mut().push_rx(bytes);
            }
            None
        }
        Err(err) => Some(ControlSessionExit::Retry {
            err: AppError::unavailable(format!("control WS read error: {err}")),
            tls_capped: false,
        }),
    }
}

async fn drain_control_ws_messages<S>(
    ctx: &ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
    last_rx: &mut tokio::time::Instant,
    initial_stream_snapshot_pending: &mut bool,
) -> Option<ControlSessionExit>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match ws.read() {
            Ok(WsMessage::Text(txt)) => {
                if txt.len() > ctx.runtime_cfg.max_ws_frame_bytes {
                    return Some(ControlSessionExit::Retry {
                        err: AppError::invalid_argument(format!(
                            "control WebSocket message {} bytes exceeded {} byte limit",
                            txt.len(),
                            ctx.runtime_cfg.max_ws_frame_bytes
                        )),
                        tls_capped: false,
                    });
                }
                *last_rx = tokio::time::Instant::now();
                if let Some(exit) = handle_server_control_text(
                    ctx,
                    ws,
                    txt.as_str(),
                    initial_stream_snapshot_pending,
                )
                .await
                {
                    return Some(exit);
                }
            }
            Ok(WsMessage::Ping(payload)) => {
                *last_rx = tokio::time::Instant::now();
                if ws.send(WsMessage::Pong(payload)).is_ok() {
                    drop(ws.get_mut().flush_tx_async().await);
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
                drop(ws.get_mut().flush_tx_async().await);
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
            drop(ws.get_mut().flush_tx_async().await);
        }
    };
    if tokio::time::timeout(WS_CLOSE_TIMEOUT, close_fut)
        .await
        .is_err()
    {
        debug!(
            component = "mesh_client.control_loop",
            event = "ws_close_timeout",
            "control WebSocket graceful close timed out within 1 s budget"
        );
    }
}

async fn handle_server_control_text<S>(
    ctx: &ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
    raw_txt: &str,
    initial_stream_snapshot_pending: &mut bool,
) -> Option<ControlSessionExit>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(frame) = serde_json::from_str::<ServerControlFrame>(raw_txt) else {
        debug!(
            component = "mesh_client.control_loop",
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
            let allow_equal = std::mem::replace(initial_stream_snapshot_pending, false);
            if apply_netmap_update(ctx, *netmap, allow_equal).await {
                close_ws_gracefully(ws).await;
                return Some(ControlSessionExit::ReconnectImmediately);
            }
            if let Err(err) = send_endpoint_update_over_ws(ctx, ws).await {
                warn!(
                    component = "mesh_client.control_loop",
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
    state: &ClientRuntimeState,
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
                component = "mesh_client.control_loop",
                event = "relayed_disco_frame_invalid_len",
                src_node_id = %src_node_id,
                len = bytes.len(),
                "dropped empty or oversized CallMeMaybeRelay Disco frame"
            );
            return;
        }
        Err(err) => {
            warn!(
                component = "mesh_client.control_loop",
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
            component = "mesh_client.control_loop",
            event = "call_me_maybe_relay_dispatch_failed",
            src_node_id = %src_node_id,
            error = %err,
            "datapath handle closed before forwarding relayed Disco frame"
        );
    }
}

/// Builds a synchronized [`RelayClientConfig`] from current bootstrap trust policy and underlay hints.
pub fn build_relay_client_config_for_runtime(
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
    state_store: Arc<dyn ClientStateStore>,
    bootstrap_save: Option<BootstrapConfig>,
    relay_update: Option<(RelayClientHandle, RelayClientConfig)>,
    migration_candidate: Option<(String, u64)>,
    udp_port: Option<Port>,
    self_overlay_ip: Option<OverlayIp>,
    self_node_name: Option<mesh_core::NodeName>,
    tun_interface_name: Option<String>,
    overlay_dns_ip: Option<OverlayIp>,
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

/// Validates and sanitizes an incoming `NetmapSnapshot` before any state mutation (`US-011`).
///
/// Returns `Ok(true)` when accepted, `Ok(false)` when stale/non-increasing version should be ignored,
/// and `Err(reason)` when the entire snapshot must be rejected safely.
pub fn validate_and_sanitize_netmap_snapshot(
    snapshot: &mut NetmapSnapshot,
    prev_version: Option<u64>,
    prev_peer_ids: &HashSet<NodeId>,
    self_node_id: Option<NodeId>,
    self_pubkey: PublicKey,
    self_overlay_ip: Option<OverlayIp>,
) -> Result<bool, String> {
    validate_and_sanitize_netmap_snapshot_with_policy(
        snapshot,
        (prev_version, false),
        prev_peer_ids,
        self_node_id,
        self_pubkey,
        self_overlay_ip,
    )
}

fn validate_and_sanitize_netmap_snapshot_with_policy(
    snapshot: &mut NetmapSnapshot,
    version_policy: (Option<u64>, bool),
    prev_peer_ids: &HashSet<NodeId>,
    self_node_id: Option<NodeId>,
    self_pubkey: PublicKey,
    self_overlay_ip: Option<OverlayIp>,
) -> Result<bool, String> {
    let (prev_version, allow_equal_version) = version_policy;
    if let Some(prev) = prev_version
        && (snapshot.netmap_version < prev
            || (!allow_equal_version && snapshot.netmap_version == prev))
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
            component = "mesh_client.control_loop",
            event = "netmap_peer_endpoints_sanitized",
            netmap_version = snapshot.netmap_version,
            stripped_count = stripped_endpoints,
            "stripped invalid peer candidate endpoints"
        );
    }

    warn_if_high_peer_churn(
        snapshot.netmap_version,
        prev_peer_ids,
        &seen_ids,
        snapshot.peers.len(),
    );
    Ok(true)
}

fn warn_if_high_peer_churn(
    netmap_version: u64,
    prev_peer_ids: &HashSet<NodeId>,
    seen_ids: &HashSet<NodeId>,
    new_count: usize,
) {
    if prev_peer_ids.is_empty() {
        return;
    }
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
            component = "mesh_client.control_loop",
            event = "netmap_abnormal_churn_warning",
            netmap_version,
            prev_peers = prev_peer_ids.len(),
            new_peers = new_count,
            changed_peers = changed,
            churn_percent = churn_pct,
            threshold_percent = warn_pct,
            "abnormal Netmap peer churn exceeds configured threshold"
        );
    }
}

async fn apply_netmap_update(
    ctx: &ControlLoopContext,
    mut snapshot: NetmapSnapshot,
    allow_equal_version: bool,
) -> bool {
    let (prev_version, prev_peer_ids, self_node_id, self_overlay_ip) = {
        let g = ctx.state.inner.read().await;
        let prev_ver = g.latest_netmap.as_ref().map(|n| n.netmap_version);
        let prev_ids: HashSet<NodeId> = g
            .latest_netmap
            .as_ref()
            .map(|n| n.peers.iter().map(|p| p.node_id).collect())
            .unwrap_or_default();
        (prev_ver, prev_ids, g.node_id, g.overlay_ip)
    };

    match validate_and_sanitize_netmap_snapshot_with_policy(
        &mut snapshot,
        (prev_version, allow_equal_version),
        &prev_peer_ids,
        self_node_id,
        ctx.node_keypair.public_key(),
        self_overlay_ip,
    ) {
        Ok(true) => {}
        Ok(false) => return false,
        Err(reason) => {
            warn!(
                component = "mesh_client.control_loop",
                event = "netmap_sanity_rejected",
                incoming_version = snapshot.netmap_version,
                reason = %reason,
                "rejecting malformed NetmapSnapshot; preserving prior valid topology"
            );
            return false;
        }
    }

    let now_ms = ctx.clock.now_unix_ms();
    let underlay_dns = ctx.platform_hooks.underlay_dns_servers();
    let update = record_netmap_in_runtime(ctx, &snapshot, &underlay_dns).await;

    if let Some(cfg) = update.bootstrap_save
        && let Err(err) = update.state_store.save_bootstrap(&cfg)
    {
        warn!(
            component = "mesh_client.control_loop",
            event = "bootstrap_pin_persist_failed",
            error = %err,
            "failed persisting updated SPKI pin set"
        );
    }

    if let Some(port) = update.udp_port
        && let Ok(signed_cache) =
            NetmapCacheFile::new_signed(port, snapshot.clone(), now_ms, update.key_expires_at_ms)
        && let Err(err) = update.state_store.save_netmap_cache(&signed_cache)
    {
        warn!(
            component = "mesh_client.control_loop",
            event = "netmap_cache_persist_failed",
            error = %err,
            "failed saving netmap cache"
        );
    }

    if let Some((relay_handle, relay_cfg)) = update.relay_update {
        relay_handle.update_config(relay_cfg);
    }

    if let Some(handle) = update.datapath_opt {
        apply_datapath_and_filter(&handle, &snapshot, ctx.platform_hooks.inbound_filter_spec())
            .await;
    }

    if let Err(err) = ctx
        .platform_hooks
        .dns_hook()
        .sync_mesh_dns(
            &snapshot,
            update.self_overlay_ip,
            update.self_node_name.as_ref(),
        )
        .await
    {
        warn!(
            component = "mesh_client.control_loop",
            event = "dns_hook_sync_failed",
            error = %err,
            "failed synchronizing mesh DNS entries via DnsUpstreamHook"
        );
    }

    if let Some(ref tun_ifname) = update.tun_interface_name
        && let Err(err) = ctx
            .platform_hooks
            .reconcile_on_roam_or_netmap(
                tun_ifname,
                snapshot.overlay_cidr,
                update.overlay_dns_ip,
                Some(&snapshot.domain_suffix),
            )
            .await
    {
        warn!(
            component = "mesh_client.control_loop",
            event = "reconcile_netmap_routes_failed",
            error = %err,
            "failed reconciling routes on NetmapSnapshot update"
        );
    }

    if let Some((cand_ep, ep_ver)) = update.migration_candidate {
        return stage_and_apply_control_migration(ctx, &cand_ep, ep_ver).await;
    }
    false
}

async fn apply_datapath_and_filter(
    handle: &DatapathHandle,
    snapshot: &NetmapSnapshot,
    filter_spec: Option<String>,
) {
    if let Err(err) = handle.apply_netmap(snapshot.clone()).await {
        warn!(
            component = "mesh_client.control_loop",
            event = "datapath_apply_netmap_failed",
            error = %err,
            "failed applying NetmapSnapshot diff to DatapathEngine"
        );
    }
    if let Some(spec) = filter_spec
        && let Err(err) = handle.try_reload_packet_filter_spec(&spec).await
    {
        warn!(
            component = "mesh_client.control_loop",
            event = "inbound_filter_reload_failed",
            error = %err,
            "invalid inbound packet filter rejected fail-safely; keeping active rules"
        );
    }
}

async fn record_netmap_in_runtime(
    ctx: &ControlLoopContext,
    snapshot: &NetmapSnapshot,
    underlay_dns: &[IpAddr],
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
    let raw_control_ep = snapshot.relay_map.control_tcp_endpoint.clone();
    let effective_control_ep = g.bootstrap.server_endpoint.as_deref().map_or_else(
        || raw_control_ep.clone(),
        |boot_ep| crate::session::resolve_effective_remote_endpoint(boot_ep, &raw_control_ep),
    );
    let same_control_ep = g.bootstrap.server_endpoint.as_ref() == Some(&effective_control_ep);
    let mut acked_changed = false;
    let mut migration_candidate = None;
    if same_control_ep {
        if ep_ver > g.bootstrap.acked_endpoint_version {
            g.bootstrap.acked_endpoint_version = ep_ver;
            acked_changed = true;
        }
        g.migration_pending_endpoint = None;
    } else if g.bootstrap.server_endpoint.is_some() {
        g.migration_pending_endpoint = Some(effective_control_ep.clone());
        migration_candidate = Some((effective_control_ep, ep_ver));
    }

    if g.overlay_cidr.is_none() {
        g.overlay_cidr = Some(snapshot.overlay_cidr);
    }
    if let (Some(name), None) = (&g.node_name, &g.fqdn) {
        g.fqdn = Some(format!("{name}.{}", snapshot.domain_suffix));
    }
    g.underlay_dns_servers = underlay_dns.to_vec();
    if let Ok(dns_ip) = derive_overlay_dns_ip(
        snapshot.overlay_cidr,
        g.overlay_ip,
        &snapshot.peers,
        underlay_dns,
    ) {
        g.overlay_dns_ip = Some(dns_ip);
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

    let bootstrap_save =
        (pins_changed || acked_changed || key_exp_changed).then(|| g.bootstrap.clone());
    let effective_relay_ep = g.bootstrap.server_endpoint.as_deref().map_or_else(
        || snapshot.relay_map.relay_tcp_endpoint.clone(),
        |boot_ep| {
            crate::session::resolve_effective_remote_endpoint(
                boot_ep,
                &snapshot.relay_map.relay_tcp_endpoint,
            )
        },
    );
    let effective_prev_relay_ep = prev_relay_ep.as_deref().map(|prev| {
        g.bootstrap.server_endpoint.as_deref().map_or_else(
            || prev.to_owned(),
            |boot_ep| crate::session::resolve_effective_remote_endpoint(boot_ep, prev),
        )
    });
    let relay_changed = effective_prev_relay_ep.as_deref() != Some(effective_relay_ep.as_str())
        || pins_changed
        || g.bootstrap.pin_set() != prev_pin_set;
    let relay_update = if relay_changed
        && let Some(ref rh) = g.relay_handle
        && let Ok(cfg) = build_relay_client_config_for_runtime(
            &g.bootstrap,
            effective_relay_ep,
            (g.underlay_if_index, g.linux_fwmark),
            ctx.runtime_cfg.agent_version.clone(),
        ) {
        Some((rh.clone(), cfg))
    } else {
        None
    };

    NetmapRuntimeUpdate {
        datapath_opt: g.datapath_handle.clone(),
        state_store: Arc::clone(&g.state_store),
        bootstrap_save,
        relay_update,
        migration_candidate,
        udp_port: Port::from_u16(g.local_udp_port.max(1)).ok(),
        self_overlay_ip: g.overlay_ip,
        self_node_name: g.node_name.clone(),
        tun_interface_name: g.tun_interface_name.clone(),
        overlay_dns_ip: g.overlay_dns_ip,
        key_expires_at_ms: g.key_expires_at_ms,
    }
}

/// Tests TLS 1.3 + `POST /v1/auth/challenge` on `candidate_ep` before committing `bootstrap.toml` (`US-074`).
pub async fn stage_and_apply_control_migration(
    ctx: &ControlLoopContext,
    candidate_ep: &str,
    ep_ver: u64,
) -> bool {
    let (mut probe_bootstrap, underlay, nat64) = {
        let g = ctx.state.inner.read().await;
        if crate::config::is_loopback_endpoint(candidate_ep)
            && g.bootstrap
                .server_endpoint
                .as_deref()
                .is_some_and(|ep| !crate::config::is_loopback_endpoint(ep))
        {
            return false;
        }
        (
            g.bootstrap.clone(),
            (g.underlay_if_index, g.linux_fwmark),
            g.nat64_prefix,
        )
    };
    probe_bootstrap.server_endpoint = Some(candidate_ep.to_owned());
    let hook_protector = ctx.platform_hooks.socket_protector();
    let protector: &dyn SocketProtector = hook_protector.as_deref().unwrap_or(&NoopSocketProtector);

    if let Err(err) = probe_control_endpoint_tls(
        &probe_bootstrap,
        &ctx.node_keypair,
        ctx.disco_pubkey,
        &ctx.runtime_cfg.agent_version,
        ControlDialOptions {
            underlay,
            nat64_prefix: nat64,
            protector,
        },
    )
    .await
    {
        warn!(
            component = "mesh_client.control_loop",
            event = "control_migration_probe_failed",
            candidate = %candidate_ep,
            target_version = ep_ver,
            error = %err,
            "candidate Control endpoint failed verification; preserving existing endpoint"
        );
        ctx.state.inner.write().await.last_error =
            Some(format!("Control migration to {candidate_ep} failed: {err}"));
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
            |n| {
                crate::session::resolve_effective_remote_endpoint(
                    candidate_ep,
                    &n.relay_map.relay_tcp_endpoint,
                )
            },
        );
        let relay_update = g.relay_handle.as_ref().and_then(|rh| {
            build_relay_client_config_for_runtime(
                &g.bootstrap,
                relay_ep,
                (g.underlay_if_index, g.linux_fwmark),
                ctx.runtime_cfg.agent_version.clone(),
            )
            .ok()
            .map(|cfg| (rh.clone(), cfg))
        });
        (
            Arc::clone(&g.state_store),
            g.bootstrap.clone(),
            relay_update,
        )
    };

    if let Err(err) = store.save_bootstrap(&persisted) {
        warn!(
            component = "mesh_client.control_loop",
            event = "migration_bootstrap_persist_failed",
            candidate = %candidate_ep,
            error = %err,
            "failed persisting migrated server_endpoint"
        );
        return false;
    }
    if let Some((rh, cfg)) = relay_update {
        rh.update_config(cfg);
    }
    true
}

async fn probe_control_endpoint_tls(
    bootstrap: &BootstrapConfig,
    node_keypair: &NodeKeypair,
    disco_pubkey: PublicKey,
    agent_version: &str,
    dial: ControlDialOptions<'_>,
) -> AppResult<()> {
    let endpoint = bootstrap.server_endpoint.as_deref().ok_or_else(|| {
        AppError::invalid_argument("missing candidate server_endpoint during migration")
    })?;
    validate_tls_trust_policy(endpoint, bootstrap.tls_auth_mode, bootstrap.active_pin)?;
    let tls_cfg = bootstrap.build_tls_client_config()?;
    let (mut tls, _exporter) = connect_control_tls_with_protector(
        endpoint,
        tls_cfg,
        dial.underlay,
        dial.nat64_prefix,
        dial.protector,
    )
    .await?;
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
    drop(tls.shutdown().await);
    Ok(())
}

async fn send_endpoint_update_over_ws<S>(
    ctx: &ControlLoopContext,
    ws: &mut WebSocket<BridgeStream<S>>,
) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (
        datapath_opt,
        acked_ep_ver,
        overlay_opt,
        control_ep,
        tun_ifname,
        stun_ep,
        cached_port,
        nat64,
    ) = {
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
            g.nat64_prefix,
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
    let local_candidates = discover_filtered_local_candidates(
        ctx.platform_hooks.as_ref(),
        active_udp_port,
        tun_ifname.as_deref(),
        &filter_ctx,
        nat64,
    )
    .await;
    persist_updated_udp_port(ctx, cached_port, active_udp_port, &local_candidates).await;

    let endpoints = merge_local_and_reflexive_candidates(&local_candidates, &reflexive_addrs);
    if let Some(handle) = datapath_opt {
        let advertised_addrs: Vec<SocketAddr> = endpoints.iter().map(|c| c.addr).collect();
        drop(
            handle
                .send(DatapathCommand::SetAdvertisedEndpoints(advertised_addrs))
                .await,
        );
    }

    let frame = ClientControlFrame::EndpointUpdate {
        endpoints,
        nat_type,
        acked_endpoint_version: acked_ep_ver,
    };
    send_client_control_frame(ws, &frame).await
}

async fn persist_updated_udp_port(
    ctx: &ControlLoopContext,
    cached_port: u16,
    active_udp_port: u16,
    local_candidates: &[CandidateEndpoint],
) {
    let persist_args = {
        let mut g = ctx.state.inner.write().await;
        g.local_candidates = local_candidates.to_vec();
        if active_udp_port > 0 {
            g.local_udp_port = active_udp_port;
            if active_udp_port != cached_port {
                Some((Arc::clone(&g.state_store), g.key_expires_at_ms))
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some((store, key_exp)) = persist_args
        && let Ok(port) = Port::from_u16(active_udp_port)
        && let Ok(Some(existing)) = store.load_netmap_cache()
        && let Ok(updated) = existing.with_updated_udp_port(port, ctx.clock.now_unix_ms())
    {
        let mut record = updated;
        record.local_key_expires_at_ms = key_exp.or(record.local_key_expires_at_ms);
        drop(store.save_netmap_cache(&record));
    }
}

async fn discover_filtered_local_candidates(
    hooks: &dyn ClientPlatformHooks,
    udp_port: u16,
    tun_interface_name: Option<&str>,
    filter_ctx: &CandidateFilterContext,
    nat64_prefix: Option<Nat64Prefix>,
) -> Vec<CandidateEndpoint> {
    if udp_port == 0 {
        return Vec::new();
    }
    let mut discovered = hooks.discover_local_interface_endpoints(udp_port);
    if discovered.is_empty() {
        let protector_opt = hooks.socket_protector();
        let protector: &dyn SocketProtector =
            protector_opt.as_deref().unwrap_or(&NoopSocketProtector);
        match probe_udp_routing_candidates_protected(udp_port, nat64_prefix, protector) {
            Ok(probed) => discovered = probed,
            Err(err) => {
                warn!(
                    component = "mesh_client.control_loop",
                    event = "udp_candidate_probe_protected_failed",
                    error = %err,
                    "UDP routing candidate probe blocked fail-closed by SocketProtector"
                );
                return Vec::new();
            }
        }
    }
    filter_local_candidate_list(&discovered, tun_interface_name, filter_ctx)
}

/// Filters locally discovered physical interface endpoints into overlay ICE [`CandidateEndpoint`]s.
pub fn filter_local_candidate_list(
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

/// Discovers local physical source IPs using UDP route-connect probes guarded fail-closed by
/// `protector` **before** `connect()`, optionally synthesizing IPv4 targets via `nat64_prefix` (`US-077`).
pub fn probe_udp_routing_candidates_protected(
    udp_port: u16,
    nat64_prefix: Option<Nat64Prefix>,
    protector: &dyn SocketProtector,
) -> AppResult<Vec<DiscoveredInterfaceEndpoint>> {
    const PROBE_TARGETS_V4: [([u8; 4], u16); 4] = [
        ([1, 1, 1, 1], 80),
        ([10, 255, 255, 254], 80),
        ([172, 16, 0, 1], 80),
        ([192, 168, 0, 1], 80),
    ];
    let synth = nat64_prefix.map(Nat64Synthesizer::new);
    let mut targets: Vec<SocketAddr> = Vec::with_capacity(6);
    for (octets, port) in PROBE_TARGETS_V4 {
        let v4 = SocketAddrV4::new(Ipv4Addr::from(octets), port);
        if let Some(s) = synth {
            targets.push(SocketAddr::V6(s.synthesize_sockaddr(v4)));
        } else {
            targets.push(SocketAddr::V4(v4));
        }
    }
    if let Ok(v6) = "[2606:4700:4700::1111]:80".parse::<SocketAddr>() {
        targets.push(v6);
    }

    let mut out = Vec::new();
    for remote in targets {
        let domain = if remote.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let Ok(sock) = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) else {
            continue;
        };
        let raw_fd = extract_socket2_raw_fd(&sock)?;
        // Fail closed immediately on any protection denial before touching OS route/connect().
        protector.protect_socket(raw_fd)?;
        let bind_addr: SocketAddr = if remote.is_ipv6() {
            SocketAddr::from(([0_u16; 8], 0))
        } else {
            SocketAddr::from(([0_u8; 4], 0))
        };
        if sock.bind(&bind_addr.into()).is_ok()
            && sock.connect(&remote.into()).is_ok()
            && let Ok(local_addr) = sock.local_addr()
            && let Some(sa) = local_addr.as_socket()
        {
            out.push(DiscoveredInterfaceEndpoint {
                interface_name: None,
                endpoint: SocketAddr::new(sa.ip(), udp_port),
            });
        }
    }
    Ok(out)
}

fn extract_socket2_raw_fd(socket: &Socket) -> AppResult<i32> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        Ok(socket.as_raw_fd())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket as _;
        let raw = socket.as_raw_socket();
        if raw == u64::MAX {
            return Err(AppError::unavailable("invalid OS socket descriptor"));
        }
        match i32::try_from(raw) {
            Ok(fd) => Ok(fd),
            Err(_) => i32::try_from(raw & 0x7FFF_FFFF)
                .map_err(|_| AppError::unavailable("invalid OS socket descriptor")),
        }
    }
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
    state: &ClientRuntimeState,
    reason: TerminationReason,
    message: &str,
) {
    let new_state = match reason {
        TerminationReason::NodeRevoked => DaemonState::Revoked,
        TerminationReason::NodeKeyExpired => DaemonState::ReauthRequired,
    };
    warn!(
        component = "mesh_client.control_loop",
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

async fn set_degraded_or_connecting(state: &ClientRuntimeState, err_msg: &str) {
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

/// Checks if an offline node's identity key has exceeded its 24h (`86_400_000 ms`) grace period (`US-031 AC4`).
pub async fn check_offline_key_grace_expired(
    state: &ClientRuntimeState,
    now_unix_ms: u64,
) -> Option<String> {
    let g = state.inner.read().await;
    if g.control_connected {
        return None;
    }
    if NetmapCacheFile::is_key_usable_offline(
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
    state: &ClientRuntimeState,
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
            () = sleep_optional_duration(expiry_poll) => {
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

async fn sleep_optional_duration(opt: Option<Duration>) {
    match opt {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

fn map_verified_tls_http_error(err: AppError) -> ControlSessionExit {
    if is_protocol_incompatible_error(&err) {
        return ControlSessionExit::ProtocolIncompatible {
            message: err.to_string(),
        };
    }
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

fn map_ws_handshake_error(ws_err: WsError) -> ControlSessionExit {
    if let WsError::Http(resp) = &ws_err {
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

/// Connects to the Control endpoint over TCP guarded by `SocketProtector` & optional NAT64 synthesis,
/// then establishes TLS 1.3 and extracts the channel-binding exporter secret.
pub async fn connect_control_tls_with_protector(
    endpoint: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    underlay: (Option<u32>, Option<u32>),
    nat64_prefix: Option<Nat64Prefix>,
    protector: &dyn SocketProtector,
) -> AppResult<(TlsStream<TcpStream>, [u8; 32])> {
    let (host, port) = split_host_port(endpoint)?;
    let addrs = tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        lookup_host((host.as_str(), port.get())),
    )
    .await
    .map_err(|_| AppError::unavailable(format!("timed out resolving Control host '{host}'")))?
    .map_err(|err| AppError::unavailable(format!("Control DNS lookup failed: {err}")))?;

    let targets = resolve_relay_target_addrs(addrs, nat64_prefix);
    let mut tcp_opt = None;
    let mut last_err = AppError::unavailable("no IP addresses resolved for Control server");
    for addr in targets {
        match connect_bound_tcp_with_protector(
            addr,
            underlay.0,
            underlay.1,
            Duration::from_millis(CONNECT_TIMEOUT_MS),
            protector,
        )
        .await
        {
            Ok(stream) => {
                if let Err(err) = stream.set_nodelay(true) {
                    debug!(component = "mesh_client.control_loop", error = %err, "TCP_NODELAY ignored");
                }
                tcp_opt = Some(stream);
                break;
            }
            Err(err) => {
                last_err = err;
                if last_err.kind() == ErrorKind::PermissionDenied {
                    return Err(last_err);
                }
            }
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

fn classify_tls_io_error(io_err: &io::Error) -> AppError {
    if let Some(inner) = io_err.get_ref()
        && let Some(rustls_err) = inner.downcast_ref::<tokio_rustls::rustls::Error>()
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

    let (status, resp_body) = tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        read_http_response_inner(stream),
    )
    .await
    .map_err(|_| AppError::unavailable("timed out reading Control HTTP response"))??;

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

async fn read_http_response_inner<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> AppResult<(u16, Vec<u8>)> {
    let raw_head = read_http_head_bytes(stream).await?;
    let head_str = std::str::from_utf8(&raw_head)
        .map_err(|_| AppError::unavailable("non-UTF8 Control HTTP response headers"))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| AppError::unavailable("malformed Control HTTP status line"))?;

    let (content_len, is_chunked) = parse_http_body_framing(lines)?;
    if is_chunked {
        return Ok((status, read_chunked_body(stream).await?));
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

async fn read_http_head_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> AppResult<Vec<u8>> {
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
            return Ok(raw_head);
        }
        if raw_head.len() > MAX_HTTP_HEADER_BYTES {
            return Err(AppError::invalid_argument(
                "Control HTTP response headers exceeded 16 KiB limit",
            ));
        }
    }
}

fn parse_http_body_framing<'a>(lines: impl Iterator<Item = &'a str>) -> AppResult<(usize, bool)> {
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
    Ok((content_len, is_chunked))
}

async fn read_chunked_body<S: AsyncRead + Unpin>(stream: &mut S) -> AppResult<Vec<u8>> {
    let mut body = Vec::new();
    let mut line_buf = Vec::with_capacity(64);
    loop {
        line_buf.clear();
        read_crlf_line(stream, &mut line_buf).await?;
        let hex_line = std::str::from_utf8(&line_buf)
            .map_err(|_| AppError::unavailable("non-UTF8 HTTP chunk length"))?;
        let size_token = hex_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_token, 16)
            .map_err(|_| AppError::unavailable("invalid HTTP chunk size"))?;
        if chunk_len == 0 {
            let mut trailer = Vec::with_capacity(64);
            loop {
                trailer.clear();
                read_crlf_line(stream, &mut trailer).await?;
                if trailer.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        if body.len().saturating_add(chunk_len) > MAX_HTTP_BODY_BYTES {
            return Err(AppError::invalid_argument(
                "chunked HTTP body exceeded limit",
            ));
        }
        let start = body.len();
        body.resize(start + chunk_len, 0);
        if let Some(dst) = body.get_mut(start..start + chunk_len) {
            stream
                .read_exact(dst)
                .await
                .map_err(|err| AppError::unavailable(format!("HTTP chunk read failed: {err}")))?;
        }
        let mut crlf = [0_u8; 2];
        stream
            .read_exact(&mut crlf)
            .await
            .map_err(|err| AppError::unavailable(format!("HTTP chunk CRLF failed: {err}")))?;
    }
}

async fn read_crlf_line<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> AppResult<()> {
    let mut b = [0_u8; 1];
    loop {
        let n = stream
            .read(&mut b)
            .await
            .map_err(|err| AppError::unavailable(format!("HTTP line read failed: {err}")))?;
        if n == 0 {
            return Err(AppError::unavailable("unexpected EOF reading HTTP chunk"));
        }
        if let Some(&ch) = b.first() {
            buf.push(ch);
        }
        if buf.ends_with(b"\r\n") {
            buf.truncate(buf.len().saturating_sub(2));
            return Ok(());
        }
        if buf.len() > 256 {
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

fn is_protocol_incompatible_message(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("unknown variant")
        || lower.contains("protocol incompatible")
        || lower.contains("agent upgrade required")
        || lower.contains("unsupported os")
        || lower.contains("unsupported protocol")
}

/// Maps a verified TLS HTTP error status/body into an [`AppError`], classifying HTTP `400`
/// compatibility rejections so [`map_verified_tls_http_error`] halts retries immediately.
#[must_use]
pub fn map_http_error_response(status: u16, raw_body: &[u8]) -> AppError {
    if let Ok(env) = serde_json::from_slice::<ErrorResponse>(raw_body) {
        if status == 400
            && env.error.kind == ErrorKind::InvalidArgument
            && is_protocol_incompatible_message(&env.error.message)
        {
            return AppError::invalid_argument(format!(
                "{PROTOCOL_INCOMPATIBLE_PREFIX}: {}",
                env.error.message
            ));
        }
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
        400 => {
            if is_protocol_incompatible_message(&msg) {
                AppError::invalid_argument(format!(
                    "{PROTOCOL_INCOMPATIBLE_PREFIX}: {}",
                    msg.trim()
                ))
            } else {
                AppError::invalid_argument(msg.into_owned())
            }
        }
        _ => AppError::unavailable(format!("Control HTTP {status}: {msg}")),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex, mpsc};
    use tokio_rustls::TlsAcceptor;
    use tokio_util::sync::CancellationToken;

    use mesh_core::backoff::{BackoffConfig, ExponentialBackoff};
    use mesh_core::clock::{Clock as _, FakeClock, SystemClock};
    use mesh_core::defaults::{
        BACKOFF_INITIAL_MS, BACKOFF_NETWORK_MAX_MS, BACKOFF_TLS_MAX_MS,
        DEFAULT_MOBILE_MAX_WS_FRAME_BYTES,
    };
    use mesh_core::{
        AppError, ErrorKind, NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey, SpkiPin,
    };
    use mesh_crypto::{
        DiscoKeypair, NodeKeypair, build_rustls_server_config_from_der, generate_ip_pinned_cert,
    };
    use mesh_datapath::TimerMode;
    use mesh_net::nat64::SocketProtector;
    use mesh_net::netmon::NetworkChangeEvent;
    use mesh_proto::agent_ipc::{DaemonState, TlsAuthMode};
    use mesh_proto::control::{ChallengeResponse, RegisterNodeRequest, TerminationReason};
    use mesh_proto::netmap::{
        CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap,
    };

    use crate::config::{BootstrapConfig, ClientRuntimeConfig};
    use crate::hooks::{
        ClientPlatformHooks, ClientStateStore, InMemoryClientPlatformHooks,
        InMemoryClientStateStore,
    };
    use crate::state::ClientRuntimeState;

    use super::{
        BackoffWaitOutcome, ControlLoop, ControlLoopContext, ControlSessionExit, ControlWakeSignal,
        advance_retry_backoff, build_netmap_stream_target, check_offline_key_grace_expired,
        connect_control_ws, forward_relayed_disco_frame, handle_terminal_revocation,
        is_tls_or_pin_error, map_http_error_response, map_verified_tls_http_error,
        probe_udp_routing_candidates_protected, read_http_response_inner,
        set_degraded_or_connecting, stage_and_apply_control_migration,
        validate_and_sanitize_netmap_snapshot, validate_and_sanitize_netmap_snapshot_with_policy,
        wait_backoff_or_wake,
    };

    struct DenyProtector(AtomicUsize);
    impl SocketProtector for DenyProtector {
        fn protect_socket(&self, _raw_fd: i32) -> mesh_core::AppResult<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AppError::permission_denied("vpn protect denied"))
        }
    }

    fn make_state(
        bootstrap: BootstrapConfig,
        now_ms: u64,
    ) -> (Arc<InMemoryClientStateStore>, Arc<ClientRuntimeState>) {
        let store = Arc::new(InMemoryClientStateStore::new());
        drop(store.save_bootstrap(&bootstrap));
        let state = Arc::new(ClientRuntimeState::new_with_now(
            bootstrap,
            Arc::clone(&store) as Arc<dyn ClientStateStore>,
            None,
            1280,
            TimerMode::Responsive,
            now_ms,
        ));
        (store, state)
    }

    fn make_ctx(
        state: Arc<ClientRuntimeState>,
        clock: Arc<dyn mesh_core::clock::Clock>,
        roaming_rx: Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>,
        wake_rx: mpsc::Receiver<ControlWakeSignal>,
        termination_tx: Option<mpsc::Sender<(TerminationReason, String)>>,
        shutdown: CancellationToken,
    ) -> ControlLoopContext {
        ControlLoopContext {
            state,
            clock,
            node_keypair: NodeKeypair::generate(),
            disco_pubkey: DiscoKeypair::generate().public_key(),
            runtime_cfg: ClientRuntimeConfig::for_desktop(),
            platform_hooks: Arc::new(InMemoryClientPlatformHooks::default())
                as Arc<dyn ClientPlatformHooks>,
            roaming_rx,
            wake_rx,
            termination_tx,
            protocol_incompatible_tx: None,
            shutdown,
        }
    }

    #[test]
    fn test_http_400_unknown_variant_maps_to_protocol_incompatible() {
        // Arrange
        let body = br#"{"error":{"kind":"invalid_argument","message":"unknown variant `ios`, expected one of `darwin`, `windows`, `linux`"}}"#;

        // Act
        let app_err = map_http_error_response(400, body);
        let exit = map_verified_tls_http_error(app_err);

        // Assert
        assert!(matches!(
            exit,
            ControlSessionExit::ProtocolIncompatible { .. }
        ));
    }

    #[test]
    fn test_udp_candidate_probe_fails_closed_when_socket_protector_denies() {
        // Arrange
        let protector = DenyProtector(AtomicUsize::new(0));

        // Act
        let res = probe_udp_routing_candidates_protected(51820, None, &protector);

        // Assert
        assert_eq!(protector.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            res.expect_err("must fail closed").kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn test_control_loop_halts_only_on_verified_tls_revocation() {
        // Arrange
        let (_store, state) = make_state(BootstrapConfig::default(), 1_700_000_000_000);

        // Act
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
        let (_store, state) = make_state(BootstrapConfig::default(), 1_700_000_000_000);
        let (roam_tx, roam_rx) = mpsc::channel(4);
        let (_wake_tx, wake_rx) = mpsc::channel(4);
        let mut ctx = make_ctx(
            state,
            Arc::new(SystemClock::new()),
            Arc::new(Mutex::new(roam_rx)),
            wake_rx,
            None,
            CancellationToken::new(),
        );
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

        // Act
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
        assert_eq!(tls_backoff.attempts(), 11);

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
        assert!(
            observed_net.last().copied().unwrap_or_default()
                <= Duration::from_millis(BACKOFF_NETWORK_MAX_MS)
        );
        assert!(
            observed_tls.last().copied().unwrap_or_default()
                <= Duration::from_millis(BACKOFF_TLS_MAX_MS)
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
            drop(server.write_all(partial).await);
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        // Act
        let res = tokio::time::timeout(
            Duration::from_millis(40),
            read_http_response_inner(&mut client),
        )
        .await;
        server_task.abort();

        // Assert
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_staged_control_migration_rolls_back_on_failure_and_commits_on_verified_tls() {
        // Arrange
        let clock = SystemClock::new();
        let now_ms = clock.now_unix_ms();
        let cert =
            generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 30, now_ms / 1000).expect("cert");
        let server_tls = build_rustls_server_config_from_der(
            vec![cert.cert_der.clone()],
            &cert.key_pkcs8_der,
            vec![b"http/1.1".to_vec()],
        )
        .expect("server tls");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let good_addr = listener.local_addr().expect("addr");
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));
        let server_task = tokio::spawn(async move {
            let srv_clock = SystemClock::new();
            if let Ok((tcp, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(tcp).await
            {
                let mut buf = [0_u8; 2048];
                drop(tls.read(&mut buf).await);
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
                    drop(tls.write_all(head.as_bytes()).await);
                    drop(tls.write_all(&json).await);
                    drop(tls.shutdown().await);
                }
            }
        });

        let closed = TcpListener::bind("127.0.0.1:0").await.expect("bind closed");
        let dead_addr = closed.local_addr().expect("dead addr");
        drop(closed);

        let initial_bootstrap = BootstrapConfig {
            server_endpoint: Some("127.0.0.1:1".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(cert.spki_pin),
            next_pin: None,
            node_id: Some(NodeId::new_v7(now_ms)),
            acked_endpoint_version: 1,
            ..BootstrapConfig::default()
        };
        let (store, state) = make_state(initial_bootstrap, now_ms);
        let (_rtx, rrx) = mpsc::channel(4);
        let (_wtx, wrx) = mpsc::channel(4);
        let ctx = make_ctx(
            Arc::clone(&state),
            Arc::new(clock),
            Arc::new(Mutex::new(rrx)),
            wrx,
            None,
            CancellationToken::new(),
        );

        // Act 1
        let failed = stage_and_apply_control_migration(&ctx, &dead_addr.to_string(), 2).await;
        assert!(!failed);
        let after_fail = store.load_bootstrap().expect("load bootstrap");
        assert_eq!(after_fail.server_endpoint.as_deref(), Some("127.0.0.1:1"));
        assert_eq!(after_fail.acked_endpoint_version, 1);

        // Act 2
        let good_ep = good_addr.to_string();
        let succeeded = stage_and_apply_control_migration(&ctx, &good_ep, 3).await;
        server_task.abort();

        // Assert
        assert!(succeeded);
        let after_ok = store.load_bootstrap().expect("load bootstrap");
        assert_eq!(after_ok.server_endpoint.as_deref(), Some(good_ep.as_str()));
        assert_eq!(after_ok.acked_endpoint_version, 3);
        let g = state.inner.read().await;
        assert_eq!(g.migration_pending_endpoint, None);
    }

    #[tokio::test]
    async fn test_forward_relayed_disco_frame_ignores_malformed_safely() {
        // Arrange
        let (_store, state) = make_state(BootstrapConfig::default(), 1_700_000_000_000);
        let node_id = NodeId::new_v7(1_700_000_000_000);
        let pk = PublicKey::from_bytes([7_u8; 32]).expect("pubkey");

        // Act & Assert
        forward_relayed_disco_frame(&state, node_id, pk, "not-valid-base64!!!").await;
    }

    #[tokio::test]
    async fn test_netmap_sanity_rejects_bad_cidr_duplicates_and_local_collision_preserves_valid() {
        // Arrange
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
                stun_udp_endpoints: vec!["203.0.113.10:13478".to_owned()],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([1_u8; 32]),
                next_pin: None,
            },
            peers,
        };

        // Act & Assert: out-of-CIDR
        let mut bad_cidr_snap = make_snap(
            2,
            vec![make_peer(
                1_700_000_000_100,
                "peer-a",
                "192.168.1.5",
                vec![],
            )],
        );
        assert!(
            validate_and_sanitize_netmap_snapshot(
                &mut bad_cidr_snap,
                Some(1),
                &HashSet::new(),
                Some(self_id),
                self_kp.public_key(),
                Some(self_ip),
            )
            .is_err()
        );

        // Duplicate IP
        let mut dup_ip_snap = make_snap(
            3,
            vec![
                make_peer(1_700_000_000_101, "peer-a", "100.115.0.20", vec![]),
                make_peer(1_700_000_000_102, "peer-b", "100.115.0.20", vec![]),
            ],
        );
        assert!(
            validate_and_sanitize_netmap_snapshot(
                &mut dup_ip_snap,
                Some(1),
                &HashSet::new(),
                Some(self_id),
                self_kp.public_key(),
                Some(self_ip),
            )
            .is_err()
        );

        // Local self overlay IP collision
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
            validate_and_sanitize_netmap_snapshot(
                &mut self_col_snap,
                Some(1),
                &HashSet::new(),
                Some(self_id),
                self_kp.public_key(),
                Some(self_ip),
            )
            .is_err()
        );

        // Stale version
        let mut stale_snap = make_snap(1, vec![]);
        assert_eq!(
            validate_and_sanitize_netmap_snapshot(
                &mut stale_snap,
                Some(5),
                &HashSet::new(),
                Some(self_id),
                self_kp.public_key(),
                Some(self_ip),
            ),
            Ok(false)
        );

        // Valid snapshot strips overlay & Control endpoints
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
        let accepted = validate_and_sanitize_netmap_snapshot(
            &mut ok_snap,
            Some(5),
            &prev_ids,
            Some(self_id),
            self_kp.public_key(),
            Some(self_ip),
        );
        assert_eq!(accepted, Ok(true));
        let first_peer = ok_snap.peers.first().expect("sanitized peer");
        assert_eq!(first_peer.endpoints.len(), 1);
        assert_eq!(
            first_peer.endpoints.first().expect("kept endpoint").addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 51820)
        );
    }

    #[tokio::test]
    async fn test_captive_portal_and_tls_errors_use_5m_backoff_and_surface_waiting_for_control() {
        // Arrange
        let portal_redirect = map_http_error_response(302, b"Found");
        let portal_511 = map_http_error_response(511, b"Network Authentication Required");
        let portal_html = map_http_error_response(200, b"<!DOCTYPE html><html>Wi-Fi Login</html>");
        let tls_issuer = AppError::unavailable("TLS certificate signed by unknown issuer");
        let clock_skew = AppError::new(ErrorKind::ClockSkew, "clock skew");

        // Act & Assert
        for err in [
            portal_redirect,
            portal_511,
            portal_html,
            tls_issuer,
            clock_skew,
        ] {
            assert!(
                is_tls_or_pin_error(&err),
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

        let (_store, state) = make_state(BootstrapConfig::default(), 1_700_000_000_000);
        set_degraded_or_connecting(&state, "Control TLS handshake failed").await;
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
        // Arrange
        let old_id = NodeId::new_v7(1_700_000_000_555);
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let dead_ep = dead_listener.local_addr().expect("addr").to_string();
        drop(dead_listener);

        let bootstrap = BootstrapConfig {
            node_id: Some(old_id),
            server_endpoint: Some(dead_ep),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(SpkiPin::from_sha256_bytes([9_u8; 32])),
            acked_endpoint_version: 2,
            ..BootstrapConfig::default()
        };
        let store = InMemoryClientStateStore::new();
        store
            .save_bootstrap(&bootstrap)
            .expect("save old bootstrap");

        let old_kp = NodeKeypair::generate();
        let new_kp = NodeKeypair::generate();
        let req = RegisterNodeRequest {
            node_pubkey: new_kp.public_key(),
            disco_pubkey: DiscoKeypair::generate().public_key(),
            preauth_key: "mpk_rotate_test_secret".to_owned(),
            node_name: NodeName::parse("rotate-test-node").expect("node name"),
            previous_node_pubkey: Some(old_kp.public_key()),
        };

        // Act
        let res =
            ControlLoop::register_node(&bootstrap, &new_kp, &req, "0.1.0-test", (None, None)).await;

        // Assert
        assert!(res.is_err());
        let after = store.load_bootstrap().expect("load preserved bootstrap");
        assert_eq!(after.node_id, Some(old_id));
        assert_eq!(after.acked_endpoint_version, 2);
    }

    #[tokio::test]
    async fn test_control_loop_run_tears_down_when_offline_key_grace_exceeds_24h() {
        // Arrange
        let t0: u64 = 1_700_000_000_000;
        let key_expiry_ms = t0 + 5_000;
        let clock = Arc::new(FakeClock::new(t0));
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let dead_addr = dead_listener.local_addr().expect("addr");
        drop(dead_listener);

        let node_id = NodeId::new_v7(t0);
        let bootstrap = BootstrapConfig {
            node_id: Some(node_id),
            node_name: Some(NodeName::parse("offline-grace-node").expect("name")),
            overlay_ip: Some("100.115.0.44".parse().expect("ip")),
            fqdn: Some("offline-grace-node.mesh.internal".to_owned()),
            server_endpoint: Some(dead_addr.to_string()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(SpkiPin::from_sha256_bytes([3_u8; 32])),
            key_expires_at_ms: Some(key_expiry_ms),
            ..BootstrapConfig::default()
        };
        let (_store, state) = make_state(bootstrap, t0);
        assert!(
            check_offline_key_grace_expired(&state, t0 + 86_400_000)
                .await
                .is_none()
        );

        let (_roaming_tx, roaming_rx) = mpsc::channel(4);
        let (wake_tx, wake_rx) = mpsc::channel(8);
        let (term_tx, mut term_rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let ctx = make_ctx(
            Arc::clone(&state),
            Arc::clone(&clock) as Arc<dyn mesh_core::clock::Clock>,
            Arc::new(Mutex::new(roaming_rx)),
            wake_rx,
            Some(term_tx),
            shutdown.clone(),
        );

        let loop_handle = tokio::spawn(ControlLoop::run(ctx));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(term_rx.try_recv().is_err());

        // Act
        clock.set_wall_ms(key_expiry_ms + 86_400_000 + 1_000);
        assert!(wake_tx.send(ControlWakeSignal::ConfigUpdated).await.is_ok());

        // Assert
        let term = tokio::time::timeout(Duration::from_secs(5), term_rx.recv()).await;
        assert!(matches!(
            term,
            Ok(Some((TerminationReason::NodeKeyExpired, _)))
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

    #[tokio::test]
    async fn test_connect_control_ws_flushes_upgrade_request_and_completes_handshake() {
        // Arrange
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let accepted = tokio_tungstenite::accept_async(server_io).await;
            let ok = accepted.is_ok();
            drop(done_rx.await);
            ok
        });

        // Act
        let client_res = tokio::time::timeout(
            Duration::from_secs(2),
            connect_control_ws(
                client_io,
                "127.0.0.1:18443",
                "/v1/netmap/stream",
                &[("x-mesh-challenge-id".to_owned(), "test-123".to_owned())],
                DEFAULT_MOBILE_MAX_WS_FRAME_BYTES,
            ),
        )
        .await;

        // Assert
        assert!(matches!(client_res, Ok(Ok(_))));
        assert!(done_tx.send(()).is_ok());
        assert_eq!(server_task.await.ok(), Some(true));
    }

    #[test]
    fn test_control_loop_validate_netmap_allows_equal_version_only_on_initial_stream_sync() {
        // Arrange
        let self_node_id = NodeId::new_v7(1_700_000_000_000);
        let peer_id = NodeId::new_v7(1_700_000_000_001);
        let self_pubkey = NodeKeypair::generate().public_key();
        let peer_pubkey = NodeKeypair::generate().public_key();
        let overlay_cidr = "100.115.0.0/16".parse::<OverlayCidr>().expect("cidr");
        let self_ip = "100.115.0.2".parse::<OverlayIp>().expect("self ip");
        let base = NetmapSnapshot {
            netmap_version: 7,
            generated_at_ms: 1_700_000_000_000,
            overlay_cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: Vec::new(),
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([2_u8; 32]),
                next_pin: None,
            },
            peers: vec![PeerEntry {
                node_id: peer_id,
                name: NodeName::parse("peer-1").expect("name"),
                fqdn: "peer-1.mesh.internal".to_owned(),
                overlay_ip: "100.115.0.10".parse().expect("peer ip"),
                node_pubkey: peer_pubkey,
                disco_pubkey: DiscoKeypair::generate().public_key(),
                endpoints: Vec::new(),
                relay_home: "203.0.113.10:8443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            }],
        };
        let mut prev_ids = HashSet::new();
        prev_ids.insert(peer_id);

        // Act
        let mut same_stream_push = base.clone();
        let stale_res = validate_and_sanitize_netmap_snapshot(
            &mut same_stream_push,
            Some(7),
            &prev_ids,
            Some(self_node_id),
            self_pubkey,
            Some(self_ip),
        );
        let mut initial_reconnect_sync = base;
        let sync_res = validate_and_sanitize_netmap_snapshot_with_policy(
            &mut initial_reconnect_sync,
            (Some(7), true),
            &prev_ids,
            Some(self_node_id),
            self_pubkey,
            Some(self_ip),
        );

        // Assert
        assert_eq!(stale_res, Ok(false));
        assert_eq!(sync_res, Ok(true));
    }

    #[tokio::test]
    async fn test_control_loop_guards_against_loopback_relay_map_poisoning() {
        // Arrange
        let t0 = 1_700_000_000_000_u64;
        let bootstrap = BootstrapConfig {
            node_id: Some(NodeId::new_v7(t0)),
            node_name: Some(NodeName::parse("client-win").expect("name")),
            overlay_ip: Some("100.115.0.2".parse().expect("ip")),
            fqdn: Some("client-win.mesh.internal".to_owned()),
            server_endpoint: Some("203.0.113.10:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(SpkiPin::from_sha256_bytes([2_u8; 32])),
            ..BootstrapConfig::default()
        };
        let (_store, state) = make_state(bootstrap, t0);
        let clock = Arc::new(FakeClock::new(t0));
        let (_roaming_tx, roaming_rx) = mpsc::channel(4);
        let (_wake_tx, wake_rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let ctx = make_ctx(
            Arc::clone(&state),
            Arc::clone(&clock) as Arc<dyn mesh_core::clock::Clock>,
            Arc::new(Mutex::new(roaming_rx)),
            wake_rx,
            None,
            shutdown,
        );

        let snapshot = NetmapSnapshot {
            netmap_version: 2,
            generated_at_ms: t0,
            overlay_cidr: "100.115.0.0/16".parse().expect("cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 4,
                control_tcp_endpoint: "127.0.0.1:8443".to_owned(),
                relay_tcp_endpoint: "127.0.0.1:8443".to_owned(),
                stun_udp_endpoints: Vec::new(),
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([2_u8; 32]),
                next_pin: None,
            },
            peers: Vec::new(),
        };

        // Act
        let applied_need_reconnect = super::apply_netmap_update(&ctx, snapshot, true).await;
        let status = state.build_status_response().await;
        let migrated = stage_and_apply_control_migration(&ctx, "127.0.0.1:8443", 5).await;

        // Assert
        assert!(!applied_need_reconnect);
        assert!(!migrated);
        let srv = status.server_connection.expect("server connection");
        assert_eq!(srv.control_endpoint, "203.0.113.10:8443");
        assert_eq!(srv.relay_endpoint, "203.0.113.10:8443");
        assert_eq!(srv.migration_pending_endpoint, None);
    }
}
