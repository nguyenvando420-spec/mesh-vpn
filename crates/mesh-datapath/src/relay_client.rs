//! Authenticated TLS 1.3 + WebSocket Blind Relay client with per-peer drop-tail queues (`US-025`, `US-034`, `SEC-04`).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::{self, ErrorKind as IoErrorKind, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::handshake::HandshakeError;
use tokio_tungstenite::tungstenite::handshake::client::ClientHandshake;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::{WebSocket, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mesh_core::backoff::{BackoffConfig, ExponentialBackoff};
use mesh_core::clock::Clock;
use mesh_core::defaults::{
    CONNECT_TIMEOUT_MS, HEARTBEAT_TIMEOUT_MS, MAX_FRAME_SIZE, RELAY_QUEUE_CAPACITY,
};
use mesh_core::{AppError, AppResult, ErrorKind, NodeId, PublicKey};
use mesh_crypto::{
    DiscoKeypair, NodeKeypair, PinSet, ProofPayload, build_pinned_client_config,
    build_system_ca_client_config, classify_rustls_error, extract_tls_exporter_binding, seal_proof,
    sha256_hex,
};
use mesh_net::bind_underlay_socket2;
use mesh_proto::control::{
    ChallengeResponse, HEADER_AUTH_PROOF, HEADER_BOX_NONCE, HEADER_CHALLENGE_ID, HEADER_NODE_PUBKEY,
};
use mesh_proto::netmap::PinSetDto;
use mesh_proto::relay::{RELAY_MAX_CIPHERTEXT_BYTES, RelayFrame, RelayNoticeCode};

const RELAY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
const OUTBOUND_BATCH_SIZE: usize = 32;
const MAX_CHALLENGE_HTTP_RESPONSE_BYTES: usize = 16 * 1024;
const WS_PATH_RELAY: &str = "/v1/relay";
const HTTP_PATH_CHALLENGE: &str = "/v1/auth/challenge";

/// Connection lifecycle state reported by [`RelayClient`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionState {
    /// No active TLS/WebSocket connection; reconnecting in background if not terminated.
    Disconnected,
    /// Establishing TCP, TLS 1.3, challenge auth, and `/v1/relay` WebSocket upgrade.
    Connecting,
    /// WebSocket Blind Relay session authenticated and ready to forward frames.
    Connected,
    /// Stopped permanently because the Control/Relay server revoked/expired the node (`US-034`).
    Terminated(ErrorKind),
}

/// Configuration for connecting [`RelayClient`] to `mesh-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayClientConfig {
    /// Endpoint string `<host_or_ip>:<port>` parsed from `RelayMap::relay_tcp_endpoint`.
    pub endpoint: String,
    /// Optional TLS SNI / server name override (defaults to host from `endpoint`).
    pub server_name_override: Option<String>,
    /// Pinned SPKI digests (`SEC-04`). `None` uses system CA roots when configured for domain TLS.
    pub pin_set: Option<PinSet>,
    /// Physical underlay interface index for routing-loop exclusion (`REL-09`).
    pub underlay_if_index: Option<u32>,
    /// Linux `SO_MARK` policy-routing mark (`REL-09`).
    pub linux_fwmark: Option<u32>,
    /// Execute `POST /v1/auth/challenge` before WebSocket upgrade (`api-design.md §1.2-1.3`).
    pub require_challenge_auth: bool,
    /// Client agent version string sent inside `ChallengeRequest`.
    pub agent_version: String,
}

impl RelayClientConfig {
    /// Converts `PinSetDto` from a `NetmapSnapshot` into `PinSet`.
    #[must_use]
    pub fn pin_set_from_dto(dto: &PinSetDto) -> PinSet {
        match dto.next_pin {
            Some(next) => PinSet::dual(dto.active_pin, next),
            None => PinSet::single(dto.active_pin),
        }
    }
}

/// Asynchronous events emitted by the [`RelayClient`] task toward [`crate::DatapathEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEvent {
    /// Connection state transition.
    StateChanged(RelayConnectionState),
    /// Authenticated packet (`0x02`) forwarded from `src_pubkey`.
    PacketReceived {
        /// Server-authenticated source node WireGuard public key.
        src_pubkey: PublicKey,
        /// End-to-end encrypted WireGuard or Disco payload (`<= 1480` B).
        ciphertext: Bytes,
    },
    /// Server status notice (`0x04`).
    NoticeReceived(RelayNoticeCode),
}

/// Counters tracking Blind Relay throughput, backpressure drops, and reconnects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayMetricsSnapshot {
    /// Total packets forwarded into WebSocket (`ClientToPeerPacket`).
    pub tx_packets: u64,
    /// Total packets received from WebSocket (`RelayToClientPacket`).
    pub rx_packets: u64,
    /// Packets dropped tail-first when a per-destination bounded `256`-slot queue was full (`US-025 AC6`).
    pub dropped_tail_packets: u64,
    /// Number of server `Throttled` (`0x01`) control notices observed.
    pub throttled_notices: u64,
    /// Number of reconnect attempts performed.
    pub reconnects: u64,
}

#[derive(Debug, Default)]
struct RelayMetrics {
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    dropped_tail_packets: AtomicU64,
    throttled_notices: AtomicU64,
    reconnects: AtomicU64,
}

impl RelayMetrics {
    fn snapshot(&self) -> RelayMetricsSnapshot {
        RelayMetricsSnapshot {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            dropped_tail_packets: self.dropped_tail_packets.load(Ordering::Relaxed),
            throttled_notices: self.throttled_notices.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
        }
    }
}

/// Non-blocking handle enforcing strict per-destination `mpsc::channel(256)` + `try_send()`
/// (no HoL blocking across destinations, drop-tail on congestion per `US-025 AC6`).
#[derive(Debug, Clone)]
pub struct RelayClientHandle {
    inner: Arc<RelayQueueRegistry>,
    metrics: Arc<RelayMetrics>,
    config_tx: Option<Arc<watch::Sender<RelayClientConfig>>>,
}

#[derive(Debug)]
struct RelayQueueRegistry {
    queues: Mutex<HashMap<PublicKey, PeerTxChannel>>,
    active_rx_queues: Mutex<Vec<(PublicKey, mpsc::Receiver<Bytes>)>>,
    wake: Notify,
}

#[derive(Debug)]
struct PeerTxChannel {
    tx: mpsc::Sender<Bytes>,
}

impl RelayQueueRegistry {
    fn new() -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            active_rx_queues: Mutex::new(Vec::new()),
            wake: Notify::new(),
        }
    }
}

impl RelayClientHandle {
    /// Creates a standalone pair `(RelayClientHandle, PeerTxDrain)` suitable for wiring `RelayClient`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RelayQueueRegistry::new()),
            metrics: Arc::new(RelayMetrics::default()),
            config_tx: None,
        }
    }

    /// Atomically replaces the active Relay endpoint/TLS configuration and wakes any running
    /// session or reconnect sleep to switch immediately (`HR-W12-01`).
    pub fn update_config(&self, next: RelayClientConfig) {
        if let Some(tx) = &self.config_tx
            && let Err(err) = tx.send(next)
        {
            debug!(
                component = "datapath.relay_client",
                event = "relay_config_update_dropped",
                error = %err,
                "relay config update dropped because relay client stopped"
            );
        }
    }

    /// Enqueues a WireGuard or Disco payload toward `dst_pubkey` without blocking (`US-025 AC6`).
    ///
    /// Allocates a dedicated `mpsc::channel(256)` per destination and drops tail with metric
    /// increment when full so one congested peer never causes Head-of-Line blocking for others.
    pub fn try_send_packet(&self, dst_pubkey: PublicKey, ciphertext: Bytes) -> bool {
        if ciphertext.is_empty() || ciphertext.len() > RELAY_MAX_CIPHERTEXT_BYTES {
            return false;
        }
        let sender = {
            let Ok(mut map) = self.inner.queues.lock() else {
                return false;
            };
            if let Some(entry) = map.get(&dst_pubkey) {
                entry.tx.clone()
            } else {
                let (tx, rx) = mpsc::channel(RELAY_QUEUE_CAPACITY);
                if let Ok(mut rx_list) = self.inner.active_rx_queues.lock() {
                    rx_list.push((dst_pubkey, rx));
                }
                map.insert(dst_pubkey, PeerTxChannel { tx: tx.clone() });
                tx
            }
        };

        match sender.try_send(ciphertext) {
            Ok(()) => {
                self.inner.wake.notify_one();
                true
            }
            Err(_) => {
                self.metrics
                    .dropped_tail_packets
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Returns a point-in-time metrics snapshot.
    #[must_use]
    pub fn metrics_snapshot(&self) -> RelayMetricsSnapshot {
        self.metrics.snapshot()
    }

    fn drain_one_round(&self, max_total: usize) -> Vec<RelayFrame> {
        let Ok(mut rx_list) = self.inner.active_rx_queues.lock() else {
            return Vec::new();
        };
        let mut drained = Vec::new();
        let len = rx_list.len();
        if len == 0 {
            return drained;
        }

        for _ in 0..max_total {
            let mut progressed = false;
            for (dst_pubkey, rx) in rx_list.iter_mut() {
                if let Ok(ciphertext) = rx.try_recv() {
                    drained.push(RelayFrame::ClientToPeerPacket {
                        dst_pubkey: *dst_pubkey,
                        ciphertext,
                    });
                    progressed = true;
                    if drained.len() >= max_total {
                        break;
                    }
                }
            }
            if !progressed || drained.len() >= max_total {
                break;
            }
        }

        // Rotate queue fairness offset so the same peer does not always run first.
        if rx_list.len() > 1 {
            rx_list.rotate_left(1);
        }
        drained
    }
}

impl Default for RelayClientHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Abstract stream + optional RFC 5705 TLS exporter binding returned by a [`RelayTransport`].
pub trait RelayIoStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> RelayIoStream for T {}

/// Established transport stream paired with optional TLS exporter secret (`[u8; 32]`).
pub struct ConnectedRelayTransport {
    /// Underlying async stream (TLS 1.3 in production; loopback stream in unit tests).
    pub stream: Box<dyn RelayIoStream>,
    /// 32-byte TLS exporter binding (`extract_tls_exporter_binding`) if over TLS.
    pub tls_exporter_binding: Option<[u8; 32]>,
}

impl std::fmt::Debug for ConnectedRelayTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectedRelayTransport")
            .field("has_tls_exporter", &self.tls_exporter_binding.is_some())
            .finish_non_exhaustive()
    }
}

/// Factory establishing an underlay-bound stream to the Blind Relay endpoint.
pub trait RelayConnector: Send + Sync + 'static {
    /// Connects TCP + TLS 1.3 and extracts the RFC 5705 TLS exporter binding.
    fn connect<'a>(
        &'a self,
        config: &'a RelayClientConfig,
    ) -> Pin<Box<dyn Future<Output = AppResult<ConnectedRelayTransport>> + Send + 'a>>;
}

/// Production connector enforcing `bind_underlay_socket2`, TLS 1.3, and SPKI pinning (`SEC-04`).
#[derive(Debug, Default, Clone, Copy)]
pub struct TlsRelayConnector;

impl RelayConnector for TlsRelayConnector {
    fn connect<'a>(
        &'a self,
        config: &'a RelayClientConfig,
    ) -> Pin<Box<dyn Future<Output = AppResult<ConnectedRelayTransport>> + Send + 'a>> {
        Box::pin(connect_tls_transport(config))
    }
}

/// Authenticated WebSocket Blind Relay client with reconnect backoff and graceful shutdown.
pub struct RelayClient {
    config_tx: Arc<watch::Sender<RelayClientConfig>>,
    node_keypair: NodeKeypair,
    disco_keypair: DiscoKeypair,
    handle: RelayClientHandle,
    connector: Arc<dyn RelayConnector>,
}

impl std::fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cfg = self.config_tx.borrow();
        f.debug_struct("RelayClient")
            .field("endpoint", &cfg.endpoint)
            .field("require_challenge_auth", &cfg.require_challenge_auth)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReconnectStep {
    delay: Duration,
    attempt: u32,
    ceiling_ms: u64,
    tls_capped: bool,
}

struct ReconnectBackoffs {
    network: ExponentialBackoff,
    tls: ExponentialBackoff,
}

impl ReconnectBackoffs {
    const fn new() -> Self {
        Self {
            network: ExponentialBackoff::new(BackoffConfig::network()),
            tls: ExponentialBackoff::new(BackoffConfig::tls_or_security()),
        }
    }

    fn reset_all(&mut self) {
        self.network.reset();
        self.tls.reset();
    }

    fn schedule(&mut self, tls_capped: bool) -> ReconnectStep {
        let tracker = if tls_capped {
            &mut self.tls
        } else {
            &mut self.network
        };
        let attempt = tracker.attempts();
        let ceiling_ms = tracker.current_ceiling_ms();
        let delay = tracker.next_delay();
        ReconnectStep {
            delay,
            attempt,
            ceiling_ms,
            tls_capped,
        }
    }
}

fn is_tls_capped_error(err: &AppError) -> bool {
    if matches!(err.kind(), ErrorKind::ClockSkew | ErrorKind::PinMismatch) {
        return true;
    }
    let msg = err.to_string();
    msg.starts_with("TLS ") || msg.starts_with("relay TLS ")
}

impl RelayClient {
    /// Creates a production `RelayClient` backed by [`TlsRelayConnector`].
    #[must_use]
    pub fn new(
        config: RelayClientConfig,
        node_keypair: NodeKeypair,
        disco_keypair: DiscoKeypair,
    ) -> Self {
        Self::with_connector(
            config,
            node_keypair,
            disco_keypair,
            Arc::new(TlsRelayConnector),
        )
    }

    /// Creates a `RelayClient` with a custom [`RelayConnector`] (useful for deterministic tests).
    #[must_use]
    pub fn with_connector(
        config: RelayClientConfig,
        node_keypair: NodeKeypair,
        disco_keypair: DiscoKeypair,
        connector: Arc<dyn RelayConnector>,
    ) -> Self {
        let (config_tx, _config_rx) = watch::channel(config);
        let config_tx = Arc::new(config_tx);
        Self {
            config_tx: Arc::clone(&config_tx),
            node_keypair,
            disco_keypair,
            handle: RelayClientHandle {
                inner: Arc::new(RelayQueueRegistry::new()),
                metrics: Arc::new(RelayMetrics::default()),
                config_tx: Some(config_tx),
            },
            connector,
        }
    }

    /// Returns a clonable non-blocking outbound send handle (`try_send` per peer `256` queue).
    #[must_use]
    pub fn handle(&self) -> RelayClientHandle {
        self.handle.clone()
    }

    /// Runs the reconnect/session loop until `shutdown` fires or server sends `NodeRevoked`/`NodeKeyExpired`.
    pub async fn run(
        self,
        clock: Arc<dyn Clock>,
        events_tx: mpsc::Sender<RelayEvent>,
        shutdown: CancellationToken,
    ) {
        self.run_with_sleeper(&clock, &events_tx, &shutdown, |step| {
            tokio::time::sleep(step.delay)
        })
        .await;
    }

    async fn run_with_sleeper<F, Fut>(
        &self,
        clock: &Arc<dyn Clock>,
        events_tx: &mpsc::Sender<RelayEvent>,
        shutdown: &CancellationToken,
        mut sleeper: F,
    ) where
        F: FnMut(ReconnectStep) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut backoffs = ReconnectBackoffs::new();
        let mut config_rx = self.config_tx.subscribe();

        loop {
            if shutdown.is_cancelled() {
                break;
            }
            emit_relay_event(
                events_tx,
                RelayEvent::StateChanged(RelayConnectionState::Connecting),
            )
            .await;

            match self
                .run_single_session(&mut config_rx, clock, events_tx, shutdown, &mut backoffs)
                .await
            {
                SessionExit::Shutdown => break,
                SessionExit::ConfigUpdated => {
                    backoffs.reset_all();
                }
                SessionExit::TerminalAuth(kind) => {
                    warn!(
                        component = "datapath.relay_client",
                        event = "relay_terminal_auth_stop",
                        error_kind = ?kind,
                        "halting Blind Relay reconnect loop on authoritative terminal notice"
                    );
                    emit_relay_event(
                        events_tx,
                        RelayEvent::StateChanged(RelayConnectionState::Terminated(kind)),
                    )
                    .await;
                    break;
                }
                SessionExit::Reconnect { error, tls_capped } => {
                    emit_relay_event(
                        events_tx,
                        RelayEvent::StateChanged(RelayConnectionState::Disconnected),
                    )
                    .await;
                    let step = backoffs.schedule(tls_capped);
                    let delay_ms = u64::try_from(step.delay.as_millis()).unwrap_or(u64::MAX);
                    self.handle
                        .metrics
                        .reconnects
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        component = "datapath.relay_client",
                        event = "relay_reconnect_scheduled",
                        delay_ms,
                        attempt = step.attempt,
                        ceiling_ms = step.ceiling_ms,
                        tls_capped = step.tls_capped,
                        error = %error,
                        "Blind Relay session ended; backing off before reconnect"
                    );
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        Ok(()) = config_rx.changed() => {
                            backoffs.reset_all();
                        }
                        () = sleeper(step) => {}
                    }
                }
            }
        }
    }

    async fn establish_ws_session(
        &self,
        session_cfg: &RelayClientConfig,
        clock: &dyn Clock,
    ) -> Result<WebSocket<BridgeStream>, SessionExit> {
        let mut transport = self.connector.connect(session_cfg).await.map_err(|err| {
            let tls_capped = is_tls_capped_error(&err);
            SessionExit::Reconnect {
                error: err,
                tls_capped,
            }
        })?;

        let headers = self
            .prepare_auth_headers(&mut transport, session_cfg, clock)
            .await
            .map_err(classify_auth_or_ws_exit)?;

        perform_ws_handshake(transport.stream, &session_cfg.endpoint, &headers)
            .await
            .map_err(classify_auth_or_ws_exit)
    }

    async fn run_single_session(
        &self,
        config_rx: &mut watch::Receiver<RelayClientConfig>,
        clock: &Arc<dyn Clock>,
        events_tx: &mpsc::Sender<RelayEvent>,
        shutdown: &CancellationToken,
        backoffs: &mut ReconnectBackoffs,
    ) -> SessionExit {
        let session_cfg = config_rx.borrow_and_update().clone();
        let mut ws = tokio::select! {
            () = shutdown.cancelled() => return SessionExit::Shutdown,
            Ok(()) = config_rx.changed() => return SessionExit::ConfigUpdated,
            res = self.establish_ws_session(&session_cfg, clock.as_ref()) => match res {
                Ok(ws) => ws,
                Err(exit) => return exit,
            },
        };

        backoffs.reset_all();
        emit_relay_event(
            events_tx,
            RelayEvent::StateChanged(RelayConnectionState::Connected),
        )
        .await;
        info!(
            component = "datapath.relay_client",
            event = "relay_connected",
            endpoint = %session_cfg.endpoint,
            "connected to Blind Relay WebSocket"
        );

        let result = self
            .drive_ws_loop(&mut ws, clock.as_ref(), events_tx, shutdown, config_rx)
            .await;
        close_ws_gracefully(&mut ws).await;
        result
    }

    async fn prepare_auth_headers(
        &self,
        transport: &mut ConnectedRelayTransport,
        session_cfg: &RelayClientConfig,
        _clock: &dyn Clock,
    ) -> AppResult<Vec<(String, String)>> {
        if !session_cfg.require_challenge_auth {
            return Ok(Vec::new());
        }
        let challenge = execute_challenge_http(
            transport.stream.as_mut(),
            session_cfg,
            self.node_keypair.public_key(),
            self.disco_keypair.public_key(),
        )
        .await?;

        let exporter = transport.tls_exporter_binding.unwrap_or([0u8; 32]);
        let payload = ProofPayload {
            challenge_id: challenge.challenge_id,
            challenge_nonce: challenge.challenge_nonce,
            method: "GET".to_owned(),
            path: WS_PATH_RELAY.to_owned(),
            body_sha256: sha256_hex(b""),
            node_pubkey: self.node_keypair.public_key(),
            disco_pubkey: self.disco_keypair.public_key(),
            timestamp_at_ms: challenge.server_time_at_ms,
            tls_exporter_binding: base64_encode(&exporter),
        };
        let sealed = seal_proof(&payload, &challenge.server_eph_pubkey, &self.node_keypair)?;

        Ok(vec![
            (
                HEADER_CHALLENGE_ID.to_owned(),
                challenge.challenge_id.to_string(),
            ),
            (
                HEADER_NODE_PUBKEY.to_owned(),
                base64_encode(self.node_keypair.public_key().as_bytes()),
            ),
            (
                HEADER_BOX_NONCE.to_owned(),
                base64_encode(&sealed.box_nonce),
            ),
            (
                HEADER_AUTH_PROOF.to_owned(),
                base64_encode(&sealed.ciphertext),
            ),
        ])
    }

    async fn drive_ws_loop(
        &self,
        ws: &mut WebSocket<BridgeStream>,
        clock: &dyn Clock,
        events_tx: &mpsc::Sender<RelayEvent>,
        shutdown: &CancellationToken,
        config_rx: &mut watch::Receiver<RelayClientConfig>,
    ) -> SessionExit {
        let mut keepalive_tick = tokio::time::interval(RELAY_KEEPALIVE_INTERVAL);
        keepalive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_rx_instant = tokio::time::Instant::now();
        let heartbeat_timeout = Duration::from_millis(HEARTBEAT_TIMEOUT_MS);
        let mut read_scratch = [0u8; MAX_FRAME_SIZE * 2];

        if let Some(exit) = self.drain_ws_messages(ws, events_tx).await {
            return exit;
        }

        loop {
            if let Err(err) = self.flush_outbound_batch(ws).await {
                return SessionExit::Reconnect {
                    error: err,
                    tls_capped: false,
                };
            }

            let idle_deadline = tokio::time::sleep_until(last_rx_instant + heartbeat_timeout);
            tokio::pin!(idle_deadline);

            tokio::select! {
                () = shutdown.cancelled() => return SessionExit::Shutdown,
                Ok(()) = config_rx.changed() => return SessionExit::ConfigUpdated,
                () = self.handle.inner.wake.notified() => {}
                _ = keepalive_tick.tick() => {
                    let frame = RelayFrame::KeepAlive { sent_at_ms: clock.now_unix_ms() };
                    if let Err(err) = send_relay_frame(ws, &frame).await {
                        return SessionExit::Reconnect { error: err, tls_capped: false };
                    }
                }
                () = &mut idle_deadline => {
                    return SessionExit::Reconnect {
                        error: AppError::unavailable("relay heartbeat timeout exceeded (60 s)"),
                        tls_capped: false,
                    };
                }
                read_res = ws.get_mut().async_stream.read(&mut read_scratch) => {
                    match read_res {
                        Ok(0) => {
                            return SessionExit::Reconnect {
                                error: AppError::unavailable("relay WebSocket EOF"),
                                tls_capped: false,
                            };
                        }
                        Ok(n) => {
                            last_rx_instant = tokio::time::Instant::now();
                            if let Some(bytes) = read_scratch.get(..n) {
                                ws.get_mut().push_rx(bytes);
                            }
                            if let Some(exit) = self.drain_ws_messages(ws, events_tx).await {
                                return exit;
                            }
                        }
                        Err(err) => {
                            return SessionExit::Reconnect {
                                error: AppError::unavailable(format!("relay read error: {err}")),
                                tls_capped: false,
                            };
                        }
                    }
                }
            }
        }
    }

    async fn flush_outbound_batch(&self, ws: &mut WebSocket<BridgeStream>) -> AppResult<()> {
        loop {
            let frames = self.handle.drain_one_round(OUTBOUND_BATCH_SIZE);
            if frames.is_empty() {
                return Ok(());
            }
            let drained_count = frames.len();
            for frame in frames {
                send_relay_frame(ws, &frame).await?;
                self.handle
                    .metrics
                    .tx_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            if drained_count < OUTBOUND_BATCH_SIZE {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    }

    async fn drain_ws_messages(
        &self,
        ws: &mut WebSocket<BridgeStream>,
        events_tx: &mpsc::Sender<RelayEvent>,
    ) -> Option<SessionExit> {
        loop {
            match ws.read() {
                Ok(Message::Binary(bin)) => {
                    let exit = self.handle_decoded_relay_frame(&bin, events_tx).await;
                    flush_ignored(ws.get_mut()).await;
                    if exit.is_some() {
                        return exit;
                    }
                }
                Ok(Message::Ping(_) | Message::Pong(_)) => {
                    flush_ignored(ws.get_mut()).await;
                }
                Ok(Message::Close(_)) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {
                    flush_ignored(ws.get_mut()).await;
                    return Some(SessionExit::Reconnect {
                        error: AppError::unavailable("relay server closed WebSocket"),
                        tls_capped: false,
                    });
                }
                Ok(Message::Text(_) | Message::Frame(_)) => {}
                Err(WsError::Io(io_err)) if io_err.kind() == IoErrorKind::WouldBlock => {
                    flush_ignored(ws.get_mut()).await;
                    return None;
                }
                Err(err) => {
                    return Some(SessionExit::Reconnect {
                        error: AppError::unavailable(format!("relay ws protocol error: {err}")),
                        tls_capped: false,
                    });
                }
            }
        }
    }

    async fn handle_decoded_relay_frame(
        &self,
        raw: &[u8],
        events_tx: &mpsc::Sender<RelayEvent>,
    ) -> Option<SessionExit> {
        match RelayFrame::decode(raw) {
            Ok(RelayFrame::RelayToClientPacket {
                src_pubkey,
                ciphertext,
            }) => {
                self.handle
                    .metrics
                    .rx_packets
                    .fetch_add(1, Ordering::Relaxed);
                emit_relay_event(
                    events_tx,
                    RelayEvent::PacketReceived {
                        src_pubkey,
                        ciphertext,
                    },
                )
                .await;
                None
            }
            Ok(RelayFrame::ControlNotice { code }) => {
                if code == RelayNoticeCode::Throttled {
                    self.handle
                        .metrics
                        .throttled_notices
                        .fetch_add(1, Ordering::Relaxed);
                }
                emit_relay_event(events_tx, RelayEvent::NoticeReceived(code)).await;
                match code {
                    RelayNoticeCode::NodeRevoked => {
                        Some(SessionExit::TerminalAuth(ErrorKind::NodeRevoked))
                    }
                    RelayNoticeCode::NodeKeyExpired => {
                        Some(SessionExit::TerminalAuth(ErrorKind::NodeKeyExpired))
                    }
                    RelayNoticeCode::ServerMigratingPort => Some(SessionExit::Reconnect {
                        error: AppError::unavailable("server migrating relay port"),
                        tls_capped: false,
                    }),
                    RelayNoticeCode::Throttled => None,
                }
            }
            Ok(RelayFrame::KeepAlive { .. } | RelayFrame::ClientToPeerPacket { .. }) => None,
            Err(err) => {
                warn!(
                    component = "datapath.relay_client",
                    event = "malformed_relay_frame",
                    error = %err,
                    "dropped malformed Relay binary frame"
                );
                None
            }
        }
    }
}

enum SessionExit {
    Shutdown,
    ConfigUpdated,
    TerminalAuth(ErrorKind),
    Reconnect { error: AppError, tls_capped: bool },
}

fn classify_auth_or_ws_exit(err: AppError) -> SessionExit {
    if err.kind().should_stop_auto_retry() {
        return SessionExit::TerminalAuth(err.kind());
    }
    let tls_capped = is_tls_capped_error(&err);
    SessionExit::Reconnect {
        error: err,
        tls_capped,
    }
}

/// Bridges synchronous `tungstenite::WebSocket<BridgeStream>` onto Tokio async I/O cleanly
/// without requiring external stream/sink adapter crates.
struct BridgeStream {
    async_stream: Box<dyn RelayIoStream>,
    rx_queue: VecDeque<u8>,
    tx_queue: Vec<u8>,
}

impl BridgeStream {
    fn new(async_stream: Box<dyn RelayIoStream>) -> Self {
        Self {
            async_stream,
            rx_queue: VecDeque::with_capacity(4096),
            tx_queue: Vec::new(),
        }
    }

    fn push_rx(&mut self, data: &[u8]) {
        self.rx_queue.extend(data);
    }

    async fn flush_tx_async(&mut self) -> io::Result<()> {
        if !self.tx_queue.is_empty() {
            self.async_stream.write_all(&self.tx_queue).await?;
            self.tx_queue.clear();
            self.async_stream.flush().await?;
        }
        Ok(())
    }
}

impl Read for BridgeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_queue.is_empty() {
            return Err(io::Error::new(
                IoErrorKind::WouldBlock,
                "no buffered relay bytes",
            ));
        }
        self.rx_queue.read(buf)
    }
}

impl Write for BridgeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx_queue.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn connect_tls_transport(config: &RelayClientConfig) -> AppResult<ConnectedRelayTransport> {
    let (host, port) = split_host_port(&config.endpoint)?;
    let target_addrs = tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| AppError::unavailable("timed out resolving Blind Relay hostname"))?
    .map_err(|err| AppError::unavailable(format!("DNS resolution failed for relay: {err}")))?;

    let mut tcp_stream = None;
    let mut last_err = AppError::unavailable("no IP addresses resolved for Blind Relay");
    for addr in target_addrs {
        match connect_bound_tcp(addr, config.underlay_if_index, config.linux_fwmark).await {
            Ok(stream) => {
                tcp_stream = Some(stream);
                break;
            }
            Err(err) => last_err = err,
        }
    }
    let tcp_stream = tcp_stream.ok_or(last_err)?;

    let tls_cfg = match &config.pin_set {
        Some(pins) => build_pinned_client_config(*pins)?,
        None => build_system_ca_client_config()?,
    };
    let sni_host = config.server_name_override.as_deref().unwrap_or(host);
    let server_name = ServerName::try_from(sni_host.to_owned()).map_err(|_| {
        AppError::invalid_argument(format!("invalid TLS SNI server name '{sni_host}'"))
    })?;

    let connector = TlsConnector::from(tls_cfg);
    let tls_stream = tokio::time::timeout(
        Duration::from_millis(CONNECT_TIMEOUT_MS),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .map_err(|_| AppError::unavailable("TLS 1.3 handshake with Blind Relay timed out"))?
    .map_err(|io_err| classify_tls_io_error(&io_err))?;

    let exporter = extract_tls_exporter_binding(tls_stream.get_ref().1)?;
    Ok(ConnectedRelayTransport {
        stream: Box::new(tls_stream),
        tls_exporter_binding: Some(exporter),
    })
}

async fn connect_bound_tcp(
    addr: SocketAddr,
    if_index: Option<u32>,
    fwmark: Option<u32>,
) -> AppResult<TcpStream> {
    connect_bound_tcp_with_timeout(
        addr,
        if_index,
        fwmark,
        Duration::from_millis(CONNECT_TIMEOUT_MS),
    )
    .await
}

/// Opens a non-blocking TCP connection bound to the OS underlay interface (`if_index` / `fwmark`)
/// with an explicit timeout budget, preventing routing-loop traversal across the overlay TUN.
pub async fn connect_bound_tcp_with_timeout(
    addr: SocketAddr,
    if_index: Option<u32>,
    fwmark: Option<u32>,
    timeout: Duration,
) -> AppResult<TcpStream> {
    let is_ipv6 = addr.is_ipv6();
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|err| AppError::unavailable(format!("failed to create tcp socket: {err}")))?;
    sock.set_nonblocking(true)
        .map_err(|err| AppError::unavailable(format!("failed to set tcp nonblocking: {err}")))?;
    if let Err(err) = sock.set_nodelay(true) {
        debug!(component = "datapath.relay_client", error = %err, "TCP_NODELAY ignored");
    }

    if if_index.is_some() || fwmark.is_some() {
        bind_underlay_socket2(&sock, is_ipv6, if_index, fwmark)?;
    }

    if let Err(err) = sock.connect(&addr.into())
        && err.kind() != IoErrorKind::WouldBlock
        && err.raw_os_error() != Some(115)
        && err.raw_os_error() != Some(36)
        && err.raw_os_error() != Some(10035)
    {
        return Err(AppError::unavailable(format!("tcp connect failed: {err}")));
    }

    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream)
        .map_err(|err| AppError::unavailable(format!("failed to adopt tokio tcp stream: {err}")))?;
    tokio::time::timeout(timeout, stream.writable())
        .await
        .map_err(|_| AppError::unavailable("tcp connect timed out"))?
        .map_err(|err| AppError::unavailable(format!("tcp writable wait failed: {err}")))?;

    if let Ok(Some(so_err)) = stream.take_error() {
        return Err(AppError::unavailable(format!("tcp socket error: {so_err}")));
    }
    Ok(stream)
}

fn classify_tls_io_error(io_err: &io::Error) -> AppError {
    if let Some(inner) = io_err.get_ref()
        && let Some(rustls_err) = inner.downcast_ref::<tokio_rustls::rustls::Error>()
    {
        return classify_rustls_error(rustls_err);
    }
    AppError::unavailable(format!("relay TLS handshake failed: {io_err}"))
}

async fn execute_challenge_http(
    stream: &mut dyn RelayIoStream,
    config: &RelayClientConfig,
    node_pubkey: PublicKey,
    disco_pubkey: PublicKey,
) -> AppResult<ChallengeResponse> {
    let body_bytes =
        encode_challenge_request_json(node_pubkey, disco_pubkey, &config.agent_version);

    let raw_req = format!(
        "POST {HTTP_PATH_CHALLENGE} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n",
        config.endpoint,
        body_bytes.len()
    );
    stream
        .write_all(raw_req.as_bytes())
        .await
        .map_err(|err| AppError::unavailable(format!("challenge header write failed: {err}")))?;
    stream
        .write_all(&body_bytes)
        .await
        .map_err(|err| AppError::unavailable(format!("challenge body write failed: {err}")))?;
    stream
        .flush()
        .await
        .map_err(|err| AppError::unavailable(format!("challenge flush failed: {err}")))?;

    let (status_code, resp_body) = read_bounded_http_response(stream).await?;
    if status_code != 200 {
        return Err(map_http_status_error(status_code, &resp_body));
    }
    parse_challenge_response_json(&resp_body)
}

fn encode_challenge_request_json(
    node_pubkey: PublicKey,
    disco_pubkey: PublicKey,
    agent_version: &str,
) -> Vec<u8> {
    let escaped_agent = escape_json_string(agent_version);
    format!(
        "{{\"node_pubkey\":\"{node_pubkey}\",\"disco_pubkey\":\"{disco_pubkey}\",\
         \"protocol_version\":1,\"agent_version\":\"{escaped_agent}\",\
         \"os\":\"{}\",\"arch\":\"{}\"}}",
        current_target_os_str(),
        current_target_arch_str(),
    )
    .into_bytes()
}

fn escape_json_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[derive(Default)]
struct ChallengeResponseBuilder {
    challenge_id: Option<NodeId>,
    server_eph_pubkey: Option<PublicKey>,
    challenge_nonce: Option<String>,
    server_time_at_ms: Option<u64>,
    expires_at_ms: Option<u64>,
}

impl ChallengeResponseBuilder {
    fn assign_field(&mut self, key: &str, cursor: &mut JsonCursor<'_>) -> AppResult<()> {
        match key {
            "challenge_id" => {
                if self.challenge_id.is_some() {
                    return Err(AppError::unavailable("duplicate challenge_id JSON field"));
                }
                let raw = cursor.parse_string()?;
                let id = raw.parse::<NodeId>().map_err(|err| {
                    AppError::unavailable(format!("invalid challenge_id UUID: {err}"))
                })?;
                self.challenge_id = Some(id);
            }
            "server_eph_pubkey" => {
                if self.server_eph_pubkey.is_some() {
                    return Err(AppError::unavailable(
                        "duplicate server_eph_pubkey JSON field",
                    ));
                }
                let raw = cursor.parse_string()?;
                let pk = PublicKey::parse(&raw).map_err(|err| {
                    AppError::unavailable(format!("invalid server_eph_pubkey in challenge: {err}"))
                })?;
                self.server_eph_pubkey = Some(pk);
            }
            "challenge_nonce" => {
                if self.challenge_nonce.is_some() {
                    return Err(AppError::unavailable(
                        "duplicate challenge_nonce JSON field",
                    ));
                }
                self.challenge_nonce = Some(cursor.parse_string()?);
            }
            "server_time_at_ms" => {
                if self.server_time_at_ms.is_some() {
                    return Err(AppError::unavailable(
                        "duplicate server_time_at_ms JSON field",
                    ));
                }
                self.server_time_at_ms = Some(cursor.parse_u64()?);
            }
            "expires_at_ms" => {
                if self.expires_at_ms.is_some() {
                    return Err(AppError::unavailable("duplicate expires_at_ms JSON field"));
                }
                self.expires_at_ms = Some(cursor.parse_u64()?);
            }
            _ => {
                return Err(AppError::unavailable(format!(
                    "unexpected JSON field '{key}' in challenge response"
                )));
            }
        }
        Ok(())
    }

    fn build(self) -> AppResult<ChallengeResponse> {
        Ok(ChallengeResponse {
            challenge_id: self
                .challenge_id
                .ok_or_else(|| AppError::unavailable("missing JSON field 'challenge_id'"))?,
            server_eph_pubkey: self
                .server_eph_pubkey
                .ok_or_else(|| AppError::unavailable("missing JSON field 'server_eph_pubkey'"))?,
            challenge_nonce: self
                .challenge_nonce
                .ok_or_else(|| AppError::unavailable("missing JSON field 'challenge_nonce'"))?,
            server_time_at_ms: self
                .server_time_at_ms
                .ok_or_else(|| AppError::unavailable("missing JSON field 'server_time_at_ms'"))?,
            expires_at_ms: self
                .expires_at_ms
                .ok_or_else(|| AppError::unavailable("missing JSON field 'expires_at_ms'"))?,
        })
    }
}

struct JsonCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos)
            && matches!(b, b' ' | b'\t' | b'\r' | b'\n')
        {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect_byte(&mut self, expected: u8) -> AppResult<()> {
        self.skip_ws();
        if self.peek() != Some(expected) {
            return Err(AppError::unavailable(format!(
                "malformed challenge JSON: expected '{}'",
                char::from(expected)
            )));
        }
        self.pos = self.pos.saturating_add(1);
        Ok(())
    }

    fn parse_string(&mut self) -> AppResult<String> {
        self.expect_byte(b'"')?;
        let mut out = String::new();
        while let Some(&byte) = self.bytes.get(self.pos) {
            self.pos = self.pos.saturating_add(1);
            match byte {
                b'"' => return Ok(out),
                b'\\' => out.push(self.parse_escape()?),
                b if b < 0x20 => {
                    return Err(AppError::unavailable(
                        "unescaped control byte inside JSON string",
                    ));
                }
                b if b.is_ascii() => out.push(char::from(b)),
                _ => {
                    let start = self.pos.saturating_sub(1);
                    let rest = self.bytes.get(start..).unwrap_or_default();
                    let text = std::str::from_utf8(rest)
                        .map_err(|_| AppError::unavailable("invalid UTF-8 inside JSON string"))?;
                    let ch = text
                        .chars()
                        .next()
                        .ok_or_else(|| AppError::unavailable("invalid UTF-8 inside JSON string"))?;
                    out.push(ch);
                    self.pos = start.saturating_add(ch.len_utf8());
                }
            }
        }
        Err(AppError::unavailable("unterminated JSON string literal"))
    }

    fn parse_escape(&mut self) -> AppResult<char> {
        let esc = self
            .peek()
            .ok_or_else(|| AppError::unavailable("unterminated JSON escape"))?;
        self.pos = self.pos.saturating_add(1);
        match esc {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000C}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.parse_unicode_escape(),
            _ => Err(AppError::unavailable("invalid JSON escape sequence")),
        }
    }

    fn parse_unicode_escape(&mut self) -> AppResult<char> {
        let code = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if self.bytes.get(self.pos..self.pos.saturating_add(2)) != Some(b"\\u") {
                return Err(AppError::unavailable("unpaired JSON high surrogate"));
            }
            self.pos = self.pos.saturating_add(2);
            let low = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(AppError::unavailable("invalid JSON low surrogate"));
            }
            let combined =
                0x1_0000 + ((u32::from(code) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
            return char::from_u32(combined)
                .ok_or_else(|| AppError::unavailable("invalid Unicode scalar from JSON"));
        }
        char::from_u32(u32::from(code))
            .ok_or_else(|| AppError::unavailable("invalid BMP code point in JSON"))
    }

    fn read_hex4(&mut self) -> AppResult<u16> {
        let end = self.pos.saturating_add(4);
        let hex = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| AppError::unavailable("truncated \\uXXXX escape in JSON"))?;
        self.pos = end;
        let hex_str = std::str::from_utf8(hex)
            .map_err(|_| AppError::unavailable("invalid hex escape in JSON"))?;
        u16::from_str_radix(hex_str, 16)
            .map_err(|_| AppError::unavailable("invalid hex digits in \\uXXXX escape"))
    }

    fn parse_u64(&mut self) -> AppResult<u64> {
        self.skip_ws();
        let start = self.pos;
        while let Some(b) = self.peek()
            && b.is_ascii_digit()
        {
            self.pos = self.pos.saturating_add(1);
        }
        let digits = self
            .bytes
            .get(start..self.pos)
            .filter(|slice| !slice.is_empty())
            .ok_or_else(|| AppError::unavailable("expected unsigned integer in challenge JSON"))?;
        if digits.len() > 1 && digits.first().copied() == Some(b'0') {
            return Err(AppError::unavailable(
                "leading zeros forbidden in JSON integer",
            ));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(AppError::unavailable(
                "non-integer number forbidden for u64 JSON field",
            ));
        }
        let raw = std::str::from_utf8(digits)
            .map_err(|_| AppError::unavailable("non-UTF8 digits in challenge JSON"))?;
        raw.parse::<u64>()
            .map_err(|_| AppError::unavailable("u64 overflow in challenge JSON"))
    }
}

fn parse_challenge_response_json(body: &[u8]) -> AppResult<ChallengeResponse> {
    let text = std::str::from_utf8(body)
        .map_err(|_| AppError::unavailable("non-UTF8 challenge JSON response"))?;
    let mut cursor = JsonCursor::new(text.as_bytes());
    let mut builder = ChallengeResponseBuilder::default();

    cursor.expect_byte(b'{')?;
    cursor.skip_ws();
    if cursor.peek() == Some(b'}') {
        cursor.pos = cursor.pos.saturating_add(1);
    } else {
        loop {
            let key = cursor.parse_string()?;
            cursor.expect_byte(b':')?;
            builder.assign_field(&key, &mut cursor)?;
            cursor.skip_ws();
            match cursor.peek() {
                Some(b',') => cursor.pos = cursor.pos.saturating_add(1),
                Some(b'}') => {
                    cursor.pos = cursor.pos.saturating_add(1);
                    break;
                }
                _ => {
                    return Err(AppError::unavailable(
                        "malformed JSON object separator in challenge response",
                    ));
                }
            }
        }
    }
    cursor.skip_ws();
    if cursor.pos != cursor.bytes.len() {
        return Err(AppError::unavailable(
            "unexpected trailing tokens after challenge JSON object",
        ));
    }
    builder.build()
}

async fn read_bounded_http_response(stream: &mut dyn RelayIoStream) -> AppResult<(u16, Vec<u8>)> {
    let (buf, header_end) = read_http_headers(stream).await?;
    let header_bytes = buf
        .get(..header_end)
        .ok_or_else(|| AppError::internal("http header bounds mismatch"))?;
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| AppError::unavailable("non-UTF8 challenge HTTP response header"))?;

    let status_code = parse_http_status(header_str)?;
    let initial = buf.get(header_end.saturating_add(4)..).unwrap_or_default();
    let body = if is_chunked_transfer_encoding(header_str) {
        read_chunked_body(stream, initial).await?
    } else {
        let content_len = parse_content_length(header_str)?;
        if content_len > MAX_CHALLENGE_HTTP_RESPONSE_BYTES {
            return Err(AppError::unavailable(
                "challenge HTTP response body too large",
            ));
        }
        read_content_length_body(stream, initial, content_len).await?
    };
    Ok((status_code, body))
}

async fn read_http_headers(stream: &mut dyn RelayIoStream) -> AppResult<(Vec<u8>, usize)> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];

    let header_end = loop {
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() >= MAX_CHALLENGE_HTTP_RESPONSE_BYTES {
            return Err(AppError::unavailable(
                "challenge HTTP header exceeded 16 KiB limit",
            ));
        }
        let n = tokio::time::timeout(
            Duration::from_millis(CONNECT_TIMEOUT_MS),
            stream.read(&mut tmp),
        )
        .await
        .map_err(|_| AppError::unavailable("timed out reading challenge HTTP response"))?
        .map_err(|err| {
            AppError::unavailable(format!("failed reading challenge response: {err}"))
        })?;
        if n == 0 {
            return Err(AppError::unavailable(
                "unexpected EOF during HTTP challenge",
            ));
        }
        if let Some(slice) = tmp.get(..n) {
            buf.extend_from_slice(slice);
        }
    };
    Ok((buf, header_end))
}

async fn read_content_length_body(
    stream: &mut dyn RelayIoStream,
    initial: &[u8],
    content_len: usize,
) -> AppResult<Vec<u8>> {
    let mut tmp = [0u8; 1024];
    let mut body = initial.to_vec();
    while body.len() < content_len {
        let n = tokio::time::timeout(
            Duration::from_millis(CONNECT_TIMEOUT_MS),
            stream.read(&mut tmp),
        )
        .await
        .map_err(|_| AppError::unavailable("timed out reading challenge HTTP body"))?
        .map_err(|err| AppError::unavailable(format!("failed reading challenge body: {err}")))?;
        if n == 0 {
            return Err(AppError::unavailable("truncated HTTP challenge body"));
        }
        if let Some(slice) = tmp.get(..n) {
            body.extend_from_slice(slice);
        }
    }
    body.truncate(content_len);
    Ok(body)
}

async fn read_http_chunk_more(
    stream: &mut dyn RelayIoStream,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> AppResult<()> {
    if buf.len() >= MAX_CHALLENGE_HTTP_RESPONSE_BYTES.saturating_mul(2) {
        return Err(AppError::unavailable(
            "chunked HTTP buffer exceeded bounded limit",
        ));
    }
    let n = tokio::time::timeout(Duration::from_millis(CONNECT_TIMEOUT_MS), stream.read(tmp))
        .await
        .map_err(|_| AppError::unavailable("timed out reading chunked HTTP challenge body"))?
        .map_err(|err| AppError::unavailable(format!("failed reading chunked HTTP body: {err}")))?;
    if n == 0 {
        return Err(AppError::unavailable(
            "unexpected EOF in chunked HTTP challenge body",
        ));
    }
    if let Some(slice) = tmp.get(..n) {
        buf.extend_from_slice(slice);
    }
    Ok(())
}

async fn read_chunk_size_line(
    stream: &mut dyn RelayIoStream,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> AppResult<usize> {
    let crlf_pos = loop {
        if let Some(pos) = find_crlf(buf) {
            break pos;
        }
        read_http_chunk_more(stream, buf, tmp).await?;
    };
    let line_bytes = buf
        .get(..crlf_pos)
        .ok_or_else(|| AppError::internal("chunk size line bounds mismatch"))?;
    let line_str = std::str::from_utf8(line_bytes)
        .map_err(|_| AppError::unavailable("non-UTF8 HTTP chunk size line"))?;
    let hex_part = line_str.split(';').next().unwrap_or_default().trim();
    if hex_part.is_empty() {
        return Err(AppError::unavailable("empty HTTP chunk size"));
    }
    let size = usize::from_str_radix(hex_part, 16)
        .map_err(|_| AppError::unavailable("invalid hexadecimal HTTP chunk size"))?;
    buf.drain(..crlf_pos.saturating_add(2));
    Ok(size)
}

async fn drain_chunk_trailers(
    stream: &mut dyn RelayIoStream,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> AppResult<()> {
    loop {
        while buf.len() < 2 {
            read_http_chunk_more(stream, buf, tmp).await?;
        }
        if buf.starts_with(b"\r\n") {
            return Ok(());
        }
        if find_double_crlf(buf).is_some() {
            return Ok(());
        }
        read_http_chunk_more(stream, buf, tmp).await?;
    }
}

async fn read_chunked_body(stream: &mut dyn RelayIoStream, initial: &[u8]) -> AppResult<Vec<u8>> {
    let mut buf = initial.to_vec();
    let mut body = Vec::new();
    let mut tmp = [0u8; 1024];

    loop {
        let chunk_size = read_chunk_size_line(stream, &mut buf, &mut tmp).await?;
        if chunk_size == 0 {
            drain_chunk_trailers(stream, &mut buf, &mut tmp).await?;
            return Ok(body);
        }
        let next_total = body.len().saturating_add(chunk_size);
        if next_total > MAX_CHALLENGE_HTTP_RESPONSE_BYTES {
            return Err(AppError::unavailable(
                "chunked challenge HTTP response body too large",
            ));
        }
        let needed = chunk_size.saturating_add(2);
        while buf.len() < needed {
            read_http_chunk_more(stream, &mut buf, &mut tmp).await?;
        }
        if buf.get(chunk_size..needed) != Some(b"\r\n") {
            return Err(AppError::unavailable("malformed HTTP chunk terminator"));
        }
        if let Some(chunk_bytes) = buf.get(..chunk_size) {
            body.extend_from_slice(chunk_bytes);
        }
        buf.drain(..needed);
    }
}

async fn perform_ws_handshake(
    stream: Box<dyn RelayIoStream>,
    endpoint: &str,
    headers: &[(String, String)],
) -> AppResult<WebSocket<BridgeStream>> {
    let uri = format!("wss://{endpoint}{WS_PATH_RELAY}");
    let mut req = uri
        .into_client_request()
        .map_err(|err| AppError::invalid_argument(format!("invalid relay URI: {err}")))?;

    for (name, val) in headers {
        let hdr_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| AppError::invalid_argument(format!("invalid header name: {err}")))?;
        let hdr_val = HeaderValue::from_str(val)
            .map_err(|err| AppError::invalid_argument(format!("invalid header val: {err}")))?;
        req.headers_mut().insert(hdr_name, hdr_val);
    }

    let mut ws_cfg = WebSocketConfig::default();
    ws_cfg.max_message_size = Some(MAX_FRAME_SIZE);
    ws_cfg.max_frame_size = Some(MAX_FRAME_SIZE);

    let bridge = BridgeStream::new(stream);
    let mut handshake = ClientHandshake::start(bridge, req, Some(ws_cfg))
        .map_err(|err| AppError::unavailable(format!("relay ws handshake init failed: {err}")))?;

    let mut scratch = [0u8; 2048];
    loop {
        handshake
            .get_mut()
            .get_mut()
            .flush_tx_async()
            .await
            .map_err(|err| {
                AppError::unavailable(format!("relay ws handshake write failed: {err}"))
            })?;
        match handshake.handshake() {
            Ok((mut ws, _resp)) => {
                ws.get_mut().flush_tx_async().await.map_err(|err| {
                    AppError::unavailable(format!("relay ws handshake tail flush failed: {err}"))
                })?;
                return Ok(ws);
            }
            Err(HandshakeError::Interrupted(mut mid)) => {
                mid.get_mut()
                    .get_mut()
                    .flush_tx_async()
                    .await
                    .map_err(|err| {
                        AppError::unavailable(format!("relay ws handshake flush failed: {err}"))
                    })?;
                let n = tokio::time::timeout(
                    Duration::from_millis(CONNECT_TIMEOUT_MS),
                    mid.get_mut().get_mut().async_stream.read(&mut scratch),
                )
                .await
                .map_err(|_| AppError::unavailable("relay ws upgrade response timed out"))?
                .map_err(|err| AppError::unavailable(format!("relay ws upgrade io: {err}")))?;
                if n == 0 {
                    return Err(AppError::unavailable(
                        "relay closed during WebSocket upgrade",
                    ));
                }
                if let Some(bytes) = scratch.get(..n) {
                    mid.get_mut().get_mut().push_rx(bytes);
                }
                handshake = mid;
            }
            Err(HandshakeError::Failure(err)) => {
                return Err(map_ws_handshake_failure(err));
            }
        }
    }
}

async fn send_relay_frame(ws: &mut WebSocket<BridgeStream>, frame: &RelayFrame) -> AppResult<()> {
    let encoded = frame.encode()?;
    ws.send(Message::Binary(encoded))
        .map_err(|err| AppError::unavailable(format!("relay ws send failed: {err}")))?;
    ws.get_mut()
        .flush_tx_async()
        .await
        .map_err(|err| AppError::unavailable(format!("relay ws flush failed: {err}")))
}

async fn close_ws_gracefully(ws: &mut WebSocket<BridgeStream>) {
    if let Err(err) = ws.close(None) {
        debug!(component = "datapath.relay_client", error = %err, "ws close frame skipped");
    }
    if let Err(err) =
        tokio::time::timeout(Duration::from_millis(500), ws.get_mut().flush_tx_async()).await
    {
        debug!(component = "datapath.relay_client", error = %err, "ws close flush timed out");
    }
}

async fn flush_ignored(bridge: &mut BridgeStream) {
    if let Err(err) = bridge.flush_tx_async().await {
        debug!(component = "datapath.relay_client", error = %err, "best-effort relay flush failed");
    }
}

async fn emit_relay_event(events_tx: &mpsc::Sender<RelayEvent>, event: RelayEvent) {
    if events_tx.send(event).await.is_err() {
        debug!(
            component = "datapath.relay_client",
            "relay event receiver closed"
        );
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn is_chunked_transfer_encoding(header: &str) -> bool {
    for line in header.lines() {
        if let Some((name, val)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("transfer-encoding")
            && val
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
        {
            return true;
        }
    }
    false
}

fn parse_http_status(header: &str) -> AppResult<u16> {
    let first_line = header
        .lines()
        .next()
        .ok_or_else(|| AppError::unavailable("empty HTTP response"))?;
    let code_str = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| AppError::unavailable("malformed HTTP status line"))?;
    code_str
        .parse::<u16>()
        .map_err(|_| AppError::unavailable("invalid HTTP status code"))
}

fn parse_content_length(header: &str) -> AppResult<usize> {
    let mut parsed: Option<usize> = None;
    for line in header.lines() {
        if let Some((name, val)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            let value = val
                .trim()
                .parse::<usize>()
                .map_err(|_| AppError::unavailable("invalid Content-Length header"))?;
            if let Some(prev) = parsed
                && prev != value
            {
                return Err(AppError::unavailable("conflicting Content-Length headers"));
            }
            parsed = Some(value);
        }
    }
    Ok(parsed.unwrap_or(0))
}

fn map_http_status_error(status: u16, body: &[u8]) -> AppError {
    let text = String::from_utf8_lossy(body);
    if status == 403 {
        if text.contains("E_NODE_REVOKED") || text.contains("node_revoked") {
            return AppError::node_revoked("server rejected node as revoked");
        }
        if text.contains("E_KEY_EXPIRED") || text.contains("node_key_expired") {
            return AppError::node_key_expired("server rejected node with expired key");
        }
    }
    if status == 401 {
        return AppError::unauthenticated("relay challenge authentication failed");
    }
    AppError::unavailable(format!("relay HTTP auth returned status {status}"))
}

fn map_ws_handshake_failure(err: WsError) -> AppError {
    if let WsError::Http(resp) = &err {
        let body_bytes = resp.body().as_deref().unwrap_or_default();
        return map_http_status_error(resp.status().as_u16(), body_bytes);
    }
    AppError::unavailable(format!("relay WebSocket handshake failed: {err}"))
}

fn split_host_port(endpoint: &str) -> AppResult<(&str, u16)> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, port_part) = rest
            .split_once("]:")
            .ok_or_else(|| AppError::invalid_argument("invalid IPv6 relay endpoint syntax"))?;
        let port = port_part
            .parse::<u16>()
            .map_err(|_| AppError::invalid_argument("invalid IPv6 relay port"))?;
        return Ok((host, port));
    }
    let (host, port_str) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| AppError::invalid_argument("relay endpoint must include :<port>"))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| AppError::invalid_argument("invalid relay endpoint port"))?;
    Ok((host, port))
}

fn current_target_os_str() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "darwin"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "linux"
    }
}

fn current_target_arch_str() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        "amd64"
    }
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    for chunk in input.chunks(3) {
        let b0 = usize::from(*chunk.first().unwrap_or(&0));
        let b1 = usize::from(*chunk.get(1).unwrap_or(&0));
        let b2 = usize::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(*TABLE.get((n >> 18) & 0x3f).unwrap_or(&b'A')));
        out.push(char::from(*TABLE.get((n >> 12) & 0x3f).unwrap_or(&b'A')));
        let c2 = if chunk.len() > 1 {
            *TABLE.get((n >> 6) & 0x3f).unwrap_or(&b'A')
        } else {
            b'='
        };
        let c3 = if chunk.len() > 2 {
            *TABLE.get(n & 0x3f).unwrap_or(&b'A')
        } else {
            b'='
        };
        out.push(char::from(c2));
        out.push(char::from(c3));
    }
    out
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::accept;

    use mesh_core::clock::FakeClock;

    use super::*;

    struct PlainTcpConnector {
        addr: SocketAddr,
    }

    impl RelayConnector for PlainTcpConnector {
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

    // Traces: US-025 AC6
    #[test]
    fn test_relay_handle_per_destination_bounded_queue_drops_tail_without_hol_blocking() {
        // Arrange
        let handle = RelayClientHandle::new();
        let peer_a = PublicKey::from_bytes([1u8; 32]).expect("pk a");
        let peer_b = PublicKey::from_bytes([2u8; 32]).expect("pk b");

        // Act: saturate peer A's 256-slot queue + 5 overflow packets
        for idx in 0..(RELAY_QUEUE_CAPACITY + 5) {
            let fill = u8::try_from(idx % 251).unwrap_or(0);
            let sent = handle.try_send_packet(peer_a, Bytes::from(vec![fill; 16]));
            if idx < RELAY_QUEUE_CAPACITY {
                assert!(sent);
            } else {
                assert!(!sent);
            }
        }

        // Assert: Peer B still enqueues immediately with ZERO HoL blocking!
        assert!(handle.try_send_packet(peer_b, Bytes::from_static(b"unblocked-peer-b")));
        assert_eq!(handle.metrics_snapshot().dropped_tail_packets, 5);
    }

    async fn spawn_mock_ws_relay_server(
        listener: TcpListener,
        peer_pk: PublicKey,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.expect("accept client");
            let std_stream = tcp_stream.into_std().expect("to std");
            std_stream
                .set_nonblocking(false)
                .expect("blocking for mock");

            tokio::task::spawn_blocking(move || {
                let mut ws = accept(std_stream).expect("ws handshake");
                let msg = ws.read().expect("read frame");
                let raw = match msg {
                    Message::Binary(raw) => raw,
                    other => unreachable_ws_msg(other),
                };
                let decoded = RelayFrame::decode(&raw).expect("valid relay frame");
                assert!(matches!(
                    decoded,
                    RelayFrame::ClientToPeerPacket { dst_pubkey, .. } if dst_pubkey == peer_pk
                ));

                let reply = RelayFrame::RelayToClientPacket {
                    src_pubkey: peer_pk,
                    ciphertext: Bytes::from_static(b"mock-ciphertext-from-peer"),
                };
                ws.send(Message::Binary(reply.encode().expect("encode reply")))
                    .expect("send reply");

                let revoke = RelayFrame::ControlNotice {
                    code: RelayNoticeCode::NodeRevoked,
                };
                ws.send(Message::Binary(revoke.encode().expect("encode revoke")))
                    .expect("send revoke");
                if ws.close(None).is_ok() {
                    while ws.read().is_ok() {}
                }
            })
            .await
            .expect("mock blocking task");
        })
    }

    fn unreachable_ws_msg(other: Message) -> bytes::Bytes {
        assert!(
            other.is_binary(),
            "expected binary relay frame, got {other:?}"
        );
        bytes::Bytes::new()
    }

    // Traces: US-025, US-034 AC5
    #[tokio::test]
    async fn test_relay_client_forwards_binary_frames_and_stops_on_node_revoked_notice() {
        // Arrange: spin up a mock WebSocket Relay server on loopback TCP
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock ws");
        let addr = listener.local_addr().expect("local addr");
        let peer_pk = PublicKey::from_bytes([9u8; 32]).expect("peer pk");
        let server_task = spawn_mock_ws_relay_server(listener, peer_pk).await;

        let cfg = RelayClientConfig {
            endpoint: addr.to_string(),
            server_name_override: None,
            pin_set: None,
            underlay_if_index: None,
            linux_fwmark: None,
            require_challenge_auth: false,
            agent_version: "0.1.0-test".to_owned(),
        };
        let client = RelayClient::with_connector(
            cfg,
            NodeKeypair::generate(),
            DiscoKeypair::generate(),
            Arc::new(PlainTcpConnector { addr }),
        );
        let handle = client.handle();
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(50_000));
        let (ev_tx, mut ev_rx) = mpsc::channel(32);
        let shutdown = CancellationToken::new();
        let run_task = tokio::spawn(client.run(clock, ev_tx, shutdown.clone()));

        assert!(handle.try_send_packet(peer_pk, Bytes::from_static(b"outbound-via-relay")));
        let mut flags = (false, false, false);
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(3), ev_rx.recv()).await {
            match ev {
                RelayEvent::StateChanged(RelayConnectionState::Connected) => flags.0 = true,
                RelayEvent::PacketReceived {
                    src_pubkey,
                    ciphertext,
                } => {
                    assert_eq!(src_pubkey, peer_pk);
                    assert_eq!(ciphertext.as_ref(), b"mock-ciphertext-from-peer");
                    flags.1 = true;
                }
                RelayEvent::StateChanged(RelayConnectionState::Terminated(
                    ErrorKind::NodeRevoked,
                )) => {
                    flags.2 = true;
                    break;
                }
                _ => {}
            }
        }

        shutdown.cancel();
        server_task.await.expect("server ok");
        run_task.await.expect("client stopped");

        // Assert
        assert!(flags.0);
        assert!(flags.1);
        assert!(flags.2);
    }

    // Traces: US-025, SEC-04
    #[test]
    fn test_challenge_json_serialization_and_response_parsing() {
        // Arrange
        let kp = NodeKeypair::generate();
        let dk = DiscoKeypair::generate();
        let cid = NodeId::from_bytes([0xABu8; 16]);
        let req_bytes = encode_challenge_request_json(
            kp.public_key(),
            dk.public_key(),
            "0.1.0-\"quoted\"\\dev",
        );
        let req_text = String::from_utf8(req_bytes).expect("utf8 json");
        let resp_json = format!(
            "{{\"challenge_id\":\"{cid}\",\"server_eph_pubkey\":\"{}\",\
             \"challenge_nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\
             \"server_time_at_ms\":1700000000000,\"expires_at_ms\":1700000060000}}",
            dk.public_key()
        );

        // Act
        let parsed = parse_challenge_response_json(resp_json.as_bytes()).expect("valid resp");

        // Assert
        assert!(req_text.contains("\"protocol_version\":1"));
        assert!(req_text.contains("\\\"quoted\\\"\\\\dev"));
        assert_eq!(parsed.challenge_id, cid);
        assert_eq!(parsed.server_eph_pubkey, dk.public_key());
        assert_eq!(parsed.server_time_at_ms, 1_700_000_000_000);
        assert_eq!(parsed.expires_at_ms, 1_700_000_060_000);
        assert!(parse_challenge_response_json(b"{}").is_err());

        // Strict JSON edge checks: escapes succeed; unknown/duplicate/trailing fail
        let escaped_json = format!(
            "{{\"challenge_id\":\"{cid}\",\"server_eph_pubkey\":\"{}\",\
             \"challenge_nonce\":\"nonce\\u002B\\\"val\\\"\",\
             \"server_time_at_ms\":42,\"expires_at_ms\":84}}",
            dk.public_key()
        );
        let parsed_escaped =
            parse_challenge_response_json(escaped_json.as_bytes()).expect("escaped ok");
        assert_eq!(parsed_escaped.challenge_nonce, "nonce+\"val\"");

        let unknown_field = format!(
            "{{\"challenge_id\":\"{cid}\",\"server_eph_pubkey\":\"{}\",\
             \"challenge_nonce\":\"AA==\",\"server_time_at_ms\":1,\
             \"expires_at_ms\":2,\"extra\":9}}",
            dk.public_key()
        );
        assert!(parse_challenge_response_json(unknown_field.as_bytes()).is_err());
        assert!(parse_challenge_response_json(format!("{resp_json} trailing").as_bytes()).is_err());
    }

    // Traces: US-025 AC6, HR-S1-07
    #[tokio::test]
    async fn test_relay_client_drains_150_packet_burst_under_500ms() {
        // Arrange
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let peer_pk = PublicKey::from_bytes([0x44u8; 32]).expect("peer pk");
        let total_packets: usize = 150;

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let std_tcp = tcp.into_std().expect("std");
            std_tcp.set_nonblocking(false).expect("blocking");
            tokio::task::spawn_blocking(move || {
                let mut ws = accept(std_tcp).expect("ws accept");
                let mut received = 0usize;
                while received < total_packets {
                    let msg = ws.read().expect("ws read");
                    if let Message::Binary(raw) = msg
                        && matches!(
                            RelayFrame::decode(&raw),
                            Ok(RelayFrame::ClientToPeerPacket { .. })
                        )
                    {
                        received = received.saturating_add(1);
                    }
                }
                drop(ws.close(None));
                received
            })
            .await
            .expect("blocking join")
        });

        let cfg = RelayClientConfig {
            endpoint: addr.to_string(),
            server_name_override: None,
            pin_set: None,
            underlay_if_index: None,
            linux_fwmark: None,
            require_challenge_auth: false,
            agent_version: "0.1.0-burst".to_owned(),
        };
        let client = RelayClient::with_connector(
            cfg,
            NodeKeypair::generate(),
            DiscoKeypair::generate(),
            Arc::new(PlainTcpConnector { addr }),
        );
        let handle = client.handle();
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(60_000));
        let (ev_tx, mut ev_rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let client_task = tokio::spawn(client.run(clock, ev_tx, shutdown.clone()));

        // Wait for Connected before blasting 150-frame burst
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(2), ev_rx.recv()).await {
            if matches!(
                ev,
                RelayEvent::StateChanged(RelayConnectionState::Connected)
            ) {
                break;
            }
        }

        // Act: send burst of 150 packets (> 64) and assert complete delivery in < 500 ms
        let started = std::time::Instant::now();
        for seq in 0..total_packets {
            let mut payload = vec![0xAAu8; 32];
            if let Some(first) = payload.first_mut() {
                *first = u8::try_from(seq % 251).unwrap_or(0);
            }
            assert!(handle.try_send_packet(peer_pk, Bytes::from(payload)));
        }

        let got = tokio::time::timeout(Duration::from_millis(500), server_task)
            .await
            .expect("server received 150-packet burst in < 500 ms")
            .expect("server ok");
        let elapsed = started.elapsed();

        shutdown.cancel();
        drop(client_task.await);

        // Assert
        assert_eq!(got, total_packets);
        assert_eq!(handle.metrics_snapshot().tx_packets, 150);
        assert!(
            elapsed < Duration::from_millis(500),
            "burst flush took {elapsed:?}"
        );
    }

    struct ScriptedBackoffConnector {
        call_index: AtomicU64,
        ws_addr: SocketAddr,
    }

    impl RelayConnector for ScriptedBackoffConnector {
        fn connect<'a>(
            &'a self,
            _config: &'a RelayClientConfig,
        ) -> Pin<Box<dyn Future<Output = AppResult<ConnectedRelayTransport>> + Send + 'a>> {
            let idx = self.call_index.fetch_add(1, Ordering::Relaxed);
            let addr = self.ws_addr;
            Box::pin(async move {
                match idx {
                    0 | 3 | 6 | 9 => Err(AppError::pin_mismatch("test pin mismatch")),
                    1 | 4 | 7 | 10 => Err(AppError::clock_skew("test clock skew")),
                    2 | 5 | 8 | 12 => Err(AppError::unavailable(
                        "TLS certificate rejected: UnknownIssuer",
                    )),
                    11 => {
                        let stream = TcpStream::connect(addr)
                            .await
                            .map_err(|e| AppError::unavailable(format!("ws connect: {e}")))?;
                        Ok(ConnectedRelayTransport {
                            stream: Box::new(stream),
                            tls_exporter_binding: None,
                        })
                    }
                    _ => Err(AppError::unavailable("relay tcp connect failed")),
                }
            })
        }
    }

    // Traces: US-034, HR-S1-07
    #[tokio::test]
    async fn test_relay_tls_backoff_accumulates_across_consecutive_errors_and_resets_after_connect()
    {
        // Arrange: server accepts once on call 11 and closes immediately to force next reconnect
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let ws_addr = listener.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let std_tcp = tcp.into_std().expect("std");
            std_tcp.set_nonblocking(false).expect("blocking");
            drop(
                tokio::task::spawn_blocking(move || {
                    let mut ws = accept(std_tcp).expect("ws accept");
                    drop(ws.close(None));
                })
                .await,
            );
        });

        let cfg = RelayClientConfig {
            endpoint: ws_addr.to_string(),
            server_name_override: None,
            pin_set: None,
            underlay_if_index: None,
            linux_fwmark: None,
            require_challenge_auth: false,
            agent_version: "0.1.0-backoff".to_owned(),
        };
        let connector = Arc::new(ScriptedBackoffConnector {
            call_index: AtomicU64::new(0),
            ws_addr,
        });
        let client = RelayClient::with_connector(
            cfg,
            NodeKeypair::generate(),
            DiscoKeypair::generate(),
            connector,
        );
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(70_000));
        let (ev_tx, mut ev_rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let recorded = Arc::new(Mutex::new(Vec::<ReconnectStep>::new()));
        let recorded_clone = Arc::clone(&recorded);
        let shutdown_clone = shutdown.clone();

        // Act
        client
            .run_with_sleeper(&clock, &ev_tx, &shutdown, move |step| {
                let mut guard = recorded_clone.lock().expect("lock");
                guard.push(step);
                if guard.len() >= 14 {
                    shutdown_clone.cancel();
                }
                std::future::ready(())
            })
            .await;

        server_task.await.expect("server ok");
        while ev_rx.try_recv().is_ok() {}

        // Assert: first 11 failures accumulate TLS backoff (1s..=300s), call 11 succeeds and resets,
        // call 12 starts fresh at attempt 0 TLS, call 13 routes plain TCP failure to network backoff
        let steps = recorded.lock().expect("lock");
        assert_eq!(steps.len(), 14);
        let expected_tls_ceilings = [
            1_000u64, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 300_000,
            300_000,
        ];
        for (idx, &expected_ceil) in expected_tls_ceilings.iter().enumerate() {
            let st = steps.get(idx).expect("tls step");
            assert!(st.tls_capped, "step {idx} should use tls_backoff");
            assert_eq!(usize::try_from(st.attempt).unwrap_or(99), idx);
            assert_eq!(st.ceiling_ms, expected_ceil);
        }
        // Step 11 (index 11) corresponds to post-Connected disconnect -> network attempt 0 (reset!)
        let post_connect = steps.get(11).expect("post connect");
        assert!(!post_connect.tls_capped);
        assert_eq!(post_connect.attempt, 0);
        // Step 12 (index 12) corresponds to TLS Untrusted rejection -> TLS attempt 0 (was reset!)
        let reset_tls = steps.get(12).expect("reset tls");
        assert!(reset_tls.tls_capped);
        assert_eq!(reset_tls.attempt, 0);
        assert_eq!(reset_tls.ceiling_ms, 1_000);
        // Step 13 (index 13) corresponds to plain TCP failure -> network attempt 1
        let next_net = steps.get(13).expect("next net");
        assert!(!next_net.tls_capped);
        assert_eq!(next_net.attempt, 1);
    }

    // Traces: US-024, HR-S1-07
    #[tokio::test]
    async fn test_http_challenge_chunked_transfer_encoding_and_strict_json_parsing() {
        // Arrange: HTTP proxy returning Transfer-Encoding: chunked across multiple small segments
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let dk = DiscoKeypair::generate();
        let dk_pub = dk.public_key();
        let cid = NodeId::from_bytes([0xCDu8; 16]);
        let json_body = format!(
            "{{\"challenge_id\":\"{cid}\",\"server_eph_pubkey\":\"{dk_pub}\",\
             \"challenge_nonce\":\"chunked\\u002Dnonce\",\
             \"server_time_at_ms\":1700000100000,\"expires_at_ms\":1700000160000}}"
        );

        let srv_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut req_buf = [0u8; 1024];
            let req_n = sock.read(&mut req_buf).await.expect("read req");
            assert!(req_n > 0);

            let split = json_body.len() / 2;
            let part1 = json_body.get(..split).expect("p1");
            let part2 = json_body.get(split..).expect("p2");
            let chunked = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Transfer-Encoding: chunked\r\n\r\n\
                 {:x};ext=1\r\n{part1}\r\n\
                 {:x}\r\n{part2}\r\n\
                 0\r\nX-Proxy-Trailer: done\r\n\r\n",
                part1.len(),
                part2.len()
            );
            // Send in two TCP segments to exercise streaming chunk reconstruction
            let mid = chunked.len() / 2;
            sock.write_all(chunked.get(..mid).expect("h1").as_bytes())
                .await
                .expect("w1");
            sock.flush().await.expect("f1");
            tokio::time::sleep(Duration::from_millis(10)).await;
            sock.write_all(chunked.get(mid..).expect("h2").as_bytes())
                .await
                .expect("w2");
            sock.flush().await.expect("f2");
        });

        let mut client_stream = TcpStream::connect(addr).await.expect("connect");
        let cfg = RelayClientConfig {
            endpoint: addr.to_string(),
            server_name_override: None,
            pin_set: None,
            underlay_if_index: None,
            linux_fwmark: None,
            require_challenge_auth: true,
            agent_version: "0.1.0-chunked".to_owned(),
        };
        let kp = NodeKeypair::generate();

        // Act
        let resp =
            execute_challenge_http(&mut client_stream, &cfg, kp.public_key(), dk.public_key())
                .await
                .expect("chunked challenge response must parse cleanly");
        srv_task.await.expect("server ok");

        // Assert
        assert_eq!(resp.challenge_id, cid);
        assert_eq!(resp.server_eph_pubkey, dk.public_key());
        assert_eq!(resp.challenge_nonce, "chunked-nonce");
        assert_eq!(resp.server_time_at_ms, 1_700_000_100_000);
        assert_eq!(resp.expires_at_ms, 1_700_000_160_000);
    }

    struct DynamicEndpointConnector;

    impl RelayConnector for DynamicEndpointConnector {
        fn connect<'a>(
            &'a self,
            config: &'a RelayClientConfig,
        ) -> Pin<Box<dyn Future<Output = AppResult<ConnectedRelayTransport>> + Send + 'a>> {
            let endpoint = config.endpoint.clone();
            Box::pin(async move {
                let addr: SocketAddr = endpoint
                    .parse()
                    .map_err(|e| AppError::invalid_argument(format!("bad test addr: {e}")))?;
                let stream = connect_bound_tcp_with_timeout(
                    addr,
                    config.underlay_if_index,
                    config.linux_fwmark,
                    Duration::from_secs(2),
                )
                .await?;
                Ok(ConnectedRelayTransport {
                    stream: Box::new(stream),
                    tls_exporter_binding: None,
                })
            })
        }
    }

    // Traces: HR-W12-01
    #[tokio::test]
    async fn test_relay_client_live_config_update_reconnects_to_new_endpoint() {
        // Arrange
        let listener_a = TcpListener::bind("127.0.0.1:0").await.expect("bind a");
        let addr_a = listener_a.local_addr().expect("addr a");
        let listener_b = TcpListener::bind("127.0.0.1:0").await.expect("bind b");
        let addr_b = listener_b.local_addr().expect("addr b");

        let srv_a = tokio::spawn(async move {
            let (tcp, _) = listener_a.accept().await.expect("accept a");
            let std_tcp = tcp.into_std().expect("std tcp a");
            std_tcp.set_nonblocking(false).expect("blocking a");
            let _ws = tokio::task::spawn_blocking(move || accept(std_tcp).expect("ws a"))
                .await
                .expect("join a");
            tokio::time::sleep(Duration::from_millis(400)).await;
        });
        let srv_b = tokio::spawn(async move {
            let (tcp, _) = listener_b.accept().await.expect("accept b");
            let std_tcp = tcp.into_std().expect("std tcp b");
            std_tcp.set_nonblocking(false).expect("blocking b");
            let _ws = tokio::task::spawn_blocking(move || accept(std_tcp).expect("ws b"))
                .await
                .expect("join b");
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let initial_cfg = RelayClientConfig {
            endpoint: addr_a.to_string(),
            server_name_override: None,
            pin_set: None,
            underlay_if_index: None,
            linux_fwmark: None,
            require_challenge_auth: false,
            agent_version: "0.1.0-test".to_owned(),
        };
        let updated_cfg = RelayClientConfig {
            endpoint: addr_b.to_string(),
            ..initial_cfg.clone()
        };
        let client = RelayClient::with_connector(
            initial_cfg,
            NodeKeypair::generate(),
            DiscoKeypair::generate(),
            Arc::new(DynamicEndpointConnector),
        );
        let handle = client.handle();
        let (ev_tx, mut ev_rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(1_700_000_000_000));
        let task = tokio::spawn(client.run(clock, ev_tx, shutdown.clone()));

        // Wait for initial connection to server A.
        let mut connected_count = 0usize;
        while connected_count == 0 {
            match tokio::time::timeout(Duration::from_secs(3), ev_rx.recv())
                .await
                .expect("wait connect a")
            {
                Some(RelayEvent::StateChanged(RelayConnectionState::Connected)) => {
                    connected_count += 1;
                }
                Some(_) => {}
                None => panic!("event channel closed unexpectedly"),
            }
        }

        // Act: dynamically update Relay endpoint to server B without tearing down task.
        handle.update_config(updated_cfg);

        // Assert: second Connected event arrives from switching live to server B.
        while connected_count < 2 {
            match tokio::time::timeout(Duration::from_secs(3), ev_rx.recv())
                .await
                .expect("wait connect b")
            {
                Some(RelayEvent::StateChanged(RelayConnectionState::Connected)) => {
                    connected_count += 1;
                }
                Some(_) => {}
                None => panic!("event channel closed before connecting to endpoint b"),
            }
        }

        shutdown.cancel();
        task.await.expect("relay task exits cleanly");
        srv_a.abort();
        srv_b.abort();
    }

    // Traces: HR-W12-04
    #[tokio::test]
    async fn test_connect_bound_tcp_with_timeout_respects_short_budget() {
        // Arrange: TEST-NET-1 non-routable documentation IP triggers timeout/unreachable within budget.
        let target: SocketAddr = "192.0.2.1:65432".parse().expect("valid addr");
        let started = tokio::time::Instant::now();

        // Act
        let res =
            connect_bound_tcp_with_timeout(target, None, None, Duration::from_millis(80)).await;

        // Assert
        assert!(res.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
