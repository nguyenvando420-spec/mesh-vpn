//! WP-M-C1 QA Resilience Suite for `mesh-mobile-ffi` (`US-095`).
//!
//! Covers:
//! - 10-round Wi-Fi IPv4 <-> IPv6-only NAT64 (`64:ff9b::/96` + RFC 7050 `ipv4only.arpa`) roaming,
//!   ensuring dual-stack/LAN RFC 1918 targets are never NAT64-synthesized and `overlay_ip` + `mtu`
//!   remain invariant while WireGuard Noise handshakes settle promptly.
//! - Split-DNS `.mesh.internal`: `A`, RFC 4074 NODATA (`RCODE=0, ANCOUNT=0`) for `AAAA`/`HTTPS`/`SVCB`,
//!   UDP EDNS0 `<= 1232 B` budget enforcement, L3 TCP `:53` 16 LRU slots eviction, 3 s TTL expiry,
//!   single-transaction `PSH|FIN|ACK`, `RST|ACK` on pipelined 2nd query, immediate `:853` `TCP RST|ACK`,
//!   and live `DatapathEngine` + `FakeTunDevice` TUN interception.
//! - `TimerMode::IdleAware`, `set_power_saving_mode`, `JetsamPressureController` hysteresis (`15/18 MiB`,
//!   `6/8 MiB + 10s cooldown`, `< 4 MiB` critical), `export_bugreport_to_file`, Doze clock jump (`> 30_000 ms`),
//!   Captive Portal / Clock Skew / `NodeRevoked`, and `shutdown() <= 5 s`.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use rustls::ServerConfig;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Error as WsError, Message, WebSocket};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use mesh_core::{
    Clock as _, ClockJumpDetector, FakeClock, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin,
    SystemClock,
};
use mesh_crypto::certgen::{build_rustls_server_config_from_der, generate_ip_pinned_cert};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use mesh_datapath::{
    DatapathConfig, DatapathEngine, DatapathEngineOptions, DiscoConfig, DnsInterceptDecision,
    DnsPacketInterceptor, MAGIC_SOCKET_BUFFER_SIZE, MagicSocketConfig, PacketBuffer, PeerMap,
    StunClientConfig, TimerMode,
};
use mesh_net::NoopSocketProtector;
use mesh_net::nat64::{Nat64Prefix, is_eligible_for_nat64_synthesis};
use mesh_net::tun::{FakeTunDevice, TunConfig};
use mesh_proto::control::{
    ChallengeRequest, ChallengeResponse, RegisterNodeRequest, RegisterNodeResponse,
    ServerControlFrame, TerminationReason,
};
use mesh_proto::netmap::{
    CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap,
};

use mesh_mobile_ffi::{
    JetsamPressureController, JetsamPressureStage, MobileDaemonState, MobileEngine,
    MobileEngineInitConfig, MobileEnrollConfig, MobileError, MobileNetEventKind,
    MobilePlatformKind, MobilePlatformWarning, MobileSplitDnsInterceptor, MobileStatusSnapshot,
    MobileTlsAuthMode, MobileTunnelNetworkConfig, MobileUnderlayState, MobileUpConfig,
    PlatformNetworkBridge, create_pending_join_session, mobile_enroll_or_rotate_node,
};

fn test_err(msg: impl fmt::Display) -> String {
    msg.to_string()
}

fn ensure_rustls_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        drop(rustls::crypto::ring::default_provider().install_default());
    });
}

fn make_preauth_key(seed: u8) -> String {
    format!("mpk_{}", URL_SAFE_NO_PAD.encode([seed; 32]))
}

#[derive(Debug, Clone, Copy)]
enum MockServerScenario {
    Normal,
    CaptivePortalHtml,
    CaptivePortal511,
    RevokeOnWsConnect,
}

struct WsSyncBridge {
    rx_buf: VecDeque<u8>,
    tx_buf: Vec<u8>,
}

impl WsSyncBridge {
    fn new(preloaded_rx: Vec<u8>) -> Self {
        Self {
            rx_buf: VecDeque::from(preloaded_rx),
            tx_buf: Vec::new(),
        }
    }

    fn push_rx(&mut self, data: &[u8]) {
        self.rx_buf.extend(data);
    }

    fn take_tx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.tx_buf)
    }
}

impl Read for WsSyncBridge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rx_buf.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let mut copied = 0_usize;
        for slot in buf.iter_mut() {
            let Some(byte) = self.rx_buf.pop_front() else {
                break;
            };
            *slot = byte;
            copied = copied.saturating_add(1);
        }
        Ok(copied)
    }
}

impl Write for WsSyncBridge {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    raw_head: Vec<u8>,
}

async fn read_http_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Option<ParsedHttpRequest>, String> {
    let mut raw = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos.saturating_add(4);
        }
        if raw.len() > 32 * 1024 {
            return Err("mock HTTP request head exceeded 32 KiB".to_owned());
        }
        let read_n = stream.read(&mut chunk).await.map_err(test_err)?;
        if read_n == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Err("unexpected EOF reading HTTP head".to_owned());
        }
        raw.extend_from_slice(chunk.get(..read_n).unwrap_or_default());
    };

    let head_bytes = raw.get(..header_end).unwrap_or_default().to_vec();
    let head_str = std::str::from_utf8(&head_bytes).map_err(test_err)?;
    let mut lines = head_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_owned())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_owned())?
        .to_owned();
    let path = parts
        .next()
        .ok_or_else(|| "missing HTTP path".to_owned())?
        .to_owned();

    let mut headers = BTreeMap::new();
    let mut content_len = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_owned();
            if key == "content-length" {
                content_len = val.parse::<usize>().map_err(test_err)?;
            }
            headers.insert(key, val);
        }
    }

    let mut body = raw.get(header_end..).unwrap_or_default().to_vec();
    while body.len() < content_len {
        let read_n = stream.read(&mut chunk).await.map_err(test_err)?;
        if read_n == 0 {
            return Err("unexpected EOF reading HTTP body".to_owned());
        }
        body.extend_from_slice(chunk.get(..read_n).unwrap_or_default());
    }
    body.truncate(content_len);

    Ok(Some(ParsedHttpRequest {
        method,
        path,
        headers,
        body,
        raw_head: head_bytes,
    }))
}

async fn write_http_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status_line: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let header = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(test_err)?;
    stream.write_all(body).await.map_err(test_err)?;
    stream.flush().await.map_err(test_err)?;
    Ok(())
}

fn accept_ws_server(req: &ParsedHttpRequest) -> Result<WebSocket<WsSyncBridge>, String> {
    let mut bridge = WsSyncBridge::new(req.raw_head.clone());
    let key = req
        .headers
        .get("sec-websocket-key")
        .ok_or_else(|| "missing Sec-WebSocket-Key".to_owned())?;
    let accept_val = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_val}\r\n\r\n"
    );
    bridge.tx_buf.extend_from_slice(resp.as_bytes());
    bridge.rx_buf.clear();
    Ok(WebSocket::from_raw_socket(bridge, Role::Server, None))
}

async fn flush_ws_tx<S: AsyncWrite + Unpin>(
    stream: &mut S,
    ws: &mut WebSocket<WsSyncBridge>,
) -> io::Result<()> {
    drop(ws.flush());
    let out = ws.get_mut().take_tx();
    if !out.is_empty() {
        stream.write_all(&out).await?;
        stream.flush().await?;
    }
    Ok(())
}

fn sample_snapshot(
    version: u64,
    endpoint: &str,
    spki_pin: SpkiPin,
    peers: Vec<PeerEntry>,
) -> Result<NetmapSnapshot, String> {
    let overlay_cidr: OverlayCidr = "10.100.0.0/16".parse().map_err(test_err)?;
    Ok(NetmapSnapshot {
        netmap_version: version,
        generated_at_ms: 1_763_000_000_000,
        overlay_cidr,
        domain_suffix: "mesh.internal".to_owned(),
        relay_map: RelayMap {
            endpoint_version: 1,
            control_tcp_endpoint: endpoint.to_owned(),
            relay_tcp_endpoint: endpoint.to_owned(),
            stun_udp_endpoints: vec!["127.0.0.1:13490".to_owned()],
        },
        pin_set: PinSetDto {
            active_pin: spki_pin,
            next_pin: None,
        },
        peers,
    })
}

struct ResilienceMockServer {
    addr: SocketAddr,
    spki_pin: SpkiPin,
    scenario: Arc<Mutex<MockServerScenario>>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
}

impl ResilienceMockServer {
    async fn start_with_cert_time(now_unix_secs: u64) -> Result<Self, String> {
        ensure_rustls_provider();
        let cert = generate_ip_pinned_cert(
            &["127.0.0.1".to_owned(), "localhost".to_owned()],
            30,
            now_unix_secs,
        )
        .map_err(test_err)?;
        let server_cfg: ServerConfig = build_rustls_server_config_from_der(
            vec![cert.cert_der.clone()],
            &cert.key_pkcs8_der,
            Vec::new(),
        )
        .map_err(test_err)?;
        let spki_pin = cert.spki_pin;
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .map_err(test_err)?;
        let addr = listener.local_addr().map_err(test_err)?;

        let server_kp = NodeKeypair::generate();
        let scenario = Arc::new(Mutex::new(MockServerScenario::Normal));
        let next_challenge = Arc::new(AtomicU64::new(1));
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();

        let accept_shutdown = shutdown.clone();
        let tracker_clone = tracker.clone();
        let scenario_ref = Arc::clone(&scenario);

        tracker.spawn(async move {
            loop {
                tokio::select! {
                    () = accept_shutdown.cancelled() => break,
                    accept_res = listener.accept() => {
                        let Ok((tcp, _)) = accept_res else {
                            break;
                        };
                        let acceptor = acceptor.clone();
                        let server_kp = server_kp.clone_keypair();
                        let scenario = Arc::clone(&scenario_ref);
                        let next_challenge = Arc::clone(&next_challenge);
                        let conn_shutdown = accept_shutdown.clone();
                        let endpoint_str = addr.to_string();

                        tracker_clone.spawn(async move {
                            let Ok(mut tls) = acceptor.accept(tcp).await else {
                                return;
                            };

                            while !conn_shutdown.is_cancelled() {
                                let Ok(Some(req)) = read_http_request(&mut tls).await else {
                                    break;
                                };

                                let cur = scenario
                                    .lock()
                                    .map(|g| *g)
                                    .unwrap_or(MockServerScenario::Normal);

                                match cur {
                                    MockServerScenario::CaptivePortalHtml => {
                                        let html = b"<!DOCTYPE html><html><title>Wi-Fi Sign-in</title></html>";
                                        drop(write_http_response(&mut tls, "200 OK", "text/html", html).await);
                                        continue;
                                    }
                                    MockServerScenario::CaptivePortal511 => {
                                        let body = b"Network Authentication Required";
                                        drop(write_http_response(&mut tls, "511 Network Authentication Required", "text/plain", body).await);
                                        continue;
                                    }
                                    MockServerScenario::Normal
                                    | MockServerScenario::RevokeOnWsConnect => {}
                                }

                                if req.method == "POST" && req.path == "/v1/auth/challenge" {
                                    let Ok(_parsed_req) = serde_json::from_slice::<ChallengeRequest>(&req.body) else {
                                        break;
                                    };
                                    let cid = next_challenge.fetch_add(1, Ordering::Relaxed);
                                    let mut cid_bytes = [0_u8; 16];
                                    if let Some(tail) = cid_bytes.get_mut(8..16) {
                                        tail.copy_from_slice(&cid.to_be_bytes());
                                    }
                                    let now_ms = SystemClock::new().now_unix_ms();
                                    let resp = ChallengeResponse {
                                        challenge_id: NodeId::from_bytes(cid_bytes),
                                        challenge_nonce: BASE64_STD.encode([0x55_u8; 32]),
                                        server_eph_pubkey: server_kp.public_key(),
                                        server_time_at_ms: now_ms,
                                        expires_at_ms: now_ms.saturating_add(60_000),
                                    };
                                    if let Ok(bytes) = serde_json::to_vec(&resp) {
                                        drop(write_http_response(&mut tls, "200 OK", "application/json", &bytes).await);
                                    }
                                    continue;
                                }

                                if req.method == "POST" && req.path == "/v1/nodes/register" {
                                    let Ok(reg_req) = serde_json::from_slice::<RegisterNodeRequest>(&req.body) else {
                                        break;
                                    };
                                    let mut id_bytes = [0_u8; 16];
                                    id_bytes.copy_from_slice(
                                        reg_req.node_pubkey.as_bytes().get(..16).unwrap_or(&[7_u8; 16]),
                                    );
                                    let Ok(node_name) = NodeName::parse("resilience-ios") else {
                                        break;
                                    };
                                    let Ok(overlay_ip) = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 33)) else {
                                        break;
                                    };
                                    let Ok(snapshot) = sample_snapshot(1, &endpoint_str, spki_pin, Vec::new()) else {
                                        break;
                                    };
                                    let resp = RegisterNodeResponse {
                                        node_id: NodeId::from_bytes(id_bytes),
                                        fqdn: format!("{}.mesh.internal", node_name.as_str()),
                                        node_name,
                                        overlay_ip,
                                        overlay_cidr: snapshot.overlay_cidr,
                                        key_expires_at_ms: None,
                                        netmap: snapshot,
                                    };
                                    if let Ok(bytes) = serde_json::to_vec(&resp) {
                                        drop(write_http_response(&mut tls, "200 OK", "application/json", &bytes).await);
                                    }
                                    continue;
                                }

                                if req.method == "GET"
                                    && (req.path == "/v1/netmap/stream"
                                        || req.path.starts_with("/v1/netmap/stream?"))
                                {
                                    let Ok(mut ws) = accept_ws_server(&req) else {
                                        break;
                                    };
                                    if matches!(cur, MockServerScenario::RevokeOnWsConnect) {
                                        let revoked = ServerControlFrame::IdentityTerminated {
                                            error_kind: TerminationReason::NodeRevoked,
                                            public_msg: "revoked by security test".to_owned(),
                                            occurred_at_ms: SystemClock::new().now_unix_ms(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&revoked) {
                                            drop(ws.send(Message::Text(json.into())));
                                        }
                                        drop(flush_ws_tx(&mut tls, &mut ws).await);
                                        drop(ws.close(None));
                                        drop(flush_ws_tx(&mut tls, &mut ws).await);
                                        return;
                                    }

                                    let Ok(snap) = sample_snapshot(2, &endpoint_str, spki_pin, Vec::new()) else {
                                        break;
                                    };
                                    let frame = ServerControlFrame::NetmapSnapshot {
                                        sent_at_ms: SystemClock::new().now_unix_ms(),
                                        netmap: Box::new(snap),
                                    };
                                    if let Ok(json) = serde_json::to_string(&frame) {
                                        drop(ws.send(Message::Text(json.into())));
                                    }
                                    if flush_ws_tx(&mut tls, &mut ws).await.is_err() {
                                        break;
                                    }

                                    let mut scratch = [0_u8; 4096];
                                    loop {
                                        tokio::select! {
                                            () = conn_shutdown.cancelled() => {
                                                drop(ws.close(None));
                                                drop(flush_ws_tx(&mut tls, &mut ws).await);
                                                return;
                                            }
                                            read_res = tls.read(&mut scratch) => {
                                                let Ok(n) = read_res else {
                                                    return;
                                                };
                                                if n == 0 {
                                                    return;
                                                }
                                                ws.get_mut().push_rx(scratch.get(..n).unwrap_or_default());
                                                loop {
                                                    match ws.read() {
                                                        Ok(Message::Ping(p)) => {
                                                            drop(ws.send(Message::Pong(p)));
                                                            drop(flush_ws_tx(&mut tls, &mut ws).await);
                                                        }
                                                        Ok(Message::Close(_)) => return,
                                                        Ok(_) => {}
                                                        Err(WsError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                                                        Err(_) => return,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                break;
                            }
                        });
                    }
                }
            }
        });
        tracker.close();

        Ok(Self {
            addr,
            spki_pin,
            scenario,
            shutdown,
            tracker,
        })
    }

    fn set_scenario(&self, next: MockServerScenario) {
        if let Ok(mut guard) = self.scenario.lock() {
            *guard = next;
        }
    }

    async fn shutdown(self) {
        self.shutdown.cancel();
        let _timed = tokio::time::timeout(Duration::from_secs(3), self.tracker.wait()).await;
    }
}

struct ResilienceBridgeState {
    dek: [u8; 32],
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    route_ops: Mutex<Vec<(u64, MobileTunnelNetworkConfig)>>,
    statuses: Mutex<Vec<MobileStatusSnapshot>>,
    warnings: Mutex<Vec<MobilePlatformWarning>>,
    underlay: Mutex<MobileUnderlayState>,
    engine_ref: Mutex<Option<Arc<MobileEngine>>>,
    protected_fds: AtomicU32,
}

impl ResilienceBridgeState {
    fn new(dek: [u8; 32], underlay: MobileUnderlayState) -> Self {
        Self {
            dek,
            files: Mutex::new(BTreeMap::new()),
            route_ops: Mutex::new(Vec::new()),
            statuses: Mutex::new(Vec::new()),
            warnings: Mutex::new(Vec::new()),
            underlay: Mutex::new(underlay),
            engine_ref: Mutex::new(None),
            protected_fds: AtomicU32::new(0),
        }
    }
}

struct ResilienceBridge {
    state: Arc<ResilienceBridgeState>,
    notify: Arc<Notify>,
}

impl fmt::Debug for ResilienceBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResilienceBridge").finish_non_exhaustive()
    }
}

impl ResilienceBridge {
    fn create_pair(
        dek: [u8; 32],
        underlay: MobileUnderlayState,
    ) -> (
        Box<dyn PlatformNetworkBridge>,
        Arc<ResilienceBridgeState>,
        Arc<Notify>,
    ) {
        let state = Arc::new(ResilienceBridgeState::new(dek, underlay));
        let notify = Arc::new(Notify::new());
        let bridge = Box::new(Self {
            state: Arc::clone(&state),
            notify: Arc::clone(&notify),
        });
        (bridge, state, notify)
    }

    fn clone_bridge(
        state: &Arc<ResilienceBridgeState>,
        notify: &Arc<Notify>,
    ) -> Box<dyn PlatformNetworkBridge> {
        Box::new(Self {
            state: Arc::clone(state),
            notify: Arc::clone(notify),
        })
    }

    fn attach_engine(state: &Arc<ResilienceBridgeState>, engine: &Arc<MobileEngine>) {
        if let Ok(mut g) = state.engine_ref.lock() {
            *g = Some(Arc::clone(engine));
        }
    }
}

impl PlatformNetworkBridge for ResilienceBridge {
    fn protect_socket(&self, _fd: i32) -> Result<bool, MobileError> {
        self.state.protected_fds.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    fn on_tun_packets(&self, _packets: Vec<Vec<u8>>) {}

    fn on_route_changed(&self, op_id: u64, route: MobileTunnelNetworkConfig) {
        if let Ok(mut g) = self.state.route_ops.lock() {
            g.push((op_id, route));
        }
        let eng = self
            .state
            .engine_ref
            .lock()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        if let Some(engine) = eng {
            tokio::spawn(async move {
                engine.complete_route_change(op_id, true, None, None);
            });
        }
    }

    fn on_status_changed(&self, snapshot: MobileStatusSnapshot) {
        if let Ok(mut g) = self.state.statuses.lock() {
            g.push(snapshot);
        }
        self.notify.notify_waiters();
    }

    fn on_platform_warning(&self, warning: MobilePlatformWarning) {
        if let Ok(mut g) = self.state.warnings.lock() {
            g.push(warning);
        }
    }

    fn query_underlay_state(&self) -> Result<MobileUnderlayState, MobileError> {
        self.state
            .underlay
            .lock()
            .map(|g| g.clone())
            .map_err(|_| MobileError::internal("underlay mutex poisoned"))
    }

    fn load_or_create_platform_dek(&self) -> Result<Vec<u8>, MobileError> {
        Ok(self.state.dek.to_vec())
    }

    fn load_state_file(&self, name: String) -> Result<Option<Vec<u8>>, MobileError> {
        Ok(self
            .state
            .files
            .lock()
            .map_err(|_| MobileError::internal("files mutex poisoned"))?
            .get(&name)
            .cloned())
    }

    fn save_state_file(&self, name: String, data: Vec<u8>) -> Result<(), MobileError> {
        self.state
            .files
            .lock()
            .map_err(|_| MobileError::internal("files mutex poisoned"))?
            .insert(name, data);
        Ok(())
    }

    fn delete_state_file(&self, name: String) -> Result<(), MobileError> {
        self.state
            .files
            .lock()
            .map_err(|_| MobileError::internal("files mutex poisoned"))?
            .remove(&name);
        Ok(())
    }
}

fn wifi_ipv4_underlay() -> MobileUnderlayState {
    MobileUnderlayState {
        active_interface_name: Some("en0".to_owned()),
        physical_if_index: Some(11),
        has_ipv4: true,
        has_ipv6: false,
        underlay_dns_servers: vec!["192.0.2.53".to_owned()],
        os_nat64_prefix: None,
        physical_subnets: vec!["192.168.10.25/24".to_owned()],
        is_android_lockdown_enabled: false,
        is_android_private_dns_strict: false,
        private_dns_server_name: None,
    }
}

fn cellular_nat64_underlay() -> MobileUnderlayState {
    MobileUnderlayState {
        active_interface_name: Some("pdp_ip0".to_owned()),
        physical_if_index: Some(14),
        has_ipv4: false,
        has_ipv6: true,
        underlay_dns_servers: vec!["2001:4860:4860::6464".to_owned()],
        os_nat64_prefix: Some("64:ff9b::/96".to_owned()),
        physical_subnets: Vec::new(),
        is_android_lockdown_enabled: false,
        is_android_private_dns_strict: false,
        private_dns_server_name: None,
    }
}

fn dual_stack_lan_underlay() -> MobileUnderlayState {
    MobileUnderlayState {
        active_interface_name: Some("wlan0".to_owned()),
        physical_if_index: Some(8),
        has_ipv4: true,
        has_ipv6: true,
        underlay_dns_servers: vec!["192.168.1.1".to_owned(), "2001:4860:4860::8888".to_owned()],
        os_nat64_prefix: Some("64:ff9b::/96".to_owned()),
        physical_subnets: vec!["192.168.1.40/24".to_owned()],
        is_android_lockdown_enabled: false,
        is_android_private_dns_strict: false,
        private_dns_server_name: None,
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut i = 0_usize;
    while i.saturating_add(1) < header.len() {
        if i != 10 {
            let hi = u32::from(header.get(i).copied().unwrap_or(0));
            let lo = u32::from(header.get(i + 1).copied().unwrap_or(0));
            sum = sum.saturating_add((hi << 8) | lo);
        }
        i = i.saturating_add(2);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF).saturating_add(sum >> 16);
    }
    !(u16::try_from(sum & 0xFFFF).unwrap_or(0))
}

fn encode_dns_name(fqdn: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in fqdn.split('.') {
        if label.is_empty() {
            continue;
        }
        let len_byte = u8::try_from(label.len()).unwrap_or(63);
        out.push(len_byte);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn build_dns_query_wire(tx_id: u16, fqdn: &str, qtype: u16, edns_udp_size: Option<u16>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&0x0100_u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT=1
    out.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT=0
    out.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT=0
    let arcount: u16 = if edns_udp_size.is_some() { 1 } else { 0 };
    out.extend_from_slice(&arcount.to_be_bytes());
    out.extend_from_slice(&encode_dns_name(fqdn));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes()); // IN
    if let Some(udp_sz) = edns_udp_size {
        out.push(0); // Root owner name
        out.extend_from_slice(&41_u16.to_be_bytes()); // OPT
        out.extend_from_slice(&udp_sz.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes()); // ext RCODE/flags
        out.extend_from_slice(&0_u16.to_be_bytes()); // RDLEN=0
    }
    out
}

fn build_l3_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 28_usize.saturating_add(payload.len());
    let mut pkt = vec![0_u8; total_len];
    if let Some(b) = pkt.get_mut(0) {
        *b = 0x45;
    }
    let tot_bytes = u16::try_from(total_len).unwrap_or(28).to_be_bytes();
    if let Some(slice) = pkt.get_mut(2..4) {
        slice.copy_from_slice(&tot_bytes);
    }
    if let Some(slice) = pkt.get_mut(8..10) {
        slice.copy_from_slice(&[64, 17]);
    }
    if let Some(slice) = pkt.get_mut(12..16) {
        slice.copy_from_slice(&src.octets());
    }
    if let Some(slice) = pkt.get_mut(16..20) {
        slice.copy_from_slice(&dst.octets());
    }
    let csum = ipv4_checksum(pkt.get(..20).unwrap_or_default()).to_be_bytes();
    if let Some(slice) = pkt.get_mut(10..12) {
        slice.copy_from_slice(&csum);
    }
    if let Some(slice) = pkt.get_mut(20..22) {
        slice.copy_from_slice(&src_port.to_be_bytes());
    }
    if let Some(slice) = pkt.get_mut(22..24) {
        slice.copy_from_slice(&dst_port.to_be_bytes());
    }
    let udp_len = u16::try_from(8_usize.saturating_add(payload.len()))
        .unwrap_or(8)
        .to_be_bytes();
    if let Some(slice) = pkt.get_mut(24..26) {
        slice.copy_from_slice(&udp_len);
    }
    if let Some(slice) = pkt.get_mut(28..) {
        slice.copy_from_slice(payload);
    }
    pkt
}

#[derive(Clone, Copy)]
struct TcpTestSpec<'a> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    mss: Option<u16>,
    payload: &'a [u8],
}

fn build_l3_tcp_packet(spec: TcpTestSpec<'_>) -> Vec<u8> {
    let opt_bytes: Vec<u8> = match spec.mss {
        Some(m) => {
            let mb = m.to_be_bytes();
            vec![2, 4, mb[0], mb[1]]
        }
        None => Vec::new(),
    };
    let tcp_hdr_len = 20_usize.saturating_add(opt_bytes.len());
    let total_len = 20_usize
        .saturating_add(tcp_hdr_len)
        .saturating_add(spec.payload.len());
    let mut pkt = vec![0_u8; total_len];
    if let Some(b) = pkt.get_mut(0) {
        *b = 0x45;
    }
    if let Some(slice) = pkt.get_mut(2..4) {
        slice.copy_from_slice(&u16::try_from(total_len).unwrap_or(40).to_be_bytes());
    }
    if let Some(slice) = pkt.get_mut(8..10) {
        slice.copy_from_slice(&[64, 6]);
    }
    if let Some(slice) = pkt.get_mut(12..16) {
        slice.copy_from_slice(&spec.src.octets());
    }
    if let Some(slice) = pkt.get_mut(16..20) {
        slice.copy_from_slice(&spec.dst.octets());
    }
    let ip_csum = ipv4_checksum(pkt.get(..20).unwrap_or_default()).to_be_bytes();
    if let Some(slice) = pkt.get_mut(10..12) {
        slice.copy_from_slice(&ip_csum);
    }

    if let Some(slice) = pkt.get_mut(20..22) {
        slice.copy_from_slice(&spec.src_port.to_be_bytes());
    }
    if let Some(slice) = pkt.get_mut(22..24) {
        slice.copy_from_slice(&spec.dst_port.to_be_bytes());
    }
    if let Some(slice) = pkt.get_mut(24..28) {
        slice.copy_from_slice(&spec.seq.to_be_bytes());
    }
    if let Some(slice) = pkt.get_mut(28..32) {
        slice.copy_from_slice(&spec.ack.to_be_bytes());
    }
    let data_offset = u8::try_from(tcp_hdr_len / 4).unwrap_or(5) << 4;
    if let Some(b) = pkt.get_mut(32) {
        *b = data_offset;
    }
    if let Some(b) = pkt.get_mut(33) {
        *b = spec.flags;
    }
    if let Some(slice) = pkt.get_mut(34..36) {
        slice.copy_from_slice(&65535_u16.to_be_bytes());
    }
    if !opt_bytes.is_empty()
        && let Some(slice) = pkt.get_mut(40..40 + opt_bytes.len())
    {
        slice.copy_from_slice(&opt_bytes);
    }
    let payload_off = 20_usize.saturating_add(tcp_hdr_len);
    if !spec.payload.is_empty()
        && let Some(slice) = pkt.get_mut(payload_off..payload_off + spec.payload.len())
    {
        slice.copy_from_slice(spec.payload);
    }
    // Compute TCP pseudo-header checksum.
    let tcp_len = tcp_hdr_len.saturating_add(spec.payload.len());
    let mut sum = 0_u32;
    for chunk in spec.src.octets().chunks_exact(2) {
        let w = u32::from(u16::from_be_bytes([
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
        ]));
        sum = sum.saturating_add(w);
    }
    for chunk in spec.dst.octets().chunks_exact(2) {
        let w = u32::from(u16::from_be_bytes([
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
        ]));
        sum = sum.saturating_add(w);
    }
    sum = sum.saturating_add(6);
    sum = sum.saturating_add(u32::try_from(tcp_len).unwrap_or(0));
    let tcp_slice = pkt.get(20..).unwrap_or_default();
    let mut i = 0_usize;
    while i < tcp_slice.len() {
        let hi = u32::from(tcp_slice.get(i).copied().unwrap_or(0));
        let lo = u32::from(tcp_slice.get(i + 1).copied().unwrap_or(0));
        sum = sum.saturating_add((hi << 8) | lo);
        i = i.saturating_add(2);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF).saturating_add(sum >> 16);
    }
    let tcp_csum = (!(u16::try_from(sum & 0xFFFF).unwrap_or(0))).to_be_bytes();
    if let Some(slice) = pkt.get_mut(36..38) {
        slice.copy_from_slice(&tcp_csum);
    }
    pkt
}

#[tokio::test]
async fn test_resilience_roaming_10_rounds_wifi_ipv4_ipv6_nat64_rfc7050_and_wg_handshake()
-> Result<(), String> {
    // Arrange 1: RFC 7050 `ipv4only.arpa` WKA discovery and RFC 1918 non-synthesis rules.
    let wka_custom: [Ipv6Addr; 2] = [
        "2001:db8:64::192.0.0.170".parse().map_err(test_err)?,
        "2001:db8:64::192.0.0.171".parse().map_err(test_err)?,
    ];
    let detected_custom = Nat64Prefix::from_ipv4only_arpa_addrs(&wka_custom)
        .ok_or_else(|| "RFC 7050 custom prefix detection returned None".to_owned())?;
    assert_eq!(
        detected_custom,
        Nat64Prefix::from_cidr("2001:db8:64::/96").map_err(test_err)?
    );

    let wka_well_known: [Ipv6Addr; 2] = [
        "64:ff9b::192.0.0.170".parse().map_err(test_err)?,
        "64:ff9b::192.0.0.171".parse().map_err(test_err)?,
    ];
    let detected_wk = Nat64Prefix::from_ipv4only_arpa_addrs(&wka_well_known)
        .ok_or_else(|| "RFC 7050 well-known 64:ff9b::/96 detection returned None".to_owned())?;
    assert_eq!(detected_wk, Nat64Prefix::well_known());

    // Public endpoints eligible for NAT64; RFC 1918, CGNAT, loopback, link-local NEVER eligible.
    assert!(is_eligible_for_nat64_synthesis(Ipv4Addr::new(
        198, 51, 100, 10
    )));
    assert!(is_eligible_for_nat64_synthesis(Ipv4Addr::new(
        203, 0, 113, 5
    )));
    assert!(!is_eligible_for_nat64_synthesis(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(!is_eligible_for_nat64_synthesis(Ipv4Addr::new(
        172, 16, 0, 5
    )));
    assert!(!is_eligible_for_nat64_synthesis(Ipv4Addr::new(
        192, 168, 1, 50
    )));
    assert!(!is_eligible_for_nat64_synthesis(Ipv4Addr::new(
        127, 0, 0, 1
    )));
    assert!(!is_eligible_for_nat64_synthesis(Ipv4Addr::new(
        169, 254, 1, 1
    )));

    // Arrange 2: Enroll & start MobileEngine on TLS 1.3 Mock Server.
    let now_secs = SystemClock::new().now_unix_secs();
    let server = ResilienceMockServer::start_with_cert_time(now_secs).await?;
    let endpoint = server.addr.to_string();
    let pin_str = server.spki_pin.to_string();
    let dir = TempDir::new().map_err(test_err)?;
    let (bridge, state, notify) =
        ResilienceBridge::create_pair([0x77_u8; 32], wifi_ipv4_underlay());
    let init_cfg = MobileEngineInitConfig {
        platform: MobilePlatformKind::Ios,
        agent_version: "0.2.0-resilience".to_owned(),
        default_node_name: Some("roam-ios".to_owned()),
        log_dir_path: dir.path().to_string_lossy().into_owned(),
    };
    let pending = create_pending_join_session(make_preauth_key(0x77)).map_err(test_err)?;
    drop(
        mobile_enroll_or_rotate_node(
            init_cfg.clone(),
            bridge,
            MobileEnrollConfig {
                server_endpoint: endpoint.clone(),
                port_override: None,
                tls_auth_mode: MobileTlsAuthMode::SpkiPin,
                server_pin: Some(pin_str.clone()),
                pending_join: pending,
                node_name: Some("roam-ios".to_owned()),
                rotate_existing_identity: false,
            },
        )
        .await
        .map_err(test_err)?,
    );

    let engine = MobileEngine::new(init_cfg, ResilienceBridge::clone_bridge(&state, &notify))
        .map_err(test_err)?;
    ResilienceBridge::attach_engine(&state, &engine);
    let initial = engine
        .start_tunnel(MobileUpConfig {
            server_endpoint: endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str),
            pending_join: None,
            node_name: Some("roam-ios".to_owned()),
            android_tun_fd: None,
            tun_interface_name: Some("utun7".to_owned()),
        })
        .await
        .map_err(test_err)?;
    let expected_ip = initial
        .overlay_ip
        .clone()
        .ok_or_else(|| "missing initial overlay_ip".to_owned())?;

    // Check dual-stack LAN does NOT synthesize NAT64.
    if let Ok(mut u) = state.underlay.lock() {
        *u = dual_stack_lan_underlay();
    }
    engine.on_network_change(
        MobileNetEventKind::InterfaceChanged,
        dual_stack_lan_underlay(),
    );
    let dual_netcheck = engine.netcheck().await.map_err(test_err)?;
    assert_eq!(dual_netcheck.nat64_prefix, None);

    // Act: 10 consecutive roaming rounds alternating Wi-Fi IPv4 <-> IPv6-only NAT64 `64:ff9b::/96`.
    let roam_t0 = Instant::now();
    for round in 0..10_u32 {
        let next_underlay = if round % 2 == 0 {
            cellular_nat64_underlay()
        } else {
            wifi_ipv4_underlay()
        };
        if let Ok(mut u) = state.underlay.lock() {
            *u = next_underlay.clone();
        }
        engine.on_network_change(MobileNetEventKind::InterfaceChanged, next_underlay);
        tokio::time::sleep(Duration::from_millis(15)).await;
        let snap = engine.status_snapshot().await.map_err(test_err)?;
        assert_eq!(snap.overlay_ip.as_deref(), Some(expected_ip.as_str()));
    }
    assert!(
        roam_t0.elapsed() <= Duration::from_secs(5),
        "10 roaming transitions exceeded 5s budget"
    );

    // Confirm WireGuard Noise handshake convergence completes within <= 2s after roaming.
    let kp_a = NodeKeypair::generate();
    let kp_b = NodeKeypair::generate();
    let id_a = NodeId::from_bytes([1_u8; 16]);
    let id_b = NodeId::from_bytes([2_u8; 16]);
    let ip_a = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 33)).map_err(test_err)?;
    let ip_b = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 34)).map_err(test_err)?;
    let entry_b = PeerEntry {
        node_id: id_b,
        name: NodeName::parse("peer-roam-b").map_err(test_err)?,
        fqdn: "peer-roam-b.mesh.internal".to_owned(),
        overlay_ip: ip_b,
        node_pubkey: kp_b.public_key(),
        disco_pubkey: DiscoKeypair::generate().public_key(),
        endpoints: vec![CandidateEndpoint {
            addr: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 88), 51820)),
            source: CandidateSource::Reflexive,
        }],
        relay_home: endpoint.clone(),
        key_expires_at_ms: None,
        online: true,
    };
    let entry_a = PeerEntry {
        node_id: id_a,
        name: NodeName::parse("peer-roam-a").map_err(test_err)?,
        fqdn: "peer-roam-a.mesh.internal".to_owned(),
        overlay_ip: ip_a,
        node_pubkey: kp_a.public_key(),
        disco_pubkey: DiscoKeypair::generate().public_key(),
        endpoints: Vec::new(),
        relay_home: endpoint.clone(),
        key_expires_at_ms: None,
        online: true,
    };
    let mut map_a = PeerMap::new(id_a, kp_a.clone_keypair());
    let mut map_b = PeerMap::new(id_b, kp_b.clone_keypair());
    map_a.apply_diff(&sample_snapshot(
        3,
        &endpoint,
        server.spki_pin,
        vec![entry_b],
    )?);
    map_b.apply_diff(&sample_snapshot(
        3,
        &endpoint,
        server.spki_pin,
        vec![entry_a],
    )?);

    let wg_t0 = Instant::now();
    let mut buf_a: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
    let mut buf_b: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
    let probe = build_l3_udp_packet(ip_a.as_ipv4(), ip_b.as_ipv4(), 41000, 42000, b"wg-roam");
    let (_, _, init_len) = map_a
        .encapsulate_to_overlay_ip(ip_b, &probe, &mut buf_a, 1_000)
        .map_err(test_err)?
        .ok_or_else(|| "missing handshake init".to_owned())?;
    let dec_b = map_b
        .decapsulate_from_relay(
            kp_a.public_key(),
            buf_a.get(..init_len).unwrap_or_default(),
            &mut buf_b,
            1_005,
        )
        .ok_or_else(|| "B failed handshake decapsulate".to_owned())?;
    let resp = dec_b
        .outbound_network_packets
        .first()
        .ok_or_else(|| "missing WG handshake response".to_owned())?;
    drop(map_a.decapsulate_from_relay(kp_b.public_key(), resp, &mut buf_a, 1_010));
    assert!(wg_t0.elapsed() <= Duration::from_secs(2));

    let shut_t0 = Instant::now();
    drop(engine.stop_tunnel().await);
    engine.shutdown().map_err(test_err)?;
    assert!(shut_t0.elapsed() <= Duration::from_secs(5));
    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn test_resilience_split_dns_rfc4074_nodata_edns0_l3_tcp_lru16_ttl3s_dot853_and_tun()
-> Result<(), String> {
    // Arrange
    let clock = Arc::new(FakeClock::new(1_763_000_000_000));
    let interceptor = MobileSplitDnsInterceptor::new(clock.clone());
    let self_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 10)).map_err(test_err)?;
    let alpha_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 11)).map_err(test_err)?;
    let dns_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 2)).map_err(test_err)?;
    let self_name = NodeName::parse("mobile-self").map_err(test_err)?;
    let peer_alpha = PeerEntry {
        node_id: NodeId::from_bytes([0x11_u8; 16]),
        name: NodeName::parse("alpha").map_err(test_err)?,
        fqdn: "alpha.mesh.internal".to_owned(),
        overlay_ip: alpha_ip,
        node_pubkey: NodeKeypair::generate().public_key(),
        disco_pubkey: DiscoKeypair::generate().public_key(),
        endpoints: Vec::new(),
        relay_home: "127.0.0.1:8443".to_owned(),
        key_expires_at_ms: None,
        online: true,
    };
    let snap = sample_snapshot(
        1,
        "127.0.0.1:8443",
        SpkiPin::from_sha256_bytes([0x55_u8; 32]),
        vec![peer_alpha],
    )?;
    interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));

    // Act & Assert 1: UDP `A` (`alpha.mesh.internal`), RFC 4074 NODATA for `AAAA`, `HTTPS` (65),
    // `SVCB` (64), and EDNS0 UDP <= 1232 B budget check.
    let q_a = build_dns_query_wire(0x1001, "alpha.mesh.internal", 1, Some(1232));
    let p_a = build_l3_udp_packet(self_ip.as_ipv4(), dns_ip.as_ipv4(), 45_001, 53, &q_a);
    let DnsInterceptDecision::Handled { tun_responses: r_a } =
        interceptor.intercept_outbound_packet(&p_a)
    else {
        return Err("expected A query handled".to_owned());
    };
    let resp_a = r_a.first().ok_or_else(|| "missing A response".to_owned())?;
    let dns_a = resp_a.get(28..).unwrap_or_default();
    assert_eq!(dns_a.get(3).copied().unwrap_or(0xFF) & 0x0F, 0); // RCODE=0
    assert_eq!(
        u16::from_be_bytes([
            dns_a.get(6).copied().unwrap_or(0),
            dns_a.get(7).copied().unwrap_or(0)
        ]),
        1
    ); // ANCOUNT=1
    assert!(dns_a.len() <= 1232);
    // EDNS0 OPT additional record occupies trailing 11 bytes; A RDATA precedes it.
    assert!(
        dns_a.windows(4).any(|w| w == alpha_ip.as_ipv4().octets()),
        "A response must contain resolved peer IPv4 10.100.0.11"
    );
    assert!(
        u16::from_be_bytes([
            dns_a.get(10).copied().unwrap_or(0),
            dns_a.get(11).copied().unwrap_or(0)
        ]) >= 1,
        "EDNS0 response must include OPT additional RR"
    );

    // Classic non-EDNS0 UDP query (no OPT RR) must stay <= 512 bytes.
    let q_classic = build_dns_query_wire(0x1009, "alpha.mesh.internal", 1, None);
    let p_classic =
        build_l3_udp_packet(self_ip.as_ipv4(), dns_ip.as_ipv4(), 45_009, 53, &q_classic);
    let DnsInterceptDecision::Handled {
        tun_responses: r_classic,
    } = interceptor.intercept_outbound_packet(&p_classic)
    else {
        return Err("expected classic non-EDNS0 A query handled".to_owned());
    };
    let resp_classic = r_classic
        .first()
        .ok_or_else(|| "missing classic A response".to_owned())?;
    let dns_classic = resp_classic.get(28..).unwrap_or_default();
    assert!(dns_classic.len() <= 512);
    assert_eq!(
        u16::from_be_bytes([
            dns_classic.get(10).copied().unwrap_or(9),
            dns_classic.get(11).copied().unwrap_or(9)
        ]),
        0
    );

    for (tx_id, qtype, label) in [
        (0x1002_u16, 28_u16, "AAAA"),
        (0x1003, 65, "HTTPS"),
        (0x1004, 64, "SVCB"),
    ] {
        let q = build_dns_query_wire(tx_id, "alpha.mesh.internal", qtype, Some(1232));
        let p = build_l3_udp_packet(self_ip.as_ipv4(), dns_ip.as_ipv4(), 45_002, 53, &q);
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&p)
        else {
            return Err(format!(
                "expected {label} query handled via RFC 4074 NODATA"
            ));
        };
        let pkt = tun_responses
            .first()
            .ok_or_else(|| format!("missing {label} response"))?;
        let dns = pkt.get(28..).unwrap_or_default();
        assert_eq!(
            dns.get(3).copied().unwrap_or(0xFF) & 0x0F,
            0,
            "{label} must return RCODE=0 NODATA (not NXDOMAIN)"
        );
        assert_eq!(
            u16::from_be_bytes([
                dns.get(6).copied().unwrap_or(9),
                dns.get(7).copied().unwrap_or(9)
            ]),
            0,
            "{label} must have ANCOUNT=0"
        );
        assert!(dns.len() <= 1232);
    }

    // Act & Assert 2: L3 TCP `:53` single-transaction (`PSH|FIN|ACK`), pipelined 2nd query `RST|ACK`,
    // 16 LRU slot cap, and 3s TTL eviction.
    let c_port = 52_001_u16;
    let syn = build_l3_tcp_packet(TcpTestSpec {
        src: self_ip.as_ipv4(),
        dst: dns_ip.as_ipv4(),
        src_port: c_port,
        dst_port: 53,
        seq: 100,
        ack: 0,
        flags: 0x02, // SYN
        mss: Some(1240),
        payload: &[],
    });
    let DnsInterceptDecision::Handled {
        tun_responses: syn_acks,
    } = interceptor.intercept_outbound_packet(&syn)
    else {
        return Err("expected TCP :53 SYN handled".to_owned());
    };
    let syn_ack = syn_acks
        .first()
        .ok_or_else(|| "missing SYN|ACK".to_owned())?;
    assert_eq!(syn_ack.get(33).copied().unwrap_or(0) & 0x12, 0x12);
    let srv_seq = u32::from_be_bytes([
        syn_ack.get(24).copied().unwrap_or(0),
        syn_ack.get(25).copied().unwrap_or(0),
        syn_ack.get(26).copied().unwrap_or(0),
        syn_ack.get(27).copied().unwrap_or(0),
    ]);

    let tcp_q = build_dns_query_wire(0x2001, "alpha.mesh.internal", 1, None);
    let mut framed_q = Vec::with_capacity(2 + tcp_q.len());
    framed_q.extend_from_slice(&u16::try_from(tcp_q.len()).unwrap_or(0).to_be_bytes());
    framed_q.extend_from_slice(&tcp_q);

    let psh = build_l3_tcp_packet(TcpTestSpec {
        src: self_ip.as_ipv4(),
        dst: dns_ip.as_ipv4(),
        src_port: c_port,
        dst_port: 53,
        seq: 101,
        ack: srv_seq.wrapping_add(1),
        flags: 0x18, // PSH|ACK
        mss: None,
        payload: &framed_q,
    });
    let DnsInterceptDecision::Handled {
        tun_responses: dns_tcp_resps,
    } = interceptor.intercept_outbound_packet(&psh)
    else {
        return Err("expected TCP :53 DNS payload handled".to_owned());
    };
    let psh_fin_ack = dns_tcp_resps
        .iter()
        .find(|r| (r.get(33).copied().unwrap_or(0) & 0x19) == 0x19)
        .ok_or_else(|| "expected TCP :53 single-transaction PSH|FIN|ACK response".to_owned())?;
    assert!(psh_fin_ack.len() > 42);

    // Pipelined 2nd query on the same TCP 4-tuple must receive RST|ACK.
    let psh2 = build_l3_tcp_packet(TcpTestSpec {
        src: self_ip.as_ipv4(),
        dst: dns_ip.as_ipv4(),
        src_port: c_port,
        dst_port: 53,
        seq: 101_u32.wrapping_add(u32::try_from(framed_q.len()).unwrap_or(0)),
        ack: srv_seq.wrapping_add(1),
        flags: 0x18,
        mss: None,
        payload: &framed_q,
    });
    let DnsInterceptDecision::Handled {
        tun_responses: pipeline_resps,
    } = interceptor.intercept_outbound_packet(&psh2)
    else {
        return Err("expected pipelined 2nd TCP :53 query handled with RST|ACK".to_owned());
    };
    assert!(
        pipeline_resps
            .iter()
            .any(|r| (r.get(33).copied().unwrap_or(0) & 0x14) == 0x14),
        "pipelined 2nd query must emit TCP RST|ACK"
    );

    // 16 LRU slots eviction when opening 17 concurrent TCP `:53` client ports.
    for offset in 0..17_u16 {
        let s = build_l3_tcp_packet(TcpTestSpec {
            src: self_ip.as_ipv4(),
            dst: dns_ip.as_ipv4(),
            src_port: 53_000_u16.saturating_add(offset),
            dst_port: 53,
            seq: 1,
            ack: 0,
            flags: 0x02,
            mss: Some(1240),
            payload: &[],
        });
        drop(interceptor.intercept_outbound_packet(&s));
    }
    assert!(interceptor.active_tcp_slot_count() <= 16);

    // 3 s idle TTL eviction via FakeClock advance (> 3_000 ms).
    clock.advance(3_500);
    let fresh_syn = build_l3_tcp_packet(TcpTestSpec {
        src: self_ip.as_ipv4(),
        dst: dns_ip.as_ipv4(),
        src_port: 54_000,
        dst_port: 53,
        seq: 1,
        ack: 0,
        flags: 0x02,
        mss: Some(1240),
        payload: &[],
    });
    drop(interceptor.intercept_outbound_packet(&fresh_syn));
    assert_eq!(interceptor.active_tcp_slot_count(), 1);

    // Act & Assert 3: TCP `:853` (DoT) emits immediate `TCP RST|ACK` (`0` block).
    let dot_syn = build_l3_tcp_packet(TcpTestSpec {
        src: self_ip.as_ipv4(),
        dst: dns_ip.as_ipv4(),
        src_port: 55_001,
        dst_port: 853,
        seq: 777,
        ack: 0,
        flags: 0x02,
        mss: Some(1240),
        payload: &[],
    });
    let DnsInterceptDecision::Handled {
        tun_responses: dot_resps,
    } = interceptor.intercept_outbound_packet(&dot_syn)
    else {
        return Err("expected TCP :853 DoT probe handled".to_owned());
    };
    let rst = dot_resps
        .first()
        .ok_or_else(|| "missing :853 RST|ACK".to_owned())?;
    assert_eq!(rst.get(33).copied().unwrap_or(0) & 0x14, 0x14);

    // Act & Assert 4: Live `DatapathEngine` + `FakeTunDevice` TUN interception.
    let tun_cfg = TunConfig {
        interface_name: "qa-tun0".to_owned(),
        overlay_ip: self_ip,
        overlay_cidr: "10.100.0.0/16".parse().map_err(test_err)?,
        mtu: 1280,
    };
    let fake_tun = Arc::new(FakeTunDevice::new(tun_cfg));
    let dp_cfg = DatapathConfig {
        local_node_id: NodeId::from_bytes([9_u8; 16]),
        local_overlay_ip: self_ip,
        overlay_cidr: "10.100.0.0/16".parse().map_err(test_err)?,
        node_keypair: NodeKeypair::generate(),
        disco_keypair: DiscoKeypair::generate(),
        socket_config: MagicSocketConfig {
            preferred_port: None,
            bind_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            mtu: 1280,
            underlay_if_index: None,
            linux_fwmark: None,
            nat64_prefix: None,
            socket_protector: Arc::new(NoopSocketProtector),
        },
        stun_config: StunClientConfig {
            probe_timeout: Duration::from_secs(1),
            nat64_prefix: None,
            socket_protector: Arc::new(NoopSocketProtector),
        },
        disco_config: DiscoConfig::default(),
        control_tcp_endpoint: None,
        wg_timer_interval: Duration::from_millis(250),
        disco_tick_interval: Duration::from_millis(250),
    };
    let engine = DatapathEngine::bind_with_options(
        dp_cfg,
        fake_tun.clone(),
        clock,
        None,
        DatapathEngineOptions {
            timer_mode: TimerMode::IdleAware,
            idle_entry_window_ms: 180_000,
            dns_interceptor: Some(Arc::new(interceptor)),
        },
    )
    .await
    .map_err(test_err)?;

    let shutdown = CancellationToken::new();
    let (_relay_ev_tx, relay_ev_rx) = tokio::sync::mpsc::channel(16);
    let (_rebind_cmd_tx, rebind_cmd_rx) = tokio::sync::mpsc::channel(16);
    let dp_handle = tokio::spawn(engine.run(relay_ev_rx, rebind_cmd_rx, shutdown.clone()));
    fake_tun
        .inject_inbound_packet(build_l3_udp_packet(
            self_ip.as_ipv4(),
            dns_ip.as_ipv4(),
            56_001,
            53,
            &build_dns_query_wire(0x3333, "alpha.mesh.internal", 1, Some(1232)),
        ))
        .await
        .map_err(test_err)?;
    fake_tun
        .inject_inbound_packet(dot_syn)
        .await
        .map_err(test_err)?;

    let mut received_packets = Vec::new();
    for _ in 0..40 {
        let batch = fake_tun.drain_outbound_packets().await;
        received_packets.extend(batch);
        if received_packets.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        received_packets.len() >= 2,
        "DatapathEngine + FakeTunDevice must write intercepted DNS + :853 RST back to TUN"
    );

    shutdown.cancel();
    let _done = tokio::time::timeout(Duration::from_secs(3), dp_handle).await;
    Ok(())
}

#[tokio::test]
async fn test_resilience_idle_aware_jetsam_hysteresis_doze_clock_jump_captive_clock_skew_revoked_and_shutdown()
-> Result<(), String> {
    // Arrange 1: JetsamPressureController exact hysteresis & cooldown thresholds.
    const MIB: u64 = 1024 * 1024;
    let mut jetsam = JetsamPressureController::new();
    let ev_normal = jetsam.evaluate(25 * MIB, 1_000);
    assert_eq!(ev_normal.stage, JetsamPressureStage::Normal);
    assert!(!ev_normal.force_idle_aware);

    // < 15 MiB -> TrimCaches; 16 MiB stays in TrimCaches (hysteresis); >= 18 MiB recovers.
    let ev_trim = jetsam.evaluate(14 * MIB, 2_000);
    assert_eq!(ev_trim.stage, JetsamPressureStage::TrimCaches);
    assert!(ev_trim.trim_logs);
    assert!(!ev_trim.force_idle_aware);
    let ev_hyst = jetsam.evaluate(16 * MIB, 3_000);
    assert_eq!(ev_hyst.stage, JetsamPressureStage::TrimCaches);
    let ev_rec = jetsam.evaluate(19 * MIB, 4_000);
    assert_eq!(ev_rec.stage, JetsamPressureStage::Normal);

    // < 6 MiB -> ShedIdle; 9 MiB before 10_000 ms cooldown stays ShedIdle; >= 10_000 ms recovers.
    let ev_shed = jetsam.evaluate(5 * MIB, 10_000);
    assert_eq!(ev_shed.stage, JetsamPressureStage::ShedIdle);
    assert!(ev_shed.force_idle_aware);
    assert!(ev_shed.emit_low_memory_warning);
    let ev_early = jetsam.evaluate(9 * MIB, 12_000);
    assert_eq!(ev_early.stage, JetsamPressureStage::ShedIdle);
    let ev_cooled = jetsam.evaluate(9 * MIB, 21_000);
    assert_ne!(ev_cooled.stage, JetsamPressureStage::ShedIdle);

    // < 4 MiB -> CriticalShutdown.
    let ev_crit = jetsam.evaluate(3 * MIB, 25_000);
    assert_eq!(ev_crit.stage, JetsamPressureStage::CriticalShutdown);
    assert!(ev_crit.trigger_graceful_shutdown);

    // Arrange 2: Doze clock jump (`> 30_000 ms`) detection.
    let fake_clock = FakeClock::new(1_763_000_000_000);
    let mut jump_detector = ClockJumpDetector::new(&fake_clock);
    fake_clock.advance(4_000);
    assert!(jump_detector.check(&fake_clock).is_none());
    fake_clock.jump_wall_ms(45_000);
    let jump_ev = jump_detector
        .check(&fake_clock)
        .ok_or_else(|| "expected >30s Doze clock jump detection".to_owned())?;
    assert_eq!(jump_ev.drift_ms, 45_000);

    // Arrange 3: Captive Portal (HTTP 511 & HTML 200), Clock Skew cert, and NodeRevoked WS termination.
    let now_secs = SystemClock::new().now_unix_secs();
    let normal_server = ResilienceMockServer::start_with_cert_time(now_secs).await?;
    let endpoint = normal_server.addr.to_string();
    let pin_str = normal_server.spki_pin.to_string();

    // Captive Portal HTML / 511 during enroll returns retryable `Unavailable` (not Revoked/Unauth).
    normal_server.set_scenario(MockServerScenario::CaptivePortalHtml);
    let portal_dir = TempDir::new().map_err(test_err)?;
    let (portal_bridge, _, _) = ResilienceBridge::create_pair([0x31_u8; 32], wifi_ipv4_underlay());
    let portal_err = mobile_enroll_or_rotate_node(
        MobileEngineInitConfig {
            platform: MobilePlatformKind::Android,
            agent_version: "0.2.0-resilience".to_owned(),
            default_node_name: Some("portal-test".to_owned()),
            log_dir_path: portal_dir.path().to_string_lossy().into_owned(),
        },
        portal_bridge,
        MobileEnrollConfig {
            server_endpoint: endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str.clone()),
            pending_join: create_pending_join_session(make_preauth_key(0x31)).map_err(test_err)?,
            node_name: Some("portal-test".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .err()
    .ok_or_else(|| "expected captive portal enroll to fail transiently".to_owned())?;
    assert!(matches!(portal_err, MobileError::Unavailable { .. }));

    // Captive Portal HTTP 511 Network Authentication Required -> retryable Unavailable.
    normal_server.set_scenario(MockServerScenario::CaptivePortal511);
    let portal511_dir = TempDir::new().map_err(test_err)?;
    let (portal511_bridge, _, _) =
        ResilienceBridge::create_pair([0x34_u8; 32], wifi_ipv4_underlay());
    let portal511_err = mobile_enroll_or_rotate_node(
        MobileEngineInitConfig {
            platform: MobilePlatformKind::Android,
            agent_version: "0.2.0-resilience".to_owned(),
            default_node_name: Some("portal-511".to_owned()),
            log_dir_path: portal511_dir.path().to_string_lossy().into_owned(),
        },
        portal511_bridge,
        MobileEnrollConfig {
            server_endpoint: endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str.clone()),
            pending_join: create_pending_join_session(make_preauth_key(0x34)).map_err(test_err)?,
            node_name: Some("portal-511".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .err()
    .ok_or_else(|| "expected HTTP 511 captive portal enroll to fail transiently".to_owned())?;
    assert!(matches!(portal511_err, MobileError::Unavailable { .. }));

    // Clock Skew cert (`not_before` 7 days in the future -> MobileError::ClockSkew).
    let skew_server =
        ResilienceMockServer::start_with_cert_time(now_secs.saturating_add(7 * 86_400)).await?;
    let skew_dir = TempDir::new().map_err(test_err)?;
    let (skew_bridge, _, _) = ResilienceBridge::create_pair([0x32_u8; 32], wifi_ipv4_underlay());
    let skew_err = mobile_enroll_or_rotate_node(
        MobileEngineInitConfig {
            platform: MobilePlatformKind::Ios,
            agent_version: "0.2.0-resilience".to_owned(),
            default_node_name: Some("skew-test".to_owned()),
            log_dir_path: skew_dir.path().to_string_lossy().into_owned(),
        },
        skew_bridge,
        MobileEnrollConfig {
            server_endpoint: skew_server.addr.to_string(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(skew_server.spki_pin.to_string()),
            pending_join: create_pending_join_session(make_preauth_key(0x32)).map_err(test_err)?,
            node_name: Some("skew-test".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .err()
    .ok_or_else(|| "expected future-dated certificate to fail with ClockSkew".to_owned())?;
    assert!(matches!(skew_err, MobileError::ClockSkew { .. }));
    skew_server.shutdown().await;

    // Normal enroll -> set_power_saving_mode + export_bugreport_to_file + evaluate_memory_pressure_once +
    // NodeRevoked -> MobileDaemonState::Revoked + shutdown() <= 5s.
    normal_server.set_scenario(MockServerScenario::Normal);
    let work_dir = TempDir::new().map_err(test_err)?;
    let (work_bridge, work_state, work_notify) =
        ResilienceBridge::create_pair([0x33_u8; 32], wifi_ipv4_underlay());
    let work_init = MobileEngineInitConfig {
        platform: MobilePlatformKind::Ios,
        agent_version: "0.2.0-resilience".to_owned(),
        default_node_name: Some("revoke-ios".to_owned()),
        log_dir_path: work_dir.path().to_string_lossy().into_owned(),
    };
    drop(
        mobile_enroll_or_rotate_node(
            work_init.clone(),
            work_bridge,
            MobileEnrollConfig {
                server_endpoint: endpoint.clone(),
                port_override: None,
                tls_auth_mode: MobileTlsAuthMode::SpkiPin,
                server_pin: Some(pin_str.clone()),
                pending_join: create_pending_join_session(make_preauth_key(0x33))
                    .map_err(test_err)?,
                node_name: Some("revoke-ios".to_owned()),
                rotate_existing_identity: false,
            },
        )
        .await
        .map_err(test_err)?,
    );

    normal_server.set_scenario(MockServerScenario::RevokeOnWsConnect);
    let engine = MobileEngine::new(
        work_init,
        ResilienceBridge::clone_bridge(&work_state, &work_notify),
    )
    .map_err(test_err)?;
    ResilienceBridge::attach_engine(&work_state, &engine);
    engine.set_power_saving_mode(true);
    engine.set_power_saving_mode(false);
    let _mem_eval = engine.evaluate_memory_pressure_once().await;

    let tar_path = work_dir.path().join("qa-resilience-bugreport.tar");
    let bug = engine
        .export_bugreport_to_file(tar_path.to_string_lossy().into_owned())
        .await
        .map_err(test_err)?;
    assert!(bug.size_bytes > 0 && bug.size_bytes <= 1_048_576);

    drop(
        engine
            .start_tunnel(MobileUpConfig {
                server_endpoint: endpoint,
                port_override: None,
                tls_auth_mode: MobileTlsAuthMode::SpkiPin,
                server_pin: Some(pin_str),
                pending_join: None,
                node_name: Some("revoke-ios".to_owned()),
                android_tun_fd: None,
                tun_interface_name: Some("utun6".to_owned()),
            })
            .await,
    );

    for _ in 0..40 {
        let cur = engine.status_snapshot().await.map_err(test_err)?;
        if cur.daemon_state == MobileDaemonState::Revoked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let revoked_snap = engine.status_snapshot().await.map_err(test_err)?;
    assert_eq!(revoked_snap.daemon_state, MobileDaemonState::Revoked);

    let shut_t0 = Instant::now();
    engine.shutdown().map_err(test_err)?;
    assert!(shut_t0.elapsed() <= Duration::from_secs(5));
    normal_server.shutdown().await;
    Ok(())
}
