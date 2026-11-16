//! WP-M-C1 QA AppSec & Cryptographic Isolation Suite for `mesh-mobile-ffi` (`US-096`).
//!
//! Verifies:
//! - Explicit secret canaries (pre-auth token `mpk_*`, 32-byte DEK hex/base64/UTF-8, internal
//!   secrets) produce **0 leaked bytes** across `tracing` `DEBUG` logs, `MobilePendingJoinSession`,
//!   `MobileStatusSnapshot::to_bounded_ipc_json()` (`<= 4096 B`), `MobileError` (`Unauthenticated` =
//!   `"authentication failed"` per `SEC-05`), `export_bugreport_to_file()` `.tar` (`<= 1 MiB`), and
//!   persisted non-identity config files.
//! - Zero-TOFU (`SEC-04`) rejects IP literal + `SystemCa` (empty pin) across URI parsing,
//!   enrollment, and `BootstrapConfig` validation.
//! - `"identity.sealed.bin"` stores valid `"MSH1"` ChaCha20-Poly1305 AEAD ciphertext containing zero
//!   plaintext private keys or JSON schema tags, and rejects decryption under wrong DEKs.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

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
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;

use mesh_client::BootstrapConfig;
use mesh_core::{
    AppError, Clock as _, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin, SystemClock,
};
use mesh_crypto::NodeKeypair;
use mesh_crypto::certgen::{build_rustls_server_config_from_der, generate_ip_pinned_cert};
use mesh_net::keystore::{SEALED_IDENTITY_MAGIC, StoredNodeIdentity};
use mesh_proto::agent_ipc::TlsAuthMode;
use mesh_proto::control::{
    ChallengeRequest, ChallengeResponse, RegisterNodeRequest, RegisterNodeResponse,
    ServerControlFrame,
};
use mesh_proto::netmap::{NetmapSnapshot, PinSetDto, RelayMap};

use mesh_mobile_ffi::{
    MobileEngine, MobileEngineInitConfig, MobileEnrollConfig, MobileError, MobilePlatformKind,
    MobilePlatformWarning, MobileStatusSnapshot, MobileTlsAuthMode, MobileTunnelNetworkConfig,
    MobileUnderlayState, MobileUpConfig, PlatformNetworkBridge, create_pending_join_session,
    mobile_enroll_or_rotate_node, parse_mobile_join_uri,
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

#[derive(Clone, Default)]
struct DebugLogRecorder {
    lines: Arc<Mutex<Vec<String>>>,
}

impl DebugLogRecorder {
    fn snapshot_text(&self) -> String {
        self.lines.lock().map(|g| g.join("\n")).unwrap_or_default()
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.push_str(&format!("{}={:?} ", field.name(), value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!("{}={} ", field.name(), value));
    }
}

impl<S: Subscriber> Layer<S> for DebugLogRecorder {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if *event.metadata().level() > Level::DEBUG {
            return;
        }
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        if let Ok(mut guard) = self.lines.lock() {
            guard.push(format!("{} {}", event.metadata().target(), visitor.0));
        }
    }
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

async fn write_http_json<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status_line: &str,
    body: &[u8],
) -> Result<(), String> {
    let header = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
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

struct SecurityMockServer {
    addr: SocketAddr,
    spki_pin: SpkiPin,
    force_401: Arc<AtomicBool>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
}

impl SecurityMockServer {
    async fn start() -> Result<Self, String> {
        ensure_rustls_provider();
        let now_secs = SystemClock::new().now_unix_secs();
        let cert = generate_ip_pinned_cert(
            &["127.0.0.1".to_owned(), "localhost".to_owned()],
            30,
            now_secs,
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
        let force_401 = Arc::new(AtomicBool::new(false));
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();

        let accept_shutdown = shutdown.clone();
        let tracker_clone = tracker.clone();
        let force_401_ref = Arc::clone(&force_401);

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
                        let force_401 = Arc::clone(&force_401_ref);
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
                                if force_401.load(Ordering::Acquire) {
                                    let body = serde_json::json!({
                                        "error": "unauthenticated",
                                        "message": "bad canary token mpk_SHOULD_NOT_ECHO"
                                    });
                                    if let Ok(b) = serde_json::to_vec(&body) {
                                        drop(write_http_json(&mut tls, "401 Unauthorized", &b).await);
                                    }
                                    continue;
                                }
                                if req.method == "POST" && req.path == "/v1/auth/challenge" {
                                    let Ok(_parsed) = serde_json::from_slice::<ChallengeRequest>(&req.body) else {
                                        break;
                                    };
                                    let now_ms = SystemClock::new().now_unix_ms();
                                    let resp = ChallengeResponse {
                                        challenge_id: NodeId::from_bytes([0x42_u8; 16]),
                                        challenge_nonce: BASE64_STD.encode([0x42_u8; 32]),
                                        server_eph_pubkey: server_kp.public_key(),
                                        server_time_at_ms: now_ms,
                                        expires_at_ms: now_ms.saturating_add(60_000),
                                    };
                                    if let Ok(b) = serde_json::to_vec(&resp) {
                                        drop(write_http_json(&mut tls, "200 OK", &b).await);
                                    }
                                    continue;
                                }
                                if req.method == "POST" && req.path == "/v1/nodes/register" {
                                    let Ok(reg) = serde_json::from_slice::<RegisterNodeRequest>(&req.body) else {
                                        break;
                                    };
                                    let Ok(overlay_cidr) = "10.100.0.0/16".parse::<OverlayCidr>() else {
                                        break;
                                    };
                                    let Ok(overlay_ip) = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 77)) else {
                                        break;
                                    };
                                    let Ok(node_name) = NodeName::parse("audit-node") else {
                                        break;
                                    };
                                    let snap = NetmapSnapshot {
                                        netmap_version: 1,
                                        generated_at_ms: SystemClock::new().now_unix_ms(),
                                        overlay_cidr,
                                        domain_suffix: "mesh.internal".to_owned(),
                                        relay_map: RelayMap {
                                            endpoint_version: 1,
                                            control_tcp_endpoint: endpoint_str.clone(),
                                            relay_tcp_endpoint: endpoint_str.clone(),
                                            stun_udp_endpoints: vec!["127.0.0.1:13495".to_owned()],
                                        },
                                        pin_set: PinSetDto {
                                            active_pin: spki_pin,
                                            next_pin: None,
                                        },
                                        peers: Vec::new(),
                                    };
                                    let mut id_bytes = [0_u8; 16];
                                    id_bytes.copy_from_slice(reg.node_pubkey.as_bytes().get(..16).unwrap_or(&[8_u8; 16]));
                                    let resp = RegisterNodeResponse {
                                        node_id: NodeId::from_bytes(id_bytes),
                                        fqdn: "audit-node.mesh.internal".to_owned(),
                                        node_name,
                                        overlay_ip,
                                        overlay_cidr,
                                        key_expires_at_ms: None,
                                        netmap: snap.clone(),
                                    };
                                    if let Ok(b) = serde_json::to_vec(&resp) {
                                        drop(write_http_json(&mut tls, "200 OK", &b).await);
                                    }
                                    continue;
                                }
                                if req.method == "GET"
                                    && (req.path == "/v1/netmap/stream"
                                        || req.path.starts_with("/v1/netmap/stream?"))
                                {
                                    let Some(key) = req.headers.get("sec-websocket-key") else {
                                        break;
                                    };
                                    let accept_val =
                                        tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
                                    let mut bridge = WsSyncBridge::new(req.raw_head.clone());
                                    bridge.tx_buf.extend_from_slice(
                                        format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_val}\r\n\r\n").as_bytes(),
                                    );
                                    bridge.rx_buf.clear();
                                    let mut ws = WebSocket::from_raw_socket(bridge, Role::Server, None);
                                    if let Ok(overlay_cidr) = "10.100.0.0/16".parse::<OverlayCidr>() {
                                        let frame = ServerControlFrame::NetmapSnapshot {
                                            sent_at_ms: SystemClock::new().now_unix_ms(),
                                            netmap: Box::new(NetmapSnapshot {
                                                netmap_version: 2,
                                                generated_at_ms: SystemClock::new().now_unix_ms(),
                                                overlay_cidr,
                                                domain_suffix: "mesh.internal".to_owned(),
                                                relay_map: RelayMap {
                                                    endpoint_version: 1,
                                                    control_tcp_endpoint: endpoint_str.clone(),
                                                    relay_tcp_endpoint: endpoint_str.clone(),
                                                    stun_udp_endpoints: vec!["127.0.0.1:13495".to_owned()],
                                                },
                                                pin_set: PinSetDto {
                                                    active_pin: spki_pin,
                                                    next_pin: None,
                                                },
                                                peers: Vec::new(),
                                            }),
                                        };
                                        if let Ok(json) = serde_json::to_string(&frame) {
                                            drop(ws.send(Message::Text(json.into())));
                                        }
                                    }
                                    drop(ws.flush());
                                    let out = ws.get_mut().take_tx();
                                    if tls.write_all(&out).await.is_err() || tls.flush().await.is_err() {
                                        break;
                                    }
                                    let mut scratch = [0_u8; 2048];
                                    loop {
                                        tokio::select! {
                                            () = conn_shutdown.cancelled() => return,
                                            n_res = tls.read(&mut scratch) => {
                                                let Ok(n) = n_res else { return };
                                                if n == 0 { return; }
                                                ws.get_mut().push_rx(scratch.get(..n).unwrap_or_default());
                                                loop {
                                                    match ws.read() {
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
            force_401,
            shutdown,
            tracker,
        })
    }

    async fn shutdown(self) {
        self.shutdown.cancel();
        let _t = tokio::time::timeout(Duration::from_secs(3), self.tracker.wait()).await;
    }
}

struct AuditBridgeState {
    dek: [u8; 32],
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    engine_ref: Mutex<Option<Arc<MobileEngine>>>,
}

struct AuditBridge {
    state: Arc<AuditBridgeState>,
    notify: Arc<Notify>,
}

impl fmt::Debug for AuditBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditBridge").finish_non_exhaustive()
    }
}

impl AuditBridge {
    fn create_pair(
        dek: [u8; 32],
    ) -> (
        Box<dyn PlatformNetworkBridge>,
        Arc<AuditBridgeState>,
        Arc<Notify>,
    ) {
        let state = Arc::new(AuditBridgeState {
            dek,
            files: Mutex::new(BTreeMap::new()),
            engine_ref: Mutex::new(None),
        });
        let notify = Arc::new(Notify::new());
        let bridge = Box::new(Self {
            state: Arc::clone(&state),
            notify: Arc::clone(&notify),
        });
        (bridge, state, notify)
    }

    fn clone_bridge(
        state: &Arc<AuditBridgeState>,
        notify: &Arc<Notify>,
    ) -> Box<dyn PlatformNetworkBridge> {
        Box::new(Self {
            state: Arc::clone(state),
            notify: Arc::clone(notify),
        })
    }

    fn attach_engine(state: &Arc<AuditBridgeState>, engine: &Arc<MobileEngine>) {
        if let Ok(mut g) = state.engine_ref.lock() {
            *g = Some(Arc::clone(engine));
        }
    }
}

impl PlatformNetworkBridge for AuditBridge {
    fn protect_socket(&self, _fd: i32) -> Result<bool, MobileError> {
        Ok(true)
    }

    fn on_tun_packets(&self, _packets: Vec<Vec<u8>>) {}

    fn on_route_changed(&self, op_id: u64, _route: MobileTunnelNetworkConfig) {
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

    fn on_status_changed(&self, _snapshot: MobileStatusSnapshot) {
        self.notify.notify_waiters();
    }

    fn on_platform_warning(&self, _warning: MobilePlatformWarning) {}

    fn query_underlay_state(&self) -> Result<MobileUnderlayState, MobileError> {
        Ok(MobileUnderlayState {
            active_interface_name: Some("en0".to_owned()),
            physical_if_index: Some(4),
            has_ipv4: true,
            has_ipv6: false,
            underlay_dns_servers: vec!["192.0.2.53".to_owned()],
            os_nat64_prefix: None,
            physical_subnets: Vec::new(),
            is_android_lockdown_enabled: false,
            is_android_private_dns_strict: false,
            private_dns_server_name: None,
        })
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

fn hex_encode_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn test_no_secrets_in_outputs_e2e_debug_logs_ipc_tar_and_unauthenticated()
-> Result<(), String> {
    // Arrange: Explicit distinct canaries + DEBUG-level tracing subscriber.
    let recorder = DebugLogRecorder::default();
    let subscriber = tracing_subscriber::registry().with(recorder.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let preauth_secret_raw = b"CANARY_PREAUTH_KEY_32_BYTES_QA01";
    let preauth_canary = format!("mpk_{}", URL_SAFE_NO_PAD.encode(preauth_secret_raw));
    let dek_canary: [u8; 32] = *b"QA_DEK_CANARY_SECRET_32_BYTES_01";
    let dek_hex_canary = hex_encode_lower(&dek_canary);
    let dek_b64_canary = BASE64_STD.encode(dek_canary);
    let privkey_canary: [u8; 32] = *b"QA_PRIVKEY_CANARY_32_BYTES_SEC96";
    let privkey_hex_canary = hex_encode_lower(&privkey_canary);
    let privkey_b64_canary = BASE64_STD.encode(privkey_canary);
    let canary_str_raw = "QA_DEK_CANARY_SECRET_32_BYTES_01";

    let scrubbed_priv_err = MobileError::internal(format!(
        "diag node_privkey_hex={privkey_hex_canary} mpk={preauth_canary}"
    ));
    let scrubbed_priv_msg = format!("{scrubbed_priv_err} {scrubbed_priv_err:?}");
    assert!(!scrubbed_priv_msg.contains(&privkey_hex_canary));
    assert!(!scrubbed_priv_msg.contains(&preauth_canary));

    let scrubbed_b64_unauth: MobileError =
        AppError::unauthenticated(format!("privkey_b64={privkey_b64_canary}")).into();
    assert_eq!(scrubbed_b64_unauth.to_string(), "authentication failed");
    assert!(!format!("{scrubbed_b64_unauth:?}").contains(&privkey_b64_canary));

    let server = SecurityMockServer::start().await?;
    let endpoint = server.addr.to_string();
    let pin_str = server.spki_pin.to_string();

    // Act 1: PendingJoinSession + URI redaction + Unauthenticated fixed SEC-05 error message.
    let join_uri =
        format!("mesh://join?v=1&ep={endpoint}&pin={pin_str}&key={preauth_canary}&name=sec-ios");
    let parsed = parse_mobile_join_uri(join_uri).map_err(test_err)?;
    let session_dbg = format!("{:?}", parsed.session);
    let preview = parsed.session.masked_preview();
    assert!(!session_dbg.contains(&preauth_canary));
    assert!(!preview.contains(&preauth_canary));
    assert!(preview.contains("mpk_"));

    let unauth_session = create_pending_join_session(preauth_canary.clone()).map_err(test_err)?;
    server.force_401.store(true, Ordering::Release);
    let err_dir = TempDir::new().map_err(test_err)?;
    let (err_bridge, _, _) = AuditBridge::create_pair(dek_canary);
    let err_res = mobile_enroll_or_rotate_node(
        MobileEngineInitConfig {
            platform: MobilePlatformKind::Ios,
            agent_version: "0.2.0-sec".to_owned(),
            default_node_name: Some("sec-err".to_owned()),
            log_dir_path: err_dir.path().to_string_lossy().into_owned(),
        },
        err_bridge,
        MobileEnrollConfig {
            server_endpoint: endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str.clone()),
            pending_join: unauth_session,
            node_name: Some("sec-err".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .err()
    .ok_or_else(|| "expected 401 enrollment to fail with Unauthenticated".to_owned())?;
    match &err_res {
        MobileError::Unauthenticated { message, .. } => {
            assert_eq!(message, "authentication failed");
        }
        other => return Err(format!("expected Unauthenticated, got {other:?}")),
    }
    let err_display = format!("{err_res} {:?}", err_res);
    assert!(!err_display.contains(&preauth_canary));
    assert!(!err_display.contains("mpk_SHOULD_NOT_ECHO"));
    let sec05_app: MobileError = AppError::unauthenticated(format!("leak {preauth_canary}")).into();
    assert_eq!(sec05_app.to_string(), "authentication failed");

    // Act 2: Full E2E enroll -> tunnel up -> bounded IPC JSON (<= 4096 B) -> bugreport .tar (<= 1 MiB).
    server.force_401.store(false, Ordering::Release);
    let dir = TempDir::new().map_err(test_err)?;
    let (bridge, state, notify) = AuditBridge::create_pair(dek_canary);
    let init_cfg = MobileEngineInitConfig {
        platform: MobilePlatformKind::Ios,
        agent_version: "0.2.0-sec".to_owned(),
        default_node_name: Some("audit-node".to_owned()),
        log_dir_path: dir.path().to_string_lossy().into_owned(),
    };
    let enrolled = mobile_enroll_or_rotate_node(
        init_cfg.clone(),
        bridge,
        MobileEnrollConfig {
            server_endpoint: endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str.clone()),
            pending_join: Arc::clone(&parsed.session),
            node_name: Some("audit-node".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .map_err(test_err)?;
    parsed.session.cancel();

    let ipc_json = enrolled.to_bounded_ipc_json().map_err(test_err)?;
    assert!(ipc_json.len() <= 4096);

    let engine = MobileEngine::new(init_cfg, AuditBridge::clone_bridge(&state, &notify))
        .map_err(test_err)?;
    AuditBridge::attach_engine(&state, &engine);
    drop(
        engine
            .start_tunnel(MobileUpConfig {
                server_endpoint: endpoint,
                port_override: None,
                tls_auth_mode: MobileTlsAuthMode::SpkiPin,
                server_pin: Some(pin_str),
                pending_join: None,
                node_name: Some("audit-node".to_owned()),
                android_tun_fd: None,
                tun_interface_name: Some("utun5".to_owned()),
            })
            .await
            .map_err(test_err)?,
    );

    let live_snap = engine.status_snapshot().await.map_err(test_err)?;
    let live_ipc = live_snap.to_bounded_ipc_json().map_err(test_err)?;
    assert!(live_ipc.len() <= 4096);

    let tar_path = dir.path().join("security-audit-bugreport.tar");
    let bug = engine
        .export_bugreport_to_file(tar_path.to_string_lossy().into_owned())
        .await
        .map_err(test_err)?;
    assert!(bug.size_bytes > 0 && bug.size_bytes <= 1_048_576);
    let tar_bytes = std::fs::read(&tar_path).map_err(test_err)?;
    assert!(tar_bytes.len() <= 1_048_576);

    drop(engine.stop_tunnel().await);
    engine.shutdown().map_err(test_err)?;
    server.shutdown().await;

    // Assert: 0 bytes of any secret canary appear in DEBUG logs, IPC JSON, bugreport .tar, or config files.
    let debug_logs = recorder.snapshot_text();
    let canary_strs = [
        preauth_canary.as_str(),
        dek_hex_canary.as_str(),
        dek_b64_canary.as_str(),
        privkey_hex_canary.as_str(),
        privkey_b64_canary.as_str(),
        canary_str_raw,
        "CANARY_PREAUTH_KEY_32_BYTES_QA01",
    ];
    for needle in canary_strs {
        assert!(
            !debug_logs.contains(needle),
            "DEBUG tracing logs leaked secret canary"
        );
        assert!(
            !contains_subslice(&ipc_json, needle.as_bytes()),
            "enroll IPC JSON leaked secret canary"
        );
        assert!(
            !contains_subslice(&live_ipc, needle.as_bytes()),
            "live IPC JSON leaked secret canary"
        );
        assert!(
            !contains_subslice(&tar_bytes, needle.as_bytes()),
            "bugreport .tar leaked secret canary"
        );
    }

    if let Ok(files) = state.files.lock() {
        for (name, bytes) in files.iter() {
            assert!(
                !contains_subslice(bytes, preauth_canary.as_bytes()),
                "state file {name} leaked preauth canary"
            );
            assert!(
                !contains_subslice(bytes, &dek_canary),
                "state file {name} leaked raw DEK bytes"
            );
            assert!(
                !contains_subslice(bytes, dek_hex_canary.as_bytes()),
                "state file {name} leaked DEK hex"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_security_zero_tofu_rejects_ip_literal_system_ca_and_verifies_msh1_sealed_identity()
-> Result<(), String> {
    // Arrange & Act 1: Zero-TOFU (`SEC-04`) rejects IP literal + SystemCa without SPKI pin across
    // URI parser, `BootstrapConfig::validate`, and FFI enroll/up entrypoints.
    let raw_key = make_preauth_canary(0x88);
    let uri_res = parse_mobile_join_uri(format!(
        "mesh://join?v=1&ep=127.0.0.1:8443&pin=system-ca&key={raw_key}"
    ));
    assert!(matches!(uri_res, Err(MobileError::InvalidArgument { .. })));

    let invalid_bootstrap = BootstrapConfig {
        server_endpoint: Some("127.0.0.1:8443".to_owned()),
        tls_auth_mode: TlsAuthMode::SystemCa,
        ..BootstrapConfig::default()
    };
    assert!(invalid_bootstrap.validate().is_err());

    let dir = TempDir::new().map_err(test_err)?;
    let dek: [u8; 32] = [0xAA_u8; 32];
    let (bridge, state, notify) = AuditBridge::create_pair(dek);
    let init_cfg = MobileEngineInitConfig {
        platform: MobilePlatformKind::Android,
        agent_version: "0.2.0-sec".to_owned(),
        default_node_name: Some("zero-tofu".to_owned()),
        log_dir_path: dir.path().to_string_lossy().into_owned(),
    };
    let pending = create_pending_join_session(raw_key).map_err(test_err)?;
    let enroll_tofu_res = mobile_enroll_or_rotate_node(
        init_cfg.clone(),
        bridge,
        MobileEnrollConfig {
            server_endpoint: "127.0.0.1:8443".to_owned(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SystemCa,
            server_pin: None,
            pending_join: pending,
            node_name: Some("zero-tofu".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await;
    assert!(matches!(
        enroll_tofu_res,
        Err(MobileError::InvalidArgument { .. } | MobileError::PinMismatch { .. })
    ));

    // Arrange & Act 2: Enroll with valid SPKI pin, then audit `"identity.sealed.bin"`.
    let server = SecurityMockServer::start().await?;
    let endpoint = server.addr.to_string();
    let pin_str = server.spki_pin.to_string();
    let valid_key = make_preauth_canary(0x99);
    let enrolled = mobile_enroll_or_rotate_node(
        init_cfg,
        AuditBridge::clone_bridge(&state, &notify),
        MobileEnrollConfig {
            server_endpoint: endpoint,
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str),
            pending_join: create_pending_join_session(valid_key).map_err(test_err)?,
            node_name: Some("sealed-check".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .map_err(test_err)?;
    assert!(enrolled.overlay_ip.is_some());

    // Assert: `"identity.sealed.bin"` starts with `"MSH1"` magic, contains ZERO plaintext private-key
    // fields or key material, fails unseal with a wrong DEK, and unseals cleanly with `dek`.
    let sealed_bytes = state
        .files
        .lock()
        .ok()
        .and_then(|g| g.get("identity.sealed.bin").cloned())
        .ok_or_else(|| "missing identity.sealed.bin after enrollment".to_owned())?;
    assert!(sealed_bytes.starts_with(&SEALED_IDENTITY_MAGIC));
    assert!(sealed_bytes.len() > SEALED_IDENTITY_MAGIC.len() + 12 + 16);
    assert!(!contains_subslice(&sealed_bytes, b"node_privkey_hex"));
    assert!(!contains_subslice(&sealed_bytes, b"disco_privkey_hex"));
    assert!(!contains_subslice(&sealed_bytes, b"schema_version"));
    assert!(!contains_subslice(&sealed_bytes, b"\"node_pubkey\""));

    let wrong_dek = [0x99_u8; 32];
    assert!(StoredNodeIdentity::unseal_with_dek(&sealed_bytes, &wrong_dek).is_err());

    let unsealed = StoredNodeIdentity::unseal_with_dek(&sealed_bytes, &dek).map_err(test_err)?;
    let re_sealed = unsealed.seal_with_dek(&dek).map_err(test_err)?;
    assert_ne!(
        sealed_bytes.get(4..16),
        re_sealed.get(4..16),
        "re-sealing must use a fresh 12-byte random ChaCha20-Poly1305 nonce"
    );

    server.shutdown().await;
    Ok(())
}

fn make_preauth_canary(seed: u8) -> String {
    format!("mpk_{}", URL_SAFE_NO_PAD.encode([seed; 32]))
}
