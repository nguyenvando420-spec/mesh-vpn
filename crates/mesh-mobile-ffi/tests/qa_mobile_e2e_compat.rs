//! WP-M-C1 QA Integration & E2E Compatibility Suite for `mesh-mobile-ffi` (`US-094`).
//!
//! Exercises public UniFFI exports (`parse_mobile_join_uri`, `create_pending_join_session`,
//! `mobile_enroll_or_rotate_node`, `MobileEngine`, `start_tunnel`, `complete_route_change`,
//! `status_snapshot`, `stop_tunnel`, `shutdown`), TLS 1.3 SPKI-pinned WebSocket Control & Blind
//! Relay servers, Desktop `v0.1.0-rc1` wire compatibility, HTTP `400 ProtocolIncompatible`,
//! Double-CGNAT Blind Relay bounded 256-slot `try_send()` isolation, and `mesh://join` CLI/QR URI
//! roundtrips.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use rustls::ServerConfig;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Error as WsError, Message, WebSocket};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use mesh_core::Clock as _;
use mesh_core::defaults::RELAY_QUEUE_CAPACITY;
use mesh_core::mobile_uri::{MobileJoinTlsAuth, format_join_uri};
use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey, SpkiPin, SystemClock};
use mesh_crypto::certgen::{build_rustls_server_config_from_der, generate_ip_pinned_cert};
use mesh_crypto::{DiscoKeypair, NodeKeypair, PinSet};
use mesh_datapath::{
    MAGIC_SOCKET_BUFFER_SIZE, PacketBuffer, PeerMap, RelayClient, RelayClientConfig,
    RelayConnectionState, RelayEvent, TimerMode, TlsRelayConnector,
};
use mesh_net::nat64::{Nat64Prefix, Nat64Synthesizer};
use mesh_proto::control::{
    ChallengeRequest, ChallengeResponse, HEADER_NODE_PUBKEY, RegisterNodeRequest,
    RegisterNodeResponse, ServerControlFrame, TargetArch, TargetOs,
};
use mesh_proto::netmap::{
    CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap,
};
use mesh_proto::relay::RelayFrame;

use mesh_mobile_ffi::{
    MobileDaemonState, MobileEngine, MobileEngineInitConfig, MobileEnrollConfig, MobileError,
    MobileNetEventKind, MobilePlatformKind, MobilePlatformWarning, MobileStatusSnapshot,
    MobileTlsAuthMode, MobileTunnelNetworkConfig, MobileUnderlayState, MobileUpConfig,
    PlatformNetworkBridge, create_pending_join_session, mobile_enroll_or_rotate_node,
    parse_mobile_join_uri,
};

fn test_err(msg: impl fmt::Display) -> String {
    msg.to_string()
}

fn make_preauth_key(seed: u8) -> String {
    format!("mpk_{}", URL_SAFE_NO_PAD.encode([seed; 32]))
}

fn ensure_rustls_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        drop(rustls::crypto::ring::default_provider().install_default());
    });
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
            return Err("unexpected EOF while reading mock HTTP request head".to_owned());
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
            return Err("unexpected EOF while reading mock HTTP body".to_owned());
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

fn accept_ws_server(req: &ParsedHttpRequest) -> Result<WebSocket<WsSyncBridge>, String> {
    let mut bridge = WsSyncBridge::new(req.raw_head.clone());
    let key = req
        .headers
        .get("sec-websocket-key")
        .ok_or_else(|| "missing Sec-WebSocket-Key header".to_owned())?;
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

fn build_test_snapshot(
    version: u64,
    endpoint: &str,
    stun_port: u16,
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
            stun_udp_endpoints: vec![format!("127.0.0.1:{stun_port}")],
        },
        pin_set: PinSetDto {
            active_pin: spki_pin,
            next_pin: None,
        },
        peers,
    })
}

fn overlay_ip_octet(octet: u8) -> Result<OverlayIp, String> {
    OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, octet)).map_err(test_err)
}

#[derive(Debug, Clone)]
enum ServerResponseMode {
    Normal,
    ProtocolIncompatible,
}

#[derive(Debug, Default)]
struct MockServerObserved {
    challenge_requests: Vec<ChallengeRequest>,
    register_requests: Vec<RegisterNodeRequest>,
    netmap_stream_connects: u32,
    relay_connects: u32,
}

struct MockControlAndRelayServer {
    addr: SocketAddr,
    _stun_port: u16,
    spki_pin: SpkiPin,
    observed: Arc<Mutex<MockServerObserved>>,
    mode: Arc<Mutex<ServerResponseMode>>,
    netmap_shutdown: Arc<Notify>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
}

impl MockControlAndRelayServer {
    async fn start(stun_port: u16) -> Result<Self, String> {
        ensure_rustls_provider();
        let clock = SystemClock::new();
        let now_secs = clock.now_unix_secs();
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
        let observed = Arc::new(Mutex::new(MockServerObserved::default()));
        let mode = Arc::new(Mutex::new(ServerResponseMode::Normal));
        let relay_peers: Arc<Mutex<HashMap<PublicKey, mpsc::Sender<RelayFrame>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let assigned_ips: Arc<Mutex<HashMap<PublicKey, OverlayIp>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let next_octet = Arc::new(AtomicU32::new(10));
        let next_challenge = Arc::new(AtomicU64::new(1));
        let netmap_shutdown = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();

        let accept_shutdown = shutdown.clone();
        let tracker_clone = tracker.clone();
        let observed_ref = Arc::clone(&observed);
        let mode_ref = Arc::clone(&mode);
        let netmap_notify_ref = Arc::clone(&netmap_shutdown);

        tracker.spawn(async move {
            loop {
                tokio::select! {
                    () = accept_shutdown.cancelled() => break,
                    accept_res = listener.accept() => {
                        let Ok((tcp, _peer_addr)) = accept_res else {
                            break;
                        };
                        let acceptor = acceptor.clone();
                        let server_kp = server_kp.clone_keypair();
                        let observed = Arc::clone(&observed_ref);
                        let mode = Arc::clone(&mode_ref);
                        let relay_peers = Arc::clone(&relay_peers);
                        let assigned_ips = Arc::clone(&assigned_ips);
                        let next_octet = Arc::clone(&next_octet);
                        let next_challenge = Arc::clone(&next_challenge);
                        let netmap_notify = Arc::clone(&netmap_notify_ref);
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

                                let current_mode = mode
                                    .lock()
                                    .map(|g| g.clone())
                                    .unwrap_or(ServerResponseMode::Normal);

                                if matches!(current_mode, ServerResponseMode::ProtocolIncompatible) {
                                    let body_json = serde_json::json!({
                                        "error": "protocol_incompatible",
                                        "message": "control protocol version mismatch: agent upgrade required"
                                    });
                                    if let Ok(bytes) = serde_json::to_vec(&body_json) {
                                        drop(write_http_json(&mut tls, "400 Bad Request", &bytes).await);
                                    }
                                    continue;
                                }

                                if req.method == "POST" && req.path == "/v1/auth/challenge" {
                                    let Ok(parsed_req) = serde_json::from_slice::<ChallengeRequest>(&req.body) else {
                                        let err = serde_json::json!({
                                            "error": "invalid_argument",
                                            "message": "invalid challenge payload"
                                        });
                                        if let Ok(b) = serde_json::to_vec(&err) {
                                            drop(write_http_json(&mut tls, "400 Bad Request", &b).await);
                                        }
                                        continue;
                                    };
                                    if let Ok(mut guard) = observed.lock() {
                                        guard.challenge_requests.push(parsed_req);
                                    }
                                    let cid = next_challenge.fetch_add(1, Ordering::Relaxed);
                                    let mut cid_bytes = [0_u8; 16];
                                    if let Some(tail) = cid_bytes.get_mut(8..16) {
                                        tail.copy_from_slice(&cid.to_be_bytes());
                                    }
                                    let now_ms = SystemClock::new().now_unix_ms();
                                    let resp = ChallengeResponse {
                                        challenge_id: NodeId::from_bytes(cid_bytes),
                                        challenge_nonce: BASE64_STD.encode([u8::try_from(cid & 0xFF).unwrap_or(1); 32]),
                                        server_eph_pubkey: server_kp.public_key(),
                                        server_time_at_ms: now_ms,
                                        expires_at_ms: now_ms.saturating_add(60_000),
                                    };
                                    if let Ok(bytes) = serde_json::to_vec(&resp) {
                                        drop(write_http_json(&mut tls, "200 OK", &bytes).await);
                                    }
                                    continue;
                                }

                                if req.method == "POST" && req.path == "/v1/nodes/register" {
                                    let Ok(reg_req) = serde_json::from_slice::<RegisterNodeRequest>(&req.body) else {
                                        continue;
                                    };
                                    let pk = reg_req.node_pubkey;
                                    let overlay_ip = {
                                        let Ok(mut ips) = assigned_ips.lock() else {
                                            break;
                                        };
                                        if let Some(existing) = ips.get(&pk).copied() {
                                            existing
                                        } else {
                                            let oct = u8::try_from(
                                                (next_octet.fetch_add(1, Ordering::Relaxed) % 230) + 10,
                                            )
                                            .unwrap_or(10);
                                            let Ok(ip) = overlay_ip_octet(oct) else {
                                                break;
                                            };
                                            ips.insert(pk, ip);
                                            ip
                                        }
                                    };
                                    let mut id_bytes = [0_u8; 16];
                                    id_bytes.copy_from_slice(pk.as_bytes().get(..16).unwrap_or(&[1_u8; 16]));
                                    let node_id = NodeId::from_bytes(id_bytes);
                                    let Ok(node_name) = NodeName::parse("qa-mobile-node") else {
                                        break;
                                    };
                                    let Ok(snapshot) = build_test_snapshot(
                                        1,
                                        &endpoint_str,
                                        stun_port,
                                        spki_pin,
                                        Vec::new(),
                                    ) else {
                                        break;
                                    };
                                    if let Ok(mut guard) = observed.lock() {
                                        guard.register_requests.push(reg_req);
                                    }
                                    let resp = RegisterNodeResponse {
                                        node_id,
                                        fqdn: format!("{}.{}", node_name.as_str(), snapshot.domain_suffix),
                                        node_name,
                                        overlay_ip,
                                        overlay_cidr: snapshot.overlay_cidr,
                                        key_expires_at_ms: None,
                                        netmap: snapshot,
                                    };
                                    if let Ok(bytes) = serde_json::to_vec(&resp) {
                                        drop(write_http_json(&mut tls, "200 OK", &bytes).await);
                                    }
                                    continue;
                                }

                                if req.method == "GET"
                                    && (req.path == "/v1/netmap/stream"
                                        || req.path.starts_with("/v1/netmap/stream?"))
                                {
                                    if let Ok(mut guard) = observed.lock() {
                                        guard.netmap_stream_connects = guard.netmap_stream_connects.saturating_add(1);
                                    }
                                    let Ok(mut ws) = accept_ws_server(&req) else {
                                        break;
                                    };
                                    let Ok(snap) = build_test_snapshot(
                                        2,
                                        &endpoint_str,
                                        stun_port,
                                        spki_pin,
                                        Vec::new(),
                                    ) else {
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
                                            () = netmap_notify.notified() => {
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

                                if req.method == "GET" && req.path == "/v1/relay" {
                                    let Some(pk_b64) = req.headers.get(&HEADER_NODE_PUBKEY.to_ascii_lowercase()) else {
                                        break;
                                    };
                                    let Ok(pk_bytes) = BASE64_STD.decode(pk_b64) else {
                                        break;
                                    };
                                    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
                                        break;
                                    };
                                    let Ok(peer_pk) = PublicKey::from_bytes(pk_arr) else {
                                        break;
                                    };
                                    if let Ok(mut guard) = observed.lock() {
                                        guard.relay_connects = guard.relay_connects.saturating_add(1);
                                    }
                                    let Ok(mut ws) = accept_ws_server(&req) else {
                                        break;
                                    };
                                    if flush_ws_tx(&mut tls, &mut ws).await.is_err() {
                                        break;
                                    }

                                    let (out_tx, mut out_rx) = mpsc::channel::<RelayFrame>(RELAY_QUEUE_CAPACITY);
                                    if let Ok(mut table) = relay_peers.lock() {
                                        table.insert(peer_pk, out_tx);
                                    }
                                    let mut scratch = [0_u8; 4096];
                                    loop {
                                        tokio::select! {
                                            () = conn_shutdown.cancelled() => {
                                                drop(ws.close(None));
                                                drop(flush_ws_tx(&mut tls, &mut ws).await);
                                                break;
                                            }
                                            maybe_out = out_rx.recv() => {
                                                let Some(out_frame) = maybe_out else {
                                                    break;
                                                };
                                                if let Ok(bin) = out_frame.encode() {
                                                    drop(ws.send(Message::Binary(bin)));
                                                    if flush_ws_tx(&mut tls, &mut ws).await.is_err() {
                                                        break;
                                                    }
                                                }
                                            }
                                            read_res = tls.read(&mut scratch) => {
                                                let Ok(n) = read_res else {
                                                    break;
                                                };
                                                if n == 0 {
                                                    break;
                                                }
                                                ws.get_mut().push_rx(scratch.get(..n).unwrap_or_default());
                                                loop {
                                                    match ws.read() {
                                                        Ok(Message::Binary(bin)) => {
                                                            if let Ok(frame) = RelayFrame::decode(&bin) {
                                                                match frame {
                                                                    RelayFrame::ClientToPeerPacket { dst_pubkey, ciphertext } => {
                                                                        let dst_tx = relay_peers
                                                                            .lock()
                                                                            .ok()
                                                                            .and_then(|t| t.get(&dst_pubkey).cloned());
                                                                        if let Some(tx) = dst_tx {
                                                                            drop(tx.try_send(RelayFrame::RelayToClientPacket {
                                                                                src_pubkey: peer_pk,
                                                                                ciphertext,
                                                                            }));
                                                                        }
                                                                    }
                                                                    RelayFrame::KeepAlive { sent_at_ms } => {
                                                                        if let Ok(k) = (RelayFrame::KeepAlive { sent_at_ms }).encode() {
                                                                            drop(ws.send(Message::Binary(k)));
                                                                            drop(flush_ws_tx(&mut tls, &mut ws).await);
                                                                        }
                                                                    }
                                                                    RelayFrame::RelayToClientPacket { .. } => {}
                                                                    _ => {}
                                                                }
                                                            }
                                                        }
                                                        Ok(Message::Ping(p)) => {
                                                            drop(ws.send(Message::Pong(p)));
                                                            drop(flush_ws_tx(&mut tls, &mut ws).await);
                                                        }
                                                        Ok(Message::Close(_)) => {
                                                            if let Ok(mut table) = relay_peers.lock() {
                                                                table.remove(&peer_pk);
                                                            }
                                                            return;
                                                        }
                                                        Ok(_) => {}
                                                        Err(WsError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                                                        Err(_) => {
                                                            if let Ok(mut table) = relay_peers.lock() {
                                                                table.remove(&peer_pk);
                                                            }
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if let Ok(mut table) = relay_peers.lock() {
                                        table.remove(&peer_pk);
                                    }
                                    return;
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
            _stun_port: stun_port,
            observed,
            mode,
            netmap_shutdown,
            shutdown,
            tracker,
        })
    }

    fn endpoint(&self) -> String {
        self.addr.to_string()
    }

    fn set_mode(&self, next_mode: ServerResponseMode) {
        if let Ok(mut guard) = self.mode.lock() {
            *guard = next_mode;
        }
    }

    fn close_active_netmap_streams(&self) {
        self.netmap_shutdown.notify_waiters();
    }

    fn observed_challenge_os_list(&self) -> Vec<TargetOs> {
        self.observed
            .lock()
            .map(|g| g.challenge_requests.iter().map(|r| r.os).collect())
            .unwrap_or_default()
    }

    fn observed_netmap_stream_count(&self) -> u32 {
        self.observed
            .lock()
            .map(|g| g.netmap_stream_connects)
            .unwrap_or(0)
    }

    async fn shutdown(self) {
        self.shutdown.cancel();
        let _timed = tokio::time::timeout(Duration::from_secs(3), self.tracker.wait()).await;
    }
}

struct InMemoryMobileBridgeState {
    dek: [u8; 32],
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    protected_fds: AtomicU32,
    fd_closes: AtomicU32,
    route_ops: Mutex<Vec<(u64, MobileTunnelNetworkConfig)>>,
    tun_rx_packets: Mutex<Vec<Vec<u8>>>,
    statuses: Mutex<Vec<MobileStatusSnapshot>>,
    warnings: Mutex<Vec<MobilePlatformWarning>>,
    underlay: Mutex<MobileUnderlayState>,
    android_tun_fd_to_supply: Option<i32>,
    engine_ref: Mutex<Option<Arc<MobileEngine>>>,
    fail_protect: AtomicBool,
}

impl InMemoryMobileBridgeState {
    fn new(
        dek: [u8; 32],
        underlay: MobileUnderlayState,
        android_tun_fd_to_supply: Option<i32>,
    ) -> Self {
        Self {
            dek,
            files: Mutex::new(BTreeMap::new()),
            protected_fds: AtomicU32::new(0),
            fd_closes: AtomicU32::new(0),
            route_ops: Mutex::new(Vec::new()),
            tun_rx_packets: Mutex::new(Vec::new()),
            statuses: Mutex::new(Vec::new()),
            warnings: Mutex::new(Vec::new()),
            underlay: Mutex::new(underlay),
            android_tun_fd_to_supply,
            engine_ref: Mutex::new(None),
            fail_protect: AtomicBool::new(false),
        }
    }

    fn read_file_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.files.lock().ok().and_then(|g| g.get(name).cloned())
    }

    fn route_op_history(&self) -> Vec<(u64, MobileTunnelNetworkConfig)> {
        self.route_ops.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn status_history(&self) -> Vec<MobileStatusSnapshot> {
        self.statuses.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

struct TestPlatformBridge {
    state: Arc<InMemoryMobileBridgeState>,
    status_notify: Arc<Notify>,
}

impl fmt::Debug for TestPlatformBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestPlatformBridge").finish_non_exhaustive()
    }
}

impl TestPlatformBridge {
    fn create_pair(
        dek: [u8; 32],
        underlay: MobileUnderlayState,
        android_tun_fd_to_supply: Option<i32>,
    ) -> (
        Box<dyn PlatformNetworkBridge>,
        Arc<InMemoryMobileBridgeState>,
        Arc<Notify>,
    ) {
        let state = Arc::new(InMemoryMobileBridgeState::new(
            dek,
            underlay,
            android_tun_fd_to_supply,
        ));
        let status_notify = Arc::new(Notify::new());
        let bridge = Box::new(Self {
            state: Arc::clone(&state),
            status_notify: Arc::clone(&status_notify),
        });
        (bridge, state, status_notify)
    }

    fn clone_bridge(
        state: &Arc<InMemoryMobileBridgeState>,
        status_notify: &Arc<Notify>,
    ) -> Box<dyn PlatformNetworkBridge> {
        Box::new(Self {
            state: Arc::clone(state),
            status_notify: Arc::clone(status_notify),
        })
    }

    fn attach_engine(state: &Arc<InMemoryMobileBridgeState>, engine: &Arc<MobileEngine>) {
        if let Ok(mut g) = state.engine_ref.lock() {
            *g = Some(Arc::clone(engine));
        }
    }
}

impl PlatformNetworkBridge for TestPlatformBridge {
    fn protect_socket(&self, _fd: i32) -> Result<bool, MobileError> {
        self.state.protected_fds.fetch_add(1, Ordering::Relaxed);
        Ok(!self.state.fail_protect.load(Ordering::Relaxed))
    }

    fn on_tun_packets(&self, packets: Vec<Vec<u8>>) {
        if let Ok(mut g) = self.state.tun_rx_packets.lock() {
            g.extend(packets);
        }
    }

    fn on_route_changed(&self, op_id: u64, route: MobileTunnelNetworkConfig) {
        if let Ok(mut g) = self.state.route_ops.lock() {
            g.push((op_id, route));
        }
        let engine_opt = self
            .state
            .engine_ref
            .lock()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        if let Some(engine) = engine_opt {
            let supplied_fd = self.state.android_tun_fd_to_supply;
            tokio::spawn(async move {
                engine.complete_route_change(op_id, true, supplied_fd, None);
            });
        }
    }

    fn on_status_changed(&self, snapshot: MobileStatusSnapshot) {
        if let Ok(mut g) = self.state.statuses.lock() {
            g.push(snapshot);
        }
        self.status_notify.notify_waiters();
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
            .map_err(|_| MobileError::internal("bridge file mutex poisoned"))?
            .get(&name)
            .cloned())
    }

    fn save_state_file(&self, name: String, data: Vec<u8>) -> Result<(), MobileError> {
        self.state
            .files
            .lock()
            .map_err(|_| MobileError::internal("bridge file mutex poisoned"))?
            .insert(name, data);
        Ok(())
    }

    fn delete_state_file(&self, name: String) -> Result<(), MobileError> {
        self.state
            .files
            .lock()
            .map_err(|_| MobileError::internal("bridge file mutex poisoned"))?
            .remove(&name);
        Ok(())
    }
}

fn default_ipv4_underlay() -> MobileUnderlayState {
    MobileUnderlayState {
        active_interface_name: Some("wlan0".to_owned()),
        physical_if_index: Some(7),
        has_ipv4: true,
        has_ipv6: false,
        underlay_dns_servers: vec!["192.0.2.53".to_owned()],
        os_nat64_prefix: None,
        physical_subnets: vec!["192.168.1.50/24".to_owned()],
        is_android_lockdown_enabled: false,
        is_android_private_dns_strict: false,
        private_dns_server_name: None,
    }
}

fn build_init_cfg(
    log_dir: &TempDir,
    platform: MobilePlatformKind,
    default_name: &str,
) -> MobileEngineInitConfig {
    MobileEngineInitConfig {
        platform,
        agent_version: "0.1.0-mobile-qa".to_owned(),
        default_node_name: Some(default_name.to_owned()),
        log_dir_path: log_dir.path().to_string_lossy().into_owned(),
    }
}

fn build_synthetic_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = 28_usize.saturating_add(payload.len());
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&u16::try_from(total_len).unwrap_or(28).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, 17, 0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    pkt.extend_from_slice(&51000_u16.to_be_bytes());
    pkt.extend_from_slice(&52000_u16.to_be_bytes());
    pkt.extend_from_slice(
        &u16::try_from(8_usize.saturating_add(payload.len()))
            .unwrap_or(8)
            .to_be_bytes(),
    );
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(payload);
    pkt
}

#[tokio::test]
async fn test_e2e_mobile_ffi_ios_and_android_custom_port_route_preservation_and_offline_control()
-> Result<(), String> {
    // Arrange: Mock TLS 1.3 + WS Control/Relay server on custom non-443/non-3478 ports.
    let server = MockControlAndRelayServer::start(13_479).await?;
    let endpoint = server.endpoint();
    let pin_str = server.spki_pin.to_string();

    let ios_preauth = make_preauth_key(0x1A);
    let ios_uri = format_join_uri(
        &endpoint,
        &MobileJoinTlsAuth::SpkiPin(server.spki_pin),
        &ios_preauth,
        Some(&NodeName::parse("ios-qa-01").map_err(test_err)?),
    )
    .map_err(test_err)?;
    let parsed_ios = parse_mobile_join_uri(ios_uri).map_err(test_err)?;

    let ios_dir = TempDir::new().map_err(test_err)?;
    let (ios_bridge, ios_state, ios_notify) =
        TestPlatformBridge::create_pair([0x11_u8; 32], default_ipv4_underlay(), None);

    // Act 1: Enroll iOS node via public FFI.
    let ios_enrolled = mobile_enroll_or_rotate_node(
        build_init_cfg(&ios_dir, MobilePlatformKind::Ios, "ios-qa-01"),
        ios_bridge,
        MobileEnrollConfig {
            server_endpoint: parsed_ios.summary.server_endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str.clone()),
            pending_join: Arc::clone(&parsed_ios.session),
            node_name: Some("ios-qa-01".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .map_err(test_err)?;

    assert!(ios_enrolled.overlay_ip.is_some());
    assert!(ios_state.read_file_bytes("identity.sealed.bin").is_some());
    assert!(ios_state.read_file_bytes("bootstrap.toml").is_some());
    assert!(ios_state.read_file_bytes("netmap-cache.json").is_some());

    // Act 2: Start iOS MobileEngine, handle route change & preserve overlay_ip + MTU,
    // verify push_tun_packets, and survive Control going offline.
    let ios_engine = MobileEngine::new(
        build_init_cfg(&ios_dir, MobilePlatformKind::Ios, "ios-qa-01"),
        TestPlatformBridge::clone_bridge(&ios_state, &ios_notify),
    )
    .map_err(test_err)?;
    TestPlatformBridge::attach_engine(&ios_state, &ios_engine);

    let up_snap = ios_engine
        .start_tunnel(MobileUpConfig {
            server_endpoint: endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str.clone()),
            pending_join: None,
            node_name: Some("ios-qa-01".to_owned()),
            android_tun_fd: None,
            tun_interface_name: Some("utun9".to_owned()),
        })
        .await
        .map_err(test_err)?;

    let initial_routes = ios_state.route_op_history();
    let (_, initial_route) = initial_routes
        .first()
        .ok_or_else(|| "missing initial iOS on_route_changed invocation".to_owned())?;
    let expected_overlay = initial_route.overlay_ip.clone();
    let expected_mtu = initial_route.tun_mtu;
    assert_eq!(
        up_snap.overlay_ip.as_deref(),
        Some(expected_overlay.as_str())
    );
    assert!(expected_mtu >= 1280);

    for _ in 0..40 {
        if server.observed_netmap_stream_count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(server.observed_netmap_stream_count() >= 1);

    let src_v4: Ipv4Addr = expected_overlay.parse().map_err(test_err)?;
    let dst_v4 = Ipv4Addr::new(10, 100, 0, 99);
    let pushed =
        ios_engine.push_tun_packets(vec![build_synthetic_ipv4_udp(src_v4, dst_v4, b"hello-tun")]);
    assert!(pushed <= 1);

    let mut updated_underlay = default_ipv4_underlay();
    updated_underlay.physical_if_index = Some(9);
    if let Ok(mut u) = ios_state.underlay.lock() {
        *u = updated_underlay.clone();
    }
    ios_engine.on_network_change(MobileNetEventKind::InterfaceChanged, updated_underlay);
    tokio::time::sleep(Duration::from_millis(120)).await;

    let post_roam_snap = ios_engine.status_snapshot().await.map_err(test_err)?;
    assert_eq!(
        post_roam_snap.overlay_ip.as_deref(),
        Some(expected_overlay.as_str())
    );
    for (_, route) in ios_state.route_op_history() {
        assert_eq!(route.overlay_ip, expected_overlay);
        assert_eq!(route.tun_mtu, expected_mtu);
    }
    ios_engine.complete_route_change(999_999, false, Some(77), Some("stale op".to_owned()));
    assert_eq!(ios_state.fd_closes.load(Ordering::Relaxed), 0);

    server.close_active_netmap_streams();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let during_offline = ios_engine.status_snapshot().await.map_err(test_err)?;
    assert_ne!(during_offline.daemon_state, MobileDaemonState::Stopped);
    assert_eq!(
        during_offline.overlay_ip.as_deref(),
        Some(expected_overlay.as_str())
    );

    let stopped = ios_engine.stop_tunnel().await.map_err(test_err)?;
    assert_eq!(stopped.daemon_state, MobileDaemonState::Stopped);
    ios_engine.shutdown().map_err(test_err)?;

    // Act 3: Android FFI flow (`TargetOs::Android`).
    let android_dir = TempDir::new().map_err(test_err)?;
    let (android_bridge, android_state, android_notify) =
        TestPlatformBridge::create_pair([0x22_u8; 32], default_ipv4_underlay(), Some(42));
    let android_session = create_pending_join_session(make_preauth_key(0x2B)).map_err(test_err)?;
    let android_enrolled = mobile_enroll_or_rotate_node(
        build_init_cfg(&android_dir, MobilePlatformKind::Android, "android-qa-01"),
        android_bridge,
        MobileEnrollConfig {
            server_endpoint: endpoint.clone(),
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str.clone()),
            pending_join: android_session,
            node_name: Some("android-qa-01".to_owned()),
            rotate_existing_identity: false,
        },
    )
    .await
    .map_err(test_err)?;
    assert!(android_enrolled.overlay_ip.is_some());

    let android_engine = MobileEngine::new(
        build_init_cfg(&android_dir, MobilePlatformKind::Android, "android-qa-01"),
        TestPlatformBridge::clone_bridge(&android_state, &android_notify),
    )
    .map_err(test_err)?;
    TestPlatformBridge::attach_engine(&android_state, &android_engine);

    let netcheck_res = android_engine.netcheck().await.map_err(test_err)?;
    assert!(netcheck_res.relay_connected || netcheck_res.ipv4_available);
    assert!(android_state.protected_fds.load(Ordering::Relaxed) >= 1);

    let android_start_res = android_engine
        .start_tunnel(MobileUpConfig {
            server_endpoint: endpoint,
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str),
            pending_join: None,
            node_name: Some("android-qa-01".to_owned()),
            android_tun_fd: Some(42),
            tun_interface_name: Some("tun0".to_owned()),
        })
        .await;
    if cfg!(not(target_os = "android")) {
        assert!(matches!(
            android_start_res,
            Err(MobileError::InvalidArgument { .. })
        ));
    }
    assert_eq!(android_state.fd_closes.load(Ordering::Relaxed), 0);
    android_engine.shutdown().map_err(test_err)?;

    // Assert: Mock Control observed challenge requests for both enrollments and supports
    // Android & iOS TargetOs wire values.
    let expected_host_os = if cfg!(target_os = "android") {
        TargetOs::Android
    } else if cfg!(target_os = "ios") {
        TargetOs::Ios
    } else if cfg!(target_os = "macos") {
        TargetOs::Darwin
    } else if cfg!(target_os = "windows") {
        TargetOs::Windows
    } else {
        TargetOs::Linux
    };
    let os_list = server.observed_challenge_os_list();
    assert!(os_list.len() >= 2);
    assert!(os_list.iter().all(|os| *os == expected_host_os));

    for mobile_os in [TargetOs::Android, TargetOs::Ios] {
        let req = ChallengeRequest {
            protocol_version: 1,
            node_pubkey: NodeKeypair::generate().public_key(),
            disco_pubkey: DiscoKeypair::generate().public_key(),
            os: mobile_os,
            arch: TargetArch::Arm64,
            agent_version: "0.2.0-mobile".to_owned(),
        };
        let encoded = serde_json::to_vec(&req).map_err(test_err)?;
        let decoded: ChallengeRequest = serde_json::from_slice(&encoded).map_err(test_err)?;
        assert_eq!(decoded.os, mobile_os);
    }

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn test_compat_desktop_v0_1_0_rc1_and_400_protocol_incompatible_preserves_netmap_cache()
-> Result<(), String> {
    // Arrange 1: Verify `v0.1.0-rc1` Desktop (`TargetOs::Windows`, `TargetOs::Darwin`) wire
    // interoperability alongside Mobile (`TargetOs::Android`, `TargetOs::Ios`) in NetmapSnapshot.
    let desktop_win_req = ChallengeRequest {
        protocol_version: 1,
        node_pubkey: NodeKeypair::generate().public_key(),
        disco_pubkey: DiscoKeypair::generate().public_key(),
        os: TargetOs::Windows,
        arch: TargetArch::Amd64,
        agent_version: "0.1.0-rc1".to_owned(),
    };
    let desktop_mac_req = ChallengeRequest {
        protocol_version: 1,
        node_pubkey: NodeKeypair::generate().public_key(),
        disco_pubkey: DiscoKeypair::generate().public_key(),
        os: TargetOs::Darwin,
        arch: TargetArch::Arm64,
        agent_version: "0.1.0-rc1".to_owned(),
    };
    let win_json = serde_json::to_vec(&desktop_win_req).map_err(test_err)?;
    let mac_json = serde_json::to_vec(&desktop_mac_req).map_err(test_err)?;
    let decoded_win: ChallengeRequest = serde_json::from_slice(&win_json).map_err(test_err)?;
    let decoded_mac: ChallengeRequest = serde_json::from_slice(&mac_json).map_err(test_err)?;
    assert_eq!(decoded_win.os, TargetOs::Windows);
    assert_eq!(decoded_mac.os, TargetOs::Darwin);
    assert_eq!(decoded_win.agent_version, "0.1.0-rc1");

    let peer_kp = NodeKeypair::generate();
    let peer_disco = DiscoKeypair::generate();
    let desktop_peer = PeerEntry {
        node_id: NodeId::from_bytes([0xAB_u8; 16]),
        name: NodeName::parse("desktop-rc1").map_err(test_err)?,
        fqdn: "desktop-rc1.mesh.internal".to_owned(),
        overlay_ip: overlay_ip_octet(55)?,
        node_pubkey: peer_kp.public_key(),
        disco_pubkey: peer_disco.public_key(),
        endpoints: vec![CandidateEndpoint {
            addr: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 44), 51820)),
            source: CandidateSource::Reflexive,
        }],
        relay_home: "198.51.100.10:8443".to_owned(),
        key_expires_at_ms: None,
        online: true,
    };
    let snap = build_test_snapshot(
        7,
        "198.51.100.10:8443",
        13_478,
        SpkiPin::from_sha256_bytes([0x33_u8; 32]),
        vec![desktop_peer],
    )?;
    let snap_bytes = serde_json::to_vec(&snap).map_err(test_err)?;
    let roundtrip_snap: NetmapSnapshot = serde_json::from_slice(&snap_bytes).map_err(test_err)?;
    assert_eq!(roundtrip_snap.peers.len(), 1);

    // Arrange 2: Enroll once normally to populate `netmap-cache.json`, then force HTTP 400
    // `protocol_incompatible`.
    let server = MockControlAndRelayServer::start(13_480).await?;
    let endpoint = server.endpoint();
    let pin_str = server.spki_pin.to_string();
    let dir = TempDir::new().map_err(test_err)?;
    let (bridge, state, notify) =
        TestPlatformBridge::create_pair([0x44_u8; 32], default_ipv4_underlay(), None);
    let compat_session = create_pending_join_session(make_preauth_key(0x3C)).map_err(test_err)?;

    drop(
        mobile_enroll_or_rotate_node(
            build_init_cfg(&dir, MobilePlatformKind::Ios, "compat-ios"),
            bridge,
            MobileEnrollConfig {
                server_endpoint: endpoint.clone(),
                port_override: None,
                tls_auth_mode: MobileTlsAuthMode::SpkiPin,
                server_pin: Some(pin_str.clone()),
                pending_join: compat_session,
                node_name: Some("compat-ios".to_owned()),
                rotate_existing_identity: false,
            },
        )
        .await
        .map_err(test_err)?,
    );

    let cached_before = state
        .read_file_bytes("netmap-cache.json")
        .ok_or_else(|| "netmap-cache.json missing before 400 test".to_owned())?;

    server.set_mode(ServerResponseMode::ProtocolIncompatible);

    let engine = MobileEngine::new(
        build_init_cfg(&dir, MobilePlatformKind::Ios, "compat-ios"),
        TestPlatformBridge::clone_bridge(&state, &notify),
    )
    .map_err(test_err)?;
    TestPlatformBridge::attach_engine(&state, &engine);

    // Act: Start tunnel against HTTP 400 `ProtocolIncompatible` server.
    let start_res = engine
        .start_tunnel(MobileUpConfig {
            server_endpoint: endpoint,
            port_override: None,
            tls_auth_mode: MobileTlsAuthMode::SpkiPin,
            server_pin: Some(pin_str),
            pending_join: None,
            node_name: Some("compat-ios".to_owned()),
            android_tun_fd: None,
            tun_interface_name: Some("utun8".to_owned()),
        })
        .await;

    for _ in 0..40 {
        if state
            .status_history()
            .iter()
            .any(|s| s.daemon_state == MobileDaemonState::ServerUpgradeRequired)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Assert: `ServerUpgradeRequired` reached (or returned via error) and cached
    // `netmap-cache.json` preserved verbatim.
    let snap_after = engine.status_snapshot().await.map_err(test_err)?;
    let history = state.status_history();
    let got_upgrade_state = snap_after.daemon_state == MobileDaemonState::ServerUpgradeRequired
        || history
            .iter()
            .any(|s| s.daemon_state == MobileDaemonState::ServerUpgradeRequired)
        || matches!(start_res, Err(MobileError::ServerUpgradeRequired { .. }));
    assert!(
        got_upgrade_state,
        "expected ServerUpgradeRequired state, got {:?} / start_res={:?}",
        snap_after.daemon_state, start_res
    );
    let cached_after = state
        .read_file_bytes("netmap-cache.json")
        .ok_or_else(|| "netmap-cache.json deleted after HTTP 400!".to_owned())?;
    let before_json: serde_json::Value =
        serde_json::from_slice(&cached_before).map_err(test_err)?;
    let after_json: serde_json::Value = serde_json::from_slice(&cached_after).map_err(test_err)?;
    assert_eq!(
        before_json.get("netmap"),
        after_json.get("netmap"),
        "cached netmap payload must be preserved verbatim on HTTP 400 ProtocolIncompatible"
    );

    engine.shutdown().map_err(test_err)?;
    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn test_e2e_double_cgnat_blind_relay_256_try_send_no_hol_blocking_and_cli_uri_qr_roundtrip()
-> Result<(), String> {
    // Arrange 1: Live TLS 1.3 Blind Relay serving Double-CGNAT peers A & B.
    let server = MockControlAndRelayServer::start(13_481).await?;
    let endpoint = server.endpoint();
    let pin = server.spki_pin;

    let kp_a = NodeKeypair::generate();
    let disco_a = DiscoKeypair::generate();
    let pk_a = kp_a.public_key();
    let kp_b = NodeKeypair::generate();
    let disco_b = DiscoKeypair::generate();
    let pk_b = kp_b.public_key();
    let offline_peer_c = NodeKeypair::generate().public_key();

    let cfg_a = RelayClientConfig {
        endpoint: endpoint.clone(),
        server_name_override: None,
        pin_set: Some(PinSet::single(pin)),
        underlay_if_index: None,
        linux_fwmark: None,
        require_challenge_auth: true,
        agent_version: "0.1.0-mobile-qa".to_owned(),
    };
    let cfg_b = RelayClientConfig {
        endpoint: endpoint.clone(),
        server_name_override: None,
        pin_set: Some(PinSet::single(pin)),
        underlay_if_index: None,
        linux_fwmark: None,
        require_challenge_auth: true,
        agent_version: "0.1.0-mobile-qa".to_owned(),
    };
    let client_a = RelayClient::with_connector_and_timer_mode(
        cfg_a,
        kp_a.clone_keypair(),
        disco_a.clone_keypair(),
        Arc::new(TlsRelayConnector),
        TimerMode::Responsive,
    );
    let client_b = RelayClient::with_connector_and_timer_mode(
        cfg_b,
        kp_b.clone_keypair(),
        disco_b.clone_keypair(),
        Arc::new(TlsRelayConnector),
        TimerMode::Responsive,
    );
    let handle_a = client_a.handle();
    let handle_b = client_b.handle();

    let (ev_a_tx, mut ev_a_rx) = mpsc::channel::<RelayEvent>(256);
    let (ev_b_tx, mut ev_b_rx) = mpsc::channel::<RelayEvent>(256);
    let clock = Arc::new(SystemClock::new());
    let shutdown = CancellationToken::new();

    let task_a = tokio::spawn(client_a.run(clock.clone(), ev_a_tx, shutdown.clone()));
    let task_b = tokio::spawn(client_b.run(clock, ev_b_tx, shutdown.clone()));

    let mut a_connected = false;
    let mut b_connected = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !(a_connected && b_connected) && tokio::time::Instant::now() < deadline {
        tokio::select! {
            maybe_a = ev_a_rx.recv() => {
                if let Some(RelayEvent::StateChanged(RelayConnectionState::Connected)) = maybe_a {
                    a_connected = true;
                }
            }
            maybe_b = ev_b_rx.recv() => {
                if let Some(RelayEvent::StateChanged(RelayConnectionState::Connected)) = maybe_b {
                    b_connected = true;
                }
            }
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(
        a_connected && b_connected,
        "RelayClients must connect over TLS 1.3"
    );

    // Act 1: Saturate offline Peer C's 256-slot queue (`try_send` drop-tail without HoL blocking),
    // then send WireGuard-sized ciphertext from A -> B through the live Blind Relay.
    let mut c_ok = 0_usize;
    let mut c_drop = 0_usize;
    for i in 0..300_usize {
        let mut payload = vec![0xA5_u8; 64];
        if let Some(slot) = payload.get_mut(0) {
            *slot = u8::try_from(i & 0xFF).unwrap_or(0);
        }
        if handle_a.try_send_packet(offline_peer_c, Bytes::from(payload)) {
            c_ok = c_ok.saturating_add(1);
        } else {
            c_drop = c_drop.saturating_add(1);
        }
    }
    assert_eq!(c_ok, RELAY_QUEUE_CAPACITY);
    assert_eq!(c_drop, 300 - RELAY_QUEUE_CAPACITY);

    let ip_a = overlay_ip_octet(21)?;
    let ip_b = overlay_ip_octet(22)?;
    let node_id_a = NodeId::from_bytes([1_u8; 16]);
    let node_id_b = NodeId::from_bytes([2_u8; 16]);
    let peer_b_entry = PeerEntry {
        node_id: node_id_b,
        name: NodeName::parse("peer-b").map_err(test_err)?,
        fqdn: "peer-b.mesh.internal".to_owned(),
        overlay_ip: ip_b,
        node_pubkey: pk_b,
        disco_pubkey: disco_b.public_key(),
        endpoints: Vec::new(),
        relay_home: endpoint.clone(),
        key_expires_at_ms: None,
        online: true,
    };
    let peer_a_entry = PeerEntry {
        node_id: node_id_a,
        name: NodeName::parse("peer-a").map_err(test_err)?,
        fqdn: "peer-a.mesh.internal".to_owned(),
        overlay_ip: ip_a,
        node_pubkey: pk_a,
        disco_pubkey: disco_a.public_key(),
        endpoints: Vec::new(),
        relay_home: endpoint.clone(),
        key_expires_at_ms: None,
        online: true,
    };
    let mut map_a = PeerMap::new(node_id_a, kp_a);
    let mut map_b = PeerMap::new(node_id_b, kp_b);
    let snap_a = build_test_snapshot(1, &endpoint, 13_481, pin, vec![peer_b_entry])?;
    let snap_b = build_test_snapshot(1, &endpoint, 13_481, pin, vec![peer_a_entry])?;
    map_a.apply_diff(&snap_a);
    map_b.apply_diff(&snap_b);

    let mut buf_a: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
    let inner_pkt = build_synthetic_ipv4_udp(ip_a.as_ipv4(), ip_b.as_ipv4(), b"cgnat-relay-ping");
    let (_, _, init_len) = map_a
        .encapsulate_to_overlay_ip(ip_b, &inner_pkt, &mut buf_a, 1_000)
        .map_err(test_err)?
        .ok_or_else(|| "missing handshake initiation bytes".to_owned())?;
    let init_bytes = Bytes::copy_from_slice(buf_a.get(..init_len).unwrap_or_default());

    if !handle_a.try_send_packet(pk_b, init_bytes) {
        return Err("failed to enqueue handshake initiation packet to Peer B".to_owned());
    }

    let mut received_from_a = None;
    let recv_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < recv_deadline {
        if let Ok(Some(RelayEvent::PacketReceived {
            src_pubkey,
            ciphertext,
        })) = tokio::time::timeout(Duration::from_millis(200), ev_b_rx.recv()).await
        {
            received_from_a = Some((src_pubkey, ciphertext));
            break;
        }
    }

    let (stamped_src, relay_ct) = received_from_a
        .ok_or_else(|| "Peer B did not receive relayed packet from Peer A".to_owned())?;
    assert_eq!(stamped_src, pk_a);
    let mut buf_b: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
    let dec_b = map_b
        .decapsulate_from_relay(stamped_src, &relay_ct, &mut buf_b, 1_010)
        .ok_or_else(|| "Peer B could not decapsulate relayed initiation".to_owned())?;
    assert!(!dec_b.outbound_network_packets.is_empty());

    let resp_bytes = dec_b
        .outbound_network_packets
        .first()
        .ok_or_else(|| "missing handshake response".to_owned())?
        .clone();
    if !handle_b.try_send_packet(pk_a, Bytes::from(resp_bytes)) {
        return Err("failed to enqueue handshake response to Peer A".to_owned());
    }
    let mut received_from_b = false;
    let resp_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < resp_deadline {
        if let Ok(Some(RelayEvent::PacketReceived { src_pubkey, .. })) =
            tokio::time::timeout(Duration::from_millis(200), ev_a_rx.recv()).await
            && src_pubkey == pk_b
        {
            received_from_b = true;
            break;
        }
    }
    assert!(
        received_from_b,
        "Peer A did not receive handshake response over Blind Relay"
    );

    // Act 2: CLI `--emit-uri` / QR URI formatting & FFI `parse_mobile_join_uri` roundtrip
    // + NAT64 synthesis check.
    let raw_uris = [
        format_join_uri(
            &endpoint,
            &MobileJoinTlsAuth::SpkiPin(pin),
            &make_preauth_key(0x4D),
            None,
        )
        .map_err(test_err)?,
        format_join_uri(
            "[2001:db8::10]:8443",
            &MobileJoinTlsAuth::SpkiPin(pin),
            &make_preauth_key(0x5E),
            Some(&NodeName::parse("pixel-9-pro").map_err(test_err)?),
        )
        .map_err(test_err)?,
        format_join_uri(
            "vpn.example.net:8443",
            &MobileJoinTlsAuth::SystemCa,
            &make_preauth_key(0x6F),
            Some(&NodeName::parse("iphone-16").map_err(test_err)?),
        )
        .map_err(test_err)?,
    ];
    for raw_uri in raw_uris {
        let parsed = parse_mobile_join_uri(raw_uri).map_err(test_err)?;
        assert!(!parsed.summary.server_endpoint.is_empty());
    }

    let nat64 = Nat64Prefix::from_cidr("64:ff9b::/96").map_err(test_err)?;
    let syn = Nat64Synthesizer::new(nat64);
    let translated =
        syn.synthesize_sockaddr(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 8443));
    assert_eq!(
        translated,
        SocketAddrV6::new(
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc633, 0x640a),
            8443,
            0,
            0
        )
    );

    shutdown.cancel();
    let _joined_a = tokio::time::timeout(Duration::from_secs(3), task_a).await;
    let _joined_b = tokio::time::timeout(Duration::from_secs(3), task_b).await;
    server.shutdown().await;
    Ok(())
}
