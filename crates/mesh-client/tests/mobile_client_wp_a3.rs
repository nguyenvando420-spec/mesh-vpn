//! WP-M-A3 integration & edge-case tests for shared OS-neutral `mesh-client` runtime (`US-099`).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use proptest::strategy::Just;
use proptest::{prop_assert, prop_assert_eq, prop_assert_ne, prop_oneof, proptest};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Message as WsMessage, accept_with_config};
use tokio_util::sync::CancellationToken;

use mesh_client::config::{
    BootstrapConfig, ClientRuntimeConfig, SplitTunnelCidr, compute_split_tunnel_routes,
    current_target_os, derive_overlay_dns_ip,
};
use mesh_client::control_loop::{
    ControlDialOptions, ControlLoop, connect_control_tls_with_protector,
    probe_udp_routing_candidates_protected,
};
use mesh_client::diagnostics::{BugreportBuildOptions, create_bugreport_tar_bundle};
use mesh_client::hooks::{
    ClientPlatformHooks as _, ClientStateStore as _, FileClientStateStore,
    InMemoryClientPlatformHooks, InMemoryClientStateStore,
};
use mesh_client::netmap_cache::NetmapCacheFile;
use mesh_client::ping_probe::PingProbe;
use mesh_client::session::{ClientSessionOptions, ClientSessionSupervisor, EnrollOrRotateRequest};
use mesh_client::state::ClientRuntimeState;
use mesh_core::clock::{Clock as _, FakeClock, SystemClock};
use mesh_core::defaults::{
    DEFAULT_MOBILE_COALESCED_HEARTBEAT_MS, DEFAULT_MOBILE_MAX_BUGREPORT_BYTES,
    DEFAULT_MOBILE_MAX_WS_FRAME_BYTES,
};
use mesh_core::{
    AppError, AppResult, ErrorEnvelope, ErrorKind, ErrorResponse, NodeId, NodeName, OverlayCidr,
    OverlayIp, Port, SpkiPin,
};
use mesh_crypto::certgen::{build_rustls_server_config_from_der, generate_ip_pinned_cert};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use mesh_datapath::{
    DatapathConfig, DatapathEngine, DatapathEngineOptions, DiscoConfig, DnsInterceptDecision,
    DnsPacketInterceptor, MagicSocket, MagicSocketConfig, RelayClient, RelayClientConfig,
    RelayClientOptions, RelayConnectionState, RelayEvent, StunClientConfig, TimerMode,
};
use mesh_net::keystore::KeysFileStore;
use mesh_net::nat64::{Nat64Prefix, Nat64Synthesizer, NoopSocketProtector, SocketProtector};
use mesh_net::tun::{FakeTunDevice, TunConfig};
use mesh_proto::agent_ipc::{AgentStatusResponse, DaemonState, SelfNetworkStatus, TlsAuthMode};
use mesh_proto::control::{ChallengeResponse, RegisterNodeRequest, RegisterNodeResponse, TargetOs};
use mesh_proto::netmap::{NatMappingKind, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockEndpointBehavior {
    Http400Challenge,
    Http400Register,
    Http400NetmapWs,
    Http400RelayWs,
    OversizedNetmapFrame,
    EnrollSuccessOnly,
}

#[derive(Debug, Default)]
struct MockServerCounters {
    challenge_hits: AtomicUsize,
    register_hits: AtomicUsize,
    netmap_ws_hits: AtomicUsize,
    relay_ws_hits: AtomicUsize,
}

struct SyncWsBridge {
    rx: VecDeque<u8>,
    tx: Vec<u8>,
}

impl Read for SyncWsBridge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.rx.read(buf)
    }
}

impl Write for SyncWsBridge {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct MockTlsServer {
    addr: SocketAddr,
    pin: SpkiPin,
    counters: Arc<MockServerCounters>,
    shutdown: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MockTlsServer {
    async fn start(
        behavior: MockEndpointBehavior,
        mut sample_netmap: NetmapSnapshot,
    ) -> Option<Self> {
        let now_secs = SystemClock::new().now_unix_ms() / 1000;
        let cert =
            generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 30, now_secs.saturating_sub(60))
                .ok()?;
        let pin = cert.spki_pin;
        let server_cfg =
            build_rustls_server_config_from_der(vec![cert.cert_der], &cert.key_pkcs8_der, vec![])
                .ok()?;
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let addr = listener.local_addr().ok()?;
        sample_netmap.pin_set.active_pin = pin;
        sample_netmap.relay_map.control_tcp_endpoint = addr.to_string();
        let counters = Arc::new(MockServerCounters::default());
        let shutdown = CancellationToken::new();

        let task_counters = Arc::clone(&counters);
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break; };
                        let acc = acceptor.clone();
                        let cnt = Arc::clone(&task_counters);
                        let netmap = sample_netmap.clone();
                        tokio::spawn(async move {
                            let Ok(tls) = acc.accept(tcp).await else { return; };
                            serve_mock_tls_conn(tls, behavior, cnt, netmap).await;
                        });
                    }
                }
            }
        });

        Some(Self {
            addr,
            pin,
            counters,
            shutdown,
            task: Some(task),
        })
    }

    async fn stop(mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.task.take() {
            let _res = handle.await;
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_content_length(head: &str) -> usize {
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            return v.trim().parse::<usize>().unwrap_or(0);
        }
    }
    0
}

async fn read_next_http_head(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    carry: &mut Vec<u8>,
) -> Option<(String, String, Vec<u8>)> {
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(pos) = find_header_end(carry) {
            break pos;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(slice) = chunk.get(..n) {
            carry.extend_from_slice(slice);
        }
    };
    let head_bytes = carry.get(..head_end)?.to_vec();
    let head_str = String::from_utf8_lossy(&head_bytes).into_owned();
    let first_line = head_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("").to_owned();
    let content_len = parse_content_length(&head_str);
    while carry.len() < head_end + content_len {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(slice) = chunk.get(..n) {
            carry.extend_from_slice(slice);
        }
    }
    let total = head_end + content_len;
    let raw_req = carry.drain(..total).collect();
    Some((method, path, raw_req))
}

async fn write_json_response(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    status_line: &str,
    body: &[u8],
) -> bool {
    let head = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return false;
    }
    if stream.write_all(body).await.is_err() {
        return false;
    }
    stream.flush().await.is_ok()
}

fn build_protocol_incompatible_body() -> Vec<u8> {
    let env = ErrorResponse {
        error: ErrorEnvelope {
            kind: ErrorKind::InvalidArgument,
            code: ErrorKind::InvalidArgument.wire_code().to_owned(),
            message: "unknown variant `mobile_future`, expected one of `linux`, `android`, `ios`"
                .to_owned(),
            request_id: "req-compat-check".to_owned(),
        },
    };
    serde_json::to_vec(&env).unwrap_or_default()
}

fn build_challenge_ok_body(now_ms: u64) -> Vec<u8> {
    let eph = NodeKeypair::generate();
    let resp = ChallengeResponse {
        challenge_id: NodeId::new_v7(now_ms),
        server_eph_pubkey: eph.public_key(),
        challenge_nonce: BASE64_STANDARD.encode([0x42u8; 32]),
        server_time_at_ms: now_ms,
        expires_at_ms: now_ms + 30_000,
    };
    serde_json::to_vec(&resp).unwrap_or_default()
}

fn build_register_ok_body(netmap: &NetmapSnapshot) -> Vec<u8> {
    let Ok(name) = "mobile-test".parse::<NodeName>() else {
        return Vec::new();
    };
    let Ok(overlay_ip) = "100.115.0.21".parse::<OverlayIp>() else {
        return Vec::new();
    };
    let resp = RegisterNodeResponse {
        node_id: NodeId::new_v7(1_700_000_000_123),
        node_name: name,
        fqdn: "mobile-test.mesh.internal".to_owned(),
        overlay_ip,
        overlay_cidr: netmap.overlay_cidr,
        key_expires_at_ms: None,
        netmap: netmap.clone(),
    };
    serde_json::to_vec(&resp).unwrap_or_default()
}

async fn write_oversized_ws_frame(stream: &mut TlsStream<tokio::net::TcpStream>, raw_req: Vec<u8>) {
    let bridge = SyncWsBridge {
        rx: VecDeque::from(raw_req),
        tx: Vec::new(),
    };
    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = None;
    cfg.max_frame_size = None;
    if let Ok(mut ws) = accept_with_config(bridge, Some(cfg)) {
        let oversized = "X".repeat(DEFAULT_MOBILE_MAX_WS_FRAME_BYTES + 16_384);
        let _send = ws.send(WsMessage::Text(oversized.into()));
        let bytes = &ws.get_mut().tx;
        if stream.write_all(bytes).await.is_ok() {
            let _flushed = stream.flush().await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

async fn serve_mock_tls_conn(
    mut stream: TlsStream<tokio::net::TcpStream>,
    behavior: MockEndpointBehavior,
    counters: Arc<MockServerCounters>,
    netmap: NetmapSnapshot,
) {
    let now_ms = SystemClock::new().now_unix_ms();
    let mut carry = Vec::new();
    loop {
        let Some((_method, path, raw_req)) = read_next_http_head(&mut stream, &mut carry).await
        else {
            break;
        };
        if path == "/v1/auth/challenge" {
            counters.challenge_hits.fetch_add(1, Ordering::SeqCst);
            if behavior == MockEndpointBehavior::Http400Challenge {
                let body = build_protocol_incompatible_body();
                let _ok = write_json_response(&mut stream, "400 Bad Request", &body).await;
                break;
            }
            let body = build_challenge_ok_body(now_ms);
            if !write_json_response(&mut stream, "200 OK", &body).await {
                break;
            }
            continue;
        }
        if path == "/v1/nodes/register" {
            counters.register_hits.fetch_add(1, Ordering::SeqCst);
            if behavior == MockEndpointBehavior::Http400Register {
                let body = build_protocol_incompatible_body();
                let _ok = write_json_response(&mut stream, "400 Bad Request", &body).await;
                break;
            }
            let body = build_register_ok_body(&netmap);
            let _ok = write_json_response(&mut stream, "200 OK", &body).await;
            continue;
        }
        if path.starts_with("/v1/netmap/stream") {
            counters.netmap_ws_hits.fetch_add(1, Ordering::SeqCst);
            if behavior == MockEndpointBehavior::Http400NetmapWs {
                let body = build_protocol_incompatible_body();
                let _ok = write_json_response(&mut stream, "400 Bad Request", &body).await;
                break;
            }
            if behavior == MockEndpointBehavior::OversizedNetmapFrame {
                write_oversized_ws_frame(&mut stream, raw_req).await;
                break;
            }
        }
        if path.starts_with("/v1/relay") {
            counters.relay_ws_hits.fetch_add(1, Ordering::SeqCst);
            if behavior == MockEndpointBehavior::Http400RelayWs {
                let body = build_protocol_incompatible_body();
                let _ok = write_json_response(&mut stream, "400 Bad Request", &body).await;
            }
            break;
        }
        let _ok = write_json_response(&mut stream, "404 Not Found", b"{}").await;
        break;
    }
}

fn make_sample_netmap(control_ep: &str, relay_ep: &str, pin: SpkiPin) -> Option<NetmapSnapshot> {
    let overlay_cidr = "100.115.0.0/16".parse::<OverlayCidr>().ok()?;
    Some(NetmapSnapshot {
        netmap_version: 7,
        generated_at_ms: 1_700_000_000_000,
        overlay_cidr,
        domain_suffix: "mesh.internal".to_owned(),
        relay_map: RelayMap {
            endpoint_version: 2,
            control_tcp_endpoint: control_ep.to_owned(),
            relay_tcp_endpoint: relay_ep.to_owned(),
            stun_udp_endpoints: vec![],
        },
        pin_set: PinSetDto {
            active_pin: pin,
            next_pin: None,
        },
        peers: vec![],
    })
}

fn seed_enrolled_disk_state(
    state_dir: &Path,
    control_ep: &str,
    pin: SpkiPin,
    netmap: &NetmapSnapshot,
    now_ms: u64,
) -> Option<Vec<u8>> {
    let node_id = NodeId::new_v7(now_ms);
    let keys_store = KeysFileStore::new(state_dir.join("keys.json"));
    let _created = keys_store.load_or_create(now_ms).ok()?;
    let _saved_id = keys_store.set_node_id(node_id).ok()?;

    let store = FileClientStateStore::from_dir(state_dir.to_path_buf());
    let bootstrap = BootstrapConfig {
        node_id: Some(node_id),
        node_name: "pixel-9".parse::<NodeName>().ok(),
        overlay_ip: "100.115.0.15".parse::<OverlayIp>().ok(),
        fqdn: Some("pixel-9.mesh.internal".to_owned()),
        server_endpoint: Some(control_ep.to_owned()),
        tls_auth_mode: TlsAuthMode::SpkiPin,
        active_pin: Some(pin),
        ..BootstrapConfig::default()
    };
    store.save_bootstrap(&bootstrap).ok()?;

    let udp_port = Port::from_u16(51820).ok()?;
    let cache_file = NetmapCacheFile::new_signed(udp_port, netmap.clone(), now_ms, None).ok()?;
    store.save_netmap_cache(&cache_file).ok()?;
    std::fs::read(state_dir.join("netmap-cache.json")).ok()
}

#[derive(Debug)]
struct RecordingSocketProtector {
    deny: AtomicBool,
    calls: AtomicUsize,
    protected_fds: Mutex<Vec<i32>>,
}

impl RecordingSocketProtector {
    fn new(deny: bool) -> Self {
        Self {
            deny: AtomicBool::new(deny),
            calls: AtomicUsize::new(0),
            protected_fds: Mutex::new(Vec::new()),
        }
    }

    fn set_deny(&self, deny: bool) {
        self.deny.store(deny, Ordering::SeqCst);
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn recorded_fds(&self) -> Vec<i32> {
        self.protected_fds
            .try_lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

impl SocketProtector for RecordingSocketProtector {
    fn protect_socket(&self, fd: i32) -> AppResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.deny.load(Ordering::SeqCst) {
            return Err(AppError::permission_denied(
                "VpnService.protect returned false",
            ));
        }
        if let Ok(mut g) = self.protected_fds.try_lock() {
            g.push(fd);
        }
        Ok(())
    }
}

struct MockDnsInterceptor {
    expected_dst: Ipv4Addr,
    intercept_count: AtomicUsize,
}

impl DnsPacketInterceptor for MockDnsInterceptor {
    fn intercept_outbound_packet(&self, packet: &[u8]) -> DnsInterceptDecision {
        let Some(&version_ihl) = packet.first() else {
            return DnsInterceptDecision::PassThrough;
        };
        if (version_ihl >> 4) != 4 || packet.len() < 28 {
            return DnsInterceptDecision::PassThrough;
        }
        let dst = Ipv4Addr::new(
            packet.get(16).copied().unwrap_or(0),
            packet.get(17).copied().unwrap_or(0),
            packet.get(18).copied().unwrap_or(0),
            packet.get(19).copied().unwrap_or(0),
        );
        let dst_port = u16::from_be_bytes([
            packet.get(22).copied().unwrap_or(0),
            packet.get(23).copied().unwrap_or(0),
        ]);
        if dst != self.expected_dst || dst_port != 53 {
            return DnsInterceptDecision::PassThrough;
        }
        self.intercept_count.fetch_add(1, Ordering::SeqCst);
        let mut reply = packet.to_vec();
        // Swap src/dst IP and src/dst UDP port to craft synthetic L3 DNS reply packet.
        if let (Some(src_slice), Some(dst_slice)) = (
            packet.get(12..16).map(|s| s.to_vec()),
            packet.get(16..20).map(|s| s.to_vec()),
        ) {
            if let Some(out_src) = reply.get_mut(12..16) {
                out_src.copy_from_slice(&dst_slice);
            }
            if let Some(out_dst) = reply.get_mut(16..20) {
                out_dst.copy_from_slice(&src_slice);
            }
        }
        DnsInterceptDecision::Handled {
            tun_responses: vec![reply],
        }
    }
}

async fn boot_and_wait_protocol_incompatible(
    dir_path: &Path,
    behavior: MockEndpointBehavior,
) -> Result<
    (
        ClientSessionSupervisor,
        Arc<InMemoryClientPlatformHooks>,
        Arc<FileClientStateStore>,
        MockTlsServer,
        NetmapSnapshot,
    ),
    String,
> {
    let placeholder_pin = SpkiPin::from_sha256_bytes([0x11; 32]);
    let bootstrap_netmap = make_sample_netmap("127.0.0.1:8443", "127.0.0.1:9", placeholder_pin)
        .ok_or_else(|| "sample netmap".to_owned())?;
    let server = MockTlsServer::start(behavior, bootstrap_netmap)
        .await
        .ok_or_else(|| "start mock TLS server".to_owned())?;
    let control_ep = server.addr.to_string();
    let netmap = make_sample_netmap(&control_ep, "127.0.0.1:9", server.pin)
        .ok_or_else(|| "netmap".to_owned())?;
    let now_ms = SystemClock::new().now_unix_ms();
    let _seeded = seed_enrolled_disk_state(dir_path, &control_ep, server.pin, &netmap, now_ms)
        .ok_or_else(|| "seed disk state".to_owned())?;
    let hooks = Arc::new(InMemoryClientPlatformHooks::default());
    let store = Arc::new(FileClientStateStore::from_dir(dir_path.to_path_buf()));
    let options = ClientSessionOptions::new(ClientRuntimeConfig::for_mobile())
        .with_default_tun_ifname("utun7")
        .with_bugreport(
            dir_path.join("bugreports"),
            "mesh-mobile-test",
            vec![],
            None,
        );
    let supervisor = ClientSessionSupervisor::boot(
        options,
        Arc::new(SystemClock::new()),
        Arc::clone(&hooks) as Arc<dyn mesh_client::hooks::ClientPlatformHooks>,
        Arc::clone(&store) as Arc<dyn mesh_client::hooks::ClientStateStore>,
    )
    .map_err(|err| format!("boot supervisor: {err}"))?;
    Ok((supervisor, hooks, store, server, netmap))
}

async fn run_protocol_incompatible_supervisor_case(
    behavior: MockEndpointBehavior,
) -> Result<(), String> {
    let dir = tempdir().map_err(|err| format!("tempdir: {err}"))?;
    let (supervisor, hooks, store, server, expected_netmap) =
        boot_and_wait_protocol_incompatible(dir.path(), behavior).await?;
    let runtime = supervisor.runtime_state();
    let root_shutdown = CancellationToken::new();
    let sup_task = tokio::spawn(supervisor.run(hooks.fake_monitor(), root_shutdown.clone()));

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if runtime.is_protocol_incompatible().await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        runtime.is_protocol_incompatible().await,
        "protocol_incompatible flag was not raised for {behavior:?}"
    );
    // Allow brief window to prove zero auto-retry spam happens after ProtocolIncompatible stop.
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert_eq!(server.counters.challenge_hits.load(Ordering::SeqCst), 1);
    if behavior == MockEndpointBehavior::Http400NetmapWs {
        assert_eq!(server.counters.netmap_ws_hits.load(Ordering::SeqCst), 1);
    }

    let status = runtime.build_status_response().await;
    assert_eq!(status.daemon_state, DaemonState::Stopped);
    assert!(hooks.deactivate_count() >= 1);
    assert!(hooks.recording_dns().clear_count() >= 1);
    assert!(!hooks.is_route_installed());
    let cache_path = dir.path().join("netmap-cache.json");
    assert!(cache_path.exists());
    let preserved = store.load_netmap_cache();
    assert!(matches!(
        preserved,
        Ok(Some(ref file)) if file.netmap == expected_netmap
    ));

    let shutdown_start = Instant::now();
    root_shutdown.cancel();
    assert!(matches!(sup_task.await, Ok(Ok(()))));
    assert!(shutdown_start.elapsed() <= Duration::from_secs(5));
    server.stop().await;
    Ok(())
}

async fn assert_register_node_protocol_incompatible(
    sample_netmap: NetmapSnapshot,
) -> Result<(), String> {
    let reg_server = MockTlsServer::start(MockEndpointBehavior::Http400Register, sample_netmap)
        .await
        .ok_or_else(|| "start reg server".to_owned())?;
    let bootstrap = BootstrapConfig {
        server_endpoint: Some(reg_server.addr.to_string()),
        tls_auth_mode: TlsAuthMode::SpkiPin,
        active_pin: Some(reg_server.pin),
        ..BootstrapConfig::default()
    };
    let node_kp = NodeKeypair::generate();
    let disco_kp = DiscoKeypair::generate();
    let node_name = "mobile-reg"
        .parse::<NodeName>()
        .map_err(|err| format!("node name: {err}"))?;
    let reg_req = RegisterNodeRequest {
        node_pubkey: node_kp.public_key(),
        disco_pubkey: disco_kp.public_key(),
        preauth_key: "mpk_test_compat_register".to_owned(),
        node_name,
        previous_node_pubkey: None,
    };
    let reg_res = ControlLoop::register_node_protected(
        &bootstrap,
        &node_kp,
        &reg_req,
        "mesh-mobile/0.1.0",
        ControlDialOptions {
            underlay: (None, None),
            nat64_prefix: None,
            protector: &NoopSocketProtector,
        },
    )
    .await;
    assert!(matches!(
        reg_res,
        Err(ref err) if err.kind() == ErrorKind::InvalidArgument
            && err.to_string().contains("protocol incompatible")
    ));
    assert_eq!(reg_server.counters.register_hits.load(Ordering::SeqCst), 1);
    reg_server.stop().await;
    Ok(())
}

async fn assert_relay_protocol_incompatible(sample_netmap: NetmapSnapshot) -> Result<(), String> {
    let relay_server = MockTlsServer::start(MockEndpointBehavior::Http400RelayWs, sample_netmap)
        .await
        .ok_or_else(|| "start relay server".to_owned())?;
    let relay_cfg = RelayClientConfig {
        endpoint: relay_server.addr.to_string(),
        server_name_override: None,
        pin_set: Some(mesh_crypto::PinSet::single(relay_server.pin)),
        underlay_if_index: None,
        linux_fwmark: None,
        require_challenge_auth: true,
        agent_version: "mesh-mobile/0.1.0".to_owned(),
    };
    let relay_client = RelayClient::with_options(
        relay_cfg,
        NodeKeypair::generate(),
        DiscoKeypair::generate(),
        RelayClientOptions::default().with_timer_mode(TimerMode::IdleAware),
    );
    let (ev_tx, mut ev_rx) = mpsc::channel(16);
    let relay_cancel = CancellationToken::new();
    let relay_handle =
        tokio::spawn(relay_client.run(Arc::new(SystemClock::new()), ev_tx, relay_cancel.clone()));
    let mut terminated_kind = None;
    let ev_deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < ev_deadline {
        let Ok(maybe_ev) = tokio::time::timeout(Duration::from_millis(200), ev_rx.recv()).await
        else {
            continue;
        };
        let Some(ev) = maybe_ev else {
            break;
        };
        if let RelayEvent::StateChanged(RelayConnectionState::Terminated(kind)) = ev {
            terminated_kind = Some(kind);
            break;
        }
    }
    assert_eq!(terminated_kind, Some(ErrorKind::InvalidArgument));
    assert_eq!(
        relay_server.counters.relay_ws_hits.load(Ordering::SeqCst),
        1
    );
    relay_cancel.cancel();
    let _joined = relay_handle.await;
    relay_server.stop().await;
    Ok(())
}

// Traces: US-099, mobile-system-architecture.md §4.3
#[tokio::test]
async fn test_http_400_protocol_incompatible_across_challenge_register_netmap_ws_and_relay() {
    // Arrange & Act & Assert 1 & 2: /v1/auth/challenge and /v1/netmap/stream WS HTTP 400
    assert_eq!(
        run_protocol_incompatible_supervisor_case(MockEndpointBehavior::Http400Challenge).await,
        Ok(())
    );
    assert_eq!(
        run_protocol_incompatible_supervisor_case(MockEndpointBehavior::Http400NetmapWs).await,
        Ok(())
    );

    // Arrange & Act & Assert 3 & 4: /v1/nodes/register HTTP 400 and Blind Relay /v1/relay WS HTTP 400
    let placeholder_pin = SpkiPin::from_sha256_bytes([0x22; 32]);
    let Some(sample_netmap) =
        make_sample_netmap("127.0.0.1:8443", "127.0.0.1:8443", placeholder_pin)
    else {
        panic!("sample netmap");
    };
    assert_eq!(
        assert_register_node_protocol_incompatible(sample_netmap.clone()).await,
        Ok(())
    );
    assert_eq!(
        assert_relay_protocol_incompatible(sample_netmap).await,
        Ok(())
    );
}

async fn spawn_counting_tcp_listener(
    cancel: &CancellationToken,
) -> Result<(SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("bind tcp listener: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("tcp local_addr: {err}"))?;
    let count = Arc::new(AtomicUsize::new(0));
    let clone = Arc::clone(&count);
    let token = cancel.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = token.cancelled() => break,
                res = listener.accept() => {
                    if res.is_ok() {
                        clone.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
    });
    Ok((addr, count, task))
}

async fn spawn_counting_udp_listener(
    cancel: &CancellationToken,
) -> Result<(SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>), String> {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|err| format!("bind udp listener: {err}"))?;
    let addr = sock
        .local_addr()
        .map_err(|err| format!("udp local_addr: {err}"))?;
    let count = Arc::new(AtomicUsize::new(0));
    let clone = Arc::clone(&count);
    let token = cancel.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                () = token.cancelled() => break,
                res = sock.recv_from(&mut buf) => {
                    if res.is_ok() {
                        clone.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
    });
    Ok((addr, count, task))
}

async fn assert_protector_blocks_netcheck_and_relay(
    tcp_addr: SocketAddr,
    udp_rx_addr: SocketAddr,
    pin: SpkiPin,
    bootstrap: BootstrapConfig,
    protector: Arc<RecordingSocketProtector>,
) {
    let store = Arc::new(InMemoryClientStateStore::new());
    let state = ClientRuntimeState::new(bootstrap, store, None, 1280, TimerMode::IdleAware);
    {
        let mut g = state.inner.write().await;
        g.latest_netmap = make_sample_netmap(&tcp_addr.to_string(), &tcp_addr.to_string(), pin);
        if let Some(ref mut nm) = g.latest_netmap {
            nm.relay_map.stun_udp_endpoints = vec![udp_rx_addr.to_string()];
        }
    }
    let netcheck = PingProbe::execute_netcheck_with_protector(
        &state,
        Some(Arc::clone(&protector) as Arc<dyn SocketProtector>),
    )
    .await;
    assert!(matches!(
        netcheck,
        Ok(ref resp) if !resp.control_tcp_reachable && !resp.udp_egress_ok
    ));

    let relay_cfg = RelayClientConfig {
        endpoint: tcp_addr.to_string(),
        server_name_override: None,
        pin_set: Some(mesh_crypto::PinSet::single(pin)),
        underlay_if_index: None,
        linux_fwmark: None,
        require_challenge_auth: false,
        agent_version: "mesh-mobile/0.1.0".to_owned(),
    };
    let relay_client = RelayClient::with_options(
        relay_cfg,
        NodeKeypair::generate(),
        DiscoKeypair::generate(),
        RelayClientOptions::default().with_socket_protector(protector as Arc<dyn SocketProtector>),
    );
    let (relay_tx, _relay_rx) = mpsc::channel(8);
    let relay_cancel = CancellationToken::new();
    let relay_task = tokio::spawn(relay_client.run(
        Arc::new(SystemClock::new()),
        relay_tx,
        relay_cancel.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(120)).await;
    relay_cancel.cancel();
    let _r = relay_task.await;
}

// Traces: US-077, US-099
#[tokio::test]
async fn test_socket_protector_fail_closed_blocks_bytes_across_all_sockets_and_allows_when_true() {
    // Arrange
    let protector = Arc::new(RecordingSocketProtector::new(true));
    let cancel = CancellationToken::new();
    let Ok((tcp_addr, accepted_tcp, tcp_task)) = spawn_counting_tcp_listener(&cancel).await else {
        panic!("spawn tcp listener");
    };
    let Ok((udp_rx_addr, udp_rx_count, udp_task)) = spawn_counting_udp_listener(&cancel).await
    else {
        panic!("spawn udp listener");
    };
    let Ok(cert) = generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 7, 1_700_000_000) else {
        panic!("certgen");
    };
    let bootstrap = BootstrapConfig {
        server_endpoint: Some(tcp_addr.to_string()),
        tls_auth_mode: TlsAuthMode::SpkiPin,
        active_pin: Some(cert.spki_pin),
        ..BootstrapConfig::default()
    };
    let Ok(tls_cfg) = bootstrap.build_tls_client_config() else {
        panic!("tls_cfg");
    };

    // Act 1-3: Fail-closed Control TCP TLS connect, UDP probe, Netcheck & Relay
    let ctl_res = connect_control_tls_with_protector(
        &tcp_addr.to_string(),
        tls_cfg,
        (None, None),
        None,
        protector.as_ref(),
    )
    .await;
    assert!(matches!(ctl_res, Err(ref e) if e.kind() == ErrorKind::PermissionDenied));
    let probe_res = probe_udp_routing_candidates_protected(51820, None, protector.as_ref());
    assert!(matches!(probe_res, Err(ref e) if e.kind() == ErrorKind::PermissionDenied));
    assert_protector_blocks_netcheck_and_relay(
        tcp_addr,
        udp_rx_addr,
        cert.spki_pin,
        bootstrap,
        Arc::clone(&protector),
    )
    .await;

    // Act 4: Fail-closed MagicSocket::bind -> Assert 0 bytes leaked -> Allow -> Assert received
    let blocked_magic_cfg = MagicSocketConfig::default()
        .with_socket_protector(Arc::clone(&protector) as Arc<dyn SocketProtector>);
    let blocked_bind = MagicSocket::bind(blocked_magic_cfg).await;
    assert!(matches!(
        blocked_bind,
        Err(ref err) if err.kind() == ErrorKind::PermissionDenied
    ));
    assert_eq!(accepted_tcp.load(Ordering::SeqCst), 0);
    assert_eq!(udp_rx_count.load(Ordering::SeqCst), 0);
    assert!(protector.call_count() >= 5);

    protector.set_deny(false);
    let allowed_magic_cfg = MagicSocketConfig::default()
        .with_socket_protector(Arc::clone(&protector) as Arc<dyn SocketProtector>);
    let Ok(magic) = MagicSocket::bind(allowed_magic_cfg).await else {
        panic!("bind allowed magic socket");
    };
    assert!(magic.send_to(b"hello-protected", udp_rx_addr).await.is_ok());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(udp_rx_count.load(Ordering::SeqCst), 1);
    assert!(!protector.recorded_fds().is_empty());

    cancel.cancel();
    let _t1 = tcp_task.await;
    let _t2 = udp_task.await;
}

// Traces: US-077, US-099
#[tokio::test]
async fn test_nat64_prefix_synthesis_for_probes_magic_socket_and_netcheck() {
    // Arrange
    let prefix = Nat64Prefix::well_known();
    let synth = Nat64Synthesizer::new(prefix);
    let v4_target = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 8443);

    // Act 1: RFC 6052 roundtrip
    let v6_target = synth.synthesize_sockaddr(v4_target);
    let recovered = synth.desynthesize_sockaddr(SocketAddr::V6(v6_target));

    // Assert 1
    assert_eq!(
        v6_target.ip(),
        &Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xcb00, 0x710a)
    );
    assert_eq!(recovered, Some(v4_target));

    // Arrange 2: Recording protector + NAT64 prefix on UDP candidate probe, MagicSocket, and PingProbe
    let protector = Arc::new(RecordingSocketProtector::new(false));
    let _probed = probe_udp_routing_candidates_protected(51820, Some(prefix), protector.as_ref());
    assert!(protector.call_count() >= 4);

    let magic =
        match MagicSocket::bind(MagicSocketConfig::default().with_nat64_prefix(Some(prefix))).await
        {
            Ok(m) => m,
            Err(err) => panic!("bind magic socket with nat64: {err}"),
        };
    assert_eq!(magic.nat64_prefix(), Some(prefix));

    let hooks = InMemoryClientPlatformHooks::default();
    hooks.set_nat64_prefix(Some(prefix));
    let store = Arc::new(InMemoryClientStateStore::new());
    let state = ClientRuntimeState::new(
        BootstrapConfig::default(),
        store,
        None,
        1280,
        TimerMode::IdleAware,
    );
    {
        let mut g = state.inner.write().await;
        g.nat64_prefix = hooks.nat64_prefix();
        g.latest_netmap = make_sample_netmap(
            "198.51.100.10:8443",
            "198.51.100.10:8443",
            SpkiPin::from_sha256_bytes([0x33; 32]),
        );
    }

    // Act 2: Execute netcheck with NAT64 prefix within 5s budget
    let started = Instant::now();
    let res = PingProbe::execute_netcheck_with_protector(
        &state,
        Some(Arc::clone(&protector) as Arc<dyn SocketProtector>),
    )
    .await;

    // Assert 2
    assert!(res.is_ok());
    assert!(started.elapsed() <= Duration::from_secs(5));
}

fn sample_connected_status() -> AgentStatusResponse {
    AgentStatusResponse {
        daemon_state: DaemonState::Connected,
        node_id: None,
        node_name: None,
        fqdn: None,
        overlay_ip: None,
        overlay_cidr: None,
        tun_interface_name: Some("utun4".to_owned()),
        tun_mtu: 1280,
        netmap_version: 9,
        key_expires_at_ms: None,
        server_connection: None,
        self_network: SelfNetworkStatus {
            local_udp_port: 51820,
            bound_physical_interface: Some("en0".to_owned()),
            nat_type: NatMappingKind::EimOrAdm,
            nat_classification_note: None,
            overlay_conflict_warning: None,
            macos_firewall_warning: None,
            candidates: vec![],
        },
        peers: vec![],
    }
}

// Traces: US-041, ADR-016, US-099
#[test]
fn test_mobile_streaming_bugreport_respects_1mib_cap_tail_truncation_and_0_secrets() {
    // Arrange
    let Ok(dir) = tempdir() else {
        panic!("tempdir");
    };
    let log_dir = dir.path().join("logs");
    if let Err(err) = std::fs::create_dir_all(&log_dir) {
        panic!("mkdir logs: {err}");
    }
    let canary_mpk = "mpk_MOBILE_CANARY_SECRET_001";
    let canary_jwt = "eyJhbGciOiJIUzI1NiJ9.MOBILE_CANARY_PAYLOAD";
    let canary_priv = "NODE_PRIV_CANARY_99887766";
    let mut big_log = format!(
        "auth preauth_key=\"{canary_mpk}\" Authorization: Bearer {canary_jwt} private_key=\"{canary_priv}\"\n"
    );
    big_log.push_str(&"INFO mobile datapath idle-aware tick\n".repeat(95_000));
    big_log.push_str(&format!(
        "FINAL_TAIL_MARKER preauth_key=\"{canary_mpk}\" Authorization: Bearer {canary_jwt} node_secret=\"{canary_priv}\"\n"
    ));
    if let Err(err) = std::fs::write(log_dir.join("mobile.log"), &big_log) {
        panic!("write oversized log: {err}");
    }

    let hooks = InMemoryClientPlatformHooks::default();
    let status = sample_connected_status();
    let mem_logs = format!(
        "ring_buf token=\"{canary_mpk}\" bearer=\"Bearer {canary_jwt}\"\nring_tail_ok=true\n"
    );

    // Act
    let resp = match create_bugreport_tar_bundle(BugreportBuildOptions {
        output_dir: &dir.path().join("out"),
        max_total_bytes: DEFAULT_MOBILE_MAX_BUGREPORT_BYTES,
        binary_name: "mesh-mobile-ffi",
        agent_version: "0.1.0-mobile",
        bootstrap: &BootstrapConfig::default(),
        status: &status,
        netcheck: Err("offline"),
        platform_hooks: &hooks,
        log_dirs: &[log_dir],
        in_memory_logs: Some(&mem_logs),
        now_unix_ms: 1_700_000_777_000,
    }) {
        Ok(r) => r,
        Err(err) => panic!("create bugreport: {err}"),
    };

    // Assert
    let tar_bytes = match std::fs::read(&resp.bundle_path) {
        Ok(b) => b,
        Err(err) => panic!("read tar bundle: {err}"),
    };
    assert!(tar_bytes.len() <= DEFAULT_MOBILE_MAX_BUGREPORT_BYTES);
    assert_eq!(tar_bytes.len() % 512, 0);
    assert!(resp.scrubbed_items >= 4);
    let lossy = String::from_utf8_lossy(&tar_bytes);
    assert!(!lossy.contains(canary_mpk));
    assert!(!lossy.contains(canary_jwt));
    assert!(!lossy.contains(canary_priv));
    assert!(lossy.contains("routes.txt"));
    assert!(lossy.contains("logs/mobile-ring.log"));
    assert!(lossy.contains("ring_tail_ok=true"));
    assert!(lossy.contains("FINAL_TAIL_MARKER"));
}

// Traces: OQ-MOB-04, US-099
#[test]
fn test_split_tunnel_routes_enforce_no_default_route_32_prefix_and_dns_collision_guard() {
    // Arrange
    assert!(SplitTunnelCidr::parse("0.0.0.0/0").is_err());
    let Ok(host_cidr) = SplitTunnelCidr::parse("100.115.0.2/32") else {
        panic!("/32 host route parse");
    };
    assert_eq!(host_cidr.prefix_len(), 32);

    let Ok(overlay_cidr) = "100.115.0.0/16".parse::<OverlayCidr>() else {
        panic!("overlay cidr");
    };
    let Ok(self_ip) = "100.115.0.1".parse::<OverlayIp>() else {
        panic!("self ip");
    };
    let Ok(peer_ip) = "100.115.0.10".parse::<OverlayIp>() else {
        panic!("peer ip");
    };
    let Ok(external_dns) = "100.116.0.53".parse::<OverlayIp>() else {
        panic!("external dns");
    };
    let Ok(peer_name) = "peer-a".parse::<NodeName>() else {
        panic!("peer name");
    };
    let peer = PeerEntry {
        node_id: NodeId::new_v7(1_700_000_000_001),
        name: peer_name,
        fqdn: "peer-a.mesh.internal".to_owned(),
        overlay_ip: peer_ip,
        node_pubkey: NodeKeypair::generate().public_key(),
        disco_pubkey: DiscoKeypair::generate().public_key(),
        endpoints: vec![],
        relay_home: "127.0.0.1:8443".to_owned(),
        key_expires_at_ms: None,
        online: true,
    };

    // Act 1: Underlay collides with top host (100.115.255.254) -> collision guard picks free IP
    let collide_ip = Ipv4Addr::new(100, 115, 255, 254);
    let derived = match derive_overlay_dns_ip(
        overlay_cidr,
        Some(self_ip),
        std::slice::from_ref(&peer),
        &[IpAddr::V4(collide_ip)],
    ) {
        Ok(ip) => ip,
        Err(err) => panic!("derive dns ip: {err}"),
    };
    assert_ne!(derived, self_ip);
    assert_ne!(derived, peer_ip);
    assert_ne!(derived.as_ipv4(), collide_ip);

    // Act 2: External DNS IP outside overlay_cidr adds explicit /32 route; conflict emits only /32
    let Ok(plan_outside) =
        compute_split_tunnel_routes(overlay_cidr, self_ip, external_dns, &[], &[], false)
    else {
        panic!("plan_outside");
    };
    assert_eq!(plan_outside.interface_address.prefix_len(), 32);
    assert!(!plan_outside.dns_inside_overlay_cidr);
    assert!(
        plan_outside
            .included_routes
            .iter()
            .all(|r| (1..=32).contains(&r.prefix_len()))
    );
    assert!(
        plan_outside
            .included_routes
            .contains(&SplitTunnelCidr::host(external_dns))
    );

    let Ok(plan_conflict) = compute_split_tunnel_routes(
        overlay_cidr,
        self_ip,
        derived,
        &[peer],
        &[IpAddr::V4(collide_ip)],
        true,
    ) else {
        panic!("plan_conflict");
    };
    assert_eq!(plan_conflict.interface_address.prefix_len(), 32);
    assert!(plan_conflict.dns_inside_overlay_cidr);
    assert!(
        plan_conflict
            .included_routes
            .iter()
            .all(|r| r.prefix_len() == 32)
    );
    assert!(compute_split_tunnel_routes(overlay_cidr, self_ip, self_ip, &[], &[], false).is_err());
}

proptest! {
    #[test]
    fn test_prop_split_tunnel_never_emits_default_route_and_avoids_dns_collisions(
        net_b in 64u8..127u8,
        net_c in 0u8..250u8,
        prefix_len in prop_oneof![Just(16u8), Just(20u8), Just(24u8), Just(25u8)],
        underlay_host in 1u8..6u8,
        conflict_mode in proptest::bool::ANY,
    ) {
        let base_ip = match prefix_len {
            16 => Ipv4Addr::new(100, net_b, 0, 0),
            20 => Ipv4Addr::new(100, net_b, net_c & 0xF0, 0),
            24 => Ipv4Addr::new(100, net_b, net_c, 0),
            _ => Ipv4Addr::new(100, net_b, net_c, 128),
        };
        let Ok(cidr) = format!("{base_ip}/{prefix_len}").parse::<OverlayCidr>() else {
            return Ok(());
        };
        let self_octets = base_ip.octets();
        let Ok(self_ip) = Ipv4Addr::new(
            self_octets[0],
            self_octets[1],
            self_octets[2],
            self_octets[3].saturating_add(1),
        )
        .to_string()
        .parse::<OverlayIp>()
        else {
            return Ok(());
        };
        let collide_v4 = Ipv4Addr::new(
            self_octets[0],
            self_octets[1],
            self_octets[2],
            self_octets[3].saturating_add(underlay_host),
        );
        let underlay = [IpAddr::V4(collide_v4)];
        let Ok(derived) = derive_overlay_dns_ip(cidr, Some(self_ip), &[], &underlay) else {
            return Ok(());
        };
        prop_assert_ne!(derived, self_ip);
        prop_assert_ne!(derived.as_ipv4(), collide_v4);
        let Ok(plan) =
            compute_split_tunnel_routes(cidr, self_ip, derived, &[], &underlay, conflict_mode)
        else {
            return Ok(());
        };
        prop_assert_eq!(plan.interface_address.prefix_len(), 32);
        prop_assert!(plan.included_routes.iter().all(|r| (1..=32).contains(&r.prefix_len())));
        if conflict_mode {
            prop_assert!(plan.included_routes.iter().all(|r| r.prefix_len() == 32));
        }
        let host_route_str = format!("{collide_v4}/32");
        prop_assert!(SplitTunnelCidr::parse(&host_route_str).is_ok());
        prop_assert!(SplitTunnelCidr::parse("0.0.0.0/0").is_err());
    }
}

async fn assert_zero_tun_enroll(enroll_netmap: &NetmapSnapshot) -> Result<(), String> {
    let dir = tempdir().map_err(|err| format!("tempdir: {err}"))?;
    let enroll_server = MockTlsServer::start(
        MockEndpointBehavior::EnrollSuccessOnly,
        enroll_netmap.clone(),
    )
    .await
    .ok_or_else(|| "start enroll server".to_owned())?;
    let hooks = Arc::new(InMemoryClientPlatformHooks::default());
    let store = Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf()));
    let mut supervisor = ClientSessionSupervisor::boot(
        ClientSessionOptions::new(ClientRuntimeConfig::for_mobile()),
        Arc::new(FakeClock::new(SystemClock::new().now_unix_ms())),
        Arc::clone(&hooks) as Arc<dyn mesh_client::hooks::ClientPlatformHooks>,
        store,
    )
    .map_err(|err| format!("boot supervisor: {err}"))?;
    let enroll_res = supervisor
        .enroll_or_rotate_only(EnrollOrRotateRequest {
            server_endpoint: enroll_server.addr.to_string(),
            port_override: None,
            server_pin: Some(enroll_server.pin),
            node_name: "iphone-16".parse::<NodeName>().ok(),
            preauth_key: Some("mpk_mobile_zero_tun".to_owned()),
            rotate_existing_keypair: false,
        })
        .await;
    assert!(enroll_res.is_ok());
    assert!(
        hooks.active_tun().is_none(),
        "enroll_or_rotate_only must not open TUN"
    );
    assert!(dir.path().join("netmap-cache.json").exists());
    enroll_server.stop().await;
    Ok(())
}

async fn assert_oversized_ws_frame_rejected(enroll_netmap: &NetmapSnapshot) -> Result<(), String> {
    let ws_server = MockTlsServer::start(
        MockEndpointBehavior::OversizedNetmapFrame,
        enroll_netmap.clone(),
    )
    .await
    .ok_or_else(|| "start oversized ws server".to_owned())?;
    let ws_temp = tempdir().map_err(|err| format!("ws tempdir: {err}"))?;
    let ws_ep = ws_server.addr.to_string();
    let ws_netmap = make_sample_netmap(&ws_ep, "127.0.0.1:9", ws_server.pin)
        .ok_or_else(|| "ws netmap".to_owned())?;
    let now_ms = SystemClock::new().now_unix_ms();
    let _seeded =
        seed_enrolled_disk_state(ws_temp.path(), &ws_ep, ws_server.pin, &ws_netmap, now_ms);
    let ws_hooks = Arc::new(InMemoryClientPlatformHooks::default());
    let ws_store = Arc::new(FileClientStateStore::from_dir(ws_temp.path().to_path_buf()));
    let ws_sup = ClientSessionSupervisor::boot(
        ClientSessionOptions::new(ClientRuntimeConfig::for_mobile()),
        Arc::new(SystemClock::new()),
        Arc::clone(&ws_hooks) as Arc<dyn mesh_client::hooks::ClientPlatformHooks>,
        ws_store,
    )
    .map_err(|err| format!("boot ws sup: {err}"))?;
    let ws_rt = ws_sup.runtime_state();
    let ws_shutdown = CancellationToken::new();
    let ws_task = tokio::spawn(ws_sup.run(ws_hooks.fake_monitor(), ws_shutdown.clone()));
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if ws_server.counters.netmap_ws_hits.load(Ordering::SeqCst) >= 1
            && ws_rt.inner.read().await.last_error.is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let ws_status = ws_rt.build_status_response().await;
    assert!(
        ws_status
            .server_connection
            .as_ref()
            .and_then(|s| s.last_error.as_deref())
            .is_some(),
        "oversized >262_144 B server WS frame should fail closed cleanly"
    );
    ws_shutdown.cancel();
    let _ws_done = ws_task.await;
    ws_server.stop().await;
    Ok(())
}

fn build_dns_udp_probe_packet(ov_ip: OverlayIp, dns_dst: Ipv4Addr) -> Vec<u8> {
    let mut dns_pkt = vec![0u8; 28];
    if let Some(first) = dns_pkt.first_mut() {
        *first = 0x45;
    }
    if let Some(total_len) = dns_pkt.get_mut(2..4) {
        total_len.copy_from_slice(&28u16.to_be_bytes());
    }
    if let Some(proto) = dns_pkt.get_mut(9) {
        *proto = 17;
    }
    if let Some(src) = dns_pkt.get_mut(12..16) {
        src.copy_from_slice(&ov_ip.as_ipv4().octets());
    }
    if let Some(dst) = dns_pkt.get_mut(16..20) {
        dst.copy_from_slice(&dns_dst.octets());
    }
    if let Some(sport) = dns_pkt.get_mut(20..22) {
        sport.copy_from_slice(&53000u16.to_be_bytes());
    }
    if let Some(dport) = dns_pkt.get_mut(22..24) {
        dport.copy_from_slice(&53u16.to_be_bytes());
    }
    if let Some(ulen) = dns_pkt.get_mut(24..26) {
        ulen.copy_from_slice(&8u16.to_be_bytes());
    }
    dns_pkt
}

async fn assert_dns_interceptor_on_datapath() -> Result<(), String> {
    let ov_ip = "100.115.0.10"
        .parse::<OverlayIp>()
        .map_err(|err| format!("ov_ip parse: {err}"))?;
    let ov_cidr = "100.115.0.0/16"
        .parse::<OverlayCidr>()
        .map_err(|err| format!("ov_cidr parse: {err}"))?;
    let tun_cfg = TunConfig::new("utun9".to_owned(), ov_ip, ov_cidr, 1280)
        .map_err(|err| format!("tun cfg: {err}"))?;
    let fake_tun = Arc::new(FakeTunDevice::new(tun_cfg));
    let dns_dst = Ipv4Addr::new(100, 115, 0, 2);
    let interceptor = Arc::new(MockDnsInterceptor {
        expected_dst: dns_dst,
        intercept_count: AtomicUsize::new(0),
    });
    let dp_cfg = DatapathConfig {
        local_node_id: NodeId::new_v7(1_700_000_000_000),
        local_overlay_ip: ov_ip,
        overlay_cidr: ov_cidr,
        node_keypair: NodeKeypair::generate(),
        disco_keypair: DiscoKeypair::generate(),
        socket_config: MagicSocketConfig::default(),
        stun_config: StunClientConfig::default(),
        disco_config: DiscoConfig::default(),
        control_tcp_endpoint: None,
        wg_timer_interval: Duration::from_millis(250),
        disco_tick_interval: Duration::from_millis(250),
    };
    let dp_opts = DatapathEngineOptions::default()
        .with_timer_mode(TimerMode::IdleAware)
        .with_dns_interceptor(Arc::clone(&interceptor) as Arc<dyn DnsPacketInterceptor>);
    let engine = DatapathEngine::bind_with_options(
        dp_cfg,
        Arc::clone(&fake_tun) as Arc<dyn mesh_net::tun::TunDevice>,
        Arc::new(SystemClock::new()),
        None,
        dp_opts,
    )
    .await
    .map_err(|err| format!("bind datapath engine: {err}"))?;
    let (_relay_tx, relay_rx) = mpsc::channel(8);
    let (_rebind_handle, rebind_rx) = mesh_datapath::RebindHandle::channel();
    let dp_cancel = CancellationToken::new();
    let dp_task = tokio::spawn(engine.run(relay_rx, rebind_rx, dp_cancel.clone()));

    fake_tun
        .inject_inbound_packet(build_dns_udp_probe_packet(ov_ip, dns_dst))
        .await
        .map_err(|err| format!("inject packet: {err}"))?;

    let mut outbound = Vec::new();
    let dp_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < dp_deadline {
        let drained = fake_tun.drain_outbound_packets().await;
        if !drained.is_empty() {
            outbound = drained;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(interceptor.intercept_count.load(Ordering::SeqCst), 1);
    assert_eq!(outbound.len(), 1);
    assert_eq!(
        outbound.first().and_then(|p| p.get(12..16)),
        Some(dns_dst.octets().as_slice())
    );
    dp_cancel.cancel();
    let _dp_res = dp_task.await;
    Ok(())
}

// Traces: ADR-016, US-077, US-099
#[tokio::test]
async fn test_mobile_budgets_ws_frame_limit_262144_idle_aware_dns_interceptor_and_target_os() {
    // Arrange & Assert 1: ADR-016 budgets & TargetOs check
    let mobile_cfg = ClientRuntimeConfig::for_mobile();
    assert_eq!(
        mobile_cfg.max_ws_frame_bytes,
        DEFAULT_MOBILE_MAX_WS_FRAME_BYTES
    );
    assert_eq!(mobile_cfg.max_ws_frame_bytes, 262_144);
    assert_eq!(
        mobile_cfg.coalesced_heartbeat_ms,
        DEFAULT_MOBILE_COALESCED_HEARTBEAT_MS
    );
    assert_eq!(mobile_cfg.coalesced_heartbeat_ms, 45_000);
    assert_eq!(mobile_cfg.timer_mode, TimerMode::IdleAware);
    assert_eq!(
        mobile_cfg.max_bugreport_bytes,
        DEFAULT_MOBILE_MAX_BUGREPORT_BYTES
    );
    assert_eq!(
        mobile_cfg.control_heartbeat_ms_for(TimerMode::IdleAware),
        45_000
    );

    let os = current_target_os();
    if cfg!(target_os = "android") {
        assert_eq!(os, TargetOs::Android);
    } else if cfg!(target_os = "ios") {
        assert_eq!(os, TargetOs::Ios);
    } else if cfg!(target_os = "macos") {
        assert_eq!(os, TargetOs::Darwin);
    } else if cfg!(target_os = "windows") {
        assert_eq!(os, TargetOs::Windows);
    } else {
        assert_eq!(os, TargetOs::Linux);
    }

    // Act & Assert 2-4: zero-TUN enroll, >262_144 B WS frame cap, L3 DnsPacketInterceptor
    let dummy_pin = SpkiPin::from_sha256_bytes([0x44; 32]);
    let Some(enroll_netmap) = make_sample_netmap("127.0.0.1:8443", "127.0.0.1:8443", dummy_pin)
    else {
        panic!("enroll netmap");
    };
    assert_eq!(assert_zero_tun_enroll(&enroll_netmap).await, Ok(()));
    assert_eq!(
        assert_oversized_ws_frame_rejected(&enroll_netmap).await,
        Ok(())
    );
    assert_eq!(assert_dns_interceptor_on_datapath().await, Ok(()));
}
