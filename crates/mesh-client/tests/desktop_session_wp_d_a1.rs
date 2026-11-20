//! Integration tests for WP-D-A1 (`US-101`, `ADR-024`, `HR-DGUI-G2-04`):
//! - `ClientStateStore::delete_identity` on `FileClientStateStore`
//! - `ClientSessionSupervisor::execute_reset_identity` clearing disk + RAM while keeping daemon alive
//! - `update_bootstrap_trust_preserving_next_pin` across `execute_up` (1-click reconnect) & `execute_set`

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::accept_with_config;
use tokio_util::sync::CancellationToken;

use mesh_client::ClientRuntimeConfig;
use mesh_client::config::BootstrapConfig;
use mesh_client::hooks::{
    ClientPlatformHooks, ClientStateStore, FileClientStateStore, InMemoryClientPlatformHooks,
};
use mesh_client::netmap_cache::NetmapCacheFile;
use mesh_client::session::{
    ClientSessionOptions, ClientSessionSupervisor, update_bootstrap_trust_preserving_next_pin,
};
use mesh_core::clock::{Clock as _, SystemClock};
use mesh_core::{
    MobileJoinTlsAuth, NodeId, NodeName, OverlayCidr, OverlayIp, Port, SpkiPin, format_join_uri,
    parse_join_uri,
};
use mesh_crypto::{
    DiscoKeypair, NodeKeypair, build_rustls_server_config_from_der, generate_ip_pinned_cert,
};
use mesh_net::netmon::FakeNetMonitor;
use mesh_proto::agent_ipc::{AgentSetRequest, AgentUpRequest, DaemonState, TlsAuthMode};
use mesh_proto::control::{ChallengeResponse, RegisterNodeResponse, ServerControlFrame};
use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};

#[tokio::test]
async fn test_file_backed_reset_identity_and_next_pin_preservation_e2e() -> Result<(), String> {
    // Arrange
    let dir = tempdir().map_err(|e| e.to_string())?;
    let hooks = Arc::new(InMemoryClientPlatformHooks::default());
    let store = Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf()));
    let now_ms = 1_700_000_000_000_u64;

    let _identity = store
        .load_or_create_identity(now_ms)
        .map_err(|e| e.to_string())?;
    let node_id = NodeId::new_v7(now_ms);
    let _saved_id = store
        .set_identity_node_id(node_id)
        .map_err(|e| e.to_string())?;

    let pin_active = SpkiPin::from_sha256_bytes([0x11_u8; 32]);
    let pin_next = SpkiPin::from_sha256_bytes([0x22_u8; 32]);
    let bootstrap = BootstrapConfig {
        node_id: Some(node_id),
        node_name: "win-node".parse::<NodeName>().ok(),
        overlay_ip: "100.115.0.8".parse::<OverlayIp>().ok(),
        server_endpoint: Some("203.0.113.10:8443".to_owned()),
        tls_auth_mode: TlsAuthMode::SpkiPin,
        active_pin: Some(pin_active),
        next_pin: Some(pin_next),
        ..BootstrapConfig::default()
    };
    store
        .save_bootstrap(&bootstrap)
        .map_err(|e| e.to_string())?;

    let snap = NetmapSnapshot {
        netmap_version: 3,
        generated_at_ms: now_ms,
        overlay_cidr: "100.115.0.0/16".parse().map_err(|e| format!("{e}"))?,
        domain_suffix: "mesh.internal".to_owned(),
        relay_map: RelayMap {
            endpoint_version: 1,
            control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
            relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
            stun_udp_endpoints: vec![],
        },
        pin_set: PinSetDto {
            active_pin: pin_active,
            next_pin: Some(pin_next),
        },
        peers: vec![PeerEntry {
            node_id: NodeId::new_v7(now_ms + 1),
            name: "peer-a".parse::<NodeName>().map_err(|e| format!("{e}"))?,
            fqdn: "peer-a.mesh.internal".to_owned(),
            overlay_ip: "100.115.0.9"
                .parse::<OverlayIp>()
                .map_err(|e| format!("{e}"))?,
            node_pubkey: mesh_crypto::NodeKeypair::generate().public_key(),
            disco_pubkey: mesh_crypto::DiscoKeypair::generate().public_key(),
            endpoints: vec![],
            relay_home: "203.0.113.10:8443".to_owned(),
            key_expires_at_ms: None,
            online: true,
        }],
    };
    let cache = NetmapCacheFile::new_signed(
        Port::from_u16(51820).map_err(|e| format!("{e}"))?,
        snap,
        now_ms,
        None,
    )
    .map_err(|e| format!("{e}"))?;
    store.save_netmap_cache(&cache).map_err(|e| e.to_string())?;

    // Also stage a stale `.tmp` file beside `keys.json`
    let stale_tmp = dir.path().join("keys.json.tmp.42424");
    fs::write(&stale_tmp, b"stale-temp-keys").map_err(|e| e.to_string())?;

    let mut supervisor = ClientSessionSupervisor::boot(
        ClientSessionOptions::new(ClientRuntimeConfig::for_desktop()),
        Arc::new(SystemClock::new()),
        Arc::clone(&hooks) as Arc<dyn ClientPlatformHooks>,
        Arc::clone(&store) as Arc<dyn ClientStateStore>,
    )
    .map_err(|e| e.to_string())?;

    // Act 1: 1-click reconnect `execute_up` + `execute_set` keep `next_pin` on disk
    let shutdown = CancellationToken::new();
    supervisor
        .execute_up(
            AgentUpRequest {
                server_endpoint: "203.0.113.10:8443".to_owned(),
                port_override: None,
                server_pin: Some(pin_active),
                preauth_key: None,
                node_name: None,
            },
            &shutdown,
        )
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        store.load_bootstrap().map_err(|e| e.to_string())?.next_pin,
        Some(pin_next)
    );

    supervisor
        .execute_set(AgentSetRequest {
            server_endpoint: "203.0.113.10:8443".to_owned(),
            server_pin: Some(pin_active),
        })
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        store.load_bootstrap().map_err(|e| e.to_string())?.next_pin,
        Some(pin_next)
    );

    // Promote next_pin via execute_set -> becomes active_pin, next_pin cleared
    let mut promoted_cfg = store.load_bootstrap().map_err(|e| e.to_string())?;
    update_bootstrap_trust_preserving_next_pin(
        &mut promoted_cfg,
        "203.0.113.10:8443",
        TlsAuthMode::SpkiPin,
        Some(pin_next),
        false,
    );
    assert_eq!(promoted_cfg.active_pin, Some(pin_next));
    assert_eq!(promoted_cfg.next_pin, None);

    // Act 2: execute_reset_identity removes keys.json, keys.json.tmp.*, netmap-cache.json, and resets bootstrap.toml
    let reset_resp = supervisor
        .execute_reset_identity()
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(reset_resp.state, DaemonState::Stopped);
    assert!(!dir.path().join("keys.json").exists());
    assert!(!stale_tmp.exists());
    assert!(!dir.path().join("netmap-cache.json").exists());
    assert_eq!(
        store.load_bootstrap().map_err(|e| e.to_string())?,
        BootstrapConfig::default()
    );

    // Act 3: supervisor loop remains alive after reset-identity
    let run_shutdown = CancellationToken::new();
    let runtime = supervisor.runtime_state();
    let sup_task =
        tokio::spawn(supervisor.run(Arc::new(FakeNetMonitor::new()), run_shutdown.clone()));
    let status = runtime.build_status_response().await;
    assert_eq!(status.daemon_state, DaemonState::Stopped);
    assert_eq!(status.node_id, None);
    assert!(status.peers.is_empty());
    run_shutdown.cancel();
    let _done = sup_task.await;
    Ok(())
}

#[derive(Debug, Default)]
struct ReconnectServerCounters {
    challenge_hits: AtomicUsize,
    register_hits: AtomicUsize,
    netmap_ws_hits: AtomicUsize,
    relay_ws_hits: AtomicUsize,
    ws_snapshots_sent: AtomicUsize,
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

fn find_http_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_http_content_length(head: &str) -> usize {
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            return v.trim().parse::<usize>().unwrap_or(0);
        }
    }
    0
}

async fn read_next_async_http_head(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    carry: &mut Vec<u8>,
    shutdown: &CancellationToken,
) -> Option<(String, String, Vec<u8>)> {
    let mut chunk = [0_u8; 2048];
    let head_end = loop {
        if let Some(pos) = find_http_head_end(carry) {
            break pos;
        }
        let read_res = tokio::select! {
            () = shutdown.cancelled() => return None,
            res = stream.read(&mut chunk) => res,
        };
        let n = read_res.ok()?;
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
    let content_len = parse_http_content_length(&head_str);
    while carry.len() < head_end.saturating_add(content_len) {
        let read_res = tokio::select! {
            () = shutdown.cancelled() => return None,
            res = stream.read(&mut chunk) => res,
        };
        let n = read_res.ok()?;
        if n == 0 {
            return None;
        }
        if let Some(slice) = chunk.get(..n) {
            carry.extend_from_slice(slice);
        }
    }
    let total = head_end.saturating_add(content_len);
    let raw_req = carry.drain(..total).collect();
    Some((method, path, raw_req))
}

async fn write_async_json_response(
    stream: &mut TlsStream<tokio::net::TcpStream>,
    status_line: &str,
    body: &[u8],
) -> bool {
    let head = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.is_ok()
        && stream.write_all(body).await.is_ok()
        && stream.flush().await.is_ok()
}

async fn send_ws_upgrade_and_hold(
    mut stream: TlsStream<tokio::net::TcpStream>,
    raw_req: Vec<u8>,
    initial_text: Option<String>,
    snapshot_counter: Option<(&AtomicUsize, usize)>,
    shutdown: &CancellationToken,
) {
    let bridge = SyncWsBridge {
        rx: VecDeque::from(raw_req),
        tx: Vec::new(),
    };
    let Ok(mut ws) = accept_with_config(bridge, None) else {
        return;
    };
    if let Some(text) = initial_text
        && ws.send(WsMessage::Text(text.into())).is_err()
    {
        return;
    }
    let tx_bytes = ws.get_mut().tx.clone();
    if stream.write_all(&tx_bytes).await.is_err() || stream.flush().await.is_err() {
        return;
    }
    if let Some((counter, delta)) = snapshot_counter {
        counter.fetch_add(delta, Ordering::SeqCst);
    }

    let mut discard = [0_u8; 1024];
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            res = stream.read(&mut discard) => match res {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}

async fn handle_async_tls_conn(
    mut stream: TlsStream<tokio::net::TcpStream>,
    counters: Arc<ReconnectServerCounters>,
    netmap: NetmapSnapshot,
    shutdown: CancellationToken,
) {
    let mut carry = Vec::new();
    let now_ms = SystemClock::new().now_unix_ms();

    loop {
        let Some((_method, path, raw_req)) =
            read_next_async_http_head(&mut stream, &mut carry, &shutdown).await
        else {
            break;
        };
        if path == "/v1/auth/challenge" {
            counters.challenge_hits.fetch_add(1, Ordering::SeqCst);
            let eph = NodeKeypair::generate();
            let ch = ChallengeResponse {
                challenge_id: NodeId::new_v7(now_ms),
                server_eph_pubkey: eph.public_key(),
                challenge_nonce: BASE64_STANDARD.encode([0x42_u8; 32]),
                server_time_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(30_000),
            };
            let body = serde_json::to_vec(&ch).unwrap_or_default();
            if !write_async_json_response(&mut stream, "200 OK", &body).await {
                break;
            }
            continue;
        }
        if path == "/v1/nodes/register" {
            counters.register_hits.fetch_add(1, Ordering::SeqCst);
            let (Ok(name), Ok(ip)) = (
                "desktop-reconn".parse::<NodeName>(),
                "100.115.0.10".parse::<OverlayIp>(),
            ) else {
                break;
            };
            let reg = RegisterNodeResponse {
                node_id: NodeId::new_v7(now_ms.saturating_add(2)),
                node_name: name,
                fqdn: "desktop-reconn.mesh.internal".to_owned(),
                overlay_ip: ip,
                overlay_cidr: netmap.overlay_cidr,
                key_expires_at_ms: None,
                netmap: netmap.clone(),
            };
            let body = serde_json::to_vec(&reg).unwrap_or_default();
            if !write_async_json_response(&mut stream, "200 OK", &body).await {
                break;
            }
            continue;
        }
        if path.starts_with("/v1/netmap/stream") {
            counters.netmap_ws_hits.fetch_add(1, Ordering::SeqCst);
            let frame = ServerControlFrame::NetmapSnapshot {
                sent_at_ms: SystemClock::new().now_unix_ms(),
                netmap: Box::new(netmap.clone()),
            };
            let text = serde_json::to_string(&frame).ok();
            send_ws_upgrade_and_hold(
                stream,
                raw_req,
                text,
                Some((&counters.ws_snapshots_sent, 1)),
                &shutdown,
            )
            .await;
            break;
        }
        if path.starts_with("/v1/relay") {
            counters.relay_ws_hits.fetch_add(1, Ordering::SeqCst);
            send_ws_upgrade_and_hold(stream, raw_req, None, None, &shutdown).await;
            break;
        }
        let _sent = write_async_json_response(&mut stream, "404 Not Found", b"{}").await;
        break;
    }
}

struct ReconnectTestServer {
    addr: SocketAddr,
    pin: SpkiPin,
    counters: Arc<ReconnectServerCounters>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

async fn start_tls13_reconnect_test_server(
    netmap_version: u64,
) -> Result<ReconnectTestServer, String> {
    if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
        drop(err);
    }
    let now_secs = SystemClock::new().now_unix_ms() / 1000;
    let cert = generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 30, now_secs.saturating_sub(60))
        .map_err(|e| e.to_string())?;
    let pin = cert.spki_pin;
    let server_cfg = Arc::new(
        build_rustls_server_config_from_der(vec![cert.cert_der], &cert.key_pkcs8_der, vec![])
            .map_err(|e| e.to_string())?,
    );
    let acceptor = TlsAcceptor::from(server_cfg);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let now_ms = SystemClock::new().now_unix_ms();
    let overlay_cidr = "100.115.0.0/16"
        .parse::<OverlayCidr>()
        .map_err(|e| e.to_string())?;
    let netmap = NetmapSnapshot {
        netmap_version,
        generated_at_ms: now_ms,
        overlay_cidr,
        domain_suffix: "mesh.internal".to_owned(),
        relay_map: RelayMap {
            endpoint_version: 1,
            control_tcp_endpoint: addr.to_string(),
            relay_tcp_endpoint: addr.to_string(),
            stun_udp_endpoints: Vec::new(),
        },
        pin_set: PinSetDto {
            active_pin: pin,
            next_pin: None,
        },
        peers: vec![PeerEntry {
            node_id: NodeId::new_v7(now_ms.saturating_add(1)),
            name: "peer-b".parse::<NodeName>().map_err(|e| e.to_string())?,
            fqdn: "peer-b.mesh.internal".to_owned(),
            overlay_ip: "100.115.0.22"
                .parse::<OverlayIp>()
                .map_err(|e| e.to_string())?,
            node_pubkey: NodeKeypair::generate().public_key(),
            disco_pubkey: DiscoKeypair::generate().public_key(),
            endpoints: Vec::new(),
            relay_home: addr.to_string(),
            key_expires_at_ms: None,
            online: true,
        }],
    };

    let counters = Arc::new(ReconnectServerCounters::default());
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task_counters = Arc::clone(&counters);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = task_shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((tcp, _peer)) = accepted else {
                        break;
                    };
                    let acc = acceptor.clone();
                    let cnt = Arc::clone(&task_counters);
                    let nm = netmap.clone();
                    let sd = task_shutdown.clone();
                    drop(tokio::spawn(async move {
                        if let Ok(tls) = acc.accept(tcp).await {
                            handle_async_tls_conn(tls, cnt, nm, sd).await;
                        }
                    }));
                }
            }
        }
    });

    Ok(ReconnectTestServer {
        addr,
        pin,
        counters,
        shutdown,
        task,
    })
}

async fn wait_for_connected_and_dns_sync(
    runtime: &mesh_client::state::ClientRuntimeState,
    hooks: &InMemoryClientPlatformHooks,
    counters: &ReconnectServerCounters,
    expected_ws_snapshots: usize,
    min_synced_dns: usize,
    timeout: Duration,
) -> Result<mesh_proto::agent_ipc::AgentStatusResponse, String> {
    let start = Instant::now();
    loop {
        let status = runtime.build_status_response().await;
        let synced_len = hooks.recording_dns().synced_snapshots().len();
        let ws_sent = counters.ws_snapshots_sent.load(Ordering::SeqCst);
        let last_err_none = status
            .server_connection
            .as_ref()
            .and_then(|s| s.last_error.as_ref())
            .is_none();
        if status.daemon_state == DaemonState::Connected
            && last_err_none
            && ws_sent >= expected_ws_snapshots
            && synced_len >= min_synced_dns
        {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "timed out waiting for Connected + WS({ws_sent}/{expected_ws_snapshots}) + DNS({synced_len}/{min_synced_dns}): state={:?}, err={:?}",
                status.daemon_state,
                status
                    .server_connection
                    .as_ref()
                    .and_then(|s| s.last_error.clone())
            ));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn test_desktop_uri_enroll_disconnect_and_multi_cycle_reconnect_resyncs_hosts_over_tls13()
-> Result<(), String> {
    // Arrange
    let ReconnectTestServer {
        addr,
        pin,
        counters,
        shutdown: srv_shutdown,
        task: srv_task,
    } = start_tls13_reconnect_test_server(5).await?;
    let preauth_raw = format!("mpk_{}", URL_SAFE_NO_PAD.encode([0x5A_u8; 32]));
    let node_name_hint = "desktop-reconn"
        .parse::<NodeName>()
        .map_err(|e| e.to_string())?;
    let join_uri = format_join_uri(
        &addr.to_string(),
        &MobileJoinTlsAuth::SpkiPin(pin),
        &preauth_raw,
        Some(&node_name_hint),
    )
    .map_err(|e| e.to_string())?;
    let parsed = parse_join_uri(&join_uri).map_err(|e| e.to_string())?;

    let dir = tempdir().map_err(|e| e.to_string())?;
    let hooks = Arc::new(InMemoryClientPlatformHooks::default());
    let store = Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf()));
    let mut supervisor = ClientSessionSupervisor::boot(
        ClientSessionOptions::new(ClientRuntimeConfig::for_desktop()),
        Arc::new(SystemClock::new()),
        Arc::clone(&hooks) as Arc<dyn ClientPlatformHooks>,
        Arc::clone(&store) as Arc<dyn ClientStateStore>,
    )
    .map_err(|e| e.to_string())?;
    let runtime = supervisor.runtime_state();
    let root_shutdown = CancellationToken::new();

    // Act 1: Initial onboarding via mesh://join URI -> Connected + DNS hosts synced at v5
    let up_pin = match parsed.tls_auth {
        MobileJoinTlsAuth::SpkiPin(p) => Some(p),
        MobileJoinTlsAuth::SystemCa => None,
    };
    supervisor
        .execute_up(
            AgentUpRequest {
                server_endpoint: parsed.control_endpoint.clone(),
                port_override: None,
                server_pin: up_pin,
                preauth_key: Some(parsed.preauth_key().to_owned()),
                node_name: parsed.node_name.clone(),
            },
            &root_shutdown,
        )
        .await
        .map_err(|e| e.to_string())?;
    let s1 =
        wait_for_connected_and_dns_sync(&runtime, &hooks, &counters, 1, 2, Duration::from_secs(6))
            .await?;
    assert_eq!(counters.register_hits.load(Ordering::SeqCst), 1);
    assert!(
        s1.peers.iter().any(|p| p.fqdn == "peer-b.mesh.internal"),
        "expected peer-b in initial netmap"
    );
    let synced_after_1 = hooks.recording_dns().synced_snapshots().len();
    assert!(synced_after_1 >= 1);
    assert!(
        hooks
            .recording_dns()
            .synced_snapshots()
            .last()
            .is_some_and(|n| n.peers.iter().any(|p| p.fqdn == "peer-b.mesh.internal"))
    );

    // Act 2: First Disconnect -> Stopped with clean last_error == None and DNS cleared
    let clears_before_down1 = hooks.recording_dns().clear_count();
    let down1 = supervisor.execute_down().await.map_err(|e| e.to_string())?;
    assert_eq!(down1.state, DaemonState::Stopped);
    let after_down1 = runtime.build_status_response().await;
    assert_eq!(after_down1.daemon_state, DaemonState::Stopped);
    assert_eq!(
        after_down1
            .server_connection
            .as_ref()
            .and_then(|s| s.last_error.as_deref()),
        None
    );
    assert!(hooks.recording_dns().clear_count() > clears_before_down1);

    // Act 3: First 1-click Reconnect (`preauth_key: None`) with server still at netmap_version == 5
    supervisor
        .execute_up(
            AgentUpRequest {
                server_endpoint: parsed.control_endpoint.clone(),
                port_override: None,
                server_pin: up_pin,
                preauth_key: None,
                node_name: parsed.node_name.clone(),
            },
            &root_shutdown,
        )
        .await
        .map_err(|e| e.to_string())?;
    let s2 = wait_for_connected_and_dns_sync(
        &runtime,
        &hooks,
        &counters,
        2,
        synced_after_1.saturating_add(2),
        Duration::from_secs(6),
    )
    .await?;
    assert_eq!(
        counters.register_hits.load(Ordering::SeqCst),
        1,
        "one-time preauth registration must not be re-sent on reconnect"
    );
    let synced_after_2 = hooks.recording_dns().synced_snapshots().len();
    assert!(
        synced_after_2 > synced_after_1,
        "reconnect must re-sync DNS/hosts even when netmap_version is unchanged"
    );
    assert!(s2.peers.iter().any(|p| p.fqdn == "peer-b.mesh.internal"));

    // Act 4: Second Disconnect -> Second 1-click Reconnect
    let clears_before_down2 = hooks.recording_dns().clear_count();
    let down2 = supervisor.execute_down().await.map_err(|e| e.to_string())?;
    assert_eq!(down2.state, DaemonState::Stopped);
    assert!(hooks.recording_dns().clear_count() > clears_before_down2);

    supervisor
        .execute_up(
            AgentUpRequest {
                server_endpoint: parsed.control_endpoint,
                port_override: None,
                server_pin: up_pin,
                preauth_key: None,
                node_name: parsed.node_name,
            },
            &root_shutdown,
        )
        .await
        .map_err(|e| e.to_string())?;
    drop(
        wait_for_connected_and_dns_sync(
            &runtime,
            &hooks,
            &counters,
            3,
            synced_after_2.saturating_add(2),
            Duration::from_secs(6),
        )
        .await?,
    );

    // Assert
    assert!(hooks.recording_dns().synced_snapshots().len() > synced_after_2);
    assert!(counters.netmap_ws_hits.load(Ordering::SeqCst) >= 3);
    assert_eq!(counters.register_hits.load(Ordering::SeqCst), 1);

    // Teardown
    supervisor
        .stop_active_session_and_cleanup()
        .await
        .map_err(|e| e.to_string())?;
    root_shutdown.cancel();
    srv_shutdown.cancel();
    drop(srv_task.await);
    Ok(())
}
