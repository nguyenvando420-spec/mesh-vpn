//! Integration tests for 3-tier IPC timeouts, `50`-peer bounded JSON reads, `ERROR_PIPE_BUSY`
//! retry, `LegacyPre030` version probing, and bugreport streaming (`ADR-023`, `ADR-024`, `US-101`).

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use mesh_core::defaults::{MAX_BUGREPORT_ARCHIVE_BYTES, MAX_HTTP_BODY_BYTES};
use mesh_core::{ErrorKind, NodeId, NodeName, OverlayIp};
use mesh_net::ipc::{
    AgentVersionStatus, HEADER_MESH_AGENT_VERSION, HEADER_MESH_ARCHIVE_BYTES,
    HEADER_MESH_SCRUBBED_ITEMS, IPC_ADMIN_MUTATION_TIMEOUT, IPC_CONNECT_TIMEOUT,
    IPC_NETCHECK_TIMEOUT, IPC_PING_MAX_TIMEOUT, IPC_RO_QUERY_TIMEOUT, IpcConnectFailureKind,
    IpcOperationTier, classify_agent_version_probe, classify_cli_version_probe_exit_code,
    classify_ipc_io_error_kind, connect_with_pipe_busy_retry, ping_request_timeout,
    send_ipc_json_request_with_timeout, send_ipc_json_with_meta, serve_ipc_http_connection,
    stream_ipc_bugreport,
};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentPeerStatus, AgentStatusResponse, AgentVersionResponse, DaemonState,
    SelfNetworkStatus,
};
use mesh_proto::netmap::NatMappingKind;
use tokio::io::duplex;

#[test]
fn test_ipc_three_tier_timeouts_match_adr_024_budgets() {
    // Arrange & Act
    let t_connect = IPC_CONNECT_TIMEOUT;
    let t_ro = IpcOperationTier::ReadOnlyQuery.response_timeout();
    let t_netcheck = IpcOperationTier::NetcheckProbe.response_timeout();
    let t_ping_default = IpcOperationTier::PingProbe {
        count: 4,
        per_probe_timeout_ms: 2_500,
    }
    .response_timeout();
    let t_ping_capped = ping_request_timeout(64, 2_500);
    let t_admin = IpcOperationTier::AdminMutation.response_timeout();

    // Assert
    assert_eq!(t_connect, Duration::from_millis(850));
    assert_eq!(t_ro, IPC_RO_QUERY_TIMEOUT);
    assert_eq!(t_ro, Duration::from_millis(2_000));
    assert_eq!(t_netcheck, IPC_NETCHECK_TIMEOUT);
    assert_eq!(t_netcheck, Duration::from_millis(10_000));
    assert_eq!(t_ping_default, Duration::from_millis(12_000));
    assert_eq!(t_ping_capped, IPC_PING_MAX_TIMEOUT);
    assert_eq!(t_admin, IPC_ADMIN_MUTATION_TIMEOUT);
    assert_eq!(t_admin, Duration::from_millis(35_000));
}

#[tokio::test]
async fn test_ipc_pipe_busy_retries_succeed_and_errors_map_distinctly() {
    // Arrange
    let attempts = AtomicUsize::new(0);
    let busy_err = io::Error::from_raw_os_error(231);
    let access_err = io::Error::from_raw_os_error(5);
    let not_found_err = io::Error::from_raw_os_error(2);

    // Assert classifications
    assert_eq!(
        classify_ipc_io_error_kind(&busy_err),
        IpcConnectFailureKind::BusyRetryable
    );
    assert_eq!(
        classify_ipc_io_error_kind(&access_err),
        IpcConnectFailureKind::PermissionDenied
    );
    assert_eq!(
        classify_ipc_io_error_kind(&not_found_err),
        IpcConnectFailureKind::ServiceUnavailable
    );

    // Act 1: 2x ERROR_PIPE_BUSY (231) then success within 850 ms budget
    let res = connect_with_pipe_busy_retry(
        r"\\.\pipe\mesh-agent-ro",
        false,
        IPC_CONNECT_TIMEOUT,
        || {
            let n = attempts.fetch_add(1, Ordering::Relaxed);
            async move {
                if n < 2 {
                    Err(io::Error::from_raw_os_error(231))
                } else {
                    Ok(42_u32)
                }
            }
        },
    )
    .await;
    assert_eq!(res.ok(), Some(42));
    assert_eq!(attempts.load(Ordering::Relaxed), 3);

    // Act 2: immediate fail-fast on ERROR_FILE_NOT_FOUND (< 200 ms)
    let started = Instant::now();
    let offline_res: Result<u32, _> = connect_with_pipe_busy_retry(
        r"\\.\pipe\mesh-agent-ro",
        false,
        IPC_CONNECT_TIMEOUT,
        || async { Err(io::Error::from_raw_os_error(2)) },
    )
    .await;
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(
        offline_res.err().map(|e| e.kind()),
        Some(ErrorKind::Unavailable)
    );

    // Act 3: PermissionDenied preserved on admin channel
    let denied_res: Result<u32, _> = connect_with_pipe_busy_retry(
        r"\\.\pipe\mesh-agent-admin",
        true,
        IPC_CONNECT_TIMEOUT,
        || async { Err(io::Error::from_raw_os_error(5)) },
    )
    .await;
    assert_eq!(
        denied_res.err().map(|e| e.kind()),
        Some(ErrorKind::PermissionDenied)
    );
}

#[tokio::test]
async fn test_ipc_ro_50_peers_over_4kib_version_header_and_legacy_pre_030() {
    // Arrange: build 50-peer AgentStatusResponse exceeding 4 KiB
    let mut peers = Vec::with_capacity(50);
    for idx in 0_u8..50 {
        let Ok(name) = NodeName::parse(&format!("desktop-peer-{idx:02}")) else {
            assert!(NodeName::parse("desktop-peer-00").is_ok());
            return;
        };
        let Ok(ip) = format!("100.115.1.{}", idx + 1).parse::<OverlayIp>() else {
            assert!("100.115.1.1".parse::<OverlayIp>().is_ok());
            return;
        };
        peers.push(AgentPeerStatus {
            node_id: NodeId::from_bytes([idx + 1; 16]),
            name: name.clone(),
            fqdn: format!("{name}.mesh.internal"),
            overlay_ip: ip,
            online: idx % 2 == 0,
            active_path: ActivePathKind::Direct,
            direct_endpoint: Some(format!("198.51.100.{}:51820", idx + 1)),
            rtt_ms: Some(14),
            last_handshake_at_ms: Some(1_799_999_999_000),
            rx_bytes: 12_345,
            tx_bytes: 67_890,
        });
    }
    let status = AgentStatusResponse {
        daemon_state: DaemonState::Connected,
        node_id: Some(NodeId::from_bytes([0x99_u8; 16])),
        node_name: NodeName::parse("host-node").ok(),
        fqdn: Some("host-node.mesh.internal".to_owned()),
        overlay_ip: "100.115.0.2".parse().ok(),
        overlay_cidr: "100.115.0.0/16".parse().ok(),
        tun_interface_name: Some("MeshVPN".to_owned()),
        tun_mtu: 1280,
        netmap_version: 10,
        key_expires_at_ms: None,
        server_connection: None,
        self_network: SelfNetworkStatus {
            local_udp_port: 51820,
            bound_physical_interface: None,
            nat_type: NatMappingKind::EimOrAdm,
            nat_classification_note: None,
            overlay_conflict_warning: None,
            macos_firewall_warning: None,
            candidates: vec![],
        },
        peers,
    };
    let encoded_len = serde_json::to_vec(&status).map_or(0, |v| v.len());
    assert!(
        encoded_len > 4_096 && encoded_len < MAX_HTTP_BODY_BYTES,
        "expected 50-peer JSON between 4 KiB and 64 KiB, got {encoded_len}"
    );

    let router = Router::new()
        .route(
            "/v1/agent/status",
            get(move || {
                let s = status.clone();
                async move {
                    let mut resp = axum::Json(s).into_response();
                    resp.headers_mut()
                        .insert(HEADER_MESH_AGENT_VERSION, HeaderValue::from_static("0.3.0"));
                    resp
                }
            }),
        )
        .route(
            "/v1/agent/version",
            get(|| async {
                axum::Json(AgentVersionResponse {
                    agent_version: "0.3.0".to_owned(),
                    protocol_version: 1,
                    binary_name: "meshd".to_owned(),
                })
            }),
        );

    // Act
    let (client_io, server_io) = duplex(128 * 1024);
    let srv_task = tokio::spawn(serve_ipc_http_connection(server_io, router.clone()));
    let resp_res = send_ipc_json_with_meta::<_, (), AgentStatusResponse>(
        client_io,
        Method::GET,
        "/v1/agent/status",
        None,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await;
    assert!(srv_task.await.is_ok());

    // Assert
    assert!(resp_res.is_ok(), "50-peer RO query failed: {resp_res:?}");
    if let Ok(resp) = resp_res {
        assert_eq!(resp.body.peers.len(), 50);
        assert_eq!(resp.agent_version.as_deref(), Some("0.3.0"));
    }

    // LegacyPre030 classification tests
    let legacy = classify_agent_version_probe(
        None,
        Err(mesh_core::AppError::not_found("not found in v0.1.0-rc1")),
    );
    assert_eq!(legacy.ok(), Some(AgentVersionStatus::LegacyPre030));
    assert_eq!(
        classify_cli_version_probe_exit_code(Some(2), "").ok(),
        Some(AgentVersionStatus::LegacyPre030)
    );
    assert_eq!(
        classify_cli_version_probe_exit_code(Some(0), "meshd 0.3.0\n").ok(),
        Some(AgentVersionStatus::Version("0.3.0".to_owned()))
    );
}

#[tokio::test]
async fn test_ipc_timeout_enforced_when_server_hangs() {
    // Arrange
    let router = Router::new().route(
        "/v1/agent/status",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            "{}"
        }),
    );
    let (client_io, server_io) = duplex(8_192);
    let _srv = tokio::spawn(serve_ipc_http_connection(server_io, router));

    // Act
    let res = send_ipc_json_request_with_timeout::<_, (), serde_json::Value>(
        client_io,
        Method::GET,
        "/v1/agent/status",
        None,
        MAX_HTTP_BODY_BYTES,
        Duration::from_millis(60),
    )
    .await;

    // Assert
    assert_eq!(res.err().map(|e| e.kind()), Some(ErrorKind::Unavailable));
}

#[tokio::test]
async fn test_ipc_bugreport_stream_transfers_chunks_and_rejects_truncation_or_oversize() {
    // Arrange: 150 KiB payload (> 2 chunks of 64 KiB)
    let payload: Vec<u8> = (0..153_600_usize)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let expected_len = payload.len();
    let payload_ok = payload.clone();

    let ok_router = Router::new().route(
        "/v1/agent/bugreport/stream",
        post(move || {
            let bytes = payload_ok.clone();
            async move {
                let len_str = bytes.len().to_string();
                let mut resp = (StatusCode::OK, Body::from(bytes)).into_response();
                if let Ok(hdr) = HeaderValue::from_str(&len_str) {
                    resp.headers_mut().insert(HEADER_MESH_ARCHIVE_BYTES, hdr);
                }
                resp.headers_mut()
                    .insert(HEADER_MESH_SCRUBBED_ITEMS, HeaderValue::from_static("7"));
                resp.headers_mut()
                    .insert(HEADER_MESH_AGENT_VERSION, HeaderValue::from_static("0.3.0"));
                resp
            }
        }),
    );

    let (cli_ok, srv_ok) = duplex(256 * 1024);
    let ok_task = tokio::spawn(serve_ipc_http_connection(srv_ok, ok_router));
    let mut collected = Vec::new();
    let meta = stream_ipc_bugreport(
        cli_ok,
        IPC_ADMIN_MUTATION_TIMEOUT,
        Duration::from_secs(2),
        |chunk| {
            assert!(chunk.len() <= 65_536);
            collected.extend_from_slice(chunk);
            Ok(())
        },
    )
    .await;
    assert!(ok_task.await.is_ok());
    assert!(meta.is_ok(), "stream_ipc_bugreport failed: {meta:?}");
    if let Ok(m) = meta {
        assert_eq!(m.total_bytes, u64::try_from(expected_len).unwrap_or(0));
        assert_eq!(m.scrubbed_items, 7);
        assert_eq!(m.agent_version.as_deref(), Some("0.3.0"));
    }
    assert_eq!(collected, payload);

    // Truncated stream (declares 2048 bytes, sends 512) must fail
    let trunc_router = Router::new().route(
        "/v1/agent/bugreport/stream",
        post(|| async {
            let mut resp = (StatusCode::OK, Body::from(vec![0x55_u8; 512])).into_response();
            resp.headers_mut()
                .insert(HEADER_MESH_ARCHIVE_BYTES, HeaderValue::from_static("2048"));
            resp
        }),
    );
    let (cli_tr, srv_tr) = duplex(16 * 1024);
    let _tr_task = tokio::spawn(serve_ipc_http_connection(srv_tr, trunc_router));
    let tr_res = stream_ipc_bugreport(
        cli_tr,
        Duration::from_secs(2),
        Duration::from_secs(1),
        |_| Ok(()),
    )
    .await;
    assert!(tr_res.is_err());

    // Oversized declaration (> 20 MiB) must fail before reading body
    let over_str = (MAX_BUGREPORT_ARCHIVE_BYTES + 1).to_string();
    let over_router = Router::new().route(
        "/v1/agent/bugreport/stream",
        post(move || {
            let hdr_val = over_str.clone();
            async move {
                let mut resp = (StatusCode::OK, Body::from(vec![1_u8; 16])).into_response();
                if let Ok(hv) = HeaderValue::from_str(&hdr_val) {
                    resp.headers_mut().insert(HEADER_MESH_ARCHIVE_BYTES, hv);
                }
                resp
            }
        }),
    );
    let (cli_ov, srv_ov) = duplex(16 * 1024);
    let _ov_task = tokio::spawn(serve_ipc_http_connection(srv_ov, over_router));
    let ov_res = stream_ipc_bugreport(
        cli_ov,
        Duration::from_secs(2),
        Duration::from_secs(1),
        |_| Ok(()),
    )
    .await;
    assert_eq!(
        ov_res.err().map(|e| e.kind()),
        Some(ErrorKind::InvalidArgument)
    );
}
