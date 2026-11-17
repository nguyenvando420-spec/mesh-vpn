//! Headless End-to-End Desktop IPC, `UnprivilegedSinkWriter` Atomic Replace & `LegacyPre030`
//! Lifecycle Test Suite (`WP-D-C2`, `US-101`, `US-104..107`, `US-110`, `US-112`, `US-116`).
//!
//! Drives the complete desktop client lifecycle over real `mesh-proto` / `mesh-net::ipc` /
//! `axum::Router` / `tokio::io::duplex` channels:
//! `Unconfigured` (`NotEnrolled`) -> `Up` (via `Secret` + `MGH1` `build_up_handoff_payload` +
//! `parse_handoff_request_payload`, verifying `0` secret leak) -> `Connected` with **50 peers**
//! (`> 4 KiB`, `<= 64 KiB` truncation boundary) -> `1-Click Reconnect` preserving `next_pin` ->
//! `Netcheck` -> `Ping` -> `Set` -> `RotateKey` -> `Bugreport` streaming (`<= 64 KiB` chunks)
//! into `UnprivilegedSinkWriter` Atomic `.part` *Replace* (and mid-stream error preserving
//! existing `.tar` with `0` `.part` files left) -> `ResetIdentity` keeping daemon responsive
//! and returning to `Unconfigured` -> `LegacyPre030` detection when `/v1/agent/version` returns
//! `404` without `X-Mesh-Agent-Version`.

#[path = "../src/app.rs"]
mod app;
#[path = "../src/diagnostics_view.rs"]
mod diagnostics_view;
#[path = "../src/onboarding.rs"]
mod onboarding;
#[path = "../src/peers_view.rs"]
mod peers_view;

use std::net::Ipv4Addr;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use mesh_core::defaults::{
    MAX_ADMIN_IPC_BODY_BYTES, MAX_BUGREPORT_ARCHIVE_BYTES, MAX_HTTP_BODY_BYTES,
    MAX_RO_IPC_BODY_BYTES,
};
use mesh_core::error::{ErrorEnvelope, ErrorResponse};
use mesh_core::{
    AppError, ErrorKind, MobileJoinTlsAuth, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin,
    format_join_uri,
};
use mesh_crypto::Secret;
use mesh_net::gui_handoff::{
    HandoffFrame, HandoffResponse, HandoffStreamHeaderPayload, MGH1_PROTOCOL_VERSION,
    build_rotate_key_handoff_payload, build_up_handoff_payload,
    handoff_request_to_agent_rotate_key, handoff_request_to_agent_up,
    parse_handoff_request_payload, read_mgh1_frame, write_mgh1_frame, zeroize_handoff_payload,
};
use mesh_net::ipc::{
    AgentVersionStatus, HEADER_MESH_AGENT_VERSION, HEADER_MESH_ARCHIVE_BYTES,
    HEADER_MESH_SCRUBBED_ITEMS, IPC_ADMIN_MUTATION_TIMEOUT, IPC_NETCHECK_TIMEOUT,
    IPC_RO_QUERY_TIMEOUT, IpcJsonResponse, classify_agent_version_probe,
    classify_cli_version_probe_exit_code, ping_request_timeout, send_ipc_json_request_with_timeout,
    send_ipc_json_with_meta, serve_ipc_http_connection, stream_ipc_bugreport,
};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentActionResponse, AgentPeerStatus, AgentResetIdentityRequest,
    AgentRotateKeyRequest, AgentSetRequest, AgentStatusResponse, AgentUpRequest,
    AgentVersionResponse, DaemonState, NetcheckResponse, PingRequest, PingResponse, PingSample,
    PingVia, SelfNetworkStatus, ServerConnectionStatus, TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::duplex;
use tokio::sync::Mutex;

use crate::app::{
    AgentVersionIndicator, DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState,
    derive_desktop_ui_state, derive_version_indicator, format_user_facing_error,
    is_status_enrolled, sanitize_gui_log_text,
};
use crate::diagnostics_view::{
    DEFAULT_BUGREPORT_FILENAME, format_netcheck_report, format_self_network_panel,
    validate_bugreport_archive_size,
};
use crate::onboarding::{
    ConfirmActionKind, OnboardingTlsMode, parse_mesh_join_uri_to_draft,
    should_lock_system_ca_for_endpoint, validate_manual_onboarding_to_draft,
    validate_rotate_key_to_draft, validate_update_server_payload,
};
use crate::peers_view::{
    filter_peers, format_human_bytes, format_peer_detail_summary, format_peer_list_entry,
    format_ping_response,
};

#[derive(Debug, Clone)]
struct MockDaemonState {
    daemon_state: DaemonState,
    node_id: Option<NodeId>,
    node_name: Option<NodeName>,
    overlay_ip: Option<OverlayIp>,
    control_endpoint: Option<String>,
    tls_auth_mode: TlsAuthMode,
    active_pin: Option<SpkiPin>,
    next_pin: Option<SpkiPin>,
    peers: Vec<AgentPeerStatus>,
    key_rotations: u32,
    bugreport_archive: Vec<u8>,
    truncate_bugreport_at: Option<usize>,
}

impl MockDaemonState {
    fn new_unconfigured(bugreport_archive: Vec<u8>) -> Self {
        Self {
            daemon_state: DaemonState::Stopped,
            node_id: None,
            node_name: None,
            overlay_ip: None,
            control_endpoint: None,
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: None,
            next_pin: None,
            peers: Vec::new(),
            key_rotations: 0,
            bugreport_archive,
            truncate_bugreport_at: None,
        }
    }

    fn build_status(&self) -> AgentStatusResponse {
        let server_connection = self
            .control_endpoint
            .as_ref()
            .map(|ep| ServerConnectionStatus {
                control_endpoint: ep.clone(),
                relay_endpoint: ep.clone(),
                stun_endpoints: vec!["198.51.100.10:3478".to_owned()],
                tls_auth_mode: self.tls_auth_mode,
                active_pin: self.active_pin,
                next_pin: self.next_pin,
                control_connected: self.daemon_state == DaemonState::Connected,
                relay_connected: self.daemon_state == DaemonState::Connected,
                relay_rtt_ms: Some(15),
                migration_pending_endpoint: None,
                last_error: None,
            });
        AgentStatusResponse {
            daemon_state: self.daemon_state,
            node_id: self.node_id,
            node_name: self.node_name.clone(),
            fqdn: self
                .node_name
                .as_ref()
                .map(|n| format!("{}.mesh.internal", n.as_str())),
            overlay_ip: self.overlay_ip,
            overlay_cidr: OverlayCidr::parse("100.64.0.0/10").ok(),
            tun_interface_name: if self.node_id.is_some() {
                Some("MeshVPN".to_owned())
            } else {
                None
            },
            tun_mtu: 1420,
            netmap_version: if self.node_id.is_some() { 11 } else { 0 },
            key_expires_at_ms: self.node_id.map(|_| 1_900_000_000_000),
            server_connection,
            self_network: SelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: Some("Ethernet0".to_owned()),
                nat_type: NatMappingKind::EimOrAdm,
                nat_classification_note: Some("single STUN probe".to_owned()),
                overlay_conflict_warning: Some("10.0.0.0/8 route notice".to_owned()),
                macos_firewall_warning: Some("socketfilterfw check".to_owned()),
                candidates: Vec::new(),
            },
            peers: self.peers.clone(),
        }
    }
}

fn build_50_peers() -> Result<Vec<AgentPeerStatus>, String> {
    let mut peers = Vec::with_capacity(50);
    for idx in 0_u8..50 {
        let name = NodeName::parse(&format!("mesh-peer-{idx:02}")).map_err(|e| format!("{e}"))?;
        let overlay_ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 1, idx.saturating_add(1)))
            .map_err(|e| format!("{e}"))?;
        let active_path = if idx % 3 == 0 {
            ActivePathKind::Direct
        } else if idx % 3 == 1 {
            ActivePathKind::Relay
        } else {
            ActivePathKind::None
        };
        peers.push(AgentPeerStatus {
            node_id: NodeId::from_bytes([idx.saturating_add(1); 16]),
            name: name.clone(),
            fqdn: format!("{}.mesh.internal", name.as_str()),
            overlay_ip,
            online: idx % 5 != 0,
            active_path,
            direct_endpoint: if active_path == ActivePathKind::Direct {
                Some(format!("203.0.113.{}:51820", idx.saturating_add(10)))
            } else {
                None
            },
            rtt_ms: Some(u64::from(idx) + 8),
            last_handshake_at_ms: Some(1_750_000_000_000 + u64::from(idx) * 1_000),
            rx_bytes: 4_096 * (u64::from(idx) + 1),
            tx_bytes: 8_192 * (u64::from(idx) + 1),
        });
    }
    Ok(peers)
}

fn attach_agent_version_header(mut resp: axum::response::Response) -> axum::response::Response {
    resp.headers_mut()
        .insert(HEADER_MESH_AGENT_VERSION, HeaderValue::from_static("0.3.0"));
    resp
}

fn not_found_envelope(msg: &str) -> axum::response::Response {
    let body = ErrorResponse {
        error: ErrorEnvelope {
            kind: ErrorKind::NotFound,
            code: "E_NOT_FOUND".to_owned(),
            message: msg.to_owned(),
            request_id: "req_ro_reject".to_owned(),
        },
    };
    attach_agent_version_header((StatusCode::NOT_FOUND, Json(body)).into_response())
}

fn build_mock_ro_router(state: Arc<Mutex<MockDaemonState>>) -> Router {
    Router::new()
        .route(
            "/v1/agent/status",
            get({
                let st = Arc::clone(&state);
                move || async move {
                    let guard = st.lock().await;
                    attach_agent_version_header(Json(guard.build_status()).into_response())
                }
            }),
        )
        .route(
            "/v1/agent/peers",
            get({
                let st = Arc::clone(&state);
                move || async move {
                    let guard = st.lock().await;
                    attach_agent_version_header(Json(guard.build_status()).into_response())
                }
            }),
        )
        .route(
            "/v1/agent/version",
            get(|| async {
                attach_agent_version_header(
                    Json(AgentVersionResponse {
                        agent_version: "0.3.0".to_owned(),
                        protocol_version: 1,
                        binary_name: "meshd".to_owned(),
                    })
                    .into_response(),
                )
            }),
        )
        .route(
            "/v1/agent/netcheck",
            post(|| async {
                attach_agent_version_header(
                    Json(NetcheckResponse {
                        udp_egress_ok: true,
                        stun_reachable: true,
                        stun_endpoint_tested: Some("198.51.100.10:3478".to_owned()),
                        reflexive_ipv4: Some("203.0.113.88:51820".to_owned()),
                        ipv6_available: true,
                        nat_mapping: NatMappingKind::EimOrAdm,
                        nat_note: "Endpoint-Independent Mapping".to_owned(),
                        control_tcp_reachable: true,
                        control_tcp_endpoint_tested: Some("198.51.100.10:8443".to_owned()),
                        relay_rtt_ms: Some(14.5),
                        diagnostic_hint: Some("Direct UDP P2P ready".to_owned()),
                    })
                    .into_response(),
                )
            }),
        )
        .route(
            "/v1/agent/ping",
            post(|Json(req): Json<PingRequest>| async move {
                let Ok(target_name) =
                    NodeName::parse(&req.target).or_else(|_| NodeName::parse("mesh-peer-00"))
                else {
                    return not_found_envelope("invalid target node name");
                };
                let Ok(target_ip) = OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 1, 1)) else {
                    return not_found_envelope("invalid overlay ip");
                };
                attach_agent_version_header(
                    Json(PingResponse {
                        target_name,
                        target_overlay_ip: target_ip,
                        samples: vec![
                            PingSample {
                                seq: 1,
                                via: PingVia::Relay,
                                endpoint: Some("198.51.100.10:8443".to_owned()),
                                rtt_ms: Some(19.0),
                            },
                            PingSample {
                                seq: 2,
                                via: PingVia::Direct,
                                endpoint: Some("203.0.113.10:51820".to_owned()),
                                rtt_ms: Some(7.5),
                            },
                        ],
                        packets_sent: req.count.max(2),
                        packets_received: 2,
                        loss_percent: 0.0,
                        rtt_min_ms: Some(7.5),
                        rtt_avg_ms: Some(13.25),
                        rtt_max_ms: Some(19.0),
                    })
                    .into_response(),
                )
            }),
        )
        .fallback(|| async { not_found_envelope("route not available on meshd-ro") })
}

fn build_mock_admin_router(state: Arc<Mutex<MockDaemonState>>) -> Router {
    let ro_routes = build_mock_ro_router(Arc::clone(&state));
    let admin_only = Router::new()
        .route(
            "/v1/agent/up",
            post(
                |State(st): State<Arc<Mutex<MockDaemonState>>>,
                 Json(req): Json<AgentUpRequest>| async move {
                    let mut guard = st.lock().await;
                    let is_re_enroll = req.preauth_key.is_some();
                    if is_re_enroll {
                        guard.node_id = Some(NodeId::from_bytes([0x42_u8; 16]));
                        guard.node_name = req
                            .node_name
                            .clone()
                            .or_else(|| NodeName::parse("win-desktop-01").ok());
                        guard.overlay_ip =
                            OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 10)).ok();
                        guard.control_endpoint = Some(req.server_endpoint.clone());
                        guard.active_pin = req.server_pin;
                        guard.next_pin = SpkiPin::parse(
                            "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                        )
                        .ok();
                        if let Ok(peers_50) = build_50_peers() {
                            guard.peers = peers_50;
                        }
                    } else {
                        // 1-Click Reconnect (`preauth_key: None`) preserves `next_pin` when trust matches (`SEC-04(d)`)
                        let same_trust =
                            guard.control_endpoint.as_deref() == Some(req.server_endpoint.as_str())
                                && guard.active_pin == req.server_pin;
                        if !same_trust {
                            guard.control_endpoint = Some(req.server_endpoint.clone());
                            guard.active_pin = req.server_pin;
                            guard.next_pin = None;
                        }
                    }
                    guard.daemon_state = DaemonState::Connected;
                    attach_agent_version_header(
                        Json(AgentActionResponse {
                            state: DaemonState::Connected,
                            message: "tunnel connected".to_owned(),
                        })
                        .into_response(),
                    )
                },
            ),
        )
        .route(
            "/v1/agent/down",
            post(|State(st): State<Arc<Mutex<MockDaemonState>>>| async move {
                let mut guard = st.lock().await;
                guard.daemon_state = DaemonState::Stopped;
                attach_agent_version_header(
                    Json(AgentActionResponse {
                        state: DaemonState::Stopped,
                        message: "tunnel stopped".to_owned(),
                    })
                    .into_response(),
                )
            }),
        )
        .route(
            "/v1/agent/set",
            post(
                |State(st): State<Arc<Mutex<MockDaemonState>>>,
                 Json(req): Json<AgentSetRequest>| async move {
                    let mut guard = st.lock().await;
                    let same_trust =
                        guard.control_endpoint.as_deref() == Some(req.server_endpoint.as_str())
                            && guard.active_pin == req.server_pin;
                    if !same_trust {
                        guard.active_pin = req.server_pin;
                        guard.next_pin = None;
                        guard.control_endpoint = Some(req.server_endpoint);
                    }
                    attach_agent_version_header(
                        Json(AgentActionResponse {
                            state: guard.daemon_state,
                            message: "server configuration updated".to_owned(),
                        })
                        .into_response(),
                    )
                },
            ),
        )
        .route(
            "/v1/agent/rotate-key",
            post(
                |State(st): State<Arc<Mutex<MockDaemonState>>>,
                 Json(req): Json<AgentRotateKeyRequest>| async move {
                    let _dbg_redacted = format!("{req:?}");
                    let mut guard = st.lock().await;
                    guard.key_rotations = guard.key_rotations.saturating_add(1);
                    guard.daemon_state = DaemonState::Connected;
                    attach_agent_version_header(
                        Json(AgentActionResponse {
                            state: DaemonState::Connected,
                            message: "node key rotated".to_owned(),
                        })
                        .into_response(),
                    )
                },
            ),
        )
        .route(
            "/v1/agent/reset-identity",
            post(
                |State(st): State<Arc<Mutex<MockDaemonState>>>,
                 Json(_req): Json<AgentResetIdentityRequest>| async move {
                    let mut guard = st.lock().await;
                    guard.daemon_state = DaemonState::Stopped;
                    guard.node_id = None;
                    guard.node_name = None;
                    guard.overlay_ip = None;
                    guard.control_endpoint = None;
                    guard.active_pin = None;
                    guard.next_pin = None;
                    guard.peers.clear();
                    attach_agent_version_header(
                        Json(AgentActionResponse {
                            state: DaemonState::Stopped,
                            message: "node identity reset cleanly; ready for enrollment".to_owned(),
                        })
                        .into_response(),
                    )
                },
            ),
        )
        .route(
            "/v1/agent/bugreport/stream",
            post(|State(st): State<Arc<Mutex<MockDaemonState>>>| async move {
                let guard = st.lock().await;
                let declared_len = guard.bugreport_archive.len();
                let body_bytes = match guard.truncate_bugreport_at {
                    Some(cut) => guard
                        .bugreport_archive
                        .get(..cut.min(declared_len))
                        .unwrap_or(&[])
                        .to_vec(),
                    None => guard.bugreport_archive.clone(),
                };
                drop(guard);

                let mut resp = (StatusCode::OK, Body::from(body_bytes)).into_response();
                if let Ok(hv) = HeaderValue::from_str(&declared_len.to_string()) {
                    resp.headers_mut().insert(HEADER_MESH_ARCHIVE_BYTES, hv);
                }
                resp.headers_mut()
                    .insert(HEADER_MESH_SCRUBBED_ITEMS, HeaderValue::from_static("6"));
                attach_agent_version_header(resp)
            }),
        )
        .with_state(state);

    admin_only.merge(ro_routes)
}

async fn call_ipc_with_meta<Req, Resp>(
    router: Router,
    method: Method,
    path: &str,
    body: Option<&Req>,
    max_bytes: usize,
    timeout: Duration,
) -> Result<IpcJsonResponse<Resp>, AppError>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let (cli, srv) = duplex(128 * 1024);
    let srv_task = tokio::spawn(serve_ipc_http_connection(srv, router));
    let res = send_ipc_json_with_meta(cli, method, path, body, max_bytes, timeout).await;
    let _srv_done = srv_task.await;
    res
}

async fn call_ipc<Req, Resp>(
    router: Router,
    method: Method,
    path: &str,
    body: Option<&Req>,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Resp, AppError>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let (cli, srv) = duplex(128 * 1024);
    let srv_task = tokio::spawn(serve_ipc_http_connection(srv, router));
    let res = send_ipc_json_request_with_timeout(cli, method, path, body, max_bytes, timeout).await;
    let _srv_done = srv_task.await;
    res
}

#[tokio::test]
async fn test_e2e_desktop_ipc_lifecycle_50_peers_sink_replace_reset_and_legacy()
-> Result<(), String> {
    // Prepare a 150 KiB (> 2 chunks of 64 KiB) deterministic `.tar` archive payload
    let archive_payload: Vec<u8> = (0..150_000_usize)
        .map(|i| u8::try_from((i * 7 + 13) % 251).unwrap_or(0))
        .collect();
    let mock_state = Arc::new(Mutex::new(MockDaemonState::new_unconfigured(
        archive_payload.clone(),
    )));
    let ro_router = build_mock_ro_router(Arc::clone(&mock_state));
    let admin_router = build_mock_admin_router(Arc::clone(&mock_state));

    // =========================================================================
    // Phase 1: `Unconfigured` (`Stopped`, unenrolled) + RO channel isolation
    // =========================================================================
    let initial_meta: IpcJsonResponse<AgentStatusResponse> = call_ipc_with_meta(
        ro_router.clone(),
        Method::GET,
        "/v1/agent/status",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(initial_meta.agent_version.as_deref(), Some("0.3.0"));
    assert!(!is_status_enrolled(&initial_meta.body));

    let ver_resp: AgentVersionResponse = call_ipc(
        ro_router.clone(),
        Method::GET,
        "/v1/agent/version",
        None::<&()>,
        MAX_RO_IPC_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    let ver_status =
        classify_agent_version_probe(initial_meta.agent_version.as_deref(), Ok(ver_resp))
            .map_err(|e| e.to_string())?;
    assert_eq!(ver_status, AgentVersionStatus::Version("0.3.0".to_owned()));

    let ui_unconfigured = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&initial_meta.body),
        version_status: Some(&ver_status),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(ui_unconfigured.ui_state, DesktopUiState::NotEnrolled);
    assert_eq!(
        ui_unconfigured.tunnel_sub_state,
        TunnelSubState::NotEnrolled
    );
    assert!(!ui_unconfigured.enrolled);
    assert!(ui_unconfigured.legacy_banner.is_none());
    assert!(ui_unconfigured.version_mismatch_banner.is_none());
    assert!(ui_unconfigured.recoverable_error.is_none());

    // RO channel must reject admin mutations with NotFound
    let ro_up_reject: Result<AgentActionResponse, AppError> = call_ipc(
        ro_router.clone(),
        Method::POST,
        "/v1/agent/reset-identity",
        Some(&AgentResetIdentityRequest {}),
        MAX_RO_IPC_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await;
    assert_eq!(
        ro_up_reject.err().map(|e| e.kind()),
        Some(ErrorKind::NotFound)
    );

    // =========================================================================
    // Phase 2: `Up` via `Secret` + `build_up_handoff_payload` + `MGH1` framing
    // =========================================================================
    let active_pin_str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let active_pin = SpkiPin::parse(active_pin_str).map_err(|e| e.to_string())?;
    let next_pin =
        SpkiPin::parse("sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
            .map_err(|e| e.to_string())?;
    let enroll_token = "mpk_RW5yb2xsQ2FuYXJ5VG9rZW5Gb3JFMkVEZXNrdG9wVGVzdA";
    assert!(should_lock_system_ca_for_endpoint("198.51.100.10:8443"));

    let join_uri = format_join_uri(
        "198.51.100.10:8443",
        &MobileJoinTlsAuth::SpkiPin(active_pin),
        enroll_token,
        Some(&NodeName::parse("win-desktop-01").map_err(|e| e.to_string())?),
    )
    .map_err(|e| e.to_string())?;
    let (form_from_uri, draft_from_uri) = parse_mesh_join_uri_to_draft(&join_uri, "")?;
    assert!(!format!("{form_from_uri:?}").contains(enroll_token));
    assert!(!format!("{draft_from_uri:?}").contains(enroll_token));
    assert_eq!(draft_from_uri.action_kind, ConfirmActionKind::EnrollNewNode);
    assert_eq!(draft_from_uri.tls_mode, OnboardingTlsMode::SpkiPin);
    assert_eq!(draft_from_uri.server_pin, Some(active_pin));
    assert!(draft_from_uri.port_override.is_some());
    assert!(draft_from_uri.node_name.is_some());
    assert!(!draft_from_uri.masked_preauth_preview.contains(enroll_token));
    assert!(
        !draft_from_uri
            .format_confirmation_summary()
            .contains(enroll_token)
    );

    let manual_draft = validate_manual_onboarding_to_draft(&form_from_uri)?;
    let mut handoff_up_bytes = manual_draft.build_handoff_payload()?;

    // Also verify direct `build_up_handoff_payload` with `Secret<String>` over async MGH1 stream
    let secret_key = Secret::new(enroll_token.to_owned());
    let direct_up_bytes = build_up_handoff_payload(
        &manual_draft.normalized_endpoint,
        manual_draft.port_override,
        manual_draft.server_pin,
        Some(&secret_key),
        manual_draft.node_name.clone(),
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(handoff_up_bytes.as_slice(), direct_up_bytes.as_slice());

    let (mut handoff_cli, mut handoff_srv) = duplex(64 * 1024);
    write_mgh1_frame(
        &mut handoff_cli,
        &HandoffFrame::WorkerHello {
            protocol_version: MGH1_PROTOCOL_VERSION,
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let rx_hello = read_mgh1_frame(&mut handoff_srv)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        rx_hello,
        HandoffFrame::WorkerHello {
            protocol_version: MGH1_PROTOCOL_VERSION
        }
    );

    let tx_req_frame = HandoffFrame::HandoffRequest(handoff_up_bytes.clone());
    assert!(!format!("{tx_req_frame:?}").contains(enroll_token));
    write_mgh1_frame(&mut handoff_srv, &tx_req_frame)
        .await
        .map_err(|e| e.to_string())?;
    zeroize_handoff_payload(&mut handoff_up_bytes);
    assert!(handoff_up_bytes.is_empty());

    let rx_req_frame = read_mgh1_frame(&mut handoff_cli)
        .await
        .map_err(|e| e.to_string())?;
    let HandoffFrame::HandoffRequest(worker_payload) = rx_req_frame else {
        return Err("expected MGH1 HandoffRequest frame".to_owned());
    };
    let parsed_handoff_req =
        parse_handoff_request_payload(worker_payload.as_slice()).map_err(|e| e.to_string())?;
    assert!(!format!("{parsed_handoff_req:?}").contains(enroll_token));
    let agent_up_req =
        handoff_request_to_agent_up(&parsed_handoff_req).map_err(|e| e.to_string())?;
    assert!(!format!("{agent_up_req:?}").contains(enroll_token));
    assert!(!sanitize_gui_log_text(&format!("enroll key={enroll_token}")).contains(enroll_token));

    let up_action: AgentActionResponse = call_ipc(
        admin_router.clone(),
        Method::POST,
        "/v1/agent/up",
        Some(&agent_up_req),
        MAX_ADMIN_IPC_BODY_BYTES,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(up_action.state, DaemonState::Connected);
    let handoff_up_resp = HandoffResponse::from_action(up_action);
    assert!(handoff_up_resp.into_action_result().is_ok());

    // =========================================================================
    // Phase 3: `Connected` with 50 peers (> 4 KiB, <= 64 KiB) + 1-Click Reconnect
    // =========================================================================
    let connected_status: AgentStatusResponse = call_ipc(
        ro_router.clone(),
        Method::GET,
        "/v1/agent/peers",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    let raw_status_json =
        serde_json::to_vec(&connected_status).map_err(|e| format!("serialize status: {e}"))?;
    assert!(
        raw_status_json.len() > MAX_RO_IPC_BODY_BYTES
            && raw_status_json.len() <= MAX_HTTP_BODY_BYTES,
        "expected 50-peer payload in (4096..=65536], got {}",
        raw_status_json.len()
    );
    assert_eq!(connected_status.peers.len(), 50);
    assert_eq!(
        connected_status
            .server_connection
            .as_ref()
            .and_then(|s| s.next_pin),
        Some(next_pin)
    );

    let ui_connected = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&connected_status),
        version_status: Some(&ver_status),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(ui_connected.ui_state, DesktopUiState::Connected);
    assert_eq!(ui_connected.tunnel_sub_state, TunnelSubState::Connected);
    assert!(ui_connected.enrolled);
    assert!(!ui_connected.ui_state.label().is_empty());
    assert!(
        !ui_connected
            .ui_state
            .headline(ui_connected.tunnel_sub_state)
            .is_empty()
    );
    assert!(
        !ui_connected
            .ui_state
            .tray_tooltip_summary(ui_connected.tunnel_sub_state)
            .is_empty()
    );

    // Exercise peer filtering & diagnostics panel formatting across 50 peers
    assert_eq!(filter_peers(&connected_status.peers, "").len(), 50);
    assert_eq!(
        filter_peers(&connected_status.peers, "mesh-peer-25").len(),
        1
    );
    for sample_peer in connected_status.peers.iter().take(3) {
        assert!(!format_peer_list_entry(sample_peer).is_empty());
        assert!(!format_peer_detail_summary(sample_peer).is_empty());
    }
    assert_eq!(format_human_bytes(900), "900 B");
    assert_eq!(format_human_bytes(4096), "4.0 KiB");
    assert_eq!(format_human_bytes(2 * 1024 * 1024), "2.0 MiB");
    assert_eq!(format_human_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    assert!(format_self_network_panel(&connected_status).contains("MeshVPN"));

    // Disconnect (`down`) -> 1-Click Reconnect (`preauth_key: None`) preserves `next_pin`
    let down_resp: AgentActionResponse = call_ipc(
        admin_router.clone(),
        Method::POST,
        "/v1/agent/down",
        None::<&()>,
        MAX_ADMIN_IPC_BODY_BYTES,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(down_resp.state, DaemonState::Stopped);

    let reconnect_payload =
        build_up_handoff_payload("198.51.100.10:8443", None, Some(active_pin), None, None)
            .map_err(|e| e.to_string())?;
    let reconnect_handoff =
        parse_handoff_request_payload(reconnect_payload.as_slice()).map_err(|e| e.to_string())?;
    let reconnect_up =
        handoff_request_to_agent_up(&reconnect_handoff).map_err(|e| e.to_string())?;
    let reconnect_resp: AgentActionResponse = call_ipc(
        admin_router.clone(),
        Method::POST,
        "/v1/agent/up",
        Some(&reconnect_up),
        MAX_ADMIN_IPC_BODY_BYTES,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(reconnect_resp.state, DaemonState::Connected);
    let after_reconnect: AgentStatusResponse = call_ipc(
        ro_router.clone(),
        Method::GET,
        "/v1/agent/status",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(
        after_reconnect
            .server_connection
            .as_ref()
            .and_then(|s| s.next_pin),
        Some(next_pin)
    );

    // =========================================================================
    // Phase 4: `Netcheck` & `Ping` over `meshd-ro`
    // =========================================================================
    let netcheck_resp: NetcheckResponse = call_ipc(
        ro_router.clone(),
        Method::POST,
        "/v1/agent/netcheck",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_NETCHECK_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert!(netcheck_resp.udp_egress_ok && netcheck_resp.stun_reachable);
    assert!(format_netcheck_report(&netcheck_resp).contains("203.0.113.88:51820"));

    let ping_req = PingRequest {
        target: "mesh-peer-01".to_owned(),
        count: 2,
        force_direct: false,
        timeout_ms: 2_000,
    };
    let ping_resp: PingResponse = call_ipc(
        ro_router.clone(),
        Method::POST,
        "/v1/agent/ping",
        Some(&ping_req),
        MAX_HTTP_BODY_BYTES,
        ping_request_timeout(ping_req.count, ping_req.timeout_ms),
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(ping_resp.packets_received, 2);
    assert!(format_ping_response(&ping_resp).contains("mesh-peer-01"));

    // =========================================================================
    // Phase 5: `Set` & `RotateKey` (`ReauthRequired` -> `Connected`)
    // =========================================================================
    let (norm_set_ep, _set_handoff_bytes) = validate_update_server_payload(
        "198.51.100.10:8443",
        OnboardingTlsMode::SpkiPin,
        active_pin_str,
    )?;
    let set_resp: AgentActionResponse = call_ipc(
        admin_router.clone(),
        Method::POST,
        "/v1/agent/set",
        Some(&AgentSetRequest {
            server_endpoint: norm_set_ep,
            server_pin: Some(active_pin),
        }),
        MAX_ADMIN_IPC_BODY_BYTES,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(set_resp.state, DaemonState::Connected);

    {
        let mut guard = mock_state.lock().await;
        guard.daemon_state = DaemonState::ReauthRequired;
    }
    let reauth_status: AgentStatusResponse = call_ipc(
        ro_router.clone(),
        Method::GET,
        "/v1/agent/status",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    let ui_reauth = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&reauth_status),
        version_status: Some(&ver_status),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(ui_reauth.ui_state, DesktopUiState::ReauthRequired);
    assert_eq!(ui_reauth.tunnel_sub_state, TunnelSubState::ReauthRequired);

    let rot_token = "mpk_Um90YXRlS2V5VG9rZW5Gb3JFMkVEZXNrdG9wVGVzdDAx";
    let rot_draft = validate_rotate_key_to_draft(
        "198.51.100.10:8443",
        OnboardingTlsMode::SpkiPin,
        Some(active_pin),
        rot_token,
    )?;
    assert_eq!(rot_draft.action_kind, ConfirmActionKind::RotateKey);
    let rot_secret = Secret::new(rot_token.to_owned());
    let rot_payload = build_rotate_key_handoff_payload(&rot_secret).map_err(|e| e.to_string())?;
    let rot_handoff =
        parse_handoff_request_payload(rot_payload.as_slice()).map_err(|e| e.to_string())?;
    let agent_rot_req =
        handoff_request_to_agent_rotate_key(&rot_handoff).map_err(|e| e.to_string())?;
    assert!(!format!("{agent_rot_req:?}").contains(rot_token));

    let rot_resp: AgentActionResponse = call_ipc(
        admin_router.clone(),
        Method::POST,
        "/v1/agent/rotate-key",
        Some(&agent_rot_req),
        MAX_ADMIN_IPC_BODY_BYTES,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(rot_resp.state, DaemonState::Connected);

    // =========================================================================
    // Phase 6: `Bugreport` streaming `<= 64 KiB` chunks + Atomic `.part` Replace
    //          (and mid-stream truncation preserving prior `.tar` with 0 `.part`)
    // =========================================================================
    assert_eq!(DEFAULT_BUGREPORT_FILENAME, "meshvpn-bugreport.tar");
    assert_eq!(
        validate_bugreport_archive_size(u64::try_from(archive_payload.len()).unwrap_or(0)),
        Ok(u64::try_from(archive_payload.len()).unwrap_or(0))
    );
    assert!(validate_bugreport_archive_size(0).is_err());
    assert!(
        validate_bugreport_archive_size(
            u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(20_971_520) + 1
        )
        .is_err()
    );

    let temp_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let dest_tar = temp_dir.path().join(DEFAULT_BUGREPORT_FILENAME);
    let prior_tar_bytes = b"prior-intact-bugreport-archive".to_vec();
    std::fs::write(&dest_tar, &prior_tar_bytes).map_err(|e| e.to_string())?;

    // 6a. Simulate mid-stream truncation at 40,000 bytes (of 150,000 declared)
    {
        let mut guard = mock_state.lock().await;
        guard.truncate_bugreport_at = Some(40_000);
    }
    #[cfg(target_os = "windows")]
    {
        let declared_u64 = u64::try_from(archive_payload.len()).unwrap_or(0);
        let mut sink =
            mesh_sys::gui_windows::UnprivilegedSinkWriter::create(&dest_tar, declared_u64)
                .map_err(|e| e.to_string())?;
        let part_path = sink.temp_path().to_path_buf();
        let (cli_io, srv_io) = duplex(256 * 1024);
        let srv_task = tokio::spawn(serve_ipc_http_connection(srv_io, admin_router.clone()));
        let stream_res = stream_ipc_bugreport(
            cli_io,
            IPC_ADMIN_MUTATION_TIMEOUT,
            Duration::from_secs(2),
            |chunk| {
                assert!(chunk.len() <= 65_536);
                sink.write_chunk(chunk)
                    .map_err(|e| AppError::unavailable(e.to_string()))
            },
        )
        .await;
        let _srv_done = srv_task.await;
        assert!(
            stream_res.is_err(),
            "truncated stream must return Err before finalize"
        );
        drop(sink);
        assert!(
            !part_path.exists(),
            "aborted UnprivilegedSinkWriter must remove .part sibling"
        );
        assert_eq!(
            std::fs::read(&dest_tar).map_err(|e| e.to_string())?,
            prior_tar_bytes,
            "existing destination .tar must remain untouched on mid-stream failure"
        );
    }

    // 6b. Full 150,000-byte stream (`<= 64 KiB` chunks) atomically replaces existing `.tar`
    {
        let mut guard = mock_state.lock().await;
        guard.truncate_bugreport_at = None;
    }
    let (cli_io, srv_io) = duplex(256 * 1024);
    let srv_task = tokio::spawn(serve_ipc_http_connection(srv_io, admin_router.clone()));
    let mut chunk_lengths = Vec::new();

    #[cfg(target_os = "windows")]
    let stream_meta = {
        let declared_u64 = u64::try_from(archive_payload.len()).unwrap_or(0);
        let mut sink =
            mesh_sys::gui_windows::UnprivilegedSinkWriter::create(&dest_tar, declared_u64)
                .map_err(|e| e.to_string())?;
        let part_path = sink.temp_path().to_path_buf();
        let meta = stream_ipc_bugreport(
            cli_io,
            IPC_ADMIN_MUTATION_TIMEOUT,
            Duration::from_secs(2),
            |chunk| {
                assert!(!chunk.is_empty() && chunk.len() <= 65_536);
                chunk_lengths.push(chunk.len());
                sink.write_chunk(chunk)
                    .map_err(|e| AppError::unavailable(e.to_string()))
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let committed = sink.finalize().map_err(|e| e.to_string())?;
        assert_eq!(committed, declared_u64);
        assert!(!part_path.exists());
        meta
    };

    #[cfg(not(target_os = "windows"))]
    let stream_meta = {
        let part_path = temp_dir.path().join(".mesh-bugreport-test.tar.part");
        let mut received = Vec::new();
        let meta = stream_ipc_bugreport(
            cli_io,
            IPC_ADMIN_MUTATION_TIMEOUT,
            Duration::from_secs(2),
            |chunk| {
                assert!(!chunk.is_empty() && chunk.len() <= 65_536);
                chunk_lengths.push(chunk.len());
                received.extend_from_slice(chunk);
                Ok(())
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        std::fs::write(&part_path, &received).map_err(|e| e.to_string())?;
        std::fs::rename(&part_path, &dest_tar).map_err(|e| e.to_string())?;
        meta
    };

    let _srv_done = srv_task.await;
    assert!(
        chunk_lengths.len() >= 3,
        "150 KiB archive must stream across multiple <= 64 KiB chunks"
    );
    assert_eq!(
        stream_meta.total_bytes,
        u64::try_from(archive_payload.len()).unwrap_or(0)
    );
    assert_eq!(stream_meta.scrubbed_items, 6);
    assert_eq!(stream_meta.agent_version.as_deref(), Some("0.3.0"));
    assert_eq!(
        std::fs::read(&dest_tar).map_err(|e| e.to_string())?,
        archive_payload
    );

    // Ensure 0 leftover `.part` files in `temp_dir`
    for entry_res in std::fs::read_dir(temp_dir.path()).map_err(|e| e.to_string())? {
        let entry = entry_res.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !name.ends_with(".part"),
            "unexpected leftover .part file: {name}"
        );
    }

    // Also verify MGH1 `0x02 HandoffStreamHeader` + `0x03 BugreportChunk` + `0x04 HandoffResponse`
    let mgh1_hdr = HandoffFrame::HandoffStreamHeader(HandoffStreamHeaderPayload {
        total_bytes: stream_meta.total_bytes,
        scrubbed_items: stream_meta.scrubbed_items,
    });
    write_mgh1_frame(&mut handoff_cli, &mgh1_hdr)
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        read_mgh1_frame(&mut handoff_srv)
            .await
            .map_err(|e| e.to_string())?,
        mgh1_hdr
    );

    // =========================================================================
    // Phase 7: `ResetIdentity` (`Revoked` -> `POST /v1/agent/reset-identity` -> `NotEnrolled`)
    // =========================================================================
    {
        let mut guard = mock_state.lock().await;
        guard.daemon_state = DaemonState::Revoked;
    }
    let revoked_status: AgentStatusResponse = call_ipc(
        ro_router.clone(),
        Method::GET,
        "/v1/agent/status",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    let ui_revoked = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&revoked_status),
        version_status: Some(&ver_status),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(ui_revoked.ui_state, DesktopUiState::Revoked);
    assert_eq!(ui_revoked.tunnel_sub_state, TunnelSubState::Revoked);

    let reset_resp: AgentActionResponse = call_ipc(
        admin_router.clone(),
        Method::POST,
        "/v1/agent/reset-identity",
        Some(&AgentResetIdentityRequest {}),
        MAX_ADMIN_IPC_BODY_BYTES,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(reset_resp.state, DaemonState::Stopped);

    // Daemon stays alive and responsive on RO channel, now reporting `NotEnrolled`
    let post_reset_status: AgentStatusResponse = call_ipc(
        ro_router,
        Method::GET,
        "/v1/agent/status",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert!(!is_status_enrolled(&post_reset_status));
    let ui_post_reset = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&post_reset_status),
        version_status: Some(&ver_status),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(ui_post_reset.ui_state, DesktopUiState::NotEnrolled);

    // =========================================================================
    // Phase 8: `LegacyPre030` detection when `/v1/agent/version` returns `404`
    //          without `X-Mesh-Agent-Version`
    // =========================================================================
    let legacy_status = post_reset_status.clone();
    let legacy_router = Router::new().route(
        "/v1/agent/status",
        get(move || {
            let st = legacy_status.clone();
            async move { Json(st) }
        }),
    );
    let legacy_meta: IpcJsonResponse<AgentStatusResponse> = call_ipc_with_meta(
        legacy_router.clone(),
        Method::GET,
        "/v1/agent/status",
        None::<&()>,
        MAX_HTTP_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| e.to_string())?;
    assert_eq!(legacy_meta.agent_version, None);

    let legacy_ver_call: Result<AgentVersionResponse, AppError> = call_ipc(
        legacy_router,
        Method::GET,
        "/v1/agent/version",
        None::<&()>,
        MAX_RO_IPC_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await;
    assert_eq!(
        legacy_ver_call.as_ref().err().map(AppError::kind),
        Some(ErrorKind::NotFound)
    );
    let classified_legacy =
        classify_agent_version_probe(legacy_meta.agent_version.as_deref(), legacy_ver_call)
            .map_err(|e| e.to_string())?;
    assert_eq!(classified_legacy, AgentVersionStatus::LegacyPre030);
    assert_eq!(
        classify_cli_version_probe_exit_code(Some(2), "").ok(),
        Some(AgentVersionStatus::LegacyPre030)
    );

    let ui_legacy = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&legacy_meta.body),
        version_status: Some(&classified_legacy),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(
        ui_legacy.version_indicator,
        AgentVersionIndicator::LegacyPre030
    );
    assert!(ui_legacy.legacy_banner.is_some());

    // Exercise remaining `app.rs` variants so `clippy --all-targets` has 0 dead_code warnings
    for probe in [
        ServiceProbeKind::Stopped,
        ServiceProbeKind::NotInstalled,
        ServiceProbeKind::Unknown,
    ] {
        let snap = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.3.0",
            service_probe: probe,
            ipc_connected: false,
            status: None,
            version_status: None,
            ipc_error: Some("offline"),
            active_action_error: None,
        });
        assert_eq!(snap.version_indicator, AgentVersionIndicator::Unknown);
        assert_eq!(
            derive_version_indicator(
                "0.3.0",
                Some(&AgentVersionStatus::Version("0.2.9".to_owned()))
            ),
            AgentVersionIndicator::Mismatch {
                gui_version: "0.3.0".to_owned(),
                agent_version: "0.2.9".to_owned()
            }
        );
    }
    for sub in [
        TunnelSubState::Connecting,
        TunnelSubState::Degraded,
        TunnelSubState::Disconnected,
    ] {
        let mut st = connected_status.clone();
        st.daemon_state = match sub {
            TunnelSubState::Connecting => DaemonState::Connecting,
            TunnelSubState::Degraded => DaemonState::Degraded,
            _ => DaemonState::Stopped,
        };
        let snap = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.3.0",
            service_probe: ServiceProbeKind::Running,
            ipc_connected: true,
            status: Some(&st),
            version_status: Some(&AgentVersionStatus::Version("0.2.9".to_owned())),
            ipc_error: None,
            active_action_error: Some("Unauthenticated"),
        });
        assert!(snap.version_mismatch_banner.is_some());
        assert_eq!(
            snap.recoverable_error.as_deref(),
            Some("authentication failed")
        );
        assert_eq!(
            format_user_facing_error("Unauthenticated"),
            "authentication failed"
        );
    }

    #[cfg(target_os = "windows")]
    {
        let log_dir = crate::app::gui_log_directory(Some(Path::new(r"C:\LocalAppData")));
        assert!(log_dir.is_some_and(|p| {
            p.ends_with(
                Path::new(crate::app::GUI_APP_DATA_DIR_NAME).join(crate::app::GUI_LOG_SUBDIR),
            )
        }));
    }

    Ok(())
}
