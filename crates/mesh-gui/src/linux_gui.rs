//! Native Linux Desktop GUI runtime, Polkit `MGH1` UDS elevation worker, and FreeDesktop
//! autostart integration (`MeshVPN` on Ubuntu/Debian/Linux).

use std::fs::{self, Permissions};
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use mesh_core::defaults::{
    MAX_ADMIN_IPC_BODY_BYTES, MAX_BUGREPORT_ARCHIVE_BYTES, MAX_RO_IPC_BODY_BYTES,
    UNIX_AGENT_ADMIN_SOCKET, UNIX_AGENT_RO_SOCKET,
};
use mesh_core::logging::{LogGuard, LoggingConfig, init_json_logging};
use mesh_core::{AppError, AppResult, ErrorKind, NodeName, SpkiPin};
use mesh_crypto::{ct_eq_bytes, random_bytes};
use mesh_net::gui_handoff::{
    HANDOFF_UAC_WAIT_TIMEOUT, HANDOFF_WORKER_HELLO_TIMEOUT, HandoffFrame, HandoffRequest,
    HandoffResponse, MGH1_PROTOCOL_VERSION, handoff_request_to_agent_rotate_key,
    handoff_request_to_agent_up, parse_handoff_request_payload, read_mgh1_frame,
    serialize_handoff_request_zeroizing, write_mgh1_frame,
};
use mesh_net::ipc::{
    AgentVersionStatus, IPC_ADMIN_MUTATION_TIMEOUT, IPC_NETCHECK_TIMEOUT, IPC_RO_QUERY_TIMEOUT,
    IPC_STREAM_CHUNK_IDLE_TIMEOUT, connect_agent_unix_socket, ping_request_timeout,
    send_ipc_json_request_with_timeout, send_ipc_json_with_meta, stream_ipc_bugreport,
};
use mesh_net::ledger::ResourceLedger;
use mesh_net::route_linux::LinuxCleanupOps;
use mesh_proto::agent_ipc::{
    AgentActionResponse, AgentResetIdentityRequest, AgentSetRequest, AgentStatusResponse,
    AgentVersionResponse, DaemonState, NetcheckResponse, PingRequest, PingResponse,
};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::process::Command as TokioCommand;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::app::{
    DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState, derive_desktop_ui_state,
    format_user_facing_error, gui_log_directory, sanitize_gui_log_text,
};
use crate::diagnostics_view::{
    DEFAULT_BUGREPORT_FILENAME, format_netcheck_report, format_self_network_panel,
    validate_bugreport_archive_size,
};
use crate::onboarding::{
    ConfirmActionKind, EnrollmentConfirmationDraft, OnboardingFormInput, OnboardingTlsMode,
    parse_mesh_join_uri_to_draft, should_lock_system_ca_for_endpoint,
    validate_manual_onboarding_to_draft, validate_rotate_key_to_draft,
    validate_update_server_payload,
};
use crate::peers_view::{
    filter_peers, format_human_bytes, format_peer_detail_summary, format_peer_list_entry,
    format_ping_response,
};

const GUI_LOG_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
const GUI_LOG_MAX_TOTAL_BYTES: u64 = 20 * 1024 * 1024;
const FALLBACK_UNIX_AGENT_RO_SOCKET: &str = "/run/meshd/meshd-ro.sock";
const FALLBACK_UNIX_AGENT_ADMIN_SOCKET: &str = "/run/meshd/meshd-admin.sock";
const LINUX_HANDOFF_SOCKET_PREFIX: &str = "/tmp/mesh-gui-handoff-";
const LINUX_HANDOFF_SOCKET_SUFFIX: &str = ".sock";
const AUTOSTART_DESKTOP_FILENAME: &str = "mesh-vpn.desktop";

const INDEX_HTML: &str = include_str!("../assets/linux_ui/index.html");
const APP_CSS: &str = include_str!("../assets/linux_ui/app.css");
const APP_JS: &str = include_str!("../assets/linux_ui/app.js");

/// Parsed CLI launch mode for Linux `MeshVPN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinuxGuiLaunchMode {
    Normal { start_minimized: bool },
    ElevatedWorker { socket_path: String },
    CheckConfig,
    PrintVersion,
    PrintHelp,
}

/// Parses Linux `MeshVPN` CLI arguments into [`LinuxGuiLaunchMode`].
pub(crate) fn parse_linux_gui_args<I>(args: I) -> Result<LinuxGuiLaunchMode, String>
where
    I: IntoIterator<Item = String>,
{
    let items: Vec<String> = args.into_iter().collect();
    let rest = items.get(1..).unwrap_or(&[]);
    match rest {
        [] => Ok(LinuxGuiLaunchMode::Normal {
            start_minimized: false,
        }),
        [flag] if flag == "--minimized" || flag == "--no-browser" => {
            Ok(LinuxGuiLaunchMode::Normal {
                start_minimized: true,
            })
        }
        [flag] if flag == "--check-config" => Ok(LinuxGuiLaunchMode::CheckConfig),
        [flag] if flag == "--version" || flag == "-V" => Ok(LinuxGuiLaunchMode::PrintVersion),
        [flag] if flag == "--help" || flag == "-h" => Ok(LinuxGuiLaunchMode::PrintHelp),
        [flag, pipe_flag, sock]
            if flag == "--elevated-worker" && pipe_flag == "--pipe" && !sock.trim().is_empty() =>
        {
            validate_linux_handoff_socket_path(sock)?;
            Ok(LinuxGuiLaunchMode::ElevatedWorker {
                socket_path: sock.clone(),
            })
        }
        _ => Err(
            "invalid arguments; supported: [--minimized | --no-browser | --check-config | --version | --help | --elevated-worker --pipe <sock>]"
                .to_owned(),
        ),
    }
}

/// Validates `/tmp/mesh-gui-handoff-<32_lowercase_hex>.sock`.
pub(crate) fn validate_linux_handoff_socket_path(path: &str) -> Result<(), String> {
    let Some(mid) = path
        .strip_prefix(LINUX_HANDOFF_SOCKET_PREFIX)
        .and_then(|s| s.strip_suffix(LINUX_HANDOFF_SOCKET_SUFFIX))
    else {
        return Err(
            "handoff socket path must match `/tmp/mesh-gui-handoff-<32hex>.sock`".to_owned(),
        );
    };
    if mid.len() != 32
        || !mid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("handoff socket name suffix must be 32 lowercase hex digits".to_owned());
    }
    Ok(())
}

fn generate_hex_128bit() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = random_bytes::<16>();
    let mut out = String::with_capacity(32);
    for b in bytes {
        if let (Some(&hi), Some(&lo)) =
            (HEX.get(usize::from(b >> 4)), HEX.get(usize::from(b & 0x0f)))
        {
            out.push(char::from(hi));
            out.push(char::from(lo));
        }
    }
    out
}

fn generate_hex_256bit() -> String {
    format!("{}{}", generate_hex_128bit(), generate_hex_128bit())
}

fn generate_linux_handoff_socket_path() -> String {
    format!(
        "{LINUX_HANDOFF_SOCKET_PREFIX}{}{LINUX_HANDOFF_SOCKET_SUFFIX}",
        generate_hex_128bit()
    )
}

fn write_stdout_line(text: &str) {
    let mut out = std::io::stdout().lock();
    drop(out.write_all(text.as_bytes()));
    drop(out.write_all(b"\n"));
    drop(out.flush());
}

fn write_stderr_line(text: &str) {
    let mut err = std::io::stderr().lock();
    drop(err.write_all(text.as_bytes()));
    drop(err.write_all(b"\n"));
    drop(err.flush());
}

fn init_linux_gui_logging(is_worker: bool) -> Option<LogGuard> {
    let data_base = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    let log_dir = gui_log_directory(data_base.as_deref());
    let (component, prefix) = if is_worker {
        ("mesh-gui-worker", "meshvpn-worker")
    } else {
        ("mesh-gui", "meshvpn-gui")
    };
    let mut cfg = LoggingConfig::for_component(component);
    cfg.log_dir = log_dir;
    cfg.file_prefix = prefix.to_owned();
    cfg.max_file_bytes = GUI_LOG_MAX_FILE_BYTES;
    cfg.max_total_bytes = GUI_LOG_MAX_TOTAL_BYTES;
    match init_json_logging(&cfg) {
        Ok(guard) => Some(guard),
        Err(_) => {
            cfg.log_dir = None;
            init_json_logging(&cfg).ok()
        }
    }
}

/// Entrypoint invoked by `crates/mesh-gui/src/main.rs` on Linux.
pub(crate) fn run_linux_main<I>(args: I) -> ExitCode
where
    I: IntoIterator<Item = String>,
{
    let mode = match parse_linux_gui_args(args) {
        Ok(m) => m,
        Err(err) => {
            let _guard = init_linux_gui_logging(false);
            let safe = sanitize_gui_log_text(&err);
            tracing::error!(component = "mesh-gui", event = "invalid_cli_args", error = %safe, "invalid CLI args");
            write_stderr_line(&format!("error: {safe}"));
            return ExitCode::from(2);
        }
    };

    match mode {
        LinuxGuiLaunchMode::PrintVersion => {
            write_stdout_line(&format!("MeshVPN {}", env!("CARGO_PKG_VERSION")));
            ExitCode::SUCCESS
        }
        LinuxGuiLaunchMode::PrintHelp => {
            write_stdout_line(
                "Usage: MeshVPN [--minimized | --no-browser | --check-config | --version | --help]",
            );
            ExitCode::SUCCESS
        }
        LinuxGuiLaunchMode::CheckConfig => {
            let _guard = init_linux_gui_logging(false);
            write_stdout_line("MeshVPN Linux configuration OK");
            ExitCode::SUCCESS
        }
        LinuxGuiLaunchMode::ElevatedWorker { socket_path } => {
            let _guard = init_linux_gui_logging(true);
            run_elevated_worker_blocking(&socket_path)
        }
        LinuxGuiLaunchMode::Normal { start_minimized } => {
            let _guard = init_linux_gui_logging(false);
            run_gui_server_blocking(start_minimized)
        }
    }
}

fn run_elevated_worker_blocking(socket_path: &str) -> ExitCode {
    let rt = match Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(component = "mesh-gui-worker", event = "runtime_init_failed", error = %err, "worker runtime failed");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run_linux_elevated_worker(socket_path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let safe = sanitize_gui_log_text(&err);
            tracing::error!(component = "mesh-gui-worker", event = "elevated_worker_failed", error = %safe, "elevated worker failed");
            write_stderr_line(&safe);
            ExitCode::from(1)
        }
    }
}

fn run_gui_server_blocking(start_minimized: bool) -> ExitCode {
    let rt = match Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(component = "mesh-gui", event = "runtime_init_failed", error = %err, "GUI runtime failed");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run_linux_gui_server(start_minimized)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let safe = sanitize_gui_log_text(&err);
            tracing::error!(component = "mesh-gui", event = "gui_server_failed", error = %safe, "Linux GUI terminated with error");
            write_stderr_line(&safe);
            ExitCode::from(1)
        }
    }
}

#[derive(Debug)]
struct LinuxGuiState {
    session_token: String,
    staged_draft: Mutex<Option<EnrollmentConfirmationDraft>>,
    active_action_error: Mutex<Option<String>>,
    shutdown: CancellationToken,
}

impl LinuxGuiState {
    fn new(session_token: String, shutdown: CancellationToken) -> Self {
        Self {
            session_token,
            staged_draft: Mutex::new(None),
            active_action_error: Mutex::new(None),
            shutdown,
        }
    }

    fn verify_token(&self, headers: &HeaderMap) -> bool {
        let Some(val) = headers
            .get("x-mesh-session-token")
            .and_then(|h| h.to_str().ok())
        else {
            return false;
        };
        ct_eq_bytes(val.as_bytes(), self.session_token.as_bytes())
    }

    fn set_action_error(&self, err: Option<String>) {
        if let Ok(mut guard) = self.active_action_error.lock() {
            *guard = err;
        }
    }

    fn current_action_error(&self) -> Option<String> {
        self.active_action_error
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }
}

async fn run_linux_gui_server(start_minimized: bool) -> Result<(), String> {
    let shutdown = CancellationToken::new();
    let token = generate_hex_256bit();
    let state = Arc::new(LinuxGuiState::new(token.clone(), shutdown.clone()));

    let bind_addr: SocketAddr = "127.0.0.1:0"
        .parse()
        .map_err(|err| format!("invalid loopback address: {err}"))?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|err| format!("failed binding loopback GUI listener: {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("failed reading local GUI listener addr: {err}"))?;

    let session_url = format!("http://127.0.0.1:{}/?token={token}", local_addr.port());
    let runtime_url_file = write_session_url_file(&session_url);
    tracing::info!(
        component = "mesh-gui",
        event = "linux_gui_listening",
        port = local_addr.port(),
        "Mesh VPN Linux Desktop GUI ready"
    );

    if !start_minimized
        && std::env::var_os("MESH_GUI_NO_BROWSER").is_none_or(|v| v.is_empty())
        && has_graphical_display()
    {
        spawn_linux_desktop_window(&session_url);
    }

    let router = build_gui_router(Arc::clone(&state));
    let server_res = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        })
        .await
        .map_err(|err| format!("GUI HTTP server failed: {err}"));

    if let Some(path) = runtime_url_file {
        drop(fs::remove_file(path));
    }
    server_res
}

fn build_gui_router(state: Arc<LinuxGuiState>) -> Router {
    Router::new()
        .route("/", get(handle_index))
        .route("/app.css", get(handle_css))
        .route("/app.js", get(handle_js))
        .route("/api/state", get(handle_api_state))
        .route("/api/validate-endpoint", get(handle_validate_endpoint))
        .route("/api/enroll/preview", post(handle_enroll_preview))
        .route("/api/enroll/confirm", post(handle_enroll_confirm))
        .route("/api/enroll/cancel", post(handle_enroll_cancel))
        .route("/api/connect", post(handle_connect))
        .route("/api/disconnect", post(handle_disconnect))
        .route("/api/cleanup", post(handle_cleanup))
        .route("/api/service/start", post(handle_service_start))
        .route("/api/server/update", post(handle_server_update))
        .route("/api/rotate-key", post(handle_rotate_key))
        .route("/api/reset-identity", post(handle_reset_identity))
        .route("/api/ping", post(handle_ping))
        .route("/api/netcheck", post(handle_netcheck))
        .route("/api/bugreport", get(handle_bugreport))
        .route("/api/autostart", post(handle_autostart))
        .route("/api/quit", post(handle_quit))
        .with_state(state)
}

fn static_asset_response(content_type: &'static str, body: &'static str) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    let headers = resp.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

async fn handle_index() -> Response {
    static_asset_response("text/html; charset=utf-8", INDEX_HTML)
}

async fn handle_css() -> Response {
    static_asset_response("text/css; charset=utf-8", APP_CSS)
}

async fn handle_js() -> Response {
    static_asset_response("application/javascript; charset=utf-8", APP_JS)
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    ok: bool,
    error: String,
}

fn json_ok<T: Serialize>(value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) => {
            let mut resp = Response::new(axum::body::Body::from(bytes));
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            resp.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(err) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

fn json_err(status: StatusCode, msg: &str) -> Response {
    let payload = ApiErrorBody {
        ok: false,
        error: format_user_facing_error(msg),
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut resp = Response::new(axum::body::Body::from(bytes));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn require_auth(state: &LinuxGuiState, headers: &HeaderMap) -> Option<Response> {
    if state.verify_token(headers) {
        None
    } else {
        Some(json_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized session token",
        ))
    }
}

#[derive(Debug, Deserialize)]
struct StateQuery {
    q: Option<String>,
}

#[derive(Debug, Serialize)]
struct PeerItemDto {
    node_id: String,
    name: String,
    line: String,
    traffic: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct GuiStateDto {
    ok: bool,
    state_label: &'static str,
    headline: &'static str,
    tray_summary: &'static str,
    tone: &'static str,
    enrolled: bool,
    autostart_enabled: bool,
    server_endpoint: Option<String>,
    active_pin: Option<String>,
    node_name: Option<String>,
    recoverable_error: Option<String>,
    legacy_banner: Option<String>,
    version_mismatch_banner: Option<String>,
    self_network_text: String,
    peers: Vec<PeerItemDto>,
}

const fn state_tone(ui_state: DesktopUiState, sub_state: TunnelSubState) -> &'static str {
    match ui_state {
        DesktopUiState::Connected => match sub_state {
            TunnelSubState::Connected => "ok",
            TunnelSubState::Degraded | TunnelSubState::Connecting => "warn",
            TunnelSubState::Disconnected
            | TunnelSubState::NotEnrolled
            | TunnelSubState::ReauthRequired
            | TunnelSubState::Revoked => "",
        },
        DesktopUiState::Connecting => "warn",
        DesktopUiState::ReauthRequired
        | DesktopUiState::Revoked
        | DesktopUiState::ErrorRecoverable => "err",
        DesktopUiState::AgentUnavailable
        | DesktopUiState::ServiceStopped
        | DesktopUiState::NotEnrolled => "",
    }
}

async fn handle_api_state(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    Query(query): Query<StateQuery>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let service_probe = probe_systemd_service_status().await;
    let ro_probe = query_ro_agent_status().await;
    let action_err = state.current_action_error();

    let (ipc_connected, status, version_status, ipc_err) = match ro_probe {
        Ok((st, ver)) => (true, Some(st), Some(ver), None),
        Err(err) => (false, None, None, Some(err.to_string())),
    };

    let derived = derive_desktop_ui_state(StateProbeInputs {
        gui_version: env!("CARGO_PKG_VERSION"),
        service_probe,
        ipc_connected,
        status: status.as_ref(),
        version_status: version_status.as_ref(),
        ipc_error: ipc_err.as_deref(),
        active_action_error: action_err.as_deref(),
    });

    let filter_q = query.q.as_deref().unwrap_or("");
    let peers = status.as_ref().map_or_else(Vec::new, |st| {
        filter_peers(&st.peers, filter_q)
            .into_iter()
            .map(|p| PeerItemDto {
                node_id: p.node_id.to_string(),
                name: p.name.as_str().to_owned(),
                line: format_peer_list_entry(p),
                traffic: format!(
                    "{} / {}",
                    format_human_bytes(p.tx_bytes),
                    format_human_bytes(p.rx_bytes)
                ),
                detail: format_peer_detail_summary(p),
            })
            .collect()
    });
    let self_network_text = status.as_ref().map_or_else(
        || "meshd daemon is offline or unreachable.".to_owned(),
        format_self_network_panel,
    );
    let srv = status.as_ref().and_then(|s| s.server_connection.as_ref());

    json_ok(&GuiStateDto {
        ok: true,
        state_label: derived.ui_state.label(),
        headline: derived.ui_state.headline(derived.tunnel_sub_state),
        tray_summary: derived
            .ui_state
            .tray_tooltip_summary(derived.tunnel_sub_state),
        tone: state_tone(derived.ui_state, derived.tunnel_sub_state),
        enrolled: derived.enrolled,
        autostart_enabled: is_linux_autostart_enabled(),
        server_endpoint: srv.map(|s| s.control_endpoint.clone()),
        active_pin: srv.and_then(|s| s.active_pin.map(|p| p.to_string())),
        node_name: status
            .as_ref()
            .and_then(|s| s.node_name.as_ref().map(|n| n.as_str().to_owned())),
        recoverable_error: derived.recoverable_error,
        legacy_banner: derived.legacy_banner,
        version_mismatch_banner: derived.version_mismatch_banner,
        self_network_text,
        peers,
    })
}

#[derive(Debug, Deserialize)]
struct ValidateEndpointQuery {
    endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidateEndpointDto {
    ok: bool,
    lock_system_ca: bool,
}

async fn handle_validate_endpoint(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    Query(q): Query<ValidateEndpointQuery>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let locked = should_lock_system_ca_for_endpoint(q.endpoint.as_deref().unwrap_or(""));
    json_ok(&ValidateEndpointDto {
        ok: true,
        lock_system_ca: locked,
    })
}

#[derive(Debug, Deserialize)]
struct EnrollPreviewBody {
    join_uri: Option<String>,
    endpoint: Option<String>,
    tls_mode: Option<String>,
    spki_pin: Option<String>,
    preauth_key: Option<String>,
    node_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct EnrollPreviewDto {
    ok: bool,
    action_kind: &'static str,
    form_endpoint: String,
    form_tls_mode: &'static str,
    form_spki_pin: Option<String>,
    form_node_name: Option<String>,
    masked_preauth_preview: String,
    locked_system_ca: bool,
    confirmation_summary: String,
}

async fn handle_enroll_preview(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<EnrollPreviewBody>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let parsed_res = build_preview_draft(body);
    let (form, draft) = match parsed_res {
        Ok(pair) => pair,
        Err(msg) => return json_err(StatusCode::BAD_REQUEST, &msg),
    };

    let dto = EnrollPreviewDto {
        ok: true,
        action_kind: match draft.action_kind {
            ConfirmActionKind::EnrollNewNode => "enroll_new_node",
            ConfirmActionKind::RotateKey => "rotate_key",
        },
        form_endpoint: form.endpoint_raw.clone(),
        form_tls_mode: match form.tls_mode {
            OnboardingTlsMode::SpkiPin => "spki_pin",
            OnboardingTlsMode::SystemCa => "system_ca",
        },
        form_spki_pin: draft.server_pin.map(|p| p.to_string()),
        form_node_name: draft.node_name.as_ref().map(|n| n.as_str().to_owned()),
        masked_preauth_preview: draft.masked_preauth_preview.clone(),
        locked_system_ca: should_lock_system_ca_for_endpoint(&form.endpoint_raw),
        confirmation_summary: draft.format_confirmation_summary(),
    };

    if let Ok(mut slot) = state.staged_draft.lock() {
        *slot = Some(draft);
    }
    state.set_action_error(None);
    json_ok(&dto)
}

fn build_preview_draft(
    body: EnrollPreviewBody,
) -> Result<(OnboardingFormInput, EnrollmentConfirmationDraft), String> {
    if let Some(uri) = body
        .join_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return parse_mesh_join_uri_to_draft(uri, body.node_name.as_deref().unwrap_or(""));
    }
    let tls_mode = match body.tls_mode.as_deref() {
        Some("system_ca") => OnboardingTlsMode::SystemCa,
        _ => OnboardingTlsMode::SpkiPin,
    };
    let form = OnboardingFormInput {
        endpoint_raw: body.endpoint.unwrap_or_default(),
        tls_mode,
        spki_pin_raw: body.spki_pin.unwrap_or_default(),
        preauth_key_raw: body.preauth_key.unwrap_or_default(),
        node_name_raw: body.node_name.unwrap_or_default(),
    };
    let draft = validate_manual_onboarding_to_draft(&form)?;
    Ok((form, draft))
}

#[derive(Debug, Serialize)]
struct ActionMessageDto {
    ok: bool,
    message: String,
}

async fn handle_enroll_confirm(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let maybe_draft = state.staged_draft.lock().ok().and_then(|mut g| g.take());
    let Some(draft) = maybe_draft else {
        return json_err(StatusCode::BAD_REQUEST, "no staged enrollment confirmation");
    };
    let payload = match draft.build_handoff_payload() {
        Ok(p) => p,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, &err),
    };
    run_admin_payload_response(&state, payload).await
}

async fn handle_enroll_cancel(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    if let Ok(mut g) = state.staged_draft.lock() {
        *g = None;
    }
    json_ok(&ActionMessageDto {
        ok: true,
        message: "Cancelled".to_owned(),
    })
}

#[derive(Debug, Deserialize)]
struct ConnectBody {
    endpoint: Option<String>,
    spki_pin: Option<String>,
    node_name: Option<String>,
}

async fn handle_connect(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<ConnectBody>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let endpoint = body.endpoint.unwrap_or_default().trim().to_owned();
    if endpoint.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "Control endpoint is required");
    }
    let server_pin = body
        .spki_pin
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(SpkiPin::parse)
        .transpose();
    let parsed_pin = match server_pin {
        Ok(p) => p,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let parsed_name = body
        .node_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(NodeName::parse)
        .transpose();
    let validated_name = match parsed_name {
        Ok(n) => n,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, &err.to_string()),
    };

    let req = HandoffRequest::UpWithSecret {
        server_endpoint: endpoint,
        port_override: None,
        server_pin: parsed_pin.map(|p| p.to_string()),
        preauth_key: None,
        node_name: validated_name.map(|n| n.as_str().to_owned()),
    };
    let payload = match serialize_handoff_request_zeroizing(&req) {
        Ok(p) => p,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    run_admin_payload_response(&state, payload).await
}

async fn handle_disconnect(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let Ok(payload) = serialize_handoff_request_zeroizing(&HandoffRequest::Down) else {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "failed serializing Down");
    };
    run_admin_payload_response(&state, payload).await
}

async fn handle_cleanup(State(state): State<Arc<LinuxGuiState>>, headers: HeaderMap) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let Ok(payload) = serialize_handoff_request_zeroizing(&HandoffRequest::Cleanup) else {
        return json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed serializing Cleanup",
        );
    };
    run_admin_payload_response(&state, payload).await
}

async fn handle_service_start(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let req = HandoffRequest::InstallOrStartService {
        source_dir: "/usr/bin".to_owned(),
        start_only: true,
    };
    let Ok(payload) = serialize_handoff_request_zeroizing(&req) else {
        return json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed serializing service request",
        );
    };
    run_admin_payload_response(&state, payload).await
}

#[derive(Debug, Deserialize)]
struct UpdateServerBody {
    endpoint: String,
    tls_mode: Option<String>,
    spki_pin: Option<String>,
}

async fn handle_server_update(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<UpdateServerBody>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let tls_mode = match body.tls_mode.as_deref() {
        Some("system_ca") => OnboardingTlsMode::SystemCa,
        _ => OnboardingTlsMode::SpkiPin,
    };
    let payload = match validate_update_server_payload(
        &body.endpoint,
        tls_mode,
        body.spki_pin.as_deref().unwrap_or(""),
    ) {
        Ok((_norm, bytes)) => bytes,
        Err(msg) => return json_err(StatusCode::BAD_REQUEST, &msg),
    };
    run_admin_payload_response(&state, payload).await
}

#[derive(Debug, Deserialize)]
struct RotateKeyBody {
    endpoint: Option<String>,
    tls_mode: Option<String>,
    spki_pin: Option<String>,
    preauth_key: String,
}

async fn handle_rotate_key(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<RotateKeyBody>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let tls_mode = match body.tls_mode.as_deref() {
        Some("system_ca") => OnboardingTlsMode::SystemCa,
        _ => OnboardingTlsMode::SpkiPin,
    };
    let pin = match body
        .spki_pin
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(SpkiPin::parse)
        .transpose()
    {
        Ok(p) => p,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, &err.to_string()),
    };
    let draft = match validate_rotate_key_to_draft(
        body.endpoint.as_deref().unwrap_or(""),
        tls_mode,
        pin,
        &body.preauth_key,
    ) {
        Ok(d) => d,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, &err),
    };
    let payload = match draft.build_handoff_payload() {
        Ok(p) => p,
        Err(err) => return json_err(StatusCode::BAD_REQUEST, &err),
    };
    run_admin_payload_response(&state, payload).await
}

async fn handle_reset_identity(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let Ok(payload) = serialize_handoff_request_zeroizing(&HandoffRequest::ResetIdentity) else {
        return json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed serializing reset",
        );
    };
    run_admin_payload_response(&state, payload).await
}

async fn run_admin_payload_response(
    state: &LinuxGuiState,
    payload: Zeroizing<Vec<u8>>,
) -> Response {
    match execute_privileged_request(payload).await {
        Ok(action) => {
            state.set_action_error(None);
            json_ok(&ActionMessageDto {
                ok: true,
                message: action.message,
            })
        }
        Err(err) => {
            let msg = err.to_string();
            state.set_action_error(Some(msg.clone()));
            json_err(StatusCode::BAD_GATEWAY, &msg)
        }
    }
}

#[derive(Debug, Deserialize)]
struct PingBody {
    target: String,
    force_direct: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ReportDto {
    ok: bool,
    report: String,
}

async fn handle_ping(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<PingBody>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let req = PingRequest {
        target: body.target.trim().to_owned(),
        count: 4,
        force_direct: body.force_direct.unwrap_or(false),
        timeout_ms: 2_500,
    };
    let timeout = ping_request_timeout(req.count, req.timeout_ms);
    let ro_path = probe_ro_socket_path();
    let stream = match connect_agent_unix_socket(ro_path, false).await {
        Ok(s) => s,
        Err(err) => return json_err(StatusCode::BAD_GATEWAY, &err.to_string()),
    };
    match send_ipc_json_request_with_timeout::<_, _, PingResponse>(
        stream,
        Method::POST,
        "/v1/agent/ping",
        Some(&req),
        MAX_RO_IPC_BODY_BYTES,
        timeout,
    )
    .await
    {
        Ok(resp) => json_ok(&ReportDto {
            ok: true,
            report: format_ping_response(&resp),
        }),
        Err(err) => json_err(StatusCode::BAD_GATEWAY, &err.to_string()),
    }
}

async fn handle_netcheck(State(state): State<Arc<LinuxGuiState>>, headers: HeaderMap) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    let ro_path = probe_ro_socket_path();
    let stream = match connect_agent_unix_socket(ro_path, false).await {
        Ok(s) => s,
        Err(err) => return json_err(StatusCode::BAD_GATEWAY, &err.to_string()),
    };
    match send_ipc_json_request_with_timeout::<_, _, NetcheckResponse>(
        stream,
        Method::POST,
        "/v1/agent/netcheck",
        Some(&()),
        MAX_RO_IPC_BODY_BYTES,
        IPC_NETCHECK_TIMEOUT,
    )
    .await
    {
        Ok(resp) => json_ok(&ReportDto {
            ok: true,
            report: format_netcheck_report(&resp),
        }),
        Err(err) => json_err(StatusCode::BAD_GATEWAY, &err.to_string()),
    }
}

async fn handle_bugreport(State(state): State<Arc<LinuxGuiState>>, headers: HeaderMap) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    match fetch_bugreport_tar_bytes().await {
        Ok(bytes) => {
            let mut resp = Response::new(axum::body::Body::from(bytes));
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/x-tar"));
            let disp = format!("attachment; filename=\"{DEFAULT_BUGREPORT_FILENAME}\"");
            if let Ok(hdr_val) = HeaderValue::from_str(&disp) {
                resp.headers_mut().insert(CONTENT_DISPOSITION, hdr_val);
            }
            resp.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(err) => json_err(StatusCode::BAD_GATEWAY, &err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct AutostartBody {
    enabled: bool,
}

async fn handle_autostart(
    State(state): State<Arc<LinuxGuiState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<AutostartBody>,
) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    match set_linux_autostart_enabled(body.enabled) {
        Ok(()) => json_ok(&ActionMessageDto {
            ok: true,
            message: if body.enabled {
                "Autostart enabled".to_owned()
            } else {
                "Autostart disabled".to_owned()
            },
        }),
        Err(err) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &err),
    }
}

async fn handle_quit(State(state): State<Arc<LinuxGuiState>>, headers: HeaderMap) -> Response {
    if let Some(unauth) = require_auth(&state, &headers) {
        return unauth;
    }
    state.shutdown.cancel();
    json_ok(&ActionMessageDto {
        ok: true,
        message: "Shutting down".to_owned(),
    })
}

fn probe_ro_socket_path() -> &'static str {
    if Path::new(UNIX_AGENT_RO_SOCKET).exists() {
        UNIX_AGENT_RO_SOCKET
    } else if Path::new(FALLBACK_UNIX_AGENT_RO_SOCKET).exists() {
        FALLBACK_UNIX_AGENT_RO_SOCKET
    } else {
        UNIX_AGENT_RO_SOCKET
    }
}

fn probe_admin_socket_path() -> &'static str {
    if Path::new(UNIX_AGENT_ADMIN_SOCKET).exists() {
        UNIX_AGENT_ADMIN_SOCKET
    } else if Path::new(FALLBACK_UNIX_AGENT_ADMIN_SOCKET).exists() {
        FALLBACK_UNIX_AGENT_ADMIN_SOCKET
    } else {
        UNIX_AGENT_ADMIN_SOCKET
    }
}

fn find_systemctl_bin() -> Option<&'static str> {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|p| Path::new(p).exists())
}

fn find_pkexec_bin() -> Option<&'static str> {
    ["/usr/bin/pkexec", "/bin/pkexec"]
        .into_iter()
        .find(|p| Path::new(p).exists())
}

async fn probe_systemd_service_status() -> ServiceProbeKind {
    let Some(systemctl) = find_systemctl_bin() else {
        return ServiceProbeKind::Unknown;
    };
    let active_ok = TokioCommand::new(systemctl)
        .args(["is-active", "--quiet", "meshd.service"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success());
    if active_ok {
        return ServiceProbeKind::Running;
    }
    let unit_installed = [
        "/etc/systemd/system/meshd.service",
        "/lib/systemd/system/meshd.service",
        "/usr/lib/systemd/system/meshd.service",
    ]
    .iter()
    .any(|p| Path::new(p).exists());
    if unit_installed {
        ServiceProbeKind::Stopped
    } else {
        ServiceProbeKind::NotInstalled
    }
}

async fn query_ro_agent_status() -> AppResult<(AgentStatusResponse, AgentVersionStatus)> {
    let ro_path = probe_ro_socket_path();
    let stream = connect_agent_unix_socket(ro_path, false).await?;
    let status_resp = send_ipc_json_with_meta::<_, (), AgentStatusResponse>(
        stream,
        Method::GET,
        "/v1/agent/status",
        None,
        MAX_RO_IPC_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await?;
    let header_ver = status_resp.agent_version.clone();
    let version_res = if header_ver.is_some() {
        Err(AppError::not_found("unused"))
    } else {
        let s2 = connect_agent_unix_socket(ro_path, false).await?;
        send_ipc_json_request_with_timeout::<_, (), AgentVersionResponse>(
            s2,
            Method::GET,
            "/v1/agent/version",
            None,
            MAX_RO_IPC_BODY_BYTES,
            IPC_RO_QUERY_TIMEOUT,
        )
        .await
    };
    let version_status =
        mesh_net::ipc::classify_agent_version_probe(header_ver.as_deref(), version_res)?;
    Ok((status_resp.body, version_status))
}

async fn execute_privileged_request(payload: Zeroizing<Vec<u8>>) -> AppResult<AgentActionResponse> {
    let parsed = parse_handoff_request_payload(payload.as_slice())?;
    let force_polkit = matches!(
        parsed,
        HandoffRequest::InstallOrStartService { .. }
            | HandoffRequest::UpdateService { .. }
            | HandoffRequest::UninstallService { .. }
    );
    if !force_polkit {
        match dispatch_handoff_to_admin_socket(&parsed).await {
            Ok(action) => return Ok(action),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {}
            Err(err)
                if err.kind() == ErrorKind::Unavailable
                    && matches!(parsed, HandoffRequest::Cleanup) => {}
            Err(err) => return Err(err),
        }
    }
    let (resp, _archive) = run_polkit_handoff(payload, false).await?;
    resp.into_action_result()
}

async fn fetch_bugreport_tar_bytes() -> AppResult<Vec<u8>> {
    let admin_sock = probe_admin_socket_path();
    match connect_agent_unix_socket(admin_sock, true).await {
        Ok(stream) => {
            let mut archive = Vec::new();
            let meta = stream_ipc_bugreport(
                stream,
                IPC_ADMIN_MUTATION_TIMEOUT,
                IPC_STREAM_CHUNK_IDLE_TIMEOUT,
                |chunk| {
                    if archive.len().saturating_add(chunk.len()) > MAX_BUGREPORT_ARCHIVE_BYTES {
                        return Err(AppError::invalid_argument(
                            "bugreport stream exceeded 20 MiB cap",
                        ));
                    }
                    archive.extend_from_slice(chunk);
                    Ok(())
                },
            )
            .await?;
            validate_bugreport_archive_size(meta.total_bytes)
                .map_err(AppError::invalid_argument)?;
            validate_bugreport_archive_size(u64::try_from(archive.len()).unwrap_or(u64::MAX))
                .map_err(AppError::invalid_argument)?;
            Ok(archive)
        }
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            let payload =
                serialize_handoff_request_zeroizing(&HandoffRequest::ExportBugreportStream)?;
            let (resp, archive) = run_polkit_handoff(payload, true).await?;
            if !resp.ok {
                return Err(resp
                    .into_action_result()
                    .err()
                    .unwrap_or_else(|| AppError::unavailable("bugreport export failed")));
            }
            validate_bugreport_archive_size(u64::try_from(archive.len()).unwrap_or(u64::MAX))
                .map_err(AppError::invalid_argument)?;
            Ok(archive)
        }
        Err(err) => Err(err),
    }
}

async fn post_admin_ipc<Req: Serialize>(path: &str, body: &Req) -> AppResult<AgentActionResponse> {
    let admin_sock = probe_admin_socket_path();
    let stream = connect_agent_unix_socket(admin_sock, true).await?;
    send_ipc_json_request_with_timeout(
        stream,
        Method::POST,
        path,
        Some(body),
        MAX_ADMIN_IPC_BODY_BYTES,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
}

async fn dispatch_handoff_to_admin_socket(req: &HandoffRequest) -> AppResult<AgentActionResponse> {
    match req {
        HandoffRequest::UpWithSecret { .. } => {
            let up = handoff_request_to_agent_up(req)?;
            post_admin_ipc("/v1/agent/up", &up).await
        }
        HandoffRequest::RotateKeyWithSecret { .. } => {
            let rot = handoff_request_to_agent_rotate_key(req)?;
            post_admin_ipc("/v1/agent/rotate-key", &rot).await
        }
        HandoffRequest::Down => post_admin_ipc("/v1/agent/down", &()).await,
        HandoffRequest::Cleanup => post_admin_ipc("/v1/agent/cleanup", &()).await,
        HandoffRequest::Set {
            server_endpoint,
            server_pin,
        } => {
            let set_req = AgentSetRequest {
                server_endpoint: server_endpoint.clone(),
                server_pin: server_pin.as_deref().map(SpkiPin::parse).transpose()?,
            };
            post_admin_ipc("/v1/agent/set", &set_req).await
        }
        HandoffRequest::ResetIdentity => {
            post_admin_ipc("/v1/agent/reset-identity", &AgentResetIdentityRequest {}).await
        }
        _ => Err(AppError::invalid_argument(
            "unsupported direct admin IPC request kind",
        )),
    }
}

async fn run_polkit_handoff(
    mut payload: Zeroizing<Vec<u8>>,
    expect_stream: bool,
) -> AppResult<(HandoffResponse, Vec<u8>)> {
    let pkexec = find_pkexec_bin()
        .ok_or_else(|| AppError::unavailable("pkexec was not found on this Linux system"))?;
    let exe_path = std::env::current_exe()
        .map_err(|err| AppError::internal(format!("failed locating MeshVPN binary: {err}")))?;
    let socket_path = generate_linux_handoff_socket_path();
    drop(fs::remove_file(&socket_path));

    let listener = UnixListener::bind(&socket_path).map_err(|err| {
        AppError::internal(format!(
            "failed binding handoff socket {socket_path}: {err}"
        ))
    })?;
    fs::set_permissions(&socket_path, Permissions::from_mode(0o600)).map_err(|err| {
        drop(fs::remove_file(&socket_path));
        AppError::internal(format!("failed setting handoff socket permissions: {err}"))
    })?;

    let mut child = TokioCommand::new(pkexec)
        .arg(&exe_path)
        .arg("--elevated-worker")
        .arg("--pipe")
        .arg(&socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            drop(fs::remove_file(&socket_path));
            AppError::unavailable(format!("failed launching pkexec elevation worker: {err}"))
        })?;

    let io_res = exchange_polkit_frames(&listener, &payload, expect_stream).await;
    mesh_net::gui_handoff::zeroize_handoff_payload(&mut payload);
    drop(fs::remove_file(&socket_path));

    let child_status = child.wait().await;
    if io_res.is_err()
        && let Ok(st) = child_status
        && matches!(st.code(), Some(126 | 127))
    {
        return Err(AppError::permission_denied(
            "Polkit authentication cancelled or rejected",
        ));
    }
    io_res
}

async fn exchange_polkit_frames(
    listener: &UnixListener,
    payload: &Zeroizing<Vec<u8>>,
    expect_stream: bool,
) -> AppResult<(HandoffResponse, Vec<u8>)> {
    let (mut stream, _) = tokio::time::timeout(HANDOFF_UAC_WAIT_TIMEOUT, listener.accept())
        .await
        .map_err(|_| AppError::unavailable("timed out waiting for Polkit elevated worker"))?
        .map_err(|err| AppError::unavailable(format!("handoff accept failed: {err}")))?;

    let hello = tokio::time::timeout(HANDOFF_WORKER_HELLO_TIMEOUT, read_mgh1_frame(&mut stream))
        .await
        .map_err(|_| AppError::unavailable("timed out waiting for WorkerHello"))??;
    let HandoffFrame::WorkerHello { protocol_version } = hello else {
        return Err(AppError::invalid_argument(
            "expected MGH1 WorkerHello frame",
        ));
    };
    if protocol_version != MGH1_PROTOCOL_VERSION {
        return Err(AppError::invalid_argument(format!(
            "unsupported WorkerHello version {protocol_version}"
        )));
    }

    write_mgh1_frame(
        &mut stream,
        &HandoffFrame::HandoffRequest(Zeroizing::new(payload.as_slice().to_vec())),
    )
    .await?;

    let mut archive = Vec::new();
    let mut expected_bytes: Option<u64> = None;
    loop {
        let frame = tokio::time::timeout(IPC_ADMIN_MUTATION_TIMEOUT, read_mgh1_frame(&mut stream))
            .await
            .map_err(|_| AppError::unavailable("elevated worker timed out"))??;
        match frame {
            HandoffFrame::HandoffStreamHeader(hdr) if expect_stream => {
                expected_bytes = Some(hdr.total_bytes);
            }
            HandoffFrame::BugreportChunk(chunk) if expect_stream => {
                if archive.len().saturating_add(chunk.len()) > MAX_BUGREPORT_ARCHIVE_BYTES {
                    return Err(AppError::invalid_argument(
                        "bugreport archive exceeded 20 MiB cap",
                    ));
                }
                archive.extend_from_slice(&chunk);
            }
            HandoffFrame::HandoffResponse(bytes) => {
                let parsed: HandoffResponse = serde_json::from_slice(&bytes).map_err(|err| {
                    AppError::internal(format!("invalid MGH1 HandoffResponse JSON: {err}"))
                })?;
                if parsed.ok
                    && let Some(expected) = expected_bytes
                    && u64::try_from(archive.len()).ok() != Some(expected)
                {
                    return Err(AppError::unavailable(
                        "truncated bugreport stream from worker",
                    ));
                }
                return Ok((parsed, archive));
            }
            _ => {
                return Err(AppError::invalid_argument(
                    "unexpected MGH1 frame from worker",
                ));
            }
        }
    }
}

async fn run_linux_elevated_worker(socket_path: &str) -> Result<(), String> {
    validate_linux_handoff_socket_path(socket_path)?;
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| format!("failed connecting to GUI handoff socket {socket_path}: {err}"))?;

    let hello = HandoffFrame::WorkerHello {
        protocol_version: MGH1_PROTOCOL_VERSION,
    };
    write_mgh1_frame(&mut stream, &hello)
        .await
        .map_err(|e| e.to_string())?;

    let req_frame = read_mgh1_frame(&mut stream)
        .await
        .map_err(|e| e.to_string())?;
    let HandoffFrame::HandoffRequest(mut payload) = req_frame else {
        return Err("expected HandoffRequest frame".to_owned());
    };
    let parsed_res = parse_handoff_request_payload(payload.as_slice());
    mesh_net::gui_handoff::zeroize_handoff_payload(&mut payload);
    let req = parsed_res.map_err(|e| e.to_string())?;

    if matches!(req, HandoffRequest::ExportBugreportStream) {
        let res = stream_worker_bugreport(&mut stream).await;
        if let Err(err) = res {
            let err_frame = HandoffResponse::from_error(&err);
            let bytes = serde_json::to_vec(&err_frame).unwrap_or_default();
            drop(write_mgh1_frame(&mut stream, &HandoffFrame::HandoffResponse(bytes)).await);
        }
        return Ok(());
    }

    let response = execute_worker_command(&req).await;
    let resp_bytes = serde_json::to_vec(&response)
        .map_err(|err| format!("failed serializing HandoffResponse: {err}"))?;
    write_mgh1_frame(&mut stream, &HandoffFrame::HandoffResponse(resp_bytes))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn execute_worker_command(req: &HandoffRequest) -> HandoffResponse {
    match req {
        HandoffRequest::InstallOrStartService { .. } => start_systemd_meshd_service().await,
        HandoffRequest::Cleanup => match dispatch_handoff_to_admin_socket(req).await {
            Ok(action) => HandoffResponse::from_action(action),
            Err(err) if err.kind() == ErrorKind::Unavailable => {
                match cleanup_offline_linux_ledger() {
                    Ok(action) => HandoffResponse::from_action(action),
                    Err(e2) => HandoffResponse::from_error(&e2),
                }
            }
            Err(err) => HandoffResponse::from_error(&err),
        },
        _ => match dispatch_handoff_to_admin_socket(req).await {
            Ok(action) => HandoffResponse::from_action(action),
            Err(err) => HandoffResponse::from_error(&err),
        },
    }
}

async fn start_systemd_meshd_service() -> HandoffResponse {
    let Some(systemctl) = find_systemctl_bin() else {
        return HandoffResponse::from_error(&AppError::unavailable("systemctl binary not found"));
    };
    drop(
        TokioCommand::new(systemctl)
            .args(["reset-failed", "meshd.service"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await,
    );
    let out = TokioCommand::new(systemctl)
        .args(["enable", "--now", "meshd.service"])
        .stdin(Stdio::null())
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => HandoffResponse::from_action(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "meshd.service started cleanly".to_owned(),
        }),
        Ok(o) => {
            let err_txt = String::from_utf8_lossy(&o.stderr).trim().to_owned();
            HandoffResponse::from_error(&AppError::unavailable(format!(
                "systemctl enable --now meshd.service failed: {err_txt}"
            )))
        }
        Err(err) => HandoffResponse::from_error(&AppError::unavailable(format!(
            "failed executing systemctl: {err}"
        ))),
    }
}

fn cleanup_offline_linux_ledger() -> AppResult<AgentActionResponse> {
    let path = ResourceLedger::default_ledger_path();
    if !path.exists() {
        return Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "no stale Linux network resources recorded".to_owned(),
        });
    }
    let mut ledger = ResourceLedger::load_or_init(path)?;
    if !ledger.needs_stale_recovery() {
        return Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "no stale Linux network resources recorded".to_owned(),
        });
    }
    let ops = LinuxCleanupOps::new();
    ledger.cleanup_all(&ops)?;
    Ok(AgentActionResponse {
        state: DaemonState::Stopped,
        message: "cleaned offline Linux ResourceLedger entries".to_owned(),
    })
}

async fn stream_worker_bugreport(handoff_stream: &mut UnixStream) -> AppResult<()> {
    let admin_sock = probe_admin_socket_path();
    let admin_io = connect_agent_unix_socket(admin_sock, true).await?;
    let mut buffered = Vec::new();
    let meta = stream_ipc_bugreport(
        admin_io,
        IPC_ADMIN_MUTATION_TIMEOUT,
        IPC_STREAM_CHUNK_IDLE_TIMEOUT,
        |chunk| {
            if buffered.len().saturating_add(chunk.len()) > MAX_BUGREPORT_ARCHIVE_BYTES {
                return Err(AppError::invalid_argument(
                    "bugreport archive exceeds 20 MiB cap",
                ));
            }
            buffered.extend_from_slice(chunk);
            Ok(())
        },
    )
    .await?;

    let header = mesh_net::gui_handoff::HandoffStreamHeaderPayload {
        total_bytes: u64::try_from(buffered.len()).unwrap_or(0),
        scrubbed_items: meta.scrubbed_items,
    };
    write_mgh1_frame(handoff_stream, &HandoffFrame::HandoffStreamHeader(header)).await?;
    for chunk in buffered.chunks(65_536) {
        write_mgh1_frame(
            handoff_stream,
            &HandoffFrame::BugreportChunk(chunk.to_vec()),
        )
        .await?;
    }
    let done = HandoffResponse::from_bugreport(meta.scrubbed_items, header.total_bytes);
    let done_bytes = serde_json::to_vec(&done)
        .map_err(|err| AppError::internal(format!("failed serializing bugreport done: {err}")))?;
    write_mgh1_frame(handoff_stream, &HandoffFrame::HandoffResponse(done_bytes)).await?;
    Ok(())
}

fn autostart_desktop_path() -> Option<PathBuf> {
    let cfg_dir = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(cfg_dir.join("autostart").join(AUTOSTART_DESKTOP_FILENAME))
}

fn is_linux_autostart_enabled() -> bool {
    autostart_desktop_path().is_some_and(|p| p.exists())
}

fn set_linux_autostart_enabled(enabled: bool) -> Result<(), String> {
    let path = autostart_desktop_path().ok_or_else(|| "cannot resolve config dir".to_owned())?;
    if !enabled {
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|err| format!("failed removing autostart entry: {err}"))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed creating autostart dir: {err}"))?;
    }
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_else(|| "/usr/bin/MeshVPN".to_owned());
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Mesh VPN\nExec={exe} --minimized\nIcon=mesh-vpn\nX-GNOME-Autostart-enabled=true\n"
    );
    fs::write(&path, entry).map_err(|err| format!("failed writing autostart entry: {err}"))
}

fn has_graphical_display() -> bool {
    std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

fn write_session_url_file(url: &str) -> Option<PathBuf> {
    let path = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(|d| PathBuf::from(d).join("meshvpn-gui.url"))?;
    if fs::write(&path, format!("{url}\n")).is_ok() {
        drop(fs::set_permissions(&path, Permissions::from_mode(0o600)));
        Some(path)
    } else {
        None
    }
}

fn spawn_linux_desktop_window(session_url: &str) {
    let profile_dir = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|d| d.join("mesh-vpn/app-profile"));
    let chrome_bins = [
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/brave-browser",
        "/usr/bin/microsoft-edge",
    ];
    for bin in chrome_bins {
        if Path::new(bin).exists() {
            let mut cmd = std::process::Command::new(bin);
            cmd.arg(format!("--app={session_url}"))
                .arg("--class=mesh-vpn");
            if let Some(ref prof) = profile_dir {
                cmd.arg(format!("--user-data-dir={}", prof.display()));
            }
            if cmd
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .is_ok()
            {
                return;
            }
        }
    }
    if Path::new("/usr/bin/xdg-open").exists() {
        drop(
            std::process::Command::new("/usr/bin/xdg-open")
                .arg(session_url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LinuxGuiLaunchMode, generate_linux_handoff_socket_path, parse_linux_gui_args, state_tone,
        validate_linux_handoff_socket_path,
    };
    use crate::app::{DesktopUiState, TunnelSubState};

    #[test]
    fn test_linux_gui_arg_parsing_and_socket_validation() {
        assert_eq!(
            parse_linux_gui_args(["MeshVPN".to_owned()]),
            Ok(LinuxGuiLaunchMode::Normal {
                start_minimized: false
            })
        );
        assert_eq!(
            parse_linux_gui_args(["MeshVPN".to_owned(), "--minimized".to_owned()]),
            Ok(LinuxGuiLaunchMode::Normal {
                start_minimized: true
            })
        );
        assert_eq!(
            parse_linux_gui_args(["MeshVPN".to_owned(), "--no-browser".to_owned()]),
            Ok(LinuxGuiLaunchMode::Normal {
                start_minimized: true
            })
        );
        assert_eq!(
            parse_linux_gui_args(["MeshVPN".to_owned(), "--check-config".to_owned()]),
            Ok(LinuxGuiLaunchMode::CheckConfig)
        );
        assert!(parse_linux_gui_args(["MeshVPN".to_owned(), "--unknown-flag".to_owned()]).is_err());

        let sock = generate_linux_handoff_socket_path();
        assert!(validate_linux_handoff_socket_path(&sock).is_ok());
        assert_eq!(
            parse_linux_gui_args([
                "MeshVPN".to_owned(),
                "--elevated-worker".to_owned(),
                "--pipe".to_owned(),
                sock.clone()
            ]),
            Ok(LinuxGuiLaunchMode::ElevatedWorker { socket_path: sock })
        );
        assert!(validate_linux_handoff_socket_path("/var/run/meshd/meshd-admin.sock").is_err());
        assert_eq!(
            state_tone(DesktopUiState::Connected, TunnelSubState::Connected),
            "ok"
        );
    }
}
