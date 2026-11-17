//! Dual local IPC routers (`meshd-ro` vs `meshd-admin`) with kernel peer credential enforcement
//! (`SEC-14`, `BLK-G2-03`, `US-039`, `US-073`).

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
#[cfg(unix)]
use tracing::debug;
use tracing::{info, warn};

use mesh_core::brand::DAEMON_BINARY_NAME;
use mesh_core::clock::{Clock as _, SystemClock};
use mesh_core::defaults::{
    MAX_ADMIN_IPC_BODY_BYTES, MAX_BUGREPORT_ARCHIVE_BYTES, MAX_RO_IPC_BODY_BYTES,
};
use mesh_core::error::{ErrorEnvelope, ErrorKind, ErrorResponse};
use mesh_core::{AppError, AppResult};
use mesh_net::ipc::{
    HEADER_MESH_AGENT_VERSION, HEADER_MESH_ARCHIVE_BYTES, HEADER_MESH_SCRUBBED_ITEMS,
    IpcChannelKind,
};
use mesh_proto::agent_ipc::{
    AgentResetIdentityRequest, AgentRotateKeyRequest, AgentSetRequest, AgentUpRequest,
    AgentVersionResponse, BugreportResponse, PingRequest,
};

use crate::config::create_bugreport_tar_bundle;
use crate::control_loop::DaemonRuntimeState;
use crate::ping_probe::PingProbe;
use crate::supervisor::SupervisorCommand;

const IPC_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const BUGREPORT_NETCHECK_TIMEOUT: Duration = Duration::from_secs(2);
const BUGREPORT_STREAM_CHUNK_BYTES: usize = 65_536;
const AGENT_IPC_PROTOCOL_VERSION: u16 = 1;

/// Shared router state passed cleanly into read-only and privileged IPC routers.
#[derive(Debug, Clone)]
pub(crate) struct IpcRouterState {
    pub(crate) runtime: Arc<DaemonRuntimeState>,
    pub(crate) cmd_tx: mpsc::Sender<SupervisorCommand>,
}

/// Hosts dual OS-secured local IPC listeners for `meshd`.
#[derive(Debug)]
pub(crate) struct IpcService;

impl IpcService {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "ipc_service:ready"
    }

    /// Builds the strictly Read-Only router (`meshd-ro`) with `4 KiB` body limit and `0` mutation routes.
    pub(crate) fn build_ro_router(state: IpcRouterState) -> Router {
        Router::new()
            .route("/v1/agent/status", get(handle_status))
            .route("/v1/agent/peers", get(handle_peers))
            .route("/v1/agent/version", get(handle_version))
            .route("/v1/agent/ping", post(handle_ping))
            .route("/v1/agent/netcheck", post(handle_netcheck))
            .fallback(handle_ro_fallback)
            .layer(DefaultBodyLimit::max(MAX_RO_IPC_BODY_BYTES))
            .layer(middleware::from_fn(attach_agent_version_header))
            .with_state(state)
    }

    /// Builds the privileged Admin router (`meshd-admin`) adding tunnel lifecycle & mutation routes.
    pub(crate) fn build_admin_router(state: IpcRouterState) -> Router {
        Router::new()
            .route("/v1/agent/status", get(handle_status))
            .route("/v1/agent/peers", get(handle_peers))
            .route("/v1/agent/version", get(handle_version))
            .route("/v1/agent/ping", post(handle_ping))
            .route("/v1/agent/netcheck", post(handle_netcheck))
            .route("/v1/agent/up", post(handle_up))
            .route("/v1/agent/down", post(handle_down))
            .route("/v1/agent/cleanup", post(handle_cleanup))
            .route("/v1/agent/set", post(handle_set))
            .route("/v1/agent/rotate-key", post(handle_rotate_key))
            .route("/v1/agent/reset-identity", post(handle_reset_identity))
            .route("/v1/agent/bugreport", post(handle_bugreport))
            .route("/v1/agent/bugreport/stream", post(handle_bugreport_stream))
            .layer(DefaultBodyLimit::max(MAX_ADMIN_IPC_BODY_BYTES))
            .layer(middleware::from_fn(attach_agent_version_header))
            .with_state(state)
    }

    /// Binds and spawns both `meshd-ro` and `meshd-admin` platform IPC listeners inside `tracker`.
    pub(crate) async fn start_listeners(
        ro_endpoint: &str,
        admin_endpoint: &str,
        state: IpcRouterState,
        tracker: &TaskTracker,
        shutdown: &CancellationToken,
    ) -> AppResult<()> {
        let ro_router = Self::build_ro_router(state.clone());
        let admin_router = Self::build_admin_router(state);
        start_platform_listeners(
            ro_endpoint,
            admin_endpoint,
            ro_router,
            admin_router,
            tracker,
            shutdown,
        )
        .await
    }
}

async fn attach_agent_version_header(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        HeaderName::from_static(HEADER_MESH_AGENT_VERSION),
        HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
    resp
}

async fn handle_status(State(state): State<IpcRouterState>) -> Response {
    let resp = state.runtime.build_status_response().await;
    (StatusCode::OK, Json(resp)).into_response()
}

async fn handle_peers(State(state): State<IpcRouterState>) -> Response {
    let resp = state.runtime.build_status_response().await;
    (StatusCode::OK, Json(resp)).into_response()
}

async fn handle_version() -> Response {
    let resp = AgentVersionResponse {
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: AGENT_IPC_PROTOCOL_VERSION,
        binary_name: DAEMON_BINARY_NAME.to_owned(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

async fn handle_ping(
    State(state): State<IpcRouterState>,
    Json(req): Json<PingRequest>,
) -> Response {
    match PingProbe::execute_ping(&state.runtime, &req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => app_error_response(&err),
    }
}

async fn handle_netcheck(State(state): State<IpcRouterState>) -> Response {
    match PingProbe::execute_netcheck(&state.runtime).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => app_error_response(&err),
    }
}

async fn handle_up(
    State(state): State<IpcRouterState>,
    Json(req): Json<AgentUpRequest>,
) -> Response {
    dispatch_cmd(&state.cmd_tx, |reply| SupervisorCommand::Up { req, reply }).await
}

async fn handle_down(State(state): State<IpcRouterState>) -> Response {
    dispatch_cmd(&state.cmd_tx, |reply| SupervisorCommand::Down { reply }).await
}

async fn handle_cleanup(State(state): State<IpcRouterState>) -> Response {
    dispatch_cmd(&state.cmd_tx, |reply| SupervisorCommand::Cleanup { reply }).await
}

async fn handle_set(
    State(state): State<IpcRouterState>,
    Json(req): Json<AgentSetRequest>,
) -> Response {
    dispatch_cmd(&state.cmd_tx, |reply| SupervisorCommand::Set { req, reply }).await
}

async fn handle_rotate_key(
    State(state): State<IpcRouterState>,
    Json(req): Json<AgentRotateKeyRequest>,
) -> Response {
    dispatch_cmd(&state.cmd_tx, |reply| SupervisorCommand::RotateKey {
        req,
        reply,
    })
    .await
}

async fn handle_reset_identity(State(state): State<IpcRouterState>, body: Bytes) -> Response {
    if let Err(err) = parse_optional_empty_json_request(&body) {
        return app_error_response(&err);
    }
    dispatch_cmd(&state.cmd_tx, |reply| SupervisorCommand::ResetIdentity {
        reply,
    })
    .await
}

fn parse_optional_empty_json_request(body: &[u8]) -> AppResult<()> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let _parsed: Option<AgentResetIdentityRequest> =
        serde_json::from_slice(body).map_err(|err| {
            AppError::invalid_argument(format!("invalid empty/object JSON request body: {err}"))
        })?;
    Ok(())
}

/// Streams a temporary `.tar` bugreport archive in `64 KiB` chunks and removes the temporary
/// archive only AFTER closing the underlying `ReaderStream<tokio::fs::File>` OS handle (`ADR-023`).
#[derive(Debug)]
struct GuardedBugreportStream {
    inner: Option<Body>,
    path: PathBuf,
}

impl GuardedBugreportStream {
    fn from_stream(reader_stream: ReaderStream<tokio::fs::File>, path: PathBuf) -> Self {
        Self {
            inner: Some(Body::from_stream(reader_stream)),
            path,
        }
    }

    fn cleanup_guard_only(path: PathBuf) -> Self {
        Self { inner: None, path }
    }

    fn disarm(&mut self) -> PathBuf {
        std::mem::take(&mut self.path)
    }
}

impl hyper::body::Body for GuardedBugreportStream {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut() {
            Some(inner) => Pin::new(inner).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner
            .as_ref()
            .is_none_or(hyper::body::Body::is_end_stream)
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner
            .as_ref()
            .map_or_else(hyper::body::SizeHint::default, hyper::body::Body::size_hint)
    }
}

impl Drop for GuardedBugreportStream {
    fn drop(&mut self) {
        // Close `ReaderStream<tokio::fs::File>` (and its OS file handle) BEFORE removing the temp
        // file so Windows does not reject `remove_file` or leak open handles (`HR-DGUI-G2-03`).
        drop(self.inner.take());
        if self.path.as_os_str().is_empty() {
            return;
        }
        if let Err(err) = std::fs::remove_file(&self.path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                component = "meshd.ipc",
                event = "bugreport_temp_cleanup_failed",
                path = %self.path.display(),
                error = %err,
                "failed removing temporary streamed bugreport archive"
            );
        }
    }
}

async fn handle_bugreport_stream(State(state): State<IpcRouterState>, body: Bytes) -> Response {
    if let Err(err) = parse_optional_empty_json_request(&body) {
        return app_error_response(&err);
    }
    let bundle = match build_bugreport_bundle_for_stream(&state).await {
        Ok(resp) => resp,
        Err(err) => return app_error_response(&err),
    };
    match build_streamed_bugreport_response(bundle).await {
        Ok(resp) => resp,
        Err(err) => app_error_response(&err),
    }
}

async fn build_bugreport_bundle_for_stream(state: &IpcRouterState) -> AppResult<BugreportResponse> {
    let (bootstrap, state_dir_opt) = {
        let g = state.runtime.inner.read().await;
        let dir = g.state_store.state_dir().map(std::path::Path::to_path_buf);
        (g.bootstrap.clone(), dir)
    };
    let Some(state_dir) = state_dir_opt else {
        let (reply_tx, reply_rx) = oneshot::channel();
        if state
            .cmd_tx
            .send(SupervisorCommand::Bugreport { reply: reply_tx })
            .await
            .is_err()
        {
            return Err(AppError::unavailable("daemon supervisor shutting down"));
        }
        return match tokio::time::timeout(IPC_COMMAND_TIMEOUT, reply_rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(AppError::unavailable("daemon supervisor dropped reply")),
            Err(_) => Err(AppError::unavailable("daemon operation timed out")),
        };
    };

    let status = state.runtime.build_status_response().await;
    let netcheck_res = tokio::time::timeout(
        BUGREPORT_NETCHECK_TIMEOUT,
        PingProbe::execute_netcheck(&state.runtime),
    )
    .await;
    let now_unix_ms = SystemClock::new().now_unix_ms();

    tokio::task::spawn_blocking(move || {
        let netcheck_ref = match &netcheck_res {
            Ok(Ok(ok)) => Ok(ok),
            Ok(Err(err)) => Err(err.public_message()),
            Err(_) => Err("netcheck timed out during bugreport collection"),
        };
        create_bugreport_tar_bundle(&state_dir, &bootstrap, &status, netcheck_ref, now_unix_ms)
    })
    .await
    .map_err(|join_err| AppError::internal(format!("bugreport worker task failed: {join_err}")))?
}

async fn build_streamed_bugreport_response(resp: BugreportResponse) -> AppResult<Response> {
    let mut guarded = GuardedBugreportStream::cleanup_guard_only(PathBuf::from(&resp.bundle_path));
    let max_bytes = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX);
    if resp.size_bytes == 0 || resp.size_bytes > max_bytes {
        return Err(AppError::invalid_argument(format!(
            "bugreport archive size {} outside allowed 1..={max_bytes} bytes",
            resp.size_bytes
        )));
    }

    let file = tokio::fs::File::open(&guarded.path)
        .await
        .map_err(|err| AppError::internal(format!("failed opening bugreport archive: {err}")))?;
    let actual_size = file
        .metadata()
        .await
        .map_err(|err| AppError::internal(format!("failed reading bugreport metadata: {err}")))?
        .len();
    if actual_size == 0 || actual_size > max_bytes || actual_size != resp.size_bytes {
        drop(file);
        return Err(AppError::invalid_argument(format!(
            "bugreport archive size {actual_size} does not match expected {} inside 1..={max_bytes}",
            resp.size_bytes
        )));
    }

    let reader_stream = ReaderStream::with_capacity(file, BUGREPORT_STREAM_CHUNK_BYTES);
    let path_for_stream = guarded.disarm();
    let stream_body = GuardedBugreportStream::from_stream(reader_stream, path_for_stream);

    let size_str = actual_size.to_string();
    let content_len_hv = HeaderValue::from_str(&size_str)
        .map_err(|err| AppError::internal(format!("invalid Content-Length header value: {err}")))?;
    let archive_bytes_hv = HeaderValue::from_str(&size_str).map_err(|err| {
        AppError::internal(format!("invalid X-Mesh-Archive-Bytes header value: {err}"))
    })?;
    let scrubbed_hv = HeaderValue::from_str(&resp.scrubbed_items.to_string()).map_err(|err| {
        AppError::internal(format!("invalid X-Mesh-Scrubbed-Items header value: {err}"))
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-tar"),
        )
        .header(header::CONTENT_LENGTH, content_len_hv)
        .header(
            HeaderName::from_static(HEADER_MESH_ARCHIVE_BYTES),
            archive_bytes_hv,
        )
        .header(
            HeaderName::from_static(HEADER_MESH_SCRUBBED_ITEMS),
            scrubbed_hv,
        )
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .body(Body::new(stream_body))
        .map_err(|err| {
            AppError::internal(format!(
                "failed constructing bugreport stream response: {err}"
            ))
        })
}

async fn handle_bugreport(State(state): State<IpcRouterState>) -> Response {
    let (bootstrap, state_dir_opt) = {
        let g = state.runtime.inner.read().await;
        let dir = g.state_store.state_dir().map(std::path::Path::to_path_buf);
        (g.bootstrap.clone(), dir)
    };
    let status = state.runtime.build_status_response().await;
    let netcheck_res = PingProbe::execute_netcheck(&state.runtime).await;
    let now_unix_ms = SystemClock::new().now_unix_ms();
    let Some(state_dir) = state_dir_opt else {
        return dispatch_cmd(&state.cmd_tx, |reply| SupervisorCommand::Bugreport {
            reply,
        })
        .await;
    };

    let bundle_join = tokio::task::spawn_blocking(move || {
        let nc_ref = match netcheck_res.as_ref() {
            Ok(ok) => Ok(ok),
            Err(err) => Err(err.public_message()),
        };
        create_bugreport_tar_bundle(&state_dir, &bootstrap, &status, nc_ref, now_unix_ms)
    })
    .await;

    match bundle_join {
        Ok(Ok(resp)) => (StatusCode::OK, Json(resp)).into_response(),
        Ok(Err(err)) => app_error_response(&err),
        Err(join_err) => app_error_response(&AppError::internal(format!(
            "bugreport worker task failed: {join_err}"
        ))),
    }
}

async fn dispatch_cmd<Resp, F>(tx: &mpsc::Sender<SupervisorCommand>, make_cmd: F) -> Response
where
    Resp: serde::Serialize,
    F: FnOnce(oneshot::Sender<AppResult<Resp>>) -> SupervisorCommand,
{
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(make_cmd(reply_tx)).await.is_err() {
        return app_error_response(&AppError::unavailable("daemon supervisor shutting down"));
    }
    match tokio::time::timeout(IPC_COMMAND_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(payload))) => (StatusCode::OK, Json(payload)).into_response(),
        Ok(Ok(Err(err))) => app_error_response(&err),
        Ok(Err(_)) => app_error_response(&AppError::unavailable("daemon supervisor dropped reply")),
        Err(_) => app_error_response(&AppError::unavailable("daemon operation timed out")),
    }
}

async fn handle_ro_fallback() -> Response {
    app_error_response(&AppError::not_found(
        "endpoint is not exposed on read-only IPC socket",
    ))
}

fn app_error_response(err: &AppError) -> Response {
    let kind = err.kind();
    let status = match kind {
        ErrorKind::InvalidArgument => StatusCode::BAD_REQUEST,
        ErrorKind::Unauthenticated => StatusCode::UNAUTHORIZED,
        ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Conflict => StatusCode::CONFLICT,
        ErrorKind::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorKind::Unavailable | ErrorKind::NodeRevoked | ErrorKind::NodeKeyExpired => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ErrorKind::PinMismatch | ErrorKind::ClockSkew => StatusCode::BAD_GATEWAY,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = ErrorResponse {
        error: ErrorEnvelope {
            kind,
            code: kind.wire_code().to_owned(),
            message: err.to_string(),
            request_id: "ipc".to_owned(),
        },
    };
    (status, Json(body)).into_response()
}

#[cfg(target_os = "windows")]
async fn start_platform_listeners(
    ro_endpoint: &str,
    admin_endpoint: &str,
    ro_router: Router,
    admin_router: Router,
    tracker: &TaskTracker,
    shutdown: &CancellationToken,
) -> AppResult<()> {
    use mesh_net::ipc_windows::WindowsIpcServer;

    let ro_srv = WindowsIpcServer::new(ro_endpoint.to_owned(), IpcChannelKind::AgentReadOnly);
    let admin_srv = WindowsIpcServer::new(admin_endpoint.to_owned(), IpcChannelKind::AgentAdmin);

    let ro_shutdown = shutdown.clone();
    tracker.spawn(async move {
        if let Err(err) = ro_srv.serve(ro_router, ro_shutdown).await {
            warn!(
                component = "meshd.ipc",
                event = "windows_ro_pipe_stopped",
                error = %err,
                "Windows Read-Only IPC server exited with error"
            );
        }
    });

    let admin_shutdown = shutdown.clone();
    tracker.spawn(async move {
        if let Err(err) = admin_srv.serve(admin_router, admin_shutdown).await {
            warn!(
                component = "meshd.ipc",
                event = "windows_admin_pipe_stopped",
                error = %err,
                "Windows Admin IPC server exited with error"
            );
        }
    });

    info!(
        component = "meshd.ipc",
        event = "ipc_listeners_started",
        ro_pipe = %ro_endpoint,
        admin_pipe = %admin_endpoint,
        "started dual Windows Named Pipe IPC listeners"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
async fn start_platform_listeners(
    ro_endpoint: &str,
    admin_endpoint: &str,
    ro_router: Router,
    admin_router: Router,
    tracker: &TaskTracker,
    shutdown: &CancellationToken,
) -> AppResult<()> {
    use std::path::Path;

    use mesh_core::defaults::LINUX_ADMIN_GROUP_NAME;
    use mesh_net::ipc_linux::{
        agent_admin_socket_mode, agent_runtime_dir_policy, bind_linux_ipc_listener,
    };

    let policy = agent_runtime_dir_policy();
    let admin_mode = agent_admin_socket_mode(Some(LINUX_ADMIN_GROUP_NAME))?;
    let admin_gid = resolve_group_gid_from_etc_group(LINUX_ADMIN_GROUP_NAME);

    let ro_listener = bind_linux_ipc_listener(Path::new(ro_endpoint), policy, 0o666, None)?;
    let admin_listener =
        bind_linux_ipc_listener(Path::new(admin_endpoint), policy, admin_mode, admin_gid)?;

    spawn_unix_accept_loop(
        ro_listener,
        IpcChannelKind::AgentReadOnly,
        ro_router,
        tracker,
        shutdown.clone(),
    );
    spawn_unix_accept_loop(
        admin_listener,
        IpcChannelKind::AgentAdmin,
        admin_router,
        tracker,
        shutdown.clone(),
    );

    info!(
        component = "meshd.ipc",
        event = "ipc_listeners_started",
        ro_socket = %ro_endpoint,
        admin_socket = %admin_endpoint,
        "started dual Linux UDS IPC listeners"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
async fn start_platform_listeners(
    ro_endpoint: &str,
    admin_endpoint: &str,
    ro_router: Router,
    admin_router: Router,
    tracker: &TaskTracker,
    shutdown: &CancellationToken,
) -> AppResult<()> {
    use std::path::Path;

    use mesh_net::ipc_macos::bind_macos_agent_sockets;

    let (admin_listener, ro_listener) =
        bind_macos_agent_sockets(Path::new(admin_endpoint), Path::new(ro_endpoint))?;

    spawn_unix_accept_loop(
        ro_listener,
        IpcChannelKind::AgentReadOnly,
        ro_router,
        tracker,
        shutdown.clone(),
    );
    spawn_unix_accept_loop(
        admin_listener,
        IpcChannelKind::AgentAdmin,
        admin_router,
        tracker,
        shutdown.clone(),
    );

    info!(
        component = "meshd.ipc",
        event = "ipc_listeners_started",
        ro_socket = %ro_endpoint,
        admin_socket = %admin_endpoint,
        "started dual macOS UDS IPC listeners"
    );
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
async fn start_platform_listeners(
    _ro_endpoint: &str,
    _admin_endpoint: &str,
    _ro_router: Router,
    _admin_router: Router,
    _tracker: &TaskTracker,
    _shutdown: &CancellationToken,
) -> AppResult<()> {
    Err(AppError::internal(
        "IPC listeners unsupported on this target OS",
    ))
}

#[cfg(unix)]
fn spawn_unix_accept_loop(
    listener: tokio::net::UnixListener,
    channel: IpcChannelKind,
    router: Router,
    tracker: &TaskTracker,
    shutdown: CancellationToken,
) {
    let conn_tracker = tracker.clone();
    tracker.spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = shutdown.cancelled() => break,
                res = listener.accept() => res,
            };
            let (stream, _) = match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    warn!(
                        component = "meshd.ipc",
                        event = "unix_ipc_accept_error",
                        channel = ?channel,
                        error = %err,
                        "Unix IPC accept error"
                    );
                    continue;
                }
            };
            let conn_router = router.clone();
            conn_tracker.spawn(async move {
                if let Err(err) = authorize_unix_peer(&stream, channel) {
                    debug!(
                        component = "meshd.ipc",
                        event = "unix_ipc_peer_rejected",
                        channel = ?channel,
                        error = %err,
                        "rejected unauthorized Unix IPC client"
                    );
                    return;
                }
                if let Err(err) =
                    mesh_net::ipc::serve_ipc_http_connection(stream, conn_router).await
                {
                    debug!(
                        component = "meshd.ipc",
                        event = "unix_ipc_conn_closed",
                        error = %err,
                        "Unix IPC HTTP connection closed"
                    );
                }
            });
        }
    });
}

#[cfg(target_os = "linux")]
fn authorize_unix_peer(
    stream: &tokio::net::UnixStream,
    channel: IpcChannelKind,
) -> AppResult<mesh_net::ipc::CallerPrivilege> {
    mesh_net::ipc_linux::verify_unix_socket_peer(
        stream,
        channel,
        Some(mesh_core::defaults::LINUX_ADMIN_GROUP_NAME),
    )
}

#[cfg(target_os = "macos")]
fn authorize_unix_peer(
    stream: &tokio::net::UnixStream,
    channel: IpcChannelKind,
) -> AppResult<mesh_net::ipc::CallerPrivilege> {
    mesh_net::ipc_macos::verify_macos_socket_peer(stream, channel)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn authorize_unix_peer(
    _stream: &tokio::net::UnixStream,
    _channel: IpcChannelKind,
) -> AppResult<mesh_net::ipc::CallerPrivilege> {
    Err(AppError::permission_denied(
        "unsupported Unix platform for IPC auth",
    ))
}

#[cfg(target_os = "linux")]
fn resolve_group_gid_from_etc_group(group_name: &str) -> Option<u32> {
    let raw = std::fs::read_to_string("/etc/group").ok()?;
    for line in raw.lines() {
        let mut parts = line.split(':');
        if parts.next() == Some(group_name) {
            let _passwd = parts.next();
            if let Some(gid_str) = parts.next()
                && let Ok(gid) = gid_str.parse::<u32>()
            {
                return Some(gid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::Method;
    use tokio::io::duplex;
    use tokio::sync::mpsc;

    use mesh_client::hooks::FileClientStateStore;
    use mesh_core::ErrorKind;
    use mesh_core::defaults::MAX_RO_IPC_BODY_BYTES;
    use mesh_datapath::TimerMode;
    use mesh_net::ipc::{send_ipc_json_request, serve_ipc_http_connection};
    use mesh_proto::agent_ipc::{AgentActionResponse, AgentStatusResponse};
    use tempfile::tempdir;

    use super::{IpcRouterState, IpcService};
    use crate::config::BootstrapConfig;
    use crate::control_loop::DaemonRuntimeState;

    #[tokio::test]
    async fn test_ipc_ro_router_exposes_only_four_read_routes_and_blocks_admin_mutations() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let runtime = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf())),
            None,
            1280,
            TimerMode::Responsive,
        ));
        let (cmd_tx, _cmd_rx) = mpsc::channel(4);
        let ro_router = IpcService::build_ro_router(IpcRouterState { runtime, cmd_tx });

        let (ro_client, ro_server) = duplex(16 * 1024);
        let srv_task = tokio::spawn(serve_ipc_http_connection(ro_server, ro_router.clone()));

        // Act
        let status: AgentStatusResponse = send_ipc_json_request(
            ro_client,
            Method::GET,
            "/v1/agent/status",
            Option::<&()>::None,
            MAX_RO_IPC_BODY_BYTES,
        )
        .await
        .expect("ro status succeeds");

        let (mut_client, mut_server) = duplex(16 * 1024);
        let srv_task2 = tokio::spawn(serve_ipc_http_connection(mut_server, ro_router));
        let denied_down: Result<AgentActionResponse, _> = send_ipc_json_request(
            mut_client,
            Method::POST,
            "/v1/agent/down",
            Option::<&()>::None,
            MAX_RO_IPC_BODY_BYTES,
        )
        .await;

        srv_task
            .await
            .expect("ro status task join")
            .expect("ro status server clean exit");
        srv_task2
            .await
            .expect("ro mutation task join")
            .expect("ro mutation server clean exit");

        // Assert
        assert_eq!(status.peers.len(), 0);
        assert!(matches!(
            denied_down,
            Err(err) if err.kind() == ErrorKind::NotFound || err.kind() == ErrorKind::PermissionDenied
        ));
    }

    #[tokio::test]
    async fn test_ipc_admin_bugreport_creates_tar_scrubs_secrets_and_ro_blocks_it() {
        use crate::config::MAX_BUGREPORT_ARCHIVE_BYTES;
        use mesh_core::defaults::MAX_ADMIN_IPC_BODY_BYTES;
        use mesh_proto::agent_ipc::BugreportResponse;

        // Arrange: stage rotated log containing canary tokens inside daemon state_dir
        let dir = tempdir().expect("tempdir");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("mkdir logs");
        let canary_mpk = "mpk_IPC_CANARY_TOKEN_11223344";
        let canary_bearer = "eyJhbGciOiJIUzI1NiJ9.IPC_CANARY_BEARER_5566";
        let canary_secret = "IPC_NODE_SECRET_CANARY_9988";
        std::fs::write(
            log_dir.join("meshd.log.1"),
            format!(
                "WARN connect preauth_key=\"{canary_mpk}\" Authorization: Bearer {canary_bearer} node_secret=\"{canary_secret}\"\n"
            ),
        )
        .expect("write canary log");

        let runtime = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf())),
            None,
            1280,
            TimerMode::Responsive,
        ));
        let (cmd_tx, _cmd_rx) = mpsc::channel(4);
        let router_state = IpcRouterState { runtime, cmd_tx };
        let ro_router = IpcService::build_ro_router(router_state.clone());
        let admin_router = IpcService::build_admin_router(router_state);

        // Act 1: verify RO socket rejects /v1/agent/bugreport (`US-041` / `SEC-14`)
        let (ro_client, ro_server) = duplex(16 * 1024);
        let ro_task = tokio::spawn(serve_ipc_http_connection(ro_server, ro_router));
        let ro_res: Result<BugreportResponse, _> = send_ipc_json_request(
            ro_client,
            Method::POST,
            "/v1/agent/bugreport",
            Some(&()),
            MAX_RO_IPC_BODY_BYTES,
        )
        .await;
        ro_task.await.expect("ro join").expect("ro clean");
        assert!(matches!(
            ro_res,
            Err(err) if err.kind() == ErrorKind::NotFound || err.kind() == ErrorKind::PermissionDenied
        ));

        // Act 2: invoke /v1/agent/bugreport over privileged admin router
        let (ad_client, ad_server) = duplex(16 * 1024);
        let ad_task = tokio::spawn(serve_ipc_http_connection(ad_server, admin_router));
        let resp: BugreportResponse = send_ipc_json_request(
            ad_client,
            Method::POST,
            "/v1/agent/bugreport",
            Some(&()),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("admin bugreport succeeds");
        ad_task.await.expect("admin join").expect("admin clean");

        // Assert
        let tar_bytes = std::fs::read(&resp.bundle_path).expect("read bugreport tar");
        assert!(resp.bundle_path.ends_with(".tar"));
        assert!(tar_bytes.len() <= MAX_BUGREPORT_ARCHIVE_BYTES);
        assert!(resp.scrubbed_items >= 3);
        let text = String::from_utf8_lossy(&tar_bytes);
        assert!(!text.contains(canary_mpk));
        assert!(!text.contains(canary_bearer));
        assert!(!text.contains(canary_secret));
        assert!(text.contains("ustar"));
        assert!(text.contains("status.json"));
        assert!(text.contains("netcheck.json"));
        assert!(text.contains("routes.txt"));
    }

    #[tokio::test]
    async fn test_ipc_version_endpoint_header_and_13_field_status_compat() -> Result<(), String> {
        use hyper::client::conn::http1 as hyper_client_http1;
        use hyper_util::rt::TokioIo;
        use mesh_net::ipc::{
            HEADER_MESH_AGENT_VERSION, IPC_RO_QUERY_TIMEOUT, send_ipc_json_with_meta,
        };
        use mesh_proto::agent_ipc::AgentVersionResponse;

        // Arrange
        let dir = tempdir().map_err(|e| e.to_string())?;
        let runtime = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf())),
            None,
            1280,
            TimerMode::Responsive,
        ));
        let (cmd_tx, _cmd_rx) = mpsc::channel(4);
        let state = IpcRouterState { runtime, cmd_tx };
        let ro_router = IpcService::build_ro_router(state.clone());
        let admin_router = IpcService::build_admin_router(state);

        // Act 1: GET /v1/agent/version on both RO and Admin
        let (ro_cli, ro_srv) = duplex(16 * 1024);
        let ro_task = tokio::spawn(serve_ipc_http_connection(ro_srv, ro_router.clone()));
        let ro_ver = send_ipc_json_with_meta::<_, (), AgentVersionResponse>(
            ro_cli,
            Method::GET,
            "/v1/agent/version",
            None,
            MAX_RO_IPC_BODY_BYTES,
            IPC_RO_QUERY_TIMEOUT,
        )
        .await
        .map_err(|e| e.to_string())?;
        ro_task
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

        let (ad_cli, ad_srv) = duplex(16 * 1024);
        let ad_task = tokio::spawn(serve_ipc_http_connection(ad_srv, admin_router.clone()));
        let ad_ver = send_ipc_json_with_meta::<_, (), AgentVersionResponse>(
            ad_cli,
            Method::GET,
            "/v1/agent/version",
            None,
            MAX_RO_IPC_BODY_BYTES,
            IPC_RO_QUERY_TIMEOUT,
        )
        .await
        .map_err(|e| e.to_string())?;
        ad_task
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

        // Act 2: GET /v1/agent/status preserves exact 13 fields + emits X-Mesh-Agent-Version
        let (st_cli, st_srv) = duplex(16 * 1024);
        let st_task = tokio::spawn(serve_ipc_http_connection(st_srv, ro_router.clone()));
        let st_meta = send_ipc_json_with_meta::<_, (), serde_json::Value>(
            st_cli,
            Method::GET,
            "/v1/agent/status",
            None,
            MAX_RO_IPC_BODY_BYTES,
            IPC_RO_QUERY_TIMEOUT,
        )
        .await
        .map_err(|e| e.to_string())?;
        st_task
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

        // Act 3: Error response on RO router also emits X-Mesh-Agent-Version header
        let (err_cli, err_srv) = duplex(16 * 1024);
        let err_task = tokio::spawn(serve_ipc_http_connection(err_srv, ro_router));
        let (mut sender, conn) = hyper_client_http1::handshake(TokioIo::new(err_cli))
            .await
            .map_err(|e| e.to_string())?;
        let conn_task = tokio::spawn(conn);
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/agent/reset-identity")
            .header(axum::http::header::HOST, "localhost")
            .header(axum::http::header::CONNECTION, "close")
            .body(axum::body::Body::empty())
            .map_err(|e| e.to_string())?;
        let err_resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let err_status = err_resp.status();
        let err_ver_hdr = err_resp
            .headers()
            .get(HEADER_MESH_AGENT_VERSION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        drop(err_resp);
        drop(sender);
        let _conn_res = conn_task.await;
        let _err_srv_res = err_task.await;

        // Assert
        let expected_ver = env!("CARGO_PKG_VERSION");
        assert_eq!(ro_ver.body.agent_version, expected_ver);
        assert_eq!(ro_ver.body.protocol_version, 1);
        assert_eq!(ro_ver.body.binary_name, "meshd");
        assert_eq!(ro_ver.agent_version.as_deref(), Some(expected_ver));
        assert_eq!(ad_ver.body, ro_ver.body);
        assert_eq!(ad_ver.agent_version.as_deref(), Some(expected_ver));

        let status_keys = st_meta
            .body
            .as_object()
            .map(|m| m.len())
            .unwrap_or_default();
        assert_eq!(status_keys, 13);
        assert_eq!(st_meta.agent_version.as_deref(), Some(expected_ver));
        assert!(serde_json::from_value::<AgentStatusResponse>(st_meta.body).is_ok());

        assert_eq!(err_status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(err_ver_hdr.as_deref(), Some(expected_ver));
        Ok(())
    }

    #[tokio::test]
    async fn test_ipc_ro_blocks_new_admin_routes_and_admin_reset_identity_accepts_empty_null_obj()
    -> Result<(), String> {
        use hyper::client::conn::http1 as hyper_client_http1;
        use hyper_util::rt::TokioIo;
        use mesh_client::hooks::{
            ClientPlatformHooks, ClientStateStore, InMemoryClientPlatformHooks,
        };
        use mesh_client::{ClientRuntimeConfig, ClientSessionOptions, ClientSessionSupervisor};
        use mesh_core::clock::SystemClock;
        use mesh_core::{NodeId, NodeName, OverlayIp, SpkiPin};
        use mesh_net::netmon::FakeNetMonitor;
        use mesh_proto::agent_ipc::DaemonState;
        use tokio_util::sync::CancellationToken;

        // Arrange: start real ClientSessionSupervisor loop backed by FileClientStateStore
        let dir = tempdir().map_err(|e| e.to_string())?;
        let store = Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf()));
        let hooks = Arc::new(InMemoryClientPlatformHooks::default());
        let now_ms = 1_700_000_000_000_u64;
        let _id = store
            .load_or_create_identity(now_ms)
            .map_err(|e| e.to_string())?;
        let node_id = NodeId::new_v7(now_ms);
        let _id2 = store
            .set_identity_node_id(node_id)
            .map_err(|e| e.to_string())?;
        let bootstrap = BootstrapConfig {
            node_id: Some(node_id),
            node_name: "win-desktop".parse::<NodeName>().ok(),
            overlay_ip: "100.115.0.4".parse::<OverlayIp>().ok(),
            server_endpoint: Some("203.0.113.10:8443".to_owned()),
            active_pin: Some(SpkiPin::from_sha256_bytes([5; 32])),
            ..BootstrapConfig::default()
        };
        store
            .save_bootstrap(&bootstrap)
            .map_err(|e| e.to_string())?;

        let supervisor = ClientSessionSupervisor::boot(
            ClientSessionOptions::new(ClientRuntimeConfig::for_desktop()),
            Arc::new(SystemClock::new()),
            Arc::clone(&hooks) as Arc<dyn ClientPlatformHooks>,
            Arc::clone(&store) as Arc<dyn ClientStateStore>,
        )
        .map_err(|e| e.to_string())?;
        let runtime = supervisor.runtime_state();
        let cmd_tx = supervisor.command_sender();
        let shutdown = CancellationToken::new();
        let sup_task =
            tokio::spawn(supervisor.run(Arc::new(FakeNetMonitor::new()), shutdown.clone()));

        let router_state = IpcRouterState {
            runtime: Arc::clone(&runtime),
            cmd_tx,
        };
        let ro_router = IpcService::build_ro_router(router_state.clone());
        let admin_router = IpcService::build_admin_router(router_state);

        // Act 1: RO router blocks /v1/agent/reset-identity and /v1/agent/bugreport/stream
        for blocked_path in ["/v1/agent/reset-identity", "/v1/agent/bugreport/stream"] {
            let (cli, srv) = duplex(16 * 1024);
            let srv_task = tokio::spawn(serve_ipc_http_connection(srv, ro_router.clone()));
            let res: Result<AgentActionResponse, _> = send_ipc_json_request(
                cli,
                Method::POST,
                blocked_path,
                Option::<&()>::None,
                MAX_RO_IPC_BODY_BYTES,
            )
            .await;
            let _srv_res = srv_task.await;
            assert!(matches!(
                res,
                Err(ref e) if e.kind() == ErrorKind::NotFound
            ));
        }

        // Act 2: Admin router rejects unknown fields in /v1/agent/reset-identity (deny_unknown_fields)
        {
            let (cli, srv) = duplex(16 * 1024);
            let srv_task = tokio::spawn(serve_ipc_http_connection(srv, admin_router.clone()));
            let (mut sender, conn) = hyper_client_http1::handshake(TokioIo::new(cli))
                .await
                .map_err(|e| e.to_string())?;
            let conn_task = tokio::spawn(conn);
            let req = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v1/agent/reset-identity")
                .header(axum::http::header::HOST, "localhost")
                .header(axum::http::header::CONNECTION, "close")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"purge":true}"#))
                .map_err(|e| e.to_string())?;
            let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
            assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
            drop(resp);
            drop(sender);
            let _c = conn_task.await;
            let _s = srv_task.await;
        }

        // Act 3: Admin router accepts empty body, `null`, and `{}` while keeping daemon alive
        for raw_body in [b"" as &[u8], b"null", b"{}"] {
            let (cli, srv) = duplex(16 * 1024);
            let srv_task = tokio::spawn(serve_ipc_http_connection(srv, admin_router.clone()));
            let (mut sender, conn) = hyper_client_http1::handshake(TokioIo::new(cli))
                .await
                .map_err(|e| e.to_string())?;
            let conn_task = tokio::spawn(conn);
            let req = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v1/agent/reset-identity")
                .header(axum::http::header::HOST, "localhost")
                .header(axum::http::header::CONNECTION, "close")
                .body(axum::body::Body::from(raw_body.to_vec()))
                .map_err(|e| e.to_string())?;
            let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
            assert_eq!(resp.status(), axum::http::StatusCode::OK);
            let bytes = axum::body::to_bytes(axum::body::Body::new(resp.into_body()), 4096)
                .await
                .map_err(|e| e.to_string())?;
            let parsed: AgentActionResponse =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            assert_eq!(parsed.state, DaemonState::Stopped);
            assert_eq!(
                parsed.message,
                "node identity reset cleanly; ready for enrollment"
            );
            drop(sender);
            let _c = conn_task.await;
            let _s = srv_task.await;
        }

        // Assert: disk & RAM reset cleanly, and daemon remains alive for status queries
        assert!(!dir.path().join("keys.json").exists());
        assert_eq!(
            store.load_bootstrap().map_err(|e| e.to_string())?,
            BootstrapConfig::default()
        );
        let (st_cli, st_srv) = duplex(16 * 1024);
        let st_task = tokio::spawn(serve_ipc_http_connection(st_srv, ro_router));
        let status: AgentStatusResponse = send_ipc_json_request(
            st_cli,
            Method::GET,
            "/v1/agent/status",
            Option::<&()>::None,
            MAX_RO_IPC_BODY_BYTES,
        )
        .await
        .map_err(|e| e.to_string())?;
        let _st = st_task.await;
        assert_eq!(status.daemon_state, DaemonState::Stopped);
        assert_eq!(status.node_id, None);
        assert!(status.peers.is_empty());

        shutdown.cancel();
        let _sup_res = sup_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn test_ipc_admin_bugreport_stream_64kib_chunks_headers_and_temp_cleanup()
    -> Result<(), String> {
        use hyper::client::conn::http1 as hyper_client_http1;
        use hyper_util::rt::TokioIo;
        use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
        use mesh_net::ipc::{
            HEADER_MESH_AGENT_VERSION, HEADER_MESH_ARCHIVE_BYTES, HEADER_MESH_SCRUBBED_ITEMS,
            IPC_ADMIN_MUTATION_TIMEOUT, stream_ipc_bugreport,
        };

        // Arrange: stage >140 KiB log so tar archive requires >=3 64 KiB stream chunks
        let dir = tempdir().map_err(|e| e.to_string())?;
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).map_err(|e| e.to_string())?;
        let canary_mpk = "mpk_STREAM_CANARY_TOKEN_778899";
        let mut log_content = format!("WARN preauth_key=\"{canary_mpk}\"\n");
        let filler = "INFO meshd stream test line padding 0123456789abcdef\n".repeat(3_000);
        log_content.push_str(&filler);
        std::fs::write(log_dir.join("meshd.log.1"), &log_content).map_err(|e| e.to_string())?;

        let runtime = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf())),
            None,
            1280,
            TimerMode::Responsive,
        ));
        let (cmd_tx, _cmd_rx) = mpsc::channel(4);
        let admin_router = IpcService::build_admin_router(IpcRouterState { runtime, cmd_tx });

        // Act 1: stream via `stream_ipc_bugreport` verifying chunk size <= 64 KiB
        let (cli_io, srv_io) = duplex(256 * 1024);
        let srv_task = tokio::spawn(serve_ipc_http_connection(srv_io, admin_router.clone()));
        let mut collected = Vec::new();
        let mut chunk_count = 0_usize;
        let meta = stream_ipc_bugreport(
            cli_io,
            IPC_ADMIN_MUTATION_TIMEOUT,
            std::time::Duration::from_secs(5),
            |chunk| {
                assert!(chunk.len() <= super::BUGREPORT_STREAM_CHUNK_BYTES);
                chunk_count = chunk_count.saturating_add(1);
                collected.extend_from_slice(chunk);
                Ok(())
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        srv_task
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

        assert!(chunk_count >= 2);
        assert!(meta.total_bytes > 65_536);
        assert!(meta.total_bytes <= u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX));
        assert_eq!(
            u64::try_from(collected.len()).unwrap_or(0),
            meta.total_bytes
        );
        assert!(meta.scrubbed_items >= 1);
        assert_eq!(
            meta.agent_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        let tar_lossy = String::from_utf8_lossy(&collected);
        assert!(!tar_lossy.contains(canary_mpk));
        assert!(tar_lossy.contains("ustar"));

        // Act 2: inspect all required HTTP headers directly on empty `{}` / `null` body
        let (hdr_cli, hdr_srv) = duplex(256 * 1024);
        let hdr_srv_task = tokio::spawn(serve_ipc_http_connection(hdr_srv, admin_router));
        let (mut sender, conn) = hyper_client_http1::handshake(TokioIo::new(hdr_cli))
            .await
            .map_err(|e| e.to_string())?;
        let conn_task = tokio::spawn(conn);
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/agent/bugreport/stream")
            .header(axum::http::header::HOST, "localhost")
            .header(axum::http::header::CONNECTION, "close")
            .body(axum::body::Body::from("{}"))
            .map_err(|e| e.to_string())?;
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let headers = resp.headers().clone();
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-tar")
        );
        assert_eq!(
            headers
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            headers
                .get(HEADER_MESH_AGENT_VERSION)
                .and_then(|v| v.to_str().ok()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        let cl = headers
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let ab = headers
            .get(HEADER_MESH_ARCHIVE_BYTES)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        assert!(cl.is_some());
        assert_eq!(cl, ab);
        assert!(headers.get(HEADER_MESH_SCRUBBED_ITEMS).is_some());
        let _body = axum::body::to_bytes(
            axum::body::Body::new(resp.into_body()),
            MAX_BUGREPORT_ARCHIVE_BYTES,
        )
        .await
        .map_err(|e| e.to_string())?;
        drop(sender);
        let _conn_res = conn_task.await;
        let _hdr_res = hdr_srv_task.await;

        // Assert: temp files inside state_dir/bugreports were removed by GuardedBugreportStream::drop
        let bugreports_dir = dir.path().join("bugreports");
        let remaining: Vec<_> = std::fs::read_dir(&bugreports_dir)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .collect();
        assert!(
            remaining.is_empty(),
            "expected no leaked temporary bugreports, found {remaining:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_guarded_bugreport_stream_drops_handle_before_removing_file_and_rejects_oversize()
    -> Result<(), String> {
        use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
        use mesh_proto::agent_ipc::BugreportResponse;
        use tokio_util::io::ReaderStream;

        // Arrange 1: early drop closes tokio::fs::File handle before std::fs::remove_file
        let dir = tempdir().map_err(|e| e.to_string())?;
        let temp_tar = dir.path().join("early-drop.tar");
        std::fs::write(&temp_tar, vec![0x42_u8; 4096]).map_err(|e| e.to_string())?;
        let file = tokio::fs::File::open(&temp_tar)
            .await
            .map_err(|e| e.to_string())?;
        let stream = super::GuardedBugreportStream::from_stream(
            ReaderStream::with_capacity(file, super::BUGREPORT_STREAM_CHUNK_BYTES),
            temp_tar.clone(),
        );
        assert!(temp_tar.exists());

        // Act 1
        drop(stream);

        // Assert 1: deleted immediately even without draining stream
        assert!(!temp_tar.exists());

        // Arrange 2 & Act 2: oversize / zero-size rejection also removes temp file cleanly
        let zero_tar = dir.path().join("zero.tar");
        std::fs::write(&zero_tar, b"").map_err(|e| e.to_string())?;
        let zero_res = super::build_streamed_bugreport_response(BugreportResponse {
            bundle_path: zero_tar.display().to_string(),
            size_bytes: 0,
            scrubbed_items: 0,
        })
        .await;
        assert!(matches!(
            zero_res,
            Err(ref e) if e.kind() == ErrorKind::InvalidArgument
        ));
        assert!(!zero_tar.exists());

        let over_tar = dir.path().join("over.tar");
        std::fs::write(&over_tar, b"dummy").map_err(|e| e.to_string())?;
        let over_res = super::build_streamed_bugreport_response(BugreportResponse {
            bundle_path: over_tar.display().to_string(),
            size_bytes: u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES + 1).unwrap_or(u64::MAX),
            scrubbed_items: 0,
        })
        .await;
        assert!(matches!(
            over_res,
            Err(ref e) if e.kind() == ErrorKind::InvalidArgument
        ));
        assert!(!over_tar.exists());

        // Arrange 3 & Act 3: client drops HTTP stream mid-transfer before reading full body
        let disc_dir = tempdir().map_err(|e| e.to_string())?;
        let log_dir = disc_dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).map_err(|e| e.to_string())?;
        std::fs::write(
            log_dir.join("meshd.log.1"),
            "INFO client disconnect cleanup test line\n".repeat(3_500),
        )
        .map_err(|e| e.to_string())?;
        let runtime = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            Arc::new(FileClientStateStore::from_dir(
                disc_dir.path().to_path_buf(),
            )),
            None,
            1280,
            TimerMode::Responsive,
        ));
        let (cmd_tx, _cmd_rx) = mpsc::channel(4);
        let admin_router = IpcService::build_admin_router(IpcRouterState { runtime, cmd_tx });
        let (disc_cli, disc_srv) = duplex(8 * 1024);
        let disc_srv_task = tokio::spawn(serve_ipc_http_connection(disc_srv, admin_router));
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(disc_cli))
                .await
                .map_err(|e| e.to_string())?;
        let conn_task = tokio::spawn(conn);
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/agent/bugreport/stream")
            .header(axum::http::header::HOST, "localhost")
            .header(axum::http::header::CONNECTION, "close")
            .body(axum::body::Body::empty())
            .map_err(|e| e.to_string())?;
        let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // Drop client response + connection immediately without draining remaining chunks.
        drop(resp);
        drop(sender);
        let _c = conn_task.await;
        let _s = disc_srv_task.await;

        let remaining: Vec<_> = std::fs::read_dir(disc_dir.path().join("bugreports"))
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .collect();
        assert!(
            remaining.is_empty(),
            "abrupt client disconnect leaked temporary archive: {remaining:?}"
        );
        Ok(())
    }
}
