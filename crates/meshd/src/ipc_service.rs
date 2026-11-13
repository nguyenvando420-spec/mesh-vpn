//! Dual local IPC routers (`meshd-ro` vs `meshd-admin`) with kernel peer credential enforcement
//! (`SEC-14`, `BLK-G2-03`, `US-039`, `US-073`).

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
#[cfg(unix)]
use tracing::debug;
use tracing::{info, warn};

use mesh_core::clock::{Clock as _, SystemClock};
use mesh_core::defaults::{MAX_ADMIN_IPC_BODY_BYTES, MAX_RO_IPC_BODY_BYTES};
use mesh_core::error::{ErrorEnvelope, ErrorKind, ErrorResponse};
use mesh_core::{AppError, AppResult};
use mesh_net::ipc::IpcChannelKind;
use mesh_proto::agent_ipc::{AgentRotateKeyRequest, AgentSetRequest, AgentUpRequest, PingRequest};

use crate::config::create_bugreport_tar_bundle;
use crate::control_loop::DaemonRuntimeState;
use crate::ping_probe::PingProbe;
use crate::supervisor::SupervisorCommand;

const IPC_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

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
            .route("/v1/agent/ping", post(handle_ping))
            .route("/v1/agent/netcheck", post(handle_netcheck))
            .fallback(handle_ro_fallback)
            .layer(DefaultBodyLimit::max(MAX_RO_IPC_BODY_BYTES))
            .with_state(state)
    }

    /// Builds the privileged Admin router (`meshd-admin`) adding tunnel lifecycle & mutation routes.
    pub(crate) fn build_admin_router(state: IpcRouterState) -> Router {
        Router::new()
            .route("/v1/agent/status", get(handle_status))
            .route("/v1/agent/peers", get(handle_peers))
            .route("/v1/agent/ping", post(handle_ping))
            .route("/v1/agent/netcheck", post(handle_netcheck))
            .route("/v1/agent/up", post(handle_up))
            .route("/v1/agent/down", post(handle_down))
            .route("/v1/agent/cleanup", post(handle_cleanup))
            .route("/v1/agent/set", post(handle_set))
            .route("/v1/agent/rotate-key", post(handle_rotate_key))
            .route("/v1/agent/bugreport", post(handle_bugreport))
            .layer(DefaultBodyLimit::max(MAX_ADMIN_IPC_BODY_BYTES))
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

async fn handle_status(State(state): State<IpcRouterState>) -> Response {
    let resp = state.runtime.build_status_response().await;
    (StatusCode::OK, Json(resp)).into_response()
}

async fn handle_peers(State(state): State<IpcRouterState>) -> Response {
    let resp = state.runtime.build_status_response().await;
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

async fn handle_bugreport(State(state): State<IpcRouterState>) -> Response {
    let (bootstrap, state_dir_opt) = {
        let g = state.runtime.inner.read().await;
        let dir = g
            .bootstrap_store
            .path()
            .parent()
            .map(std::path::Path::to_path_buf);
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

    use mesh_core::ErrorKind;
    use mesh_core::defaults::MAX_RO_IPC_BODY_BYTES;
    use mesh_net::ipc::{send_ipc_json_request, serve_ipc_http_connection};
    use mesh_proto::agent_ipc::{AgentActionResponse, AgentStatusResponse};
    use tempfile::tempdir;

    use super::{IpcRouterState, IpcService};
    use crate::config::{BootstrapConfig, BootstrapStore};
    use crate::control_loop::DaemonRuntimeState;
    use crate::netmap_cache::NetmapCacheStore;

    #[tokio::test]
    async fn test_ipc_ro_router_exposes_only_four_read_routes_and_blocks_admin_mutations() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let runtime = Arc::new(DaemonRuntimeState::new(
            BootstrapConfig::default(),
            BootstrapStore::new(dir.path().join("bootstrap.toml")),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
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
            BootstrapStore::new(dir.path().join("bootstrap.toml")),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
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
}
