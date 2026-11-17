//! Local IPC channel classification, fail-closed peer privilege authorization (`SEC-14`),
//! 3-tier IPC timeout enforcement (`ADR-024`), bounded HTTP-over-IPC JSON transport (`BLK-04`),
//! and bounded streaming bugreport client support (`ADR-023`).

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use hyper::body::Body as _;
use hyper::client::conn::http1 as hyper_client_http1;
use hyper::server::conn::http1 as hyper_server_http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use mesh_core::defaults::{
    LINUX_SERVER_ADMIN_SOCKET, MACOS_ADMIN_GID, MAX_ADMIN_IPC_BODY_BYTES,
    MAX_BUGREPORT_ARCHIVE_BYTES, MAX_RO_IPC_BODY_BYTES, UNIX_AGENT_ADMIN_SOCKET,
    UNIX_AGENT_RO_SOCKET, WINDOWS_AGENT_ADMIN_PIPE, WINDOWS_AGENT_RO_PIPE,
};
use mesh_core::error::ErrorResponse;
use mesh_core::{AppError, AppResult};
use mesh_proto::agent_ipc::AgentVersionResponse;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};

/// Tier 1 IPC connect / pipe-open timeout (`850 ms`, `ADR-024`, `DGUI-IPC-04`).
pub const IPC_CONNECT_TIMEOUT: Duration = Duration::from_millis(850);

/// Hard Tier 1 connect budget ceiling including Windows `ERROR_PIPE_BUSY` retries (`1_000 ms`).
pub const IPC_CONNECT_BUDGET_CAP: Duration = Duration::from_millis(1_000);

/// Tier 2 read-only query response timeout (`status`, `peers`, `version`, `2_000 ms`).
pub const IPC_RO_QUERY_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Tier 3a active `netcheck` probe timeout (`10_000 ms`).
pub const IPC_NETCHECK_TIMEOUT: Duration = Duration::from_millis(10_000);

/// Tier 3b upper bound for Disco `ping` probe (`35_000 ms`).
pub const IPC_PING_MAX_TIMEOUT: Duration = Duration::from_millis(35_000);

/// Tier 3c admin mutation / streaming timeout (`35_000 ms`, exceeding `IPC_COMMAND_TIMEOUT = 30 s`).
pub const IPC_ADMIN_MUTATION_TIMEOUT: Duration = Duration::from_millis(35_000);

/// Maximum idle stall between consecutive chunks when streaming `/v1/agent/bugreport/stream`.
pub const IPC_STREAM_CHUNK_IDLE_TIMEOUT: Duration = Duration::from_millis(10_000);

/// HTTP header emitted on all `meshd` v0.3.0+ IPC responses carrying bare SemVer (`"0.3.0"`).
pub const HEADER_MESH_AGENT_VERSION: &str = "x-mesh-agent-version";

/// HTTP header emitted on `/v1/agent/bugreport/stream` declaring exact `.tar` byte count.
pub const HEADER_MESH_ARCHIVE_BYTES: &str = "x-mesh-archive-bytes";

/// HTTP header emitted on `/v1/agent/bugreport/stream` declaring scrubbed secret item count.
pub const HEADER_MESH_SCRUBBED_ITEMS: &str = "x-mesh-scrubbed-items";

const WIN_ERROR_FILE_NOT_FOUND: i32 = 2;
const WIN_ERROR_ACCESS_DENIED: i32 = 5;
const WIN_ERROR_PIPE_BUSY: i32 = 231;
const WIN_ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const PIPE_BUSY_BACKOFF_MS: [u64; 7] = [50, 100, 150, 150, 150, 150, 100];

/// IPC request timeout tier (`ADR-024`, `DGUI-IPC-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpcOperationTier {
    /// Tier 2 read-only query (`status`, `peers`, `version`) — `2_000 ms`.
    ReadOnlyQuery,
    /// Tier 3a `netcheck` diagnostic probe — `10_000 ms`.
    NetcheckProbe,
    /// Tier 3b Disco `ping` probe — `min(count * per_probe_timeout_ms + 2_000, 35_000) ms`.
    PingProbe {
        /// Number of Disco echo probes (`1..=64`).
        count: u16,
        /// Per-probe wait timeout in milliseconds.
        per_probe_timeout_ms: u64,
    },
    /// Tier 3c admin mutation or bugreport stream — `35_000 ms`.
    AdminMutation,
}

impl IpcOperationTier {
    /// Computes the exact response timeout budget for this IPC operation tier.
    #[must_use]
    pub fn response_timeout(self) -> Duration {
        match self {
            Self::ReadOnlyQuery => IPC_RO_QUERY_TIMEOUT,
            Self::NetcheckProbe => IPC_NETCHECK_TIMEOUT,
            Self::PingProbe {
                count,
                per_probe_timeout_ms,
            } => ping_request_timeout(count, per_probe_timeout_ms),
            Self::AdminMutation => IPC_ADMIN_MUTATION_TIMEOUT,
        }
    }
}

/// Computes bounded Disco ping IPC timeout `min(count * per_probe_timeout_ms + 2_000 ms, 35_000 ms)`.
#[must_use]
pub fn ping_request_timeout(count: u16, per_probe_timeout_ms: u64) -> Duration {
    let probes = u64::from(count.max(1));
    let total_ms = probes
        .saturating_mul(per_probe_timeout_ms)
        .saturating_add(2_000)
        .min(35_000);
    Duration::from_millis(total_ms)
}

/// Classification of local OS IPC connect/open failures (`DGUI-IPC-05`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpcConnectFailureKind {
    /// Daemon offline, socket/pipe absent (`ENOENT`, `ECONNREFUSED`, Win32 `2`/`1060`).
    ServiceUnavailable,
    /// Access rejected by kernel ACL/SDDL (`EACCES`, Win32 `5`).
    PermissionDenied,
    /// Windows Named Pipe momentarily busy (`ERROR_PIPE_BUSY = 231`); eligible for short retry.
    BusyRetryable,
}

/// Daemon version probe outcome distinguishing v0.3.0+ SemVer from `v0.1.0-rc1` (`MED-DGUI-G2-01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentVersionStatus {
    /// Running or probed daemon reported a SemVer string (e.g. `"0.3.0"`).
    Version(String),
    /// Running `v0.1.0-rc1` daemon lacking `X-Mesh-Agent-Version`, `/v1/agent/version`, and `--version`.
    LegacyPre030,
}

/// HTTP-over-IPC JSON response paired with extracted `X-Mesh-Agent-Version` metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcJsonResponse<T> {
    /// Deserialized JSON body.
    pub body: T,
    /// Optional bare SemVer string parsed from `X-Mesh-Agent-Version`.
    pub agent_version: Option<String>,
    /// HTTP status code returned by the daemon IPC router.
    pub status: StatusCode,
}

/// Metadata parsed from `POST /v1/agent/bugreport/stream` response headers (`ADR-023`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamedBugreportMetadata {
    /// Exact `.tar` archive length declared by `X-Mesh-Archive-Bytes` / `Content-Length`.
    pub total_bytes: u64,
    /// Number of secret items redacted during archive generation.
    pub scrubbed_items: u32,
    /// Optional daemon SemVer from `X-Mesh-Agent-Version`.
    pub agent_version: Option<String>,
}

/// Dual-channel IPC endpoint classification separating Admin mutations from ReadOnly status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpcChannelKind {
    /// Server-side admin UDS (`/run/mesh-server/admin.sock`).
    ServerAdmin,
    /// Agent-side privileged control channel (`meshd-admin.sock` / `mesh-agent-admin`).
    AgentAdmin,
    /// Agent-side unprivileged read-only channel (`meshd-ro.sock` / `mesh-agent-ro`, max `4 KiB`).
    AgentReadOnly,
}

impl IpcChannelKind {
    /// Returns the default OS socket/pipe endpoint path for this IPC channel.
    #[must_use]
    pub const fn default_endpoint(self) -> &'static str {
        match self {
            Self::ServerAdmin => LINUX_SERVER_ADMIN_SOCKET,
            Self::AgentAdmin => {
                if cfg!(target_os = "windows") {
                    WINDOWS_AGENT_ADMIN_PIPE
                } else {
                    UNIX_AGENT_ADMIN_SOCKET
                }
            }
            Self::AgentReadOnly => {
                if cfg!(target_os = "windows") {
                    WINDOWS_AGENT_RO_PIPE
                } else {
                    UNIX_AGENT_RO_SOCKET
                }
            }
        }
    }

    /// Maximum HTTP-over-IPC request frame size permitted on this channel.
    #[must_use]
    pub const fn max_body_bytes(self) -> usize {
        match self {
            Self::AgentReadOnly => MAX_RO_IPC_BODY_BYTES,
            Self::ServerAdmin | Self::AgentAdmin => MAX_ADMIN_IPC_BODY_BYTES,
        }
    }
}

/// Verified OS caller identity extracted via kernel credential inspection (`SO_PEERCRED`,
/// `LOCAL_PEERCRED` + `getgrouplist`, or Windows Token SIDs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentity {
    /// Unix peer identity resolved via kernel peer credentials.
    Unix {
        /// Effective user ID.
        uid: u32,
        /// Primary group ID.
        primary_gid: u32,
        /// Full supplementary group list (e.g. `xucred.cr_groups` + `getgrouplist`).
        supplementary_gids: Vec<u32>,
        /// Target OS group GID authorized for `mesh-admin` (`None` if group missing on Linux).
        mesh_admin_gid: Option<u32>,
        /// `true` on macOS (enforcing BSD `admin` GID `80`).
        is_macos: bool,
    },
    /// Windows Named Pipe impersonated/token identity check (`BA` + `SY`).
    Windows {
        /// Whether caller holds Builtin Administrators (`S-1-5-32-544`).
        is_builtin_admin: bool,
        /// Whether caller is LocalSystem (`S-1-5-18`).
        is_local_system: bool,
        /// Principal SID string for structured audit logs (non-secret).
        principal: String,
    },
}

/// Authorized privilege level assigned to an IPC connection after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerPrivilege {
    /// Authorized administrator (`root`, `mesh-admin`, macOS `admin` GID 80, or Windows `BA`/`SY`).
    Admin {
        /// Non-secret caller identifier for audit logs.
        principal: String,
    },
    /// Local unprivileged user allowed strictly read-only status/peers/ping/netcheck queries.
    ReadOnly {
        /// Non-secret caller identifier for audit logs.
        principal: String,
    },
}

/// Authorization policy verifying whether a local IPC caller may access a channel.
pub trait PrivilegeIpc: Send + Sync + std::fmt::Debug {
    /// Evaluates `peer` credentials against `channel`, failing closed with `PermissionDenied`.
    fn authorize(&self, channel: IpcChannelKind, peer: &PeerIdentity)
    -> AppResult<CallerPrivilege>;
}

/// Fail-closed production credential evaluator enforcing `SEC-14`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPrivilegeIpc;

impl DefaultPrivilegeIpc {
    /// Creates the standard fail-closed IPC privilege policy evaluator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PrivilegeIpc for DefaultPrivilegeIpc {
    fn authorize(
        &self,
        channel: IpcChannelKind,
        peer: &PeerIdentity,
    ) -> AppResult<CallerPrivilege> {
        let is_admin = match peer {
            PeerIdentity::Unix {
                uid,
                primary_gid,
                supplementary_gids,
                mesh_admin_gid,
                is_macos,
            } => {
                let is_root = *uid == 0;
                let has_gid = |target_gid: u32| {
                    *primary_gid == target_gid || supplementary_gids.contains(&target_gid)
                };
                let is_mesh_admin = mesh_admin_gid.is_some_and(has_gid);
                let is_macos_admin = *is_macos && has_gid(MACOS_ADMIN_GID);
                is_root || is_mesh_admin || is_macos_admin
            }
            PeerIdentity::Windows {
                is_builtin_admin,
                is_local_system,
                ..
            } => *is_builtin_admin || *is_local_system,
        };

        let principal = match peer {
            PeerIdentity::Unix {
                uid, primary_gid, ..
            } => format!("unix:uid={uid},gid={primary_gid}"),
            PeerIdentity::Windows { principal, .. } => principal.clone(),
        };

        match channel {
            IpcChannelKind::AgentReadOnly => Ok(if is_admin {
                CallerPrivilege::Admin { principal }
            } else {
                CallerPrivilege::ReadOnly { principal }
            }),
            IpcChannelKind::ServerAdmin | IpcChannelKind::AgentAdmin => {
                if is_admin {
                    Ok(CallerPrivilege::Admin { principal })
                } else {
                    Err(AppError::permission_denied(
                        "operation requires administrator/root or mesh-admin privileges",
                    ))
                }
            }
        }
    }
}

/// Deterministic in-memory [`PrivilegeIpc`] delegating to [`DefaultPrivilegeIpc`] for unit tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakePrivilegeIpc {
    inner: DefaultPrivilegeIpc,
}

impl FakePrivilegeIpc {
    /// Creates a fake IPC privilege checker using the production fail-closed policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: DefaultPrivilegeIpc::new(),
        }
    }
}

impl PrivilegeIpc for FakePrivilegeIpc {
    fn authorize(
        &self,
        channel: IpcChannelKind,
        peer: &PeerIdentity,
    ) -> AppResult<CallerPrivilege> {
        self.inner.authorize(channel, peer)
    }
}

/// Explicit OS socket/pipe authentication policy differentiating server & dual agent channels (`SEC-14`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixSocketAuthPolicy {
    /// Server Admin UDS (`/run/mesh-server/admin.sock`) allowing `root`, `mesh`, and `allowed_group`.
    ServerAdmin {
        /// Administrative Unix group name (default `"mesh-admin"`).
        allowed_group: String,
    },
    /// Agent privileged control channel (`meshd-admin.sock` / `mesh-agent-admin`).
    AgentAdmin,
    /// Agent unprivileged read-only channel (`meshd-ro.sock` / `mesh-agent-ro`, max `4 KiB`).
    AgentReadOnly,
}

impl UnixSocketAuthPolicy {
    /// Maps this authentication policy to the corresponding [`IpcChannelKind`].
    #[must_use]
    pub const fn channel(&self) -> IpcChannelKind {
        match self {
            Self::ServerAdmin { .. } => IpcChannelKind::ServerAdmin,
            Self::AgentAdmin => IpcChannelKind::AgentAdmin,
            Self::AgentReadOnly => IpcChannelKind::AgentReadOnly,
        }
    }
}

/// Verifies local OS peer credentials against [`UnixSocketAuthPolicy`].
pub trait IpcPeerVerifier: Send + Sync + std::fmt::Debug {
    /// Evaluates caller `peer` against `policy`, failing closed with `PermissionDenied`.
    fn verify_peer(
        &self,
        policy: &UnixSocketAuthPolicy,
        peer: &PeerIdentity,
    ) -> AppResult<CallerPrivilege>;
}

/// In-memory & fail-closed [`IpcPeerVerifier`] backed by [`DefaultPrivilegeIpc`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeIpcPeerVerifier {
    inner: DefaultPrivilegeIpc,
}

impl FakeIpcPeerVerifier {
    /// Creates a [`FakeIpcPeerVerifier`] instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: DefaultPrivilegeIpc::new(),
        }
    }
}

impl IpcPeerVerifier for FakeIpcPeerVerifier {
    fn verify_peer(
        &self,
        policy: &UnixSocketAuthPolicy,
        peer: &PeerIdentity,
    ) -> AppResult<CallerPrivilege> {
        self.inner.authorize(policy.channel(), peer)
    }
}

fn build_ipc_http_request<Req: Serialize>(
    method: Method,
    path: &str,
    body: Option<&Req>,
) -> AppResult<Request<Body>> {
    let payload = match body {
        Some(val) => serde_json::to_vec(val).map_err(|err| {
            AppError::invalid_argument(format!("IPC JSON serialize error: {err}"))
        })?,
        None => Vec::new(),
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HeaderValue::from_static("localhost"))
        .header(header::CONNECTION, HeaderValue::from_static("close"));
    if !payload.is_empty() {
        builder = builder.header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    builder
        .body(Body::from(payload))
        .map_err(|err| AppError::invalid_argument(format!("invalid IPC HTTP request: {err}")))
}

fn map_ipc_error_response(status: StatusCode, raw_bytes: &[u8]) -> AppError {
    if let Ok(parsed) = serde_json::from_slice::<ErrorResponse>(raw_bytes) {
        return AppError::new(parsed.error.kind, parsed.error.message);
    }
    if status == StatusCode::UNAUTHORIZED {
        AppError::unauthenticated("IPC peer returned 401")
    } else if status == StatusCode::FORBIDDEN {
        AppError::permission_denied("IPC peer denied permission")
    } else if status == StatusCode::NOT_FOUND {
        AppError::not_found("IPC endpoint not found")
    } else {
        AppError::unavailable(format!("IPC endpoint returned HTTP {status}"))
    }
}

/// Classifies a local UDS / Named Pipe connect `std::io::Error` into `ServiceUnavailable`,
/// `PermissionDenied`, or `BusyRetryable` (`DGUI-IPC-05`).
#[must_use]
pub fn classify_ipc_io_error_kind(err: &std::io::Error) -> IpcConnectFailureKind {
    match err.raw_os_error() {
        Some(WIN_ERROR_PIPE_BUSY) => IpcConnectFailureKind::BusyRetryable,
        Some(WIN_ERROR_ACCESS_DENIED) => IpcConnectFailureKind::PermissionDenied,
        Some(WIN_ERROR_FILE_NOT_FOUND | WIN_ERROR_SERVICE_DOES_NOT_EXIST) => {
            IpcConnectFailureKind::ServiceUnavailable
        }
        _ => match err.kind() {
            std::io::ErrorKind::PermissionDenied => IpcConnectFailureKind::PermissionDenied,
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                IpcConnectFailureKind::ServiceUnavailable
            }
            #[cfg(unix)]
            _ if err.raw_os_error() == Some(13) => IpcConnectFailureKind::PermissionDenied,
            _ => IpcConnectFailureKind::ServiceUnavailable,
        },
    }
}

/// Maps a local IPC connect failure onto `AppError` (`PermissionDenied` vs `Unavailable`).
#[must_use]
pub fn map_ipc_connect_error(endpoint: &str, is_admin: bool, err: &std::io::Error) -> AppError {
    match classify_ipc_io_error_kind(err) {
        IpcConnectFailureKind::PermissionDenied => {
            let role = if is_admin {
                "administrator / admin-group privileges"
            } else {
                "local IPC access permissions"
            };
            AppError::permission_denied(format!(
                "permission denied accessing meshd IPC endpoint {endpoint}: requires {role}"
            ))
        }
        IpcConnectFailureKind::BusyRetryable => AppError::unavailable(format!(
            "meshd daemon is busy (timed out opening {endpoint})"
        )),
        IpcConnectFailureKind::ServiceUnavailable => {
            AppError::unavailable(format!("meshd daemon is not running ({endpoint}: {err})"))
        }
    }
}

/// Attempts local IPC stream connection with bounded backoff retries on Windows
/// `ERROR_PIPE_BUSY (231)` inside `budget` (capped at `IPC_CONNECT_BUDGET_CAP = 1_000 ms`).
pub async fn connect_with_pipe_busy_retry<F, Fut, S>(
    endpoint: &str,
    is_admin: bool,
    budget: Duration,
    mut attempt: F,
) -> AppResult<S>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<S>>,
{
    let capped = budget.min(IPC_CONNECT_BUDGET_CAP);
    let deadline = tokio::time::Instant::now() + capped;
    let mut step_idx = 0_usize;

    loop {
        let now = tokio::time::Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            return Err(AppError::unavailable(format!(
                "meshd daemon is not running (timed out connecting to {endpoint})"
            )));
        };
        if remaining.is_zero() {
            return Err(AppError::unavailable(format!(
                "meshd daemon is not running (timed out connecting to {endpoint})"
            )));
        }

        match tokio::time::timeout(remaining, attempt()).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => {
                if classify_ipc_io_error_kind(&err) == IpcConnectFailureKind::BusyRetryable {
                    let post_attempt_rem = deadline
                        .checked_duration_since(tokio::time::Instant::now())
                        .unwrap_or(Duration::ZERO);
                    if post_attempt_rem.is_zero() {
                        return Err(AppError::unavailable(format!(
                            "meshd daemon is busy (busy pipe timeout on {endpoint})"
                        )));
                    }
                    let delay_ms = PIPE_BUSY_BACKOFF_MS.get(step_idx).copied().unwrap_or(100);
                    step_idx = step_idx.saturating_add(1);
                    let wait = Duration::from_millis(delay_ms).min(post_attempt_rem);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                return Err(map_ipc_connect_error(endpoint, is_admin, &err));
            }
            Err(_) => {
                return Err(AppError::unavailable(format!(
                    "meshd daemon is not running (timed out connecting to {endpoint})"
                )));
            }
        }
    }
}

/// Connects to a local Unix Domain Socket enforcing Tier 1 `IPC_CONNECT_TIMEOUT` (`850 ms`).
#[cfg(unix)]
pub async fn connect_agent_unix_socket(
    endpoint: &str,
    is_admin: bool,
) -> AppResult<tokio::net::UnixStream> {
    match tokio::time::timeout(
        IPC_CONNECT_TIMEOUT,
        tokio::net::UnixStream::connect(endpoint),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(map_ipc_connect_error(endpoint, is_admin, &err)),
        Err(_) => Err(AppError::unavailable(format!(
            "meshd daemon is not running (timed out connecting to {endpoint})"
        ))),
    }
}

/// Connects to a Windows Named Pipe with bounded `ERROR_PIPE_BUSY (231)` retries inside
/// Tier 1 `IPC_CONNECT_TIMEOUT` (`850 ms`).
#[cfg(windows)]
pub async fn connect_agent_named_pipe(
    pipe_name: &str,
    is_admin: bool,
) -> AppResult<tokio::net::windows::named_pipe::NamedPipeClient> {
    connect_with_pipe_busy_retry(pipe_name, is_admin, IPC_CONNECT_TIMEOUT, || async {
        tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name)
    })
    .await
}

/// Classifies the running daemon's version from `X-Mesh-Agent-Version` and `GET /v1/agent/version`,
/// treating `v0.1.0-rc1` (`404 NotFound` + missing header) as [`AgentVersionStatus::LegacyPre030`].
pub fn classify_agent_version_probe(
    header_version: Option<&str>,
    version_endpoint_result: AppResult<AgentVersionResponse>,
) -> AppResult<AgentVersionStatus> {
    if let Some(ver) = header_version.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(AgentVersionStatus::Version(ver.to_owned()));
    }
    match version_endpoint_result {
        Ok(resp) => {
            let trimmed = resp.agent_version.trim();
            if trimmed.is_empty() {
                Ok(AgentVersionStatus::LegacyPre030)
            } else {
                Ok(AgentVersionStatus::Version(trimmed.to_owned()))
            }
        }
        Err(err) if err.kind() == mesh_core::ErrorKind::NotFound => {
            Ok(AgentVersionStatus::LegacyPre030)
        }
        Err(err) => Err(err),
    }
}

/// Classifies offline `meshd --version` probe output (`exit 2` on `v0.1.0-rc1` -> `LegacyPre030`,
/// `MED-DGUI-G2-01`).
pub fn classify_cli_version_probe_exit_code(
    exit_code: Option<i32>,
    stdout: &str,
) -> AppResult<AgentVersionStatus> {
    match exit_code {
        Some(0) => {
            let token = stdout.split_whitespace().last().unwrap_or("").trim();
            if token.is_empty() {
                Ok(AgentVersionStatus::LegacyPre030)
            } else {
                Ok(AgentVersionStatus::Version(token.to_owned()))
            }
        }
        Some(2) => Ok(AgentVersionStatus::LegacyPre030),
        _ => Err(AppError::unavailable(
            "failed probing offline daemon binary version",
        )),
    }
}

fn extract_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|val| val.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Sends a single JSON HTTP/1.1 request over an established local IPC stream (`UDS` / Named Pipe / duplex)
/// enforcing a hard `max_response_bytes` cap and preserving remote [`ErrorKind`] mappings (`BLK-04`).
pub async fn send_ipc_json_request<S, Req, Resp>(
    io: S,
    method: Method,
    path: &str,
    body: Option<&Req>,
    max_response_bytes: usize,
) -> AppResult<Resp>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Req: Serialize,
    Resp: DeserializeOwned,
{
    send_ipc_json_request_with_timeout(
        io,
        method,
        path,
        body,
        max_response_bytes,
        IPC_ADMIN_MUTATION_TIMEOUT,
    )
    .await
}

/// Sends a single JSON HTTP/1.1 request over local IPC enforcing both `max_response_bytes` and
/// a strict end-to-end `io_timeout` (Tier 2 `2_000 ms` vs Tier 3 `10_000..=35_000 ms`, `ADR-024`).
pub async fn send_ipc_json_request_with_timeout<S, Req, Resp>(
    io: S,
    method: Method,
    path: &str,
    body: Option<&Req>,
    max_response_bytes: usize,
    io_timeout: Duration,
) -> AppResult<Resp>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let resp =
        send_ipc_json_with_meta(io, method, path, body, max_response_bytes, io_timeout).await?;
    Ok(resp.body)
}

/// Sends a single JSON HTTP/1.1 request over local IPC returning both the parsed payload and
/// `X-Mesh-Agent-Version` response metadata (`ADR-024`).
pub async fn send_ipc_json_with_meta<S, Req, Resp>(
    io: S,
    method: Method,
    path: &str,
    body: Option<&Req>,
    max_response_bytes: usize,
    io_timeout: Duration,
) -> AppResult<IpcJsonResponse<Resp>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let req = build_ipc_http_request(method, path, body)?;
    let timed = tokio::time::timeout(io_timeout, async move {
        let (mut sender, conn) = hyper_client_http1::handshake(TokioIo::new(io))
            .await
            .map_err(|err| AppError::unavailable(format!("IPC HTTP handshake failed: {err}")))?;

        let mut req_fut = std::pin::pin!(async {
            let resp = sender
                .send_request(req)
                .await
                .map_err(|err| AppError::unavailable(format!("IPC HTTP request failed: {err}")))?;
            let status = resp.status();
            let agent_version = extract_header_string(resp.headers(), HEADER_MESH_AGENT_VERSION);
            let raw_bytes = to_bytes(Body::new(resp.into_body()), max_response_bytes)
                .await
                .map_err(|err| {
                    AppError::invalid_argument(format!(
                        "IPC response exceeded {max_response_bytes} bytes or failed reading: {err}"
                    ))
                })?;
            Ok::<_, AppError>((status, agent_version, raw_bytes))
        });
        let mut conn_fut = std::pin::pin!(conn);
        let mut conn_active = true;

        let (status, agent_version, raw_bytes) = loop {
            tokio::select! {
                res = &mut req_fut => break res?,
                conn_res = &mut conn_fut, if conn_active => {
                    conn_active = false;
                    if let Err(err) = conn_res {
                        return Err(AppError::unavailable(format!("IPC HTTP connection failed: {err}")));
                    }
                }
            }
        };

        if !status.is_success() {
            return Err(map_ipc_error_response(status, &raw_bytes));
        }

        let parsed = serde_json::from_slice(&raw_bytes)
            .map_err(|err| AppError::internal(format!("malformed JSON from IPC endpoint: {err}")))?;
        Ok(IpcJsonResponse {
            body: parsed,
            agent_version,
            status,
        })
    })
    .await;

    match timed {
        Ok(res) => res,
        Err(_) => Err(AppError::unavailable(format!(
            "IPC request `{path}` timed out after {} ms",
            io_timeout.as_millis()
        ))),
    }
}

/// Streams a redacted diagnostic `.tar` archive from `POST /v1/agent/bugreport/stream` (`<= 20 MiB`)
/// chunk-by-chunk without buffering the full archive in RAM (`ADR-023`, `DGUI-UX-07`).
pub async fn stream_ipc_bugreport<S, F>(
    io: S,
    total_timeout: Duration,
    chunk_idle_timeout: Duration,
    mut on_chunk: F,
) -> AppResult<StreamedBugreportMetadata>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut(&[u8]) -> AppResult<()>,
{
    let req = build_ipc_http_request::<()>(Method::POST, "/v1/agent/bugreport/stream", None)?;
    let started = Instant::now();

    let mut conn_io = TokioIo::new(io);
    let handshake_rem = total_timeout
        .checked_sub(started.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| AppError::unavailable("bugreport stream timed out before handshake"))?;

    let (mut sender, conn) = match tokio::time::timeout(
        handshake_rem,
        hyper_client_http1::handshake(&mut conn_io),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(err)) => {
            return Err(AppError::unavailable(format!(
                "IPC bugreport stream handshake failed: {err}"
            )));
        }
        Err(_) => {
            return Err(AppError::unavailable(
                "IPC bugreport stream handshake timed out",
            ));
        }
    };

    let mut conn_fut = std::pin::pin!(conn);
    let mut conn_active = true;

    let hdr_rem = total_timeout
        .checked_sub(started.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| AppError::unavailable("bugreport stream timed out waiting for headers"))?;
    let resp = {
        let mut send_fut = std::pin::pin!(tokio::time::timeout(hdr_rem, sender.send_request(req)));
        loop {
            tokio::select! {
                res = &mut send_fut => {
                    match res {
                        Ok(Ok(resp)) => break resp,
                        Ok(Err(err)) => {
                            return Err(AppError::unavailable(format!(
                                "IPC bugreport stream request failed: {err}"
                            )));
                        }
                        Err(_) => {
                            return Err(AppError::unavailable(
                                "IPC bugreport stream timed out waiting for response headers",
                            ));
                        }
                    }
                }
                conn_res = &mut conn_fut, if conn_active => {
                    conn_active = false;
                    if let Err(err) = conn_res {
                        return Err(AppError::unavailable(format!(
                            "IPC bugreport stream connection closed: {err}"
                        )));
                    }
                }
            }
        }
    };

    let status = resp.status();
    let agent_version = extract_header_string(resp.headers(), HEADER_MESH_AGENT_VERSION);
    let archive_hdr = extract_header_string(resp.headers(), HEADER_MESH_ARCHIVE_BYTES)
        .or_else(|| extract_header_string(resp.headers(), header::CONTENT_LENGTH.as_str()));
    let scrubbed_hdr = extract_header_string(resp.headers(), HEADER_MESH_SCRUBBED_ITEMS);

    if !status.is_success() {
        let err_rem = total_timeout
            .checked_sub(started.elapsed())
            .unwrap_or_else(|| Duration::from_millis(1));
        let err_bytes = tokio::time::timeout(
            err_rem,
            to_bytes(Body::new(resp.into_body()), MAX_ADMIN_IPC_BODY_BYTES),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
        return Err(map_ipc_error_response(status, &err_bytes));
    }

    let max_bytes = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX);
    let expected_total_bytes: u64 = archive_hdr
        .as_deref()
        .ok_or_else(|| {
            AppError::invalid_argument(
                "bugreport stream missing X-Mesh-Archive-Bytes / Content-Length header",
            )
        })?
        .parse()
        .map_err(|_| AppError::invalid_argument("invalid bugreport stream byte length header"))?;
    if expected_total_bytes == 0 || expected_total_bytes > max_bytes {
        return Err(AppError::invalid_argument(format!(
            "bugreport archive size {expected_total_bytes} outside allowed 1..={max_bytes} bytes"
        )));
    }

    let scrubbed_items: u32 = match scrubbed_hdr {
        Some(raw) => raw.parse().map_err(|_| {
            AppError::invalid_argument("invalid X-Mesh-Scrubbed-Items header in bugreport stream")
        })?,
        None => 0,
    };

    let mut body = resp.into_body();
    let mut cumulative_bytes: u64 = 0;

    loop {
        let Some(total_rem) = total_timeout.checked_sub(started.elapsed()) else {
            return Err(AppError::unavailable(
                "bugreport stream exceeded total IPC timeout",
            ));
        };
        if total_rem.is_zero() {
            return Err(AppError::unavailable(
                "bugreport stream exceeded total IPC timeout",
            ));
        }
        let step_timeout = chunk_idle_timeout.min(total_rem);

        let next_frame = {
            let mut frame_fut = std::pin::pin!(tokio::time::timeout(
                step_timeout,
                std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)),
            ));
            loop {
                tokio::select! {
                    res = &mut frame_fut => break res,
                    conn_res = &mut conn_fut, if conn_active => {
                        conn_active = false;
                        if let Err(err) = conn_res {
                            return Err(AppError::unavailable(format!(
                                "bugreport stream connection error: {err}"
                            )));
                        }
                    }
                }
            }
        };

        let frame_opt = match next_frame {
            Ok(opt) => opt,
            Err(_) => {
                return Err(AppError::unavailable(
                    "bugreport stream stalled waiting for next chunk",
                ));
            }
        };
        let Some(frame_res) = frame_opt else {
            break;
        };
        let frame = frame_res.map_err(|err| {
            AppError::unavailable(format!("bugreport stream body read error: {err}"))
        })?;
        if let Ok(data) = frame.into_data() {
            for chunk in data.chunks(MAX_ADMIN_IPC_BODY_BYTES) {
                if chunk.is_empty() {
                    continue;
                }
                let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                let next_total = cumulative_bytes
                    .checked_add(chunk_len)
                    .ok_or_else(|| AppError::invalid_argument("bugreport stream size overflow"))?;
                if next_total > expected_total_bytes || next_total > max_bytes {
                    return Err(AppError::invalid_argument(
                        "bugreport stream exceeded declared archive size",
                    ));
                }
                on_chunk(chunk)?;
                cumulative_bytes = next_total;
            }
        }
    }

    if cumulative_bytes == 0
        || cumulative_bytes != expected_total_bytes
        || cumulative_bytes > max_bytes
    {
        return Err(AppError::unavailable(format!(
            "bugreport stream truncated: received {cumulative_bytes} of {expected_total_bytes} bytes"
        )));
    }

    Ok(StreamedBugreportMetadata {
        total_bytes: cumulative_bytes,
        scrubbed_items,
        agent_version,
    })
}

/// Serves a single local HTTP/1.1 connection over UDS / Named Pipe / duplex using an `axum::Router`.
pub async fn serve_ipc_http_connection<S>(io: S, router: Router) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(router);
    hyper_server_http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .await
        .map_err(|err| AppError::unavailable(format!("IPC HTTP server connection failed: {err}")))
}

#[cfg(test)]
mod tests {
    use axum::http::Method;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use mesh_core::defaults::{MACOS_ADMIN_GID, MAX_RO_IPC_BODY_BYTES};
    use mesh_core::error::{ErrorEnvelope, ErrorKind, ErrorResponse};
    use serde::{Deserialize, Serialize};

    use super::{
        CallerPrivilege, FakeIpcPeerVerifier, FakePrivilegeIpc, IpcChannelKind, IpcPeerVerifier,
        PeerIdentity, PrivilegeIpc, UnixSocketAuthPolicy, send_ipc_json_request,
        serve_ipc_http_connection,
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct EchoDto {
        msg: String,
    }

    #[test]
    fn test_ipc_macos_admin_gid_80_and_fail_closed_non_admin() {
        // Arrange
        let ipc = FakePrivilegeIpc::new();
        let macos_admin = PeerIdentity::Unix {
            uid: 501,
            primary_gid: 20,
            supplementary_gids: vec![20, MACOS_ADMIN_GID],
            mesh_admin_gid: None,
            is_macos: true,
        };
        let macos_standard = PeerIdentity::Unix {
            uid: 502,
            primary_gid: 20,
            supplementary_gids: vec![20],
            mesh_admin_gid: None,
            is_macos: true,
        };

        // Act
        let admin_res = ipc.authorize(IpcChannelKind::AgentAdmin, &macos_admin);
        let denied_res = ipc.authorize(IpcChannelKind::AgentAdmin, &macos_standard);
        let ro_res = ipc.authorize(IpcChannelKind::AgentReadOnly, &macos_standard);

        // Assert
        assert!(matches!(admin_res, Ok(CallerPrivilege::Admin { .. })));
        assert!(matches!(
            denied_res,
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied
        ));
        assert!(matches!(ro_res, Ok(CallerPrivilege::ReadOnly { .. })));
        assert_eq!(
            IpcChannelKind::AgentReadOnly.max_body_bytes(),
            MAX_RO_IPC_BODY_BYTES
        );
    }

    #[test]
    fn test_ipc_linux_mesh_admin_and_windows_builtin_admin_rules() {
        // Arrange
        let ipc = FakePrivilegeIpc::new();
        let linux_mesh_admin = PeerIdentity::Unix {
            uid: 1001,
            primary_gid: 1001,
            supplementary_gids: vec![998],
            mesh_admin_gid: Some(998),
            is_macos: false,
        };
        let linux_other = PeerIdentity::Unix {
            uid: 1002,
            primary_gid: 1002,
            supplementary_gids: vec![1002],
            mesh_admin_gid: Some(998),
            is_macos: false,
        };
        let win_standard = PeerIdentity::Windows {
            is_builtin_admin: false,
            is_local_system: false,
            principal: "S-1-5-21-1001".to_owned(),
        };
        let win_admin = PeerIdentity::Windows {
            is_builtin_admin: true,
            is_local_system: false,
            principal: "S-1-5-32-544".to_owned(),
        };

        // Assert
        assert!(
            ipc.authorize(IpcChannelKind::ServerAdmin, &linux_mesh_admin)
                .is_ok()
        );
        assert!(
            ipc.authorize(IpcChannelKind::ServerAdmin, &linux_other)
                .is_err()
        );
        assert!(
            ipc.authorize(IpcChannelKind::AgentAdmin, &win_standard)
                .is_err()
        );
        assert!(
            ipc.authorize(IpcChannelKind::AgentAdmin, &win_admin)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_ipc_http_json_roundtrip_policy_and_error_mapping() {
        // Arrange
        let verifier = FakeIpcPeerVerifier::new();
        let policy = UnixSocketAuthPolicy::ServerAdmin {
            allowed_group: "mesh-admin".to_owned(),
        };
        let non_admin = PeerIdentity::Unix {
            uid: 1002,
            primary_gid: 1002,
            supplementary_gids: vec![1002],
            mesh_admin_gid: Some(998),
            is_macos: false,
        };
        assert_eq!(
            verifier
                .verify_peer(&policy, &non_admin)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::PermissionDenied)
        );

        let router = Router::new()
            .route(
                "/v1/test/echo",
                post(|Json(body): Json<EchoDto>| async move { Json(body) }),
            )
            .route(
                "/v1/test/denied",
                get(|| async {
                    let body = ErrorResponse {
                        error: ErrorEnvelope {
                            kind: ErrorKind::PermissionDenied,
                            code: "E_PERM_DENIED".to_owned(),
                            message: "forbidden".to_owned(),
                            request_id: "req_1".to_owned(),
                        },
                    };
                    (axum::http::StatusCode::FORBIDDEN, Json(body))
                }),
            );

        // Act: happy roundtrip over in-memory duplex
        let (client_io, server_io) = tokio::io::duplex(4096);
        let req_dto = EchoDto {
            msg: "hello-ipc".to_owned(),
        };
        let (srv_res, cli_res) = tokio::join!(
            serve_ipc_http_connection(server_io, router.clone()),
            send_ipc_json_request::<_, EchoDto, EchoDto>(
                client_io,
                Method::POST,
                "/v1/test/echo",
                Some(&req_dto),
                4096,
            )
        );

        // Error mapping roundtrip
        let (err_cli_io, err_srv_io) = tokio::io::duplex(4096);
        let (err_srv_res, err_cli_res) = tokio::join!(
            serve_ipc_http_connection(err_srv_io, router),
            send_ipc_json_request::<_, EchoDto, EchoDto>(
                err_cli_io,
                Method::GET,
                "/v1/test/denied",
                None,
                4096,
            )
        );

        // Assert
        assert!(srv_res.is_ok());
        assert_eq!(cli_res.ok(), Some(req_dto));
        assert!(err_srv_res.is_ok());
        assert!(err_cli_res.is_err());
        if let Err(err) = err_cli_res {
            assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        }
    }
}
