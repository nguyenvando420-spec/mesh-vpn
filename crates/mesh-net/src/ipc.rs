//! Local IPC channel classification, fail-closed peer privilege authorization (`SEC-14`),
//! and bounded HTTP-over-IPC JSON transport helpers (`BLK-04`).

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use hyper::client::conn::http1 as hyper_client_http1;
use hyper::server::conn::http1 as hyper_server_http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use mesh_core::defaults::{
    LINUX_SERVER_ADMIN_SOCKET, MACOS_ADMIN_GID, MAX_ADMIN_IPC_BODY_BYTES, MAX_RO_IPC_BODY_BYTES,
    UNIX_AGENT_ADMIN_SOCKET, UNIX_AGENT_RO_SOCKET, WINDOWS_AGENT_ADMIN_PIPE, WINDOWS_AGENT_RO_PIPE,
};
use mesh_core::error::ErrorResponse;
use mesh_core::{AppError, AppResult};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};

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
    } else {
        AppError::unavailable(format!("IPC endpoint returned HTTP {status}"))
    }
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
    let req = build_ipc_http_request(method, path, body)?;
    let (mut sender, conn) = hyper_client_http1::handshake(TokioIo::new(io))
        .await
        .map_err(|err| AppError::unavailable(format!("IPC HTTP handshake failed: {err}")))?;

    let mut req_fut = std::pin::pin!(async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|err| AppError::unavailable(format!("IPC HTTP request failed: {err}")))?;
        let status = resp.status();
        let raw_bytes = to_bytes(Body::new(resp.into_body()), max_response_bytes)
            .await
            .map_err(|err| {
                AppError::invalid_argument(format!(
                    "IPC response exceeded {max_response_bytes} bytes or failed reading: {err}"
                ))
            })?;
        Ok::<_, AppError>((status, raw_bytes))
    });
    let mut conn_fut = std::pin::pin!(conn);
    let mut conn_active = true;

    let (status, raw_bytes) = loop {
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

    serde_json::from_slice(&raw_bytes)
        .map_err(|err| AppError::internal(format!("malformed JSON from IPC endpoint: {err}")))
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
