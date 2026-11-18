//! Windows dual Named Pipes with explicit SDDL ACLs (`SY+BA` vs `SY+BA+AU`, `WP-S1-04`).

use std::os::windows::io::AsHandle as _;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use mesh_core::{AppError, AppResult, ErrorKind};
use mesh_sys::ipc_windows::{PipeAclMode, SecuredPipeServer, inspect_named_pipe_peer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio_util::sync::CancellationToken;

use crate::ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, IpcChannelKind, PeerIdentity, PrivilegeIpc,
    serve_ipc_http_connection,
};

/// Protected SDDL ACL restricting Admin Named Pipe strictly to LocalSystem (`SY`) and Builtin Admins (`BA`).
pub const ADMIN_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// Protected SDDL ACL allowing read-only IPC queries from Authenticated Users (`AU`) alongside `SY` and `BA`.
pub const RO_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

const PIPE_STREAM_BUFFER: usize = 16 * 1024;
const GRACEFUL_SHUTDOWN_SECS: u64 = 5;

/// Maps [`IpcChannelKind`] to Windows Named Pipe SDDL tier.
#[must_use]
pub const fn pipe_acl_mode_for_channel(channel: IpcChannelKind) -> PipeAclMode {
    match channel {
        IpcChannelKind::AgentReadOnly => PipeAclMode::ReadOnly,
        IpcChannelKind::AgentAdmin => PipeAclMode::Admin,
        IpcChannelKind::ServerAdmin => PipeAclMode::ServerAdmin,
    }
}

/// Verifies connected Named Pipe client credentials against [`IpcChannelKind`].
pub fn verify_named_pipe_peer(
    pipe: &NamedPipeServer,
    channel: IpcChannelKind,
) -> AppResult<CallerPrivilege> {
    let creds = inspect_named_pipe_peer(pipe.as_handle()).map_err(AppError::from)?;
    authorize_windows_creds(channel, creds)
}

/// Verifies a connected [`SecuredPipeServer`] against [`IpcChannelKind`].
pub fn verify_secured_pipe_peer(
    pipe: &SecuredPipeServer,
    channel: IpcChannelKind,
) -> AppResult<CallerPrivilege> {
    let creds = pipe.inspect_peer().map_err(AppError::from)?;
    authorize_windows_creds(channel, creds)
}

fn authorize_windows_creds(
    channel: IpcChannelKind,
    creds: mesh_sys::ipc_windows::WindowsPeerCredentials,
) -> AppResult<CallerPrivilege> {
    if matches!(channel, IpcChannelKind::ServerAdmin)
        && let Ok(owner_sid) = mesh_sys::ipc_windows::current_process_user_sid()
        && creds.principal == owner_sid
    {
        return Ok(CallerPrivilege::Admin {
            principal: creds.principal,
        });
    }
    let identity = PeerIdentity::Windows {
        is_builtin_admin: creds.is_builtin_admin,
        is_local_system: creds.is_local_system,
        principal: creds.principal,
    };
    DefaultPrivilegeIpc::new().authorize(channel, &identity)
}

/// Asynchronous Windows Named Pipe IPC server enforcing `FILE_FLAG_FIRST_PIPE_INSTANCE` and
/// explicit SDDL ACLs without using `unsafe` in `mesh-net`.
#[derive(Debug)]
pub struct WindowsIpcServer {
    pipe_name: String,
    channel: IpcChannelKind,
}

impl WindowsIpcServer {
    /// Constructs a server config targeting `pipe_name` with the SDDL matching `channel`.
    #[must_use]
    pub fn new(pipe_name: impl Into<String>, channel: IpcChannelKind) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            channel,
        }
    }

    /// Binds initial pipe instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`) and serves HTTP/JSON IPC
    /// until `shutdown` triggers graceful exit within 5 seconds.
    pub async fn serve(&self, router: Router, shutdown: CancellationToken) -> AppResult<()> {
        let mode = pipe_acl_mode_for_channel(self.channel);
        let first_pipe =
            Arc::new(SecuredPipeServer::bind(&self.pipe_name, mode, true).map_err(AppError::from)?);
        self.serve_with_initial(first_pipe, router, shutdown).await
    }

    /// Runs the accept loop starting from an already-bound initial pipe instance.
    pub async fn serve_with_initial(
        &self,
        initial_pipe: Arc<SecuredPipeServer>,
        router: Router,
        shutdown: CancellationToken,
    ) -> AppResult<()> {
        let mode = pipe_acl_mode_for_channel(self.channel);
        let mut next_pipe = Some(initial_pipe);
        let mut tasks = tokio::task::JoinSet::new();

        loop {
            if shutdown.is_cancelled() {
                break;
            }
            let current = match next_pipe.take() {
                Some(existing) => existing,
                None => Arc::new(
                    SecuredPipeServer::bind(&self.pipe_name, mode, false)
                        .map_err(AppError::from)?,
                ),
            };

            let accept_handle = Arc::clone(&current);
            let mut accept_task =
                tokio::task::spawn_blocking(move || accept_handle.accept_blocking());
            let accepted = tokio::select! {
                () = shutdown.cancelled() => {
                    current.cancel_io();
                    let _drained = accept_task.await;
                    break;
                }
                res = &mut accept_task => {
                    res.map_err(|err| AppError::internal(format!("pipe accept task panic: {err}")))?
                }
            };

            if let Err(err) = accepted {
                if shutdown.is_cancelled() {
                    break;
                }
                tracing::warn!(
                    target: "mesh::net::ipc_windows",
                    pipe = %self.pipe_name,
                    error = %err,
                    "Named Pipe accept failed"
                );
                continue;
            }

            let channel = self.channel;
            let conn_router = router.clone();
            let conn_shutdown = shutdown.child_token();
            tasks.spawn(async move {
                if let Err(err) =
                    handle_connected_pipe(current, channel, conn_router, conn_shutdown).await
                {
                    tracing::debug!(
                        target: "mesh::net::ipc_windows",
                        error = %err,
                        "Named Pipe IPC connection closed"
                    );
                }
            });
        }

        let drain_budget = Duration::from_secs(GRACEFUL_SHUTDOWN_SECS);
        let _timed = tokio::time::timeout(drain_budget, async {
            while let Some(res) = tasks.join_next().await {
                if let Err(err) = res {
                    tracing::warn!(
                        target: "mesh::net::ipc_windows",
                        error = %err,
                        "Named Pipe worker join error during shutdown"
                    );
                }
            }
        })
        .await;
        tasks.abort_all();
        Ok(())
    }
}

async fn handle_connected_pipe(
    pipe: Arc<SecuredPipeServer>,
    channel: IpcChannelKind,
    router: Router,
    shutdown: CancellationToken,
) -> AppResult<()> {
    let check_pipe = Arc::clone(&pipe);
    let _privilege =
        tokio::task::spawn_blocking(move || verify_secured_pipe_peer(&check_pipe, channel))
            .await
            .map_err(|err| AppError::internal(format!("pipe auth join error: {err}")))??;

    let (client_io, bridge_io) = duplex(PIPE_STREAM_BUFFER);
    let (mut bridge_reader, mut bridge_writer) = tokio::io::split(bridge_io);

    let read_pipe = Arc::clone(&pipe);
    let read_shutdown = shutdown.clone();
    let reader_task = tokio::task::spawn(async move {
        let mut buf = vec![0_u8; 4096];
        loop {
            if read_shutdown.is_cancelled() {
                read_pipe.cancel_io();
                break;
            }
            let p = Arc::clone(&read_pipe);
            let mut tmp = buf;
            let res = tokio::task::spawn_blocking(move || {
                let n = p.read_blocking(&mut tmp);
                (n, tmp)
            })
            .await;
            let Ok((read_res, returned)) = res else {
                break;
            };
            buf = returned;
            match read_res {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let Some(slice) = buf.get(..n) else {
                        break;
                    };
                    if bridge_writer.write_all(slice).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _closed = bridge_writer.shutdown().await;
    });

    let write_pipe = Arc::clone(&pipe);
    let writer_task = tokio::task::spawn(async move {
        let mut out_buf = vec![0_u8; 4096];
        loop {
            let Ok(n) = bridge_reader.read(&mut out_buf).await else {
                break;
            };
            if n == 0 {
                break;
            }
            let Some(chunk) = out_buf.get(..n) else {
                break;
            };
            let owned = chunk.to_vec();
            let p = Arc::clone(&write_pipe);
            let write_res = tokio::task::spawn_blocking(move || write_all_pipe(&p, &owned)).await;
            if !matches!(write_res, Ok(Ok(()))) {
                break;
            }
        }
    });

    let http_res = serve_ipc_http_connection(client_io, router).await;
    let _writer_drained = tokio::time::timeout(Duration::from_secs(2), writer_task).await;
    pipe.cancel_io();
    let _reader_done = tokio::time::timeout(Duration::from_secs(1), reader_task).await;

    if let Err(err) = http_res
        && err.kind() != ErrorKind::Unavailable
    {
        return Err(err);
    }
    Ok(())
}

fn write_all_pipe(pipe: &SecuredPipeServer, mut data: &[u8]) -> AppResult<()> {
    while !data.is_empty() {
        let written = pipe.write_blocking(data).map_err(AppError::from)?;
        if written == 0 {
            return Err(AppError::unavailable("Named Pipe closed during write"));
        }
        data = data.get(written..).unwrap_or(&[]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use axum::Router;
    use axum::routing::get;
    use mesh_core::ErrorKind;
    use mesh_sys::ipc_windows::{PipeAclMode, SecuredPipeServer};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio_util::sync::CancellationToken;

    use super::{
        ADMIN_PIPE_SDDL, IpcChannelKind, RO_PIPE_SDDL, WindowsIpcServer, authorize_windows_creds,
        pipe_acl_mode_for_channel,
    };
    use crate::ipc::CallerPrivilege;

    static NET_TEST_PIPE_SEQ: AtomicU64 = AtomicU64::new(1);

    fn unique_pipe_path(tag: &str) -> String {
        let seq = NET_TEST_PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\mesh-net-test-{tag}-{}-{seq}", std::process::id())
    }

    #[test]
    fn test_ipc_windows_sddl_mode_and_privilege_mapping() {
        // Arrange
        let unprivileged = mesh_sys::ipc_windows::WindowsPeerCredentials {
            is_builtin_admin: false,
            is_local_system: false,
            principal: "S-1-5-21-1001".to_owned(),
        };
        let admin = mesh_sys::ipc_windows::WindowsPeerCredentials {
            is_builtin_admin: true,
            is_local_system: false,
            principal: "S-1-5-32-544".to_owned(),
        };

        // Act
        let admin_denied =
            authorize_windows_creds(IpcChannelKind::AgentAdmin, unprivileged.clone());
        let ro_allowed = authorize_windows_creds(IpcChannelKind::AgentReadOnly, unprivileged);
        let admin_allowed = authorize_windows_creds(IpcChannelKind::AgentAdmin, admin);

        // Assert
        assert_eq!(
            pipe_acl_mode_for_channel(IpcChannelKind::AgentAdmin),
            PipeAclMode::Admin
        );
        assert_eq!(
            pipe_acl_mode_for_channel(IpcChannelKind::AgentReadOnly),
            PipeAclMode::ReadOnly
        );
        assert_eq!(ADMIN_PIPE_SDDL, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(RO_PIPE_SDDL, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)");
        assert!(matches!(
            admin_denied,
            Err(err) if err.kind() == ErrorKind::PermissionDenied
        ));
        assert!(matches!(ro_allowed, Ok(CallerPrivilege::ReadOnly { .. })));
        assert!(matches!(admin_allowed, Ok(CallerPrivilege::Admin { .. })));
    }

    #[tokio::test]
    async fn test_ipc_windows_server_first_instance_and_ro_http_roundtrip() {
        // Arrange
        let pipe_name = unique_pipe_path("ro-http");
        let first = SecuredPipeServer::bind(&pipe_name, PipeAclMode::ReadOnly, true);
        assert!(first.is_ok(), "initial bind failed: {first:?}");
        let Ok(first) = first else {
            return;
        };

        let duplicate = SecuredPipeServer::bind(&pipe_name, PipeAclMode::ReadOnly, true);
        assert!(
            duplicate.is_err(),
            "FILE_FLAG_FIRST_PIPE_INSTANCE must block duplicate"
        );

        let app = Router::new().route("/v1/status", get(|| async { "{\"ok\":true}" }));
        let server = WindowsIpcServer::new(pipe_name.clone(), IpcChannelKind::AgentReadOnly);
        let shutdown = CancellationToken::new();
        let srv_shutdown = shutdown.clone();
        let initial = Arc::new(first);
        let srv_task =
            tokio::spawn(
                async move { server.serve_with_initial(initial, app, srv_shutdown).await },
            );

        // Act
        let client = ClientOptions::new().open(&pipe_name);
        assert!(
            client.is_ok(),
            "client connect to ReadOnly test pipe failed: {client:?}"
        );
        let Ok(mut client) = client else {
            shutdown.cancel();
            return;
        };
        let req = b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        assert!(client.write_all(req).await.is_ok());
        let mut resp = Vec::new();
        let read_res =
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut resp)).await;

        shutdown.cancel();
        let srv_res = tokio::time::timeout(Duration::from_secs(3), srv_task).await;

        // Assert
        assert!(read_res.is_ok(), "HTTP response over Named Pipe timed out");
        let resp_text = String::from_utf8_lossy(&resp);
        assert!(
            resp_text.contains("200 OK"),
            "unexpected response: {resp_text}"
        );
        assert!(
            resp_text.contains("{\"ok\":true}"),
            "missing JSON body: {resp_text}"
        );
        assert!(srv_res.is_ok(), "WindowsIpcServer shutdown exceeded 3 s");
    }
}
