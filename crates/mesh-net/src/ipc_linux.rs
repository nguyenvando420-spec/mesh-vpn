//! Linux dual UDS + `SO_PEERCRED` + `getgrouplist` backend (`WP-S1-03`, `US-056`, `SEC-14`).

use std::fs::{self, Permissions};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mesh_core::defaults::LINUX_ADMIN_GROUP_NAME;
use mesh_core::{AppError, AppResult};
use mesh_sys::fs_unix::{SecureDirPolicy, prepare_secure_runtime_dir, set_path_group_if_root};
use tokio::net::{UnixListener, UnixStream};

use crate::ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, IpcChannelKind, PeerIdentity, PrivilegeIpc,
};

/// Server-admin runtime directory policy on Linux (`/run/mesh-server`, `0750`).
#[must_use]
pub fn server_runtime_dir_policy(service_uid: u32, mesh_admin_gid: Option<u32>) -> SecureDirPolicy {
    SecureDirPolicy {
        expected_uid: service_uid,
        expected_gid: mesh_admin_gid,
        max_mode: 0o750,
    }
}

/// Agent daemon runtime directory policy on Linux (`/var/run/meshd`, `0755 root:root`).
#[must_use]
pub const fn agent_runtime_dir_policy() -> SecureDirPolicy {
    SecureDirPolicy {
        expected_uid: 0,
        expected_gid: Some(0),
        max_mode: 0o755,
    }
}

/// Binds a Linux Unix-domain socket inside a verified runtime directory and applies `socket_gid`
/// plus `socket_mode` (`0600`/`0660` for Admin, `0666` for ReadOnly), rejecting symlinks.
pub fn bind_linux_ipc_listener(
    socket_path: &Path,
    dir_policy: SecureDirPolicy,
    socket_mode: u32,
    socket_gid: Option<u32>,
) -> AppResult<UnixListener> {
    let parent = socket_path.parent().ok_or_else(|| {
        AppError::invalid_argument("Linux IPC socket path must have a parent directory")
    })?;
    prepare_secure_runtime_dir(parent, dir_policy)?;
    remove_stale_non_symlink_socket(socket_path)?;

    let listener = UnixListener::bind(socket_path).map_err(|err| {
        AppError::internal(format!(
            "failed binding Linux IPC socket {}: {err}",
            socket_path.display()
        ))
    })?;
    if let Some(gid) = socket_gid {
        set_path_group_if_root(socket_path, gid)?;
    }
    fs::set_permissions(socket_path, Permissions::from_mode(socket_mode & 0o777)).map_err(
        |err| {
            AppError::internal(format!(
                "failed setting mode {:04o} on {}: {err}",
                socket_mode & 0o777,
                socket_path.display()
            ))
        },
    )?;

    Ok(listener)
}

/// Returns recommended permissions (`0660` if `mesh-admin` group exists, `0600` otherwise)
/// for `/var/run/meshd/meshd-admin.sock`.
pub fn agent_admin_socket_mode(admin_group_name: Option<&str>) -> AppResult<u32> {
    let group_name = admin_group_name.unwrap_or(LINUX_ADMIN_GROUP_NAME);
    let gid = mesh_sys::ipc_linux::resolve_group_gid(group_name)?;
    Ok(if gid.is_some() { 0o660 } else { 0o600 })
}

/// Verifies an incoming Linux Unix-domain socket connection against [`IpcChannelKind`].
pub fn verify_unix_socket_peer(
    stream: &UnixStream,
    channel: IpcChannelKind,
    admin_group_name: Option<&str>,
) -> AppResult<CallerPrivilege> {
    let service_uid = mesh_sys::ipc_linux::current_euid();
    verify_unix_socket_peer_with_service_uid(stream, channel, service_uid, admin_group_name)
}

/// Verifies an incoming Linux UDS peer with explicit `service_uid` (`mesh` on VPS server, `0` on `meshd`).
pub fn verify_unix_socket_peer_with_service_uid(
    stream: &UnixStream,
    channel: IpcChannelKind,
    service_uid: u32,
    admin_group_name: Option<&str>,
) -> AppResult<CallerPrivilege> {
    let fd = stream.as_raw_fd();
    let creds = mesh_sys::ipc_linux::inspect_peer_creds(fd)?;
    let mesh_admin_gid = match admin_group_name {
        Some(group_name) => mesh_sys::ipc_linux::resolve_group_gid(group_name)?,
        None => None,
    };

    if matches!(channel, IpcChannelKind::ServerAdmin) && creds.uid == service_uid {
        let principal = format!("unix:uid={},gid={}", creds.uid, creds.primary_gid);
        return Ok(CallerPrivilege::Admin { principal });
    }

    let identity = PeerIdentity::Unix {
        uid: creds.uid,
        primary_gid: creds.primary_gid,
        supplementary_gids: creds.supplementary_gids.clone(),
        mesh_admin_gid,
        is_macos: false,
    };
    let result = DefaultPrivilegeIpc::new().authorize(channel, &identity);
    if result.is_err() {
        tracing::warn!(
            component = "ipc_linux",
            event = "ipc_admin_auth_denied",
            uid = creds.uid,
            primary_gid = creds.primary_gid,
            channel = ?channel,
            "rejected unauthorized Linux IPC peer"
        );
    }
    result
}

fn remove_stale_non_symlink_socket(socket_path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(AppError::permission_denied(format!(
                    "refusing to replace symlink at IPC socket path {}",
                    socket_path.display()
                )));
            }
            fs::remove_file(socket_path).map_err(|err| {
                AppError::internal(format!(
                    "failed removing stale socket {}: {err}",
                    socket_path.display()
                ))
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(AppError::internal(format!(
            "failed inspecting socket {}: {err}",
            socket_path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;
    use tokio::net::{UnixListener, UnixStream};

    use super::{
        remove_stale_non_symlink_socket, verify_unix_socket_peer,
        verify_unix_socket_peer_with_service_uid,
    };
    use crate::ipc::{CallerPrivilege, IpcChannelKind};

    #[tokio::test]
    async fn test_ipc_linux_server_admin_authorizes_service_uid_and_ro_allows_reader() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let sock_path = dir.path().join("admin.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let _client = UnixStream::connect(&sock_path).await.expect("connect");
        let (server_stream, _) = listener.accept().await.expect("accept");
        let euid = mesh_sys::ipc_linux::current_euid();

        // Act
        let priv_res = verify_unix_socket_peer(&server_stream, IpcChannelKind::ServerAdmin, None);
        let ro_res = verify_unix_socket_peer(&server_stream, IpcChannelKind::AgentReadOnly, None);

        // Assert
        assert!(matches!(priv_res, Ok(CallerPrivilege::Admin { .. })));
        assert!(ro_res.is_ok());
        if euid != 0 {
            let denied = verify_unix_socket_peer_with_service_uid(
                &server_stream,
                IpcChannelKind::AgentAdmin,
                0,
                None,
            );
            assert!(denied.is_err());
        }
    }

    #[test]
    fn test_ipc_linux_rejects_symlink_at_socket_path() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("other");
        let link = dir.path().join("meshd-admin.sock");
        fs::write(&target, b"placeholder").expect("write");
        symlink(&target, &link).expect("symlink");

        // Act
        let res = remove_stale_non_symlink_socket(&link);

        // Assert
        assert!(res.is_err());
    }
}
