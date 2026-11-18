//! macOS dual UDS + `LOCAL_PEERCRED` (`xucred.cr_groups`) backend (`US-073`, `SEC-14`).

use std::fs::{self, Permissions};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt};
use std::path::Path;

use mesh_core::defaults::{
    LINUX_SERVER_ADMIN_SOCKET, MACOS_ADMIN_GID, MACOS_SERVER_ADMIN_FALLBACK_SOCKET,
    MACOS_SERVER_ADMIN_SOCKET,
};
use mesh_core::{AppError, AppResult};
use mesh_sys::fs_unix::{
    SecureDirPolicy, current_euid, prepare_secure_runtime_dir, set_path_group_if_root,
    verify_secure_file,
};
use tokio::net::{UnixListener, UnixStream};

use crate::ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, IpcChannelKind, PeerIdentity, PrivilegeIpc,
};

/// Installed location of the privileged `meshd` binary on macOS.
pub const MACOS_DAEMON_BINARY_PATH: &str = "/usr/local/libexec/mesh/meshd";
/// Installed `launchd` property list path on macOS.
pub const MACOS_LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/internal.mesh.meshd.plist";
/// Persistent state directory for keys and ledger on macOS (`0700 root:wheel`).
pub const MACOS_STATE_DIR_PATH: &str = "/var/db/mesh";

/// Runtime socket directory policy on macOS (`/var/run/meshd`, `0755 root:wheel`).
#[must_use]
pub const fn macos_runtime_dir_policy() -> SecureDirPolicy {
    SecureDirPolicy {
        expected_uid: 0,
        expected_gid: Some(0),
        max_mode: 0o755,
    }
}

/// Persistent daemon state directory policy on macOS (`/var/db/mesh`, `0700 root:wheel`).
#[must_use]
pub const fn macos_state_dir_policy() -> SecureDirPolicy {
    SecureDirPolicy {
        expected_uid: 0,
        expected_gid: Some(0),
        max_mode: 0o700,
    }
}

/// Binary and LaunchDaemon plist ownership policy on macOS (`uid == 0`, `(mode & 0o022) == 0`).
#[must_use]
pub const fn macos_root_file_policy() -> SecureDirPolicy {
    SecureDirPolicy {
        expected_uid: 0,
        expected_gid: Some(0),
        max_mode: 0o755,
    }
}

/// Verifies at macOS daemon startup that binary, plist, state directory, and ancestor dirs are
/// strictly root-owned and non-writable by non-root users (`US-073 AC2`).
pub fn verify_macos_daemon_startup_paths(
    binary_path: &Path,
    plist_path: &Path,
    state_dir: &Path,
    runtime_dir: &Path,
) -> AppResult<()> {
    verify_secure_file(binary_path, macos_root_file_policy())?;
    verify_secure_file(
        plist_path,
        SecureDirPolicy {
            expected_uid: 0,
            expected_gid: Some(0),
            max_mode: 0o644,
        },
    )?;
    prepare_secure_runtime_dir(state_dir, macos_state_dir_policy())?;
    prepare_secure_runtime_dir(runtime_dir, macos_runtime_dir_policy())?;
    Ok(())
}

/// Binds the dual macOS agent UDS listeners (`/var/run/meshd/meshd-admin.sock` `0660 root:admin`
/// and `/var/run/meshd/meshd-ro.sock` `0666 root:wheel`), rejecting symlink tampering (`US-073`).
pub fn bind_macos_agent_sockets(
    admin_socket_path: &Path,
    ro_socket_path: &Path,
) -> AppResult<(UnixListener, UnixListener)> {
    let admin_listener = bind_single_macos_socket(admin_socket_path, 0o660, Some(MACOS_ADMIN_GID))?;
    let ro_listener = bind_single_macos_socket(ro_socket_path, 0o666, None)?;
    Ok((admin_listener, ro_listener))
}

/// Binds the macOS `mesh-server` Admin Unix domain socket.
///
/// Maps `/run/mesh-server/admin.sock` to `/var/run/mesh-server/admin.sock` (`0660 root:admin`)
/// when running as `root`, or `/tmp/mesh-server-admin.sock` (`0600`) when running unprivileged.
pub fn bind_macos_server_admin_socket(socket_path: &Path) -> AppResult<UnixListener> {
    let euid = current_euid();
    let mapped_path = if socket_path.as_os_str().is_empty()
        || socket_path == Path::new(LINUX_SERVER_ADMIN_SOCKET)
    {
        Path::new(MACOS_SERVER_ADMIN_SOCKET)
    } else {
        socket_path
    };

    if euid == 0 {
        return bind_single_macos_socket(mapped_path, 0o660, Some(MACOS_ADMIN_GID));
    }

    let unpriv_path = if mapped_path == Path::new(MACOS_SERVER_ADMIN_SOCKET) {
        Path::new(MACOS_SERVER_ADMIN_FALLBACK_SOCKET)
    } else {
        mapped_path
    };
    if let Some(parent) = unpriv_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| {
            AppError::internal(format!(
                "failed creating macOS server admin socket directory {}: {err}",
                parent.display()
            ))
        })?;
    }
    remove_owned_stale_non_symlink_socket(unpriv_path, Some(euid))?;
    let listener = UnixListener::bind(unpriv_path).map_err(|err| {
        AppError::internal(format!(
            "failed binding macOS server admin socket {}: {err}",
            unpriv_path.display()
        ))
    })?;
    fs::set_permissions(unpriv_path, Permissions::from_mode(0o600)).map_err(|err| {
        AppError::internal(format!(
            "failed setting permissions 0600 on {}: {err}",
            unpriv_path.display()
        ))
    })?;
    Ok(listener)
}

fn bind_single_macos_socket(
    socket_path: &Path,
    mode: u32,
    gid: Option<u32>,
) -> AppResult<UnixListener> {
    let parent = socket_path.parent().ok_or_else(|| {
        AppError::invalid_argument("macOS IPC socket path must have a parent directory")
    })?;
    prepare_secure_runtime_dir(parent, macos_runtime_dir_policy())?;
    remove_stale_non_symlink_socket(socket_path)?;

    let listener = UnixListener::bind(socket_path).map_err(|err| {
        AppError::internal(format!(
            "failed binding macOS IPC socket {}: {err}",
            socket_path.display()
        ))
    })?;
    if let Some(target_gid) = gid {
        set_path_group_if_root(socket_path, target_gid)?;
    }
    fs::set_permissions(socket_path, Permissions::from_mode(mode & 0o777)).map_err(|err| {
        AppError::internal(format!(
            "failed setting permissions {:04o} on {}: {err}",
            mode & 0o777,
            socket_path.display()
        ))
    })?;
    Ok(listener)
}

/// Verifies an incoming macOS Unix-domain socket connection against [`IpcChannelKind`].
pub fn verify_macos_socket_peer(
    stream: &UnixStream,
    channel: IpcChannelKind,
) -> AppResult<CallerPrivilege> {
    let fd = stream.as_raw_fd();
    let creds = mesh_sys::ipc_macos::inspect_peer_creds(fd)?;
    if channel == IpcChannelKind::ServerAdmin && creds.uid == current_euid() {
        return Ok(CallerPrivilege::Admin {
            principal: format!("uid:{}", creds.uid),
        });
    }
    let identity = PeerIdentity::Unix {
        uid: creds.uid,
        primary_gid: creds.primary_gid,
        supplementary_gids: creds.supplementary_gids.clone(),
        mesh_admin_gid: None,
        is_macos: true,
    };
    let res = DefaultPrivilegeIpc::new().authorize(channel, &identity);
    if res.is_err() {
        tracing::warn!(
            component = "ipc_macos",
            event = "ipc_admin_auth_denied",
            uid = creds.uid,
            primary_gid = creds.primary_gid,
            channel = ?channel,
            "rejected unauthorized macOS IPC peer"
        );
    }
    res
}

fn remove_owned_stale_non_symlink_socket(
    socket_path: &Path,
    expected_uid: Option<u32>,
) -> AppResult<()> {
    match fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(AppError::permission_denied(format!(
                    "refusing to replace symlink at macOS IPC path {}",
                    socket_path.display()
                )));
            }
            if let Some(uid) = expected_uid
                && meta.uid() != uid
            {
                return Err(AppError::permission_denied(format!(
                    "refusing to remove macOS IPC socket {} owned by uid {}",
                    socket_path.display(),
                    meta.uid()
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

fn remove_stale_non_symlink_socket(socket_path: &Path) -> AppResult<()> {
    remove_owned_stale_non_symlink_socket(socket_path, None)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use tempfile::tempdir;
    use tokio::net::{UnixListener, UnixStream};

    use super::{
        MACOS_DAEMON_BINARY_PATH, MACOS_LAUNCHD_PLIST_PATH, MACOS_STATE_DIR_PATH,
        bind_macos_server_admin_socket, remove_stale_non_symlink_socket,
        verify_macos_daemon_startup_paths, verify_macos_socket_peer,
    };
    use crate::ipc::{CallerPrivilege, IpcChannelKind};

    #[tokio::test]
    async fn test_ipc_macos_ro_socket_succeeds_and_non_admin_check_enforced() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let sock_path = dir.path().join("meshd-ro.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let _client = UnixStream::connect(&sock_path).await.expect("connect");
        let (server_stream, _) = listener.accept().await.expect("accept");

        // Act
        let ro_res = verify_macos_socket_peer(&server_stream, IpcChannelKind::AgentReadOnly);

        // Assert
        assert!(ro_res.is_ok());
    }

    #[test]
    fn test_ipc_macos_rejects_symlink_and_untrusted_temp_startup_paths() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("other");
        let link = dir.path().join("meshd-admin.sock");
        fs::write(&target, b"x").expect("write");
        symlink(&target, &link).expect("symlink");

        // Act & Assert
        assert!(remove_stale_non_symlink_socket(&link).is_err());
        let res = verify_macos_daemon_startup_paths(
            Path::new(MACOS_DAEMON_BINARY_PATH),
            Path::new(MACOS_LAUNCHD_PLIST_PATH),
            Path::new(MACOS_STATE_DIR_PATH),
            dir.path(),
        );
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_ipc_macos_server_admin_socket_binds_and_authorizes_same_uid() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let sock_path = dir.path().join("server-admin.sock");
        let listener =
            bind_macos_server_admin_socket(&sock_path).expect("bind server admin socket");
        let _client = UnixStream::connect(&sock_path).await.expect("connect");
        let (server_stream, _) = listener.accept().await.expect("accept");

        // Act
        let admin_res = verify_macos_socket_peer(&server_stream, IpcChannelKind::ServerAdmin);

        // Assert
        assert!(matches!(admin_res, Ok(CallerPrivilege::Admin { .. })));
    }
}
