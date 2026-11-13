//! Linux `SO_PEERCRED` + `getpwuid_r` / `getgrouplist` admin socket verification (`SEC-14`, `WP-S1-03`).

use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};
use crate::fs_unix::UnixPeerCredentials;

/// Inspects kernel `SO_PEERCRED` credentials and supplementary groups (`getgrouplist`) on `fd`.
pub fn inspect_peer_creds(_fd: RawFd) -> SysResult<UnixPeerCredentials> {
    Err(SysError::NotImplemented("ipc_linux::inspect_peer_creds"))
}

/// Resolves an OS group name (e.g. `"mesh-admin"`) to its numeric GID if present.
pub fn resolve_group_gid(_group_name: &str) -> SysResult<Option<u32>> {
    Err(SysError::NotImplemented("ipc_linux::resolve_group_gid"))
}

/// Verifies that the Unix socket peer belongs to `root`, `service_uid`, or `admin_gid`
/// including supplementary group membership via `getgrouplist` (`api-design.md` §4).
pub fn verify_admin_peer_cred(
    _fd: RawFd,
    _service_uid: u32,
    _admin_gid: Option<u32>,
) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "ipc_linux::verify_admin_peer_cred",
    ))
}
