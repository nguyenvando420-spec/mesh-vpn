//! macOS `getpeereid` + `LOCAL_PEERCRED` (`xucred.cr_groups`) + `getgrouplist` admin check (`WP-S1-02`).

use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};
use crate::fs_unix::UnixPeerCredentials;

/// Inspects macOS `getpeereid` / `LOCAL_PEERCRED` (`xucred`) and `getgrouplist` fallback on `fd`.
pub fn inspect_peer_creds(_fd: RawFd) -> SysResult<UnixPeerCredentials> {
    Err(SysError::NotImplemented("ipc_macos::inspect_peer_creds"))
}

/// Verifies `euid == 0` or `gid == 80` (`admin`) via `xucred` and `getgrouplist` fallback.
pub fn verify_admin_peer_cred(_fd: RawFd, _admin_gid: u32) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "ipc_macos::verify_admin_peer_cred",
    ))
}
