//! Unix filesystem ownership, mode, and symlink-traversal hardening helpers (`SEC-14`).

use std::path::Path;

use crate::error::{SysError, SysResult};

/// Expected Unix runtime directory ownership and permission mask policy (`SEC-14`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureDirPolicy {
    /// Expected owner UID (`0` for `root`, or service account UID such as `mesh`).
    pub expected_uid: u32,
    /// Optional required owning group GID (`Some(gid)` for `/run/mesh-server`).
    pub expected_gid: Option<u32>,
    /// Maximum allowed Unix permission mask (e.g., `0o750` or `0o755`).
    pub max_mode: u32,
}

/// Verified Unix domain socket peer identity extracted via kernel credentials and group lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixPeerCredentials {
    /// Effective caller user ID.
    pub uid: u32,
    /// Primary caller group ID.
    pub primary_gid: u32,
    /// Supplementary group IDs discovered via `LOCAL_PEERCRED` / `getgrouplist`.
    pub supplementary_gids: Vec<u32>,
}

/// Verifies directory ancestry contains no symlinks and matches [`SecureDirPolicy`] (`WP-S1-01..03`).
pub fn verify_secure_runtime_dir(_path: &Path, _policy: SecureDirPolicy) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "fs_unix::verify_secure_runtime_dir",
    ))
}

/// Ensures `path` exists with strict ownership and permissions matching [`SecureDirPolicy`] (`WP-S1-01..03`).
pub fn prepare_secure_runtime_dir(_path: &Path, _policy: SecureDirPolicy) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "fs_unix::prepare_secure_runtime_dir",
    ))
}
