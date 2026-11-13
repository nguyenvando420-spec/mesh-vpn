//! Windows Named Pipe creation with `FILE_FLAG_FIRST_PIPE_INSTANCE` and explicit SDDL (`WP-S1-04`).

use std::os::windows::io::{OwnedHandle, RawHandle};

use crate::error::{SysError, SysResult};

/// Named Pipe security ACL tier matching `api-design.md` §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeAclMode {
    /// Read-only pipe (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)`).
    ReadOnly,
    /// Privileged Admin pipe (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`).
    Admin,
}

/// Verified Windows Named Pipe client token flags (`S-1-5-32-544` BA and `S-1-5-18` SY).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPeerCredentials {
    /// Caller holds Builtin Administrators (`BA`).
    pub is_builtin_admin: bool,
    /// Caller holds LocalSystem (`SY`).
    pub is_local_system: bool,
    /// Non-secret caller SID string for audit logs.
    pub principal: String,
}

/// Creates the first instance of a Windows Named Pipe enforcing the explicit SDDL DACL (`WP-S1-04`).
pub fn create_secured_named_pipe(_pipe_name: &str, _mode: PipeAclMode) -> SysResult<OwnedHandle> {
    Err(SysError::NotImplemented(
        "ipc_windows::create_secured_named_pipe",
    ))
}

/// Impersonates and inspects connected Named Pipe client token SIDs (`WP-S1-04`).
pub fn inspect_named_pipe_peer(_handle: RawHandle) -> SysResult<WindowsPeerCredentials> {
    Err(SysError::NotImplemented(
        "ipc_windows::inspect_named_pipe_peer",
    ))
}
