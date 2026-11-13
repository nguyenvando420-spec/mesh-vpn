//! Windows dual Named Pipes with explicit SDDL ACLs (`SY+BA` vs `SY+BA+AU`, `WP-S1-04`).

use std::os::windows::io::AsRawHandle as _;

use mesh_core::AppResult;
use tokio::net::windows::named_pipe::NamedPipeServer;

use crate::ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, IpcChannelKind, PeerIdentity, PrivilegeIpc,
};

/// Protected SDDL ACL restricting Admin Named Pipe strictly to LocalSystem (`SY`) and Builtin Admins (`BA`).
pub const ADMIN_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// Protected SDDL ACL allowing read-only IPC queries from Authenticated Users (`AU`) alongside `SY` and `BA`.
pub const RO_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// Verifies connected Named Pipe client credentials against [`IpcChannelKind`].
pub fn verify_named_pipe_peer(
    pipe: &NamedPipeServer,
    channel: IpcChannelKind,
) -> AppResult<CallerPrivilege> {
    let handle = pipe.as_raw_handle();
    let creds = mesh_sys::ipc_windows::inspect_named_pipe_peer(handle)?;
    let identity = PeerIdentity::Windows {
        is_builtin_admin: creds.is_builtin_admin,
        is_local_system: creds.is_local_system,
        principal: creds.principal,
    };
    DefaultPrivilegeIpc::new().authorize(channel, &identity)
}
