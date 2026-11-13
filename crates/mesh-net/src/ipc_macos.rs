//! macOS dual UDS + `LOCAL_PEERCRED` (`xucred.cr_groups`) backend (implemented in `WP-S1-02`).

use std::os::fd::AsRawFd as _;

use mesh_core::AppResult;
use tokio::net::UnixStream;

use crate::ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, IpcChannelKind, PeerIdentity, PrivilegeIpc,
};

/// Verifies an incoming macOS Unix-domain socket connection against [`IpcChannelKind`].
pub fn verify_macos_socket_peer(
    stream: &UnixStream,
    channel: IpcChannelKind,
) -> AppResult<CallerPrivilege> {
    let fd = stream.as_raw_fd();
    let creds = mesh_sys::ipc_macos::inspect_peer_creds(fd)?;
    let identity = PeerIdentity::Unix {
        uid: creds.uid,
        primary_gid: creds.primary_gid,
        supplementary_gids: creds.supplementary_gids,
        mesh_admin_gid: None,
        is_macos: true,
    };
    DefaultPrivilegeIpc::new().authorize(channel, &identity)
}
