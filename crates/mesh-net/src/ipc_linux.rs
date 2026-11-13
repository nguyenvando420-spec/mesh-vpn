//! Linux dual UDS + `SO_PEERCRED` + `getgrouplist` backend (implemented in `WP-S1-03`).

use std::os::fd::AsRawFd as _;

use mesh_core::AppResult;
use tokio::net::UnixStream;

use crate::ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, IpcChannelKind, PeerIdentity, PrivilegeIpc,
};

/// Verifies an incoming Linux Unix-domain socket connection against [`IpcChannelKind`].
pub fn verify_unix_socket_peer(
    stream: &UnixStream,
    channel: IpcChannelKind,
    admin_group_name: Option<&str>,
) -> AppResult<CallerPrivilege> {
    let fd = stream.as_raw_fd();
    let creds = mesh_sys::ipc_linux::inspect_peer_creds(fd)?;
    let mesh_admin_gid = match admin_group_name {
        Some(group_name) => mesh_sys::ipc_linux::resolve_group_gid(group_name)?,
        None => None,
    };
    let identity = PeerIdentity::Unix {
        uid: creds.uid,
        primary_gid: creds.primary_gid,
        supplementary_gids: creds.supplementary_gids,
        mesh_admin_gid,
        is_macos: false,
    };
    DefaultPrivilegeIpc::new().authorize(channel, &identity)
}
