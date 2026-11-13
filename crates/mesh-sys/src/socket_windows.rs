//! Windows `IP_UNICAST_IF` / `IPV6_UNICAST_IF` and `IP_DONTFRAGMENT` socket controls (`REL-09`, `WP-S1-04`).

use std::os::windows::io::RawSocket;

use crate::error::{SysError, SysResult};

/// Binds an outbound socket directly to physical interface index `if_index` via WinSock setsockopt.
pub fn bind_socket_to_interface_index(
    _socket: RawSocket,
    _is_ipv6: bool,
    _if_index: u32,
) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "socket_windows::bind_socket_to_interface_index",
    ))
}

/// Clears forced IPv4 Don't Fragment (`IP_DONTFRAGMENT = 0`) via WinSock setsockopt (`WP-S1-04`).
pub fn disable_ipv4_dont_fragment(_socket: RawSocket) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "socket_windows::disable_ipv4_dont_fragment",
    ))
}
