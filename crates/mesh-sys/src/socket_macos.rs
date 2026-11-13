//! macOS `IP_BOUND_IF` / `IPV6_BOUND_IF` and `IP_DONTFRAG` controls for routing-loop immunity (`REL-09`, `WP-S1-02`).

use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};

/// Binds an outbound socket directly to physical interface index `if_index`.
pub fn bind_socket_to_interface_index(_fd: RawFd, _is_ipv6: bool, _if_index: u32) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "socket_macos::bind_socket_to_interface_index",
    ))
}

/// Disables forced IPv4 Don't Fragment (`IP_DONTFRAG = 0`) on a BSD/macOS socket (`WP-S1-02`).
pub fn disable_ipv4_dont_fragment(_fd: RawFd) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "socket_macos::disable_ipv4_dont_fragment",
    ))
}
