//! Linux `SO_MARK` and IP MTU discovery socket controls for routing-loop immunity (`REL-09`, `WP-S1-03`).

use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};

/// Marks an outbound socket with `fwmark` (`0x5d56`) to bypass overlay table `51820`.
pub fn set_socket_fwmark(_fd: RawFd, _fwmark: u32) -> SysResult<()> {
    Err(SysError::NotImplemented("socket_linux::set_socket_fwmark"))
}

/// Clears forced Don't Fragment (`IP_MTU_DISCOVER = IP_PMTUDISC_DONT`) on an IPv4 socket (`WP-S1-03`).
pub fn disable_ipv4_dont_fragment(_fd: RawFd) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "socket_linux::disable_ipv4_dont_fragment",
    ))
}
