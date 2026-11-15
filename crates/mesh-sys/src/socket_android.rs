//! Android outer socket options (`US-016`, `US-017`, `ADR-014`).

use std::io::Error;
use std::mem::size_of;
use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};

/// Disables forced IPv4 `DF=1` on outer Android transport sockets via `IP_MTU_DISCOVER = IP_PMTUDISC_DONT`.
///
/// Android anti-routing-loop uses `VpnService.protect(fd)` (`SocketProtector`) rather than `SO_MARK`.
pub fn disable_ipv4_dont_fragment(fd: RawFd) -> SysResult<()> {
    if fd < 0 {
        return Err(SysError::io(
            "disable_ipv4_dont_fragment",
            Error::from_raw_os_error(libc::EBADF),
        ));
    }
    let policy: libc::c_int = libc::IP_PMTUDISC_DONT;

    // SAFETY: `fd` is validated non-negative and `policy` points to a stack `c_int`
    // valid for the synchronous `setsockopt` syscall.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&raw const policy).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(SysError::io(
            "disable_ipv4_dont_fragment",
            Error::last_os_error(),
        ));
    }
    Ok(())
}
