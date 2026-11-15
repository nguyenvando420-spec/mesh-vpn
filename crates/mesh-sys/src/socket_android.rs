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
    let optlen = libc::socklen_t::try_from(size_of::<libc::c_int>()).map_err(|_| {
        SysError::io(
            "disable_ipv4_dont_fragment",
            Error::from_raw_os_error(libc::EINVAL),
        )
    })?;

    // SAFETY: `fd` is validated non-negative and `policy` points to a stack `c_int`
    // valid for the synchronous `setsockopt` syscall.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&raw const policy).cast::<libc::c_void>(),
            optlen,
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

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    use super::disable_ipv4_dont_fragment;

    #[test]
    fn test_socket_android_disable_df_rejects_negative_fd_and_accepts_udp_socket() {
        // Arrange
        // SAFETY: Creating a local unbound IPv4 UDP socket takes no pointers.
        let sock_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(sock_fd >= 0);
        // SAFETY: `sock_fd` was just checked non-negative as a newly created socket descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(sock_fd) };

        // Act
        let neg_res = disable_ipv4_dont_fragment(-1);
        let ok_res = disable_ipv4_dont_fragment(owned.as_raw_fd());

        // Assert
        assert!(neg_res.is_err());
        assert!(ok_res.is_ok());
    }
}
