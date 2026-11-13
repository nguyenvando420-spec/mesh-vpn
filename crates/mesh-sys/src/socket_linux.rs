use std::io::Error;
use std::mem::size_of;
use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};

/// Applies `SO_MARK` on a Linux outer UDP/TCP socket to bypass the overlay routing table (`51820`).
pub fn set_socket_fwmark(fd: RawFd, fwmark: u32) -> SysResult<()> {
    validate_fd(fd, "set_socket_fwmark")?;
    let raw_mark: libc::c_uint = fwmark;

    // SAFETY: `fd` is validated non-negative and `raw_mark` points to a stack `c_uint`
    // valid for the duration of the synchronous `setsockopt` syscall.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const raw_mark).cast::<libc::c_void>(),
            size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(SysError::io("set_socket_fwmark", Error::last_os_error()));
    }

    Ok(())
}

/// Disables forced IPv4 `DF=1` (`IP_PMTUDISC_DO`) on outer transport sockets by switching
/// `IP_MTU_DISCOVER` to `IP_PMTUDISC_WANT` so fragmented/NAT paths can succeed (`US-016`, `US-017`).
pub fn disable_ipv4_dont_fragment(fd: RawFd) -> SysResult<()> {
    validate_fd(fd, "disable_ipv4_dont_fragment")?;
    let policy: libc::c_int = libc::IP_PMTUDISC_WANT;

    // SAFETY: `fd` is validated non-negative and `policy` points to a stack `c_int`
    // valid for the duration of the synchronous `setsockopt` syscall.
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

fn validate_fd(fd: RawFd, operation: &'static str) -> SysResult<()> {
    if fd < 0 {
        return Err(SysError::io(
            operation,
            Error::from_raw_os_error(libc::EBADF),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use mesh_core::defaults::LINUX_FWMARK;

    use super::{disable_ipv4_dont_fragment, set_socket_fwmark};
    use crate::error::SysError;

    #[test]
    fn test_socket_linux_invalid_fd_rejected() {
        // Arrange & Act
        let res_mark = set_socket_fwmark(-1, LINUX_FWMARK);
        let res_df = disable_ipv4_dont_fragment(-1);

        // Assert
        assert!(matches!(res_mark, Err(SysError::Io { .. })));
        assert!(matches!(res_df, Err(SysError::Io { .. })));
    }

    #[test]
    fn test_socket_linux_disable_dont_fragment_sets_pmtudisc_want() {
        // Arrange
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp socket");
        let fd = socket.as_raw_fd();

        // Act
        disable_ipv4_dont_fragment(fd).expect("set IP_PMTUDISC_WANT");

        // Assert
        let mut observed: libc::c_int = -1;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `fd` is an open socket and `observed`/`len` are valid writable stack pointers.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                (&raw mut observed).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(observed, libc::IP_PMTUDISC_WANT);
    }

    #[test]
    #[ignore = "privileged"]
    fn test_socket_linux_set_fwmark_with_cap_net_admin() {
        // Arrange
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp socket");

        // Act
        set_socket_fwmark(socket.as_raw_fd(), LINUX_FWMARK).expect("apply SO_MARK");

        // Assert
        let mut observed: libc::c_uint = 0;
        let mut len = size_of::<libc::c_uint>() as libc::socklen_t;
        // SAFETY: `socket` is open and `observed`/`len` point to writable stack locals.
        let rc = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&raw mut observed).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(observed, LINUX_FWMARK);
    }
}
