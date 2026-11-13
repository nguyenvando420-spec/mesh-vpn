use std::ffi::CStr;
use std::io::Error;
use std::mem::size_of;
use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};

/// Binds an outer UDP/TCP socket to a specific physical macOS interface index via `IP_BOUND_IF`
/// or `IPV6_BOUND_IF` (`US-016` anti-routing-loop Layer 1).
///
/// Refuses index `0` and any `utun*` virtual tunnel interface to prevent overlay encapsulation loops.
pub fn bind_socket_to_interface_index(fd: RawFd, is_ipv6: bool, if_index: u32) -> SysResult<()> {
    validate_fd(fd, "bind_socket_to_interface_index")?;
    if if_index == 0 {
        return Err(SysError::SecurityViolation {
            operation: "bind_socket_to_interface_index",
            detail: "refusing to bind outer socket to interface index 0".to_owned(),
        });
    }

    ensure_interface_not_utun(if_index, "bind_socket_to_interface_index")?;

    let raw_idx: libc::c_uint = if_index;
    let (level, optname) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };

    // SAFETY: `fd` is validated non-negative and `raw_idx` points to a valid `c_uint` on the stack
    // for the duration of the synchronous `setsockopt` call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            (&raw const raw_idx).cast::<libc::c_void>(),
            size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(SysError::io(
            "bind_socket_to_interface_index",
            Error::last_os_error(),
        ));
    }

    Ok(())
}

/// Disables forced IPv4 `DF=1` (`IP_DONTFRAG = 0`) on outer transport sockets (`US-016`, `US-017`).
pub fn disable_ipv4_dont_fragment(fd: RawFd) -> SysResult<()> {
    validate_fd(fd, "disable_ipv4_dont_fragment")?;
    let disabled: libc::c_int = 0;

    // SAFETY: `fd` is validated non-negative and `disabled` points to a valid `c_int` on the stack
    // for the duration of the synchronous `setsockopt` call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_DONTFRAG,
            (&raw const disabled).cast::<libc::c_void>(),
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

fn ensure_interface_not_utun(if_index: u32, operation: &'static str) -> SysResult<()> {
    let mut name_buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `name_buf` is an initialized stack buffer of size `IF_NAMESIZE` (16 bytes on macOS),
    // which matches the contract of POSIX `if_indextoname`.
    let ptr = unsafe { libc::if_indextoname(if_index, name_buf.as_mut_ptr()) };
    if ptr.is_null() {
        return Ok(());
    }

    // SAFETY: Non-null return from `if_indextoname` guarantees `name_buf` contains a valid
    // NUL-terminated interface name within `IF_NAMESIZE` bytes.
    let c_name = unsafe { CStr::from_ptr(ptr) };
    let name = c_name.to_string_lossy();
    if name.starts_with("utun") {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!("refusing to bind outer socket to tunnel interface '{name}'"),
        });
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

    use super::{bind_socket_to_interface_index, disable_ipv4_dont_fragment};
    use crate::error::SysError;

    #[test]
    fn test_socket_macos_invalid_fd_and_zero_if_index_rejected() {
        // Arrange
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp socket");

        // Act & Assert
        assert!(matches!(
            bind_socket_to_interface_index(-1, false, 1),
            Err(SysError::Io { .. })
        ));
        assert!(matches!(
            bind_socket_to_interface_index(socket.as_raw_fd(), false, 0),
            Err(SysError::SecurityViolation { .. })
        ));
        assert!(matches!(
            disable_ipv4_dont_fragment(-1),
            Err(SysError::Io { .. })
        ));
    }

    #[test]
    fn test_socket_macos_disable_dont_fragment_clears_ip_dontfrag() {
        // Arrange
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp socket");
        let fd = socket.as_raw_fd();

        // Act
        disable_ipv4_dont_fragment(fd).expect("clear IP_DONTFRAG");

        // Assert
        let mut observed: libc::c_int = -1;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `fd` is open and `observed`/`len` point to valid writable stack locals.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_DONTFRAG,
                (&raw mut observed).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(observed, 0);
    }

    #[test]
    fn test_socket_macos_bind_loopback_if_index() {
        // Arrange
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp socket");
        // SAFETY: `"lo0\0"` is a static NUL-terminated C string.
        let lo_idx = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        if lo_idx == 0 {
            return;
        }

        // Act & Assert
        bind_socket_to_interface_index(socket.as_raw_fd(), false, lo_idx)
            .expect("bind IPv4 socket to lo0");
    }
}
