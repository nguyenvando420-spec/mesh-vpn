//! iOS outer socket options (`IP_BOUND_IF`, `IP_DONTFRAG`, `US-016`, `US-017`).

use std::ffi::CStr;
use std::io::Error;
use std::mem::size_of;
use std::os::fd::RawFd;

use crate::error::{SysError, SysResult};

/// Binds an outer UDP/TCP socket to a specific physical iOS interface index via `IP_BOUND_IF` /
/// `IPV6_BOUND_IF`.
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
    let optlen = libc::socklen_t::try_from(size_of::<libc::c_uint>()).map_err(|_| {
        SysError::io(
            "bind_socket_to_interface_index",
            Error::from_raw_os_error(libc::EINVAL),
        )
    })?;
    let (level, optname) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };

    // SAFETY: `fd` is validated non-negative and `raw_idx` points to a valid `c_uint` on the stack
    // for the synchronous `setsockopt` syscall.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            (&raw const raw_idx).cast::<libc::c_void>(),
            optlen,
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

/// Disables forced IPv4 `DF=1` (`IP_DONTFRAG = 0`) on outer iOS transport sockets (`US-016`, `US-017`).
pub fn disable_ipv4_dont_fragment(fd: RawFd) -> SysResult<()> {
    validate_fd(fd, "disable_ipv4_dont_fragment")?;
    let disabled: libc::c_int = 0;
    let optlen = libc::socklen_t::try_from(size_of::<libc::c_int>()).map_err(|_| {
        SysError::io(
            "disable_ipv4_dont_fragment",
            Error::from_raw_os_error(libc::EINVAL),
        )
    })?;

    // SAFETY: `fd` is validated non-negative and `disabled` points to a valid `c_int` on the stack
    // for the synchronous `setsockopt` syscall.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_DONTFRAG,
            (&raw const disabled).cast::<libc::c_void>(),
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

fn ensure_interface_not_utun(if_index: u32, operation: &'static str) -> SysResult<()> {
    let mut name_buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `name_buf` is an initialized stack buffer of size `IF_NAMESIZE` matching `if_indextoname`.
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
    use crate::error::SysError;

    use super::{bind_socket_to_interface_index, disable_ipv4_dont_fragment};

    #[test]
    fn test_socket_ios_rejects_negative_fd_and_zero_interface_index() {
        // Arrange & Act
        let neg_bind = bind_socket_to_interface_index(-1, false, 1);
        let neg_df = disable_ipv4_dont_fragment(-1);
        let zero_idx = bind_socket_to_interface_index(0, true, 0);

        // Assert
        assert!(neg_bind.is_err());
        assert!(neg_df.is_err());
        assert!(matches!(
            zero_idx,
            Err(SysError::SecurityViolation {
                operation: "bind_socket_to_interface_index",
                ..
            })
        ));
    }
}
