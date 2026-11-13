use std::ffi::CStr;
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::error::{SysError, SysResult};

/// Linux `TUNSETIFF` ioctl request code (`_IOW('T', 202, int)`).
const TUNSETIFF_IOCTL: libc::Ioctl = 0x4004_54ca_u32 as libc::Ioctl;
const MAX_IFNAME_LEN: usize = libc::IFNAMSIZ - 1;

#[repr(C)]
struct TunIfReq {
    ifr_name: [u8; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// Opens `/dev/net/tun` using `IFF_TUN | IFF_NO_PI` and non-blocking `O_CLOEXEC` flags,
/// returning `(ifname, raw_fd)`.
pub fn open_tun_device(preferred_name: Option<&str>) -> SysResult<(String, i32)> {
    let (name, owned_fd) = open_tun_owned(preferred_name)?;
    Ok((name, owned_fd.into_raw_fd()))
}

/// Opens `/dev/net/tun` returning an RAII [`OwnedFd`] alongside the kernel-assigned interface name.
pub fn open_tun_owned(preferred_name: Option<&str>) -> SysResult<(String, OwnedFd)> {
    if let Some(name) = preferred_name {
        validate_linux_ifname(name)?;
    }

    // SAFETY: `"/dev/net/tun\0"` is a static NUL-terminated path literal passed to `libc::open`.
    let raw_fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw_fd < 0 {
        return Err(SysError::io("open_tun_device", Error::last_os_error()));
    }

    // SAFETY: `raw_fd` was just returned as a valid owned file descriptor from `libc::open`.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut req = TunIfReq {
        ifr_name: [0u8; libc::IFNAMSIZ],
        ifr_flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
        _pad: [0u8; 22],
    };
    if let Some(name) = preferred_name {
        for (dst, src) in req.ifr_name.iter_mut().zip(name.as_bytes().iter()) {
            *dst = *src;
        }
    }

    // SAFETY: `owned_fd` is open and `req` is a `#[repr(C)]` `ifreq`-compatible struct on the stack.
    let rc = unsafe { libc::ioctl(owned_fd.as_raw_fd(), TUNSETIFF_IOCTL, &raw mut req) };
    if rc < 0 {
        return Err(SysError::io("open_tun_device", Error::last_os_error()));
    }

    let c_name =
        CStr::from_bytes_until_nul(&req.ifr_name).map_err(|_| SysError::SecurityViolation {
            operation: "open_tun_device",
            detail: "kernel returned non-NUL-terminated interface name".to_owned(),
        })?;
    let assigned_name = c_name
        .to_str()
        .map_err(|_| SysError::SecurityViolation {
            operation: "open_tun_device",
            detail: "kernel returned non-UTF-8 interface name".to_owned(),
        })?
        .to_owned();
    validate_linux_ifname(&assigned_name)?;

    Ok((assigned_name, owned_fd))
}

/// Validates a Linux network interface name length and ASCII character set.
pub fn validate_linux_ifname(name: &str) -> SysResult<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IFNAME_LEN {
        return Err(SysError::SecurityViolation {
            operation: "validate_linux_ifname",
            detail: format!("invalid interface name length for '{name}'"),
        });
    }
    let valid_chars = bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if !valid_chars {
        return Err(SysError::SecurityViolation {
            operation: "validate_linux_ifname",
            detail: format!("interface name '{name}' contains disallowed characters"),
        });
    }
    Ok(())
}

/// Performs a single non-blocking `read(2)` from a Linux TUN descriptor.
pub fn read_tun_packet(fd: impl AsFd, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "empty TUN read buffer"));
    }
    let raw_fd = fd.as_fd().as_raw_fd();
    // SAFETY: `fd.as_fd()` guarantees an open descriptor and `buf` is writable for `buf.len()` bytes.
    let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n < 0 {
        return Err(Error::last_os_error());
    }
    Ok(n as usize)
}

/// Performs a single non-blocking `write(2)` to a Linux TUN descriptor.
pub fn write_tun_packet(fd: impl AsFd, buf: &[u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "empty TUN write packet",
        ));
    }
    let raw_fd = fd.as_fd().as_raw_fd();
    // SAFETY: `fd.as_fd()` guarantees an open descriptor and `buf` is readable for `buf.len()` bytes.
    let n = unsafe { libc::write(raw_fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
    if n < 0 {
        return Err(Error::last_os_error());
    }
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::{open_tun_owned, validate_linux_ifname};
    use crate::error::SysError;

    #[test]
    fn test_tun_linux_ifname_validation() {
        // Arrange & Act & Assert
        validate_linux_ifname("mesh0").expect("valid interface name");
        assert!(matches!(
            validate_linux_ifname(""),
            Err(SysError::SecurityViolation { .. })
        ));
        assert!(matches!(
            validate_linux_ifname("interface_name_over_15"),
            Err(SysError::SecurityViolation { .. })
        ));
        assert!(matches!(
            validate_linux_ifname("mesh/0"),
            Err(SysError::SecurityViolation { .. })
        ));
        assert!(matches!(
            validate_linux_ifname("mesh 0"),
            Err(SysError::SecurityViolation { .. })
        ));
    }

    #[test]
    #[ignore = "privileged"]
    fn test_tun_linux_open_with_cap_net_admin() {
        // Arrange & Act
        let (ifname, _fd) = open_tun_owned(Some("mesh0")).expect("open /dev/net/tun");

        // Assert
        assert!(ifname.starts_with("mesh"));
    }
}
