use std::ffi::CStr;
use std::io::{self, Error, ErrorKind};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::error::{SysError, SysResult};

const UTUN_CONTROL_NAME_BYTES: &[u8] = b"com.apple.net.utun_control";
const UTUN_PREFIX: &str = "utun";
const AF_INET_BE: [u8; 4] = (libc::AF_INET as u32).to_be_bytes();
const AF_INET6_BE: [u8; 4] = (libc::AF_INET6 as u32).to_be_bytes();

/// Opens a macOS `utunN` kernel control tunnel socket (`PF_SYSTEM`/`SYSPROTO_CONTROL`)
/// and returns `(utunN, raw_fd)`.
pub fn open_utun_device(unit_hint: Option<u32>) -> SysResult<(String, i32)> {
    let (name, owned_fd) = open_utun_owned(unit_hint)?;
    Ok((name, owned_fd.into_raw_fd()))
}

/// Opens a macOS `utunN` kernel control tunnel socket returning an RAII [`OwnedFd`].
///
/// When `unit_hint` is `None`, the kernel dynamically allocates the next free `utunN` unit
/// without disturbing existing system or third-party `utun` interfaces (`US-060`).
pub fn open_utun_owned(unit_hint: Option<u32>) -> SysResult<(String, OwnedFd)> {
    // SAFETY: Creating a `PF_SYSTEM` `SYSPROTO_CONTROL` datagram socket requires no pointer arguments.
    let raw_fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw_fd < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }

    // SAFETY: `raw_fd` was just returned as a valid owned file descriptor from `libc::socket`.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    configure_cloexec_and_nonblock(&owned_fd)?;

    let ctl_id = resolve_utun_control_id(&owned_fd)?;
    connect_utun_control(&owned_fd, ctl_id, unit_hint)?;
    let ifname = query_utun_ifname(&owned_fd)?;
    validate_utun_name(&ifname)?;

    Ok((ifname, owned_fd))
}

/// Validates that an interface name strictly matches macOS `utun[0-9]+`.
pub fn validate_utun_name(name: &str) -> SysResult<()> {
    let Some(suffix) = name.strip_prefix(UTUN_PREFIX) else {
        return Err(SysError::SecurityViolation {
            operation: "validate_utun_name",
            detail: format!("interface '{name}' is not a macOS utun device"),
        });
    };
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SysError::SecurityViolation {
            operation: "validate_utun_name",
            detail: format!("invalid macOS utun unit suffix in '{name}'"),
        });
    }
    Ok(())
}

/// Encodes the 4-byte network-byte-order `AF_INET`/`AF_INET6` header required by macOS `utun`.
pub fn encode_utun_family_header(payload: &[u8]) -> Option<[u8; 4]> {
    let version = payload.first().map(|b| b >> 4)?;
    match version {
        4 => Some(AF_INET_BE),
        6 => Some(AF_INET6_BE),
        _ => None,
    }
}

/// Decodes the 4-byte macOS `utun` header into IP version (`4` or `6`).
pub fn decode_utun_family_header(header: [u8; 4]) -> Option<u8> {
    if header == AF_INET_BE {
        Some(4)
    } else if header == AF_INET6_BE {
        Some(6)
    } else {
        None
    }
}

/// Reads a single packet from a macOS `utun` descriptor, stripping the 4-byte `AF_*` header
/// via scatter-gather `readv` without extra heap allocation.
pub fn read_utun_packet(fd: impl AsFd, out_payload: &mut [u8]) -> io::Result<usize> {
    if out_payload.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "empty utun read buffer",
        ));
    }

    let raw_fd = fd.as_fd().as_raw_fd();
    let mut header = [0u8; 4];
    let mut iov = [
        libc::iovec {
            iov_base: header.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: out_payload.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: out_payload.len(),
        },
    ];

    // SAFETY: `fd.as_fd()` guarantees an open descriptor and both `iovec` entries point to live stack/caller buffers.
    let n = unsafe { libc::readv(raw_fd, iov.as_mut_ptr(), 2) };
    if n < 0 {
        return Err(Error::last_os_error());
    }
    let total = n as usize;
    if total == 0 {
        return Ok(0);
    }
    if total < 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "truncated macOS utun family header",
        ));
    }
    if decode_utun_family_header(header).is_none() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "unsupported macOS utun address family",
        ));
    }

    Ok(total - 4)
}

/// Writes an IPv4 or IPv6 packet to a macOS `utun` descriptor, prepending the 4-byte `AF_*`
/// family header via scatter-gather `writev` without copying the payload.
pub fn write_utun_packet(fd: impl AsFd, payload: &[u8]) -> io::Result<usize> {
    let header = encode_utun_family_header(payload).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "utun payload must be a valid IPv4 or IPv6 packet",
        )
    })?;

    let raw_fd = fd.as_fd().as_raw_fd();
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: payload.len(),
        },
    ];

    // SAFETY: `fd.as_fd()` guarantees an open descriptor and `iov` points to valid immutable slices for `writev`.
    let n = unsafe { libc::writev(raw_fd, iov.as_ptr(), 2) };
    if n < 0 {
        return Err(Error::last_os_error());
    }
    let total = n as usize;
    Ok(total.saturating_sub(4))
}

fn configure_cloexec_and_nonblock(fd: &OwnedFd) -> SysResult<()> {
    // SAFETY: `fd` is an open descriptor and `F_GETFD`/`F_SETFD` take no pointer args.
    let fd_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }
    // SAFETY: `fd` is open and `fd_flags | FD_CLOEXEC` is a valid flag mask.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }

    // SAFETY: `fd` is open and `F_GETFL`/`F_SETFL` inspect/update socket status flags.
    let fl_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if fl_flags < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }
    // SAFETY: `fd` is open and `fl_flags | O_NONBLOCK` enables non-blocking `AsyncFd` I/O.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl_flags | libc::O_NONBLOCK) } < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }

    Ok(())
}

fn resolve_utun_control_id(fd: &OwnedFd) -> SysResult<u32> {
    // SAFETY: `ctl_info` is a plain C struct composed solely of integers and byte arrays.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME_BYTES.iter()) {
        *dst = *src as libc::c_char;
    }

    // SAFETY: `fd` is an open `SYSPROTO_CONTROL` socket and `info` is a valid stack `ctl_info`.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &raw mut info) };
    if rc < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }

    Ok(info.ctl_id)
}

fn connect_utun_control(fd: &OwnedFd, ctl_id: u32, unit_hint: Option<u32>) -> SysResult<()> {
    let sc_unit = unit_hint.map_or(0, |unit| unit.saturating_add(1));
    let addr = libc::sockaddr_ctl {
        sc_len: size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: ctl_id,
        sc_unit,
        sc_reserved: [0; 5],
    };

    // SAFETY: `fd` is open and `addr` is a stack `sockaddr_ctl` whose byte length matches `sc_len`.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }

    Ok(())
}

fn query_utun_ifname(fd: &OwnedFd) -> SysResult<String> {
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    let mut len = buf.len() as libc::socklen_t;

    // SAFETY: `fd` is connected to `utun_control` and `buf` has `IFNAMSIZ` bytes for `UTUN_OPT_IFNAME`.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc < 0 {
        return Err(SysError::io("open_utun_device", Error::last_os_error()));
    }
    if let Some(last) = buf.last_mut() {
        *last = 0;
    }

    // SAFETY: `buf` has its trailing byte forced to `0`, guaranteeing NUL termination.
    let c_str = unsafe { CStr::from_ptr(buf.as_ptr()) };
    Ok(c_str.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_utun_family_header, encode_utun_family_header, open_utun_owned, validate_utun_name,
    };
    use crate::error::SysError;

    #[test]
    fn test_tun_macos_utun_name_validation() {
        // Arrange & Act & Assert
        validate_utun_name("utun0").expect("utun0 is valid");
        validate_utun_name("utun14").expect("utun14 is valid");
        assert!(matches!(
            validate_utun_name("utun"),
            Err(SysError::SecurityViolation { .. })
        ));
        assert!(matches!(
            validate_utun_name("utun-1"),
            Err(SysError::SecurityViolation { .. })
        ));
        assert!(matches!(
            validate_utun_name("en0"),
            Err(SysError::SecurityViolation { .. })
        ));
    }

    #[test]
    fn test_tun_macos_family_header_round_trip() {
        // Arrange
        let ipv4_pkt = [0x45u8, 0x00, 0x00, 0x14];
        let ipv6_pkt = [0x60u8, 0x00, 0x00, 0x00];
        let bogus_pkt = [0x30u8, 0x00];

        // Act
        let h4 = encode_utun_family_header(&ipv4_pkt).expect("ipv4 header");
        let h6 = encode_utun_family_header(&ipv6_pkt).expect("ipv6 header");

        // Assert
        assert_eq!(decode_utun_family_header(h4), Some(4));
        assert_eq!(decode_utun_family_header(h6), Some(6));
        assert_eq!(encode_utun_family_header(&bogus_pkt), None);
        assert_eq!(encode_utun_family_header(&[]), None);
        assert_eq!(decode_utun_family_header([0, 0, 0, 99]), None);
    }

    #[test]
    #[ignore = "privileged"]
    fn test_tun_macos_open_dynamic_utun_as_root() {
        // Arrange & Act
        let (name, _fd) = open_utun_owned(None).expect("open dynamic macOS utun");

        // Assert
        validate_utun_name(&name).expect("valid utun name returned");
    }
}
