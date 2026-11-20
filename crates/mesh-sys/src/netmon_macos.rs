use std::ffi::CStr;
use std::io::{self, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use crate::error::{SysError, SysResult};

const DARWIN_RT_MSGHDR_MIN_LEN: usize = 92;
const DARWIN_NET_RT_DUMP: libc::c_int = 1;
const DARWIN_RTM_ADD: u8 = 0x1;
const DARWIN_RTM_DELETE: u8 = 0x2;
const DARWIN_RTM_CHANGE: u8 = 0x3;
const DARWIN_RTM_NEWADDR: u8 = 0xc;
const DARWIN_RTM_DELADDR: u8 = 0xd;
const DARWIN_RTM_IFINFO: u8 = 0xe;
const DARWIN_RTM_IFANNOUNCE: u8 = 0x11;
const DARWIN_RTA_DST: i32 = 0x1;
const DARWIN_RTA_GATEWAY: i32 = 0x2;
const DARWIN_RTA_NETMASK: i32 = 0x4;

/// macOS `ENOBUFS` OS error code reported when `PF_ROUTE` receive buffers overflow.
pub const ENOBUFS_ERRNO: i32 = libc::ENOBUFS;

/// Coarse network change event decoded from macOS `PF_ROUTE` BSD routing sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawNetEventKind {
    InterfaceUpChanged,
    AddressChanged,
    DefaultRouteChanged,
    PhysicalInterfaceChanged,
}

/// Snapshot of a macOS network interface unicast address and subnet prefix (`US-035`, `US-037`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsInterfaceAddress {
    pub if_index: u32,
    pub name: String,
    pub ip: IpAddr,
    pub prefix_len: u8,
    pub is_up: bool,
    pub is_virtual: bool,
}

/// Resolves a macOS interface name from its numeric interface index via `if_indextoname`.
#[must_use]
pub fn lookup_if_name(if_index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is a stack array of size `IF_NAMESIZE` required by `if_indextoname`.
    let ptr = unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Non-null `if_indextoname` return guarantees NUL-terminated bytes inside `buf`.
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Queries the primary physical macOS interface `(if_index, name)` (e.g. `(4, "en0")`) from the
/// kernel default route via `sysctl(NET_RT_DUMP)` with an active non-virtual `getifaddrs`
/// fallback, never selecting virtual interfaces (`utun*`, `awdl*`, `llw*`, `bridge*`, `lo*`).
pub fn query_primary_physical_interface() -> SysResult<(u32, String)> {
    if let Some(idx) = query_default_route_if_index_via_sysctl()?
        && let Some(name) = lookup_if_name(idx)
        && !is_virtual_macos_ifname(&name)
    {
        return Ok((idx, name));
    }

    if let Some(idx) = query_active_physical_if_index_via_ifaddrs()?
        && let Some(name) = lookup_if_name(idx)
        && !is_virtual_macos_ifname(&name)
    {
        return Ok((idx, name));
    }

    Err(SysError::io(
        "query_primary_physical_interface",
        Error::from_raw_os_error(libc::ENETUNREACH),
    ))
}

/// Queries the primary physical macOS interface index (e.g. `en0`) from the kernel default route
/// via `sysctl(NET_RT_DUMP)` with an active non-virtual `getifaddrs` fallback, never choosing `utun*`.
pub fn query_primary_physical_if_index() -> SysResult<u32> {
    query_primary_physical_interface().map(|(idx, _)| idx)
}

/// Enumerates active macOS interface unicast addresses and CIDR prefixes via `getifaddrs` (`US-037`).
pub fn list_interface_addresses() -> SysResult<Vec<MacOsInterfaceAddress>> {
    const OP: &str = "netmon_macos::list_interface_addresses";
    let mut list: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `list` is initialized to null and populated by `libc::getifaddrs`.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        return Err(SysError::io(OP, Error::last_os_error()));
    }

    let mut out = Vec::new();
    let mut cursor = list;
    let mut visited = 0usize;

    while !cursor.is_null() && visited < 4096 {
        visited += 1;
        // SAFETY: `cursor` traverses valid nodes allocated by `getifaddrs` before `freeifaddrs`.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;

        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: Non-null `ifa_name` points to a valid NUL-terminated C string from `getifaddrs`.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let flags = ifa.ifa_flags as libc::c_int;
        let is_up = (flags & libc::IFF_UP) != 0 && (flags & libc::IFF_RUNNING) != 0;
        let is_virtual = (flags & libc::IFF_LOOPBACK) != 0 || is_virtual_macos_ifname(&name);
        // SAFETY: `ifa.ifa_name` is a valid NUL-terminated C string.
        let if_index = unsafe { libc::if_nametoindex(ifa.ifa_name) };

        let addr_bytes = copy_darwin_sockaddr_bytes(ifa.ifa_addr);
        let mask_bytes = copy_darwin_sockaddr_bytes(ifa.ifa_netmask);
        if let Some((ip, prefix_len)) = parse_darwin_addr_and_mask(&addr_bytes, mask_bytes.as_ref())
        {
            out.push(MacOsInterfaceAddress {
                if_index,
                name,
                ip,
                prefix_len,
                is_up,
                is_virtual,
            });
        }
    }

    // SAFETY: `list` came from `libc::getifaddrs` and must be freed with `libc::freeifaddrs`.
    unsafe { libc::freeifaddrs(list) };
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct DarwinSockaddrBytes {
    len: usize,
    data: [u8; 28],
}

fn copy_darwin_sockaddr_bytes(sa_ptr: *const libc::sockaddr) -> Option<DarwinSockaddrBytes> {
    if sa_ptr.is_null() {
        return None;
    }
    // SAFETY: Non-null `sockaddr` from `getifaddrs` has at least its leading `sa_len: u8` byte.
    let sa_len = usize::from(unsafe { *sa_ptr.cast::<u8>() });
    let bounded = sa_len.min(28);
    if bounded < 2 {
        return None;
    }
    let mut data = [0u8; 28];
    // SAFETY: Darwin sockaddrs store their valid length in the leading `sa_len` byte (`bounded`).
    let src = unsafe { std::slice::from_raw_parts(sa_ptr.cast::<u8>(), bounded) };
    if let Some(dst) = data.get_mut(..bounded) {
        dst.copy_from_slice(src);
    }
    Some(DarwinSockaddrBytes { len: bounded, data })
}

fn parse_darwin_addr_and_mask(
    addr: &Option<DarwinSockaddrBytes>,
    mask: Option<&DarwinSockaddrBytes>,
) -> Option<(IpAddr, u8)> {
    let addr = addr.as_ref()?;
    let family = i32::from(addr.data.get(1).copied().unwrap_or(0));
    match family {
        libc::AF_INET => {
            if addr.len < 8 {
                return None;
            }
            let octets: [u8; 4] = addr.data.get(4..8).and_then(|s| s.try_into().ok())?;
            let ip = IpAddr::V4(Ipv4Addr::from(octets));
            let prefix_len = match mask {
                Some(m) if m.len >= 4 => {
                    let mask_octets: [u8; 4] = m.data.get(4..8).and_then(|s| s.try_into().ok())?;
                    u8::try_from(u32::from_be_bytes(mask_octets).leading_ones()).unwrap_or(32)
                }
                _ => 32,
            };
            Some((ip, prefix_len))
        }
        libc::AF_INET6 => {
            if addr.len < 24 {
                return None;
            }
            let octets: [u8; 16] = addr.data.get(8..24).and_then(|s| s.try_into().ok())?;
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            let prefix_len = match mask {
                Some(m) if m.len >= 8 => {
                    let mask_octets: [u8; 16] =
                        m.data.get(8..24).and_then(|s| s.try_into().ok())?;
                    u8::try_from(u128::from_be_bytes(mask_octets).leading_ones()).unwrap_or(128)
                }
                _ => 128,
            };
            Some((ip, prefix_len))
        }
        _ => None,
    }
}

/// Opens a non-blocking, close-on-exec macOS `PF_ROUTE` raw routing socket for async change events.
pub fn open_route_monitor_socket() -> SysResult<OwnedFd> {
    // SAFETY: Opening a `PF_ROUTE` raw socket requires no pointer arguments.
    let raw_fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if raw_fd < 0 {
        return Err(SysError::io(
            "open_route_monitor_socket",
            Error::last_os_error(),
        ));
    }

    // SAFETY: `raw_fd` was just returned as an owned descriptor from `libc::socket`.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    set_cloexec_and_nonblock(&owned_fd)?;
    Ok(owned_fd)
}

/// Drains one batch of non-blocking BSD routing socket notifications from `fd`.
pub fn read_route_events(fd: impl AsFd) -> io::Result<Vec<RawNetEventKind>> {
    let mut buf = [0u8; 8192];
    let raw_fd = fd.as_fd().as_raw_fd();
    // SAFETY: `fd.as_fd()` guarantees an open descriptor and `buf` is a live writable buffer of 8192 bytes.
    let n = unsafe {
        libc::recv(
            raw_fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            0,
        )
    };
    if n < 0 {
        return Err(Error::last_os_error());
    }
    let len = (n as usize).min(buf.len());
    Ok(buf
        .get(..len)
        .map(|slice| {
            parse_bsd_route_messages_physical(slice, &|if_index, if_name_opt| {
                if let Some(name) = if_name_opt {
                    return is_virtual_macos_ifname(name);
                }
                if if_index == 0 {
                    return false;
                }
                lookup_if_name(if_index).is_some_and(|name| is_virtual_macos_ifname(&name))
            })
        })
        .unwrap_or_default())
}

/// Parses concatenated Darwin `PF_ROUTE` messages into deduplicated [`RawNetEventKind`] values.
pub fn parse_bsd_route_messages(buf: &[u8]) -> Vec<RawNetEventKind> {
    parse_bsd_route_messages_physical(buf, &|_, _| false)
}

/// Parses concatenated Darwin `PF_ROUTE` messages while skipping virtual interfaces (e.g. `utun*`).
pub fn parse_bsd_route_messages_physical(
    buf: &[u8],
    is_virtual_if: &dyn Fn(u32, Option<&str>) -> bool,
) -> Vec<RawNetEventKind> {
    let mut events = Vec::new();
    let mut offset = 0usize;

    while let Some(hdr) = buf.get(offset..offset.saturating_add(4)) {
        let Some(len_bytes) = hdr.get(0..2).and_then(|s| <[u8; 2]>::try_from(s).ok()) else {
            break;
        };
        let Some(&msg_type) = hdr.get(3) else {
            break;
        };
        let msg_len = u16::from_ne_bytes(len_bytes) as usize;
        let Some(end) = offset.checked_add(msg_len) else {
            break;
        };
        if msg_len < 4 || end > buf.len() {
            break;
        }

        let Some(msg) = buf.get(offset..end) else {
            break;
        };
        let (if_idx_opt, if_name_opt) = extract_bsd_msg_interface(msg, msg_type);
        let is_virtual = match (if_idx_opt, if_name_opt) {
            (Some(idx), name_opt) => is_virtual_if(idx, name_opt),
            (None, Some(name)) => is_virtual_if(0, Some(name)),
            (None, None) => false,
        };
        if !is_virtual
            && let Some(kind) = classify_bsd_rtm_type(msg_type)
            && !events.contains(&kind)
        {
            events.push(kind);
        }

        offset = end;
    }

    events
}

fn extract_bsd_msg_interface(msg: &[u8], msg_type: u8) -> (Option<u32>, Option<&str>) {
    match msg_type {
        DARWIN_RTM_ADD | DARWIN_RTM_DELETE | DARWIN_RTM_CHANGE => {
            let if_index = msg
                .get(4..6)
                .and_then(|s| <[u8; 2]>::try_from(s).ok())
                .map(|b| u32::from(u16::from_ne_bytes(b)));
            (if_index, None)
        }
        DARWIN_RTM_NEWADDR | DARWIN_RTM_DELADDR | DARWIN_RTM_IFINFO => {
            let if_index = msg
                .get(12..14)
                .and_then(|s| <[u8; 2]>::try_from(s).ok())
                .map(|b| u32::from(u16::from_ne_bytes(b)));
            (if_index, None)
        }
        DARWIN_RTM_IFANNOUNCE => {
            let if_index = msg
                .get(4..6)
                .and_then(|s| <[u8; 2]>::try_from(s).ok())
                .map(|b| u32::from(u16::from_ne_bytes(b)));
            let if_name = msg.get(6..22).and_then(|raw| {
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                let candidate = raw.get(..end).unwrap_or_default();
                (!candidate.is_empty())
                    .then(|| std::str::from_utf8(candidate).ok())
                    .flatten()
            });
            (if_index, if_name)
        }
        _ => (None, None),
    }
}

/// Parses a `sysctl(NET_RT_DUMP)` response buffer to extract the first non-virtual default-route
/// physical interface index.
pub fn pick_default_route_if_index_from_dump(
    buf: &[u8],
    is_physical_index: &dyn Fn(u32) -> bool,
) -> Option<u32> {
    let mut offset = 0usize;
    while let Some(hdr) = buf.get(offset..offset.saturating_add(DARWIN_RT_MSGHDR_MIN_LEN)) {
        let len_bytes = hdr.get(0..2).and_then(|s| <[u8; 2]>::try_from(s).ok())?;
        let msg_len = u16::from_ne_bytes(len_bytes) as usize;
        if msg_len < DARWIN_RT_MSGHDR_MIN_LEN || offset.saturating_add(msg_len) > buf.len() {
            break;
        }

        let idx_bytes = hdr.get(4..6).and_then(|s| <[u8; 2]>::try_from(s).ok())?;
        let flags_bytes = hdr.get(8..12).and_then(|s| <[u8; 4]>::try_from(s).ok())?;
        let addrs_bytes = hdr.get(12..16).and_then(|s| <[u8; 4]>::try_from(s).ok())?;

        let if_index = u32::from(u16::from_ne_bytes(idx_bytes));
        let flags = i32::from_ne_bytes(flags_bytes);
        let addrs_mask = i32::from_ne_bytes(addrs_bytes);

        let is_up_gateway = (flags & libc::RTF_UP) != 0 && (flags & libc::RTF_GATEWAY) != 0;
        if is_up_gateway
            && if_index != 0
            && let Some(payload) = buf.get(offset + DARWIN_RT_MSGHDR_MIN_LEN..offset + msg_len)
            && is_default_dst_route(addrs_mask, payload)
            && is_physical_index(if_index)
        {
            return Some(if_index);
        }

        offset = offset.saturating_add(msg_len);
    }

    None
}

/// Returns `true` when `ifname` denotes a macOS virtual/tunnel interface that must never be bound
/// as the outer physical interface (`utun*`, `lo*`, `awdl*`, `llw*`, `bridge*`, etc.).
pub fn is_virtual_macos_ifname(ifname: &str) -> bool {
    ifname.starts_with("utun")
        || ifname.starts_with("lo")
        || ifname.starts_with("awdl")
        || ifname.starts_with("llw")
        || ifname.starts_with("bridge")
        || ifname.starts_with("anpi")
        || ifname.starts_with("gif")
        || ifname.starts_with("stf")
        || ifname.starts_with("vmnet")
        || ifname.starts_with("vboxnet")
        || ifname.starts_with("mesh")
}

fn is_default_dst_route(addrs_mask: i32, sockaddr_payload: &[u8]) -> bool {
    if (addrs_mask & DARWIN_RTA_DST) == 0 {
        return false;
    }

    let mut pos = 0usize;
    let Some(dst_sa) = read_darwin_sockaddr(sockaddr_payload, &mut pos) else {
        return false;
    };
    if !is_zero_address_sockaddr(dst_sa) {
        return false;
    }

    if (addrs_mask & DARWIN_RTA_GATEWAY) != 0
        && read_darwin_sockaddr(sockaddr_payload, &mut pos).is_none()
    {
        return false;
    }

    if (addrs_mask & DARWIN_RTA_NETMASK) != 0
        && let Some(mask_sa) = read_darwin_sockaddr(sockaddr_payload, &mut pos)
    {
        return is_zero_mask_sockaddr(mask_sa);
    }

    true
}

fn read_darwin_sockaddr<'a>(payload: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let rem = payload.get(*pos..)?;
    let sa_len = usize::from(*rem.first()?);
    let step = if sa_len == 0 {
        4
    } else {
        (sa_len.saturating_add(3)) & !3usize
    };
    let slice = payload.get(*pos..(*pos).saturating_add(sa_len.max(2).min(rem.len())))?;
    *pos = (*pos).saturating_add(step);
    Some(slice)
}

fn is_zero_address_sockaddr(sa: &[u8]) -> bool {
    let family = i32::from(sa.get(1).copied().unwrap_or(0));
    match family {
        libc::AF_INET => sa.get(4..8).is_some_and(|addr| addr == [0, 0, 0, 0]),
        libc::AF_INET6 => sa
            .get(8..24)
            .is_some_and(|addr| addr.iter().all(|&b| b == 0)),
        _ => false,
    }
}

fn is_zero_mask_sockaddr(sa: &[u8]) -> bool {
    let sa_len = usize::from(sa.first().copied().unwrap_or(0));
    if sa_len == 0 {
        return true;
    }
    let family = i32::from(sa.get(1).copied().unwrap_or(0));
    match family {
        libc::AF_INET => sa.get(4..8).is_none_or(|addr| addr.iter().all(|&b| b == 0)),
        libc::AF_INET6 => sa
            .get(8..24)
            .is_none_or(|addr| addr.iter().all(|&b| b == 0)),
        _ => false,
    }
}

fn query_default_route_if_index_via_sysctl() -> SysResult<Option<u32>> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, DARWIN_NET_RT_DUMP, 0];
    let mut len: libc::size_t = 0;

    // SAFETY: First `sysctl` pass queries required buffer length with a null output pointer.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            ptr::null_mut(),
            &raw mut len,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(SysError::io(
            "query_primary_physical_if_index",
            Error::last_os_error(),
        ));
    }
    if len == 0 {
        return Ok(None);
    }

    let mut buf = vec![0u8; len];
    // SAFETY: `buf` is allocated with `len` writable bytes returned by the first `sysctl` call.
    let rc2 = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut len,
            ptr::null_mut(),
            0,
        )
    };
    if rc2 != 0 {
        return Err(SysError::io(
            "query_primary_physical_if_index",
            Error::last_os_error(),
        ));
    }

    let valid = buf.get(..len).unwrap_or(&buf);
    Ok(pick_default_route_if_index_from_dump(
        valid,
        &is_physical_if_index,
    ))
}

fn query_active_physical_if_index_via_ifaddrs() -> SysResult<Option<u32>> {
    let mut list: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `list` is initialized to null and populated by `libc::getifaddrs`.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        return Err(SysError::io(
            "query_primary_physical_if_index",
            Error::last_os_error(),
        ));
    }

    let mut preferred_en: Option<u32> = None;
    let mut fallback_other: Option<u32> = None;
    let mut cursor = list;

    while !cursor.is_null() {
        // SAFETY: `cursor` traverses nodes allocated by `getifaddrs` until `ifa_next` is null.
        let ifa = unsafe { &*cursor };
        let flags = ifa.ifa_flags as libc::c_int;
        let active = (flags & libc::IFF_UP) != 0
            && (flags & libc::IFF_RUNNING) != 0
            && (flags & libc::IFF_LOOPBACK) == 0;

        if active && !ifa.ifa_name.is_null() {
            // SAFETY: Non-null `ifa_name` is a valid NUL-terminated C string in `getifaddrs`.
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
            if !is_virtual_macos_ifname(&name) {
                // SAFETY: `ifa.ifa_name` is a valid C string interface name.
                let idx = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                if idx != 0 {
                    if name.starts_with("en") && preferred_en.is_none() {
                        preferred_en = Some(idx);
                    } else if fallback_other.is_none() {
                        fallback_other = Some(idx);
                    }
                }
            }
        }
        cursor = ifa.ifa_next;
    }

    // SAFETY: `list` came from `libc::getifaddrs` and must be freed with `libc::freeifaddrs`.
    unsafe { libc::freeifaddrs(list) };
    Ok(preferred_en.or(fallback_other))
}

fn is_physical_if_index(if_index: u32) -> bool {
    let Some(name) = lookup_if_name(if_index) else {
        return false;
    };
    !is_virtual_macos_ifname(&name)
}

fn set_cloexec_and_nonblock(fd: &OwnedFd) -> SysResult<()> {
    // SAFETY: `fd` is open and `F_GETFD`/`F_SETFD` take no pointers.
    let fd_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(SysError::io(
            "open_route_monitor_socket",
            Error::last_os_error(),
        ));
    }
    // SAFETY: `fd` is open and `FD_CLOEXEC` is a valid descriptor flag bit.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(SysError::io(
            "open_route_monitor_socket",
            Error::last_os_error(),
        ));
    }

    // SAFETY: `fd` is open and `F_GETFL`/`F_SETFL` update socket status flags.
    let fl_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if fl_flags < 0 {
        return Err(SysError::io(
            "open_route_monitor_socket",
            Error::last_os_error(),
        ));
    }
    // SAFETY: `fd` is open and `O_NONBLOCK` enables async readiness waits.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl_flags | libc::O_NONBLOCK) } < 0 {
        return Err(SysError::io(
            "open_route_monitor_socket",
            Error::last_os_error(),
        ));
    }

    Ok(())
}

fn classify_bsd_rtm_type(msg_type: u8) -> Option<RawNetEventKind> {
    match msg_type {
        DARWIN_RTM_ADD | DARWIN_RTM_DELETE | DARWIN_RTM_CHANGE => {
            Some(RawNetEventKind::DefaultRouteChanged)
        }
        DARWIN_RTM_NEWADDR | DARWIN_RTM_DELADDR => Some(RawNetEventKind::AddressChanged),
        DARWIN_RTM_IFINFO => Some(RawNetEventKind::InterfaceUpChanged),
        DARWIN_RTM_IFANNOUNCE => Some(RawNetEventKind::PhysicalInterfaceChanged),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DARWIN_RT_MSGHDR_MIN_LEN, DARWIN_RTA_DST, DARWIN_RTA_GATEWAY, DARWIN_RTA_NETMASK,
        DARWIN_RTM_ADD, DARWIN_RTM_IFANNOUNCE, DARWIN_RTM_IFINFO, DARWIN_RTM_NEWADDR,
        RawNetEventKind, is_virtual_macos_ifname, parse_bsd_route_messages,
        parse_bsd_route_messages_physical, pick_default_route_if_index_from_dump,
    };

    fn write_at(buf: &mut [u8], offset: usize, bytes: &[u8]) {
        if let Some(dst) = buf.get_mut(offset..offset + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
    }

    fn make_ipv4_sockaddr(ip: [u8; 4]) -> [u8; 16] {
        let mut sa = [0u8; 16];
        write_at(&mut sa, 0, &[16, libc::AF_INET as u8]);
        write_at(&mut sa, 4, &ip);
        sa
    }

    fn make_dump_entry(if_index: u16, flags: i32, dst_ip: [u8; 4]) -> Vec<u8> {
        let total_len = DARWIN_RT_MSGHDR_MIN_LEN + 48;
        let mut buf = vec![0u8; total_len];
        write_at(&mut buf, 0, &(total_len as u16).to_ne_bytes());
        write_at(&mut buf, 2, &[5, 4]);
        write_at(&mut buf, 4, &if_index.to_ne_bytes());
        write_at(&mut buf, 8, &flags.to_ne_bytes());
        let addrs = DARWIN_RTA_DST | DARWIN_RTA_GATEWAY | DARWIN_RTA_NETMASK;
        write_at(&mut buf, 12, &addrs.to_ne_bytes());
        write_at(
            &mut buf,
            DARWIN_RT_MSGHDR_MIN_LEN,
            &make_ipv4_sockaddr(dst_ip),
        );
        write_at(
            &mut buf,
            DARWIN_RT_MSGHDR_MIN_LEN + 16,
            &make_ipv4_sockaddr([192, 168, 1, 1]),
        );
        write_at(
            &mut buf,
            DARWIN_RT_MSGHDR_MIN_LEN + 32,
            &make_ipv4_sockaddr([0, 0, 0, 0]),
        );
        buf
    }

    #[test]
    fn test_netmon_macos_skips_virtual_utun_and_picks_physical_default_route() {
        // Arrange
        let mut dump = Vec::new();
        dump.extend(make_dump_entry(
            9,
            libc::RTF_UP | libc::RTF_GATEWAY,
            [0, 0, 0, 0],
        ));
        dump.extend(make_dump_entry(
            4,
            libc::RTF_UP | libc::RTF_GATEWAY,
            [0, 0, 0, 0],
        ));

        // Act
        let chosen = pick_default_route_if_index_from_dump(&dump, &|idx| idx != 9);

        // Assert
        assert_eq!(chosen, Some(4));
        assert!(is_virtual_macos_ifname("utun3"));
        assert!(is_virtual_macos_ifname("awdl0"));
        assert!(!is_virtual_macos_ifname("en0"));
    }

    #[test]
    fn test_netmon_macos_parses_bsd_route_notifications() {
        // Arrange
        let mut buf = Vec::new();
        for (len, msg_type) in [
            (92u16, DARWIN_RTM_ADD),
            (16u16, DARWIN_RTM_NEWADDR),
            (16u16, DARWIN_RTM_IFINFO),
        ] {
            let mut msg = vec![0u8; len as usize];
            write_at(&mut msg, 0, &len.to_ne_bytes());
            write_at(&mut msg, 2, &[5, msg_type]);
            buf.extend(msg);
        }

        // Act
        let parsed = parse_bsd_route_messages(&buf);

        // Assert
        assert_eq!(
            parsed,
            vec![
                RawNetEventKind::DefaultRouteChanged,
                RawNetEventKind::AddressChanged,
                RawNetEventKind::InterfaceUpChanged,
            ]
        );
    }

    #[test]
    fn test_netmon_macos_parses_compressed_bsd_netmask_safely() {
        // Arrange: compressed /24 BSD netmask has sa_len = 7 (trailing .0 omitted)
        let mut addr_buf = [0u8; 28];
        write_at(
            &mut addr_buf,
            0,
            &[16, libc::AF_INET as u8, 0, 0, 100, 64, 1, 20],
        );
        let addr = Some(super::DarwinSockaddrBytes {
            len: 16,
            data: addr_buf,
        });
        let mut mask_buf = [0u8; 28];
        write_at(
            &mut mask_buf,
            0,
            &[7, libc::AF_INET as u8, 0, 0, 255, 255, 255],
        );
        let mask = super::DarwinSockaddrBytes {
            len: 7,
            data: mask_buf,
        };

        // Act
        let parsed = super::parse_darwin_addr_and_mask(&addr, Some(&mask));

        // Assert
        assert_eq!(
            parsed,
            Some((
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 1, 20)),
                24
            ))
        );
    }

    #[test]
    fn test_netmon_macos_filters_virtual_utun_pf_route_messages() {
        // Arrange: virtual utun7 RTM_ADD (idx=9), RTM_IFINFO (idx=9), RTM_IFANNOUNCE ("utun7"),
        // plus one physical en0 RTM_NEWADDR (idx=4).
        let mut buf = Vec::new();

        // 1) RTM_ADD with rtm_index=9 at offset 4..6
        let mut rtm_add = vec![0u8; 92];
        write_at(&mut rtm_add, 0, &92u16.to_ne_bytes());
        write_at(&mut rtm_add, 2, &[5, DARWIN_RTM_ADD]);
        write_at(&mut rtm_add, 4, &9u16.to_ne_bytes());
        buf.extend(rtm_add);

        // 2) RTM_IFINFO with ifm_index=9 at offset 12..14
        let mut ifinfo = vec![0u8; 20];
        write_at(&mut ifinfo, 0, &20u16.to_ne_bytes());
        write_at(&mut ifinfo, 2, &[5, DARWIN_RTM_IFINFO]);
        write_at(&mut ifinfo, 12, &9u16.to_ne_bytes());
        buf.extend(ifinfo);

        // 3) RTM_IFANNOUNCE with ifan_index=9, ifan_name="utun7"
        let mut announce = vec![0u8; 24];
        write_at(&mut announce, 0, &24u16.to_ne_bytes());
        write_at(&mut announce, 2, &[5, DARWIN_RTM_IFANNOUNCE]);
        write_at(&mut announce, 4, &9u16.to_ne_bytes());
        write_at(&mut announce, 6, b"utun7");
        buf.extend(announce);

        // 4) Physical en0 RTM_NEWADDR with ifam_index=4 at offset 12..14
        let mut newaddr = vec![0u8; 20];
        write_at(&mut newaddr, 0, &20u16.to_ne_bytes());
        write_at(&mut newaddr, 2, &[5, DARWIN_RTM_NEWADDR]);
        write_at(&mut newaddr, 12, &4u16.to_ne_bytes());
        buf.extend(newaddr);

        // Act
        let filtered = parse_bsd_route_messages_physical(&buf, &|idx, name_opt| {
            name_opt.map_or(idx == 9, is_virtual_macos_ifname)
        });

        // Assert: only physical en0 AddressChanged remains.
        assert_eq!(filtered, vec![RawNetEventKind::AddressChanged]);
    }
}
