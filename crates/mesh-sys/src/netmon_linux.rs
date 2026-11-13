use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Error};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use crate::error::{SysError, SysResult};

const NETLINK_MSG_HDR_LEN: usize = 16;

/// Linux `ENOBUFS` OS error code reported when `NETLINK_ROUTE` receive buffers overflow.
pub const ENOBUFS_ERRNO: i32 = libc::ENOBUFS;

/// Coarse network change event decoded from Linux `NETLINK_ROUTE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawNetEventKind {
    InterfaceUpChanged,
    AddressChanged,
    DefaultRouteChanged,
    PhysicalInterfaceChanged,
}

/// Snapshot of a Linux network interface unicast address and subnet prefix (`US-035`, `US-037`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxInterfaceAddress {
    pub if_index: u32,
    pub name: String,
    pub ip: IpAddr,
    pub prefix_len: u8,
    pub is_up: bool,
    pub is_virtual: bool,
}

/// Queries the primary physical Linux interface `(if_index, name)` from the active default route
/// table (`/proc/net/route` with `/proc/net/ipv6_route` and active physical `getifaddrs`
/// fallbacks), ignoring virtual tunnel/loopback NICs.
pub fn query_primary_physical_interface() -> SysResult<(u32, String)> {
    if let Ok(content) = fs::read_to_string("/proc/net/route")
        && let Some(ifname) = pick_primary_ipv4_default_iface(&content)
        && let Some(idx) = lookup_if_index(&ifname)
    {
        return Ok((idx, ifname));
    }

    if let Ok(content) = fs::read_to_string("/proc/net/ipv6_route")
        && let Some(ifname) = pick_primary_ipv6_default_iface(&content)
        && let Some(idx) = lookup_if_index(&ifname)
    {
        return Ok((idx, ifname));
    }

    if let Ok(addrs) = list_interface_addresses()
        && let Some(found) = addrs
            .into_iter()
            .find(|a| a.is_up && !a.is_virtual && a.if_index != 0 && is_usable_linux_ip(a.ip))
    {
        return Ok((found.if_index, found.name));
    }

    Err(SysError::io(
        "query_primary_physical_interface",
        Error::from_raw_os_error(libc::ENETUNREACH),
    ))
}

/// Queries the primary physical Linux interface index from the active default route table
/// (`/proc/net/route` with `/proc/net/ipv6_route` fallback), ignoring virtual tunnel/loopback NICs.
pub fn query_primary_physical_if_index() -> SysResult<u32> {
    query_primary_physical_interface().map(|(idx, _)| idx)
}

/// Resolves a Linux interface name from its numeric interface index via `if_indextoname`.
#[must_use]
pub fn lookup_if_name(if_index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is a stack array of size `IF_NAMESIZE` required by `if_indextoname`.
    let ptr = unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Non-null `if_indextoname` result guarantees NUL-terminated bytes inside `buf`.
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Enumerates active Linux interface unicast addresses and CIDR prefixes via `getifaddrs` (`US-037`).
pub fn list_interface_addresses() -> SysResult<Vec<LinuxInterfaceAddress>> {
    const OP: &str = "netmon_linux::list_interface_addresses";
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
        // SAFETY: `cursor` traverses non-null nodes returned by `getifaddrs` prior to `freeifaddrs`.
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
        let is_up = (flags & libc::IFF_UP) != 0;
        let is_virtual = (flags & libc::IFF_LOOPBACK) != 0 || is_virtual_linux_ifname(&name);
        let if_index = lookup_if_index(&name).unwrap_or(0);

        // SAFETY: Non-null `ifa_addr` points to a valid `libc::sockaddr` allocated by `getifaddrs`.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        match family {
            libc::AF_INET => {
                // SAFETY: `sa_family == AF_INET` ensures `ifa_addr` holds `libc::sockaddr_in`.
                let sa_in =
                    unsafe { ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in>()) };
                let ip = Ipv4Addr::from(sa_in.sin_addr.s_addr.to_ne_bytes());
                let prefix_len = read_linux_ipv4_mask_prefix(ifa.ifa_netmask);
                out.push(LinuxInterfaceAddress {
                    if_index,
                    name,
                    ip: IpAddr::V4(ip),
                    prefix_len,
                    is_up,
                    is_virtual,
                });
            }
            libc::AF_INET6 => {
                // SAFETY: `sa_family == AF_INET6` ensures `ifa_addr` holds `libc::sockaddr_in6`.
                let sa_in6 =
                    unsafe { ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in6>()) };
                let ip = Ipv6Addr::from(sa_in6.sin6_addr.s6_addr);
                let prefix_len = read_linux_ipv6_mask_prefix(ifa.ifa_netmask);
                out.push(LinuxInterfaceAddress {
                    if_index,
                    name,
                    ip: IpAddr::V6(ip),
                    prefix_len,
                    is_up,
                    is_virtual,
                });
            }
            _ => {}
        }
    }

    // SAFETY: `list` was allocated by `libc::getifaddrs` and is freed exactly once here.
    unsafe { libc::freeifaddrs(list) };
    Ok(out)
}

fn read_linux_ipv4_mask_prefix(netmask_ptr: *const libc::sockaddr) -> u8 {
    if netmask_ptr.is_null() {
        return 32;
    }
    // SAFETY: Non-null `ifa_netmask` points to a valid `libc::sockaddr` from `getifaddrs`.
    let family = i32::from(unsafe { (*netmask_ptr).sa_family });
    if family != libc::AF_INET {
        return 32;
    }
    // SAFETY: `sa_family == AF_INET` ensures `netmask_ptr` holds `libc::sockaddr_in`.
    let mask_in = unsafe { ptr::read_unaligned(netmask_ptr.cast::<libc::sockaddr_in>()) };
    ipv4_netmask_to_prefix(Ipv4Addr::from(mask_in.sin_addr.s_addr.to_ne_bytes()))
}

fn read_linux_ipv6_mask_prefix(netmask_ptr: *const libc::sockaddr) -> u8 {
    if netmask_ptr.is_null() {
        return 128;
    }
    // SAFETY: Non-null `ifa_netmask` points to a valid `libc::sockaddr` from `getifaddrs`.
    let family = i32::from(unsafe { (*netmask_ptr).sa_family });
    if family != libc::AF_INET6 {
        return 128;
    }
    // SAFETY: `sa_family == AF_INET6` ensures `netmask_ptr` holds `libc::sockaddr_in6`.
    let mask_in6 = unsafe { ptr::read_unaligned(netmask_ptr.cast::<libc::sockaddr_in6>()) };
    ipv6_netmask_to_prefix(mask_in6.sin6_addr.s6_addr)
}

fn ipv4_netmask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    u8::try_from(bits.leading_ones()).unwrap_or(32)
}

fn ipv6_netmask_to_prefix(octets: [u8; 16]) -> u8 {
    let bits = u128::from_be_bytes(octets);
    u8::try_from(bits.leading_ones()).unwrap_or(128)
}

fn is_usable_linux_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            let first_seg = v6.segments().first().copied().unwrap_or(0);
            !v6.is_unspecified() && !v6.is_loopback() && (first_seg & 0xffc0) != 0xfe80
        }
    }
}

/// Opens a non-blocking `NETLINK_ROUTE` multicast socket subscribed to link, address, and route changes.
pub fn open_netlink_route_monitor() -> SysResult<OwnedFd> {
    // SAFETY: Creating a `NETLINK_ROUTE` socket requires no pointer arguments.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw_fd < 0 {
        return Err(SysError::io(
            "open_netlink_route_monitor",
            Error::last_os_error(),
        ));
    }

    // SAFETY: `raw_fd` was returned as an owned descriptor by `libc::socket`.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let groups = (libc::RTMGRP_LINK
        | libc::RTMGRP_IPV4_IFADDR
        | libc::RTMGRP_IPV6_IFADDR
        | libc::RTMGRP_IPV4_ROUTE
        | libc::RTMGRP_IPV6_ROUTE) as u32;

    // SAFETY: `libc::sockaddr_nl` is a plain C struct composed solely of integer fields.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups = groups;

    // SAFETY: `owned_fd` is open and `addr` is a stack `sockaddr_nl` valid during `bind`.
    let rc = unsafe {
        libc::bind(
            owned_fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(SysError::io(
            "open_netlink_route_monitor",
            Error::last_os_error(),
        ));
    }

    Ok(owned_fd)
}

/// Drains one batch of non-blocking `NETLINK_ROUTE` notifications from `fd`.
pub fn read_netlink_events(fd: impl AsFd) -> io::Result<Vec<RawNetEventKind>> {
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
        .map(parse_netlink_messages)
        .unwrap_or_default())
}

/// Parses concatenated `nlmsghdr` frames into deduplicated coarse [`RawNetEventKind`] events.
pub fn parse_netlink_messages(buf: &[u8]) -> Vec<RawNetEventKind> {
    let mut events = Vec::new();
    let mut offset = 0usize;

    while let Some(hdr) = buf.get(offset..offset.saturating_add(NETLINK_MSG_HDR_LEN)) {
        let Some(len_bytes) = hdr.get(0..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
            break;
        };
        let Some(type_bytes) = hdr.get(4..6).and_then(|s| <[u8; 2]>::try_from(s).ok()) else {
            break;
        };

        let msg_len = u32::from_ne_bytes(len_bytes) as usize;
        let msg_type = u16::from_ne_bytes(type_bytes);
        if msg_len < NETLINK_MSG_HDR_LEN || offset.saturating_add(msg_len) > buf.len() {
            break;
        }

        if let Some(kind) = classify_nlmsg_type(msg_type)
            && !events.contains(&kind)
        {
            events.push(kind);
        }

        let aligned_len = (msg_len.saturating_add(3)) & !3usize;
        if aligned_len == 0 {
            break;
        }
        offset = offset.saturating_add(aligned_len);
    }

    events
}

/// Returns `true` when `ifname` denotes a virtual/tunnel/container interface that must never
/// be chosen as the physical underlay NIC.
pub fn is_virtual_linux_ifname(ifname: &str) -> bool {
    ifname == "lo"
        || ifname.starts_with("mesh")
        || ifname.starts_with("tun")
        || ifname.starts_with("tap")
        || ifname.starts_with("utun")
        || ifname.starts_with("wg")
        || ifname.starts_with("docker")
        || ifname.starts_with("veth")
        || ifname.starts_with("br-")
        || ifname.starts_with("virbr")
        || ifname.starts_with("tailscale")
        || ifname.starts_with("cni")
        || ifname.starts_with("flannel")
}

/// Selects the lowest-metric IPv4 default-route physical interface name from `/proc/net/route`.
pub fn pick_primary_ipv4_default_iface(proc_net_route: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;

    for line in proc_net_route.lines().skip(1) {
        let mut fields = line.split_ascii_whitespace();
        let Some(ifname) = fields.next() else {
            continue;
        };
        let Some(dest) = fields.next() else {
            continue;
        };
        let _gateway = fields.next()?;
        let Some(flags_hex) = fields.next() else {
            continue;
        };
        let _refcnt = fields.next();
        let _use = fields.next();
        let Some(metric_str) = fields.next() else {
            continue;
        };
        let Some(mask) = fields.next() else {
            continue;
        };

        if dest != "00000000" || mask != "00000000" || is_virtual_linux_ifname(ifname) {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(flags_hex, 16) else {
            continue;
        };
        if (flags & 0x0001) == 0 {
            continue;
        }
        let metric = metric_str.parse::<u32>().unwrap_or(u32::MAX);
        update_best_metric(&mut best, metric, ifname);
    }

    best.map(|(_, name)| name)
}

/// Selects the lowest-metric IPv6 default-route physical interface name from `/proc/net/ipv6_route`.
pub fn pick_primary_ipv6_default_iface(proc_net_ipv6_route: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;

    for line in proc_net_ipv6_route.lines() {
        let mut cols = line.split_ascii_whitespace();
        let Some(dest) = cols.next() else {
            continue;
        };
        let Some(dest_plen) = cols.next() else {
            continue;
        };
        let _src = cols.next();
        let _src_plen = cols.next();
        let _next_hop = cols.next();
        let Some(metric_hex) = cols.next() else {
            continue;
        };
        let _refcnt = cols.next();
        let _use = cols.next();
        let Some(flags_hex) = cols.next() else {
            continue;
        };
        let Some(ifname) = cols.next() else {
            continue;
        };

        if dest != "00000000000000000000000000000000"
            || dest_plen != "00"
            || is_virtual_linux_ifname(ifname)
        {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(flags_hex, 16) else {
            continue;
        };
        if (flags & 0x0001) == 0 {
            continue;
        }
        let metric = u32::from_str_radix(metric_hex, 16).unwrap_or(u32::MAX);
        update_best_metric(&mut best, metric, ifname);
    }

    best.map(|(_, name)| name)
}

fn update_best_metric(best: &mut Option<(u32, String)>, metric: u32, ifname: &str) {
    let replace = best
        .as_ref()
        .is_none_or(|(best_metric, _)| metric < *best_metric);
    if replace {
        *best = Some((metric, ifname.to_owned()));
    }
}

fn lookup_if_index(ifname: &str) -> Option<u32> {
    let c_name = CString::new(ifname).ok()?;
    // SAFETY: `c_name` is a valid NUL-terminated interface name string.
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

fn classify_nlmsg_type(msg_type: u16) -> Option<RawNetEventKind> {
    match msg_type {
        libc::RTM_NEWLINK | libc::RTM_DELLINK => Some(RawNetEventKind::InterfaceUpChanged),
        libc::RTM_NEWADDR | libc::RTM_DELADDR => Some(RawNetEventKind::AddressChanged),
        libc::RTM_NEWROUTE | libc::RTM_DELROUTE => Some(RawNetEventKind::DefaultRouteChanged),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RawNetEventKind, is_virtual_linux_ifname, parse_netlink_messages,
        pick_primary_ipv4_default_iface, pick_primary_ipv6_default_iface,
    };

    #[test]
    fn test_netmon_linux_picks_lowest_metric_non_virtual_ipv4_route() {
        // Arrange
        let sample = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
mesh0\t00000000\t00000000\t0001\t0\t0\t10\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

        // Act
        let chosen = pick_primary_ipv4_default_iface(sample);

        // Assert
        assert_eq!(chosen.as_deref(), Some("eth0"));
        assert!(is_virtual_linux_ifname("mesh0"));
        assert!(is_virtual_linux_ifname("veth12ab"));
        assert!(!is_virtual_linux_ifname("ens5"));
    }

    #[test]
    fn test_netmon_linux_ipv6_fallback_skips_virtual() {
        // Arrange
        let sample = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 0000000a 0 0 00000001 mesh0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 0 0 00000003 ens3
";

        // Act
        let chosen = pick_primary_ipv6_default_iface(sample);

        // Assert
        assert_eq!(chosen.as_deref(), Some("ens3"));
    }

    #[test]
    fn test_netmon_linux_parses_netlink_frames_safely() {
        // Arrange
        let mut frame = Vec::new();
        for msg_type in [libc::RTM_NEWLINK, libc::RTM_NEWADDR, libc::RTM_NEWROUTE] {
            frame.extend_from_slice(&16u32.to_ne_bytes());
            frame.extend_from_slice(&msg_type.to_ne_bytes());
            frame.extend_from_slice(&0u16.to_ne_bytes());
            frame.extend_from_slice(&0u32.to_ne_bytes());
            frame.extend_from_slice(&0u32.to_ne_bytes());
        }

        // Act
        let parsed = parse_netlink_messages(&frame);

        // Assert
        assert_eq!(
            parsed,
            vec![
                RawNetEventKind::InterfaceUpChanged,
                RawNetEventKind::AddressChanged,
                RawNetEventKind::DefaultRouteChanged,
            ]
        );
        assert!(parse_netlink_messages(&[0x04, 0x00, 0x00, 0x00]).is_empty());
    }

    #[test]
    fn test_netmon_linux_netmask_prefix_and_usable_ip_helpers() {
        // Arrange / Act / Assert
        assert_eq!(
            super::ipv4_netmask_to_prefix(super::Ipv4Addr::new(255, 192, 0, 0)),
            10
        );
        assert_eq!(
            super::ipv4_netmask_to_prefix(super::Ipv4Addr::new(255, 255, 255, 0)),
            24
        );
        assert!(!super::is_usable_linux_ip(super::IpAddr::V4(
            super::Ipv4Addr::new(169, 254, 12, 34)
        )));
        assert!(super::is_usable_linux_ip(super::IpAddr::V4(
            super::Ipv4Addr::new(192, 168, 1, 50)
        )));
    }
}
