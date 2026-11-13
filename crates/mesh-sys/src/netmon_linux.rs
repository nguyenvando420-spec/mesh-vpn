use std::ffi::CString;
use std::fs;
use std::io::{self, Error};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use crate::error::{SysError, SysResult};

const NETLINK_MSG_HDR_LEN: usize = 16;

/// Coarse network change event decoded from Linux `NETLINK_ROUTE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawNetEventKind {
    InterfaceUpChanged,
    AddressChanged,
    DefaultRouteChanged,
    PhysicalInterfaceChanged,
}

/// Queries the primary physical Linux interface index from the active default route table
/// (`/proc/net/route` with `/proc/net/ipv6_route` fallback), ignoring virtual tunnel/loopback NICs.
pub fn query_primary_physical_if_index() -> SysResult<u32> {
    if let Ok(content) = fs::read_to_string("/proc/net/route")
        && let Some(ifname) = pick_primary_ipv4_default_iface(&content)
        && let Some(idx) = lookup_if_index(&ifname)
    {
        return Ok(idx);
    }

    if let Ok(content) = fs::read_to_string("/proc/net/ipv6_route")
        && let Some(ifname) = pick_primary_ipv6_default_iface(&content)
        && let Some(idx) = lookup_if_index(&ifname)
    {
        return Ok(idx);
    }

    Err(SysError::io(
        "query_primary_physical_if_index",
        Error::from_raw_os_error(libc::ENETUNREACH),
    ))
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
}
