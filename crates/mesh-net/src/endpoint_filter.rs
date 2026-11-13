//! Candidate UDP endpoint filtering protecting against virtual loops and STUN reflection (`US-020`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mesh_core::OverlayCidr;

const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "mesh",
    "utun",
    "wg",
    "tailscale",
    "docker",
    "veth",
    "wintun",
    "tun",
    "tap",
    "br-",
    "virbr",
    "cni",
    "flannel",
    "cali",
];

/// Context needed to validate advertised UDP candidate endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFilterContext {
    /// Active overlay CIDR that must never be advertised as an underlay candidate.
    pub overlay_cidr: OverlayCidr,
    /// Control server TCP socket address (allowed to share the same port number for UDP P2P).
    pub control_tcp_endpoint: Option<SocketAddr>,
    /// Active STUN UDP socket address that MUST be excluded from UDP P2P candidates.
    pub stun_udp_endpoint: Option<SocketAddr>,
}

/// Tagged interface + UDP socket address discovered on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredInterfaceEndpoint {
    /// Optional OS interface name (`en0`, `eth0`, `utun7`, etc.).
    pub interface_name: Option<String>,
    /// Candidate UDP `IP:port`.
    pub endpoint: SocketAddr,
}

/// Returns `true` if `name` belongs to a virtual/tunnel/loopback adapter that must be skipped.
#[must_use]
pub fn is_virtual_interface_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    if lower == "lo"
        || lower
            .strip_prefix("lo")
            .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
    {
        return true;
    }
    VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Returns `true` if `ip` is eligible to participate in underlay UDP P2P hole-punching.
#[must_use]
pub fn is_valid_candidate_ip(ip: IpAddr, overlay_cidr: &OverlayCidr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
            {
                return false;
            }
            !overlay_cidr.contains_subnet_ip(v4)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
                || v6.is_unspecified()
                || is_ipv4_mapped_invalid(v6.to_ipv4_mapped(), overlay_cidr))
        }
    }
}

fn is_ipv4_mapped_invalid(mapped: Option<Ipv4Addr>, overlay_cidr: &OverlayCidr) -> bool {
    match mapped {
        Some(v4) => !is_valid_candidate_ip(IpAddr::V4(v4), overlay_cidr),
        None => false,
    }
}

/// Validates whether a UDP endpoint `addr` from optional `interface_name` is a safe candidate.
///
/// Matches `api-design.md` (`Codex R2 #4`): rejects only exact UDP equality with
/// `stun_udp_endpoint`, NEVER rejecting a candidate solely because its UDP port equals
/// `control_tcp_endpoint`'s TCP port.
#[must_use]
pub fn is_valid_candidate_endpoint(
    addr: SocketAddr,
    interface_name: Option<&str>,
    ctx: &CandidateFilterContext,
) -> bool {
    if addr.port() == 0 {
        return false;
    }
    if let Some(iface) = interface_name
        && is_virtual_interface_name(iface)
    {
        return false;
    }
    if !is_valid_candidate_ip(addr.ip(), &ctx.overlay_cidr) {
        return false;
    }
    if ctx.stun_udp_endpoint == Some(addr) {
        return false;
    }
    true
}

/// Filters and deduplicates candidate endpoints while preserving deterministic order.
#[must_use]
pub fn filter_candidate_endpoints(
    discovered: &[DiscoveredInterfaceEndpoint],
    ctx: &CandidateFilterContext,
) -> Vec<SocketAddr> {
    let mut accepted = Vec::new();
    for item in discovered {
        if is_valid_candidate_endpoint(item.endpoint, item.interface_name.as_deref(), ctx)
            && !accepted.contains(&item.endpoint)
        {
            accepted.push(item.endpoint);
        }
    }
    accepted
}

/// Snapshot of an OS interface IPv4/IPv6 unicast address and subnet prefix (`US-036`, `US-037`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSubnetSnapshot {
    /// OS interface index.
    pub if_index: u32,
    /// Human-readable adapter/interface name (`en0`, `eth0`, `Wi-Fi`, etc.).
    pub interface_name: String,
    /// Assigned unicast IPv4 or IPv6 address.
    pub ip: IpAddr,
    /// On-link CIDR prefix length (`0..=32` IPv4, `0..=128` IPv6).
    pub prefix_len: u8,
    /// Whether the interface is currently operationally up.
    pub is_up: bool,
    /// Whether the OS marks the interface as virtual, loopback, or tunnel.
    pub is_virtual: bool,
    /// Whether the interface currently advertises a default gateway.
    pub has_gateway: bool,
}

/// Overlap between an active physical interface subnet and the configured overlay CIDR (`US-037`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlaySubnetConflict {
    /// Name of the conflicting physical OS interface.
    pub interface_name: String,
    /// Assigned physical IPv4 address on that interface.
    pub physical_ip: Ipv4Addr,
    /// Subnet prefix length of the physical interface.
    pub physical_prefix_len: u8,
    /// Mesh overlay CIDR that overlaps the physical subnet.
    pub overlay_cidr: OverlayCidr,
}

impl OverlaySubnetConflict {
    /// Formats an operator-facing diagnostic warning suitable for `mesh status` (`US-037`).
    #[must_use]
    pub fn format_warning(&self) -> String {
        format!(
            "overlay CIDR {} conflicts with physical interface {} ({}/{}); overlapping overlay route refused",
            self.overlay_cidr, self.interface_name, self.physical_ip, self.physical_prefix_len
        )
    }
}

/// Returns `true` when `ip` is a routable DHCP/static address (excludes unspecified, loopback,
/// IPv4 APIPA `169.254.0.0/16`, and IPv6 link-local `fe80::/10`) (`US-036 AC4`).
#[must_use]
pub fn is_usable_dhcp_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_unicast_link_local()
                || v6.is_multicast())
        }
    }
}

/// Returns `true` when two IPv4 CIDR ranges `(ip_a/prefix_a)` and `(ip_b/prefix_b)` share at
/// least one address (`US-037`).
#[must_use]
pub fn ipv4_subnets_overlap(ip_a: Ipv4Addr, prefix_a: u8, ip_b: Ipv4Addr, prefix_b: u8) -> bool {
    let min_prefix = prefix_a.min(prefix_b);
    if min_prefix == 0 || min_prefix > 32 {
        return false;
    }
    let shift = 32_u32.saturating_sub(u32::from(min_prefix));
    let mask = if shift >= 32 { 0_u32 } else { !0_u32 << shift };
    (u32::from(ip_a) & mask) == (u32::from(ip_b) & mask)
}

/// Detects whether any active non-virtual interface subnet overlaps `overlay_cidr` (`US-037`).
///
/// Guarantees zero false positives against RFC 1918 (`192.168.0.0/16`, `10.0.0.0/8`,
/// `172.16.0.0/12`) when using default CGNAT overlay ranges (`100.64.0.0/10`, `100.115.0.0/16`),
/// and skips virtual/loopback/tunnel adapters as well as APIPA `169.254.0.0/16`.
#[must_use]
pub fn detect_overlay_subnet_conflict(
    subnets: &[InterfaceSubnetSnapshot],
    overlay_cidr: OverlayCidr,
) -> Option<OverlaySubnetConflict> {
    for snap in subnets {
        if !snap.is_up || snap.is_virtual || is_virtual_interface_name(&snap.interface_name) {
            continue;
        }
        let IpAddr::V4(v4) = snap.ip else {
            continue;
        };
        if v4.is_unspecified()
            || v4.is_loopback()
            || v4.is_link_local()
            || v4.is_multicast()
            || v4.is_broadcast()
        {
            continue;
        }
        let physical_prefix_len = snap.prefix_len.min(32);
        if ipv4_subnets_overlap(
            v4,
            physical_prefix_len,
            overlay_cidr.network(),
            overlay_cidr.prefix_len(),
        ) {
            return Some(OverlaySubnetConflict {
                interface_name: snap.interface_name.clone(),
                physical_ip: v4,
                physical_prefix_len,
                overlay_cidr,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use mesh_core::OverlayCidr;

    use super::{
        CandidateFilterContext, DiscoveredInterfaceEndpoint, InterfaceSubnetSnapshot,
        detect_overlay_subnet_conflict, filter_candidate_endpoints, ipv4_subnets_overlap,
        is_usable_dhcp_ip, is_valid_candidate_endpoint, is_virtual_interface_name,
    };

    #[test]
    fn test_endpoint_filter_codex_r2_4_tcp_vs_udp_port_distinction() {
        // Arrange: mandatory vector from api-design.md Codex R2 #4
        let overlay_cidr = match "100.115.0.0/16".parse::<OverlayCidr>() {
            Ok(cidr) => cidr,
            Err(err) => {
                assert_eq!(err.to_string(), "cidr parse failed");
                return;
            }
        };
        let vps_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let control_tcp = SocketAddr::new(vps_ip, 51820);
        let stun_udp = SocketAddr::new(vps_ip, 3478);

        let ctx = CandidateFilterContext {
            overlay_cidr,
            control_tcp_endpoint: Some(control_tcp),
            stun_udp_endpoint: Some(stun_udp),
        };

        // Act
        let same_port_as_control_udp = SocketAddr::new(vps_ip, 51820);
        let matches_stun_udp = SocketAddr::new(vps_ip, 3478);

        // Assert
        assert!(is_valid_candidate_endpoint(
            same_port_as_control_udp,
            Some("eth0"),
            &ctx,
        ));
        assert!(!is_valid_candidate_endpoint(
            matches_stun_udp,
            Some("eth0"),
            &ctx,
        ));
    }

    #[test]
    fn test_endpoint_filter_rejects_virtual_ifaces_and_special_ips() {
        // Arrange
        let overlay_cidr = match "100.115.0.0/16".parse::<OverlayCidr>() {
            Ok(cidr) => cidr,
            Err(err) => {
                assert_eq!(err.to_string(), "cidr parse failed");
                return;
            }
        };
        let ctx = CandidateFilterContext {
            overlay_cidr,
            control_tcp_endpoint: None,
            stun_udp_endpoint: None,
        };
        let candidates = vec![
            DiscoveredInterfaceEndpoint {
                interface_name: Some("utun7".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 51820),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("mesh0".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 115, 0, 1)), 51820),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 2)), 51820),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51820),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 51820),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 115, 0, 0)), 51820),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 115, 255, 255)), 51820),
            },
            DiscoveredInterfaceEndpoint {
                interface_name: Some("en0".to_owned()),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 51820),
            },
        ];

        // Act
        let filtered = filter_candidate_endpoints(&candidates, &ctx);

        // Assert
        assert!(is_virtual_interface_name("utun7"));
        assert!(is_virtual_interface_name("Docker0"));
        assert!(is_virtual_interface_name("lo0"));
        assert!(!is_virtual_interface_name("en0"));
        assert_eq!(
            filtered,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                51820
            )]
        );
    }

    #[test]
    fn test_endpoint_filter_cgnat_conflict_detection_zero_false_positives() {
        // Traces: US-037
        // Arrange
        let Ok(overlay) = "100.115.0.0/16".parse::<OverlayCidr>() else {
            panic_unreachable_test_parse();
            return;
        };
        let safe_lans = [
            InterfaceSubnetSnapshot {
                if_index: 1,
                interface_name: "en0".to_owned(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
                prefix_len: 24,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            },
            InterfaceSubnetSnapshot {
                if_index: 2,
                interface_name: "eth0".to_owned(),
                ip: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
                prefix_len: 8,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            },
            InterfaceSubnetSnapshot {
                if_index: 3,
                interface_name: "wlan0".to_owned(),
                ip: IpAddr::V4(Ipv4Addr::new(172, 16, 12, 9)),
                prefix_len: 12,
                is_up: true,
                is_virtual: false,
                has_gateway: false,
            },
            InterfaceSubnetSnapshot {
                if_index: 9,
                interface_name: "MeshVPN".to_owned(),
                ip: IpAddr::V4(Ipv4Addr::new(100, 115, 0, 1)),
                prefix_len: 16,
                is_up: true,
                is_virtual: true,
                has_gateway: false,
            },
        ];

        // Act / Assert: zero false positives on private ranges and virtual own TUN
        assert!(detect_overlay_subnet_conflict(&safe_lans, overlay).is_none());
        assert!(!ipv4_subnets_overlap(
            Ipv4Addr::new(192, 168, 0, 1),
            16,
            Ipv4Addr::new(100, 64, 0, 0),
            10
        ));
        assert!(!ipv4_subnets_overlap(
            Ipv4Addr::new(10, 0, 0, 1),
            8,
            Ipv4Addr::new(100, 64, 0, 0),
            10
        ));
        assert!(!ipv4_subnets_overlap(
            Ipv4Addr::new(172, 16, 0, 1),
            12,
            Ipv4Addr::new(100, 64, 0, 0),
            10
        ));

        // Conflicting ISP CGNAT physical uplink (100.64.5.12/10 vs 100.115.0.0/16)
        let conflicting = vec![InterfaceSubnetSnapshot {
            if_index: 4,
            interface_name: "wwan0".to_owned(),
            ip: IpAddr::V4(Ipv4Addr::new(100, 64, 5, 12)),
            prefix_len: 10,
            is_up: true,
            is_virtual: false,
            has_gateway: true,
        }];
        let conflict = detect_overlay_subnet_conflict(&conflicting, overlay);
        assert!(conflict.is_some());
        if let Some(c) = conflict {
            assert_eq!(c.interface_name, "wwan0");
            assert!(c.format_warning().contains("100.115.0.0/16"));
        }

        // Usable DHCP filter ignores APIPA 169.254.x.x
        assert!(!is_usable_dhcp_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 8, 9
        ))));
        assert!(is_usable_dhcp_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 8, 9))));
    }

    fn panic_unreachable_test_parse() {
        assert_eq!("valid", "invalid cidr");
    }
}
