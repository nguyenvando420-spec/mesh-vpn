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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use mesh_core::OverlayCidr;

    use super::{
        CandidateFilterContext, DiscoveredInterfaceEndpoint, filter_candidate_endpoints,
        is_valid_candidate_endpoint, is_virtual_interface_name,
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
}
