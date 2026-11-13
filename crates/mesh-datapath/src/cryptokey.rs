//! Strict `/32` WireGuard cryptokey routing validation and fail-closed host packet filter.

use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{error, warn};

use mesh_core::{AppError, AppResult, OverlayCidr, OverlayIp};

const IPV4_MIN_HEADER_LEN: usize = 20;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// Decoded inner IPv4 header metadata needed for cryptokey routing and packet filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedIpv4Header {
    /// Inner IPv4 source address.
    pub src_ip: Ipv4Addr,
    /// Inner IPv4 destination address.
    pub dst_ip: Ipv4Addr,
    /// IPv4 protocol number.
    pub protocol: u8,
    /// Header length in bytes.
    pub ihl_bytes: usize,
    /// Declared IPv4 total packet length in bytes.
    pub total_len: usize,
    /// Destination TCP/UDP port when present in the first fragment.
    pub dst_port: Option<u16>,
    /// True if this packet is a non-initial IPv4 fragment (`fragment_offset != 0`).
    pub is_non_initial_fragment: bool,
}

/// Transport protocol selector for host packet filter rules (`US-018`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterProtocol {
    /// Matches any IPv4 protocol.
    Any,
    /// Matches ICMP (`1`).
    Icmp,
    /// Matches TCP (`6`).
    Tcp,
    /// Matches UDP (`17`).
    Udp,
}

impl FilterProtocol {
    fn matches(self, protocol: u8) -> bool {
        match self {
            Self::Any => true,
            Self::Icmp => protocol == PROTO_ICMP,
            Self::Tcp => protocol == PROTO_TCP,
            Self::Udp => protocol == PROTO_UDP,
        }
    }
}

/// Inclusive TCP/UDP destination port range guaranteed to have `start <= end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Constructs a validated inclusive port range; returns `None` if `start > end`.
    #[must_use]
    pub fn new(start: u16, end: u16) -> Option<Self> {
        if start > end {
            return None;
        }
        Some(Self { start, end })
    }

    /// Returns a single-port range.
    #[must_use]
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Returns the inclusive bounds as a standard range.
    #[must_use]
    pub fn as_range(self) -> RangeInclusive<u16> {
        self.start..=self.end
    }

    fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// Single inbound packet allow rule evaluated after `/32` cryptokey verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFilterRule {
    /// Optional source peer overlay IP restriction (`None` matches any authenticated peer).
    pub source_peer_ip: Option<OverlayIp>,
    /// Transport protocol selector.
    pub protocol: FilterProtocol,
    /// Optional destination port restriction (`None` allows any port or non-port protocol).
    pub dst_ports: Option<PortRange>,
}

impl PacketFilterRule {
    fn matches(&self, header: &ParsedIpv4Header) -> bool {
        if let Some(allowed_src) = self.source_peer_ip
            && allowed_src.as_ipv4() != header.src_ip
        {
            return false;
        }
        if !self.protocol.matches(header.protocol) {
            return false;
        }
        match self.dst_ports {
            None => true,
            Some(range) => {
                if header.is_non_initial_fragment {
                    return false;
                }
                header.dst_port.is_some_and(|port| range.contains(port))
            }
        }
    }
}

/// Fail-closed packet filtering policy applied inside `CryptokeyValidator` (`US-018`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PacketFilterPolicy {
    /// Allow all cryptokey-verified overlay packets (default baseline).
    #[default]
    AllowAllOverlay,
    /// Allow only packets matching at least one explicit allow rule (default deny).
    AllowRules(Vec<PacketFilterRule>),
    /// Block packets matching any explicit deny rule while allowing remaining overlay packets (`US-018`).
    DenyRules(Vec<PacketFilterRule>),
    /// Drop every packet (fail-closed state when policy reload fails validation).
    FailClosed,
}

impl PacketFilterPolicy {
    fn allows(&self, header: &ParsedIpv4Header) -> bool {
        match self {
            Self::AllowAllOverlay => true,
            Self::AllowRules(rules) => rules.iter().any(|rule| rule.matches(header)),
            Self::DenyRules(rules) => {
                if header.is_non_initial_fragment
                    && rules.iter().any(|rule| rule.dst_ports.is_some())
                {
                    return false;
                }
                !rules.iter().any(|rule| rule.matches(header))
            }
            Self::FailClosed => false,
        }
    }
}

/// Parses a human/config inbound filter rule list into [`PacketFilterPolicy`] (`US-018`).
///
/// Supported syntax (comma or semicolon delimited):
/// - `""` or `"allow-all"` -> [`PacketFilterPolicy::AllowAllOverlay`]
/// - `"fail-closed"` or `"deny-all"` -> [`PacketFilterPolicy::FailClosed`]
/// - Port/protocol block entries (`DenyRules`): `"3389"`, `"tcp:3389"`, `"udp:5353"`,
///   `"tcp:8000-8080"`, `"deny:tcp:3389"`, `"block:3389"`, `"icmp"`.
pub fn parse_inbound_filter_spec(spec: &str) -> AppResult<PacketFilterPolicy> {
    let trimmed = spec.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("allow-all")
        || trimmed.eq_ignore_ascii_case("allow_all")
        || trimmed.eq_ignore_ascii_case("all")
    {
        return Ok(PacketFilterPolicy::AllowAllOverlay);
    }
    if trimmed.eq_ignore_ascii_case("fail-closed")
        || trimmed.eq_ignore_ascii_case("fail_closed")
        || trimmed.eq_ignore_ascii_case("deny-all")
        || trimmed.eq_ignore_ascii_case("deny_all")
    {
        return Ok(PacketFilterPolicy::FailClosed);
    }

    let mut deny_rules = Vec::new();
    for raw_item in trimmed.split([',', ';', '\n']) {
        let item = raw_item.trim();
        if item.is_empty() {
            continue;
        }
        let lower = item.to_ascii_lowercase();
        let without_action = if let Some(rest) = lower.strip_prefix("deny:") {
            rest.trim()
        } else if let Some(rest) = lower.strip_prefix("block:") {
            rest.trim()
        } else if lower.starts_with("allow:") {
            return Err(AppError::invalid_argument(format!(
                "invalid inbound filter rule '{item}': only deny/block port rules are supported here"
            )));
        } else {
            lower.as_str()
        };

        let rule = parse_single_deny_rule(without_action, item)?;
        deny_rules.push(rule);
    }

    if deny_rules.is_empty() {
        return Err(AppError::invalid_argument(
            "inbound filter rule specification contained no valid rules",
        ));
    }
    Ok(PacketFilterPolicy::DenyRules(deny_rules))
}

fn parse_single_deny_rule(normalized: &str, original: &str) -> AppResult<PacketFilterRule> {
    if normalized == "icmp" {
        return Ok(PacketFilterRule {
            source_peer_ip: None,
            protocol: FilterProtocol::Icmp,
            dst_ports: None,
        });
    }
    let (protocol, port_spec) = if let Some((proto_str, ports_str)) = normalized.split_once(':') {
        let proto = match proto_str.trim() {
            "tcp" => FilterProtocol::Tcp,
            "udp" => FilterProtocol::Udp,
            "any" | "*" => FilterProtocol::Any,
            _ => {
                return Err(AppError::invalid_argument(format!(
                    "unsupported protocol in inbound filter rule '{original}'"
                )));
            }
        };
        (proto, ports_str.trim())
    } else {
        (FilterProtocol::Any, normalized)
    };
    let range = parse_port_range_token(port_spec, original)?;
    Ok(PacketFilterRule {
        source_peer_ip: None,
        protocol,
        dst_ports: Some(range),
    })
}

fn parse_port_range_token(token: &str, original: &str) -> AppResult<PortRange> {
    if token.is_empty() {
        return Err(AppError::invalid_argument(format!(
            "missing port number in inbound filter rule '{original}'"
        )));
    }
    if let Some((start_raw, end_raw)) = token.split_once('-') {
        let start = start_raw.trim().parse::<u16>().map_err(|_| {
            AppError::invalid_argument(format!("invalid start port in filter rule '{original}'"))
        })?;
        let end = end_raw.trim().parse::<u16>().map_err(|_| {
            AppError::invalid_argument(format!("invalid end port in filter rule '{original}'"))
        })?;
        if start == 0 || end == 0 {
            return Err(AppError::invalid_argument(format!(
                "port 0 is forbidden in filter rule '{original}'"
            )));
        }
        return PortRange::new(start, end).ok_or_else(|| {
            AppError::invalid_argument(format!("inverted port range in filter rule '{original}'"))
        });
    }
    let port = token.parse::<u16>().map_err(|_| {
        AppError::invalid_argument(format!("invalid port in filter rule '{original}'"))
    })?;
    if port == 0 {
        return Err(AppError::invalid_argument(format!(
            "port 0 is forbidden in filter rule '{original}'"
        )));
    }
    Ok(PortRange::single(port))
}

/// Reason a decapsulated or outbound tunnel packet was dropped by `CryptokeyValidator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptokeyDropReason {
    /// Packet was truncated or had an invalid IPv4 header length / total length.
    MalformedPacket,
    /// Inner packet IP version was not IPv4.
    UnsupportedIpVersion(u8),
    /// Decapsulated inner source IPv4 address did not match the peer's locked `/32` overlay IP.
    SpoofedSourceIp {
        /// Expected peer `/32` overlay IP.
        expected: Ipv4Addr,
        /// Observed spoofed source IP inside the decrypted payload.
        observed: Ipv4Addr,
    },
    /// Inbound packet source IP was accepted, but destination fell outside `overlay_cidr`.
    NonOverlayDestination(Ipv4Addr),
    /// Inbound packet was inside `overlay_cidr`, but not addressed to the local node IP.
    DestinationNotLocal {
        /// Local node overlay IP.
        expected: Ipv4Addr,
        /// Observed destination IP inside the decrypted payload.
        observed: Ipv4Addr,
    },
    /// Outbound TUN packet did not originate from the local overlay IP.
    NonOverlaySource(Ipv4Addr),
    /// Packet did not match the active `PacketFilterPolicy` allow rules.
    PolicyDenied,
}

/// Point-in-time snapshot of `CryptokeyValidator` drop counters for metrics/diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CryptokeyMetricsSnapshot {
    /// Total inbound packets dropped for spoofed inner source IP (`mesh_agent_spoofed_packets_dropped_total`).
    pub spoofed_packets_dropped: u64,
    /// Total malformed or non-IPv4 inner packets dropped.
    pub malformed_packets_dropped: u64,
    /// Total packets dropped because source or destination was outside allowed overlay bounds.
    pub non_overlay_packets_dropped: u64,
    /// Total valid overlay packets dropped by `PacketFilterPolicy`.
    pub filtered_packets_dropped: u64,
}

#[derive(Debug, Default)]
struct CryptokeyMetrics {
    spoofed_packets_dropped: AtomicU64,
    malformed_packets_dropped: AtomicU64,
    non_overlay_packets_dropped: AtomicU64,
    filtered_packets_dropped: AtomicU64,
}

impl CryptokeyMetrics {
    fn snapshot(&self) -> CryptokeyMetricsSnapshot {
        CryptokeyMetricsSnapshot {
            spoofed_packets_dropped: self.spoofed_packets_dropped.load(Ordering::Relaxed),
            malformed_packets_dropped: self.malformed_packets_dropped.load(Ordering::Relaxed),
            non_overlay_packets_dropped: self.non_overlay_packets_dropped.load(Ordering::Relaxed),
            filtered_packets_dropped: self.filtered_packets_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Enforces strict WireGuard `/32` inner source/destination checks (`SEC-11`, `US-014 AC4`, `US-018`).
#[derive(Debug, Default)]
pub struct CryptokeyValidator {
    policy: PacketFilterPolicy,
    metrics: CryptokeyMetrics,
}

impl CryptokeyValidator {
    /// Creates a validator with the default `AllowAllOverlay` policy after `/32` checks.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a validator configured with an explicit `PacketFilterPolicy`.
    #[must_use]
    pub fn with_policy(policy: PacketFilterPolicy) -> Self {
        Self {
            policy,
            metrics: CryptokeyMetrics::default(),
        }
    }

    /// Replaces the active packet filter policy (for atomic fail-closed reloads).
    pub fn set_policy(&mut self, policy: PacketFilterPolicy) {
        self.policy = policy;
    }

    /// Returns a reference to the active inbound packet filter policy (`US-018`).
    #[must_use]
    pub const fn policy(&self) -> &PacketFilterPolicy {
        &self.policy
    }

    /// Parses and atomically applies an inbound filter specification (`US-018 AC4`).
    ///
    /// Rejecting invalid syntax logs an `error` event and **preserves the previous valid
    /// policy** without leaving the tunnel unprotected or breaking active flows.
    pub fn try_reload_policy_spec(&mut self, spec: &str) -> AppResult<()> {
        match parse_inbound_filter_spec(spec) {
            Ok(next_policy) => {
                self.policy = next_policy;
                Ok(())
            }
            Err(err) => {
                error!(
                    component = "datapath.cryptokey",
                    event = "inbound_filter_reload_rejected",
                    error = %err,
                    "rejected invalid inbound filter configuration; preserving previous policy"
                );
                Err(err)
            }
        }
    }

    /// Returns true when `observed_src` equals the peer's locked `/32` `expected_peer_ip`.
    #[must_use]
    pub fn matches_peer_source(expected_peer_ip: OverlayIp, observed_src: OverlayIp) -> bool {
        expected_peer_ip == observed_src
    }

    /// Validates an inbound IPv4 packet right after `Tunn::decapsulate` (`SEC-11`, `US-014 AC4`).
    ///
    /// Rejects any packet whose inner source IPv4 differs from `expected_peer_ip` (`/32`), whose
    /// destination falls outside `overlay_cidr` (or differs from `local_overlay_ip` when given),
    /// or that fails `PacketFilterPolicy`.
    pub fn validate_inbound(
        &self,
        expected_peer_ip: OverlayIp,
        local_overlay_ip: Option<OverlayIp>,
        overlay_cidr: OverlayCidr,
        packet: &[u8],
    ) -> Result<ParsedIpv4Header, CryptokeyDropReason> {
        let header = match parse_ipv4_packet(packet) {
            Ok(parsed) => parsed,
            Err(reason) => {
                self.metrics
                    .malformed_packets_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return Err(reason);
            }
        };

        let expected_src = expected_peer_ip.as_ipv4();
        if header.src_ip != expected_src {
            self.metrics
                .spoofed_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                component = "datapath.cryptokey",
                event = "spoofed_inner_source_ip",
                expected_src = %expected_src,
                observed_src = %header.src_ip,
                "dropping decapsulated packet with spoofed inner source IP"
            );
            return Err(CryptokeyDropReason::SpoofedSourceIp {
                expected: expected_src,
                observed: header.src_ip,
            });
        }

        let Ok(dst_overlay) = OverlayIp::from_ipv4(header.dst_ip) else {
            self.metrics
                .non_overlay_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(CryptokeyDropReason::NonOverlayDestination(header.dst_ip));
        };
        if !overlay_cidr.contains_usable_host(dst_overlay) {
            self.metrics
                .non_overlay_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(CryptokeyDropReason::NonOverlayDestination(header.dst_ip));
        }

        if let Some(local_ip) = local_overlay_ip
            && header.dst_ip != local_ip.as_ipv4()
        {
            self.metrics
                .non_overlay_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(CryptokeyDropReason::DestinationNotLocal {
                expected: local_ip.as_ipv4(),
                observed: header.dst_ip,
            });
        }

        if !self.policy.allows(&header) {
            self.metrics
                .filtered_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(CryptokeyDropReason::PolicyDenied);
        }

        Ok(header)
    }

    /// Validates an outbound IPv4 packet read from the TUN interface before peer lookup.
    pub fn validate_outbound(
        &self,
        local_overlay_ip: OverlayIp,
        overlay_cidr: OverlayCidr,
        packet: &[u8],
    ) -> Result<ParsedIpv4Header, CryptokeyDropReason> {
        let header = match parse_ipv4_packet(packet) {
            Ok(parsed) => parsed,
            Err(reason) => {
                self.metrics
                    .malformed_packets_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return Err(reason);
            }
        };

        if header.src_ip != local_overlay_ip.as_ipv4() {
            self.metrics
                .non_overlay_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(CryptokeyDropReason::NonOverlaySource(header.src_ip));
        }

        let Ok(dst_overlay) = OverlayIp::from_ipv4(header.dst_ip) else {
            self.metrics
                .non_overlay_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(CryptokeyDropReason::NonOverlayDestination(header.dst_ip));
        };
        if !overlay_cidr.contains_usable_host(dst_overlay) {
            self.metrics
                .non_overlay_packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Err(CryptokeyDropReason::NonOverlayDestination(header.dst_ip));
        }

        Ok(header)
    }

    /// Returns the total spoofed inner-source packets dropped so far.
    #[must_use]
    pub fn spoofed_packets_dropped(&self) -> u64 {
        self.metrics.spoofed_packets_dropped.load(Ordering::Relaxed)
    }

    /// Returns an immutable snapshot of all cryptokey drop counters.
    #[must_use]
    pub fn metrics_snapshot(&self) -> CryptokeyMetricsSnapshot {
        self.metrics.snapshot()
    }
}

/// Parses an inner IPv4 header strictly with bounds-checked `.get(...)` slicing.
pub fn parse_ipv4_packet(packet: &[u8]) -> Result<ParsedIpv4Header, CryptokeyDropReason> {
    let first = *packet.first().ok_or(CryptokeyDropReason::MalformedPacket)?;
    let version = first >> 4;
    if version != 4 {
        return Err(CryptokeyDropReason::UnsupportedIpVersion(version));
    }

    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(CryptokeyDropReason::MalformedPacket);
    }

    let ihl_bytes = usize::from(first & 0x0f).saturating_mul(4);
    if ihl_bytes < IPV4_MIN_HEADER_LEN || ihl_bytes > packet.len() {
        return Err(CryptokeyDropReason::MalformedPacket);
    }

    let total_len = usize::from(read_be_u16(packet, 2)?);
    if total_len < ihl_bytes || total_len > packet.len() {
        return Err(CryptokeyDropReason::MalformedPacket);
    }

    let flags_frag = read_be_u16(packet, 6)?;
    let is_non_initial_fragment = (flags_frag & 0x1fff) != 0;
    let protocol = *packet.get(9).ok_or(CryptokeyDropReason::MalformedPacket)?;
    let src_ip = read_ipv4_addr(packet, 12)?;
    let dst_ip = read_ipv4_addr(packet, 16)?;

    let dst_port = if !is_non_initial_fragment
        && (protocol == PROTO_TCP || protocol == PROTO_UDP)
        && total_len >= ihl_bytes.saturating_add(4)
    {
        read_be_u16(packet, ihl_bytes.saturating_add(2)).ok()
    } else {
        None
    };

    Ok(ParsedIpv4Header {
        src_ip,
        dst_ip,
        protocol,
        ihl_bytes,
        total_len,
        dst_port,
        is_non_initial_fragment,
    })
}

fn read_be_u16(buf: &[u8], offset: usize) -> Result<u16, CryptokeyDropReason> {
    let hi = *buf
        .get(offset)
        .ok_or(CryptokeyDropReason::MalformedPacket)?;
    let lo = *buf
        .get(offset.saturating_add(1))
        .ok_or(CryptokeyDropReason::MalformedPacket)?;
    Ok(u16::from_be_bytes([hi, lo]))
}

fn read_ipv4_addr(buf: &[u8], offset: usize) -> Result<Ipv4Addr, CryptokeyDropReason> {
    let a = *buf
        .get(offset)
        .ok_or(CryptokeyDropReason::MalformedPacket)?;
    let b = *buf
        .get(offset.saturating_add(1))
        .ok_or(CryptokeyDropReason::MalformedPacket)?;
    let c = *buf
        .get(offset.saturating_add(2))
        .ok_or(CryptokeyDropReason::MalformedPacket)?;
    let d = *buf
        .get(offset.saturating_add(3))
        .ok_or(CryptokeyDropReason::MalformedPacket)?;
    Ok(Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay_ip(last_octet: u8) -> OverlayIp {
        OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, last_octet)).expect("valid overlay ip")
    }

    fn overlay_cidr() -> OverlayCidr {
        "10.100.0.0/16".parse().expect("valid cidr")
    }

    fn build_ipv4_udp_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(28);
        pkt.extend_from_slice(&[0x45, 0]);
        pkt.extend_from_slice(&28u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 5]);
        pkt.push(PROTO_UDP);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 2]);
        pkt
    }

    // Traces: US-014, SEC-11
    #[test]
    fn test_cryptokey_valid_inbound_packet_succeeds() {
        // Arrange
        let validator = CryptokeyValidator::new();
        let peer_ip = overlay_ip(10);
        let local_ip = overlay_ip(2);
        let packet = build_ipv4_udp_packet(peer_ip.as_ipv4(), local_ip.as_ipv4(), 5000, 8080);

        // Act
        let parsed = validator.validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &packet);

        // Assert
        let header = parsed.expect("valid packet should pass");
        assert_eq!(header.src_ip, peer_ip.as_ipv4());
        assert_eq!(header.dst_ip, local_ip.as_ipv4());
        assert_eq!(header.dst_port, Some(8080));
        assert_eq!(validator.spoofed_packets_dropped(), 0);
    }

    // Traces: US-014, SEC-11
    #[test]
    fn test_cryptokey_spoofed_inner_source_ip_is_dropped_and_counted() {
        // Arrange
        let validator = CryptokeyValidator::new();
        let assigned_peer_ip = overlay_ip(10);
        let spoofed_peer_ip = overlay_ip(11);
        let local_ip = overlay_ip(2);
        let packet =
            build_ipv4_udp_packet(spoofed_peer_ip.as_ipv4(), local_ip.as_ipv4(), 5000, 8080);

        // Act
        let result =
            validator.validate_inbound(assigned_peer_ip, Some(local_ip), overlay_cidr(), &packet);

        // Assert
        assert_eq!(
            result,
            Err(CryptokeyDropReason::SpoofedSourceIp {
                expected: assigned_peer_ip.as_ipv4(),
                observed: spoofed_peer_ip.as_ipv4(),
            })
        );
        assert_eq!(validator.spoofed_packets_dropped(), 1);
    }

    // Traces: US-014, SEC-11
    #[test]
    fn test_cryptokey_non_overlay_destination_is_dropped() {
        // Arrange
        let validator = CryptokeyValidator::new();
        let peer_ip = overlay_ip(10);
        let packet = build_ipv4_udp_packet(peer_ip.as_ipv4(), Ipv4Addr::new(8, 8, 8, 8), 5000, 53);

        // Act
        let result = validator.validate_inbound(peer_ip, None, overlay_cidr(), &packet);

        // Assert
        assert_eq!(
            result,
            Err(CryptokeyDropReason::NonOverlayDestination(Ipv4Addr::new(
                8, 8, 8, 8
            )))
        );
        assert_eq!(validator.metrics_snapshot().non_overlay_packets_dropped, 1);
    }

    // Traces: US-018
    #[test]
    fn test_cryptokey_packet_filter_enforces_allow_rules_and_fail_closed() {
        // Arrange
        let rule = PacketFilterRule {
            source_peer_ip: None,
            protocol: FilterProtocol::Udp,
            dst_ports: Some(PortRange::single(8080)),
        };
        let mut validator =
            CryptokeyValidator::with_policy(PacketFilterPolicy::AllowRules(vec![rule]));
        let peer_ip = overlay_ip(10);
        let local_ip = overlay_ip(2);
        let allowed_pkt = build_ipv4_udp_packet(peer_ip.as_ipv4(), local_ip.as_ipv4(), 5000, 8080);
        let denied_pkt = build_ipv4_udp_packet(peer_ip.as_ipv4(), local_ip.as_ipv4(), 5000, 22);

        // Act & Assert allow + deny
        assert!(
            validator
                .validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &allowed_pkt)
                .is_ok()
        );
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &denied_pkt),
            Err(CryptokeyDropReason::PolicyDenied)
        );

        // Act & Assert fail-closed rejects even previously allowed traffic
        validator.set_policy(PacketFilterPolicy::FailClosed);
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &allowed_pkt),
            Err(CryptokeyDropReason::PolicyDenied)
        );
        assert_eq!(validator.metrics_snapshot().filtered_packets_dropped, 2);
    }

    // Traces: US-018
    #[test]
    fn test_cryptokey_deny_rules_and_fail_safe_reload_preserves_previous_policy() {
        // Arrange: default allows all, then load block rule for port 3389
        let mut validator = CryptokeyValidator::new();
        let peer_ip = overlay_ip(10);
        let local_ip = overlay_ip(2);
        let pkt_3389 = build_ipv4_udp_packet(peer_ip.as_ipv4(), local_ip.as_ipv4(), 50000, 3389);
        let pkt_22 = build_ipv4_udp_packet(peer_ip.as_ipv4(), local_ip.as_ipv4(), 50000, 22);

        validator
            .try_reload_policy_spec("3389,tcp:8443-8444")
            .expect("valid blocklist");

        // Act & Assert: 3389 blocked, 22 allowed
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &pkt_3389),
            Err(CryptokeyDropReason::PolicyDenied)
        );
        assert!(
            validator
                .validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &pkt_22)
                .is_ok()
        );

        // Invalid reload MUST fail cleanly AND preserve previous blocklist!
        let err = validator
            .try_reload_policy_spec("tcp:notaport,99999")
            .expect_err("invalid rule must error");
        assert!(err.to_string().contains("invalid port"));
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &pkt_3389),
            Err(CryptokeyDropReason::PolicyDenied)
        );
        assert!(
            validator
                .validate_inbound(peer_ip, Some(local_ip), overlay_cidr(), &pkt_22)
                .is_ok()
        );
    }
}
