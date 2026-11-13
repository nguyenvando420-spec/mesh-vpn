//! Validated domain newtypes parsed strictly at trust boundaries.

use std::fmt;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use rand::RngCore as _;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::brand::RESERVED_HOSTNAMES;
use crate::error::{AppError, AppResult};

/// Validated UUIDv4/v7 identifier for a registered Mesh node.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 16]);

/// Validated UUIDv4/v7 identifier for an authentication or pre-auth key record.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; 16]);

impl NodeId {
    /// Generates a new random RFC 9562 UUIDv7 identifier stamped at `now_unix_ms`.
    #[must_use]
    pub fn new_v7(now_unix_ms: u64) -> Self {
        Self(generate_uuid_v7(now_unix_ms))
    }

    /// Wraps raw 16 UUID bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 16 UUID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl KeyId {
    /// Generates a new random RFC 9562 UUIDv7 identifier stamped at `now_unix_ms`.
    #[must_use]
    pub fn new_v7(now_unix_ms: u64) -> Self {
        Self(generate_uuid_v7(now_unix_ms))
    }

    /// Wraps raw 16 UUID bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 16 UUID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

macro_rules! impl_uuid_traits {
    ($ty:ident, $label:literal) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", $label, format_uuid_bytes(&self.0))
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&format_uuid_bytes(&self.0))
            }
        }

        impl FromStr for $ty {
            type Err = AppError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_uuid_bytes(s).map(Self)
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&format_uuid_bytes(&self.0))
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::from_str(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_uuid_traits!(NodeId, "NodeId");
impl_uuid_traits!(KeyId, "KeyId");

fn generate_uuid_v7(now_unix_ms: u64) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let ts_bytes = now_unix_ms.to_be_bytes();
    if let (Some(dst), Some(src)) = (bytes.get_mut(..6), ts_bytes.get(2..8)) {
        dst.copy_from_slice(src);
    }
    if let Some(ver) = bytes.get_mut(6) {
        *ver = (*ver & 0x0f) | 0x70;
    }
    if let Some(var) = bytes.get_mut(8) {
        *var = (*var & 0x3f) | 0x80;
    }
    bytes
}

fn format_uuid_bytes(bytes: &[u8; 16]) -> String {
    let hex = HEXLOWER.encode(bytes);
    let (p1, r1) = hex.split_at_checked(8).unwrap_or((&hex, ""));
    let (p2, r2) = r1.split_at_checked(4).unwrap_or((r1, ""));
    let (p3, r3) = r2.split_at_checked(4).unwrap_or((r2, ""));
    let (p4, p5) = r3.split_at_checked(4).unwrap_or((r3, ""));
    format!("{p1}-{p2}-{p3}-{p4}-{p5}")
}

fn parse_uuid_bytes(raw: &str) -> AppResult<[u8; 16]> {
    let mut parts = raw.split('-');
    let expected_lens = [8_usize, 4, 4, 4, 12];
    let mut compact = String::with_capacity(32);
    for expected in expected_lens {
        let Some(part) = parts.next() else {
            return Err(AppError::invalid_argument("invalid UUID: missing segment"));
        };
        if part.len() != expected || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AppError::invalid_argument(
                "invalid UUID: malformed hex segment",
            ));
        }
        compact.push_str(part);
    }
    if parts.next().is_some() {
        return Err(AppError::invalid_argument(
            "invalid UUID: trailing segments",
        ));
    }
    let decoded = HEXLOWER_PERMISSIVE
        .decode(compact.as_bytes())
        .map_err(|_| AppError::invalid_argument("invalid UUID: hex decode failed"))?;
    <[u8; 16]>::try_from(decoded.as_slice())
        .map_err(|_| AppError::invalid_argument("invalid UUID: wrong byte length"))
}

/// Validated RFC 1123 single-label hostname (`1..=63` lowercase `[a-z0-9-]`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeName(String);

impl NodeName {
    /// Parses and normalizes a node hostname according to RFC 1123 and hosts-file safety rules.
    pub fn parse(raw: &str) -> AppResult<Self> {
        if raw.len() != raw.trim().len() || raw.contains(['\n', '\r', '#', ' ', '\t']) {
            return Err(AppError::invalid_argument(
                "invalid node name: contains forbidden whitespace or comment characters",
            ));
        }
        if raw.is_empty() || raw.len() > 63 {
            return Err(AppError::invalid_argument(
                "invalid node name: length must be 1..=63 characters",
            ));
        }
        let normalized = raw.to_ascii_lowercase();
        let bytes = normalized.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err(AppError::invalid_argument("invalid node name: empty"));
        };
        let Some(&last) = bytes.last() else {
            return Err(AppError::invalid_argument("invalid node name: empty"));
        };
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return Err(AppError::invalid_argument(
                "invalid node name: must start and end with ASCII letter or digit",
            ));
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err(AppError::invalid_argument(
                "invalid node name: allowed characters are [a-z0-9-]",
            ));
        }
        if RESERVED_HOSTNAMES.contains(&normalized.as_str()) {
            return Err(AppError::invalid_argument(format!(
                "invalid node name: reserved hostname `{normalized}`"
            )));
        }
        Ok(Self(normalized))
    }

    /// Rejects registration if this node name collides with the server's configured `public_host`.
    pub fn validate_against_public_host(
        &self,
        public_host: &str,
        domain_suffix: &str,
    ) -> AppResult<()> {
        let host = public_host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(AppError::invalid_argument(
                "public_host must not be empty when validating node name",
            ));
        }
        let fqdn = self.fqdn(domain_suffix);
        if self.0 == host || fqdn == host {
            return Err(AppError::invalid_argument(format!(
                "node name `{}` collides with control server public host",
                self.0
            )));
        }
        Ok(())
    }

    /// Returns the normalized lowercase node label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Formats the FQDN `<node>.<domain_suffix>`.
    #[must_use]
    pub fn fqdn(&self, domain_suffix: &str) -> String {
        let suffix = domain_suffix
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() {
            self.0.clone()
        } else {
            format!("{}.{}", self.0, suffix)
        }
    }
}

impl fmt::Display for NodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NodeName {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for NodeName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NodeName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Validated non-reserved unicast IPv4 address allocated within the overlay network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OverlayIp(Ipv4Addr);

impl OverlayIp {
    /// Wraps an [`Ipv4Addr`] after rejecting unspecified, loopback, link-local, and multicast IPs.
    pub fn from_ipv4(addr: Ipv4Addr) -> AppResult<Self> {
        let bits = u32::from(addr);
        if addr.is_unspecified()
            || addr.is_loopback()
            || addr.is_link_local()
            || addr.is_multicast()
            || addr.is_broadcast()
            || bits >= 0xF000_0000
        {
            return Err(AppError::invalid_argument(format!(
                "invalid overlay IP `{addr}`: reserved IPv4 range"
            )));
        }
        Ok(Self(addr))
    }

    /// Returns the underlying IPv4 address.
    #[must_use]
    pub const fn as_ipv4(self) -> Ipv4Addr {
        self.0
    }
}

impl fmt::Display for OverlayIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for OverlayIp {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = Ipv4Addr::from_str(s)
            .map_err(|_| AppError::invalid_argument("invalid overlay IPv4 address syntax"))?;
        Self::from_ipv4(addr)
    }
}

impl Serialize for OverlayIp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for OverlayIp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// Validated IPv4 overlay CIDR block enforcing minimum capacity (`>= 64` usable hosts)
/// and exclusion of system/reserved address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OverlayCidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl OverlayCidr {
    /// Parses and validates an IPv4 CIDR string (e.g. `"100.115.0.0/16"`).
    pub fn parse(raw: &str) -> AppResult<Self> {
        let Some((ip_part, prefix_part)) = raw.split_once('/') else {
            return Err(AppError::invalid_argument(
                "invalid overlay CIDR: missing '/' prefix",
            ));
        };
        let addr = Ipv4Addr::from_str(ip_part)
            .map_err(|_| AppError::invalid_argument("invalid overlay CIDR: bad IPv4 address"))?;
        let prefix_len: u8 = prefix_part
            .parse()
            .map_err(|_| AppError::invalid_argument("invalid overlay CIDR: bad prefix length"))?;
        if !(8..=25).contains(&prefix_len) {
            return Err(AppError::invalid_argument(
                "invalid overlay CIDR: prefix must be /8../25 (>= 64 usable hosts)",
            ));
        }
        let mask = prefix_mask(prefix_len);
        let addr_u32 = u32::from(addr);
        if (addr_u32 & mask) != addr_u32 {
            return Err(AppError::invalid_argument(
                "invalid overlay CIDR: host bits must be zero",
            ));
        }
        let candidate = Self {
            network: addr,
            prefix_len,
        };
        candidate.validate_reserved_ranges()?;
        Ok(candidate)
    }

    fn validate_reserved_ranges(self) -> AppResult<()> {
        let reserved = [
            (Ipv4Addr::new(0, 0, 0, 0), 8_u8),
            (Ipv4Addr::new(127, 0, 0, 0), 8_u8),
            (Ipv4Addr::new(169, 254, 0, 0), 16_u8),
            (Ipv4Addr::new(224, 0, 0, 0), 4_u8),
            (Ipv4Addr::new(240, 0, 0, 0), 4_u8),
        ];
        for (net, prefix) in reserved {
            if self.overlaps_raw(net, prefix) {
                return Err(AppError::invalid_argument(format!(
                    "invalid overlay CIDR `{self}` overlaps reserved range {net}/{prefix}"
                )));
            }
        }
        Ok(())
    }

    /// Returns `true` if this CIDR overlaps RFC 6598 CGNAT (`100.64.0.0/10`) (`US-008 AC4`).
    #[must_use]
    pub fn overlaps_cgnat(self) -> bool {
        self.overlaps_raw(Ipv4Addr::new(100, 64, 0, 0), 10)
    }

    /// Returns `true` if `ip` falls inside this CIDR network prefix (including network/broadcast).
    ///
    /// Use this for rejecting underlay candidates inside the overlay subnet (`endpoint_filter`).
    #[must_use]
    pub fn contains_subnet_ip(self, ip: Ipv4Addr) -> bool {
        let mask = prefix_mask(self.prefix_len);
        (u32::from(ip) & mask) == u32::from(self.network)
    }

    /// Returns `true` if `ip` is a usable host address inside this CIDR, excluding network and
    /// directed broadcast addresses when `prefix_len <= 30`.
    #[must_use]
    pub fn contains_usable_host(self, ip: OverlayIp) -> bool {
        let addr_u32 = u32::from(ip.as_ipv4());
        let mask = prefix_mask(self.prefix_len);
        let net_u32 = u32::from(self.network);
        if (addr_u32 & mask) != net_u32 {
            return false;
        }
        if self.prefix_len <= 30 {
            let bcast_u32 = net_u32 | !mask;
            return addr_u32 != net_u32 && addr_u32 != bcast_u32;
        }
        true
    }

    /// Returns `true` if `ip` is a usable host address inside this CIDR (alias for [`Self::contains_usable_host`]).
    #[must_use]
    pub fn contains(self, ip: OverlayIp) -> bool {
        self.contains_usable_host(ip)
    }

    /// Returns the number of usable host addresses (excluding network and broadcast).
    #[must_use]
    pub const fn usable_host_count(self) -> u32 {
        let host_bits = 32_u32.saturating_sub(self.prefix_len as u32);
        let total = 1_u32 << host_bits;
        total.saturating_sub(2)
    }

    /// Returns the `index`-th usable host IP (`0` yields `network + 1`).
    #[must_use]
    pub fn nth_usable_ip(self, index: u32) -> Option<OverlayIp> {
        if index >= self.usable_host_count() {
            return None;
        }
        let host_u32 = u32::from(self.network).checked_add(1)?.checked_add(index)?;
        OverlayIp::from_ipv4(Ipv4Addr::from(host_u32)).ok()
    }

    /// Returns the base network address.
    #[must_use]
    pub const fn network(self) -> Ipv4Addr {
        self.network
    }

    /// Returns the CIDR prefix length.
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    fn overlaps_raw(self, other_net: Ipv4Addr, other_prefix: u8) -> bool {
        let common_prefix = self.prefix_len.min(other_prefix);
        let mask = prefix_mask(common_prefix);
        (u32::from(self.network) & mask) == (u32::from(other_net) & mask)
    }
}

const fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

impl fmt::Display for OverlayCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for OverlayCidr {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for OverlayCidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OverlayCidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Validated non-zero TCP/UDP port (`1..=65535`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(NonZeroU16);

impl Port {
    /// Creates a [`Port`] from a compile-time or validated [`NonZeroU16`].
    #[must_use]
    pub const fn from_non_zero(port: NonZeroU16) -> Self {
        Self(port)
    }

    /// Validates a `u16`, rejecting port `0`.
    pub fn from_u16(value: u16) -> AppResult<Self> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or_else(|| AppError::invalid_argument("port must be between 1 and 65535"))
    }

    /// Returns the numeric `u16` value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Port {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw: u16 = s
            .parse()
            .map_err(|_| AppError::invalid_argument("invalid TCP/UDP port integer"))?;
        Self::from_u16(raw)
    }
}

impl Serialize for Port {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.0.get())
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u16::deserialize(deserializer)?;
        Self::from_u16(raw).map_err(serde::de::Error::custom)
    }
}

/// Validated 32-byte X25519 public key (WireGuard NodeKey or Disco public key).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

/// Canonical and non-canonical Curve25519 low-order torsion u-coordinates (`RFC 7748` §6.1).
const CURVE25519_LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    [0x00_u8; 32],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

impl PublicKey {
    /// Wraps 32 public key bytes after rejecting all Curve25519 low-order torsion points.
    pub fn from_bytes(bytes: [u8; 32]) -> AppResult<Self> {
        let mut masked = bytes;
        if let Some(msb) = masked.last_mut() {
            *msb &= 0x7f;
        }
        if CURVE25519_LOW_ORDER_POINTS
            .iter()
            .any(|low_order| low_order == &masked)
        {
            return Err(AppError::invalid_argument(
                "invalid public key: low-order Curve25519 point rejected",
            ));
        }
        Ok(Self(bytes))
    }

    /// Parses either standard 44-char Base64 or 64-char hex representation.
    pub fn parse(raw: &str) -> AppResult<Self> {
        let bytes = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            let decoded = HEXLOWER_PERMISSIVE
                .decode(raw.as_bytes())
                .map_err(|_| AppError::invalid_argument("invalid hex public key"))?;
            <[u8; 32]>::try_from(decoded.as_slice())
                .map_err(|_| AppError::invalid_argument("public key must decode to 32 bytes"))?
        } else {
            let decoded = BASE64_STANDARD
                .decode(raw)
                .map_err(|_| AppError::invalid_argument("invalid base64 public key"))?;
            <[u8; 32]>::try_from(decoded.as_slice())
                .map_err(|_| AppError::invalid_argument("public key must decode to 32 bytes"))?
        };
        Self::from_bytes(bytes)
    }

    /// Returns the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Formats the key as canonical 44-character Base64.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.0)
    }

    /// Formats the key as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        HEXLOWER.encode(&self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

impl FromStr for PublicKey {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Validated TLS certificate SPKI SHA-256 fingerprint (`"sha256:<64_lowercase_hex>"`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpkiPin([u8; 32]);

impl SpkiPin {
    /// Wraps a raw 32-byte SHA-256 SPKI digest.
    #[must_use]
    pub const fn from_sha256_bytes(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Parses `"sha256:<64_lowercase_hex>"` strictly rejecting uppercase hex or missing prefix.
    pub fn parse(raw: &str) -> AppResult<Self> {
        let Some(hex_part) = raw.strip_prefix("sha256:") else {
            return Err(AppError::invalid_argument(
                "invalid SPKI pin: must begin with `sha256:`",
            ));
        };
        if hex_part.len() != 64
            || !hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(AppError::invalid_argument(
                "invalid SPKI pin: digest must be 64 lowercase hexadecimal characters",
            ));
        }
        let decoded = HEXLOWER
            .decode(hex_part.as_bytes())
            .map_err(|_| AppError::invalid_argument("invalid SPKI pin hex"))?;
        let arr = <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| AppError::invalid_argument("invalid SPKI pin digest length"))?;
        Ok(Self(arr))
    }

    /// Returns the raw 32-byte SHA-256 SPKI digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpkiPin({self})")
    }
}

impl fmt::Display for SpkiPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", HEXLOWER.encode(&self.0))
    }
}

impl FromStr for SpkiPin {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for SpkiPin {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SpkiPin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr as _;

    use proptest::prelude::*;

    use super::{KeyId, NodeId, NodeName, OverlayCidr, OverlayIp, Port, PublicKey, SpkiPin};

    #[test]
    fn test_node_id_and_key_id_v7_roundtrip() {
        // Arrange
        let node_id = NodeId::new_v7(1_731_480_000_000);
        let key_id = KeyId::new_v7(1_731_480_000_000);

        // Act
        let node_str = node_id.to_string();
        let parsed_node = NodeId::from_str(&node_str);
        let parsed_key = KeyId::from_str(&key_id.to_string());

        // Assert
        assert_eq!(parsed_node.ok(), Some(node_id));
        assert_eq!(parsed_key.ok(), Some(key_id));
        assert_eq!(node_str.len(), 36);
    }

    #[test]
    fn test_node_name_rejects_reserved_and_public_host_collision() {
        // Arrange
        let reserved = [
            "localhost",
            "LOCALHOST",
            "wpad",
            "broadcasthost",
            "isatap",
            "local",
        ];

        // Act & Assert
        for item in reserved {
            assert!(NodeName::parse(item).is_err());
        }
        assert!(NodeName::parse("laptop-1\n1.2.3.4 evil").is_err());
        assert!(NodeName::parse("-bad").is_err());
        assert!(NodeName::parse("bad-").is_err());
        if let Ok(valid) = NodeName::parse("Alice-Mac") {
            assert_eq!(valid.as_str(), "alice-mac");
            assert_eq!(valid.fqdn("mesh.internal"), "alice-mac.mesh.internal");
            assert!(
                valid
                    .validate_against_public_host("alice-mac.mesh.internal", "mesh.internal")
                    .is_err()
            );
            assert!(
                valid
                    .validate_against_public_host("vpn.example.com", "mesh.internal")
                    .is_ok()
            );
        }
    }

    #[test]
    fn test_overlay_cidr_validation_and_cgnat_detection() {
        // Arrange & Act
        let valid_default = OverlayCidr::parse("100.115.0.0/16");
        let valid_slash25 = OverlayCidr::parse("10.200.0.0/25");
        let too_small_slash26 = OverlayCidr::parse("10.200.0.0/26");
        let loopback = OverlayCidr::parse("127.0.0.0/8");
        let link_local = OverlayCidr::parse("169.254.0.0/16");
        let multicast = OverlayCidr::parse("224.0.0.0/8");

        // Assert
        if let Ok(cidr) = valid_default {
            assert!(cidr.overlaps_cgnat());
            assert_eq!(cidr.usable_host_count(), 65_534);
            assert_eq!(
                cidr.nth_usable_ip(0).map(OverlayIp::as_ipv4),
                Some(Ipv4Addr::new(100, 115, 0, 1))
            );
            assert!(cidr.contains_subnet_ip(Ipv4Addr::new(100, 115, 0, 0)));
            assert!(cidr.contains_subnet_ip(Ipv4Addr::new(100, 115, 255, 255)));
            if let Ok(net_ip) = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 0)) {
                assert!(!cidr.contains_usable_host(net_ip));
            }
            if let Ok(bcast_ip) = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 255, 255)) {
                assert!(!cidr.contains_usable_host(bcast_ip));
            }
            if let Ok(host_ip) = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 2)) {
                assert!(cidr.contains_usable_host(host_ip));
            }
        } else {
            assert!(valid_default.is_ok());
        }
        assert!(valid_slash25.is_ok());
        if let Ok(non_cgnat) = valid_slash25 {
            assert!(!non_cgnat.overlaps_cgnat());
            assert_eq!(non_cgnat.usable_host_count(), 126);
        }
        assert!(too_small_slash26.is_err());
        assert!(loopback.is_err());
        assert!(link_local.is_err());
        assert!(multicast.is_err());
        assert!(Port::from_u16(0).is_err());
        assert_eq!(Port::from_u16(8443).map(Port::get).ok(), Some(8443));
    }

    #[test]
    fn test_public_key_and_spki_pin_reject_malformed_inputs() {
        // Arrange
        let valid_bytes = [0x2a_u8; 32];
        let low_order_one = {
            let mut b = [0_u8; 32];
            if let Some(first) = b.first_mut() {
                *first = 1;
            }
            b
        };
        let low_order_e0eb = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        let mut low_order_p_msb_set = [0xff_u8; 32];
        if let Some(first) = low_order_p_msb_set.first_mut() {
            *first = 0xed;
        }
        let mut p_plus_1_msb_set = [0xff_u8; 32];
        if let Some(first) = p_plus_1_msb_set.first_mut() {
            *first = 0xee;
        }

        // Act
        let pk_result = PublicKey::from_bytes(valid_bytes);
        let pin = SpkiPin::from_sha256_bytes([0xab_u8; 32]);

        // Assert
        assert!(PublicKey::from_bytes([0_u8; 32]).is_err());
        assert!(PublicKey::from_bytes(low_order_one).is_err());
        assert!(PublicKey::from_bytes(low_order_e0eb).is_err());
        assert!(PublicKey::from_bytes(low_order_p_msb_set).is_err());
        assert!(PublicKey::from_bytes(p_plus_1_msb_set).is_err());
        if let Ok(pk) = pk_result {
            assert_eq!(PublicKey::parse(&pk.to_base64()).ok(), Some(pk));
            assert_eq!(PublicKey::parse(&pk.to_hex()).ok(), Some(pk));
        }
        let formatted_pin = pin.to_string();
        assert_eq!(SpkiPin::parse(&formatted_pin).ok(), Some(pin));
        assert!(SpkiPin::parse(&formatted_pin.to_ascii_uppercase()).is_err());
        assert!(SpkiPin::parse("abc").is_err());
    }

    proptest! {
        #[test]
        fn proptest_node_name_valid_and_adversarial(s in "\\PC{0,80}") {
            let res = NodeName::parse(&s);
            if let Ok(name) = res {
                prop_assert!((1..=63).contains(&name.as_str().len()));
                prop_assert!(!name.as_str().starts_with('-'));
                prop_assert!(!name.as_str().ends_with('-'));
                prop_assert!(name.as_str().bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
            }
        }

        #[test]
        fn proptest_spki_pin_roundtrip(digest in prop::array::uniform32(any::<u8>())) {
            let pin = SpkiPin::from_sha256_bytes(digest);
            let encoded = pin.to_string();
            prop_assert!(encoded.starts_with("sha256:"));
            prop_assert_eq!(encoded.len(), 71);
            prop_assert_eq!(SpkiPin::parse(&encoded).ok(), Some(pin));
        }

        #[test]
        fn proptest_spki_pin_never_panics_on_arbitrary_input(s in "\\PC{0,100}") {
            let _res = SpkiPin::parse(&s);
        }
    }
}
