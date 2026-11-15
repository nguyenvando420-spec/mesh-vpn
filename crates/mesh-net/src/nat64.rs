//! RFC 6052 / RFC 7050 NAT64 address synthesis and Android/mobile outer socket protection
//! (`US-095`, `IG-MOB-G2-02`).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use mesh_core::{AppError, AppResult};

const RFC7050_IPV4ONLY_ADDR_A: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 170);
const RFC7050_IPV4ONLY_ADDR_B: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 171);

/// Hook allowing mobile VPN engines (notably Android `VpnService.protect(fd)`) to exclude
/// underlay sockets from TUN routing prior to `connect`/`bind` (`HR-MOB-G2-01`).
pub trait SocketProtector: Send + Sync {
    /// Protects an open OS socket descriptor (`raw_fd`) from being routed through the VPN tunnel.
    fn protect_socket(&self, raw_fd: i32) -> AppResult<()>;
}

/// No-op [`SocketProtector`] used on Desktop / iOS `NEPacketTunnelProvider` / unit tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NoopSocketProtector;

impl SocketProtector for NoopSocketProtector {
    fn protect_socket(&self, _raw_fd: i32) -> AppResult<()> {
        Ok(())
    }
}

/// Supported RFC 6052 §2.2 NAT64 prefix lengths (`/32`, `/40`, `/48`, `/56`, `/64`, `/96`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nat64PrefixLen {
    /// `/32`
    P32,
    /// `/40`
    P40,
    /// `/48`
    P48,
    /// `/56`
    P56,
    /// `/64`
    P64,
    /// `/96` (Well-Known Prefix `64:ff9b::/96`)
    P96,
}

impl Nat64PrefixLen {
    /// Parses a CIDR prefix length into a valid RFC 6052 length.
    pub fn from_u8(bits: u8) -> AppResult<Self> {
        match bits {
            32 => Ok(Self::P32),
            40 => Ok(Self::P40),
            48 => Ok(Self::P48),
            56 => Ok(Self::P56),
            64 => Ok(Self::P64),
            96 => Ok(Self::P96),
            other => Err(AppError::invalid_argument(format!(
                "unsupported RFC 6052 NAT64 prefix length `/{other}` (expected 32, 40, 48, 56, 64, or 96)"
            ))),
        }
    }

    /// Returns the numeric CIDR bit length.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::P32 => 32,
            Self::P40 => 40,
            Self::P48 => 48,
            Self::P56 => 56,
            Self::P64 => 64,
            Self::P96 => 96,
        }
    }
}

/// Validated RFC 6052 NAT64 IPv6 prefix with non-prefix host bits zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nat64Prefix {
    prefix: Ipv6Addr,
    len: Nat64PrefixLen,
}

impl Nat64Prefix {
    /// Well-Known NAT64 Prefix CIDR (`64:ff9b::/96`, RFC 6052 §2.1).
    pub const WELL_KNOWN_CIDR: &str = "64:ff9b::/96";

    /// Returns the RFC 6052 Well-Known Prefix `64:ff9b::/96`.
    #[must_use]
    pub const fn well_known() -> Self {
        Self {
            prefix: Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0),
            len: Nat64PrefixLen::P96,
        }
    }

    /// Builds a validated [`Nat64Prefix`], masking trailing bits outside `prefix_len` to zero.
    pub fn from_prefix_and_len(prefix: Ipv6Addr, prefix_len: u8) -> AppResult<Self> {
        let len = Nat64PrefixLen::from_u8(prefix_len)?;
        let masked = mask_prefix_octets(prefix.octets(), len);
        Ok(Self {
            prefix: Ipv6Addr::from(masked),
            len,
        })
    }

    /// Parses a CIDR string such as `"64:ff9b::/96"` into a validated [`Nat64Prefix`].
    pub fn from_cidr(cidr: &str) -> AppResult<Self> {
        let trimmed = cidr.trim();
        let Some((addr_str, len_str)) = trimmed.split_once('/') else {
            return Err(AppError::invalid_argument(
                "NAT64 prefix must use CIDR notation `<ipv6>/<len>`",
            ));
        };
        let addr = Ipv6Addr::from_str(addr_str)
            .map_err(|_| AppError::invalid_argument("invalid IPv6 address in NAT64 CIDR"))?;
        let bits: u8 = len_str
            .parse()
            .map_err(|_| AppError::invalid_argument("invalid prefix length in NAT64 CIDR"))?;
        Self::from_prefix_and_len(addr, bits)
    }

    /// Returns the masked IPv6 network prefix.
    #[must_use]
    pub const fn prefix_addr(&self) -> Ipv6Addr {
        self.prefix
    }

    /// Returns the validated RFC 6052 prefix length.
    #[must_use]
    pub const fn prefix_len(&self) -> Nat64PrefixLen {
        self.len
    }

    /// Infers an RFC 7050 NAT64 `Pref64` from DNS64 `AAAA ipv4only.arpa` answers containing
    /// `192.0.0.170` or `192.0.0.171`.
    #[must_use]
    pub fn from_ipv4only_arpa_addrs(addrs: &[Ipv6Addr]) -> Option<Self> {
        const CANDIDATES: [Nat64PrefixLen; 6] = [
            Nat64PrefixLen::P96,
            Nat64PrefixLen::P64,
            Nat64PrefixLen::P56,
            Nat64PrefixLen::P48,
            Nat64PrefixLen::P40,
            Nat64PrefixLen::P32,
        ];
        for &addr in addrs {
            for len in CANDIDATES {
                let candidate = Self {
                    prefix: Ipv6Addr::from(mask_prefix_octets(addr.octets(), len)),
                    len,
                };
                let synth = Nat64Synthesizer::new(candidate);
                if synth.synthesize_ip(RFC7050_IPV4ONLY_ADDR_A) == addr
                    || synth.synthesize_ip(RFC7050_IPV4ONLY_ADDR_B) == addr
                {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

/// Pure RFC 6052 §2.2 IPv4-embedded IPv6 address synthesizer preserving reserved octet `u = 0x00`
/// at byte index `8` (bits `64..71`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Synthesizer {
    prefix: Nat64Prefix,
}

impl Nat64Synthesizer {
    /// Creates a synthesizer bound to `prefix`.
    #[must_use]
    pub const fn new(prefix: Nat64Prefix) -> Self {
        Self { prefix }
    }

    /// Returns the underlying [`Nat64Prefix`].
    #[must_use]
    pub const fn prefix(&self) -> Nat64Prefix {
        self.prefix
    }

    /// Synthesizes an RFC 6052 IPv6 address embedding `ipv4` (with `u = 0x00` at bits `64..71`).
    #[must_use]
    pub const fn synthesize_ip(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        let [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, _, _, _, _] =
            self.prefix.prefix.octets();
        let [v0, v1, v2, v3] = ipv4.octets();
        let out = match self.prefix.len {
            Nat64PrefixLen::P96 => [
                p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, v0, v1, v2, v3,
            ],
            Nat64PrefixLen::P64 => [p0, p1, p2, p3, p4, p5, p6, p7, 0, v0, v1, v2, v3, 0, 0, 0],
            Nat64PrefixLen::P56 => [p0, p1, p2, p3, p4, p5, p6, v0, 0, v1, v2, v3, 0, 0, 0, 0],
            Nat64PrefixLen::P48 => [p0, p1, p2, p3, p4, p5, v0, v1, 0, v2, v3, 0, 0, 0, 0, 0],
            Nat64PrefixLen::P40 => [p0, p1, p2, p3, p4, v0, v1, v2, 0, v3, 0, 0, 0, 0, 0, 0],
            Nat64PrefixLen::P32 => [p0, p1, p2, p3, v0, v1, v2, v3, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        Ipv6Addr::from_bits(u128::from_be_bytes(out))
    }

    /// Synthesizes a [`SocketAddrV6`] targeting the IPv4 peer via NAT64, preserving port.
    #[must_use]
    pub const fn synthesize_sockaddr(&self, target: SocketAddrV4) -> SocketAddrV6 {
        SocketAddrV6::new(self.synthesize_ip(*target.ip()), target.port(), 0, 0)
    }

    /// Extracts the embedded IPv4 address if `addr` matches this prefix and satisfies `u == 0x00`
    /// and zeroed suffix invariants.
    #[must_use]
    pub fn desynthesize_ip(&self, addr: Ipv6Addr) -> Option<Ipv4Addr> {
        let [
            a0,
            a1,
            a2,
            a3,
            a4,
            a5,
            a6,
            a7,
            a8,
            a9,
            a10,
            a11,
            a12,
            a13,
            a14,
            a15,
        ] = addr.octets();
        let [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, _, _, _, _] =
            self.prefix.prefix.octets();
        match self.prefix.len {
            Nat64PrefixLen::P96 => {
                if [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11]
                    != [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11]
                {
                    return None;
                }
                Some(Ipv4Addr::new(a12, a13, a14, a15))
            }
            Nat64PrefixLen::P64 => {
                if [a0, a1, a2, a3, a4, a5, a6, a7] != [p0, p1, p2, p3, p4, p5, p6, p7]
                    || a8 != 0
                    || [a13, a14, a15] != [0, 0, 0]
                {
                    return None;
                }
                Some(Ipv4Addr::new(a9, a10, a11, a12))
            }
            Nat64PrefixLen::P56 => {
                if [a0, a1, a2, a3, a4, a5, a6] != [p0, p1, p2, p3, p4, p5, p6]
                    || a8 != 0
                    || [a12, a13, a14, a15] != [0, 0, 0, 0]
                {
                    return None;
                }
                Some(Ipv4Addr::new(a7, a9, a10, a11))
            }
            Nat64PrefixLen::P48 => {
                if [a0, a1, a2, a3, a4, a5] != [p0, p1, p2, p3, p4, p5]
                    || a8 != 0
                    || [a11, a12, a13, a14, a15] != [0, 0, 0, 0, 0]
                {
                    return None;
                }
                Some(Ipv4Addr::new(a6, a7, a9, a10))
            }
            Nat64PrefixLen::P40 => {
                if [a0, a1, a2, a3, a4] != [p0, p1, p2, p3, p4]
                    || a8 != 0
                    || [a10, a11, a12, a13, a14, a15] != [0, 0, 0, 0, 0, 0]
                {
                    return None;
                }
                Some(Ipv4Addr::new(a5, a6, a7, a9))
            }
            Nat64PrefixLen::P32 => {
                if [a0, a1, a2, a3] != [p0, p1, p2, p3]
                    || [a8, a9, a10, a11, a12, a13, a14, a15] != [0, 0, 0, 0, 0, 0, 0, 0]
                {
                    return None;
                }
                Some(Ipv4Addr::new(a4, a5, a6, a7))
            }
        }
    }
}

const fn mask_prefix_octets(octets: [u8; 16], len: Nat64PrefixLen) -> [u8; 16] {
    let [o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, _, _, _, _] = octets;
    match len {
        Nat64PrefixLen::P32 => [o0, o1, o2, o3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        Nat64PrefixLen::P40 => [o0, o1, o2, o3, o4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        Nat64PrefixLen::P48 => [o0, o1, o2, o3, o4, o5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        Nat64PrefixLen::P56 => [o0, o1, o2, o3, o4, o5, o6, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        Nat64PrefixLen::P64 => [o0, o1, o2, o3, o4, o5, o6, o7, 0, 0, 0, 0, 0, 0, 0, 0],
        Nat64PrefixLen::P96 => [o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, 0, 0, 0, 0],
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use proptest::prelude::*;

    use super::{Nat64Prefix, Nat64Synthesizer, NoopSocketProtector, SocketProtector};

    #[test]
    fn test_nat64_rfc6052_vectors_and_rfc7050_discovery() {
        // Arrange
        let target_v4 = Ipv4Addr::new(192, 0, 2, 33);
        let vectors = [
            ("64:ff9b::/96", "64:ff9b::c000:221"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8::/32", "2001:db8:c000:221::"),
        ];

        // Act & Assert
        for (cidr, expected_str) in vectors {
            let Ok(prefix) = Nat64Prefix::from_cidr(cidr) else {
                assert_eq!(cidr, "failed to parse prefix");
                return;
            };
            let synth = Nat64Synthesizer::new(prefix);
            let out = synth.synthesize_ip(target_v4);
            let expected = Ipv6Addr::from_str(expected_str).unwrap_or(Ipv6Addr::UNSPECIFIED);
            assert_eq!(out, expected);
            if prefix.prefix_len().as_u8() < 96 {
                assert_eq!(out.octets().get(8).copied(), Some(0));
            }
            assert_eq!(synth.desynthesize_ip(out), Some(target_v4));
        }

        let arpa_probe = Nat64Synthesizer::new(Nat64Prefix::well_known())
            .synthesize_ip(Ipv4Addr::new(192, 0, 0, 170));
        assert_eq!(
            Nat64Prefix::from_ipv4only_arpa_addrs(&[arpa_probe]),
            Some(Nat64Prefix::well_known())
        );
        assert!(NoopSocketProtector.protect_socket(42).is_ok());
    }

    proptest! {
        #[test]
        fn proptest_nat64_roundtrip_and_reserved_octet_zero(
            prefix_bytes in any::<[u8; 8]>(),
            prefix_idx in 0_usize..6,
            v4 in any::<[u8; 4]>(),
        ) {
            let lengths = [32_u8, 40, 48, 56, 64, 96];
            let prefix_len = lengths.get(prefix_idx).copied().unwrap_or(96);
            let mut full = [0_u8; 16];
            for (dst, src) in full.iter_mut().take(8).zip(prefix_bytes.iter()) {
                *dst = *src;
            }
            if let Ok(prefix) = Nat64Prefix::from_prefix_and_len(Ipv6Addr::from(full), prefix_len) {
                let synth = Nat64Synthesizer::new(prefix);
                let ip4 = Ipv4Addr::from(v4);
                let ip6 = synth.synthesize_ip(ip4);
                if prefix_len < 96 {
                    prop_assert_eq!(ip6.octets().get(8).copied(), Some(0));
                }
                prop_assert_eq!(synth.desynthesize_ip(ip6), Some(ip4));
            }
        }
    }
}
