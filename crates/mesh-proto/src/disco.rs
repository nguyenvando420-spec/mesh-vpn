//! Inner Disco message bodies and `IngressSource` provenance tagging (`HR-G2-04`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mesh_core::{AppError, AppResult, PublicKey};

/// Maximum number of endpoints accepted inside a single `DiscoCallMeMaybe` payload.
pub const MAX_DISCO_ENDPOINTS: usize = 16;

/// Verified ingress path indicating how a Disco or WireGuard datagram arrived (`HR-G2-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressSource {
    /// Received directly over UDP on `MagicSocket` from `SocketAddr`.
    DirectUdp(SocketAddr),
    /// Received via server-authenticated Blind Relay frame `0x02` (`src_pubkey` trusted from Relay).
    Relay {
        /// Node WireGuard public key authenticated by `mesh-server`.
        verified_src_node_pubkey: PublicKey,
    },
}

/// Wire byte codes identifying inner Disco message payloads (`api-design.md` §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DiscoMsgType {
    /// Connectivity probe requesting a `Pong` response (`0x01`).
    Ping = 0x01,
    /// Connectivity reply reporting observed source `SocketAddr` (`0x02`).
    Pong = 0x02,
    /// NAT hole-punching coordination carrying sender UDP endpoints (`0x03`).
    CallMeMaybe = 0x03,
}

impl DiscoMsgType {
    /// Converts a raw byte into a validated [`DiscoMsgType`].
    pub fn from_byte(byte: u8) -> AppResult<Self> {
        match byte {
            0x01 => Ok(Self::Ping),
            0x02 => Ok(Self::Pong),
            0x03 => Ok(Self::CallMeMaybe),
            _ => Err(AppError::invalid_argument(format!(
                "unknown disco message type byte 0x{byte:02x}"
            ))),
        }
    }
}

/// Decoded inner body attached after the 93-byte authenticated Disco header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoBody {
    /// Empty body (`0 bytes`) -> total wire packet size `172 bytes`.
    Ping,
    /// Reports the UDP source address observed by the responder (`0.0.0.0:0` when relayed).
    Pong {
        /// Sender address observed by the responder on UDP ingress.
        observed_addr: SocketAddr,
    },
    /// Announces sender candidate UDP addresses for simultaneous hole punching.
    CallMeMaybe {
        /// Bounded list of `1..=16` UDP endpoint candidates.
        endpoints: Vec<SocketAddr>,
    },
}

impl DiscoBody {
    /// Returns the matching wire message type tag.
    #[must_use]
    pub const fn msg_type(&self) -> DiscoMsgType {
        match self {
            Self::Ping => DiscoMsgType::Ping,
            Self::Pong { .. } => DiscoMsgType::Pong,
            Self::CallMeMaybe { .. } => DiscoMsgType::CallMeMaybe,
        }
    }

    /// Serializes the body into canonical binary wire bytes.
    pub fn encode(&self) -> AppResult<Vec<u8>> {
        match self {
            Self::Ping => Ok(Vec::new()),
            Self::Pong { observed_addr } => {
                let mut out = Vec::with_capacity(19);
                encode_socket_addr(*observed_addr, &mut out);
                Ok(out)
            }
            Self::CallMeMaybe { endpoints } => {
                if endpoints.is_empty() || endpoints.len() > MAX_DISCO_ENDPOINTS {
                    return Err(AppError::invalid_argument(
                        "DiscoCallMeMaybe must carry 1..=16 endpoints",
                    ));
                }
                let mut out = Vec::with_capacity(1 + endpoints.len() * 19);
                let count = u8::try_from(endpoints.len())
                    .map_err(|_| AppError::invalid_argument("endpoint count overflow"))?;
                out.push(count);
                for addr in endpoints {
                    encode_socket_addr(*addr, &mut out);
                }
                Ok(out)
            }
        }
    }

    /// Parses and bounds-checks a decrypted Disco inner body slice.
    pub fn decode(msg_type_byte: u8, body: &[u8]) -> AppResult<Self> {
        match DiscoMsgType::from_byte(msg_type_byte)? {
            DiscoMsgType::Ping => {
                if !body.is_empty() {
                    return Err(AppError::invalid_argument(
                        "DiscoPing inner body must be empty",
                    ));
                }
                Ok(Self::Ping)
            }
            DiscoMsgType::Pong => {
                let (addr, consumed) = decode_socket_addr(body)?;
                if consumed != body.len() {
                    return Err(AppError::invalid_argument(
                        "DiscoPong body contains trailing bytes",
                    ));
                }
                Ok(Self::Pong {
                    observed_addr: addr,
                })
            }
            DiscoMsgType::CallMeMaybe => {
                let Some(&count) = body.first() else {
                    return Err(AppError::invalid_argument(
                        "DiscoCallMeMaybe missing endpoint count",
                    ));
                };
                let count_usize = usize::from(count);
                if !(1..=MAX_DISCO_ENDPOINTS).contains(&count_usize) {
                    return Err(AppError::invalid_argument(
                        "DiscoCallMeMaybe endpoint count must be 1..=16",
                    ));
                }
                let mut cursor = body.get(1..).unwrap_or(&[]);
                let mut endpoints = Vec::with_capacity(count_usize);
                for _ in 0..count_usize {
                    let (addr, used) = decode_socket_addr(cursor)?;
                    endpoints.push(addr);
                    cursor = cursor.get(used..).unwrap_or(&[]);
                }
                if !cursor.is_empty() {
                    return Err(AppError::invalid_argument(
                        "DiscoCallMeMaybe contains trailing bytes",
                    ));
                }
                Ok(Self::CallMeMaybe { endpoints })
            }
        }
    }
}

fn encode_socket_addr(addr: SocketAddr, out: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x04);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x06);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn decode_socket_addr(slice: &[u8]) -> AppResult<(SocketAddr, usize)> {
    let Some(&family) = slice.first() else {
        return Err(AppError::invalid_argument(
            "missing address family in Disco body",
        ));
    };
    match family {
        0x04 => {
            let (Some(ip_b), Some(port_b)) = (slice.get(1..5), slice.get(5..7)) else {
                return Err(AppError::invalid_argument(
                    "truncated IPv4 endpoint in Disco body",
                ));
            };
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(ip_b).unwrap_or([0, 0, 0, 0]));
            let port = u16::from_be_bytes(<[u8; 2]>::try_from(port_b).unwrap_or([0, 0]));
            Ok((SocketAddr::new(IpAddr::V4(ip), port), 7))
        }
        0x06 => {
            let (Some(ip_b), Some(port_b)) = (slice.get(1..17), slice.get(17..19)) else {
                return Err(AppError::invalid_argument(
                    "truncated IPv6 endpoint in Disco body",
                ));
            };
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(ip_b).unwrap_or([0; 16]));
            let port = u16::from_be_bytes(<[u8; 2]>::try_from(port_b).unwrap_or([0, 0]));
            Ok((SocketAddr::new(IpAddr::V6(ip), port), 19))
        }
        _ => Err(AppError::invalid_argument(
            "invalid address family in Disco body",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use proptest::prelude::*;

    use super::DiscoBody;

    #[test]
    fn test_disco_body_ping_pong_and_call_me_maybe_roundtrip() {
        // Arrange
        let pong_v4 = DiscoBody::Pong {
            observed_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)), 51_829),
        };
        let cmm = DiscoBody::CallMeMaybe {
            endpoints: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 51_820),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    51_820,
                ),
            ],
        };

        // Act
        let ping_raw = DiscoBody::Ping.encode();
        let pong_raw = pong_v4.encode();
        let cmm_raw = cmm.encode();

        // Assert
        assert_eq!(ping_raw.as_ref().map(Vec::len).ok(), Some(0));
        assert_eq!(pong_raw.as_ref().map(Vec::len).ok(), Some(7));
        if let Ok(raw) = pong_raw {
            assert_eq!(DiscoBody::decode(0x02, &raw).ok(), Some(pong_v4));
        }
        if let Ok(raw) = cmm_raw {
            assert_eq!(DiscoBody::decode(0x03, &raw).ok(), Some(cmm));
        }
        assert!(DiscoBody::decode(0x01, &[1]).is_err());
        assert!(
            DiscoBody::CallMeMaybe {
                endpoints: Vec::new()
            }
            .encode()
            .is_err()
        );
    }

    proptest! {
        #[test]
        fn proptest_disco_body_decode_never_panics(msg_type in any::<u8>(), data in prop::collection::vec(any::<u8>(), 0..300)) {
            let res = DiscoBody::decode(msg_type, &data);
            prop_assert!(res.is_ok() || res.is_err());
        }
    }
}
