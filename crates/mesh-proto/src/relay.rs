//! Binary WebSocket frame codec for Blind Relay `/v1/relay` (`api-design.md` §2.1).

use bytes::{BufMut as _, Bytes, BytesMut};

use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, AppResult, PublicKey};

/// Maximum inner WireGuard/Disco ciphertext carried by a single Relay packet frame (`US-025 AC3`).
pub const RELAY_MAX_CIPHERTEXT_BYTES: usize = 1480;

/// Status notification codes carried inside `RelayFrame::ControlNotice` (`0x04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayNoticeCode {
    /// Sender exceeded relay Token Bucket rate limit (`US-027 AC4`).
    Throttled = 0x01,
    /// Authenticated peer was revoked; session terminating (`US-029`).
    NodeRevoked = 0x02,
    /// Authenticated node identity key expired (`US-031`).
    NodeKeyExpired = 0x03,
    /// Server is gracefully migrating listener ports (`US-074`).
    ServerMigratingPort = 0x04,
}

impl RelayNoticeCode {
    /// Decodes a notice code byte.
    pub fn from_byte(byte: u8) -> AppResult<Self> {
        match byte {
            0x01 => Ok(Self::Throttled),
            0x02 => Ok(Self::NodeRevoked),
            0x03 => Ok(Self::NodeKeyExpired),
            0x04 => Ok(Self::ServerMigratingPort),
            _ => Err(AppError::invalid_argument(format!(
                "unknown relay notice code 0x{byte:02x}"
            ))),
        }
    }
}

/// Framed binary message transported across `/v1/relay`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    /// Client -> Relay packet addressed to `dst_pubkey` (`0x01`).
    ClientToPeerPacket {
        /// Recipient peer WireGuard public key.
        dst_pubkey: PublicKey,
        /// End-to-end encrypted WireGuard or Disco payload (`1..=1480` bytes).
        ciphertext: Bytes,
    },
    /// Relay -> Client packet stamped with server-authenticated `src_pubkey` (`0x02`).
    RelayToClientPacket {
        /// Authenticated sending node WireGuard public key.
        src_pubkey: PublicKey,
        /// End-to-end encrypted WireGuard or Disco payload (`1..=1480` bytes).
        ciphertext: Bytes,
    },
    /// Bidirectional NAT/proxy keep-alive frame (`0x03`, exact `9` bytes).
    KeepAlive {
        /// Sender UTC Unix milliseconds.
        sent_at_ms: u64,
    },
    /// Server -> Client status notification (`0x04`, exact `8` bytes).
    ControlNotice {
        /// Reason code.
        code: RelayNoticeCode,
    },
}

impl RelayFrame {
    /// Serializes the binary relay frame enforcing strict wire bounds (`<= 2048 B`).
    pub fn encode(&self) -> AppResult<Bytes> {
        match self {
            Self::ClientToPeerPacket {
                dst_pubkey,
                ciphertext,
            } => encode_routed_packet(0x01, dst_pubkey, ciphertext),
            Self::RelayToClientPacket {
                src_pubkey,
                ciphertext,
            } => encode_routed_packet(0x02, src_pubkey, ciphertext),
            Self::KeepAlive { sent_at_ms } => {
                let mut buf = BytesMut::with_capacity(9);
                buf.put_u8(0x03);
                buf.put_u64(*sent_at_ms);
                Ok(buf.freeze())
            }
            Self::ControlNotice { code } => {
                let mut buf = BytesMut::with_capacity(8);
                buf.put_u8(0x04);
                buf.put_u8(*code as u8);
                buf.put_slice(&[0_u8; 6]);
                Ok(buf.freeze())
            }
        }
    }

    /// Parses and bounds-checks a raw WebSocket binary frame from `/v1/relay`.
    pub fn decode(raw: &[u8]) -> AppResult<Self> {
        if raw.len() > MAX_FRAME_SIZE {
            return Err(AppError::invalid_argument(
                "relay frame exceeds MAX_FRAME_SIZE (2048 bytes)",
            ));
        }
        let Some(&frame_type) = raw.first() else {
            return Err(AppError::invalid_argument("empty relay frame"));
        };
        match frame_type {
            0x01 | 0x02 => {
                let (Some(key_slice), Some(payload)) = (raw.get(1..33), raw.get(33..)) else {
                    return Err(AppError::invalid_argument("truncated relay packet frame"));
                };
                if payload.is_empty() || payload.len() > RELAY_MAX_CIPHERTEXT_BYTES {
                    return Err(AppError::invalid_argument(
                        "relay ciphertext length must be 1..=1480 bytes",
                    ));
                }
                let key_arr = <[u8; 32]>::try_from(key_slice)
                    .map_err(|_| AppError::invalid_argument("invalid relay pubkey length"))?;
                let pubkey = PublicKey::from_bytes(key_arr)?;
                let ciphertext = Bytes::copy_from_slice(payload);
                if frame_type == 0x01 {
                    Ok(Self::ClientToPeerPacket {
                        dst_pubkey: pubkey,
                        ciphertext,
                    })
                } else {
                    Ok(Self::RelayToClientPacket {
                        src_pubkey: pubkey,
                        ciphertext,
                    })
                }
            }
            0x03 => {
                if raw.len() != 9 {
                    return Err(AppError::invalid_argument(
                        "relay keep-alive frame must be exactly 9 bytes",
                    ));
                }
                let Some(ts_slice) = raw.get(1..9) else {
                    return Err(AppError::invalid_argument("missing keep-alive timestamp"));
                };
                let ts_arr = <[u8; 8]>::try_from(ts_slice)
                    .map_err(|_| AppError::invalid_argument("invalid keep-alive timestamp"))?;
                Ok(Self::KeepAlive {
                    sent_at_ms: u64::from_be_bytes(ts_arr),
                })
            }
            0x04 => {
                if raw.len() != 8 {
                    return Err(AppError::invalid_argument(
                        "relay control notice frame must be exactly 8 bytes",
                    ));
                }
                let Some(&code_byte) = raw.get(1) else {
                    return Err(AppError::invalid_argument("missing relay notice code"));
                };
                Ok(Self::ControlNotice {
                    code: RelayNoticeCode::from_byte(code_byte)?,
                })
            }
            _ => Err(AppError::invalid_argument(format!(
                "unknown relay frame type 0x{frame_type:02x}"
            ))),
        }
    }
}

fn encode_routed_packet(frame_type: u8, key: &PublicKey, ciphertext: &[u8]) -> AppResult<Bytes> {
    if ciphertext.is_empty() || ciphertext.len() > RELAY_MAX_CIPHERTEXT_BYTES {
        return Err(AppError::invalid_argument(
            "relay ciphertext length must be 1..=1480 bytes",
        ));
    }
    let mut buf = BytesMut::with_capacity(33 + ciphertext.len());
    buf.put_u8(frame_type);
    buf.put_slice(key.as_bytes());
    buf.put_slice(ciphertext);
    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use proptest::prelude::*;

    use mesh_core::PublicKey;

    use super::{RELAY_MAX_CIPHERTEXT_BYTES, RelayFrame, RelayNoticeCode};

    #[test]
    fn test_relay_frame_variants_roundtrip_and_bounds() {
        // Arrange
        let Ok(pk) = PublicKey::from_bytes([0x33_u8; 32]) else {
            return;
        };
        let frames = [
            RelayFrame::ClientToPeerPacket {
                dst_pubkey: pk,
                ciphertext: Bytes::from_static(b"wg-ciphertext"),
            },
            RelayFrame::RelayToClientPacket {
                src_pubkey: pk,
                ciphertext: Bytes::from_static(b"wg-ciphertext-reply"),
            },
            RelayFrame::KeepAlive {
                sent_at_ms: 1_762_958_151_000,
            },
            RelayFrame::ControlNotice {
                code: RelayNoticeCode::Throttled,
            },
        ];

        // Act & Assert
        for frame in frames {
            let enc = frame.encode();
            assert!(enc.is_ok());
            if let Ok(raw) = enc {
                assert_eq!(RelayFrame::decode(&raw).ok(), Some(frame));
            }
        }

        let oversized = RelayFrame::ClientToPeerPacket {
            dst_pubkey: pk,
            ciphertext: Bytes::from(vec![0xaa_u8; RELAY_MAX_CIPHERTEXT_BYTES + 1]),
        };
        assert!(oversized.encode().is_err());
        assert!(RelayFrame::decode(&[0x03, 1, 2]).is_err());
        assert!(RelayFrame::decode(&[0x01; 33]).is_err());
    }

    proptest! {
        #[test]
        fn proptest_relay_decode_never_panics(data in prop::collection::vec(any::<u8>(), 0..2200)) {
            let res = RelayFrame::decode(&data);
            prop_assert!(res.is_ok() || res.is_err());
        }
    }
}
