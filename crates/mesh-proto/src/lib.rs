//! Bounded wire protocol codecs, Control/IPC DTOs, and zero-allocation UDP packet demultiplexing.

pub mod admin_ipc;
pub mod agent_ipc;
pub mod control;
pub mod disco;
pub mod netmap;
pub mod relay;
pub mod stun;

pub use disco::IngressSource;
pub use stun::is_stun_rfc5389;

/// Minimum wire length in bytes of a valid `MESHDS` authenticated Disco packet (`63 + 93 + 16`).
pub const MIN_DISCO_PACKET_LEN: usize = mesh_crypto::MIN_DISCO_PACKET_LEN;

/// Zero-allocation classification result produced by [`demux_packet`] on `MagicSocket` UDP ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemuxPacket<'a> {
    /// Authenticated peer Disco traversal packet (`b"MESHDS\x01..."`, length >= 172).
    Disco(&'a [u8]),
    /// RFC 5389 / 8489 STUN Binding message (validated header + magic cookie + word alignment).
    Stun(&'a [u8]),
    /// WireGuard initiator, responder, cookie reply, or encrypted transport frame.
    WireGuard(&'a [u8]),
    /// Unrecognized or malformed datagram (must be dropped silently with zero allocations).
    Unknown,
}

/// Returns `true` iff `buf` matches a structurally valid WireGuard datagram prefix (`type 1..=4`, `reserved == [0,0,0]`).
#[must_use]
pub fn is_wireguard_packet(buf: &[u8]) -> bool {
    buf.len() >= 32 && matches!(buf, [1..=4, 0x00, 0x00, 0x00, ..])
}

/// Returns `true` iff `buf` matches a `MESHDS` v1 Disco packet meeting the minimum `172`-byte length.
#[must_use]
pub fn is_disco_packet(buf: &[u8]) -> bool {
    buf.len() >= MIN_DISCO_PACKET_LEN
        && matches!(buf, [b'M', b'E', b'S', b'H', b'D', b'S', 0x01, ..])
}

/// Demultiplexes a shared `MagicSocket` UDP datagram in deterministic priority order:
/// 1. Authenticated Disco (`MESHDS\x01`, len >= 172)
/// 2. STUN RFC 5389
/// 3. WireGuard (`1..=4, 0, 0, 0`, len >= 32)
/// 4. Unknown (silent drop)
#[must_use]
pub fn demux_packet(buf: &[u8]) -> DemuxPacket<'_> {
    if is_disco_packet(buf) {
        DemuxPacket::Disco(buf)
    } else if is_stun_rfc5389(buf) {
        DemuxPacket::Stun(buf)
    } else if is_wireguard_packet(buf) {
        DemuxPacket::WireGuard(buf)
    } else {
        DemuxPacket::Unknown
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use proptest::prelude::*;

    use crate::stun::{encode_binding_request, encode_binding_success_response};

    use super::{DemuxPacket, MIN_DISCO_PACKET_LEN, demux_packet};

    #[test]
    fn test_demux_distinguishes_disco_stun_wireguard_and_noise() {
        // Arrange
        let mut disco = vec![0_u8; MIN_DISCO_PACKET_LEN];
        if let Some(prefix) = disco.get_mut(..7) {
            prefix.copy_from_slice(b"MESHDS\x01");
        }
        let mut short_disco = vec![0_u8; MIN_DISCO_PACKET_LEN - 1];
        if let Some(prefix) = short_disco.get_mut(..7) {
            prefix.copy_from_slice(b"MESHDS\x01");
        }

        let tx_id = [1_u8; 12];
        let stun_req = encode_binding_request(tx_id);
        let stun_resp = encode_binding_success_response(
            tx_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)), 51_829),
        );

        let mut wg_transport = [0_u8; 64];
        if let Some(first) = wg_transport.first_mut() {
            *first = 4;
        }

        // Act & Assert
        assert_eq!(demux_packet(&disco), DemuxPacket::Disco(&disco));
        assert_eq!(demux_packet(&short_disco), DemuxPacket::Unknown);
        assert_eq!(demux_packet(&stun_req), DemuxPacket::Stun(&stun_req));
        assert_eq!(demux_packet(&stun_resp), DemuxPacket::Stun(&stun_resp));
        assert_eq!(
            demux_packet(&wg_transport),
            DemuxPacket::WireGuard(&wg_transport)
        );
        assert_eq!(demux_packet(b"GET / HTTP/1.1"), DemuxPacket::Unknown);
        assert_eq!(demux_packet(&[]), DemuxPacket::Unknown);
    }

    proptest! {
        #[test]
        fn proptest_demux_never_panics(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
            let parsed = demux_packet(&buf);
            prop_assert!(matches!(
                parsed,
                DemuxPacket::Disco(_)
                    | DemuxPacket::Stun(_)
                    | DemuxPacket::WireGuard(_)
                    | DemuxPacket::Unknown
            ));
        }
    }
}
