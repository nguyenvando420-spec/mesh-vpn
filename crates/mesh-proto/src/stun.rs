//! RFC 5389 / 8489 bounded zero-panic STUN Binding Request & Success Response codec (`US-019`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mesh_core::{AppError, AppResult};

/// Fixed RFC 5389 Magic Cookie (`0x2112A442`).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

/// Fixed RFC 5389 Magic Cookie byte sequence.
pub const STUN_MAGIC_COOKIE_BYTES: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// STUN Binding Request message type (`0x0001`).
pub const STUN_BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Success Response message type (`0x0101`).
pub const STUN_BINDING_SUCCESS_RESPONSE: u16 = 0x0101;

const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR_MASK: u32 = 0x5354_554E;
const STUN_HEADER_LEN: usize = 20;

/// Decoded RFC 5389 STUN Binding message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    /// 16-bit STUN message type (`0x0001` or `0x0101`).
    pub msg_type: u16,
    /// 96-bit transaction identifier copied verbatim into responses.
    pub tx_id: [u8; 12],
    /// Decoded `XOR-MAPPED-ADDRESS` attribute, when present.
    pub xor_mapped_addr: Option<SocketAddr>,
    /// Whether a valid `FINGERPRINT` (`0x8028`) attribute was verified.
    pub has_valid_fingerprint: bool,
}

/// Returns `true` iff `buf` satisfies RFC 5389 header framing without indexing panics (`Codex #1`).
#[must_use]
pub fn is_stun_rfc5389(buf: &[u8]) -> bool {
    let [b0, _, len_hi, len_lo, 0x21, 0x12, 0xA4, 0x42, ..] = buf else {
        return false;
    };
    buf.len() >= STUN_HEADER_LEN
        && (b0 & 0b1100_0000) == 0
        && (len_lo & 0b0000_0011) == 0
        && (STUN_HEADER_LEN + usize::from(u16::from_be_bytes([*len_hi, *len_lo]))) <= buf.len()
}

/// Encodes a compact 28-byte STUN Binding Request (`0x0001`) carrying `FINGERPRINT` (`0x8028`).
#[must_use]
pub fn encode_binding_request(tx_id: [u8; 12]) -> [u8; 28] {
    let mut out = [0_u8; 28];
    if let Some(h) = out.get_mut(0..2) {
        h.copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    }
    if let Some(l) = out.get_mut(2..4) {
        l.copy_from_slice(&8_u16.to_be_bytes());
    }
    if let Some(c) = out.get_mut(4..8) {
        c.copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
    }
    if let Some(t) = out.get_mut(8..20) {
        t.copy_from_slice(&tx_id);
    }
    let fp_value = out
        .get(..20)
        .map_or(0, |prefix| crc32fast::hash(prefix) ^ FINGERPRINT_XOR_MASK);
    if let Some(attr) = out.get_mut(20..28) {
        let mut attr_bytes = [0_u8; 8];
        if let Some(k) = attr_bytes.get_mut(0..2) {
            k.copy_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        }
        if let Some(v) = attr_bytes.get_mut(2..4) {
            v.copy_from_slice(&4_u16.to_be_bytes());
        }
        if let Some(d) = attr_bytes.get_mut(4..8) {
            d.copy_from_slice(&fp_value.to_be_bytes());
        }
        attr.copy_from_slice(&attr_bytes);
    }
    out
}

/// Encodes a STUN Binding Success Response (`0x0101`) containing `XOR-MAPPED-ADDRESS` + `FINGERPRINT`.
#[must_use]
pub fn encode_binding_success_response(tx_id: [u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let xor_port = mapped.port() ^ u16::try_from(STUN_MAGIC_COOKIE >> 16).unwrap_or(0);
    let mut attrs = Vec::with_capacity(32);

    attrs.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    match mapped.ip() {
        IpAddr::V4(v4) => {
            attrs.extend_from_slice(&8_u16.to_be_bytes());
            attrs.push(0x00);
            attrs.push(0x01);
            attrs.extend_from_slice(&xor_port.to_be_bytes());
            let xip = u32::from(v4) ^ STUN_MAGIC_COOKIE;
            attrs.extend_from_slice(&xip.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            attrs.extend_from_slice(&20_u16.to_be_bytes());
            attrs.push(0x00);
            attrs.push(0x02);
            attrs.extend_from_slice(&xor_port.to_be_bytes());
            let mut pad = [0_u8; 16];
            if let Some(head) = pad.get_mut(..4) {
                head.copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
            }
            if let Some(tail) = pad.get_mut(4..16) {
                tail.copy_from_slice(&tx_id);
            }
            let ip_bytes = v6.octets();
            for (b, m) in ip_bytes.iter().zip(pad.iter()) {
                attrs.push(b ^ m);
            }
        }
    }

    let msg_len = u16::try_from(attrs.len() + 8).unwrap_or(u16::MAX);
    let mut pkt = Vec::with_capacity(STUN_HEADER_LEN + attrs.len() + 8);
    pkt.extend_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
    pkt.extend_from_slice(&msg_len.to_be_bytes());
    pkt.extend_from_slice(&STUN_MAGIC_COOKIE_BYTES);
    pkt.extend_from_slice(&tx_id);
    pkt.extend_from_slice(&attrs);

    let fp_value = crc32fast::hash(&pkt) ^ FINGERPRINT_XOR_MASK;
    pkt.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    pkt.extend_from_slice(&4_u16.to_be_bytes());
    pkt.extend_from_slice(&fp_value.to_be_bytes());
    pkt
}

/// Decodes and validates a STUN Binding Request or Success Response without panicking on corrupt input.
pub fn parse_stun_packet(buf: &[u8]) -> AppResult<StunMessage> {
    if !is_stun_rfc5389(buf) {
        return Err(AppError::invalid_argument(
            "packet is not a valid RFC 5389 STUN header",
        ));
    }
    let (Some(type_slice), Some(len_slice), Some(tx_slice)) =
        (buf.get(0..2), buf.get(2..4), buf.get(8..20))
    else {
        return Err(AppError::invalid_argument("truncated STUN header"));
    };
    let msg_type = u16::from_be_bytes(<[u8; 2]>::try_from(type_slice).unwrap_or([0, 0]));
    let msg_len = usize::from(u16::from_be_bytes(
        <[u8; 2]>::try_from(len_slice).unwrap_or([0, 0]),
    ));
    let tx_id =
        <[u8; 12]>::try_from(tx_slice).map_err(|_| AppError::invalid_argument("bad STUN tx_id"))?;

    let mut offset = STUN_HEADER_LEN;
    let end = STUN_HEADER_LEN + msg_len;
    let mut xor_mapped_addr = None;
    let mut has_valid_fingerprint = false;

    while offset < end {
        let Some(attr_hdr) = buf.get(offset..offset + 4) else {
            return Err(AppError::invalid_argument(
                "truncated STUN attribute header",
            ));
        };
        let (Some(kind_b), Some(alen_b)) = (attr_hdr.get(0..2), attr_hdr.get(2..4)) else {
            return Err(AppError::invalid_argument("invalid STUN attribute header"));
        };
        let attr_type = u16::from_be_bytes(<[u8; 2]>::try_from(kind_b).unwrap_or([0, 0]));
        let attr_len = usize::from(u16::from_be_bytes(
            <[u8; 2]>::try_from(alen_b).unwrap_or([0, 0]),
        ));
        let val_start = offset + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return Err(AppError::invalid_argument(
                "STUN attribute overruns message length",
            ));
        }
        let Some(val) = buf.get(val_start..val_end) else {
            return Err(AppError::invalid_argument(
                "STUN attribute slice out of bounds",
            ));
        };

        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            xor_mapped_addr = Some(decode_xor_mapped_addr(val, &tx_id)?);
        } else if attr_type == ATTR_FINGERPRINT {
            verify_fingerprint_attr(buf, offset, val)?;
            has_valid_fingerprint = true;
        }

        let padded_len = (attr_len + 3) & !3;
        offset = val_start + padded_len;
    }

    Ok(StunMessage {
        msg_type,
        tx_id,
        xor_mapped_addr,
        has_valid_fingerprint,
    })
}

fn verify_fingerprint_attr(full_buf: &[u8], attr_offset: usize, val: &[u8]) -> AppResult<()> {
    let val_arr = <[u8; 4]>::try_from(val)
        .map_err(|_| AppError::invalid_argument("STUN FINGERPRINT attribute must be 4 bytes"))?;
    let claimed_fp = u32::from_be_bytes(val_arr);
    let Some(header_and_prior) = full_buf.get(..attr_offset) else {
        return Err(AppError::invalid_argument(
            "invalid STUN FINGERPRINT offset",
        ));
    };
    let mut header_adjusted = header_and_prior.to_vec();
    let fp_end_len = u16::try_from(attr_offset + 8 - STUN_HEADER_LEN)
        .map_err(|_| AppError::invalid_argument("STUN message length overflow"))?;
    if let Some(len_bytes) = header_adjusted.get_mut(2..4) {
        len_bytes.copy_from_slice(&fp_end_len.to_be_bytes());
    }
    let expected_fp = crc32fast::hash(&header_adjusted) ^ FINGERPRINT_XOR_MASK;
    if claimed_fp != expected_fp {
        return Err(AppError::invalid_argument(
            "STUN FINGERPRINT CRC32 mismatch",
        ));
    }
    Ok(())
}

fn decode_xor_mapped_addr(val: &[u8], tx_id: &[u8; 12]) -> AppResult<SocketAddr> {
    let Some(&family) = val.get(1) else {
        return Err(AppError::invalid_argument("truncated XOR-MAPPED-ADDRESS"));
    };
    let Some(port_slice) = val.get(2..4) else {
        return Err(AppError::invalid_argument(
            "truncated XOR-MAPPED-ADDRESS port",
        ));
    };
    let xport = u16::from_be_bytes(<[u8; 2]>::try_from(port_slice).unwrap_or([0, 0]));
    let port = xport ^ u16::try_from(STUN_MAGIC_COOKIE >> 16).unwrap_or(0);

    match family {
        0x01 => {
            let Some(ip_slice) = val.get(4..8) else {
                return Err(AppError::invalid_argument(
                    "truncated IPv4 XOR-MAPPED-ADDRESS",
                ));
            };
            let xip = u32::from_be_bytes(<[u8; 4]>::try_from(ip_slice).unwrap_or([0, 0, 0, 0]));
            let ip = Ipv4Addr::from(xip ^ STUN_MAGIC_COOKIE);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            let Some(ip_slice) = val.get(4..20) else {
                return Err(AppError::invalid_argument(
                    "truncated IPv6 XOR-MAPPED-ADDRESS",
                ));
            };
            let mut pad = [0_u8; 16];
            if let Some(head) = pad.get_mut(..4) {
                head.copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
            }
            if let Some(tail) = pad.get_mut(4..16) {
                tail.copy_from_slice(tx_id);
            }
            let mut octets = [0_u8; 16];
            for ((dst, src), mask) in octets.iter_mut().zip(ip_slice.iter()).zip(pad.iter()) {
                *dst = src ^ mask;
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(AppError::invalid_argument(
            "unknown XOR-MAPPED-ADDRESS address family",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use proptest::prelude::*;

    use super::{
        STUN_BINDING_REQUEST, STUN_BINDING_SUCCESS_RESPONSE, encode_binding_request,
        encode_binding_success_response, is_stun_rfc5389, parse_stun_packet,
    };

    #[test]
    fn test_stun_codex_test_vectors_1_and_2() {
        // Arrange: Vector 1 — Binding Request (28 bytes)
        let tx_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let req_vec = encode_binding_request(tx_id);
        assert_eq!(req_vec.get(0..4), Some([0x00, 0x01, 0x00, 0x08].as_slice()));
        assert_eq!(req_vec.get(4..8), Some([0x21, 0x12, 0xA4, 0x42].as_slice()));
        assert_eq!(req_vec.get(8..20), Some(tx_id.as_slice()));

        // Act & Assert Vector 1
        assert!(is_stun_rfc5389(&req_vec));
        let parsed_req = parse_stun_packet(&req_vec);
        assert!(parsed_req.is_ok());
        if let Ok(req) = parsed_req {
            assert_eq!(req.msg_type, STUN_BINDING_REQUEST);
            assert_eq!(req.tx_id, tx_id);
            assert!(req.has_valid_fingerprint);
        }

        // Arrange: Vector 2 — Binding Success Response reflecting 198.51.100.77:51829 (40 bytes)
        let reflected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)), 51_829);
        let resp_vec = encode_binding_success_response(tx_id, reflected);

        // Assert exact spec bytes from api-design.md §3.2
        assert_eq!(resp_vec.len(), 40);
        assert_eq!(
            resp_vec.get(0..4),
            Some([0x01, 0x01, 0x00, 0x14].as_slice())
        );
        assert_eq!(
            resp_vec.get(20..32),
            Some(
                [
                    0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xEB, 0x67, 0xE7, 0x21, 0xC0, 0x0F
                ]
                .as_slice()
            )
        );

        // Act & Assert decode Vector 2
        assert!(is_stun_rfc5389(&resp_vec));
        let parsed_resp = parse_stun_packet(&resp_vec);
        assert!(parsed_resp.is_ok());
        if let Ok(resp) = parsed_resp {
            assert_eq!(resp.msg_type, STUN_BINDING_SUCCESS_RESPONSE);
            assert_eq!(resp.xor_mapped_addr, Some(reflected));
            assert!(resp.has_valid_fingerprint);
        }

        // Also test IPv6 roundtrip (52 bytes)
        let v6_addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xabcd)),
            51_829,
        );
        let resp_v6 = encode_binding_success_response(tx_id, v6_addr);
        assert_eq!(resp_v6.len(), 52);
        let parsed_v6 = parse_stun_packet(&resp_v6);
        assert_eq!(
            parsed_v6.ok().and_then(|m| m.xor_mapped_addr),
            Some(v6_addr)
        );
    }

    proptest! {
        #[test]
        fn proptest_stun_parser_never_panics_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
            let res = parse_stun_packet(&data);
            prop_assert!(res.is_ok() || res.is_err());
        }
    }
}
