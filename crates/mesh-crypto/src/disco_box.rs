//! Authenticated peer Disco sealing and anti-reflection opening (`US-021`, `Codex #2`).
//!
//! Outer layout (`63 bytes` + `>= 109 bytes` ciphertext, `MIN_DISCO_PACKET_LEN = 172`):
//! - `0..6`: `b"MESHDS"`
//! - `6`: `0x01` (protocol version)
//! - `7..39`: `outer_sender_disco_pubkey` (32 bytes)
//! - `39..63`: `box_nonce` (24 bytes from `OsRng`)
//! - `63..N`: `SalsaBox` ciphertext of inner `>= 93 byte` plaintext + 16-byte Poly1305 MAC
//!
//! Inner plaintext layout:
//! - `0..8`: `b"MESHDSv1"`
//! - `8`: `msg_type` (`0x01` = Ping, `0x02` = Pong, `0x03` = CallMeMaybe)
//! - `9..21`: `tx_id` (`[u8; 12]`)
//! - `21..29`: `sent_at_ms` (`u64` big-endian)
//! - `29..61`: `inner_sender_disco_pubkey` (32 bytes)
//! - `61..93`: `inner_recipient_disco_pubkey` (32 bytes)
//! - `93..M`: message body

use std::fmt;

use crypto_box::aead::{Aead as _, OsRng};
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use rand::RngCore as _;
use zeroize::Zeroize as _;

use mesh_core::brand::{DISCO_INNER_CTX, DISCO_MAGIC};
use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, PublicKey};

use crate::hash::ct_eq_bytes;
use crate::keys::DiscoKeypair;

/// Outer protocol version byte after `b"MESHDS"`.
pub const DISCO_PROTOCOL_VERSION: u8 = 0x01;

/// Fixed unencrypted Disco outer header length (`6 + 1 + 32 + 24`).
pub const DISCO_OUTER_HEADER_LEN: usize = 63;

/// Fixed decrypted Disco inner header length (`8 + 1 + 12 + 8 + 32 + 32`).
pub const DISCO_INNER_HEADER_LEN: usize = 93;

/// Poly1305 authentication tag length appended by `SalsaBox`.
pub const POLY1305_TAG_LEN: usize = 16;

/// Minimum valid Disco packet length (`63 + 93 + 16 = 172` bytes).
pub const MIN_DISCO_PACKET_LEN: usize =
    DISCO_OUTER_HEADER_LEN + DISCO_INNER_HEADER_LEN + POLY1305_TAG_LEN;

/// Inputs to [`seal_disco_packet`] kept compact under argument threshold rules.
#[derive(Debug, Clone, Copy)]
pub struct DiscoSealParams<'a> {
    /// Target peer Disco public key.
    pub recipient_pubkey: PublicKey,
    /// Disco frame message type (`0x01`, `0x02`, or `0x03`).
    pub msg_type: u8,
    /// 96-bit transaction correlation identifier.
    pub tx_id: [u8; 12],
    /// Sender UTC timestamp in milliseconds.
    pub sent_at_ms: u64,
    /// Plaintext body bytes appended at inner offset `93`.
    pub body: &'a [u8],
}

/// Verified and opened Disco payload bound explicitly to outer/inner sender and recipient keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedDiscoPacket {
    /// Disco message type byte (`0x01..=0x03`).
    pub msg_type: u8,
    /// 96-bit transaction identifier.
    pub tx_id: [u8; 12],
    /// Sender UTC timestamp in milliseconds.
    pub sent_at_ms: u64,
    /// Verified sender Disco public key matching both outer header and inner plaintext.
    pub sender_disco_pubkey: PublicKey,
    /// Verified recipient Disco public key matching the local `DiscoKeypair`.
    pub recipient_disco_pubkey: PublicKey,
    /// Unparsed message body slice following byte `93` of inner plaintext.
    pub body: Vec<u8>,
}

/// Detailed metric-compatible reason a Disco packet was dropped (`api-design.md` §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoRejectReason {
    /// Packet shorter than `172` bytes or wrong `MESHDS` + `0x01` prefix.
    MalformedFrame,
    /// Outer sender public key matched our own Disco public key before decryption (`Codex #2`).
    SelfReflection,
    /// Inner context failed or Poly1305 MAC failed.
    BadMac,
    /// Outer header sender key differed from authenticated inner sender key (`Codex #2`).
    SenderMismatch,
    /// Authenticated inner recipient key did not match our own Disco public key (`Codex #2`).
    RecipientMismatch,
}

impl fmt::Display for DiscoRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedFrame => "malformed disco frame header or length",
            Self::SelfReflection => "self_reflection",
            Self::BadMac => "bad_mac",
            Self::SenderMismatch => "sender_mismatch",
            Self::RecipientMismatch => "recipient_mismatch",
        })
    }
}

impl std::error::Error for DiscoRejectReason {}

impl DiscoRejectReason {
    /// Returns the Prometheus label value for `mesh_agent_disco_invalid_packets_total`.
    #[must_use]
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::MalformedFrame => "bad_mac",
            Self::SelfReflection => "self_reflection",
            Self::BadMac => "bad_mac",
            Self::SenderMismatch => "sender_mismatch",
            Self::RecipientMismatch => "recipient_mismatch",
        }
    }

    /// Converts the rejection reason into an [`AppError`].
    #[must_use]
    pub fn into_app_error(self) -> AppError {
        AppError::unauthenticated(self.to_string())
    }
}

/// Extracts `outer_sender_disco_pubkey` from a raw UDP/Relay frame before decryption.
///
/// Rejects packets whose claimed outer sender equals `self_disco_pubkey` before CPU decryption.
pub fn peek_outer_sender_pubkey(
    packet: &[u8],
    self_disco_pubkey: &PublicKey,
) -> Result<PublicKey, DiscoRejectReason> {
    if packet.len() < MIN_DISCO_PACKET_LEN || packet.len() > MAX_FRAME_SIZE {
        return Err(DiscoRejectReason::MalformedFrame);
    }
    let Some(header) = packet.get(..DISCO_OUTER_HEADER_LEN) else {
        return Err(DiscoRejectReason::MalformedFrame);
    };
    let (Some(magic), Some(&version), Some(sender_slice)) =
        (header.get(0..6), header.get(6), header.get(7..39))
    else {
        return Err(DiscoRejectReason::MalformedFrame);
    };
    if magic != DISCO_MAGIC || version != DISCO_PROTOCOL_VERSION {
        return Err(DiscoRejectReason::MalformedFrame);
    }
    if ct_eq_bytes(sender_slice, self_disco_pubkey.as_bytes()) {
        return Err(DiscoRejectReason::SelfReflection);
    }
    let sender_arr =
        <[u8; 32]>::try_from(sender_slice).map_err(|_| DiscoRejectReason::MalformedFrame)?;
    PublicKey::from_bytes(sender_arr).map_err(|_| DiscoRejectReason::MalformedFrame)
}

/// Encrypts and authenticates an outbound Disco control frame binding sender & recipient identities.
pub fn seal_disco_packet(
    sender: &DiscoKeypair,
    params: &DiscoSealParams<'_>,
) -> Result<Vec<u8>, AppError> {
    let max_body = MAX_FRAME_SIZE.saturating_sub(MIN_DISCO_PACKET_LEN);
    if params.body.len() > max_body {
        return Err(AppError::invalid_argument(format!(
            "disco payload body exceeds max {} bytes",
            max_body
        )));
    }

    let mut plaintext = Vec::with_capacity(DISCO_INNER_HEADER_LEN + params.body.len());
    plaintext.extend_from_slice(&DISCO_INNER_CTX);
    plaintext.push(params.msg_type);
    plaintext.extend_from_slice(&params.tx_id);
    plaintext.extend_from_slice(&params.sent_at_ms.to_be_bytes());
    plaintext.extend_from_slice(sender.public_key().as_bytes());
    plaintext.extend_from_slice(params.recipient_pubkey.as_bytes());
    plaintext.extend_from_slice(params.body);

    let mut nonce_bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut raw_sk = *sender.secret_bytes().expose_secret();
    let sk = BoxSecretKey::from(raw_sk);
    raw_sk.zeroize();
    let pk = BoxPublicKey::from(*params.recipient_pubkey.as_bytes());
    let crypto_box = SalsaBox::new(&pk, &sk);

    let ciphertext = crypto_box
        .encrypt(&nonce_bytes.into(), plaintext.as_slice())
        .map_err(|_| AppError::internal("Disco SalsaBox encryption failed"))?;

    let mut out = Vec::with_capacity(DISCO_OUTER_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&DISCO_MAGIC);
    out.push(DISCO_PROTOCOL_VERSION);
    out.extend_from_slice(sender.public_key().as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Verifies outer/inner binding and decrypts an inbound Disco frame (`Codex #2`).
pub fn open_disco_packet(
    packet: &[u8],
    recipient: &DiscoKeypair,
) -> Result<OpenedDiscoPacket, DiscoRejectReason> {
    let outer_sender = peek_outer_sender_pubkey(packet, &recipient.public_key())?;
    let (Some(nonce_slice), Some(ciphertext)) = (packet.get(39..63), packet.get(63..)) else {
        return Err(DiscoRejectReason::MalformedFrame);
    };
    let nonce_arr =
        <[u8; 24]>::try_from(nonce_slice).map_err(|_| DiscoRejectReason::MalformedFrame)?;

    let mut raw_sk = *recipient.secret_bytes().expose_secret();
    let sk = BoxSecretKey::from(raw_sk);
    raw_sk.zeroize();
    let pk = BoxPublicKey::from(*outer_sender.as_bytes());
    let crypto_box = SalsaBox::new(&pk, &sk);

    let plaintext = crypto_box
        .decrypt(&nonce_arr.into(), ciphertext)
        .map_err(|_| DiscoRejectReason::BadMac)?;
    verify_opened_inner_payload(&plaintext, outer_sender, recipient.public_key())
}

fn verify_opened_inner_payload(
    plaintext: &[u8],
    outer_sender: PublicKey,
    self_pubkey: PublicKey,
) -> Result<OpenedDiscoPacket, DiscoRejectReason> {
    if plaintext.len() < DISCO_INNER_HEADER_LEN {
        return Err(DiscoRejectReason::MalformedFrame);
    }
    let (
        Some(ctx_slice),
        Some(&msg_type),
        Some(tx_slice),
        Some(ts_slice),
        Some(inner_sender_slice),
        Some(inner_recip_slice),
        Some(body_slice),
    ) = (
        plaintext.get(0..8),
        plaintext.get(8),
        plaintext.get(9..21),
        plaintext.get(21..29),
        plaintext.get(29..61),
        plaintext.get(61..93),
        plaintext.get(93..),
    )
    else {
        return Err(DiscoRejectReason::MalformedFrame);
    };

    if !ct_eq_bytes(ctx_slice, &DISCO_INNER_CTX) {
        return Err(DiscoRejectReason::BadMac);
    }
    if !ct_eq_bytes(inner_sender_slice, outer_sender.as_bytes()) {
        return Err(DiscoRejectReason::SenderMismatch);
    }
    if !ct_eq_bytes(inner_recip_slice, self_pubkey.as_bytes()) {
        return Err(DiscoRejectReason::RecipientMismatch);
    }

    let tx_id = <[u8; 12]>::try_from(tx_slice).map_err(|_| DiscoRejectReason::MalformedFrame)?;
    let ts_arr = <[u8; 8]>::try_from(ts_slice).map_err(|_| DiscoRejectReason::MalformedFrame)?;
    Ok(OpenedDiscoPacket {
        msg_type,
        tx_id,
        sent_at_ms: u64::from_be_bytes(ts_arr),
        sender_disco_pubkey: outer_sender,
        recipient_disco_pubkey: self_pubkey,
        body: body_slice.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use crate::keys::DiscoKeypair;

    use super::{
        DiscoRejectReason, DiscoSealParams, MIN_DISCO_PACKET_LEN, open_disco_packet,
        seal_disco_packet,
    };

    #[test]
    fn test_disco_box_roundtrip_and_anti_reflection_rejection() {
        // Arrange
        let alice = DiscoKeypair::generate();
        let bob = DiscoKeypair::generate();
        let tx_id = [0x12_u8; 12];
        let params = DiscoSealParams {
            recipient_pubkey: bob.public_key(),
            msg_type: 0x01,
            tx_id,
            sent_at_ms: 1_762_958_151_000,
            body: b"",
        };

        // Act
        let packet_res = seal_disco_packet(&alice, &params);
        assert!(packet_res.is_ok());
        let Ok(mut packet) = packet_res else {
            return;
        };
        assert_eq!(packet.len(), MIN_DISCO_PACKET_LEN);

        // Normal receipt by Bob succeeds.
        let bob_opened = open_disco_packet(&packet, &bob);
        assert!(bob_opened.is_ok());
        if let Ok(opened) = bob_opened {
            assert_eq!(opened.sender_disco_pubkey, alice.public_key());
            assert_eq!(opened.recipient_disco_pubkey, bob.public_key());
            assert_eq!(opened.tx_id, tx_id);
        }

        // Reflection 1: attacker echoes packet unmodified back to Alice -> rejected pre-decrypt as SelfReflection.
        let reflected_unmodified = open_disco_packet(&packet, &alice);
        assert_eq!(
            reflected_unmodified.err(),
            Some(DiscoRejectReason::SelfReflection)
        );

        // Reflection 2 (Codex #2): attacker overwrites outer_sender_disco_pubkey = Bob_pub and bounces to Alice.
        // Because SalsaBox key is symmetric between (Alice, Bob), MAC passes! Inner checks MUST reject!
        if let Some(outer_sender) = packet.get_mut(7..39) {
            outer_sender.copy_from_slice(bob.public_key().as_bytes());
        }
        let reflected_rewritten = open_disco_packet(&packet, &alice);

        // Assert
        assert!(matches!(
            reflected_rewritten.err(),
            Some(DiscoRejectReason::SenderMismatch | DiscoRejectReason::RecipientMismatch)
        ));
    }
}
