//! Control-plane challenge proof sealing and opening via `crypto_box::SalsaBox` (`ADR-003`, `BLK-G2-02`).

use crypto_box::aead::{Aead as _, OsRng};
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use mesh_core::defaults::CONTROL_MAX_SKEW_SECS;
use mesh_core::{AppError, AppResult, NodeId, PublicKey};

use crate::hash::ct_eq_bytes;
use crate::keys::NodeKeypair;
use crate::secret::Secret;

/// JSON structure encrypted by clients inside `X-Mesh-Auth-Proof` (`api-design.md` §1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofPayload {
    /// Server-issued single-use challenge UUID.
    pub challenge_id: NodeId,
    /// Server-issued 32-byte base64-encoded challenge nonce.
    pub challenge_nonce: String,
    /// Uppercase HTTP method (`POST`, `GET`).
    pub method: String,
    /// Canonical request path (`/v1/nodes/register`, `/v1/netmap/stream`, `/v1/relay`, etc.).
    pub path: String,
    /// Lowercase SHA-256 hex digest of the raw request body (`SHA256("")` for WebSocket GET).
    pub body_sha256: String,
    /// Client node X25519 public key.
    pub node_pubkey: PublicKey,
    /// Client Disco X25519 public key.
    pub disco_pubkey: PublicKey,
    /// Client estimated server-anchored Unix timestamp in milliseconds.
    pub timestamp_at_ms: u64,
    /// Base64-encoded 32-byte RFC 5705 TLS exporter material bound to the active connection.
    pub tls_exporter_binding: String,
}

/// Sealed `X-Mesh-Auth-Proof` header outputs produced by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAuthProof {
    /// 24-byte XSalsa20Poly1305 nonce (`X-Mesh-Box-Nonce`).
    pub box_nonce: [u8; 24],
    /// Ciphertext plus Poly1305 tag (`X-Mesh-Auth-Proof`).
    pub ciphertext: Vec<u8>,
}

/// Server-side expectations enforced when verifying an opened [`ProofPayload`].
#[derive(Debug, Clone, Copy)]
pub struct ExpectedProofClaims<'a> {
    /// Expected challenge UUID (atomically removed from `pending_challenges` prior to decrypt).
    pub challenge_id: NodeId,
    /// Expected challenge nonce (base64 encoded 32-byte value).
    pub challenge_nonce_b64: &'a str,
    /// Expected uppercase HTTP method.
    pub method: &'a str,
    /// Expected HTTP request path.
    pub path: &'a str,
    /// Expected lowercase hex SHA-256 of the HTTP body.
    pub body_sha256_hex: &'a str,
    /// Claimed sender node public key from `X-Mesh-Node-Pubkey`.
    pub claimed_node_pubkey: PublicKey,
    /// Current authoritative server UTC timestamp in milliseconds.
    pub now_unix_ms: u64,
    /// Expected base64-encoded TLS exporter when terminating TLS directly (`None` behind trusted reverse proxy).
    pub expected_tls_exporter_b64: Option<&'a str>,
}

/// Encrypts `payload` for `server_eph_pubkey` using the client's `NodeKeypair` (`SalsaBox`).
pub fn seal_proof(
    payload: &ProofPayload,
    server_eph_pubkey: &PublicKey,
    client_keypair: &NodeKeypair,
) -> AppResult<SealedAuthProof> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|err| AppError::internal(format!("failed to serialize auth proof: {err}")))?;

    let mut nonce_bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut raw_sk = *client_keypair.secret_bytes().expose_secret();
    let sk = BoxSecretKey::from(raw_sk);
    raw_sk.zeroize();
    let pk = BoxPublicKey::from(*server_eph_pubkey.as_bytes());
    let crypto_box = SalsaBox::new(&pk, &sk);

    let ciphertext = crypto_box
        .encrypt(&nonce_bytes.into(), plaintext.as_slice())
        .map_err(|_| AppError::internal("SalsaBox encryption failed"))?;
    Ok(SealedAuthProof {
        box_nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts `ciphertext` with `server_eph_secret` and `claimed_node_pubkey`, failing uniformly
/// with [`ErrorKind::Unauthenticated`] (`SEC-05`) on any tampering or key mismatch.
pub fn open_proof(
    ciphertext: &[u8],
    box_nonce: &[u8; 24],
    claimed_node_pubkey: &PublicKey,
    server_eph_secret: &Secret<[u8; 32]>,
) -> AppResult<ProofPayload> {
    let mut raw_sk = *server_eph_secret.expose_secret();
    let sk = BoxSecretKey::from(raw_sk);
    raw_sk.zeroize();
    let pk = BoxPublicKey::from(*claimed_node_pubkey.as_bytes());
    let crypto_box = SalsaBox::new(&pk, &sk);

    let plaintext = crypto_box
        .decrypt(box_nonce.into(), ciphertext)
        .map_err(|_| AppError::unauthenticated("SalsaBox decryption failed"))?;
    serde_json::from_slice(&plaintext)
        .map_err(|_| AppError::unauthenticated("malformed ProofPayload JSON"))
}

/// Validates decrypted [`ProofPayload`] claims in constant time against server challenge state.
pub fn verify_proof_claims(
    proof: &ProofPayload,
    expected: &ExpectedProofClaims<'_>,
) -> AppResult<()> {
    let nonce_match = ct_eq_bytes(
        proof.challenge_nonce.as_bytes(),
        expected.challenge_nonce_b64.as_bytes(),
    );
    let body_match = ct_eq_bytes(
        proof.body_sha256.as_bytes(),
        expected.body_sha256_hex.as_bytes(),
    );
    let exporter_match = match expected.expected_tls_exporter_b64 {
        Some(expected_exp) => ct_eq_bytes(
            proof.tls_exporter_binding.as_bytes(),
            expected_exp.as_bytes(),
        ),
        None => true,
    };

    let skew_ms = proof.timestamp_at_ms.abs_diff(expected.now_unix_ms);
    let max_skew_ms = CONTROL_MAX_SKEW_SECS.saturating_mul(1_000);

    if proof.challenge_id != expected.challenge_id
        || !nonce_match
        || proof.method != expected.method
        || proof.path != expected.path
        || !body_match
        || proof.node_pubkey != expected.claimed_node_pubkey
        || !exporter_match
        || skew_ms > max_skew_ms
    {
        return Err(AppError::unauthenticated("proof claim mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use mesh_core::{ErrorKind, NodeId};

    use crate::hash::sha256_hex;
    use crate::keys::{DiscoKeypair, NodeKeypair};

    use super::{ExpectedProofClaims, ProofPayload, open_proof, seal_proof, verify_proof_claims};

    #[test]
    fn test_auth_box_seal_open_and_reject_tamper() {
        // Arrange
        let now_ms = 1_762_958_151_000_u64;
        let client_node = NodeKeypair::generate();
        let client_disco = DiscoKeypair::generate();
        let server_eph = NodeKeypair::generate();
        let challenge_id = NodeId::new_v7(now_ms);
        let challenge_nonce = STANDARD.encode([0x44_u8; 32]);
        let exporter_b64 = STANDARD.encode([0x55_u8; 32]);
        let body_hash = sha256_hex(b"{}");

        let payload = ProofPayload {
            challenge_id,
            challenge_nonce: challenge_nonce.clone(),
            method: "POST".to_owned(),
            path: "/v1/nodes/register".to_owned(),
            body_sha256: body_hash.clone(),
            node_pubkey: client_node.public_key(),
            disco_pubkey: client_disco.public_key(),
            timestamp_at_ms: now_ms + 120,
            tls_exporter_binding: exporter_b64.clone(),
        };

        // Act
        let sealed = seal_proof(&payload, &server_eph.public_key(), &client_node);
        assert!(sealed.is_ok());
        let Ok(sealed) = sealed else {
            return;
        };

        let opened = open_proof(
            &sealed.ciphertext,
            &sealed.box_nonce,
            &client_node.public_key(),
            server_eph.secret_bytes(),
        );
        assert!(opened.is_ok());
        let Ok(opened) = opened else {
            return;
        };

        let expected = ExpectedProofClaims {
            challenge_id,
            challenge_nonce_b64: &challenge_nonce,
            method: "POST",
            path: "/v1/nodes/register",
            body_sha256_hex: &body_hash,
            claimed_node_pubkey: client_node.public_key(),
            now_unix_ms: now_ms + 200,
            expected_tls_exporter_b64: Some(&exporter_b64),
        };
        let verified = verify_proof_claims(&opened, &expected);

        let wrong_exporter = ExpectedProofClaims {
            expected_tls_exporter_b64: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            ..expected
        };
        let rejected = verify_proof_claims(&opened, &wrong_exporter);

        // Assert
        assert!(verified.is_ok());
        assert!(rejected.is_err());
        if let Err(err) = rejected {
            assert_eq!(err.kind(), ErrorKind::Unauthenticated);
            assert_eq!(err.public_message(), "authentication failed");
        }
    }

    #[test]
    fn test_auth_box_payload_rejects_unknown_fields() {
        // Arrange
        let now_ms = 1_762_958_151_000_u64;
        let client_node = NodeKeypair::generate();
        let client_disco = DiscoKeypair::generate();
        let raw_json = format!(
            concat!(
                "{{",
                "\"challenge_id\":\"{}\",",
                "\"challenge_nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",",
                "\"method\":\"POST\",",
                "\"path\":\"/v1/nodes/register\",",
                "\"body_sha256\":\"{}\",",
                "\"node_pubkey\":\"{}\",",
                "\"disco_pubkey\":\"{}\",",
                "\"timestamp_at_ms\":{},",
                "\"tls_exporter_binding\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",",
                "\"unexpected_extra\":true",
                "}}"
            ),
            NodeId::new_v7(now_ms),
            sha256_hex(b"{}"),
            client_node.public_key(),
            client_disco.public_key(),
            now_ms
        );

        // Act
        let parsed: Result<ProofPayload, _> = serde_json::from_str(&raw_json);

        // Assert
        assert!(parsed.is_err());
    }
}
