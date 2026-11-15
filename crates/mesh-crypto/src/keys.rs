//! Asymmetric X25519 identity/disco keypairs, pre-auth tokens, and TLS exporter bindings.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};
use rand::RngCore as _;
use rand::rngs::OsRng;
use rustls::ConnectionCommon;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize as _, Zeroizing};

use mesh_core::brand::{PREAUTH_KEY_PREFIX, TLS_EXPORTER_LABEL};
use mesh_core::{AppError, AppResult, PublicKey};

use crate::hash::{ct_eq_bytes, sha256_digest};
use crate::secret::Secret;

/// Long-lived X25519 WireGuard / Control identity keypair stored with zeroized secret bytes.
#[derive(Debug)]
pub struct NodeKeypair {
    secret: Secret<[u8; 32]>,
    public: PublicKey,
}

/// Separate X25519 keypair used strictly for authenticated peer Disco traversal (`US-021`).
#[derive(Debug)]
pub struct DiscoKeypair {
    secret: Secret<[u8; 32]>,
    public: PublicKey,
}

macro_rules! impl_x25519_keypair {
    ($ty:ident) => {
        impl $ty {
            /// Generates a fresh X25519 keypair using OS CSPRNG (`OsRng`).
            #[must_use]
            pub fn generate() -> Self {
                loop {
                    let static_secret = StaticSecret::random_from_rng(OsRng);
                    let public_x = X25519Public::from(&static_secret);
                    let Ok(public) = PublicKey::from_bytes(*public_x.as_bytes()) else {
                        continue;
                    };
                    let secret_bytes = static_secret.to_bytes();
                    return Self {
                        secret: Secret::new(secret_bytes),
                        public,
                    };
                }
            }

            /// Reconstructs the keypair from a 32-byte clamped private key, rejecting low-order public points.
            pub fn from_secret_bytes(bytes: [u8; 32]) -> AppResult<Self> {
                if bytes == [0_u8; 32] {
                    return Err(AppError::invalid_argument(
                        "X25519 private key must not be all zeros",
                    ));
                }
                let static_secret = StaticSecret::from(bytes);
                let public_x = X25519Public::from(&static_secret);
                let public = PublicKey::from_bytes(*public_x.as_bytes())?;
                Ok(Self {
                    secret: Secret::new(bytes),
                    public,
                })
            }

            /// Returns the validated public key corresponding to this keypair.
            #[must_use]
            pub const fn public_key(&self) -> PublicKey {
                self.public
            }

            /// Returns the protected secret key bytes.
            #[must_use]
            pub const fn secret_bytes(&self) -> &Secret<[u8; 32]> {
                &self.secret
            }

            /// Clones this keypair while preserving zeroization semantics.
            #[must_use]
            pub fn clone_keypair(&self) -> Self {
                Self {
                    secret: self.secret.clone_secret(),
                    public: self.public,
                }
            }
        }
    };
}

impl_x25519_keypair!(NodeKeypair);
impl_x25519_keypair!(DiscoKeypair);

/// High-entropy single-or-bounded-use pre-authentication token (`"mpk_<43_base64url>"`).
///
/// Always redacts itself via `Debug`/`Display`/`Serialize` (`SEC-01`).
pub struct PreAuthToken {
    raw: Secret<String>,
}

impl PreAuthToken {
    /// Generates a new 256-bit pre-authentication token prefixed with `mpk_`.
    #[must_use]
    pub fn generate() -> Self {
        let mut entropy = [0_u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let encoded = URL_SAFE_NO_PAD.encode(entropy);
        entropy.zeroize();
        Self {
            raw: Secret::new(format!("{PREAUTH_KEY_PREFIX}{encoded}")),
        }
    }

    /// Parses and validates pre-auth token syntax (`mpk_` prefix + >= 32 bytes base64url entropy).
    pub fn parse(token: &str) -> AppResult<Self> {
        let trimmed = token.trim();
        let Some(body) = trimmed.strip_prefix(PREAUTH_KEY_PREFIX) else {
            return Err(AppError::invalid_argument(
                "invalid pre-auth key format: missing `mpk_` prefix",
            ));
        };
        let mut decoded = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| AppError::invalid_argument("invalid pre-auth key base64url payload"))?;
        let valid_len = decoded.len() >= 32;
        decoded.zeroize();
        if !valid_len {
            return Err(AppError::invalid_argument(
                "invalid pre-auth key entropy: must be >= 256 bits",
            ));
        }
        Ok(Self {
            raw: Secret::new(trimmed.to_owned()),
        })
    }

    /// Computes the non-reversible 32-byte SHA-256 digest stored by `mesh-store`.
    #[must_use]
    pub fn sha256_digest(&self) -> [u8; 32] {
        sha256_digest(self.raw.expose_secret().as_bytes())
    }

    /// Returns a reference to the protected inner `Secret<String>`.
    #[must_use]
    pub const fn as_secret(&self) -> &Secret<String> {
        &self.raw
    }

    /// Returns a masked display string preserving only a tiny boundary hint (e.g. `mpk_AbCd...6789`).
    #[must_use]
    pub fn masked_preview(&self) -> String {
        mask_preauth_token(self.raw.expose_secret())
    }
}

/// Formats a pre-authentication token with middle characters redacted (`SEC-01`).
///
/// Short, malformed, or non-ASCII inputs collapse completely to `"[REDACTED]"`.
#[must_use]
pub fn mask_preauth_token(raw: &str) -> String {
    let trimmed = raw.trim();
    let min_maskable_len = PREAUTH_KEY_PREFIX.len() + 16;
    if !trimmed.is_ascii()
        || !trimmed.starts_with(PREAUTH_KEY_PREFIX)
        || trimmed.len() < min_maskable_len
    {
        return "[REDACTED]".to_owned();
    }
    let prefix_end = PREAUTH_KEY_PREFIX.len() + 4;
    let suffix_start = trimmed.len().saturating_sub(4);
    match (trimmed.get(..prefix_end), trimmed.get(suffix_start..)) {
        (Some(head), Some(tail)) => format!("{head}...{tail}"),
        _ => "[REDACTED]".to_owned(),
    }
}

impl fmt::Debug for PreAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreAuthToken([REDACTED])")
    }
}

impl fmt::Display for PreAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Generates `N` cryptographically secure random bytes from `OsRng`.
#[must_use]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0_u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Extracts the 32-byte RFC 5705 TLS keying material channel binding (`EXPORTER-mesh-control-v1`).
pub fn extract_tls_exporter_binding<Data>(conn: &ConnectionCommon<Data>) -> AppResult<[u8; 32]> {
    let out = [0_u8; 32];
    conn.export_keying_material(out, TLS_EXPORTER_LABEL, None)
        .map_err(|err| AppError::internal(format!("TLS exporter binding unavailable: {err}")))
}

/// Seals `plaintext` using `ChaCha20-Poly1305` under `dek`, returning `magic || nonce[12] || ct_and_tag`.
pub fn seal_aead_with_dek(
    dek: &[u8; 32],
    aad: &[u8],
    magic: &[u8; 4],
    plaintext: &[u8],
) -> AppResult<Vec<u8>> {
    if ct_eq_bytes(dek, &[0_u8; 32]) {
        return Err(AppError::invalid_argument(
            "identity DEK must not be all zeros",
        ));
    }
    let nonce_bytes: [u8; 12] = random_bytes();
    let cipher = ChaCha20Poly1305::new_from_slice(dek)
        .map_err(|_| AppError::invalid_argument("invalid 32-byte ChaCha20-Poly1305 DEK"))?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AppError::internal("failed sealing payload with ChaCha20-Poly1305"))?;

    let mut out = Vec::with_capacity(magic.len() + nonce_bytes.len() + ciphertext.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Verifies `magic || nonce[12] || ct_and_tag` and returns decrypted bytes inside [`Zeroizing`].
pub fn unseal_aead_with_dek(
    dek: &[u8; 32],
    aad: &[u8],
    magic: &[u8; 4],
    sealed: &[u8],
) -> AppResult<Zeroizing<Vec<u8>>> {
    if ct_eq_bytes(dek, &[0_u8; 32]) {
        return Err(AppError::invalid_argument(
            "identity DEK must not be all zeros",
        ));
    }
    let Some(rest) = sealed.strip_prefix(magic.as_slice()) else {
        return Err(AppError::invalid_argument(
            "invalid sealed identity blob header",
        ));
    };
    let Some((nonce_slice, ciphertext)) = rest.split_at_checked(12) else {
        return Err(AppError::invalid_argument(
            "sealed identity blob truncated before nonce",
        ));
    };
    if ciphertext.len() < 16 {
        return Err(AppError::invalid_argument(
            "sealed identity blob truncated before Poly1305 tag",
        ));
    }
    let nonce_bytes: [u8; 12] = nonce_slice
        .try_into()
        .map_err(|_| AppError::invalid_argument("invalid sealed identity nonce length"))?;

    let cipher = ChaCha20Poly1305::new_from_slice(dek)
        .map_err(|_| AppError::invalid_argument("invalid 32-byte ChaCha20-Poly1305 DEK"))?;
    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            AppError::invalid_argument("sealed identity authentication failed or wrong DEK")
        })?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "certgen")]
    use std::io;
    #[cfg(feature = "certgen")]
    use std::net::Ipv4Addr;
    #[cfg(feature = "certgen")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(feature = "certgen")]
    use rustls::pki_types::{IpAddr, ServerName};
    #[cfg(feature = "certgen")]
    use rustls::{ClientConnection, ServerConnection};

    #[cfg(feature = "certgen")]
    use crate::certgen::{build_rustls_server_config_from_der, generate_ip_pinned_cert};
    #[cfg(feature = "certgen")]
    use crate::tlspin::{PinSet, build_pinned_client_config};

    #[cfg(feature = "certgen")]
    use super::extract_tls_exporter_binding;
    use super::{
        DiscoKeypair, NodeKeypair, PreAuthToken, mask_preauth_token, random_bytes,
        seal_aead_with_dek, unseal_aead_with_dek,
    };

    #[test]
    fn test_keypairs_and_preauth_token_redact_secrets_and_reject_zero() {
        // Arrange
        let node = NodeKeypair::generate();
        let disco = DiscoKeypair::generate();
        let token = PreAuthToken::generate();

        // Act
        let dbg_token = format!("{token:?}");
        let disp_token = format!("{token}");
        let parsed = PreAuthToken::parse(token.as_secret().expose_secret());
        let short = PreAuthToken::parse("mpk_abc");
        let zero_node = NodeKeypair::from_secret_bytes([0_u8; 32]);
        let r1 = random_bytes::<12>();
        let r2 = random_bytes::<12>();

        // Assert
        assert_ne!(node.public_key(), disco.public_key());
        assert_eq!(dbg_token, "PreAuthToken([REDACTED])");
        assert_eq!(disp_token, "[REDACTED]");
        assert!(!dbg_token.contains(token.as_secret().expose_secret()));
        assert!(parsed.is_ok());
        if let Ok(re_parsed) = parsed {
            assert_eq!(re_parsed.sha256_digest(), token.sha256_digest());
        }
        assert!(short.is_err());
        assert!(zero_node.is_err());
        assert_ne!(r1, [0_u8; 12]);
        assert_ne!(r1, r2);
    }

    #[cfg(feature = "certgen")]
    #[test]
    fn test_tls_exporter_binding_matches_between_client_and_server() {
        // Arrange
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1_794_529_922, |dur| dur.as_secs())
            .saturating_sub(60);
        let identity = generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 7, now_secs);
        assert!(identity.is_ok());
        let Ok(id) = identity else {
            return;
        };
        let server_cfg = build_rustls_server_config_from_der(
            vec![id.cert_der],
            &id.key_pkcs8_der,
            vec![b"http/1.1".to_vec()],
        );
        assert!(server_cfg.is_ok());
        let Ok(srv_cfg) = server_cfg else {
            return;
        };
        let client_cfg = build_pinned_client_config(PinSet::single(id.spki_pin));
        assert!(client_cfg.is_ok());
        let Ok(cli_cfg) = client_cfg else {
            return;
        };

        let server_name = ServerName::IpAddress(IpAddr::from(Ipv4Addr::LOCALHOST));
        let mut client = match ClientConnection::new(cli_cfg, server_name) {
            Ok(c) => c,
            Err(err) => {
                assert!(err.to_string().is_empty(), "client creation failed: {err}");
                return;
            }
        };
        let mut server = match ServerConnection::new(std::sync::Arc::new(srv_cfg)) {
            Ok(s) => s,
            Err(err) => {
                assert!(err.to_string().is_empty(), "server creation failed: {err}");
                return;
            }
        };

        // Act: complete in-memory TLS 1.3 handshake
        while client.is_handshaking() || server.is_handshaking() {
            let mut c_to_s = Vec::new();
            let write_c = client.write_tls(&mut c_to_s);
            assert!(write_c.is_ok());
            if !c_to_s.is_empty() {
                let mut reader = io::Cursor::new(c_to_s);
                assert!(server.read_tls(&mut reader).is_ok());
                assert!(server.process_new_packets().is_ok());
            }

            let mut s_to_c = Vec::new();
            let write_s = server.write_tls(&mut s_to_c);
            assert!(write_s.is_ok());
            if !s_to_c.is_empty() {
                let mut reader = io::Cursor::new(s_to_c);
                assert!(client.read_tls(&mut reader).is_ok());
                assert!(client.process_new_packets().is_ok());
            }
        }

        let client_binding = extract_tls_exporter_binding(&client);
        let server_binding = extract_tls_exporter_binding(&server);

        // Assert
        assert!(client_binding.is_ok());
        assert!(server_binding.is_ok());
        assert_eq!(client_binding.ok(), server_binding.ok());
    }

    #[test]
    fn test_mask_preauth_token_preserves_short_preview_and_redacts_invalid() {
        // Arrange
        let generated = PreAuthToken::generate();
        let raw_secret = generated.as_secret().expose_secret();

        // Act
        let masked_gen = generated.masked_preview();
        let masked_sample = mask_preauth_token("mpk_AbCdEfGhIjKlMnOpQrStUvWxYz6789");
        let masked_short = mask_preauth_token("mpk_short");
        let masked_bad_prefix = mask_preauth_token("other_AbCdEfGhIjKlMnOpQrStUv6789");
        let masked_unicode = mask_preauth_token("mpk_AbCd\u{00e9}GhIjKlMnOpQrStUvWx6789");

        // Assert
        assert!(masked_gen.starts_with("mpk_"));
        assert!(masked_gen.contains("..."));
        assert!(!masked_gen.contains(raw_secret));
        assert_eq!(masked_sample, "mpk_AbCd...6789");
        assert_eq!(masked_short, "[REDACTED]");
        assert_eq!(masked_bad_prefix, "[REDACTED]");
        assert_eq!(masked_unicode, "[REDACTED]");
    }

    #[test]
    fn test_aead_dek_roundtrip_and_rejects_tamper_wrong_dek_aad_or_magic() {
        // Arrange
        let dek = [0x37_u8; 32];
        let wrong_dek = [0x99_u8; 32];
        let magic = *b"MSH1";
        let aad = b"mesh-identity-v1";
        let plaintext = b"{\"schema_version\":1,\"secret\":\"sensitive_payload\"}";

        // Act
        let sealed = seal_aead_with_dek(&dek, aad, &magic, plaintext);
        assert!(sealed.is_ok());
        let Ok(mut blob) = sealed else {
            return;
        };
        let opened = unseal_aead_with_dek(&dek, aad, &magic, &blob);
        let wrong_dek_res = unseal_aead_with_dek(&wrong_dek, aad, &magic, &blob);
        let wrong_aad_res = unseal_aead_with_dek(&dek, b"wrong-aad", &magic, &blob);
        let wrong_magic_res = unseal_aead_with_dek(&dek, aad, b"MSH2", &blob);

        let mut tampered_tag = blob.clone();
        if let Some(last) = tampered_tag.last_mut() {
            *last ^= 0x01;
        }
        let tampered_res = unseal_aead_with_dek(&dek, aad, &magic, &tampered_tag);
        blob.truncate(20);
        let truncated_res = unseal_aead_with_dek(&dek, aad, &magic, &blob);

        // Assert
        assert_eq!(
            opened.ok().as_deref().map(Vec::as_slice),
            Some(plaintext.as_slice())
        );
        assert!(wrong_dek_res.is_err());
        assert!(wrong_aad_res.is_err());
        assert!(wrong_magic_res.is_err());
        assert!(tampered_res.is_err());
        assert!(truncated_res.is_err());
    }
}
