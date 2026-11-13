//! Server ECDSA P-256 identity persistence keeping raw private keys wrapped in `Secret<Vec<u8>>`
//! (`SEC-01`, `WP-S1-01`).

use mesh_core::{AppError, AppResult, SpkiPin};
use mesh_crypto::Secret;

/// Loaded server identity holding DER-encoded key material inside [`Secret`].
#[derive(Debug)]
pub struct ServerIdentity {
    /// Active SPKI SHA-256 pin derived from the signing public key.
    pub spki_pin: SpkiPin,
    /// DER private key bytes automatically zeroized on drop.
    pub private_key_der: Secret<Vec<u8>>,
    /// DER X.509 certificate chain.
    pub cert_chain_der: Vec<Vec<u8>>,
}

/// Repository persisting/rotating the control server certificate identity (`WP-S1-01`).
#[derive(Debug, Default)]
pub struct IdentityRepository;

impl IdentityRepository {
    /// Loads the active server identity from `redb` (`WP-S1-01`).
    pub fn load_active() -> AppResult<ServerIdentity> {
        Err(AppError::unavailable(
            "server identity repository will be implemented in WP-S1-01",
        ))
    }
}
