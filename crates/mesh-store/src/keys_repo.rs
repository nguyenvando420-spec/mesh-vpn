//! Pre-authentication key generation, bounded/reusable tracking, and revocation (`WP-S1-01`).

use mesh_core::{AppError, AppResult, KeyId};

/// Repository managing hashed pre-auth keys (`WP-S1-01`).
#[derive(Debug, Default)]
pub struct KeysRepository;

impl KeysRepository {
    /// Revokes a pre-auth key identifier (`WP-S1-01`).
    pub fn revoke_key(_key_id: KeyId) -> AppResult<()> {
        Err(AppError::unavailable(
            "pre-auth key repository will be implemented in WP-S1-01",
        ))
    }
}
