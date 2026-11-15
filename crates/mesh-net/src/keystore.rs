//! Fail-closed client identity key storage (`keys.json`, mode `0600`).

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use mesh_core::{AppError, AppResult, NodeId, PublicKey};
use mesh_crypto::keys::{seal_aead_with_dek, unseal_aead_with_dek};
use mesh_crypto::secret::{Secret, Zeroize as _, Zeroizing};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use serde::{Deserialize, Serialize};

/// Current schema version for `keys.json`.
pub const KEYSTORE_SCHEMA_VERSION: u32 = 1;

/// Magic header for DEK-sealed mobile identities (`"MSH1"`).
pub const SEALED_IDENTITY_MAGIC: [u8; 4] = *b"MSH1";

/// AEAD additional authenticated data bound to DEK-sealed mobile identities.
pub const SEALED_IDENTITY_AAD: &[u8] = b"mesh-identity-v1";

/// Loaded client cryptographic identity protected in memory by `mesh_crypto::Secret`.
pub struct StoredNodeIdentity {
    /// Assigned server node identifier (`None` prior to initial registration).
    pub node_id: Option<NodeId>,
    /// Long-lived WireGuard/Control identity keypair.
    pub node_keypair: NodeKeypair,
    /// Separate peer-discovery Disco X25519 keypair.
    pub disco_keypair: DiscoKeypair,
    /// Unix creation timestamp in milliseconds.
    pub created_at_ms: u64,
}

impl fmt::Debug for StoredNodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredNodeIdentity")
            .field("node_id", &self.node_id)
            .field("node_pubkey", &self.node_keypair.public_key())
            .field("disco_pubkey", &self.disco_keypair.public_key())
            .field("node_secret", &"[REDACTED]")
            .field("disco_secret", &"[REDACTED]")
            .field("created_at_ms", &self.created_at_ms)
            .finish()
    }
}

impl StoredNodeIdentity {
    /// Seals this identity with a 32-byte hardware-wrapped DEK (`"MSH1" || nonce[12] || ct_and_tag`)
    /// bound to AAD `"mesh-identity-v1"` (`IG-MOB-G2-02`).
    pub fn seal_with_dek(&self, dek: &[u8; 32]) -> AppResult<Vec<u8>> {
        let plaintext_json = serialize_identity_zeroizing(self)?;
        seal_aead_with_dek(
            dek,
            SEALED_IDENTITY_AAD,
            &SEALED_IDENTITY_MAGIC,
            &plaintext_json,
        )
    }

    /// Unseals an encrypted `"MSH1" || nonce[12] || ct_and_tag` blob using the 32-byte DEK
    /// (`IG-MOB-G2-02`).
    pub fn unseal_with_dek(ciphertext: &[u8], dek: &[u8; 32]) -> AppResult<Self> {
        let plaintext_json =
            unseal_aead_with_dek(dek, SEALED_IDENTITY_AAD, &SEALED_IDENTITY_MAGIC, ciphertext)?;
        parse_keys_json(&plaintext_json)
    }
}

#[derive(Serialize, Deserialize)]
struct KeysFileJson {
    schema_version: u32,
    node_id: Option<NodeId>,
    node_pubkey: PublicKey,
    node_privkey_hex: String,
    disco_privkey_hex: String,
    created_at_ms: u64,
}

/// Persists and validates client key material in `keys.json` without overwriting corrupt files.
#[derive(Debug, Clone)]
pub struct KeysFileStore {
    path: PathBuf,
}

impl KeysFileStore {
    /// Returns the OS default path for client `keys.json`.
    #[must_use]
    pub fn default_keystore_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/var/db/mesh/keys.json")
        }
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Mesh\keys.json")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            PathBuf::from("/var/lib/meshd/keys.json")
        }
    }

    /// Creates a store targeting the OS default path.
    #[must_use]
    pub fn default_store() -> Self {
        Self::new(Self::default_keystore_path())
    }

    /// Creates a store backed by a specific `keys.json` path.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the underlying `keys.json` path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads an existing `keys.json`, failing closed if absent, unreadable, or corrupt.
    pub fn load_existing(&self) -> AppResult<StoredNodeIdentity> {
        let bytes = fs::read(&self.path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                AppError::not_found(format!("keystore file {} not found", self.path.display()))
            } else {
                AppError::internal(format!("failed to read {}: {err}", self.path.display()))
            }
        })?;
        parse_keys_json(&bytes)
    }

    /// Loads `keys.json` if present, or atomically generates and persists fresh keys ONLY when absent.
    ///
    /// Never overwrites an existing file — even if corrupted or unreadable (fail-closed).
    pub fn load_or_create(&self, now_ms: u64) -> AppResult<StoredNodeIdentity> {
        match fs::read(&self.path) {
            Ok(bytes) => parse_keys_json(&bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.create_new_identity(now_ms)
            }
            Err(err) => Err(AppError::internal(format!(
                "refusing to touch unreadable keystore {}: {err}",
                self.path.display()
            ))),
        }
    }

    /// Atomically replaces `keys.json` after explicit key rotation (`0600`).
    pub fn save_rotated(&self, identity: &StoredNodeIdentity) -> AppResult<()> {
        let bytes = serialize_identity_zeroizing(identity)?;
        let parent = self.path.parent().ok_or_else(|| {
            AppError::invalid_argument("keystore path must have a parent directory")
        })?;
        fs::create_dir_all(parent).map_err(|err| {
            AppError::internal(format!("failed to create {}: {err}", parent.display()))
        })?;

        let tmp_name = format!(
            "{}.tmp.{}",
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("keys.json"),
            std::process::id()
        );
        let tmp_path = parent.join(tmp_name);
        match write_exclusive_0600(&tmp_path, &bytes, true) {
            Ok(()) => {}
            Err(WriteExclusiveError::AlreadyExists) => {
                return Err(AppError::internal(
                    "temporary keystore file unexpectedly existed",
                ));
            }
            Err(WriteExclusiveError::Other(err)) => return Err(err),
        }
        fs::rename(&tmp_path, &self.path).map_err(|err| {
            AppError::internal(format!(
                "failed to replace keystore {}: {err}",
                self.path.display()
            ))
        })
    }

    /// Records the assigned [`NodeId`] in `keys.json` after initial node registration.
    pub fn set_node_id(&self, node_id: NodeId) -> AppResult<StoredNodeIdentity> {
        let mut identity = self.load_existing()?;
        identity.node_id = Some(node_id);
        self.save_rotated(&identity)?;
        Ok(identity)
    }

    fn create_new_identity(&self, now_ms: u64) -> AppResult<StoredNodeIdentity> {
        let parent = self.path.parent().ok_or_else(|| {
            AppError::invalid_argument("keystore path must have a parent directory")
        })?;
        fs::create_dir_all(parent).map_err(|err| {
            AppError::internal(format!("failed to create {}: {err}", parent.display()))
        })?;

        let identity = StoredNodeIdentity {
            node_id: None,
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            created_at_ms: now_ms,
        };
        let bytes = serialize_identity_zeroizing(&identity)?;

        match write_exclusive_0600(&self.path, &bytes, false) {
            Ok(()) => Ok(identity),
            Err(WriteExclusiveError::AlreadyExists) => self.load_existing(),
            Err(WriteExclusiveError::Other(err)) => Err(err),
        }
    }
}

enum WriteExclusiveError {
    AlreadyExists,
    Other(AppError),
}

fn write_exclusive_0600(
    path: &Path,
    data: &[u8],
    overwrite: bool,
) -> Result<(), WriteExclusiveError> {
    let mut opts = OpenOptions::new();
    if overwrite {
        opts.write(true).create(true).truncate(true);
    } else {
        opts.write(true).create_new(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(path).map_err(|err| {
        if !overwrite && err.kind() == std::io::ErrorKind::AlreadyExists {
            WriteExclusiveError::AlreadyExists
        } else {
            WriteExclusiveError::Other(AppError::internal(format!(
                "failed to create {}: {err}",
                path.display()
            )))
        }
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| {
                WriteExclusiveError::Other(AppError::internal(format!(
                    "failed to chmod 0600 {}: {err}",
                    path.display()
                )))
            })?;
    }

    file.write_all(data).map_err(|err| {
        WriteExclusiveError::Other(AppError::internal(format!(
            "failed to write {}: {err}",
            path.display()
        )))
    })?;
    file.sync_all().map_err(|err| {
        WriteExclusiveError::Other(AppError::internal(format!(
            "failed to sync {}: {err}",
            path.display()
        )))
    })
}

fn serialize_identity_zeroizing(identity: &StoredNodeIdentity) -> AppResult<Zeroizing<Vec<u8>>> {
    let node_priv_hex = Secret::new(encode_hex_32(
        identity.node_keypair.secret_bytes().expose_secret(),
    ));
    let disco_priv_hex = Secret::new(encode_hex_32(
        identity.disco_keypair.secret_bytes().expose_secret(),
    ));
    let mut dto = KeysFileJson {
        schema_version: KEYSTORE_SCHEMA_VERSION,
        node_id: identity.node_id,
        node_pubkey: identity.node_keypair.public_key(),
        node_privkey_hex: node_priv_hex.expose_secret().clone(),
        disco_privkey_hex: disco_priv_hex.expose_secret().clone(),
        created_at_ms: identity.created_at_ms,
    };
    let encoded_res = serde_json::to_vec_pretty(&dto);
    dto.node_privkey_hex.zeroize();
    dto.disco_privkey_hex.zeroize();
    let encoded = encoded_res
        .map_err(|err| AppError::internal(format!("failed to serialize keystore: {err}")))?;
    Ok(Zeroizing::new(encoded))
}

fn parse_keys_json(bytes: &[u8]) -> AppResult<StoredNodeIdentity> {
    let mut parsed: KeysFileJson = serde_json::from_slice(bytes)
        .map_err(|err| AppError::invalid_argument(format!("corrupt keystore JSON: {err}")))?;
    if parsed.schema_version != KEYSTORE_SCHEMA_VERSION {
        parsed.node_privkey_hex.zeroize();
        parsed.disco_privkey_hex.zeroize();
        return Err(AppError::invalid_argument(format!(
            "unsupported keystore schema version {}",
            parsed.schema_version
        )));
    }
    let node_secret_res = decode_hex_32(&parsed.node_privkey_hex).map(Secret::new);
    parsed.node_privkey_hex.zeroize();
    let disco_secret_res = decode_hex_32(&parsed.disco_privkey_hex).map(Secret::new);
    parsed.disco_privkey_hex.zeroize();
    let node_secret = node_secret_res?;
    let disco_secret = disco_secret_res?;

    let node_keypair = NodeKeypair::from_secret_bytes(*node_secret.expose_secret())?;
    if node_keypair.public_key() != parsed.node_pubkey {
        return Err(AppError::invalid_argument(
            "keystore node_pubkey mismatches derived public key",
        ));
    }
    let disco_keypair = DiscoKeypair::from_secret_bytes(*disco_secret.expose_secret())?;

    Ok(StoredNodeIdentity {
        node_id: parsed.node_id,
        node_keypair,
        disco_keypair,
        created_at_ms: parsed.created_at_ms,
    })
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        if let (Some(&c_hi), Some(&c_lo)) = (HEX_DIGITS.get(hi), HEX_DIGITS.get(lo)) {
            out.push(char::from(c_hi));
            out.push(char::from(c_lo));
        }
    }
    out
}

fn decode_hex_32(hex: &str) -> AppResult<[u8; 32]> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err(AppError::invalid_argument(
            "keystore private key hex must be exactly 64 characters",
        ));
    }
    let mut out = [0_u8; 32];
    for (idx, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let (Some(&hi), Some(&lo)) = (chunk.first(), chunk.get(1)) else {
            return Err(AppError::invalid_argument("invalid private key hex length"));
        };
        let nibble_hi = hex_nibble(hi)?;
        let nibble_lo = hex_nibble(lo)?;
        if let Some(slot) = out.get_mut(idx) {
            *slot = (nibble_hi << 4) | nibble_lo;
        }
    }
    Ok(out)
}

fn hex_nibble(ch: u8) -> AppResult<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        b'A'..=b'F' => Ok(ch - b'A' + 10),
        _ => Err(AppError::invalid_argument(
            "invalid hex character in keystore private key",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::KeysFileStore;

    #[test]
    fn test_keystore_creates_once_and_never_overwrites_corrupt_file() {
        // Arrange
        let dir = match TempDir::new() {
            Ok(d) => d,
            Err(err) => {
                assert_eq!(err.to_string(), "tempdir failed");
                return;
            }
        };
        let path = dir.path().join("keys.json");
        let store = KeysFileStore::new(path.clone());

        // Act
        let first = match store.load_or_create(1_700_000_000_000) {
            Ok(id) => id,
            Err(err) => {
                assert_eq!(err.to_string(), "initial key creation failed");
                return;
            }
        };
        let second = match store.load_or_create(1_700_000_999_000) {
            Ok(id) => id,
            Err(err) => {
                assert_eq!(err.to_string(), "reload failed");
                return;
            }
        };

        // Assert identity stability and redaction
        assert_eq!(
            first.node_keypair.public_key(),
            second.node_keypair.public_key()
        );
        assert_eq!(second.created_at_ms, 1_700_000_000_000);
        let debug_str = format!("{first:?}");
        assert!(debug_str.contains("[REDACTED]"));

        // Corrupt existing file and verify fail-closed NEVER overwrites bytes
        let corrupt_path = dir.path().join("corrupt-keys.json");
        let corrupt_bytes = b"CORRUPT_DO_NOT_OVERWRITE{";
        assert!(fs::write(&corrupt_path, corrupt_bytes).is_ok());
        let corrupt_store = KeysFileStore::new(corrupt_path.clone());

        let corrupt_res = corrupt_store.load_or_create(1_700_000_000_000);
        assert!(corrupt_res.is_err());

        let preserved = fs::read(&corrupt_path).unwrap_or_default();
        assert_eq!(preserved.as_slice(), corrupt_bytes);
    }

    #[test]
    fn test_keystore_dek_seal_and_unseal_roundtrip_preserves_identity() {
        // Arrange
        let dek = [0x42_u8; 32];
        let node = mesh_crypto::NodeKeypair::generate();
        let disco = mesh_crypto::DiscoKeypair::generate();
        let node_id = mesh_core::NodeId::new_v7(1_700_000_000_000);
        let identity = super::StoredNodeIdentity {
            node_id: Some(node_id),
            node_keypair: node.clone_keypair(),
            disco_keypair: disco.clone_keypair(),
            created_at_ms: 1_700_000_000_123,
        };

        // Act
        let sealed_a = identity.seal_with_dek(&dek);
        let sealed_b = identity.seal_with_dek(&dek);
        assert!(sealed_a.is_ok());
        assert!(sealed_b.is_ok());
        let (Ok(blob_a), Ok(blob_b)) = (sealed_a, sealed_b) else {
            return;
        };
        let unsealed = super::StoredNodeIdentity::unseal_with_dek(&blob_a, &dek);

        // Assert
        assert!(blob_a.starts_with(&super::SEALED_IDENTITY_MAGIC));
        assert_ne!(blob_a.get(4..16), blob_b.get(4..16));
        assert!(unsealed.is_ok());
        let Ok(restored) = unsealed else {
            return;
        };
        assert_eq!(restored.node_id, Some(node_id));
        assert_eq!(restored.created_at_ms, 1_700_000_000_123);
        assert_eq!(restored.node_keypair.public_key(), node.public_key());
        assert_eq!(
            restored.node_keypair.secret_bytes().expose_secret(),
            node.secret_bytes().expose_secret()
        );
        assert_eq!(restored.disco_keypair.public_key(), disco.public_key());
        assert_eq!(
            restored.disco_keypair.secret_bytes().expose_secret(),
            disco.secret_bytes().expose_secret()
        );
    }

    #[test]
    fn test_keystore_dek_rejects_zero_wrong_dek_bad_magic_tampered_and_truncated() {
        // Arrange
        let zero_dek = [0_u8; 32];
        let valid_dek = [0x42_u8; 32];
        let wrong_dek = [0x43_u8; 32];
        let identity = super::StoredNodeIdentity {
            node_id: None,
            node_keypair: mesh_crypto::NodeKeypair::generate(),
            disco_keypair: mesh_crypto::DiscoKeypair::generate(),
            created_at_ms: 1_700_000_000_000,
        };
        let Ok(sealed) = identity.seal_with_dek(&valid_dek) else {
            return;
        };

        // Act
        let zero_seal = identity.seal_with_dek(&zero_dek);
        let zero_unseal = super::StoredNodeIdentity::unseal_with_dek(&sealed, &zero_dek);
        let wrong_dek_unseal = super::StoredNodeIdentity::unseal_with_dek(&sealed, &wrong_dek);

        let mut bad_magic = sealed.clone();
        if let Some(first) = bad_magic.first_mut() {
            *first = b'X';
        }
        let bad_magic_unseal = super::StoredNodeIdentity::unseal_with_dek(&bad_magic, &valid_dek);

        let mut tampered_tag = sealed.clone();
        if let Some(last) = tampered_tag.last_mut() {
            *last ^= 0x80;
        }
        let tampered_tag_unseal =
            super::StoredNodeIdentity::unseal_with_dek(&tampered_tag, &valid_dek);

        let mut tampered_ct = sealed.clone();
        if let Some(mid) = tampered_ct.get_mut(20) {
            *mid ^= 0x01;
        }
        let tampered_ct_unseal =
            super::StoredNodeIdentity::unseal_with_dek(&tampered_ct, &valid_dek);

        let short_blob = super::StoredNodeIdentity::unseal_with_dek(b"BAD!", &valid_dek);
        let truncated_blob = super::StoredNodeIdentity::unseal_with_dek(
            sealed
                .get(..sealed.len().saturating_sub(1))
                .unwrap_or_default(),
            &valid_dek,
        );

        // Assert
        assert!(zero_seal.is_err());
        assert!(zero_unseal.is_err());
        assert!(wrong_dek_unseal.is_err());
        assert!(bad_magic_unseal.is_err());
        assert!(tampered_tag_unseal.is_err());
        assert!(tampered_ct_unseal.is_err());
        assert!(short_blob.is_err());
        assert!(truncated_blob.is_err());
    }

    #[test]
    fn test_sealed_identity_never_exposes_plaintext_keys() {
        // Arrange
        let dek = [0x55_u8; 32];
        let identity = super::StoredNodeIdentity {
            node_id: Some(mesh_core::NodeId::new_v7(1_700_000_000_000)),
            node_keypair: mesh_crypto::NodeKeypair::generate(),
            disco_keypair: mesh_crypto::DiscoKeypair::generate(),
            created_at_ms: 1_700_000_000_000,
        };
        let node_raw = *identity.node_keypair.secret_bytes().expose_secret();
        let disco_raw = *identity.disco_keypair.secret_bytes().expose_secret();
        let node_hex = super::encode_hex_32(&node_raw);
        let disco_hex = super::encode_hex_32(&disco_raw);

        // Act
        let Ok(sealed) = identity.seal_with_dek(&dek) else {
            return;
        };
        let dbg_str = format!("{identity:?}");

        // Assert
        assert!(
            !sealed
                .windows(node_raw.len())
                .any(|window| window == node_raw)
        );
        assert!(
            !sealed
                .windows(disco_raw.len())
                .any(|window| window == disco_raw)
        );
        assert!(
            !sealed
                .windows(node_hex.len())
                .any(|window| window == node_hex.as_bytes())
        );
        assert!(
            !sealed
                .windows(disco_hex.len())
                .any(|window| window == disco_hex.as_bytes())
        );
        assert!(
            !sealed
                .windows(b"node_privkey_hex".len())
                .any(|window| window == b"node_privkey_hex")
        );
        assert!(
            !sealed
                .windows(b"disco_privkey_hex".len())
                .any(|window| window == b"disco_privkey_hex")
        );
        assert!(!dbg_str.contains(&node_hex));
        assert!(!dbg_str.contains(&disco_hex));
    }
}
