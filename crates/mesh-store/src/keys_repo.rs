//! Pre-authentication key repository supporting SHA-256 constant-time verification,
//! bounded TTL (`<= 90 days`), `--for <node>` binding, and revocation (`US-002`, `US-031`, `WP-S1-01`).

use mesh_core::{AppError, AppResult, KeyId, NodeId, NodeName};
use mesh_crypto::ct_eq_bytes;
use redb::{Database, ReadableTable, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::audit_repo::{AuditEventInput, AuditRepository};
use crate::schema::{
    TABLE_IDX_PREAUTH_HASH, TABLE_PREAUTH_KEYS, decode_envelope, encode_envelope, key_id_to_u128,
    map_store_err,
};

/// Maximum permitted lifetime for a pre-authentication key (`90 days` per `US-002`).
pub const MAX_PREAUTH_TTL_SECS: u64 = 90 * 86_400;

/// Default lifetime (`24 hours`) when no custom TTL is supplied (`US-002`).
pub const DEFAULT_PREAUTH_TTL_SECS: u64 = 86_400;

/// Parameters required to issue a new hashed pre-authentication key (`US-002`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePreAuthKeyInput {
    /// Pre-assigned unique key identifier (UUIDv7).
    pub key_id: KeyId,
    /// `SHA-256(raw_preauth_token)` digest (plaintext token is never stored).
    pub token_hash: [u8; 32],
    /// Optional human-readable non-secret label.
    pub label: Option<String>,
    /// Optional node name restriction (`--for <node>`, `US-002`, `US-031`).
    pub bound_node_name: Option<NodeName>,
    /// Whether this key may onboard multiple distinct nodes (`US-006`).
    pub reusable: bool,
    /// Optional cap on total consumptions when `reusable` is enabled (`HR-S1-03`).
    pub max_uses: Option<u32>,
    /// Whether nodes registered with this key auto-expire on idle/offline (`US-006`).
    pub ephemeral: bool,
    /// Optional offline auto-reap timeout in seconds for `--ephemeral` nodes (`US-006`).
    pub ephemeral_timeout_secs: Option<u32>,
    /// Key lifetime in seconds (`1..=MAX_PREAUTH_TTL_SECS`).
    pub ttl_secs: u64,
    /// Creation timestamp (`unix_ms` UTC).
    pub now_unix_ms: u64,
}

/// Persisted pre-authentication key record stored inside [`TABLE_PREAUTH_KEYS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPreAuthKeyRecord {
    /// Key UUIDv7 identifier.
    pub key_id: KeyId,
    /// SHA-256 hash of raw `mpk_...` token (`[u8; 32]`).
    pub token_hash: [u8; 32],
    /// Optional non-secret display label.
    pub label: Option<String>,
    /// Optional target [`NodeName`] binding (`--for <node>`).
    pub bound_node_name: Option<String>,
    /// Reusable flag (`false` for MVP single-use default).
    pub reusable: bool,
    /// Optional maximum consumption limit (`HR-S1-03`).
    #[serde(default)]
    pub max_uses: Option<u32>,
    /// Ephemeral flag (`false` by default).
    pub ephemeral: bool,
    /// Optional offline reap timeout in seconds (`US-006`).
    #[serde(default)]
    pub ephemeral_timeout_secs: Option<u32>,
    /// UTC creation timestamp in milliseconds.
    pub created_at_ms: u64,
    /// UTC expiration timestamp in milliseconds.
    pub expires_at_ms: u64,
    /// Number of successful registrations completed with this key.
    pub used_count: u32,
    /// Most recent `NodeId` enrolled using this key.
    pub used_by_node_id: Option<NodeId>,
    /// UTC timestamp when the key was most recently consumed.
    pub used_at_ms: Option<u64>,
    /// Optional revocation UTC timestamp in milliseconds.
    pub revoked_at_ms: Option<u64>,
}

/// Repository managing hashed pre-authentication keys (`US-002`, `US-031`).
#[derive(Debug, Default)]
pub struct KeysRepository;

impl KeysRepository {
    /// Creates and indexes a hashed pre-authentication key inside an open `WriteTransaction`.
    pub fn create_key_in_tx(
        tx: &WriteTransaction,
        input: &CreatePreAuthKeyInput,
        actor: &str,
    ) -> AppResult<StoredPreAuthKeyRecord> {
        if input.ttl_secs == 0 || input.ttl_secs > MAX_PREAUTH_TTL_SECS {
            return Err(AppError::invalid_argument(format!(
                "pre-auth key TTL must be within 1..={MAX_PREAUTH_TTL_SECS} seconds"
            )));
        }
        if let Some(0) = input.max_uses {
            return Err(AppError::invalid_argument(
                "pre-auth key max_uses must be at least 1",
            ));
        }
        if !input.ephemeral && input.ephemeral_timeout_secs.is_some() {
            return Err(AppError::invalid_argument(
                "ephemeral_timeout_secs requires --ephemeral",
            ));
        }
        if let Some(0) = input.ephemeral_timeout_secs {
            return Err(AppError::invalid_argument(
                "ephemeral_timeout_secs must be at least 1",
            ));
        }

        let expires_at_ms = input
            .now_unix_ms
            .checked_add(input.ttl_secs.saturating_mul(1_000))
            .ok_or_else(|| AppError::invalid_argument("pre-auth key expiry overflow"))?;

        let record = StoredPreAuthKeyRecord {
            key_id: input.key_id,
            token_hash: input.token_hash,
            label: input.label.clone(),
            bound_node_name: input
                .bound_node_name
                .as_ref()
                .map(|n| n.as_str().to_owned()),
            reusable: input.reusable,
            max_uses: input.max_uses,
            ephemeral: input.ephemeral,
            ephemeral_timeout_secs: input.ephemeral_timeout_secs,
            created_at_ms: input.now_unix_ms,
            expires_at_ms,
            used_count: 0,
            used_by_node_id: None,
            used_at_ms: None,
            revoked_at_ms: None,
        };

        let key_u128 = key_id_to_u128(record.key_id);
        let encoded = encode_envelope(&record)?;

        {
            let mut keys_table = tx
                .open_table(TABLE_PREAUTH_KEYS)
                .map_err(|e| map_store_err("open write preauth_keys", e))?;
            if keys_table
                .get(key_u128)
                .map_err(|e| map_store_err("check existing preauth key", e))?
                .is_some()
            {
                return Err(AppError::conflict("duplicate pre-auth KeyId"));
            }
            keys_table
                .insert(key_u128, encoded.as_slice())
                .map_err(|e| map_store_err("insert preauth_keys", e))?;

            let mut hash_idx = tx
                .open_table(TABLE_IDX_PREAUTH_HASH)
                .map_err(|e| map_store_err("open write idx_preauth_hash", e))?;
            if hash_idx
                .get(&record.token_hash)
                .map_err(|e| map_store_err("check idx_preauth_hash", e))?
                .is_some()
            {
                return Err(AppError::conflict("duplicate pre-auth token digest"));
            }
            hash_idx
                .insert(&record.token_hash, key_u128)
                .map_err(|e| map_store_err("insert idx_preauth_hash", e))?;
        }

        let audit_input = AuditEventInput {
            occurred_at_ms: input.now_unix_ms,
            actor,
            action: "preauth_key_created",
            target: &record.key_id.to_string(),
            outcome: "success",
            metadata: serde_json::json!({
                "bound_node_name": record.bound_node_name,
                "reusable": record.reusable,
                "ephemeral": record.ephemeral,
                "ephemeral_timeout_secs": record.ephemeral_timeout_secs,
                "expires_at_ms": record.expires_at_ms,
            }),
        };
        AuditRepository::append_audit_in_tx(tx, &audit_input)?;

        Ok(record)
    }

    /// Validates and atomically consumes a pre-authentication key inside `tx`.
    ///
    /// Returns uniform `ErrorKind::Unauthenticated` (`"authentication failed"`) on any hash
    /// miss, expiration, revocation, node binding mismatch, or one-time reuse attempt (`SEC-05`).
    pub fn verify_and_consume_in_tx(
        tx: &WriteTransaction,
        presented_hash: &[u8; 32],
        node_name: &NodeName,
        node_id: NodeId,
        now_unix_ms: u64,
    ) -> AppResult<StoredPreAuthKeyRecord> {
        let mut record = {
            let hash_idx = tx
                .open_table(TABLE_IDX_PREAUTH_HASH)
                .map_err(|e| map_store_err("open read idx_preauth_hash", e))?;
            let Some(key_id_guard) = hash_idx
                .get(presented_hash)
                .map_err(|e| map_store_err("lookup idx_preauth_hash", e))?
            else {
                return Err(AppError::unauthenticated("pre-auth token hash not found"));
            };
            let key_u128 = key_id_guard.value();
            let keys_table = tx
                .open_table(TABLE_PREAUTH_KEYS)
                .map_err(|e| map_store_err("open preauth_keys for verify", e))?;
            let Some(record_guard) = keys_table
                .get(key_u128)
                .map_err(|e| map_store_err("get preauth_key", e))?
            else {
                return Err(AppError::unauthenticated(
                    "dangling pre-auth hash index entry",
                ));
            };
            decode_envelope::<StoredPreAuthKeyRecord>(record_guard.value())?
        };

        if !ct_eq_bytes(&record.token_hash, presented_hash) {
            return Err(AppError::unauthenticated(
                "constant-time pre-auth hash mismatch",
            ));
        }
        if record.revoked_at_ms.is_some() {
            return Err(AppError::unauthenticated("pre-auth key revoked"));
        }
        if now_unix_ms >= record.expires_at_ms {
            return Err(AppError::unauthenticated("pre-auth key expired"));
        }
        if !record.reusable && record.used_count > 0 {
            return Err(AppError::unauthenticated(
                "single-use pre-auth key already consumed",
            ));
        }
        if let Some(max_uses) = record.max_uses
            && max_uses > 0
            && record.used_count >= max_uses
        {
            return Err(AppError::unauthenticated(
                "pre-auth key usage limit reached",
            ));
        }
        if let Some(ref bound_name) = record.bound_node_name
            && bound_name != node_name.as_str()
        {
            return Err(AppError::unauthenticated(
                "pre-auth key is restricted to another node name",
            ));
        }

        record.used_count = record.used_count.saturating_add(1);
        record.used_by_node_id = Some(node_id);
        record.used_at_ms = Some(now_unix_ms);

        let encoded = encode_envelope(&record)?;
        let mut keys_table = tx
            .open_table(TABLE_PREAUTH_KEYS)
            .map_err(|e| map_store_err("open write preauth_keys consume", e))?;
        keys_table
            .insert(key_id_to_u128(record.key_id), encoded.as_slice())
            .map_err(|e| map_store_err("update preauth_keys consume", e))?;

        Ok(record)
    }

    /// Marks `key_id` as revoked inside an active write transaction (`US-002`).
    pub fn revoke_key_in_tx(
        tx: &WriteTransaction,
        key_id: KeyId,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<StoredPreAuthKeyRecord> {
        let key_u128 = key_id_to_u128(key_id);
        let mut record = {
            let keys_table = tx
                .open_table(TABLE_PREAUTH_KEYS)
                .map_err(|e| map_store_err("open read preauth_keys revoke", e))?;
            let Some(guard) = keys_table
                .get(key_u128)
                .map_err(|e| map_store_err("get preauth_key revoke", e))?
            else {
                return Err(AppError::not_found(format!(
                    "pre-auth key {key_id} not found"
                )));
            };
            decode_envelope::<StoredPreAuthKeyRecord>(guard.value())?
        };

        if record.revoked_at_ms.is_none() {
            record.revoked_at_ms = Some(now_unix_ms);
            let encoded = encode_envelope(&record)?;
            let mut keys_table = tx
                .open_table(TABLE_PREAUTH_KEYS)
                .map_err(|e| map_store_err("open write preauth_keys revoke", e))?;
            keys_table
                .insert(key_u128, encoded.as_slice())
                .map_err(|e| map_store_err("update preauth_keys revoke", e))?;
        }

        let audit_input = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "preauth_key_revoked",
            target: &key_id.to_string(),
            outcome: "success",
            metadata: serde_json::json!({ "revoked_at_ms": record.revoked_at_ms }),
        };
        AuditRepository::append_audit_in_tx(tx, &audit_input)?;

        Ok(record)
    }

    /// Reads all stored pre-authentication keys ordered by creation timestamp.
    pub fn list_keys(db: &Database) -> AppResult<Vec<StoredPreAuthKeyRecord>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read list_keys", e))?;
        let table = tx
            .open_table(TABLE_PREAUTH_KEYS)
            .map_err(|e| map_store_err("open read list_keys", e))?;
        let mut out: Vec<StoredPreAuthKeyRecord> = Vec::new();
        for item in table
            .iter()
            .map_err(|e| map_store_err("iterate preauth_keys", e))?
        {
            let (_, val_guard) = item.map_err(|e| map_store_err("read preauth_keys row", e))?;
            out.push(decode_envelope(val_guard.value())?);
        }
        out.sort_by_key(|k| k.created_at_ms);
        Ok(out)
    }

    /// Reads a single key by ID.
    pub fn find_by_id(db: &Database, key_id: KeyId) -> AppResult<Option<StoredPreAuthKeyRecord>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read find_key", e))?;
        let table = tx
            .open_table(TABLE_PREAUTH_KEYS)
            .map_err(|e| map_store_err("open read find_key", e))?;
        let Some(guard) = table
            .get(key_id_to_u128(key_id))
            .map_err(|e| map_store_err("get preauth_key", e))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_envelope(guard.value())?))
    }
}

#[cfg(test)]
mod tests {
    use mesh_core::ErrorKind;
    use tempfile::TempDir;

    use super::*;
    use crate::schema::ensure_all_tables;

    fn open_test_db() -> Option<(TempDir, Database)> {
        let dir = TempDir::new().ok()?;
        let db = Database::create(dir.path().join("keys.redb")).ok()?;
        let tx = db.begin_write().ok()?;
        ensure_all_tables(&tx).ok()?;
        tx.commit().ok()?;
        Some((dir, db))
    }

    #[test]
    fn test_preauth_key_ttl_bound_single_use_and_node_restriction() {
        // Arrange
        let Some((_dir, db)) = open_test_db() else {
            return;
        };
        let now_ms = 1_731_480_000_000;
        let hash = [0x42_u8; 32];
        let Ok(target_name) = NodeName::parse("macbook") else {
            return;
        };
        let Ok(other_name) = NodeName::parse("windows-pc") else {
            return;
        };

        // Act: reject TTL > 90 days
        let tx_bad = db.begin_write().ok();
        if let Some(tx) = tx_bad {
            let over_ttl = CreatePreAuthKeyInput {
                key_id: KeyId::new_v7(now_ms),
                token_hash: hash,
                label: None,
                bound_node_name: None,
                reusable: false,
                max_uses: None,
                ephemeral: false,
                ephemeral_timeout_secs: None,
                ttl_secs: MAX_PREAUTH_TTL_SECS + 1,
                now_unix_ms: now_ms,
            };
            assert!(KeysRepository::create_key_in_tx(&tx, &over_ttl, "admin:uid=0").is_err());
        }

        // Create valid key bound to "macbook"
        let Ok(tx) = db.begin_write() else {
            return;
        };
        let input = CreatePreAuthKeyInput {
            key_id: KeyId::new_v7(now_ms),
            token_hash: hash,
            label: Some("laptop".to_owned()),
            bound_node_name: Some(target_name.clone()),
            reusable: false,
            max_uses: None,
            ephemeral: false,
            ephemeral_timeout_secs: None,
            ttl_secs: 3_600,
            now_unix_ms: now_ms,
        };
        assert!(KeysRepository::create_key_in_tx(&tx, &input, "admin:uid=0").is_ok());

        // Wrong node name must return Unauthenticated ("authentication failed")
        let wrong_node = NodeId::new_v7(now_ms + 1);
        let wrong_res =
            KeysRepository::verify_and_consume_in_tx(&tx, &hash, &other_name, wrong_node, now_ms);
        assert_eq!(
            wrong_res.as_ref().err().map(|e| e.kind()),
            Some(ErrorKind::Unauthenticated)
        );
        assert_eq!(
            wrong_res.as_ref().err().map(|e| e.public_message()),
            Some("authentication failed")
        );

        // Matching node succeeds once, then second attempt fails
        let ok_res =
            KeysRepository::verify_and_consume_in_tx(&tx, &hash, &target_name, wrong_node, now_ms);
        assert!(ok_res.is_ok());
        let replay_res =
            KeysRepository::verify_and_consume_in_tx(&tx, &hash, &target_name, wrong_node, now_ms);
        assert_eq!(
            replay_res.as_ref().err().map(|e| e.kind()),
            Some(ErrorKind::Unauthenticated)
        );
        assert!(tx.commit().is_ok());
    }

    #[test]
    fn test_reusable_key_respects_max_uses_cap() {
        // Arrange
        let Some((_dir, db)) = open_test_db() else {
            return;
        };
        let now_ms = 1_731_480_100_000;
        let hash = [0x99_u8; 32];
        let Ok(n1) = NodeName::parse("worker-1") else {
            return;
        };
        let Ok(n2) = NodeName::parse("worker-2") else {
            return;
        };
        let Ok(n3) = NodeName::parse("worker-3") else {
            return;
        };
        let Ok(tx) = db.begin_write() else {
            return;
        };
        let capped = CreatePreAuthKeyInput {
            key_id: KeyId::new_v7(now_ms),
            token_hash: hash,
            label: Some("capped".to_owned()),
            bound_node_name: None,
            reusable: true,
            max_uses: Some(2),
            ephemeral: false,
            ephemeral_timeout_secs: None,
            ttl_secs: 3_600,
            now_unix_ms: now_ms,
        };
        assert!(KeysRepository::create_key_in_tx(&tx, &capped, "admin").is_ok());

        // Act & Assert
        assert!(
            KeysRepository::verify_and_consume_in_tx(
                &tx,
                &hash,
                &n1,
                NodeId::new_v7(now_ms + 1),
                now_ms
            )
            .is_ok()
        );
        assert!(
            KeysRepository::verify_and_consume_in_tx(
                &tx,
                &hash,
                &n2,
                NodeId::new_v7(now_ms + 2),
                now_ms
            )
            .is_ok()
        );
        let third = KeysRepository::verify_and_consume_in_tx(
            &tx,
            &hash,
            &n3,
            NodeId::new_v7(now_ms + 3),
            now_ms,
        );
        assert_eq!(
            third.as_ref().err().map(|e| e.kind()),
            Some(ErrorKind::Unauthenticated)
        );
    }

    #[test]
    fn test_ephemeral_timeout_validation_and_persistence() {
        // Arrange
        let Some((_dir, db)) = open_test_db() else {
            return;
        };
        let now_ms = 1_731_480_200_000;
        let Ok(tx) = db.begin_write() else {
            return;
        };

        // Act: non-ephemeral with ephemeral_timeout_secs or zero timeout rejected
        let bad_non_ephemeral = CreatePreAuthKeyInput {
            key_id: KeyId::new_v7(now_ms),
            token_hash: [0xA1_u8; 32],
            label: None,
            bound_node_name: None,
            reusable: false,
            max_uses: None,
            ephemeral: false,
            ephemeral_timeout_secs: Some(60),
            ttl_secs: 3_600,
            now_unix_ms: now_ms,
        };
        assert_eq!(
            KeysRepository::create_key_in_tx(&tx, &bad_non_ephemeral, "admin")
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::InvalidArgument)
        );

        let valid_ephemeral = CreatePreAuthKeyInput {
            key_id: KeyId::new_v7(now_ms + 1),
            token_hash: [0xA2_u8; 32],
            label: Some("ephem-ci".to_owned()),
            bound_node_name: None,
            reusable: true,
            max_uses: Some(3),
            ephemeral: true,
            ephemeral_timeout_secs: Some(120),
            ttl_secs: 3_600,
            now_unix_ms: now_ms,
        };
        let saved = KeysRepository::create_key_in_tx(&tx, &valid_ephemeral, "admin")
            .expect("valid ephemeral key");
        tx.commit().expect("commit");

        // Assert
        assert!(saved.ephemeral);
        assert_eq!(saved.ephemeral_timeout_secs, Some(120));
        let listed = KeysRepository::list_keys(&db).expect("list keys");
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed.first().and_then(|k| k.ephemeral_timeout_secs),
            Some(120)
        );
    }
}
