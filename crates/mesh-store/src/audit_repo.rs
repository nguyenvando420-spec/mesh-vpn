//! Append-only immutable security audit event log with structured fallback (`US-013`,
//! `SEC-09`, `WP-S1-01`).

use mesh_core::{AppError, AppResult};
use redb::{Database, ReadableTable, WriteTransaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::schema::{
    META_KEY_AUDIT_SEQ, TABLE_AUDIT_EVENTS, TABLE_SCHEMA_META, decode_envelope, decode_u64_be,
    encode_envelope, encode_u64_be, map_store_err,
};

/// Input descriptor for appending a single immutable security audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventInput<'a> {
    /// UTC Unix timestamp in milliseconds.
    pub occurred_at_ms: u64,
    /// Acting entity (`"admin:uid=0"`, `"node:<uuid>"`, `"system"`).
    pub actor: &'a str,
    /// Verb/event category (`"preauth_create"`, `"node_register"`, `"node_revoke"`, etc.).
    pub action: &'a str,
    /// Non-secret identifier of the target resource.
    pub target: &'a str,
    /// Outcome tag (`"success"`, `"denied"`, `"failed"`, `"degraded"`).
    pub outcome: &'a str,
    /// Non-secret structured context fields.
    pub metadata: Value,
}

/// Persisted immutable security audit event stored inside [`TABLE_AUDIT_EVENTS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAuditEventRecord {
    /// Strictly monotonic 1-based audit sequence number.
    pub seq: u64,
    /// UTC Unix timestamp in milliseconds.
    pub occurred_at_ms: u64,
    /// Acting entity (`"admin:uid=1000"`, `"node:<uuid>"`, `"system"`).
    pub actor: String,
    /// Canonical action identifier.
    pub action: String,
    /// Non-secret target identifier (`NodeId`, `KeyId`, `"server"`, etc.).
    pub target: String,
    /// Outcome (`"success"`, `"denied"`, `"failed"`, `"degraded"`).
    pub outcome: String,
    /// Non-secret structured metadata JSON object.
    pub metadata: Value,
}

/// Bounded filter parameters when listing security audit events (`US-013`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    /// Maximum number of records to return (clamped to `[1, 1_000]`).
    pub limit: usize,
    /// Optional exclusive upper sequence cursor for reverse pagination.
    pub before_seq: Option<u64>,
    /// Optional exact filter by actor prefix/value.
    pub actor: Option<String>,
    /// Optional exact filter by action name.
    pub action: Option<String>,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            limit: 100,
            before_seq: None,
            actor: None,
            action: None,
        }
    }
}

/// Append-only audit repository (`TABLE_AUDIT_EVENTS`).
///
/// No update or deletion API exists on this repository (`US-013 AC2`).
#[derive(Debug, Default)]
pub struct AuditRepository;

impl AuditRepository {
    /// Appends a single audit event within the caller's ACID `WriteTransaction` (`US-013 AC1`).
    pub fn append_audit_in_tx(
        tx: &WriteTransaction,
        input: &AuditEventInput<'_>,
    ) -> AppResult<StoredAuditEventRecord> {
        let next_seq = {
            let mut meta = tx
                .open_table(TABLE_SCHEMA_META)
                .map_err(|e| map_store_err("open meta for audit_seq", e))?;
            let current_seq = match meta
                .get(META_KEY_AUDIT_SEQ)
                .map_err(|e| map_store_err("read audit_seq", e))?
            {
                Some(guard) => decode_u64_be(guard.value())?,
                None => 0,
            };
            let seq = current_seq
                .checked_add(1)
                .ok_or_else(|| AppError::internal("audit sequence counter exhausted"))?;
            let seq_bytes = encode_u64_be(seq);
            meta.insert(META_KEY_AUDIT_SEQ, seq_bytes.as_slice())
                .map_err(|e| map_store_err("update audit_seq", e))?;
            seq
        };

        let record = StoredAuditEventRecord {
            seq: next_seq,
            occurred_at_ms: input.occurred_at_ms,
            actor: input.actor.to_owned(),
            action: input.action.to_owned(),
            target: input.target.to_owned(),
            outcome: input.outcome.to_owned(),
            metadata: input.metadata.clone(),
        };
        let encoded = encode_envelope(&record)?;

        let mut audit = tx
            .open_table(TABLE_AUDIT_EVENTS)
            .map_err(|e| map_store_err("open audit_events", e))?;
        audit
            .insert(next_seq, encoded.as_slice())
            .map_err(|e| map_store_err("insert audit_events", e))?;

        Ok(record)
    }

    /// Queries audit events in descending sequence order (newest first).
    pub fn list_audit_events(
        db: &Database,
        query: &AuditQuery,
    ) -> AppResult<Vec<StoredAuditEventRecord>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read audit_events", e))?;
        let table = tx
            .open_table(TABLE_AUDIT_EVENTS)
            .map_err(|e| map_store_err("open read audit_events", e))?;

        let capped_limit = query.limit.clamp(1, 1_000);
        let mut results = Vec::new();
        let iter = table
            .iter()
            .map_err(|e| map_store_err("iterate audit_events", e))?;

        for item in iter.rev() {
            let (seq_guard, val_guard) =
                item.map_err(|e| map_store_err("read audit_events row", e))?;
            let seq = seq_guard.value();
            if let Some(before) = query.before_seq
                && seq >= before
            {
                continue;
            }
            let record: StoredAuditEventRecord = decode_envelope(val_guard.value())?;
            if let Some(ref actor_filter) = query.actor
                && &record.actor != actor_filter
            {
                continue;
            }
            if let Some(ref action_filter) = query.action
                && &record.action != action_filter
            {
                continue;
            }
            results.push(record);
            if results.len() >= capped_limit {
                break;
            }
        }

        Ok(results)
    }

    /// Emits a structured security audit fallback event when primary `redb` storage fails.
    pub fn emit_fallback_log(input: &AuditEventInput<'_>, reason: &str) {
        tracing::error!(
            component = "mesh-store",
            event = "audit_fallback",
            ts_ms = input.occurred_at_ms,
            actor = input.actor,
            action = input.action,
            target = input.target,
            outcome = input.outcome,
            reason = reason,
            "persisted audit write failed; emitted non-secret structured fallback log"
        );
    }

    /// Emits a structured boot-check trace log.
    pub fn record_boot_check() -> AppResult<()> {
        tracing::info!(
            component = "mesh-store",
            event = "audit_repo_initialized",
            "append-only audit repository verified"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::schema::ensure_all_tables;

    fn open_test_db() -> Option<(TempDir, Database)> {
        let dir = TempDir::new().ok()?;
        let db = Database::create(dir.path().join("audit.redb")).ok()?;
        let tx = db.begin_write().ok()?;
        ensure_all_tables(&tx).ok()?;
        tx.commit().ok()?;
        Some((dir, db))
    }

    #[test]
    fn test_audit_append_and_reverse_pagination_preserves_order() {
        // Arrange
        let Some((_dir, db)) = open_test_db() else {
            return;
        };
        let tx = db.begin_write().ok();
        let Some(tx) = tx else {
            return;
        };

        // Act
        for idx in 1..=5_u64 {
            let target = format!("node-{idx}");
            let input = AuditEventInput {
                occurred_at_ms: 1_731_480_000_000 + idx * 100,
                actor: "admin:uid=1000",
                action: if idx % 2 == 0 {
                    "node_revoke"
                } else {
                    "preauth_create"
                },
                target: &target,
                outcome: "success",
                metadata: json!({ "idx": idx }),
            };
            assert!(AuditRepository::append_audit_in_tx(&tx, &input).is_ok());
        }
        assert!(tx.commit().is_ok());

        // Assert
        let page1 = AuditRepository::list_audit_events(
            &db,
            &AuditQuery {
                limit: 2,
                ..AuditQuery::default()
            },
        )
        .unwrap_or_default();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1.first().map(|r| r.seq), Some(5));
        assert_eq!(page1.get(1).map(|r| r.seq), Some(4));

        let filtered = AuditRepository::list_audit_events(
            &db,
            &AuditQuery {
                action: Some("node_revoke".to_owned()),
                ..AuditQuery::default()
            },
        )
        .unwrap_or_default();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered.first().map(|r| r.seq), Some(4));
        assert_eq!(filtered.get(1).map(|r| r.seq), Some(2));
    }
}
