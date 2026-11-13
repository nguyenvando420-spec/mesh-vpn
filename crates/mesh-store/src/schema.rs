//! `redb` 2.4 table definitions, versioned JSON envelopes (`0x01`), and schema constants
//! (`US-007`, `WP-S1-01`).

use std::fmt::Display;
use std::net::Ipv4Addr;

use mesh_core::{AppError, AppResult, KeyId, NodeId, OverlayIp};
use redb::{ReadTransaction, TableDefinition, WriteTransaction};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Current ACID database schema version (`US-007`).
pub const SCHEMA_VERSION: u32 = 1;

/// Monotonic netmap version lease block persisted per server epoch (`REL-01`).
pub const VERSION_LEASE_STEP: u64 = 1_024;

/// Version prefix byte for every JSON record serialized into `redb` (`database-design.md` §3.1).
pub const RECORD_ENVELOPE_PREFIX: u8 = 0x01;

/// Metadata key storing schema version envelope inside [`TABLE_SCHEMA_META`].
pub const META_KEY_SCHEMA_VERSION: &str = "schema_version";
/// Metadata key storing the authoritative overlay IPv4 CIDR string (`US-008`).
pub const META_KEY_OVERLAY_CIDR: &str = "overlay_cidr";
/// Metadata key storing the durable monotonic `netmap_version` watermark (`u64` big-endian).
pub const META_KEY_WATERMARK: &str = "netmap_version_watermark";
/// Metadata key storing the sequential overlay IP allocation cursor (`u32` big-endian).
pub const META_KEY_IP_ALLOC_CURSOR: &str = "ip_alloc_cursor";
/// Metadata key storing the strictly monotonic audit sequence counter (`u64` big-endian).
pub const META_KEY_AUDIT_SEQ: &str = "audit_seq";
/// Active server identity row key in [`TABLE_SERVER_IDENTITY`].
pub const SERVER_IDENTITY_KEY_ACTIVE: &str = "active";

/// Table 1: schema version, netmap version watermark, overlay CIDR, and allocators.
pub const TABLE_SCHEMA_META: TableDefinition<'static, &str, &[u8]> =
    TableDefinition::new("schema_meta");
/// Table 2: active server P-256 identity keypair metadata (`"active"` -> `0x01 || json`).
pub const TABLE_SERVER_IDENTITY: TableDefinition<'static, &str, &[u8]> =
    TableDefinition::new("server_identity");
/// Table 3: canonical node records (`NodeId` `u128` -> `0x01 || json`).
pub const TABLE_NODES: TableDefinition<'static, u128, &[u8]> = TableDefinition::new("nodes");
/// Table 4: unique index mapping WireGuard `PublicKey` (`[u8; 32]`) -> `NodeId` (`u128`).
pub const TABLE_IDX_NODES_PUBKEY: TableDefinition<'static, &[u8; 32], u128> =
    TableDefinition::new("idx_nodes_pubkey");
/// Table 5: unique index mapping `OverlayIp` (`u32` big-endian) -> `NodeId` (`u128`).
pub const TABLE_IDX_NODES_OVERLAY_IP: TableDefinition<'static, u32, u128> =
    TableDefinition::new("idx_nodes_overlay_ip");
/// Table 6: unique index mapping canonical node name -> `NodeId` (`u128`).
pub const TABLE_IDX_NODES_NAME: TableDefinition<'static, &str, u128> =
    TableDefinition::new("idx_nodes_name");
/// Table 7: hashed pre-auth key records (`KeyId` `u128` -> `0x01 || json`).
pub const TABLE_PREAUTH_KEYS: TableDefinition<'static, u128, &[u8]> =
    TableDefinition::new("preauth_keys");
/// Table 8: unique index mapping `SHA-256(raw_token)` (`[u8; 32]`) -> `KeyId` (`u128`).
pub const TABLE_IDX_PREAUTH_HASH: TableDefinition<'static, &[u8; 32], u128> =
    TableDefinition::new("idx_preauth_hash");
/// Table 9: append-only immutable security audit events (`seq` `u64` -> `0x01 || json`).
pub const TABLE_AUDIT_EVENTS: TableDefinition<'static, u64, &[u8]> =
    TableDefinition::new("audit_events");

/// Stored schema version payload inside [`TABLE_SCHEMA_META`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersionRecord {
    /// Current schema revision (`SCHEMA_VERSION`).
    pub version: u32,
    /// UTC epoch timestamp in milliseconds when the schema was initialized or migrated.
    pub updated_at_ms: u64,
}

/// Stored overlay CIDR configuration inside [`TABLE_SCHEMA_META`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayCidrRecord {
    /// Canonical CIDR notation (e.g. `"10.100.0.0/16"`).
    pub cidr: String,
    /// UTC epoch timestamp in milliseconds when configured.
    pub configured_at_ms: u64,
}

/// Encodes `value` into a `0x01 || JSON` envelope byte vector.
pub fn encode_envelope<T: Serialize>(value: &T) -> AppResult<Vec<u8>> {
    let json_bytes = serde_json::to_vec(value)
        .map_err(|err| AppError::internal(format!("failed to serialize store record: {err}")))?;
    let mut out = Vec::with_capacity(1 + json_bytes.len());
    out.push(RECORD_ENVELOPE_PREFIX);
    out.extend_from_slice(&json_bytes);
    Ok(out)
}

/// Decodes a `0x01 || JSON` envelope byte slice into `T`, rejecting unknown versions or fields.
pub fn decode_envelope<T: DeserializeOwned>(raw: &[u8]) -> AppResult<T> {
    let Some((prefix, body)) = raw.split_first() else {
        return Err(AppError::internal("corrupt store record: empty envelope"));
    };
    if *prefix != RECORD_ENVELOPE_PREFIX {
        return Err(AppError::internal(format!(
            "unsupported store record envelope prefix {prefix:#04x}"
        )));
    }
    serde_json::from_slice(body)
        .map_err(|err| AppError::internal(format!("corrupt store JSON record: {err}")))
}

/// Encodes a `u64` counter in big-endian byte representation.
#[must_use]
pub const fn encode_u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Decodes a big-endian `u64` slice stored inside [`TABLE_SCHEMA_META`].
pub fn decode_u64_be(raw: &[u8]) -> AppResult<u64> {
    let arr: [u8; 8] = raw
        .try_into()
        .map_err(|_| AppError::internal("corrupt u64 metadata value length"))?;
    Ok(u64::from_be_bytes(arr))
}

/// Encodes a `u32` counter in big-endian byte representation.
#[must_use]
pub const fn encode_u32_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Decodes a big-endian `u32` slice stored inside [`TABLE_SCHEMA_META`].
pub fn decode_u32_be(raw: &[u8]) -> AppResult<u32> {
    let arr: [u8; 4] = raw
        .try_into()
        .map_err(|_| AppError::internal("corrupt u32 metadata value length"))?;
    Ok(u32::from_be_bytes(arr))
}

/// Converts a [`NodeId`] UUID to big-endian `u128` for `redb` key lookup.
#[must_use]
pub const fn node_id_to_u128(id: NodeId) -> u128 {
    u128::from_be_bytes(*id.as_bytes())
}

/// Reconstructs a [`NodeId`] from a `redb` `u128` key.
#[must_use]
pub const fn u128_to_node_id(raw: u128) -> NodeId {
    NodeId::from_bytes(raw.to_be_bytes())
}

/// Converts a [`KeyId`] UUID to big-endian `u128` for `redb` key lookup.
#[must_use]
pub const fn key_id_to_u128(id: KeyId) -> u128 {
    u128::from_be_bytes(*id.as_bytes())
}

/// Reconstructs a [`KeyId`] from a `redb` `u128` key.
#[must_use]
pub const fn u128_to_key_id(raw: u128) -> KeyId {
    KeyId::from_bytes(raw.to_be_bytes())
}

/// Converts an [`OverlayIp`] to `u32` host-order index key.
#[must_use]
pub const fn overlay_ip_to_u32(ip: OverlayIp) -> u32 {
    u32::from_be_bytes(ip.as_ipv4().octets())
}

/// Converts a `u32` index key back into an [`OverlayIp`].
pub fn u32_to_overlay_ip(raw: u32) -> AppResult<OverlayIp> {
    OverlayIp::from_ipv4(Ipv4Addr::from(raw))
}

/// Opens all 9 canonical tables inside an active `redb` write transaction to initialize schema.
pub fn ensure_all_tables(tx: &WriteTransaction) -> AppResult<()> {
    let _ = tx
        .open_table(TABLE_SCHEMA_META)
        .map_err(|e| map_store_err("open TABLE_SCHEMA_META", e))?;
    let _ = tx
        .open_table(TABLE_SERVER_IDENTITY)
        .map_err(|e| map_store_err("open TABLE_SERVER_IDENTITY", e))?;
    let _ = tx
        .open_table(TABLE_NODES)
        .map_err(|e| map_store_err("open TABLE_NODES", e))?;
    let _ = tx
        .open_table(TABLE_IDX_NODES_PUBKEY)
        .map_err(|e| map_store_err("open TABLE_IDX_NODES_PUBKEY", e))?;
    let _ = tx
        .open_table(TABLE_IDX_NODES_OVERLAY_IP)
        .map_err(|e| map_store_err("open TABLE_IDX_NODES_OVERLAY_IP", e))?;
    let _ = tx
        .open_table(TABLE_IDX_NODES_NAME)
        .map_err(|e| map_store_err("open TABLE_IDX_NODES_NAME", e))?;
    let _ = tx
        .open_table(TABLE_PREAUTH_KEYS)
        .map_err(|e| map_store_err("open TABLE_PREAUTH_KEYS", e))?;
    let _ = tx
        .open_table(TABLE_IDX_PREAUTH_HASH)
        .map_err(|e| map_store_err("open TABLE_IDX_PREAUTH_HASH", e))?;
    let _ = tx
        .open_table(TABLE_AUDIT_EVENTS)
        .map_err(|e| map_store_err("open TABLE_AUDIT_EVENTS", e))?;
    Ok(())
}

/// Verifies all 9 tables exist and can be opened cleanly in a read transaction.
pub fn verify_all_tables_readable(tx: &ReadTransaction) -> AppResult<()> {
    let _ = tx
        .open_table(TABLE_SCHEMA_META)
        .map_err(|e| map_store_err("read TABLE_SCHEMA_META", e))?;
    let _ = tx
        .open_table(TABLE_SERVER_IDENTITY)
        .map_err(|e| map_store_err("read TABLE_SERVER_IDENTITY", e))?;
    let _ = tx
        .open_table(TABLE_NODES)
        .map_err(|e| map_store_err("read TABLE_NODES", e))?;
    let _ = tx
        .open_table(TABLE_IDX_NODES_PUBKEY)
        .map_err(|e| map_store_err("read TABLE_IDX_NODES_PUBKEY", e))?;
    let _ = tx
        .open_table(TABLE_IDX_NODES_OVERLAY_IP)
        .map_err(|e| map_store_err("read TABLE_IDX_NODES_OVERLAY_IP", e))?;
    let _ = tx
        .open_table(TABLE_IDX_NODES_NAME)
        .map_err(|e| map_store_err("read TABLE_IDX_NODES_NAME", e))?;
    let _ = tx
        .open_table(TABLE_PREAUTH_KEYS)
        .map_err(|e| map_store_err("read TABLE_PREAUTH_KEYS", e))?;
    let _ = tx
        .open_table(TABLE_IDX_PREAUTH_HASH)
        .map_err(|e| map_store_err("read TABLE_IDX_PREAUTH_HASH", e))?;
    let _ = tx
        .open_table(TABLE_AUDIT_EVENTS)
        .map_err(|e| map_store_err("read TABLE_AUDIT_EVENTS", e))?;
    Ok(())
}

/// Maps a storage-layer `redb` failure to [`AppError::unavailable`] so degraded-disk failover triggers.
pub(crate) fn map_store_err(context: &str, err: impl Display) -> AppError {
    AppError::unavailable(format!("redb {context} failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip_accepts_known_version_and_rejects_bad_prefix() {
        // Arrange
        let record = SchemaVersionRecord {
            version: SCHEMA_VERSION,
            updated_at_ms: 1_731_480_000_000,
        };

        // Act
        let encoded = encode_envelope(&record);
        let decoded = encoded
            .as_ref()
            .ok()
            .and_then(|bytes| decode_envelope::<SchemaVersionRecord>(bytes).ok());

        // Assert
        assert_eq!(decoded, Some(record));
        let mut corrupt = encoded.unwrap_or_default();
        if let Some(first) = corrupt.first_mut() {
            *first = 0x02;
        }
        assert!(decode_envelope::<SchemaVersionRecord>(&corrupt).is_err());
    }

    #[test]
    fn test_envelope_rejects_unknown_fields() {
        // Arrange
        let mut raw = vec![RECORD_ENVELOPE_PREFIX];
        raw.extend_from_slice(br#"{"version":1,"updated_at_ms":10,"extra":true}"#);

        // Act
        let res = decode_envelope::<SchemaVersionRecord>(&raw);

        // Assert
        assert!(res.is_err());
    }

    #[test]
    fn test_node_and_key_id_u128_roundtrip() {
        // Arrange
        let node_id = NodeId::new_v7(1_731_480_000_123);
        let key_id = KeyId::new_v7(1_731_480_000_456);

        // Act / Assert
        assert_eq!(u128_to_node_id(node_id_to_u128(node_id)), node_id);
        assert_eq!(u128_to_key_id(key_id_to_u128(key_id)), key_id);
    }
}
