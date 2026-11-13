//! `redb` 2.4 table definitions and schema migration constants (`WP-S1-01`).

use redb::TableDefinition;

/// Database schema version stored inside `meta`.
pub const SCHEMA_VERSION: u32 = 1;

/// Monotonic netmap version lease block reserved per server epoch (`REL-01`).
pub const VERSION_LEASE_STEP: u64 = 1_024;

/// Metadata table storing schema version, netmap watermark, and IP allocator cursor.
pub const META_TABLE: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("meta");
/// Registered nodes table (`NodeId` -> JSON record).
pub const NODES_TABLE: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new("nodes");
/// Index mapping normalized `NodeName` -> `NodeId` bytes.
pub const IDX_NODES_NAME_TABLE: TableDefinition<'static, &str, &[u8]> =
    TableDefinition::new("idx_nodes_name");
/// Index mapping `PublicKey` `[u8; 32]` -> `NodeId` bytes.
pub const IDX_NODES_PUBKEY_TABLE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("idx_nodes_pubkey");
/// Index mapping `Ipv4Addr` `[u8; 4]` -> `NodeId` / quarantine state.
pub const IDX_NODES_OVERLAY_IP_TABLE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("idx_nodes_overlay_ip");
/// Pre-authentication keys table (`KeyId` -> hashed token record).
pub const PREAUTH_KEYS_TABLE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("preauth_keys");
/// Index mapping SHA-256 hash of `mpk_...` -> `KeyId`.
pub const IDX_KEYS_HASH_TABLE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("idx_keys_hash");
/// Append-only audit events table (`(ts_ms, seq)` -> JSON audit event).
pub const AUDIT_EVENTS_TABLE: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("audit_events");
/// Server TLS/Control identity table (`"active"` -> key/cert metadata).
pub const SERVER_IDENTITY_TABLE: TableDefinition<'static, &str, &[u8]> =
    TableDefinition::new("server_identity");
