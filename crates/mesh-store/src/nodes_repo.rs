//! Node registration (idempotent single-`WriteTransaction`), lookup, 24h IP quarantine reuse,
//! rename, expiry, and revocation repository (`US-004`, `US-005`, `US-008`, `US-029`, `US-031`,
//! `WP-S1-01`).

use mesh_core::{AppError, AppResult, KeyId, NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey};
use mesh_proto::netmap::CandidateEndpoint;
use redb::{Database, ReadableTable, ReadableTableMetadata as _, WriteTransaction};
use serde::{Deserialize, Serialize};

use crate::audit_repo::{AuditEventInput, AuditRepository};
use crate::keys_repo::KeysRepository;
use crate::schema::{
    META_KEY_IP_ALLOC_CURSOR, META_KEY_OVERLAY_CIDR, OverlayCidrRecord, TABLE_IDX_NODES_NAME,
    TABLE_IDX_NODES_OVERLAY_IP, TABLE_IDX_NODES_PUBKEY, TABLE_NODES, TABLE_PREAUTH_KEYS,
    TABLE_SCHEMA_META, decode_envelope, decode_u32_be, encode_envelope, encode_u32_be,
    map_store_err, node_id_to_u128, overlay_ip_to_u32, u32_to_overlay_ip, u128_to_node_id,
};

/// Default node key validity window (`180 days`, `US-031`).
pub const DEFAULT_NODE_KEY_TTL_MS: u64 = 180 * 86_400 * 1_000;

/// Minimum quarantine window (`24 hours`) before a revoked/expired node's IP may be reused.
pub const QUARANTINE_DURATION_MS: u64 = 24 * 3_600 * 1_000;

/// Lifecycle state of a registered overlay node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Node is allowed to authenticate, pull Netmaps, and traverse Blind Relay.
    Active,
    /// Node was explicitly revoked by an administrator (`US-029`).
    Revoked,
    /// Node's long-lived WireGuard identity expired (`US-031`).
    Expired,
}

/// Persisted canonical node row stored inside [`TABLE_NODES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredNodeRecord {
    /// Stable UUIDv7 node identifier.
    pub node_id: NodeId,
    /// Validated RFC 1123 node hostname label.
    pub node_name: String,
    /// Raw WireGuard static Curve25519 public key bytes.
    pub pubkey: [u8; 32],
    /// Raw Disco traversal Curve25519 public key bytes.
    pub disco_pubkey: [u8; 32],
    /// Assigned overlay IPv4 address (`None` only after post-quarantine IP reclamation).
    pub overlay_ip: Option<OverlayIp>,
    /// Last assigned overlay IPv4 address retained for admin audit visibility after reclamation (`HR-S1-03`).
    #[serde(default)]
    pub last_overlay_ip: Option<OverlayIp>,
    /// Current lifecycle status.
    pub status: NodeStatus,
    /// Pre-auth key identifier used during enrollment or re-registration.
    pub preauth_key_id: KeyId,
    /// Ephemeral node marker (`US-006`).
    pub ephemeral: bool,
    /// UTC epoch milliseconds when the node was created.
    pub created_at_ms: u64,
    /// UTC epoch milliseconds of latest verified heartbeat/API activity.
    pub last_seen_at_ms: u64,
    /// UTC epoch milliseconds when the node key expires (`US-031`).
    pub key_expires_at_ms: u64,
    /// Optional explicit revocation timestamp.
    pub revoked_at_ms: Option<u64>,
    /// Optional expiration transition timestamp.
    pub expired_at_ms: Option<u64>,
    /// Quarantine deadline (`+24h`) after which `overlay_ip` may be reclaimed cleanly.
    pub quarantine_until_ms: Option<u64>,
    /// OS and architecture triplet reported by the client (e.g. `"darwin/arm64"`).
    pub os_arch: String,
    /// Client agent binary version string.
    pub agent_version: String,
    /// Client control protocol version.
    pub protocol_version: u16,
    /// Latest reported ICE/STUN/local UDP candidate endpoints.
    pub endpoints: Vec<CandidateEndpoint>,
}

/// Input arguments for single-transaction idempotent node registration (`US-004`, `US-005`).
#[derive(Debug, Clone)]
pub struct RegisterNodeInput<'a> {
    /// Caller's WireGuard Curve25519 public key.
    pub pubkey: PublicKey,
    /// Caller's Disco Curve25519 public key.
    pub disco_pubkey: PublicKey,
    /// Optional previous node public key being rotated out (`US-032`).
    pub previous_node_pubkey: Option<PublicKey>,
    /// Requested RFC 1123 node label.
    pub requested_name: NodeName,
    /// `SHA-256(raw_preauth_token)` provided by caller (`None` only when replaying an active key).
    pub preauth_token_hash: [u8; 32],
    /// Control server's public host/IP to reserve against spoofed mesh hostnames (`US-004 AC3`).
    pub public_control_host: &'a str,
    /// Internal DNS domain suffix (default `"mesh.internal"`).
    pub domain_suffix: &'a str,
    /// Client platform string (`"darwin/arm64"`, `"windows/amd64"`, `"linux/amd64"`).
    pub os_arch: &'a str,
    /// Client agent semantic version.
    pub agent_version: &'a str,
    /// Client wire protocol revision.
    pub protocol_version: u16,
    /// Desired node key validity duration in milliseconds (`DEFAULT_NODE_KEY_TTL_MS`).
    pub node_key_ttl_ms: u64,
    /// Current server UTC Unix timestamp in milliseconds.
    pub now_unix_ms: u64,
}

/// Result returned from [`NodesRepository::register_node_in_tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterNodeOutcome {
    /// Resulting node record stored in `redb`.
    pub record: StoredNodeRecord,
    /// True if state changed (new node created or expired node re-enrolled); false on pure replay.
    pub state_changed: bool,
    /// Previous public key displaced by key rotation or re-enrollment so RAM/streams revoke it immediately (`BLK-S1-01`).
    pub replaced_pubkey: Option<PublicKey>,
}

/// Repository managing registered nodes, unique indexes, overlay CIDR, and 24h IP quarantine.
#[derive(Debug, Default)]
pub struct NodesRepository;

impl NodesRepository {
    /// Atomically validates pre-auth credentials, reserves name/IP, updates indexes, and appends an
    /// immutable audit event inside a single `redb::WriteTransaction` (`US-004`, `US-005`).
    pub fn register_node_in_tx(
        tx: &WriteTransaction,
        input: &RegisterNodeInput<'_>,
    ) -> AppResult<RegisterNodeOutcome> {
        input
            .requested_name
            .validate_against_public_host(input.public_control_host, input.domain_suffix)?;

        if let Some(existing) = lookup_node_by_pubkey_in_tx(tx, &input.pubkey)? {
            return handle_existing_pubkey_registration(tx, existing, input);
        }

        let new_node_id = NodeId::new_v7(input.now_unix_ms);
        let consumed_key = KeysRepository::verify_and_consume_in_tx(
            tx,
            &input.preauth_token_hash,
            &input.requested_name,
            new_node_id,
            input.now_unix_ms,
        )?;

        if let Some(prev_pk) = input.previous_node_pubkey
            && let Some(prev_record) = lookup_node_by_pubkey_in_tx(tx, &prev_pk)?
        {
            if prev_record.status == NodeStatus::Revoked
                || input.now_unix_ms >= prev_record.key_expires_at_ms
                || prev_record.node_name != input.requested_name.as_str()
                || consumed_key.bound_node_name.as_deref() != Some(prev_record.node_name.as_str())
            {
                return Err(AppError::unauthenticated(
                    "pre-auth key is not authorized for key rotation on target node",
                ));
            }
            return handle_key_rotation_registration(tx, prev_record, consumed_key.key_id, input);
        }

        if let Some(existing_by_name) =
            lookup_node_by_name_in_tx(tx, input.requested_name.as_str())?
        {
            return handle_name_collision_registration(tx, existing_by_name, consumed_key, input);
        }

        let overlay_ip = allocate_next_overlay_ip_in_tx(tx, new_node_id, input.now_unix_ms)?;
        let record = build_new_node_record(new_node_id, overlay_ip, &consumed_key, input);
        persist_new_node_and_indexes_in_tx(tx, &record)?;
        append_register_audit(tx, &record, "node_registered")?;

        Ok(RegisterNodeOutcome {
            record,
            state_changed: true,
            replaced_pubkey: None,
        })
    }

    /// Updates a node's candidate endpoint list; returns `true` if endpoints changed.
    pub fn update_endpoints_in_tx(
        tx: &WriteTransaction,
        node_id: NodeId,
        endpoints: Vec<CandidateEndpoint>,
        now_unix_ms: u64,
    ) -> AppResult<(StoredNodeRecord, bool)> {
        let mut record = load_node_by_id_in_tx(tx, node_id)?
            .ok_or_else(|| AppError::unauthenticated("unknown node during endpoint update"))?;
        ensure_node_active(&record, now_unix_ms)?;

        let changed = record.endpoints != endpoints;
        record.endpoints = endpoints;
        record.last_seen_at_ms = now_unix_ms;
        save_node_record_in_tx(tx, &record)?;
        Ok((record, changed))
    }

    /// Renames a registered node atomically updating `idx_nodes_name` (`US-012`).
    pub fn rename_node_in_tx(
        tx: &WriteTransaction,
        node_id: NodeId,
        new_name: NodeName,
        public_host: &str,
        domain_suffix: &str,
        now_unix_ms: u64,
    ) -> AppResult<StoredNodeRecord> {
        new_name.validate_against_public_host(public_host, domain_suffix)?;
        let mut record = load_node_by_id_in_tx(tx, node_id)?
            .ok_or_else(|| AppError::not_found(format!("node {node_id} not found")))?;
        if record.node_name == new_name.as_str() {
            return Ok(record);
        }
        if lookup_node_by_name_in_tx(tx, new_name.as_str())?.is_some() {
            return Err(AppError::conflict(format!(
                "node name `{new_name}` already exists"
            )));
        }
        let old_name = record.node_name.clone();
        {
            let mut name_idx = tx
                .open_table(TABLE_IDX_NODES_NAME)
                .map_err(|e| map_store_err("open write idx_nodes_name rename", e))?;
            name_idx
                .remove(old_name.as_str())
                .map_err(|e| map_store_err("remove old idx_nodes_name", e))?;
            name_idx
                .insert(new_name.as_str(), node_id_to_u128(node_id))
                .map_err(|e| map_store_err("insert new idx_nodes_name", e))?;
        }
        record.node_name = new_name.as_str().to_owned();
        save_node_record_in_tx(tx, &record)?;
        let audit = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor: "admin",
            action: "node_renamed",
            target: &node_id.to_string(),
            outcome: "success",
            metadata: serde_json::json!({ "old_name": old_name, "new_name": record.node_name }),
        };
        AuditRepository::append_audit_in_tx(tx, &audit)?;
        Ok(record)
    }

    /// Marks `node_id` revoked (`US-029`), placing its `overlay_ip` into 24h quarantine
    /// and releasing its unique hostname index entry for clean reuse (`HR-S1-04`).
    pub fn revoke_node_in_tx(
        tx: &WriteTransaction,
        node_id: NodeId,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<StoredNodeRecord> {
        let mut record = load_node_by_id_in_tx(tx, node_id)?
            .ok_or_else(|| AppError::not_found(format!("node {node_id} not found")))?;
        if record.status != NodeStatus::Revoked {
            record.status = NodeStatus::Revoked;
            record.revoked_at_ms = Some(now_unix_ms);
            record.quarantine_until_ms = Some(now_unix_ms.saturating_add(QUARANTINE_DURATION_MS));
            record.last_overlay_ip = record.last_overlay_ip.or(record.overlay_ip);
            save_node_record_in_tx(tx, &record)?;
        }
        {
            let mut name_idx = tx
                .open_table(TABLE_IDX_NODES_NAME)
                .map_err(|e| map_store_err("open write idx_nodes_name revoke", e))?;
            name_idx
                .remove(record.node_name.as_str())
                .map_err(|e| map_store_err("remove revoked idx_nodes_name", e))?;
        }
        let audit = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "node_revoked",
            target: &node_id.to_string(),
            outcome: "success",
            metadata: serde_json::json!({
                "node_name": record.node_name,
                "quarantine_until_ms": record.quarantine_until_ms,
            }),
        };
        AuditRepository::append_audit_in_tx(tx, &audit)?;
        Ok(record)
    }

    /// Inserts or updates a tombstone revocation record during degraded recovery compaction so
    /// nodes revoked during `redb` outage remain blocked (`US-029`, Gate 2 policy (a)).
    pub fn apply_compacted_revocation_in_tx(
        tx: &WriteTransaction,
        node_id: NodeId,
        pubkey_bytes: [u8; 32],
        revoked_at_ms: u64,
        mark_expired: bool,
    ) -> AppResult<()> {
        if let Some(mut existing) = load_node_by_id_in_tx(tx, node_id)? {
            if mark_expired {
                if existing.status == NodeStatus::Active {
                    existing.status = NodeStatus::Expired;
                    existing.expired_at_ms = Some(revoked_at_ms);
                    existing.quarantine_until_ms =
                        Some(revoked_at_ms.saturating_add(QUARANTINE_DURATION_MS));
                    existing.last_overlay_ip = existing.last_overlay_ip.or(existing.overlay_ip);
                }
            } else {
                existing.status = NodeStatus::Revoked;
                existing.revoked_at_ms = Some(revoked_at_ms);
                existing.quarantine_until_ms =
                    Some(revoked_at_ms.saturating_add(QUARANTINE_DURATION_MS));
                existing.last_overlay_ip = existing.last_overlay_ip.or(existing.overlay_ip);
                let mut name_idx = tx
                    .open_table(TABLE_IDX_NODES_NAME)
                    .map_err(|e| map_store_err("open write idx_nodes_name compact revoke", e))?;
                name_idx
                    .remove(existing.node_name.as_str())
                    .map_err(|e| map_store_err("remove compacted revoked idx_nodes_name", e))?;
            }
            save_node_record_in_tx(tx, &existing)?;
            return Ok(());
        }

        let tombstone = StoredNodeRecord {
            node_id,
            node_name: format!("revoked-{}", &node_id.to_string()[..8]),
            pubkey: pubkey_bytes,
            disco_pubkey: [0_u8; 32],
            overlay_ip: None,
            last_overlay_ip: None,
            status: if mark_expired {
                NodeStatus::Expired
            } else {
                NodeStatus::Revoked
            },
            preauth_key_id: KeyId::new_v7(revoked_at_ms),
            ephemeral: false,
            created_at_ms: revoked_at_ms,
            last_seen_at_ms: revoked_at_ms,
            key_expires_at_ms: revoked_at_ms,
            revoked_at_ms: (!mark_expired).then_some(revoked_at_ms),
            expired_at_ms: mark_expired.then_some(revoked_at_ms),
            quarantine_until_ms: Some(revoked_at_ms.saturating_add(QUARANTINE_DURATION_MS)),
            os_arch: "unknown".to_owned(),
            agent_version: "unknown".to_owned(),
            protocol_version: 1,
            endpoints: Vec::new(),
        };
        save_node_record_in_tx(tx, &tombstone)?;
        if pubkey_bytes != [0_u8; 32] {
            let mut pk_idx = tx
                .open_table(TABLE_IDX_NODES_PUBKEY)
                .map_err(|e| map_store_err("open write idx_nodes_pubkey tombstone", e))?;
            pk_idx
                .insert(&pubkey_bytes, node_id_to_u128(node_id))
                .map_err(|e| map_store_err("insert tombstone idx_nodes_pubkey", e))?;
        }
        Ok(())
    }

    /// Forces immediate expiration of a node key (`US-031`).
    pub fn expire_node_in_tx(
        tx: &WriteTransaction,
        node_id: NodeId,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<StoredNodeRecord> {
        let mut record = load_node_by_id_in_tx(tx, node_id)?
            .ok_or_else(|| AppError::not_found(format!("node {node_id} not found")))?;
        if record.status == NodeStatus::Revoked {
            return Err(AppError::conflict("cannot expire an already revoked node"));
        }
        record.status = NodeStatus::Expired;
        record.expired_at_ms = Some(now_unix_ms);
        record.key_expires_at_ms = record.key_expires_at_ms.min(now_unix_ms);
        record.quarantine_until_ms = Some(now_unix_ms.saturating_add(QUARANTINE_DURATION_MS));
        save_node_record_in_tx(tx, &record)?;
        let audit = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "node_expired",
            target: &node_id.to_string(),
            outcome: "success",
            metadata: serde_json::json!({
                "node_name": record.node_name,
                "quarantine_until_ms": record.quarantine_until_ms,
            }),
        };
        AuditRepository::append_audit_in_tx(tx, &audit)?;
        Ok(record)
    }

    /// Reclaims `idx_nodes_overlay_ip` entries for nodes whose 24h quarantine has elapsed (`US-008`).
    pub fn reclaim_expired_quarantines_in_tx(
        tx: &WriteTransaction,
        now_unix_ms: u64,
    ) -> AppResult<Vec<OverlayIp>> {
        let mut candidates = Vec::new();
        {
            let ip_idx = tx
                .open_table(TABLE_IDX_NODES_OVERLAY_IP)
                .map_err(|e| map_store_err("open idx_nodes_overlay_ip sweep", e))?;
            for item in ip_idx
                .iter()
                .map_err(|e| map_store_err("iterate idx_nodes_overlay_ip", e))?
            {
                let (ip_guard, owner_guard) =
                    item.map_err(|e| map_store_err("read idx_nodes_overlay_ip row", e))?;
                candidates.push((ip_guard.value(), u128_to_node_id(owner_guard.value())));
            }
        }

        let mut reclaimed = Vec::new();
        for (ip_u32, owner_id) in candidates {
            if let Some(mut owner) = load_node_by_id_in_tx(tx, owner_id)? {
                if owner.status == NodeStatus::Active {
                    continue;
                }
                if owner.quarantine_until_ms.unwrap_or(0) > now_unix_ms {
                    continue;
                }
                owner.last_overlay_ip = owner.last_overlay_ip.or(owner.overlay_ip);
                owner.overlay_ip = None;
                owner.quarantine_until_ms = None;
                save_node_record_in_tx(tx, &owner)?;
            }
            let mut ip_idx = tx
                .open_table(TABLE_IDX_NODES_OVERLAY_IP)
                .map_err(|e| map_store_err("open write idx_nodes_overlay_ip reclaim", e))?;
            ip_idx
                .remove(ip_u32)
                .map_err(|e| map_store_err("remove expired idx_nodes_overlay_ip", e))?;
            if let Ok(ip) = u32_to_overlay_ip(ip_u32) {
                reclaimed.push(ip);
            }
        }
        Ok(reclaimed)
    }

    /// Configures or updates the overlay IPv4 CIDR; refuses silent CIDR change when nodes exist
    /// and emits a `WARN` log if overlapping `100.64.0.0/10` (`US-008 AC3/AC4`).
    pub fn set_overlay_cidr_in_tx(
        tx: &WriteTransaction,
        raw_cidr: &str,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<OverlayCidr> {
        let parsed = OverlayCidr::parse(raw_cidr)?;
        if parsed.overlaps_cgnat() {
            tracing::warn!(
                component = "mesh-store",
                event = "overlay_cidr_cgnat_overlap",
                cidr = %parsed,
                "overlay CIDR overlaps RFC 6598 100.64.0.0/10 CGNAT space; monitor for routing conflicts"
            );
        }

        let current_cidr = load_overlay_cidr_in_tx(tx)?;
        if let Some(existing_str) = current_cidr {
            if existing_str == parsed.to_string() {
                return Ok(parsed);
            }
            let nodes = tx
                .open_table(TABLE_NODES)
                .map_err(|e| map_store_err("open nodes check cidr lock", e))?;
            if !nodes
                .is_empty()
                .map_err(|e| map_store_err("check nodes empty for cidr change", e))?
            {
                return Err(AppError::conflict(
                    "cannot silently change overlay_cidr once registered nodes exist",
                ));
            }
        }

        let rec = OverlayCidrRecord {
            cidr: parsed.to_string(),
            configured_at_ms: now_unix_ms,
        };
        let encoded = encode_envelope(&rec)?;
        {
            let mut meta = tx
                .open_table(TABLE_SCHEMA_META)
                .map_err(|e| map_store_err("open meta set_overlay_cidr", e))?;
            meta.insert(META_KEY_OVERLAY_CIDR, encoded.as_slice())
                .map_err(|e| map_store_err("insert meta overlay_cidr", e))?;
        }

        let audit = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "overlay_cidr_configured",
            target: "server",
            outcome: "success",
            metadata: serde_json::json!({ "cidr": parsed.to_string() }),
        };
        AuditRepository::append_audit_in_tx(tx, &audit)?;
        Ok(parsed)
    }

    /// Reads the configured overlay CIDR from `redb`.
    pub fn load_overlay_cidr(db: &Database) -> AppResult<OverlayCidr> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read overlay_cidr", e))?;
        let meta = tx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open read meta overlay_cidr", e))?;
        let guard = meta
            .get(META_KEY_OVERLAY_CIDR)
            .map_err(|e| map_store_err("get meta overlay_cidr", e))?
            .ok_or_else(|| AppError::internal("overlay_cidr missing from schema_meta"))?;
        let rec: OverlayCidrRecord = decode_envelope(guard.value())?;
        OverlayCidr::parse(&rec.cidr)
    }

    /// Looks up a registered node record by `NodeId`.
    pub fn find_by_id(db: &Database, node_id: NodeId) -> AppResult<Option<StoredNodeRecord>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read node_by_id", e))?;
        let table = tx
            .open_table(TABLE_NODES)
            .map_err(|e| map_store_err("open read nodes", e))?;
        let Some(guard) = table
            .get(node_id_to_u128(node_id))
            .map_err(|e| map_store_err("get node", e))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_envelope(guard.value())?))
    }

    /// Looks up a registered node record by WireGuard `PublicKey`.
    pub fn find_by_pubkey(
        db: &Database,
        pubkey: &PublicKey,
    ) -> AppResult<Option<StoredNodeRecord>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read node_by_pubkey", e))?;
        let pk_idx = tx
            .open_table(TABLE_IDX_NODES_PUBKEY)
            .map_err(|e| map_store_err("open read idx_nodes_pubkey", e))?;
        let Some(id_guard) = pk_idx
            .get(pubkey.as_bytes())
            .map_err(|e| map_store_err("get idx_nodes_pubkey", e))?
        else {
            return Ok(None);
        };
        let nodes = tx
            .open_table(TABLE_NODES)
            .map_err(|e| map_store_err("open read nodes by pubkey", e))?;
        let Some(node_guard) = nodes
            .get(id_guard.value())
            .map_err(|e| map_store_err("get node row by pubkey", e))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_envelope(node_guard.value())?))
    }

    /// Looks up a registered node record by normalized [`NodeName`].
    pub fn find_by_name(db: &Database, name: &NodeName) -> AppResult<Option<StoredNodeRecord>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read node_by_name", e))?;
        let name_idx = tx
            .open_table(TABLE_IDX_NODES_NAME)
            .map_err(|e| map_store_err("open read idx_nodes_name", e))?;
        let Some(id_guard) = name_idx
            .get(name.as_str())
            .map_err(|e| map_store_err("get idx_nodes_name", e))?
        else {
            return Ok(None);
        };
        let nodes = tx
            .open_table(TABLE_NODES)
            .map_err(|e| map_store_err("open read nodes by name", e))?;
        let Some(node_guard) = nodes
            .get(id_guard.value())
            .map_err(|e| map_store_err("get node row by name", e))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_envelope(node_guard.value())?))
    }

    /// Lists all node records ordered by creation time.
    pub fn list_nodes(db: &Database) -> AppResult<Vec<StoredNodeRecord>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read list_nodes", e))?;
        let table = tx
            .open_table(TABLE_NODES)
            .map_err(|e| map_store_err("open read list_nodes", e))?;
        let mut out: Vec<StoredNodeRecord> = Vec::new();
        for item in table
            .iter()
            .map_err(|e| map_store_err("iterate nodes table", e))?
        {
            let (_, val_guard) = item.map_err(|e| map_store_err("read node row", e))?;
            out.push(decode_envelope(val_guard.value())?);
        }
        out.sort_by_key(|n| n.created_at_ms);
        Ok(out)
    }

    /// Transitions any active nodes whose `key_expires_at_ms <= now_unix_ms` to [`NodeStatus::Expired`].
    pub fn sweep_expired_nodes_in_tx(
        tx: &WriteTransaction,
        now_unix_ms: u64,
    ) -> AppResult<Vec<NodeId>> {
        let mut expired_ids = Vec::new();
        let all_nodes = {
            let table = tx
                .open_table(TABLE_NODES)
                .map_err(|e| map_store_err("open nodes sweep", e))?;
            let mut list = Vec::new();
            for item in table
                .iter()
                .map_err(|e| map_store_err("iterate nodes sweep", e))?
            {
                let (_, v) = item.map_err(|e| map_store_err("read node sweep", e))?;
                list.push(decode_envelope::<StoredNodeRecord>(v.value())?);
            }
            list
        };

        for node in all_nodes {
            if node.status == NodeStatus::Active && now_unix_ms >= node.key_expires_at_ms {
                let id = node.node_id;
                Self::expire_node_in_tx(tx, id, now_unix_ms, "system:expiry_sweeper")?;
                expired_ids.push(id);
            }
        }
        Ok(expired_ids)
    }
}

fn ensure_node_active(record: &StoredNodeRecord, now_unix_ms: u64) -> AppResult<()> {
    match record.status {
        NodeStatus::Revoked => Err(AppError::unauthenticated("node has been revoked")),
        NodeStatus::Expired => Err(AppError::unauthenticated("node key has expired")),
        NodeStatus::Active if now_unix_ms >= record.key_expires_at_ms => {
            Err(AppError::unauthenticated("node key reached expiration"))
        }
        NodeStatus::Active => Ok(()),
    }
}

fn handle_existing_pubkey_registration(
    tx: &WriteTransaction,
    mut existing: StoredNodeRecord,
    input: &RegisterNodeInput<'_>,
) -> AppResult<RegisterNodeOutcome> {
    if existing.status != NodeStatus::Active || input.now_unix_ms >= existing.key_expires_at_ms {
        return Err(AppError::unauthenticated(
            "cannot re-register with a revoked or expired node key",
        ));
    }
    if existing.node_name != input.requested_name.as_str() {
        return Err(AppError::unauthenticated(
            "public key is bound to another node identity",
        ));
    }

    // Verify caller presented the matching pre-auth key for idempotent replay (`US-005 AC4`).
    let key_matches =
        verify_matching_key_for_replay(tx, existing.preauth_key_id, &input.preauth_token_hash)?;
    if !key_matches {
        return Err(AppError::unauthenticated(
            "pre-auth key mismatch during idempotent registration replay",
        ));
    }

    existing.last_seen_at_ms = input.now_unix_ms;
    existing.disco_pubkey = *input.disco_pubkey.as_bytes();
    existing.os_arch = input.os_arch.to_owned();
    existing.agent_version = input.agent_version.to_owned();
    existing.protocol_version = input.protocol_version;
    save_node_record_in_tx(tx, &existing)?;

    Ok(RegisterNodeOutcome {
        record: existing,
        state_changed: false,
        replaced_pubkey: None,
    })
}

fn handle_key_rotation_registration(
    tx: &WriteTransaction,
    mut existing: StoredNodeRecord,
    new_preauth_key_id: KeyId,
    input: &RegisterNodeInput<'_>,
) -> AppResult<RegisterNodeOutcome> {
    let old_pubkey = existing.pubkey;
    let node_u128 = node_id_to_u128(existing.node_id);
    {
        let mut pk_idx = tx
            .open_table(TABLE_IDX_NODES_PUBKEY)
            .map_err(|e| map_store_err("open idx_nodes_pubkey rotation", e))?;
        pk_idx
            .remove(&old_pubkey)
            .map_err(|e| map_store_err("remove old idx_nodes_pubkey rotation", e))?;
        pk_idx
            .insert(input.pubkey.as_bytes(), node_u128)
            .map_err(|e| map_store_err("insert new idx_nodes_pubkey rotation", e))?;
    }

    existing.pubkey = *input.pubkey.as_bytes();
    existing.disco_pubkey = *input.disco_pubkey.as_bytes();
    existing.preauth_key_id = new_preauth_key_id;
    existing.last_seen_at_ms = input.now_unix_ms;
    existing.key_expires_at_ms = input.now_unix_ms.saturating_add(input.node_key_ttl_ms);
    existing.os_arch = input.os_arch.to_owned();
    existing.agent_version = input.agent_version.to_owned();
    existing.protocol_version = input.protocol_version;
    save_node_record_in_tx(tx, &existing)?;
    append_register_audit(tx, &existing, "node_key_rotated")?;

    let replaced_pubkey = PublicKey::from_bytes(old_pubkey)
        .ok()
        .filter(|_| old_pubkey != *input.pubkey.as_bytes());

    Ok(RegisterNodeOutcome {
        record: existing,
        state_changed: true,
        replaced_pubkey,
    })
}

fn verify_matching_key_for_replay(
    tx: &WriteTransaction,
    enrolled_key_id: KeyId,
    presented_hash: &[u8; 32],
) -> AppResult<bool> {
    let keys_table = tx
        .open_table(TABLE_PREAUTH_KEYS)
        .map_err(|e| map_store_err("open preauth_keys replay check", e))?;
    let Some(guard) = keys_table
        .get(crate::schema::key_id_to_u128(enrolled_key_id))
        .map_err(|e| map_store_err("get enrolled preauth key", e))?
    else {
        return Ok(false);
    };
    let rec: crate::keys_repo::StoredPreAuthKeyRecord = decode_envelope(guard.value())?;
    Ok(mesh_crypto::ct_eq_bytes(&rec.token_hash, presented_hash) && rec.revoked_at_ms.is_none())
}

fn handle_name_collision_registration(
    tx: &WriteTransaction,
    mut existing: StoredNodeRecord,
    consumed_key: crate::keys_repo::StoredPreAuthKeyRecord,
    input: &RegisterNodeInput<'_>,
) -> AppResult<RegisterNodeOutcome> {
    // Only allow taking over an existing name if its key expired AND pre-auth key was explicitly
    // bound with `--for <node>` (`US-031 AC5`). Active or revoked names refuse collision.
    let explicitly_bound =
        consumed_key.bound_node_name.as_deref() == Some(existing.node_name.as_str());
    let expired_or_past =
        existing.status == NodeStatus::Expired || input.now_unix_ms >= existing.key_expires_at_ms;
    if existing.status == NodeStatus::Revoked || !expired_or_past || !explicitly_bound {
        return Err(AppError::conflict(format!(
            "node name `{}` already registered",
            input.requested_name
        )));
    }

    let old_pubkey = existing.pubkey;
    let node_u128 = node_id_to_u128(existing.node_id);
    {
        let mut pk_idx = tx
            .open_table(TABLE_IDX_NODES_PUBKEY)
            .map_err(|e| map_store_err("open idx_nodes_pubkey reenroll", e))?;
        pk_idx
            .remove(&old_pubkey)
            .map_err(|e| map_store_err("remove old idx_nodes_pubkey reenroll", e))?;
        pk_idx
            .insert(input.pubkey.as_bytes(), node_u128)
            .map_err(|e| map_store_err("insert new idx_nodes_pubkey reenroll", e))?;
    }

    let preserved_ip = match existing.overlay_ip {
        Some(ip) => ip,
        None => allocate_next_overlay_ip_in_tx(tx, existing.node_id, input.now_unix_ms)?,
    };

    existing.pubkey = *input.pubkey.as_bytes();
    existing.disco_pubkey = *input.disco_pubkey.as_bytes();
    existing.overlay_ip = Some(preserved_ip);
    existing.last_overlay_ip = Some(preserved_ip);
    existing.status = NodeStatus::Active;
    existing.preauth_key_id = consumed_key.key_id;
    existing.expired_at_ms = None;
    existing.quarantine_until_ms = None;
    existing.last_seen_at_ms = input.now_unix_ms;
    existing.key_expires_at_ms = input.now_unix_ms.saturating_add(input.node_key_ttl_ms);
    existing.os_arch = input.os_arch.to_owned();
    existing.agent_version = input.agent_version.to_owned();
    existing.protocol_version = input.protocol_version;

    save_node_record_in_tx(tx, &existing)?;
    append_register_audit(tx, &existing, "node_reenrolled")?;

    let replaced_pubkey = PublicKey::from_bytes(old_pubkey)
        .ok()
        .filter(|_| old_pubkey != *input.pubkey.as_bytes());

    Ok(RegisterNodeOutcome {
        record: existing,
        state_changed: true,
        replaced_pubkey,
    })
}

fn allocate_next_overlay_ip_in_tx(
    tx: &WriteTransaction,
    assignee_node_id: NodeId,
    now_unix_ms: u64,
) -> AppResult<OverlayIp> {
    let cidr_str = load_overlay_cidr_in_tx(tx)?
        .ok_or_else(|| AppError::internal("overlay_cidr not configured"))?;
    let cidr = OverlayCidr::parse(&cidr_str)?;
    let total_usable = cidr.usable_host_count();
    if total_usable < 2 {
        return Err(AppError::internal("overlay CIDR lacks usable host space"));
    }
    // Skip index 0 (`.1` gateway reserve) when iterating candidates (`1..total_usable`).
    let allocatable = total_usable - 1;
    let start_offset = {
        let meta = tx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open meta read ip_alloc_cursor", e))?;
        match meta
            .get(META_KEY_IP_ALLOC_CURSOR)
            .map_err(|e| map_store_err("get ip_alloc_cursor", e))?
        {
            Some(g) => decode_u32_be(g.value())? % allocatable,
            None => 0,
        }
    };

    for step in 0..allocatable {
        let host_idx = 1 + ((start_offset + step) % allocatable);
        let Some(candidate) = cidr.nth_usable_ip(host_idx) else {
            continue;
        };
        if try_claim_candidate_ip_in_tx(tx, candidate, assignee_node_id, now_unix_ms)? {
            let next_cursor = (start_offset + step + 1) % allocatable;
            let mut meta = tx
                .open_table(TABLE_SCHEMA_META)
                .map_err(|e| map_store_err("open meta write ip_alloc_cursor", e))?;
            let encoded = encode_u32_be(next_cursor);
            meta.insert(META_KEY_IP_ALLOC_CURSOR, encoded.as_slice())
                .map_err(|e| map_store_err("update ip_alloc_cursor", e))?;
            return Ok(candidate);
        }
    }

    Err(AppError::conflict(
        "overlay CIDR IPv4 address pool exhausted",
    ))
}

fn try_claim_candidate_ip_in_tx(
    tx: &WriteTransaction,
    candidate: OverlayIp,
    assignee: NodeId,
    now_unix_ms: u64,
) -> AppResult<bool> {
    let ip_u32 = overlay_ip_to_u32(candidate);
    let existing_owner = {
        let ip_idx = tx
            .open_table(TABLE_IDX_NODES_OVERLAY_IP)
            .map_err(|e| map_store_err("open idx_nodes_overlay_ip claim", e))?;
        ip_idx
            .get(ip_u32)
            .map_err(|e| map_store_err("get idx_nodes_overlay_ip claim", e))?
            .map(|g| u128_to_node_id(g.value()))
    };

    if let Some(owner_id) = existing_owner
        && let Some(mut owner) = load_node_by_id_in_tx(tx, owner_id)?
    {
        if owner.status == NodeStatus::Active {
            return Ok(false);
        }
        if owner.quarantine_until_ms.unwrap_or(0) > now_unix_ms {
            return Ok(false);
        }
        // Quarantine elapsed: clear stale IP from old quarantined node record before reassigning.
        owner.last_overlay_ip = owner.last_overlay_ip.or(owner.overlay_ip);
        owner.overlay_ip = None;
        owner.quarantine_until_ms = None;
        save_node_record_in_tx(tx, &owner)?;
    }

    let mut ip_idx = tx
        .open_table(TABLE_IDX_NODES_OVERLAY_IP)
        .map_err(|e| map_store_err("open write idx_nodes_overlay_ip", e))?;
    ip_idx
        .insert(ip_u32, node_id_to_u128(assignee))
        .map_err(|e| map_store_err("insert idx_nodes_overlay_ip", e))?;
    Ok(true)
}

fn build_new_node_record(
    node_id: NodeId,
    overlay_ip: OverlayIp,
    key: &crate::keys_repo::StoredPreAuthKeyRecord,
    input: &RegisterNodeInput<'_>,
) -> StoredNodeRecord {
    StoredNodeRecord {
        node_id,
        node_name: input.requested_name.as_str().to_owned(),
        pubkey: *input.pubkey.as_bytes(),
        disco_pubkey: *input.disco_pubkey.as_bytes(),
        overlay_ip: Some(overlay_ip),
        last_overlay_ip: Some(overlay_ip),
        status: NodeStatus::Active,
        preauth_key_id: key.key_id,
        ephemeral: key.ephemeral,
        created_at_ms: input.now_unix_ms,
        last_seen_at_ms: input.now_unix_ms,
        key_expires_at_ms: input.now_unix_ms.saturating_add(input.node_key_ttl_ms),
        revoked_at_ms: None,
        expired_at_ms: None,
        quarantine_until_ms: None,
        os_arch: input.os_arch.to_owned(),
        agent_version: input.agent_version.to_owned(),
        protocol_version: input.protocol_version,
        endpoints: Vec::new(),
    }
}

fn persist_new_node_and_indexes_in_tx(
    tx: &WriteTransaction,
    record: &StoredNodeRecord,
) -> AppResult<()> {
    let node_u128 = node_id_to_u128(record.node_id);
    save_node_record_in_tx(tx, record)?;
    let mut pk_idx = tx
        .open_table(TABLE_IDX_NODES_PUBKEY)
        .map_err(|e| map_store_err("open write idx_nodes_pubkey", e))?;
    pk_idx
        .insert(&record.pubkey, node_u128)
        .map_err(|e| map_store_err("insert idx_nodes_pubkey", e))?;

    let mut name_idx = tx
        .open_table(TABLE_IDX_NODES_NAME)
        .map_err(|e| map_store_err("open write idx_nodes_name", e))?;
    name_idx
        .insert(record.node_name.as_str(), node_u128)
        .map_err(|e| map_store_err("insert idx_nodes_name", e))?;
    Ok(())
}

fn append_register_audit(
    tx: &WriteTransaction,
    record: &StoredNodeRecord,
    action: &str,
) -> AppResult<()> {
    let audit = AuditEventInput {
        occurred_at_ms: record.last_seen_at_ms,
        actor: "node",
        action,
        target: &record.node_id.to_string(),
        outcome: "success",
        metadata: serde_json::json!({
            "node_name": record.node_name,
            "overlay_ip": record.overlay_ip.map(|ip| ip.to_string()),
            "preauth_key_id": record.preauth_key_id.to_string(),
        }),
    };
    AuditRepository::append_audit_in_tx(tx, &audit)?;
    Ok(())
}

fn save_node_record_in_tx(tx: &WriteTransaction, record: &StoredNodeRecord) -> AppResult<()> {
    let encoded = encode_envelope(record)?;
    let mut table = tx
        .open_table(TABLE_NODES)
        .map_err(|e| map_store_err("open write nodes", e))?;
    table
        .insert(node_id_to_u128(record.node_id), encoded.as_slice())
        .map_err(|e| map_store_err("insert nodes", e))?;
    Ok(())
}

fn load_node_by_id_in_tx(
    tx: &WriteTransaction,
    node_id: NodeId,
) -> AppResult<Option<StoredNodeRecord>> {
    let table = tx
        .open_table(TABLE_NODES)
        .map_err(|e| map_store_err("open read nodes in tx", e))?;
    let Some(guard) = table
        .get(node_id_to_u128(node_id))
        .map_err(|e| map_store_err("get node in tx", e))?
    else {
        return Ok(None);
    };
    Ok(Some(decode_envelope(guard.value())?))
}

fn lookup_node_by_pubkey_in_tx(
    tx: &WriteTransaction,
    pubkey: &PublicKey,
) -> AppResult<Option<StoredNodeRecord>> {
    let id_opt = {
        let pk_idx = tx
            .open_table(TABLE_IDX_NODES_PUBKEY)
            .map_err(|e| map_store_err("open idx_nodes_pubkey in tx", e))?;
        pk_idx
            .get(pubkey.as_bytes())
            .map_err(|e| map_store_err("get idx_nodes_pubkey in tx", e))?
            .map(|g| u128_to_node_id(g.value()))
    };
    match id_opt {
        Some(node_id) => load_node_by_id_in_tx(tx, node_id),
        None => Ok(None),
    }
}

fn lookup_node_by_name_in_tx(
    tx: &WriteTransaction,
    name: &str,
) -> AppResult<Option<StoredNodeRecord>> {
    let id_opt = {
        let name_idx = tx
            .open_table(TABLE_IDX_NODES_NAME)
            .map_err(|e| map_store_err("open idx_nodes_name in tx", e))?;
        name_idx
            .get(name)
            .map_err(|e| map_store_err("get idx_nodes_name in tx", e))?
            .map(|g| u128_to_node_id(g.value()))
    };
    match id_opt {
        Some(node_id) => load_node_by_id_in_tx(tx, node_id),
        None => Ok(None),
    }
}

fn load_overlay_cidr_in_tx(tx: &WriteTransaction) -> AppResult<Option<String>> {
    let meta = tx
        .open_table(TABLE_SCHEMA_META)
        .map_err(|e| map_store_err("open read meta cidr in tx", e))?;
    let Some(guard) = meta
        .get(META_KEY_OVERLAY_CIDR)
        .map_err(|e| map_store_err("get meta cidr in tx", e))?
    else {
        return Ok(None);
    };
    let rec: OverlayCidrRecord = decode_envelope(guard.value())?;
    Ok(Some(rec.cidr))
}

#[cfg(test)]
mod tests {
    use mesh_core::ErrorKind;
    use tempfile::TempDir;

    use super::*;
    use crate::keys_repo::CreatePreAuthKeyInput;
    use crate::schema::ensure_all_tables;

    fn setup_db(cidr: &str) -> (TempDir, Database) {
        let dir = TempDir::new().expect("create temp dir");
        let db = Database::create(dir.path().join("nodes.redb")).expect("create nodes db");
        let tx = db.begin_write().expect("begin setup write tx");
        ensure_all_tables(&tx).expect("ensure tables");
        NodesRepository::set_overlay_cidr_in_tx(&tx, cidr, 1_731_480_000_000, "system")
            .expect("set overlay cidr");
        tx.commit().expect("commit setup tx");
        (dir, db)
    }

    fn mint_key(db: &Database, seed: u8, bound: Option<&str>, now: u64) -> [u8; 32] {
        let hash = [seed; 32];
        let tx = db.begin_write().expect("begin key write tx");
        let bound_name = bound.map(|s| NodeName::parse(s).expect("valid node name"));
        KeysRepository::create_key_in_tx(
            &tx,
            &CreatePreAuthKeyInput {
                key_id: KeyId::new_v7(now + u64::from(seed)),
                token_hash: hash,
                label: None,
                bound_node_name: bound_name,
                reusable: false,
                max_uses: None,
                ephemeral: false,
                ttl_secs: 3_600,
                now_unix_ms: now,
            },
            "admin",
        )
        .expect("mint key");
        tx.commit().expect("commit key tx");
        hash
    }

    #[test]
    fn test_register_idempotent_single_tx_and_rejects_revoked_with_unauthenticated() {
        // Arrange
        let (_dir, db) = setup_db("10.100.0.0/24");
        let now = 1_731_480_000_000;
        let key_hash = mint_key(&db, 0x11, None, now);
        let pk = PublicKey::from_bytes([0x22_u8; 32]).expect("pk");
        let disco_pk = PublicKey::from_bytes([0x23_u8; 32]).expect("disco pk");
        let name = NodeName::parse("macbook").expect("node name");
        let req = RegisterNodeInput {
            pubkey: pk,
            disco_pubkey: disco_pk,
            previous_node_pubkey: None,
            requested_name: name,
            preauth_token_hash: key_hash,
            public_control_host: "203.0.113.10",
            domain_suffix: "mesh.internal",
            os_arch: "darwin/arm64",
            agent_version: "0.1.0",
            protocol_version: 1,
            node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
            now_unix_ms: now,
        };

        // Act: initial registration + idempotent replay
        let tx1 = db.begin_write().expect("begin tx1");
        let r1 = NodesRepository::register_node_in_tx(&tx1, &req).expect("register r1");
        tx1.commit().expect("commit tx1");

        let tx2 = db.begin_write().expect("begin tx2");
        let r2 = NodesRepository::register_node_in_tx(&tx2, &req).expect("register r2");
        tx2.commit().expect("commit tx2");

        // Revoke node, then retry register -> must fail with ErrorKind::Unauthenticated
        assert!(r1.state_changed);
        assert!(!r2.state_changed);
        assert_eq!(r1.record.node_id, r2.record.node_id);
        assert_eq!(r1.record.overlay_ip, r2.record.overlay_ip);

        let tx_rev = db.begin_write().expect("begin revoke tx");
        NodesRepository::revoke_node_in_tx(&tx_rev, r1.record.node_id, now + 10, "admin")
            .expect("revoke node");
        tx_rev.commit().expect("commit revoke tx");

        let tx_retry = db.begin_write().expect("begin retry tx");
        let revoked_retry = NodesRepository::register_node_in_tx(&tx_retry, &req);
        assert_eq!(
            revoked_retry.as_ref().err().map(|e| e.kind()),
            Some(ErrorKind::Unauthenticated)
        );
        assert_eq!(
            revoked_retry.as_ref().err().map(|e| e.public_message()),
            Some("authentication failed")
        );
    }

    #[test]
    fn test_quarantine_ip_reclaim_cleans_index_after_24_hours_and_blocks_cidr_change() {
        // Arrange
        let (_dir, db) = setup_db("10.100.0.0/25");
        let now = 1_731_480_000_000;
        let k1 = mint_key(&db, 0x31, None, now);
        let pk1 = PublicKey::from_bytes([0x41_u8; 32]).expect("pk1");
        let disco1 = PublicKey::from_bytes([0x42_u8; 32]).expect("disco1");
        let n1 = NodeName::parse("node-alpha").expect("node name");

        let tx1 = db.begin_write().expect("begin tx1");
        let out1 = NodesRepository::register_node_in_tx(
            &tx1,
            &RegisterNodeInput {
                pubkey: pk1,
                disco_pubkey: disco1,
                previous_node_pubkey: None,
                requested_name: n1,
                preauth_token_hash: k1,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now,
            },
        )
        .expect("register node-alpha");
        NodesRepository::revoke_node_in_tx(&tx1, out1.record.node_id, now + 100, "admin")
            .expect("revoke node-alpha");
        // Refusing silent CIDR change when node exists
        assert!(
            NodesRepository::set_overlay_cidr_in_tx(&tx1, "10.101.0.0/24", now + 200, "admin")
                .is_err()
        );
        tx1.commit().expect("commit tx1");

        // Act: 12h later -> still quarantined, explicit sweep returns empty
        let tx_early = db.begin_write().expect("begin tx_early");
        let reclaimed_early =
            NodesRepository::reclaim_expired_quarantines_in_tx(&tx_early, now + 12 * 3_600 * 1_000)
                .expect("early reclaim");
        assert!(reclaimed_early.is_empty());
        tx_early.commit().expect("commit tx_early");

        // 25h later -> quarantine elapsed, reclaim removes from idx_nodes_overlay_ip
        let tx_late = db.begin_write().expect("begin tx_late");
        let reclaimed_late = NodesRepository::reclaim_expired_quarantines_in_tx(
            &tx_late,
            now + QUARANTINE_DURATION_MS + 1_000,
        )
        .expect("late reclaim");
        tx_late.commit().expect("commit tx_late");

        // Assert
        let allocated_ip = out1.record.overlay_ip.expect("overlay ip assigned");
        assert_eq!(reclaimed_late, vec![allocated_ip]);
        let reloaded = NodesRepository::find_by_id(&db, out1.record.node_id)
            .expect("find_by_id")
            .expect("reloaded node");
        assert_eq!(reloaded.overlay_ip, None);
    }

    #[test]
    fn test_unbound_preauth_key_cannot_hijack_existing_node_via_rotation() {
        // Arrange
        let (_dir, db) = setup_db("10.100.0.0/24");
        let now = 1_731_480_500_000;
        let victim_name = NodeName::parse("prod-gateway").expect("node name");
        let victim_key_hash = mint_key(&db, 0x71, Some("prod-gateway"), now);
        let victim_pk = PublicKey::from_bytes([0x81_u8; 32]).expect("victim pk");
        let victim_disco = PublicKey::from_bytes([0x82_u8; 32]).expect("victim disco");

        let tx1 = db.begin_write().expect("begin tx1");
        let enrolled = NodesRepository::register_node_in_tx(
            &tx1,
            &RegisterNodeInput {
                pubkey: victim_pk,
                disco_pubkey: victim_disco,
                previous_node_pubkey: None,
                requested_name: victim_name.clone(),
                preauth_token_hash: victim_key_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now,
            },
        )
        .expect("enroll victim");
        tx1.commit().expect("commit tx1");

        // Mint an unbound key and attempt rotation using victim's pubkey
        let unbound_hash = mint_key(&db, 0x72, None, now + 10);
        let attacker_pk = PublicKey::from_bytes([0x83_u8; 32]).expect("attacker pk");
        let attacker_disco = PublicKey::from_bytes([0x84_u8; 32]).expect("attacker disco");

        let tx_hijack = db.begin_write().expect("begin hijack tx");
        let hijack_res = NodesRepository::register_node_in_tx(
            &tx_hijack,
            &RegisterNodeInput {
                pubkey: attacker_pk,
                disco_pubkey: attacker_disco,
                previous_node_pubkey: Some(victim_pk),
                requested_name: victim_name.clone(),
                preauth_token_hash: unbound_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now + 20,
            },
        );

        // Assert: rejected as Unauthenticated ("authentication failed") and victim untouched
        assert_eq!(
            hijack_res.as_ref().err().map(|e| e.kind()),
            Some(ErrorKind::Unauthenticated)
        );
        assert_eq!(
            hijack_res.as_ref().err().map(|e| e.public_message()),
            Some("authentication failed")
        );
        drop(tx_hijack);

        // Bound rotation with `--for prod-gateway` succeeds and returns replaced_pubkey
        let bound_rot_hash = mint_key(&db, 0x73, Some("prod-gateway"), now + 30);
        let rotated_pk = PublicKey::from_bytes([0x85_u8; 32]).expect("rotated pk");
        let tx_rot = db.begin_write().expect("begin rot tx");
        let rotated = NodesRepository::register_node_in_tx(
            &tx_rot,
            &RegisterNodeInput {
                pubkey: rotated_pk,
                disco_pubkey: victim_disco,
                previous_node_pubkey: Some(victim_pk),
                requested_name: victim_name,
                preauth_token_hash: bound_rot_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now + 40,
            },
        )
        .expect("bound rotation should succeed");
        tx_rot.commit().expect("commit rot tx");
        assert_eq!(rotated.record.node_id, enrolled.record.node_id);
        assert_eq!(rotated.replaced_pubkey, Some(victim_pk));
    }

    #[test]
    fn test_revoked_node_name_can_be_reregistered() {
        // Arrange
        let (_dir, db) = setup_db("10.100.0.0/24");
        let now = 1_731_480_600_000;
        let name = NodeName::parse("reclaimable-host").expect("node name");
        let k1 = mint_key(&db, 0x91, None, now);
        let pk1 = PublicKey::from_bytes([0x92_u8; 32]).expect("pk1");
        let disco1 = PublicKey::from_bytes([0x93_u8; 32]).expect("disco1");

        let tx1 = db.begin_write().expect("begin tx1");
        let out1 = NodesRepository::register_node_in_tx(
            &tx1,
            &RegisterNodeInput {
                pubkey: pk1,
                disco_pubkey: disco1,
                previous_node_pubkey: None,
                requested_name: name.clone(),
                preauth_token_hash: k1,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now,
            },
        )
        .expect("enroll first node");
        NodesRepository::revoke_node_in_tx(&tx1, out1.record.node_id, now + 10, "admin")
            .expect("revoke first node");
        tx1.commit().expect("commit revoke");

        // Act: enroll fresh keypair under same name using new pre-auth key
        let k2 = mint_key(&db, 0x94, None, now + 20);
        let pk2 = PublicKey::from_bytes([0x95_u8; 32]).expect("pk2");
        let disco2 = PublicKey::from_bytes([0x96_u8; 32]).expect("disco2");
        let tx2 = db.begin_write().expect("begin tx2");
        let out2 = NodesRepository::register_node_in_tx(
            &tx2,
            &RegisterNodeInput {
                pubkey: pk2,
                disco_pubkey: disco2,
                previous_node_pubkey: None,
                requested_name: name,
                preauth_token_hash: k2,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now + 30,
            },
        )
        .expect("re-register revoked hostname");
        tx2.commit().expect("commit re-register");

        // Assert
        assert_ne!(out2.record.node_id, out1.record.node_id);
        assert_eq!(out2.record.status, NodeStatus::Active);
    }
}
