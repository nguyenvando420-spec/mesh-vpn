//! Control store initialization, fail-closed boot checks, `MonotonicNetmapVersion` leasing,
//! emergency recovery compaction, and hot backup/restore coordination (`WP-S1-01`).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use mesh_core::defaults::DEFAULT_OVERLAY_CIDR;
use mesh_core::{
    AppError, AppResult, Clock, KeyId, NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey,
    SystemClock,
};
use mesh_proto::admin_ipc::PersistenceTier;
use mesh_proto::netmap::CandidateEndpoint;
use redb::{Database, ReadableTable as _};
use serde_json::json;

use crate::audit_repo::{AuditEventInput, AuditQuery, AuditRepository, StoredAuditEventRecord};
use crate::backup::{
    BackupArtifact, BackupManager, DEFAULT_BACKUP_RETENTION, EmergencySnapshotOverlay,
    RestoreOptions, RestoreOutcome,
};
use crate::identity_repo::{AcmeAccountCredentialsBox, IdentityRepository, ServerIdentity};
use crate::keys_repo::{CreatePreAuthKeyInput, KeysRepository, StoredPreAuthKeyRecord};
use crate::nodes_repo::{
    NodeStatus, NodesRepository, RegisterNodeInput, RegisterNodeOutcome, StoredNodeRecord,
};
use crate::revoked_ram::{
    EmergencyFileBackend, EmergencyNodeReason, EmergencyRevocationKeyEntry,
    EmergencyRevocationNodeEntry, EmergencyRevocationState, OsEmergencyFileBackend, RevokedSet,
};
use crate::schema::{
    META_KEY_SCHEMA_VERSION, META_KEY_WATERMARK, SCHEMA_VERSION, SchemaVersionRecord, TABLE_NODES,
    TABLE_PREAUTH_KEYS, TABLE_SCHEMA_META, VERSION_LEASE_STEP, decode_envelope, decode_u64_be,
    encode_envelope, encode_u64_be, ensure_all_tables, map_store_err, verify_all_tables_readable,
};

/// Configuration for opening [`ControlStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlStoreConfig {
    /// Path to `mesh-server.redb`.
    pub db_path: PathBuf,
    /// Path to `emergency-revocations.bin` (`64 KiB` slot A/B file).
    pub emergency_revocations_path: PathBuf,
}

/// Strictly monotonic epoch-independent `netmap_version` allocator (`database-design.md` §3.4).
#[derive(Debug)]
pub struct MonotonicNetmapVersion {
    current: AtomicU64,
    persisted_watermark: AtomicU64,
    lease_guard: Mutex<()>,
}

impl MonotonicNetmapVersion {
    fn new(boot_current: u64, boot_watermark: u64) -> Self {
        Self {
            current: AtomicU64::new(boot_current),
            persisted_watermark: AtomicU64::new(boot_watermark),
            lease_guard: Mutex::new(()),
        }
    }

    /// Returns the most recently emitted `netmap_version`.
    #[must_use]
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::SeqCst)
    }

    /// Returns the highest durable `netmap_version` leased to this server epoch in `redb`.
    #[must_use]
    pub fn persisted_watermark(&self) -> u64 {
        self.persisted_watermark.load(Ordering::SeqCst)
    }

    fn allocate_next(&self, db: &Database, inject_redb_failure: bool) -> AppResult<u64> {
        let _guard = self
            .lease_guard
            .lock()
            .map_err(|_| AppError::internal("netmap version lease mutex poisoned"))?;
        let cur = self.current.load(Ordering::SeqCst);
        let wm = self.persisted_watermark.load(Ordering::SeqCst);
        let next = cur
            .checked_add(1)
            .ok_or_else(|| AppError::internal("netmap_version u64 space exhausted"))?;

        if next > wm {
            if inject_redb_failure {
                return Err(AppError::unavailable(
                    "primary redb unavailable while extending netmap_version lease",
                ));
            }
            let new_wm = next.saturating_add(VERSION_LEASE_STEP.saturating_sub(1));
            persist_watermark(db, new_wm)?;
            self.persisted_watermark.store(new_wm, Ordering::SeqCst);
        }

        self.current.store(next, Ordering::SeqCst);
        Ok(next)
    }

    fn reset_after_restore(&self, new_current: u64, new_watermark: u64) -> AppResult<()> {
        let _guard = self
            .lease_guard
            .lock()
            .map_err(|_| AppError::internal("netmap version lease mutex poisoned"))?;
        self.current.store(new_current, Ordering::SeqCst);
        self.persisted_watermark
            .store(new_watermark, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(test)]
    fn exhaust_lease_to_watermark_for_test(&self) {
        if let Ok(_guard) = self.lease_guard.lock() {
            let wm = self.persisted_watermark.load(Ordering::SeqCst);
            self.current.store(wm, Ordering::SeqCst);
        }
    }
}

/// Outcome returned from revoking or expiring a node (`US-029`, Gate 2 policy (b)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeStoreOutcome {
    /// Target node UUID.
    pub node_id: NodeId,
    /// Durability tier achieved (`Redb`, `EmergencySlot`, or `RamOnly`).
    pub persistence_tier: PersistenceTier,
    /// Newly allocated monotonic `netmap_version`, or `None` if dual `EIO` hit exhausted lease.
    pub netmap_version: Option<u64>,
    /// True when lease exhaustion under `EIO` prevented persisting a new `netmap_version`; callers
    /// must close connected peers' control streams to force full reconnect & re-auth.
    pub must_disconnect_all_peers_to_reauth: bool,
    /// Updated node record when primary `redb` succeeded.
    pub record: Option<StoredNodeRecord>,
}

/// Lightweight in-memory node directory record kept synchronized with `control.redb`
/// so immediate revocations avoid blocking on or failing under `redb` read I/O (`HR-W21-04`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDirectoryEntry {
    /// Stable UUIDv7 node identifier.
    pub node_id: NodeId,
    /// Validated RFC 1123 node hostname label.
    pub node_name: String,
    /// WireGuard static Curve25519 public key bytes.
    pub pubkey: [u8; 32],
    /// Lifecycle status tracked in RAM (`Active`, `Expired`, `Revoked`).
    pub status: NodeStatus,
}

#[derive(Debug, Default)]
struct RamDirectory {
    nodes_by_id: HashMap<NodeId, NodeDirectoryEntry>,
    node_id_by_name: HashMap<String, NodeId>,
    known_preauth_keys: HashSet<KeyId>,
    preauth_id_by_hash: HashMap<[u8; 32], KeyId>,
}

impl RamDirectory {
    fn upsert_node(&mut self, rec: &StoredNodeRecord) {
        let new_lower = rec.node_name.to_ascii_lowercase();
        if let Some(prev) = self.nodes_by_id.get(&rec.node_id) {
            let prev_lower = prev.node_name.to_ascii_lowercase();
            if prev_lower != new_lower
                && self.node_id_by_name.get(&prev_lower) == Some(&rec.node_id)
            {
                self.node_id_by_name.remove(&prev_lower);
            }
        }
        if rec.status != NodeStatus::Revoked || !self.node_id_by_name.contains_key(&new_lower) {
            self.node_id_by_name.insert(new_lower, rec.node_id);
        }
        self.nodes_by_id.insert(
            rec.node_id,
            NodeDirectoryEntry {
                node_id: rec.node_id,
                node_name: rec.node_name.clone(),
                pubkey: rec.pubkey,
                status: rec.status,
            },
        );
    }

    fn remove_node(&mut self, node_id: NodeId) {
        if let Some(prev) = self.nodes_by_id.remove(&node_id) {
            let prev_lower = prev.node_name.to_ascii_lowercase();
            if self.node_id_by_name.get(&prev_lower) == Some(&node_id) {
                self.node_id_by_name.remove(&prev_lower);
            }
        }
    }

    fn mark_status(&mut self, node_id: NodeId, status: NodeStatus) {
        if let Some(entry) = self.nodes_by_id.get_mut(&node_id)
            && (status == NodeStatus::Revoked || entry.status != NodeStatus::Revoked)
        {
            entry.status = status;
        }
    }

    fn insert_preauth_key(&mut self, key_id: KeyId, token_hash: [u8; 32]) {
        self.known_preauth_keys.insert(key_id);
        self.preauth_id_by_hash.insert(token_hash, key_id);
    }

    fn resolve_node(&self, target_ref: &str) -> Option<NodeDirectoryEntry> {
        let trimmed = target_ref.trim();
        if let Ok(node_id) = trimmed.parse::<NodeId>() {
            return self.nodes_by_id.get(&node_id).cloned();
        }
        let lower = trimmed.to_ascii_lowercase();
        self.node_id_by_name
            .get(&lower)
            .and_then(|id| self.nodes_by_id.get(id))
            .cloned()
    }
}

/// Primary ACID storage facade backed by `redb` (`control.redb`) + emergency `64 KiB` A/B log.
pub struct ControlStore {
    config: ControlStoreConfig,
    clock: Arc<dyn Clock>,
    db_lock: RwLock<Option<Database>>,
    versions: MonotonicNetmapVersion,
    emergency_state: Mutex<EmergencyRevocationState>,
    revoked_ram: RwLock<RevokedSet>,
    ram_dir: RwLock<RamDirectory>,
    emergency_backend: Arc<dyn EmergencyFileBackend>,
    inject_redb_read_failure: AtomicBool,
    inject_redb_write_failure: AtomicBool,
}

impl std::fmt::Debug for ControlStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlStore")
            .field("db_path", &self.config.db_path)
            .field("emergency_path", &self.config.emergency_revocations_path)
            .field("netmap_version", &self.versions.current())
            .field("persisted_watermark", &self.versions.persisted_watermark())
            .field("disk_degraded", &self.is_disk_degraded())
            .finish()
    }
}

impl ControlStore {
    /// Opens or initializes the primary `redb` database with fail-closed emergency checks.
    pub fn open(config: ControlStoreConfig) -> AppResult<Self> {
        Self::open_with_clock(config, DEFAULT_OVERLAY_CIDR, Arc::new(SystemClock::new()))
    }

    /// Opens [`ControlStore`] with explicit overlay CIDR configuration and injected [`Clock`].
    pub fn open_with_clock(
        config: ControlStoreConfig,
        overlay_cidr: &str,
        clock: Arc<dyn Clock>,
    ) -> AppResult<Self> {
        Self::open_with_backend(
            config,
            overlay_cidr,
            clock,
            Arc::new(OsEmergencyFileBackend),
        )
    }

    /// Internal constructor allowing deterministic backend injection in tests.
    pub fn open_with_backend(
        config: ControlStoreConfig,
        overlay_cidr: &str,
        clock: Arc<dyn Clock>,
        emergency_backend: Arc<dyn EmergencyFileBackend>,
    ) -> AppResult<Self> {
        let now_ms = clock.now_unix_ms();
        let redb_existed = config.db_path.exists();

        let (emergency_state, mut initial_ram) = EmergencyRevocationState::boot_open_with_backend(
            config.emergency_revocations_path.clone(),
            redb_existed,
            emergency_backend.as_ref(),
        )?;

        if let Some(parent) = config.db_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                AppError::unavailable(format!("failed creating db directory: {err}"))
            })?;
            restrict_dir_0700(parent)?;
        }

        let db = if redb_existed {
            Database::open(&config.db_path).map_err(|e| map_store_err("open control.redb", e))?
        } else {
            Database::create(&config.db_path)
                .map_err(|e| map_store_err("create control.redb", e))?
        };
        restrict_file_0600(&config.db_path)?;

        let backup_dir = default_backup_dir(&config.db_path);
        let (boot_current, boot_watermark) = initialize_or_migrate_db(
            &db,
            overlay_cidr,
            &backup_dir,
            now_ms,
            emergency_state.min_netmap_version,
        )?;
        let mut initial_dir = RamDirectory::default();
        populate_ram_caches_from_db(&db, &mut initial_ram, &mut initial_dir)?;

        let store = Self {
            config,
            clock,
            db_lock: RwLock::new(Some(db)),
            versions: MonotonicNetmapVersion::new(boot_current, boot_watermark),
            emergency_state: Mutex::new(emergency_state),
            revoked_ram: RwLock::new(initial_ram),
            ram_dir: RwLock::new(initial_dir),
            emergency_backend,
            inject_redb_read_failure: AtomicBool::new(false),
            inject_redb_write_failure: AtomicBool::new(false),
        };

        if store.has_pending_compactions()
            && let Err(err) = store.try_compact_emergency_revocations()
        {
            tracing::warn!(
                component = "mesh-store",
                event = "startup_emergency_compaction_deferred",
                error = %err,
                "deferred startup emergency compaction; database remains degraded until recovery"
            );
        }
        Ok(store)
    }

    /// Returns store path configuration.
    #[must_use]
    pub const fn config(&self) -> &ControlStoreConfig {
        &self.config
    }

    /// Returns the store's [`Clock`].
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Returns current monotonic `netmap_version`.
    #[must_use]
    pub fn current_netmap_version(&self) -> u64 {
        self.versions.current()
    }

    /// Returns highest persisted `netmap_version` watermark leased to this server epoch.
    #[must_use]
    pub fn persisted_watermark(&self) -> u64 {
        self.versions.persisted_watermark()
    }

    /// Returns `true` when storage is in degraded disk mode (unmerged emergency revocations exist).
    #[must_use]
    pub fn is_disk_degraded(&self) -> bool {
        self.emergency_state
            .lock()
            .map(|s| s.disk_degraded)
            .unwrap_or(true)
    }

    /// Returns non-secret degradation message if [`Self::is_disk_degraded`] is `true`.
    #[must_use]
    pub fn degraded_reason(&self) -> Option<String> {
        self.emergency_state
            .lock()
            .ok()
            .and_then(|s| s.degraded_reason.clone())
    }

    /// Checks database readability across all 9 canonical tables and metadata invariants.
    pub fn check_integrity(&self) -> AppResult<()> {
        self.with_db_read_checked(|db| {
            let rtx = db
                .begin_read()
                .map_err(|e| map_store_err("begin check_integrity read tx", e))?;
            verify_all_tables_readable(&rtx)?;
            let meta = rtx
                .open_table(TABLE_SCHEMA_META)
                .map_err(|e| map_store_err("open meta integrity", e))?;
            let ver_guard = meta
                .get(META_KEY_SCHEMA_VERSION)
                .map_err(|e| map_store_err("get schema_version integrity", e))?
                .ok_or_else(|| AppError::internal("missing schema_version row"))?;
            let rec: SchemaVersionRecord = decode_envelope(ver_guard.value())?;
            if rec.version != SCHEMA_VERSION {
                return Err(AppError::internal("unexpected schema_version"));
            }
            Ok(())
        })
    }

    /// Fast hot-path lock-friendly RAM check whether `node_id` is blocked (`Revoked` OR `Expired`).
    #[must_use]
    pub fn is_node_revoked_ram(&self, node_id: NodeId) -> bool {
        self.revoked_ram
            .read()
            .map(|set| set.contains(node_id))
            .unwrap_or(true)
    }

    /// Fast hot-path RAM check whether `node_id` is permanently revoked (`NodeStatus::Revoked`).
    #[must_use]
    pub fn is_node_permanently_revoked_ram(&self, node_id: NodeId) -> bool {
        self.revoked_ram
            .read()
            .map(|set| set.is_permanently_revoked(node_id))
            .unwrap_or(true)
    }

    /// Fast hot-path RAM check whether `node_id` is blocked strictly due to `NodeStatus::Expired`.
    #[must_use]
    pub fn is_node_expired_ram(&self, node_id: NodeId) -> bool {
        self.revoked_ram
            .read()
            .map(|set| set.is_expired(node_id))
            .unwrap_or(false)
    }

    /// Fast hot-path RAM check whether `pubkey` belongs to a revoked node.
    #[must_use]
    pub fn is_pubkey_revoked_ram(&self, pubkey: &PublicKey) -> bool {
        self.revoked_ram
            .read()
            .map(|set| set.contains_pubkey(pubkey))
            .unwrap_or(true)
    }

    /// Fast hot-path RAM check whether `key_id` has been revoked.
    #[must_use]
    pub fn is_key_revoked_ram(&self, key_id: KeyId) -> bool {
        self.revoked_ram
            .read()
            .map(|set| set.contains_key(key_id))
            .unwrap_or(true)
    }

    /// Looks up a node entry from the in-memory directory without touching `redb` (`HR-W21-04`).
    #[must_use]
    pub fn lookup_node_ram_by_id(&self, node_id: NodeId) -> Option<NodeDirectoryEntry> {
        self.ram_dir
            .read()
            .ok()
            .and_then(|dir| dir.nodes_by_id.get(&node_id).cloned())
    }

    /// Resolves a node UUID or RFC 1123 name from the in-memory directory without touching `redb`.
    #[must_use]
    pub fn resolve_node_ram(&self, target_ref: &str) -> Option<NodeDirectoryEntry> {
        self.ram_dir
            .read()
            .ok()
            .and_then(|dir| dir.resolve_node(target_ref))
    }

    /// Configures simulated `redb` read/write I/O failure flags for Dual-`EIO` testing (`IMP-W21-01`).
    #[doc(hidden)]
    pub fn inject_redb_failure(&self, read_fail: bool, write_fail: bool) {
        self.inject_redb_read_failure
            .store(read_fail, Ordering::SeqCst);
        self.inject_redb_write_failure
            .store(write_fail, Ordering::SeqCst);
    }

    /// Idempotently loads or initializes the server TLS identity (`US-047 AC3`, `US-051 AC5`).
    pub fn ensure_or_init_identity(
        &self,
        san_ips_and_hosts: &[String],
        valid_days: u32,
    ) -> AppResult<ServerIdentity> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_read(|db| {
            IdentityRepository::ensure_or_init_identity(db, san_ips_and_hosts, valid_days, now_ms)
        })
    }

    /// Loads active server TLS identity.
    pub fn load_active_identity(&self) -> AppResult<ServerIdentity> {
        self.with_db_read_checked(IdentityRepository::load_active)
    }

    /// Re-issues leaf server cert reusing active keypair so `spki_pin` remains unchanged.
    pub fn reissue_cert_same_key(
        &self,
        san_ips_and_hosts: &[String],
        valid_days: u32,
        actor: &str,
    ) -> AppResult<ServerIdentity> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_write_checked(|db| {
            IdentityRepository::reissue_cert_same_key(
                db,
                san_ips_and_hosts,
                valid_days,
                now_ms,
                actor,
            )
        })
    }

    /// Stages next server keypair (`US-047 AC5` Step 1) and advances `netmap_version`.
    pub fn stage_next_identity(
        &self,
        san_ips_and_hosts: &[String],
        valid_days: u32,
        actor: &str,
    ) -> AppResult<(ServerIdentity, u64)> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_write_checked(|db| {
            let id = IdentityRepository::stage_next_identity(
                db,
                san_ips_and_hosts,
                valid_days,
                now_ms,
                actor,
            )?;
            let ver = self
                .versions
                .allocate_next(db, self.inject_redb_write_failure.load(Ordering::SeqCst))?;
            Ok((id, ver))
        })
    }

    /// Activates staged replacement identity (`US-047 AC5` Step 2) and advances `netmap_version`.
    pub fn activate_staged_identity(
        &self,
        grace_window_ms: u64,
        actor: &str,
    ) -> AppResult<(ServerIdentity, u64)> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_write_checked(|db| {
            let id =
                IdentityRepository::activate_staged_identity(db, grace_window_ms, now_ms, actor)?;
            let ver = self
                .versions
                .allocate_next(db, self.inject_redb_write_failure.load(Ordering::SeqCst))?;
            Ok((id, ver))
        })
    }

    /// Persists a CA-issued certificate chain preserving the existing key (`US-047`).
    pub fn save_ca_issued_cert(
        &self,
        cert_chain_der: Vec<Vec<u8>>,
        not_after_ms: u64,
        actor: &str,
    ) -> AppResult<ServerIdentity> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_write_checked(|db| {
            IdentityRepository::save_ca_issued_cert(db, cert_chain_der, not_after_ms, now_ms, actor)
        })
    }

    /// Persists serialized ACME account credentials inside the ACID store (`US-047`).
    pub fn save_acme_account_json(&self, credentials_json: &str) -> AppResult<()> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_write_checked(|db| {
            IdentityRepository::save_acme_account_json(db, credentials_json, now_ms)
        })
    }

    /// Loads persisted ACME account credentials if present (`US-047`).
    pub fn load_acme_account(&self) -> AppResult<Option<AcmeAccountCredentialsBox>> {
        self.with_db_read_checked(IdentityRepository::load_acme_account)
    }

    /// Creates a new hashed pre-authentication key (`US-002`).
    pub fn create_preauth_key(
        &self,
        input: &CreatePreAuthKeyInput,
        actor: &str,
    ) -> AppResult<StoredPreAuthKeyRecord> {
        let rec = self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write create_preauth_key", e))?;
            let rec = KeysRepository::create_key_in_tx(&tx, input, actor)?;
            tx.commit()
                .map_err(|e| map_store_err("commit create_preauth_key", e))?;
            Ok(rec)
        })?;
        if let Ok(mut dir) = self.ram_dir.write() {
            dir.insert_preauth_key(rec.key_id, rec.token_hash);
        }
        Ok(rec)
    }

    /// Revokes a pre-authentication key (`HR-W21-04`): locks RAM immediately before disk/fallback
    /// I/O, rolling back RAM ONLY if primary healthy `redb` definitively reports `NotFound`.
    pub fn revoke_preauth_key(&self, key_id: KeyId, actor: &str) -> AppResult<PersistenceTier> {
        let now_ms = self.clock.now_unix_ms();
        let was_revoked_in_ram = {
            let mut ram = self
                .revoked_ram
                .write()
                .map_err(|_| AppError::internal("revoked ram lock poisoned"))?;
            let prev = ram.contains_key(key_id);
            ram.insert_key(key_id);
            prev
        };

        let primary_res = self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write revoke_key", e))?;
            let revoked_rec = KeysRepository::revoke_key_in_tx(&tx, key_id, now_ms, actor)?;
            tx.commit()
                .map_err(|e| map_store_err("commit revoke_key", e))?;
            Ok(revoked_rec)
        });

        match primary_res {
            Ok(_revoked_rec) => Ok(PersistenceTier::Redb),
            Err(err)
                if matches!(
                    err.kind(),
                    mesh_core::ErrorKind::NotFound
                        | mesh_core::ErrorKind::Conflict
                        | mesh_core::ErrorKind::InvalidArgument
                ) =>
            {
                if !was_revoked_in_ram && let Ok(mut ram) = self.revoked_ram.write() {
                    ram.remove_key_for_rollback(key_id);
                }
                Err(err)
            }
            Err(err) => {
                let reason = err.to_string();
                AuditRepository::emit_fallback_log(
                    &AuditEventInput {
                        occurred_at_ms: now_ms,
                        actor,
                        action: "preauth_key_revoked",
                        target: &key_id.to_string(),
                        outcome: "degraded",
                        metadata: json!({ "fallback": "emergency" }),
                    },
                    &reason,
                );
                let mut state = self
                    .emergency_state
                    .lock()
                    .map_err(|_| AppError::internal("emergency state mutex poisoned"))?;
                let mut ram = self
                    .revoked_ram
                    .write()
                    .map_err(|_| AppError::internal("revoked ram lock poisoned"))?;
                Ok(state.record_emergency_key(
                    &mut ram,
                    EmergencyRevocationKeyEntry {
                        key_id,
                        revoked_at_ms: now_ms,
                        tier: PersistenceTier::EmergencySlot,
                    },
                    &reason,
                    self.emergency_backend.as_ref(),
                ))
            }
        }
    }

    /// Lists all pre-authentication keys (`US-002`).
    pub fn list_preauth_keys(&self) -> AppResult<Vec<StoredPreAuthKeyRecord>> {
        self.with_db_read_checked(KeysRepository::list_keys)
    }

    /// Registers or idempotently refreshes a node in a single ACID `WriteTransaction` (`US-004`,
    /// `US-005`) and returns `(RegisterNodeOutcome, netmap_version)`.
    pub fn register_node(
        &self,
        input: &RegisterNodeInput<'_>,
    ) -> AppResult<(RegisterNodeOutcome, u64)> {
        if self.is_pubkey_revoked_ram(&input.pubkey) {
            return Err(AppError::unauthenticated(
                "public key is present in in-memory revocation set",
            ));
        }
        let hashed_key_id = self.ram_dir.read().ok().and_then(|dir| {
            dir.preauth_id_by_hash
                .get(&input.preauth_token_hash)
                .copied()
        });
        if let Some(kid) = hashed_key_id
            && self.is_key_revoked_ram(kid)
        {
            return Err(AppError::unauthenticated(
                "pre-auth key is present in in-memory revocation set",
            ));
        }
        let (outcome, ver) = self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write register_node", e))?;
            let outcome = NodesRepository::register_node_in_tx(&tx, input)?;
            tx.commit()
                .map_err(|e| map_store_err("commit register_node", e))?;
            let ver = if outcome.state_changed {
                self.versions.allocate_next(db, false)?
            } else {
                self.versions.current()
            };
            Ok((outcome, ver))
        })?;

        if let Ok(mut ram) = self.revoked_ram.write() {
            if let Some(old_pk) = outcome.replaced_pubkey {
                ram.insert_rotated_pubkey(&old_pk);
            }
            if outcome.record.status == NodeStatus::Active {
                ram.clear_expired_node(outcome.record.node_id);
            }
        }
        if outcome.record.status == NodeStatus::Active
            && let Ok(mut state) = self.emergency_state.lock()
        {
            let cleared = state.clear_pending_expired_node(
                outcome.record.node_id,
                self.emergency_backend.as_ref(),
            );
            if cleared {
                tracing::info!(
                    component = "mesh-store",
                    event = "cleared_pending_expired_node",
                    node_id = %outcome.record.node_id,
                    "cleared expired emergency entry after valid node renewal"
                );
            }
        }
        if let Ok(mut dir) = self.ram_dir.write() {
            dir.upsert_node(&outcome.record);
        }
        Ok((outcome, ver))
    }

    /// Updates a node's ICE/STUN candidate endpoints; bumps `netmap_version` ONLY if changed.
    pub fn update_node_endpoints(
        &self,
        node_id: NodeId,
        endpoints: Vec<CandidateEndpoint>,
    ) -> AppResult<(StoredNodeRecord, Option<u64>)> {
        if self.is_node_revoked_ram(node_id) {
            return Err(AppError::unauthenticated("node revoked in RAM"));
        }
        let now_ms = self.clock.now_unix_ms();
        self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write update_endpoints", e))?;
            let (rec, changed) =
                NodesRepository::update_endpoints_in_tx(&tx, node_id, endpoints, now_ms)?;
            tx.commit()
                .map_err(|e| map_store_err("commit update_endpoints", e))?;
            let maybe_ver = if changed {
                Some(self.versions.allocate_next(db, false)?)
            } else {
                None
            };
            Ok((rec, maybe_ver))
        })
    }

    /// Renames a node and allocates a new `netmap_version` (`US-012`).
    pub fn rename_node(
        &self,
        node_id: NodeId,
        new_name: NodeName,
        public_host: &str,
        domain_suffix: &str,
    ) -> AppResult<(StoredNodeRecord, u64)> {
        let now_ms = self.clock.now_unix_ms();
        let (rec, ver) = self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write rename_node", e))?;
            let rec = NodesRepository::rename_node_in_tx(
                &tx,
                node_id,
                new_name,
                public_host,
                domain_suffix,
                now_ms,
            )?;
            tx.commit()
                .map_err(|e| map_store_err("commit rename_node", e))?;
            let ver = self.versions.allocate_next(db, false)?;
            Ok((rec, ver))
        })?;
        if let Ok(mut dir) = self.ram_dir.write() {
            dir.upsert_node(&rec);
        }
        Ok((rec, ver))
    }

    /// Immediately revokes `node_id` (`US-029`), falling back across `Redb -> EmergencySlot ->
    /// RamOnly` and obeying Gate 2 policy (b) when dual `EIO` collides with an exhausted lease.
    pub fn revoke_node(&self, node_id: NodeId, actor: &str) -> AppResult<RevokeStoreOutcome> {
        self.revoke_or_expire_node_with_hook(node_id, actor, false, |_, _| {})
    }

    /// Immediately revokes `node_id`, invoking `on_ram_locked` right after locking `revoked_ram`
    /// and BEFORE touching disk (`redb` / `EmergencySlot`) so active streams sever in `< 100 ms`
    /// (`HR-W21-04`).
    pub fn revoke_node_with_hook<F>(
        &self,
        node_id: NodeId,
        actor: &str,
        on_ram_locked: F,
    ) -> AppResult<RevokeStoreOutcome>
    where
        F: FnOnce(NodeId, Option<PublicKey>),
    {
        self.revoke_or_expire_node_with_hook(node_id, actor, false, on_ram_locked)
    }

    /// Marks `node_id` key expired (`US-031`), enforcing the exact same `EIO` failover guarantees.
    pub fn expire_node(&self, node_id: NodeId, actor: &str) -> AppResult<RevokeStoreOutcome> {
        self.revoke_or_expire_node_with_hook(node_id, actor, true, |_, _| {})
    }

    /// Marks `node_id` key expired (`US-031`), invoking `on_ram_locked` immediately after RAM
    /// revocation lock and BEFORE any disk write (`HR-W21-04`).
    pub fn expire_node_with_hook<F>(
        &self,
        node_id: NodeId,
        actor: &str,
        on_ram_locked: F,
    ) -> AppResult<RevokeStoreOutcome>
    where
        F: FnOnce(NodeId, Option<PublicKey>),
    {
        self.revoke_or_expire_node_with_hook(node_id, actor, true, on_ram_locked)
    }

    /// Clears node key expiry indefinitely (`--never`, `US-031 AC2`) and allocates next `netmap_version`.
    pub fn set_node_expiry_never(
        &self,
        node_id: NodeId,
        actor: &str,
    ) -> AppResult<(StoredNodeRecord, u64)> {
        let now_ms = self.clock.now_unix_ms();
        let (rec, ver) = self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write set_node_expiry_never", e))?;
            let rec = NodesRepository::set_node_expiry_never_in_tx(&tx, node_id, now_ms, actor)?;
            tx.commit()
                .map_err(|e| map_store_err("commit set_node_expiry_never", e))?;
            let ver = self.versions.allocate_next(db, false)?;
            Ok((rec, ver))
        })?;
        if let Ok(mut dir) = self.ram_dir.write() {
            dir.upsert_node(&rec);
        }
        Ok((rec, ver))
    }

    /// Allocates and persists the next monotonic `netmap_version` (e.g., for endpoint migration).
    pub fn allocate_next_netmap_version(&self) -> AppResult<u64> {
        self.with_db_read(|db| {
            self.versions
                .allocate_next(db, self.inject_redb_write_failure.load(Ordering::SeqCst))
        })
    }

    /// Records node activity timestamp without advancing `netmap_version` (`US-006`, `US-009`).
    pub fn touch_node_last_seen(&self, node_id: NodeId) -> AppResult<()> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_read(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write touch_node_last_seen", e))?;
            let _touched = NodesRepository::touch_last_seen_in_tx(&tx, node_id, now_ms)?;
            tx.commit()
                .map_err(|e| map_store_err("commit touch_node_last_seen", e))?;
            Ok(())
        })
    }

    /// Reaps offline ephemeral nodes past their idle timeout, freeing IPs and bumping Netmap (`US-006`).
    pub fn reap_expired_ephemeral_nodes<F>(
        &self,
        default_timeout_secs: u32,
        is_online: F,
        actor: &str,
    ) -> AppResult<(Vec<StoredNodeRecord>, Option<u64>)>
    where
        F: Fn(NodeId) -> bool,
    {
        let now_ms = self.clock.now_unix_ms();
        let (reaped, maybe_ver) = self.with_db_write_checked(|db| {
            let nodes = NodesRepository::list_nodes(db)?;
            let candidates: Vec<(NodeId, u32)> = nodes
                .into_iter()
                .filter(|n| {
                    if !n.ephemeral || n.status != NodeStatus::Active || is_online(n.node_id) {
                        return false;
                    }
                    let timeout_secs = n.ephemeral_timeout_secs.unwrap_or(default_timeout_secs);
                    let threshold_ms = u64::from(timeout_secs).saturating_mul(1_000);
                    now_ms.saturating_sub(n.last_seen_at_ms) >= threshold_ms
                })
                .map(|n| {
                    (
                        n.node_id,
                        n.ephemeral_timeout_secs.unwrap_or(default_timeout_secs),
                    )
                })
                .collect();
            if candidates.is_empty() {
                return Ok((Vec::new(), None));
            }

            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write reap_ephemeral_nodes", e))?;
            let mut reaped = Vec::with_capacity(candidates.len());
            for (node_id, timeout_secs) in candidates {
                if is_online(node_id) {
                    continue;
                }
                if let Some(rec) = NodesRepository::reap_ephemeral_node_in_tx(
                    &tx,
                    node_id,
                    now_ms,
                    timeout_secs,
                    actor,
                )? {
                    reaped.push(rec);
                }
            }
            if reaped.is_empty() {
                tx.abort()
                    .map_err(|e| map_store_err("abort empty reap_ephemeral_nodes", e))?;
                return Ok((Vec::new(), None));
            }
            tx.commit()
                .map_err(|e| map_store_err("commit reap_ephemeral_nodes", e))?;
            let ver = self.versions.allocate_next(db, false)?;
            Ok((reaped, Some(ver)))
        })?;
        if !reaped.is_empty()
            && let Ok(mut dir) = self.ram_dir.write()
        {
            for rec in &reaped {
                dir.remove_node(rec.node_id);
            }
        }
        Ok((reaped, maybe_ver))
    }

    /// Reclaims overlay IPs whose 24h post-revoke/expiry quarantine has elapsed (`US-029 AC5`).
    pub fn reclaim_expired_quarantines(&self) -> AppResult<Vec<OverlayIp>> {
        let now_ms = self.clock.now_unix_ms();
        self.with_db_write_checked(|db| {
            let has_due = NodesRepository::list_nodes(db)?.into_iter().any(|n| {
                n.status != NodeStatus::Active
                    && n.overlay_ip.is_some()
                    && n.quarantine_until_ms.unwrap_or(0) <= now_ms
            });
            if !has_due {
                return Ok(Vec::new());
            }
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write reclaim_quarantines", e))?;
            let reclaimed = NodesRepository::reclaim_expired_quarantines_in_tx(&tx, now_ms)?;
            tx.commit()
                .map_err(|e| map_store_err("commit reclaim_quarantines", e))?;
            Ok(reclaimed)
        })
    }

    /// Sweeps active nodes whose `key_expires_at_ms <= now`, transitioning them cleanly.
    pub fn sweep_expired_nodes(&self) -> AppResult<Vec<RevokeStoreOutcome>> {
        let now_ms = self.clock.now_unix_ms();
        let candidates: Vec<NodeId> = self
            .list_nodes()?
            .into_iter()
            .filter(|n| n.status == NodeStatus::Active && n.is_key_expired_at(now_ms))
            .map(|n| n.node_id)
            .collect();

        let mut outcomes = Vec::with_capacity(candidates.len());
        for node_id in candidates {
            outcomes.push(self.expire_node(node_id, "system:expiry_sweeper")?);
        }
        Ok(outcomes)
    }

    /// Merges ALL unmerged revocations from [`EmergencyRevocationState`] (including BOTH
    /// `EmergencySlot` AND `RamOnly` entries — Gate 2 policy (a)) into `control.redb`, and only
    /// clears `disk_degraded` after `redb::WriteTransaction::commit` succeeds.
    ///
    /// Returns `Ok(Some(new_netmap_version))` when compaction committed changes so callers can
    /// broadcast an updated snapshot (`HR-W21-12`), or `Ok(None)` when nothing was pending.
    pub fn try_compact_emergency_revocations(&self) -> AppResult<Option<u64>> {
        if self.inject_redb_read_failure.load(Ordering::SeqCst)
            || self.inject_redb_write_failure.load(Ordering::SeqCst)
        {
            return Err(AppError::unavailable(
                "primary redb still failing; deferring emergency compaction",
            ));
        }

        let now_ms = self.clock.now_unix_ms();
        self.with_db_read(|db| {
            let mut state = self
                .emergency_state
                .lock()
                .map_err(|_| AppError::internal("emergency state mutex poisoned"))?;
            if !state.has_unmerged_entries() && !state.disk_degraded {
                return Ok(None);
            }

            let pending_nodes = state.pending_nodes.clone();
            let pending_keys = state.pending_keys.clone();

            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write emergency compaction", e))?;
            for entry in &pending_nodes {
                NodesRepository::apply_compacted_revocation_in_tx(
                    &tx,
                    entry.node_id,
                    entry.pubkey_bytes,
                    entry.revoked_at_ms,
                    entry.reason == EmergencyNodeReason::Expired,
                )?;
            }
            for k in &pending_keys {
                if KeysRepository::revoke_key_in_tx(
                    &tx,
                    k.key_id,
                    k.revoked_at_ms,
                    "system:compact",
                )
                .is_err()
                {
                    tracing::warn!(
                        component = "mesh-store",
                        event = "compact_missing_preauth_key",
                        key_id = %k.key_id,
                        "pre-auth key missing during emergency compaction"
                    );
                }
            }
            let summary_audit = AuditEventInput {
                occurred_at_ms: now_ms,
                actor: "system:compactor",
                action: "emergency_revocations_compacted",
                target: "server",
                outcome: "success",
                metadata: json!({
                    "nodes_compacted": pending_nodes.len(),
                    "keys_compacted": pending_keys.len(),
                }),
            };
            AuditRepository::append_audit_in_tx(&tx, &summary_audit)?;
            tx.commit()
                .map_err(|e| map_store_err("commit emergency compaction", e))?;

            let ver = self.versions.allocate_next(db, false)?;
            state.finalize_compaction_after_redb_commit(
                self.versions.persisted_watermark(),
                self.emergency_backend.as_ref(),
            )?;
            if let Ok(mut dir) = self.ram_dir.write() {
                for entry in &pending_nodes {
                    let target_status = match entry.reason {
                        EmergencyNodeReason::Revoked => NodeStatus::Revoked,
                        EmergencyNodeReason::Expired => NodeStatus::Expired,
                    };
                    dir.mark_status(entry.node_id, target_status);
                }
            }
            Ok(Some(ver))
        })
    }

    /// Reads the overlay IPv4 CIDR currently stored in `redb`.
    pub fn load_overlay_cidr(&self) -> AppResult<OverlayCidr> {
        self.with_db_read_checked(NodesRepository::load_overlay_cidr)
    }

    /// Lists all registered node records.
    pub fn list_nodes(&self) -> AppResult<Vec<StoredNodeRecord>> {
        self.with_db_read_checked(NodesRepository::list_nodes)
    }

    /// Finds a node by [`NodeId`].
    pub fn find_node_by_id(&self, node_id: NodeId) -> AppResult<Option<StoredNodeRecord>> {
        self.with_db_read_checked(|db| NodesRepository::find_by_id(db, node_id))
    }

    /// Finds a node by [`PublicKey`].
    pub fn find_node_by_pubkey(&self, pubkey: &PublicKey) -> AppResult<Option<StoredNodeRecord>> {
        self.with_db_read_checked(|db| NodesRepository::find_by_pubkey(db, pubkey))
    }

    /// Lists immutable security audit events in reverse chronological sequence order (`US-013`).
    pub fn list_audit_events(&self, query: &AuditQuery) -> AppResult<Vec<StoredAuditEventRecord>> {
        self.with_db_read_checked(|db| AuditRepository::list_audit_events(db, query))
    }

    /// Records an independent audit event or emits a fallback log when disk is degraded.
    pub fn record_audit_best_effort(&self, input: &AuditEventInput<'_>) {
        let res = self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write best_effort audit", e))?;
            AuditRepository::append_audit_in_tx(&tx, input)?;
            tx.commit()
                .map_err(|e| map_store_err("commit best_effort audit", e))?;
            Ok(())
        });
        if let Err(err) = res {
            AuditRepository::emit_fallback_log(input, &err.to_string());
        }
    }

    /// Creates an atomic MVCC hot backup inside `backup_dir` retaining `DEFAULT_BACKUP_RETENTION`.
    /// Any unmerged RAM / EmergencySlot revocations are folded directly into the backup snapshot
    /// (`BLK-S1-04`).
    pub fn create_backup(&self, backup_dir: &Path, actor: &str) -> AppResult<BackupArtifact> {
        let now_ms = self.clock.now_unix_ms();
        let (pending_nodes, pending_keys, emerg_min_ver) = {
            let state = self
                .emergency_state
                .lock()
                .map_err(|_| AppError::internal("emergency state mutex poisoned"))?;
            (
                state.pending_nodes.clone(),
                state.pending_keys.clone(),
                state.min_netmap_version,
            )
        };
        let min_floor = self
            .versions
            .current()
            .max(self.versions.persisted_watermark())
            .max(emerg_min_ver);

        let artifact = self.with_db_read(|db| {
            BackupManager::create_snapshot_with_emergency(
                db,
                backup_dir,
                "mesh-backup",
                now_ms,
                DEFAULT_BACKUP_RETENTION,
                EmergencySnapshotOverlay {
                    pending_nodes: &pending_nodes,
                    pending_keys: &pending_keys,
                    min_netmap_version: min_floor,
                },
            )
        })?;
        self.record_audit_best_effort(&AuditEventInput {
            occurred_at_ms: now_ms,
            actor,
            action: "backup_created",
            target: &artifact.snapshot_path.display().to_string(),
            outcome: "success",
            metadata: json!({
                "sha256": artifact.sha256_hex,
                "size_bytes": artifact.size_bytes,
                "folded_emergency_entries": pending_nodes.len().saturating_add(pending_keys.len()),
            }),
        });
        Ok(artifact)
    }

    /// Restores a verified backup snapshot into the active store, validating checksum/schema/pin
    /// before closing live DB, swapping atomically with rollback, and advancing watermark (`BLK-S1-04`).
    pub fn restore_backup(&self, mut options: RestoreOptions) -> AppResult<RestoreOutcome> {
        options.target_db_path = self.config.db_path.clone();
        options.target_emergency_path = self.config.emergency_revocations_path.clone();

        let mut db_guard = self
            .db_lock
            .write()
            .map_err(|_| AppError::internal("db rwlock poisoned for restore"))?;

        let now_ms = self.clock.now_unix_ms();
        let existing_db_wm = db_guard
            .as_ref()
            .and_then(|db| read_stored_watermark(db).ok())
            .unwrap_or(0);
        let emerg_mem_min = self
            .emergency_state
            .lock()
            .map(|s| s.min_netmap_version)
            .unwrap_or(0);
        let emerg_disk_min = crate::revoked_ram::read_slot_min_netmap_version(
            &self.config.emergency_revocations_path,
        )
        .unwrap_or(0);
        options.min_netmap_version = options
            .min_netmap_version
            .max(existing_db_wm)
            .max(self.versions.current())
            .max(self.versions.persisted_watermark())
            .max(emerg_mem_min)
            .max(emerg_disk_min)
            .max(now_ms);

        // Pre-stage and verify pin/checksum/schema BEFORE releasing live DB handle.
        let staged = BackupManager::prepare_staged_restore(&options)?;

        // Temporarily release live Database file handle so Windows & POSIX rename succeeds cleanly.
        drop(db_guard.take());

        if let Err(err) =
            BackupManager::swap_and_verify_staged_db(&staged.staged_path, &self.config.db_path)
        {
            if self.config.db_path.exists()
                && let Ok(recovered_old) = Database::open(&self.config.db_path)
            {
                *db_guard = Some(recovered_old);
            }
            return Err(err);
        }

        let reopened_db = Database::open(&self.config.db_path)
            .map_err(|e| map_store_err("reopen restored control.redb", e))?;
        BackupManager::reset_emergency_file_after_restore(
            &self.config.emergency_revocations_path,
            staged.new_netmap_watermark,
        )?;

        let (boot_cur, boot_wm) = allocate_boot_lease(&reopened_db, staged.new_netmap_watermark)?;
        self.versions.reset_after_restore(boot_cur, boot_wm)?;

        let (new_emerg, mut new_ram) = EmergencyRevocationState::boot_open_with_backend(
            self.config.emergency_revocations_path.clone(),
            true,
            self.emergency_backend.as_ref(),
        )?;
        let mut new_dir = RamDirectory::default();
        populate_ram_caches_from_db(&reopened_db, &mut new_ram, &mut new_dir)?;

        if let Ok(mut e_guard) = self.emergency_state.lock() {
            *e_guard = new_emerg;
        }
        if let Ok(mut r_guard) = self.revoked_ram.write() {
            *r_guard = new_ram;
        }
        if let Ok(mut d_guard) = self.ram_dir.write() {
            *d_guard = new_dir;
        }
        *db_guard = Some(reopened_db);

        Ok(RestoreOutcome {
            verified_sha256_hex: staged.verified_sha256_hex,
            restored_spki_pin: staged.restored_spki_pin,
            new_netmap_watermark: staged.new_netmap_watermark,
        })
    }

    fn revoke_or_expire_node_with_hook<F>(
        &self,
        node_id: NodeId,
        actor: &str,
        is_expire: bool,
        on_ram_locked: F,
    ) -> AppResult<RevokeStoreOutcome>
    where
        F: FnOnce(NodeId, Option<PublicKey>),
    {
        let now_ms = self.clock.now_unix_ms();
        let known_pubkey = self
            .lookup_node_ram_by_id(node_id)
            .map(|entry| entry.pubkey)
            .unwrap_or([0_u8; 32]);
        let pk_opt = PublicKey::from_bytes(known_pubkey)
            .ok()
            .filter(|_| known_pubkey != [0_u8; 32]);

        // Step 1 (`HR-W21-04`): Lock RAM revocation immediately before any disk I/O so auth &
        // packet paths see the block with zero wait on slow/broken `redb` or `EmergencySlot`.
        let (was_perm_revoked, was_expired, was_pk_revoked) = {
            let mut ram = self
                .revoked_ram
                .write()
                .map_err(|_| AppError::internal("revoked ram lock poisoned"))?;
            let prev = (
                ram.is_permanently_revoked(node_id),
                ram.is_expired(node_id),
                pk_opt.as_ref().is_some_and(|pk| ram.contains_pubkey(pk)),
            );
            if is_expire {
                ram.insert_expired_node_with_pubkey(node_id, pk_opt.as_ref());
            } else {
                ram.insert_node_with_pubkey(node_id, pk_opt.as_ref());
            }
            prev
        };

        // Step 2 (`HR-W21-04`): Sever active Hub sessions immediately (< 100 ms) BEFORE disk I/O.
        on_ram_locked(node_id, pk_opt);

        // Step 3: Attempt durable persistence into primary `redb`.
        let primary_res = self.with_db_write_checked(|db| {
            let tx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write revoke/expire node", e))?;
            let rec = if is_expire {
                NodesRepository::expire_node_in_tx(&tx, node_id, now_ms, actor)?
            } else {
                NodesRepository::revoke_node_in_tx(&tx, node_id, now_ms, actor)?
            };
            tx.commit()
                .map_err(|e| map_store_err("commit revoke/expire node", e))?;
            let ver = self.versions.allocate_next(db, false)?;
            Ok((rec, ver))
        });

        match primary_res {
            Ok((rec, netmap_ver)) => {
                if let Ok(mut ram) = self.revoked_ram.write() {
                    let rec_pk = PublicKey::from_bytes(rec.pubkey).ok();
                    if is_expire {
                        ram.insert_expired_node_with_pubkey(node_id, rec_pk.as_ref());
                    } else {
                        ram.insert_node_with_pubkey(node_id, rec_pk.as_ref());
                    }
                }
                if let Ok(mut dir) = self.ram_dir.write() {
                    dir.upsert_node(&rec);
                }
                Ok(RevokeStoreOutcome {
                    node_id,
                    persistence_tier: PersistenceTier::Redb,
                    netmap_version: Some(netmap_ver),
                    must_disconnect_all_peers_to_reauth: false,
                    record: Some(rec),
                })
            }
            Err(err)
                if matches!(
                    err.kind(),
                    mesh_core::ErrorKind::NotFound
                        | mesh_core::ErrorKind::Conflict
                        | mesh_core::ErrorKind::InvalidArgument
                ) =>
            {
                if let Ok(mut ram) = self.revoked_ram.write() {
                    ram.rollback_speculative_node(
                        node_id,
                        known_pubkey,
                        was_perm_revoked,
                        was_expired,
                        was_pk_revoked,
                    );
                }
                if err.kind() == mesh_core::ErrorKind::NotFound
                    && let Ok(mut dir) = self.ram_dir.write()
                {
                    dir.remove_node(node_id);
                }
                Err(err)
            }
            Err(err) => {
                if let Ok(mut dir) = self.ram_dir.write() {
                    dir.mark_status(
                        node_id,
                        if is_expire {
                            NodeStatus::Expired
                        } else {
                            NodeStatus::Revoked
                        },
                    );
                }
                let reason_msg = err.to_string();
                let action_str = if is_expire {
                    "node_expired"
                } else {
                    "node_revoked"
                };
                AuditRepository::emit_fallback_log(
                    &AuditEventInput {
                        occurred_at_ms: now_ms,
                        actor,
                        action: action_str,
                        target: &node_id.to_string(),
                        outcome: "degraded",
                        metadata: json!({ "fallback": "emergency" }),
                    },
                    &reason_msg,
                );

                // Allocate version ONLY within already-leased persisted watermark; if lease is
                // exhausted (`current == persisted_watermark`) while redb write failed, do NOT
                // emit an unpersisted netmap_version (`Gate 2 policy (b)`): force re-auth.
                let lease_ver = self
                    .with_db_read(|db| self.versions.allocate_next(db, true))
                    .ok();
                let min_netmap_version =
                    lease_ver.unwrap_or_else(|| self.versions.persisted_watermark());

                let entry = EmergencyRevocationNodeEntry {
                    node_id,
                    pubkey_bytes: known_pubkey,
                    revoked_at_ms: now_ms,
                    min_netmap_version,
                    reason: if is_expire {
                        EmergencyNodeReason::Expired
                    } else {
                        EmergencyNodeReason::Revoked
                    },
                    tier: PersistenceTier::EmergencySlot,
                };
                let tier = {
                    let mut state = self
                        .emergency_state
                        .lock()
                        .map_err(|_| AppError::internal("emergency state mutex poisoned"))?;
                    let mut ram = self
                        .revoked_ram
                        .write()
                        .map_err(|_| AppError::internal("revoked ram lock poisoned"))?;
                    state.record_emergency_node(
                        &mut ram,
                        entry,
                        &reason_msg,
                        self.emergency_backend.as_ref(),
                    )
                };

                Ok(RevokeStoreOutcome {
                    node_id,
                    persistence_tier: tier,
                    netmap_version: lease_ver,
                    must_disconnect_all_peers_to_reauth: lease_ver.is_none(),
                    record: None,
                })
            }
        }
    }

    fn has_pending_compactions(&self) -> bool {
        self.emergency_state
            .lock()
            .map(|s| s.has_unmerged_entries())
            .unwrap_or(false)
    }

    fn with_db_read<T>(&self, f: impl FnOnce(&Database) -> AppResult<T>) -> AppResult<T> {
        let guard = self
            .db_lock
            .read()
            .map_err(|_| AppError::internal("db rwlock poisoned"))?;
        let db = guard.as_ref().ok_or_else(|| {
            AppError::unavailable("control database temporarily closed for restore")
        })?;
        f(db)
    }

    fn with_db_read_checked<T>(&self, f: impl FnOnce(&Database) -> AppResult<T>) -> AppResult<T> {
        if self.inject_redb_read_failure.load(Ordering::SeqCst) {
            return Err(AppError::unavailable("redb read fault injected"));
        }
        self.with_db_read(f)
    }

    fn with_db_write_checked<T>(&self, f: impl FnOnce(&Database) -> AppResult<T>) -> AppResult<T> {
        if self.inject_redb_write_failure.load(Ordering::SeqCst) {
            return Err(AppError::unavailable("redb write fault injected"));
        }
        self.with_db_read(f)
    }

    #[cfg(test)]
    fn set_redb_failure_for_test(&self, fail: bool) {
        self.inject_redb_failure(fail, fail);
    }

    #[cfg(test)]
    fn exhaust_lease_for_test(&self) {
        self.versions.exhaust_lease_to_watermark_for_test();
    }
}

fn initialize_or_migrate_db(
    db: &Database,
    overlay_cidr: &str,
    backup_dir: &Path,
    now_ms: u64,
    min_floor: u64,
) -> AppResult<(u64, u64)> {
    {
        let wtx = db
            .begin_write()
            .map_err(|e| map_store_err("begin write init tables", e))?;
        ensure_all_tables(&wtx)?;
        wtx.commit()
            .map_err(|e| map_store_err("commit init tables", e))?;
    }

    let existing_ver = {
        let rtx = db
            .begin_read()
            .map_err(|e| map_store_err("read schema_version", e))?;
        let meta = rtx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open meta read schema_version", e))?;
        meta.get(META_KEY_SCHEMA_VERSION)
            .map_err(|e| map_store_err("get schema_version", e))?
            .map(|g| decode_envelope::<SchemaVersionRecord>(g.value()))
            .transpose()?
    };

    match existing_ver {
        None => {
            let wtx = db
                .begin_write()
                .map_err(|e| map_store_err("begin write bootstrap schema", e))?;
            {
                let mut meta = wtx
                    .open_table(TABLE_SCHEMA_META)
                    .map_err(|e| map_store_err("open meta write schema_version", e))?;
                let rec = SchemaVersionRecord {
                    version: SCHEMA_VERSION,
                    updated_at_ms: now_ms,
                };
                meta.insert(META_KEY_SCHEMA_VERSION, encode_envelope(&rec)?.as_slice())
                    .map_err(|e| map_store_err("insert schema_version", e))?;
            }
            NodesRepository::set_overlay_cidr_in_tx(&wtx, overlay_cidr, now_ms, "system")?;
            wtx.commit()
                .map_err(|e| map_store_err("commit bootstrap schema", e))?;
        }
        Some(rec) => {
            if rec.version > SCHEMA_VERSION {
                return Err(AppError::invalid_argument(format!(
                    "database schema version {} exceeds supported version {SCHEMA_VERSION}",
                    rec.version
                )));
            }
            if rec.version < SCHEMA_VERSION {
                BackupManager::create_pre_migration_snapshot(db, backup_dir, rec.version, now_ms)?;
                let wtx = db
                    .begin_write()
                    .map_err(|e| map_store_err("begin write schema migration", e))?;
                {
                    let mut meta = wtx
                        .open_table(TABLE_SCHEMA_META)
                        .map_err(|e| map_store_err("open meta migration", e))?;
                    let upgraded = SchemaVersionRecord {
                        version: SCHEMA_VERSION,
                        updated_at_ms: now_ms,
                    };
                    meta.insert(
                        META_KEY_SCHEMA_VERSION,
                        encode_envelope(&upgraded)?.as_slice(),
                    )
                    .map_err(|e| map_store_err("update schema_version", e))?;
                }
                wtx.commit()
                    .map_err(|e| map_store_err("commit schema migration", e))?;
            }
        }
    }

    allocate_boot_lease(db, min_floor)
}

fn read_stored_watermark(db: &Database) -> AppResult<u64> {
    let rtx = db
        .begin_read()
        .map_err(|e| map_store_err("read stored watermark", e))?;
    let meta = rtx
        .open_table(TABLE_SCHEMA_META)
        .map_err(|e| map_store_err("open meta stored watermark", e))?;
    let val = match meta
        .get(META_KEY_WATERMARK)
        .map_err(|e| map_store_err("get stored watermark", e))?
    {
        Some(g) => decode_u64_be(g.value())?,
        None => 0,
    };
    Ok(val)
}

fn allocate_boot_lease(db: &Database, min_floor: u64) -> AppResult<(u64, u64)> {
    let wtx = db
        .begin_write()
        .map_err(|e| map_store_err("begin write boot lease", e))?;
    let (boot_current, boot_watermark) = {
        let mut meta = wtx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open meta boot lease", e))?;
        let stored_watermark = match meta
            .get(META_KEY_WATERMARK)
            .map_err(|e| map_store_err("read boot watermark", e))?
        {
            Some(g) => decode_u64_be(g.value())?,
            None => 0,
        };
        let prev_watermark = stored_watermark.max(min_floor);
        let next_watermark = prev_watermark
            .checked_add(VERSION_LEASE_STEP)
            .ok_or_else(|| AppError::internal("netmap watermark overflow on boot"))?;
        meta.insert(META_KEY_WATERMARK, encode_u64_be(next_watermark).as_slice())
            .map_err(|e| map_store_err("write boot watermark", e))?;
        (prev_watermark, next_watermark)
    };
    wtx.commit()
        .map_err(|e| map_store_err("commit boot lease", e))?;
    Ok((boot_current, boot_watermark))
}

fn persist_watermark(db: &Database, watermark: u64) -> AppResult<()> {
    let wtx = db
        .begin_write()
        .map_err(|e| map_store_err("begin write extend watermark", e))?;
    {
        let mut meta = wtx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open meta extend watermark", e))?;
        meta.insert(META_KEY_WATERMARK, encode_u64_be(watermark).as_slice())
            .map_err(|e| map_store_err("insert extend watermark", e))?;
    }
    wtx.commit()
        .map_err(|e| map_store_err("commit extend watermark", e))?;
    Ok(())
}

fn populate_ram_caches_from_db(
    db: &Database,
    ram: &mut RevokedSet,
    ram_dir: &mut RamDirectory,
) -> AppResult<()> {
    let rtx = db
        .begin_read()
        .map_err(|e| map_store_err("begin read populate_revoked_ram", e))?;
    let nodes = rtx
        .open_table(TABLE_NODES)
        .map_err(|e| map_store_err("open nodes populate_revoked_ram", e))?;
    for row in nodes
        .iter()
        .map_err(|e| map_store_err("iter nodes ram", e))?
    {
        let (_, val) = row.map_err(|e| map_store_err("row nodes ram", e))?;
        let rec: StoredNodeRecord = decode_envelope(val.value())?;
        ram_dir.upsert_node(&rec);
        let pk_opt = PublicKey::from_bytes(rec.pubkey).ok();
        let pk_ref = pk_opt.as_ref().filter(|_| rec.pubkey != [0_u8; 32]);
        match rec.status {
            NodeStatus::Active => {}
            NodeStatus::Revoked => ram.insert_node_with_pubkey(rec.node_id, pk_ref),
            NodeStatus::Expired => ram.insert_expired_node_with_pubkey(rec.node_id, pk_ref),
        }
    }
    let keys = rtx
        .open_table(TABLE_PREAUTH_KEYS)
        .map_err(|e| map_store_err("open keys populate_revoked_ram", e))?;
    for row in keys.iter().map_err(|e| map_store_err("iter keys ram", e))? {
        let (_, val) = row.map_err(|e| map_store_err("row keys ram", e))?;
        let rec: StoredPreAuthKeyRecord = decode_envelope(val.value())?;
        ram_dir.insert_preauth_key(rec.key_id, rec.token_hash);
        if rec.revoked_at_ms.is_some() {
            ram.insert_key(rec.key_id);
        }
    }
    Ok(())
}

fn default_backup_dir(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("backups")
}

#[cfg(unix)]
fn restrict_dir_0700(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| AppError::unavailable(format!("failed chmod 0700 {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn restrict_dir_0700(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file_0600(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| AppError::unavailable(format!("failed chmod 0600 {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn restrict_file_0600(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::AtomicBool;

    use mesh_core::FakeClock;
    use tempfile::TempDir;

    use super::*;
    use crate::RESTORE_WATERMARK_JUMP;
    use crate::nodes_repo::DEFAULT_NODE_KEY_TTL_MS;

    #[derive(Debug)]
    struct TestEmergencyBackend {
        inner: OsEmergencyFileBackend,
        fail_slot_writes: AtomicBool,
    }

    impl TestEmergencyBackend {
        fn new(fail_slot_writes: bool) -> Self {
            Self {
                inner: OsEmergencyFileBackend,
                fail_slot_writes: AtomicBool::new(fail_slot_writes),
            }
        }
    }

    impl EmergencyFileBackend for TestEmergencyBackend {
        fn exists(&self, path: &Path) -> bool {
            self.inner.exists(path)
        }

        fn file_len(&self, path: &Path) -> io::Result<u64> {
            self.inner.file_len(path)
        }

        fn create_preallocated(&self, path: &Path, full_image: &[u8]) -> io::Result<()> {
            self.inner.create_preallocated(path, full_image)
        }

        fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.inner.read_all(path)
        }

        fn write_slot_synced(&self, path: &Path, offset: u64, slot_bytes: &[u8]) -> io::Result<()> {
            if self.fail_slot_writes.load(Ordering::SeqCst) {
                return Err(io::Error::other("injected slot EIO"));
            }
            self.inner.write_slot_synced(path, offset, slot_bytes)
        }
    }

    fn test_config(dir: &TempDir) -> ControlStoreConfig {
        ControlStoreConfig {
            db_path: dir.path().join("control.redb"),
            emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
        }
    }

    fn enroll_sample_node(store: &ControlStore, seed: u8, name_str: &str) -> Option<NodeId> {
        let now_ms = store.clock().now_unix_ms();
        let key_hash = [seed; 32];
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms + u64::from(seed)),
                    token_hash: key_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: None,
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .ok()?;
        let pk = PublicKey::from_bytes([seed.wrapping_add(50); 32]).ok()?;
        let disco_pk = PublicKey::from_bytes([seed.wrapping_add(90); 32]).ok()?;
        let req_name = NodeName::parse(name_str).ok()?;
        let (outcome, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: pk,
                disco_pubkey: disco_pk,
                previous_node_pubkey: None,
                requested_name: req_name,
                preauth_token_hash: key_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .ok()?;
        Some(outcome.record.node_id)
    }

    #[test]
    fn test_netmap_version_clock_rollback_and_crash_never_regresses() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let cfg = test_config(&dir);
        let clock = Arc::new(FakeClock::new(1_731_480_000_000));

        // Act: boot 1 allocates versions 1..=2, then simulate 1-year backward clock jump + crash
        let pre_crash_version = {
            let store = ControlStore::open_with_clock(
                cfg.clone(),
                DEFAULT_OVERLAY_CIDR,
                Arc::clone(&clock) as Arc<dyn Clock>,
            )
            .expect("open store");
            assert!(enroll_sample_node(&store, 1, "alpha").is_some());
            assert!(enroll_sample_node(&store, 2, "beta").is_some());
            store.current_netmap_version()
        };

        // Roll wall clock backward by 365 days before rebooting store
        clock.jump_wall_ms(-31_536_000_000);
        let restarted = ControlStore::open_with_clock(
            cfg,
            DEFAULT_OVERLAY_CIDR,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .expect("reopen store");
        let post_crash_node = enroll_sample_node(&restarted, 3, "gamma");

        // Assert: post-crash version strictly exceeds pre-crash version despite clock rollback
        assert!(post_crash_node.is_some());
        assert!(pre_crash_version >= 2);
        assert!(restarted.current_netmap_version() > pre_crash_version);
        assert!(restarted.current_netmap_version() > VERSION_LEASE_STEP);
    }

    #[test]
    fn test_restore_advances_netmap_version_watermark() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let cfg = test_config(&dir);
        let backup_dir = dir.path().join("backups");
        let clock = Arc::new(FakeClock::new(1_731_480_000_000));

        let store = ControlStore::open_with_clock(
            cfg.clone(),
            DEFAULT_OVERLAY_CIDR,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .expect("open store");
        store
            .ensure_or_init_identity(&["127.0.0.1".to_owned()], 365)
            .expect("init identity");
        assert!(enroll_sample_node(&store, 10, "mac-one").is_some());
        let pre_backup_wm = store.persisted_watermark();
        let artifact = store.create_backup(&backup_dir, "admin").expect("backup");

        // Act: restore snapshot via live store handle
        let restore_res = store.restore_backup(RestoreOptions {
            snapshot_path: artifact.snapshot_path,
            target_db_path: cfg.db_path.clone(),
            target_emergency_path: cfg.emergency_revocations_path.clone(),
            expected_published_pin: None,
            allow_pin_change: false,
            verify_sha256: true,
            min_netmap_version: 0,
            min_required_snapshot_version: None,
        });

        // Assert
        assert!(restore_res.is_ok());
        let post_restore_wm = store.persisted_watermark();
        assert!(post_restore_wm >= pre_backup_wm + RESTORE_WATERMARK_JUMP);
        assert!(store.current_netmap_version() >= pre_backup_wm + RESTORE_WATERMARK_JUMP);
    }

    #[test]
    fn test_dual_eio_with_exhausted_lease_forces_peer_reauth_without_unpersisted_version() {
        // Arrange: open store and exhaust lease so current == persisted_watermark
        let dir = TempDir::new().expect("tempdir");
        let backend = Arc::new(TestEmergencyBackend::new(false));
        let clock = Arc::new(FakeClock::new(1_731_480_000_000));
        let store = ControlStore::open_with_backend(
            test_config(&dir),
            DEFAULT_OVERLAY_CIDR,
            clock,
            Arc::clone(&backend) as Arc<dyn EmergencyFileBackend>,
        )
        .expect("open store with backend");
        let node1 = enroll_sample_node(&store, 20, "peer-one").expect("node1");
        let node2 = enroll_sample_node(&store, 21, "peer-two").expect("node2");

        // Force BOTH redb + Slot EIO with exhausted netmap lease on node2!
        store.set_redb_failure_for_test(true);
        store.exhaust_lease_for_test();
        let exhausted_before = store.current_netmap_version();
        assert_eq!(exhausted_before, store.persisted_watermark());

        backend.fail_slot_writes.store(true, Ordering::SeqCst);
        let outcome = store.revoke_node(node2, "admin").expect("revoke outcome");

        // Assert Gate 2(b): inserted into RAM, NO unpersisted netmap_version emitted, disconnect flag true
        assert_eq!(outcome.persistence_tier, PersistenceTier::RamOnly);
        assert_eq!(outcome.netmap_version, None);
        assert!(outcome.must_disconnect_all_peers_to_reauth);
        assert!(store.is_node_revoked_ram(node2));
        assert_eq!(store.current_netmap_version(), exhausted_before);

        // Now recover hardware I/O and run compaction (Gate 2(a): must persist RamOnly item!)
        backend.fail_slot_writes.store(false, Ordering::SeqCst);
        store.inject_redb_failure(false, false);
        let compacted = store
            .try_compact_emergency_revocations()
            .expect("compaction");
        assert!(compacted.is_some());
        assert!(!store.is_disk_degraded());

        let persisted_n2 = store.find_node_by_id(node2).expect("find node2");
        assert_eq!(persisted_n2.map(|r| r.status), Some(NodeStatus::Revoked));
        assert!(!store.is_node_revoked_ram(node1));
    }

    #[test]
    fn test_create_backup_folds_pending_emergency_revocations_and_restore_preserves_live_db_on_pin_mismatch()
     {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let cfg = test_config(&dir);
        let backup_dir = dir.path().join("backups");
        let clock = Arc::new(FakeClock::new(1_731_480_000_000));
        let store = ControlStore::open_with_clock(
            cfg.clone(),
            DEFAULT_OVERLAY_CIDR,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .expect("open store");
        let id = store
            .ensure_or_init_identity(&["127.0.0.1".to_owned()], 365)
            .expect("init identity");
        let n1 = enroll_sample_node(&store, 31, "fold-alpha").expect("node1");
        let _n2 = enroll_sample_node(&store, 32, "fold-beta").expect("node2");

        // Trigger emergency fallback revocation without compacting primary redb yet
        store.set_redb_failure_for_test(true);
        let rev_outcome = store.revoke_node(n1, "admin").expect("emergency revoke");
        assert_eq!(rev_outcome.persistence_tier, PersistenceTier::EmergencySlot);
        store.set_redb_failure_for_test(false);

        // Act: take hot backup BEFORE compaction -> folded snapshot must persist revocation
        let artifact = store
            .create_backup(&backup_dir, "admin")
            .expect("create backup");

        // Attempt restore with wrong SPKI pin & verify_sha256: false -> MUST fail and preserve live DB
        let wrong_pin = mesh_core::SpkiPin::from_sha256_bytes([0xAB_u8; 32]);
        let bad_restore = store.restore_backup(RestoreOptions {
            snapshot_path: artifact.snapshot_path.clone(),
            target_db_path: cfg.db_path.clone(),
            target_emergency_path: cfg.emergency_revocations_path.clone(),
            expected_published_pin: Some(wrong_pin),
            allow_pin_change: false,
            verify_sha256: false,
            min_netmap_version: 0,
            min_required_snapshot_version: None,
        });
        assert!(bad_restore.is_err());
        assert_eq!(
            store.list_nodes().expect("live nodes still intact").len(),
            2
        );

        // Now restore validly with matching pin and confirm folded revocation survived!
        let ok_restore = store.restore_backup(RestoreOptions {
            snapshot_path: artifact.snapshot_path,
            target_db_path: cfg.db_path,
            target_emergency_path: cfg.emergency_revocations_path,
            expected_published_pin: Some(id.spki_pin),
            allow_pin_change: false,
            verify_sha256: true,
            min_netmap_version: 0,
            min_required_snapshot_version: None,
        });
        assert!(ok_restore.is_ok());
        assert!(store.is_node_revoked_ram(n1));
        assert_eq!(
            store
                .find_node_by_id(n1)
                .expect("find n1")
                .map(|r| r.status),
            Some(NodeStatus::Revoked)
        );
    }

    #[test]
    fn test_expiry_never_ephemeral_reap_and_min_snapshot_version_anti_rollback() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let cfg = test_config(&dir);
        let backup_dir = dir.path().join("backups");
        let clock = Arc::new(FakeClock::new(1_731_480_000_000));
        let store = ControlStore::open_with_clock(
            cfg.clone(),
            DEFAULT_OVERLAY_CIDR,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .expect("open store");
        store
            .ensure_or_init_identity(&["127.0.0.1".to_owned()], 365)
            .expect("init identity");

        let trusted_id = enroll_sample_node(&store, 41, "trusted-gw").expect("trusted");
        let ephem_hash = [0x42_u8; 32];
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(clock.now_unix_ms()),
                    token_hash: ephem_hash,
                    label: Some("ephem".to_owned()),
                    bound_node_name: None,
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: true,
                    ephemeral_timeout_secs: Some(30),
                    ttl_secs: 3_600,
                    now_unix_ms: clock.now_unix_ms(),
                },
                "admin",
            )
            .expect("ephem key");
        let (ephem_out, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: PublicKey::from_bytes([0x43_u8; 32]).expect("ephem pk"),
                disco_pubkey: PublicKey::from_bytes([0x44_u8; 32]).expect("ephem dpk"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("ci-runner-01").expect("name"),
                preauth_token_hash: ephem_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.2.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: clock.now_unix_ms(),
            })
            .expect("register ephem");
        let ephem_ip = ephem_out.record.overlay_ip.expect("ephem ip");

        // Act 1: mark trusted node --never, advance clock +200d -> trusted survives, normal expires
        let (_rec_never, _ver) = store
            .set_node_expiry_never(trusted_id, "admin")
            .expect("set never");
        clock.advance(200 * 86_400 * 1_000);
        let expired = store.sweep_expired_nodes().expect("sweep");
        assert!(expired.iter().all(|o| o.node_id != trusted_id));
        let trusted_rec = store
            .find_node_by_id(trusted_id)
            .expect("find")
            .expect("some");
        assert_eq!(trusted_rec.status, NodeStatus::Active);
        assert_eq!(trusted_rec.key_expires_at_ms, None);

        // Act 2: restore anti-rollback check against stored snapshot watermark BEFORE swap
        let snap = store.create_backup(&backup_dir, "admin").expect("backup");
        let too_high_min = store.persisted_watermark().saturating_add(500_000);
        let rollback_res = store.restore_backup(RestoreOptions {
            snapshot_path: snap.snapshot_path,
            target_db_path: cfg.db_path,
            target_emergency_path: cfg.emergency_revocations_path,
            expected_published_pin: None,
            allow_pin_change: false,
            verify_sha256: true,
            min_netmap_version: 0,
            min_required_snapshot_version: Some(too_high_min),
        });
        assert_eq!(
            rollback_res.err().map(|e| e.kind()),
            Some(mesh_core::ErrorKind::InvalidArgument)
        );

        // Act 3: re-enroll active ephemeral node and verify reap after idle > 30s frees IP
        let ephem_reap_hash = [0x45_u8; 32];
        let now2 = clock.now_unix_ms();
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now2),
                    token_hash: ephem_reap_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: true,
                    ephemeral_timeout_secs: Some(30),
                    ttl_secs: 3_600,
                    now_unix_ms: now2,
                },
                "admin",
            )
            .expect("ephem2 key");
        assert!(!ephem_ip.to_string().is_empty());
        let (ephem2_out, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: PublicKey::from_bytes([0x46_u8; 32]).expect("pk2"),
                disco_pubkey: PublicKey::from_bytes([0x47_u8; 32]).expect("dpk2"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("ci-runner-02").expect("name2"),
                preauth_token_hash: ephem_reap_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.2.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now2,
            })
            .expect("register ephem2");
        let ephem2_id = ephem2_out.record.node_id;

        // While online -> not reaped; once offline >= 30s -> reaped cleanly
        clock.advance(40_000);
        let (online_reaped, _) = store
            .reap_expired_ephemeral_nodes(300, |_| true, "system")
            .expect("online reap");
        assert!(online_reaped.is_empty());

        let (offline_reaped, reap_ver) = store
            .reap_expired_ephemeral_nodes(300, |_| false, "system")
            .expect("offline reap");
        assert!(reap_ver.is_some());
        assert!(offline_reaped.iter().any(|r| r.node_id == ephem2_id));
        assert!(store.find_node_by_id(ephem2_id).expect("find").is_none());
    }

    #[test]
    fn test_expired_node_renewal_clears_expired_ram_and_emergency_slot_while_preserving_revoked() {
        // Arrange (`HR-W21-02` + `IMP-W21-01`)
        let dir = TempDir::new().expect("tempdir");
        let cfg = test_config(&dir);
        let backend = Arc::new(TestEmergencyBackend::new(false));
        let now_ms = 1_731_480_000_000_u64;
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = ControlStore::open_with_backend(
            cfg.clone(),
            DEFAULT_OVERLAY_CIDR,
            Arc::clone(&clock) as Arc<dyn Clock>,
            Arc::clone(&backend) as Arc<dyn EmergencyFileBackend>,
        )
        .expect("open store");

        let init_hash = [0x61_u8; 32];
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms),
                    token_hash: init_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: true,
                    max_uses: Some(5),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .expect("create init key");

        let pk_old = PublicKey::from_bytes([0x62_u8; 32]).expect("pk_old");
        let (reg_exp, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: pk_old,
                disco_pubkey: PublicKey::from_bytes([0x63_u8; 32]).expect("dpk_old"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("renew-box").expect("name"),
                preauth_token_hash: init_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .expect("register renew-box");
        let node_exp = reg_exp.record.node_id;

        let pk_rev = PublicKey::from_bytes([0x72_u8; 32]).expect("pk_rev");
        let (reg_rev, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: pk_rev,
                disco_pubkey: PublicKey::from_bytes([0x73_u8; 32]).expect("dpk_rev"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("revoked-box").expect("rev name"),
                preauth_token_hash: init_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .expect("register revoked-box");
        let node_rev = reg_rev.record.node_id;
        store
            .revoke_node(node_rev, "admin")
            .expect("revoke node_rev");
        assert!(store.is_node_permanently_revoked_ram(node_rev));
        assert!(!store.is_node_expired_ram(node_rev));

        // Inject redb read+write EIO (`IMP-W21-01`), verify read fails while expire_node records
        // `EmergencyNodeReason::Expired` via RAM dir.
        store.inject_redb_failure(true, true);
        assert!(store.find_node_by_id(node_exp).is_err());
        let exp_out = store
            .expire_node(node_exp, "admin")
            .expect("expire node_exp into emergency slot");
        assert_eq!(exp_out.persistence_tier, PersistenceTier::EmergencySlot);
        assert!(store.is_node_revoked_ram(node_exp));
        assert!(store.is_node_expired_ram(node_exp));
        assert!(!store.is_node_permanently_revoked_ram(node_exp));

        // Storage recovers BEFORE compaction: admin mints `--for renew-box` renewal key (`US-031 AC5`).
        store.inject_redb_failure(false, false);
        let renew_hash = [0x64_u8; 32];
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms + 10),
                    token_hash: renew_hash,
                    label: None,
                    bound_node_name: Some(NodeName::parse("renew-box").expect("bound name")),
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms + 10,
                },
                "admin",
            )
            .expect("create bound renewal key");

        let pk_new = PublicKey::from_bytes([0x65_u8; 32]).expect("pk_new");
        let (renew_out, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: pk_new,
                disco_pubkey: PublicKey::from_bytes([0x66_u8; 32]).expect("dpk_new"),
                previous_node_pubkey: Some(pk_old),
                requested_name: NodeName::parse("renew-box").expect("renew name"),
                preauth_token_hash: renew_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms + 20,
            })
            .expect("valid renewal for expired node must succeed");

        assert_eq!(renew_out.record.node_id, node_exp);
        assert_eq!(renew_out.record.status, NodeStatus::Active);
        assert!(!store.is_node_revoked_ram(node_exp));
        assert!(!store.is_node_expired_ram(node_exp));
        assert!(store.is_pubkey_revoked_ram(&pk_old));
        assert!(!store.is_pubkey_revoked_ram(&pk_new));

        // Reopen store to prove emergency slot was cleaned and never re-expires `renew-box`, while
        // `revoked-box` remains permanently blocked even with a bound key.
        drop(store);
        let reopened = ControlStore::open_with_backend(
            cfg,
            DEFAULT_OVERLAY_CIDR,
            Arc::clone(&clock) as Arc<dyn Clock>,
            backend as Arc<dyn EmergencyFileBackend>,
        )
        .expect("reopen store");
        assert!(!reopened.is_node_revoked_ram(node_exp));
        assert!(!reopened.is_node_expired_ram(node_exp));
        assert_eq!(
            reopened
                .try_compact_emergency_revocations()
                .expect("no pending emergency expiry"),
            None
        );
        assert_eq!(
            reopened
                .find_node_by_id(node_exp)
                .expect("lookup node_exp")
                .map(|r| r.status),
            Some(NodeStatus::Active)
        );
        assert!(reopened.is_node_permanently_revoked_ram(node_rev));

        let rev_try_hash = [0x74_u8; 32];
        reopened
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms + 30),
                    token_hash: rev_try_hash,
                    label: None,
                    bound_node_name: Some(NodeName::parse("revoked-box").expect("rev bound")),
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms + 30,
                },
                "admin",
            )
            .expect("create bound key for revoked");
        let rev_renew_err = reopened.register_node(&RegisterNodeInput {
            pubkey: PublicKey::from_bytes([0x75_u8; 32]).expect("pk_rev_new"),
            disco_pubkey: PublicKey::from_bytes([0x76_u8; 32]).expect("dpk_rev_new"),
            previous_node_pubkey: Some(pk_rev),
            requested_name: NodeName::parse("revoked-box").expect("rev name"),
            preauth_token_hash: rev_try_hash,
            public_control_host: "203.0.113.10",
            domain_suffix: "mesh.internal",
            os_arch: "linux/amd64",
            agent_version: "0.1.0",
            protocol_version: 1,
            node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
            now_unix_ms: now_ms + 40,
        });
        assert!(rev_renew_err.is_err());
    }

    #[test]
    fn test_revoke_hook_disconnects_before_slow_disk_and_redb_read_eio() {
        // Arrange (`HR-W21-04`, `IMP-W21-01`)
        #[derive(Debug)]
        struct SlowEmergencyBackend {
            inner: OsEmergencyFileBackend,
            write_started_tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
            write_gate_rx: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
            events: Arc<std::sync::Mutex<Vec<&'static str>>>,
        }
        impl EmergencyFileBackend for SlowEmergencyBackend {
            fn exists(&self, path: &Path) -> bool {
                self.inner.exists(path)
            }
            fn file_len(&self, path: &Path) -> io::Result<u64> {
                self.inner.file_len(path)
            }
            fn create_preallocated(&self, path: &Path, full_image: &[u8]) -> io::Result<()> {
                self.inner.create_preallocated(path, full_image)
            }
            fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
                self.inner.read_all(path)
            }
            fn write_slot_synced(
                &self,
                path: &Path,
                offset: u64,
                slot_bytes: &[u8],
            ) -> io::Result<()> {
                let started_tx = self.write_started_tx.lock().ok().and_then(|mut g| g.take());
                let gate_rx = self.write_gate_rx.lock().ok().and_then(|mut g| g.take());
                if started_tx.is_some()
                    && let Ok(mut ev) = self.events.lock()
                {
                    ev.push("disk_write_entered");
                }
                if let Some(tx) = started_tx
                    && tx.send(()).is_err()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "started channel closed",
                    ));
                }
                if let Some(rx) = gate_rx
                    && rx.recv_timeout(std::time::Duration::from_secs(5)).is_err()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "test write gate timed out",
                    ));
                }
                self.inner.write_slot_synced(path, offset, slot_bytes)
            }
        }

        let dir = TempDir::new().expect("tempdir");
        let cfg = test_config(&dir);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let backend = Arc::new(SlowEmergencyBackend {
            inner: OsEmergencyFileBackend,
            write_started_tx: std::sync::Mutex::new(None),
            write_gate_rx: std::sync::Mutex::new(None),
            events: Arc::clone(&events),
        });
        let now_ms = 1_731_480_000_000_u64;
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_backend(
                cfg,
                DEFAULT_OVERLAY_CIDR,
                clock,
                Arc::clone(&backend) as Arc<dyn EmergencyFileBackend>,
            )
            .expect("open store"),
        );

        let fast_node = enroll_sample_node(&store, 81, "fast-node").expect("fast node");
        let fast_key_id = KeyId::new_v7(now_ms + 1);
        let fast_key_hash = [0x82_u8; 32];
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: fast_key_id,
                    token_hash: fast_key_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .expect("create preauth key");

        // Enable both redb read+write failure AND gated slow emergency slot write.
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (hook_tx, hook_rx) = std::sync::mpsc::channel();
        *backend.write_started_tx.lock().expect("started lock") = Some(started_tx);
        *backend.write_gate_rx.lock().expect("gate lock") = Some(gate_rx);
        store.inject_redb_failure(true, true);
        assert!(store.find_node_by_id(fast_node).is_err());

        let store_bg = Arc::clone(&store);
        let events_bg = Arc::clone(&events);
        let handle = std::thread::spawn(move || {
            store_bg.revoke_node_with_hook(fast_node, "admin", |nid, _| {
                if let Ok(mut ev) = events_bg.lock() {
                    ev.push("hook_fired");
                }
                assert!(store_bg.is_node_revoked_ram(nid));
                hook_tx.send(nid).expect("send hook signal");
            })
        });

        let hooked_node = hook_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("on_ram_locked hook fires before slow disk");
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("disk write reached after hook");
        assert_eq!(hooked_node, fast_node);
        assert!(
            !handle.is_finished(),
            "disk write still blocked while hook already ran"
        );
        assert_eq!(
            *events.lock().expect("events lock"),
            vec!["hook_fired", "disk_write_entered"]
        );

        gate_tx.send(()).expect("release slow disk write");
        let outcome = handle
            .join()
            .expect("join worker thread")
            .expect("revoke succeeds via RAM directory + EmergencySlot");
        assert_eq!(outcome.persistence_tier, PersistenceTier::EmergencySlot);

        // Revoking a pre-auth key under redb read+write EIO succeeds via RAM directory
        let key_tier = store
            .revoke_preauth_key(fast_key_id, "admin")
            .expect("preauth revoke under redb read+write EIO");
        assert_eq!(key_tier, PersistenceTier::EmergencySlot);
        assert!(store.is_key_revoked_ram(fast_key_id));

        // Healthy rollback check: revoking unknown node must fail NotFound and leave RAM clean
        store.inject_redb_failure(false, false);
        let _compacted = store
            .try_compact_emergency_revocations()
            .expect("compact slow test");
        let ghost_id = NodeId::new_v7(now_ms + 9_999);
        let err = store
            .revoke_node(ghost_id, "admin")
            .expect_err("unknown node fails");
        assert_eq!(err.kind(), mesh_core::ErrorKind::NotFound);
        assert!(!store.is_node_revoked_ram(ghost_id));
    }
}
