//! Hot MVCC atomic snapshot backup (`SHA-256`, `0600`, retention `7`), pre-migration snapshots,
//! and verified restore (`+1_000_000` netmap watermark jump) (`US-045`, `US-007`, `WP-S1-01`).

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use mesh_core::{AppError, AppResult, ErrorKind, SpkiPin};
use mesh_crypto::{sha256_hex, verify_file_sha256};
use redb::{Database, ReadTransaction, ReadableTable as _, TableDefinition, WriteTransaction};

use crate::audit_repo::{AuditEventInput, AuditRepository};
use crate::identity_repo::IdentityRepository;
use crate::keys_repo::KeysRepository;
use crate::nodes_repo::NodesRepository;
use crate::revoked_ram::{
    EmergencyNodeReason, EmergencyRevocationKeyEntry, EmergencyRevocationNodeEntry,
    EmergencyRevocationState, OsEmergencyFileBackend,
};
use crate::schema::{
    META_KEY_WATERMARK, SCHEMA_VERSION, SchemaVersionRecord, TABLE_AUDIT_EVENTS,
    TABLE_IDX_NODES_NAME, TABLE_IDX_NODES_OVERLAY_IP, TABLE_IDX_NODES_PUBKEY,
    TABLE_IDX_PREAUTH_HASH, TABLE_NODES, TABLE_PREAUTH_KEYS, TABLE_SCHEMA_META,
    TABLE_SERVER_IDENTITY, decode_envelope, decode_u64_be, encode_u64_be, ensure_all_tables,
    map_store_err, verify_all_tables_readable,
};

/// Default number of rolling snapshot backups retained on disk (`US-045 AC1`).
pub const DEFAULT_BACKUP_RETENTION: usize = 7;

/// Minimum netmap version jump applied on restore to invalidate stale cached netmaps (`REL-01`).
pub const RESTORE_WATERMARK_JUMP: u64 = 1_000_000;

/// Metadata describing a completed snapshot backup file and its SHA-256 sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupArtifact {
    /// Final `.redb` snapshot path (`0600` permissions on Unix).
    pub snapshot_path: PathBuf,
    /// Companion `.sha256` checksum path (`0600` permissions on Unix).
    pub sha256_path: PathBuf,
    /// Lowercase hexadecimal SHA-256 digest of the snapshot file bytes.
    pub sha256_hex: String,
    /// Snapshot byte size on disk.
    pub size_bytes: u64,
    /// True because backups contain server identity key material (`US-045 AC5`).
    pub contains_server_identity: bool,
}

/// Parameters controlling validated database restoration (`US-045`).
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    /// Snapshot `.redb` path to restore.
    pub snapshot_path: PathBuf,
    /// Destination live `redb` database path.
    pub target_db_path: PathBuf,
    /// Destination `emergency-revocations.bin` path (reset to clean 64 KiB after restore).
    pub target_emergency_path: PathBuf,
    /// Optional currently published SPKI pin to warn/guard against silent pin mismatch (`US-045 AC6`).
    pub expected_published_pin: Option<SpkiPin>,
    /// Explicit override permitting restore even when pin mismatches or identity was absent.
    pub allow_pin_change: bool,
    /// Whether to require and verify the companion `.sha256` sidecar file (`BLK-S1-04`).
    pub verify_sha256: bool,
    /// Monotonic floor from live DB + emergency slot + current clock (`database-design.md` §3.3).
    pub min_netmap_version: u64,
    /// Optional operator-requested minimum snapshot version (`--min-netmap-version`, `US-045`).
    pub min_required_snapshot_version: Option<u64>,
}

/// Outcome returned by [`BackupManager::restore_from_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Verified snapshot SHA-256 hex digest.
    pub verified_sha256_hex: String,
    /// Active SPKI pin recovered from the snapshot (`None` only if `allow_pin_change == true`).
    pub restored_spki_pin: Option<SpkiPin>,
    /// New durable `netmap_version_watermark` written (`floor + RESTORE_WATERMARK_JUMP`).
    pub new_netmap_watermark: u64,
}

/// Validated, pre-bumped snapshot database file ready for atomic live swap (`BLK-S1-04`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedRestore {
    /// Temporary validated `.redb` path in the target directory.
    pub staged_path: PathBuf,
    /// Hex SHA-256 digest of the snapshot file.
    pub verified_sha256_hex: String,
    /// Active SPKI pin recovered from the snapshot.
    pub restored_spki_pin: Option<SpkiPin>,
    /// Monotonic `netmap_version_watermark` already persisted into `staged_path`.
    pub new_netmap_watermark: u64,
}

/// Pending in-memory / emergency-slot revocations and watermark floor folded into hot backups.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmergencySnapshotOverlay<'a> {
    /// Pending uncompacted node revocations to fold into the snapshot copy.
    pub pending_nodes: &'a [EmergencyRevocationNodeEntry],
    /// Pending uncompacted pre-auth key revocations to fold into the snapshot copy.
    pub pending_keys: &'a [EmergencyRevocationKeyEntry],
    /// Monotonic netmap version floor to enforce in the snapshot metadata.
    pub min_netmap_version: u64,
}

/// Atomic database backup and restore coordinator (`US-045`).
#[derive(Debug, Default)]
pub struct BackupManager;

impl BackupManager {
    /// Creates an atomic MVCC snapshot of `source_db` inside `backup_dir`, writes `<name>.sha256`,
    /// enforces `0600` permissions, and prunes older snapshots past `retention`.
    pub fn create_snapshot(
        source_db: &Database,
        backup_dir: &Path,
        prefix: &str,
        now_unix_ms: u64,
        retention: usize,
    ) -> AppResult<BackupArtifact> {
        Self::create_snapshot_with_emergency(
            source_db,
            backup_dir,
            prefix,
            now_unix_ms,
            retention,
            EmergencySnapshotOverlay::default(),
        )
    }

    /// Creates an atomic MVCC snapshot and folds unmerged RAM/EmergencySlot revocations + watermark
    /// floor directly into the backup copy without mutating the primary database (`BLK-S1-04`).
    pub fn create_snapshot_with_emergency(
        source_db: &Database,
        backup_dir: &Path,
        prefix: &str,
        now_unix_ms: u64,
        retention: usize,
        overlay: EmergencySnapshotOverlay<'_>,
    ) -> AppResult<BackupArtifact> {
        fs::create_dir_all(backup_dir).map_err(|err| {
            AppError::unavailable(format!(
                "failed creating backup directory {}: {err}",
                backup_dir.display()
            ))
        })?;
        restrict_dir_permissions(backup_dir)?;

        let file_stem = format!("{prefix}-{now_unix_ms}");
        let tmp_path = backup_dir.join(format!(".{file_stem}.redb.tmp"));
        let final_path = backup_dir.join(format!("{file_stem}.redb"));
        let sha_tmp_path = backup_dir.join(format!(".{file_stem}.sha256.tmp"));
        let sha_final_path = backup_dir.join(format!("{file_stem}.sha256"));

        let contains_identity = copy_mvcc_snapshot_db(source_db, &tmp_path, overlay, now_unix_ms)?;
        restrict_file_permissions(&tmp_path)?;

        let snapshot_bytes = fs::read(&tmp_path).map_err(|err| {
            AppError::unavailable(format!("failed reading snapshot for hashing: {err}"))
        })?;
        let digest_hex = sha256_hex(&snapshot_bytes);
        let size_bytes = u64::try_from(snapshot_bytes.len()).unwrap_or(u64::MAX);

        let sha_line = format!(
            "{digest_hex}  {}\n",
            final_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("backup.redb")
        );
        write_restricted_file(&sha_tmp_path, sha_line.as_bytes())?;

        fs::rename(&tmp_path, &final_path).map_err(|err| {
            AppError::unavailable(format!("failed publishing backup snapshot: {err}"))
        })?;
        fs::rename(&sha_tmp_path, &sha_final_path).map_err(|err| {
            AppError::unavailable(format!("failed publishing backup checksum file: {err}"))
        })?;
        restrict_file_permissions(&final_path)?;
        restrict_file_permissions(&sha_final_path)?;

        let keep = retention.max(1);
        prune_old_backups(backup_dir, prefix, keep)?;

        Ok(BackupArtifact {
            snapshot_path: final_path,
            sha256_path: sha_final_path,
            sha256_hex: digest_hex,
            size_bytes,
            contains_server_identity: contains_identity,
        })
    }

    /// Creates a mandatory pre-migration snapshot retained prior to schema upgrades (`US-007`).
    pub fn create_pre_migration_snapshot(
        source_db: &Database,
        backup_dir: &Path,
        from_version: u32,
        now_unix_ms: u64,
    ) -> AppResult<BackupArtifact> {
        let prefix = format!("pre-migration-v{from_version}");
        Self::create_snapshot(
            source_db,
            backup_dir,
            &prefix,
            now_unix_ms,
            DEFAULT_BACKUP_RETENTION,
        )
    }

    /// Validates checksum (when enabled), checks schema/SPKI pin, and writes the watermark jump
    /// into a temporary staged DB without disturbing the active live database (`BLK-S1-04`).
    pub fn prepare_staged_restore(options: &RestoreOptions) -> AppResult<StagedRestore> {
        let verified_sha256_hex = if options.verify_sha256 {
            let expected_hex = read_companion_sha256(&options.snapshot_path)?;
            let _verified_digest = verify_file_sha256(&options.snapshot_path, &expected_hex)?;
            expected_hex
        } else {
            let bytes = fs::read(&options.snapshot_path).map_err(|err| {
                AppError::unavailable(format!(
                    "failed reading snapshot {}: {err}",
                    options.snapshot_path.display()
                ))
            })?;
            sha256_hex(&bytes)
        };

        let Some(parent) = options.target_db_path.parent() else {
            return Err(AppError::invalid_argument(
                "target_db_path lacks parent dir",
            ));
        };
        fs::create_dir_all(parent).map_err(|err| {
            AppError::unavailable(format!("failed creating target DB directory: {err}"))
        })?;
        let staged_path = parent.join(".restore-staged.redb.tmp");
        remove_if_exists(&staged_path)?;
        fs::copy(&options.snapshot_path, &staged_path).map_err(|err| {
            AppError::unavailable(format!("failed staging restore snapshot: {err}"))
        })?;
        restrict_file_permissions(&staged_path)?;

        match validate_and_bump_staged_db(&staged_path, options) {
            Ok((restored_spki_pin, new_netmap_watermark)) => Ok(StagedRestore {
                staged_path,
                verified_sha256_hex,
                restored_spki_pin,
                new_netmap_watermark,
            }),
            Err(err) => {
                if let Err(clean_err) = remove_if_exists(&staged_path) {
                    tracing::warn!(
                        component = "mesh-store",
                        event = "cleanup_staged_restore_failed",
                        error = %clean_err,
                        "failed removing failed restore staging file"
                    );
                }
                Err(err)
            }
        }
    }

    /// Atomically swaps `staged_path` onto `target_db_path` with automatic rollback if reopening or
    /// reading the restored database fails (`BLK-S1-04`), retaining `<target_db_path>.before-restore`
    /// with `0600` permissions after a successful restore (`HR-S1-12-R2`).
    pub fn swap_and_verify_staged_db(staged_path: &Path, target_db_path: &Path) -> AppResult<()> {
        if target_db_path.parent().is_none() {
            return Err(AppError::invalid_argument(
                "target_db_path lacks parent dir",
            ));
        }
        let mut before_restore_os = target_db_path.as_os_str().to_os_string();
        before_restore_os.push(".before-restore");
        let before_restore_path = PathBuf::from(before_restore_os);
        remove_if_exists(&before_restore_path)?;
        let had_previous = target_db_path.exists();
        if had_previous {
            fs::rename(target_db_path, &before_restore_path).map_err(|err| {
                AppError::unavailable(format!(
                    "failed preserving pre-restore database rollback copy: {err}"
                ))
            })?;
            if let Err(err) = restrict_file_permissions(&before_restore_path) {
                if let Err(rb_err) = fs::rename(&before_restore_path, target_db_path) {
                    tracing::error!(
                        component = "mesh-store",
                        event = "restore_rollback_rename_failed",
                        error = %rb_err,
                        "failed restoring live database after chmod error on before-restore copy"
                    );
                }
                return Err(err);
            }
        }

        if let Err(err) = fs::rename(staged_path, target_db_path) {
            if had_previous && let Err(rb_err) = fs::rename(&before_restore_path, target_db_path) {
                tracing::error!(
                    component = "mesh-store",
                    event = "restore_rollback_rename_failed",
                    error = %rb_err,
                    "failed restoring rollback database after rename failure"
                );
            }
            return Err(AppError::unavailable(format!(
                "failed activating restored control database: {err}"
            )));
        }

        let verify_res = (|| -> AppResult<()> {
            restrict_file_permissions(target_db_path)?;
            let reopened = Database::open(target_db_path)
                .map_err(|e| map_store_err("verify restored database open", e))?;
            let rtx = reopened
                .begin_read()
                .map_err(|e| map_store_err("verify restored database read", e))?;
            verify_all_tables_readable(&rtx)?;
            Ok(())
        })();

        if let Err(err) = verify_res {
            if let Err(rm_err) = remove_if_exists(target_db_path) {
                tracing::warn!(
                    component = "mesh-store",
                    event = "restore_remove_broken_db_failed",
                    error = %rm_err,
                    "failed removing unreadable restored db before rollback"
                );
            }
            if had_previous && let Err(rb_err) = fs::rename(&before_restore_path, target_db_path) {
                tracing::error!(
                    component = "mesh-store",
                    event = "restore_rollback_failed",
                    error = %rb_err,
                    "failed restoring rollback database copy"
                );
            }
            return Err(err);
        }

        if before_restore_path.exists() {
            restrict_file_permissions(&before_restore_path)?;
        }
        Ok(())
    }

    /// Resets `emergency-revocations.bin` cleanly after a restored database is confirmed live and
    /// stamps `restored_watermark` into its header so floor monotonicity survives next boot.
    pub fn reset_emergency_file_after_restore(
        emergency_path: &Path,
        restored_watermark: u64,
    ) -> AppResult<()> {
        remove_if_exists(emergency_path)?;
        let backend = OsEmergencyFileBackend;
        let (mut state, _ram) = EmergencyRevocationState::boot_open_with_backend(
            emergency_path.to_path_buf(),
            false,
            &backend,
        )?;
        state.reset_after_restore_commit(restored_watermark, &backend)?;
        Ok(())
    }

    /// Verifies sidecar `.sha256` (if enabled), checks schema and server identity (`US-045 AC4/AC6`),
    /// advances `netmap_version_watermark`, swaps live DB with rollback, and resets emergency file.
    pub fn restore_from_snapshot(options: &RestoreOptions) -> AppResult<RestoreOutcome> {
        let staged = Self::prepare_staged_restore(options)?;
        Self::swap_and_verify_staged_db(&staged.staged_path, &options.target_db_path)?;
        Self::reset_emergency_file_after_restore(
            &options.target_emergency_path,
            staged.new_netmap_watermark,
        )?;

        Ok(RestoreOutcome {
            verified_sha256_hex: staged.verified_sha256_hex,
            restored_spki_pin: staged.restored_spki_pin,
            new_netmap_watermark: staged.new_netmap_watermark,
        })
    }

    /// Verifies a `.redb` snapshot + `.sha256` pair on disk without touching any live DB.
    pub fn verify_snapshot_checksum(snapshot_path: &Path) -> AppResult<String> {
        let expected_hex = read_companion_sha256(snapshot_path)?;
        let _ = verify_file_sha256(snapshot_path, &expected_hex)?;
        Ok(expected_hex)
    }

    /// Compatibility stub signature check; returns configuration error if invoked without target.
    pub fn create_snapshot_unconfigured() -> AppResult<()> {
        Err(AppError::invalid_argument(
            "BackupManager::create_snapshot requires an open database and backup directory",
        ))
    }
}

fn validate_and_bump_staged_db(
    staged_path: &Path,
    options: &RestoreOptions,
) -> AppResult<(Option<SpkiPin>, u64)> {
    let staged_db = Database::open(staged_path)
        .map_err(|e| AppError::invalid_argument(format!("corrupt backup database: {e}")))?;
    {
        let rtx = staged_db
            .begin_read()
            .map_err(|e| map_store_err("read staged backup", e))?;
        verify_all_tables_readable(&rtx)?;
        let meta = rtx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open meta staged backup", e))?;
        if let Some(ver_guard) = meta
            .get("schema_version")
            .map_err(|e| map_store_err("read backup schema_version", e))?
        {
            let rec: SchemaVersionRecord = decode_envelope(ver_guard.value())?;
            if rec.version > SCHEMA_VERSION {
                return Err(AppError::invalid_argument(format!(
                    "backup schema version {} is newer than supported version {SCHEMA_VERSION}",
                    rec.version
                )));
            }
        }
    }

    let identity_opt = IdentityRepository::load_active_opt(&staged_db)?;
    let restored_pin = identity_opt.as_ref().map(|id| id.spki_pin);
    if identity_opt.is_none() && !options.allow_pin_change {
        return Err(AppError::conflict(
            "backup omits server identity key; restore refused without explicit re-pin confirmation",
        ));
    }
    if let (Some(expected_pin), Some(actual_pin)) = (options.expected_published_pin, restored_pin)
        && expected_pin != actual_pin
        && !options.allow_pin_change
    {
        return Err(AppError::conflict(format!(
            "backup server pin {actual_pin} mismatches published pin {expected_pin}; clients would have to re-pin manually"
        )));
    }

    let wtx = staged_db
        .begin_write()
        .map_err(|e| map_store_err("begin write staged watermark jump", e))?;
    let new_watermark = {
        let mut meta = wtx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open meta staged watermark", e))?;
        let current = match meta
            .get(META_KEY_WATERMARK)
            .map_err(|e| map_store_err("read staged watermark", e))?
        {
            Some(g) => decode_u64_be(g.value())?,
            None => 0,
        };
        if let Some(required_ver) = options.min_required_snapshot_version
            && current < required_ver
        {
            return Err(AppError::invalid_argument(format!(
                "snapshot netmap_version watermark {current} is below --min-netmap-version {required_ver}"
            )));
        }
        let jumped = current
            .max(options.min_netmap_version)
            .saturating_add(RESTORE_WATERMARK_JUMP);
        let encoded = encode_u64_be(jumped);
        meta.insert(META_KEY_WATERMARK, encoded.as_slice())
            .map_err(|e| map_store_err("write jumped watermark", e))?;
        jumped
    };
    wtx.commit()
        .map_err(|e| map_store_err("commit staged watermark jump", e))?;
    Ok((restored_pin, new_watermark))
}

fn read_companion_sha256(snapshot_path: &Path) -> AppResult<String> {
    let mut sha_os = snapshot_path.as_os_str().to_os_string();
    sha_os.push(".sha256");
    let companion_alt = PathBuf::from(sha_os);
    let companion_stem = snapshot_path.with_extension("sha256");
    let sha_path = if companion_stem.exists() {
        companion_stem
    } else if companion_alt.exists() {
        companion_alt
    } else {
        return Err(AppError::not_found(format!(
            "backup checksum sidecar missing for {}",
            snapshot_path.display()
        )));
    };
    let text = fs::read_to_string(&sha_path).map_err(|err| {
        AppError::unavailable(format!(
            "failed reading checksum sidecar {}: {err}",
            sha_path.display()
        ))
    })?;
    let hex_token = text
        .split_whitespace()
        .next()
        .ok_or_else(|| AppError::invalid_argument("empty backup .sha256 checksum file"))?;
    Ok(hex_token.to_owned())
}

fn copy_mvcc_snapshot_db(
    source_db: &Database,
    dest_path: &Path,
    overlay: EmergencySnapshotOverlay<'_>,
    now_unix_ms: u64,
) -> AppResult<bool> {
    remove_if_exists(dest_path)?;
    let rtx = source_db
        .begin_read()
        .map_err(|e| map_store_err("begin MVCC snapshot read tx", e))?;
    let dest_db =
        Database::create(dest_path).map_err(|e| map_store_err("create snapshot redb file", e))?;
    let wtx = dest_db
        .begin_write()
        .map_err(|e| map_store_err("begin snapshot write tx", e))?;
    ensure_all_tables(&wtx)?;

    let has_identity = copy_str_bytes_table(&rtx, &wtx, TABLE_SERVER_IDENTITY)?;
    let _ = copy_str_bytes_table(&rtx, &wtx, TABLE_SCHEMA_META)?;
    copy_u128_bytes_table(&rtx, &wtx, TABLE_NODES)?;
    copy_pk_u128_table(&rtx, &wtx, TABLE_IDX_NODES_PUBKEY)?;
    copy_u32_u128_table(&rtx, &wtx, TABLE_IDX_NODES_OVERLAY_IP)?;
    copy_str_u128_table(&rtx, &wtx, TABLE_IDX_NODES_NAME)?;
    copy_u128_bytes_table(&rtx, &wtx, TABLE_PREAUTH_KEYS)?;
    copy_pk_u128_table(&rtx, &wtx, TABLE_IDX_PREAUTH_HASH)?;
    copy_u64_bytes_table(&rtx, &wtx, TABLE_AUDIT_EVENTS)?;

    for entry in overlay.pending_nodes {
        if let Err(err) = NodesRepository::apply_compacted_revocation_in_tx(
            &wtx,
            entry.node_id,
            entry.pubkey_bytes,
            entry.revoked_at_ms,
            entry.reason == EmergencyNodeReason::Expired,
        ) && err.kind() != ErrorKind::NotFound
        {
            tracing::warn!(
                component = "mesh-store",
                event = "backup_fold_node_error",
                node_id = %entry.node_id,
                error = %err,
                "failed folding pending emergency node revocation into backup snapshot"
            );
        }
    }
    for key in overlay.pending_keys {
        if let Err(err) = KeysRepository::revoke_key_in_tx(
            &wtx,
            key.key_id,
            key.revoked_at_ms,
            "system:backup_fold",
        ) {
            tracing::warn!(
                component = "mesh-store",
                event = "backup_fold_key_warn",
                key_id = %key.key_id,
                error = %err,
                "failed folding pending emergency key revocation into backup snapshot"
            );
        }
    }
    if overlay.min_netmap_version > 0 {
        let mut meta = wtx
            .open_table(TABLE_SCHEMA_META)
            .map_err(|e| map_store_err("open meta snapshot watermark floor", e))?;
        let cur = match meta
            .get(META_KEY_WATERMARK)
            .map_err(|e| map_store_err("read snapshot watermark", e))?
        {
            Some(g) => decode_u64_be(g.value())?,
            None => 0,
        };
        let raised = cur.max(overlay.min_netmap_version);
        if raised > cur {
            meta.insert(META_KEY_WATERMARK, encode_u64_be(raised).as_slice())
                .map_err(|e| map_store_err("raise snapshot watermark floor", e))?;
        }
    }
    if !overlay.pending_nodes.is_empty() || !overlay.pending_keys.is_empty() {
        let fold_audit = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor: "system:backup_fold",
            action: "backup_folded_emergency_revocations",
            target: "server",
            outcome: "success",
            metadata: serde_json::json!({
                "nodes_folded": overlay.pending_nodes.len(),
                "keys_folded": overlay.pending_keys.len(),
            }),
        };
        AuditRepository::append_audit_in_tx(&wtx, &fold_audit)?;
    }

    wtx.commit()
        .map_err(|e| map_store_err("commit snapshot redb", e))?;
    Ok(has_identity)
}

fn copy_str_bytes_table(
    rtx: &ReadTransaction,
    wtx: &WriteTransaction,
    def: TableDefinition<'static, &str, &[u8]>,
) -> AppResult<bool> {
    let src = rtx
        .open_table(def)
        .map_err(|e| map_store_err("open src str->bytes", e))?;
    let mut dst = wtx
        .open_table(def)
        .map_err(|e| map_store_err("open dst str->bytes", e))?;
    let mut non_empty = false;
    for row in src
        .iter()
        .map_err(|e| map_store_err("iter str->bytes", e))?
    {
        let (k, v) = row.map_err(|e| map_store_err("row str->bytes", e))?;
        dst.insert(k.value(), v.value())
            .map_err(|e| map_store_err("insert str->bytes", e))?;
        non_empty = true;
    }
    Ok(non_empty)
}

fn copy_u128_bytes_table(
    rtx: &ReadTransaction,
    wtx: &WriteTransaction,
    def: TableDefinition<'static, u128, &[u8]>,
) -> AppResult<()> {
    let src = rtx
        .open_table(def)
        .map_err(|e| map_store_err("open src u128->bytes", e))?;
    let mut dst = wtx
        .open_table(def)
        .map_err(|e| map_store_err("open dst u128->bytes", e))?;
    for row in src
        .iter()
        .map_err(|e| map_store_err("iter u128->bytes", e))?
    {
        let (k, v) = row.map_err(|e| map_store_err("row u128->bytes", e))?;
        dst.insert(k.value(), v.value())
            .map_err(|e| map_store_err("insert u128->bytes", e))?;
    }
    Ok(())
}

fn copy_u64_bytes_table(
    rtx: &ReadTransaction,
    wtx: &WriteTransaction,
    def: TableDefinition<'static, u64, &[u8]>,
) -> AppResult<()> {
    let src = rtx
        .open_table(def)
        .map_err(|e| map_store_err("open src u64->bytes", e))?;
    let mut dst = wtx
        .open_table(def)
        .map_err(|e| map_store_err("open dst u64->bytes", e))?;
    for row in src
        .iter()
        .map_err(|e| map_store_err("iter u64->bytes", e))?
    {
        let (k, v) = row.map_err(|e| map_store_err("row u64->bytes", e))?;
        dst.insert(k.value(), v.value())
            .map_err(|e| map_store_err("insert u64->bytes", e))?;
    }
    Ok(())
}

fn copy_pk_u128_table(
    rtx: &ReadTransaction,
    wtx: &WriteTransaction,
    def: TableDefinition<'static, &[u8; 32], u128>,
) -> AppResult<()> {
    let src = rtx
        .open_table(def)
        .map_err(|e| map_store_err("open src [u8;32]->u128", e))?;
    let mut dst = wtx
        .open_table(def)
        .map_err(|e| map_store_err("open dst [u8;32]->u128", e))?;
    for row in src
        .iter()
        .map_err(|e| map_store_err("iter [u8;32]->u128", e))?
    {
        let (k, v) = row.map_err(|e| map_store_err("row [u8;32]->u128", e))?;
        dst.insert(k.value(), v.value())
            .map_err(|e| map_store_err("insert [u8;32]->u128", e))?;
    }
    Ok(())
}

fn copy_u32_u128_table(
    rtx: &ReadTransaction,
    wtx: &WriteTransaction,
    def: TableDefinition<'static, u32, u128>,
) -> AppResult<()> {
    let src = rtx
        .open_table(def)
        .map_err(|e| map_store_err("open src u32->u128", e))?;
    let mut dst = wtx
        .open_table(def)
        .map_err(|e| map_store_err("open dst u32->u128", e))?;
    for row in src.iter().map_err(|e| map_store_err("iter u32->u128", e))? {
        let (k, v) = row.map_err(|e| map_store_err("row u32->u128", e))?;
        dst.insert(k.value(), v.value())
            .map_err(|e| map_store_err("insert u32->u128", e))?;
    }
    Ok(())
}

fn copy_str_u128_table(
    rtx: &ReadTransaction,
    wtx: &WriteTransaction,
    def: TableDefinition<'static, &str, u128>,
) -> AppResult<()> {
    let src = rtx
        .open_table(def)
        .map_err(|e| map_store_err("open src str->u128", e))?;
    let mut dst = wtx
        .open_table(def)
        .map_err(|e| map_store_err("open dst str->u128", e))?;
    for row in src.iter().map_err(|e| map_store_err("iter str->u128", e))? {
        let (k, v) = row.map_err(|e| map_store_err("row str->u128", e))?;
        dst.insert(k.value(), v.value())
            .map_err(|e| map_store_err("insert str->u128", e))?;
    }
    Ok(())
}

fn prune_old_backups(backup_dir: &Path, prefix: &str, keep: usize) -> AppResult<()> {
    let match_prefix = format!("{prefix}-");
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let entries = fs::read_dir(backup_dir).map_err(|err| {
        AppError::unavailable(format!("failed scanning backup dir for pruning: {err}"))
    })?;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with(&match_prefix) && name.ends_with(".redb") {
            files.push((name.to_owned(), path));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    if files.len() <= keep {
        return Ok(());
    }
    let remove_count = files.len() - keep;
    for (_, path) in files.into_iter().take(remove_count) {
        let sha_path = path.with_extension("sha256");
        if let Err(err) = fs::remove_file(&path) {
            tracing::warn!(
                component = "mesh-store",
                event = "backup_prune_failed",
                path = %path.display(),
                error = %err,
                "failed removing pruned backup snapshot"
            );
        }
        if sha_path.exists()
            && let Err(err) = fs::remove_file(&sha_path)
        {
            tracing::warn!(
                component = "mesh-store",
                event = "backup_prune_checksum_failed",
                path = %sha_path.display(),
                error = %err,
                "failed removing pruned backup checksum sidecar"
            );
        }
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> AppResult<()> {
    if path.exists() {
        fs::remove_file(path).map_err(|err| {
            AppError::unavailable(format!("failed removing {}: {err}", path.display()))
        })?;
    }
    Ok(())
}

fn write_restricted_file(path: &Path, content: &[u8]) -> AppResult<()> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|err| {
        AppError::unavailable(format!("failed creating {}: {err}", path.display()))
    })?;
    file.write_all(content).map_err(|err| {
        AppError::unavailable(format!("failed writing {}: {err}", path.display()))
    })?;
    file.sync_all().map_err(|err| {
        AppError::unavailable(format!("failed syncing {}: {err}", path.display()))
    })?;
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms).map_err(|err| {
        AppError::unavailable(format!("failed chmod 0600 {}: {err}", path.display()))
    })
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, perms).map_err(|err| {
        AppError::unavailable(format!("failed chmod 0700 {}: {err}", path.display()))
    })
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_hot_backup_retention_checksum_and_tamper_rejection() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("control.redb");
        let backup_dir = dir.path().join("backups");
        let db = Database::create(&db_path).expect("create db");
        let wtx = db.begin_write().expect("begin write");
        ensure_all_tables(&wtx).expect("ensure tables");
        NodesRepository::set_overlay_cidr_in_tx(&wtx, "10.100.0.0/24", 1_731_480_000_000, "sys")
            .expect("set overlay cidr");
        wtx.commit().expect("commit setup");
        IdentityRepository::ensure_or_init_identity(
            &db,
            &["127.0.0.1".to_owned()],
            365,
            1_731_480_000_000,
        )
        .expect("init identity");

        // Act: create 9 snapshots with retention 7
        let mut latest = None;
        for i in 1..=9_u64 {
            let art = BackupManager::create_snapshot(
                &db,
                &backup_dir,
                "daily",
                1_731_480_000_000 + i * 1_000,
                DEFAULT_BACKUP_RETENTION,
            )
            .expect("create snapshot");
            latest = Some(art);
        }

        // Assert: only 7 `.redb` files remain
        let kept_count = fs::read_dir(&backup_dir)
            .expect("read_dir")
            .flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("redb"))
            .count();
        assert_eq!(kept_count, DEFAULT_BACKUP_RETENTION);

        let art = latest.expect("latest backup artifact");
        assert!(art.contains_server_identity);
        BackupManager::verify_snapshot_checksum(&art.snapshot_path).expect("verify checksum");

        // Corrupt the backup bytes -> restore MUST fail cleanly
        let mut file = OpenOptions::new()
            .write(true)
            .open(&art.snapshot_path)
            .expect("open snapshot for tamper");
        file.write_all(b"CORRUPTED").expect("tamper snapshot");
        drop(file);

        let target_db = dir.path().join("restored.redb");
        let emerg = dir.path().join("emergency-revocations.bin");
        let restore_res = BackupManager::restore_from_snapshot(&RestoreOptions {
            snapshot_path: art.snapshot_path,
            target_db_path: target_db,
            target_emergency_path: emerg,
            expected_published_pin: None,
            allow_pin_change: false,
            verify_sha256: true,
            min_netmap_version: 0,
            min_required_snapshot_version: None,
        });
        assert!(restore_res.is_err());
    }

    #[test]
    fn test_restore_retains_before_restore_copy_with_restricted_permissions() {
        // Arrange
        let dir_res = TempDir::new();
        assert!(dir_res.is_ok(), "tempdir creation failed: {dir_res:?}");
        let Ok(dir) = dir_res else {
            return;
        };
        let db_path = dir.path().join("control.redb");
        let backup_dir = dir.path().join("backups");
        let emerg_path = dir.path().join("emergency-revocations.bin");
        let db_res = Database::create(&db_path);
        assert!(db_res.is_ok(), "db create failed: {db_res:?}");
        let Ok(db) = db_res else {
            return;
        };
        let wtx_res = db.begin_write();
        assert!(
            wtx_res.is_ok(),
            "begin write failed: {:?}",
            wtx_res.as_ref().err()
        );
        let Ok(wtx) = wtx_res else {
            return;
        };
        assert!(ensure_all_tables(&wtx).is_ok());
        assert!(
            NodesRepository::set_overlay_cidr_in_tx(
                &wtx,
                "10.100.0.0/24",
                1_731_480_000_000,
                "sys",
            )
            .is_ok()
        );
        assert!(wtx.commit().is_ok());
        let id_res = IdentityRepository::ensure_or_init_identity(
            &db,
            &["127.0.0.1".to_owned()],
            365,
            1_731_480_000_000,
        );
        assert!(id_res.is_ok(), "init identity failed: {id_res:?}");
        let Ok(identity) = id_res else {
            return;
        };
        let art_res = BackupManager::create_snapshot(
            &db,
            &backup_dir,
            "daily",
            1_731_480_000_500,
            DEFAULT_BACKUP_RETENTION,
        );
        assert!(art_res.is_ok(), "create snapshot failed: {art_res:?}");
        let Ok(art) = art_res else {
            return;
        };
        drop(db);

        // Act
        let restore_res = BackupManager::restore_from_snapshot(&RestoreOptions {
            snapshot_path: art.snapshot_path,
            target_db_path: db_path,
            target_emergency_path: emerg_path,
            expected_published_pin: Some(identity.spki_pin),
            allow_pin_change: false,
            verify_sha256: true,
            min_netmap_version: 1_731_480_001_000,
            min_required_snapshot_version: None,
        });

        // Assert: `<target_db_path>.before-restore` MUST be retained cleanly with 0600 mode.
        assert!(restore_res.is_ok(), "restore failed: {restore_res:?}");
        let before_restore_path = dir.path().join("control.redb.before-restore");
        assert!(
            before_restore_path.exists(),
            "expected preserved copy at {}",
            before_restore_path.display()
        );
        assert!(!dir.path().join(".control.redb.rollback").exists());
        assert!(Database::open(&before_restore_path).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let meta_res = fs::metadata(&before_restore_path);
            assert!(meta_res.is_ok(), "metadata failed: {meta_res:?}");
            if let Ok(meta) = meta_res {
                assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            }
        }
    }
}
