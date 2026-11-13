//! In-memory `RevokedSet`, pre-allocated `64 KiB` Slot A/B emergency revocation log,
//! fail-closed boot validation, and recovery compaction (`SEC-08`, `US-029`, `WP-S1-01`).

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use mesh_core::brand::EMERGENCY_REVOKE_MAGIC;
use mesh_core::{AppError, AppResult, KeyId, NodeId, PublicKey};
use mesh_proto::admin_ipc::PersistenceTier;

use crate::schema::{decode_u32_be, decode_u64_be, encode_u32_be, encode_u64_be};

/// Fixed `64 KiB` size of `emergency-revocations.bin` (Slot A `32 KiB` + Slot B `32 KiB`).
pub const EMERGENCY_REVOCATION_FILE_BYTES: usize = 65_536;

/// Magic header stamped at byte 0 of every `32 KiB` emergency revocation slot.
pub const EMERGENCY_SLOT_MAGIC: [u8; 8] = EMERGENCY_REVOKE_MAGIC;

/// Size of a single atomic emergency slot (`32 KiB`).
pub const EMERGENCY_SLOT_BYTES: usize = 32_768;

/// Header byte length inside each `32 KiB` slot (`8 magic + 2 version + 2 flags + 8 seq + 8 min_ver + 2 nc + 2 kc + 4 crc32`).
pub const EMERGENCY_HEADER_BYTES: usize = 36;

/// Encoded byte size per revoked node entry (`16 NodeId + 32 PublicKey + 8 timestamp + 8 min_netmap_version + 1 reason`).
pub const EMERGENCY_NODE_ENTRY_BYTES: usize = 65;

/// Encoded byte size per revoked key entry (`16 KeyId + 8 timestamp`).
pub const EMERGENCY_KEY_ENTRY_BYTES: usize = 24;

/// Maximum number of node entries tracked inside one on-disk slot (`database-design.md` §3.3).
pub const MAX_SLOT_NODES: usize = 500;

/// Maximum number of pre-auth key entries tracked inside one on-disk slot (`database-design.md` §3.3).
pub const MAX_SLOT_KEYS: usize = 250;

const SLOT_FORMAT_VERSION: u16 = 2;

/// Lock-friendly memory cache of revoked node, public-key, and pre-auth key identifiers (`SEC-08`).
#[derive(Debug, Default, Clone)]
pub struct RevokedSet {
    nodes: HashSet<NodeId>,
    pubkeys: HashSet<[u8; 32]>,
    keys: HashSet<KeyId>,
}

impl RevokedSet {
    /// Creates an empty [`RevokedSet`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `node_id` has been revoked.
    #[must_use]
    pub fn contains(&self, node_id: NodeId) -> bool {
        self.nodes.contains(&node_id)
    }

    /// Returns `true` if a WireGuard node `pubkey` has been revoked or expired.
    #[must_use]
    pub fn contains_pubkey(&self, pubkey: &PublicKey) -> bool {
        self.pubkeys.contains(pubkey.as_bytes())
    }

    /// Returns `true` if a pre-authentication `key_id` has been revoked.
    #[must_use]
    pub fn contains_key(&self, key_id: KeyId) -> bool {
        self.keys.contains(&key_id)
    }

    /// Records `node_id` into the in-memory revocation set.
    pub fn insert(&mut self, node_id: NodeId) {
        self.nodes.insert(node_id);
    }

    /// Records both `node_id` and its optional `PublicKey` into the in-memory revocation set.
    pub fn insert_node_with_pubkey(&mut self, node_id: NodeId, pubkey: Option<&PublicKey>) {
        self.nodes.insert(node_id);
        if let Some(pk) = pubkey {
            self.pubkeys.insert(*pk.as_bytes());
        }
    }

    /// Blocks a superseded node public key without marking `node_id` revoked (`BLK-S1-01`).
    pub fn insert_rotated_pubkey(&mut self, pubkey: &PublicKey) {
        self.pubkeys.insert(*pubkey.as_bytes());
    }

    /// Records a revoked pre-authentication `key_id` into RAM.
    pub fn insert_key(&mut self, key_id: KeyId) {
        self.keys.insert(key_id);
    }
}

/// Reason a node revocation was recorded in memory/slot before `redb` recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyNodeReason {
    /// Explicit administrative revocation (`US-029`).
    Revoked,
    /// Key lifetime expiration (`US-031`).
    Expired,
}

/// Unmerged node revocation kept in [`EmergencyRevocationState`] until `redb` compaction succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRevocationNodeEntry {
    /// Identifier of the revoked or expired node.
    pub node_id: NodeId,
    /// Public key `[u8; 32]` (`[0; 32]` when unavailable during fallback).
    pub pubkey_bytes: [u8; 32],
    /// UTC epoch milliseconds when the revocation occurred.
    pub revoked_at_ms: u64,
    /// Minimum Netmap version monotonic floor guaranteed across reboots (`HR-S1-04`).
    pub min_netmap_version: u64,
    /// Revoked vs expired transition tag for `redb` compaction.
    pub reason: EmergencyNodeReason,
    /// Persistence tier reached when this item was accepted (`EmergencySlot` vs `RamOnly`).
    pub tier: PersistenceTier,
}

/// Unmerged pre-auth key revocation kept in [`EmergencyRevocationState`] until compaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRevocationKeyEntry {
    /// Identifier of the revoked pre-auth key.
    pub key_id: KeyId,
    /// UTC epoch milliseconds when revoked.
    pub revoked_at_ms: u64,
    /// Persistence tier reached when this item was accepted.
    pub tier: PersistenceTier,
}

/// Decoded snapshot of one `32 KiB` emergency slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEmergencySlot {
    /// Monotonic slot generation sequence number.
    pub seq_no: u64,
    /// Minimum Netmap version floor preserved in this emergency slot (`HR-S1-04`).
    pub min_netmap_version: u64,
    /// Node revocations stored in this slot.
    pub nodes: Vec<EmergencyRevocationNodeEntry>,
    /// Key revocations stored in this slot.
    pub keys: Vec<EmergencyRevocationKeyEntry>,
}

/// Encapsulated file I/O abstraction enabling deterministic fault-injection unit tests
/// (`ENOSPC`, `EIO`, corruption) without kernel disk fills.
pub trait EmergencyFileBackend: Send + Sync {
    /// Returns `true` if the emergency file exists.
    fn exists(&self, path: &Path) -> bool;

    /// Returns the byte length of the emergency file if present.
    fn file_len(&self, path: &Path) -> io::Result<u64>;

    /// Atomically creates and pre-allocates the full `65_536 B` emergency file.
    fn create_preallocated(&self, path: &Path, full_image: &[u8]) -> io::Result<()>;

    /// Reads the entire `65_536 B` emergency file into memory.
    fn read_all(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Writes exactly `32_768 B` to `offset` (`0` for Slot A, `32_768` for Slot B) and fsyncs.
    fn write_slot_synced(&self, path: &Path, offset: u64, slot_bytes: &[u8]) -> io::Result<()>;
}

/// Production OS filesystem backend for `emergency-revocations.bin`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEmergencyFileBackend;

impl EmergencyFileBackend for OsEmergencyFileBackend {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn file_len(&self, path: &Path) -> io::Result<u64> {
        Ok(fs::metadata(path)?.len())
    }

    fn create_preallocated(&self, path: &Path, full_image: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        file.write_all(full_image)?;
        file.sync_all()?;
        Ok(())
    }

    fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut buf = Vec::with_capacity(EMERGENCY_REVOCATION_FILE_BYTES);
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn write_slot_synced(&self, path: &Path, offset: u64, slot_bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(slot_bytes)?;
        file.sync_data()?;
        Ok(())
    }
}

/// In-memory + pre-allocated A/B emergency slot coordinator (`database-design.md` §3.3).
#[derive(Debug, Clone)]
pub struct EmergencyRevocationState {
    /// Path to `emergency-revocations.bin`.
    pub emergency_file_path: PathBuf,
    /// True whenever unmerged emergency revocations exist or primary `redb` I/O has degraded.
    pub disk_degraded: bool,
    /// Human-readable non-secret explanation when `disk_degraded == true`.
    pub degraded_reason: Option<String>,
    /// Next slot generation sequence number to assign on slot flip.
    pub current_seq_no: u64,
    /// Monotonic Netmap version floor carried by emergency slot writes (`HR-S1-04`).
    pub min_netmap_version: u64,
    /// Active slot (`0` = Slot A offset `0`, `1` = Slot B offset `32_768`).
    pub active_slot: u8,
    /// Full set of unmerged node revocations across BOTH `EmergencySlot` AND `RamOnly` tiers.
    pub pending_nodes: Vec<EmergencyRevocationNodeEntry>,
    /// Full set of unmerged key revocations across BOTH `EmergencySlot` AND `RamOnly` tiers.
    pub pending_keys: Vec<EmergencyRevocationKeyEntry>,
}

impl EmergencyRevocationState {
    /// Initializes or fail-closed-verifies `emergency-revocations.bin` on startup.
    pub fn boot_open_with_backend(
        emergency_file_path: PathBuf,
        redb_existed: bool,
        backend: &dyn EmergencyFileBackend,
    ) -> AppResult<(Self, RevokedSet)> {
        if !backend.exists(&emergency_file_path) {
            if redb_existed {
                return Err(AppError::unavailable(format!(
                    "fail-closed boot: {} missing while primary redb exists",
                    emergency_file_path.display()
                )));
            }
            let image = build_clean_initial_image()?;
            backend
                .create_preallocated(&emergency_file_path, &image)
                .map_err(|err| {
                    AppError::unavailable(format!(
                        "failed pre-allocating emergency revocation file {}: {err}",
                        emergency_file_path.display()
                    ))
                })?;
            let state = Self {
                emergency_file_path,
                disk_degraded: false,
                degraded_reason: None,
                current_seq_no: 1,
                min_netmap_version: 0,
                active_slot: 0,
                pending_nodes: Vec::new(),
                pending_keys: Vec::new(),
            };
            return Ok((state, RevokedSet::new()));
        }

        let len = backend.file_len(&emergency_file_path).map_err(|err| {
            AppError::unavailable(format!("failed reading emergency file metadata: {err}"))
        })?;
        if len < EMERGENCY_REVOCATION_FILE_BYTES as u64 {
            return Err(AppError::unavailable(format!(
                "fail-closed boot: emergency file truncated ({len} < {EMERGENCY_REVOCATION_FILE_BYTES})"
            )));
        }

        let raw = backend.read_all(&emergency_file_path).map_err(|err| {
            AppError::unavailable(format!(
                "fail-closed boot: failed reading emergency file: {err}"
            ))
        })?;
        recover_from_file_bytes(emergency_file_path, &raw, backend)
    }

    /// Persists an emergency node revocation into the standby slot (`A`/`B` flip) or falls back
    /// cleanly to `RamOnly` without ever evicting older unmerged items (`database-design.md` §3.3).
    pub fn record_emergency_node(
        &mut self,
        revoked_ram: &mut RevokedSet,
        entry: EmergencyRevocationNodeEntry,
        reason: &str,
        backend: &dyn EmergencyFileBackend,
    ) -> PersistenceTier {
        let pk_opt = PublicKey::from_bytes(entry.pubkey_bytes).ok();
        revoked_ram.insert_node_with_pubkey(
            entry.node_id,
            pk_opt.as_ref().filter(|_| entry.pubkey_bytes != [0_u8; 32]),
        );

        let already_pending = self
            .pending_nodes
            .iter()
            .position(|existing| existing.node_id == entry.node_id);
        let candidate_nodes = if let Some(idx) = already_pending {
            let mut copy = self.pending_nodes.clone();
            if let Some(slot) = copy.get_mut(idx) {
                *slot = entry.clone();
            }
            copy
        } else {
            let mut copy = self.pending_nodes.clone();
            copy.push(entry.clone());
            copy
        };

        self.min_netmap_version = self.min_netmap_version.max(entry.min_netmap_version);
        let tier = flush_slot_state(
            EmergencySlotMeta {
                emergency_file_path: &self.emergency_file_path,
                current_seq_no: &mut self.current_seq_no,
                min_netmap_version: self.min_netmap_version,
                active_slot: &mut self.active_slot,
            },
            &candidate_nodes,
            &self.pending_keys,
            backend,
        );
        let mut stored = entry;
        stored.tier = tier;
        if let Some(idx) = already_pending {
            if let Some(existing) = self.pending_nodes.get_mut(idx) {
                *existing = stored;
            }
        } else {
            self.pending_nodes.push(stored);
        }
        self.disk_degraded = true;
        self.degraded_reason = Some(reason.to_owned());
        tier
    }

    /// Persists an emergency pre-auth key revocation into Slot A/B or degrades to `RamOnly`
    /// without evicting older unmerged records.
    pub fn record_emergency_key(
        &mut self,
        revoked_ram: &mut RevokedSet,
        entry: EmergencyRevocationKeyEntry,
        reason: &str,
        backend: &dyn EmergencyFileBackend,
    ) -> PersistenceTier {
        revoked_ram.insert_key(entry.key_id);

        let already_pending = self
            .pending_keys
            .iter()
            .position(|existing| existing.key_id == entry.key_id);
        let mut candidate_keys = self.pending_keys.clone();
        if let Some(idx) = already_pending {
            if let Some(slot) = candidate_keys.get_mut(idx) {
                *slot = entry.clone();
            }
        } else {
            candidate_keys.push(entry.clone());
        }

        let tier = flush_slot_state(
            EmergencySlotMeta {
                emergency_file_path: &self.emergency_file_path,
                current_seq_no: &mut self.current_seq_no,
                min_netmap_version: self.min_netmap_version,
                active_slot: &mut self.active_slot,
            },
            &self.pending_nodes,
            &candidate_keys,
            backend,
        );
        let mut stored = entry;
        stored.tier = tier;
        if let Some(idx) = already_pending {
            if let Some(existing) = self.pending_keys.get_mut(idx) {
                *existing = stored;
            }
        } else {
            self.pending_keys.push(stored);
        }
        self.disk_degraded = true;
        self.degraded_reason = Some(reason.to_owned());
        tier
    }

    /// Clears all pending revocations ONLY AFTER the caller committed them into `control.redb`,
    /// writing a clean 0-entry checkpoint slot to `emergency-revocations.bin`.
    pub fn finalize_compaction_after_redb_commit(
        &mut self,
        min_netmap_version: u64,
        backend: &dyn EmergencyFileBackend,
    ) -> AppResult<()> {
        let next_seq = self.current_seq_no.saturating_add(1);
        let next_min_ver = self.min_netmap_version.max(min_netmap_version);
        let next_slot = self.active_slot ^ 1;
        let offset = slot_byte_offset(next_slot);
        let encoded = encode_slot(next_seq, next_min_ver, &[], &[])?;

        backend
            .write_slot_synced(&self.emergency_file_path, offset, &encoded)
            .map_err(|err| {
                AppError::unavailable(format!(
                    "failed clearing emergency slot during compaction: {err}"
                ))
            })?;

        self.current_seq_no = next_seq;
        self.min_netmap_version = next_min_ver;
        self.active_slot = next_slot;
        self.pending_nodes.clear();
        self.pending_keys.clear();
        self.disk_degraded = false;
        self.degraded_reason = None;
        Ok(())
    }

    /// Writes a clean checkpoint slot mirroring a restored `netmap_version_watermark`
    /// atomically AFTER the restored `control.redb` has been opened successfully (`BLK-S1-04`).
    pub fn reset_after_restore_commit(
        &mut self,
        restored_watermark: u64,
        backend: &dyn EmergencyFileBackend,
    ) -> AppResult<()> {
        let next_seq = self.current_seq_no.saturating_add(1);
        let next_min_ver = self.min_netmap_version.max(restored_watermark);
        let next_slot = self.active_slot ^ 1;
        let offset = slot_byte_offset(next_slot);
        let encoded = encode_slot(next_seq, next_min_ver, &[], &[])?;

        backend
            .write_slot_synced(&self.emergency_file_path, offset, &encoded)
            .map_err(|err| {
                AppError::unavailable(format!(
                    "failed resetting emergency slot after restore: {err}"
                ))
            })?;

        self.current_seq_no = next_seq;
        self.min_netmap_version = next_min_ver;
        self.active_slot = next_slot;
        self.pending_nodes.clear();
        self.pending_keys.clear();
        self.disk_degraded = false;
        self.degraded_reason = None;
        Ok(())
    }

    /// Returns whether any pending unmerged revocations remain in RAM/emergency slots.
    #[must_use]
    pub fn has_unmerged_entries(&self) -> bool {
        !self.pending_nodes.is_empty() || !self.pending_keys.is_empty()
    }
}

struct EmergencySlotMeta<'a> {
    emergency_file_path: &'a Path,
    current_seq_no: &'a mut u64,
    min_netmap_version: u64,
    active_slot: &'a mut u8,
}

fn flush_slot_state(
    meta: EmergencySlotMeta<'_>,
    candidate_nodes: &[EmergencyRevocationNodeEntry],
    candidate_keys: &[EmergencyRevocationKeyEntry],
    backend: &dyn EmergencyFileBackend,
) -> PersistenceTier {
    if !fits_in_emergency_slot(candidate_nodes.len(), candidate_keys.len()) {
        return PersistenceTier::RamOnly;
    }
    let next_seq = meta.current_seq_no.saturating_add(1);
    let next_slot = *meta.active_slot ^ 1;
    let Ok(encoded) = encode_slot(
        next_seq,
        meta.min_netmap_version,
        candidate_nodes,
        candidate_keys,
    ) else {
        return PersistenceTier::RamOnly;
    };
    let offset = slot_byte_offset(next_slot);
    match backend.write_slot_synced(meta.emergency_file_path, offset, &encoded) {
        Ok(()) => {
            *meta.current_seq_no = next_seq;
            *meta.active_slot = next_slot;
            PersistenceTier::EmergencySlot
        }
        Err(err) => {
            tracing::error!(
                component = "mesh-store",
                event = "emergency_slot_write_failed",
                error = %err,
                "emergency slot write failed; retaining revocation in RAM-only tier"
            );
            PersistenceTier::RamOnly
        }
    }
}

const fn slot_byte_offset(slot_idx: u8) -> u64 {
    if slot_idx == 0 {
        0
    } else {
        EMERGENCY_SLOT_BYTES as u64
    }
}

fn fits_in_emergency_slot(node_count: usize, key_count: usize) -> bool {
    if node_count > MAX_SLOT_NODES || key_count > MAX_SLOT_KEYS {
        return false;
    }
    let payload_bytes = node_count
        .saturating_mul(EMERGENCY_NODE_ENTRY_BYTES)
        .saturating_add(key_count.saturating_mul(EMERGENCY_KEY_ENTRY_BYTES));
    EMERGENCY_HEADER_BYTES.saturating_add(payload_bytes) <= EMERGENCY_SLOT_BYTES
}

fn build_clean_initial_image() -> AppResult<Vec<u8>> {
    let mut image = Vec::with_capacity(EMERGENCY_REVOCATION_FILE_BYTES);
    let slot_a = encode_slot(1, 0, &[], &[])?;
    let slot_b = encode_slot(0, 0, &[], &[])?;
    image.extend_from_slice(&slot_a);
    image.extend_from_slice(&slot_b);
    Ok(image)
}

fn recover_from_file_bytes(
    path: PathBuf,
    raw: &[u8],
    backend: &dyn EmergencyFileBackend,
) -> AppResult<(EmergencyRevocationState, RevokedSet)> {
    let slot_a_bytes = raw
        .get(0..EMERGENCY_SLOT_BYTES)
        .ok_or_else(|| AppError::unavailable("emergency file too short for Slot A"))?;
    let slot_b_bytes = raw
        .get(EMERGENCY_SLOT_BYTES..EMERGENCY_REVOCATION_FILE_BYTES)
        .ok_or_else(|| AppError::unavailable("emergency file too short for Slot B"))?;

    let decoded_a = decode_slot(slot_a_bytes);
    let decoded_b = decode_slot(slot_b_bytes);

    let (active_slot, chosen, repair_other_slot) = match (decoded_a, decoded_b) {
        (Ok(a), Ok(b)) => {
            if b.seq_no > a.seq_no {
                (1_u8, b, false)
            } else {
                (0_u8, a, false)
            }
        }
        (Ok(a), Err(_)) => (0_u8, a, true),
        (Err(_), Ok(b)) => (1_u8, b, true),
        (Err(err_a), Err(err_b)) => {
            return Err(AppError::unavailable(format!(
                "fail-closed boot: both emergency slots corrupted (slotA: {err_a}; slotB: {err_b})"
            )));
        }
    };

    if repair_other_slot {
        let bad_slot = active_slot ^ 1;
        let repaired = encode_slot(
            chosen.seq_no,
            chosen.min_netmap_version,
            &chosen.nodes,
            &chosen.keys,
        )?;
        backend
            .write_slot_synced(&path, slot_byte_offset(bad_slot), &repaired)
            .map_err(|err| {
                AppError::unavailable(format!(
                    "failed self-healing corrupted standby emergency slot: {err}"
                ))
            })?;
    }

    let mut revoked_ram = RevokedSet::new();
    for node in &chosen.nodes {
        let pk_opt = PublicKey::from_bytes(node.pubkey_bytes).ok();
        revoked_ram.insert_node_with_pubkey(
            node.node_id,
            pk_opt.as_ref().filter(|_| node.pubkey_bytes != [0_u8; 32]),
        );
    }
    for key in &chosen.keys {
        revoked_ram.insert_key(key.key_id);
    }

    let has_pending = !chosen.nodes.is_empty() || !chosen.keys.is_empty();
    let state = EmergencyRevocationState {
        emergency_file_path: path,
        disk_degraded: has_pending,
        degraded_reason: if has_pending {
            Some("recovered unmerged emergency revocations awaiting compaction".to_owned())
        } else {
            None
        },
        current_seq_no: chosen.seq_no,
        min_netmap_version: chosen.min_netmap_version,
        active_slot,
        pending_nodes: chosen.nodes,
        pending_keys: chosen.keys,
    };
    Ok((state, revoked_ram))
}

/// Reads the highest `min_netmap_version` floor across valid Slot A/B headers (`HR-S1-04`, `BLK-S1-04`).
pub fn read_slot_min_netmap_version(path: &Path) -> AppResult<u64> {
    let backend = OsEmergencyFileBackend;
    if !backend.exists(path) {
        return Ok(0);
    }
    let len = backend.file_len(path).map_err(|err| {
        AppError::unavailable(format!(
            "failed reading emergency revocation metadata: {err}"
        ))
    })?;
    if len < EMERGENCY_REVOCATION_FILE_BYTES as u64 {
        return Err(AppError::unavailable(format!(
            "emergency revocation file truncated ({len} < {EMERGENCY_REVOCATION_FILE_BYTES})"
        )));
    }
    let raw = backend.read_all(path).map_err(|err| {
        AppError::unavailable(format!("failed reading emergency revocation file: {err}"))
    })?;
    let slot_a = raw
        .get(0..EMERGENCY_SLOT_BYTES)
        .ok_or_else(|| AppError::unavailable("emergency file too short for Slot A"))?;
    let slot_b = raw
        .get(EMERGENCY_SLOT_BYTES..EMERGENCY_REVOCATION_FILE_BYTES)
        .ok_or_else(|| AppError::unavailable("emergency file too short for Slot B"))?;
    match (decode_slot(slot_a), decode_slot(slot_b)) {
        (Ok(a), Ok(b)) => Ok(a.min_netmap_version.max(b.min_netmap_version)),
        (Ok(a), Err(_)) => Ok(a.min_netmap_version),
        (Err(_), Ok(b)) => Ok(b.min_netmap_version),
        (Err(err_a), Err(err_b)) => Err(AppError::unavailable(format!(
            "both emergency slots corrupted during version check (slotA: {err_a}; slotB: {err_b})"
        ))),
    }
}

/// Encodes a fixed `32_768 B` emergency slot buffer with big-endian framing and CRC-32 checksum.
pub fn encode_slot(
    seq_no: u64,
    min_netmap_version: u64,
    nodes: &[EmergencyRevocationNodeEntry],
    keys: &[EmergencyRevocationKeyEntry],
) -> AppResult<[u8; EMERGENCY_SLOT_BYTES]> {
    if !fits_in_emergency_slot(nodes.len(), keys.len()) {
        return Err(AppError::invalid_argument(
            "emergency slot capacity exceeded",
        ));
    }
    let mut buf = [0_u8; EMERGENCY_SLOT_BYTES];
    let node_count_u16 = u16::try_from(nodes.len())
        .map_err(|_| AppError::internal("emergency slot node_count overflow"))?;
    let key_count_u16 = u16::try_from(keys.len())
        .map_err(|_| AppError::internal("emergency slot key_count overflow"))?;

    if let Some(magic_dst) = buf.get_mut(0..8) {
        magic_dst.copy_from_slice(&EMERGENCY_SLOT_MAGIC);
    }
    if let Some(ver_dst) = buf.get_mut(8..10) {
        ver_dst.copy_from_slice(&SLOT_FORMAT_VERSION.to_be_bytes());
    }
    if let Some(flags_dst) = buf.get_mut(10..12) {
        flags_dst.copy_from_slice(&0_u16.to_be_bytes());
    }
    if let Some(seq_dst) = buf.get_mut(12..20) {
        seq_dst.copy_from_slice(&encode_u64_be(seq_no));
    }
    if let Some(min_ver_dst) = buf.get_mut(20..28) {
        min_ver_dst.copy_from_slice(&encode_u64_be(min_netmap_version));
    }
    if let Some(nc_dst) = buf.get_mut(28..30) {
        nc_dst.copy_from_slice(&node_count_u16.to_be_bytes());
    }
    if let Some(kc_dst) = buf.get_mut(30..32) {
        kc_dst.copy_from_slice(&key_count_u16.to_be_bytes());
    }

    let mut cursor = EMERGENCY_HEADER_BYTES;
    for node in nodes {
        let end = cursor.saturating_add(EMERGENCY_NODE_ENTRY_BYTES);
        if let Some(dst) = buf.get_mut(cursor..end) {
            if let Some(id_part) = dst.get_mut(0..16) {
                id_part.copy_from_slice(node.node_id.as_bytes());
            }
            if let Some(pk_part) = dst.get_mut(16..48) {
                pk_part.copy_from_slice(&node.pubkey_bytes);
            }
            if let Some(ts_part) = dst.get_mut(48..56) {
                ts_part.copy_from_slice(&encode_u64_be(node.revoked_at_ms));
            }
            if let Some(mv_part) = dst.get_mut(56..64) {
                mv_part.copy_from_slice(&encode_u64_be(node.min_netmap_version));
            }
            if let Some(reason_part) = dst.get_mut(64..65) {
                let tag = match node.reason {
                    EmergencyNodeReason::Revoked => 1_u8,
                    EmergencyNodeReason::Expired => 2_u8,
                };
                reason_part.copy_from_slice(&[tag]);
            }
        }
        cursor = end;
    }

    for key in keys {
        let end = cursor.saturating_add(EMERGENCY_KEY_ENTRY_BYTES);
        if let Some(dst) = buf.get_mut(cursor..end) {
            if let Some(id_part) = dst.get_mut(0..16) {
                id_part.copy_from_slice(key.key_id.as_bytes());
            }
            if let Some(ts_part) = dst.get_mut(16..24) {
                ts_part.copy_from_slice(&encode_u64_be(key.revoked_at_ms));
            }
        }
        cursor = end;
    }

    let crc = compute_slot_crc32(&buf, cursor);
    if let Some(crc_dst) = buf.get_mut(32..36) {
        crc_dst.copy_from_slice(&encode_u32_be(crc));
    }
    Ok(buf)
}

/// Decodes and checksum-verifies one `32_768 B` emergency slot slice.
pub fn decode_slot(slot: &[u8]) -> AppResult<DecodedEmergencySlot> {
    if slot.len() != EMERGENCY_SLOT_BYTES {
        return Err(AppError::internal("invalid emergency slot length"));
    }
    let magic = slot
        .get(0..8)
        .ok_or_else(|| AppError::internal("missing slot magic"))?;
    if magic != EMERGENCY_SLOT_MAGIC {
        return Err(AppError::internal("invalid emergency slot magic"));
    }
    let version = read_u16_be(slot.get(8..10))?;
    if version != SLOT_FORMAT_VERSION {
        return Err(AppError::internal(format!(
            "unsupported emergency slot version {version}"
        )));
    }
    let seq_no = decode_u64_be(
        slot.get(12..20)
            .ok_or_else(|| AppError::internal("missing slot seq_no"))?,
    )?;
    let min_netmap_version = decode_u64_be(
        slot.get(20..28)
            .ok_or_else(|| AppError::internal("missing slot min_netmap_version"))?,
    )?;
    let node_count = usize::from(read_u16_be(slot.get(28..30))?);
    let key_count = usize::from(read_u16_be(slot.get(30..32))?);
    if !fits_in_emergency_slot(node_count, key_count) {
        return Err(AppError::internal("emergency slot counts exceed capacity"));
    }
    let stored_crc = decode_u32_be(
        slot.get(32..36)
            .ok_or_else(|| AppError::internal("missing slot crc32"))?,
    )?;

    let payload_end = EMERGENCY_HEADER_BYTES
        .saturating_add(node_count.saturating_mul(EMERGENCY_NODE_ENTRY_BYTES))
        .saturating_add(key_count.saturating_mul(EMERGENCY_KEY_ENTRY_BYTES));
    let expected_crc = compute_slot_crc32(slot, payload_end);
    if stored_crc != expected_crc {
        return Err(AppError::internal("emergency slot CRC32 mismatch"));
    }

    let mut nodes = Vec::with_capacity(node_count);
    let mut cursor = EMERGENCY_HEADER_BYTES;
    for _ in 0..node_count {
        let end = cursor.saturating_add(EMERGENCY_NODE_ENTRY_BYTES);
        let chunk = slot
            .get(cursor..end)
            .ok_or_else(|| AppError::internal("truncated node entry in emergency slot"))?;
        let id_bytes: [u8; 16] = chunk
            .get(0..16)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| AppError::internal("corrupt emergency node_id"))?;
        let pk_bytes: [u8; 32] = chunk
            .get(16..48)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| AppError::internal("corrupt emergency pubkey"))?;
        let revoked_at_ms = decode_u64_be(
            chunk
                .get(48..56)
                .ok_or_else(|| AppError::internal("corrupt emergency node timestamp"))?,
        )?;
        let entry_min_version = decode_u64_be(
            chunk
                .get(56..64)
                .ok_or_else(|| AppError::internal("corrupt emergency node min_netmap_version"))?,
        )?;
        let reason_tag = chunk
            .get(64)
            .copied()
            .ok_or_else(|| AppError::internal("corrupt emergency node reason"))?;
        let reason = match reason_tag {
            1 => EmergencyNodeReason::Revoked,
            2 => EmergencyNodeReason::Expired,
            other => {
                return Err(AppError::internal(format!(
                    "unsupported emergency node reason tag {other}"
                )));
            }
        };
        nodes.push(EmergencyRevocationNodeEntry {
            node_id: NodeId::from_bytes(id_bytes),
            pubkey_bytes: pk_bytes,
            revoked_at_ms,
            min_netmap_version: entry_min_version,
            reason,
            tier: PersistenceTier::EmergencySlot,
        });
        cursor = end;
    }

    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let end = cursor.saturating_add(EMERGENCY_KEY_ENTRY_BYTES);
        let chunk = slot
            .get(cursor..end)
            .ok_or_else(|| AppError::internal("truncated key entry in emergency slot"))?;
        let id_bytes: [u8; 16] = chunk
            .get(0..16)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| AppError::internal("corrupt emergency key_id"))?;
        let revoked_at_ms = decode_u64_be(
            chunk
                .get(16..24)
                .ok_or_else(|| AppError::internal("corrupt emergency key timestamp"))?,
        )?;
        keys.push(EmergencyRevocationKeyEntry {
            key_id: KeyId::from_bytes(id_bytes),
            revoked_at_ms,
            tier: PersistenceTier::EmergencySlot,
        });
        cursor = end;
    }

    Ok(DecodedEmergencySlot {
        seq_no,
        min_netmap_version,
        nodes,
        keys,
    })
}

fn compute_slot_crc32(slot: &[u8], payload_end: usize) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    if let Some(header_prefix) = slot.get(0..32) {
        hasher.update(header_prefix);
    }
    if let Some(payload) = slot.get(EMERGENCY_HEADER_BYTES..payload_end) {
        hasher.update(payload);
    }
    hasher.finalize()
}

fn read_u16_be(bytes_opt: Option<&[u8]>) -> AppResult<u16> {
    let raw = bytes_opt.ok_or_else(|| AppError::internal("missing u16 slot field"))?;
    let arr: [u8; 2] = raw
        .try_into()
        .map_err(|_| AppError::internal("corrupt u16 slot field"))?;
    Ok(u16::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tempfile::TempDir;

    use super::*;

    #[derive(Debug)]
    struct FaultableBackend {
        inner: OsEmergencyFileBackend,
        fail_writes: AtomicBool,
    }

    impl FaultableBackend {
        fn new(fail_writes: bool) -> Self {
            Self {
                inner: OsEmergencyFileBackend,
                fail_writes: AtomicBool::new(fail_writes),
            }
        }
    }

    impl EmergencyFileBackend for FaultableBackend {
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
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(io::Error::other("injected EIO on emergency slot write"));
            }
            self.inner.write_slot_synced(path, offset, slot_bytes)
        }
    }

    fn make_node_entry(seed: u64) -> EmergencyRevocationNodeEntry {
        EmergencyRevocationNodeEntry {
            node_id: NodeId::new_v7(1_731_480_000_000 + seed),
            pubkey_bytes: [u8::try_from(seed % 250 + 1).unwrap_or(1); 32],
            revoked_at_ms: 1_731_480_000_000 + seed,
            reason: EmergencyNodeReason::Revoked,
            min_netmap_version: 0,
            tier: PersistenceTier::EmergencySlot,
        }
    }

    #[test]
    fn test_emergency_revoke_enospc_persists_to_slot_and_survives_restart() {
        // Arrange: clean pre-allocated emergency file (simulating ENOSPC on redb)
        let Ok(dir) = TempDir::new() else {
            return;
        };
        let emerg_path = dir.path().join("emergency-revocations.bin");
        let backend = OsEmergencyFileBackend;
        let Ok((mut state, mut ram)) =
            EmergencyRevocationState::boot_open_with_backend(emerg_path.clone(), false, &backend)
        else {
            return;
        };
        let entry = make_node_entry(42);
        let pk = PublicKey::from_bytes(entry.pubkey_bytes).ok();

        // Act: persist emergency revocation to Slot B, then simulate process restart
        let tier =
            state.record_emergency_node(&mut ram, entry.clone(), "simulated redb ENOSPC", &backend);
        let reopened = EmergencyRevocationState::boot_open_with_backend(emerg_path, true, &backend);

        // Assert
        assert_eq!(tier, PersistenceTier::EmergencySlot);
        assert!(state.disk_degraded);
        assert!(ram.contains(entry.node_id));
        if let Ok(key) = pk.as_ref().ok_or(()) {
            assert!(ram.contains_pubkey(key));
        }
        assert!(reopened.is_ok());
        if let Ok((reopened_state, reopened_ram)) = reopened {
            assert!(reopened_state.disk_degraded);
            assert_eq!(reopened_state.pending_nodes.len(), 1);
            assert!(reopened_ram.contains(entry.node_id));
        }
    }

    #[test]
    fn test_emergency_slot_compaction_clears_entries_after_redb_recovery() {
        // Arrange: record 1 entry into EmergencySlot + 1 entry into RamOnly during slot EIO
        let Ok(dir) = TempDir::new() else {
            return;
        };
        let emerg_path = dir.path().join("emergency-revocations.bin");
        let fault_backend = FaultableBackend::new(false);
        let Ok((mut state, mut ram)) = EmergencyRevocationState::boot_open_with_backend(
            emerg_path.clone(),
            false,
            &fault_backend,
        ) else {
            return;
        };

        let slot_entry = make_node_entry(1);
        let tier1 =
            state.record_emergency_node(&mut ram, slot_entry.clone(), "redb EIO", &fault_backend);
        assert_eq!(tier1, PersistenceTier::EmergencySlot);

        fault_backend.fail_writes.store(true, Ordering::SeqCst);
        let ram_only_entry = make_node_entry(2);
        let tier2 = state.record_emergency_node(
            &mut ram,
            ram_only_entry.clone(),
            "double EIO",
            &fault_backend,
        );
        assert_eq!(tier2, PersistenceTier::RamOnly);
        assert_eq!(state.pending_nodes.len(), 2);

        // Act: recovery clears EIO, caller compacts BOTH items into redb, then finalizes compaction
        fault_backend.fail_writes.store(false, Ordering::SeqCst);
        let merged_snapshot = state.pending_nodes.clone();
        let finalized = state.finalize_compaction_after_redb_commit(0, &fault_backend);
        let reopened =
            EmergencyRevocationState::boot_open_with_backend(emerg_path, true, &fault_backend);

        // Assert: BOTH slot_entry AND ram_only_entry were included before clearing degraded flag
        assert!(finalized.is_ok());
        assert_eq!(merged_snapshot.len(), 2);
        assert!(
            merged_snapshot
                .iter()
                .any(|e| e.node_id == ram_only_entry.node_id && e.tier == PersistenceTier::RamOnly)
        );
        assert!(!state.disk_degraded);
        assert!(state.pending_nodes.is_empty());
        if let Ok((reopened_state, _)) = reopened {
            assert!(!reopened_state.disk_degraded);
            assert!(reopened_state.pending_nodes.is_empty());
        }
    }

    #[test]
    fn test_emergency_slot_overflow_never_evicts_older_unmerged_revocations() {
        // Arrange: fill slot up to MAX_SLOT_NODES (500)
        let Ok(dir) = TempDir::new() else {
            return;
        };
        let emerg_path = dir.path().join("emergency-revocations.bin");
        let backend = OsEmergencyFileBackend;
        let Ok((mut state, mut ram)) =
            EmergencyRevocationState::boot_open_with_backend(emerg_path, false, &backend)
        else {
            return;
        };

        // Pre-seed 500 unmerged node entries directly into state & flush slot once cleanly
        for i in 1..=u64::try_from(MAX_SLOT_NODES).unwrap_or(500) {
            let entry = make_node_entry(i);
            ram.insert(entry.node_id);
            state.pending_nodes.push(entry);
        }
        let first_node_id = state
            .pending_nodes
            .first()
            .map(|e| e.node_id)
            .unwrap_or_else(|| NodeId::new_v7(0));

        // Act: append the 501st revocation causing overflow
        let overflow_entry = make_node_entry(9_999);
        let tier = state.record_emergency_node(
            &mut ram,
            overflow_entry.clone(),
            "overflow check",
            &backend,
        );

        // Assert: 501st goes to RamOnly, older 500 entries are NEVER evicted
        assert_eq!(tier, PersistenceTier::RamOnly);
        assert_eq!(state.pending_nodes.len(), MAX_SLOT_NODES + 1);
        assert!(ram.contains(first_node_id));
        assert!(ram.contains(overflow_entry.node_id));
        assert!(
            state
                .pending_nodes
                .iter()
                .any(|e| e.node_id == first_node_id)
        );
    }

    #[test]
    fn test_boot_fails_closed_when_emergency_file_missing_or_both_slots_corrupted() {
        // Case 1: control DB exists while emergency-revocations.bin is missing -> FAIL CLOSED
        let Ok(dir) = TempDir::new() else {
            return;
        };
        let missing_path = dir.path().join("missing-emergency.bin");
        let backend = OsEmergencyFileBackend;
        let missing_res =
            EmergencyRevocationState::boot_open_with_backend(missing_path, true, &backend);
        assert!(missing_res.is_err());

        // Case 2: file exists and both Slot A and Slot B checksums are corrupted -> FAIL CLOSED
        let corrupt_path = dir.path().join("corrupt-emergency.bin");
        let garbage = vec![0xAA_u8; EMERGENCY_REVOCATION_FILE_BYTES];
        assert!(backend.create_preallocated(&corrupt_path, &garbage).is_ok());
        let both_corrupt =
            EmergencyRevocationState::boot_open_with_backend(corrupt_path, true, &backend);
        assert!(both_corrupt.is_err());

        // Case 3: one slot corrupted while the other is valid -> recovers AND heals bad slot
        let half_corrupt_path = dir.path().join("half-corrupt.bin");
        let Ok((mut state, mut ram)) = EmergencyRevocationState::boot_open_with_backend(
            half_corrupt_path.clone(),
            false,
            &backend,
        ) else {
            return;
        };
        let saved = make_node_entry(77);
        assert_eq!(
            state.record_emergency_node(&mut ram, saved.clone(), "degraded", &backend),
            PersistenceTier::EmergencySlot
        );
        // Active slot is now Slot B (offset 32_768). Corrupt Slot A (offset 0).
        let bad_slot = [0xFF_u8; EMERGENCY_SLOT_BYTES];
        assert!(
            backend
                .write_slot_synced(&half_corrupt_path, 0, &bad_slot)
                .is_ok()
        );
        let recovered =
            EmergencyRevocationState::boot_open_with_backend(half_corrupt_path, true, &backend);
        assert!(recovered.is_ok());
        if let Ok((rec_state, rec_ram)) = recovered {
            assert!(rec_ram.contains(saved.node_id));
            assert_eq!(rec_state.pending_nodes.len(), 1);
        }
    }

    #[test]
    fn test_emergency_slot_preserves_reason_and_min_netmap_version() {
        // Arrange
        let Ok(dir) = TempDir::new() else {
            return;
        };
        let path = dir.path().join("emerg-ver.bin");
        let backend = OsEmergencyFileBackend;
        let Ok((mut state, mut ram)) =
            EmergencyRevocationState::boot_open_with_backend(path.clone(), false, &backend)
        else {
            return;
        };
        let mut entry = make_node_entry(501);
        entry.reason = EmergencyNodeReason::Expired;
        entry.min_netmap_version = 42_000;

        // Act
        let tier = state.record_emergency_node(&mut ram, entry.clone(), "expired", &backend);
        assert_eq!(tier, PersistenceTier::EmergencySlot);

        let Ok((reopened_state, reopened_ram)) =
            EmergencyRevocationState::boot_open_with_backend(path.clone(), true, &backend)
        else {
            return;
        };
        let slot_floor = read_slot_min_netmap_version(&path).expect("read slot floor");

        // Assert
        assert!(reopened_ram.contains(entry.node_id));
        assert_eq!(reopened_state.min_netmap_version, 42_000);
        assert_eq!(slot_floor, 42_000);
        assert_eq!(reopened_state.pending_nodes.len(), 1);
        assert_eq!(
            reopened_state.pending_nodes.first().map(|e| e.reason),
            Some(EmergencyNodeReason::Expired)
        );
        assert_eq!(
            reopened_state
                .pending_nodes
                .first()
                .map(|e| e.min_netmap_version),
            Some(42_000)
        );
    }
}
