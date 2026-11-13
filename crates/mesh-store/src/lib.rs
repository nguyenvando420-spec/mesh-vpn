//! ACID control-plane state storage (`redb`), emergency `64 KiB` A/B revocation log,
//! monotonic netmap version leasing, and atomic MVCC backups (`WP-S1-01`).

pub mod audit_repo;
pub mod backup;
pub mod identity_repo;
pub mod keys_repo;
pub mod nodes_repo;
pub mod revoked_ram;
pub mod schema;
pub mod store;

pub use audit_repo::{AuditEventInput, AuditQuery, AuditRepository, StoredAuditEventRecord};
pub use backup::{
    BackupArtifact, BackupManager, DEFAULT_BACKUP_RETENTION, RESTORE_WATERMARK_JUMP,
    RestoreOptions, RestoreOutcome, StagedRestore,
};
pub use identity_repo::{
    AcmeAccountCredentialsBox, IdentityRepository, ServerIdentity, StagedServerIdentity,
};
pub use keys_repo::{
    CreatePreAuthKeyInput, DEFAULT_PREAUTH_TTL_SECS, KeysRepository, MAX_PREAUTH_TTL_SECS,
    StoredPreAuthKeyRecord,
};
pub use nodes_repo::{
    DEFAULT_NODE_KEY_TTL_MS, NodeStatus, NodesRepository, QUARANTINE_DURATION_MS,
    RegisterNodeInput, RegisterNodeOutcome, StoredNodeRecord,
};
pub use revoked_ram::{
    DecodedEmergencySlot, EMERGENCY_REVOCATION_FILE_BYTES, EMERGENCY_SLOT_BYTES,
    EmergencyFileBackend, EmergencyNodeReason, EmergencyRevocationKeyEntry,
    EmergencyRevocationNodeEntry, EmergencyRevocationState, MAX_SLOT_KEYS, MAX_SLOT_NODES,
    OsEmergencyFileBackend, RevokedSet, read_slot_min_netmap_version,
};
pub use schema::{SCHEMA_VERSION, VERSION_LEASE_STEP};
pub use store::{ControlStore, ControlStoreConfig, MonotonicNetmapVersion, RevokeStoreOutcome};
