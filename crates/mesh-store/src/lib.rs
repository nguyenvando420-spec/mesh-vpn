//! Pure-Rust ACID `redb` 2.4 storage skeleton, fail-closed revocation boot log,
//! and atomic backup manager (implemented in `WP-S1-01`).

pub mod audit_repo;
pub mod backup;
pub mod identity_repo;
pub mod keys_repo;
pub mod nodes_repo;
pub mod revoked_ram;
pub mod schema;
pub mod store;

pub use audit_repo::AuditRepository;
pub use backup::{BackupManager, DEFAULT_BACKUP_RETENTION};
pub use identity_repo::{IdentityRepository, ServerIdentity};
pub use keys_repo::KeysRepository;
pub use nodes_repo::NodesRepository;
pub use revoked_ram::{EMERGENCY_REVOCATION_FILE_BYTES, RevokedSet};
pub use schema::{SCHEMA_VERSION, VERSION_LEASE_STEP};
pub use store::{ControlStore, ControlStoreConfig};
