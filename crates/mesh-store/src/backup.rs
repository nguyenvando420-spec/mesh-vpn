//! Hot atomic snapshot backup (`SHA-256`, retention `7`), restore (`+1_000_000` watermark jump)
//! (`US-045`, `WP-S1-01`).

use mesh_core::{AppError, AppResult};

/// Default number of snapshot backups retained (`US-045`).
pub const DEFAULT_BACKUP_RETENTION: usize = 7;

/// Netmap version watermark jump added during backup restoration to avoid stale rollback (`REL-01`).
pub const RESTORE_WATERMARK_JUMP: u64 = 1_000_000;

/// Atomic database backup and restore coordinator (`WP-S1-01`).
#[derive(Debug, Default)]
pub struct BackupManager;

impl BackupManager {
    /// Creates an atomic snapshot backup of `redb` (`WP-S1-01`).
    pub fn create_snapshot() -> AppResult<()> {
        Err(AppError::unavailable(
            "hot backup creation will be implemented in WP-S1-01",
        ))
    }
}
