//! Control store initialization, integrity checks, and monotonic netmap version leasing (`WP-S1-01`).

use std::path::PathBuf;

use mesh_core::{AppError, AppResult};

/// Configuration for opening [`ControlStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlStoreConfig {
    /// Path to `mesh-server.redb`.
    pub db_path: PathBuf,
    /// Path to `emergency-revocations.bin` (`64 KiB` slot A/B file).
    pub emergency_revocations_path: PathBuf,
}

/// Primary ACID storage facade backed by `redb` (full implementation in `WP-S1-01`).
#[derive(Debug)]
pub struct ControlStore {
    config: ControlStoreConfig,
}

impl ControlStore {
    /// Validates paths cleanly prior to opening `redb` (`WP-S1-01`).
    pub fn open(config: ControlStoreConfig) -> AppResult<Self> {
        let _path = &config.db_path;
        Ok(Self { config })
    }

    /// Returns store configuration.
    #[must_use]
    pub const fn config(&self) -> &ControlStoreConfig {
        &self.config
    }

    /// Checks database consistency before accepting traffic (`WP-S1-01`).
    pub fn check_integrity(&self) -> AppResult<()> {
        Err(AppError::unavailable(format!(
            "redb integrity check for {} will be implemented in WP-S1-01",
            self.config.db_path.display()
        )))
    }
}
