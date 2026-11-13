//! Linux opt-in firewall management with 90-second auto-rollback (`US-046`, `WP-S1-03`).

use mesh_core::{AppError, AppResult};

/// Default confirmation timeout before automatic firewall rollback (`90 s`).
pub const FIREWALL_AUTO_ROLLBACK_SECS: u64 = 90;

/// Applies opt-in Linux firewall rules while preserving SSH connectivity (`WP-S1-03`).
pub fn apply_optin_firewall(_dry_run: bool) -> AppResult<()> {
    Err(AppError::unavailable(
        "Linux firewall opt-in management will be implemented in WP-S1-03",
    ))
}
