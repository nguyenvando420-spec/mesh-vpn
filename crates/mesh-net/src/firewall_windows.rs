//! Windows Firewall adapter profile and overlay rule management (`US-053`, `WP-S1-04`).

use mesh_core::{AppError, AppResult};

/// Applies Private network category + scoped overlay rule on the Wintun adapter (`WP-S1-04`).
pub fn configure_overlay_firewall_profile(_interface_name: &str) -> AppResult<()> {
    Err(AppError::unavailable(
        "Windows Firewall adapter policy will be implemented in WP-S1-04",
    ))
}
