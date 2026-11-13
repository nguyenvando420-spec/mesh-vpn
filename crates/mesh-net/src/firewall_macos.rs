//! macOS Application Firewall check & dedicated `pf` anchor backend (`US-073 AC6`, `WP-S1-02`).

use mesh_core::{AppError, AppResult};

/// Dedicated `pf` anchor name owned exclusively by Mesh VPN (`REL-08`).
pub const MESH_PF_ANCHOR_NAME: &str = "com.internal.mesh";

/// Queries macOS `socketfilterfw` state for diagnostic visibility without disabling protections.
pub fn inspect_application_firewall() -> AppResult<bool> {
    Err(AppError::unavailable(
        "macOS Application Firewall inspection will be implemented in WP-S1-02",
    ))
}
