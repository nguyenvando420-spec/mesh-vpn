//! Windows fixed-adapter overlay routing backend (implemented in `WP-S1-04`).

use mesh_core::{AppError, AppResult};

use crate::route::{LinuxPolicyRoutingSpec, RouteManager, RouteSpec};

/// Windows Wintun overlay-only route manager (`netsh.exe` / IP Helper).
#[derive(Debug, Clone, Default)]
pub struct WindowsRouteManager;

impl WindowsRouteManager {
    /// Creates a Windows route manager instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RouteManager for WindowsRouteManager {
    fn apply_overlay_route(&self, _spec: &RouteSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "Windows route installation will be implemented in WP-S1-04",
        ))
    }

    fn remove_overlay_route(&self, _spec: &RouteSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "Windows route removal will be implemented in WP-S1-04",
        ))
    }

    fn apply_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }

    fn remove_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }
}
