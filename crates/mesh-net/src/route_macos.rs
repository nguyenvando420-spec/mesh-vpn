//! macOS `/sbin/route` backend bound to exact session `utunN` (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};

use crate::route::{LinuxPolicyRoutingSpec, RouteManager, RouteSpec};

/// macOS `/sbin/route` overlay-only route manager.
#[derive(Debug, Clone, Default)]
pub struct MacOsRouteManager;

impl MacOsRouteManager {
    /// Creates a macOS route manager instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RouteManager for MacOsRouteManager {
    fn apply_overlay_route(&self, _spec: &RouteSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "macOS route installation will be implemented in WP-S1-02",
        ))
    }

    fn remove_overlay_route(&self, _spec: &RouteSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "macOS route removal will be implemented in WP-S1-02",
        ))
    }

    fn apply_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }

    fn remove_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }
}
