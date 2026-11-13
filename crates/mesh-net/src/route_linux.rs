//! Linux policy routing (`table 51820`, `fwmark 0x5d56`) backend (implemented in `WP-S1-03`).

use mesh_core::{AppError, AppResult};

use crate::route::{LinuxPolicyRoutingSpec, RouteManager, RouteSpec};

/// Linux `/usr/sbin/ip` overlay route and policy-routing manager.
#[derive(Debug, Clone, Default)]
pub struct LinuxRouteManager;

impl LinuxRouteManager {
    /// Creates a Linux route manager instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RouteManager for LinuxRouteManager {
    fn apply_overlay_route(&self, _spec: &RouteSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "Linux route installation will be implemented in WP-S1-03",
        ))
    }

    fn remove_overlay_route(&self, _spec: &RouteSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "Linux route removal will be implemented in WP-S1-03",
        ))
    }

    fn apply_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "Linux ip rule installation will be implemented in WP-S1-03",
        ))
    }

    fn remove_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Err(AppError::unavailable(
            "Linux ip rule removal will be implemented in WP-S1-03",
        ))
    }
}
