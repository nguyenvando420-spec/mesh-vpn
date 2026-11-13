//! macOS `PF_ROUTE` event monitor (implemented in `WP-S1-02`).

use mesh_core::AppResult;

use crate::netmon::{NetEvent, NetMonitor, netmon_unavailable};
use crate::tun::BoxFuture;

/// macOS `PF_ROUTE` [`NetMonitor`] backend.
#[derive(Debug, Default)]
pub struct MacOsNetMonitor;

impl MacOsNetMonitor {
    /// Creates a macOS `PF_ROUTE` monitor handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NetMonitor for MacOsNetMonitor {
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>> {
        Box::pin(async { Err(netmon_unavailable("macOS PF_ROUTE")) })
    }
}
