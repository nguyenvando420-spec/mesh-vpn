//! Windows `NotifyIpInterfaceChange` + PowerEvent monitor (implemented in `WP-S1-04`).

use mesh_core::AppResult;

use crate::netmon::{NetEvent, NetMonitor, netmon_unavailable};
use crate::tun::BoxFuture;

/// Windows IP Helper [`NetMonitor`] backend.
#[derive(Debug, Default)]
pub struct WindowsNetMonitor;

impl WindowsNetMonitor {
    /// Creates a Windows IP Helper monitor handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NetMonitor for WindowsNetMonitor {
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>> {
        Box::pin(async { Err(netmon_unavailable("Windows IP Helper")) })
    }
}
