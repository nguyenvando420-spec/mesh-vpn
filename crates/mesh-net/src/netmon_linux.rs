//! Linux Netlink route/address/link event monitor (implemented in `WP-S1-03`).

use mesh_core::AppResult;

use crate::netmon::{NetEvent, NetMonitor, netmon_unavailable};
use crate::tun::BoxFuture;

/// Linux Netlink [`NetMonitor`] backend.
#[derive(Debug, Default)]
pub struct LinuxNetMonitor;

impl LinuxNetMonitor {
    /// Creates a Linux Netlink monitor handle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NetMonitor for LinuxNetMonitor {
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>> {
        Box::pin(async { Err(netmon_unavailable("Linux Netlink")) })
    }
}
