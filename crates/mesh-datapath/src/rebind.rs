//! Physical NIC socket rebinding (`IP_BOUND_IF` / `IP_UNICAST_IF` / `SO_MARK`) and
//! `local_udp_port` continuity across network transitions (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};
use tokio::sync::mpsc;

/// Bounded capacity for pending socket rebind / refresh commands sent from `roaming_loop`.
pub const REBIND_COMMAND_CHANNEL_CAPACITY: usize = 32;

/// Commands issued to `MagicSocket` / `SocketRebinder` when physical NICs or routes change (`US-035`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebindCommand {
    /// Re-anchor the shared `MagicSocket` onto an updated physical interface (`IP_BOUND_IF` / `IP_UNICAST_IF`).
    RebindInterface {
        /// Physical interface name (e.g. `en0`, `eth0`, `Ethernet`).
        interface_name: String,
        /// Resolved OS interface index if available.
        if_index: Option<u32>,
        /// Whether the bound underlay socket uses IPv6.
        is_ipv6: bool,
    },
    /// Re-run STUN discovery and push refreshed candidate endpoints without rotating UDP port.
    RefreshCandidates,
    /// Wake the Relay WebSocket loop immediately after wake-from-sleep or route change.
    WakeRelay,
}

/// Bounded handle allowing `meshd::roaming_loop` to dispatch [`RebindCommand`] events to the datapath.
#[derive(Debug, Clone)]
pub struct RebindHandle {
    tx: mpsc::Sender<RebindCommand>,
}

impl RebindHandle {
    /// Creates a bounded [`RebindHandle`] and receiver pair (`REBIND_COMMAND_CHANNEL_CAPACITY`).
    #[must_use]
    pub fn channel() -> (Self, mpsc::Receiver<RebindCommand>) {
        let (tx, rx) = mpsc::channel(REBIND_COMMAND_CHANNEL_CAPACITY);
        (Self { tx }, rx)
    }

    /// Creates a [`RebindHandle`] wrapping an existing bounded `mpsc::Sender`.
    #[must_use]
    pub const fn from_sender(tx: mpsc::Sender<RebindCommand>) -> Self {
        Self { tx }
    }

    /// Non-blocking bounded enqueue safe inside event debouncers without blocking callers.
    pub fn try_send(&self, cmd: RebindCommand) -> AppResult<()> {
        self.tx
            .try_send(cmd)
            .map_err(|err| AppError::unavailable(format!("rebind command queue rejected: {err}")))
    }

    /// Asynchronously enqueues a [`RebindCommand`] respecting channel capacity backpressure.
    pub async fn send(&self, cmd: RebindCommand) -> AppResult<()> {
        self.tx
            .send(cmd)
            .await
            .map_err(|_| AppError::unavailable("rebind receiver channel closed"))
    }
}

/// Rebinds `MagicSocket` onto the current physical underlay adapter cleanly.
#[derive(Debug, Default)]
pub struct SocketRebinder;

impl SocketRebinder {
    /// Triggers socket interface rebinding after a `NetMonitor` transition event.
    pub fn rebind_interface(_interface_name: &str) -> AppResult<()> {
        Err(AppError::unavailable(
            "SocketRebinder will be implemented in WP-S1-02",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{RebindCommand, RebindHandle};

    #[tokio::test]
    async fn test_rebind_handle_bounded_channel_delivers_commands() {
        // Arrange
        let (handle, mut rx) = RebindHandle::channel();
        let cmd = RebindCommand::RebindInterface {
            interface_name: "en0".to_owned(),
            if_index: Some(4),
            is_ipv6: false,
        };

        // Act
        assert!(handle.try_send(cmd.clone()).is_ok());
        assert!(handle.send(RebindCommand::RefreshCandidates).await.is_ok());

        // Assert
        assert_eq!(rx.recv().await, Some(cmd));
        assert_eq!(rx.recv().await, Some(RebindCommand::RefreshCandidates));
    }
}
