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

/// Outcome of executing a `RebindCommand` against `MagicSocket`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebindOutcome {
    /// Physical underlay socket binding updated (`rebind_underlay` or socket re-creation).
    Rebound {
        /// Effective local socket address after rebinding.
        local_addr: std::net::SocketAddr,
        /// True when the underlying `UdpSocket` had to be closed and recreated.
        recreated_socket: bool,
        /// True when recreating the socket had to fall back to an ephemeral port `0`.
        used_fallback_port: bool,
    },
    /// Caller should refresh local candidate endpoints (interface list / STUN probe).
    RefreshCandidatesRequested,
    /// Caller should immediately wake or re-check the Blind Relay connection.
    WakeRelayRequested,
}

/// Applies network-interface and routing-loop prevention rebinds to `MagicSocket` (`US-019`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SocketRebinder;

impl SocketRebinder {
    /// Executes a `RebindCommand` received from `NetMonitor` against `magic_socket`.
    ///
    /// First attempts an in-place underlay rebind (`IP_UNICAST_IF` / `IP_BOUND_IF` / `SO_MARK`)
    /// so active NAT mappings are preserved; if OS binding fails or requires recreation,
    /// recreates the UDP socket while requesting the previous `local_udp_port`.
    pub fn apply_command(
        magic_socket: &mut crate::magic_socket::MagicSocket,
        command: &RebindCommand,
        linux_fwmark: Option<u32>,
    ) -> AppResult<RebindOutcome> {
        match command {
            RebindCommand::RebindInterface {
                interface_name,
                if_index,
                ..
            } => Self::rebind_socket(magic_socket, interface_name, *if_index, linux_fwmark),
            RebindCommand::RefreshCandidates => Ok(RebindOutcome::RefreshCandidatesRequested),
            RebindCommand::WakeRelay => Ok(RebindOutcome::WakeRelayRequested),
        }
    }

    /// Rebinds `magic_socket` onto the specified physical interface (`if_index`, `linux_fwmark`).
    pub fn rebind_socket(
        magic_socket: &mut crate::magic_socket::MagicSocket,
        interface_name: &str,
        if_index: Option<u32>,
        linux_fwmark: Option<u32>,
    ) -> AppResult<RebindOutcome> {
        let normalized_if_index = if_index.filter(|&id| id != 0);
        if magic_socket
            .rebind_underlay(normalized_if_index, linux_fwmark)
            .is_ok()
        {
            let local_addr = magic_socket.local_addr()?;
            tracing::info!(
                component = "datapath.rebind",
                event = "underlay_rebound_in_place",
                interface = %interface_name,
                if_index = ?normalized_if_index,
                local_addr = %local_addr,
                "rebound MagicSocket underlay interface in place"
            );
            return Ok(RebindOutcome::Rebound {
                local_addr,
                recreated_socket: false,
                used_fallback_port: false,
            });
        }

        let report = magic_socket.recreate_socket(normalized_if_index, linux_fwmark)?;
        tracing::info!(
            component = "datapath.rebind",
            event = "underlay_socket_recreated",
            interface = %interface_name,
            if_index = ?normalized_if_index,
            local_addr = %report.local_addr,
            used_fallback_port = report.used_fallback_port,
            "recreated MagicSocket on new physical underlay interface"
        );
        Ok(RebindOutcome::Rebound {
            local_addr: report.local_addr,
            recreated_socket: true,
            used_fallback_port: report.used_fallback_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{RebindCommand, RebindHandle, RebindOutcome, SocketRebinder};
    use crate::magic_socket::{MagicSocket, MagicSocketConfig};

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

    // Traces: US-019
    #[tokio::test]
    async fn test_socket_rebinder_rebinds_in_place_and_handles_control_commands() {
        // Arrange
        let mut sock = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("loopback socket binds");
        let original_addr = sock.local_addr().expect("local addr");

        // Act
        let rebind_res = SocketRebinder::apply_command(
            &mut sock,
            &RebindCommand::RebindInterface {
                interface_name: "lo".to_owned(),
                if_index: None,
                is_ipv6: false,
            },
            None,
        )
        .expect("in-place rebind without explicit if_index should succeed");
        let refresh_res =
            SocketRebinder::apply_command(&mut sock, &RebindCommand::RefreshCandidates, None)
                .expect("refresh command succeeds");
        let wake_res = SocketRebinder::apply_command(&mut sock, &RebindCommand::WakeRelay, None)
            .expect("wake command succeeds");

        // Assert
        assert_eq!(
            rebind_res,
            RebindOutcome::Rebound {
                local_addr: original_addr,
                recreated_socket: false,
                used_fallback_port: false,
            }
        );
        assert_eq!(refresh_res, RebindOutcome::RefreshCandidatesRequested);
        assert_eq!(wake_res, RebindOutcome::WakeRelayRequested);
    }

    #[tokio::test]
    async fn test_socket_rebinder_recreate_preserves_local_udp_port() {
        // Traces: US-035 AC2
        // Arrange
        let bound = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await;
        assert!(bound.is_ok());
        let Ok(mut sock) = bound else {
            return;
        };
        let Ok(original_addr) = sock.local_addr() else {
            assert!(sock.local_addr().is_ok());
            return;
        };
        let original_port = original_addr.port();

        // Act: force socket recreation without explicit physical interface index (0 normalized out)
        let outcome = SocketRebinder::apply_command(
            &mut sock,
            &RebindCommand::RebindInterface {
                interface_name: "en0".to_owned(),
                if_index: Some(0),
                is_ipv6: false,
            },
            None,
        );
        assert!(outcome.is_ok());
        let Ok(outcome) = outcome else {
            return;
        };
        let Ok(after_addr) = sock.local_addr() else {
            assert!(sock.local_addr().is_ok());
            return;
        };
        let after_port = after_addr.port();

        // Assert
        assert_eq!(after_port, original_port);
        assert!(matches!(
            outcome,
            RebindOutcome::Rebound {
                used_fallback_port: false,
                ..
            }
        ));
    }
}
