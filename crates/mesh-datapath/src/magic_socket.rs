//! Single `tokio::net::UdpSocket` packet demuxer with reusable `[u8; 2048]` static buffers
//! (`ADR-002`, implemented in `WP-S1-02`).

use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, AppResult};

/// Unified non-blocking UDP demuxer handling STUN, Disco, and WireGuard traffic.
#[derive(Debug, Default)]
pub struct MagicSocket {
    /// Fixed buffer capacity reserved per packet read/write (`2048 B`).
    frame_capacity: usize,
}

impl MagicSocket {
    /// Constructs a skeleton descriptor for `MagicSocket`.
    #[must_use]
    pub const fn descriptor() -> Self {
        Self {
            frame_capacity: MAX_FRAME_SIZE,
        }
    }

    /// Binds a single non-blocking UDP socket (`IP_BOUND_IF` / `IP_UNICAST_IF` / `SO_MARK`).
    pub fn bind_uninitialized(&self) -> AppResult<()> {
        Err(AppError::unavailable(format!(
            "MagicSocket bind (frame_capacity={}) will be implemented in WP-S1-02",
            self.frame_capacity
        )))
    }
}
