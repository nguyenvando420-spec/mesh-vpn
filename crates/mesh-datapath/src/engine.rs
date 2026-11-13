//! Unified packet forwarding coordinator joining `TunDevice <-> PeerMap <-> MagicSocket <-> RelayClient`
//! (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};

/// Coordinates non-blocking packet encryption, transmission, and `tokio_util` cancellation.
#[derive(Debug, Default)]
pub struct DatapathEngine;

impl DatapathEngine {
    /// Starts the datapath event loop (`WP-S1-02`).
    pub fn start_unavailable() -> AppResult<()> {
        Err(AppError::unavailable(
            "DatapathEngine will be implemented in WP-S1-02",
        ))
    }
}
