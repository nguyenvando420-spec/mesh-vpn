//! Authenticated TLS WebSocket `/v1/relay` client (`0x01`/`0x02`/`0x03`) with bounded queueing
//! and automatic reconnection (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};

/// Client connection to the VPS Blind Relay forwarder.
#[derive(Debug, Default)]
pub struct RelayClient;

impl RelayClient {
    /// Connects to `/v1/relay` over SPKI-pinned or WebPKI TLS (`WP-S1-02`).
    pub fn connect_unavailable() -> AppResult<()> {
        Err(AppError::unavailable(
            "RelayClient will be implemented in WP-S1-02",
        ))
    }
}
