//! RFC 5389 STUN Binding client running over `MagicSocket` (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};

/// Discovers public reflexive UDP endpoint and classifies symmetric vs cone NAT.
#[derive(Debug, Default)]
pub struct StunClient;

impl StunClient {
    /// Performs an initial STUN binding probe.
    pub fn probe_unavailable() -> AppResult<()> {
        Err(AppError::unavailable(
            "StunClient probing will be implemented in WP-S1-02",
        ))
    }
}
