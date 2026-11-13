//! Peer table & `defguard_boringtun::noise::Tunn` session manager (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};

/// Manages active WireGuard peer crypto sessions synchronized from Netmap diffs (`US-010`).
#[derive(Debug, Default)]
pub struct PeerMap;

impl PeerMap {
    /// Applies a verified Netmap diff against the active WireGuard peer table.
    pub fn apply_diff_unavailable() -> AppResult<()> {
        Err(AppError::unavailable(
            "PeerMap WireGuard engine will be implemented in WP-S1-02",
        ))
    }
}
