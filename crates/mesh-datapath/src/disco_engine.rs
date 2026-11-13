//! Peer discovery `pending_pings` state machine, simultaneous NAT hole-punching, and strict
//! `IngressSource::{DirectUdp, Relay}` separation (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};

/// Stateful Disco coordinator upgrading paths to `Direct` strictly on `IngressSource::DirectUdp`.
#[derive(Debug, Default)]
pub struct DiscoEngine;

impl DiscoEngine {
    /// Triggers a hole-punch probe round (`WP-S1-02`).
    pub fn initiate_probe_unavailable() -> AppResult<()> {
        Err(AppError::unavailable(
            "DiscoEngine will be implemented in WP-S1-02",
        ))
    }
}
