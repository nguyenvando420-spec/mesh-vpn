//! Strict WireGuard cryptokey routing (`AllowedIPs = /32`) & optional overlay packet filter
//! (`SEC-11`, `US-018`, implemented in `WP-S1-02`).

use mesh_core::OverlayIp;

/// Verifies that decrypted IPv4 source addresses match the peer's assigned `/32` overlay IP.
#[derive(Debug, Default)]
pub struct CryptokeyValidator;

impl CryptokeyValidator {
    /// Returns `true` strictly when decrypted packet source IP matches `expected_peer_ip`.
    #[must_use]
    pub fn matches_peer_source(expected_peer_ip: OverlayIp, observed_src: OverlayIp) -> bool {
        expected_peer_ip == observed_src
    }
}
