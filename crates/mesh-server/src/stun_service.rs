//! Embedded UDP RFC 5389 STUN responder rate-limited at `100 pkt/s/IP` (`WP-S1-01`).

/// Unprivileged UDP STUN listener skeleton.
#[derive(Debug, Default)]
pub(crate) struct StunService;

impl StunService {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "stun_service:ready"
    }
}
