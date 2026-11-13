//! Active `mesh ping <peer>` and `mesh netcheck` measurement handlers (`US-040`, `WP-S1-05`).

/// Executes STUN & Disco latency probes for diagnostics without mutating path routing on Relay.
#[derive(Debug, Default)]
pub(crate) struct PingProbe;

impl PingProbe {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "ping_probe:ready"
    }
}
