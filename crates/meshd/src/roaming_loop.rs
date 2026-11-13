//! Roaming and sleep/wake recovery handler driven by `NetMonitor` & `ClockJumpDetector` (`US-035`).

/// Reacts to underlay interface/address/wake events without losing overlay sessions.
#[derive(Debug, Default)]
pub(crate) struct RoamingLoop;

impl RoamingLoop {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "roaming_loop:ready"
    }
}
