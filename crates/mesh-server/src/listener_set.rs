//! Dual old+new port listener manager during zero-downtime port changes (`US-074`, `WP-S1-01`).

/// Coordinates dual-bound TCP/UDP listeners during port migration (`US-074`).
#[derive(Debug, Default)]
pub(crate) struct ListenerSet;

impl ListenerSet {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "listener_set:ready"
    }
}
