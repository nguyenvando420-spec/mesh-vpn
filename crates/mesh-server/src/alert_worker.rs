//! Minimal personal alerting background task for TLS expiry, disk pressure, relay saturation,
//! and key expiry (`US-049`, `WP-S1-01`).

/// Alert monitoring worker skeleton.
#[derive(Debug, Default)]
pub(crate) struct AlertWorker;

impl AlertWorker {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "alert_worker:ready"
    }
}
