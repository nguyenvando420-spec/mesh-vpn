//! WebSocket `/v1/netmap/stream` broadcast hub supporting `ClientControlFrame` updates (`WP-S1-01`).

/// Manages active subscriber channels for netmap delta fan-out.
#[derive(Debug, Default)]
pub(crate) struct NetmapHub;

impl NetmapHub {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "netmap_hub:ready"
    }
}
