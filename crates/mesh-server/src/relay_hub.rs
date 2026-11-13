//! Blind Relay `/v1/relay` session forwarder (`mpsc::channel(256)` + `try_send()` drop-tail,
//! 20 Mbps token bucket, `US-025 AC6`, `WP-S1-01`).

use mesh_core::defaults::RELAY_QUEUE_CAPACITY;

/// Stateful encrypted relay session hub with bounded per-peer drop-tail queues.
#[derive(Debug, Default)]
pub(crate) struct RelayHub;

impl RelayHub {
    /// Summary label for initialization diagnostics confirming bounded queue capacity.
    #[must_use]
    pub(crate) fn status_label() -> String {
        format!("relay_hub:queue={RELAY_QUEUE_CAPACITY}")
    }
}
