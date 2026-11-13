//! Atomic `netmap-cache.json` persistence with `local_udp_port` continuity & SHA-256 verification
//! (`US-019 AC1`, `US-033 AC2/AC3`, `WP-S1-05`).

/// Cached last-known netmap & `local_udp_port` store skeleton.
#[derive(Debug, Default)]
pub(crate) struct NetmapCacheStore;

impl NetmapCacheStore {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "netmap_cache:ready"
    }
}
