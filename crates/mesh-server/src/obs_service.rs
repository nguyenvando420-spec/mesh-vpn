//! Dedicated read-only localhost observability HTTP listener (`/healthz`, `/readyz`, `/metrics`,
//! `WP-S1-01`).

/// Isolated read-only monitoring listener skeleton.
#[derive(Debug, Default)]
pub(crate) struct ObsService;

impl ObsService {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "obs_service:ready"
    }
}
