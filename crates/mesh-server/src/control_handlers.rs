//! HTTP control API handlers (`/v1/auth/challenge`, `/v1/nodes/register`, `/v1/endpoints`,
//! `/v1/disco/call-me-maybe`, `WP-S1-01`).

/// Control plane HTTP route registry skeleton.
#[derive(Debug, Default)]
pub(crate) struct ControlRouter;

impl ControlRouter {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "control_router:ready"
    }
}
