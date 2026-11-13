//! Local UDS Admin router (`/run/mesh-server/admin.sock`, `SO_PEERCRED` + `getgrouplist mesh-admin`)
//! (`SEC-14`, `WP-S1-01`).

/// Local administrator IPC service skeleton.
#[derive(Debug, Default)]
pub(crate) struct AdminService;

impl AdminService {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "admin_service:ready"
    }
}
