//! Dual privilege-separated daemon IPC routers (`meshd-admin.sock` / `meshd-ro.sock` or Named Pipes,
//! `SEC-14`, `WP-S1-05`).

/// Dual Admin / ReadOnly local IPC server skeleton.
#[derive(Debug, Default)]
pub(crate) struct IpcService;

impl IpcService {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "ipc_service:ready"
    }
}
