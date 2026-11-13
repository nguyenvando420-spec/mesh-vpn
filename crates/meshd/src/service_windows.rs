//! Windows Service Control Manager (`windows-service`) & PowerEvent integration (`WP-S1-04`).

/// Windows service name registered with SCM.
pub(crate) const WINDOWS_SERVICE_NAME: &str = "MeshVPNService";

/// Summary label for Windows SCM subsystem initialization.
#[must_use]
pub(crate) fn status_label() -> String {
    format!("windows_scm:{WINDOWS_SERVICE_NAME}")
}
