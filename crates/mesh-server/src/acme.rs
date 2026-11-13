//! Automated ACME TLS-ALPN-01 (default control port) / DNS-01 certificate lifecycle via
//! `instant-acme` (`WP-S1-01`).

/// ACME renewal coordinator skeleton.
#[derive(Debug, Default)]
pub(crate) struct AcmeManager;

impl AcmeManager {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "acme:ready"
    }
}
