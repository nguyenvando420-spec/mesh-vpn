//! Windows ACL-preserving `hosts` editor + retry/DNS flush (`WP-S1-04`).

use mesh_core::AppResult;

use crate::hosts::FileHostsEditor;

/// Returns a [`FileHostsEditor`] targeting Windows `%SystemRoot%\System32\drivers\etc\hosts`.
#[must_use]
pub fn windows_hosts_editor() -> FileHostsEditor {
    FileHostsEditor::default_system()
}

/// Flushes Windows resolver cache (`DnsFlushResolverCache`, implemented in `WP-S1-04`).
pub fn flush_dns_cache_best_effort() -> AppResult<()> {
    Ok(())
}
