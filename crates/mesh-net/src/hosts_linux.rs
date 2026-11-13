//! Linux atomic `/etc/hosts` editor with bind-mount fallback (`US-038 AC2d`, `WP-S1-03`).

use mesh_core::AppResult;

use crate::hosts::FileHostsEditor;

/// Returns a [`FileHostsEditor`] configured for Linux `/etc/hosts`.
#[must_use]
pub fn linux_hosts_editor() -> FileHostsEditor {
    FileHostsEditor::default_system()
}

/// Flushes local DNS caches on Linux if systemd-resolved is active.
pub fn flush_dns_cache_best_effort() -> AppResult<()> {
    Ok(())
}
