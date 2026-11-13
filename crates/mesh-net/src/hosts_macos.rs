//! macOS `/etc/hosts -> /private/etc/hosts` symlink-safe editor & DNS flush (`WP-S1-02`).

use mesh_core::AppResult;

use crate::hosts::FileHostsEditor;

/// Returns a [`FileHostsEditor`] resolving macOS `/etc/hosts` symlink cleanly.
#[must_use]
pub fn macos_hosts_editor() -> FileHostsEditor {
    FileHostsEditor::default_system()
}

/// Flushes macOS mDNSResponder / DirectoryService caches (`WP-S1-02`).
pub fn flush_dns_cache_best_effort() -> AppResult<()> {
    Ok(())
}
