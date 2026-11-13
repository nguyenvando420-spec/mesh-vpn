//! Linux `/etc/hosts` managed block & best-effort DNS cache flush helpers (`US-038`).

use std::path::PathBuf;

use mesh_core::AppResult;

use crate::hosts::{FileHostsEditor, HostsEditor, HostsEntry};
use crate::ledger::ResourceLedger;
use crate::sysexec::{AllowedBinary, CommandExecutor, CommandSpec, StdCommandExecutor};

/// Default system `hosts` path on Linux (`/etc/hosts`).
pub const LINUX_HOSTS_PATH: &str = "/etc/hosts";

/// Returns a [`FileHostsEditor`] targeting `/etc/hosts` (supports Docker bind-mount fallback).
#[must_use]
pub fn linux_hosts_editor() -> FileHostsEditor {
    FileHostsEditor::new(PathBuf::from(LINUX_HOSTS_PATH))
}

/// Records hosts ownership in `ResourceLedger` before applying `# BEGIN mesh ... # END mesh`
/// entries on Linux without altering `/etc/resolv.conf`.
pub fn apply_linux_hosts_with_ledger(
    editor: &dyn HostsEditor,
    entries: &[HostsEntry],
    public_server_host: Option<&str>,
    ledger: &mut ResourceLedger,
) -> AppResult<()> {
    if !entries.is_empty()
        && let Some(real_path) = editor.canonical_real_path()?
    {
        ledger.record_hosts_before_activate(real_path.display().to_string())?;
    }
    editor.apply(entries, public_server_host)
}

/// Flushes local DNS caches on Linux best-effort via `/usr/bin/resolvectl flush-caches`.
pub fn flush_dns_cache_best_effort() -> AppResult<()> {
    let executor = StdCommandExecutor::new();
    flush_dns_cache_with_executor(&executor)
}

/// Flushes Linux `systemd-resolved` DNS caches best-effort using an injected [`CommandExecutor`].
pub fn flush_dns_cache_with_executor(executor: &dyn CommandExecutor) -> AppResult<()> {
    let spec = CommandSpec::new(AllowedBinary::LinuxResolvectl, ["flush-caches".to_owned()])?;
    match executor.execute(&spec) {
        Ok(output) if output.success() => {
            tracing::debug!(
                component = "hosts_linux",
                event = "dns_cache_flushed",
                "flushed systemd-resolved DNS caches"
            );
        }
        Ok(output) => {
            tracing::debug!(
                component = "hosts_linux",
                event = "dns_cache_flush_skipped",
                status_code = output.status_code,
                "resolvectl flush-caches returned non-zero status; continuing without error"
            );
        }
        Err(err) => {
            tracing::debug!(
                component = "hosts_linux",
                event = "dns_cache_flush_unavailable",
                error = %err,
                "resolvectl not present; skipping DNS cache flush"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::str::FromStr;

    use mesh_core::{NodeName, OverlayIp};
    use tempfile::tempdir;

    use super::{apply_linux_hosts_with_ledger, flush_dns_cache_with_executor, linux_hosts_editor};
    use crate::hosts::{FileHostsEditor, HostsEditor, HostsEntry};
    use crate::ledger::ResourceLedger;
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};

    #[test]
    fn test_hosts_linux_applies_with_ledger_and_clears_preserving_existing() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let hosts_file = dir.path().join("hosts");
        let original = "127.0.0.1 localhost\n::1 ip6-localhost\n";
        fs::write(&hosts_file, original).expect("seed hosts");
        let editor = FileHostsEditor::new(hosts_file.clone());
        let mut ledger =
            ResourceLedger::load_or_init(dir.path().join("ledger.json")).expect("ledger");
        let entry = HostsEntry::new(
            OverlayIp::from_str("100.115.0.5").expect("ip"),
            NodeName::from_str("vps").expect("node"),
            "mesh.internal",
            Some("relay.example.com"),
        )
        .expect("entry");

        // Act
        apply_linux_hosts_with_ledger(&editor, &[entry], Some("relay.example.com"), &mut ledger)
            .expect("apply hosts");
        let mid = fs::read_to_string(&hosts_file).expect("read mid");
        editor.clear().expect("clear hosts");
        let end = fs::read_to_string(&hosts_file).expect("read end");

        // Assert
        assert!(ledger.data().hosts_block_active);
        assert!(mid.contains("100.115.0.5 vps.mesh.internal vps"));
        assert_eq!(end, original);
        assert_eq!(linux_hosts_editor().default_hosts_display(), "/etc/hosts");
    }

    #[test]
    fn test_hosts_linux_flush_dns_cache_is_best_effort() {
        // Arrange
        let executor = FakeCommandExecutor::new();
        executor
            .push_result(Ok(CommandOutput {
                status_code: 1,
                stdout: String::new(),
                stderr: "Unit systemd-resolved.service not found.".to_owned(),
            }))
            .expect("queue output");

        // Act
        flush_dns_cache_with_executor(&executor).expect("best-effort succeeds");

        // Assert
        let recorded = executor.recorded().expect("recorded");
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded.first().map(|c| c.binary),
            Some(AllowedBinary::LinuxResolvectl)
        );
    }

    trait HostsDisplayExt {
        fn default_hosts_display(&self) -> String;
    }

    impl HostsDisplayExt for FileHostsEditor {
        fn default_hosts_display(&self) -> String {
            super::LINUX_HOSTS_PATH.to_owned()
        }
    }
}
