//! macOS `/etc/hosts -> /private/etc/hosts` symlink-preserving editor and DNS flush (`US-038`).

use std::path::PathBuf;

use mesh_core::AppResult;

use crate::hosts::{FileHostsEditor, HostsEditor, HostsEntry};
use crate::ledger::ResourceLedger;
use crate::sysexec::{AllowedBinary, CommandExecutor, CommandSpec, StdCommandExecutor};

/// Default system `hosts` path on macOS (symlink to `/private/etc/hosts`).
pub const MACOS_HOSTS_PATH: &str = "/etc/hosts";

/// Returns a [`FileHostsEditor`] for `/etc/hosts` that preserves the macOS symlink and `0644` mode.
#[must_use]
pub fn macos_hosts_editor() -> FileHostsEditor {
    FileHostsEditor::new(PathBuf::from(MACOS_HOSTS_PATH))
}

/// Records the canonical target of `/etc/hosts` in `ResourceLedger` before rewriting the managed
/// `# BEGIN mesh ... # END mesh` block (`US-038`, `US-073 AC7`).
pub fn apply_macos_hosts_with_ledger(
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

/// Flushes macOS system DNS caches using `/usr/bin/dscacheutil` and `/usr/bin/killall`.
pub fn flush_dns_cache_best_effort() -> AppResult<()> {
    let executor = StdCommandExecutor::new();
    flush_dns_cache_with_executor(&executor)
}

/// Flushes macOS DNS caches using an injected [`CommandExecutor`] for deterministic testing.
pub fn flush_dns_cache_with_executor(executor: &dyn CommandExecutor) -> AppResult<()> {
    let dscacheutil =
        CommandSpec::new(AllowedBinary::MacOsDscacheutil, ["-flushcache".to_owned()])?;
    run_dns_cmd_best_effort(executor, &dscacheutil, "dscacheutil");

    let killall = CommandSpec::new(
        AllowedBinary::MacOsKillall,
        ["-HUP".to_owned(), "mDNSResponder".to_owned()],
    )?;
    run_dns_cmd_best_effort(executor, &killall, "killall");

    Ok(())
}

fn run_dns_cmd_best_effort(
    executor: &dyn CommandExecutor,
    spec: &CommandSpec,
    tool_label: &'static str,
) {
    match executor.execute(spec) {
        Ok(out) if out.success() => {
            tracing::debug!(
                component = "hosts_macos",
                event = "dns_cache_flushed",
                tool = tool_label,
                "flushed macOS DNS cache"
            );
        }
        Ok(out) => {
            tracing::warn!(
                component = "hosts_macos",
                event = "dns_cache_flush_nonzero",
                tool = tool_label,
                status_code = out.status_code,
                stderr = %out.stderr.trim(),
                "macOS DNS flush command exited non-zero"
            );
        }
        Err(err) => {
            tracing::warn!(
                component = "hosts_macos",
                event = "dns_cache_flush_error",
                tool = tool_label,
                error = %err,
                "macOS DNS flush command invocation failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::str::FromStr;

    use mesh_core::{NodeName, OverlayIp};
    use tempfile::tempdir;

    use super::{apply_macos_hosts_with_ledger, flush_dns_cache_with_executor, macos_hosts_editor};
    use crate::hosts::{FileHostsEditor, HostsEditor, HostsEntry};
    use crate::ledger::ResourceLedger;
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};

    #[test]
    fn test_hosts_macos_preserves_symlink_and_0644_permissions() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let private_etc = dir.path().join("private_etc");
        let etc = dir.path().join("etc");
        fs::create_dir_all(&private_etc).expect("private_etc");
        fs::create_dir_all(&etc).expect("etc");

        let real_hosts = private_etc.join("hosts");
        let baseline = "##\n127.0.0.1\tlocalhost\n";
        fs::write(&real_hosts, baseline).expect("write real hosts");
        fs::set_permissions(&real_hosts, fs::Permissions::from_mode(0o644)).expect("chmod 0644");

        let symlink_hosts = etc.join("hosts");
        symlink(&real_hosts, &symlink_hosts).expect("create symlink");

        let editor = FileHostsEditor::new(symlink_hosts.clone());
        let mut ledger =
            ResourceLedger::load_or_init(dir.path().join("ledger.json")).expect("ledger");
        let entry = HostsEntry::new(
            OverlayIp::from_str("100.115.0.12").expect("ip"),
            NodeName::from_str("macbook").expect("node"),
            "mesh.internal",
            Some("vps.example.net"),
        )
        .expect("entry");

        // Act
        apply_macos_hosts_with_ledger(&editor, &[entry], Some("vps.example.net"), &mut ledger)
            .expect("apply macos hosts");
        let mid_symlink_meta = fs::symlink_metadata(&symlink_hosts).expect("symlink meta");
        let mid_real_meta = fs::metadata(&real_hosts).expect("real meta");
        let mid_content = fs::read_to_string(&real_hosts).expect("read mid");
        editor.clear().expect("clear");
        let end_content = fs::read_to_string(&real_hosts).expect("read end");

        // Assert
        assert!(mid_symlink_meta.file_type().is_symlink());
        assert_eq!(mid_real_meta.permissions().mode() & 0o777, 0o644);
        assert!(mid_content.contains("100.115.0.12 macbook.mesh.internal macbook"));
        assert_eq!(end_content, baseline);
        assert_eq!(
            fs::canonicalize(&symlink_hosts).ok(),
            editor.canonical_real_path().expect("canonical path")
        );
        let _default_editor = macos_hosts_editor();
    }

    #[test]
    fn test_hosts_macos_flush_dns_cache_invokes_dscacheutil_and_killall() {
        // Arrange
        let executor = FakeCommandExecutor::new();
        for _ in 0..2 {
            executor
                .push_result(Ok(CommandOutput {
                    status_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }))
                .expect("queue output");
        }

        // Act
        flush_dns_cache_with_executor(&executor).expect("flush dns cache");

        // Assert
        let recorded = executor.recorded().expect("recorded");
        assert_eq!(recorded.len(), 2);
        assert!(recorded.first().is_some_and(|c| {
            c.binary == AllowedBinary::MacOsDscacheutil && c.args == ["-flushcache"]
        }));
        assert!(recorded.get(1).is_some_and(|c| {
            c.binary == AllowedBinary::MacOsKillall && c.args == ["-HUP", "mDNSResponder"]
        }));
    }
}
