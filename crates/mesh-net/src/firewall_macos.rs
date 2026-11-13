//! macOS Application Firewall inspection and scoped `pf` anchor management (`US-073 AC6`, `G4`).

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use mesh_core::{AppError, AppResult};

use crate::ledger::ResourceLedger;
use crate::sysexec::{AllowedBinary, CommandExecutor, CommandSpec, StdCommandExecutor};

/// Dedicated macOS `pf` anchor name owned exclusively by Mesh VPN (never modifies `/etc/pf.conf`).
pub const MESH_PF_ANCHOR_NAME: &str = "com.internal.mesh";

/// Snapshot of macOS Application Firewall (`socketfilterfw`) state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacOsFirewallStatus {
    /// Whether the macOS Application Firewall is enabled.
    pub enabled: bool,
    /// Whether stealth mode is enabled (`--getstealthmode`).
    pub stealth_mode: bool,
    /// Whether all non-essential incoming connections are blocked (`--getblockall`).
    pub block_all_incoming: bool,
}

/// Returns `true` when the macOS Application Firewall is enabled (`socketfilterfw --getglobalstate`).
pub fn inspect_application_firewall() -> AppResult<bool> {
    let executor = StdCommandExecutor::new();
    inspect_application_firewall_with(&executor)
}

/// Returns `true` when the macOS Application Firewall is enabled using an injected [`CommandExecutor`].
pub fn inspect_application_firewall_with(executor: &dyn CommandExecutor) -> AppResult<bool> {
    let spec = CommandSpec::new(
        AllowedBinary::MacOsSocketFilterFw,
        ["--getglobalstate".to_owned()],
    )?;
    let out = executor.execute(&spec)?;
    if !out.success() {
        return Err(AppError::internal(format!(
            "socketfilterfw --getglobalstate failed (exit {}): {}",
            out.status_code,
            out.stderr.trim()
        )));
    }
    Ok(parse_socketfilterfw_enabled(&out.stdout))
}

/// Inspects enabled, stealth, and block-all Application Firewall flags (`US-073 AC6`).
pub fn inspect_firewall_status_with(
    executor: &dyn CommandExecutor,
) -> AppResult<MacOsFirewallStatus> {
    let enabled = inspect_application_firewall_with(executor)?;
    let stealth_mode = query_socketfilterfw_flag(executor, "--getstealthmode");
    let block_all_incoming = query_socketfilterfw_flag(executor, "--getblockall");

    if block_all_incoming || stealth_mode {
        tracing::warn!(
            component = "firewall_macos",
            event = "macos_firewall_restrictive",
            enabled,
            stealth_mode,
            block_all_incoming,
            "macOS Application Firewall restricts direct incoming P2P packets; relay fallback remains available"
        );
    }

    Ok(MacOsFirewallStatus {
        enabled,
        stealth_mode,
        block_all_incoming,
    })
}

/// Opt-in adds an unblock exception in `socketfilterfw` strictly for the verified daemon binary.
pub fn optin_unblock_daemon(executor: &dyn CommandExecutor, binary_path: &Path) -> AppResult<()> {
    let bin_str = validate_binary_path_str(binary_path)?;
    for flag in ["--add", "--unblockapp"] {
        let spec = CommandSpec::new(
            AllowedBinary::MacOsSocketFilterFw,
            [flag.to_owned(), bin_str.to_owned()],
        )?;
        let out = executor.execute(&spec)?;
        if !out.success() {
            return Err(AppError::internal(format!(
                "socketfilterfw {flag} failed (exit {}): {}",
                out.status_code,
                out.stderr.trim()
            )));
        }
    }
    Ok(())
}

/// Removes a previously granted opt-in `socketfilterfw` rule during uninstall (`US-073 AC9`).
pub fn remove_optin_unblock_daemon(
    executor: &dyn CommandExecutor,
    binary_path: &Path,
) -> AppResult<()> {
    let bin_str = validate_binary_path_str(binary_path)?;
    let spec = CommandSpec::new(
        AllowedBinary::MacOsSocketFilterFw,
        ["--remove".to_owned(), bin_str.to_owned()],
    )?;
    let out = executor.execute(&spec)?;
    if out.success() || out.stderr.to_ascii_lowercase().contains("not found") {
        return Ok(());
    }
    Err(AppError::internal(format!(
        "socketfilterfw --remove failed (exit {}): {}",
        out.status_code,
        out.stderr.trim()
    )))
}

/// Applies rules exclusively inside the `com.internal.mesh` `pf` anchor after persisting
/// anchor ownership to `ResourceLedger`. Never flushes or alters `/etc/pf.conf`.
pub fn apply_pf_anchor_with_ledger(
    executor: &dyn CommandExecutor,
    anchor_file_path: &Path,
    rules_text: &str,
    ledger: &mut ResourceLedger,
) -> AppResult<()> {
    if !anchor_file_path.is_absolute() {
        return Err(AppError::invalid_argument(
            "pf anchor rules path must be absolute",
        ));
    }

    ledger.record_firewall_before_apply(Some(MESH_PF_ANCHOR_NAME.to_owned()), Vec::new())?;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(anchor_file_path)
        .map_err(|err| {
            AppError::internal(format!(
                "failed writing pf anchor rules {}: {err}",
                anchor_file_path.display()
            ))
        })?;
    file.write_all(rules_text.as_bytes()).map_err(|err| {
        AppError::internal(format!(
            "failed flushing pf anchor rules {}: {err}",
            anchor_file_path.display()
        ))
    })?;
    file.sync_all().map_err(|err| {
        AppError::internal(format!(
            "failed syncing pf anchor rules {}: {err}",
            anchor_file_path.display()
        ))
    })?;
    drop(file);

    let spec = CommandSpec::new(
        AllowedBinary::MacOsPfctl,
        [
            "-a".to_owned(),
            MESH_PF_ANCHOR_NAME.to_owned(),
            "-f".to_owned(),
            anchor_file_path.display().to_string(),
        ],
    )?;
    let out = executor.execute(&spec)?;
    if !out.success() {
        return Err(AppError::internal(format!(
            "/sbin/pfctl anchor apply failed (exit {}): {}",
            out.status_code,
            out.stderr.trim()
        )));
    }
    Ok(())
}

/// Flushes ONLY the `com.internal.mesh` `pf` anchor idempotently (`US-055`, `US-073 AC9`).
pub fn remove_pf_anchor(executor: &dyn CommandExecutor) -> AppResult<()> {
    let spec = CommandSpec::new(
        AllowedBinary::MacOsPfctl,
        [
            "-a".to_owned(),
            MESH_PF_ANCHOR_NAME.to_owned(),
            "-F".to_owned(),
            "all".to_owned(),
        ],
    )?;
    let out = executor.execute(&spec)?;
    if out.success() || out.stderr.to_ascii_lowercase().contains("does not exist") {
        return Ok(());
    }
    Err(AppError::internal(format!(
        "/sbin/pfctl anchor cleanup failed (exit {}): {}",
        out.status_code,
        out.stderr.trim()
    )))
}

fn validate_binary_path_str(path: &Path) -> AppResult<&str> {
    if !path.is_absolute() {
        return Err(AppError::invalid_argument(
            "firewall daemon path must be absolute",
        ));
    }
    path.to_str()
        .ok_or_else(|| AppError::invalid_argument("firewall daemon path must be valid UTF-8"))
}

fn parse_socketfilterfw_enabled(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    lower.contains("enabled") && !lower.contains("disabled")
}

fn query_socketfilterfw_flag(executor: &dyn CommandExecutor, flag: &str) -> bool {
    let Ok(spec) = CommandSpec::new(AllowedBinary::MacOsSocketFilterFw, [flag.to_owned()]) else {
        return false;
    };
    executor
        .execute(&spec)
        .is_ok_and(|out| out.success() && parse_socketfilterfw_enabled(&out.stdout))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        MESH_PF_ANCHOR_NAME, apply_pf_anchor_with_ledger, inspect_firewall_status_with,
        optin_unblock_daemon, remove_pf_anchor,
    };
    use crate::ledger::ResourceLedger;
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};

    #[test]
    fn test_firewall_macos_inspects_stealth_and_block_all_states() {
        // Arrange
        let executor = FakeCommandExecutor::new();
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: "Firewall is enabled. (State = 1)\n".to_owned(),
                stderr: String::new(),
            }))
            .expect("queue globalstate");
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: "Stealth mode disabled\n".to_owned(),
                stderr: String::new(),
            }))
            .expect("queue stealth");
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: "Block all incoming enabled\n".to_owned(),
                stderr: String::new(),
            }))
            .expect("queue blockall");

        // Act
        let status = inspect_firewall_status_with(&executor).expect("inspect status");

        // Assert
        assert!(status.enabled);
        assert!(!status.stealth_mode);
        assert!(status.block_all_incoming);
    }

    #[test]
    fn test_firewall_macos_anchor_apply_and_remove_scopes_only_com_internal_mesh() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let mut ledger =
            ResourceLedger::load_or_init(dir.path().join("ledger.json")).expect("ledger");
        let anchor_file = dir.path().join("mesh.pf.conf");
        let exec = FakeCommandExecutor::new();
        for _ in 0..4 {
            exec.push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue ok");
        }

        // Act
        apply_pf_anchor_with_ledger(
            &exec,
            &anchor_file,
            "pass quick on utun7 all\n",
            &mut ledger,
        )
        .expect("apply anchor");
        optin_unblock_daemon(&exec, Path::new("/usr/local/libexec/mesh/meshd"))
            .expect("optin unblock");
        remove_pf_anchor(&exec).expect("remove anchor");

        // Assert
        assert_eq!(
            ledger.data().pf_anchor_name.as_deref(),
            Some(MESH_PF_ANCHOR_NAME)
        );
        let recorded = exec.recorded().expect("recorded");
        assert!(recorded.iter().any(|c| {
            c.binary == AllowedBinary::MacOsPfctl
                && c.args.first().map(String::as_str) == Some("-a")
                && c.args.get(1).map(String::as_str) == Some(MESH_PF_ANCHOR_NAME)
        }));
        assert!(recorded.iter().any(|c| {
            c.binary == AllowedBinary::MacOsSocketFilterFw
                && c.args.first().map(String::as_str) == Some("--unblockapp")
        }));
    }
}
