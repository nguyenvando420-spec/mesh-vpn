//! Windows fixed-adapter overlay routing backend (`US-015`, `US-016`, `REL-09`, `WP-S1-04`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mesh_core::{AppError, AppResult, OverlayCidr};
use mesh_sys::netmon_windows::windows_system_directory;

use crate::firewall_windows::WindowsFirewallManager;
use crate::hosts::HostsEditor as _;
use crate::hosts_windows::{WindowsHostsEditor, windows_hosts_path};
use crate::ledger::{LedgerCleanupOps, LedgerIpRuleEntry, LedgerRouteEntry, ResourceLedger};
use crate::route::{LinuxPolicyRoutingSpec, RouteManager, RouteSpec};
use crate::sysexec::{
    AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, StdCommandExecutor,
};

const DEFAULT_CLEANUP_HOSTS_BUDGET: Duration = Duration::from_secs(2);

/// Windows Wintun overlay-only route manager using `GetSystemDirectoryW` + `netsh.exe` (`sysexec`).
#[derive(Clone, Default)]
pub struct WindowsRouteManager {
    executor: Option<Arc<dyn CommandExecutor>>,
}

impl std::fmt::Debug for WindowsRouteManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsRouteManager")
            .field("custom_executor", &self.executor.is_some())
            .finish()
    }
}

impl WindowsRouteManager {
    /// Creates a Windows route manager resolving `System32` dynamically via `GetSystemDirectoryW`.
    #[must_use]
    pub const fn new() -> Self {
        Self { executor: None }
    }

    /// Creates a route manager backed by a caller-supplied [`CommandExecutor`] (for tests).
    #[must_use]
    pub fn with_executor(executor: Arc<dyn CommandExecutor>) -> Self {
        Self {
            executor: Some(executor),
        }
    }

    /// Records the overlay route into `ledger` BEFORE applying it on the OS (`REL-08`).
    pub fn apply_overlay_route_with_ledger(
        &self,
        spec: &RouteSpec,
        ledger: &mut ResourceLedger,
    ) -> AppResult<()> {
        validate_windows_route_spec(spec)?;
        let entry = LedgerRouteEntry {
            destination_cidr: spec.destination_cidr.to_string(),
            interface_name: spec.interface_name.clone(),
            table: spec.table,
        };
        ledger.record_route_before_add(entry)?;
        self.apply_overlay_route(spec)
    }

    fn run_command(&self, spec: &CommandSpec, allow_absent: bool) -> AppResult<()> {
        let out = execute_windows_command(self.executor.as_deref(), spec)?;
        check_windows_netsh_output(&out, allow_absent)
    }
}

fn execute_windows_command(
    executor: Option<&dyn CommandExecutor>,
    spec: &CommandSpec,
) -> AppResult<CommandOutput> {
    if let Some(exec) = executor {
        return exec.execute(spec);
    }
    let sys_dir = windows_system_directory().map_err(AppError::from)?;
    let exec = StdCommandExecutor::with_windows_system32_dir(sys_dir)?;
    exec.execute(spec)
}

fn check_windows_netsh_output(out: &CommandOutput, allow_absent: bool) -> AppResult<()> {
    if out.success() || (allow_absent && is_windows_route_absent(out)) {
        return Ok(());
    }
    let detail = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let clipped: String = detail.chars().take(240).collect();
    Err(AppError::internal(format!(
        "Windows netsh route command failed (exit {}): {clipped}",
        out.status_code
    )))
}

fn is_windows_route_absent(out: &CommandOutput) -> bool {
    let combined = format!("{} {}", out.stderr, out.stdout).to_ascii_lowercase();
    combined.contains("element not found")
        || combined.contains("not found")
        || combined.contains("does not exist")
        || combined.contains("cannot find")
        || combined.contains("no routes")
}

fn validate_windows_route_spec(spec: &RouteSpec) -> AppResult<()> {
    if spec.destination_cidr.prefix_len() == 0 {
        return Err(AppError::invalid_argument(
            "refusing to install default route (0.0.0.0/0 or ::/0) on Windows",
        ));
    }
    let iface = spec.interface_name.trim();
    if iface.is_empty() || iface.contains('\0') {
        return Err(AppError::invalid_argument(
            "Windows route interface name must be non-empty",
        ));
    }
    Ok(())
}

impl RouteManager for WindowsRouteManager {
    fn apply_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        validate_windows_route_spec(spec)?;
        let cidr = spec.destination_cidr.to_string();
        let iface = spec.interface_name.trim().to_owned();

        // Remove any identical stale route best-effort so repeated startup stays idempotent.
        let del_spec = build_delete_route_command(&cidr, &iface)?;
        self.run_command(&del_spec, true)?;

        let add_spec = CommandSpec::new(
            AllowedBinary::WindowsNetsh,
            vec![
                "interface".to_owned(),
                "ipv4".to_owned(),
                "add".to_owned(),
                "route".to_owned(),
                cidr,
                iface,
                "store=active".to_owned(),
            ],
        )?;
        self.run_command(&add_spec, false)
    }

    fn remove_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        validate_windows_route_spec(spec)?;
        let del_spec = build_delete_route_command(
            &spec.destination_cidr.to_string(),
            spec.interface_name.trim(),
        )?;
        self.run_command(&del_spec, true)
    }

    fn apply_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }

    fn remove_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }
}

fn build_delete_route_command(cidr: &str, interface_name: &str) -> AppResult<CommandSpec> {
    CommandSpec::new(
        AllowedBinary::WindowsNetsh,
        vec![
            "interface".to_owned(),
            "ipv4".to_owned(),
            "delete".to_owned(),
            "route".to_owned(),
            cidr.to_owned(),
            interface_name.to_owned(),
            "store=active".to_owned(),
        ],
    )
}

/// Crash-recovery and shutdown cleanup adapter implementing [`LedgerCleanupOps`] on Windows (`BLK-S1-08`).
#[derive(Debug, Clone)]
pub struct WindowsCleanupOps<E = StdCommandExecutor> {
    executor: Option<Arc<E>>,
    hosts_retry_budget: Duration,
}

impl Default for WindowsCleanupOps<StdCommandExecutor> {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsCleanupOps<StdCommandExecutor> {
    /// Creates a production Windows cleanup adapter resolving `System32` via `GetSystemDirectoryW`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            executor: None,
            hosts_retry_budget: DEFAULT_CLEANUP_HOSTS_BUDGET,
        }
    }
}

impl<E: CommandExecutor> WindowsCleanupOps<E> {
    /// Creates a Windows cleanup adapter backed by a custom [`CommandExecutor`] (for tests).
    #[must_use]
    pub fn with_executor(executor: E) -> Self {
        Self {
            executor: Some(Arc::new(executor)),
            hosts_retry_budget: DEFAULT_CLEANUP_HOSTS_BUDGET,
        }
    }

    /// Overrides the transient file-lock backoff budget when clearing the `hosts` block.
    #[must_use]
    pub const fn with_hosts_retry_budget(mut self, budget: Duration) -> Self {
        self.hosts_retry_budget = budget;
        self
    }
}

impl<E: CommandExecutor + 'static> LedgerCleanupOps for WindowsCleanupOps<E> {
    fn remove_routes(&self, routes: &[LedgerRouteEntry]) -> AppResult<()> {
        for entry in routes {
            let cidr = entry.destination_cidr.parse::<OverlayCidr>()?;
            if cidr.prefix_len() == 0 {
                return Err(AppError::invalid_argument(
                    "refusing ledger cleanup of default route on Windows",
                ));
            }
            let iface = entry.interface_name.trim();
            if iface.is_empty() || iface.contains('\0') {
                return Err(AppError::invalid_argument(
                    "invalid interface name in Windows ledger route entry",
                ));
            }
            let del_spec = build_delete_route_command(&cidr.to_string(), iface)?;
            let exec_ref = self.executor.as_deref().map(|e| e as &dyn CommandExecutor);
            let out = execute_windows_command(exec_ref, &del_spec)?;
            check_windows_netsh_output(&out, true)?;
        }
        Ok(())
    }

    fn remove_linux_policy(
        &self,
        _table: Option<u32>,
        _rules: &[LedgerIpRuleEntry],
    ) -> AppResult<()> {
        Ok(())
    }

    fn remove_hosts_block(&self, hosts_real_path: Option<&str>) -> AppResult<()> {
        let path = match hosts_real_path {
            Some(p) => PathBuf::from(p),
            None => windows_hosts_path()?,
        };
        let flush_exec = self
            .executor
            .as_ref()
            .map(|e| Arc::clone(e) as Arc<dyn CommandExecutor>);
        let editor = WindowsHostsEditor::with_path(path, self.hosts_retry_budget, flush_exec);
        editor.clear()
    }

    fn remove_firewall_rules(
        &self,
        _pf_anchor_name: Option<&str>,
        rule_names: &[String],
    ) -> AppResult<()> {
        let mgr = match &self.executor {
            Some(exec) => {
                WindowsFirewallManager::with_executor(Arc::clone(exec) as Arc<dyn CommandExecutor>)
            }
            None => WindowsFirewallManager::new(),
        };
        for rule in rule_names {
            mgr.remove_overlay_rule(rule)?;
        }
        Ok(())
    }

    fn close_tun_interface(
        &self,
        tun_interface_name: Option<&str>,
        windows_adapter_guid: Option<&str>,
    ) -> AppResult<()> {
        if let Some(name) = tun_interface_name {
            let trimmed = name.trim();
            if trimmed.is_empty() || trimmed.len() > 63 || trimmed.contains('\0') {
                return Err(AppError::invalid_argument(
                    "invalid Wintun interface name in Windows ledger",
                ));
            }
        }
        tracing::info!(
            target: "mesh::net::route_windows",
            adapter = tun_interface_name.unwrap_or("MeshVPN"),
            guid = windows_adapter_guid.unwrap_or("unknown"),
            "Completed Wintun adapter ledger teardown on Windows"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;

    use mesh_core::OverlayCidr;
    use mesh_core::brand::{HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
    use tempfile::tempdir;

    use super::{WindowsCleanupOps, WindowsRouteManager};
    use crate::ledger::{LedgerRouteEntry, ResourceLedger};
    use crate::route::{RouteManager, RouteSpec};
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};

    #[test]
    fn test_route_windows_rejects_default_route() {
        // Arrange
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let mgr = WindowsRouteManager::with_executor(Arc::clone(&fake_exec) as _);
        let default_v4 = "0.0.0.0/0".parse::<OverlayCidr>();
        let overlay = "100.64.0.0/10".parse::<OverlayCidr>();

        // Act
        if let (Ok(dest), Ok(allowed)) = (default_v4, overlay) {
            let spec = RouteSpec::new(dest, allowed, "MeshVPN", None);
            if let Ok(spec) = spec {
                assert!(mgr.apply_overlay_route(&spec).is_err());
            }
        }

        // Assert
        let recorded = fake_exec.recorded();
        assert!(recorded.is_ok());
        if let Ok(calls) = recorded {
            assert!(calls.is_empty());
        }
    }

    #[test]
    fn test_route_windows_applies_and_removes_overlay_route_via_netsh() {
        // Arrange
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let mgr = WindowsRouteManager::with_executor(Arc::clone(&fake_exec) as _);
        let cidr = "100.64.0.0/10".parse::<OverlayCidr>();
        assert!(cidr.is_ok());
        let Ok(cidr) = cidr else {
            return;
        };
        let spec = RouteSpec::new(cidr, cidr, "MeshVPN", None);
        assert!(spec.is_ok());
        let Ok(spec) = spec else {
            return;
        };

        // Act
        let add_res = mgr.apply_overlay_route(&spec);
        let del_res = mgr.remove_overlay_route(&spec);

        // Assert
        assert!(add_res.is_ok(), "apply_overlay_route failed: {add_res:?}");
        assert!(del_res.is_ok(), "remove_overlay_route failed: {del_res:?}");
        let recorded = fake_exec.recorded();
        assert!(recorded.is_ok());
        if let Ok(calls) = recorded {
            assert_eq!(calls.len(), 3);
            assert!(
                calls
                    .iter()
                    .all(|c| c.binary == AllowedBinary::WindowsNetsh)
            );
        }
    }

    #[test]
    fn test_route_windows_fails_on_nonzero_netsh_status_and_handles_absent_route() {
        // Arrange
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let mgr = WindowsRouteManager::with_executor(Arc::clone(&fake_exec) as _);
        let cidr = "100.64.0.0/10".parse::<OverlayCidr>();
        assert!(cidr.is_ok());
        let Ok(cidr) = cidr else {
            return;
        };
        let spec = RouteSpec::new(cidr, cidr, "MeshVPN", None);
        assert!(spec.is_ok());
        let Ok(spec) = spec else {
            return;
        };

        // 1) Pre-delete returns absent -> proceeds, 2) add returns status_code = 1 ("Access is denied.") -> Err.
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: "Element not found.".to_owned(),
                    stderr: String::new(),
                }))
                .is_ok()
        );
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: String::new(),
                    stderr: "Access is denied.".to_owned(),
                }))
                .is_ok()
        );
        // 3) remove returns status_code = 1 ("Access is denied.") -> Err.
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: String::new(),
                    stderr: "Access is denied.".to_owned(),
                }))
                .is_ok()
        );
        // 4) remove returns absent -> Ok.
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: "Element not found.".to_owned(),
                    stderr: String::new(),
                }))
                .is_ok()
        );

        // Act / Assert
        assert!(mgr.apply_overlay_route(&spec).is_err());
        assert!(mgr.remove_overlay_route(&spec).is_err());
        assert!(mgr.remove_overlay_route(&spec).is_ok());
    }

    #[test]
    fn test_route_windows_cleanup_ops_runs_with_resource_ledger_cleanup_all() {
        // Arrange
        let dir = tempdir();
        assert!(dir.is_ok());
        let Ok(dir) = dir else {
            return;
        };
        let ledger_path = dir.path().join("ledger.json");
        let hosts_path = dir.path().join("hosts");
        let initial_hosts = format!(
            "127.0.0.1 localhost\r\n{HOSTS_BEGIN_MARKER}\r\n100.64.0.10 nas.mesh.internal nas\r\n{HOSTS_END_MARKER}\r\n"
        );
        assert!(fs::write(&hosts_path, initial_hosts).is_ok());

        let ledger = ResourceLedger::load_or_init(ledger_path);
        assert!(ledger.is_ok());
        let Ok(mut ledger) = ledger else {
            return;
        };
        assert!(
            ledger
                .record_tun_before_create(
                    "MeshVPN".to_owned(),
                    Some("{4d455348-5650-4e31-8000-000000000001}".to_owned()),
                    4242,
                    1_700_000_000_000,
                )
                .is_ok()
        );
        assert!(
            ledger
                .record_route_before_add(LedgerRouteEntry {
                    destination_cidr: "100.64.0.0/10".to_owned(),
                    interface_name: "MeshVPN".to_owned(),
                    table: None,
                })
                .is_ok()
        );
        assert!(
            ledger
                .record_hosts_before_activate(hosts_path.display().to_string())
                .is_ok()
        );
        assert!(
            ledger
                .record_firewall_before_apply(None, vec!["MeshVPN-Overlay-Inbound".to_owned()])
                .is_ok()
        );

        let fake_exec = FakeCommandExecutor::new();
        let cleanup = WindowsCleanupOps::with_executor(fake_exec.clone())
            .with_hosts_retry_budget(Duration::from_millis(50));

        // Act
        let cleanup_res = ledger.cleanup_all(&cleanup);

        // Assert
        assert!(cleanup_res.is_ok(), "cleanup_all failed: {cleanup_res:?}");
        assert!(!ledger.needs_stale_recovery());
        let after_hosts = fs::read_to_string(&hosts_path);
        assert!(after_hosts.is_ok());
        if let Ok(text) = after_hosts {
            assert!(text.contains("127.0.0.1 localhost"));
            assert!(!text.contains(HOSTS_BEGIN_MARKER));
            assert!(!text.contains("nas.mesh.internal"));
        }
        let recorded = fake_exec.recorded();
        assert!(recorded.is_ok());
        if let Ok(calls) = recorded {
            assert_eq!(calls.len(), 3);
            assert!(matches!(
                calls.first().map(|c| c.binary),
                Some(AllowedBinary::WindowsNetsh)
            ));
            assert!(matches!(
                calls.get(1).map(|c| c.binary),
                Some(AllowedBinary::WindowsIpconfig)
            ));
            assert!(matches!(
                calls.get(2).map(|c| c.binary),
                Some(AllowedBinary::WindowsNetsh)
            ));
        }
    }
}
