//! macOS overlay routing (`/sbin/route`) and targeted `utunN` cleanup (`US-060`, `REL-08`).

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use mesh_core::{AppError, AppResult};

use crate::firewall_macos::MESH_PF_ANCHOR_NAME;
use crate::hosts::{FileHostsEditor, HostsEditor};
use crate::hosts_macos::flush_dns_cache_with_executor;
use crate::ledger::{LedgerCleanupOps, LedgerIpRuleEntry, LedgerRouteEntry, ResourceLedger};
use crate::route::{LinuxPolicyRoutingSpec, RouteManager, RouteSpec};
use crate::sysexec::{
    AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, StdCommandExecutor,
};

/// macOS `/sbin/route` overlay-only route manager targeting strictly the session's `utunN`.
#[derive(Debug, Clone, Default)]
pub struct MacOsRouteManager {
    executor: Option<Arc<dyn CommandExecutor>>,
}

impl MacOsRouteManager {
    /// Creates a production macOS route manager executing `/sbin/route`.
    #[must_use]
    pub const fn new() -> Self {
        Self { executor: None }
    }

    /// Creates a macOS route manager backed by a caller-supplied [`CommandExecutor`].
    #[must_use]
    pub fn with_executor(executor: Arc<dyn CommandExecutor>) -> Self {
        Self {
            executor: Some(executor),
        }
    }

    /// Records the route in `ResourceLedger` **before** calling `/sbin/route -n add`.
    pub fn apply_overlay_route_with_ledger(
        &self,
        spec: &RouteSpec,
        ledger: &mut ResourceLedger,
    ) -> AppResult<()> {
        validate_macos_route_spec(spec)?;
        ledger.record_route_before_add(LedgerRouteEntry {
            destination_cidr: spec.destination_cidr.to_string(),
            interface_name: spec.interface_name.clone(),
            table: spec.table,
        })?;
        self.apply_overlay_route(spec)
    }

    fn exec_with<T>(&self, f: impl FnOnce(&dyn CommandExecutor) -> T) -> T {
        match &self.executor {
            Some(exec) => f(exec.as_ref()),
            None => {
                let std_exec = StdCommandExecutor::new();
                f(&std_exec)
            }
        }
    }
}

impl RouteManager for MacOsRouteManager {
    fn apply_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        validate_macos_route_spec(spec)?;
        let cidr = spec.destination_cidr.to_string();
        let add_spec = CommandSpec::new(
            AllowedBinary::MacOsRoute,
            [
                "-n".to_owned(),
                "add".to_owned(),
                "-net".to_owned(),
                cidr.clone(),
                "-interface".to_owned(),
                spec.interface_name.clone(),
            ],
        )?;

        self.exec_with(|exec| {
            let output = exec.execute(&add_spec)?;
            if output.success() {
                return Ok(());
            }
            if output.stderr.to_ascii_lowercase().contains("file exists") {
                let change_spec = CommandSpec::new(
                    AllowedBinary::MacOsRoute,
                    [
                        "-n".to_owned(),
                        "change".to_owned(),
                        "-net".to_owned(),
                        cidr,
                        "-interface".to_owned(),
                        spec.interface_name.clone(),
                    ],
                )?;
                let change_out = exec.execute(&change_spec)?;
                if change_out.success() {
                    return Ok(());
                }
                return Err(AppError::internal(format!(
                    "/sbin/route change failed (exit {}): {}",
                    change_out.status_code,
                    change_out.stderr.trim()
                )));
            }
            Err(AppError::internal(format!(
                "/sbin/route add failed (exit {}): {}",
                output.status_code,
                output.stderr.trim()
            )))
        })
    }

    fn remove_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        validate_macos_route_spec(spec)?;
        delete_macos_route_args(
            &self.executor,
            &spec.destination_cidr.to_string(),
            &spec.interface_name,
        )
    }

    fn apply_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }

    fn remove_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        Ok(())
    }
}

/// Crash-recovery and shutdown cleanup adapter implementing [`LedgerCleanupOps`] on macOS.
///
/// Strictly cleans ONLY the recorded `utunN`, overlay routes, `# BEGIN mesh ... # END mesh`
/// block, and `com.internal.mesh` `pf` anchor, never touching third-party VPN `utunK` (`US-060`).
#[derive(Debug, Clone, Default)]
pub struct MacOsCleanupOps {
    executor: Option<Arc<dyn CommandExecutor>>,
}

impl MacOsCleanupOps {
    /// Creates a production macOS cleanup adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self { executor: None }
    }

    /// Creates a macOS cleanup adapter backed by a custom [`CommandExecutor`] for testing.
    #[must_use]
    pub fn with_executor(executor: Arc<dyn CommandExecutor>) -> Self {
        Self {
            executor: Some(executor),
        }
    }

    fn exec_with<T>(&self, f: impl FnOnce(&dyn CommandExecutor) -> T) -> T {
        match &self.executor {
            Some(exec) => f(exec.as_ref()),
            None => {
                let std_exec = StdCommandExecutor::new();
                f(&std_exec)
            }
        }
    }
}

impl LedgerCleanupOps for MacOsCleanupOps {
    fn remove_routes(&self, routes: &[LedgerRouteEntry]) -> AppResult<()> {
        for entry in routes {
            mesh_sys::tun_macos::validate_utun_name(&entry.interface_name)?;
            delete_macos_route_args(
                &self.executor,
                &entry.destination_cidr,
                &entry.interface_name,
            )?;
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
        let editor = match hosts_real_path {
            Some(path) => FileHostsEditor::new(PathBuf::from(path)),
            None => FileHostsEditor::default_system(),
        };
        editor.clear()?;
        self.exec_with(flush_dns_cache_with_executor)
    }

    fn remove_firewall_rules(
        &self,
        pf_anchor_name: Option<&str>,
        _rule_names: &[String],
    ) -> AppResult<()> {
        if let Some(anchor) = pf_anchor_name {
            if anchor != MESH_PF_ANCHOR_NAME {
                return Err(AppError::invalid_argument(format!(
                    "refusing to flush non-mesh pf anchor '{anchor}'"
                )));
            }
            let spec = CommandSpec::new(
                AllowedBinary::MacOsPfctl,
                [
                    "-a".to_owned(),
                    MESH_PF_ANCHOR_NAME.to_owned(),
                    "-F".to_owned(),
                    "all".to_owned(),
                ],
            )?;
            self.exec_with(|exec| {
                let out = exec.execute(&spec)?;
                if out.success() || is_route_or_anchor_absent(&out) {
                    return Ok(());
                }
                Err(AppError::internal(format!(
                    "/sbin/pfctl anchor flush failed (exit {}): {}",
                    out.status_code,
                    out.stderr.trim()
                )))
            })?;
        }
        Ok(())
    }

    fn close_tun_interface(
        &self,
        tun_interface_name: Option<&str>,
        _windows_adapter_guid: Option<&str>,
    ) -> AppResult<()> {
        let Some(ifname) = tun_interface_name else {
            return Ok(());
        };
        mesh_sys::tun_macos::validate_utun_name(ifname)?;
        let spec = CommandSpec::new(
            AllowedBinary::MacOsIfconfig,
            [ifname.to_owned(), "down".to_owned()],
        )?;
        self.exec_with(|exec| {
            let out = exec.execute(&spec)?;
            if out.success() || is_route_or_anchor_absent(&out) {
                return Ok(());
            }
            Err(AppError::internal(format!(
                "/sbin/ifconfig {ifname} down failed (exit {}): {}",
                out.status_code,
                out.stderr.trim()
            )))
        })
    }
}

fn validate_macos_route_spec(spec: &RouteSpec) -> AppResult<()> {
    mesh_sys::tun_macos::validate_utun_name(&spec.interface_name)?;
    if spec.destination_cidr.prefix_len() == 0
        && spec.destination_cidr.network() == Ipv4Addr::UNSPECIFIED
    {
        return Err(AppError::invalid_argument(
            "default route 0.0.0.0/0 is forbidden on macOS",
        ));
    }
    Ok(())
}

fn delete_macos_route_args(
    executor: &Option<Arc<dyn CommandExecutor>>,
    cidr: &str,
    utun_name: &str,
) -> AppResult<()> {
    mesh_sys::tun_macos::validate_utun_name(utun_name)?;
    let spec = CommandSpec::new(
        AllowedBinary::MacOsRoute,
        [
            "-n".to_owned(),
            "delete".to_owned(),
            "-net".to_owned(),
            cidr.to_owned(),
            "-interface".to_owned(),
            utun_name.to_owned(),
        ],
    )?;
    let out = match executor {
        Some(exec) => exec.execute(&spec)?,
        None => StdCommandExecutor::new().execute(&spec)?,
    };
    if out.success() || is_route_or_anchor_absent(&out) {
        return Ok(());
    }
    Err(AppError::internal(format!(
        "/sbin/route delete failed (exit {}): {}",
        out.status_code,
        out.stderr.trim()
    )))
}

fn is_route_or_anchor_absent(out: &CommandOutput) -> bool {
    let lower = out.stderr.to_ascii_lowercase();
    lower.contains("not in table")
        || lower.contains("does not exist")
        || lower.contains("no such process")
        || lower.contains("anchor does not exist")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use mesh_core::OverlayCidr;
    use tempfile::tempdir;

    use super::{MacOsCleanupOps, MacOsRouteManager};
    use crate::firewall_macos::MESH_PF_ANCHOR_NAME;
    use crate::ledger::ResourceLedger;
    use crate::route::{RouteManager, RouteSpec};
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};

    #[test]
    fn test_route_macos_rejects_non_utun_interface_and_applies_route() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let ledger_path = dir.path().join("ledger.json");
        let mut ledger = ResourceLedger::load_or_init(ledger_path).expect("ledger");
        let exec = Arc::new(FakeCommandExecutor::new());
        exec.push_result(Ok(CommandOutput {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }))
        .expect("queue ok");
        let mgr = MacOsRouteManager::with_executor(
            Arc::clone(&exec) as Arc<dyn crate::sysexec::CommandExecutor>
        );
        let overlay = OverlayCidr::from_str("100.115.0.0/16").expect("cidr");
        let bad_spec = RouteSpec::new(overlay, overlay, "en0", None).expect("spec shape");
        let good_spec = RouteSpec::new(overlay, overlay, "utun7", None).expect("spec shape");

        // Act
        let rejected = mgr.apply_overlay_route(&bad_spec);
        mgr.apply_overlay_route_with_ledger(&good_spec, &mut ledger)
            .expect("apply utun7 route");

        // Assert
        assert!(rejected.is_err());
        assert_eq!(ledger.data().installed_routes.len(), 1);
        let recorded = exec.recorded().expect("recorded");
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded.first().map(|c| c.binary),
            Some(AllowedBinary::MacOsRoute)
        );
        assert!(recorded.first().is_some_and(|c| {
            c.args == ["-n", "add", "-net", "100.115.0.0/16", "-interface", "utun7"]
        }));
    }

    #[test]
    fn test_route_macos_cleanup_preserves_other_utun_and_flushes_only_mesh_anchor() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let ledger_path = dir.path().join("ledger.json");
        let mut ledger = ResourceLedger::load_or_init(ledger_path).expect("ledger");
        ledger
            .record_tun_before_create("utun7".to_owned(), None, 42, 1_700_000_000_000)
            .expect("record tun");
        ledger
            .record_firewall_before_apply(Some(MESH_PF_ANCHOR_NAME.to_owned()), Vec::new())
            .expect("record anchor");

        let exec = Arc::new(FakeCommandExecutor::new());
        for _ in 0..2 {
            exec.push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue ok");
        }
        let ops = MacOsCleanupOps::with_executor(
            Arc::clone(&exec) as Arc<dyn crate::sysexec::CommandExecutor>
        );

        // Act
        ledger.cleanup_all(&ops).expect("cleanup");

        // Assert
        let recorded = exec.recorded().expect("recorded");
        assert!(recorded.iter().any(|c| {
            c.binary == AllowedBinary::MacOsPfctl
                && c.args == ["-a", MESH_PF_ANCHOR_NAME, "-F", "all"]
        }));
        assert!(
            recorded.iter().any(|c| {
                c.binary == AllowedBinary::MacOsIfconfig && c.args == ["utun7", "down"]
            })
        );
    }
}
