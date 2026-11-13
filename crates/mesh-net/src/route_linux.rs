//! Linux policy routing (`table 51820`, `SO_MARK 0x5d56`) and overlay routes (`HR-G2-01`, `REL-09`).

use std::path::PathBuf;
use std::sync::Arc;

use mesh_core::{AppError, AppResult};

use crate::hosts::{FileHostsEditor, HostsEditor};
use crate::ledger::{LedgerCleanupOps, LedgerIpRuleEntry, LedgerRouteEntry, ResourceLedger};
use crate::route::{LinuxPolicyRoutingSpec, RouteManager, RouteSpec};
use crate::sysexec::{
    AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, StdCommandExecutor,
};
use crate::tun_linux::execute_ip_with_fallback;

/// Linux overlay route and anti-routing-loop policy manager backed by allowlisted `ip(8)` binaries.
#[derive(Debug, Clone, Default)]
pub struct LinuxRouteManager {
    executor: Option<Arc<dyn CommandExecutor>>,
}

impl LinuxRouteManager {
    /// Creates a production route manager invoking `/usr/sbin/ip` (fallback `/sbin/ip`).
    #[must_use]
    pub const fn new() -> Self {
        Self { executor: None }
    }

    /// Creates a route manager using a caller-supplied [`CommandExecutor`] for testing.
    #[must_use]
    pub fn with_executor(executor: Arc<dyn CommandExecutor>) -> Self {
        Self {
            executor: Some(executor),
        }
    }

    /// Records the policy table & rules in `ResourceLedger` **before** applying `ip rule` entries.
    pub fn apply_linux_policy_with_ledger(
        &self,
        policy: &LinuxPolicyRoutingSpec,
        ledger: &mut ResourceLedger,
    ) -> AppResult<()> {
        let rules = build_ledger_rules(policy);
        ledger.record_linux_policy_before_apply(policy.table, rules)?;
        self.apply_linux_policy(policy)
    }

    /// Records an overlay CIDR route in `ResourceLedger` **before** running `ip route replace`.
    pub fn apply_overlay_route_with_ledger(
        &self,
        spec: &RouteSpec,
        ledger: &mut ResourceLedger,
    ) -> AppResult<()> {
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

impl RouteManager for LinuxRouteManager {
    fn apply_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        mesh_sys::tun_linux::validate_linux_ifname(&spec.interface_name)?;
        let mut args = vec![
            "route".to_owned(),
            "replace".to_owned(),
            spec.destination_cidr.to_string(),
            "dev".to_owned(),
            spec.interface_name.clone(),
        ];
        if let Some(table) = spec.table {
            args.push("table".to_owned());
            args.push(table.to_string());
        }

        self.exec_with(|exec| execute_ip_with_fallback(exec, args))
    }

    fn remove_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        mesh_sys::tun_linux::validate_linux_ifname(&spec.interface_name)?;
        let mut args = vec![
            "route".to_owned(),
            "del".to_owned(),
            spec.destination_cidr.to_string(),
            "dev".to_owned(),
            spec.interface_name.clone(),
        ];
        if let Some(table) = spec.table {
            args.push("table".to_owned());
            args.push(table.to_string());
        }

        self.exec_with(|exec| execute_ip_idempotent_delete(exec, args))
    }

    fn apply_linux_policy(&self, policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        let fwmark_hex = format!("0x{:x}", policy.fwmark);
        let overlay_args =
            overlay_rule_args(policy.overlay_rule_priority, &fwmark_hex, policy.table);
        let suppress_args = suppress_main_rule_args(policy.main_suppress_priority);

        // Remove any identical stale rules left by an unclean exit before adding cleanly.
        self.exec_with(|exec| -> AppResult<()> {
            let mut del_overlay = vec!["rule".to_owned(), "del".to_owned()];
            del_overlay.extend_from_slice(&overlay_args);
            execute_ip_idempotent_delete(exec, del_overlay)?;

            let mut del_suppress = vec!["rule".to_owned(), "del".to_owned()];
            del_suppress.extend_from_slice(&suppress_args);
            execute_ip_idempotent_delete(exec, del_suppress)?;

            let mut add_overlay = vec!["rule".to_owned(), "add".to_owned()];
            add_overlay.extend(overlay_args);
            execute_ip_with_fallback(exec, add_overlay)?;

            let mut add_suppress = vec!["rule".to_owned(), "add".to_owned()];
            add_suppress.extend(suppress_args);
            execute_ip_with_fallback(exec, add_suppress)
        })?;

        tracing::info!(
            component = "route_linux",
            event = "linux_policy_applied",
            table = policy.table,
            fwmark = %fwmark_hex,
            overlay_priority = policy.overlay_rule_priority,
            suppress_priority = policy.main_suppress_priority,
            "applied Linux anti-routing-loop policy rules"
        );
        Ok(())
    }

    fn remove_linux_policy(&self, policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        let fwmark_hex = format!("0x{:x}", policy.fwmark);
        let mut del_overlay = vec!["rule".to_owned(), "del".to_owned()];
        del_overlay.extend(overlay_rule_args(
            policy.overlay_rule_priority,
            &fwmark_hex,
            policy.table,
        ));

        let mut del_suppress = vec!["rule".to_owned(), "del".to_owned()];
        del_suppress.extend(suppress_main_rule_args(policy.main_suppress_priority));

        let flush_args = vec![
            "route".to_owned(),
            "flush".to_owned(),
            "table".to_owned(),
            policy.table.to_string(),
        ];

        self.exec_with(|exec| -> AppResult<()> {
            execute_ip_idempotent_delete(exec, del_overlay)?;
            execute_ip_idempotent_delete(exec, del_suppress)?;
            execute_ip_idempotent_delete(exec, flush_args)
        })?;

        tracing::info!(
            component = "route_linux",
            event = "linux_policy_removed",
            table = policy.table,
            "removed Linux anti-routing-loop policy rules and flushed table"
        );
        Ok(())
    }
}

/// Crash-recovery and shutdown cleanup adapter implementing [`LedgerCleanupOps`] on Linux.
#[derive(Debug, Clone, Default)]
pub struct LinuxCleanupOps {
    executor: Option<Arc<dyn CommandExecutor>>,
}

impl LinuxCleanupOps {
    /// Creates a production Linux cleanup handler.
    #[must_use]
    pub const fn new() -> Self {
        Self { executor: None }
    }

    /// Creates a cleanup handler backed by a custom [`CommandExecutor`] for testing.
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

impl LedgerCleanupOps for LinuxCleanupOps {
    fn remove_routes(&self, routes: &[LedgerRouteEntry]) -> AppResult<()> {
        for entry in routes {
            mesh_sys::tun_linux::validate_linux_ifname(&entry.interface_name)?;
            let mut args = vec![
                "route".to_owned(),
                "del".to_owned(),
                entry.destination_cidr.clone(),
                "dev".to_owned(),
                entry.interface_name.clone(),
            ];
            if let Some(table) = entry.table {
                args.push("table".to_owned());
                args.push(table.to_string());
            }
            self.exec_with(|exec| execute_ip_idempotent_delete(exec, args))?;
        }
        Ok(())
    }

    fn remove_linux_policy(
        &self,
        table: Option<u32>,
        rules: &[LedgerIpRuleEntry],
    ) -> AppResult<()> {
        for rule in rules {
            let mut args = vec![
                "rule".to_owned(),
                "del".to_owned(),
                "priority".to_owned(),
                rule.priority.to_string(),
            ];
            if let Some(mark) = rule.not_fwmark {
                args.push("not".to_owned());
                args.push("fwmark".to_owned());
                args.push(format!("0x{mark:x}"));
            }
            args.push("table".to_owned());
            args.push(table_name_for_id(rule.lookup_table));
            if let Some(suppress) = rule.suppress_prefixlength {
                args.push("suppress_prefixlength".to_owned());
                args.push(suppress.to_string());
            }
            self.exec_with(|exec| execute_ip_idempotent_delete(exec, args))?;
        }

        if let Some(table_id) = table {
            let flush = vec![
                "route".to_owned(),
                "flush".to_owned(),
                "table".to_owned(),
                table_id.to_string(),
            ];
            self.exec_with(|exec| execute_ip_idempotent_delete(exec, flush))?;
        }
        Ok(())
    }

    fn remove_hosts_block(&self, hosts_real_path: Option<&str>) -> AppResult<()> {
        let editor = match hosts_real_path {
            Some(path) => FileHostsEditor::new(PathBuf::from(path)),
            None => FileHostsEditor::default_system(),
        };
        editor.clear()
    }

    fn remove_firewall_rules(
        &self,
        _pf_anchor_name: Option<&str>,
        rule_names: &[String],
    ) -> AppResult<()> {
        self.exec_with(|exec| crate::firewall_linux::rollback_from_ledger_rules(exec, rule_names))
    }

    fn close_tun_interface(
        &self,
        tun_interface_name: Option<&str>,
        _windows_adapter_guid: Option<&str>,
    ) -> AppResult<()> {
        if let Some(ifname) = tun_interface_name {
            mesh_sys::tun_linux::validate_linux_ifname(ifname)?;
            let args = vec![
                "link".to_owned(),
                "del".to_owned(),
                "dev".to_owned(),
                ifname.to_owned(),
            ];
            self.exec_with(|exec| execute_ip_idempotent_delete(exec, args))?;
        }
        Ok(())
    }
}

fn build_ledger_rules(policy: &LinuxPolicyRoutingSpec) -> Vec<LedgerIpRuleEntry> {
    vec![
        LedgerIpRuleEntry {
            priority: policy.overlay_rule_priority,
            not_fwmark: Some(policy.fwmark),
            lookup_table: policy.table,
            suppress_prefixlength: None,
            family: "inet".to_owned(),
        },
        LedgerIpRuleEntry {
            priority: policy.main_suppress_priority,
            not_fwmark: None,
            lookup_table: 254,
            suppress_prefixlength: Some(0),
            family: "inet".to_owned(),
        },
    ]
}

fn overlay_rule_args(priority: u32, fwmark_hex: &str, table: u32) -> Vec<String> {
    vec![
        "priority".to_owned(),
        priority.to_string(),
        "not".to_owned(),
        "fwmark".to_owned(),
        fwmark_hex.to_owned(),
        "table".to_owned(),
        table.to_string(),
    ]
}

fn suppress_main_rule_args(priority: u32) -> Vec<String> {
    vec![
        "priority".to_owned(),
        priority.to_string(),
        "table".to_owned(),
        "main".to_owned(),
        "suppress_prefixlength".to_owned(),
        "0".to_owned(),
    ]
}

fn table_name_for_id(table_id: u32) -> String {
    if table_id == 254 {
        "main".to_owned()
    } else {
        table_id.to_string()
    }
}

fn execute_ip_idempotent_delete(
    executor: &dyn CommandExecutor,
    args: Vec<String>,
) -> AppResult<()> {
    let primary = CommandSpec::new(AllowedBinary::LinuxIpUsrSbin, args.clone())?;
    let output = match executor.execute(&primary) {
        Ok(out) => out,
        Err(err) => {
            let fallback = CommandSpec::new(AllowedBinary::LinuxIpSbin, args)?;
            executor.execute(&fallback).map_err(|fallback_err| {
                AppError::internal(format!(
                    "failed executing /usr/sbin/ip ({err}) and /sbin/ip ({fallback_err})"
                ))
            })?
        }
    };
    if is_ip_success_or_absent(&output) {
        return Ok(());
    }
    Err(AppError::internal(format!(
        "ip cleanup command failed (exit {}): {}",
        output.status_code,
        output.stderr.trim()
    )))
}

fn is_ip_success_or_absent(output: &CommandOutput) -> bool {
    if output.success() {
        return true;
    }
    let lower = output.stderr.to_ascii_lowercase();
    lower.contains("no such file")
        || lower.contains("no such process")
        || lower.contains("cannot find device")
        || lower.contains("does not exist")
        || lower.contains("not found")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use mesh_core::OverlayCidr;
    use tempfile::tempdir;

    use super::{LinuxCleanupOps, LinuxRouteManager};
    use crate::ledger::ResourceLedger;
    use crate::route::{LinuxPolicyRoutingSpec, RouteSpec};
    use crate::sysexec::{CommandOutput, FakeCommandExecutor};

    fn push_ok_n(executor: &FakeCommandExecutor, count: usize) {
        for _ in 0..count {
            executor
                .push_result(Ok(CommandOutput {
                    status_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }))
                .expect("queue ok");
        }
    }

    #[test]
    fn test_route_linux_policy_records_ledger_before_applying_ip_rules() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let ledger_path = dir.path().join("ledger.json");
        let mut ledger = ResourceLedger::load_or_init(ledger_path.clone()).expect("ledger");
        let exec = Arc::new(FakeCommandExecutor::new());
        push_ok_n(&exec, 5);
        let mgr = LinuxRouteManager::with_executor(
            Arc::clone(&exec) as Arc<dyn crate::sysexec::CommandExecutor>
        );
        let policy = LinuxPolicyRoutingSpec::default();
        let overlay = OverlayCidr::from_str("100.115.0.0/16").expect("cidr");
        let spec = RouteSpec::new(overlay, overlay, "mesh0", Some(51820)).expect("spec");

        // Act
        mgr.apply_linux_policy_with_ledger(&policy, &mut ledger)
            .expect("apply policy");
        mgr.apply_overlay_route_with_ledger(&spec, &mut ledger)
            .expect("apply route");

        // Assert
        let reloaded = ResourceLedger::load_or_init(ledger_path).expect("reload ledger");
        assert_eq!(reloaded.data().linux_routing_table, Some(51820));
        assert_eq!(reloaded.data().linux_ip_rules.len(), 2);
        assert_eq!(reloaded.data().installed_routes.len(), 1);
        let recorded = exec.recorded().expect("recorded");
        assert_eq!(recorded.len(), 5);
        assert!(recorded.get(2).is_some_and(|c| {
            c.args
                == [
                    "rule", "add", "priority", "51820", "not", "fwmark", "0x5d56", "table", "51820",
                ]
        }));
        assert!(recorded.get(3).is_some_and(|c| {
            c.args
                == [
                    "rule",
                    "add",
                    "priority",
                    "51810",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ]
        }));
    }

    #[test]
    fn test_route_linux_cleanup_ops_handles_absent_rules_idempotently() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let ledger_path = dir.path().join("ledger.json");
        let mut ledger = ResourceLedger::load_or_init(ledger_path).expect("ledger");
        let exec = Arc::new(FakeCommandExecutor::new());
        push_ok_n(&exec, 5);
        let mgr = LinuxRouteManager::with_executor(
            Arc::clone(&exec) as Arc<dyn crate::sysexec::CommandExecutor>
        );
        let policy = LinuxPolicyRoutingSpec::default();
        let overlay = OverlayCidr::from_str("100.115.0.0/16").expect("cidr");
        let spec = RouteSpec::new(overlay, overlay, "mesh0", Some(51820)).expect("spec");
        mgr.apply_linux_policy_with_ledger(&policy, &mut ledger)
            .expect("policy");
        mgr.apply_overlay_route_with_ledger(&spec, &mut ledger)
            .expect("route");

        // Simulate `RTNETLINK answers: No such file` during idempotent recovery
        let cleanup_exec = Arc::new(FakeCommandExecutor::new());
        for _ in 0..4 {
            cleanup_exec
                .push_result(Ok(CommandOutput {
                    status_code: 2,
                    stdout: String::new(),
                    stderr: "RTNETLINK answers: No such file or directory".to_owned(),
                }))
                .expect("queue enoent");
        }
        let ops = LinuxCleanupOps::with_executor(
            Arc::clone(&cleanup_exec) as Arc<dyn crate::sysexec::CommandExecutor>
        );

        // Act
        ledger.cleanup_all(&ops).expect("cleanup all");

        // Assert
        assert!(ledger.data().cleanly_stopped);
        assert!(ledger.data().linux_ip_rules.is_empty());
        assert!(ledger.data().installed_routes.is_empty());
    }

    #[test]
    fn test_route_linux_cleanup_ops_rolls_back_recorded_firewall_rules() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let ledger_path = dir.path().join("ledger.json");
        let mut ledger = ResourceLedger::load_or_init(ledger_path).expect("ledger");
        ledger
            .record_firewall_before_apply(
                None,
                vec![
                    "backend:iptables".to_owned(),
                    "control_tcp:8443".to_owned(),
                    "stun_udp:3479".to_owned(),
                ],
            )
            .expect("record firewall");

        let cleanup_exec = Arc::new(FakeCommandExecutor::new());
        push_ok_n(&cleanup_exec, 3);
        let ops = LinuxCleanupOps::with_executor(
            Arc::clone(&cleanup_exec) as Arc<dyn crate::sysexec::CommandExecutor>
        );

        // Act
        ledger.cleanup_all(&ops).expect("cleanup all with firewall");

        // Assert
        let recorded = cleanup_exec.recorded().expect("recorded");
        assert_eq!(recorded.len(), 3);
        assert!(
            recorded
                .first()
                .is_some_and(|c| c.args == ["-D", "INPUT", "-j", "MESH_VPN_INPUT"])
        );
        assert!(ledger.data().firewall_rule_names.is_empty());
        assert!(ledger.data().cleanly_stopped);
    }
}
