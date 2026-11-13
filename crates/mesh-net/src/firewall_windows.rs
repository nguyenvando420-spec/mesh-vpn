//! Windows Firewall adapter profile and overlay rule management (`US-053`, `REL-08`, `WP-S1-04`).

use std::sync::Arc;

use mesh_core::{AppError, AppResult, OverlayCidr};
use mesh_sys::netmon_windows::windows_system_directory;

use crate::ledger::ResourceLedger;
use crate::sysexec::{
    AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, StdCommandExecutor,
};

/// Fixed Windows Firewall rule name owned exclusively by Mesh VPN (`US-053 AC3`).
pub const DEFAULT_OVERLAY_FIREWALL_RULE_NAME: &str = "MeshVPN-Overlay-Inbound";

/// Prefix required for every Windows Firewall rule modified or deleted by Mesh VPN.
pub const OWNED_FIREWALL_RULE_PREFIX: &str = "MeshVPN-";

const DEFAULT_FALLBACK_OVERLAY_CIDR: &str = "100.64.0.0/10";

/// Scoped inbound Windows Firewall rule specification allowing only traffic within `overlay_cidr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsFirewallRuleSpec {
    /// Owned Windows Firewall rule name (must begin with `MeshVPN-`).
    pub rule_name: String,
    /// Fixed Wintun interface name (`MeshVPN`).
    pub interface_name: String,
    /// Allowed overlay source & destination CIDR (`US-053 AC1/AC4`).
    pub overlay_cidr: OverlayCidr,
}

impl WindowsFirewallRuleSpec {
    /// Builds a validated scoped firewall rule spec for `interface_name` and `overlay_cidr`.
    pub fn new(
        rule_name: impl Into<String>,
        interface_name: impl Into<String>,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<Self> {
        let spec = Self {
            rule_name: rule_name.into(),
            interface_name: interface_name.into(),
            overlay_cidr,
        };
        validate_firewall_spec(&spec)?;
        Ok(spec)
    }
}

/// Manages Mesh VPN's scoped Windows Firewall inbound overlay rule via `System32\netsh.exe`.
#[derive(Clone, Default)]
pub struct WindowsFirewallManager {
    executor: Option<Arc<dyn CommandExecutor>>,
}

impl std::fmt::Debug for WindowsFirewallManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsFirewallManager")
            .field("custom_executor", &self.executor.is_some())
            .finish()
    }
}

impl WindowsFirewallManager {
    /// Creates a Windows Firewall manager backed by `GetSystemDirectoryW` + `netsh.exe`.
    #[must_use]
    pub const fn new() -> Self {
        Self { executor: None }
    }

    /// Creates a Windows Firewall manager with an injected [`CommandExecutor`] for testing.
    #[must_use]
    pub fn with_executor(executor: Arc<dyn CommandExecutor>) -> Self {
        Self {
            executor: Some(executor),
        }
    }

    /// Records the owned firewall rule in `ledger` before creation, clears stale duplicates of
    /// only this owned rule, and installs an inbound allow rule scoped to `overlay_cidr`.
    pub fn apply_overlay_rule(
        &self,
        spec: &WindowsFirewallRuleSpec,
        ledger: Option<&mut ResourceLedger>,
    ) -> AppResult<()> {
        validate_firewall_spec(spec)?;
        if let Some(ledger_ref) = ledger {
            ledger_ref.record_firewall_before_apply(None, vec![spec.rule_name.clone()])?;
        }

        // Remove only our owned rule first so recovery after Public profile drift is idempotent (`US-053 AC2`).
        let del_spec = build_delete_rule_command(&spec.rule_name)?;
        self.run_command(&del_spec, true)?;

        let add_spec = build_add_rule_command(spec)?;
        self.run_command(&add_spec, false)?;

        tracing::info!(
            target: "mesh::net::firewall_windows",
            rule = %spec.rule_name,
            interface = %spec.interface_name,
            overlay_cidr = %spec.overlay_cidr,
            "Applied scoped Windows Firewall inbound overlay rule"
        );
        Ok(())
    }

    /// Removes strictly a Mesh-owned Windows Firewall rule (`US-053 AC3`), never touching others.
    pub fn remove_overlay_rule(&self, rule_name: &str) -> AppResult<()> {
        validate_owned_rule_name(rule_name)?;
        let del_spec = build_delete_rule_command(rule_name)?;
        self.run_command(&del_spec, true)
    }

    fn run_command(&self, spec: &CommandSpec, allow_absent: bool) -> AppResult<()> {
        let out = match &self.executor {
            Some(exec) => exec.execute(spec)?,
            None => {
                let sys_dir = windows_system_directory().map_err(AppError::from)?;
                let exec = StdCommandExecutor::with_windows_system32_dir(sys_dir)?;
                exec.execute(spec)?
            }
        };
        if out.success() || (allow_absent && is_firewall_rule_absent(&out)) {
            return Ok(());
        }
        Err(format_netsh_firewall_failure(&out))
    }
}

fn is_firewall_rule_absent(out: &CommandOutput) -> bool {
    let combined = format!("{} {}", out.stderr, out.stdout).to_ascii_lowercase();
    combined.contains("no rules match")
        || combined.contains("element not found")
        || combined.contains("not found")
        || combined.contains("does not exist")
        || combined.contains("cannot find")
}

fn format_netsh_firewall_failure(out: &CommandOutput) -> AppError {
    let detail = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let clipped: String = detail.chars().take(240).collect();
    AppError::internal(format!(
        "Windows netsh advfirewall command failed (exit {}): {clipped}",
        out.status_code
    ))
}

/// Applies the scoped overlay inbound rule on `interface_name` using default overlay CIDR (`US-053`).
pub fn configure_overlay_firewall_profile(interface_name: &str) -> AppResult<()> {
    let default_cidr = DEFAULT_FALLBACK_OVERLAY_CIDR
        .parse::<OverlayCidr>()
        .map_err(|err| AppError::internal(format!("invalid fallback overlay CIDR: {err}")))?;
    configure_overlay_firewall_profile_for_cidr(interface_name, default_cidr, None)
}

/// Applies the scoped overlay inbound rule for a negotiated `overlay_cidr` and optional `ledger`.
pub fn configure_overlay_firewall_profile_for_cidr(
    interface_name: &str,
    overlay_cidr: OverlayCidr,
    ledger: Option<&mut ResourceLedger>,
) -> AppResult<()> {
    let spec = WindowsFirewallRuleSpec::new(
        DEFAULT_OVERLAY_FIREWALL_RULE_NAME,
        interface_name,
        overlay_cidr,
    )?;
    WindowsFirewallManager::new().apply_overlay_rule(&spec, ledger)
}

fn validate_owned_rule_name(rule_name: &str) -> AppResult<()> {
    let trimmed = rule_name.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with(OWNED_FIREWALL_RULE_PREFIX)
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(AppError::invalid_argument(
            "firewall rule name must start with MeshVPN- and use safe ASCII characters",
        ));
    }
    Ok(())
}

fn validate_firewall_spec(spec: &WindowsFirewallRuleSpec) -> AppResult<()> {
    validate_owned_rule_name(&spec.rule_name)?;
    let iface = spec.interface_name.trim();
    if iface.is_empty() || iface.contains('\0') {
        return Err(AppError::invalid_argument(
            "Windows firewall interface name must be non-empty",
        ));
    }
    if spec.overlay_cidr.prefix_len() == 0 {
        return Err(AppError::invalid_argument(
            "firewall overlay rule cannot permit 0.0.0.0/0 or ::/0",
        ));
    }
    Ok(())
}

fn build_delete_rule_command(rule_name: &str) -> AppResult<CommandSpec> {
    CommandSpec::new(
        AllowedBinary::WindowsNetsh,
        vec![
            "advfirewall".to_owned(),
            "firewall".to_owned(),
            "delete".to_owned(),
            "rule".to_owned(),
            format!("name={}", rule_name.trim()),
        ],
    )
}

fn build_add_rule_command(spec: &WindowsFirewallRuleSpec) -> AppResult<CommandSpec> {
    let cidr = spec.overlay_cidr.to_string();
    CommandSpec::new(
        AllowedBinary::WindowsNetsh,
        vec![
            "advfirewall".to_owned(),
            "firewall".to_owned(),
            "add".to_owned(),
            "rule".to_owned(),
            format!("name={}", spec.rule_name.trim()),
            "dir=in".to_owned(),
            "action=allow".to_owned(),
            "enable=yes".to_owned(),
            "profile=any".to_owned(),
            "protocol=any".to_owned(),
            format!("localip={cidr}"),
            format!("remoteip={cidr}"),
            format!(
                "description=Allow Mesh VPN overlay traffic for {}",
                spec.interface_name.trim()
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mesh_core::OverlayCidr;

    use super::{
        DEFAULT_OVERLAY_FIREWALL_RULE_NAME, WindowsFirewallManager, WindowsFirewallRuleSpec,
    };
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};

    #[test]
    fn test_firewall_windows_rejects_unowned_rule_and_wildcard_cidr() {
        // Arrange
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let mgr = WindowsFirewallManager::with_executor(Arc::clone(&fake_exec) as _);
        let wildcard = "0.0.0.0/0".parse::<OverlayCidr>();
        let valid_cidr = "100.64.0.0/10".parse::<OverlayCidr>();

        // Act
        let delete_foreign = mgr.remove_overlay_rule("CoreNetworking-ICMP");
        let foreign_spec = valid_cidr
            .as_ref()
            .ok()
            .map(|&c| WindowsFirewallRuleSpec::new("WindowsDefender", "MeshVPN", c));
        let blank_iface_spec = valid_cidr
            .ok()
            .map(|c| WindowsFirewallRuleSpec::new(DEFAULT_OVERLAY_FIREWALL_RULE_NAME, "   ", c));
        let wildcard_allowed = match wildcard {
            Err(_) => false,
            Ok(c) => WindowsFirewallRuleSpec::new(DEFAULT_OVERLAY_FIREWALL_RULE_NAME, "MeshVPN", c)
                .is_ok(),
        };

        // Assert
        assert!(delete_foreign.is_err());
        assert!(matches!(foreign_spec, Some(Err(_))));
        assert!(matches!(blank_iface_spec, Some(Err(_))));
        assert!(!wildcard_allowed);
        let recorded = fake_exec.recorded();
        assert!(recorded.is_ok());
        if let Ok(calls) = recorded {
            assert!(calls.is_empty());
        }
    }

    #[test]
    fn test_firewall_windows_applies_and_deletes_scoped_overlay_rule() {
        // Arrange
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let mgr = WindowsFirewallManager::with_executor(Arc::clone(&fake_exec) as _);
        let cidr = "100.64.0.0/10".parse::<OverlayCidr>();
        assert!(cidr.is_ok());
        let Ok(cidr) = cidr else {
            return;
        };
        let spec =
            WindowsFirewallRuleSpec::new(DEFAULT_OVERLAY_FIREWALL_RULE_NAME, "MeshVPN", cidr);
        assert!(spec.is_ok());
        let Ok(spec) = spec else {
            return;
        };

        // Act
        let apply_res = mgr.apply_overlay_rule(&spec, None);
        let remove_res = mgr.remove_overlay_rule(DEFAULT_OVERLAY_FIREWALL_RULE_NAME);

        // Assert
        assert!(
            apply_res.is_ok(),
            "apply_overlay_rule failed: {apply_res:?}"
        );
        assert!(
            remove_res.is_ok(),
            "remove_overlay_rule failed: {remove_res:?}"
        );
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
    fn test_firewall_windows_fails_on_nonzero_exit_and_allows_idempotent_absent_delete() {
        // Arrange
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let mgr = WindowsFirewallManager::with_executor(Arc::clone(&fake_exec) as _);
        let cidr = "100.64.0.0/10".parse::<OverlayCidr>();
        assert!(cidr.is_ok());
        let Ok(cidr) = cidr else {
            return;
        };
        let spec =
            WindowsFirewallRuleSpec::new(DEFAULT_OVERLAY_FIREWALL_RULE_NAME, "MeshVPN", cidr);
        assert!(spec.is_ok());
        let Ok(spec) = spec else {
            return;
        };

        // 1) Stale delete returns "No rules match", 2) Add rule fails with status_code = 1 ("Access denied").
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: "No rules match the specified criteria.".to_owned(),
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
        // 3) Delete rule fails with status_code = 1 ("Access is denied") -> must fail!
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: String::new(),
                    stderr: "Access is denied.".to_owned(),
                }))
                .is_ok()
        );
        // 4) Delete rule returns status_code = 1 ("No rules match") -> idempotent Ok.
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: "No rules match the specified criteria.".to_owned(),
                    stderr: String::new(),
                }))
                .is_ok()
        );

        // Act
        let apply_err = mgr.apply_overlay_rule(&spec, None);
        let remove_err = mgr.remove_overlay_rule(DEFAULT_OVERLAY_FIREWALL_RULE_NAME);
        let remove_absent_ok = mgr.remove_overlay_rule(DEFAULT_OVERLAY_FIREWALL_RULE_NAME);

        // Assert
        assert!(apply_err.is_err());
        assert!(remove_err.is_err());
        assert!(remove_absent_ok.is_ok());
    }
}
