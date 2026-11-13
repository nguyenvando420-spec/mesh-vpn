//! Opt-in Linux firewall hardening with SSH lockout prevention and 90-second auto-rollback (`US-046`).

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use mesh_core::defaults::{DEFAULT_CONTROL_TCP_PORT, DEFAULT_STUN_UDP_PORT};
use mesh_core::{AppError, AppResult, Port};
use tokio::sync::oneshot;

use crate::ledger::ResourceLedger;
use crate::sysexec::{AllowedBinary, CommandExecutor, CommandSpec, StdCommandExecutor};

/// Auto-rollback safety timer (`90 s`) for unconfirmed firewall mutations.
pub const FIREWALL_AUTO_ROLLBACK_SECS: u64 = 90;

const MESH_NFT_TABLE: &str = "mesh_vpn";
const MESH_IPTABLES_CHAIN: &str = "MESH_VPN_INPUT";

/// Supported Linux host firewall backends compatible without flushing existing rules (`US-056 AC5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxFirewallBackend {
    Nftables,
    Iptables,
    Ufw,
}

impl LinuxFirewallBackend {
    const fn as_tag(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
            Self::Ufw => "ufw",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "nftables" => Some(Self::Nftables),
            "iptables" => Some(Self::Iptables),
            "ufw" => Some(Self::Ufw),
            _ => None,
        }
    }
}

/// Additive firewall modification plan preserving active SSH and existing non-mesh rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxFirewallPlan {
    /// Target firewall tool (`nft`, `iptables`, or `ufw`).
    pub backend: LinuxFirewallBackend,
    /// Detected SSH port explicitly allowed before tightening rules.
    pub ssh_port: u16,
    /// HTTPS control & blind relay TCP port.
    pub control_tcp_port: u16,
    /// Embedded STUN UDP port.
    pub stun_udp_port: u16,
    /// Optional validated overlay TUN interface allowed on inbound traffic.
    pub tun_interface: Option<String>,
    /// When `true`, commands are planned and logged but never executed.
    pub dry_run: bool,
    /// Sequence of allowlisted additive commands (never flush/reset global tables or chains).
    pub commands: Vec<CommandSpec>,
    /// Ledger tracking identifiers for rollback/cleanup.
    pub rule_names: Vec<String>,
}

/// Evaluates or applies the opt-in Linux firewall policy with default ports (`US-046`).
pub fn apply_optin_firewall(dry_run: bool) -> AppResult<()> {
    let control_port = Port::from_u16(DEFAULT_CONTROL_TCP_PORT)?;
    let stun_port = Port::from_u16(DEFAULT_STUN_UDP_PORT)?;
    apply_optin_firewall_with_ports(None, control_port, stun_port, dry_run)
}

/// Evaluates or applies the opt-in Linux firewall policy for custom ports and an optional TUN
/// interface while preserving active SSH (`GNFR-11`, `US-046`, `US-074`).
pub fn apply_optin_firewall_with_ports(
    tun_interface: Option<&str>,
    control_tcp_port: Port,
    stun_udp_port: Port,
    dry_run: bool,
) -> AppResult<()> {
    let executor = StdCommandExecutor::new();
    let backend = detect_firewall_backend(&executor);
    let ssh_cfg = fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default();
    let ssh_env = std::env::var("SSH_CONNECTION").ok();
    let ssh_port = detect_ssh_port(&ssh_cfg, ssh_env.as_deref());
    let plan = build_optin_firewall_plan_with_ports(
        backend,
        tun_interface,
        ssh_port,
        control_tcp_port,
        stun_udp_port,
        dry_run,
    )?;
    apply_optin_firewall_with_executor(&executor, &plan, None)
}

/// Detects the active SSH listening port from `SSH_CONNECTION` or `/etc/ssh/sshd_config`,
/// defaulting safely to port `22`.
#[must_use]
pub fn detect_ssh_port(sshd_config: &str, ssh_connection_env: Option<&str>) -> u16 {
    if let Some(conn) = ssh_connection_env
        && let Some(port_str) = conn.split_ascii_whitespace().nth(3)
        && let Ok(port) = port_str.parse::<u16>()
        && port > 0
    {
        return port;
    }

    for line in sshd_config.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_ascii_whitespace();
        if parts.next().is_some_and(|k| k.eq_ignore_ascii_case("Port"))
            && let Some(val) = parts.next()
            && let Ok(port) = val.parse::<u16>()
            && port > 0
        {
            return port;
        }
    }

    22
}

/// Probes available firewall tools without modifying host state (prefers `nft`, then `ufw`, then `iptables`).
pub fn detect_firewall_backend(executor: &dyn CommandExecutor) -> LinuxFirewallBackend {
    if let Ok(spec) = CommandSpec::new(
        AllowedBinary::LinuxNft,
        ["list".to_owned(), "tables".to_owned()],
    ) && let Ok(out) = executor.execute(&spec)
        && out.success()
    {
        return LinuxFirewallBackend::Nftables;
    }
    if let Ok(spec) = CommandSpec::new(AllowedBinary::LinuxUfw, ["status".to_owned()])
        && let Ok(out) = executor.execute(&spec)
        && out.success()
        && !out.stdout.to_ascii_lowercase().contains("inactive")
    {
        return LinuxFirewallBackend::Ufw;
    }
    LinuxFirewallBackend::Iptables
}

/// Constructs an additive firewall plan with default Mesh VPN ports without touching existing
/// system chains or tables.
pub fn build_optin_firewall_plan(
    backend: LinuxFirewallBackend,
    ssh_port: u16,
    dry_run: bool,
) -> AppResult<LinuxFirewallPlan> {
    build_optin_firewall_plan_with_ports(
        backend,
        None,
        ssh_port,
        Port::from_u16(DEFAULT_CONTROL_TCP_PORT)?,
        Port::from_u16(DEFAULT_STUN_UDP_PORT)?,
        dry_run,
    )
}

/// Constructs an additive firewall plan for custom ports and an optional overlay TUN interface
/// without flushing existing system chains or tables.
pub fn build_optin_firewall_plan_with_ports(
    backend: LinuxFirewallBackend,
    tun_interface: Option<&str>,
    ssh_port: u16,
    control_tcp_port: Port,
    stun_udp_port: Port,
    dry_run: bool,
) -> AppResult<LinuxFirewallPlan> {
    if ssh_port == 0 {
        return Err(AppError::invalid_argument("SSH port must be non-zero"));
    }
    if let Some(ifname) = tun_interface {
        mesh_sys::tun_linux::validate_linux_ifname(ifname)?;
    }

    let control_u16 = control_tcp_port.get();
    let stun_u16 = stun_udp_port.get();
    let commands = match backend {
        LinuxFirewallBackend::Nftables => {
            build_nft_commands(tun_interface, ssh_port, control_u16, stun_u16)?
        }
        LinuxFirewallBackend::Iptables => {
            build_iptables_commands(tun_interface, ssh_port, control_u16, stun_u16)?
        }
        LinuxFirewallBackend::Ufw => {
            build_ufw_commands(tun_interface, ssh_port, control_u16, stun_u16)?
        }
    };

    let mut rule_names = vec![
        format!("backend:{}", backend.as_tag()),
        format!("ssh:{ssh_port}"),
        format!("control_tcp:{control_u16}"),
        format!("stun_udp:{stun_u16}"),
    ];
    if let Some(ifname) = tun_interface {
        rule_names.push(format!("tun:{ifname}"));
    }

    Ok(LinuxFirewallPlan {
        backend,
        ssh_port,
        control_tcp_port: control_u16,
        stun_udp_port: stun_u16,
        tun_interface: tun_interface.map(str::to_owned),
        dry_run,
        commands,
        rule_names,
    })
}

/// Executes a [`LinuxFirewallPlan`] (unless `dry_run` is set) and records rule identifiers
/// in `ResourceLedger` beforehand if supplied.
pub fn apply_optin_firewall_with_executor(
    executor: &dyn CommandExecutor,
    plan: &LinuxFirewallPlan,
    ledger: Option<&mut ResourceLedger>,
) -> AppResult<()> {
    if plan.dry_run {
        tracing::info!(
            component = "firewall_linux",
            event = "firewall_dry_run",
            backend = ?plan.backend,
            ssh_port = plan.ssh_port,
            control_tcp_port = plan.control_tcp_port,
            stun_udp_port = plan.stun_udp_port,
            command_count = plan.commands.len(),
            "planned Linux opt-in firewall rules (dry-run)"
        );
        return Ok(());
    }

    if let Some(ledger_ref) = ledger {
        ledger_ref.record_firewall_before_apply(None, plan.rule_names.clone())?;
    }

    for spec in &plan.commands {
        let out = executor.execute(spec)?;
        if !out.success() && !is_already_present(&out.stderr) {
            return Err(AppError::internal(format!(
                "Linux firewall rule failed (exit {}): {}",
                out.status_code,
                out.stderr.trim()
            )));
        }
    }

    if plan.backend == LinuxFirewallBackend::Iptables {
        ensure_iptables_input_jump(executor)?;
    }

    tracing::info!(
        component = "firewall_linux",
        event = "firewall_applied",
        backend = ?plan.backend,
        ssh_port = plan.ssh_port,
        control_tcp_port = plan.control_tcp_port,
        stun_udp_port = plan.stun_udp_port,
        "applied opt-in Linux firewall rules preserving SSH and existing chains"
    );
    Ok(())
}

fn ensure_iptables_input_jump(executor: &dyn CommandExecutor) -> AppResult<()> {
    let check_spec = CommandSpec::new(
        AllowedBinary::LinuxIptables,
        [
            "-C".to_owned(),
            "INPUT".to_owned(),
            "-j".to_owned(),
            MESH_IPTABLES_CHAIN.to_owned(),
        ],
    )?;
    let check_out = executor.execute(&check_spec)?;
    if check_out.success() {
        return Ok(());
    }

    let insert_spec = CommandSpec::new(
        AllowedBinary::LinuxIptables,
        [
            "-I".to_owned(),
            "INPUT".to_owned(),
            "1".to_owned(),
            "-j".to_owned(),
            MESH_IPTABLES_CHAIN.to_owned(),
        ],
    )?;
    let insert_out = executor.execute(&insert_spec)?;
    if !insert_out.success() {
        return Err(AppError::internal(format!(
            "Linux iptables jump insertion failed (exit {}): {}",
            insert_out.status_code,
            insert_out.stderr.trim()
        )));
    }
    Ok(())
}

/// Removes only the dedicated Mesh VPN firewall table/chain/ports using default Mesh VPN ports.
pub fn rollback_optin_firewall(
    executor: &dyn CommandExecutor,
    backend: LinuxFirewallBackend,
) -> AppResult<()> {
    rollback_optin_firewall_with_ports(
        executor,
        backend,
        None,
        Port::from_u16(DEFAULT_CONTROL_TCP_PORT)?,
        Port::from_u16(DEFAULT_STUN_UDP_PORT)?,
    )
}

/// Removes only the dedicated Mesh VPN firewall table/chain and custom TCP/UDP/TUN allowances.
pub fn rollback_optin_firewall_with_ports(
    executor: &dyn CommandExecutor,
    backend: LinuxFirewallBackend,
    tun_interface: Option<&str>,
    control_tcp_port: Port,
    stun_udp_port: Port,
) -> AppResult<()> {
    if let Some(ifname) = tun_interface {
        mesh_sys::tun_linux::validate_linux_ifname(ifname)?;
    }

    match backend {
        LinuxFirewallBackend::Nftables => {
            let spec = CommandSpec::new(
                AllowedBinary::LinuxNft,
                [
                    "delete".to_owned(),
                    "table".to_owned(),
                    "inet".to_owned(),
                    MESH_NFT_TABLE.to_owned(),
                ],
            )?;
            let out = executor.execute(&spec)?;
            if !out.success() && !is_absent(&out.stderr) {
                return Err(AppError::internal(format!(
                    "nft rollback failed: {}",
                    out.stderr.trim()
                )));
            }
        }
        LinuxFirewallBackend::Iptables => {
            for args in [
                vec![
                    "-D".to_owned(),
                    "INPUT".to_owned(),
                    "-j".to_owned(),
                    MESH_IPTABLES_CHAIN.to_owned(),
                ],
                vec!["-F".to_owned(), MESH_IPTABLES_CHAIN.to_owned()],
                vec!["-X".to_owned(), MESH_IPTABLES_CHAIN.to_owned()],
            ] {
                let spec = CommandSpec::new(AllowedBinary::LinuxIptables, args)?;
                match executor.execute(&spec) {
                    Ok(out) if !out.success() && !is_absent(&out.stderr) => {
                        tracing::debug!(
                            component = "firewall_linux",
                            event = "iptables_rollback_step_skipped",
                            status_code = out.status_code,
                            stderr = %out.stderr.trim(),
                            "best-effort iptables rollback step returned non-zero"
                        );
                    }
                    Err(err) => {
                        tracing::debug!(
                            component = "firewall_linux",
                            event = "iptables_rollback_step_skipped",
                            error = %err,
                            "best-effort iptables rollback step failed"
                        );
                    }
                    Ok(_) => {}
                }
            }
        }
        LinuxFirewallBackend::Ufw => {
            let mut commands = vec![
                CommandSpec::new(
                    AllowedBinary::LinuxUfw,
                    [
                        "--force".to_owned(),
                        "delete".to_owned(),
                        "allow".to_owned(),
                        format!("{}/tcp", control_tcp_port.get()),
                    ],
                )?,
                CommandSpec::new(
                    AllowedBinary::LinuxUfw,
                    [
                        "--force".to_owned(),
                        "delete".to_owned(),
                        "allow".to_owned(),
                        format!("{}/udp", stun_udp_port.get()),
                    ],
                )?,
            ];
            if let Some(ifname) = tun_interface {
                commands.push(CommandSpec::new(
                    AllowedBinary::LinuxUfw,
                    [
                        "--force".to_owned(),
                        "delete".to_owned(),
                        "allow".to_owned(),
                        "in".to_owned(),
                        "on".to_owned(),
                        ifname.to_owned(),
                    ],
                )?);
            }
            for spec in &commands {
                match executor.execute(spec) {
                    Ok(out) if !out.success() && !is_absent(&out.stderr) => {
                        tracing::debug!(
                            component = "firewall_linux",
                            event = "ufw_rollback_step_skipped",
                            status_code = out.status_code,
                            stderr = %out.stderr.trim(),
                            "best-effort ufw rollback step returned non-zero"
                        );
                    }
                    Err(err) => {
                        tracing::debug!(
                            component = "firewall_linux",
                            event = "ufw_rollback_step_skipped",
                            error = %err,
                            "best-effort ufw rollback step failed"
                        );
                    }
                    Ok(_) => {}
                }
            }
        }
    }
    tracing::warn!(
        component = "firewall_linux",
        event = "firewall_rolled_back",
        backend = ?backend,
        control_tcp_port = control_tcp_port.get(),
        stun_udp_port = stun_udp_port.get(),
        "rolled back Linux opt-in firewall rules"
    );
    Ok(())
}

/// Rolls back previously recorded opt-in firewall rules parsed from `ResourceLedger.firewall_rule_names`.
pub fn rollback_from_ledger_rules(
    executor: &dyn CommandExecutor,
    rule_names: &[String],
) -> AppResult<()> {
    if rule_names.is_empty() {
        return Ok(());
    }

    let mut backend: Option<LinuxFirewallBackend> = None;
    let mut control_port = Port::from_u16(DEFAULT_CONTROL_TCP_PORT)?;
    let mut stun_port = Port::from_u16(DEFAULT_STUN_UDP_PORT)?;
    let mut tun_ifname: Option<String> = None;

    for entry in rule_names {
        if let Some(tag) = entry.strip_prefix("backend:") {
            backend = LinuxFirewallBackend::from_tag(tag);
        } else if let Some(port_str) = entry.strip_prefix("control_tcp:")
            && let Ok(parsed) = port_str.parse::<Port>()
        {
            control_port = parsed;
        } else if let Some(port_str) = entry.strip_prefix("stun_udp:")
            && let Ok(parsed) = port_str.parse::<Port>()
        {
            stun_port = parsed;
        } else if let Some(ifname) = entry.strip_prefix("tun:") {
            tun_ifname = Some(ifname.to_owned());
        }
    }

    let target_backend = backend.unwrap_or_else(|| detect_firewall_backend(executor));
    rollback_optin_firewall_with_ports(
        executor,
        target_backend,
        tun_ifname.as_deref(),
        control_port,
        stun_port,
    )
}

/// Applies the opt-in firewall plan with an automatic [`FIREWALL_AUTO_ROLLBACK_SECS`] rollback
/// timer if confirmation is not received in time.
pub async fn apply_with_auto_rollback(
    executor: Arc<dyn CommandExecutor>,
    plan: LinuxFirewallPlan,
    confirm_rx: oneshot::Receiver<()>,
) -> AppResult<bool> {
    apply_optin_firewall_with_executor(executor.as_ref(), &plan, None)?;
    if plan.dry_run {
        return Ok(true);
    }

    let timeout = Duration::from_secs(FIREWALL_AUTO_ROLLBACK_SECS);
    match tokio::time::timeout(timeout, confirm_rx).await {
        Ok(Ok(())) => Ok(true),
        Ok(Err(_)) | Err(_) => {
            let control_port = Port::from_u16(plan.control_tcp_port)?;
            let stun_port = Port::from_u16(plan.stun_udp_port)?;
            rollback_optin_firewall_with_ports(
                executor.as_ref(),
                plan.backend,
                plan.tun_interface.as_deref(),
                control_port,
                stun_port,
            )?;
            Ok(false)
        }
    }
}

fn build_nft_commands(
    tun_interface: Option<&str>,
    ssh_port: u16,
    control_tcp_port: u16,
    stun_udp_port: u16,
) -> AppResult<Vec<CommandSpec>> {
    let mut commands = vec![
        CommandSpec::new(
            AllowedBinary::LinuxNft,
            [
                "add".to_owned(),
                "table".to_owned(),
                "inet".to_owned(),
                MESH_NFT_TABLE.to_owned(),
            ],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxNft,
            [
                "add".to_owned(),
                "chain".to_owned(),
                "inet".to_owned(),
                MESH_NFT_TABLE.to_owned(),
                "input".to_owned(),
                "{ type filter hook input priority 10; policy accept; }".to_owned(),
            ],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxNft,
            [
                "add".to_owned(),
                "rule".to_owned(),
                "inet".to_owned(),
                MESH_NFT_TABLE.to_owned(),
                "input".to_owned(),
                "tcp".to_owned(),
                "dport".to_owned(),
                ssh_port.to_string(),
                "accept".to_owned(),
            ],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxNft,
            [
                "add".to_owned(),
                "rule".to_owned(),
                "inet".to_owned(),
                MESH_NFT_TABLE.to_owned(),
                "input".to_owned(),
                "tcp".to_owned(),
                "dport".to_owned(),
                control_tcp_port.to_string(),
                "accept".to_owned(),
            ],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxNft,
            [
                "add".to_owned(),
                "rule".to_owned(),
                "inet".to_owned(),
                MESH_NFT_TABLE.to_owned(),
                "input".to_owned(),
                "udp".to_owned(),
                "dport".to_owned(),
                stun_udp_port.to_string(),
                "accept".to_owned(),
            ],
        )?,
    ];
    if let Some(ifname) = tun_interface {
        commands.push(CommandSpec::new(
            AllowedBinary::LinuxNft,
            [
                "add".to_owned(),
                "rule".to_owned(),
                "inet".to_owned(),
                MESH_NFT_TABLE.to_owned(),
                "input".to_owned(),
                "iifname".to_owned(),
                format!("\"{ifname}\""),
                "accept".to_owned(),
            ],
        )?);
    }
    Ok(commands)
}

fn build_iptables_commands(
    tun_interface: Option<&str>,
    ssh_port: u16,
    control_tcp_port: u16,
    stun_udp_port: u16,
) -> AppResult<Vec<CommandSpec>> {
    let mut commands = vec![
        CommandSpec::new(
            AllowedBinary::LinuxIptables,
            ["-N".to_owned(), MESH_IPTABLES_CHAIN.to_owned()],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxIptables,
            ["-F".to_owned(), MESH_IPTABLES_CHAIN.to_owned()],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxIptables,
            [
                "-A".to_owned(),
                MESH_IPTABLES_CHAIN.to_owned(),
                "-p".to_owned(),
                "tcp".to_owned(),
                "--dport".to_owned(),
                ssh_port.to_string(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxIptables,
            [
                "-A".to_owned(),
                MESH_IPTABLES_CHAIN.to_owned(),
                "-p".to_owned(),
                "tcp".to_owned(),
                "--dport".to_owned(),
                control_tcp_port.to_string(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxIptables,
            [
                "-A".to_owned(),
                MESH_IPTABLES_CHAIN.to_owned(),
                "-p".to_owned(),
                "udp".to_owned(),
                "--dport".to_owned(),
                stun_udp_port.to_string(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
        )?,
    ];
    if let Some(ifname) = tun_interface {
        commands.push(CommandSpec::new(
            AllowedBinary::LinuxIptables,
            [
                "-A".to_owned(),
                MESH_IPTABLES_CHAIN.to_owned(),
                "-i".to_owned(),
                ifname.to_owned(),
                "-j".to_owned(),
                "ACCEPT".to_owned(),
            ],
        )?);
    }
    Ok(commands)
}

fn build_ufw_commands(
    tun_interface: Option<&str>,
    ssh_port: u16,
    control_tcp_port: u16,
    stun_udp_port: u16,
) -> AppResult<Vec<CommandSpec>> {
    let mut commands = vec![
        CommandSpec::new(
            AllowedBinary::LinuxUfw,
            ["allow".to_owned(), format!("{ssh_port}/tcp")],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxUfw,
            ["allow".to_owned(), format!("{control_tcp_port}/tcp")],
        )?,
        CommandSpec::new(
            AllowedBinary::LinuxUfw,
            ["allow".to_owned(), format!("{stun_udp_port}/udp")],
        )?,
    ];
    if let Some(ifname) = tun_interface {
        commands.push(CommandSpec::new(
            AllowedBinary::LinuxUfw,
            [
                "allow".to_owned(),
                "in".to_owned(),
                "on".to_owned(),
                ifname.to_owned(),
            ],
        )?);
    }
    Ok(commands)
}

fn is_already_present(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("already exists") || lower.contains("chain already")
}

fn is_absent(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("no such file")
        || lower.contains("does not exist")
        || lower.contains("could not delete non-existent rule")
}

#[cfg(test)]
mod tests {
    use mesh_core::Port;

    use super::{
        FIREWALL_AUTO_ROLLBACK_SECS, LinuxFirewallBackend, apply_optin_firewall_with_executor,
        build_optin_firewall_plan, build_optin_firewall_plan_with_ports, detect_ssh_port,
        rollback_from_ledger_rules, rollback_optin_firewall_with_ports,
    };
    use crate::sysexec::{CommandOutput, FakeCommandExecutor};

    fn ok_out() -> CommandOutput {
        CommandOutput {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn test_firewall_linux_detects_custom_ssh_port_and_dry_run_never_executes() {
        // Arrange
        let sshd_cfg = "#Port 22\nPort 2222\nPermitRootLogin no\n";
        let port_from_cfg = detect_ssh_port(sshd_cfg, None);
        let port_from_env = detect_ssh_port(sshd_cfg, Some("10.0.0.1 54321 198.51.100.1 2022"));
        let exec = FakeCommandExecutor::new();
        let plan = build_optin_firewall_plan(LinuxFirewallBackend::Nftables, port_from_env, true)
            .expect("build plan");

        // Act
        apply_optin_firewall_with_executor(&exec, &plan, None).expect("dry run");

        // Assert
        assert_eq!(FIREWALL_AUTO_ROLLBACK_SECS, 90);
        assert_eq!(port_from_cfg, 2222);
        assert_eq!(port_from_env, 2022);
        assert!(exec.recorded().expect("recorded").is_empty());
        assert!(
            !plan
                .commands
                .iter()
                .any(|c| c.args.iter().any(|a| a == "flush"))
        );
    }

    #[test]
    fn test_firewall_linux_plan_never_flushes_existing_rules() {
        // Arrange & Act
        let plan =
            build_optin_firewall_plan(LinuxFirewallBackend::Nftables, 22, false).expect("nft plan");

        // Assert
        assert!(
            plan.commands
                .iter()
                .any(|c| { c.args == ["add", "table", "inet", "mesh_vpn"] })
        );
        assert!(
            !plan
                .commands
                .iter()
                .any(|c| c.args.contains(&"flush".to_owned()))
        );
    }

    #[test]
    fn test_firewall_linux_iptables_first_install_inserts_jump_on_check_miss() {
        // Arrange
        let exec = FakeCommandExecutor::new();
        let control = Port::from_u16(8443).expect("control port");
        let stun = Port::from_u16(3479).expect("stun port");
        let plan = build_optin_firewall_plan_with_ports(
            LinuxFirewallBackend::Iptables,
            Some("mesh0"),
            2222,
            control,
            stun,
            false,
        )
        .expect("iptables plan");
        // 6 base commands (-N, -F, 4x -A) + -C miss (exit 1) + -I INPUT 1 (exit 0)
        for _ in 0..plan.commands.len() {
            exec.push_result(Ok(ok_out())).expect("queue base cmd");
        }
        exec.push_result(Ok(CommandOutput {
            status_code: 1,
            stdout: String::new(),
            stderr: "iptables: Bad rule (does a matching rule exist in that chain?).".to_owned(),
        }))
        .expect("queue -C miss");
        exec.push_result(Ok(ok_out())).expect("queue -I INPUT 1");

        // Act
        apply_optin_firewall_with_executor(&exec, &plan, None).expect("apply iptables");

        // Assert
        let recorded = exec.recorded().expect("recorded");
        assert_eq!(recorded.len(), plan.commands.len() + 2);
        assert!(
            recorded
                .get(1)
                .is_some_and(|c| c.args == ["-F", "MESH_VPN_INPUT"])
        );
        assert!(recorded.iter().any(|c| c.args
            == [
                "-A",
                "MESH_VPN_INPUT",
                "-p",
                "tcp",
                "--dport",
                "8443",
                "-j",
                "ACCEPT"
            ]));
        assert!(
            recorded
                .get(recorded.len().saturating_sub(2))
                .is_some_and(|c| c.args == ["-C", "INPUT", "-j", "MESH_VPN_INPUT"])
        );
        assert!(
            recorded
                .last()
                .is_some_and(|c| c.args == ["-I", "INPUT", "1", "-j", "MESH_VPN_INPUT"])
        );
    }

    #[test]
    fn test_firewall_linux_iptables_reapply_skips_duplicate_jump_insertion() {
        // Arrange
        let exec = FakeCommandExecutor::new();
        let control = Port::from_u16(8443).expect("control port");
        let stun = Port::from_u16(3479).expect("stun port");
        let plan = build_optin_firewall_plan_with_ports(
            LinuxFirewallBackend::Iptables,
            None,
            22,
            control,
            stun,
            false,
        )
        .expect("iptables plan");
        exec.push_result(Ok(CommandOutput {
            status_code: 1,
            stdout: String::new(),
            stderr: "iptables: Chain already exists.".to_owned(),
        }))
        .expect("queue -N already exists");
        for _ in 1..plan.commands.len() {
            exec.push_result(Ok(ok_out())).expect("queue base cmd");
        }
        exec.push_result(Ok(ok_out())).expect("queue -C hit");

        // Act
        apply_optin_firewall_with_executor(&exec, &plan, None).expect("idempotent reapply");

        // Assert
        let recorded = exec.recorded().expect("recorded");
        assert!(!recorded.iter().any(|c| c.args.contains(&"-I".to_owned())));
    }

    #[test]
    fn test_firewall_linux_ufw_rollback_deletes_both_control_tcp_and_stun_udp() {
        // Arrange
        let exec = FakeCommandExecutor::new();
        for _ in 0..3 {
            exec.push_result(Ok(ok_out())).expect("queue ufw delete");
        }
        let control = Port::from_u16(8443).expect("control port");
        let stun = Port::from_u16(3479).expect("stun port");

        // Act
        rollback_optin_firewall_with_ports(
            &exec,
            LinuxFirewallBackend::Ufw,
            Some("mesh0"),
            control,
            stun,
        )
        .expect("ufw rollback");

        // Assert
        let recorded = exec.recorded().expect("recorded");
        assert_eq!(recorded.len(), 3);
        assert_eq!(
            recorded.first().map(|c| c.args.as_slice()),
            Some(
                ["--force", "delete", "allow", "8443/tcp"]
                    .map(str::to_owned)
                    .as_slice()
            )
        );
        assert_eq!(
            recorded.get(1).map(|c| c.args.as_slice()),
            Some(
                ["--force", "delete", "allow", "3479/udp"]
                    .map(str::to_owned)
                    .as_slice()
            )
        );
        assert_eq!(
            recorded.get(2).map(|c| c.args.as_slice()),
            Some(
                ["--force", "delete", "allow", "in", "on", "mesh0"]
                    .map(str::to_owned)
                    .as_slice()
            )
        );
    }

    #[test]
    fn test_firewall_linux_rollback_from_ledger_rules_handles_empty_and_ufw_tags() {
        // Arrange
        let exec = FakeCommandExecutor::new();
        exec.push_result(Ok(ok_out())).expect("queue tcp delete");
        exec.push_result(Ok(ok_out())).expect("queue udp delete");
        let rules = vec![
            "backend:ufw".to_owned(),
            "ssh:2222".to_owned(),
            "control_tcp:9443".to_owned(),
            "stun_udp:4478".to_owned(),
        ];

        // Act
        rollback_from_ledger_rules(&exec, &[]).expect("empty ledger rules no-op");
        rollback_from_ledger_rules(&exec, &rules).expect("ufw ledger rollback");

        // Assert
        let recorded = exec.recorded().expect("recorded");
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded.first().map(|c| c.args.as_slice()),
            Some(
                ["--force", "delete", "allow", "9443/tcp"]
                    .map(str::to_owned)
                    .as_slice()
            )
        );
        assert_eq!(
            recorded.get(1).map(|c| c.args.as_slice()),
            Some(
                ["--force", "delete", "allow", "4478/udp"]
                    .map(str::to_owned)
                    .as_slice()
            )
        );
    }
}
