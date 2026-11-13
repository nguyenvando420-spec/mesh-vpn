//! Atomic crash-safe OS resource ledger (`ledger.json`) for idempotent cleanup (`REL-08`, `G4`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mesh_core::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};

/// Current schema version of `ledger.json`.
pub const LEDGER_SCHEMA_VERSION: u32 = 1;

/// Recorded Linux `ip rule` entry tracked in [`ResourceLedgerData`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerIpRuleEntry {
    /// Policy routing priority (`51820` or `51810`).
    pub priority: u32,
    /// Inverted fwmark filter (`0x5d56` = `23894`).
    pub not_fwmark: Option<u32>,
    /// Target routing table (`51820` or `254` for main).
    pub lookup_table: u32,
    /// Optional `suppress_prefixlength` parameter (`Some(0)` for main lookup).
    pub suppress_prefixlength: Option<u32>,
    /// Address family (`"inet"` or `"inet6"`).
    pub family: String,
}

/// Recorded OS route entry tracked in [`ResourceLedgerData`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRouteEntry {
    /// Destination CIDR installed in the OS routing table.
    pub destination_cidr: String,
    /// Target TUN/Wintun interface name.
    pub interface_name: String,
    /// Optional routing table identifier (Linux policy table `51820`).
    pub table: Option<u32>,
}

/// Persisted JSON state of `ledger.json` matching `database-design.md` §6.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLedgerData {
    /// Schema format version.
    pub schema_version: u32,
    /// Daemon process ID owning the active session.
    pub session_pid: u32,
    /// Session start Unix timestamp in milliseconds.
    pub started_at_ms: u64,
    /// `true` only after `cleanup_all` finished cleanly or on fresh state.
    pub cleanly_stopped: bool,
    /// OS interface name (`utun7`, `mesh0`, `MeshVPN`).
    pub tun_interface_name: Option<String>,
    /// Fixed Wintun adapter GUID on Windows.
    pub windows_adapter_guid: Option<String>,
    /// Routes installed during the active session.
    pub installed_routes: Vec<LedgerRouteEntry>,
    /// Linux dedicated policy routing table (`51820`).
    pub linux_routing_table: Option<u32>,
    /// Linux `ip rule` entries added before routing.
    pub linux_ip_rules: Vec<LedgerIpRuleEntry>,
    /// Whether `# BEGIN mesh ... # END mesh` is currently active in hosts.
    pub hosts_block_active: bool,
    /// Canonical path of the hosts file modified by this session.
    pub hosts_real_path: Option<String>,
    /// macOS `pf` anchor name if firewall rules were added.
    pub pf_anchor_name: Option<String>,
    /// Firewall rule names installed during the active session.
    pub firewall_rule_names: Vec<String>,
}

impl Default for ResourceLedgerData {
    fn default() -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            session_pid: 0,
            started_at_ms: 0,
            cleanly_stopped: true,
            tun_interface_name: None,
            windows_adapter_guid: None,
            installed_routes: Vec::new(),
            linux_routing_table: None,
            linux_ip_rules: Vec::new(),
            hosts_block_active: false,
            hosts_real_path: None,
            pf_anchor_name: None,
            firewall_rule_names: Vec::new(),
        }
    }
}

impl ResourceLedgerData {
    /// Returns `true` if any tracked OS resource remains recorded.
    #[must_use]
    pub fn has_any_resources(&self) -> bool {
        self.tun_interface_name.is_some()
            || self.windows_adapter_guid.is_some()
            || !self.installed_routes.is_empty()
            || self.linux_routing_table.is_some()
            || !self.linux_ip_rules.is_empty()
            || self.hosts_block_active
            || self.pf_anchor_name.is_some()
            || !self.firewall_rule_names.is_empty()
    }
}

/// Platform cleanup operations driven sequentially by [`ResourceLedger::cleanup_all`].
pub trait LedgerCleanupOps: Send + Sync + std::fmt::Debug {
    /// Removes overlay routes recorded in `ledger.json`.
    fn remove_routes(&self, routes: &[LedgerRouteEntry]) -> AppResult<()>;
    /// Removes Linux `ip rule` entries and flushes/deletes the dedicated policy table.
    fn remove_linux_policy(&self, table: Option<u32>, rules: &[LedgerIpRuleEntry])
    -> AppResult<()>;
    /// Removes the managed block in the system `hosts` file and flushes DNS cache.
    fn remove_hosts_block(&self, hosts_real_path: Option<&str>) -> AppResult<()>;
    /// Removes `pf` anchors or OS firewall rules added by this session.
    fn remove_firewall_rules(
        &self,
        pf_anchor_name: Option<&str>,
        rule_names: &[String],
    ) -> AppResult<()>;
    /// Closes the TUN descriptor or destroys the Wintun adapter created by this session.
    fn close_tun_interface(
        &self,
        tun_interface_name: Option<&str>,
        windows_adapter_guid: Option<&str>,
    ) -> AppResult<()>;
}

/// Atomic crash-safe ledger controller backed by `ledger.json`.
#[derive(Debug, Clone)]
pub struct ResourceLedger {
    path: PathBuf,
    data: ResourceLedgerData,
}

impl ResourceLedger {
    /// Returns the default OS state file path for `ledger.json`.
    #[must_use]
    pub fn default_ledger_path() -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/var/db/mesh/ledger.json")
        }
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Mesh\ledger.json")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            PathBuf::from("/var/lib/meshd/ledger.json")
        }
    }

    /// Loads `ledger.json` if present, or initializes a clean ledger if absent.
    ///
    /// Fails closed if `ledger.json` exists but is corrupted or unreadable.
    pub fn load_or_init(path: PathBuf) -> AppResult<Self> {
        match fs::read(&path) {
            Ok(bytes) => {
                let data: ResourceLedgerData = serde_json::from_slice(&bytes).map_err(|err| {
                    AppError::invalid_argument(format!(
                        "corrupt ledger file {}: {err}",
                        path.display()
                    ))
                })?;
                if data.schema_version != LEDGER_SCHEMA_VERSION {
                    return Err(AppError::invalid_argument(format!(
                        "unsupported ledger schema version {}",
                        data.schema_version
                    )));
                }
                Ok(Self { path, data })
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path,
                data: ResourceLedgerData::default(),
            }),
            Err(err) => Err(AppError::internal(format!(
                "failed to read ledger {}: {err}",
                path.display()
            ))),
        }
    }

    /// Returns the filesystem path of this ledger.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns an immutable view of the tracked resource state.
    #[must_use]
    pub const fn data(&self) -> &ResourceLedgerData {
        &self.data
    }

    /// Returns `true` if a previous run left dirty resources or exited uncleanly.
    #[must_use]
    pub fn needs_stale_recovery(&self) -> bool {
        !self.data.cleanly_stopped || self.data.has_any_resources()
    }

    /// Atomically persists the current ledger state via temp file + `sync_all()` + `rename()`.
    pub fn save_atomic(&self) -> AppResult<()> {
        let parent = self.path.parent().ok_or_else(|| {
            AppError::invalid_argument("ledger path must have a parent directory")
        })?;
        fs::create_dir_all(parent).map_err(|err| {
            AppError::internal(format!("failed to create {}: {err}", parent.display()))
        })?;

        let serialized = serde_json::to_vec_pretty(&self.data)
            .map_err(|err| AppError::internal(format!("failed to serialize ledger: {err}")))?;

        let tmp_name = format!(
            "{}.tmp.{}",
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("ledger.json"),
            std::process::id()
        );
        let tmp_path = parent.join(tmp_name);

        write_file_0600(&tmp_path, &serialized)?;

        fs::rename(&tmp_path, &self.path).map_err(|err| {
            AppError::internal(format!(
                "failed to atomically replace {} with {}: {err}",
                self.path.display(),
                tmp_path.display()
            ))
        })
    }

    /// Records the TUN interface / Wintun GUID **before** allocating or configuring it.
    pub fn record_tun_before_create(
        &mut self,
        interface_name: String,
        windows_adapter_guid: Option<String>,
        session_pid: u32,
        started_at_ms: u64,
    ) -> AppResult<()> {
        self.data.cleanly_stopped = false;
        self.data.session_pid = session_pid;
        self.data.started_at_ms = started_at_ms;
        self.data.tun_interface_name = Some(interface_name);
        if windows_adapter_guid.is_some() {
            self.data.windows_adapter_guid = windows_adapter_guid;
        }
        self.save_atomic()
    }

    /// Records Linux policy routing table & `ip rule` entries **before** executing `ip rule add`.
    pub fn record_linux_policy_before_apply(
        &mut self,
        table: u32,
        rules: Vec<LedgerIpRuleEntry>,
    ) -> AppResult<()> {
        self.data.cleanly_stopped = false;
        self.data.linux_routing_table = Some(table);
        for rule in rules {
            if !self.data.linux_ip_rules.contains(&rule) {
                self.data.linux_ip_rules.push(rule);
            }
        }
        self.save_atomic()
    }

    /// Records an overlay CIDR route **before** adding it to the OS routing table.
    pub fn record_route_before_add(&mut self, route: LedgerRouteEntry) -> AppResult<()> {
        self.data.cleanly_stopped = false;
        if !self.data.installed_routes.contains(&route) {
            self.data.installed_routes.push(route);
        }
        self.save_atomic()
    }

    /// Records hosts block ownership **before** rewriting the real `hosts` file.
    pub fn record_hosts_before_activate(&mut self, real_path: String) -> AppResult<()> {
        self.data.cleanly_stopped = false;
        self.data.hosts_block_active = true;
        self.data.hosts_real_path = Some(real_path);
        self.save_atomic()
    }

    /// Records session `pf` anchor / firewall rule names **before** applying them.
    pub fn record_firewall_before_apply(
        &mut self,
        pf_anchor_name: Option<String>,
        rule_names: Vec<String>,
    ) -> AppResult<()> {
        self.data.cleanly_stopped = false;
        if pf_anchor_name.is_some() {
            self.data.pf_anchor_name = pf_anchor_name;
        }
        for name in rule_names {
            if !self.data.firewall_rule_names.contains(&name) {
                self.data.firewall_rule_names.push(name);
            }
        }
        self.save_atomic()
    }

    /// Executes idempotent cleanup strictly according to `system-architecture.md` §6.1:
    /// (1) routes & Linux policy rules, (2) hosts block, (3) firewall rules/pf anchor,
    /// (4) TUN descriptor/Wintun adapter, (5) atomic persistence of clean state.
    pub fn cleanup_all(&mut self, ops: &dyn LedgerCleanupOps) -> AppResult<()> {
        if !self.needs_stale_recovery() {
            return Ok(());
        }

        let mut first_error: Option<AppError> = None;

        if !self.data.installed_routes.is_empty() {
            let mut reversed = self.data.installed_routes.clone();
            reversed.reverse();
            capture_first_err(&mut first_error, ops.remove_routes(&reversed));
        }

        if self.data.linux_routing_table.is_some() || !self.data.linux_ip_rules.is_empty() {
            capture_first_err(
                &mut first_error,
                ops.remove_linux_policy(self.data.linux_routing_table, &self.data.linux_ip_rules),
            );
        }

        if self.data.hosts_block_active {
            capture_first_err(
                &mut first_error,
                ops.remove_hosts_block(self.data.hosts_real_path.as_deref()),
            );
        }

        if self.data.pf_anchor_name.is_some() || !self.data.firewall_rule_names.is_empty() {
            capture_first_err(
                &mut first_error,
                ops.remove_firewall_rules(
                    self.data.pf_anchor_name.as_deref(),
                    &self.data.firewall_rule_names,
                ),
            );
        }

        if self.data.tun_interface_name.is_some() || self.data.windows_adapter_guid.is_some() {
            capture_first_err(
                &mut first_error,
                ops.close_tun_interface(
                    self.data.tun_interface_name.as_deref(),
                    self.data.windows_adapter_guid.as_deref(),
                ),
            );
        }

        if let Some(err) = first_error {
            return Err(err);
        }

        self.data.installed_routes.clear();
        self.data.linux_routing_table = None;
        self.data.linux_ip_rules.clear();
        self.data.hosts_block_active = false;
        self.data.hosts_real_path = None;
        self.data.pf_anchor_name = None;
        self.data.firewall_rule_names.clear();
        self.data.tun_interface_name = None;
        self.data.windows_adapter_guid = None;
        self.data.cleanly_stopped = true;
        self.save_atomic()
    }
}

fn capture_first_err(slot: &mut Option<AppError>, res: AppResult<()>) {
    if let Err(err) = res
        && slot.is_none()
    {
        *slot = Some(err);
    }
}

fn write_file_0600(path: &Path, data: &[u8]) -> AppResult<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts
        .open(path)
        .map_err(|err| AppError::internal(format!("failed to open {}: {err}", path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| {
                AppError::internal(format!("failed to chmod 0600 {}: {err}", path.display()))
            })?;
    }

    file.write_all(data)
        .map_err(|err| AppError::internal(format!("failed to write {}: {err}", path.display())))?;
    file.sync_all()
        .map_err(|err| AppError::internal(format!("failed to sync {}: {err}", path.display())))
}

/// In-memory fake implementation of [`LedgerCleanupOps`] for deterministic unit tests.
#[derive(Debug, Clone, Default)]
pub struct FakeLedgerCleanupOps {
    steps: Arc<Mutex<Vec<String>>>,
}

impl FakeLedgerCleanupOps {
    /// Creates an empty fake cleanup tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the ordered list of cleanup actions performed.
    pub fn recorded_steps(&self) -> AppResult<Vec<String>> {
        let guard = self
            .steps
            .lock()
            .map_err(|_| AppError::internal("fake cleanup mutex poisoned"))?;
        Ok(guard.clone())
    }

    fn push_step(&self, step: String) -> AppResult<()> {
        let mut guard = self
            .steps
            .lock()
            .map_err(|_| AppError::internal("fake cleanup mutex poisoned"))?;
        guard.push(step);
        Ok(())
    }
}

impl LedgerCleanupOps for FakeLedgerCleanupOps {
    fn remove_routes(&self, routes: &[LedgerRouteEntry]) -> AppResult<()> {
        for route in routes {
            self.push_step(format!(
                "remove_route:{}:{}",
                route.interface_name, route.destination_cidr
            ))?;
        }
        Ok(())
    }

    fn remove_linux_policy(
        &self,
        table: Option<u32>,
        rules: &[LedgerIpRuleEntry],
    ) -> AppResult<()> {
        self.push_step(format!(
            "remove_linux_policy:table={}:rules={}",
            table.unwrap_or(0),
            rules.len()
        ))
    }

    fn remove_hosts_block(&self, hosts_real_path: Option<&str>) -> AppResult<()> {
        self.push_step(format!(
            "remove_hosts:{}",
            hosts_real_path.unwrap_or("default")
        ))
    }

    fn remove_firewall_rules(
        &self,
        pf_anchor_name: Option<&str>,
        rule_names: &[String],
    ) -> AppResult<()> {
        self.push_step(format!(
            "remove_firewall:anchor={}:rules={}",
            pf_anchor_name.unwrap_or("none"),
            rule_names.len()
        ))
    }

    fn close_tun_interface(
        &self,
        tun_interface_name: Option<&str>,
        windows_adapter_guid: Option<&str>,
    ) -> AppResult<()> {
        self.push_step(format!(
            "close_tun:{}:{}",
            tun_interface_name.unwrap_or("none"),
            windows_adapter_guid.unwrap_or("none")
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{FakeLedgerCleanupOps, LedgerIpRuleEntry, LedgerRouteEntry, ResourceLedger};

    #[test]
    fn test_ledger_write_before_create_and_idempotent_cleanup_sequence() {
        // Arrange
        let dir = match TempDir::new() {
            Ok(d) => d,
            Err(err) => {
                assert_eq!(err.to_string(), "tempdir creation failed");
                return;
            }
        };
        let path = dir.path().join("ledger.json");
        let mut ledger = match ResourceLedger::load_or_init(path.clone()) {
            Ok(l) => l,
            Err(err) => {
                assert_eq!(err.to_string(), "init ledger failed");
                return;
            }
        };
        assert!(!ledger.needs_stale_recovery());

        // Act
        assert!(
            ledger
                .record_tun_before_create("utun7".to_owned(), None, 4242, 1_700_000_000_000)
                .is_ok()
        );
        assert!(
            ledger
                .record_linux_policy_before_apply(
                    51820,
                    vec![LedgerIpRuleEntry {
                        priority: 51820,
                        not_fwmark: Some(0x5d56),
                        lookup_table: 51820,
                        suppress_prefixlength: None,
                        family: "inet".to_owned(),
                    }],
                )
                .is_ok()
        );
        assert!(
            ledger
                .record_route_before_add(LedgerRouteEntry {
                    destination_cidr: "100.115.0.0/16".to_owned(),
                    interface_name: "utun7".to_owned(),
                    table: Some(51820),
                })
                .is_ok()
        );
        assert!(
            ledger
                .record_hosts_before_activate("/private/etc/hosts".to_owned())
                .is_ok()
        );
        assert!(
            ledger
                .record_firewall_before_apply(
                    Some("com.internal.mesh".to_owned()),
                    vec!["MeshVPN-Overlay".to_owned()],
                )
                .is_ok()
        );

        let reloaded = match ResourceLedger::load_or_init(path) {
            Ok(l) => l,
            Err(err) => {
                assert_eq!(err.to_string(), "reload ledger failed");
                return;
            }
        };
        assert!(reloaded.needs_stale_recovery());

        let fake_ops = FakeLedgerCleanupOps::new();
        let mut to_clean = reloaded;
        assert!(to_clean.cleanup_all(&fake_ops).is_ok());
        // Second call must be idempotent no-op
        assert!(to_clean.cleanup_all(&fake_ops).is_ok());

        // Assert
        let steps = match fake_ops.recorded_steps() {
            Ok(s) => s,
            Err(err) => {
                assert_eq!(err.to_string(), "steps failed");
                return;
            }
        };
        assert_eq!(
            steps,
            vec![
                "remove_route:utun7:100.115.0.0/16",
                "remove_linux_policy:table=51820:rules=1",
                "remove_hosts:/private/etc/hosts",
                "remove_firewall:anchor=com.internal.mesh:rules=1",
                "close_tun:utun7:none",
            ]
        );
        assert!(!to_clean.needs_stale_recovery());
    }

    #[test]
    fn test_ledger_fails_closed_on_corrupt_json() {
        // Arrange
        let dir = match TempDir::new() {
            Ok(d) => d,
            Err(err) => {
                assert_eq!(err.to_string(), "tempdir failed");
                return;
            }
        };
        let path = dir.path().join("ledger.json");
        assert!(fs::write(&path, b"{not valid json").is_ok());

        // Act
        let res = ResourceLedger::load_or_init(path);

        // Assert
        assert!(res.is_err());
    }
}
