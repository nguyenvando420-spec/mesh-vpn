//! Desktop daemon runtime paths, platform log/route collection, and thin config re-exports (`US-004`, `US-099`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use mesh_client::config::DEFAULT_DESKTOP_MAX_BUGREPORT_BYTES;
pub(crate) use mesh_client::config::{
    BootstrapConfig, BootstrapStore, ClientRuntimeConfig, load_inbound_filter_spec, split_host_port,
};
use mesh_client::diagnostics::{
    BugreportBuildOptions, create_bugreport_tar_bundle as build_client_bugreport_tar_bundle,
};
use mesh_client::hooks::{
    ClientFuture, ClientPlatformHooks, DnsUpstreamHook, InMemoryDnsUpstreamHook,
    TunActivationOutcome,
};
use mesh_core::brand::DAEMON_BINARY_NAME;
use mesh_core::defaults::{DEFAULT_TUN_MTU, LINUX_FWMARK};
#[cfg(unix)]
use mesh_core::defaults::{UNIX_AGENT_ADMIN_SOCKET, UNIX_AGENT_RO_SOCKET};
#[cfg(windows)]
use mesh_core::defaults::{WINDOWS_AGENT_ADMIN_PIPE, WINDOWS_AGENT_RO_PIPE};
use mesh_core::{AppError, AppResult, OverlayCidr, OverlayIp};
use mesh_net::DiscoveredInterfaceEndpoint;
use mesh_net::keystore::KeysFileStore;
use mesh_net::ledger::ResourceLedger;
use mesh_net::nat64::SocketProtector;
use mesh_net::netmon::{
    FakeNetMonitor, FakePhysicalNetworkProbe, NetMonitor, PhysicalNetworkProbe,
};
use mesh_net::sysexec::{AllowedBinary, CommandExecutor as _, CommandSpec, StdCommandExecutor};
use mesh_net::tun::TunConfig;
use mesh_proto::agent_ipc::{AgentStatusResponse, BugreportResponse, NetcheckResponse};

/// Env override for rotated log directory collected by `mesh bugreport` (`US-041`).
const ENV_LOG_DIR: &str = "MESH_LOG_DIR";
/// Maximum total archive size permitted for desktop `mesh bugreport` (`20 MiB`, `US-041 AC3`).
pub(crate) const MAX_BUGREPORT_ARCHIVE_BYTES: usize = DEFAULT_DESKTOP_MAX_BUGREPORT_BYTES;

/// Platform-aware state, socket, and datapath runtime settings for `meshd`.
#[derive(Debug, Clone)]
pub(crate) struct DaemonRuntimePaths {
    /// Path to `bootstrap.toml`.
    pub(crate) bootstrap_path: PathBuf,
    /// Path to `netmap-cache.json`.
    pub(crate) netmap_cache_path: PathBuf,
    /// Path to `keys.json` managed exclusively via [`KeysFileStore`].
    pub(crate) keystore_path: PathBuf,
    /// Path to crash-recovery `ledger.json`.
    pub(crate) ledger_path: PathBuf,
    /// Privileged Admin IPC socket/pipe endpoint.
    pub(crate) admin_ipc_endpoint: String,
    /// Unprivileged Read-Only IPC socket/pipe endpoint.
    pub(crate) ro_ipc_endpoint: String,
    /// Directory where redacted `bugreport` bundles are created.
    pub(crate) bugreport_dir: PathBuf,
    /// Optional explicit Wintun SHA-256 hex digest pin (`MESH_WINTUN_SHA256`).
    pub(crate) wintun_sha256: Option<String>,
    /// Overlay TUN MTU (`576..=1420`).
    pub(crate) tun_mtu: u16,
    /// Optional physical underlay interface index (`IP_BOUND_IF` / `IP_UNICAST_IF`).
    pub(crate) underlay_if_index: Option<u32>,
    /// Linux policy-routing socket mark (`0x5d56`).
    pub(crate) linux_fwmark: Option<u32>,
    /// Daemon semantic version reported in Control challenge metadata.
    pub(crate) agent_version: String,
    /// Optional override for `/etc/hosts` in non-privileged integration tests.
    pub(crate) hosts_path_override: Option<PathBuf>,
}

impl DaemonRuntimePaths {
    /// Constructs production OS-standard runtime paths (`database-design.md` §6).
    #[must_use]
    pub(crate) fn system_default() -> Self {
        let state_dir = default_state_dir();
        Self {
            bootstrap_path: state_dir.join("bootstrap.toml"),
            netmap_cache_path: state_dir.join("netmap-cache.json"),
            keystore_path: KeysFileStore::default_keystore_path(),
            ledger_path: ResourceLedger::default_ledger_path(),
            admin_ipc_endpoint: default_admin_ipc_endpoint().to_owned(),
            ro_ipc_endpoint: default_ro_ipc_endpoint().to_owned(),
            bugreport_dir: state_dir.join("bugreports"),
            wintun_sha256: resolve_default_wintun_sha256(),
            tun_mtu: DEFAULT_TUN_MTU,
            underlay_if_index: None,
            linux_fwmark: default_linux_fwmark(),
            agent_version: format!("{DAEMON_BINARY_NAME}/{}", env!("CARGO_PKG_VERSION")),
            hosts_path_override: None,
        }
    }

    /// Constructs isolated paths under `base_dir` for unit and integration tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_temp_dir(base_dir: &Path, id_tag: &str) -> Self {
        Self {
            bootstrap_path: base_dir.join("bootstrap.toml"),
            netmap_cache_path: base_dir.join("netmap-cache.json"),
            keystore_path: base_dir.join("keys.json"),
            ledger_path: base_dir.join("ledger.json"),
            admin_ipc_endpoint: test_ipc_endpoint(base_dir, id_tag, true),
            ro_ipc_endpoint: test_ipc_endpoint(base_dir, id_tag, false),
            bugreport_dir: base_dir.join("bugreports"),
            wintun_sha256: None,
            tun_mtu: DEFAULT_TUN_MTU,
            underlay_if_index: None,
            linux_fwmark: None,
            agent_version: format!("{DAEMON_BINARY_NAME}/{}", env!("CARGO_PKG_VERSION")),
            hosts_path_override: Some(base_dir.join("hosts")),
        }
    }

    /// Builds desktop runtime budgets matching `self.tun_mtu` and `self.agent_version`.
    #[must_use]
    pub(crate) fn to_client_runtime_config(&self) -> ClientRuntimeConfig {
        let mut cfg = ClientRuntimeConfig::for_desktop();
        cfg.tun_mtu = self.tun_mtu;
        cfg.agent_version.clone_from(&self.agent_version);
        cfg
    }
}

#[cfg(all(test, windows))]
fn test_ipc_endpoint(_base_dir: &Path, id_tag: &str, admin: bool) -> String {
    let kind = if admin { "admin" } else { "ro" };
    format!(r"\\.\pipe\meshd-test-{id_tag}-{kind}")
}

#[cfg(all(test, not(windows)))]
fn test_ipc_endpoint(base_dir: &Path, id_tag: &str, admin: bool) -> String {
    let kind = if admin { "admin" } else { "ro" };
    base_dir
        .join(format!("meshd-{id_tag}-{kind}.sock"))
        .display()
        .to_string()
}

const fn default_linux_fwmark() -> Option<u32> {
    if cfg!(target_os = "linux") {
        Some(LINUX_FWMARK)
    } else {
        None
    }
}

fn resolve_default_wintun_sha256() -> Option<String> {
    if let Some(pin) = option_env!("MESH_WINTUN_SHA256") {
        let trimmed = pin.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    resolve_app_wintun_sidecar_sha256()
}

#[cfg(target_os = "windows")]
fn resolve_app_wintun_sidecar_sha256() -> Option<String> {
    let spec = mesh_net::tun_windows::WindowsTunOpenSpec::app_local("").ok()?;
    let sidecar_path = spec.dll_path.parent()?.join("wintun.dll.sha256");
    read_wintun_sha256_sidecar(&sidecar_path)
}

#[cfg(not(target_os = "windows"))]
const fn resolve_app_wintun_sidecar_sha256() -> Option<String> {
    None
}

#[cfg(any(target_os = "windows", test))]
fn read_wintun_sha256_sidecar(sidecar_path: &Path) -> Option<String> {
    let meta = std::fs::metadata(sidecar_path).ok()?;
    if !meta.is_file() || meta.len() > 4096 {
        return None;
    }
    let raw = std::fs::read_to_string(sidecar_path).ok()?;
    let token = raw.split_whitespace().next()?;
    let hex = token.strip_prefix("sha256:").unwrap_or(token);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

/// Returns platform state root directory for `meshd` (`database-design.md` §6).
#[must_use]
pub(crate) fn default_state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/db/mesh")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Mesh")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/var/lib/meshd")
    }
}

/// Returns platform default Admin IPC endpoint string.
#[must_use]
pub(crate) const fn default_admin_ipc_endpoint() -> &'static str {
    #[cfg(windows)]
    {
        WINDOWS_AGENT_ADMIN_PIPE
    }
    #[cfg(not(windows))]
    {
        UNIX_AGENT_ADMIN_SOCKET
    }
}

/// Returns platform default Read-Only IPC endpoint string.
#[must_use]
pub(crate) const fn default_ro_ipc_endpoint() -> &'static str {
    #[cfg(windows)]
    {
        WINDOWS_AGENT_RO_PIPE
    }
    #[cfg(not(windows))]
    {
        UNIX_AGENT_RO_SOCKET
    }
}

/// Executes sanitized desktop `sysexec` route inspection for bugreport bundles (`US-041`).
pub(crate) fn collect_os_route_table() -> String {
    let executor = StdCommandExecutor::default();
    let specs: Vec<AppResult<CommandSpec>> = if cfg!(target_os = "windows") {
        vec![CommandSpec::new(
            AllowedBinary::WindowsRoute,
            ["PRINT".to_owned(), "-4".to_owned()],
        )]
    } else if cfg!(target_os = "macos") {
        vec![CommandSpec::new(
            AllowedBinary::MacOsRoute,
            ["-n".to_owned(), "get".to_owned(), "default".to_owned()],
        )]
    } else {
        vec![
            CommandSpec::new(
                AllowedBinary::LinuxIpUsrSbin,
                [
                    "route".to_owned(),
                    "show".to_owned(),
                    "table".to_owned(),
                    "all".to_owned(),
                ],
            ),
            CommandSpec::new(
                AllowedBinary::LinuxIpSbin,
                [
                    "route".to_owned(),
                    "show".to_owned(),
                    "table".to_owned(),
                    "all".to_owned(),
                ],
            ),
        ]
    };
    for spec_res in specs {
        if let Ok(spec) = spec_res
            && let Ok(out) = executor.execute(&spec)
            && out.success()
        {
            return out.stdout;
        }
    }
    "(route table unavailable or permission denied)\n".to_owned()
}

pub(crate) fn candidate_log_dirs(state_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(env_dir) = std::env::var(ENV_LOG_DIR) {
        let p = PathBuf::from(env_dir.trim());
        if !p.as_os_str().is_empty() {
            dirs.push(p);
        }
    }
    if let Some(dir) = state_dir {
        dirs.push(dir.join("logs"));
    }
    if cfg!(target_os = "windows") {
        dirs.push(PathBuf::from(r"C:\ProgramData\Mesh\logs"));
    } else {
        dirs.push(PathBuf::from("/var/log/mesh"));
        dirs.push(PathBuf::from("/var/log/meshd"));
    }
    dirs
}

#[derive(Debug)]
struct DesktopRouteDiagHooks;

impl ClientPlatformHooks for DesktopRouteDiagHooks {
    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe> {
        Arc::new(FakePhysicalNetworkProbe::default())
    }

    fn net_monitor(&self) -> Arc<dyn NetMonitor> {
        Arc::new(FakeNetMonitor::new())
    }

    fn dns_hook(&self) -> Arc<dyn DnsUpstreamHook> {
        Arc::new(InMemoryDnsUpstreamHook::default())
    }

    fn socket_protector(&self) -> Option<Arc<dyn SocketProtector>> {
        None
    }

    fn activate_tun_and_routes<'a>(
        &'a self,
        _tun_cfg: TunConfig,
        _overlay_cidr: OverlayCidr,
        _dns_server_ip: Option<OverlayIp>,
        _domain_suffix: Option<&'a str>,
        _now_ms: u64,
    ) -> ClientFuture<'a, AppResult<TunActivationOutcome>> {
        Box::pin(async { Err(AppError::internal("not used for route diagnostics")) })
    }

    fn reconcile_on_roam_or_netmap<'a>(
        &'a self,
        _tun_ifname: &'a str,
        _overlay_cidr: OverlayCidr,
        _dns_server_ip: Option<OverlayIp>,
        _domain_suffix: Option<&'a str>,
    ) -> ClientFuture<'a, AppResult<Option<String>>> {
        Box::pin(async { Ok(None) })
    }

    fn deactivate_and_cleanup<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn discover_local_interface_endpoints(
        &self,
        _udp_port: u16,
    ) -> Vec<DiscoveredInterfaceEndpoint> {
        Vec::new()
    }

    fn collect_route_diagnostics(&self) -> String {
        collect_os_route_table()
    }
}

/// Creates a bounded (`<= 20 MiB`), scrubbed POSIX `.tar` bugreport archive (`US-041`).
pub(crate) fn create_bugreport_tar_bundle(
    state_dir: &Path,
    bootstrap: &BootstrapConfig,
    status: &AgentStatusResponse,
    netcheck: Result<&NetcheckResponse, &str>,
    now_unix_ms: u64,
) -> AppResult<BugreportResponse> {
    let output_dir = state_dir.join("bugreports");
    let log_dirs = candidate_log_dirs(Some(state_dir));
    let agent_version = format!("{DAEMON_BINARY_NAME}/{}", env!("CARGO_PKG_VERSION"));
    let hooks = DesktopRouteDiagHooks;
    build_client_bugreport_tar_bundle(BugreportBuildOptions {
        output_dir: &output_dir,
        max_total_bytes: MAX_BUGREPORT_ARCHIVE_BYTES,
        binary_name: DAEMON_BINARY_NAME,
        agent_version: &agent_version,
        bootstrap,
        status,
        netcheck,
        platform_hooks: &hooks,
        log_dirs: &log_dirs,
        in_memory_logs: None,
        now_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::BootstrapConfig;

    // Traces: US-041 AC1/AC2/AC3
    #[test]
    fn test_bugreport_tar_scrubs_100_percent_of_canary_secrets_and_caps_at_20mb() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("mkdir logs");
        let canary_mpk = "mpk_CANARY_LIVE_TOKEN_9876543210";
        let canary_bearer = "eyJhbGciOi.CANARY_BEARER_SECRET_XYZ";
        let canary_priv = "PRIVATE_CANARY_SECRET_HEX_001122334455";
        let mut oversized_log = String::new();
        oversized_log.push_str(&format!(
            "auth preauth_key=\"{canary_mpk}\" Authorization: Bearer {canary_bearer} private_key=\"{canary_priv}\"\n"
        ));
        let filler = "INFO meshd keepalive tick ok overlay=100.115.0.2\n".repeat(420_000);
        oversized_log.push_str(&filler);
        oversized_log.push_str(&format!("tail entry node_secret = \"{canary_priv}\"\n"));
        std::fs::write(log_dir.join("meshd.log.1"), &oversized_log).expect("write log");

        let status = mesh_proto::agent_ipc::AgentStatusResponse {
            daemon_state: mesh_proto::agent_ipc::DaemonState::Degraded,
            node_id: None,
            node_name: None,
            fqdn: None,
            overlay_ip: None,
            overlay_cidr: None,
            tun_interface_name: None,
            tun_mtu: 1380,
            netmap_version: 5,
            key_expires_at_ms: None,
            server_connection: None,
            self_network: mesh_proto::agent_ipc::SelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: None,
                nat_type: mesh_proto::netmap::NatMappingKind::EimOrAdm,
                nat_classification_note: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                candidates: vec![],
            },
            peers: vec![],
        };

        // Act
        let resp = super::create_bugreport_tar_bundle(
            dir.path(),
            &BootstrapConfig::default(),
            &status,
            Err("offline"),
            1_700_000_555_000,
        )
        .expect("create tar bugreport");

        // Assert: size strictly <= 20 MiB, 0 canary bytes anywhere in tar, valid ustar headers
        let archive_bytes = std::fs::read(&resp.bundle_path).expect("read tar");
        assert!(resp.bundle_path.ends_with(".tar"));
        assert!(archive_bytes.len() <= super::MAX_BUGREPORT_ARCHIVE_BYTES);
        assert_eq!(archive_bytes.len() % 512, 0);
        assert!(resp.scrubbed_items >= 4);

        let archive_lossy = String::from_utf8_lossy(&archive_bytes);
        assert!(!archive_lossy.contains(canary_mpk), "mpk canary leaked!");
        assert!(
            !archive_lossy.contains(canary_bearer),
            "bearer canary leaked!"
        );
        assert!(
            !archive_lossy.contains(canary_priv),
            "private key canary leaked!"
        );
        assert!(archive_lossy.contains("ustar"));
        assert!(archive_lossy.contains("version.txt"));
        assert!(archive_lossy.contains("status.json"));
        assert!(archive_lossy.contains("netcheck.json"));
        assert!(archive_lossy.contains("bootstrap-sanitized.toml"));
        assert!(archive_lossy.contains("routes.txt"));
    }

    #[test]
    fn test_read_wintun_sha256_sidecar_parses_valid_and_rejects_malformed() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let valid_path = dir.path().join("wintun.dll.sha256");
        let hex = "E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE";
        std::fs::write(&valid_path, format!("{hex}  wintun.dll\n")).expect("write valid sidecar");

        let bad_path = dir.path().join("bad.sha256");
        std::fs::write(&bad_path, "not-a-valid-sha256  wintun.dll\n").expect("write bad sidecar");

        // Act & Assert
        assert_eq!(
            super::read_wintun_sha256_sidecar(&valid_path).as_deref(),
            Some("e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce")
        );
        assert_eq!(super::read_wintun_sha256_sidecar(&bad_path), None);
        assert_eq!(
            super::read_wintun_sha256_sidecar(&dir.path().join("missing.sha256")),
            None
        );
    }
}
