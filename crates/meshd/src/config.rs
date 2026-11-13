//! Daemon runtime paths, zero-TOFU TLS policy builder, and `bootstrap.toml` persistence (`US-004`, `SEC-15`).

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ClientConfig;
use serde::{Deserialize, Serialize};

use mesh_core::brand::DAEMON_BINARY_NAME;
use mesh_core::defaults::{DEFAULT_TUN_MTU, LINUX_FWMARK};
#[cfg(unix)]
use mesh_core::defaults::{UNIX_AGENT_ADMIN_SOCKET, UNIX_AGENT_RO_SOCKET};
#[cfg(windows)]
use mesh_core::defaults::{WINDOWS_AGENT_ADMIN_PIPE, WINDOWS_AGENT_RO_PIPE};
use mesh_core::{AppError, AppResult, ErrorKind, NodeId, NodeName, OverlayIp, Port, SpkiPin};
use mesh_crypto::{PinSet, build_pinned_client_config, build_system_ca_client_config};
use mesh_net::keystore::KeysFileStore;
use mesh_net::ledger::ResourceLedger;
use mesh_proto::agent_ipc::TlsAuthMode;

/// Current schema version for `bootstrap.toml`.
pub(crate) const BOOTSTRAP_SCHEMA_VERSION: u16 = 1;

/// Bootstrap persistence document containing ONLY Control endpoint & TLS trust material (`SEC-15`).
///
/// STUN and Blind Relay ports/endpoints are intentionally omitted here and always discovered
/// dynamically from signed `NetmapSnapshot::relay_map` frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapConfig {
    /// On-disk bootstrap schema version (`1`).
    #[serde(default = "default_schema_version")]
    pub(crate) schema_version: u16,
    /// Persistent local node UUID once registered.
    pub(crate) node_id: Option<NodeId>,
    /// Persistent RFC 1123 node label once registered.
    pub(crate) node_name: Option<NodeName>,
    /// Assigned local overlay IPv4 persisted for offline P2P resume (`US-033`).
    #[serde(default)]
    pub(crate) overlay_ip: Option<OverlayIp>,
    /// Assigned local mesh FQDN persisted for offline display.
    #[serde(default)]
    pub(crate) fqdn: Option<String>,
    /// Control-plane `<host_or_ip>:<port>` endpoint.
    pub(crate) server_endpoint: Option<String>,
    /// Explicit TLS verification strategy (`spki_pin` vs `system_ca`).
    #[serde(default = "default_tls_auth_mode")]
    pub(crate) tls_auth_mode: TlsAuthMode,
    /// Active pinned server certificate SPKI SHA-256 fingerprint.
    pub(crate) active_pin: Option<SpkiPin>,
    /// Optional staged secondary pin during zero-downtime cert rotation.
    pub(crate) next_pin: Option<SpkiPin>,
    /// Highest server `endpoint_version` acknowledged during port migration (`US-074`).
    #[serde(default)]
    pub(crate) acked_endpoint_version: u64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            schema_version: BOOTSTRAP_SCHEMA_VERSION,
            node_id: None,
            node_name: None,
            overlay_ip: None,
            fqdn: None,
            server_endpoint: None,
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: None,
            next_pin: None,
            acked_endpoint_version: 0,
        }
    }
}

const fn default_schema_version() -> u16 {
    BOOTSTRAP_SCHEMA_VERSION
}

const fn default_tls_auth_mode() -> TlsAuthMode {
    TlsAuthMode::SpkiPin
}

impl BootstrapConfig {
    /// Validates internal invariants, endpoint syntax, and strict zero-TOFU policy.
    pub(crate) fn validate(&self) -> AppResult<()> {
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION {
            return Err(AppError::invalid_argument(format!(
                "unsupported bootstrap.toml schema_version {}",
                self.schema_version
            )));
        }
        if let Some(ref endpoint) = self.server_endpoint {
            validate_tls_trust_policy(endpoint, self.tls_auth_mode, self.active_pin)?;
        }
        Ok(())
    }

    /// Returns the configured [`PinSet`] when operating in SPKI-pinning mode.
    #[must_use]
    pub(crate) fn pin_set(&self) -> Option<PinSet> {
        if self.tls_auth_mode != TlsAuthMode::SpkiPin {
            return None;
        }
        self.active_pin.map(|active| match self.next_pin {
            Some(next) => PinSet::dual(active, next),
            None => PinSet::single(active),
        })
    }

    /// Builds a validated TLS 1.3 `rustls::ClientConfig` enforcing zero-TOFU fail-closed rules.
    pub(crate) fn build_tls_client_config(&self) -> AppResult<Arc<ClientConfig>> {
        self.validate()?;
        let endpoint = self.server_endpoint.as_deref().ok_or_else(|| {
            AppError::invalid_argument("cannot build TLS config without server_endpoint")
        })?;
        build_tls_client_config_for(endpoint, self.tls_auth_mode, self.active_pin, self.next_pin)
    }

    /// Updates pinned TLS trust material after receiving a signed Netmap `PinSetDto`.
    pub(crate) fn apply_netmap_pins(&mut self, active: SpkiPin, next: Option<SpkiPin>) -> bool {
        if self.tls_auth_mode != TlsAuthMode::SpkiPin {
            return false;
        }
        let changed = self.active_pin != Some(active) || self.next_pin != next;
        self.active_pin = Some(active);
        self.next_pin = next;
        changed
    }
}

/// Persists and loads [`BootstrapConfig`] atomically with restrictive `0600` Unix permissions.
#[derive(Debug, Clone)]
pub(crate) struct BootstrapStore {
    path: PathBuf,
}

impl BootstrapStore {
    /// Creates a store backed by `path`.
    #[must_use]
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the backing `bootstrap.toml` path.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Loads `bootstrap.toml`, returning `Default` only when the file does not yet exist.
    pub(crate) fn load_or_default(&self) -> AppResult<BootstrapConfig> {
        match fs::read_to_string(&self.path) {
            Ok(raw) => {
                let parsed: BootstrapConfig = toml::from_str(&raw).map_err(|err| {
                    AppError::new(
                        ErrorKind::InvalidArgument,
                        format!("corrupt bootstrap config {}: {err}", self.path.display()),
                    )
                })?;
                parsed.validate()?;
                Ok(parsed)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Ok(BootstrapConfig::default())
            }
            Err(err) => Err(AppError::internal(format!(
                "failed reading bootstrap config {}: {err}",
                self.path.display()
            ))),
        }
    }

    /// Atomically writes `config` to disk with strict `0600` permissions on Unix hosts.
    pub(crate) fn save_atomic(&self, config: &BootstrapConfig) -> AppResult<()> {
        config.validate()?;
        let serialized = toml::to_string_pretty(config).map_err(|err| {
            AppError::internal(format!("failed serializing bootstrap config: {err}"))
        })?;
        write_private_file_atomic(&self.path, serialized.as_bytes())
    }
}

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
            wintun_sha256: option_env!("MESH_WINTUN_SHA256").map(str::to_owned),
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
            linux_fwmark: default_linux_fwmark(),
            agent_version: format!("{DAEMON_BINARY_NAME}/{}", env!("CARGO_PKG_VERSION")),
            hosts_path_override: Some(base_dir.join("hosts")),
        }
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

/// Parses `<host_or_ip>:<port>` supporting DNS names, IPv4, and bracketed IPv6 literals.
pub(crate) fn split_host_port(endpoint: &str) -> AppResult<(String, Port)> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(AppError::invalid_argument(
            "server endpoint cannot be empty",
        ));
    }
    if trimmed.contains("://") {
        return Err(AppError::invalid_argument(
            "server endpoint must be <host:port> without URL scheme",
        ));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (addr_raw, port_raw) = rest.split_once("]:").ok_or_else(|| {
            AppError::invalid_argument("IPv6 endpoint must match [<ipv6>]:<port>")
        })?;
        let parsed_v6: Ipv6Addr = addr_raw.parse().map_err(|err| {
            AppError::invalid_argument(format!("invalid IPv6 host '{addr_raw}': {err}"))
        })?;
        let port: Port = port_raw.parse()?;
        return Ok((parsed_v6.to_string(), port));
    }
    let (host_raw, port_raw) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| AppError::invalid_argument("server endpoint must contain :<port>"))?;
    let host = host_raw.trim();
    if host.is_empty() || host.contains(':') {
        return Err(AppError::invalid_argument(format!(
            "invalid server endpoint host '{host_raw}'"
        )));
    }
    let port: Port = port_raw.trim().parse()?;
    Ok((host.to_owned(), port))
}

/// Enforces fail-closed zero-TOFU rules against IP endpoints and missing SPKI pins.
pub(crate) fn validate_tls_trust_policy(
    endpoint: &str,
    mode: TlsAuthMode,
    active_pin: Option<SpkiPin>,
) -> AppResult<(String, Port)> {
    let (host, port) = split_host_port(endpoint)?;
    let is_ip_literal = host.parse::<IpAddr>().is_ok();
    match mode {
        TlsAuthMode::SpkiPin => {
            if active_pin.is_none() {
                return Err(AppError::invalid_argument(
                    "SPKI pin is required in spki_pin TLS mode; TOFU is forbidden",
                ));
            }
        }
        TlsAuthMode::SystemCa => {
            if is_ip_literal {
                return Err(AppError::invalid_argument(
                    "system_ca TLS mode requires a DNS hostname; IP endpoints require an SPKI pin",
                ));
            }
        }
    }
    Ok((host, port))
}

/// Builds a `rustls::ClientConfig` implementing zero-TOFU SPKI pinning or system WebPKI CAs.
pub(crate) fn build_tls_client_config_for(
    endpoint: &str,
    mode: TlsAuthMode,
    active_pin: Option<SpkiPin>,
    next_pin: Option<SpkiPin>,
) -> AppResult<Arc<ClientConfig>> {
    validate_tls_trust_policy(endpoint, mode, active_pin)?;
    match mode {
        TlsAuthMode::SpkiPin => {
            let primary = active_pin.ok_or_else(|| {
                AppError::invalid_argument("SPKI pin missing for spki_pin TLS mode")
            })?;
            let pin_set = match next_pin {
                Some(staged) => PinSet::dual(primary, staged),
                None => PinSet::single(primary),
            };
            build_pinned_client_config(pin_set)
        }
        TlsAuthMode::SystemCa => build_system_ca_client_config(),
    }
}

/// Formats an OS hostname into a valid RFC 1123 `NodeName` (`1..=63` `[a-z0-9-]`).
pub(crate) fn sanitize_hostname_to_node_name(raw: &str) -> AppResult<NodeName> {
    let mut cleaned = String::with_capacity(63);
    let mut prev_hyphen = true;
    for ch in raw.chars() {
        if cleaned.len() >= 63 {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            cleaned.push(ch.to_ascii_lowercase());
            prev_hyphen = false;
        } else if !prev_hyphen && !cleaned.is_empty() {
            cleaned.push('-');
            prev_hyphen = true;
        }
    }
    while cleaned.ends_with('-') {
        cleaned.pop();
    }
    if cleaned.is_empty() {
        "mesh-node".clone_into(&mut cleaned);
    }
    NodeName::parse(&cleaned)
}

/// Reads local OS hostname (`COMPUTERNAME`/`HOSTNAME`/sysinfo fallback) as a [`NodeName`].
pub(crate) fn detect_default_node_name() -> AppResult<NodeName> {
    let raw = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "mesh-node".to_owned());
    sanitize_hostname_to_node_name(&raw)
}

/// Atomically writes `bytes` to `target_path`, setting `0600` mode on Unix platforms.
pub(crate) fn write_private_file_atomic(target_path: &Path, bytes: &[u8]) -> AppResult<()> {
    let parent = target_path.parent().ok_or_else(|| {
        AppError::invalid_argument(format!(
            "target path has no parent directory: {}",
            target_path.display()
        ))
    })?;
    ensure_private_parent_dir(parent)?;

    let pid = std::process::id();
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state");
    let tmp_path = parent.join(format!(".{file_name}.{pid}.tmp"));

    let mut file = open_private_temp_file(&tmp_path)?;
    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        remove_temp_best_effort(&tmp_path);
        return Err(AppError::internal(format!(
            "failed writing temp state file {}: {err}",
            tmp_path.display()
        )));
    }
    drop(file);

    if let Err(err) = fs::rename(&tmp_path, target_path) {
        remove_temp_best_effort(&tmp_path);
        return Err(AppError::internal(format!(
            "failed promoting state file {}: {err}",
            target_path.display()
        )));
    }
    Ok(())
}

fn ensure_private_parent_dir(parent: &Path) -> AppResult<()> {
    fs::create_dir_all(parent).map_err(|err| {
        AppError::internal(format!(
            "failed creating directory {}: {err}",
            parent.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(err) = fs::set_permissions(parent, fs::Permissions::from_mode(0o700)) {
            tracing::debug!(
                component = "meshd.config",
                path = %parent.display(),
                error = %err,
                "could not tighten directory permissions to 0700"
            );
        }
    }
    Ok(())
}

fn open_private_temp_file(tmp_path: &Path) -> AppResult<fs::File> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(tmp_path).map_err(|err| {
        AppError::internal(format!(
            "failed opening temp state file {}: {err}",
            tmp_path.display()
        ))
    })
}

fn remove_temp_best_effort(path: &Path) {
    if let Err(err) = fs::remove_file(path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(
            component = "meshd.config",
            path = %path.display(),
            error = %err,
            "failed removing temp state file"
        );
    }
}

#[cfg(test)]
mod tests {
    use mesh_core::{ErrorKind, SpkiPin};
    use mesh_proto::agent_ipc::TlsAuthMode;
    use tempfile::tempdir;

    use super::{
        BOOTSTRAP_SCHEMA_VERSION, BootstrapConfig, BootstrapStore, sanitize_hostname_to_node_name,
        split_host_port, validate_tls_trust_policy,
    };

    #[test]
    fn test_bootstrap_rejects_stun_relay_ports_and_enforces_zero_tofu() {
        // Arrange
        let tampered_toml = r#"
schema_version = 1
server_endpoint = "203.0.113.10:8443"
tls_auth_mode = "spki_pin"
active_pin = "sha256:0101010101010101010101010101010101010101010101010101010101010101"
stun_port = 3479
"#;
        let ip_without_pin = BootstrapConfig {
            schema_version: BOOTSTRAP_SCHEMA_VERSION,
            server_endpoint: Some("203.0.113.10:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: None,
            ..BootstrapConfig::default()
        };
        let ip_with_system_ca =
            validate_tls_trust_policy("203.0.113.10:8443", TlsAuthMode::SystemCa, None);

        // Act
        let unknown_field_err = toml::from_str::<BootstrapConfig>(tampered_toml);
        let missing_pin_err = ip_without_pin.validate();

        // Assert
        assert!(unknown_field_err.is_err());
        assert!(matches!(
            missing_pin_err,
            Err(err) if err.kind() == ErrorKind::InvalidArgument
        ));
        assert!(matches!(
            ip_with_system_ca,
            Err(err) if err.kind() == ErrorKind::InvalidArgument
        ));
    }

    #[test]
    fn test_bootstrap_store_roundtrip_omits_stun_and_relay_fields() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let store = BootstrapStore::new(dir.path().join("bootstrap.toml"));
        let pin = SpkiPin::from_sha256_bytes([0x2a; 32]);
        let cfg = BootstrapConfig {
            server_endpoint: Some("203.0.113.20:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(pin),
            ..BootstrapConfig::default()
        };

        // Act
        store.save_atomic(&cfg).expect("save bootstrap");
        let raw = std::fs::read_to_string(store.path()).expect("read raw");
        let reloaded = store.load_or_default().expect("reload bootstrap");

        // Assert
        assert_eq!(reloaded, cfg);
        assert!(!raw.contains("stun"));
        assert!(!raw.contains("relay"));
        assert!(reloaded.build_tls_client_config().is_ok());
    }

    #[test]
    fn test_split_host_port_and_hostname_sanitization() {
        // Arrange & Act
        let ipv6 = split_host_port("[2001:db8::1]:9443").expect("ipv6");
        let dns = split_host_port("vpn.example.com:8443").expect("dns");
        let scheme_err = split_host_port("https://vpn.example.com:8443");
        let node = sanitize_hostname_to_node_name("Alice_MacBook.Local").expect("node name");

        // Assert
        assert_eq!(ipv6.0, "2001:db8::1");
        assert_eq!(ipv6.1.get(), 9443);
        assert_eq!(dns.0, "vpn.example.com");
        assert!(scheme_err.is_err());
        assert_eq!(node.as_str(), "alice-macbook-local");
    }
}
