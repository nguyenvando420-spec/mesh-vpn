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
use mesh_net::sysexec::{AllowedBinary, CommandExecutor as _, CommandSpec, StdCommandExecutor};
use mesh_proto::agent_ipc::{
    AgentStatusResponse, BugreportResponse, NetcheckResponse, TlsAuthMode,
};

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
    /// Optional local identity key expiry timestamp in UTC milliseconds (`US-031 AC4`).
    #[serde(default)]
    pub(crate) key_expires_at_ms: Option<u64>,
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
            key_expires_at_ms: None,
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

/// Env override for blocked inbound overlay ports/rules (`US-018`).
const ENV_BLOCKED_INBOUND_PORTS: &str = "MESH_BLOCKED_INBOUND_PORTS";
/// Env override for rotated log directory collected by `mesh bugreport` (`US-041`).
const ENV_LOG_DIR: &str = "MESH_LOG_DIR";
/// Maximum total archive size permitted for `mesh bugreport` (`20 MiB`, `US-041 AC3`).
pub(crate) const MAX_BUGREPORT_ARCHIVE_BYTES: usize = 20 * 1024 * 1024;
const TAR_BLOCK_SIZE: usize = 512;
const TAR_END_MARKER_BYTES: usize = 1024;
const REDACTED_SECRET_PLACEHOLDER: &str = "[REDACTED_SECRET]";
const REDACTED_BEARER_PLACEHOLDER: &str = "[REDACTED_BEARER]";

/// Loads configured inbound packet filter rules from `MESH_BLOCKED_INBOUND_PORTS` or
/// `<state_dir>/inbound-filter.conf` (`US-018`).
#[must_use]
pub(crate) fn load_inbound_filter_spec(state_dir: Option<&Path>) -> Option<String> {
    if let Ok(env_val) = std::env::var(ENV_BLOCKED_INBOUND_PORTS) {
        let trimmed = env_val.trim().to_owned();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    let dir = state_dir?;
    let conf_path = dir.join("inbound-filter.conf");
    let raw = fs::read_to_string(conf_path).ok()?;
    let joined: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if joined.is_empty() {
        None
    } else {
        Some(joined.join(","))
    }
}

/// Sanitizes diagnostic text by redacting all pre-auth tokens (`mpk_*`), Bearer/JWT tokens,
/// PEM private keys, and secret key-value fields (`US-041 AC2`).
#[must_use]
pub(crate) fn scrub_diagnostic_secrets(input: &str) -> (String, usize) {
    let mut scrubbed_count = 0usize;
    let pem_redacted = redact_pem_private_keys(input, &mut scrubbed_count);
    let mpk_redacted = redact_prefixed_tokens(&pem_redacted, "mpk_", &mut scrubbed_count);
    let bearer_redacted = redact_bearer_tokens(&mpk_redacted, &mut scrubbed_count);

    let mut out = String::with_capacity(bearer_redacted.len());
    for (idx, line) in bearer_redacted.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let cleaned_line = redact_secret_kv_line(line, &mut scrubbed_count);
        out.push_str(&cleaned_line);
    }
    (out, scrubbed_count)
}

fn redact_pem_private_keys(input: &str, count: &mut usize) -> String {
    const BEGIN_MARKER: &str = "-----BEGIN ";
    const END_MARKER: &str = "-----END ";
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(BEGIN_MARKER) {
        let prefix = rest.get(..start).unwrap_or("");
        out.push_str(prefix);
        let after_begin = rest.get(start..).unwrap_or("");
        if let Some(first_line_end) = after_begin.find('\n') {
            let header = after_begin.get(..first_line_end).unwrap_or("");
            if header.contains("PRIVATE KEY")
                && let Some(end_idx) = after_begin.find(END_MARKER)
                && let Some(after_end) = after_begin.get(end_idx..)
            {
                let close_offset = after_end.find('\n').map_or(after_end.len(), |p| p + 1);
                out.push_str("[REDACTED_PRIVATE_KEY]\n");
                *count = count.saturating_add(1);
                rest = after_end.get(close_offset..).unwrap_or("");
                continue;
            }
        }
        out.push_str(BEGIN_MARKER);
        rest = rest.get(start + BEGIN_MARKER.len()..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

fn redact_prefixed_tokens(input: &str, prefix: &str, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let lower_prefix = prefix.to_ascii_lowercase();
    let mut idx = 0usize;
    while idx < input.len() {
        let slice_lower = lower.get(idx..).unwrap_or("");
        let Some(rel_pos) = slice_lower.find(&lower_prefix) else {
            out.push_str(input.get(idx..).unwrap_or(""));
            break;
        };
        let abs_pos = idx + rel_pos;
        out.push_str(input.get(idx..abs_pos).unwrap_or(""));
        let token_tail = input.get(abs_pos..).unwrap_or("");
        let tok_len = token_tail
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+'))
            .count();
        if tok_len > prefix.len() {
            out.push_str(REDACTED_SECRET_PLACEHOLDER);
            *count = count.saturating_add(1);
            idx = abs_pos + tok_len;
        } else {
            out.push_str(input.get(abs_pos..abs_pos + prefix.len()).unwrap_or(prefix));
            idx = abs_pos + prefix.len();
        }
    }
    out
}

fn redact_bearer_tokens(input: &str, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let needle = "bearer ";
    let mut idx = 0usize;
    while idx < input.len() {
        let slice_lower = lower.get(idx..).unwrap_or("");
        let Some(rel) = slice_lower.find(needle) else {
            out.push_str(input.get(idx..).unwrap_or(""));
            break;
        };
        let abs = idx + rel;
        out.push_str(input.get(idx..abs + needle.len()).unwrap_or(""));
        let rest = input.get(abs + needle.len()..).unwrap_or("");
        let tok_len = rest
            .bytes()
            .take_while(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/' | b'=' | b'~')
            })
            .count();
        if tok_len > 0 {
            out.push_str(REDACTED_BEARER_PLACEHOLDER);
            *count = count.saturating_add(1);
            idx = abs + needle.len() + tok_len;
        } else {
            idx = abs + needle.len();
        }
    }
    out
}

fn redact_secret_kv_line(line: &str, count: &mut usize) -> String {
    const SECRET_KEYS: [&str; 19] = [
        "node_secret",
        "disco_secret",
        "tls_private_key",
        "private_key",
        "secret_key",
        "preauth_key",
        "pre_auth_key",
        "authkey",
        "password",
        "passphrase",
        "api_token",
        "access_token",
        "secret_bytes",
        "wireguard_key",
        "noise_key",
        "x-mesh-auth-proof",
        "x-mesh-box-nonce",
        "authorization",
        "jwt",
    ];

    let lower = line.to_ascii_lowercase();
    let bytes = line.as_bytes();
    let lower_bytes = lower.as_bytes();
    let mut out = String::with_capacity(line.len() + 24);
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let Some(rel_sep) = bytes
            .get(cursor..)
            .and_then(|rest| rest.iter().position(|&b| b == b':' || b == b'='))
        else {
            break;
        };
        let sep_idx = cursor + rel_sep;
        let next_after_sep = advance_to_char_boundary(line, sep_idx + 1);
        let Some(key_end) = trim_kv_key_padding_before_sep(bytes, cursor, sep_idx) else {
            out.push_str(line.get(cursor..next_after_sep).unwrap_or(""));
            cursor = next_after_sep;
            continue;
        };
        let matched = lower.get(..key_end).is_some_and(|prefix| {
            matches_secret_key_suffix(prefix, lower_bytes, cursor, &SECRET_KEYS)
        });
        if !matched {
            out.push_str(line.get(cursor..next_after_sep).unwrap_or(""));
            cursor = next_after_sep;
            continue;
        }

        let val_start = skip_ascii_ws(bytes, sep_idx + 1);
        if val_start >= bytes.len() {
            out.push_str(line.get(cursor..next_after_sep).unwrap_or(""));
            cursor = next_after_sep;
            continue;
        }
        let val_rest = line.get(val_start..).unwrap_or("");
        if let Some(already_len) = already_redacted_prefix_len(val_rest) {
            let next = advance_to_char_boundary(line, val_start + already_len);
            out.push_str(line.get(cursor..next).unwrap_or(""));
            cursor = next.max(next_after_sep);
            continue;
        }

        let first = bytes.get(val_start).copied().unwrap_or(0);
        out.push_str(line.get(cursor..val_start).unwrap_or(""));
        let val_end = match first {
            b'"' | b'\'' => {
                let end = scan_quoted_value_end(line, val_start, first);
                let quote_ch = char::from(first);
                out.push(quote_ch);
                out.push_str(REDACTED_SECRET_PLACEHOLDER);
                out.push(quote_ch);
                end
            }
            b'{' | b'[' => {
                let end = scan_nested_json_value_end(line, val_start);
                out.push('"');
                out.push_str(REDACTED_SECRET_PLACEHOLDER);
                out.push('"');
                end
            }
            _ => {
                let end = scan_unquoted_value_end(line, val_start);
                out.push_str(REDACTED_SECRET_PLACEHOLDER);
                end
            }
        };
        *count = count.saturating_add(1);
        cursor = advance_to_char_boundary(line, val_end.max(next_after_sep));
    }

    if cursor < line.len() {
        out.push_str(line.get(cursor..).unwrap_or(""));
    }
    out
}

fn trim_kv_key_padding_before_sep(bytes: &[u8], cursor: usize, sep_idx: usize) -> Option<usize> {
    let mut i = sep_idx;
    while i > cursor {
        let prev = bytes.get(i - 1).copied()?;
        if matches!(prev, b'"' | b'\'' | b' ' | b'\t') {
            i -= 1;
            if matches!(prev, b'"' | b'\'')
                && i > cursor
                && bytes.get(i - 1).copied() == Some(b'\\')
            {
                i -= 1;
            }
        } else {
            break;
        }
    }
    (i > cursor).then_some(i)
}

fn matches_secret_key_suffix(
    lower_prefix: &str,
    lower_bytes: &[u8],
    min_start: usize,
    secret_keys: &[&str],
) -> bool {
    let key_end = lower_prefix.len();
    for &key in secret_keys {
        if key_end >= min_start + key.len() && lower_prefix.ends_with(key) {
            let key_start = key_end - key.len();
            if key_start == 0 {
                return true;
            }
            let prev = lower_bytes.get(key_start - 1).copied().unwrap_or(b' ');
            if !prev.is_ascii_alphanumeric() && prev != b'_' {
                return true;
            }
        }
    }
    false
}

fn skip_ascii_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if matches!(bytes.get(i).copied(), Some(b' ' | b'\t')) {
            i += 1;
        } else {
            break;
        }
    }
    i
}

fn already_redacted_prefix_len(val_rest: &str) -> Option<usize> {
    if val_rest.starts_with(REDACTED_BEARER_PLACEHOLDER) {
        return Some(REDACTED_BEARER_PLACEHOLDER.len());
    }
    if val_rest.starts_with(REDACTED_SECRET_PLACEHOLDER) {
        return Some(REDACTED_SECRET_PLACEHOLDER.len());
    }
    let quoted_len = REDACTED_SECRET_PLACEHOLDER.len() + 2;
    if (val_rest.starts_with('"') || val_rest.starts_with('\''))
        && val_rest
            .get(1..)
            .is_some_and(|inner| inner.starts_with(REDACTED_SECRET_PLACEHOLDER))
    {
        return Some(val_rest.len().min(quoted_len));
    }
    None
}

fn advance_to_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn scan_quoted_value_end(line: &str, val_start: usize, quote: u8) -> usize {
    let bytes = line.as_bytes();
    let mut i = val_start + 1;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes.get(i).copied().unwrap_or(0);
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if b == quote {
            return advance_to_char_boundary(line, i + 1);
        }
        i += 1;
    }
    line.len()
}

fn scan_nested_json_value_end(line: &str, val_start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut i = val_start;
    let mut depth = 0usize;
    let mut in_string: Option<u8> = None;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes.get(i).copied().unwrap_or(0);
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == quote {
                in_string = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => in_string = Some(b),
            b'{' | b'[' => depth = depth.saturating_add(1),
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return advance_to_char_boundary(line, i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    line.len()
}

fn scan_unquoted_value_end(line: &str, val_start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut i = val_start;
    while i < bytes.len() {
        let b = bytes.get(i).copied().unwrap_or(0);
        if matches!(
            b,
            b' ' | b'\t' | b'\r' | b',' | b'}' | b']' | b';' | b'"' | b'\''
        ) {
            break;
        }
        i += 1;
    }
    advance_to_char_boundary(line, i)
}

/// Pure-Rust POSIX ustar `.tar` archive builder bounded cleanly to `<= 20 MiB` (`US-041`).
struct BoundedTarArchive {
    bytes: Vec<u8>,
    max_total_bytes: usize,
    mtime_secs: u64,
}

impl BoundedTarArchive {
    fn new(max_total_bytes: usize, mtime_secs: u64) -> Self {
        Self {
            bytes: Vec::with_capacity(64 * 1024),
            max_total_bytes: max_total_bytes.max(TAR_END_MARKER_BYTES + TAR_BLOCK_SIZE * 2),
            mtime_secs,
        }
    }

    fn remaining_payload_budget(&self) -> usize {
        let reserved = self
            .bytes
            .len()
            .saturating_add(TAR_BLOCK_SIZE)
            .saturating_add(TAR_END_MARKER_BYTES);
        let raw = self.max_total_bytes.saturating_sub(reserved);
        (raw / TAR_BLOCK_SIZE).saturating_mul(TAR_BLOCK_SIZE)
    }

    fn append_text_entry(&mut self, name: &str, content: &[u8]) {
        let budget = self.remaining_payload_budget();
        if budget == 0 {
            return;
        }
        let header = build_ustar_header(name, content.len().min(budget), self.mtime_secs);
        self.bytes.extend_from_slice(&header);
        let write_len = content.len().min(budget);
        if let Some(slice) = content.get(..write_len) {
            self.bytes.extend_from_slice(slice);
        }
        let rem = write_len % TAR_BLOCK_SIZE;
        if rem != 0 {
            self.bytes
                .resize(self.bytes.len() + (TAR_BLOCK_SIZE - rem), 0);
        }
    }

    fn append_tail_truncated_log(&mut self, archive_name: &str, text: &str) {
        let budget = self.remaining_payload_budget();
        if budget == 0 {
            return;
        }
        let raw = text.as_bytes();
        if raw.len() <= budget {
            self.append_text_entry(archive_name, raw);
            return;
        }
        let banner = b"[... older log lines truncated to obey 20 MiB bugreport limit ...]\n";
        let tail_room = budget.saturating_sub(banner.len());
        let tail_start = raw.len().saturating_sub(tail_room);
        let aligned_start = raw
            .get(tail_start..)
            .and_then(|s| s.iter().position(|&b| b == b'\n'))
            .map_or(tail_start, |pos| (tail_start + pos + 1).min(raw.len()));
        let mut combined = Vec::with_capacity(budget);
        combined.extend_from_slice(banner);
        if let Some(tail) = raw.get(aligned_start..) {
            let copy_len = tail.len().min(budget.saturating_sub(combined.len()));
            if let Some(sl) = tail.get(..copy_len) {
                combined.extend_from_slice(sl);
            }
        }
        self.append_text_entry(archive_name, &combined);
    }

    fn finish(mut self) -> Vec<u8> {
        self.bytes
            .resize(self.bytes.len().saturating_add(TAR_END_MARKER_BYTES), 0);
        self.bytes
    }
}

fn build_ustar_header(name: &str, size: usize, mtime_secs: u64) -> [u8; TAR_BLOCK_SIZE] {
    let mut hdr = [0_u8; TAR_BLOCK_SIZE];
    let safe_name: String = name
        .trim_start_matches(['/', '\\'])
        .replace("..", "_")
        .chars()
        .take(99)
        .collect();
    write_tar_bytes(hdr.get_mut(0..100), safe_name.as_bytes());
    write_tar_bytes(hdr.get_mut(100..108), b"0000644\0");
    write_tar_bytes(hdr.get_mut(108..116), b"0000000\0");
    write_tar_bytes(hdr.get_mut(116..124), b"0000000\0");
    let size_oct = format!("{size:011o}\0");
    write_tar_bytes(hdr.get_mut(124..136), size_oct.as_bytes());
    let mtime_oct = format!("{mtime_secs:011o}\0");
    write_tar_bytes(hdr.get_mut(136..148), mtime_oct.as_bytes());
    write_tar_bytes(hdr.get_mut(148..156), b"        ");
    if let Some(t) = hdr.get_mut(156) {
        *t = b'0';
    }
    write_tar_bytes(hdr.get_mut(257..263), b"ustar\0");
    write_tar_bytes(hdr.get_mut(263..265), b"00");
    let checksum: u32 = hdr.iter().map(|&b| u32::from(b)).sum();
    let chk_oct = format!("{checksum:06o}\0 ");
    write_tar_bytes(hdr.get_mut(148..156), chk_oct.as_bytes());
    hdr
}

fn write_tar_bytes(dest: Option<&mut [u8]>, src: &[u8]) {
    if let Some(buf) = dest {
        let n = buf.len().min(src.len());
        if let (Some(d), Some(s)) = (buf.get_mut(..n), src.get(..n)) {
            d.copy_from_slice(s);
        }
    }
}

/// Collects OS route table diagnostics strictly via allowlisted `sysexec` (`G4`).
#[must_use]
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

fn candidate_log_dirs(state_dir: Option<&Path>) -> Vec<PathBuf> {
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

/// Creates a bounded (`<= 20 MiB`), scrubbed POSIX `.tar` bugreport archive (`US-041`).
pub(crate) fn create_bugreport_tar_bundle(
    state_dir: &Path,
    bootstrap: &BootstrapConfig,
    status: &AgentStatusResponse,
    netcheck: Result<&NetcheckResponse, &str>,
    now_unix_ms: u64,
) -> AppResult<BugreportResponse> {
    let mut scrubbed_total = 0usize;
    let mtime_secs = now_unix_ms / 1000;
    let mut archive = BoundedTarArchive::new(MAX_BUGREPORT_ARCHIVE_BYTES, mtime_secs);
    let target_os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };

    let version_text = format!(
        "binary={}\nversion={}\nos={target_os}\narch={}\ncreated_at_ms={now_unix_ms}\n",
        DAEMON_BINARY_NAME,
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    );
    let (v_clean, v_cnt) = scrub_diagnostic_secrets(&version_text);
    scrubbed_total = scrubbed_total.saturating_add(v_cnt);
    archive.append_text_entry("version.txt", v_clean.as_bytes());

    let status_json =
        serde_json::to_string_pretty(status).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
    let (st_clean, st_cnt) = scrub_diagnostic_secrets(&status_json);
    scrubbed_total = scrubbed_total.saturating_add(st_cnt);
    archive.append_text_entry("status.json", st_clean.as_bytes());

    let netcheck_json = match netcheck {
        Ok(nc) => {
            serde_json::to_string_pretty(nc).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        }
        Err(err) => format!(
            "{{\"error\":{}}}",
            serde_json::to_string(err).unwrap_or_default()
        ),
    };
    let (nc_clean, nc_cnt) = scrub_diagnostic_secrets(&netcheck_json);
    scrubbed_total = scrubbed_total.saturating_add(nc_cnt);
    archive.append_text_entry("netcheck.json", nc_clean.as_bytes());

    let bootstrap_toml = toml::to_string_pretty(bootstrap).unwrap_or_default();
    let (bs_clean, bs_cnt) = scrub_diagnostic_secrets(&bootstrap_toml);
    scrubbed_total = scrubbed_total.saturating_add(bs_cnt);
    archive.append_text_entry("bootstrap-sanitized.toml", bs_clean.as_bytes());

    let routes_raw = collect_os_route_table();
    let (rt_clean, rt_cnt) = scrub_diagnostic_secrets(&routes_raw);
    scrubbed_total = scrubbed_total.saturating_add(rt_cnt);
    archive.append_text_entry("routes.txt", rt_clean.as_bytes());

    let mut log_paths: Vec<PathBuf> = Vec::new();
    for dir in candidate_log_dirs(Some(state_dir)) {
        if let Ok(entries) = fs::read_dir(&dir) {
            for ent in entries.flatten() {
                let p = ent.path();
                if p.is_file() {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.contains("mesh") || name.ends_with(".log") {
                        log_paths.push(p);
                    }
                }
            }
        }
    }
    log_paths.sort_by(|a, b| {
        let ma = fs::metadata(a).and_then(|m| m.modified()).ok();
        let mb = fs::metadata(b).and_then(|m| m.modified()).ok();
        mb.cmp(&ma).then_with(|| a.cmp(b))
    });
    log_paths.dedup();

    for log_path in log_paths {
        if archive.remaining_payload_budget() < TAR_BLOCK_SIZE * 4 {
            break;
        }
        if let Ok(raw_bytes) = fs::read(&log_path) {
            let lossy = String::from_utf8_lossy(&raw_bytes);
            let (clean, cnt) = scrub_diagnostic_secrets(&lossy);
            scrubbed_total = scrubbed_total.saturating_add(cnt);
            let fname = log_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("meshd.log");
            archive.append_tail_truncated_log(&format!("logs/{fname}"), &clean);
        }
    }

    let tar_bytes = archive.finish();
    let bundle_dir = state_dir.join("bugreports");
    let bundle_path = bundle_dir.join(format!("mesh-bugreport-{now_unix_ms}.tar"));
    write_private_file_atomic(&bundle_path, &tar_bytes)?;

    Ok(BugreportResponse {
        bundle_path: bundle_path.to_string_lossy().into_owned(),
        size_bytes: u64::try_from(tar_bytes.len()).unwrap_or(u64::MAX),
        scrubbed_items: u32::try_from(scrubbed_total).unwrap_or(u32::MAX),
    })
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

    // Traces: HR-W21-10 (`US-041 AC2`, `SEC-01`)
    #[test]
    fn test_redact_secret_kv_line_scrubs_15_plus_canary_secrets_escaped_and_nested() {
        // Arrange
        let json_line = concat!(
            "{",
            "\"safe_node\":\"macbook-1\",",
            "\"node_secret\":\"CANARY_01_escaped\\\"quote\",",
            "\"disco_secret\":\"CANARY_02_secret\",",
            "\"tls_private_key\":\"CANARY_03_pem_body\",",
            "\"private_key\":\"CANARY_04_raw_hex\",",
            "\"secret_key\":{\"nested_inner\":\"CANARY_05_nested_obj\",\"arr\":[\"CANARY_06_arr\"]},",
            "\"preauth_key\":\"CANARY_07_preauth\",",
            "\"pre_auth_key\":\"CANARY_08_pre_auth\",",
            "\"authkey\":\"CANARY_09_authkey\",",
            "\"password\":\"CANARY_10_pw\\\"escaped\",",
            "\"passphrase\":\"CANARY_11_passphrase\",",
            "\"api_token\":\"CANARY_12_api_tok\",",
            "\"access_token\":\"CANARY_13_access_tok\",",
            "\"secret_bytes\":[1,2,\"CANARY_14_bytes\"],",
            "\"wireguard_key\":\"CANARY_15_wg_key\",",
            "\"noise_key\":\"CANARY_16_noise_key\",",
            "\"x-mesh-auth-proof\":\"CANARY_17_proof\",",
            "\"x-mesh-box-nonce\":\"CANARY_18_nonce\",",
            "\"authorization\":\"CANARY_19_authz\",",
            "\"jwt\":\"CANARY_20_jwt_tail\"",
            "}"
        );

        // Act
        let (scrubbed, scrubbed_count) = super::scrub_diagnostic_secrets(json_line);

        // Assert
        assert!(
            scrubbed_count >= 19,
            "expected all 19 secret fields redacted, got {scrubbed_count}: {scrubbed}"
        );
        for idx in 1..=20 {
            let marker = format!("CANARY_{idx:02}_");
            assert!(
                !scrubbed.contains(&marker),
                "leaked canary {marker} in redacted output: {scrubbed}"
            );
        }
        assert!(scrubbed.contains("\"safe_node\":\"macbook-1\""));
        assert!(
            serde_json::from_str::<serde_json::Value>(&scrubbed).is_ok(),
            "redacted JSON structure corrupted: {scrubbed}"
        );
    }
}
