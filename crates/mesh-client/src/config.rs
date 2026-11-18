//! Client bootstrap configuration, TLS trust policy, runtime budgets, and split-tunnel routing
//! helpers (`US-004`, `SEC-15`, `OQ-MOB-04`, `ADR-016`).

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use rustls::ClientConfig;
use serde::{Deserialize, Serialize};

use mesh_core::defaults::{
    DEFAULT_IDLE_ENTRY_WINDOW_MS, DEFAULT_MOBILE_COALESCED_HEARTBEAT_MS,
    DEFAULT_MOBILE_MAX_BUGREPORT_BYTES, DEFAULT_MOBILE_MAX_WS_FRAME_BYTES, DEFAULT_TUN_MTU,
};
use mesh_core::{
    AppError, AppResult, ErrorKind, NodeId, NodeName, OverlayCidr, OverlayIp, Port, SpkiPin,
};
use mesh_crypto::{PinSet, build_pinned_client_config, build_system_ca_client_config};
use mesh_datapath::TimerMode;
use mesh_proto::agent_ipc::TlsAuthMode;
use mesh_proto::control::{TargetArch, TargetOs};
use mesh_proto::netmap::PeerEntry;

/// Current schema version for `bootstrap.toml`.
pub const BOOTSTRAP_SCHEMA_VERSION: u16 = 1;

/// Default desktop control WebSocket frame limit (`4 MiB`).
pub const DEFAULT_DESKTOP_MAX_WS_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Default desktop control application heartbeat cadence (`25 s`).
pub const DEFAULT_DESKTOP_HEARTBEAT_MS: u64 = 25_000;

/// Default desktop bugreport archive cap (`20 MiB`).
pub const DEFAULT_DESKTOP_MAX_BUGREPORT_BYTES: usize = 20 * 1024 * 1024;

/// Env override for blocked inbound overlay ports/rules (`US-018`).
const ENV_BLOCKED_INBOUND_PORTS: &str = "MESH_BLOCKED_INBOUND_PORTS";

const DEFAULT_MAX_DNS_DERIVATION_PROBE_STEPS: u32 = 4096;

/// Platform-parameterized client runtime budgets (`ADR-016`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRuntimeConfig {
    /// Maximum incoming WebSocket frame payload accepted on Control stream.
    pub max_ws_frame_bytes: usize,
    /// Initial datapath/relay timer cadence mode (`Responsive` desktop / `IdleAware` mobile).
    pub timer_mode: TimerMode,
    /// Inactivity window in milliseconds before `IdleAware` enters coalesced sleep.
    pub idle_entry_window_ms: u64,
    /// Application heartbeat interval in milliseconds when `IdleAware` / coalesced is active.
    pub coalesced_heartbeat_ms: u64,
    /// Maximum streamed bugreport `.tar` bundle size in bytes.
    pub max_bugreport_bytes: usize,
    /// Overlay TUN interface MTU.
    pub tun_mtu: u16,
    /// Reported agent version tag on Control registration/heartbeats.
    pub agent_version: String,
}

impl ClientRuntimeConfig {
    /// Returns the desktop daemon defaults (`4 MiB` WS frames, responsive `250 ms` ticks).
    #[must_use]
    pub fn for_desktop() -> Self {
        Self {
            max_ws_frame_bytes: DEFAULT_DESKTOP_MAX_WS_FRAME_BYTES,
            timer_mode: TimerMode::Responsive,
            idle_entry_window_ms: DEFAULT_IDLE_ENTRY_WINDOW_MS,
            coalesced_heartbeat_ms: DEFAULT_DESKTOP_HEARTBEAT_MS,
            max_bugreport_bytes: DEFAULT_DESKTOP_MAX_BUGREPORT_BYTES,
            tun_mtu: DEFAULT_TUN_MTU,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Returns mobile defaults obeying `ADR-016` (`256 KiB` WS frames, `IdleAware`, `45 s` heartbeat, `1 MiB` bugreport).
    #[must_use]
    pub fn for_mobile() -> Self {
        Self {
            max_ws_frame_bytes: DEFAULT_MOBILE_MAX_WS_FRAME_BYTES,
            timer_mode: TimerMode::IdleAware,
            idle_entry_window_ms: DEFAULT_IDLE_ENTRY_WINDOW_MS,
            coalesced_heartbeat_ms: DEFAULT_MOBILE_COALESCED_HEARTBEAT_MS,
            max_bugreport_bytes: DEFAULT_MOBILE_MAX_BUGREPORT_BYTES,
            tun_mtu: DEFAULT_TUN_MTU,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Returns the active Control WebSocket heartbeat cadence matching `mode`.
    #[must_use]
    pub fn control_heartbeat_ms_for(&self, mode: TimerMode) -> u64 {
        match mode {
            TimerMode::Responsive => {
                DEFAULT_DESKTOP_HEARTBEAT_MS.min(self.coalesced_heartbeat_ms.max(1))
            }
            TimerMode::IdleAware => self.coalesced_heartbeat_ms.max(1),
        }
    }
}

impl Default for ClientRuntimeConfig {
    fn default() -> Self {
        Self::for_desktop()
    }
}

/// Bootstrap persistence document containing ONLY Control endpoint & TLS trust material (`SEC-15`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    /// On-disk bootstrap schema version (`1`).
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    /// Persistent local node UUID once registered.
    pub node_id: Option<NodeId>,
    /// Persistent RFC 1123 node label once registered.
    pub node_name: Option<NodeName>,
    /// Assigned local overlay IPv4 persisted for offline P2P resume (`US-033`).
    #[serde(default)]
    pub overlay_ip: Option<OverlayIp>,
    /// Assigned local mesh FQDN persisted for offline display.
    #[serde(default)]
    pub fqdn: Option<String>,
    /// Control-plane `<host_or_ip>:<port>` endpoint.
    pub server_endpoint: Option<String>,
    /// Explicit TLS verification strategy (`spki_pin` vs `system_ca`).
    #[serde(default = "default_tls_auth_mode")]
    pub tls_auth_mode: TlsAuthMode,
    /// Active pinned server certificate SPKI SHA-256 fingerprint.
    pub active_pin: Option<SpkiPin>,
    /// Optional staged secondary pin during zero-downtime cert rotation.
    pub next_pin: Option<SpkiPin>,
    /// Highest server `endpoint_version` acknowledged during port migration (`US-074`).
    #[serde(default)]
    pub acked_endpoint_version: u64,
    /// Optional local identity key expiry timestamp in UTC milliseconds (`US-031 AC4`).
    #[serde(default)]
    pub key_expires_at_ms: Option<u64>,
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
    pub fn validate(&self) -> AppResult<()> {
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
    pub fn pin_set(&self) -> Option<PinSet> {
        if self.tls_auth_mode != TlsAuthMode::SpkiPin {
            return None;
        }
        self.active_pin.map(|active| match self.next_pin {
            Some(next) => PinSet::dual(active, next),
            None => PinSet::single(active),
        })
    }

    /// Builds a validated TLS 1.3 `rustls::ClientConfig` enforcing zero-TOFU fail-closed rules.
    pub fn build_tls_client_config(&self) -> AppResult<std::sync::Arc<ClientConfig>> {
        self.validate()?;
        let endpoint = self.server_endpoint.as_deref().ok_or_else(|| {
            AppError::invalid_argument("cannot build TLS config without server_endpoint")
        })?;
        build_tls_client_config_for(endpoint, self.tls_auth_mode, self.active_pin, self.next_pin)
    }

    /// Updates pinned TLS trust material after receiving a signed Netmap `PinSetDto`.
    pub fn apply_netmap_pins(&mut self, active: SpkiPin, next: Option<SpkiPin>) -> bool {
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
pub struct BootstrapStore {
    path: PathBuf,
}

impl BootstrapStore {
    /// Creates a store backed by `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the backing `bootstrap.toml` path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads `bootstrap.toml`, returning `Default` only when the file does not yet exist.
    pub fn load_or_default(&self) -> AppResult<BootstrapConfig> {
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
    pub fn save_atomic(&self, config: &BootstrapConfig) -> AppResult<()> {
        config.validate()?;
        let serialized = toml::to_string_pretty(config).map_err(|err| {
            AppError::internal(format!("failed serializing bootstrap config: {err}"))
        })?;
        write_private_file_atomic(&self.path, serialized.as_bytes())
    }
}

/// Validated non-default IPv4 split-tunnel route CIDR supporting `/1..=/32` (`OQ-MOB-04`).
///
/// Explicitly rejects `0.0.0.0/0` (`prefix_len == 0`) so Exit Node full-tunnel leakage cannot
/// slip into Android `VpnService.Builder.addRoute` or iOS `NEIPv4Settings.includedRoutes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SplitTunnelCidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl SplitTunnelCidr {
    /// Builds a host route `<ip>/32`.
    #[must_use]
    pub const fn host(ip: OverlayIp) -> Self {
        Self {
            network: ip.as_ipv4(),
            prefix_len: 32,
        }
    }

    /// Converts an [`OverlayCidr`] into a split-tunnel route entry.
    #[must_use]
    pub const fn from_overlay_cidr(cidr: OverlayCidr) -> Self {
        Self {
            network: cidr.network(),
            prefix_len: cidr.prefix_len(),
        }
    }

    /// Parses and canonicalizes `<ipv4>/<1..=32>`, rejecting `0.0.0.0/0` and reserved prefixes.
    pub fn parse(raw: &str) -> AppResult<Self> {
        let Some((ip_part, prefix_part)) = raw.trim().split_once('/') else {
            return Err(AppError::invalid_argument(
                "split-tunnel CIDR must match <ipv4>/<prefix_len>",
            ));
        };
        let ip: Ipv4Addr = ip_part.parse().map_err(|err| {
            AppError::invalid_argument(format!("invalid split-tunnel IPv4 '{ip_part}': {err}"))
        })?;
        let prefix_len: u8 = prefix_part.parse().map_err(|err| {
            AppError::invalid_argument(format!(
                "invalid split-tunnel prefix '{prefix_part}': {err}"
            ))
        })?;
        if prefix_len == 0 || prefix_len > 32 {
            return Err(AppError::invalid_argument(format!(
                "split-tunnel prefix length /{prefix_len} is forbidden (0.0.0.0/0 is disallowed)"
            )));
        }
        let _validated_ip = OverlayIp::from_ipv4(ip)?;
        let mask = ipv4_mask(prefix_len);
        let network = Ipv4Addr::from(u32::from(ip) & mask);
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Returns the masked network address.
    #[must_use]
    pub const fn network(self) -> Ipv4Addr {
        self.network
    }

    /// Returns the prefix length (`1..=32`).
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Returns the subnet mask corresponding to [`Self::prefix_len`].
    #[must_use]
    pub const fn subnet_mask(self) -> Ipv4Addr {
        let bits = ipv4_mask(self.prefix_len);
        Ipv4Addr::new(
            ((bits >> 24) & 0xff) as u8,
            ((bits >> 16) & 0xff) as u8,
            ((bits >> 8) & 0xff) as u8,
            (bits & 0xff) as u8,
        )
    }

    /// Formats canonical `<network>/<prefix_len>`.
    #[must_use]
    pub fn to_cidr_string(self) -> String {
        format!("{}/{}", self.network, self.prefix_len)
    }
}

impl std::fmt::Display for SplitTunnelCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

const fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

/// Computed mobile split-tunnel interface & route plan (`OQ-MOB-04`, `ADR-015`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitTunnelRoutePlan {
    /// Local TUN IPv4 host address (always `/32` on mobile to suppress implicit kernel subnet route).
    pub interface_address: SplitTunnelCidr,
    /// Ordered, deduplicated split-tunnel routes (`0` `0.0.0.0/0` entries).
    pub included_routes: Vec<SplitTunnelCidr>,
    /// Selected overlay DNS resolver IP (`<ip>/32`).
    pub overlay_dns_ip: OverlayIp,
    /// Whether `overlay_dns_ip` lies inside `overlay_cidr`.
    pub dns_inside_overlay_cidr: bool,
}

/// Derives a collision-free `overlay_dns_ip` inside `overlay_cidr` (`ADR-015` §2).
///
/// Walks backwards from the top usable host (`usable_host_count - 1 - k`) so `.1/.2` peer IPAM
/// assignments and active `underlay_ips` (including physical DNS servers) are never shadowed.
pub fn derive_overlay_dns_ip(
    overlay_cidr: OverlayCidr,
    self_overlay_ip: Option<OverlayIp>,
    peers: &[PeerEntry],
    underlay_ips: &[IpAddr],
) -> AppResult<OverlayIp> {
    let total = overlay_cidr.usable_host_count();
    if total == 0 {
        return Err(AppError::invalid_argument(format!(
            "overlay CIDR {overlay_cidr} has no usable host addresses"
        )));
    }
    let peer_ips: HashSet<OverlayIp> = peers.iter().map(|p| p.overlay_ip).collect();
    let max_probe = total.min(DEFAULT_MAX_DNS_DERIVATION_PROBE_STEPS);
    for step in 0..max_probe {
        let index = total - 1 - step;
        let Some(candidate) = overlay_cidr.nth_usable_ip(index) else {
            continue;
        };
        if !has_overlay_dns_collision(candidate, self_overlay_ip, &peer_ips, underlay_ips) {
            return Ok(candidate);
        }
    }
    Err(AppError::conflict(format!(
        "exhausted collision-free overlay_dns_ip candidates within {overlay_cidr}"
    )))
}

fn has_overlay_dns_collision(
    candidate: OverlayIp,
    self_overlay_ip: Option<OverlayIp>,
    peer_ips: &HashSet<OverlayIp>,
    underlay_ips: &[IpAddr],
) -> bool {
    if Some(candidate) == self_overlay_ip || peer_ips.contains(&candidate) {
        return true;
    }
    let cand_v4 = IpAddr::V4(candidate.as_ipv4());
    underlay_ips.contains(&cand_v4)
}

/// Builds a split-tunnel route plan enforcing `/32` TUN interface addressing, `0` `0.0.0.0/0`
/// routes, and `overlay_dns_ip/32` collision guards (`OQ-MOB-04`, `ADR-015`).
pub fn compute_split_tunnel_routes(
    overlay_cidr: OverlayCidr,
    self_overlay_ip: OverlayIp,
    overlay_dns_ip: OverlayIp,
    peers: &[PeerEntry],
    underlay_ips: &[IpAddr],
    subnet_conflict_detected: bool,
) -> AppResult<SplitTunnelRoutePlan> {
    let peer_ips: HashSet<OverlayIp> = peers.iter().map(|p| p.overlay_ip).collect();
    if has_overlay_dns_collision(
        overlay_dns_ip,
        Some(self_overlay_ip),
        &peer_ips,
        underlay_ips,
    ) {
        return Err(AppError::conflict(format!(
            "overlay_dns_ip {overlay_dns_ip} collides with local/peer overlay IP or underlay IP"
        )));
    }

    let dns_inside_overlay_cidr = overlay_cidr.contains_usable_host(overlay_dns_ip);
    let dns_route = SplitTunnelCidr::host(overlay_dns_ip);
    let mut included_routes = Vec::new();

    if subnet_conflict_detected {
        for peer in peers {
            let host = SplitTunnelCidr::host(peer.overlay_ip);
            if !included_routes.contains(&host) {
                included_routes.push(host);
            }
        }
        if !included_routes.contains(&dns_route) {
            included_routes.push(dns_route);
        }
    } else {
        included_routes.push(SplitTunnelCidr::from_overlay_cidr(overlay_cidr));
        // When `overlay_dns_ip` lives outside `overlay_cidr` (e.g. dedicated /32 resolver VIP),
        // append `<overlay_dns_ip>/32` explicitly so Split-DNS packets enter the TUN instead of
        // leaking out the physical gateway. When inside `overlay_cidr`, `overlay_cidr` already
        // covers it cleanly without overlapping routes.
        if !dns_inside_overlay_cidr {
            included_routes.push(dns_route);
        }
    }

    Ok(SplitTunnelRoutePlan {
        interface_address: SplitTunnelCidr::host(self_overlay_ip),
        included_routes,
        overlay_dns_ip,
        dns_inside_overlay_cidr,
    })
}

/// Returns the true compiled [`TargetOs`] variant without platform spoofing.
#[must_use]
pub const fn current_target_os() -> TargetOs {
    #[cfg(target_os = "android")]
    {
        TargetOs::Android
    }
    #[cfg(target_os = "ios")]
    {
        TargetOs::Ios
    }
    #[cfg(target_os = "macos")]
    {
        TargetOs::Darwin
    }
    #[cfg(target_os = "windows")]
    {
        TargetOs::Windows
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        TargetOs::Linux
    }
}

/// Returns the compiled CPU architecture tag matching `mesh_proto::control::TargetArch`.
#[must_use]
pub const fn current_target_arch() -> TargetArch {
    #[cfg(target_arch = "aarch64")]
    {
        TargetArch::Arm64
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        TargetArch::Amd64
    }
}

/// Splits `<host_or_ip>:<port>` (including bracketed IPv6) into validated host and [`Port`].
pub fn split_host_port(endpoint: &str) -> AppResult<(String, Port)> {
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

/// Returns `true` when `endpoint` targets a loopback host (`localhost`, `127.0.0.0/8`, `::1`, or
/// IPv4-mapped `::ffff:127.0.0.0/8`) that must not be pinned to a non-loopback physical NIC.
#[must_use]
pub fn is_loopback_endpoint(endpoint: &str) -> bool {
    let Ok((host, _port)) = split_host_port(endpoint) else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

/// Enforces fail-closed zero-TOFU rules against IP endpoints and missing SPKI pins.
pub fn validate_tls_trust_policy(
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
pub fn build_tls_client_config_for(
    endpoint: &str,
    mode: TlsAuthMode,
    active_pin: Option<SpkiPin>,
    next_pin: Option<SpkiPin>,
) -> AppResult<std::sync::Arc<ClientConfig>> {
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
pub fn sanitize_hostname_to_node_name(raw: &str) -> AppResult<NodeName> {
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

/// Reads local OS hostname (`HOSTNAME`/`COMPUTERNAME`/fallback) as a [`NodeName`].
pub fn detect_default_node_name() -> AppResult<NodeName> {
    let raw = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "mesh-node".to_owned());
    sanitize_hostname_to_node_name(&raw)
}

/// Loads configured inbound packet filter rules from `MESH_BLOCKED_INBOUND_PORTS` or
/// `<state_dir>/inbound-filter.conf` (`US-018`).
#[must_use]
pub fn load_inbound_filter_spec(state_dir: Option<&Path>) -> Option<String> {
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

/// Atomically writes `bytes` to `target_path`, setting `0600` mode on Unix platforms.
pub fn write_private_file_atomic(target_path: &Path, bytes: &[u8]) -> AppResult<()> {
    let parent = target_path.parent().ok_or_else(|| {
        AppError::invalid_argument(format!(
            "target path has no parent directory: {}",
            target_path.display()
        ))
    })?;
    ensure_private_parent_dir(parent)?;

    let tmp_path = temp_sibling_path(parent, target_path);
    let mut file = open_private_temp_file(&tmp_path)?;
    if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        remove_temp_best_effort(&tmp_path);
        return Err(AppError::internal(format!(
            "failed writing temp state file {}: {err}",
            tmp_path.display()
        )));
    }
    drop(file);

    promote_temp_file(&tmp_path, target_path)
}

/// Builds a private temporary sibling file path for streaming atomic writes.
#[must_use]
pub fn temp_sibling_path(parent: &Path, target_path: &Path) -> PathBuf {
    let pid = std::process::id();
    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state");
    parent.join(format!(".{file_name}.{pid}.tmp"))
}

/// Creates `parent` (with `0700` on Unix) and opens a `0600` writable handle at `tmp_path`.
pub fn create_private_file_handle(parent: &Path, tmp_path: &Path) -> AppResult<fs::File> {
    ensure_private_parent_dir(parent)?;
    open_private_temp_file(tmp_path)
}

/// Syncs `file` and atomically renames `tmp_path` onto `target_path`, cleaning up on error.
pub fn promote_private_temp_file(
    file: fs::File,
    tmp_path: &Path,
    target_path: &Path,
) -> AppResult<()> {
    if let Err(err) = file.sync_all() {
        remove_temp_best_effort(tmp_path);
        return Err(AppError::internal(format!(
            "failed syncing temp state file {}: {err}",
            tmp_path.display()
        )));
    }
    drop(file);
    promote_temp_file(tmp_path, target_path)
}

fn promote_temp_file(tmp_path: &Path, target_path: &Path) -> AppResult<()> {
    if let Err(err) = fs::rename(tmp_path, target_path) {
        remove_temp_best_effort(tmp_path);
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
                component = "mesh_client.config",
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

/// Removes a temporary state file on error, ignoring `NotFound`.
pub fn remove_temp_best_effort(path: &Path) {
    if let Err(err) = fs::remove_file(path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(
            component = "mesh_client.config",
            path = %path.display(),
            error = %err,
            "failed removing temp state file"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use mesh_core::{ErrorKind, OverlayCidr, OverlayIp, SpkiPin};
    use mesh_proto::agent_ipc::TlsAuthMode;
    use mesh_proto::control::TargetOs;
    use tempfile::tempdir;

    use super::{
        BOOTSTRAP_SCHEMA_VERSION, BootstrapConfig, BootstrapStore, ClientRuntimeConfig,
        SplitTunnelCidr, compute_split_tunnel_routes, current_target_os, derive_overlay_dns_ip,
        is_loopback_endpoint, sanitize_hostname_to_node_name, split_host_port,
        validate_tls_trust_policy,
    };

    #[test]
    fn test_bootstrap_store_roundtrip_and_zero_tofu_rejections() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let store = BootstrapStore::new(dir.path().join("bootstrap.toml"));
        let pin = SpkiPin::parse(&format!("sha256:{}", "a".repeat(64))).expect("pin");
        let cfg = BootstrapConfig {
            schema_version: BOOTSTRAP_SCHEMA_VERSION,
            server_endpoint: Some("203.0.113.10:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(pin),
            ..BootstrapConfig::default()
        };

        // Act
        store.save_atomic(&cfg).expect("save");
        let loaded = store.load_or_default().expect("load");
        let missing_pin =
            validate_tls_trust_policy("203.0.113.10:8443", TlsAuthMode::SpkiPin, None);
        let system_ca_ip =
            validate_tls_trust_policy("203.0.113.10:8443", TlsAuthMode::SystemCa, None);

        // Assert
        assert_eq!(loaded, cfg);
        assert_eq!(
            missing_pin.expect_err("tofu rejected").kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            system_ca_ip.expect_err("system_ca with ip rejected").kind(),
            ErrorKind::InvalidArgument
        );
    }

    #[test]
    fn test_split_host_port_and_hostname_sanitization() {
        // Arrange & Act
        let (v6, p6) = split_host_port("[2001:db8::1]:9443").expect("ipv6");
        let node = sanitize_hostname_to_node_name("My_Phone.Local!").expect("sanitize");

        // Assert
        assert_eq!(v6, "2001:db8::1");
        assert_eq!(p6.get(), 9443);
        assert_eq!(node.as_str(), "my-phone-local");
        assert!(is_loopback_endpoint("127.0.0.1:443"));
        assert!(is_loopback_endpoint("LOCALHOST:8443"));
        assert!(is_loopback_endpoint("[::1]:443"));
        assert!(is_loopback_endpoint("[::ffff:127.0.0.1]:3478"));
        assert!(!is_loopback_endpoint("203.0.113.10:443"));
        assert!(!is_loopback_endpoint("vpn.example.com:443"));
    }

    #[test]
    fn test_split_tunnel_routes_rejects_default_route_and_handles_dns_inside_and_outside_cidr() {
        // Arrange
        let cidr = OverlayCidr::parse("100.115.0.0/16").expect("cidr");
        let self_ip = cidr.nth_usable_ip(0).expect("self");
        let inner_dns = derive_overlay_dns_ip(cidr, Some(self_ip), &[], &[]).expect("inner dns");
        let external_dns = OverlayIp::from_ipv4(Ipv4Addr::new(100, 120, 0, 53)).expect("ext dns");

        // Act
        let default_route = SplitTunnelCidr::parse("0.0.0.0/0");
        let plan_inside =
            compute_split_tunnel_routes(cidr, self_ip, inner_dns, &[], &[], false).expect("inside");
        let plan_outside =
            compute_split_tunnel_routes(cidr, self_ip, external_dns, &[], &[], false)
                .expect("outside");
        let plan_conflict = compute_split_tunnel_routes(cidr, self_ip, inner_dns, &[], &[], true)
            .expect("conflict");
        let collision = compute_split_tunnel_routes(
            cidr,
            self_ip,
            inner_dns,
            &[],
            &[IpAddr::V4(inner_dns.as_ipv4())],
            false,
        );

        // Assert
        assert!(default_route.is_err());
        assert_eq!(plan_inside.interface_address.prefix_len(), 32);
        assert!(plan_inside.dns_inside_overlay_cidr);
        assert_eq!(plan_inside.included_routes.len(), 1);
        assert_eq!(
            plan_inside
                .included_routes
                .first()
                .copied()
                .map(SplitTunnelCidr::to_cidr_string)
                .as_deref(),
            Some("100.115.0.0/16")
        );

        assert!(!plan_outside.dns_inside_overlay_cidr);
        assert_eq!(plan_outside.included_routes.len(), 2);
        assert_eq!(
            plan_outside.included_routes.get(1).map(|r| r.prefix_len()),
            Some(32)
        );
        assert_eq!(
            plan_outside.included_routes.get(1).map(|r| r.network()),
            Some(external_dns.as_ipv4())
        );

        assert_eq!(plan_conflict.included_routes.len(), 1);
        assert_eq!(
            plan_conflict.included_routes.first().copied(),
            Some(SplitTunnelCidr::host(inner_dns))
        );
        assert_eq!(
            collision.expect_err("dns collision").kind(),
            ErrorKind::Conflict
        );
    }

    #[test]
    fn test_mobile_runtime_config_and_target_os_mapping() {
        // Arrange & Act
        let mobile = ClientRuntimeConfig::for_mobile();
        let target = current_target_os();

        // Assert
        assert_eq!(mobile.max_ws_frame_bytes, 262_144);
        assert_eq!(mobile.coalesced_heartbeat_ms, 45_000);
        assert_eq!(mobile.max_bugreport_bytes, 1_048_576);
        assert!(
            !matches!(target, TargetOs::Android | TargetOs::Ios)
                || cfg!(any(target_os = "android", target_os = "ios"))
        );
    }
}
