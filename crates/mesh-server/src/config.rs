//! TOML configuration loading and invariant validation for `mesh-server` (`GNFR-11`, `US-042`,
//! `US-046`, `US-047`, `WP-S1-01`).

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use mesh_core::brand::DEFAULT_DOMAIN_SUFFIX;
use mesh_core::defaults::{
    DEFAULT_CONTROL_TCP_PORT, DEFAULT_OBS_BIND_ADDR, DEFAULT_OVERLAY_CIDR,
    LINUX_SERVER_ADMIN_SOCKET, default_control_port, default_stun_port,
};
use mesh_core::{AppError, AppResult, OverlayCidr, Port};
use serde::{Deserialize, Serialize};

/// Default per-node relay bandwidth ceiling (`20 Mbps = 2_500_000 bytes/sec`, `US-027 AC1`).
pub const DEFAULT_RELAY_BYTES_PER_SEC: u64 = 2_500_000;

/// Default STUN rate limit per source IP (`100 pkt/s/IP`, `US-019`).
pub const DEFAULT_STUN_PPS_PER_IP: u32 = 100;

/// Minimum supported client control protocol version (`US-050`).
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u16 = 1;

/// Control & Relay server TLS termination architecture mode (`US-047`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Default IP + ECDSA P-256 SPKI pin mode (`SEC-04(c)`).
    #[default]
    IpPinned,
    /// Standalone ACME mode (`TLS-ALPN-01` on default control port or `DNS-01` on any port).
    Acme,
    /// Terminated behind Nginx/Caddy/Traefik on the same host (`US-046`, `US-047`).
    ReverseProxy,
}

impl TlsMode {
    /// Canonical lowercase configuration string used in Admin API status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IpPinned => "ip_pinned",
            Self::Acme => "acme",
            Self::ReverseProxy => "reverse_proxy",
        }
    }

    /// Parses canonical string representation (`ip_pinned`, `acme`, `reverse_proxy`).
    pub fn parse(raw: &str) -> AppResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ip_pinned" | "pin" => Ok(Self::IpPinned),
            "acme" => Ok(Self::Acme),
            "reverse_proxy" | "proxy" => Ok(Self::ReverseProxy),
            _ => Err(AppError::invalid_argument(format!(
                "unsupported tls_mode `{raw}`; expected ip_pinned, acme, or reverse_proxy"
            ))),
        }
    }
}

/// Supported zero-port-80 ACME challenge variants (`US-047 AC1/AC7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallengeKind {
    /// RFC 8737 `tls-alpn-01` served over the default HTTPS port without opening port 80.
    #[default]
    TlsAlpn01,
    /// RFC 8555 `dns-01` allowing custom control TCP ports such as `8443` without port 80.
    Dns01,
}

/// Optional ACME issuance & renewal settings (`US-047`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeSettings {
    /// Public domain DNS name to request in SAN (required when `tls_mode == Acme`).
    pub domain: Option<String>,
    /// Contact `mailto:` email registered with ACME directory account.
    pub contact_email: Option<String>,
    /// ACME challenge kind (`tls_alpn01` or `dns01`).
    pub challenge: AcmeChallengeKind,
    /// Custom ACME directory URL (defaults to Let's Encrypt production when unset).
    pub directory_url: Option<String>,
    /// Optional webhook command/URL notified to publish `_acme-challenge` TXT for `dns01`.
    pub dns_webhook_url: Option<String>,
}

/// Control server runtime configuration loaded from TOML or CLI defaults (`GNFR-11`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// IP address bound by Control + Blind Relay TCP listener (`0.0.0.0` or `127.0.0.1`).
    pub control_bind_ip: String,
    /// TCP port for HTTPS + WebSocket control & Blind Relay listeners.
    pub control_tcp_port: u16,
    /// IP address bound by embedded UDP STUN listener.
    pub stun_bind_ip: String,
    /// UDP port for the embedded RFC 5389 STUN service.
    pub stun_udp_port: u16,
    /// Read-only localhost bind address for observability endpoints (`/healthz`, `/readyz`, `/metrics`).
    pub obs_bind_addr: String,
    /// Explicit flag allowing observability bind on overlay IP as well (`false` by default).
    pub obs_allow_non_loopback: bool,
    /// Default overlay IPv4 CIDR managed by this server.
    pub overlay_cidr: String,
    /// Mesh internal DNS suffix (`mesh.internal`).
    pub domain_suffix: String,
    /// Server public host or IP advertised in client Netmap `RelayMap` & join commands.
    pub public_host: String,
    /// Persistent state directory storing `control.redb`, `emergency-revocations.bin`, and backups.
    pub state_dir: PathBuf,
    /// Path to local UDS Admin socket (`/run/mesh-server/admin.sock` on Linux).
    pub admin_socket_path: PathBuf,
    /// Group allowed access to local Admin socket (`mesh-admin`).
    pub admin_group_name: String,
    /// Configured TLS mode (`ip_pinned`, `acme`, or `reverse_proxy`).
    pub tls_mode: TlsMode,
    /// ACME configuration block used when `tls_mode == Acme`.
    pub acme: AcmeSettings,
    /// Explicit trusted Reverse Proxy source IPs (`X-Real-IP` / `X-Forwarded-For` whitelist).
    pub trusted_proxies: Vec<IpAddr>,
    /// Per-node Blind Relay throughput cap in bytes/sec (default 20 Mbps = `2_500_000 B/s`).
    pub relay_bytes_per_sec: u64,
    /// Global aggregate Blind Relay throughput ceiling in bytes/sec across all nodes.
    pub relay_global_bytes_per_sec: u64,
    /// Maximum STUN packets processed per source IP per second (`100`).
    pub stun_pps_limit_per_ip: u32,
    /// Minimum client control protocol version permitted (`1`).
    pub min_protocol_version: u16,
    /// Optional operational alert webhook URL (`US-049`).
    pub alert_webhook_url: Option<String>,
    /// Allowed disk utilization percentage threshold before alert fires (`85%`).
    pub disk_alert_threshold_pct: u8,
    /// Allowed relay throughput ratio threshold (`80%`).
    pub relay_alert_threshold_pct: u8,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            control_bind_ip: "0.0.0.0".to_owned(),
            control_tcp_port: default_control_port().get(),
            stun_bind_ip: "0.0.0.0".to_owned(),
            stun_udp_port: default_stun_port().get(),
            obs_bind_addr: DEFAULT_OBS_BIND_ADDR.to_owned(),
            obs_allow_non_loopback: false,
            overlay_cidr: DEFAULT_OVERLAY_CIDR.to_owned(),
            domain_suffix: DEFAULT_DOMAIN_SUFFIX.to_owned(),
            public_host: "127.0.0.1".to_owned(),
            state_dir: PathBuf::from("/var/lib/mesh"),
            admin_socket_path: PathBuf::from(LINUX_SERVER_ADMIN_SOCKET),
            admin_group_name: mesh_core::defaults::LINUX_ADMIN_GROUP_NAME.to_owned(),
            tls_mode: TlsMode::IpPinned,
            acme: AcmeSettings::default(),
            trusted_proxies: Vec::new(),
            relay_bytes_per_sec: DEFAULT_RELAY_BYTES_PER_SEC,
            relay_global_bytes_per_sec: DEFAULT_RELAY_BYTES_PER_SEC.saturating_mul(20),
            stun_pps_limit_per_ip: DEFAULT_STUN_PPS_PER_IP,
            min_protocol_version: MIN_SUPPORTED_PROTOCOL_VERSION,
            alert_webhook_url: None,
            disk_alert_threshold_pct: 85,
            relay_alert_threshold_pct: 80,
        }
    }
}

impl ServerConfig {
    /// Parses a TOML configuration file and enforces production security & port invariants.
    pub fn load_from_toml(path: &Path) -> AppResult<Self> {
        let raw = fs::read_to_string(path).map_err(|err| {
            AppError::invalid_argument(format!(
                "failed reading server config {}: {err}",
                path.display()
            ))
        })?;
        let parsed: Self = toml::from_str(&raw).map_err(|err| {
            AppError::invalid_argument(format!(
                "invalid server TOML config {}: {err}",
                path.display()
            ))
        })?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Validates all port numbers, CIDR capacity, Reverse Proxy trust list, and ACME constraints.
    pub fn validate(&self) -> AppResult<()> {
        let _ = Port::from_u16(self.control_tcp_port)?;
        let _ = Port::from_u16(self.stun_udp_port)?;
        let _ = OverlayCidr::parse(&self.overlay_cidr)?;

        let control_ip: IpAddr = self.control_bind_ip.parse().map_err(|_| {
            AppError::invalid_argument(format!(
                "invalid control_bind_ip `{}`",
                self.control_bind_ip
            ))
        })?;
        let _: IpAddr = self.stun_bind_ip.parse().map_err(|_| {
            AppError::invalid_argument(format!("invalid stun_bind_ip `{}`", self.stun_bind_ip))
        })?;

        let obs_addr: SocketAddr = self.obs_bind_addr.parse().map_err(|_| {
            AppError::invalid_argument(format!("invalid obs_bind_addr `{}`", self.obs_bind_addr))
        })?;
        if !obs_addr.ip().is_loopback() && !self.obs_allow_non_loopback {
            return Err(AppError::permission_denied(format!(
                "obs_bind_addr `{}` must be loopback unless obs_allow_non_loopback is enabled",
                self.obs_bind_addr
            )));
        }

        if self.tls_mode == TlsMode::ReverseProxy && self.trusted_proxies.is_empty() {
            return Err(AppError::invalid_argument(
                "reverse_proxy mode requires non-empty trusted_proxies list (SEC-05)",
            ));
        }

        if self.tls_mode == TlsMode::ReverseProxy && control_ip.is_unspecified() {
            tracing::warn!(
                component = "mesh-server",
                event = "reverse_proxy_wildcard_bind",
                bind_ip = %control_ip,
                "control_bind_ip is wildcard while tls_mode=reverse_proxy; 127.0.0.1 is strongly recommended"
            );
        }

        self.validate_acme_settings()?;
        Ok(())
    }

    /// Returns deduplicated proxy trust set for [`crate::rate_limit::ClientIpExtractor`].
    #[must_use]
    pub fn trusted_proxy_set(&self) -> HashSet<IpAddr> {
        self.trusted_proxies.iter().copied().collect()
    }

    /// Returns `<public_host>:<control_tcp_port>` endpoint string published to peers.
    #[must_use]
    pub fn public_control_endpoint(&self) -> String {
        format_host_port(&self.public_host, self.control_tcp_port)
    }

    /// Returns `<public_host>:<stun_udp_port>` endpoint string published to peers.
    #[must_use]
    pub fn public_stun_endpoint(&self) -> String {
        format_host_port(&self.public_host, self.stun_udp_port)
    }

    /// Returns local TCP bind `SocketAddr` for Control + Blind Relay.
    pub fn control_socket_addr(&self) -> AppResult<SocketAddr> {
        let ip: IpAddr = self.control_bind_ip.parse().map_err(|_| {
            AppError::invalid_argument(format!(
                "invalid control_bind_ip `{}`",
                self.control_bind_ip
            ))
        })?;
        Ok(SocketAddr::new(ip, self.control_tcp_port))
    }

    /// Returns local UDP bind `SocketAddr` for embedded RFC 5389 STUN.
    pub fn stun_socket_addr(&self) -> AppResult<SocketAddr> {
        let ip: IpAddr = self.stun_bind_ip.parse().map_err(|_| {
            AppError::invalid_argument(format!("invalid stun_bind_ip `{}`", self.stun_bind_ip))
        })?;
        Ok(SocketAddr::new(ip, self.stun_udp_port))
    }

    /// Builds default SAN list (`public_host` + loopback `127.0.0.1` + `::1`) for self-signed identity.
    #[must_use]
    pub fn default_tls_sans(&self) -> Vec<String> {
        let mut sans = vec![self.public_host.clone()];
        let loopback_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST).to_string();
        if !sans.contains(&loopback_v4) {
            sans.push(loopback_v4);
        }
        sans
    }

    /// Path to `control.redb`.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("control.redb")
    }

    /// Path to pre-allocated `64 KiB` emergency revocation file.
    #[must_use]
    pub fn emergency_revocations_path(&self) -> PathBuf {
        self.state_dir.join("emergency-revocations.bin")
    }

    /// Path to local snapshot backups directory.
    #[must_use]
    pub fn backup_dir(&self) -> PathBuf {
        self.state_dir.join("backups")
    }

    fn validate_acme_settings(&self) -> AppResult<()> {
        if self.tls_mode != TlsMode::Acme {
            return Ok(());
        }
        let domain = self.acme.domain.as_deref().map(str::trim).unwrap_or("");
        if domain.is_empty() {
            return Err(AppError::invalid_argument(
                "acme mode requires non-empty acme.domain",
            ));
        }
        if self.acme.challenge == AcmeChallengeKind::TlsAlpn01
            && self.control_tcp_port != DEFAULT_CONTROL_TCP_PORT
        {
            return Err(AppError::invalid_argument(format!(
                "ACME TLS-ALPN-01 requires control_tcp_port == {DEFAULT_CONTROL_TCP_PORT} (port 80 not used); configure DNS-01 or Reverse Proxy for custom port {}",
                self.control_tcp_port
            )));
        }
        Ok(())
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_tls_alpn_rejects_custom_control_port_while_dns01_succeeds() {
        // Arrange
        let mut cfg = ServerConfig {
            tls_mode: TlsMode::Acme,
            control_tcp_port: 8443,
            ..ServerConfig::default()
        };
        cfg.acme.domain = Some("vpn.example.com".to_owned());
        cfg.acme.challenge = AcmeChallengeKind::TlsAlpn01;

        // Act & Assert: custom port rejected for TLS-ALPN-01 (`US-047 AC7`)
        assert!(cfg.validate().is_err());

        // Switching to DNS-01 allows non-443 control port without opening port 80
        cfg.acme.challenge = AcmeChallengeKind::Dns01;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_reverse_proxy_requires_trusted_proxies_and_obs_forbids_public_bind() {
        // Arrange
        let mut cfg = ServerConfig {
            tls_mode: TlsMode::ReverseProxy,
            ..ServerConfig::default()
        };
        assert!(cfg.validate().is_err());

        cfg.trusted_proxies = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        assert!(cfg.validate().is_ok());

        cfg.obs_bind_addr = "0.0.0.0:9091".to_owned();
        assert!(cfg.validate().is_err());
    }
}
