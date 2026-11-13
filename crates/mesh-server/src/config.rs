//! `mesh-server` TOML configuration skeleton (implemented in `WP-S1-01`).

use mesh_core::defaults::{
    DEFAULT_OBS_BIND_ADDR, DEFAULT_OVERLAY_CIDR, default_control_port, default_stun_port,
};
use serde::{Deserialize, Serialize};

/// Control server runtime configuration loaded from TOML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ServerConfig {
    /// TCP port for HTTPS + WebSocket control & Blind Relay listeners.
    pub(crate) control_tcp_port: u16,
    /// UDP port for the embedded RFC 5389 STUN service.
    pub(crate) stun_udp_port: u16,
    /// Read-only localhost bind address for observability endpoints.
    pub(crate) obs_bind_addr: String,
    /// Default overlay IPv4 CIDR managed by this server.
    pub(crate) overlay_cidr: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            control_tcp_port: default_control_port().get(),
            stun_udp_port: default_stun_port().get(),
            obs_bind_addr: DEFAULT_OBS_BIND_ADDR.to_owned(),
            overlay_cidr: DEFAULT_OVERLAY_CIDR.to_owned(),
        }
    }
}
