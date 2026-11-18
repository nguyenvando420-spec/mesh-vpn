//! Shared OS-neutral client runtime (`US-099`, `ADR-012`) extracted from `meshd` so Desktop
//! (`meshd`) and Mobile (`mesh-mobile-ffi`) execute one Control, Datapath, Roaming, Diagnostics,
//! and session supervision engine without `reqwest`, `unsafe`, or OS `sysexec` coupling.

pub mod config;
pub mod control_loop;
pub mod diagnostics;
pub mod hooks;
pub mod netmap_cache;
pub mod ping_probe;
pub mod roaming_loop;
pub mod session;
pub mod state;

use mesh_core::defaults::DEFAULT_MOBILE_MAX_WS_FRAME_BYTES;

pub use config::{
    BOOTSTRAP_SCHEMA_VERSION, BootstrapConfig, BootstrapStore, ClientRuntimeConfig,
    SplitTunnelCidr, SplitTunnelRoutePlan, build_tls_client_config_for,
    compute_split_tunnel_routes, current_target_arch, current_target_os, derive_overlay_dns_ip,
    detect_default_node_name, is_loopback_endpoint, load_inbound_filter_spec,
    sanitize_hostname_to_node_name, split_host_port, validate_tls_trust_policy,
    write_private_file_atomic,
};
pub use control_loop::{
    ControlDialOptions, ControlLoop, ControlLoopContext, ControlSessionExit, ControlWakeSignal,
    build_netmap_stream_target, build_relay_client_config_for_runtime,
    check_offline_key_grace_expired, connect_control_tls_with_protector, map_http_error_response,
    probe_udp_routing_candidates_protected, stage_and_apply_control_migration,
    validate_and_sanitize_netmap_snapshot,
};
pub use diagnostics::{
    BoundedTarArchive, BugreportBuildOptions, TAR_STREAM_BUFFER_BYTES, create_bugreport_tar_bundle,
    scrub_diagnostic_secrets,
};
pub use hooks::{
    ClientFuture, ClientPlatformHooks, ClientStateStore, DnsUpstreamHook, FileClientStateStore,
    InMemoryClientPlatformHooks, InMemoryClientStateStore, InMemoryDnsUpstreamHook,
    NoopDnsUpstreamHook, TunActivationOutcome,
};
pub use netmap_cache::{
    DEFAULT_KEY_EXPIRY_GRACE_HOURS, DEFAULT_OFFLINE_GRACE_HOURS, NetmapCacheFile, NetmapCacheStore,
    configured_offline_grace_hours,
};
pub use ping_probe::{
    PingProbe, probe_tcp_reachability, run_ephemeral_stun_probe, summarize_ping_samples,
};
pub use roaming_loop::{
    NETWORK_CHANGE_CHANNEL_CAPACITY, RoamingLoop, map_net_event_to_rebind_commands,
    map_net_event_with_primary,
};
pub use session::{
    ClientCommand, ClientSessionOptions, ClientSessionSupervisor, EnrollOrRotateRequest,
    EnrollOrRotateResult, RebindForwardContext, apply_port_override,
    apply_registration_to_bootstrap, forward_rebind_loop, handle_rebind_command,
    persist_bootstrap_and_runtime,
};
pub use state::{ClientRuntimeData, ClientRuntimeState, merge_local_and_reflexive_candidates};

/// Baseline capabilities and resource budgets for the shared client runtime (`WP-M-A0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRuntimeDescriptor {
    /// Maximum incoming Control WebSocket frame limit on mobile extensions (`256 KiB`, `ADR-016`).
    pub mobile_ws_frame_limit_bytes: usize,
}

impl Default for ClientRuntimeDescriptor {
    fn default() -> Self {
        Self {
            mobile_ws_frame_limit_bytes: DEFAULT_MOBILE_MAX_WS_FRAME_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_runtime_descriptor_defaults_to_mobile_ws_limit() {
        let descriptor = ClientRuntimeDescriptor::default();
        assert_eq!(descriptor.mobile_ws_frame_limit_bytes, 262_144);
    }
}
