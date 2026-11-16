//! Human-readable table formatting, `--json` serialization, and zero-secret checks (`US-039`, `US-040`).

use std::fmt::{Arguments, Write as _};
use std::io::Write as _;

use serde::Serialize;

use mesh_core::{AppError, AppResult};
use mesh_crypto::Secret;
use mesh_proto::admin_ipc::{
    AdminNodeSummary, BackupCreatedResponse, HardeningCheckResponse, ListAuditEventsResponse,
    MigrateEndpointResponse, PersistenceTier, PreAuthKeyCreatedResponse, PreAuthKeySummary,
    RestoreBackupResponse, RevokeActionResponse, RotateTlsKeyResponse, ServerAdminStatusResponse,
};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentActionResponse, AgentStatusResponse, BugreportResponse, DaemonState,
    NetcheckResponse, PingResponse, PingVia, TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;

/// Returns diagnostic subsystem label.
#[cfg(test)]
#[must_use]
pub(crate) const fn status_label() -> &'static str {
    "output:ready"
}

/// Writes a formatted message cleanly to `stdout` without triggering `print_stdout` lints.
pub(crate) fn write_stdout(text: &str) -> AppResult<()> {
    let mut handle = std::io::stdout().lock();
    writeln!(handle, "{text}")
        .map_err(|err| AppError::internal(format!("failed writing to stdout: {err}")))
}

/// Writes a formatted warning or diagnostic line cleanly to `stderr`.
pub(crate) fn write_stderr(text: &str) -> AppResult<()> {
    let mut handle = std::io::stderr().lock();
    writeln!(handle, "{text}")
        .map_err(|err| AppError::internal(format!("failed writing to stderr: {err}")))
}

/// Serializes any response DTO cleanly for `--json` output.
pub(crate) fn render_json_string<T: Serialize>(value: &T) -> AppResult<String> {
    serde_json::to_string_pretty(value)
        .map_err(|err| AppError::internal(format!("failed serializing JSON output: {err}")))
}

fn push_line(out: &mut String, args: Arguments<'_>) {
    if out.write_fmt(args).is_err() {
        return;
    }
    out.push('\n');
}

/// Maps [`DaemonState`] to canonical lowercase label.
#[must_use]
pub(crate) const fn format_daemon_state(state: DaemonState) -> &'static str {
    match state {
        DaemonState::Stopped => "stopped",
        DaemonState::Connecting => "connecting",
        DaemonState::Connected => "connected",
        DaemonState::ReauthRequired => "reauth_required",
        DaemonState::Revoked => "revoked",
        DaemonState::Degraded => "degraded",
    }
}

const fn format_tls_mode(mode: TlsAuthMode) -> &'static str {
    match mode {
        TlsAuthMode::SpkiPin => "spki_pin",
        TlsAuthMode::SystemCa => "system_ca",
    }
}

const fn format_path_kind(path: ActivePathKind) -> &'static str {
    match path {
        ActivePathKind::Direct => "direct",
        ActivePathKind::Relay => "relay",
        ActivePathKind::None => "none",
    }
}

const fn format_ping_via(via: PingVia) -> &'static str {
    match via {
        PingVia::Direct => "direct",
        PingVia::Relay => "relay",
        PingVia::Timeout => "timeout",
    }
}

const fn format_nat_mapping(nat: NatMappingKind) -> &'static str {
    match nat {
        NatMappingKind::EimOrAdm => "eim_or_adm",
        NatMappingKind::PortDependent => "port_dependent",
        NatMappingKind::Unknown => "unknown",
    }
}

const fn format_persistence_tier(tier: PersistenceTier) -> &'static str {
    match tier {
        PersistenceTier::Redb => "redb",
        PersistenceTier::EmergencySlot => "emergency_slot",
        PersistenceTier::RamOnly => "ram_only",
    }
}

/// Formats `mesh status` output including daemon state, server connection, local NAT, and peers.
#[must_use]
pub(crate) fn format_status(resp: &AgentStatusResponse) -> String {
    let mut out = String::new();
    let waiting_for_control = resp.daemon_state == DaemonState::Connecting
        && (resp.netmap_version == 0
            || resp
                .server_connection
                .as_ref()
                .and_then(|c| c.last_error.as_deref())
                .is_some_and(|e| e.contains("waiting_for_control")));
    let state_suffix = if waiting_for_control {
        " (waiting_for_control)"
    } else {
        ""
    };
    push_line(
        &mut out,
        format_args!(
            "Daemon State : {}{state_suffix}",
            format_daemon_state(resp.daemon_state)
        ),
    );
    push_line(
        &mut out,
        format_args!(
            "Node         : {} ({})",
            resp.node_name
                .as_ref()
                .map_or("<unregistered>", |n| n.as_str()),
            resp.node_id
                .as_ref()
                .map_or_else(|| "-".to_owned(), ToString::to_string)
        ),
    );
    push_line(
        &mut out,
        format_args!(
            "Overlay      : {} (CIDR {}, TUN {}, MTU {})",
            resp.overlay_ip
                .map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
            resp.overlay_cidr
                .map_or_else(|| "-".to_owned(), |c| c.to_string()),
            resp.tun_interface_name.as_deref().unwrap_or("-"),
            resp.tun_mtu
        ),
    );
    push_line(
        &mut out,
        format_args!("Netmap       : v{}", resp.netmap_version),
    );
    if let Some(exp_ms) = resp.key_expires_at_ms {
        push_line(&mut out, format_args!("Key Expires  : {exp_ms} ms (epoch)"));
    }
    if let Some(conn) = &resp.server_connection {
        push_line(
            &mut out,
            format_args!(
                "Control      : {} (connected={}, tls={}, pin={})",
                conn.control_endpoint,
                conn.control_connected,
                format_tls_mode(conn.tls_auth_mode),
                conn.active_pin
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), ToString::to_string)
            ),
        );
        push_line(
            &mut out,
            format_args!(
                "Relay / STUN : {} (connected={}, rtt={}ms) | STUN [{}]",
                conn.relay_endpoint,
                conn.relay_connected,
                conn.relay_rtt_ms
                    .map_or_else(|| "-".to_owned(), |ms| ms.to_string()),
                conn.stun_endpoints.join(", ")
            ),
        );
        if let Some(err) = &conn.last_error {
            push_line(&mut out, format_args!("Last Error   : {err}"));
        }
    }
    push_line(
        &mut out,
        format_args!(
            "Self Network : udp_port={} iface={} nat={}",
            resp.self_network.local_udp_port,
            resp.self_network
                .bound_physical_interface
                .as_deref()
                .unwrap_or("-"),
            format_nat_mapping(resp.self_network.nat_type)
        ),
    );
    if let Some(warn_msg) = &resp.self_network.overlay_conflict_warning {
        push_line(&mut out, format_args!("Warning      : {warn_msg}"));
    }
    if let Some(fw_msg) = &resp.self_network.macos_firewall_warning {
        push_line(&mut out, format_args!("Firewall Note: {fw_msg}"));
    }
    out.push('\n');
    out.push_str(&format_peers(resp));
    out.trim_end().to_owned()
}

/// Formats `mesh peers` table.
#[must_use]
pub(crate) fn format_peers(resp: &AgentStatusResponse) -> String {
    let mut out = String::new();
    if resp.peers.is_empty() {
        out.push_str("Peers: (none)");
        return out;
    }
    push_line(
        &mut out,
        format_args!(
            "{:<18} {:<16} {:<7} {:<7} {:<22} {:<8} {}",
            "NAME", "OVERLAY_IP", "ONLINE", "PATH", "ENDPOINT", "RTT_MS", "RX/TX"
        ),
    );
    for peer in &resp.peers {
        push_line(
            &mut out,
            format_args!(
                "{:<18} {:<16} {:<7} {:<7} {:<22} {:<8} {}/{}",
                peer.name.as_str(),
                peer.overlay_ip,
                peer.online,
                format_path_kind(peer.active_path),
                peer.direct_endpoint.as_deref().unwrap_or("relay"),
                peer.rtt_ms
                    .map_or_else(|| "-".to_owned(), |ms| ms.to_string()),
                peer.rx_bytes,
                peer.tx_bytes
            ),
        );
    }
    out.trim_end().to_owned()
}

/// Formats `mesh ping` samples, aggregate stats, and `--direct` diagnostics (`US-040`).
#[must_use]
pub(crate) fn format_ping(resp: &PingResponse, force_direct: bool) -> String {
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!(
            "PING {} ({})",
            resp.target_name.as_str(),
            resp.target_overlay_ip
        ),
    );
    for sample in &resp.samples {
        let rtt_text = sample
            .rtt_ms
            .map_or_else(|| "-".to_owned(), |ms| format!("{ms:.2} ms"));
        push_line(
            &mut out,
            format_args!(
                "seq={} via={} endpoint={} rtt={}",
                sample.seq,
                format_ping_via(sample.via),
                sample.endpoint.as_deref().unwrap_or("-"),
                rtt_text
            ),
        );
    }
    push_line(
        &mut out,
        format_args!("--- {} ping statistics ---", resp.target_name.as_str()),
    );
    push_line(
        &mut out,
        format_args!(
            "{} packets transmitted, {} received, {:.1}% packet loss",
            resp.packets_sent, resp.packets_received, resp.loss_percent
        ),
    );
    if let (Some(min), Some(avg), Some(max)) = (resp.rtt_min_ms, resp.rtt_avg_ms, resp.rtt_max_ms) {
        push_line(
            &mut out,
            format_args!("rtt min/avg/max = {min:.2}/{avg:.2}/{max:.2} ms"),
        );
    }
    if force_direct && !resp.samples.iter().any(|s| s.via == PingVia::Direct) {
        push_line(
            &mut out,
            format_args!(
                "note: direct UDP path could not be established during --direct probe window (NAT traversal blocked or peer direct candidates unreachable)"
            ),
        );
    }
    out.trim_end().to_owned()
}

/// Formats `mesh netcheck` diagnostics.
#[must_use]
pub(crate) fn format_netcheck(resp: &NetcheckResponse) -> String {
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!("UDP Egress        : {}", resp.udp_egress_ok),
    );
    push_line(
        &mut out,
        format_args!(
            "STUN Reachable    : {} ({})",
            resp.stun_reachable,
            resp.stun_endpoint_tested.as_deref().unwrap_or("-")
        ),
    );
    push_line(
        &mut out,
        format_args!(
            "Reflexive IPv4    : {}",
            resp.reflexive_ipv4.as_deref().unwrap_or("-")
        ),
    );
    push_line(
        &mut out,
        format_args!("IPv6 Available    : {}", resp.ipv6_available),
    );
    push_line(
        &mut out,
        format_args!(
            "NAT Mapping       : {} ({})",
            format_nat_mapping(resp.nat_mapping),
            resp.nat_note
        ),
    );
    push_line(
        &mut out,
        format_args!(
            "Control/Relay TCP : {} ({})",
            resp.control_tcp_reachable,
            resp.control_tcp_endpoint_tested.as_deref().unwrap_or("-")
        ),
    );
    push_line(
        &mut out,
        format_args!(
            "Relay RTT         : {}",
            resp.relay_rtt_ms
                .map_or_else(|| "-".to_owned(), |ms| format!("{ms:.2} ms"))
        ),
    );
    if let Some(hint) = &resp.diagnostic_hint {
        push_line(&mut out, format_args!("Hint              : {hint}"));
    }
    out.trim_end().to_owned()
}

/// Formats `mesh up` / `down` / `cleanup` / `set` / `rotate-key` action acknowledgements.
#[must_use]
pub(crate) fn format_agent_action(resp: &AgentActionResponse) -> String {
    format!(
        "state={}: {}",
        format_daemon_state(resp.state),
        resp.message
    )
}

/// Formats `mesh bugreport` bundle location and scrubbing counts.
#[must_use]
pub(crate) fn format_bugreport(resp: &BugreportResponse) -> String {
    format!(
        "Bugreport created: {} ({} bytes, {} secret patterns scrubbed)",
        resp.bundle_path, resp.size_bytes, resp.scrubbed_items
    )
}

/// Formats one-time `mesh preauthkey create` output, wrapping plaintext key via `Secret<String>`.
#[must_use]
pub(crate) fn format_preauth_key_created(resp: &PreAuthKeyCreatedResponse) -> String {
    let raw_secret = Secret::new(resp.raw_key.clone());
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!("Pre-Auth Key Created (SHOWN ONCE - SAVE NOW)"),
    );
    push_line(&mut out, format_args!("Key ID          : {}", resp.key_id));
    push_line(
        &mut out,
        format_args!("Raw Key         : {}", raw_secret.expose_secret()),
    );
    push_line(
        &mut out,
        format_args!(
            "Reusable        : {} (max_uses={})",
            resp.reusable, resp.max_uses
        ),
    );
    push_line(
        &mut out,
        format_args!("Expires At (ms) : {}", resp.expires_at_ms),
    );
    push_line(
        &mut out,
        format_args!("Server Endpoint : {}", resp.server_endpoint),
    );
    if let Some(pin) = &resp.active_pin {
        push_line(&mut out, format_args!("Server Pin      : {pin}"));
    }
    push_line(
        &mut out,
        format_args!("Join (default)  : {}", resp.cli_join_command),
    );
    push_line(
        &mut out,
        format_args!("Join (file)     : {}", resp.join_command_file),
    );
    push_line(
        &mut out,
        format_args!("Join (stdin)    : {}", resp.join_command_stdin),
    );
    out.trim_end().to_owned()
}

/// Formats `mesh preauthkey create` output with optional stdout-only `--emit-uri` / `--qr` sections.
#[must_use]
pub(crate) fn format_preauth_key_created_with_mobile(
    resp: &PreAuthKeyCreatedResponse,
    join_uri: Option<&Secret<String>>,
    qr_terminal: Option<&str>,
) -> String {
    let mut out = format_preauth_key_created(resp);
    if let Some(uri_secret) = join_uri {
        out.push('\n');
        push_line(
            &mut out,
            format_args!("Mobile Join URI : {}", uri_secret.expose_secret()),
        );
    }
    if let Some(qr) = qr_terminal {
        out.push_str("\nScan Mobile Join QR Code:\n");
        out.push_str(qr);
        out.push('\n');
    }
    out.trim_end().to_owned()
}

/// Formats `mesh preauthkey list` summary rows.
#[must_use]
pub(crate) fn format_preauth_key_list(items: &[PreAuthKeySummary]) -> String {
    if items.is_empty() {
        return "Pre-Auth Keys: (none)".to_owned();
    }
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!(
            "{:<36} {:<10} {:<8} {:<10} {:<10} {}",
            "KEY_ID", "STATUS", "REUSE", "USED/MAX", "EPHEMERAL", "EXPIRES_AT_MS"
        ),
    );
    for item in items {
        push_line(
            &mut out,
            format_args!(
                "{:<36} {:<10} {:<8} {}/{:<8} {:<10} {}",
                item.key_id,
                item.status,
                item.reusable,
                item.used_count,
                item.max_uses,
                item.is_ephemeral,
                item.expires_at_ms
            ),
        );
    }
    out.trim_end().to_owned()
}

/// Formats urgent revoke/expire responses together with any required `stderr` persistence warning.
#[must_use]
pub(crate) fn format_revoke_action(
    action_label: &str,
    resp: &RevokeActionResponse,
) -> (String, Option<String>) {
    let stdout_line = format!(
        "{action_label}: target={} revoked={} ram_enforced={} persisted={} tier={} acted_at_ms={}",
        resp.target_id,
        resp.revoked,
        resp.ram_enforced,
        resp.persisted,
        format_persistence_tier(resp.persistence_tier),
        resp.acted_at_ms
    );
    let stderr_warn = match resp.persistence_tier {
        PersistenceTier::Redb => None,
        PersistenceTier::EmergencySlot => Some(format!(
            "WARNING: {action_label} for '{}' fell back to the emergency revocation slot because primary redb storage was unavailable.",
            resp.target_id
        )),
        PersistenceTier::RamOnly => Some(format!(
            "URGENT WARNING: {action_label} for '{}' was enforced in RAM ONLY (disk storage unavailable); state WILL BE LOST on mesh-server restart until disk space recovers!",
            resp.target_id
        )),
    };
    (stdout_line, stderr_warn)
}

/// Formats `mesh node list`.
#[must_use]
pub(crate) fn format_node_list(nodes: &[AdminNodeSummary]) -> String {
    if nodes.is_empty() {
        return "Nodes: (none)".to_owned();
    }
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!(
            "{:<36} {:<18} {:<16} {:<8} {:<7} {:<10} {}",
            "NODE_ID", "NAME", "OVERLAY_IP", "STATUS", "ONLINE", "OS/ARCH", "ACK_EP_VER"
        ),
    );
    for node in nodes {
        push_line(
            &mut out,
            format_args!(
                "{:<36} {:<18} {:<16} {:<8} {:<7} {}/{:<6} {}",
                node.node_id,
                node.name.as_str(),
                node.overlay_ip,
                node.status,
                node.online,
                node.os,
                node.arch,
                node.acked_endpoint_version
            ),
        );
    }
    out.trim_end().to_owned()
}

/// Formats `mesh node inspect`.
#[must_use]
pub(crate) fn format_node_inspect(node: &AdminNodeSummary) -> String {
    let mut out = String::new();
    push_line(&mut out, format_args!("Node ID       : {}", node.node_id));
    push_line(
        &mut out,
        format_args!("Name          : {}", node.name.as_str()),
    );
    push_line(
        &mut out,
        format_args!("Overlay IP    : {}", node.overlay_ip),
    );
    push_line(&mut out, format_args!("Status        : {}", node.status));
    push_line(&mut out, format_args!("Online        : {}", node.online));
    push_line(
        &mut out,
        format_args!("Platform      : {}/{}", node.os, node.arch),
    );
    push_line(
        &mut out,
        format_args!("Agent Version : {}", node.agent_version),
    );
    push_line(
        &mut out,
        format_args!("Last Seen(ms) : {}", node.last_seen_at_ms),
    );
    push_line(
        &mut out,
        format_args!(
            "Key Expires   : {}",
            node.key_expires_at_ms
                .map_or_else(|| "never".to_owned(), |ms| ms.to_string())
        ),
    );
    push_line(
        &mut out,
        format_args!("Acked Ep Ver  : {}", node.acked_endpoint_version),
    );
    out.trim_end().to_owned()
}

/// Formats `mesh server status` / `mesh server info`.
#[must_use]
pub(crate) fn format_server_status(resp: &ServerAdminStatusResponse) -> String {
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!("Control TCP Listen : {}", resp.control_tcp_listen),
    );
    push_line(
        &mut out,
        format_args!("STUN UDP Listen    : {}", resp.stun_udp_listen),
    );
    push_line(
        &mut out,
        format_args!(
            "TLS Mode           : {} (auth_mode={})",
            resp.tls_mode, resp.tls_auth_mode
        ),
    );
    push_line(
        &mut out,
        format_args!(
            "Active Pin         : {}",
            resp.active_pin
                .as_ref()
                .map_or_else(|| "-".to_owned(), ToString::to_string)
        ),
    );
    push_line(
        &mut out,
        format_args!(
            "Next Pin           : {}",
            resp.next_pin
                .as_ref()
                .map_or_else(|| "-".to_owned(), ToString::to_string)
        ),
    );
    push_line(
        &mut out,
        format_args!("Netmap Version     : v{}", resp.netmap_version),
    );
    push_line(
        &mut out,
        format_args!("Endpoint Version   : v{}", resp.endpoint_version),
    );
    push_line(
        &mut out,
        format_args!("Active Relays      : {}", resp.relay_sessions_active),
    );
    push_line(
        &mut out,
        format_args!("DB Degraded        : {}", resp.db_degraded),
    );
    if !resp.unacked_migration_nodes.is_empty() {
        push_line(
            &mut out,
            format_args!(
                "Unacked Migration  : {}",
                resp.unacked_migration_nodes.join(", ")
            ),
        );
    }
    out.trim_end().to_owned()
}

/// Formats `mesh server hardening-check`.
#[must_use]
pub(crate) fn format_hardening_check(resp: &HardeningCheckResponse) -> String {
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!("Hardening Check All Passed: {}", resp.all_passed),
    );
    for item in &resp.items {
        let tag = if item.passed { "PASS" } else { "FAIL" };
        push_line(
            &mut out,
            format_args!("[{tag}] {}: {}", item.check_id, item.detail),
        );
    }
    out.trim_end().to_owned()
}

/// Formats `mesh server backup`.
#[must_use]
pub(crate) fn format_backup_created(resp: &BackupCreatedResponse) -> String {
    format!(
        "Backup created: {} ({} bytes, sha256={})",
        resp.snapshot_path, resp.size_bytes, resp.sha256_hex
    )
}

/// Formats `mesh server restore`.
#[must_use]
pub(crate) fn format_restore_backup(resp: &RestoreBackupResponse) -> String {
    format!(
        "Restore completed: restored={} netmap_version={} nodes={}",
        resp.restored, resp.netmap_version, resp.node_count
    )
}

/// Formats `mesh server migrate-endpoint`.
#[must_use]
pub(crate) fn format_migrate_endpoint(resp: &MigrateEndpointResponse) -> String {
    format!(
        "Endpoint migrated: endpoint_version={} netmap_version={} control={} stun={} transition_deadline_ms={}",
        resp.endpoint_version,
        resp.netmap_version,
        resp.control_tcp_endpoint,
        resp.stun_udp_endpoint,
        resp.transition_deadline_at_ms
            .map_or_else(|| "none".to_owned(), |v| v.to_string())
    )
}

/// Formats `mesh server rotate-tls-key`.
#[must_use]
pub(crate) fn format_rotate_tls_key(resp: &RotateTlsKeyResponse) -> String {
    format!(
        "TLS key rotation: active_pin={} next_pin={} netmap_version={} staged={} promoted={}",
        resp.active_pin
            .as_ref()
            .map_or_else(|| "-".to_owned(), ToString::to_string),
        resp.next_pin
            .as_ref()
            .map_or_else(|| "-".to_owned(), ToString::to_string),
        resp.netmap_version,
        resp.staged,
        resp.promoted
    )
}

/// Formats `mesh audit list`.
#[must_use]
pub(crate) fn format_audit_events(resp: &ListAuditEventsResponse) -> String {
    if resp.events.is_empty() {
        return "Audit Events: (none)".to_owned();
    }
    let mut out = String::new();
    push_line(
        &mut out,
        format_args!(
            "{:<8} {:<15} {:<18} {:<24} {:<10} {}",
            "SEQ", "OCCURRED_AT_MS", "ACTOR", "ACTION", "OUTCOME", "TARGET"
        ),
    );
    for ev in &resp.events {
        push_line(
            &mut out,
            format_args!(
                "{:<8} {:<15} {:<18} {:<24} {:<10} {}",
                ev.seq,
                ev.occurred_at_ms,
                ev.actor,
                ev.action,
                ev.outcome,
                ev.target_id.as_deref().unwrap_or("-")
            ),
        );
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin};
    use mesh_proto::admin_ipc::{PersistenceTier, RevokeActionResponse};
    use mesh_proto::agent_ipc::{
        ActivePathKind, AgentPeerStatus, AgentStatusResponse, DaemonState, PingResponse,
        PingSample, PingVia, SelfNetworkStatus, ServerConnectionStatus, TlsAuthMode,
    };
    use mesh_proto::netmap::NatMappingKind;

    use super::{
        format_peers, format_ping, format_revoke_action, format_status, render_json_string,
    };

    fn sample_status() -> AgentStatusResponse {
        let pin = SpkiPin::parse(&format!("sha256:{}", "a".repeat(64))).expect("valid pin");
        AgentStatusResponse {
            daemon_state: DaemonState::Connected,
            node_id: Some(NodeId::new_v7(1_700_000_000_000)),
            node_name: Some(NodeName::parse("macbook-pro").expect("name")),
            fqdn: Some("macbook-pro.mesh".to_owned()),
            overlay_ip: Some(
                OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 2)).expect("overlay ip"),
            ),
            overlay_cidr: Some(OverlayCidr::parse("100.64.0.0/10").expect("cidr")),
            tun_interface_name: Some("utun4".to_owned()),
            tun_mtu: 1380,
            netmap_version: 12,
            key_expires_at_ms: Some(1_900_000_000_000),
            server_connection: Some(ServerConnectionStatus {
                control_endpoint: "203.0.113.10:8443".to_owned(),
                relay_endpoint: "203.0.113.10:8443".to_owned(),
                stun_endpoints: vec!["203.0.113.10:5478".to_owned()],
                tls_auth_mode: TlsAuthMode::SpkiPin,
                active_pin: Some(pin),
                next_pin: None,
                control_connected: true,
                relay_connected: true,
                relay_rtt_ms: Some(14),
                migration_pending_endpoint: None,
                last_error: None,
            }),
            self_network: SelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: Some("en0".to_owned()),
                nat_type: NatMappingKind::EimOrAdm,
                nat_classification_note: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                candidates: vec![],
            },
            peers: vec![AgentPeerStatus {
                node_id: NodeId::new_v7(1_700_000_000_001),
                name: NodeName::parse("build-vps").expect("peer"),
                fqdn: "build-vps.mesh".to_owned(),
                overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 1)).expect("overlay ip"),
                online: true,
                active_path: ActivePathKind::Direct,
                direct_endpoint: Some("203.0.113.20:51820".to_owned()),
                rtt_ms: Some(11),
                last_handshake_at_ms: Some(1_800_000_000_000),
                rx_bytes: 2048,
                tx_bytes: 1024,
            }],
        }
    }

    #[test]
    fn test_no_secrets_in_outputs() {
        // Arrange
        let status = sample_status();

        // Act
        let human_status = format_status(&status);
        let human_peers = format_peers(&status);
        let json_status = render_json_string(&status).expect("serialize status");

        // Assert
        for output in [&human_status, &human_peers, &json_status] {
            let lower = output.to_ascii_lowercase();
            assert!(!lower.contains("private_key"));
            assert!(!lower.contains("preauth"));
            assert!(!lower.contains("mpk_"));
            assert!(!lower.contains("secret"));
        }
        assert!(human_status.contains("build-vps"));
        assert!(human_peers.contains("direct"));
    }

    #[test]
    fn test_format_revoke_action_emits_urgent_warning_for_ram_only() {
        // Arrange
        let ram_only = RevokeActionResponse {
            target_id: "node-1".to_owned(),
            revoked: true,
            ram_enforced: true,
            persisted: false,
            persistence_tier: PersistenceTier::RamOnly,
            acted_at_ms: 1_700_000_000_000,
        };
        let durable = RevokeActionResponse {
            persistence_tier: PersistenceTier::Redb,
            persisted: true,
            ..ram_only.clone()
        };

        // Act
        let (out_ram, err_ram) = format_revoke_action("node_revoke", &ram_only);
        let (_out_db, err_db) = format_revoke_action("node_revoke", &durable);

        // Assert
        assert!(out_ram.contains("tier=ram_only"));
        let msg = err_ram.expect("ram_only warning");
        assert!(msg.contains("URGENT WARNING"));
        assert!(err_db.is_none());
    }

    #[test]
    fn test_format_ping_reports_relay_direct_and_direct_failure_note() {
        // Arrange
        let upgrade_resp = PingResponse {
            target_name: NodeName::parse("peer-a").expect("name"),
            target_overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 5))
                .expect("overlay ip"),
            samples: vec![
                PingSample {
                    seq: 1,
                    via: PingVia::Relay,
                    endpoint: Some("relay".to_owned()),
                    rtt_ms: Some(32.5),
                },
                PingSample {
                    seq: 2,
                    via: PingVia::Direct,
                    endpoint: Some("198.51.100.5:51820".to_owned()),
                    rtt_ms: Some(7.4),
                },
            ],
            packets_sent: 2,
            packets_received: 2,
            loss_percent: 0.0,
            rtt_min_ms: Some(7.4),
            rtt_avg_ms: Some(19.95),
            rtt_max_ms: Some(32.5),
        };
        let failed_direct = PingResponse {
            samples: vec![PingSample {
                seq: 1,
                via: PingVia::Timeout,
                endpoint: None,
                rtt_ms: None,
            }],
            packets_sent: 1,
            packets_received: 0,
            loss_percent: 100.0,
            rtt_min_ms: None,
            rtt_avg_ms: None,
            rtt_max_ms: None,
            ..upgrade_resp.clone()
        };

        // Act
        let upgraded_text = format_ping(&upgrade_resp, false);
        let direct_fail_text = format_ping(&failed_direct, true);

        // Assert
        assert!(upgraded_text.contains("via=relay"));
        assert!(upgraded_text.contains("via=direct"));
        assert!(direct_fail_text.contains("direct UDP path could not be established"));
    }

    #[test]
    fn test_format_waiting_for_control_netcheck_hints_and_bugreport_output() {
        use mesh_core::defaults::DEFAULT_CONTROL_TCP_PORT;
        use mesh_proto::agent_ipc::{
            AgentStatusResponse, BugreportResponse, DaemonState, NetcheckResponse,
            SelfNetworkStatus, ServerConnectionStatus, TlsAuthMode,
        };
        use mesh_proto::netmap::NatMappingKind;

        use super::{format_bugreport, format_netcheck};

        // Arrange: US-033 AC3 waiting_for_control status
        let waiting_status = AgentStatusResponse {
            daemon_state: DaemonState::Connecting,
            node_id: None,
            node_name: None,
            fqdn: None,
            overlay_ip: None,
            overlay_cidr: None,
            tun_interface_name: None,
            tun_mtu: 1280,
            netmap_version: 0,
            key_expires_at_ms: None,
            server_connection: Some(ServerConnectionStatus {
                control_endpoint: "203.0.113.10:8443".to_owned(),
                control_connected: false,
                relay_endpoint: "203.0.113.10:8443".to_owned(),
                relay_connected: false,
                relay_rtt_ms: None,
                stun_endpoints: vec![],
                tls_auth_mode: TlsAuthMode::SpkiPin,
                active_pin: None,
                next_pin: None,
                migration_pending_endpoint: None,
                last_error: Some("waiting_for_control: cache checksum mismatch".to_owned()),
            }),
            self_network: SelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: None,
                nat_type: NatMappingKind::Unknown,
                nat_classification_note: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                candidates: vec![],
            },
            peers: vec![],
        };

        // Act 1
        let status_txt = format_status(&waiting_status);

        // Assert 1
        assert!(status_txt.contains("connecting (waiting_for_control)"));

        // Arrange & Act 2: US-023 netcheck output + US-041 bugreport output
        let netcheck = NetcheckResponse {
            udp_egress_ok: false,
            stun_reachable: false,
            stun_endpoint_tested: None,
            reflexive_ipv4: None,
            ipv6_available: false,
            nat_mapping: NatMappingKind::Unknown,
            nat_note: "1-IP STUN heuristic".to_owned(),
            control_tcp_reachable: true,
            control_tcp_endpoint_tested: Some("203.0.113.10:8443".to_owned()),
            relay_rtt_ms: Some(14.5),
            diagnostic_hint: Some(format!(
                "UDP blocked, relay-only: try port {DEFAULT_CONTROL_TCP_PORT}"
            )),
        };
        let nc_txt = format_netcheck(&netcheck);
        assert!(nc_txt.contains("UDP blocked, relay-only"));
        assert!(nc_txt.contains("14.50 ms"));

        let bugreport = BugreportResponse {
            bundle_path: "/var/lib/meshd/bugreports/mesh-bugreport-1700000000.tar".to_owned(),
            size_bytes: 8192,
            scrubbed_items: 4,
        };
        let br_txt = format_bugreport(&bugreport);
        assert!(br_txt.contains(".tar"));
        assert!(br_txt.contains("8192 bytes"));
        assert!(br_txt.contains("4 secret patterns scrubbed"));
    }
}
