//! Local diagnostics formatting (`SelfNetworkStatus`, `NetcheckResponse`, bugreport sizing)
//! (`US-106`, `ADR-021`).

use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
use mesh_proto::agent_ipc::{
    AgentStatusResponse, NetcheckResponse, ServerConnectionStatus, TlsAuthMode,
};

/// Default file name proposed in `GetSaveFileNameW` when exporting redacted diagnostics.
pub(crate) const DEFAULT_BUGREPORT_FILENAME: &str = "meshvpn-bugreport.tar";

/// Formats local self-node, Control/Relay TLS, UDP port, NAT, and conflict warnings (`US-106`).
#[must_use]
pub(crate) fn format_self_network_panel(status: &AgentStatusResponse) -> String {
    let mut lines = Vec::new();
    let self_ip = status
        .overlay_ip
        .map_or_else(|| "Unassigned".to_owned(), |ip| ip.to_string());
    let self_cidr = status
        .overlay_cidr
        .map_or_else(|| "-".to_owned(), |c| c.to_string());
    let tun_name = status.tun_interface_name.as_deref().unwrap_or("-");
    lines.push(format!(
        "Overlay: {} ({}) | TUN: {} (MTU {}) | Netmap v{}",
        self_ip, self_cidr, tun_name, status.tun_mtu, status.netmap_version
    ));

    if let Some(srv) = &status.server_connection {
        append_server_lines(&mut lines, srv);
    } else {
        lines.push("Server: Not configured".to_owned());
    }

    let net = &status.self_network;
    let nic = net.bound_physical_interface.as_deref().unwrap_or("-");
    lines.push(format!(
        "Local UDP Port: {} | Physical NIC: {} | NAT: {:?} ({} candidates)",
        net.local_udp_port,
        nic,
        net.nat_type,
        net.candidates.len()
    ));
    if let Some(note) = &net.nat_classification_note {
        lines.push(format!("NAT Note: {note}"));
    }
    if let Some(conflict) = &net.overlay_conflict_warning {
        lines.push(format!("WARNING (CIDR Overlap): {conflict}"));
    }
    if let Some(fw) = &net.macos_firewall_warning {
        lines.push(format!("Firewall Notice: {fw}"));
    }
    lines.join("\r\n")
}

fn append_server_lines(lines: &mut Vec<String>, srv: &ServerConnectionStatus) {
    let tls_str = match srv.tls_auth_mode {
        TlsAuthMode::SpkiPin => srv
            .active_pin
            .as_ref()
            .map_or_else(|| "SPKI Pin (unset)".to_owned(), |p| format!("SPKI {p}")),
        TlsAuthMode::SystemCa => "System CA Trust".to_owned(),
    };
    let next_pin = srv
        .next_pin
        .as_ref()
        .map_or_else(String::new, |p| format!(" | Next Pin: {p}"));
    let relay_rtt = srv
        .relay_rtt_ms
        .map_or_else(|| "-".to_owned(), |ms| format!("{ms}ms"));
    lines.push(format!(
        "Control: {} ({}) | Relay: {} ({}, RTT {})",
        srv.control_endpoint,
        if srv.control_connected { "up" } else { "down" },
        srv.relay_endpoint,
        if srv.relay_connected { "up" } else { "down" },
        relay_rtt,
    ));
    lines.push(format!("TLS Mode: {tls_str}{next_pin}"));
    if let Some(err) = &srv.last_error {
        lines.push(format!("Last Daemon Error: {err}"));
    }
}

/// Formats `POST /v1/agent/netcheck` probe output into readable multiline diagnostics.
#[must_use]
pub(crate) fn format_netcheck_report(resp: &NetcheckResponse) -> String {
    let mut lines = Vec::new();
    let stun_ep = resp.stun_endpoint_tested.as_deref().unwrap_or("-");
    let mapped = resp.reflexive_ipv4.as_deref().unwrap_or("-");
    let ctrl_ep = resp.control_tcp_endpoint_tested.as_deref().unwrap_or("-");
    let relay_rtt = resp
        .relay_rtt_ms
        .map_or_else(|| "-".to_owned(), |ms| format!("{ms:.2} ms"));

    lines.push(format!(
        "UDP Egress: {} | STUN Reachable: {} ({})",
        if resp.udp_egress_ok { "OK" } else { "BLOCKED" },
        if resp.stun_reachable { "OK" } else { "FAIL" },
        stun_ep
    ));
    lines.push(format!(
        "Reflexive IPv4: {} | IPv6: {} | NAT Mapping: {:?}",
        mapped,
        if resp.ipv6_available {
            "available"
        } else {
            "unavailable"
        },
        resp.nat_mapping
    ));
    lines.push(format!(
        "Control HTTPS TCP: {} ({}) | Relay RTT: {}",
        if resp.control_tcp_reachable {
            "OK"
        } else {
            "FAIL"
        },
        ctrl_ep,
        relay_rtt
    ));
    lines.push(format!("NAT Note: {}", resp.nat_note));
    if let Some(hint) = &resp.diagnostic_hint {
        lines.push(format!("Hint: {hint}"));
    }
    lines.join("\r\n")
}

/// Validates bugreport archive total size against `MAX_BUGREPORT_ARCHIVE_BYTES` (20 MiB) and
/// rejects zero-byte archives (`US-106`, `ADR-021`).
pub(crate) fn validate_bugreport_archive_size(expected_total_bytes: u64) -> Result<u64, String> {
    if expected_total_bytes == 0 {
        return Err("bugreport archive reported 0 bytes".to_owned());
    }
    let cap = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(20_971_520);
    if expected_total_bytes > cap {
        return Err(format!(
            "bugreport archive size {expected_total_bytes} exceeds limit {cap}"
        ));
    }
    Ok(expected_total_bytes)
}
