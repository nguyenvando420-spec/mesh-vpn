//! Local diagnostics formatting (`SelfNetworkStatus`, `NetcheckResponse`, bugreport sizing)
//! (`US-106`, `ADR-021`).

use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
#[cfg(any(target_os = "linux", test))]
use mesh_proto::agent_ipc::ServerConnectionStatus;
use mesh_proto::agent_ipc::{AgentStatusResponse, NetcheckResponse, TlsAuthMode};

/// Default file name proposed in `GetSaveFileNameW` when exporting redacted diagnostics.
pub(crate) const DEFAULT_BUGREPORT_FILENAME: &str = "meshvpn-bugreport.tar";

/// Formats local self-node, Control/Relay TLS, UDP port, NAT, and conflict warnings (`US-106`).
#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(target_os = "linux", test))]
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

/// Formats Zone 3 Settings & Identity summary (`Theme`, `Language`, `Server`, `Identity`, `ADR-028`).
#[cfg(all(target_os = "windows", test))]
#[must_use]
pub(crate) fn format_settings_identity_summary(
    status: Option<&AgentStatusResponse>,
    theme_label: &str,
    locale_label: &str,
) -> String {
    let mut lines = vec![format!(
        "Appearance: Theme={theme_label} | Language={locale_label} | Version=v{}",
        env!("CARGO_PKG_VERSION")
    )];
    if let Some(st) = status {
        lines.push(format_self_network_panel(st));
    } else {
        lines.push("Daemon diagnostics unavailable until MeshVpnAgent is running.".to_owned());
    }
    lines.join("\r\n")
}

/// Localized labels for the Zone 3 3-way Theme selector (`System / Light / Dark`, `US-127`).
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThemeSelectorLabels {
    pub(crate) section_label: String,
    pub(crate) system: String,
    pub(crate) light: String,
    pub(crate) dark: String,
}

/// Builds localized labels for the 3-way Theme selector using Discovery v1.1 §4.1 lookup `tr`.
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn build_theme_selector_labels(
    tr: impl Fn(&str) -> &'static str,
) -> ThemeSelectorLabels {
    let pick = |key: &str, fallback: &str| {
        let val = tr(key);
        if val.is_empty() {
            fallback.to_owned()
        } else {
            val.to_owned()
        }
    };
    ThemeSelectorLabels {
        section_label: format!("{}:", pick("theme.appearance", "Appearance")),
        system: pick("theme.system", "System"),
        light: pick("theme.light", "Light"),
        dark: pick("theme.dark", "Dark"),
    }
}

/// Localized labels for the Zone 3 3-way Language selector (`System / Tiếng Việt / English`,
/// `ADR-029`, `US-127`, `US-131` prep).
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocaleSelectorLabels {
    pub(crate) section_label: String,
    pub(crate) system: String,
    pub(crate) vietnamese: String,
    pub(crate) english: String,
}

/// Builds localized labels for the 3-way Language selector using Discovery v1.1 §4.1 lookup `tr`.
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn build_locale_selector_labels(
    tr: impl Fn(&str) -> &'static str,
) -> LocaleSelectorLabels {
    let pick = |key: &str, fallback: &str| {
        let val = tr(key);
        if val.is_empty() {
            fallback.to_owned()
        } else {
            val.to_owned()
        }
    };
    LocaleSelectorLabels {
        section_label: format!("{}:", pick("locale.language", "Language")),
        system: pick("locale.system", "System"),
        vietnamese: pick("locale.vietnamese", "Tiếng Việt"),
        english: pick("locale.english", "English"),
    }
}

/// Localized self-node network diagnostics panel using Discovery v1.1 §4.1 lookup `tr` (`US-127`).
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn format_self_network_panel_localized(
    status: &AgentStatusResponse,
    tr: impl Fn(&str) -> &'static str,
) -> String {
    let pick = |key: &str, fallback: &'static str| -> &'static str {
        let val = tr(key);
        if val.is_empty() { fallback } else { val }
    };
    let mut lines = Vec::new();
    let self_ip = status
        .overlay_ip
        .map_or_else(|| "-".to_owned(), |ip| ip.to_string());
    let self_cidr = status
        .overlay_cidr
        .map_or_else(|| "-".to_owned(), |c| c.to_string());
    let tun_name = status.tun_interface_name.as_deref().unwrap_or("-");
    lines.push(format!(
        "{}: {} ({}) | TUN: {} (MTU {}) | Netmap v{}",
        pick("label.overlay", "Overlay"),
        self_ip,
        self_cidr,
        tun_name,
        status.tun_mtu,
        status.netmap_version
    ));

    if let Some(srv) = &status.server_connection {
        let tls_str = match srv.tls_auth_mode {
            TlsAuthMode::SpkiPin => srv.active_pin.as_ref().map_or_else(
                || pick("onboarding.tls_spki_pin", "SPKI Pin (Default)").to_owned(),
                |p| format!("{} {p}", pick("onboarding.tls_spki_pin", "SPKI Pin")),
            ),
            TlsAuthMode::SystemCa => {
                pick("onboarding.tls_system_ca", "System CA (Domain)").to_owned()
            }
        };
        let next_pin = srv
            .next_pin
            .as_ref()
            .map_or_else(String::new, |p| format!(" | Next Pin: {p}"));
        let relay_rtt = srv
            .relay_rtt_ms
            .map_or_else(|| "-".to_owned(), |ms| format!("{ms}ms"));
        lines.push(format!(
            "{}: {} ({}) | {}: {} ({}, RTT {})",
            pick("label.control", "Control"),
            srv.control_endpoint,
            if srv.control_connected { "up" } else { "down" },
            pick("label.blind_relay", "Blind Relay"),
            srv.relay_endpoint,
            if srv.relay_connected { "up" } else { "down" },
            relay_rtt,
        ));
        lines.push(format!("TLS: {tls_str}{next_pin}"));
        if let Some(err) = &srv.last_error {
            lines.push(format!("Last Daemon Error: {err}"));
        }
    } else {
        lines.push(format!(
            "{}: {}",
            pick("label.control", "Control"),
            pick("state.not_enrolled", "Not Enrolled")
        ));
    }

    let net = &status.self_network;
    let nic = net.bound_physical_interface.as_deref().unwrap_or("-");
    lines.push(format!(
        "UDP: {} | NIC: {} | NAT: {:?} ({})",
        net.local_udp_port,
        nic,
        net.nat_type,
        net.candidates.len()
    ));
    if let Some(note) = &net.nat_classification_note {
        lines.push(format!("NAT: {note}"));
    }
    if let Some(conflict) = &net.overlay_conflict_warning {
        lines.push(format!(
            "{}: {conflict}",
            pick("warn.subnet_conflict", "Local Network Subnet Conflict")
        ));
    }
    if let Some(fw) = &net.macos_firewall_warning {
        lines.push(format!(
            "{}: {fw}",
            pick("warn.firewall", "Firewall Warning")
        ));
    }
    lines.join("\r\n")
}

/// Localized `POST /v1/agent/netcheck` diagnostics report using Discovery v1.1 §4.1 lookup `tr`.
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn format_netcheck_report_localized(
    resp: &NetcheckResponse,
    tr: impl Fn(&str) -> &'static str,
) -> String {
    let pick = |key: &str, fallback: &'static str| -> &'static str {
        let val = tr(key);
        if val.is_empty() { fallback } else { val }
    };
    let mut lines = vec![pick("diag.netcheck_title", "Network & NAT Diagnostics").to_owned()];
    lines.push(format_netcheck_report(resp));
    lines.join("\r\n")
}

/// Localized Zone 3 Settings & Identity summary using Discovery v1.1 §4.1 lookup `tr` (`US-127`).
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn format_settings_identity_summary_localized(
    status: Option<&AgentStatusResponse>,
    theme_label: &str,
    locale_label: &str,
    tr: impl Fn(&str) -> &'static str,
) -> String {
    let pick = |key: &str, fallback: &'static str| -> &'static str {
        let val = tr(key);
        if val.is_empty() { fallback } else { val }
    };
    let mut lines = vec![format!(
        "{}: {theme_label} | {}: {locale_label} | v{}",
        pick("theme.appearance", "Appearance"),
        pick("locale.language", "Language"),
        env!("CARGO_PKG_VERSION")
    )];
    if let Some(st) = status {
        lines.push(format_self_network_panel_localized(st, tr));
    } else {
        lines.push(pick("state.agent_unavailable", "Agent Unavailable").to_owned());
    }
    lines.join("\r\n")
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use mesh_proto::agent_ipc::NetcheckResponse;
    use mesh_proto::netmap::NatMappingKind;

    use super::{
        DEFAULT_BUGREPORT_FILENAME, build_locale_selector_labels, build_theme_selector_labels,
        format_netcheck_report, format_netcheck_report_localized,
        format_self_network_panel_localized, format_settings_identity_summary,
        format_settings_identity_summary_localized, validate_bugreport_archive_size,
    };

    #[test]
    fn test_diagnostics_view_settings_summary_without_status() {
        // Arrange & Act
        let text = format_settings_identity_summary(None, "Dark", "English");
        let loc_text = format_settings_identity_summary_localized(None, "Dark", "English", |_| "");
        let theme_lbls = build_theme_selector_labels(|_| "");
        let locale_lbls = build_locale_selector_labels(|_| "");
        let nc = NetcheckResponse {
            udp_egress_ok: true,
            stun_reachable: true,
            stun_endpoint_tested: None,
            reflexive_ipv4: None,
            ipv6_available: false,
            nat_mapping: NatMappingKind::Unknown,
            nat_note: "ok".to_owned(),
            control_tcp_reachable: true,
            control_tcp_endpoint_tested: None,
            relay_rtt_ms: None,
            diagnostic_hint: None,
        };
        type TrFn = fn(&str) -> &'static str;
        let _panel_fn: fn(&mesh_proto::agent_ipc::AgentStatusResponse, TrFn) -> String =
            format_self_network_panel_localized;

        // Assert
        assert_eq!(DEFAULT_BUGREPORT_FILENAME, "meshvpn-bugreport.tar");
        assert_eq!(validate_bugreport_archive_size(128), Ok(128));
        assert!(text.contains("Theme=Dark"));
        assert!(text.contains("Language=English"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(loc_text.contains("Appearance"));
        assert_eq!(theme_lbls.system, "System");
        assert_eq!(locale_lbls.vietnamese, "Tiếng Việt");
        assert!(format_netcheck_report(&nc).contains("UDP Egress: OK"));
        assert!(format_netcheck_report_localized(&nc, |_| "").contains("UDP Egress: OK"));
    }
}
