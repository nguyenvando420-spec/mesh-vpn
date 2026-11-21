//! Application state machine, daemon version comparison, and sanitized GUI logging
//! (`ADR-020`, `ADR-022`, `OPS-01`, `SEC-01`, `SEC-05`).

#[cfg(any(target_os = "windows", target_os = "linux"))]
use std::path::{Path, PathBuf};

use mesh_net::ipc::AgentVersionStatus;
use mesh_proto::agent_ipc::{AgentStatusResponse, DaemonState};

/// Subdirectory inside local data dir reserved for MeshVPN client logs.
#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) const GUI_APP_DATA_DIR_NAME: &str = "MeshVPN";

/// Folder inside app data dir storing rotating JSON logs.
#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) const GUI_LOG_SUBDIR: &str = "logs";

/// Eight high-level Windows Desktop GUI lifecycle states (`US-103`, `US-104`, `US-107`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DesktopUiState {
    /// Local daemon IPC pipe is unreachable and SCM did not confirm Stopped/NotInstalled.
    AgentUnavailable,
    /// SCM confirmed `MeshVpnAgent` service is Stopped or NotInstalled.
    ServiceStopped,
    /// Daemon IPC reachable, `DaemonState::Stopped`, and node is not yet enrolled.
    NotEnrolled,
    /// Daemon is actively establishing Control/Relay/Noise connectivity.
    Connecting,
    /// Node is enrolled (`Connected`, `Degraded` banner, or clean `Disconnected` with 1-click Up).
    Connected,
    /// Node key expired (`ErrorKind::NodeKeyExpired`); user must rotate Pre-Auth Key via UAC.
    ReauthRequired,
    /// Admin revoked this node; user must Reset Identity & Re-enroll via UAC.
    Revoked,
    /// Recoverable transient error surfaced with actionable retry controls.
    ErrorRecoverable,
}

impl DesktopUiState {
    /// Returns a concise human-readable state tag for badges and accessibility labels.
    ///
    /// Preserved unchanged for `linux_gui.rs` and existing test compatibility (`ADR-030`).
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::AgentUnavailable => "Agent Unavailable",
            Self::ServiceStopped => "Service Stopped",
            Self::NotEnrolled => "Not Enrolled",
            Self::Connecting => "Connecting",
            Self::Connected => "Enrolled",
            Self::ReauthRequired => "Re-auth Required",
            Self::Revoked => "Revoked",
            Self::ErrorRecoverable => "Error (Recoverable)",
        }
    }

    /// Returns a concise sub-state-aware canonical label for UI badges, tray tooltips,
    /// and accessibility announcements (`ADR-030`).
    #[must_use]
    pub(crate) const fn display_label(self, sub_state: TunnelSubState) -> &'static str {
        match self {
            Self::AgentUnavailable => "Agent Unavailable",
            Self::ServiceStopped => "Service Stopped",
            Self::NotEnrolled => "Not Enrolled",
            Self::Connecting => "Connecting",
            Self::Connected => match sub_state {
                TunnelSubState::Connected => "Connected",
                TunnelSubState::Degraded => "Degraded",
                TunnelSubState::Disconnected => "Disconnected",
                TunnelSubState::Connecting => "Connecting",
                TunnelSubState::NotEnrolled => "Not Enrolled",
                TunnelSubState::ReauthRequired => "Re-auth Required",
                TunnelSubState::Revoked => "Device Revoked",
            },
            Self::ReauthRequired => "Re-auth Required",
            Self::Revoked => "Device Revoked",
            Self::ErrorRecoverable => "Attention Required",
        }
    }

    /// Returns the primary dashboard headline distinguishing Connected, Degraded, and Disconnected.
    #[must_use]
    pub(crate) const fn headline(self, sub_state: TunnelSubState) -> &'static str {
        match self {
            Self::AgentUnavailable => "Mesh Agent Unreachable",
            Self::ServiceStopped => "Windows Service Stopped / Not Installed",
            Self::NotEnrolled => "Set Up Mesh VPN",
            Self::Connecting => "Connecting to Mesh Network...",
            Self::Connected => match sub_state {
                TunnelSubState::Connected => "Connected to Mesh Network",
                TunnelSubState::Degraded => "Connected (Degraded: Control Stream Offline)",
                TunnelSubState::Disconnected => "Disconnected (Enrolled — Ready to Reconnect)",
                TunnelSubState::Connecting => "Connecting to Mesh Network...",
                TunnelSubState::NotEnrolled => "Not Enrolled",
                TunnelSubState::ReauthRequired => "Node Key Expired — Re-auth Required",
                TunnelSubState::Revoked => "Node Revoked by Administrator",
            },
            Self::ReauthRequired => "Node Key Expired — Re-auth Required",
            Self::Revoked => "Node Revoked — Identity Reset Required",
            Self::ErrorRecoverable => "Action Failed (Recoverable)",
        }
    }

    /// Returns a short tray tooltip summary (well under the Win32 128-UTF-16 limit).
    #[must_use]
    pub(crate) const fn tray_tooltip_summary(self, sub_state: TunnelSubState) -> &'static str {
        match self {
            Self::AgentUnavailable => "Mesh VPN - Agent Unavailable",
            Self::ServiceStopped => "Mesh VPN - Service Stopped",
            Self::NotEnrolled => "Mesh VPN - Not Enrolled",
            Self::Connecting => "Mesh VPN - Connecting...",
            Self::Connected => match sub_state {
                TunnelSubState::Connected => "Mesh VPN - Connected",
                TunnelSubState::Degraded => "Mesh VPN - Degraded (Control Offline)",
                TunnelSubState::Disconnected => "Mesh VPN - Disconnected",
                TunnelSubState::Connecting => "Mesh VPN - Connecting...",
                TunnelSubState::NotEnrolled => "Mesh VPN - Not Enrolled",
                TunnelSubState::ReauthRequired => "Mesh VPN - Re-auth Required",
                TunnelSubState::Revoked => "Mesh VPN - Node Revoked",
            },
            Self::ReauthRequired => "Mesh VPN - Re-auth Required",
            Self::Revoked => "Mesh VPN - Node Revoked",
            Self::ErrorRecoverable => "Mesh VPN - Attention Needed",
        }
    }
}

/// Fine-grained daemon tunnel sub-state mapped inside `DesktopUiState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TunnelSubState {
    NotEnrolled,
    Connecting,
    Connected,
    Degraded,
    Disconnected,
    ReauthRequired,
    Revoked,
}

/// Result of querying Win32 SCM for `MeshVpnAgent` (`OpenSCManagerW` + `QueryServiceStatusEx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ServiceProbeKind {
    Running,
    Stopped,
    NotInstalled,
    Unknown,
}

/// Comparison result between running `MeshVPN.exe` version and `meshd` `X-Mesh-Agent-Version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentVersionIndicator {
    Compatible(String),
    Mismatch {
        gui_version: String,
        agent_version: String,
    },
    LegacyPre030,
    Unknown,
}

/// Primary 3-Zone navigation tabs displayed whenever a node is enrolled (`ADR-028`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) enum DashboardTab {
    /// Zone 1: Status hero, tunnel telemetry, and primary connection CTAs.
    #[default]
    Status,
    /// Zone 2: Peer search, 4-state filter chips, RTT/ping, and Copy IP/FQDN.
    Peers,
    /// Zone 3: Theme/Language preferences, Netcheck, Bugreport, and Rotate/Update modals.
    DiagnosticsSettings,
}

/// Evaluates whether the 3-Tab Navigation bar (`Status / Peers / Diagnostics & Settings`)
/// must be displayed (`ADR-028`).
///
/// Always visible when `enrolled == true`, regardless of `DesktopUiState` (including
/// `ReauthRequired`, `Revoked`, `ErrorRecoverable`, `Connecting`, and `Connected`).
#[must_use]
pub(crate) const fn show_tab_bar(enrolled: bool, _ui_state: DesktopUiState) -> bool {
    enrolled
}

/// Derived snapshot rendered by both Dashboard window and System Tray menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DerivedUiSnapshot {
    pub(crate) ui_state: DesktopUiState,
    pub(crate) tunnel_sub_state: TunnelSubState,
    pub(crate) version_indicator: AgentVersionIndicator,
    pub(crate) enrolled: bool,
    pub(crate) recoverable_error: Option<String>,
    pub(crate) legacy_banner: Option<String>,
    pub(crate) version_mismatch_banner: Option<String>,
}

impl DerivedUiSnapshot {
    /// Returns `true` when the 3-Tab Navigation bar must remain visible (`ADR-028`).
    #[must_use]
    pub(crate) const fn should_show_tab_bar(&self) -> bool {
        show_tab_bar(self.enrolled, self.ui_state)
    }

    /// Returns `true` when the standalone onboarding form should be shown (`ADR-028`).
    ///
    /// Hidden completely whenever `self.enrolled == true`.
    #[must_use]
    pub(crate) const fn should_show_onboarding_form(&self) -> bool {
        !self.enrolled
            && !matches!(
                self.ui_state,
                DesktopUiState::AgentUnavailable | DesktopUiState::ServiceStopped
            )
    }
}

/// Classifies `AgentVersionStatus` returned from `meshd-ro` against `gui_version` (`ADR-022`).
#[must_use]
pub(crate) fn derive_version_indicator(
    gui_version: &str,
    status: Option<&AgentVersionStatus>,
) -> AgentVersionIndicator {
    match status {
        None => AgentVersionIndicator::Unknown,
        Some(AgentVersionStatus::LegacyPre030) => AgentVersionIndicator::LegacyPre030,
        Some(AgentVersionStatus::Version(agent_ver)) => {
            if agent_ver.trim() == gui_version.trim() {
                AgentVersionIndicator::Compatible(agent_ver.clone())
            } else {
                AgentVersionIndicator::Mismatch {
                    gui_version: gui_version.to_owned(),
                    agent_version: agent_ver.clone(),
                }
            }
        }
    }
}

/// Evaluates whether `AgentStatusResponse` represents an already-enrolled node whose cached
/// Control endpoint/keys allow 1-click reconnect (`preauth_key: None`).
#[must_use]
pub(crate) fn is_status_enrolled(status: &AgentStatusResponse) -> bool {
    status.overlay_ip.is_some()
        || status.node_id.is_some()
        || status
            .server_connection
            .as_ref()
            .is_some_and(|s| !s.control_endpoint.trim().is_empty())
}

/// Probe inputs passed to [`derive_desktop_ui_state`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct StateProbeInputs<'a> {
    pub(crate) gui_version: &'a str,
    pub(crate) service_probe: ServiceProbeKind,
    pub(crate) ipc_connected: bool,
    pub(crate) status: Option<&'a AgentStatusResponse>,
    pub(crate) version_status: Option<&'a AgentVersionStatus>,
    pub(crate) ipc_error: Option<&'a str>,
    pub(crate) active_action_error: Option<&'a str>,
}

/// Derives the authoritative 8-state `DesktopUiState` snapshot from the latest probe inputs.
#[must_use]
pub(crate) fn derive_desktop_ui_state(inputs: StateProbeInputs<'_>) -> DerivedUiSnapshot {
    let StateProbeInputs {
        gui_version,
        service_probe,
        ipc_connected,
        status,
        version_status,
        ipc_error,
        active_action_error,
    } = inputs;
    let version_indicator = derive_version_indicator(gui_version, version_status);
    let legacy_banner = match &version_indicator {
        AgentVersionIndicator::LegacyPre030 => Some(
            "Incompatible legacy agent (< 0.3.0) detected. Click 'Fix & Update Service (UAC)'."
                .to_owned(),
        ),
        _ => None,
    };
    let version_mismatch_banner = match &version_indicator {
        AgentVersionIndicator::Mismatch {
            gui_version,
            agent_version,
        } => Some(format!(
            "Version mismatch: GUI {gui_version} vs Agent {agent_version}. Update recommended."
        )),
        _ => None,
    };

    if !ipc_connected || status.is_none() {
        let ui_state = match service_probe {
            ServiceProbeKind::Stopped | ServiceProbeKind::NotInstalled => {
                DesktopUiState::ServiceStopped
            }
            ServiceProbeKind::Running | ServiceProbeKind::Unknown => {
                DesktopUiState::AgentUnavailable
            }
        };
        let combined_err = active_action_error
            .or(ipc_error)
            .map(format_user_facing_error);
        return DerivedUiSnapshot {
            ui_state,
            tunnel_sub_state: TunnelSubState::NotEnrolled,
            version_indicator,
            enrolled: false,
            recoverable_error: combined_err,
            legacy_banner,
            version_mismatch_banner,
        };
    }

    let Some(st) = status else {
        return DerivedUiSnapshot {
            ui_state: DesktopUiState::AgentUnavailable,
            tunnel_sub_state: TunnelSubState::NotEnrolled,
            version_indicator,
            enrolled: false,
            recoverable_error: active_action_error.map(format_user_facing_error),
            legacy_banner,
            version_mismatch_banner,
        };
    };

    let enrolled = is_status_enrolled(st);
    let last_err = st
        .server_connection
        .as_ref()
        .and_then(|s| s.last_error.as_deref())
        .map(str::trim);
    let server_error = last_err
        .filter(|s| !s.is_empty())
        .map(format_user_facing_error);
    let action_error = active_action_error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(format_user_facing_error);

    let (tunnel_sub_state, base_ui_state) = match st.daemon_state {
        DaemonState::Connected => (TunnelSubState::Connected, DesktopUiState::Connected),
        DaemonState::Degraded => (TunnelSubState::Degraded, DesktopUiState::Connected),
        DaemonState::Connecting => (TunnelSubState::Connecting, DesktopUiState::Connecting),
        DaemonState::ReauthRequired => (
            TunnelSubState::ReauthRequired,
            DesktopUiState::ReauthRequired,
        ),
        DaemonState::Revoked => (TunnelSubState::Revoked, DesktopUiState::Revoked),
        DaemonState::Stopped => {
            if enrolled {
                (TunnelSubState::Disconnected, DesktopUiState::Connected)
            } else {
                (TunnelSubState::NotEnrolled, DesktopUiState::NotEnrolled)
            }
        }
    };

    let recoverable_error = action_error.or(server_error);
    let ui_state = match base_ui_state {
        DesktopUiState::ReauthRequired | DesktopUiState::Revoked => base_ui_state,
        _ => {
            if active_action_error.is_some()
                || (st.daemon_state == DaemonState::Stopped && recoverable_error.is_some())
            {
                DesktopUiState::ErrorRecoverable
            } else {
                base_ui_state
            }
        }
    };

    DerivedUiSnapshot {
        ui_state,
        tunnel_sub_state,
        version_indicator,
        enrolled,
        recoverable_error,
        legacy_banner,
        version_mismatch_banner,
    }
}

/// Redacts sensitive Pre-Auth Key patterns and URIs before logging or UI display (`SEC-01`).
#[must_use]
pub(crate) fn sanitize_gui_log_text(input: &str) -> String {
    let mut out = input.to_owned();
    for marker in [
        "\"preauth_key\":\"",
        "\"preauth_key\": \"",
        "preauth_key=",
        "preauth=",
        "mesh://",
        "mpk_",
        "mesh_pak_",
    ] {
        let mut search_from = 0usize;
        while let Some(rel) = out.get(search_from..).and_then(|s| s.find(marker)) {
            let pos = search_from + rel;
            let prefix_end = pos + marker.len();
            let rest = out.get(prefix_end..).unwrap_or("");
            let value_len = rest
                .find(|c: char| {
                    c.is_whitespace()
                        || matches!(c, '"' | '\'' | ',' | '}')
                        || (marker != "mesh://" && c == '&')
                })
                .unwrap_or(rest.len());
            let mut replacement = String::new();
            let mut extra_skip = 0usize;
            if marker.starts_with("\"preauth_key\"") {
                replacement.push_str("\"preauth_key\":\"[REDACTED]\"");
                if out
                    .get(prefix_end + value_len..)
                    .is_some_and(|after| after.starts_with('"'))
                {
                    extra_skip = 1;
                }
            } else if marker == "mesh://" {
                replacement.push_str("mesh://[REDACTED]");
            } else {
                replacement.push_str(marker);
                replacement.push_str("[REDACTED]");
            }

            let end_of_secret = (prefix_end + value_len + extra_skip).min(out.len());
            out.replace_range(pos..end_of_secret, &replacement);
            search_from = pos + replacement.len();
        }
    }
    out
}

/// Formats errors for UI display, preserving `"authentication failed"` verbatim (`SEC-05`)
/// and sanitizing secret material (`SEC-01`).
#[must_use]
pub(crate) fn format_user_facing_error(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("authentication failed") || lower.contains("unauthenticated") {
        return "authentication failed".to_owned();
    }
    if lower.contains("uac") && lower.contains("cancel") {
        return "Elevation cancelled by user. Privileged action was not performed.".to_owned();
    }
    sanitize_gui_log_text(raw.trim())
}

/// Computes `<local_data_dir>/MeshVPN/logs` when a local app-data base directory is provided.
#[cfg(any(target_os = "windows", target_os = "linux"))]
#[must_use]
pub(crate) fn gui_log_directory(local_app_data: Option<&Path>) -> Option<PathBuf> {
    local_app_data
        .filter(|p| !p.as_os_str().is_empty())
        .map(|base| base.join(GUI_APP_DATA_DIR_NAME).join(GUI_LOG_SUBDIR))
}

#[cfg(test)]
mod tests {
    use super::{
        DashboardTab, DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState,
        derive_desktop_ui_state, show_tab_bar,
    };

    #[test]
    fn test_app_display_label_and_tab_bar_invariants() {
        // Arrange
        let tabs = [
            DashboardTab::Status,
            DashboardTab::Peers,
            DashboardTab::DiagnosticsSettings,
        ];
        let probes = [
            ServiceProbeKind::Running,
            ServiceProbeKind::Stopped,
            ServiceProbeKind::NotInstalled,
            ServiceProbeKind::Unknown,
        ];

        // Act & Assert
        assert_eq!(tabs.len(), 3);
        assert_eq!(probes.len(), 4);
        assert_eq!(
            DesktopUiState::Connected.display_label(TunnelSubState::Disconnected),
            "Disconnected"
        );
        assert_eq!(
            DesktopUiState::Connected.display_label(TunnelSubState::Revoked),
            "Device Revoked"
        );
        assert_eq!(
            DesktopUiState::ErrorRecoverable.display_label(TunnelSubState::Disconnected),
            "Attention Required"
        );
        assert!(show_tab_bar(true, DesktopUiState::ReauthRequired));
        assert!(!show_tab_bar(false, DesktopUiState::NotEnrolled));
        assert!(
            DesktopUiState::Connected
                .headline(TunnelSubState::Connected)
                .contains("Connected")
        );
        assert!(
            DesktopUiState::Connected
                .tray_tooltip_summary(TunnelSubState::Connected)
                .contains("Connected")
        );

        let snap = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.4.0",
            service_probe: ServiceProbeKind::Stopped,
            ipc_connected: false,
            status: None,
            version_status: None,
            ipc_error: None,
            active_action_error: None,
        });
        assert!(!snap.should_show_tab_bar());
        assert!(!snap.should_show_onboarding_form());

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            let dir = super::gui_log_directory(Some(std::path::Path::new("local")));
            assert!(dir.is_some());
        }
    }
}
