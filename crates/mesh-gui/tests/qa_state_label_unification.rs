//! Cross-Platform State Label Unification, 3-Way Locale Selector Integration, SEC-05/OPS-01
//! Invariants, Notification Semantic Colors & Tablet 600dp Adaptive Layout QA Suite
//! (`WP-U-D0`, `US-131`, `US-132`, `US-137`, `US-138`, `ADR-029`, `ADR-030`).

#[path = "../src/app.rs"]
mod app;
#[path = "../src/i18n.rs"]
mod i18n;

use std::fs;
use std::path::{Path, PathBuf};

use mesh_core::AppError;

use crate::app::{DesktopUiState, TunnelSubState, format_user_facing_error};
use crate::i18n::{LocaleMode, t_for};

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed resolving workspace root".to_owned())
}

fn read_repo_file(rel_path: &str) -> Result<String, String> {
    let root = workspace_root()?;
    let full = root.join(rel_path);
    fs::read_to_string(&full).map_err(|err| format!("failed reading {}: {err}", full.display()))
}

#[test]
fn test_display_label_revoked_device_revoked() {
    // Arrange & Act & Assert (`US-132`, `ADR-030`)
    assert_eq!(
        DesktopUiState::Revoked.display_label(TunnelSubState::Revoked),
        "Device Revoked"
    );
    assert_eq!(
        DesktopUiState::Revoked.display_label(TunnelSubState::Disconnected),
        "Device Revoked"
    );
    assert_eq!(
        DesktopUiState::Connected.display_label(TunnelSubState::Revoked),
        "Device Revoked"
    );
    assert_eq!(t_for("state.revoked", LocaleMode::En), "Device Revoked");
    assert_eq!(
        t_for("state.revoked", LocaleMode::Vi),
        "Thiết bị bị thu hồi"
    );
}

#[test]
fn test_display_label_error_attention_required() {
    // Arrange & Act & Assert (`US-132`, `ADR-030`)
    assert_eq!(
        DesktopUiState::ErrorRecoverable.display_label(TunnelSubState::Disconnected),
        "Attention Required"
    );
    assert_eq!(
        DesktopUiState::ErrorRecoverable.display_label(TunnelSubState::NotEnrolled),
        "Attention Required"
    );
    assert_eq!(t_for("state.error", LocaleMode::En), "Attention Required");
    assert_eq!(t_for("state.error", LocaleMode::Vi), "Cần xử lý");
}

#[test]
fn test_label_still_accessible_for_linux_gui() -> Result<(), String> {
    // Arrange
    let linux_gui = read_repo_file("crates/mesh-gui/src/linux_gui.rs")?;

    // Act & Assert: `DesktopUiState::label()` preserved unchanged for `linux_gui.rs`
    assert_eq!(
        DesktopUiState::AgentUnavailable.label(),
        "Agent Unavailable"
    );
    assert_eq!(DesktopUiState::ServiceStopped.label(), "Service Stopped");
    assert_eq!(DesktopUiState::NotEnrolled.label(), "Not Enrolled");
    assert_eq!(DesktopUiState::Connecting.label(), "Connecting");
    assert_eq!(DesktopUiState::Connected.label(), "Enrolled");
    assert_eq!(DesktopUiState::ReauthRequired.label(), "Re-auth Required");
    assert_eq!(DesktopUiState::Revoked.label(), "Revoked");
    assert_eq!(
        DesktopUiState::ErrorRecoverable.label(),
        "Error (Recoverable)"
    );
    assert!(linux_gui.contains(".label()"));

    Ok(())
}

#[test]
fn test_state_label_unified_8_states_windows_macos() -> Result<(), String> {
    // Arrange: canonical 8-state English labels shared between Windows and macOS (`ADR-030`)
    let macos_state_swift = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/DesktopUiState.swift",
    )?;
    let pairs = [
        (
            DesktopUiState::AgentUnavailable,
            TunnelSubState::NotEnrolled,
            "case .serviceNotInstalled: return \"Agent Unavailable\"",
            "Agent Unavailable",
        ),
        (
            DesktopUiState::ServiceStopped,
            TunnelSubState::NotEnrolled,
            "case .serviceStopped: return \"Service Stopped\"",
            "Service Stopped",
        ),
        (
            DesktopUiState::NotEnrolled,
            TunnelSubState::NotEnrolled,
            "case .unconfigured: return \"Not Enrolled\"",
            "Not Enrolled",
        ),
        (
            DesktopUiState::Connecting,
            TunnelSubState::Connecting,
            "case .connecting: return \"Connecting\"",
            "Connecting",
        ),
        (
            DesktopUiState::Connected,
            TunnelSubState::Connected,
            "case .connected: return \"Connected\"",
            "Connected",
        ),
        (
            DesktopUiState::ReauthRequired,
            TunnelSubState::ReauthRequired,
            "case .reauthRequired: return \"Re-auth Required\"",
            "Re-auth Required",
        ),
        (
            DesktopUiState::Revoked,
            TunnelSubState::Revoked,
            "case .revoked: return \"Device Revoked\"",
            "Device Revoked",
        ),
        (
            DesktopUiState::ErrorRecoverable,
            TunnelSubState::Disconnected,
            "case .error: return \"Attention Required\"",
            "Attention Required",
        ),
    ];

    // Act & Assert
    for (win_state, sub_state, macos_case_line, canonical_label) in pairs {
        assert_eq!(
            win_state.display_label(sub_state),
            canonical_label,
            "Windows display_label mismatch for {win_state:?}"
        );
        assert!(
            macos_state_swift.contains(macos_case_line),
            "macOS DesktopUiState.swift missing unified case `{macos_case_line}`"
        );
    }
    assert_eq!(
        DesktopUiState::Connected.display_label(TunnelSubState::Degraded),
        "Degraded"
    );
    assert_eq!(
        DesktopUiState::Connected.display_label(TunnelSubState::Disconnected),
        "Disconnected"
    );
    assert!(!macos_state_swift.contains("Key Rotation Required"));
    assert!(!macos_state_swift.contains("Service Not Installed"));

    Ok(())
}

#[test]
fn test_android_canonical_label_not_raw_enum() -> Result<(), String> {
    // Arrange
    let status_kt = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/status/StatusScreen.kt",
    )?;

    // Act & Assert: no raw `${session.daemonState.name}` print; all 8 states map via R.string.*
    assert!(!status_kt.contains("daemonState.name"));
    assert!(status_kt.contains("fun daemonStateLabelRes(state: MobileDaemonState): Int"));
    for res_id in [
        "R.string.state_disconnected",
        "R.string.notif_waiting_unlock",
        "R.string.state_connecting",
        "R.string.state_connected",
        "R.string.state_degraded",
        "R.string.state_reauth_required",
        "R.string.state_revoked",
        "R.string.state_error",
    ] {
        assert!(
            status_kt.contains(res_id),
            "Android StatusScreen.kt missing canonical resource mapping `{res_id}`"
        );
    }
    for canonical in [
        "\"Disconnected\"",
        "\"Waiting for Unlock\"",
        "\"Connecting\"",
        "\"Connected\"",
        "\"Degraded\"",
        "\"Re-auth Required\"",
        "\"Device Revoked\"",
        "\"Attention Required\"",
    ] {
        assert!(
            status_kt.contains(canonical),
            "Android StatusScreen.kt missing canonical label {canonical}"
        );
    }
    assert!(status_kt.contains("testTag(\"daemon_state_label\")"));

    Ok(())
}

#[test]
fn test_locale_selector_all_platforms() -> Result<(), String> {
    // Arrange
    let win_window = read_repo_file("crates/mesh-gui/src/window.rs")?;
    let mac_diag = read_repo_file("desktop/macos/MeshVPNApp/Sources/DiagnosticsSheetView.swift")?;
    let mac_l10n =
        read_repo_file("desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/MeshL10n.swift")?;
    let android_settings = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/settings/SettingsScreen.kt",
    )?;
    let android_locale =
        read_repo_file("mobile/android/app/src/main/kotlin/dev/meshvpn/android/LocaleHelper.kt")?;
    let ios_settings = read_repo_file("mobile/ios/MeshApp/Sources/SettingsView.swift")?;
    let ios_l10n = read_repo_file("mobile/ios/MeshApp/Sources/LocaleManager.swift")?;

    // Act & Assert: Windows 3-way locale selector + live switch
    assert!(win_window.contains("IDC_BTN_LOCALE_SYSTEM"));
    assert!(win_window.contains("IDC_BTN_LOCALE_VI"));
    assert!(win_window.contains("IDC_BTN_LOCALE_EN"));
    assert!(win_window.contains("apply_localized_control_texts(&st.controls)"));
    assert_eq!(t_for("locale.system", LocaleMode::Vi), "Hệ thống");
    assert_eq!(t_for("locale.vietnamese", LocaleMode::Vi), "Tiếng Việt");
    assert_eq!(t_for("locale.english", LocaleMode::Vi), "English");

    // macOS 3-way locale selector + `mesh_locale_mode` persistence
    assert!(mac_diag.contains("AppearanceAndLocaleSection"));
    assert!(mac_diag.contains("$localeManager.mode"));
    assert!(mac_l10n.contains("mesh_locale_mode"));

    // Android 3-way locale selector + `testTag("locale_selector")` + `mesh_locale_mode`
    assert!(android_settings.contains("testTag(\"locale_selector\")"));
    assert!(android_settings.contains("locale_option_system"));
    assert!(android_settings.contains("locale_option_vi"));
    assert!(android_settings.contains("locale_option_en"));
    assert!(android_locale.contains("mesh_locale_mode"));
    assert!(android_locale.contains("createConfigurationContext"));

    // iOS 3-way locale selector + `mesh_locale_mode` + iOS 15 `Locale(identifier:)`
    assert!(ios_settings.contains("$localeManager.localeMode"));
    assert!(ios_settings.contains("[LocaleMode.system, .vi, .en]"));
    assert!(ios_l10n.contains("mesh_locale_mode"));
    assert!(!ios_l10n.contains("Locale(\"vi\")"));
    assert!(!ios_l10n.contains("Bundle.module"));

    Ok(())
}

#[test]
fn test_sec05_ops01_invariant_locale_vi() -> Result<(), String> {
    // Arrange: wire auth error & OPS-01 English log checks across all 4 platforms
    let mac_vi = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Resources/vi.lproj/Localizable.strings",
    )?;
    let android_vi = read_repo_file("mobile/android/app/src/main/res/values-vi/strings.xml")?;
    let ios_xcstrings = read_repo_file("mobile/ios/MeshApp/Resources/Localizable.xcstrings")?;
    let win_window = read_repo_file("crates/mesh-gui/src/window.rs")?;

    // Act
    let win_vi_auth = t_for("error.auth_failed", LocaleMode::Vi);
    let win_en_auth = t_for("error.auth_failed", LocaleMode::En);
    let wire_err = AppError::unauthenticated("token expired").to_string();
    let formatted_err = format_user_facing_error(&wire_err);

    // Assert (`SEC-05`): `"authentication failed"` MUST remain untranslated English on all 4 OSes
    assert_eq!(win_en_auth, "authentication failed");
    assert_eq!(win_vi_auth, "authentication failed");
    assert_eq!(wire_err, "authentication failed");
    assert_eq!(formatted_err, "authentication failed");
    assert!(mac_vi.contains("\"error.auth_failed\" = \"authentication failed\";"));
    assert!(
        android_vi.contains("<string name=\"error_auth_failed\">authentication failed</string>")
    );
    assert!(ios_xcstrings.contains("\"error.auth_failed\""));
    assert!(ios_xcstrings.contains("\"value\": \"authentication failed\""));

    // Assert (`OPS-01`): structured log events in `window.rs` stay English (never via `t(...)`)
    assert!(win_window.contains("event = \"ui_locale_changed\""));
    assert!(win_window.contains("event = \"ui_state_changed\""));
    assert!(!win_window.contains("event = t("));

    Ok(())
}

#[test]
fn test_tablet_layout_breakpoint_600dp() -> Result<(), String> {
    // Arrange
    let android_peers = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/peers/PeersScreen.kt",
    )?;
    let ios_peers = read_repo_file("mobile/ios/MeshApp/Sources/PeersView.swift")?;

    // Act & Assert: Android adaptive 2-column LazyVerticalGrid at >= 600 dp + preserved testTags
    assert!(android_peers.contains("TABLET_LAYOUT_BREAKPOINT_DP = 600"));
    assert!(android_peers.contains("fun peersGridColumnCount(screenWidthDp: Int): Int"));
    assert!(android_peers.contains("LocalConfiguration.current.screenWidthDp"));
    assert!(android_peers.contains("LazyVerticalGrid("));
    assert!(android_peers.contains("GridCells.Fixed(columnCount)"));
    for tag in [
        "peers_search_field",
        "peers_filter_all",
        "peers_filter_online",
        "peers_filter_direct",
        "peers_filter_relay",
        "peers_copy_ip_button",
        "peers_copy_fqdn_button",
    ] {
        assert!(
            android_peers.contains(tag),
            "Android PeersScreen.kt missing required testTag `{tag}`"
        );
    }

    // Assert: iOS adaptive 2-column LazyVGrid for `.regular` horizontalSizeClass
    assert!(ios_peers.contains("@Environment(\\.horizontalSizeClass)"));
    assert!(ios_peers.contains("enum PeersAdaptiveLayout"));
    assert!(ios_peers.contains("sizeClass == .regular ? 2 : 1"));
    assert!(ios_peers.contains("LazyVGrid(columns: gridColumns"));

    Ok(())
}

#[test]
fn test_notification_badge_semantic_colors_cross_platform() -> Result<(), String> {
    // Arrange
    let android_vpn = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/vpn/MeshVpnService.kt",
    )?;
    let ios_status = read_repo_file("mobile/ios/MeshApp/Sources/StatusTab.swift")?;
    let mac_state = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/DesktopUiState.swift",
    )?;

    // Act & Assert (`US-137`, `ADR-030`): semantic colors match across Android, iOS, macOS
    assert!(android_vpn.contains(".setColor(notificationColorForState(uiState.daemonState))"));
    assert!(android_vpn.contains("0xFF16A34A"));
    assert!(android_vpn.contains("0xFFD97706"));
    assert!(android_vpn.contains("0xFFDC2626"));
    assert!(android_vpn.contains("0xFF6B7280"));

    assert!(ios_status.contains("public struct StatusBadge: View"));
    assert!(ios_status.contains("case .reauthRequired:"));
    assert!(ios_status.contains("tone: .warning"));

    assert!(mac_state.contains("case .connectingOrDegraded, .reauthRequired: return .warning"));
    assert!(mac_state.contains("semanticWarningLight = \"#D97706\""));

    Ok(())
}
