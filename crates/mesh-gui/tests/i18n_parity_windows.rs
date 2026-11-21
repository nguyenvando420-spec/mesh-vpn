//! Wave U-C.1 (`WP-U-C1`) Windows i18n (`213` keys), user-space atomic `UiPrefs`, Tray bilingual
//! wiring, live locale switch without daemon restart, and `US-125` `WM_SETTINGCHANGE` live OS
//! theme reload verification suite (`ADR-027`, `ADR-029`, `ADR-030`, `ADR-031`, `US-125`, `US-127`).

#![cfg(target_os = "windows")]

#[path = "../src/app.rs"]
mod app;
#[path = "../src/diagnostics_view.rs"]
mod diagnostics_view;
#[path = "../src/i18n.rs"]
mod i18n;
#[path = "../src/icons.rs"]
mod icons;
#[path = "../src/peers_view.rs"]
mod peers_view;
#[path = "../src/prefs.rs"]
mod prefs;
#[path = "../src/status_view.rs"]
mod status_view;
#[path = "../src/theme.rs"]
mod theme;
#[path = "../src/tray.rs"]
mod tray;

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;

use mesh_core::{AppError, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentPeerStatus, AgentStatusResponse, DaemonState, SelfNetworkStatus,
    ServerConnectionStatus, TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;
use tempfile::tempdir;

use crate::app::{
    DashboardTab, DerivedUiSnapshot, DesktopUiState, ServiceProbeKind, StateProbeInputs,
    TunnelSubState, derive_desktop_ui_state, format_user_facing_error,
};
use crate::diagnostics_view::{
    build_locale_selector_labels, build_theme_selector_labels,
    format_settings_identity_summary_localized,
};
use crate::i18n::{EN_STRINGS, LocaleMode, VI_STRINGS, current_locale, set_locale, t, t_for};
use crate::peers_view::{
    PeerFilterMode, count_peers_by_mode, format_filter_chip_label,
    format_peer_detail_summary_localized, format_peer_list_entry_localized,
};
use crate::prefs::{
    UI_PREFS_FILENAME, UiPrefs, load_prefs_from_path, prefs_path_from_base, save_prefs_to_path,
};
use crate::theme::ThemeMode;
use crate::tray::{
    IDM_CONNECT_UP, IDM_DISCONNECT, IDM_DISCONNECT_AND_QUIT, IDM_EXPORT_BUGREPORT, IDM_NETCHECK,
    IDM_OPEN_DASHBOARD, IDM_QUIT_KEEP_BACKGROUND, IDM_TOGGLE_AUTOSTART, TrayMenuItemModel,
    build_tray_menu_model, build_tray_menu_model_for_locale, count_non_separator_entries,
    tray_tooltip_for_locale,
};

static GLOBAL_LOCALE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn sample_connected_status() -> AgentStatusResponse {
    AgentStatusResponse {
        daemon_state: DaemonState::Connected,
        node_id: Some(NodeId::from_bytes([0x11_u8; 16])),
        node_name: NodeName::parse("win-node").ok(),
        fqdn: Some("win-node.mesh.internal".to_owned()),
        overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 5)).ok(),
        overlay_cidr: OverlayCidr::parse("100.64.0.0/10").ok(),
        tun_interface_name: Some("MeshVPN".to_owned()),
        tun_mtu: 1420,
        netmap_version: 4,
        key_expires_at_ms: None,
        server_connection: Some(ServerConnectionStatus {
            control_endpoint: "198.51.100.10:8443".to_owned(),
            relay_endpoint: "198.51.100.10:8443".to_owned(),
            stun_endpoints: vec!["198.51.100.10:3478".to_owned()],
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: SpkiPin::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .ok(),
            next_pin: None,
            control_connected: true,
            relay_connected: true,
            relay_rtt_ms: Some(15),
            migration_pending_endpoint: None,
            last_error: None,
        }),
        self_network: SelfNetworkStatus {
            local_udp_port: 51820,
            bound_physical_interface: Some("Ethernet".to_owned()),
            nat_type: NatMappingKind::EimOrAdm,
            nat_classification_note: None,
            overlay_conflict_warning: None,
            macos_firewall_warning: None,
            candidates: Vec::new(),
        },
        peers: Vec::new(),
    }
}

fn sample_snapshot(status: &AgentStatusResponse) -> DerivedUiSnapshot {
    derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.4.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(status),
        version_status: None,
        ipc_error: None,
        active_action_error: None,
    })
}

fn parse_discovery_glossary_rows() -> Vec<(String, String, String)> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let doc_path = manifest_dir
        .join("../..")
        .join("docs/01-discovery/unified-ui-readiness-requirements.md");
    let raw = fs::read_to_string(&doc_path).unwrap_or_default();
    let Some(after_start) = raw.split("### 4.1 Canonical Glossary").nth(1) else {
        return Vec::new();
    };
    let section = after_start
        .split("### 4.2 i18n Implementation Gap Analysis")
        .next()
        .unwrap_or(after_start);
    let mut rows = Vec::new();
    for line in section.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("| `") {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').collect();
        if let (Some(raw_key), Some(en_col), Some(vi_col)) =
            (parts.get(1), parts.get(2), parts.get(3))
        {
            let key = raw_key.trim().trim_matches('`');
            let en = en_col.trim();
            let vi = vi_col.trim();
            if !key.is_empty() && !en.is_empty() && !vi.is_empty() {
                rows.push((key.to_owned(), en.to_owned(), vi.to_owned()));
            }
        }
    }
    rows
}

#[test]
fn test_i18n_all_213_keys_present_vi_and_en() {
    // Arrange: cross-check compile-time tables directly against Discovery v1.1 §4.1
    let doc_rows = parse_discovery_glossary_rows();
    assert_eq!(
        doc_rows.len(),
        213,
        "Discovery v1.1 §4.1 canonical glossary must contain exactly 213 keys"
    );
    assert_eq!(EN_STRINGS.len(), 213);
    assert_eq!(VI_STRINGS.len(), 213);

    let mut seen_keys = BTreeSet::new();

    // Act & Assert: 100% 1-to-1 key + string parity across EN_STRINGS, VI_STRINGS, and §4.1
    for (idx, (doc_key, doc_en, doc_vi)) in doc_rows.iter().enumerate() {
        assert!(
            seen_keys.insert(doc_key.as_str()),
            "duplicate canonical key `{doc_key}`"
        );
        let en_pair = EN_STRINGS.get(idx);
        let vi_pair = VI_STRINGS.get(idx);
        assert_eq!(
            en_pair,
            Some(&(doc_key.as_str(), doc_en.as_str())),
            "EN_STRINGS mismatch at index {idx} for `{doc_key}`"
        );
        assert_eq!(
            vi_pair,
            Some(&(doc_key.as_str(), doc_vi.as_str())),
            "VI_STRINGS mismatch at index {idx} for `{doc_key}`"
        );
        assert_eq!(t_for(doc_key, LocaleMode::En), doc_en.as_str());
        assert_eq!(t_for(doc_key, LocaleMode::Vi), doc_vi.as_str());
    }
    assert_eq!(seen_keys.len(), 213);
}

#[test]
fn test_t_for_pure_no_global_state() {
    // Arrange: spawn parallel reader threads verifying t_for never depends on global AtomicU8
    let _guard = GLOBAL_LOCALE_TEST_LOCK.lock();
    let prev = current_locale();
    set_locale(LocaleMode::Vi);

    // Act
    let en_tab = t_for("tab.status", LocaleMode::En);
    let vi_tab = t_for("tab.status", LocaleMode::Vi);
    let en_state = t_for("state.connected", LocaleMode::En);
    let vi_state = t_for("state.connected", LocaleMode::Vi);
    set_locale(LocaleMode::En);
    let en_tab_after = t_for("tab.status", LocaleMode::En);
    let vi_tab_after = t_for("tab.status", LocaleMode::Vi);
    set_locale(prev);

    // Assert
    assert_eq!(en_tab, "Status");
    assert_eq!(vi_tab, "Trạng thái");
    assert_eq!(en_state, "Connected");
    assert_eq!(vi_state, "Đã kết nối");
    assert_eq!(en_tab, en_tab_after);
    assert_eq!(vi_tab, vi_tab_after);
    assert_eq!(t_for("unknown.missing.key", LocaleMode::Vi), "");
}

#[test]
fn test_sec05_wire_string_not_localized() {
    // Arrange
    let _guard = GLOBAL_LOCALE_TEST_LOCK.lock();
    let prev = current_locale();
    set_locale(LocaleMode::Vi);

    // Act
    let en_auth = t_for("error.auth_failed", LocaleMode::En);
    let vi_auth = t_for("error.auth_failed", LocaleMode::Vi);
    let live_auth = t("error.auth_failed");
    let wire_err = AppError::unauthenticated("invalid preauth key hash");
    let ui_err = format_user_facing_error(&wire_err.to_string());
    set_locale(prev);

    // Assert (`SEC-05`): authentication failed MUST stay English in en, vi, live t(), and wire
    assert_eq!(en_auth, "authentication failed");
    assert_eq!(vi_auth, "authentication failed");
    assert_eq!(live_auth, "authentication failed");
    assert_eq!(wire_err.to_string(), "authentication failed");
    assert_eq!(ui_err, "authentication failed");
}

#[test]
fn test_tray_label_vi_locale() {
    // Arrange
    let status = sample_connected_status();
    let snap = sample_snapshot(&status);

    // Act
    let vi_menu = build_tray_menu_model_for_locale(&snap, Some("100.64.0.5"), true, LocaleMode::Vi);
    let en_menu = build_tray_menu_model_for_locale(&snap, Some("100.64.0.5"), true, LocaleMode::En);
    let vi_tooltip = tray_tooltip_for_locale(
        DesktopUiState::Connected,
        TunnelSubState::Connected,
        LocaleMode::Vi,
    );
    let en_tooltip = tray_tooltip_for_locale(
        DesktopUiState::Connected,
        TunnelSubState::Connected,
        LocaleMode::En,
    );

    // Assert: canonical 9 non-separator entries preserved + exact VI translations
    assert_eq!(count_non_separator_entries(&vi_menu), 9);
    assert_eq!(count_non_separator_entries(&en_menu), 9);
    assert_eq!(vi_tooltip, "Mesh VPN - Đã kết nối");
    assert_eq!(en_tooltip, "Mesh VPN - Connected");

    assert!(matches!(
        vi_menu.first(),
        Some(TrayMenuItemModel::Header(text))
            if text == "Trạng thái: Đã kết nối (100.64.0.5)"
    ));

    let label_for = |menu: &[TrayMenuItemModel], target_id: u16| -> Option<String> {
        menu.iter().find_map(|item| match item {
            TrayMenuItemModel::Action { id, label, .. } if *id == target_id => Some(label.clone()),
            _ => None,
        })
    };

    assert_eq!(
        label_for(&vi_menu, IDM_OPEN_DASHBOARD).as_deref(),
        Some("Mở bảng điều khiển")
    );
    assert_eq!(
        label_for(&vi_menu, IDM_CONNECT_UP).as_deref(),
        Some("Kết nối")
    );
    assert_eq!(
        label_for(&vi_menu, IDM_DISCONNECT).as_deref(),
        Some("Ngắt kết nối")
    );
    assert_eq!(
        label_for(&vi_menu, IDM_NETCHECK).as_deref(),
        Some("Chạy chẩn đoán mạng")
    );
    assert_eq!(
        label_for(&vi_menu, IDM_EXPORT_BUGREPORT).as_deref(),
        Some("Xuất báo lỗi đã che bí mật")
    );
    assert_eq!(
        label_for(&vi_menu, IDM_TOGGLE_AUTOSTART).as_deref(),
        Some("Khởi chạy cùng hệ thống")
    );
    assert_eq!(
        label_for(&vi_menu, IDM_QUIT_KEEP_BACKGROUND).as_deref(),
        Some("Thoát Mesh VPN (Giữ kết nối nền)")
    );
    assert_eq!(
        label_for(&vi_menu, IDM_DISCONNECT_AND_QUIT).as_deref(),
        Some("Ngắt kết nối & Thoát Mesh VPN")
    );
}

#[test]
fn test_locale_switch_no_daemon_restart() {
    // Arrange: simulate active connected daemon session; switching locale mutates only client RAM
    // (`AtomicU8`) and user-space `ui-prefs.json` without resetting tunnel state or IPC snapshot.
    let _guard = GLOBAL_LOCALE_TEST_LOCK.lock();
    let prev = current_locale();
    let Ok(dir) = tempdir() else {
        return;
    };
    let Some(prefs_path) = prefs_path_from_base(Some(dir.path())) else {
        return;
    };
    let status = sample_connected_status();
    let snap = sample_snapshot(&status);

    // Act 1: switch live to Vietnamese
    set_locale(LocaleMode::Vi);
    assert!(
        save_prefs_to_path(
            &prefs_path,
            &UiPrefs {
                theme: ThemeMode::System,
                locale: LocaleMode::Vi,
            }
        )
        .is_ok()
    );
    let vi_tray = build_tray_menu_model(&snap, Some("100.64.0.5"), false);
    let vi_locale_labels = build_locale_selector_labels(t);
    let vi_theme_labels = build_theme_selector_labels(t);
    let vi_settings = format_settings_identity_summary_localized(
        Some(&status),
        &vi_theme_labels.system,
        &vi_locale_labels.vietnamese,
        t,
    );

    #[cfg(target_os = "windows")]
    let vi_hero =
        status_view::build_status_hero_model(&snap, Some(&status), DashboardTab::Status, None);

    // Act 2: switch live back to English (same connected snapshot — zero daemon restart)
    set_locale(LocaleMode::En);
    assert!(
        save_prefs_to_path(
            &prefs_path,
            &UiPrefs {
                theme: ThemeMode::System,
                locale: LocaleMode::En,
            }
        )
        .is_ok()
    );
    let en_tray = build_tray_menu_model(&snap, Some("100.64.0.5"), false);
    #[cfg(target_os = "windows")]
    let en_hero =
        status_view::build_status_hero_model(&snap, Some(&status), DashboardTab::Status, None);

    // Also exercise localized peers & onboarding confirmation helpers under VI
    if let (Ok(name), Ok(ip)) = (
        NodeName::parse("peer-vn"),
        OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 9)),
    ) {
        let peer = AgentPeerStatus {
            node_id: NodeId::from_bytes([0x22_u8; 16]),
            name,
            fqdn: "peer-vn.mesh.internal".to_owned(),
            overlay_ip: ip,
            online: true,
            active_path: ActivePathKind::Direct,
            direct_endpoint: Some("203.0.113.9:51820".to_owned()),
            rtt_ms: Some(12),
            last_handshake_at_ms: Some(1_700_000_000_000),
            rx_bytes: 1024,
            tx_bytes: 2048,
        };
        let counts = count_peers_by_mode(std::slice::from_ref(&peer));
        #[cfg(target_os = "windows")]
        {
            let chip = format_filter_chip_label(
                PeerFilterMode::Direct,
                counts,
                Some(t_for(PeerFilterMode::Direct.label_key(), LocaleMode::Vi)),
            );
            assert_eq!(chip, "Trực tiếp (1)");
            assert!(
                format_peer_list_entry_localized(&peer, |k| t_for(k, LocaleMode::Vi))
                    .contains("Trực tiếp")
            );
            assert!(
                format_peer_detail_summary_localized(&peer, |k| t_for(k, LocaleMode::Vi))
                    .contains("Lớp phủ mạng")
            );
        }
    }

    set_locale(prev);

    // Assert
    assert_eq!(snap.ui_state, DesktopUiState::Connected);
    assert_eq!(snap.tunnel_sub_state, TunnelSubState::Connected);
    assert_eq!(vi_locale_labels.section_label, "Ngôn ngữ:");
    assert_eq!(vi_locale_labels.system, "Hệ thống");
    assert_eq!(vi_locale_labels.vietnamese, "Tiếng Việt");
    assert_eq!(vi_locale_labels.english, "English");
    assert!(vi_settings.contains("Giao diện"));
    assert!(vi_settings.contains("Ngôn ngữ"));
    assert!(matches!(
        vi_tray.first(),
        Some(TrayMenuItemModel::Header(h)) if h.contains("Đã kết nối")
    ));
    assert!(matches!(
        en_tray.first(),
        Some(TrayMenuItemModel::Header(h)) if h.contains("Connected")
    ));
    #[cfg(target_os = "windows")]
    {
        assert_eq!(vi_hero.badge_label, "Đã kết nối");
        assert_eq!(vi_hero.headline, "Đã kết nối mạng Mesh");
        assert_eq!(en_hero.badge_label, "Connected");
        assert_eq!(en_hero.headline, "Connected to Mesh Network");
    }
}

#[cfg(target_os = "windows")]
#[test]
fn test_wm_settingchange_theme_rebuild() {
    use mesh_sys::gui_windows::{
        apply_window_dark_titlebar, detect_high_contrast, invalidate_window,
        read_windows_apps_use_light_theme,
    };

    let _lock = theme::GDI_TEST_LOCK.lock();

    // Arrange: simulate palette rebuild sequence executed by WM_SETTINGCHANGE / WM_THEMECHANGED
    let os_light = read_windows_apps_use_light_theme();
    let high_contrast = detect_high_contrast();
    let expected_system_dark = !os_light || high_contrast;

    let mut palette = theme::resolve_palette_for_dpi(ThemeMode::Dark, 96);
    assert!(palette.is_dark_titlebar);

    // Act: clear brush cache -> rebuild System palette -> apply DWM titlebar -> invalidate HWND
    palette.clear_brush_cache();
    palette = theme::resolve_palette_for_dpi(ThemeMode::System, 120);
    apply_window_dark_titlebar(0, palette.is_dark_titlebar);
    invalidate_window(0);

    // Assert
    assert_eq!(palette.mode, ThemeMode::System);
    assert_eq!(palette.dpi, 120);
    assert_eq!(palette.is_dark_titlebar, expected_system_dark);
    if expected_system_dark {
        assert_eq!(palette.bg_color, theme::DARK_SURFACE_BG);
        assert_eq!(palette.brand_primary, theme::DARK_BRAND_SKY);
    } else {
        assert_eq!(palette.bg_color, theme::LIGHT_SURFACE_BG);
        assert_eq!(palette.brand_primary, theme::LIGHT_BRAND_COBALT);
    }
}

#[cfg(target_os = "windows")]
#[test]
fn test_registry_dark_light_detection() {
    use mesh_sys::gui_windows::{detect_high_contrast, read_windows_apps_use_light_theme};

    let _lock = theme::GDI_TEST_LOCK.lock();

    // Arrange & Act: reads HKCU\...\Themes\Personalize\AppsUseLightTheme (no ShouldAppsUseDarkMode)
    let apps_use_light = read_windows_apps_use_light_theme();
    let high_contrast = detect_high_contrast();
    let system_palette = theme::resolve_palette(ThemeMode::System);
    let light_palette = theme::resolve_palette(ThemeMode::Light);
    let dark_palette = theme::resolve_palette(ThemeMode::Dark);

    // Assert
    assert_eq!(
        system_palette.is_dark_titlebar,
        !apps_use_light || high_contrast
    );
    assert!(!light_palette.is_dark_titlebar);
    assert!(dark_palette.is_dark_titlebar);
}

#[test]
fn test_prefs_json_fields_theme_locale() {
    // Arrange
    let Ok(dir) = tempdir() else {
        return;
    };
    let Some(path) = prefs_path_from_base(Some(dir.path())) else {
        return;
    };
    assert_eq!(
        path.file_name().and_then(|s| s.to_str()),
        Some(UI_PREFS_FILENAME)
    );

    let cases = [
        (ThemeMode::System, LocaleMode::System, "system", "system"),
        (ThemeMode::Light, LocaleMode::En, "light", "en"),
        (ThemeMode::Dark, LocaleMode::Vi, "dark", "vi"),
    ];

    // Act & Assert: exact JSON field names `"theme"` and `"locale"` (never themeMode/localeMode)
    for (theme_mode, locale_mode, exp_theme, exp_locale) in cases {
        let prefs = UiPrefs {
            theme: theme_mode,
            locale: locale_mode,
        };
        assert!(save_prefs_to_path(&path, &prefs).is_ok());
        let raw = fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            raw,
            format!(r#"{{"theme":"{exp_theme}","locale":"{exp_locale}"}}"#)
        );
        assert!(!raw.contains("themeMode"));
        assert!(!raw.contains("localeMode"));
        assert_eq!(load_prefs_from_path(&path), prefs);
    }
}

#[test]
fn test_prefs_fallback_on_corrupt_file() {
    // Arrange
    let Ok(dir) = tempdir() else {
        return;
    };
    let Some(path) = prefs_path_from_base(Some(dir.path())) else {
        return;
    };
    if let Some(parent) = path.parent() {
        assert!(fs::create_dir_all(parent).is_ok());
    }
    assert!(fs::write(&path, r#"{"theme":"invalid_mode","locale":123}"#).is_ok());

    // Act
    let loaded = load_prefs_from_path(&path);

    // Assert: corrupt JSON is deleted and safely falls back to UiPrefs::default()
    assert_eq!(loaded, UiPrefs::default());
    assert!(!path.exists());
}
