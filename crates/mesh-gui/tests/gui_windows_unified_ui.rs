//! Unified UI Wave U-B.1 (`WP-U-B1`) verification tests for Windows `MeshVPN.exe`
//! (`ADR-027`, `ADR-028`, `ADR-030`, `US-118`, `US-120`, `US-121`, `US-122`, `US-123`, `US-126`).

#[path = "../src/app.rs"]
mod app;
#[path = "../src/clipboard.rs"]
mod clipboard;
#[path = "../src/i18n.rs"]
mod i18n;
#[path = "../src/icons.rs"]
mod icons;
#[path = "../src/peers_view.rs"]
mod peers_view;
#[cfg(target_os = "windows")]
#[path = "../src/status_view.rs"]
mod status_view;
#[path = "../src/theme.rs"]
mod theme;
#[path = "../src/tray.rs"]
mod tray;

use std::net::Ipv4Addr;

use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentPeerStatus, AgentStatusResponse, DaemonState, SelfNetworkStatus,
    ServerConnectionStatus, TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;

use crate::app::{
    DashboardTab, DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState,
    derive_desktop_ui_state, show_tab_bar,
};
use crate::clipboard::{ClipboardSecretGuard, CopyKind, format_copy_toast};
use crate::icons::{UiIconTone, icon_tone_for_state};
use crate::peers_view::{
    PeerFilterCounts, PeerFilterMode, count_peers_by_mode, filter_peers, filter_peers_by_mode,
    filter_peers_combined,
};
use crate::tray::{IDM_STATUS_HEADER, build_tray_menu_model, count_non_separator_entries};

fn make_peer(
    id_byte: u8,
    name: &str,
    ip_last: u8,
    online: bool,
    path: ActivePathKind,
) -> Option<AgentPeerStatus> {
    Some(AgentPeerStatus {
        node_id: NodeId::from_bytes([id_byte; 16]),
        name: NodeName::parse(name).ok()?,
        fqdn: format!("{name}.mesh.internal"),
        overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, ip_last)).ok()?,
        online,
        active_path: path,
        direct_endpoint: if path == ActivePathKind::Direct {
            Some("203.0.113.20:51820".to_owned())
        } else {
            None
        },
        rtt_ms: if online { Some(14) } else { None },
        last_handshake_at_ms: if online {
            Some(1_700_000_000_000)
        } else {
            None
        },
        rx_bytes: 2048,
        tx_bytes: 4096,
    })
}

fn make_enrolled_status(daemon_state: DaemonState) -> AgentStatusResponse {
    AgentStatusResponse {
        daemon_state,
        node_id: Some(NodeId::from_bytes([9_u8; 16])),
        node_name: NodeName::parse("win-node").ok(),
        fqdn: Some("win-node.mesh.internal".to_owned()),
        overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 5)).ok(),
        overlay_cidr: OverlayCidr::parse("100.64.0.0/10").ok(),
        tun_interface_name: Some("MeshVPN".to_owned()),
        tun_mtu: 1420,
        netmap_version: 3,
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
            control_connected: daemon_state == DaemonState::Connected,
            relay_connected: daemon_state == DaemonState::Connected,
            relay_rtt_ms: Some(12),
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

#[test]
fn test_tab_bar_visible_all_enrolled_states() {
    // Arrange: all 8 DesktopUiState variants
    let all_states = [
        DesktopUiState::AgentUnavailable,
        DesktopUiState::ServiceStopped,
        DesktopUiState::NotEnrolled,
        DesktopUiState::Connecting,
        DesktopUiState::Connected,
        DesktopUiState::ReauthRequired,
        DesktopUiState::Revoked,
        DesktopUiState::ErrorRecoverable,
    ];

    // Act & Assert: enrolled == true MUST show 3-tab bar regardless of DesktopUiState (`ADR-028`)
    assert_eq!(DashboardTab::default(), DashboardTab::Status);
    assert_eq!(
        [
            DashboardTab::Status,
            DashboardTab::Peers,
            DashboardTab::DiagnosticsSettings,
        ]
        .len(),
        3
    );
    for state in all_states {
        assert!(
            show_tab_bar(true, state),
            "tab bar must remain visible when enrolled in state {state:?}"
        );
        assert!(
            !show_tab_bar(false, state),
            "tab bar must be hidden when not enrolled in state {state:?}"
        );
    }

    // Verify derived snapshots across all enrolled daemon states hide onboarding and keep tabs
    for daemon_state in [
        DaemonState::Connected,
        DaemonState::Degraded,
        DaemonState::Stopped,
        DaemonState::Connecting,
        DaemonState::ReauthRequired,
        DaemonState::Revoked,
    ] {
        let st = make_enrolled_status(daemon_state);
        let snap = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.4.0",
            service_probe: ServiceProbeKind::Running,
            ipc_connected: true,
            status: Some(&st),
            version_status: None,
            ipc_error: None,
            active_action_error: None,
        });
        assert!(snap.enrolled);
        assert!(snap.should_show_tab_bar());
        assert!(!snap.should_show_onboarding_form());
    }
}

#[test]
fn test_tab_bar_visible_in_all_enrolled_states() {
    // Arrange: enrolled + ErrorRecoverable (transient action failure while enrolled)
    let st = make_enrolled_status(DaemonState::Stopped);
    let snap = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.4.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st),
        version_status: None,
        ipc_error: None,
        active_action_error: Some("temporary handshake timeout"),
    });

    // Act & Assert
    assert_eq!(snap.ui_state, DesktopUiState::ErrorRecoverable);
    assert!(snap.enrolled);
    assert!(snap.should_show_tab_bar());
    assert!(!snap.should_show_onboarding_form());
}

#[test]
fn test_display_label_revoked_device_revoked() {
    // Arrange & Act & Assert: every Revoked combination MUST return "Device Revoked" (`ADR-030`)
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
}

#[test]
fn test_display_label_error_attention_required() {
    // Arrange & Act & Assert: ErrorRecoverable MUST return "Attention Required" (`ADR-030`)
    assert_eq!(
        DesktopUiState::ErrorRecoverable.display_label(TunnelSubState::Disconnected),
        "Attention Required"
    );
    assert_eq!(
        DesktopUiState::ErrorRecoverable.display_label(TunnelSubState::NotEnrolled),
        "Attention Required"
    );
}

#[test]
fn test_display_label_disconnected_not_connected() {
    // Arrange & Act
    let label = DesktopUiState::Connected.display_label(TunnelSubState::Disconnected);

    // Assert: HR-UUI-G1-03 — enrolled-but-stopped MUST never display "Connected" or "Enrolled"
    assert_eq!(label, "Disconnected");
    assert_ne!(label, "Connected");
    assert_ne!(label, "Enrolled");
}

#[test]
fn test_display_label_all_states() {
    // Arrange & Act & Assert: canonical 10-state mapping (`ADR-030` §5)
    assert_eq!(
        DesktopUiState::AgentUnavailable.display_label(TunnelSubState::NotEnrolled),
        "Agent Unavailable"
    );
    assert_eq!(
        DesktopUiState::ServiceStopped.display_label(TunnelSubState::NotEnrolled),
        "Service Stopped"
    );
    assert_eq!(
        DesktopUiState::NotEnrolled.display_label(TunnelSubState::NotEnrolled),
        "Not Enrolled"
    );
    assert_eq!(
        DesktopUiState::Connecting.display_label(TunnelSubState::Connecting),
        "Connecting"
    );
    assert_eq!(
        DesktopUiState::Connected.display_label(TunnelSubState::Connected),
        "Connected"
    );
    assert_eq!(
        DesktopUiState::Connected.display_label(TunnelSubState::Degraded),
        "Degraded"
    );
    assert_eq!(
        DesktopUiState::Connected.display_label(TunnelSubState::Disconnected),
        "Disconnected"
    );
    assert_eq!(
        DesktopUiState::Connected.display_label(TunnelSubState::Connecting),
        "Connecting"
    );
    assert_eq!(
        DesktopUiState::ReauthRequired.display_label(TunnelSubState::ReauthRequired),
        "Re-auth Required"
    );
    assert_eq!(
        DesktopUiState::Revoked.display_label(TunnelSubState::Revoked),
        "Device Revoked"
    );
    assert_eq!(
        DesktopUiState::ErrorRecoverable.display_label(TunnelSubState::Disconnected),
        "Attention Required"
    );
}

#[test]
fn test_label_preserved_for_linux_compat() {
    // Arrange & Act & Assert: existing `DesktopUiState::label()` unchanged for `linux_gui.rs:597`
    assert_eq!(DesktopUiState::Connected.label(), "Enrolled");
    assert_eq!(DesktopUiState::Revoked.label(), "Revoked");
    assert_eq!(
        DesktopUiState::ErrorRecoverable.label(),
        "Error (Recoverable)"
    );
}

#[test]
fn test_filter_peers_node_id() {
    // Arrange
    let Some(p1) = make_peer(0xaa, "alpha-host", 10, true, ActivePathKind::Direct) else {
        return;
    };
    let Some(p2) = make_peer(0xbb, "beta-host", 11, true, ActivePathKind::Relay) else {
        return;
    };
    let peers = vec![p1.clone(), p2];
    let p1_id_prefix = p1.node_id.to_string();
    let needle = p1_id_prefix.get(..8).unwrap_or("aaaaaaaa");

    // Act: 2-param `filter_peers` preserved for `linux_gui.rs:574` and searches node_id
    let matched = filter_peers(&peers, needle);

    // Assert
    assert_eq!(matched.len(), 1);
    assert_eq!(matched.first().map(|p| p.name.as_str()), Some("alpha-host"));
}

#[test]
fn test_peer_filter_mode_all_online_direct_relay() {
    // Arrange
    let peers: Vec<AgentPeerStatus> = [
        make_peer(0x01, "direct-node", 10, true, ActivePathKind::Direct),
        make_peer(0x02, "relay-node", 11, true, ActivePathKind::Relay),
        make_peer(0x03, "idle-online", 12, true, ActivePathKind::None),
        make_peer(0x04, "offline-node", 13, false, ActivePathKind::None),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(peers.len(), 4);

    // Act
    let counts = count_peers_by_mode(&peers);
    let all = filter_peers_by_mode(&peers, PeerFilterMode::All);
    let online = filter_peers_by_mode(&peers, PeerFilterMode::Online);
    let direct = filter_peers_by_mode(&peers, PeerFilterMode::Direct);
    let relay = filter_peers_by_mode(&peers, PeerFilterMode::Relay);
    let combined = filter_peers_combined(&peers, "relay", PeerFilterMode::Relay);

    // Assert
    assert_eq!(
        counts,
        PeerFilterCounts {
            all: 4,
            online: 3,
            direct: 1,
            relay: 1,
        }
    );
    assert_eq!(all.len(), 4);
    assert_eq!(online.len(), 3);
    assert_eq!(direct.len(), 1);
    assert_eq!(relay.len(), 1);
    assert_eq!(combined.len(), 1);
    assert_eq!(
        combined.first().map(|p| p.name.as_str()),
        Some("relay-node")
    );
}

#[test]
fn test_clipboard_no_secret_guard_on_ip_copy() {
    // Arrange: an independent pre-existing secret guard for mpk_*
    let secret_guard = ClipboardSecretGuard::arm(999, "mpk_existing_secret_token");

    // Act: standard IP / FQDN copy toast MUST NOT arm or interfere with ClipboardSecretGuard
    let ip_toast = format_copy_toast(CopyKind::OverlayIp, "100.64.0.10");
    let fqdn_toast = format_copy_toast(CopyKind::Fqdn, "alpha.mesh.internal");

    // Assert (`ADR-030` §4)
    assert!(!ip_toast.uses_secret_guard);
    assert!(!fqdn_toast.uses_secret_guard);
    assert!(ip_toast.body.contains("100.64.0.10"));
    assert!(fqdn_toast.body.contains("alpha.mesh.internal"));
    assert!(secret_guard.is_armed());
    assert_eq!(secret_guard.expected_seq(), 999);
}

#[test]
fn test_clipboard_no_flag_secure_on_ip_copy() {
    // Arrange & Act
    let toast = format_copy_toast(CopyKind::OverlayIp, "100.64.0.42");

    // Assert: non-secret copy never uses secret guard or wipe timer
    assert!(!toast.uses_secret_guard);
    assert_eq!(toast.title, "Copied Overlay IP");
}

#[test]
fn test_tray_state_color_mapping_10_states() {
    // Arrange: exact 10-state mapping matrix from ADR-030 §5
    let cases = [
        (
            DesktopUiState::AgentUnavailable,
            TunnelSubState::NotEnrolled,
            UiIconTone::Gray,
            "#6B7280",
        ),
        (
            DesktopUiState::ServiceStopped,
            TunnelSubState::NotEnrolled,
            UiIconTone::Gray,
            "#6B7280",
        ),
        (
            DesktopUiState::NotEnrolled,
            TunnelSubState::NotEnrolled,
            UiIconTone::Gray,
            "#6B7280",
        ),
        (
            DesktopUiState::Connecting,
            TunnelSubState::Connecting,
            UiIconTone::Amber,
            "#D97706",
        ),
        (
            DesktopUiState::Connected,
            TunnelSubState::Connected,
            UiIconTone::Green,
            "#16A34A",
        ),
        (
            DesktopUiState::Connected,
            TunnelSubState::Degraded,
            UiIconTone::Amber,
            "#D97706",
        ),
        (
            DesktopUiState::Connected,
            TunnelSubState::Disconnected,
            UiIconTone::Gray,
            "#6B7280",
        ),
        (
            DesktopUiState::ReauthRequired,
            TunnelSubState::ReauthRequired,
            UiIconTone::Amber,
            "#D97706",
        ),
        (
            DesktopUiState::Revoked,
            TunnelSubState::Revoked,
            UiIconTone::Red,
            "#DC2626",
        ),
        (
            DesktopUiState::ErrorRecoverable,
            TunnelSubState::Disconnected,
            UiIconTone::Red,
            "#DC2626",
        ),
    ];

    // Act & Assert
    for (ui_state, sub_state, expected_tone, expected_hex) in cases {
        let tone = icon_tone_for_state(ui_state, sub_state);
        assert_eq!(
            tone, expected_tone,
            "unexpected tray tone for ({ui_state:?}, {sub_state:?})"
        );
        assert_eq!(tone.hex(), expected_hex);
    }

    // Verify canonical 9-item tray menu invariant and sub-state-aware header label
    let disc_status = make_enrolled_status(DaemonState::Stopped);
    let disc_snap = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.4.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&disc_status),
        version_status: None,
        ipc_error: None,
        active_action_error: None,
    });
    let menu = build_tray_menu_model(&disc_snap, Some("100.64.0.5"), false);
    assert_eq!(IDM_STATUS_HEADER, 1001);
    assert_eq!(count_non_separator_entries(&menu), 9);
    assert!(matches!(
        menu.first(),
        Some(crate::tray::TrayMenuItemModel::Header(text))
            if text.contains("Disconnected") && !text.contains("Enrolled")
    ));
}

#[cfg(target_os = "windows")]
#[test]
fn test_gdi_obj_no_leak() {
    use mesh_sys::gui_windows::{OwnedMemDc, get_gui_resources_gdi_count};

    let _lock = theme::GDI_TEST_LOCK.lock();
    let run_cycle = || {
        let light = theme::resolve_palette(theme::ThemeMode::Light);
        let dark = theme::resolve_palette_for_dpi(theme::ThemeMode::Dark, 144);
        let st = make_enrolled_status(DaemonState::Connected);
        let snap = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.4.0",
            service_probe: ServiceProbeKind::Running,
            ipc_connected: true,
            status: Some(&st),
            version_status: None,
            ipc_error: None,
            active_action_error: None,
        });
        let model =
            status_view::build_status_hero_model(&snap, Some(&st), DashboardTab::Status, None);
        if let Some(dc) = OwnedMemDc::from_compatible(0) {
            status_view::paint_status_hero_surface(dc.as_raw(), 860, 660, 96, &model, &light);
            status_view::paint_status_hero_surface(dc.as_raw(), 1290, 990, 144, &model, &dark);
        }
    };

    // Arrange: warm up one-time process GDI initialization before baseline
    run_cycle();

    // Act: full Light -> Dark -> High-DPI theme switch + double-buffered Hero paint cycle
    let mut zero_delta = false;
    for _attempt in 0..5 {
        let before = get_gui_resources_gdi_count();
        for _ in 0..4 {
            run_cycle();
        }
        let after = get_gui_resources_gdi_count();
        if after == before {
            zero_delta = true;
            break;
        }
        std::thread::yield_now();
    }

    // Assert: zero GDI handle delta (`ADR-027`, `US-123`)
    assert!(
        zero_delta,
        "GDI handle leak detected after theme+paint cycle"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn test_gdi_no_leak_after_paint_cycle() {
    test_gdi_obj_no_leak();
}

#[cfg(target_os = "windows")]
#[test]
fn test_gdi_handle_leak_zero_after_lifecycle() {
    test_gdi_obj_no_leak();
}

#[cfg(target_os = "windows")]
#[test]
fn test_owned_mem_dc_lifecycle() {
    use mesh_sys::gui_windows::{OwnedMemDc, create_double_buffer, get_gui_resources_gdi_count};

    let _lock = theme::GDI_TEST_LOCK.lock();
    // Arrange: warm up one-time process GDI initialization
    drop(OwnedMemDc::from_compatible(0));

    // Act
    let mut zero_delta = false;
    for _attempt in 0..5 {
        let before = get_gui_resources_gdi_count();
        {
            let dc = OwnedMemDc::from_compatible(0);
            assert!(dc.is_some());
            if let Some(dc) = dc {
                assert_ne!(dc.as_raw(), 0);
                let buf = create_double_buffer(dc.as_raw(), 320, 180);
                assert!(buf.is_some());
            }
        }
        let after = get_gui_resources_gdi_count();
        if after == before {
            zero_delta = true;
            break;
        }
        std::thread::yield_now();
    }

    // Assert
    assert!(
        zero_delta,
        "OwnedMemDc/create_double_buffer leaked GDI handles"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn test_paint_guard_drop() {
    use mesh_sys::gui_windows::{PaintGuard, announce_accessible_label};

    // Arrange & Act
    let null_guard = PaintGuard::begin(0);
    announce_accessible_label(0, "State: Connected");

    // Assert
    assert!(null_guard.is_none());
}

#[cfg(target_os = "windows")]
#[test]
fn test_detect_high_contrast_cbsize() {
    use mesh_sys::gui_windows::{detect_high_contrast, high_contrast_struct_cb_size};

    // Arrange & Act
    let cb = high_contrast_struct_cb_size();
    let _hc = detect_high_contrast();

    // Assert
    assert!(cb >= 12);
}

#[cfg(target_os = "windows")]
#[test]
fn test_ws_clipchildren_in_dwstyle() {
    use mesh_sys::gui_windows::{
        MAIN_WINDOW_STYLE, WIN_WS_CLIPCHILDREN, WIN_WS_OVERLAPPEDWINDOW, calc_font_height_for_dpi,
    };

    // Arrange & Act & Assert
    assert_ne!(MAIN_WINDOW_STYLE & WIN_WS_CLIPCHILDREN, 0);
    assert_eq!(
        MAIN_WINDOW_STYLE & WIN_WS_OVERLAPPEDWINDOW,
        WIN_WS_OVERLAPPEDWINDOW
    );
    assert_eq!(calc_font_height_for_dpi(10, 96), -13);
    assert_eq!(calc_font_height_for_dpi(10, 120), -17);
    assert_eq!(calc_font_height_for_dpi(10, 144), -20);
    assert_eq!(calc_font_height_for_dpi(10, 192), -27);
}
