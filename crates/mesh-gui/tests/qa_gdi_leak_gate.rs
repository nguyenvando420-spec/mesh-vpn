//! GDI Handle Leak Gate Test Suite (`WP-U-D0`, `US-136`, `ADR-027`, `contracts §5.3`).
//!
//! Exercises 100 full create/paint/destroy cycles across Light/Dark/System palettes, DPI scales
//! (`96..=192`), `OwnedMemDc`, double-buffer bitmaps, rounded cards/pills/owner-drawn buttons,
//! and status icons, enforcing `GetGuiResources(GR_GDIOBJECTS)` `delta == 0` and total `< 5_000`.

#[cfg(target_os = "windows")]
#[path = "../src/app.rs"]
mod app;
#[cfg(target_os = "windows")]
#[path = "../src/i18n.rs"]
mod i18n;
#[cfg(target_os = "windows")]
#[path = "../src/icons.rs"]
mod icons;
#[cfg(target_os = "windows")]
#[path = "../src/status_view.rs"]
mod status_view;
#[cfg(target_os = "windows")]
#[path = "../src/theme.rs"]
mod theme;

#[cfg(target_os = "windows")]
mod windows_gdi_gate {
    use std::net::Ipv4Addr;

    use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin};
    use mesh_proto::agent_ipc::{
        AgentStatusResponse, DaemonState, SelfNetworkStatus, ServerConnectionStatus, TlsAuthMode,
    };
    use mesh_proto::netmap::NatMappingKind;
    use mesh_sys::gui_windows::{
        ControlRect, OwnedMemDc, OwnerDrawButtonStyle, PaintGuard, create_double_buffer,
        draw_owner_draw_button, get_gui_resources_gdi_count,
    };

    use crate::app::{DashboardTab, ServiceProbeKind, StateProbeInputs, derive_desktop_ui_state};
    use crate::icons::{create_status_icon_for_px, icon_tone_for_state};
    use crate::status_view::{build_status_hero_model, paint_status_hero_surface};
    use crate::theme::{GDI_TEST_LOCK, ThemeMode, resolve_palette_for_dpi};

    const GDI_ALERT_THRESHOLD: u32 = 5_000;
    const LIFECYCLE_CYCLES: usize = 100;

    fn sample_status(state: DaemonState) -> AgentStatusResponse {
        AgentStatusResponse {
            daemon_state: state,
            node_id: Some(NodeId::from_bytes([0x44_u8; 16])),
            node_name: NodeName::parse("gdi-gate-node").ok(),
            fqdn: Some("gdi-gate-node.mesh.internal".to_owned()),
            overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 21)).ok(),
            overlay_cidr: OverlayCidr::parse("100.64.0.0/10").ok(),
            tun_interface_name: Some("MeshVPN".to_owned()),
            tun_mtu: 1420,
            netmap_version: 7,
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
                control_connected: state == DaemonState::Connected,
                relay_connected: state == DaemonState::Connected,
                relay_rtt_ms: Some(11),
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

    fn execute_single_gdi_cycle(cycle_idx: usize) {
        let mode = match cycle_idx % 3 {
            0 => ThemeMode::Light,
            1 => ThemeMode::Dark,
            _ => ThemeMode::System,
        };
        let dpi = match cycle_idx % 4 {
            0 => 96,
            1 => 120,
            2 => 144,
            _ => 192,
        };
        let daemon_state = match cycle_idx % 4 {
            0 => DaemonState::Connected,
            1 => DaemonState::Degraded,
            2 => DaemonState::Stopped,
            _ => DaemonState::ReauthRequired,
        };
        let tab = match cycle_idx % 3 {
            0 => DashboardTab::Status,
            1 => DashboardTab::Peers,
            _ => DashboardTab::DiagnosticsSettings,
        };

        let mut palette = resolve_palette_for_dpi(mode, dpi);
        let status = sample_status(daemon_state);
        let snap = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.4.0",
            service_probe: ServiceProbeKind::Running,
            ipc_connected: true,
            status: Some(&status),
            version_status: None,
            ipc_error: None,
            active_action_error: None,
        });
        let model = build_status_hero_model(&snap, Some(&status), tab, Some("Copied"));

        if let Some(dc) = OwnedMemDc::from_compatible(0) {
            paint_status_hero_surface(dc.as_raw(), 860, 660, dpi, &model, &palette);
            if let (Some(bg), Some(pen), Some(font)) = (
                palette.brand_brush.as_ref(),
                palette.brand_border_pen.as_ref(),
                palette.font_body.as_ref(),
            ) {
                let btn_rect = ControlRect::new(16, 16, 140, 32);
                let style = OwnerDrawButtonStyle {
                    text: "Connect",
                    bg_brush: bg,
                    border_pen: pen,
                    text_color: palette.on_accent_text_color(),
                    font,
                    focused: cycle_idx.is_multiple_of(2),
                };
                draw_owner_draw_button(dc.as_raw(), &btn_rect, &style);
            }
        }

        let tone = icon_tone_for_state(snap.ui_state, snap.tunnel_sub_state);
        let _icon = create_status_icon_for_px(tone, 32);
        palette.clear_brush_cache();
        drop(palette);
    }

    #[test]
    fn test_gdi_handle_lifecycle() {
        let _lock = GDI_TEST_LOCK.lock();

        // Arrange: warm up one-time Win32 GDI/font-mapper process allocations
        for warm in 0..4 {
            execute_single_gdi_cycle(warm);
        }

        // Act: run 100 full create/paint/destroy cycles and assert delta == 0 and total < 5_000
        let mut zero_delta = false;
        let mut last_before = 0_u32;
        let mut last_after = 0_u32;
        let mut peak_handles = 0_u32;

        for _attempt in 0..3 {
            let before = get_gui_resources_gdi_count();
            let mut local_peak = before;
            for cycle in 0..LIFECYCLE_CYCLES {
                execute_single_gdi_cycle(cycle);
                let current = get_gui_resources_gdi_count();
                if current > local_peak {
                    local_peak = current;
                }
            }
            let after = get_gui_resources_gdi_count();
            last_before = before;
            last_after = after;
            peak_handles = local_peak;
            if after == before {
                zero_delta = true;
                break;
            }
            std::thread::yield_now();
        }

        // Assert (`US-136`): delta == 0 and total < 5_000 alert ceiling
        assert!(
            peak_handles < GDI_ALERT_THRESHOLD,
            "peak GDI handles ({peak_handles}) exceeded alert threshold ({GDI_ALERT_THRESHOLD})"
        );
        assert!(
            last_after < GDI_ALERT_THRESHOLD,
            "final GDI handles ({last_after}) exceeded alert threshold ({GDI_ALERT_THRESHOLD})"
        );
        assert!(
            zero_delta,
            "GDI handle leak detected after {LIFECYCLE_CYCLES} cycles: before={last_before}, after={last_after}"
        );
    }

    #[test]
    fn test_gdi_owned_mem_dc_double_buffer_and_paint_guard_100_cycles() {
        let _lock = GDI_TEST_LOCK.lock();

        // Arrange: warm up one-time GDI state
        drop(OwnedMemDc::from_compatible(0));
        assert!(PaintGuard::begin(0).is_none());

        // Act
        let mut zero_delta = false;
        let mut last_before = 0_u32;
        let mut last_after = 0_u32;
        let mut peak = 0_u32;
        for _attempt in 0..3 {
            let before = get_gui_resources_gdi_count();
            for _ in 0..LIFECYCLE_CYCLES {
                if let Some(dc) = OwnedMemDc::from_compatible(0) {
                    let buf = create_double_buffer(dc.as_raw(), 640, 480);
                    assert!(buf.is_some());
                    let cur = get_gui_resources_gdi_count();
                    if cur > peak {
                        peak = cur;
                    }
                    drop(buf);
                }
                assert!(PaintGuard::begin(0).is_none());
            }
            let after = get_gui_resources_gdi_count();
            last_before = before;
            last_after = after;
            if after == before {
                zero_delta = true;
                break;
            }
            std::thread::yield_now();
        }

        // Assert
        assert!(peak < GDI_ALERT_THRESHOLD);
        assert!(last_after < GDI_ALERT_THRESHOLD);
        assert!(
            zero_delta,
            "OwnedMemDc/double-buffer leak: before={last_before}, after={last_after}"
        );
    }
}

#[cfg(not(target_os = "windows"))]
#[test]
fn test_gdi_handle_lifecycle_non_windows_compile_guard() {
    // Arrange & Act & Assert: GDI handle APIs are Windows-only; non-Windows targets stay green.
    assert_eq!(5_000_u32, 5_000_u32);
}
