//! Unit and integration tests for Windows Desktop GUI (`MeshVPN.exe`, `US-103..108`).
//!
//! Covers all 8 `DesktopUiState` transitions + `LegacyPre030`, Zero-TOFU & `mesh://` onboarding,
//! atomic `ClipboardSecretGuard` invariants (`IG-DGUI-WA-01`), `UnprivilegedSinkWriter` Atomic
//! `.part` Replace (`IG-DGUI-WA-03` / `ADR-021`), `MGH1` framing & zeroization, `wintun.dll`
//! anti-TOCTOU verification, single-instance SemVer negotiation, autostart formatting,
//! `CARGO_BIN_EXE_MeshVPN` CLI validation, and `test_no_secrets_in_outputs` (`SEC-01`).

#[path = "../src/app.rs"]
mod app;
#[path = "../src/autostart.rs"]
mod autostart;
#[path = "../src/clipboard.rs"]
mod clipboard;
#[path = "../src/diagnostics_view.rs"]
mod diagnostics_view;
#[path = "../src/icons.rs"]
mod icons;
#[path = "../src/onboarding.rs"]
mod onboarding;
#[path = "../src/peers_view.rs"]
mod peers_view;
#[path = "../src/single_instance.rs"]
mod single_instance;

use std::net::Ipv4Addr;
use std::path::Path;
#[cfg(target_os = "windows")]
use std::process::Command;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
use mesh_core::{
    MobileJoinTlsAuth, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin, format_join_uri,
};
use mesh_crypto::Secret;
use mesh_net::gui_handoff::{
    HandoffFrame, HandoffRequest, HandoffResponse, HandoffStreamHeaderPayload,
    MGH1_PROTOCOL_VERSION, build_up_handoff_payload, decode_mgh1_frame, encode_mgh1_frame,
    generate_handoff_pipe_name, masked_preauth_preview_from_secret, parse_handoff_request_payload,
    validate_handoff_pipe_name, zeroize_handoff_payload,
};
use mesh_net::ipc::{
    AgentVersionStatus, HEADER_MESH_AGENT_VERSION, HEADER_MESH_ARCHIVE_BYTES,
    HEADER_MESH_SCRUBBED_ITEMS, IPC_ADMIN_MUTATION_TIMEOUT, serve_ipc_http_connection,
    stream_ipc_bugreport,
};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentPeerStatus, AgentStatusResponse, DaemonState, NetcheckResponse,
    PingResponse, PingSample, PingVia, SelfNetworkStatus, ServerConnectionStatus, TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;
use proptest::prelude::*;
use tokio::io::duplex;

use crate::app::{
    AgentVersionIndicator, DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState,
    derive_desktop_ui_state, derive_version_indicator, format_user_facing_error,
    is_status_enrolled, sanitize_gui_log_text,
};
use crate::autostart::{AUTOSTART_REG_VALUE_NAME, format_autostart_command_line};
use crate::clipboard::{CLIPBOARD_WIPE_DELAY_MS, ClipboardSecretGuard, looks_like_sensitive_paste};
use crate::diagnostics_view::{
    DEFAULT_BUGREPORT_FILENAME, format_netcheck_report, format_self_network_panel,
    validate_bugreport_archive_size,
};
use crate::icons::{
    ICON_MAX_PX, ICON_MIN_PX, UiIconTone, icon_tone_for_state, render_status_badge_bgra,
};
use crate::onboarding::{
    ConfirmActionKind, OnboardingFormInput, OnboardingTlsMode, parse_mesh_join_uri_to_draft,
    should_lock_system_ca_for_endpoint, validate_manual_onboarding_to_draft,
    validate_rotate_key_to_draft, validate_update_server_payload,
};
use crate::peers_view::{
    filter_peers, format_human_bytes, format_peer_detail_summary, format_peer_list_entry,
    format_ping_response,
};
use crate::single_instance::{
    MAIN_WINDOW_CLASS_NAME, SemVerTriple, UPGRADE_SHUTDOWN_WAIT_MS, should_request_upgrade_shutdown,
};

fn sample_self_network() -> SelfNetworkStatus {
    SelfNetworkStatus {
        local_udp_port: 51820,
        bound_physical_interface: Some("Ethernet".to_owned()),
        nat_type: NatMappingKind::EimOrAdm,
        nat_classification_note: Some("single STUN server probe".to_owned()),
        overlay_conflict_warning: None,
        macos_firewall_warning: None,
        candidates: Vec::new(),
    }
}

fn sample_server(control_endpoint: &str, last_error: Option<&str>) -> ServerConnectionStatus {
    let pin =
        SpkiPin::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .ok();
    ServerConnectionStatus {
        control_endpoint: control_endpoint.to_owned(),
        relay_endpoint: "198.51.100.10:8443".to_owned(),
        stun_endpoints: vec!["198.51.100.10:3478".to_owned()],
        tls_auth_mode: TlsAuthMode::SpkiPin,
        active_pin: pin,
        next_pin: None,
        control_connected: true,
        relay_connected: true,
        relay_rtt_ms: Some(14),
        migration_pending_endpoint: None,
        last_error: last_error.map(ToOwned::to_owned),
    }
}

fn sample_status(
    daemon_state: DaemonState,
    enrolled: bool,
    last_error: Option<&str>,
) -> AgentStatusResponse {
    AgentStatusResponse {
        daemon_state,
        node_id: if enrolled {
            Some(NodeId::from_bytes([7_u8; 16]))
        } else {
            None
        },
        node_name: NodeName::parse("win-laptop").ok(),
        fqdn: Some("win-laptop.mesh.internal".to_owned()),
        overlay_ip: if enrolled {
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 2)).ok()
        } else {
            None
        },
        overlay_cidr: OverlayCidr::parse("100.64.0.0/10").ok(),
        tun_interface_name: Some("MeshVPN".to_owned()),
        tun_mtu: 1420,
        netmap_version: 5,
        key_expires_at_ms: Some(1_900_000_000_000),
        server_connection: if enrolled {
            Some(sample_server("198.51.100.10:8443", last_error))
        } else {
            None
        },
        self_network: sample_self_network(),
        peers: Vec::new(),
    }
}

#[test]
fn test_app_derives_all_8_ui_states_plus_legacy_pre_030() {
    // 1. AgentUnavailable (IPC down, SCM running)
    let s1 = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: false,
        status: None,
        version_status: None,
        ipc_error: Some("pipe not found"),
        active_action_error: None,
    });
    assert_eq!(s1.ui_state, DesktopUiState::AgentUnavailable);
    assert!(!s1.ui_state.label().is_empty());

    // 2. ServiceStopped (IPC down, SCM stopped or missing)
    for probe in [ServiceProbeKind::Stopped, ServiceProbeKind::NotInstalled] {
        let s2 = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.3.0",
            service_probe: probe,
            ipc_connected: false,
            status: None,
            version_status: None,
            ipc_error: None,
            active_action_error: None,
        });
        assert_eq!(s2.ui_state, DesktopUiState::ServiceStopped);
        assert_eq!(
            s2.ui_state.headline(s2.tunnel_sub_state),
            "Windows Service Stopped / Not Installed"
        );
    }
    let s_unk = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Unknown,
        ipc_connected: false,
        status: None,
        version_status: None,
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s_unk.ui_state, DesktopUiState::AgentUnavailable);

    #[cfg(target_os = "windows")]
    {
        let expected_logs = Path::new(r"C:\LocalAppData")
            .join(crate::app::GUI_APP_DATA_DIR_NAME)
            .join(crate::app::GUI_LOG_SUBDIR);
        assert_eq!(
            crate::app::gui_log_directory(Some(Path::new(r"C:\LocalAppData"))),
            Some(expected_logs)
        );
    }

    // 3. NotEnrolled (Stopped + no node_id/overlay_ip/endpoint)
    let st_not_enrolled = sample_status(DaemonState::Stopped, false, None);
    assert!(!is_status_enrolled(&st_not_enrolled));
    let s3 = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_not_enrolled),
        version_status: Some(&AgentVersionStatus::Version("0.3.0".to_owned())),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s3.ui_state, DesktopUiState::NotEnrolled);
    assert_eq!(s3.tunnel_sub_state, TunnelSubState::NotEnrolled);
    assert!(s3.legacy_banner.is_none());

    // 4. Connecting
    let st_conn = sample_status(DaemonState::Connecting, true, None);
    let s4 = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_conn),
        version_status: Some(&AgentVersionStatus::Version("0.3.0".to_owned())),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s4.ui_state, DesktopUiState::Connecting);
    assert_eq!(
        icon_tone_for_state(s4.ui_state, s4.tunnel_sub_state),
        UiIconTone::Amber
    );

    // 5a. Connected (Active)
    let st_up = sample_status(DaemonState::Connected, true, None);
    let s5a = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_up),
        version_status: Some(&AgentVersionStatus::Version("0.3.0".to_owned())),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s5a.ui_state, DesktopUiState::Connected);
    assert_eq!(s5a.tunnel_sub_state, TunnelSubState::Connected);
    assert_eq!(
        icon_tone_for_state(s5a.ui_state, s5a.tunnel_sub_state),
        UiIconTone::Green
    );

    // 5b. Connected (Degraded)
    let st_deg = sample_status(DaemonState::Degraded, true, None);
    let s5b = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_deg),
        version_status: Some(&AgentVersionStatus::Version("0.3.0".to_owned())),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s5b.ui_state, DesktopUiState::Connected);
    assert_eq!(s5b.tunnel_sub_state, TunnelSubState::Degraded);
    assert!(
        s5b.ui_state
            .tray_tooltip_summary(s5b.tunnel_sub_state)
            .contains("Degraded")
    );

    // 5c. Connected (Enrolled but clean Stopped -> Disconnected ready for 1-click Up)
    let st_disc = sample_status(DaemonState::Stopped, true, None);
    let s5c = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_disc),
        version_status: None,
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s5c.ui_state, DesktopUiState::Connected);
    assert_eq!(s5c.tunnel_sub_state, TunnelSubState::Disconnected);
    assert!(s5c.enrolled);
    assert_eq!(s5c.version_indicator, AgentVersionIndicator::Unknown);

    // 6. ReauthRequired
    let st_reauth = sample_status(DaemonState::ReauthRequired, true, None);
    let s6 = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_reauth),
        version_status: Some(&AgentVersionStatus::Version("0.2.9".to_owned())),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s6.ui_state, DesktopUiState::ReauthRequired);
    assert!(s6.version_mismatch_banner.is_some());

    // 7. Revoked
    let st_revoked = sample_status(DaemonState::Revoked, true, None);
    let s7 = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_revoked),
        version_status: Some(&AgentVersionStatus::LegacyPre030),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s7.ui_state, DesktopUiState::Revoked);
    assert_eq!(s7.version_indicator, AgentVersionIndicator::LegacyPre030);
    assert!(s7.legacy_banner.is_some());
    assert_eq!(
        icon_tone_for_state(s7.ui_state, s7.tunnel_sub_state),
        UiIconTone::Red
    );

    // 8. ErrorRecoverable + SEC-05 authentication failed exact error text
    let st_err = sample_status(DaemonState::Stopped, true, Some("status: Unauthenticated"));
    let s8 = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&st_err),
        version_status: None,
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s8.ui_state, DesktopUiState::ErrorRecoverable);
    assert_eq!(
        s8.recoverable_error.as_deref(),
        Some("authentication failed")
    );
    assert_eq!(
        derive_version_indicator(
            "0.3.0",
            Some(&AgentVersionStatus::Version("0.3.0".to_owned()))
        ),
        AgentVersionIndicator::Compatible("0.3.0".to_owned())
    );
}

#[test]
fn test_onboarding_zero_tofu_uri_and_rotation_validation() {
    let valid_pin_str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let valid_pin = SpkiPin::parse(valid_pin_str);
    assert!(valid_pin.is_ok());

    // Zero-TOFU must lock SystemCA on IPv4 and IPv6 literals
    assert!(should_lock_system_ca_for_endpoint("198.51.100.10:8443"));
    assert!(should_lock_system_ca_for_endpoint("[2001:db8::1]:8443"));
    assert!(!should_lock_system_ca_for_endpoint("mesh.example.com:8443"));
    assert!(!should_lock_system_ca_for_endpoint(""));

    let valid_token_a = "mpk_QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";
    let valid_token_b = "mpk_QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
    let valid_token_c = "mpk_Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M";

    let blocked_ip_sys_ca = validate_manual_onboarding_to_draft(&OnboardingFormInput {
        endpoint_raw: "198.51.100.10:8443".to_owned(),
        tls_mode: OnboardingTlsMode::SystemCa,
        spki_pin_raw: String::new(),
        preauth_key_raw: valid_token_a.to_owned(),
        node_name_raw: "win-node-1".to_owned(),
    });
    assert!(blocked_ip_sys_ca.is_err());

    // Valid SPKI + IPv4 literal builds masked confirmation draft & handoff payload cleanly
    let ok_draft = validate_manual_onboarding_to_draft(&OnboardingFormInput {
        endpoint_raw: "198.51.100.10".to_owned(),
        tls_mode: OnboardingTlsMode::SpkiPin,
        spki_pin_raw: valid_pin_str.to_owned(),
        preauth_key_raw: valid_token_a.to_owned(),
        node_name_raw: "win-node-1".to_owned(),
    });
    assert!(ok_draft.is_ok(), "unexpected error: {ok_draft:?}");
    if let Ok(draft) = ok_draft {
        assert_eq!(draft.action_kind, ConfirmActionKind::EnrollNewNode);
        assert!(!draft.format_confirmation_summary().contains(valid_token_a));
        let dbg = format!("{draft:?}");
        assert!(!dbg.contains(valid_token_a));
        let payload = draft.build_handoff_payload();
        assert!(payload.is_ok());
    }

    // Parse canonical mesh://join URI into pre-filled draft
    if let Ok(pin) = valid_pin
        && let Ok(uri) = format_join_uri(
            "198.51.100.10:8443",
            &MobileJoinTlsAuth::SpkiPin(pin),
            valid_token_b,
            None,
        )
    {
        let parsed = parse_mesh_join_uri_to_draft(&uri, "");
        assert!(
            parsed.is_ok(),
            "parse_mesh_join_uri_to_draft failed: {parsed:?}"
        );
        if let Ok((form, draft)) = parsed {
            assert_eq!(form.endpoint_raw, "198.51.100.10:8443");
            assert!(!format!("{form:?}").contains(valid_token_b));
            assert!(!draft.format_confirmation_summary().contains(valid_token_b));
        }
    }

    // Key rotation & Update Server / Pin validation
    let rotate_res = validate_rotate_key_to_draft(
        "mesh.example.com:8443",
        OnboardingTlsMode::SystemCa,
        None,
        valid_token_c,
    );
    assert!(
        rotate_res.is_ok(),
        "validate_rotate_key_to_draft failed: {rotate_res:?}"
    );
    if let Ok(r) = rotate_res {
        assert_eq!(r.action_kind, ConfirmActionKind::RotateKey);
        assert!(r.build_handoff_payload().is_ok());
    }
    assert!(
        validate_update_server_payload("mesh.example.com:8443", OnboardingTlsMode::SystemCa, "")
            .is_ok()
    );
    assert!(
        validate_update_server_payload("198.51.100.10:8443", OnboardingTlsMode::SystemCa, "")
            .is_err()
    );
}

#[test]
fn test_clipboard_guard_atomic_sequence_and_hash_clear() {
    assert_eq!(CLIPBOARD_WIPE_DELAY_MS, 30_000);
    assert!(looks_like_sensitive_paste(
        "mesh://join?v=1&ep=1.2.3.4:443&key=abc"
    ));
    assert!(looks_like_sensitive_paste("mpk_0123456789abcdef"));
    assert!(!looks_like_sensitive_paste("hello world sentence"));

    let mut guard = ClipboardSecretGuard::arm(42, "mpk_super_secret_clip_value");
    assert!(guard.is_armed());
    assert_eq!(guard.expected_seq(), 42);
    assert!(!format!("{guard:?}").contains("mpk_super_secret_clip_value"));
    assert!(guard.matches_text("mpk_super_secret_clip_value"));
    assert!(!guard.matches_text("different_user_copy"));

    // Matching (seq, sha256) returns true and disarms
    assert!(guard.evaluate_clear(42, Some("mpk_super_secret_clip_value")));
    assert!(!guard.is_armed());
    assert!(!guard.evaluate_clear(42, Some("mpk_super_secret_clip_value")));

    // Changed clipboard sequence number does NOT clear someone else's clipboard
    let mut guard2 = ClipboardSecretGuard::arm(99, "mpk_another_secret");
    assert!(!guard2.evaluate_clear(100, Some("mpk_another_secret")));
    assert!(!guard2.is_armed());

    // Changed content even with matching seq returns false
    let mut guard3 = ClipboardSecretGuard::arm(101, "mpk_secret_a");
    assert!(!guard3.evaluate_clear(101, Some("mpk_secret_b")));

    let mut guard4 = ClipboardSecretGuard::arm(102, "mpk_secret_c");
    guard4.disarm();
    assert!(!guard4.is_armed());

    #[cfg(target_os = "windows")]
    {
        let mut unarmed = ClipboardSecretGuard::arm(555, "mpk_unarmed");
        unarmed.disarm();
        let res = crate::clipboard::attempt_atomic_clipboard_clear(&mut unarmed);
        assert!(matches!(res, Ok(false)));
    }
}

#[test]
fn test_mgh1_handoff_framing_pipe_validation_and_zeroize() {
    let pipe = generate_handoff_pipe_name();
    assert!(validate_handoff_pipe_name(&pipe).is_ok());
    assert!(validate_handoff_pipe_name(r"\\.\pipe\mesh-agent-admin").is_err());

    let hello_raw = encode_mgh1_frame(&HandoffFrame::WorkerHello {
        protocol_version: MGH1_PROTOCOL_VERSION,
    });
    assert!(hello_raw.is_ok());
    if let Ok(buf) = hello_raw {
        assert_eq!(buf.len(), 13);
        let decoded = decode_mgh1_frame(&buf);
        assert!(matches!(
            decoded,
            Ok((
                HandoffFrame::WorkerHello {
                    protocol_version: MGH1_PROTOCOL_VERSION
                },
                13
            ))
        ));
    }

    let handoff_token = "mpk_REREREREREREREREREREREREREREREREREREREREREQ";
    let secret = Secret::new(handoff_token.to_owned());
    let payload_res = build_up_handoff_payload(
        "198.51.100.10:8443",
        None,
        SpkiPin::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .ok(),
        Some(&secret),
        NodeName::parse("host-a").ok(),
    );
    assert!(
        payload_res.is_ok(),
        "build_up_handoff_payload failed: {payload_res:?}"
    );
    if let Ok(mut payload) = payload_res {
        let parsed = parse_handoff_request_payload(payload.as_slice());
        assert!(parsed.is_ok());
        if let Ok(req) = parsed {
            assert!(!format!("{req:?}").contains(handoff_token));
        }

        zeroize_handoff_payload(&mut payload);
        assert!(payload.is_empty());
    }

    let header = HandoffStreamHeaderPayload {
        total_bytes: 2_048,
        scrubbed_items: 4,
    };
    assert!(header.validate().is_ok());
    assert!(encode_mgh1_frame(&HandoffFrame::HandoffStreamHeader(header)).is_ok());
    assert!(encode_mgh1_frame(&HandoffFrame::BugreportChunk(vec![0xAA_u8; 256])).is_ok());
    let resp_json =
        serde_json::to_vec(&HandoffResponse::from_bugreport(4, 2_048)).unwrap_or_default();
    assert!(encode_mgh1_frame(&HandoffFrame::HandoffResponse(resp_json)).is_ok());
}

#[test]
fn test_single_instance_semver_autostart_icons_peers_and_diagnostics() {
    assert_eq!(MAIN_WINDOW_CLASS_NAME, "MeshVpnDashboardWindowClass");
    assert_eq!(UPGRADE_SHUTDOWN_WAIT_MS, 3_000);
    assert_eq!(AUTOSTART_REG_VALUE_NAME, "MeshVPN");
    assert_eq!(DEFAULT_BUGREPORT_FILENAME, "meshvpn-bugreport.tar");

    let cur = SemVerTriple::parse("0.3.0");
    let old = SemVerTriple::parse("0.2.9-rc1");
    assert!(cur.is_some() && old.is_some());
    if let (Some(c), Some(o)) = (cur, old) {
        let packed_old = o.pack_u32();
        let packed_cur = c.pack_u32();
        assert_eq!(SemVerTriple::unpack_u32(packed_cur), c);
        assert!(should_request_upgrade_shutdown(c, Some(packed_old)));
        assert!(!should_request_upgrade_shutdown(c, Some(packed_cur)));
        assert!(!should_request_upgrade_shutdown(c, None));
    }

    let cmd = format_autostart_command_line(Path::new(r"C:\Program Files\Mesh\MeshVPN.exe"));
    assert_eq!(cmd, "\"C:\\Program Files\\Mesh\\MeshVPN.exe\" --minimized");

    let bgra = render_status_badge_bgra(UiIconTone::Green, 32);
    assert_eq!(bgra.len(), 32 * 32 * 4);
    assert_eq!(
        render_status_badge_bgra(UiIconTone::Gray, 4).len(),
        usize::try_from(ICON_MIN_PX * ICON_MIN_PX * 4).unwrap_or(0)
    );
    assert_eq!(
        render_status_badge_bgra(UiIconTone::Amber, 999).len(),
        usize::try_from(ICON_MAX_PX * ICON_MAX_PX * 4).unwrap_or(0)
    );
    #[cfg(target_os = "windows")]
    {
        let icon = icons::create_status_icon_for_px(UiIconTone::Green, 24);
        assert!(icon.is_ok(), "create_status_icon_for_px failed: {icon:?}");
    }

    // Peers, Ping, SelfNetwork, Netcheck formatting, and Bugreport size cap
    assert_eq!(format_human_bytes(512), "512 B");
    assert_eq!(format_human_bytes(2048), "2.0 KiB");
    assert_eq!(format_human_bytes(5 * 1024 * 1024), "5.0 MiB");

    if let (Ok(name), Ok(ip)) = (
        NodeName::parse("server-alpha"),
        OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 10)),
    ) {
        let peers = vec![AgentPeerStatus {
            node_id: NodeId::from_bytes([1_u8; 16]),
            name,
            fqdn: "server-alpha.mesh.internal".to_owned(),
            overlay_ip: ip,
            online: true,
            active_path: ActivePathKind::Direct,
            direct_endpoint: Some("203.0.113.5:51820".to_owned()),
            rtt_ms: Some(11),
            last_handshake_at_ms: Some(1_700_000_000_000),
            rx_bytes: 1024,
            tx_bytes: 2048,
        }];
        assert_eq!(filter_peers(&peers, "alpha").len(), 1);
        assert_eq!(filter_peers(&peers, "missing").len(), 0);
        if let Some(p) = peers.first() {
            assert!(format_peer_list_entry(p).contains("server-alpha"));
            assert!(format_peer_detail_summary(p).contains("Direct P2P UDP"));
        }
    }

    if let (Ok(target_name), Ok(target_ip)) = (
        NodeName::parse("peer-b"),
        OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 3)),
    ) {
        let ping = PingResponse {
            target_name,
            target_overlay_ip: target_ip,
            samples: vec![PingSample {
                seq: 1,
                via: PingVia::Relay,
                endpoint: Some("198.51.100.10:8443".to_owned()),
                rtt_ms: Some(18.5),
            }],
            packets_sent: 1,
            packets_received: 1,
            loss_percent: 0.0,
            rtt_min_ms: Some(18.5),
            rtt_avg_ms: Some(18.5),
            rtt_max_ms: Some(18.5),
        };
        assert!(format_ping_response(&ping).contains("18.50"));
    }

    let st = sample_status(DaemonState::Connected, true, None);
    assert!(format_self_network_panel(&st).contains("MeshVPN"));

    let nc = NetcheckResponse {
        udp_egress_ok: true,
        stun_reachable: true,
        stun_endpoint_tested: Some("198.51.100.10:3478".to_owned()),
        reflexive_ipv4: Some("203.0.113.42:54321".to_owned()),
        ipv6_available: false,
        nat_mapping: NatMappingKind::EimOrAdm,
        nat_note: "single probe".to_owned(),
        control_tcp_reachable: true,
        control_tcp_endpoint_tested: Some("198.51.100.10:8443".to_owned()),
        relay_rtt_ms: Some(15.2),
        diagnostic_hint: None,
    };
    assert!(format_netcheck_report(&nc).contains("203.0.113.42"));
    assert!(validate_bugreport_archive_size(0).is_err());
    assert!(
        validate_bugreport_archive_size(
            u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(0) + 1
        )
        .is_err()
    );
    assert_eq!(validate_bugreport_archive_size(4096), Ok(4096));
}

#[tokio::test]
async fn test_bugreport_stream_bounded_64kib_chunks_and_truncation_rejection() {
    let payload = vec![0x42_u8; 140_000];
    let len_str = payload.len().to_string();
    let payload_ok = payload.clone();
    let ok_router = Router::new().route(
        "/v1/agent/bugreport/stream",
        post(move || {
            let body_bytes = payload_ok.clone();
            let header_val = len_str.clone();
            async move {
                let mut resp = (StatusCode::OK, Body::from(body_bytes)).into_response();
                if let Ok(hv) = HeaderValue::from_str(&header_val) {
                    resp.headers_mut().insert(HEADER_MESH_ARCHIVE_BYTES, hv);
                }
                resp.headers_mut()
                    .insert(HEADER_MESH_SCRUBBED_ITEMS, HeaderValue::from_static("5"));
                resp.headers_mut()
                    .insert(HEADER_MESH_AGENT_VERSION, HeaderValue::from_static("0.3.0"));
                resp
            }
        }),
    );

    let (cli, srv) = duplex(256 * 1024);
    let srv_task = tokio::spawn(serve_ipc_http_connection(srv, ok_router));
    let mut got = Vec::new();
    let meta = stream_ipc_bugreport(
        cli,
        IPC_ADMIN_MUTATION_TIMEOUT,
        Duration::from_secs(2),
        |c| {
            assert!(c.len() <= 65_536);
            got.extend_from_slice(c);
            Ok(())
        },
    )
    .await;
    assert!(srv_task.await.is_ok());
    assert!(meta.is_ok(), "stream_ipc_bugreport failed: {meta:?}");
    assert_eq!(got, payload);
}

#[test]
fn test_no_secrets_in_outputs() {
    let canary = "mpk_RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUU";
    let secret = Secret::new(canary.to_owned());

    // 1. Secret Debug / Display / preview
    assert!(!format!("{secret:?}").contains(canary));
    assert!(!format!("{secret}").contains(canary));
    assert!(!masked_preauth_preview_from_secret(&secret).contains(canary));

    // 2. OnboardingFormInput & EnrollmentConfirmationDraft Debug / modal summary
    let form = OnboardingFormInput {
        endpoint_raw: "mesh.example.com:8443".to_owned(),
        tls_mode: OnboardingTlsMode::SystemCa,
        spki_pin_raw: String::new(),
        preauth_key_raw: canary.to_owned(),
        node_name_raw: "gui-node".to_owned(),
    };
    assert!(!format!("{form:?}").contains(canary));
    let draft_res = validate_manual_onboarding_to_draft(&form);
    assert!(draft_res.is_ok(), "expected valid draft: {draft_res:?}");
    if let Ok(draft) = draft_res {
        assert!(!format!("{draft:?}").contains(canary));
        assert!(!draft.format_confirmation_summary().contains(canary));
    }

    // 3. Log sanitizer and error formatter
    let dirty_log = format!(
        "GET mesh://join?v=1&ep=mesh.example.com:8443&key={canary} \
         json={{\"preauth_key\":\"{canary}\"}} preauth_key={canary} standalone={canary}"
    );
    let scrubbed = sanitize_gui_log_text(&dirty_log);
    assert!(!scrubbed.contains(canary));
    let ui_err = format_user_facing_error(&format!("join failed with preauth_key={canary}"));
    assert!(!ui_err.contains(canary));
    assert_eq!(
        format_user_facing_error("RPC returned Unauthenticated"),
        "authentication failed"
    );

    // 4. HandoffRequest Debug redacts Zeroizing payload
    let req = HandoffRequest::RotateKeyWithSecret {
        preauth_key: canary.to_owned(),
    };
    assert!(!format!("{req:?}").contains(canary));
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_sink_writer_pipe_validation_and_cli_binary_args() {
    use std::fs;
    use tempfile::tempdir;

    let Ok(dir) = tempdir() else {
        return;
    };
    let dest = dir.path().join("archive.tar");
    assert!(fs::write(&dest, b"existing-valid-tar").is_ok());

    // Oversize & 0-byte rejected
    assert!(mesh_sys::gui_windows::UnprivilegedSinkWriter::create(&dest, 0).is_err());
    assert!(
        mesh_sys::gui_windows::UnprivilegedSinkWriter::create(
            &dest,
            u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(20_971_520) + 1
        )
        .is_err()
    );

    // Aborted UnprivilegedSinkWriter keeps prior archive intact and removes .part
    let writer_res = mesh_sys::gui_windows::UnprivilegedSinkWriter::create(&dest, 8);
    assert!(writer_res.is_ok(), "sink create failed: {writer_res:?}");
    if let Ok(mut w) = writer_res {
        let part_path = w.temp_path().to_path_buf();
        assert!(w.write_chunk(b"1234").is_ok());
        drop(w);
        assert!(!part_path.exists());
        assert_eq!(
            fs::read(&dest).ok().as_deref(),
            Some(&b"existing-valid-tar"[..])
        );
    }

    // Completed UnprivilegedSinkWriter replaces atomically
    if let Ok(mut w2) = mesh_sys::gui_windows::UnprivilegedSinkWriter::create(&dest, 8) {
        assert!(w2.write_chunk(b"12345678").is_ok());
        assert!(matches!(w2.finalize(), Ok(8)));
        assert_eq!(fs::read(&dest).ok().as_deref(), Some(&b"12345678"[..]));
    }

    // MeshVPN.exe rejects invalid CLI flags cleanly without hanging
    if let Some(bin_path) = option_env!("CARGO_BIN_EXE_MeshVPN") {
        let bad_arg = Command::new(bin_path).arg("--unknown-flag").status();
        assert!(bad_arg.is_ok());
        if let Ok(st) = bad_arg {
            assert!(!st.success());
        }
        let bad_pipe = Command::new(bin_path)
            .args(["--elevated-worker", "--pipe", r"\\.\pipe\mesh-agent-admin"])
            .status();
        assert!(bad_pipe.is_ok());
        if let Ok(st) = bad_pipe {
            assert!(!st.success());
        }
    }
}

proptest! {
    #[test]
    fn prop_sanitize_gui_log_never_emits_preauth_canary(token in "[a-zA-Z0-9]{8,24}") {
        let secret = format!("mesh_pak_{token}");
        let raw = format!("error preauth_key={secret} json={{\"preauth_key\":\"{secret}\"}}");
        let sanitized = sanitize_gui_log_text(&raw);
        prop_assert!(!sanitized.contains(&secret));
    }

    #[test]
    fn prop_semver_pack_roundtrips(major in 0_u8..=99, minor in 0_u8..=99, patch in 0_u8..=99) {
        let s = format!("{major}.{minor}.{patch}");
        let parsed = SemVerTriple::parse(&s);
        prop_assert!(parsed.is_some());
        if let Some(v) = parsed {
            let packed = v.pack_u32();
            prop_assert_eq!(SemVerTriple::unpack_u32(packed), v);
        }
    }
}
