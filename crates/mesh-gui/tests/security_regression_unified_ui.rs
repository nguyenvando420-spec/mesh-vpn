//! Unified UI Security Invariants Preservation Regression Suite (`WP-U-E0`, `US-133`, `UUI-34`).
//!
//! Independently verifies that all Wave U-A..U-D UI refactorings (`US-118..US-139`) preserve
//! 100% of Mesh VPN's security invariants across Windows, macOS, Android, and iOS:
//! 1. `test_no_secrets_in_outputs` (`SEC-01`)
//! 2. `test_clipboard_secret_guard_timer_active_for_mpk_only` (`SEC-01`, `IG-DGUI-WA-01`)
//! 3. `test_clipboard_no_secret_guard_on_ip_copy` (`US-121`, `ADR-030` §4)
//! 4. `test_android_flag_secure_scope_not_peers_tab` (`US-119`, `US-121`, `ADR-030`)
//! 5. `test_ios_biometric_authorizer_unmodified` (`US-133`, `ADR-018`)
//! 6. `test_mgh1_handoff_no_mpk_in_argv` (`D-GNFR-02`, `ADR-020`, `ADR-021`)
//! 7. `test_agent_status_response_13_fields` (`ADR-031`, `US-039`)
//! 8. `test_sec05_auth_failed_wire_en_all_platforms` (`SEC-05`, `UUI-21`)
//! 9. `test_prefs_no_secrets_in_ui_prefs_json` (`ADR-031`, `US-133`)

#[path = "../src/app.rs"]
mod app;
#[path = "../src/clipboard.rs"]
mod clipboard;
#[path = "../src/i18n.rs"]
mod i18n;
#[path = "../src/onboarding.rs"]
mod onboarding;
#[cfg(any(target_os = "windows", target_os = "linux"))]
#[path = "../src/prefs.rs"]
mod prefs;
#[cfg(any(target_os = "windows", target_os = "linux"))]
#[path = "../src/theme.rs"]
mod theme;

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use mesh_core::{
    AppError, ErrorKind, MobileJoinTlsAuth, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin,
    format_join_uri,
};
use mesh_crypto::Secret;
use mesh_net::gui_handoff::{
    HANDOFF_PIPE_PREFIX, HandoffFrame, HandoffResponse, generate_handoff_pipe_name,
    masked_preauth_preview_from_secret, parse_handoff_request_payload, validate_handoff_pipe_name,
    zeroize_handoff_payload,
};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentPeerStatus, AgentStatusResponse, DaemonState, SelfNetworkStatus,
    ServerConnectionStatus, TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use tempfile::tempdir;

use crate::app::{
    ServiceProbeKind, StateProbeInputs, derive_desktop_ui_state, format_user_facing_error,
    sanitize_gui_log_text,
};
use crate::clipboard::{
    CLIPBOARD_WIPE_DELAY_MS, ClipboardSecretGuard, CopyKind, format_copy_toast,
    looks_like_sensitive_paste,
};
use crate::i18n::{LocaleMode, t_for};
use crate::onboarding::{
    ConfirmActionKind, OnboardingFormInput, OnboardingTlsMode, parse_mesh_join_uri_to_draft,
    should_lock_system_ca_for_endpoint, validate_manual_onboarding_to_draft,
    validate_rotate_key_to_draft, validate_update_server_payload,
};
#[cfg(any(target_os = "windows", target_os = "linux"))]
use crate::prefs::{
    UI_PREFS_FILENAME, UiPrefs, load_prefs_from_path, prefs_path_from_base, save_prefs_to_path,
};
#[cfg(any(target_os = "windows", target_os = "linux"))]
use crate::theme::ThemeMode;

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed resolving workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn read_repo_file(rel_path: &str) -> Result<String, String> {
    let root = workspace_root()?;
    let full = root.join(rel_path);
    fs::read_to_string(&full).map_err(|err| format!("failed reading {}: {err}", full.display()))
}

fn sample_full_status(last_error: Option<&str>) -> Result<AgentStatusResponse, String> {
    let pin =
        SpkiPin::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .map_err(|err| err.to_string())?;
    let node_name = NodeName::parse("sec-audit-node").map_err(|err| err.to_string())?;
    let peer_name = NodeName::parse("peer-alpha").map_err(|err| err.to_string())?;
    let local_ip =
        OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 10)).map_err(|err| err.to_string())?;
    let peer_ip =
        OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 11)).map_err(|err| err.to_string())?;
    let cidr = OverlayCidr::parse("100.64.0.0/10").map_err(|err| err.to_string())?;

    Ok(AgentStatusResponse {
        daemon_state: DaemonState::Connected,
        node_id: Some(NodeId::from_bytes([0x5a_u8; 16])),
        node_name: Some(node_name),
        fqdn: Some("sec-audit-node.mesh.internal".to_owned()),
        overlay_ip: Some(local_ip),
        overlay_cidr: Some(cidr),
        tun_interface_name: Some("MeshVPN".to_owned()),
        tun_mtu: 1420,
        netmap_version: 12,
        key_expires_at_ms: Some(1_950_000_000_000),
        server_connection: Some(ServerConnectionStatus {
            control_endpoint: "198.51.100.10:8443".to_owned(),
            relay_endpoint: "198.51.100.10:8443".to_owned(),
            stun_endpoints: vec!["198.51.100.10:3478".to_owned()],
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(pin),
            next_pin: None,
            control_connected: true,
            relay_connected: true,
            relay_rtt_ms: Some(11),
            migration_pending_endpoint: None,
            last_error: last_error.map(ToOwned::to_owned),
        }),
        self_network: SelfNetworkStatus {
            local_udp_port: 51820,
            bound_physical_interface: Some("Ethernet".to_owned()),
            nat_type: NatMappingKind::EimOrAdm,
            nat_classification_note: Some("single STUN probe".to_owned()),
            overlay_conflict_warning: None,
            macos_firewall_warning: None,
            candidates: Vec::new(),
        },
        peers: vec![AgentPeerStatus {
            node_id: NodeId::from_bytes([0x7b_u8; 16]),
            name: peer_name,
            fqdn: "peer-alpha.mesh.internal".to_owned(),
            overlay_ip: peer_ip,
            online: true,
            active_path: ActivePathKind::Direct,
            direct_endpoint: Some("203.0.113.44:51820".to_owned()),
            rtt_ms: Some(8),
            last_handshake_at_ms: Some(1_730_000_000_000),
            rx_bytes: 4096,
            tx_bytes: 8192,
        }],
    })
}

#[test]
fn test_no_secrets_in_outputs() -> Result<(), String> {
    // Arrange: realistic pre-auth token, join URI, and simulated private key material (`SEC-01`)
    let canary_mpk = "mpk_U0VDVVJJVFlfUkVHUkVTU0lPTl9VSUlfQ0FOQVJZXzRPTl9a";
    let canary_priv = "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
    let pin_str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let pin = SpkiPin::parse(pin_str).map_err(|err| err.to_string())?;
    let secret = Secret::new(canary_mpk.to_owned());
    let priv_secret = Secret::new(canary_priv.to_owned());

    // Act: format Debug/Display/summaries/logs/errors across all UI state paths
    assert!(should_lock_system_ca_for_endpoint("198.51.100.10:8443"));
    let form = OnboardingFormInput {
        endpoint_raw: "198.51.100.10:8443".to_owned(),
        tls_mode: OnboardingTlsMode::SpkiPin,
        spki_pin_raw: pin_str.to_owned(),
        preauth_key_raw: canary_mpk.to_owned(),
        node_name_raw: "uui-sec-node".to_owned(),
    };
    let draft = validate_manual_onboarding_to_draft(&form)?;
    assert_eq!(draft.action_kind, ConfirmActionKind::EnrollNewNode);

    let join_uri = format_join_uri(
        "198.51.100.10:8443",
        &MobileJoinTlsAuth::SpkiPin(pin),
        canary_mpk,
        None,
    )
    .map_err(|err| err.to_string())?;
    let (uri_form, uri_draft) = parse_mesh_join_uri_to_draft(&join_uri, "uui-uri-node")?;
    let rot_draft = validate_rotate_key_to_draft(
        "198.51.100.10:8443",
        OnboardingTlsMode::SpkiPin,
        Some(pin),
        canary_mpk,
    )?;
    assert_eq!(rot_draft.action_kind, ConfirmActionKind::RotateKey);

    let guard = ClipboardSecretGuard::arm(42, canary_mpk);
    let scrubbed_log = sanitize_gui_log_text(&format!(
        "event=enroll uri={join_uri} preauth_key={canary_mpk} token={canary_mpk}"
    ));
    let dirty_status = sample_full_status(Some(&format!("rejected key={canary_mpk}")))?;
    let derived = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.4.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&dirty_status),
        version_status: None,
        ipc_error: None,
        active_action_error: Some(&format!("failed with {join_uri}")),
    });

    // Assert: 0 canary leaks in any Rust formatting, Debug, summary, or error output
    for output in [
        format!("{secret:?}"),
        format!("{secret}"),
        format!("{priv_secret:?}"),
        format!("{priv_secret}"),
        masked_preauth_preview_from_secret(&secret),
        format!("{form:?}"),
        format!("{uri_form:?}"),
        format!("{draft:?}"),
        format!("{uri_draft:?}"),
        format!("{rot_draft:?}"),
        draft.format_confirmation_summary(),
        uri_draft.format_confirmation_summary(),
        rot_draft.format_confirmation_summary(),
        format!("{guard:?}"),
        scrubbed_log,
        derived.recoverable_error.unwrap_or_default(),
    ] {
        assert!(
            !output.contains(canary_mpk),
            "SEC-01 leak of mpk_* canary in output: {output}"
        );
        assert!(
            !output.contains(canary_priv),
            "SEC-01 leak of private key canary in output: {output}"
        );
    }

    #[cfg(target_os = "windows")]
    {
        let vi_summary =
            draft.format_confirmation_summary_localized(|key| t_for(key, LocaleMode::Vi));
        assert!(!vi_summary.contains(canary_mpk));
    }

    // Assert: cross-platform scrubbers & CharArray zeroization remain intact on macOS/Android/iOS
    let mac_state = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/DesktopUiState.swift",
    )?;
    let android_logger = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/data/diagnostics/SafeLogger.kt",
    )?;
    let android_vm = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/MeshMainViewModel.kt",
    )?;
    let ios_scrubber = read_repo_file("mobile/ios/MeshCoreKit/Sources/MeshLogger.swift")?;

    assert!(mac_state.contains("public enum MeshSecretScrubber: Sendable"));
    assert!(mac_state.contains("secret=[REDACTED]"));
    assert!(android_logger.contains("mpk_"));
    assert!(android_vm.contains("rawPreauthKey.fill('\\u0000')"));
    assert!(ios_scrubber.contains("MeshSecretScrubber"));

    Ok(())
}

#[test]
fn test_clipboard_secret_guard_timer_active_for_mpk_only() -> Result<(), String> {
    // Arrange
    let mpk_token = "mpk_Q0xJUEJPQVJEX1NFQ1JFVF9HVUFSRF9PTkxZXzMwU19XSVBF";
    let join_uri = "mesh://join?v=1&ep=198.51.100.10:8443&pin=system-ca&key=mpk_secret";
    let win_window = read_repo_file("crates/mesh-gui/src/window.rs")?;
    let mac_clip = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Security/ClipboardAutoClear.swift",
    )?;
    let mac_defaults = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/DesktopUiState.swift",
    )?;

    // Act & Assert: 30s delay constant + sensitive credential classification
    assert_eq!(CLIPBOARD_WIPE_DELAY_MS, 30_000);
    assert!(looks_like_sensitive_paste(mpk_token));
    assert!(looks_like_sensitive_paste(join_uri));
    assert!(!looks_like_sensitive_paste("hello mesh peers"));

    // Behavioral sequence + constant-time SHA-256 verification
    let mut guard = ClipboardSecretGuard::arm(512, mpk_token);
    assert!(guard.is_armed());
    assert_eq!(guard.expected_seq(), 512);
    assert!(guard.matches_text(mpk_token));
    assert!(!guard.matches_text("100.64.0.10"));

    // Different clipboard sequence number (user copied something else) -> must NOT wipe
    let mut overwritten_guard = guard.clone();
    assert!(!overwritten_guard.evaluate_clear(513, Some(mpk_token)));
    assert!(!overwritten_guard.is_armed());

    // Matching sequence + matching SHA-256 -> wipes once and disarms
    assert!(guard.evaluate_clear(512, Some(mpk_token)));
    assert!(!guard.is_armed());

    // Assert: `window.rs` arms `TIMER_CLIPBOARD_WIPE` exclusively inside `arm_clipboard_wipe`,
    // called only on secret paste (`trigger_paste_uri_button` + `IDC_EDIT_PREAUTH` paste guard).
    assert!(
        win_window
            .contains("set_window_timer(st.hwnd, TIMER_CLIPBOARD_WIPE, CLIPBOARD_WIPE_DELAY_MS);")
    );
    assert!(win_window.contains("focused_control_id == IDC_EDIT_PREAUTH"));
    assert!(win_window.contains("looks_like_sensitive_paste(&text)"));
    assert_eq!(
        win_window.matches("arm_clipboard_wipe(").count(),
        3,
        "expected 1 fn definition + 2 secret-paste call sites for arm_clipboard_wipe"
    );
    assert!(mac_defaults.contains("clipboardWipeDelaySeconds: TimeInterval = 30.0"));
    assert!(mac_clip.contains("recordedChangeCount"));

    Ok(())
}

#[test]
fn test_clipboard_no_secret_guard_on_ip_copy() -> Result<(), String> {
    // Arrange: arm a live `ClipboardSecretGuard` for an `mpk_*` secret first (`ADR-030` §4)
    let mpk_secret = "mpk_PREAUTH_SECRET_MUST_NOT_BE_CANCELED_BY_IP_COPY";
    let mut secret_guard = ClipboardSecretGuard::arm(888, mpk_secret);
    let win_window = read_repo_file("crates/mesh-gui/src/window.rs")?;
    let mac_peers = read_repo_file("desktop/macos/MeshVPNApp/Sources/PeersTableView.swift")?;
    let android_peers = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/peers/PeersScreen.kt",
    )?;
    let ios_peers = read_repo_file("mobile/ios/MeshApp/Sources/PeersView.swift")?;

    // Act: trigger non-secret Overlay IP and FQDN copy toast builders (`US-121`)
    let ip_toast = format_copy_toast(CopyKind::OverlayIp, "100.64.0.25");
    let fqdn_toast = format_copy_toast(CopyKind::Fqdn, "db-primary.mesh.internal");

    // Assert: neither IP nor FQDN copy activates `uses_secret_guard` or cancels `secret_guard`
    assert!(!ip_toast.uses_secret_guard);
    assert!(!fqdn_toast.uses_secret_guard);
    assert!(ip_toast.body.contains("100.64.0.25"));
    assert!(fqdn_toast.body.contains("db-primary.mesh.internal"));
    assert!(secret_guard.is_armed());
    assert_eq!(secret_guard.expected_seq(), 888);
    assert!(secret_guard.evaluate_clear(888, Some(mpk_secret)));
    secret_guard.disarm();
    assert!(!secret_guard.is_armed());

    // Assert: Windows `IDC_BTN_COPY_PEER_IP | IDC_BTN_COPY_PEER_FQDN` handler never touches
    // `ClipboardSecretGuard` or `TIMER_CLIPBOARD_WIPE`.
    let copy_pos = win_window
        .find("(IDC_BTN_COPY_PEER_IP | IDC_BTN_COPY_PEER_FQDN, WIN_BN_CLICKED)")
        .ok_or_else(|| "missing peer copy handler in window.rs".to_owned())?;
    let copy_snippet = win_window
        .get(copy_pos..(copy_pos + 900).min(win_window.len()))
        .unwrap_or("");
    assert!(copy_snippet.contains("copy_non_secret_peer_value(kind, &value)"));
    assert!(!copy_snippet.contains("ClipboardSecretGuard"));
    assert!(!copy_snippet.contains("TIMER_CLIPBOARD_WIPE"));
    assert!(!copy_snippet.contains("arm_clipboard_wipe"));

    // Assert: macOS, Android, and iOS Peers copy paths never invoke 30s secret wipe timers
    assert!(mac_peers.contains("private func copyToPasteboard("));
    assert!(!mac_peers.contains("ClipboardAutoClear"));
    assert!(!mac_peers.contains("clipboardWipeDelaySeconds"));

    assert!(android_peers.contains("ClipData.newPlainText(label, value)"));
    assert!(!android_peers.contains("readPrimaryTextAndClear"));
    assert!(!android_peers.contains("ClipboardAccess"));

    assert!(ios_peers.contains("viewModel.copyNonSecretAddress(value)"));
    assert!(!ios_peers.contains("scheduleClipboardRedactionIfMatching"));

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AndroidTabMirror {
    Status,
    Peers,
    Settings,
}

const fn eval_android_require_flag_secure(
    is_enrolled: bool,
    has_pending_confirmation: bool,
    active_tab: AndroidTabMirror,
    is_admin_pins_revealed: bool,
    is_sensitive_modal_open: bool,
) -> bool {
    !is_enrolled
        || has_pending_confirmation
        || (matches!(active_tab, AndroidTabMirror::Settings)
            && (is_admin_pins_revealed || is_sensitive_modal_open))
}

#[test]
fn test_android_flag_secure_scope_not_peers_tab() -> Result<(), String> {
    // Arrange
    let vm_kt = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/MeshMainViewModel.kt",
    )?;
    let main_activity_kt =
        read_repo_file("mobile/android/app/src/main/kotlin/dev/meshvpn/android/MainActivity.kt")?;
    let peers_kt = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/peers/PeersScreen.kt",
    )?;

    // Act & Assert 1: Exhaustive truth table for enrolled user on `Peers` tab (`US-119`, `US-121`)
    for pins_revealed in [false, true] {
        for modal_open in [false, true] {
            assert!(
                !eval_android_require_flag_secure(
                    true,
                    false,
                    AndroidTabMirror::Peers,
                    pins_revealed,
                    modal_open,
                ),
                "FLAG_SECURE must NEVER activate on enrolled Peers tab"
            );
        }
    }
    // Onboarding (!isEnrolled), confirmation modal, and Settings pin reveal MUST still activate it
    assert!(eval_android_require_flag_secure(
        false,
        false,
        AndroidTabMirror::Status,
        false,
        false,
    ));
    assert!(eval_android_require_flag_secure(
        true,
        true,
        AndroidTabMirror::Peers,
        false,
        false,
    ));
    assert!(eval_android_require_flag_secure(
        true,
        false,
        AndroidTabMirror::Settings,
        true,
        false,
    ));

    // Assert 2: Verify exact Kotlin formula in `MeshMainViewModel.kt` and `MainActivity.kt`
    assert!(vm_kt.contains("val requireFlagSecure: Boolean"));
    assert!(vm_kt.contains("!session.isEnrolled ||"));
    assert!(vm_kt.contains("pendingConfirmation != null ||"));
    assert!(vm_kt.contains("activeTab == MainTab.SETTINGS &&"));
    assert!(vm_kt.contains("(isAdminPinsRevealed || isSensitiveModalOpen)"));

    // Navigating away from SETTINGS (e.g. SETTINGS -> PEERS) auto-locks `isAdminPinsRevealed`
    let select_tab_pos = vm_kt
        .find("fun selectTab(tab: MainTab)")
        .ok_or_else(|| "missing selectTab in MeshMainViewModel.kt".to_owned())?;
    let select_tab_body = vm_kt
        .get(select_tab_pos..(select_tab_pos + 420).min(vm_kt.len()))
        .unwrap_or("");
    assert!(select_tab_body.contains("val onSettings = tab == MainTab.SETTINGS"));
    assert!(select_tab_body.contains("val keepReveal = onSettings && current.isAdminPinsRevealed"));
    assert!(select_tab_body.contains("isAdminPinsRevealed = keepReveal"));

    assert!(main_activity_kt.contains("LaunchedEffect(screenState.requireFlagSecure)"));
    assert!(main_activity_kt.contains("WindowManager.LayoutParams.FLAG_SECURE"));
    assert!(!peers_kt.contains("WindowManager.LayoutParams.FLAG_SECURE"));

    Ok(())
}

#[test]
fn test_ios_biometric_authorizer_unmodified() -> Result<(), String> {
    // Arrange
    let bio_swift = read_repo_file("mobile/ios/MeshApp/Sources/BiometricAuthorizer.swift")?;
    let actions_swift = read_repo_file("mobile/ios/MeshApp/Sources/AppViewModel+Actions.swift")?;

    // Act & Assert: `BiometricAuthorizer.swift` preserves LAContext `.deviceOwnerAuthentication`
    // (Face ID / Touch ID / Passcode fallback) and `MeshSecretScrubber.scrub(...)`
    assert!(bio_swift.contains("public enum BiometricAuthOutcome: Sendable, Equatable"));
    assert!(bio_swift.contains("case authorized"));
    assert!(bio_swift.contains("case cancelled"));
    assert!(bio_swift.contains("case unavailable(String)"));
    assert!(bio_swift.contains("case failed(String)"));
    assert!(bio_swift.contains("public protocol BiometricAuthorizing: Sendable"));
    assert!(
        bio_swift
            .contains("public struct LocalAuthBiometricAuthorizer: BiometricAuthorizing, Sendable")
    );
    assert!(bio_swift.contains("context.canEvaluatePolicy(.deviceOwnerAuthentication"));
    assert!(bio_swift.contains("try await context.evaluatePolicy("));
    assert!(bio_swift.contains(".deviceOwnerAuthentication,"));
    assert!(bio_swift.contains("case .userCancel, .systemCancel, .appCancel:"));
    assert!(bio_swift.contains("MeshSecretScrubber.scrub("));

    // Assert: all 4 sensitive iOS operations remain gated by `biometricAuthorizer.authorize(...)`
    assert_eq!(
        actions_swift
            .matches("await biometricAuthorizer.authorize(")
            .count(),
        4,
        "expected 4 biometric-gated operations (rotate key, update server, bugreport, reset)"
    );

    Ok(())
}

#[test]
fn test_mgh1_handoff_no_mpk_in_argv() -> Result<(), String> {
    // Arrange (`D-GNFR-02`, `SEC-01`, `ADR-021`)
    let canary_mpk = "mpk_SEFORFBGRl9OT19BUkdWX0xFQUTFXzAxMjM0NTY3ODkwMTIz";
    let pin_str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let form = OnboardingFormInput {
        endpoint_raw: "198.51.100.10:8443".to_owned(),
        tls_mode: OnboardingTlsMode::SpkiPin,
        spki_pin_raw: pin_str.to_owned(),
        preauth_key_raw: canary_mpk.to_owned(),
        node_name_raw: "argv-guard-node".to_owned(),
    };
    let worker_rs = read_repo_file("crates/mesh-gui/src/elevation_worker.rs")?;
    let gui_win_rs = read_repo_file("crates/mesh-sys/src/gui_windows.rs")?;

    // Act 1: verify pipe name allowlist & payload framing keep `mpk_*` inside pipe bytes only
    let pipe_name = generate_handoff_pipe_name();
    assert!(pipe_name.starts_with(HANDOFF_PIPE_PREFIX));
    assert!(!pipe_name.contains("mpk_"));
    assert!(validate_handoff_pipe_name(&pipe_name).is_ok());

    let draft = validate_manual_onboarding_to_draft(&form)?;
    let mut payload = draft.build_handoff_payload()?;
    let frame = HandoffFrame::HandoffRequest(payload.clone());
    assert!(!format!("{frame:?}").contains(canary_mpk));
    let parsed_req =
        parse_handoff_request_payload(payload.as_slice()).map_err(|err| err.to_string())?;
    assert!(!format!("{parsed_req:?}").contains(canary_mpk));
    zeroize_handoff_payload(&mut payload);
    assert!(payload.is_empty());

    let (norm_ep, mut set_payload) =
        validate_update_server_payload("198.51.100.10:8443", OnboardingTlsMode::SpkiPin, pin_str)?;
    assert_eq!(norm_ep, "198.51.100.10:8443");
    zeroize_handoff_payload(&mut set_payload);
    assert!(set_payload.is_empty());

    // Act 2 & Assert: `elevation_worker.rs::parse_gui_launch_args` accepts ONLY `--minimized`
    // and `--elevated-worker --pipe <pipe>`, rejecting any `--preauth-key` / `mpk_*` argv flags.
    assert!(worker_rs.contains("\"--minimized\" => start_minimized = true"));
    assert!(worker_rs.contains("\"--elevated-worker\" => elevated_worker = true"));
    assert!(worker_rs.contains("\"--pipe\" | \"--handoff-pipe\""));
    assert!(worker_rs.contains("other => return Err(format!(\"unsupported argument `{other}`\"))"));
    assert!(!worker_rs.contains("\"--preauth-key\""));
    assert!(!worker_rs.contains("\"--key\""));

    // Assert: `gui_windows.rs::launch_elevated_worker` passes ONLY `--elevated-worker --handoff-pipe`
    let launch_pos = gui_win_rs
        .find("pub fn launch_elevated_worker(")
        .ok_or_else(|| "missing launch_elevated_worker in gui_windows.rs".to_owned())?;
    let launch_body = gui_win_rs
        .get(launch_pos..(launch_pos + 1_400).min(gui_win_rs.len()))
        .unwrap_or("");
    let expected_argv = "format!(\"--elevated-worker --handoff-pipe {handoff_pipe_name}\")";
    assert!(launch_body.contains("!is_valid_handoff_pipe_name(handoff_pipe_name)"));
    assert!(launch_body.contains(expected_argv));
    assert!(launch_body.contains("contains_shell_metacharacters(&params)"));
    assert!(!launch_body.contains("mpk_"));
    assert!(!launch_body.contains("preauth"));

    Ok(())
}

#[test]
fn test_agent_status_response_13_fields() -> Result<(), String> {
    // Arrange (`ADR-031`, `US-133 AC2`)
    let status = sample_full_status(None)?;
    let expected_keys: BTreeSet<&str> = BTreeSet::from([
        "daemon_state",
        "node_id",
        "node_name",
        "fqdn",
        "overlay_ip",
        "overlay_cidr",
        "tun_interface_name",
        "tun_mtu",
        "netmap_version",
        "key_expires_at_ms",
        "server_connection",
        "self_network",
        "peers",
    ]);

    // Act: serialize -> inspect JSON object keys -> round-trip deserialize
    let val = serde_json::to_value(&status).map_err(|err| err.to_string())?;
    let obj = val
        .as_object()
        .ok_or_else(|| "AgentStatusResponse did not serialize as JSON object".to_owned())?;
    let actual_keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let roundtrip: AgentStatusResponse =
        serde_json::from_value(val.clone()).map_err(|err| err.to_string())?;

    // Assert 1: exact 13 fields, 100% round-trip equality
    assert_eq!(
        obj.len(),
        13,
        "AgentStatusResponse must have exactly 13 fields"
    );
    assert_eq!(actual_keys, expected_keys);
    assert_eq!(roundtrip, status);

    // Assert 2: `#[serde(deny_unknown_fields)]` rejects any UI-only field injection
    for forbidden_ui_field in ["locale", "theme", "display_label"] {
        let mut mutated = val.clone();
        if let Some(map) = mutated.as_object_mut() {
            let _prev = map.insert(
                forbidden_ui_field.to_owned(),
                serde_json::Value::String("vi".to_owned()),
            );
        }
        assert!(
            serde_json::from_value::<AgentStatusResponse>(mutated).is_err(),
            "AgentStatusResponse must reject unknown field `{forbidden_ui_field}`"
        );
    }

    // Assert 3: macOS Swift `AgentStatusResponse` (`AgentIpcModels.swift`) matches all 13 wire keys
    let mac_ipc_swift = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/AgentIpcModels.swift",
    )?;
    let status_struct_pos = mac_ipc_swift
        .find("public struct AgentStatusResponse: Codable")
        .ok_or_else(|| "missing AgentStatusResponse in AgentIpcModels.swift".to_owned())?;
    let status_struct_body = mac_ipc_swift
        .get(status_struct_pos..(status_struct_pos + 1_300).min(mac_ipc_swift.len()))
        .unwrap_or("");
    for wire_key in &expected_keys {
        assert!(
            status_struct_body.contains(wire_key),
            "macOS AgentStatusResponse CodingKeys missing `{wire_key}`"
        );
    }
    assert!(!status_struct_body.contains("mesh_locale_mode"));
    assert!(!status_struct_body.contains("mesh_theme_mode"));

    Ok(())
}

#[test]
fn test_sec05_auth_failed_wire_en_all_platforms() -> Result<(), String> {
    // Arrange (`SEC-05`, `UUI-21`): wire-level unauthenticated string must stay exact English
    let canary = "mpk_U0VDMDVfQVVUSF9GQUlMRURfQ0FOQVJZX1RPS0VOXzEyMzQ1";
    let mac_en = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Resources/en.lproj/Localizable.strings",
    )?;
    let mac_vi = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Resources/vi.lproj/Localizable.strings",
    )?;
    let android_mapper = read_repo_file(
        "mobile/android/app/src/main/kotlin/dev/meshvpn/android/ffi/FfiErrorMapper.kt",
    )?;
    let android_en = read_repo_file("mobile/android/app/src/main/res/values/strings.xml")?;
    let android_vi = read_repo_file("mobile/android/app/src/main/res/values-vi/strings.xml")?;
    let ios_mapper = read_repo_file("mobile/ios/MeshCoreKit/Sources/MeshErrorMapper.swift")?;
    let ios_xcstrings = read_repo_file("mobile/ios/MeshApp/Resources/Localizable.xcstrings")?;

    // Act: evaluate Rust core + Windows GUI + MGH1 handoff + i18n tables
    let app_err = AppError::unauthenticated(format!("bad preauth key {canary}"));
    let handoff_err = HandoffResponse::from_error(&app_err)
        .into_action_result()
        .err()
        .ok_or_else(|| "expected Err from HandoffResponse".to_owned())?;
    let win_ui_err = format_user_facing_error(&format!("Unauthenticated: {canary}"));

    // Assert 1: Windows / Rust
    assert_eq!(app_err.kind(), ErrorKind::Unauthenticated);
    assert_eq!(app_err.to_string(), "authentication failed");
    assert_eq!(handoff_err.kind(), ErrorKind::Unauthenticated);
    assert_eq!(handoff_err.to_string(), "authentication failed");
    assert_eq!(win_ui_err, "authentication failed");
    assert_eq!(
        t_for("error.auth_failed", LocaleMode::En),
        "authentication failed"
    );
    assert_eq!(
        t_for("error.auth_failed", LocaleMode::Vi),
        "authentication failed"
    );
    assert_eq!(
        t_for("error.auth_failed", LocaleMode::System),
        "authentication failed"
    );

    // Assert 2: macOS (`en.lproj` & `vi.lproj`)
    assert!(mac_en.contains("\"error.auth_failed\" = \"authentication failed\";"));
    assert!(mac_vi.contains("\"error.auth_failed\" = \"authentication failed\";"));

    // Assert 3: Android (`FfiErrorMapper.kt` + `values/strings.xml` + `values-vi/strings.xml`)
    assert!(android_mapper.contains("AUTH_FAILED_PUBLIC = \"authentication failed\""));
    assert!(
        android_en.contains("<string name=\"error_auth_failed\">authentication failed</string>")
    );
    assert!(
        android_vi.contains("<string name=\"error_auth_failed\">authentication failed</string>")
    );

    // Assert 4: iOS (`MeshErrorMapper.swift` + `Localizable.xcstrings` JSON parse)
    assert!(ios_mapper.contains("case .Unauthenticated(let code, _):"));
    assert!(ios_mapper.contains("message: \"authentication failed\""));
    let xcstrings_val: serde_json::Value =
        serde_json::from_str(&ios_xcstrings).map_err(|err| err.to_string())?;
    let ios_en_val = xcstrings_val
        .pointer("/strings/error.auth_failed/localizations/en/stringUnit/value")
        .and_then(serde_json::Value::as_str);
    let ios_vi_val = xcstrings_val
        .pointer("/strings/error.auth_failed/localizations/vi/stringUnit/value")
        .and_then(serde_json::Value::as_str);
    assert_eq!(ios_en_val, Some("authentication failed"));
    assert_eq!(ios_vi_val, Some("authentication failed"));

    Ok(())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
#[test]
fn test_prefs_no_secrets_in_ui_prefs_json() -> Result<(), String> {
    // Arrange (`ADR-031`, `US-133`): user-space `ui-prefs.json` may ONLY store
    // `"theme"` in `{"system","light","dark"}` and `"locale"` in `{"system","en","vi"}`.
    let dir = tempdir().map_err(|err| err.to_string())?;
    let prefs_path = prefs_path_from_base(Some(dir.path()))
        .ok_or_else(|| "failed building ui-prefs.json path".to_owned())?;
    assert_eq!(
        prefs_path.file_name().and_then(|n| n.to_str()),
        Some(UI_PREFS_FILENAME)
    );

    let allowed_themes = ["system", "light", "dark"];
    let allowed_locales = ["system", "en", "vi"];

    // Act & Assert 1: test all 9 `(ThemeMode, LocaleMode)` combinations
    for theme in [ThemeMode::System, ThemeMode::Light, ThemeMode::Dark] {
        for locale in [LocaleMode::System, LocaleMode::En, LocaleMode::Vi] {
            let input = UiPrefs { theme, locale };
            save_prefs_to_path(&prefs_path, &input).map_err(|err| err.to_string())?;
            let raw = fs::read_to_string(&prefs_path).map_err(|err| err.to_string())?;

            let parsed_json: serde_json::Value =
                serde_json::from_str(&raw).map_err(|err| err.to_string())?;
            let obj = parsed_json
                .as_object()
                .ok_or_else(|| "ui-prefs.json is not a JSON object".to_owned())?;

            assert_eq!(obj.len(), 2, "ui-prefs.json must contain exactly 2 keys");
            let theme_str = obj
                .get("theme")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing string `theme` in ui-prefs.json".to_owned())?;
            let locale_str = obj
                .get("locale")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing string `locale` in ui-prefs.json".to_owned())?;

            assert!(allowed_themes.contains(&theme_str));
            assert!(allowed_locales.contains(&locale_str));
            for forbidden in ["mpk_", "sha256:", "mesh://", "preauth", "privkey", "secret"] {
                assert!(
                    !raw.contains(forbidden),
                    "forbidden token `{forbidden}` in ui-prefs.json: {raw}"
                );
            }
            assert_eq!(load_prefs_from_path(&prefs_path), input);
        }
    }

    // Act & Assert 2: secret-stuffed invalid enum value in `ui-prefs.json` is deleted & reset
    fs::write(&prefs_path, r#"{"theme":"mpk_SECRET_LEAK","locale":"vi"}"#)
        .map_err(|err| err.to_string())?;
    let recovered = load_prefs_from_path(&prefs_path);
    assert_eq!(recovered, UiPrefs::default());
    assert!(
        !prefs_path.exists(),
        "corrupt/secret-stuffed ui-prefs.json must be deleted"
    );

    #[cfg(target_os = "windows")]
    {
        let state = crate::app::DesktopUiState::Connected;
        let sub = crate::app::TunnelSubState::Connected;
        let palette = crate::theme::resolve_palette(recovered.theme);
        assert_ne!(palette.text_primary, palette.bg_color);
        assert_ne!(palette.text_secondary, palette.bg_color);
        assert_ne!(palette.semantic_success, palette.semantic_error);
        assert_ne!(palette.semantic_neutral, 0);
        assert_ne!(palette.on_accent_text_color(), 0);
        let color = palette.semantic_color_for_state(state, sub);
        assert_eq!(color, palette.semantic_success);
        assert!(palette.semantic_brush_for_state(state, sub).is_some());
    }

    Ok(())
}
