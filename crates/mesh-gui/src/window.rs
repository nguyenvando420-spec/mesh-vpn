//! Win32 Dashboard window layout, 3-Zone Navigation (`ADR-028`), GDI/DWM Dark/Light/High-Contrast
//! rendering (`ADR-027`, `ADR-030`), Peers Zone filter chips & Copy IP/FQDN (`US-120`, `US-121`),
//! Zone 3 maintenance modals, atomic clipboard 30s wipe hooks (`IG-DGUI-WA-01`), bugreport
//! `GetSaveFileNameW` -> `PollingSuspensionGuard` ordering (`IG-DGUI-WA-03`), and clean `<= 3s`
//! shutdown (`US-103..108`, `US-118..126`).

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mesh_net::gui_handoff::{HandoffRequest, serialize_handoff_request_zeroizing};
use mesh_proto::agent_ipc::{AgentPeerStatus, AgentStatusResponse, TlsAuthMode};
use mesh_sys::error::{SysError, SysResult};
use mesh_sys::gui_windows::{
    ControlRect, GuiWindowSpec, MessageBoxKind, OwnedGdiObj, OwnedIcon, OwnerDrawButtonStyle,
    OwnerDrawItem, PaintGuard, SingleInstanceGuard, WIN_BN_CLICKED, WIN_EN_CHANGE,
    WIN_LBN_SELCHANGE, WIN_ODS_DISABLED, WIN_ODS_FOCUS, WIN_ODS_SELECTED, WIN_WM_CTLCOLOREDIT,
    WIN_WM_CTLCOLORLISTBOX, WIN_WM_CTLCOLORSTATIC, WIN_WM_LBUTTONDBLCLK, WIN_WM_LBUTTONUP,
    WIN_WM_RBUTTONUP, WM_APP_BUGREPORT_DONE, WM_APP_NETCHECK_DONE, WM_APP_PING_DONE,
    WM_APP_STATE_REFRESH, WM_APP_WORKER_DONE, WindowEventHandler, acquire_single_instance_mutex,
    activate_existing_gui_window, announce_accessible_label, apply_window_dark_titlebar,
    create_button, create_checkbox, create_edit, create_listbox, create_named_shutdown_event,
    create_owner_draw_button, create_radio_button, create_static_text, destroy_window,
    draw_owner_draw_button, enable_per_monitor_v2_dpi, find_window_by_class, get_checkbox_checked,
    get_client_size, get_control_text, get_dpi_for_window, get_sm_icon_px_for_dpi, hide_window,
    init_common_controls, invalidate_window, is_user_autostart_enabled, kill_window_timer,
    listbox_reset_and_fill, listbox_selected_index, post_graceful_shutdown_to_window,
    query_window_version, read_clipboard_utf16_with_seq, register_activate_window_message,
    register_taskbar_created_message, remove_user_shortcuts_and_autostart, run_gui_window,
    save_tar_file_dialog, set_checkbox_checked, set_control_bounds, set_control_enabled,
    set_control_font, set_control_text, set_control_visible, set_dc_text_and_bk_color,
    set_focus_control, set_user_autostart, set_window_icon, set_window_timer, show_message_box,
    show_window_and_focus, signal_shutdown_event, wait_event_signaled,
};
use zeroize::Zeroizing;

use crate::app::{
    DashboardTab, DerivedUiSnapshot, DesktopUiState, ServiceProbeKind, StateProbeInputs,
    TunnelSubState, derive_desktop_ui_state, format_user_facing_error, sanitize_gui_log_text,
};
use crate::autostart::{AUTOSTART_REG_VALUE_NAME, format_autostart_command_line};
use crate::clipboard::{
    CLIPBOARD_WIPE_DELAY_MS, ClipboardSecretGuard, CopyKind, attempt_atomic_clipboard_clear,
    copy_non_secret_peer_value, looks_like_sensitive_paste,
};
use crate::diagnostics_view::{
    DEFAULT_BUGREPORT_FILENAME, format_netcheck_report, format_self_network_panel,
    format_settings_identity_summary,
};
use crate::elevation_worker::resolve_program_files_mesh_dir;
use crate::i18n::{LocaleMode, t};
use crate::icons::{UiIconTone, create_status_icon_for_px, icon_tone_for_state};
use crate::ipc_poller::{BackgroundIpcController, PolledStateUpdate, UiAsyncEvent};
use crate::onboarding::{
    DesktopOnboardingTab, OnboardingFormInput, OnboardingTlsMode, Zone3ModalKind,
    parse_mesh_join_uri_to_draft, should_lock_system_ca_for_endpoint,
    validate_manual_onboarding_to_draft, validate_rotate_key_to_draft,
    validate_update_server_payload,
};
use crate::peers_view::{
    PeerFilterMode, count_peers_by_mode, filter_peers, filter_peers_by_mode, filter_peers_combined,
    format_filter_chip_label, format_peer_detail_summary, format_peer_list_entry,
    format_ping_response,
};
use crate::prefs::{UiPrefs, load_prefs, save_prefs};
use crate::single_instance::{
    MAIN_WINDOW_CLASS_NAME, SemVerTriple, UPGRADE_SHUTDOWN_WAIT_MS, should_request_upgrade_shutdown,
};
use crate::status_view::{build_status_hero_model, paint_status_hero_surface};
use crate::theme::{ThemeMode, UiThemePalette, resolve_palette_for_dpi};
use crate::tray::{
    IDM_CONNECT_UP, IDM_DISCONNECT, IDM_DISCONNECT_AND_QUIT, IDM_EXPORT_BUGREPORT, IDM_NETCHECK,
    IDM_OPEN_DASHBOARD, IDM_QUIT_KEEP_BACKGROUND, IDM_TOGGLE_AUTOSTART, TrayStateManager,
};

// Accessible hidden/proxy status label + Zone 0 CTAs
const IDC_STATUS_TITLE: u16 = 2001;
const IDC_BTN_CONNECT: u16 = 2004;
const IDC_BTN_DISCONNECT: u16 = 2005;
const IDC_BTN_START_REPAIR: u16 = 2006;
const IDC_BTN_CLEANUP: u16 = 2007;
const IDC_BTN_RESET_ID: u16 = 2008;
const IDC_BTN_NETCHECK: u16 = 2009;
const IDC_BTN_BUGREPORT: u16 = 2010;
const IDC_CHK_AUTOSTART: u16 = 2011;
const IDC_BTN_UNINSTALL: u16 = 2012;

// 3-Tab Navigation (`ADR-028`)
const IDC_TAB_STATUS: u16 = 2013;
const IDC_TAB_PEERS: u16 = 2014;
const IDC_TAB_DIAG_SETTINGS: u16 = 2015;

// Zone 3 Maintenance Modal triggers & Theme selectors (`ADR-028`, `ADR-030`)
const IDC_BTN_OPEN_ROTATE_MODAL: u16 = 2016;
const IDC_BTN_OPEN_UPDATE_SERVER_MODAL: u16 = 2017;
const IDC_BTN_MODAL_CANCEL: u16 = 2018;
const IDC_BTN_THEME_SYSTEM: u16 = 2050;
const IDC_BTN_THEME_LIGHT: u16 = 2051;
const IDC_BTN_THEME_DARK: u16 = 2052;
const IDC_LBL_THEME: u16 = 2053;

// Onboarding (2-tab Join URI / Manual) & Zone 3 modal inputs
const IDC_LBL_SETUP: u16 = 2020;
const IDC_BTN_PASTE_URI: u16 = 2021;
const IDC_LBL_ENDPOINT: u16 = 2022;
const IDC_EDIT_ENDPOINT: u16 = 2023;
const IDC_RADIO_SPKI: u16 = 2024;
const IDC_RADIO_SYSTEM_CA: u16 = 2025;
const IDC_LBL_PIN: u16 = 2026;
const IDC_EDIT_PIN: u16 = 2027;
const IDC_LBL_PREAUTH: u16 = 2028;
const IDC_EDIT_PREAUTH: u16 = 2029;
const IDC_LBL_NODENAME: u16 = 2030;
const IDC_EDIT_NODE_NAME: u16 = 2031;
const IDC_BTN_ENROLL_SAVE: u16 = 2032;
const IDC_BTN_UPDATE_SERVER: u16 = 2033;
const IDC_TAB_ONBOARD_URI: u16 = 2034;
const IDC_TAB_ONBOARD_MANUAL: u16 = 2035;

// Zone 2 Peers controls (`US-120`, `US-121`)
const IDC_LBL_PEERS: u16 = 2040;
const IDC_EDIT_PEER_FILTER: u16 = 2041;
const IDC_BTN_PING_PEER: u16 = 2042;
const IDC_LIST_PEERS: u16 = 2043;
const IDC_EDIT_DETAILS: u16 = 2044;
const IDC_BTN_PEER_FILTER_ALL: u16 = 2045;
const IDC_BTN_PEER_FILTER_ONLINE: u16 = 2046;
const IDC_BTN_PEER_FILTER_DIRECT: u16 = 2047;
const IDC_BTN_PEER_FILTER_RELAY: u16 = 2048;
const IDC_BTN_COPY_PEER_IP: u16 = 2054;
const IDC_BTN_COPY_PEER_FQDN: u16 = 2055;

const TIMER_CLIPBOARD_WIPE: usize = 1;
const TIMER_SHUTDOWN_POLL: usize = 2;
const TIMER_TOAST_CLEAR: usize = 3;

const TOAST_DISPLAY_MS: u32 = 4_000;
const BASE_WIN_W: i32 = 860;
const BASE_WIN_H: i32 = 660;

enum SingleInstanceStartup {
    Primary {
        guard: SingleInstanceGuard,
        activate_msg: u32,
    },
    ActivatedExistingAndExit,
}

fn tr_or(key: &str, fallback: &str) -> String {
    let localized = t(key);
    if localized.is_empty() {
        fallback.to_owned()
    } else {
        localized.to_owned()
    }
}

fn negotiate_single_instance_startup() -> SysResult<SingleInstanceStartup> {
    let activate_msg = register_activate_window_message()?;
    if let Some(guard) = acquire_single_instance_mutex()? {
        return Ok(SingleInstanceStartup::Primary {
            guard,
            activate_msg,
        });
    }

    let current_ver = SemVerTriple::parse(env!("CARGO_PKG_VERSION")).unwrap_or(SemVerTriple {
        major: 0,
        minor: 4,
        patch: 0,
    });

    if let Some(hwnd) = find_window_by_class(MAIN_WINDOW_CLASS_NAME) {
        let running_ver = query_window_version(hwnd, 500);
        if should_request_upgrade_shutdown(current_ver, running_ver) {
            let _signaled = signal_shutdown_event();
            post_graceful_shutdown_to_window(hwnd);
            let deadline =
                Instant::now() + Duration::from_millis(u64::from(UPGRADE_SHUTDOWN_WAIT_MS));
            while Instant::now() < deadline {
                if let Some(retry_guard) = acquire_single_instance_mutex()? {
                    return Ok(SingleInstanceStartup::Primary {
                        guard: retry_guard,
                        activate_msg,
                    });
                }
                std::thread::park_timeout(Duration::from_millis(75));
            }
        } else {
            activate_existing_gui_window(hwnd, activate_msg);
            return Ok(SingleInstanceStartup::ActivatedExistingAndExit);
        }
    }

    Ok(SingleInstanceStartup::ActivatedExistingAndExit)
}

fn query_launch_at_login_enabled() -> bool {
    is_user_autostart_enabled(AUTOSTART_REG_VALUE_NAME).unwrap_or(false)
}

fn set_launch_at_login_enabled(enabled: bool) -> SysResult<()> {
    let exe_path =
        std::env::current_exe().map_err(|err| SysError::io("autostart::current_exe", err))?;
    let cmd = format_autostart_command_line(&exe_path);
    set_user_autostart(AUTOSTART_REG_VALUE_NAME, &cmd, enabled)
}

fn cleanup_current_user_autostart_and_shortcuts() -> SysResult<()> {
    remove_user_shortcuts_and_autostart(AUTOSTART_REG_VALUE_NAME)
}

fn read_clipboard_zeroizing_with_seq() -> SysResult<(u32, Option<Zeroizing<String>>)> {
    let (seq, maybe_text) = read_clipboard_utf16_with_seq()?;
    Ok((seq, maybe_text.map(Zeroizing::new)))
}

/// Launches single-instance check, creates the Win32 Dashboard + Tray window, and runs the loop.
pub(crate) fn run_gui_entrypoint(start_minimized: bool) -> Result<(), String> {
    if let Err(err) = enable_per_monitor_v2_dpi() {
        tracing::warn!(
            component = "mesh-gui",
            event = "dpi_awareness_fallback",
            error = %err,
            "failed setting Per-Monitor V2 DPI awareness"
        );
    }
    init_common_controls().map_err(|err| err.to_string())?;

    let SingleInstanceStartup::Primary {
        guard: _single_instance_guard,
        activate_msg,
    } = negotiate_single_instance_startup().map_err(|err| err.to_string())?
    else {
        return Ok(());
    };

    let taskbar_created_msg = register_taskbar_created_message().map_err(|err| err.to_string())?;
    let initial_icon = create_status_icon_for_px(UiIconTone::Gray, 32).ok();

    let state = DashboardApp::new(!start_minimized);
    let spec = GuiWindowSpec {
        class_name: MAIN_WINDOW_CLASS_NAME,
        title: "Mesh VPN",
        width_96dpi: BASE_WIN_W,
        height_96dpi: BASE_WIN_H,
        start_hidden: start_minimized,
        activate_msg,
        taskbar_created_msg,
        initial_icon: initial_icon.as_ref(),
    };

    run_gui_window(spec, &state).map_err(|err| err.to_string())
}

#[derive(Debug, Default)]
struct UiControls {
    status_title: isize,

    // 3-Tab Navigation (`ADR-028`)
    tab_status: isize,
    tab_peers: isize,
    tab_diag_settings: isize,

    // Primary / Zone 1 CTAs
    btn_connect: isize,
    btn_disconnect: isize,
    btn_start_repair: isize,

    // Zone 3 Diagnostics & Settings controls
    btn_netcheck: isize,
    btn_bugreport: isize,
    btn_cleanup: isize,
    btn_reset_id: isize,
    chk_autostart: isize,
    btn_uninstall: isize,
    btn_open_rotate_modal: isize,
    btn_open_update_server_modal: isize,
    lbl_theme: isize,
    btn_theme_system: isize,
    btn_theme_light: isize,
    btn_theme_dark: isize,

    // Onboarding (2-tab) & Zone 3 modal shared inputs
    tab_onboard_uri: isize,
    tab_onboard_manual: isize,
    lbl_setup: isize,
    btn_paste_uri: isize,
    lbl_endpoint: isize,
    edit_endpoint: isize,
    radio_spki: isize,
    radio_system_ca: isize,
    lbl_pin: isize,
    edit_pin: isize,
    lbl_preauth: isize,
    edit_preauth: isize,
    lbl_nodename: isize,
    edit_node_name: isize,
    btn_enroll_save: isize,
    btn_update_server: isize,
    btn_modal_cancel: isize,

    // Zone 2 Peers controls
    lbl_peers: isize,
    edit_peer_filter: isize,
    btn_peer_all: isize,
    btn_peer_online: isize,
    btn_peer_direct: isize,
    btn_peer_relay: isize,
    btn_ping_peer: isize,
    btn_copy_ip: isize,
    btn_copy_fqdn: isize,
    list_peers: isize,
    edit_details: isize,
}

impl UiControls {
    fn all_handles(&self) -> [isize; 41] {
        [
            self.status_title,
            self.tab_status,
            self.tab_peers,
            self.tab_diag_settings,
            self.btn_connect,
            self.btn_disconnect,
            self.btn_start_repair,
            self.btn_netcheck,
            self.btn_bugreport,
            self.btn_cleanup,
            self.btn_reset_id,
            self.chk_autostart,
            self.btn_uninstall,
            self.btn_open_rotate_modal,
            self.btn_open_update_server_modal,
            self.lbl_theme,
            self.btn_theme_system,
            self.btn_theme_light,
            self.btn_theme_dark,
            self.tab_onboard_uri,
            self.tab_onboard_manual,
            self.lbl_setup,
            self.btn_paste_uri,
            self.lbl_endpoint,
            self.edit_endpoint,
            self.radio_spki,
            self.radio_system_ca,
            self.lbl_pin,
            self.edit_pin,
            self.lbl_preauth,
            self.edit_preauth,
            self.lbl_nodename,
            self.edit_node_name,
            self.btn_enroll_save,
            self.btn_update_server,
            self.btn_modal_cancel,
            self.lbl_peers,
            self.edit_peer_filter,
            self.btn_peer_all,
            self.btn_peer_online,
            self.btn_peer_direct,
        ]
    }

    fn extra_peer_handles(&self) -> [isize; 6] {
        [
            self.btn_peer_relay,
            self.btn_ping_peer,
            self.btn_copy_ip,
            self.btn_copy_fqdn,
            self.list_peers,
            self.edit_details,
        ]
    }
}

struct DashboardState {
    hwnd: isize,
    visible: bool,
    current_dpi: u32,
    theme_mode: ThemeMode,
    locale_mode: LocaleMode,
    palette: UiThemePalette,
    active_tab: DashboardTab,
    onboarding_tab: DesktopOnboardingTab,
    active_modal: Option<Zone3ModalKind>,
    peer_filter_mode: PeerFilterMode,
    controls: UiControls,
    window_icon: Option<OwnedIcon>,
    tray: Option<TrayStateManager>,
    poller: Option<BackgroundIpcController>,
    shutdown_event: Option<mesh_sys::gui_windows::OwnedWinHandle>,
    clipboard_guard: Option<ClipboardSecretGuard>,
    latest_poll: Option<PolledStateUpdate>,
    snapshot: DerivedUiSnapshot,
    displayed_peers: Vec<AgentPeerStatus>,
    active_action_error: Option<String>,
    detail_override: Option<String>,
    toast_message: Option<String>,
    last_announced_state: String,
    form_seeded_from_status: bool,
    busy_action: bool,
    pending_disconnect_and_quit: bool,
    shutdown_started: bool,
    autostart_enabled: bool,
}

impl DashboardState {
    fn new(initially_visible: bool) -> Self {
        let prefs = load_prefs();
        let initial_snapshot = derive_desktop_ui_state(StateProbeInputs {
            gui_version: env!("CARGO_PKG_VERSION"),
            service_probe: ServiceProbeKind::Unknown,
            ipc_connected: false,
            status: None,
            version_status: None,
            ipc_error: None,
            active_action_error: None,
        });
        Self {
            hwnd: 0,
            visible: initially_visible,
            current_dpi: 96,
            theme_mode: prefs.theme,
            locale_mode: prefs.locale,
            palette: resolve_palette_for_dpi(prefs.theme, 96),
            active_tab: DashboardTab::Status,
            onboarding_tab: DesktopOnboardingTab::JoinUri,
            active_modal: None,
            peer_filter_mode: PeerFilterMode::All,
            controls: UiControls::default(),
            window_icon: None,
            tray: None,
            poller: None,
            shutdown_event: create_named_shutdown_event().ok(),
            clipboard_guard: None,
            latest_poll: None,
            snapshot: initial_snapshot,
            displayed_peers: Vec::new(),
            active_action_error: None,
            detail_override: None,
            toast_message: None,
            last_announced_state: String::new(),
            form_seeded_from_status: false,
            busy_action: false,
            pending_disconnect_and_quit: false,
            shutdown_started: false,
            autostart_enabled: query_launch_at_login_enabled(),
        }
    }
}

struct DashboardApp {
    inner: RefCell<DashboardState>,
}

impl DashboardApp {
    fn new(initially_visible: bool) -> Self {
        Self {
            inner: RefCell::new(DashboardState::new(initially_visible)),
        }
    }
}

#[derive(Clone, Copy)]
enum PendingUiPrompt {
    SaveBugreport,
    ConfirmAndRunEnrollment { is_rotate: bool },
    ConfirmResetIdentity,
    ConfirmUninstall,
    QuitKeepBackground,
    DisconnectAndQuit,
}

fn scale(px96: i32, dpi: u32) -> i32 {
    ((px96 * i32::try_from(dpi.max(72)).unwrap_or(96)) + 48) / 96
}

fn build_controls(hwnd: isize) -> Option<UiControls> {
    let z = ControlRect::new(0, 0, 100, 24);
    Some(UiControls {
        // Accessible screen-reader label proxy (kept off-visual or 1x1 while GDI hero paints visually)
        status_title: create_static_text(hwnd, IDC_STATUS_TITLE, "Initializing Mesh VPN...", z)
            .ok()?,

        // 3-Tab Navigation (`BS_OWNERDRAW` + `WS_TABSTOP`)
        tab_status: create_owner_draw_button(
            hwnd,
            IDC_TAB_STATUS,
            &tr_or("tab.status", "Status"),
            z,
        )
        .ok()?,
        tab_peers: create_owner_draw_button(hwnd, IDC_TAB_PEERS, &tr_or("tab.peers", "Peers"), z)
            .ok()?,
        tab_diag_settings: create_owner_draw_button(
            hwnd,
            IDC_TAB_DIAG_SETTINGS,
            &tr_or("tab.diagnostics_settings", "Diagnostics & Settings"),
            z,
        )
        .ok()?,

        // Primary CTAs (`BS_OWNERDRAW` for crisp Dark Mode styling)
        btn_connect: create_owner_draw_button(
            hwnd,
            IDC_BTN_CONNECT,
            &tr_or("action.connect", "Connect"),
            z,
        )
        .ok()?,
        btn_disconnect: create_owner_draw_button(
            hwnd,
            IDC_BTN_DISCONNECT,
            &tr_or("action.disconnect", "Disconnect"),
            z,
        )
        .ok()?,
        btn_start_repair: create_owner_draw_button(
            hwnd,
            IDC_BTN_START_REPAIR,
            &tr_or("win.start_update_service", "Start / Update Service (UAC)"),
            z,
        )
        .ok()?,

        // Zone 3 Diagnostics & Settings controls
        btn_netcheck: create_owner_draw_button(
            hwnd,
            IDC_BTN_NETCHECK,
            &tr_or("action.run_netcheck", "Run Netcheck"),
            z,
        )
        .ok()?,
        btn_bugreport: create_owner_draw_button(
            hwnd,
            IDC_BTN_BUGREPORT,
            &tr_or("action.export_bugreport", "Export Bugreport..."),
            z,
        )
        .ok()?,
        btn_cleanup: create_owner_draw_button(hwnd, IDC_BTN_CLEANUP, "Cleanup Routes", z).ok()?,
        btn_reset_id: create_owner_draw_button(
            hwnd,
            IDC_BTN_RESET_ID,
            &tr_or("action.reset_identity", "Reset Identity"),
            z,
        )
        .ok()?,
        chk_autostart: create_checkbox(
            hwnd,
            IDC_CHK_AUTOSTART,
            &tr_or("settings.launch_at_login", "Launch at Login"),
            z,
        )
        .ok()?,
        btn_uninstall: create_owner_draw_button(hwnd, IDC_BTN_UNINSTALL, "Uninstall...", z).ok()?,
        btn_open_rotate_modal: create_owner_draw_button(
            hwnd,
            IDC_BTN_OPEN_ROTATE_MODAL,
            &tr_or("action.rotate_key", "Rotate Node Key..."),
            z,
        )
        .ok()?,
        btn_open_update_server_modal: create_owner_draw_button(
            hwnd,
            IDC_BTN_OPEN_UPDATE_SERVER_MODAL,
            &tr_or("settings.update_server", "Update Server / SPKI Pin..."),
            z,
        )
        .ok()?,
        lbl_theme: create_static_text(hwnd, IDC_LBL_THEME, "Theme:", z).ok()?,
        btn_theme_system: create_owner_draw_button(
            hwnd,
            IDC_BTN_THEME_SYSTEM,
            &tr_or("theme.system", "System"),
            z,
        )
        .ok()?,
        btn_theme_light: create_owner_draw_button(
            hwnd,
            IDC_BTN_THEME_LIGHT,
            &tr_or("theme.light", "Light"),
            z,
        )
        .ok()?,
        btn_theme_dark: create_owner_draw_button(
            hwnd,
            IDC_BTN_THEME_DARK,
            &tr_or("theme.dark", "Dark"),
            z,
        )
        .ok()?,

        // Onboarding 2-tab switchers & inputs (reused cleanly by Zone 3 modals when open)
        tab_onboard_uri: create_owner_draw_button(
            hwnd,
            IDC_TAB_ONBOARD_URI,
            &tr_or("onboarding.desktop.tab.join_uri", "Join URI"),
            z,
        )
        .ok()?,
        tab_onboard_manual: create_owner_draw_button(
            hwnd,
            IDC_TAB_ONBOARD_MANUAL,
            &tr_or("onboarding.desktop.tab.manual", "Manual Setup"),
            z,
        )
        .ok()?,
        lbl_setup: create_static_text(hwnd, IDC_LBL_SETUP, "Set Up Mesh VPN:", z).ok()?,
        btn_paste_uri: create_owner_draw_button(
            hwnd,
            IDC_BTN_PASTE_URI,
            "Paste mesh:// Join URI",
            z,
        )
        .ok()?,
        lbl_endpoint: create_static_text(hwnd, IDC_LBL_ENDPOINT, "Control Server:", z).ok()?,
        edit_endpoint: create_edit(hwnd, IDC_EDIT_ENDPOINT, "", z, false, false).ok()?,
        radio_spki: create_radio_button(hwnd, IDC_RADIO_SPKI, "SPKI Pin (Zero-TOFU)", z, true)
            .ok()?,
        radio_system_ca: create_radio_button(
            hwnd,
            IDC_RADIO_SYSTEM_CA,
            "System CA (Domain Only)",
            z,
            false,
        )
        .ok()?,
        lbl_pin: create_static_text(hwnd, IDC_LBL_PIN, "SPKI Pin:", z).ok()?,
        edit_pin: create_edit(hwnd, IDC_EDIT_PIN, "", z, false, false).ok()?,
        lbl_preauth: create_static_text(hwnd, IDC_LBL_PREAUTH, "Pre-Auth Key:", z).ok()?,
        edit_preauth: create_edit(hwnd, IDC_EDIT_PREAUTH, "", z, true, false).ok()?,
        lbl_nodename: create_static_text(hwnd, IDC_LBL_NODENAME, "Node Name:", z).ok()?,
        edit_node_name: create_edit(hwnd, IDC_EDIT_NODE_NAME, "", z, false, false).ok()?,
        btn_enroll_save: create_owner_draw_button(hwnd, IDC_BTN_ENROLL_SAVE, "Enroll & Connect", z)
            .ok()?,
        btn_update_server: create_owner_draw_button(
            hwnd,
            IDC_BTN_UPDATE_SERVER,
            "Save Server / Pin (UAC)",
            z,
        )
        .ok()?,
        btn_modal_cancel: create_button(hwnd, IDC_BTN_MODAL_CANCEL, "Cancel", z, false).ok()?,

        // Zone 2 Peers controls
        lbl_peers: create_static_text(
            hwnd,
            IDC_LBL_PEERS,
            "Search Peers (Name / IP / Node ID):",
            z,
        )
        .ok()?,
        edit_peer_filter: create_edit(hwnd, IDC_EDIT_PEER_FILTER, "", z, false, false).ok()?,
        btn_peer_all: create_owner_draw_button(hwnd, IDC_BTN_PEER_FILTER_ALL, "All (0)", z).ok()?,
        btn_peer_online: create_owner_draw_button(
            hwnd,
            IDC_BTN_PEER_FILTER_ONLINE,
            "Online (0)",
            z,
        )
        .ok()?,
        btn_peer_direct: create_owner_draw_button(
            hwnd,
            IDC_BTN_PEER_FILTER_DIRECT,
            "Direct (0)",
            z,
        )
        .ok()?,
        btn_peer_relay: create_owner_draw_button(hwnd, IDC_BTN_PEER_FILTER_RELAY, "Relay (0)", z)
            .ok()?,
        btn_ping_peer: create_owner_draw_button(hwnd, IDC_BTN_PING_PEER, "Ping Peer", z).ok()?,
        btn_copy_ip: create_owner_draw_button(hwnd, IDC_BTN_COPY_PEER_IP, "Copy Overlay IP", z)
            .ok()?,
        btn_copy_fqdn: create_owner_draw_button(hwnd, IDC_BTN_COPY_PEER_FQDN, "Copy FQDN", z)
            .ok()?,
        list_peers: create_listbox(hwnd, IDC_LIST_PEERS, z).ok()?,
        edit_details: create_edit(hwnd, IDC_EDIT_DETAILS, "", z, false, true).ok()?,
    })
}

fn apply_font_to_all(c: &UiControls, font: &OwnedGdiObj) {
    for h in c.all_handles() {
        set_control_font(h, font);
    }
    for h in c.extra_peer_handles() {
        set_control_font(h, font);
    }
}

fn set_many_visible(handles: &[isize], visible: bool) {
    for &h in handles {
        if h != 0 {
            set_control_visible(h, visible);
        }
    }
}

fn sync_zone_visibility_and_layout(st: &DashboardState) {
    let hwnd = st.hwnd;
    if hwnd == 0 || st.controls.status_title == 0 {
        return;
    }
    let dpi = st.current_dpi;
    let (cw, ch) = get_client_size(hwnd);
    let c = &st.controls;
    let pad = scale(12, dpi);
    let inner_pad = scale(24, dpi);
    let row_h = scale(24, dpi);
    let btn_h = scale(30, dpi);
    let gap = scale(8, dpi);
    let usable_w = (cw - 2 * pad).max(scale(560, dpi));
    let inner_w = (cw - 2 * inner_pad).max(scale(520, dpi));

    // Accessible status proxy stays non-overlapping (1x1 at top-left, readable by screen readers)
    set_control_bounds(c.status_title, 0, 0, 1, 1);
    set_control_visible(c.status_title, false);

    // Hide all dynamic zone controls first, then reveal only active zone / modal controls
    set_many_visible(
        &[
            c.tab_status,
            c.tab_peers,
            c.tab_diag_settings,
            c.btn_connect,
            c.btn_disconnect,
            c.btn_start_repair,
            c.btn_netcheck,
            c.btn_bugreport,
            c.btn_cleanup,
            c.btn_reset_id,
            c.chk_autostart,
            c.btn_uninstall,
            c.btn_open_rotate_modal,
            c.btn_open_update_server_modal,
            c.lbl_theme,
            c.btn_theme_system,
            c.btn_theme_light,
            c.btn_theme_dark,
            c.tab_onboard_uri,
            c.tab_onboard_manual,
            c.lbl_setup,
            c.btn_paste_uri,
            c.lbl_endpoint,
            c.edit_endpoint,
            c.radio_spki,
            c.radio_system_ca,
            c.lbl_pin,
            c.edit_pin,
            c.lbl_preauth,
            c.edit_preauth,
            c.lbl_nodename,
            c.edit_node_name,
            c.btn_enroll_save,
            c.btn_update_server,
            c.btn_modal_cancel,
            c.lbl_peers,
            c.edit_peer_filter,
            c.btn_peer_all,
            c.btn_peer_online,
            c.btn_peer_direct,
            c.btn_peer_relay,
            c.btn_ping_peer,
            c.btn_copy_ip,
            c.btn_copy_fqdn,
            c.list_peers,
            c.edit_details,
        ],
        false,
    );

    let hero_bottom = pad + scale(96, dpi);
    let nav_y = hero_bottom + scale(10, dpi);
    let content_y = hero_bottom + scale(64, dpi);
    let content_bottom = (ch - inner_pad).max(content_y + scale(140, dpi));

    let tabs_visible = st.snapshot.should_show_tab_bar();
    if tabs_visible {
        // 3-Tab Navigation Bar visible across ALL enrolled states (`ADR-028`)
        let tab_w = (usable_w - gap * 2) / 3;
        set_control_bounds(c.tab_status, pad, nav_y, tab_w, btn_h);
        set_control_bounds(c.tab_peers, pad + tab_w + gap, nav_y, tab_w, btn_h);
        set_control_bounds(
            c.tab_diag_settings,
            pad + (tab_w + gap) * 2,
            nav_y,
            usable_w - (tab_w + gap) * 2,
            btn_h,
        );
        set_many_visible(&[c.tab_status, c.tab_peers, c.tab_diag_settings], true);
    }

    // Active Zone 3 Modal takes over Zone content cleanly (`ADR-028`)
    if tabs_visible && let Some(modal) = st.active_modal {
        layout_zone3_modal(c, dpi, inner_pad, content_y, inner_w, modal);
        return;
    }

    // Un-enrolled or service-stopped states
    if !tabs_visible {
        if st.snapshot.should_show_onboarding_form() {
            layout_onboarding_view(c, dpi, inner_pad, content_y, inner_w, st.onboarding_tab);
        } else {
            // ServiceStopped / AgentUnavailable recovery panel
            let cta_w = scale(230, dpi);
            let unin_w = scale(120, dpi);
            set_control_bounds(c.btn_start_repair, inner_pad, content_y, cta_w, btn_h);
            set_control_bounds(
                c.btn_uninstall,
                inner_pad + cta_w + gap,
                content_y,
                unin_w,
                btn_h,
            );
            let det_y = content_y + btn_h + gap * 2;
            let det_h = (content_bottom - det_y).max(scale(100, dpi));
            set_control_bounds(c.edit_details, inner_pad, det_y, inner_w, det_h);
            set_many_visible(&[c.btn_start_repair, c.btn_uninstall, c.edit_details], true);
        }
        return;
    }

    match st.active_tab {
        DashboardTab::Status => {
            let mut y = content_y;
            let bw1 = scale(130, dpi);
            let bw2 = scale(130, dpi);
            let bw3 = scale(205, dpi);
            set_control_bounds(c.btn_connect, inner_pad, y, bw1, btn_h);
            set_control_bounds(c.btn_disconnect, inner_pad + bw1 + gap, y, bw2, btn_h);
            set_control_bounds(
                c.btn_start_repair,
                inner_pad + bw1 + bw2 + gap * 2,
                y,
                bw3,
                btn_h,
            );
            set_many_visible(&[c.btn_connect, c.btn_disconnect, c.btn_start_repair], true);
            if st.snapshot.ui_state == DesktopUiState::ReauthRequired {
                set_control_bounds(
                    c.btn_open_rotate_modal,
                    inner_pad + bw1 + bw2 + bw3 + gap * 3,
                    y,
                    scale(165, dpi),
                    btn_h,
                );
                set_control_visible(c.btn_open_rotate_modal, true);
            }
            y += btn_h + gap * 2;
            let det_h = (content_bottom - y).max(scale(140, dpi));
            set_control_bounds(c.edit_details, inner_pad, y, inner_w, det_h);
            set_control_visible(c.edit_details, true);
        }
        DashboardTab::Peers => {
            let mut y = content_y;
            let lbl_w = scale(210, dpi);
            set_control_bounds(c.lbl_peers, inner_pad, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(
                c.edit_peer_filter,
                inner_pad + lbl_w + gap,
                y,
                (inner_w - lbl_w - gap).max(scale(180, dpi)),
                row_h,
            );
            y += row_h + gap;

            // 4-State Filter Chips (`All / Online / Direct / Relay` + count badges)
            let chip_w = scale(105, dpi);
            set_control_bounds(c.btn_peer_all, inner_pad, y, chip_w, btn_h);
            set_control_bounds(
                c.btn_peer_online,
                inner_pad + (chip_w + gap),
                y,
                chip_w,
                btn_h,
            );
            set_control_bounds(
                c.btn_peer_direct,
                inner_pad + (chip_w + gap) * 2,
                y,
                chip_w,
                btn_h,
            );
            set_control_bounds(
                c.btn_peer_relay,
                inner_pad + (chip_w + gap) * 3,
                y,
                chip_w,
                btn_h,
            );
            y += btn_h + gap;

            // Peer action bar: Ping + Copy Overlay IP + Copy FQDN (`US-121`)
            let ping_w = scale(115, dpi);
            let copy_ip_w = scale(135, dpi);
            let copy_fqdn_w = scale(115, dpi);
            set_control_bounds(c.btn_ping_peer, inner_pad, y, ping_w, btn_h);
            set_control_bounds(c.btn_copy_ip, inner_pad + ping_w + gap, y, copy_ip_w, btn_h);
            set_control_bounds(
                c.btn_copy_fqdn,
                inner_pad + ping_w + copy_ip_w + gap * 2,
                y,
                copy_fqdn_w,
                btn_h,
            );
            y += btn_h + gap;

            let rem_h = (content_bottom - y).max(scale(140, dpi));
            let list_h = (rem_h * 52) / 100;
            let detail_h = (rem_h - list_h - gap).max(scale(70, dpi));
            set_control_bounds(c.list_peers, inner_pad, y, inner_w, list_h);
            set_control_bounds(
                c.edit_details,
                inner_pad,
                y + list_h + gap,
                inner_w,
                detail_h,
            );
            set_many_visible(
                &[
                    c.lbl_peers,
                    c.edit_peer_filter,
                    c.btn_peer_all,
                    c.btn_peer_online,
                    c.btn_peer_direct,
                    c.btn_peer_relay,
                    c.btn_ping_peer,
                    c.btn_copy_ip,
                    c.btn_copy_fqdn,
                    c.list_peers,
                    c.edit_details,
                ],
                true,
            );
        }
        DashboardTab::DiagnosticsSettings => {
            let mut y = content_y;
            // Row 1: Appearance Theme Selector + Launch at Login
            let theme_lbl_w = scale(62, dpi);
            let theme_btn_w = scale(84, dpi);
            set_control_bounds(
                c.lbl_theme,
                inner_pad,
                y + scale(4, dpi),
                theme_lbl_w,
                row_h,
            );
            set_control_bounds(
                c.btn_theme_system,
                inner_pad + theme_lbl_w + gap,
                y,
                theme_btn_w,
                btn_h,
            );
            set_control_bounds(
                c.btn_theme_light,
                inner_pad + theme_lbl_w + theme_btn_w + gap * 2,
                y,
                theme_btn_w,
                btn_h,
            );
            set_control_bounds(
                c.btn_theme_dark,
                inner_pad + theme_lbl_w + (theme_btn_w + gap) * 2 + gap,
                y,
                theme_btn_w,
                btn_h,
            );
            set_control_bounds(
                c.chk_autostart,
                inner_pad + inner_w - scale(145, dpi),
                y,
                scale(145, dpi),
                btn_h,
            );
            y += btn_h + gap;

            // Row 2: Diagnostics (Netcheck, Bugreport, Cleanup)
            let bw_net = scale(130, dpi);
            let bw_bug = scale(165, dpi);
            let bw_cln = scale(130, dpi);
            set_control_bounds(c.btn_netcheck, inner_pad, y, bw_net, btn_h);
            set_control_bounds(c.btn_bugreport, inner_pad + bw_net + gap, y, bw_bug, btn_h);
            set_control_bounds(
                c.btn_cleanup,
                inner_pad + bw_net + bw_bug + gap * 2,
                y,
                bw_cln,
                btn_h,
            );
            y += btn_h + gap;

            // Row 3: Identity & Maintenance Modals (`ADR-028`)
            let bw_rot = scale(155, dpi);
            let bw_upd = scale(195, dpi);
            let bw_rst = scale(125, dpi);
            let bw_uni = scale(110, dpi);
            set_control_bounds(c.btn_open_rotate_modal, inner_pad, y, bw_rot, btn_h);
            set_control_bounds(
                c.btn_open_update_server_modal,
                inner_pad + bw_rot + gap,
                y,
                bw_upd,
                btn_h,
            );
            set_control_bounds(
                c.btn_reset_id,
                inner_pad + bw_rot + bw_upd + gap * 2,
                y,
                bw_rst,
                btn_h,
            );
            set_control_bounds(
                c.btn_uninstall,
                inner_pad + inner_w - bw_uni,
                y,
                bw_uni,
                btn_h,
            );
            y += btn_h + gap * 2;

            let det_h = (content_bottom - y).max(scale(140, dpi));
            set_control_bounds(c.edit_details, inner_pad, y, inner_w, det_h);
            set_many_visible(
                &[
                    c.lbl_theme,
                    c.btn_theme_system,
                    c.btn_theme_light,
                    c.btn_theme_dark,
                    c.chk_autostart,
                    c.btn_netcheck,
                    c.btn_bugreport,
                    c.btn_cleanup,
                    c.btn_open_rotate_modal,
                    c.btn_open_update_server_modal,
                    c.btn_reset_id,
                    c.btn_uninstall,
                    c.edit_details,
                ],
                true,
            );
        }
    }
}

fn layout_onboarding_view(
    c: &UiControls,
    dpi: u32,
    x: i32,
    start_y: i32,
    w: i32,
    tab: DesktopOnboardingTab,
) {
    let row_h = scale(24, dpi);
    let btn_h = scale(30, dpi);
    let gap = scale(8, dpi);
    let mut y = start_y;

    let tab_w = scale(140, dpi);
    set_control_bounds(c.tab_onboard_uri, x, y, tab_w, btn_h);
    set_control_bounds(c.tab_onboard_manual, x + tab_w + gap, y, tab_w, btn_h);
    set_many_visible(&[c.tab_onboard_uri, c.tab_onboard_manual], true);
    y += btn_h + gap * 2;

    match tab {
        DesktopOnboardingTab::JoinUri => {
            set_control_text(
                c.lbl_setup,
                "Copy a `mesh://join?...` URI from your Control Admin, then click Paste below:",
            );
            set_control_bounds(c.lbl_setup, x, y, w, row_h);
            y += row_h + gap;
            let lbl_w = scale(115, dpi);
            set_control_bounds(c.lbl_nodename, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_node_name, x + lbl_w, y, scale(240, dpi), row_h);
            y += row_h + gap * 2;
            set_control_bounds(c.btn_paste_uri, x, y, scale(210, dpi), btn_h);
            set_many_visible(
                &[
                    c.lbl_setup,
                    c.lbl_nodename,
                    c.edit_node_name,
                    c.btn_paste_uri,
                ],
                true,
            );
        }
        DesktopOnboardingTab::Manual => {
            set_control_text(
                c.lbl_setup,
                "Manual Server Enrollment (Zero-TOFU enforced):",
            );
            set_control_bounds(c.lbl_setup, x, y, w, row_h);
            y += row_h + gap;

            let lbl_w = scale(115, dpi);
            let ep_w = (w - lbl_w - scale(350, dpi) - gap * 2).max(scale(160, dpi));
            set_control_bounds(c.lbl_endpoint, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_endpoint, x + lbl_w, y, ep_w, row_h);
            set_control_bounds(
                c.radio_spki,
                x + lbl_w + ep_w + gap,
                y,
                scale(165, dpi),
                row_h,
            );
            set_control_bounds(
                c.radio_system_ca,
                x + lbl_w + ep_w + gap * 2 + scale(165, dpi),
                y,
                scale(175, dpi),
                row_h,
            );
            y += row_h + gap;

            set_control_bounds(c.lbl_pin, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_pin, x + lbl_w, y, w - lbl_w, row_h);
            y += row_h + gap;

            set_control_bounds(c.lbl_preauth, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_preauth, x + lbl_w, y, w - lbl_w, row_h);
            y += row_h + gap;

            set_control_bounds(c.lbl_nodename, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_node_name, x + lbl_w, y, scale(240, dpi), row_h);
            y += row_h + gap * 2;

            set_control_text(c.btn_enroll_save, "Enroll & Connect");
            set_control_bounds(c.btn_enroll_save, x + lbl_w, y, scale(170, dpi), btn_h);
            set_many_visible(
                &[
                    c.lbl_setup,
                    c.lbl_endpoint,
                    c.edit_endpoint,
                    c.radio_spki,
                    c.radio_system_ca,
                    c.lbl_pin,
                    c.edit_pin,
                    c.lbl_preauth,
                    c.edit_preauth,
                    c.lbl_nodename,
                    c.edit_node_name,
                    c.btn_enroll_save,
                ],
                true,
            );
        }
    }
}

fn layout_zone3_modal(
    c: &UiControls,
    dpi: u32,
    x: i32,
    start_y: i32,
    w: i32,
    modal: Zone3ModalKind,
) {
    let row_h = scale(24, dpi);
    let btn_h = scale(30, dpi);
    let gap = scale(8, dpi);
    let lbl_w = scale(125, dpi);
    let mut y = start_y;

    match modal {
        Zone3ModalKind::RotateNodeKey => {
            set_control_text(
                c.lbl_setup,
                "Rotate Node Key — Paste a fresh single-use Pre-Auth Key (UAC):",
            );
            set_control_bounds(c.lbl_setup, x, y, w, row_h);
            y += row_h + gap * 2;

            set_control_bounds(c.lbl_preauth, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_preauth, x + lbl_w, y, w - lbl_w, row_h);
            y += row_h + gap * 2;

            set_control_text(c.btn_enroll_save, "Rotate Key (UAC)");
            set_control_bounds(c.btn_enroll_save, x + lbl_w, y, scale(165, dpi), btn_h);
            set_control_bounds(
                c.btn_modal_cancel,
                x + lbl_w + scale(165, dpi) + gap,
                y,
                scale(100, dpi),
                btn_h,
            );
            set_many_visible(
                &[
                    c.lbl_setup,
                    c.lbl_preauth,
                    c.edit_preauth,
                    c.btn_enroll_save,
                    c.btn_modal_cancel,
                ],
                true,
            );
        }
        Zone3ModalKind::UpdateControlServer => {
            set_control_text(
                c.lbl_setup,
                "Update Control Server / SPKI Pin (Zero-TOFU enforced, UAC):",
            );
            set_control_bounds(c.lbl_setup, x, y, w, row_h);
            y += row_h + gap * 2;

            let ep_w = (w - lbl_w - scale(350, dpi) - gap * 2).max(scale(160, dpi));
            set_control_bounds(c.lbl_endpoint, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_endpoint, x + lbl_w, y, ep_w, row_h);
            set_control_bounds(
                c.radio_spki,
                x + lbl_w + ep_w + gap,
                y,
                scale(165, dpi),
                row_h,
            );
            set_control_bounds(
                c.radio_system_ca,
                x + lbl_w + ep_w + gap * 2 + scale(165, dpi),
                y,
                scale(175, dpi),
                row_h,
            );
            y += row_h + gap;

            set_control_bounds(c.lbl_pin, x, y + scale(3, dpi), lbl_w, row_h);
            set_control_bounds(c.edit_pin, x + lbl_w, y, w - lbl_w, row_h);
            y += row_h + gap * 2;

            set_control_bounds(c.btn_update_server, x + lbl_w, y, scale(195, dpi), btn_h);
            set_control_bounds(
                c.btn_modal_cancel,
                x + lbl_w + scale(195, dpi) + gap,
                y,
                scale(100, dpi),
                btn_h,
            );
            set_many_visible(
                &[
                    c.lbl_setup,
                    c.lbl_endpoint,
                    c.edit_endpoint,
                    c.radio_spki,
                    c.radio_system_ca,
                    c.lbl_pin,
                    c.edit_pin,
                    c.btn_update_server,
                    c.btn_modal_cancel,
                ],
                true,
            );
        }
    }
}

fn read_form_input(c: &UiControls) -> OnboardingFormInput {
    let spki_selected = get_checkbox_checked(c.radio_spki);
    OnboardingFormInput {
        endpoint_raw: get_control_text(c.edit_endpoint),
        tls_mode: if spki_selected {
            OnboardingTlsMode::SpkiPin
        } else {
            OnboardingTlsMode::SystemCa
        },
        spki_pin_raw: get_control_text(c.edit_pin),
        preauth_key_raw: get_control_text(c.edit_preauth),
        node_name_raw: get_control_text(c.edit_node_name),
    }
}

fn sync_zero_tofu_radio_state(c: &UiControls) {
    let ep = get_control_text(c.edit_endpoint);
    let ip_locked = should_lock_system_ca_for_endpoint(&ep);
    set_control_enabled(c.radio_system_ca, !ip_locked);
    if ip_locked && get_checkbox_checked(c.radio_system_ca) {
        set_checkbox_checked(c.radio_system_ca, false);
        set_checkbox_checked(c.radio_spki, true);
    }
    let use_spki = get_checkbox_checked(c.radio_spki);
    set_control_enabled(c.edit_pin, use_spki);
}

fn rebuild_theme_and_repaint(st: &mut DashboardState) {
    st.palette.clear_brush_cache();
    st.palette = resolve_palette_for_dpi(st.theme_mode, st.current_dpi);
    apply_window_dark_titlebar(st.hwnd, st.palette.is_dark_titlebar);
    tracing::debug!(
        component = "mesh-gui",
        event = "theme_palette_rebuilt",
        mode = ?st.palette.mode,
        dark = st.palette.is_dark_titlebar,
        high_contrast = st.palette.is_high_contrast,
        dpi = st.palette.dpi,
        "rebuilt GDI/DWM theme palette"
    );
    if let Some(font) = &st.palette.font_body {
        apply_font_to_all(&st.controls, font);
    }
    invalidate_window(st.hwnd);
}

fn show_toast(st: &mut DashboardState, title: &str, body: &str) {
    st.toast_message = Some(body.to_owned());
    set_window_timer(st.hwnd, TIMER_TOAST_CLEAR, TOAST_DISPLAY_MS);
    if let Some(tray) = &st.tray {
        tray.show_toast_balloon(title, body);
    }
    invalidate_window(st.hwnd);
}

fn refresh_ui_from_state(st: &mut DashboardState) {
    let snapshot = if let Some(poll) = &st.latest_poll {
        derive_desktop_ui_state(StateProbeInputs {
            gui_version: env!("CARGO_PKG_VERSION"),
            service_probe: poll.service_probe,
            ipc_connected: poll.ipc_connected,
            status: poll.status.as_ref(),
            version_status: poll.version_status.as_ref(),
            ipc_error: poll.ipc_error.as_deref(),
            active_action_error: st.active_action_error.as_deref(),
        })
    } else {
        derive_desktop_ui_state(StateProbeInputs {
            gui_version: env!("CARGO_PKG_VERSION"),
            service_probe: ServiceProbeKind::Unknown,
            ipc_connected: false,
            status: None,
            version_status: None,
            ipc_error: None,
            active_action_error: st.active_action_error.as_deref(),
        })
    };
    st.snapshot = snapshot;

    let display_lbl = st
        .snapshot
        .ui_state
        .display_label(st.snapshot.tunnel_sub_state);
    let headline = st.snapshot.ui_state.headline(st.snapshot.tunnel_sub_state);
    let accessible_text = format!("State: {display_lbl} — {headline}");
    if st.last_announced_state != accessible_text {
        tracing::debug!(
            component = "mesh-gui",
            event = "ui_state_changed",
            state = st.snapshot.ui_state.label(),
            display_label = display_lbl,
            "updated desktop UI state"
        );
        announce_accessible_label(st.controls.status_title, &accessible_text);
        st.last_announced_state = accessible_text;
    }

    let status_ref = st.latest_poll.as_ref().and_then(|p| p.status.as_ref());
    if let Some(status) = status_ref
        && !st.form_seeded_from_status
        && let Some(srv) = &status.server_connection
        && !srv.control_endpoint.trim().is_empty()
    {
        set_control_text(st.controls.edit_endpoint, &srv.control_endpoint);
        let is_pin = matches!(srv.tls_auth_mode, TlsAuthMode::SpkiPin);
        set_checkbox_checked(st.controls.radio_spki, is_pin);
        set_checkbox_checked(st.controls.radio_system_ca, !is_pin);
        if let Some(pin) = &srv.active_pin {
            set_control_text(st.controls.edit_pin, &pin.to_string());
        }
        if let Some(node) = &status.node_name {
            set_control_text(st.controls.edit_node_name, node.as_str());
        }
        st.form_seeded_from_status = true;
    }

    sync_zero_tofu_radio_state(&st.controls);
    set_checkbox_checked(st.controls.chk_autostart, st.autostart_enabled);

    let ipc_up = !matches!(
        st.snapshot.ui_state,
        DesktopUiState::AgentUnavailable | DesktopUiState::ServiceStopped
    );
    let can_reconnect = !st.busy_action
        && st.snapshot.enrolled
        && matches!(
            (st.snapshot.ui_state, st.snapshot.tunnel_sub_state),
            (DesktopUiState::Connected, TunnelSubState::Disconnected)
                | (DesktopUiState::ErrorRecoverable, _)
        );
    let can_disconnect = !st.busy_action
        && matches!(
            (st.snapshot.ui_state, st.snapshot.tunnel_sub_state),
            (
                DesktopUiState::Connected,
                TunnelSubState::Connected | TunnelSubState::Degraded
            ) | (DesktopUiState::Connecting, _)
        );
    set_control_enabled(st.controls.btn_connect, can_reconnect);
    set_control_enabled(st.controls.btn_disconnect, can_disconnect);
    set_control_enabled(st.controls.btn_start_repair, !st.busy_action);
    set_control_enabled(st.controls.btn_cleanup, !st.busy_action);
    set_control_enabled(
        st.controls.btn_reset_id,
        !st.busy_action && ipc_up && st.snapshot.enrolled,
    );
    set_control_enabled(st.controls.btn_netcheck, !st.busy_action && ipc_up);
    set_control_enabled(st.controls.btn_bugreport, !st.busy_action && ipc_up);
    set_control_enabled(st.controls.btn_uninstall, !st.busy_action);
    set_control_enabled(
        st.controls.btn_open_rotate_modal,
        !st.busy_action && ipc_up && st.snapshot.enrolled,
    );
    set_control_enabled(
        st.controls.btn_open_update_server_modal,
        !st.busy_action && ipc_up && st.snapshot.enrolled,
    );
    set_control_enabled(st.controls.btn_enroll_save, !st.busy_action && ipc_up);
    set_control_enabled(
        st.controls.btn_update_server,
        !st.busy_action && ipc_up && st.snapshot.enrolled,
    );

    sync_zone_visibility_and_layout(st);
    refresh_peers_and_details(st);

    let tone = icon_tone_for_state(st.snapshot.ui_state, st.snapshot.tunnel_sub_state);
    let big_px = get_sm_icon_px_for_dpi(st.current_dpi).max(32);
    if let Ok(win_icon) = create_status_icon_for_px(tone, big_px) {
        set_window_icon(st.hwnd, &win_icon);
        st.window_icon = Some(win_icon);
    }
    if let Some(tray) = &mut st.tray {
        tray.sync_state(st.hwnd, &st.snapshot);
    }
    invalidate_window(st.hwnd);
}

fn refresh_peers_and_details(st: &mut DashboardState) {
    let prev_sel_id = listbox_selected_index(st.controls.list_peers)
        .and_then(|idx| st.displayed_peers.get(idx))
        .map(|p| p.node_id);

    let filter_query = get_control_text(st.controls.edit_peer_filter);
    let all_peers: &[AgentPeerStatus] = st
        .latest_poll
        .as_ref()
        .and_then(|p| p.status.as_ref())
        .map_or(&[], |s| s.peers.as_slice());

    // Update 4-state filter chip count badges (`US-120`)
    let counts = count_peers_by_mode(all_peers);
    set_control_text(
        st.controls.btn_peer_all,
        &format_filter_chip_label(
            PeerFilterMode::All,
            counts,
            Some(&tr_or("peers.filter.all", "All")),
        ),
    );
    set_control_text(
        st.controls.btn_peer_online,
        &format_filter_chip_label(
            PeerFilterMode::Online,
            counts,
            Some(&tr_or("peers.filter.online", "Online")),
        ),
    );
    set_control_text(
        st.controls.btn_peer_direct,
        &format_filter_chip_label(
            PeerFilterMode::Direct,
            counts,
            Some(&tr_or("peers.filter.direct", "Direct")),
        ),
    );
    set_control_text(
        st.controls.btn_peer_relay,
        &format_filter_chip_label(
            PeerFilterMode::Relay,
            counts,
            Some(&tr_or("peers.filter.relay", "Relay")),
        ),
    );

    let filtered = if st.peer_filter_mode == PeerFilterMode::All {
        filter_peers(all_peers, &filter_query)
    } else if filter_query.trim().is_empty() {
        filter_peers_by_mode(all_peers, st.peer_filter_mode)
    } else {
        filter_peers_combined(all_peers, &filter_query, st.peer_filter_mode)
    };
    st.displayed_peers = filtered.iter().copied().cloned().collect();
    let labels: Vec<String> = st
        .displayed_peers
        .iter()
        .map(format_peer_list_entry)
        .collect();
    let new_sel =
        prev_sel_id.and_then(|id| st.displayed_peers.iter().position(|p| p.node_id == id));
    listbox_reset_and_fill(st.controls.list_peers, &labels, new_sel);

    let has_peer = new_sel.is_some();
    set_control_enabled(st.controls.btn_ping_peer, !st.busy_action && has_peer);
    set_control_enabled(st.controls.btn_copy_ip, has_peer);
    set_control_enabled(st.controls.btn_copy_fqdn, has_peer);

    if let Some(override_text) = &st.detail_override {
        set_control_text(st.controls.edit_details, override_text);
        return;
    }

    if st.active_tab == DashboardTab::Peers
        && let Some(idx) = new_sel
        && let Some(peer) = st.displayed_peers.get(idx)
    {
        set_control_text(st.controls.edit_details, &format_peer_detail_summary(peer));
        return;
    }

    let status_ref = st.latest_poll.as_ref().and_then(|p| p.status.as_ref());
    if st.active_tab == DashboardTab::DiagnosticsSettings {
        let theme_label = match st.theme_mode {
            ThemeMode::System => "System",
            ThemeMode::Light => "Light",
            ThemeMode::Dark => "Dark",
        };
        let locale_label = match st.locale_mode {
            LocaleMode::System => "System",
            LocaleMode::En => "English",
            LocaleMode::Vi => "Tieng Viet",
        };
        let summary = format_settings_identity_summary(status_ref, theme_label, locale_label);
        set_control_text(st.controls.edit_details, &summary);
        return;
    }

    if let Some(status) = status_ref {
        set_control_text(st.controls.edit_details, &format_self_network_panel(status));
    } else if let Some(err) = &st.snapshot.recoverable_error {
        set_control_text(st.controls.edit_details, err);
    } else {
        set_control_text(
            st.controls.edit_details,
            "Waiting for MeshVpnAgent status on \\\\.\\pipe\\mesh-agent-ro...",
        );
    }
}

fn build_reconnect_payload(st: &DashboardState) -> Result<Zeroizing<Vec<u8>>, String> {
    let status = st
        .latest_poll
        .as_ref()
        .and_then(|p| p.status.as_ref())
        .ok_or_else(|| "Agent status unavailable for 1-click reconnect".to_owned())?;
    build_reconnect_payload_from_status(status)
}

pub(crate) fn build_reconnect_payload_from_status(
    status: &AgentStatusResponse,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let srv = status
        .server_connection
        .as_ref()
        .filter(|s| !s.control_endpoint.trim().is_empty())
        .ok_or_else(|| {
            "Control endpoint not configured; complete Setup & Onboarding.".to_owned()
        })?;
    let server_pin = match srv.tls_auth_mode {
        TlsAuthMode::SystemCa => None,
        TlsAuthMode::SpkiPin => Some(
            srv.active_pin
                .ok_or_else(|| {
                    "Active SPKI pin is missing for pinned control server; complete Setup & Onboarding."
                        .to_owned()
                })?
                .to_string(),
        ),
    };
    let req = HandoffRequest::UpWithSecret {
        server_endpoint: srv.control_endpoint.clone(),
        port_override: None,
        server_pin,
        preauth_key: None,
        node_name: status.node_name.as_ref().map(|n| n.as_str().to_owned()),
    };
    serialize_handoff_request_zeroizing(&req).map_err(|err| err.to_string())
}

fn arm_clipboard_wipe(st: &mut DashboardState, guard: ClipboardSecretGuard) {
    st.clipboard_guard = Some(guard);
    set_window_timer(st.hwnd, TIMER_CLIPBOARD_WIPE, CLIPBOARD_WIPE_DELAY_MS);
}

fn clear_armed_clipboard(st: &mut DashboardState) {
    kill_window_timer(st.hwnd, TIMER_CLIPBOARD_WIPE);
    if let Some(mut guard) = st.clipboard_guard.take() {
        let _cleared = attempt_atomic_clipboard_clear(&mut guard);
    }
}

fn trigger_paste_uri_button(st: &mut DashboardState) -> Option<PendingUiPrompt> {
    let (seq, maybe_text) = match read_clipboard_zeroizing_with_seq() {
        Ok(res) => res,
        Err(err) => {
            st.active_action_error = Some(err.to_string());
            refresh_ui_from_state(st);
            return None;
        }
    };
    let Some(raw_text) = maybe_text else {
        st.active_action_error = Some("Clipboard does not contain UTF-16 text.".to_owned());
        refresh_ui_from_state(st);
        return None;
    };

    let guard = ClipboardSecretGuard::arm(seq, raw_text.as_str());
    arm_clipboard_wipe(st, guard);

    let node_name_override = get_control_text(st.controls.edit_node_name);
    match parse_mesh_join_uri_to_draft(raw_text.as_str(), &node_name_override) {
        Ok((form, _draft)) => {
            set_control_text(st.controls.edit_endpoint, &form.endpoint_raw);
            set_checkbox_checked(
                st.controls.radio_spki,
                form.tls_mode == OnboardingTlsMode::SpkiPin,
            );
            set_checkbox_checked(
                st.controls.radio_system_ca,
                form.tls_mode == OnboardingTlsMode::SystemCa,
            );
            set_control_text(st.controls.edit_pin, &form.spki_pin_raw);
            set_control_text(st.controls.edit_preauth, &form.preauth_key_raw);
            st.active_action_error = None;
            refresh_ui_from_state(st);
            Some(PendingUiPrompt::ConfirmAndRunEnrollment { is_rotate: false })
        }
        Err(err) => {
            st.active_action_error = Some(err);
            refresh_ui_from_state(st);
            None
        }
    }
}

fn begin_privileged_action(
    st: &mut DashboardState,
    action_label: &str,
    payload: Zeroizing<Vec<u8>>,
) {
    st.busy_action = true;
    st.active_action_error = None;
    st.detail_override = Some(format!("Executing `{action_label}`..."));
    if let Some(poller) = &st.poller {
        poller.spawn_handoff_action(action_label.to_owned(), payload);
    }
    refresh_ui_from_state(st);
}

fn perform_graceful_exit(st: &mut DashboardState) {
    if st.shutdown_started {
        return;
    }
    st.shutdown_started = true;
    let hwnd = st.hwnd;
    kill_window_timer(hwnd, TIMER_SHUTDOWN_POLL);
    kill_window_timer(hwnd, TIMER_TOAST_CLEAR);
    clear_armed_clipboard(st);
    set_control_text(st.controls.edit_preauth, "");
    if let Some(tray) = &mut st.tray {
        tray.remove();
    }
    if let Some(mut poller) = st.poller.take() {
        poller.shutdown();
    }
    destroy_window(hwnd);
}

fn is_owner_draw_active(st: &DashboardState, control_id: u16) -> bool {
    matches!(
        (control_id, st.active_tab),
        (IDC_TAB_STATUS, DashboardTab::Status)
            | (IDC_TAB_PEERS, DashboardTab::Peers)
            | (IDC_TAB_DIAG_SETTINGS, DashboardTab::DiagnosticsSettings)
    ) || matches!(
        (control_id, st.peer_filter_mode),
        (IDC_BTN_PEER_FILTER_ALL, PeerFilterMode::All)
            | (IDC_BTN_PEER_FILTER_ONLINE, PeerFilterMode::Online)
            | (IDC_BTN_PEER_FILTER_DIRECT, PeerFilterMode::Direct)
            | (IDC_BTN_PEER_FILTER_RELAY, PeerFilterMode::Relay)
    ) || matches!(
        (control_id, st.theme_mode),
        (IDC_BTN_THEME_SYSTEM, ThemeMode::System)
            | (IDC_BTN_THEME_LIGHT, ThemeMode::Light)
            | (IDC_BTN_THEME_DARK, ThemeMode::Dark)
    ) || matches!(
        (control_id, st.onboarding_tab),
        (IDC_TAB_ONBOARD_URI, DesktopOnboardingTab::JoinUri)
            | (IDC_TAB_ONBOARD_MANUAL, DesktopOnboardingTab::Manual)
    )
}

impl WindowEventHandler for DashboardApp {
    fn on_create(&self, hwnd: isize) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        st.hwnd = hwnd;
        let dpi = get_dpi_for_window(hwnd);
        st.current_dpi = dpi;
        st.palette = resolve_palette_for_dpi(st.theme_mode, dpi);
        apply_window_dark_titlebar(hwnd, st.palette.is_dark_titlebar);

        if let Some(controls) = build_controls(hwnd) {
            if let Some(font) = &st.palette.font_body {
                apply_font_to_all(&controls, font);
            }
            st.controls = controls;
            sync_zone_visibility_and_layout(&st);
        }
        let mut tray = TrayStateManager::new(hwnd);
        let _added = tray.ensure_added_or_restore(hwnd, &st.snapshot);
        st.tray = Some(tray);

        let poller = BackgroundIpcController::start(hwnd, st.visible);
        st.poller = Some(poller);
        set_window_timer(hwnd, TIMER_SHUTDOWN_POLL, 250);
        refresh_ui_from_state(&mut st);
    }

    fn on_command(&self, hwnd: isize, control_id: u16, notify_code: u16) {
        let mut prompt: Option<PendingUiPrompt> = None;
        {
            let Ok(mut st) = self.inner.try_borrow_mut() else {
                return;
            };
            match (control_id, notify_code) {
                (IDC_TAB_STATUS, WIN_BN_CLICKED) => {
                    st.active_tab = DashboardTab::Status;
                    st.active_modal = None;
                    st.detail_override = None;
                    refresh_ui_from_state(&mut st);
                    return;
                }
                (IDC_TAB_PEERS, WIN_BN_CLICKED) => {
                    st.active_tab = DashboardTab::Peers;
                    st.active_modal = None;
                    st.detail_override = None;
                    refresh_ui_from_state(&mut st);
                    return;
                }
                (IDC_TAB_DIAG_SETTINGS, WIN_BN_CLICKED) => {
                    st.active_tab = DashboardTab::DiagnosticsSettings;
                    st.active_modal = None;
                    st.detail_override = None;
                    refresh_ui_from_state(&mut st);
                    return;
                }
                (IDC_TAB_ONBOARD_URI, WIN_BN_CLICKED) => {
                    st.onboarding_tab = DesktopOnboardingTab::JoinUri;
                    sync_zone_visibility_and_layout(&st);
                    invalidate_window(hwnd);
                    return;
                }
                (IDC_TAB_ONBOARD_MANUAL, WIN_BN_CLICKED) => {
                    st.onboarding_tab = DesktopOnboardingTab::Manual;
                    sync_zone_visibility_and_layout(&st);
                    invalidate_window(hwnd);
                    return;
                }
                (IDC_BTN_OPEN_ROTATE_MODAL, WIN_BN_CLICKED) => {
                    st.active_tab = DashboardTab::DiagnosticsSettings;
                    st.active_modal = Some(Zone3ModalKind::RotateNodeKey);
                    set_control_text(st.controls.edit_preauth, "");
                    sync_zone_visibility_and_layout(&st);
                    set_focus_control(st.controls.edit_preauth);
                    invalidate_window(hwnd);
                    return;
                }
                (IDC_BTN_OPEN_UPDATE_SERVER_MODAL, WIN_BN_CLICKED) => {
                    st.active_tab = DashboardTab::DiagnosticsSettings;
                    st.active_modal = Some(Zone3ModalKind::UpdateControlServer);
                    sync_zero_tofu_radio_state(&st.controls);
                    sync_zone_visibility_and_layout(&st);
                    set_focus_control(st.controls.edit_endpoint);
                    invalidate_window(hwnd);
                    return;
                }
                (IDC_BTN_MODAL_CANCEL, WIN_BN_CLICKED) => {
                    st.active_modal = None;
                    set_control_text(st.controls.edit_preauth, "");
                    refresh_ui_from_state(&mut st);
                    return;
                }
                (
                    IDC_BTN_THEME_SYSTEM | IDC_BTN_THEME_LIGHT | IDC_BTN_THEME_DARK,
                    WIN_BN_CLICKED,
                ) => {
                    let next_mode = match control_id {
                        IDC_BTN_THEME_LIGHT => ThemeMode::Light,
                        IDC_BTN_THEME_DARK => ThemeMode::Dark,
                        _ => ThemeMode::System,
                    };
                    st.theme_mode = next_mode;
                    let _saved = save_prefs(&UiPrefs {
                        theme: st.theme_mode,
                        locale: st.locale_mode,
                    });
                    rebuild_theme_and_repaint(&mut st);
                    refresh_peers_and_details(&mut st);
                    return;
                }
                (
                    IDC_BTN_PEER_FILTER_ALL
                    | IDC_BTN_PEER_FILTER_ONLINE
                    | IDC_BTN_PEER_FILTER_DIRECT
                    | IDC_BTN_PEER_FILTER_RELAY,
                    WIN_BN_CLICKED,
                ) => {
                    st.peer_filter_mode = match control_id {
                        IDC_BTN_PEER_FILTER_ONLINE => PeerFilterMode::Online,
                        IDC_BTN_PEER_FILTER_DIRECT => PeerFilterMode::Direct,
                        IDC_BTN_PEER_FILTER_RELAY => PeerFilterMode::Relay,
                        _ => PeerFilterMode::All,
                    };
                    st.detail_override = None;
                    refresh_peers_and_details(&mut st);
                    invalidate_window(hwnd);
                    return;
                }
                (IDC_BTN_COPY_PEER_IP | IDC_BTN_COPY_PEER_FQDN, WIN_BN_CLICKED) => {
                    if let Some(idx) = listbox_selected_index(st.controls.list_peers)
                        && let Some(peer) = st.displayed_peers.get(idx).cloned()
                    {
                        let (kind, value) = if control_id == IDC_BTN_COPY_PEER_IP {
                            (CopyKind::OverlayIp, peer.overlay_ip.to_string())
                        } else {
                            (CopyKind::Fqdn, peer.fqdn)
                        };
                        match copy_non_secret_peer_value(kind, &value) {
                            Ok(notice) => show_toast(&mut st, &notice.title, &notice.body),
                            Err(err) => {
                                st.active_action_error = Some(err);
                                refresh_ui_from_state(&mut st);
                            }
                        }
                    }
                    return;
                }
                (IDC_EDIT_ENDPOINT, WIN_EN_CHANGE) => {
                    sync_zero_tofu_radio_state(&st.controls);
                    return;
                }
                (IDC_RADIO_SPKI | IDC_RADIO_SYSTEM_CA, WIN_BN_CLICKED) => {
                    sync_zero_tofu_radio_state(&st.controls);
                    return;
                }
                (IDC_EDIT_PEER_FILTER, WIN_EN_CHANGE) => {
                    st.detail_override = None;
                    refresh_peers_and_details(&mut st);
                    return;
                }
                (IDC_LIST_PEERS, WIN_LBN_SELCHANGE) => {
                    st.detail_override = None;
                    refresh_peers_and_details(&mut st);
                    return;
                }
                (IDC_BTN_PASTE_URI, WIN_BN_CLICKED) => {
                    prompt = trigger_paste_uri_button(&mut st);
                }
                (IDC_BTN_CONNECT, WIN_BN_CLICKED) => match build_reconnect_payload(&st) {
                    Ok(payload) => begin_privileged_action(&mut st, "Reconnect", payload),
                    Err(err) => {
                        st.active_action_error = Some(err);
                        refresh_ui_from_state(&mut st);
                    }
                },
                (IDC_BTN_DISCONNECT, WIN_BN_CLICKED) => {
                    if let Ok(payload) = serialize_handoff_request_zeroizing(&HandoffRequest::Down)
                    {
                        begin_privileged_action(&mut st, "Disconnect", payload);
                    }
                }
                (IDC_BTN_START_REPAIR, WIN_BN_CLICKED) => {
                    let is_legacy = st.snapshot.legacy_banner.is_some();
                    let source_dir = resolve_bundle_source_dir();
                    let req = if is_legacy {
                        HandoffRequest::UpdateService {
                            source_dir: source_dir.display().to_string(),
                            old_gui_pid: Some(std::process::id()),
                        }
                    } else {
                        let start_only = matches!(
                            st.latest_poll.as_ref().map(|p| p.service_probe),
                            Some(ServiceProbeKind::Stopped)
                        );
                        HandoffRequest::InstallOrStartService {
                            source_dir: source_dir.display().to_string(),
                            start_only,
                        }
                    };
                    if let Ok(payload) = serialize_handoff_request_zeroizing(&req) {
                        begin_privileged_action(&mut st, "Start/Repair Service", payload);
                    }
                }
                (IDC_BTN_CLEANUP, WIN_BN_CLICKED) => {
                    if let Ok(payload) =
                        serialize_handoff_request_zeroizing(&HandoffRequest::Cleanup)
                    {
                        begin_privileged_action(&mut st, "Cleanup Stale Routes", payload);
                    }
                }
                (IDC_BTN_RESET_ID, WIN_BN_CLICKED) => {
                    prompt = Some(PendingUiPrompt::ConfirmResetIdentity);
                }
                (IDC_BTN_NETCHECK, WIN_BN_CLICKED) => {
                    st.detail_override = Some("Running Netcheck diagnostics...".to_owned());
                    if let Some(poller) = &st.poller {
                        poller.spawn_netcheck();
                    }
                    refresh_ui_from_state(&mut st);
                }
                (IDC_BTN_PING_PEER, WIN_BN_CLICKED) => {
                    if let Some(idx) = listbox_selected_index(st.controls.list_peers)
                        && let Some(peer) = st.displayed_peers.get(idx)
                    {
                        let target = peer.name.as_str().to_owned();
                        st.detail_override = Some(format!("Pinging `{target}` (4 probes)..."));
                        if let Some(poller) = &st.poller {
                            poller.spawn_ping(target, 4, false);
                        }
                        refresh_ui_from_state(&mut st);
                    }
                }
                (IDC_BTN_BUGREPORT, WIN_BN_CLICKED) => {
                    prompt = Some(PendingUiPrompt::SaveBugreport);
                }
                (IDC_CHK_AUTOSTART, WIN_BN_CLICKED) => {
                    let want = get_checkbox_checked(st.controls.chk_autostart);
                    match set_launch_at_login_enabled(want) {
                        Ok(()) => st.autostart_enabled = want,
                        Err(err) => {
                            st.active_action_error = Some(err.to_string());
                            refresh_ui_from_state(&mut st);
                        }
                    }
                }
                (IDC_BTN_UNINSTALL, WIN_BN_CLICKED) => {
                    prompt = Some(PendingUiPrompt::ConfirmUninstall);
                }
                (IDC_BTN_ENROLL_SAVE, WIN_BN_CLICKED) => {
                    let is_rotate = st.active_modal == Some(Zone3ModalKind::RotateNodeKey)
                        || st.snapshot.ui_state == DesktopUiState::ReauthRequired;
                    prompt = Some(PendingUiPrompt::ConfirmAndRunEnrollment { is_rotate });
                }
                (IDC_BTN_UPDATE_SERVER, WIN_BN_CLICKED) => {
                    let form = read_form_input(&st.controls);
                    match validate_update_server_payload(
                        &form.endpoint_raw,
                        form.tls_mode,
                        &form.spki_pin_raw,
                    ) {
                        Ok((_ep, payload)) => {
                            st.active_modal = None;
                            begin_privileged_action(&mut st, "Update Server/Pin", payload);
                        }
                        Err(err) => {
                            st.active_action_error = Some(err);
                            refresh_ui_from_state(&mut st);
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(p) = prompt {
            execute_pending_prompt(self, hwnd, p);
        }
    }

    fn on_timer(&self, hwnd: isize, timer_id: usize) {
        let mut quit_now = false;
        {
            let Ok(mut st) = self.inner.try_borrow_mut() else {
                return;
            };
            if timer_id == TIMER_CLIPBOARD_WIPE {
                clear_armed_clipboard(&mut st);
            } else if timer_id == TIMER_TOAST_CLEAR {
                kill_window_timer(hwnd, TIMER_TOAST_CLEAR);
                st.toast_message = None;
                invalidate_window(hwnd);
            } else if timer_id == TIMER_SHUTDOWN_POLL
                && let Some(ev) = &st.shutdown_event
                && wait_event_signaled(ev, 0, "window::shutdown_poll").unwrap_or(false)
            {
                quit_now = true;
            }
        }
        if quit_now {
            let Ok(mut st) = self.inner.try_borrow_mut() else {
                return;
            };
            perform_graceful_exit(&mut st);
        }
    }

    fn on_tray_callback(&self, hwnd: isize, event_msg: u32) {
        if event_msg == WIN_WM_LBUTTONDBLCLK || event_msg == WIN_WM_LBUTTONUP {
            let Ok(mut st) = self.inner.try_borrow_mut() else {
                return;
            };
            st.visible = true;
            if let Some(poller) = &st.poller {
                poller.set_dashboard_visible(true);
                poller.trigger_immediate_poll();
            }
            show_window_and_focus(hwnd);
            return;
        }
        if event_msg != WIN_WM_RBUTTONUP {
            return;
        }

        let menu_choice = {
            let Ok(st) = self.inner.try_borrow() else {
                return;
            };
            let overlay_ip = st
                .latest_poll
                .as_ref()
                .and_then(|p| p.status.as_ref())
                .and_then(|s| s.overlay_ip)
                .map(|ip| ip.to_string());
            st.tray
                .as_ref()
                .and_then(|tray| {
                    tray.show_menu(
                        hwnd,
                        &st.snapshot,
                        overlay_ip.as_deref(),
                        st.autostart_enabled,
                    )
                    .ok()
                })
                .flatten()
        };

        if let Some(cmd) = menu_choice {
            handle_tray_menu_command(self, hwnd, cmd);
        }
    }

    fn on_taskbar_created(&self, hwnd: isize) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        let snapshot = st.snapshot.clone();
        if let Some(tray) = &mut st.tray {
            let _restored = tray.ensure_added_or_restore(hwnd, &snapshot);
        }
    }

    fn on_activate_requested(&self, hwnd: isize) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        st.visible = true;
        if let Some(poller) = &st.poller {
            poller.set_dashboard_visible(true);
            poller.trigger_immediate_poll();
        }
        show_window_and_focus(hwnd);
    }

    fn on_graceful_shutdown(&self, _hwnd: isize) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        perform_graceful_exit(&mut st);
    }

    fn on_app_message(&self, _hwnd: isize, msg: u32, _wparam: usize, _lparam: isize) {
        let mut quit_now = false;
        let mut message_box_err: Option<String> = None;
        {
            let Ok(mut st) = self.inner.try_borrow_mut() else {
                return;
            };
            if msg == WM_APP_STATE_REFRESH {
                let maybe_poll = st
                    .poller
                    .as_ref()
                    .and_then(BackgroundIpcController::take_latest_poll);
                if let Some(update) = maybe_poll {
                    st.latest_poll = Some(update);
                    refresh_ui_from_state(&mut st);
                }
            } else if matches!(
                msg,
                WM_APP_WORKER_DONE
                    | WM_APP_NETCHECK_DONE
                    | WM_APP_PING_DONE
                    | WM_APP_BUGREPORT_DONE
            ) {
                while let Some(ev) = st
                    .poller
                    .as_ref()
                    .and_then(BackgroundIpcController::pop_async_event)
                {
                    match ev {
                        UiAsyncEvent::Netcheck(res) => {
                            st.detail_override = Some(match res {
                                Ok(r) => format_netcheck_report(&r),
                                Err(err) => {
                                    format!("Netcheck failed: {}", format_user_facing_error(&err))
                                }
                            });
                        }
                        UiAsyncEvent::Ping(res) => {
                            st.detail_override = Some(match res {
                                Ok(r) => format_ping_response(&r),
                                Err(err) => {
                                    format!("Ping failed: {}", format_user_facing_error(&err))
                                }
                            });
                        }
                        UiAsyncEvent::Bugreport(res) => match res {
                            Ok((scrubbed, bytes, path)) => {
                                st.detail_override = Some(format!(
                                    "Bugreport saved to {path}\r\n\
                                     Size: {bytes} bytes | Redacted secrets: {scrubbed}"
                                ));
                                st.active_action_error = None;
                            }
                            Err(err) => {
                                let msg_safe = format_user_facing_error(&err);
                                st.active_action_error = Some(msg_safe.clone());
                                st.detail_override = Some(format!("Bugreport failed: {msg_safe}"));
                                message_box_err = Some(msg_safe);
                            }
                        },
                        UiAsyncEvent::WorkerAction {
                            action_label,
                            result,
                        } => {
                            st.busy_action = false;
                            match result {
                                Ok(summary) => {
                                    st.active_action_error = None;
                                    st.detail_override = Some(format!("{action_label}: {summary}"));
                                    if action_label == "Reset Identity" {
                                        st.form_seeded_from_status = false;
                                        st.active_modal = None;
                                    }
                                    if st.pending_disconnect_and_quit {
                                        quit_now = true;
                                    }
                                }
                                Err(err) => {
                                    let safe = format_user_facing_error(&err);
                                    st.active_action_error = Some(safe.clone());
                                    st.detail_override =
                                        Some(format!("{action_label} error: {safe}"));
                                    st.pending_disconnect_and_quit = false;
                                }
                            }
                        }
                    }
                }
                refresh_ui_from_state(&mut st);
            }
        }

        if let Some(err) = message_box_err {
            show_message_box(_hwnd, "Mesh VPN", &err, MessageBoxKind::Error);
        }
        if quit_now {
            let Ok(mut st) = self.inner.try_borrow_mut() else {
                return;
            };
            perform_graceful_exit(&mut st);
        }
    }

    fn on_ctrl_v(&self, _hwnd: isize, focused_control_id: u16) {
        if !matches!(
            focused_control_id,
            IDC_EDIT_PREAUTH | IDC_EDIT_ENDPOINT | IDC_EDIT_PIN
        ) {
            return;
        }
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        if let Ok((seq, Some(text))) = read_clipboard_zeroizing_with_seq()
            && (focused_control_id == IDC_EDIT_PREAUTH || looks_like_sensitive_paste(&text))
        {
            arm_clipboard_wipe(&mut st, ClipboardSecretGuard::arm(seq, &text));
        }
    }

    fn on_dpi_changed(&self, hwnd: isize, dpi: u32) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        st.current_dpi = dpi.max(72);
        rebuild_theme_and_repaint(&mut st);
        sync_zone_visibility_and_layout(&st);
        refresh_ui_from_state(&mut st);
        let _h = hwnd;
    }

    fn on_theme_changed(&self, _hwnd: isize) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        rebuild_theme_and_repaint(&mut st);
    }

    fn on_ctlcolor(&self, _hwnd: isize, hdc: isize, control_hwnd: isize, msg: u32) -> isize {
        let Ok(st) = self.inner.try_borrow() else {
            return 0;
        };
        if msg == WIN_WM_CTLCOLORSTATIC {
            if control_hwnd == st.controls.status_title {
                set_dc_text_and_bk_color(hdc, st.palette.text_primary, st.palette.bg_color, true);
                st.palette.bg_brush_raw()
            } else {
                set_dc_text_and_bk_color(hdc, st.palette.text_primary, st.palette.card_color, true);
                st.palette.card_brush_raw()
            }
        } else if msg == WIN_WM_CTLCOLOREDIT || msg == WIN_WM_CTLCOLORLISTBOX {
            set_dc_text_and_bk_color(hdc, st.palette.text_primary, st.palette.card_color, false);
            st.palette.card_brush_raw()
        } else {
            0
        }
    }

    fn on_erase_bkgnd(&self, _hwnd: isize, _hdc: isize) -> bool {
        true
    }

    fn on_paint(&self, hwnd: isize) -> bool {
        let Ok(st) = self.inner.try_borrow() else {
            return false;
        };
        let Some(guard) = PaintGuard::begin(hwnd) else {
            return false;
        };
        let (w, h) = get_client_size(hwnd);
        let status_ref = st.latest_poll.as_ref().and_then(|p| p.status.as_ref());
        let model = build_status_hero_model(
            &st.snapshot,
            status_ref,
            st.active_tab,
            st.toast_message.as_deref(),
        );
        paint_status_hero_surface(guard.hdc(), w, h, st.current_dpi, &model, &st.palette);
        true
    }

    fn on_draw_item(&self, _hwnd: isize, item: &OwnerDrawItem) -> bool {
        let Ok(st) = self.inner.try_borrow() else {
            return false;
        };
        let text = get_control_text(item.hwnd_item);
        let disabled = (item.item_state & WIN_ODS_DISABLED) != 0;
        let pressed = (item.item_state & WIN_ODS_SELECTED) != 0;
        let focused = (item.item_state & WIN_ODS_FOCUS) != 0;
        let active = is_owner_draw_active(&st, item.control_id);
        let is_primary_cta = matches!(
            item.control_id,
            IDC_BTN_CONNECT | IDC_BTN_ENROLL_SAVE | IDC_BTN_UPDATE_SERVER
        );
        let is_danger_cta = matches!(item.control_id, IDC_BTN_RESET_ID | IDC_BTN_UNINSTALL);

        let (bg_brush, border_pen, text_color) = if disabled {
            (
                st.palette.bg_brush.as_ref(),
                st.palette.border_pen.as_ref(),
                st.palette.text_secondary,
            )
        } else if active || is_primary_cta || pressed {
            (
                st.palette.brand_brush.as_ref(),
                st.palette.brand_border_pen.as_ref(),
                st.palette.on_accent_text_color(),
            )
        } else if is_danger_cta {
            (
                st.palette.error_brush.as_ref(),
                st.palette.border_pen.as_ref(),
                st.palette.on_accent_text_color(),
            )
        } else {
            (
                st.palette.card_brush.as_ref(),
                st.palette.border_pen.as_ref(),
                st.palette.text_primary,
            )
        };

        if let (Some(bg), Some(pen), Some(font)) =
            (bg_brush, border_pen, st.palette.font_body.as_ref())
        {
            let style = OwnerDrawButtonStyle {
                text: &text,
                bg_brush: bg,
                border_pen: pen,
                text_color,
                font,
                focused,
            };
            draw_owner_draw_button(item.hdc, &item.rect, &style);
            return true;
        }
        false
    }

    fn on_resize(&self, hwnd: isize, _width: i32, _height: i32) {
        let Ok(st) = self.inner.try_borrow() else {
            return;
        };
        if st.controls.status_title != 0 {
            sync_zone_visibility_and_layout(&st);
            invalidate_window(hwnd);
        }
    }

    fn on_query_version(&self) -> isize {
        let triple = SemVerTriple::parse(env!("CARGO_PKG_VERSION")).unwrap_or(SemVerTriple {
            major: 0,
            minor: 4,
            patch: 0,
        });
        isize::try_from(triple.pack_u32()).unwrap_or(0)
    }

    fn on_close(&self, hwnd: isize) -> bool {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return true;
        };
        st.visible = false;
        hide_window(hwnd);
        if let Some(poller) = &st.poller {
            poller.set_dashboard_visible(false);
        }
        if let Some(tray) = &mut st.tray {
            tray.show_minimize_balloon_once();
        }
        true
    }

    fn on_destroy(&self, hwnd: isize) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        st.shutdown_started = true;
        kill_window_timer(hwnd, TIMER_SHUTDOWN_POLL);
        kill_window_timer(hwnd, TIMER_TOAST_CLEAR);
        clear_armed_clipboard(&mut st);
        set_control_text(st.controls.edit_preauth, "");
        st.palette.clear_brush_cache();
        if let Some(tray) = &mut st.tray {
            tray.remove();
        }
        if let Some(mut poller) = st.poller.take() {
            poller.shutdown();
        }
    }
}

fn handle_tray_menu_command(app: &DashboardApp, hwnd: isize, cmd: u16) {
    let mut prompt: Option<PendingUiPrompt> = None;
    {
        let Ok(mut st) = app.inner.try_borrow_mut() else {
            return;
        };
        match cmd {
            IDM_OPEN_DASHBOARD => {
                st.visible = true;
                if let Some(poller) = &st.poller {
                    poller.set_dashboard_visible(true);
                    poller.trigger_immediate_poll();
                }
                show_window_and_focus(hwnd);
            }
            IDM_CONNECT_UP => match build_reconnect_payload(&st) {
                Ok(payload) => begin_privileged_action(&mut st, "Reconnect", payload),
                Err(err) => {
                    st.active_action_error = Some(err);
                    st.visible = true;
                    show_window_and_focus(hwnd);
                    refresh_ui_from_state(&mut st);
                }
            },
            IDM_DISCONNECT => {
                if let Ok(payload) = serialize_handoff_request_zeroizing(&HandoffRequest::Down) {
                    begin_privileged_action(&mut st, "Disconnect", payload);
                }
            }
            IDM_NETCHECK => {
                st.visible = true;
                st.active_tab = DashboardTab::DiagnosticsSettings;
                st.active_modal = None;
                st.detail_override = Some("Running Netcheck diagnostics...".to_owned());
                if let Some(poller) = &st.poller {
                    poller.set_dashboard_visible(true);
                    poller.spawn_netcheck();
                }
                show_window_and_focus(hwnd);
                refresh_ui_from_state(&mut st);
            }
            IDM_EXPORT_BUGREPORT => {
                prompt = Some(PendingUiPrompt::SaveBugreport);
            }
            IDM_TOGGLE_AUTOSTART => {
                let next = !st.autostart_enabled;
                if set_launch_at_login_enabled(next).is_ok() {
                    st.autostart_enabled = next;
                    refresh_ui_from_state(&mut st);
                }
            }
            IDM_QUIT_KEEP_BACKGROUND => {
                prompt = Some(PendingUiPrompt::QuitKeepBackground);
            }
            IDM_DISCONNECT_AND_QUIT => {
                prompt = Some(PendingUiPrompt::DisconnectAndQuit);
            }
            _ => {}
        }
    }
    if let Some(p) = prompt {
        execute_pending_prompt(app, hwnd, p);
    }
}

fn execute_pending_prompt(app: &DashboardApp, hwnd: isize, prompt: PendingUiPrompt) {
    match prompt {
        PendingUiPrompt::SaveBugreport => {
            // IG-DGUI-WA-03: Run GetSaveFileNameW BEFORE activating PollingSuspensionGuard!
            let dest_path = match save_tar_file_dialog(hwnd, DEFAULT_BUGREPORT_FILENAME) {
                Ok(Some(path)) => path,
                Ok(None) => return,
                Err(err) => {
                    show_message_box(hwnd, "Mesh VPN", &err.to_string(), MessageBoxKind::Error);
                    return;
                }
            };
            let Ok(mut st) = app.inner.try_borrow_mut() else {
                return;
            };
            st.detail_override = Some(format!(
                "Streaming redacted bugreport to {}...",
                dest_path.display()
            ));
            if let Some(poller) = &st.poller {
                poller.spawn_bugreport_export(dest_path);
            }
            refresh_ui_from_state(&mut st);
        }
        PendingUiPrompt::ConfirmAndRunEnrollment { is_rotate } => {
            let draft_res = {
                let Ok(st) = app.inner.try_borrow() else {
                    return;
                };
                let form = read_form_input(&st.controls);
                if is_rotate {
                    let srv = st
                        .latest_poll
                        .as_ref()
                        .and_then(|p| p.status.as_ref())
                        .and_then(|s| s.server_connection.as_ref());
                    let ep =
                        srv.map_or(form.endpoint_raw.as_str(), |s| s.control_endpoint.as_str());
                    let pin = srv.and_then(|s| s.active_pin);
                    validate_rotate_key_to_draft(ep, form.tls_mode, pin, &form.preauth_key_raw)
                } else {
                    validate_manual_onboarding_to_draft(&form)
                }
            };
            let draft = match draft_res {
                Ok(d) => d,
                Err(err) => {
                    let Ok(mut st) = app.inner.try_borrow_mut() else {
                        return;
                    };
                    st.active_action_error = Some(sanitize_gui_log_text(&err));
                    refresh_ui_from_state(&mut st);
                    return;
                }
            };

            let summary = draft.format_confirmation_summary();
            if !show_message_box(
                hwnd,
                "Confirm Mesh VPN Enrollment",
                &summary,
                MessageBoxKind::ConfirmYesNo,
            ) {
                return;
            }
            match draft.build_handoff_payload() {
                Ok(payload) => {
                    let Ok(mut st) = app.inner.try_borrow_mut() else {
                        return;
                    };
                    set_control_text(st.controls.edit_preauth, "");
                    clear_armed_clipboard(&mut st);
                    st.active_modal = None;
                    let label = if is_rotate {
                        "Rotate Key"
                    } else {
                        "Enroll & Connect"
                    };
                    begin_privileged_action(&mut st, label, payload);
                }
                Err(err) => {
                    let Ok(mut st) = app.inner.try_borrow_mut() else {
                        return;
                    };
                    st.active_action_error = Some(err);
                    refresh_ui_from_state(&mut st);
                }
            }
        }
        PendingUiPrompt::ConfirmResetIdentity => {
            let confirmed = show_message_box(
                hwnd,
                "Confirm Reset Identity",
                "This clears local node keys so you can enroll with a new Pre-Auth Key.\r\n\
                 Proceed with UAC elevation?",
                MessageBoxKind::ConfirmYesNo,
            );
            if !confirmed {
                return;
            }
            let Ok(mut st) = app.inner.try_borrow_mut() else {
                return;
            };
            if let Ok(payload) = serialize_handoff_request_zeroizing(&HandoffRequest::ResetIdentity)
            {
                set_control_text(st.controls.edit_preauth, "");
                st.active_modal = None;
                begin_privileged_action(&mut st, "Reset Identity", payload);
            }
        }
        PendingUiPrompt::ConfirmUninstall => {
            let proceed = show_message_box(
                hwnd,
                "Uninstall Mesh VPN",
                "Stop and remove MeshVpnAgent service and binaries?\r\n\
                 Click Yes to continue (next prompt asks whether to keep keys.json).",
                MessageBoxKind::ConfirmYesNo,
            );
            if !proceed {
                return;
            }
            let purge_keys = show_message_box(
                hwnd,
                "Purge Identity Keys?",
                "Also delete saved keys.json and bootstrap.toml from C:\\ProgramData\\Mesh?\r\n\
                 Click Yes to purge, or No to preserve keys for reinstall.",
                MessageBoxKind::ConfirmYesNo,
            );
            let _cleaned_hkcu = cleanup_current_user_autostart_and_shortcuts();
            let Ok(mut st) = app.inner.try_borrow_mut() else {
                return;
            };
            st.autostart_enabled = false;
            if let Ok(payload) =
                serialize_handoff_request_zeroizing(&HandoffRequest::UninstallService {
                    purge_keys,
                })
            {
                begin_privileged_action(&mut st, "Uninstall Service", payload);
            }
        }
        PendingUiPrompt::QuitKeepBackground => {
            let Ok(mut st) = app.inner.try_borrow_mut() else {
                return;
            };
            perform_graceful_exit(&mut st);
        }
        PendingUiPrompt::DisconnectAndQuit => {
            let mut should_exit_immediately = false;
            {
                let Ok(mut st) = app.inner.try_borrow_mut() else {
                    return;
                };
                let active_tunnel = matches!(
                    (st.snapshot.ui_state, st.snapshot.tunnel_sub_state),
                    (
                        DesktopUiState::Connected,
                        TunnelSubState::Connected | TunnelSubState::Degraded
                    ) | (DesktopUiState::Connecting, _)
                );
                if active_tunnel {
                    st.pending_disconnect_and_quit = true;
                    if let Ok(payload) = serialize_handoff_request_zeroizing(&HandoffRequest::Down)
                    {
                        begin_privileged_action(&mut st, "Disconnect & Quit", payload);
                    }
                } else {
                    should_exit_immediately = true;
                }
            }
            if should_exit_immediately {
                let Ok(mut st) = app.inner.try_borrow_mut() else {
                    return;
                };
                perform_graceful_exit(&mut st);
            }
        }
    }
}

fn resolve_bundle_source_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        return dir.to_path_buf();
    }
    let pf = std::env::var_os("ProgramFiles").map(PathBuf::from);
    resolve_program_files_mesh_dir(pf.as_deref())
}
