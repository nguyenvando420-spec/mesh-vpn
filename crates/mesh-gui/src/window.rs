//! Win32 Dashboard window layout, DPI scaling, onboarding/re-auth/recovery workflows,
//! atomic clipboard 30s wipe hooks (`IG-DGUI-WA-01`), bugreport `GetSaveFileNameW` ->
//! `PollingSuspensionGuard` ordering (`IG-DGUI-WA-03`), and clean `<= 3s` shutdown (`US-103..108`).

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mesh_core::NodeName;
use mesh_net::gui_handoff::{HandoffRequest, serialize_handoff_request_zeroizing};
use mesh_proto::agent_ipc::{AgentPeerStatus, AgentStatusResponse, TlsAuthMode};
use mesh_sys::error::{SysError, SysResult};
use mesh_sys::gui_windows::{
    ControlRect, GuiWindowSpec, MessageBoxKind, OwnedGdiObj, OwnedIcon, SingleInstanceGuard,
    WIN_BN_CLICKED, WIN_EN_CHANGE, WIN_LBN_SELCHANGE, WIN_WM_LBUTTONDBLCLK, WIN_WM_LBUTTONUP,
    WIN_WM_RBUTTONUP, WM_APP_BUGREPORT_DONE, WM_APP_NETCHECK_DONE, WM_APP_PING_DONE,
    WM_APP_STATE_REFRESH, WM_APP_WORKER_DONE, WindowEventHandler, acquire_single_instance_mutex,
    activate_existing_gui_window, create_button, create_checkbox, create_dpi_ui_font, create_edit,
    create_listbox, create_named_shutdown_event, create_radio_button, create_static_text,
    destroy_window, enable_per_monitor_v2_dpi, find_window_by_class, get_checkbox_checked,
    get_client_size, get_control_text, get_dpi_for_window, get_sm_icon_px_for_dpi, hide_window,
    init_common_controls, is_user_autostart_enabled, kill_window_timer, listbox_reset_and_fill,
    listbox_selected_index, post_graceful_shutdown_to_window, query_window_version,
    read_clipboard_utf16_with_seq, register_activate_window_message,
    register_taskbar_created_message, remove_user_shortcuts_and_autostart, run_gui_window,
    save_tar_file_dialog, set_checkbox_checked, set_control_bounds, set_control_enabled,
    set_control_font, set_control_text, set_focus_control, set_user_autostart, set_window_icon,
    set_window_timer, show_message_box, show_window_and_focus, signal_shutdown_event,
    wait_event_signaled,
};
use zeroize::Zeroizing;

use crate::app::{
    DerivedUiSnapshot, DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState,
    derive_desktop_ui_state, format_user_facing_error, sanitize_gui_log_text,
};
use crate::autostart::{AUTOSTART_REG_VALUE_NAME, format_autostart_command_line};
use crate::clipboard::{
    CLIPBOARD_WIPE_DELAY_MS, ClipboardSecretGuard, attempt_atomic_clipboard_clear,
    looks_like_sensitive_paste,
};
use crate::diagnostics_view::{
    DEFAULT_BUGREPORT_FILENAME, format_netcheck_report, format_self_network_panel,
};
use crate::elevation_worker::resolve_program_files_mesh_dir;
use crate::icons::{UiIconTone, create_status_icon_for_px, icon_tone_for_state};
use crate::ipc_poller::{BackgroundIpcController, PolledStateUpdate, UiAsyncEvent};
use crate::onboarding::{
    OnboardingFormInput, OnboardingTlsMode, parse_mesh_join_uri_to_draft,
    should_lock_system_ca_for_endpoint, validate_manual_onboarding_to_draft,
    validate_rotate_key_to_draft, validate_update_server_payload,
};
use crate::peers_view::{
    filter_peers, format_peer_detail_summary, format_peer_list_entry, format_ping_response,
};
use crate::single_instance::{
    MAIN_WINDOW_CLASS_NAME, SemVerTriple, UPGRADE_SHUTDOWN_WAIT_MS, should_request_upgrade_shutdown,
};
use crate::tray::{
    IDM_CONNECT_UP, IDM_DISCONNECT, IDM_DISCONNECT_AND_QUIT, IDM_EXPORT_BUGREPORT, IDM_NETCHECK,
    IDM_OPEN_DASHBOARD, IDM_QUIT_KEEP_BACKGROUND, IDM_TOGGLE_AUTOSTART, TrayStateManager,
};

const IDC_STATUS_TITLE: u16 = 2001;
const IDC_STATUS_META: u16 = 2002;
const IDC_BANNER_TEXT: u16 = 2003;
const IDC_BTN_CONNECT: u16 = 2004;
const IDC_BTN_DISCONNECT: u16 = 2005;
const IDC_BTN_START_REPAIR: u16 = 2006;
const IDC_BTN_CLEANUP: u16 = 2007;
const IDC_BTN_RESET_ID: u16 = 2008;
const IDC_BTN_NETCHECK: u16 = 2009;
const IDC_BTN_BUGREPORT: u16 = 2010;
const IDC_CHK_AUTOSTART: u16 = 2011;
const IDC_BTN_UNINSTALL: u16 = 2012;

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

const IDC_LBL_PEERS: u16 = 2040;
const IDC_EDIT_PEER_FILTER: u16 = 2041;
const IDC_BTN_PING_PEER: u16 = 2042;
const IDC_LIST_PEERS: u16 = 2043;
const IDC_EDIT_DETAILS: u16 = 2044;

const TIMER_CLIPBOARD_WIPE: usize = 1;
const TIMER_SHUTDOWN_POLL: usize = 2;

const BASE_WIN_W: i32 = 820;
const BASE_WIN_H: i32 = 650;

enum SingleInstanceStartup {
    Primary {
        guard: SingleInstanceGuard,
        activate_msg: u32,
    },
    ActivatedExistingAndExit,
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
        minor: 3,
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
    status_meta: isize,
    banner_text: isize,
    btn_connect: isize,
    btn_disconnect: isize,
    btn_start_repair: isize,
    btn_cleanup: isize,
    btn_reset_id: isize,
    btn_netcheck: isize,
    btn_bugreport: isize,
    chk_autostart: isize,
    btn_uninstall: isize,

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

    lbl_peers: isize,
    edit_peer_filter: isize,
    btn_ping_peer: isize,
    list_peers: isize,
    edit_details: isize,
}

impl UiControls {
    fn all_handles(&self) -> [isize; 27] {
        [
            self.status_title,
            self.status_meta,
            self.banner_text,
            self.btn_connect,
            self.btn_disconnect,
            self.btn_start_repair,
            self.btn_cleanup,
            self.btn_reset_id,
            self.btn_netcheck,
            self.btn_bugreport,
            self.chk_autostart,
            self.btn_uninstall,
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
            self.lbl_peers,
        ]
    }

    fn peer_handles(&self) -> [isize; 4] {
        [
            self.edit_peer_filter,
            self.btn_ping_peer,
            self.list_peers,
            self.edit_details,
        ]
    }
}

struct DashboardState {
    hwnd: isize,
    visible: bool,
    controls: UiControls,
    ui_font: Option<OwnedGdiObj>,
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
    form_seeded_from_status: bool,
    busy_action: bool,
    pending_disconnect_and_quit: bool,
    shutdown_started: bool,
    autostart_enabled: bool,
}

impl DashboardState {
    fn new(initially_visible: bool) -> Self {
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
            controls: UiControls::default(),
            ui_font: None,
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
    ((px96 * i32::try_from(dpi).unwrap_or(96)) + 48) / 96
}

fn build_controls(hwnd: isize) -> Option<UiControls> {
    let z = ControlRect::new(0, 0, 100, 24);
    Some(UiControls {
        status_title: create_static_text(hwnd, IDC_STATUS_TITLE, "Initializing Mesh VPN...", z)
            .ok()?,
        status_meta: create_static_text(hwnd, IDC_STATUS_META, "", z).ok()?,
        banner_text: create_static_text(hwnd, IDC_BANNER_TEXT, "", z).ok()?,
        btn_connect: create_button(hwnd, IDC_BTN_CONNECT, "Connect", z, true).ok()?,
        btn_disconnect: create_button(hwnd, IDC_BTN_DISCONNECT, "Disconnect", z, false).ok()?,
        btn_start_repair: create_button(
            hwnd,
            IDC_BTN_START_REPAIR,
            "Start / Update Service (UAC)",
            z,
            false,
        )
        .ok()?,
        btn_cleanup: create_button(hwnd, IDC_BTN_CLEANUP, "Cleanup", z, false).ok()?,
        btn_reset_id: create_button(hwnd, IDC_BTN_RESET_ID, "Reset Identity", z, false).ok()?,
        btn_netcheck: create_button(hwnd, IDC_BTN_NETCHECK, "Netcheck", z, false).ok()?,
        btn_bugreport: create_button(hwnd, IDC_BTN_BUGREPORT, "Bugreport...", z, false).ok()?,
        chk_autostart: create_checkbox(hwnd, IDC_CHK_AUTOSTART, "Launch at Login", z).ok()?,
        btn_uninstall: create_button(hwnd, IDC_BTN_UNINSTALL, "Uninstall...", z, false).ok()?,

        lbl_setup: create_static_text(
            hwnd,
            IDC_LBL_SETUP,
            "Control Onboarding / Server Settings:",
            z,
        )
        .ok()?,
        btn_paste_uri: create_button(hwnd, IDC_BTN_PASTE_URI, "Paste mesh:// URI", z, false)
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
        btn_enroll_save: create_button(hwnd, IDC_BTN_ENROLL_SAVE, "Enroll && Connect", z, false)
            .ok()?,
        btn_update_server: create_button(
            hwnd,
            IDC_BTN_UPDATE_SERVER,
            "Update Server / Pin",
            z,
            false,
        )
        .ok()?,

        lbl_peers: create_static_text(hwnd, IDC_LBL_PEERS, "Peers & Diagnostics:", z).ok()?,
        edit_peer_filter: create_edit(hwnd, IDC_EDIT_PEER_FILTER, "", z, false, false).ok()?,
        btn_ping_peer: create_button(hwnd, IDC_BTN_PING_PEER, "Ping Selected Peer", z, false)
            .ok()?,
        list_peers: create_listbox(hwnd, IDC_LIST_PEERS, z).ok()?,
        edit_details: create_edit(hwnd, IDC_EDIT_DETAILS, "", z, false, true).ok()?,
    })
}

fn layout_controls(hwnd: isize, c: &UiControls) {
    let dpi = get_dpi_for_window(hwnd);
    let (cw, ch) = get_client_size(hwnd);
    let pad = scale(12, dpi);
    let row_h = scale(24, dpi);
    let btn_h = scale(28, dpi);
    let gap = scale(8, dpi);
    let usable_w = (cw - 2 * pad).max(scale(560, dpi));

    let mut y = pad;
    set_control_bounds(c.status_title, pad, y, usable_w, row_h);
    y += row_h + scale(2, dpi);
    set_control_bounds(c.status_meta, pad, y, usable_w, row_h);
    y += row_h + scale(2, dpi);
    set_control_bounds(c.banner_text, pad, y, usable_w, row_h + scale(8, dpi));
    y += row_h + scale(12, dpi);

    // Row 1 action buttons
    let bw1 = scale(90, dpi);
    let bw2 = scale(165, dpi);
    let bw3 = scale(88, dpi);
    set_control_bounds(c.btn_connect, pad, y, bw1, btn_h);
    set_control_bounds(c.btn_disconnect, pad + bw1 + gap, y, bw1, btn_h);
    set_control_bounds(c.btn_start_repair, pad + (bw1 + gap) * 2, y, bw2, btn_h);
    set_control_bounds(
        c.btn_cleanup,
        pad + (bw1 + gap) * 2 + bw2 + gap,
        y,
        bw3,
        btn_h,
    );
    set_control_bounds(
        c.btn_reset_id,
        pad + (bw1 + gap) * 2 + bw2 + bw3 + gap * 2,
        y,
        scale(112, dpi),
        btn_h,
    );
    y += btn_h + gap;

    // Row 2 diagnostics & lifecycle buttons
    let bw_net = scale(95, dpi);
    let bw_bug = scale(110, dpi);
    let bw_auto = scale(140, dpi);
    let bw_unin = scale(100, dpi);
    set_control_bounds(c.btn_netcheck, pad, y, bw_net, btn_h);
    set_control_bounds(c.btn_bugreport, pad + bw_net + gap, y, bw_bug, btn_h);
    set_control_bounds(
        c.chk_autostart,
        pad + bw_net + bw_bug + gap * 2,
        y,
        bw_auto,
        btn_h,
    );
    set_control_bounds(c.btn_uninstall, pad + usable_w - bw_unin, y, bw_unin, btn_h);
    y += btn_h + gap * 2;

    // Onboarding & server configuration group
    let paste_w = scale(145, dpi);
    set_control_bounds(
        c.lbl_setup,
        pad,
        y + scale(3, dpi),
        usable_w - paste_w - gap,
        row_h,
    );
    set_control_bounds(c.btn_paste_uri, pad + usable_w - paste_w, y, paste_w, btn_h);
    y += btn_h + gap;

    let lbl_w = scale(115, dpi);
    let half_w = (usable_w - lbl_w - gap * 2) / 2;
    set_control_bounds(c.lbl_endpoint, pad, y + scale(3, dpi), lbl_w, row_h);
    set_control_bounds(c.edit_endpoint, pad + lbl_w, y, half_w, row_h);
    set_control_bounds(
        c.radio_spki,
        pad + lbl_w + half_w + gap,
        y,
        scale(155, dpi),
        row_h,
    );
    set_control_bounds(
        c.radio_system_ca,
        pad + lbl_w + half_w + gap * 2 + scale(155, dpi),
        y,
        scale(175, dpi),
        row_h,
    );
    y += row_h + gap;

    set_control_bounds(c.lbl_pin, pad, y + scale(3, dpi), lbl_w, row_h);
    set_control_bounds(c.edit_pin, pad + lbl_w, y, usable_w - lbl_w, row_h);
    y += row_h + gap;

    let name_lbl_w = scale(90, dpi);
    let name_edit_w = scale(170, dpi);
    let key_edit_w = (usable_w - lbl_w - name_lbl_w - name_edit_w - gap * 2).max(scale(140, dpi));
    set_control_bounds(c.lbl_preauth, pad, y + scale(3, dpi), lbl_w, row_h);
    set_control_bounds(c.edit_preauth, pad + lbl_w, y, key_edit_w, row_h);
    set_control_bounds(
        c.lbl_nodename,
        pad + lbl_w + key_edit_w + gap,
        y + scale(3, dpi),
        name_lbl_w,
        row_h,
    );
    set_control_bounds(
        c.edit_node_name,
        pad + lbl_w + key_edit_w + gap + name_lbl_w,
        y,
        name_edit_w,
        row_h,
    );
    y += row_h + gap;

    let enroll_w = scale(155, dpi);
    let update_w = scale(165, dpi);
    set_control_bounds(c.btn_enroll_save, pad + lbl_w, y, enroll_w, btn_h);
    set_control_bounds(
        c.btn_update_server,
        pad + lbl_w + enroll_w + gap,
        y,
        update_w,
        btn_h,
    );
    y += btn_h + gap * 2;

    // Peers & Diagnostics section
    let filter_w = scale(210, dpi);
    let ping_w = scale(145, dpi);
    set_control_bounds(
        c.lbl_peers,
        pad,
        y + scale(3, dpi),
        (usable_w - filter_w - ping_w - gap * 2).max(scale(120, dpi)),
        row_h,
    );
    set_control_bounds(
        c.edit_peer_filter,
        pad + usable_w - filter_w - ping_w - gap,
        y,
        filter_w,
        row_h,
    );
    set_control_bounds(c.btn_ping_peer, pad + usable_w - ping_w, y, ping_w, btn_h);
    y += btn_h + gap;

    let rem_h = (ch - y - pad).max(scale(120, dpi));
    let list_h = (rem_h * 45) / 100;
    let detail_h = (rem_h - list_h - gap).max(scale(60, dpi));
    set_control_bounds(c.list_peers, pad, y, usable_w, list_h);
    set_control_bounds(c.edit_details, pad, y + list_h + gap, usable_w, detail_h);
}

fn apply_font_to_all(c: &UiControls, font: &OwnedGdiObj) {
    for h in c.all_handles() {
        set_control_font(h, font);
    }
    for h in c.peer_handles() {
        set_control_font(h, font);
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

    let c = &st.controls;
    let headline = st.snapshot.ui_state.headline(st.snapshot.tunnel_sub_state);
    set_control_text(
        c.status_title,
        &format!("State: {} — {headline}", st.snapshot.ui_state.label()),
    );

    let status_ref = st.latest_poll.as_ref().and_then(|p| p.status.as_ref());
    let meta_line = build_meta_line(status_ref, &st.snapshot);
    set_control_text(c.status_meta, &meta_line);

    let banner = st
        .snapshot
        .legacy_banner
        .as_deref()
        .or(st.snapshot.version_mismatch_banner.as_deref())
        .or(st.snapshot.recoverable_error.as_deref())
        .unwrap_or("");
    set_control_text(c.banner_text, banner);

    if let Some(status) = status_ref
        && !st.form_seeded_from_status
        && let Some(srv) = &status.server_connection
        && !srv.control_endpoint.trim().is_empty()
    {
        set_control_text(c.edit_endpoint, &srv.control_endpoint);
        let is_pin = matches!(srv.tls_auth_mode, TlsAuthMode::SpkiPin);
        set_checkbox_checked(c.radio_spki, is_pin);
        set_checkbox_checked(c.radio_system_ca, !is_pin);
        if let Some(pin) = &srv.active_pin {
            set_control_text(c.edit_pin, &pin.to_string());
        }
        if let Some(node) = &status.node_name {
            set_control_text(c.edit_node_name, node.as_str());
        }
        st.form_seeded_from_status = true;
    }

    sync_zero_tofu_radio_state(c);
    set_checkbox_checked(c.chk_autostart, st.autostart_enabled);

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
    set_control_enabled(c.btn_connect, can_reconnect);
    set_control_enabled(c.btn_disconnect, can_disconnect);
    set_control_enabled(c.btn_start_repair, !st.busy_action);
    set_control_enabled(c.btn_cleanup, !st.busy_action);
    set_control_enabled(
        c.btn_reset_id,
        !st.busy_action && ipc_up && st.snapshot.enrolled,
    );
    set_control_enabled(c.btn_netcheck, !st.busy_action && ipc_up);
    set_control_enabled(c.btn_bugreport, !st.busy_action && ipc_up);
    set_control_enabled(c.btn_uninstall, !st.busy_action);
    set_control_enabled(
        c.btn_enroll_save,
        !st.busy_action
            && ipc_up
            && matches!(
                st.snapshot.ui_state,
                DesktopUiState::NotEnrolled
                    | DesktopUiState::ReauthRequired
                    | DesktopUiState::Revoked
                    | DesktopUiState::ErrorRecoverable
            ),
    );
    set_control_enabled(
        c.btn_update_server,
        !st.busy_action && ipc_up && st.snapshot.enrolled,
    );

    if st.snapshot.ui_state == DesktopUiState::ReauthRequired {
        set_control_text(c.btn_enroll_save, "Rotate Key (UAC)");
    } else {
        set_control_text(c.btn_enroll_save, "Enroll && Connect");
    }

    refresh_peers_and_details(st);

    let tone = icon_tone_for_state(st.snapshot.ui_state, st.snapshot.tunnel_sub_state);
    let big_px = get_sm_icon_px_for_dpi(get_dpi_for_window(st.hwnd)).max(32);
    if let Ok(win_icon) = create_status_icon_for_px(tone, big_px) {
        set_window_icon(st.hwnd, &win_icon);
        st.window_icon = Some(win_icon);
    }
    if let Some(tray) = &mut st.tray {
        tray.sync_state(st.hwnd, &st.snapshot);
    }
}

fn build_meta_line(status: Option<&AgentStatusResponse>, snapshot: &DerivedUiSnapshot) -> String {
    let ver_tag = match &snapshot.version_indicator {
        crate::app::AgentVersionIndicator::Compatible(v) => format!("Agent v{v}"),
        crate::app::AgentVersionIndicator::Mismatch {
            gui_version,
            agent_version,
        } => format!("GUI v{gui_version} != Agent v{agent_version}"),
        crate::app::AgentVersionIndicator::LegacyPre030 => "Agent <0.3.0 (Legacy)".to_owned(),
        crate::app::AgentVersionIndicator::Unknown => "Agent v?".to_owned(),
    };
    let Some(st) = status else {
        return format!("GUI v{} | {ver_tag}", env!("CARGO_PKG_VERSION"));
    };
    let ip = st
        .overlay_ip
        .map_or_else(|| "Unassigned".to_owned(), |v| v.to_string());
    let name = st.node_name.as_ref().map_or("<unnamed>", NodeName::as_str);
    format!(
        "Node: {name} | Overlay IP: {ip} | Peers: {} | {ver_tag}",
        st.peers.len()
    )
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

    let filtered = filter_peers(all_peers, &filter_query);
    st.displayed_peers = filtered.iter().copied().cloned().collect();
    let labels: Vec<String> = st
        .displayed_peers
        .iter()
        .map(format_peer_list_entry)
        .collect();
    let new_sel =
        prev_sel_id.and_then(|id| st.displayed_peers.iter().position(|p| p.node_id == id));
    listbox_reset_and_fill(st.controls.list_peers, &labels, new_sel);
    set_control_enabled(
        st.controls.btn_ping_peer,
        !st.busy_action && new_sel.is_some(),
    );

    if let Some(override_text) = &st.detail_override {
        set_control_text(st.controls.edit_details, override_text);
        return;
    }

    if let Some(idx) = new_sel
        && let Some(peer) = st.displayed_peers.get(idx)
    {
        set_control_text(st.controls.edit_details, &format_peer_detail_summary(peer));
        return;
    }

    if let Some(status) = st.latest_poll.as_ref().and_then(|p| p.status.as_ref()) {
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

impl WindowEventHandler for DashboardApp {
    fn on_create(&self, hwnd: isize) {
        let Ok(mut st) = self.inner.try_borrow_mut() else {
            return;
        };
        st.hwnd = hwnd;
        let dpi = get_dpi_for_window(hwnd);
        if let Ok(font) = create_dpi_ui_font(dpi) {
            st.ui_font = Some(font);
        }
        if let Some(controls) = build_controls(hwnd) {
            if let Some(font) = &st.ui_font {
                apply_font_to_all(&controls, font);
            }
            layout_controls(hwnd, &controls);
            st.controls = controls;
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
                    let is_rotate = st.snapshot.ui_state == DesktopUiState::ReauthRequired;
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

    fn on_timer(&self, _hwnd: isize, timer_id: usize) {
        let mut quit_now = false;
        {
            let Ok(mut st) = self.inner.try_borrow_mut() else {
                return;
            };
            if timer_id == TIMER_CLIPBOARD_WIPE {
                clear_armed_clipboard(&mut st);
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
        if !matches!(focused_control_id, IDC_EDIT_PREAUTH | IDC_EDIT_ENDPOINT) {
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
        if let Ok(font) = create_dpi_ui_font(dpi) {
            apply_font_to_all(&st.controls, &font);
            st.ui_font = Some(font);
        }
        layout_controls(hwnd, &st.controls);
        refresh_ui_from_state(&mut st);
    }

    fn on_resize(&self, hwnd: isize, _width: i32, _height: i32) {
        let Ok(st) = self.inner.try_borrow() else {
            return;
        };
        if st.controls.status_title != 0 {
            layout_controls(hwnd, &st.controls);
        }
    }

    fn on_query_version(&self) -> isize {
        let triple = SemVerTriple::parse(env!("CARGO_PKG_VERSION")).unwrap_or(SemVerTriple {
            major: 0,
            minor: 3,
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
        clear_armed_clipboard(&mut st);
        set_control_text(st.controls.edit_preauth, "");
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
    let _focus = set_focus_control;
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
