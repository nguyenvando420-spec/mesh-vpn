//! System Tray 9-item menu, `TaskbarCreated` recovery, one-time minimize balloon, and dual
//! quit semantics (`US-103`, `ADR-020`).

#[cfg(target_os = "windows")]
use mesh_sys::error::SysResult;
#[cfg(target_os = "windows")]
use mesh_sys::gui_windows::{
    OwnedIcon, TrayIconController, TrayMenuEntry, get_dpi_for_window, get_sm_icon_px_for_dpi,
    show_tray_context_menu,
};

use crate::app::{DerivedUiSnapshot, DesktopUiState, TunnelSubState};
#[cfg(target_os = "windows")]
use crate::i18n::t;
use crate::i18n::{LocaleMode, current_locale, t_for};
#[cfg(target_os = "windows")]
use crate::icons::{UiIconTone, create_status_icon_for_px, icon_tone_for_state};

/// Win32 tray icon numeric ID registered via `Shell_NotifyIconW`.
#[cfg(target_os = "windows")]
pub(crate) const TRAY_ICON_ID: u32 = 1;

/// Command ID for the disabled Status summary menu header (1/9).
pub(crate) const IDM_STATUS_HEADER: u16 = 1001;
/// Command ID for `Open Dashboard` (2/9).
pub(crate) const IDM_OPEN_DASHBOARD: u16 = 1002;
/// Command ID for `Connect` (3/9).
pub(crate) const IDM_CONNECT_UP: u16 = 1003;
/// Command ID for `Disconnect` (4/9).
pub(crate) const IDM_DISCONNECT: u16 = 1004;
/// Command ID for `Run Netcheck` (5/9).
pub(crate) const IDM_NETCHECK: u16 = 1005;
/// Command ID for `Export Bugreport...` (6/9).
pub(crate) const IDM_EXPORT_BUGREPORT: u16 = 1006;
/// Command ID for `Launch at Login` (7/9).
pub(crate) const IDM_TOGGLE_AUTOSTART: u16 = 1007;
/// Command ID for `Quit Mesh VPN (Keep Connected in Background)` (8/9).
pub(crate) const IDM_QUIT_KEEP_BACKGROUND: u16 = 1008;
/// Command ID for `Disconnect & Quit Mesh VPN` (9/9).
pub(crate) const IDM_DISCONNECT_AND_QUIT: u16 = 1009;

/// OS-neutral representation of a single entry in the 9-item System Tray context menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TrayMenuItemModel {
    Header(String),
    Separator,
    Action {
        id: u16,
        label: String,
        enabled: bool,
        checked: bool,
        default: bool,
    },
}

fn tr_for_or(key: &str, locale: LocaleMode, fallback: &str) -> String {
    let localized = t_for(key, locale);
    if localized.is_empty() {
        fallback.to_owned()
    } else {
        localized.to_owned()
    }
}

/// Returns the localized tray tooltip summary for `(ui_state, sub_state)` under `locale` (`US-127`).
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn tray_tooltip_for_locale(
    ui_state: DesktopUiState,
    sub_state: TunnelSubState,
    locale: LocaleMode,
) -> &'static str {
    let localized = t_for(ui_state.tray_tooltip_key(sub_state), locale);
    if localized.is_empty() {
        ui_state.tray_tooltip_summary(sub_state)
    } else {
        localized
    }
}

/// Escapes single `&` into `&&` for native Win32 `AppendMenuW` display labels so literal `&`
/// renders instead of an accelerator underline.
#[cfg(target_os = "windows")]
fn escape_win32_menu_ampersands(label: &str) -> String {
    if label.contains("&&") || !label.contains('&') {
        label.to_owned()
    } else {
        label.replace('&', "&&")
    }
}

/// Builds the canonical 9-item System Tray context menu for the active `DerivedUiSnapshot`
/// using the currently active [`LocaleMode`] (`ADR-029`, `ADR-030`, `US-127`, `UUI-35`).
#[must_use]
pub(crate) fn build_tray_menu_model(
    snapshot: &DerivedUiSnapshot,
    overlay_ip: Option<&str>,
    autostart_enabled: bool,
) -> Vec<TrayMenuItemModel> {
    build_tray_menu_model_for_locale(snapshot, overlay_ip, autostart_enabled, current_locale())
}

/// Pure builder for the canonical 9-item System Tray context menu under an explicit [`LocaleMode`]
/// (race-free for parallel unit tests, `US-127`, `UUI-35`).
#[must_use]
pub(crate) fn build_tray_menu_model_for_locale(
    snapshot: &DerivedUiSnapshot,
    overlay_ip: Option<&str>,
    autostart_enabled: bool,
    locale: LocaleMode,
) -> Vec<TrayMenuItemModel> {
    let status_prefix = tr_for_or("tab.status", locale, "Status");
    let state_display = tr_for_or(
        snapshot
            .ui_state
            .display_label_key(snapshot.tunnel_sub_state),
        locale,
        snapshot.ui_state.display_label(snapshot.tunnel_sub_state),
    );
    let status_text = match overlay_ip.filter(|s| !s.is_empty()) {
        Some(ip) => format!("{status_prefix}: {state_display} ({ip})"),
        None => format!("{status_prefix}: {state_display}"),
    };

    let ipc_ready = !matches!(
        snapshot.ui_state,
        DesktopUiState::AgentUnavailable | DesktopUiState::ServiceStopped
    );
    let connect_enabled = matches!(
        (snapshot.ui_state, snapshot.tunnel_sub_state),
        (DesktopUiState::Connected, TunnelSubState::Disconnected)
            | (DesktopUiState::ErrorRecoverable, _)
    );
    let disconnect_enabled = matches!(
        (snapshot.ui_state, snapshot.tunnel_sub_state),
        (
            DesktopUiState::Connected,
            TunnelSubState::Connected | TunnelSubState::Degraded
        ) | (DesktopUiState::Connecting, _)
    );

    vec![
        TrayMenuItemModel::Header(status_text),
        TrayMenuItemModel::Separator,
        TrayMenuItemModel::Action {
            id: IDM_OPEN_DASHBOARD,
            label: tr_for_or("action.open_dashboard", locale, "Open Dashboard"),
            enabled: true,
            checked: false,
            default: true,
        },
        TrayMenuItemModel::Action {
            id: IDM_CONNECT_UP,
            label: tr_for_or("action.connect", locale, "Connect"),
            enabled: connect_enabled,
            checked: false,
            default: false,
        },
        TrayMenuItemModel::Action {
            id: IDM_DISCONNECT,
            label: tr_for_or("action.disconnect", locale, "Disconnect"),
            enabled: disconnect_enabled,
            checked: false,
            default: false,
        },
        TrayMenuItemModel::Separator,
        TrayMenuItemModel::Action {
            id: IDM_NETCHECK,
            label: tr_for_or("action.run_netcheck", locale, "Run Netcheck Diagnostics"),
            enabled: ipc_ready,
            checked: false,
            default: false,
        },
        TrayMenuItemModel::Action {
            id: IDM_EXPORT_BUGREPORT,
            label: tr_for_or(
                "action.export_bugreport",
                locale,
                "Export Redacted Bugreport",
            ),
            enabled: ipc_ready,
            checked: false,
            default: false,
        },
        TrayMenuItemModel::Action {
            id: IDM_TOGGLE_AUTOSTART,
            label: tr_for_or("action.launch_at_login", locale, "Launch at Login"),
            enabled: true,
            checked: autostart_enabled,
            default: false,
        },
        TrayMenuItemModel::Separator,
        TrayMenuItemModel::Action {
            id: IDM_QUIT_KEEP_BACKGROUND,
            label: tr_for_or(
                "action.quit_keep",
                locale,
                "Quit Mesh VPN (Keep Connected in Background)",
            ),
            enabled: true,
            checked: false,
            default: false,
        },
        TrayMenuItemModel::Action {
            id: IDM_DISCONNECT_AND_QUIT,
            label: tr_for_or(
                "action.disconnect_quit",
                locale,
                "Disconnect & Quit Mesh VPN",
            ),
            enabled: true,
            checked: false,
            default: false,
        },
    ]
}

/// Counts non-separator entries (the 9 menu entries: 1 header + 8 clickable items).
#[cfg(test)]
#[must_use]
pub(crate) fn count_non_separator_entries(items: &[TrayMenuItemModel]) -> usize {
    items
        .iter()
        .filter(|entry| !matches!(entry, TrayMenuItemModel::Separator))
        .count()
}

/// Manages Win32 `TrayIconController` lifecycle, DPI-scaled icons, `TaskbarCreated` restoration,
/// and the once-per-session minimize balloon hint.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) struct TrayStateManager {
    controller: TrayIconController,
    current_icon: Option<OwnedIcon>,
    last_tone: Option<UiIconTone>,
    last_icon_px: i32,
    minimize_balloon_shown: bool,
}

#[cfg(target_os = "windows")]
impl TrayStateManager {
    /// Initializes an unadded `TrayStateManager` bound to `hwnd`.
    #[must_use]
    pub(crate) fn new(hwnd: isize) -> Self {
        Self {
            controller: TrayIconController::new(hwnd, TRAY_ICON_ID),
            current_icon: None,
            last_tone: None,
            last_icon_px: 0,
            minimize_balloon_shown: false,
        }
    }

    /// Registers or re-adds the tray icon on `WM_CREATE` or `TaskbarCreated`.
    pub(crate) fn ensure_added_or_restore(
        &mut self,
        hwnd: isize,
        snapshot: &DerivedUiSnapshot,
    ) -> SysResult<()> {
        let icon_px = get_sm_icon_px_for_dpi(get_dpi_for_window(hwnd));
        let tone = icon_tone_for_state(snapshot.ui_state, snapshot.tunnel_sub_state);
        if self.current_icon.is_none()
            || self.last_tone != Some(tone)
            || self.last_icon_px != icon_px
        {
            self.current_icon = Some(create_status_icon_for_px(tone, icon_px)?);
            self.last_tone = Some(tone);
            self.last_icon_px = icon_px;
        }
        let Some(icon) = &self.current_icon else {
            return Ok(());
        };
        let tooltip = tray_tooltip_for_locale(
            snapshot.ui_state,
            snapshot.tunnel_sub_state,
            current_locale(),
        );
        self.controller.add_or_restore(icon, tooltip)
    }

    /// Updates tray icon image and tooltip cleanly when state or monitor DPI changes.
    pub(crate) fn sync_state(&mut self, hwnd: isize, snapshot: &DerivedUiSnapshot) {
        let icon_px = get_sm_icon_px_for_dpi(get_dpi_for_window(hwnd));
        let tone = icon_tone_for_state(snapshot.ui_state, snapshot.tunnel_sub_state);
        if (self.current_icon.is_none()
            || self.last_tone != Some(tone)
            || self.last_icon_px != icon_px)
            && let Ok(new_icon) = create_status_icon_for_px(tone, icon_px)
        {
            self.current_icon = Some(new_icon);
            self.last_tone = Some(tone);
            self.last_icon_px = icon_px;
        }
        if let Some(icon) = &self.current_icon {
            let tooltip = tray_tooltip_for_locale(
                snapshot.ui_state,
                snapshot.tunnel_sub_state,
                current_locale(),
            );
            let _updated = self.controller.update(icon, tooltip);
        }
    }

    /// Shows the "Minimized to System Tray" balloon notification at most once per session.
    pub(crate) fn show_minimize_balloon_once(&mut self) {
        if self.minimize_balloon_shown {
            return;
        }
        let Some(icon) = &self.current_icon else {
            return;
        };
        let title = {
            let v = t("diag.bugreport_title");
            if v.is_empty() {
                "Mesh VPN Minimized"
            } else {
                v
            }
        };
        let body = {
            let v = t("diag.bugreport_body");
            if v.is_empty() {
                "Mesh VPN continues running in the System Tray."
            } else {
                v
            }
        };
        if self.controller.show_info_balloon(icon, title, body).is_ok() {
            self.minimize_balloon_shown = true;
        }
    }

    /// Shows an informational toast balloon (e.g. Copy Overlay IP / FQDN confirmation, `US-121`).
    pub(crate) fn show_toast_balloon(&self, title: &str, body: &str) {
        if let Some(icon) = &self.current_icon {
            let _shown = self.controller.show_info_balloon(icon, title, body);
        }
    }

    /// Displays the native Win32 tray context menu at the cursor position and returns chosen ID.
    pub(crate) fn show_menu(
        &self,
        hwnd: isize,
        snapshot: &DerivedUiSnapshot,
        overlay_ip: Option<&str>,
        autostart_enabled: bool,
    ) -> SysResult<Option<u16>> {
        let _header_id = IDM_STATUS_HEADER;
        let model = build_tray_menu_model(snapshot, overlay_ip, autostart_enabled);
        let entries: Vec<TrayMenuEntry> = model
            .into_iter()
            .map(|item| match item {
                TrayMenuItemModel::Header(text) => TrayMenuEntry::Header(text),
                TrayMenuItemModel::Separator => TrayMenuEntry::Separator,
                TrayMenuItemModel::Action {
                    id,
                    label,
                    enabled,
                    checked,
                    default,
                } => TrayMenuEntry::Action {
                    id,
                    label: escape_win32_menu_ampersands(&label),
                    enabled,
                    checked,
                    default,
                },
            })
            .collect();
        show_tray_context_menu(hwnd, &entries)
    }

    /// Removes the tray icon from the Windows notification area prior to process exit.
    pub(crate) fn remove(&mut self) {
        self.controller.remove();
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::{TRAY_ICON_ID, TrayStateManager};

    #[test]
    fn test_tray_state_manager_constructor_and_surface_bindings() {
        // Arrange & Act
        let mgr = TrayStateManager::new(0);
        let _methods = (
            TrayStateManager::ensure_added_or_restore,
            TrayStateManager::sync_state,
            TrayStateManager::show_minimize_balloon_once,
            TrayStateManager::show_toast_balloon,
            TrayStateManager::show_menu,
            TrayStateManager::remove,
        );

        // Assert
        assert_eq!(TRAY_ICON_ID, 1);
        assert!(format!("{mgr:?}").contains("TrayStateManager"));
    }
}
