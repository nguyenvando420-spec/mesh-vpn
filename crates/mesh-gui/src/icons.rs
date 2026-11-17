//! DPI-aware procedural icon badge generator for System Tray and top-level window icons
//! (`US-103`, `ADR-020`).

#[cfg(target_os = "windows")]
use mesh_sys::error::SysResult;
#[cfg(target_os = "windows")]
use mesh_sys::gui_windows::{OwnedIcon, TrayStatusIconKind, create_tray_status_icon_from_bgra};

use crate::app::{DesktopUiState, TunnelSubState};

/// Minimum procedural icon square dimension in pixels.
pub(crate) const ICON_MIN_PX: i32 = 16;

/// Maximum procedural icon square dimension in pixels.
pub(crate) const ICON_MAX_PX: i32 = 256;

/// OS-neutral color tone representing the 8 GUI states in tray/titlebar indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum UiIconTone {
    /// Connected to Control and data plane (`#16A34A` emerald green).
    Green,
    /// Connecting, Degraded, or ReauthRequired attention state (`#D97706` amber).
    Amber,
    /// Revoked, ServiceStopped, or ErrorRecoverable fault state (`#DC2626` crimson).
    Red,
    /// AgentUnavailable or NotEnrolled neutral/offline state (`#6B7280` slate gray).
    Gray,
}

impl UiIconTone {
    /// Returns the `[R, G, B]` accent fill color for this tone.
    #[must_use]
    pub(crate) const fn rgb(self) -> [u8; 3] {
        match self {
            Self::Green => [22, 163, 74],
            Self::Amber => [217, 119, 6],
            Self::Red => [220, 38, 38],
            Self::Gray => [107, 114, 128],
        }
    }

    #[cfg(target_os = "windows")]
    #[must_use]
    pub(crate) const fn into_tray_kind(self) -> TrayStatusIconKind {
        match self {
            Self::Green => TrayStatusIconKind::Connected,
            Self::Amber => TrayStatusIconKind::ConnectingOrDegraded,
            Self::Red => TrayStatusIconKind::WarningOrError,
            Self::Gray => TrayStatusIconKind::Stopped,
        }
    }
}

/// Maps the active `DesktopUiState` and `TunnelSubState` to a deterministic badge color tone.
#[must_use]
pub(crate) const fn icon_tone_for_state(
    ui_state: DesktopUiState,
    sub_state: TunnelSubState,
) -> UiIconTone {
    match ui_state {
        DesktopUiState::AgentUnavailable
        | DesktopUiState::ServiceStopped
        | DesktopUiState::NotEnrolled => UiIconTone::Gray,
        DesktopUiState::Connecting | DesktopUiState::ReauthRequired => UiIconTone::Amber,
        DesktopUiState::Revoked | DesktopUiState::ErrorRecoverable => UiIconTone::Red,
        DesktopUiState::Connected => match sub_state {
            TunnelSubState::Connected => UiIconTone::Green,
            TunnelSubState::Connecting
            | TunnelSubState::Degraded
            | TunnelSubState::ReauthRequired => UiIconTone::Amber,
            TunnelSubState::Disconnected | TunnelSubState::NotEnrolled => UiIconTone::Gray,
            TunnelSubState::Revoked => UiIconTone::Red,
        },
    }
}

/// Generates a premultiplied-alpha BGRA32 square icon buffer clamped to `16..=256` pixels.
///
/// Renders a crisp outer ring, solid color-coded status badge, and inner white emblem so status
/// transitions stay legible at both `96 DPI` (16 px) and high-DPI (32..256 px).
#[must_use]
pub(crate) fn render_status_badge_bgra(tone: UiIconTone, size_px: i32) -> Vec<u8> {
    let clamped = size_px.clamp(ICON_MIN_PX, ICON_MAX_PX);
    let side = usize::try_from(clamped).unwrap_or(16);
    let mut buf = vec![0_u8; side * side * 4];
    let [r, g, b] = tone.rgb();

    let side_f = f64::from(clamped);
    let center = (side_f - 1.0) * 0.5;
    let outer_r = side_f * 0.44;
    let ring_r = side_f * 0.36;
    let emblem_r = side_f * 0.16;

    for y in 0..side {
        for x in 0..side {
            let xf = u32::try_from(x).map_or(0.0, f64::from);
            let yf = u32::try_from(y).map_or(0.0, f64::from);
            let dx = xf - center;
            let dy = yf - center;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = (y * side + x) * 4;

            let (pr, pg, pb, pa) = if dist <= emblem_r {
                (255_u8, 255_u8, 255_u8, 255_u8)
            } else if dist <= ring_r {
                (r, g, b, 255_u8)
            } else if dist <= outer_r {
                (24_u8, 32_u8, 46_u8, 255_u8)
            } else if dist <= outer_r + 1.0 {
                let cov = ((outer_r + 1.0 - dist).clamp(0.0, 1.0) * 255.0) as u8;
                (24_u8, 32_u8, 46_u8, cov)
            } else {
                (0, 0, 0, 0)
            };

            if let Some(dst) = buf.get_mut(idx..idx + 4) {
                dst.copy_from_slice(&[pb, pg, pr, pa]);
            }
        }
    }

    buf
}

/// Creates a Win32 `OwnedIcon` scaled to `size_px` (`16..=256`) for Tray or `WM_SETICON`.
#[cfg(target_os = "windows")]
pub(crate) fn create_status_icon_for_px(tone: UiIconTone, size_px: i32) -> SysResult<OwnedIcon> {
    let clamped = size_px.clamp(ICON_MIN_PX, ICON_MAX_PX);
    let bgra = render_status_badge_bgra(tone, clamped);
    let _kind = tone.into_tray_kind();
    create_tray_status_icon_from_bgra(clamped, clamped, &bgra)
}
