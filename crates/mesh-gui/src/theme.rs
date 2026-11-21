//! Windows GDI/DWM Light, Dark, and High-Contrast theme tokens and cached GDI handles
//! (`ADR-027`, `ADR-030`, `US-122`, `US-123`).
//!
//! `UiThemePalette` lives in `crates/mesh-gui/src/theme.rs` with zero `unsafe` code, wrapping
//! [`OwnedGdiObj`] handles constructed safely through `mesh_sys::gui_windows`.

#[cfg(target_os = "windows")]
use std::collections::BTreeMap;

#[cfg(target_os = "windows")]
use mesh_sys::gui_windows::{
    OwnedGdiObj, create_font_for_dpi, create_solid_brush, create_solid_pen, detect_high_contrast,
    read_windows_apps_use_light_theme,
};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use crate::app::{DesktopUiState, TunnelSubState};

/// User-selectable color theme mode (`ADR-030`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ThemeMode {
    /// Follow OS `AppsUseLightTheme` and High Contrast settings.
    #[default]
    System,
    /// Force Light Slate + Cobalt palette.
    Light,
    /// Force Dark Slate + Sky palette.
    Dark,
}

/// Canonical Light Slate + Cobalt `COLORREF` tokens (`0x00BBGGRR`, `ADR-030` §3.1).
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_SURFACE_BG: u32 = 0x00FC_FAF8; // #F8FAFC
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_SURFACE_CARD: u32 = 0x00FF_FFFF; // #FFFFFF
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_SURFACE_BORDER: u32 = 0x00E1_D5CB; // #CBD5E1
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_TEXT_PRIMARY: u32 = 0x002A_170F; // #0F172A
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_TEXT_SECONDARY: u32 = 0x0069_5547; // #475569
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_BRAND_COBALT: u32 = 0x00D0_570B; // #0B57D0
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_BRAND_TEAL: u32 = 0x0088_940D; // #0D9488
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_SEMANTIC_SUCCESS: u32 = 0x004A_A316; // #16A34A
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_SEMANTIC_WARNING: u32 = 0x0006_77D9; // #D97706
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_SEMANTIC_ERROR: u32 = 0x0026_26DC; // #DC2626
#[cfg(target_os = "windows")]
pub(crate) const LIGHT_SEMANTIC_NEUTRAL: u32 = 0x0080_726B; // #6B7280

/// Canonical Dark Slate + Sky `COLORREF` tokens (`0x00BBGGRR`, `ADR-030` §3.1).
#[cfg(target_os = "windows")]
pub(crate) const DARK_SURFACE_BG: u32 = 0x002A_170F; // #0F172A
#[cfg(target_os = "windows")]
pub(crate) const DARK_SURFACE_CARD: u32 = 0x003B_291E; // #1E293B
#[cfg(target_os = "windows")]
pub(crate) const DARK_SURFACE_BORDER: u32 = 0x0055_4133; // #334155
#[cfg(target_os = "windows")]
pub(crate) const DARK_TEXT_PRIMARY: u32 = 0x00F9_F5F1; // #F1F5F9
#[cfg(target_os = "windows")]
pub(crate) const DARK_TEXT_SECONDARY: u32 = 0x00B8_A394; // #94A3B8
#[cfg(target_os = "windows")]
pub(crate) const DARK_BRAND_SKY: u32 = 0x00FA_A560; // #60A5FA
#[cfg(target_os = "windows")]
pub(crate) const DARK_BRAND_TEAL_LIGHT: u32 = 0x00BF_D42D; // #2DD4BF
#[cfg(target_os = "windows")]
pub(crate) const DARK_SEMANTIC_SUCCESS: u32 = 0x0080_DE4A; // #4ADE80
#[cfg(target_os = "windows")]
pub(crate) const DARK_SEMANTIC_WARNING: u32 = 0x0024_BFFB; // #FBBF24
#[cfg(target_os = "windows")]
pub(crate) const DARK_SEMANTIC_ERROR: u32 = 0x0071_71F8; // #F87171
#[cfg(target_os = "windows")]
pub(crate) const DARK_SEMANTIC_NEUTRAL: u32 = 0x00AF_A39C; // #9CA3AF

#[cfg(target_os = "windows")]
const FW_NORMAL: i32 = 400;
#[cfg(target_os = "windows")]
const FW_SEMIBOLD: i32 = 600;

/// Pre-resolved Win32 GDI theme colors and cached RAII GDI handles (`contracts §1.2`).
///
/// Rebuilt on `WM_SETTINGCHANGE`, `WM_THEMECHANGED`, `WM_DPICHANGED`, or explicit theme selection;
/// dropping releases all cached `HBRUSH`/`HPEN`/`HFONT` handles via [`OwnedGdiObj`].
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) struct UiThemePalette {
    /// Active theme mode requested by user.
    pub(crate) mode: ThemeMode,
    /// DPI used to construct cached GDI fonts.
    pub(crate) dpi: u32,
    /// Whether the DWM titlebar should use immersive dark mode.
    pub(crate) is_dark_titlebar: bool,
    /// Whether Windows High Contrast mode was active when resolved.
    pub(crate) is_high_contrast: bool,

    // Surface tokens (`COLORREF` BGR)
    pub(crate) bg_color: u32,
    pub(crate) card_color: u32,
    pub(crate) border_color: u32,
    pub(crate) text_primary: u32,
    pub(crate) text_secondary: u32,

    // Brand tokens (`COLORREF` BGR)
    pub(crate) brand_primary: u32,
    pub(crate) brand_teal: u32,

    // Semantic tokens (`COLORREF` BGR)
    pub(crate) semantic_success: u32,
    pub(crate) semantic_warning: u32,
    pub(crate) semantic_error: u32,
    pub(crate) semantic_neutral: u32,

    // Cached surface & brand GDI objects (`OwnedGdiObj`)
    pub(crate) bg_brush: Option<OwnedGdiObj>,
    pub(crate) card_brush: Option<OwnedGdiObj>,
    pub(crate) border_pen: Option<OwnedGdiObj>,
    pub(crate) brand_brush: Option<OwnedGdiObj>,
    pub(crate) brand_border_pen: Option<OwnedGdiObj>,

    // Cached semantic brushes for status pills and badges
    pub(crate) success_brush: Option<OwnedGdiObj>,
    pub(crate) warning_brush: Option<OwnedGdiObj>,
    pub(crate) error_brush: Option<OwnedGdiObj>,
    pub(crate) neutral_brush: Option<OwnedGdiObj>,

    // Cached DPI-aware font handles (`Segoe UI` & `Consolas`)
    pub(crate) font_headline: Option<OwnedGdiObj>,
    pub(crate) font_body: Option<OwnedGdiObj>,
    pub(crate) font_caption: Option<OwnedGdiObj>,
    pub(crate) font_mono: Option<OwnedGdiObj>,

    // Per-COLORREF dynamic brush cache cleared on theme switch (`coding-standards §1.1`)
    brush_cache: BTreeMap<u32, OwnedGdiObj>,
}

#[cfg(target_os = "windows")]
impl UiThemePalette {
    /// Returns raw `HBRUSH` encoded as `isize` for `WM_CTLCOLORSTATIC` (`0` if unavailable).
    #[must_use]
    pub(crate) fn bg_brush_raw(&self) -> isize {
        self.bg_brush.as_ref().map_or(0, OwnedGdiObj::as_raw_isize)
    }

    /// Returns raw `HBRUSH` encoded as `isize` for `WM_CTLCOLOREDIT`/`LISTBOX` (`0` if unavailable).
    #[must_use]
    pub(crate) fn card_brush_raw(&self) -> isize {
        self.card_brush
            .as_ref()
            .map_or(0, OwnedGdiObj::as_raw_isize)
    }

    /// Returns the semantic `COLORREF` for `(ui_state, sub_state)` per `ADR-030` §5.
    #[must_use]
    pub(crate) const fn semantic_color_for_state(
        &self,
        ui_state: DesktopUiState,
        sub_state: TunnelSubState,
    ) -> u32 {
        match ui_state {
            DesktopUiState::AgentUnavailable
            | DesktopUiState::ServiceStopped
            | DesktopUiState::NotEnrolled => self.semantic_neutral,
            DesktopUiState::Connecting | DesktopUiState::ReauthRequired => self.semantic_warning,
            DesktopUiState::Revoked | DesktopUiState::ErrorRecoverable => self.semantic_error,
            DesktopUiState::Connected => match sub_state {
                TunnelSubState::Connected => self.semantic_success,
                TunnelSubState::Connecting
                | TunnelSubState::Degraded
                | TunnelSubState::ReauthRequired => self.semantic_warning,
                TunnelSubState::Disconnected | TunnelSubState::NotEnrolled => self.semantic_neutral,
                TunnelSubState::Revoked => self.semantic_error,
            },
        }
    }

    /// Returns the cached semantic pill brush for `(ui_state, sub_state)` per `ADR-030` §5.
    #[must_use]
    pub(crate) fn semantic_brush_for_state(
        &self,
        ui_state: DesktopUiState,
        sub_state: TunnelSubState,
    ) -> Option<&OwnedGdiObj> {
        match ui_state {
            DesktopUiState::AgentUnavailable
            | DesktopUiState::ServiceStopped
            | DesktopUiState::NotEnrolled => self.neutral_brush.as_ref(),
            DesktopUiState::Connecting | DesktopUiState::ReauthRequired => {
                self.warning_brush.as_ref()
            }
            DesktopUiState::Revoked | DesktopUiState::ErrorRecoverable => self.error_brush.as_ref(),
            DesktopUiState::Connected => match sub_state {
                TunnelSubState::Connected => self.success_brush.as_ref(),
                TunnelSubState::Connecting
                | TunnelSubState::Degraded
                | TunnelSubState::ReauthRequired => self.warning_brush.as_ref(),
                TunnelSubState::Disconnected | TunnelSubState::NotEnrolled => {
                    self.neutral_brush.as_ref()
                }
                TunnelSubState::Revoked => self.error_brush.as_ref(),
            },
        }
    }

    /// Returns high-contrast foreground text `COLORREF` for filled brand/semantic pills & CTAs.
    #[must_use]
    pub(crate) const fn on_accent_text_color(&self) -> u32 {
        if self.is_dark_titlebar {
            DARK_SURFACE_BG
        } else {
            LIGHT_SURFACE_CARD
        }
    }

    /// Looks up or lazily caches a solid brush for `color`.
    #[cfg(test)]
    pub(crate) fn get_or_create_brush(&mut self, color: u32) -> Option<&OwnedGdiObj> {
        if !self.brush_cache.contains_key(&color)
            && let Some(brush) = create_solid_brush(color)
        {
            self.brush_cache.insert(color, brush);
        }
        self.brush_cache.get(&color)
    }

    /// Clears the dynamic brush cache cleanly (invoked on `WM_SETTINGCHANGE`/`WM_THEMECHANGED`).
    pub(crate) fn clear_brush_cache(&mut self) {
        self.brush_cache.clear();
    }
}

/// Resolves canonical Light/Dark COLORREF design tokens and cached GDI handles for `mode` at 96 DPI.
///
/// Preserved 1-argument signature referenced by `main.rs` (`WP-U-A0` contract).
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn resolve_palette(mode: ThemeMode) -> UiThemePalette {
    resolve_palette_for_dpi(mode, 96)
}

/// Resolves canonical Light/Dark tokens and DPI-scaled GDI brushes/pens/fonts (`ADR-027`, `ADR-030`).
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn resolve_palette_for_dpi(mode: ThemeMode, dpi: u32) -> UiThemePalette {
    let safe_dpi = dpi.max(72);
    let dpi_i32 = i32::try_from(safe_dpi).unwrap_or(96);
    let high_contrast = detect_high_contrast();
    let is_dark = match mode {
        ThemeMode::System => !read_windows_apps_use_light_theme() || high_contrast,
        ThemeMode::Light => false,
        ThemeMode::Dark => true,
    };

    let (
        bg_color,
        card_color,
        border_color,
        text_primary,
        text_secondary,
        brand_primary,
        brand_teal,
        semantic_success,
        semantic_warning,
        semantic_error,
        semantic_neutral,
    ) = if is_dark {
        (
            DARK_SURFACE_BG,
            DARK_SURFACE_CARD,
            DARK_SURFACE_BORDER,
            DARK_TEXT_PRIMARY,
            DARK_TEXT_SECONDARY,
            DARK_BRAND_SKY,
            DARK_BRAND_TEAL_LIGHT,
            DARK_SEMANTIC_SUCCESS,
            DARK_SEMANTIC_WARNING,
            DARK_SEMANTIC_ERROR,
            DARK_SEMANTIC_NEUTRAL,
        )
    } else {
        (
            LIGHT_SURFACE_BG,
            LIGHT_SURFACE_CARD,
            LIGHT_SURFACE_BORDER,
            LIGHT_TEXT_PRIMARY,
            LIGHT_TEXT_SECONDARY,
            LIGHT_BRAND_COBALT,
            LIGHT_BRAND_TEAL,
            LIGHT_SEMANTIC_SUCCESS,
            LIGHT_SEMANTIC_WARNING,
            LIGHT_SEMANTIC_ERROR,
            LIGHT_SEMANTIC_NEUTRAL,
        )
    };

    UiThemePalette {
        mode,
        dpi: safe_dpi,
        is_dark_titlebar: is_dark,
        is_high_contrast: high_contrast,
        bg_color,
        card_color,
        border_color,
        text_primary,
        text_secondary,
        brand_primary,
        brand_teal,
        semantic_success,
        semantic_warning,
        semantic_error,
        semantic_neutral,
        bg_brush: create_solid_brush(bg_color),
        card_brush: create_solid_brush(card_color),
        border_pen: create_solid_pen(1, border_color),
        brand_brush: create_solid_brush(brand_primary),
        brand_border_pen: create_solid_pen(1, brand_primary),
        success_brush: create_solid_brush(semantic_success),
        warning_brush: create_solid_brush(semantic_warning),
        error_brush: create_solid_brush(semantic_error),
        neutral_brush: create_solid_brush(semantic_neutral),
        font_headline: create_font_for_dpi("Segoe UI", 14, FW_SEMIBOLD, dpi_i32),
        font_body: create_font_for_dpi("Segoe UI", 10, FW_NORMAL, dpi_i32),
        font_caption: create_font_for_dpi("Segoe UI", 9, FW_NORMAL, dpi_i32),
        font_mono: create_font_for_dpi("Consolas", 10, FW_NORMAL, dpi_i32),
        brush_cache: BTreeMap::new(),
    }
}

#[cfg(all(test, target_os = "windows"))]
pub(crate) static GDI_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::ThemeMode;

    #[test]
    fn test_theme_mode_serde_roundtrip_canonical_lowercase() {
        // Arrange
        let modes = [ThemeMode::System, ThemeMode::Light, ThemeMode::Dark];
        let expected = ["\"system\"", "\"light\"", "\"dark\""];

        // Act & Assert
        for (mode, json_expected) in modes.iter().zip(expected.iter()) {
            let encoded = serde_json::to_string(mode);
            assert_eq!(encoded.as_deref().ok(), Some(*json_expected));
            if let Ok(raw) = encoded {
                let decoded: Result<ThemeMode, _> = serde_json::from_str(&raw);
                assert_eq!(decoded.ok(), Some(*mode));
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_resolve_palette_explicit_light_and_dark_tokens() {
        let _lock = super::GDI_TEST_LOCK.lock();
        // Arrange & Act
        let mut light = super::resolve_palette(ThemeMode::Light);
        let dark = super::resolve_palette_for_dpi(ThemeMode::Dark, 144);
        let _sys = super::resolve_palette(ThemeMode::System);

        // Assert
        assert_eq!(light.mode, ThemeMode::Light);
        assert!(!light.is_dark_titlebar);
        assert_eq!(light.bg_color, 0x00FC_FAF8);
        assert_eq!(light.card_color, 0x00FF_FFFF);
        assert_eq!(light.border_color, 0x00E1_D5CB);
        assert_eq!(light.brand_primary, 0x00D0_570B);
        assert_eq!(light.brand_teal, 0x0088_940D);
        assert_eq!(light.semantic_warning, 0x0006_77D9);
        assert!(light.bg_brush.is_some());
        assert_ne!(light.bg_brush_raw(), 0);
        assert!(light.card_brush.is_some());
        assert_ne!(light.card_brush_raw(), 0);
        assert!(light.border_pen.is_some());
        assert!(light.brand_brush.is_some());
        assert!(light.brand_border_pen.is_some());
        assert!(light.font_headline.is_some());
        assert!(light.font_body.is_some());
        assert!(light.font_caption.is_some());
        assert!(light.font_mono.is_some());
        assert!(light.get_or_create_brush(0x0011_2233).is_some());
        let _hc = light.is_high_contrast;
        light.clear_brush_cache();

        assert!(dark.is_dark_titlebar);
        assert_eq!(dark.dpi, 144);
        assert_eq!(dark.bg_color, 0x002A_170F);
        assert_eq!(dark.brand_primary, 0x00FA_A560);
        assert_eq!(dark.semantic_warning, 0x0024_BFFB);
        assert!(dark.success_brush.is_some());
        assert!(dark.warning_brush.is_some());
        assert!(dark.error_brush.is_some());
        assert!(dark.neutral_brush.is_some());
    }
}
