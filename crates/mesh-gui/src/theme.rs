//! Windows GDI/DWM Light, Dark, and High-Contrast theme tokens (`ADR-027`, `ADR-030`, `WP-U-A0`).
//!
//! Full cached brush/pen/font construction (`UiThemePalette`) is completed in `WP-U-B1`.

#[cfg(target_os = "windows")]
use mesh_sys::gui_windows::{OwnedGdiObj, detect_high_contrast, read_windows_apps_use_light_theme};
use serde::{Deserialize, Serialize};

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

/// Pre-resolved Win32 GDI theme colors and owned handles (`WP-U-A0` skeleton; expanded in `WP-U-B1`).
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) struct UiThemePalette {
    /// Whether the DWM titlebar should use immersive dark mode.
    pub(crate) is_dark_titlebar: bool,
    /// `surface.background` (`COLORREF` BGR).
    pub(crate) bg_color: u32,
    /// `surface.card` (`COLORREF` BGR).
    pub(crate) card_color: u32,
    /// `surface.border` (`COLORREF` BGR).
    pub(crate) border_color: u32,
    /// `surface.text.primary` (`COLORREF` BGR).
    pub(crate) text_primary: u32,
    /// `surface.text.secondary` (`COLORREF` BGR).
    pub(crate) text_secondary: u32,
    /// `brand.cobalt` (light) or `brand.sky` (dark) (`COLORREF` BGR).
    pub(crate) brand_primary: u32,
    /// `brand.teal` (light) or `brand.teal.light` (dark) (`COLORREF` BGR).
    pub(crate) brand_teal: u32,
    /// `semantic.success` (`COLORREF` BGR).
    pub(crate) semantic_success: u32,
    /// `semantic.warning` (`COLORREF` BGR).
    pub(crate) semantic_warning: u32,
    /// `semantic.error` (`COLORREF` BGR).
    pub(crate) semantic_error: u32,
    /// `semantic.neutral` (`COLORREF` BGR).
    pub(crate) semantic_neutral: u32,
    /// Optional RAII font handle constructed safely via `mesh_sys::gui_windows`.
    pub(crate) font_body: Option<OwnedGdiObj>,
}

/// Resolves canonical Light/Dark COLORREF design tokens for `mode` (`ADR-030`).
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn resolve_palette(mode: ThemeMode) -> UiThemePalette {
    let is_dark = match mode {
        ThemeMode::System => !read_windows_apps_use_light_theme() || detect_high_contrast(),
        ThemeMode::Light => false,
        ThemeMode::Dark => true,
    };

    if is_dark {
        UiThemePalette {
            is_dark_titlebar: true,
            bg_color: 0x002A_170F,
            card_color: 0x003B_291E,
            border_color: 0x0055_4133,
            text_primary: 0x00F9_F5F1,
            text_secondary: 0x00B8_A394,
            brand_primary: 0x00FA_A560,
            brand_teal: 0x00BF_D42D,
            semantic_success: 0x0080_DE4A,
            semantic_warning: 0x0024_BFFB,
            semantic_error: 0x0071_71F8,
            semantic_neutral: 0x00AF_A39C,
            font_body: None,
        }
    } else {
        UiThemePalette {
            is_dark_titlebar: false,
            bg_color: 0x00FC_FAF8,
            card_color: 0x00FF_FFFF,
            border_color: 0x00E1_D5CB,
            text_primary: 0x002A_170F,
            text_secondary: 0x0069_5547,
            brand_primary: 0x00D0_570B,
            brand_teal: 0x0088_940D,
            semantic_success: 0x004A_A316,
            semantic_warning: 0x0006_77D9,
            semantic_error: 0x0026_26DC,
            semantic_neutral: 0x0080_726B,
            font_body: None,
        }
    }
}

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
            let encoded = serde_json::to_string(mode).expect("serialize ThemeMode");
            assert_eq!(&encoded, json_expected);
            let decoded: ThemeMode = serde_json::from_str(&encoded).expect("deserialize ThemeMode");
            assert_eq!(decoded, *mode);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_resolve_palette_explicit_light_and_dark_tokens() {
        // Arrange & Act
        let light = super::resolve_palette(ThemeMode::Light);
        let dark = super::resolve_palette(ThemeMode::Dark);
        let _sys = super::resolve_palette(ThemeMode::System);

        // Assert
        assert!(!light.is_dark_titlebar);
        assert_eq!(light.bg_color, 0x00FC_FAF8);
        assert_eq!(light.brand_primary, 0x00D0_570B);
        assert_eq!(light.semantic_warning, 0x0006_77D9);
        assert!(dark.is_dark_titlebar);
        assert_eq!(dark.bg_color, 0x002A_170F);
        assert_eq!(dark.brand_primary, 0x00FA_A560);
        assert_eq!(dark.semantic_warning, 0x0024_BFFB);
    }
}
