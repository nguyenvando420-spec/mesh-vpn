//! Zone 1 Status & Header Hero view painting skeleton (`ADR-027`, `ADR-028`, `WP-U-A0`).
//!
//! Full GDI double-buffered cards, status pills, and `display_label` wiring land in `WP-U-B1`.

use mesh_sys::gui_windows::OwnedGdiObj;

use crate::theme::UiThemePalette;

/// Paints Zone 1 (Header Hero, status pill, and connection CTA) onto `hdc` (`WP-U-A0` stub).
pub(crate) fn paint_status_zone(hdc: isize, palette: &UiThemePalette) {
    let _palette_snapshot = (
        palette.is_dark_titlebar,
        palette.bg_color,
        palette.card_color,
        palette.border_color,
        palette.text_primary,
        palette.text_secondary,
        palette.brand_primary,
        palette.brand_teal,
        palette.semantic_success,
        palette.semantic_warning,
        palette.semantic_error,
        palette.semantic_neutral,
        palette.font_body.as_ref().map(OwnedGdiObj::as_raw),
    );
    let _hdc_ready = hdc != 0;
}

#[cfg(test)]
mod tests {
    use super::paint_status_zone;
    use crate::theme::{ThemeMode, resolve_palette};

    #[test]
    fn test_status_view_stub_noop_on_null_hdc() {
        // Arrange
        let palette = resolve_palette(ThemeMode::Light);

        // Act & Assert
        paint_status_zone(0, &palette);
    }
}
