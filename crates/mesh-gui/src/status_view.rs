//! Zone 0 Header Hero & Zone 1 Status card GDI double-buffered painting (`ADR-027`, `ADR-028`,
//! `ADR-030`).
//!
//! Contains zero `unsafe` code — delegates all Win32 GDI operations through `mesh_sys::gui_windows`.

use mesh_core::NodeName;
use mesh_proto::agent_ipc::AgentStatusResponse;
use mesh_sys::gui_windows::{
    ControlRect, draw_rounded_card, draw_status_pill, draw_text_in_rect, fill_rect_with_brush,
    with_double_buffer,
};

use crate::app::{
    AgentVersionIndicator, DashboardTab, DerivedUiSnapshot, DesktopUiState, TunnelSubState,
};
use crate::theme::UiThemePalette;

/// Render model for the custom-drawn Header Hero (Zone 0) and Status Card (Zone 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusHeroModel {
    pub(crate) ui_state: DesktopUiState,
    pub(crate) tunnel_sub_state: TunnelSubState,
    pub(crate) badge_label: String,
    pub(crate) headline: String,
    pub(crate) meta_summary: String,
    pub(crate) banner_text: Option<String>,
    pub(crate) active_tab: DashboardTab,
    pub(crate) enrolled: bool,
}

/// Builds a [`StatusHeroModel`] from the latest [`DerivedUiSnapshot`] and optional daemon status.
#[must_use]
pub(crate) fn build_status_hero_model(
    snapshot: &DerivedUiSnapshot,
    status: Option<&AgentStatusResponse>,
    active_tab: DashboardTab,
    toast_override: Option<&str>,
) -> StatusHeroModel {
    let badge_label = snapshot
        .ui_state
        .display_label(snapshot.tunnel_sub_state)
        .to_owned();
    let headline = snapshot
        .ui_state
        .headline(snapshot.tunnel_sub_state)
        .to_owned();

    let ver_tag = match &snapshot.version_indicator {
        AgentVersionIndicator::Compatible(v) => format!("Agent v{v}"),
        AgentVersionIndicator::Mismatch {
            gui_version,
            agent_version,
        } => format!("GUI v{gui_version} != Agent v{agent_version}"),
        AgentVersionIndicator::LegacyPre030 => "Agent <0.3.0 (Legacy)".to_owned(),
        AgentVersionIndicator::Unknown => "Agent v?".to_owned(),
    };

    let meta_summary = match status {
        Some(st) => {
            let ip = st
                .overlay_ip
                .map_or_else(|| "Unassigned".to_owned(), |v| v.to_string());
            let name = st.node_name.as_ref().map_or("<unnamed>", NodeName::as_str);
            format!(
                "Node: {name} | Overlay IP: {ip} | Peers: {} | {ver_tag}",
                st.peers.len()
            )
        }
        None => format!("GUI v{} | {ver_tag}", env!("CARGO_PKG_VERSION")),
    };

    let banner_text = toast_override
        .map(ToOwned::to_owned)
        .or_else(|| snapshot.legacy_banner.clone())
        .or_else(|| snapshot.version_mismatch_banner.clone())
        .or_else(|| snapshot.recoverable_error.clone());

    StatusHeroModel {
        ui_state: snapshot.ui_state,
        tunnel_sub_state: snapshot.tunnel_sub_state,
        badge_label,
        headline,
        meta_summary,
        banner_text,
        active_tab,
        enrolled: snapshot.enrolled,
    }
}

fn scale_px(px96: i32, dpi: u32) -> i32 {
    ((px96 * i32::try_from(dpi.max(72)).unwrap_or(96)) + 48) / 96
}

/// Paints the full window background, Zone 0 Header Hero card, semantic Status Pill, and Zone 1
/// rounded surface card using flicker-free GDI double buffering (`OwnedMemDc` + `OwnedGdiObj`).
pub(crate) fn paint_status_hero_surface(
    hdc: isize,
    width: i32,
    height: i32,
    dpi: u32,
    model: &StatusHeroModel,
    palette: &UiThemePalette,
) {
    if hdc == 0 || width <= 0 || height <= 0 {
        return;
    }
    let _blt = with_double_buffer(hdc, width, height, |mem_dc| {
        paint_hero_onto_dc(mem_dc, width, height, dpi, model, palette);
    });
}

fn paint_hero_onto_dc(
    dc: isize,
    width: i32,
    height: i32,
    dpi: u32,
    model: &StatusHeroModel,
    palette: &UiThemePalette,
) {
    let full = ControlRect::new(0, 0, width, height);
    if let Some(bg) = &palette.bg_brush {
        fill_rect_with_brush(dc, &full, bg);
    }

    let pad = scale_px(12, dpi);
    let hero_h = scale_px(96, dpi);
    let hero_w = (width - pad * 2).max(scale_px(320, dpi));
    let hero_rect = ControlRect::new(pad, pad, hero_w, hero_h);
    let radius = scale_px(10, dpi);

    if let (Some(card_brush), Some(border_pen)) = (&palette.card_brush, &palette.border_pen) {
        draw_rounded_card(dc, &hero_rect, radius, card_brush, border_pen);
    }

    // Semantic Status Pill (top-left of Header Hero card)
    let pill_w = scale_px(148, dpi);
    let pill_h = scale_px(26, dpi);
    let pill_rect = ControlRect::new(
        pad + scale_px(14, dpi),
        pad + scale_px(12, dpi),
        pill_w,
        pill_h,
    );
    if let (Some(pill_brush), Some(font_caption)) = (
        palette.semantic_brush_for_state(model.ui_state, model.tunnel_sub_state),
        &palette.font_caption,
    ) {
        draw_status_pill(
            dc,
            &pill_rect,
            &model.badge_label,
            pill_brush,
            palette.on_accent_text_color(),
            font_caption,
        );
    }

    // Headline text beside Status Pill
    let title_x = pill_rect.x + pill_w + scale_px(12, dpi);
    let title_w = (hero_rect.x + hero_rect.w - title_x - scale_px(14, dpi)).max(scale_px(120, dpi));
    let title_rect = ControlRect::new(title_x, pad + scale_px(10, dpi), title_w, scale_px(30, dpi));
    if let Some(font_headline) = &palette.font_headline {
        draw_text_in_rect(
            dc,
            &title_rect,
            &model.headline,
            palette.text_primary,
            font_headline,
            false,
        );
    }

    // Overlay IP / Node metadata line
    let meta_rect = ControlRect::new(
        pad + scale_px(14, dpi),
        pad + scale_px(46, dpi),
        (hero_w - scale_px(28, dpi)).max(scale_px(120, dpi)),
        scale_px(20, dpi),
    );
    if let Some(font_mono) = &palette.font_mono {
        draw_text_in_rect(
            dc,
            &meta_rect,
            &model.meta_summary,
            palette.text_secondary,
            font_mono,
            false,
        );
    }

    // Optional error / version / copy toast line inside hero footer
    if let Some(banner) = &model.banner_text
        && !banner.is_empty()
        && let Some(font_caption) = &palette.font_caption
    {
        let banner_rect = ControlRect::new(
            pad + scale_px(14, dpi),
            pad + scale_px(68, dpi),
            (hero_w - scale_px(28, dpi)).max(scale_px(120, dpi)),
            scale_px(20, dpi),
        );
        let banner_color = palette.semantic_color_for_state(model.ui_state, model.tunnel_sub_state);
        draw_text_in_rect(dc, &banner_rect, banner, banner_color, font_caption, false);
    }

    // Zone content frame card below tab bar / CTA bar
    let content_top = pad + hero_h + scale_px(52, dpi);
    let content_h = (height - content_top - pad).max(0);
    if content_h > scale_px(40, dpi)
        && let (Some(card_brush), Some(border_pen)) = (&palette.card_brush, &palette.border_pen)
    {
        let content_rect = ControlRect::new(pad, content_top, hero_w, content_h);
        draw_rounded_card(dc, &content_rect, radius, card_brush, border_pen);
    }
}

/// Paints Zone 1 (Header Hero, status pill, and surface card) onto `hdc` (`WP-U-A0` compat entry).
pub(crate) fn paint_status_zone(hdc: isize, palette: &UiThemePalette) {
    let _token_snapshot = (
        palette.mode,
        palette.is_high_contrast,
        palette.bg_color,
        palette.card_color,
        palette.border_color,
        palette.brand_primary,
        palette.brand_teal,
    );
    if hdc == 0 {
        return;
    }
    let default_model = StatusHeroModel {
        ui_state: DesktopUiState::NotEnrolled,
        tunnel_sub_state: TunnelSubState::NotEnrolled,
        badge_label: DesktopUiState::NotEnrolled
            .display_label(TunnelSubState::NotEnrolled)
            .to_owned(),
        headline: DesktopUiState::NotEnrolled
            .headline(TunnelSubState::NotEnrolled)
            .to_owned(),
        meta_summary: format!("GUI v{}", env!("CARGO_PKG_VERSION")),
        banner_text: None,
        active_tab: DashboardTab::Status,
        enrolled: false,
    };
    paint_status_hero_surface(hdc, 640, 220, palette.dpi, &default_model, palette);
}

#[cfg(test)]
mod tests {
    use mesh_sys::gui_windows::{OwnedMemDc, get_gui_resources_gdi_count};

    use super::{StatusHeroModel, paint_status_hero_surface, paint_status_zone};
    use crate::app::{DashboardTab, DesktopUiState, TunnelSubState};
    use crate::theme::{GDI_TEST_LOCK, ThemeMode, resolve_palette};

    #[test]
    fn test_status_view_stub_noop_on_null_hdc() {
        let _lock = GDI_TEST_LOCK.lock();
        // Arrange
        let palette = resolve_palette(ThemeMode::Light);

        // Act & Assert
        paint_status_zone(0, &palette);
    }

    #[test]
    fn test_status_view_double_buffer_paint_zero_gdi_leak() {
        let _lock = GDI_TEST_LOCK.lock();
        let paint_cycle = || {
            let palette = resolve_palette(ThemeMode::Dark);
            let model = StatusHeroModel {
                ui_state: DesktopUiState::Connected,
                tunnel_sub_state: TunnelSubState::Connected,
                badge_label: DesktopUiState::Connected
                    .display_label(TunnelSubState::Connected)
                    .to_owned(),
                headline: DesktopUiState::Connected
                    .headline(TunnelSubState::Connected)
                    .to_owned(),
                meta_summary: "Node: win-laptop | Overlay IP: 100.64.0.2".to_owned(),
                banner_text: Some("Copied Overlay IP".to_owned()),
                active_tab: DashboardTab::Status,
                enrolled: true,
            };
            if let Some(mem_dc) = OwnedMemDc::from_compatible(0) {
                paint_status_hero_surface(mem_dc.as_raw(), 720, 480, 96, &model, &palette);
            }
        };

        // Arrange: warm up one-time process GDI initialization, then check zero-delta across
        // 8 repeated paint cycles (bounded retries tolerate unrelated concurrent test threads).
        paint_cycle();
        let mut zero_delta_observed = false;
        for _attempt in 0..5 {
            let before = get_gui_resources_gdi_count();
            for _ in 0..8 {
                paint_cycle();
            }
            let after = get_gui_resources_gdi_count();
            if after == before {
                zero_delta_observed = true;
                break;
            }
            std::thread::yield_now();
        }

        // Assert
        assert!(
            zero_delta_observed,
            "GDI handle leak detected across repeated double-buffered StatusHero paint cycles"
        );
    }
}
