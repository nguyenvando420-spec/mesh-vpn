//! Compile-time bilingual UI string tables (`en` / `vi`, `213` canonical keys, `ADR-029`,
//! `US-127`).
//!
//! Canonical source of truth: `docs/01-discovery/unified-ui-readiness-requirements.md` §4.1.
//! `error.auth_failed` stays `"authentication failed"` in both `en` and `vi` (`SEC-05`);
//! structured JSON logs (`OPS-01`) remain English-only and never call [`t`].

use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};

/// User-selectable UI language mode (`ADR-029`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub(crate) enum LocaleMode {
    /// Follow the operating system UI locale.
    #[default]
    System = 0,
    /// Force English UI labels.
    En = 1,
    /// Force Vietnamese UI labels.
    Vi = 2,
}

impl LocaleMode {
    #[must_use]
    const fn as_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    const fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::En,
            2 => Self::Vi,
            _ => Self::System,
        }
    }
}

/// Active process-wide UI locale (`Ordering::Relaxed`, updated live without daemon restart).
static CURRENT_LOCALE: AtomicU8 = AtomicU8::new(LocaleMode::System.as_u8());

/// Updates the active UI [`LocaleMode`] immediately without restarting the daemon (`US-127`).
pub(crate) fn set_locale(mode: LocaleMode) {
    CURRENT_LOCALE.store(mode.as_u8(), Ordering::Relaxed);
}

/// Returns the currently active UI [`LocaleMode`] (`Ordering::Relaxed`).
#[must_use]
pub(crate) fn current_locale() -> LocaleMode {
    LocaleMode::from_u8(CURRENT_LOCALE.load(Ordering::Relaxed))
}

/// Compile-time English UI string table (`213` canonical keys per Discovery v1.1 §4.1).
pub(crate) const EN_STRINGS: [(&str, &str); 213] = [
    ("tab.status", "Status"),
    ("tab.peers", "Peers"),
    ("tab.settings", "Settings"),
    ("tab.diagnostics_settings", "Diagnostics & Settings"),
    ("state.connected", "Connected"),
    ("state.connecting", "Connecting"),
    ("state.disconnected", "Disconnected"),
    ("state.degraded", "Degraded"),
    ("state.reconnecting", "Reconnecting"),
    ("state.not_enrolled", "Not Enrolled"),
    ("state.agent_unavailable", "Agent Unavailable"),
    ("state.service_stopped", "Service Stopped"),
    ("state.reauth_required", "Re-auth Required"),
    ("state.revoked", "Device Revoked"),
    ("state.error", "Attention Required"),
    ("headline.connected", "Connected to Mesh Network"),
    (
        "headline.degraded",
        "Connected (Degraded: Control Stream Offline)",
    ),
    (
        "headline.disconnected_enrolled",
        "Disconnected (Enrolled — Ready to Reconnect)",
    ),
    ("headline.connecting", "Connecting to Mesh Network..."),
    ("headline.setup", "Set Up Mesh VPN"),
    ("headline.agent_unreachable", "Mesh Agent Unreachable"),
    (
        "headline.service_stopped",
        "Windows Service Stopped / Not Installed",
    ),
    ("headline.reauth", "Node Key Expired — Re-auth Required"),
    ("headline.revoked", "Node Revoked — Identity Reset Required"),
    ("headline.error", "Action Failed (Recoverable)"),
    ("action.connect", "Connect"),
    ("action.disconnect", "Disconnect"),
    ("action.connect_vpn", "Connect VPN"),
    ("action.disconnect_vpn", "Disconnect VPN"),
    ("action.enroll", "Enroll Mesh VPN"),
    ("action.rotate_key", "Rotate Node Key"),
    ("action.reset_identity", "Reset Device Identity"),
    ("action.export_bugreport", "Export Redacted Bugreport"),
    ("action.run_netcheck", "Run Netcheck Diagnostics"),
    ("action.on_demand", "On-Demand Auto-Connect"),
    ("action.scan_qr", "Scan Enrollment QR Code"),
    ("action.confirm_server", "Confirm Server"),
    ("action.open_dashboard", "Open Dashboard"),
    ("action.launch_at_login", "Launch at Login"),
    (
        "action.quit_keep",
        "Quit Mesh VPN (Keep Connected in Background)",
    ),
    ("action.disconnect_quit", "Disconnect & Quit Mesh VPN"),
    ("action.ping", "Ping"),
    ("action.review_rotation", "Review Rotation"),
    ("action.update_server", "Update Control Server"),
    ("action.verify_save", "Verify & Save"),
    (
        "action.verify_server_identity",
        "Verify Control Server Identity",
    ),
    ("warn.lockdown", "Always-On Lockdown Enabled"),
    ("warn.private_dns", "Strict Private DNS (:853) Active"),
    (
        "warn.legacy_agent",
        "Incompatible legacy agent (< 0.3.0) detected",
    ),
    (
        "warn.version_mismatch",
        "Version mismatch: GUI {v1} vs Agent {v2}",
    ),
    ("error.clock_skew", "Date & Time Settings"),
    ("error.captive_portal", "Network Settings"),
    ("error.pin_mismatch", "Review Server Pin"),
    ("error.reset_reenroll", "Reset & Re-enroll"),
    ("error.auth_failed", "authentication failed"),
    ("tray.connected", "Mesh VPN - Connected"),
    ("tray.connecting", "Mesh VPN - Connecting..."),
    ("tray.degraded", "Mesh VPN - Degraded (Control Offline)"),
    ("tray.disconnected", "Mesh VPN - Disconnected"),
    ("tray.not_enrolled", "Mesh VPN - Not Enrolled"),
    ("tray.agent_unavailable", "Mesh VPN - Agent Unavailable"),
    ("tray.service_stopped", "Mesh VPN - Service Stopped"),
    ("tray.reauth", "Mesh VPN - Re-auth Required"),
    ("tray.revoked", "Mesh VPN - Node Revoked"),
    ("tray.attention", "Mesh VPN - Attention Needed"),
    ("theme.appearance", "Appearance"),
    ("theme.system", "System"),
    ("theme.light", "Light"),
    ("theme.dark", "Dark"),
    ("locale.language", "Language"),
    ("locale.system", "System"),
    ("locale.vietnamese", "Tiếng Việt"),
    ("locale.english", "English"),
    ("peers.filter.all", "All"),
    ("peers.filter.online", "Online"),
    ("peers.filter.direct", "Direct"),
    ("peers.filter.relay", "Relay"),
    ("peers.badge.offline", "Offline"),
    ("peers.badge.idle", "Idle"),
    ("peers.search_placeholder", "Search peers..."),
    ("peers.copy_overlay_ip", "Copy Overlay IP"),
    ("peers.copy_fqdn", "Copy FQDN"),
    ("peers.copied_toast", "Copied to clipboard"),
    ("peers.ping_selected", "Ping Selected Peer"),
    ("peers.force_direct", "Force Direct P2P"),
    ("peers.section_header", "Peers & Diagnostics:"),
    ("onboarding.title", "Join Mesh Network"),
    (
        "onboarding.subtitle",
        "Scan an administrator QR or enter server fingerprint details. Automatic trust-on-first-use is disabled.",
    ),
    ("onboarding.tab.scan_qr", "Scan QR"),
    ("onboarding.tab.paste_uri", "Paste URI"),
    ("onboarding.tab.manual", "Manual"),
    (
        "onboarding.flag_secure",
        "Screen capture blocked (FLAG_SECURE)",
    ),
    ("onboarding.import_uri", "Import mesh://join URI"),
    (
        "onboarding.paste_clipboard",
        "Paste from Clipboard & Clear Immediately",
    ),
    ("onboarding.or_enter_uri", "Or enter mesh://join?... URI"),
    ("onboarding.review_uri", "Review URI Details"),
    ("onboarding.review_server", "Review Server & Continue"),
    ("onboarding.control_server", "Control server (host:port)"),
    ("onboarding.spki_pin_label", "SPKI Pin (sha256:<64 hex>)"),
    ("onboarding.preauth_key", "Pre-auth Key (mpk_...)"),
    ("onboarding.node_name", "Device Name (optional RFC 1123)"),
    ("onboarding.tls_spki_pin", "SPKI Pin (Default)"),
    ("onboarding.tls_system_ca", "System CA (Domain)"),
    (
        "onboarding.connect_after",
        "Connect VPN immediately after enrollment",
    ),
    ("onboarding.trust_connect", "Trust & Connect"),
    ("onboarding.trust_enroll", "Trust & Enroll"),
    ("onboarding.desktop.title", "Join Mesh VPN Network"),
    (
        "onboarding.desktop.subtitle",
        "Paste a mesh://join URI or enter your Control server details manually.",
    ),
    ("onboarding.desktop.tab.join_uri", "Join URI"),
    ("onboarding.desktop.tab.manual", "Manual Setup"),
    ("onboarding.desktop.review", "Review Connection Details"),
    ("onboarding.desktop.paste_uri", "Paste mesh:// URI"),
    ("onboarding.desktop.enroll_connect", "Enroll && Connect"),
    (
        "onboarding.desktop.setup_label",
        "Control Onboarding / Server Settings:",
    ),
    ("rotation.title", "Rotate Node Pre-Auth Key"),
    (
        "rotation.subtitle",
        "Provide a fresh mpk_ pre-auth key to renew this node's credentials.",
    ),
    ("rotation.dialog_title", "Rotate Node Identity Key"),
    ("rotation.new_key", "New Pre-auth Key"),
    ("rotation.authorize", "Authorize & Rotate"),
    ("rotation.review_key", "Review Key Rotation"),
    ("rotation.rotate_reconnect", "Rotate Key & Reconnect"),
    ("confirm.enrollment", "Confirm Mesh Node Enrollment"),
    ("confirm.rotation", "Confirm Pre-Auth Key Rotation"),
    ("confirm.verify_server", "Verify Control Server Identity"),
    (
        "confirm.verify_before_enroll",
        "Verify Server Trust Before Enrolling",
    ),
    ("confirm.confirm_rotation", "Confirm Key Rotation"),
    ("confirm.trust_connect", "Trust & Connect"),
    ("confirm.back_edit", "Back / Edit"),
    ("settings.server_tls", "Control Server & TLS Pin"),
    ("settings.reveal_pin", "Reveal Full Pin"),
    ("settings.hide_pin", "Hide Pin"),
    ("settings.update_server", "Update Server"),
    ("settings.update_dialog", "Update Control Server Config"),
    ("settings.authorize_save", "Authorize & Save"),
    (
        "settings.server_endpoint",
        "Control Server Endpoint & SPKI Pin",
    ),
    ("settings.apply_update", "Apply Server Update"),
    ("settings.load_current", "Load Current"),
    ("settings.identity_title", "Node Identity & Keystore DEK"),
    ("settings.rotate_key", "Rotate Key"),
    ("settings.erase_identity", "Erase Identity"),
    ("settings.erase_dialog", "Erase Local Mesh Identity?"),
    (
        "settings.erase_detail",
        "This stops the tunnel and permanently wipes Android Keystore DEK, sealed identity keys, and bootstrap state on this device.",
    ),
    ("settings.authorize_erase", "Authorize & Erase"),
    ("settings.boot_title", "Direct Boot & Always-On VPN"),
    ("settings.auto_start", "Auto-start after unlock"),
    ("settings.open_vpn_settings", "Open Android VPN Settings"),
    ("settings.diag_title", "Scrubbed Diagnostics"),
    (
        "settings.export_share",
        "Export & Share Bugreport (Biometric)",
    ),
    ("settings.purge_bugreports", "Purge Cached Bugreports"),
    ("settings.section_header", "Settings & Security"),
    ("service.start_repair", "Start / Repair Service"),
    ("service.update", "Update Service"),
    (
        "service.update_recommended",
        "Background Service Update Recommended",
    ),
    ("service.cleanup_stale", "Clean Up Stale Network State"),
    ("service.firewall_allow", "Allow macOS Firewall"),
    ("service.reset_identity", "Reset Device Identity..."),
    ("service.uninstall", "Uninstall Service..."),
    (
        "service.uninstall_title",
        "Uninstall Mesh VPN Background Service",
    ),
    (
        "service.purge_keys",
        "Also purge saved device identity keys",
    ),
    ("diag.netcheck_title", "Network & NAT Diagnostics"),
    ("diag.run_netcheck", "Run Netcheck"),
    ("diag.bugreport_export", "Redacted Bugreport Export"),
    (
        "diag.export_archive",
        "Export Daemon Diagnostics Archive (.tar)",
    ),
    ("diag.export_button", "Export Bugreport..."),
    ("diag.service_settings", "Diagnostics & Service Settings"),
    ("diag.service_lifecycle", "Service Lifecycle & Recovery"),
    ("warn.subnet_conflict", "Local Network Subnet Conflict"),
    ("warn.firewall", "macOS Application Firewall Warning"),
    ("warn.degraded_tunnel", "Tunnel Operating in Degraded Mode"),
    (
        "warn.degraded_detail",
        "Direct P2P paths are unavailable; traffic falls back via Relay.",
    ),
    ("win.start_update_service", "Start / Update Service (UAC)"),
    ("win.cleanup", "Cleanup"),
    ("win.reset_identity", "Reset Identity"),
    ("win.netcheck", "Netcheck"),
    ("win.bugreport", "Bugreport..."),
    ("win.uninstall", "Uninstall..."),
    ("win.update_server_pin", "Update Server / Pin"),
    ("win.confirm_reset", "Confirm Reset Identity"),
    ("win.confirm_uninstall", "Uninstall Mesh VPN"),
    ("win.purge_keys_q", "Purge Identity Keys?"),
    ("biometric.verify_identity", "Verify identity"),
    (
        "biometric.auth_subtitle",
        "Authenticate to perform sensitive Mesh VPN action",
    ),
    ("biometric.cancel", "Cancel"),
    ("notif.app_name", "Mesh VPN"),
    ("notif.qs_tile", "Mesh VPN"),
    ("notif.channel_vpn", "Mesh VPN Tunnel"),
    ("notif.channel_alerts", "Mesh VPN Alerts"),
    ("notif.title", "Mesh VPN"),
    ("notif.connected", "Connected (%1$s)"),
    ("notif.connecting", "Connecting to Mesh…"),
    ("notif.degraded", "Control offline; P2P active"),
    ("notif.stopped", "Disconnected"),
    (
        "notif.waiting_unlock",
        "Waiting for device unlock to load VPN keys",
    ),
    ("notif.action_disconnect", "Disconnect"),
    (
        "notif.warn_lockdown",
        "Lockdown active: non-VPN internet is blocked by Android",
    ),
    (
        "notif.warn_private_dns",
        "Strict Private DNS active: .mesh.internal may bypass Split-DNS",
    ),
    (
        "notif.share_bugreport",
        "Share scrubbed Mesh VPN diagnostics",
    ),
    ("diag.tunnel_telemetry", "Tunnel Telemetry"),
    ("diag.network_check", "Network Check"),
    ("diag.no_peers", "No peers visible yet"),
    ("diag.bugreport_title", "Mesh VPN Minimized"),
    (
        "diag.bugreport_body",
        "Mesh VPN continues running in the System Tray.",
    ),
    ("label.overlay", "Overlay"),
    ("label.control", "Control"),
    ("label.blind_relay", "Blind Relay"),
    ("confirm.reset", "Reset Device Identity?"),
    (
        "confirm.reset_detail",
        "This removes the VPN profile, sealed node keys, and Keychain DEK.",
    ),
    ("generic.cancel", "Cancel"),
    ("generic.close", "Close"),
    ("generic.dismiss", "Dismiss"),
    ("generic.refresh", "Refresh"),
    ("generic.connect", "Connect"),
    ("generic.disconnect", "Disconnect"),
];

/// Compile-time Vietnamese UI string table (`213` canonical keys per Discovery v1.1 §4.1).
///
/// `error.auth_failed` intentionally remains `"authentication failed"` (`SEC-05`).
pub(crate) const VI_STRINGS: [(&str, &str); 213] = [
    ("tab.status", "Trạng thái"),
    ("tab.peers", "Thiết bị cùng mạng"),
    ("tab.settings", "Cài đặt"),
    ("tab.diagnostics_settings", "Chẩn đoán & Cài đặt"),
    ("state.connected", "Đã kết nối"),
    ("state.connecting", "Đang kết nối"),
    ("state.disconnected", "Đã ngắt kết nối"),
    ("state.degraded", "Suy giảm"),
    ("state.reconnecting", "Đang kết nối lại"),
    ("state.not_enrolled", "Chưa đăng ký"),
    ("state.agent_unavailable", "Dịch vụ không sẵn sàng"),
    ("state.service_stopped", "Dịch vụ đã dừng"),
    ("state.reauth_required", "Yêu cầu xác thực lại"),
    ("state.revoked", "Thiết bị bị thu hồi"),
    ("state.error", "Cần xử lý"),
    ("headline.connected", "Đã kết nối mạng Mesh"),
    (
        "headline.degraded",
        "Đã kết nối (Suy giảm: Kênh điều khiển ngoại tuyến)",
    ),
    (
        "headline.disconnected_enrolled",
        "Đã ngắt (Đã đăng ký — Sẵn sàng kết nối lại)",
    ),
    ("headline.connecting", "Đang kết nối mạng Mesh..."),
    ("headline.setup", "Thiết lập Mesh VPN"),
    (
        "headline.agent_unreachable",
        "Dịch vụ Mesh không truy cập được",
    ),
    (
        "headline.service_stopped",
        "Dịch vụ Windows đã dừng / Chưa cài đặt",
    ),
    (
        "headline.reauth",
        "Khóa nút đã hết hạn — Yêu cầu xác thực lại",
    ),
    ("headline.revoked", "Nút bị thu hồi — Cần đặt lại danh tính"),
    ("headline.error", "Thao tác thất bại (Có thể khôi phục)"),
    ("action.connect", "Kết nối"),
    ("action.disconnect", "Ngắt kết nối"),
    ("action.connect_vpn", "Kết nối VPN"),
    ("action.disconnect_vpn", "Ngắt kết nối VPN"),
    ("action.enroll", "Đăng ký Mesh VPN"),
    ("action.rotate_key", "Xoay vòng khóa nút"),
    ("action.reset_identity", "Đặt lại danh tính thiết bị"),
    ("action.export_bugreport", "Xuất báo lỗi đã che bí mật"),
    ("action.run_netcheck", "Chạy chẩn đoán mạng"),
    ("action.on_demand", "Tự động kết nối On-Demand"),
    ("action.scan_qr", "Quét mã QR đăng ký"),
    ("action.confirm_server", "Xác nhận máy chủ"),
    ("action.open_dashboard", "Mở bảng điều khiển"),
    ("action.launch_at_login", "Khởi chạy cùng hệ thống"),
    ("action.quit_keep", "Thoát Mesh VPN (Giữ kết nối nền)"),
    ("action.disconnect_quit", "Ngắt kết nối & Thoát Mesh VPN"),
    ("action.ping", "Ping"),
    ("action.review_rotation", "Xem xét xoay khóa"),
    ("action.update_server", "Cập nhật máy chủ điều khiển"),
    ("action.verify_save", "Xác minh & Lưu"),
    (
        "action.verify_server_identity",
        "Xác minh danh tính máy chủ điều khiển",
    ),
    ("warn.lockdown", "Chế độ luôn bật đã kích hoạt"),
    (
        "warn.private_dns",
        "DNS riêng nghiêm ngặt (:853) đang hoạt động",
    ),
    (
        "warn.legacy_agent",
        "Phát hiện agent cũ không tương thích (< 0.3.0)",
    ),
    (
        "warn.version_mismatch",
        "Không khớp phiên bản: Giao diện {v1} vs Agent {v2}",
    ),
    ("error.clock_skew", "Cài đặt ngày & giờ"),
    ("error.captive_portal", "Cài đặt mạng"),
    ("error.pin_mismatch", "Xem lại ghim máy chủ"),
    ("error.reset_reenroll", "Đặt lại & Đăng ký lại"),
    ("error.auth_failed", "authentication failed"),
    ("tray.connected", "Mesh VPN - Đã kết nối"),
    ("tray.connecting", "Mesh VPN - Đang kết nối..."),
    (
        "tray.degraded",
        "Mesh VPN - Suy giảm (Điều khiển ngoại tuyến)",
    ),
    ("tray.disconnected", "Mesh VPN - Đã ngắt kết nối"),
    ("tray.not_enrolled", "Mesh VPN - Chưa đăng ký"),
    (
        "tray.agent_unavailable",
        "Mesh VPN - Dịch vụ không sẵn sàng",
    ),
    ("tray.service_stopped", "Mesh VPN - Dịch vụ đã dừng"),
    ("tray.reauth", "Mesh VPN - Yêu cầu xác thực lại"),
    ("tray.revoked", "Mesh VPN - Nút bị thu hồi"),
    ("tray.attention", "Mesh VPN - Cần xử lý"),
    ("theme.appearance", "Giao diện"),
    ("theme.system", "Hệ thống"),
    ("theme.light", "Sáng"),
    ("theme.dark", "Tối"),
    ("locale.language", "Ngôn ngữ"),
    ("locale.system", "Hệ thống"),
    ("locale.vietnamese", "Tiếng Việt"),
    ("locale.english", "English"),
    ("peers.filter.all", "Tất cả"),
    ("peers.filter.online", "Trực tuyến"),
    ("peers.filter.direct", "Trực tiếp"),
    ("peers.filter.relay", "Chuyển tiếp"),
    ("peers.badge.offline", "Ngoại tuyến"),
    ("peers.badge.idle", "Nhàn rỗi"),
    ("peers.search_placeholder", "Tìm thiết bị..."),
    ("peers.copy_overlay_ip", "Sao chép IP lớp phủ"),
    ("peers.copy_fqdn", "Sao chép FQDN"),
    ("peers.copied_toast", "Đã sao chép vào bộ nhớ tạm"),
    ("peers.ping_selected", "Ping thiết bị đã chọn"),
    ("peers.force_direct", "Bắt buộc kết nối trực tiếp"),
    ("peers.section_header", "Thiết bị & Chẩn đoán:"),
    ("onboarding.title", "Tham gia mạng Mesh"),
    (
        "onboarding.subtitle",
        "Quét mã QR từ quản trị viên hoặc nhập chi tiết vân tay máy chủ. Tự động tin tưởng lần đầu đã bị tắt.",
    ),
    ("onboarding.tab.scan_qr", "Quét QR"),
    ("onboarding.tab.paste_uri", "Dán URI"),
    ("onboarding.tab.manual", "Thủ công"),
    ("onboarding.flag_secure", "Chặn chụp màn hình (FLAG_SECURE)"),
    ("onboarding.import_uri", "Nhập URI mesh://join"),
    ("onboarding.paste_clipboard", "Dán từ bộ nhớ tạm & Xóa ngay"),
    ("onboarding.or_enter_uri", "Hoặc nhập URI mesh://join?..."),
    ("onboarding.review_uri", "Xem chi tiết URI"),
    ("onboarding.review_server", "Xem máy chủ & Tiếp tục"),
    (
        "onboarding.control_server",
        "Máy chủ điều khiển (host:port)",
    ),
    ("onboarding.spki_pin_label", "Ghim SPKI (sha256:<64 hex>)"),
    ("onboarding.preauth_key", "Khóa xác thực trước (mpk_...)"),
    (
        "onboarding.node_name",
        "Tên thiết bị (RFC 1123, không bắt buộc)",
    ),
    ("onboarding.tls_spki_pin", "Ghim SPKI (Mặc định)"),
    ("onboarding.tls_system_ca", "CA hệ thống (Tên miền)"),
    (
        "onboarding.connect_after",
        "Kết nối VPN ngay sau khi đăng ký",
    ),
    ("onboarding.trust_connect", "Tin tưởng & Kết nối"),
    ("onboarding.trust_enroll", "Tin tưởng & Đăng ký"),
    ("onboarding.desktop.title", "Tham gia mạng Mesh VPN"),
    (
        "onboarding.desktop.subtitle",
        "Dán URI mesh://join hoặc nhập chi tiết máy chủ điều khiển thủ công.",
    ),
    ("onboarding.desktop.tab.join_uri", "URI tham gia"),
    ("onboarding.desktop.tab.manual", "Thiết lập thủ công"),
    ("onboarding.desktop.review", "Xem chi tiết kết nối"),
    ("onboarding.desktop.paste_uri", "Dán URI mesh://"),
    ("onboarding.desktop.enroll_connect", "Đăng ký && Kết nối"),
    (
        "onboarding.desktop.setup_label",
        "Hướng dẫn gia nhập / Cài đặt máy chủ:",
    ),
    ("rotation.title", "Xoay vòng khóa xác thực nút"),
    (
        "rotation.subtitle",
        "Cung cấp khóa mpk_ mới để gia hạn chứng danh nút.",
    ),
    ("rotation.dialog_title", "Xoay vòng khóa danh tính nút"),
    ("rotation.new_key", "Khóa xác thực trước mới"),
    ("rotation.authorize", "Ủy quyền & Xoay vòng"),
    ("rotation.review_key", "Xem xét xoay khóa"),
    ("rotation.rotate_reconnect", "Xoay khóa & Kết nối lại"),
    ("confirm.enrollment", "Xác nhận đăng ký nút Mesh"),
    ("confirm.rotation", "Xác nhận xoay vòng khóa xác thực"),
    (
        "confirm.verify_server",
        "Xác minh danh tính máy chủ điều khiển",
    ),
    (
        "confirm.verify_before_enroll",
        "Xác minh tin tưởng máy chủ trước khi đăng ký",
    ),
    ("confirm.confirm_rotation", "Xác nhận xoay khóa"),
    ("confirm.trust_connect", "Tin tưởng & Kết nối"),
    ("confirm.back_edit", "Quay lại / Sửa"),
    ("settings.server_tls", "Máy chủ điều khiển & Ghim TLS"),
    ("settings.reveal_pin", "Hiện đầy đủ ghim"),
    ("settings.hide_pin", "Ẩn ghim"),
    ("settings.update_server", "Cập nhật máy chủ"),
    (
        "settings.update_dialog",
        "Cập nhật cấu hình máy chủ điều khiển",
    ),
    ("settings.authorize_save", "Ủy quyền & Lưu"),
    ("settings.server_endpoint", "Điểm cuối máy chủ & Ghim SPKI"),
    ("settings.apply_update", "Áp dụng cập nhật máy chủ"),
    ("settings.load_current", "Tải cấu hình hiện tại"),
    ("settings.identity_title", "Danh tính nút & Khóa DEK"),
    ("settings.rotate_key", "Xoay vòng khóa"),
    ("settings.erase_identity", "Xóa danh tính"),
    ("settings.erase_dialog", "Xóa danh tính Mesh cục bộ?"),
    (
        "settings.erase_detail",
        "Thao tác này dừng đường hầm và xóa vĩnh viễn DEK, khóa danh tính đã niêm phong và trạng thái khởi tạo trên thiết bị.",
    ),
    ("settings.authorize_erase", "Ủy quyền & Xóa"),
    ("settings.boot_title", "Khởi động trực tiếp & VPN luôn bật"),
    ("settings.auto_start", "Tự khởi động sau mở khóa"),
    ("settings.open_vpn_settings", "Mở cài đặt VPN Android"),
    ("settings.diag_title", "Chẩn đoán đã che bí mật"),
    (
        "settings.export_share",
        "Xuất & Chia sẻ báo lỗi (Sinh trắc học)",
    ),
    ("settings.purge_bugreports", "Xóa báo lỗi đã lưu"),
    ("settings.section_header", "Cài đặt & Bảo mật"),
    ("service.start_repair", "Khởi động / Sửa chữa dịch vụ"),
    ("service.update", "Cập nhật dịch vụ"),
    (
        "service.update_recommended",
        "Khuyến nghị cập nhật dịch vụ nền",
    ),
    ("service.cleanup_stale", "Dọn dẹp trạng thái mạng cũ"),
    ("service.firewall_allow", "Cho phép tường lửa macOS"),
    ("service.reset_identity", "Đặt lại danh tính thiết bị..."),
    ("service.uninstall", "Gỡ cài đặt dịch vụ..."),
    ("service.uninstall_title", "Gỡ cài đặt dịch vụ nền Mesh VPN"),
    ("service.purge_keys", "Đồng thời xóa khóa danh tính đã lưu"),
    ("diag.netcheck_title", "Chẩn đoán mạng & NAT"),
    ("diag.run_netcheck", "Chạy kiểm tra mạng"),
    ("diag.bugreport_export", "Xuất báo lỗi đã che bí mật"),
    (
        "diag.export_archive",
        "Xuất tệp lưu trữ chẩn đoán daemon (.tar)",
    ),
    ("diag.export_button", "Xuất báo lỗi..."),
    ("diag.service_settings", "Chẩn đoán & Cài đặt dịch vụ"),
    ("diag.service_lifecycle", "Vòng đời dịch vụ & Khôi phục"),
    ("warn.subnet_conflict", "Xung đột mạng con cục bộ"),
    ("warn.firewall", "Cảnh báo tường lửa ứng dụng macOS"),
    (
        "warn.degraded_tunnel",
        "Đường hầm hoạt động ở chế độ suy giảm",
    ),
    (
        "warn.degraded_detail",
        "Đường trực tiếp P2P không khả dụng; lưu lượng chuyển qua Relay.",
    ),
    (
        "win.start_update_service",
        "Khởi động / Cập nhật dịch vụ (UAC)",
    ),
    ("win.cleanup", "Dọn dẹp"),
    ("win.reset_identity", "Đặt lại danh tính"),
    ("win.netcheck", "Kiểm tra mạng"),
    ("win.bugreport", "Báo lỗi..."),
    ("win.uninstall", "Gỡ cài đặt..."),
    ("win.update_server_pin", "Cập nhật máy chủ / Ghim"),
    ("win.confirm_reset", "Xác nhận đặt lại danh tính"),
    ("win.confirm_uninstall", "Gỡ cài đặt Mesh VPN"),
    ("win.purge_keys_q", "Xóa khóa danh tính?"),
    ("biometric.verify_identity", "Xác minh danh tính"),
    (
        "biometric.auth_subtitle",
        "Xác thực để thực hiện thao tác nhạy cảm Mesh VPN",
    ),
    ("biometric.cancel", "Hủy"),
    ("notif.app_name", "Mesh VPN"),
    ("notif.qs_tile", "Mesh VPN"),
    ("notif.channel_vpn", "Đường hầm Mesh VPN"),
    ("notif.channel_alerts", "Cảnh báo Mesh VPN"),
    ("notif.title", "Mesh VPN"),
    ("notif.connected", "Đã kết nối (%1$s)"),
    ("notif.connecting", "Đang kết nối Mesh…"),
    ("notif.degraded", "Điều khiển ngoại tuyến; P2P hoạt động"),
    ("notif.stopped", "Đã ngắt kết nối"),
    (
        "notif.waiting_unlock",
        "Đang chờ mở khóa thiết bị để nạp khóa VPN",
    ),
    ("notif.action_disconnect", "Ngắt kết nối"),
    (
        "notif.warn_lockdown",
        "Chế độ khóa: Android chặn internet ngoài VPN",
    ),
    (
        "notif.warn_private_dns",
        "DNS riêng nghiêm ngặt: .mesh.internal có thể bỏ qua Split-DNS",
    ),
    (
        "notif.share_bugreport",
        "Chia sẻ chẩn đoán Mesh VPN đã che bí mật",
    ),
    ("diag.tunnel_telemetry", "Dữ liệu đường hầm"),
    ("diag.network_check", "Kiểm tra mạng"),
    ("diag.no_peers", "Chưa có thiết bị nào"),
    ("diag.bugreport_title", "Mesh VPN đã thu nhỏ"),
    (
        "diag.bugreport_body",
        "Mesh VPN tiếp tục chạy trong khay hệ thống.",
    ),
    ("label.overlay", "Lớp phủ mạng"),
    ("label.control", "Điều khiển"),
    ("label.blind_relay", "Chuyển tiếp ẩn"),
    ("confirm.reset", "Đặt lại danh tính thiết bị?"),
    (
        "confirm.reset_detail",
        "Thao tác này xóa cấu hình VPN, khóa nút đã niêm phong và DEK trong Keychain.",
    ),
    ("generic.cancel", "Hủy"),
    ("generic.close", "Đóng"),
    ("generic.dismiss", "Bỏ qua"),
    ("generic.refresh", "Làm mới"),
    ("generic.connect", "Kết nối"),
    ("generic.disconnect", "Ngắt kết nối"),
];

/// Looks up a localized UI string for `key` using the currently active [`LocaleMode`].
#[must_use]
pub(crate) fn t(key: &str) -> &'static str {
    t_for(key, current_locale())
}

/// Pure UI string lookup for an explicit [`LocaleMode`] (race-free for parallel unit tests).
///
/// Falls back to English when a Vietnamese entry is absent, or `""` for unknown keys.
#[must_use]
pub(crate) fn t_for(key: &str, locale: LocaleMode) -> &'static str {
    let use_vi = match locale {
        LocaleMode::System => system_locale_is_vi(),
        LocaleMode::En => false,
        LocaleMode::Vi => true,
    };
    if use_vi && let Some(val) = lookup_in_table(&VI_STRINGS, key) {
        return val;
    }
    lookup_in_table(&EN_STRINGS, key).unwrap_or("")
}

#[must_use]
fn lookup_in_table(table: &[(&str, &'static str)], key: &str) -> Option<&'static str> {
    for &(entry_key, entry_val) in table {
        if !entry_key.is_empty() && entry_key == key {
            return Some(entry_val);
        }
    }
    None
}

fn system_locale_is_vi() -> bool {
    #[cfg(target_os = "windows")]
    {
        mesh_sys::gui_windows::detect_windows_system_locale_is_vi()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{EN_STRINGS, LocaleMode, VI_STRINGS, current_locale, t, t_for};

    #[test]
    fn test_i18n_tables_have_213_non_empty_paired_keys_and_sec05_invariant() {
        // Arrange & Act & Assert
        assert_eq!(EN_STRINGS.len(), 213);
        assert_eq!(VI_STRINGS.len(), 213);
        for ((en_key, en_val), (vi_key, vi_val)) in EN_STRINGS.iter().zip(VI_STRINGS.iter()) {
            assert_eq!(en_key, vi_key, "EN/VI key order mismatch");
            assert!(!en_key.is_empty());
            assert!(!en_val.is_empty());
            assert!(!vi_val.is_empty());
            assert_eq!(t_for(en_key, LocaleMode::En), *en_val);
            assert_eq!(t_for(vi_key, LocaleMode::Vi), *vi_val);
        }
        assert_eq!(t_for("tab.status", LocaleMode::En), "Status");
        assert_eq!(t_for("tab.status", LocaleMode::Vi), "Trạng thái");
        assert_eq!(
            t_for("error.auth_failed", LocaleMode::En),
            "authentication failed"
        );
        assert_eq!(
            t_for("error.auth_failed", LocaleMode::Vi),
            "authentication failed"
        );
        assert_eq!(t_for("nonexistent.key", LocaleMode::En), "");
        assert_eq!(t_for("nonexistent.key", LocaleMode::Vi), "");
        assert!(!t("tab.status").is_empty());
        let _active = current_locale();
        let _setter = super::set_locale;
    }
}
