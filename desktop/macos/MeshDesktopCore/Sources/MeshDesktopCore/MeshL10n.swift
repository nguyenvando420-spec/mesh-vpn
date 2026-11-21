import Foundation

/// Language preference persisted under `UserDefaults(suiteName: "MeshVPN")` (`ADR-029`).
public enum LocaleMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case system
    case vi
    case en

    public static let userDefaultsSuiteName = "MeshVPN"
    public static let userDefaultsKey = "mesh_locale_mode"

    public var id: String { rawValue }

    public var l10nKey: String {
        switch self {
        case .system: return "locale.system"
        case .vi: return "locale.vietnamese"
        case .en: return "locale.english"
        }
    }

    public var effectiveLocale: Locale {
        switch self {
        case .system: return Locale.current
        case .vi: return Locale(identifier: "vi")
        case .en: return Locale(identifier: "en")
        }
    }

    public func localizedLabel(locale: Locale? = nil) -> String {
        MeshL10n.tr(l10nKey, locale: locale)
    }

    public static func load(
        from defaults: UserDefaults? = UserDefaults(suiteName: userDefaultsSuiteName)
    ) -> LocaleMode {
        guard let raw = defaults?.string(forKey: userDefaultsKey),
              let parsed = LocaleMode(rawValue: raw) else {
            return .system
        }
        return parsed
    }

    public func save(
        to defaults: UserDefaults? = UserDefaults(suiteName: userDefaultsSuiteName)
    ) {
        defaults?.set(rawValue, forKey: Self.userDefaultsKey)
    }
}

/// Pure `Sendable` `.lproj` bundle lookup supporting live locale switching (`ADR-029`).
public enum MeshL10n: Sendable {
    public static func resolvedLanguageCode(for locale: Locale? = nil) -> String {
        let effective = locale ?? Locale.current
        return effective.identifier.lowercased().hasPrefix("vi") ? "vi" : "en"
    }

    public static func localizedBundle(forLanguage lang: String) -> Bundle {
        if let path = Bundle.module.path(forResource: lang, ofType: "lproj"),
           let bundle = Bundle(path: path) {
            return bundle
        }
        return Bundle.module
    }

    public static func tr(_ key: String, locale: Locale? = nil) -> String {
        let lang = resolvedLanguageCode(for: locale)
        let bundle = localizedBundle(forLanguage: lang)
        return bundle.localizedString(forKey: key, value: key, table: nil)
    }

    public static func inline(en: String, vi: String, locale: Locale? = nil) -> String {
        resolvedLanguageCode(for: locale) == "vi" ? vi : en
    }

    public static func stringsTable(forLanguage lang: String) -> [String: String]? {
        guard let url = Bundle.module.url(
            forResource: "Localizable",
            withExtension: "strings",
            subdirectory: "\(lang).lproj"
        ) ?? localizedBundle(forLanguage: lang).url(
            forResource: "Localizable",
            withExtension: "strings"
        ) else {
            return nil
        }
        return NSDictionary(contentsOf: url) as? [String: String]
    }

    public static let canonicalKeys: [String] = [
        "tab.status",
        "tab.peers",
        "tab.settings",
        "tab.diagnostics_settings",
        "state.connected",
        "state.connecting",
        "state.disconnected",
        "state.degraded",
        "state.reconnecting",
        "state.not_enrolled",
        "state.agent_unavailable",
        "state.service_stopped",
        "state.reauth_required",
        "state.revoked",
        "state.error",
        "headline.connected",
        "headline.degraded",
        "headline.disconnected_enrolled",
        "headline.connecting",
        "headline.setup",
        "headline.agent_unreachable",
        "headline.service_stopped",
        "headline.reauth",
        "headline.revoked",
        "headline.error",
        "action.connect",
        "action.disconnect",
        "action.connect_vpn",
        "action.disconnect_vpn",
        "action.enroll",
        "action.rotate_key",
        "action.reset_identity",
        "action.export_bugreport",
        "action.run_netcheck",
        "action.on_demand",
        "action.scan_qr",
        "action.confirm_server",
        "action.open_dashboard",
        "action.launch_at_login",
        "action.quit_keep",
        "action.disconnect_quit",
        "action.ping",
        "action.review_rotation",
        "action.update_server",
        "action.verify_save",
        "action.verify_server_identity",
        "warn.lockdown",
        "warn.private_dns",
        "warn.legacy_agent",
        "warn.version_mismatch",
        "error.clock_skew",
        "error.captive_portal",
        "error.pin_mismatch",
        "error.reset_reenroll",
        "error.auth_failed",
        "tray.connected",
        "tray.connecting",
        "tray.degraded",
        "tray.disconnected",
        "tray.not_enrolled",
        "tray.agent_unavailable",
        "tray.service_stopped",
        "tray.reauth",
        "tray.revoked",
        "tray.attention",
        "theme.appearance",
        "theme.system",
        "theme.light",
        "theme.dark",
        "locale.language",
        "locale.system",
        "locale.vietnamese",
        "locale.english",
        "peers.filter.all",
        "peers.filter.online",
        "peers.filter.direct",
        "peers.filter.relay",
        "peers.badge.offline",
        "peers.badge.idle",
        "peers.search_placeholder",
        "peers.copy_overlay_ip",
        "peers.copy_fqdn",
        "peers.copied_toast",
        "peers.ping_selected",
        "peers.force_direct",
        "peers.section_header",
        "onboarding.title",
        "onboarding.subtitle",
        "onboarding.tab.scan_qr",
        "onboarding.tab.paste_uri",
        "onboarding.tab.manual",
        "onboarding.flag_secure",
        "onboarding.import_uri",
        "onboarding.paste_clipboard",
        "onboarding.or_enter_uri",
        "onboarding.review_uri",
        "onboarding.review_server",
        "onboarding.control_server",
        "onboarding.spki_pin_label",
        "onboarding.preauth_key",
        "onboarding.node_name",
        "onboarding.tls_spki_pin",
        "onboarding.tls_system_ca",
        "onboarding.connect_after",
        "onboarding.trust_connect",
        "onboarding.trust_enroll",
        "onboarding.desktop.title",
        "onboarding.desktop.subtitle",
        "onboarding.desktop.tab.join_uri",
        "onboarding.desktop.tab.manual",
        "onboarding.desktop.review",
        "onboarding.desktop.paste_uri",
        "onboarding.desktop.enroll_connect",
        "onboarding.desktop.setup_label",
        "rotation.title",
        "rotation.subtitle",
        "rotation.dialog_title",
        "rotation.new_key",
        "rotation.authorize",
        "rotation.review_key",
        "rotation.rotate_reconnect",
        "confirm.enrollment",
        "confirm.rotation",
        "confirm.verify_server",
        "confirm.verify_before_enroll",
        "confirm.confirm_rotation",
        "confirm.trust_connect",
        "confirm.back_edit",
        "settings.server_tls",
        "settings.reveal_pin",
        "settings.hide_pin",
        "settings.update_server",
        "settings.update_dialog",
        "settings.authorize_save",
        "settings.server_endpoint",
        "settings.apply_update",
        "settings.load_current",
        "settings.identity_title",
        "settings.rotate_key",
        "settings.erase_identity",
        "settings.erase_dialog",
        "settings.erase_detail",
        "settings.authorize_erase",
        "settings.boot_title",
        "settings.auto_start",
        "settings.open_vpn_settings",
        "settings.diag_title",
        "settings.export_share",
        "settings.purge_bugreports",
        "settings.section_header",
        "service.start_repair",
        "service.update",
        "service.update_recommended",
        "service.cleanup_stale",
        "service.firewall_allow",
        "service.reset_identity",
        "service.uninstall",
        "service.uninstall_title",
        "service.purge_keys",
        "diag.netcheck_title",
        "diag.run_netcheck",
        "diag.bugreport_export",
        "diag.export_archive",
        "diag.export_button",
        "diag.service_settings",
        "diag.service_lifecycle",
        "warn.subnet_conflict",
        "warn.firewall",
        "warn.degraded_tunnel",
        "warn.degraded_detail",
        "win.start_update_service",
        "win.cleanup",
        "win.reset_identity",
        "win.netcheck",
        "win.bugreport",
        "win.uninstall",
        "win.update_server_pin",
        "win.confirm_reset",
        "win.confirm_uninstall",
        "win.purge_keys_q",
        "biometric.verify_identity",
        "biometric.auth_subtitle",
        "biometric.cancel",
        "notif.app_name",
        "notif.qs_tile",
        "notif.channel_vpn",
        "notif.channel_alerts",
        "notif.title",
        "notif.connected",
        "notif.connecting",
        "notif.degraded",
        "notif.stopped",
        "notif.waiting_unlock",
        "notif.action_disconnect",
        "notif.warn_lockdown",
        "notif.warn_private_dns",
        "notif.share_bugreport",
        "diag.tunnel_telemetry",
        "diag.network_check",
        "diag.no_peers",
        "diag.bugreport_title",
        "diag.bugreport_body",
        "label.overlay",
        "label.control",
        "label.blind_relay",
        "confirm.reset",
        "confirm.reset_detail",
        "generic.cancel",
        "generic.close",
        "generic.dismiss",
        "generic.refresh",
        "generic.connect",
        "generic.disconnect"
    ]
}

extension ThemeMode {
    public var l10nKey: String {
        "theme.\(rawValue)"
    }

    public func localizedLabel(locale: Locale? = nil) -> String {
        MeshL10n.tr(l10nKey, locale: locale)
    }
}

extension DesktopTabKind {
    public var l10nKey: String {
        switch self {
        case .status: return "tab.status"
        case .peers: return "tab.peers"
        case .diagnostics: return "tab.diagnostics_settings"
        }
    }

    public func localizedTitle(locale: Locale? = nil) -> String {
        MeshL10n.tr(l10nKey, locale: locale)
    }
}

extension DesktopUiState {
    public var l10nKey: String {
        switch self {
        case .serviceNotInstalled: return "state.agent_unavailable"
        case .serviceStopped: return "state.service_stopped"
        case .unconfigured: return "state.not_enrolled"
        case .connecting: return "state.connecting"
        case .connected: return "state.connected"
        case .reauthRequired: return "state.reauth_required"
        case .revoked: return "state.revoked"
        case .error: return "state.error"
        }
    }

    public func localizedTitle(locale: Locale? = nil) -> String {
        MeshL10n.tr(l10nKey, locale: locale)
    }
}

extension PeerFilterMode {
    public var l10nKey: String {
        "peers.filter.\(rawValue.lowercased())"
    }

    public func localizedLabel(locale: Locale? = nil) -> String {
        MeshL10n.tr(l10nKey, locale: locale)
    }
}
