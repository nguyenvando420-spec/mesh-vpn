@testable import MeshApp
import MeshCoreKit
import XCTest

private enum CanonicalGlossaryFixture {
    static let keys: [String] = [
        "action.confirm_server",
        "action.connect",
        "action.connect_vpn",
        "action.disconnect",
        "action.disconnect_quit",
        "action.disconnect_vpn",
        "action.enroll",
        "action.export_bugreport",
        "action.launch_at_login",
        "action.on_demand",
        "action.open_dashboard",
        "action.ping",
        "action.quit_keep",
        "action.reset_identity",
        "action.review_rotation",
        "action.rotate_key",
        "action.run_netcheck",
        "action.scan_qr",
        "action.update_server",
        "action.verify_save",
        "action.verify_server_identity",
        "biometric.auth_subtitle",
        "biometric.cancel",
        "biometric.verify_identity",
        "confirm.back_edit",
        "confirm.confirm_rotation",
        "confirm.enrollment",
        "confirm.reset",
        "confirm.reset_detail",
        "confirm.rotation",
        "confirm.trust_connect",
        "confirm.verify_before_enroll",
        "confirm.verify_server",
        "diag.bugreport_body",
        "diag.bugreport_export",
        "diag.bugreport_title",
        "diag.export_archive",
        "diag.export_button",
        "diag.netcheck_title",
        "diag.network_check",
        "diag.no_peers",
        "diag.run_netcheck",
        "diag.service_lifecycle",
        "diag.service_settings",
        "diag.tunnel_telemetry",
        "error.auth_failed",
        "error.captive_portal",
        "error.clock_skew",
        "error.pin_mismatch",
        "error.reset_reenroll",
        "generic.cancel",
        "generic.close",
        "generic.connect",
        "generic.disconnect",
        "generic.dismiss",
        "generic.refresh",
        "headline.agent_unreachable",
        "headline.connected",
        "headline.connecting",
        "headline.degraded",
        "headline.disconnected_enrolled",
        "headline.error",
        "headline.reauth",
        "headline.revoked",
        "headline.service_stopped",
        "headline.setup",
        "label.blind_relay",
        "label.control",
        "label.overlay",
        "locale.english",
        "locale.language",
        "locale.system",
        "locale.vietnamese",
        "notif.action_disconnect",
        "notif.app_name",
        "notif.channel_alerts",
        "notif.channel_vpn",
        "notif.connected",
        "notif.connecting",
        "notif.degraded",
        "notif.qs_tile",
        "notif.share_bugreport",
        "notif.stopped",
        "notif.title",
        "notif.waiting_unlock",
        "notif.warn_lockdown",
        "notif.warn_private_dns",
        "onboarding.connect_after",
        "onboarding.control_server",
        "onboarding.desktop.enroll_connect",
        "onboarding.desktop.paste_uri",
        "onboarding.desktop.review",
        "onboarding.desktop.setup_label",
        "onboarding.desktop.subtitle",
        "onboarding.desktop.tab.join_uri",
        "onboarding.desktop.tab.manual",
        "onboarding.desktop.title",
        "onboarding.flag_secure",
        "onboarding.import_uri",
        "onboarding.node_name",
        "onboarding.or_enter_uri",
        "onboarding.paste_clipboard",
        "onboarding.preauth_key",
        "onboarding.review_server",
        "onboarding.review_uri",
        "onboarding.spki_pin_label",
        "onboarding.subtitle",
        "onboarding.tab.manual",
        "onboarding.tab.paste_uri",
        "onboarding.tab.scan_qr",
        "onboarding.title",
        "onboarding.tls_spki_pin",
        "onboarding.tls_system_ca",
        "onboarding.trust_connect",
        "onboarding.trust_enroll",
        "peers.badge.idle",
        "peers.badge.offline",
        "peers.copied_toast",
        "peers.copy_fqdn",
        "peers.copy_overlay_ip",
        "peers.filter.all",
        "peers.filter.direct",
        "peers.filter.online",
        "peers.filter.relay",
        "peers.force_direct",
        "peers.ping_selected",
        "peers.search_placeholder",
        "peers.section_header",
        "rotation.authorize",
        "rotation.dialog_title",
        "rotation.new_key",
        "rotation.review_key",
        "rotation.rotate_reconnect",
        "rotation.subtitle",
        "rotation.title",
        "service.cleanup_stale",
        "service.firewall_allow",
        "service.purge_keys",
        "service.reset_identity",
        "service.start_repair",
        "service.uninstall",
        "service.uninstall_title",
        "service.update",
        "service.update_recommended",
        "settings.apply_update",
        "settings.authorize_erase",
        "settings.authorize_save",
        "settings.auto_start",
        "settings.boot_title",
        "settings.diag_title",
        "settings.erase_detail",
        "settings.erase_dialog",
        "settings.erase_identity",
        "settings.export_share",
        "settings.hide_pin",
        "settings.identity_title",
        "settings.load_current",
        "settings.open_vpn_settings",
        "settings.purge_bugreports",
        "settings.reveal_pin",
        "settings.rotate_key",
        "settings.section_header",
        "settings.server_endpoint",
        "settings.server_tls",
        "settings.update_dialog",
        "settings.update_server",
        "state.agent_unavailable",
        "state.connected",
        "state.connecting",
        "state.degraded",
        "state.disconnected",
        "state.error",
        "state.not_enrolled",
        "state.reauth_required",
        "state.reconnecting",
        "state.revoked",
        "state.service_stopped",
        "tab.diagnostics_settings",
        "tab.peers",
        "tab.settings",
        "tab.status",
        "theme.appearance",
        "theme.dark",
        "theme.light",
        "theme.system",
        "tray.agent_unavailable",
        "tray.attention",
        "tray.connected",
        "tray.connecting",
        "tray.degraded",
        "tray.disconnected",
        "tray.not_enrolled",
        "tray.reauth",
        "tray.revoked",
        "tray.service_stopped",
        "warn.degraded_detail",
        "warn.degraded_tunnel",
        "warn.firewall",
        "warn.legacy_agent",
        "warn.lockdown",
        "warn.private_dns",
        "warn.subnet_conflict",
        "warn.version_mismatch",
        "win.bugreport",
        "win.cleanup",
        "win.confirm_reset",
        "win.confirm_uninstall",
        "win.netcheck",
        "win.purge_keys_q",
        "win.reset_identity",
        "win.start_update_service",
        "win.uninstall",
        "win.update_server_pin"
    ]
}

final class LocalizationParityTests: XCTestCase {
    func test_l10n_all213CanonicalKeys_resolveInEnglishAndVietnamese() {
        // Arrange
        let enLocale = Locale(identifier: "en")
        let viLocale = Locale(identifier: "vi")
        let keys = CanonicalGlossaryFixture.keys

        // Act & Assert
        XCTAssertEqual(keys.count, 213)
        XCTAssertEqual(Set(keys).count, 213)
        for key in keys {
            let enValue = L10n.tr(key, locale: enLocale)
            let viValue = L10n.tr(key, locale: viLocale)
            XCTAssertFalse(enValue.isEmpty, "Empty EN value for \(key)")
            XCTAssertFalse(viValue.isEmpty, "Empty VI value for \(key)")
            XCTAssertNotEqual(enValue, key, "Missing EN translation for \(key)")
            XCTAssertNotEqual(viValue, key, "Missing VI translation for \(key)")
        }
    }

    func test_l10n_stateConnected_returnsExpectedTranslations() {
        // Arrange
        let viLocale = Locale(identifier: "vi")
        let enLocale = Locale(identifier: "en")

        // Act & Assert
        XCTAssertEqual(L10n.tr("state.connected", locale: viLocale), "Đã kết nối")
        XCTAssertEqual(L10n.tr("state.connected", locale: enLocale), "Connected")
        XCTAssertEqual(L10n.tr("tab.peers", locale: viLocale), "Thiết bị cùng mạng")
        XCTAssertEqual(L10n.tr("tab.settings", locale: viLocale), "Cài đặt")
    }

    func test_sec05_authFailedRemainsEnglishAcrossAllLocales() {
        // Arrange
        let viLocale = Locale(identifier: "vi")
        let enLocale = Locale(identifier: "en")
        let mapped = MeshErrorMapper.map(
            MobileError.Unauthenticated(errorCode: "E_UNAUTHENTICATED", message: "token invalid")
        )

        // Act & Assert
        XCTAssertEqual(L10n.tr("error.auth_failed", locale: enLocale), "authentication failed")
        XCTAssertEqual(L10n.tr("error.auth_failed", locale: viLocale), "authentication failed")
        XCTAssertEqual(mapped.message, "authentication failed")
    }

    @MainActor
    func test_localeManager_persistsUnderMeshLocaleModeKeyOnUserDefaults() throws {
        // Arrange
        let stdKey = "mesh_locale_mode"
        let previousValue = UserDefaults.standard.object(forKey: stdKey)
        UserDefaults.standard.removeObject(forKey: stdKey)
        addTeardownBlock {
            if let previousValue {
                UserDefaults.standard.set(previousValue, forKey: stdKey)
            } else {
                UserDefaults.standard.removeObject(forKey: stdKey)
            }
        }

        // Act
        let manager = LocaleManager()
        XCTAssertEqual(LocaleManager.userDefaultsKey, stdKey)
        XCTAssertEqual(manager.localeMode, .system)
        manager.setLocaleMode(.vi)

        // Assert
        XCTAssertEqual(UserDefaults.standard.string(forKey: stdKey), "vi")
        XCTAssertEqual(manager.resolvedLocale, Locale(identifier: "vi"))
        XCTAssertEqual(AppTab.status.localizationKey, "tab.status")
        XCTAssertEqual(AppTab.peers.localizationKey, "tab.peers")
        XCTAssertEqual(AppTab.settings.localizationKey, "tab.settings")
        XCTAssertEqual(
            PeerFilterMode.direct.localizedTitle(locale: Locale(identifier: "vi")),
            "Trực tiếp"
        )
    }

    func test_xcstringsCatalog_containsExactly213MigratedKeysAndNoNavPrefix() throws {
        // Arrange
        let testFileURL = URL(fileURLWithPath: #filePath)
        let catalogURL = testFileURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("MeshApp")
            .appendingPathComponent("Resources")
            .appendingPathComponent("Localizable.xcstrings")
        guard FileManager.default.fileExists(atPath: catalogURL.path) else {
            throw XCTSkip("Source catalog not accessible from sandboxed test bundle")
        }

        // Act
        let data = try Data(contentsOf: catalogURL)
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        let strings = try XCTUnwrap(root["strings"] as? [String: Any])

        // Assert
        XCTAssertEqual(strings.count, 213)
        XCTAssertFalse(strings.keys.contains { $0.hasPrefix("nav.") })
        XCTAssertNil(strings["Connected"])
        for key in CanonicalGlossaryFixture.keys {
            let entry = try XCTUnwrap(strings[key] as? [String: Any], "Missing \(key)")
            let locs = try XCTUnwrap(entry["localizations"] as? [String: Any])
            let enLoc = try XCTUnwrap(locs["en"] as? [String: Any])
            let viLoc = try XCTUnwrap(locs["vi"] as? [String: Any])
            let enUnit = try XCTUnwrap(enLoc["stringUnit"] as? [String: Any])
            let viUnit = try XCTUnwrap(viLoc["stringUnit"] as? [String: Any])
            let enValue = try XCTUnwrap(enUnit["value"] as? String)
            let viValue = try XCTUnwrap(viUnit["value"] as? String)
            XCTAssertFalse(enValue.isEmpty)
            XCTAssertFalse(viValue.isEmpty)
        }
    }
}
