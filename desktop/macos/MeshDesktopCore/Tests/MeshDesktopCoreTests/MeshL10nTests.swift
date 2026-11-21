import Foundation
@testable import MeshDesktopCore
import XCTest

final class MeshL10nTests: XCTestCase {
    func testMeshL10n_All213CanonicalKeys_ExistAndAreNonEmptyInEnAndVi() throws {
        // Arrange
        XCTAssertEqual(MeshL10n.canonicalKeys.count, 213)
        XCTAssertEqual(Set(MeshL10n.canonicalKeys).count, 213)
        let enTable = try XCTUnwrap(MeshL10n.stringsTable(forLanguage: "en"))
        let viTable = try XCTUnwrap(MeshL10n.stringsTable(forLanguage: "vi"))
        let enLocale = Locale(identifier: "en")
        let viLocale = Locale(identifier: "vi")

        // Act & Assert
        XCTAssertEqual(enTable.count, 213)
        XCTAssertEqual(viTable.count, 213)
        for key in MeshL10n.canonicalKeys {
            let enVal = MeshL10n.tr(key, locale: enLocale)
            let viVal = MeshL10n.tr(key, locale: viLocale)
            XCTAssertNotNil(enTable[key], "Missing EN key: \(key)")
            XCTAssertNotNil(viTable[key], "Missing VI key: \(key)")
            XCTAssertFalse(enVal.isEmpty, "Empty EN value for \(key)")
            XCTAssertFalse(viVal.isEmpty, "Empty VI value for \(key)")
            XCTAssertEqual(enVal, enTable[key])
            XCTAssertEqual(viVal, viTable[key])
        }
    }

    func testMeshL10n_StateConnectedAndSubStates_ReturnCanonicalEnAndVi() {
        // Arrange
        let enLocale = Locale(identifier: "en")
        let viLocale = Locale(identifier: "vi")

        // Act & Assert
        XCTAssertEqual(MeshL10n.tr("state.connected", locale: viLocale), "Đã kết nối")
        XCTAssertEqual(MeshL10n.tr("state.connected", locale: enLocale), "Connected")
        XCTAssertEqual(
            DesktopUiState.connected.resolvedTitle(
                isDegradedTunnel: false,
                isManuallyDisconnected: false,
                locale: viLocale
            ),
            "Đã kết nối"
        )
        XCTAssertEqual(
            DesktopUiState.connected.resolvedTitle(
                isDegradedTunnel: true,
                isManuallyDisconnected: false,
                locale: viLocale
            ),
            "Suy giảm"
        )
        XCTAssertEqual(
            DesktopUiState.connected.resolvedTitle(
                isDegradedTunnel: false,
                isManuallyDisconnected: true,
                locale: viLocale
            ),
            "Đã ngắt kết nối"
        )
        XCTAssertEqual(DesktopTabKind.status.localizedTitle(locale: viLocale), "Trạng thái")
        XCTAssertEqual(PeerFilterMode.direct.localizedLabel(locale: viLocale), "Trực tiếp")
        XCTAssertEqual(ThemeMode.dark.localizedLabel(locale: viLocale), "Tối")
    }

    func testMeshL10n_Sec05AuthFailed_RemainsEnglishInBothLocales() {
        // Arrange
        let enLocale = Locale(identifier: "en")
        let viLocale = Locale(identifier: "vi")

        // Act
        let enAuth = MeshL10n.tr("error.auth_failed", locale: enLocale)
        let viAuth = MeshL10n.tr("error.auth_failed", locale: viLocale)

        // Assert
        XCTAssertEqual(enAuth, "authentication failed")
        XCTAssertEqual(viAuth, "authentication failed")
    }

    func testLocaleMode_UserDefaultsPersistence_UsesSuiteMeshVPNAndKeyMeshLocaleMode() {
        // Arrange
        let suiteName = "MeshVPN.locale.test.\(UUID().uuidString.prefix(8))"
        let defaults = UserDefaults(suiteName: suiteName)
        defer { defaults?.removePersistentDomain(forName: suiteName) }

        // Act & Assert
        XCTAssertEqual(LocaleMode.userDefaultsSuiteName, "MeshVPN")
        XCTAssertEqual(LocaleMode.userDefaultsKey, "mesh_locale_mode")
        XCTAssertEqual(LocaleMode.load(from: defaults), .system)

        LocaleMode.vi.save(to: defaults)
        XCTAssertEqual(defaults?.string(forKey: "mesh_locale_mode"), "vi")
        XCTAssertEqual(LocaleMode.load(from: defaults), .vi)
        XCTAssertEqual(LocaleMode.vi.effectiveLocale, Locale(identifier: "vi"))

        LocaleMode.en.save(to: defaults)
        XCTAssertEqual(LocaleMode.load(from: defaults), .en)
        XCTAssertEqual(LocaleMode.en.effectiveLocale, Locale(identifier: "en"))

        defaults?.set("invalid_locale", forKey: "mesh_locale_mode")
        XCTAssertEqual(LocaleMode.load(from: defaults), .system)
    }

    func testMeshL10n_DefaultLocalizationEn_LoadsFallbackAndTrayLabels() {
        // Arrange
        let fallbackLocale = Locale(identifier: "fr")
        let viLocale = Locale(identifier: "vi")

        // Act & Assert
        XCTAssertEqual(MeshL10n.tr("tab.status", locale: fallbackLocale), "Status")
        XCTAssertEqual(MeshL10n.tr("tray.connected", locale: viLocale), "Mesh VPN - Đã kết nối")
        XCTAssertEqual(
            MeshL10n.tr("tray.reauth", locale: viLocale),
            "Mesh VPN - Yêu cầu xác thực lại"
        )
    }
}
