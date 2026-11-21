import Foundation
import MeshDesktopCore
import XCTest

final class MeshVPNAppTests: XCTestCase {
    func testAppDefaultsAndMenuBarSymbols_MatchAuthoritativeMacOsContracts() {
        // Arrange & Act & Assert
        XCTAssertEqual(AgentDefaults.defaultControlTcpPort, 443)
        XCTAssertEqual(AgentDefaults.roSocketPath, "/var/run/meshd/meshd-ro.sock")
        XCTAssertEqual(AgentDefaults.adminSocketPath, "/var/run/meshd/meshd-admin.sock")
        XCTAssertEqual(AgentDefaults.daemonBinaryPath, "/usr/local/libexec/mesh/meshd")
        XCTAssertEqual(AgentDefaults.cliBinaryPath, "/usr/local/bin/mesh")
        XCTAssertEqual(AgentDefaults.launchdLabel, "internal.mesh.meshd")
        XCTAssertEqual(
            AgentDefaults.launchdPlistPath,
            "/Library/LaunchDaemons/internal.mesh.meshd.plist"
        )
        XCTAssertEqual(MenuBarStatusGroup.connected.symbolName, "checkmark.shield.fill")
        XCTAssertEqual(MenuBarStatusGroup.serviceOffline.symbolName, "shield.slash")
    }

    func testBundleResourcesIfPresent_EnforceNonSandboxedAndZeroArbitraryLoads() throws {
        // Arrange: Inspect app bundle Info.plist when executed via xcodebuild host app or fallback
        let candidates = [
            Bundle.main.bundleURL.appendingPathComponent("Contents/Info.plist"),
            Bundle(for: Self.self).bundleURL
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Info.plist")
        ]
        guard let infoURL = candidates.first(where: {
            FileManager.default.fileExists(atPath: $0.path)
        }),
              let dict = NSDictionary(contentsOf: infoURL) as? [String: Any]
        else {
            return
        }

        // Assert
        if dict["CFBundleIdentifier"] as? String == "dev.meshvpn.macos" {
            XCTAssertEqual(dict["LSUIElement"] as? Bool, true)
            XCTAssertNil(dict["CFBundleURLTypes"])
            let ats = dict["NSAppTransportSecurity"] as? [String: Any]
            XCTAssertNil(ats?["NSAllowsArbitraryLoads"])
        }
    }

    func testDesignTokens_CanonicalHexValues_MatchAdr030Specification() {
        // Arrange & Act & Assert
        XCTAssertEqual(MeshDesignTokens.surfaceBackgroundLight, "#F8FAFC")
        XCTAssertEqual(MeshDesignTokens.surfaceBackgroundDark, "#0F172A")
        XCTAssertEqual(MeshDesignTokens.brandCobalt, "#0B57D0")
        XCTAssertEqual(MeshDesignTokens.brandSky, "#60A5FA")
        XCTAssertEqual(MeshDesignTokens.brandTeal, "#0D9488")
        XCTAssertEqual(MeshDesignTokens.brandTealLight, "#2DD4BF")
        XCTAssertEqual(MeshDesignTokens.semanticWarningLight, "#D97706")
        XCTAssertEqual(MeshDesignTokens.semanticWarningDark, "#FBBF24")
        XCTAssertEqual(MeshDesignTokens.semanticErrorLight, "#DC2626")
        XCTAssertEqual(MeshDesignTokens.semanticErrorDark, "#F87171")
    }

    func testMenuBarAndTabVisibility_ReauthRequiredIsAmberAndShows3Tabs() {
        // Arrange
        let reauthState = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(daemonState: .reauthRequired, nodeId: "n1"),
            connectFailure: nil,
            lastActionError: nil
        )

        // Act
        let tabs = DesktopTabKind.visibleTabs(for: reauthState.uiState)

        // Assert
        XCTAssertEqual(reauthState.menuBarGroup, .reauthRequired)
        XCTAssertEqual(reauthState.menuBarGroup.lightHex, "#D97706")
        XCTAssertEqual(reauthState.menuBarGroup.darkHex, "#FBBF24")
        XCTAssertEqual(tabs, [.status, .peers, .diagnostics])
    }

    func testPeerFilter_NodeIdAndBadges_WorkWithThemeModePersistence() {
        // Arrange
        let suiteName = "MeshVPN.app.test.\(UUID().uuidString.prefix(8))"
        let defaults = UserDefaults(suiteName: suiteName)
        defer { defaults?.removePersistentDomain(forName: suiteName) }
        let peer = AgentPeerStatus(
            nodeId: "node-xyz-007",
            name: "workstation",
            fqdn: "workstation.mesh.internal",
            overlayIp: "100.64.0.15",
            online: true,
            activePath: .direct
        )

        // Act
        ThemeMode.dark.save(to: defaults)
        let matched = PeerDirectoryFilter.filter(peers: [peer], mode: .direct, query: "xyz-007")
        let counts = PeerDirectoryFilter.counts(for: [peer])

        // Assert
        XCTAssertEqual(ThemeMode.load(from: defaults), .dark)
        XCTAssertEqual(matched.count, 1)
        XCTAssertEqual(counts.direct, 1)
    }

    func testLocaleViTranslations_StateAndTrayAndTabs_ReturnCanonicalVietnameseStrings() {
        // Arrange
        let viLocale = Locale(identifier: "vi")

        // Act & Assert
        XCTAssertEqual(MeshL10n.tr("state.connected", locale: viLocale), "Đã kết nối")
        XCTAssertEqual(MeshL10n.tr("tray.connected", locale: viLocale), "Mesh VPN - Đã kết nối")
        XCTAssertEqual(DesktopTabKind.peers.localizedTitle(locale: viLocale), "Thiết bị cùng mạng")
        XCTAssertEqual(
            DesktopTabKind.diagnostics.localizedTitle(locale: viLocale),
            "Chẩn đoán & Cài đặt"
        )
    }

    func testLocaleMode_UserDefaultsKeyMeshLocaleMode_PersistsWithoutRestart() {
        // Arrange
        let suiteName = "MeshVPN.app.locale.\(UUID().uuidString.prefix(8))"
        let defaults = UserDefaults(suiteName: suiteName)
        defer { defaults?.removePersistentDomain(forName: suiteName) }

        // Act
        LocaleMode.vi.save(to: defaults)

        // Assert
        XCTAssertEqual(defaults?.string(forKey: "mesh_locale_mode"), "vi")
        XCTAssertEqual(LocaleMode.load(from: defaults), .vi)
        XCTAssertEqual(MeshL10n.tr("error.auth_failed", locale: Locale(identifier: "vi")),
                       "authentication failed")
    }
}
