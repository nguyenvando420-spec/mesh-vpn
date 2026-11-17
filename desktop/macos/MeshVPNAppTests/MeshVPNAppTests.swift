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
}
