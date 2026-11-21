@testable import MeshApp
import MeshCoreKit
import SwiftUI
import XCTest

final class UnifiedUiFoundationTests: XCTestCase {
    private func makeIsolatedDefaults(suite: String) throws -> UserDefaults {
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        addTeardownBlock {
            defaults.removePersistentDomain(forName: suite)
        }
        return defaults
    }

    private func makePeer(
        nodeId: String,
        name: String,
        fqdn: String,
        overlayIp: String,
        online: Bool,
        activePath: MobileActivePathKind
    ) -> MobilePeerStatus {
        MobilePeerStatus(
            nodeId: nodeId,
            name: name,
            fqdn: fqdn,
            overlayIp: overlayIp,
            online: online,
            activePath: activePath,
            directEndpoint: activePath == .direct ? "203.0.113.5:51820" : nil,
            rttMs: online ? 12 : nil,
            lastHandshakeAtMs: nil,
            rxBytes: 100,
            txBytes: 200
        )
    }

    @MainActor
    func test_themeManager_persistsUnderMeshThemeModeKey() throws {
        // Arrange
        let suite = "dev.meshvpn.tests.theme.\(UUID().uuidString)"
        let defaults = try makeIsolatedDefaults(suite: suite)
        let manager = ThemeManager(userDefaults: defaults)

        // Act & Assert
        XCTAssertEqual(manager.themeMode, .system)
        XCTAssertNil(manager.preferredColorScheme)

        manager.setThemeMode(.dark)
        XCTAssertEqual(defaults.string(forKey: "mesh_theme_mode"), "dark")
        XCTAssertEqual(manager.preferredColorScheme, .dark)

        let reloaded = ThemeManager(userDefaults: defaults)
        XCTAssertEqual(reloaded.themeMode, .dark)

        defaults.set("corrupt_value", forKey: "mesh_theme_mode")
        let fallback = ThemeManager(userDefaults: defaults)
        XCTAssertEqual(fallback.themeMode, .system)
    }

    @MainActor
    func test_localeManager_persistsAndResolvesIos15CompatibleLocale() throws {
        // Arrange
        let suite = "dev.meshvpn.tests.locale.\(UUID().uuidString)"
        let defaults = try makeIsolatedDefaults(suite: suite)
        let manager = LocaleManager(userDefaults: defaults)

        // Act & Assert
        XCTAssertEqual(manager.localeMode, .system)

        manager.setLocaleMode(.vi)
        XCTAssertEqual(defaults.string(forKey: "mesh_locale_mode"), "vi")
        XCTAssertEqual(manager.resolvedLocale, Locale(identifier: "vi"))
        XCTAssertEqual(manager.resolvedLanguageCode, "vi")

        let reloaded = LocaleManager(userDefaults: defaults)
        XCTAssertEqual(reloaded.localeMode, .vi)

        manager.setLocaleMode(.en)
        XCTAssertEqual(manager.resolvedLocale, Locale(identifier: "en"))
        XCTAssertEqual(manager.resolvedLanguageCode, "en")
    }

    func test_statusBadge_mapsCanonicalSemanticColorsAndLabels() {
        // Arrange & Act
        let connected = StatusBadge.resolve(status: .connected, daemonState: .connected)
        let connecting = StatusBadge.resolve(status: .connecting, daemonState: .connecting)
        let degraded = StatusBadge.resolve(status: .connected, daemonState: .degraded)
        let reauth = StatusBadge.resolve(status: .disconnected, daemonState: .reauthRequired)
        let revoked = StatusBadge.resolve(status: .disconnected, daemonState: .revoked)
        let disconnected = StatusBadge.resolve(status: .disconnected, daemonState: .stopped)

        // Assert
        XCTAssertEqual(connected.tone, .success)
        XCTAssertEqual(connected.lightHex, "#16A34A")
        XCTAssertEqual(connected.darkHex, "#4ADE80")
        XCTAssertEqual(connected.label, "Connected")
        XCTAssertEqual(connected.localizationKey, "state.connected")

        XCTAssertEqual(connecting.tone, .warning)
        XCTAssertEqual(connecting.lightHex, "#D97706")
        XCTAssertEqual(connecting.darkHex, "#FBBF24")
        XCTAssertEqual(connecting.localizationKey, "state.connecting")

        XCTAssertEqual(degraded.tone, .warning)
        XCTAssertEqual(degraded.label, "Degraded")
        XCTAssertEqual(degraded.localizationKey, "state.degraded")

        XCTAssertEqual(reauth.tone, .warning)
        XCTAssertEqual(reauth.label, "Re-auth Required")
        XCTAssertEqual(reauth.localizationKey, "state.reauth_required")

        XCTAssertEqual(revoked.tone, .error)
        XCTAssertEqual(revoked.lightHex, "#DC2626")
        XCTAssertEqual(revoked.darkHex, "#F87171")
        XCTAssertEqual(revoked.label, "Device Revoked")
        XCTAssertEqual(revoked.localizationKey, "state.revoked")

        XCTAssertEqual(disconnected.tone, .neutral)
        XCTAssertEqual(disconnected.lightHex, "#6B7280")
        XCTAssertEqual(disconnected.darkHex, "#9CA3AF")
        XCTAssertEqual(disconnected.label, "Disconnected")
        XCTAssertEqual(disconnected.localizationKey, "state.disconnected")

        XCTAssertEqual(MeshDesignTokens.brandCobaltHex, "#0B57D0")
        XCTAssertEqual(MeshDesignTokens.brandSkyHex, "#60A5FA")
    }

    func test_peerFilter_countsAndFiltersByModeAndSearchFields() {
        // Arrange
        let peers = [
            makePeer(
                nodeId: "node-alpha-111",
                name: "macbook-pro",
                fqdn: "macbook-pro.mesh.internal",
                overlayIp: "100.64.0.10",
                online: true,
                activePath: .direct
            ),
            makePeer(
                nodeId: "node-beta-222",
                name: "vps-relay",
                fqdn: "vps-relay.mesh.internal",
                overlayIp: "100.64.0.20",
                online: true,
                activePath: .relay
            ),
            makePeer(
                nodeId: "node-gamma-333",
                name: "nas-backup",
                fqdn: "nas-backup.mesh.internal",
                overlayIp: "100.64.0.30",
                online: false,
                activePath: .none
            )
        ]

        // Act
        let counts = PeerFilter.counts(peers: peers)
        let direct = PeerFilter.filter(peers: peers, mode: .direct, query: "")
        let relay = PeerFilter.filter(peers: peers, mode: .relay, query: "")
        let byFqdn = PeerFilter.filter(peers: peers, mode: .all, query: "vps-relay.mesh")
        let byIp = PeerFilter.filter(peers: peers, mode: .online, query: "100.64.0.10")
        let byNodeId = PeerFilter.filter(peers: peers, mode: .all, query: "GAMMA-333")

        // Assert
        XCTAssertEqual(counts, PeerFilterCounts(all: 3, online: 2, direct: 1, relay: 1))
        XCTAssertEqual(direct.map(\.nodeId), ["node-alpha-111"])
        XCTAssertEqual(relay.map(\.nodeId), ["node-beta-222"])
        XCTAssertEqual(byFqdn.map(\.nodeId), ["node-beta-222"])
        XCTAssertEqual(byIp.map(\.nodeId), ["node-alpha-111"])
        XCTAssertEqual(byNodeId.map(\.nodeId), ["node-gamma-333"])
    }

    @MainActor
    func test_appViewModel_selectedTabAndCopyNonSecretAddress() throws {
        // Arrange
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MeshTabTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: tempDir) }

        let store = try CoordinatedAppGroupStore(rootDirectoryURL: tempDir)
        let viewModel = AppViewModel(
            appGroupStore: store,
            dekStore: KeychainDekStore(accessGroup: nil),
            tunnelManager: TunnelManagerClient()
        )

        // Act
        XCTAssertEqual(viewModel.selectedTab, .status)
        viewModel.selectedTab = .peers
        viewModel.copyNonSecretAddress("100.64.0.42")

        // Assert
        XCTAssertEqual(viewModel.selectedTab, .peers)
        XCTAssertNil(viewModel.clipboardClearTask)
    }

    func test_peersAdaptiveLayout_usesTwoColumnsForRegularAndOneForCompact() {
        // Arrange & Act & Assert (`US-138`)
        XCTAssertEqual(PeersAdaptiveLayout.columnCount(for: .regular), 2)
        XCTAssertEqual(PeersAdaptiveLayout.columnCount(for: .compact), 1)
        XCTAssertEqual(PeersAdaptiveLayout.columnCount(for: nil), 1)
    }
}
