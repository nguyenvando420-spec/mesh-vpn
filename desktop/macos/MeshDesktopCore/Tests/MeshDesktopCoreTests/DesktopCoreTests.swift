import CryptoKit
import Foundation
@testable import MeshDesktopCore
import XCTest

final class DesktopCoreTests: XCTestCase {
    func testEndpointNormalizer_BareHostnamesAndIps_FillsDefaultPort443() throws {
        // Arrange & Act
        let domain = try EndpointNormalizer.normalize("ctrl.example.com")
        let ipv4 = try EndpointNormalizer.normalize("203.0.113.10")
        let ipv6 = try EndpointNormalizer.normalize("2001:db8::1")
        let custom = try EndpointNormalizer.normalize("ctrl.example.com", portOverride: 8_443)
        let explicit = try EndpointNormalizer.normalize("203.0.113.10:9443")

        // Assert
        XCTAssertEqual(domain.endpoint, "ctrl.example.com:443")
        XCTAssertFalse(domain.isIpLiteral)
        XCTAssertEqual(ipv4.endpoint, "203.0.113.10:443")
        XCTAssertTrue(ipv4.isIpLiteral)
        XCTAssertEqual(ipv6.endpoint, "[2001:db8::1]:443")
        XCTAssertTrue(ipv6.isIpLiteral)
        XCTAssertEqual(custom.endpoint, "ctrl.example.com:8443")
        XCTAssertEqual(explicit.endpoint, "203.0.113.10:9443")
    }

    func testEndpointNormalizer_InvalidNumericTldAndPorts_ThrowsValidationError() {
        // Arrange
        let invalidInputs = [
            "999.999.999.999",
            "https://ctrl.example.com",
            "ctrl.example.com/path",
            "ctrl.example.com:0443",
            "ctrl.example.com:0",
            "ctrl.example.com:65536",
            "ctrl.example.com;rm -rf /",
            ""
        ]

        // Act & Assert
        for candidate in invalidInputs {
            XCTAssertThrowsError(try EndpointNormalizer.normalize(candidate), candidate)
        }
    }

    func testEndpointNormalizer_ZeroTofuPolicy_BlocksSystemCaOnIpv4AndIpv6Literals() throws {
        // Arrange
        let validPin = "sha256:" + String(repeating: "ab", count: 32)

        // Act & Assert
        XCTAssertThrowsError(
            try EndpointNormalizer.validateDesktopTlsPolicy(
                rawEndpoint: "203.0.113.10",
                portOverride: nil,
                tlsAuthMode: .systemCa,
                rawServerPin: nil
            )
        )
        XCTAssertThrowsError(
            try EndpointNormalizer.validateDesktopTlsPolicy(
                rawEndpoint: "2001:db8::1",
                portOverride: nil,
                tlsAuthMode: .systemCa,
                rawServerPin: nil
            )
        )
        let ipv6Pinned = try EndpointNormalizer.validateDesktopTlsPolicy(
            rawEndpoint: "2001:db8::1",
            portOverride: nil,
            tlsAuthMode: .spkiPin,
            rawServerPin: validPin.uppercased()
        )
        XCTAssertEqual(ipv6Pinned.normalized.endpoint, "[2001:db8::1]:443")
        XCTAssertEqual(ipv6Pinned.serverPin, validPin)
    }

    func testJoinUriParser_ValidAndInvalidPayloads_MatchesRustParity() throws {
        // Arrange
        let secretBytes = Data((0..<32).map { UInt8($0) })
        let validKey = "mpk_" + base64UrlNoPadEncode(secretBytes)
        let validPin = "sha256:" + String(repeating: "01", count: 32)
        let uri = "mesh://join?v=1&ep=ctrl.example.com:443&pin=\(validPin)&key=\(validKey)"
            + "&name=Mac-Node-01"

        // Act
        let parsed = try JoinUriParser.parse(uri)

        // Assert
        XCTAssertEqual(parsed.controlEndpoint, "ctrl.example.com:443")
        XCTAssertEqual(parsed.tlsAuthMode, .spkiPin)
        XCTAssertEqual(parsed.serverPin, validPin)
        XCTAssertEqual(parsed.nodeName, "mac-node-01")
        XCTAssertEqual(parsed.unsafeRawPreauthKey(), validKey)
        XCTAssertFalse(parsed.description.contains(validKey))
        XCTAssertThrowsError(
            try JoinUriParser.parse(
                "mesh://join?v=1&ep=192.0.2.5:443&pin=system-ca&key=\(validKey)"
            )
        )
        XCTAssertThrowsError(
            try JoinUriParser.parse(
                "mesh://join?v=1&ep=ctrl.example.com:443&pin=\(validPin)&key=mpk_short"
            )
        )
        XCTAssertThrowsError(try JoinUriParser.validateNodeName("localhost"))
        XCTAssertThrowsError(try JoinUriParser.validateNodeName("-bad"))
    }

    func testAgentIpcModels_GoldenJsonDecoding_DecodesExact13FieldsAndVersion() throws {
        // Arrange
        let json = """
        { "daemon_state": "connected",
          "node_id": "node-123",
          "node_name": "macbook-pro",
          "fqdn": "macbook-pro.mesh.internal",
          "overlay_ip": "100.64.0.10",
          "overlay_cidr": "100.64.0.0/16",
          "tun_interface_name": "utun4",
          "tun_mtu": 1280,
          "netmap_version": 42,
          "key_expires_at_ms": 1800000000000,
          "server_connection": {
            "control_endpoint": "ctrl.example.com:443",
            "relay_endpoint": "relay.example.com:443",
            "stun_endpoints": ["stun.example.com:3478"],
            "tls_auth_mode": "spki_pin",
            "active_pin": "sha256:\(String(repeating: "aa", count: 32))",
            "next_pin": null,
            "control_connected": true,
            "relay_connected": true,
            "relay_rtt_ms": 18,
            "migration_pending_endpoint": null,
            "last_error": null
          },
          "self_network": {
            "local_udp_port": 51820,
            "bound_physical_interface": "en0",
            "nat_type": "eim_or_adm",
            "nat_classification_note": "Cone NAT",
            "overlay_conflict_warning": null,
            "macos_firewall_warning": null,
            "candidates": [{"addr": "203.0.113.5:51820", "source": "reflexive"}]
          },
          "peers": []
        }
        """

        // Act
        let status = try JSONDecoder().decode(AgentStatusResponse.self, from: Data(json.utf8))
        let versionData = Data(
            #"{"agent_version":"0.3.0","protocol_version":1,"binary_name":"meshd"}"#.utf8
        )
        let version = try JSONDecoder().decode(AgentVersionResponse.self, from: versionData)

        // Assert
        XCTAssertEqual(status.daemonState, .connected)
        XCTAssertEqual(status.tunInterfaceName, "utun4")
        XCTAssertEqual(status.netmapVersion, 42)
        XCTAssertEqual(status.selfNetwork.boundPhysicalInterface, "en0")
        XCTAssertEqual(version.agentVersion, "0.3.0")
        XCTAssertEqual(version.protocolVersion, 1)
        XCTAssertEqual(version.binaryName, "meshd")
    }

    @MainActor
    func testClipboardAutoClear_MatchingAndModifiedClipboard_WipesConditionally() async throws {
        // Arrange
        let fakePasteboard = InMemoryPasteboardProvider()
        let cleaner = ClipboardAutoClear(pasteboard: fakePasteboard, delaySeconds: 0.05)
        let secretUri = "mesh://join?v=1&ep=ctrl.example.com:443&pin=system-ca&key=mpk_test123"

        // Act 1: Same changeCount + SHA256 -> clears after delay
        fakePasteboard.setStringContent(secretUri)
        cleaner.recordAndScheduleWipe(text: secretUri)
        XCTAssertTrue(cleaner.hasPendingWipe)
        try await waitUntilWipeCompletes(cleaner)

        // Assert 1
        XCTAssertNil(fakePasteboard.stringContent())
        XCTAssertFalse(cleaner.hasPendingWipe)

        // Act 2: User copies newer item before timer fires -> preserved!
        fakePasteboard.setStringContent(secretUri)
        cleaner.scheduleWipeIfClipboardMatchesFieldText(secretUri)
        fakePasteboard.setStringContent("unrelated user text")
        try await waitUntilWipeCompletes(cleaner)

        // Assert 2
        XCTAssertEqual(fakePasteboard.stringContent(), "unrelated user text")
    }

    @MainActor
    func testClipboardAutoClear_TrailingNewlineFromTerminal_ArmsAndWipes() async throws {
        // Arrange: Simulate copying a token with trailing newline and Cmd+V into SecureField
        let fakePasteboard = InMemoryPasteboardProvider()
        let cleaner = ClipboardAutoClear(pasteboard: fakePasteboard, delaySeconds: 0.05)
        let rawToken = "mpk_QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE"
        fakePasteboard.setStringContent("\(rawToken)\n")

        // Act
        cleaner.scheduleWipeIfClipboardMatchesFieldText(rawToken)
        XCTAssertTrue(cleaner.hasPendingWipe)
        try await waitUntilWipeCompletes(cleaner)

        // Assert
        XCTAssertNil(fakePasteboard.stringContent())
        XCTAssertFalse(cleaner.hasPendingWipe)
    }

    func testTabVisibility_AllEnrolledAndNonEnrolledStates_ReturnsExpectedTabs() {
        // Arrange
        let enrolledStates: [DesktopUiState] = [
            .connecting, .connected, .reauthRequired, .revoked, .error
        ]
        let nonEnrolledStates: [DesktopUiState] = [
            .serviceNotInstalled, .serviceStopped, .unconfigured
        ]

        // Act & Assert
        for state in enrolledStates {
            XCTAssertTrue(state.isEnrolledState, "\(state.rawValue) must be enrolled")
            XCTAssertEqual(
                DesktopTabKind.visibleTabs(for: state),
                [.status, .peers, .diagnostics]
            )
        }
        for state in nonEnrolledStates {
            XCTAssertFalse(state.isEnrolledState, "\(state.rawValue) must not be enrolled")
            XCTAssertTrue(DesktopTabKind.visibleTabs(for: state).isEmpty)
        }
    }

    func testPeerDirectoryFilter_NodeIdSearchAndCountBadges_MatchesAndCountsAccurately() {
        // Arrange
        let peers = [
            AgentPeerStatus(
                nodeId: "node-alpha-9981",
                name: "laptop",
                fqdn: "laptop.mesh.internal",
                overlayIp: "100.64.0.2",
                online: true,
                activePath: .direct
            ),
            AgentPeerStatus(
                nodeId: "node-beta-4420",
                name: "server",
                fqdn: "server.mesh.internal",
                overlayIp: "100.64.0.3",
                online: true,
                activePath: .relay
            ),
            AgentPeerStatus(
                nodeId: "node-gamma-7711",
                name: "nas",
                fqdn: "nas.mesh.internal",
                overlayIp: "100.64.0.4",
                online: false,
                activePath: .none
            )
        ]

        // Act
        let counts = PeerDirectoryFilter.counts(for: peers)
        let byNodeId = PeerDirectoryFilter.filter(peers: peers, mode: .all, query: "BETA-4420")
        let directOnly = PeerDirectoryFilter.filter(peers: peers, mode: .direct, query: "")
        let relayNodeId = PeerDirectoryFilter.filter(peers: peers, mode: .relay, query: "4420")

        // Assert
        XCTAssertEqual(counts, PeerFilterCounts(all: 3, online: 2, direct: 1, relay: 1))
        XCTAssertEqual(counts.count(for: .all), 3)
        XCTAssertEqual(counts.count(for: .online), 2)
        XCTAssertEqual(counts.count(for: .direct), 1)
        XCTAssertEqual(counts.count(for: .relay), 1)
        XCTAssertEqual(byNodeId.map(\.nodeId), ["node-beta-4420"])
        XCTAssertEqual(directOnly.map(\.nodeId), ["node-alpha-9981"])
        XCTAssertEqual(relayNodeId.map(\.nodeId), ["node-beta-4420"])
    }

    func testThemeMode_UserDefaultsPersistence_UsesSuiteMeshVPNAndKeyMeshThemeMode() {
        // Arrange
        let suiteName = "MeshVPN.test.\(UUID().uuidString.prefix(8))"
        let defaults = UserDefaults(suiteName: suiteName)
        defer { defaults?.removePersistentDomain(forName: suiteName) }

        // Act & Assert
        XCTAssertEqual(ThemeMode.userDefaultsSuiteName, "MeshVPN")
        XCTAssertEqual(ThemeMode.userDefaultsKey, "mesh_theme_mode")
        XCTAssertEqual(ThemeMode.load(from: defaults), .system)

        ThemeMode.dark.save(to: defaults)
        XCTAssertEqual(defaults?.string(forKey: "mesh_theme_mode"), "dark")
        XCTAssertEqual(ThemeMode.load(from: defaults), .dark)

        ThemeMode.light.save(to: defaults)
        XCTAssertEqual(ThemeMode.load(from: defaults), .light)

        defaults?.set("invalid_mode", forKey: "mesh_theme_mode")
        XCTAssertEqual(ThemeMode.load(from: defaults), .system)
    }

    @MainActor
    private func waitUntilWipeCompletes(
        _ cleaner: ClipboardAutoClear,
        maxAttempts: Int = 120
    ) async throws {
        for _ in 0..<maxAttempts {
            if !cleaner.hasPendingWipe {
                return
            }
            try await Task.sleep(nanoseconds: 25_000_000)
        }
    }

    private func base64UrlNoPadEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

@MainActor
final class InMemoryPasteboardProvider: PasteboardProviding {
    private var currentValue: String?
    private(set) var changeCount: Int = 0

    func stringContent() -> String? {
        currentValue
    }

    func setStringContent(_ value: String) {
        currentValue = value
        changeCount += 1
    }

    func clearContents() {
        currentValue = nil
        changeCount += 1
    }
}
