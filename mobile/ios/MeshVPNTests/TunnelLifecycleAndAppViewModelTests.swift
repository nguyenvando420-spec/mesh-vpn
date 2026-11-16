@testable import MeshApp
import Darwin
import MeshCoreKit
import NetworkExtension
import XCTest

@MainActor
private final class MockVPNManagerHandle: VPNManagerHandling {
    enum Event: Equatable {
        case loadFromPreferences
        case setOnDemand(Bool)
        case saveToPreferences
        case removeFromPreferences
        case startTunnel
        case stopTunnel
    }

    var isEnabled = false
    private var backedOnDemand = false
    var isOnDemandEnabled: Bool {
        get { backedOnDemand }
        set {
            backedOnDemand = newValue
            events.append(.setOnDemand(newValue))
        }
    }
    var onDemandRules: [NEOnDemandRule]?
    var localizedDescription: String?
    var providerConfiguration: [String: Any]?
    var providerServerAddress: String?
    var connectionStatus: MeshTunnelConnectionStatus = .connected
    var events: [Event] = []

    func loadFromPreferences() async throws {
        events.append(.loadFromPreferences)
    }

    func saveToPreferences() async throws {
        events.append(.saveToPreferences)
    }

    func removeFromPreferences() async throws {
        events.append(.removeFromPreferences)
    }

    func startTunnel() throws {
        events.append(.startTunnel)
        connectionStatus = .connected
    }

    func stopTunnel() {
        events.append(.stopTunnel)
        connectionStatus = .disconnected
    }

    func sendProviderMessage(_ data: Data) async throws -> Data? {
        nil
    }
}

@MainActor
private final class MockVPNManagerStore: VPNManagerStoring {
    var managers: [VPNManagerHandling]

    init(managers: [VPNManagerHandling] = []) {
        self.managers = managers
    }

    func loadMeshManagers() async throws -> [VPNManagerHandling] {
        managers
    }

    func makeNewManager() -> VPNManagerHandling {
        let created = MockVPNManagerHandle()
        managers.append(created)
        return created
    }
}

private struct MockBiometricAuthorizer: BiometricAuthorizing, Sendable {
    let outcome: BiometricAuthOutcome

    func authorize(reason: String) async -> BiometricAuthOutcome {
        outcome
    }
}

private final class MockEnrollmentClient: EnrollmentClientProtocol, Sendable {
    let offlineExportCalls = LockedBox(0)
    let updateServerCalls = LockedBox(0)

    func parseJoinUri(_ rawUri: String) throws -> MobileParsedJoinUri {
        try MeshCoreKit.parseMobileJoinUri(rawUri: rawUri)
    }

    func createPendingJoinSession(_ rawPreauthKey: String) throws -> MobilePendingJoinSession {
        try MeshCoreKit.createPendingJoinSession(rawPreauthKey: rawPreauthKey)
    }

    func enrollOrRotateNode(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        enrollConfig: MobileEnrollConfig
    ) async throws -> MobileStatusSnapshot {
        sampleStatusSnapshot()
    }

    func updateServerConfig(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        setConfig: MobileSetConfig
    ) async throws -> MobileStatusSnapshot {
        updateServerCalls.withLock { $0 += 1 }
        return sampleStatusSnapshot()
    }

    func exportOfflineBugreport(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        destPath: String
    ) async throws -> MobileBugreportResult {
        offlineExportCalls.withLock { $0 += 1 }
        try Data("mock-tar".utf8).write(to: URL(fileURLWithPath: destPath))
        return MobileBugreportResult(bundlePath: destPath, sizeBytes: 8, scrubbedItems: 1)
    }

    private func sampleStatusSnapshot() -> MobileStatusSnapshot {
        MobileStatusSnapshot(
            daemonState: .stopped,
            nodeId: "n1",
            nodeName: "iphone",
            fqdn: nil,
            overlayIp: "100.64.0.2",
            overlayCidr: "100.64.0.0/16",
            overlayDnsIp: "100.64.255.254",
            tunInterfaceName: nil,
            tunMtu: 1280,
            netmapVersion: 1,
            keyExpiresAtMs: nil,
            serverConnection: nil,
            selfNetwork: MobileSelfNetworkStatus(
                localUdpPort: 0,
                boundPhysicalInterface: nil,
                natType: .unknown,
                overlayConflictWarning: nil,
                nat64ActivePrefix: nil,
                candidates: []
            ),
            peers: [],
            warnings: []
        )
    }
}

private final class MockPacketFlow: TunnelPacketFlowing, Sendable {
    let written = LockedBox<[(packets: [Data], protocols: [NSNumber])]>([])

    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {}

    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        written.withLock { $0.append((packets, protocols)) }
        return true
    }
}

final class TunnelLifecycleAndAppViewModelTests: XCTestCase {
    @MainActor
    func test_manualDisconnect_disablesOnDemandAndSavesBeforeStoppingTunnel() async throws {
        // Arrange
        let handle = MockVPNManagerHandle()
        handle.isEnabled = true
        handle.isOnDemandEnabled = true
        handle.onDemandRules = [NEOnDemandRuleConnect()]
        handle.events.removeAll()

        let client = TunnelManagerClient(store: MockVPNManagerStore(managers: [handle]))

        // Act
        let snapshot = try await client.disconnectManually()

        // Assert
        XCTAssertFalse(snapshot.isOnDemandEnabled)
        XCTAssertEqual(snapshot.status, .disconnected)
        XCTAssertEqual(
            handle.events,
            [.loadFromPreferences, .setOnDemand(false), .saveToPreferences, .stopTunnel]
        )
    }

    @MainActor
    func test_appViewModel_biometricCancelledBlocksServerUpdateAndBugreport() async throws {
        // Arrange
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MeshVMTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: tempDir) }

        let store = try CoordinatedAppGroupStore(rootDirectoryURL: tempDir)
        let enrollmentClient = MockEnrollmentClient()
        let viewModel = AppViewModel(
            appGroupStore: store,
            dekStore: KeychainDekStore(accessGroup: nil),
            tunnelManager: TunnelManagerClient(store: MockVPNManagerStore()),
            enrollmentClient: enrollmentClient,
            biometricAuthorizer: MockBiometricAuthorizer(outcome: .cancelled)
        )

        // Act
        await viewModel.updateServerEndpoint(
            endpoint: "new.example.com:443",
            tlsAuthMode: .spkiPin,
            serverPin: "sha256:00"
        )
        await viewModel.exportBugreport()

        // Assert
        XCTAssertEqual(enrollmentClient.updateServerCalls.read { $0 }, 0)
        XCTAssertEqual(enrollmentClient.offlineExportCalls.read { $0 }, 0)
        XCTAssertNil(viewModel.shareBugreportURL)
    }

    @MainActor
    func test_appViewModel_bugreportShareCompletionDeletesTempTarFile() async throws {
        // Arrange
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MeshShareTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: tempDir) }

        let store = try CoordinatedAppGroupStore(rootDirectoryURL: tempDir)
        let viewModel = AppViewModel(
            appGroupStore: store,
            dekStore: KeychainDekStore(accessGroup: nil),
            tunnelManager: TunnelManagerClient(store: MockVPNManagerStore()),
            enrollmentClient: MockEnrollmentClient(),
            biometricAuthorizer: MockBiometricAuthorizer(outcome: .authorized)
        )

        // Act
        await viewModel.exportBugreport()
        let exportedURL = try XCTUnwrap(viewModel.shareBugreportURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: exportedURL.path))
        viewModel.cleanupSharedBugreport(at: exportedURL)

        // Assert
        XCTAssertNil(viewModel.shareBugreportURL)
        XCTAssertFalse(FileManager.default.fileExists(atPath: exportedURL.path))
    }

    func test_underlayPathConverter_handlesWifiCellularNat64AndAirplaneMode() {
        // Arrange
        let wifi = UnderlayPathConverter.snapshot(
            isSatisfied: true,
            interfaces: [
                UnderlayInterfaceDescriptor(name: "utun3", index: 12, kind: .other),
                UnderlayInterfaceDescriptor(name: "en0", index: 5, kind: .wifi)
            ],
            supportsIpv4: true,
            supportsIpv6: true
        )
        let cellularIpv6Only = UnderlayPathConverter.snapshot(
            isSatisfied: true,
            interfaces: [
                UnderlayInterfaceDescriptor(name: "pdp_ip0", index: 8, kind: .cellular)
            ],
            supportsIpv4: false,
            supportsIpv6: true
        )
        let airplaneMode = UnderlayPathSnapshot.disconnected

        // Act & Assert
        XCTAssertEqual(wifi.activeInterfaceName, "en0")
        XCTAssertEqual(wifi.physicalIfIndex, 5)
        XCTAssertNil(wifi.osNat64Prefix)

        XCTAssertEqual(
            UnderlayPathConverter.classifyTransition(previous: wifi, current: cellularIpv6Only),
            .interfaceChanged
        )
        XCTAssertEqual(cellularIpv6Only.osNat64Prefix, "64:ff9b::/96")

        XCTAssertEqual(
            UnderlayPathConverter.classifyTransition(
                previous: cellularIpv6Only,
                current: airplaneMode
            ),
            .connectivityLost
        )
        XCTAssertEqual(
            UnderlayPathConverter.classifyTransition(previous: airplaneMode, current: wifi),
            .connectivityRestored
        )
    }

    func test_boundedPacketWriter_mapsAddressFamiliesAndDeliversToFlow() {
        // Arrange
        let ipv4Packet = Data([0x45, 0x00, 0x00, 0x14])
        let ipv6Packet = Data([0x60, 0x00, 0x00, 0x00])
        let burstWriter = BoundedPacketWriter(flow: nil)
        let delivered = expectation(description: "BoundedPacketWriter writes packets to flow")
        let mockFlow = MockPacketFlow()
        let flowWriter = BoundedPacketWriter(flow: mockFlow)

        // Act
        for _ in 0..<(BoundedPacketWriter.maxQueuedBatches + 25) {
            burstWriter.enqueue([ipv4Packet])
        }
        flowWriter.enqueue([ipv4Packet, ipv6Packet])
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.25) {
            if !mockFlow.written.read({ $0.isEmpty }) {
                delivered.fulfill()
            }
        }
        wait(for: [delivered], timeout: 2.0)

        // Assert
        XCTAssertEqual(
            BoundedPacketWriter.addressFamilyNumber(for: ipv4Packet),
            NSNumber(value: AF_INET)
        )
        XCTAssertEqual(
            BoundedPacketWriter.addressFamilyNumber(for: ipv6Packet),
            NSNumber(value: AF_INET6)
        )
        XCTAssertLessThanOrEqual(
            burstWriter.queuedBatchCount,
            BoundedPacketWriter.maxQueuedBatches
        )
        let writtenBatches = mockFlow.written.read { $0 }
        XCTAssertEqual(writtenBatches.first?.packets, [ipv4Packet, ipv6Packet])
        XCTAssertEqual(
            writtenBatches.first?.protocols,
            [NSNumber(value: AF_INET), NSNumber(value: AF_INET6)]
        )
    }
}
