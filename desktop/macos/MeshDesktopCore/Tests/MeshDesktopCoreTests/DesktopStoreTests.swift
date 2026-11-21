import Foundation
@testable import MeshDesktopCore
import XCTest

@MainActor
final class DesktopStoreTests: XCTestCase {
    func testDesktopStateMapper_OfflineAndUnconfiguredStates_MapsDeterministically() {
        // Arrange & Act & Assert
        XCTAssertEqual(
            DesktopStateMapper.compute(
                serviceFilesPresent: false,
                statusResponse: nil,
                connectFailure: .serviceUnavailable("off"),
                lastActionError: nil
            ).uiState,
            .serviceNotInstalled
        )
        XCTAssertEqual(
            DesktopStateMapper.compute(
                serviceFilesPresent: true,
                statusResponse: nil,
                connectFailure: .serviceUnavailable("off"),
                lastActionError: nil
            ).uiState,
            .serviceStopped
        )
        XCTAssertEqual(
            DesktopStateMapper.compute(
                serviceFilesPresent: true,
                statusResponse: nil,
                connectFailure: .permissionDenied("eacces"),
                lastActionError: nil
            ).uiState,
            .error
        )
        XCTAssertEqual(
            DesktopStateMapper.compute(
                serviceFilesPresent: true,
                statusResponse: AgentStatusResponse(daemonState: .stopped),
                connectFailure: nil,
                lastActionError: nil
            ).uiState,
            .unconfigured
        )
    }

    func testDesktopStateMapper_ActiveAndLifecycleStates_MapsDeterministically() {
        // Arrange
        let baseConn = ServerConnectionStatus(controlEndpoint: "ctrl.example.com:443")

        // Act & Assert
        XCTAssertEqual(
            DesktopStateMapper.compute(
                serviceFilesPresent: true,
                statusResponse: AgentStatusResponse(
                    daemonState: .connecting,
                    nodeId: "n1",
                    serverConnection: baseConn
                ),
                connectFailure: nil,
                lastActionError: nil
            ).uiState,
            .connecting
        )
        let degraded = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .degraded,
                nodeId: "n1",
                serverConnection: baseConn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        XCTAssertEqual(degraded.uiState, .connected)
        XCTAssertTrue(degraded.isDegradedTunnel)
        XCTAssertEqual(degraded.menuBarGroup, .connectingOrDegraded)

        let manualStop = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .stopped,
                nodeId: "n1",
                serverConnection: baseConn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        XCTAssertEqual(manualStop.uiState, .connected)
        XCTAssertTrue(manualStop.isManuallyDisconnected)
        XCTAssertEqual(manualStop.menuBarGroup, .disconnected)

        XCTAssertEqual(
            DesktopStateMapper.compute(
                serviceFilesPresent: true,
                statusResponse: AgentStatusResponse(daemonState: .reauthRequired, nodeId: "n1"),
                connectFailure: nil,
                lastActionError: nil
            ).uiState,
            .reauthRequired
        )
        XCTAssertEqual(
            DesktopStateMapper.compute(
                serviceFilesPresent: true,
                statusResponse: AgentStatusResponse(daemonState: .revoked, nodeId: "n1"),
                connectFailure: nil,
                lastActionError: nil
            ).uiState,
            .revoked
        )
    }

    func testDesktopStore_OnboardingAndOneClickConnect_WipesSecretsAndSendsExpectedIpc() async {
        // Arrange
        let transport = MockDesktopIpcTransport()
        let pasteboard = InMemoryPasteboardProvider()
        let cleaner = ClipboardAutoClear(pasteboard: pasteboard, delaySeconds: 30)
        let store = DesktopStoreTestFixtures.makeStore(transport: transport, cleaner: cleaner)
        let validKey = DesktopStoreTestFixtures.makeValidPreauthKey()
        let pin = "sha256:" + String(repeating: "cd", count: 32)
        let joinUri = "mesh://join?v=1&ep=ctrl.example.com:443&pin=\(pin)&key=\(validKey)"
        pasteboard.setStringContent(joinUri)

        // Act 1: Onboarding draft + confirm
        let draft = store.handlePastedOnboardingInput(joinUri)
        XCTAssertNotNil(draft)
        XCTAssertTrue(cleaner.hasPendingWipe)
        let enrolled = await store.confirmEnrollmentDraft()

        // Assert 1: preauthKey sent cleanly & clipboard wiped immediately
        XCTAssertTrue(enrolled)
        XCTAssertNil(pasteboard.stringContent())
        XCTAssertNil(store.pendingEnrollmentDraft)
        XCTAssertEqual(transport.lastUpRequest?.preauthKey, validKey)

        // Act 2: Manual stopped with saved identity -> 1-Click Connect sends preauthKey == nil
        transport.setState(
            AgentStatusResponse(
                daemonState: .stopped,
                nodeId: "node-1",
                nodeName: "mac",
                serverConnection: ServerConnectionStatus(
                    controlEndpoint: "ctrl.example.com:443",
                    tlsAuthMode: .spkiPin,
                    activePin: pin
                )
            )
        )
        await store.refreshNow()
        XCTAssertTrue(store.isManuallyDisconnected)
        let reconnected = await store.connectOneClick()

        // Assert 2
        XCTAssertTrue(reconnected)
        XCTAssertNil(transport.lastUpRequest?.preauthKey)
        XCTAssertEqual(transport.lastUpRequest?.serverPin, pin)
    }

    func testDesktopStore_PollingSuspensionDuringBugreport_SkipsPolls() async throws {
        // Arrange
        let tempDir = URL(fileURLWithPath: "/tmp/mesh-store-test-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let dest = tempDir.appendingPathComponent("out.tar")

        let transport = MockDesktopIpcTransport()
        transport.streamDelayNs = 150_000_000
        let store = DesktopStoreTestFixtures.makeStore(transport: transport, pollInterval: 0.03)
        store.startMonitoring()
        defer { store.stopMonitoring() }
        try await Task.sleep(nanoseconds: 80_000_000)

        // Act: Begin export AFTER destination is decided -> polling suspends while streaming
        let exportTask = Task { await store.exportBugreport(to: dest) }
        try await Task.sleep(nanoseconds: 40_000_000)
        let suspendedDuringStream = store.isPollingSuspended
        let countDuringStart = transport.fetchStatusCount
        try await Task.sleep(nanoseconds: 80_000_000)
        let countMidStream = transport.fetchStatusCount
        let exported = await exportTask.value

        // Assert
        XCTAssertTrue(suspendedDuringStream)
        XCTAssertFalse(store.isPollingSuspended)
        XCTAssertEqual(countDuringStart, countMidStream)
        XCTAssertNotNil(exported)
        XCTAssertEqual(try Data(contentsOf: dest), Data("TAR_BYTES".utf8))
    }

    func testDesktopStore_LegacyPre030AndSecretsCanary_TriggersBannerAndRedactsSecrets() async {
        // Arrange
        let transport = MockDesktopIpcTransport()
        transport.simulateLegacy404Version = true
        transport.nextUpError = IpcClientError.remoteError(
            statusCode: 401,
            envelope: ErrorEnvelope(
                kind: .unauthenticated,
                code: "E_UNAUTHENTICATED",
                message: "leaked mpk_SUPERSECRETTOKEN99999999999999",
                requestId: "r1"
            )
        )
        let store = DesktopStoreTestFixtures.makeStore(transport: transport)

        // Act
        await store.refreshNow()
        let canaryKey = "mpk_CANARYTOKENMUSTNEVERLEAK1234567890ABCDEF1234"
        _ = store.prepareKeyRotationDraft(rawPreauthKey: canaryKey)
        let errText = MeshSecretScrubber.scrub(
            "mesh://join?v=1&ep=ctrl.example.com:443&pin=system-ca&key=\(canaryKey)"
        )
        _ = await store.confirmEnrollmentDraft()

        // Assert
        XCTAssertEqual(store.versionBanner, .legacyPre030)
        XCTAssertTrue(store.versionBanner.requiresUpdateBanner)
        XCTAssertEqual(store.lastActionError?.message, "authentication failed")
        XCTAssertFalse(errText.contains(canaryKey))
        XCTAssertFalse(MeshSecretScrubber.containsSecretPattern(errText))
    }

    func testDesktopStore_RevokedAndQuitPaths_ClearsClipboard() async {
        // Arrange
        let transport = MockDesktopIpcTransport()
        let pasteboard = InMemoryPasteboardProvider()
        let cleaner = ClipboardAutoClear(pasteboard: pasteboard, delaySeconds: 30)
        let store = DesktopStoreTestFixtures.makeStore(transport: transport, cleaner: cleaner)
        pasteboard.setStringContent("mpk_sensitive_secret")
        cleaner.recordAndScheduleWipe(text: "mpk_sensitive_secret")

        // Act
        _ = await store.resetIdentity()
        await store.disconnectAndPrepareForQuit()

        // Assert
        XCTAssertTrue(transport.didCallResetIdentity)
        XCTAssertTrue(transport.didCallBringDown)
        XCTAssertNil(pasteboard.stringContent())
    }

    func testDesktopStore_StartOrRepairServiceAndManualInput_RefreshesStatusAfterResume() async {
        // Arrange
        let transport = MockDesktopIpcTransport()
        transport.setState(
            AgentStatusResponse(
                daemonState: .connected,
                nodeId: "n-live",
                serverConnection: ServerConnectionStatus(controlEndpoint: "ctrl.example.com:443")
            )
        )
        let store = DesktopStoreTestFixtures.makeStore(transport: transport)
        let manualInput = ManualOnboardingInput(
            rawEndpoint: "ctrl.example.com",
            tlsAuthMode: .systemCa,
            rawPreauthKey: DesktopStoreTestFixtures.makeValidPreauthKey(),
            rawNodeName: "mac-manual"
        )

        // Act
        let draft = store.prepareDraftFromManualForm(manualInput)
        let started = await store.startOrRepairService()

        // Assert
        XCTAssertEqual(draft?.serverEndpoint, "ctrl.example.com:443")
        XCTAssertTrue(started)
        XCTAssertEqual(transport.fetchStatusCount, 1)
        XCTAssertEqual(store.uiState, .connected)
        XCTAssertFalse(store.isPollingSuspended)
    }
}
