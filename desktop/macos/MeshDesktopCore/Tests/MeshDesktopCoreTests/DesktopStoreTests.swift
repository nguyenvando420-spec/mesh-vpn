import Foundation
@testable import MeshDesktopCore
import os
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
        let serviceChecker = MockServicePresenceChecker(installed: true)
        let pasteboard = InMemoryPasteboardProvider()
        let cleaner = ClipboardAutoClear(pasteboard: pasteboard, delaySeconds: 30)
        let store = DesktopStore(
            transport: transport,
            privilegeHelper: MockAdminPrivilegeExecutor(),
            clipboardAutoClear: cleaner,
            serviceChecker: serviceChecker,
            launchAtLogin: MockLaunchAtLoginController()
        )

        let validKey = "mpk_" + Data((0..<32).map { UInt8($0) })
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
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
        let store = DesktopStore(
            transport: transport,
            privilegeHelper: MockAdminPrivilegeExecutor(),
            serviceChecker: MockServicePresenceChecker(installed: true),
            launchAtLogin: MockLaunchAtLoginController(),
            dashboardPollIntervalSeconds: 0.03,
            idlePollIntervalSeconds: 0.03
        )
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
        let store = DesktopStore(
            transport: transport,
            privilegeHelper: MockAdminPrivilegeExecutor(),
            serviceChecker: MockServicePresenceChecker(installed: true),
            launchAtLogin: MockLaunchAtLoginController()
        )

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
        let store = DesktopStore(
            transport: transport,
            privilegeHelper: MockAdminPrivilegeExecutor(),
            clipboardAutoClear: cleaner,
            serviceChecker: MockServicePresenceChecker(installed: true),
            launchAtLogin: MockLaunchAtLoginController()
        )
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
        let store = DesktopStore(
            transport: transport,
            privilegeHelper: MockAdminPrivilegeExecutor(),
            serviceChecker: MockServicePresenceChecker(installed: true),
            launchAtLogin: MockLaunchAtLoginController()
        )
        let validKey = "mpk_" + Data((0..<32).map { UInt8($0) })
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let manualInput = ManualOnboardingInput(
            rawEndpoint: "ctrl.example.com",
            tlsAuthMode: .systemCa,
            rawPreauthKey: validKey,
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

    func testDesktopStore_MultiCycleUriEnrollDisconnectAndOneClickReconnect_PreservesIdentityAndEndpoint() async {
        // Arrange
        let transport = MockDesktopIpcTransport()
        let pasteboard = InMemoryPasteboardProvider()
        let cleaner = ClipboardAutoClear(pasteboard: pasteboard, delaySeconds: 30)
        let store = DesktopStore(
            transport: transport,
            privilegeHelper: MockAdminPrivilegeExecutor(),
            clipboardAutoClear: cleaner,
            serviceChecker: MockServicePresenceChecker(installed: true),
            launchAtLogin: MockLaunchAtLoginController()
        )
        let validKey = "mpk_" + Data((0..<32).map { UInt8($0) })
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let pin = "sha256:" + String(repeating: "ef", count: 32)
        let joinUri = "mesh://join?v=1&ep=203.0.113.55:8443&pin=\(pin)&key=\(validKey)"

        // Act 1: URI enrollment -> connected
        let draft = store.handlePastedOnboardingInput(joinUri)
        XCTAssertNotNil(draft)
        let enrolled = await store.confirmEnrollmentDraft()
        XCTAssertTrue(enrolled)
        transport.setState(
            AgentStatusResponse(
                daemonState: .connected,
                nodeId: "node-mac-1",
                nodeName: "macbook",
                serverConnection: ServerConnectionStatus(
                    controlEndpoint: "203.0.113.55:8443",
                    tlsAuthMode: .spkiPin,
                    activePin: pin,
                    controlConnected: true
                )
            )
        )
        await store.refreshNow()
        XCTAssertEqual(store.uiState, .connected)
        XCTAssertFalse(store.isManuallyDisconnected)

        // Act 2: Disconnect -> manually stopped -> 1st 1-click Connect -> connected
        let down1 = await store.disconnect()
        XCTAssertTrue(down1)
        transport.setState(
            AgentStatusResponse(
                daemonState: .stopped,
                nodeId: "node-mac-1",
                nodeName: "macbook",
                serverConnection: ServerConnectionStatus(
                    controlEndpoint: "203.0.113.55:8443",
                    tlsAuthMode: .spkiPin,
                    activePin: pin
                )
            )
        )
        await store.refreshNow()
        XCTAssertTrue(store.isManuallyDisconnected)

        let up1 = await store.connectOneClick()
        XCTAssertTrue(up1)
        transport.setState(
            AgentStatusResponse(
                daemonState: .connected,
                nodeId: "node-mac-1",
                nodeName: "macbook",
                serverConnection: ServerConnectionStatus(
                    controlEndpoint: "203.0.113.55:8443",
                    tlsAuthMode: .spkiPin,
                    activePin: pin,
                    controlConnected: true
                )
            )
        )
        await store.refreshNow()
        XCTAssertEqual(store.uiState, .connected)
        XCTAssertFalse(store.isManuallyDisconnected)

        // Act 3: 2nd Disconnect -> 2nd 1-click Connect -> connected
        let down2 = await store.disconnect()
        XCTAssertTrue(down2)
        transport.setState(
            AgentStatusResponse(
                daemonState: .stopped,
                nodeId: "node-mac-1",
                nodeName: "macbook",
                serverConnection: ServerConnectionStatus(
                    controlEndpoint: "203.0.113.55:8443",
                    tlsAuthMode: .spkiPin,
                    activePin: pin
                )
            )
        )
        await store.refreshNow()
        XCTAssertTrue(store.isManuallyDisconnected)

        let up2 = await store.connectOneClick()
        XCTAssertTrue(up2)
        transport.setState(
            AgentStatusResponse(
                daemonState: .connected,
                nodeId: "node-mac-1",
                nodeName: "macbook",
                serverConnection: ServerConnectionStatus(
                    controlEndpoint: "203.0.113.55:8443",
                    tlsAuthMode: .spkiPin,
                    activePin: pin,
                    controlConnected: true
                )
            )
        )
        await store.refreshNow()

        // Assert
        XCTAssertEqual(store.uiState, .connected)
        XCTAssertEqual(transport.bringDownCount, 2)
        XCTAssertEqual(transport.bringUpRequests.count, 3)
        XCTAssertEqual(transport.bringUpRequests[0].preauthKey, validKey)
        XCTAssertNil(transport.bringUpRequests[1].preauthKey)
        XCTAssertEqual(transport.bringUpRequests[1].serverEndpoint, "203.0.113.55:8443")
        XCTAssertEqual(transport.bringUpRequests[1].serverPin, pin)
        XCTAssertNil(transport.bringUpRequests[2].preauthKey)
        XCTAssertEqual(transport.bringUpRequests[2].serverEndpoint, "203.0.113.55:8443")
        XCTAssertEqual(transport.bringUpRequests[2].serverPin, pin)
    }
}

private struct MockServicePresenceChecker: ServicePresenceChecking {
    let installed: Bool
    func isServiceInstalled() -> Bool { installed }
}

@MainActor
private final class MockLaunchAtLoginController: LaunchAtLoginControlling {
    var isEnabled: Bool = false
    func setEnabled(_ enabled: Bool) throws { isEnabled = enabled }
}

private final class MockAdminPrivilegeExecutor: AdminPrivilegeExecuting {
    private let actions = OSAllocatedUnfairLock(initialState: [PrivilegedDaemonAction]())
    func execute(_ action: PrivilegedDaemonAction) async throws {
        actions.withLock { $0.append(action) }
    }
}

private final class MockDesktopIpcTransport: DesktopIpcTransport {
    private struct State: Sendable {
        var status = AgentStatusResponse(daemonState: .stopped)
        var version = AgentVersionResponse(
            agentVersion: "0.3.0",
            protocolVersion: 1,
            binaryName: "meshd"
        )
        var fetchCount: Int = 0
        var lastUp: AgentUpRequest?
        var upRequests: [AgentUpRequest] = []
        var resetCalled = false
        var downCalled = false
        var downCount: Int = 0
        var legacy404 = false
        var upError: Error?
        var streamDelayNs: UInt64 = 0
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    var fetchStatusCount: Int { state.withLock { $0.fetchCount } }
    var lastUpRequest: AgentUpRequest? { state.withLock { $0.lastUp } }
    var bringUpRequests: [AgentUpRequest] { state.withLock { $0.upRequests } }
    var didCallResetIdentity: Bool { state.withLock { $0.resetCalled } }
    var didCallBringDown: Bool { state.withLock { $0.downCalled } }
    var bringDownCount: Int { state.withLock { $0.downCount } }
    var simulateLegacy404Version: Bool {
        get { state.withLock { $0.legacy404 } }
        set { state.withLock { $0.legacy404 = newValue } }
    }
    var nextUpError: Error? {
        get { state.withLock { $0.upError } }
        set { state.withLock { $0.upError = newValue } }
    }
    var streamDelayNs: UInt64 {
        get { state.withLock { $0.streamDelayNs } }
        set { state.withLock { $0.streamDelayNs = newValue } }
    }

    func setState(_ newStatus: AgentStatusResponse) {
        state.withLock { $0.status = newStatus }
    }

    func fetchStatus(socketPath: String) async throws -> IpcResponseWithMeta<AgentStatusResponse> {
        state.withLock { current in
            current.fetchCount += 1
            let header: String? = current.legacy404 ? nil : "0.3.0"
            return IpcResponseWithMeta(
                value: current.status,
                agentVersionHeader: header,
                statusCode: 200
            )
        }
    }

    func fetchPeers(socketPath: String) async throws -> IpcResponseWithMeta<AgentStatusResponse> {
        try await fetchStatus(socketPath: socketPath)
    }

    func fetchVersion(socketPath: String) async throws -> AgentVersionResponse {
        try state.withLock { current in
            if current.legacy404 {
                throw IpcClientError.remoteError(
                    statusCode: 404,
                    envelope: ErrorEnvelope(
                        kind: .notFound,
                        code: "E_NOT_FOUND",
                        message: "missing",
                        requestId: "1"
                    )
                )
            }
            return current.version
        }
    }

    func runNetcheck(socketPath: String) async throws -> NetcheckResponse {
        NetcheckResponse(udpEgressOk: true, stunReachable: true)
    }

    func pingPeer(socketPath: String, request: PingRequest) async throws -> PingResponse {
        PingResponse(targetName: request.target, targetOverlayIp: request.target)
    }

    func bringUp(socketPath: String, request: AgentUpRequest) async throws -> AgentActionResponse {
        try state.withLock { current in
            if let err = current.upError {
                current.upError = nil
                throw err
            }
            current.lastUp = request
            current.upRequests.append(request)
            return AgentActionResponse(state: .connecting, message: "ok")
        }
    }

    func bringDown(socketPath: String) async throws -> AgentActionResponse {
        state.withLock {
            $0.downCalled = true
            $0.downCount += 1
        }
        return AgentActionResponse(state: .stopped, message: "ok")
    }

    func cleanup(socketPath: String) async throws -> AgentActionResponse {
        AgentActionResponse(state: .stopped, message: "ok")
    }

    func updateServer(
        socketPath: String,
        request: AgentSetRequest
    ) async throws -> AgentActionResponse {
        AgentActionResponse(state: .stopped, message: "ok")
    }

    func rotateKey(
        socketPath: String,
        request: AgentRotateKeyRequest
    ) async throws -> AgentActionResponse {
        if let err = state.withLock({ $0.upError }) {
            state.withLock { $0.upError = nil }
            throw err
        }
        return AgentActionResponse(state: .connecting, message: "ok")
    }

    func resetIdentity(socketPath: String) async throws -> AgentActionResponse {
        state.withLock { $0.resetCalled = true }
        return AgentActionResponse(state: .stopped, message: "ok")
    }

    func streamBugreport(
        socketPath: String,
        onChunk: @escaping @Sendable (Data) throws -> Void
    ) async throws -> StreamedBugreportMetadata {
        let delay = state.withLock { $0.streamDelayNs }
        if delay > 0 {
            try await Task.sleep(nanoseconds: delay)
        }
        let body = Data("TAR_BYTES".utf8)
        try onChunk(body)
        return StreamedBugreportMetadata(
            totalBytes: UInt64(body.count),
            scrubbedItems: 1,
            agentVersion: "0.3.0"
        )
    }

    func probeOfflineDaemonVersion(binaryPath: String) async -> AgentVersionStatus? {
        .version("0.3.0")
    }
}
