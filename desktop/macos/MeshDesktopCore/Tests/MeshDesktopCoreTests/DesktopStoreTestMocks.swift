import Foundation
@testable import MeshDesktopCore
import os

struct MockServicePresenceChecker: ServicePresenceChecking {
    let installed: Bool
    func isServiceInstalled() -> Bool { installed }
}

@MainActor
final class MockLaunchAtLoginController: LaunchAtLoginControlling {
    var isEnabled: Bool = false
    func setEnabled(_ enabled: Bool) throws { isEnabled = enabled }
}

final class MockAdminPrivilegeExecutor: AdminPrivilegeExecuting {
    private let actions = OSAllocatedUnfairLock(initialState: [PrivilegedDaemonAction]())
    func execute(_ action: PrivilegedDaemonAction) async throws {
        actions.withLock { $0.append(action) }
    }
}

final class MockDesktopIpcTransport: DesktopIpcTransport {
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

@MainActor
enum DesktopStoreTestFixtures {
    static func makeValidPreauthKey() -> String {
        "mpk_" + Data((0..<32).map { UInt8($0) })
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func makeStore(
        transport: MockDesktopIpcTransport,
        cleaner: ClipboardAutoClear? = nil,
        pollInterval: TimeInterval = 5.0
    ) -> DesktopStore {
        let autoClear = cleaner ?? ClipboardAutoClear(
            pasteboard: InMemoryPasteboardProvider(),
            delaySeconds: 30
        )
        return DesktopStore(
            transport: transport,
            privilegeHelper: MockAdminPrivilegeExecutor(),
            clipboardAutoClear: autoClear,
            serviceChecker: MockServicePresenceChecker(installed: true),
            launchAtLogin: MockLaunchAtLoginController(),
            dashboardPollIntervalSeconds: pollInterval,
            idlePollIntervalSeconds: pollInterval
        )
    }

    static func makePinnedStatus(
        daemonState: DaemonState,
        endpoint: String,
        pin: String,
        controlConnected: Bool = false
    ) -> AgentStatusResponse {
        AgentStatusResponse(
            daemonState: daemonState,
            nodeId: "node-mac-1",
            nodeName: "macbook",
            serverConnection: ServerConnectionStatus(
                controlEndpoint: endpoint,
                tlsAuthMode: .spkiPin,
                activePin: pin,
                controlConnected: controlConnected
            )
        )
    }
}
