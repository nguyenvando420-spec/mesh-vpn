import Darwin
import Foundation

/// Typed IPC client failures distinguishing OS ACL denial vs offline daemon (`DGUI-IPC-05`).
public enum IpcClientError: Error, Equatable, Sendable, LocalizedError {
    case serviceUnavailable(String)
    case permissionDenied(String)
    case timeout(String)
    case invalidResponse(String)
    case remoteError(statusCode: Int, envelope: ErrorEnvelope)
    case streamConstraintViolation(String)

    public var errorDescription: String? {
        switch self {
        case .serviceUnavailable(let msg):
            return msg
        case .permissionDenied(let msg):
            return msg
        case .timeout(let msg):
            return msg
        case .invalidResponse(let msg):
            return msg
        case .remoteError(_, let envelope):
            if envelope.kind == .unauthenticated {
                return "authentication failed"
            }
            return envelope.message
        case .streamConstraintViolation(let msg):
            return msg
        }
    }
}

/// Abstract async transport implemented by `UdsIpcClient` and mock test doubles (`Sendable`).
public protocol DesktopIpcTransport: Sendable {
    func fetchStatus(socketPath: String) async throws -> IpcResponseWithMeta<AgentStatusResponse>
    func fetchPeers(socketPath: String) async throws -> IpcResponseWithMeta<AgentStatusResponse>
    func fetchVersion(socketPath: String) async throws -> AgentVersionResponse
    func runNetcheck(socketPath: String) async throws -> NetcheckResponse
    func pingPeer(socketPath: String, request: PingRequest) async throws -> PingResponse
    func bringUp(socketPath: String, request: AgentUpRequest) async throws -> AgentActionResponse
    func bringDown(socketPath: String) async throws -> AgentActionResponse
    func cleanup(socketPath: String) async throws -> AgentActionResponse
    func updateServer(
        socketPath: String,
        request: AgentSetRequest
    ) async throws -> AgentActionResponse
    func rotateKey(
        socketPath: String,
        request: AgentRotateKeyRequest
    ) async throws -> AgentActionResponse
    func resetIdentity(socketPath: String) async throws -> AgentActionResponse
    func streamBugreport(
        socketPath: String,
        onChunk: @escaping @Sendable (Data) throws -> Void
    ) async throws -> StreamedBugreportMetadata
    func probeOfflineDaemonVersion(binaryPath: String) async -> AgentVersionStatus?
}

/// HTTP/1.1-over-Unix-Domain-Socket client enforcing 3-tier timeouts (`ADR-023`, `ADR-024`).
public actor UdsIpcClient: DesktopIpcTransport {
    private let ioQueue = DispatchQueue(
        label: "dev.meshvpn.macos.uds-ipc",
        qos: .userInitiated,
        attributes: .concurrent
    )
    private let connectTimeoutSeconds: TimeInterval
    private let roQueryTimeoutSeconds: TimeInterval
    private let netcheckTimeoutSeconds: TimeInterval
    private let adminMutationTimeoutSeconds: TimeInterval
    private let streamChunkIdleTimeoutSeconds: TimeInterval

    public init(
        connectTimeoutSeconds: TimeInterval = AgentDefaults.ipcConnectTimeoutSeconds,
        roQueryTimeoutSeconds: TimeInterval = AgentDefaults.ipcRoQueryTimeoutSeconds,
        netcheckTimeoutSeconds: TimeInterval = AgentDefaults.ipcNetcheckTimeoutSeconds,
        adminMutationTimeoutSeconds: TimeInterval = AgentDefaults.ipcAdminMutationTimeoutSeconds,
        streamChunkIdleTimeoutSeconds: TimeInterval =
            AgentDefaults.ipcStreamChunkIdleTimeoutSeconds
    ) {
        self.connectTimeoutSeconds = connectTimeoutSeconds
        self.roQueryTimeoutSeconds = roQueryTimeoutSeconds
        self.netcheckTimeoutSeconds = netcheckTimeoutSeconds
        self.adminMutationTimeoutSeconds = adminMutationTimeoutSeconds
        self.streamChunkIdleTimeoutSeconds = streamChunkIdleTimeoutSeconds
    }

    public static func pingTimeoutSeconds(
        count: UInt16,
        perProbeTimeoutMs: UInt64
    ) -> TimeInterval {
        let probes = Double(max(count, 1))
        let totalSec = (probes * Double(perProbeTimeoutMs) / 1000.0) + 2.0
        return min(totalSec, AgentDefaults.ipcMaxPingTimeoutSeconds)
    }

    public static func classifyVersionProbe(
        headerVersion: String?,
        endpointResult: Result<AgentVersionResponse, Error>
    ) throws -> AgentVersionStatus {
        if let header = headerVersion?.trimmingCharacters(in: .whitespacesAndNewlines),
           !header.isEmpty {
            return .version(header)
        }
        switch endpointResult {
        case .success(let resp):
            let trimmed = resp.agentVersion.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? .legacyPre030 : .version(trimmed)
        case .failure(let error):
            if let ipcErr = error as? IpcClientError,
               case .remoteError(let code, let env) = ipcErr,
               code == 404 || env.kind == .notFound {
                return .legacyPre030
            }
            throw error
        }
    }

    public static func classifyCliVersionExitCode(
        exitCode: Int32,
        stdout: String
    ) -> AgentVersionStatus? {
        if exitCode == 0 {
            let token = stdout
                .split(whereSeparator: { $0.isWhitespace })
                .last
                .map(String.init) ?? ""
            return token.isEmpty ? .legacyPre030 : .version(token)
        }
        if exitCode == 2 {
            return .legacyPre030
        }
        return nil
    }

    public func fetchStatus(
        socketPath: String = AgentDefaults.roSocketPath
    ) async throws -> IpcResponseWithMeta<AgentStatusResponse> {
        try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "GET",
            path: "/v1/agent/status",
            bodyData: nil,
            responseTimeoutSeconds: roQueryTimeoutSeconds
        )
    }

    public func fetchPeers(
        socketPath: String = AgentDefaults.roSocketPath
    ) async throws -> IpcResponseWithMeta<AgentStatusResponse> {
        try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "GET",
            path: "/v1/agent/peers",
            bodyData: nil,
            responseTimeoutSeconds: roQueryTimeoutSeconds
        )
    }

    public func fetchVersion(
        socketPath: String = AgentDefaults.roSocketPath
    ) async throws -> AgentVersionResponse {
        let resp: IpcResponseWithMeta<AgentVersionResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "GET",
            path: "/v1/agent/version",
            bodyData: nil,
            responseTimeoutSeconds: roQueryTimeoutSeconds
        )
        return resp.value
    }

    public func runNetcheck(
        socketPath: String = AgentDefaults.roSocketPath
    ) async throws -> NetcheckResponse {
        let emptyObj = Data("{}".utf8)
        let resp: IpcResponseWithMeta<NetcheckResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/netcheck",
            bodyData: emptyObj,
            responseTimeoutSeconds: netcheckTimeoutSeconds
        )
        return resp.value
    }

    public func pingPeer(
        socketPath: String = AgentDefaults.roSocketPath,
        request: PingRequest
    ) async throws -> PingResponse {
        let body = try JSONEncoder().encode(request)
        let timeout = Self.pingTimeoutSeconds(
            count: request.count,
            perProbeTimeoutMs: request.timeoutMs
        )
        let resp: IpcResponseWithMeta<PingResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/ping",
            bodyData: body,
            responseTimeoutSeconds: timeout
        )
        return resp.value
    }

    public func bringUp(
        socketPath: String = AgentDefaults.adminSocketPath,
        request: AgentUpRequest
    ) async throws -> AgentActionResponse {
        let body = try JSONEncoder().encode(request)
        let resp: IpcResponseWithMeta<AgentActionResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/up",
            bodyData: body,
            responseTimeoutSeconds: adminMutationTimeoutSeconds
        )
        return resp.value
    }

    public func bringDown(
        socketPath: String = AgentDefaults.adminSocketPath
    ) async throws -> AgentActionResponse {
        let resp: IpcResponseWithMeta<AgentActionResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/down",
            bodyData: Data("{}".utf8),
            responseTimeoutSeconds: adminMutationTimeoutSeconds
        )
        return resp.value
    }

    public func cleanup(
        socketPath: String = AgentDefaults.adminSocketPath
    ) async throws -> AgentActionResponse {
        let resp: IpcResponseWithMeta<AgentActionResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/cleanup",
            bodyData: Data("{}".utf8),
            responseTimeoutSeconds: adminMutationTimeoutSeconds
        )
        return resp.value
    }

    public func updateServer(
        socketPath: String = AgentDefaults.adminSocketPath,
        request: AgentSetRequest
    ) async throws -> AgentActionResponse {
        let body = try JSONEncoder().encode(request)
        let resp: IpcResponseWithMeta<AgentActionResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/set",
            bodyData: body,
            responseTimeoutSeconds: adminMutationTimeoutSeconds
        )
        return resp.value
    }

    public func rotateKey(
        socketPath: String = AgentDefaults.adminSocketPath,
        request: AgentRotateKeyRequest
    ) async throws -> AgentActionResponse {
        let body = try JSONEncoder().encode(request)
        let resp: IpcResponseWithMeta<AgentActionResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/rotate-key",
            bodyData: body,
            responseTimeoutSeconds: adminMutationTimeoutSeconds
        )
        return resp.value
    }

    public func resetIdentity(
        socketPath: String = AgentDefaults.adminSocketPath
    ) async throws -> AgentActionResponse {
        let body = try JSONEncoder().encode(AgentResetIdentityRequest())
        let resp: IpcResponseWithMeta<AgentActionResponse> = try await sendJsonWithMeta(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/reset-identity",
            bodyData: body,
            responseTimeoutSeconds: adminMutationTimeoutSeconds
        )
        return resp.value
    }

    public func streamBugreport(
        socketPath: String = AgentDefaults.adminSocketPath,
        onChunk: @escaping @Sendable (Data) throws -> Void
    ) async throws -> StreamedBugreportMetadata {
        let timeouts = StreamTimeoutConfig(
            connectTimeout: connectTimeoutSeconds,
            totalTimeout: adminMutationTimeoutSeconds,
            chunkIdleTimeout: streamChunkIdleTimeoutSeconds
        )
        let spec = UdsStreamRequestSpec(
            socketPath: socketPath,
            method: "POST",
            path: "/v1/agent/bugreport/stream",
            bodyData: Data("{}".utf8),
            timeouts: timeouts
        )
        return try await withCheckedThrowingContinuation { continuation in
            ioQueue.async {
                do {
                    let meta = try PosixUdsHttpTransport.executeStream(spec, onChunk: onChunk)
                    continuation.resume(returning: meta)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func probeOfflineDaemonVersion(
        binaryPath: String = AgentDefaults.daemonBinaryPath
    ) async -> AgentVersionStatus? {
        await withCheckedContinuation { continuation in
            ioQueue.async {
                let result = Self.runSecureVersionProbe(binaryPath: binaryPath)
                continuation.resume(returning: result)
            }
        }
    }

    private func sendJsonWithMeta<Resp: Decodable & Sendable>(
        socketPath: String,
        method: String,
        path: String,
        bodyData: Data?,
        responseTimeoutSeconds: TimeInterval
    ) async throws -> IpcResponseWithMeta<Resp> {
        let spec = UdsJsonRequestSpec(
            socketPath: socketPath,
            method: method,
            path: path,
            bodyData: bodyData,
            connectTimeout: connectTimeoutSeconds,
            responseTimeout: responseTimeoutSeconds
        )
        return try await withCheckedThrowingContinuation { continuation in
            ioQueue.async {
                do {
                    let raw = try PosixUdsHttpTransport.executeJson(spec)
                    let decoded = try JSONDecoder().decode(Resp.self, from: raw.body)
                    continuation.resume(
                        returning: IpcResponseWithMeta(
                            value: decoded,
                            agentVersionHeader: raw.agentVersionHeader,
                            statusCode: raw.statusCode
                        )
                    )
                } catch let ipcErr as IpcClientError {
                    continuation.resume(throwing: ipcErr)
                } catch {
                    continuation.resume(
                        throwing: IpcClientError.invalidResponse(
                            "Malformed IPC JSON response: \(error.localizedDescription)"
                        )
                    )
                }
            }
        }
    }

    private static func runSecureVersionProbe(binaryPath: String) -> AgentVersionStatus? {
        var fileStat = stat()
        guard lstat(binaryPath, &fileStat) == 0 else { return nil }
        let fileType = fileStat.st_mode & S_IFMT
        guard fileType == S_IFREG, (fileStat.st_mode & 0o022) == 0 else {
            return nil
        }

        let process = Process()
        let outPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        process.arguments = ["--version"]
        process.standardOutput = outPipe
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return nil
        }
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let stdout = String(data: data, encoding: .utf8) ?? ""
        return classifyCliVersionExitCode(exitCode: process.terminationStatus, stdout: stdout)
    }
}
