import Darwin
import Foundation
@testable import MeshDesktopCore
import os
import XCTest

final class UdsIpcAndBugreportTests: XCTestCase {
    func testUdsIpcClient_50PeersAndChunkedResponse_ParsesHeadersAndPayload() async throws {
        // Arrange
        let tempDir = try makeShortTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let socketPath = tempDir.appendingPathComponent("ro.sock").path
        let payloadData = try makeStatusJsonData(peerCount: 50)
        XCTAssertGreaterThan(payloadData.count, 4_096)

        let server = try TestUnixHttpServer(socketPath: socketPath) { requestPath in
            if requestPath == "/v1/agent/status" {
                return .json(
                    statusCode: 200,
                    headers: ["X-Mesh-Agent-Version": "0.3.0"],
                    body: payloadData,
                    chunked: true
                )
            }
            let errJson = """
            {"error":{"kind":"not_found","code":"E_NOT_FOUND","message":"no","request_id":"1"}}
            """
            return .json(
                statusCode: 404,
                headers: [:],
                body: Data(errJson.utf8)
            )
        }
        defer { server.stop() }
        let client = UdsIpcClient(
            connectTimeoutSeconds: 0.85,
            roQueryTimeoutSeconds: 2.0
        )

        // Act
        let statusMeta = try await client.fetchStatus(socketPath: socketPath)
        let versionProbeResult: Result<AgentVersionResponse, Error>
        do {
            versionProbeResult = .success(try await client.fetchVersion(socketPath: socketPath))
        } catch {
            versionProbeResult = .failure(error)
        }
        let legacyStatus = try UdsIpcClient.classifyVersionProbe(
            headerVersion: nil,
            endpointResult: versionProbeResult
        )

        // Assert
        XCTAssertEqual(statusMeta.value.peers.count, 50)
        XCTAssertEqual(statusMeta.agentVersionHeader, "0.3.0")
        XCTAssertEqual(legacyStatus, .legacyPre030)
        XCTAssertEqual(
            UdsIpcClient.classifyCliVersionExitCode(exitCode: 2, stdout: ""),
            .legacyPre030
        )
        XCTAssertEqual(
            UdsIpcClient.classifyCliVersionExitCode(exitCode: 0, stdout: "meshd 0.3.0\n"),
            .version("0.3.0")
        )
    }

    func testUdsIpcClient_OfflineAndPermissionDenied_MapsDistinctErrors() async throws {
        // Arrange
        let tempDir = try makeShortTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let missingPath = tempDir.appendingPathComponent("missing.sock").path
        let client = UdsIpcClient(connectTimeoutSeconds: 0.5, roQueryTimeoutSeconds: 1.0)

        // Act & Assert offline
        do {
            _ = try await client.fetchStatus(socketPath: missingPath)
            XCTFail("Expected serviceUnavailable")
        } catch let error as IpcClientError {
            guard case .serviceUnavailable = error else {
                XCTFail("Unexpected IPC error: \(error)")
                return
            }
        }

        // Act & Assert EACCES when non-root
        if Darwin.geteuid() != 0 {
            let lockedDir = tempDir.appendingPathComponent("locked")
            try FileManager.default.createDirectory(
                at: lockedDir,
                withIntermediateDirectories: true
            )
            let deniedSock = lockedDir.appendingPathComponent("admin.sock").path
            let server = try TestUnixHttpServer(socketPath: deniedSock) { _ in
                .json(statusCode: 200, headers: [:], body: Data("{}".utf8))
            }
            defer {
                chmod(lockedDir.path, 0o755)
                server.stop()
            }
            XCTAssertEqual(chmod(deniedSock, 0o000), 0)
            do {
                _ = try await client.bringDown(socketPath: deniedSock)
                XCTFail("Expected permissionDenied on 0000 socket")
            } catch let error as IpcClientError {
                guard case .permissionDenied = error else {
                    XCTFail("Expected permissionDenied, got \(error)")
                    return
                }
            }
        }
    }

    func testBugreportStreamWriter_AtomicPartCommit_PreservesPriorArchive() async throws {
        // Arrange
        let tempDir = try makeShortTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let sockPath = tempDir.appendingPathComponent("admin.sock").path
        let destURL = tempDir.appendingPathComponent("diag.tar")
        try Data("PRIOR_VALID_ARCHIVE".utf8).write(to: destURL)

        let tarBody = Data(repeating: 0x5A, count: 140_000)
        let server = try TestUnixHttpServer(socketPath: sockPath) { _ in
            .stream(statusCode: 200, archiveBytes: tarBody.count, scrubbed: 3, body: tarBody)
        }
        defer { server.stop() }
        let client = UdsIpcClient()

        let freshDestURL = tempDir.appendingPathComponent("brand-new.tar")
        XCTAssertFalse(FileManager.default.fileExists(atPath: freshDestURL.path))

        // Act 0: Atomic commit succeeds when destination .tar does not exist yet (Darwin.rename)
        let freshResult = try await BugreportStreamWriter.exportStream(
            transport: client,
            adminSocketPath: sockPath,
            destinationURL: freshDestURL
        )

        // Assert 0
        XCTAssertEqual(freshResult.totalBytes, UInt64(tarBody.count))
        XCTAssertEqual(try Data(contentsOf: freshDestURL), tarBody)
        let freshFiles = try FileManager.default.contentsOfDirectory(atPath: tempDir.path)
        XCTAssertFalse(freshFiles.contains { $0.contains(".part") })

        // Act 1: Atomic commit overwrites existing file cleanly without leaving .part
        let result = try await BugreportStreamWriter.exportStream(
            transport: client,
            adminSocketPath: sockPath,
            destinationURL: destURL
        )

        // Assert 1
        XCTAssertEqual(result.totalBytes, UInt64(tarBody.count))
        XCTAssertEqual(result.scrubbedItems, 3)
        XCTAssertEqual(try Data(contentsOf: destURL), tarBody)
        let files = try FileManager.default.contentsOfDirectory(atPath: tempDir.path)
        XCTAssertFalse(files.contains { $0.contains(".part") })

        // Act 2: Truncated stream leaves destination intact & removes .part
        let failingTransport = TruncatingStreamMockTransport()
        do {
            _ = try await BugreportStreamWriter.exportStream(
                transport: failingTransport,
                adminSocketPath: sockPath,
                destinationURL: destURL
            )
            XCTFail("Expected stream failure")
        } catch {
            // Expected failure
        }

        // Assert 2
        XCTAssertEqual(try Data(contentsOf: destURL), tarBody)
        let filesAfterFail = try FileManager.default.contentsOfDirectory(atPath: tempDir.path)
        XCTAssertFalse(filesAfterFail.contains { $0.contains(".part") })
    }

    func testBugreportStreamWriter_UnsafeDestinations_RejectsSymlinksAndSystemDirs() throws {
        // Arrange
        let tempDir = try makeShortTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let regularFile = tempDir.appendingPathComponent("target.tar")
        try Data("x".utf8).write(to: regularFile)
        let symlinkDest = tempDir.appendingPathComponent("link.tar")
        try FileManager.default.createSymbolicLink(at: symlinkDest, withDestinationURL: regularFile)

        // Act & Assert
        XCTAssertThrowsError(
            try BugreportStreamWriter.validateDestination(
                URL(fileURLWithPath: "/var/db/mesh/evil.tar")
            )
        )
        XCTAssertThrowsError(try BugreportStreamWriter.validateDestination(symlinkDest))
    }

    func testAdminPrivilegeHelper_FiniteEnum_RejectsControlCharsAndQuotesPathSafely() throws {
        // Arrange
        let badHelper = AdminPrivilegeHelper { URL(fileURLWithPath: "/tmp/bad\npath/Resources") }
        let tempRes = try makeShortTempDir()
        defer { try? FileManager.default.removeItem(at: tempRes) }
        try "#!/bin/sh\n".write(
            to: tempRes.appendingPathComponent("install-macos.sh"),
            atomically: true,
            encoding: .utf8
        )
        let goodHelper = AdminPrivilegeHelper { tempRes }

        // Act & Assert
        XCTAssertThrowsError(
            try badHelper.buildAppleScript(for: .installOrUpdateService(firewallOptIn: true))
        )
        let kickstartScript = try goodHelper.buildAppleScript(for: .kickstartDaemon)
        let installScript = try goodHelper.buildAppleScript(
            for: .installOrUpdateService(firewallOptIn: true)
        )
        let uninstallKeepScript = try goodHelper.buildShellCommand(
            for: .uninstallService(purgeData: false),
            bundleResourceURL: tempRes
        )
        let uninstallPurgeScript = try goodHelper.buildShellCommand(
            for: .uninstallService(purgeData: true),
            bundleResourceURL: tempRes
        )
        XCTAssertTrue(kickstartScript.contains("with administrator privileges"))
        XCTAssertTrue(kickstartScript.contains(AgentDefaults.launchdLabel))
        XCTAssertTrue(installScript.contains("--yes-firewall"))
        XCTAssertTrue(uninstallKeepScript.contains("--uninstall --keep-app"))
        XCTAssertFalse(uninstallKeepScript.contains("--purge"))
        XCTAssertTrue(uninstallPurgeScript.contains("--uninstall --keep-app --purge"))
    }

    private func makeShortTempDir() throws -> URL {
        let shortName = "m-\(UUID().uuidString.prefix(8))"
        let dir = URL(fileURLWithPath: "/tmp", isDirectory: true).appendingPathComponent(shortName)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func makeStatusJsonData(peerCount: Int) throws -> Data {
        let peers = (0..<peerCount).map { idx in
            AgentPeerStatus(
                nodeId: "node-\(idx)",
                name: "peer-\(idx)",
                fqdn: "peer-\(idx).mesh.internal",
                overlayIp: "100.64.1.\(idx + 1)",
                online: idx.isMultiple(of: 2),
                activePath: idx.isMultiple(of: 2) ? .direct : .none
            )
        }
        let status = AgentStatusResponse(
            daemonState: .connected,
            nodeId: "self-node",
            nodeName: "mac-local",
            fqdn: "mac-local.mesh.internal",
            overlayIp: "100.64.0.1",
            overlayCidr: "100.64.0.0/16",
            tunInterfaceName: "utun5",
            peers: peers
        )
        return try JSONEncoder().encode(status)
    }
}

private struct TestHttpReply: Sendable {
    let statusCode: Int
    let headers: [String: String]
    let body: Data
    let chunked: Bool

    static func json(
        statusCode: Int,
        headers: [String: String],
        body: Data,
        chunked: Bool = false
    ) -> TestHttpReply {
        TestHttpReply(statusCode: statusCode, headers: headers, body: body, chunked: chunked)
    }

    static func stream(
        statusCode: Int,
        archiveBytes: Int,
        scrubbed: Int,
        body: Data
    ) -> TestHttpReply {
        TestHttpReply(
            statusCode: statusCode,
            headers: [
                "X-Mesh-Archive-Bytes": "\(archiveBytes)",
                "X-Mesh-Scrubbed-Items": "\(scrubbed)",
                "X-Mesh-Agent-Version": "0.3.0"
            ],
            body: body,
            chunked: false
        )
    }
}

private final class TestUnixHttpServer: Sendable {
    private let listenFd: Int32
    private let stopped = OSAllocatedUnfairLock(initialState: false)
    private let queue = DispatchQueue(label: "test.unix.http.server")

    init(
        socketPath: String,
        handler: @escaping @Sendable (String) -> TestHttpReply
    ) throws {
        unlink(socketPath)
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (idx, val) in bytes.enumerated() where idx < buf.count - 1 {
                buf[idx] = val
            }
        }
        let bindRes = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindRes == 0, Darwin.listen(fd, 8) == 0 else {
            Darwin.close(fd)
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        self.listenFd = fd
        queue.async { [weak self] in
            self?.acceptLoop(handler: handler)
        }
    }

    func stop() {
        let alreadyStopped = stopped.withLock { flag in
            let prev = flag
            flag = true
            return prev
        }
        if !alreadyStopped {
            Darwin.shutdown(listenFd, SHUT_RDWR)
            Darwin.close(listenFd)
        }
    }

    private func acceptLoop(handler: @Sendable (String) -> TestHttpReply) {
        while !stopped.withLock({ $0 }) {
            let clientFd = Darwin.accept(listenFd, nil, nil)
            if clientFd < 0 {
                break
            }
            handleConnection(clientFd, handler: handler)
            Darwin.close(clientFd)
        }
    }

    private func handleConnection(_ clientFd: Int32, handler: @Sendable (String) -> TestHttpReply) {
        let bufCap = 4_096
        var reqBuf = [UInt8](repeating: 0, count: bufCap)
        let readCount = reqBuf.withUnsafeMutableBytes { ptr -> Int in
            guard let base = ptr.baseAddress else { return -1 }
            return Darwin.read(clientFd, base, bufCap)
        }
        guard readCount > 0 else { return }
        let reqText = String(bytes: reqBuf[0..<readCount], encoding: .utf8) ?? ""
        let firstLine = reqText.split(separator: "\r\n", maxSplits: 1).first ?? ""
        let reqParts = firstLine.split(separator: " ")
        let path = reqParts.count >= 2 ? String(reqParts[1]) : "/"

        let reply = handler(path)
        var rawOut = Data()
        var head = "HTTP/1.1 \(reply.statusCode) OK\r\nConnection: close\r\n"
        for (key, val) in reply.headers {
            head += "\(key): \(val)\r\n"
        }
        if reply.chunked {
            head += "Transfer-Encoding: chunked\r\n\r\n"
            rawOut.append(Data(head.utf8))
            let mid = reply.body.count / 2
            let firstHalf = reply.body.subdata(in: 0..<mid)
            let secondHalf = reply.body.subdata(in: mid..<reply.body.count)
            for part in [firstHalf, secondHalf] where !part.isEmpty {
                rawOut.append(Data("\(String(part.count, radix: 16))\r\n".utf8))
                rawOut.append(part)
                rawOut.append(Data("\r\n".utf8))
            }
            rawOut.append(Data("0\r\n\r\n".utf8))
        } else {
            head += "Content-Length: \(reply.body.count)\r\n\r\n"
            rawOut.append(Data(head.utf8))
            rawOut.append(reply.body)
        }
        _ = rawOut.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                return Darwin.write(clientFd, base, ptr.count)
            }
            return 0
        }
    }
}

private struct TruncatingStreamMockTransport: DesktopIpcTransport {
    func fetchStatus(socketPath: String) async throws -> IpcResponseWithMeta<AgentStatusResponse> {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func fetchPeers(socketPath: String) async throws -> IpcResponseWithMeta<AgentStatusResponse> {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func fetchVersion(socketPath: String) async throws -> AgentVersionResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func runNetcheck(socketPath: String) async throws -> NetcheckResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func pingPeer(socketPath: String, request: PingRequest) async throws -> PingResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func bringUp(socketPath: String, request: AgentUpRequest) async throws -> AgentActionResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func bringDown(socketPath: String) async throws -> AgentActionResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func cleanup(socketPath: String) async throws -> AgentActionResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func updateServer(
        socketPath: String,
        request: AgentSetRequest
    ) async throws -> AgentActionResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func rotateKey(
        socketPath: String,
        request: AgentRotateKeyRequest
    ) async throws -> AgentActionResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func resetIdentity(socketPath: String) async throws -> AgentActionResponse {
        throw IpcClientError.serviceUnavailable("unused")
    }
    func probeOfflineDaemonVersion(binaryPath: String) async -> AgentVersionStatus? { nil }

    func streamBugreport(
        socketPath: String,
        onChunk: @escaping @Sendable (Data) throws -> Void
    ) async throws -> StreamedBugreportMetadata {
        try onChunk(Data("partial-corrupt".utf8))
        throw IpcClientError.streamConstraintViolation("simulated mid-stream abort")
    }
}
