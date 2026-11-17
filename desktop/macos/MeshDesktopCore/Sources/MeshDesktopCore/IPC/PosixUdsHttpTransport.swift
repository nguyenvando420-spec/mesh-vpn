import Darwin
import Foundation

internal struct UdsJsonRequestSpec: Sendable {
    let socketPath: String
    let method: String
    let path: String
    let bodyData: Data?
    let connectTimeout: TimeInterval
    let responseTimeout: TimeInterval
}

internal struct UdsStreamRequestSpec: Sendable {
    let socketPath: String
    let method: String
    let path: String
    let bodyData: Data?
    let timeouts: StreamTimeoutConfig
}

/// Low-level non-blocking POSIX `AF_UNIX` stream transport with 3-tier deadlines (`ADR-023`).
internal enum PosixUdsHttpTransport {
    static func executeJson(_ spec: UdsJsonRequestSpec) throws -> RawHttpResponse {
        let fd = try openAndConnect(socketPath: spec.socketPath, timeout: spec.connectTimeout)
        defer { Darwin.close(fd) }

        let deadline = ContinuousClock.now + .milliseconds(Int(spec.responseTimeout * 1000))
        let requestBytes = HttpUdsWireCodec.buildHttpRequest(
            method: spec.method,
            path: spec.path,
            bodyData: spec.bodyData
        )
        try writeAll(fd: fd, data: requestBytes, deadline: deadline)

        let head = try HttpUdsWireCodec.readHttpHead(
            fd: fd,
            deadline: deadline,
            idleTimeout: spec.responseTimeout
        )
        var body = Data()
        let context = BodyStreamContext(
            fd: fd,
            totalDeadline: deadline,
            chunkIdleTimeout: spec.responseTimeout
        )
        try HttpUdsWireCodec.readBodyStreaming(
            context: context,
            head: head,
            maxTotalBytes: UInt64(AgentDefaults.maxJsonIpcBodyBytes)
        ) { chunk in
            body.append(chunk)
        }

        let agentVer = HttpUdsWireCodec.extractHeader(head.headers, name: "x-mesh-agent-version")
        if !(200...299).contains(head.statusCode) {
            throw HttpUdsWireCodec.mapRemoteHttpError(statusCode: head.statusCode, body: body)
        }
        return RawHttpResponse(
            statusCode: head.statusCode,
            agentVersionHeader: agentVer,
            body: body
        )
    }

    static func executeStream(
        _ spec: UdsStreamRequestSpec,
        onChunk: (Data) throws -> Void
    ) throws -> StreamedBugreportMetadata {
        let fd = try openAndConnect(
            socketPath: spec.socketPath,
            timeout: spec.timeouts.connectTimeout
        )
        defer { Darwin.close(fd) }

        let deadline = ContinuousClock.now
            + .milliseconds(Int(spec.timeouts.totalTimeout * 1000))
        let requestBytes = HttpUdsWireCodec.buildHttpRequest(
            method: spec.method,
            path: spec.path,
            bodyData: spec.bodyData
        )
        try writeAll(fd: fd, data: requestBytes, deadline: deadline)

        let head = try HttpUdsWireCodec.readHttpHead(
            fd: fd,
            deadline: deadline,
            idleTimeout: spec.timeouts.totalTimeout
        )
        let context = BodyStreamContext(
            fd: fd,
            totalDeadline: deadline,
            chunkIdleTimeout: spec.timeouts.chunkIdleTimeout
        )
        if !(200...299).contains(head.statusCode) {
            var errBody = Data()
            try HttpUdsWireCodec.readBodyStreaming(
                context: context,
                head: head,
                maxTotalBytes: UInt64(AgentDefaults.maxJsonIpcBodyBytes)
            ) { chunk in
                errBody.append(chunk)
            }
            throw HttpUdsWireCodec.mapRemoteHttpError(statusCode: head.statusCode, body: errBody)
        }

        let expectedTotal = try HttpUdsWireCodec.parseExpectedArchiveBytes(headers: head.headers)
        let scrubbedItems = try HttpUdsWireCodec.parseScrubbedItems(headers: head.headers)
        let agentVersion = HttpUdsWireCodec.extractHeader(
            head.headers,
            name: "x-mesh-agent-version"
        )

        let cumulative = try readBodyStreamingCounting(
            context: context,
            head: head,
            expectedTotal: expectedTotal,
            onChunk: onChunk
        )
        guard cumulative == expectedTotal else {
            throw IpcClientError.streamConstraintViolation(
                "Bugreport stream truncated: received \(cumulative) of \(expectedTotal) bytes"
            )
        }
        return StreamedBugreportMetadata(
            totalBytes: cumulative,
            scrubbedItems: scrubbedItems,
            agentVersion: agentVersion
        )
    }

    static func readChunk(
        fd: Int32,
        maxBytes: Int,
        deadline: ContinuousClock.Instant
    ) throws -> Data {
        var buf = [UInt8](repeating: 0, count: maxBytes)
        while true {
            try waitPoll(fd: fd, events: Int16(POLLIN), deadline: deadline, label: "read")
            let count = buf.withUnsafeMutableBytes { rawPtr -> Int in
                guard let base = rawPtr.baseAddress else { return -1 }
                return Darwin.read(fd, base, maxBytes)
            }
            if count > 0 {
                return Data(buf[0..<count])
            }
            if count == 0 {
                return Data()
            }
            let errCode = errno
            if errCode == EINTR || errCode == EAGAIN || errCode == EWOULDBLOCK {
                continue
            }
            throw mapPosixErrno(errCode, socketPath: "IPC read")
        }
    }

    private static func readBodyStreamingCounting(
        context: BodyStreamContext,
        head: ParsedHttpHead,
        expectedTotal: UInt64,
        onChunk: (Data) throws -> Void
    ) throws -> UInt64 {
        var cumulative: UInt64 = 0
        try HttpUdsWireCodec.readBodyStreaming(
            context: context,
            head: head,
            maxTotalBytes: expectedTotal
        ) { chunk in
            guard !chunk.isEmpty else { return }
            let nextTotal = cumulative + UInt64(chunk.count)
            if nextTotal > expectedTotal || nextTotal > AgentDefaults.maxBugreportArchiveBytes {
                throw IpcClientError.streamConstraintViolation(
                    "Bugreport stream exceeded declared archive size"
                )
            }
            try onChunk(chunk)
            cumulative = nextTotal
        }
        return cumulative
    }

    private static func openAndConnect(socketPath: String, timeout: TimeInterval) throws -> Int32 {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw mapPosixErrno(errno, socketPath: socketPath)
        }

        var cleanupFd = true
        defer {
            if cleanupFd {
                Darwin.close(fd)
            }
        }

        var noSigPipe: Int32 = 1
        _ = Darwin.setsockopt(
            fd,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &noSigPipe,
            socklen_t(MemoryLayout<Int32>.size)
        )

        let existingFlags = Darwin.fcntl(fd, F_GETFL, 0)
        if existingFlags >= 0 {
            _ = Darwin.fcntl(fd, F_SETFL, existingFlags | O_NONBLOCK)
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let maxSunPath = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < maxSunPath else {
            throw IpcClientError.invalidResponse("Unix socket path too long: \(socketPath)")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (idx, byte) in pathBytes.enumerated() {
                buf[idx] = byte
            }
            buf[pathBytes.count] = 0
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connRes = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, addrLen)
            }
        }

        if connRes != 0 {
            let errCode = errno
            if errCode == EINPROGRESS || errCode == EALREADY {
                let deadline = ContinuousClock.now + .milliseconds(Int(timeout * 1000))
                try waitPoll(fd: fd, events: Int16(POLLOUT), deadline: deadline, label: socketPath)
                var soErr: Int32 = 0
                var soLen = socklen_t(MemoryLayout<Int32>.size)
                _ = Darwin.getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soLen)
                if soErr != 0 {
                    throw mapPosixErrno(soErr, socketPath: socketPath)
                }
            } else {
                throw mapPosixErrno(errCode, socketPath: socketPath)
            }
        }

        cleanupFd = false
        return fd
    }

    private static func writeAll(
        fd: Int32,
        data: Data,
        deadline: ContinuousClock.Instant
    ) throws {
        var offset = 0
        while offset < data.count {
            try waitPoll(fd: fd, events: Int16(POLLOUT), deadline: deadline, label: "write")
            let written = data.withUnsafeBytes { rawPtr -> Int in
                guard let base = rawPtr.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), data.count - offset)
            }
            if written > 0 {
                offset += written
            } else if written < 0 {
                let errCode = errno
                if errCode == EINTR || errCode == EAGAIN || errCode == EWOULDBLOCK {
                    continue
                }
                throw mapPosixErrno(errCode, socketPath: "IPC write")
            } else {
                throw IpcClientError.serviceUnavailable("IPC socket closed during write")
            }
        }
    }

    private static func waitPoll(
        fd: Int32,
        events: Int16,
        deadline: ContinuousClock.Instant,
        label: String
    ) throws {
        while true {
            let remaining = ContinuousClock.now.duration(to: deadline)
            let secs = Double(remaining.components.seconds)
            let attos = Double(remaining.components.attoseconds) / 1e18
            let remainingMs = Int32(ceil((secs + attos) * 1000.0))
            if remainingMs <= 0 {
                throw IpcClientError.timeout("IPC operation timed out (\(label))")
            }
            var pfd = pollfd(fd: fd, events: events, revents: 0)
            let rc = Darwin.poll(&pfd, 1, remainingMs)
            if rc > 0 {
                return
            }
            if rc == 0 {
                throw IpcClientError.timeout("IPC operation timed out (\(label))")
            }
            let errCode = errno
            if errCode == EINTR {
                continue
            }
            throw mapPosixErrno(errCode, socketPath: label)
        }
    }

    private static func mapPosixErrno(_ errCode: Int32, socketPath: String) -> IpcClientError {
        if errCode == EACCES || errCode == EPERM {
            return .permissionDenied(
                "Permission denied accessing \(socketPath): macOS admin group (gid 80) required"
            )
        }
        if errCode == ETIMEDOUT {
            return .timeout("Timed out connecting to \(socketPath)")
        }
        return .serviceUnavailable("meshd background service is offline (\(socketPath))")
    }
}
