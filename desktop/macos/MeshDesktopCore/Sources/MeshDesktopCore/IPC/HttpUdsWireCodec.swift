import Foundation

internal struct RawHttpResponse: Sendable {
    let statusCode: Int
    let agentVersionHeader: String?
    let body: Data
}

internal struct ParsedHttpHead {
    let statusCode: Int
    let headers: [String: String]
    let remainder: Data
}

internal struct StreamTimeoutConfig: Sendable {
    let connectTimeout: TimeInterval
    let totalTimeout: TimeInterval
    let chunkIdleTimeout: TimeInterval
}

internal struct BodyStreamContext {
    let fd: Int32
    let totalDeadline: ContinuousClock.Instant
    let chunkIdleTimeout: TimeInterval
}

/// HTTP/1.1 framing, header/chunked parser, and wire error mapper for UDS IPC (`ADR-023`).
internal enum HttpUdsWireCodec {
    static let maxHeaderBytes = 16_384
    static let readBufferBytes = 65_536

    static func buildHttpRequest(method: String, path: String, bodyData: Data?) -> Data {
        var header = "\(method) \(path) HTTP/1.1\r\n"
        header += "Host: localhost\r\n"
        header += "Connection: close\r\n"
        if let bodyData, !bodyData.isEmpty {
            header += "Content-Type: application/json\r\n"
            header += "Content-Length: \(bodyData.count)\r\n"
        } else if method == "POST" {
            header += "Content-Length: 0\r\n"
        }
        header += "\r\n"
        var out = Data(header.utf8)
        if let bodyData, !bodyData.isEmpty {
            out.append(bodyData)
        }
        return out
    }

    static func readHttpHead(
        fd: Int32,
        deadline: ContinuousClock.Instant,
        idleTimeout: TimeInterval
    ) throws -> ParsedHttpHead {
        var buffer = Data()
        let delimiter = Data("\r\n\r\n".utf8)
        while true {
            if let range = buffer.range(of: delimiter) {
                let headData = buffer.subdata(in: 0..<range.lowerBound)
                let remainder = buffer.subdata(in: range.upperBound..<buffer.count)
                return try parseHttpHeadData(headData, remainder: remainder)
            }
            if buffer.count >= maxHeaderBytes {
                throw IpcClientError.invalidResponse("IPC HTTP response headers exceeded 16 KiB")
            }
            let stepDeadline = minDeadline(deadline, idleTimeout: idleTimeout)
            let chunk = try PosixUdsHttpTransport.readChunk(
                fd: fd,
                maxBytes: 4_096,
                deadline: stepDeadline
            )
            guard !chunk.isEmpty else {
                throw IpcClientError.invalidResponse("IPC connection closed before HTTP headers")
            }
            buffer.append(chunk)
        }
    }

    static func minDeadline(
        _ totalDeadline: ContinuousClock.Instant,
        idleTimeout: TimeInterval
    ) -> ContinuousClock.Instant {
        let idleDeadline = ContinuousClock.now + .milliseconds(Int(idleTimeout * 1000))
        return totalDeadline < idleDeadline ? totalDeadline : idleDeadline
    }

    static func extractHeader(_ headers: [String: String], name: String) -> String? {
        guard let raw = headers[name.lowercased()]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !raw.isEmpty
        else {
            return nil
        }
        return raw
    }

    static func parseExpectedArchiveBytes(headers: [String: String]) throws -> UInt64 {
        let raw = extractHeader(headers, name: "x-mesh-archive-bytes")
            ?? extractHeader(headers, name: "content-length")
        guard let raw, let value = UInt64(raw) else {
            throw IpcClientError.invalidResponse(
                "Bugreport stream missing X-Mesh-Archive-Bytes / Content-Length header"
            )
        }
        guard value > 0 && value <= AgentDefaults.maxBugreportArchiveBytes else {
            let cap = AgentDefaults.maxBugreportArchiveBytes
            throw IpcClientError.streamConstraintViolation(
                "Bugreport archive size \(value) outside 1...\(cap)"
            )
        }
        return value
    }

    static func parseScrubbedItems(headers: [String: String]) throws -> UInt32 {
        guard let raw = extractHeader(headers, name: "x-mesh-scrubbed-items") else {
            return 0
        }
        guard let value = UInt32(raw) else {
            throw IpcClientError.invalidResponse("Invalid X-Mesh-Scrubbed-Items header: \(raw)")
        }
        return value
    }

    static func mapRemoteHttpError(statusCode: Int, body: Data) -> IpcClientError {
        if let errResp = try? JSONDecoder().decode(ErrorResponse.self, from: body) {
            return .remoteError(statusCode: statusCode, envelope: errResp.error)
        }
        if statusCode == 401 {
            return .remoteError(
                statusCode: 401,
                envelope: ErrorEnvelope(
                    kind: .unauthenticated,
                    code: "E_UNAUTHENTICATED",
                    message: "authentication failed",
                    requestId: "ipc"
                )
            )
        }
        if statusCode == 403 {
            return .permissionDenied("Administrator privileges required for meshd-admin IPC")
        }
        let defaultKind: MeshWireErrorKind = statusCode == 404 ? .notFound : .unavailable
        return .remoteError(
            statusCode: statusCode,
            envelope: ErrorEnvelope(
                kind: defaultKind,
                code: statusCode == 404 ? "E_NOT_FOUND" : "E_UNAVAILABLE",
                message: "IPC endpoint returned HTTP \(statusCode)",
                requestId: "ipc"
            )
        )
    }

    private static func parseHttpHeadData(
        _ headData: Data,
        remainder: Data
    ) throws -> ParsedHttpHead {
        guard let headText = String(data: headData, encoding: .utf8) else {
            throw IpcClientError.invalidResponse("IPC HTTP header bytes not valid UTF-8")
        }
        let lines = headText.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else {
            throw IpcClientError.invalidResponse("Missing IPC HTTP status line")
        }
        let parts = statusLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2,
              parts[0].hasPrefix("HTTP/1."),
              let statusCode = Int(parts[1])
        else {
            throw IpcClientError.invalidResponse("Malformed IPC HTTP status line: \(statusLine)")
        }

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let val = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[key] = val
        }
        return ParsedHttpHead(statusCode: statusCode, headers: headers, remainder: remainder)
    }
}

extension HttpUdsWireCodec {
    static func readBodyStreaming(
        context: BodyStreamContext,
        head: ParsedHttpHead,
        maxTotalBytes: UInt64,
        onChunk: (Data) throws -> Void
    ) throws {
        let transferEncoding = head.headers["transfer-encoding"]?.lowercased() ?? ""
        if transferEncoding.contains("chunked") {
            try readChunkedBody(
                context: context,
                initial: head.remainder,
                maxTotalBytes: maxTotalBytes,
                onChunk: onChunk
            )
            return
        }

        if let lenHeader = head.headers["content-length"] {
            guard let expectedLen = UInt64(lenHeader) else {
                throw IpcClientError.invalidResponse("Invalid Content-Length header: \(lenHeader)")
            }
            guard expectedLen <= maxTotalBytes else {
                throw IpcClientError.streamConstraintViolation(
                    "IPC response Content-Length \(expectedLen) exceeds cap \(maxTotalBytes)"
                )
            }
            try readFixedLengthBody(
                context: context,
                initial: head.remainder,
                expectedLength: expectedLen,
                onChunk: onChunk
            )
            return
        }

        try readEofBody(
            context: context,
            initial: head.remainder,
            maxTotalBytes: maxTotalBytes,
            onChunk: onChunk
        )
    }

    private static func readFixedLengthBody(
        context: BodyStreamContext,
        initial: Data,
        expectedLength: UInt64,
        onChunk: (Data) throws -> Void
    ) throws {
        var remaining = expectedLength
        if !initial.isEmpty {
            let take = Int(min(UInt64(initial.count), remaining))
            if take > 0 {
                try onChunk(initial.subdata(in: 0..<take))
                remaining -= UInt64(take)
            }
        }
        while remaining > 0 {
            let stepDeadline = minDeadline(
                context.totalDeadline,
                idleTimeout: context.chunkIdleTimeout
            )
            let toRead = Int(min(UInt64(readBufferBytes), remaining))
            let chunk = try PosixUdsHttpTransport.readChunk(
                fd: context.fd,
                maxBytes: toRead,
                deadline: stepDeadline
            )
            if chunk.isEmpty {
                throw IpcClientError.streamConstraintViolation(
                    "IPC stream truncated before Content-Length reached"
                )
            }
            try onChunk(chunk)
            remaining -= UInt64(chunk.count)
        }
    }

    private static func readEofBody(
        context: BodyStreamContext,
        initial: Data,
        maxTotalBytes: UInt64,
        onChunk: (Data) throws -> Void
    ) throws {
        var total: UInt64 = 0
        if !initial.isEmpty {
            total += UInt64(initial.count)
            guard total <= maxTotalBytes else {
                throw IpcClientError.streamConstraintViolation("IPC body exceeded size cap")
            }
            try onChunk(initial)
        }
        while true {
            let stepDeadline = minDeadline(
                context.totalDeadline,
                idleTimeout: context.chunkIdleTimeout
            )
            let chunk = try PosixUdsHttpTransport.readChunk(
                fd: context.fd,
                maxBytes: readBufferBytes,
                deadline: stepDeadline
            )
            if chunk.isEmpty {
                break
            }
            total += UInt64(chunk.count)
            guard total <= maxTotalBytes else {
                throw IpcClientError.streamConstraintViolation("IPC body exceeded size cap")
            }
            try onChunk(chunk)
        }
    }

    private static func readChunkedBody(
        context: BodyStreamContext,
        initial: Data,
        maxTotalBytes: UInt64,
        onChunk: (Data) throws -> Void
    ) throws {
        var buffer = initial
        var total: UInt64 = 0
        while true {
            let chunkSize = try readNextChunkSize(context: context, buffer: &buffer)
            if chunkSize == 0 {
                break
            }
            guard total + chunkSize <= maxTotalBytes else {
                throw IpcClientError.streamConstraintViolation("Chunked body exceeded size cap")
            }
            total += chunkSize
            try drainChunkPayload(
                context: context,
                chunkSize: chunkSize,
                buffer: &buffer,
                onChunk: onChunk
            )
        }
    }

    private static func readNextChunkSize(
        context: BodyStreamContext,
        buffer: inout Data
    ) throws -> UInt64 {
        let crlf = Data("\r\n".utf8)
        while buffer.range(of: crlf) == nil {
            let stepDeadline = minDeadline(
                context.totalDeadline,
                idleTimeout: context.chunkIdleTimeout
            )
            let more = try PosixUdsHttpTransport.readChunk(
                fd: context.fd,
                maxBytes: 4_096,
                deadline: stepDeadline
            )
            guard !more.isEmpty else {
                throw IpcClientError.streamConstraintViolation("Truncated chunked header")
            }
            buffer.append(more)
            guard buffer.count <= maxHeaderBytes else {
                throw IpcClientError.invalidResponse("Oversized chunked size line")
            }
        }
        guard let lineRange = buffer.range(of: crlf) else {
            throw IpcClientError.invalidResponse("Missing chunked size delimiter")
        }
        let lineData = buffer.subdata(in: 0..<lineRange.lowerBound)
        buffer.removeSubrange(0..<lineRange.upperBound)
        guard let lineStr = String(data: lineData, encoding: .utf8) else {
            throw IpcClientError.invalidResponse("Non-UTF8 chunked size line")
        }
        let hexToken = lineStr.split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespaces) ?? ""
        guard let chunkSize = UInt64(hexToken, radix: 16) else {
            throw IpcClientError.invalidResponse("Invalid chunked hex size: \(hexToken)")
        }
        return chunkSize
    }

    private static func drainChunkPayload(
        context: BodyStreamContext,
        chunkSize: UInt64,
        buffer: inout Data,
        onChunk: (Data) throws -> Void
    ) throws {
        var remaining = chunkSize
        while remaining > 0 {
            if !buffer.isEmpty {
                let take = Int(min(UInt64(buffer.count), remaining))
                let slice = buffer.subdata(in: 0..<take)
                buffer.removeSubrange(0..<take)
                try emitSubChunks(slice, onChunk: onChunk)
                remaining -= UInt64(take)
            } else {
                let stepDeadline = minDeadline(
                    context.totalDeadline,
                    idleTimeout: context.chunkIdleTimeout
                )
                let want = Int(min(UInt64(readBufferBytes), remaining))
                let fetched = try PosixUdsHttpTransport.readChunk(
                    fd: context.fd,
                    maxBytes: want,
                    deadline: stepDeadline
                )
                guard !fetched.isEmpty else {
                    throw IpcClientError.streamConstraintViolation("Truncated HTTP chunk")
                }
                try emitSubChunks(fetched, onChunk: onChunk)
                remaining -= UInt64(fetched.count)
            }
        }

        while buffer.count < 2 {
            let stepDeadline = minDeadline(
                context.totalDeadline,
                idleTimeout: context.chunkIdleTimeout
            )
            let more = try PosixUdsHttpTransport.readChunk(
                fd: context.fd,
                maxBytes: 128,
                deadline: stepDeadline
            )
            guard !more.isEmpty else {
                throw IpcClientError.streamConstraintViolation("Missing chunk CRLF trailer")
            }
            buffer.append(more)
        }
        guard buffer[0] == 0x0D && buffer[1] == 0x0A else {
            throw IpcClientError.invalidResponse("Malformed HTTP chunk CRLF delimiter")
        }
        buffer.removeSubrange(0..<2)
    }

    private static func emitSubChunks(_ data: Data, onChunk: (Data) throws -> Void) throws {
        var offset = 0
        while offset < data.count {
            let end = min(offset + AgentDefaults.bugreportChunkSize, data.count)
            try onChunk(data.subdata(in: offset..<end))
            offset = end
        }
    }
}
