import Darwin
import Foundation
import os
import Security

/// Result returned after atomically committing a streamed bugreport `.tar` archive (`ADR-023`).
public struct BugreportExportResult: Equatable, Sendable {
    public let destinationURL: URL
    public let totalBytes: UInt64
    public let scrubbedItems: UInt32

    public init(destinationURL: URL, totalBytes: UInt64, scrubbedItems: UInt32) {
        self.destinationURL = destinationURL
        self.totalBytes = totalBytes
        self.scrubbedItems = scrubbedItems
    }
}

/// Errors thrown by `BugreportStreamWriter` when enforcing Unprivileged Sink Write (`ADR-023`).
public enum BugreportWriterError: Error, Equatable, Sendable, LocalizedError {
    case invalidDestination(String)
    case forbiddenSystemDirectory(String)
    case symlinkOrUnsafeTarget(String)
    case sizeMismatch(expected: UInt64, actual: UInt64)
    case ioFailure(String)

    public var errorDescription: String? {
        switch self {
        case .invalidDestination(let msg):
            return msg
        case .forbiddenSystemDirectory(let msg):
            return msg
        case .symlinkOrUnsafeTarget(let msg):
            return msg
        case .sizeMismatch(let expected, let actual):
            return "Bugreport archive size mismatch: received \(actual) of \(expected) bytes"
        case .ioFailure(let msg):
            return msg
        }
    }
}

/// Atomic Temp-Sibling Sink Writer (`US-112`, `BLK-DGUI-G2-05`, `MED-DGUI-G2-02`).
///
/// Validates destination path & parent non-symlink status, streams chunks `<= 64 KiB` to
/// `parent/.mesh-bugreport-<128bit_hex>.tar.part` (`O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`,
/// `0600`), verifies `expectedBytes > 0 && cumulative == expectedBytes <= 20_971_520`, calls
/// `fsync()`, closes the descriptor, re-verifies the destination, and atomically commits via
/// POSIX `Darwin.rename(partURL.path, destURL.path)` (`ADR-023`).
public enum BugreportStreamWriter: Sendable {
    private static let forbiddenSystemPrefixes = [
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/Library",
        "/private/var/db/mesh",
        "/var/db/mesh",
        "/private/var/run/meshd",
        "/var/run/meshd",
        "/private/etc",
        "/etc",
        "/dev"
    ]

    public static func validateDestination(_ destURL: URL) throws {
        guard destURL.isFileURL else {
            throw BugreportWriterError.invalidDestination("Destination must be a local file URL")
        }
        let destPath = destURL.standardizedFileURL.path
        guard !destPath.isEmpty, !destPath.contains("\0") else {
            throw BugreportWriterError.invalidDestination("Destination path is empty or invalid")
        }

        let parentURL = destURL.standardizedFileURL.deletingLastPathComponent()
        let parentPath = parentURL.path
        try rejectSystemPath(destPath)
        try rejectSystemPath(parentPath)
        if let resolvedParent = resolveRealPath(parentPath) {
            try rejectSystemPath(resolvedParent)
        }

        var parentStat = stat()
        guard Darwin.lstat(parentPath, &parentStat) == 0 else {
            throw BugreportWriterError.invalidDestination(
                "Destination folder does not exist: \(parentPath)"
            )
        }
        let parentType = parentStat.st_mode & S_IFMT
        if parentType == S_IFLNK {
            throw BugreportWriterError.symlinkOrUnsafeTarget(
                "Refusing to write bugreport inside symlinked parent directory"
            )
        }
        guard parentType == S_IFDIR else {
            throw BugreportWriterError.invalidDestination(
                "Destination parent path is not a directory"
            )
        }

        try validateExistingDestinationIfPresent(destPath: destPath)
    }

    public static func exportStream(
        transport: any DesktopIpcTransport,
        adminSocketPath: String = AgentDefaults.adminSocketPath,
        destinationURL: URL
    ) async throws -> BugreportExportResult {
        let destURL = destinationURL.standardizedFileURL
        try validateDestination(destURL)

        let partURL = try makeTempPartURL(nextTo: destURL)
        let sink = try AtomicPartFileSink(partURL: partURL)
        do {
            let meta = try await transport.streamBugreport(
                socketPath: adminSocketPath,
                onChunk: { chunk in
                    try sink.appendChunk(chunk)
                }
            )
            let totalWritten = try sink.finalizeAndCommit(
                expectedTotalBytes: meta.totalBytes,
                destURL: destURL
            )
            return BugreportExportResult(
                destinationURL: destURL,
                totalBytes: totalWritten,
                scrubbedItems: meta.scrubbedItems
            )
        } catch {
            sink.abortAndCleanup()
            throw error
        }
    }

    static func validateExistingDestinationIfPresent(destPath: String) throws {
        var destStat = stat()
        let rc = Darwin.lstat(destPath, &destStat)
        if rc != 0 {
            if errno == ENOENT {
                return
            }
            throw BugreportWriterError.ioFailure(
                "Unable to inspect destination path (errno=\(errno))"
            )
        }
        let destType = destStat.st_mode & S_IFMT
        if destType == S_IFLNK {
            throw BugreportWriterError.symlinkOrUnsafeTarget(
                "Refusing to overwrite symlink destination"
            )
        }
        guard destType == S_IFREG else {
            throw BugreportWriterError.symlinkOrUnsafeTarget(
                "Refusing to overwrite non-regular file destination"
            )
        }
    }

    private static func rejectSystemPath(_ path: String) throws {
        for prefix in forbiddenSystemPrefixes
        where path == prefix || path.hasPrefix(prefix + "/") {
            throw BugreportWriterError.forbiddenSystemDirectory(
                "Writing bugreport into protected system directory `\(prefix)` is forbidden"
            )
        }
    }

    private static func resolveRealPath(_ path: String) -> String? {
        guard let ptr = Darwin.realpath(path, nil) else { return nil }
        defer { Darwin.free(ptr) }
        return String(cString: ptr)
    }

    private static func makeTempPartURL(nextTo destURL: URL) throws -> URL {
        var randomBytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        guard status == errSecSuccess else {
            throw BugreportWriterError.ioFailure(
                "CSPRNG failure generating temporary bugreport name (status=\(status))"
            )
        }
        let hex = randomBytes.map { String(format: "%02x", $0) }.joined()
        let parentDir = destURL.deletingLastPathComponent()
        return parentDir.appendingPathComponent(".mesh-bugreport-\(hex).tar.part")
    }
}

private struct PartSinkState: Sendable {
    var fileDescriptor: Int32
    var cumulativeBytes: UInt64 = 0
    var isClosed = false
    var isCommitted = false
}

/// Thread-safe RAII wrapper around the `.part` file descriptor using `OSAllocatedUnfairLock`.
private final class AtomicPartFileSink: Sendable {
    private let partURL: URL
    private let state: OSAllocatedUnfairLock<PartSinkState>

    init(partURL: URL) throws {
        let fd = Darwin.open(
            partURL.path,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            mode_t(0o600)
        )
        guard fd >= 0 else {
            throw BugreportWriterError.ioFailure(
                "Failed creating temporary bugreport file (errno=\(errno))"
            )
        }
        self.partURL = partURL
        self.state = OSAllocatedUnfairLock(initialState: PartSinkState(fileDescriptor: fd))
    }

    deinit {
        abortAndCleanup()
    }

    func appendChunk(_ chunk: Data) throws {
        guard !chunk.isEmpty else { return }
        if chunk.count > AgentDefaults.bugreportChunkSize {
            throw BugreportWriterError.ioFailure("Received oversized bugreport chunk")
        }
        try state.withLock { current in
            guard !current.isClosed, current.fileDescriptor >= 0 else {
                throw BugreportWriterError.ioFailure("Bugreport sink already closed")
            }
            let nextTotal = current.cumulativeBytes + UInt64(chunk.count)
            guard nextTotal <= AgentDefaults.maxBugreportArchiveBytes else {
                throw BugreportWriterError.sizeMismatch(
                    expected: AgentDefaults.maxBugreportArchiveBytes,
                    actual: nextTotal
                )
            }
            try Self.writeAll(fd: current.fileDescriptor, data: chunk)
            current.cumulativeBytes = nextTotal
        }
    }

    func finalizeAndCommit(expectedTotalBytes: UInt64, destURL: URL) throws -> UInt64 {
        let written = try state.withLock { current -> UInt64 in
            guard !current.isClosed, current.fileDescriptor >= 0 else {
                throw BugreportWriterError.ioFailure("Bugreport sink already closed")
            }
            let fd = current.fileDescriptor
            let total = current.cumulativeBytes
            guard expectedTotalBytes > 0,
                  total == expectedTotalBytes,
                  total <= AgentDefaults.maxBugreportArchiveBytes
            else {
                throw BugreportWriterError.sizeMismatch(expected: expectedTotalBytes, actual: total)
            }
            if Darwin.fsync(fd) != 0 {
                throw BugreportWriterError.ioFailure("fsync failed on temp file (errno=\(errno))")
            }
            _ = Darwin.close(fd)
            current.fileDescriptor = -1
            current.isClosed = true
            return total
        }

        try BugreportStreamWriter.validateExistingDestinationIfPresent(destPath: destURL.path)
        guard Darwin.rename(partURL.path, destURL.path) == 0 else {
            let errCode = errno
            throw BugreportWriterError.ioFailure(
                "Failed committing bugreport archive atomically (errno=\(errCode))"
            )
        }
        state.withLock { current in
            current.isCommitted = true
        }
        return written
    }

    func abortAndCleanup() {
        let shouldUnlink = state.withLock { current -> Bool in
            if !current.isClosed && current.fileDescriptor >= 0 {
                _ = Darwin.close(current.fileDescriptor)
                current.fileDescriptor = -1
                current.isClosed = true
            }
            return !current.isCommitted
        }
        if shouldUnlink {
            _ = Darwin.unlink(partURL.path)
        }
    }

    private static func writeAll(fd: Int32, data: Data) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { rawPtr -> Int in
                guard let base = rawPtr.baseAddress else { return -1 }
                return Darwin.write(fd, base.advanced(by: offset), data.count - offset)
            }
            if written > 0 {
                offset += written
            } else if written < 0 && errno == EINTR {
                continue
            } else {
                throw BugreportWriterError.ioFailure(
                    "Failed writing bugreport chunk (errno=\(errno))"
                )
            }
        }
    }
}
