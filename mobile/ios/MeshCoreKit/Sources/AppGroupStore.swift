import Foundation

/// Non-secret bootstrap summary parsed from App Group `bootstrap.toml`.
public struct BootstrapSummary: Sendable, Equatable {
    public let serverEndpoint: String
    public let tlsAuthMode: MobileTlsAuthMode
    public let activePin: String?
    public let nextPin: String?
    public let nodeName: String?
    public let nodeId: String?
    public let overlayIp: String?
    public let fqdn: String?

    /// Creates a non-secret bootstrap summary.
    public init(
        serverEndpoint: String,
        tlsAuthMode: MobileTlsAuthMode,
        activePin: String?,
        nextPin: String?,
        nodeName: String?,
        nodeId: String?,
        overlayIp: String?,
        fqdn: String?
    ) {
        self.serverEndpoint = serverEndpoint
        self.tlsAuthMode = tlsAuthMode
        self.activePin = activePin
        self.nextPin = nextPin
        self.nodeName = nodeName
        self.nodeId = nodeId
        self.overlayIp = overlayIp
        self.fqdn = fqdn
    }

    /// Parses top-level string key/value fields from Rust's `bootstrap.toml`.
    public static func parse(tomlText: String) -> BootstrapSummary? {
        var values: [String: String] = [:]
        for rawLine in tomlText.split(whereSeparator: \.isNewline) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix("[") {
                continue
            }
            guard let eqIndex = trimmed.firstIndex(of: "=") else {
                continue
            }
            let key = trimmed[..<eqIndex].trimmingCharacters(in: .whitespaces)
            var value = trimmed[trimmed.index(after: eqIndex)...]
                .trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 {
                value = String(value.dropFirst().dropLast())
            }
            values[key] = value
        }

        guard let endpoint = values["server_endpoint"], !endpoint.isEmpty else {
            return nil
        }
        let tlsMode: MobileTlsAuthMode = values["tls_auth_mode"] == "system_ca"
            ? .systemCa
            : .spkiPin

        return BootstrapSummary(
            serverEndpoint: endpoint,
            tlsAuthMode: tlsMode,
            activePin: nonEmpty(values["active_pin"]),
            nextPin: nonEmpty(values["next_pin"]),
            nodeName: nonEmpty(values["node_name"]),
            nodeId: nonEmpty(values["node_id"]),
            overlayIp: nonEmpty(values["overlay_ip"]),
            fqdn: nonEmpty(values["fqdn"])
        )
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return value
    }
}

/// Protocol abstracting App Group file storage for testability.
public protocol AppGroupFileManaging: Sendable {
    var rootURL: URL { get }
    var stateDirectoryURL: URL { get }
    var diagnosticsDirectoryURL: URL { get }
    var logsDirectoryURL: URL { get }

    func readStateFile(fileName: String) throws -> Data?
    func writeStateFile(fileName: String, content: Data) throws
    func deleteStateFile(fileName: String) throws
    func makeBugreportDestinationURL(timestampMs: UInt64) throws -> URL
    func deleteDiagnosticsFile(at url: URL) throws
}

/// Thread-safe App Group container store using `NSFileCoordinator` and atomic writes.
public final class CoordinatedAppGroupStore: AppGroupFileManaging, Sendable {
    public let rootURL: URL
    public let stateDirectoryURL: URL
    public let diagnosticsDirectoryURL: URL
    public let logsDirectoryURL: URL

    private let logger = MeshLogger(category: "app_group")

    /// Initializes the store rooted at `group.dev.meshvpn.ios` (or custom URL in unit tests).
    public init(rootDirectoryURL: URL? = nil) throws {
        let resolvedRoot: URL
        if let rootDirectoryURL {
            resolvedRoot = rootDirectoryURL
        } else if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: MeshConstants.appGroupIdentifier
        ) {
            resolvedRoot = containerURL
        } else {
            #if targetEnvironment(simulator)
            let fallback = FileManager.default.temporaryDirectory
                .appendingPathComponent("MeshAppGroupSimulator", isDirectory: true)
            resolvedRoot = fallback
            #else
            throw MobileError.PermissionDenied(
                errorCode: "E_PERM_DENIED",
                message: "App Group container unavailable"
            )
            #endif
        }

        self.rootURL = resolvedRoot
        self.stateDirectoryURL = resolvedRoot.appendingPathComponent(
            MeshConstants.stateDirectoryName,
            isDirectory: true
        )
        self.diagnosticsDirectoryURL = resolvedRoot.appendingPathComponent(
            MeshConstants.diagnosticsDirectoryName,
            isDirectory: true
        )
        self.logsDirectoryURL = resolvedRoot.appendingPathComponent(
            MeshConstants.logsDirectoryName,
            isDirectory: true
        )
        try ensureDirectoriesExist()
    }

    public func readStateFile(fileName: String) throws -> Data? {
        let fileURL = try validatedStateFileURL(fileName: fileName)
        var readResult: Data?
        var readError: Error?
        var coordinatorError: NSError?

        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(
            readingItemAt: fileURL,
            options: [],
            error: &coordinatorError
        ) { coordinatedURL in
            guard FileManager.default.fileExists(atPath: coordinatedURL.path) else {
                return
            }
            do {
                readResult = try Data(contentsOf: coordinatedURL, options: [.mappedIfSafe])
            } catch {
                readError = error
            }
        }

        if let coordinatorError {
            throw wrapIOError(coordinatorError, action: "coordinate read \(fileName)")
        }
        if let readError {
            throw wrapIOError(readError, action: "read \(fileName)")
        }
        return readResult
    }

    public func writeStateFile(fileName: String, content: Data) throws {
        try ensureDirectoriesExist()
        let fileURL = try validatedStateFileURL(fileName: fileName)
        var writeError: Error?
        var coordinatorError: NSError?

        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(
            writingItemAt: fileURL,
            options: [.forReplacing],
            error: &coordinatorError
        ) { coordinatedURL in
            do {
                try content.write(
                    to: coordinatedURL,
                    options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
                )
            } catch {
                writeError = error
            }
        }

        if let coordinatorError {
            throw wrapIOError(coordinatorError, action: "coordinate write \(fileName)")
        }
        if let writeError {
            throw wrapIOError(writeError, action: "write \(fileName)")
        }
    }

    public func deleteStateFile(fileName: String) throws {
        let fileURL = try validatedStateFileURL(fileName: fileName)
        var deleteError: Error?
        var coordinatorError: NSError?

        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(
            writingItemAt: fileURL,
            options: [.forDeleting],
            error: &coordinatorError
        ) { coordinatedURL in
            guard FileManager.default.fileExists(atPath: coordinatedURL.path) else {
                return
            }
            do {
                try FileManager.default.removeItem(at: coordinatedURL)
            } catch {
                deleteError = error
            }
        }

        if let coordinatorError {
            throw wrapIOError(coordinatorError, action: "coordinate delete \(fileName)")
        }
        if let deleteError {
            throw wrapIOError(deleteError, action: "delete \(fileName)")
        }
    }

    public func makeBugreportDestinationURL(timestampMs: UInt64) throws -> URL {
        try ensureDirectoriesExist()
        let fileName = "mesh-bugreport-\(timestampMs).tar"
        return diagnosticsDirectoryURL.appendingPathComponent(fileName, isDirectory: false)
    }

    public func deleteDiagnosticsFile(at url: URL) throws {
        let standardizedDiagnostics = diagnosticsDirectoryURL.standardizedFileURL.path
        let standardizedTarget = url.standardizedFileURL.path
        guard standardizedTarget.hasPrefix(standardizedDiagnostics + "/") else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Refusing to delete diagnostics file outside diagnostics container"
            )
        }
        var deleteError: Error?
        var coordinatorError: NSError?
        let coordinator = NSFileCoordinator(filePresenter: nil)
        coordinator.coordinate(
            writingItemAt: url,
            options: [.forDeleting],
            error: &coordinatorError
        ) { coordinatedURL in
            guard FileManager.default.fileExists(atPath: coordinatedURL.path) else {
                return
            }
            do {
                try FileManager.default.removeItem(at: coordinatedURL)
            } catch {
                deleteError = error
            }
        }
        if let coordinatorError {
            throw wrapIOError(coordinatorError, action: "coordinate delete bugreport")
        }
        if let deleteError {
            throw wrapIOError(deleteError, action: "delete bugreport")
        }
    }

    /// Reads and parses non-secret bootstrap metadata for UI confirmation and extension startup.
    public func loadBootstrapSummary() throws -> BootstrapSummary? {
        guard let data = try readStateFile(fileName: MeshConstants.bootstrapFileName),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        return BootstrapSummary.parse(tomlText: text)
    }

    /// Loads the latest cached `MobileStatusSnapshot` written to App Group when tunnel is offline.
    public func loadCachedStatusSnapshot() throws -> MobileStatusSnapshot? {
        guard let data = try readStateFile(fileName: MeshConstants.statusSnapshotFileName) else {
            return nil
        }
        return try TunnelIpcCodec.decodeStatusSnapshot(from: data)
    }

    /// Removes sealed identity, bootstrap, netmap cache, and cached status during identity reset.
    public func wipeEnrolledStateFiles() throws {
        let targets = [
            MeshConstants.sealedIdentityFileName,
            MeshConstants.bootstrapFileName,
            MeshConstants.netmapCacheFileName,
            MeshConstants.statusSnapshotFileName
        ]
        for fileName in targets {
            try deleteStateFile(fileName: fileName)
        }
        logger.notice("app_group_state_wiped")
    }

    private func ensureDirectoriesExist() throws {
        let fileManager = FileManager.default
        let attrs: [FileAttributeKey: Any] = [
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
        ]
        for dirURL in [stateDirectoryURL, diagnosticsDirectoryURL, logsDirectoryURL] {
            if !fileManager.fileExists(atPath: dirURL.path) {
                do {
                    try fileManager.createDirectory(
                        at: dirURL,
                        withIntermediateDirectories: true,
                        attributes: attrs
                    )
                } catch {
                    throw wrapIOError(error, action: "create directory")
                }
            }
        }
    }

    private func validatedStateFileURL(fileName: String) throws -> URL {
        guard !fileName.isEmpty,
              !fileName.contains("/"),
              !fileName.contains("\\"),
              !fileName.contains(".."),
              !fileName.contains("\0") else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Invalid state filename"
            )
        }
        return stateDirectoryURL.appendingPathComponent(fileName, isDirectory: false)
    }

    private func wrapIOError(_ error: Error, action: String) -> MobileError {
        let nsError = error as NSError
        let code = OSStatus(nsError.code)
        let isCocoaReadPerm = nsError.domain == NSCocoaErrorDomain
            && nsError.code == NSFileReadNoPermissionError
        if code == MeshConstants.errSecInteractionNotAllowedCode || isCocoaReadPerm {
            logger.warning("app_group_io_locked", detail: action)
            return MobileError.DeviceLocked(
                errorCode: "E_DEVICE_LOCKED",
                message: "Protected App Group file unavailable before first unlock"
            )
        }
        logger.error("app_group_io_failed", detail: "\(action): \(nsError.localizedDescription)")
        return MobileError.Internal(
            errorCode: "E_INTERNAL",
            message: "App Group storage error during \(action)"
        )
    }
}
