import Foundation
import MeshCoreKit

/// Abstracts zero-TUN container-app UniFFI calls so `AppViewModel` stays unit-testable.
public protocol EnrollmentClientProtocol: Sendable {
    func parseJoinUri(_ rawUri: String) throws -> MobileParsedJoinUri
    func createPendingJoinSession(_ rawPreauthKey: String) throws -> MobilePendingJoinSession
    func enrollOrRotateNode(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        enrollConfig: MobileEnrollConfig
    ) async throws -> MobileStatusSnapshot
    func updateServerConfig(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        setConfig: MobileSetConfig
    ) async throws -> MobileStatusSnapshot
    func exportOfflineBugreport(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        destPath: String
    ) async throws -> MobileBugreportResult
}

/// Live UniFFI enrollment client delegating directly to `MeshCoreKit` Rust FFI functions.
public struct LiveEnrollmentClient: EnrollmentClientProtocol, Sendable {
    public init() {}

    public func parseJoinUri(_ rawUri: String) throws -> MobileParsedJoinUri {
        try MeshCoreKit.parseMobileJoinUri(rawUri: rawUri)
    }

    public func createPendingJoinSession(
        _ rawPreauthKey: String
    ) throws -> MobilePendingJoinSession {
        try MeshCoreKit.createPendingJoinSession(rawPreauthKey: rawPreauthKey)
    }

    public func enrollOrRotateNode(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        enrollConfig: MobileEnrollConfig
    ) async throws -> MobileStatusSnapshot {
        try await mobileEnrollOrRotateNode(
            init: initConfig,
            bridge: bridge,
            cfg: enrollConfig
        )
    }

    public func updateServerConfig(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        setConfig: MobileSetConfig
    ) async throws -> MobileStatusSnapshot {
        let engine = try MobileEngine(init: initConfig, bridge: bridge)
        defer { try? engine.shutdown() }
        return try await engine.updateServerConfig(cfg: setConfig)
    }

    public func exportOfflineBugreport(
        initConfig: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        destPath: String
    ) async throws -> MobileBugreportResult {
        let engine = try MobileEngine(init: initConfig, bridge: bridge)
        defer { try? engine.shutdown() }
        return try await engine.exportBugreportToFile(destPath: destPath)
    }
}
