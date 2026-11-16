import Foundation
@preconcurrency import NetworkExtension

/// Observable tunnel connection phase decoupled from `NEVPNStatus` for SwiftUI & XCTest.
public enum MeshTunnelConnectionStatus: String, Sendable, Equatable {
    case invalid
    case disconnected
    case connecting
    case connected
    case reasserting
    case disconnecting

    public init(neStatus: NEVPNStatus) {
        switch neStatus {
        case .invalid: self = .invalid
        case .disconnected: self = .disconnected
        case .connecting: self = .connecting
        case .connected: self = .connected
        case .reasserting: self = .reasserting
        case .disconnecting: self = .disconnecting
        @unknown default: self = .disconnected
        }
    }
}

/// Non-secret VPN manager state returned to UI & unit tests.
public struct TunnelConfigurationSnapshot: Sendable, Equatable {
    public let status: MeshTunnelConnectionStatus
    public let isEnabled: Bool
    public let isOnDemandEnabled: Bool
    public let serverEndpoint: String?

    public init(
        status: MeshTunnelConnectionStatus,
        isEnabled: Bool,
        isOnDemandEnabled: Bool,
        serverEndpoint: String?
    ) {
        self.status = status
        self.isEnabled = isEnabled
        self.isOnDemandEnabled = isOnDemandEnabled
        self.serverEndpoint = serverEndpoint
    }
}

/// Testable adapter wrapping `NETunnelProviderManager` lifecycle operations on `@MainActor`.
@MainActor
public protocol VPNManagerHandling: AnyObject {
    var isEnabled: Bool { get set }
    var isOnDemandEnabled: Bool { get set }
    var onDemandRules: [NEOnDemandRule]? { get set }
    var localizedDescription: String? { get set }
    var providerConfiguration: [String: Any]? { get set }
    var providerServerAddress: String? { get set }
    var connectionStatus: MeshTunnelConnectionStatus { get }

    func loadFromPreferences() async throws
    func saveToPreferences() async throws
    func removeFromPreferences() async throws
    func startTunnel() throws
    func stopTunnel()
    func sendProviderMessage(_ data: Data) async throws -> Data?
}

/// Abstract factory loading/creating `VPNManagerHandling` profiles.
@MainActor
public protocol VPNManagerStoring: AnyObject {
    func loadMeshManagers() async throws -> [VPNManagerHandling]
    func makeNewManager() -> VPNManagerHandling
}

/// Production wrapper around Apple's `NETunnelProviderManager`.
@MainActor
public final class SystemVPNManagerHandle: VPNManagerHandling {
    private let manager: NETunnelProviderManager

    public init(manager: NETunnelProviderManager) {
        self.manager = manager
    }

    public var isEnabled: Bool {
        get { manager.isEnabled }
        set { manager.isEnabled = newValue }
    }

    public var isOnDemandEnabled: Bool {
        get { manager.isOnDemandEnabled }
        set { manager.isOnDemandEnabled = newValue }
    }

    public var onDemandRules: [NEOnDemandRule]? {
        get { manager.onDemandRules }
        set { manager.onDemandRules = newValue }
    }

    public var localizedDescription: String? {
        get { manager.localizedDescription }
        set { manager.localizedDescription = newValue }
    }

    public var providerConfiguration: [String: Any]? {
        get { (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration }
        set {
            let proto = ensureProtocol()
            proto.providerConfiguration = newValue
            manager.protocolConfiguration = proto
        }
    }

    public var providerServerAddress: String? {
        get { manager.protocolConfiguration?.serverAddress }
        set {
            let proto = ensureProtocol()
            proto.serverAddress = newValue
            manager.protocolConfiguration = proto
        }
    }

    public var connectionStatus: MeshTunnelConnectionStatus {
        MeshTunnelConnectionStatus(neStatus: manager.connection.status)
    }

    public func loadFromPreferences() async throws {
        try await manager.loadFromPreferences()
    }

    public func saveToPreferences() async throws {
        try await manager.saveToPreferences()
    }

    public func removeFromPreferences() async throws {
        try await manager.removeFromPreferences()
    }

    public func startTunnel() throws {
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw MobileError.Internal(
                errorCode: "E_INTERNAL",
                message: "Unexpected VPN connection session type"
            )
        }
        try session.startTunnel(options: nil)
    }

    public func stopTunnel() {
        manager.connection.stopVPNTunnel()
    }

    public func sendProviderMessage(_ data: Data) async throws -> Data? {
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw MobileError.Unavailable(
                errorCode: "E_UNAVAILABLE",
                message: "Tunnel session is not active"
            )
        }
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { responseData in
                    continuation.resume(returning: responseData)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func ensureProtocol() -> NETunnelProviderProtocol {
        if let existing = manager.protocolConfiguration as? NETunnelProviderProtocol {
            return existing
        }
        let created = NETunnelProviderProtocol()
        created.providerBundleIdentifier = MeshConstants.tunnelBundleIdentifier
        return created
    }
}

/// Production store discovering `NETunnelProviderManager` entries for `MeshPacketTunnel`.
@MainActor
public final class SystemVPNManagerStore: VPNManagerStoring {
    public init() {}

    public func loadMeshManagers() async throws -> [VPNManagerHandling] {
        let all = try await NETunnelProviderManager.loadAllFromPreferences()
        return all.filter { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == MeshConstants.tunnelBundleIdentifier
        }.map(SystemVPNManagerHandle.init)
    }

    public func makeNewManager() -> VPNManagerHandling {
        let manager = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = MeshConstants.tunnelBundleIdentifier
        manager.protocolConfiguration = proto
        manager.localizedDescription = MeshConstants.tunnelProviderDescription
        return SystemVPNManagerHandle(manager: manager)
    }
}

/// Coordinates VPN preferences, Connect/Disconnect, On-Demand, and `<= 4096 B` IPC messages.
@MainActor
public final class TunnelManagerClient {
    private let store: VPNManagerStoring
    private let logger = MeshLogger(category: "tunnel_mgr")

    public init(store: VPNManagerStoring = SystemVPNManagerStore()) {
        self.store = store
    }

    /// Reads the current saved manager configuration without modifying preferences.
    public func refreshConfiguration() async throws -> TunnelConfigurationSnapshot {
        let managers = try await store.loadMeshManagers()
        guard let existing = managers.first else {
            return TunnelConfigurationSnapshot(
                status: .invalid,
                isEnabled: false,
                isOnDemandEnabled: false,
                serverEndpoint: nil
            )
        }
        try await existing.loadFromPreferences()
        return snapshot(for: existing)
    }

    /// Saves non-secret provider metadata (`0` `mpk_*` / private keys) and starts the tunnel.
    public func connect(
        bootstrap: BootstrapSummary,
        enableOnDemand: Bool
    ) async throws -> TunnelConfigurationSnapshot {
        let manager = try await loadOrCreateManager()
        try applyNonSecretConfiguration(bootstrap: bootstrap, to: manager)
        manager.isEnabled = true
        applyOnDemand(enableOnDemand, to: manager)

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        try manager.startTunnel()
        logger.notice("tunnel_start_requested", detail: bootstrap.serverEndpoint)
        return snapshot(for: manager)
    }

    /// Manually stops the tunnel.
    /// Disables On-Demand and saves preferences BEFORE calling `stopTunnel` (`US-092`).
    public func disconnectManually() async throws -> TunnelConfigurationSnapshot {
        let managers = try await store.loadMeshManagers()
        guard let manager = managers.first else {
            return TunnelConfigurationSnapshot(
                status: .invalid,
                isEnabled: false,
                isOnDemandEnabled: false,
                serverEndpoint: nil
            )
        }
        try await manager.loadFromPreferences()
        if manager.isOnDemandEnabled || manager.onDemandRules != nil {
            manager.isOnDemandEnabled = false
            manager.onDemandRules = nil
        }
        try await manager.saveToPreferences()
        manager.stopTunnel()
        logger.notice("tunnel_manual_disconnect_requested")
        return snapshot(for: manager)
    }

    /// Toggles `On-Demand` rules and persists VPN configuration.
    public func setOnDemandEnabled(
        _ enabled: Bool,
        bootstrap: BootstrapSummary?
    ) async throws -> TunnelConfigurationSnapshot {
        let manager = try await loadOrCreateManager()
        if let bootstrap {
            try applyNonSecretConfiguration(bootstrap: bootstrap, to: manager)
        }
        manager.isEnabled = true
        applyOnDemand(enabled, to: manager)
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        return snapshot(for: manager)
    }

    /// Removes the VPN profile when resetting local node identity.
    public func removeProfile() async throws {
        let managers = try await store.loadMeshManagers()
        for manager in managers {
            if manager.isOnDemandEnabled {
                manager.isOnDemandEnabled = false
                manager.onDemandRules = nil
                try? await manager.saveToPreferences()
            }
            manager.stopTunnel()
            try await manager.removeFromPreferences()
        }
    }

    /// Sends a bounded (`<= 4096 B`) IPC request to the running `MeshPacketTunnel` extension.
    public func sendIpc(_ request: IosTunnelIpcRequest) async throws -> IosTunnelIpcResponse {
        let managers = try await store.loadMeshManagers()
        guard let manager = managers.first else {
            throw MobileError.Unavailable(
                errorCode: "E_UNAVAILABLE",
                message: "VPN configuration is not installed"
            )
        }
        return try await sendIpcToManager(manager, request: request)
    }

    /// Validates that `providerConfiguration` contains zero secret keys (`BLK-MOB-G2-02`).
    public static func buildValidatedProviderConfiguration(
        from bootstrap: BootstrapSummary
    ) throws -> [String: Any] {
        var dict: [String: Any] = [
            MeshConstants.providerConfigKeyServerEndpoint: bootstrap.serverEndpoint,
            MeshConstants.providerConfigKeyTlsAuthMode:
                bootstrap.tlsAuthMode == .spkiPin ? "spki_pin" : "system_ca"
        ]
        if let pin = bootstrap.activePin {
            dict[MeshConstants.providerConfigKeyServerPin] = pin
        }
        if let nodeName = bootstrap.nodeName {
            dict[MeshConstants.providerConfigKeyNodeName] = nodeName
        }
        for key in dict.keys where MeshConstants.isForbiddenProviderConfigKey(key) {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Forbidden secret key detected in providerConfiguration"
            )
        }
        return dict
    }

    private func loadOrCreateManager() async throws -> VPNManagerHandling {
        let existing = try await store.loadMeshManagers()
        if let first = existing.first {
            try await first.loadFromPreferences()
            return first
        }
        return store.makeNewManager()
    }

    private func applyNonSecretConfiguration(
        bootstrap: BootstrapSummary,
        to manager: VPNManagerHandling
    ) throws {
        manager.localizedDescription = MeshConstants.tunnelProviderDescription
        manager.providerServerAddress = bootstrap.serverEndpoint
        manager.providerConfiguration = try Self.buildValidatedProviderConfiguration(
            from: bootstrap
        )
    }

    private func applyOnDemand(_ enabled: Bool, to manager: VPNManagerHandling) {
        manager.isOnDemandEnabled = enabled
        if enabled {
            let connectRule = NEOnDemandRuleConnect()
            connectRule.interfaceTypeMatch = .any
            manager.onDemandRules = [connectRule]
        } else {
            manager.onDemandRules = nil
        }
    }

    private func sendIpcToManager(
        _ manager: VPNManagerHandling,
        request: IosTunnelIpcRequest
    ) async throws -> IosTunnelIpcResponse {
        let requestData = try TunnelIpcCodec.encodeRequest(request)
        guard let rawResponse = try await manager.sendProviderMessage(requestData) else {
            throw MobileError.Unavailable(
                errorCode: "E_UNAVAILABLE",
                message: "Tunnel extension returned an empty IPC response"
            )
        }
        return try TunnelIpcCodec.decodeResponse(from: rawResponse)
    }

    private func snapshot(for manager: VPNManagerHandling) -> TunnelConfigurationSnapshot {
        TunnelConfigurationSnapshot(
            status: manager.connectionStatus,
            isEnabled: manager.isEnabled,
            isOnDemandEnabled: manager.isOnDemandEnabled,
            serverEndpoint: manager.providerServerAddress
        )
    }
}
