import Combine
import Foundation
import MeshCoreKit
import NetworkExtension
import UIKit

/// Draft prepared for explicit user review before transmitting enrollment credentials (`US-091`).
public struct EnrollmentConfirmationDraft: Identifiable, Sendable {
    public let id = UUID()
    public let serverEndpoint: String
    public let portOverride: UInt16?
    public let tlsAuthMode: MobileTlsAuthMode
    public let serverPin: String?
    public let nodeName: String?
    public let maskedPreauthPreview: String
    public let session: MobilePendingJoinSession
    public let isRotation: Bool
}

/// Top-level 3-tab navigation destinations when enrolled (`ADR-028`, `US-119`).
public enum AppTab: String, CaseIterable, Hashable, Sendable {
    case status
    case peers
    case settings
}

/// Main `@MainActor` state store driving `MeshApp` SwiftUI screens, tunnel control, and IPC.
@MainActor
public final class AppViewModel: ObservableObject {
    @Published public var selectedTab: AppTab = .status
    @Published public var isEnrolled = false
    @Published public var bootstrapSummary: BootstrapSummary?
    @Published public var tunnelStatus: MeshTunnelConnectionStatus = .disconnected
    @Published public var isOnDemandEnabled = false
    @Published public var statusSnapshot: MobileStatusSnapshot?
    @Published public var peersTruncatedNotice = false
    @Published public var totalPeerCount: Int?
    @Published public var pendingConfirmation: EnrollmentConfirmationDraft?
    @Published public var lastPingResponse: MobilePingResponse?
    @Published public var lastNetcheckResponse: MobileNetcheckResponse?
    @Published public var shareBugreportURL: URL?
    @Published public var activeError: MeshUserFacingError?
    @Published public var statusBannerMessage: String?
    @Published public var isBusy = false

    // Onboarding / update form state (never persisted; secrets cleared immediately).
    @Published public var manualServerEndpoint = ""
    @Published public var manualPortText = ""
    @Published public var manualPreauthKey = ""
    @Published public var manualTlsAuthMode: MobileTlsAuthMode = .spkiPin
    @Published public var manualServerPin = ""
    @Published public var manualNodeName = ""

    let appGroupStore: AppGroupFileManaging
    let dekStore: KeychainDekStore
    let tunnelManager: TunnelManagerClient
    let enrollmentClient: EnrollmentClientProtocol
    let biometricAuthorizer: BiometricAuthorizing
    let logger = MeshLogger(category: "app_vm")
    private var statusObserverTask: Task<Void, Never>?
    var clipboardClearTask: Task<Void, Never>?

    public init(
        appGroupStore: AppGroupFileManaging,
        dekStore: KeychainDekStore,
        tunnelManager: TunnelManagerClient,
        enrollmentClient: EnrollmentClientProtocol = LiveEnrollmentClient(),
        biometricAuthorizer: BiometricAuthorizing = LocalAuthBiometricAuthorizer()
    ) {
        self.appGroupStore = appGroupStore
        self.dekStore = dekStore
        self.tunnelManager = tunnelManager
        self.enrollmentClient = enrollmentClient
        self.biometricAuthorizer = biometricAuthorizer
    }

    /// Initializes the live container-app dependencies safely on startup.
    public static func makeLive() -> AppViewModel {
        do {
            let store = try CoordinatedAppGroupStore()
            return AppViewModel(
                appGroupStore: store,
                dekStore: KeychainDekStore(),
                tunnelManager: TunnelManagerClient()
            )
        } catch {
            let fallbackRoot = FileManager.default.temporaryDirectory
                .appendingPathComponent("MeshFallback", isDirectory: true)
            let fallbackStore: any AppGroupFileManaging
            if let diskStore = try? CoordinatedAppGroupStore(rootDirectoryURL: fallbackRoot) {
                fallbackStore = diskStore
            } else {
                fallbackStore = InMemoryFallbackAppGroupStore(rootURL: fallbackRoot)
            }
            let vm = AppViewModel(
                appGroupStore: fallbackStore,
                dekStore: KeychainDekStore(),
                tunnelManager: TunnelManagerClient()
            )
            vm.activeError = MeshErrorMapper.map(error)
            return vm
        }
    }

    /// Starts observing system `NEVPNStatusDidChange` notifications and loads initial state.
    public func startObserving() async {
        await refreshAllState()
        guard statusObserverTask == nil else { return }
        statusObserverTask = Task.detached { [weak self] in
            let stream = NotificationCenter.default.notifications(
                named: .NEVPNStatusDidChange
            )
            for await _ in stream {
                guard !Task.isCancelled else { break }
                await self?.refreshAllState()
            }
        }
    }

    public func stopObserving() {
        statusObserverTask?.cancel()
        statusObserverTask = nil
        clipboardClearTask?.cancel()
        clipboardClearTask = nil
    }

    /// Refreshes enrollment state, VPN preferences, live IPC telemetry, or cached snapshot.
    public func refreshAllState() async {
        do {
            let bootstrapData = try appGroupStore.readStateFile(
                fileName: MeshConstants.bootstrapFileName
            )
            if let bootstrapData,
               let text = String(data: bootstrapData, encoding: .utf8),
               let summary = BootstrapSummary.parse(tomlText: text) {
                self.bootstrapSummary = summary
                self.isEnrolled = true
            } else {
                self.bootstrapSummary = nil
                self.isEnrolled = false
            }
        } catch {
            self.activeError = MeshErrorMapper.map(error)
        }

        if let config = try? await tunnelManager.refreshConfiguration() {
            self.tunnelStatus = config.status
            self.isOnDemandEnabled = config.isOnDemandEnabled
        }

        await refreshStatusTelemetry()
    }

    /// Fetches live snapshot over App Group IPC when connected, or reads cached snapshot offline.
    public func refreshStatusTelemetry() async {
        if tunnelStatus == .connected || tunnelStatus == .reasserting {
            do {
                let response = try await tunnelManager.sendIpc(
                    IosTunnelIpcRequest(action: .getStatus)
                )
                if response.ok, let codableStatus = response.status {
                    self.peersTruncatedNotice = response.peersTruncated
                    self.totalPeerCount = response.totalPeerCount
                    if response.peersTruncated, let full = try? loadCachedSnapshot() {
                        self.statusSnapshot = full
                    } else {
                        self.statusSnapshot = codableStatus.toMobileModel()
                    }
                    return
                }
            } catch {
                logger.warning("ipc_get_status_fallback", detail: error.localizedDescription)
            }
        }

        self.peersTruncatedNotice = false
        self.totalPeerCount = nil
        if let cached = try? loadCachedSnapshot() {
            self.statusSnapshot = cached
        }
    }

    /// Copies non-secret overlay IP or FQDN without scheduling a 30s SEC-01 wipe (`US-121`).
    public func copyNonSecretAddress(_ value: String) {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        #if canImport(UIKit)
        UIPasteboard.general.string = trimmed
        #endif
    }

    func makeContainerBridge() -> IosPlatformBridge {
        IosPlatformBridge(
            dekStore: dekStore,
            appGroupStore: appGroupStore,
            initialUnderlay: UnderlayPathConverter.probeCurrentSnapshot()
        )
    }

    func makeEngineInitConfig(defaultNodeName: String?) -> MobileEngineInitConfig {
        MobileEngineInitConfig(
            platform: .ios,
            agentVersion: MeshConstants.agentVersion,
            defaultNodeName: defaultNodeName,
            logDirPath: appGroupStore.logsDirectoryURL.path
        )
    }

    func loadCachedSnapshot() throws -> MobileStatusSnapshot? {
        guard let data = try appGroupStore.readStateFile(
            fileName: MeshConstants.statusSnapshotFileName
        ) else {
            return nil
        }
        return try TunnelIpcCodec.decodeStatusSnapshot(from: data)
    }

    func nonEmptyTrimmed(_ text: String?) -> String? {
        guard let trimmed = text?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }

    func handleBiometricFailure(_ outcome: BiometricAuthOutcome) {
        switch outcome {
        case .authorized, .cancelled:
            break
        case .unavailable(let msg):
            activeError = MeshUserFacingError(
                code: "E_AUTH_UNAVAILABLE",
                title: "Authentication Unavailable",
                message: msg
            )
        case .failed(let msg):
            activeError = MeshUserFacingError(
                code: "E_AUTH_FAILED",
                title: "Authentication Failed",
                message: msg
            )
        }
    }
}

/// Safe fallback App Group file store used only if container resolution fails before alerting user.
private final class InMemoryFallbackAppGroupStore: AppGroupFileManaging, Sendable {
    let rootURL: URL
    let stateDirectoryURL: URL
    let diagnosticsDirectoryURL: URL
    let logsDirectoryURL: URL

    init(rootURL: URL) {
        self.rootURL = rootURL
        self.stateDirectoryURL = rootURL.appendingPathComponent("state", isDirectory: true)
        self.diagnosticsDirectoryURL = rootURL.appendingPathComponent(
            "diagnostics",
            isDirectory: true
        )
        self.logsDirectoryURL = rootURL.appendingPathComponent("logs", isDirectory: true)
    }

    func readStateFile(fileName: String) throws -> Data? { nil }
    func writeStateFile(fileName: String, content: Data) throws {}
    func deleteStateFile(fileName: String) throws {}
    func makeBugreportDestinationURL(timestampMs: UInt64) throws -> URL {
        diagnosticsDirectoryURL.appendingPathComponent("mesh-bugreport-\(timestampMs).tar")
    }
    func deleteDiagnosticsFile(at url: URL) throws {}
}
