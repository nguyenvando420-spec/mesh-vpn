import Combine
import Foundation
import ServiceManagement

/// Controls macOS Launch-at-Login (`SMAppService.mainApp`) with test double injection (`US-109`).
@MainActor
public protocol LaunchAtLoginControlling: AnyObject, Sendable {
    var isEnabled: Bool { get }
    func setEnabled(_ enabled: Bool) throws
}

/// Live `SMAppService.mainApp` controller guarded for unbundled unit-test execution.
@MainActor
public final class AppKitLaunchAtLoginController: LaunchAtLoginControlling {
    public init() {}

    public var isEnabled: Bool {
        guard Bundle.main.bundleURL.pathExtension == "app" else {
            return false
        }
        return SMAppService.mainApp.status == .enabled
    }

    public func setEnabled(_ enabled: Bool) throws {
        guard Bundle.main.bundleURL.pathExtension == "app" else {
            throw AdminPrivilegeError.scriptMissing(
                "Launch at Login requires running Mesh VPN from an installed .app bundle."
            )
        }
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
    }
}

/// Checks whether the `meshd` LaunchDaemon and binary exist on disk (`ADR-025`).
public protocol ServicePresenceChecking: Sendable {
    func isServiceInstalled() -> Bool
}

/// Live file-system checker inspecting `internal.mesh.meshd.plist` and `meshd` binary.
public struct DefaultServicePresenceChecker: ServicePresenceChecking {
    private let plistPath: String
    private let daemonBinaryPath: String

    public init(
        plistPath: String = AgentDefaults.launchdPlistPath,
        daemonBinaryPath: String = AgentDefaults.daemonBinaryPath
    ) {
        self.plistPath = plistPath
        self.daemonBinaryPath = daemonBinaryPath
    }

    public func isServiceInstalled() -> Bool {
        let fileManager = FileManager.default
        return fileManager.fileExists(atPath: plistPath)
            && fileManager.isExecutableFile(atPath: daemonBinaryPath)
    }
}

/// Central `@MainActor` store coordinating Menu Bar status, Dashboard polling, IPC, and secrets.
@MainActor
public final class DesktopStore: ObservableObject {
    @Published public internal(set) var uiState: DesktopUiState = .serviceNotInstalled
    @Published public internal(set) var menuBarGroup: MenuBarStatusGroup = .serviceOffline
    @Published public internal(set) var isDegradedTunnel: Bool = false
    @Published public internal(set) var isManuallyDisconnected: Bool = false
    @Published public internal(set) var status: AgentStatusResponse?
    @Published public internal(set) var versionBanner: DaemonVersionBannerState = .unknown
    @Published public internal(set) var isBusy: Bool = false
    @Published public internal(set) var busyMessage: String?
    @Published public internal(set) var lastActionError: DesktopUserFacingError?
    @Published public internal(set) var lastToastMessage: String?
    @Published public internal(set) var pendingEnrollmentDraft: EnrollmentConfirmationDraft?
    @Published public internal(set) var latestNetcheck: NetcheckResponse?
    @Published public internal(set) var latestPing: PingResponse?
    @Published public internal(set) var launchAtLoginEnabled: Bool = false
    @Published public internal(set) var isPollingSuspended: Bool = false
    @Published public internal(set) var isDashboardOpen: Bool = false

    let transport: any DesktopIpcTransport
    let privilegeHelper: any AdminPrivilegeExecuting
    public let clipboardAutoClear: ClipboardAutoClear
    let serviceChecker: any ServicePresenceChecking
    let launchAtLogin: any LaunchAtLoginControlling
    let roSocketPath: String
    let adminSocketPath: String
    let daemonBinaryPath: String
    let appVersion: String
    let dashboardPollIntervalSeconds: TimeInterval
    let idlePollIntervalSeconds: TimeInterval
    let logger = SafeOsLogger(category: "DesktopStore")

    private var pollingTask: Task<Void, Never>?
    private var pollingSuspendedCount: Int = 0
    private var isRefreshing: Bool = false
    var lastConnectError: IpcClientError?

    public init(
        transport: any DesktopIpcTransport = UdsIpcClient(),
        privilegeHelper: any AdminPrivilegeExecuting = AdminPrivilegeHelper(),
        clipboardAutoClear: ClipboardAutoClear? = nil,
        serviceChecker: any ServicePresenceChecking = DefaultServicePresenceChecker(),
        launchAtLogin: (any LaunchAtLoginControlling)? = nil,
        roSocketPath: String = AgentDefaults.roSocketPath,
        adminSocketPath: String = AgentDefaults.adminSocketPath,
        daemonBinaryPath: String = AgentDefaults.daemonBinaryPath,
        appVersion: String = AgentDefaults.appBundleVersion,
        dashboardPollIntervalSeconds: TimeInterval = AgentDefaults.dashboardPollIntervalSeconds,
        idlePollIntervalSeconds: TimeInterval = AgentDefaults.menuBarIdlePollIntervalSeconds
    ) {
        self.transport = transport
        self.privilegeHelper = privilegeHelper
        self.clipboardAutoClear = clipboardAutoClear ?? ClipboardAutoClear()
        self.serviceChecker = serviceChecker
        self.launchAtLogin = launchAtLogin ?? AppKitLaunchAtLoginController()
        self.roSocketPath = roSocketPath
        self.adminSocketPath = adminSocketPath
        self.daemonBinaryPath = daemonBinaryPath
        self.appVersion = appVersion
        self.dashboardPollIntervalSeconds = max(dashboardPollIntervalSeconds, 0.02)
        self.idlePollIntervalSeconds = max(idlePollIntervalSeconds, 0.02)
        self.launchAtLoginEnabled = self.launchAtLogin.isEnabled
        recomputeDerivedUiState()
    }

    public var sortedPeers: [AgentPeerStatus] {
        let peers = status?.peers ?? []
        return peers.sorted { lhs, rhs in
            if lhs.online != rhs.online {
                return lhs.online && !rhs.online
            }
            let nameOrder = lhs.name.localizedCaseInsensitiveCompare(rhs.name)
            if nameOrder != .orderedSame {
                return nameOrder == .orderedAscending
            }
            return lhs.nodeId < rhs.nodeId
        }
    }

    public var onlinePeerCount: Int {
        (status?.peers ?? []).filter(\.online).count
    }

    public var directPeerCount: Int {
        (status?.peers ?? []).filter { $0.online && $0.activePath == .direct }.count
    }

    public var relayPeerCount: Int {
        (status?.peers ?? []).filter { $0.online && $0.activePath == .relay }.count
    }

    public var currentPollIntervalSeconds: TimeInterval {
        isDashboardOpen ? dashboardPollIntervalSeconds : idlePollIntervalSeconds
    }

    public func startMonitoring() {
        guard pollingTask == nil else {
            return
        }
        launchAtLoginEnabled = launchAtLogin.isEnabled
        logger.info("monitoring_started")
        pollingTask = Task { [weak self] in
            await self?.runPollingLoop()
        }
    }

    public func stopMonitoring() {
        pollingTask?.cancel()
        pollingTask = nil
        logger.info("monitoring_stopped")
    }

    public func setDashboardOpen(_ open: Bool) {
        let changed = isDashboardOpen != open
        isDashboardOpen = open
        if open && changed && pollingTask != nil && !isPollingSuspended {
            Task { [weak self] in
                await self?.refreshStatus(probeVersionIfNeeded: true)
            }
        }
    }

    public func refreshNow() async {
        await refreshStatus(probeVersionIfNeeded: true)
    }

    public func dismissError() {
        lastActionError = nil
        recomputeDerivedUiState()
    }

    public func dismissToast() {
        lastToastMessage = nil
    }

    public func prepareForKeepConnectedQuit() {
        _ = clipboardAutoClear.clearIfMatchingNow()
        stopMonitoring()
    }

    public func disconnectAndPrepareForQuit() async {
        _ = clipboardAutoClear.clearIfMatchingNow()
        stopMonitoring()
        _ = try? await transport.bringDown(socketPath: adminSocketPath)
    }

    func refreshStatus(probeVersionIfNeeded: Bool) async {
        guard !isPollingSuspended, !isRefreshing else {
            return
        }
        isRefreshing = true
        defer { isRefreshing = false }

        let serviceFilesPresent = serviceChecker.isServiceInstalled()
        do {
            let meta = try await transport.fetchStatus(socketPath: roSocketPath)
            status = meta.value
            lastConnectError = nil
            if meta.value.daemonState == .connected {
                lastActionError = nil
            }
            await updateVersionBanner(
                headerVersion: meta.agentVersionHeader,
                probeEndpointIfMissing: probeVersionIfNeeded || versionBanner == .unknown
            )
        } catch let ipcErr as IpcClientError {
            status = nil
            lastConnectError = ipcErr
            if serviceFilesPresent,
               case .serviceUnavailable = ipcErr,
               probeVersionIfNeeded || versionBanner == .unknown
            {
                if let offline = await transport.probeOfflineDaemonVersion(
                    binaryPath: daemonBinaryPath
                ) {
                    applyVersionStatus(offline)
                }
            }
        } catch {
            status = nil
            let detail = MeshSecretScrubber.scrub(error.localizedDescription)
            lastConnectError = .invalidResponse(detail)
        }
        recomputeDerivedUiState()
    }

    func runBusyAdminMutation(
        message: String,
        operation: @MainActor () async throws -> Void
    ) async -> Bool {
        guard !isBusy else {
            return false
        }
        isBusy = true
        busyMessage = message
        lastActionError = nil
        defer {
            isBusy = false
            busyMessage = nil
        }

        let succeeded = await withSuspendedPolling {
            do {
                try await operation()
                return true
            } catch {
                self.lastActionError = self.mapErrorToUserFacing(error)
                return false
            }
        }
        await refreshStatus(probeVersionIfNeeded: false)
        return succeeded
    }

    func withSuspendedPolling<T: Sendable>(
        _ operation: @MainActor () async throws -> T
    ) async rethrows -> T {
        pollingSuspendedCount += 1
        isPollingSuspended = true
        defer {
            pollingSuspendedCount = max(pollingSuspendedCount - 1, 0)
            isPollingSuspended = pollingSuspendedCount > 0
        }
        return try await operation()
    }

    func recomputeDerivedUiState() {
        let computed = DesktopStateMapper.compute(
            serviceFilesPresent: serviceChecker.isServiceInstalled(),
            statusResponse: status,
            connectFailure: lastConnectError,
            lastActionError: lastActionError
        )
        uiState = computed.uiState
        menuBarGroup = computed.menuBarGroup
        isDegradedTunnel = computed.isDegradedTunnel
        isManuallyDisconnected = computed.isManuallyDisconnected
    }

    private func runPollingLoop() async {
        await refreshStatus(probeVersionIfNeeded: true)
        while !Task.isCancelled {
            let startedAt = Date()
            while !Task.isCancelled {
                let targetInterval = currentPollIntervalSeconds
                let elapsed = Date().timeIntervalSince(startedAt)
                if elapsed >= targetInterval {
                    break
                }
                let remaining = targetInterval - elapsed
                let stepSeconds = min(0.25, max(remaining, 0.02))
                try? await Task.sleep(nanoseconds: UInt64(stepSeconds * 1_000_000_000))
            }
            if Task.isCancelled {
                break
            }
            if !isPollingSuspended {
                let needsProbe = versionBanner == .unknown
                await refreshStatus(probeVersionIfNeeded: needsProbe)
            }
        }
    }

    private func updateVersionBanner(
        headerVersion: String?,
        probeEndpointIfMissing: Bool
    ) async {
        if let header = headerVersion?.trimmingCharacters(in: .whitespacesAndNewlines),
           !header.isEmpty
        {
            applyVersionStatus(.version(header))
            return
        }
        guard probeEndpointIfMissing else {
            return
        }
        let endpointResult: Result<AgentVersionResponse, Error>
        do {
            let resp = try await transport.fetchVersion(socketPath: roSocketPath)
            endpointResult = .success(resp)
        } catch {
            endpointResult = .failure(error)
        }
        if let classified = try? UdsIpcClient.classifyVersionProbe(
            headerVersion: headerVersion,
            endpointResult: endpointResult
        ) {
            applyVersionStatus(classified)
        }
    }

    private func applyVersionStatus(_ versionStatus: AgentVersionStatus) {
        switch versionStatus {
        case .legacyPre030:
            versionBanner = .legacyPre030
        case .version(let daemonVersion):
            if daemonVersion == appVersion {
                versionBanner = .matched(daemonVersion)
            } else {
                versionBanner = .mismatch(daemon: daemonVersion, app: appVersion)
            }
        }
    }
}
