import Foundation
import os

/// Authoritative desktop constants matching Rust `mesh-core::defaults` (`ADR-023..025`).
public enum AgentDefaults: Sendable {
    public static let defaultControlTcpPort: UInt16 = 443
    public static let maxMobileJoinUriLen = 1_024
    public static let maxDnsHostnameLen = 253
    public static let maxPreauthKeyLen = 256
    public static let preauthKeyPrefix = "mpk_"
    public static let systemCaPinSentinel = "system-ca"
    public static let maxBugreportArchiveBytes: UInt64 = 20 * 1024 * 1024
    public static let maxJsonIpcBodyBytes = 65_536
    public static let maxRoIpcRequestBytes = 4_096
    public static let bugreportChunkSize = 65_536

    public static let clipboardWipeDelaySeconds: TimeInterval = 30.0
    public static let dashboardPollIntervalSeconds: TimeInterval = 2.0
    public static let menuBarIdlePollIntervalSeconds: TimeInterval = 8.0

    public static let ipcConnectTimeoutSeconds: TimeInterval = 0.85
    public static let ipcRoQueryTimeoutSeconds: TimeInterval = 2.0
    public static let ipcNetcheckTimeoutSeconds: TimeInterval = 10.0
    public static let ipcAdminMutationTimeoutSeconds: TimeInterval = 35.0
    public static let ipcStreamChunkIdleTimeoutSeconds: TimeInterval = 10.0
    public static let ipcMaxPingTimeoutSeconds: TimeInterval = 35.0

    public static let roSocketPath = "/var/run/meshd/meshd-ro.sock"
    public static let adminSocketPath = "/var/run/meshd/meshd-admin.sock"
    public static let daemonBinaryPath = "/usr/local/libexec/mesh/meshd"
    public static let cliBinaryPath = "/usr/local/bin/mesh"
    public static let launchdLabel = "internal.mesh.meshd"
    public static let launchdPlistPath = "/Library/LaunchDaemons/internal.mesh.meshd.plist"
    public static let stateDirPath = "/var/db/mesh"
    public static let appBundlePath = "/Applications/Mesh VPN.app"
    public static let appBundleVersion = "0.4.0"
    public static let loggerSubsystem = "dev.meshvpn.macos"

    public static let reservedHostnames: Set<String> = [
        "localhost",
        "broadcasthost",
        "wpad",
        "isatap",
        "local"
    ]
}

/// Canonical 8-state Desktop UI state machine (`desktop-gui-system-architecture.md` §4).
public enum DesktopUiState: String, Equatable, Sendable, CaseIterable {
    case serviceNotInstalled
    case serviceStopped
    case unconfigured
    case connecting
    case connected
    case reauthRequired
    case revoked
    case error

    public var displayTitle: String {
        switch self {
        case .serviceNotInstalled: return "Service Not Installed"
        case .serviceStopped: return "Service Stopped"
        case .unconfigured: return "Not Enrolled"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reauthRequired: return "Key Rotation Required"
        case .revoked: return "Device Revoked"
        case .error: return "Attention Required"
        }
    }

    /// True when the node has passed initial enrollment and should show the 3-tab navigation bar.
    public var isEnrolledState: Bool {
        switch self {
        case .serviceNotInstalled, .serviceStopped, .unconfigured: return false
        case .connecting, .connected, .reauthRequired, .revoked, .error: return true
        }
    }

    /// Sub-state-aware display label distinguishing Connected, Degraded, and Disconnected.
    public func resolvedTitle(isDegradedTunnel: Bool, isManuallyDisconnected: Bool) -> String {
        guard self == .connected else { return displayTitle }
        if isManuallyDisconnected { return "Disconnected" }
        return isDegradedTunnel ? "Degraded" : "Connected"
    }
}

/// Semantic color classification shared across Menu Bar icons, badges, and status cards.
public enum SemanticColorTone: String, Equatable, Sendable, CaseIterable {
    case success, warning, error, neutral

    public var lightHex: String {
        switch self {
        case .success: return MeshDesignTokens.semanticSuccessLight
        case .warning: return MeshDesignTokens.semanticWarningLight
        case .error: return MeshDesignTokens.semanticErrorLight
        case .neutral: return MeshDesignTokens.semanticNeutralLight
        }
    }

    public var darkHex: String {
        switch self {
        case .success: return MeshDesignTokens.semanticSuccessDark
        case .warning: return MeshDesignTokens.semanticWarningDark
        case .error: return MeshDesignTokens.semanticErrorDark
        case .neutral: return MeshDesignTokens.semanticNeutralDark
        }
    }
}

/// Visual icon grouping rendered in the macOS Menu Bar `NSStatusItem` (`US-109`, `ADR-030`).
public enum MenuBarStatusGroup: Equatable, Sendable, CaseIterable {
    case connected, connectingOrDegraded, disconnected, serviceOffline, reauthRequired, warning

    public var symbolName: String {
        switch self {
        case .connected: return "checkmark.shield.fill"
        case .connectingOrDegraded: return "bolt.shield.fill"
        case .disconnected: return "shield"
        case .serviceOffline: return "shield.slash"
        case .reauthRequired: return "key.slash"
        case .warning: return "exclamationmark.shield.fill"
        }
    }

    public var semanticTone: SemanticColorTone {
        switch self {
        case .connected: return .success
        case .connectingOrDegraded, .reauthRequired: return .warning
        case .disconnected, .serviceOffline: return .neutral
        case .warning: return .error
        }
    }

    public var lightHex: String { semanticTone.lightHex }
    public var darkHex: String { semanticTone.darkHex }
}

/// Result of probing the running or installed `meshd` version (`ADR-024`, `MED-DGUI-G2-01`).
public enum AgentVersionStatus: Equatable, Sendable {
    case version(String)
    case legacyPre030
}

/// Version mismatch banner state shown when bundle version differs from daemon (`US-113`).
public enum DaemonVersionBannerState: Equatable, Sendable {
    case unknown
    case matched(String)
    case mismatch(daemon: String, app: String)
    case legacyPre030

    public var requiresUpdateBanner: Bool {
        switch self {
        case .unknown, .matched:
            return false
        case .mismatch, .legacyPre030:
            return true
        }
    }
}

/// Redacted enrollment draft displayed in confirmation modal before calling `up` or `rotate-key`.
public struct EnrollmentConfirmationDraft:
    Identifiable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let id: UUID
    public let serverEndpoint: String
    public let portOverride: UInt16?
    public let tlsAuthMode: TlsAuthMode
    public let serverPin: String?
    public let nodeName: String?
    public let maskedPreauthPreview: String
    public let isRotation: Bool
    private var preauthKeySecret: String

    public init(
        id: UUID = UUID(),
        serverEndpoint: String,
        portOverride: UInt16? = nil,
        tlsAuthMode: TlsAuthMode,
        serverPin: String? = nil,
        nodeName: String? = nil,
        maskedPreauthPreview: String,
        preauthKeySecret: String,
        isRotation: Bool = false
    ) {
        self.id = id
        self.serverEndpoint = serverEndpoint
        self.portOverride = portOverride
        self.tlsAuthMode = tlsAuthMode
        self.serverPin = serverPin
        self.nodeName = nodeName
        self.maskedPreauthPreview = maskedPreauthPreview
        self.preauthKeySecret = preauthKeySecret
        self.isRotation = isRotation
    }

    public func unsafeRawPreauthKeyForIpc() -> String {
        preauthKeySecret
    }

    public mutating func wipeSecret() {
        preauthKeySecret = ""
    }

    public var description: String {
        let pinText = serverPin ?? "none"
        return "EnrollmentConfirmationDraft(endpoint=\(serverEndpoint), "
            + "tls=\(tlsAuthMode.rawValue), pin=\(pinText), "
            + "preview=\(maskedPreauthPreview), secret=[REDACTED], isRotation=\(isRotation))"
    }

    public var debugDescription: String {
        description
    }
}

/// Safe user-facing error surfaced in Dashboard banners and alerts (`SEC-05`).
public struct DesktopUserFacingError: Equatable, Sendable {
    public let code: String
    public let title: String
    public let message: String
    public let isPermissionDenied: Bool
    public let requiresPinUpdate: Bool
    public let requiresIdentityReset: Bool
    public let requiresKeyRotation: Bool

    public init(
        code: String,
        title: String,
        message: String,
        isPermissionDenied: Bool = false,
        requiresPinUpdate: Bool = false,
        requiresIdentityReset: Bool = false,
        requiresKeyRotation: Bool = false
    ) {
        self.code = code
        self.title = title
        self.message = MeshSecretScrubber.scrub(message)
        self.isPermissionDenied = isPermissionDenied
        self.requiresPinUpdate = requiresPinUpdate
        self.requiresIdentityReset = requiresIdentityReset
        self.requiresKeyRotation = requiresKeyRotation
    }
}

/// Scrubs pre-auth tokens, join URIs, private keys, and bearer tokens before log output.
public enum MeshSecretScrubber: Sendable {
    private static let patterns: [(regex: String, replacement: String)] = [
        (#"mpk_[A-Za-z0-9._~+/=-]+"#, "mpk_[REDACTED]"),
        (#"mesh://join\?[^\s"']+"#, "mesh://join?[REDACTED]"),
        (
            #"(?i)(node_privkey_hex|disco_privkey_hex|preauth_key|private_key)"#
                + #"\s*[:=]\s*[^\s"';,]+"#,
            "$1=[REDACTED]"
        ),
        (#"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"#, "Bearer [REDACTED]"),
        (
            #"-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----"#,
            "[REDACTED_PEM_KEY]"
        )
    ]

    public static func scrub(_ input: String) -> String {
        var result = input
        for entry in patterns {
            guard let regex = try? NSRegularExpression(pattern: entry.regex, options: []) else {
                continue
            }
            let fullRange = NSRange(result.startIndex..<result.endIndex, in: result)
            result = regex.stringByReplacingMatches(
                in: result,
                options: [],
                range: fullRange,
                withTemplate: entry.replacement
            )
        }
        return result
    }

    public static func containsSecretPattern(_ input: String) -> Bool {
        let stripped = input
            .replacingOccurrences(of: "mpk_[REDACTED]", with: "")
            .replacingOccurrences(of: "mesh://join?[REDACTED]", with: "")
        let lower = stripped.lowercased()
        if lower.contains("mpk_") || lower.contains("mesh://join") {
            return true
        }
        if lower.contains("privkey") || lower.contains("begin private key") {
            return true
        }
        return false
    }
}

/// Privacy-preserving `os.Logger` wrapper marking dynamic fields `%{private}@` (`US-112`).
public struct SafeOsLogger: Sendable {
    private let logger: Logger

    public init(category: String) {
        self.logger = Logger(subsystem: AgentDefaults.loggerSubsystem, category: category)
    }

    public func info(_ event: String, detail: String? = nil) {
        if let detail {
            let safeDetail = MeshSecretScrubber.scrub(detail)
            logger.info("event=\(event, privacy: .public) detail=\(safeDetail, privacy: .private)")
        } else {
            logger.info("event=\(event, privacy: .public)")
        }
    }

    public func notice(_ event: String, detail: String? = nil) {
        if let detail {
            let clean = MeshSecretScrubber.scrub(detail)
            logger.notice("event=\(event, privacy: .public) detail=\(clean, privacy: .private)")
        } else {
            logger.notice("event=\(event, privacy: .public)")
        }
    }

    public func warning(_ event: String, detail: String? = nil) {
        if let detail {
            let clean = MeshSecretScrubber.scrub(detail)
            logger.warning("event=\(event, privacy: .public) detail=\(clean, privacy: .private)")
        } else {
            logger.warning("event=\(event, privacy: .public)")
        }
    }

    public func error(_ event: String, detail: String? = nil) {
        if let detail {
            let safeDetail = MeshSecretScrubber.scrub(detail)
            logger.error("event=\(event, privacy: .public) detail=\(safeDetail, privacy: .private)")
        } else {
            logger.error("event=\(event, privacy: .public)")
        }
    }
}

/// Pure deterministic mapper from OS service status + daemon IPC response to `DesktopUiState`.
public enum DesktopStateMapper: Sendable {
    public struct ComputedState: Equatable, Sendable {
        public let uiState: DesktopUiState
        public let menuBarGroup: MenuBarStatusGroup
        public let isDegradedTunnel: Bool
        public let isManuallyDisconnected: Bool
    }

    public static func compute(
        serviceFilesPresent: Bool,
        statusResponse: AgentStatusResponse?,
        connectFailure: IpcClientError?,
        lastActionError: DesktopUserFacingError?
    ) -> ComputedState {
        guard let status = statusResponse else {
            return mapOfflineState(
                serviceFilesPresent: serviceFilesPresent,
                connectFailure: connectFailure
            )
        }

        switch status.daemonState {
        case .revoked:
            return ComputedState(
                uiState: .revoked,
                menuBarGroup: .warning,
                isDegradedTunnel: false,
                isManuallyDisconnected: false
            )
        case .reauthRequired:
            return ComputedState(
                uiState: .reauthRequired,
                menuBarGroup: .reauthRequired,
                isDegradedTunnel: false,
                isManuallyDisconnected: false
            )
        case .connecting:
            return ComputedState(
                uiState: .connecting,
                menuBarGroup: .connectingOrDegraded,
                isDegradedTunnel: false,
                isManuallyDisconnected: false
            )
        case .connected:
            return ComputedState(
                uiState: .connected,
                menuBarGroup: .connected,
                isDegradedTunnel: false,
                isManuallyDisconnected: false
            )
        case .degraded:
            return ComputedState(
                uiState: .connected,
                menuBarGroup: .connectingOrDegraded,
                isDegradedTunnel: true,
                isManuallyDisconnected: false
            )
        case .stopped:
            return mapStoppedDaemonState(status: status, lastActionError: lastActionError)
        }
    }

    private static func mapOfflineState(
        serviceFilesPresent: Bool,
        connectFailure: IpcClientError?
    ) -> ComputedState {
        if let connectFailure, case .permissionDenied = connectFailure {
            return ComputedState(
                uiState: .error,
                menuBarGroup: .warning,
                isDegradedTunnel: false,
                isManuallyDisconnected: false
            )
        }
        if serviceFilesPresent {
            return ComputedState(
                uiState: .serviceStopped,
                menuBarGroup: .serviceOffline,
                isDegradedTunnel: false,
                isManuallyDisconnected: false
            )
        }
        return ComputedState(
            uiState: .serviceNotInstalled,
            menuBarGroup: .serviceOffline,
            isDegradedTunnel: false,
            isManuallyDisconnected: false
        )
    }

    private static func mapStoppedDaemonState(
        status: AgentStatusResponse,
        lastActionError: DesktopUserFacingError?
    ) -> ComputedState {
        if status.nodeId == nil || status.serverConnection == nil {
            return ComputedState(
                uiState: .unconfigured,
                menuBarGroup: .disconnected,
                isDegradedTunnel: false,
                isManuallyDisconnected: false
            )
        }
        if let err = lastActionError,
           err.requiresPinUpdate || err.isPermissionDenied {
            return ComputedState(
                uiState: .error,
                menuBarGroup: .warning,
                isDegradedTunnel: false,
                isManuallyDisconnected: true
            )
        }
        return ComputedState(
            uiState: .connected,
            menuBarGroup: .disconnected,
            isDegradedTunnel: false,
            isManuallyDisconnected: true
        )
    }
}

/// Canonical hex color tokens (`ADR-030` v1.1).
public enum MeshDesignTokens: Sendable {
    public static let surfaceBackgroundLight = "#F8FAFC"
    public static let surfaceBackgroundDark = "#0F172A"
    public static let surfaceCardLight = "#FFFFFF"
    public static let surfaceCardDark = "#1E293B"
    public static let surfaceBorderLight = "#CBD5E1"
    public static let surfaceBorderDark = "#334155"
    public static let textPrimaryLight = "#0F172A"
    public static let textPrimaryDark = "#F1F5F9"
    public static let textSecondaryLight = "#475569"
    public static let textSecondaryDark = "#94A3B8"
    public static let brandCobalt = "#0B57D0"
    public static let brandSky = "#60A5FA"
    public static let brandTeal = "#0D9488"
    public static let brandTealLight = "#2DD4BF"
    public static let semanticSuccessLight = "#16A34A"
    public static let semanticSuccessDark = "#4ADE80"
    public static let semanticWarningLight = "#D97706"
    public static let semanticWarningDark = "#FBBF24"
    public static let semanticErrorLight = "#DC2626"
    public static let semanticErrorDark = "#F87171"
    public static let semanticNeutralLight = "#6B7280"
    public static let semanticNeutralDark = "#9CA3AF"
}

/// Appearance preference persisted under `UserDefaults(suiteName: "MeshVPN")`.
public enum ThemeMode: String, Codable, CaseIterable, Identifiable, Sendable {
    case system, light, dark

    public static let userDefaultsSuiteName = "MeshVPN"
    public static let userDefaultsKey = "mesh_theme_mode"
    public var id: String { rawValue }
    public var displayLabel: String { rawValue.capitalized }

    public static func load(
        from defaults: UserDefaults? = UserDefaults(suiteName: userDefaultsSuiteName)
    ) -> ThemeMode {
        guard let raw = defaults?.string(forKey: userDefaultsKey),
              let parsed = ThemeMode(rawValue: raw) else { return .system }
        return parsed
    }

    public func save(
        to defaults: UserDefaults? = UserDefaults(suiteName: userDefaultsSuiteName)
    ) {
        defaults?.set(rawValue, forKey: Self.userDefaultsKey)
    }
}

/// Canonical 3-tab Dashboard navigation sections (`ADR-028`).
public enum DesktopTabKind: String, CaseIterable, Identifiable, Sendable {
    case status = "Status"
    case peers = "Peers"
    case diagnostics = "Diagnostics & Settings"

    public var id: String { rawValue }
    public static func visibleTabs(for uiState: DesktopUiState) -> [DesktopTabKind] {
        uiState.isEnrolledState ? DesktopTabKind.allCases : []
    }
}

/// Filter chips and count badges for Peers directory (`US-120`).
public enum PeerFilterMode: String, CaseIterable, Identifiable, Sendable {
    case all = "All", online = "Online", direct = "Direct", relay = "Relay"
    public var id: String { rawValue }
}

public struct PeerFilterCounts: Equatable, Sendable {
    public let all: Int
    public let online: Int
    public let direct: Int
    public let relay: Int

    public func count(for mode: PeerFilterMode) -> Int {
        switch mode {
        case .all: return all
        case .online: return online
        case .direct: return direct
        case .relay: return relay
        }
    }
}

public enum PeerDirectoryFilter: Sendable {
    public static func counts(for peers: [AgentPeerStatus]) -> PeerFilterCounts {
        PeerFilterCounts(
            all: peers.count,
            online: peers.filter(\.online).count,
            direct: peers.filter { $0.online && $0.activePath == .direct }.count,
            relay: peers.filter { $0.online && $0.activePath == .relay }.count
        )
    }

    public static func filter(
        peers: [AgentPeerStatus],
        mode: PeerFilterMode,
        query: String
    ) -> [AgentPeerStatus] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return peers.filter { peer in
            let matchesMode: Bool = switch mode {
            case .all: true
            case .online: peer.online
            case .direct: peer.online && peer.activePath == .direct
            case .relay: peer.online && peer.activePath == .relay
            }
            guard matchesMode else { return false }
            guard !trimmed.isEmpty else { return true }
            return peer.name.lowercased().contains(trimmed)
                || peer.fqdn.lowercased().contains(trimmed)
                || peer.overlayIp.lowercased().contains(trimmed)
                || peer.nodeId.lowercased().contains(trimmed)
        }
    }
}
