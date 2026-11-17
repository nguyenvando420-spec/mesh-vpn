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
    public static let appBundleVersion = "0.3.0"
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
        case .serviceNotInstalled:
            return "Service Not Installed"
        case .serviceStopped:
            return "Service Stopped"
        case .unconfigured:
            return "Not Enrolled"
        case .connecting:
            return "Connecting"
        case .connected:
            return "Connected"
        case .reauthRequired:
            return "Key Rotation Required"
        case .revoked:
            return "Device Revoked"
        case .error:
            return "Attention Required"
        }
    }
}

/// Visual icon grouping rendered in the macOS Menu Bar `NSStatusItem` (`US-109`).
public enum MenuBarStatusGroup: Equatable, Sendable {
    case connected
    case connectingOrDegraded
    case disconnected
    case serviceOffline
    case warning

    public var symbolName: String {
        switch self {
        case .connected:
            return "checkmark.shield.fill"
        case .connectingOrDegraded:
            return "bolt.shield.fill"
        case .disconnected:
            return "shield"
        case .serviceOffline:
            return "shield.slash"
        case .warning:
            return "exclamationmark.shield.fill"
        }
    }
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
    Identifiable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible
{
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
        let lower = input.lowercased()
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
                menuBarGroup: .warning,
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
