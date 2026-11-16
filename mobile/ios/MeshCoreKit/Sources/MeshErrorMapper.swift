import Foundation
import NetworkExtension

/// Sanitized, localized UI error representation mapped from Rust `MobileError` or iOS `NEVPNError`.
public struct MeshUserFacingError: Sendable, Equatable {
    public let code: String
    public let title: String
    public let message: String
    public let requiresReauth: Bool
    public let isDeviceLocked: Bool
    public let requiresServerUpgrade: Bool

    public init(
        code: String,
        title: String,
        message: String,
        requiresReauth: Bool = false,
        isDeviceLocked: Bool = false,
        requiresServerUpgrade: Bool = false
    ) {
        self.code = code
        self.title = title
        self.message = MeshSecretScrubber.scrub(message)
        self.requiresReauth = requiresReauth
        self.isDeviceLocked = isDeviceLocked
        self.requiresServerUpgrade = requiresServerUpgrade
    }
}

/// Maps `MobileError` and system errors into safe user-facing messages with zero secret leakage.
public enum MeshErrorMapper: Sendable {
    public static func map(_ error: Error) -> MeshUserFacingError {
        if let mobileError = error as? MobileError {
            return mapMobileError(mobileError)
        }
        let nsError = error as NSError
        if nsError.domain == NEVPNErrorDomain {
            return MeshUserFacingError(
                code: "E_NEVPN_\(nsError.code)",
                title: "VPN Configuration Error",
                message: MeshSecretScrubber.scrub(nsError.localizedDescription)
            )
        }
        return MeshUserFacingError(
            code: "E_INTERNAL",
            title: "Operation Failed",
            message: MeshSecretScrubber.scrub(error.localizedDescription)
        )
    }

    public static func mapMobileError(_ error: MobileError) -> MeshUserFacingError {
        switch error {
        case .InvalidArgument(let code, let message):
            return MeshUserFacingError(code: code, title: "Invalid Input", message: message)

        case .Unauthenticated(let code, _):
            return MeshUserFacingError(
                code: code,
                title: "Authentication Failed",
                message: "authentication failed"
            )

        case .PermissionDenied(let code, let message):
            return MeshUserFacingError(code: code, title: "Permission Denied", message: message)

        case .NodeRevoked(let code, let message):
            return MeshUserFacingError(
                code: code,
                title: "Device Revoked",
                message: "\(message). Re-enroll with a new pre-auth token.",
                requiresReauth: true
            )

        case .NodeKeyExpired(let code, let message):
            return MeshUserFacingError(
                code: code,
                title: "Node Key Expired",
                message: "\(message). Rotate the node key or re-enroll.",
                requiresReauth: true
            )

        case .NotFound(let code, let message):
            return MeshUserFacingError(code: code, title: "Not Found", message: message)

        case .Conflict(let code, let message):
            return MeshUserFacingError(code: code, title: "Conflict", message: message)

        case .RateLimited(let code, let message):
            return MeshUserFacingError(code: code, title: "Rate Limited", message: message)

        case .Unavailable(let code, let message):
            let lower = message.lowercased()
            let title = lower.contains("captive") ? "Captive Portal Detected" : "Server Unavailable"
            return MeshUserFacingError(code: code, title: title, message: message)

        case .ClockSkew(let code, let message):
            return MeshUserFacingError(
                code: code,
                title: "Device Clock Out of Sync",
                message: "\(message). Enable Set Automatically in iOS Date & Time settings."
            )

        case .PinMismatch(let code, let message):
            return MeshUserFacingError(
                code: code,
                title: "Server Pin Mismatch",
                message: "\(message). Verify the SHA-256 SPKI pin with your administrator."
            )

        case .ServerUpgradeRequired(let code, let message):
            return MeshUserFacingError(
                code: code,
                title: "Server Upgrade Required",
                message: message,
                requiresServerUpgrade: true
            )

        case .KeystoreInvalidated(let code, let message):
            return MeshUserFacingError(
                code: code,
                title: "Keychain Key Unavailable",
                message: "\(message). Re-enroll this device.",
                requiresReauth: true
            )

        case .DeviceLocked(let code, let message):
            return MeshUserFacingError(
                code: code,
                title: "Unlock Device First",
                message: message,
                isDeviceLocked: true
            )

        case .Internal(let code, let message):
            return MeshUserFacingError(code: code, title: "Internal Error", message: message)
        }
    }
}
