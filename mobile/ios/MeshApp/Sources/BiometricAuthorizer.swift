import Foundation
@preconcurrency import LocalAuthentication
import MeshCoreKit

/// Outcome of an iOS LocalAuthentication gate before sensitive security actions.
public enum BiometricAuthOutcome: Sendable, Equatable {
    case authorized
    case cancelled
    case unavailable(String)
    case failed(String)
}

/// Protocol abstracting biometric/passcode prompts for deterministic XCTest coverage.
public protocol BiometricAuthorizing: Sendable {
    func authorize(reason: String) async -> BiometricAuthOutcome
}

/// Production `LAContext` authorizer supporting Face ID, Touch ID, and Device Passcode fallback.
public struct LocalAuthBiometricAuthorizer: BiometricAuthorizing, Sendable {
    public init() {}

    public func authorize(reason: String) async -> BiometricAuthOutcome {
        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            let msg = policyError?.localizedDescription ?? "Device authentication is unavailable"
            return .unavailable(MeshSecretScrubber.scrub(msg))
        }

        do {
            let passed = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
            return passed ? .authorized : .failed("Authentication was not granted")
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .systemCancel, .appCancel:
                return .cancelled
            case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet:
                return .unavailable(MeshSecretScrubber.scrub(error.localizedDescription))
            default:
                return .failed(MeshSecretScrubber.scrub(error.localizedDescription))
            }
        } catch {
            return .failed(MeshSecretScrubber.scrub(error.localizedDescription))
        }
    }
}
