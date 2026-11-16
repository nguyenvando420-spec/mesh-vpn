import Foundation
import OSLog

/// Redacts pre-auth tokens, join URIs, private keys, and bearer tokens before log output.
public enum MeshSecretScrubber: Sendable {
    private static let patterns: [(regex: String, replacement: String)] = [
        (#"mpk_[A-Za-z0-9._~+/=-]+"#, "mpk_[REDACTED]"),
        (#"mesh://join\?[^\s"']+"#, "mesh://join?[REDACTED]"),
        (#"(?i)(node_privkey_hex|disco_privkey_hex|preauth_key|private_key)\s*[:=]\s*[^\s"';,]+"#,
         "$1=[REDACTED]"),
        (#"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"#, "Bearer [REDACTED]"),
        (#"-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----"#,
         "[REDACTED_PEM_KEY]")
    ]

    /// Replaces sensitive tokens with redaction placeholders.
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

    /// Returns true if the input still contains recognizable secret material.
    public static func containsSecretPattern(_ input: String) -> Bool {
        let lowercased = input.lowercased()
        if lowercased.contains("mpk_") || lowercased.contains("mesh://join") {
            return true
        }
        if lowercased.contains("privkey") || lowercased.contains("begin private key") {
            return true
        }
        return false
    }
}

/// Structured privacy-preserving wrapper around `os.Logger`.
public struct MeshLogger: Sendable {
    private let logger: Logger

    /// Creates a logger bound to a specific component category (`app`, `tunnel`, `keychain`, etc.).
    public init(category: String) {
        self.logger = Logger(subsystem: MeshConstants.loggerSubsystem, category: category)
    }

    /// Logs an informational event with dynamic details marked private and scrubbed.
    public func info(_ event: String, detail: String? = nil) {
        if let detail {
            let safeDetail = MeshSecretScrubber.scrub(detail)
            logger.info("event=\(event, privacy: .public) detail=\(safeDetail, privacy: .private)")
        } else {
            logger.info("event=\(event, privacy: .public)")
        }
    }

    /// Logs a notice-level lifecycle transition with scrubbed private metadata.
    public func notice(_ event: String, detail: String? = nil) {
        if let detail {
            let clean = MeshSecretScrubber.scrub(detail)
            logger.notice("event=\(event, privacy: .public) detail=\(clean, privacy: .private)")
        } else {
            logger.notice("event=\(event, privacy: .public)")
        }
    }

    /// Logs a non-fatal warning with scrubbed private details.
    public func warning(_ event: String, detail: String? = nil) {
        if let detail {
            let clean = MeshSecretScrubber.scrub(detail)
            logger.warning("event=\(event, privacy: .public) detail=\(clean, privacy: .private)")
        } else {
            logger.warning("event=\(event, privacy: .public)")
        }
    }

    /// Logs an error with scrubbed private details.
    public func error(_ event: String, detail: String? = nil) {
        if let detail {
            let safeDetail = MeshSecretScrubber.scrub(detail)
            logger.error("event=\(event, privacy: .public) detail=\(safeDetail, privacy: .private)")
        } else {
            logger.error("event=\(event, privacy: .public)")
        }
    }
}
