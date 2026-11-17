import Darwin
import Foundation

/// Fixed finite set of privileged daemon operations executed via `/usr/bin/osascript` (`ADR-025`).
///
/// Never accepts arbitrary strings, `mpk_*` tokens, endpoints, or user save paths.
public enum PrivilegedDaemonAction: Equatable, Sendable {
    case kickstartDaemon
    case bootoutDaemon
    case installOrUpdateService(firewallOptIn: Bool)
    case uninstallService(purgeData: Bool)
    case enableFirewallException
}

/// Typed errors produced by `AdminPrivilegeHelper` (`DGUI-MAC-05`, `US-111`).
public enum AdminPrivilegeError: Error, Equatable, Sendable, LocalizedError {
    case userCancelled
    case invalidBundleResourcePath(String)
    case scriptMissing(String)
    case executionFailed(code: Int32, message: String)

    public var errorDescription: String? {
        switch self {
        case .userCancelled:
            return "Administrator confirmation was cancelled."
        case .invalidBundleResourcePath(let msg):
            return msg
        case .scriptMissing(let msg):
            return msg
        case .executionFailed(_, let message):
            return message
        }
    }
}

/// Protocol enabling deterministic unit testing of admin elevation without OS prompts.
public protocol AdminPrivilegeExecuting: Sendable {
    func execute(_ action: PrivilegedDaemonAction) async throws
}

/// Safe `/usr/bin/osascript` elevation helper using strictly finite commands (`ADR-025`, `US-111`).
public struct AdminPrivilegeHelper: AdminPrivilegeExecuting, Sendable {
    private let bundleResourceURLProvider: @Sendable () -> URL?
    private let ioQueue = DispatchQueue(
        label: "dev.meshvpn.macos.admin-privilege",
        qos: .userInitiated
    )

    public init(
        bundleResourceURLProvider: @escaping @Sendable () -> URL? = { Bundle.main.resourceURL }
    ) {
        self.bundleResourceURLProvider = bundleResourceURLProvider
    }

    public func execute(_ action: PrivilegedDaemonAction) async throws {
        let script = try buildAppleScript(for: action)
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            ioQueue.async {
                do {
                    try Self.runOsascript(script: script)
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public func buildAppleScript(for action: PrivilegedDaemonAction) throws -> String {
        let shellCmd = try Self.buildShellCommand(
            for: action,
            bundleResourceURL: bundleResourceURLProvider()
        )
        return try Self.wrapAsAppleScript(shellCommand: shellCmd)
    }

    public static func buildShellCommand(
        for action: PrivilegedDaemonAction,
        bundleResourceURL: URL?
    ) throws -> String {
        switch action {
        case .kickstartDaemon:
            return "/bin/launchctl kickstart -kp system/\(AgentDefaults.launchdLabel) "
                + "|| /bin/launchctl bootstrap system \(AgentDefaults.launchdPlistPath)"
        case .bootoutDaemon:
            return "/bin/launchctl bootout system/\(AgentDefaults.launchdLabel)"
        case .enableFirewallException:
            return "/usr/libexec/ApplicationFirewall/socketfilterfw "
                + "--add \(AgentDefaults.daemonBinaryPath) "
                + "&& /usr/libexec/ApplicationFirewall/socketfilterfw "
                + "--unblockapp \(AgentDefaults.daemonBinaryPath)"
        case .installOrUpdateService(let firewallOptIn):
            let resDir = try validatedBundleResourcePath(bundleResourceURL)
            try requireRegularFile(at: "\(resDir)/install-macos.sh")
            let fwFlag = firewallOptIn ? "--yes-firewall" : "--no-firewall"
            let scriptPath = posixSingleQuoted("\(resDir)/install-macos.sh")
            let fromPath = posixSingleQuoted(resDir)
            let sumPath = posixSingleQuoted("\(resDir)/SHA256SUMS")
            let plistPath = posixSingleQuoted("\(resDir)/internal.mesh.meshd.plist")
            return "/bin/sh \(scriptPath) --from \(fromPath) "
                + "--sha256-file \(sumPath) --plist \(plistPath) \(fwFlag)"
        case .uninstallService(let purgeData):
            let resDir = try validatedBundleResourcePath(bundleResourceURL)
            try requireRegularFile(at: "\(resDir)/install-macos.sh")
            let scriptPath = posixSingleQuoted("\(resDir)/install-macos.sh")
            let purgeFlag = purgeData ? " --purge" : ""
            return "/bin/sh \(scriptPath) --uninstall\(purgeFlag)"
        }
    }

    public static func wrapAsAppleScript(shellCommand: String) throws -> String {
        let hasControl = shellCommand.utf8.contains { byte in
            byte == 0 || byte == 0x0A || byte == 0x0D || byte < 0x20 || byte == 0x7F
        }
        guard !hasControl else {
            throw AdminPrivilegeError.invalidBundleResourcePath(
                "Privileged command contains forbidden control characters"
            )
        }
        let escaped = shellCommand
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "do shell script \"\(escaped)\" with administrator privileges"
    }

    public static func validatedBundleResourcePath(_ resourceURL: URL?) throws -> String {
        guard let resourceURL, resourceURL.isFileURL else {
            throw AdminPrivilegeError.invalidBundleResourcePath(
                "Bundle resource directory is unavailable"
            )
        }
        let path = resourceURL.standardizedFileURL.path
        guard !path.isEmpty, path.hasPrefix("/") else {
            throw AdminPrivilegeError.invalidBundleResourcePath(
                "Bundle resource path must be an absolute path"
            )
        }
        let safePath = path.utf8.allSatisfy { byte in
            let isAlpha = (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            let isDigit = byte >= 48 && byte <= 57
            let isSafePunct = byte == 47 || byte == 46 || byte == 95 || byte == 45 || byte == 32
            return isAlpha || isDigit || isSafePunct
        }
        guard safePath else {
            throw AdminPrivilegeError.invalidBundleResourcePath(
                "Bundle resource path contains disallowed characters"
            )
        }
        var dirStat = stat()
        guard Darwin.lstat(path, &dirStat) == 0 else {
            throw AdminPrivilegeError.invalidBundleResourcePath(
                "Bundle resource directory does not exist"
            )
        }
        guard (dirStat.st_mode & S_IFMT) == S_IFDIR else {
            throw AdminPrivilegeError.invalidBundleResourcePath(
                "Bundle resource path must be a non-symlink directory"
            )
        }
        return path
    }

    private static func requireRegularFile(at path: String) throws {
        var fileStat = stat()
        guard Darwin.lstat(path, &fileStat) == 0,
              (fileStat.st_mode & S_IFMT) == S_IFREG
        else {
            throw AdminPrivilegeError.scriptMissing(
                "Required installer script missing from bundle Resources: \(path)"
            )
        }
    }

    private static func posixSingleQuoted(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\"'\"'")
        return "'\(escaped)'"
    }

    private static func runOsascript(script: String) throws {
        let process = Process()
        let errPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errPipe

        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errText = String(data: errData, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let lower = errText.lowercased()
            if lower.contains("-128")
                || lower.contains("user canceled")
                || lower.contains("user cancelled")
            {
                throw AdminPrivilegeError.userCancelled
            }
            let fallback = "osascript exited with status \(process.terminationStatus)"
            let safeMsg = MeshSecretScrubber.scrub(errText.isEmpty ? fallback : errText)
            throw AdminPrivilegeError.executionFailed(
                code: process.terminationStatus,
                message: safeMsg
            )
        }
    }
}
