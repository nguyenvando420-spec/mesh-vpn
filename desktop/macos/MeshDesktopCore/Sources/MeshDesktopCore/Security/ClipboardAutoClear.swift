import AppKit
import CryptoKit
import Foundation

/// Abstraction over `NSPasteboard.general` enabling deterministic unit testing (`DGUI-SEC-03`).
@MainActor
public protocol PasteboardProviding: AnyObject, Sendable {
    var changeCount: Int { get }
    func stringContent() -> String?
    func setStringContent(_ value: String)
    func clearContents()
}

/// Live AppKit `NSPasteboard.general` wrapper (never touches `UIKit`).
@MainActor
public final class SystemPasteboardProvider: PasteboardProviding {
    public init() {}

    public var changeCount: Int {
        NSPasteboard.general.changeCount
    }

    public func stringContent() -> String? {
        NSPasteboard.general.string(forType: .string)
    }

    public func setStringContent(_ value: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    public func clearContents() {
        NSPasteboard.general.clearContents()
    }
}

/// Conditional 30-second clipboard auto-clear guard (`DGUI-SEC-03`, `HR-DGUI-G1-02`).
///
/// Clears `NSPasteboard.general` on timer expiry or app termination ONLY if BOTH the
/// pasteboard `changeCount` AND the SHA-256 digest of the clipboard string still match.
@MainActor
public final class ClipboardAutoClear {
    private struct PendingWipe {
        let recordedChangeCount: Int
        let sha256Digest: Data
    }

    private let pasteboard: any PasteboardProviding
    private let delaySeconds: TimeInterval
    private var pendingWipe: PendingWipe?
    private var wipeTask: Task<Void, Never>?

    public init(
        pasteboard: any PasteboardProviding = SystemPasteboardProvider(),
        delaySeconds: TimeInterval = AgentDefaults.clipboardWipeDelaySeconds
    ) {
        self.pasteboard = pasteboard
        self.delaySeconds = delaySeconds
    }

    public var hasPendingWipe: Bool {
        pendingWipe != nil
    }

    /// Records `(changeCount, sha256)` for `text` and schedules wipe after `delaySeconds`.
    public func recordAndScheduleWipe(text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        wipeTask?.cancel()
        let rawToHash: String
        if let currentClip = pasteboard.stringContent(),
           currentClip.trimmingCharacters(in: .whitespacesAndNewlines) == trimmed {
            rawToHash = currentClip
        } else {
            rawToHash = text
        }
        let digest = Self.sha256Data(for: rawToHash)
        pendingWipe = PendingWipe(
            recordedChangeCount: pasteboard.changeCount,
            sha256Digest: digest
        )
        let delay = delaySeconds
        wipeTask = Task { @MainActor [weak self] in
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            _ = self?.clearIfMatchingNow()
        }
    }

    /// Detects `Cmd+V` paste into URI / `mpk_*` fields by matching current clipboard contents.
    public func scheduleWipeIfClipboardMatchesFieldText(_ fieldText: String) {
        let trimmedField = fieldText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.containsSensitiveOnboardingText(trimmedField),
              let clipText = pasteboard.stringContent()
        else {
            return
        }
        let trimmedClip = clipText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmedClip == trimmedField else { return }
        recordAndScheduleWipe(text: clipText)
    }

    /// Immediately wipes the clipboard if both `changeCount` and SHA-256 digest still match.
    @discardableResult
    public func clearIfMatchingNow() -> Bool {
        wipeTask?.cancel()
        wipeTask = nil
        guard let target = pendingWipe else { return false }
        pendingWipe = nil

        guard pasteboard.changeCount == target.recordedChangeCount,
              let currentText = pasteboard.stringContent()
        else {
            return false
        }

        let currentDigest = Self.sha256Data(for: currentText)
        let trimmedDigest = Self.sha256Data(
            for: currentText.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        guard currentDigest == target.sha256Digest || trimmedDigest == target.sha256Digest else {
            return false
        }
        pasteboard.clearContents()
        return true
    }

    public func cancelPendingWipe() {
        wipeTask?.cancel()
        wipeTask = nil
        pendingWipe = nil
    }

    public static func containsSensitiveOnboardingText(_ text: String) -> Bool {
        let lower = text.lowercased()
        return lower.hasPrefix("mesh://join") || lower.hasPrefix(AgentDefaults.preauthKeyPrefix)
    }

    private static func sha256Data(for text: String) -> Data {
        Data(SHA256.hash(data: Data(text.utf8)))
    }
}
