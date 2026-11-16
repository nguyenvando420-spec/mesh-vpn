import Foundation

/// Synchronized container providing `Sendable` access on iOS 15.0+ without `OSAllocatedUnfairLock`.
public final class LockedBox<Value>: @unchecked Sendable {
    // SAFETY-SENDABLE: Every read and mutation of `storage` acquires `lock`.
    private let lock = NSLock()
    private var storage: Value

    /// Creates a lock-protected box initialized with `initialValue`.
    public init(_ initialValue: Value) {
        self.storage = initialValue
    }

    /// Executes `body` exclusively while holding the underlying lock.
    public func withLock<Result>(_ body: (inout Value) throws -> Result) rethrows -> Result {
        lock.lock()
        defer { lock.unlock() }
        return try body(&storage)
    }

    /// Reads the current value under the lock without mutation.
    public func read<Result>(_ body: (Value) throws -> Result) rethrows -> Result {
        lock.lock()
        defer { lock.unlock() }
        return try body(storage)
    }
}
