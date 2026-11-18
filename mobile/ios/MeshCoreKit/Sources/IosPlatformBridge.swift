import Darwin
import Foundation
import NetworkExtension

/// Abstraction over `NEPacketTunnelFlow` for unit-testable L3 packet forwarding.
public protocol TunnelPacketFlowing: Sendable {
    func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void)
    func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool
}

/// Thread-safe adapter wrapping Apple's `NEPacketTunnelFlow`.
public final class NEPacketTunnelFlowAdapter: TunnelPacketFlowing, @unchecked Sendable {
    // SAFETY-SENDABLE: NEPacketTunnelFlow is safe for concurrent readPackets/writePackets calls.
    private let flow: NEPacketTunnelFlow

    /// Creates an adapter wrapping a `NEPacketTunnelProvider`'s `packetFlow`.
    public init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    public func readPackets(
        completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void
    ) {
        flow.readPackets(completionHandler: completionHandler)
    }

    @discardableResult
    public func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        flow.writePackets(packets, withProtocols: protocols)
    }
}

/// Asynchronous route change notification from Rust `MobileEngine`.
public struct RouteChangeEvent: Sendable {
    public let opId: UInt64
    public let config: MobileTunnelNetworkConfig

    public init(opId: UInt64, config: MobileTunnelNetworkConfig) {
        self.opId = opId
        self.config = config
    }
}

/// Bounded non-blocking dispatcher writing L3 IP packets into `NEPacketTunnelFlow`.
public final class BoundedPacketWriter: Sendable {
    public static let maxQueuedBatches = 128

    private let flowBox: LockedBox<TunnelPacketFlowing?>
    private let queueBox: LockedBox<[([Data], [NSNumber])]>
    private let writeQueue = DispatchQueue(
        label: "dev.meshvpn.ios.packet-write",
        qos: .userInitiated
    )
    private let schedulingBox: LockedBox<Bool>

    /// Creates a bounded packet writer optionally bound to a `TunnelPacketFlowing`.
    public init(flow: TunnelPacketFlowing? = nil) {
        self.flowBox = LockedBox(flow)
        self.queueBox = LockedBox([])
        self.schedulingBox = LockedBox(false)
    }

    /// Attaches or detaches the live `TunnelPacketFlowing`.
    public func attach(flow: TunnelPacketFlowing?) {
        flowBox.withLock { $0 = flow }
        if flow == nil {
            queueBox.withLock { $0.removeAll() }
        }
    }

    /// Enqueues outbound decrypted IP packets in O(1) without blocking the caller thread.
    /// Drops oldest queued batch when the bounded queue exceeds `maxQueuedBatches` (`Jetsam`).
    public func enqueue(_ packets: [Data]) {
        guard !packets.isEmpty else { return }
        let protocols = packets.map(Self.addressFamilyNumber(for:))
        queueBox.withLock { queue in
            if queue.count >= Self.maxQueuedBatches {
                queue.removeFirst()
            }
            queue.append((packets, protocols))
        }
        scheduleDrainIfNeeded()
    }

    /// Current number of queued packet batches (for diagnostics/unit tests).
    public var queuedBatchCount: Int {
        queueBox.read { $0.count }
    }

    /// Inspects the IP version nibble to map packets to `AF_INET` or `AF_INET6`.
    public static func addressFamilyNumber(for packet: Data) -> NSNumber {
        guard let firstByte = packet.first else {
            return NSNumber(value: AF_INET)
        }
        let version = (firstByte >> 4) & 0x0F
        return version == 6 ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
    }

    private func scheduleDrainIfNeeded() {
        let shouldSchedule = schedulingBox.withLock { isScheduled -> Bool in
            if isScheduled {
                return false
            }
            isScheduled = true
            return true
        }
        guard shouldSchedule else { return }

        writeQueue.async { [weak self] in
            self?.drainQueue()
        }
    }

    private func drainQueue() {
        while true {
            let batch = queueBox.withLock { queue -> ([Data], [NSNumber])? in
                guard !queue.isEmpty else { return nil }
                return queue.removeFirst()
            }
            guard let (packets, protocols) = batch else {
                schedulingBox.withLock { $0 = false }
                let hasMore = queueBox.read { !$0.isEmpty }
                if hasMore {
                    scheduleDrainIfNeeded()
                }
                return
            }
            if let flow = flowBox.read({ $0 }) {
                _ = flow.writePackets(packets, withProtocols: protocols)
            }
        }
    }
}

/// Non-blocking UniFFI `PlatformNetworkBridge` implementation for iOS Container App & Extension.
public final class IosPlatformBridge: PlatformNetworkBridge, Sendable {
    private let dekStore: KeychainDekStore
    private let appGroupStore: AppGroupFileManaging
    private let underlayBox: LockedBox<UnderlayPathSnapshot>
    private let statusBox: LockedBox<MobileStatusSnapshot?>
    private let routeSink: @Sendable (RouteChangeEvent) -> Void
    private let statusSink: @Sendable (MobileStatusSnapshot) -> Void
    private let warningSink: @Sendable (MobilePlatformWarning) -> Void
    private let packetWriter: BoundedPacketWriter
    private let ioQueue = DispatchQueue(label: "dev.meshvpn.ios.bridge-io", qos: .utility)
    private let logger = MeshLogger(category: "platform_bridge")

    /// Initializes the bridge with Keychain, App Group, packet writer, and event sinks.
    public init(
        dekStore: KeychainDekStore = KeychainDekStore(),
        appGroupStore: AppGroupFileManaging,
        initialUnderlay: UnderlayPathSnapshot = UnderlayPathConverter.probeCurrentSnapshot(),
        packetWriter: BoundedPacketWriter = BoundedPacketWriter(),
        onRouteChanged: @escaping @Sendable (RouteChangeEvent) -> Void = { _ in },
        onStatusChanged: @escaping @Sendable (MobileStatusSnapshot) -> Void = { _ in },
        onPlatformWarning: @escaping @Sendable (MobilePlatformWarning) -> Void = { _ in }
    ) {
        self.dekStore = dekStore
        self.appGroupStore = appGroupStore
        self.underlayBox = LockedBox(initialUnderlay)
        self.statusBox = LockedBox(nil)
        self.packetWriter = packetWriter
        self.routeSink = onRouteChanged
        self.statusSink = onStatusChanged
        self.warningSink = onPlatformWarning
    }

    /// Updates the cached physical underlay snapshot used by `queryUnderlayState`.
    public func updateUnderlaySnapshot(_ snapshot: UnderlayPathSnapshot) {
        underlayBox.withLock { $0 = snapshot }
    }

    /// Returns the most recent status snapshot received from `MobileEngine`.
    public func latestStatusSnapshot() -> MobileStatusSnapshot? {
        statusBox.read { $0 }
    }

    // MARK: - PlatformNetworkBridge

    public func protectSocket(rawFd: Int32) throws -> Bool {
        true
    }

    public func onTunPackets(packets: [Data]) {
        packetWriter.enqueue(packets)
    }

    public func onRouteChanged(opId: UInt64, config: MobileTunnelNetworkConfig) {
        routeSink(RouteChangeEvent(opId: opId, config: config))
    }

    public func onStatusChanged(status: MobileStatusSnapshot) {
        statusBox.withLock { $0 = status }
        statusSink(status)
        let store = appGroupStore
        let snapshotCopy = status
        ioQueue.async {
            if let data = try? TunnelIpcCodec.encodeStatusSnapshot(snapshotCopy) {
                try? store.writeStateFile(
                    fileName: MeshConstants.statusSnapshotFileName,
                    content: data
                )
            }
        }
    }

    public func onPlatformWarning(warning: MobilePlatformWarning) {
        logger.warning("platform_warning", detail: warning.message)
        warningSink(warning)
    }

    public func queryUnderlayState() throws -> MobileUnderlayState {
        underlayBox.read { $0.toMobileUnderlayState() }
    }

    public func loadOrCreatePlatformDek() throws -> Data {
        try dekStore.loadOrCreateDek()
    }

    public func loadStateFile(fileName: String) throws -> Data? {
        try appGroupStore.readStateFile(fileName: fileName)
    }

    public func saveStateFile(fileName: String, content: Data) throws {
        try appGroupStore.writeStateFile(fileName: fileName, content: content)
    }

    public func deleteStateFile(fileName: String) throws {
        try appGroupStore.deleteStateFile(fileName: fileName)
    }
}
