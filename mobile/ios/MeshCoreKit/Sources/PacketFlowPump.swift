import Foundation

/// Pumps inbound L3 packets from `TunnelPacketFlowing` into `MobileEngine.pushTunPackets`.
public final class PacketFlowPump: Sendable {
    private let flow: TunnelPacketFlowing
    private let stoppedBox = LockedBox(false)
    private let readQueue = DispatchQueue(label: "dev.meshvpn.ios.packet-read", qos: .userInitiated)
    private let packetConsumer: @Sendable ([Data]) -> UInt32

    /// Creates a pump backed by a packet flow and a bounded consumer closure.
    public init(
        flow: TunnelPacketFlowing,
        packetConsumer: @escaping @Sendable ([Data]) -> UInt32
    ) {
        self.flow = flow
        self.packetConsumer = packetConsumer
    }

    /// Starts the asynchronous `readPackets` loop until `stop()` is invoked.
    public func start() {
        let shouldStart = stoppedBox.withLock { stopped -> Bool in
            if stopped {
                stopped = false
            }
            return true
        }
        guard shouldStart else { return }
        scheduleNextRead()
    }

    /// Halts subsequent reads cleanly.
    public func stop() {
        stoppedBox.withLock { $0 = true }
    }

    /// Returns whether the pump has been stopped.
    public var isStopped: Bool {
        stoppedBox.read { $0 }
    }

    private func scheduleNextRead() {
        guard !isStopped else { return }
        flow.readPackets { [weak self] packets, _ in
            guard let self, !self.isStopped else { return }
            if !packets.isEmpty {
                _ = self.packetConsumer(packets)
            }
            self.readQueue.async { [weak self] in
                self?.scheduleNextRead()
            }
        }
    }
}
