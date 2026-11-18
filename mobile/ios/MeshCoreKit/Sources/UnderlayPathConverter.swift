import Darwin
import Foundation
import Network

/// Injectable physical underlay interface descriptor for path classification tests.
public struct UnderlayInterfaceDescriptor: Sendable, Equatable {
    public enum Kind: Sendable, Equatable {
        case wiredEthernet
        case wifi
        case cellular
        case loopback
        case other
    }

    public let name: String
    public let index: UInt32
    public let kind: Kind

    public init(name: String, index: UInt32, kind: Kind) {
        self.name = name
        self.index = index
        self.kind = kind
    }

    public init(nwInterface: NWInterface) {
        self.name = nwInterface.name
        self.index = nwInterface.index >= 0 ? UInt32(nwInterface.index) : 0
        switch nwInterface.type {
        case .wiredEthernet:
            self.kind = .wiredEthernet
        case .wifi:
            self.kind = .wifi
        case .cellular:
            self.kind = .cellular
        case .loopback:
            self.kind = .loopback
        case .other:
            self.kind = .other
        @unknown default:
            self.kind = .other
        }
    }
}

/// Platform-independent snapshot of the iOS physical underlay state.
public struct UnderlayPathSnapshot: Sendable, Equatable {
    public let isSatisfied: Bool
    public let activeInterfaceName: String?
    public let physicalIfIndex: UInt32?
    public let hasIpv4: Bool
    public let hasIpv6: Bool
    public let underlayDnsServers: [String]
    public let osNat64Prefix: String?
    public let physicalSubnets: [String]

    public init(
        isSatisfied: Bool,
        activeInterfaceName: String?,
        physicalIfIndex: UInt32?,
        hasIpv4: Bool,
        hasIpv6: Bool,
        underlayDnsServers: [String] = [],
        osNat64Prefix: String? = nil,
        physicalSubnets: [String] = []
    ) {
        self.isSatisfied = isSatisfied
        self.activeInterfaceName = activeInterfaceName
        self.physicalIfIndex = physicalIfIndex
        self.hasIpv4 = hasIpv4
        self.hasIpv6 = hasIpv6
        self.underlayDnsServers = underlayDnsServers
        self.osNat64Prefix = osNat64Prefix
        self.physicalSubnets = physicalSubnets
    }

    public static let disconnected = UnderlayPathSnapshot(
        isSatisfied: false,
        activeInterfaceName: nil,
        physicalIfIndex: nil,
        hasIpv4: false,
        hasIpv6: false
    )

    /// Converts to the Rust UniFFI `MobileUnderlayState` structure.
    public func toMobileUnderlayState() -> MobileUnderlayState {
        MobileUnderlayState(
            activeInterfaceName: activeInterfaceName,
            physicalIfIndex: physicalIfIndex,
            hasIpv4: hasIpv4,
            hasIpv6: hasIpv6,
            underlayDnsServers: underlayDnsServers,
            osNat64Prefix: osNat64Prefix,
            physicalSubnets: physicalSubnets,
            isAndroidLockdownEnabled: false,
            isAndroidPrivateDnsStrict: false,
            privateDnsServerName: nil
        )
    }
}

/// Converts Apple `NWPath` transitions into `MobileUnderlayState` and `MobileNetEventKind`.
public enum UnderlayPathConverter: Sendable {
    private struct InterfaceAccum {
        let kind: UnderlayInterfaceDescriptor.Kind
        var hasIpv4: Bool
        var hasIpv6: Bool
    }

    /// Synchronously probes active physical underlay interfaces via Darwin `getifaddrs`.
    public static func probeCurrentSnapshot() -> UnderlayPathSnapshot {
        var ifaddrsPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrsPtr) == 0, let firstAddr = ifaddrsPtr else {
            return .disconnected
        }
        defer { freeifaddrs(firstAddr) }

        var byName: [String: InterfaceAccum] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let entry = cursor?.pointee {
            cursor = entry.ifa_next
            accumulateInterfaceEntry(entry, into: &byName)
        }

        let descriptors = byName.compactMap { name, info -> UnderlayInterfaceDescriptor? in
            let idx = if_nametoindex(name)
            guard idx > 0 else { return nil }
            return UnderlayInterfaceDescriptor(name: name, index: idx, kind: info.kind)
        }
        guard !descriptors.isEmpty else {
            return .disconnected
        }
        return snapshot(
            isSatisfied: true,
            interfaces: descriptors,
            supportsIpv4: byName.values.contains { $0.hasIpv4 },
            supportsIpv6: byName.values.contains { $0.hasIpv6 }
        )
    }

    private static func accumulateInterfaceEntry(
        _ entry: ifaddrs,
        into byName: inout [String: InterfaceAccum]
    ) {
        let flags = entry.ifa_flags
        let isUp = (flags & UInt32(bitPattern: IFF_UP)) != 0
        let isRunning = (flags & UInt32(bitPattern: IFF_RUNNING)) != 0
        let isLoopback = (flags & UInt32(bitPattern: IFF_LOOPBACK)) != 0
        guard isUp, isRunning, !isLoopback,
              let namePtr = entry.ifa_name,
              let addr = entry.ifa_addr else {
            return
        }
        let name = String(cString: namePtr)
        if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("lo") {
            return
        }
        let family = Int32(addr.pointee.sa_family)
        guard family == AF_INET || family == AF_INET6 else {
            return
        }
        if family == AF_INET6 && isLinkLocalIpv6(addr) {
            return
        }
        var record = byName[name] ?? InterfaceAccum(
            kind: inferInterfaceKind(name: name),
            hasIpv4: false,
            hasIpv6: false
        )
        if family == AF_INET { record.hasIpv4 = true }
        if family == AF_INET6 { record.hasIpv6 = true }
        byName[name] = record
    }

    /// Builds a snapshot from a live `Network.NWPath`.
    public static func snapshot(from path: NWPath) -> UnderlayPathSnapshot {
        let descriptors = path.availableInterfaces.map(UnderlayInterfaceDescriptor.init)
        return snapshot(
            isSatisfied: path.status == .satisfied,
            interfaces: descriptors,
            supportsIpv4: path.supportsIPv4,
            supportsIpv6: path.supportsIPv6
        )
    }

    /// Deterministic snapshot builder filtering virtual `utun`/`ipsec` and loopback interfaces.
    public static func snapshot(
        isSatisfied: Bool,
        interfaces: [UnderlayInterfaceDescriptor],
        supportsIpv4: Bool,
        supportsIpv6: Bool,
        underlayDnsServers: [String] = [],
        physicalSubnets: [String] = [],
        explicitNat64Prefix: String? = nil
    ) -> UnderlayPathSnapshot {
        let physicalCandidates = interfaces.filter { descriptor in
            descriptor.kind != .loopback
                && !descriptor.name.hasPrefix("utun")
                && !descriptor.name.hasPrefix("ipsec")
        }

        let preferred = selectPreferredInterface(from: physicalCandidates)
        let nat64Prefix = explicitNat64Prefix
            ?? ((!supportsIpv4 && supportsIpv6 && isSatisfied) ? "64:ff9b::/96" : nil)

        return UnderlayPathSnapshot(
            isSatisfied: isSatisfied,
            activeInterfaceName: preferred?.name,
            physicalIfIndex: preferred.flatMap { $0.index > 0 ? $0.index : nil },
            hasIpv4: supportsIpv4,
            hasIpv6: supportsIpv6,
            underlayDnsServers: underlayDnsServers,
            osNat64Prefix: nat64Prefix,
            physicalSubnets: physicalSubnets
        )
    }

    /// Classifies the transition event emitted to `MobileEngine.onNetworkChange`.
    public static func classifyTransition(
        previous: UnderlayPathSnapshot?,
        current: UnderlayPathSnapshot
    ) -> MobileNetEventKind? {
        guard let previous else {
            return current.isSatisfied ? .connectivityRestored : .connectivityLost
        }
        if !current.isSatisfied {
            return previous.isSatisfied ? .connectivityLost : nil
        }
        if !previous.isSatisfied && current.isSatisfied {
            return .connectivityRestored
        }
        if previous.activeInterfaceName != current.activeInterfaceName
            || previous.physicalIfIndex != current.physicalIfIndex {
            return .interfaceChanged
        }
        if previous.hasIpv4 != current.hasIpv4
            || previous.hasIpv6 != current.hasIpv6
            || previous.osNat64Prefix != current.osNat64Prefix
            || previous.physicalSubnets != current.physicalSubnets {
            return .addressChanged
        }
        if previous.underlayDnsServers != current.underlayDnsServers {
            return .dnsServersChanged
        }
        return nil
    }

    private static func inferInterfaceKind(name: String) -> UnderlayInterfaceDescriptor.Kind {
        if name.hasPrefix("en") {
            return .wifi
        }
        if name.hasPrefix("pdp_ip") {
            return .cellular
        }
        return .other
    }

    private static func isLinkLocalIpv6(_ addr: UnsafePointer<sockaddr>) -> Bool {
        guard Int(addr.pointee.sa_len) >= MemoryLayout<sockaddr_in6>.size else {
            return true
        }
        var sin6 = sockaddr_in6()
        memcpy(&sin6, addr, MemoryLayout<sockaddr_in6>.size)
        var addr6 = sin6.sin6_addr
        return withUnsafeBytes(of: &addr6) { raw in
            guard let first = raw.first, raw.count >= 2 else { return true }
            return first == 0xfe && (raw[1] & 0xc0) == 0x80
        }
    }

    private static func selectPreferredInterface(
        from candidates: [UnderlayInterfaceDescriptor]
    ) -> UnderlayInterfaceDescriptor? {
        let priority: [UnderlayInterfaceDescriptor.Kind] = [
            .wiredEthernet,
            .wifi,
            .cellular,
            .other
        ]
        for kind in priority {
            if let match = candidates.first(where: { $0.kind == kind }) {
                return match
            }
        }
        return nil
    }
}
