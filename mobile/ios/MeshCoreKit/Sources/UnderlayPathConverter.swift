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
