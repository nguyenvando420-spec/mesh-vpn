import Foundation
import Network
import NetworkExtension

/// Pure Swift value representation of an IPv4 included route for unit testing.
public struct Ipv4RouteSpec: Sendable, Equatable {
    public let destination: String
    public let subnetMask: String

    /// Creates an IPv4 route specification.
    public init(destination: String, subnetMask: String) {
        self.destination = destination
        self.subnetMask = subnetMask
    }
}

/// Pure Swift mirror of `NEPacketTunnelNetworkSettings` verifying `/32` and Split-DNS invariants.
public struct TunnelSettingsSpec: Sendable, Equatable {
    public let tunnelRemoteAddress: String
    public let ipv4Address: String
    public let ipv4SubnetMask: String
    public let includedRoutes: [Ipv4RouteSpec]
    public let excludedRoutes: [Ipv4RouteSpec]
    public let dnsServers: [String]
    public let dnsMatchDomains: [String]
    public let mtu: Int

    /// Creates a tunnel settings specification.
    public init(
        tunnelRemoteAddress: String,
        ipv4Address: String,
        ipv4SubnetMask: String,
        includedRoutes: [Ipv4RouteSpec],
        excludedRoutes: [Ipv4RouteSpec],
        dnsServers: [String],
        dnsMatchDomains: [String],
        mtu: Int
    ) {
        self.tunnelRemoteAddress = tunnelRemoteAddress
        self.ipv4Address = ipv4Address
        self.ipv4SubnetMask = ipv4SubnetMask
        self.includedRoutes = includedRoutes
        self.excludedRoutes = excludedRoutes
        self.dnsServers = dnsServers
        self.dnsMatchDomains = dnsMatchDomains
        self.mtu = mtu
    }
}

/// Builds iOS `NEPacketTunnelNetworkSettings` enforcing `/32` TUN, split routes, and Split-DNS.
public enum TunnelNetworkSettingsBuilder: Sendable {
    public static let pointToPointSubnetMask = "255.255.255.255"
    private static let fallbackTunnelRemoteIp = "192.0.2.1"

    /// Validates and builds a pure Swift specification from `MobileTunnelNetworkConfig`.
    public static func buildSpec(
        from config: MobileTunnelNetworkConfig,
        serverRemoteEndpoint: String? = nil
    ) throws -> TunnelSettingsSpec {
        guard config.tunInterfacePrefixLen == 32 else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "TUN interface prefix length must be /32 on iOS"
            )
        }
        guard parseIPv4UInt32(config.overlayIp) != nil else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Invalid overlay IPv4 address"
            )
        }
        guard let dnsIpUInt32 = parseIPv4UInt32(config.overlayDnsIp) else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Invalid overlay DNS IPv4 address"
            )
        }
        let trimmedDomain = config.domainSuffix.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedDomain.isEmpty else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Split-DNS domain suffix cannot be empty"
            )
        }
        guard config.tunMtu >= 576 && config.tunMtu <= 9000 else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Invalid TUN MTU \(config.tunMtu)"
            )
        }

        var routes: [Ipv4RouteSpec] = []
        var parsedRoutePairs: [(network: UInt32, mask: UInt32)] = []

        for cidr in config.includedRoutesCidr {
            let parsed = try parseNonDefaultCidr(cidr)
            parsedRoutePairs.append(parsed)
            routes.append(
                Ipv4RouteSpec(
                    destination: formatIPv4UInt32(parsed.network),
                    subnetMask: formatIPv4UInt32(parsed.mask)
                )
            )
        }

        let dnsCovered = parsedRoutePairs.contains { (dnsIpUInt32 & $0.mask) == $0.network }
        if !dnsCovered {
            routes.append(
                Ipv4RouteSpec(
                    destination: config.overlayDnsIp,
                    subnetMask: pointToPointSubnetMask
                )
            )
        }

        let remoteAddress = resolveTunnelRemoteIp(from: serverRemoteEndpoint)

        return TunnelSettingsSpec(
            tunnelRemoteAddress: remoteAddress,
            ipv4Address: config.overlayIp,
            ipv4SubnetMask: pointToPointSubnetMask,
            includedRoutes: routes,
            excludedRoutes: [],
            dnsServers: [config.overlayDnsIp],
            dnsMatchDomains: [trimmedDomain],
            mtu: Int(config.tunMtu)
        )
    }

    /// Converts a `MobileTunnelNetworkConfig` into iOS `NEPacketTunnelNetworkSettings`.
    public static func buildNetworkSettings(
        from config: MobileTunnelNetworkConfig,
        serverRemoteEndpoint: String? = nil
    ) throws -> NEPacketTunnelNetworkSettings {
        let spec = try buildSpec(from: config, serverRemoteEndpoint: serverRemoteEndpoint)
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: spec.tunnelRemoteAddress)

        let ipv4 = NEIPv4Settings(
            addresses: [spec.ipv4Address],
            subnetMasks: [spec.ipv4SubnetMask]
        )
        ipv4.includedRoutes = spec.includedRoutes.map {
            NEIPv4Route(destinationAddress: $0.destination, subnetMask: $0.subnetMask)
        }
        ipv4.excludedRoutes = []
        settings.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: spec.dnsServers)
        dns.matchDomains = spec.dnsMatchDomains
        settings.dnsSettings = dns

        settings.mtu = NSNumber(value: spec.mtu)
        return settings
    }

    /// Parses an IPv4 CIDR string and rejects `0.0.0.0/0` default routes (`BLK-MOB-G1-01`).
    public static func parseNonDefaultCidr(
        _ cidr: String
    ) throws -> (network: UInt32, mask: UInt32) {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let ipValue = parseIPv4UInt32(String(parts[0])),
              let prefixLen = Int(parts[1]),
              (0...32).contains(prefixLen) else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Invalid IPv4 CIDR route"
            )
        }
        guard prefixLen > 0 else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Default route 0.0.0.0/0 is forbidden in split-tunnel mode"
            )
        }
        let maskValue: UInt32 = prefixLen == 32 ? UInt32.max : (~UInt32(0) << (32 - prefixLen))
        return (network: ipValue & maskValue, mask: maskValue)
    }

    /// Parses a dotted IPv4 literal into host-order `UInt32`.
    public static func parseIPv4UInt32(_ ipString: String) -> UInt32? {
        let trimmed = ipString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let addr = IPv4Address(trimmed), addr.rawValue.count == 4 else {
            return nil
        }
        return addr.rawValue.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    /// Formats a host-order `UInt32` into dotted IPv4 text.
    public static func formatIPv4UInt32(_ value: UInt32) -> String {
        let b0 = (value >> 24) & 0xFF
        let b1 = (value >> 16) & 0xFF
        let b2 = (value >> 8) & 0xFF
        let b3 = value & 0xFF
        return "\(b0).\(b1).\(b2).\(b3)"
    }

    private static func resolveTunnelRemoteIp(from serverEndpoint: String?) -> String {
        guard let endpoint = serverEndpoint?.trimmingCharacters(in: .whitespacesAndNewlines),
              !endpoint.isEmpty else {
            return fallbackTunnelRemoteIp
        }
        let host: String
        if endpoint.hasPrefix("["), let closeIdx = endpoint.firstIndex(of: "]") {
            let start = endpoint.index(after: endpoint.startIndex)
            host = String(endpoint[start..<closeIdx])
        } else if let colonIdx = endpoint.lastIndex(of: ":"),
                  endpoint.filter({ $0 == ":" }).count == 1 {
            host = String(endpoint[..<colonIdx])
        } else {
            host = endpoint
        }
        if parseIPv4UInt32(host) != nil {
            return host
        }
        return fallbackTunnelRemoteIp
    }
}
