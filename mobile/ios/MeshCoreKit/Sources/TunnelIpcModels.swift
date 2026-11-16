import Foundation

/// Bounded (`<= 4096 B`) IPC request sent from `MeshApp` to `MeshPacketTunnel`.
public struct IosTunnelIpcRequest: Codable, Sendable, Equatable {
    /// Supported control-and-telemetry actions across App/Extension IPC.
    public enum Action: String, Codable, Sendable, Equatable {
        case getStatus = "get_status"
        case ping
        case netcheck
        case exportBugreport = "export_bugreport"
        case prepareStop = "prepare_stop"
    }

    public let action: Action
    public let target: String?
    public let count: UInt16?
    public let forceDirect: Bool?
    public let timeoutMs: UInt64?
    public let bugreportDestPath: String?

    enum CodingKeys: String, CodingKey {
        case action
        case target
        case count
        case forceDirect = "force_direct"
        case timeoutMs = "timeout_ms"
        case bugreportDestPath = "bugreport_dest_path"
    }

    public init(
        action: Action,
        target: String? = nil,
        count: UInt16? = nil,
        forceDirect: Bool? = nil,
        timeoutMs: UInt64? = nil,
        bugreportDestPath: String? = nil
    ) {
        self.action = action
        self.target = target
        self.count = count
        self.forceDirect = forceDirect
        self.timeoutMs = timeoutMs
        self.bugreportDestPath = bugreportDestPath
    }
}

/// JSON-serializable mirror of Rust `MobileServerStatus`.
public struct CodableServerStatus: Codable, Sendable, Equatable {
    public let controlEndpoint: String
    public let relayEndpoint: String
    public var stunEndpoints: [String]
    public let tlsAuthMode: String
    public let activePin: String?
    public let nextPin: String?
    public let controlConnected: Bool
    public let relayConnected: Bool
    public let relayRttMs: UInt64?
    public var lastError: String?

    enum CodingKeys: String, CodingKey {
        case controlEndpoint = "control_endpoint"
        case relayEndpoint = "relay_endpoint"
        case stunEndpoints = "stun_endpoints"
        case tlsAuthMode = "tls_auth_mode"
        case activePin = "active_pin"
        case nextPin = "next_pin"
        case controlConnected = "control_connected"
        case relayConnected = "relay_connected"
        case relayRttMs = "relay_rtt_ms"
        case lastError = "last_error"
    }

    public init(from model: MobileServerStatus) {
        self.controlEndpoint = model.controlEndpoint
        self.relayEndpoint = model.relayEndpoint
        self.stunEndpoints = model.stunEndpoints
        self.tlsAuthMode = TunnelIpcCodec.encodeTlsMode(model.tlsAuthMode)
        self.activePin = model.activePin
        self.nextPin = model.nextPin
        self.controlConnected = model.controlConnected
        self.relayConnected = model.relayConnected
        self.relayRttMs = model.relayRttMs
        self.lastError = model.lastError.map(MeshSecretScrubber.scrub)
    }

    public func toMobileModel() -> MobileServerStatus {
        MobileServerStatus(
            controlEndpoint: controlEndpoint,
            relayEndpoint: relayEndpoint,
            stunEndpoints: stunEndpoints,
            tlsAuthMode: TunnelIpcCodec.decodeTlsMode(tlsAuthMode),
            activePin: activePin,
            nextPin: nextPin,
            controlConnected: controlConnected,
            relayConnected: relayConnected,
            relayRttMs: relayRttMs,
            lastError: lastError
        )
    }
}

/// JSON-serializable mirror of Rust `MobileSelfNetworkStatus`.
public struct CodableSelfNetworkStatus: Codable, Sendable, Equatable {
    public let localUdpPort: UInt16
    public let boundPhysicalInterface: String?
    public let natType: String
    public var overlayConflictWarning: String?
    public let nat64ActivePrefix: String?
    public var candidates: [String]

    enum CodingKeys: String, CodingKey {
        case localUdpPort = "local_udp_port"
        case boundPhysicalInterface = "bound_physical_interface"
        case natType = "nat_type"
        case overlayConflictWarning = "overlay_conflict_warning"
        case nat64ActivePrefix = "nat64_active_prefix"
        case candidates
    }

    public init(from model: MobileSelfNetworkStatus) {
        self.localUdpPort = model.localUdpPort
        self.boundPhysicalInterface = model.boundPhysicalInterface
        self.natType = TunnelIpcCodec.encodeNatKind(model.natType)
        self.overlayConflictWarning = model.overlayConflictWarning.map(MeshSecretScrubber.scrub)
        self.nat64ActivePrefix = model.nat64ActivePrefix
        self.candidates = model.candidates
    }

    public func toMobileModel() -> MobileSelfNetworkStatus {
        MobileSelfNetworkStatus(
            localUdpPort: localUdpPort,
            boundPhysicalInterface: boundPhysicalInterface,
            natType: TunnelIpcCodec.decodeNatKind(natType),
            overlayConflictWarning: overlayConflictWarning,
            nat64ActivePrefix: nat64ActivePrefix,
            candidates: candidates
        )
    }
}

/// JSON-serializable mirror of Rust `MobilePeerStatus`.
public struct CodablePeerStatus: Codable, Sendable, Equatable, Identifiable {
    public var id: String { nodeId }
    public let nodeId: String
    public let name: String
    public let fqdn: String
    public let overlayIp: String
    public let online: Bool
    public let activePath: String
    public let directEndpoint: String?
    public let rttMs: UInt64?
    public let lastHandshakeAtMs: UInt64?
    public let rxBytes: UInt64
    public let txBytes: UInt64

    enum CodingKeys: String, CodingKey {
        case nodeId = "node_id"
        case name
        case fqdn
        case overlayIp = "overlay_ip"
        case online
        case activePath = "active_path"
        case directEndpoint = "direct_endpoint"
        case rttMs = "rtt_ms"
        case lastHandshakeAtMs = "last_handshake_at_ms"
        case rxBytes = "rx_bytes"
        case txBytes = "tx_bytes"
    }

    public init(from model: MobilePeerStatus) {
        self.nodeId = model.nodeId
        self.name = model.name
        self.fqdn = model.fqdn
        self.overlayIp = model.overlayIp
        self.online = model.online
        self.activePath = TunnelIpcCodec.encodeActivePath(model.activePath)
        self.directEndpoint = model.directEndpoint
        self.rttMs = model.rttMs
        self.lastHandshakeAtMs = model.lastHandshakeAtMs
        self.rxBytes = model.rxBytes
        self.txBytes = model.txBytes
    }

    public func toMobileModel() -> MobilePeerStatus {
        MobilePeerStatus(
            nodeId: nodeId,
            name: name,
            fqdn: fqdn,
            overlayIp: overlayIp,
            online: online,
            activePath: TunnelIpcCodec.decodeActivePath(activePath),
            directEndpoint: directEndpoint,
            rttMs: rttMs,
            lastHandshakeAtMs: lastHandshakeAtMs,
            rxBytes: rxBytes,
            txBytes: txBytes
        )
    }
}

/// JSON-serializable mirror of Rust `MobilePlatformWarning`.
public struct CodablePlatformWarning: Codable, Sendable, Equatable {
    public let kind: String
    public var message: String

    public init(from model: MobilePlatformWarning) {
        self.kind = TunnelIpcCodec.encodeWarningKind(model.kind)
        self.message = MeshSecretScrubber.scrub(model.message)
    }

    public func toMobileModel() -> MobilePlatformWarning {
        MobilePlatformWarning(
            kind: TunnelIpcCodec.decodeWarningKind(kind),
            message: message
        )
    }
}

/// JSON mirror of `MobileStatusSnapshot` matching `status-snapshot.json`.
public struct CodableStatusSnapshot: Codable, Sendable, Equatable {
    public let daemonState: String
    public let nodeId: String?
    public let nodeName: String?
    public let fqdn: String?
    public let overlayIp: String?
    public let overlayCidr: String?
    public let overlayDnsIp: String?
    public let tunInterfaceName: String?
    public let tunMtu: UInt16
    public let netmapVersion: UInt64
    public let keyExpiresAtMs: UInt64?
    public var serverConnection: CodableServerStatus?
    public var selfNetwork: CodableSelfNetworkStatus
    public var peers: [CodablePeerStatus]
    public var warnings: [CodablePlatformWarning]

    enum CodingKeys: String, CodingKey {
        case daemonState = "daemon_state"
        case nodeId = "node_id"
        case nodeName = "node_name"
        case fqdn
        case overlayIp = "overlay_ip"
        case overlayCidr = "overlay_cidr"
        case overlayDnsIp = "overlay_dns_ip"
        case tunInterfaceName = "tun_interface_name"
        case tunMtu = "tun_mtu"
        case netmapVersion = "netmap_version"
        case keyExpiresAtMs = "key_expires_at_ms"
        case serverConnection = "server_connection"
        case selfNetwork = "self_network"
        case peers
        case warnings
    }

    public init(from model: MobileStatusSnapshot) {
        self.daemonState = TunnelIpcCodec.encodeDaemonState(model.daemonState)
        self.nodeId = model.nodeId
        self.nodeName = model.nodeName
        self.fqdn = model.fqdn
        self.overlayIp = model.overlayIp
        self.overlayCidr = model.overlayCidr
        self.overlayDnsIp = model.overlayDnsIp
        self.tunInterfaceName = model.tunInterfaceName
        self.tunMtu = model.tunMtu
        self.netmapVersion = model.netmapVersion
        self.keyExpiresAtMs = model.keyExpiresAtMs
        self.serverConnection = model.serverConnection.map(CodableServerStatus.init)
        self.selfNetwork = CodableSelfNetworkStatus(from: model.selfNetwork)
        self.peers = model.peers.map(CodablePeerStatus.init)
        self.warnings = model.warnings.map(CodablePlatformWarning.init)
    }

    public func toMobileModel() -> MobileStatusSnapshot {
        MobileStatusSnapshot(
            daemonState: TunnelIpcCodec.decodeDaemonState(daemonState),
            nodeId: nodeId,
            nodeName: nodeName,
            fqdn: fqdn,
            overlayIp: overlayIp,
            overlayCidr: overlayCidr,
            overlayDnsIp: overlayDnsIp,
            tunInterfaceName: tunInterfaceName,
            tunMtu: tunMtu,
            netmapVersion: netmapVersion,
            keyExpiresAtMs: keyExpiresAtMs,
            serverConnection: serverConnection?.toMobileModel(),
            selfNetwork: selfNetwork.toMobileModel(),
            peers: peers.map { $0.toMobileModel() },
            warnings: warnings.map { $0.toMobileModel() }
        )
    }
}

/// JSON-serializable mirror of Rust `MobilePingSample`.
public struct CodablePingSample: Codable, Sendable, Equatable {
    public let seq: UInt16
    public let via: String
    public let endpoint: String?
    public let rttMs: Double?

    enum CodingKeys: String, CodingKey {
        case seq
        case via
        case endpoint
        case rttMs = "rtt_ms"
    }

    public init(from model: MobilePingSample) {
        self.seq = model.seq
        self.via = TunnelIpcCodec.encodePingVia(model.via)
        self.endpoint = model.endpoint
        self.rttMs = model.rttMs
    }

    public func toMobileModel() -> MobilePingSample {
        MobilePingSample(
            seq: seq,
            via: TunnelIpcCodec.decodePingVia(via),
            endpoint: endpoint,
            rttMs: rttMs
        )
    }
}

/// JSON-serializable mirror of Rust `MobilePingResponse`.
public struct CodablePingResponse: Codable, Sendable, Equatable {
    public let peerId: String
    public let peerName: String
    public let peerOverlayIp: String
    public var samples: [CodablePingSample]
    public let avgRttMs: Double?

    enum CodingKeys: String, CodingKey {
        case peerId = "peer_id"
        case peerName = "peer_name"
        case peerOverlayIp = "peer_overlay_ip"
        case samples
        case avgRttMs = "avg_rtt_ms"
    }

    public init(from model: MobilePingResponse) {
        self.peerId = model.peerId
        self.peerName = model.peerName
        self.peerOverlayIp = model.peerOverlayIp
        self.samples = model.samples.map(CodablePingSample.init)
        self.avgRttMs = model.avgRttMs
    }

    public func toMobileModel() -> MobilePingResponse {
        MobilePingResponse(
            peerId: peerId,
            peerName: peerName,
            peerOverlayIp: peerOverlayIp,
            samples: samples.map { $0.toMobileModel() },
            avgRttMs: avgRttMs
        )
    }
}

/// JSON-serializable mirror of Rust `MobileNetcheckResponse`.
public struct CodableNetcheckResponse: Codable, Sendable, Equatable {
    public let udpReachable: Bool
    public let ipv4Available: Bool
    public let ipv6Available: Bool
    public let natType: String
    public let mappedEndpoint: String?
    public let relayConnected: Bool
    public let relayRttMs: UInt64?
    public let nat64Prefix: String?

    enum CodingKeys: String, CodingKey {
        case udpReachable = "udp_reachable"
        case ipv4Available = "ipv4_available"
        case ipv6Available = "ipv6_available"
        case natType = "nat_type"
        case mappedEndpoint = "mapped_endpoint"
        case relayConnected = "relay_connected"
        case relayRttMs = "relay_rtt_ms"
        case nat64Prefix = "nat64_prefix"
    }

    public init(from model: MobileNetcheckResponse) {
        self.udpReachable = model.udpReachable
        self.ipv4Available = model.ipv4Available
        self.ipv6Available = model.ipv6Available
        self.natType = TunnelIpcCodec.encodeNatKind(model.natType)
        self.mappedEndpoint = model.mappedEndpoint
        self.relayConnected = model.relayConnected
        self.relayRttMs = model.relayRttMs
        self.nat64Prefix = model.nat64Prefix
    }

    public func toMobileModel() -> MobileNetcheckResponse {
        MobileNetcheckResponse(
            udpReachable: udpReachable,
            ipv4Available: ipv4Available,
            ipv6Available: ipv6Available,
            natType: TunnelIpcCodec.decodeNatKind(natType),
            mappedEndpoint: mappedEndpoint,
            relayConnected: relayConnected,
            relayRttMs: relayRttMs,
            nat64Prefix: nat64Prefix
        )
    }
}

/// JSON-serializable mirror of Rust `MobileBugreportResult`.
public struct CodableBugreportResult: Codable, Sendable, Equatable {
    public let bundlePath: String
    public let sizeBytes: UInt64
    public let scrubbedItems: UInt32

    enum CodingKeys: String, CodingKey {
        case bundlePath = "bundle_path"
        case sizeBytes = "size_bytes"
        case scrubbedItems = "scrubbed_items"
    }

    public init(from model: MobileBugreportResult) {
        self.bundlePath = model.bundlePath
        self.sizeBytes = model.sizeBytes
        self.scrubbedItems = model.scrubbedItems
    }

    public func toMobileModel() -> MobileBugreportResult {
        MobileBugreportResult(
            bundlePath: bundlePath,
            sizeBytes: sizeBytes,
            scrubbedItems: scrubbedItems
        )
    }
}

/// Bounded (`<= 4096 B`) IPC response sent back from `MeshPacketTunnel` to `MeshApp`.
public struct IosTunnelIpcResponse: Codable, Sendable, Equatable {
    public var ok: Bool
    public var errorCode: String?
    public var errorMessage: String?
    public var peersTruncated: Bool
    public var totalPeerCount: Int?
    public var status: CodableStatusSnapshot?
    public var ping: CodablePingResponse?
    public var netcheck: CodableNetcheckResponse?
    public var bugreport: CodableBugreportResult?

    enum CodingKeys: String, CodingKey {
        case ok
        case errorCode = "error_code"
        case errorMessage = "error_message"
        case peersTruncated = "peers_truncated"
        case totalPeerCount = "total_peer_count"
        case status
        case ping
        case netcheck
        case bugreport
    }

    public init(
        ok: Bool,
        errorCode: String? = nil,
        errorMessage: String? = nil,
        peersTruncated: Bool = false,
        totalPeerCount: Int? = nil,
        status: CodableStatusSnapshot? = nil,
        ping: CodablePingResponse? = nil,
        netcheck: CodableNetcheckResponse? = nil,
        bugreport: CodableBugreportResult? = nil
    ) {
        self.ok = ok
        self.errorCode = errorCode
        self.errorMessage = errorMessage.map(MeshSecretScrubber.scrub)
        self.peersTruncated = peersTruncated
        self.totalPeerCount = totalPeerCount
        self.status = status
        self.ping = ping
        self.netcheck = netcheck
        self.bugreport = bugreport
    }
}
