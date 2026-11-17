import Foundation

/// Overall lifecycle state of the `meshd` agent daemon (`crates/mesh-proto/src/agent_ipc.rs`).
public enum DaemonState: String, Codable, Equatable, Hashable, Sendable, CaseIterable {
    case stopped
    case connecting
    case connected
    case reauthRequired = "reauth_required"
    case revoked
    case degraded
}

/// Control TLS trust strategy currently used by `meshd`.
public enum TlsAuthMode: String, Codable, Equatable, Hashable, Sendable {
    case spkiPin = "spki_pin"
    case systemCa = "system_ca"
}

/// Active transport path state for an overlay peer.
public enum ActivePathKind: String, Codable, Equatable, Hashable, Sendable {
    case direct
    case relay
    case none
}

/// Origin class of a peer UDP endpoint candidate (`crates/mesh-proto/src/netmap.rs`).
public enum CandidateSource: String, Codable, Equatable, Hashable, Sendable {
    case lan
    case ipv6
    case reflexive
}

/// Validated peer UDP endpoint paired with its discovery provenance.
public struct CandidateEndpoint: Codable, Equatable, Hashable, Sendable {
    public let addr: String
    public let source: CandidateSource

    public init(addr: String, source: CandidateSource) {
        self.addr = addr
        self.source = source
    }
}

/// NAT address mapping classification observed during `netcheck` / STUN probes.
public enum NatMappingKind: String, Codable, Equatable, Hashable, Sendable {
    case eimOrAdm = "eim_or_adm"
    case portDependent = "port_dependent"
    case unknown

    public var displayLabel: String {
        switch self {
        case .eimOrAdm:
            return "EIM / ADM (P2P Friendly)"
        case .portDependent:
            return "Port-Dependent (Symmetric NAT)"
        case .unknown:
            return "Unknown"
        }
    }
}

/// Status of the daemon's connection to Control, Relay, and STUN infrastructure.
public struct ServerConnectionStatus: Codable, Equatable, Sendable {
    public let controlEndpoint: String
    public let relayEndpoint: String
    public let stunEndpoints: [String]
    public let tlsAuthMode: TlsAuthMode
    public let activePin: String?
    public let nextPin: String?
    public let controlConnected: Bool
    public let relayConnected: Bool
    public let relayRttMs: UInt64?
    public let migrationPendingEndpoint: String?
    public let lastError: String?

    public enum CodingKeys: String, CodingKey {
        case controlEndpoint = "control_endpoint"
        case relayEndpoint = "relay_endpoint"
        case stunEndpoints = "stun_endpoints"
        case tlsAuthMode = "tls_auth_mode"
        case activePin = "active_pin"
        case nextPin = "next_pin"
        case controlConnected = "control_connected"
        case relayConnected = "relay_connected"
        case relayRttMs = "relay_rtt_ms"
        case migrationPendingEndpoint = "migration_pending_endpoint"
        case lastError = "last_error"
    }

    public init(
        controlEndpoint: String,
        relayEndpoint: String = "",
        stunEndpoints: [String] = [],
        tlsAuthMode: TlsAuthMode = .spkiPin,
        activePin: String? = nil,
        nextPin: String? = nil,
        controlConnected: Bool = false,
        relayConnected: Bool = false,
        relayRttMs: UInt64? = nil,
        migrationPendingEndpoint: String? = nil,
        lastError: String? = nil
    ) {
        self.controlEndpoint = controlEndpoint
        self.relayEndpoint = relayEndpoint
        self.stunEndpoints = stunEndpoints
        self.tlsAuthMode = tlsAuthMode
        self.activePin = activePin
        self.nextPin = nextPin
        self.controlConnected = controlConnected
        self.relayConnected = relayConnected
        self.relayRttMs = relayRttMs
        self.migrationPendingEndpoint = migrationPendingEndpoint
        self.lastError = lastError
    }
}

/// Local network interface, UDP socket, and NAT diagnostic summary for this node.
public struct SelfNetworkStatus: Codable, Equatable, Sendable {
    public let localUdpPort: UInt16
    public let boundPhysicalInterface: String?
    public let natType: NatMappingKind
    public let natClassificationNote: String?
    public let overlayConflictWarning: String?
    public let macosFirewallWarning: String?
    public let candidates: [CandidateEndpoint]

    public enum CodingKeys: String, CodingKey {
        case localUdpPort = "local_udp_port"
        case boundPhysicalInterface = "bound_physical_interface"
        case natType = "nat_type"
        case natClassificationNote = "nat_classification_note"
        case overlayConflictWarning = "overlay_conflict_warning"
        case macosFirewallWarning = "macos_firewall_warning"
        case candidates
    }

    public init(
        localUdpPort: UInt16 = 0,
        boundPhysicalInterface: String? = nil,
        natType: NatMappingKind = .unknown,
        natClassificationNote: String? = nil,
        overlayConflictWarning: String? = nil,
        macosFirewallWarning: String? = nil,
        candidates: [CandidateEndpoint] = []
    ) {
        self.localUdpPort = localUdpPort
        self.boundPhysicalInterface = boundPhysicalInterface
        self.natType = natType
        self.natClassificationNote = natClassificationNote
        self.overlayConflictWarning = overlayConflictWarning
        self.macosFirewallWarning = macosFirewallWarning
        self.candidates = candidates
    }
}

/// Per-peer runtime connectivity and byte counters returned by status/peers endpoints.
public struct AgentPeerStatus: Codable, Equatable, Identifiable, Sendable {
    public var id: String { nodeId }

    public let nodeId: String
    public let name: String
    public let fqdn: String
    public let overlayIp: String
    public let online: Bool
    public let activePath: ActivePathKind
    public let directEndpoint: String?
    public let rttMs: UInt64?
    public let lastHandshakeAtMs: UInt64?
    public let rxBytes: UInt64
    public let txBytes: UInt64

    public enum CodingKeys: String, CodingKey {
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

    public init(
        nodeId: String,
        name: String,
        fqdn: String,
        overlayIp: String,
        online: Bool,
        activePath: ActivePathKind = .none,
        directEndpoint: String? = nil,
        rttMs: UInt64? = nil,
        lastHandshakeAtMs: UInt64? = nil,
        rxBytes: UInt64 = 0,
        txBytes: UInt64 = 0
    ) {
        self.nodeId = nodeId
        self.name = name
        self.fqdn = fqdn
        self.overlayIp = overlayIp
        self.online = online
        self.activePath = activePath
        self.directEndpoint = directEndpoint
        self.rttMs = rttMs
        self.lastHandshakeAtMs = lastHandshakeAtMs
        self.rxBytes = rxBytes
        self.txBytes = txBytes
    }
}

/// Complete 13-field non-secret payload returned by `/v1/agent/status` and `/v1/agent/peers`.
public struct AgentStatusResponse: Codable, Equatable, Sendable {
    public let daemonState: DaemonState
    public let nodeId: String?
    public let nodeName: String?
    public let fqdn: String?
    public let overlayIp: String?
    public let overlayCidr: String?
    public let tunInterfaceName: String?
    public let tunMtu: UInt16
    public let netmapVersion: UInt64
    public let keyExpiresAtMs: UInt64?
    public let serverConnection: ServerConnectionStatus?
    public let selfNetwork: SelfNetworkStatus
    public let peers: [AgentPeerStatus]

    public enum CodingKeys: String, CodingKey {
        case daemonState = "daemon_state"
        case nodeId = "node_id"
        case nodeName = "node_name"
        case fqdn
        case overlayIp = "overlay_ip"
        case overlayCidr = "overlay_cidr"
        case tunInterfaceName = "tun_interface_name"
        case tunMtu = "tun_mtu"
        case netmapVersion = "netmap_version"
        case keyExpiresAtMs = "key_expires_at_ms"
        case serverConnection = "server_connection"
        case selfNetwork = "self_network"
        case peers
    }

    public init(
        daemonState: DaemonState,
        nodeId: String? = nil,
        nodeName: String? = nil,
        fqdn: String? = nil,
        overlayIp: String? = nil,
        overlayCidr: String? = nil,
        tunInterfaceName: String? = nil,
        tunMtu: UInt16 = 1_280,
        netmapVersion: UInt64 = 0,
        keyExpiresAtMs: UInt64? = nil,
        serverConnection: ServerConnectionStatus? = nil,
        selfNetwork: SelfNetworkStatus = SelfNetworkStatus(),
        peers: [AgentPeerStatus] = []
    ) {
        self.daemonState = daemonState
        self.nodeId = nodeId
        self.nodeName = nodeName
        self.fqdn = fqdn
        self.overlayIp = overlayIp
        self.overlayCidr = overlayCidr
        self.tunInterfaceName = tunInterfaceName
        self.tunMtu = tunMtu
        self.netmapVersion = netmapVersion
        self.keyExpiresAtMs = keyExpiresAtMs
        self.serverConnection = serverConnection
        self.selfNetwork = selfNetwork
        self.peers = peers
    }
}

/// Agent daemon version metadata returned from `GET /v1/agent/version` (`ADR-024`).
public struct AgentVersionResponse: Codable, Equatable, Sendable {
    public let agentVersion: String
    public let protocolVersion: UInt16
    public let binaryName: String

    public enum CodingKeys: String, CodingKey {
        case agentVersion = "agent_version"
        case protocolVersion = "protocol_version"
        case binaryName = "binary_name"
    }

    public init(agentVersion: String, protocolVersion: UInt16, binaryName: String) {
        self.agentVersion = agentVersion
        self.protocolVersion = protocolVersion
        self.binaryName = binaryName
    }
}
