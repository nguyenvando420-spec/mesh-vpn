import Foundation

/// Request sent to `POST /v1/agent/ping`.
public struct PingRequest: Codable, Equatable, Sendable {
    public let target: String
    public let count: UInt16
    public let forceDirect: Bool
    public let timeoutMs: UInt64

    public enum CodingKeys: String, CodingKey {
        case target
        case count
        case forceDirect = "force_direct"
        case timeoutMs = "timeout_ms"
    }

    public init(target: String, count: UInt16, forceDirect: Bool, timeoutMs: UInt64) {
        self.target = target
        self.count = count
        self.forceDirect = forceDirect
        self.timeoutMs = timeoutMs
    }
}

/// Path traversed by a single Disco ping probe sample.
public enum PingVia: String, Codable, Equatable, Hashable, Sendable {
    case direct
    case relay
    case timeout
}

/// Single latency probe measurement inside `PingResponse`.
public struct PingSample: Codable, Equatable, Sendable {
    public let seq: UInt16
    public let via: PingVia
    public let endpoint: String?
    public let rttMs: Double?

    public enum CodingKeys: String, CodingKey {
        case seq
        case via
        case endpoint
        case rttMs = "rtt_ms"
    }

    public init(seq: UInt16, via: PingVia, endpoint: String? = nil, rttMs: Double? = nil) {
        self.seq = seq
        self.via = via
        self.endpoint = endpoint
        self.rttMs = rttMs
    }
}

/// Response returned from `POST /v1/agent/ping`.
public struct PingResponse: Codable, Equatable, Sendable {
    public let targetName: String
    public let targetOverlayIp: String
    public let samples: [PingSample]
    public let packetsSent: UInt16
    public let packetsReceived: UInt16
    public let lossPercent: Double
    public let rttMinMs: Double?
    public let rttAvgMs: Double?
    public let rttMaxMs: Double?

    public enum CodingKeys: String, CodingKey {
        case targetName = "target_name"
        case targetOverlayIp = "target_overlay_ip"
        case samples
        case packetsSent = "packets_sent"
        case packetsReceived = "packets_received"
        case lossPercent = "loss_percent"
        case rttMinMs = "rtt_min_ms"
        case rttAvgMs = "rtt_avg_ms"
        case rttMaxMs = "rtt_max_ms"
    }

    public init(
        targetName: String,
        targetOverlayIp: String,
        samples: [PingSample] = [],
        packetsSent: UInt16 = 0,
        packetsReceived: UInt16 = 0,
        lossPercent: Double = 0,
        rttMinMs: Double? = nil,
        rttAvgMs: Double? = nil,
        rttMaxMs: Double? = nil
    ) {
        self.targetName = targetName
        self.targetOverlayIp = targetOverlayIp
        self.samples = samples
        self.packetsSent = packetsSent
        self.packetsReceived = packetsReceived
        self.lossPercent = lossPercent
        self.rttMinMs = rttMinMs
        self.rttAvgMs = rttAvgMs
        self.rttMaxMs = rttMaxMs
    }
}

/// Response returned from `POST /v1/agent/netcheck`.
public struct NetcheckResponse: Codable, Equatable, Sendable {
    public let udpEgressOk: Bool
    public let stunReachable: Bool
    public let stunEndpointTested: String?
    public let reflexiveIpv4: String?
    public let ipv6Available: Bool
    public let natMapping: NatMappingKind
    public let natNote: String
    public let controlTcpReachable: Bool
    public let controlTcpEndpointTested: String?
    public let relayRttMs: Double?
    public let diagnosticHint: String?

    public enum CodingKeys: String, CodingKey {
        case udpEgressOk = "udp_egress_ok"
        case stunReachable = "stun_reachable"
        case stunEndpointTested = "stun_endpoint_tested"
        case reflexiveIpv4 = "reflexive_ipv4"
        case ipv6Available = "ipv6_available"
        case natMapping = "nat_mapping"
        case natNote = "nat_note"
        case controlTcpReachable = "control_tcp_reachable"
        case controlTcpEndpointTested = "control_tcp_endpoint_tested"
        case relayRttMs = "relay_rtt_ms"
        case diagnosticHint = "diagnostic_hint"
    }

    public init(
        udpEgressOk: Bool,
        stunReachable: Bool,
        stunEndpointTested: String? = nil,
        reflexiveIpv4: String? = nil,
        ipv6Available: Bool = false,
        natMapping: NatMappingKind = .unknown,
        natNote: String = "",
        controlTcpReachable: Bool = false,
        controlTcpEndpointTested: String? = nil,
        relayRttMs: Double? = nil,
        diagnosticHint: String? = nil
    ) {
        self.udpEgressOk = udpEgressOk
        self.stunReachable = stunReachable
        self.stunEndpointTested = stunEndpointTested
        self.reflexiveIpv4 = reflexiveIpv4
        self.ipv6Available = ipv6Available
        self.natMapping = natMapping
        self.natNote = natNote
        self.controlTcpReachable = controlTcpReachable
        self.controlTcpEndpointTested = controlTcpEndpointTested
        self.relayRttMs = relayRttMs
        self.diagnosticHint = diagnosticHint
    }
}

/// Privileged request sent to `POST /v1/agent/up` (`meshd-admin`).
public struct AgentUpRequest:
    Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let serverEndpoint: String
    public let portOverride: UInt16?
    public let serverPin: String?
    public let preauthKey: String?
    public let nodeName: String?

    public enum CodingKeys: String, CodingKey {
        case serverEndpoint = "server_endpoint"
        case portOverride = "port_override"
        case serverPin = "server_pin"
        case preauthKey = "preauth_key"
        case nodeName = "node_name"
    }

    public init(
        serverEndpoint: String,
        portOverride: UInt16? = nil,
        serverPin: String? = nil,
        preauthKey: String? = nil,
        nodeName: String? = nil
    ) {
        self.serverEndpoint = serverEndpoint
        self.portOverride = portOverride
        self.serverPin = serverPin
        self.preauthKey = preauthKey
        self.nodeName = nodeName
    }

    public var description: String {
        let keyStatus = preauthKey == nil ? "nil" : "[REDACTED]"
        return "AgentUpRequest(endpoint=\(serverEndpoint), preauth_key=\(keyStatus))"
    }

    public var debugDescription: String {
        description
    }
}

/// Privileged request sent to `POST /v1/agent/set` (`meshd-admin`).
public struct AgentSetRequest: Codable, Equatable, Sendable {
    public let serverEndpoint: String
    public let serverPin: String?

    public enum CodingKeys: String, CodingKey {
        case serverEndpoint = "server_endpoint"
        case serverPin = "server_pin"
    }

    public init(serverEndpoint: String, serverPin: String? = nil) {
        self.serverEndpoint = serverEndpoint
        self.serverPin = serverPin
    }
}

/// Privileged request sent to `POST /v1/agent/rotate-key` (`meshd-admin`).
public struct AgentRotateKeyRequest:
    Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let preauthKey: String

    public enum CodingKeys: String, CodingKey {
        case preauthKey = "preauth_key"
    }

    public init(preauthKey: String) {
        self.preauthKey = preauthKey
    }

    public var description: String {
        "AgentRotateKeyRequest(preauth_key=[REDACTED])"
    }

    public var debugDescription: String {
        description
    }
}

/// Empty request sent to `POST /v1/agent/reset-identity` (`ADR-024`).
public struct AgentResetIdentityRequest: Codable, Equatable, Sendable {
    public init() {}
}

/// Generic acknowledgement response returned from `up`, `down`, `cleanup`, `set`, `rotate-key`.
public struct AgentActionResponse: Codable, Equatable, Sendable {
    public let state: DaemonState
    public let message: String

    public init(state: DaemonState, message: String) {
        self.state = state
        self.message = message
    }
}

/// Canonical 12-variant wire error taxonomy matching `crates/mesh-core/src/error.rs`.
public enum MeshWireErrorKind: String, Codable, Equatable, Hashable, Sendable {
    case `internal`
    case invalidArgument = "invalid_argument"
    case unauthenticated
    case permissionDenied = "permission_denied"
    case nodeRevoked = "node_revoked"
    case nodeKeyExpired = "node_key_expired"
    case notFound = "not_found"
    case conflict
    case rateLimited = "rate_limited"
    case unavailable
    case clockSkew = "clock_skew"
    case pinMismatch = "pin_mismatch"
}

/// Wire JSON error payload nested under `{"error": ...}`.
public struct ErrorEnvelope: Codable, Equatable, Sendable {
    public let kind: MeshWireErrorKind
    public let code: String
    public let message: String
    public let requestId: String

    public enum CodingKeys: String, CodingKey {
        case kind
        case code
        case message
        case requestId = "request_id"
    }

    public init(kind: MeshWireErrorKind, code: String, message: String, requestId: String) {
        self.kind = kind
        self.code = code
        self.message = message
        self.requestId = requestId
    }
}

/// Outer HTTP/IPC JSON error wrapper matching `{"error": { ... }}`.
public struct ErrorResponse: Codable, Equatable, Sendable {
    public let error: ErrorEnvelope

    public init(error: ErrorEnvelope) {
        self.error = error
    }
}

/// Decoded JSON response paired with extracted `X-Mesh-Agent-Version` header metadata.
public struct IpcResponseWithMeta<T: Sendable>: Sendable {
    public let value: T
    public let agentVersionHeader: String?
    public let statusCode: Int

    public init(value: T, agentVersionHeader: String?, statusCode: Int) {
        self.value = value
        self.agentVersionHeader = agentVersionHeader
        self.statusCode = statusCode
    }
}

/// Metadata extracted from `POST /v1/agent/bugreport/stream` headers (`ADR-023`).
public struct StreamedBugreportMetadata: Equatable, Sendable {
    public let totalBytes: UInt64
    public let scrubbedItems: UInt32
    public let agentVersion: String?

    public init(totalBytes: UInt64, scrubbedItems: UInt32, agentVersion: String?) {
        self.totalBytes = totalBytes
        self.scrubbedItems = scrubbedItems
        self.agentVersion = agentVersion
    }
}
