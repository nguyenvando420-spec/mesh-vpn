import Foundation

/// Strictly bounded (`<= 4096 B`) JSON codec for App/Extension IPC and App Group snapshot caching.
public enum TunnelIpcCodec: Sendable {
    public static func encodeRequest(_ request: IosTunnelIpcRequest) throws -> Data {
        let data = try makeEncoder().encode(request)
        guard data.count <= MeshConstants.maxIpcPayloadBytes else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "IPC request exceeds \(MeshConstants.maxIpcPayloadBytes) bytes"
            )
        }
        return data
    }

    public static func decodeRequest(from data: Data) throws -> IosTunnelIpcRequest {
        guard data.count <= MeshConstants.maxIpcPayloadBytes else {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "IPC request exceeds \(MeshConstants.maxIpcPayloadBytes) bytes"
            )
        }
        return try JSONDecoder().decode(IosTunnelIpcRequest.self, from: data)
    }

    /// Encodes a response capped strictly at `<= 4096 B`, tail-trimming peers and writing the
    /// full snapshot to `status-snapshot.json` when truncation occurs.
    public static func encodeResponse(
        _ response: IosTunnelIpcResponse,
        snapshotFallbackWriter: ((Data) throws -> Void)? = nil
    ) throws -> Data {
        var mutable = response
        if let msg = mutable.errorMessage {
            mutable.errorMessage = MeshSecretScrubber.scrub(msg)
        }

        let encoder = makeEncoder()
        if let initial = try? encoder.encode(mutable),
           initial.count <= MeshConstants.maxIpcPayloadBytes {
            return initial
        }

        if let trimmedData = encodeTrimmedStatusIfPossible(
            &mutable,
            encoder: encoder,
            snapshotFallbackWriter: snapshotFallbackWriter
        ) {
            return trimmedData
        }

        if var ping = mutable.ping {
            while !ping.samples.isEmpty {
                ping.samples.removeLast()
                mutable.ping = ping
                if let attempt = try? encoder.encode(mutable),
                   attempt.count <= MeshConstants.maxIpcPayloadBytes {
                    return attempt
                }
            }
        }

        let fallback = IosTunnelIpcResponse(
            ok: false,
            errorCode: "E_INTERNAL",
            errorMessage: "IPC response truncated beyond 4096 byte budget"
        )
        return try encoder.encode(fallback)
    }

    public static func decodeResponse(from data: Data) throws -> IosTunnelIpcResponse {
        guard data.count <= MeshConstants.maxIpcPayloadBytes else {
            throw MobileError.Internal(
                errorCode: "E_INTERNAL",
                message: "IPC response exceeded 4096 byte limit"
            )
        }
        return try JSONDecoder().decode(IosTunnelIpcResponse.self, from: data)
    }

    public static func encodeStatusSnapshot(_ model: MobileStatusSnapshot) throws -> Data {
        let codable = CodableStatusSnapshot(from: model)
        return try makeEncoder().encode(codable)
    }

    public static func decodeStatusSnapshot(from data: Data) throws -> MobileStatusSnapshot {
        let codable = try JSONDecoder().decode(CodableStatusSnapshot.self, from: data)
        return codable.toMobileModel()
    }

    private static func encodeTrimmedStatusIfPossible(
        _ mutable: inout IosTunnelIpcResponse,
        encoder: JSONEncoder,
        snapshotFallbackWriter: ((Data) throws -> Void)?
    ) -> Data? {
        guard var status = mutable.status else { return nil }
        if let snapshotFallbackWriter, let fullData = try? encoder.encode(status) {
            try? snapshotFallbackWriter(fullData)
        }
        let originalPeerCount = status.peers.count
        while !status.peers.isEmpty {
            status.peers.removeLast()
            mutable.status = status
            mutable.peersTruncated = true
            mutable.totalPeerCount = originalPeerCount
            if let attempt = try? encoder.encode(mutable),
               attempt.count <= MeshConstants.targetIpcPayloadBytes {
                return attempt
            }
        }
        return shrinkAuxiliaryStatusFields(&mutable, status: &status, encoder: encoder)
    }

    private static func shrinkAuxiliaryStatusFields(
        _ mutable: inout IosTunnelIpcResponse,
        status: inout CodableStatusSnapshot,
        encoder: JSONEncoder
    ) -> Data? {
        while !status.selfNetwork.candidates.isEmpty {
            status.selfNetwork.candidates.removeLast()
            mutable.status = status
            if let attempt = fitResponse(mutable, encoder: encoder) { return attempt }
        }
        while status.warnings.count > 1 {
            status.warnings.removeLast()
            mutable.status = status
            if let attempt = fitResponse(mutable, encoder: encoder) { return attempt }
        }
        if var serverConn = status.serverConnection {
            serverConn.stunEndpoints.removeAll()
            if let lastErr = serverConn.lastError {
                serverConn.lastError = truncateUTF8(lastErr, maxBytes: 96)
            }
            status.serverConnection = serverConn
            mutable.status = status
            if let attempt = fitResponse(mutable, encoder: encoder) { return attempt }
        }
        status.warnings.removeAll()
        mutable.status = status
        return fitResponse(mutable, encoder: encoder)
    }

    private static func fitResponse(
        _ response: IosTunnelIpcResponse,
        encoder: JSONEncoder
    ) -> Data? {
        guard let encoded = try? encoder.encode(response),
              encoded.count <= MeshConstants.maxIpcPayloadBytes else {
            return nil
        }
        return encoded
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    private static func truncateUTF8(_ input: String, maxBytes: Int) -> String {
        guard input.utf8.count > maxBytes else { return input }
        var end = input.startIndex
        for idx in input.indices {
            let candidate = String(input[...idx])
            if candidate.utf8.count > maxBytes {
                break
            }
            end = input.index(after: idx)
        }
        return String(input[..<end])
    }

    static func encodeDaemonState(_ state: MobileDaemonState) -> String {
        switch state {
        case .stopped: return "Stopped"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .reauthRequired: return "ReauthRequired"
        case .revoked: return "Revoked"
        case .degraded: return "Degraded"
        case .serverUpgradeRequired: return "ServerUpgradeRequired"
        case .deviceLocked: return "DeviceLocked"
        }
    }

    static func decodeDaemonState(_ raw: String) -> MobileDaemonState {
        switch raw {
        case "Stopped": return .stopped
        case "Connecting": return .connecting
        case "Connected": return .connected
        case "ReauthRequired": return .reauthRequired
        case "Revoked": return .revoked
        case "Degraded": return .degraded
        case "ServerUpgradeRequired": return .serverUpgradeRequired
        case "DeviceLocked": return .deviceLocked
        default: return .stopped
        }
    }

    static func encodeTlsMode(_ mode: MobileTlsAuthMode) -> String {
        switch mode {
        case .spkiPin: return "SpkiPin"
        case .systemCa: return "SystemCa"
        }
    }

    static func decodeTlsMode(_ raw: String) -> MobileTlsAuthMode {
        raw == "SystemCa" ? .systemCa : .spkiPin
    }

    static func encodeActivePath(_ kind: MobileActivePathKind) -> String {
        switch kind {
        case .direct: return "Direct"
        case .relay: return "Relay"
        case .none: return "None"
        }
    }

    static func decodeActivePath(_ raw: String) -> MobileActivePathKind {
        switch raw {
        case "Direct": return .direct
        case "Relay": return .relay
        default: return .none
        }
    }

    static func encodeNatKind(_ nat: MobileNatKind) -> String {
        switch nat {
        case .unknown: return "Unknown"
        case .endpointIndependent: return "EndpointIndependent"
        case .addressDependent: return "AddressDependent"
        case .addressAndPortDependent: return "AddressAndPortDependent"
        }
    }

    static func decodeNatKind(_ raw: String) -> MobileNatKind {
        switch raw {
        case "EndpointIndependent": return .endpointIndependent
        case "AddressDependent": return .addressDependent
        case "AddressAndPortDependent": return .addressAndPortDependent
        default: return .unknown
        }
    }

    static func encodePingVia(_ via: MobilePingVia) -> String {
        switch via {
        case .direct: return "Direct"
        case .relay: return "Relay"
        case .timeout: return "Timeout"
        }
    }

    static func decodePingVia(_ raw: String) -> MobilePingVia {
        switch raw {
        case "Direct": return .direct
        case "Relay": return .relay
        default: return .timeout
        }
    }

    static func encodeWarningKind(_ kind: MobileWarningKind) -> String {
        switch kind {
        case .overlaySubnetConflict: return "OverlaySubnetConflict"
        case .androidLockdownActive: return "AndroidLockdownActive"
        case .androidPrivateDnsStrict: return "AndroidPrivateDnsStrict"
        case .iosLowMemoryPressure: return "IosLowMemoryPressure"
        case .protocolServerUpgradeNeeded: return "ProtocolServerUpgradeNeeded"
        case .deviceKeystoreLocked: return "DeviceKeystoreLocked"
        }
    }

    static func decodeWarningKind(_ raw: String) -> MobileWarningKind {
        switch raw {
        case "OverlaySubnetConflict": return .overlaySubnetConflict
        case "AndroidLockdownActive": return .androidLockdownActive
        case "AndroidPrivateDnsStrict": return .androidPrivateDnsStrict
        case "IosLowMemoryPressure": return .iosLowMemoryPressure
        case "ProtocolServerUpgradeNeeded": return .protocolServerUpgradeNeeded
        case "DeviceKeystoreLocked": return .deviceKeystoreLocked
        default: return .overlaySubnetConflict
        }
    }
}
