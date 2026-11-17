import Darwin
import Foundation

/// Validation error matching Rust `ErrorKind::InvalidArgument` semantics (`US-102`).
public enum DesktopValidationError: Error, Equatable, Sendable, LocalizedError {
    case invalidArgument(String)

    public var errorDescription: String? {
        switch self {
        case .invalidArgument(let message):
            return message
        }
    }
}

/// Canonical `<host>:<effective_port>` Control endpoint and host classification (`US-102`).
public struct NormalizedControlEndpoint: Equatable, Sendable {
    public let endpoint: String
    public let host: String
    public let port: UInt16
    public let isIpLiteral: Bool

    public init(endpoint: String, host: String, port: UInt16, isIpLiteral: Bool) {
        self.endpoint = endpoint
        self.host = host
        self.port = port
        self.isIpLiteral = isIpLiteral
    }
}

/// Validated TLS trust policy paired with a normalized Control endpoint.
public struct ValidatedTlsPolicy: Equatable, Sendable {
    public let normalized: NormalizedControlEndpoint
    public let tlsAuthMode: TlsAuthMode
    public let serverPin: String?

    public init(
        normalized: NormalizedControlEndpoint,
        tlsAuthMode: TlsAuthMode,
        serverPin: String?
    ) {
        self.normalized = normalized
        self.tlsAuthMode = tlsAuthMode
        self.serverPin = serverPin
    }
}

/// Control endpoint & TLS normalizer mirroring `mesh-core::mobile_uri` (`IG-DGUI-WA-02`).
public enum EndpointNormalizer: Sendable {
    private static let forbiddenCharacters = CharacterSet(
        charactersIn: "/\\@?#;|&$'\"`()"
    )

    public static func isIpLiteralHost(_ rawHost: String) -> Bool {
        let trimmed = trimAsciiWhitespace(rawHost)
        if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") && trimmed.count >= 2 {
            let start = trimmed.index(after: trimmed.startIndex)
            let end = trimmed.index(before: trimmed.endIndex)
            let inner = String(trimmed[start..<end])
            return parseCanonicalIPv6(inner) != nil
        }
        return parseStrictIPv4(trimmed) != nil || parseCanonicalIPv6(trimmed) != nil
    }

    public static func normalize(
        _ raw: String,
        portOverride: UInt16? = nil
    ) throws -> NormalizedControlEndpoint {
        if let portOverride, portOverride == 0 {
            throw DesktopValidationError.invalidArgument("port override must be in 1...65535")
        }
        if containsAsciiControl(raw) {
            throw DesktopValidationError.invalidArgument(
                "control endpoint contains invalid control characters"
            )
        }
        let trimmed = trimAsciiWhitespace(raw)
        if trimmed.isEmpty {
            throw DesktopValidationError.invalidArgument("control endpoint must not be empty")
        }
        if trimmed.contains("://")
            || containsAsciiWhitespace(trimmed)
            || trimmed.rangeOfCharacter(from: forbiddenCharacters) != nil {
            throw DesktopValidationError.invalidArgument(
                "control endpoint must be <host> or <host>:<port> without scheme or shell chars"
            )
        }

        let parsed = try parseHostAndPort(trimmed)
        let effectivePort = portOverride
            ?? parsed.port
            ?? AgentDefaults.defaultControlTcpPort
        let formatted = parsed.host.contains(":")
            ? "[\(parsed.host)]:\(effectivePort)"
            : "\(parsed.host):\(effectivePort)"

        return NormalizedControlEndpoint(
            endpoint: formatted,
            host: parsed.host,
            port: effectivePort,
            isIpLiteral: parsed.isIpLiteral
        )
    }

    public static func validateDesktopTlsPolicy(
        rawEndpoint: String,
        portOverride: UInt16?,
        tlsAuthMode: TlsAuthMode,
        rawServerPin: String?
    ) throws -> ValidatedTlsPolicy {
        let normalized = try normalize(rawEndpoint, portOverride: portOverride)
        if normalized.isIpLiteral && tlsAuthMode == .systemCa {
            throw DesktopValidationError.invalidArgument(
                "system-ca TLS mode cannot be paired with an IP literal control endpoint (SEC-04)"
            )
        }

        switch tlsAuthMode {
        case .systemCa:
            return ValidatedTlsPolicy(
                normalized: normalized,
                tlsAuthMode: .systemCa,
                serverPin: nil
            )
        case .spkiPin:
            guard let rawPin = rawServerPin else {
                throw DesktopValidationError.invalidArgument(
                    "SPKI pin is required when TLS mode is SPKI Pin (Zero-TOFU)"
                )
            }
            let pin = try normalizeSpkiPin(rawPin, allowUppercase: true)
            return ValidatedTlsPolicy(
                normalized: normalized,
                tlsAuthMode: .spkiPin,
                serverPin: pin
            )
        }
    }

    public static func normalizeSpkiPin(
        _ raw: String,
        allowUppercase: Bool = false
    ) throws -> String {
        let candidate = allowUppercase ? trimAsciiWhitespace(raw) : raw
        let prefix = "sha256:"
        let hasPrefix: Bool
        if allowUppercase {
            hasPrefix = candidate.lowercased().hasPrefix(prefix)
        } else {
            hasPrefix = candidate.hasPrefix(prefix)
        }
        guard hasPrefix else {
            throw DesktopValidationError.invalidArgument(
                "invalid SPKI pin: must begin with `sha256:`"
            )
        }
        let hexPart = String(candidate.dropFirst(prefix.count))
        guard hexPart.utf8.count == 64 else {
            throw DesktopValidationError.invalidArgument(
                "invalid SPKI pin: digest must be 64 hexadecimal characters"
            )
        }
        let validHex = hexPart.utf8.allSatisfy { byte in
            let isDigit = byte >= 48 && byte <= 57
            let isLowerHex = byte >= 97 && byte <= 102
            let isUpperHex = allowUppercase && byte >= 65 && byte <= 70
            return isDigit || isLowerHex || isUpperHex
        }
        guard validHex else {
            throw DesktopValidationError.invalidArgument(
                "invalid SPKI pin: digest contains invalid hex characters"
            )
        }
        return prefix + hexPart.lowercased()
    }

    public static func parseStrictPort(_ portStr: String) throws -> UInt16 {
        guard !portStr.isEmpty else {
            throw DesktopValidationError.invalidArgument("control endpoint port must not be empty")
        }
        if portStr.hasPrefix("0") {
            throw DesktopValidationError.invalidArgument(
                "control endpoint port must be 1...65535 without leading zeros"
            )
        }
        guard portStr.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let portNum = UInt16(portStr),
              portNum >= 1
        else {
            throw DesktopValidationError.invalidArgument(
                "control endpoint port out of range 1...65535"
            )
        }
        return portNum
    }

    public static func validateDnsHostname(_ host: String) throws {
        let utf8Count = host.utf8.count
        guard utf8Count >= 1 && utf8Count <= AgentDefaults.maxDnsHostnameLen else {
            throw DesktopValidationError.invalidArgument(
                "control endpoint hostname must be 1...253 bytes"
            )
        }
        if host.hasPrefix(".") || host.hasSuffix(".") || host.contains("..") {
            throw DesktopValidationError.invalidArgument(
                "control endpoint DNS hostname contains invalid dot placement"
            )
        }
        var lastLabelHasAlpha = false
        for labelSub in host.split(separator: ".", omittingEmptySubsequences: false) {
            let label = String(labelSub)
            if label.isEmpty || label.utf8.count > 63 {
                throw DesktopValidationError.invalidArgument(
                    "control endpoint DNS label must be 1...63 characters"
                )
            }
            if label.hasPrefix("-") || label.hasSuffix("-") {
                throw DesktopValidationError.invalidArgument(
                    "control endpoint DNS label must not start or end with `-`"
                )
            }
            let validChars = label.utf8.allSatisfy { byte in
                isAsciiAlpha(byte) || isAsciiDigit(byte) || byte == 45
            }
            if !validChars {
                throw DesktopValidationError.invalidArgument(
                    "control endpoint DNS hostname contains invalid characters"
                )
            }
            lastLabelHasAlpha = label.utf8.contains { isAsciiAlpha($0) }
        }
        if !lastLabelHasAlpha {
            throw DesktopValidationError.invalidArgument(
                "control endpoint host is neither a valid IP address nor a valid DNS hostname"
            )
        }
    }

    public static func parseStrictIPv4(_ raw: String) -> String? {
        let parts = raw.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        octets.reserveCapacity(4)
        for partSub in parts {
            let part = String(partSub)
            if part.isEmpty || part.utf8.count > 3 {
                return nil
            }
            if part.utf8.count > 1 && part.hasPrefix("0") {
                return nil
            }
            guard part.utf8.allSatisfy({ isAsciiDigit($0) }), let value = UInt8(part) else {
                return nil
            }
            octets.append(value)
        }
        return "\(octets[0]).\(octets[1]).\(octets[2]).\(octets[3])"
    }

    public static func parseCanonicalIPv6(_ raw: String) -> String? {
        guard raw.contains(":"),
              !raw.contains("%"),
              !raw.contains("["),
              !raw.contains("]"),
              !containsAsciiWhitespace(raw),
              !containsAsciiControl(raw)
        else {
            return nil
        }
        var addr = in6_addr()
        let result = raw.withCString { cString in
            inet_pton(AF_INET6, cString, &addr)
        }
        guard result == 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let rendered = buffer.withUnsafeMutableBufferPointer { bufPtr -> String? in
            guard let base = bufPtr.baseAddress else { return nil }
            guard inet_ntop(AF_INET6, &addr, base, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return nil
            }
            return String(cString: base)
        }
        return rendered
    }

    private struct HostPortParts: Sendable {
        let host: String
        let port: UInt16?
        let isIpLiteral: Bool
    }

    private static func parseHostAndPort(_ trimmed: String) throws -> HostPortParts {
        if trimmed.hasPrefix("[") {
            guard let closeIdx = trimmed.firstIndex(of: "]") else {
                throw DesktopValidationError.invalidArgument(
                    "missing closing `]` in IPv6 control endpoint"
                )
            }
            let afterOpen = trimmed.index(after: trimmed.startIndex)
            let inner = String(trimmed[afterOpen..<closeIdx])
            guard let canonicalV6 = parseCanonicalIPv6(inner) else {
                throw DesktopValidationError.invalidArgument(
                    "invalid bracketed IPv6 literal in endpoint"
                )
            }
            let afterClose = trimmed.index(after: closeIdx)
            let rest = String(trimmed[afterClose...])
            if rest.isEmpty {
                return HostPortParts(host: canonicalV6, port: nil, isIpLiteral: true)
            }
            guard rest.hasPrefix(":") else {
                throw DesktopValidationError.invalidArgument(
                    "invalid suffix after bracketed IPv6 endpoint host"
                )
            }
            let port = try parseStrictPort(String(rest.dropFirst()))
            return HostPortParts(host: canonicalV6, port: port, isIpLiteral: true)
        }

        if let canonicalV6 = parseCanonicalIPv6(trimmed) {
            return HostPortParts(host: canonicalV6, port: nil, isIpLiteral: true)
        }

        if let colonIdx = trimmed.lastIndex(of: ":") {
            let hostRaw = String(trimmed[..<colonIdx])
            let portStr = String(trimmed[trimmed.index(after: colonIdx)...])
            if hostRaw.isEmpty || hostRaw.contains(":") {
                throw DesktopValidationError.invalidArgument(
                    "unbracketed IPv6 or extra colon in control endpoint host"
                )
            }
            let parsedPort = try parseStrictPort(portStr)
            if let canonicalV4 = parseStrictIPv4(hostRaw) {
                return HostPortParts(host: canonicalV4, port: parsedPort, isIpLiteral: true)
            }
            try validateDnsHostname(hostRaw)
            return HostPortParts(host: hostRaw.lowercased(), port: parsedPort, isIpLiteral: false)
        }

        if let canonicalV4 = parseStrictIPv4(trimmed) {
            return HostPortParts(host: canonicalV4, port: nil, isIpLiteral: true)
        }
        try validateDnsHostname(trimmed)
        return HostPortParts(host: trimmed.lowercased(), port: nil, isIpLiteral: false)
    }

    static func containsAsciiControl(_ text: String) -> Bool {
        text.utf8.contains { $0 < 0x20 || $0 == 0x7F }
    }

    static func containsAsciiWhitespace(_ text: String) -> Bool {
        text.utf8.contains { byte in
            byte == 0x20 || (byte >= 0x09 && byte <= 0x0D)
        }
    }

    static func trimAsciiWhitespace(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func isAsciiAlpha(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
    }

    private static func isAsciiDigit(_ byte: UInt8) -> Bool {
        byte >= 48 && byte <= 57
    }
}
