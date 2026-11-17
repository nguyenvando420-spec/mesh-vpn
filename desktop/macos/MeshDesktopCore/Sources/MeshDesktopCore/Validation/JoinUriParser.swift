import Foundation

/// Strict parser & token validator matching `crates/mesh-core/src/mobile_uri.rs` 100%.
public enum JoinUriParser: Sendable {
    private static let uriPrefix = "mesh://join?"

    private struct RawJoinQueryParams {
        var version: String?
        var endpoint: String?
        var pin: String?
        var key: String?
        var name: String?
    }

    public static func parse(_ raw: String) throws -> ParsedJoinUri {
        guard raw.utf8.count <= AgentDefaults.maxMobileJoinUriLen else {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI exceeds maximum \(AgentDefaults.maxMobileJoinUriLen) bytes"
            )
        }
        let trimmed = EndpointNormalizer.trimAsciiWhitespace(raw)
        if trimmed.isEmpty {
            throw DesktopValidationError.invalidArgument("mobile join URI must not be empty")
        }
        if trimmed.count != raw.count {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI must not contain leading or trailing whitespace"
            )
        }
        if EndpointNormalizer.containsAsciiControl(trimmed)
            || EndpointNormalizer.containsAsciiWhitespace(trimmed) {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI contains invalid whitespace or control characters"
            )
        }
        if trimmed.contains("#") {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI must not contain URL fragments"
            )
        }
        guard trimmed.hasPrefix(uriPrefix) else {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI must begin with `mesh://join?`"
            )
        }
        let query = String(trimmed.dropFirst(uriPrefix.count))
        if query.isEmpty {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI query parameters must not be empty"
            )
        }

        let params = try parseQueryParameters(query)
        return try buildParsedJoinUri(from: params)
    }

    /// Validates `mpk_` + `<= 256` ASCII + `BASE64URL_NOPAD` decoding to `>= 32` bytes (`US-102`).
    public static func validatePreauthKey(_ key: String) throws {
        guard key.utf8.count <= AgentDefaults.maxPreauthKeyLen,
              !EndpointNormalizer.containsAsciiControl(key),
              !EndpointNormalizer.containsAsciiWhitespace(key)
        else {
            throw DesktopValidationError.invalidArgument("invalid pre-auth key syntax")
        }
        guard key.hasPrefix(AgentDefaults.preauthKeyPrefix) else {
            throw DesktopValidationError.invalidArgument(
                "invalid pre-auth key format: missing `mpk_` prefix"
            )
        }
        let body = String(key.dropFirst(AgentDefaults.preauthKeyPrefix.count))
        guard var decoded = JoinUriCodec.decodeBase64UrlNoPad(body) else {
            throw DesktopValidationError.invalidArgument("invalid pre-auth key base64url payload")
        }
        let byteCount = decoded.count
        if byteCount > 0 {
            decoded.resetBytes(in: 0..<byteCount)
        }
        guard byteCount >= 32 else {
            throw DesktopValidationError.invalidArgument(
                "invalid pre-auth key entropy: must be >= 256 bits"
            )
        }
    }

    /// Validates an optional RFC 1123 node label (`1...63`, `[a-z0-9-]`, no reserved hostnames).
    public static func validateNodeName(_ raw: String) throws -> String {
        let trimmed = EndpointNormalizer.trimAsciiWhitespace(raw)
        if trimmed.count != raw.count
            || raw.contains("\n")
            || raw.contains("\r")
            || raw.contains("#")
            || raw.contains(" ")
            || raw.contains("\t")
            || EndpointNormalizer.containsAsciiControl(raw) {
            throw DesktopValidationError.invalidArgument(
                "invalid node name: contains forbidden whitespace or comment characters"
            )
        }
        if raw.isEmpty || raw.utf8.count > 63 {
            throw DesktopValidationError.invalidArgument(
                "invalid node name: length must be 1...63 characters"
            )
        }
        let normalized = raw.lowercased()
        let bytes = Array(normalized.utf8)
        guard let first = bytes.first, let last = bytes.last else {
            throw DesktopValidationError.invalidArgument("invalid node name: empty")
        }
        guard isAsciiLowerAlnum(first) && isAsciiLowerAlnum(last) else {
            throw DesktopValidationError.invalidArgument(
                "invalid node name: must start and end with ASCII letter or digit"
            )
        }
        guard bytes.allSatisfy({ isAsciiLowerAlnum($0) || $0 == 45 }) else {
            throw DesktopValidationError.invalidArgument(
                "invalid node name: allowed characters are [a-z0-9-]"
            )
        }
        if AgentDefaults.reservedHostnames.contains(normalized) {
            throw DesktopValidationError.invalidArgument(
                "invalid node name: reserved hostname `\(normalized)`"
            )
        }
        return normalized
    }

    public static func maskPreauthKey(_ key: String) -> String {
        guard key.hasPrefix(AgentDefaults.preauthKeyPrefix) else {
            return "[REDACTED]"
        }
        let suffix = key.dropFirst(AgentDefaults.preauthKeyPrefix.count)
        guard suffix.count >= 8 else {
            return "mpk_[REDACTED]"
        }
        let head = suffix.prefix(4)
        let tail = suffix.suffix(4)
        return "mpk_\(head)...\(tail)"
    }

    private static func parseQueryParameters(_ query: String) throws -> RawJoinQueryParams {
        var params = RawJoinQueryParams()
        for segmentSub in query.split(separator: "&", omittingEmptySubsequences: false) {
            let segment = String(segmentSub)
            if segment.isEmpty {
                throw DesktopValidationError.invalidArgument(
                    "mobile join URI contains empty query parameter segment"
                )
            }
            guard let eqIdx = segment.firstIndex(of: "=") else {
                throw DesktopValidationError.invalidArgument(
                    "mobile join URI query parameter missing `=`"
                )
            }
            let rawK = String(segment[..<eqIdx])
            let rawV = String(segment[segment.index(after: eqIdx)...])
            let key = try JoinUriCodec.percentDecodeComponent(rawK, label: "query key")
            let val = try JoinUriCodec.percentDecodeComponent(rawV, label: "query value")
            if key.isEmpty || val.isEmpty {
                throw DesktopValidationError.invalidArgument(
                    "mobile join URI query parameter key and value must not be empty"
                )
            }
            try assignQueryParam(key: key, value: val, params: &params)
        }
        return params
    }

    private static func assignQueryParam(
        key: String,
        value: String,
        params: inout RawJoinQueryParams
    ) throws {
        switch key {
        case "v":
            guard params.version == nil else {
                throw DesktopValidationError.invalidArgument("duplicate `v` query parameter")
            }
            params.version = value
        case "ep":
            guard params.endpoint == nil else {
                throw DesktopValidationError.invalidArgument("duplicate `ep` query parameter")
            }
            params.endpoint = value
        case "pin":
            guard params.pin == nil else {
                throw DesktopValidationError.invalidArgument("duplicate `pin` query parameter")
            }
            params.pin = value
        case "key":
            guard params.key == nil else {
                throw DesktopValidationError.invalidArgument("duplicate `key` query parameter")
            }
            params.key = value
        case "name":
            guard params.name == nil else {
                throw DesktopValidationError.invalidArgument("duplicate `name` query parameter")
            }
            params.name = value
        default:
            throw DesktopValidationError.invalidArgument(
                "unsupported query parameter `\(key)` in mobile join URI"
            )
        }
    }

    private static func buildParsedJoinUri(
        from params: RawJoinQueryParams
    ) throws -> ParsedJoinUri {
        guard let versionStr = params.version else {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI missing required `v` parameter"
            )
        }
        guard versionStr == "1" else {
            throw DesktopValidationError.invalidArgument(
                "unsupported mobile join URI version `\(versionStr)` (expected `1`)"
            )
        }
        guard let epRaw = params.endpoint else {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI missing required `ep` parameter"
            )
        }
        let validatedEp = try validateControlEndpointWithExplicitPort(epRaw)

        guard let pinStr = params.pin else {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI missing required `pin` parameter"
            )
        }
        let tlsAuthMode: TlsAuthMode
        let serverPin: String?
        if pinStr == AgentDefaults.systemCaPinSentinel {
            if validatedEp.isIpLiteral {
                throw DesktopValidationError.invalidArgument(
                    "system-ca TLS mode cannot be paired with an IP literal endpoint (SEC-04)"
                )
            }
            tlsAuthMode = .systemCa
            serverPin = nil
        } else {
            serverPin = try EndpointNormalizer.normalizeSpkiPin(pinStr, allowUppercase: false)
            tlsAuthMode = .spkiPin
        }

        guard let key = params.key else {
            throw DesktopValidationError.invalidArgument(
                "mobile join URI missing required `key` parameter"
            )
        }
        try validatePreauthKey(key)

        let nodeName = try params.name.map { try validateNodeName($0) }
        return ParsedJoinUri(
            version: 1,
            controlEndpoint: validatedEp.endpoint,
            tlsAuthMode: tlsAuthMode,
            serverPin: serverPin,
            nodeName: nodeName,
            isIpEndpoint: validatedEp.isIpLiteral,
            maskedPreauthPreview: maskPreauthKey(key),
            preauthKeySecret: key
        )
    }

    private static func validateControlEndpointWithExplicitPort(
        _ raw: String
    ) throws -> NormalizedControlEndpoint {
        if raw.isEmpty
            || raw.contains("/")
            || raw.contains("\\")
            || raw.contains("@")
            || raw.contains("?")
            || raw.contains("#")
            || raw.contains("://")
            || EndpointNormalizer.containsAsciiControl(raw)
            || EndpointNormalizer.containsAsciiWhitespace(raw) {
            throw DesktopValidationError.invalidArgument("invalid `ep` control endpoint syntax")
        }

        if raw.hasPrefix("[") {
            guard let closeIdx = raw.firstIndex(of: "]") else {
                throw DesktopValidationError.invalidArgument(
                    "missing closing `]` in IPv6 `ep` control endpoint"
                )
            }
            let afterOpen = raw.index(after: raw.startIndex)
            let host = String(raw[afterOpen..<closeIdx])
            let rest = String(raw[raw.index(after: closeIdx)...])
            guard rest.hasPrefix(":") else {
                throw DesktopValidationError.invalidArgument(
                    "missing `:port` after bracketed IPv6 `ep` host"
                )
            }
            let port = try EndpointNormalizer.parseStrictPort(String(rest.dropFirst()))
            guard !host.isEmpty, host.utf8.count <= AgentDefaults.maxDnsHostnameLen,
                  let canonicalV6 = EndpointNormalizer.parseCanonicalIPv6(host)
            else {
                throw DesktopValidationError.invalidArgument(
                    "invalid bracketed IPv6 literal in `ep`"
                )
            }
            return NormalizedControlEndpoint(
                endpoint: "[\(canonicalV6)]:\(port)",
                host: canonicalV6,
                port: port,
                isIpLiteral: true
            )
        }

        guard let colonIdx = raw.lastIndex(of: ":") else {
            throw DesktopValidationError.invalidArgument("control endpoint `ep` must have `:port`")
        }
        let host = String(raw[..<colonIdx])
        let portStr = String(raw[raw.index(after: colonIdx)...])
        if host.isEmpty || host.utf8.count > AgentDefaults.maxDnsHostnameLen {
            throw DesktopValidationError.invalidArgument(
                "control endpoint hostname must be 1...253 bytes"
            )
        }
        if host.contains(":") {
            throw DesktopValidationError.invalidArgument(
                "unbracketed IPv6 or extra colon in `ep` host"
            )
        }
        let port = try EndpointNormalizer.parseStrictPort(portStr)
        if let canonicalV4 = EndpointNormalizer.parseStrictIPv4(host) {
            return NormalizedControlEndpoint(
                endpoint: "\(canonicalV4):\(port)",
                host: canonicalV4,
                port: port,
                isIpLiteral: true
            )
        }
        try EndpointNormalizer.validateDnsHostname(host)
        return NormalizedControlEndpoint(
            endpoint: "\(host):\(port)",
            host: host,
            port: port,
            isIpLiteral: false
        )
    }

    private static func isAsciiLowerAlnum(_ byte: UInt8) -> Bool {
        (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57)
    }
}
