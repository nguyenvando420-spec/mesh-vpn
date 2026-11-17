import Foundation

/// Validated `mesh://join?v=1&...` onboarding URI with secret redaction (`SEC-01`, `US-102`).
public struct ParsedJoinUri:
    Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible
{
    public let version: UInt8
    public let controlEndpoint: String
    public let tlsAuthMode: TlsAuthMode
    public let serverPin: String?
    public let nodeName: String?
    public let isIpEndpoint: Bool
    public let maskedPreauthPreview: String
    private let preauthKeySecret: String

    public init(
        version: UInt8 = 1,
        controlEndpoint: String,
        tlsAuthMode: TlsAuthMode,
        serverPin: String? = nil,
        nodeName: String? = nil,
        isIpEndpoint: Bool = false,
        maskedPreauthPreview: String,
        preauthKeySecret: String
    ) {
        self.version = version
        self.controlEndpoint = controlEndpoint
        self.tlsAuthMode = tlsAuthMode
        self.serverPin = serverPin
        self.nodeName = nodeName
        self.isIpEndpoint = isIpEndpoint
        self.maskedPreauthPreview = maskedPreauthPreview
        self.preauthKeySecret = preauthKeySecret
    }

    public func unsafeRawPreauthKey() -> String {
        preauthKeySecret
    }

    public var redactedUriString: String {
        let pinRaw = serverPin ?? AgentDefaults.systemCaPinSentinel
        var result = "mesh://join?v=\(version)&ep=\(controlEndpoint)"
            + "&pin=\(pinRaw)&key=[REDACTED]"
        if let nodeName {
            result += "&name=\(nodeName)"
        }
        return result
    }

    public var description: String {
        redactedUriString
    }

    public var debugDescription: String {
        redactedUriString
    }
}

/// Low-level strict URI percent-decoding and `BASE64URL_NOPAD` primitives (`mobile_uri.rs`).
internal enum JoinUriCodec {
    private static let base64UrlChars: [UInt8] = Array(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8
    )

    /// Strict `BASE64URL_NOPAD` decoder matching `data_encoding::BASE64URL_NOPAD` in Rust.
    static func decodeBase64UrlNoPad(_ input: String) -> Data? {
        let utf8 = Array(input.utf8)
        let remainder = utf8.count % 4
        if remainder == 1 {
            return nil
        }

        var lookup = [Int8](repeating: -1, count: 256)
        for (idx, charByte) in base64UrlChars.enumerated() {
            lookup[Int(charByte)] = Int8(idx)
        }

        var values = [UInt8]()
        values.reserveCapacity(utf8.count)
        for byte in utf8 {
            let mapped = lookup[Int(byte)]
            if mapped < 0 {
                return nil
            }
            values.append(UInt8(mapped))
        }

        if remainder == 2, let last = values.last, (last & 0x0F) != 0 {
            return nil
        }
        if remainder == 3, let last = values.last, (last & 0x03) != 0 {
            return nil
        }

        var standardBase64 = input
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if remainder == 2 {
            standardBase64 += "=="
        } else if remainder == 3 {
            standardBase64 += "="
        }
        return Data(base64Encoded: standardBase64)
    }

    static func percentDecodeComponent(_ raw: String, label: String) throws -> String {
        let bytes = Array(raw.utf8)
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count)
        var idx = 0
        while idx < bytes.count {
            let current = bytes[idx]
            if current == 37 { // '%'
                guard idx + 2 < bytes.count else {
                    throw DesktopValidationError.invalidArgument(
                        "truncated percent-escape in mobile join URI \(label)"
                    )
                }
                let hi = try hexNibble(bytes[idx + 1], label: label)
                let lo = try hexNibble(bytes[idx + 2], label: label)
                let decoded = (hi << 4) | lo
                if decoded == 0 || decoded < 0x20 || decoded == 0x7F {
                    throw DesktopValidationError.invalidArgument(
                        "disallowed control character in mobile join URI \(label)"
                    )
                }
                out.append(decoded)
                idx += 3
            } else {
                let isCtrl = current < 0x20 || current == 0x7F
                let isSpace = current == 0x20 || (current >= 0x09 && current <= 0x0D)
                if isCtrl || isSpace {
                    throw DesktopValidationError.invalidArgument(
                        "disallowed unescaped whitespace in mobile join URI \(label)"
                    )
                }
                out.append(current)
                idx += 1
            }
        }
        guard let str = String(bytes: out, encoding: .utf8) else {
            throw DesktopValidationError.invalidArgument(
                "invalid UTF-8 sequence in mobile join URI \(label)"
            )
        }
        return str
    }

    private static func hexNibble(_ byte: UInt8, label: String) throws -> UInt8 {
        if byte >= 48 && byte <= 57 { return byte - 48 }
        if byte >= 97 && byte <= 102 { return byte - 97 + 10 }
        if byte >= 65 && byte <= 70 { return byte - 65 + 10 }
        throw DesktopValidationError.invalidArgument(
            "invalid hex escape in mobile join URI \(label)"
        )
    }
}
