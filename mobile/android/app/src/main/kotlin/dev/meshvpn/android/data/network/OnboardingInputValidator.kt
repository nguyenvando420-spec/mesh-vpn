package dev.meshvpn.android.data.network

import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

data class ManualJoinValidationResult(
    val canonicalEndpoint: String? = null,
    val canonicalPin: String? = null,
    val canonicalNodeName: String? = null,
    val endpointError: String? = null,
    val pinError: String? = null,
    val preauthKeyError: String? = null,
    val nodeNameError: String? = null,
) {
    val isValid: Boolean
        get() = endpointError == null &&
            pinError == null &&
            preauthKeyError == null &&
            nodeNameError == null &&
            canonicalEndpoint != null
}

/**
 * Pure JVM client-side validator for onboarding manual fields and server config updates (`US-084`).
 * Mirrors Rust `mesh_core::mobile_uri` rules fail-closed before crossing FFI or opening sockets.
 */
object OnboardingInputValidator {
    private const val PREAUTH_PREFIX = "mpk_"
    private const val MIN_PREAUTH_BODY_LEN = 43
    private const val MAX_PREAUTH_LEN = 256
    private const val MAX_PORT = 65535
    private const val MAX_DNS_LEN = 253
    private const val MAX_NODE_NAME_LEN = 63

    private val spkiPinRegex = Regex("^sha256:[0-9a-f]{64}$")
    private val ipv4Regex = Regex(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
            "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
    )
    private val nodeNameRegex = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    private val reservedNodeNames = setOf("localhost", "broadcasthost", "wpad", "isatap", "local")

    fun validateManualFields(
        rawEndpoint: String,
        tlsAuthMode: MobileTlsAuthMode,
        rawPin: String,
        rawPreauthKey: CharArray,
        rawNodeName: String,
        requirePreauthKey: Boolean = true,
    ): ManualJoinValidationResult {
        val (canonicalEndpoint, hostIsIp, epError) = validateEndpoint(rawEndpoint)
        val (canonicalPin, pinError) = validatePinForMode(tlsAuthMode, rawPin, hostIsIp)
        val keyError = if (requirePreauthKey) validatePreauthKeyChars(rawPreauthKey) else null
        val (canonicalNodeName, nodeError) = validateOptionalNodeName(rawNodeName)

        return ManualJoinValidationResult(
            canonicalEndpoint = canonicalEndpoint,
            canonicalPin = canonicalPin,
            canonicalNodeName = canonicalNodeName,
            endpointError = epError,
            pinError = pinError,
            preauthKeyError = keyError,
            nodeNameError = nodeError,
        )
    }

    fun validateEndpoint(rawEndpoint: String): Triple<String?, Boolean, String?> {
        val trimmed = rawEndpoint.trim()
        val preCheck = precheckEndpointSyntax(trimmed)
        if (preCheck != null) {
            return Triple(null, false, preCheck)
        }
        val split = splitHostAndPort(trimmed)
            ?: return Triple(null, false, "Endpoint must include valid host and :port")
        val (host, portStr, bracketedV6) = split
        val portErr = validatePortString(portStr)
        if (portErr != null) {
            return Triple(null, false, portErr)
        }
        return validateParsedHost(host, portStr.toInt(), bracketedV6)
    }

    fun validatePinForMode(
        mode: MobileTlsAuthMode,
        rawPin: String,
        hostIsIp: Boolean,
    ): Pair<String?, String?> {
        val trimmed = rawPin.trim().lowercase()
        return when (mode) {
            MobileTlsAuthMode.SPKI_PIN -> when {
                trimmed.isEmpty() ->
                    null to "SPKI Pin (sha256:<64 hex>) is required; TOFU is disabled"
                !spkiPinRegex.matches(trimmed) ->
                    null to "Pin must match sha256:<64 lowercase hex characters>"
                else -> trimmed to null
            }
            MobileTlsAuthMode.SYSTEM_CA -> when {
                hostIsIp ->
                    null to "System CA requires a DNS domain; IP endpoints require an SPKI pin"
                trimmed.isNotEmpty() ->
                    null to "Omit SPKI pin when System CA mode is selected"
                else -> null to null
            }
        }
    }

    fun validatePreauthKeyChars(chars: CharArray): String? {
        var start = 0
        var end = chars.size
        while (start < end && chars[start].isWhitespace()) {
            start++
        }
        while (end > start && chars[end - 1].isWhitespace()) {
            end--
        }
        val len = end - start
        val prefixErr = when {
            len == 0 -> "Pre-auth key (mpk_...) is required"
            len > MAX_PREAUTH_LEN -> "Pre-auth key exceeds maximum length ($MAX_PREAUTH_LEN chars)"
            !hasMpkPrefix(chars, start, len) -> "Pre-auth key must begin with mpk_"
            len - PREAUTH_PREFIX.length < MIN_PREAUTH_BODY_LEN ->
                "Pre-auth key must carry at least 256 bits of entropy"
            else -> null
        }
        if (prefixErr != null) {
            return prefixErr
        }
        return validatePreauthBodyChars(chars, start, end)
    }

    fun validateOptionalNodeName(rawNodeName: String): Pair<String?, String?> {
        val trimmed = rawNodeName.trim().lowercase()
        return when {
            trimmed.isEmpty() -> null to null
            trimmed.length > MAX_NODE_NAME_LEN -> null to "Device name must be 1..63 characters"
            !nodeNameRegex.matches(trimmed) ->
                null to "Device name must use lowercase [a-z0-9-] and not start/end with '-'"
            trimmed in reservedNodeNames ->
                null to "Device name '$trimmed' is reserved and cannot be used"
            else -> trimmed to null
        }
    }

    private fun precheckEndpointSyntax(trimmed: String): String? = when {
        trimmed.isEmpty() -> "Control server endpoint is required (host:port)"
        trimmed.contains("://") || trimmed.contains('/') || trimmed.contains('?') ||
            trimmed.contains('#') || trimmed.contains('@') || trimmed.any { it.isWhitespace() } ->
            "Enter host:port without URL scheme, path, or spaces"
        else -> null
    }

    private fun splitHostAndPort(trimmed: String): Triple<String, String, Boolean>? {
        if (trimmed.startsWith("[")) {
            val closeIdx = trimmed.indexOf("]:")
            if (closeIdx <= 1) {
                return null
            }
            return Triple(trimmed.substring(1, closeIdx), trimmed.substring(closeIdx + 2), true)
        }
        val colonIdx = trimmed.lastIndexOf(':')
        if (colonIdx <= 0) {
            return null
        }
        val host = trimmed.substring(0, colonIdx)
        if (host.contains(':')) {
            return null
        }
        return Triple(host, trimmed.substring(colonIdx + 1), false)
    }

    private fun validateParsedHost(
        host: String,
        portNum: Int,
        bracketedV6: Boolean,
    ): Triple<String?, Boolean, String?> {
        if (bracketedV6) {
            val err = if (!isPlausibleIpv6Literal(host)) {
                "Invalid bracketed IPv6 literal address"
            } else {
                null
            }
            return Triple(if (err == null) "[$host]:$portNum" else null, err == null, err)
        }
        if (ipv4Regex.matches(host)) {
            return Triple("$host:$portNum", true, null)
        }
        val dnsErr = validateDnsHostname(host)
        return Triple(if (dnsErr == null) "$host:$portNum" else null, false, dnsErr)
    }

    private fun hasMpkPrefix(chars: CharArray, start: Int, len: Int): Boolean =
        len >= PREAUTH_PREFIX.length &&
            chars[start] == 'm' &&
            chars[start + 1] == 'p' &&
            chars[start + 2] == 'k' &&
            chars[start + 3] == '_'

    private fun validatePreauthBodyChars(chars: CharArray, start: Int, end: Int): String? {
        for (i in start until end) {
            val ch = chars[i]
            if (ch.isISOControl() || ch.isWhitespace()) {
                return "Pre-auth key cannot contain spaces or control characters"
            }
            if (i >= start + PREAUTH_PREFIX.length) {
                val ok = ch in 'A'..'Z' || ch in 'a'..'z' ||
                    ch in '0'..'9' || ch == '-' || ch == '_'
                if (!ok) {
                    return "Pre-auth key contains non-base64url characters"
                }
            }
        }
        return null
    }

    private fun validatePortString(portStr: String): String? {
        val parsed = portStr.toIntOrNull()
        return when {
            portStr.isEmpty() || !portStr.all { it in '0'..'9' } || portStr.startsWith('0') ->
                "Port must be a decimal number between 1 and $MAX_PORT"
            parsed == null || parsed !in 1..MAX_PORT ->
                "Port must be between 1 and $MAX_PORT"
            else -> null
        }
    }

    private fun validateDnsHostname(host: String): String? {
        val boundaryErr = when {
            host.isEmpty() || host.length > MAX_DNS_LEN ->
                "Hostname must be 1..$MAX_DNS_LEN characters"
            host.startsWith('.') || host.endsWith('.') || host.contains("..") ->
                "Hostname contains invalid dot placement"
            else -> null
        }
        if (boundaryErr != null) {
            return boundaryErr
        }
        val labels = host.split('.')
        val labelErr = labels.firstNotNullOfOrNull { validateDnsLabel(it) }
        if (labelErr != null) {
            return labelErr
        }
        val lastHasAlpha = labels.lastOrNull()?.any { it in 'a'..'z' || it in 'A'..'Z' } == true
        return if (!lastHasAlpha) {
            "Endpoint host is neither a valid IP nor a valid DNS hostname"
        } else {
            null
        }
    }

    private fun validateDnsLabel(label: String): String? = when {
        label.isEmpty() || label.length > MAX_NODE_NAME_LEN ->
            "Hostname label must be 1..63 characters"
        label.startsWith('-') || label.endsWith('-') ->
            "Hostname labels cannot start or end with '-'"
        !label.all { (it.isLetterOrDigit() && it.code < 128) || it == '-' } ->
            "Hostname contains unsupported characters"
        else -> null
    }

    private fun isPlausibleIpv6Literal(host: String): Boolean {
        if (host.isEmpty() || !host.contains(':')) {
            return false
        }
        return host.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' }
    }
}
