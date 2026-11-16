package dev.meshvpn.android.ffi

import dev.meshvpn.android.data.diagnostics.SafeLogger
import uniffi.mesh_mobile_ffi.MobileException

enum class UiErrorKind {
    INVALID_ARGUMENT,
    UNAUTHENTICATED,
    PERMISSION_DENIED,
    NODE_REVOKED,
    NODE_KEY_EXPIRED,
    NOT_FOUND,
    CONFLICT,
    RATE_LIMITED,
    CAPTIVE_PORTAL,
    CLOCK_SKEW,
    PIN_MISMATCH,
    SERVER_UPGRADE_REQUIRED,
    KEYSTORE_INVALIDATED,
    DEVICE_LOCKED,
    UNAVAILABLE,
    INTERNAL,
}

data class UiErrorInfo(
    val kind: UiErrorKind,
    val code: String,
    val title: String,
    val detail: String,
    val actionHint: String,
    val requiresReenroll: Boolean = false,
)

/**
 * Classifies UniFFI [MobileException] variants and runtime error strings into actionable UI cards
 * while preserving `SEC-05` (`authentication failed`) and zero-TOFU guarantees.
 */
object FfiErrorMapper {
    private const val AUTH_FAILED_PUBLIC = "authentication failed"

    fun mapThrowable(error: Throwable): UiErrorInfo {
        return when (error) {
            is MobileException -> mapMobileException(error)
            else -> {
                val clean = SafeLogger.redact(error.message ?: "Unexpected failure")
                classifyFromMessage(clean) ?: UiErrorInfo(
                    kind = UiErrorKind.INTERNAL,
                    code = "E_INTERNAL",
                    title = "Unexpected Error",
                    detail = clean,
                    actionHint = "Check status logs or export a scrubbed bugreport.",
                )
            }
        }
    }

    fun mapMobileException(ex: MobileException): UiErrorInfo {
        return mapControlAndAuthException(ex) ?: mapTransportAndDeviceException(ex)
    }

    private fun mapControlAndAuthException(ex: MobileException): UiErrorInfo? = when (ex) {
        is MobileException.InvalidArgument -> simpleInfo(
            UiErrorKind.INVALID_ARGUMENT,
            ex.errorCode,
            "Invalid Input",
            SafeLogger.redact(ex.message),
            "Verify the server endpoint, SPKI pin, and pre-auth key.",
        )
        is MobileException.Unauthenticated -> simpleInfo(
            UiErrorKind.UNAUTHENTICATED,
            ex.errorCode,
            "Authentication Failed",
            AUTH_FAILED_PUBLIC,
            "Request a new pre-auth key from your Mesh administrator.",
        )
        is MobileException.PermissionDenied -> simpleInfo(
            UiErrorKind.PERMISSION_DENIED,
            ex.errorCode,
            "Permission Denied",
            SafeLogger.redact(ex.message),
            "Grant VPN permission when prompted by Android.",
        )
        is MobileException.NodeRevoked -> simpleInfo(
            UiErrorKind.NODE_REVOKED,
            ex.errorCode,
            "Device Access Revoked",
            SafeLogger.redact(ex.message),
            "This node was revoked by the administrator. Re-enroll to rejoin.",
            requiresReenroll = true,
        )
        is MobileException.NodeKeyExpired -> simpleInfo(
            UiErrorKind.NODE_KEY_EXPIRED,
            ex.errorCode,
            "Node Key Expired",
            SafeLogger.redact(ex.message),
            "Node identity key expired. Re-enroll with a new pre-auth key.",
            requiresReenroll = true,
        )
        is MobileException.NotFound -> simpleInfo(
            UiErrorKind.NOT_FOUND,
            ex.errorCode,
            "Resource Not Found",
            SafeLogger.redact(ex.message),
            "Verify the target peer name or node enrollment state.",
        )
        is MobileException.Conflict -> simpleInfo(
            UiErrorKind.CONFLICT,
            ex.errorCode,
            "Registration Conflict",
            SafeLogger.redact(ex.message),
            "Choose a different device name or check overlay pool capacity.",
        )
        is MobileException.RateLimited -> simpleInfo(
            UiErrorKind.RATE_LIMITED,
            ex.errorCode,
            "Rate Limited",
            SafeLogger.redact(ex.message),
            "Wait briefly before retrying the operation.",
        )
        else -> null
    }

    private fun mapTransportAndDeviceException(ex: MobileException): UiErrorInfo = when (ex) {
        is MobileException.ClockSkew -> simpleInfo(
            UiErrorKind.CLOCK_SKEW,
            ex.errorCode,
            "Device Clock Out of Sync",
            SafeLogger.redact(ex.message),
            "Enable Automatic Date & Time in Android settings.",
        )
        is MobileException.PinMismatch -> simpleInfo(
            UiErrorKind.PIN_MISMATCH,
            ex.errorCode,
            "TLS Certificate Pin Mismatch",
            SafeLogger.redact(ex.message),
            "Verify server SPKI pin out-of-band; Mesh VPN enforces Zero-TOFU pinning.",
        )
        is MobileException.ServerUpgradeRequired -> simpleInfo(
            UiErrorKind.SERVER_UPGRADE_REQUIRED,
            ex.errorCode,
            "Mesh Server Upgrade Required",
            SafeLogger.redact(ex.message),
            "Control server is missing v0.2.0 mobile support; upgrade mesh-server.",
        )
        is MobileException.KeystoreInvalidated -> simpleInfo(
            UiErrorKind.KEYSTORE_INVALIDATED,
            ex.errorCode,
            "Android Keystore Invalidated",
            SafeLogger.redact(ex.message),
            "Hardware key material is no longer valid. Reset identity and re-enroll.",
            requiresReenroll = true,
        )
        is MobileException.DeviceLocked -> simpleInfo(
            UiErrorKind.DEVICE_LOCKED,
            ex.errorCode,
            "Waiting for Device Unlock",
            SafeLogger.redact(ex.message),
            "Unlock your phone once after reboot so encrypted keys can load.",
        )
        is MobileException.Unavailable -> mapUnavailable(ex)
        is MobileException.Internal -> internalErrorInfo(ex)
        else -> internalErrorInfo(ex)
    }

    private fun internalErrorInfo(ex: MobileException): UiErrorInfo = simpleInfo(
        UiErrorKind.INTERNAL,
        ex.errorCode,
        "Internal Engine Error",
        SafeLogger.redact(ex.message),
        "Export a scrubbed bugreport for inspection.",
    )

    private fun mapUnavailable(ex: MobileException.Unavailable): UiErrorInfo {
        val redacted = SafeLogger.redact(ex.message)
        return if (looksLikeCaptivePortal(redacted)) {
            simpleInfo(
                UiErrorKind.CAPTIVE_PORTAL,
                ex.errorCode,
                "Captive Portal Detected",
                redacted,
                "Open your browser to sign in to the Wi-Fi portal; VPN retries automatically.",
            )
        } else {
            simpleInfo(
                UiErrorKind.UNAVAILABLE,
                ex.errorCode,
                "Control Server Unavailable",
                redacted,
                "Check internet connectivity; Mesh VPN is retrying with backoff.",
            )
        }
    }

    fun classifyFromMessage(rawMessage: String?): UiErrorInfo? {
        if (rawMessage.isNullOrBlank()) {
            return null
        }
        val clean = SafeLogger.redact(rawMessage)
        val lower = clean.lowercase()
        return when {
            looksLikeCaptivePortal(lower) -> simpleInfo(
                UiErrorKind.CAPTIVE_PORTAL,
                "E_CAPTIVE_PORTAL",
                "Captive Portal Detected",
                clean,
                "Complete Wi-Fi hotspot sign-in in your browser.",
            )
            lower.contains("spki pin mismatch") || lower.contains("pin_mismatch") -> simpleInfo(
                UiErrorKind.PIN_MISMATCH,
                "E_PIN_MISMATCH",
                "TLS Certificate Pin Mismatch",
                clean,
                "Verify server SPKI pin out-of-band. No TOFU bypass exists.",
            )
            lower.contains("clock skew") || lower.contains("not yet valid") ||
                lower.contains("expired") && lower.contains("tls") -> simpleInfo(
                UiErrorKind.CLOCK_SKEW,
                "E_CLOCK_SKEW",
                "Device Clock Out of Sync",
                clean,
                "Sync Android date and time with the network.",
            )
            lower.contains("protocol incompatible") || lower.contains("upgrade required") ->
                simpleInfo(
                    UiErrorKind.SERVER_UPGRADE_REQUIRED,
                    "E_SERVER_UPGRADE_REQUIRED",
                    "Mesh Server Upgrade Required",
                    clean,
                    "Upgrade mesh-server VPS to v0.2.0 or newer.",
                )
            lower.contains("revoked") -> simpleInfo(
                UiErrorKind.NODE_REVOKED,
                "E_NODE_REVOKED",
                "Node Revoked",
                clean,
                "Re-enroll this device using a fresh pre-auth key.",
                requiresReenroll = true,
            )
            else -> null
        }
    }

    private fun simpleInfo(
        kind: UiErrorKind,
        code: String,
        title: String,
        detail: String,
        actionHint: String,
        requiresReenroll: Boolean = false,
    ) = UiErrorInfo(
        kind = kind,
        code = code,
        title = title,
        detail = detail,
        actionHint = actionHint,
        requiresReenroll = requiresReenroll,
    )

    private fun looksLikeCaptivePortal(lowerOrRaw: String): Boolean {
        val lower = lowerOrRaw.lowercase()
        return lower.contains("captive portal") ||
            lower.contains("http 511") ||
            lower.contains("network authentication required")
    }
}
