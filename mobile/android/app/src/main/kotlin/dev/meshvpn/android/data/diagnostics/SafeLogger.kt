package dev.meshvpn.android.data.diagnostics

import android.util.Log
import dev.meshvpn.android.BuildConfig

/**
 * Redacting logger wrapper. All production log calls must flow through [SafeLogger]
 * so secrets (`mpk_*`, private keys, raw onboarding URIs, bearer tokens) never reach logcat.
 */
object SafeLogger {
    private const val TAG_PREFIX = "MeshVPN/"
    private const val REDACTED_TOKEN = "[REDACTED_TOKEN]"
    private const val REDACTED_KEY = "[REDACTED_KEY]"
    private const val REDACTED_URI = "mesh://join?[REDACTED]"
    private const val REDACTED_BEARER = "Bearer [REDACTED]"

    private val preauthRegex = Regex("""mpk_[A-Za-z0-9_-]{8,}""")
    private val joinUriRegex = Regex("""mesh://join\?[^\s"']+""", RegexOption.IGNORE_CASE)
    private val privKeyFieldRegex = Regex(
        """(?i)(node_privkey_hex|disco_privkey_hex|preauth_key|privkey|secret_key)""" +
            """\s*[:=]\s*[^\s,;}"']+""",
    )
    private val bearerRegex = Regex("""(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}""")
    private val hexSecretParamRegex = Regex(
        """(?i)(secret|token|key)\s*[:=]\s*[0-9a-f]{32,}""",
    )

    fun redact(raw: String): String {
        var sanitized = raw
        sanitized = joinUriRegex.replace(sanitized, REDACTED_URI)
        sanitized = preauthRegex.replace(sanitized, REDACTED_TOKEN)
        sanitized = privKeyFieldRegex.replace(sanitized) { match ->
            val fieldName = match.groupValues.getOrNull(1) ?: "secret"
            "$fieldName=$REDACTED_KEY"
        }
        sanitized = bearerRegex.replace(sanitized, REDACTED_BEARER)
        sanitized = hexSecretParamRegex.replace(sanitized) { match ->
            val fieldName = match.groupValues.getOrNull(1) ?: "secret"
            "$fieldName=$REDACTED_KEY"
        }
        return sanitized
    }

    fun d(tag: String, message: String) {
        if (!BuildConfig.DEBUG) {
            return
        }
        emitDebug(TAG_PREFIX + tag, redact(message))
    }

    fun i(tag: String, message: String) {
        emitInfo(TAG_PREFIX + tag, redact(message))
    }

    fun w(tag: String, message: String, error: Throwable? = null) {
        val cleanMsg = redact(message)
        val detail = error?.let { "${it::class.java.simpleName}: ${redact(it.message.orEmpty())}" }
        val combined = if (detail != null) "$cleanMsg ($detail)" else cleanMsg
        emitWarn(TAG_PREFIX + tag, combined)
    }

    fun e(tag: String, message: String, error: Throwable? = null) {
        val cleanMsg = redact(message)
        val detail = error?.let { "${it::class.java.simpleName}: ${redact(it.message.orEmpty())}" }
        val combined = if (detail != null) "$cleanMsg ($detail)" else cleanMsg
        emitError(TAG_PREFIX + tag, combined)
    }

    @Suppress("ForbiddenMethodCall")
    private fun emitDebug(tag: String, message: String) {
        try {
            Log.d(tag, message)
        } catch (_: RuntimeException) {
            // Safe no-op when invoked under unmocked JVM unit tests.
        }
    }

    @Suppress("ForbiddenMethodCall")
    private fun emitInfo(tag: String, message: String) {
        try {
            Log.i(tag, message)
        } catch (_: RuntimeException) {
            // Safe no-op when invoked under unmocked JVM unit tests.
        }
    }

    @Suppress("ForbiddenMethodCall")
    private fun emitWarn(tag: String, message: String) {
        try {
            Log.w(tag, message)
        } catch (_: RuntimeException) {
            // Safe no-op when invoked under unmocked JVM unit tests.
        }
    }

    @Suppress("ForbiddenMethodCall")
    private fun emitError(tag: String, message: String) {
        try {
            Log.e(tag, message)
        } catch (_: RuntimeException) {
            // Safe no-op when invoked under unmocked JVM unit tests.
        }
    }
}
