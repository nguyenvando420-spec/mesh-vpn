package dev.meshvpn.android.data.diagnostics

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafeLoggerTest {
    @Test
    fun safeLoggerRedactJoinUriAndPreauthRemovesSecrets() {
        // Arrange
        val secretToken = "mpk_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF"
        val joinUri = "mesh://join?v=1&server=203.0.113.10:443&pin=sha256:aaa&key=$secretToken"
        val raw = "Onboarding failed for $joinUri with key $secretToken"

        // Act
        val sanitized = SafeLogger.redact(raw)

        // Assert
        assertFalse(sanitized.contains(secretToken))
        assertFalse(sanitized.contains("pin=sha256"))
        assertTrue(sanitized.contains("mesh://join?[REDACTED]"))
        assertTrue(sanitized.contains("[REDACTED_TOKEN]"))
    }

    @Test
    fun safeLoggerRedactPrivateKeysAndBearerRemovesMaterial() {
        // Arrange
        val raw = "node_privkey_hex=0123456789abcdef0123456789abcdef " +
            "Authorization: Bearer topsecretTokenValue1234"

        // Act
        val sanitized = SafeLogger.redact(raw)

        // Assert
        assertFalse(sanitized.contains("0123456789abcdef"))
        assertFalse(sanitized.contains("topsecretTokenValue1234"))
        assertTrue(sanitized.contains("node_privkey_hex=[REDACTED_KEY]"))
        assertTrue(sanitized.contains("Bearer [REDACTED]"))
    }
}
