package dev.meshvpn.android.ffi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.mesh_mobile_ffi.MobileException

class FfiErrorMapperTest {
    @Test
    fun ffiErrorMapperUnauthenticatedPreservesSec05String() {
        // Arrange
        val err =
            MobileException.Unauthenticated(
                errorCode = "E_UNAUTHENTICATED",
                message = "token mismatch for secret realm",
            )

        // Act
        val mapped = FfiErrorMapper.mapThrowable(err)

        // Assert
        assertEquals(UiErrorKind.UNAUTHENTICATED, mapped.kind)
        assertEquals("authentication failed", mapped.detail)
    }

    @Test
    fun ffiErrorMapperCaptivePortalPinClockUpgradeClassified() {
        // Arrange
        val captive =
            MobileException.Unavailable(
                errorCode = "E_UNAVAILABLE",
                message = "Captive portal detected (HTTP 511 Network Authentication Required)",
            )
        val pinMismatch =
            MobileException.PinMismatch(
                errorCode = "E_PIN_MISMATCH",
                message = "SPKI pin mismatch against sha256:abc",
            )
        val clockSkew =
            MobileException.ClockSkew(
                errorCode = "E_CLOCK_SKEW",
                message = "Certificate NotYetValid due to clock skew",
            )
        val upgrade =
            MobileException.ServerUpgradeRequired(
                errorCode = "E_SERVER_UPGRADE_REQUIRED",
                message = "Protocol incompatible",
            )

        // Act + Assert
        assertEquals(UiErrorKind.CAPTIVE_PORTAL, FfiErrorMapper.mapThrowable(captive).kind)
        assertEquals(UiErrorKind.PIN_MISMATCH, FfiErrorMapper.mapThrowable(pinMismatch).kind)
        assertEquals(UiErrorKind.CLOCK_SKEW, FfiErrorMapper.mapThrowable(clockSkew).kind)
        assertEquals(
            UiErrorKind.SERVER_UPGRADE_REQUIRED,
            FfiErrorMapper.mapThrowable(upgrade).kind,
        )
        assertTrue(
            FfiErrorMapper
                .mapThrowable(
                    MobileException.NodeRevoked(errorCode = "E_REVOKED", message = "revoked"),
                ).requiresReenroll,
        )
    }

    @Test
    fun ffiErrorMapperInternalRedactsSecretsAndUsesErrorCode() {
        // Arrange
        val internal =
            MobileException.Internal(
                errorCode = "E_INTERNAL",
                message = "failure with token mpk_SecretPreauthValue123456",
            )

        // Act
        val mapped = FfiErrorMapper.mapThrowable(internal)

        // Assert
        assertEquals(UiErrorKind.INTERNAL, mapped.kind)
        assertEquals("E_INTERNAL", mapped.code)
        assertTrue(mapped.detail.contains("[REDACTED_TOKEN]"))
    }
}
