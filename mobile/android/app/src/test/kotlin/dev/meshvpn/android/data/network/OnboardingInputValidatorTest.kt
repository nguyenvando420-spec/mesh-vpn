package dev.meshvpn.android.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

class OnboardingInputValidatorTest {
    private val validPin = "sha256:" + "a".repeat(64)
    private val validPreauthKey = "mpk_" + "A".repeat(44)

    @Test
    fun onboardingValidatorValidSpkiPinIpEndpointSucceeds() {
        // Arrange
        val keyChars = validPreauthKey.toCharArray()

        // Act
        val result =
            OnboardingInputValidator.validateManualFields(
                rawEndpoint = " 203.0.113.10:443 ",
                tlsAuthMode = MobileTlsAuthMode.SPKI_PIN,
                rawPin = validPin.uppercase(),
                rawPreauthKey = keyChars,
                rawNodeName = "Pixel-8",
                requirePreauthKey = true,
            )

        // Assert
        assertTrue(result.isValid)
        assertEquals("203.0.113.10:443", result.canonicalEndpoint)
        assertEquals(validPin, result.canonicalPin)
        assertEquals("pixel-8", result.canonicalNodeName)
        assertNull(result.endpointError)
        assertNull(result.pinError)
        assertNull(result.preauthKeyError)
        assertNull(result.nodeNameError)
    }

    @Test
    fun onboardingValidatorSystemCaRejectsIpLiteral() {
        // Arrange
        val keyChars = validPreauthKey.toCharArray()

        // Act
        val result =
            OnboardingInputValidator.validateManualFields(
                rawEndpoint = "203.0.113.10:443",
                tlsAuthMode = MobileTlsAuthMode.SYSTEM_CA,
                rawPin = "",
                rawPreauthKey = keyChars,
                rawNodeName = "android-phone",
                requirePreauthKey = true,
            )

        // Assert
        assertFalse(result.isValid)
        assertNotNull(result.pinError)
    }

    @Test
    fun onboardingValidatorSpkiModeMissingPinBlocksTofu() {
        // Arrange
        val keyChars = validPreauthKey.toCharArray()

        // Act
        val result =
            OnboardingInputValidator.validateManualFields(
                rawEndpoint = "vpn.example.com:443",
                tlsAuthMode = MobileTlsAuthMode.SPKI_PIN,
                rawPin = "",
                rawPreauthKey = keyChars,
                rawNodeName = "",
                requirePreauthKey = true,
            )

        // Assert
        assertFalse(result.isValid)
        assertNotNull(result.pinError)
    }

    @Test
    fun onboardingValidatorRejectsReservedNodeNameAndShortKey() {
        // Arrange
        val shortKey = "mpk_short".toCharArray()

        // Act
        val result =
            OnboardingInputValidator.validateManualFields(
                rawEndpoint = "[2001:db8::1]:443",
                tlsAuthMode = MobileTlsAuthMode.SPKI_PIN,
                rawPin = validPin,
                rawPreauthKey = shortKey,
                rawNodeName = "localhost",
                requirePreauthKey = true,
            )

        // Assert
        assertFalse(result.isValid)
        assertEquals("[2001:db8::1]:443", result.canonicalEndpoint)
        assertNotNull(result.preauthKeyError)
        assertNotNull(result.nodeNameError)
    }
}
