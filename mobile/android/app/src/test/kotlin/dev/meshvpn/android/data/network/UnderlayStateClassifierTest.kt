package dev.meshvpn.android.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.mesh_mobile_ffi.MobileNetEventKind

class UnderlayStateClassifierTest {
    @Test
    fun underlayClassifierDetectsStrictPrivateDnsAndLockdown() {
        // Arrange
        val raw =
            RawLinkSnapshot(
                activeInterfaceName = " wlan0 ",
                physicalIfIndex = 12u,
                hasIpv4 = false,
                hasIpv6 = true,
                underlayDnsServers = listOf("2001:4860:4860::8888", "2001:4860:4860::8888"),
                osNat64Prefix = "64:ff9b::/96",
                physicalSubnets = listOf("192.168.1.0/24", "invalid"),
                isAndroidLockdownEnabled = true,
                isPrivateDnsActive = true,
                privateDnsServerName = "dns.quad9.net",
            )

        // Act
        val state = UnderlayStateClassifier.toMobileUnderlayState(raw)

        // Assert
        assertEquals("wlan0", state.activeInterfaceName)
        assertEquals(12u, state.physicalIfIndex)
        assertFalse(state.hasIpv4)
        assertTrue(state.hasIpv6)
        assertEquals(listOf("2001:4860:4860::8888"), state.underlayDnsServers)
        assertEquals(listOf("192.168.1.0/24"), state.physicalSubnets)
        assertEquals("64:ff9b::/96", state.osNat64Prefix)
        assertTrue(state.isAndroidLockdownEnabled)
        assertTrue(state.isAndroidPrivateDnsStrict)
        assertEquals("dns.quad9.net", state.privateDnsServerName)
    }

    @Test
    fun underlayClassifierOpportunisticPrivateDnsIsNotStrict() {
        // Arrange
        val raw =
            RawLinkSnapshot(
                activeInterfaceName = "rmnet_data0",
                physicalIfIndex = 4u,
                hasIpv4 = true,
                hasIpv6 = true,
                underlayDnsServers = listOf("8.8.8.8"),
                osNat64Prefix = null,
                physicalSubnets = emptyList(),
                isAndroidLockdownEnabled = false,
                isPrivateDnsActive = true,
                privateDnsServerName = null,
            )

        // Act
        val state = UnderlayStateClassifier.toMobileUnderlayState(raw)

        // Assert
        assertFalse(state.isAndroidPrivateDnsStrict)
    }

    @Test
    fun underlayClassifierInfersRoamingAndConnectivityTransitions() {
        // Arrange
        val wifi =
            UnderlayStateClassifier.toMobileUnderlayState(
                RawLinkSnapshot(
                    activeInterfaceName = "wlan0",
                    physicalIfIndex = 5u,
                    hasIpv4 = true,
                    hasIpv6 = false,
                    underlayDnsServers = listOf("192.168.1.1"),
                    osNat64Prefix = null,
                    physicalSubnets = listOf("192.168.1.0/24"),
                    isAndroidLockdownEnabled = false,
                    isPrivateDnsActive = false,
                    privateDnsServerName = null,
                ),
            )
        val cellular = wifi.copy(activeInterfaceName = "rmnet0", physicalIfIndex = 9u)
        val offline = UnderlayStateClassifier.emptyOfflineState(isLockdownEnabled = false)

        // Act + Assert
        assertEquals(
            MobileNetEventKind.CONNECTIVITY_RESTORED,
            UnderlayStateClassifier.inferChangeKind(null, wifi),
        )
        assertEquals(
            MobileNetEventKind.INTERFACE_CHANGED,
            UnderlayStateClassifier.inferChangeKind(wifi, cellular),
        )
        assertEquals(
            MobileNetEventKind.CONNECTIVITY_LOST,
            UnderlayStateClassifier.inferChangeKind(cellular, offline),
        )
        assertEquals(
            MobileNetEventKind.CONNECTIVITY_RESTORED,
            UnderlayStateClassifier.inferChangeKind(offline, wifi),
        )
    }
}
