package dev.meshvpn.android.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.mesh_mobile_ffi.MobileTunnelNetworkConfig

class SplitTunnelBuilderValidatorTest {
    @Test
    fun splitTunnelValidatorAcceptsSlash32WithDnsRoute() {
        // Arrange
        val cfg = MobileTunnelNetworkConfig(
            overlayIp = "100.64.0.10",
            tunInterfacePrefixLen = 32u,
            overlayCidr = "100.64.0.0/10",
            overlaySubnetMask = "255.192.0.0",
            overlayDnsIp = "100.64.0.2",
            domainSuffix = "mesh.local",
            tunMtu = 1280u,
            includedRoutesCidr = listOf("100.64.0.0/10", "100.64.0.2/32"),
        )

        // Act
        val validated = SplitTunnelBuilderValidator.validate(cfg)

        // Assert
        assertEquals("100.64.0.10", validated.overlayIp)
        assertEquals(32, validated.tunPrefixLength)
        assertEquals("100.64.0.2", validated.overlayDnsIp)
        assertEquals("mesh.local", validated.domainSuffix)
        assertEquals(1280, validated.mtu)
        assertEquals(2, validated.routes.size)
    }

    @Test
    fun splitTunnelValidatorRejectsDefaultRouteAndNon32Prefix() {
        // Arrange
        val badDefaultRoute = MobileTunnelNetworkConfig(
            overlayIp = "100.64.0.10",
            tunInterfacePrefixLen = 32u,
            overlayCidr = "100.64.0.0/10",
            overlaySubnetMask = "255.192.0.0",
            overlayDnsIp = "100.64.0.2",
            domainSuffix = "mesh.local",
            tunMtu = 1280u,
            includedRoutesCidr = listOf("0.0.0.0/0"),
        )
        val badPrefix = badDefaultRoute.copy(
            tunInterfacePrefixLen = 10u,
            includedRoutesCidr = listOf("100.64.0.0/10"),
        )

        // Act + Assert
        assertThrows(IllegalArgumentException::class.java) {
            SplitTunnelBuilderValidator.validate(badDefaultRoute)
        }
        assertThrows(IllegalArgumentException::class.java) {
            SplitTunnelBuilderValidator.validate(badPrefix)
        }
    }

    @Test
    fun splitTunnelValidatorRejectsRouteMissingDnsCoverage() {
        // Arrange
        val missingDnsRoute = MobileTunnelNetworkConfig(
            overlayIp = "100.64.0.10",
            tunInterfacePrefixLen = 32u,
            overlayCidr = "100.64.0.0/10",
            overlaySubnetMask = "255.192.0.0",
            overlayDnsIp = "100.127.255.253",
            domainSuffix = "mesh.local",
            tunMtu = 1280u,
            includedRoutesCidr = listOf("100.64.0.0/16"),
        )

        // Act + Assert
        assertThrows(IllegalArgumentException::class.java) {
            SplitTunnelBuilderValidator.validate(missingDnsRoute)
        }
    }
}
