package dev.meshvpn.android.ui.peers

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.mesh_mobile_ffi.MobileActivePathKind
import uniffi.mesh_mobile_ffi.MobilePeerStatus

class PeersFilteringTest {
    private fun samplePeers(): List<MobilePeerStatus> =
        listOf(
            MobilePeerStatus(
                nodeId = "node-alpha-01",
                name = "alpha-laptop",
                fqdn = "alpha-laptop.mesh.internal",
                overlayIp = "100.64.0.10",
                online = true,
                activePath = MobileActivePathKind.DIRECT,
                directEndpoint = "198.51.100.10:51820",
                rttMs = 12u,
                lastHandshakeAtMs = 1_700_000_000_000u,
                rxBytes = 1024u,
                txBytes = 2048u,
            ),
            MobilePeerStatus(
                nodeId = "node-beta-02",
                name = "beta-phone",
                fqdn = "beta-phone.mesh.internal",
                overlayIp = "100.64.0.11",
                online = true,
                activePath = MobileActivePathKind.RELAY,
                directEndpoint = null,
                rttMs = 45u,
                lastHandshakeAtMs = 1_700_000_000_000u,
                rxBytes = 512u,
                txBytes = 256u,
            ),
            MobilePeerStatus(
                nodeId = "node-gamma-03",
                name = "gamma-server",
                fqdn = "gamma-server.mesh.internal",
                overlayIp = "100.64.0.12",
                online = false,
                activePath = MobileActivePathKind.NONE,
                directEndpoint = null,
                rttMs = null,
                lastHandshakeAtMs = null,
                rxBytes = 0u,
                txBytes = 0u,
            ),
        )

    @Test
    fun countPeersByModeReturnsAccurateCountsForAllStates() {
        // Arrange
        val peers = samplePeers()

        // Act
        val counts = countPeersByMode(peers)

        // Assert
        assertEquals(3, counts.all)
        assertEquals(2, counts.online)
        assertEquals(1, counts.direct)
        assertEquals(1, counts.relay)
    }

    @Test
    fun filterPeersFiltersByAllOnlineDirectAndRelay() {
        // Arrange
        val peers = samplePeers()

        // Act & Assert
        assertEquals(3, filterPeers(peers, "", PeerFilterMode.ALL).size)
        assertEquals(
            listOf("alpha-laptop", "beta-phone"),
            filterPeers(peers, "", PeerFilterMode.ONLINE).map { it.name },
        )
        assertEquals(
            listOf("alpha-laptop"),
            filterPeers(peers, "", PeerFilterMode.DIRECT).map { it.name },
        )
        assertEquals(
            listOf("beta-phone"),
            filterPeers(peers, "", PeerFilterMode.RELAY).map { it.name },
        )
    }

    @Test
    fun filterPeersMatchesNameFqdnOverlayIpAndNodeIdCaseInsensitively() {
        // Arrange
        val peers = samplePeers()

        // Act & Assert
        assertEquals(
            listOf("alpha-laptop"),
            filterPeers(peers, "ALPHA", PeerFilterMode.ALL).map { it.name },
        )
        assertEquals(
            listOf("beta-phone"),
            filterPeers(peers, "beta-phone.MESH", PeerFilterMode.ALL).map { it.name },
        )
        assertEquals(
            listOf("gamma-server"),
            filterPeers(peers, "100.64.0.12", PeerFilterMode.ALL).map { it.name },
        )
        assertEquals(
            listOf("gamma-server"),
            filterPeers(peers, "GAMMA-03", PeerFilterMode.ALL).map { it.name },
        )
        assertEquals(
            emptyList<String>(),
            filterPeers(peers, "gamma", PeerFilterMode.ONLINE).map { it.name },
        )
    }

    @Test
    fun tabletLayoutBreakpoint600dpUsesTwoColumnsAndPortraitOneColumn() {
        // Arrange & Act & Assert
        assertEquals(600, TABLET_LAYOUT_BREAKPOINT_DP)
        assertEquals(1, peersGridColumnCount(360))
        assertEquals(1, peersGridColumnCount(599))
        assertEquals(2, peersGridColumnCount(600))
        assertEquals(2, peersGridColumnCount(840))
    }

    @Test
    fun offlinePeersWithCachedDirectOrRelayPathAreExcludedFromDirectAndRelayFilters() {
        // Arrange: stale cached activePath on offline peers must never inflate Direct/Relay
        val peers =
            samplePeers() +
                listOf(
                    MobilePeerStatus(
                        nodeId = "node-stale-direct-04",
                        name = "stale-direct",
                        fqdn = "stale-direct.mesh.internal",
                        overlayIp = "100.64.0.14",
                        online = false,
                        activePath = MobileActivePathKind.DIRECT,
                        directEndpoint = "198.51.100.14:51820",
                        rttMs = null,
                        lastHandshakeAtMs = null,
                        rxBytes = 0u,
                        txBytes = 0u,
                    ),
                    MobilePeerStatus(
                        nodeId = "node-stale-relay-05",
                        name = "stale-relay",
                        fqdn = "stale-relay.mesh.internal",
                        overlayIp = "100.64.0.15",
                        online = false,
                        activePath = MobileActivePathKind.RELAY,
                        directEndpoint = null,
                        rttMs = null,
                        lastHandshakeAtMs = null,
                        rxBytes = 0u,
                        txBytes = 0u,
                    ),
                )

        // Act
        val counts = countPeersByMode(peers)
        val directNames = filterPeers(peers, "", PeerFilterMode.DIRECT).map { it.name }
        val relayNames = filterPeers(peers, "", PeerFilterMode.RELAY).map { it.name }

        // Assert: offline peers excluded; direct + relay <= online invariant preserved
        assertEquals(5, counts.all)
        assertEquals(2, counts.online)
        assertEquals(1, counts.direct)
        assertEquals(1, counts.relay)
        assertEquals(listOf("alpha-laptop"), directNames)
        assertEquals(listOf("beta-phone"), relayNames)
    }
}
