package dev.meshvpn.android.vpn

import dev.meshvpn.android.data.keystore.AndroidKeystoreDekManager
import dev.meshvpn.android.data.keystore.KeyWrapBackend
import dev.meshvpn.android.data.storage.DeviceUnlockChecker
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import dev.meshvpn.android.ffi.MobileEngineHandle
import dev.meshvpn.android.ui.FakeMobileEngineHandle
import java.io.File
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.mesh_mobile_ffi.MobileTunnelNetworkConfig
import uniffi.mesh_mobile_ffi.MobileUnderlayState

private data class RouteCompletion(
    val opId: ULong,
    val ok: Boolean,
    val newAndroidTunFd: Int?,
    val errorMessage: String?,
)

private class RecordingEngineHandle(
    private val throwOnComplete: Throwable? = null,
) : MobileEngineHandle by FakeMobileEngineHandle("sha256:" + "a".repeat(64)) {
    val completions = mutableListOf<RouteCompletion>()

    override fun completeRouteChange(
        opId: ULong,
        ok: Boolean,
        newAndroidTunFd: Int?,
        errorMessage: String?,
    ) {
        if (throwOnComplete != null) {
            throw throwOnComplete
        }
        completions.add(RouteCompletion(opId, ok, newAndroidTunFd, errorMessage))
    }
}

private class NoopKeyWrapBackend : KeyWrapBackend {
    override fun hasWrappingKey(alias: String) = false

    override fun createWrappingKey(alias: String) = Unit

    override fun wrapDek(
        alias: String,
        plainDek: ByteArray,
    ) = plainDek.copyOf()

    override fun unwrapDek(
        alias: String,
        wrappedBlob: ByteArray,
    ) = wrappedBlob.copyOf()

    override fun deleteWrappingKey(alias: String) = Unit
}

class AndroidPlatformBridgeTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun createBridge(
        stateDir: File,
        tunEstablisher: TunEstablisher?,
        engineProvider: () -> MobileEngineHandle?,
        testScope: TestScope,
        closedFds: MutableList<Int>,
    ): AndroidPlatformBridge {
        val store =
            PrivateStateFileStore(
                stateDirProvider = { stateDir },
                deviceUnlockChecker = DeviceUnlockChecker { true },
            )
        val dekManager = AndroidKeystoreDekManager(store, NoopKeyWrapBackend())
        return AndroidPlatformBridge(
            socketProtector = { true },
            tunEstablisher = tunEstablisher,
            engineProvider = engineProvider,
            routeScope = testScope,
            underlayProvider = {
                MobileUnderlayState(
                    activeInterfaceName = "wlan0",
                    physicalIfIndex = 1u,
                    hasIpv4 = true,
                    hasIpv6 = false,
                    underlayDnsServers = emptyList(),
                    osNat64Prefix = null,
                    physicalSubnets = listOf("192.168.1.0/24"),
                    isAndroidLockdownEnabled = false,
                    isAndroidPrivateDnsStrict = false,
                    privateDnsServerName = null,
                )
            },
            dekManager = dekManager,
            stateStore = store,
            statusSink = {},
            warningSink = {},
            routeDispatcher = UnconfinedTestDispatcher(testScope.testScheduler),
            fdCloser = { fd -> closedFds.add(fd) },
        )
    }

    private fun sampleRouteConfig() =
        MobileTunnelNetworkConfig(
            overlayIp = "100.64.0.10",
            tunInterfacePrefixLen = 32u,
            overlayCidr = "100.64.0.0/10",
            overlaySubnetMask = "255.192.0.0",
            overlayDnsIp = "100.64.0.2",
            domainSuffix = "mesh.local",
            tunMtu = 1280u,
            includedRoutesCidr = listOf("100.64.0.0/10", "100.64.0.2/32"),
        )

    @Test
    fun onRouteChangedClosesDetachedFdWhenEngineIsNullAfterOnRevoke() =
        runTest {
            // Arrange
            val closedFds = mutableListOf<Int>()
            var activeEngine: MobileEngineHandle? = RecordingEngineHandle()
            val bridge =
                createBridge(
                    stateDir = tempFolder.newFolder("bridge_null_engine"),
                    tunEstablisher =
                        TunEstablisher {
                            activeEngine = null
                            42
                        },
                    engineProvider = { activeEngine },
                    testScope = this,
                    closedFds = closedFds,
                )

            // Act
            bridge.onRouteChanged(7uL, sampleRouteConfig())

            // Assert
            assertEquals(listOf(42), closedFds)
        }

    @Test
    fun onRouteChangedClosesDetachedFdWhenCompleteRouteChangeThrows() =
        runTest {
            // Arrange
            val closedFds = mutableListOf<Int>()
            val failingEngine =
                RecordingEngineHandle(
                    throwOnComplete = IllegalStateException("Engine already destroyed"),
                )
            val bridge =
                createBridge(
                    stateDir = tempFolder.newFolder("bridge_throwing_engine"),
                    tunEstablisher = TunEstablisher { 99 },
                    engineProvider = { failingEngine },
                    testScope = this,
                    closedFds = closedFds,
                )

            // Act
            bridge.onRouteChanged(8uL, sampleRouteConfig())

            // Assert
            assertEquals(listOf(99), closedFds)
        }

    @Test
    fun onRouteChangedHandsOffDetachedFdWithoutClosingWhenCompleteSucceeds() =
        runTest {
            // Arrange
            val closedFds = mutableListOf<Int>()
            val engine = RecordingEngineHandle()
            val bridge =
                createBridge(
                    stateDir = tempFolder.newFolder("bridge_success"),
                    tunEstablisher = TunEstablisher { 55 },
                    engineProvider = { engine },
                    testScope = this,
                    closedFds = closedFds,
                )

            // Act
            bridge.onRouteChanged(9uL, sampleRouteConfig())

            // Assert
            assertTrue(closedFds.isEmpty())
            assertEquals(listOf(RouteCompletion(9uL, true, 55, null)), engine.completions)
        }

    @Test
    fun onRouteChangedReportsFailureWithoutClosingWhenEstablishReturnsNull() =
        runTest {
            // Arrange
            val closedFds = mutableListOf<Int>()
            val engine = RecordingEngineHandle()
            val bridge =
                createBridge(
                    stateDir = tempFolder.newFolder("bridge_null_fd"),
                    tunEstablisher = TunEstablisher { null },
                    engineProvider = { engine },
                    testScope = this,
                    closedFds = closedFds,
                )

            // Act
            bridge.onRouteChanged(10uL, sampleRouteConfig())

            // Assert
            assertTrue(closedFds.isEmpty())
            assertEquals(1, engine.completions.size)
            assertEquals(false, engine.completions.first().ok)
            assertNull(engine.completions.first().newAndroidTunFd)
        }
}
