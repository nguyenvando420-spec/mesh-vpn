package dev.meshvpn.android.ui

import dev.meshvpn.android.data.diagnostics.BugreportShareManager
import dev.meshvpn.android.data.diagnostics.BugreportShareOps
import dev.meshvpn.android.data.keystore.AndroidKeystoreDekManager
import dev.meshvpn.android.data.keystore.KeyWrapBackend
import dev.meshvpn.android.data.storage.DeviceUnlockChecker
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import dev.meshvpn.android.ffi.EnrollParams
import dev.meshvpn.android.ffi.MeshFfiGateway
import dev.meshvpn.android.ffi.MobileEngineHandle
import dev.meshvpn.android.ffi.ParsedJoinSummary
import dev.meshvpn.android.ffi.PendingJoinSessionHandle
import dev.meshvpn.android.vpn.MeshSessionRepository
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.plus
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileEngineInitConfig
import uniffi.mesh_mobile_ffi.MobileJoinUriData
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode
import uniffi.mesh_mobile_ffi.MobileUnderlayState
import uniffi.mesh_mobile_ffi.PlatformNetworkBridge

internal class TestKeyWrapBackend : KeyWrapBackend {
    val keys = mutableSetOf<String>()

    override fun hasWrappingKey(alias: String) = alias in keys

    override fun createWrappingKey(alias: String) {
        keys.add(alias)
    }

    override fun wrapDek(
        alias: String,
        plainDek: ByteArray,
    ) = plainDek.copyOf()

    override fun unwrapDek(
        alias: String,
        wrappedBlob: ByteArray,
    ) = wrappedBlob.copyOf()

    override fun deleteWrappingKey(alias: String) {
        keys.remove(alias)
    }
}

internal class MeshTestHarness(
    stateDir: File,
    testScope: TestScope,
    @OptIn(ExperimentalCoroutinesApi::class)
    dispatcher: CoroutineDispatcher = UnconfinedTestDispatcher(testScope.testScheduler),
) {
    var clipboardText: String? = null
    var clipboardClearedCount = 0
    var authResult: BiometricGateResult = BiometricGateResult.Authenticated
    var enrollCallCount = 0
    var lastPendingSession: FakePendingSession? = null
    var lastCapturedBridge: PlatformNetworkBridge? = null
    val pin = "sha256:" + "b".repeat(64)

    val stateStore =
        PrivateStateFileStore(
            stateDirProvider = { stateDir },
            deviceUnlockChecker = DeviceUnlockChecker { true },
        )
    val keyBackend = TestKeyWrapBackend()
    val dekManager = AndroidKeystoreDekManager(stateStore, keyBackend)
    val bugreportOps =
        object : BugreportShareOps {
            override fun nextExportDestination() = File(stateDir, "bug.tar")

            override fun prepareShareUri(
                archiveFile: File,
                reportedSizeBytes: Long,
            ) = BugreportShareManager.PreparedBugreport(
                shareUri = null,
                shareFile = archiveFile,
                sourceArchiveFile = archiveFile,
                sizeBytes = reportedSizeBytes,
            )

            override fun cleanupAllDiagnosticArtifacts() = Unit
        }

    val gateway =
        object : MeshFfiGateway {
            override fun ffiVersion() = "0.2.0-test"

            override fun parseJoinUri(rawUri: String): ParsedJoinSummary {
                val session = FakePendingSession("mpk_test...6789").also { lastPendingSession = it }
                return ParsedJoinSummary(
                    summary =
                        MobileJoinUriData(
                            version = 1u,
                            serverEndpoint = "203.0.113.10:443",
                            tlsAuthMode = MobileTlsAuthMode.SPKI_PIN,
                            serverPin = pin,
                            preauthKeyMasked = "mpk_test...6789",
                            nodeName = "pixel-test",
                        ),
                    session = session,
                )
            }

            override fun createPendingSessionFromChars(
                rawPreauthKey: CharArray,
            ): PendingJoinSessionHandle =
                FakePendingSession("mpk_char...9999").also { lastPendingSession = it }

            override suspend fun enrollOrRotateNode(
                init: MobileEngineInitConfig,
                bridge: PlatformNetworkBridge,
                params: EnrollParams,
            ): MobileStatusSnapshot {
                enrollCallCount += 1
                lastCapturedBridge = bridge
                val dek = bridge.loadOrCreatePlatformDek()
                dek.fill(0)
                bridge.saveStateFile("identity.sealed.bin", byteArrayOf(7, 8, 9))
                bridge.saveStateFile(
                    "bootstrap.toml",
                    buildString {
                        appendLine("server_endpoint = \"${params.serverEndpoint}\"")
                        appendLine("tls_auth_mode = \"spki_pin\"")
                        appendLine("active_pin = \"$pin\"")
                        appendLine("node_id = \"node-123\"")
                        appendLine("node_name = \"pixel-test\"")
                        appendLine("overlay_ip = \"100.64.0.4\"")
                        appendLine("fqdn = \"pixel-test.mesh.local\"")
                    }.toByteArray(),
                )
                return sampleSnapshot(MobileDaemonState.STOPPED, params.serverEndpoint, pin)
            }

            override fun createEngine(
                init: MobileEngineInitConfig,
                bridge: PlatformNetworkBridge,
            ): MobileEngineHandle {
                lastCapturedBridge = bridge
                return FakeMobileEngineHandle(pin)
            }
        }

    val repo =
        MeshSessionRepository(
            ffiGateway = gateway,
            stateStore = stateStore,
            dekManager = dekManager,
            bugreportManager = bugreportOps,
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
            nativeInitializer = { true },
            defaultNodeNameProvider = { "pixel-test" },
            ioDispatcher = dispatcher,
        )

    val viewModel =
        MeshMainViewModel(
            sessionRepository = repo,
            ffiGateway = gateway,
            clipboardAccess =
                object : ClipboardAccess {
                    override fun readPrimaryTextAndClear(): String? {
                        val out = clipboardText
                        clipboardText = null
                        clipboardClearedCount += 1
                        return out
                    }
                },
            authRequester = { authResult },
            cleanupDiagnostics = {},
            ioDispatcher = dispatcher,
            externalScope = testScope.backgroundScope + dispatcher,
        )
}
