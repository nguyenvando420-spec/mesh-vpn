package dev.meshvpn.android.ui

import dev.meshvpn.android.ffi.MobileEngineHandle
import dev.meshvpn.android.ffi.PendingJoinSessionHandle
import dev.meshvpn.android.ffi.UpParams
import uniffi.mesh_mobile_ffi.MobileBugreportResult
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileNatKind
import uniffi.mesh_mobile_ffi.MobileNetEventKind
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobilePendingJoinSession
import uniffi.mesh_mobile_ffi.MobilePingRequest
import uniffi.mesh_mobile_ffi.MobilePingResponse
import uniffi.mesh_mobile_ffi.MobileSelfNetworkStatus
import uniffi.mesh_mobile_ffi.MobileServerStatus
import uniffi.mesh_mobile_ffi.MobileSetConfig
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode
import uniffi.mesh_mobile_ffi.MobileUnderlayState

internal class FakePendingSession(
    private val preview: String,
) : PendingJoinSessionHandle {
    var cancelled = false
    override fun maskedPreview() = preview
    override fun cancel() {
        cancelled = true
    }

    override fun unwrapNative(): MobilePendingJoinSession? = null
}

internal class FakeMobileEngineHandle(
    private val pin: String,
) : MobileEngineHandle {
    override suspend fun startTunnel(cfg: UpParams) =
        sampleSnapshot(MobileDaemonState.CONNECTED, cfg.serverEndpoint, pin)

    override suspend fun stopTunnel() =
        sampleSnapshot(MobileDaemonState.STOPPED, "203.0.113.10:443", pin)

    override suspend fun rotateKey(pendingJoin: PendingJoinSessionHandle) =
        sampleSnapshot(MobileDaemonState.CONNECTED, "203.0.113.10:443", pin)

    override suspend fun updateServerConfig(cfg: MobileSetConfig) =
        sampleSnapshot(MobileDaemonState.CONNECTED, cfg.serverEndpoint, pin)

    override suspend fun statusSnapshot() =
        sampleSnapshot(MobileDaemonState.CONNECTED, "203.0.113.10:443", pin)

    override suspend fun pingPeer(req: MobilePingRequest) =
        MobilePingResponse("p1", "peer1", "100.64.0.5", emptyList(), 12.0)

    override suspend fun netcheck() =
        MobileNetcheckResponse(true, true, false, MobileNatKind.UNKNOWN, null, true, 20u, null)

    override suspend fun exportBugreportToFile(destPath: String) =
        MobileBugreportResult(destPath, 512u, 2u)

    override fun pushTunPackets(packets: List<ByteArray>) = packets.size.toUInt()

    override fun completeRouteChange(
        opId: ULong,
        ok: Boolean,
        newAndroidTunFd: Int?,
        errorMessage: String?,
    ) = Unit

    override fun onNetworkChange(kind: MobileNetEventKind, underlay: MobileUnderlayState) = Unit
    override fun setPowerSavingMode(enabled: Boolean) = Unit
    override fun shutdown() = Unit
    override fun destroy() = Unit
}

internal fun sampleSnapshot(
    state: MobileDaemonState,
    endpoint: String,
    pin: String,
) = MobileStatusSnapshot(
    daemonState = state,
    nodeId = "node-123",
    nodeName = "pixel-test",
    fqdn = "pixel-test.mesh.local",
    overlayIp = "100.64.0.4",
    overlayCidr = "100.64.0.0/10",
    overlayDnsIp = "100.64.0.2",
    tunInterfaceName = "tun0",
    tunMtu = 1280u,
    netmapVersion = 1u,
    keyExpiresAtMs = null,
    serverConnection = MobileServerStatus(
        controlEndpoint = endpoint,
        relayEndpoint = endpoint,
        stunEndpoints = emptyList(),
        tlsAuthMode = MobileTlsAuthMode.SPKI_PIN,
        activePin = pin,
        nextPin = null,
        controlConnected = state == MobileDaemonState.CONNECTED,
        relayConnected = state == MobileDaemonState.CONNECTED,
        relayRttMs = 25u,
        lastError = null,
    ),
    selfNetwork = MobileSelfNetworkStatus(
        localUdpPort = 51820u,
        boundPhysicalInterface = "wlan0",
        natType = MobileNatKind.UNKNOWN,
        overlayConflictWarning = null,
        nat64ActivePrefix = null,
        candidates = emptyList(),
    ),
    peers = emptyList(),
    warnings = emptyList(),
)
