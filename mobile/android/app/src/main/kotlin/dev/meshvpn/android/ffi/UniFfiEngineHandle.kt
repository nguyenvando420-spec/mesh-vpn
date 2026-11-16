package dev.meshvpn.android.ffi

import uniffi.mesh_mobile_ffi.MobileBugreportResult
import uniffi.mesh_mobile_ffi.MobileEngine
import uniffi.mesh_mobile_ffi.MobileNetEventKind
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobilePendingJoinSession
import uniffi.mesh_mobile_ffi.MobilePingRequest
import uniffi.mesh_mobile_ffi.MobilePingResponse
import uniffi.mesh_mobile_ffi.MobileRotateKeyConfig
import uniffi.mesh_mobile_ffi.MobileSetConfig
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileUnderlayState
import uniffi.mesh_mobile_ffi.MobileUpConfig

class UniFfiPendingJoinSessionHandle(
    private val native: MobilePendingJoinSession,
) : PendingJoinSessionHandle {
    override fun maskedPreview(): String = native.maskedPreview()

    override fun cancel() {
        native.cancel()
    }

    override fun unwrapNative(): MobilePendingJoinSession = native
}

class UniFfiMobileEngineHandle(
    private val native: MobileEngine,
) : MobileEngineHandle {
    override suspend fun startTunnel(cfg: UpParams): MobileStatusSnapshot {
        val upConfig = MobileUpConfig(
            serverEndpoint = cfg.serverEndpoint,
            portOverride = cfg.portOverride,
            tlsAuthMode = cfg.tlsAuthMode,
            serverPin = cfg.serverPin,
            pendingJoin = cfg.pendingJoin?.unwrapNative(),
            nodeName = cfg.nodeName,
            androidTunFd = cfg.androidTunFd,
            tunInterfaceName = cfg.tunInterfaceName,
        )
        return native.startTunnel(upConfig)
    }

    override suspend fun stopTunnel(): MobileStatusSnapshot = native.stopTunnel()

    override suspend fun rotateKey(pendingJoin: PendingJoinSessionHandle): MobileStatusSnapshot {
        val nativeSession = requireNotNull(pendingJoin.unwrapNative()) {
            "Pending join session is unavailable for native rotateKey"
        }
        return native.rotateKey(MobileRotateKeyConfig(pendingJoin = nativeSession))
    }

    override suspend fun updateServerConfig(cfg: MobileSetConfig): MobileStatusSnapshot =
        native.updateServerConfig(cfg)

    override suspend fun statusSnapshot(): MobileStatusSnapshot = native.statusSnapshot()

    override suspend fun pingPeer(req: MobilePingRequest): MobilePingResponse = native.pingPeer(req)

    override suspend fun netcheck(): MobileNetcheckResponse = native.netcheck()

    override suspend fun exportBugreportToFile(destPath: String): MobileBugreportResult =
        native.exportBugreportToFile(destPath)

    override fun pushTunPackets(packets: List<ByteArray>): UInt = native.pushTunPackets(packets)

    override fun completeRouteChange(
        opId: ULong,
        ok: Boolean,
        newAndroidTunFd: Int?,
        errorMessage: String?,
    ) {
        native.completeRouteChange(opId, ok, newAndroidTunFd, errorMessage)
    }

    override fun onNetworkChange(kind: MobileNetEventKind, underlay: MobileUnderlayState) {
        native.onNetworkChange(kind, underlay)
    }

    override fun setPowerSavingMode(enabled: Boolean) {
        native.setPowerSavingMode(enabled)
    }

    override fun shutdown() {
        native.shutdown()
    }

    override fun destroy() {
        native.destroy()
    }
}
