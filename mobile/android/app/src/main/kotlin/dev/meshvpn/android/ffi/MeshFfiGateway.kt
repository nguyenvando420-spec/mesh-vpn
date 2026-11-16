package dev.meshvpn.android.ffi

import uniffi.mesh_mobile_ffi.MobileBugreportResult
import uniffi.mesh_mobile_ffi.MobileEngineInitConfig
import uniffi.mesh_mobile_ffi.MobileJoinUriData
import uniffi.mesh_mobile_ffi.MobileNetEventKind
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobilePendingJoinSession
import uniffi.mesh_mobile_ffi.MobilePingRequest
import uniffi.mesh_mobile_ffi.MobilePingResponse
import uniffi.mesh_mobile_ffi.MobileSetConfig
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode
import uniffi.mesh_mobile_ffi.MobileUnderlayState
import uniffi.mesh_mobile_ffi.PlatformNetworkBridge

/**
 * Abstraction over opaque [MobilePendingJoinSession] so ViewModels can be JVM-unit-tested
 * without loading native `.so` code (`HR-MOB-G2-03`).
 */
interface PendingJoinSessionHandle {
    fun maskedPreview(): String

    fun cancel()

    fun unwrapNative(): MobilePendingJoinSession?
}

data class ParsedJoinSummary(
    val summary: MobileJoinUriData,
    val session: PendingJoinSessionHandle,
)

data class EnrollParams(
    val serverEndpoint: String,
    val portOverride: UShort?,
    val tlsAuthMode: MobileTlsAuthMode,
    val serverPin: String?,
    val pendingJoin: PendingJoinSessionHandle,
    val nodeName: String?,
    val rotateExistingIdentity: Boolean,
)

data class UpParams(
    val serverEndpoint: String,
    val portOverride: UShort?,
    val tlsAuthMode: MobileTlsAuthMode,
    val serverPin: String?,
    val pendingJoin: PendingJoinSessionHandle?,
    val nodeName: String?,
    val androidTunFd: Int?,
    val tunInterfaceName: String?,
)

interface MobileEngineHandle {
    suspend fun startTunnel(cfg: UpParams): MobileStatusSnapshot

    suspend fun stopTunnel(): MobileStatusSnapshot

    suspend fun rotateKey(pendingJoin: PendingJoinSessionHandle): MobileStatusSnapshot

    suspend fun updateServerConfig(cfg: MobileSetConfig): MobileStatusSnapshot

    suspend fun statusSnapshot(): MobileStatusSnapshot

    suspend fun pingPeer(req: MobilePingRequest): MobilePingResponse

    suspend fun netcheck(): MobileNetcheckResponse

    suspend fun exportBugreportToFile(destPath: String): MobileBugreportResult

    fun pushTunPackets(packets: List<ByteArray>): UInt

    fun completeRouteChange(
        opId: ULong,
        ok: Boolean,
        newAndroidTunFd: Int?,
        errorMessage: String?,
    )

    fun onNetworkChange(
        kind: MobileNetEventKind,
        underlay: MobileUnderlayState,
    )

    fun setPowerSavingMode(enabled: Boolean)

    fun shutdown()

    fun destroy()
}

interface MeshFfiGateway {
    fun ffiVersion(): String

    fun parseJoinUri(rawUri: String): ParsedJoinSummary

    fun createPendingSessionFromChars(rawPreauthKey: CharArray): PendingJoinSessionHandle

    suspend fun enrollOrRotateNode(
        init: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        params: EnrollParams,
    ): MobileStatusSnapshot

    fun createEngine(
        init: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
    ): MobileEngineHandle
}
