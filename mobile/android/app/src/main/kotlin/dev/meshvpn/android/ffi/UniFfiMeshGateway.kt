package dev.meshvpn.android.ffi

import uniffi.mesh_mobile_ffi.MobileEngine
import uniffi.mesh_mobile_ffi.MobileEngineInitConfig
import uniffi.mesh_mobile_ffi.MobileEnrollConfig
import uniffi.mesh_mobile_ffi.MobileParsedJoinUri
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.PlatformNetworkBridge
import uniffi.mesh_mobile_ffi.createPendingJoinSession
import uniffi.mesh_mobile_ffi.mobileEnrollOrRotateNode
import uniffi.mesh_mobile_ffi.mobileFfiVersion
import uniffi.mesh_mobile_ffi.parseMobileJoinUri

class UniFfiMeshGateway : MeshFfiGateway {
    override fun ffiVersion(): String = mobileFfiVersion()

    override fun parseJoinUri(rawUri: String): ParsedJoinSummary {
        val parsed: MobileParsedJoinUri = parseMobileJoinUri(rawUri)
        return ParsedJoinSummary(
            summary = parsed.summary,
            session = UniFfiPendingJoinSessionHandle(parsed.session),
        )
    }

    override fun createPendingSessionFromChars(rawPreauthKey: CharArray): PendingJoinSessionHandle {
        val nativeSession =
            try {
                val transientKey = String(rawPreauthKey)
                createPendingJoinSession(transientKey)
            } finally {
                rawPreauthKey.fill('\u0000')
            }
        return UniFfiPendingJoinSessionHandle(nativeSession)
    }

    override suspend fun enrollOrRotateNode(
        init: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
        params: EnrollParams,
    ): MobileStatusSnapshot {
        val nativeSession =
            requireNotNull(params.pendingJoin.unwrapNative()) {
                "Pending join session is unavailable for native enrollment"
            }
        val enrollConfig =
            MobileEnrollConfig(
                serverEndpoint = params.serverEndpoint,
                portOverride = params.portOverride,
                tlsAuthMode = params.tlsAuthMode,
                serverPin = params.serverPin,
                pendingJoin = nativeSession,
                nodeName = params.nodeName,
                rotateExistingIdentity = params.rotateExistingIdentity,
            )
        return mobileEnrollOrRotateNode(init, bridge, enrollConfig)
    }

    override fun createEngine(
        init: MobileEngineInitConfig,
        bridge: PlatformNetworkBridge,
    ): MobileEngineHandle = UniFfiMobileEngineHandle(MobileEngine(init, bridge))
}
