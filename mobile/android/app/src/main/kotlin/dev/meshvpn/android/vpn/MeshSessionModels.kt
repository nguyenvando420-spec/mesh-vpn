package dev.meshvpn.android.vpn

import dev.meshvpn.android.BuildConfig
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import dev.meshvpn.android.data.storage.StoredBootstrapSummary
import dev.meshvpn.android.ffi.PendingJoinSessionHandle
import dev.meshvpn.android.ffi.UiErrorInfo
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileEngineInitConfig
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobilePingResponse
import uniffi.mesh_mobile_ffi.MobilePlatformKind
import uniffi.mesh_mobile_ffi.MobilePlatformWarning
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

data class PendingEnrollmentRequest(
    val serverEndpoint: String,
    val tlsAuthMode: MobileTlsAuthMode,
    val serverPin: String?,
    val nodeName: String?,
    val preauthKeyMasked: String,
    val session: PendingJoinSessionHandle,
)

data class MeshSessionUiState(
    val isEnrolled: Boolean = false,
    val isDeviceUnlocked: Boolean = true,
    val isLockdownEnabled: Boolean = false,
    val isPrivateDnsStrict: Boolean = false,
    val privateDnsServerName: String? = null,
    val isAlwaysOnHintEnabled: Boolean = false,
    val daemonState: MobileDaemonState = MobileDaemonState.STOPPED,
    val snapshot: MobileStatusSnapshot? = null,
    val bootstrapSummary: StoredBootstrapSummary? = null,
    val activeWarnings: List<MobilePlatformWarning> = emptyList(),
    val lastError: UiErrorInfo? = null,
    val isBusy: Boolean = false,
    val lastPingResult: MobilePingResponse? = null,
    val lastNetcheckResult: MobileNetcheckResponse? = null,
)

internal object MeshSessionStateHelper {
    fun loadInitialUiState(stateStore: PrivateStateFileStore): MeshSessionUiState {
        val unlocked = stateStore.isDeviceUnlocked()
        val enrolled = stateStore.hasEnrolledIdentity()
        val bootstrap = if (unlocked) stateStore.readBootstrapSummary() else null
        val initialDaemonState = if (unlocked) {
            MobileDaemonState.STOPPED
        } else {
            MobileDaemonState.DEVICE_LOCKED
        }
        return MeshSessionUiState(
            isEnrolled = enrolled,
            isDeviceUnlocked = unlocked,
            isAlwaysOnHintEnabled = stateStore.getAlwaysOnHint(),
            daemonState = initialDaemonState,
            bootstrapSummary = bootstrap,
        )
    }

    fun buildInitConfig(
        stateStore: PrivateStateFileStore,
        defaultNodeNameProvider: () -> String,
    ): MobileEngineInitConfig {
        val logDirPath = if (stateStore.isDeviceUnlocked()) {
            stateStore.stateDirectory().absolutePath
        } else {
            ""
        }
        return MobileEngineInitConfig(
            platform = MobilePlatformKind.ANDROID,
            agentVersion = BuildConfig.VERSION_NAME,
            defaultNodeName = defaultNodeNameProvider(),
            logDirPath = logDirPath,
        )
    }
}
