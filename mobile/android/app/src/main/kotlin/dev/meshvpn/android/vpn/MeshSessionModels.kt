package dev.meshvpn.android.vpn

import dev.meshvpn.android.BuildConfig
import dev.meshvpn.android.data.diagnostics.SafeLogger
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import dev.meshvpn.android.data.storage.StoredBootstrapSummary
import dev.meshvpn.android.ffi.FfiErrorMapper
import dev.meshvpn.android.ffi.PendingJoinSessionHandle
import dev.meshvpn.android.ffi.UiErrorInfo
import dev.meshvpn.android.ffi.UiErrorKind
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileEngineInitConfig
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobilePingResponse
import uniffi.mesh_mobile_ffi.MobilePlatformKind
import uniffi.mesh_mobile_ffi.MobilePlatformWarning
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode
import uniffi.mesh_mobile_ffi.MobileWarningKind

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
        val initialDaemonState =
            if (unlocked) {
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
        val logDirPath =
            if (stateStore.isDeviceUnlocked()) {
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

    fun resolveSnapshotStateError(snapshot: MobileStatusSnapshot): UiErrorInfo? {
        val lastConnErr = snapshot.serverConnection?.lastError
        val classifiedConnErr = FfiErrorMapper.classifyFromMessage(lastConnErr)
        return when (snapshot.daemonState) {
            MobileDaemonState.SERVER_UPGRADE_REQUIRED ->
                UiErrorInfo(
                    kind = UiErrorKind.SERVER_UPGRADE_REQUIRED,
                    code = "E_SERVER_UPGRADE_REQUIRED",
                    title = "Mesh Server Upgrade Required",
                    detail =
                        SafeLogger.redact(
                            lastConnErr ?: "Server rejected Android client",
                        ),
                    actionHint = "Upgrade mesh-server VPS to v0.2.0 or newer.",
                )
            MobileDaemonState.REVOKED ->
                UiErrorInfo(
                    kind = UiErrorKind.NODE_REVOKED,
                    code = "E_NODE_REVOKED",
                    title = "Node Revoked",
                    detail = "This device was revoked by the administrator.",
                    actionHint =
                        "Local session keys were cleared. Enroll again with a new key.",
                    requiresReenroll = true,
                )
            MobileDaemonState.REAUTH_REQUIRED ->
                UiErrorInfo(
                    kind = UiErrorKind.NODE_KEY_EXPIRED,
                    code = "E_KEY_EXPIRED",
                    title = "Node Key Expired",
                    detail = "Device identity key expired.",
                    actionHint =
                        "Local session keys were cleared. Re-enroll with a new pre-auth key.",
                    requiresReenroll = true,
                )
            else -> classifiedConnErr
        }
    }

    fun applySnapshotUpdate(
        current: MeshSessionUiState,
        snapshot: MobileStatusSnapshot,
        stateError: UiErrorInfo?,
        isEnrolled: Boolean,
        isDeviceUnlocked: Boolean,
    ): MeshSessionUiState {
        val lockdown =
            current.isLockdownEnabled ||
                snapshot.warnings.any { it.kind == MobileWarningKind.ANDROID_LOCKDOWN_ACTIVE }
        val privateDns =
            current.isPrivateDnsStrict ||
                snapshot.warnings.any {
                    it.kind == MobileWarningKind.ANDROID_PRIVATE_DNS_STRICT
                }
        return current.copy(
            isEnrolled = isEnrolled,
            isDeviceUnlocked = isDeviceUnlocked,
            isLockdownEnabled = lockdown,
            isPrivateDnsStrict = privateDns,
            daemonState = snapshot.daemonState,
            snapshot = snapshot,
            activeWarnings = snapshot.warnings,
            lastError =
                stateError ?: current.lastError?.takeIf {
                    snapshot.daemonState != MobileDaemonState.CONNECTED
                },
        )
    }

    fun applyWarningUpdate(
        current: MeshSessionUiState,
        warning: MobilePlatformWarning,
    ): MeshSessionUiState {
        val updated = current.activeWarnings.filterNot { it.kind == warning.kind } + warning
        return current.copy(
            activeWarnings = updated,
            isLockdownEnabled =
                current.isLockdownEnabled ||
                    warning.kind == MobileWarningKind.ANDROID_LOCKDOWN_ACTIVE,
            isPrivateDnsStrict =
                current.isPrivateDnsStrict ||
                    warning.kind == MobileWarningKind.ANDROID_PRIVATE_DNS_STRICT,
        )
    }

    fun applyFfiFailureUpdate(
        current: MeshSessionUiState,
        mapped: UiErrorInfo,
        isEnrolled: Boolean,
    ): MeshSessionUiState {
        val nextState =
            when (mapped.kind) {
                UiErrorKind.SERVER_UPGRADE_REQUIRED -> MobileDaemonState.SERVER_UPGRADE_REQUIRED
                UiErrorKind.NODE_REVOKED -> MobileDaemonState.REVOKED
                UiErrorKind.NODE_KEY_EXPIRED -> MobileDaemonState.REAUTH_REQUIRED
                UiErrorKind.DEVICE_LOCKED -> MobileDaemonState.DEVICE_LOCKED
                else -> current.daemonState
            }
        return current.copy(
            isEnrolled = isEnrolled,
            daemonState = nextState,
            lastError = mapped,
        )
    }
}
