package dev.meshvpn.android.vpn

import dev.meshvpn.android.data.diagnostics.BugreportShareOps
import dev.meshvpn.android.data.diagnostics.SafeLogger
import dev.meshvpn.android.data.keystore.AndroidKeystoreDekManager
import dev.meshvpn.android.data.network.UnderlayStateClassifier
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import dev.meshvpn.android.ffi.EnrollParams
import dev.meshvpn.android.ffi.FfiErrorMapper
import dev.meshvpn.android.ffi.MeshFfiGateway
import dev.meshvpn.android.ffi.MobileEngineHandle
import dev.meshvpn.android.ffi.UiErrorInfo
import dev.meshvpn.android.ffi.UiErrorKind
import dev.meshvpn.android.ffi.UpParams
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileNetEventKind
import uniffi.mesh_mobile_ffi.MobileNetcheckResponse
import uniffi.mesh_mobile_ffi.MobilePingRequest
import uniffi.mesh_mobile_ffi.MobilePingResponse
import uniffi.mesh_mobile_ffi.MobilePlatformWarning
import uniffi.mesh_mobile_ffi.MobileSetConfig
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode
import uniffi.mesh_mobile_ffi.MobileUnderlayState
import uniffi.mesh_mobile_ffi.MobileWarningKind

/**
 * Process-wide single source of truth coordinating [MobileEngineHandle], RAM-only pending join
 * sessions, Keystore/state cleanup on revocation, Direct Boot transitions, and UI [StateFlow].
 */
class MeshSessionRepository(
    private val ffiGateway: MeshFfiGateway,
    private val stateStore: PrivateStateFileStore,
    private val dekManager: AndroidKeystoreDekManager,
    private val bugreportManager: BugreportShareOps,
    private val underlayProvider: () -> MobileUnderlayState,
    private val nativeInitializer: () -> Boolean,
    private val defaultNodeNameProvider: () -> String,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val engineMutex = Mutex()
    private val pendingJoinLock = Any()

    @Volatile
    private var activeEngine: MobileEngineHandle? = null

    @Volatile
    private var activePendingJoin: PendingEnrollmentRequest? = null

    @Volatile
    private var activePowerSaving: Boolean = false

    private val _uiState = MutableStateFlow(MeshSessionStateHelper.loadInitialUiState(stateStore))
    val uiState: StateFlow<MeshSessionUiState> = _uiState.asStateFlow()

    fun refreshFromDisk() {
        val unlocked = stateStore.isDeviceUnlocked()
        val enrolled = stateStore.hasEnrolledIdentity()
        val bootstrap = if (unlocked) stateStore.readBootstrapSummary() else null
        val alwaysOn = stateStore.getAlwaysOnHint()
        _uiState.update { current ->
            val nextState =
                if (!unlocked) {
                    MobileDaemonState.DEVICE_LOCKED
                } else if (current.daemonState == MobileDaemonState.DEVICE_LOCKED) {
                    MobileDaemonState.STOPPED
                } else {
                    current.daemonState
                }
            current.copy(
                isEnrolled = enrolled,
                isDeviceUnlocked = unlocked,
                isAlwaysOnHintEnabled = alwaysOn,
                bootstrapSummary = bootstrap ?: current.bootstrapSummary,
                daemonState = nextState,
            )
        }
    }

    fun stagePendingEnrollment(request: PendingEnrollmentRequest) {
        synchronized(pendingJoinLock) {
            activePendingJoin?.session?.cancel()
            activePendingJoin = request
        }
    }

    fun cancelStagedPendingEnrollment() {
        synchronized(pendingJoinLock) {
            activePendingJoin?.session?.cancel()
            activePendingJoin = null
        }
    }

    fun hasStagedPendingEnrollment(): Boolean =
        synchronized(pendingJoinLock) {
            activePendingJoin != null
        }

    fun markDeviceLockedWaiting() {
        _uiState.update { current ->
            val lockWarning =
                MobilePlatformWarning(
                    kind = MobileWarningKind.DEVICE_KEYSTORE_LOCKED,
                    message = "Waiting for first device unlock after reboot",
                )
            val merged =
                (
                    current.activeWarnings.filterNot {
                        it.kind == MobileWarningKind.DEVICE_KEYSTORE_LOCKED
                    }
                ) + lockWarning
            current.copy(
                isDeviceUnlocked = false,
                daemonState = MobileDaemonState.DEVICE_LOCKED,
                activeWarnings = merged,
                lastError =
                    UiErrorInfo(
                        kind = UiErrorKind.DEVICE_LOCKED,
                        code = "E_DEVICE_LOCKED",
                        title = "Device Locked (Direct Boot)",
                        detail = "Credential-encrypted Keystore is locked until first unlock.",
                        actionHint = "Unlock the device to start Mesh VPN automatically.",
                    ),
            )
        }
    }

    fun updateUnderlayFlags(underlay: MobileUnderlayState) {
        _uiState.update { current ->
            current.copy(
                isLockdownEnabled = underlay.isAndroidLockdownEnabled,
                isPrivateDnsStrict = underlay.isAndroidPrivateDnsStrict,
                privateDnsServerName = underlay.privateDnsServerName,
            )
        }
        activeEngine?.let { engine ->
            val kind = UnderlayStateClassifier.inferChangeKind(null, underlay)
            engine.onNetworkChange(kind, underlay)
        }
    }

    fun dispatchNetworkChange(
        kind: MobileNetEventKind,
        underlay: MobileUnderlayState,
    ) {
        _uiState.update { current ->
            current.copy(
                isLockdownEnabled = underlay.isAndroidLockdownEnabled,
                isPrivateDnsStrict = underlay.isAndroidPrivateDnsStrict,
                privateDnsServerName = underlay.privateDnsServerName,
            )
        }
        activeEngine?.onNetworkChange(kind, underlay)
    }

    fun setPowerSavingMode(enabled: Boolean) {
        activePowerSaving = enabled
        activeEngine?.setPowerSavingMode(enabled)
    }

    suspend fun enrollOnlyWithoutTunnel(
        pending: PendingEnrollmentRequest,
    ): Result<MobileStatusSnapshot> =
        withContext(ioDispatcher) {
            if (!nativeInitializer()) {
                return@withContext Result.failure(
                    IllegalStateException("Native Mesh FFI library failed to initialize"),
                )
            }
            if (!stateStore.isDeviceUnlocked()) {
                markDeviceLockedWaiting()
                return@withContext Result.failure(IllegalStateException("Device is locked"))
            }

            _uiState.update { it.copy(isBusy = true, lastError = null) }
            try {
                val bridge =
                    createBridge(
                        socketProtector = { false },
                        tunEstablisher = null,
                        routeScope = null,
                    )
                val snapshot =
                    ffiGateway.enrollOrRotateNode(
                        init =
                            MeshSessionStateHelper.buildInitConfig(
                                stateStore,
                                defaultNodeNameProvider,
                            ),
                        bridge = bridge,
                        params =
                            EnrollParams(
                                serverEndpoint = pending.serverEndpoint,
                                portOverride = null,
                                tlsAuthMode = pending.tlsAuthMode,
                                serverPin = pending.serverPin,
                                pendingJoin = pending.session,
                                nodeName = pending.nodeName,
                                rotateExistingIdentity = false,
                            ),
                    )
                applySnapshot(snapshot)
                refreshFromDisk()
                Result.success(snapshot)
            } catch (err: Throwable) {
                handleFfiFailure(err)
                Result.failure(err)
            } finally {
                pending.session.cancel()
                _uiState.update { it.copy(isBusy = false) }
            }
        }

    suspend fun startServiceSession(
        socketProtector: (Int) -> Boolean,
        tunEstablisher: TunEstablisher,
        routeScope: CoroutineScope,
    ): Result<MobileStatusSnapshot> =
        withContext(ioDispatcher) {
            if (!stateStore.isDeviceUnlocked()) {
                markDeviceLockedWaiting()
                return@withContext Result.failure(IllegalStateException("Direct Boot locked"))
            }
            if (!nativeInitializer()) {
                val err = IllegalStateException("Native Mesh FFI library unavailable")
                handleFfiFailure(err)
                return@withContext Result.failure(err)
            }

            val staged =
                synchronized(pendingJoinLock) {
                    val current = activePendingJoin
                    activePendingJoin = null
                    current
                }

            _uiState.update { it.copy(isBusy = true, lastError = null) }
            engineMutex.withLock {
                try {
                    val engine =
                        ensureEngineLocked(
                            socketProtector = socketProtector,
                            tunEstablisher = tunEstablisher,
                            routeScope = routeScope,
                        )
                    engine.setPowerSavingMode(activePowerSaving)

                    val snapshot =
                        if (staged != null) {
                            try {
                                engine.startTunnel(
                                    UpParams(
                                        serverEndpoint = staged.serverEndpoint,
                                        portOverride = null,
                                        tlsAuthMode = staged.tlsAuthMode,
                                        serverPin = staged.serverPin,
                                        pendingJoin = staged.session,
                                        nodeName = staged.nodeName,
                                        androidTunFd = null,
                                        tunInterfaceName = TUN_INTERFACE_HINT,
                                    ),
                                )
                            } finally {
                                staged.session.cancel()
                            }
                        } else {
                            val bootstrap =
                                checkNotNull(stateStore.readBootstrapSummary()) {
                                    "No enrolled Mesh VPN profile found"
                                }
                            engine.startTunnel(
                                UpParams(
                                    serverEndpoint = bootstrap.serverEndpoint,
                                    portOverride = null,
                                    tlsAuthMode = bootstrap.tlsAuthMode,
                                    serverPin = bootstrap.activePin,
                                    pendingJoin = null,
                                    nodeName = bootstrap.nodeName,
                                    androidTunFd = null,
                                    tunInterfaceName = TUN_INTERFACE_HINT,
                                ),
                            )
                        }

                    applySnapshot(snapshot)
                    refreshFromDisk()
                    Result.success(snapshot)
                } catch (err: Throwable) {
                    handleFfiFailure(err)
                    Result.failure(err)
                } finally {
                    staged?.session?.cancel()
                    _uiState.update { it.copy(isBusy = false) }
                }
            }
        }

    suspend fun stopAndShutdownEngine(): Result<Unit> =
        withContext(ioDispatcher) {
            engineMutex.withLock {
                val engine = activeEngine
                activeEngine = null
                if (engine == null) {
                    _uiState.update {
                        it.copy(
                            daemonState = MobileDaemonState.STOPPED,
                            isBusy = false,
                        )
                    }
                    return@withLock Result.success(Unit)
                }
                return@withLock try {
                    val snap = engine.stopTunnel()
                    applySnapshot(snap)
                    engine.shutdown()
                    engine.destroy()
                    Result.success(Unit)
                } catch (err: Throwable) {
                    SafeLogger.w(TAG, "Error stopping tunnel cleanly; forcing shutdown", err)
                    try {
                        engine.shutdown()
                        engine.destroy()
                    } catch (_: Throwable) {
                        // Best-effort cleanup within 5s teardown budget.
                    }
                    _uiState.update {
                        it.copy(
                            daemonState = MobileDaemonState.STOPPED,
                            isBusy = false,
                        )
                    }
                    Result.failure(err)
                }
            }
        }

    suspend fun rotateIdentityKey(rawPreauthKey: CharArray): Result<MobileStatusSnapshot> =
        withContext(ioDispatcher) {
            if (!stateStore.isDeviceUnlocked()) {
                rawPreauthKey.fill('\u0000')
                return@withContext Result.failure(IllegalStateException("Device is locked"))
            }
            val session =
                try {
                    ffiGateway.createPendingSessionFromChars(rawPreauthKey)
                } catch (err: Throwable) {
                    handleFfiFailure(err)
                    return@withContext Result.failure(err)
                }

            _uiState.update { it.copy(isBusy = true, lastError = null) }
            try {
                val runningEngine = activeEngine
                val snapshot =
                    if (runningEngine != null) {
                        runningEngine.rotateKey(session)
                    } else {
                        val bootstrap =
                            checkNotNull(stateStore.readBootstrapSummary()) {
                                "Device must be enrolled before rotating keys"
                            }
                        val bridge =
                            createBridge(
                                socketProtector = { false },
                                tunEstablisher = null,
                                routeScope = null,
                            )
                        ffiGateway.enrollOrRotateNode(
                            init =
                                MeshSessionStateHelper.buildInitConfig(
                                    stateStore,
                                    defaultNodeNameProvider,
                                ),
                            bridge = bridge,
                            params =
                                EnrollParams(
                                    serverEndpoint = bootstrap.serverEndpoint,
                                    portOverride = null,
                                    tlsAuthMode = bootstrap.tlsAuthMode,
                                    serverPin = bootstrap.activePin,
                                    pendingJoin = session,
                                    nodeName = bootstrap.nodeName,
                                    rotateExistingIdentity = true,
                                ),
                        )
                    }
                applySnapshot(snapshot)
                refreshFromDisk()
                Result.success(snapshot)
            } catch (err: Throwable) {
                handleFfiFailure(err)
                Result.failure(err)
            } finally {
                session.cancel()
                _uiState.update { it.copy(isBusy = false) }
            }
        }

    suspend fun updateServerConfig(
        endpoint: String,
        tlsAuthMode: MobileTlsAuthMode,
        pin: String?,
    ): Result<MobileStatusSnapshot> =
        withContext(ioDispatcher) {
            val engine =
                activeEngine
                    ?: return@withContext Result.failure(
                        IllegalStateException("Start VPN tunnel before updating server config"),
                    )
            _uiState.update { it.copy(isBusy = true, lastError = null) }
            try {
                val snapshot =
                    engine.updateServerConfig(
                        MobileSetConfig(
                            serverEndpoint = endpoint,
                            tlsAuthMode = tlsAuthMode,
                            serverPin = pin,
                        ),
                    )
                applySnapshot(snapshot)
                refreshFromDisk()
                Result.success(snapshot)
            } catch (err: Throwable) {
                handleFfiFailure(err)
                Result.failure(err)
            } finally {
                _uiState.update { it.copy(isBusy = false) }
            }
        }

    suspend fun pingPeer(
        target: String,
        count: Int = 4,
        forceDirect: Boolean = false,
        timeoutMs: Long = 2_000L,
    ): Result<MobilePingResponse> =
        withContext(ioDispatcher) {
            val engine =
                activeEngine
                    ?: return@withContext Result.failure(
                        IllegalStateException("Tunnel is not running"),
                    )
            return@withContext try {
                val response =
                    engine.pingPeer(
                        MobilePingRequest(
                            target = target,
                            count = count.coerceIn(1, 64).toUShort(),
                            forceDirect = forceDirect,
                            timeoutMs = timeoutMs.coerceIn(100L, 10_000L).toULong(),
                        ),
                    )
                _uiState.update { it.copy(lastPingResult = response, lastError = null) }
                Result.success(response)
            } catch (err: Throwable) {
                handleFfiFailure(err)
                Result.failure(err)
            }
        }

    suspend fun runNetcheck(): Result<MobileNetcheckResponse> =
        withContext(ioDispatcher) {
            val engine =
                activeEngine
                    ?: return@withContext Result.failure(
                        IllegalStateException("Tunnel is not running"),
                    )
            _uiState.update { it.copy(isBusy = true) }
            return@withContext try {
                val result = engine.netcheck()
                _uiState.update { it.copy(lastNetcheckResult = result, lastError = null) }
                Result.success(result)
            } catch (err: Throwable) {
                handleFfiFailure(err)
                Result.failure(err)
            } finally {
                _uiState.update { it.copy(isBusy = false) }
            }
        }

    suspend fun exportScrubbedBugreport(): Result<BugreportShareManager.PreparedBugreport> =
        withContext(ioDispatcher) {
            val engine =
                activeEngine
                    ?: return@withContext Result.failure(
                        IllegalStateException("Start VPN tunnel to export live bugreport"),
                    )
            _uiState.update { it.copy(isBusy = true) }
            return@withContext try {
                val destFile = bugreportManager.nextExportDestination()
                val res = engine.exportBugreportToFile(destFile.absolutePath)
                val prepared =
                    bugreportManager.prepareShareUri(
                        archiveFile = destFile,
                        reportedSizeBytes = res.sizeBytes.toLong(),
                    )
                Result.success(prepared)
            } catch (err: Throwable) {
                handleFfiFailure(err)
                Result.failure(err)
            } finally {
                _uiState.update { it.copy(isBusy = false) }
            }
        }

    suspend fun resetLocalIdentity(): Result<Unit> =
        withContext(ioDispatcher) {
            cancelStagedPendingEnrollment()
            stopAndShutdownEngine()
            dekManager.resetKeystoreAndDek()
            stateStore.clearAllMeshState()
            bugreportManager.cleanupAllDiagnosticArtifacts()
            _uiState.value = MeshSessionStateHelper.loadInitialUiState(stateStore)
            Result.success(Unit)
        }

    fun setAlwaysOnHint(enabled: Boolean) {
        stateStore.setAlwaysOnHint(enabled)
        _uiState.update { it.copy(isAlwaysOnHintEnabled = enabled) }
    }

    private fun ensureEngineLocked(
        socketProtector: (Int) -> Boolean,
        tunEstablisher: TunEstablisher,
        routeScope: CoroutineScope,
    ): MobileEngineHandle {
        val existing = activeEngine
        if (existing != null) {
            return existing
        }
        val bridge =
            createBridge(
                socketProtector = socketProtector,
                tunEstablisher = tunEstablisher,
                routeScope = routeScope,
            )
        val created =
            ffiGateway.createEngine(
                MeshSessionStateHelper.buildInitConfig(stateStore, defaultNodeNameProvider),
                bridge,
            )
        activeEngine = created
        return created
    }

    private fun createBridge(
        socketProtector: (Int) -> Boolean,
        tunEstablisher: TunEstablisher?,
        routeScope: CoroutineScope?,
    ): AndroidPlatformBridge =
        AndroidPlatformBridge(
            socketProtector = socketProtector,
            tunEstablisher = tunEstablisher,
            engineProvider = { activeEngine },
            routeScope = routeScope,
            underlayProvider = underlayProvider,
            dekManager = dekManager,
            stateStore = stateStore,
            statusSink = ::applySnapshot,
            warningSink = ::applyWarning,
        )

    private fun applySnapshot(snapshot: MobileStatusSnapshot) {
        val stateError = MeshSessionStateHelper.resolveSnapshotStateError(snapshot)
        if (snapshot.daemonState == MobileDaemonState.REVOKED ||
            snapshot.daemonState == MobileDaemonState.REAUTH_REQUIRED
        ) {
            wipeKeysOnTerminalRevocation()
        }

        _uiState.update { current ->
            MeshSessionStateHelper.applySnapshotUpdate(
                current = current,
                snapshot = snapshot,
                stateError = stateError,
                isEnrolled = stateStore.hasEnrolledIdentity(),
                isDeviceUnlocked = stateStore.isDeviceUnlocked(),
            )
        }
    }

    private fun applyWarning(warning: MobilePlatformWarning) {
        _uiState.update { current ->
            MeshSessionStateHelper.applyWarningUpdate(current, warning)
        }
    }

    private fun handleFfiFailure(error: Throwable) {
        val mapped = FfiErrorMapper.mapThrowable(error)
        SafeLogger.w(TAG, "FFI operation failed: ${mapped.code} - ${mapped.detail}")
        if (mapped.kind == UiErrorKind.NODE_REVOKED ||
            mapped.kind == UiErrorKind.NODE_KEY_EXPIRED
        ) {
            wipeKeysOnTerminalRevocation()
        }
        _uiState.update { current ->
            MeshSessionStateHelper.applyFfiFailureUpdate(
                current = current,
                mapped = mapped,
                isEnrolled = stateStore.hasEnrolledIdentity(),
            )
        }
    }

    private fun wipeKeysOnTerminalRevocation() {
        SafeLogger.i(TAG, "Clearing local keys after verified node revocation or expiry")
        dekManager.resetKeystoreAndDek()
        if (stateStore.isDeviceUnlocked()) {
            stateStore.clearAllMeshState()
        }
    }

    companion object {
        private const val TAG = "MeshSessionRepo"
        private const val TUN_INTERFACE_HINT = "tun0"
    }
}
