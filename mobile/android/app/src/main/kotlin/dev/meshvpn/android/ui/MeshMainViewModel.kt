package dev.meshvpn.android.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.meshvpn.android.data.diagnostics.BugreportShareManager
import dev.meshvpn.android.data.network.OnboardingInputValidator
import dev.meshvpn.android.ffi.FfiErrorMapper
import dev.meshvpn.android.ffi.MeshFfiGateway
import dev.meshvpn.android.ui.peers.PeerFilterMode
import dev.meshvpn.android.ui.theme.InMemoryThemePrefsStore
import dev.meshvpn.android.ui.theme.ThemeMode
import dev.meshvpn.android.ui.theme.ThemePrefsStore
import dev.meshvpn.android.vpn.MeshSessionRepository
import dev.meshvpn.android.vpn.MeshSessionUiState
import dev.meshvpn.android.vpn.PendingEnrollmentRequest
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

enum class AdminAuthPurpose {
    REVEAL_SPKI_PIN,
    UPDATE_SERVER_CONFIG,
    ROTATE_KEY,
    EXPORT_BUGREPORT,
    RESET_IDENTITY,
}

enum class MainTab {
    STATUS,
    PEERS,
    SETTINGS,
}

enum class OnboardingMethod {
    SCAN_QR,
    PASTE_URI,
    MANUAL,
}

data class JoinConfirmationUiModel(
    val serverEndpoint: String,
    val tlsAuthMode: MobileTlsAuthMode,
    val serverPin: String?,
    val preauthKeyMasked: String,
    val nodeName: String?,
)

data class MainUiScreenState(
    val session: MeshSessionUiState = MeshSessionUiState(),
    val activeTab: MainTab = MainTab.STATUS,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val peerSearchQuery: String = "",
    val peerFilterMode: PeerFilterMode = PeerFilterMode.ALL,
    val onboardingMethod: OnboardingMethod = OnboardingMethod.SCAN_QR,
    val pendingConfirmation: JoinConfirmationUiModel? = null,
    val connectOnConfirm: Boolean = true,
    val isAdminPinsRevealed: Boolean = false,
    val isSensitiveModalOpen: Boolean = false,
    val infoBanner: String? = null,
    val inputError: String? = null,
    val pendingShareBugreport: BugreportShareManager.PreparedBugreport? = null,
) {
    val requireFlagSecure: Boolean
        get() =
            !session.isEnrolled ||
                pendingConfirmation != null ||
                (
                    activeTab == MainTab.SETTINGS &&
                        (isAdminPinsRevealed || isSensitiveModalOpen)
                )
}

/**
 * Coordinates Compose screens with [MeshSessionRepository], clipboard scrubbing,
 * `CharArray`-based manual pre-auth submission, `BiometricPrompt` gating, and `FLAG_SECURE`.
 */
class MeshMainViewModel(
    private val sessionRepository: MeshSessionRepository,
    private val ffiGateway: MeshFfiGateway,
    private val clipboardAccess: ClipboardAccess,
    private val authRequester: suspend (AdminAuthPurpose) -> BiometricGateResult,
    private val cleanupDiagnostics: () -> Unit,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    externalScope: CoroutineScope? = null,
    initialThemePrefs: ThemePrefsStore = InMemoryThemePrefsStore(),
) : ViewModel() {
    private val scope: CoroutineScope = externalScope ?: viewModelScope
    private val confirmationLock = Any()

    @Volatile
    private var themePrefsStore: ThemePrefsStore = initialThemePrefs

    @Volatile
    private var themePrefsAttached = false

    @Volatile
    private var heldConfirmationRequest: PendingEnrollmentRequest? = null

    private val _screenState =
        MutableStateFlow(
            MainUiScreenState(
                session = sessionRepository.uiState.value,
                themeMode = initialThemePrefs.loadThemeMode(),
            ),
        )
    val screenState: StateFlow<MainUiScreenState> = _screenState.asStateFlow()

    init {
        scope.launch {
            sessionRepository.uiState.collectLatest { session ->
                _screenState.update { current ->
                    val hidePins = if (!session.isEnrolled) false else current.isAdminPinsRevealed
                    current.copy(session = session, isAdminPinsRevealed = hidePins)
                }
            }
        }
    }

    fun attachThemePrefs(store: ThemePrefsStore) {
        if (themePrefsAttached) {
            return
        }
        themePrefsAttached = true
        themePrefsStore = store
        val savedMode = store.loadThemeMode()
        _screenState.update { it.copy(themeMode = savedMode) }
    }

    fun selectThemeMode(mode: ThemeMode) {
        themePrefsStore.saveThemeMode(mode)
        _screenState.update { it.copy(themeMode = mode) }
    }

    fun updatePeerSearchQuery(query: String) {
        _screenState.update { it.copy(peerSearchQuery = query) }
    }

    fun selectPeerFilterMode(mode: PeerFilterMode) {
        _screenState.update { it.copy(peerFilterMode = mode) }
    }

    fun selectTab(tab: MainTab) {
        _screenState.update { current ->
            val onSettings = tab == MainTab.SETTINGS
            val keepReveal = onSettings && current.isAdminPinsRevealed
            val keepModal = onSettings && current.isSensitiveModalOpen
            current.copy(
                activeTab = tab,
                isAdminPinsRevealed = keepReveal,
                isSensitiveModalOpen = keepModal,
            )
        }
    }

    fun selectOnboardingMethod(method: OnboardingMethod) {
        _screenState.update { it.copy(onboardingMethod = method, inputError = null) }
    }

    fun setConnectOnConfirm(connect: Boolean) {
        _screenState.update { it.copy(connectOnConfirm = connect) }
    }

    fun setSensitiveModalOpen(open: Boolean) {
        _screenState.update { it.copy(isSensitiveModalOpen = open) }
    }

    fun refreshState() {
        sessionRepository.refreshFromDisk()
    }

    fun pasteJoinUriAndClearClipboard() {
        val rawText = clipboardAccess.readPrimaryTextAndClear()
        if (rawText == null) {
            _screenState.update {
                it.copy(inputError = "Clipboard is empty. Copy a mesh://join URI first.")
            }
            return
        }
        submitJoinUriInput(rawText)
    }

    fun submitJoinUriInput(rawUri: String) {
        val trimmed = rawUri.trim()
        if (trimmed.isEmpty()) {
            _screenState.update { it.copy(inputError = "Enter or scan a valid mesh://join URI.") }
            return
        }
        _screenState.update { it.copy(inputError = null, infoBanner = null) }
        scope.launch {
            val result =
                withContext(ioDispatcher) {
                    runCatching { ffiGateway.parseJoinUri(trimmed) }
                }
            result
                .onSuccess { parsed ->
                    val summary = parsed.summary
                    val req =
                        PendingEnrollmentRequest(
                            serverEndpoint = summary.serverEndpoint,
                            tlsAuthMode = summary.tlsAuthMode,
                            serverPin = summary.serverPin,
                            nodeName = summary.nodeName,
                            preauthKeyMasked = summary.preauthKeyMasked,
                            session = parsed.session,
                        )
                    stageConfirmation(req)
                }.onFailure { err ->
                    val mapped = FfiErrorMapper.mapThrowable(err)
                    _screenState.update { it.copy(inputError = mapped.detail) }
                }
        }
    }

    fun submitManualJoin(
        rawEndpoint: String,
        tlsAuthMode: MobileTlsAuthMode,
        rawPin: String,
        rawPreauthKey: CharArray,
        rawNodeName: String,
    ) {
        _screenState.update { it.copy(inputError = null, infoBanner = null) }
        scope.launch {
            try {
                val validation =
                    OnboardingInputValidator.validateManualFields(
                        rawEndpoint = rawEndpoint,
                        tlsAuthMode = tlsAuthMode,
                        rawPin = rawPin,
                        rawPreauthKey = rawPreauthKey,
                        rawNodeName = rawNodeName,
                        requirePreauthKey = true,
                    )
                val firstError =
                    listOfNotNull(
                        validation.endpointError,
                        validation.pinError,
                        validation.preauthKeyError,
                        validation.nodeNameError,
                    ).firstOrNull()
                if (!validation.isValid || firstError != null) {
                    _screenState.update {
                        it.copy(inputError = firstError ?: "Invalid onboarding configuration.")
                    }
                    return@launch
                }
                val session =
                    withContext(ioDispatcher) {
                        ffiGateway.createPendingSessionFromChars(rawPreauthKey)
                    }
                val req =
                    PendingEnrollmentRequest(
                        serverEndpoint = validation.canonicalEndpoint ?: "",
                        tlsAuthMode = tlsAuthMode,
                        serverPin = validation.canonicalPin,
                        nodeName = validation.canonicalNodeName,
                        preauthKeyMasked = session.maskedPreview(),
                        session = session,
                    )
                stageConfirmation(req)
            } catch (err: Throwable) {
                val mapped = FfiErrorMapper.mapThrowable(err)
                _screenState.update { it.copy(inputError = mapped.detail) }
            } finally {
                rawPreauthKey.fill('\u0000')
            }
        }
    }

    fun cancelPendingConfirmation() {
        val cleared =
            synchronized(confirmationLock) {
                val prev = heldConfirmationRequest
                heldConfirmationRequest = null
                prev
            }
        cleared?.session?.cancel()
        _screenState.update { it.copy(pendingConfirmation = null) }
    }

    fun confirmPendingJoin(onReadyForVpnService: () -> Unit) {
        val req =
            synchronized(confirmationLock) {
                val current = heldConfirmationRequest
                heldConfirmationRequest = null
                current
            } ?: return

        val connectNow = _screenState.value.connectOnConfirm
        _screenState.update { it.copy(pendingConfirmation = null, inputError = null) }

        if (connectNow) {
            sessionRepository.stagePendingEnrollment(req)
            onReadyForVpnService()
        } else {
            scope.launch {
                val res = sessionRepository.enrollOnlyWithoutTunnel(req)
                res
                    .onSuccess {
                        _screenState.update {
                            it.copy(infoBanner = "Device enrolled. Tap Connect whenever ready.")
                        }
                    }.onFailure { err ->
                        val mapped = FfiErrorMapper.mapThrowable(err)
                        _screenState.update { it.copy(inputError = mapped.detail) }
                    }
            }
        }
    }

    fun onVpnConsentResult(
        granted: Boolean,
        onStartVpnService: () -> Unit,
    ) {
        if (granted) {
            onStartVpnService()
        } else {
            sessionRepository.cancelStagedPendingEnrollment()
            _screenState.update {
                it.copy(inputError = "VPN consent denied. Grant VPN permission to connect.")
            }
        }
    }

    fun onToggleTunnelRequested(
        onPrepareAndStart: () -> Unit,
        onStopService: () -> Unit,
    ) {
        val state = _screenState.value.session.daemonState
        val active =
            state == MobileDaemonState.CONNECTED ||
                state == MobileDaemonState.CONNECTING ||
                state == MobileDaemonState.DEGRADED
        if (active) {
            onStopService()
        } else {
            onPrepareAndStart()
        }
    }

    fun toggleRevealAdminPins() {
        if (_screenState.value.isAdminPinsRevealed) {
            _screenState.update { it.copy(isAdminPinsRevealed = false) }
            return
        }
        scope.launch {
            when (val auth = authRequester(AdminAuthPurpose.REVEAL_SPKI_PIN)) {
                BiometricGateResult.Authenticated -> {
                    _screenState.update {
                        it.copy(isAdminPinsRevealed = true, inputError = null)
                    }
                }
                BiometricGateResult.Cancelled -> {
                    _screenState.update {
                        it.copy(infoBanner = "Authentication cancelled; SPKI pin stays masked.")
                    }
                }
                is BiometricGateResult.Unavailable -> {
                    _screenState.update { it.copy(inputError = auth.reason) }
                }
            }
        }
    }

    fun rotateKeyWithAuth(rawPreauthKey: CharArray) {
        val formatErr = OnboardingInputValidator.validatePreauthKeyChars(rawPreauthKey)
        if (formatErr != null) {
            rawPreauthKey.fill('\u0000')
            _screenState.update { it.copy(inputError = formatErr) }
            return
        }
        scope.launch {
            try {
                when (val auth = authRequester(AdminAuthPurpose.ROTATE_KEY)) {
                    BiometricGateResult.Authenticated -> {
                        val res = sessionRepository.rotateIdentityKey(rawPreauthKey.copyOf())
                        res
                            .onSuccess {
                                _screenState.update {
                                    it.copy(
                                        infoBanner = "Node key rotated successfully.",
                                        isSensitiveModalOpen = false,
                                    )
                                }
                            }.onFailure { err ->
                                val msg = FfiErrorMapper.mapThrowable(err).detail
                                _screenState.update { it.copy(inputError = msg) }
                            }
                    }
                    BiometricGateResult.Cancelled -> {
                        _screenState.update { it.copy(infoBanner = "Key rotation cancelled.") }
                    }
                    is BiometricGateResult.Unavailable -> {
                        _screenState.update { it.copy(inputError = auth.reason) }
                    }
                }
            } finally {
                rawPreauthKey.fill('\u0000')
            }
        }
    }

    fun updateServerConfigWithAuth(
        rawEndpoint: String,
        tlsAuthMode: MobileTlsAuthMode,
        rawPin: String,
    ) {
        val (canonicalEndpoint, hostIsIp, epErr) =
            OnboardingInputValidator.validateEndpoint(rawEndpoint)
        val (canonicalPin, pinErr) =
            OnboardingInputValidator.validatePinForMode(tlsAuthMode, rawPin, hostIsIp)
        val validationErr = epErr ?: pinErr
        if (validationErr != null || canonicalEndpoint == null) {
            _screenState.update {
                it.copy(inputError = validationErr ?: "Invalid server endpoint")
            }
            return
        }
        scope.launch {
            when (val auth = authRequester(AdminAuthPurpose.UPDATE_SERVER_CONFIG)) {
                BiometricGateResult.Authenticated -> {
                    val res =
                        sessionRepository.updateServerConfig(
                            endpoint = canonicalEndpoint,
                            tlsAuthMode = tlsAuthMode,
                            pin = canonicalPin,
                        )
                    res
                        .onSuccess {
                            _screenState.update {
                                it.copy(
                                    infoBanner = "Server configuration updated.",
                                    isSensitiveModalOpen = false,
                                )
                            }
                        }.onFailure { err ->
                            val msg = FfiErrorMapper.mapThrowable(err).detail
                            _screenState.update { it.copy(inputError = msg) }
                        }
                }
                BiometricGateResult.Cancelled -> {
                    _screenState.update { it.copy(infoBanner = "Server update cancelled.") }
                }
                is BiometricGateResult.Unavailable -> {
                    _screenState.update { it.copy(inputError = auth.reason) }
                }
            }
        }
    }

    fun exportBugreportWithAuth() {
        scope.launch {
            when (val auth = authRequester(AdminAuthPurpose.EXPORT_BUGREPORT)) {
                BiometricGateResult.Authenticated -> {
                    val res = sessionRepository.exportScrubbedBugreport()
                    res
                        .onSuccess { prepared ->
                            _screenState.update { it.copy(pendingShareBugreport = prepared) }
                        }.onFailure { err ->
                            val msg = FfiErrorMapper.mapThrowable(err).detail
                            _screenState.update { it.copy(inputError = msg) }
                        }
                }
                BiometricGateResult.Cancelled -> {
                    _screenState.update { it.copy(infoBanner = "Bugreport export cancelled.") }
                }
                is BiometricGateResult.Unavailable -> {
                    _screenState.update { it.copy(inputError = auth.reason) }
                }
            }
        }
    }

    fun onBugreportShareDispatched() {
        _screenState.update { it.copy(pendingShareBugreport = null) }
    }

    fun purgeDiagnosticArtifacts() {
        cleanupDiagnostics()
        _screenState.update {
            it.copy(infoBanner = "Cached bugreport archives purged.", inputError = null)
        }
    }

    fun resetIdentityWithAuth() {
        scope.launch {
            when (val auth = authRequester(AdminAuthPurpose.RESET_IDENTITY)) {
                BiometricGateResult.Authenticated -> {
                    sessionRepository.resetLocalIdentity()
                    cleanupDiagnostics()
                    val currentTheme = _screenState.value.themeMode
                    _screenState.update {
                        MainUiScreenState(
                            session = sessionRepository.uiState.value,
                            themeMode = currentTheme,
                            infoBanner = "Local keys and Mesh state erased.",
                        )
                    }
                }
                BiometricGateResult.Cancelled -> {
                    _screenState.update { it.copy(infoBanner = "Identity reset cancelled.") }
                }
                is BiometricGateResult.Unavailable -> {
                    _screenState.update { it.copy(inputError = auth.reason) }
                }
            }
        }
    }

    fun pingPeer(
        target: String,
        forceDirect: Boolean = false,
    ) {
        scope.launch {
            val res = sessionRepository.pingPeer(target = target, forceDirect = forceDirect)
            res.onFailure { err ->
                val detail = FfiErrorMapper.mapThrowable(err).detail
                _screenState.update { it.copy(inputError = detail) }
            }
        }
    }

    fun runNetcheck() {
        scope.launch {
            val res = sessionRepository.runNetcheck()
            res.onFailure { err ->
                val detail = FfiErrorMapper.mapThrowable(err).detail
                _screenState.update { it.copy(inputError = detail) }
            }
        }
    }

    fun setAlwaysOnHint(enabled: Boolean) {
        sessionRepository.setAlwaysOnHint(enabled)
    }

    override fun onCleared() {
        cancelPendingConfirmation()
        super.onCleared()
    }

    private fun stageConfirmation(req: PendingEnrollmentRequest) {
        val prev =
            synchronized(confirmationLock) {
                val old = heldConfirmationRequest
                heldConfirmationRequest = req
                old
            }
        prev?.session?.cancel()
        _screenState.update {
            it.copy(
                pendingConfirmation =
                    JoinConfirmationUiModel(
                        serverEndpoint = req.serverEndpoint,
                        tlsAuthMode = req.tlsAuthMode,
                        serverPin = req.serverPin,
                        preauthKeyMasked = req.preauthKeyMasked,
                        nodeName = req.nodeName,
                    ),
                inputError = null,
            )
        }
    }
}
