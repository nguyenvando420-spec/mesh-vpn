package dev.meshvpn.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.meshvpn.android.data.diagnostics.BugreportShareManager
import dev.meshvpn.android.data.diagnostics.SafeLogger
import dev.meshvpn.android.ui.ActivityBiometricBridge
import dev.meshvpn.android.ui.AdminAuthPurpose
import dev.meshvpn.android.ui.AndroidBiometricAuthenticator
import dev.meshvpn.android.ui.AndroidClipboardAccess
import dev.meshvpn.android.ui.MainTab
import dev.meshvpn.android.ui.MainUiScreenState
import dev.meshvpn.android.ui.MeshMainViewModel
import dev.meshvpn.android.ui.MeshMainViewModelFactory
import dev.meshvpn.android.ui.onboarding.OnboardingScreen
import dev.meshvpn.android.ui.peers.PeersScreen
import dev.meshvpn.android.ui.settings.SettingsScreen
import dev.meshvpn.android.ui.status.StatusScreen
import dev.meshvpn.android.ui.theme.MeshTheme
import dev.meshvpn.android.ui.theme.SharedPrefsThemeStore
import dev.meshvpn.android.vpn.MeshVpnService

/**
 * Single-activity Compose host (`US-081..US-086`, `US-119`) managing Android VPN consent,
 * `FLAG_SECURE`, `BiometricPrompt` attachment, 3-tab navigation, and transient bugreport sharing.
 */
class MainActivity : FragmentActivity() {
    private val biometricBridge = ActivityBiometricBridge()

    private val viewModel: MeshMainViewModel by viewModels {
        val appContainer = (application as MeshApplication).container
        MeshMainViewModelFactory(
            appContainer = appContainer,
            clipboardAccess = AndroidClipboardAccess(applicationContext),
            authRequester = { purpose -> authorizeAdminPurpose(purpose) },
        )
    }

    private val vpnPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { result ->
            val granted = result.resultCode == RESULT_OK
            viewModel.onVpnConsentResult(granted) {
                startTunnelWithNotificationCheck()
            }
        }

    private val notificationPermissionLauncher =
        registerForActivityResult(
            ActivityResultContracts.RequestPermission(),
        ) { _ ->
            MeshVpnService.startTunnelService(this)
        }

    private val bugreportShareLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { _ ->
            (application as? MeshApplication)
                ?.container
                ?.bugreportManager
                ?.cleanupAllDiagnosticArtifacts()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel.attachThemePrefs(SharedPrefsThemeStore(applicationContext))
        viewModel.attachLocalePrefs(SharedPrefsLocaleStore(applicationContext))
        setContent {
            val screenState by viewModel.screenState.collectAsStateWithLifecycle()
            val localizedContext =
                remember(this@MainActivity, screenState.localeMode) {
                    LocaleHelper.wrapActivityContext(this@MainActivity, screenState.localeMode)
                }

            LaunchedEffect(screenState.requireFlagSecure) {
                updateFlagSecure(screenState.requireFlagSecure)
            }

            LaunchedEffect(screenState.pendingShareBugreport) {
                val report = screenState.pendingShareBugreport ?: return@LaunchedEffect
                viewModel.onBugreportShareDispatched()
                launchBugreportShareChooser(report)
            }

            CompositionLocalProvider(
                LocalContext provides localizedContext,
                LocalConfiguration provides localizedContext.resources.configuration,
            ) {
                MeshTheme(themeMode = screenState.themeMode) {
                    MeshRootScaffold(
                        screenState = screenState,
                        viewModel = viewModel,
                        onPrepareAndStartVpn = { prepareVpnConsentAndStart() },
                        onStopVpnService = { MeshVpnService.stopTunnelService(this) },
                        onOpenSystemSettings = { action -> openSystemSettingsScreen(action) },
                    )
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        biometricBridge.attach(AndroidBiometricAuthenticator(this))
    }

    override fun onResume() {
        super.onResume()
        viewModel.refreshState()
    }

    override fun onStop() {
        biometricBridge.detach()
        super.onStop()
    }

    private suspend fun authorizeAdminPurpose(purpose: AdminAuthPurpose):
        dev.meshvpn.android.ui.BiometricGateResult {
        val localized =
            LocaleHelper.wrapActivityContext(
                activity = this,
                mode = viewModel.screenState.value.localeMode,
            )
        val subtitle =
            when (purpose) {
                AdminAuthPurpose.REVEAL_SPKI_PIN ->
                    LocaleHelper.tr(
                        localized,
                        "Reveal Control server SPKI fingerprint",
                        "Hiện vân tay SPKI máy chủ điều khiển",
                    )
                AdminAuthPurpose.UPDATE_SERVER_CONFIG ->
                    LocaleHelper.tr(
                        localized,
                        "Authorize Control server update",
                        "Ủy quyền cập nhật máy chủ điều khiển",
                    )
                AdminAuthPurpose.ROTATE_KEY ->
                    LocaleHelper.tr(
                        localized,
                        "Authorize node key rotation",
                        "Ủy quyền xoay vòng khóa nút",
                    )
                AdminAuthPurpose.EXPORT_BUGREPORT ->
                    localized.getString(R.string.biometric_prompt_subtitle)
                AdminAuthPurpose.RESET_IDENTITY ->
                    LocaleHelper.tr(
                        localized,
                        "Authorize permanent erasure of local keys",
                        "Ủy quyền xóa vĩnh viễn khóa cục bộ",
                    )
            }
        return biometricBridge.authenticate(
            title = localized.getString(R.string.biometric_prompt_title),
            subtitle = subtitle,
            negativeButtonText = localized.getString(R.string.biometric_prompt_negative),
        )
    }

    private fun prepareVpnConsentAndStart() {
        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            vpnPermissionLauncher.launch(consentIntent)
        } else {
            viewModel.onVpnConsentResult(granted = true) {
                startTunnelWithNotificationCheck()
            }
        }
    }

    private fun startTunnelWithNotificationCheck() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted =
                ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS,
                ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        MeshVpnService.startTunnelService(this)
    }

    private fun updateFlagSecure(secure: Boolean) {
        if (secure) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    private fun launchBugreportShareChooser(report: BugreportShareManager.PreparedBugreport) {
        val shareUri = report.shareUri ?: return
        val sendIntent =
            Intent(Intent.ACTION_SEND).apply {
                type = "application/x-tar"
                putExtra(Intent.EXTRA_STREAM, shareUri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        val localized =
            LocaleHelper.wrapActivityContext(
                activity = this,
                mode = viewModel.screenState.value.localeMode,
            )
        val chooser =
            Intent.createChooser(
                sendIntent,
                localized.getString(R.string.share_bugreport_chooser),
            )
        try {
            bugreportShareLauncher.launch(chooser)
        } catch (err: Exception) {
            SafeLogger.w("MainActivity", "Unable to launch bugreport chooser", err)
            (application as? MeshApplication)
                ?.container
                ?.bugreportManager
                ?.cleanupAllDiagnosticArtifacts()
        }
    }

    private fun openSystemSettingsScreen(action: String) {
        val intent = Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { startActivity(intent) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }
}

@Composable
private fun MeshRootScaffold(
    screenState: MainUiScreenState,
    viewModel: MeshMainViewModel,
    onPrepareAndStartVpn: () -> Unit,
    onStopVpnService: () -> Unit,
    onOpenSystemSettings: (String) -> Unit,
) {
    val enrolled = screenState.session.isEnrolled
    Scaffold(
        bottomBar = {
            if (enrolled) {
                MeshBottomNavigation(
                    activeTab = screenState.activeTab,
                    onSelectTab = viewModel::selectTab,
                )
            }
        },
    ) { innerPadding ->
        if (!enrolled) {
            OnboardingScreen(
                screenState = screenState,
                onSelectMethod = viewModel::selectOnboardingMethod,
                onSubmitJoinUri = viewModel::submitJoinUriInput,
                onPasteFromClipboard = viewModel::pasteJoinUriAndClearClipboard,
                onSubmitManual = viewModel::submitManualJoin,
                onToggleConnectOnConfirm = viewModel::setConnectOnConfirm,
                onConfirmJoin = { viewModel.confirmPendingJoin(onPrepareAndStartVpn) },
                onCancelConfirmation = viewModel::cancelPendingConfirmation,
                modifier = Modifier.padding(innerPadding),
            )
            return@Scaffold
        }

        when (screenState.activeTab) {
            MainTab.STATUS ->
                StatusScreen(
                    screenState = screenState,
                    onToggleTunnel = {
                        viewModel.onToggleTunnelRequested(
                            onPrepareAndStart = onPrepareAndStartVpn,
                            onStopService = onStopVpnService,
                        )
                    },
                    onRunNetcheck = viewModel::runNetcheck,
                    onOpenVpnSettings = { onOpenSystemSettings(Settings.ACTION_VPN_SETTINGS) },
                    onOpenNetworkSettings = {
                        onOpenSystemSettings(Settings.ACTION_WIRELESS_SETTINGS)
                    },
                    onOpenDateTimeSettings = {
                        onOpenSystemSettings(Settings.ACTION_DATE_SETTINGS)
                    },
                    onOpenPeersTab = { viewModel.selectTab(MainTab.PEERS) },
                    onOpenSettingsTab = { viewModel.selectTab(MainTab.SETTINGS) },
                    onResetAndReenroll = viewModel::resetIdentityWithAuth,
                    modifier = Modifier.padding(innerPadding),
                )
            MainTab.PEERS ->
                PeersScreen(
                    screenState = screenState,
                    onSearchQueryChanged = viewModel::updatePeerSearchQuery,
                    onSelectFilterMode = viewModel::selectPeerFilterMode,
                    onPingPeer = { target -> viewModel.pingPeer(target) },
                    modifier = Modifier.padding(innerPadding),
                )
            MainTab.SETTINGS ->
                SettingsScreen(
                    screenState = screenState,
                    onSelectThemeMode = viewModel::selectThemeMode,
                    onSelectLocaleMode = viewModel::setLocaleMode,
                    onToggleRevealPins = viewModel::toggleRevealAdminPins,
                    onSensitiveModalChanged = viewModel::setSensitiveModalOpen,
                    onUpdateServerConfig = viewModel::updateServerConfigWithAuth,
                    onRotateKey = viewModel::rotateKeyWithAuth,
                    onToggleAlwaysOnHint = viewModel::setAlwaysOnHint,
                    onOpenVpnSettings = { onOpenSystemSettings(Settings.ACTION_VPN_SETTINGS) },
                    onRunNetcheck = viewModel::runNetcheck,
                    onExportBugreport = viewModel::exportBugreportWithAuth,
                    onCleanupDiagnostics = viewModel::purgeDiagnosticArtifacts,
                    onResetIdentity = viewModel::resetIdentityWithAuth,
                    modifier = Modifier.padding(innerPadding),
                )
        }
    }
}

@Composable
private fun MeshBottomNavigation(
    activeTab: MainTab,
    onSelectTab: (MainTab) -> Unit,
) {
    NavigationBar {
        NavigationBarItem(
            selected = activeTab == MainTab.STATUS,
            onClick = { onSelectTab(MainTab.STATUS) },
            icon = { Icon(imageVector = Icons.Outlined.Shield, contentDescription = null) },
            label = { Text(stringResource(R.string.tab_status)) },
            modifier = Modifier.testTag("nav_tab_status"),
        )
        NavigationBarItem(
            selected = activeTab == MainTab.PEERS,
            onClick = { onSelectTab(MainTab.PEERS) },
            icon = { Icon(imageVector = Icons.Outlined.Group, contentDescription = null) },
            label = { Text(stringResource(R.string.tab_peers)) },
            modifier = Modifier.testTag("nav_tab_peers"),
        )
        NavigationBarItem(
            selected = activeTab == MainTab.SETTINGS,
            onClick = { onSelectTab(MainTab.SETTINGS) },
            icon = { Icon(imageVector = Icons.Outlined.Settings, contentDescription = null) },
            label = { Text(stringResource(R.string.tab_settings)) },
            modifier = Modifier.testTag("nav_tab_settings"),
        )
    }
}
