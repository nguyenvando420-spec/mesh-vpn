package dev.meshvpn.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.meshvpn.android.LocaleHelper
import dev.meshvpn.android.LocaleMode
import dev.meshvpn.android.MainActivity
import dev.meshvpn.android.MeshApplication
import dev.meshvpn.android.R
import dev.meshvpn.android.SharedPrefsLocaleStore
import dev.meshvpn.android.data.diagnostics.SafeLogger
import dev.meshvpn.android.data.network.UnderlayStateClassifier
import dev.meshvpn.android.ffi.MeshNativeInit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileNetEventKind
import uniffi.mesh_mobile_ffi.MobileTunnelNetworkConfig
import uniffi.mesh_mobile_ffi.MobileUnderlayState

/**
 * Android [VpnService] hosting the in-process Rust Mesh VPN engine (`ADR-017`, `US-081`, `US-083`).
 *
 * Implements:
 * - Idempotent [MeshNativeInit.ensureInitialized] in [onCreate] for Direct Boot & Always-On VPN.
 * - `FOREGROUND_SERVICE_SPECIAL_USE` lifecycle on Android 14+ (API 34+).
 * - Synchronous lock-free `VpnService.protect(fd)` and `/32` split-tunnel `VpnService.Builder`.
 * - [ConnectivityManager.NetworkCallback] for Wi-Fi <-> cellular roaming, Airplane Mode, and
 *   Strict Private DNS / Lockdown Mode warnings.
 * - Direct Boot `LOCKED_BOOT_COMPLETED` -> `ACTION_USER_UNLOCKED` deferred startup.
 * - Bounded `<= 5_000 ms` graceful teardown on [onRevoke] and [onDestroy].
 */
class MeshVpnService : VpnService() {
    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.IO)
    private val tearingDown = AtomicBoolean(false)

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var systemEventsReceiver: BroadcastReceiver? = null
    private var unlockReceiver: BroadcastReceiver? = null
    private var stateObserverJob: Job? = null

    @Volatile
    private var lastUnderlayState: MobileUnderlayState? = null

    override fun onCreate() {
        super.onCreate()
        MeshNativeInit.ensureInitialized(applicationContext)
        createNotificationChannels()
        startStateObserver()
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        val action = intent?.action ?: SERVICE_INTERFACE
        SafeLogger.i(TAG, "MeshVpnService onStartCommand action=$action")

        if (action == ACTION_STOP_TUNNEL || action == ACTION_DISCONNECT_NOTIFICATION) {
            promoteToForeground(buildStatusNotification(MeshSessionUiState()))
            triggerShutdownAndStop()
            return START_NOT_STICKY
        }

        val container = (application as? MeshApplication)?.container
        if (container == null) {
            SafeLogger.e(TAG, "MeshApplication container unavailable")
            stopSelf()
            return START_NOT_STICKY
        }

        if (!container.stateStore.isDeviceUnlocked()) {
            container.sessionRepository.markDeviceLockedWaiting()
            promoteToForeground(
                buildStatusNotification(container.sessionRepository.uiState.value),
            )
            registerUnlockWaiterReceiver(container)
            return START_STICKY
        }

        promoteToForeground(buildStatusNotification(container.sessionRepository.uiState.value))
        registerNetworkAndPowerMonitors(container)
        startTunnelCoroutine(container)
        return START_STICKY
    }

    override fun onRevoke() {
        SafeLogger.i(TAG, "System revoked VPN permission via onRevoke()")
        triggerShutdownAndStop()
        super.onRevoke()
    }

    override fun onDestroy() {
        SafeLogger.i(TAG, "MeshVpnService onDestroy() tearing down within 5s budget")
        unregisterMonitors()
        stateObserverJob?.cancel()

        val container = (application as? MeshApplication)?.container
        if (container != null && tearingDown.compareAndSet(false, true)) {
            runBlocking(Dispatchers.IO) {
                withTimeoutOrNull(TEARDOWN_BUDGET_MS) {
                    container.sessionRepository.stopAndShutdownEngine()
                }
            }
        }
        serviceScope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun startTunnelCoroutine(container: dev.meshvpn.android.di.MeshAppContainer) {
        container.attachVpnLockdownChecker {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                isLockdownEnabled
            } else {
                false
            }
        }
        serviceScope.launch {
            val underlay = container.underlayCollector.collectUnderlayState()
            lastUnderlayState = underlay
            container.sessionRepository.updateUnderlayFlags(underlay)

            container.sessionRepository.startServiceSession(
                socketProtector = { fd -> protect(fd) },
                tunEstablisher = TunEstablisher { cfg -> establishDetachedTun(cfg) },
                routeScope = serviceScope,
            )
        }
    }

    private fun establishDetachedTun(config: MobileTunnelNetworkConfig): Int? {
        if (prepare(this) != null) {
            SafeLogger.w(TAG, "VPN consent not granted; cannot establish TUN")
            return null
        }
        val builder = Builder()
        SplitTunnelBuilderValidator.applyToBuilder(
            builder = builder,
            packageName = packageName,
            config = config,
        )
        val pfd = builder.establish() ?: return null
        return pfd.detachFd()
    }

    private fun registerNetworkAndPowerMonitors(
        container: dev.meshvpn.android.di.MeshAppContainer,
    ) {
        if (networkCallback == null) {
            val cm = getSystemService(ConnectivityManager::class.java)
            if (cm != null) {
                val callback =
                    object : ConnectivityManager.NetworkCallback() {
                        override fun onAvailable(network: Network) {
                            handleUnderlayTransition(container, network, forcedLost = false)
                        }

                        override fun onCapabilitiesChanged(
                            network: Network,
                            networkCapabilities: NetworkCapabilities,
                        ) {
                            val notVpn =
                                networkCapabilities.hasCapability(
                                    NetworkCapabilities.NET_CAPABILITY_NOT_VPN,
                                )
                            if (notVpn) {
                                handleUnderlayTransition(container, network, forcedLost = false)
                            }
                        }

                        override fun onLinkPropertiesChanged(
                            network: Network,
                            linkProperties: LinkProperties,
                        ) {
                            handleUnderlayTransition(container, network, forcedLost = false)
                        }

                        override fun onLost(network: Network) {
                            handleUnderlayTransition(
                                container = container,
                                explicitNetwork = null,
                                forcedLost = true,
                            )
                        }
                    }
                cm.registerDefaultNetworkCallback(callback)
                networkCallback = callback
            }
        }

        if (systemEventsReceiver == null) {
            val receiver =
                object : BroadcastReceiver() {
                    override fun onReceive(
                        context: Context?,
                        intent: Intent?,
                    ) {
                        val act = intent?.action ?: return
                        when (act) {
                            Intent.ACTION_SCREEN_OFF ->
                                container.sessionRepository.setPowerSavingMode(true)
                            Intent.ACTION_SCREEN_ON ->
                                container.sessionRepository.setPowerSavingMode(false)
                            PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                                val pm = getSystemService(PowerManager::class.java)
                                val idle = pm?.isDeviceIdleMode ?: false
                                container.sessionRepository.setPowerSavingMode(idle)
                            }
                        }
                    }
                }
            val filter =
                IntentFilter().apply {
                    addAction(Intent.ACTION_SCREEN_OFF)
                    addAction(Intent.ACTION_SCREEN_ON)
                    addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                }
            ContextCompat.registerReceiver(
                this,
                receiver,
                filter,
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
            systemEventsReceiver = receiver
        }
    }

    private fun handleUnderlayTransition(
        container: dev.meshvpn.android.di.MeshAppContainer,
        explicitNetwork: Network?,
        forcedLost: Boolean,
    ) {
        val next = container.underlayCollector.collectUnderlayState(explicitNetwork)
        val prev = lastUnderlayState
        lastUnderlayState = next
        val kind =
            if (forcedLost && !next.hasIpv4 && !next.hasIpv6) {
                MobileNetEventKind.CONNECTIVITY_LOST
            } else {
                UnderlayStateClassifier.inferChangeKind(prev, next)
            }
        container.sessionRepository.dispatchNetworkChange(kind, next)
    }

    private fun registerUnlockWaiterReceiver(container: dev.meshvpn.android.di.MeshAppContainer) {
        if (unlockReceiver != null) {
            return
        }
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(
                    context: Context?,
                    intent: Intent?,
                ) {
                    if (intent?.action == Intent.ACTION_USER_UNLOCKED &&
                        container.stateStore.isDeviceUnlocked()
                    ) {
                        SafeLogger.i(TAG, "Device unlocked after Direct Boot; resuming Mesh VPN")
                        unregisterUnlockReceiver()
                        container.sessionRepository.refreshFromDisk()
                        registerNetworkAndPowerMonitors(container)
                        startTunnelCoroutine(container)
                    }
                }
            }
        val filter = IntentFilter(Intent.ACTION_USER_UNLOCKED)
        ContextCompat.registerReceiver(
            this,
            receiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        unlockReceiver = receiver
    }

    private fun unregisterUnlockReceiver() {
        val receiver = unlockReceiver
        unlockReceiver = null
        if (receiver != null) {
            try {
                unregisterReceiver(receiver)
            } catch (_: IllegalArgumentException) {
                // Already unregistered.
            }
        }
    }

    private fun unregisterMonitors() {
        unregisterUnlockReceiver()
        val cb = networkCallback
        networkCallback = null
        if (cb != null) {
            val cm = getSystemService(ConnectivityManager::class.java)
            try {
                cm?.unregisterNetworkCallback(cb)
            } catch (_: IllegalArgumentException) {
                // Callback was already unregistered.
            }
        }

        val sysReceiver = systemEventsReceiver
        systemEventsReceiver = null
        if (sysReceiver != null) {
            try {
                unregisterReceiver(sysReceiver)
            } catch (_: IllegalArgumentException) {
                // Already unregistered.
            }
        }
    }

    private fun triggerShutdownAndStop() {
        if (!tearingDown.compareAndSet(false, true)) {
            return
        }
        unregisterMonitors()
        val container = (application as? MeshApplication)?.container
        serviceScope.launch {
            withTimeoutOrNull(TEARDOWN_BUDGET_MS) {
                container?.sessionRepository?.stopAndShutdownEngine()
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun startStateObserver() {
        val container = (application as? MeshApplication)?.container ?: return
        stateObserverJob =
            serviceScope.launch {
                container.sessionRepository.uiState.collectLatest { uiState ->
                    val nm = getSystemService(NotificationManager::class.java)
                    nm?.notify(NOTIFICATION_ID, buildStatusNotification(uiState))
                    MeshTileService.requestTileSync(applicationContext)
                }
            }
    }

    private fun promoteToForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun localizedContext(): Context {
        val mode =
            runCatching { SharedPrefsLocaleStore(applicationContext).loadLocaleMode() }
                .getOrDefault(LocaleMode.SYSTEM)
        return LocaleHelper.buildLocalizedContext(this, mode)
    }

    private fun createNotificationChannels() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val l10n = localizedContext()
        val tunnelChannel =
            NotificationChannel(
                CHANNEL_VPN_STATUS,
                l10n.getString(R.string.notification_channel_vpn),
                NotificationManager.IMPORTANCE_LOW,
            )
        val alertChannel =
            NotificationChannel(
                CHANNEL_VPN_ALERTS,
                l10n.getString(R.string.notification_channel_alerts),
                NotificationManager.IMPORTANCE_HIGH,
            )
        nm.createNotificationChannel(tunnelChannel)
        nm.createNotificationChannel(alertChannel)
    }

    private fun buildStatusNotification(uiState: MeshSessionUiState): Notification {
        val l10n = localizedContext()
        val contentIntent =
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        val disconnectIntent =
            PendingIntent.getService(
                this,
                1,
                Intent(this, MeshVpnService::class.java).setAction(ACTION_DISCONNECT_NOTIFICATION),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

        val statusText =
            when {
                !uiState.isDeviceUnlocked ||
                    uiState.daemonState == MobileDaemonState.DEVICE_LOCKED ->
                    l10n.getString(R.string.notification_status_waiting_unlock)
                uiState.daemonState == MobileDaemonState.CONNECTED -> {
                    val ip =
                        uiState.snapshot?.overlayIp
                            ?: uiState.bootstrapSummary?.overlayIp
                            ?: "mesh"
                    l10n.getString(R.string.notification_status_connected, ip)
                }
                uiState.daemonState == MobileDaemonState.CONNECTING ->
                    l10n.getString(R.string.notification_status_connecting)
                uiState.daemonState == MobileDaemonState.DEGRADED ->
                    l10n.getString(R.string.notification_status_degraded)
                uiState.daemonState == MobileDaemonState.REAUTH_REQUIRED ->
                    l10n.getString(R.string.state_reauth_required)
                uiState.daemonState == MobileDaemonState.REVOKED ->
                    l10n.getString(R.string.state_revoked)
                uiState.daemonState == MobileDaemonState.SERVER_UPGRADE_REQUIRED ->
                    l10n.getString(R.string.state_error)
                else -> l10n.getString(R.string.notification_status_stopped)
            }

        val warningLines =
            buildList {
                if (uiState.isLockdownEnabled) {
                    add(l10n.getString(R.string.notification_warning_lockdown))
                }
                if (uiState.isPrivateDnsStrict) {
                    add(l10n.getString(R.string.notification_warning_private_dns))
                }
            }
        val channelId = if (warningLines.isNotEmpty()) CHANNEL_VPN_ALERTS else CHANNEL_VPN_STATUS

        val builder =
            NotificationCompat
                .Builder(this, channelId)
                .setSmallIcon(R.drawable.ic_vpn_key)
                .setColor(notificationColorForState(uiState.daemonState))
                .setContentTitle(l10n.getString(R.string.notification_title))
                .setContentText(warningLines.firstOrNull() ?: statusText)
                .setContentIntent(contentIntent)
                .setOngoing(uiState.daemonState != MobileDaemonState.STOPPED)
                .setOnlyAlertOnce(warningLines.isEmpty())
                .addAction(
                    R.drawable.ic_vpn_key,
                    l10n.getString(R.string.notification_action_disconnect),
                    disconnectIntent,
                )

        if (warningLines.isNotEmpty()) {
            val combined = (listOf(statusText) + warningLines).joinToString("\n")
            builder.setStyle(NotificationCompat.BigTextStyle().bigText(combined))
        }
        return builder.build()
    }

    companion object {
        private const val TAG = "MeshVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_VPN_STATUS = "mesh_vpn_status"
        private const val CHANNEL_VPN_ALERTS = "mesh_vpn_alerts"
        private const val TEARDOWN_BUDGET_MS = 4_500L

        private const val COLOR_SEMANTIC_SUCCESS = 0xFF16A34A.toInt()
        private const val COLOR_SEMANTIC_WARNING = 0xFFD97706.toInt()
        private const val COLOR_SEMANTIC_ERROR = 0xFFDC2626.toInt()
        private const val COLOR_SEMANTIC_NEUTRAL = 0xFF6B7280.toInt()

        const val ACTION_START_TUNNEL = "dev.meshvpn.android.action.START_TUNNEL"
        const val ACTION_STOP_TUNNEL = "dev.meshvpn.android.action.STOP_TUNNEL"
        private const val ACTION_DISCONNECT_NOTIFICATION =
            "dev.meshvpn.android.action.DISCONNECT_FROM_NOTIFICATION"

        fun notificationColorForState(state: MobileDaemonState): Int =
            when (state) {
                MobileDaemonState.CONNECTED -> COLOR_SEMANTIC_SUCCESS
                MobileDaemonState.CONNECTING,
                MobileDaemonState.DEGRADED,
                MobileDaemonState.REAUTH_REQUIRED,
                -> COLOR_SEMANTIC_WARNING
                MobileDaemonState.REVOKED,
                MobileDaemonState.SERVER_UPGRADE_REQUIRED,
                -> COLOR_SEMANTIC_ERROR
                MobileDaemonState.STOPPED,
                MobileDaemonState.DEVICE_LOCKED,
                -> COLOR_SEMANTIC_NEUTRAL
            }

        fun startTunnelService(context: Context) {
            val intent =
                Intent(context, MeshVpnService::class.java)
                    .setAction(ACTION_START_TUNNEL)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stopTunnelService(context: Context) {
            val intent =
                Intent(context, MeshVpnService::class.java)
                    .setAction(ACTION_STOP_TUNNEL)
            context.startService(intent)
        }
    }
}
