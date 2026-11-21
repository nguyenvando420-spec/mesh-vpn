package dev.meshvpn.android.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import dev.meshvpn.android.LocaleHelper
import dev.meshvpn.android.LocaleMode
import dev.meshvpn.android.R
import dev.meshvpn.android.SharedPrefsLocaleStore
import uniffi.mesh_mobile_ffi.MobileDaemonState

/**
 * Localized notification channel and text helpers for [MeshVpnService].
 */
internal object MeshVpnNotificationHelper {
    const val CHANNEL_VPN_STATUS = "mesh_vpn_status"
    const val CHANNEL_VPN_ALERTS = "mesh_vpn_alerts"

    fun localizedContext(context: Context): Context {
        val mode =
            runCatching { SharedPrefsLocaleStore(context.applicationContext).loadLocaleMode() }
                .getOrDefault(LocaleMode.SYSTEM)
        return LocaleHelper.buildLocalizedContext(context, mode)
    }

    fun createChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        val l10n = localizedContext(context)
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

    fun resolveStatusText(
        l10n: Context,
        uiState: MeshSessionUiState,
    ): String =
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

    fun buildWarningLines(
        l10n: Context,
        uiState: MeshSessionUiState,
    ): List<String> =
        buildList {
            if (uiState.isLockdownEnabled) {
                add(l10n.getString(R.string.notification_warning_lockdown))
            }
            if (uiState.isPrivateDnsStrict) {
                add(l10n.getString(R.string.notification_warning_private_dns))
            }
        }
}
