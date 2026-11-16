package dev.meshvpn.android.vpn

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.meshvpn.android.MainActivity
import dev.meshvpn.android.MeshApplication
import dev.meshvpn.android.data.diagnostics.SafeLogger
import uniffi.mesh_mobile_ffi.MobileDaemonState

/**
 * Android Quick Settings [TileService] for one-tap Mesh VPN toggle.
 */
class MeshTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        syncTileState()
    }

    override fun onClick() {
        super.onClick()
        val app = application as? MeshApplication ?: return
        val repo = app.container.sessionRepository
        val state = repo.uiState.value

        if (!state.isDeviceUnlocked || !state.isEnrolled) {
            openMainApp()
            return
        }

        val isRunning =
            state.daemonState == MobileDaemonState.CONNECTED ||
                state.daemonState == MobileDaemonState.CONNECTING ||
                state.daemonState == MobileDaemonState.DEGRADED

        if (isRunning) {
            MeshVpnService.stopTunnelService(applicationContext)
        } else if (VpnService.prepare(this) == null) {
            MeshVpnService.startTunnelService(applicationContext)
        } else {
            openMainApp()
        }
        syncTileState()
    }

    private fun syncTileState() {
        val tile = qsTile ?: return
        val app = application as? MeshApplication ?: return
        app.container.sessionRepository.refreshFromDisk()
        val state = app.container.sessionRepository.uiState.value

        tile.state =
            when {
                !state.isDeviceUnlocked || !state.isEnrolled -> Tile.STATE_UNAVAILABLE
                state.daemonState == MobileDaemonState.CONNECTED ||
                    state.daemonState == MobileDaemonState.CONNECTING ||
                    state.daemonState == MobileDaemonState.DEGRADED -> Tile.STATE_ACTIVE
                else -> Tile.STATE_INACTIVE
            }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle =
                when (state.daemonState) {
                    MobileDaemonState.CONNECTED -> state.snapshot?.overlayIp ?: "Connected"
                    MobileDaemonState.CONNECTING -> "Connecting"
                    MobileDaemonState.DEGRADED -> "P2P Only"
                    MobileDaemonState.DEVICE_LOCKED -> "Locked"
                    else -> if (state.isEnrolled) "Disconnected" else "Setup needed"
                }
        }
        tile.updateTile()
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openMainApp() {
        val intent =
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi =
                PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    companion object {
        private const val TAG = "MeshTileService"

        fun requestTileSync(context: Context) {
            try {
                requestListeningState(
                    context,
                    ComponentName(context, MeshTileService::class.java),
                )
            } catch (err: SecurityException) {
                SafeLogger.w(TAG, "Unable to request Quick Settings tile sync", err)
            } catch (err: IllegalArgumentException) {
                SafeLogger.w(TAG, "Quick Settings tile component unavailable", err)
            }
        }
    }
}
