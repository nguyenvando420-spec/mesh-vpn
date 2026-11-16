package dev.meshvpn.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import dev.meshvpn.android.MeshApplication
import dev.meshvpn.android.data.diagnostics.SafeLogger

/**
 * Direct-Boot-aware receiver resuming Mesh VPN when Always-On auto-start is enabled (`US-085`).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(
        context: Context?,
        intent: Intent?,
    ) {
        val action = intent?.action
        val validAction =
            action == Intent.ACTION_LOCKED_BOOT_COMPLETED ||
                action == Intent.ACTION_BOOT_COMPLETED ||
                action == Intent.ACTION_USER_UNLOCKED
        val app = context?.applicationContext as? MeshApplication
        if (context == null || !validAction || app == null) {
            return
        }
        if (!app.container.stateStore.getAlwaysOnHint()) {
            return
        }
        if (VpnService.prepare(context) != null) {
            SafeLogger.i(TAG, "Skipping boot start: VPN consent not yet granted")
            return
        }
        SafeLogger.i(TAG, "Boot event $action triggering MeshVpnService")
        MeshVpnService.startTunnelService(context)
    }

    companion object {
        private const val TAG = "BootReceiver"
    }
}
