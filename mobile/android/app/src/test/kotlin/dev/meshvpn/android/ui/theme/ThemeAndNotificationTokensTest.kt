package dev.meshvpn.android.ui.theme

import android.content.SharedPreferences
import androidx.compose.ui.graphics.toArgb
import dev.meshvpn.android.R
import dev.meshvpn.android.ui.status.canonicalDaemonStateLabel
import dev.meshvpn.android.ui.status.daemonStateLabelRes
import dev.meshvpn.android.vpn.MeshVpnService
import java.lang.reflect.Proxy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import uniffi.mesh_mobile_ffi.MobileDaemonState

class ThemeAndNotificationTokensTest {
    private fun createInMemorySharedPrefs(
        backing: MutableMap<String, Any?>,
    ): SharedPreferences {
        val editor =
            Proxy.newProxyInstance(
                SharedPreferences.Editor::class.java.classLoader,
                arrayOf(SharedPreferences.Editor::class.java),
            ) { proxy, method, args ->
                when (method.name) {
                    "putString" -> {
                        val key = args?.getOrNull(0) as? String
                        val value = args?.getOrNull(1) as? String
                        if (key != null) {
                            backing[key] = value
                        }
                        proxy
                    }
                    "remove" -> {
                        val key = args?.getOrNull(0) as? String
                        if (key != null) {
                            backing.remove(key)
                        }
                        proxy
                    }
                    "clear" -> {
                        backing.clear()
                        proxy
                    }
                    "commit" -> true
                    "apply" -> Unit
                    else -> proxy
                }
            } as SharedPreferences.Editor

        return Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java),
        ) { _, method, args ->
            when (method.name) {
                "getString" -> {
                    val key = args?.getOrNull(0) as? String
                    val defValue = args?.getOrNull(1) as? String
                    backing[key] as? String ?: defValue
                }
                "contains" -> {
                    val key = args?.getOrNull(0) as? String
                    key != null && backing.containsKey(key)
                }
                "edit" -> editor
                else -> null
            }
        } as SharedPreferences
    }

    @Test
    fun sharedPrefsThemeStorePersistsCanonicalKeyAndFallsBackToSystem() {
        // Arrange
        val backing = mutableMapOf<String, Any?>()
        val store = SharedPrefsThemeStore(createInMemorySharedPrefs(backing))

        // Act & Assert default
        assertEquals("mesh_ui_prefs", SharedPrefsThemeStore.PREFS_NAME)
        assertEquals("mesh_theme_mode", SharedPrefsThemeStore.KEY_THEME_MODE)
        assertEquals(ThemeMode.SYSTEM, store.loadThemeMode())

        // Act & Assert save DARK
        store.saveThemeMode(ThemeMode.DARK)
        assertEquals("dark", backing["mesh_theme_mode"])
        assertEquals(ThemeMode.DARK, store.loadThemeMode())

        // Act & Assert save LIGHT
        store.saveThemeMode(ThemeMode.LIGHT)
        assertEquals("light", backing["mesh_theme_mode"])
        assertEquals(ThemeMode.LIGHT, store.loadThemeMode())

        // Act & Assert invalid value fallback
        backing["mesh_theme_mode"] = "corrupted"
        assertEquals(ThemeMode.SYSTEM, store.loadThemeMode())
    }

    @Test
    fun canonicalDesignTokensMatchAdr030HexValues() {
        // Assert Light tokens
        assertEquals(0xFFF8FAFC.toInt(), MeshTokens.SurfaceBackground.toArgb())
        assertEquals(0xFFFFFFFF.toInt(), MeshTokens.SurfaceCard.toArgb())
        assertEquals(0xFFCBD5E1.toInt(), MeshTokens.SurfaceBorder.toArgb())
        assertEquals(0xFF0B57D0.toInt(), MeshTokens.BrandCobalt.toArgb())
        assertEquals(0xFF0D9488.toInt(), MeshTokens.BrandTeal.toArgb())
        assertEquals(0xFF16A34A.toInt(), MeshTokens.SemanticSuccess.toArgb())
        assertEquals(0xFFD97706.toInt(), MeshTokens.SemanticWarning.toArgb())
        assertEquals(0xFFDC2626.toInt(), MeshTokens.SemanticError.toArgb())
        assertEquals(0xFF6B7280.toInt(), MeshTokens.SemanticNeutral.toArgb())

        // Assert Dark tokens
        assertEquals(0xFF0F172A.toInt(), MeshTokens.SurfaceBackgroundDark.toArgb())
        assertEquals(0xFF1E293B.toInt(), MeshTokens.SurfaceCardDark.toArgb())
        assertEquals(0xFF334155.toInt(), MeshTokens.SurfaceBorderDark.toArgb())
        assertEquals(0xFF60A5FA.toInt(), MeshTokens.BrandSky.toArgb())
        assertEquals(0xFF2DD4BF.toInt(), MeshTokens.BrandTealLight.toArgb())
        assertEquals(0xFF4ADE80.toInt(), MeshTokens.SemanticSuccessDark.toArgb())
        assertEquals(0xFFFBBF24.toInt(), MeshTokens.SemanticWarningDark.toArgb())
        assertEquals(0xFFF87171.toInt(), MeshTokens.SemanticErrorDark.toArgb())
        assertEquals(0xFF9CA3AF.toInt(), MeshTokens.SemanticNeutralDark.toArgb())
    }

    @Test
    fun notificationColorForStateMapsAllDaemonStatesToSemanticHex() {
        assertEquals(
            0xFF16A34A.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.CONNECTED),
        )
        assertEquals(
            0xFFD97706.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.CONNECTING),
        )
        assertEquals(
            0xFFD97706.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.DEGRADED),
        )
        assertEquals(
            0xFFD97706.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.REAUTH_REQUIRED),
        )
        assertEquals(
            0xFFDC2626.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.REVOKED),
        )
        assertEquals(
            0xFFDC2626.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.SERVER_UPGRADE_REQUIRED),
        )
        assertEquals(
            0xFF6B7280.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.STOPPED),
        )
        assertEquals(
            0xFF6B7280.toInt(),
            MeshVpnService.notificationColorForState(MobileDaemonState.DEVICE_LOCKED),
        )
    }

    @Test
    fun canonicalDaemonStateLabelMapsAllEightStates() {
        assertEquals("Disconnected", canonicalDaemonStateLabel(MobileDaemonState.STOPPED))
        assertEquals(
            "Waiting for Unlock",
            canonicalDaemonStateLabel(MobileDaemonState.DEVICE_LOCKED),
        )
        assertEquals("Connecting", canonicalDaemonStateLabel(MobileDaemonState.CONNECTING))
        assertEquals("Connected", canonicalDaemonStateLabel(MobileDaemonState.CONNECTED))
        assertEquals("Degraded", canonicalDaemonStateLabel(MobileDaemonState.DEGRADED))
        assertEquals(
            "Re-auth Required",
            canonicalDaemonStateLabel(MobileDaemonState.REAUTH_REQUIRED),
        )
        assertEquals("Device Revoked", canonicalDaemonStateLabel(MobileDaemonState.REVOKED))
        assertEquals(
            "Attention Required",
            canonicalDaemonStateLabel(MobileDaemonState.SERVER_UPGRADE_REQUIRED),
        )
    }

    @Test
    fun androidCanonicalLabelNeverPrintsRawEnumAndUsesStringResForAllEightStates() {
        // Arrange
        val expectedRes =
            mapOf(
                MobileDaemonState.STOPPED to R.string.state_disconnected,
                MobileDaemonState.DEVICE_LOCKED to R.string.notif_waiting_unlock,
                MobileDaemonState.CONNECTING to R.string.state_connecting,
                MobileDaemonState.CONNECTED to R.string.state_connected,
                MobileDaemonState.DEGRADED to R.string.state_degraded,
                MobileDaemonState.REAUTH_REQUIRED to R.string.state_reauth_required,
                MobileDaemonState.REVOKED to R.string.state_revoked,
                MobileDaemonState.SERVER_UPGRADE_REQUIRED to R.string.state_error,
            )

        // Act & Assert
        assertEquals(8, MobileDaemonState.entries.size)
        for (state in MobileDaemonState.entries) {
            val label = canonicalDaemonStateLabel(state)
            assertNotEquals(state.name, label)
            assertEquals(expectedRes[state], daemonStateLabelRes(state))
        }
    }
}
