package dev.meshvpn.android.di

import android.content.Context
import android.os.Build
import dev.meshvpn.android.data.diagnostics.BugreportShareManager
import dev.meshvpn.android.data.keystore.AndroidKeystoreDekManager
import dev.meshvpn.android.data.network.AndroidUnderlayStateCollector
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import dev.meshvpn.android.ffi.MeshFfiGateway
import dev.meshvpn.android.ffi.MeshNativeInit
import dev.meshvpn.android.ffi.UniFfiMeshGateway
import dev.meshvpn.android.vpn.MeshSessionRepository
import java.util.concurrent.atomic.AtomicReference

/**
 * Lightweight manual dependency container keeping RAM footprint below the 48 MiB Android budget.
 */
class MeshAppContainer(
    private val appContext: Context,
) {
    private val lockdownCheckerRef = AtomicReference<() -> Boolean>({ false })

    val ffiGateway: MeshFfiGateway by lazy { UniFfiMeshGateway() }
    val stateStore: PrivateStateFileStore by lazy { PrivateStateFileStore(appContext) }
    val dekManager: AndroidKeystoreDekManager by lazy { AndroidKeystoreDekManager(stateStore) }
    val bugreportManager: BugreportShareManager by lazy { BugreportShareManager(appContext) }
    val underlayCollector: AndroidUnderlayStateCollector by lazy {
        AndroidUnderlayStateCollector(appContext) { lockdownCheckerRef.get().invoke() }
    }
    val sessionRepository: MeshSessionRepository by lazy {
        MeshSessionRepository(
            ffiGateway = ffiGateway,
            stateStore = stateStore,
            dekManager = dekManager,
            bugreportManager = bugreportManager,
            underlayProvider = { underlayCollector.collectUnderlayState() },
            nativeInitializer = { MeshNativeInit.ensureInitialized(appContext) },
            defaultNodeNameProvider = { sanitizeDeviceModelToNodeName() },
        )
    }

    fun attachVpnLockdownChecker(checker: () -> Boolean) {
        lockdownCheckerRef.set(checker)
    }

    private fun sanitizeDeviceModelToNodeName(): String {
        val raw = "${Build.MANUFACTURER}-${Build.MODEL}".lowercase()
        val sb = StringBuilder(63)
        var prevDash = true
        for (ch in raw) {
            if (sb.length >= 63) {
                break
            }
            if (ch in 'a'..'z' || ch in '0'..'9') {
                sb.append(ch)
                prevDash = false
            } else if (!prevDash && sb.isNotEmpty()) {
                sb.append('-')
                prevDash = true
            }
        }
        while (sb.endsWith("-")) {
            sb.deleteCharAt(sb.length - 1)
        }
        return if (sb.isEmpty()) "android-node" else sb.toString()
    }
}
