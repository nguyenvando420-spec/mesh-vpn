package dev.meshvpn.android.vpn

import dev.meshvpn.android.data.diagnostics.SafeLogger
import dev.meshvpn.android.data.keystore.AndroidKeystoreDekManager
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import dev.meshvpn.android.ffi.MobileEngineHandle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import uniffi.mesh_mobile_ffi.MobilePlatformWarning
import uniffi.mesh_mobile_ffi.MobileStatusSnapshot
import uniffi.mesh_mobile_ffi.MobileTunnelNetworkConfig
import uniffi.mesh_mobile_ffi.MobileUnderlayState
import uniffi.mesh_mobile_ffi.PlatformNetworkBridge

/**
 * Callback interface invoked by [AndroidPlatformBridge] to build & establish the Android TUN FD.
 * Implementations must return the detached raw FD (via `ParcelFileDescriptor.detachFd()`) or `null`
 * if VPN permission was revoked / `Builder.establish()` returned `null`.
 */
fun interface TunEstablisher {
    fun establishDetachedTunFd(config: MobileTunnelNetworkConfig): Int?
}

/**
 * UniFFI [PlatformNetworkBridge] implementation for Android (`ADR-014`, `ADR-015`, `ADR-017`).
 *
 * Non-reentrancy & zero-lock invariants:
 * - [protectSocket] calls `VpnService.protect(fd)` directly without holding any Kotlin lock.
 * - [onRouteChanged] dispatches asynchronously onto [routeScope] and completes via
 *   `MobileEngine.completeRouteChange` without synchronously re-entering Rust inside the callback.
 * - [onStatusChanged] and [onPlatformWarning] perform O(1) non-blocking emission.
 */
class AndroidPlatformBridge(
    private val socketProtector: (Int) -> Boolean,
    private val tunEstablisher: TunEstablisher?,
    private val engineProvider: () -> MobileEngineHandle?,
    private val routeScope: CoroutineScope?,
    private val underlayProvider: () -> MobileUnderlayState,
    private val dekManager: AndroidKeystoreDekManager,
    private val stateStore: PrivateStateFileStore,
    private val statusSink: (MobileStatusSnapshot) -> Unit,
    private val warningSink: (MobilePlatformWarning) -> Unit,
) : PlatformNetworkBridge {
    private val routeMutex = Mutex()

    override fun protectSocket(rawFd: Int): Boolean {
        if (rawFd < 0) {
            return false
        }
        return try {
            socketProtector(rawFd)
        } catch (err: Throwable) {
            SafeLogger.w(TAG, "VpnService.protect($rawFd) threw exception; failing closed", err)
            false
        }
    }

    override fun onTunPackets(packets: List<ByteArray>) {
        // Android uses detached raw `android_tun_fd` directly via Tokio AsyncFd in Rust.
    }

    override fun onRouteChanged(opId: ULong, config: MobileTunnelNetworkConfig) {
        val scope = routeScope
        val establisher = tunEstablisher
        if (scope == null || establisher == null) {
            engineProvider()?.completeRouteChange(
                opId = opId,
                ok = false,
                newAndroidTunFd = null,
                errorMessage = "TUN establisher is unavailable in enrollment-only context",
            )
            return
        }

        scope.launch(Dispatchers.IO) {
            routeMutex.withLock {
                var detachedFd: Int? = null
                var errorMessage: String? = null
                val ok = try {
                    val fd = establisher.establishDetachedTunFd(config)
                    if (fd != null && fd >= 0) {
                        detachedFd = fd
                        true
                    } else {
                        errorMessage = "VpnService.Builder.establish() returned null"
                        false
                    }
                } catch (err: Throwable) {
                    SafeLogger.e(TAG, "Failed configuring VpnService TUN route op=$opId", err)
                    errorMessage = err.message ?: "Failed configuring Android TUN interface"
                    false
                }

                val engine = engineProvider()
                if (engine != null) {
                    engine.completeRouteChange(
                        opId = opId,
                        ok = ok,
                        newAndroidTunFd = detachedFd,
                        errorMessage = errorMessage,
                    )
                } else {
                    SafeLogger.w(TAG, "MobileEngine disappeared before completeRouteChange($opId)")
                }
            }
        }
    }

    override fun onStatusChanged(status: MobileStatusSnapshot) {
        statusSink(status)
    }

    override fun onPlatformWarning(warning: MobilePlatformWarning) {
        warningSink(warning)
    }

    override fun queryUnderlayState(): MobileUnderlayState = underlayProvider()

    override fun loadOrCreatePlatformDek(): ByteArray = dekManager.loadOrCreatePlatformDek()

    override fun loadStateFile(fileName: String): ByteArray? = stateStore.loadStateFile(fileName)

    override fun saveStateFile(fileName: String, content: ByteArray) {
        stateStore.saveStateFile(fileName, content)
    }

    override fun deleteStateFile(fileName: String) {
        stateStore.deleteStateFile(fileName)
    }

    companion object {
        private const val TAG = "AndroidPlatformBridge"
    }
}
