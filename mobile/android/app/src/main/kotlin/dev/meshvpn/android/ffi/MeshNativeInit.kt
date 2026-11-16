package dev.meshvpn.android.ffi

import android.content.Context
import dev.meshvpn.android.data.diagnostics.SafeLogger
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Idempotent Android JNI initializer for `rustls-platform-verifier` (`ADR-014`).
 *
 * Matches the exact exported Rust JNI symbol in `crates/mesh-sys/src/jni_android.rs`:
 * `Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier`.
 */
object MeshNativeInit {
    private const val TAG = "MeshNativeInit"
    private const val NATIVE_LIB_NAME = "mesh_mobile_ffi"

    private val lock = Any()
    private val nativeLoaded = AtomicBoolean(false)
    private val verifierReady = AtomicBoolean(false)

    external fun initPlatformVerifier(context: Context): Boolean

    fun ensureInitialized(context: Context): Boolean {
        if (verifierReady.get()) {
            return true
        }
        synchronized(lock) {
            if (verifierReady.get()) {
                return true
            }
            if (!nativeLoaded.get()) {
                val loaded = try {
                    System.loadLibrary(NATIVE_LIB_NAME)
                    true
                } catch (err: UnsatisfiedLinkError) {
                    SafeLogger.e(TAG, "Failed loading native library $NATIVE_LIB_NAME", err)
                    false
                } catch (err: SecurityException) {
                    SafeLogger.e(TAG, "Security error loading $NATIVE_LIB_NAME", err)
                    false
                }
                if (!loaded) {
                    return false
                }
                nativeLoaded.set(true)
            }

            val appContext = context.applicationContext ?: context
            val initialized = try {
                initPlatformVerifier(appContext)
            } catch (err: UnsatisfiedLinkError) {
                SafeLogger.e(TAG, "JNI symbol initPlatformVerifier unavailable", err)
                false
            }
            if (initialized) {
                verifierReady.set(true)
            } else {
                SafeLogger.w(TAG, "initPlatformVerifier returned false")
            }
            return initialized
        }
    }

    fun isNativeLoaded(): Boolean = nativeLoaded.get()

    fun isPlatformVerifierReady(): Boolean = verifierReady.get()
}
