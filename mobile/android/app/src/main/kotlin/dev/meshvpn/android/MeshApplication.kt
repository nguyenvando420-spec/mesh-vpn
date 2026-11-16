package dev.meshvpn.android

import android.app.Application
import dev.meshvpn.android.di.MeshAppContainer
import dev.meshvpn.android.ffi.MeshNativeInit

/**
 * Application entrypoint guaranteeing idempotent initialization of `libmesh_mobile_ffi.so` and
 * `MeshNativeInit.initPlatformVerifier(applicationContext)` before Rust TLS calls (`ADR-014`).
 */
class MeshApplication : Application() {
    val container: MeshAppContainer by lazy { MeshAppContainer(applicationContext) }

    override fun onCreate() {
        super.onCreate()
        MeshNativeInit.ensureInitialized(applicationContext)
    }
}
