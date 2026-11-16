package dev.meshvpn.android

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.meshvpn.android.ffi.MeshNativeInit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ManifestAndNativeInitInstrumentedTest {
    @Test
    fun manifestDisablesBackupAndBlocksMeshDeepLinkHijacking() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val allowBackup =
            (context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
        assertEquals(false, allowBackup)

        val deepLinkProbe = Intent(Intent.ACTION_VIEW, Uri.parse("mesh://join?v=1"))
        val handlers = context.packageManager.queryIntentActivities(deepLinkProbe, 0)
        val selfHandlers = handlers.filter {
            it.activityInfo.packageName == context.packageName
        }
        assertTrue(selfHandlers.isEmpty())
    }

    @Test
    fun nativeInitIsIdempotentAcrossRepeatedCalls() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(MeshNativeInit.ensureInitialized(context))
        assertTrue(MeshNativeInit.ensureInitialized(context))
    }
}
