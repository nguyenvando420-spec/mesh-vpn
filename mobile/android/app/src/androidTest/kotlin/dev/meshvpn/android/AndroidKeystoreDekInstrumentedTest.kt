package dev.meshvpn.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.meshvpn.android.data.keystore.AndroidKeystoreDekManager
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidKeystoreDekInstrumentedTest {
    @Test
    fun keystoreAes256GcmWrapsAndUnwraps32ByteDekInNoBackupDir() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = PrivateStateFileStore(context)
        val manager = AndroidKeystoreDekManager(store)
        manager.resetKeystoreAndDek()

        val first = manager.loadOrCreatePlatformDek()
        val second = manager.loadOrCreatePlatformDek()
        try {
            assertEquals(32, first.size)
            assertArrayEquals(first, second)
            val dekFile = File(context.noBackupFilesDir, PrivateStateFileStore.DEK_FILE)
            assertTrue(dekFile.exists())
            assertFalse(File(context.filesDir, PrivateStateFileStore.DEK_FILE).exists())
        } finally {
            first.fill(0)
            second.fill(0)
            manager.resetKeystoreAndDek()
        }
    }
}
