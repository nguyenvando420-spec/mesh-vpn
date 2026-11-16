package dev.meshvpn.android.data.keystore

import dev.meshvpn.android.data.storage.DeviceUnlockChecker
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import java.io.File
import javax.crypto.AEADBadTagException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.mesh_mobile_ffi.MobileException

private class FakeKeyWrapBackend : KeyWrapBackend {
    private val aliases = mutableSetOf<String>()

    override fun hasWrappingKey(alias: String): Boolean = alias in aliases

    override fun createWrappingKey(alias: String) {
        aliases.add(alias)
    }

    override fun wrapDek(
        alias: String,
        plainDek: ByteArray,
    ): ByteArray {
        check(alias in aliases) { "Missing alias $alias" }
        return plainDek.map { (it.toInt() xor 0x5A).toByte() }.toByteArray()
    }

    override fun unwrapDek(
        alias: String,
        wrappedBlob: ByteArray,
    ): ByteArray {
        if (alias !in aliases) {
            throw AEADBadTagException("Key alias removed")
        }
        if (wrappedBlob.size != 32) {
            throw AEADBadTagException("Corrupted dek.enc")
        }
        return wrappedBlob.map { (it.toInt() xor 0x5A).toByte() }.toByteArray()
    }

    override fun deleteWrappingKey(alias: String) {
        aliases.remove(alias)
    }
}

class DirectBootAndKeystoreTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun keystoreDekLockedDeviceThrowsDeviceLockedBeforeKeystoreAccess() {
        // Arrange
        var unlocked = false
        val stateDir = tempFolder.newFolder("no_backup")
        val store =
            PrivateStateFileStore(
                stateDirProvider = { stateDir },
                deviceUnlockChecker = DeviceUnlockChecker { unlocked },
            )
        val dekManager = AndroidKeystoreDekManager(store, FakeKeyWrapBackend())

        // Act + Assert
        assertThrows(MobileException.DeviceLocked::class.java) {
            dekManager.loadOrCreatePlatformDek()
        }
        unlocked = true
        val first = dekManager.loadOrCreatePlatformDek()
        val second = dekManager.loadOrCreatePlatformDek()
        assertEquals(32, first.size)
        assertArrayEquals(first, second)
    }

    @Test
    fun keystoreDekInvalidatedKeyFailsClosedWithoutOverwriting() {
        // Arrange
        val stateDir = tempFolder.newFolder("no_backup_invalidated")
        val store =
            PrivateStateFileStore(
                stateDirProvider = { stateDir },
                deviceUnlockChecker = DeviceUnlockChecker { true },
            )
        val backend = FakeKeyWrapBackend()
        val dekManager = AndroidKeystoreDekManager(store, backend)
        val originalDek = dekManager.loadOrCreatePlatformDek()
        val originalDekFileBytes = File(stateDir, PrivateStateFileStore.DEK_FILE).readBytes()

        // Act: simulate Keystore KEK invalidation after lockscreen clear.
        backend.deleteWrappingKey(AndroidKeystoreDekManager.KEYSTORE_ALIAS)

        // Assert: fail closed and do NOT overwrite dek.enc with a replacement key.
        assertThrows(MobileException.KeystoreInvalidated::class.java) {
            dekManager.loadOrCreatePlatformDek()
        }
        assertArrayEquals(
            originalDekFileBytes,
            File(stateDir, PrivateStateFileStore.DEK_FILE).readBytes(),
        )
        originalDek.fill(0)
    }

    @Test
    fun keystoreDekMissingDekWithExistingIdentityFailsClosed() {
        // Arrange
        val stateDir = tempFolder.newFolder("no_backup_orphan_identity")
        val store =
            PrivateStateFileStore(
                stateDirProvider = { stateDir },
                deviceUnlockChecker = DeviceUnlockChecker { true },
            )
        store.saveStateFile(PrivateStateFileStore.SEALED_IDENTITY_FILE, byteArrayOf(1, 2, 3))
        val dekManager = AndroidKeystoreDekManager(store, FakeKeyWrapBackend())

        // Act + Assert
        assertThrows(MobileException.KeystoreInvalidated::class.java) {
            dekManager.loadOrCreatePlatformDek()
        }
        assertFalse(File(stateDir, PrivateStateFileStore.DEK_FILE).exists())
        assertTrue(File(stateDir, PrivateStateFileStore.SEALED_IDENTITY_FILE).exists())
    }

    @Test
    fun keystoreUsePlatformDekZeroizesTransientBuffer() {
        // Arrange
        val stateDir = tempFolder.newFolder("no_backup_zeroize")
        val store =
            PrivateStateFileStore(
                stateDirProvider = { stateDir },
                deviceUnlockChecker = DeviceUnlockChecker { true },
            )
        val dekManager = AndroidKeystoreDekManager(store, FakeKeyWrapBackend())
        var capturedRef: ByteArray? = null

        // Act
        dekManager.usePlatformDek { bytes ->
            capturedRef = bytes
            assertTrue(bytes.any { it.toInt() != 0 })
        }

        // Assert
        assertTrue(capturedRef?.all { it.toInt() == 0 } == true)
    }
}
