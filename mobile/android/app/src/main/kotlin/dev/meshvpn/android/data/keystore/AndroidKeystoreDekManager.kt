package dev.meshvpn.android.data.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import dev.meshvpn.android.data.diagnostics.SafeLogger
import dev.meshvpn.android.data.storage.PrivateStateFileStore
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.mesh_mobile_ffi.MobileException

interface KeyWrapBackend {
    fun hasWrappingKey(alias: String): Boolean
    fun createWrappingKey(alias: String)
    fun wrapDek(alias: String, plainDek: ByteArray): ByteArray
    fun unwrapDek(alias: String, wrappedBlob: ByteArray): ByteArray
    fun deleteWrappingKey(alias: String)
}

/**
 * Hardware-backed `AndroidKeyStore` AES-256-GCM key wrapper (`US-082`, `ADR-017`).
 *
 * Wraps and unwraps the 32-byte Master DEK directly without legacy encrypted preference wrappers.
 */
class AndroidKeyStoreBackend : KeyWrapBackend {
    override fun hasWrappingKey(alias: String): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.containsAlias(alias)
    }

    override fun createWrappingKey(alias: String) {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(AES_KEY_BITS)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .build()
        generator.init(spec)
        generator.generateKey()
    }

    override fun wrapDek(alias: String, plainDek: ByteArray): ByteArray {
        val key = loadSecretKey(alias)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(DEK_AAD)
        val iv = cipher.iv
        require(iv.size == GCM_IV_LEN) { "Unexpected GCM IV length ${iv.size}" }
        val ciphertext = cipher.doFinal(plainDek)
        val out = ByteArray(MAGIC_HEADER.size + GCM_IV_LEN + ciphertext.size)
        MAGIC_HEADER.copyInto(out, destinationOffset = 0)
        iv.copyInto(out, destinationOffset = MAGIC_HEADER.size)
        ciphertext.copyInto(out, destinationOffset = MAGIC_HEADER.size + GCM_IV_LEN)
        return out
    }

    override fun unwrapDek(alias: String, wrappedBlob: ByteArray): ByteArray {
        if (wrappedBlob.size < MAGIC_HEADER.size + GCM_IV_LEN + GCM_TAG_LEN) {
            throw AEADBadTagException("Wrapped DEK blob truncated")
        }
        val header = wrappedBlob.copyOfRange(0, MAGIC_HEADER.size)
        if (!header.contentEquals(MAGIC_HEADER)) {
            throw AEADBadTagException("Invalid wrapped DEK magic header")
        }
        val iv = wrappedBlob.copyOfRange(MAGIC_HEADER.size, MAGIC_HEADER.size + GCM_IV_LEN)
        val ciphertext = wrappedBlob.copyOfRange(MAGIC_HEADER.size + GCM_IV_LEN, wrappedBlob.size)
        val key = loadSecretKey(alias)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        cipher.updateAAD(DEK_AAD)
        return cipher.doFinal(ciphertext)
    }

    override fun deleteWrappingKey(alias: String) {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias)
            }
        } catch (err: GeneralSecurityException) {
            SafeLogger.w(TAG, "Unable to delete Keystore alias", err)
        }
    }

    private fun loadSecretKey(alias: String): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry
            ?: throw KeyPermanentlyInvalidatedException("AndroidKeyStore alias $alias is missing")
        return entry.secretKey
    }

    companion object {
        private const val TAG = "AndroidKeyStoreBackend"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val AES_KEY_BITS = 256
        private const val GCM_IV_LEN = 12
        private const val GCM_TAG_BITS = 128
        private const val GCM_TAG_LEN = 16
        private val MAGIC_HEADER = byteArrayOf(
            'S'.code.toByte(),
            'D'.code.toByte(),
            'K'.code.toByte(),
            '1'.code.toByte(),
        )
        private val DEK_AAD = "mesh-android-dek-v1".toByteArray(Charsets.UTF_8)
    }
}

/**
 * Manages the 32-byte Master DEK sealed in `context.noBackupFilesDir/dek.enc` by the
 * `AndroidKeyStore` AES-256-GCM key (`mesh_identity_kek_v1`).
 *
 * Fail-closed invariants (`US-082 AC3`):
 * - Never generates a replacement DEK when `dek.enc` or `identity.sealed.bin` already exists
 *   but cannot be decrypted.
 * - Throws [MobileException.DeviceLocked] before Direct Boot first unlock.
 * - Throws [MobileException.KeystoreInvalidated] if the KEK was wiped or `dek.enc` is corrupt.
 */
class AndroidKeystoreDekManager(
    private val stateStore: PrivateStateFileStore,
    private val keyWrapBackend: KeyWrapBackend = AndroidKeyStoreBackend(),
    private val random: SecureRandom = SecureRandom(),
) {
    private val lock = Any()

    /**
     * Loads the existing 32-byte DEK or generates/wraps a new one on first enrollment.
     * Callers bridging across FFI must zeroize transient copies immediately in `finally`.
     */
    fun loadOrCreatePlatformDek(): ByteArray {
        if (!stateStore.isDeviceUnlocked()) {
            throw MobileException.DeviceLocked(
                errorCode = "E_DEVICE_LOCKED",
                message = "Device locked before first unlock; Android Keystore DEK unavailable",
            )
        }
        synchronized(lock) {
            val stateDir = stateStore.stateDirectory()
            val dekFile = File(stateDir, PrivateStateFileStore.DEK_FILE)
            val sealedIdentityFile = File(stateDir, PrivateStateFileStore.SEALED_IDENTITY_FILE)

            if (dekFile.exists()) {
                return unwrapExistingDek(dekFile)
            }

            if (sealedIdentityFile.exists()) {
                throw MobileException.KeystoreInvalidated(
                    errorCode = "E_KEYSTORE_INVALIDATED",
                    message = "dek.enc missing while identity.sealed.bin exists; re-enroll",
                )
            }

            return generateAndSealFreshDek()
        }
    }

    /**
     * Executes [block] with an unwrapped DEK and guarantees zeroization of the local DEK buffer
     * in `finally` (`HR-MOB-G2-03`).
     */
    fun <T> usePlatformDek(block: (ByteArray) -> T): T {
        val dek = loadOrCreatePlatformDek()
        return try {
            block(dek)
        } finally {
            dek.fill(0)
        }
    }

    fun resetKeystoreAndDek() {
        synchronized(lock) {
            if (stateStore.isDeviceUnlocked()) {
                try {
                    stateStore.deleteStateFile(PrivateStateFileStore.DEK_FILE)
                } catch (err: MobileException) {
                    SafeLogger.w(TAG, "Failed deleting dek.enc during reset", err)
                }
            }
            keyWrapBackend.deleteWrappingKey(KEYSTORE_ALIAS)
        }
    }

    private fun unwrapExistingDek(dekFile: File): ByteArray {
        if (!keyWrapBackend.hasWrappingKey(KEYSTORE_ALIAS)) {
            throw MobileException.KeystoreInvalidated(
                errorCode = "E_KEYSTORE_INVALIDATED",
                message = "Android Keystore key $KEYSTORE_ALIAS missing for existing dek.enc",
            )
        }
        val wrapped = try {
            dekFile.readBytes()
        } catch (err: Exception) {
            throw MobileException.KeystoreInvalidated(
                errorCode = "E_KEYSTORE_INVALIDATED",
                message = "Unable to read dek.enc: ${err.message}",
            )
        }
        val dek = try {
            keyWrapBackend.unwrapDek(KEYSTORE_ALIAS, wrapped)
        } catch (err: UserNotAuthenticatedException) {
            throw MobileException.DeviceLocked(
                errorCode = "E_DEVICE_LOCKED",
                message = "Keystore authentication required before unlock: ${err.message}",
            )
        } catch (err: KeyPermanentlyInvalidatedException) {
            throw MobileException.KeystoreInvalidated(
                errorCode = "E_KEYSTORE_INVALIDATED",
                message = "KeyPermanentlyInvalidatedException: ${err.message}",
            )
        } catch (err: AEADBadTagException) {
            throw MobileException.KeystoreInvalidated(
                errorCode = "E_KEYSTORE_INVALIDATED",
                message = "AEADBadTagException decrypting dek.enc: ${err.message}",
            )
        } catch (err: GeneralSecurityException) {
            throw MobileException.KeystoreInvalidated(
                errorCode = "E_KEYSTORE_INVALIDATED",
                message = "Keystore unwrap failed: ${err.message}",
            )
        } finally {
            wrapped.fill(0)
        }

        if (dek.size != DEK_SIZE_BYTES) {
            dek.fill(0)
            throw MobileException.KeystoreInvalidated(
                errorCode = "E_KEYSTORE_INVALIDATED",
                message = "Unwrapped DEK had invalid length ${dek.size}",
            )
        }
        return dek
    }

    private fun generateAndSealFreshDek(): ByteArray {
        val freshDek = ByteArray(DEK_SIZE_BYTES)
        var wrapped: ByteArray? = null
        try {
            random.nextBytes(freshDek)
            if (!keyWrapBackend.hasWrappingKey(KEYSTORE_ALIAS)) {
                keyWrapBackend.createWrappingKey(KEYSTORE_ALIAS)
            }
            val sealed = keyWrapBackend.wrapDek(KEYSTORE_ALIAS, freshDek)
            wrapped = sealed
            stateStore.saveStateFile(PrivateStateFileStore.DEK_FILE, sealed)
            return freshDek.copyOf()
        } catch (err: UserNotAuthenticatedException) {
            throw MobileException.DeviceLocked(
                errorCode = "E_DEVICE_LOCKED",
                message = "Keystore unavailable while device is locked: ${err.message}",
            )
        } catch (err: GeneralSecurityException) {
            throw MobileException.KeystoreInvalidated(
                errorCode = "E_KEYSTORE_INVALIDATED",
                message = "Failed creating or wrapping Android Keystore DEK: ${err.message}",
            )
        } finally {
            freshDek.fill(0)
            wrapped?.fill(0)
        }
    }

    companion object {
        private const val TAG = "AndroidKeystoreDekMgr"
        const val KEYSTORE_ALIAS = "mesh_identity_kek_v1"
        const val DEK_SIZE_BYTES = 32
    }
}
