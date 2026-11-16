package dev.meshvpn.android.data.storage

import android.content.Context
import android.os.UserManager
import android.system.ErrnoException
import android.system.Os
import dev.meshvpn.android.data.diagnostics.SafeLogger
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import uniffi.mesh_mobile_ffi.MobileException
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

/**
 * Non-secret bootstrap summary parsed locally from `bootstrap.toml` for stopped-state UI rendering.
 */
data class StoredBootstrapSummary(
    val serverEndpoint: String,
    val tlsAuthMode: MobileTlsAuthMode,
    val activePin: String?,
    val nextPin: String?,
    val nodeId: String?,
    val nodeName: String?,
    val overlayIp: String?,
    val fqdn: String?,
)

interface DeviceUnlockChecker {
    fun isUserUnlocked(): Boolean
}

class AndroidDeviceUnlockChecker(
    private val context: Context,
) : DeviceUnlockChecker {
    override fun isUserUnlocked(): Boolean {
        val um = context.getSystemService(UserManager::class.java)
        return um?.isUserUnlocked ?: true
    }
}

/**
 * Private file storage under `context.noBackupFilesDir` (`0600`, zero backup, Direct-Boot safe).
 */
class PrivateStateFileStore(
    private val stateDirProvider: () -> File,
    private val deviceUnlockChecker: DeviceUnlockChecker,
    private val bootPrefsReader: (() -> Boolean)? = null,
    private val bootPrefsWriter: ((Boolean) -> Unit)? = null,
) {
    private val fileLock = Any()

    constructor(context: Context) : this(
        stateDirProvider = { context.noBackupFilesDir },
        deviceUnlockChecker = AndroidDeviceUnlockChecker(context),
        bootPrefsReader = {
            val dpContext = context.createDeviceProtectedStorageContext()
            dpContext
                .getSharedPreferences(DEVICE_PROTECTED_PREFS, Context.MODE_PRIVATE)
                .getBoolean(KEY_ALWAYS_ON_HINT, false)
        },
        bootPrefsWriter = { enabled ->
            val dpContext = context.createDeviceProtectedStorageContext()
            dpContext
                .getSharedPreferences(DEVICE_PROTECTED_PREFS, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_ALWAYS_ON_HINT, enabled)
                .apply()
        },
    )

    fun isDeviceUnlocked(): Boolean = deviceUnlockChecker.isUserUnlocked()

    fun getAlwaysOnHint(): Boolean = bootPrefsReader?.invoke() ?: false

    fun setAlwaysOnHint(enabled: Boolean) {
        bootPrefsWriter?.invoke(enabled)
    }

    fun stateDirectory(): File {
        ensureUnlocked()
        val dir = stateDirProvider()
        if (!dir.exists() && !dir.mkdirs()) {
            throw MobileException.Internal(
                errorCode = "E_INTERNAL",
                message = "Unable to initialize noBackupFilesDir",
            )
        }
        return dir
    }

    fun hasEnrolledIdentity(): Boolean {
        if (!isDeviceUnlocked()) {
            return false
        }
        synchronized(fileLock) {
            val dir = stateDirProvider()
            val sealed = File(dir, SEALED_IDENTITY_FILE)
            val bootstrap = File(dir, BOOTSTRAP_FILE)
            return sealed.exists() && bootstrap.exists()
        }
    }

    fun loadStateFile(fileName: String): ByteArray? {
        val target = resolveSafeFile(fileName)
        synchronized(fileLock) {
            if (!target.exists()) {
                return null
            }
            return try {
                target.readBytes()
            } catch (err: IOException) {
                throw MobileException
                    .Internal(
                        errorCode = "E_INTERNAL",
                        message = "Failed reading state file $fileName: ${err.message}",
                    ).apply { initCause(err) }
            }
        }
    }

    fun saveStateFile(
        fileName: String,
        content: ByteArray,
    ) {
        val target = resolveSafeFile(fileName)
        synchronized(fileLock) {
            writeAtomic0600(target, content)
        }
    }

    fun deleteStateFile(fileName: String) {
        val target = resolveSafeFile(fileName)
        synchronized(fileLock) {
            if (target.exists() && !target.delete()) {
                throw MobileException.Internal(
                    errorCode = "E_INTERNAL",
                    message = "Failed deleting state file $fileName",
                )
            }
        }
    }

    fun clearAllMeshState() {
        ensureUnlocked()
        synchronized(fileLock) {
            val dir = stateDirProvider()
            for (name in KNOWN_STATE_FILES) {
                val f = File(dir, name)
                if (f.exists() && !f.delete()) {
                    SafeLogger.w(TAG, "Failed deleting state file $name during reset")
                }
            }
            val diagDir = File(dir, "diagnostics")
            if (diagDir.exists()) {
                diagDir.deleteRecursively()
            }
        }
        setAlwaysOnHint(false)
    }

    fun readBootstrapSummary(): StoredBootstrapSummary? {
        if (!isDeviceUnlocked()) {
            return null
        }
        val bytes =
            try {
                loadStateFile(BOOTSTRAP_FILE) ?: return null
            } catch (err: MobileException) {
                SafeLogger.w(TAG, "Could not load bootstrap summary", err)
                return null
            }
        return parseBootstrapSummary(bytes.toString(Charsets.UTF_8))
    }

    fun readCachedStatusJson(): String? {
        if (!isDeviceUnlocked()) {
            return null
        }
        val bytes =
            try {
                loadStateFile(STATUS_SNAPSHOT_FILE) ?: return null
            } catch (_: MobileException) {
                return null
            }
        return bytes.toString(Charsets.UTF_8)
    }

    internal fun writeAtomic0600(
        target: File,
        content: ByteArray,
    ) {
        val parent = ensureStateParentDir(target)
        val tmp = File(parent, ".${target.name}.tmp")
        try {
            writeAndSyncTempFile(tmp, content)
            enforcePrivatePermissions(tmp)
            replaceTargetFile(tmp, target)
            enforcePrivatePermissions(target)
        } catch (err: IOException) {
            if (tmp.exists()) {
                tmp.delete()
            }
            throw MobileException
                .Internal(
                    errorCode = "E_INTERNAL",
                    message = "Failed persisting state file ${target.name}: ${err.message}",
                ).apply { initCause(err) }
        }
    }

    private fun ensureStateParentDir(target: File): File {
        val parent =
            target.parentFile ?: throw MobileException.Internal(
                errorCode = "E_INTERNAL",
                message = "State file missing parent directory",
            )
        if (!parent.exists() && !parent.mkdirs()) {
            throw MobileException.Internal(
                errorCode = "E_INTERNAL",
                message = "Failed creating state parent directory",
            )
        }
        return parent
    }

    private fun writeAndSyncTempFile(
        tmp: File,
        content: ByteArray,
    ) {
        FileOutputStream(tmp).use { fos ->
            fos.write(content)
            fos.flush()
            fos.fd.sync()
        }
    }

    private fun replaceTargetFile(
        tmp: File,
        target: File,
    ) {
        if (!tmp.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                throw IOException("Could not replace existing state file ${target.name}")
            }
            if (!tmp.renameTo(target)) {
                throw IOException("Atomic rename failed for ${target.name}")
            }
        }
    }

    private fun enforcePrivatePermissions(file: File) {
        try {
            Os.chmod(file.absolutePath, MODE_0600)
        } catch (_: ErrnoException) {
            // Host JVM unit tests without Bionic/POSIX chmod support can ignore.
        } catch (_: LinkageError) {
            // Host JVM unit tests do not load Android android.system.Os.
        }
    }

    private fun ensureUnlocked() {
        if (!deviceUnlockChecker.isUserUnlocked()) {
            throw MobileException.DeviceLocked(
                errorCode = "E_DEVICE_LOCKED",
                message = "Direct Boot locked: credential-encrypted storage is unavailable",
            )
        }
    }

    private fun resolveSafeFile(fileName: String): File {
        ensureUnlocked()
        if (!SAFE_FILENAME_REGEX.matches(fileName) || fileName.contains("..")) {
            throw MobileException.InvalidArgument(
                errorCode = "E_INVALID_ARG",
                message = "Disallowed state file name",
            )
        }
        return File(stateDirectory(), fileName)
    }

    companion object {
        private const val TAG = "PrivateStateFileStore"
        private const val DEVICE_PROTECTED_PREFS = "mesh_boot_prefs"
        private const val KEY_ALWAYS_ON_HINT = "always_on_hint"
        private const val MODE_0600 = 384 // 0600 octal

        const val SEALED_IDENTITY_FILE = "identity.sealed.bin"
        const val DEK_FILE = "dek.enc"
        const val BOOTSTRAP_FILE = "bootstrap.toml"
        const val NETMAP_CACHE_FILE = "netmap-cache.json"
        const val STATUS_SNAPSHOT_FILE = "status-snapshot.json"

        private val KNOWN_STATE_FILES =
            listOf(
                SEALED_IDENTITY_FILE,
                DEK_FILE,
                BOOTSTRAP_FILE,
                NETMAP_CACHE_FILE,
                STATUS_SNAPSHOT_FILE,
            )

        private val SAFE_FILENAME_REGEX = Regex("^[a-zA-Z0-9._-]{1,64}$")

        fun parseBootstrapSummary(tomlText: String): StoredBootstrapSummary? {
            val kv = mutableMapOf<String, String>()
            for (rawLine in tomlText.lineSequence()) {
                parseTomlKeyValue(rawLine)?.let { (k, v) -> kv[k] = v }
            }
            val endpoint = kv["server_endpoint"] ?: return null
            val tlsMode =
                when (kv["tls_auth_mode"]?.lowercase()) {
                    "system_ca" -> MobileTlsAuthMode.SYSTEM_CA
                    else -> MobileTlsAuthMode.SPKI_PIN
                }
            return StoredBootstrapSummary(
                serverEndpoint = endpoint,
                tlsAuthMode = tlsMode,
                activePin = kv["active_pin"],
                nextPin = kv["next_pin"],
                nodeId = kv["node_id"],
                nodeName = kv["node_name"],
                overlayIp = kv["overlay_ip"],
                fqdn = kv["fqdn"],
            )
        }

        private fun parseTomlKeyValue(rawLine: String): Pair<String, String>? {
            val line = rawLine.trim()
            val eqIdx = line.indexOf('=')
            val isCommentOrHeader = line.isEmpty() || line.startsWith("#") || line.startsWith("[")
            if (isCommentOrHeader || eqIdx <= 0) {
                return null
            }
            val key = line.substring(0, eqIdx).trim()
            val rawVal = line.substring(eqIdx + 1).trim()
            val isQuoted =
                rawVal.startsWith("\"") &&
                    rawVal.endsWith("\"") &&
                    rawVal.length >= 2
            val unquoted =
                if (isQuoted) {
                    rawVal.substring(1, rawVal.length - 1)
                } else {
                    rawVal
                }
            return key to unquoted
        }
    }
}
