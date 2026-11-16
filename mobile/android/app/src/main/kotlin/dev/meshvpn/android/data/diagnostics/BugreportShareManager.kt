package dev.meshvpn.android.data.diagnostics

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File
import java.io.IOException

interface BugreportShareOps {
    fun nextExportDestination(): File

    fun prepareShareUri(
        archiveFile: File,
        reportedSizeBytes: Long,
    ): BugreportShareManager.PreparedBugreport

    fun cleanupAllDiagnosticArtifacts()
}

/**
 * Coordinates bounded (`<= 1 MiB`) diagnostic `.tar` export under `noBackupFilesDir/diagnostics/`
 * and short-lived sharing via [FileProvider] from `cacheDir/shared-diagnostics/`.
 */
class BugreportShareManager(
    private val context: Context,
    private val clockMs: () -> Long = { System.currentTimeMillis() },
) : BugreportShareOps {
    data class PreparedBugreport(
        val shareUri: Uri?,
        val shareFile: File,
        val sourceArchiveFile: File,
        val sizeBytes: Long,
    )

    override fun nextExportDestination(): File {
        val dir = File(context.noBackupFilesDir, DIAGNOSTICS_DIR_NAME)
        if (!dir.exists() && !dir.mkdirs()) {
            throw IOException("Failed creating diagnostics directory")
        }
        cleanupOlderArchives(dir)
        val ts = clockMs()
        return File(dir, "mesh-bugreport-$ts.tar")
    }

    override fun prepareShareUri(
        archiveFile: File,
        reportedSizeBytes: Long,
    ): PreparedBugreport {
        if (!archiveFile.exists() || !archiveFile.isFile) {
            throw IOException("Exported bugreport archive does not exist")
        }
        val actualLen = archiveFile.length()
        if (actualLen <= 0L ||
            actualLen > MAX_BUGREPORT_BYTES ||
            reportedSizeBytes > MAX_BUGREPORT_BYTES
        ) {
            throw IOException("Bugreport archive size ($actualLen bytes) violates <= 1 MiB ceiling")
        }

        val shareDir = File(context.cacheDir, SHARED_DIAGNOSTICS_DIR_NAME)
        if (!shareDir.exists() && !shareDir.mkdirs()) {
            throw IOException("Failed creating shared diagnostics cache directory")
        }
        cleanupDirectoryFiles(shareDir)

        val stagedShareFile = File(shareDir, archiveFile.name)
        archiveFile.inputStream().use { input ->
            stagedShareFile.outputStream().use { output ->
                input.copyTo(output, bufferSize = COPY_BUFFER_BYTES)
                output.flush()
            }
        }
        // Delete primary export immediately once staged for share so retention stays minimal.
        if (!archiveFile.delete()) {
            SafeLogger.w("BugreportShare", "Could not delete temporary primary archive")
        }

        val authority = "${context.packageName}.fileprovider"
        val shareUri = FileProvider.getUriForFile(context, authority, stagedShareFile)
        return PreparedBugreport(
            shareUri = shareUri,
            shareFile = stagedShareFile,
            sourceArchiveFile = archiveFile,
            sizeBytes = actualLen,
        )
    }

    override fun cleanupAllDiagnosticArtifacts() {
        cleanupDirectoryFiles(File(context.noBackupFilesDir, DIAGNOSTICS_DIR_NAME))
        cleanupDirectoryFiles(File(context.cacheDir, SHARED_DIAGNOSTICS_DIR_NAME))
    }

    private fun cleanupOlderArchives(dir: File) {
        val now = clockMs()
        val files = dir.listFiles() ?: return
        for (file in files) {
            if (file.isFile && now - file.lastModified() > ARCHIVE_RETENTION_MS) {
                if (!file.delete()) {
                    SafeLogger.w("BugreportShare", "Failed deleting stale diagnostic archive")
                }
            }
        }
    }

    private fun cleanupDirectoryFiles(dir: File) {
        val files = dir.listFiles() ?: return
        for (file in files) {
            if (file.isFile && !file.delete()) {
                SafeLogger.w("BugreportShare", "Failed deleting diagnostic cache file")
            }
        }
    }

    companion object {
        const val DIAGNOSTICS_DIR_NAME = "diagnostics"
        const val SHARED_DIAGNOSTICS_DIR_NAME = "shared-diagnostics"
        const val MAX_BUGREPORT_BYTES = 1_048_576L
        private const val ARCHIVE_RETENTION_MS = 300_000L
        private const val COPY_BUFFER_BYTES = 8 * 1024
    }
}
