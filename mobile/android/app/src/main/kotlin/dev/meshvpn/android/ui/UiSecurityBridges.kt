package dev.meshvpn.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import dev.meshvpn.android.data.diagnostics.SafeLogger
import dev.meshvpn.android.di.MeshAppContainer

interface ClipboardAccess {
    fun readPrimaryTextAndClear(): String?
}

/**
 * Reads primary clipboard text during onboarding paste and immediately scrubs clipboard history
 * (`HR-MOB-G2-04`) to minimize exposure of `mesh://join?...` pre-auth credentials.
 */
class AndroidClipboardAccess(
    private val context: Context,
) : ClipboardAccess {
    override fun readPrimaryTextAndClear(): String? {
        val manager = context.getSystemService(ClipboardManager::class.java) ?: return null
        return try {
            val item = manager.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)
            item
                ?.coerceToText(context)
                ?.toString()
                ?.trim()
                ?.takeIf { it.isNotEmpty() }
        } finally {
            clearClipboardNow(manager)
        }
    }

    private fun clearClipboardNow(manager: ClipboardManager) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                manager.clearPrimaryClip()
            } else {
                manager.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        } catch (err: SecurityException) {
            SafeLogger.w("ClipboardAccess", "Unable to clear system clipboard", err)
        }
    }
}

/**
 * Lifecycle bridge letting a surviving [MeshMainViewModel] invoke the active Activity's
 * [BiometricAuthenticator] without retaining an Activity reference across configuration changes.
 */
class ActivityBiometricBridge {
    @Volatile
    private var delegate: BiometricAuthenticator? = null

    fun attach(authenticator: BiometricAuthenticator) {
        delegate = authenticator
    }

    fun detach() {
        delegate = null
    }

    suspend fun authenticate(
        title: String,
        subtitle: String,
        negativeButtonText: String,
    ): BiometricGateResult {
        val current =
            delegate
                ?: return BiometricGateResult.Unavailable("Authentication UI is not foregrounded.")
        return current.authenticateAdminAction(title, subtitle, negativeButtonText)
    }
}

class MeshMainViewModelFactory(
    private val appContainer: MeshAppContainer,
    private val clipboardAccess: ClipboardAccess,
    private val authRequester: suspend (AdminAuthPurpose) -> BiometricGateResult,
) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T =
        MeshMainViewModel(
            sessionRepository = appContainer.sessionRepository,
            ffiGateway = appContainer.ffiGateway,
            clipboardAccess = clipboardAccess,
            authRequester = authRequester,
            cleanupDiagnostics = { appContainer.bugreportManager.cleanupAllDiagnosticArtifacts() },
        ) as T
}
