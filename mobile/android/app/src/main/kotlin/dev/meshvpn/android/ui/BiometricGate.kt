package dev.meshvpn.android.ui

import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.meshvpn.android.data.diagnostics.SafeLogger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

sealed interface BiometricGateResult {
    data object Authenticated : BiometricGateResult

    data object Cancelled : BiometricGateResult

    data class Unavailable(
        val reason: String,
    ) : BiometricGateResult
}

interface BiometricAuthenticator {
    suspend fun authenticateAdminAction(
        title: String,
        subtitle: String,
        negativeButtonText: String,
    ): BiometricGateResult
}

/**
 * Hardware-backed `BiometricPrompt` gate (`US-085 AC4`) accepting `BIOMETRIC_STRONG` or
 * device credential (`DEVICE_CREDENTIAL` on API 28+).
 */
class AndroidBiometricAuthenticator(
    private val activity: FragmentActivity,
) : BiometricAuthenticator {
    override suspend fun authenticateAdminAction(
        title: String,
        subtitle: String,
        negativeButtonText: String,
    ): BiometricGateResult =
        withContext(Dispatchers.Main.immediate) {
            val authenticators = supportedAuthenticators()
            val manager = BiometricManager.from(activity)
            val status = manager.canAuthenticate(authenticators)
            if (status != BiometricManager.BIOMETRIC_SUCCESS) {
                return@withContext mapAvailabilityError(status)
            }

            val infoBuilder =
                BiometricPrompt.PromptInfo
                    .Builder()
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    .setAllowedAuthenticators(authenticators)
            if ((authenticators and Authenticators.DEVICE_CREDENTIAL) == 0) {
                infoBuilder.setNegativeButtonText(negativeButtonText)
            }
            val promptInfo = infoBuilder.build()

            suspendCancellableCoroutine { continuation ->
                val resumed = AtomicBoolean(false)
                val callback =
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult,
                        ) {
                            if (resumed.compareAndSet(false, true) && continuation.isActive) {
                                continuation.resume(BiometricGateResult.Authenticated)
                            }
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            if (!resumed.compareAndSet(false, true) || !continuation.isActive) {
                                return
                            }
                            val mapped =
                                if (
                                    errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                                    errorCode == BiometricPrompt.ERROR_CANCELED
                                ) {
                                    BiometricGateResult.Cancelled
                                } else {
                                    BiometricGateResult.Unavailable(
                                        SafeLogger.redact(errString.toString()),
                                    )
                                }
                            continuation.resume(mapped)
                        }

                        override fun onAuthenticationFailed() {
                            // Keep prompt open until success, cancellation, or lockout error.
                        }
                    }

                val executor = ContextCompat.getMainExecutor(activity)
                val prompt = BiometricPrompt(activity, executor, callback)
                continuation.invokeOnCancellation {
                    prompt.cancelAuthentication()
                }
                prompt.authenticate(promptInfo)
            }
        }

    private fun supportedAuthenticators(): Int =
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> {
                Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
            }
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                Authenticators.BIOMETRIC_WEAK or Authenticators.DEVICE_CREDENTIAL
            }
            else -> Authenticators.BIOMETRIC_STRONG
        }

    private fun mapAvailabilityError(status: Int): BiometricGateResult {
        val reason =
            when (status) {
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                    "Set a device PIN, pattern, password, or biometric in Android Settings."
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                    "Biometric hardware is temporarily unavailable."
                else ->
                    "Device authentication is unavailable on this device."
            }
        return BiometricGateResult.Unavailable(reason)
    }
}
