package dev.meshvpn.android.ui

import dev.meshvpn.android.ffi.UiErrorKind
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.mesh_mobile_ffi.MobileDaemonState
import uniffi.mesh_mobile_ffi.MobileTlsAuthMode

class MeshMainViewModelTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun pasteJoinUriClearsClipboardImmediatelyAndRequiresConfirmation() =
        runTest {
            // Arrange
            val harness = MeshTestHarness(tempFolder.newFolder("vm_paste"), this)
            harness.clipboardText = "mesh://join?v=1&server=203.0.113.10:443"

            // Act
            harness.viewModel.pasteJoinUriAndClearClipboard()
            val pending = harness.viewModel.screenState.value

            // Assert
            assertEquals(1, harness.clipboardClearedCount)
            assertNull(harness.clipboardText)
            assertEquals(0, harness.enrollCallCount)
            assertNotNull(pending.pendingConfirmation)
            assertTrue(pending.requireFlagSecure)

            // Act 2: Confirm offline enrollment
            harness.viewModel.setConnectOnConfirm(false)
            harness.viewModel.confirmPendingJoin {}

            // Assert 2
            val enrolled = harness.viewModel.screenState.value
            assertEquals(1, harness.enrollCallCount)
            assertTrue(enrolled.session.isEnrolled)
            assertNull(enrolled.pendingConfirmation)
            assertFalse(enrolled.requireFlagSecure)
        }

    @Test
    fun manualJoinZeroizesCharArrayAndVpnDenialCancelsStagedSession() =
        runTest {
            // Arrange
            val harness = MeshTestHarness(tempFolder.newFolder("vm_manual"), this)
            val keyChars = ("mpk_" + "Z".repeat(44)).toCharArray()

            // Act
            harness.viewModel.submitManualJoin(
                rawEndpoint = "203.0.113.10:443",
                tlsAuthMode = MobileTlsAuthMode.SPKI_PIN,
                rawPin = harness.pin,
                rawPreauthKey = keyChars,
                rawNodeName = "pixel-8",
            )

            // Assert char buffer zeroized immediately and confirmation staged
            assertTrue(keyChars.all { it == '\u0000' })
            assertNotNull(harness.viewModel.screenState.value.pendingConfirmation)

            // Act 2: confirm with connect=true, then deny VPN consent
            harness.viewModel.setConnectOnConfirm(true)
            var prepareCalled = false
            harness.viewModel.confirmPendingJoin { prepareCalled = true }
            assertTrue(prepareCalled)
            assertTrue(harness.repo.hasStagedPendingEnrollment())

            harness.viewModel.onVpnConsentResult(granted = false) {}

            // Assert 2: staged pending session wiped on denial
            assertFalse(harness.repo.hasStagedPendingEnrollment())
            assertTrue(harness.lastPendingSession?.cancelled == true)
            assertNotNull(harness.viewModel.screenState.value.inputError)
        }

    @Test
    fun biometricGateFailClosedKeepsPinsMaskedAndPreservesIdentity() =
        runTest {
            // Arrange
            val harness = MeshTestHarness(tempFolder.newFolder("vm_biometric"), this)
            harness.viewModel.submitJoinUriInput("mesh://join?v=1")
            harness.viewModel.setConnectOnConfirm(false)
            harness.viewModel.confirmPendingJoin {}
            harness.viewModel.selectTab(MainTab.SETTINGS)

            // Act 1: cancelled biometric cannot reveal pins or reset identity
            harness.authResult = BiometricGateResult.Cancelled
            harness.viewModel.toggleRevealAdminPins()
            harness.viewModel.resetIdentityWithAuth()

            // Assert 1
            assertFalse(harness.viewModel.screenState.value.isAdminPinsRevealed)
            assertTrue(harness.stateStore.hasEnrolledIdentity())

            // Act 2: authenticated reveals pins + enables FLAG_SECURE, leaving tab re-hides
            harness.authResult = BiometricGateResult.Authenticated
            harness.viewModel.toggleRevealAdminPins()
            assertTrue(harness.viewModel.screenState.value.isAdminPinsRevealed)
            assertTrue(harness.viewModel.screenState.value.requireFlagSecure)

            harness.viewModel.selectTab(MainTab.STATUS)
            assertFalse(harness.viewModel.screenState.value.isAdminPinsRevealed)
        }

    @Test
    fun terminalRevocationWipesKeystoreAndStateFiles() =
        runTest {
            // Arrange
            val harness = MeshTestHarness(tempFolder.newFolder("vm_revoked"), this)
            harness.viewModel.submitJoinUriInput("mesh://join?v=1")
            harness.viewModel.setConnectOnConfirm(false)
            harness.viewModel.confirmPendingJoin {}
            assertTrue(harness.stateStore.hasEnrolledIdentity())

            // Act: server reports REVOKED via bridge status callback
            harness.lastCapturedBridge?.onStatusChanged(
                sampleSnapshot(MobileDaemonState.REVOKED, "203.0.113.10:443", harness.pin),
            )

            // Assert: identity.sealed.bin, dek.enc, bootstrap.toml & Keystore alias all wiped
            val ui = harness.viewModel.screenState.value.session
            assertFalse(harness.stateStore.hasEnrolledIdentity())
            assertTrue(harness.keyBackend.keys.isEmpty())
            assertEquals(MobileDaemonState.REVOKED, ui.daemonState)
            assertEquals(UiErrorKind.NODE_REVOKED, ui.lastError?.kind)
        }
}
