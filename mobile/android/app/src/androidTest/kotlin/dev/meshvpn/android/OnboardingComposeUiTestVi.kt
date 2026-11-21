package dev.meshvpn.android

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.meshvpn.android.ui.JoinConfirmationUiModel
import dev.meshvpn.android.ui.MainUiScreenState
import dev.meshvpn.android.ui.OnboardingMethod
import dev.meshvpn.android.ui.onboarding.OnboardingScreen
import dev.meshvpn.android.ui.settings.SettingsScreen
import dev.meshvpn.android.ui.theme.MeshTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OnboardingComposeUiTestVi {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun manualTabInVietnameseLocaleDisplaysVietnameseConfirmationDialog() {
        var submittedEndpoint = ""
        var submittedKeyLen = 0
        val testPin = "sha256:" + "c".repeat(64)
        var screenState by mutableStateOf(
            MainUiScreenState(
                onboardingMethod = OnboardingMethod.MANUAL,
                localeMode = LocaleMode.VI,
            ),
        )

        composeRule.setContent {
            val baseContext = LocalContext.current
            val viContext =
                remember(baseContext) {
                    LocaleHelper.buildLocalizedContext(baseContext, LocaleMode.VI)
                }
            CompositionLocalProvider(
                LocalContext provides viContext,
                LocalConfiguration provides viContext.resources.configuration,
            ) {
                MeshTheme {
                    OnboardingScreen(
                        screenState = screenState,
                        onSelectMethod = {},
                        onSubmitJoinUri = {},
                        onPasteFromClipboard = {},
                        onSubmitManual = { ep, mode, pin, chars, name ->
                            submittedEndpoint = ep
                            submittedKeyLen = chars.size
                            chars.fill('\u0000')
                            screenState =
                                screenState.copy(
                                    pendingConfirmation =
                                        JoinConfirmationUiModel(
                                            serverEndpoint = ep,
                                            tlsAuthMode = mode,
                                            serverPin = pin,
                                            preauthKeyMasked = "mpk_abcd...9999",
                                            nodeName = name.ifBlank { null },
                                        ),
                                )
                        },
                        onToggleConnectOnConfirm = {},
                        onConfirmJoin = {},
                        onCancelConfirmation = {},
                    )
                }
            }
        }

        composeRule.onNodeWithTag("manual_endpoint_input").performTextInput("203.0.113.10:443")
        composeRule.onNodeWithTag("manual_pin_input").performTextInput(testPin)
        composeRule
            .onNodeWithTag("manual_preauth_input")
            .performTextInput("mpk_" + "A".repeat(44))
        composeRule.onNodeWithTag("manual_submit_button").performClick()

        assertEquals("203.0.113.10:443", submittedEndpoint)
        assertTrue(submittedKeyLen >= 48)
        composeRule.onNodeWithTag("confirm_join_button").assertIsDisplayed()
        composeRule.onNodeWithText("Xác minh danh tính máy chủ điều khiển").assertIsDisplayed()
        composeRule.onNodeWithText("Tin tưởng & Kết nối").assertIsDisplayed()
    }

    @Test
    fun settingsLocaleSelectorSwitchesUiToVietnameseLive() {
        var screenState by mutableStateOf(MainUiScreenState(localeMode = LocaleMode.EN))

        composeRule.setContent {
            val baseContext = LocalContext.current
            val localizedContext =
                remember(baseContext, screenState.localeMode) {
                    LocaleHelper.buildLocalizedContext(baseContext, screenState.localeMode)
                }
            CompositionLocalProvider(
                LocalContext provides localizedContext,
                LocalConfiguration provides localizedContext.resources.configuration,
            ) {
                MeshTheme {
                    SettingsScreen(
                        screenState = screenState,
                        onSelectThemeMode = {},
                        onSelectLocaleMode = { mode ->
                            screenState = screenState.copy(localeMode = mode)
                        },
                        onToggleRevealPins = {},
                        onSensitiveModalChanged = {},
                        onUpdateServerConfig = { _, _, _ -> },
                        onRotateKey = {},
                        onToggleAlwaysOnHint = {},
                        onOpenVpnSettings = {},
                        onRunNetcheck = {},
                        onExportBugreport = {},
                        onCleanupDiagnostics = {},
                        onResetIdentity = {},
                    )
                }
            }
        }

        composeRule.onNodeWithTag("locale_selector").assertIsDisplayed()
        composeRule.onNodeWithTag("locale_option_vi").performClick()
        composeRule.onNodeWithText("Ngôn ngữ").assertIsDisplayed()
        composeRule.onNodeWithText("Cài đặt & Bảo mật").assertIsDisplayed()
    }
}
