package dev.meshvpn.android.ui.onboarding

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.meshvpn.android.LocaleMode
import dev.meshvpn.android.R
import dev.meshvpn.android.ui.theme.ThemeMode

/**
 * Compact pre-enrollment Language (`System / Tiếng Việt / English`) and Appearance
 * (`System / Light / Dark`) selector shown on [OnboardingScreen] (`HIGH-UUI-G3-02`).
 */
@Composable
internal fun OnboardingQuickPreferencesCard(
    themeMode: ThemeMode,
    localeMode: LocaleMode,
    onSelectThemeMode: (ThemeMode) -> Unit,
    onSelectLocaleMode: (LocaleMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            QuickLocaleChipsRow(
                localeMode = localeMode,
                onSelectLocaleMode = onSelectLocaleMode,
            )
            QuickThemeChipsRow(
                themeMode = themeMode,
                onSelectThemeMode = onSelectThemeMode,
            )
        }
    }
}

@Composable
private fun QuickLocaleChipsRow(
    localeMode: LocaleMode,
    onSelectLocaleMode: (LocaleMode) -> Unit,
) {
    val options =
        listOf(
            Triple(
                LocaleMode.SYSTEM,
                stringResource(R.string.locale_system),
                "onboarding_locale_option_system",
            ),
            Triple(
                LocaleMode.VI,
                stringResource(R.string.locale_vietnamese),
                "onboarding_locale_option_vi",
            ),
            Triple(
                LocaleMode.EN,
                stringResource(R.string.locale_english),
                "onboarding_locale_option_en",
            ),
        )
    Text(
        text = stringResource(R.string.locale_language),
        style = MaterialTheme.typography.labelLarge,
    )
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .testTag("onboarding_locale_selector"),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        for ((mode, label, tag) in options) {
            FilterChip(
                selected = localeMode == mode,
                onClick = { onSelectLocaleMode(mode) },
                label = { Text(label) },
                modifier = Modifier.testTag(tag),
            )
        }
    }
}

@Composable
private fun QuickThemeChipsRow(
    themeMode: ThemeMode,
    onSelectThemeMode: (ThemeMode) -> Unit,
) {
    val options =
        listOf(
            Triple(
                ThemeMode.SYSTEM,
                stringResource(R.string.theme_system),
                "onboarding_theme_option_system",
            ),
            Triple(
                ThemeMode.LIGHT,
                stringResource(R.string.theme_light),
                "onboarding_theme_option_light",
            ),
            Triple(
                ThemeMode.DARK,
                stringResource(R.string.theme_dark),
                "onboarding_theme_option_dark",
            ),
        )
    Text(
        text = stringResource(R.string.theme_appearance),
        style = MaterialTheme.typography.labelLarge,
    )
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .testTag("onboarding_theme_selector"),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        for ((mode, label, tag) in options) {
            FilterChip(
                selected = themeMode == mode,
                onClick = { onSelectThemeMode(mode) },
                label = { Text(label) },
                modifier = Modifier.testTag(tag),
            )
        }
    }
}
