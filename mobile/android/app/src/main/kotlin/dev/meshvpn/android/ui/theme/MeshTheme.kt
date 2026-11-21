package dev.meshvpn.android.ui.theme

import android.content.Context
import android.content.SharedPreferences
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * User-selected appearance mode persisted locally in `mesh_ui_prefs` (`ADR-031`).
 */
enum class ThemeMode(
    val storageValue: String,
) {
    SYSTEM("system"),
    LIGHT("light"),
    DARK("dark"),
    ;

    companion object {
        fun fromStorageValue(raw: String?): ThemeMode =
            entries.firstOrNull { it.storageValue == raw } ?: SYSTEM
    }
}

interface ThemePrefsStore {
    fun loadThemeMode(): ThemeMode

    fun saveThemeMode(mode: ThemeMode)
}

class InMemoryThemePrefsStore(
    initialMode: ThemeMode = ThemeMode.SYSTEM,
) : ThemePrefsStore {
    private var currentMode: ThemeMode = initialMode

    override fun loadThemeMode(): ThemeMode = currentMode

    override fun saveThemeMode(mode: ThemeMode) {
        currentMode = mode
    }
}

class SharedPrefsThemeStore(
    private val prefs: SharedPreferences,
) : ThemePrefsStore {
    constructor(context: Context) : this(
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
    )

    override fun loadThemeMode(): ThemeMode =
        ThemeMode.fromStorageValue(prefs.getString(KEY_THEME_MODE, null))

    override fun saveThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME_MODE, mode.storageValue).apply()
    }

    companion object {
        const val PREFS_NAME = "mesh_ui_prefs"
        const val KEY_THEME_MODE = "mesh_theme_mode"
    }
}

/**
 * Canonical Light/Dark design tokens shared across Mesh VPN v0.4.0 (`ADR-030`).
 */
object MeshTokens {
    // Light tokens
    val SurfaceBackground = Color(0xFFF8FAFC)
    val SurfaceCard = Color(0xFFFFFFFF)
    val SurfaceBorder = Color(0xFFCBD5E1)
    val TextPrimary = Color(0xFF0F172A)
    val TextSecondary = Color(0xFF475569)
    val BrandCobalt = Color(0xFF0B57D0)
    val BrandTeal = Color(0xFF0D9488)
    val SemanticSuccess = Color(0xFF16A34A)
    val SemanticWarning = Color(0xFFD97706)
    val SemanticError = Color(0xFFDC2626)
    val SemanticNeutral = Color(0xFF6B7280)

    // Dark tokens
    val SurfaceBackgroundDark = Color(0xFF0F172A)
    val SurfaceCardDark = Color(0xFF1E293B)
    val SurfaceBorderDark = Color(0xFF334155)
    val TextPrimaryDark = Color(0xFFF1F5F9)
    val TextSecondaryDark = Color(0xFF94A3B8)
    val BrandSky = Color(0xFF60A5FA)
    val BrandTealLight = Color(0xFF2DD4BF)
    val SemanticSuccessDark = Color(0xFF4ADE80)
    val SemanticWarningDark = Color(0xFFFBBF24)
    val SemanticErrorDark = Color(0xFFF87171)
    val SemanticNeutralDark = Color(0xFF9CA3AF)
}

private val LightColorScheme =
    lightColorScheme(
        primary = MeshTokens.BrandCobalt,
        onPrimary = Color(0xFFFFFFFF),
        primaryContainer = Color(0xFFD3E3FD),
        onPrimaryContainer = Color(0xFF041E49),
        secondary = MeshTokens.BrandTeal,
        onSecondary = Color(0xFFFFFFFF),
        secondaryContainer = Color(0xFFCCFBF1),
        onSecondaryContainer = Color(0xFF042F2E),
        tertiary = MeshTokens.SemanticWarning,
        onTertiary = Color(0xFFFFFFFF),
        tertiaryContainer = Color(0xFFFEF3C7),
        onTertiaryContainer = Color(0xFF451A03),
        error = MeshTokens.SemanticError,
        onError = Color(0xFFFFFFFF),
        errorContainer = Color(0xFFFEE2E2),
        onErrorContainer = Color(0xFF450A0A),
        background = MeshTokens.SurfaceBackground,
        onBackground = MeshTokens.TextPrimary,
        surface = MeshTokens.SurfaceBackground,
        onSurface = MeshTokens.TextPrimary,
        surfaceVariant = Color(0xFFE2E8F0),
        onSurfaceVariant = MeshTokens.TextSecondary,
        surfaceContainerLow = MeshTokens.SurfaceCard,
        surfaceContainer = MeshTokens.SurfaceCard,
        surfaceContainerHigh = MeshTokens.SurfaceCard,
        outline = MeshTokens.SurfaceBorder,
    )

private val DarkColorScheme =
    darkColorScheme(
        primary = MeshTokens.BrandSky,
        onPrimary = Color(0xFF0F172A),
        primaryContainer = Color(0xFF1E3A8A),
        onPrimaryContainer = Color(0xFFDBEAFE),
        secondary = MeshTokens.BrandTealLight,
        onSecondary = Color(0xFF0F172A),
        secondaryContainer = Color(0xFF134E4A),
        onSecondaryContainer = Color(0xFFCCFBF1),
        tertiary = MeshTokens.SemanticWarningDark,
        onTertiary = Color(0xFF0F172A),
        tertiaryContainer = Color(0xFF78350F),
        onTertiaryContainer = Color(0xFFFEF3C7),
        error = MeshTokens.SemanticErrorDark,
        onError = Color(0xFF0F172A),
        errorContainer = Color(0xFF7F1D1D),
        onErrorContainer = Color(0xFFFEE2E2),
        background = MeshTokens.SurfaceBackgroundDark,
        onBackground = MeshTokens.TextPrimaryDark,
        surface = MeshTokens.SurfaceBackgroundDark,
        onSurface = MeshTokens.TextPrimaryDark,
        surfaceVariant = MeshTokens.SurfaceBorderDark,
        onSurfaceVariant = MeshTokens.TextSecondaryDark,
        surfaceContainerLow = MeshTokens.SurfaceCardDark,
        surfaceContainer = MeshTokens.SurfaceCardDark,
        surfaceContainerHigh = MeshTokens.SurfaceCardDark,
        outline = MeshTokens.SurfaceBorderDark,
    )

private val MeshTypography =
    Typography(
        headlineSmall =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.SemiBold,
                fontSize = 22.sp,
                lineHeight = 28.sp,
            ),
        titleMedium =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.SemiBold,
                fontSize = 16.sp,
                lineHeight = 22.sp,
            ),
        bodyMedium =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.Normal,
                fontSize = 14.sp,
                lineHeight = 20.sp,
            ),
        labelMedium =
            TextStyle(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Medium,
                fontSize = 12.sp,
                lineHeight = 16.sp,
            ),
    )

@Composable
fun MeshTheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    darkTheme: Boolean =
        when (themeMode) {
            ThemeMode.SYSTEM -> isSystemInDarkTheme()
            ThemeMode.LIGHT -> false
            ThemeMode.DARK -> true
        },
    content: @Composable () -> Unit,
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        typography = MeshTypography,
        content = content,
    )
}
