package dev.meshvpn.android

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.content.res.Configuration
import android.content.res.Resources
import androidx.core.os.ConfigurationCompat
import androidx.fragment.app.FragmentActivity
import java.util.Locale

/**
 * User-selected UI language mode persisted locally in `mesh_ui_prefs` (`ADR-029`, `ADR-031`).
 */
enum class LocaleMode(
    val storageValue: String,
) {
    SYSTEM("system"),
    EN("en"),
    VI("vi"),
    ;

    val value: String
        get() = storageValue

    companion object {
        fun fromStorageValue(raw: String?): LocaleMode =
            entries.firstOrNull { it.storageValue == raw } ?: SYSTEM
    }
}

interface LocalePrefsStore {
    fun loadLocaleMode(): LocaleMode

    fun saveLocaleMode(mode: LocaleMode)
}

class InMemoryLocalePrefsStore(
    initialMode: LocaleMode = LocaleMode.SYSTEM,
) : LocalePrefsStore {
    private var currentMode: LocaleMode = initialMode

    override fun loadLocaleMode(): LocaleMode = currentMode

    override fun saveLocaleMode(mode: LocaleMode) {
        currentMode = mode
    }
}

class SharedPrefsLocaleStore(
    private val prefs: SharedPreferences,
) : LocalePrefsStore {
    constructor(context: Context) : this(
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
    )

    override fun loadLocaleMode(): LocaleMode =
        LocaleMode.fromStorageValue(prefs.getString(KEY_LOCALE_MODE, null))

    override fun saveLocaleMode(mode: LocaleMode) {
        prefs.edit().putString(KEY_LOCALE_MODE, mode.storageValue).apply()
    }

    companion object {
        const val PREFS_NAME = "mesh_ui_prefs"
        const val KEY_LOCALE_MODE = "mesh_locale_mode"
    }
}

/**
 * Live bilingual locale wrapper (`ADR-029`) preserving [FragmentActivity] identity for
 * `BiometricPrompt` without requiring `androidx.appcompat`.
 */
object LocaleHelper {
    fun resolveLocale(
        mode: LocaleMode,
        systemLocale: Locale = Locale.getDefault(),
    ): Locale =
        when (mode) {
            LocaleMode.SYSTEM -> systemLocale
            LocaleMode.EN -> Locale.forLanguageTag("en")
            LocaleMode.VI -> Locale.forLanguageTag("vi")
        }

    fun buildLocalizedContext(
        base: Context,
        mode: LocaleMode,
    ): Context {
        val systemLocale =
            ConfigurationCompat.getLocales(base.resources.configuration)[0]
                ?: Locale.getDefault()
        val locale = resolveLocale(mode, systemLocale)
        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        return base.createConfigurationContext(config)
    }

    fun wrapActivityContext(
        activity: FragmentActivity,
        mode: LocaleMode,
    ): ContextWrapper {
        val localizedConfigContext = buildLocalizedContext(activity, mode)
        // Delegate getResources() to the localized configuration context while keeping
        // FragmentActivity as the base context for BiometricPrompt lookup.
        return object : ContextWrapper(activity) {
            override fun getResources(): Resources = localizedConfigContext.resources
        }
    }

    fun isVietnamese(context: Context): Boolean {
        val activeLocale =
            ConfigurationCompat.getLocales(context.resources.configuration)[0]
                ?: Locale.getDefault()
        return activeLocale.language.equals("vi", ignoreCase = true)
    }

    fun tr(
        context: Context,
        en: String,
        vi: String,
    ): String = if (isVietnamese(context)) vi else en
}
