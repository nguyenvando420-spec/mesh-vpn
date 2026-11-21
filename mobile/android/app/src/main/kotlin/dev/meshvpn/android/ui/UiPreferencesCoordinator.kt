package dev.meshvpn.android.ui

import dev.meshvpn.android.LocaleMode
import dev.meshvpn.android.LocalePrefsStore
import dev.meshvpn.android.ui.peers.PeerFilterMode
import dev.meshvpn.android.ui.theme.ThemeMode
import dev.meshvpn.android.ui.theme.ThemePrefsStore
import dev.meshvpn.android.vpn.MeshSessionUiState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update

/**
 * UI preferences, peer filter, and sensitive modal state operations exposed by [MeshMainViewModel].
 */
interface MeshUiPreferencesController {
    fun attachThemePrefs(store: ThemePrefsStore)

    fun selectThemeMode(mode: ThemeMode)

    fun attachLocalePrefs(store: LocalePrefsStore)

    fun setLocaleMode(mode: LocaleMode)

    fun updatePeerSearchQuery(query: String)

    fun selectPeerFilterMode(mode: PeerFilterMode)

    fun setSensitiveModalOpen(open: Boolean)
}

/**
 * Coordinates theme, locale, peer search/filter, and sensitive-modal screen state updates
 * delegated from [MeshMainViewModel].
 */
internal class UiPreferencesCoordinator(
    initialSession: MeshSessionUiState,
    initialThemePrefs: ThemePrefsStore,
    initialLocalePrefs: LocalePrefsStore,
) : MeshUiPreferencesController {
    @Volatile
    private var themePrefsStore: ThemePrefsStore = initialThemePrefs

    @Volatile
    private var themePrefsAttached = false

    @Volatile
    private var localePrefsStore: LocalePrefsStore = initialLocalePrefs

    @Volatile
    private var localePrefsAttached = false

    val screenStateFlow: MutableStateFlow<MainUiScreenState> =
        MutableStateFlow(
            MainUiScreenState(
                session = initialSession,
                themeMode = initialThemePrefs.loadThemeMode(),
                localeMode = initialLocalePrefs.loadLocaleMode(),
            ),
        )

    override fun attachThemePrefs(store: ThemePrefsStore) {
        if (themePrefsAttached) {
            return
        }
        themePrefsAttached = true
        themePrefsStore = store
        val savedMode = store.loadThemeMode()
        screenStateFlow.update { it.copy(themeMode = savedMode) }
    }

    override fun selectThemeMode(mode: ThemeMode) {
        themePrefsStore.saveThemeMode(mode)
        screenStateFlow.update { it.copy(themeMode = mode) }
    }

    override fun attachLocalePrefs(store: LocalePrefsStore) {
        if (localePrefsAttached) {
            return
        }
        localePrefsAttached = true
        localePrefsStore = store
        val savedMode = store.loadLocaleMode()
        screenStateFlow.update { it.copy(localeMode = savedMode) }
    }

    override fun setLocaleMode(mode: LocaleMode) {
        localePrefsStore.saveLocaleMode(mode)
        screenStateFlow.update { it.copy(localeMode = mode) }
    }

    override fun updatePeerSearchQuery(query: String) {
        screenStateFlow.update { it.copy(peerSearchQuery = query) }
    }

    override fun selectPeerFilterMode(mode: PeerFilterMode) {
        screenStateFlow.update { it.copy(peerFilterMode = mode) }
    }

    override fun setSensitiveModalOpen(open: Boolean) {
        screenStateFlow.update { it.copy(isSensitiveModalOpen = open) }
    }
}
