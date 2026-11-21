import Foundation

/// Persisted language preference across System, English, and Vietnamese (`ADR-029`).
public enum LocaleMode: String, Codable, CaseIterable, Sendable {
    case system
    case en
    case vi

    /// Canonical glossary key for the locale option label.
    public var localizationKey: String {
        switch self {
        case .system: return "locale.system"
        case .en: return "locale.english"
        case .vi: return "locale.vietnamese"
        }
    }

    /// Human-readable option label for Settings selector.
    public var displayTitle: String {
        switch self {
        case .system: return "System"
        case .en: return "English"
        case .vi: return "Tiếng Việt"
        }
    }

    /// Returns the localized display label for the active `Locale`.
    public func localizedTitle(locale: Locale) -> String {
        L10n.tr(localizationKey, locale: locale)
    }
}

/// Pure `Sendable` runtime localization lookup backed by `Bundle.main` `.lproj` tables (`ADR-029`).
public enum L10n: Sendable {
    /// Looks up `key` in the matching `.lproj` bundle inside `Bundle.main` for `locale`.
    public static func tr(_ key: String, locale: Locale) -> String {
        let lang = languageCode(for: locale)
        return Bundle.main.path(forResource: lang, ofType: "lproj")
            .flatMap(Bundle.init(path:))?
            .localizedString(forKey: key, value: key, table: nil)
            ?? Bundle.main.localizedString(forKey: key, value: key, table: nil)
    }

    /// Resolves canonical 2-letter language code (`"vi"` or `"en"`) from a `Locale`.
    public static func languageCode(for locale: Locale) -> String {
        locale.identifier.lowercased().hasPrefix("vi") ? "vi" : "en"
    }
}

/// Manages `UserDefaults` key `"mesh_locale_mode"` and live `Locale` resolution (`ADR-029`).
@MainActor
public final class LocaleManager: ObservableObject {
    public static let userDefaultsKey = "mesh_locale_mode"

    @Published public var localeMode: LocaleMode {
        didSet {
            userDefaults.set(localeMode.rawValue, forKey: Self.userDefaultsKey)
        }
    }

    private let userDefaults: UserDefaults

    public init(userDefaults: UserDefaults = .standard) {
        self.userDefaults = userDefaults
        if let raw = userDefaults.string(forKey: Self.userDefaultsKey),
           let parsed = LocaleMode(rawValue: raw) {
            self.localeMode = parsed
        } else {
            self.localeMode = .system
        }
    }

    /// Resolves an iOS 15.0+ compatible `Locale` using explicit identifier init.
    public var resolvedLocale: Locale {
        switch localeMode {
        case .system:
            return Locale.current
        case .en:
            return Locale(identifier: "en")
        case .vi:
            return Locale(identifier: "vi")
        }
    }

    /// Resolves canonical 2-letter language code (`"vi"` or `"en"`).
    public var resolvedLanguageCode: String {
        L10n.languageCode(for: resolvedLocale)
    }

    public func setLocaleMode(_ mode: LocaleMode) {
        localeMode = mode
    }

    /// Translates a canonical key using the active `resolvedLocale`.
    public func tr(_ key: String) -> String {
        L10n.tr(key, locale: resolvedLocale)
    }

    /// Pure `Sendable` `.lproj` bundle lookup via `Bundle.main` (`ADR-029`).
    public nonisolated static func localizedString(
        _ key: String,
        locale: Locale,
        fallback: String? = nil
    ) -> String {
        let lang = L10n.languageCode(for: locale)
        let bundle = Bundle.main.path(forResource: lang, ofType: "lproj")
            .flatMap(Bundle.init(path:)) ?? Bundle.main
        return bundle.localizedString(forKey: key, value: fallback ?? key, table: nil)
    }
}
