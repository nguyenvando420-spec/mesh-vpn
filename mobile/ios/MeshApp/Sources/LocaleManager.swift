import Foundation

/// Persisted language preference across System, English, and Vietnamese (`ADR-029`).
public enum LocaleMode: String, Codable, CaseIterable, Sendable {
    case system
    case en
    case vi

    /// Human-readable option label for Settings selector.
    public var displayTitle: String {
        switch self {
        case .system: return "System"
        case .en: return "English"
        case .vi: return "Tiếng Việt"
        }
    }
}

/// Stub `@EnvironmentObject` managing `UserDefaults` key `"mesh_locale_mode"` for Wave U-C4.
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
        Self.languageCode(for: resolvedLocale)
    }

    public func setLocaleMode(_ mode: LocaleMode) {
        localeMode = mode
    }

    /// Pure `Sendable` `.lproj` bundle lookup via `Bundle.main` (ready for `WP-U-C4`).
    public nonisolated static func localizedString(
        _ key: String,
        locale: Locale,
        fallback: String? = nil
    ) -> String {
        let lang = languageCode(for: locale)
        let bundle = Bundle.main.path(forResource: lang, ofType: "lproj")
            .flatMap(Bundle.init(path:)) ?? Bundle.main
        return bundle.localizedString(forKey: key, value: fallback ?? key, table: nil)
    }

    private nonisolated static func languageCode(for locale: Locale) -> String {
        locale.identifier.lowercased().hasPrefix("vi") ? "vi" : "en"
    }
}
