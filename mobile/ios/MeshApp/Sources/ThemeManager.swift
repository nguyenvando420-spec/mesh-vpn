import Foundation
import SwiftUI

/// Persisted appearance mode across Light, Dark, and System defaults (`US-124`, `ADR-030`).
public enum ThemeMode: String, Codable, CaseIterable, Sendable {
    case system
    case light
    case dark

    /// Human-readable label shown in Settings before Wave C localization wiring.
    public var displayTitle: String {
        switch self {
        case .system: return "System"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
}

/// Semantic color classification shared by `StatusBadge` and status banners (`ADR-030`).
public enum MeshSemanticTone: String, Sendable, Equatable {
    case success
    case warning
    case error
    case neutral
    case brand
}

/// Canonical v0.4.0 design tokens aligned across Windows, macOS, Android, and iOS (`ADR-030`).
public enum MeshDesignTokens: Sendable {
    public static let surfaceBackgroundLightHex = "#F8FAFC"
    public static let surfaceBackgroundDarkHex = "#0F172A"
    public static let surfaceCardLightHex = "#FFFFFF"
    public static let surfaceCardDarkHex = "#1E293B"
    public static let surfaceBorderLightHex = "#CBD5E1"
    public static let surfaceBorderDarkHex = "#334155"
    public static let textPrimaryLightHex = "#0F172A"
    public static let textPrimaryDarkHex = "#F1F5F9"
    public static let textSecondaryLightHex = "#475569"
    public static let textSecondaryDarkHex = "#94A3B8"

    public static let brandCobaltHex = "#0B57D0"
    public static let brandSkyHex = "#60A5FA"
    public static let brandTealHex = "#0D9488"
    public static let brandTealLightHex = "#2DD4BF"

    public static let semanticSuccessLightHex = "#16A34A"
    public static let semanticSuccessDarkHex = "#4ADE80"
    public static let semanticWarningLightHex = "#D97706"
    public static let semanticWarningDarkHex = "#FBBF24"
    public static let semanticErrorLightHex = "#DC2626"
    public static let semanticErrorDarkHex = "#F87171"
    public static let semanticNeutralLightHex = "#6B7280"
    public static let semanticNeutralDarkHex = "#9CA3AF"

    /// Returns the canonical hex string for a semantic tone in light or dark mode.
    public static func hexString(for tone: MeshSemanticTone, isDark: Bool) -> String {
        switch tone {
        case .success:
            return isDark ? semanticSuccessDarkHex : semanticSuccessLightHex
        case .warning:
            return isDark ? semanticWarningDarkHex : semanticWarningLightHex
        case .error:
            return isDark ? semanticErrorDarkHex : semanticErrorLightHex
        case .neutral:
            return isDark ? semanticNeutralDarkHex : semanticNeutralLightHex
        case .brand:
            return isDark ? brandSkyHex : brandCobaltHex
        }
    }

    /// Resolves a semantic SwiftUI `Color` for the active `ColorScheme`.
    public static func color(for tone: MeshSemanticTone, colorScheme: ColorScheme) -> Color {
        Color(meshHex: hexString(for: tone, isDark: colorScheme == .dark))
    }

    /// Resolves the primary brand accent (`Cobalt` in light, `Sky` in dark).
    public static func brandPrimary(colorScheme: ColorScheme) -> Color {
        color(for: .brand, colorScheme: colorScheme)
    }

    /// Resolves the card surface color for light or dark appearance.
    public static func surfaceCard(colorScheme: ColorScheme) -> Color {
        let hex = colorScheme == .dark ? surfaceCardDarkHex : surfaceCardLightHex
        return Color(meshHex: hex)
    }

    /// Resolves the border color for light or dark appearance.
    public static func surfaceBorder(colorScheme: ColorScheme) -> Color {
        let hex = colorScheme == .dark ? surfaceBorderDarkHex : surfaceBorderLightHex
        return Color(meshHex: hex)
    }
}

public extension Color {
    /// Initializes an sRGB SwiftUI `Color` from a 6-digit `#RRGGBB` hex string.
    init(meshHex hex: String) {
        let cleaned = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var value: UInt64 = 0
        Scanner(string: cleaned).scanHexInt64(&value)
        let red = Double((value >> 16) & 0xFF) / 255.0
        let green = Double((value >> 8) & 0xFF) / 255.0
        let blue = Double(value & 0xFF) / 255.0
        self.init(.sRGB, red: red, green: green, blue: blue, opacity: 1.0)
    }
}

/// Coordinates user theme selection backed by `UserDefaults.standard` key `"mesh_theme_mode"`.
@MainActor
public final class ThemeManager: ObservableObject {
    public static let userDefaultsKey = "mesh_theme_mode"

    @Published public var themeMode: ThemeMode {
        didSet {
            userDefaults.set(themeMode.rawValue, forKey: Self.userDefaultsKey)
        }
    }

    private let userDefaults: UserDefaults

    public init(userDefaults: UserDefaults = .standard) {
        self.userDefaults = userDefaults
        if let raw = userDefaults.string(forKey: Self.userDefaultsKey),
           let parsed = ThemeMode(rawValue: raw) {
            self.themeMode = parsed
        } else {
            self.themeMode = .system
        }
    }

    /// Maps `ThemeMode` to SwiftUI `.preferredColorScheme(_:)`.
    public var preferredColorScheme: ColorScheme? {
        switch themeMode {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    public func setThemeMode(_ mode: ThemeMode) {
        themeMode = mode
    }
}
