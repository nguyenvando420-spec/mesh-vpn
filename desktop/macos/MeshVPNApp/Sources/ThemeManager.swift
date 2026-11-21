import AppKit
import MeshDesktopCore
import SwiftUI

extension Color {
    /// Initializes a `Color` from a 6- or 8-digit hex string (e.g. `"#D97706"`).
    init(hex: String) {
        let components = MeshPalette.rgbaComponents(hex: hex)
        self.init(
            .sRGB,
            red: components.red,
            green: components.green,
            blue: components.blue,
            opacity: components.alpha
        )
    }
}

/// Canonical Light/Dark adaptive colors implementing `ADR-030` design tokens.
enum MeshPalette: Sendable {
    struct RgbaComponents: Sendable {
        let red: Double
        let green: Double
        let blue: Double
        let alpha: Double
    }

    static var surfaceBackground: Color {
        adaptive(
            lightHex: MeshDesignTokens.surfaceBackgroundLight,
            darkHex: MeshDesignTokens.surfaceBackgroundDark
        )
    }

    static var surfaceCard: Color {
        adaptive(
            lightHex: MeshDesignTokens.surfaceCardLight,
            darkHex: MeshDesignTokens.surfaceCardDark
        )
    }

    static var surfaceBorder: Color {
        adaptive(
            lightHex: MeshDesignTokens.surfaceBorderLight,
            darkHex: MeshDesignTokens.surfaceBorderDark
        )
    }

    static var textPrimary: Color {
        adaptive(
            lightHex: MeshDesignTokens.textPrimaryLight,
            darkHex: MeshDesignTokens.textPrimaryDark
        )
    }

    static var textSecondary: Color {
        adaptive(
            lightHex: MeshDesignTokens.textSecondaryLight,
            darkHex: MeshDesignTokens.textSecondaryDark
        )
    }

    static var brandPrimary: Color {
        adaptive(
            lightHex: MeshDesignTokens.brandCobalt,
            darkHex: MeshDesignTokens.brandSky
        )
    }

    static var brandTeal: Color {
        adaptive(
            lightHex: MeshDesignTokens.brandTeal,
            darkHex: MeshDesignTokens.brandTealLight
        )
    }

    static var semanticSuccess: Color {
        adaptive(
            lightHex: MeshDesignTokens.semanticSuccessLight,
            darkHex: MeshDesignTokens.semanticSuccessDark
        )
    }

    static var semanticWarning: Color {
        adaptive(
            lightHex: MeshDesignTokens.semanticWarningLight,
            darkHex: MeshDesignTokens.semanticWarningDark
        )
    }

    static var semanticError: Color {
        adaptive(
            lightHex: MeshDesignTokens.semanticErrorLight,
            darkHex: MeshDesignTokens.semanticErrorDark
        )
    }

    static var semanticNeutral: Color {
        adaptive(
            lightHex: MeshDesignTokens.semanticNeutralLight,
            darkHex: MeshDesignTokens.semanticNeutralDark
        )
    }

    static func color(for tone: SemanticColorTone) -> Color {
        switch tone {
        case .success: return semanticSuccess
        case .warning: return semanticWarning
        case .error: return semanticError
        case .neutral: return semanticNeutral
        }
    }

    static func color(for group: MenuBarStatusGroup) -> Color {
        color(for: group.semanticTone)
    }

    static func adaptive(lightHex: String, darkHex: String) -> Color {
        let dynamicColor = NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let parts = rgbaComponents(hex: isDark ? darkHex : lightHex)
            return NSColor(
                srgbRed: parts.red,
                green: parts.green,
                blue: parts.blue,
                alpha: parts.alpha
            )
        }
        return Color(nsColor: dynamicColor)
    }

    static func rgbaComponents(hex: String) -> RgbaComponents {
        let cleaned = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var rawValue: UInt64 = 0
        Scanner(string: cleaned).scanHexInt64(&rawValue)
        switch cleaned.count {
        case 6:
            return RgbaComponents(
                red: Double((rawValue >> 16) & 0xFF) / 255.0,
                green: Double((rawValue >> 8) & 0xFF) / 255.0,
                blue: Double(rawValue & 0xFF) / 255.0,
                alpha: 1.0
            )
        case 8:
            return RgbaComponents(
                red: Double((rawValue >> 16) & 0xFF) / 255.0,
                green: Double((rawValue >> 8) & 0xFF) / 255.0,
                blue: Double(rawValue & 0xFF) / 255.0,
                alpha: Double((rawValue >> 24) & 0xFF) / 255.0
            )
        default:
            return RgbaComponents(red: 0, green: 0, blue: 0, alpha: 1.0)
        }
    }
}

/// Manages `ThemeMode` persistence (`UserDefaults(suiteName: "MeshVPN")`) and `NSApp.appearance`.
@MainActor
final class ThemeManager: ObservableObject {
    @Published var mode: ThemeMode {
        didSet {
            mode.save(to: defaults)
            applyAppearance()
        }
    }

    private let defaults: UserDefaults?

    init(defaults: UserDefaults? = UserDefaults(suiteName: ThemeMode.userDefaultsSuiteName)) {
        self.defaults = defaults
        self.mode = ThemeMode.load(from: defaults)
        applyAppearance()
    }

    var preferredColorScheme: ColorScheme? {
        switch mode {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    func applyAppearance() {
        let app: NSApplication? = NSApp
        switch mode {
        case .system:
            app?.appearance = nil
        case .light:
            app?.appearance = NSAppearance(named: .aqua)
        case .dark:
            app?.appearance = NSAppearance(named: .darkAqua)
        }
    }
}
