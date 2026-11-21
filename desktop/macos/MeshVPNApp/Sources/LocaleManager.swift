import Foundation
import MeshDesktopCore
import SwiftUI

/// Manages live `LocaleMode` persistence (`UserDefaults(suiteName: "MeshVPN")`)
/// without restarting the privileged daemon (`ADR-029`).
@MainActor
final class LocaleManager: ObservableObject {
    @Published var mode: LocaleMode {
        didSet {
            mode.save(to: defaults)
        }
    }

    private let defaults: UserDefaults?

    init(defaults: UserDefaults? = UserDefaults(suiteName: LocaleMode.userDefaultsSuiteName)) {
        self.defaults = defaults
        self.mode = LocaleMode.load(from: defaults)
    }

    var effectiveLocale: Locale {
        mode.effectiveLocale
    }

    func tr(_ key: String) -> String {
        MeshL10n.tr(key, locale: effectiveLocale)
    }
}
