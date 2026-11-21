import SwiftUI

/// Enrolled dashboard container injecting `ThemeManager`, `LocaleManager`, and `MainTabView`.
@MainActor
struct DashboardView: View {
    @ObservedObject var viewModel: AppViewModel
    @EnvironmentObject var themeManager: ThemeManager
    @EnvironmentObject var localeManager: LocaleManager

    var body: some View {
        MainTabView(viewModel: viewModel)
            .preferredColorScheme(themeManager.preferredColorScheme)
            .environment(\.locale, localeManager.resolvedLocale)
    }
}
