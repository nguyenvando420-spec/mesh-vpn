import SwiftUI

/// Enrolled dashboard container injecting `ThemeManager`, `LocaleManager`, and `MainTabView`.
@MainActor
struct DashboardView: View {
    @ObservedObject var viewModel: AppViewModel
    @StateObject private var themeManager = ThemeManager()
    @StateObject private var localeManager = LocaleManager()

    var body: some View {
        MainTabView(viewModel: viewModel)
            .environmentObject(themeManager)
            .environmentObject(localeManager)
            .preferredColorScheme(themeManager.preferredColorScheme)
            .environment(\.locale, localeManager.resolvedLocale)
    }
}
