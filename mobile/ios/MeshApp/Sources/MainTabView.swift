import MeshCoreKit
import SwiftUI

/// Root 3-tab container (`Status`, `Peers`, `Settings`) shown when enrolled (`ADR-028`).
@MainActor
struct MainTabView: View {
    @ObservedObject var viewModel: AppViewModel
    @EnvironmentObject var themeManager: ThemeManager
    @EnvironmentObject var localeManager: LocaleManager

    var body: some View {
        let locale = localeManager.resolvedLocale
        TabView(selection: $viewModel.selectedTab) {
            StatusTab(viewModel: viewModel)
                .tabItem {
                    Label(
                        AppTab.status.localizedTitle(locale: locale),
                        systemImage: "shield.lefthalf.filled"
                    )
                }
                .tag(AppTab.status)

            PeersView(viewModel: viewModel)
                .tabItem {
                    Label(
                        AppTab.peers.localizedTitle(locale: locale),
                        systemImage: "person.2"
                    )
                }
                .tag(AppTab.peers)

            SettingsView(viewModel: viewModel)
                .tabItem {
                    Label(
                        AppTab.settings.localizedTitle(locale: locale),
                        systemImage: "gearshape"
                    )
                }
                .tag(AppTab.settings)
        }
        .tint(MeshDesignTokens.brandPrimary(colorScheme: effectiveColorScheme))
        .sheet(item: $viewModel.pendingConfirmation) { draft in
            EnrollmentConfirmationSheet(
                draft: draft,
                isBusy: viewModel.isBusy,
                onCancel: { viewModel.cancelPendingEnrollment() },
                onConfirm: {
                    Task { await viewModel.confirmPendingEnrollment() }
                }
            )
            .environment(\.locale, locale)
        }
        .sheet(item: shareSheetItemBinding) { item in
            ShareSheetView(fileURL: item.url) { completedURL in
                viewModel.cleanupSharedBugreport(at: completedURL)
            }
        }
    }

    @Environment(\.colorScheme) private var systemColorScheme

    private var effectiveColorScheme: ColorScheme {
        themeManager.preferredColorScheme ?? systemColorScheme
    }

    private var shareSheetItemBinding: Binding<ShareFileItem?> {
        Binding(
            get: { viewModel.shareBugreportURL.map(ShareFileItem.init) },
            set: { newValue in
                if newValue == nil, let url = viewModel.shareBugreportURL {
                    viewModel.cleanupSharedBugreport(at: url)
                }
            }
        )
    }
}

private struct ShareFileItem: Identifiable {
    var id: String { url.path }
    let url: URL
}
