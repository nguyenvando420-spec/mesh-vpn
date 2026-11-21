import MeshCoreKit
import SwiftUI

/// Entry point for the iOS `MeshApp` SwiftUI container application (`US-087..093`).
@main
struct MeshVpnApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var viewModel = AppViewModel.makeLive()
    @StateObject private var themeManager = ThemeManager()
    @StateObject private var localeManager = LocaleManager()
    @State private var isPrivacyScreenActive = false

    var body: some Scene {
        WindowGroup {
            let locale = localeManager.resolvedLocale
            ZStack {
                if viewModel.isEnrolled {
                    DashboardView(viewModel: viewModel)
                } else {
                    OnboardingView(viewModel: viewModel)
                }

                if isPrivacyScreenActive {
                    PrivacyBlurOverlayView(locale: locale)
                        .transition(.opacity)
                }
            }
            .environmentObject(themeManager)
            .environmentObject(localeManager)
            .preferredColorScheme(themeManager.preferredColorScheme)
            .environment(\.locale, locale)
            .task {
                await viewModel.startObserving()
            }
            .onChange(of: scenePhase) { newPhase in
                withAnimation(.easeInOut(duration: 0.15)) {
                    isPrivacyScreenActive = newPhase != .active
                }
                if newPhase == .active {
                    Task {
                        await viewModel.refreshAllState()
                    }
                }
            }
            .alert(
                viewModel.activeError?.title ?? "Notice",
                isPresented: Binding(
                    get: { viewModel.activeError != nil },
                    set: { isPresented in
                        if !isPresented {
                            viewModel.activeError = nil
                        }
                    }
                )
            ) {
                Button(L10n.tr("generic.close", locale: locale), role: .cancel) {
                    viewModel.activeError = nil
                }
            } message: {
                Text(viewModel.activeError?.message ?? "")
            }
        }
    }
}

private struct PrivacyBlurOverlayView: View {
    let locale: Locale

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.ultraThinMaterial)
                .ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(.secondary)
                Text(L10n.tr("notif.app_name", locale: locale))
                    .font(.headline)
                Text("Sensitive keys and credentials are hidden.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding()
        }
    }
}
