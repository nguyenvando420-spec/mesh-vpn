import AppKit
import MeshDesktopCore
import SwiftUI

/// Single-instance Desktop Dashboard rendering 3-zone navigation for all enrolled states.
struct DashboardWindowView: View {
    @ObservedObject var store: DesktopStore
    @ObservedObject var themeManager: ThemeManager

    @State private var activeTab: DesktopTabKind = .status
    @State private var onboardingSheetMode: OnboardingSheetModeWrapper?
    @State private var showDiagnosticsSheet: Bool = false
    @State private var firewallOptInOnInstall: Bool = true
    @State private var confirmRevokedReset: Bool = false

    private struct OnboardingSheetModeWrapper: Identifiable {
        let mode: OnboardingMode
        var id: String { mode == .keyRotation ? "rotate" : "enroll" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            topHeaderBar
            DashboardBannersView(
                store: store,
                onOpenDiagnostics: {
                    if store.uiState.isEnrolledState {
                        activeTab = .diagnostics
                    } else {
                        showDiagnosticsSheet = true
                    }
                },
                onOpenKeyRotation: {
                    onboardingSheetMode = OnboardingSheetModeWrapper(mode: .keyRotation)
                },
                onConfirmResetIdentity: {
                    confirmRevokedReset = true
                }
            )
            Divider()
            stateMainContent
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(18)
        .background(MeshPalette.surfaceBackground)
        .sheet(item: $onboardingSheetMode) { wrapper in
            OnboardingSheetView(store: store, mode: wrapper.mode)
                .preferredColorScheme(themeManager.preferredColorScheme)
        }
        .sheet(isPresented: $showDiagnosticsSheet) {
            DiagnosticsSheetView(
                store: store,
                themeManager: themeManager,
                showCloseButton: true
            )
            .frame(minWidth: 620, minHeight: 520)
            .preferredColorScheme(themeManager.preferredColorScheme)
        }
        .alert("Reset Device Identity?", isPresented: $confirmRevokedReset) {
            Button("Cancel", role: .cancel) {}
            Button("Reset Identity", role: .destructive) {
                Task { @MainActor in
                    _ = await store.resetIdentity()
                }
            }
        } message: {
            Text(
                "Removes local WireGuard/control credentials so you can enroll again with a "
                    + "fresh pre-auth key."
            )
        }
    }

    private var topHeaderBar: some View {
        HStack(spacing: 12) {
            Image(systemName: store.menuBarGroup.symbolName)
                .font(.title2)
                .foregroundStyle(statusTintColor)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text("Mesh VPN")
                        .font(.title2.weight(.semibold))
                    Text("v\(AgentDefaults.appBundleVersion)")
                        .font(.caption.monospaced())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.12), in: Capsule())
                }
                Text(headerStatusSubtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if store.isBusy {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    if let msg = store.busyMessage {
                        Text(msg).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            Toggle(
                "Launch at Login",
                isOn: Binding(
                    get: { store.launchAtLoginEnabled },
                    set: { store.setLaunchAtLogin($0) }
                )
            )
            .toggleStyle(.checkbox)

            Button {
                Task { @MainActor in await store.refreshNow() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(store.isBusy)

            if !store.uiState.isEnrolledState {
                Button("Diagnostics...") { showDiagnosticsSheet = true }
            }
        }
    }

    @ViewBuilder
    private var stateMainContent: some View {
        if store.uiState.isEnrolledState {
            enrolledNavigationContent
        } else {
            nonEnrolledCardContent
        }
    }

    private var enrolledNavigationContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            ConnectedHeroSummaryView(
                store: store,
                onOpenKeyRotation: {
                    onboardingSheetMode = OnboardingSheetModeWrapper(mode: .keyRotation)
                },
                onConfirmResetIdentity: {
                    confirmRevokedReset = true
                }
            )
            Picker("Section", selection: $activeTab) {
                Text(DesktopTabKind.status.rawValue)
                    .tag(DesktopTabKind.status)
                Text("Peers (\(store.onlinePeerCount)/\(store.sortedPeers.count))")
                    .tag(DesktopTabKind.peers)
                Text(DesktopTabKind.diagnostics.rawValue)
                    .tag(DesktopTabKind.diagnostics)
            }
            .pickerStyle(.segmented)

            switch activeTab {
            case .status:
                StatusTabView(
                    store: store,
                    onOpenKeyRotation: {
                        onboardingSheetMode = OnboardingSheetModeWrapper(mode: .keyRotation)
                    },
                    onConfirmResetIdentity: {
                        confirmRevokedReset = true
                    },
                    onOpenDiagnostics: {
                        activeTab = .diagnostics
                    }
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .peers:
                PeersTableView(store: store)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .diagnostics:
                DiagnosticsSheetView(
                    store: store,
                    themeManager: themeManager,
                    showCloseButton: false
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    @ViewBuilder
    private var nonEnrolledCardContent: some View {
        switch store.uiState {
        case .serviceNotInstalled:
            DashboardCenteredCard(
                icon: "shield.slash",
                tintColor: statusTintColor,
                title: "Background Service Not Installed",
                subtitle: "Mesh VPN requires the privileged meshd LaunchDaemon "
                    + "(\(AgentDefaults.launchdLabel)) to manage utun tunnels and routes."
            ) {
                Toggle(
                    "Add macOS Application Firewall exception for meshd (recommended for P2P)",
                    isOn: $firewallOptInOnInstall
                )
                Button("Install Background Service") {
                    Task { @MainActor in
                        _ = await store.installOrUpdateService(
                            firewallOptIn: firewallOptInOnInstall
                        )
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
                Text("CLI alternative: sudo /bin/sh scripts/install-macos.sh")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        case .serviceStopped:
            DashboardCenteredCard(
                icon: "pause.circle",
                tintColor: statusTintColor,
                title: "Background Service Is Stopped",
                subtitle: "meshd is installed at \(AgentDefaults.daemonBinaryPath), "
                    + "but is not listening on \(AgentDefaults.roSocketPath)."
            ) {
                HStack(spacing: 12) {
                    Button("Start Background Service") {
                        Task { @MainActor in _ = await store.startOrRepairService() }
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Reinstall / Update Service") {
                        Task { @MainActor in
                            _ = await store.installOrUpdateService(firewallOptIn: true)
                        }
                    }
                }
                .disabled(store.isBusy)
            }
        case .unconfigured:
            DashboardCenteredCard(
                icon: "link.badge.plus",
                tintColor: statusTintColor,
                title: "Ready to Join a Mesh Network",
                subtitle: "Paste a mesh://join URI or enter your Control server endpoint and pin."
            ) {
                Button("Enroll Device...") {
                    onboardingSheetMode = OnboardingSheetModeWrapper(mode: .initialEnrollment)
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            }
        case .connecting, .connected, .reauthRequired, .revoked, .error:
            EmptyView()
        }
    }

    private var headerStatusSubtitle: String {
        store.uiState.resolvedTitle(
            isDegradedTunnel: store.isDegradedTunnel,
            isManuallyDisconnected: store.isManuallyDisconnected
        )
    }

    private var statusTintColor: Color {
        MeshPalette.color(for: store.menuBarGroup)
    }
}
