import AppKit
import MeshDesktopCore
import SwiftUI

/// Single-instance Desktop Dashboard rendering all 8 UI states, warnings, peers, and settings.
struct DashboardWindowView: View {
    @ObservedObject var store: DesktopStore

    @State private var activeTab: DashboardTab = .peers
    @State private var onboardingSheetMode: OnboardingSheetModeWrapper?
    @State private var showDiagnosticsSheet: Bool = false
    @State private var firewallOptInOnInstall: Bool = true
    @State private var confirmRevokedReset: Bool = false

    private enum DashboardTab: String, CaseIterable, Identifiable {
        case peers = "Peers"
        case diagnostics = "Diagnostics & Settings"

        var id: String { rawValue }
    }

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
                    if store.uiState == .connected {
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
        .sheet(item: $onboardingSheetMode) { wrapper in
            OnboardingSheetView(store: store, mode: wrapper.mode)
        }
        .sheet(isPresented: $showDiagnosticsSheet) {
            DiagnosticsSheetView(store: store, showCloseButton: true)
                .frame(minWidth: 620, minHeight: 520)
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
                Text(store.uiState.displayTitle)
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

            if store.uiState != .connected {
                Button("Diagnostics...") { showDiagnosticsSheet = true }
            }
        }
    }

    @ViewBuilder
    private var stateMainContent: some View {
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
        case .connecting:
            DashboardCenteredCard(
                icon: "bolt.shield.fill",
                tintColor: statusTintColor,
                title: "Connecting to Mesh Network...",
                subtitle: "Establishing control session and utun interface for "
                    + "\(store.status?.serverConnection?.controlEndpoint ?? "Control server")."
            ) {
                ProgressView().padding(.vertical, 4)
                Button("Disconnect") {
                    Task { @MainActor in _ = await store.disconnect() }
                }
                .disabled(store.isBusy)
            }
        case .connected:
            VStack(alignment: .leading, spacing: 14) {
                ConnectedHeroSummaryView(store: store)
                Picker("Section", selection: $activeTab) {
                    Text("Peers (\(store.onlinePeerCount)/\(store.sortedPeers.count))")
                        .tag(DashboardTab.peers)
                    Text("Diagnostics & Settings")
                        .tag(DashboardTab.diagnostics)
                }
                .pickerStyle(.segmented)

                switch activeTab {
                case .peers:
                    PeersTableView(store: store)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                case .diagnostics:
                    DiagnosticsSheetView(store: store, showCloseButton: false)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        case .reauthRequired:
            DashboardCenteredCard(
                icon: "key.fill",
                tintColor: statusTintColor,
                title: "Node Pre-Auth Key Expired",
                subtitle: "Control server requires a fresh mpk_ pre-auth key to reconnect."
            ) {
                HStack(spacing: 12) {
                    Button("Rotate Pre-Auth Key...") {
                        onboardingSheetMode = OnboardingSheetModeWrapper(mode: .keyRotation)
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Disconnect") {
                        Task { @MainActor in _ = await store.disconnect() }
                    }
                }
                .disabled(store.isBusy)
            }
        case .revoked:
            DashboardCenteredCard(
                icon: "hand.raised.fill",
                tintColor: statusTintColor,
                title: "Device Revoked by Control Server",
                subtitle: "Reset local identity keys to re-enroll with a new pre-auth key."
            ) {
                Button("Reset Device Identity...", role: .destructive) {
                    confirmRevokedReset = true
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            }
        case .error:
            DashboardCenteredCard(
                icon: "exclamationmark.shield.fill",
                tintColor: statusTintColor,
                title: store.lastActionError?.title ?? "Daemon Communication Error",
                subtitle: store.lastActionError?.message
                    ?? "Unable to communicate with meshd admin socket."
            ) {
                HStack(spacing: 12) {
                    Button("Retry") {
                        Task { @MainActor in await store.refreshNow() }
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Start / Repair Service") {
                        Task { @MainActor in _ = await store.startOrRepairService() }
                    }
                    Button("Open Diagnostics...") { showDiagnosticsSheet = true }
                }
                .disabled(store.isBusy)
            }
        }
    }

    private var statusTintColor: Color {
        switch store.menuBarGroup {
        case .connected: return .green
        case .connectingOrDegraded: return .orange
        case .disconnected: return .secondary
        case .serviceOffline: return .secondary
        case .warning: return .red
        }
    }
}
