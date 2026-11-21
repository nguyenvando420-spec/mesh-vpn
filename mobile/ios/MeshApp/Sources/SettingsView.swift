import MeshCoreKit
import SwiftUI

/// Zone 3 tab hosting appearance/locale preferences, diagnostics, and security maintenance.
@MainActor
struct SettingsView: View {
    @ObservedObject var viewModel: AppViewModel
    @EnvironmentObject var themeManager: ThemeManager
    @EnvironmentObject var localeManager: LocaleManager

    @State private var isShowingRotateSheet = false
    @State private var isShowingServerEditSheet = false
    @State private var isShowingResetConfirm = false
    @State private var rotationTokenInput = ""
    @State private var editServerEndpoint = ""
    @State private var editServerTlsMode: MobileTlsAuthMode = .spkiPin
    @State private var editServerPin = ""

    var body: some View {
        NavigationView {
            Form {
                appearanceSection
                languageSection
                diagnosticsSection
                maintenanceSection
            }
            .navigationTitle("Settings")
            .sheet(isPresented: $isShowingRotateSheet) {
                RotateKeyPromptSheet(
                    tokenInput: $rotationTokenInput,
                    onCancel: {
                        rotationTokenInput = ""
                        isShowingRotateSheet = false
                    },
                    onContinue: {
                        let captured = rotationTokenInput
                        rotationTokenInput = ""
                        isShowingRotateSheet = false
                        viewModel.manualPreauthKey = captured
                        viewModel.prepareManualEnrollment(isRotation: true)
                    }
                )
            }
            .sheet(isPresented: $isShowingServerEditSheet) {
                UpdateServerSheet(
                    endpoint: $editServerEndpoint,
                    tlsMode: $editServerTlsMode,
                    serverPin: $editServerPin,
                    onCancel: { isShowingServerEditSheet = false },
                    onSave: {
                        isShowingServerEditSheet = false
                        let pinToApply = editServerTlsMode == .spkiPin ? editServerPin : nil
                        Task {
                            await viewModel.updateServerEndpoint(
                                endpoint: editServerEndpoint,
                                tlsAuthMode: editServerTlsMode,
                                serverPin: pinToApply
                            )
                        }
                    }
                )
            }
            .confirmationDialog(
                "Reset Device Identity?",
                isPresented: $isShowingResetConfirm,
                titleVisibility: .visible
            ) {
                Button("Reset & Delete Local Keys", role: .destructive) {
                    Task { await viewModel.resetIdentity() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes the VPN profile, sealed node keys, and Keychain DEK.")
            }
        }
        .navigationViewStyle(.stack)
    }

    private var appearanceSection: some View {
        Section("Appearance") {
            Picker("Theme", selection: $themeManager.themeMode) {
                ForEach(ThemeMode.allCases, id: \.self) { mode in
                    Text(mode.displayTitle).tag(mode)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    private var languageSection: some View {
        Section("Language") {
            Picker("Language", selection: $localeManager.localeMode) {
                ForEach(LocaleMode.allCases, id: \.self) { mode in
                    Text(mode.displayTitle).tag(mode)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    private var diagnosticsSection: some View {
        Section("Diagnostics") {
            Button {
                Task { await viewModel.runNetcheck() }
            } label: {
                Label("Run UDP & NAT Netcheck", systemImage: "network")
            }
            .disabled(viewModel.tunnelStatus != .connected || viewModel.isBusy)

            if let netcheck = viewModel.lastNetcheckResponse {
                VStack(alignment: .leading, spacing: 4) {
                    Text("NAT: \(String(describing: netcheck.natType))")
                        .font(.subheadline)
                    let relayText = netcheck.relayConnected ? "Connected" : "Offline"
                    let udpText = netcheck.udpReachable ? "Reachable" : "Blocked"
                    Text("UDP: \(udpText) | Relay: \(relayText)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let mapped = netcheck.mappedEndpoint {
                        Text("Mapped: \(mapped)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Button {
                Task { await viewModel.exportBugreport() }
            } label: {
                Label("Export Redacted Bugreport", systemImage: "square.and.arrow.up")
            }
            .disabled(viewModel.isBusy)
        }
    }

    private var maintenanceSection: some View {
        Section("Security & Maintenance") {
            if let summary = viewModel.bootstrapSummary {
                LabeledValueRow(title: "Control", value: summary.serverEndpoint)
                LabeledValueRow(
                    title: "TLS Mode",
                    value: summary.tlsAuthMode == .spkiPin ? "SPKI Pin" : "System CA"
                )
            }
            LabeledValueRow(title: "Version", value: MeshConstants.agentVersion)

            Button {
                rotationTokenInput = ""
                isShowingRotateSheet = true
            } label: {
                Label("Rotate Node Key", systemImage: "key.fill")
            }
            .disabled(viewModel.isBusy)

            Button {
                if let summary = viewModel.bootstrapSummary {
                    editServerEndpoint = summary.serverEndpoint
                    editServerTlsMode = summary.tlsAuthMode
                    editServerPin = summary.activePin ?? ""
                }
                isShowingServerEditSheet = true
            } label: {
                Label("Update Control Server", systemImage: "server.rack")
            }
            .disabled(viewModel.isBusy)

            Button(role: .destructive) {
                isShowingResetConfirm = true
            } label: {
                Label("Reset Device Identity", systemImage: "trash")
            }
            .disabled(viewModel.isBusy)
        }
    }
}

@MainActor
private struct RotateKeyPromptSheet: View {
    @Binding var tokenInput: String
    let onCancel: @MainActor () -> Void
    let onContinue: @MainActor () -> Void

    var body: some View {
        NavigationView {
            Form {
                Section("Pre-Auth Token") {
                    SecureField("mpk_...", text: $tokenInput)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section {
                    let trimmedToken = tokenInput.trimmingCharacters(in: .whitespacesAndNewlines)
                    Button("Review Rotation", action: onContinue)
                        .disabled(trimmedToken.isEmpty)
                }
            }
            .navigationTitle("Rotate Node Key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
        }
    }
}

@MainActor
private struct UpdateServerSheet: View {
    @Binding var endpoint: String
    @Binding var tlsMode: MobileTlsAuthMode
    @Binding var serverPin: String
    let onCancel: @MainActor () -> Void
    let onSave: @MainActor () -> Void

    var body: some View {
        NavigationView {
            Form {
                Section("Control Server") {
                    TextField("host:port", text: $endpoint)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    Picker("TLS Mode", selection: $tlsMode) {
                        Text("SPKI Pin").tag(MobileTlsAuthMode.spkiPin)
                        Text("System CA").tag(MobileTlsAuthMode.systemCa)
                    }
                    if tlsMode == .spkiPin {
                        TextField("sha256:...", text: $serverPin)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                }
                Section {
                    Button("Verify & Save", action: onSave)
                }
            }
            .navigationTitle("Update Server")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
        }
    }
}
