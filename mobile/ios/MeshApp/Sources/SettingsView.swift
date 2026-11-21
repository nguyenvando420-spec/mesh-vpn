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
        let locale = localeManager.resolvedLocale
        NavigationView {
            Form {
                appearanceSection(locale: locale)
                languageSection(locale: locale)
                diagnosticsSection(locale: locale)
                maintenanceSection(locale: locale)
            }
            .navigationTitle(L10n.tr("tab.settings", locale: locale))
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
                .environment(\.locale, locale)
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
                .environment(\.locale, locale)
            }
            .confirmationDialog(
                L10n.tr("confirm.reset", locale: locale),
                isPresented: $isShowingResetConfirm,
                titleVisibility: .visible
            ) {
                Button(L10n.tr("action.reset_identity", locale: locale), role: .destructive) {
                    Task { await viewModel.resetIdentity() }
                }
                Button(L10n.tr("generic.cancel", locale: locale), role: .cancel) {}
            } message: {
                Text(L10n.tr("confirm.reset_detail", locale: locale))
            }
        }
        .navigationViewStyle(.stack)
    }

    private func appearanceSection(locale: Locale) -> some View {
        Section(L10n.tr("theme.appearance", locale: locale)) {
            Picker(
                L10n.tr("theme.appearance", locale: locale),
                selection: $themeManager.themeMode
            ) {
                ForEach(ThemeMode.allCases, id: \.self) { mode in
                    Text(themeLabel(for: mode, locale: locale)).tag(mode)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    private func languageSection(locale: Locale) -> some View {
        Section(L10n.tr("locale.language", locale: locale)) {
            Picker(
                L10n.tr("locale.language", locale: locale),
                selection: $localeManager.localeMode
            ) {
                ForEach([LocaleMode.system, .vi, .en], id: \.self) { mode in
                    Text(mode.localizedTitle(locale: locale)).tag(mode)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    private func diagnosticsSection(locale: Locale) -> some View {
        Section(L10n.tr("settings.diag_title", locale: locale)) {
            Button {
                Task { await viewModel.runNetcheck() }
            } label: {
                Label(L10n.tr("action.run_netcheck", locale: locale), systemImage: "network")
            }
            .disabled(viewModel.tunnelStatus != .connected || viewModel.isBusy)

            if let netcheck = viewModel.lastNetcheckResponse {
                VStack(alignment: .leading, spacing: 4) {
                    Text("NAT: \(String(describing: netcheck.natType))")
                        .font(.subheadline)
                    let relayKey = netcheck.relayConnected
                        ? "state.connected"
                        : "peers.badge.offline"
                    let relayText = L10n.tr(relayKey, locale: locale)
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
                Label(
                    L10n.tr("action.export_bugreport", locale: locale),
                    systemImage: "square.and.arrow.up"
                )
            }
            .disabled(viewModel.isBusy)
        }
    }

    private func maintenanceSection(locale: Locale) -> some View {
        Section(L10n.tr("settings.section_header", locale: locale)) {
            if let summary = viewModel.bootstrapSummary {
                LabeledValueRow(
                    title: L10n.tr("label.control", locale: locale),
                    value: summary.serverEndpoint
                )
                let tlsKey = summary.tlsAuthMode == .spkiPin
                    ? "onboarding.tls_spki_pin"
                    : "onboarding.tls_system_ca"
                LabeledValueRow(
                    title: L10n.tr("settings.server_tls", locale: locale),
                    value: L10n.tr(tlsKey, locale: locale)
                )
            }
            LabeledValueRow(title: "Version", value: MeshConstants.agentVersion)

            Button {
                rotationTokenInput = ""
                isShowingRotateSheet = true
            } label: {
                Label(L10n.tr("action.rotate_key", locale: locale), systemImage: "key.fill")
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
                Label(L10n.tr("action.update_server", locale: locale), systemImage: "server.rack")
            }
            .disabled(viewModel.isBusy)

            Button(role: .destructive) {
                isShowingResetConfirm = true
            } label: {
                Label(L10n.tr("action.reset_identity", locale: locale), systemImage: "trash")
            }
            .disabled(viewModel.isBusy)
        }
    }

    private func themeLabel(for mode: ThemeMode, locale: Locale) -> String {
        switch mode {
        case .system: return L10n.tr("theme.system", locale: locale)
        case .light: return L10n.tr("theme.light", locale: locale)
        case .dark: return L10n.tr("theme.dark", locale: locale)
        }
    }
}

@MainActor
private struct RotateKeyPromptSheet: View {
    @Binding var tokenInput: String
    let onCancel: @MainActor () -> Void
    let onContinue: @MainActor () -> Void
    @Environment(\.locale) private var locale

    var body: some View {
        NavigationView {
            Form {
                Section(L10n.tr("onboarding.preauth_key", locale: locale)) {
                    SecureField("mpk_...", text: $tokenInput)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section {
                    let trimmedToken = tokenInput.trimmingCharacters(in: .whitespacesAndNewlines)
                    Button(L10n.tr("action.review_rotation", locale: locale), action: onContinue)
                        .disabled(trimmedToken.isEmpty)
                }
            }
            .navigationTitle(L10n.tr("action.rotate_key", locale: locale))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.tr("generic.cancel", locale: locale), action: onCancel)
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
    @Environment(\.locale) private var locale

    var body: some View {
        NavigationView {
            Form {
                Section(L10n.tr("onboarding.control_server", locale: locale)) {
                    TextField("host:port", text: $endpoint)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                    Picker(L10n.tr("settings.server_tls", locale: locale), selection: $tlsMode) {
                        Text(L10n.tr("onboarding.tls_spki_pin", locale: locale))
                            .tag(MobileTlsAuthMode.spkiPin)
                        Text(L10n.tr("onboarding.tls_system_ca", locale: locale))
                            .tag(MobileTlsAuthMode.systemCa)
                    }
                    if tlsMode == .spkiPin {
                        TextField("sha256:...", text: $serverPin)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                }
                Section {
                    Button(L10n.tr("action.verify_save", locale: locale), action: onSave)
                }
            }
            .navigationTitle(L10n.tr("settings.update_server", locale: locale))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.tr("generic.cancel", locale: locale), action: onCancel)
                }
            }
        }
    }
}
