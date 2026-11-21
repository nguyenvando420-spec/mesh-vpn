import MeshCoreKit
import SwiftUI

/// Onboarding screen offering QR Scan, iOS 16+ `PasteButton` / iOS 15 paste, and Manual join.
struct OnboardingView: View {
    @ObservedObject var viewModel: AppViewModel
    @EnvironmentObject var localeManager: LocaleManager
    @State private var isShowingScanner = false

    var body: some View {
        let locale = localeManager.resolvedLocale
        NavigationView {
            Form {
                quickJoinSection(locale: locale)
                manualEnrollmentSection(locale: locale)
                languageSection(locale: locale)
            }
            .navigationTitle(L10n.tr("action.enroll", locale: locale))
            .sheet(isPresented: $isShowingScanner) {
                QrScannerSheetView(
                    onScan: { rawCode in
                        isShowingScanner = false
                        viewModel.prepareJoinFromUri(rawCode, isRotation: false)
                    },
                    onCancel: {
                        isShowingScanner = false
                    }
                )
                .environment(\.locale, locale)
            }
            .sheet(item: $viewModel.pendingConfirmation) { draft in
                EnrollmentConfirmationSheet(
                    draft: draft,
                    isBusy: viewModel.isBusy,
                    onCancel: { viewModel.cancelPendingEnrollment() },
                    onConfirm: {
                        Task {
                            await viewModel.confirmPendingEnrollment()
                        }
                    }
                )
                .environment(\.locale, locale)
            }
        }
        .navigationViewStyle(.stack)
    }

    private func quickJoinSection(locale: Locale) -> some View {
        Section {
            Button {
                isShowingScanner = true
            } label: {
                Label(
                    L10n.tr("action.scan_qr", locale: locale),
                    systemImage: "qrcode.viewfinder"
                )
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            pasteJoinControl(locale: locale)
        } header: {
            Text(L10n.tr("onboarding.import_uri", locale: locale))
        } footer: {
            Text(L10n.tr("onboarding.subtitle", locale: locale))
        }
    }

    private func manualEnrollmentSection(locale: Locale) -> some View {
        Section {
            TextField(
                L10n.tr("onboarding.control_server", locale: locale),
                text: $viewModel.manualServerEndpoint
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .keyboardType(.URL)

            TextField(
                L10n.inline(en: "Port (optional)", vi: "Cổng (tùy chọn)", locale: locale),
                text: $viewModel.manualPortText
            )
            .keyboardType(.numberPad)

            Picker(
                L10n.tr("settings.server_tls", locale: locale),
                selection: $viewModel.manualTlsAuthMode
            ) {
                Text(L10n.tr("onboarding.tls_spki_pin", locale: locale))
                    .tag(MobileTlsAuthMode.spkiPin)
                Text(L10n.tr("onboarding.tls_system_ca", locale: locale))
                    .tag(MobileTlsAuthMode.systemCa)
            }

            if viewModel.manualTlsAuthMode == .spkiPin {
                TextField(
                    L10n.tr("onboarding.spki_pin_label", locale: locale),
                    text: $viewModel.manualServerPin
                )
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            }

            SecureField(
                L10n.tr("onboarding.preauth_key", locale: locale),
                text: $viewModel.manualPreauthKey
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()

            TextField(
                L10n.tr("onboarding.node_name", locale: locale),
                text: $viewModel.manualNodeName
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()

            Button {
                viewModel.prepareManualEnrollment(isRotation: false)
            } label: {
                if viewModel.isBusy {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                } else {
                    Text(L10n.tr("onboarding.review_server", locale: locale))
                        .frame(maxWidth: .infinity)
                }
            }
            .disabled(viewModel.isBusy)
        } header: {
            Text(L10n.tr("onboarding.tab.manual", locale: locale))
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

    @ViewBuilder
    private func pasteJoinControl(locale: Locale) -> some View {
        if #available(iOS 16.0, *) {
            PasteButton(payloadType: String.self) { payloads in
                if let first = payloads.first {
                    viewModel.handlePastedText(first)
                }
            }
            .labelStyle(.titleAndIcon)
        } else {
            Button {
                viewModel.pasteFromSystemClipboard()
            } label: {
                Label(
                    L10n.tr("onboarding.paste_clipboard", locale: locale),
                    systemImage: "doc.on.clipboard"
                )
            }
        }
    }
}

/// Mandatory review sheet confirming Control endpoint, TLS trust policy, and masked token.
@MainActor
struct EnrollmentConfirmationSheet: View {
    let draft: EnrollmentConfirmationDraft
    let isBusy: Bool
    let onCancel: @MainActor () -> Void
    let onConfirm: @MainActor () -> Void
    @Environment(\.locale) private var locale

    var body: some View {
        NavigationView {
            List {
                Section(L10n.tr("confirm.verify_server", locale: locale)) {
                    LabeledRow(
                        label: L10n.tr("onboarding.control_server", locale: locale),
                        value: draft.serverEndpoint
                    )
                    let tlsKey = draft.tlsAuthMode == .spkiPin
                        ? "onboarding.tls_spki_pin"
                        : "onboarding.tls_system_ca"
                    LabeledRow(
                        label: L10n.tr("settings.server_tls", locale: locale),
                        value: L10n.tr(tlsKey, locale: locale)
                    )
                    let fallbackPin = L10n.tr("onboarding.tls_system_ca", locale: locale)
                    LabeledRow(
                        label: L10n.tr("onboarding.spki_pin_label", locale: locale),
                        value: draft.serverPin ?? fallbackPin
                    )
                }

                let credKey = draft.isRotation ? "confirm.rotation" : "confirm.enrollment"
                Section(L10n.tr(credKey, locale: locale)) {
                    LabeledRow(
                        label: L10n.tr("onboarding.preauth_key", locale: locale),
                        value: draft.maskedPreauthPreview
                    )
                    LabeledRow(
                        label: L10n.tr("onboarding.node_name", locale: locale),
                        value: draft.nodeName ?? "Auto"
                    )
                    let actionKey = draft.isRotation ? "action.rotate_key" : "action.enroll"
                    LabeledRow(
                        label: L10n.tr("confirm.verify_before_enroll", locale: locale),
                        value: L10n.tr(actionKey, locale: locale)
                    )
                }

                Section {
                    Button {
                        onConfirm()
                    } label: {
                        if isBusy {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            let btnKey = draft.isRotation
                                ? "confirm.confirm_rotation"
                                : "onboarding.trust_enroll"
                            Text(L10n.tr(btnKey, locale: locale))
                                .fontWeight(.semibold)
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(isBusy)
                }
            }
            .navigationTitle(L10n.tr("action.confirm_server", locale: locale))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.tr("generic.cancel", locale: locale), action: onCancel)
                        .disabled(isBusy)
                }
            }
        }
    }
}

private struct LabeledRow: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.body.monospaced())
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }
}
