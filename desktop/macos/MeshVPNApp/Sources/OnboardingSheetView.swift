import AppKit
import MeshDesktopCore
import SwiftUI

/// Enrollment mode shared by initial onboarding and key rotation (`ReauthRequired`).
enum OnboardingMode: Equatable {
    case initialEnrollment
    case keyRotation
}

/// Non-sandboxed macOS onboarding & key-rotation sheet with clipboard wipe and IP pin lock.
struct OnboardingSheetView: View {
    @ObservedObject var store: DesktopStore
    let mode: OnboardingMode
    @EnvironmentObject private var localeManager: LocaleManager
    @Environment(\.dismiss) private var dismiss

    @State private var selectedTab: OnboardingTab = .joinUri
    @State private var rawEndpoint: String = ""
    @State private var rawPortOverride: String = ""
    @State private var tlsAuthMode: TlsAuthMode = .spkiPin
    @State private var rawServerPin: String = ""
    @State private var rawPreauthKey: String = ""
    @State private var rawNodeName: String = ""
    @State private var pastedUriPreview: String = ""

    private var loc: Locale { localeManager.effectiveLocale }

    private enum OnboardingTab: String, CaseIterable, Identifiable {
        case joinUri
        case manualForm

        var id: String { rawValue }

        func localizedTitle(locale: Locale) -> String {
            switch self {
            case .joinUri: return MeshL10n.tr("onboarding.desktop.tab.join_uri", locale: locale)
            case .manualForm: return MeshL10n.tr("onboarding.desktop.tab.manual", locale: locale)
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            headerSection
            if let error = store.lastActionError {
                inlineErrorBanner(error)
            }
            if let draft = store.pendingEnrollmentDraft {
                EnrollmentConfirmationSection(
                    draft: draft,
                    isBusy: store.isBusy,
                    locale: loc,
                    onCancel: {
                        store.cancelEnrollmentDraft()
                    },
                    onConfirm: {
                        Task { @MainActor in
                            let succeeded = await store.confirmEnrollmentDraft()
                            if succeeded {
                                rawPreauthKey = ""
                                pastedUriPreview = ""
                                dismiss()
                            }
                        }
                    }
                )
            } else {
                draftInputSection
            }
        }
        .padding(20)
        .frame(minWidth: 520, idealWidth: 560)
    }

    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(
                    mode == .keyRotation
                        ? MeshL10n.tr("rotation.title", locale: loc)
                        : MeshL10n.tr("onboarding.desktop.title", locale: loc)
                )
                .font(.title2.weight(.semibold))
                Text(headerSubtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(MeshL10n.tr("generic.close", locale: loc)) {
                store.cancelEnrollmentDraft()
                rawPreauthKey = ""
                pastedUriPreview = ""
                dismiss()
            }
            .keyboardShortcut(.cancelAction)
        }
    }

    private var headerSubtitle: String {
        if mode == .keyRotation {
            return MeshL10n.tr("rotation.subtitle", locale: loc)
        }
        return MeshL10n.tr("onboarding.desktop.subtitle", locale: loc)
    }

    @ViewBuilder
    private var draftInputSection: some View {
        if mode == .initialEnrollment {
            Picker("", selection: $selectedTab) {
                ForEach(OnboardingTab.allCases) { tab in
                    Text(tab.localizedTitle(locale: loc)).tag(tab)
                }
            }
            .pickerStyle(.segmented)

            switch selectedTab {
            case .joinUri:
                joinUriInputForm
            case .manualForm:
                manualEnrollmentForm
            }
        } else {
            keyRotationForm
        }
    }

    private var joinUriInputForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(MeshL10n.tr("onboarding.import_uri", locale: loc))
                .font(.callout)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                PasteButton(payloadType: String.self) { items in
                    if let first = items.first {
                        handleJoinUriPaste(first)
                    }
                }
                Button(MeshL10n.tr("onboarding.paste_clipboard", locale: loc)) {
                    if let clip = NSPasteboard.general.string(forType: .string) {
                        handleJoinUriPaste(clip)
                    }
                }
                Spacer()
            }

            SecureField(MeshL10n.tr("onboarding.or_enter_uri", locale: loc), text: uriInputBinding)
                .textFieldStyle(.roundedBorder)

            if !pastedUriPreview.isEmpty {
                Text("Preview (redacted): \(MeshSecretScrubber.scrub(pastedUriPreview))")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            HStack {
                Spacer()
                Button(MeshL10n.tr("onboarding.desktop.review", locale: loc)) {
                    _ = store.handlePastedOnboardingInput(pastedUriPreview)
                }
                .buttonStyle(.borderedProminent)
                .disabled(pastedUriPreview.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
    }

    private var uriInputBinding: Binding<String> {
        Binding(
            get: { pastedUriPreview },
            set: { newValue in
                pastedUriPreview = newValue
                if MeshSecretScrubber.containsSecretPattern(newValue) {
                    store.clipboardAutoClear.scheduleWipeIfClipboardMatchesFieldText(newValue)
                }
            }
        )
    }

    private var endpointInputBinding: Binding<String> {
        Binding(
            get: { rawEndpoint },
            set: { newValue in
                rawEndpoint = newValue
                if isCurrentEndpointIpLiteral {
                    tlsAuthMode = .spkiPin
                }
            }
        )
    }

    private var preauthKeyBinding: Binding<String> {
        Binding(
            get: { rawPreauthKey },
            set: { newValue in
                rawPreauthKey = newValue
                store.handleManualPreauthKeyChange(newValue)
            }
        )
    }

    private var isCurrentEndpointIpLiteral: Bool {
        if let normalized = try? EndpointNormalizer.normalize(rawEndpoint) {
            return normalized.isIpLiteral
        }
        return EndpointNormalizer.isIpLiteralHost(rawEndpoint)
    }

    private var manualEnrollmentForm: some View {
        Form {
            TextField(
                MeshL10n.tr("onboarding.control_server", locale: loc),
                text: endpointInputBinding
            )
            .textFieldStyle(.roundedBorder)

            if let preview = normalizedEndpointPreview {
                Text("Normalized target: \(preview)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }

            TextField("Port Override (optional, defaults to 443)", text: $rawPortOverride)
                .textFieldStyle(.roundedBorder)

            Picker("TLS", selection: $tlsAuthMode) {
                Text(MeshL10n.tr("onboarding.tls_spki_pin", locale: loc)).tag(TlsAuthMode.spkiPin)
                Text(MeshL10n.tr("onboarding.tls_system_ca", locale: loc)).tag(TlsAuthMode.systemCa)
                    .disabled(isCurrentEndpointIpLiteral)
            }
            .disabled(isCurrentEndpointIpLiteral)

            if isCurrentEndpointIpLiteral {
                Text("IP literal endpoints require SPKI SHA-256 pinning (`System CA` disabled).")
                    .font(.caption)
                    .foregroundStyle(MeshPalette.semanticWarning)
            }

            if tlsAuthMode == .spkiPin || isCurrentEndpointIpLiteral {
                TextField(
                    MeshL10n.tr("onboarding.spki_pin_label", locale: loc),
                    text: $rawServerPin
                )
                .textFieldStyle(.roundedBorder)
                .font(.body.monospaced())
            }

            SecureField(MeshL10n.tr("onboarding.preauth_key", locale: loc), text: preauthKeyBinding)
                .textFieldStyle(.roundedBorder)

            TextField(MeshL10n.tr("onboarding.node_name", locale: loc), text: $rawNodeName)
                .textFieldStyle(.roundedBorder)

            HStack {
                Spacer()
                Button(MeshL10n.tr("onboarding.desktop.review", locale: loc)) {
                    let input = ManualOnboardingInput(
                        rawEndpoint: rawEndpoint,
                        rawPortOverride: rawPortOverride,
                        tlsAuthMode: isCurrentEndpointIpLiteral ? .spkiPin : tlsAuthMode,
                        rawServerPin: rawServerPin,
                        rawPreauthKey: rawPreauthKey,
                        rawNodeName: rawNodeName
                    )
                    _ = store.prepareDraftFromManualForm(input)
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .formStyle(.grouped)
    }

    private var keyRotationForm: some View {
        Form {
            if let endpoint = store.status?.serverConnection?.controlEndpoint {
                LabeledContent(MeshL10n.tr("label.control", locale: loc), value: endpoint)
            }
            SecureField(MeshL10n.tr("rotation.new_key", locale: loc), text: preauthKeyBinding)
                .textFieldStyle(.roundedBorder)

            HStack {
                PasteButton(payloadType: String.self) { items in
                    if let first = items.first {
                        applyRotationClipboardPaste(first)
                    }
                }
                Button(MeshL10n.tr("onboarding.paste_clipboard", locale: loc)) {
                    if let clip = NSPasteboard.general.string(forType: .string) {
                        applyRotationClipboardPaste(clip)
                    }
                }
                Spacer()
                Button(MeshL10n.tr("rotation.review_key", locale: loc)) {
                    _ = store.prepareKeyRotationDraft(rawPreauthKey: rawPreauthKey)
                }
                .buttonStyle(.borderedProminent)
                .disabled(rawPreauthKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .formStyle(.grouped)
    }

    private var normalizedEndpointPreview: String? {
        let trimmed = rawEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        let portText = rawPortOverride.trimmingCharacters(in: .whitespacesAndNewlines)
        let parsedPort: UInt16? = portText.isEmpty
            ? nil
            : try? EndpointNormalizer.parseStrictPort(portText)
        return (try? EndpointNormalizer.normalize(trimmed, portOverride: parsedPort))?.endpoint
    }

    private func handleJoinUriPaste(_ text: String) {
        pastedUriPreview = MeshSecretScrubber.scrub(
            text.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        _ = store.handlePastedOnboardingInput(text)
    }

    private func applyRotationClipboardPaste(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        rawPreauthKey = trimmed
        store.clipboardAutoClear.recordAndScheduleWipe(text: text)
        _ = store.prepareKeyRotationDraft(rawPreauthKey: trimmed)
    }

    private func inlineErrorBanner(_ error: DesktopUserFacingError) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(MeshPalette.semanticError)
            VStack(alignment: .leading, spacing: 2) {
                Text(error.title).font(.headline)
                Text(error.message).font(.callout)
            }
            Spacer()
            Button(MeshL10n.tr("generic.dismiss", locale: loc)) {
                store.dismissError()
            }
            .buttonStyle(.borderless)
        }
        .padding(10)
        .background(
            MeshPalette.semanticError.opacity(0.10),
            in: RoundedRectangle(cornerRadius: 8)
        )
    }
}

/// Out-of-band confirmation sheet showing full SPKI pin & masked key prior to daemon call.
private struct EnrollmentConfirmationSection: View {
    let draft: EnrollmentConfirmationDraft
    let isBusy: Bool
    let locale: Locale
    let onCancel: () -> Void
    let onConfirm: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(
                draft.isRotation
                    ? MeshL10n.tr("confirm.confirm_rotation", locale: locale)
                    : MeshL10n.tr("confirm.verify_before_enroll", locale: locale)
            )
            .font(.headline)

            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    LabeledContent(
                        MeshL10n.tr("label.control", locale: locale),
                        value: draft.serverEndpoint
                    )
                    LabeledContent(
                        "TLS",
                        value: draft.tlsAuthMode == .spkiPin
                            ? MeshL10n.tr("onboarding.tls_spki_pin", locale: locale)
                            : MeshL10n.tr("onboarding.tls_system_ca", locale: locale)
                    )
                    if let pin = draft.serverPin {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(MeshL10n.tr("onboarding.spki_pin_label", locale: locale))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(pin)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                    LabeledContent(
                        MeshL10n.tr("onboarding.node_name", locale: locale),
                        value: draft.nodeName ?? "(OS hostname)"
                    )
                    LabeledContent(
                        MeshL10n.tr("onboarding.preauth_key", locale: locale),
                        value: draft.maskedPreauthPreview
                    )
                }
                .padding(6)
            }

            HStack {
                Button(MeshL10n.tr("confirm.back_edit", locale: locale)) {
                    onCancel()
                }
                Spacer()
                Button(
                    draft.isRotation
                        ? MeshL10n.tr("rotation.rotate_reconnect", locale: locale)
                        : MeshL10n.tr("confirm.trust_connect", locale: locale)
                ) {
                    onConfirm()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isBusy)
            }
        }
    }
}
