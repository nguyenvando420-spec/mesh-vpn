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
    @Environment(\.dismiss) private var dismiss

    @State private var selectedTab: OnboardingTab = .joinUri
    @State private var rawEndpoint: String = ""
    @State private var rawPortOverride: String = ""
    @State private var tlsAuthMode: TlsAuthMode = .spkiPin
    @State private var rawServerPin: String = ""
    @State private var rawPreauthKey: String = ""
    @State private var rawNodeName: String = ""
    @State private var pastedUriPreview: String = ""

    private enum OnboardingTab: String, CaseIterable, Identifiable {
        case joinUri = "Join URI"
        case manualForm = "Manual Setup"

        var id: String { rawValue }
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
                Text(mode == .keyRotation ? "Rotate Node Pre-Auth Key" : "Join Mesh VPN Network")
                    .font(.title2.weight(.semibold))
                Text(headerSubtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Close") {
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
            return "Provide a fresh mpk_ pre-auth key to renew this node's credentials."
        }
        return "Paste a mesh://join URI or enter your Control server details manually."
    }

    @ViewBuilder
    private var draftInputSection: some View {
        if mode == .initialEnrollment {
            Picker("Setup Method", selection: $selectedTab) {
                ForEach(OnboardingTab.allCases) { tab in
                    Text(tab.rawValue).tag(tab)
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
            Text("Paste an onboarding link (`mesh://join?v=1&ep=...&pin=...&key=mpk_...`).")
                .font(.callout)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                PasteButton(payloadType: String.self) { items in
                    if let first = items.first {
                        handleJoinUriPaste(first)
                    }
                }
                Button("Paste from Clipboard") {
                    if let clip = NSPasteboard.general.string(forType: .string) {
                        handleJoinUriPaste(clip)
                    }
                }
                Spacer()
            }

            SecureField("Or paste mesh://join?... URI here", text: uriInputBinding)
                .textFieldStyle(.roundedBorder)

            if !pastedUriPreview.isEmpty {
                Text("Preview (redacted): \(MeshSecretScrubber.scrub(pastedUriPreview))")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            HStack {
                Spacer()
                Button("Review Connection Details") {
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
            TextField("Control Endpoint (host or IP[:port])", text: endpointInputBinding)
                .textFieldStyle(.roundedBorder)

            if let preview = normalizedEndpointPreview {
                Text("Normalized target: \(preview)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }

            TextField("Port Override (optional, defaults to 443)", text: $rawPortOverride)
                .textFieldStyle(.roundedBorder)

            Picker("TLS Trust Mode", selection: $tlsAuthMode) {
                Text("SPKI SHA-256 Pin (Zero-TOFU)").tag(TlsAuthMode.spkiPin)
                Text("System CA (DNS Hostnames Only)").tag(TlsAuthMode.systemCa)
                    .disabled(isCurrentEndpointIpLiteral)
            }
            .disabled(isCurrentEndpointIpLiteral)

            if isCurrentEndpointIpLiteral {
                Text("IP literal endpoints require SPKI SHA-256 pinning (`System CA` disabled).")
                    .font(.caption)
                    .foregroundStyle(MeshPalette.semanticWarning)
            }

            if tlsAuthMode == .spkiPin || isCurrentEndpointIpLiteral {
                TextField("Server SPKI Pin (sha256:<64-hex>)", text: $rawServerPin)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
            }

            SecureField("Pre-Auth Key (mpk_...)", text: preauthKeyBinding)
                .textFieldStyle(.roundedBorder)

            TextField("Node Name (optional RFC 1123 hostname)", text: $rawNodeName)
                .textFieldStyle(.roundedBorder)

            HStack {
                Spacer()
                Button("Review Connection Details") {
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
                LabeledContent("Control Endpoint", value: endpoint)
            }
            SecureField("New Pre-Auth Key (mpk_...)", text: preauthKeyBinding)
                .textFieldStyle(.roundedBorder)

            HStack {
                PasteButton(payloadType: String.self) { items in
                    if let first = items.first {
                        applyRotationClipboardPaste(first)
                    }
                }
                Button("Paste Key") {
                    if let clip = NSPasteboard.general.string(forType: .string) {
                        applyRotationClipboardPaste(clip)
                    }
                }
                Spacer()
                Button("Review Key Rotation") {
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
            Button("Dismiss") {
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
    let onCancel: () -> Void
    let onConfirm: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(
                draft.isRotation
                    ? "Confirm Key Rotation"
                    : "Verify Server Trust Before Enrolling"
            )
            .font(.headline)

            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    LabeledContent("Control Endpoint", value: draft.serverEndpoint)
                    LabeledContent(
                        "TLS Mode",
                        value: draft.tlsAuthMode == .spkiPin
                            ? "SPKI SHA-256 Pin (Zero-TOFU)"
                            : "System CA"
                    )
                    if let pin = draft.serverPin {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Server SPKI Fingerprint")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(pin)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                    LabeledContent("Node Name", value: draft.nodeName ?? "(OS hostname)")
                    LabeledContent("Pre-Auth Key", value: draft.maskedPreauthPreview)
                }
                .padding(6)
            }

            HStack {
                Button("Back / Edit") {
                    onCancel()
                }
                Spacer()
                Button(draft.isRotation ? "Rotate Key & Reconnect" : "Trust & Connect") {
                    onConfirm()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isBusy)
            }
        }
    }
}
