import MeshCoreKit
import SwiftUI

/// Onboarding screen offering QR Scan, iOS 16+ `PasteButton` / iOS 15 paste, and Manual join.
struct OnboardingView: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var isShowingScanner = false

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Button {
                        isShowingScanner = true
                    } label: {
                        Label("Scan Enrollment QR Code", systemImage: "qrcode.viewfinder")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    pasteJoinControl
                } header: {
                    Text("Quick Join")
                } footer: {
                    Text("mesh://join URIs are validated inside this app before confirmation.")
                }

                Section {
                    TextField("Control Endpoint (host:port)", text: $viewModel.manualServerEndpoint)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)

                    TextField("Port Override (optional)", text: $viewModel.manualPortText)
                        .keyboardType(.numberPad)

                    Picker("TLS Verification", selection: $viewModel.manualTlsAuthMode) {
                        Text("SPKI Pin (Default)").tag(MobileTlsAuthMode.spkiPin)
                        Text("System CA").tag(MobileTlsAuthMode.systemCa)
                    }

                    if viewModel.manualTlsAuthMode == .spkiPin {
                        TextField("SPKI Pin (sha256:...)", text: $viewModel.manualServerPin)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }

                    SecureField("Pre-Auth Token (mpk_...)", text: $viewModel.manualPreauthKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    TextField("Device Name (optional RFC 1123)", text: $viewModel.manualNodeName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    Button {
                        viewModel.prepareManualEnrollment(isRotation: false)
                    } label: {
                        if viewModel.isBusy {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            Text("Review & Enroll")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(viewModel.isBusy)
                } header: {
                    Text("Manual Enrollment")
                }
            }
            .navigationTitle("Enroll Mesh VPN")
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
            }
        }
        .navigationViewStyle(.stack)
    }

    @ViewBuilder
    private var pasteJoinControl: some View {
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
                Label("Paste Join URI or Token", systemImage: "doc.on.clipboard")
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

    var body: some View {
        NavigationView {
            List {
                Section("Server Trust Verification") {
                    LabeledRow(label: "Control Endpoint", value: draft.serverEndpoint)
                    LabeledRow(
                        label: "TLS Mode",
                        value: draft.tlsAuthMode == .spkiPin ? "Pinned SPKI SHA-256" : "System CA"
                    )
                    LabeledRow(
                        label: "SPKI Fingerprint",
                        value: draft.serverPin ?? "None (System CA)"
                    )
                }

                Section("Credential Summary") {
                    LabeledRow(label: "Token Preview", value: draft.maskedPreauthPreview)
                    LabeledRow(label: "Device Name", value: draft.nodeName ?? "Auto-generated")
                    LabeledRow(
                        label: "Action",
                        value: draft.isRotation ? "Rotate Existing Identity Key" : "Enroll New Node"
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
                            Text(draft.isRotation ? "Confirm Key Rotation" : "Confirm & Enroll")
                                .fontWeight(.semibold)
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .disabled(isBusy)
                }
            }
            .navigationTitle("Confirm Server")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
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
