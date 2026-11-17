import AppKit
import MeshDesktopCore
import SwiftUI
import UniformTypeIdentifiers

/// Network diagnostics (`netcheck`), atomic `.tar` bugreport export, server config, and cleanup.
struct DiagnosticsSheetView: View {
    @ObservedObject var store: DesktopStore
    let showCloseButton: Bool
    @Environment(\.dismiss) private var dismiss

    @State private var rawEndpoint: String = ""
    @State private var rawPortOverride: String = ""
    @State private var tlsAuthMode: TlsAuthMode = .spkiPin
    @State private var rawServerPin: String = ""

    @State private var confirmResetIdentity: Bool = false
    @State private var confirmUninstallSheet: Bool = false
    @State private var purgeKeysOnUninstall: Bool = false

    init(store: DesktopStore, showCloseButton: Bool = false) {
        self.store = store
        self.showCloseButton = showCloseButton
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if showCloseButton {
                    HStack {
                        Text("Diagnostics & Service Settings")
                            .font(.title2.weight(.semibold))
                        Spacer()
                        Button("Close") { dismiss() }
                            .keyboardShortcut(.cancelAction)
                    }
                }
                netcheckSection
                bugreportSection
                updateServerSection
                maintenanceAndDangerSection
            }
            .padding(showCloseButton ? 20 : 4)
        }
        .onAppear {
            prefillCurrentServerIfNeeded()
        }
        .alert("Reset Device Identity?", isPresented: $confirmResetIdentity) {
            Button("Cancel", role: .cancel) {}
            Button("Reset Identity", role: .destructive) {
                Task { @MainActor in
                    _ = await store.resetIdentity()
                }
            }
        } message: {
            Text(
                "This permanently removes this node's local WireGuard/control keys and returns "
                    + "to the Not Enrolled state. A new pre-auth key will be required to rejoin."
            )
        }
        .sheet(isPresented: $confirmUninstallSheet) {
            uninstallConfirmationSheet
        }
    }

    private var netcheckSection: some View {
        GroupBox("Network & NAT Diagnostics") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Button("Run Netcheck") {
                        Task { @MainActor in
                            _ = await store.runNetcheck()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(store.isBusy || store.status == nil)

                    Spacer()
                    if let net = store.status?.selfNetwork {
                        Text("Local UDP :\(net.localUdpPort) • \(net.natType.displayLabel)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }

                if let result = store.latestNetcheck {
                    Divider()
                    Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                        GridRow {
                            Text("UDP Egress / STUN").foregroundStyle(.secondary)
                            Text(
                                "\(result.udpEgressOk ? "OK" : "Blocked") / "
                                    + "\(result.stunReachable ? "Reachable" : "Unreachable")"
                            )
                        }
                        GridRow {
                            Text("NAT Classification").foregroundStyle(.secondary)
                            Text(result.natMapping.displayLabel)
                        }
                        GridRow {
                            Text("Reflexive IPv4 / IPv6").foregroundStyle(.secondary)
                            Text(
                                "\(result.reflexiveIpv4 ?? "—") / "
                                    + "\(result.ipv6Available ? "Available" : "No")"
                            )
                            .font(.body.monospaced())
                        }
                        GridRow {
                            Text("Control TCP / Relay RTT").foregroundStyle(.secondary)
                            let rttText = result.relayRttMs.map {
                                String(format: "%.1f ms", $0)
                            } ?? "—"
                            let tcpText = result.controlTcpReachable ? "Reachable" : "Blocked"
                            Text("\(tcpText) • \(rttText)")
                        }
                    }
                    Text(result.natNote)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let hint = result.diagnosticHint, !hint.isEmpty {
                        Text(hint)
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            }
            .padding(8)
        }
    }

    private var bugreportSection: some View {
        GroupBox("Redacted Bugreport Export") {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Export Daemon Diagnostics Archive (.tar)")
                        .font(.headline)
                    Text(
                        "Private keys, tokens, and pre-auth secrets are redacted by meshd "
                            + "before streaming atomically to disk."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Export Bugreport...") {
                    promptAndExportBugreport()
                }
                .disabled(store.isBusy || store.status == nil)
            }
            .padding(8)
        }
    }

    private var isEndpointIpLiteral: Bool {
        if let normalized = try? EndpointNormalizer.normalize(rawEndpoint) {
            return normalized.isIpLiteral
        }
        return EndpointNormalizer.isIpLiteralHost(rawEndpoint)
    }

    private var endpointBinding: Binding<String> {
        Binding(
            get: { rawEndpoint },
            set: { newValue in
                rawEndpoint = newValue
                if isEndpointIpLiteral {
                    tlsAuthMode = .spkiPin
                }
            }
        )
    }

    private var updateServerSection: some View {
        GroupBox("Control Server Endpoint & SPKI Pin") {
            VStack(alignment: .leading, spacing: 10) {
                TextField("Control Endpoint (host or IP[:port])", text: endpointBinding)
                    .textFieldStyle(.roundedBorder)

                HStack(spacing: 12) {
                    TextField("Port Override (443)", text: $rawPortOverride)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 160)

                    Picker("TLS Mode", selection: $tlsAuthMode) {
                        Text("SPKI Pin").tag(TlsAuthMode.spkiPin)
                        Text("System CA").tag(TlsAuthMode.systemCa)
                            .disabled(isEndpointIpLiteral)
                    }
                    .disabled(isEndpointIpLiteral)
                }

                if isEndpointIpLiteral {
                    Text("System CA is disabled for IP literal endpoints (Zero-TOFU).")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }

                if tlsAuthMode == .spkiPin || isEndpointIpLiteral {
                    TextField("SPKI SHA-256 Pin (sha256:...)", text: $rawServerPin)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                }

                HStack {
                    Button("Load Current") {
                        prefillCurrentServerIfNeeded(force: true)
                    }
                    Spacer()
                    Button("Apply Server Update") {
                        Task { @MainActor in
                            let effectiveMode: TlsAuthMode = isEndpointIpLiteral
                                ? .spkiPin
                                : tlsAuthMode
                            _ = await store.updateServerConfig(
                                rawEndpoint: rawEndpoint,
                                rawPortOverride: rawPortOverride,
                                tlsAuthMode: effectiveMode,
                                rawServerPin: rawServerPin
                            )
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        store.isBusy
                            || store.status == nil
                            || rawEndpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                }
            }
            .padding(8)
        }
    }

    private var maintenanceAndDangerSection: some View {
        GroupBox("Service Lifecycle & Recovery") {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Button("Clean Up Stale Network State") {
                        Task { @MainActor in
                            _ = await store.cleanupStaleState()
                        }
                    }
                    .disabled(store.isBusy || store.status == nil)

                    Button("Allow macOS Firewall") {
                        Task { @MainActor in
                            _ = await store.enableFirewallException()
                        }
                    }
                    .disabled(store.isBusy)

                    Spacer()
                }
                Divider()
                HStack(spacing: 10) {
                    Button("Reset Device Identity...", role: .destructive) {
                        confirmResetIdentity = true
                    }
                    .disabled(store.isBusy || store.status == nil)

                    Button("Uninstall Service...", role: .destructive) {
                        purgeKeysOnUninstall = false
                        confirmUninstallSheet = true
                    }
                    .disabled(store.isBusy)

                    Spacer()
                }
            }
            .padding(8)
        }
    }

    private var uninstallConfirmationSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Uninstall Mesh VPN Background Service")
                .font(.title3.weight(.semibold))
            Text(
                "Stops the LaunchDaemon, runs cleanup on routes and utun devices, and removes "
                    + "system binaries and LaunchDaemon plist."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            Toggle(
                "Also purge saved device identity keys (\(AgentDefaults.stateDirPath)/keys.json)",
                isOn: $purgeKeysOnUninstall
            )

            HStack {
                Button("Cancel") {
                    confirmUninstallSheet = false
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Uninstall Service", role: .destructive) {
                    let shouldPurge = purgeKeysOnUninstall
                    confirmUninstallSheet = false
                    Task { @MainActor in
                        _ = await store.uninstallService(purgeData: shouldPurge)
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 440)
    }

    private func prefillCurrentServerIfNeeded(force: Bool = false) {
        guard force || rawEndpoint.isEmpty,
              let conn = store.status?.serverConnection
        else {
            return
        }
        rawEndpoint = conn.controlEndpoint
        let isIpEndpoint = (try? EndpointNormalizer.normalize(conn.controlEndpoint))?
            .isIpLiteral ?? false
        tlsAuthMode = isIpEndpoint ? .spkiPin : conn.tlsAuthMode
        rawServerPin = conn.activePin ?? ""
        rawPortOverride = ""
    }

    /// Opens `NSSavePanel` before suspending polling (`IG-DGUI-WA-03`).
    @MainActor
    private func promptAndExportBugreport() {
        let panel = NSSavePanel()
        panel.title = "Export Redacted Diagnostics Archive"
        panel.nameFieldStringValue = "mesh-vpn-bugreport.tar"
        panel.allowedContentTypes = [UTType(filenameExtension: "tar") ?? .data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destinationURL = panel.url else {
            return
        }
        Task { @MainActor in
            _ = await store.exportBugreport(to: destinationURL)
        }
    }
}
