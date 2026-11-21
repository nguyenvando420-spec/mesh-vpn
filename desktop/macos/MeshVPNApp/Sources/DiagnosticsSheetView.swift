import AppKit
import MeshDesktopCore
import SwiftUI
import UniformTypeIdentifiers

/// Network diagnostics (`netcheck`), atomic `.tar` bugreport export, server config, and cleanup.
struct DiagnosticsSheetView: View {
    @ObservedObject var store: DesktopStore
    @ObservedObject var themeManager: ThemeManager
    @EnvironmentObject private var localeManager: LocaleManager
    let showCloseButton: Bool
    @Environment(\.dismiss) private var dismiss

    @State private var rawEndpoint: String = ""
    @State private var rawPortOverride: String = ""
    @State private var tlsAuthMode: TlsAuthMode = .spkiPin
    @State private var rawServerPin: String = ""

    @State private var confirmResetIdentity: Bool = false
    @State private var confirmUninstallSheet: Bool = false
    @State private var purgeKeysOnUninstall: Bool = false

    private var loc: Locale { localeManager.effectiveLocale }

    init(
        store: DesktopStore,
        themeManager: ThemeManager,
        showCloseButton: Bool = false
    ) {
        self.store = store
        self.themeManager = themeManager
        self.showCloseButton = showCloseButton
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if showCloseButton {
                    HStack {
                        Text(MeshL10n.tr("diag.service_settings", locale: loc))
                            .font(.title2.weight(.semibold))
                        Spacer()
                        Button(MeshL10n.tr("generic.close", locale: loc)) { dismiss() }
                            .keyboardShortcut(.cancelAction)
                    }
                }
                AppearanceAndLocaleSection(
                    themeManager: themeManager,
                    localeManager: localeManager
                )
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
        .alert(MeshL10n.tr("confirm.reset", locale: loc), isPresented: $confirmResetIdentity) {
            Button(MeshL10n.tr("generic.cancel", locale: loc), role: .cancel) {}
            Button(MeshL10n.tr("action.reset_identity", locale: loc), role: .destructive) {
                Task { @MainActor in
                    _ = await store.resetIdentity()
                }
            }
        } message: {
            Text(MeshL10n.tr("confirm.reset_detail", locale: loc))
        }
        .sheet(isPresented: $confirmUninstallSheet) {
            uninstallConfirmationSheet
        }
    }

    private var netcheckSection: some View {
        GroupBox(MeshL10n.tr("diag.netcheck_title", locale: loc)) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Button(MeshL10n.tr("diag.run_netcheck", locale: loc)) {
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
                            .foregroundStyle(MeshPalette.semanticWarning)
                    }
                }
            }
            .padding(8)
        }
    }

    private var bugreportSection: some View {
        GroupBox(MeshL10n.tr("diag.bugreport_export", locale: loc)) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(MeshL10n.tr("diag.export_archive", locale: loc))
                        .font(.headline)
                    Text(
                        "Private keys, tokens, and pre-auth secrets are redacted by meshd "
                            + "before streaming atomically to disk."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                Spacer()
                Button(MeshL10n.tr("diag.export_button", locale: loc)) {
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
        GroupBox(MeshL10n.tr("settings.server_endpoint", locale: loc)) {
            VStack(alignment: .leading, spacing: 10) {
                TextField(
                    MeshL10n.tr("onboarding.control_server", locale: loc),
                    text: endpointBinding
                )
                .textFieldStyle(.roundedBorder)

                HStack(spacing: 12) {
                    TextField("Port Override (443)", text: $rawPortOverride)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 160)

                    Picker("TLS", selection: $tlsAuthMode) {
                        Text(MeshL10n.tr("onboarding.tls_spki_pin", locale: loc))
                            .tag(TlsAuthMode.spkiPin)
                        Text(MeshL10n.tr("onboarding.tls_system_ca", locale: loc))
                            .tag(TlsAuthMode.systemCa)
                            .disabled(isEndpointIpLiteral)
                    }
                    .disabled(isEndpointIpLiteral)
                }

                if isEndpointIpLiteral {
                    Text("System CA is disabled for IP literal endpoints (Zero-TOFU).")
                        .font(.caption)
                        .foregroundStyle(MeshPalette.semanticWarning)
                }

                if tlsAuthMode == .spkiPin || isEndpointIpLiteral {
                    TextField(
                        MeshL10n.tr("onboarding.spki_pin_label", locale: loc),
                        text: $rawServerPin
                    )
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                }

                HStack {
                    Button(MeshL10n.tr("settings.load_current", locale: loc)) {
                        prefillCurrentServerIfNeeded(force: true)
                    }
                    Spacer()
                    Button(MeshL10n.tr("settings.apply_update", locale: loc)) {
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
        GroupBox(MeshL10n.tr("diag.service_lifecycle", locale: loc)) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Button(MeshL10n.tr("service.cleanup_stale", locale: loc)) {
                        Task { @MainActor in
                            _ = await store.cleanupStaleState()
                        }
                    }
                    .disabled(store.isBusy || store.status == nil)

                    Button(MeshL10n.tr("service.firewall_allow", locale: loc)) {
                        Task { @MainActor in
                            _ = await store.enableFirewallException()
                        }
                    }
                    .disabled(store.isBusy)

                    Spacer()
                }
                Divider()
                HStack(spacing: 10) {
                    Button(MeshL10n.tr("service.reset_identity", locale: loc), role: .destructive) {
                        confirmResetIdentity = true
                    }
                    .disabled(store.isBusy || store.status == nil)

                    Button(MeshL10n.tr("service.uninstall", locale: loc), role: .destructive) {
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
            Text(MeshL10n.tr("service.uninstall_title", locale: loc))
                .font(.title3.weight(.semibold))
            Text(
                "Stops the LaunchDaemon, runs cleanup on routes and utun devices, and removes "
                    + "system binaries and LaunchDaemon plist."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            let purgeLabel = MeshL10n.tr("service.purge_keys", locale: loc)
            Toggle(
                "\(purgeLabel) (\(AgentDefaults.stateDirPath)/keys.json)",
                isOn: $purgeKeysOnUninstall
            )

            HStack {
                Button(MeshL10n.tr("generic.cancel", locale: loc)) {
                    confirmUninstallSheet = false
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                Button(MeshL10n.tr("service.uninstall", locale: loc), role: .destructive) {
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

    /// Opens `NSSavePanel` before polling suspension (`IG-DGUI-WA-03`).
    @MainActor
    private func promptAndExportBugreport() {
        let panel = NSSavePanel()
        panel.title = MeshL10n.tr("diag.bugreport_export", locale: loc)
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

private struct AppearanceAndLocaleSection: View {
    @ObservedObject var themeManager: ThemeManager
    @ObservedObject var localeManager: LocaleManager

    private var loc: Locale { localeManager.effectiveLocale }

    var body: some View {
        GroupBox(MeshL10n.tr("theme.appearance", locale: loc)) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    Text(MeshL10n.tr("theme.appearance", locale: loc))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Picker(
                        MeshL10n.tr("theme.appearance", locale: loc),
                        selection: $themeManager.mode
                    ) {
                        ForEach(ThemeMode.allCases) { item in
                            Text(item.localizedLabel(locale: loc)).tag(item)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 260)
                }
                Divider()
                HStack(spacing: 12) {
                    Text(MeshL10n.tr("locale.language", locale: loc))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Picker(
                        MeshL10n.tr("locale.language", locale: loc),
                        selection: $localeManager.mode
                    ) {
                        ForEach(LocaleMode.allCases) { item in
                            Text(item.localizedLabel(locale: loc)).tag(item)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 260)
                }
            }
            .padding(8)
        }
    }
}
