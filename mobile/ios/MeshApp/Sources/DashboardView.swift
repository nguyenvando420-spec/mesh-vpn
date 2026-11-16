import MeshCoreKit
import SwiftUI

/// Primary operational dashboard displaying status, peers, diagnostics, and security actions.
struct DashboardView: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var isShowingRotateSheet = false
    @State private var isShowingServerEditSheet = false
    @State private var isShowingResetConfirm = false
    @State private var rotationTokenInput = ""
    @State private var editServerEndpoint = ""
    @State private var editServerTlsMode: MobileTlsAuthMode = .spkiPin
    @State private var editServerPin = ""

    var body: some View {
        NavigationView {
            List {
                connectionSection
                warningsSection
                peersSection
                diagnosticsSection
                maintenanceSection
            }
            .navigationTitle("Mesh VPN")
            .refreshable {
                await viewModel.refreshAllState()
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task { await viewModel.refreshAllState() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(viewModel.isBusy)
                }
            }
            .sheet(item: $viewModel.pendingConfirmation) { draft in
                EnrollmentConfirmationSheet(
                    draft: draft,
                    isBusy: viewModel.isBusy,
                    onCancel: { viewModel.cancelPendingEnrollment() },
                    onConfirm: {
                        Task { await viewModel.confirmPendingEnrollment() }
                    }
                )
            }
            .sheet(item: shareSheetItemBinding) { item in
                ShareSheetView(fileURL: item.url) { completedURL in
                    viewModel.cleanupSharedBugreport(at: completedURL)
                }
            }
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

    private var connectionSection: some View {
        Section("Tunnel Status") {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(statusTitle)
                        .font(.headline)
                    if let overlayIp = displayOverlayIp {
                        Text(overlayIp)
                            .font(.subheadline.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    if let fqdn = displayFqdn {
                        Text(fqdn)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                StatusBadge(status: viewModel.tunnelStatus)
            }

            if let endpoint = viewModel.bootstrapSummary?.serverEndpoint {
                LabeledValueRow(title: "Control", value: endpoint)
            }
            if let snapshot = viewModel.statusSnapshot {
                LabeledValueRow(
                    title: "Netmap Version",
                    value: "v\(snapshot.netmapVersion)"
                )
                if let nat64 = snapshot.selfNetwork.nat64ActivePrefix {
                    LabeledValueRow(title: "NAT64 Prefix", value: nat64)
                }
            }
            if let banner = viewModel.statusBannerMessage {
                Text(banner)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Button {
                Task {
                    if isConnectedOrConnecting {
                        await viewModel.disconnectTunnel()
                    } else {
                        await viewModel.connectTunnel()
                    }
                }
            } label: {
                Text(isConnectedOrConnecting ? "Disconnect" : "Connect")
                    .fontWeight(.semibold)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(isConnectedOrConnecting ? .red : .accentColor)
            .disabled(viewModel.isBusy)

            Toggle(
                "On-Demand Auto-Connect",
                isOn: Binding(
                    get: { viewModel.isOnDemandEnabled },
                    set: { newValue in
                        Task { await viewModel.toggleOnDemand(newValue) }
                    }
                )
            )
            .disabled(viewModel.isBusy)
        }
    }

    @ViewBuilder
    private var warningsSection: some View {
        let warnings = viewModel.statusSnapshot?.warnings ?? []
        if !warnings.isEmpty {
            Section("Operational Warnings") {
                ForEach(Array(warnings.enumerated()), id: \.offset) { _, warning in
                    Label(warning.message, systemImage: "exclamationmark.triangle.fill")
                        .font(.subheadline)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private var peersSection: some View {
        Section {
            let peers = viewModel.statusSnapshot?.peers ?? []
            if peers.isEmpty {
                Text("No peers visible yet.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(peers, id: \.nodeId) { peer in
                    PeerRowView(peer: peer) {
                        Task { await viewModel.pingPeer(peer) }
                    }
                    .disabled(viewModel.tunnelStatus != .connected || viewModel.isBusy)
                }
            }
            if viewModel.peersTruncatedNotice, let total = viewModel.totalPeerCount {
                Text("Showing compact peer slice from \(total) total peers.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Peers")
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

            if let ping = viewModel.lastPingResponse {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Ping \(ping.peerName) (\(ping.peerOverlayIp))")
                        .font(.subheadline)
                    if let avg = ping.avgRttMs {
                        Text(String(format: "Average RTT: %.1f ms", avg))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    ForEach(ping.samples, id: \.seq) { sample in
                        Text(
                            "Seq \(sample.seq): \(String(describing: sample.via)) "
                                + (sample.rttMs.map { String(format: "%.1f ms", $0) } ?? "timeout")
                        )
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var maintenanceSection: some View {
        Section("Security & Maintenance") {
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

            Button {
                Task { await viewModel.exportBugreport() }
            } label: {
                Label("Export Redacted Bugreport", systemImage: "square.and.arrow.up")
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

    private var isConnectedOrConnecting: Bool {
        viewModel.tunnelStatus == .connected
            || viewModel.tunnelStatus == .connecting
            || viewModel.tunnelStatus == .reasserting
    }

    private var statusTitle: String {
        switch viewModel.tunnelStatus {
        case .connected: return "Connected"
        case .connecting: return "Connecting"
        case .reasserting: return "Reconnecting"
        case .disconnecting: return "Disconnecting"
        case .disconnected, .invalid: return "Disconnected"
        }
    }

    private var displayOverlayIp: String? {
        viewModel.statusSnapshot?.overlayIp ?? viewModel.bootstrapSummary?.overlayIp
    }

    private var displayFqdn: String? {
        viewModel.statusSnapshot?.fqdn ?? viewModel.bootstrapSummary?.fqdn
    }

    private var shareSheetItemBinding: Binding<ShareFileItem?> {
        Binding(
            get: { viewModel.shareBugreportURL.map(ShareFileItem.init) },
            set: { newValue in
                if newValue == nil, let url = viewModel.shareBugreportURL {
                    viewModel.cleanupSharedBugreport(at: url)
                }
            }
        )
    }
}

private struct ShareFileItem: Identifiable {
    var id: String { url.path }
    let url: URL
}

private struct StatusBadge: View {
    let status: MeshTunnelConnectionStatus

    var body: some View {
        Text(status.rawValue.capitalized)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(badgeColor.opacity(0.18))
            .foregroundStyle(badgeColor)
            .clipShape(Capsule())
    }

    private var badgeColor: Color {
        switch status {
        case .connected: return .green
        case .connecting, .reasserting: return .orange
        case .disconnecting: return .yellow
        case .disconnected, .invalid: return .secondary
        }
    }
}

private struct LabeledValueRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline.monospaced())
        }
    }
}

@MainActor
private struct PeerRowView: View {
    let peer: MobilePeerStatus
    let onPing: @MainActor () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(peer.name)
                    .font(.headline)
                Text(peer.overlayIp)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                Text(pathSubtitle)
                    .font(.caption2)
                    .foregroundStyle(peer.online ? .green : .secondary)
            }
            Spacer()
            Button("Ping", action: onPing)
                .buttonStyle(.bordered)
        }
    }

    private var pathSubtitle: String {
        let pathText = String(describing: peer.activePath)
        if let rtt = peer.rttMs {
            return "\(peer.online ? "Online" : "Offline") • \(pathText) • \(rtt) ms"
        }
        return "\(peer.online ? "Online" : "Offline") • \(pathText)"
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
