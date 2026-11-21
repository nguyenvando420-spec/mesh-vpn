import AppKit
import MeshDesktopCore
import SwiftUI

/// Searchable peer directory and inspector displaying path, latency, traffic, and Ping actions.
struct PeersTableView: View {
    @ObservedObject var store: DesktopStore
    @State private var searchQuery: String = ""
    @State private var filter: PeerFilterMode = .all
    @State private var selectedPeerId: String?
    @State private var forceDirectPing: Bool = false
    @State private var copyToastMessage: String?
    @State private var toastDismissTask: Task<Void, Never>?

    private var filterCounts: PeerFilterCounts {
        PeerDirectoryFilter.counts(for: store.sortedPeers)
    }

    private var filteredPeers: [AgentPeerStatus] {
        PeerDirectoryFilter.filter(
            peers: store.sortedPeers,
            mode: filter,
            query: searchQuery
        )
    }

    private var selectedPeer: AgentPeerStatus? {
        if let selectedPeerId,
           let matched = filteredPeers.first(where: { $0.nodeId == selectedPeerId }) {
            return matched
        }
        return filteredPeers.first
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 12) {
                filterToolbar
                if filteredPeers.isEmpty {
                    emptyStateView
                } else {
                    HSplitView {
                        peerListPane
                            .frame(minWidth: 280, idealWidth: 340)
                        peerInspectorPane
                            .frame(minWidth: 320)
                    }
                }
            }
            if let toast = copyToastMessage {
                copyToastOverlay(toast)
            }
        }
    }

    private var filterToolbar: some View {
        let counts = filterCounts
        return HStack(spacing: 12) {
            TextField(
                "Search peers by name, FQDN, IP, or node ID...",
                text: $searchQuery
            )
            .textFieldStyle(.roundedBorder)

            HStack(spacing: 6) {
                ForEach(PeerFilterMode.allCases) { item in
                    filterChipButton(item: item, count: counts.count(for: item))
                }
            }
        }
    }

    private func filterChipButton(item: PeerFilterMode, count: Int) -> some View {
        let isSelected = filter == item
        let fgColor = isSelected ? Color.white : MeshPalette.textPrimary
        let bgColor = isSelected ? MeshPalette.brandPrimary : MeshPalette.surfaceCard
        let borderColor = isSelected ? MeshPalette.brandPrimary : MeshPalette.surfaceBorder
        return Button {
            filter = item
        } label: {
            HStack(spacing: 5) {
                Text(item.rawValue)
                    .font(.callout.weight(isSelected ? .semibold : .regular))
                Text("\(count)")
                    .font(.caption2.monospacedDigit().weight(.semibold))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(
                        isSelected
                            ? Color.white.opacity(0.22)
                            : MeshPalette.surfaceBorder.opacity(0.5),
                        in: Capsule()
                    )
            }
            .foregroundStyle(fgColor)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(bgColor, in: RoundedRectangle(cornerRadius: 7))
            .overlay(
                RoundedRectangle(cornerRadius: 7)
                    .stroke(borderColor, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }

    private var peerListPane: some View {
        List(filteredPeers, selection: $selectedPeerId) { peer in
            PeerRowView(peer: peer)
                .tag(peer.nodeId)
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
    }

    @ViewBuilder
    private var peerInspectorPane: some View {
        if let peer = selectedPeer {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    inspectorHeader(peer)
                    Divider()
                    inspectorMetrics(peer)
                    Divider()
                    inspectorActions(peer)
                    if let ping = store.latestPing,
                       ping.targetOverlayIp == peer.overlayIp || ping.targetName == peer.name {
                        Divider()
                        pingSummaryBox(ping)
                    }
                }
                .padding(16)
            }
        } else {
            emptyStateView
        }
    }

    private func inspectorHeader(_ peer: AgentPeerStatus) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(peer.name)
                    .font(.title3.weight(.semibold))
                Text(peer.fqdn)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Spacer()
            PeerPathBadge(online: peer.online, activePath: peer.activePath)
        }
    }

    private func inspectorMetrics(_ peer: AgentPeerStatus) -> some View {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
            GridRow {
                Text("Overlay IP").foregroundStyle(.secondary)
                Text(peer.overlayIp).font(.body.monospaced()).textSelection(.enabled)
            }
            GridRow {
                Text("Node ID").foregroundStyle(.secondary)
                Text(peer.nodeId).font(.caption.monospaced()).textSelection(.enabled)
            }
            GridRow {
                Text("Direct Endpoint").foregroundStyle(.secondary)
                Text(peer.directEndpoint ?? "—").font(.body.monospaced())
            }
            GridRow {
                Text("Latency (RTT)").foregroundStyle(.secondary)
                Text(peer.rttMs.map { "\($0) ms" } ?? "—")
            }
            GridRow {
                Text("Traffic RX / TX").foregroundStyle(.secondary)
                Text("\(formatBytes(peer.rxBytes)) / \(formatBytes(peer.txBytes))")
            }
            GridRow {
                Text("Last Handshake").foregroundStyle(.secondary)
                Text(formatTimestampMs(peer.lastHandshakeAtMs))
            }
        }
    }

    private func inspectorActions(_ peer: AgentPeerStatus) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Button("Copy Overlay IP") {
                    copyToPasteboard(peer.overlayIp, label: "Overlay IP")
                }
                Button("Copy FQDN") {
                    copyToPasteboard(peer.fqdn, label: "FQDN")
                }
                Spacer()
                Button("Ping Peer") {
                    Task { @MainActor in
                        _ = await store.pingPeer(
                            target: peer.overlayIp,
                            count: 4,
                            forceDirect: forceDirectPing
                        )
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy || !peer.online)
            }
            Toggle("Force Direct Path Probe", isOn: $forceDirectPing)
                .font(.caption)
        }
    }

    private func pingSummaryBox(_ ping: PingResponse) -> some View {
        GroupBox("Last Ping Result (\(ping.packetsReceived)/\(ping.packetsSent) received)") {
            VStack(alignment: .leading, spacing: 6) {
                let loss = String(format: "%.1f%%", ping.lossPercent)
                let avg = ping.rttAvgMs.map { String(format: "%.1f ms", $0) } ?? "—"
                Text("Loss: \(loss) • Avg RTT: \(avg)")
                    .font(.callout.weight(.medium))

                ForEach(ping.samples, id: \.seq) { sample in
                    let rttLabel = sample.rttMs.map { String(format: "%.1f ms", $0) } ?? "timeout"
                    let endpointLabel = sample.endpoint ?? ""
                    Text("#\(sample.seq) [\(sample.via.rawValue)] \(rttLabel) \(endpointLabel)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }

    private var emptyStateView: some View {
        VStack(spacing: 8) {
            Image(systemName: "network")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("No matching peers")
                .font(.headline)
            Text("Peers from your mesh netmap will appear here automatically.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func copyToastOverlay(_ message: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(MeshPalette.semanticSuccess)
            Text(message)
                .font(.callout.weight(.medium))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(MeshPalette.surfaceCard, in: Capsule())
        .overlay(Capsule().stroke(MeshPalette.surfaceBorder, lineWidth: 1))
        .shadow(radius: 4)
        .padding(.bottom, 12)
    }

    private func copyToPasteboard(_ text: String, label: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
        copyToastMessage = "Copied \(label): \(text)"
        toastDismissTask?.cancel()
        toastDismissTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            guard !Task.isCancelled else { return }
            copyToastMessage = nil
        }
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: Int64(min(bytes, UInt64(Int64.max))))
    }

    private func formatTimestampMs(_ timestampMs: UInt64?) -> String {
        guard let timestampMs, timestampMs > 0 else {
            return "Never"
        }
        let date = Date(timeIntervalSince1970: TimeInterval(timestampMs) / 1000.0)
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

private struct PeerRowView: View {
    let peer: AgentPeerStatus

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(
                    peer.online
                        ? MeshPalette.semanticSuccess
                        : MeshPalette.semanticNeutral.opacity(0.45)
                )
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(peer.name)
                    .font(.body.weight(.medium))
                Text(peer.overlayIp)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let rtt = peer.rttMs, peer.online {
                Text("\(rtt) ms")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            PeerPathBadge(online: peer.online, activePath: peer.activePath)
        }
        .padding(.vertical, 2)
    }
}

private struct PeerPathBadge: View {
    let online: Bool
    let activePath: ActivePathKind

    var body: some View {
        Text(label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(badgeColor.opacity(0.15), in: Capsule())
            .foregroundStyle(badgeColor)
    }

    private var label: String {
        guard online else { return "Offline" }
        switch activePath {
        case .direct: return "Direct"
        case .relay: return "Relay"
        case .none: return "Idle"
        }
    }

    private var badgeColor: Color {
        guard online else { return MeshPalette.semanticNeutral }
        switch activePath {
        case .direct: return MeshPalette.semanticSuccess
        case .relay: return MeshPalette.semanticWarning
        case .none: return MeshPalette.semanticNeutral
        }
    }
}
