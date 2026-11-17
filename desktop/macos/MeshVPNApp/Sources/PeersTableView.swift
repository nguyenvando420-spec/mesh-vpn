import AppKit
import MeshDesktopCore
import SwiftUI

/// Searchable peer directory and inspector displaying path, latency, traffic, and Ping actions.
struct PeersTableView: View {
    @ObservedObject var store: DesktopStore
    @State private var searchQuery: String = ""
    @State private var filter: PeerFilter = .all
    @State private var selectedPeerId: String?
    @State private var forceDirectPing: Bool = false

    private enum PeerFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case online = "Online"
        case direct = "Direct"
        case relay = "Relay"

        var id: String { rawValue }
    }

    private var filteredPeers: [AgentPeerStatus] {
        let query = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return store.sortedPeers.filter { peer in
            switch filter {
            case .all:
                break
            case .online:
                guard peer.online else { return false }
            case .direct:
                guard peer.online && peer.activePath == .direct else { return false }
            case .relay:
                guard peer.online && peer.activePath == .relay else { return false }
            }
            guard !query.isEmpty else {
                return true
            }
            return peer.name.lowercased().contains(query)
                || peer.fqdn.lowercased().contains(query)
                || peer.overlayIp.lowercased().contains(query)
        }
    }

    private var selectedPeer: AgentPeerStatus? {
        if let selectedPeerId,
           let matched = filteredPeers.first(where: { $0.nodeId == selectedPeerId }) {
            return matched
        }
        return filteredPeers.first
    }

    var body: some View {
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
    }

    private var filterToolbar: some View {
        HStack(spacing: 12) {
            TextField("Search peers by name, FQDN, or IP...", text: $searchQuery)
                .textFieldStyle(.roundedBorder)

            Picker("Filter", selection: $filter) {
                ForEach(PeerFilter.allCases) { item in
                    Text(item.rawValue).tag(item)
                }
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 260)
        }
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
                    copyToPasteboard(peer.overlayIp)
                }
                Button("Copy FQDN") {
                    copyToPasteboard(peer.fqdn)
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

    private func copyToPasteboard(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
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
                .fill(peer.online ? Color.green : Color.secondary.opacity(0.4))
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
        guard online else { return .secondary }
        switch activePath {
        case .direct: return .green
        case .relay: return .orange
        case .none: return .secondary
        }
    }
}
