import MeshCoreKit
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// 4-state peer list filter mode (`US-120`, `ADR-028`).
public enum PeerFilterMode: String, CaseIterable, Sendable {
    case all
    case online
    case direct
    case relay

    public var localizationKey: String {
        switch self {
        case .all: return "peers.filter.all"
        case .online: return "peers.filter.online"
        case .direct: return "peers.filter.direct"
        case .relay: return "peers.filter.relay"
        }
    }

    public var displayTitle: String {
        switch self {
        case .all: return "All"
        case .online: return "Online"
        case .direct: return "Direct"
        case .relay: return "Relay"
        }
    }

    public func localizedTitle(locale: Locale) -> String {
        L10n.tr(localizationKey, locale: locale)
    }
}

/// Counts for each 4-state peer filter chip.
public struct PeerFilterCounts: Equatable, Sendable {
    public let all: Int
    public let online: Int
    public let direct: Int
    public let relay: Int

    public init(all: Int, online: Int, direct: Int, relay: Int) {
        self.all = all
        self.online = online
        self.direct = direct
        self.relay = relay
    }

    public func count(for mode: PeerFilterMode) -> Int {
        switch mode {
        case .all: return all
        case .online: return online
        case .direct: return direct
        case .relay: return relay
        }
    }
}

/// Pure peer filtering and count helpers for `PeersView` and XCTest (`US-120`).
public enum PeerFilter: Sendable {
    public static func counts(peers: [MobilePeerStatus]) -> PeerFilterCounts {
        let onlineCount = peers.filter(\.online).count
        let directCount = peers.filter { $0.online && $0.activePath == .direct }.count
        let relayCount = peers.filter { $0.online && $0.activePath == .relay }.count
        return PeerFilterCounts(
            all: peers.count,
            online: onlineCount,
            direct: directCount,
            relay: relayCount
        )
    }

    public static func filter(
        peers: [MobilePeerStatus],
        mode: PeerFilterMode,
        query: String
    ) -> [MobilePeerStatus] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return peers.filter { peer in
            matchesMode(peer, mode: mode) && matchesQuery(peer, needle: needle)
        }
    }

    private static func matchesMode(_ peer: MobilePeerStatus, mode: PeerFilterMode) -> Bool {
        switch mode {
        case .all:
            return true
        case .online:
            return peer.online
        case .direct:
            return peer.online && peer.activePath == .direct
        case .relay:
            return peer.online && peer.activePath == .relay
        }
    }

    private static func matchesQuery(_ peer: MobilePeerStatus, needle: String) -> Bool {
        if needle.isEmpty {
            return true
        }
        return peer.name.lowercased().contains(needle)
            || peer.fqdn.lowercased().contains(needle)
            || peer.overlayIp.lowercased().contains(needle)
            || peer.nodeId.lowercased().contains(needle)
    }
}

/// Adaptive column layout resolver for iPhone (`.compact`) vs iPad (`.regular`) (`US-138`).
public enum PeersAdaptiveLayout: Sendable {
    public static func columnCount(for sizeClass: UserInterfaceSizeClass?) -> Int {
        sizeClass == .regular ? 2 : 1
    }
}

/// Zone 2 tab with peer search, 4-state filter chips, standard IP/FQDN copy, and ping (`US-120`).
@MainActor
struct PeersView: View {
    @ObservedObject var viewModel: AppViewModel
    @EnvironmentObject var localeManager: LocaleManager
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @State private var searchText = ""
    @State private var selectedFilter: PeerFilterMode = .all
    @State private var toastMessage: String?
    @State private var toastDismissTask: Task<Void, Never>?

    var body: some View {
        let locale = localeManager.resolvedLocale
        NavigationView {
            ZStack(alignment: .bottom) {
                peersContent(locale: locale)
                if let toastMessage {
                    ToastBannerView(message: toastMessage)
                        .padding(.bottom, 16)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .navigationTitle(L10n.tr("tab.peers", locale: locale))
            .searchable(
                text: $searchText,
                prompt: L10n.tr("peers.search_placeholder", locale: locale)
            )
            .refreshable {
                await viewModel.refreshAllState()
            }
        }
        .navigationViewStyle(.stack)
    }

    private func peersContent(locale: Locale) -> some View {
        let allPeers = viewModel.statusSnapshot?.peers ?? []
        let counts = PeerFilter.counts(peers: allPeers)
        let filtered = PeerFilter.filter(peers: allPeers, mode: selectedFilter, query: searchText)
        let columnCount = PeersAdaptiveLayout.columnCount(for: horizontalSizeClass)
        let gridColumns = Array(
            repeating: GridItem(.flexible(), spacing: 12, alignment: .top),
            count: columnCount
        )

        return ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                PeerFilterBar(
                    selectedFilter: $selectedFilter,
                    counts: counts,
                    colorScheme: colorScheme,
                    locale: locale
                )

                if let ping = viewModel.lastPingResponse {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(L10n.inline(en: "Latest Ping", vi: "Ping gần nhất", locale: locale))
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        PingSummaryView(ping: ping, locale: locale)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(cardBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    }
                }

                Text("\(L10n.tr("tab.peers", locale: locale)) (\(filtered.count))")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)

                if filtered.isEmpty {
                    Text(L10n.tr("diag.no_peers", locale: locale))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(cardBackground)
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                } else {
                    LazyVGrid(columns: gridColumns, alignment: .leading, spacing: 12) {
                        ForEach(filtered, id: \.nodeId) { peer in
                            PeerRowView(
                                peer: peer,
                                canPing: viewModel.tunnelStatus == .connected && !viewModel.isBusy,
                                colorScheme: colorScheme,
                                locale: locale,
                                onCopyIp: { copyValue(peer.overlayIp, locale: locale) },
                                onCopyFqdn: { copyValue(peer.fqdn, locale: locale) },
                                onPing: { Task { await viewModel.pingPeer(peer) } }
                            )
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(cardBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        }
                    }
                }

                if viewModel.peersTruncatedNotice, let total = viewModel.totalPeerCount {
                    Text(
                        L10n.inline(
                            en: "Showing compact peer slice from \(total) total peers.",
                            vi: "Đang hiển thị nhóm rút gọn trong tổng số \(total) thiết bị.",
                            locale: locale
                        )
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            .padding(16)
        }
    }

    private var cardBackground: Color {
        colorScheme == .dark
            ? Color.secondary.opacity(0.16)
            : Color.secondary.opacity(0.08)
    }

    private func copyValue(_ value: String, locale: Locale) {
        viewModel.copyNonSecretAddress(value)
        showToast("\(L10n.tr("peers.copied_toast", locale: locale)): \(value)")
    }

    private func showToast(_ message: String) {
        toastDismissTask?.cancel()
        withAnimation(.easeInOut(duration: 0.2)) {
            toastMessage = message
        }
        toastDismissTask = Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            guard !Task.isCancelled else { return }
            withAnimation(.easeInOut(duration: 0.2)) {
                toastMessage = nil
            }
        }
    }
}

private struct PeerFilterBar: View {
    @Binding var selectedFilter: PeerFilterMode
    let counts: PeerFilterCounts
    let colorScheme: ColorScheme
    let locale: Locale

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(PeerFilterMode.allCases, id: \.self) { mode in
                    let isSelected = selectedFilter == mode
                    let activeBg = MeshDesignTokens.brandPrimary(colorScheme: colorScheme)
                    let chipCount = counts.count(for: mode)
                    Button {
                        selectedFilter = mode
                    } label: {
                        HStack(spacing: 4) {
                            Text(mode.localizedTitle(locale: locale))
                            Text("\(chipCount)")
                                .font(.caption2.monospacedDigit().weight(.semibold))
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(
                                    isSelected
                                        ? Color.white.opacity(0.24)
                                        : Color.secondary.opacity(0.18)
                                )
                                .clipShape(Capsule())
                        }
                        .font(.subheadline.weight(isSelected ? .semibold : .regular))
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(isSelected ? activeBg : Color.secondary.opacity(0.12))
                        .foregroundStyle(isSelected ? Color.white : Color.primary)
                        .clipShape(Capsule())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }
}

@MainActor
private struct PeerRowView: View {
    let peer: MobilePeerStatus
    let canPing: Bool
    let colorScheme: ColorScheme
    let locale: Locale
    let onCopyIp: @MainActor () -> Void
    let onCopyFqdn: @MainActor () -> Void
    let onPing: @MainActor () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(peer.name)
                        .font(.headline)
                    Text(peer.overlayIp)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                    Text(peer.fqdn)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                    Text(pathSubtitle)
                        .font(.caption2)
                        .foregroundStyle(statusColor)
                }
                Spacer()
                Button(L10n.tr("action.ping", locale: locale), action: onPing)
                    .buttonStyle(.bordered)
                    .disabled(!canPing)
            }

            HStack(spacing: 10) {
                Button {
                    onCopyIp()
                } label: {
                    Label(
                        L10n.tr("peers.copy_overlay_ip", locale: locale),
                        systemImage: "doc.on.doc"
                    )
                    .font(.caption)
                }
                .buttonStyle(.bordered)

                if !peer.fqdn.isEmpty {
                    Button {
                        onCopyFqdn()
                    } label: {
                        Label(
                            L10n.tr("peers.copy_fqdn", locale: locale),
                            systemImage: "doc.on.doc"
                        )
                        .font(.caption)
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var statusColor: Color {
        let tone: MeshSemanticTone = peer.online ? .success : .neutral
        return MeshDesignTokens.color(for: tone, colorScheme: colorScheme)
    }

    private var pathSubtitle: String {
        let stateKey = peer.online ? "peers.filter.online" : "peers.badge.offline"
        let stateText = L10n.tr(stateKey, locale: locale)
        let pathText: String
        switch peer.activePath {
        case .direct:
            pathText = L10n.tr("peers.filter.direct", locale: locale)
        case .relay:
            pathText = L10n.tr("peers.filter.relay", locale: locale)
        case .none:
            pathText = String(describing: peer.activePath)
        }
        if let rtt = peer.rttMs {
            return "\(stateText) | \(pathText) | \(rtt) ms"
        }
        return "\(stateText) | \(pathText)"
    }
}

private struct PingSummaryView: View {
    let ping: MobilePingResponse
    let locale: Locale

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Ping \(ping.peerName) (\(ping.peerOverlayIp))")
                .font(.subheadline.weight(.medium))
            if let avg = ping.avgRttMs {
                let avgLabel = L10n.inline(
                    en: String(format: "Average RTT: %.1f ms", avg),
                    vi: String(format: "RTT trung bình: %.1f ms", avg),
                    locale: locale
                )
                Text(avgLabel)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            ForEach(ping.samples, id: \.seq) { sample in
                let rttText = sample.rttMs.map { String(format: "%.1f ms", $0) } ?? "timeout"
                Text("Seq \(sample.seq): \(String(describing: sample.via)) \(rttText)")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct ToastBannerView: View {
    let message: String

    var body: some View {
        Text(message)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(.ultraThickMaterial)
            .clipShape(Capsule())
            .shadow(radius: 4)
    }
}
