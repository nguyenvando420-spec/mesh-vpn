import MeshCoreKit
import SwiftUI

/// Resolved display label and canonical semantic hex colors for `StatusBadge` (`ADR-030`).
public struct StatusBadgePresentation: Equatable, Sendable {
    public let label: String
    public let tone: MeshSemanticTone
    public let lightHex: String
    public let darkHex: String

    public init(label: String, tone: MeshSemanticTone) {
        self.label = label
        self.tone = tone
        self.lightHex = MeshDesignTokens.hexString(for: tone, isDark: false)
        self.darkHex = MeshDesignTokens.hexString(for: tone, isDark: true)
    }
}

/// Semantic capsule pill reflecting tunnel and daemon lifecycle state (`US-137`, `ADR-030`).
public struct StatusBadge: View {
    public let status: MeshTunnelConnectionStatus
    public let daemonState: MobileDaemonState?
    @Environment(\.colorScheme) private var colorScheme

    public init(
        status: MeshTunnelConnectionStatus,
        daemonState: MobileDaemonState? = nil
    ) {
        self.status = status
        self.daemonState = daemonState
    }

    public var body: some View {
        let resolved = Self.resolve(status: status, daemonState: daemonState)
        let color = MeshDesignTokens.color(for: resolved.tone, colorScheme: colorScheme)
        Text(resolved.label)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(color.opacity(0.18))
            .foregroundStyle(color)
            .clipShape(Capsule())
    }

    /// Maps tunnel connection phase and optional daemon state to canonical label and tone.
    public nonisolated static func resolve(
        status: MeshTunnelConnectionStatus,
        daemonState: MobileDaemonState? = nil
    ) -> StatusBadgePresentation {
        if let daemonState {
            switch daemonState {
            case .revoked:
                return StatusBadgePresentation(label: "Device Revoked", tone: .error)
            case .reauthRequired:
                return StatusBadgePresentation(label: "Re-auth Required", tone: .warning)
            case .serverUpgradeRequired:
                return StatusBadgePresentation(label: "Attention Required", tone: .error)
            case .deviceLocked:
                return StatusBadgePresentation(label: "Waiting for Unlock", tone: .neutral)
            case .degraded where status == .connected || status == .reasserting:
                return StatusBadgePresentation(label: "Degraded", tone: .warning)
            case .stopped, .connecting, .connected, .degraded:
                break
            }
        }

        switch status {
        case .connected:
            return StatusBadgePresentation(label: "Connected", tone: .success)
        case .connecting:
            return StatusBadgePresentation(label: "Connecting", tone: .warning)
        case .reasserting:
            return StatusBadgePresentation(label: "Degraded", tone: .warning)
        case .disconnecting:
            return StatusBadgePresentation(label: "Disconnecting", tone: .neutral)
        case .disconnected, .invalid:
            return StatusBadgePresentation(label: "Disconnected", tone: .neutral)
        }
    }
}

/// Shared key/value row used across Status and Settings screens.
struct LabeledValueRow: View {
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

/// Zone 1 tab presenting tunnel state, self overlay identity, CTA toggle, and warnings.
@MainActor
struct StatusTab: View {
    @ObservedObject var viewModel: AppViewModel
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        NavigationView {
            List {
                connectionSection
                warningsSection
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
        }
        .navigationViewStyle(.stack)
    }

    private var connectionSection: some View {
        Section("Tunnel Status") {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(resolvedPresentation.label)
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
                StatusBadge(
                    status: viewModel.tunnelStatus,
                    daemonState: viewModel.statusSnapshot?.daemonState
                )
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

            tunnelActionButton

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

    private var tunnelActionButton: some View {
        let ctaColor = isConnectedOrConnecting
            ? MeshDesignTokens.color(for: .error, colorScheme: colorScheme)
            : MeshDesignTokens.brandPrimary(colorScheme: colorScheme)

        return Button {
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
        .tint(ctaColor)
        .disabled(viewModel.isBusy)
    }

    @ViewBuilder
    private var warningsSection: some View {
        let warnings = viewModel.statusSnapshot?.warnings ?? []
        if !warnings.isEmpty {
            let warnColor = MeshDesignTokens.color(for: .warning, colorScheme: colorScheme)
            Section("Operational Warnings") {
                ForEach(warnings.indices, id: \.self) { idx in
                    Label(warnings[idx].message, systemImage: "exclamationmark.triangle.fill")
                        .font(.subheadline)
                        .foregroundStyle(warnColor)
                }
            }
        }
    }

    private var resolvedPresentation: StatusBadgePresentation {
        StatusBadge.resolve(
            status: viewModel.tunnelStatus,
            daemonState: viewModel.statusSnapshot?.daemonState
        )
    }

    private var isConnectedOrConnecting: Bool {
        viewModel.tunnelStatus == .connected
            || viewModel.tunnelStatus == .connecting
            || viewModel.tunnelStatus == .reasserting
    }

    private var displayOverlayIp: String? {
        viewModel.statusSnapshot?.overlayIp ?? viewModel.bootstrapSummary?.overlayIp
    }

    private var displayFqdn: String? {
        viewModel.statusSnapshot?.fqdn ?? viewModel.bootstrapSummary?.fqdn
    }
}
