import AppKit
import MeshDesktopCore
import SwiftUI

/// Alert, version mismatch, subnet conflict, firewall, and toast banners in the Dashboard.
struct DashboardBannersView: View {
    @ObservedObject var store: DesktopStore
    let onOpenDiagnostics: () -> Void
    let onOpenKeyRotation: () -> Void
    let onConfirmResetIdentity: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if store.versionBanner.requiresUpdateBanner {
                versionMismatchBanner
            }
            if let err = store.lastActionError {
                errorBanner(err)
            }
            if let conflict = store.status?.selfNetwork.overlayConflictWarning,
               !conflict.isEmpty {
                DashboardWarningBanner(
                    icon: "exclamationmark.triangle.fill",
                    color: MeshPalette.semanticWarning,
                    title: "Local Network Subnet Conflict",
                    message: conflict,
                    actionTitle: nil,
                    isBusy: store.isBusy,
                    action: nil
                )
            }
            if let fwWarn = store.status?.selfNetwork.macosFirewallWarning, !fwWarn.isEmpty {
                DashboardWarningBanner(
                    icon: "flame.fill",
                    color: MeshPalette.semanticWarning,
                    title: "macOS Application Firewall Warning",
                    message: fwWarn,
                    actionTitle: "Allow meshd",
                    isBusy: store.isBusy
                ) {
                    Task { @MainActor in
                        _ = await store.enableFirewallException()
                    }
                }
            }
            if store.isDegradedTunnel {
                DashboardWarningBanner(
                    icon: "bolt.trianglebadge.exclamationmark.fill",
                    color: MeshPalette.semanticWarning,
                    title: "Tunnel Operating in Degraded Mode",
                    message: "Direct P2P paths are unavailable; traffic falls back via Relay.",
                    actionTitle: "Diagnostics",
                    isBusy: store.isBusy,
                    action: onOpenDiagnostics
                )
            }
            if let toast = store.lastToastMessage {
                toastBanner(toast)
            }
        }
    }

    private var versionMismatchBanner: some View {
        let message: String = switch store.versionBanner {
        case .legacyPre030:
            "Installed meshd is legacy (<0.3.0) and lacks desktop IPC endpoints."
        case .mismatch(let daemon, let app):
            "Running meshd (\(daemon)) differs from Mesh VPN.app (\(app))."
        case .unknown, .matched:
            ""
        }
        return DashboardWarningBanner(
            icon: "arrow.triangle.2.circlepath.circle.fill",
            color: MeshPalette.semanticWarning,
            title: "Background Service Update Recommended",
            message: message,
            actionTitle: "Update Service",
            isBusy: store.isBusy
        ) {
            Task { @MainActor in
                _ = await store.installOrUpdateService(firewallOptIn: true)
            }
        }
    }

    private func errorBanner(_ error: DesktopUserFacingError) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "xmark.octagon.fill")
                .foregroundStyle(MeshPalette.semanticError)
            VStack(alignment: .leading, spacing: 2) {
                Text(error.title).font(.headline)
                Text(error.message).font(.callout)
            }
            Spacer()
            if error.isPermissionDenied {
                Button("Start / Repair Service") {
                    Task { @MainActor in _ = await store.startOrRepairService() }
                }
            } else if error.requiresPinUpdate {
                Button("Update Server Pin", action: onOpenDiagnostics)
            } else if error.requiresKeyRotation {
                Button("Rotate Key...", action: onOpenKeyRotation)
            } else if error.requiresIdentityReset {
                Button("Reset Identity...", action: onConfirmResetIdentity)
            }
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

    private func toastBanner(_ toast: String) -> some View {
        HStack {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(MeshPalette.brandPrimary)
            Text(toast)
                .font(.callout)
            Spacer()
            Button("Dismiss") {
                store.dismissToast()
            }
            .buttonStyle(.borderless)
        }
        .padding(10)
        .background(
            MeshPalette.brandPrimary.opacity(0.08),
            in: RoundedRectangle(cornerRadius: 8)
        )
    }
}

private struct DashboardWarningBanner: View {
    let icon: String
    let color: Color
    let title: String
    let message: String
    let actionTitle: String?
    let isBusy: Bool
    let action: (() -> Void)?

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(message).font(.callout)
            }
            Spacer()
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .disabled(isBusy)
            }
        }
        .padding(10)
        .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Centered single-card presentation for non-enrolled daemon lifecycle states.
struct DashboardCenteredCard<Actions: View>: View {
    let icon: String
    let tintColor: Color
    let title: String
    let subtitle: String
    @ViewBuilder let actions: () -> Actions

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 42))
                .foregroundStyle(tintColor)
            Text(title)
                .font(.title3.weight(.semibold))
            Text(subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
            actions()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

/// Persistent Header Hero shown above the 3-tab navigation bar across all enrolled states.
struct ConnectedHeroSummaryView: View {
    @ObservedObject var store: DesktopStore
    let onOpenKeyRotation: () -> Void
    let onConfirmResetIdentity: () -> Void
    @State private var copiedFeedback: Bool = false

    init(
        store: DesktopStore,
        onOpenKeyRotation: @escaping () -> Void = {},
        onConfirmResetIdentity: @escaping () -> Void = {}
    ) {
        self.store = store
        self.onOpenKeyRotation = onOpenKeyRotation
        self.onConfirmResetIdentity = onConfirmResetIdentity
    }

    var body: some View {
        GroupBox {
            HStack(alignment: .center, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    heroTitleRow
                    heroMetadataRow
                }
                Spacer()
                heroPrimaryAction
            }
            .padding(6)
        }
    }

    private var heroTitleRow: some View {
        let badgeColor = MeshPalette.color(for: store.menuBarGroup)
        let badgeTitle = store.uiState.resolvedTitle(
            isDegradedTunnel: store.isDegradedTunnel,
            isManuallyDisconnected: store.isManuallyDisconnected
        )
        return HStack(spacing: 8) {
            Text(store.status?.nodeName ?? "Unnamed Node")
                .font(.title3.weight(.semibold))
            Text(badgeTitle)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
                .background(badgeColor.opacity(0.15), in: Capsule())
                .foregroundStyle(badgeColor)
            if let overlayIp = store.status?.overlayIp {
                Text(overlayIp)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                Button(copiedFeedback ? "Copied" : "Copy") {
                    copyStandardText(overlayIp)
                    copiedFeedback = true
                    Task { @MainActor in
                        try? await Task.sleep(nanoseconds: 1_500_000_000)
                        copiedFeedback = false
                    }
                }
                .buttonStyle(.link)
            }
        }
    }

    private var heroMetadataRow: some View {
        HStack(spacing: 12) {
            if let fqdn = store.status?.fqdn {
                Text(fqdn)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            if let tunName = store.status?.tunInterfaceName {
                Text("TUN: \(tunName) (MTU \(store.status?.tunMtu ?? 1_280))")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            if let conn = store.status?.serverConnection {
                Text("Control: \(conn.controlEndpoint)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var heroPrimaryAction: some View {
        switch store.uiState {
        case .reauthRequired:
            Button("Rotate Key...", action: onOpenKeyRotation)
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
        case .revoked:
            Button("Reset Identity...", role: .destructive, action: onConfirmResetIdentity)
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
        case .error:
            if store.isManuallyDisconnected {
                Button("Connect") {
                    Task { @MainActor in _ = await store.connectOneClick() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            } else {
                Button("Retry") {
                    Task { @MainActor in await store.refreshNow() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            }
        case .connecting:
            Button("Disconnect") {
                Task { @MainActor in _ = await store.disconnect() }
            }
            .disabled(store.isBusy)
        case .connected:
            if store.isManuallyDisconnected {
                Button("Connect") {
                    Task { @MainActor in _ = await store.connectOneClick() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            } else {
                Button("Disconnect") {
                    Task { @MainActor in _ = await store.disconnect() }
                }
                .disabled(store.isBusy)
            }
        case .serviceNotInstalled, .serviceStopped, .unconfigured:
            EmptyView()
        }
    }

    private func copyStandardText(_ text: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
    }
}

/// Zone 1 (`Status` tab) rendered across all enrolled states (`ADR-028`).
struct StatusTabView: View {
    @ObservedObject var store: DesktopStore
    let onOpenKeyRotation: () -> Void
    let onConfirmResetIdentity: () -> Void
    let onOpenDiagnostics: () -> Void
    @State private var copiedField: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                lifecycleStateCard
                identityTelemetryCard
                networkTelemetryCard
            }
            .padding(4)
        }
    }

    private var lifecycleStateCard: some View {
        let tint = MeshPalette.color(for: store.menuBarGroup)
        return GroupBox("Connection Status") {
            HStack(alignment: .center, spacing: 14) {
                Image(systemName: store.menuBarGroup.symbolName)
                    .font(.system(size: 28))
                    .foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 4) {
                    Text(stateHeadline)
                        .font(.headline)
                    Text(stateSubtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                stateActionButtons
            }
            .padding(8)
        }
    }

    private var identityTelemetryCard: some View {
        GroupBox("Node Identity & Overlay") {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                GridRow {
                    Text("Node Name").foregroundStyle(.secondary)
                    Text(store.status?.nodeName ?? "—")
                }
                GridRow {
                    Text("Node ID").foregroundStyle(.secondary)
                    Text(store.status?.nodeId ?? "—").font(.caption.monospaced())
                }
                GridRow {
                    Text("Overlay IP").foregroundStyle(.secondary)
                    copyableValueRow(
                        value: store.status?.overlayIp,
                        label: "Overlay IP"
                    )
                }
                GridRow {
                    Text("FQDN").foregroundStyle(.secondary)
                    copyableValueRow(
                        value: store.status?.fqdn,
                        label: "FQDN"
                    )
                }
                GridRow {
                    Text("Overlay CIDR").foregroundStyle(.secondary)
                    Text(store.status?.overlayCidr ?? "—").font(.body.monospaced())
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
        }
    }

    private var networkTelemetryCard: some View {
        GroupBox("Control & Self-Network Telemetry") {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                GridRow {
                    Text("Control Endpoint").foregroundStyle(.secondary)
                    Text(store.status?.serverConnection?.controlEndpoint ?? "—")
                        .font(.body.monospaced())
                }
                GridRow {
                    Text("Relay Endpoint").foregroundStyle(.secondary)
                    let relay = store.status?.serverConnection?.relayEndpoint ?? ""
                    Text(relay.isEmpty ? "—" : relay).font(.body.monospaced())
                }
                GridRow {
                    Text("Local UDP / Interface").foregroundStyle(.secondary)
                    let port = store.status?.selfNetwork.localUdpPort ?? 0
                    let iface = store.status?.selfNetwork.boundPhysicalInterface ?? "auto"
                    Text(":\(port) • \(iface)").font(.body.monospaced())
                }
                GridRow {
                    Text("NAT Classification").foregroundStyle(.secondary)
                    Text(store.status?.selfNetwork.natType.displayLabel ?? "Unknown")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
        }
    }

    @ViewBuilder
    private func copyableValueRow(value: String?, label: String) -> some View {
        if let value, !value.isEmpty {
            HStack(spacing: 8) {
                Text(value).font(.body.monospaced()).textSelection(.enabled)
                Button(copiedField == label ? "Copied" : "Copy") {
                    let pasteboard = NSPasteboard.general
                    pasteboard.clearContents()
                    pasteboard.setString(value, forType: .string)
                    copiedField = label
                    Task { @MainActor in
                        try? await Task.sleep(nanoseconds: 1_500_000_000)
                        if copiedField == label {
                            copiedField = nil
                        }
                    }
                }
                .buttonStyle(.link)
            }
        } else {
            Text("—")
        }
    }

    @ViewBuilder
    private var stateActionButtons: some View {
        switch store.uiState {
        case .connecting:
            HStack(spacing: 10) {
                ProgressView().controlSize(.small)
                Button("Disconnect") {
                    Task { @MainActor in _ = await store.disconnect() }
                }
            }
            .disabled(store.isBusy)
        case .reauthRequired:
            HStack(spacing: 10) {
                Button("Rotate Pre-Auth Key...", action: onOpenKeyRotation)
                    .buttonStyle(.borderedProminent)
                Button("Disconnect") {
                    Task { @MainActor in _ = await store.disconnect() }
                }
            }
            .disabled(store.isBusy)
        case .revoked:
            Button("Reset Device Identity...", role: .destructive, action: onConfirmResetIdentity)
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
        case .error:
            HStack(spacing: 10) {
                Button("Start / Repair Service") {
                    Task { @MainActor in _ = await store.startOrRepairService() }
                }
                Button("Diagnostics", action: onOpenDiagnostics)
            }
            .disabled(store.isBusy)
        default:
            EmptyView()
        }
    }

    private var stateHeadline: String {
        switch store.uiState {
        case .connecting:
            return "Connecting to Mesh Network..."
        case .connected:
            if store.isManuallyDisconnected {
                return "Disconnected (Identity Saved)"
            }
            if store.isDegradedTunnel {
                return "Connected (Degraded: Relay Fallback)"
            }
            return "Connected to Mesh Network"
        case .reauthRequired:
            return "Node Pre-Auth Key Expired"
        case .revoked:
            return "Device Revoked by Control Server"
        case .error:
            return store.lastActionError?.title ?? "Daemon Communication Error"
        case .serviceNotInstalled, .serviceStopped, .unconfigured:
            return store.uiState.displayTitle
        }
    }

    private var stateSubtitle: String {
        switch store.uiState {
        case .connecting:
            let ep = store.status?.serverConnection?.controlEndpoint ?? "Control server"
            return "Establishing control session and utun interface for \(ep)."
        case .connected:
            if store.isManuallyDisconnected {
                return "Tunnel is down. Click Connect to resume without re-enrolling."
            }
            return "\(store.onlinePeerCount) of \(store.sortedPeers.count) peers online."
        case .reauthRequired:
            return "Control server requires a fresh mpk_ pre-auth key to reconnect."
        case .revoked:
            return "Reset local identity keys to re-enroll with a new pre-auth key."
        case .error:
            return store.lastActionError?.message
                ?? "Unable to communicate with meshd admin socket."
        case .serviceNotInstalled, .serviceStopped, .unconfigured:
            return ""
        }
    }
}
