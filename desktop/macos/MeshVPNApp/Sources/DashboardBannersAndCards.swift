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
               !conflict.isEmpty
            {
                DashboardWarningBanner(
                    icon: "exclamationmark.triangle.fill",
                    color: .orange,
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
                    color: .orange,
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
                    color: .yellow,
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
            color: .orange,
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
                .foregroundStyle(.red)
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
        .background(Color.red.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
    }

    private func toastBanner(_ toast: String) -> some View {
        HStack {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(.blue)
            Text(toast)
                .font(.callout)
            Spacer()
            Button("Dismiss") {
                store.dismissToast()
            }
            .buttonStyle(.borderless)
        }
        .padding(10)
        .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
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

/// Centered single-card presentation for non-connected daemon lifecycle states.
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

/// Top identity & quick-connect card shown above Peers/Diagnostics in Connected state.
struct ConnectedHeroSummaryView: View {
    @ObservedObject var store: DesktopStore

    var body: some View {
        GroupBox {
            HStack(alignment: .center, spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(store.status?.nodeName ?? "Unnamed Node")
                            .font(.title3.weight(.semibold))
                        if let overlayIp = store.status?.overlayIp {
                            Text(overlayIp)
                                .font(.body.monospaced())
                                .textSelection(.enabled)
                            Button("Copy") {
                                let pasteboard = NSPasteboard.general
                                pasteboard.clearContents()
                                pasteboard.setString(overlayIp, forType: .string)
                            }
                            .buttonStyle(.link)
                        }
                    }
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
                Spacer()
                if store.isManuallyDisconnected {
                    Button("Connect") {
                        Task { @MainActor in
                            _ = await store.connectOneClick()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(store.isBusy)
                } else {
                    Button("Disconnect") {
                        Task { @MainActor in
                            _ = await store.disconnect()
                        }
                    }
                    .disabled(store.isBusy)
                }
            }
            .padding(6)
        }
    }
}
