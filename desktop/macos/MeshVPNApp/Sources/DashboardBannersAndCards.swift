import AppKit
import MeshDesktopCore
import SwiftUI

/// Alert, version mismatch, subnet conflict, firewall, and toast banners in the Dashboard.
struct DashboardBannersView: View {
    @ObservedObject var store: DesktopStore
    @EnvironmentObject private var localeManager: LocaleManager
    let onOpenDiagnostics: () -> Void
    let onOpenKeyRotation: () -> Void
    let onConfirmResetIdentity: () -> Void

    private var loc: Locale { localeManager.effectiveLocale }

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
                    title: MeshL10n.tr("warn.subnet_conflict", locale: loc),
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
                    title: MeshL10n.tr("warn.firewall", locale: loc),
                    message: fwWarn,
                    actionTitle: MeshL10n.tr("service.firewall_allow", locale: loc),
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
                    title: MeshL10n.tr("warn.degraded_tunnel", locale: loc),
                    message: MeshL10n.tr("warn.degraded_detail", locale: loc),
                    actionTitle: MeshL10n.tr("tab.diagnostics_settings", locale: loc),
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
            "\(MeshL10n.tr("warn.legacy_agent", locale: loc)) (<0.3.0)"
        case .mismatch(let daemon, let app):
            MeshL10n.tr("warn.version_mismatch", locale: loc)
                .replacingOccurrences(of: "{v1}", with: app)
                .replacingOccurrences(of: "{v2}", with: daemon)
        case .unknown, .matched:
            ""
        }
        return DashboardWarningBanner(
            icon: "arrow.triangle.2.circlepath.circle.fill",
            color: MeshPalette.semanticWarning,
            title: MeshL10n.tr("service.update_recommended", locale: loc),
            message: message,
            actionTitle: MeshL10n.tr("service.update", locale: loc),
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
                Button(MeshL10n.tr("service.start_repair", locale: loc)) {
                    Task { @MainActor in _ = await store.startOrRepairService() }
                }
            } else if error.requiresPinUpdate {
                Button(MeshL10n.tr("error.pin_mismatch", locale: loc), action: onOpenDiagnostics)
            } else if error.requiresKeyRotation {
                Button(MeshL10n.tr("action.rotate_key", locale: loc), action: onOpenKeyRotation)
            } else if error.requiresIdentityReset {
                Button(
                    MeshL10n.tr("action.reset_identity", locale: loc),
                    action: onConfirmResetIdentity
                )
            }
            Button(MeshL10n.tr("generic.dismiss", locale: loc)) {
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
            Button(MeshL10n.tr("generic.dismiss", locale: loc)) {
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
    @EnvironmentObject private var localeManager: LocaleManager
    let onOpenKeyRotation: () -> Void
    let onConfirmResetIdentity: () -> Void
    @State private var copiedFeedback: Bool = false

    private var loc: Locale { localeManager.effectiveLocale }

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
            isManuallyDisconnected: store.isManuallyDisconnected,
            locale: loc
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
                Button(
                    copiedFeedback
                        ? MeshL10n.tr("peers.copied_toast", locale: loc)
                        : MeshL10n.tr("peers.copy_overlay_ip", locale: loc)
                ) {
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
                Text("\(MeshL10n.tr("label.control", locale: loc)): \(conn.controlEndpoint)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var heroPrimaryAction: some View {
        switch store.uiState {
        case .reauthRequired:
            Button(MeshL10n.tr("action.rotate_key", locale: loc), action: onOpenKeyRotation)
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
        case .revoked:
            Button(
                MeshL10n.tr("action.reset_identity", locale: loc),
                role: .destructive,
                action: onConfirmResetIdentity
            )
            .buttonStyle(.borderedProminent)
            .disabled(store.isBusy)
        case .error:
            if store.isManuallyDisconnected {
                Button(MeshL10n.tr("generic.connect", locale: loc)) {
                    Task { @MainActor in _ = await store.connectOneClick() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            } else {
                Button(MeshL10n.tr("generic.refresh", locale: loc)) {
                    Task { @MainActor in await store.refreshNow() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            }
        case .connecting:
            Button(MeshL10n.tr("generic.disconnect", locale: loc)) {
                Task { @MainActor in _ = await store.disconnect() }
            }
            .disabled(store.isBusy)
        case .connected:
            if store.isManuallyDisconnected {
                Button(MeshL10n.tr("generic.connect", locale: loc)) {
                    Task { @MainActor in _ = await store.connectOneClick() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.isBusy)
            } else {
                Button(MeshL10n.tr("generic.disconnect", locale: loc)) {
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
    @EnvironmentObject private var localeManager: LocaleManager
    let onOpenKeyRotation: () -> Void
    let onConfirmResetIdentity: () -> Void
    let onOpenDiagnostics: () -> Void
    @State private var copiedField: String?

    private var loc: Locale { localeManager.effectiveLocale }

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
        return GroupBox(MeshL10n.tr("tab.status", locale: loc)) {
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
        GroupBox(MeshL10n.tr("label.overlay", locale: loc)) {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                GridRow {
                    Text(MeshL10n.tr("onboarding.node_name", locale: loc))
                        .foregroundStyle(.secondary)
                    Text(store.status?.nodeName ?? "—")
                }
                GridRow {
                    Text("Node ID").foregroundStyle(.secondary)
                    Text(store.status?.nodeId ?? "—").font(.caption.monospaced())
                }
                GridRow {
                    Text("Overlay IP").foregroundStyle(.secondary)
                    copyableValueRow(value: store.status?.overlayIp, label: "Overlay IP")
                }
                GridRow {
                    Text("FQDN").foregroundStyle(.secondary)
                    copyableValueRow(value: store.status?.fqdn, label: "FQDN")
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
        GroupBox(MeshL10n.tr("diag.tunnel_telemetry", locale: loc)) {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                GridRow {
                    Text(MeshL10n.tr("label.control", locale: loc)).foregroundStyle(.secondary)
                    Text(store.status?.serverConnection?.controlEndpoint ?? "—")
                        .font(.body.monospaced())
                }
                GridRow {
                    Text(MeshL10n.tr("label.blind_relay", locale: loc)).foregroundStyle(.secondary)
                    let relay = store.status?.serverConnection?.relayEndpoint ?? ""
                    Text(relay.isEmpty ? "—" : relay).font(.body.monospaced())
                }
                GridRow {
                    Text(MeshL10n.inline(en: "Local UDP / Interface",
                                         vi: "UDP cục bộ / Giao diện", locale: loc))
                        .foregroundStyle(.secondary)
                    let port = store.status?.selfNetwork.localUdpPort ?? 0
                    let iface = store.status?.selfNetwork.boundPhysicalInterface ?? "auto"
                    Text(":\(port) • \(iface)").font(.body.monospaced())
                }
                GridRow {
                    Text(MeshL10n.inline(en: "NAT Classification",
                                         vi: "Phân loại NAT", locale: loc))
                        .foregroundStyle(.secondary)
                    let natUnknown = MeshL10n.inline(en: "Unknown", vi: "Không rõ", locale: loc)
                    Text(store.status?.selfNetwork.natType.displayLabel ?? natUnknown)
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
                Button(
                    copiedField == label
                        ? MeshL10n.tr("peers.copied_toast", locale: loc)
                        : MeshL10n.inline(en: "Copy", vi: "Sao chép", locale: loc)
                ) {
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
                Button(MeshL10n.tr("generic.disconnect", locale: loc)) {
                    Task { @MainActor in _ = await store.disconnect() }
                }
            }
            .disabled(store.isBusy)
        case .reauthRequired:
            HStack(spacing: 10) {
                Button(MeshL10n.tr("action.rotate_key", locale: loc), action: onOpenKeyRotation)
                    .buttonStyle(.borderedProminent)
                Button(MeshL10n.tr("generic.disconnect", locale: loc)) {
                    Task { @MainActor in _ = await store.disconnect() }
                }
            }
            .disabled(store.isBusy)
        case .revoked:
            Button(
                MeshL10n.tr("action.reset_identity", locale: loc),
                role: .destructive,
                action: onConfirmResetIdentity
            )
            .buttonStyle(.borderedProminent)
            .disabled(store.isBusy)
        case .error:
            HStack(spacing: 10) {
                Button(MeshL10n.tr("service.start_repair", locale: loc)) {
                    Task { @MainActor in _ = await store.startOrRepairService() }
                }
                Button(
                    MeshL10n.tr("tab.diagnostics_settings", locale: loc),
                    action: onOpenDiagnostics
                )
            }
            .disabled(store.isBusy)
        default:
            EmptyView()
        }
    }

    private var stateHeadline: String {
        switch store.uiState {
        case .connecting:
            return MeshL10n.tr("headline.connecting", locale: loc)
        case .connected:
            if store.isManuallyDisconnected {
                return MeshL10n.tr("headline.disconnected_enrolled", locale: loc)
            }
            if store.isDegradedTunnel {
                return MeshL10n.tr("headline.degraded", locale: loc)
            }
            return MeshL10n.tr("headline.connected", locale: loc)
        case .reauthRequired:
            return MeshL10n.tr("headline.reauth", locale: loc)
        case .revoked:
            return MeshL10n.tr("headline.revoked", locale: loc)
        case .error:
            return store.lastActionError?.title ?? MeshL10n.tr("headline.error", locale: loc)
        case .serviceNotInstalled, .serviceStopped, .unconfigured:
            return store.uiState.localizedTitle(locale: loc)
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
            return MeshL10n.tr("rotation.subtitle", locale: loc)
        case .revoked:
            return MeshL10n.tr("confirm.reset_detail", locale: loc)
        case .error:
            return store.lastActionError?.message
                ?? "Unable to communicate with meshd admin socket."
        case .serviceNotInstalled, .serviceStopped, .unconfigured:
            return ""
        }
    }
}
