import AppKit
import MeshDesktopCore
import SwiftUI

/// AppKit delegate keeping the menu bar resident after the dashboard window closes (`ADR-025`).
@MainActor
final class MeshAppDelegate: NSObject, NSApplicationDelegate {
    weak var store: DesktopStore?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        NSApp.setActivationPolicy(.regular)
        for window in NSApp.windows where !(window is NSPanel) {
            let windowId = window.identifier?.rawValue ?? ""
            let isDashboard = windowId == "dashboard"
                || windowId.hasPrefix("dashboard-")
                || window.title == "Mesh VPN"
            if isDashboard {
                window.makeKeyAndOrderFront(nil)
            }
        }
        NSApp.activate(ignoringOtherApps: true)
        store?.setDashboardOpen(true)
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        store?.prepareForKeepConnectedQuit()
    }
}

/// Coordinates dashboard window visibility (`NSActivationPolicy`) and AppKit lifecycle events.
@MainActor
final class AppLifecycleCoordinator: NSObject, ObservableObject {
    private let store: DesktopStore

    init(store: DesktopStore) {
        self.store = store
        super.init()
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleWindowWillClose(_:)),
            name: NSWindow.willCloseNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleAppWillTerminate(_:)),
            name: NSApplication.willTerminateNotification,
            object: nil
        )
    }

    @objc
    private func handleAppWillTerminate(_ notification: Notification) {
        store.prepareForKeepConnectedQuit()
    }

    @objc
    private func handleWindowWillClose(_ notification: Notification) {
        guard let closingWindow = notification.object as? NSWindow else {
            return
        }
        let windowId = closingWindow.identifier?.rawValue ?? ""
        let isDashboard = windowId == "dashboard"
            || windowId.hasPrefix("dashboard-")
            || closingWindow.title == "Mesh VPN"
        guard isDashboard else {
            return
        }
        store.setDashboardOpen(false)
        let anotherDashboardVisible = NSApp.windows.contains { window in
            guard window !== closingWindow, window.isVisible else {
                return false
            }
            let otherId = window.identifier?.rawValue ?? ""
            return otherId == "dashboard"
                || otherId.hasPrefix("dashboard-")
                || window.title == "Mesh VPN"
        }
        if !anotherDashboardVisible {
            NSApp.setActivationPolicy(.accessory)
        }
    }
}

/// Native macOS Non-Sandboxed Menu Bar (`LSUIElement`) + Single-Instance Dashboard (`ADR-025`).
@main
struct MeshApp: App {
    @NSApplicationDelegateAdaptor(MeshAppDelegate.self) private var appDelegate
    @StateObject private var store: DesktopStore
    @StateObject private var lifecycle: AppLifecycleCoordinator
    @StateObject private var themeManager = ThemeManager()
    @StateObject private var localeManager = LocaleManager()

    @MainActor
    init() {
        let initialStore = DesktopStore()
        _store = StateObject(wrappedValue: initialStore)
        _lifecycle = StateObject(wrappedValue: AppLifecycleCoordinator(store: initialStore))
        Task { @MainActor [initialStore] in
            initialStore.startMonitoring()
        }
    }

    var body: some Scene {
        Window("Mesh VPN", id: "dashboard") {
            DashboardWindowView(
                store: store,
                themeManager: themeManager,
                localeManager: localeManager
            )
            .frame(minWidth: 760, minHeight: 540)
            .preferredColorScheme(themeManager.preferredColorScheme)
            .environmentObject(localeManager)
            .environment(\.locale, localeManager.effectiveLocale)
            .onAppear {
                appDelegate.store = store
                themeManager.applyAppearance()
                if !CommandLine.arguments.contains("--minimized") {
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                    store.setDashboardOpen(true)
                }
            }
        }
        .defaultSize(width: 860, height: 620)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }

        MenuBarExtra {
            MenuBarContentView(
                store: store,
                appDelegate: appDelegate,
                localeManager: localeManager
            )
            .preferredColorScheme(themeManager.preferredColorScheme)
            .environmentObject(localeManager)
            .environment(\.locale, localeManager.effectiveLocale)
        } label: {
            Label(
                "Mesh VPN",
                systemImage: store.menuBarGroup.symbolName
            )
            .symbolRenderingMode(.palette)
            .foregroundStyle(MeshPalette.color(for: store.menuBarGroup))
            .onAppear {
                appDelegate.store = store
                themeManager.applyAppearance()
            }
        }
    }
}

/// Dynamic Menu Bar popover listing quick status, peer IPs, Launch at Login, and Quit actions.
private struct MenuBarContentView: View {
    @ObservedObject var store: DesktopStore
    let appDelegate: MeshAppDelegate
    @ObservedObject var localeManager: LocaleManager
    @Environment(\.openWindow) private var openWindow

    private var loc: Locale { localeManager.effectiveLocale }

    var body: some View {
        VStack(alignment: .leading) {
            statusHeaderButton
            if store.versionBanner.requiresUpdateBanner {
                Text(versionWarningLabel)
            }
            Divider()
            primaryActionSection
            copyOverlayIpSection
            peersSubmenuSection
            Divider()
            launchAtLoginToggle
            Button(MeshL10n.tr("action.open_dashboard", locale: loc)) {
                bringDashboardToFront()
            }
            .keyboardShortcut("o")
            Divider()
            quitSection
        }
        .onAppear {
            appDelegate.store = store
        }
    }

    @ViewBuilder
    private var statusHeaderButton: some View {
        Text(statusSummaryLine)
        if let fqdn = store.status?.fqdn, !fqdn.isEmpty {
            Text(fqdn)
        }
    }

    @ViewBuilder
    private var primaryActionSection: some View {
        switch store.uiState {
        case .serviceNotInstalled:
            Button(MeshL10n.tr("service.start_repair", locale: loc)) {
                bringDashboardToFront()
            }
        case .serviceStopped:
            Button(MeshL10n.tr("service.start_repair", locale: loc)) {
                Task { _ = await store.startOrRepairService() }
            }
        case .unconfigured:
            Button(MeshL10n.tr("action.enroll", locale: loc)) {
                bringDashboardToFront()
            }
        case .connecting:
            Button(MeshL10n.tr("action.disconnect", locale: loc)) {
                Task { _ = await store.disconnect() }
            }
        case .connected:
            if store.isManuallyDisconnected {
                Button(MeshL10n.tr("action.connect", locale: loc)) {
                    Task { _ = await store.connectOneClick() }
                }
            } else {
                Button(MeshL10n.tr("action.disconnect", locale: loc)) {
                    Task { _ = await store.disconnect() }
                }
            }
        case .reauthRequired:
            Button(MeshL10n.tr("action.rotate_key", locale: loc)) {
                bringDashboardToFront()
            }
        case .revoked, .error:
            Button(MeshL10n.tr("action.open_dashboard", locale: loc)) {
                bringDashboardToFront()
            }
        }
    }

    @ViewBuilder
    private var copyOverlayIpSection: some View {
        if let ip = store.status?.overlayIp, !ip.isEmpty {
            Button("\(MeshL10n.tr("peers.copy_overlay_ip", locale: loc)) (\(ip))") {
                let pasteboard = NSPasteboard.general
                pasteboard.clearContents()
                pasteboard.setString(ip, forType: .string)
            }
        }
    }

    @ViewBuilder
    private var peersSubmenuSection: some View {
        let peers = store.sortedPeers
        if !peers.isEmpty {
            let peersLabel = MeshL10n.tr("tab.peers", locale: loc)
            Menu("\(peersLabel) (\(store.onlinePeerCount)/\(peers.count))") {
                ForEach(peers.prefix(15)) { peer in
                    Button(peerMenuTitle(peer)) {
                        let pasteboard = NSPasteboard.general
                        pasteboard.clearContents()
                        pasteboard.setString(peer.overlayIp, forType: .string)
                    }
                }
                if peers.count > 15 {
                    Divider()
                    Button(MeshL10n.tr("action.open_dashboard", locale: loc)) {
                        bringDashboardToFront()
                    }
                }
            }
        }
    }

    private var launchAtLoginToggle: some View {
        Toggle(
            MeshL10n.tr("action.launch_at_login", locale: loc),
            isOn: Binding(
                get: { store.launchAtLoginEnabled },
                set: { store.setLaunchAtLogin($0) }
            )
        )
    }

    @ViewBuilder
    private var quitSection: some View {
        Button(MeshL10n.tr("action.quit_keep", locale: loc)) {
            store.prepareForKeepConnectedQuit()
            NSApp.terminate(nil)
        }
        Button(MeshL10n.tr("action.disconnect_quit", locale: loc)) {
            Task { @MainActor in
                await store.disconnectAndPrepareForQuit()
                NSApp.terminate(nil)
            }
        }
        .disabled(!canDisconnectBeforeQuit)
    }

    private var canDisconnectBeforeQuit: Bool {
        guard let state = store.status?.daemonState else {
            return false
        }
        return state == .connected || state == .connecting || state == .degraded
    }

    private var statusSummaryLine: String {
        let key: String
        switch store.uiState {
        case .serviceNotInstalled: key = "tray.agent_unavailable"
        case .serviceStopped: key = "tray.service_stopped"
        case .unconfigured: key = "tray.not_enrolled"
        case .connecting: key = "tray.connecting"
        case .connected:
            if store.isManuallyDisconnected {
                key = "tray.disconnected"
            } else if store.isDegradedTunnel {
                key = "tray.degraded"
            } else {
                key = "tray.connected"
            }
        case .reauthRequired: key = "tray.reauth"
        case .revoked: key = "tray.revoked"
        case .error: key = "tray.attention"
        }
        return MeshL10n.tr(key, locale: loc)
    }

    private var versionWarningLabel: String {
        switch store.versionBanner {
        case .legacyPre030:
            return MeshL10n.tr("warn.legacy_agent", locale: loc)
        case .mismatch(let daemon, let app):
            return MeshL10n.tr("warn.version_mismatch", locale: loc)
                .replacingOccurrences(of: "{v1}", with: app)
                .replacingOccurrences(of: "{v2}", with: daemon)
        case .unknown, .matched:
            return ""
        }
    }

    private func peerMenuTitle(_ peer: AgentPeerStatus) -> String {
        let offlineLabel = MeshL10n.tr("peers.badge.offline", locale: loc)
        let state = peer.online ? peer.activePath.rawValue.uppercased() : offlineLabel
        return "\(peer.name) — \(peer.overlayIp) [\(state)]"
    }

    /// Brings the single-instance dashboard window forward and temporarily restores the Dock icon.
    private func bringDashboardToFront() {
        NSApp.setActivationPolicy(.regular)
        openWindow(id: "dashboard")
        NSApp.activate(ignoringOtherApps: true)
        store.setDashboardOpen(true)
    }
}
