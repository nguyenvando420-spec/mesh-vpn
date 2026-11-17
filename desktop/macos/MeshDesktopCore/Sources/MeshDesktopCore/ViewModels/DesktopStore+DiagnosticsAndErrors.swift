import Foundation

/// Diagnostics (`netcheck`, `ping`, `.tar` export), service actions, and safe error mapping.
extension DesktopStore {
    public func runNetcheck() async -> NetcheckResponse? {
        guard !isBusy else {
            return nil
        }
        isBusy = true
        busyMessage = "Running network diagnostics..."
        lastActionError = nil
        defer {
            isBusy = false
            busyMessage = nil
        }
        do {
            let response = try await transport.runNetcheck(socketPath: roSocketPath)
            latestNetcheck = response
            lastToastMessage = "Netcheck completed."
            return response
        } catch {
            lastActionError = mapErrorToUserFacing(error)
            recomputeDerivedUiState()
            return nil
        }
    }

    public func pingPeer(
        target: String,
        count: UInt16 = 4,
        forceDirect: Bool = false,
        timeoutMs: UInt64 = 3_000
    ) async -> PingResponse? {
        guard !isBusy else {
            return nil
        }
        let trimmedTarget = target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedTarget.isEmpty else {
            lastActionError = DesktopUserFacingError(
                code: "invalid_target",
                title: "Invalid Ping Target",
                message: "Select a peer before starting a ping probe."
            )
            return nil
        }
        isBusy = true
        busyMessage = "Pinging \(trimmedTarget)..."
        lastActionError = nil
        defer {
            isBusy = false
            busyMessage = nil
        }
        do {
            let req = PingRequest(
                target: trimmedTarget,
                count: count,
                forceDirect: forceDirect,
                timeoutMs: timeoutMs
            )
            let response = try await transport.pingPeer(socketPath: roSocketPath, request: req)
            latestPing = response
            return response
        } catch {
            lastActionError = mapErrorToUserFacing(error)
            recomputeDerivedUiState()
            return nil
        }
    }

    /// Streams `.tar` diagnostics AFTER user confirms `NSSavePanel` (`IG-DGUI-WA-03`).
    public func exportBugreport(to destinationURL: URL) async -> BugreportExportResult? {
        guard !isBusy else {
            return nil
        }
        isBusy = true
        busyMessage = "Exporting redacted diagnostics..."
        lastActionError = nil
        defer {
            isBusy = false
            busyMessage = nil
        }
        return await withSuspendedPolling {
            do {
                let result = try await BugreportStreamWriter.exportStream(
                    transport: transport,
                    adminSocketPath: adminSocketPath,
                    destinationURL: destinationURL
                )
                lastToastMessage = "Exported \(result.totalBytes) bytes "
                    + "(\(result.scrubbedItems) secrets redacted)."
                return result
            } catch {
                lastActionError = mapErrorToUserFacing(error)
                recomputeDerivedUiState()
                return nil
            }
        }
    }

    public func startOrRepairService() async -> Bool {
        await runPrivilegedAction(
            action: .kickstartDaemon,
            busyText: "Starting background service...",
            successToast: "Mesh VPN background service started."
        )
    }

    public func installOrUpdateService(firewallOptIn: Bool) async -> Bool {
        let succeeded = await runPrivilegedAction(
            action: .installOrUpdateService(firewallOptIn: firewallOptIn),
            busyText: "Installing background service...",
            successToast: "Mesh VPN background service installed."
        )
        if succeeded {
            await refreshStatus(probeVersionIfNeeded: true)
        }
        return succeeded
    }

    public func uninstallService(purgeData: Bool) async -> Bool {
        let succeeded = await runPrivilegedAction(
            action: .uninstallService(purgeData: purgeData),
            busyText: "Removing background service...",
            successToast: purgeData
                ? "Service uninstalled and identity keys purged."
                : "Service uninstalled. Identity keys preserved."
        )
        if succeeded {
            status = nil
            versionBanner = .unknown
            latestNetcheck = nil
            latestPing = nil
            lastConnectError = nil
            await refreshStatus(probeVersionIfNeeded: true)
        }
        return succeeded
    }

    public func enableFirewallException() async -> Bool {
        await runPrivilegedAction(
            action: .enableFirewallException,
            busyText: "Authorizing daemon firewall exception...",
            successToast: "macOS Application Firewall exception added for meshd."
        )
    }

    public func setLaunchAtLogin(_ enabled: Bool) {
        lastActionError = nil
        do {
            try launchAtLogin.setEnabled(enabled)
            launchAtLoginEnabled = launchAtLogin.isEnabled
            lastToastMessage = enabled
                ? "Mesh VPN will launch automatically at login."
                : "Launch at login disabled."
        } catch {
            launchAtLoginEnabled = launchAtLogin.isEnabled
            lastActionError = mapErrorToUserFacing(error)
        }
    }

    private func runPrivilegedAction(
        action: PrivilegedDaemonAction,
        busyText: String,
        successToast: String
    ) async -> Bool {
        guard !isBusy else {
            return false
        }
        isBusy = true
        busyMessage = busyText
        lastActionError = nil
        defer {
            isBusy = false
            busyMessage = nil
        }

        let succeeded = await withSuspendedPolling {
            do {
                try await self.privilegeHelper.execute(action)
                self.lastToastMessage = successToast
                return true
            } catch AdminPrivilegeError.userCancelled {
                self.lastToastMessage = "Administrator authorization was cancelled."
                self.recomputeDerivedUiState()
                return false
            } catch {
                self.lastActionError = self.mapErrorToUserFacing(error)
                self.recomputeDerivedUiState()
                return false
            }
        }
        if succeeded {
            await self.refreshStatus(probeVersionIfNeeded: true)
        }
        return succeeded
    }

    func mapErrorToUserFacing(_ error: Error) -> DesktopUserFacingError {
        if let validationErr = error as? DesktopValidationError {
            return DesktopUserFacingError(
                code: "invalid_argument",
                title: "Validation Error",
                message: validationErr.localizedDescription
            )
        }
        if let ipcErr = error as? IpcClientError {
            return mapIpcError(ipcErr)
        }
        if let bugErr = error as? BugreportWriterError {
            return DesktopUserFacingError(
                code: "bugreport_export_failed",
                title: "Bugreport Export Failed",
                message: bugErr.localizedDescription
            )
        }
        if let privErr = error as? AdminPrivilegeError {
            return mapPrivilegeError(privErr)
        }
        return DesktopUserFacingError(
            code: "unexpected_error",
            title: "Operation Failed",
            message: MeshSecretScrubber.scrub(error.localizedDescription)
        )
    }

    private func mapPrivilegeError(_ error: AdminPrivilegeError) -> DesktopUserFacingError {
        let code: String
        let title: String
        switch error {
        case .userCancelled:
            code = "cancelled"
            title = "Cancelled"
        case .scriptMissing:
            code = "installer_missing"
            title = "Installer Package Required"
        case .invalidBundleResourcePath:
            code = "invalid_bundle_path"
            title = "Unsafe App Bundle Location"
        case .executionFailed:
            code = "privileged_command_failed"
            title = "Service Command Failed"
        }
        return DesktopUserFacingError(code: code, title: title, message: error.localizedDescription)
    }

    private func mapIpcError(_ error: IpcClientError) -> DesktopUserFacingError {
        switch error {
        case .permissionDenied(let msg):
            return DesktopUserFacingError(
                code: "permission_denied",
                title: "Administrator Access Needed",
                message: msg,
                isPermissionDenied: true
            )
        case .serviceUnavailable(let msg):
            return DesktopUserFacingError(
                code: "service_unavailable",
                title: "Service Offline",
                message: msg
            )
        case .timeout(let msg):
            return DesktopUserFacingError(
                code: "ipc_timeout",
                title: "Service Timeout",
                message: msg
            )
        case .invalidResponse(let msg):
            return DesktopUserFacingError(
                code: "invalid_ipc_response",
                title: "Invalid Service Response",
                message: msg
            )
        case .streamConstraintViolation(let msg):
            return DesktopUserFacingError(
                code: "stream_violation",
                title: "Diagnostics Stream Error",
                message: msg
            )
        case .remoteError(_, let envelope):
            return mapRemoteEnvelope(envelope)
        }
    }

    private func mapRemoteEnvelope(_ envelope: ErrorEnvelope) -> DesktopUserFacingError {
        switch envelope.kind {
        case .unauthenticated:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "Authentication Failed",
                message: "authentication failed"
            )
        case .nodeRevoked:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "Device Revoked",
                message: envelope.message,
                requiresIdentityReset: true
            )
        case .nodeKeyExpired:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "Node Key Expired",
                message: envelope.message,
                requiresKeyRotation: true
            )
        case .pinMismatch:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "Server SPKI Pin Mismatch",
                message: envelope.message,
                requiresPinUpdate: true
            )
        case .permissionDenied:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "Permission Denied",
                message: envelope.message,
                isPermissionDenied: true
            )
        case .clockSkew:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "System Clock Skew",
                message: envelope.message
            )
        case .invalidArgument:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "Invalid Configuration",
                message: envelope.message
            )
        case .conflict, .rateLimited, .notFound, .unavailable, .internal:
            return DesktopUserFacingError(
                code: envelope.code,
                title: "Daemon Request Failed",
                message: envelope.message
            )
        }
    }
}
