import Foundation
import MeshCoreKit
import UIKit

/// Enrollment, tunnel control, diagnostics, and biometric-gated maintenance actions.
extension AppViewModel {
    // MARK: - Onboarding & Key Rotation (`US-091`, `US-092`)

    /// Parses a QR-scanned or pasted `mesh://join?...` URI into a confirmation draft.
    public func prepareJoinFromUri(_ rawUri: String, isRotation: Bool = false) {
        let trimmed = rawUri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        do {
            let parsed = try enrollmentClient.parseJoinUri(trimmed)
            let summary = parsed.summary
            let optionalName = manualNodeName.trimmingCharacters(in: .whitespacesAndNewlines)
            pendingConfirmation = EnrollmentConfirmationDraft(
                serverEndpoint: summary.serverEndpoint,
                portOverride: nil,
                tlsAuthMode: summary.tlsAuthMode,
                serverPin: summary.serverPin,
                nodeName: optionalName.isEmpty ? summary.nodeName : optionalName,
                maskedPreauthPreview: parsed.session.maskedPreview(),
                session: parsed.session,
                isRotation: isRotation
            )
            activeError = nil
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    /// Reads iOS 15 clipboard fallback string, prepares enrollment, and schedules clipboard wipe.
    public func pasteFromSystemClipboard() {
        #if canImport(UIKit)
        guard let rawValue = UIPasteboard.general.string else {
            activeError = MeshUserFacingError(
                code: "E_EMPTY_CLIPBOARD",
                title: "Clipboard Empty",
                message: "Copy a mesh://join URI or pre-auth key first."
            )
            return
        }
        handlePastedText(rawValue)
        scheduleClipboardRedactionIfMatching(rawValue)
        #endif
    }

    /// Accepts pasted text from iOS 16 `PasteButton` or iOS 15 fallback button.
    public func handlePastedText(_ pastedText: String) {
        let trimmed = pastedText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if trimmed.lowercased().hasPrefix("mesh://") {
            prepareJoinFromUri(trimmed, isRotation: isEnrolled)
        } else if trimmed.hasPrefix("mpk_") {
            manualPreauthKey = trimmed
        } else {
            prepareJoinFromUri(trimmed, isRotation: isEnrolled)
        }
    }

    /// Wraps manual endpoint + `mpk_*` into `MobilePendingJoinSession` and clears raw input.
    public func prepareManualEnrollment(isRotation: Bool = false) {
        var rawKey = manualPreauthKey.trimmingCharacters(in: .whitespacesAndNewlines)
        defer {
            rawKey = ""
            manualPreauthKey = ""
        }

        let endpoint = isRotation
            ? (bootstrapSummary?.serverEndpoint ?? "")
            : manualServerEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !endpoint.isEmpty else {
            activeError = MeshUserFacingError(
                code: "E_INVALID_ARG",
                title: "Missing Endpoint",
                message: "Enter the control server host:port before enrolling."
            )
            return
        }

        let tlsMode = isRotation
            ? (bootstrapSummary?.tlsAuthMode ?? manualTlsAuthMode)
            : manualTlsAuthMode
        let pinText = isRotation
            ? bootstrapSummary?.activePin
            : nonEmptyTrimmed(manualServerPin)

        if tlsMode == .spkiPin && pinText == nil {
            activeError = MeshUserFacingError(
                code: "E_INVALID_ARG",
                title: "SPKI Pin Required",
                message: "Enter the sha256:<hex> pin or switch TLS mode to System CA."
            )
            return
        }

        let portOverride: UInt16?
        let portTrimmed = manualPortText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !portTrimmed.isEmpty {
            guard let parsedPort = UInt16(portTrimmed), parsedPort > 0 else {
                activeError = MeshUserFacingError(
                    code: "E_INVALID_ARG",
                    title: "Invalid Port",
                    message: "Port override must be between 1 and 65535."
                )
                return
            }
            portOverride = parsedPort
        } else {
            portOverride = nil
        }

        do {
            let session = try enrollmentClient.createPendingJoinSession(rawKey)
            pendingConfirmation = EnrollmentConfirmationDraft(
                serverEndpoint: endpoint,
                portOverride: portOverride,
                tlsAuthMode: tlsMode,
                serverPin: pinText,
                nodeName: nonEmptyTrimmed(manualNodeName) ?? bootstrapSummary?.nodeName,
                maskedPreauthPreview: session.maskedPreview(),
                session: session,
                isRotation: isRotation
            )
            activeError = nil
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    public func cancelPendingEnrollment() {
        pendingConfirmation?.session.cancel()
        pendingConfirmation = nil
    }

    /// Executes zero-TUN container-app enrollment or key rotation after user confirmation.
    public func confirmPendingEnrollment() async {
        guard let draft = pendingConfirmation else { return }

        if draft.isRotation {
            let auth = await biometricAuthorizer.authorize(
                reason: "Authenticate to rotate node identity key"
            )
            guard case .authorized = auth else {
                handleBiometricFailure(auth)
                return
            }
            if tunnelStatus == .connected || tunnelStatus == .connecting {
                _ = try? await tunnelManager.disconnectManually()
            }
        }

        isBusy = true
        defer { isBusy = false }

        do {
            let bridge = makeContainerBridge()
            let initConfig = makeEngineInitConfig(defaultNodeName: draft.nodeName)
            let enrollCfg = MobileEnrollConfig(
                serverEndpoint: draft.serverEndpoint,
                portOverride: draft.portOverride,
                tlsAuthMode: draft.tlsAuthMode,
                serverPin: draft.serverPin,
                pendingJoin: draft.session,
                nodeName: draft.nodeName,
                rotateExistingIdentity: draft.isRotation
            )
            let snapshot = try await enrollmentClient.enrollOrRotateNode(
                initConfig: initConfig,
                bridge: bridge,
                enrollConfig: enrollCfg
            )
            pendingConfirmation = nil
            statusSnapshot = snapshot
            statusBannerMessage = draft.isRotation
                ? "Node identity key rotated."
                : "Enrollment completed."
            await refreshAllState()
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    // MARK: - Tunnel Lifecycle (`US-089`, `US-092`)

    public func connectTunnel() async {
        guard let bootstrapSummary else {
            activeError = MeshUserFacingError(
                code: "E_NOT_FOUND",
                title: "Not Enrolled",
                message: "Enroll this device before connecting the tunnel."
            )
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let config = try await tunnelManager.connect(
                bootstrap: bootstrapSummary,
                enableOnDemand: isOnDemandEnabled
            )
            tunnelStatus = config.status
            await refreshAllState()
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    /// Disables On-Demand and saves VPN preferences BEFORE stopping the tunnel (`US-092`).
    public func disconnectTunnel() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let config = try await tunnelManager.disconnectManually()
            isOnDemandEnabled = config.isOnDemandEnabled
            tunnelStatus = config.status
            await refreshAllState()
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    public func toggleOnDemand(_ enabled: Bool) async {
        isBusy = true
        defer { isBusy = false }
        do {
            let config = try await tunnelManager.setOnDemandEnabled(
                enabled,
                bootstrap: bootstrapSummary
            )
            isOnDemandEnabled = config.isOnDemandEnabled
            tunnelStatus = config.status
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    // MARK: - Diagnostics & Biometric-Gated Controls (`US-092`)

    public func pingPeer(_ peer: MobilePeerStatus) async {
        isBusy = true
        defer { isBusy = false }
        do {
            let req = IosTunnelIpcRequest(
                action: .ping,
                target: peer.name,
                count: 4,
                forceDirect: false,
                timeoutMs: 2000
            )
            let response = try await tunnelManager.sendIpc(req)
            if response.ok, let ping = response.ping {
                lastPingResponse = ping.toMobileModel()
            } else {
                activeError = MeshUserFacingError(
                    code: response.errorCode ?? "E_INTERNAL",
                    title: "Ping Failed",
                    message: response.errorMessage ?? "Peer did not respond"
                )
            }
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    public func runNetcheck() async {
        isBusy = true
        defer { isBusy = false }
        do {
            let response = try await tunnelManager.sendIpc(
                IosTunnelIpcRequest(action: .netcheck)
            )
            if response.ok, let netcheck = response.netcheck {
                lastNetcheckResponse = netcheck.toMobileModel()
            } else {
                activeError = MeshUserFacingError(
                    code: response.errorCode ?? "E_UNAVAILABLE",
                    title: "Netcheck Failed",
                    message: response.errorMessage ?? "Unable to run netcheck"
                )
            }
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    public func updateServerEndpoint(
        endpoint: String,
        tlsAuthMode: MobileTlsAuthMode,
        serverPin: String?
    ) async {
        let auth = await biometricAuthorizer.authorize(
            reason: "Authenticate to update Control server endpoint"
        )
        guard case .authorized = auth else {
            handleBiometricFailure(auth)
            return
        }

        let trimmedEndpoint = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedEndpoint.isEmpty else {
            activeError = MeshUserFacingError(
                code: "E_INVALID_ARG",
                title: "Invalid Endpoint",
                message: "Server endpoint cannot be empty."
            )
            return
        }
        if tlsAuthMode == .spkiPin && nonEmptyTrimmed(serverPin) == nil {
            activeError = MeshUserFacingError(
                code: "E_INVALID_ARG",
                title: "SPKI Pin Required",
                message: "SPKI pin mode requires a sha256:<hex> fingerprint."
            )
            return
        }

        if tunnelStatus == .connected || tunnelStatus == .connecting {
            _ = try? await tunnelManager.disconnectManually()
        }

        isBusy = true
        defer { isBusy = false }
        do {
            let bridge = makeContainerBridge()
            let initConfig = makeEngineInitConfig(defaultNodeName: bootstrapSummary?.nodeName)
            let setCfg = MobileSetConfig(
                serverEndpoint: trimmedEndpoint,
                tlsAuthMode: tlsAuthMode,
                serverPin: nonEmptyTrimmed(serverPin)
            )
            let snapshot = try await enrollmentClient.updateServerConfig(
                initConfig: initConfig,
                bridge: bridge,
                setConfig: setCfg
            )
            statusSnapshot = snapshot
            statusBannerMessage = "Server configuration updated."
            await refreshAllState()
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    public func exportBugreport() async {
        let auth = await biometricAuthorizer.authorize(
            reason: "Authenticate to export scrubbed Mesh diagnostics"
        )
        guard case .authorized = auth else {
            handleBiometricFailure(auth)
            return
        }

        isBusy = true
        defer { isBusy = false }
        do {
            if tunnelStatus == .connected || tunnelStatus == .reasserting {
                let response = try await tunnelManager.sendIpc(
                    IosTunnelIpcRequest(action: .exportBugreport)
                )
                if response.ok, let result = response.bugreport {
                    shareBugreportURL = URL(fileURLWithPath: result.bundlePath)
                    return
                }
                if let errorMsg = response.errorMessage {
                    activeError = MeshUserFacingError(
                        code: response.errorCode ?? "E_INTERNAL",
                        title: "Bugreport Export Failed",
                        message: errorMsg
                    )
                    return
                }
            }

            let timestampMs = UInt64(Date().timeIntervalSince1970 * 1000.0)
            let destURL = try appGroupStore.makeBugreportDestinationURL(timestampMs: timestampMs)
            let bridge = makeContainerBridge()
            let initConfig = makeEngineInitConfig(defaultNodeName: bootstrapSummary?.nodeName)
            let result = try await enrollmentClient.exportOfflineBugreport(
                initConfig: initConfig,
                bridge: bridge,
                destPath: destURL.path
            )
            shareBugreportURL = URL(fileURLWithPath: result.bundlePath)
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    /// Deletes temporary exported `.tar` once `UIActivityViewController` finishes or cancels.
    public func cleanupSharedBugreport(at url: URL) {
        shareBugreportURL = nil
        do {
            try appGroupStore.deleteDiagnosticsFile(at: url)
            statusBannerMessage = "Temporary bugreport deleted after share."
        } catch {
            logger.warning("bugreport_cleanup_failed", detail: error.localizedDescription)
        }
    }

    public func resetIdentity() async {
        let auth = await biometricAuthorizer.authorize(
            reason: "Authenticate to reset local Mesh device identity"
        )
        guard case .authorized = auth else {
            handleBiometricFailure(auth)
            return
        }

        isBusy = true
        defer { isBusy = false }
        do {
            try await tunnelManager.removeProfile()
            for fileName in [
                MeshConstants.sealedIdentityFileName,
                MeshConstants.bootstrapFileName,
                MeshConstants.netmapCacheFileName,
                MeshConstants.statusSnapshotFileName
            ] {
                try appGroupStore.deleteStateFile(fileName: fileName)
            }
            try dekStore.deleteDek()
            bootstrapSummary = nil
            statusSnapshot = nil
            isEnrolled = false
            isOnDemandEnabled = false
            tunnelStatus = .invalid
            lastPingResponse = nil
            lastNetcheckResponse = nil
            statusBannerMessage = "Local device identity wiped."
        } catch {
            activeError = MeshErrorMapper.map(error)
        }
    }

    private func scheduleClipboardRedactionIfMatching(_ copiedSecret: String) {
        clipboardClearTask?.cancel()
        let delayNs = UInt64(MeshConstants.clipboardClearDelaySeconds * 1_000_000_000)
        clipboardClearTask = Task {
            try? await Task.sleep(nanoseconds: delayNs)
            guard !Task.isCancelled else { return }
            #if canImport(UIKit)
            if UIPasteboard.general.string == copiedSecret {
                UIPasteboard.general.string = ""
            }
            #endif
        }
    }
}
