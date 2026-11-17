import Foundation

/// Manual onboarding form inputs passed to `DesktopStore.prepareDraftFromManualForm` (`US-110`).
public struct ManualOnboardingInput: Equatable, Sendable {
    public let rawEndpoint: String
    public let rawPortOverride: String
    public let tlsAuthMode: TlsAuthMode
    public let rawServerPin: String
    public let rawPreauthKey: String
    public let rawNodeName: String

    public init(
        rawEndpoint: String,
        rawPortOverride: String = "",
        tlsAuthMode: TlsAuthMode,
        rawServerPin: String = "",
        rawPreauthKey: String,
        rawNodeName: String = ""
    ) {
        self.rawEndpoint = rawEndpoint
        self.rawPortOverride = rawPortOverride
        self.tlsAuthMode = tlsAuthMode
        self.rawServerPin = rawServerPin
        self.rawPreauthKey = rawPreauthKey
        self.rawNodeName = rawNodeName
    }
}

/// Onboarding draft validation, enrollment confirmation, and connection control actions.
extension DesktopStore {
    public func handlePastedOnboardingInput(_ pastedText: String) -> EnrollmentConfirmationDraft? {
        let trimmed = pastedText.trimmingCharacters(in: .whitespacesAndNewlines)
        if MeshSecretScrubber.containsSecretPattern(trimmed) {
            clipboardAutoClear.recordAndScheduleWipe(text: pastedText)
        }
        return prepareDraftFromJoinUri(trimmed)
    }

    public func handleManualPreauthKeyChange(_ fieldValue: String) {
        guard !fieldValue.isEmpty else {
            return
        }
        clipboardAutoClear.scheduleWipeIfClipboardMatchesFieldText(fieldValue)
    }

    public func prepareDraftFromJoinUri(_ rawUri: String) -> EnrollmentConfirmationDraft? {
        lastActionError = nil
        do {
            let parsed = try JoinUriParser.parse(rawUri)
            let draft = EnrollmentConfirmationDraft(
                serverEndpoint: parsed.controlEndpoint,
                portOverride: nil,
                tlsAuthMode: parsed.tlsAuthMode,
                serverPin: parsed.serverPin,
                nodeName: parsed.nodeName,
                maskedPreauthPreview: parsed.maskedPreauthPreview,
                preauthKeySecret: parsed.unsafeRawPreauthKey(),
                isRotation: false
            )
            pendingEnrollmentDraft = draft
            logger.info("join_uri_draft_prepared", detail: parsed.redactedUriString)
            return draft
        } catch {
            lastActionError = mapErrorToUserFacing(error)
            recomputeDerivedUiState()
            return nil
        }
    }

    public func prepareDraftFromManualForm(
        _ input: ManualOnboardingInput
    ) -> EnrollmentConfirmationDraft? {
        lastActionError = nil
        do {
            let trimmedPort = input.rawPortOverride.trimmingCharacters(in: .whitespacesAndNewlines)
            let parsedPort: UInt16? = trimmedPort.isEmpty
                ? nil
                : try EndpointNormalizer.parseStrictPort(trimmedPort)
            let policy = try EndpointNormalizer.validateDesktopTlsPolicy(
                rawEndpoint: input.rawEndpoint,
                portOverride: parsedPort,
                tlsAuthMode: input.tlsAuthMode,
                rawServerPin: input.rawServerPin
            )
            let trimmedKey = input.rawPreauthKey.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedKey.isEmpty else {
                throw DesktopValidationError.invalidArgument("Pre-auth key is required.")
            }
            try JoinUriParser.validatePreauthKey(trimmedKey)

            let trimmedNode = input.rawNodeName.trimmingCharacters(in: .whitespacesAndNewlines)
            let validatedNode: String? = trimmedNode.isEmpty
                ? nil
                : try JoinUriParser.validateNodeName(trimmedNode)

            let draft = EnrollmentConfirmationDraft(
                serverEndpoint: policy.normalized.endpoint,
                portOverride: nil,
                tlsAuthMode: policy.tlsAuthMode,
                serverPin: policy.serverPin,
                nodeName: validatedNode,
                maskedPreauthPreview: JoinUriParser.maskPreauthKey(trimmedKey),
                preauthKeySecret: trimmedKey,
                isRotation: false
            )
            pendingEnrollmentDraft = draft
            logger.info("manual_draft_prepared", detail: policy.normalized.endpoint)
            return draft
        } catch {
            lastActionError = mapErrorToUserFacing(error)
            recomputeDerivedUiState()
            return nil
        }
    }

    public func prepareKeyRotationDraft(rawPreauthKey: String) -> EnrollmentConfirmationDraft? {
        lastActionError = nil
        do {
            let trimmedKey = rawPreauthKey.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedKey.isEmpty else {
                throw DesktopValidationError.invalidArgument("Pre-auth key is required.")
            }
            try JoinUriParser.validatePreauthKey(trimmedKey)

            let conn = status?.serverConnection
            let draft = EnrollmentConfirmationDraft(
                serverEndpoint: conn?.controlEndpoint ?? "configured-control-server",
                portOverride: nil,
                tlsAuthMode: conn?.tlsAuthMode ?? .spkiPin,
                serverPin: conn?.activePin,
                nodeName: status?.nodeName,
                maskedPreauthPreview: JoinUriParser.maskPreauthKey(trimmedKey),
                preauthKeySecret: trimmedKey,
                isRotation: true
            )
            pendingEnrollmentDraft = draft
            logger.info("rotate_key_draft_prepared")
            return draft
        } catch {
            lastActionError = mapErrorToUserFacing(error)
            recomputeDerivedUiState()
            return nil
        }
    }

    public func cancelEnrollmentDraft() {
        pendingEnrollmentDraft?.wipeSecret()
        pendingEnrollmentDraft = nil
    }

    public func confirmEnrollmentDraft() async -> Bool {
        guard var draft = pendingEnrollmentDraft else {
            return false
        }
        pendingEnrollmentDraft = nil
        defer {
            draft.wipeSecret()
            _ = clipboardAutoClear.clearIfMatchingNow()
        }

        let isRotation = draft.isRotation
        let endpoint = draft.serverEndpoint
        let portOverride = draft.portOverride
        let serverPin = draft.serverPin
        let nodeName = draft.nodeName
        let rawKey = draft.unsafeRawPreauthKeyForIpc()

        return await runBusyAdminMutation(
            message: isRotation ? "Rotating node key..." : "Enrolling device..."
        ) {
            if isRotation {
                let req = AgentRotateKeyRequest(preauthKey: rawKey)
                _ = try await self.transport.rotateKey(
                    socketPath: self.adminSocketPath,
                    request: req
                )
                self.lastToastMessage = "Node key rotated. Reconnecting..."
            } else {
                let req = AgentUpRequest(
                    serverEndpoint: endpoint,
                    portOverride: portOverride,
                    serverPin: serverPin,
                    preauthKey: rawKey,
                    nodeName: nodeName
                )
                _ = try await self.transport.bringUp(
                    socketPath: self.adminSocketPath,
                    request: req
                )
                self.lastToastMessage = "Enrollment submitted. Connecting..."
            }
        }
    }

    public func connectOneClick() async -> Bool {
        guard let conn = status?.serverConnection else {
            lastActionError = DesktopUserFacingError(
                code: "not_enrolled",
                title: "Enrollment Required",
                message: "Configure a Control endpoint and pre-auth key before connecting."
            )
            recomputeDerivedUiState()
            return false
        }
        let pinForUp: String? = conn.tlsAuthMode == .systemCa ? nil : conn.activePin
        let endpoint = conn.controlEndpoint
        let nodeName = status?.nodeName
        return await runBusyAdminMutation(message: "Connecting VPN...") {
            let req = AgentUpRequest(
                serverEndpoint: endpoint,
                portOverride: nil,
                serverPin: pinForUp,
                preauthKey: nil,
                nodeName: nodeName
            )
            _ = try await self.transport.bringUp(socketPath: self.adminSocketPath, request: req)
            self.lastToastMessage = "VPN connection started."
        }
    }

    public func disconnect() async -> Bool {
        await runBusyAdminMutation(message: "Disconnecting VPN...") {
            _ = try await self.transport.bringDown(socketPath: self.adminSocketPath)
            self.lastToastMessage = "VPN disconnected. Identity preserved."
        }
    }

    public func cleanupStaleState() async -> Bool {
        await runBusyAdminMutation(message: "Cleaning up stale network state...") {
            _ = try await self.transport.cleanup(socketPath: self.adminSocketPath)
            self.lastToastMessage = "Stale tunnel and route resources cleaned up."
        }
    }

    public func updateServerConfig(
        rawEndpoint: String,
        rawPortOverride: String,
        tlsAuthMode: TlsAuthMode,
        rawServerPin: String
    ) async -> Bool {
        lastActionError = nil
        do {
            let trimmedPort = rawPortOverride.trimmingCharacters(in: .whitespacesAndNewlines)
            let parsedPort: UInt16? = trimmedPort.isEmpty
                ? nil
                : try EndpointNormalizer.parseStrictPort(trimmedPort)
            let policy = try EndpointNormalizer.validateDesktopTlsPolicy(
                rawEndpoint: rawEndpoint,
                portOverride: parsedPort,
                tlsAuthMode: tlsAuthMode,
                rawServerPin: rawServerPin
            )
            let req = AgentSetRequest(
                serverEndpoint: policy.normalized.endpoint,
                serverPin: policy.serverPin
            )
            return await runBusyAdminMutation(message: "Updating Control server...") {
                _ = try await self.transport.updateServer(
                    socketPath: self.adminSocketPath,
                    request: req
                )
                self.lastToastMessage = "Control server updated to \(policy.normalized.endpoint)."
            }
        } catch {
            lastActionError = mapErrorToUserFacing(error)
            recomputeDerivedUiState()
            return false
        }
    }

    public func resetIdentity() async -> Bool {
        await runBusyAdminMutation(message: "Resetting device identity...") {
            _ = try await self.transport.resetIdentity(socketPath: self.adminSocketPath)
            self.latestNetcheck = nil
            self.latestPing = nil
            self.lastToastMessage = "Device identity cleared. Ready for re-enrollment."
        }
    }
}
