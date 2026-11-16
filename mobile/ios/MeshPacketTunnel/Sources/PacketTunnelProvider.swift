import Darwin
import Foundation
import MeshCoreKit
import Network
import NetworkExtension
import os.proc

/// Thread-safe one-shot wrapper bridging Objective-C reply closures to Swift 6 tasks.
private final class IpcReplyBox: @unchecked Sendable {
    // SAFETY-SENDABLE: Access to `handler` is locked and invoked at most once.
    private let lock = NSLock()
    private var handler: ((Data?) -> Void)?

    init(_ handler: ((Data?) -> Void)?) {
        self.handler = handler
    }

    func complete(with data: Data?) {
        lock.lock()
        let callback = handler
        handler = nil
        lock.unlock()
        callback?(data)
    }
}

/// Mutable runtime state serialized inside `PacketTunnelProvider`.
private struct PacketTunnelRuntimeState {
    var engine: MobileEngine?
    var bridge: IosPlatformBridge?
    var appGroupStore: CoordinatedAppGroupStore?
    var bootstrap: BootstrapSummary?
    var packetWriter: BoundedPacketWriter?
    var packetPump: PacketFlowPump?
    var pathMonitor: NWPathMonitor?
    var memorySource: DispatchSourceMemoryPressure?
    var routeContinuation: AsyncStream<RouteChangeEvent>.Continuation?
    var routeTask: Task<Void, Never>?
    var lastUnderlay: UnderlayPathSnapshot?
    var isStopping = false
}

/// Network Extension `NEPacketTunnelProvider` owning the Rust `MobileEngine` runtime (`ADR-014`).
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    // SAFETY-SENDABLE: All mutable state is synchronized through `stateLock`.
    private let stateLock = LockedBox(PacketTunnelRuntimeState())
    private let monitorQueue = DispatchQueue(
        label: "dev.meshvpn.ios.path-monitor",
        qos: .utility
    )
    private let memoryQueue = DispatchQueue(
        label: "dev.meshvpn.ios.memory-pressure",
        qos: .utility
    )
    private let logger = MeshLogger(category: "packet_tunnel")

    override func startTunnel(options: [String: NSObject]?) async throws {
        try validateNoSecretOptions(options)
        let appGroupStore = try CoordinatedAppGroupStore()
        let bootstrap = try loadBootstrapConfiguration(from: appGroupStore)
        let packetWriter = BoundedPacketWriter()

        var routeStreamContinuation: AsyncStream<RouteChangeEvent>.Continuation?
        let routeStream = AsyncStream<RouteChangeEvent>(bufferingPolicy: .bufferingNewest(16)) {
            routeStreamContinuation = $0
        }

        let bridge = makeBridge(
            appGroupStore: appGroupStore,
            packetWriter: packetWriter,
            routeContinuation: routeStreamContinuation
        )
        let engine = try MobileEngine(
            init: MobileEngineInitConfig(
                platform: .ios,
                agentVersion: MeshConstants.agentVersion,
                defaultNodeName: bootstrap.nodeName,
                logDirPath: appGroupStore.logsDirectoryURL.path
            ),
            bridge: bridge
        )

        let routeTask = Task(priority: .userInitiated) { [weak self] in
            for await event in routeStream {
                await self?.handleRouteChange(event, engine: engine, bootstrap: bootstrap)
            }
        }
        startSystemMonitors(
            engine: engine,
            bridge: bridge,
            appGroupStore: appGroupStore,
            bootstrap: bootstrap,
            packetWriter: packetWriter,
            routeContinuation: routeStreamContinuation,
            routeTask: routeTask
        )

        let upConfig = MobileUpConfig(
            serverEndpoint: bootstrap.serverEndpoint,
            portOverride: nil,
            tlsAuthMode: bootstrap.tlsAuthMode,
            serverPin: bootstrap.activePin,
            pendingJoin: nil,
            nodeName: bootstrap.nodeName,
            androidTunFd: nil,
            tunInterfaceName: nil
        )
        do {
            _ = try await engine.startTunnel(cfg: upConfig)
            logger.notice("tunnel_started", detail: bootstrap.serverEndpoint)
        } catch {
            logger.error("tunnel_start_failed", detail: error.localizedDescription)
            await performBoundedTeardown(reason: "start_failed")
            throw error
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        logger.notice("tunnel_stop_requested", detail: "reason=\(reason.rawValue)")
        await performBoundedTeardown(reason: "stop_reason_\(reason.rawValue)")
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        let replyBox = IpcReplyBox(completionHandler)
        Task(priority: .userInitiated) { [weak self] in
            let responseBytes = await self?.processAppMessage(messageData)
            replyBox.complete(with: responseBytes)
        }
    }

    override func sleep() async {
        stateLock.read { $0.engine }?.setPowerSavingMode(enabled: true)
    }

    override func wake() {
        stateLock.read { $0.engine }?.setPowerSavingMode(enabled: false)
    }
}

private extension PacketTunnelProvider {
    func validateNoSecretOptions(_ options: [String: NSObject]?) throws {
        if let options, options.keys.contains(where: MeshConstants.isForbiddenProviderConfigKey) {
            throw MobileError.InvalidArgument(
                errorCode: "E_INVALID_ARG",
                message: "Secrets are forbidden in tunnel startup options"
            )
        }
    }

    func makeBridge(
        appGroupStore: CoordinatedAppGroupStore,
        packetWriter: BoundedPacketWriter,
        routeContinuation: AsyncStream<RouteChangeEvent>.Continuation?
    ) -> IosPlatformBridge {
        IosPlatformBridge(
            dekStore: KeychainDekStore(),
            appGroupStore: appGroupStore,
            initialUnderlay: .disconnected,
            packetWriter: packetWriter,
            onRouteChanged: { event in
                routeContinuation?.yield(event)
            },
            onStatusChanged: { [logger] snapshot in
                logger.info("tunnel_status_changed", detail: "\(snapshot.daemonState)")
            },
            onPlatformWarning: { [logger] warning in
                logger.warning("tunnel_platform_warning", detail: warning.message)
            }
        )
    }

    func startSystemMonitors(
        engine: MobileEngine,
        bridge: IosPlatformBridge,
        appGroupStore: CoordinatedAppGroupStore,
        bootstrap: BootstrapSummary,
        packetWriter: BoundedPacketWriter,
        routeContinuation: AsyncStream<RouteChangeEvent>.Continuation?,
        routeTask: Task<Void, Never>
    ) {
        let pathMonitor = NWPathMonitor()
        pathMonitor.pathUpdateHandler = { [weak self] path in
            self?.handleNetworkPathUpdate(path)
        }
        let memorySource = DispatchSource.makeMemoryPressureSource(
            eventMask: [.warning, .critical],
            queue: memoryQueue
        )
        memorySource.setEventHandler { [weak self] in
            self?.handleMemoryPressure()
        }

        stateLock.withLock { state in
            state.engine = engine
            state.bridge = bridge
            state.appGroupStore = appGroupStore
            state.bootstrap = bootstrap
            state.packetWriter = packetWriter
            state.pathMonitor = pathMonitor
            state.memorySource = memorySource
            state.routeContinuation = routeContinuation
            state.routeTask = routeTask
            state.isStopping = false
        }
        pathMonitor.start(queue: monitorQueue)
        memorySource.resume()
    }

    func handleRouteChange(
        _ event: RouteChangeEvent,
        engine: MobileEngine,
        bootstrap: BootstrapSummary
    ) async {
        guard !stateLock.read({ $0.isStopping }) else {
            engine.completeRouteChange(
                opId: event.opId,
                ok: false,
                newAndroidTunFd: nil,
                errorMessage: "Tunnel is stopping"
            )
            return
        }
        do {
            let settings = try TunnelNetworkSettingsBuilder.buildNetworkSettings(
                from: event.config,
                serverRemoteEndpoint: bootstrap.serverEndpoint
            )
            try await setTunnelNetworkSettings(settings)
            startPacketForwardingIfNeeded(engine: engine)
            engine.completeRouteChange(
                opId: event.opId,
                ok: true,
                newAndroidTunFd: nil,
                errorMessage: nil
            )
            logger.info("tunnel_routes_applied", detail: event.config.overlayCidr)
        } catch {
            let sanitized = MeshSecretScrubber.scrub(error.localizedDescription)
            logger.error("tunnel_routes_failed", detail: sanitized)
            stopPacketForwarding()
            try? await setTunnelNetworkSettings(nil)
            engine.completeRouteChange(
                opId: event.opId,
                ok: false,
                newAndroidTunFd: nil,
                errorMessage: sanitized
            )
        }
    }

    func startPacketForwardingIfNeeded(engine: MobileEngine) {
        let adapter = NEPacketTunnelFlowAdapter(flow: packetFlow)
        stateLock.read { $0.packetWriter }?.attach(flow: adapter)
        guard stateLock.read({ $0.packetPump }) == nil else { return }
        let pump = PacketFlowPump(flow: adapter) { packets in
            engine.pushTunPackets(packets: packets)
        }
        stateLock.withLock { $0.packetPump = pump }
        pump.start()
    }

    func stopPacketForwarding() {
        let (pump, writer) = stateLock.withLock { state in
            let currentPump = state.packetPump
            state.packetPump = nil
            return (currentPump, state.packetWriter)
        }
        pump?.stop()
        writer?.attach(flow: nil)
    }

    func handleNetworkPathUpdate(_ path: NWPath) {
        let newSnapshot = UnderlayPathConverter.snapshot(from: path)
        let (engine, bridge, previous, stopping) = stateLock.withLock { state in
            let prev = state.lastUnderlay
            state.lastUnderlay = newSnapshot
            return (state.engine, state.bridge, prev, state.isStopping)
        }
        guard !stopping, let bridge, let engine else { return }

        bridge.updateUnderlaySnapshot(newSnapshot)
        if let kind = UnderlayPathConverter.classifyTransition(
            previous: previous,
            current: newSnapshot
        ) {
            engine.onNetworkChange(kind: kind, underlay: newSnapshot.toMobileUnderlayState())
            logger.info(
                "underlay_network_changed",
                detail: "\(kind) iface=\(newSnapshot.activeInterfaceName ?? "none")"
            )
        }
    }

    func handleMemoryPressure() {
        let availableBytes = os_proc_available_memory()
        let availableMiB = Double(availableBytes) / (1024.0 * 1024.0)
        let (engine, source, stopping) = stateLock.read {
            ($0.engine, $0.memorySource, $0.isStopping)
        }
        guard !stopping, let engine, let source else { return }
        let event = source.data

        if event.contains(.critical) {
            logger.error(
                "jetsam_critical_memory_pressure",
                detail: String(format: "available_mib=%.2f", availableMiB)
            )
            engine.setPowerSavingMode(enabled: true)
            if availableBytes < 4 * 1024 * 1024 {
                Task { [weak self] in
                    await self?.performBoundedTeardown(reason: "jetsam_critical")
                    self?.cancelTunnelWithError(
                        MobileError.Internal(
                            errorCode: "E_LOW_MEMORY",
                            message: "Tunnel stopped due to iOS critical memory pressure"
                        )
                    )
                }
            }
        } else if event.contains(.warning) {
            logger.warning(
                "jetsam_warning_memory_pressure",
                detail: String(format: "available_mib=%.2f", availableMiB)
            )
            engine.setPowerSavingMode(enabled: true)
        }
    }

    func processAppMessage(_ messageData: Data) async -> Data {
        let (engine, bridge, store) = stateLock.read {
            ($0.engine, $0.bridge, $0.appGroupStore)
        }
        do {
            let request = try TunnelIpcCodec.decodeRequest(from: messageData)
            let response = try await dispatchIpcRequest(
                request,
                engine: engine,
                bridge: bridge,
                store: store
            )
            return try encodeIpcResponse(response, store: store)
        } catch {
            let mapped = MeshErrorMapper.map(error)
            return (try? encodeErrorResponse(code: mapped.code, message: mapped.message)) ?? Data()
        }
    }

    func dispatchIpcRequest(
        _ request: IosTunnelIpcRequest,
        engine: MobileEngine?,
        bridge: IosPlatformBridge?,
        store: CoordinatedAppGroupStore?
    ) async throws -> IosTunnelIpcResponse {
        switch request.action {
        case .getStatus:
            return try await handleStatusRequest(engine: engine, bridge: bridge, store: store)
        case .ping:
            return try await handlePingRequest(request, engine: engine)
        case .netcheck:
            guard let engine else {
                return errorResponse(code: "E_UNAVAILABLE", message: "Tunnel engine is not active")
            }
            let resp = try await engine.netcheck()
            return IosTunnelIpcResponse(ok: true, netcheck: CodableNetcheckResponse(from: resp))
        case .exportBugreport:
            return try await handleBugreportRequest(engine: engine, store: store)
        case .prepareStop:
            engine?.setPowerSavingMode(enabled: true)
            return IosTunnelIpcResponse(ok: true)
        }
    }

    func handleStatusRequest(
        engine: MobileEngine?,
        bridge: IosPlatformBridge?,
        store: CoordinatedAppGroupStore?
    ) async throws -> IosTunnelIpcResponse {
        guard let engine else {
            let cached = try store?.loadCachedStatusSnapshot()
            return IosTunnelIpcResponse(ok: true, status: cached.map(CodableStatusSnapshot.init))
        }
        let snapshot: MobileStatusSnapshot
        do {
            snapshot = try await engine.statusSnapshot()
        } catch {
            if let fallback = bridge?.latestStatusSnapshot() {
                snapshot = fallback
            } else {
                throw error
            }
        }
        return IosTunnelIpcResponse(ok: true, status: CodableStatusSnapshot(from: snapshot))
    }

    func handlePingRequest(
        _ request: IosTunnelIpcRequest,
        engine: MobileEngine?
    ) async throws -> IosTunnelIpcResponse {
        guard let engine, let target = request.target, !target.isEmpty else {
            return errorResponse(
                code: "E_INVALID_ARG",
                message: "Missing ping target or engine inactive"
            )
        }
        let pingReq = MobilePingRequest(
            target: target,
            count: request.count ?? 4,
            forceDirect: request.forceDirect ?? false,
            timeoutMs: request.timeoutMs ?? 2000
        )
        let resp = try await engine.pingPeer(req: pingReq)
        return IosTunnelIpcResponse(ok: true, ping: CodablePingResponse(from: resp))
    }

    func handleBugreportRequest(
        engine: MobileEngine?,
        store: CoordinatedAppGroupStore?
    ) async throws -> IosTunnelIpcResponse {
        guard let engine, let store else {
            return errorResponse(code: "E_UNAVAILABLE", message: "Tunnel engine is not active")
        }
        let timestampMs = UInt64(Date().timeIntervalSince1970 * 1000.0)
        let destURL = try store.makeBugreportDestinationURL(timestampMs: timestampMs)
        let result = try await engine.exportBugreportToFile(destPath: destURL.path)
        return IosTunnelIpcResponse(ok: true, bugreport: CodableBugreportResult(from: result))
    }

    func errorResponse(code: String, message: String) -> IosTunnelIpcResponse {
        IosTunnelIpcResponse(ok: false, errorCode: code, errorMessage: message)
    }

    func encodeIpcResponse(
        _ response: IosTunnelIpcResponse,
        store: CoordinatedAppGroupStore?
    ) throws -> Data {
        try TunnelIpcCodec.encodeResponse(response) { fullStatusBytes in
            try store?.writeStateFile(
                fileName: MeshConstants.statusSnapshotFileName,
                content: fullStatusBytes
            )
        }
    }

    func encodeErrorResponse(code: String, message: String) throws -> Data {
        try TunnelIpcCodec.encodeResponse(errorResponse(code: code, message: message))
    }

    func loadBootstrapConfiguration(
        from store: CoordinatedAppGroupStore
    ) throws -> BootstrapSummary {
        if let fromAppGroup = try store.loadBootstrapSummary() {
            return fromAppGroup
        }
        if let proto = protocolConfiguration as? NETunnelProviderProtocol,
           let config = proto.providerConfiguration,
           let endpoint = config[MeshConstants.providerConfigKeyServerEndpoint] as? String,
           !endpoint.isEmpty {
            let rawMode = config[MeshConstants.providerConfigKeyTlsAuthMode] as? String
            let tlsMode: MobileTlsAuthMode = rawMode == "system_ca" ? .systemCa : .spkiPin
            let pin = config[MeshConstants.providerConfigKeyServerPin] as? String
            let nodeName = config[MeshConstants.providerConfigKeyNodeName] as? String
            return BootstrapSummary(
                serverEndpoint: endpoint,
                tlsAuthMode: tlsMode,
                activePin: pin,
                nextPin: nil,
                nodeName: nodeName,
                nodeId: nil,
                overlayIp: nil,
                fqdn: nil
            )
        }
        throw MobileError.NotFound(
            errorCode: "E_NOT_FOUND",
            message: "Enrollment bootstrap missing; enroll inside Mesh VPN app first"
        )
    }

    func performBoundedTeardown(reason: String) async {
        let captured = stateLock.withLock { state in
            if state.isStopping {
                return (true, PacketTunnelRuntimeState())
            }
            state.isStopping = true
            let snapshot = state
            state.engine = nil
            state.bridge = nil
            state.packetPump = nil
            state.packetWriter = nil
            state.pathMonitor = nil
            state.memorySource = nil
            state.routeContinuation = nil
            state.routeTask = nil
            return (false, snapshot)
        }

        let alreadyStopping = captured.0
        let runtime = captured.1
        guard !alreadyStopping else { return }

        runtime.packetPump?.stop()
        runtime.packetWriter?.attach(flow: nil)
        runtime.pathMonitor?.cancel()
        runtime.memorySource?.cancel()
        runtime.routeContinuation?.finish()
        runtime.routeTask?.cancel()

        let engineToStop = runtime.engine
        await withTaskGroup(of: Void.self) { group in
            group.addTask { [weak self] in
                if let engineToStop {
                    _ = try? await engineToStop.stopTunnel()
                    try? engineToStop.shutdown()
                }
                try? await self?.setTunnelNetworkSettings(nil)
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 4_500_000_000)
            }
            _ = await group.next()
            group.cancelAll()
        }

        logger.notice("tunnel_stopped_cleanly", detail: reason)
    }
}
