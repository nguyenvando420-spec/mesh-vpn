import MeshCoreKit
import XCTest

final class TunnelIpcAndAppGroupTests: XCTestCase {
    private func makeTempDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MeshTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: dir)
        }
        return dir
    }

    func test_encodeResponse_truncatesOversizedPeersUnder4096BAndSavesFullSnapshot() throws {
        // Arrange
        let tempRoot = try makeTempDirectory()
        let store = try CoordinatedAppGroupStore(rootDirectoryURL: tempRoot)
        let peers: [MobilePeerStatus] = (0..<150).map { idx in
            MobilePeerStatus(
                nodeId: "00000000-0000-0000-0000-\(String(format: "%012d", idx))",
                name: "peer-node-\(idx)",
                fqdn: "peer-node-\(idx).mesh.internal",
                overlayIp: "100.64.0.\((idx % 250) + 1)",
                online: idx % 2 == 0,
                activePath: idx % 2 == 0 ? .direct : .relay,
                directEndpoint: "203.0.113.10:\(51820 + idx)",
                rttMs: 14,
                lastHandshakeAtMs: 1_700_000_000_000,
                rxBytes: 1024,
                txBytes: 2048
            )
        }
        let snapshot = MobileStatusSnapshot(
            daemonState: .connected,
            nodeId: "node-1",
            nodeName: "iphone-1",
            fqdn: "iphone-1.mesh.internal",
            overlayIp: "100.64.0.2",
            overlayCidr: "100.64.0.0/16",
            overlayDnsIp: "100.64.255.254",
            tunInterfaceName: "utun7",
            tunMtu: 1280,
            netmapVersion: 12,
            keyExpiresAtMs: nil,
            serverConnection: nil,
            selfNetwork: MobileSelfNetworkStatus(
                localUdpPort: 51820,
                boundPhysicalInterface: "en0",
                natType: .endpointIndependent,
                overlayConflictWarning: nil,
                nat64ActivePrefix: nil,
                candidates: ["192.168.1.50:51820"]
            ),
            peers: peers,
            warnings: []
        )
        let response = IosTunnelIpcResponse(
            ok: true,
            status: CodableStatusSnapshot(from: snapshot)
        )

        // Act
        let encoded = try TunnelIpcCodec.encodeResponse(response) { fullBytes in
            try store.writeStateFile(
                fileName: MeshConstants.statusSnapshotFileName,
                content: fullBytes
            )
        }
        let decoded = try TunnelIpcCodec.decodeResponse(from: encoded)
        let persistedFull = try store.loadCachedStatusSnapshot()

        // Assert
        XCTAssertLessThanOrEqual(encoded.count, MeshConstants.maxIpcPayloadBytes)
        XCTAssertTrue(decoded.peersTruncated)
        XCTAssertEqual(decoded.totalPeerCount, 150)
        XCTAssertLessThan(decoded.status?.peers.count ?? 150, 150)
        XCTAssertEqual(persistedFull?.peers.count, 150)
    }

    func test_decodeRequest_rejectsPayloadLargerThan4096Bytes() {
        // Arrange
        let oversized = Data(repeating: 0x20, count: MeshConstants.maxIpcPayloadBytes + 1)

        // Act & Assert
        XCTAssertThrowsError(try TunnelIpcCodec.decodeRequest(from: oversized))
    }

    func test_appGroupStore_parsesBootstrapAndBlocksTraversalAndCleansDiagnostics() throws {
        // Arrange
        let tempRoot = try makeTempDirectory()
        let store = try CoordinatedAppGroupStore(rootDirectoryURL: tempRoot)
        let toml = """
        schema_version = 1
        server_endpoint = "203.0.113.10:443"
        tls_auth_mode = "spki_pin"
        active_pin = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        node_name = "iphone-lab"
        overlay_ip = "100.64.0.11"
        """
        try store.writeStateFile(
            fileName: MeshConstants.bootstrapFileName,
            content: Data(toml.utf8)
        )

        // Act
        let summary = try store.loadBootstrapSummary()
        let tarURL = try store.makeBugreportDestinationURL(timestampMs: 12345)
        try Data("tar-content".utf8).write(to: tarURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tarURL.path))
        try store.deleteDiagnosticsFile(at: tarURL)

        // Assert
        XCTAssertEqual(summary?.serverEndpoint, "203.0.113.10:443")
        XCTAssertEqual(summary?.tlsAuthMode, .spkiPin)
        XCTAssertEqual(summary?.nodeName, "iphone-lab")
        XCTAssertEqual(summary?.overlayIp, "100.64.0.11")
        XCTAssertFalse(FileManager.default.fileExists(atPath: tarURL.path))
        XCTAssertThrowsError(try store.readStateFile(fileName: "../escape.bin"))
        let outsidePath = tempRoot.appendingPathComponent("outside.tar")
        XCTAssertThrowsError(try store.deleteDiagnosticsFile(at: outsidePath))
    }

    func test_providerConfiguration_neverContainsPreauthSecret() throws {
        // Arrange
        let summary = BootstrapSummary(
            serverEndpoint: "vpn.example.com:443",
            tlsAuthMode: .spkiPin,
            activePin: "sha256:aaaa",
            nextPin: nil,
            nodeName: "iphone-1",
            nodeId: nil,
            overlayIp: nil,
            fqdn: nil
        )

        // Act
        let dict = try TunnelManagerClient.buildValidatedProviderConfiguration(from: summary)

        // Assert
        XCTAssertFalse(dict.keys.contains(where: MeshConstants.isForbiddenProviderConfigKey))
        let endpoint = dict[MeshConstants.providerConfigKeyServerEndpoint] as? String
        XCTAssertEqual(endpoint, "vpn.example.com:443")
    }
}
