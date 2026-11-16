import MeshCoreKit
import XCTest

final class TunnelNetworkSettingsBuilderTests: XCTestCase {
    func test_buildSpec_enforcesSlash32AndSplitDnsAndIncludedRoutes() throws {
        // Arrange
        let config = MobileTunnelNetworkConfig(
            overlayIp: "100.64.0.42",
            tunInterfacePrefixLen: 32,
            overlayCidr: "100.64.0.0/16",
            overlaySubnetMask: "255.255.0.0",
            overlayDnsIp: "100.64.255.254",
            domainSuffix: "mesh.internal",
            tunMtu: 1280,
            includedRoutesCidr: ["100.64.0.0/16", "100.64.255.254/32"]
        )

        // Act
        let spec = try TunnelNetworkSettingsBuilder.buildSpec(
            from: config,
            serverRemoteEndpoint: "198.51.100.10:443"
        )
        let settings = try TunnelNetworkSettingsBuilder.buildNetworkSettings(
            from: config,
            serverRemoteEndpoint: "198.51.100.10:443"
        )

        // Assert
        XCTAssertEqual(spec.ipv4Address, "100.64.0.42")
        XCTAssertEqual(spec.ipv4SubnetMask, "255.255.255.255")
        XCTAssertEqual(spec.dnsServers, ["100.64.255.254"])
        XCTAssertEqual(spec.dnsMatchDomains, ["mesh.internal"])
        XCTAssertEqual(spec.mtu, 1280)
        XCTAssertTrue(spec.excludedRoutes.isEmpty)
        XCTAssertTrue(
            spec.includedRoutes.contains(
                Ipv4RouteSpec(destination: "100.64.0.0", subnetMask: "255.255.0.0")
            )
        )
        XCTAssertTrue(
            spec.includedRoutes.contains(
                Ipv4RouteSpec(destination: "100.64.255.254", subnetMask: "255.255.255.255")
            )
        )
        XCTAssertEqual(settings.ipv4Settings?.subnetMasks, ["255.255.255.255"])
        XCTAssertEqual(settings.dnsSettings?.matchDomains, ["mesh.internal"])
        XCTAssertEqual(settings.mtu, 1280)
    }

    func test_buildSpec_injectsOverlayDnsHostRouteWhenNotCovered() throws {
        // Arrange
        let config = MobileTunnelNetworkConfig(
            overlayIp: "10.200.0.5",
            tunInterfacePrefixLen: 32,
            overlayCidr: "10.200.0.0/24",
            overlaySubnetMask: "255.255.255.0",
            overlayDnsIp: "100.64.255.254",
            domainSuffix: "mesh.internal",
            tunMtu: 1280,
            includedRoutesCidr: ["10.200.0.0/24"]
        )

        // Act
        let spec = try TunnelNetworkSettingsBuilder.buildSpec(from: config)

        // Assert
        XCTAssertTrue(
            spec.includedRoutes.contains(
                Ipv4RouteSpec(destination: "100.64.255.254", subnetMask: "255.255.255.255")
            )
        )
    }

    func test_buildSpec_rejectsZeroDefaultRoute() {
        // Arrange
        let config = MobileTunnelNetworkConfig(
            overlayIp: "100.64.0.42",
            tunInterfacePrefixLen: 32,
            overlayCidr: "100.64.0.0/16",
            overlaySubnetMask: "255.255.0.0",
            overlayDnsIp: "100.64.255.254",
            domainSuffix: "mesh.internal",
            tunMtu: 1280,
            includedRoutesCidr: ["0.0.0.0/0"]
        )

        // Act & Assert
        XCTAssertThrowsError(try TunnelNetworkSettingsBuilder.buildSpec(from: config)) { error in
            guard case MobileError.InvalidArgument = error else {
                XCTFail("Expected MobileError.InvalidArgument, got \(error)")
                return
            }
        }
    }

    func test_buildSpec_rejectsNon32InterfacePrefix() {
        // Arrange
        let config = MobileTunnelNetworkConfig(
            overlayIp: "100.64.0.42",
            tunInterfacePrefixLen: 16,
            overlayCidr: "100.64.0.0/16",
            overlaySubnetMask: "255.255.0.0",
            overlayDnsIp: "100.64.255.254",
            domainSuffix: "mesh.internal",
            tunMtu: 1280,
            includedRoutesCidr: ["100.64.0.0/16"]
        )

        // Act & Assert
        XCTAssertThrowsError(try TunnelNetworkSettingsBuilder.buildSpec(from: config))
    }
}
