import Foundation
@testable import MeshDesktopCore
import XCTest

private struct IconMappingCase {
    let computed: ComputedDesktopState
    let symbol: String
    var tone: SemanticStatusTone?
    var lightHex: String?
    var darkHex: String?
    var expectedGroup: MenuBarStatusGroup?
}

extension DesktopStoreTests {
    func testDesktopStateMapper_All10States_MapsIconSymbolAndSemanticHexColors() {
        // Arrange
        let conn = ServerConnectionStatus(controlEndpoint: "ctrl.example.com:443")
        let pinErr = DesktopUserFacingError(
            code: "pin_mismatch",
            title: "Pin Mismatch",
            message: "Mismatch",
            requiresPinUpdate: true
        )
        let offline = IpcClientError.serviceUnavailable("off")

        // Act: Compute all 10 canonical desktop states
        let cases: [IconMappingCase] = [
            IconMappingCase(
                computed: computeState(servicePresent: false, connectFailure: offline),
                symbol: "shield.slash",
                lightHex: "#6B7280"
            ),
            IconMappingCase(
                computed: computeState(connectFailure: offline),
                symbol: "shield.slash",
                darkHex: "#9CA3AF"
            ),
            IconMappingCase(
                computed: computeState(status: AgentStatusResponse(daemonState: .stopped)),
                symbol: "shield",
                tone: .neutral
            ),
            IconMappingCase(
                computed: computeState(status: enrolledStatus(.connecting, conn: conn)),
                symbol: "bolt.shield.fill",
                lightHex: "#D97706"
            ),
            IconMappingCase(
                computed: computeState(status: enrolledStatus(.connected, conn: conn)),
                symbol: "checkmark.shield.fill",
                lightHex: "#16A34A",
                darkHex: "#4ADE80"
            ),
            IconMappingCase(
                computed: computeState(status: enrolledStatus(.degraded, conn: conn)),
                symbol: "bolt.shield.fill",
                darkHex: "#FBBF24"
            ),
            IconMappingCase(
                computed: computeState(status: enrolledStatus(.stopped, conn: conn)),
                symbol: "shield",
                lightHex: "#6B7280"
            ),
            IconMappingCase(
                computed: computeState(status: enrolledStatus(.reauthRequired, conn: conn)),
                symbol: "key.slash",
                tone: .warning,
                lightHex: "#D97706",
                darkHex: "#FBBF24",
                expectedGroup: .reauthRequired
            ),
            IconMappingCase(
                computed: computeState(status: enrolledStatus(.revoked, conn: conn)),
                symbol: "exclamationmark.shield.fill",
                tone: .error,
                lightHex: "#DC2626"
            ),
            IconMappingCase(
                computed: computeState(
                    status: enrolledStatus(.stopped, conn: conn),
                    lastActionError: pinErr
                ),
                symbol: "exclamationmark.shield.fill",
                darkHex: "#F87171"
            ),
        ]

        // Assert: Verify symbol, semantic tone, and canonical light/dark hex tokens
        for item in cases {
            assertIconMapping(item)
        }
    }

    private func computeState(
        servicePresent: Bool = true,
        status: AgentStatusResponse? = nil,
        connectFailure: IpcClientError? = nil,
        lastActionError: DesktopUserFacingError? = nil
    ) -> ComputedDesktopState {
        DesktopStateMapper.compute(
            serviceFilesPresent: servicePresent,
            statusResponse: status,
            connectFailure: connectFailure,
            lastActionError: lastActionError
        )
    }

    private func enrolledStatus(
        _ state: DaemonState,
        conn: ServerConnectionStatus
    ) -> AgentStatusResponse {
        AgentStatusResponse(daemonState: state, nodeId: "n1", serverConnection: conn)
    }

    private func assertIconMapping(
        _ item: IconMappingCase,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let group = item.computed.menuBarGroup
        XCTAssertEqual(group.symbolName, item.symbol, file: file, line: line)
        if let expectedGroup = item.expectedGroup {
            XCTAssertEqual(group, expectedGroup, file: file, line: line)
        }
        if let expectedTone = item.tone {
            XCTAssertEqual(group.semanticTone, expectedTone, file: file, line: line)
        }
        if let expectedLight = item.lightHex {
            XCTAssertEqual(group.lightHex, expectedLight, file: file, line: line)
        }
        if let expectedDark = item.darkHex {
            XCTAssertEqual(group.darkHex, expectedDark, file: file, line: line)
        }
    }
}
