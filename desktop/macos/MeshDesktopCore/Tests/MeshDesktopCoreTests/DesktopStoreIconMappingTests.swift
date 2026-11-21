import Foundation
@testable import MeshDesktopCore
import XCTest

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

        // Act: Compute all 10 canonical desktop states
        let unavailable = DesktopStateMapper.compute(
            serviceFilesPresent: false,
            statusResponse: nil,
            connectFailure: .serviceUnavailable("off"),
            lastActionError: nil
        )
        let stopped = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: nil,
            connectFailure: .serviceUnavailable("off"),
            lastActionError: nil
        )
        let notEnrolled = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(daemonState: .stopped),
            connectFailure: nil,
            lastActionError: nil
        )
        let connecting = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .connecting,
                nodeId: "n1",
                serverConnection: conn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        let connected = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .connected,
                nodeId: "n1",
                serverConnection: conn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        let degraded = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .degraded,
                nodeId: "n1",
                serverConnection: conn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        let disconnected = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .stopped,
                nodeId: "n1",
                serverConnection: conn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        let reauth = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .reauthRequired,
                nodeId: "n1",
                serverConnection: conn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        let revoked = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .revoked,
                nodeId: "n1",
                serverConnection: conn
            ),
            connectFailure: nil,
            lastActionError: nil
        )
        let recoverableErr = DesktopStateMapper.compute(
            serviceFilesPresent: true,
            statusResponse: AgentStatusResponse(
                daemonState: .stopped,
                nodeId: "n1",
                serverConnection: conn
            ),
            connectFailure: nil,
            lastActionError: pinErr
        )

        // Assert: Verify symbol, semantic tone, and canonical light/dark hex tokens
        XCTAssertEqual(unavailable.menuBarGroup.symbolName, "shield.slash")
        XCTAssertEqual(unavailable.menuBarGroup.lightHex, "#6B7280")
        XCTAssertEqual(stopped.menuBarGroup.symbolName, "shield.slash")
        XCTAssertEqual(stopped.menuBarGroup.darkHex, "#9CA3AF")
        XCTAssertEqual(notEnrolled.menuBarGroup.symbolName, "shield")
        XCTAssertEqual(notEnrolled.menuBarGroup.semanticTone, .neutral)
        XCTAssertEqual(connecting.menuBarGroup.symbolName, "bolt.shield.fill")
        XCTAssertEqual(connecting.menuBarGroup.lightHex, "#D97706")
        XCTAssertEqual(connected.menuBarGroup.symbolName, "checkmark.shield.fill")
        XCTAssertEqual(connected.menuBarGroup.lightHex, "#16A34A")
        XCTAssertEqual(connected.menuBarGroup.darkHex, "#4ADE80")
        XCTAssertEqual(degraded.menuBarGroup.symbolName, "bolt.shield.fill")
        XCTAssertEqual(degraded.menuBarGroup.darkHex, "#FBBF24")
        XCTAssertEqual(disconnected.menuBarGroup.symbolName, "shield")
        XCTAssertEqual(disconnected.menuBarGroup.lightHex, "#6B7280")
        XCTAssertEqual(reauth.menuBarGroup, .reauthRequired)
        XCTAssertEqual(reauth.menuBarGroup.symbolName, "key.slash")
        XCTAssertEqual(reauth.menuBarGroup.semanticTone, .warning)
        XCTAssertEqual(reauth.menuBarGroup.lightHex, "#D97706")
        XCTAssertEqual(reauth.menuBarGroup.darkHex, "#FBBF24")
        XCTAssertEqual(revoked.menuBarGroup.symbolName, "exclamationmark.shield.fill")
        XCTAssertEqual(revoked.menuBarGroup.semanticTone, .error)
        XCTAssertEqual(revoked.menuBarGroup.lightHex, "#DC2626")
        XCTAssertEqual(recoverableErr.menuBarGroup.symbolName, "exclamationmark.shield.fill")
        XCTAssertEqual(recoverableErr.menuBarGroup.darkHex, "#F87171")
    }
}
