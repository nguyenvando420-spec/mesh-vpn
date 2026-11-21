import Foundation
@testable import MeshDesktopCore
import XCTest

@MainActor
final class DesktopStoreReconnectTests: XCTestCase {
    func testDesktopStore_MultiCycleReconnect_PreservesIdentityAndEndpoint() async {
        // Arrange
        let transport = MockDesktopIpcTransport()
        let store = DesktopStoreTestFixtures.makeStore(transport: transport)
        let validKey = DesktopStoreTestFixtures.makeValidPreauthKey()
        let endpoint = "203.0.113.55:8443"
        let pin = "sha256:" + String(repeating: "ef", count: 32)
        let joinUri = "mesh://join?v=1&ep=\(endpoint)&pin=\(pin)&key=\(validKey)"

        // Act 1: URI enrollment -> connected
        let draft = store.handlePastedOnboardingInput(joinUri)
        XCTAssertNotNil(draft)
        let enrolled = await store.confirmEnrollmentDraft()
        XCTAssertTrue(enrolled)
        transport.setState(
            DesktopStoreTestFixtures.makePinnedStatus(
                daemonState: .connected,
                endpoint: endpoint,
                pin: pin,
                controlConnected: true
            )
        )
        await store.refreshNow()
        XCTAssertEqual(store.uiState, .connected)
        XCTAssertFalse(store.isManuallyDisconnected)

        // Act 2 & 3: Two full Disconnect -> 1-Click Reconnect cycles
        await assertDisconnectAndReconnectCycle(
            store: store,
            transport: transport,
            endpoint: endpoint,
            pin: pin
        )
        await assertDisconnectAndReconnectCycle(
            store: store,
            transport: transport,
            endpoint: endpoint,
            pin: pin
        )

        // Assert
        XCTAssertEqual(store.uiState, .connected)
        XCTAssertEqual(transport.bringDownCount, 2)
        XCTAssertEqual(transport.bringUpRequests.count, 3)
        XCTAssertEqual(transport.bringUpRequests[0].preauthKey, validKey)
        for index in 1...2 {
            XCTAssertNil(transport.bringUpRequests[index].preauthKey)
            XCTAssertEqual(transport.bringUpRequests[index].serverEndpoint, endpoint)
            XCTAssertEqual(transport.bringUpRequests[index].serverPin, pin)
        }
    }

    private func assertDisconnectAndReconnectCycle(
        store: DesktopStore,
        transport: MockDesktopIpcTransport,
        endpoint: String,
        pin: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        let downOk = await store.disconnect()
        XCTAssertTrue(downOk, file: file, line: line)
        transport.setState(
            DesktopStoreTestFixtures.makePinnedStatus(
                daemonState: .stopped,
                endpoint: endpoint,
                pin: pin
            )
        )
        await store.refreshNow()
        XCTAssertTrue(store.isManuallyDisconnected, file: file, line: line)

        let upOk = await store.connectOneClick()
        XCTAssertTrue(upOk, file: file, line: line)
        transport.setState(
            DesktopStoreTestFixtures.makePinnedStatus(
                daemonState: .connected,
                endpoint: endpoint,
                pin: pin,
                controlConnected: true
            )
        )
        await store.refreshNow()
        XCTAssertEqual(store.uiState, .connected, file: file, line: line)
        XCTAssertFalse(store.isManuallyDisconnected, file: file, line: line)
    }
}
