import MeshCoreKit
import Security
import XCTest

private final class MockKeychainClient: KeychainClient, Sendable {
    struct State {
        var readOutcome: KeychainReadOutcome = .notFound
        var writeRequests: [KeychainWriteRequest] = []
        var deleteCount = 0
        var writeStatus: OSStatus = errSecSuccess
    }

    let box = LockedBox(State())

    func readItem(service: String, account: String, accessGroup: String?) -> KeychainReadOutcome {
        box.read { $0.readOutcome }
    }

    func writeItem(_ request: KeychainWriteRequest) -> OSStatus {
        box.withLock { state in
            state.writeRequests.append(request)
            if state.writeStatus == errSecSuccess {
                state.readOutcome = .found(request.data)
            }
            return state.writeStatus
        }
    }

    func deleteItem(service: String, account: String, accessGroup: String?) -> OSStatus {
        box.withLock { state in
            state.deleteCount += 1
            state.readOutcome = .notFound
            return errSecSuccess
        }
    }
}

final class KeychainDekStoreTests: XCTestCase {
    func test_loadOrCreateDek_writesRequiredAttributesAndPersists32Bytes() throws {
        // Arrange
        let mock = MockKeychainClient()
        let fixedSeed = Data(repeating: 0xAB, count: 32)
        let store = KeychainDekStore(
            client: mock,
            accessGroup: "ABCDE.dev.meshvpn.ios.shared",
            randomGenerator: { count in count == 32 ? fixedSeed : nil }
        )

        // Act
        let firstDek = try store.loadOrCreateDek()
        let secondDek = try store.loadOrCreateDek()

        // Assert
        XCTAssertEqual(firstDek, fixedSeed)
        XCTAssertEqual(secondDek, fixedSeed)
        let writes = mock.box.read { $0.writeRequests }
        XCTAssertEqual(writes.count, 1)
        let writeReq = try XCTUnwrap(writes.first)
        XCTAssertEqual(writeReq.accessGroup, "ABCDE.dev.meshvpn.ios.shared")
        XCTAssertEqual(
            writeReq.accessibleAttribute,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        )
        XCTAssertFalse(writeReq.synchronizable)
    }

    func test_loadOrCreateDek_whenInteractionNotAllowed_preservesKeyAndThrowsDeviceLocked() {
        // Arrange
        let mock = MockKeychainClient()
        mock.box.withLock { $0.readOutcome = .interactionNotAllowed }
        let store = KeychainDekStore(
            client: mock,
            accessGroup: "ABCDE.dev.meshvpn.ios.shared"
        )

        // Act & Assert
        XCTAssertThrowsError(try store.loadOrCreateDek()) { error in
            guard case MobileError.DeviceLocked = error else {
                XCTFail("Expected MobileError.DeviceLocked, got \(error)")
                return
            }
        }
        XCTAssertEqual(mock.box.read { $0.writeRequests.count }, 0)
        XCTAssertEqual(mock.box.read { $0.deleteCount }, 0)
    }

    func test_loadOrCreateDek_whenCorruptedLength_failsClosedWithoutDeleting() {
        // Arrange
        let mock = MockKeychainClient()
        mock.box.withLock { $0.readOutcome = .found(Data(repeating: 0x01, count: 16)) }
        let store = KeychainDekStore(
            client: mock,
            accessGroup: "ABCDE.dev.meshvpn.ios.shared"
        )

        // Act & Assert
        XCTAssertThrowsError(try store.loadOrCreateDek()) { error in
            guard case MobileError.KeystoreInvalidated = error else {
                XCTFail("Expected MobileError.KeystoreInvalidated, got \(error)")
                return
            }
        }
        XCTAssertEqual(mock.box.read { $0.writeRequests.count }, 0)
        XCTAssertEqual(mock.box.read { $0.deleteCount }, 0)
    }
}
