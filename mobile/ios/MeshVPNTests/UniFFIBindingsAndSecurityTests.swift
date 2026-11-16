import MeshCoreKit
import XCTest

final class UniFFIBindingsAndSecurityTests: XCTestCase {
    func test_mobileFfiVersion_returnsNonEmptySemver() {
        // Arrange & Act
        let version = mobileFfiVersion()

        // Assert
        XCTAssertFalse(version.isEmpty)
    }

    func test_parseMobileJoinUri_masksPreauthSecretAndExtractsTrustFields() throws {
        // Arrange
        let secret = "mpk_Q2FuYXJ5VG9rZW4zMkJ5dGVzQ2FuYXJ5VG9rZW4zMkI"
        let pin = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        let encodedPin = pin.replacingOccurrences(of: ":", with: "%3A")
        let rawUri = "mesh://join?v=1&ep=203.0.113.10%3A443&pin=\(encodedPin)"
            + "&key=\(secret)&name=iphone-15"

        // Act
        let parsed = try parseMobileJoinUri(rawUri: rawUri)
        let preview = parsed.session.maskedPreview()
        defer { parsed.session.cancel() }

        // Assert
        XCTAssertEqual(parsed.summary.version, 1)
        XCTAssertEqual(parsed.summary.serverEndpoint, "203.0.113.10:443")
        XCTAssertEqual(parsed.summary.tlsAuthMode, .spkiPin)
        XCTAssertEqual(parsed.summary.serverPin, pin)
        XCTAssertEqual(parsed.summary.nodeName, "iphone-15")
        XCTAssertFalse(parsed.summary.preauthKeyMasked.contains(secret))
        XCTAssertFalse(preview.contains(secret))
        XCTAssertTrue(preview.hasPrefix("mpk_"))
    }

    func test_createPendingJoinSession_rejectsEmptyAndRedactsToken() throws {
        // Arrange & Act & Assert
        XCTAssertThrowsError(try createPendingJoinSession(rawPreauthKey: "   "))

        let secret = "mpk_Q2FuYXJ5VG9rZW4zMkJ5dGVzQ2FuYXJ5VG9rZW4zMkI"
        let session = try createPendingJoinSession(rawPreauthKey: secret)
        defer { session.cancel() }
        XCTAssertFalse(session.maskedPreview().contains(secret))
    }

    func test_secretScrubber_masksTokensPrivateKeysAndJoinUris() {
        // Arrange
        let dirty = "token=mpk_testsecret999 node_privkey_hex=deadbeef "
            + "uri=mesh://join?v=1&token=mpk_other Bearer abc.def.ghi"

        // Act
        let scrubbed = MeshSecretScrubber.scrub(dirty)

        // Assert
        XCTAssertFalse(scrubbed.contains("mpk_testsecret999"))
        XCTAssertFalse(scrubbed.contains("mpk_other"))
        XCTAssertFalse(scrubbed.contains("deadbeef"))
        XCTAssertFalse(scrubbed.contains("abc.def.ghi"))
        XCTAssertTrue(scrubbed.contains("[REDACTED]"))
    }

    func test_errorMapper_mapsSec05UnauthenticatedAndMobileFailures() {
        // Arrange & Act
        let authErr = MeshErrorMapper.map(
            MobileError.Unauthenticated(errorCode: "E_UNAUTHENTICATED", message: "secret details")
        )
        let upgradeErr = MeshErrorMapper.map(
            MobileError.ServerUpgradeRequired(errorCode: "E_UPGRADE", message: "upgrade control")
        )
        let lockedErr = MeshErrorMapper.map(
            MobileError.DeviceLocked(errorCode: "E_DEVICE_LOCKED", message: "locked (-25308)")
        )

        // Assert
        XCTAssertEqual(authErr.message, "authentication failed")
        XCTAssertTrue(upgradeErr.requiresServerUpgrade)
        XCTAssertTrue(lockedErr.isDeviceLocked)
    }
}
