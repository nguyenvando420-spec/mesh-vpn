import Foundation
import Security

/// Captured Keychain write metadata used to enforce and unit-test SEC-01 / §6.3 invariants.
public struct KeychainWriteRequest: Sendable, Equatable {
    public let service: String
    public let account: String
    public let accessGroup: String?
    public let accessibleAttribute: String
    public let synchronizable: Bool
    public let data: Data

    /// Initializes a Keychain write payload with mandatory iOS security attributes.
    public init(
        service: String,
        account: String,
        accessGroup: String?,
        accessibleAttribute: String,
        synchronizable: Bool,
        data: Data
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.accessibleAttribute = accessibleAttribute
        self.synchronizable = synchronizable
        self.data = data
    }
}

/// Outcome of reading an item from Keychain.
public enum KeychainReadOutcome: Sendable, Equatable {
    case found(Data)
    case notFound
    case interactionNotAllowed
    case missingEntitlement
    case failed(OSStatus)
}

/// Abstraction over Security.framework Keychain operations for deterministic unit testing.
public protocol KeychainClient: Sendable {
    func readItem(service: String, account: String, accessGroup: String?) -> KeychainReadOutcome
    func writeItem(_ request: KeychainWriteRequest) -> OSStatus
    func deleteItem(service: String, account: String, accessGroup: String?) -> OSStatus
}

/// Production Security.framework Keychain client with shared Access Group and `-25308` protection.
public final class SecurityKeychainClient: KeychainClient, Sendable {
    private let logger = MeshLogger(category: "keychain")

    /// Creates a Security.framework Keychain client.
    public init() {}

    /// Discovers the prefixed Keychain Access Group from an entitlement probe when available.
    public static func resolveAccessGroupIfPresent() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: MeshConstants.keychainProbeService,
            kSecAttrAccount as String: MeshConstants.keychainProbeAccount,
            kSecReturnAttributes as String: kCFBooleanTrue ?? true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess,
           let attrs = result as? [String: Any],
           let group = attrs[kSecAttrAccessGroup as String] as? String,
           group.hasSuffix(MeshConstants.keychainAccessGroupSuffix) {
            return group
        }
        return nil
    }

    public func readItem(
        service: String,
        account: String,
        accessGroup: String?
    ) -> KeychainReadOutcome {
        var query = baseQuery(service: service, account: account, accessGroup: accessGroup)
        query[kSecReturnData as String] = kCFBooleanTrue ?? true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == MeshConstants.errSecMissingEntitlementCode && accessGroup != nil {
            #if targetEnvironment(simulator)
            logger.warning(
                "keychain_simulator_no_entitlement",
                detail: "Retrying read without access group"
            )
            return readItem(service: service, account: account, accessGroup: nil)
            #else
            return .missingEntitlement
            #endif
        }

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                return .failed(errSecDecode)
            }
            return .found(data)
        case errSecItemNotFound:
            return .notFound
        case MeshConstants.errSecInteractionNotAllowedCode:
            return .interactionNotAllowed
        case MeshConstants.errSecMissingEntitlementCode:
            return .missingEntitlement
        default:
            return .failed(status)
        }
    }

    public func writeItem(_ request: KeychainWriteRequest) -> OSStatus {
        var attrs = baseQuery(
            service: request.service,
            account: request.account,
            accessGroup: request.accessGroup
        )
        attrs[kSecAttrAccessible as String] = request.accessibleAttribute
        let syncVal: Any = request.synchronizable
            ? (kCFBooleanTrue ?? true)
            : (kCFBooleanFalse ?? false)
        attrs[kSecAttrSynchronizable as String] = syncVal
        attrs[kSecValueData as String] = request.data

        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status == MeshConstants.errSecMissingEntitlementCode && request.accessGroup != nil {
            #if targetEnvironment(simulator)
            logger.warning(
                "keychain_simulator_no_entitlement",
                detail: "Retrying write without access group"
            )
            let fallback = KeychainWriteRequest(
                service: request.service,
                account: request.account,
                accessGroup: nil,
                accessibleAttribute: request.accessibleAttribute,
                synchronizable: request.synchronizable,
                data: request.data
            )
            return writeItem(fallback)
            #else
            return status
            #endif
        }
        return status
    }

    public func deleteItem(service: String, account: String, accessGroup: String?) -> OSStatus {
        let query = baseQuery(service: service, account: account, accessGroup: accessGroup)
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecItemNotFound ? errSecSuccess : status
    }

    private func baseQuery(
        service: String,
        account: String,
        accessGroup: String?
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

/// Manages the 32-byte Master Data Encryption Key (DEK) in the shared iOS Keychain Access Group.
public final class KeychainDekStore: Sendable {
    public typealias RandomBytesGenerator = @Sendable (Int) -> Data?

    private let client: KeychainClient
    private let accessGroup: String?
    private let service: String
    private let account: String
    private let randomGenerator: RandomBytesGenerator
    private let logger = MeshLogger(category: "dek_store")

    /// Creates a DEK store with `AfterFirstUnlockThisDeviceOnly` and `Synchronizable=false`.
    public init(
        client: KeychainClient = SecurityKeychainClient(),
        accessGroup: String? = SecurityKeychainClient.resolveAccessGroupIfPresent()
            ?? MeshConstants.keychainAccessGroupSuffix,
        service: String = MeshConstants.keychainService,
        account: String = MeshConstants.keychainAccount,
        randomGenerator: @escaping RandomBytesGenerator = KeychainDekStore.defaultRandomBytes
    ) {
        self.client = client
        self.accessGroup = accessGroup
        self.service = service
        self.account = account
        self.randomGenerator = randomGenerator
    }

    /// Generates cryptographically secure random bytes via `SecRandomCopyBytes`.
    public static func defaultRandomBytes(count: Int) -> Data? {
        var buffer = [UInt8](repeating: 0, count: count)
        defer {
            for index in buffer.indices {
                buffer[index] = 0
            }
        }
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &buffer)
        guard status == errSecSuccess else {
            return nil
        }
        return Data(buffer)
    }

    /// Loads the existing 32-byte DEK or creates a new one if none exists yet.
    /// Never deletes or overwrites the item when `errSecInteractionNotAllowed (-25308)` occurs.
    public func loadOrCreateDek() throws -> Data {
        switch client.readItem(service: service, account: account, accessGroup: accessGroup) {
        case .found(var existingData):
            guard existingData.count == MeshConstants.dekByteCount else {
                KeychainDekStore.zeroizeData(&existingData)
                throw MobileError.KeystoreInvalidated(
                    errorCode: "E_KEYSTORE_INVALIDATED",
                    message: "Stored DEK length invalid; re-enrollment required"
                )
            }
            return existingData

        case .interactionNotAllowed:
            logger.warning(
                "keychain_locked",
                detail: "errSecInteractionNotAllowed (-25308); preserving key"
            )
            throw MobileError.DeviceLocked(
                errorCode: "E_DEVICE_LOCKED",
                message: "Keychain locked before first unlock (errSecInteractionNotAllowed -25308)"
            )

        case .missingEntitlement:
            throw MobileError.KeystoreInvalidated(
                errorCode: "E_KEYSTORE_INVALIDATED",
                message: "Missing Keychain Access Group entitlement"
            )

        case .failed(let status):
            throw MobileError.KeystoreInvalidated(
                errorCode: "E_KEYSTORE_INVALIDATED",
                message: "Keychain read failed with OSStatus \(status)"
            )

        case .notFound:
            return try createAndPersistFreshDek()
        }
    }

    /// Explicitly removes the stored DEK during user-initiated identity reset.
    public func deleteDek() throws {
        let status = client.deleteItem(service: service, account: account, accessGroup: accessGroup)
        if status == MeshConstants.errSecInteractionNotAllowedCode {
            throw MobileError.DeviceLocked(
                errorCode: "E_DEVICE_LOCKED",
                message: "Cannot delete Keychain DEK while device is locked (-25308)"
            )
        }
        if status != errSecSuccess && status != errSecItemNotFound {
            throw MobileError.Internal(
                errorCode: "E_INTERNAL",
                message: "Keychain delete failed with OSStatus \(status)"
            )
        }
    }

    /// Zeroizes sensitive mutable byte buffers immediately after use.
    public static func zeroizeData(_ data: inout Data) {
        guard !data.isEmpty else { return }
        data.resetBytes(in: 0..<data.count)
    }

    private func createAndPersistFreshDek() throws -> Data {
        guard var freshDek = randomGenerator(MeshConstants.dekByteCount),
              freshDek.count == MeshConstants.dekByteCount else {
            throw MobileError.Internal(
                errorCode: "E_INTERNAL",
                message: "SecRandomCopyBytes failed generating 32-byte DEK"
            )
        }
        let accessibleAttr = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        let request = KeychainWriteRequest(
            service: service,
            account: account,
            accessGroup: accessGroup,
            accessibleAttribute: accessibleAttr,
            synchronizable: false,
            data: freshDek
        )
        let writeStatus = client.writeItem(request)
        if writeStatus == errSecDuplicateItem {
            KeychainDekStore.zeroizeData(&freshDek)
            return try reloadExistingDekAfterRace()
        }
        if writeStatus == MeshConstants.errSecInteractionNotAllowedCode {
            KeychainDekStore.zeroizeData(&freshDek)
            throw MobileError.DeviceLocked(
                errorCode: "E_DEVICE_LOCKED",
                message: "Keychain locked before first unlock (errSecInteractionNotAllowed -25308)"
            )
        }
        guard writeStatus == errSecSuccess else {
            KeychainDekStore.zeroizeData(&freshDek)
            throw MobileError.KeystoreInvalidated(
                errorCode: "E_KEYSTORE_INVALIDATED",
                message: "Keychain write failed with OSStatus \(writeStatus)"
            )
        }
        return freshDek
    }

    private func reloadExistingDekAfterRace() throws -> Data {
        switch client.readItem(service: service, account: account, accessGroup: accessGroup) {
        case .found(var existing) where existing.count == MeshConstants.dekByteCount:
            return existing
        case .found(var invalid):
            KeychainDekStore.zeroizeData(&invalid)
            throw MobileError.KeystoreInvalidated(
                errorCode: "E_KEYSTORE_INVALIDATED",
                message: "Stored DEK length invalid after duplicate race"
            )
        case .interactionNotAllowed:
            throw MobileError.DeviceLocked(
                errorCode: "E_DEVICE_LOCKED",
                message: "Keychain locked before first unlock (errSecInteractionNotAllowed -25308)"
            )
        default:
            throw MobileError.KeystoreInvalidated(
                errorCode: "E_KEYSTORE_INVALIDATED",
                message: "Failed reloading DEK after errSecDuplicateItem"
            )
        }
    }
}
