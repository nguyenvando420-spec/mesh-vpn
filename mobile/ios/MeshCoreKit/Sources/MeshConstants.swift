import Foundation

/// Shared constants across MeshApp, MeshPacketTunnel, and MeshCoreKit.
public enum MeshConstants: Sendable {
    public static let appGroupIdentifier = "group.dev.meshvpn.ios"
    public static let keychainAccessGroupSuffix = "dev.meshvpn.ios.shared"
    public static let keychainService = "dev.meshvpn.ios.dek"
    public static let keychainAccount = "mesh_primary_dek_v1"
    public static let keychainProbeService = "dev.meshvpn.ios.dek.probe"
    public static let keychainProbeAccount = "access_group_probe"

    public static let tunnelBundleIdentifier = "dev.meshvpn.ios.PacketTunnel"
    public static let tunnelProviderDescription = "Mesh VPN"
    public static let loggerSubsystem = "dev.meshvpn.ios"
    public static let agentVersion = "0.3.0"

    public static let sealedIdentityFileName = "identity.sealed.bin"
    public static let bootstrapFileName = "bootstrap.toml"
    public static let netmapCacheFileName = "netmap-cache.json"
    public static let statusSnapshotFileName = "status-snapshot.json"

    public static let stateDirectoryName = "state"
    public static let diagnosticsDirectoryName = "diagnostics"
    public static let logsDirectoryName = "logs"

    public static let maxIpcPayloadBytes = 4096
    public static let targetIpcPayloadBytes = 3800
    public static let maxBugreportBytes = 1_048_576
    public static let dekByteCount = 32
    public static let gracefulShutdownBudgetSeconds: TimeInterval = 5.0
    public static let clipboardClearDelaySeconds: TimeInterval = 30.0
    public static let packetReadBatchLimit = 128

    public static let errSecInteractionNotAllowedCode: OSStatus = -25308
    public static let errSecMissingEntitlementCode: OSStatus = -34018

    public static let providerConfigKeyServerEndpoint = "server_endpoint"
    public static let providerConfigKeyTlsAuthMode = "tls_auth_mode"
    public static let providerConfigKeyServerPin = "server_pin"
    public static let providerConfigKeyNodeName = "node_name"
    public static let providerConfigKeyUpdatedAtMs = "updated_at_ms"

    private static let forbiddenConfigTokens = [
        "mpk",
        "preauth",
        "privkey",
        "private_key",
        "dek",
        "secret",
        "token",
        "join_uri"
    ]

    /// Returns true if a providerConfiguration key would violate secret isolation.
    public static func isForbiddenProviderConfigKey(_ key: String) -> Bool {
        let lowercased = key.lowercased()
        return forbiddenConfigTokens.contains { lowercased.contains($0) }
    }
}
