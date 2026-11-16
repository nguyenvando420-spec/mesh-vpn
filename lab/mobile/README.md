# Mobile QA & NAT64 Security Lab (`lab/mobile`)

Automated static security auditing and IPv6-only NAT64 (`64:ff9b::/96` + RFC 7050 `ipv4only.arpa`) test lab scripts for **WP-M-C1** (`US-094`, `US-095`, `US-096`).

## Files

- [audit-mobile-security.ps1](audit-mobile-security.ps1) (Windows PowerShell, CRLF, UTF-8 without BOM)
- [audit-mobile-security.sh](audit-mobile-security.sh) (POSIX `sh` for Linux/macOS CI, LF, UTF-8 without BOM)
- [nat64-lab-setup.sh](nat64-lab-setup.sh) (IPv6-only + NAT64 `64:ff9b::/96` & RFC 7050 `ipv4only.arpa` simulator & verification guide, LF)

## Quick Start

### 1. Run Mobile Static Security Audit (Android + iOS + `mesh-mobile-ffi`)

Windows:
```powershell
powershell -ExecutionPolicy Bypass -File lab/mobile/audit-mobile-security.ps1
```

Linux / macOS:
```sh
sh lab/mobile/audit-mobile-security.sh
```

Verified controls (`MOB-SEC-01..MOB-SEC-16`):
- `AndroidManifest.xml`: `android:allowBackup="false"`, zero `mesh://` deep-link `<intent-filter>` handlers.
- Android XML backup rules (`data_extraction_rules.xml`, `full_backup_content.xml`) exclude `identity.sealed.bin` and `dek.enc`.
- Android Kotlin main sources: `0` `!!` non-null assertions, `0` `GlobalScope`, `0` `ServerSocket` listeners.
- Android Gradle / dependencies: zero `EncryptedSharedPreferences`, GMS/Play Services, ML Kit, or `ndk-context`.
- Android JNI & ProGuard: `dev.meshvpn.android.ffi.MeshNativeInit.initPlatformVerifier` invoked from `MeshApplication` and kept in `proguard-rules.pro`.
- iOS `Info.plist` & Entitlements: zero `CFBundleURLTypes`/`mesh://`, zero `com.apple.developer.associated-domains`, zero `NSAllowsArbitraryLoads`.
- iOS Swift production sources: zero force-unwraps (`!`), `try!`, `as!`, `fatalError(...)`, zero `NWListener`/`ServerSocket`.
- iOS Keychain (`KeychainDekStore.swift`): `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `kSecAttrSynchronizable = false`.
- iOS On-Demand (`TunnelManagerClient.swift`): `isOnDemandEnabled = false` persisted before calling `stopTunnel()`.
- Sealed identity consistency: `"identity.sealed.bin"` used on both Android & iOS, zero `mpk_*` tokens passed into `MeshPacketTunnel`.
- Rust FFI safety: zero `.unwrap()`, zero `.expect()`, zero hand-written `unsafe` in `crates/mesh-mobile-ffi/src/*.rs` non-test code.

### 2. NAT64 (`64:ff9b::/96`) & RFC 7050 `ipv4only.arpa` Lab

1. **Automated Unit/Integration Verification (No root required)**:
   `cargo test -p mesh-mobile-ffi --test qa_mobile_resilience --all-features` exercises RFC 7050 WKA `ipv4only.arpa` prefix discovery (`2001:db8:64::/96` & `64:ff9b::/96`), RFC 6052 synthesis rejection on RFC 1918 LAN IPs & dual-stack interfaces, and 10 consecutive roaming rounds alternating Wi-Fi IPv4 and IPv6-only NAT64.
2. **Linux Physical/Emulator Lab (`tayga` + `dnsmasq`)**:
   - Start: `sudo ./lab/mobile/nat64-lab-setup.sh up-linux`
   - Verify DNS64: `./lab/mobile/nat64-lab-setup.sh verify-dns64`
   - Teardown: `sudo ./lab/mobile/nat64-lab-setup.sh down-linux`
3. **macOS Physical iPhone NAT64 Internet Sharing**:
   - Print setup commands: `./lab/mobile/nat64-lab-setup.sh macos-guide`
   - Print Android ADB checks: `./lab/mobile/nat64-lab-setup.sh android-guide`
