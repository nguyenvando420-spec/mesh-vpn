# Mobile Security Audit Report (`US-096` / `WP-M-C1`)

- **Audit Target:** `crates/mesh-mobile-ffi/**`, `mobile/android/**`, `mobile/ios/**`
- **Automated Audit Tooling:**
  - Runtime/Cryptographic Canary & FFI Security Tests: [qa_mobile_security_audit.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_security_audit.rs)
  - Static AppSec Verification Scripts: [audit-mobile-security.ps1](../../lab/mobile/audit-mobile-security.ps1) (Windows CRLF) and [audit-mobile-security.sh](../../lab/mobile/audit-mobile-security.sh) (POSIX LF)
- **Host Verification Date:** `2026-11-16` (Windows host, Rust `1.94.1` `x86_64-pc-windows-msvc`)

---

## 1. Cryptographic, Key Isolation & Secret-Scrubbing Verification (Observed `PASS`)

| Security Control | Requirement | Verification Mechanism | Host Result |
| :--- | :--- | :--- | :--- |
| **`SEC-01` Canary Non-Leakage** | Zero raw private keys, DEK bytes/hex/base64, or `mpk_*` preauth tokens in logs, IPC JSON, errors, or bugreports | `test_no_secrets_in_outputs_e2e_debug_logs_ipc_tar_and_unauthenticated` injects distinct preauth (`mpk_...`), 32-byte DEK (raw/hex/base64), and 64-hex private-key canaries across `tracing` `Level::DEBUG` capture, `MobilePendingJoinSession`, `MobileStatusSnapshot::to_bounded_ipc_json()` (`<= 4096 B`), `MobileError`, `export_bugreport_to_file()` (`.tar <= 1 MiB`), and state files (`bootstrap.toml`, `netmap-cache.json`, `status-snapshot.json`). | **PASS (`0` leaked bytes)** |
| **`SEC-05` Fixed Auth Error** | `ErrorKind::Unauthenticated` always returns exact `"authentication failed"` | Verified against mock `401 Unauthorized` response containing sensitive token canary and via `AppError::unauthenticated(...) -> MobileError::Unauthenticated` conversion. | **PASS (`"authentication failed"`)** |
| **`SEC-04` Zero-TOFU** | Reject IP literal + `SystemCa` (empty SPKI pin) | Verified fail-closed rejection across `parse_mobile_join_uri`, `BootstrapConfig::validate()`, and `mobile_enroll_or_rotate_node`. | **PASS** |
| **`ADR-014` `MSH1` Sealed Identity** | Store node identity encrypted under hardware-backed DEK in `"identity.sealed.bin"` | Verified `"MSH1"` header (`SEALED_IDENTITY_MAGIC`), ChaCha20-Poly1305 ciphertext excluding plaintext `"node_privkey_hex"` / `"disco_privkey_hex"` / `"schema_version"` / `"node_pubkey"`, wrong-DEK rejection, and fresh 12-byte random nonce on `seal_with_dek`. | **PASS** |
| **Rust FFI Memory Safety** | `0` `.unwrap()`, `0` `.expect()`, `0` hand-written `unsafe` in `crates/mesh-mobile-ffi/src/*.rs` | `MOB-SEC-16` static audit + `cargo clippy --workspace --all-targets --all-features -- -D warnings`. | **PASS** |

---

## 2. Static Android & iOS Security Controls (`MOB-SEC-01..MOB-SEC-16`)

Executed via `powershell -ExecutionPolicy Bypass -File lab/mobile/audit-mobile-security.ps1` (**`16 passed, 0 failed`**, exit code `0`):

| Rule ID | Platform | Verified Invariant & Source Evidence | Status |
| :--- | :--- | :--- | :--- |
| `MOB-SEC-01` | Android | [AndroidManifest.xml](../../mobile/android/app/src/main/AndroidManifest.xml) sets `android:allowBackup="false"`. | **PASS** |
| `MOB-SEC-02` | Android | [AndroidManifest.xml](../../mobile/android/app/src/main/AndroidManifest.xml) defines `0` `mesh://` deep-link `<intent-filter>` entries. | **PASS** |
| `MOB-SEC-03` | Android | [data_extraction_rules.xml](../../mobile/android/app/src/main/res/xml/data_extraction_rules.xml) and [full_backup_content.xml](../../mobile/android/app/src/main/res/xml/full_backup_content.xml) exclude `identity.sealed.bin` and `dek.enc`. | **PASS** |
| `MOB-SEC-04` | Android | `mobile/android/app/src/main/kotlin/**/*.kt` contains `0` `!!` non-null assertions. | **PASS** |
| `MOB-SEC-05` | Android | `mobile/android/app/src/main/kotlin/**/*.kt` contains `0` `GlobalScope` usages. | **PASS** |
| `MOB-SEC-06` | Android | `mobile/android` Gradle/TOML/ProGuard files contain `0` `EncryptedSharedPreferences`, `security-crypto`, `com.google.android.gms`, `com.google.mlkit`, or `ndk-context`. | **PASS** |
| `MOB-SEC-07` | Android | `dev.meshvpn.android.ffi.MeshNativeInit.initPlatformVerifier` exists in [MeshNativeInit.kt](../../mobile/android/app/src/main/kotlin/dev/meshvpn/android/ffi/MeshNativeInit.kt), is initialized in [MeshApplication.kt](../../mobile/android/app/src/main/kotlin/dev/meshvpn/android/MeshApplication.kt), and both `org.rustls.platformverifier.**` and `MeshNativeInit` are preserved in [proguard-rules.pro](../../mobile/android/app/proguard-rules.pro). | **PASS** |
| `MOB-SEC-08` | iOS | `MeshApp`, `MeshPacketTunnel`, and `MeshCoreKit` `Info.plist` + Entitlements contain `0` `CFBundleURLTypes` / `mesh://` schemes and `0` `com.apple.developer.associated-domains`. | **PASS** |
| `MOB-SEC-09` | iOS | All iOS `Info.plist` files contain `0` `NSAllowsArbitraryLoads`. | **PASS** |
| `MOB-SEC-10` | iOS | Production Swift files under `MeshApp/Sources`, `MeshCoreKit/Sources`, `MeshPacketTunnel/Sources` contain `0` `!` force unwraps, `try!`, `as!`, or `fatalError(...)`. | **PASS** |
| `MOB-SEC-11` | iOS | [KeychainDekStore.swift](../../mobile/ios/MeshCoreKit/Sources/KeychainDekStore.swift) enforces `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `kSecAttrSynchronizable = false`. | **PASS** |
| `MOB-SEC-12` | iOS | [TunnelManagerClient.swift](../../mobile/ios/MeshCoreKit/Sources/TunnelManagerClient.swift) sets `isOnDemandEnabled = false` and clears rules before `manager.stopTunnel()`. | **PASS** |
| `MOB-SEC-13` | Android + iOS | Both platforms reference sealed identity filename `"identity.sealed.bin"`. | **PASS** |
| `MOB-SEC-14` | iOS | [MeshConstants.swift](../../mobile/ios/MeshCoreKit/Sources/MeshConstants.swift), [TunnelManagerClient.swift](../../mobile/ios/MeshCoreKit/Sources/TunnelManagerClient.swift), and [PacketTunnelProvider.swift](../../mobile/ios/MeshPacketTunnel/Sources/PacketTunnelProvider.swift) forbid `mpk_*` / `preauth` / private-key / DEK keys in `providerConfiguration` and startup options, with `0` `mpk_*` token literals inside `MeshPacketTunnel`. | **PASS** |
| `MOB-SEC-15` | Android + iOS | `0` TCP listeners (`ServerSocket` / `NWListener`) in mobile host wrappers. | **PASS** |
| `MOB-SEC-16` | Rust FFI | `crates/mesh-mobile-ffi/src/*.rs` production code has `0` `.unwrap()`, `0` `.expect()`, and `0` hand-written `unsafe`. | **PASS** |

---

## 3. Residual Risk & Pending Verification Outside Windows Sandbox

1. **POSIX Audit & NAT64 Lab Scripts (`$0` Linux/macOS CI):**
   - [audit-mobile-security.sh](../../lab/mobile/audit-mobile-security.sh) and [nat64-lab-setup.sh](../../lab/mobile/nat64-lab-setup.sh) could not execute `bash -n` on this Windows host (`WSL` returned `Bash/E_ACCESSDENIED`, no Git Bash installed), though their embedded Python AST blocks parsed cleanly (`3/3` and `1/1`). Execution is gated in CI (`macos-15` / `ubuntu-latest`).
2. **Gradle / Xcode Signing & Runtime Mobile OS Verification:**
   - **Android `$0` CI:** Gradle `ktlintCheck`, `detekt`, `lintRelease`, APK/AAB signing verification, and 16 KB `.so` alignment run on `ubuntu-latest` CI.
   - **iOS `$0` CI:** `swiftlint lint --strict`, `xcodebuild test ... CODE_SIGNING_ALLOWED=NO` (iOS Simulator) run on `macos-15` CI.
   - **`hardware_signoff_required (chờ Apple Developer $99/năm)`:** Real Keychain `errSecInteractionNotAllowed` (`-25308`) before-first-unlock testing, physical App Group IPC boundary enforcement, `NEPacketTunnelProvider` signed `.ipa` entitlements, and real iPhone Jetsam/Energy profiling require physical hardware + paid Apple Developer provisioning.
