# Mobile QA Test Plan & Verification Report (`WP-M-C1`)

- **Work Package:** `WP-M-C1` (`US-094`, `US-095`, `US-096`)
- **Crate Under Test:** `mesh-mobile-ffi` (`crates/mesh-mobile-ffi/`) + Android/iOS host wrappers (`mobile/android/**`, `mobile/ios/**`)
- **Host Verification Environment:** Windows host (`x86_64-pc-windows-msvc`), Rust `1.94.1` (`cargo +1.94.1-x86_64-pc-windows-msvc`)
- **Scope Boundary Note:** Android NDK/Gradle builds and macOS Xcode/`xcodebuild` builds require Linux/NDK or macOS/Xcode runners and are NOT fabricated or executed locally on Windows; those gates are explicitly separated below into `$0` CI checks vs `hardware_signoff_required (chờ Apple Developer $99/năm)`.

---

## 1. Automated Rust/FFI & Lab Test Suites Built (`crates/mesh-mobile-ffi/tests/`)

| Suite | User Story | Test Functions | Key Scenarios Covered |
| :--- | :--- | :--- | :--- |
| [qa_mobile_e2e_compat.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_e2e_compat.rs) | `US-094` | `test_e2e_mobile_ffi_ios_and_android_custom_port_route_preservation_and_offline_control` | Mock TLS 1.3 (SPKI-pinned via `mesh_crypto::certgen`) + WS Control (`/v1/auth/challenge`, `/v1/nodes/register`, `/v1/netmap/stream`) on custom non-443/non-3478 ports; public FFI (`parse_mobile_join_uri`, `create_pending_join_session`, `mobile_enroll_or_rotate_node`, `MobileEngine`, `start_tunnel`, `complete_route_change`, `status_snapshot`, `stop_tunnel`, `shutdown`) for `MobilePlatformKind::Ios` and `MobilePlatformKind::Android`; `complete_route_change` preserving `overlay_ip` + `tun_mtu` without FD double-close; offline Control stream tolerance; wire verification of `TargetOs::Android` and `TargetOs::Ios`. |
| [qa_mobile_e2e_compat.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_e2e_compat.rs) | `US-094` | `test_compat_desktop_v0_1_0_rc1_and_400_protocol_incompatible_preserves_netmap_cache` | Desktop `v0.1.0-rc1` (`TargetOs::Windows`, `TargetOs::Darwin`) mixed-peer `NetmapSnapshot` wire compatibility (`#[serde(deny_unknown_fields)]`); Control HTTP `400 protocol_incompatible` transitioning to `MobileDaemonState::ServerUpgradeRequired` while preserving `netmap-cache.json` `netmap` payload intact. |
| [qa_mobile_e2e_compat.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_e2e_compat.rs) | `US-094` | `test_e2e_double_cgnat_blind_relay_256_try_send_no_hol_blocking_and_cli_uri_qr_roundtrip` | Double-CGNAT live TLS 1.3 `/v1/relay` WebSocket Blind Relay between two `RelayClient`s (`0x01 -> 0x02` `src_pubkey` stamping + WireGuard `PeerMap` Noise handshake payload); saturating offline peer C's `256`-slot queue with `300` packets (`256` accepted, `44` dropped via `try_send()`) with zero HoL blocking against peer B; CLI `format_join_uri` / QR URI roundtrip via `parse_mobile_join_uri`; RFC 6052 `Nat64Synthesizer`. |
| [qa_mobile_resilience.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_resilience.rs) | `US-095` | `test_resilience_roaming_10_rounds_wifi_ipv4_ipv6_nat64_rfc7050_and_wg_handshake` | RFC 7050 `Nat64Prefix::from_ipv4only_arpa_addrs` (`2001:db8:64::/96` and `64:ff9b::/96`); `is_eligible_for_nat64_synthesis` rejecting RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), `127.0.0.1`, `169.254.1.1`; dual-stack LAN suppression of NAT64; `10` consecutive roaming rounds alternating Wi-Fi IPv4 and Cellular IPv6-only NAT64 `64:ff9b::/96` with invariant `overlay_ip` (`<= 5 s` budget) and WireGuard handshake completion (`<= 2 s`). |
| [qa_mobile_resilience.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_resilience.rs) | `US-095` | `test_resilience_split_dns_rfc4074_nodata_edns0_l3_tcp_lru16_ttl3s_dot853_and_tun` | `MobileSplitDnsInterceptor`: `.mesh.internal` `A` (`RCODE=0`, `ANCOUNT=1`), RFC 4074 NODATA (`RCODE=0`, `ANCOUNT=0`) for `AAAA`/`HTTPS`/`SVCB`, EDNS0 UDP `<= 1232 B` & classic UDP `<= 512 B`, L3 TCP `:53` single-transaction `PSH\|FIN\|ACK`, pipelined 2nd query `RST\|ACK`, `16`-slot LRU cap, `3_000 ms` TTL eviction via `FakeClock`, immediate DoT `:853` `TCP RST\|ACK`, and live `DatapathEngine` + `FakeTunDevice` TUN interception under `TimerMode::IdleAware`. |
| [qa_mobile_resilience.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_resilience.rs) | `US-095` | `test_resilience_idle_aware_jetsam_hysteresis_doze_clock_jump_captive_clock_skew_revoked_and_shutdown` | `JetsamPressureController` hysteresis (`< 15 MiB` `TrimCaches`, `16 MiB` hold, `>= 18 MiB` recover; `< 6 MiB` `ShedIdle` forcing `IdleAware`, `>= 10_000 ms` cooldown; `< 4 MiB` `CriticalShutdown`); Doze clock jump (`> 30_000 ms` detected via `ClockJumpDetector`); Captive Portal HTML `200` and HTTP `511` returning retryable `MobileError::Unavailable`; future-dated TLS cert returning `MobileError::ClockSkew`; WS `IdentityTerminated(NodeRevoked)` moving to `MobileDaemonState::Revoked`; `export_bugreport_to_file()` (`<= 1 MiB` `.tar`); `shutdown()` completing `<= 5 s`. |
| [qa_mobile_security_audit.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_security_audit.rs) | `US-096` | `test_no_secrets_in_outputs_e2e_debug_logs_ipc_tar_and_unauthenticated` | End-to-end canary leak audit across `DEBUG` `tracing_subscriber` capture, `MobilePendingJoinSession`, `MobileError` (`Unauthenticated` = `"authentication failed"`), bounded IPC JSON (`<= 4096 B`), bugreport `.tar` (`<= 1 MiB`), and state files with `0` leaked bytes. |
| [qa_mobile_security_audit.rs](../../crates/mesh-mobile-ffi/tests/qa_mobile_security_audit.rs) | `US-096` | `test_security_zero_tofu_rejects_ip_literal_system_ca_and_verifies_msh1_sealed_identity` | Zero-TOFU enforcement rejecting IP literal + `SystemCa` across URI parse, `BootstrapConfig::validate`, and enrollment; verification of `"identity.sealed.bin"` `"MSH1"` ChaCha20-Poly1305 AEAD ciphertext, wrong-DEK failure, fresh 12-byte nonces, and zero plaintext key fields. |

Additionally, existing `mesh-mobile-ffi` unit tests (`23` tests in `crates/mesh-mobile-ffi/src/*.rs`) complement the integration suites above, covering crate-internal `set_test_available_memory_bytes` critical Jetsam `export_bugreport_to_file` denial `< 6 MiB` / non-deadlocking `< 4 MiB` shutdown, `test_udp_edns0_clamp_sets_tc_bit_and_respects_budget` internal `TC=1` clamping, and L3 DNS fuzz tests.

---

## 2. Observed Execution Results on Windows Host

All commands below were executed directly in worktree `swarm-dev-m-c1-2fc3e5ab` on the final codebase:

| Check / Command | Outcome | Exact Observed Output Summary |
| :--- | :--- | :--- |
| `cargo +1.94.1-x86_64-pc-windows-gnu test ...` | Host Toolchain Limitation | Failed with `error: error calling dlltool 'dlltool.exe': program not found` (`CreateProcess` inside rustup `self-contained` lacking full MinGW binutils). Active host toolchain `+1.94.1-x86_64-pc-windows-msvc` was used for all compilation and test execution. |
| `cargo +1.94.1-x86_64-pc-windows-msvc fmt --all -- --check` | **PASS** | Exit code `0`, `0` formatting diffs. |
| `cargo +1.94.1-x86_64-pc-windows-msvc clippy --workspace --all-targets --all-features -- -D warnings` | **PASS** | Exit code `0`, `Finished dev profile` (`0` warnings, `0` errors across all workspace crates & tests). |
| `cargo +1.94.1-x86_64-pc-windows-msvc test -p mesh-mobile-ffi --tests --all-features` | **PASS (`31/31`)** | `src\lib.rs`: `23 passed; 0 failed`; `qa_mobile_e2e_compat.rs`: `3 passed; 0 failed`; `qa_mobile_resilience.rs`: `3 passed; 0 failed`; `qa_mobile_security_audit.rs`: `2 passed; 0 failed` (`0` skipped, `0` ignored). |
| `powershell -ExecutionPolicy Bypass -File lab/mobile/audit-mobile-security.ps1` | **PASS (`16/16`)** | Exit code `0`, `Summary: 16 passed, 0 failed.` (`MOB-SEC-01..MOB-SEC-16`). |
| Embedded Python AST validation on `lab/mobile/*.sh` | **PASS** | `audit-mobile-security.sh` (`3/3` Python blocks parsed), `nat64-lab-setup.sh` (`1/1` Python block parsed). |
| POSIX `bash -n` on `lab/mobile/*.sh` | Not Run on Host | WSL returned `Bash/E_ACCESSDENIED` and Git Bash was not present at `AppData\Local\Programs\Git\bin\bash.exe`; runtime shell syntax check deferred to Linux/macOS CI (`audit-mobile-security.sh`, `nat64-lab-setup.sh`). |

---

## 3. Environment Split: `$0` CI vs `hardware_signoff_required`

### A. `$0` Automated CI Matrix (No Paid Apple Developer Account Required)
Runs in `.github/workflows/mobile-release.yml` and `lab/mobile/` on Linux (`ubuntu-latest`) and macOS (`macos-15`):
1. **Rust Workspace & Cross-Checks:** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo deny check`.
2. **Android (`$0`, Linux CI):** NDK r27c+ cross-compile (`aarch64-linux-android`, `x86_64-linux-android`), 16 KB page alignment & `.so <= 6 MiB` verification, `./gradlew ktlintCheck detekt lintRelease testDebugUnitTest assembleDebug assembleRelease bundleRelease`, `sh lab/mobile/audit-mobile-security.sh`.
3. **iOS Simulator & Framework (`$0`, macOS CI):** `MeshMobileFFI.xcframework` (`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios` `<= 6 MiB`), `xcodegen generate`, `swiftlint lint --strict`, `xcodebuild test ... -destination 'platform=iOS Simulator,...' CODE_SIGNING_ALLOWED=NO`.
4. **Linux NAT64 Lab:** `lab/mobile/nat64-lab-setup.sh` (`tayga` + `dnsmasq` RFC 7050 `ipv4only.arpa` inside isolated `mesh-nat64` netns).

### B. `hardware_signoff_required (chờ Apple Developer $99/năm)` & Physical Device Gates
Not executed on Windows host and cannot be signed/verified without real hardware / paid Apple provisioning:
1. **Apple Developer `$99/năm` Provisioned iOS Runs (Physical iPhone):**
   - Signed `NEPacketTunnelProvider` Network Extension entitlement + App Group (`group.dev.meshvpn.ios`) + Keychain Access Group (`$(AppIdentifierPrefix)dev.meshvpn.ios.shared`) runtime tests.
   - Real Xcode Instruments **Allocations/VM Tracker** RSS verification inside the **50 MiB Jetsam** sandbox (`RSS <= 25 MiB` steady-state, `< 15 MiB` / `< 6 MiB` / `< 4 MiB` `os_proc_available_memory()` trigger checks).
   - Real Xcode Instruments **Energy Log** overnight idle drain measurement (`<= 1.5%/hour` with `TimerMode::IdleAware`) and TestFlight `.ipa` distribution sign-off.
2. **Physical Android 14+ Device / Real Carrier NAT64 Field Runs:**
   - Real `VpnService.protect(fd)` + Android Doze idle battery drain (`dumpsys batterystats`) + `RSS <= 48 MiB` + physical carrier IPv6-only NAT64 / Strict Private DNS (`:853`) + Always-On VPN Lockdown behavior (`US-097`, `mobile-hardware-acceptance-protocol.md`).
