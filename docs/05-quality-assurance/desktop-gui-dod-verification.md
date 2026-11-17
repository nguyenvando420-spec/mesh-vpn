# Báo Cáo Xác Minh Definition of Done (DoD) — Desktop GUI & Tray Companion (`v0.3.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Phiên bản mục tiêu** | `v0.3.0` (`EP-17..EP-20`, `US-100..US-117 = 78 SP`, `43/43` `DGUI-*`, `ADR-020..026`) |
| **Mã tài liệu** | `QA-DOD-DGUI-001` |
| **Phiên bản tài liệu** | `1.2` |
| **Ngày cập nhật** | `2026-11-18` |
| **Người thực hiện** | QA & Security Verification (`WP-D-C2` — `US-116`) |
| **Tài liệu đối chiếu** | `docs/01-discovery/desktop-gui-readiness-requirements.md` v1.1, `docs/02-product-planning/desktop-gui-product-backlog.md` v1.1, `docs/04-sprint-management/desktop-gui-sprint-backlog.md` v1.1, `docs/05-quality-assurance/critique-reviews/desktop-gui-gate-3-critique.md` |
| **Trạng thái Gate 3** | **`VERIFIED_ON_WINDOWS_HOST` + `VERIFIED_AT_CI_$0` ([CI Gate #44156673083](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083) `7/7` jobs PASS) + `hardware_signoff_required`** |

---

## 1. Nguyên tắc Trung thực Bằng chứng (3-Bucket Strict Separation)

Báo cáo DoD này tách bạch nghiêm ngặt 3 mức độ xác minh theo `US-116 AC3 & AC5`, tuyệt đối không suy diễn kết quả phần cứng vật lý từ máy kiểm định Windows hay runner CI:
1. **`VERIFIED_ON_WINDOWS_HOST`**: Kết quả chạy thực tế trên host Windows (`+1.94.1-x86_64-pc-windows-gnu`) qua `scripts/run-desktop-qa.ps1` và `scripts/check.ps1 -Cross`.
2. **`VERIFIED_AT_CI_$0`**: Kết quả chạy thực tế trên GitHub Actions `$0` runners cho nhánh `feat/desktop-gui`:
   - **[CI Gate #44156673083](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083)** (commit `65b38c4` — **`7/7` jobs `completed/success`**): `Static, BOM/LF & Lab Validation` ([134299131310](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083/job/134299131310)), `Check Linux (scripts/check.sh)` ([134299131851](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083/job/134299131851)), `Check macOS & Desktop macOS` (`macos-15-intel` Xcode 16 Swift 6 + `MeshDesktopCore` XCTest + XcodeGen + `SwiftLint --strict` + `xcodebuild test` + `scripts/check.sh` + Darwin `aarch64`/`x86_64` builds — [134299132054](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083/job/134299132054)), `Check Windows (scripts/check.ps1)` ([134299132072](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083/job/134299132072) — `windows-latest` MSVC + `MeshVPN.exe` `<= 6 MiB` PE `2` + installer dry-runs), `Docker Multi-Stage Build & Optional NAT Lab` ([134301117131](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083/job/134301117131)), `Build Linux & Windows Release Matrix (x86_64-unknown-linux-musl)` ([134313203322](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083/job/134313203322)), `Build Linux & Windows Release Matrix (x86_64-pc-windows-msvc)` ([134313203564](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083/job/134313203564)).
   - **[Mesh Android Native Build #44151164308](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44151164308)** (commit `c24715a` — **`success`**).
   - **[Mobile iOS CI #44096615783](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44096615783)** (commit `440f2ba` — **`success`**; ghi chú: lần push `c24715a` chỉ chạm test Rust/workflow mà `mobile-ios.yml` trên `macos-15` bị giới hạn hàng đợi arm64 GitHub Actions).
3. **`hardware_signoff_required`**: Nghiệm thu tương tác OS vật lý (Explorer Tray, macOS Menu Bar `gid = 80`, hộp thoại UAC/`osascript`, DPI, đo RAM/CPU/Quit thực tế) ghi vào sổ cái tại `docs/06-operations/desktop-gui-hardware-acceptance-protocol.md`.

---

## 2. Kết quả Cổng Kiểm định Tự động trên Host (`VERIFIED_ON_WINDOWS_HOST`)

| Mã cổng | Hạng mục kiểm định | Lệnh thực thi | Số lượng test thật trong repo |
|---|---|---|:-:|
| **DGUI-QA-01** | Workspace `fmt` & `clippy` (`-D warnings`) | `cargo fmt --all -- --check` & `cargo clippy --workspace --all-targets --all-features -- -D warnings` | `0` warnings / `0` errors |
| **DGUI-QA-02A** | Bộ kiểm thử `mesh-gui` (`main.rs::tests` + `gui_unit_tests` + `qa_desktop_security_audit` + `qa_desktop_e2e_ipc`) | `cargo test -p mesh-gui --all-targets --all-features` | **`23`** (`3` bin + `10` unit + `9` audit + `1` E2E 8 pha) |
| **DGUI-QA-02B** | Bộ kiểm thử CLI launcher (`qa_desktop_cli_launcher`) | `cargo test -p mesh --test qa_desktop_cli_launcher --all-features` | **`4`** tests |
| **DGUI-QA-02C** | Bộ kiểm thử hợp đồng IPC & `MGH1` (`desktop_ipc_contract`) | `cargo test -p mesh-net --test desktop_ipc_contract --all-features` | **`5`** *(+ `8` inline `ipc.rs`/`gui_handoff.rs`)* |
| **DGUI-QA-02D** | Bộ kiểm thử phiên & CLI version (`desktop_session_wp_d_a1` + `daemon_version_cli`) | `cargo test -p mesh-client --test desktop_session_wp_d_a1 --all-features` & `-p meshd --test daemon_version_cli` | **`1`** + **`1`** = **`2`** |
| **DGUI-QA-02E** | Bộ kiểm thử Onboarding & Zero-TOFU (`desktop_onboarding_validation`) | `cargo test -p mesh-core --test desktop_onboarding_validation --all-features` | **`7`** (`4` unit + `3` `proptest!`) |
| **DGUI-QA-02F** | Bộ kiểm thử Win32 FFI & Explorer (`gui_windows::tests` + `process_windows::tests`) | `cargo test -p mesh-sys --lib --all-features -- windows::tests` | **`3`** + **`2`** = **`5`** |
| **DGUI-QA-03** | Ngân sách release `MeshVPN.exe` & PE Subsystem | `cargo build --release -p mesh-gui --bin MeshVPN` | `<= 6 MiB` (mục tiêu `<= 4 MiB`), `PE Subsystem == 2` |
| **DGUI-QA-04** | Gỡ cài đặt & nâng cấp Windows (`UNINST-01..08`) | `powershell -File lab/desktop/verify-desktop-uninstall.ps1 -DryRun` | **`8/8`** checks |
| **DGUI-QA-05** | Kiểm toán tĩnh bảo mật đa nền tảng (`DGUI-AUDIT-01..10`) | `qa_desktop_security_audit.rs` + `lab/desktop/audit-desktop-security.sh` | **`10/10`** checks |

---

## 3. Bảng Xác minh 7 Work Packages (`WP-D-A0` .. `WP-D-C2` — `78 SP`)

| Work Package | Phạm vi thực tế theo `desktop-gui-sprint-backlog.md` v1.1 | Stories (`SP`) | Trạng thái tự động / CI / Phần cứng |
|---|---|:-:|:---|
| **`WP-D-A0`** *(Wave D-A.0)* | Workspace `v0.3.0`, `Dockerfile`, `scripts/check.{ps1,sh}`, `mesh-core` (`validate_preauth_key`, `MAX_BUGREPORT_ARCHIVE_BYTES`), `mesh-crypto`, `mesh-proto`, `mesh/Cargo.toml`, `mesh-sys` features/stubs, `mesh-net` (`ipc.rs`, `gui_handoff.rs` `MGH1`), `mesh-gui` skeleton | `US-102` (`3` Must) | `VERIFIED_ON_WINDOWS_HOST` + `VERIFIED_AT_CI_$0` (`#44156673083` Linux/macOS/Windows MSVC) |
| **`WP-D-A1`** *(Wave D-A.1)* | `mesh-client` (`delete_identity`, `execute_reset_identity`, `update_bootstrap_trust_preserving_next_pin`), `mesh-mobile-ffi/src/bridge.rs` (`FfiStateStore::delete_identity`), `meshd` (`--version`, `/v1/agent/version`, `X-Mesh-Agent-Version`, `/v1/agent/reset-identity`, `/v1/agent/bugreport/stream` `GuardedBugreportStream`) | `US-101` (`5` Must) | `VERIFIED_ON_WINDOWS_HOST` + `VERIFIED_AT_CI_$0` (`#44156673083`) |
| **`WP-D-A2`** *(Wave D-A.1)* | `crates/mesh-sys/src/process_windows.rs` (3-condition Explorer double-click + `CREATE_NEW_PROCESS_GROUP \| DETACHED_PROCESS`), `crates/mesh` (`mesh gui`, `mesh reset-identity [--yes]`, 0-arg exit `2`) | `US-100` (`3` Must) | `VERIFIED_ON_WINDOWS_HOST` + `VERIFIED_AT_CI_$0` (`#44156673083`) + `hardware_signoff_required` (`WIN-UAT-13`, `MAC-UAT-13`) |
| **`WP-D-B1`** *(Wave D-B1)* | `crates/mesh-sys/src/gui_windows.rs` + `crates/mesh-gui/src/**` (`MeshVPN.exe` Tray + Dashboard 8 states, Onboarding, 1-Click Reconnect, UAC `MGH1` `9 B` LE `<= 64 KiB` + `0x00 WorkerHello` `13 B`, `elevation_worker.rs` SDDL `OICI`/self-copy/`5 \| 32`, `UnprivilegedSinkWriter`, `Local\MeshVpnGuiSingleInstance`, `HKCU\...\Run\MeshVPN`) | `US-103..108` (`26` Must + `3` Should = **`29`**) | `VERIFIED_ON_WINDOWS_HOST` + `VERIFIED_AT_CI_$0` (`#44156673083` `check-windows` MSVC & matrix `MeshVPN.exe`) + `hardware_signoff_required` (`WIN-UAT-01..16`) |
| **`WP-D-B2`** *(Wave D-B2)* | `desktop/macos/**` (`Package.swift` Swift 6, `project.yml` `dev.meshvpn.macos`, `.swiftlint.yml`, `MeshDesktopCore` + `MeshVPNAppTests`, `LSUIElement`, single `Window("Mesh VPN", id: "dashboard")`, Non-Sandboxed, `0` `UIKit`, UDS `gid = 80`, `ClipboardAutoClear` trim `\n`, `AdminPrivilegeHelper` `--uninstall --keep-app`, `BugreportStreamWriter` `Darwin.rename`, `SafeOsLogger` `%{private}@`) + `scripts/install-macos.sh` | `US-109..113` (`18` Must + `3` Should = **`21`**) | `VERIFIED_ON_WINDOWS_HOST` (static audit) + `VERIFIED_AT_CI_$0` (`#44156673083` `check-macos` `swift test` + `swiftlint --strict` + `xcodebuild test`) + `hardware_signoff_required` (`MAC-UAT-01..16`) |
| **`WP-D-C1`** *(Wave D-C.0)* | `.github/workflows/{ci,release}.yml`, `scripts/package-macos-app.sh` (3-step `ADR-026` không `--deep`), `scripts/install-windows.ps1` (SDDL `OICI`, `Local\MeshVpnGuiShutdownEvent`, 12 bundle files cleanup, giữ `keys.json` mặc định) | `US-114, 115, 117` (`10` Must + `2` Could = **`12`**) | `VERIFIED_ON_WINDOWS_HOST` (`verify-desktop-uninstall.ps1`, `qa_desktop_security_audit`) + `VERIFIED_AT_CI_$0` (`#44156673083` `check-macos` Darwin dry-runs + `release-build-matrix` Linux/Windows) + `hardware_signoff_required` |
| **`WP-D-C2`** *(Wave D-C.1)* | `qa_desktop_{security_audit,e2e_ipc}.rs`, `lab/desktop/{audit-desktop-security.sh,verify-desktop-uninstall.ps1}`, `scripts/run-desktop-qa.{ps1,sh}`, 5 tài liệu QA & Ops Gate 3 | `US-116` (`5` Must) | `VERIFIED_ON_WINDOWS_HOST` (automated QA suites) + `hardware_signoff_required` (physical UAT ledger) |
| **TỔNG** | **`7` Work Packages (`4` Epics `EP-17..20`)** | **`18` Stories (`78 SP`)** | **`70` Must + `6` Should + `2` Could = `78 SP`** |

---

## 4. Bảng Xác minh Chi tiết 18 User Stories (`US-100..US-117` = `78 SP`)

| Story | Tên theo `desktop-gui-product-backlog.md` v1.1 | SP / MoSCoW | Bằng chứng Tự động (`VERIFIED_ON_WINDOWS_HOST` & `VERIFIED_AT_CI_$0`) | Phần cứng (`hardware_signoff_required`) |
|---|---|:---:|---|---|
| **US-100** | Lệnh `mesh gui`, bảo toàn CLI `0-arg` tự động hóa & fallback Explorer 3 điều kiện | `3` / `Must` | `qa_desktop_cli_launcher` (`4/4` tests), `cli::tests`, `process_windows::tests` (`2/2`), CI `#44156673083` | `WIN-UAT-13`, `MAC-UAT-13` |
| **US-101** | Hợp đồng IPC Dual-Channel, Stream Bugreport `<= 20 MiB`, Reset Identity, Bảo toàn `next_pin`, `agent_version` & Timeout 3 Tầng | `5` / `Must` | `desktop_ipc_contract` (`5/5` + `8` inline `mesh-net`), `desktop_session_wp_d_a1` (`1/1`), `daemon_version_cli` (`1/1`) | `WIN-UAT-04/10/11`, `MAC-UAT-03/10/11` |
| **US-102** | Kiểm chứng Onboarding Desktop (Chuẩn hóa `<host>:<port>`, Zero-TOFU) & Hàng rào Tĩnh `scripts/check.{ps1,sh}` | `3` / `Must` | `desktop_onboarding_validation` (`7/7`), `qa_desktop_security_audit` (Zero-TOFU + `mpk_` parity Rust/Swift), `scripts/check.ps1`, CI `#44156673083` | `WIN-UAT-05/06`, `MAC-UAT-04/05` |
| **US-103** | Win32 FFI An toàn trong `crates/mesh-sys` & Khung `MeshVPN.exe` (MSVC + MinGW `gnu` + Non-Windows CI, DPI-Aware, Tray Lifecycle) | `5` / `Must` | `mesh-gui` `#![windows_subsystem = "windows"]`, `0` `unsafe` trong `mesh-gui`, `100%` `// SAFETY:` trong `gui_windows.rs`, `DGUI-QA-03` (`<= 6 MiB`, `PE = 2`), `VERIFIED_AT_CI_$0` (`#44156673083` MSVC) | `WIN-UAT-01/02/14/16` |
| **US-104** | Tray Menu, Full Dashboard Windows, Onboarding `mesh://join`, 1-Click Reconnect vs Confirmation & Phục hồi `Revoked`/`ReauthRequired` | `5` / `Must` | `gui_unit_tests` (8 states + `LegacyPre030` + `ClipboardSecretGuard`), `qa_desktop_e2e_ipc` (`50` peers, `1-Click Reconnect` giữ `next_pin`, `RotateKey`, `ResetIdentity`), `SEC-05` | `WIN-UAT-03/05/06/07/10/12` |
| **US-105** | Cầu nối Nâng quyền `ShellExecuteExW("runas")`, Handoff `mpk_*` (`0` `argv`), Unprivileged Bridge & Bảo toàn `ADMIN_PIPE_SDDL` | `8` / `Must` | `qa_desktop_security_audit` (`MGH1` `9 B` LE, `0x00 WorkerHello` `13 B`, `SQOS`, `Zeroizing`), `gui_windows::tests`, `ipc_poller.rs` (`suspend()` trên `spawn_handoff_action`) | `WIN-UAT-04` |
| **US-106** | 1-Click Cài đặt, Nâng cấp & Khởi động `MeshVpnAgent` (`MESH_WINTUN_SHA256`, Anti-TOCTOU, Chống `ERROR_SHARING_VIOLATION`) | `5` / `Must` | `main.rs::tests` (`OICI` SDDL, `windows_paths_equivalent` self-copy guard, `Some(5 \| 32)` -> `.new`), `open_anti_toctou_read_locked` | `WIN-UAT-08` |
| **US-107** | Xuất Bugreport Unprivileged Sink Write (Stream `<= 20 MiB`) & Structured GUI Logging Windows | `3` / `Must` | `qa_desktop_e2e_ipc` + `gui_unit_tests` (`UnprivilegedSinkWriter` Replace & abort + `test_no_secrets_in_outputs` + `prop_sanitize_gui_log_*`) | `WIN-UAT-11` |
| **US-108** | Single-Instance Guard (`Local\`), Nâng cấp Êm & Tự Khởi chạy Đăng nhập (Opt-in) trên Windows | `3` / `Should` | `gui_unit_tests` (`SemVerTriple`, `should_request_upgrade_shutdown`, `format_autostart_command_line`), `Local\MeshVpnGuiSingleInstance` & `Local\MeshVpnGuiShutdownEvent` | `WIN-UAT-02/09` |
| **US-109** | Khung `Mesh VPN.app` (`LSUIElement`, Single-Window, Non-Sandboxed, Swift 6) & Menu Bar `NSStatusItem` | `5` / `Must` | `qa_desktop_security_audit` & `audit-desktop-security.sh` (`MeshApp.swift` single `Window("Mesh VPN", id: "dashboard")`, `startMonitoring()`, `.regular`/`.accessory`, `0` `UIKit`/`app-sandbox`/`CFBundleURLTypes`/`NSAllowsArbitraryLoads`, `Package.swift` Swift `6.0`), `VERIFIED_AT_CI_$0` (`#44156673083` `check-macos`) | `MAC-UAT-01/02/16` |
| **US-110** | Tầng Giao tiếp UDS (`meshd-ro`/`meshd-admin`, `gid=80` `0`-Mật khẩu) & SwiftUI Dashboard (Khắc phục 3 Lỗi `MeshApp`) | `5` / `Must` | `DesktopCoreTests.swift`, `DesktopStoreTests.swift`, `UdsIpcAndBugreportTests.swift` (`VERIFIED_AT_CI_$0` trên `#44156673083` `macos-15-intel` `swift test` + `xcodebuild test`) | `MAC-UAT-03..07/10/12` |
| **US-111** | 1-Click Cài đặt / Khởi động `LaunchDaemon` qua `osascript` (`root:wheel`), Bảo toàn Chữ ký & `socketfilterfw` Opt-In | `5` / `Must` | `UdsIpcAndBugreportTests.swift` (`AdminPrivilegeHelper`), `audit-desktop-security.sh` (`codesign -v`, `/usr/local/libexec/mesh/meshd`, `0` Gatekeeper disable) (`VERIFIED_AT_CI_$0` trên `#44156673083`) | `MAC-UAT-03/08` |
| **US-112** | Xuất Bugreport Streaming An toàn (Unprivileged Sink Write `0` Mật khẩu) & `OSLog` Secret Hygiene trên macOS | `3` / `Must` | `BugreportStreamWriter.swift` (`Darwin.rename(partURL.path, destURL.path)`), `SafeOsLogger` `%{private}@`, `UdsIpcAndBugreportTests.swift` (`VERIFIED_AT_CI_$0` trên `#44156673083`) | `MAC-UAT-11` |
| **US-113** | Phát hiện Lệch Phiên bản Bundle ↔ Daemon (`agent_version` & `meshd --version`) & Nâng cấp 1-Click trên macOS | `3` / `Should` | `DesktopStoreTests.swift` (`LegacyPre030`), `daemon_version_cli` (`1/1`), `UdsIpcClient.classifyVersionProbe` (`VERIFIED_AT_CI_$0` trên `#44156673083`) | `MAC-UAT-12` |
| **US-114** | Mở rộng `.github/workflows/{ci,release}.yml` Đóng gói `MeshVPN.exe` & `Mesh VPN.app` (`$0` Mode, Đúng Thứ tự `SHA256SUMS`) | `5` / `Must` | `qa_desktop_security_audit`, `verify-desktop-uninstall.ps1` (`UNINST-07/08`), `audit-desktop-security.sh` (`DGUI-AUDIT-09/10`), `VERIFIED_AT_CI_$0` (`#44156673083` `7/7` jobs) | `WIN-UAT-01`, `MAC-UAT-01` |
| **US-115** | Nâng cấp & Gỡ cài đặt Sạch qua `ResourceLedger` (`G4`), Dọn Sạch Dấu vết GUI & Giữ `keys.json` Mặc định | `5` / `Must` | `verify-desktop-uninstall.ps1` (`8/8`), `main.rs::tests` (`WINDOWS_BUNDLE_REMOVAL_LIST` 12 items + `netmap-cache.json` + `logs`/`bugreports` purge), `AdminPrivilegeHelper.swift` (`--uninstall --keep-app`) | `WIN-UAT-15`, `MAC-UAT-15` |
| **US-116** | Bộ Kiểm toán Bảo mật Đa Nền tảng (`$0` CI), Giao thức Nghiệm thu Phần cứng & Sổ tay Vận hành Desktop GUI | `5` / `Must` | `scripts/run-desktop-qa.{ps1,sh}`, `qa_desktop_security_audit` (`9/9`), `qa_desktop_e2e_ipc` (`1/1`), `audit-desktop-security.sh` (`10/10`), 5 tài liệu QA/Ops, CI `#44156673083` | `WIN-UAT-01..16`, `MAC-UAT-01..16` |
| **US-117** | Sẵn sàng Chữ ký Số Thương mại Có Điều kiện (Authenticode / Apple Developer ID & Notarization) | `2` / `Could` | `.github/workflows/release.yml` (fallback `$0` sạch sẽ, `KC_PASS="$(openssl rand -hex 24)"`, `files:` khớp artifact thực tế) | `paid_cert_required` (tùy chọn khi cấp cert) |

---

## 5. Tổng kết Cổng Kiểm chứng 43 `DGUI-*` & 5 `D-GNFR-*`

- **`DGUI-UX-01..07`, `DGUI-WIN-01..07`, `DGUI-MAC-01..07`, `DGUI-SEC-01..08`, `DGUI-IPC-01..05`, `DGUI-OPS-01..05`, `DGUI-PERF-01..04` (`43/43`)** và **`D-GNFR-01..05` (`5/5`)** đều được ánh xạ đầy đủ vào `7` Work Packages (`WP-D-A0..WP-D-C2`) và `18` Stories (`US-100..US-117` = `78 SP`).
- **Điều kiện hoàn tất phát hành `v0.3.0`**:
  1. `VERIFIED_ON_WINDOWS_HOST`: Toàn bộ bộ kiểm định Rust (`mesh-gui`, `mesh`, `mesh-net`, `mesh-client`, `meshd`, `mesh-core`, `mesh-sys`) + `scripts/check.ps1 -Cross` + `scripts/run-desktop-qa.ps1` xanh `100%`.
  2. `VERIFIED_AT_CI_$0`: [CI Gate #44156673083](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44156673083) (`7/7` jobs `success` tại `65b38c4`), [Mesh Android Native Build #44151164308](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44151164308) (`c24715a`), và [Mobile iOS CI #44096615783](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44096615783) (`440f2ba`).
  3. `hardware_signoff_required`: Ký duyệt sổ cái UAT máy thật Windows 10/11 & macOS 13+ trong `docs/06-operations/desktop-gui-hardware-acceptance-protocol.md`.
