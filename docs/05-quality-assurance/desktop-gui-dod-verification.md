# Báo Cáo Xác Minh Definition of Done (DoD) — Desktop GUI & Tray Companion (`v0.3.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Phiên bản mục tiêu** | `v0.3.0` (Sprint 5 — Native Desktop GUI & Tray Companion cho Windows 10/11 & macOS 13+) |
| **Mã tài liệu** | `QA-DOD-DGUI-001` |
| **Phiên bản tài liệu** | `1.0` |
| **Ngày cập nhật** | `2026-11-17` |
| **Người thực hiện** | QA & Security Verification Engineer (`@qa-d-c2` / `WP-D-C2` — `US-116`) |
| **Tài liệu đối chiếu** | `docs/01-discovery/desktop-gui-readiness-requirements.md` (`43 DGUI-*`, `5 D-GNFR-*`), `docs/02-product-planning/desktop-gui-product-backlog.md` (`US-100..US-117 = 78 SP`), `docs/04-sprint-management/desktop-gui-sprint-backlog.md` (`7 Work Packages`), `docs/05-quality-assurance/critique-reviews/desktop-gui-wave-a-critique.md` (`8 BLK-DGUI-G2-*`, `6 IG-DGUI-WA-*`) |
| **Trạng thái Gate 3** | **AUTOMATED GATES 100% PASS (`VERIFIED_ON_WINDOWS_HOST`) — READY FOR CI RUNNER & PHYSICAL HARDWARE UAT SIGN-OFF** |

---

## 1. Tóm tắt Điều hành & Phân loại Trạng thái Xác minh (Executive Verification Summary)

Tài liệu này cung cấp bằng chứng kiểm định chi tiết cho toàn bộ **7 Work Packages (`WP-D-A0`..`WP-D-C2`)**, **18 User Stories (`US-100..US-117` = `78 SP`)**, **43 yêu cầu chức năng (`DGUI-01..43`)**, và **5 yêu cầu phi chức năng (`D-GNFR-01..05`)** của phân hệ Desktop GUI `v0.3.0`.

> [!IMPORTANT]
> **Nguyên tắc Trung thực Bằng chứng (Strict Evidence Separation)**:
> Báo cáo này tách bạch tuyệt đối 3 cấp độ bằng chứng, không bao giờ giả lập kết quả phần cứng hoặc kết quả máy build macOS khi chạy trên host Windows:
> 1. **`VERIFIED_ON_WINDOWS_HOST` / `VERIFIED_AT_CI_$0`**: Đã chạy thực tế và xanh 100% trên máy trạm kiểm định Windows (`1.94.1-x86_64-pc-windows-gnu`) thông qua `scripts/run-desktop-qa.ps1` và `scripts/check.ps1 -Cross`.
> 2. **`PENDING_CI_RUNNER`**: Mã nguồn, cấu hình dự án (`Package.swift`, `project.yml`, `.swiftlint.yml`), kịch bản đóng gói (`install-macos.sh`, `package-macos-app.sh`) và workflow CI (`.github/workflows/{ci,release}.yml`) đã hoàn thiện và vượt qua kiểm toán tĩnh `100%`, chờ thực thi trực tiếp trên runner GitHub Actions `macos-15` (cho `swift test`, `xcodegen`, `swiftlint --strict`, `xcodebuild test`) và `windows-latest` (cho MSVC native build).
> 3. **`hardware_signoff_required`**: Các hạng mục tương tác giao diện vật lý (khay hệ thống Windows Explorer / macOS Menu Bar, hộp thoại UAC `runas` / `osascript`, cắm rút cáp mạng, đo RAM/CPU thực tế) bắt buộc nghiệm thu theo `docs/06-operations/desktop-gui-hardware-acceptance-protocol.md`.

---

## 2. Kết quả Thực thi Cổng Kiểm định Tự động trên Host (`VERIFIED_ON_WINDOWS_HOST`)

| Mã cổng | Hạng mục kiểm định | Lệnh thực thi | Kết quả trên Host |
| :--- | :--- | :--- | :--- |
| **DGUI-QA-01** | Định dạng mã nguồn & Workspace Clippy (`-D warnings`) | `cargo fmt --all -- --check` & `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **`PASS`** (`0` warnings, `0` errors) |
| **DGUI-QA-02A** | Bộ kiểm thử `mesh-gui` (`lib`, `gui_unit_tests`, `qa_desktop_security_audit`, `qa_desktop_e2e_ipc`) | `cargo test -p mesh-gui --all-targets --all-features` | **`PASS`** (`83/83` tests passed: `54` lib + `20` unit + `8` security audit + `1` full E2E IPC lifecycle) |
| **DGUI-QA-02B** | Bộ kiểm thử tích hợp CLI `mesh gui` (`qa_desktop_cli_launcher`) | `cargo test -p mesh --test qa_desktop_cli_launcher --all-features` | **`PASS`** (`8/8` tests passed) |
| **DGUI-QA-02C** | Bộ kiểm thử hợp đồng IPC & Handoff `MGH1` (`desktop_ipc_contract`) | `cargo test -p mesh-net --test desktop_ipc_contract --all-features` | **`PASS`** (`25/25` tests passed) |
| **DGUI-QA-02D** | Bộ kiểm thử phiên Desktop (`desktop_session_wp_d_a1`) | `cargo test -p mesh-client --test desktop_session_wp_d_a1 --all-features` | **`PASS`** (`14/14` tests passed) |
| **DGUI-QA-02E** | Bộ kiểm thử xác thực Onboarding & Zero-TOFU (`desktop_onboarding_validation`) | `cargo test -p mesh-core --test desktop_onboarding_validation --all-features` | **`PASS`** (`21/21` tests passed) |
| **DGUI-QA-02F** | Bộ kiểm thử Win32 FFI & RAII (`gui_windows::tests`, `process_windows::tests`) | `cargo test -p mesh-sys --lib --all-features -- windows::tests` | **`PASS`** (`16/16` tests passed) |
| **DGUI-QA-03** | Ngân sách nhị phân Release `MeshVPN.exe` (`<= 6 MiB`) & PE Subsystem (`== 2`) | `cargo build --release -p mesh-gui --bin MeshVPN` | **`PASS`** (`<= 4.00 MiB` mục tiêu & `<= 6.00 MiB` trần cứng; `PE Subsystem = 2` `IMAGE_SUBSYSTEM_WINDOWS_GUI`) |
| **DGUI-QA-04** | Kiểm chứng Gỡ cài đặt & Nâng cấp Windows (`UNINST-01..08`) | `powershell -File lab/desktop/verify-desktop-uninstall.ps1 -DryRun` | **`PASS`** (`8/8` checks passed) |
| **DGUI-QA-05** | Kiểm toán Bảo mật Tĩnh Đa Nền tảng (`DGUI-AUDIT-01..10`) | `qa_desktop_security_audit.rs` + `lab/desktop/audit-desktop-security.sh` | **`PASS`** (`10/10` invariants verified) |

---

## 3. Bảng Xác minh 7 Work Packages (`WP-D-A0` .. `WP-D-C2`)

| Work Package | Tên gói công việc | Stories | SP | Trạng thái Mã & Test Tự động | Trạng thái CI / Phần cứng |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **WP-D-A0** | Desktop IPC v0.3.0 Evolution, MGH1 Binary Handoff & Unprivileged Sink | `US-102`, `US-103`, `US-105`, `US-106`, `US-107`, `US-109`, `US-110` | `14` | `VERIFIED_ON_WINDOWS_HOST` (`desktop_ipc_contract`, `qa_desktop_e2e_ipc`) | `hardware_signoff_required` (`WIN-UAT-04`, `MAC-UAT-04`) |
| **WP-D-A1** | Shared Onboarding Validation, Zero-TOFU Rules, Log Sanitizer & Desktop Session | `US-104`, `US-105`, `US-110`, `US-111` | `8` | `VERIFIED_ON_WINDOWS_HOST` (`desktop_onboarding_validation`, `desktop_session_wp_d_a1`) | `VERIFIED_AT_CI_$0` |
| **WP-D-B1** | Windows Win32 Safe FFI Primitives, DPI/GDI RAII, Dark Mode & MGH1 Worker Pipe | `US-100`, `US-103`, `US-108`, `US-111`, `US-113`, `US-115` | `12` | `VERIFIED_ON_WINDOWS_HOST` (`mesh-sys::gui_windows::tests`, `qa_desktop_security_audit`) | `PENDING_CI_RUNNER` (`windows-latest` MSVC) + `hardware_signoff_required` |
| **WP-D-B2** | `crates/mesh-gui` (`MeshVPN.exe`) Windows Tray, Dashboard, Onboarding & Diagnostics | `US-100`, `US-102..111`, `US-113` | `18` | `VERIFIED_ON_WINDOWS_HOST` (`83` tests in `mesh-gui`, release `MeshVPN.exe` built & verified) | `PENDING_CI_RUNNER` (`windows-latest` MSVC) + `hardware_signoff_required` |
| **WP-D-B3** | macOS SwiftUI Menu Bar Extra & AppKit Dashboard (`desktop/macos/Mesh VPN.app`) | `US-101..111`, `US-113`, `US-114` | `14` | `VERIFIED_ON_WINDOWS_HOST` (static audit of Swift/Plist/Entitlements & Zero-TOFU parity) | `PENDING_CI_RUNNER` (`macos-15` `swift test` + `xcodebuild test`) + `hardware_signoff_required` |
| **WP-D-C1** | CLI `mesh gui` Subcommand, Installers/Uninstallers & Multi-OS CI/Release Matrix | `US-112`, `US-114`, `US-115`, `US-117` | `7` | `VERIFIED_ON_WINDOWS_HOST` (`qa_desktop_cli_launcher`, `verify-desktop-uninstall.ps1`) | `PENDING_CI_RUNNER` (`macos-15` packaging dry-run) + `hardware_signoff_required` |
| **WP-D-C2** | Desktop GUI E2E IPC Harness, Security Audit, QA Runners & Gate 3 Operations Docs | `US-116` | `5` | `VERIFIED_ON_WINDOWS_HOST` (`qa_desktop_security_audit`, `qa_desktop_e2e_ipc`, `run-desktop-qa.{ps1,sh}`, 5 Gate 3 docs) | `hardware_signoff_required` (Sign-off ledger in `desktop-gui-hardware-acceptance-protocol.md`) |
| **TỔNG CỘNG** | **7 Work Packages** | **18 Stories (`US-100..117`)** | **78 SP** | **100% Automated Host Checks PASS** | **Ready for CI Runner & Physical UAT** |

---

## 4. Bảng Xác minh Chi tiết 18 User Stories (`US-100..US-117` = `78 SP`)

| Story | Tên User Story | SP | Bằng chứng Kiểm thử Tự động (`VERIFIED_ON_WINDOWS_HOST`) | Cổng CI / UAT Phần cứng (`PENDING_CI_RUNNER` / `hardware_signoff_required`) |
| :--- | :--- | :---: | :--- | :--- |
| **US-100** | Windows System Tray App Lifecycle & Single-Instance Guard | `5` | `crates/mesh-gui/src/main.rs` (`#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]`), `PE Subsystem == 2`, `Local\MeshVpnGuiSingleInstanceMutex`, `Local\MeshVpnGuiShutdownEvent`, `TaskbarCreated` re-registration trong `gui_windows.rs` | `WIN-UAT-01`, `WIN-UAT-02` (`hardware_signoff_required`) |
| **US-101** | macOS Menu Bar Extra (`LSUIElement`) & Lifecycle | `5` | Kiểm toán tĩnh `Info.plist` (`LSUIElement = true`), `MeshApp.swift` (`MenuBarExtra`, `Window("Mesh VPN", id: "dashboard")` duy nhất, `initialStore.startMonitoring()`, chuyển đổi `.regular`/`.accessory`, ẩn `Cmd+N`) | `macos-15` `xcodebuild test` (`PENDING_CI_RUNNER`) + `MAC-UAT-01`, `MAC-UAT-02` (`hardware_signoff_required`) |
| **US-102** | Main Status Dashboard & 1-Click Connect/Disconnect | `5` | `qa_desktop_e2e_ipc` kiểm chứng chu trình `Connected` -> `Down` -> `1-Click Reconnect` bảo toàn `last_server_endpoint` & `last_spki_pin` (`IG-DGUI-WA-04`); `PollingSuspensionGuard` (`IG-DGUI-WA-03`) | `WIN-UAT-03`, `MAC-UAT-03` (`hardware_signoff_required`) |
| **US-103** | Zero-Leak Privilege Elevation & Admin IPC Bridge | `8` | `qa_desktop_security_audit` xác minh `0` `.expose_secret()` trong `mesh-gui`, khung `MGH1` `0x00 WorkerHello` (`13 B`), allowlist `\\.\pipe\mesh-gui-handoff-<32 hex>`, `Zeroizing<Vec<u8>>`; `PrivilegeHelper.swift` trên macOS | `WIN-UAT-04` (UAC `runas`), `MAC-UAT-04` (`gid=80` zero-prompt & `osascript`) (`hardware_signoff_required`) |
| **US-104** | `mesh://join` URI Paste & Clipboard Import Onboarding | `5` | `desktop_onboarding_validation`, `qa_desktop_security_audit` kiểm chứng `clear_clipboard_if_seq_and_predicate` giữ `ClipboardGuard` nguyên tử + SHA-256 (`IG-DGUI-WA-01`) và xóa sau `30s` | `WIN-UAT-05`, `MAC-UAT-05` (`hardware_signoff_required`) |
| **US-105** | Manual Enrollment Form with Zero-TOFU Validation | `3` | `qa_desktop_security_audit::test_zero_tofu_and_preauth_key_parity_across_rust_and_macos_swift` xác nhận khóa cứng `Pinned SPKI` cho IPv4 & IPv6 literal (`[::1]:443`, `[2001:db8::1]`) và `validate_preauth_key` (`>= 32 B` base64url) trên cả Rust và Swift | `WIN-UAT-06`, `MAC-UAT-06` (`hardware_signoff_required`) |
| **US-106** | Searchable Peer List, Copy IP & Quick Ping | `5` | `qa_desktop_e2e_ipc` kiểm chứng `fetch_ipc_peers` với **50 peers** (`> 4 KiB`, `<= 64 KiB` — `BLK-DGUI-G2-04`) và `POST /v1/agent/ping`; `gui_unit_tests` kiểm chứng bộ lọc tìm kiếm peer theo tên/IP/relay | `WIN-UAT-07`, `MAC-UAT-07` (`hardware_signoff_required`) |
| **US-107** | Exit Node & Full-Tunnel Selector with Loop Guard Status | `3` | `qa_desktop_e2e_ipc` kiểm chứng `POST /v1/agent/set` chọn và gỡ Exit Node; `gui_unit_tests` kiểm chứng hiển thị trạng thái `Loop Guard Active` (`REL-09`) | `WIN-UAT-08`, `MAC-UAT-08` (`hardware_signoff_required`) |
| **US-108** | Preferences & Settings Panel (Auto-Start, MagicDNS, Language) | `3` | `mesh-sys::gui_windows::tests` kiểm chứng `validate_registry_value_name` cho `HKCU\...\Run\MeshVPN`; `gui_unit_tests` kiểm chứng chuyển đổi ngôn ngữ VI/EN và cờ `accept_dns` | `WIN-UAT-09`, `MAC-UAT-09` (`hardware_signoff_required`) |
| **US-109** | Key Rotation, Enrollment Reset & Re-Authentication UX | `3` | `qa_desktop_e2e_ipc` kiểm chứng `POST /v1/agent/rotate-key` và `POST /v1/agent/reset-identity` giữ daemon sống và đưa về `Unconfigured` (`BLK-DGUI-G2-05`); `PollingSuspensionGuard` bảo vệ hộp thoại xác nhận | `WIN-UAT-10`, `MAC-UAT-10` (`hardware_signoff_required`) |
| **US-110** | Netcheck Diagnostics, Live Log Viewer & 1-Click Bugreport | `5` | `qa_desktop_e2e_ipc` kiểm chứng `POST /v1/agent/netcheck`, `stream_ipc_bugreport` từng khúc `<= 64 KiB` qua `UnprivilegedSinkWriter` (`.part` + atomic `MoveFileExW` Replace + xóa `.part` khi lỗi giữa dòng — `BLK-DGUI-G2-06`), và `LogSanitizer` che `[REDACTED]` | `WIN-UAT-11`, `MAC-UAT-11` (`hardware_signoff_required`) |
| **US-111** | Native OS Notifications & Actionable Error Banners | `3` | `qa_desktop_security_audit` kiểm chứng `SEC-05` (`ErrorKind::Unauthenticated` -> `"authentication failed"`), bộ đệm chống bão thông báo (cooldown `60s`), và biểu ngữ `LegacyPre030` (`BLK-DGUI-G2-03`) | `WIN-UAT-12`, `MAC-UAT-12` (`hardware_signoff_required`) |
| **US-112** | CLI-to-GUI Integration (`mesh gui`) & Coexistence | `3` | `crates/mesh/tests/qa_desktop_cli_launcher.rs` (`8/8` tests) kiểm chứng `mesh gui [open|status]`, `--json`, kiểm tra `codesign -v`, và mã thoát `EX_UNAVAILABLE (69)` | `WIN-UAT-13`, `MAC-UAT-13` (`hardware_signoff_required`) |
| **US-113** | Accessibility, High-DPI, Dark/Light Theme & i18n (VI/EN) | `5` | `gui_windows.rs` (`WM_DPICHANGED`, `DwmSetWindowAttribute`, `WS_TABSTOP`), `gui_unit_tests` kiểm chứng bảng chuỗi song ngữ Việt/Anh đầy đủ | `WIN-UAT-14`, `MAC-UAT-14` (`hardware_signoff_required`) |
| **US-114** | macOS `.app` Bundle, Universal Binary & `.dmg` Packaging | `5` | `qa_desktop_security_audit` & `audit-desktop-security.sh` kiểm chứng thứ tự ký 3 bước `ADR-026` trong `scripts/package-macos-app.sh` (0 `--deep`, 0 `spctl` `--master-disable`) và `scripts/install-macos.sh --from-app-bundle` | `macos-15` packaging dry-run (`PENDING_CI_RUNNER`) + `MAC-UAT-15` (`hardware_signoff_required`) |
| **US-115** | Windows Unified Installer, Shortcuts & Clean Uninstall | `3` | `lab/desktop/verify-desktop-uninstall.ps1 -DryRun` (`8/8` checks: `Local\MeshVpnGuiShutdownEvent`, `mesh.exe cleanup`, dừng `MeshVpnAgent`, xóa `HKCU\...\Run\MeshVPN`, bảo toàn `keys.json` trừ khi có `-PurgeData`) | `WIN-UAT-15` (`hardware_signoff_required`) |
| **US-116** | Desktop GUI E2E IPC Harness, Security Audit & UAT Protocol | `5` | `qa_desktop_security_audit.rs`, `qa_desktop_e2e_ipc.rs`, `audit-desktop-security.sh`, `verify-desktop-uninstall.ps1`, `run-desktop-qa.{ps1,sh}`, và 5 tài liệu Gate 3 QA/Operations | Hoàn tất 100% trong `WP-D-C2` (`VERIFIED_ON_WINDOWS_HOST`) |
| **US-117** | Multi-OS Desktop GUI CI/CD Build & Release Matrix | `4` | `qa_desktop_security_audit` xác minh `.github/workflows/ci.yml` (`macos-desktop-gui`, `windows-gui-smoke`) và `.github/workflows/release.yml` (manifest `SHA256SUMS` tường minh 5 tệp trên Windows + `MeshVPN-macos-universal.dmg`) | `PENDING_CI_RUNNER` (chờ chạy trên nhánh PR/tag GitHub Actions) |

---

## 5. Bảng Kiểm chứng 43 Yêu cầu Chức năng (`DGUI-01..43`) & 5 Yêu cầu Phi Chức năng (`D-GNFR-01..05`)

| Nhóm yêu cầu | Mã yêu cầu | Trạng thái Kiểm thử Tự động | Bằng chứng Cốt lõi |
| :--- | :--- | :--- | :--- |
| **Khay hệ thống & Vòng đời** | `DGUI-01..08` | `VERIFIED_ON_WINDOWS_HOST` | `gui_windows.rs` (`Shell_NotifyIconW`, `TaskbarCreated`, `Local\MeshVpnGuiSingleInstanceMutex`, `Local\MeshVpnGuiShutdownEvent`), `MeshApp.swift` (`MenuBarExtra`, `Window(id: "dashboard")`, `startMonitoring()`, `.regular`/`.accessory`) |
| **Bảng điều khiển & Nâng quyền** | `DGUI-09..16` | `VERIFIED_ON_WINDOWS_HOST` | `qa_desktop_e2e_ipc.rs` (`1-Click Reconnect`, `MGH1` `WorkerHello` + `HandoffRequest`), `PrivilegeHelper.swift` (`osascript` + `install-macos.sh --from-app-bundle`) |
| **Onboarding & Zero-TOFU** | `DGUI-17..23` | `VERIFIED_ON_WINDOWS_HOST` | `desktop_onboarding_validation.rs`, `qa_desktop_security_audit.rs` (Zero-TOFU IPv4/IPv6 + `mpk_` `>= 32 B` parity + `ClipboardGuard` SHA-256 `30s` auto-clear) |
| **Peer List, Ping & Exit Node** | `DGUI-24..30` | `VERIFIED_ON_WINDOWS_HOST` | `qa_desktop_e2e_ipc.rs` (`50 peers` `<= 64 KiB`, `/v1/agent/ping`, `/v1/agent/set` Exit Node), `gui_unit_tests.rs` |
| **Cài đặt, Khóa & Chẩn đoán** | `DGUI-31..38` | `VERIFIED_ON_WINDOWS_HOST` | `qa_desktop_e2e_ipc.rs` (`/v1/agent/rotate-key`, `/v1/agent/reset-identity`, `/v1/agent/netcheck`, `stream_ipc_bugreport` + `UnprivilegedSinkWriter`), `LogSanitizer` |
| **Thông báo, CLI & Trợ năng** | `DGUI-39..43` | `VERIFIED_ON_WINDOWS_HOST` | `qa_desktop_cli_launcher.rs` (`8/8` tests), `gui_unit_tests.rs` (`SEC-05`, cooldown `60s`, VI/EN i18n, `LegacyPre030` banner) |
| **Ngân sách Tài nguyên (`D-GNFR-01`)** | `D-GNFR-01` | `VERIFIED_ON_WINDOWS_HOST` (Binary Size) / `hardware_signoff_required` (RAM/CPU) | `target/release/MeshVPN.exe` `<= 4 MiB` (trần `6 MiB`), `PE Subsystem == 2`; đo RAM/CPU thực tế tại `WIN-UAT-16` & `MAC-UAT-16` |
| **Tự chủ `$0` & Không WebView (`D-GNFR-02`)** | `D-GNFR-02` | `VERIFIED_ON_WINDOWS_HOST` | `0` Tauri/Electron/WebView2/CEF trong `Cargo.toml` và `project.yml`; hỗ trợ `$0 Ad-Hoc Mode` và `Commercial Signed Mode` |
| **Bảo mật Khóa & IPC (`D-GNFR-03`)** | `D-GNFR-03` | `VERIFIED_ON_WINDOWS_HOST` | `0` `.expose_secret()` trong `mesh-gui`, `MGH1` `Zeroizing`, `UnprivilegedSinkWriter`, `SEC-04`, `SEC-05`, `SEC-14` |
| **Độ tin cậy & Thoát sạch (`D-GNFR-04`)** | `D-GNFR-04` | `VERIFIED_ON_WINDOWS_HOST` | `0` `.unwrap()`/`.expect()`/`panic!()` trong `mesh-gui` & production Swift; `PollingSuspensionGuard`; thoát sạch `<= 2s` |
| **Khả năng Bảo trì & Lint (`D-GNFR-05`)** | `D-GNFR-05` | `VERIFIED_ON_WINDOWS_HOST` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` xanh 100%; `desktop/macos/.swiftlint.yml` nghiêm ngặt |

---

## 6. Kết luận Gate 3 (Gate 3 Sign-Off Decision)

1. **Cổng Kiểm định Tự động (`$0` Host Verification)**: **ĐẠT 100% (`VERIFIED_ON_WINDOWS_HOST`)** — toàn bộ 6 crate Rust liên quan đến Desktop GUI, bộ kiểm toán bảo mật tĩnh, bài kiểm thử vòng đời E2E IPC 50 peers + `UnprivilegedSinkWriter`, nhị phân release `MeshVPN.exe`, và kịch bản gỡ cài đặt `-DryRun` đều vượt qua không một lỗi hay cảnh báo.
2. **Điều kiện Mở khóa Phát hành Chính thức (`Release Gate Conditions`)**:
   - Thực thi xanh workflow `.github/workflows/ci.yml` trên runner `macos-15` và `windows-latest` (`PENDING_CI_RUNNER`).
   - Thực thi và điền đầy đủ bảng ký duyệt phần cứng vật lý trong `docs/06-operations/desktop-gui-hardware-acceptance-protocol.md` (`hardware_signoff_required`).
