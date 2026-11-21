# Báo Cáo Xác Minh Definition of Done (DoD) — Unified UI (`v0.4.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Phiên bản mục tiêu** | `v0.4.0` (Unified UI & Live Bilingual `vi`/`en` trên Windows · macOS · Android · iOS) |
| **Mã tài liệu** | `QA-DOD-UUI-001` |
| **Phiên bản tài liệu** | `1.0` |
| **Ngày cập nhật** | `2026-11-21` |
| **Phạm vi báo cáo** | Tổng hợp Wave U-A..U-D (trọng tâm khóa sổ `WP-U-D0` = `24 SP`: `US-131, 132, 135..139`), chuẩn bị bàn giao Wave U-E (`WP-U-E0`) |
| **Trạng thái hiện tại** | **`VERIFIED_ON_WINDOWS_HOST` (Rust `mesh-gui` + release binary) · `PENDING_CI_RUNNER` (macOS/Android/iOS/MSVC/musl CI) · `hardware_signoff_required`** |

---

## 1. Cam kết Trung thực Bằng chứng (3-Tier Honest Reporting)

Báo cáo này tách bạch tuyệt đối những gì đã chạy thực tế trên máy chủ Windows với những gì đang chờ GitHub Actions runner hoặc thiết bị vật lý thật:

- **`VERIFIED_ON_WINDOWS_HOST`**: Đã biên dịch và thực thi trực tiếp trong phiên làm việc `WP-U-D0` bằng toolchain Rust `+1.94.1-x86_64-pc-windows-gnu` trên máy chủ Windows.
- **`PENDING_CI_RUNNER`**: Các kiểm thử Xcode (`xcodebuild test`, `swift test`, `swiftlint --strict`) cho macOS/iOS, Android Gradle (`ktlintCheck`, `detekt`, `lintDebug`, `lintVitalRelease`, `testDebugUnitTest`), Linux `x86_64-unknown-linux-musl` cross-build, và Windows MSVC native **chưa chạy cục bộ** do máy trạm kiểm định là Windows không có macOS/Xcode hay Android SDK/emulator cục bộ — phải được xác nhận trên GitHub Actions CI tại Wave U-E (`WP-U-E0`).
- **`hardware_signoff_required`**: Các tiêu chí cảm quan & tương tác hệ điều hành thật (Windows Narrator Tab traversal, Windows High-Contrast visual, Android Tablet `>= 600 dp`, iPadOS `.regular` 2-column, macOS Dark/Light/Retina) ghi vào sổ cái `docs/06-operations/unified-ui-hardware-acceptance-protocol.md`.

---

## 2. Kết quả Cổng Kiểm định Tự động trên Host (`VERIFIED_ON_WINDOWS_HOST`)

> Ghi chú: Số liệu thực thi thực tế từ lệnh chạy trong `WP-U-D0` được ghi nhận dưới đây sau khi hoàn tất biên dịch và chạy kiểm thử.

| Mã cổng | Hạng mục kiểm định | Lệnh thực thi trên Host | Trạng thái |
|---|---|---|---|
| **UUI-HOST-01** | Rust Formatting (`rustfmt.toml`) | `cargo +1.94.1-x86_64-pc-windows-gnu fmt --all -- --check` | `VERIFIED_ON_WINDOWS_HOST` |
| **UUI-HOST-02** | `mesh-gui` Clippy (`-D warnings`, `0` `unsafe`, `0` `#[allow(`) | `cargo +1.94.1-x86_64-pc-windows-gnu clippy -p mesh-gui --all-targets --all-features -- -D warnings` | `VERIFIED_ON_WINDOWS_HOST` |
| **UUI-HOST-03** | Toàn bộ test suite `mesh-gui` (`bin` + `gui_unit_tests` + `gui_windows_unified_ui` + `i18n_parity_windows` + `qa_desktop_security_audit` + `qa_desktop_e2e_ipc` + `qa_gdi_leak_gate` + `qa_accessibility_unified_ui` + `qa_state_label_unification`) | `cargo +1.94.1-x86_64-pc-windows-gnu test -p mesh-gui --all-targets --all-features` | `VERIFIED_ON_WINDOWS_HOST` |
| **UUI-HOST-04** | GDI Handle Leak Gate (`100` chu kỳ -> `delta == 0`, `< 5_000`) | `cargo +1.94.1-x86_64-pc-windows-gnu test -p mesh-gui --test qa_gdi_leak_gate --all-features` | `VERIFIED_ON_WINDOWS_HOST` |
| **UUI-HOST-05** | Ngân sách nhị phân Release `MeshVPN.exe` (`<= 6_291_456` B, `PE Subsystem == 2`) | `cargo +1.94.1-x86_64-pc-windows-gnu build --release -p mesh-gui --bin MeshVPN` | `VERIFIED_ON_WINDOWS_HOST` (`2,695,168` B / `2.57 MiB`, `PE = 2`) |
| **UUI-HOST-06** | Vệ sinh tệp nguồn (UTF-8 No BOM, LF cho non-`.ps1`, CRLF cho `.ps1`, Swift/Kotlin `<= 100` cols, `0` cấm khóa) | Kiểm tra tĩnh PowerShell trên toàn bộ tệp `WP-U-D0` (`27/27` tệp sạch) | `VERIFIED_ON_WINDOWS_HOST` |

### 2.1. Chi tiết Số liệu Thực đo trên Windows Host
- **Binary Release `MeshVPN.exe`**: `2,695,168` bytes (`2.57 MiB` `<= 4.00 MiB` mục tiêu, `<= 6.00 MiB` trần cứng), `PE Subsystem = 2` (`IMAGE_SUBSYSTEM_WINDOWS_GUI`).
- **Tổng số test `mesh-gui` PASS (`--all-targets --all-features`)**: **`124/124` PASS, `0` failed, `0` ignored**:
  - `src/main.rs` (`MeshVPN` bin): `19/19` PASS
  - `tests/gui_unit_tests.rs`: `16/16` PASS
  - `tests/gui_windows_unified_ui.rs`: `29/29` PASS
  - `tests/i18n_parity_windows.rs`: `20/20` PASS
  - `tests/qa_accessibility_unified_ui.rs`: `3/3` PASS
  - `tests/qa_desktop_e2e_ipc.rs`: `5/5` PASS
  - `tests/qa_desktop_security_audit.rs`: `12/12` PASS
  - `tests/qa_gdi_leak_gate.rs`: `9/9` PASS (`test_gdi_handle_lifecycle` `100` chu kỳ -> `delta == 0`, `< 5_000`)
  - `tests/qa_state_label_unification.rs`: `11/11` PASS

---

## 3. Bảng Xác minh 7 User Stories của `WP-U-D0` (`24 SP`)

| Story | Tên hạng mục | SP / MoSCoW | Thay đổi thực tế trong `WP-U-D0` | Trạng thái |
|---|---|:---:|---|---|
| **US-131** | Tích hợp 3-Way Locale Selector (`System / Tiếng Việt / English`) đa nền tảng | `5` / `Must` | Xác minh đầy đủ 4 nền tảng (Windows `window.rs` + `diagnostics_view.rs`, macOS `DiagnosticsSheetView.swift` + `MeshL10n.swift`, Android `SettingsScreen.kt` + `LocaleHelper.kt`, iOS `SettingsView.swift` + `L10n.swift`); bổ sung `test_locale_selector_all_platforms`, `test_sec05_ops01_invariant_locale_vi` (Rust), `LocaleHelperTest.kt` (Android), `LocalizationParityTests.swift` (iOS), `MeshVPNAppTests.swift` (macOS) | `VERIFIED_ON_WINDOWS_HOST` (Rust) + `PENDING_CI_RUNNER` (macOS/Android/iOS) |
| **US-132** | Đồng nhất nhãn trạng thái chuẩn 8/10 trạng thái (`ADR-030`) | `2` / `Must` | Windows giữ `label()` cho `linux_gui.rs` & kiểm chứng `display_label(sub_state)`; sửa macOS `DesktopUiState.swift` (`serviceNotInstalled -> "Agent Unavailable"`, `reauthRequired -> "Re-auth Required"`); nâng cấp Android `StatusScreen.kt` dùng `@StringRes fun daemonStateLabelRes(state)` cho đủ 8 trạng thái `R.string.*` (0 raw enum) | `VERIFIED_ON_WINDOWS_HOST` (Rust) + `PENDING_CI_RUNNER` (macOS/Android) |
| **US-135** | Điều hướng `Tab` Windows (`WS_TABSTOP`, `WM_GETDLGCODE -> DLGC_WANTTAB`) & High-Contrast | `5` / `Must` | Bổ sung `dialog_code_for_message` (`WM_GETDLGCODE -> DLGC_WANTTAB`) & `ordered_tab_stop_control_ids` trong `window.rs`; kiểm định `WS_EX_CONTROLPARENT`, `IsDialogMessageW`, `WS_TABSTOP` trên 6 hàm tạo control và `SPI_GETHIGHCONTRAST` `cbSize`/`uiParam` trong `qa_accessibility_unified_ui.rs` | `VERIFIED_ON_WINDOWS_HOST` + `hardware_signoff_required` |
| **US-136** | GDI Handle Leak Gate Test (`100` chu kỳ -> `delta == 0`, `< 5_000`) | `3` / `Should` | Tạo `crates/mesh-gui/tests/qa_gdi_leak_gate.rs` chạy `100` chu kỳ create/paint/destroy cho palette + `OwnedMemDc` + double-buffer + hero + owner-draw + icon, khẳng định `GetGuiResources(GR_GDIOBJECTS)` `delta == 0` & tổng `< 5_000` | `VERIFIED_ON_WINDOWS_HOST` |
| **US-137** | Tích hợp màu ngữ nghĩa Notification & StatusBadge đa nền tảng | `3` / `Should` | Hoàn thiện mapping text thông báo cho `REAUTH_REQUIRED`/`REVOKED`/`SERVER_UPGRADE_REQUIRED` trong `MeshVpnService.kt` giữ `setColor(notificationColorForState(...))`; kiểm tra chéo màu `#16A34A`/`#D97706`/`#DC2626`/`#6B7280` across Windows/macOS/Android/iOS trong `qa_state_label_unification.rs` | `VERIFIED_ON_WINDOWS_HOST` (Rust) + `PENDING_CI_RUNNER` (Android/iOS/macOS) |
| **US-138** | Bố cục thích ứng 2 cột cho Tablet/iPad | `3` / `Could` | Nâng cấp Android `PeersScreen.kt` sang `LazyVerticalGrid(GridCells.Fixed(columnCount))` với `TABLET_LAYOUT_BREAKPOINT_DP = 600` (`peersGridColumnCount`), bảo toàn 100% `testTag`; nâng cấp iOS `PeersView.swift` sang `LazyVGrid` 2 cột khi `horizontalSizeClass == .regular` và 1 cột ở `.compact` (`PeersAdaptiveLayout`); bổ sung unit tests Android/iOS/Rust | `VERIFIED_ON_WINDOWS_HOST` (Rust) + `PENDING_CI_RUNNER` (Android/iOS) + `hardware_signoff_required` |
| **US-139** | Trình đọc màn hình Windows MSAA (`SetWindowTextW` + `NotifyWinEvent`, `0` `IAccessible`) | `3` / `Could` | Bổ sung `format_accessible_status_announcement` trong `window.rs` công bố trạng thái + tab hoạt động và thông báo toast qua `announce_accessible_label`; kiểm định `0` `IAccessible` COM & fallback an toàn khi `hwnd == 0` trong `qa_accessibility_unified_ui.rs` | `VERIFIED_ON_WINDOWS_HOST` + `hardware_signoff_required` |

---

## 4. Cổng Chờ CI Runner (`PENDING_CI_RUNNER`) & Phần cứng (`hardware_signoff_required`)

| Cổng | Nền tảng / Runner | Phạm vi cần xác nhận | Trạng thái |
|---|---|---|---|
| **UUI-CI-MAC-01** | GitHub Actions `macos-15` | `swift test --package-path desktop/macos/MeshDesktopCore`, `xcodegen`, `swiftlint lint --strict`, `xcodebuild test -scheme MeshVPNApp CODE_SIGNING_ALLOWED=NO` | `PENDING_CI_RUNNER` |
| **UUI-CI-IOS-01** | GitHub Actions `macos-15` | `xcodegen`, `swiftlint lint --strict`, `xcodebuild test -scheme MeshApp -destination "platform=iOS Simulator,name=iPhone 16" CODE_SIGNING_ALLOWED=NO` | `PENDING_CI_RUNNER` |
| **UUI-CI-AND-01** | GitHub Actions `ubuntu-latest` | `./gradlew ktlintCheck detekt lintDebug lintVitalRelease testDebugUnitTest` (+ `OnboardingComposeUiTest.kt` EN & `OnboardingComposeUiTestVi.kt` VI khi có emulator) | `PENDING_CI_RUNNER` |
| **UUI-CI-RUST-01** | GitHub Actions `ubuntu-latest` & `windows-latest` | `scripts/check.sh --cross` (`x86_64-unknown-linux-musl` + `linux_gui.rs`) & `scripts/check.ps1 -Cross` (MSVC) + `cargo deny check` | `PENDING_CI_RUNNER` |
| **UUI-HW-01** | Thiết bị thật (4 nền tảng) | Sổ cái `docs/06-operations/unified-ui-hardware-acceptance-protocol.md` (`UUI-UAT-WIN-01..06`, `UUI-UAT-MAC-01..04`, `UUI-UAT-AND-01..05`, `UUI-UAT-IOS-01..05`) | `hardware_signoff_required` |
