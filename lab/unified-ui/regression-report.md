# Báo Cáo Kiểm Thử Không Hồi Quy Toàn Diện — Unified UI (`v0.4.0` · `US-134`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Milestone / Nhánh** | `v0.4.0` (`feat/unified-ui`) |
| **Work Package / Story** | `WP-U-E0` — `US-134` (`UUI-37`: Zero-Regression Suite & CI Gate Verification) |
| **Mã tài liệu** | `LAB-UUI-REG-001` |
| **Phiên bản** | `1.2` (Đồng bộ kết quả kiểm định sau khắc phục `BUG-UUI-001..004` & Gate 3 Round 1 `CRIT-UUI-G3-001`) |
| **Ngày kiểm thử** | `2026-11-21` |
| **Người thực hiện** | `@qa-ui` (`agile-qa` độc lập) & `@coordinator` (host re-verification sau Gate 3 Round 1) |
| **Kết luận hồi quy `US-134`** | **`[PASS - ĐẠT DoD]` — Rust/Windows (`146/146` `mesh-gui` + `12/12` `mesh-sys -- gui_windows` [`30/30` `windows::tests`] + `2,699,264 B` [`2.57 MiB`] `MeshVPN.exe`), Bảo mật di động (`16/16`), Parity `213/213` khóa 4 nền tảng, và Kiểm toán tĩnh cổng CI Linter (`51/51` Kotlin + `69/69` Swift = `0` vi phạm) đều PASS 100%** |

---

## 1. Tóm Tắt Thực Thi & Phân Tách Bằng Chứng 3 Tầng

Báo cáo này tổng hợp kết quả kiểm thử không hồi quy độc lập trên toàn bộ kho mã `feat/unified-ui` cho Milestone `v0.4.0`, tuân thủ nghiêm ngặt 3 tầng bằng chứng:

1. **`VERIFIED_ON_WINDOWS_HOST`**: Đã biên dịch và thực thi trực tiếp trên máy chủ Windows bằng toolchain chuẩn `cargo +1.94.1-x86_64-pc-windows-gnu` và các trình kiểm toán tĩnh sâu PowerShell.
2. **`PENDING_CI_RUNNER`**: Các lệnh biên dịch/chạy test trên runner đích (`macos-15` Xcode/SwiftPM/SwiftLint, `ubuntu-latest` Android Gradle/Detekt/Android Lint & Linux `musl`, `windows-latest` MSVC) — đã được QA mô phỏng tĩnh 1-1 theo đúng cấu hình `.github/workflows/{ci,mobile-android,mobile-ios,release}.yml` với **`0` lỗi còn tồn đọng**.
3. **`hardware_signoff_required`**: Nghiệm thu tương tác trên thiết bị vật lý thật theo `docs/06-operations/unified-ui-hardware-acceptance-protocol.md`.

---

## 2. Kết Quả Thực Thi Trực Tiếp Trên Windows Host (`VERIFIED_ON_WINDOWS_HOST`)

| STT | Lệnh thực thi thực tế (Tái thẩm định sau Gate 3 Round 1) | Số liệu kết quả | Trạng thái |
| :---: | :--- | :--- | :---: |
| **1** | `cargo +1.94.1-x86_64-pc-windows-gnu fmt --all -- --check` | `0` khác biệt định dạng trên toàn bộ workspace Rust (`rustfmt.toml` `max_width = 100`) | **PASS** |
| **2** | `cargo +1.94.1-x86_64-pc-windows-gnu clippy -p mesh-gui -p mesh-sys --all-targets --all-features -- -D warnings` | `0` warnings, `0` errors, `0` `#[allow(clippy::...)]`, `0` `unsafe` trong `mesh-gui` | **PASS** |
| **3** | `cargo +1.94.1-x86_64-pc-windows-gnu test -p mesh-gui --all-targets --all-features` | **`146/146` PASS, `0` failed, `0` ignored** trên 10 test binaries | **PASS** |
| **4** | `cargo +1.94.1-x86_64-pc-windows-gnu test -p mesh-sys -- gui_windows` & `--lib -- windows::tests` | **`12/12` `gui_windows` (`30/30` `windows::tests`) PASS, `0` failed** (GDI/DWM/Shell/High-Contrast `GetSysColor` RAII + Win32 Tab-escape & `←`/`→`) | **PASS** |
| **5** | `cargo +1.94.1-x86_64-pc-windows-gnu build --release -p mesh-gui --bin MeshVPN` | **`2,699,264` bytes (`2.57 MiB`)** `<= 4.00 MiB` mục tiêu `<= 6.00 MiB` trần cứng; **`PE Subsystem = 2`** (`IMAGE_SUBSYSTEM_WINDOWS_GUI`) | **PASS** |
| **6** | `cargo-deny check advisories bans licenses sources` | `advisories ok, bans ok, licenses ok, sources ok` (`0` crate bị cấm, `0` phụ thuộc mới) | **PASS** |
| **7** | `powershell -ExecutionPolicy Bypass -File lab/mobile/audit-mobile-security.ps1` | **`16/16` PASS (`MOB-SEC-01..16`), `0` failed** | **PASS** |

### 2.1. Chi Tiết Phân Rã `146/146` Bài Kiểm Thử `mesh-gui` (`--all-targets --all-features`)

| Test Target | Số test PASS | Nội dung bảo vệ hồi quy |
| :--- | :---: | :--- |
| `src/main.rs` (`MeshVPN` bin unittests) | `21 / 21` | Unit tests nội tuyến: 8/10 UI states, `213` khóa i18n, `ThemeMode` serde, High-Contrast *Desert*/*Aquatic* `GetSysColor`, `UiPrefs` atomic save/corrupt fallback, double-buffer paint `0` leak, `WM_SETTINGCHANGE`, 3-tab arrow nav & non-enrolled zero-RECT-overlap layout, tray 9-item menu, worker CLI args |
| `tests/gui_unit_tests.rs` | `16 / 16` | Bộ hồi quy `v0.3.0`: 8 states + legacy pre-`0.3.0`, Zero-TOFU URI & rotate validation, `MGH1` framing & zeroize, `ClipboardSecretGuard`, bugreport 64 KiB chunks, `proptest` log sanitizer |
| `tests/gui_windows_unified_ui.rs` | `30 / 30` | Bộ `WP-U-B1`: 3-tab bar ở mọi trạng thái enrolled, `display_label`, giữ `label()` cho Linux, 4-state peer filter chips, non-secret copy boundary, 10-state tray tone, `WS_CLIPCHILDREN`, GDI RAII |
| `tests/i18n_parity_windows.rs` | `21 / 21` | Bộ `WP-U-C1`: đối chiếu 1-1 đủ `213` khóa EN/VI, `t_for` thuần túy không đụng biến toàn cục, `SEC-05` không dịch, tray VI, live switch không restart daemon, `ui-prefs.json` |
| `tests/qa_accessibility_unified_ui.rs` | `3 / 3` | Bộ `WP-U-D0` & `HIGH-UUI-G3-01`: `handle_dialog_keydown_navigation` thoát `ES_MULTILINE` `EDIT` + `on_tab_arrow_key` 3 tab `←`/`→`, `SPI_GETHIGHCONTRAST` + `GetSysColor`, MSAA `SetWindowTextW` + `NotifyWinEvent` (`0` `IAccessible`) |
| `tests/qa_desktop_e2e_ipc.rs` | `5 / 5` | E2E IPC vòng đời 50 peers, sink replace, reset identity, tương thích daemon cũ |
| `tests/qa_desktop_security_audit.rs` | `12 / 12` | Kiểm toán bảo mật Desktop `v0.3.0` (SDDL `OICI`, `MGH1` fuzzing `proptest`, Zero-TOFU parity Rust/macOS, `0` `expose_secret`, `0` `unsafe`) |
| `tests/qa_gdi_leak_gate.rs` | `10 / 10` | Cổng GDI Leak `100` chu kỳ create/paint/destroy -> `GetGuiResources(GR_GDIOBJECTS)` `delta == 0` & tổng `< 5_000` |
| `tests/qa_state_label_unification.rs` | `11 / 11` | Đồng nhất nhãn trạng thái Windows/macOS/Android, 3-way locale selector 4 nền tảng, `SEC-05`/`OPS-01` ở `vi`, breakpoint `600 dp` / `.regular`, màu ngữ nghĩa notification/badge |
| `tests/security_regression_unified_ui.rs` | `17 / 17` | **Mới (`WP-U-E0`)**: đủ `9` bài kiểm thử hồi quy bảo mật `US-133` + `8` unit tests của các mô-đun được gắn kiểm tra chéo |
| **TỔNG CỘNG (`mesh-gui`)** | **`146 / 146`** | **`0` failed · `0` ignored** |

---

## 3. Kiểm Chứng Hồi Quy Đa Nền Tảng & Tính Tương Thích Ngược (`US-134` AC1..AC4)

### 3.1. Đối xứng `213/213` Khóa Từ điển Chuẩn (`Discovery v1.1` §4.1)
Kiểm toán tự động PowerShell đối chiếu tập khóa chuẩn `213` mục từ `docs/01-discovery/unified-ui-readiness-requirements.md`:
- **Windows (`crates/mesh-gui/src/i18n.rs`)**: `213/213` khóa EN và `213/213` khóa VI không rỗng (`0` thiếu, `0` dư).
- **macOS (`en.lproj/Localizable.strings` & `vi.lproj/Localizable.strings`)**: `213/213` khóa EN và `213/213` khóa VI không rỗng (`0` thiếu, `0` dư).
- **Android (`values/strings.xml` & `values-vi/strings.xml`)**: `230/230` mục đối xứng 1-1 giữa `values` và `values-vi` (`213` khóa chuẩn chuyển sang `snake_case` + `17` khóa kế thừa Android `v0.3.0`; `0` `MissingTranslation`, `0` `ExtraTranslation`, khai báo đầy đủ `tools:ignore="TypographyDashes,TypographyEllipsis,UnusedResources"`).
- **iOS (`mobile/ios/MeshApp/Resources/Localizable.xcstrings`)**: JSON hợp lệ chứa đúng `213/213` khóa với đầy đủ `localizations.en` và `localizations.vi` không rỗng (`0` thiếu).

### 3.2. Tái Thẩm Định Tĩnh Toàn Bộ Cổng Linter CI (`detekt.yml`, `.swiftlint.yml`, `Package.swift`)
Sau bản sửa `#65` (`BUG-UUI-001..004` -> `CLOSED`) và bản vá Gate 3 Round 1 (`#71`):
- **Android Kotlin (`51/51` tệp `.kt` trong `mobile/android/app/src`)**:
  - Mọi tệp/class trong `main` đều có `< 25` hàm (`MeshMainViewModel.kt` = `23` hàm; `UiPreferencesCoordinator.kt` = `7` interface + `7` class; `QuickPreferencesRow.kt` cho `!enrolled`; `MeshVpnService.kt` = `24` hàm; `MeshVpnNotificationHelper.kt` = `4` hàm).
  - Mọi hàm cụ thể đều có thân `< 95` dòng không trống (`CameraPreviewScanner` = `80` dòng; `PeersScreen` = `74` dòng; `JoinConfirmationDialog` = `41` dòng).
  - `0` dòng `> 120` cột (toàn bộ tệp UI `v0.4.0` `<= 100` cột), `0` wildcard import, `0` `!!` trong `main`, `0` `GlobalScope`, `0` `@Suppress` mới.
- **macOS & iOS Swift (`69/69` tệp `.swift`: `33` macOS + `36` iOS)**:
  - `desktop/macos/MeshDesktopCore/Package.swift` tự động nạp toàn bộ tệp trong `Tests/MeshDesktopCoreTests` (gồm cả `DesktopStoreReconnectTests.swift` và `DesktopStoreTestMocks.swift`), và `desktop/macos/project.yml` + `mobile/ios/project.yml` + `Info.plist` đều khai báo đủ `developmentLanguage: en`, `knownRegions: [en, vi, Base]`, `CFBundleLocalizations: [en, vi]`.
  - `0` dòng `> 100` cột, `0` tệp `> 600` dòng (`max = 589`), `0` kiểu dữ liệu `> 350` dòng thân, `0` hàm cụ thể `> 80` dòng thân, `0` định danh `> 90` ký tự, `0` `swiftlint:disable`, `0` force-unwrap / `try!` / `as!` / `print` / `fatalError`.
- **Bảo toàn Tương thích Linux & Android UI Tests (`US-134` AC1)**:
  - `DesktopUiState::label()` và `filter_peers(peers, query)` 2 tham số được giữ nguyên cho `linux_gui.rs`.
  - `OnboardingComposeUiTest.kt` (`en`) giữ nguyên vẹn `"Verify Control Server Identity"` và toàn bộ `testTag`; `OnboardingComposeUiTestVi.kt` kiểm thử tiếng Việt độc lập.
- **Vệ sinh Tệp Nguồn**: Toàn bộ tệp mã nguồn và tài liệu mới/sửa đều đạt **UTF-8 No BOM**, chuẩn dòng kết thúc `LF` (`.ps1` = `CRLF`).

---

## 4. Kết Luận Hồi Quy (`US-134`)

Toàn bộ yêu cầu của **`US-134` (`UUI-37`) ĐẠT 100% (`[PASS - ĐẠT DoD]`)**: không còn lỗi `Critical`/`Major`/`Minor` mở; kho mã sẵn sàng thực thi xác nhận cuối cùng trên các runner `PENDING_CI_RUNNER` (`macos-15`, `ubuntu-latest`, `windows-latest`) và nghiệm thu phần cứng `hardware_signoff_required`.
