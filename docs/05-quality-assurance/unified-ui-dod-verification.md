# Báo Cáo Xác Minh Definition of Done (DoD) — Unified UI & Bilingual (`v0.4.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Phiên bản mục tiêu** | `v0.4.0` (Unified UI & Live Bilingual `vi`/`en` trên Windows · macOS · Android · iOS) |
| **Mã tài liệu** | `QA-DOD-UUI-001` |
| **Phiên bản tài liệu** | `1.4` (Đồng bộ truy vết `22/22 Stories = 93 SP` & ghi nhận xanh `3/3` GitHub Actions CI `VERIFIED_AT_CI_$0` sau Gate 3 `A1`) |
| **Ngày cập nhật** | `2026-11-21` |
| **Người kiểm định** | `@qa-ui` (`WP-U-E0`: `US-133`, `US-134`), `@dev-fix-g3` & Orchestrator (`VERIFIED_AT_CI_$0`) |
| **Phạm vi kiểm chứng** | Toàn bộ `22/22 Stories = 93 SP` (`US-118..US-139`: `16 Must = 75 SP`, `4 Should = 12 SP`, `2 Could = 6 SP`; `Wave U-A` `WP-U-A0` = `0 Stories / 0 SP`), `38/38 UUI-*`, `ADR-027..031`, `213/213` khóa song ngữ trên 4 nền tảng |
| **KẾT LUẬN DoD CUỐI CÙNG** | **`[PASS - ĐẠT DoD]`** *(100% cổng `VERIFIED_ON_WINDOWS_HOST` + **3/3 GitHub Actions workflows `VERIFIED_AT_CI_$0`** xanh tuyệt đối: [CI Gate #44884759994](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44884759994) `7/7` jobs, [Mesh Android Native Build #44884760060](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44884760060), [Mobile iOS CI #44883437843](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44883437843); `4/4` Bug `BUG-UUI-001..004` `CLOSED`; chỉ còn cổng `hardware_signoff_required` trên thiết bị vật lý thật trước khi merge `main`)* |

---

## 1. Cam Kết Trung Thực Bằng Chứng 3 Tầng (3-Tier Honest Reporting)

Báo cáo này tách bạch tuyệt đối 3 tầng bằng chứng kiểm định, không suy diễn hay giả lập kết quả của công cụ chưa chạy trên OS đích:

1. **`VERIFIED_ON_WINDOWS_HOST`**: Đã biên dịch và thực thi trực tiếp trên máy chủ Windows (`cargo +1.94.1-x86_64-pc-windows-gnu` `fmt`/`clippy`/`test`, `cargo-deny check advisories bans licenses sources`, `lab/mobile/audit-mobile-security.ps1`, `ktlint-cli 1.5.0`, và trình kiểm toán tĩnh sâu PowerShell cho `51` tệp Kotlin, `69` tệp Swift, `4` kho tài nguyên `213` khóa, `532` tệp văn bản BOM/EOL).
2. **`VERIFIED_AT_CI_$0`**: Đã chạy thật và **đạt `3/3` workflows (`SUCCESS`)** trên GitHub Actions runner OS đích sau khi Người dùng duyệt Gate 3 (`Phương án A1 — $0 Mode`) tại commit `65dd171` (và `78fbc25` cho iOS): `macos-15-intel`/`macos-15` (Xcode 16.4 Swift 6, `SwiftPM`, `XcodeGen`, `SwiftLint --strict`, `xcodebuild test` macOS & iOS Simulator, `scripts/check.sh`, Darwin `aarch64`/`x86_64`, Universal `Mesh VPN.app`/DMG, unsigned `.ipa`), `ubuntu-latest` (Android `ktlintCheck`, `detekt`, `lintDebug`, `testDebugUnitTest`, `.apk`/`.aab` `16 KB`, `scripts/check.sh`, Linux `musl` release, Docker NAT lab), và `windows-latest` (MSVC `scripts/check.ps1`, `gui_unit_tests`, `MeshVPN.exe` release). *(Lưu ý trung thực: bài instrumentation `OnboardingComposeUiTest.kt` / `OnboardingComposeUiTestVi.kt` trong `androidTest` không chạy trong job `ubuntu-latest` không có emulator và được kiểm ở Tầng 3.)*
3. **`hardware_signoff_required`**: Nghiệm thu tương tác trên thiết bị vật lý thật theo sổ cái `docs/06-operations/unified-ui-hardware-acceptance-protocol.md` (Windows Narrator Tab traversal + High-Contrast *Desert*/*Aquatic* visual, macOS Dark/Light/Retina, Android Phone/Tablet `>= 600 dp` + `OnboardingComposeUiTest*` + `FLAG_SECURE` + Notification semantic tint, iPadOS `.regular` 2-column `LazyVGrid` + Face ID/Touch ID).

---

## 2. Kết Quả Cổng Kiểm Định Thực Tế Trên Host (`VERIFIED_ON_WINDOWS_HOST`)

| Mã cổng | Hạng mục kiểm định | Lệnh thực thi thực tế | Số liệu / Kết quả | Trạng thái |
| :--- | :--- | :--- | :--- | :---: |
| **UUI-HOST-01** | Định dạng mã Rust (`rustfmt.toml`) | `cargo +1.94.1-x86_64-pc-windows-gnu fmt --all -- --check` | `0` vi phạm trên toàn workspace | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-02** | Phân tích tĩnh Clippy (`-D warnings`, `0` `unsafe` ở `mesh-gui`, `0` `#[allow(clippy::...)]`) | `cargo +1.94.1-x86_64-pc-windows-gnu clippy -p mesh-gui -p mesh-sys --all-targets --all-features -- -D warnings` | `0` warnings, `0` errors | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-03** | Toàn bộ test suite `mesh-gui` (gồm `security_regression_unified_ui`, High-Contrast `GetSysColor`, non-enrolled layout, 3-tab arrow nav) | `cargo +1.94.1-x86_64-pc-windows-gnu test -p mesh-gui --all-targets --all-features` | **`146/146` PASS, `0` failed, `0` ignored** (10 binaries) | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-04** | Bộ kiểm thử Win32/GDI FFI `mesh-sys` (gồm Win32 Tab-escape khỏi `ES_MULTILINE` `EDIT` + `←`/`→` 3 tab + `GetSysColor`) | `cargo +1.94.1-x86_64-pc-windows-gnu test -p mesh-sys -- gui_windows` | **`12/12` PASS, `0` failed** | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-05** | Cổng chống rò rỉ GDI Handle (`100` chu kỳ -> `delta == 0`, `< 5_000`) | `qa_gdi_leak_gate` (`windows_gdi_gate::*` + `theme::tests`) | `10/10` PASS (`delta == 0`, `< 5_000`) | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-06** | Ngân sách nhị phân Release `MeshVPN.exe` (`<= 6_291_456` B, `PE Subsystem == 2`) & `libmesh_mobile_ffi.so` | `cargo build --release -p mesh-gui --bin MeshVPN` (xác minh trên host Windows) | `MeshVPN.exe` = **`2,699,264` B (`2.57 MiB` `<= 6.00 MiB`), `PE = 2`**; `libmesh_mobile_ffi.so` = **`4,379,040` B (`4.18 MiB`)** | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-07** | Kiểm toán chính sách phụ thuộc & giấy phép Rust | `cargo-deny check advisories bans licenses sources` | `advisories ok, bans ok, licenses ok, sources ok` (`exit 0`) | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-08** | Kiểm toán bảo mật di động Android & iOS | `powershell -ExecutionPolicy Bypass -File lab/mobile/audit-mobile-security.ps1` | **`16/16` PASS (`MOB-SEC-01..16`), `0` failed** | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-09** | Đối xứng `213/213` khóa từ điển song ngữ trên 4 nền tảng & `knownRegions`/`CFBundleLocalizations` | Kiểm toán tự động `i18n.rs`, `en.lproj`/`vi.lproj`, `values`/`values-vi/strings.xml` (`230/230`), `Localizable.xcstrings`, `project.yml`, `Info.plist` | **`213/213` khớp 100%** trên cả 4 nền tảng (`0` thiếu); `en`/`vi` khai báo đủ trên iOS & macOS | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **UUI-HOST-10** | Vệ sinh tệp nguồn & kiểm toán tĩnh cổng CI Linter 4 nền tảng | Kiểm tra BOM/CRLF/LF (`532` tệp) + đối chiếu `detekt.yml` (`51` `.kt`), `.swiftlint.yml` (`69` `.swift`), Android Lint `strings.xml` | BOM=`0`, sai dòng kết thúc=`0`, **`0` vi phạm linter (`BUG-UUI-001..004` `CLOSED`)** | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |

---

## 3. Ma Trận Kiểm Chứng Độc Lập `22/22` User Stories (`93 SP`), `38/38 UUI-*` & `ADR-027..031`

### 3.1. Xác Minh Kiến Trúc Quyết Định (`ADR-027 .. ADR-031`)
- **`ADR-027` (Win32 Owner-Draw + DWM + GDI RAII, `0` crate GUI ngoài)**: **ĐẠT 100%** — `MeshVPN.exe` chỉ dùng `mesh-sys::gui_windows` (`OwnedGdiObj`, `OwnedMemDc`, `PaintGuard`, `OwnedIcon`, `OwnedMenu`), `2.57 MiB`, `0` rò rỉ GDI sau `100` chu kỳ, hỗ trợ `GetSysColor` High-Contrast (*Desert* & *Aquatic*) và thoát bẫy `Tab` khỏi `ES_MULTILINE` `EDIT`.
- **`ADR-028` (3-Zone / 3-Tab Information Architecture)**: **ĐẠT 100%** — Windows (`Status / Peers / Diagnostics & Settings` + thanh chọn nhanh `Appearance`/`Language` khi `!enrolled`), macOS (`Window("Mesh VPN", id: "dashboard")` + `MenuBarExtra` với Segmented `Picker` 3 tab xuyên suốt mọi trạng thái enrolled), Android (`Status / Peers / Settings` `NavigationBar` + `OnboardingQuickPreferencesCard` khi `!enrolled`), iOS (`TabView` 3 tab + `OnboardingView` kèm chọn ngôn ngữ).
- **`ADR-029` (Native Zero-Dependency Live Bilingual `vi`/`en`)**: **ĐẠT 100%** — Đủ `213/213` khóa đối xứng trên cả 4 nền tảng, chuyển đổi tức thời không khởi động lại daemon/tunnel, `knownRegions: [en, vi, Base]` + `CFBundleLocalizations: [en, vi]` trên iOS/macOS, `strings.xml` sạch `tools:ignore="TypographyDashes,TypographyEllipsis,UnusedResources"`, kèm helper nội tuyến (`tr_inline`, `MeshL10n.inline`, `L10n.inline`, `LocaleHelper.tr`) cho nhãn phụ.
- **`ADR-030` (Design Tokens, 8/10 Canonical State Labels, 4-Chip Peer Filter `online &&`, Non-Secret Copy Boundary)**: **ĐẠT 100%** trên cả 4 nền tảng (`qa_state_label_unification` `11/11` + `security_regression_unified_ui` `17/17`).
- **`ADR-031` (Zero-Wire-Change `AgentStatusResponse` 13 Fields, User-Space `ui-prefs.json`, SemVer `0.4.0`)**: **ĐẠT 100%** (`test_agent_status_response_13_fields` & `test_prefs_no_secrets_in_ui_prefs_json` PASS, SemVer `0.4.0` đồng bộ toàn kho).

### 3.2. Bảng Trạng Thái `22/22` User Stories (`93 SP`) & `38/38 UUI-*`

> **Ghi chú nền tảng (`Wave U-A` / `WP-U-A0` = `0 Stories / 0 SP`)**: Theo `unified-ui-sprint-backlog.md` v1.2, `WP-U-A0` là gói khóa khung nền tảng (`0 SP`: đồng bộ SemVer `0.4.0`, bật `Win32_Graphics_Dwm`/`Win32_UI_Accessibility`, khung `OwnedMemDc`/`PaintGuard` và các mô-đun `theme.rs`/`i18n.rs`/`prefs.rs`/`status_view.rs`). Toàn bộ `22` Stories (`93 SP` = `16 Must [75 SP]` + `4 Should [12 SP]` + `2 Could [6 SP]`) nằm trong các Wave `U-B..U-E` dưới đây và khớp **1:1** với `unified-ui-product-backlog.md` v1.1:

| Wave (WP Lead / Contrib) | Story | SP | MoSCoW | Yêu cầu `UUI-*` | Tên Story & Kết quả kiểm chứng độc lập |
| :---: | :--- | :---: | :---: | :--- | :--- |
| **U-B1** (`WP-U-B1` / `B2`) | `US-118` | `8` | `Must` | `UUI-01, UUI-03, UUI-33` | **3-Tab Navigation Desktop (Windows & macOS) + Onboarding tách biệt + Zone 3 Maintenance CTAs** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `gui_windows_unified_ui` `30/30`, `window.rs` non-enrolled prefs + `linux_gui.rs`; **`VERIFIED_AT_CI_$0`**: macOS `DashboardWindowView.swift` Swift 6 + `CI Gate #44884759994`) |
| **U-B3** (`WP-U-B3` / `B4`) | `US-119` | `5` | `Must` | `UUI-02, UUI-03, UUI-33` | **Bottom Tab Bar Mobile (Android & iOS) 3 tabs + Onboarding tách biệt + SPKI Pin auto-lock** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `test_android_flag_secure_scope_not_peers_tab` + `OnboardingQuickPreferencesCard` + `OnboardingView.swift`; **`VERIFIED_AT_CI_$0`**: `#44884760060` / `#44883437843`) |
| **U-B1** (`WP-U-B1` / `B2,B3,B4`) | `US-120` | `5` | `Must` | `UUI-04, UUI-05` | **Peers Zone: Search (`nodeId`) + 4-State Filter (`online &&`) + Count Badge (4 nền tảng)** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `peers_view.rs`, `gui_windows_unified_ui`, `PeersScreen.kt` `online &&`; **`VERIFIED_AT_CI_$0`**: Android `PeersFilteringTest`, macOS `DesktopCoreTests`, iOS `UnifiedUiFoundationTests`) |
| **U-B1** (`WP-U-B1` / `B3,B4`) | `US-121` | `3` | `Must` | `UUI-06, UUI-07` | **Peers Zone: Copy IP/FQDN Clipboard (Simple Copy + Toast, tách `ClipboardSecretGuard`)** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `#44884759994` / `#44884760060` / `#44883437843`) |
| **U-B1** (`WP-U-B1`) | `US-122` | `8` | `Must` | `UUI-08, UUI-09, UUI-23, UUI-24, UUI-25, UUI-32` | **Windows GDI/DWM Modern: Rounded Cards, Status Pills, 3-Tab Widget & Dark Titlebar** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `mesh-sys -- gui_windows` `12/12`, `window.rs` 3-tab `←`/`→`, `MeshVPN.exe` `2.57 MiB`; **`VERIFIED_AT_CI_$0`**: `windows-latest` MSVC `#44884759994`) |
| **U-B1** (`WP-U-B1`) | `US-123` | `3` | `Must` | `UUI-13, UUI-14, UUI-26, UUI-31, UUI-32` | **Windows DPI Per-Monitor V2 & `OwnedGdiObj` RAII Gate Test** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `OwnedGdiObj`/`OwnedMemDc`/`PaintGuard`, `calc_font_height_for_dpi`, `0` GDI leak; **`VERIFIED_AT_CI_$0`** MSVC `#44884759994`) |
| **U-B2** (`WP-U-B2` / `B3,B4`) | `US-124` | `5` | `Must` | `UUI-10, UUI-11, UUI-12, UUI-15` | **Design Token Color System: macOS, Android (3-way), iOS Theme Selector** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: macOS `MeshVPNAppTests`, Android `ThemeAndNotificationTokensTest`, iOS `UnifiedUiFoundationTests`, `BUG-UUI-001` `CLOSED`) |
| **U-C1** (`WP-U-C1`) | `US-125` | `3` | `Should` | `UUI-27` | **Windows: `WM_SETTINGCHANGE` / Registry Live Theme Reload** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `windows-latest` MSVC `#44884759994`) |
| **U-B1** (`WP-U-B1` / `B2`) | `US-126` | `3` | `Should` | `UUI-15, UUI-35` | **Tray/Menu Bar Icon Semantic Color Mapping & Bilingual Labels (Windows & macOS)** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `DesktopStoreIconMappingTests` trên `macos-15-intel` `#44884759994`) |
| **U-C1** (`WP-U-C1`) | `US-127` | `5` | `Must` | `UUI-16, UUI-20, UUI-21, UUI-22, UUI-35` | **Windows i18n String Table Module (`en` / `vi`, `213` keys) + Tray Bilingual** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `i18n_parity_windows` `21/21`, `213/213` khóa + `tr_inline`) |
| **U-C2** (`WP-U-C2`) | `US-128` | `5` | `Must` | `UUI-17, UUI-20, UUI-21, UUI-22, UUI-35` | **macOS i18n: `MeshL10n` + `{en,vi}.lproj/Localizable.strings` (`213` keys) + Live Switch** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `MeshL10nTests` + `MeshVPNAppTests` trên `macos-15-intel` `#44884759994`) |
| **U-C3** (`WP-U-C3`) | `US-129` | `5` | `Must` | `UUI-18, UUI-20, UUI-21, UUI-22` | **Android i18n: `values-vi/strings.xml` (`230/230`) + Live `ContextWrapper` Locale Mechanism + `enableSplit = false`** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `LocaleHelperTest`, `ktlint`, `lintDebug`, `bundleRelease` `#44884760060`) |
| **U-C4** (`WP-U-C4`) | `US-130` | `3` | `Must` | `UUI-19, UUI-20, UUI-21, UUI-22` | **iOS i18n: `Localizable.xcstrings` Full Glossary (`213` keys) + `Bundle.main` Live Switch** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `LocalizationParityTests` trên iPhone Simulator `#44883437843`) |
| **U-D** (`WP-U-D0` / `C1..C4`) | `US-131` | `5` | `Must` | `UUI-20, UUI-21, UUI-22` | **3-Way Locale Selector (`System / Tiếng Việt / English`) — All Platforms** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `CI Gate #44884759994`, Android `#44884760060`, iOS `#44883437843`) |
| **U-D** (`WP-U-D0`) | `US-132` | `2` | `Must` | `UUI-33` | **Canonical State Label Glossary — All Platforms + `TunnelSubState` Display Logic** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**) |
| **U-E** (`WP-U-E0`) | `US-133` | `5` | `Must` | `UUI-34` | **Security Invariants Preservation Regression Suite** — **PASS 100%** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `security_regression_unified_ui` `17/17`, `audit-mobile-security`) |
| **U-E** (`WP-U-E0`) | `US-134` | `3` | `Must` | `UUI-37` | **Existing Test Suite Regression Safety (All Platforms)** — **PASS 100%** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `3/3` GitHub Actions workflows `SUCCESS`) |
| **U-D** (`WP-U-D0`) | `US-135` | `5` | `Must` | `UUI-28, UUI-29` | **Windows Keyboard Tab Traversal (`Tab`/`←`/`→`) & High-Contrast Mode (`GetSysColor`)** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `qa_accessibility_unified_ui` `3/3`; **`VERIFIED_AT_CI_$0`** MSVC `#44884759994`; `hardware_signoff_required`) |
| **U-D** (`WP-U-D0`) | `US-136` | `3` | `Should` | `UUI-31` | **Windows GDI Handle Leak Gate Test** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `qa_gdi_leak_gate` `10/10` — `100` chu kỳ `delta == 0`) |
| **U-D** (`WP-U-D0` / `B3,B4`) | `US-137` | `3` | `Should` | `UUI-36` | **Notification Badge/Status Semantic Color Mapping (Android & iOS)** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: `ThemeAndNotificationTokensTest` & `UnifiedUiFoundationTests`) |
| **U-D** (`WP-U-D0`) | `US-138` | `3` | `Could` | `UUI-38` | **Tablet/iPad Adaptive Layout: 2-Column Peers Zone (`>= 600 dp` / `.regular`)** — **PASS** (`VERIFIED_ON_WINDOWS_HOST` + **`VERIFIED_AT_CI_$0`**: Android `PeersFilteringTest` + iOS `UnifiedUiFoundationTests`; `hardware_signoff_required`) |
| **U-D** (`WP-U-D0`) | `US-139` | `3` | `Could` | `UUI-30` | **Windows MSAA/UIA Screen Reader Accessibility Names** — **PASS** (`VERIFIED_ON_WINDOWS_HOST`: `SetWindowTextW` + `NotifyWinEvent`, `0` `IAccessible` COM + `hardware_signoff_required`) |
| **Tổng cộng** | **`22` Stories** | **`93`** | `16M/4S/2C` | **`38/38 UUI-*`** | **`75 SP Must + 12 SP Should + 6 SP Could = 93 SP` (Wave U-A `WP-U-A0` = `0 SP`) ✓** |

---

## 4. Kết Quả Cổng GitHub Actions CI (`VERIFIED_AT_CI_$0`) & Phần Cứng (`hardware_signoff_required`)

| Cổng | Nền tảng / Runner | Phạm vi thực thi & Bằng chứng | Trạng thái |
| :--- | :--- | :--- | :--- |
| **UUI-CI-MAC-01** | GitHub Actions `macos-15-intel` | `swift test --package-path desktop/macos/MeshDesktopCore`, `xcodegen`, `swiftlint lint --strict`, `xcodebuild test -scheme MeshVPNApp CODE_SIGNING_ALLOWED=NO`, Universal `.app`/DMG — [CI Gate #44884759994](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44884759994) (`65dd171`) | **PASS (`VERIFIED_AT_CI_$0`)** |
| **UUI-CI-IOS-01** | GitHub Actions `macos-15` | `build-ios-xcframework.sh`, `xcodegen`, `swiftlint lint --strict`, `xcodebuild build test -scheme MeshApp` Simulator & `.ipa` packaging — [Mobile iOS CI #44883437843](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44883437843) (`78fbc25`) | **PASS (`VERIFIED_AT_CI_$0`)** |
| **UUI-CI-AND-01** | GitHub Actions `ubuntu-latest` | `gradle ktlintCheck detekt lintDebug testDebugUnitTest assembleDebug bundleRelease assembleRelease` + 16 KB APK/AAB check — [Mesh Android Native Build #44884760060](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44884760060) (`65dd171`; `OnboardingComposeUiTest*.kt` instrumentation chờ emulator/máy thật) | **PASS (`VERIFIED_AT_CI_$0`)** |
| **UUI-CI-RUST-01** | GitHub Actions `ubuntu-latest` & `windows-latest` | `scripts/check.sh` + `SLO`, `scripts/check.ps1` + `gui_unit_tests` + MSVC `MeshVPN.exe` + Linux `musl` & Windows release matrix — [CI Gate #44884759994](https://github.com/nguyenvando420-spec/mesh-vpn/actions/runs/44884759994) (`7/7` jobs `completed/success`) | **PASS (`VERIFIED_AT_CI_$0`)** |
| **UUI-HW-01** | Thiết bị thật (4 nền tảng) | Sổ cái `docs/06-operations/unified-ui-hardware-acceptance-protocol.md` (`UUI-UAT-WIN-01..06`, `UUI-UAT-MAC-01..04`, `UUI-UAT-AND-01..05` gồm `OnboardingComposeUiTest*.kt`, `UUI-UAT-IOS-01..05`) | `hardware_signoff_required` |
