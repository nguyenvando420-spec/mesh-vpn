# Unified UI Tech Stack Decision — Mesh VPN (`v0.4.0`: Windows · macOS · Android · iOS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` (`techlead-ui`) |
| Ngày lập | 2026-11-20 |
| Phiên bản | **1.1 (Chặng 2 — Unified UI Gate 2, Round 2 Remediation)** |
| Nhánh làm việc | `feat/unified-ui` (tách từ `feat/desktop-gui` sau khi chốt sạch working tree) |
| Thành phần AI/SLM | **Không có** → bỏ qua mục AI/ML Stack |
| Đầu vào bắt buộc | [unified-ui-readiness-requirements.md](../01-discovery/unified-ui-readiness-requirements.md) v1.1 (`213` Glossary keys, `38` `UUI-*`) · [unified-ui-product-backlog.md](../02-product-planning/unified-ui-product-backlog.md) v1.1 (`22` Stories `US-118..US-139 = 93 SP`) · [unified-ui-gate-1-critique.md](../05-quality-assurance/critique-reviews/unified-ui-gate-1-critique.md) (`IG-UUI-G1-01..03`) |
| Kế thừa nền tảng | [desktop-gui-tech-stack-decision.md](./desktop-gui-tech-stack-decision.md) · [mobile-tech-stack-decision.md](./mobile-tech-stack-decision.md) · [coding-standards.md](./coding-standards.md) v2.2 · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Tài liệu đi kèm | [unified-ui-adr.md](./unified-ui-adr.md) (`ADR-027..031`) · [unified-ui-coding-standards.md](./unified-ui-coding-standards.md) · [unified-ui-system-architecture.md](./unified-ui-system-architecture.md) · [unified-ui-contracts-and-tokens.md](./unified-ui-contracts-and-tokens.md) |

> **Quy ước kiểm chứng:** `[V]` = đã đối chiếu trực tiếp từ file thực tế trong repo. `[N]` = thiết kế mới cho Chặng 3 (sẽ được biên dịch và kiểm chứng trên CI `$0` + máy thật).

---

## 1. Tóm tắt Quyết định Công nghệ Unified UI (`v0.4.0`)

| Tầng / Nền tảng | Quyết định chốt (`v0.4.0`) | Tham chiếu ADR |
|---|---|---|
| **Windows GUI (`crates/mesh-gui` → `MeshVPN.exe`)** | Giữ nguyên `ADR-020`: thuần `windows-sys = "0.59"` `[V]`, `unsafe_code = "forbid"` trong `crates/mesh-gui` `[V]`, **`<= 6 MiB`** (`2.43 MiB` thực tế `[V]`). Nâng cấp GDI/DWM hiện đại: dark titlebar `DwmSetWindowAttribute(20/19)`, custom-drawn Header Hero + Status Cards + Tab Bar 3 mục, Status Pills, double-buffering memory DC chống flicker, **`WS_CLIPCHILDREN`** trong `dwStyle` (không dùng `WS_EX_COMPOSITED`), `WM_CTLCOLOR*` với `BS_OWNERDRAW` cho buttons + brush cache theo theme. Thêm 2 features vào `crates/mesh-sys/Cargo.toml`: `Win32_Graphics_Dwm` + `Win32_UI_Accessibility`. Tách module mới: `theme.rs`, `i18n.rs`, `prefs.rs`, `status_view.rs`. | `ADR-027`, `ADR-028`, `ADR-029`, `ADR-030`, `ADR-031` |
| **macOS App (`desktop/macos/MeshVPNApp/`)** | Swift `6.0` `SWIFT_STRICT_CONCURRENCY = complete` `[V]`, XcodeGen `project.yml` `[V]`, macOS `13.0+` `[V]`. Giữ `Window("Mesh VPN", id: "dashboard") + MenuBarExtra` `[V]`. Hiện 3 tab xuyên suốt mọi trạng thái đã enroll. Live locale: `Locale(identifier:)` + pure `Sendable` `.lproj` bundle lookup (`MeshL10n`) + `defaultLocalization: "en"` và `resources: [.process("Resources")]` trong `MeshDesktopCore/Package.swift` `[N]`. Live theme qua `EnvironmentObject`. `PeersTableView` bổ sung `nodeId` search + count badge `[N]`. | `ADR-027`, `ADR-028`, `ADR-029`, `ADR-030`, `ADR-031` |
| **Android App (`mobile/android/`)** | `MainActivity` giữ `FragmentActivity` `[V]` (`0` `androidx.appcompat`). Kotlin `2.1.20` `[V]`, AGP `8.7.3` `[V]`, Compose BOM `2025.02.00` `[V]`, `minSdk = 26` `[V]`. 3-tab Bottom Nav (`STATUS / PEERS / SETTINGS`). Live locale: `createConfigurationContext` + `CompositionLocalProvider` + `LocaleManager` API 33+. `MeshTheme.kt` mở rộng Design Tokens Light/Dark `[N]`. Giữ nguyên 100% `testTag` cũ `[V]`. | `ADR-028`, `ADR-029`, `ADR-030`, `ADR-031` |
| **iOS App (`mobile/ios/`)** | Swift `6.0` `SWIFT_STRICT_CONCURRENCY = complete` `[V]`, iOS `15.0+` `[V]`, XcodeGen `project.yml` `[V]`. `MainTabView` 3 tabs `Status/Peers/Settings`. Live locale: `Locale(identifier:)` + pure `Sendable` `L10n.tr(_:locale:)` `.lproj` lookup + `.environment(\.locale, ...)` trên root view + `Localizable.xcstrings` `213` keys `[N]`. `StatusBadge` màu semantic token. | `ADR-028`, `ADR-029`, `ADR-030`, `ADR-031` |
| **Dependency Policy (`0` vi phạm `deny.toml`)** | Không thêm crate Rust mới ngoài danh mục hiện có. Bật thêm `Win32_Graphics_Dwm` + `Win32_UI_Accessibility` trong `crates/mesh-sys/Cargo.toml`. `0` `androidx.appcompat` trên Android. Giữ nguyên `ktlint` + `detekt` + `lintVitalRelease` Android; `SwiftLint --strict` iOS/macOS. | `ADR-027` |
| **SemVer Đồng bộ (`0.4.0`)** | `Cargo.toml` workspace `0.4.0`, `crates/*/Cargo.toml` kế thừa workspace, `desktop/macos/project.yml` `MARKETING_VERSION: "0.4.0"`, Android `versionName = "0.4.0"` / `versionCode = 40000`, iOS `project.yml` `MARKETING_VERSION: "0.4.0"`. Giữ nguyên 13 trường `AgentStatusResponse` `[V]`, `protocol_version = 1` `[V]`. | `ADR-031` |

---

## 2. Ràng buộc Kế thừa Bất biến (`[V]`)

Các ràng buộc sau **không được phá vỡ** trong `v0.4.0`:

### 2.1. Windows — Bất biến `ADR-020` (`[V]`)

1. **Binary budget**: `MeshVPN.exe <= 6 MiB` (thực tế `2.43 MiB` `[V]`). Mọi thay đổi UI phải chạy `cargo build --release --target x86_64-pc-windows-gnu` + kiểm tra kích thước trước khi merge.
2. **`unsafe_code = "forbid"`** trong `crates/mesh-gui` (`[lints] workspace = true` tại `crates/mesh-gui/Cargo.toml:10-11` `[V]`). **0 dòng `unsafe`** trong toàn bộ `crates/mesh-gui/src/*.rs`.
3. **`windows-sys = "0.59"` đã có sẵn** (`Cargo.toml` workspace `[V]`). Không thêm crate UI ngoài: `0` WebView2, `0` Tauri, `0` egui/iced/slint.
4. **Allowlist `.expose_secret()`**: 4 crate cố định (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`) — không mở rộng sang `mesh-gui` hay module UI mới (`scripts/check.{ps1,sh}` `[V]`).
5. **`OwnedGdiObj(HGDIOBJ)`** tại `crates/mesh-sys/src/gui_windows.rs:332` `[V]` — kiểu non-generic hiện có, `DeleteObject` trong `Drop`. Bổ sung `OwnedMemDc(HDC)` (`DeleteDC`) và `PaintGuard` (`EndPaint`) vào cùng file `[N]`.
6. **`linux_gui.rs`** tại `crates/mesh-gui/src/linux_gui.rs` `[V]` phải biên dịch xanh trên `x86_64-unknown-linux-musl` sau mọi thay đổi (`scripts/check.ps1 -Cross` `[V]`).

### 2.2. macOS — Bất biến `ADR-025` (`[V]`)

1. **Swift `6.0` `SWIFT_STRICT_CONCURRENCY = complete`** (`desktop/macos/project.yml:15` `[V]`), `SWIFT_TREAT_WARNINGS_AS_ERRORS = YES` (`[V]`).
2. **Non-Sandboxed, LSUIElement, `0` UIKit** (macOS `13.0+`, `arm64 + x86_64`).
3. **`MeshDesktopCore/Package.swift`**: `swift-tools-version: 6.0` `[V]`, thêm `defaultLocalization: "en"` cho i18n `[N]`.
4. **`SwiftLint --strict`** trên mọi file `.swift` mới.

### 2.3. Android — Bất biến `ADR-017` (`[V]`)

1. **`MainActivity: FragmentActivity`** (`[V]`) — tuyệt đối `0` `androidx.appcompat`.
2. **Kotlin `2.1.20`** (`libs.versions.toml:kotlin` `[V]`), AGP `8.7.3` `[V]`, Compose BOM `2025.02.00` `[V]`.
3. **`ktlint` + `detekt` + `lintVitalRelease`** bắt buộc xanh trên mọi file Kotlin mới.
4. **`testTag`** hiện có không được đổi tên hay xóa (bảo toàn `OnboardingComposeUiTest.kt` ở locale `en` — `IG-UUI-G1-03`).
5. **`FLAG_SECURE`** chỉ bật cho màn hình hiển thị bí mật `SEC-01` (Onboarding, SPKI reveal), **không** bật ở tab Peers để tránh màn đen khi Copy IP/FQDN.

### 2.4. iOS — Bất biến `ADR-018` (`[V]`)

1. **Swift `6.0` `SWIFT_STRICT_CONCURRENCY = complete`** (`mobile/ios/project.yml:12` `[V]`), `SWIFT_TREAT_WARNINGS_AS_ERRORS = YES` (`[V]`).
2. **iOS `15.0+`** (`mobile/ios/project.yml:5` `[V]`).
3. **`SwiftLint --strict`** (`mobile/ios/.swiftlint.yml` `[V]`).
4. **`Localizable.xcstrings`** (`mobile/ios/MeshApp/Resources/Localizable.xcstrings` `[V]`) — mở rộng lên `213` keys `[N]`.

### 2.5. Bảo mật Bất biến (`SEC-01`, `SEC-05`, `OPS-01`)

1. **`SEC-05`**: Khi `ErrorKind::Unauthenticated`, chỉ trả `"authentication failed"` — không bao giờ dịch hay đa ngữ hóa chuỗi lỗi wire protocol này.
2. **`OPS-01`**: Log JSON (`ts` UTC, `level`, `component`, `event`) luôn bằng **tiếng Anh**, bất kể locale người dùng.
3. **Clipboard**: 30s wipe (`ClipboardSecretGuard` Windows / `ClipboardAutoClear` macOS / `ClipboardAccess` Android/iOS) **chỉ** cho `mpk_*`, `mesh://join?...`, SPKI Pin reveal. Copy IP/FQDN = simple copy + toast, `0` `FLAG_SECURE`.
4. **`AgentStatusResponse` 13 trường** `[V]` — `#[serde(deny_unknown_fields)]` không được đổi/thêm field.

---

## 3. Ma trận Quyết định Công nghệ UI (`v0.4.0`)

### 3.1. Windows: GDI/DWM Hiện đại vs Các phương án khác

| Tiêu chí | Trọng số | **Win32 GDI/DWM Thuần [CHỌN]** | WinRT/XAML Islands | WebView2 |
|---|---:|---|---|---|
| Giữ `unsafe_code = "forbid"` trong `mesh-gui` | 30 | **5/5** — Toàn bộ FFI trong `mesh-sys` | **2/5** — WinRT COM cần `unsafe` trong layer bọc | **1/5** — WebView2 COM `unsafe` |
| Binary `<= 6 MiB` | 25 | **5/5** — Dùng GDI object đã có, không kéo crate mới | **3/5** — XAML Islands kéo thêm COM/WinRT | **1/5** — Kéo WebView2 Runtime |
| Không thêm crate ngoài `deny.toml` | 25 | **5/5** — Chỉ bật feature `windows-sys` đã có | **2/5** — Cần crate WinRT wrapper | **1/5** — Cần `webview2-com` |
| DWM dark titlebar + High Contrast + DPI | 20 | **5/5** — `DwmSetWindowAttribute`, `SPI_GETHIGHCONTRAST`, `WM_DPICHANGED` trực tiếp | **4/5** — Hỗ trợ tốt nhưng phức tạp hơn | **3/5** — Hạn chế hơn |
| **Tổng** | 100 | **100/100** | 55/100 | 30/100 |

**Quyết định**: Win32 GDI/DWM thuần — không thay đổi stack `ADR-020`, chỉ thêm 2 features mới trong `crates/mesh-sys/Cargo.toml`.

### 3.2. i18n: Cơ chế Live Locale theo Nền tảng (`*(KN)*` Gate 2)

| Nền tảng | Cơ chế chọn | Lý do / Ràng buộc |
|---|---|---|
| **Windows** | Static `&'static [(&'static str, &'static str)]` table trong RAM (module `i18n.rs`), load lúc khởi động, store key `LocaleMode` vào `%LOCALAPPDATA%\MeshVPN\ui-prefs.json` | `0` crate ngoài, không cần file `.resx`, xanh trên MSVC + MinGW; không restart daemon |
| **macOS** | `defaultLocalization: "en"` và `resources: [.process("Resources")]` trong `Package.swift` `[N]` + pure `Sendable` `MeshL10n` helper đọc `.lproj` bundle (`Bundle(path:)`) + `.environment(\.locale, Locale(identifier: localeId))` trên `ContentView`. **Cấm** `Locale("vi")` (lỗi compile API cũ); dùng `Locale(identifier: "vi")`. `Bundle.module` chỉ `internal` — `MeshVPNApp` gọi qua `MeshL10n` public API. | Swift 6 `Sendable` safe, `0` phụ thuộc ngoài; switch locale không restart |
| **Android** | `createConfigurationContext(config)` tạo `Context` với `Locale` target, dùng `CompositionLocalProvider(LocalContext provides ctx)` trong Compose; trên API 33+: `LocaleManager.setApplicationLocales()` bổ sung. Map dot→underscore (`tab.status` → `R.string.tab_status`) đồng bộ cả `values/strings.xml` và `values-vi/strings.xml` tránh `ExtraTranslation` lint. `LocaleHelper.wrapActivityContext()` bọc qua `ContextWrapper` tránh `ClassCastException`. | `0` `androidx.appcompat`; giữ `FragmentActivity`; locale áp dụng tức thì trong UI Compose không restart daemon |
| **iOS** | `Localizable.xcstrings` 213 dot-keys đúng §4.1 (`tab.*` không phải `nav.*`) + `.environment(\.locale, Locale(identifier: localeId))` trên root view + `L10n.tr(_:locale:)` pure `Sendable` `.lproj` lookup. **Cấm** `Locale("vi")` (compile error iOS 15.0); dùng `Locale(identifier: "vi")`. | Extend 13 → 213 keys; `0` phụ thuộc ngoài; `SwiftLint --strict` |

**Bảo toàn `IG-UUI-G1-03`**: `OnboardingComposeUiTest.kt` giữ nguyên chạy ở locale `en` mặc định; test locale `vi` được viết thành file mới riêng biệt.

### 3.3. Design Tokens: Bảng Màu Chính thức (`DEC-UI-03`)

#### Surface & Background Tokens

| Token | Light Mode | Dark Mode | Dùng cho |
|---|---|---|---|
| `surface.background` | `#F8FAFC` | `#0F172A` | App background chính |
| `surface.card` | `#FFFFFF` | `#1E293B` | Card / panel fill |
| `surface.border` | `#CBD5E1` | `#334155` | Dividers, viền card |
| `surface.text.primary` | `#0F172A` | `#F1F5F9` | Văn bản chính |
| `surface.text.secondary` | `#475569` | `#94A3B8` | Nhãn phụ, caption |

#### Brand Tokens

| Token | Giá trị | Dùng cho |
|---|---|---|
| `brand.cobalt` | `#0B57D0` | CTA button, Tab active, accent (light) |
| `brand.sky` | `#60A5FA` | CTA button, accent (dark) |
| `brand.teal` | `#0D9488` | Secondary action, Connected accent (light) |
| `brand.teal.light` | `#2DD4BF` | Connected accent (dark) |

#### Semantic Tokens

| Token | Light | Dark | Dùng cho |
|---|---|---|---|
| `semantic.success` | `#16A34A` | `#4ADE80` | Connected state (Emerald 600/400) |
| `semantic.warning` | `#D97706` | `#FBBF24` | Connecting, Degraded, **ReauthRequired** (Amber 600/400) |
| `semantic.error` | `#DC2626` | `#F87171` | Revoked, Error, destructive (Red 600/400) |
| `semantic.neutral` | `#6B7280` | `#9CA3AF` | Offline, Unavailable (Slate 500/400) |

> `[V]` Windows `icons.rs:35-38` hiện dùng `[22,163,74]` = `#16A34A`, `[217,119,6]` = `#D97706`, `[220,38,38]` = `#DC2626`, `[107,114,128]` = `#6B7280` — khớp hoàn toàn bảng Semantic trên.
> `semantic.warning = #D97706` (Light) là màu Amber chuẩn cho **ReauthRequired** trên cả Windows lẫn macOS (thay thế `.red` hiện tại trên macOS — `HR-UUI-G1-03` đã đóng).

### 3.4. Clipboard Security Boundary (`SEC-01` vs Copy IP/FQDN)

| Dữ liệu | Cơ chế | FLAG_SECURE | 30s Wipe | Nền tảng |
|---|---|---|---|---|
| `mpk_*` (Pre-Auth Key) | `ClipboardSecretGuard` / `ClipboardAutoClear` | ✅ | ✅ | Win/macOS/Android/iOS |
| `mesh://join?...` URI | `ClipboardSecretGuard` / `ClipboardAutoClear` | ✅ | ✅ | Win/macOS/Android/iOS |
| SPKI Pin reveal | `ClipboardSecretGuard` / `ClipboardAutoClear` | ✅ | ✅ | Win/macOS/Android/iOS |
| Overlay IP (`100.64.x.x`) | Simple copy + toast | ❌ | ❌ | Win/macOS/Android/iOS |
| FQDN (`*.mesh.internal`) | Simple copy + toast | ❌ | ❌ | Win/macOS/Android/iOS |

---

## 4. Ngưỡng Nghiệm thu (`v0.4.0` — Áp dụng cho Chặng 3)

### 4.1. Nghiệm thu Tự động CI (`$0`)

| Hạng mục | Lệnh kiểm định | Ngưỡng PASS |
|---|---|---|
| Rust format | `cargo fmt --all -- --check` | `exit 0` |
| Rust lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | `0` warning |
| Rust test | `cargo test --workspace --all-features` | `100%` xanh |
| Deny | `cargo deny check advisories bans licenses sources` | `0` violation |
| Cross-build | `scripts/check.ps1 -Cross` / `scripts/check.sh --cross` | `exit 0` trên `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-gnu` |
| `linux_gui.rs` | Included trong cross-build | Compile xanh |
| Binary size | `MeshVPN.exe` release | `<= 6 MiB` |
| GDI leak | `GetGuiResources(hProcess, GR_GDIOBJECTS)` delta | `== 0` sau chu trình mở/đóng theme/tab |
| Glossary parity | Script kiểm 213 keys `vi`/`en` | `213/213` |
| Clipboard boundary | Unit test `test_clipboard_no_flag_secure_on_ip_copy` | PASS |
| `OnboardingComposeUiTest.kt` | `./gradlew connectedAndroidTest` locale `en` | Giữ nguyên PASS |
| Android ktlint | `./gradlew ktlintCheck` | `0` error |
| Android detekt | `./gradlew detekt` | `0` error |
| Android lintVital | `./gradlew lintVitalRelease` | `0` error |
| macOS Swift | `xcodebuild test -scheme MeshVPNApp CODE_SIGNING_ALLOWED=NO` + `SwiftLint --strict` | `0` error/warning |
| iOS Swift | `xcodebuild test -scheme MeshApp CODE_SIGNING_ALLOWED=NO` + `SwiftLint --strict` | `0` error/warning |

### 4.2. Nghiệm thu Thủ công Máy thật (`hardware_signoff_required`)

| Hạng mục | Tiêu chí |
|---|---|
| DPI `125%`/`150%`/`200%` Windows | Custom-drawn cards/pills/tab không vỡ layout |
| Dark/Light toggle Windows | Titlebar + toàn bộ custom-drawn surface đổi ngay không cần restart |
| High Contrast Windows | `WM_SETTINGCHANGE` + `WM_THEMECHANGED` cập nhật brush cache |
| Tab 3 mục xuyên suốt states | Tab bar hiện khi `Connecting`/`ReauthRequired`/`Revoked`/`Error` (đã enroll) |
| Live locale `vi`/`en` | Đổi trong Settings → UI đổi tức thì, daemon không restart |
| `ReauthRequired` màu Amber | Win + macOS + Android + iOS đều hiện Amber `#D97706` (Light) / `#FBBF24` (Dark) |
| Copy IP/FQDN | Paste được ngay không cần xóa clipboard; toast xuất hiện |
| `Rotate Key` modal | Mở từ Zone 3 / CTA Zone 1 — không mất trên mọi state đã enroll |

---

## 5. Phân loại Work Packages Chặng 3 (`v0.4.0` — Tham chiếu từ `unified-ui-sprint-backlog.md`)

> Bảng này đồng bộ 100% với `docs/04-sprint-management/unified-ui-sprint-backlog.md` v1.1 (`sm-ui`). Toán học SP (không double-count, mỗi Story tính 1 lần ở WP Lead): **16 Must = 75 SP, 4 Should = 12 SP, 2 Could = 6 SP → Tổng 22 Stories = 93 SP**.

| Wave | WP | Nội dung | Stories (Lead) | SP | File Overlap Risk |
|---|---|---|---|---:|---|
| **Wave U-A** (Tuần tự) | WP-U-A0 | Foundation: SemVer `0.4.0`, thêm `Win32_Graphics_Dwm`+`Win32_UI_Accessibility` vào `crates/mesh-sys/Cargo.toml`, skeleton `theme.rs`/`i18n.rs`/`prefs.rs`/`status_view.rs` | — (Foundation prep) | **0** | `0%` |
| **Wave U-B** (Song song) | WP-U-B1 | Windows: GDI/DWM dark titlebar, Tab 3 mục, `status_view.rs`, `BS_OWNERDRAW` buttons, brush cache | US-118(8), US-120(5), US-121(3), US-122(8), US-123(3), US-126(3) | **30** | `0%` (chỉ `crates/mesh-gui` + `crates/mesh-sys`) |
| | WP-U-B2 | macOS: 3 tab xuyên suốt enrolled states, `PeersTableView` nodeId search + count badge | US-124(5) | **5** | `0%` (chỉ `desktop/macos/`) |
| | WP-U-B3 | Android: 3-tab Bottom Nav, `PeersScreen`, `MeshTheme.kt` tokens | US-119(5) | **5** | `0%` (chỉ `mobile/android/`) |
| | WP-U-B4 | iOS: `MainTabView` 3 tabs, `PeersView`, `StatusBadge` tokens | — (Contributor) | **0** | `0%` (chỉ `mobile/ios/`) |
| **Wave U-C** (Song song) | WP-U-C1 | Windows i18n: `i18n.rs` 213 keys, `prefs.rs` `ui-prefs.json`, nối `i18n::t` vào `window/status_view/peers_view/onboarding/tray` | US-127(5), US-125(3) | **8** | `0%` (chỉ `crates/mesh-gui/src/*`) |
| | WP-U-C2 | macOS i18n: `Package.swift` `defaultLocalization`+`resources`, `MeshL10n`, `.lproj` 213 keys, nối vào `MeshVPNApp` & `MeshDesktopCore` | US-128(5) | **5** | `0%` (chỉ `desktop/macos/`) |
| | WP-U-C3 | Android i18n: `LocaleHelper.kt` (`ContextWrapper`), `values/strings.xml`+`values-vi/strings.xml`, `OnboardingComposeUiTestVi.kt` | US-129(5) | **5** | `0%` (chỉ `mobile/android/`) |
| | WP-U-C4 | iOS i18n: `Localizable.xcstrings` 213 keys, `L10n.tr(_:locale:)` (`Bundle.main`) | US-130(3) | **3** | `0%` (chỉ `mobile/ios/`) |
| **Wave U-D** (Tuần tự) | WP-U-D0 | Cross-platform Parity, Polish & Accessibility: `213`-key parity, `display_label`, SemVer `0.4.0` verify, GDI 0-leak test, high contrast/reduced motion, tablet 2-col, screen reader/keyboard nav | US-131(5), US-132(2), US-135(5), US-136(3), US-137(3), US-138(3), US-139(3) | **24** | `0%` (tuần tự sau Wave U-C) |
| **Wave U-E** (Tuần tự) | WP-U-E0 | Regression & Security Audit: `OnboardingComposeUiTest.kt` (`en`), `test_no_secrets_in_outputs`, `SEC-01`/`SEC-05`/`OPS-01` invariants, QA sign-off | US-133(5), US-134(3) | **8** | `0%` (tuần tự sau Wave U-D) |
| **Tổng** | **11 WPs** | **22/22 Stories (`US-118..US-139`)** | **16 Must (75) + 4 Should (12) + 2 Could (6)** | **93** | **`0%` trong mọi Wave** |

**Kiểm toán SP**: `WP-U-A0(0) + WP-U-B1(8+5+3+8+3+3=30) + WP-U-B2(5) + WP-U-B3(5) + WP-U-B4(0) + WP-U-C1(5+3=8) + WP-U-C2(5) + WP-U-C3(5) + WP-U-C4(3) + WP-U-D0(5+2+5+3+3+3+3=24) + WP-U-E0(5+3=8) = 93 SP` ✓ (`16 Must = 75 SP`, `4 Should = 12 SP`, `2 Could = 6 SP`).

---

*Tài liệu này là Nguồn Chân lý cho quyết định stack của `v0.4.0`. Mọi thay đổi phải được `agile-tech-lead` phê duyệt và phản ánh vào `unified-ui-adr.md`.*
