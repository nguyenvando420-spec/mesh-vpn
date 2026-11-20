# Unified UI Coding Standards — Mesh VPN (`v0.4.0`: Windows · macOS · Android · iOS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` (`techlead-ui`) |
| Ngày lập | 2026-11-20 |
| Phiên bản | **1.1 (Chặng 2 — Unified UI Gate 2, Round 2 Remediation)** |
| Nhánh làm việc | `feat/unified-ui` |
| Áp dụng cho | `agile-developer`, `agile-qa`, `agile-devops` (Wave A, B1–B4, C, D, E Chặng 3) |
| Kế thừa bắt buộc | [coding-standards.md](./coding-standards.md) v2.2 · [desktop-gui-coding-standards.md](./desktop-gui-coding-standards.md) v1.0 · [mobile-coding-standards.md](./mobile-coding-standards.md) v1.1 · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Tài liệu thiết kế đi kèm | [unified-ui-tech-stack-decision.md](./unified-ui-tech-stack-decision.md) · [unified-ui-adr.md](./unified-ui-adr.md) (`ADR-027..031`) · [unified-ui-system-architecture.md](./unified-ui-system-architecture.md) · [unified-ui-contracts-and-tokens.md](./unified-ui-contracts-and-tokens.md) |

> **Nguyên tắc tối thượng:** Mọi quy tắc trong [coding-standards.md](./coding-standards.md), [desktop-gui-coding-standards.md](./desktop-gui-coding-standards.md) và [mobile-coding-standards.md](./mobile-coding-standards.md) giữ nguyên **100% hiệu lực**. Tài liệu này bổ sung quy chuẩn bắt buộc riêng cho **Unified UI `v0.4.0`** (`ADR-027..031`): GDI/DWM hiện đại, module tách rõ, i18n 213 keys, Design Tokens, Clipboard boundary, SemVer đồng bộ.

---

## 0. File Hygiene (Bất biến)

| Quy tắc | Phạm vi | Công cụ |
|---|---|---|
| **Ngôn ngữ code** | Biến, hàm, struct, comment, log, test name, commit: **100% tiếng Anh** | Review |
| **UTF-8 không BOM** | 100% tệp (`.rs`, `.toml`, `.md`, `.kt`, `.kts`, `.xml`, `.swift`, `.yml`, `.json`, `.xcstrings`) | `scripts/check.{ps1,sh}` |
| **LF (`\n`) 100%** | Mọi tệp nguồn trừ `*.ps1`, `*.bat`, `*.cmd` (CRLF) | `.editorconfig` + `scripts/check.{ps1,sh}` |

---

## 1. Quy chuẩn Rust Mở rộng (`crates/mesh-gui`, `crates/mesh-sys`, `v0.4.0`)

### 1.1. Module Mới `crates/mesh-gui/src/` (`ADR-028`)

Tách module để tránh `window.rs` phình (1,656 dòng `[V]`) và cho phép Wave B1-B4 chạy song song `0% File Overlap`:

| File | Nội dung | Quy tắc bổ sung |
|---|---|---|
| `theme.rs` | `ThemeMode { System, Light, Dark }`, `UiThemePalette { bg, card, border, text_primary, text_secondary, cobalt, teal, success, warning, error, neutral }`, brush cache `BTreeMap<u32, OwnedGdiObj>`, `WM_SETTINGCHANGE`/`WM_THEMECHANGED` handler | Brush cache phải `clear()` khi theme đổi; `0` leak kiểm qua `GetGuiResources` |
| `i18n.rs` | `LocaleMode { System, Vi, En }`, `static EN_STRINGS`, `static VI_STRINGS` (213 cặp), `fn t(key: &'static str) -> &'static str`, `fn set_locale(mode: LocaleMode)` | Cấm dùng `i18n::t()` cho `SEC-05`/`OPS-01`; test `test_i18n_all_213_keys_present_vi_and_en` |
| `prefs.rs` | `UiPrefs { theme: ThemeMode, locale: LocaleMode }`, `fn load_prefs() -> UiPrefs`, `fn save_prefs(prefs: &UiPrefs) -> AppResult<()>` | Atomic write qua `UnprivilegedSinkWriter` hoặc temp-sibling; fallback `UiPrefs::default()` khi corrupt |
| `status_view.rs` | Zone 1 painting: Header Hero, State pill, CTA buttons, `display_label(TunnelSubState)` badge | `0 unsafe`; paint qua memory DC (`OwnedMemDc`) |
| `window.rs` | Message loop orchestration, `WM_*` dispatch, layout (giữ ngắn `< 500 dòng` sau tách) | Ủy quyền painting sang `status_view.rs`/`peers_view.rs`/`diagnostics_view.rs` |

**Tuyệt đối không tạo các file tên `util.rs`, `common.rs`, `helpers.rs`.**

### 1.2. RAII Win32 Mới trong `crates/mesh-sys/src/gui_windows.rs` (`ADR-027`)

Thêm 2 structs kế bên `OwnedGdiObj(HGDIOBJ)` tại dòng 332 `[V]`:

```rust
/// RAII guard deleting a memory DC (`CreateCompatibleDC`) on drop.
/// Do NOT use for DCs from `BeginPaint` (use `PaintGuard`) or `GetDC` (use `ReleaseDC`).
/// API public: chỉ dùng `isize` (không expose `HDC`/`HWND` từ `windows-sys`).
pub struct OwnedMemDc(isize);  // isize wraps HDC; mesh-gui không phụ thuộc windows-sys

impl OwnedMemDc {
    #[must_use]
    pub fn from_compatible(hdc_ref: isize) -> Option<Self> {
        // SAFETY: CreateCompatibleDC returns NULL on failure; non-NULL is a valid HDC.
        let mem_dc = unsafe { CreateCompatibleDC(hdc_ref as _) };
        if mem_dc.is_null() { None } else { Some(Self(mem_dc as isize)) }
    }
    #[must_use]
    pub const fn as_raw(&self) -> isize { self.0 }
}

impl std::fmt::Debug for OwnedMemDc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnedMemDc(0x{:x})", self.0)
    }
}

impl Drop for OwnedMemDc {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: `self.0` is a live memory DC owned exclusively by `self`.
            unsafe { DeleteDC(self.0 as _); }
        }
    }
}

/// RAII guard calling `EndPaint` on drop. Created by `PaintGuard::begin(hwnd)`.
/// API public: chỉ dùng `isize` (không expose `HWND/HDC/PAINTSTRUCT`).
pub struct PaintGuard {
    hwnd: isize,
    ps: PAINTSTRUCT,   // trong mesh-sys; không re-export ra mesh-gui
    hdc: isize,
}

impl PaintGuard {
    /// Begin painting; returns `None` if `BeginPaint` returns NULL.
    pub fn begin(hwnd: isize) -> Option<Self> {
        // PAINTSTRUCT không implement Default trong windows-sys 0.59 → zeroed()
        // SAFETY: zeroed PAINTSTRUCT là valid initial state cho BeginPaint.
        let mut ps: PAINTSTRUCT = unsafe { std::mem::zeroed() };
        // SAFETY: hwnd must be a valid, non-destroyed window handle.
        let hdc = unsafe { BeginPaint(hwnd as _, &mut ps) };
        if hdc.is_null() { None } else { Some(Self { hwnd, ps, hdc: hdc as isize }) }
    }
    #[must_use]
    pub const fn hdc(&self) -> isize { self.hdc }
}

impl std::fmt::Debug for PaintGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PaintGuard(hwnd=0x{:x}, hdc=0x{:x})", self.hwnd, self.hdc)
    }
}

impl Drop for PaintGuard {
    fn drop(&mut self) {
        // SAFETY: hwnd and ps are from the matching BeginPaint call; must call EndPaint.
        unsafe { EndPaint(self.hwnd as _, &self.ps); }
    }
}
```

**Quy tắc sử dụng bắt buộc:**

1. `OwnedGdiObj(HGDIOBJ)`: Dùng cho `HFONT`, `HBITMAP`, `HBRUSH` tạo bởi `Create*` API. Phải gọi `SelectObject(dc, old_obj)` **trước** khi `OwnedGdiObj` drop (`DeleteObject`).
2. `OwnedMemDc(HDC)`: Dùng cho DC tạo bởi `CreateCompatibleDC`. Không dùng cho DC từ `BeginPaint` hay `GetDC`.
3. `PaintGuard`: Dùng cho DC từ `BeginPaint` trong `WM_PAINT`. Không gọi `EndPaint` thủ công.
4. Mẫu double-buffering chuẩn:
   ```rust
   // Trong WM_PAINT handler (crates/mesh-sys, 0 unsafe trong mesh-gui):
   if let Some(guard) = PaintGuard::begin(hwnd) {
       if let Some(mem_dc) = OwnedMemDc::from_compatible(guard.hdc()) {
           if let Some(bmp) = OwnedGdiObj::from_raw(create_compatible_bitmap(...)) {
               let old_bmp = unsafe { SelectObject(mem_dc.as_raw(), bmp.as_raw()) };
               // Vẽ vào mem_dc ...
               unsafe { BitBlt(guard.hdc(), 0, 0, w, h, mem_dc.as_raw(), 0, 0, SRCCOPY) };
               // Phải trả stock object TRƯỚC khi bmp drop:
               unsafe { SelectObject(mem_dc.as_raw(), old_bmp) };
               // bmp drop -> DeleteObject; mem_dc drop -> DeleteDC; guard drop -> EndPaint
           }
       }
   }
   ```

### 1.3. Safe Wrappers DWM/Theme trong `crates/mesh-sys/src/gui_windows.rs` (`ADR-027`)

```rust
/// Apply or remove dark titlebar via DwmSetWindowAttribute.
/// Tries DWMWA_USE_IMMERSIVE_DARK_MODE = 20 first, falls back to 19 on old Win10.
pub fn apply_window_dark_titlebar(hwnd: isize, dark: bool);
// hwnd: isize; DWMWA_USE_IMMERSIVE_DARK_MODE cast as u32 (20), fallback 19_u32 on Win10 < 19041.
// Không expose HWND/HDC/RECT ra ngoài mesh-sys — mesh-gui không phụ thuộc windows-sys.

/// Read HKCU\...\Personalize\AppsUseLightTheme (REG_DWORD) via Win32_System_Registry.
/// Returns true (light) if key absent or unreadable.
pub fn read_windows_apps_use_light_theme() -> bool;

/// Query SPI_GETHIGHCONTRAST: uiParam = size_of::<HIGHCONTRASTW>() as u32,
/// hc.cbSize = same value trước khi gọi; (hc.dwFlags & HCF_HIGHCONTRASTON) != 0.
pub fn detect_high_contrast() -> bool;

/// Read HKCU\Control Panel\International\LocaleName; returns true if starts_with("vi").
pub fn detect_windows_system_locale_is_vi() -> bool;

/// InvalidateRect(hwnd, NULL, TRUE) + UpdateWindow. hwnd: isize.
pub fn invalidate_window(hwnd: isize);

/// Reuse set_focus_control(ctrl: isize) hiện có — không tạo hàm mới.
```

**Cấm tuyệt đối:**
- `ShouldAppsUseDarkMode()` — API ẩn, không chính thức.
- `DestroyFont()` — hàm không tồn tại; dùng `DeleteObject` qua `OwnedGdiObj`.
- `IAccessible` trong `windows-sys 0.59` — không tồn tại; dùng `SetWindowTextW` label proxy + `NotifyWinEvent`.
- Export `HWND`/`HDC`/`RECT` ra ngoài `crates/mesh-sys` — dùng `isize`/`ControlRect`/`&OwnedGdiObj`.
- `WS_EX_CLIPCHILDREN` trong `dwExStyle` — không tồn tại trong `windows-sys 0.59`; dùng **`WS_CLIPCHILDREN`** trong `dwStyle` (`WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN`).
- `BS_PUSHBUTTON` cho Dark Mode buttons — dùng **`BS_OWNERDRAW` + `WM_DRAWITEM`** cho CTA/Tab buttons.

### 1.4. `DesktopUiState::display_label(TunnelSubState)` (`ADR-030`, `app.rs`)

- Hàm `label(self) -> &'static str` hiện tại (`app.rs:42-52` `[V]`) giữ nguyên — bảo toàn test cũ.
- Thêm `display_label(self, sub: TunnelSubState) -> &'static str` trả chuỗi chính xác phân biệt theo `TunnelSubState` (xem ADR-030 §Decision 2).
- Phủ bởi unit test: `test_display_label_disconnected_not_connected` và `test_display_label_all_states`.

### 1.5. Module `i18n.rs` — 213 Keys (`ADR-029`)

```rust
// crates/mesh-gui/src/i18n.rs
// Gắn #[cfg(any(target_os = "windows", target_os = "linux"))] trong main.rs cho mod i18n
// để cross-clippy x86_64-unknown-linux-musl sạch 100%.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocaleMode { System = 0, En = 1, Vi = 2 }

// Pure fn không race khi chạy test song song (không AtomicU8 mutable global):
pub(crate) fn t(key: &'static str) -> &'static str {
    t_for(key, current_locale())
}

pub(crate) fn t_for(key: &'static str, locale: LocaleMode) -> &'static str {
    lookup(key, locale)  // lookup trong VI_STRINGS / EN_STRINGS với fallback sang EN
}

pub(crate) fn set_locale(mode: LocaleMode) { /* lưu vào prefs + notify UI */ }
pub(crate) fn current_locale() -> LocaleMode { /* đọc từ prefs */ }

// static EN_STRINGS: &[(&str, &str)] = &[ ... 213 cặp ... ];
// static VI_STRINGS: &[(&str, &str)] = &[ ... 213 cặp ... ];
```

**Quy tắc:**
- **Cấm** dùng `i18n::t()` cho: `SEC-05` `"authentication failed"`, log JSON `OPS-01`, tên trường IPC, chuỗi wire protocol.
- Mọi chuỗi UI hiển thị (labels, tooltips, placeholders, toast, error messages UI) phải đi qua `i18n::t("canonical.key")`.
- Key phải có trong Canonical Glossary Discovery v1.1 §4.1 (213 keys). Không tự thêm key mới ngoài danh mục mà không cập nhật Discovery.

### 1.6. Module `prefs.rs` — `UiPrefs` Atomic Write (`ADR-031`)

```rust
// crates/mesh-gui/src/prefs.rs
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct UiPrefs {
    pub theme: ThemeMode,
    pub locale: LocaleMode,
}

impl Default for UiPrefs {
    fn default() -> Self { Self { theme: ThemeMode::System, locale: LocaleMode::System } }
}

pub(crate) fn load_prefs() -> UiPrefs { /* đọc %LOCALAPPDATA%\MeshVPN\ui-prefs.json */ }
pub(crate) fn save_prefs(prefs: &UiPrefs) -> AppResult<()> { /* atomic write temp-sibling */ }
```

- Fallback `UiPrefs::default()` khi file không tồn tại, corrupt, hoặc lỗi permission.
- Atomic write: ghi vào `ui-prefs.json.tmp` → `fsync` → rename. Không dùng `std::fs::write` trực tiếp.
- `0` UAC/`root` cho đọc/ghi prefs.

---

## 2. Quy chuẩn macOS Swift (`desktop/macos/`, `ADR-027..031`)

### 2.1. Bất biến Kế thừa (`ADR-025`)

Giữ nguyên 100%: Swift `6.0`, `SWIFT_STRICT_CONCURRENCY = complete`, `SWIFT_TREAT_WARNINGS_AS_ERRORS = YES`, `LSUIElement`, Non-Sandboxed, `SwiftLint --strict`.

### 2.2. `MeshDesktopCore/Package.swift` — `defaultLocalization: "en"` (`ADR-029`)

```swift
// swift-tools-version: 6.0
let package = Package(
    name: "MeshDesktopCore",
    defaultLocalization: "en",   // BẮT BUỘC thêm
    platforms: [.macOS(.v13)],
    targets: [
        .target(
            name: "MeshDesktopCore",
            resources: [.process("Resources")],  // BẮT BUỘC → sinh Bundle.module
        ),
    ]
)
```
// Bundle.module chỉ `internal` — `MeshVPNApp` gọi qua `MeshL10n` public pure `Sendable` API.

**Các file `.lproj` cần tạo (trong `MeshDesktopCore/Sources/MeshDesktopCore/Resources/`):**
- `en.lproj/Localizable.strings` (213 keys)
- `vi.lproj/Localizable.strings` (213 keys)

### 2.3. Live Locale (`ADR-029`)

```swift
// MeshVPNApp/Sources/MeshApp.swift hoặc root WindowGroup
@main struct MeshVPNApp: App {
    @StateObject private var appState = AppState()
    var body: some Scene {
        WindowGroup("Mesh VPN", id: "dashboard") {
            ContentView()
                .environmentObject(appState)
                .environment(\.locale, appState.resolvedLocale)
        }
        MenuBarExtra { MenuBarContent().environment(\.locale, appState.resolvedLocale) }
            label: { Image(systemName: appState.menuBarIcon) }
    }
}
// resolvedLocale: { .system → Locale.current
//                  .vi    → Locale(identifier: "vi")   // CẤM Locale("vi") — không khả dụng macOS SDK
//                  .en    → Locale(identifier: "en") }
```

Không dùng `Bundle.main` cho string trong `MeshDesktopCore` — phải dùng `Bundle.module`.

### 2.4. 3-Tab Xuyên suốt (`ADR-028`)

```swift
// DashboardWindowView.swift — mở rộng từ Segmented Picker 2 tab hiện có
// Hiện: hiện tab ở .connected [V]. Mới: hiện tab ở mọi state khi enrolled.
@State private var selectedTab: DashboardTab = .status
enum DashboardTab: String, CaseIterable { case status, peers, settings }

// Điều kiện hiện Tab Bar:
var body: some View {
    if appState.isEnrolled {
        VStack(spacing: 0) {
            HeaderHeroView()
            Picker("Tab", selection: $selectedTab) {
                ForEach(DashboardTab.allCases, id: \.self) { tab in
                    Text(tab.localizedTitle).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            tabContent(for: selectedTab)
        }
    } else {
        OnboardingSheetView()
    }
}
```

### 2.5. `ReauthRequired` Amber Unification (`ADR-030`)

Sửa `DesktopUiState.swift`: `reauthRequired` → tint Amber (`Color(hex: "#D97706")` light / `Color(hex: "#FBBF24")` dark), không dùng `.red`.

### 2.6. Naming & Lint macOS

- File, type, function: `PascalCase` cho types, `camelCase` cho properties/methods — tuân thủ Swift API Guidelines.
- `SwiftLint --strict`: 0 warning được phép.
- Tên test: `test_<unit>_<scenario>_<expected>` (lowercase với underscores).

---

## 3. Quy chuẩn Android Kotlin (`mobile/android/`, `ADR-028..031`)

### 3.1. Bất biến Kế thừa (`ADR-017`)

Giữ nguyên 100%: `MainActivity: FragmentActivity` (`0` `androidx.appcompat`), Kotlin `2.1.20`, AGP `8.7.3`, Compose BOM `2025.02.00`, `minSdk = 26`, `ktlint` + `detekt` + `lintVitalRelease`.

### 3.2. Live Locale (`ADR-029`)

```kotlin
// LocaleHelper.kt (file mới)
object LocaleHelper {
    fun buildLocalizedContext(base: Context, mode: LocaleMode): Context {
        val locale = when (mode) {
            LocaleMode.SYSTEM -> ConfigurationCompat.getLocales(base.resources.configuration)[0]
                ?: Locale.getDefault()
            LocaleMode.VI -> Locale("vi")
            LocaleMode.EN -> Locale.ENGLISH
        }
        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        return base.createConfigurationContext(config)
    }

    fun wrapActivityContext(activity: FragmentActivity, mode: LocaleMode): Context {
        val localizedConfigContext = buildLocalizedContext(activity, mode)
        // Bọc qua ContextWrapper(activity) để giữ FragmentActivity base cho BiometricPrompt
        // và delegate getResources() sang localizedConfigContext.resources (tránh ClassCastException)
        return object : ContextWrapper(activity) {
            override fun getResources() = localizedConfigContext.resources
        }
    }
}

// Trong root Composable (MeshApp.kt hoặc MainActivity):
@Composable fun MeshApp(activity: FragmentActivity, viewModel: MeshMainViewModel = viewModel()) {
    val localeMode by viewModel.localeMode.collectAsStateWithLifecycle()
    val localizedCtx = remember(activity, localeMode) {
        LocaleHelper.wrapActivityContext(activity, localeMode)
    }
    CompositionLocalProvider(LocalContext provides localizedCtx) {
        MeshTheme(darkTheme = viewModel.isDarkTheme) {
            MainNavigation(viewModel)
        }
    }
}
```

### 3.3. `testTag` Bất biến (`IG-UUI-G1-03`)

**TUYỆT ĐỐI không xóa, đổi tên hay di chuyển** các `testTag` hiện có (đã verify trong `OnboardingComposeUiTest.kt`). Mọi UI element mới thêm `testTag` mới không trùng.

Test locale `vi` → tạo **`OnboardingComposeUiTestVi.kt`** file mới riêng biệt. Không sửa `OnboardingComposeUiTest.kt`.

### 3.4. `isAdminPinsRevealed = false` khi `SETTINGS → PEERS` (`MED-UUI-G1-03`)

```kotlin
// MeshMainViewModel.kt
fun onTabSelected(tab: MainTab) {
    if (_currentTab.value == MainTab.SETTINGS && tab == MainTab.PEERS) {
        _isAdminPinsRevealed.value = false
    }
    _currentTab.value = tab
}
```

Unit test: `test_admin_pins_reset_when_navigating_from_settings_to_peers`.

### 3.5. `MeshTheme.kt` Tokens (`ADR-030`)

```kotlin
// MeshTheme.kt — Design Token constants
object MeshTokens {
    // Light
    val SurfaceBackground = Color(0xFFF8FAFC)
    val SurfaceCard = Color(0xFFFFFFFF)
    val SurfaceBorder = Color(0xFFCBD5E1)
    val TextPrimary = Color(0xFF0F172A)
    val TextSecondary = Color(0xFF475569)
    val BrandCobalt = Color(0xFF0B57D0)
    val BrandTeal = Color(0xFF0D9488)
    val SemanticSuccess = Color(0xFF16A34A)
    val SemanticWarning = Color(0xFFD97706)   // Amber: Connecting/Degraded/ReauthRequired
    val SemanticError = Color(0xFFDC2626)
    val SemanticNeutral = Color(0xFF6B7280)

    // Dark
    val SurfaceBackgroundDark = Color(0xFF0F172A)
    val SurfaceCardDark = Color(0xFF1E293B)
    val SurfaceBorderDark = Color(0xFF334155)
    val TextPrimaryDark = Color(0xFFF1F5F9)
    val TextSecondaryDark = Color(0xFF94A3B8)
    val BrandSky = Color(0xFF60A5FA)
    val BrandTealLight = Color(0xFF2DD4BF)
    val SemanticSuccessDark = Color(0xFF4ADE80)
    val SemanticWarningDark = Color(0xFFFBBF24)
    val SemanticErrorDark = Color(0xFFF87171)
    val SemanticNeutralDark = Color(0xFF9CA3AF)
}
```

### 3.6. Lint Android (`ADR-027..031`)

- `ktlint`: 0 violation, chạy `./gradlew ktlintCheck`.
- `detekt`: 0 error, chạy `./gradlew detekt`.
- `lintVitalRelease`: 0 error, chạy `./gradlew lintVitalRelease`.
- Mọi file `.kt` mới phải pass cả 3 trước khi merge.

---

## 4. Quy chuẩn iOS Swift (`mobile/ios/`, `ADR-028..031`)

### 4.1. Bất biến Kế thừa (`ADR-018`)

Giữ nguyên 100%: Swift `6.0`, `SWIFT_STRICT_CONCURRENCY = complete`, `iOS 15.0+`, `SwiftLint --strict`.

### 4.2. `Localizable.xcstrings` Mở rộng (`ADR-029`)

Mở rộng `mobile/ios/MeshApp/Resources/Localizable.xcstrings` từ 13 → **213** `vi` translations. Chỉ dùng đúng dot-keys theo Discovery v1.1 §4.1 (ví dụ `"tab.status"` thay vì `"nav.status"`, `"state.connected"` thay vì `"Connected"`). Cấu trúc:

```json
{
  "sourceLanguage": "en",
  "strings": {
    "tab.status": {
      "localizations": {
        "en": { "stringUnit": { "state": "translated", "value": "Status" } },
        "vi": { "stringUnit": { "state": "translated", "value": "Trạng thái" } }
      }
    }
    // ... 212 entries còn lại theo Canonical Glossary §4.1
  },
  "version": "1.0"
}
```

### 4.3. Live Locale (`ADR-029`)

```swift
// MeshApp.swift (iOS) hoặc root ContentView
@main struct MeshApp: App {
    @StateObject private var appViewModel = AppViewModel()
    var body: some Scene {
        WindowGroup {
            MainTabView()
                .environmentObject(appViewModel)
                .environment(\.locale, appViewModel.resolvedLocale)
        }
    }
}
// resolvedLocale: { .system → Locale.current
//                  .vi    → Locale(identifier: "vi")   // CẤM Locale("vi") — lỗi compile iOS 15.0
//                  .en    → Locale(identifier: "en") }
// Dùng L10n.tr(_:locale:) pure Sendable .lproj lookup (không String(localized:) + .environment)
```

### 4.4. `MainTabView` 3 Tabs (`ADR-028`)

```swift
// MainTabView.swift (mới)
struct MainTabView: View {
    @EnvironmentObject var viewModel: AppViewModel
    var body: some View {
        TabView(selection: $viewModel.selectedTab) {
            StatusView().tabItem {
                Label(L10n.tr("tab.status", locale: viewModel.locale), systemImage: "shield")
            }.tag(AppTab.status)
            PeersView().tabItem {
                Label(L10n.tr("tab.peers", locale: viewModel.locale), systemImage: "person.2")
            }.tag(AppTab.peers)
            SettingsView().tabItem {
                Label(L10n.tr("tab.settings", locale: viewModel.locale), systemImage: "gear")
            }.tag(AppTab.settings)
        }
    }
}
```

### 4.5. Naming & Lint iOS

- `SwiftLint --strict` (`mobile/ios/.swiftlint.yml` `[V]`): 0 warning.
- File mới: `PascalCase.swift`.
- `@testable import MeshApp` trong test targets; test names: `test_<unit>_<scenario>_<expected>`.

---

## 5. Quy chuẩn Test Thống nhất 4 Nền tảng

### 5.1. Rust (`crates/mesh-gui`)

| Test | Mô tả |
|---|---|
| `test_i18n_all_213_keys_present_vi_and_en` | 213 keys hiện diện đủ trong cả `VI_STRINGS` và `EN_STRINGS` |
| `test_display_label_disconnected_not_connected` | `Connected.display_label(TunnelSubState::Disconnected)` trả `"Disconnected"`, không phải `"Connected"` |
| `test_display_label_all_states` | Mọi `(DesktopUiState, TunnelSubState)` combo trả chuỗi hợp lệ, không rỗng |
| `test_clipboard_no_flag_secure_on_ip_copy` | Copy Overlay IP không kích hoạt `FLAG_SECURE` hay 30s wipe |
| `test_gdi_no_leak_after_paint_cycle` | `GetGuiResources(GR_GDIOBJECTS)` delta == 0 sau paint cycle |
| `test_prefs_fallback_on_corrupt_file` | `load_prefs()` trả `UiPrefs::default()` khi file corrupt |
| `test_tab_bar_visible_in_all_enrolled_states` | Tab bar hiện khi `enrolled == true` cho mọi `DesktopUiState` |

### 5.2. macOS (XCTest trong `MeshVPNAppTests/`)

| Test | Mô tả |
|---|---|
| `testTabBarAppearsInAllEnrolledStates` | Tab bar 3 mục visible khi `appState.isEnrolled == true` |
| `testReauthRequiredColorIsAmber` | `reauthRequired` state → Amber tint (không phải `.red`) |
| `testLocaleViTranslations` | Sample keys có translation `vi` chính xác |

### 5.3. Android (Compose UI Tests)

| Test | Mô tả |
|---|---|
| `OnboardingComposeUiTest.kt` (giữ nguyên) | Chạy ở locale `en`, giữ assert `"Verify Control Server Identity"` `[V]` |
| `OnboardingComposeUiTestVi.kt` (mới) | Test locale `vi`: chuỗi `vi` tương ứng |
| `MeshMainViewModelTest.kt` (mở rộng) | `test_admin_pins_reset_when_navigating_from_settings_to_peers` |
| `LocaleHelperTest.kt` (mới) | `createConfigurationContext` trả đúng locale |

### 5.4. iOS (XCTest trong `MeshVPNTests/`)

| Test | Mô tả |
|---|---|
| `TunnelLifecycleAndAppViewModelTests.swift` (mở rộng) | Tab selection, locale switch không crash |
| `LocalizationParityTests.swift` (mới) | 213 keys có `en` và `vi` translations trong `Localizable.xcstrings` |

---

## 6. Bộ Lệnh Kiểm định Chuẩn (Standard Check Commands) — Bắt buộc 100% xanh trước khi bàn giao

### 6.1. Rust (Windows/Linux/macOS)

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
# Bao gồm: static checks, fmt, clippy -D warnings, test, cargo deny, cross-build
```

```sh
# Linux/macOS
sh scripts/check.sh
# Bao gồm: static checks, fmt, clippy -D warnings, test, cargo deny, --cross targets
```

**Yêu cầu bổ sung `v0.4.0`:**
- `linux_gui.rs` phải biên dịch xanh trên `x86_64-unknown-linux-musl` (đã có trong `--cross` `[V]`).
- Binary size check: `MeshVPN.exe` release `<= 6 MiB`.

### 6.2. macOS

```sh
# XcodeGen + build + SwiftLint + test
xcodegen generate --spec desktop/macos/project.yml
xcodebuild -project desktop/macos/MeshVPNApp.xcodeproj \
  -scheme MeshVPNApp test -destination "platform=macOS" CODE_SIGNING_ALLOWED=NO
swiftlint lint --strict desktop/macos/MeshVPNApp/Sources
swiftlint lint --strict desktop/macos/MeshDesktopCore/Sources
```

### 6.3. Android

```sh
# Từ thư mục mobile/android/
./gradlew ktlintCheck
./gradlew detekt
./gradlew lintVitalRelease
./gradlew testDebugUnitTest
./gradlew connectedAndroidTest   # cần emulator/device; locale=en mặc định
```

### 6.4. iOS

```sh
# XcodeGen + build + SwiftLint + test (Simulator)
xcodegen generate --spec mobile/ios/project.yml
xcodebuild -project mobile/ios/MeshApp.xcodeproj \
  -scheme MeshApp test \
  -destination "platform=iOS Simulator,name=iPhone 16" CODE_SIGNING_ALLOWED=NO
swiftlint lint --strict mobile/ios/MeshApp/Sources
```

---

## 7. Git & Commit Conventions

Giữ nguyên Conventional Commits: `type(scope): subject` (`<= 72 chars`), type: `feat`/`fix`/`refactor`/`test`/`docs`/`chore`/`ci`.

**Scope `v0.4.0`:**

| Scope | Áp dụng cho |
|---|---|
| `win-theme` | `crates/mesh-gui/src/theme.rs`, `crates/mesh-sys/src/gui_windows.rs` GDI/DWM |
| `win-i18n` | `crates/mesh-gui/src/i18n.rs`, `crates/mesh-gui/src/prefs.rs` |
| `win-nav` | `crates/mesh-gui/src/window.rs`, `status_view.rs`, `diagnostics_view.rs` |
| `macos-nav` | `desktop/macos/MeshVPNApp/Sources/DashboardWindowView.swift` |
| `macos-i18n` | `desktop/macos/MeshDesktopCore/Package.swift`, `.lproj` files |
| `android-nav` | `mobile/android/.../ui/` Compose screens |
| `android-i18n` | `mobile/android/.../res/values*/strings.xml`, `LocaleHelper.kt` |
| `ios-nav` | `mobile/ios/MeshApp/Sources/MainTabView.swift` |
| `ios-i18n` | `mobile/ios/MeshApp/Resources/Localizable.xcstrings` |
| `tokens` | Design token constants trên mọi nền tảng |
| `semver` | Nâng version `0.4.0` |

**Refs bắt buộc:** Mọi commit phải có `Refs: US-xxx` (story liên quan từ `US-118..US-139`).

**Ví dụ hợp lệ:**
```
feat(win-theme): add OwnedMemDc and PaintGuard RAII wrappers

Refs: US-122
```

```
feat(android-i18n): implement LocaleHelper with createConfigurationContext

Refs: US-129
```

---

*Tài liệu này là chuẩn kỹ thuật bắt buộc cho mọi developer tham gia `v0.4.0`. Mọi ngoại lệ phải được `agile-tech-lead` phê duyệt và ghi vào ADR tương ứng.*
