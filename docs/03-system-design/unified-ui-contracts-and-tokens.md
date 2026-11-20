# Hợp đồng Giao diện & Design Tokens Thống nhất — Mesh VPN (`v0.4.0`)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-architect` (`architect-ui`) |
| Ngày lập | 2026-11-20 |
| Phiên bản | **1.1 — Revision (Gate 2 — Chặng 2, Round 2 Remediation)** |
| Nhánh làm việc | `feat/unified-ui` |
| Đầu vào chuẩn tắc | [unified-ui-readiness-requirements.md](../01-discovery/unified-ui-readiness-requirements.md) v1.1 · [unified-ui-product-backlog.md](../02-product-planning/unified-ui-product-backlog.md) v1.1 · [unified-ui-gate-1-critique.md](../05-quality-assurance/critique-reviews/unified-ui-gate-1-critique.md) (`IG-UUI-G1-01..03`) |
| Tài liệu đi kèm | [unified-ui-system-architecture.md](./unified-ui-system-architecture.md) · [unified-ui-adr.md](./unified-ui-adr.md) (`ADR-027..031`, `@techlead-ui`) |

> [!IMPORTANT]
> Tài liệu này khóa cứng các **contract** (chữ ký hàm, struct, schema, giá trị hex, test-tag) giữa `crates/mesh-sys` ↔ `crates/mesh-gui` ↔ 4 nền tảng. Mọi thay đổi ranh giới/contract phải **DỪNG và báo Scrum Master** theo coding-standards.md.

---

## 1. Contract Win32 FFI (`crates/mesh-sys/src/gui_windows.rs`)

Tất cả unsafe FFI nằm trong `crates/mesh-sys/src/gui_windows.rs` (`unsafe_code = "allow"`, `undocumented_unsafe_blocks = "deny"`). `crates/mesh-gui` (`unsafe_code = "forbid"`) gọi hoàn toàn qua safe wrappers bên dưới — **0 dòng `unsafe`** ở `crates/mesh-gui`.

### 1.1. RAII GDI Handle Guards (Existing + New)

#### `OwnedGdiObj` (Existing — `gui_windows.rs:332-361` `[V]`)

```rust
/// RAII guard deleting a Win32 GDI object (`DeleteObject`) on drop.
/// Wraps: HBRUSH, HPEN, HFONT, HBITMAP.
/// MUST call `SelectObject(hdc, old_stock_object)` to restore stock object
/// BEFORE this guard drops, otherwise `DeleteObject` returns 0 → handle leak.
pub struct OwnedGdiObj(HGDIOBJ);

impl OwnedGdiObj {
    pub fn from_raw(obj: HGDIOBJ) -> Option<Self>;
    pub const fn as_raw(&self) -> HGDIOBJ;
}

impl Drop for OwnedGdiObj {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live GDI object owned exclusively by `self`.
        let _deleted = unsafe { DeleteObject(self.0) };
    }
}
```

> **Win32 has no `DestroyFont` API** — fonts are `HGDIOBJ` disposed via `DeleteObject` after `SelectObject` restoration (`IG-UUI-G1-02`).

#### `OwnedMemDc` (New)

```rust
/// RAII guard for a memory DC created via `CreateCompatibleDC`.
/// Disposed via `DeleteDC` — NOT `DeleteObject` (undefined behavior on HDC).
pub struct OwnedMemDc(isize); // wraps HDC as isize; public API uses `isize`

impl OwnedMemDc {
    /// Creates a compatible memory DC from an `isize` reference DC (`CreateCompatibleDC`).
    /// For creating both a memory DC and a sized compatible bitmap, use `create_double_buffer(hdc_ref, width, height)`.
    #[must_use]
    pub fn from_compatible(hdc_ref: isize) -> Option<Self>;

    /// Borrows the underlying raw handle as `isize`.
    #[must_use]
    pub const fn as_raw(&self) -> isize;
}

impl fmt::Debug for OwnedMemDc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OwnedMemDc").field(&self.0).finish()
    }
}

impl Drop for OwnedMemDc {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a memory DC owned exclusively by `self`.
        let _deleted = unsafe { DeleteDC(self.0) };
    }
}
```

#### `PaintGuard` (New)

```rust
/// RAII guard for `BeginPaint`/`EndPaint` lifecycle.
/// Must call `EndPaint(hwnd, &ps)` exactly once per `BeginPaint`.
pub struct PaintGuard {
    hwnd: isize,         // HWND stored as isize
    ps: PAINTSTRUCT,     // internal Win32 type
    hdc: isize,          // HDC stored as isize
}

impl PaintGuard {
    /// Calls `BeginPaint(hwnd, &mut ps)` and wraps the result.
    /// `PAINTSTRUCT` is initialized via `unsafe { mem::zeroed() }` because
    /// `windows-sys 0.59` does NOT derive `Default` or `Debug` for `PAINTSTRUCT`.
    pub fn begin(hwnd: isize) -> Option<Self>;

    /// Returns the paint DC as `isize`.
    pub const fn hdc(&self) -> isize;

    /// Returns the paint rect as `ControlRect` (crate-local type, not `RECT`).
    pub fn rect(&self) -> ControlRect;
}

impl fmt::Debug for PaintGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaintGuard").field("hwnd", &self.hwnd).finish()
    }
}

impl Drop for PaintGuard {
    fn drop(&mut self) {
        // SAFETY: matches earlier `BeginPaint` on this HWND.
        unsafe { EndPaint(self.hwnd as HWND, &self.ps) };
    }
}
```

> **v1.1 fix (`BLK-UUI-G2-01`)**: Public API exposes only `isize` / `ControlRect` / `&OwnedGdiObj`. `HWND`, `HDC`, `RECT` from `windows-sys` are **never** exported because `crates/mesh-gui/Cargo.toml` does NOT depend on `windows-sys`. Reuses existing `set_focus_control(ctrl: isize)` at `gui_windows.rs:2929` — no `set_focus_safe(hwnd: HWND)` duplicate.

### 1.2. `UiThemePalette` (New — in `crates/mesh-gui/src/theme.rs`)

> **v1.1 fix (`HR-UUI-G2-01`)**: `UiThemePalette` lives in `crates/mesh-gui/src/theme.rs` (not `gui_windows.rs`), wrapping `OwnedGdiObj` handles created via safe constructors from `gui_windows.rs`.

```rust
/// Pre-resolved palette of cached GDI handles for a given theme mode.
/// Created once per theme change; all brushes/pens/fonts owned via OwnedGdiObj.
/// Lives in `crates/mesh-gui/src/theme.rs` — `0` lines `unsafe`.
pub struct UiThemePalette {
    // Surface tokens
    pub bg_brush: OwnedGdiObj,         // surface.background
    pub card_brush: OwnedGdiObj,       // surface.card
    pub border_pen: OwnedGdiObj,       // surface.border
    pub text_primary: u32,             // COLORREF surface.text.primary
    pub text_secondary: u32,           // COLORREF surface.text.secondary

    // Brand tokens
    pub brand_primary: u32,            // COLORREF brand.cobalt (light) or brand.sky (dark)
    pub brand_teal: u32,               // COLORREF brand.teal (light) or brand.teal.light (dark)

    // Semantic tokens
    pub semantic_success: u32,         // COLORREF semantic.success
    pub semantic_warning: u32,         // COLORREF semantic.warning
    pub semantic_error: u32,           // COLORREF semantic.error
    pub semantic_neutral: u32,         // COLORREF semantic.neutral

    // Semantic brushes (for status pills, badges)
    pub success_brush: OwnedGdiObj,
    pub warning_brush: OwnedGdiObj,
    pub error_brush: OwnedGdiObj,
    pub neutral_brush: OwnedGdiObj,

    // Font handles
    pub font_headline: OwnedGdiObj,    // "Segoe UI" 20sp FW_SEMIBOLD
    pub font_body: OwnedGdiObj,        // "Segoe UI" 14sp FW_NORMAL
    pub font_caption: OwnedGdiObj,     // "Segoe UI" 12sp FW_NORMAL
    pub font_mono: OwnedGdiObj,        // "Consolas" 14sp FW_NORMAL

    // Titlebar state
    pub is_dark_titlebar: bool,
}
```

### 1.3. Safe Wrapper Functions (New)

```rust
/// Reads `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme`.
/// Returns `true` if light theme, `false` if dark theme or registry key missing.
/// Does NOT use undocumented `ShouldAppsUseDarkMode()` from uxtheme.dll.
pub fn read_windows_apps_use_light_theme() -> bool;

/// Reads `SystemParametersInfoW(SPI_GETHIGHCONTRAST)`.
/// Passes `uiParam = size_of::<HIGHCONTRASTW>() as u32` and sets
/// `hc.cbSize = size_of::<HIGHCONTRASTW>() as u32` before the call.
/// Returns `(hc.dwFlags & HCF_HIGHCONTRASTON) != 0`.
/// Requires `Win32_UI_Accessibility` feature in `crates/mesh-sys/Cargo.toml`.
pub fn detect_high_contrast() -> bool;

/// Calls `DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE as u32, &value, 4)`.
/// Uses attribute `20` (Windows 10 20H1+), fallback to `19_u32` (Windows 10 1903).
/// `DWMWA_USE_IMMERSIVE_DARK_MODE` is `i32` in `windows-sys 0.59` — cast `as u32`.
/// Requires `Win32_Graphics_Dwm` feature in `crates/mesh-sys/Cargo.toml`.
/// No-op on older Windows versions.
pub fn apply_window_dark_titlebar(hwnd: isize, is_dark: bool);

/// Calls `InvalidateRect(hwnd, null, TRUE)` + `UpdateWindow(hwnd)`.
pub fn invalidate_window(hwnd: isize);

/// Reads `HKCU\Control Panel\International\LocaleName` via `Win32_System_Registry` (already enabled).
/// Returns `true` if the system locale starts with `"vi"`.
/// Does NOT use `GetUserDefaultUILanguage` (feature `Win32_Globalization` not enabled).
pub fn detect_windows_system_locale_is_vi() -> bool;
```

### 1.4. `WindowEventHandler` Trait Extensions (New Callbacks)

```rust
pub trait WindowEventHandler {
    // ... existing 13 callbacks unchanged (all use `isize` for HWND/HDC) ...

    /// Invoked on `WM_SETTINGCHANGE` or `WM_THEMECHANGED`.
    /// Handler should re-read theme, rebuild palette, and invalidate.
    fn on_theme_changed(&self, hwnd: isize);

    /// Invoked on `WM_CTLCOLORSTATIC`, `WM_CTLCOLOREDIT`, `WM_CTLCOLORLISTBOX`.
    /// Returns `isize` (HBRUSH) for the control's background.
    /// NOTE: `WM_CTLCOLORBTN` is handled but standard `BS_PUSHBUTTON` buttons
    /// IGNORE the returned HBRUSH — CTA/Tab buttons MUST use `BS_OWNERDRAW`
    /// (`WM_DRAWITEM`) or custom-drawn surface for Dark Mode.
    fn on_ctlcolor(&self, hwnd: isize, hdc: isize, control_hwnd: isize, msg: u32) -> isize;

    /// Invoked on `WM_DPICHANGED` for DPI-aware reflow.
    fn on_dpi_changed(&self, hwnd: isize, new_dpi: u32);
}
```

### 1.5. Double-Buffer Painting Helpers (New)

```rust
/// Creates a memory DC compatible with `hdc`, selects a bitmap of `(width, height)`,
/// and returns `(OwnedMemDc, OwnedGdiObj /* bitmap */)`.
/// Caller paints onto `mem_dc.as_raw()`, then `BitBlt` to `hdc`.
pub fn create_double_buffer(hdc: isize, width: i32, height: i32)
    -> Option<(OwnedMemDc, OwnedGdiObj)>;

/// Custom-drawn rounded card: `RoundRect` with `surface.card` fill and `surface.border` outline.
pub fn draw_rounded_card(
    hdc: isize,
    rect: &ControlRect,
    radius: i32,
    palette: &UiThemePalette,
);

/// Custom-drawn status pill with semantic background color and white/dark text.
/// CTA buttons and Tab Bar MUST use `BS_OWNERDRAW` (`WM_DRAWITEM`) or custom-drawn
/// surface because Win32 `BS_PUSHBUTTON` standard buttons ignore `WM_CTLCOLORBTN`
/// HBRUSH return value (`MED-UUI-G2-01`).
pub fn draw_status_pill(
    hdc: isize,
    rect: &ControlRect,
    text: &str,
    bg_brush: &OwnedGdiObj,
    text_color: u32,
    font: &OwnedGdiObj,
);

/// Font height calculation without `MulDiv` (feature not enabled):
/// `font_height = -((point_size * dpi) + 36) / 72`
/// (matches existing `gui_windows.rs:2959` pattern).
pub fn create_font_for_dpi(face: &str, point_size: i32, weight: i32, dpi: i32) -> Option<OwnedGdiObj>;
```

### 1.6. `crates/mesh-sys/Cargo.toml` Feature Additions

```toml
[target.'cfg(windows)'.dependencies.windows-sys]
workspace = true
features = [
    # ... existing features ...
    "Win32_Graphics_Dwm",         # DwmSetWindowAttribute (ADR-027)
    "Win32_UI_Accessibility",     # SPI_GETHIGHCONTRAST (ADR-027)
]
```

### 1.7. Proof: 0 `unsafe` in `crates/mesh-gui`

| Verification | Method |
|---|---|
| `crates/mesh-gui/Cargo.toml` | `[lints] workspace = true` → `unsafe_code = "forbid"` |
| All GDI handle creation | Via `OwnedGdiObj::from_raw()`, `OwnedMemDc::from_compatible()`, `PaintGuard::begin()` in `mesh-sys` |
| All Win32 API calls | Via safe wrappers in `gui_windows.rs` (`read_windows_apps_use_light_theme`, `apply_window_dark_titlebar`, `invalidate_window`, `detect_high_contrast`, `detect_windows_system_locale_is_vi`, `draw_rounded_card`, `draw_status_pill`, `create_font_for_dpi`) |
| `WindowEventHandler` impl | Receives `isize` handles, calls only safe wrappers. Reuses existing `set_focus_control(ctrl: isize)`. |
| Compilation check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` must pass |

---

## 2. Client User Preferences Schema

### 2.1. `ThemeMode` Enum

| Platform | Type | Values | Storage |
|---|---|---|---|
| **Windows (Rust)** | `enum ThemeMode { System, Light, Dark }` | `"system"` \| `"light"` \| `"dark"` | `ui-prefs.json` field `"theme"` |
| **macOS (Swift)** | `enum ThemeMode: String, Codable { case system, light, dark }` | Same | `UserDefaults` key `"mesh_theme_mode"` |
| **Android (Kotlin)** | `enum class ThemeMode { SYSTEM, LIGHT, DARK }` | Same | `SharedPreferences("mesh_ui_prefs")` key `"mesh_theme_mode"` |
| **iOS (Swift)** | `enum ThemeMode: String, Codable { case system, light, dark }` | Same | `UserDefaults` key `"mesh_theme_mode"` |

### 2.2. `LocaleMode` Enum

| Platform | Type | Values | Storage |
|---|---|---|---|
| **Windows (Rust)** | `enum LocaleMode { System, En, Vi }` | `"system"` \| `"en"` \| `"vi"` | `ui-prefs.json` field `"locale"` |
| **macOS (Swift)** | `enum LocaleMode: String, Codable { case system, en, vi }` | Same | `UserDefaults` key `"mesh_locale_mode"` |
| **Android (Kotlin)** | `enum class LocaleMode { SYSTEM, EN, VI }` | Same | `SharedPreferences("mesh_ui_prefs")` key `"mesh_locale_mode"` |
| **iOS (Swift)** | `enum LocaleMode: String, Codable { case system, en, vi }` | Same | `UserDefaults` key `"mesh_locale_mode"` |

### 2.3. Atomic Write & Safe Parse Contract

| Concern | Windows | macOS | Android | iOS |
|---|---|---|---|---|
| **Write atomicity** | `.part` file → `sync_all()` → `MoveFileExW REPLACE_EXISTING` | `UserDefaults` (atomic by OS) | `SharedPreferences.Editor.apply()` (atomic by OS) | `UserDefaults` (atomic by OS) |
| **Parse failure** | `serde_json::from_str` error → log `tracing::warn!`, return `UiPrefs::default()` | `rawValue` init fail → `.system` | `getString` null/invalid → `SYSTEM` | `rawValue` init fail → `.system` |
| **Permission error** | `io::Error` on read/write → log `tracing::warn!`, use defaults, don't crash | N/A (always writable) | N/A (private mode) | N/A (always writable) |
| **Corrupt file** | Invalid JSON → delete file, use defaults | N/A (UserDefaults handles) | N/A | N/A |
| **Secrets** | `0` secrets in prefs (only `"system"/"light"/"dark"/"en"/"vi"`) | Same | Same | Same |
| **Elevation** | `0` UAC — `%LOCALAPPDATA%` is user-writable | `0` admin — user-space | `0` root | `0` root |

---

## 3. Design Tokens & 10-State Mapping Matrix

### 3.1. Complete Design Token Table (DEC-UI-03)

Source of truth: Discovery v1.1 §2.1. Coordinator seq #21 confirms canonical hex values.

#### Surface & Background

| Token | Light Hex | Dark Hex | COLORREF Light | COLORREF Dark | Usage |
|---|---|---|---|---|---|
| `surface.background` | `#F8FAFC` | `#0F172A` | `0x00FCFAF8` | `0x002A170F` | App background |
| `surface.card` | `#FFFFFF` | `#1E293B` | `0x00FFFFFF` | `0x003B291E` | Card / panel fill |
| `surface.border` | `#CBD5E1` | `#334155` | `0x00E1D5CB` | `0x00554133` | Dividers, outlines |
| `surface.text.primary` | `#0F172A` | `#F1F5F9` | `0x002A170F` | `0x00F9F5F1` | Primary text |
| `surface.text.secondary` | `#475569` | `#94A3B8` | `0x00695547` | `0x00B8A394` | Secondary / caption |

> **Note**: Win32 `COLORREF` is `0x00BBGGRR` (BGR byte order), so `#F8FAFC` → `0x00FCFAF8`.

#### Brand

| Token | Value | COLORREF | Usage |
|---|---|---|---|
| `brand.cobalt` | `#0B57D0` | `0x00D0570B` | Primary accent (light mode) |
| `brand.sky` | `#60A5FA` | `0x00FAA560` | Primary accent (dark mode) |
| `brand.teal` | `#0D9488` | `0x0088940D` | Connected accent (light mode) |
| `brand.teal.light` | `#2DD4BF` | `0x00BFD42D` | Connected accent (dark mode) |

#### Semantic

| Token | Light Hex | Dark Hex | COLORREF Light | COLORREF Dark | States |
|---|---|---|---|---|---|
| `semantic.success` | `#16A34A` | `#4ADE80` | `0x004AA316` | `0x0080DE4A` | Connected |
| `semantic.warning` | `#D97706` | `#FBBF24` | `0x000677D9` | `0x0024BFFB` | Connecting, Degraded, **ReauthRequired** |
| `semantic.error` | `#DC2626` | `#F87171` | `0x002626DC` | `0x007171F8` | Revoked, Error, destructive |
| `semantic.neutral` | `#6B7280` | `#9CA3AF` | `0x0080726B` | `0x00AFA39C` | Offline, unavailable |

> **ReauthRequired = Amber (`semantic.warning`)** — unified across Windows (`icons.rs:64`) and macOS (changed from `.warning` red tint `DesktopUiState.swift:338` to Amber). See `ADR-030`.

### 3.2. Android `MeshTheme.kt` Color Reconciliation

Current `MeshTheme.kt` values that need reconciliation with canonical tokens:

| Token | Current Android Value `[V]` | Canonical Value | Action |
|---|---|---|---|
| `surface.background` (light) | `0xFFF8F9FC` (`MeshTheme.kt`) | `#F8FAFC` (`0xFFF8FAFC`) | Fix `F9` → `FA` |
| `surface.background` (dark) | `0xFF111318` (`MeshTheme.kt`) | `#0F172A` (`0xFF0F172A`) | Fix `111318` → `0F172A` |
| `brand.sky` (dark accent) | `0xFFA8C7FA` (`MeshTheme.kt`) | `#60A5FA` (`0xFF60A5FA`) | Fix `A8C7FA` → `60A5FA` |
| `brand.cobalt` | `0xFF0B57D0` (`MeshTheme.kt:14`) | `#0B57D0` | ✅ Matches |

### 3.3. 10-State → Visual Mapping Matrix (Desktop)

| # | `DesktopUiState` | `TunnelSubState` | Icon Tone | Tray/Badge Color | Canonical Label (EN) | Canonical Label (VI) | Headline (EN) |
|---|---|---|---|---|---|---|---|
| 1 | `AgentUnavailable` | — | Gray | `#6B7280` | Agent Unavailable | Dịch vụ không sẵn sàng | Mesh Agent Unreachable |
| 2 | `ServiceStopped` | — | Gray | `#6B7280` | Service Stopped | Dịch vụ đã dừng | Windows Service Stopped / Not Installed |
| 3 | `NotEnrolled` | `NotEnrolled` | Gray | `#6B7280` | Not Enrolled | Chưa đăng ký | Set Up Mesh VPN |
| 4 | `Connecting` | `Connecting` | Amber | `#D97706` | Connecting | Đang kết nối | Connecting to Mesh Network... |
| 5a | `Connected` | `Connected` | Green | `#16A34A` | Connected | Đã kết nối | Connected to Mesh Network |
| 5b | `Connected` | `Degraded` | Amber | `#D97706` | Degraded | Suy giảm | Connected (Degraded: Control Stream Offline) |
| 5c | `Connected` | `Disconnected` | Gray | `#6B7280` | Disconnected | Đã ngắt kết nối | Disconnected (Enrolled — Ready to Reconnect) |
| 6 | `ReauthRequired` | `ReauthRequired` | **Amber** | **`#D97706`** | Re-auth Required | Yêu cầu xác thực lại | Node Key Expired — Re-auth Required |
| 7 | `Revoked` | `Revoked` | Red | `#DC2626` | Device Revoked | Thiết bị bị thu hồi | Node Revoked — Identity Reset Required |
| 8 | `ErrorRecoverable` | — | Red | `#DC2626` | Attention Required | Cần xử lý | Action Failed (Recoverable) |

**Key design decisions:**
- **State #5 (`Connected`) uses `TunnelSubState`-aware label** per Discovery v1.1 §1.1 gap note (`app.rs:281-287` `[V]`): `"Connected"` only when `TunnelSubState::Connected`, never the misleading `"Enrolled"`.
- **State #6 (`ReauthRequired`) = Amber** (`semantic.warning`), not Red — unified across Windows and macOS per `ADR-030`.

### 3.4. `DesktopUiState::display_label` — New Sub-State-Aware Method (Additive)

> **v1.1 fix (`HR-UUI-G2-01`)**: **Keep** existing `DesktopUiState::label(self) -> &'static str` at `app.rs:42-52` unchanged — it is called by `linux_gui.rs:597` and existing tests. The new `display_label` is an **additive** method, not a replacement.

```rust
impl DesktopUiState {
    /// Existing method — PRESERVED UNCHANGED for backward compat.
    /// Called by `linux_gui.rs:597` and existing tests.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        // ... existing implementation at app.rs:42-52 unchanged ...
    }

    /// NEW: Returns a concise sub-state-aware label for badges and accessibility.
    /// Uses canonical labels from Discovery v1.1 §4.1.
    #[must_use]
    pub(crate) const fn display_label(self, sub_state: TunnelSubState) -> &'static str {
        match self {
            Self::AgentUnavailable => "Agent Unavailable",
            Self::ServiceStopped => "Service Stopped",
            Self::NotEnrolled => "Not Enrolled",
            Self::Connecting => "Connecting",
            Self::Connected => match sub_state {
                TunnelSubState::Connected => "Connected",
                TunnelSubState::Degraded => "Degraded",
                TunnelSubState::Disconnected => "Disconnected",
                TunnelSubState::Connecting => "Connecting",
                TunnelSubState::NotEnrolled => "Not Enrolled",
                TunnelSubState::ReauthRequired => "Re-auth Required",
                TunnelSubState::Revoked => "Device Revoked",
            },
            Self::ReauthRequired => "Re-auth Required",
            Self::Revoked => "Device Revoked",
            Self::ErrorRecoverable => "Attention Required",
        }
    }
}
```

> **Note (`HR-UUI-G2-R2-01`)**: Every branch where `sub_state == TunnelSubState::Revoked` (including `(Self::Connected, TunnelSubState::Revoked)` / `(DaemonState::Degraded, TunnelSubState::Revoked)` / `Self::Revoked`) MUST return `"Device Revoked"` (never `"Revoked"`), and `Self::ErrorRecoverable` MUST return `"Attention Required"` (never `"Error"`), matching Discovery v1.1 §4.1 (`state.revoked`, `state.error`).
>
> **`linux_gui.rs` impact**: `linux_gui.rs:574-602` calls `ui_state.label()` — this signature is **preserved unchanged**. `display_label(sub_state)` is only called from `window.rs` / `status_view.rs` (Windows-only code). No `linux_gui.rs` changes needed. Verify via `scripts/check.ps1 -Cross`.

### 3.5. Mobile State Mapping

| Android `MobileDaemonState` | iOS Status | Canonical EN | Canonical VI | Semantic Color |
|---|---|---|---|---|
| `STOPPED` | Disconnected | Disconnected | Đã ngắt kết nối | `#6B7280` |
| `DEVICE_LOCKED` | — | Waiting for Unlock | Đang chờ mở khóa | `#6B7280` |
| `CONNECTING` | Connecting | Connecting | Đang kết nối | `#D97706` |
| `CONNECTED` | Connected | Connected | Đã kết nối | `#16A34A` |
| `DEGRADED` | Reconnecting | Degraded | Suy giảm | `#D97706` |
| `REAUTH_REQUIRED` | — | Re-auth Required | Yêu cầu xác thực lại | `#D97706` |
| `REVOKED` | — | Device Revoked | Thiết bị bị thu hồi | `#DC2626` |

> Android `StatusScreen.kt:118` currently prints raw enum `"State: ${session.daemonState.name}"` on `testTag("daemon_state_label")` — must map to canonical labels above.

### 3.6. `PeerFilterMode` — New Filter Enum (`peers_view.rs`)

> **v1.1 fix (`MED-UUI-G2-01`)**: `peers_view.rs:41-45` already filters by `node_id`. The new filter is for 4-state UI tabs.

```rust
/// Filter mode for Peers Zone 2 filter chips.
/// Keep existing `filter_peers(peers, query)` 2-param signature unchanged
/// (called by `linux_gui.rs:574`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerFilterMode {
    All,
    Online,
    Direct,
    Relay,
}

/// Filters peers by mode using `mesh_proto::AgentPeerStatus` (`crates/mesh-proto/src/agent_ipc.rs:103`).
/// Additive — does NOT replace `filter_peers(peers, query)`.
pub(crate) fn filter_peers_by_mode(
    peers: &[AgentPeerStatus],
    mode: PeerFilterMode,
) -> Vec<&AgentPeerStatus>;

/// Counts peers per mode for count badges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerFilterCounts {
    pub all: usize,
    pub online: usize,
    pub direct: usize,
    pub relay: usize,
}

pub(crate) fn count_peers_by_mode(peers: &[AgentPeerStatus]) -> PeerFilterCounts;
```

---

## 4. Clipboard Security Boundary (`SEC-01`)

### 4.1. Classification Matrix

| Data Type | Secret? | 30s Wipe | `FLAG_SECURE` (Android) | Clipboard Read-Back | Timer |
|---|---|---|---|---|---|
| `mpk_*` Pre-Auth Key | ✅ SEC-01 | ✅ | ✅ (Onboarding screen) | ✅ (seq + SHA-256 guard) | `ClipboardSecretGuard` / `TIMER_CLIPBOARD_WIPE` |
| `mesh://join?...` URI | ✅ SEC-01 | ✅ | ✅ (Onboarding screen) | ✅ | Same timer |
| SPKI Pin reveal | ✅ SEC-01 | ✅ | ✅ (Settings screen) | ✅ | Same timer |
| Overlay IP (`100.64.0.x`) | ❌ | ❌ | ❌ | ❌ | None |
| FQDN (`*.mesh.internal`) | ❌ | ❌ | ❌ | ❌ | None |

### 4.2. Copy IP/FQDN Contract Per Platform

| Platform | Copy Mechanism | Toast | `FLAG_SECURE` | Wipe Timer |
|---|---|---|---|---|
| **Windows** | `OpenClipboard` → `EmptyClipboard` → `SetClipboardData(CF_UNICODETEXT)` | Win32 balloon notification or in-app toast | N/A | ❌ NOT shared with `ClipboardSecretGuard` |
| **macOS** | `NSPasteboard.general.setString()` (existing `copyToPasteboard()` in `PeersTableView.swift:161-166,220-224` `[V]`) | SwiftUI toast overlay | N/A | ❌ No `clipboardWipeDelaySeconds` for IP/FQDN |
| **Android** | `ClipboardManager.setPrimaryClip(ClipData.newPlainText(...))` | `Toast.makeText(...)` / Snackbar | ❌ (would blackout Peers tab) | ❌ No background clipboard read-back (blocked on Android 10+) |
| **iOS** | `UIPasteboard.general.string = ...` | SwiftUI toast overlay | N/A | ❌ No paste banner trigger (iOS 16+), no scrub-on-dispose |

---

## 5. Test Contract Invariants

### 5.1. Android `testTag` Preservation (100% Immutable)

The following `testTag` values MUST NOT be renamed or removed:

| `testTag` | File | Line `[V]` | Context |
|---|---|---|---|
| `"daemon_state_label"` | `StatusScreen.kt` | `:120` | State text display |
| `"toggle_tunnel_button"` | `StatusScreen.kt` | `:147` | Connect/Disconnect button |
| `"error_card"` | `StatusScreen.kt` | `:287` | Error state card |
| `"warning_lockdown"` | `StatusScreen.kt` | `:167` | Lockdown warning banner |
| `"warning_private_dns"` | `StatusScreen.kt` | `:177` | Private DNS warning banner |
| `"manual_endpoint_input"` | `OnboardingScreen.kt` | UI test | Manual onboarding endpoint field |
| `"manual_pin_input"` | `OnboardingScreen.kt` | UI test | Manual onboarding SPKI pin field |
| `"manual_preauth_input"` | `OnboardingScreen.kt` | UI test | Manual onboarding pre-auth key field |
| `"manual_submit_button"` | `OnboardingScreen.kt` | UI test | Manual onboarding submit button |
| `"confirm_join_button"` | `OnboardingScreen.kt` | UI test | Enrollment confirmation button |

**New `testTag` values** (may be added, never conflict with above):

| `testTag` | File | Context |
|---|---|---|
| `"peers_filter_all"` | `PeersScreen.kt` | Filter chip: All |
| `"peers_filter_online"` | `PeersScreen.kt` | Filter chip: Online |
| `"peers_filter_direct"` | `PeersScreen.kt` | Filter chip: Direct |
| `"peers_filter_relay"` | `PeersScreen.kt` | Filter chip: Relay |
| `"peers_search_field"` | `PeersScreen.kt` | Peer search input |
| `"peers_copy_ip_button"` | `PeersScreen.kt` | Copy Overlay IP button |
| `"peers_copy_fqdn_button"` | `PeersScreen.kt` | Copy FQDN button |
| `"theme_selector"` | `SettingsScreen.kt` | Theme mode selector |
| `"locale_selector"` | `SettingsScreen.kt` | Language mode selector |

### 5.2. `OnboardingComposeUiTest.kt` EN-Default Rule (`IG-UUI-G1-03`)

- **`OnboardingComposeUiTest.kt:68-78` `[V]`** asserts `onNodeWithText("Verify Control Server Identity").assertIsDisplayed()` — this is a **direct UI text assertion**, not a `testTag` check.
- Tests MUST run under default `en` locale. Existing test file is NOT modified.
- New **separate** Compose test file for `vi` locale verification:
  - Create `OnboardingComposeUiTestVi.kt` (PascalCase, NOT `_vi.kt` which violates `ktlint standard:filename`) at `mobile/android/app/src/androidTest/kotlin/dev/meshvpn/android/OnboardingComposeUiTestVi.kt` that sets locale to `vi` and asserts `onNodeWithText("Xác minh danh tính máy chủ điều khiển").assertIsDisplayed()`.

### 5.3. Windows GDI Leak Test Contract

```rust
/// Gate criterion (ADR-020): 0 GDI handle leak after window lifecycle.
#[test]
fn test_gdi_handle_leak_zero_after_lifecycle() {
    // Arrange: record GDI handle count before
    let before = get_gui_resources_gdi_count();

    // Act: create window → switch theme → switch tabs → close window
    // (simulated via WindowEventHandler mock)

    // Assert: GDI handle count delta == 0
    let after = get_gui_resources_gdi_count();
    assert_eq!(after - before, 0, "GDI handle leak detected");
}
```

Verification method: `GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS)` before and after window create/destroy cycle. Alert threshold: > 5000 (Windows limit: 10,000 per process).

### 5.4. Glossary `213`-Key Parity Test

Each platform must verify at build/test time that its string resources cover all `213` canonical keys from Discovery v1.1 §4.1.

| Platform | Verification Method |
|---|---|
| **Windows** | Compile-time: `i18n.rs` `const EN_STRINGS: [(&str, &str); 213]` and `const VI_STRINGS: [(&str, &str); 213]` — count mismatch is a build error. `i18n::t(key)` reads current locale, `i18n::t_for(key, locale)` for unit test parallelism (no `AtomicU8` race). |
| **macOS** | Test: `XCTest` in `MeshDesktopCoreTests` checks `en.lproj/Localizable.strings` and `vi.lproj/Localizable.strings` via `MeshL10n.tr(_:locale:)` in `MeshDesktopCore`, asserting all `213` canonical keys exist and return non-empty strings in both `en` and `vi` |
| **Android** | Test: `@Test` reads `R.string.*` via reflection, asserts 213+ entries in both `values/strings.xml` and `values-vi/strings.xml` |
| **iOS** | Test: `XCTest` loads `Localizable.xcstrings`, asserts `213` keys present with non-empty `vi` translations |

### 5.5. Cross-Platform Test Suite Preservation

| Suite | Location | Must PASS | Notes |
|---|---|---|---|
| Windows 23/23 unit tests | `crates/mesh-gui/src/*.rs` + `crates/mesh-gui/tests/gui_unit_tests.rs` | ✅ 100% | `cargo test --workspace --all-features` |
| macOS `DesktopStoreTests` | `desktop/macos/MeshDesktopCore/Tests/.../DesktopStoreTests.swift` | ✅ 100% | `xcodebuild test` |
| macOS `DesktopCoreTests` | `desktop/macos/MeshDesktopCore/Tests/.../DesktopCoreTests.swift` | ✅ 100% | `xcodebuild test` |
| Android 10 unit tests | `mobile/android/app/src/test/` | ✅ 100% | `./gradlew testDebugUnitTest` |
| Android 3 instrumented tests | `mobile/android/app/src/androidTest/` | ✅ 100% | `./gradlew connectedDebugAndroidTest` |
| iOS 5 test files | `mobile/ios/MeshVPNTests/` | ✅ 100% | `xcodebuild test` |
| `scripts/check.ps1` | — | ✅ Green | fmt, clippy, test, deny |
| `scripts/check.ps1 -Cross` | — | ✅ Green | `linux_gui.rs` cross-build |

---

## 6. Glossary Key Structure (213 Keys)

The canonical glossary is defined in Discovery v1.1 §4.1. This section provides the **key naming convention** for cross-platform consistency:

### 6.1. Key Prefix Convention

| Prefix | Category | Example | Count |
|---|---|---|---|
| `action.*` | Action Buttons | `action.connect`, `action.rotate_key` | **21** |
| `biometric.*` | Biometric Prompts | `biometric.verify_identity`, `biometric.cancel` | **3** |
| `confirm.*` | Enrollment Confirmation | `confirm.enrollment`, `confirm.verify_server` | **9** |
| `diag.*` | Diagnostics & Netcheck | `diag.netcheck_title`, `diag.bugreport_export` | **12** |
| `error.*` | Error Messages | `error.clock_skew`, `error.auth_failed` | **5** |
| `generic.*` | Generic/Shared | `generic.cancel`, `generic.refresh` | **6** |
| `headline.*` | Desktop Headlines | `headline.connected`, `headline.reauth` | **10** |
| `label.*` | Diagnostic Labels | `label.overlay`, `label.blind_relay` | **3** |
| `locale.*` | Language | `locale.system`, `locale.vietnamese` | **4** |
| `notif.*` | Android Notifications | `notif.channel_vpn`, `notif.connected` | **14** |
| `onboarding.*` | Mobile Onboarding (3-tab) | `onboarding.tab.scan_qr`, `onboarding.trust_connect` | **20** |
| `onboarding.desktop.*` | Desktop Onboarding (2-tab) | `onboarding.desktop.tab.join_uri` | **8** |
| `peers.*` | Peer Filters/Badges/Search | `peers.filter.all`, `peers.copy_overlay_ip` | **13** |
| `rotation.*` | Key Rotation | `rotation.dialog_title`, `rotation.authorize` | **7** |
| `service.*` | macOS Service Lifecycle | `service.start_repair`, `service.uninstall` | **9** |
| `settings.*` | Settings Categories | `settings.server_tls`, `settings.rotate_key` | **22** |
| `state.*` | Connection States | `state.connected`, `state.degraded` | **11** |
| `tab.*` | Navigation & Tabs | `tab.status`, `tab.peers` | **4** |
| `theme.*` | Appearance & Theme | `theme.system`, `theme.dark` | **4** |
| `tray.*` | Tray Tooltips (Windows) | `tray.connected`, `tray.revoked` | **10** |
| `warn.*` | Warning Banners | `warn.lockdown`, `warn.private_dns` | **8** |
| `win.*` | Windows Service & Dialogs | `win.start_update_service`, `win.confirm_reset` | **10** |
| **Total** | **22 prefixes** | | **213** |

> **v1.1 fix (`LOW-UUI-G2-01`)**: Counts verified against Discovery v1.1 §4.1 — `21+3+9+12+5+6+10+3+4+14+20+8+13+7+9+22+11+4+4+10+8+10 = 213`. No "Misc" category — all keys belong to a named prefix. `confirm.reset` and `confirm.reset_detail` are under `confirm.*` (counted in the 9). `diag.tunnel_telemetry` etc. are under `diag.*` (counted in the 12). `label.*` keys are under `label.*` (counted in the 3).

### 6.2. `error.auth_failed` Invariant (`SEC-05`)

```
Key: error.auth_failed
EN: "authentication failed"
VI: "authentication failed"   ← INTENTIONALLY NOT TRANSLATED
```

This key is mapped to wire-level `ErrorKind::Unauthenticated` and MUST remain `"authentication failed"` in **both** `en` and `vi` locales per `SEC-05`. The UI may show a user-friendly wrapper (e.g., `"Xác thực thất bại — vui lòng kiểm tra khóa"`) but the wire message and log entry must be the English canonical form.

### 6.3. Android Dot→Underscore Key Mapping Convention

Android resource XML does not allow `.` in `<string name="...">`. Canonical dot-keys MUST be mapped 1-1 to underscore:

```
Canonical key:    tab.status          → Android resource: R.string.tab_status
Canonical key:    peers.filter.all    → Android resource: R.string.peers_filter_all
Canonical key:    onboarding.tab.scan_qr → Android resource: R.string.onboarding_tab_scan_qr
```

Both `res/values/strings.xml` (EN, default) and `res/values-vi/strings.xml` (VI) MUST contain ALL 213 keys (plus the existing 17 keys for backward compat). Adding keys only to `values-vi/` without `values/` triggers `ExtraTranslation` lint error under `warningsAsErrors = true` (`build.gradle.kts:88`).

### 6.4. iOS `Localizable.xcstrings` Migration

Current `Localizable.xcstrings` contains 13 raw English keys (`"Connected"`, `"Confirm Server"`, etc.). These MUST be migrated to canonical dot-keys from Discovery v1.1 §4.1 (e.g., `"Connected"` → `"state.connected"`). Callers in `MeshApp/Sources/*.swift` must update accordingly.

### 6.5. Swift Locale Compatibility (`iOS 15.0+`)

- **Cấm** `Locale("vi")` — unavailable on iOS 15.0 (`IPHONEOS_DEPLOYMENT_TARGET: "15.0"`), compile error.
- **Dùng** `Locale(identifier: "vi")` / `Locale(identifier: "en")`.
- **Cấm** `String(localized:)` — reads static `Locale.current`, ignores `.environment(\.locale)`.
- **Dùng** pure `Sendable` lookup: `L10n.tr(_:locale:)` reading `.lproj` bundle.

---

## Appendix A — ADR Cross-Reference (`@techlead-ui`)

This document aligns with `ADR-027..031` authored by `@techlead-ui`:

| ADR | Topic | Contract in This Doc |
|---|---|---|
| `ADR-027` | Win32 GDI/DWM Modern | §1 (OwnedGdiObj/OwnedMemDc/PaintGuard/UiThemePalette/dark titlebar) |
| `ADR-028` | 3-Zone Navigation | §3.3 State Mapping Matrix, §4 Zone Mapping |
| `ADR-029` | Live Bilingual | §6 Glossary Key Structure, §2 Preferences Schema |
| `ADR-030` | Design Tokens & Clipboard | §3 Design Token Table, §4 Clipboard Boundary |
| `ADR-031` | SemVer 0.4.0 | Architecture doc §7.2 (13-field AgentStatusResponse) |
