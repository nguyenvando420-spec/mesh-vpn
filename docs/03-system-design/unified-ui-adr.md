# Unified UI Architecture Decision Records (`ADR-027..031`) — Mesh VPN (`v0.4.0`)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` (`techlead-ui`) |
| Ngày lập | 2026-11-20 |
| Phiên bản | **1.1 (Chặng 2 — Unified UI Gate 2, Round 2 Remediation)** |
| Nhánh làm việc | `feat/unified-ui` (tách từ `feat/desktop-gui` sau khi chốt sạch working tree theo `MED-UUI-G1-01`) |
| Trạng thái chung | **Proposed-for-Gate-2** (kế thừa và nối tiếp `ADR-001..011`, `ADR-012..019`, `ADR-020..026`) |
| Quyết định Gate 1 ràng buộc | `DEC-UI-01` (3-Zone + Onboarding tách riêng) · `DEC-UI-02` (Win32 GDI/DWM hiện đại) · `DEC-UI-03` (Design Tokens) · `DEC-UI-04` (Song ngữ `vi`/`en`) |
| Chốt `*(KN)*` Gate 2 | `WM_CTLCOLOR*`/double-buffering Win32 · cơ chế live-locale · SemVer `0.4.0` |
| Giải quyết `IG-UUI-G1-01..03` | Lấy `213` keys từ Discovery v1.1 §4.1 · kiểu `OwnedGdiObj(HGDIOBJ)` tại `gui_windows.rs:332` · giữ `OnboardingComposeUiTest.kt` ở locale `en` |
| Tài liệu đi kèm | [unified-ui-tech-stack-decision.md](./unified-ui-tech-stack-decision.md) · [unified-ui-coding-standards.md](./unified-ui-coding-standards.md) · [unified-ui-system-architecture.md](./unified-ui-system-architecture.md) · [unified-ui-contracts-and-tokens.md](./unified-ui-contracts-and-tokens.md) |

---

## Mục lục (`ADR-027..031`)

| ADR | Tiêu đề | `*(KN)*` / Truy vết chính |
|---|---|---|
| [ADR-027](#adr-027) | Win32 GDI/DWM Hiện đại: Dark Titlebar, Custom-Drawn UI, Double-Buffering, RAII GDI (`OwnedMemDc`, `PaintGuard`) \& `Win32_Graphics_Dwm` / `Win32_UI_Accessibility` | `*(KN)* BLK-UUI-G1-02`, `US-122`, `US-123`, `US-125`, `US-136` |
| [ADR-028](#adr-028) | 3-Zone Navigation (`Status · Peers · Diagnostics & Settings`) Xuyên suốt \& Onboarding Tách riêng + Tương thích `linux_gui.rs` | `DEC-UI-01`, `BLK-UUI-G1-01`, `US-118`, `US-119`, `US-120`, `US-127`, `US-134` |
| [ADR-029](#adr-029) | Live Bilingual `System / vi / en` (`213` keys) Không Restart Daemon — Cơ chế theo Nền tảng | `*(KN)* BLK-UUI-G1-03`, `DEC-UI-04`, `IG-UUI-G1-03`, `US-127..131` |
| [ADR-030](#adr-030) | Design Tokens Light/Dark, `DesktopUiState::display_label(TunnelSubState)` \& Clipboard Security Boundary (`SEC-01` vs Copy IP/FQDN) | `DEC-UI-03`, `HR-UUI-G1-02`, `HR-UUI-G1-03`, `US-121`, `US-124`, `US-132` |
| [ADR-031](#adr-031) | SemVer `0.4.0` Đồng bộ Toàn Workspace (`Cargo.toml`, macOS, Android, iOS) \& Giữ nguyên 13 Trường `AgentStatusResponse` | `*(KN)* MED-UUI-G1-03`, `US-135`, `US-136` |

---

<a id="adr-027"></a>
## ADR-027 — Win32 GDI/DWM Hiện đại: Dark Titlebar, Custom-Drawn UI, Double-Buffering, RAII GDI (`*(KN)*`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt `*(KN)*` `BLK-UUI-G1-02`)
- **Ngày**: 2026-11-20

### Context

- `crates/mesh-gui` hiện có layout Tab 3 mục cơ bản nhưng chưa có dark titlebar, custom-drawn Header Hero, Status Cards bo tròn, Status Pills, Tab Bar hội tụ theo DEC-UI-01/02/03.
- **Phát hiện đã đóng `BLK-UUI-G1-02`** (Gate 1 Critique): Discovery v1.1 phân tách rõ RAII wrappers: `OwnedGdiObj(HGDIOBJ)` cho GDI objects (`DeleteObject` sau khi trả stock `SelectObject`), `OwnedMemDc(HDC)` (`DeleteDC`), `PaintGuard(HWND, PAINTSTRUCT)` (`EndPaint`) — 3 kiểu độc lập, không gộp `HDC` vào `OwnedGdiObj`.
- **`IG-UUI-G1-02`**: Kiểu `OwnedGdiObj(HGDIOBJ)` non-generic hiện có tại `crates/mesh-sys/src/gui_windows.rs:332` `[V]`, không generic `OwnedGdiObj<T>`.
- `crates/mesh-sys/Cargo.toml` hiện **chưa có** `Win32_Graphics_Dwm` và `Win32_UI_Accessibility` trong feature list `[V]`.
- `crates/mesh-gui` giữ `[lints] workspace = true` (`unsafe_code = "forbid"`) `[V]` → **0 dòng `unsafe`** trong `crates/mesh-gui/src/*.rs`.

### Options

1. **Phương án A — Mở rộng `crates/mesh-sys/src/gui_windows.rs` với RAII mới + safe wrappers GDI/DWM, bật 2 features mới trong `crates/mesh-sys/Cargo.toml` [CHỌN]**:
   - Thêm `OwnedMemDc(HDC)` và `PaintGuard(HWND, PAINTSTRUCT)` vào `gui_windows.rs` kế bên `OwnedGdiObj(HGDIOBJ)` hiện có (không generic, non-breaking).
   - Bật `"Win32_Graphics_Dwm"` và `"Win32_UI_Accessibility"` trong `[target.'cfg(windows)'.dependencies]` `windows-sys` của `crates/mesh-sys/Cargo.toml`.
   - Toàn bộ logic double-buffering, `DwmSetWindowAttribute`, `WM_CTLCOLOR*` nằm trong `crates/mesh-sys` qua safe API, `crates/mesh-gui` chỉ gọi safe function.
2. **Phương án B — Gộp `HDC` vào `OwnedGdiObj`, dùng `ShouldAppsUseDarkMode()` và `DestroyFont`**: Đã bác bỏ — `BLK-UUI-G1-02` chứng minh sai về semantics (gộp `HDC` + `HGDIOBJ` gây sai `DeleteObject`/`DeleteDC`; `ShouldAppsUseDarkMode` là API ẩn không chính thức; `DestroyFont` không tồn tại trong Win32).

### Decision

1. **Bật 2 features trong `crates/mesh-sys/Cargo.toml` (`[target.'cfg(windows)'.dependencies]`):**
   ```toml
   "Win32_Graphics_Dwm",        # DwmSetWindowAttribute dark titlebar
   "Win32_UI_Accessibility",    # NotifyWinEvent, accessibility hooks (US-139 Could)
   ```
   Giữ nguyên toàn bộ feature hiện có `[V]`. **0 crate mới**, **0 thay đổi `deny.toml`**.

2. **Thêm 2 RAII structs mới vào `crates/mesh-sys/src/gui_windows.rs` (kế bên `OwnedGdiObj` hiện có tại dòng 332 `[V]`):**
   - **`OwnedMemDc(HDC)`**: RAII guard gọi `DeleteDC` trong `Drop` (kèm `impl std::fmt::Debug`). Tạo bằng `OwnedMemDc::from_compatible(hdc_ref: isize) -> Option<OwnedMemDc>`. Dùng cho memory DC tạo bằng `CreateCompatibleDC`. **Không** dùng để bọc DC từ `BeginPaint` hay `GetDC`.
   - **`PaintGuard { hwnd: isize, ps: PAINTSTRUCT, hdc: isize }`**: RAII guard gọi `EndPaint(self.hwnd as HWND, &self.ps)` trong `Drop` (kèm `impl std::fmt::Debug`). Tạo bằng `PaintGuard::begin(hwnd: isize) -> Option<PaintGuard>` (gọi `BeginPaint` với `PAINTSTRUCT` khởi tạo bằng `unsafe { std::mem::zeroed() }`). Trả về `hdc() -> isize` cho painting.

3. **Safe wrappers DWM Dark Titlebar trong `crates/mesh-sys/src/gui_windows.rs`:**
   ```rust
   // SAFETY contract: hwnd là HWND (isize) hợp lệ và chưa bị destroy.
   // API public chỉ dùng isize / ControlRect / &OwnedGdiObj (cấm export HWND/HDC/RECT).
   pub fn apply_window_dark_titlebar(hwnd: isize, dark: bool);
   ```
   - Cast `DWMWA_USE_IMMERSIVE_DARK_MODE as u32` (kiểu `i32` trong SDK → ép `as u32`).
   - Thử attr `20_u32` trước; nếu `HRESULT` lỗi (Windows 10 `< 19041`) fallback `19_u32` và bỏ qua an toàn.
   - `0` gọi `ShouldAppsUseDarkMode()` (API ẩn, không chính thức).

4. **Đọc theme hệ thống qua registry + SPI (không dùng API ẩn):**
   ```rust
   pub fn read_windows_apps_use_light_theme() -> bool;
   // HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme (REG_DWORD)
   // Via Win32_System_Registry (đã bật); Fallback: true (light) khi key không tồn tại.

   pub fn detect_high_contrast() -> bool;
   // SystemParametersInfoW(SPI_GETHIGHCONTRAST,
   //   size_of::<HIGHCONTRASTW>() as u32,  // uiParam PHẢI = cbSize
   //   &mut hc as *mut _ as *mut c_void,
   //   0)
   // với hc.cbSize = size_of::<HIGHCONTRASTW>() as u32 trước khi gọi
   // → (hc.dwFlags & HCF_HIGHCONTRASTON) != 0

   pub fn detect_windows_system_locale_is_vi() -> bool;
   // Đọc HKCU\Control Panel\International\LocaleName (REG_SZ)
   // via Win32_System_Registry (đã bật); trả true nếu starts_with("vi")
   ```
   **Bỏ `MulDiv`** (feature `Win32_System_WindowsProgramming` chưa bật) → toán học nguyên: `-(((base_pt as i32 * dpi as i32) + 36) / 72)`.
   **Không dùng COM interface ngoài `windows-sys 0.59`** → dùng `SetWindowTextW` label proxy + `NotifyWinEvent` trong `gui_windows.rs` nội bộ.

5. **Double-Buffering Memory DC (custom-drawn surface/Header Hero/Cards/Tab Bar/Status Pills):**
   - Tạo `OwnedMemDc` từ `CreateCompatibleDC(paint_dc)`.
   - Tạo `OwnedGdiObj` từ `CreateCompatibleBitmap` (bitmap off-screen).
   - Gọi `SelectObject(mem_dc, bitmap.as_raw())` → lưu old_bmp.
   - Vẽ vào `mem_dc` → `BitBlt(paint_dc, ..., mem_dc, ...)`.
   - `SelectObject(mem_dc, old_bmp)` **trước khi** `OwnedGdiObj` drop (`DeleteObject`).
   - **`WS_CLIPCHILDREN`** trong `dwStyle` (`WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN`) trên main window để tránh repaint xung đột child controls `EDIT`/`LISTBOX` (không dùng `WS_EX_CLIPCHILDREN` — không tồn tại trong `windows-sys 0.59`).

6. **`WM_CTLCOLORSTATIC`, `WM_CTLCOLOREDIT`, `WM_CTLCOLORLISTBOX` với brush cache theo theme; Buttons dùng `BS_OWNERDRAW` (`WM_DRAWITEM`):**
   - Cache `HBRUSH` trong `UiThemePalette` (safe wrapper trong `gui_windows.rs`), tái dùng per-theme.
   - Trả về brush phù hợp theme hiện tại (light/dark/high-contrast) cho static/edit/listbox.
   - **`BS_PUSHBUTTON` bỏ qua `WM_CTLCOLORBTN` ở Dark Mode** → phải dùng `BS_OWNERDRAW` + `WM_DRAWITEM` cho CTA và Tab buttons custom-painted.
   - `WM_SETTINGCHANGE` và `WM_THEMECHANGED`: xóa cache, `InvalidateRect(hwnd, NULL, TRUE)`.

7. **`WM_DPICHANGED`**: Tính lại font (`CreateFontIndirectW` với `lfHeight = -(((base_pt * dpi as i32) + 36) / 72)`), tính lại layout, `SetWindowPos` theo `lParam` rect mới. Dùng toán học nguyên (không cần `MulDiv` — feature `Win32_System_WindowsProgramming` chưa bật).

8. **`mod i18n` gắn `#[cfg(any(target_os = "windows", target_os = "linux"))]`** trong `crates/mesh-gui/src/main.rs` để cross-clippy `x86_64-unknown-linux-musl` sạch 100%.

9. **Keyboard Tab Order (`WS_TABSTOP`)**: Các control Tab Bar, nút CTA, Peers list, Settings inputs đều có `WS_TABSTOP`. Dùng `set_focus_control(ctrl: isize)` hiện có trong `gui_windows.rs`.

### Consequences

- **(+)**: `0` crate mới, `0` thay đổi `deny.toml`, `0` `unsafe` trong `mesh-gui`, binary budget `<= 6 MiB` được bảo toàn, `linux_gui.rs` cross-build xanh.
- **(−)**: Phải implement brush cache, memory DC pattern trong `crates/mesh-sys` cẩn thận, cần test `GetGuiResources(GR_GDIOBJECTS) delta == 0` tự động.

---

<a id="adr-028"></a>
## ADR-028 — 3-Zone Navigation (`Status · Peers · Diagnostics & Settings`) Xuyên suốt \& Onboarding Tách riêng + Tương thích `linux_gui.rs`

- **Trạng thái**: Proposed-for-Gate-2 (Chốt `BLK-UUI-G1-01`)
- **Ngày**: 2026-11-20

### Context

- **`DEC-UI-01`**: 3 phân khu thống nhất (`Status`, `Peers`, `Diagnostics & Settings`) + Onboarding tách riêng. Khi đã enroll, **ẩn form Onboarding khỏi màn chính**, nhưng **giữ Tab Bar 3 mục hiển thị xuyên suốt mọi trạng thái**.
- **Phát hiện đã đóng `BLK-UUI-G1-01`** (Gate 1 Critique): Ẩn Onboarding form khi enrolled mà không tách `Rotate Node Key` và `Update Control Server/SPKI Pin` sang Zone 3 modals sẽ khóa đường cứu hộ quan trọng.
- Hiện tại trên Windows (`window.rs:77-90, 745-749` `[V]`): form Onboarding được ẩn bằng `ShowWindow` khi enrolled nhưng `Rotate Key` và `Update Server/Pin` vẫn nằm trong form Onboarding → mất khả năng truy cập.
- Hiện tại trên macOS: Tab bar chỉ hiện khi `.connected` state (`DashboardWindowView.swift:203-222` `[V]`).
- `crates/mesh-gui/src/linux_gui.rs` `[V]` gọi `app.rs`/`peers_view.rs` logic → phải biên dịch xanh trên `x86_64-unknown-linux-musl` sau mọi thay đổi.

### Options

1. **Phương án A — Tab Bar cố định 3 mục, Onboarding là modal/sheet riêng, Zone 3 chứa modals hành động nguy hiểm [CHỌN]**: Tách rõ zone, giữ đường truy cập Settings/Language/Theme và `Rotate Key`/`Update Server` ở mọi trạng thái enrolled.
2. **Phương án B — Giữ form Onboarding cũ, bổ sung nút trong tray menu**: Không nhất quán UX, trái `DEC-UI-01`, không giải quyết macOS 7/8 states.

### Decision

#### Zone Architecture (Desktop Windows & macOS)

```
┌─────────────────────────────────────────────────────────┐
│  Zone 0 (Header Hero)  — Overlay IP · State label       │
│  [CTA: Connect/Disconnect/Rotate Key if ReauthRequired] │
├──────────┬────────────┬────────────────────────────────-┤
│ Zone 1   │ Zone 2     │ Zone 3                          │
│ Status   │ Peers      │ Diagnostics & Settings          │
│          │ (Search,   │ (Theme/Language, Server,        │
│          │ Filter,    │ Identity, Netcheck, Bugreport,  │
│          │ RTT, Copy) │ Rotate Key modal*, Update Pin*) │
└──────────┴────────────┴─────────────────────────────────┘
  * Zone 3 modals: Rotate Node Key, Update Control Server/SPKI Pin
    (mở từ nút trong Zone 3, hoặc CTA trong Zone 0 khi ReauthRequired)
```

#### Mobile (Android & iOS)

```
Bottom Tab Bar: [ Status ] [ Peers ] [ Settings ]
  - Status:   Header card, State pill, Connect/Disconnect CTA
  - Peers:    Search, 4-state Filter, RTT, Copy IP/FQDN, Ping result inline
  - Settings: Theme/Language, Server/Identity, Netcheck+Bugreport
              isAdminPinsRevealed = false khi chuyển Settings→Peers
```

#### Rules bắt buộc

1. **Tab Bar 3 mục hiển thị xuyên suốt mọi trạng thái đã enroll** trên Windows và macOS:
   - Windows: `show_tab_bar()` được gọi khi `enrolled == true`, **bất kể** `DesktopUiState` (kể cả `ReauthRequired`, `Revoked`, `ErrorRecoverable`, `Connecting`, `Connected`).
   - macOS: `DashboardWindowView.swift` hiển thị `Segmented Picker` 3 tab (mở rộng từ 2 tab `Peers/DiagSettings` hiện có, thêm tab `Status`) **bất kể** `.connected` hay state khác khi enrolled.

2. **Onboarding Form** (Windows: `onboarding.rs`; macOS: `OnboardingSheetView.swift`; Android: `OnboardingScreen.kt`; iOS: `OnboardingView.swift`):
   - Hiển thị khi `!enrolled`: fullscreen/sheet.
   - **Ẩn hoàn toàn** khi `enrolled == true` → Tab Bar 3 mục lên trước.
   - Mobile Onboarding: **3 tabs** (QR Camera, Paste URI, Manual).
   - Desktop Onboarding: **2 tabs** (Join URI, Manual).

3. **`Rotate Node Key` và `Update Control Server/SPKI Pin`** di chuyển sang:
   - Zone 3 (`Diagnostics & Settings`) → modal dialog kích hoạt qua nút trong Settings section `Identity`.
   - CTA button trong Zone 0 (Header Hero) khi `DesktopUiState::ReauthRequired`.

4. **Settings (Theme/Language/Diagnostics)** mở được cả khi chưa enroll (trang Settings là Tab 3 không phụ thuộc enrolled state trên Mobile).

5. **`linux_gui.rs` cross-compilation**: Mọi API mới trong `app.rs` / `peers_view.rs` / `window.rs` phải có stub `#[cfg(not(target_os = "windows"))]` hoặc tách module rõ ràng để `x86_64-unknown-linux-musl` build xanh. Script: `scripts/check.ps1 -Cross` / `scripts/check.sh --cross`.

#### Module Tách rõ cho Windows (`crates/mesh-gui/src/`)

Để tránh `window.rs` phình (hiện `1,656` dòng `[V]`), tách module theo Chặng 3:

| Module | Trách nhiệm | Phụ thuộc |
|---|---|---|
| `theme.rs` | `ThemeMode`, `UiThemePalette`, brush cache, event `WM_SETTINGCHANGE`/`WM_THEMECHANGED` | `mesh_sys::gui_windows` |
| `i18n.rs` | `LocaleMode`, static string table 213 keys `en`/`vi`, lookup `t(key)` | `prefs.rs` |
| `prefs.rs` | `UiPrefs { theme: ThemeMode, locale: LocaleMode }`, atomic write/read `ui-prefs.json` | `mesh_core` |
| `status_view.rs` | Zone 1 painting, Header Hero, State pill, CTA buttons | `theme.rs`, `app.rs` |
| `peers_view.rs` | Zone 2 Peers list, Search, Filter, RTT, Copy (đã có `[V]`) | `theme.rs`, `i18n.rs` |
| `diagnostics_view.rs` | Zone 3 Settings, Netcheck, Bugreport, Modals | `theme.rs`, `i18n.rs` |
| `onboarding.rs` | Onboarding form 2-tab (đã có `[V]`), modal lifecycle | `theme.rs`, `i18n.rs` |
| `window.rs` | Message loop, `WM_*` dispatch, layout orchestration | Tất cả trên |

### Consequences

- **(+)**: Luôn truy cập được `Rotate Key`, `Update Server/Pin`, `Netcheck`, `Bugreport`, `Theme/Language` ở mọi trạng thái enrolled.
- **(+)**: Tách module giúp chia Work Packages song song ở Chặng 3 với `0% File Overlap`.
- **(−)**: Cần refactor `DashboardWindowView.swift` macOS (vốn chỉ bật tab khi `.connected`) và tách cụm `Rotate Key`/`Update Server` khỏi form Onboarding Windows.

---

<a id="adr-029"></a>
## ADR-029 — Live Bilingual `System / vi / en` (`213` keys) Không Restart Daemon — Cơ chế theo Nền tảng (`*(KN)*`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt `*(KN)*` `BLK-UUI-G1-03` và `DEC-UI-04`)
- **Ngày**: 2026-11-20

### Context

- **`DEC-UI-04`**: Người dùng đổi ngôn ngữ trực tiếp trong Settings (`System / Tiếng Việt / English`) không cần khởi động lại daemon; giữ wire `SEC-05` `"authentication failed"` và log `OPS-01` bằng tiếng Anh.
- **Phát hiện đã đóng `BLK-UUI-G1-03`**: Không dùng `AppCompatDelegate.setApplicationLocales()` (yêu cầu `androidx.appcompat` — crate bị cấm); không dùng `Locale.preferredLanguages` readonly trực tiếp.
- **`IG-UUI-G1-01`**: Nguồn 213 keys là Discovery v1.1 §4.1 — Canonical Glossary (không phải con số "60+ keys" ở một số đoạn Backlog còn sót).
- **`IG-UUI-G1-03`**: `OnboardingComposeUiTest.kt` giữ nguyên chạy locale `en` mặc định; test locale `vi` thêm vào **file mới riêng biệt**.

### Options (theo nền tảng)

**Windows:**
1. Static `&'static [(&'static str, &'static str)]` table trong RAM (key → translation) `[CHỌN]`: Không crate ngoài, không file `.resx`, không I/O lúc runtime UI, switch ngay tức thì trong message loop.
2. `GetUserDefaultUILanguage` / `LoadString` với `.rc` resources: Cần `embed-resource` bị cấm trong `deny.toml`.

**macOS:**
1. `MeshL10n.tr(_:locale:)` pure `Sendable` `.lproj` bundle lookup (`Bundle.module` nội bộ trong `MeshDesktopCore`) + `.environment(\.locale, Locale(identifier: id))` trên `ContentView` `[CHỌN]`: Swift 6 safe, không phụ thuộc ngoài, `defaultLocalization: "en"` và `resources: [.process("Resources")]` trong `Package.swift`.
2. `Bundle.main` với `.lproj` hardcoded: Không hỗ trợ live switch trong `MeshDesktopCore`.

**Android:**
1. `createConfigurationContext(config)` tạo `Context` với `Locale` target bọc qua `ContextWrapper(activity)` + `CompositionLocalProvider(LocalContext provides ctx)` `[CHỌN]`: Hoạt động từ API 26+, không cần `androidx.appcompat`, giữ `FragmentActivity`.
2. Bổ sung `LocaleManager.setApplicationLocales(list)` trên API 33+ song song: Áp dụng system-wide persistent preference.

**iOS:**
1. `.environment(\.locale, Locale(identifier: id))` trên root `ContentView`/`MainTabView` + tra cứu `.lproj` bundle qua `L10n.tr(_:locale:)` (`Bundle.main.path(forResource:ofType:)`) `[CHỌN]`: Swift 6 `Sendable` safe, iOS 15.0+.

### Decision

1. **Windows — Module `crates/mesh-gui/src/i18n.rs` (mới, `[N]`):**
   - Định nghĩa `LocaleMode { System, Vi, En }` và `static EN_STRINGS: &[(&str, &str)]`, `static VI_STRINGS: &[(&str, &str)]` (compile-time, 213 cặp key/value).
   - Hàm `fn t(key: &'static str) -> &'static str` và `fn t_for(key: &'static str, locale: LocaleMode) -> &'static str` (pure, không race `AtomicU8` khi chạy test song song).
   - Khi người dùng thay đổi locale trong Settings: gọi `i18n::set_locale(mode)` → `InvalidateRect` toàn bộ windows → UI re-render.
   - `SEC-05` và log `OPS-01` **không** đi qua `i18n::t()` — luôn hardcode tiếng Anh.
   - `mod i18n` gắn `#[cfg(any(target_os = "windows", target_os = "linux"))]` trong `main.rs` → cross-clippy `x86_64-unknown-linux-musl` sạch 100%.

2. **macOS — `MeshDesktopCore/Package.swift` (cập nhật `[N]`):**
   ```swift
   // swift-tools-version: 6.0
   let package = Package(
       name: "MeshDesktopCore",
       defaultLocalization: "en",   // BẮT BUỘC thêm
       platforms: [.macOS(.v13)],
       products: [ ... ],
       targets: [
           .target(
               name: "MeshDesktopCore",
               resources: [.process("Resources")],  // BẮT BUỘC thêm → sinh Bundle.module
           ),
       ]
   )
   ```
   - `Bundle.module` chỉ `internal` — `MeshVPNApp` gọi qua `MeshL10n` public pure `Sendable` struct (không gọi `Bundle.module` trực tiếp từ ngoài package).
   - `MeshVPNApp` truyền `\.locale` environment qua root View:
     ```swift
     ContentView()
         .environment(\.locale, appState.resolvedLocale)
     // resolvedLocale: { .system → Locale.current
     //                  .vi    → Locale(identifier: "vi")   // KHÔNG dùng Locale("vi")
     //                  .en    → Locale(identifier: "en") }
     ```
   - `MeshL10n.string(key:)` đọc `.lproj` bundle via `Bundle(path:)` điều khiển bởi `@EnvironmentObject`/`@ObservedObject` view state — không dựa vào `String(localized:)` + `.environment(\.locale)` (bỏ qua inject trên macOS SDK).

3. **Android — `createConfigurationContext` + `CompositionLocalProvider` + `ContextWrapper` (mới, `[N]`):**
   ```kotlin
   // LocaleHelper.kt
   object LocaleHelper {
       fun wrapActivityContext(activity: FragmentActivity, mode: LocaleMode): Context {
           val locale = when (mode) {
               LocaleMode.SYSTEM -> ConfigurationCompat.getLocales(activity.resources.configuration)[0]
                   ?: Locale.getDefault()
               LocaleMode.VI -> Locale("vi")
               LocaleMode.EN -> Locale.ENGLISH
           }
           val config = Configuration(activity.resources.configuration)
           config.setLocale(locale)
           val localizedConfigContext = activity.createConfigurationContext(config)
           // Bọc qua ContextWrapper để delegate getResources() → tránh ClassCastException
           return object : ContextWrapper(activity) {
               override fun getResources() = localizedConfigContext.resources
           }
       }
   }
   ```
   - Map dot → underscore: `tab.status` → `R.string.tab_status` đồng bộ **cả hai** `res/values/strings.xml` và `res/values-vi/strings.xml` tránh `ExtraTranslation` lint dưới `warningsAsErrors = true`.
   - `CompositionLocalProvider(LocalContext provides localizedCtx) { MainContent() }` ở root Composable.
   - API 33+: gọi thêm `getSystemService(LocaleManager::class.java).applicationLocales = ...` cho system-level persistence.
   - **Giữ nguyên `OnboardingComposeUiTest.kt`** ở locale `en` (default) — `IG-UUI-G1-03`; assertion `"Verify Control Server Identity"` không thay đổi.
   - Test locale `vi` → **`OnboardingComposeUiTestVi.kt`** file mới tại `mobile/android/app/src/androidTest/kotlin/dev/meshvpn/android/`.

4. **iOS — `Localizable.xcstrings` mở rộng lên 213 dot-keys + `L10n.tr(_:locale:)` (mới, `[N]`):**
   - Mở rộng `mobile/ios/MeshApp/Resources/Localizable.xcstrings` từ 13 → 213 `vi` translations.
   - Dùng đúng dot-keys theo Discovery v1.1 §4.1 (ví dụ `"state.connected"` thay vì `"Connected"`, `"tab.status"` thay vì `"nav.status"`).
   - **Cấm `Locale("vi")`** (compile error trên iOS 15.0) → dùng `Locale(identifier: "vi")`.
   - `L10n.tr(_:locale:)` pure `Sendable` đọc `.lproj` bundle via `Bundle(path:)` điều khiển bởi `@EnvironmentObject`.
   - Root `ContentView` hoặc `MainTabView`:
     ```swift
     body: some View {
         MainTabView()
             .environment(\.locale, Locale(identifier: appState.localeId))
     }
     // localeId: "vi" | "en" | Locale.current.identifier
     ```

5. **Bảo toàn `SEC-05` và `OPS-01` ở mọi nền tảng:**
   - Chuỗi lỗi wire protocol `"authentication failed"` → **không dịch, không tham số hóa, không đi qua `i18n::t()`**.
   - Log JSON (`ts`, `level`, `component`, `event`) → **100% tiếng Anh** bất kể locale người dùng.
   - Tên trường JSON `AgentStatusResponse` và protocol framing → **không thay đổi**.

### Consequences

- **(+)**: Đổi ngôn ngữ tức thì trong Settings, `0` restart daemon, `0` gián đoạn WireGuard tunnel.
- **(+)**: Giữ `FragmentActivity` trên Android, `0` `androidx.appcompat`.
- **(−)**: Windows cần build bảng 213 cặp compile-time; macOS cần thêm 2 file `.lproj` với 213 entries mỗi file.

---

<a id="adr-030"></a>
## ADR-030 — Design Tokens Light/Dark, `DesktopUiState::display_label(TunnelSubState)` \& Clipboard Security Boundary

- **Trạng thái**: Proposed-for-Gate-2 (Chốt `DEC-UI-03`, `HR-UUI-G1-02`, `HR-UUI-G1-03`)
- **Ngày**: 2026-11-20

### Context

- **`DEC-UI-03`**: Bảng màu thống nhất Light/Dark Slate + Cobalt/Sky + Teal + Semantic trên 4 nền tảng.
- **`HR-UUI-G1-03`**: State #5 Windows hiện trả `"Enrolled"` và khi `TunnelSubState::Disconnected` vẫn hiện `"Status: Connected"` (sai). `DesktopUiState::headline()` đã xử lý đúng (phân biệt theo `sub_state` `[V]`) nhưng cần thêm `display_label(TunnelSubState)` cho badge.
- **`HR-UUI-G1-02`**: Clipboard 30s wipe + `FLAG_SECURE` không được áp dụng cho Copy IP/FQDN (gây màn đen Android, paste banner iOS, xung đột Windows timer).
- **macOS `ReauthRequired`**: Hiện maps `.warning → .red` (`DesktopUiState.swift:338` `[V]`), phải unify sang Amber `#D97706` (Light) / `#FBBF24` (Dark) theo `semantic.warning`.

### Options

1. **Phương án A — Khóa cứng hex token trong `UiThemePalette` (Windows) / `MeshTheme.kt` (Android), `semantic.warning = Amber` xuyên suốt 4 nền tảng [CHỌN]**: Nguồn chân lý duy nhất tại Discovery v1.1 §2.1.
2. **Phương án B — Mỗi nền tảng tự định nghĩa màu riêng**: Gây lệch giữa `HR-UUI-G1-03` và sau.

### Decision

1. **Design Token Canonical Table (nguồn chân lý: Discovery v1.1 §2.1 `[V]`):**

   | Token | Light | Dark | Dùng cho |
   |---|---|---|---|
   | `surface.background` | `#F8FAFC` | `#0F172A` | App background |
   | `surface.card` | `#FFFFFF` | `#1E293B` | Card/panel |
   | `surface.border` | `#CBD5E1` | `#334155` | Divider, viền |
   | `surface.text.primary` | `#0F172A` | `#F1F5F9` | Văn bản chính |
   | `surface.text.secondary` | `#475569` | `#94A3B8` | Caption phụ |
   | `brand.cobalt` | `#0B57D0` | — | CTA (light mode) |
   | `brand.sky` | — | `#60A5FA` | CTA (dark mode) |
   | `brand.teal` | `#0D9488` | — | Secondary (light) |
   | `brand.teal.light` | — | `#2DD4BF` | Secondary (dark) |
   | `semantic.success` | `#16A34A` | `#4ADE80` | Connected |
   | `semantic.warning` | `#D97706` | `#FBBF24` | Connecting/Degraded/**ReauthRequired** |
   | `semantic.error` | `#DC2626` | `#F87171` | Revoked/Error |
   | `semantic.neutral` | `#6B7280` | `#9CA3AF` | Stopped/Unavailable |

   > Màu Windows `icons.rs:35-38` hiện match chính xác `[V]`: `[22,163,74]`=`#16A34A`, `[217,119,6]`=`#D97706`, `[220,38,38]`=`#DC2626`, `[107,114,128]`=`#6B7280`.

2. **`DesktopUiState::display_label(sub_state: TunnelSubState) -> &'static str` (mới, `[N]`):**
   ```rust
   // Trong crates/mesh-gui/src/app.rs — 0 unsafe
   impl DesktopUiState {
       pub(crate) const fn display_label(self, sub: TunnelSubState) -> &'static str {
           match self {
               Self::Connected => match sub {
                   TunnelSubState::Connected    => "Connected",
                   TunnelSubState::Degraded     => "Degraded",
                   TunnelSubState::Disconnected => "Disconnected",
                   TunnelSubState::Connecting   => "Connecting",
                   TunnelSubState::ReauthRequired => "Re-auth Required",
                   TunnelSubState::Revoked      => "Device Revoked",
                   TunnelSubState::NotEnrolled  => "Not Enrolled",
               },
               Self::AgentUnavailable  => "Agent Unavailable",
               Self::ServiceStopped    => "Service Stopped",
               Self::NotEnrolled       => "Not Enrolled",
               Self::Connecting        => "Connecting",
               Self::ReauthRequired    => "Re-auth Required",
               Self::Revoked           => "Device Revoked",
               Self::ErrorRecoverable  => "Attention Required",
           }
       }
   }
   ```
   - Lưu ý khi ánh xạ từ `(DaemonState, TunnelSubState)`: cả `(DaemonState::Disconnected, TunnelSubState::Revoked)` lẫn `(DaemonState::Degraded, TunnelSubState::Revoked)` (hay `(Self::Connected, TunnelSubState::Revoked)`) đều trả `"Device Revoked"` (khớp khóa `state.device_revoked`); nhánh lỗi có thể khôi phục trả `"Attention Required"` (khớp khóa `state.attention_required`).
   - Hàm `label(self)` hiện tại (`app.rs:42-52` `[V]`, trả `"Enrolled"` cho `Connected`) **giữ nguyên** để không phá `linux_gui.rs:597` và test cũ.
   - `display_label` dùng cho UI badge, tray tooltip mở rộng, và i18n key lookup.

3. **Thống nhất `ReauthRequired` sang Amber trên macOS:**
   - Sửa `DesktopUiState.swift`: `reauthRequired` → `MenuBarStatusGroup.warning` với **Amber** tint thay vì `.red`.
   - Cụ thể: thêm case `.reauthRequired` với SF Symbol `"key.slash"` và color `Color(hex: "#D97706")` (light) / `Color(hex: "#FBBF24")` (dark).

4. **Clipboard Security Boundary (`SEC-01`):**

   | Dữ liệu | `FLAG_SECURE` | 30s Wipe | Cơ chế |
   |---|---|---|---|
   | `mpk_*` Pre-Auth Key | ✅ | ✅ | `ClipboardSecretGuard` (Win) / `ClipboardAutoClear` (mac) / `ClipboardAccess` (mobile) |
   | `mesh://join?...` URI | ✅ | ✅ | Tương tự trên |
   | SPKI Pin reveal | ✅ | ✅ | Tương tự trên |
   | Overlay IP (`100.64.x.x`) | ❌ | ❌ | Simple copy + toast |
   | FQDN (`*.mesh.internal`) | ❌ | ❌ | Simple copy + toast |

   - **Lý do**: `FLAG_SECURE` trên tab Peers gây màn hình đen (Android), paste banner giả (iOS 16+), xung đột `ClipboardSecretGuard` timer `mpk_*` (Windows) → không áp dụng cho dữ liệu không nhạy cảm.

5. **10-State Mapping Matrix (Windows Tray / macOS Menu Bar):**

   | `DesktopUiState` | `TunnelSubState` | `display_label` | Tray Icon Tone | Semantic Token |
   |---|---|---|---|---|
   | `AgentUnavailable` | — | `"Agent Unavailable"` | Gray | `semantic.neutral` |
   | `ServiceStopped` | — | `"Service Stopped"` | Gray | `semantic.neutral` |
   | `NotEnrolled` | — | `"Not Enrolled"` | Gray | `semantic.neutral` |
   | `Connecting` | — | `"Connecting"` | Amber | `semantic.warning` |
   | `Connected` | `Connected` | `"Connected"` | Green | `semantic.success` |
   | `Connected` | `Degraded` | `"Degraded"` | Amber | `semantic.warning` |
   | `Connected` | `Disconnected` | `"Disconnected"` | Gray | `semantic.neutral` |
   | `Connected` | `Connecting` | `"Connecting"` | Amber | `semantic.warning` |
   | `ReauthRequired` | — | `"Re-auth Required"` | Amber | `semantic.warning` |
   | `Revoked` | — | `"Device Revoked"` | Red | `semantic.error` |
   | `ErrorRecoverable` | — | `"Attention Required"` | Red | `semantic.error` |

### Consequences

- **(+)**: Hệ thống màu nhất quán 4 nền tảng; `Disconnected` không bao giờ hiển thị `"Connected"`.
- **(+)**: Copy IP/FQDN hoạt động mượt mà trên Android/iOS/Windows không gây UX bug.
- **(−)**: Cần sửa `DashboardWindowView.swift` macOS cho `ReauthRequired` Amber và tạo `display_label()` mới trong `app.rs`.

---

<a id="adr-031"></a>
## ADR-031 — SemVer `0.4.0` Đồng bộ Toàn Workspace \& Giữ nguyên 13 Trường `AgentStatusResponse` (`*(KN)*`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt `*(KN)*` `MED-UUI-G1-03`)
- **Ngày**: 2026-11-20

### Context

- **`MED-UUI-G1-03`**: Đồng bộ SemVer `0.4.0` toàn workspace là điều kiện bắt buộc Gate 2.
- Hiện tại workspace ở `0.3.0` (`Cargo.toml` `[workspace.package] version` `[V]`, `desktop/macos/project.yml` `MARKETING_VERSION: "0.3.0"` `[V]`, Android `versionName = "0.3.0"` `[V]`, iOS `MARKETING_VERSION: "0.3.0"` `[V]`).
- `AgentStatusResponse` tại `crates/mesh-proto/src/agent_ipc.rs` có `#[serde(deny_unknown_fields)]` và 13 trường cố định `[V]` → không được phá vỡ tương thích `v0.1.0-rc1`.
- `protocol_version = 1` trong wire protocol giữ nguyên.

### Options

1. **Phương án A — Nâng đồng thời tất cả `0.3.0` → `0.4.0` tại Wave A trước khi bắt đầu các Wave B1-B4 [CHỌN]**: Tránh lệch version giữa các nền tảng trong quá trình thi công.
2. **Phương án B — Nâng từng nền tảng riêng**: Gây lệch, khó kiểm soát tương thích.

### Decision

1. **Nâng version tại Wave U-A (`WP-U-A0`) — danh sách đầy đủ 17 vị trí cần sửa:**

   | File | Thay đổi | Ghi chú |
   |---|---|---|
   | `Cargo.toml` | `[workspace.package] version = "0.4.0"` + **8 dòng** `[workspace.dependencies]` ở lines 40–47 | Áp cho toàn bộ crate kế thừa `version.workspace = true` |
   | `Cargo.lock` | Re-generate sau khi bump | `cargo build` tự cập nhật |
   | `crates/mesh-gui/Cargo.toml` | `version = "0.4.0"` | Hardcode hiện tại |
   | `crates/mesh-client/Cargo.toml` | `version = "0.4.0"` | Hardcode hiện tại |
   | `crates/mesh-datapath/Cargo.toml` | `version = "0.4.0"` | Hardcode hiện tại |
   | `crates/mesh-mobile-ffi/Cargo.toml` | `version = "0.4.0"` | Hardcode hiện tại |
   | `crates/mesh-net/Cargo.toml` | `version = "0.4.0"` | Hardcode hiện tại |
   | `crates/mesh-proto/Cargo.toml` | `version = "0.4.0"` | Hardcode hiện tại |
   | `crates/mesh-gui/tests/qa_desktop_security_audit.rs:689` | `assert!(... "MARKETING_VERSION: \"0.4.0\"" ...)` | Giữ test xanh |
   | `desktop/macos/project.yml` | `MARKETING_VERSION: "0.4.0"` (dòng `18` hiện `"0.3.0"` `[V]`) | XcodeGen không commit `.xcodeproj` |
   | `desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/DesktopUiState.swift:36` | `AgentDefaults.appBundleVersion = "0.4.0"` | Tránh banner mismatch macOS |
   | `mobile/ios/MeshCoreKit/Sources/MeshConstants.swift:15` | `agentVersion = "0.4.0"` | Tránh version mismatch iOS |
   | `mobile/android/app/build.gradle.kts` | `versionName = "0.4.0"` + `versionCode = 40000` (dòng `21-22` hiện `"0.3.0"` / `30000` `[V]`) | `versionCode` tăng đơn điệu |
   | `mobile/ios/project.yml` | `MARKETING_VERSION: "0.4.0"` (dòng `14` hiện `"0.3.0"` `[V]`) | XcodeGen không commit `.xcodeproj` |
   | `scripts/package-linux-deb.sh:9` | `VERSION="0.4.0"` | Script packaging |
   | `.github/workflows/release.yml:398` | Hardcode version nếu có | Giữ nguyên chuỗi `< 0.3.0` / `LegacyPre030` kiểm tương thích wire protocol cũ |
   | `Dockerfile` | Nếu có `ARG VERSION=0.3.0` hay label hardcode | Kiểm và cập nhật nếu cần |

2. **Giữ nguyên tuyệt đối 13 trường `AgentStatusResponse`:**
   ```rust
   // crates/mesh-proto/src/agent_ipc.rs — KHÔNG được thêm/xóa/đổi tên field
   #[derive(Debug, Clone, Serialize, Deserialize)]
   #[serde(deny_unknown_fields)]
   pub struct AgentStatusResponse {
       // 13 fields — xem source thực tế [V]
       // protocol_version: u16 = 1
   }
   ```
   - **Không thêm field UI-only** vào `AgentStatusResponse` (phá tương thích `v0.1.0-rc1`).
   - Mọi thông tin UI bổ sung (locale, theme, display label) **hoàn toàn phía client user-space**, không qua IPC admin socket.

3. **`ThemeMode` và `LocaleMode` lưu phía client — tên key thống nhất:**
   - Windows: `%LOCALAPPDATA%\MeshVPN\ui-prefs.json` JSON keys: `"theme"`, `"locale"` (atomic write qua temp-sibling rename).
   - macOS: `UserDefaults(suiteName: "MeshVPN")` keys: `"mesh_theme_mode"`, `"mesh_locale_mode"`.
   - Android: `SharedPreferences("mesh_ui_prefs")` keys: `"mesh_theme_mode"`, `"mesh_locale_mode"`.
   - iOS: `UserDefaults.standard` keys: `"mesh_theme_mode"`, `"mesh_locale_mode"`.
   - **`0` UAC/`root` cho đọc/ghi prefs UI** — toàn bộ trong user-space.
   - Safe parse fallback: khi file corrupt/không đọc được → `ThemeMode::System`, `LocaleMode::System` (không crash).

4. **`AgentDefaults.appBundleVersion` trong `DesktopUiState.swift` (nếu có hardcode):** Nâng lên `"0.4.0"` đồng bộ.

### Consequences

- **(+)**: Toàn bộ 4 nền tảng hiển thị `"0.4.0"` đồng nhất trong About/Settings.
- **(+)**: Giữ 100% tương thích `v0.1.0-rc1` với 13 trường `AgentStatusResponse`.
- **(−)**: Wave A phải hoàn thành trước mọi Wave B để tránh conflict SemVer trong CI.

---

## Checklist Nghiệm thu Gate 2 (`ADR-027..031`)

| ADR | Tiêu chí | Kiểm bởi |
|---|---|---|
| `ADR-027` | `Win32_Graphics_Dwm` + `Win32_UI_Accessibility` trong `crates/mesh-sys/Cargo.toml`; `OwnedMemDc` + `PaintGuard` định nghĩa; `0 unsafe` trong `mesh-gui` | `cargo clippy` + `scripts/check.ps1 -Cross` |
| `ADR-027` | `GetGuiResources(GR_GDIOBJECTS)` delta `== 0` sau chu trình mở/đóng | Unit test `test_gdi_no_leak_after_paint_cycle` |
| `ADR-028` | Tab Bar 3 mục hiện khi `enrolled == true` và `DesktopUiState != NotEnrolled/ServiceStopped/AgentUnavailable` | Unit test `test_tab_bar_visible_in_all_enrolled_states` |
| `ADR-028` | `linux_gui.rs` cross-build xanh | `cargo clippy --target x86_64-unknown-linux-musl` |
| `ADR-029` | `i18n::t("key")` trả đúng chuỗi `vi`/`en` cho tất cả 213 keys | Unit test `test_i18n_all_213_keys_present_vi_and_en` |
| `ADR-029` | `OnboardingComposeUiTest.kt` xanh ở locale `en` mặc định | `./gradlew connectedAndroidTest` |
| `ADR-030` | `display_label(TunnelSubState::Disconnected) != "Connected"` | Unit test `test_display_label_disconnected_not_connected` |
| `ADR-030` | Copy IP/FQDN: `FLAG_SECURE` không bật ở Peers tab | Unit test `test_clipboard_no_flag_secure_on_ip_copy` |
| `ADR-031` | `Cargo.toml workspace version == "0.4.0"` | `grep -r 'version = "0\.3\.0"' Cargo.toml` → `0` kết quả |
| `ADR-031` | `versionCode == 40000`, `versionName == "0.4.0"` Android | Grep `build.gradle.kts` |
| `ADR-031` | `MARKETING_VERSION == "0.4.0"` macOS + iOS | Grep `project.yml` |
