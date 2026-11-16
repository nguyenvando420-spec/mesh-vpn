# Desktop GUI Tech Stack Decision — Mesh VPN (`v0.3.0`: Windows `MeshVPN.exe` & macOS `Mesh VPN.app`)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày lập | 2026-11-17 |
| Phiên bản | **1.0 (Chặng 2 — Desktop GUI Gate 2)** |
| Nhánh làm việc | `feat/desktop-gui` (không chạm `main`, `v0.1.0-rc1` và `v0.2.0`) |
| Thành phần AI/SLM | **Không có** → bỏ qua mục AI/ML Stack |
| Đầu vào bắt buộc | [desktop-gui-readiness-requirements.md](../01-discovery/desktop-gui-readiness-requirements.md) v1.1 (`43` `DGUI-*`), [desktop-gui-product-backlog.md](../02-product-planning/desktop-gui-product-backlog.md) v1.1 (`US-100..117`, `78 SP`, `OQ-DGUI-01..03`), [desktop-gui-gate-1-critique.md](../05-quality-assurance/critique-reviews/desktop-gui-gate-1-critique.md) |
| Kế thừa nền tảng | [tech-stack-decision.md](./tech-stack-decision.md) v2.1 · [architecture-decision-record.md](./architecture-decision-record.md) (`ADR-001..011`) · [mobile-tech-stack-decision.md](./mobile-tech-stack-decision.md) (`ADR-012..019`) · [coding-standards.md](./coding-standards.md) v2.2 · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Tài liệu đi kèm | [desktop-gui-adr.md](./desktop-gui-adr.md) (`ADR-020..026`) · [desktop-gui-coding-standards.md](./desktop-gui-coding-standards.md) · [desktop-gui-system-architecture.md](./desktop-gui-system-architecture.md) · [desktop-gui-ipc-and-ui-contracts.md](./desktop-gui-ipc-and-ui-contracts.md) |

> **Quy ước kiểm chứng:** `[V]` = đã đối chiếu trực tiếp trong codebase/toolchain thực tế của repo (`Cargo.toml`, `deny.toml`, `scripts/check.{ps1,sh}`, `.github/workflows/{ci,release}.yml`, `crates/*`, `mobile/ios/MeshApp/Sources/*`). `[N]` = thiết kế chuẩn bị cho Wave D-A/B1/B2/C ở Chặng 3 (sẽ được biên dịch và kiểm chứng trên CI `$0` + máy thật).

---

## 1. Tóm tắt Quyết định Công nghệ Desktop GUI (`v0.3.0`)

| Tầng / Nền tảng | Quyết định chốt (`v0.3.0`) | Tham chiếu ADR & Gate 1 |
|---|---|---|
| **Kiến trúc Tiến trình & Launcher (`Shared`)** | Giữ **Two-Binary Split**: CLI `crates/mesh` (`mesh`/`mesh.exe`, `SUBSYSTEM:CONSOLE`) giữ 100% hành vi tự động hóa/test; bổ sung `mesh gui` và fallback 0-arg Windows Explorer chỉ kích hoạt khi thỏa đồng thời **3 điều kiện** trong `mesh_sys::process_windows::is_interactive_explorer_double_click()`. GUI chạy tách biệt ở quyền người dùng thường (`MeshVPN.exe` / `Mesh VPN.app`), không chạy dưới `SYSTEM`/`root`. | `OQ-DGUI-01/02`, `ADR-022`, `US-100`, `DGUI-UX-06` |
| **Windows Stack (`crates/mesh-gui` → `MeshVPN.exe`)** | Crate binary mới **`crates/mesh-gui`** (`[[bin]] name = "MeshVPN"`), `#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]`, **`[lints] workspace = true` (`unsafe_code = "forbid"`)**. Dùng thuần **`windows-sys = "0.59"`** (đã có sẵn trong `Cargo.toml` / `Cargo.lock` `[V]`) qua lớp bọc an toàn trong **`crates/mesh-sys`** (`gui_windows.rs`, `process_windows.rs`, `OwnedWinHandle`) cho `Shell_NotifyIconW`, `CreateWindowExW`, Common Controls v6 (`ComCtl32`), và High-DPI `PerMonitorV2` (`SetProcessDpiAwarenessContext`). **0** WebView2, **0** Electron/Tauri, **0** `embed-resource`/`winres`, **0** thay đổi `deny.toml`. Có stub `#[cfg(not(windows))]` cho non-Windows CI. | `OQ-DGUI-02` (A2), `ADR-020`, `US-103`, `DGUI-WIN-01/05` |
| **Ranh giới Bí mật & Allowlist `.expose_secret()`** | Bảo toàn nguyên vẹn allowlist **4 crate** (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`) trong `scripts/check.{ps1,sh}` `[V]`. Toàn bộ logic giải bọc `Secret<String>` phục vụ đóng gói `AgentUpRequest` / `AgentRotateKeyRequest` và truyền qua Ephemeral Handoff Pipe đặt trong **`crates/mesh-net/src/gui_handoff.rs`**; `crates/mesh-gui` chỉ cầm `Secret<String>` / `Zeroizing<String>` không gọi `.expose_secret()`. | `ADR-020`, `HR-DGUI-G1-03`, `DGUI-SEC-01` |
| **Đặc quyền & Handoff Windows (`asInvoker` + `runas`)** | `MeshVPN.exe` chạy ở **Medium Integrity (`asInvoker`)**, đọc `\\.\pipe\mesh-agent-ro` với **`0` UAC**. Mọi thao tác ghi (`up`, `down`, `set`, `rotate-key`, `reset-identity`, `cleanup`, `bugreport/stream`, cài/bật/gỡ `MeshVpnAgent`) gọi `ShellExecuteExW("runas")` (`SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`) mở worker ngắn hạn `MeshVPN.exe --elevated-worker --handoff-pipe <pipe_name>` (High Integrity). Chốt **Cơ chế A — Ephemeral Authenticated Named Pipe Handoff (`MGH1`)**: pipe `\\.\pipe\mesh-gui-handoff-<128bit_hex>` (`FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS`, SDDL `SY+BA+<CurrentUserSid>`), worker mở bằng `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED` và gửi trước Frame `0x00 WorkerHello` (`13 B`), GUI kiểm `GetNamedPipeClientProcessId == child_pid` rồi gọi `ImpersonateNamedPipeClient` (`SecurityIdentification`) → `OpenThreadToken` → `CheckTokenMembership` (`BA`/`SY`), zero-disk `mpk_*`, zeroize + cleanup `<= 100 ms` khi `ERROR_CANCELLED`. | `OQ-DGUI-03`, `ADR-021`, `US-104`, `US-105`, `DGUI-WIN-02/03/07` |
| **macOS Stack (`desktop/macos/MeshVPNApp/`)** | Quản lý bằng **`XcodeGen` (`project.yml`)** (không commit `.xcodeproj`), **Swift `6.0`** (`SWIFT_STRICT_CONCURRENCY = complete`, `SWIFT_TREAT_WARNINGS_AS_ERRORS = YES`), **macOS `13.0+`** (`arm64` + `x86_64`), AppKit `NSStatusItem` + SwiftUI **single-window** Dashboard (`applicationShouldTerminateAfterLastWindowClosed == false`, `NSApp.setActivationPolicy(.regular/.accessory)`), **`LSUIElement = YES`**, **Non-Sandboxed** (0 `com.apple.security.app-sandbox`, 0 `CFBundleURLTypes`, 0 `NSAllowsArbitraryLoads`). Sửa triệt để **3 lỗi** tái sử dụng từ `mobile/ios/MeshApp/Sources/`. Kết nối trực tiếp `/var/run/meshd/meshd-{ro,admin}.sock` (`0660 root:admin`, `gid = 80`, **0 mật khẩu** cho user `admin`); chỉ dùng `/usr/bin/osascript` (cố định, chống injection) khi cài/nâng cấp LaunchDaemon vào `/usr/local/libexec/mesh/meshd` (`root:wheel`). | `OQ-DGUI-02/03`, `ADR-025`, `US-109..113`, `DGUI-MAC-01..07` |
| **Hợp đồng IPC Mở rộng & Bugreport Streaming** | Giữ nguyên 100% schema `AgentStatusResponse` (`#[serde(deny_unknown_fields)]`) không phá CLI `v0.1.0-rc1`; đọc phiên bản qua `GET /v1/agent/version` + header `X-Mesh-Agent-Version` + `meshd --version`. Bổ sung `POST /v1/agent/bugreport/stream` (`<= 20 MiB`, chunk `64 KiB`, xóa tạm qua `Drop` guard) theo bất biến **Unprivileged Sink Write**, `POST /v1/agent/reset-identity` (`mesh reset-identity`), sửa `execute_up` giữ `bootstrap.next_pin`, và áp dụng **3 tầng timeout IPC** (`<= 1 s` / `<= 2 s` / `10–35 s`). | `ADR-023`, `ADR-024`, `US-101`, `US-107`, `US-112`, `DGUI-IPC-01..05` |
| **Cài đặt, Nâng cấp & CI Packaging (`$0`)** | Windows nhúng compile-time `option_env!("MESH_WINTUN_SHA256")`, mở handle `FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT`, bỏ qua self-copy, đóng êm Tray cũ qua `Local\MeshVpnGuiSingleInstance` + `Local\MeshVpnGuiShutdownEvent` tránh `ERROR_SHARING_VIOLATION (32)`, dọn `HKCU\...\Run` đúng user context trước `runas`. `release.yml` liệt kê tường minh `MeshVPN.exe` (bỏ glob `mesh*`); macOS ký inner → `SHA256SUMS` → outer `.app` không `--deep` (chỉ ad-hoc sign khi `codesign -v` lỗi). | `ADR-026`, `US-106`, `US-108`, `US-114..117`, `DGUI-OPS-01..05` |

---

## 2. Ràng buộc Kế thừa & Nguồn Đối chiếu Codebase (`[V]`)

Qua kiểm tra trực tiếp mã nguồn trên nhánh `feat/desktop-gui`, các hằng số, tệp cấu hình và ràng buộc hiện hành sau đây là **bất biến** và không được phá vỡ:

1. **Cargo Workspace & `deny.toml` (`[V]`):**
   - [`Cargo.toml`](../../Cargo.toml#L109) đã khai báo sẵn `windows-sys = "0.59"` trong `[workspace.dependencies]`; [`crates/mesh-sys/Cargo.toml`](../../crates/mesh-sys/Cargo.toml#L44-L59) đang dùng `windows-sys` dưới `[target.'cfg(windows)'.dependencies]`.
   - [`deny.toml`](../../deny.toml) đang chặn `aws-lc-rs`, `openssl-sys`, `native-tls`, `rusqlite`, `anyhow` (ngoài `uniffi*`), `MPL-2.0` (ngoài 8 crate `uniffi*` đã liệt kê). Việc dùng thuần `windows-sys = "0.59"` (đã có trong `Cargo.lock`) **không thêm bất kỳ crate ngoài mới nào** và giữ nguyên **0 thay đổi `deny.toml`**.
2. **Hàng rào Tĩnh `scripts/check.{ps1,sh}` (`[V]`):**
   - [`scripts/check.ps1`](../../scripts/check.ps1#L98-L114) và [`scripts/check.sh`](../../scripts/check.sh#L81-L101) cưỡng chế:
     - `unsafe` chỉ được phép nằm trong `crates/mesh-sys/*`;
     - `.expose_secret()` chỉ được phép gọi trong 4 crate: `crates/mesh-crypto/*`, `crates/mesh-datapath/*`, `crates/mesh-net/*`, `crates/mesh/*`;
     - Cấm `:443` / `:3478` ngoài `crates/mesh-core/*` và `*/tests/*` (`GNFR-11`);
     - UTF-8 không BOM và 100% LF (trừ `.ps1`/`.bat`/`.cmd` dùng CRLF).
   - Ngoài ra, [`scripts/check.ps1`](../../scripts/check.ps1#L164-L177) tự động chuyển sang toolchain `+1.94.1-x86_64-pc-windows-gnu` (MinGW-w64 UCRT) khi máy phát triển không cài MSVC `link.exe`, còn [`scripts/check.sh`](../../scripts/check.sh#L154-L160) chạy `--cross` với `x86_64-pc-windows-gnu`, `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`.
3. **Lỗ hổng Thực tế Cần Khắc phục Đã Đối chứng (`[V]`):**
   - [`crates/mesh/src/cli.rs`](../../crates/mesh/src/cli.rs#L29-L30) dùng subcommand bắt buộc, [`crates/mesh/src/main.rs`](../../crates/mesh/src/main.rs#L52) thoát exit code `2` ở 0-arg → gây chớp console đen khi double-click `mesh.exe` từ Explorer.
   - [`crates/mesh-client/src/session.rs`](../../crates/mesh-client/src/session.rs#L678-L680) và [`apply_pin_selection`](../../crates/mesh-client/src/session.rs#L2220-L2231) xóa `bootstrap.next_pin = None` mỗi lần gọi `execute_up` → làm mất staged pin (`SEC-04(d)`) khi 1-Click Reconnect.
   - [`crates/mesh-client/src/config.rs`](../../crates/mesh-client/src/config.rs#L531-L564) (`split_host_port`) từ chối endpoint thiếu `:<port>` (`400 InvalidArgument`).
   - [`crates/mesh-proto/src/agent_ipc.rs`](../../crates/mesh-proto/src/agent_ipc.rs#L133-L161) gắn `#[serde(deny_unknown_fields)]` trên `AgentStatusResponse` → cấm tùy tiện nhét trường mới vào JSON `/v1/agent/status` nếu muốn tương thích ngược với CLI `v0.1.0-rc1`.
   - [`crates/meshd/src/main.rs`](../../crates/meshd/src/main.rs#L32-L44) (`DaemonArgs`) thiếu `version` flag (`meshd --version`).
   - [`mobile/ios/MeshApp/Sources/`](../../mobile/ios/MeshApp/Sources/AppViewModel+Actions.swift#L3-L61) (`9` tệp `.swift`) có 3 lỗi không được mang sang macOS: `PasteButton` bỏ qua `scheduleClipboardRedactionIfMatching`, form nhập tay thiếu chuẩn hóa `<host>:<port>` và chưa khóa `System CA` cho IP literal (`DashboardView.swift:441-479`), và `4/9` tệp (`AppViewModel.swift`, `AppViewModel+Actions.swift`, `QrScannerView.swift`, `ShareSheetView.swift`) đang `import UIKit` (cùng các modifier SwiftUI đặc thù iOS trong `DashboardView.swift` & `OnboardingView.swift`).
   - [`.github/workflows/release.yml`](../../.github/workflows/release.yml#L277-L285) dùng glob `mesh*` (phân biệt hoa-thường trên bash/MSYS2 nên sẽ bỏ sót `MeshVPN.exe`), và [`scripts/install-macos.sh`](../../scripts/install-macos.sh#L223-L224) chạy lại `codesign --force -s -` vô điều kiện làm đổi SHA-256 so với `SHA256SUMS` và phá chữ ký thương mại.

---

## 3. Quyết định Công nghệ Windows GUI (`crates/mesh-gui` → `MeshVPN.exe`)

### 3.1. Ma trận So sánh Lựa chọn UI Framework Windows (`OQ-DGUI-02`)

| Tiêu chí | Trọng số | **Win32 `windows-sys` Thuần (`crates/mesh-gui` + `crates/mesh-sys`) [CHỌN]** | WebView2 / Tauri / Electron | `egui` / `iced` / `slint` |
|---|---:|---|---|---|
| **Không thêm crate ngoài & Sạch `deny.toml`** | 25 | **5/5** — Dùng `windows-sys = "0.59"` đã có sẵn trong `Cargo.lock`; `0` thay đổi `deny.toml`; `0` phụ thuộc WebView2 Runtime trên Windows 10 sạch. | **1/5** — Kéo hàng trăm crate JS/WebView2 COM, hoặc đóng gói Chromium ~120+ MiB. | **2/5** — Kéo thêm cây crate đồ họa/GPU (`wgpu`/`winit`/`softbuffer`/`skia`), dễ xung đột license/C-deps trong `deny.toml`. |
| **Kích thước Binary & RAM rảnh (`DGUI-PERF-01/02`)** | 25 | **5/5** — Nhị phân `MeshVPN.exe` mục tiêu **`<= 4 MiB`** (trần `<= 6 MiB`), Working Set rảnh ở Tray **`<= 15 MiB`**, cold start `<= 500 ms`. | **1/5** — WebView2/Electron ngốn `80–250 MiB` RAM nền. | **3/5** — Binary ~8–15 MiB, GPU context idle ~35–70 MiB RAM. |
| **Tương thích MSVC + MinGW `gnu` + Non-Windows CI** | 20 | **5/5** — `windows-sys` biên dịch thuần qua import libraries có sẵn trên cả `x86_64-pc-windows-msvc` và `x86_64-pc-windows-gnu`; không phụ thuộc `embed-resource`/`winres`; trên Linux/macOS có stub `#[cfg(not(windows))]`. | **2/5** — Phức tạp trên MinGW/headless CI. | **2.5/5** — Đòi hỏi thư viện đồ họa/linker OS. |
| **Kiểm soát Tray (`Shell_NotifyIconW`), `TaskbarCreated`, `runas`, High-DPI** | 20 | **5/5** — Truy cập trực tiếp Win32 message loop (`WM_TRAYICON`, `TaskbarCreated`, `WM_DPICHANGED`, `WM_QUERYENDSESSION`), `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` lúc runtime, `ShellExecuteExW("runas")` với `SEE_MASK_NOCLOSEPROCESS`. | **3/5** — Vẫn phải tự bọc Win32 cho handoff pipe & DPI/Tray edge cases. | **2/5** — Hỗ trợ Tray và multi-DPI `TaskbarCreated` hạn chế, vẫn cần tự viết FFI riêng. |
| **Cô lập `unsafe` (`crates/mesh-sys`)** | 10 | **4.5/5** — `crates/mesh-gui` giữ `[lints] workspace = true` (`unsafe_code = "forbid"`); mọi Win32 FFI nằm trong `crates/mesh-sys/src/{gui_windows,process_windows}.rs` qua RAII `OwnedWinHandle`. | **4/5** — Đẩy `unsafe` vào crate bên thứ ba. | **3/5** — `unsafe` rải trong thư viện đồ họa ngoài. |
| **Tổng điểm (/100)** | **100** | **97.5 / 100** | 32.5 / 100 | 51.5 / 100 |

### 3.2. Kiến trúc Crate & Thành phần Kỹ thuật `crates/mesh-gui`

1. **Cấu trúc Workspace mở rộng (`crates/mesh-gui`, `crates/mesh`, `Cargo.toml`, `Dockerfile`):**
   - `Cargo.toml` giữ `members = ["crates/*", "tools/uniffi-bindgen"]` nên `crates/mesh-gui` tự động là thành viên workspace (`[V]`). Đồng thời **nâng `[workspace.package] version = "0.3.0"`** (và version nội bộ các crate tại `Cargo.toml:40-47`) khớp với `MARKETING_VERSION = "0.3.0"` của `desktop/macos/project.yml` (`HR-DGUI-G2-03`).
   - `crates/mesh-gui/Cargo.toml` khai báo:
     - `[package] name = "mesh-gui"`, `[[bin]] name = "MeshVPN"` (`path = "src/main.rs"` — sinh ra `MeshVPN.exe` trên Windows và `MeshVPN` stub trên non-Windows để `cargo check/clippy/test --workspace` xanh 100%).
     - `[lints] workspace = true` (`unsafe_code = "forbid"`).
     - Dependencies tối giản chỉ lấy từ workspace (**cấm** `sha2`/`subtle` trực tiếp ngoài `mesh-crypto` — `HR-DGUI-G2-02`): `mesh-core`, **`mesh-crypto = { workspace = true, default-features = false }`** (dùng `Secret<String>`, `sha256_digest`, `ct_eq_bytes`, `verify_file_sha256` đã xuất sẵn trong `crates/mesh-crypto/src/lib.rs`), `mesh-proto`, `mesh-net`, `mesh-sys`, `serde`, `serde_json`, `tokio` (multi-thread `worker_threads(1)` hoặc `current_thread` nền chạy song song Win32 UI thread qua `mpsc` channel + `PostMessageW`), `tokio-util`, `hyper`, `tracing`, `tracing-subscriber`, `tracing-appender`, `zeroize`, `rand`.
   - `crates/mesh/Cargo.toml` bổ sung `[target.'cfg(windows)'.dependencies] mesh-sys.workspace = true` để `crates/mesh/src/{main.rs,client_cmds.rs}` gọi `mesh_sys::process_windows::{is_interactive_explorer_double_click, spawn_detached_gui}` (`BLK-DGUI-G2-02`).
   - [`Dockerfile`](../../Dockerfile#L32-L66) Stage 1 bổ sung `COPY crates/mesh-gui/Cargo.toml crates/mesh-gui/Cargo.toml`, thư mục `crates/mesh-gui/src` và stub `main.rs` trong vòng lặp tạo placeholder trước `cargo fetch --locked` để giữ CI Docker & Release container luôn xanh (`BLK-DGUI-G2-03`).
2. **Win32 UI & Tài nguyên Nhị phân Không Dùng `embed-resource` / `winres`:**
   - **DPI Awareness**: gọi `mesh_sys::gui_windows::enable_per_monitor_v2_dpi()` ở đầu `main()` trước khi tạo bất kỳ cửa sổ nào (nạp/gọi `SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)` với fallback an toàn sang `SetProcessDPIAware()`).
   - **Common Controls v6 & Kiểu dáng Hiện đại**: kích hoạt `InitCommonControlsEx` (`ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES`) và thiết lập font chữ chuẩn hệ thống theo DPI hiện tại (`SystemParametersInfoForDpi(SPI_GETICONTITLELOGFONT)` / `Segoe UI`) qua `WM_DPICHANGED`.
   - **Biểu tượng Tray & Cửa sổ Động**: dựng 5 trạng thái icon `HICON` vector-bitmap trong RAM (`CreateIconIndirect` từ mảng RGBA 16x16 / 32x32 theo DPI — 0 phụ thuộc file `.rc`/`.res` ngoài!) tương ứng `Connected` (xanh lá), `Connecting`/`Degraded` (vàng), `Stopped` (xám), `DaemonNotRunning` (xám gạch chéo), `Warning`/`Revoked`/`ReauthRequired` (đỏ/cam).
   - **Manifest `asInvoker` & Tương thích MinGW `gnu`**: Trên Windows `msvc`, có thể dùng cờ linker nhẹ qua `build.rs` được rào chặt `if env::var_os("CARGO_CFG_TARGET_ENV").as_deref() == Some("msvc")`; trên `x86_64-pc-windows-gnu` (MinGW UCRT), không truyền `/MANIFEST:EMBED` và mặc định Windows cấp token `asInvoker` (Medium Integrity) khi không có resource manifest nâng quyền, đồng thời DPI được kích hoạt bằng API runtime nên hoạt động đồng nhất trên cả MSVC và MinGW `gnu`.
3. **Bổ sung Feature Win32 trong `crates/mesh-sys/Cargo.toml` (`[target.'cfg(windows)'.dependencies]`):**
   - Chỉ mở thêm các feature đã có sẵn trong `windows-sys = "0.59.0"` + `libwindows.0.52.0.a` trong `Cargo.lock` (`0` thêm crate mới, `BLK-DGUI-G2-02`):
     - `Win32_UI_WindowsAndMessaging` (`CreateWindowExW`, `DefWindowProcW`, `PostMessageW`, `RegisterWindowMessageW`, `GetMessageW`, `DispatchMessageW`, `SetForegroundWindow`, `CreatePopupMenu`, `TrackPopupMenuEx`, `WM_CLOSE`, `WM_QUERYENDSESSION`, `WM_ENDSESSION`, `WM_DPICHANGED`, `CreateIconIndirect`)
     - `Win32_UI_Shell` (`Shell_NotifyIconW`, `ShellExecuteExW`, `SEE_MASK_NOCLOSEPROCESS`, `SEE_MASK_NOASYNC`, `SHGetKnownFolderPath`, `NIF_*`, `NIM_*`)
     - `Win32_UI_Controls` (`InitCommonControlsEx`)
     - **`Win32_UI_Controls_Dialogs`** (`GetSaveFileNameW`, `OPENFILENAMEW`, `OFN_OVERWRITEPROMPT`)
     - **`Win32_UI_Input_KeyboardAndMouse`** (`SetFocus`, `GetFocus`, `EnableWindow`)
     - `Win32_UI_HiDpi` (`SetProcessDpiAwarenessContext`, `GetDpiForWindow`)
     - `Win32_Graphics_Gdi` (`CreateFontIndirectW`, `CreateDIBSection`, `DeleteObject`, `GetDC`, `ReleaseDC`)
     - `Win32_System_DataExchange` (`OpenClipboard`, `GetClipboardData`, `EmptyClipboard`, `CloseClipboard`, `GetClipboardSequenceNumber`)
     - **`Win32_System_Ole`** (`CF_UNICODETEXT` — hoặc hằng nội bộ `const CF_UNICODETEXT: u32 = 13`)
     - **`Win32_System_Com`** (`CoTaskMemFree` đi kèm `SHGetKnownFolderPath`)
     - `Win32_System_Memory` (`GlobalLock`, `GlobalUnlock`)
     - `Win32_System_Registry` (`RegOpenKeyExW`, `RegSetValueExW`, `RegDeleteValueW`, `RegCloseKey`, `HKEY_CURRENT_USER`)
     - `Win32_System_Diagnostics_ToolHelp` (`CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, `TH32CS_SNAPPROCESS`)
     - `Win32_System_Console` (`GetConsoleProcessList`)
   - *Shortcut `.lnk` (`US-106`, `US-108` — không dùng crate `windows`)*: `windows-sys` không sinh COM wrapper `IShellLinkW`/`IPersistFile`, nên việc **tạo** `.lnk` Start Menu/Desktop do `scripts/install-windows.ps1` (`WScript.Shell`) thực hiện hoặc qua minimal COM vtable chuẩn Win32 trong `mesh-sys`, còn việc **xóa** `.lnk` khi Uninstall dùng `SHGetKnownFolderPath` + `CoTaskMemFree` + `std::fs::remove_file`.

---

## 4. Quyết định Công nghệ macOS GUI (`desktop/macos/MeshVPNApp/`)

### 4.1. Stack & Cấu hình Project (`XcodeGen` + Swift 6 + macOS 13.0+)

| Thành phần | Quyết định chuẩn tắc | Lý do kỹ thuật |
|---|---|---|
| **Thư mục mã nguồn** | `desktop/macos/` (`project.yml`, `MeshDesktopCore/`, `MeshVPNApp/`, `MeshVPNAppTests/`, `.swiftlint.yml`) | Tách biệt rõ ràng với `mobile/ios/` (`v0.2.0`), không kéo `NEPacketTunnelProvider` hay `MeshMobileFFI.xcframework` vào app Desktop. |
| **Quản lý Project** | **`XcodeGen`** (`desktop/macos/project.yml`) | Sinh `MeshVPNApp.xcodeproj` tất định trên CI và local; **cấm** commit `.xcodeproj/` vào Git (đồng bộ `mobile-coding-standards.md`). |
| **Phiên bản Swift & OS** | **Swift `6.0`** (`SWIFT_VERSION = "6.0"`, `SWIFT_STRICT_CONCURRENCY = complete`, `SWIFT_TREAT_WARNINGS_AS_ERRORS = "YES"`); **macOS `13.0+`** (`MACOSX_DEPLOYMENT_TARGET = "13.0"`, hỗ trợ `arm64` + `x86_64` Universal/per-arch). | `macOS 13.0+` khớp `scripts/install-macos.sh:50` (`major_ver -lt 13`) và hỗ trợ sẵn `PasteButton` + SwiftUI hiện đại. |
| **UI & Menu Bar Architecture** | **AppKit `NSStatusItem`** + **`NSMenu`** + **SwiftUI Single-Window `Dashboard`** (bọc trong `NSWindowController` duy nhất, `NSApp.setActivationPolicy(.accessory)` khi thu gọn Menu Bar, chuyển tạm `.regular` khi mở Dashboard và trả về `.accessory` khi đóng cửa sổ; `applicationShouldTerminateAfterLastWindowClosed == false`). | `LSUIElement = YES` kết hợp `NSWindowController` đơn đảm bảo luôn có tối đa **1 cửa sổ Dashboard**, không hiện nhiều cửa sổ khi bấm `Cmd+N`, và kiểm soát chính xác biểu tượng Menu Bar + tooltip. |
| **Entitlements & Info.plist (`DGUI-MAC-03`)** | **Non-Sandboxed** (không khai báo `com.apple.security.app-sandbox`), `LSUIElement = YES`, `NSPrincipalClass = NSApplication`, `CFBundleIdentifier = dev.meshvpn.macos`; **CẤM** `CFBundleURLTypes` (`mesh://`) và **CẤM** `NSAllowsArbitraryLoads`. | App Sandbox chặn hoàn toàn kết nối Unix Domain Socket tới `/var/run/meshd/meshd-{ro,admin}.sock` ngoài container và chặn `osascript` cài `LaunchDaemon`. |
| **Transport & Privilege** | `MeshDesktopUdsClient` (Swift `Network` `NWConnection` với `NWEndpoint.unix(path:)` hoặc POSIX non-blocking socket qua `DispatchSourceRead`/`async` bọc gọn trong `actor`) giao tiếp HTTP/1.1 JSON trực tiếp tới `/var/run/meshd/meshd-ro.sock` (`0666`) và `/var/run/meshd/meshd-admin.sock` (`0660 root:admin`, `gid = 80`). **`0` mật khẩu** cho mọi thao tác thường ngày của user `admin`; chỉ gọi `/usr/bin/osascript` khi cần cài/nâng cấp `LaunchDaemon` vào `/usr/local/libexec/mesh/meshd` (`root:wheel`). | Tái sử dụng 100% cơ chế `LOCAL_PEERCRED` + `getgrouplist` sẵn có trong `crates/mesh-sys/src/ipc_macos.rs` (`[V]`). |

### 4.2. Khắc phục Triệt để 3 Lỗi Tái sử dụng từ `mobile/ios/MeshApp/Sources/` (`HR-DGUI-G1-02`)

Đối chiếu trực tiếp `9` tệp Swift trong `mobile/ios/MeshApp/Sources/` (`[V]`):

| Lỗi thực tế ở mã iOS (`[V]`) | Tác động nếu giữ nguyên trên macOS | Cách sửa bắt buộc tại `desktop/macos/MeshVPNApp/` |
|---|---|---|
| **1. `PasteButton` bỏ qua xóa clipboard `30 s`** (`OnboardingView.swift:102-107`, `AppViewModel+Actions.swift:35-60`) | Dán `mesh://join?...&key=mpk_...` qua `PasteButton` hoặc `Cmd+V` làm `mpk_*` tồn tại vô thời hạn trong clipboard macOS (Universal Clipboard có thể đồng bộ sang thiết bị khác!). | Mọi đường dán (**`PasteButton`**, nút Paste fallback, **`Cmd+V`** vào ô URI/token) đều đi qua một điểm xử lý thống nhất kích hoạt `ClipboardRedactor.scheduleWipeIfMatching(rawText, after: .seconds(30))`: lưu cặp **`(changeCount, sha256Digest)`** của `NSPasteboard.general`; sau `30 s`, chỉ gọi `NSPasteboard.general.clearContents()` nếu `changeCount` không đổi hoặc nội dung hiện tại vẫn khớp SHA-256 (không xóa nhầm nội dung người dùng mới sao chép). |
| **2. Thiếu `:<port>` làm vỡ `split_host_port` & chưa khóa `System CA` trên IP literal** (`AppViewModel+Actions.swift:71-128`, `DashboardView.swift:441-479`) | Nhập `203.0.113.10` + Port `8443` hoặc `vpn.example.com` không port → `meshd` trả `400 InvalidArgument` (`"server endpoint must contain :<port>"` tại `mesh-client/src/config.rs:555`); chọn IP + `System CA` bị server từ chối. | Lớp `EndpointNormalizer` trong `MeshDesktopCore` (đối xứng 100% với `validate_server_and_policy` trong `crates/mesh/src/client_cmds.rs:360-406` `[V]`): tự điền `portOverride` hoặc `DEFAULT_CONTROL_TCP_PORT` thành `<host>:<effective_port>` (hỗ trợ IPv6 `[2001:db8::1]:port`), đồng thời UI tự động khóa/vô hiệu hóa lựa chọn `System CA` ngay khi nhận diện host là IPv4/IPv6 literal (`NWEndpoint.Host` / `inet_pton`). |
| **3. Phụ thuộc độc quyền `UIKit` & modifier iOS-only** (`4/9` tệp `AppViewModel.swift`, `AppViewModel+Actions.swift`, `QrScannerView.swift`, `ShareSheetView.swift` đang `import UIKit`; `MeshApp.swift` & `DashboardView.swift` không import `UIKit`, còn `DashboardView.swift` & `OnboardingView.swift` dùng modifier SwiftUI đặc thù iOS `[V]`) | Không thể biên dịch cho target `macOS` (`xcodebuild` báo lỗi `No such module 'UIKit'`). | **0 `import UIKit`** trong toàn bộ `desktop/macos/`. Thay thế bằng `AppKit` (`NSApp`, `NSPasteboard`, `NSSavePanel`, `NSStatusItem`, `NSWindowController`) và macOS SwiftUI idioms (bỏ `.navigationBarTitleDisplayMode`, `.navigationViewStyle(.stack)`, `.keyboardType`, `.textInputAutocapitalization`, `.navigationBarTrailing`). |

---

## 5. Ma trận Build & Kiểm định CI `$0` (vs Nghiệm thu Phần cứng)

| Môi trường / Job CI (`$0`) | Toolchain & Lệnh chạy chính xác | Mục tiêu chứng minh tự động ở `$0` | Giới hạn cần nghiệm thu máy thật (`hardware_signoff_required`) |
|---|---|---|---|
| **Static Hygiene (`ubuntu-latest` / `windows-latest` / `macos-15`)** | `scripts/check.ps1` và `scripts/check.sh` (mở rộng quét `desktop/macos/`) | UTF-8 No-BOM, 100% LF (`.ps1` CRLF), `0` `unsafe` ngoài `crates/mesh-sys/`, giữ allowlist 4 crate `.expose_secret()`, `0` `:443`/`:3478` ngoài `mesh-core`, `0` `app-sandbox` / `CFBundleURLTypes` / `NSAllowsArbitraryLoads` / `spctl --master-disable` / `UIKit` trong `desktop/macos/`, `cargo deny check`. | — |
| **Windows MSVC (`windows-latest`)** | `cargo build --release --locked --target x86_64-pc-windows-msvc --bin MeshVPN --bin mesh --bin meshd --bin mesh-server` (kèm `MESH_WINTUN_SHA256`) + `cargo test --workspace --all-features` | Biên dịch thành công `MeshVPN.exe` (`SUBSYSTEM:WINDOWS`), kiểm kích thước `<= 6 MiB` (mục tiêu `<= 4 MiB`), test logic IPC/handoff/SDDL/Explorer 3 điều kiện/Unprivileged Sink Write/single-instance/`HKCU` cleanup, xác minh `MeshVPN.exe` có mặt trong `SHA256SUMS`. | Test hộp thoại UAC thật, `Shell_NotifyIconW` trên Windows 10/11 DPI 125%–200%, `TaskbarCreated` sau restart `explorer.exe`, nâng cấp sống tránh `ERROR_SHARING_VIOLATION`, `wintun.dll` thật, Working Set `<= 15 MiB`. |
| **Windows MinGW (`windows-latest` & local)** | `scripts/check.ps1` nhánh `+1.94.1-x86_64-pc-windows-gnu` & `cargo check --locked --target x86_64-pc-windows-gnu --bin MeshVPN ...` | Bảo đảm `mesh-gui` + `mesh-sys` biên dịch sạch với MinGW-w64 UCRT không phụ thuộc MSVC `link.exe` hay `/MANIFEST:EMBED`. | Chạy bản GNU/MSVC trên máy Windows người dùng không cài WebView2 Runtime. |
| **Non-Windows Cross & Stub (`ubuntu-latest`)** | `sh scripts/check.sh` và `sh scripts/check.sh --cross` | Bảo đảm `crates/mesh-gui` (`#[cfg(not(windows))]` stub) vượt qua `cargo fmt`, `clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features` và `--cross` (`linux-musl`, `darwin`, `windows-gnu`). | — |
| **macOS Swift 6 & Packaging (`macos-15`)** | `xcodegen generate`, `swiftlint lint --strict`, `xcodebuild test -project MeshVPNApp.xcodeproj -scheme MeshVPNApp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`, đóng gói `.app` (inner `codesign` → `SHA256SUMS` → outer `.app` không `--deep` → `codesign -v`), `bash -n`, `plutil -lint`. | Build Swift 6 (`SWIFT_STRICT_CONCURRENCY = complete`), `XCTest` `MeshDesktopCore` (`Codable` parity, `<host>:<port>`, khóa `System CA` trên IP, clipboard 30s, bugreport stream `<= 20 MiB`, `agent_version` fallback), xác minh hash `Contents/Resources/meshd` khớp `SHA256SUMS` sau `codesign -v`. | Mở `Mesh VPN.app` trên MacBook thật (`arm64`/`x86_64`), 1-click `osascript` cài `/usr/local/libexec/mesh/meshd`, user `admin` (`gid=80`) bật/tắt & xuất bugreport `0` mật khẩu, Standard User bị `EACCES`, `socketfilterfw` opt-in, RSS `<= 35 MiB`. |
| **Thương mại hóa (`paid_cert_required`, `US-117` Could)** | Authenticode (Windows) & Developer ID + `notarytool` + `stapler` (macOS `$99/năm`) | Tự động bỏ qua sạch khi thiếu repository secrets trong `$0` CI; `install-macos.sh` kiểm `codesign -v` trước để không ghi đè ad-hoc lên chữ ký thật. | Kiểm chứng ký số thương mại khi kích hoạt chứng chỉ. |

---

## 6. Tham chiếu Chéo Tài liệu Gate 2

- Quyết định kiến trúc chi tiết & phân tích phương án (`ADR-020..026`): [desktop-gui-adr.md](./desktop-gui-adr.md)
- Quy chuẩn mã nguồn Rust/Win32 & Swift 6 macOS & quy tắc `scripts/check.{ps1,sh}`: [desktop-gui-coding-standards.md](./desktop-gui-coding-standards.md)
- Kiến trúc C4, phân tách đặc quyền & luồng cài đặt/gỡ cài đặt: [desktop-gui-system-architecture.md](./desktop-gui-system-architecture.md)
- Đặc tả wire protocol IPC, Handoff Pipe, 3 tầng timeout & UI State Machine: [desktop-gui-ipc-and-ui-contracts.md](./desktop-gui-ipc-and-ui-contracts.md)
