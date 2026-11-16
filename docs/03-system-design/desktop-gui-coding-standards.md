# Desktop GUI Coding Standards — Mesh VPN (`v0.3.0`: Windows `MeshVPN.exe` & macOS `Mesh VPN.app`)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày lập | 2026-11-17 |
| Phiên bản | **1.0 (Chặng 2 — Desktop GUI Gate 2)** |
| Nhánh làm việc | `feat/desktop-gui` (không chạm `main`, `v0.1.0-rc1` và `v0.2.0`) |
| Áp dụng cho | `agile-developer`, `agile-qa`, `agile-devops` (Wave D-A, Wave D-B1 Windows, Wave D-B2 macOS, Wave D-C QA & CI) |
| Kế thừa bắt buộc | [coding-standards.md](./coding-standards.md) v2.2 · [mobile-coding-standards.md](./mobile-coding-standards.md) v1.1 · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Tài liệu thiết kế đi kèm | [desktop-gui-tech-stack-decision.md](./desktop-gui-tech-stack-decision.md) · [desktop-gui-adr.md](./desktop-gui-adr.md) (`ADR-020..026`) · [desktop-gui-system-architecture.md](./desktop-gui-system-architecture.md) · [desktop-gui-ipc-and-ui-contracts.md](./desktop-gui-ipc-and-ui-contracts.md) |

> **Nguyên tắc tối thượng:** Toàn bộ quy chuẩn Rust, TOML, Shell, Markdown và Git trong [coding-standards.md](./coding-standards.md) giữ nguyên **100% hiệu lực**. Tài liệu này bổ sung các quy chuẩn bắt buộc cho **Windows Native GUI (`crates/mesh-gui`, `crates/mesh-sys`, `crates/mesh-net/src/gui_handoff.rs`)**, **macOS Native App (`desktop/macos/MeshVPNApp/`)** và phần mở rộng **`scripts/check.{ps1,sh}`** để mã nguồn do nhiều subagent viết song song đạt chất lượng đồng nhất và vượt qua `$0` CI Gate ngay từ lần chạy đầu tiên.

---

## 0. Ngôn ngữ, Mã hóa Tệp & Kết thúc Dòng (File Hygiene)

| Quy tắc | Phạm vi áp dụng | Công cụ cưỡng chế |
|---|---|---|
| **Ngôn ngữ mã nguồn** | Tên biến, hàm, struct/class/enum, doc comment (`///`), comment nội dòng (`//`), thông điệp lỗi, log JSON/`OSLog`, tên test, commit message: **100% Tiếng Anh**. Tài liệu thiết kế/vận hành trong `docs/`: **Tiếng Việt** (giữ thuật ngữ kỹ thuật tiếng Anh). | Review & Lint |
| **Bảng mã UTF-8 KHÔNG BOM** | **100% tệp** (`.rs`, `.toml`, `.md`, `.ps1`, `.sh`, `.swift`, `.yml`, `.yaml`, `.plist`, `.entitlements`, `.json`, `.strings`, `.xcstrings`). **Cấm tuyệt đối** byte BOM `0xEF 0xBB 0xBF`. | `scripts/check.{ps1,sh}` & `.github/workflows/ci.yml` |
| **Kết thúc dòng `LF` (`\n`)** | **100% LF** cho mọi tệp nguồn Rust, Swift, XcodeGen `project.yml`, `Info.plist`, `.swiftlint.yml`, `.md`, `.sh`, `.json`. Chỉ `*.ps1`, `*.bat`, `*.cmd` dùng **CRLF**. | `.editorconfig` + `scripts/check.{ps1,sh}` |

---

## 1. Quy chuẩn Rust Mở rộng (`crates/mesh-gui`, `crates/mesh-sys`, `crates/mesh-net`, `crates/mesh-client`, `crates/meshd`, `crates/mesh`)

### 1.1. Ranh giới `unsafe` & Cấu hình `crates/mesh-gui` (`ADR-020`)

1. **`crates/mesh-gui/Cargo.toml` BẮT BUỘC khai báo `[lints] workspace = true` (`unsafe_code = "forbid"`):**
   - Khai báo binary mục tiêu:
     ```toml
     [package]
     name = "mesh-gui"
     version.workspace = true
     edition.workspace = true
     rust-version.workspace = true
     license.workspace = true
     publish.workspace = true

     [lints]
     workspace = true

     [[bin]]
     name = "MeshVPN"
     path = "src/main.rs"
     ```
   - Đầu tệp `crates/mesh-gui/src/main.rs` đặt `#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]`.
   - **0 dòng `unsafe`** trong `crates/mesh-gui` (kể cả trong tests).
   - **0 `.unwrap()`, 0 `.expect()`, 0 `panic!()`, 0 `todo!()`, 0 `println!()`/`eprintln!()`** trong non-test code (`mesh-gui` ghi log qua `tracing` JSON, không ghi ra stdout/stderr để tránh lỗi handle vô hiệu trên `SUBSYSTEM:WINDOWS`).
   - **Cấm** thêm `embed-resource`, `winres`, `webview2-com`, `tauri`, `egui`, `iced`, `slint`, **`sha2`, `subtle`** vào `crates/mesh-gui/Cargo.toml` hoặc sửa đổi `deny.toml` (`HR-DGUI-G2-02`: `mesh-crypto` là crate duy nhất import mật mã; `crates/mesh-gui` dùng `mesh-crypto = { workspace = true, default-features = false }` cho `Secret<String>`, `sha256_digest`, `ct_eq_bytes`, `verify_file_sha256`).
   - **Cấm** gọi flags linker MSVC trần: mọi logic đặc thù MSVC trong `crates/mesh-gui/build.rs` (nếu có) phải rào `CARGO_CFG_TARGET_ENV == "msvc"`; đặt DPI runtime bằng `mesh_sys::gui_windows::enable_per_monitor_v2_dpi()` để xanh trên cả **MSVC** lẫn **MinGW `x86_64-pc-windows-gnu`**.
   - **Stub Non-Windows bắt buộc:** Các module xử lý state/validation/framing/logging/IPC (`state.rs`, `validation.rs`, `handoff_codec.rs`, `ipc_client.rs`, `logging.rs`) phải biên dịch và chạy unit tests được trên Linux/macOS/Windows; nhánh giao diện Win32 đặt dưới `#[cfg(target_os = "windows")]` kèm `#[cfg(not(target_os = "windows"))]` stub trong `main.rs`.

### 1.2. Quy chuẩn `crates/mesh-sys` (`gui_windows.rs`, `process_windows.rs`, RAII `OwnedWinHandle`)

Toàn bộ lời gọi Win32 FFI (`windows-sys = "0.59"`) cho Desktop GUI và Launcher phải nằm cô lập trong `crates/mesh-sys/src/` dưới `#[cfg(target_os = "windows")]` với các quy tắc cứng sau:

1. **Lint & Safety Comment Bắt buộc:** Giữ nguyên `[lints.rust]` (`unsafe_op_in_unsafe_fn = "deny"`) và `[lints.clippy]` (`undocumented_unsafe_blocks = "deny"`, `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`, `indexing_slicing = "deny"`) trong [`crates/mesh-sys/Cargo.toml`](../../crates/mesh-sys/Cargo.toml). Mọi khối `unsafe` phải có comment `// SAFETY: ...` ngay phía trên giải thích tính hợp lệ của con trỏ, chuỗi UTF-16 kết thúc bằng NUL (`0u16`), kích thước buffer và vòng đời handle.
2. **Bắt buộc RAII Wrapper cho mọi Tài nguyên Win32 (Cấm Rò rỉ Handle):**
   - `OwnedWinHandle(HANDLE)` (dùng chung cho `CreateNamedPipeW`, `CreateFileW`, `CreateMutexW`, `CreateEventW`, `OpenProcess`, `CreateToolhelp32Snapshot`, `ShellExecuteExW.hProcess`, đóng bằng `CloseHandle` trong `Drop` nếu `!is_null() && != INVALID_HANDLE_VALUE`).
   - `OwnedIcon(HICON)` (`DestroyIcon` trong `Drop`).
   - `OwnedMenu(HMENU)` (`DestroyMenu` trong `Drop`).
   - `OwnedGdiObj(HGDIOBJ)` (`DeleteObject` trong `Drop` cho `HFONT`/`HBITMAP`).
   - `OwnedRegKey(HKEY)` (`RegCloseKey` trong `Drop`).
   - `LocalAllocGuard(*mut c_void)` (`LocalFree` trong `Drop`, tái sử dụng mẫu tại `crates/mesh-sys/src/ipc_windows.rs:242-256` `[V]`).
   - `ClipboardGuard` (`CloseClipboard` trong `Drop` sau `OpenClipboard`).
3. **Phân tách 2 Module Win32 Mới trong `crates/mesh-sys/src/`:**
   - **`crates/mesh-sys/src/process_windows.rs`** (`ADR-022`):
     - `is_interactive_explorer_double_click() -> SysResult<bool>`: thực hiện **đồng thời** (i) `GetConsoleProcessList` == `1`, (ii) quét `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` lấy `th32ParentProcessID`, mở tiến trình cha với `PROCESS_QUERY_LIMITED_INFORMATION`, đối chiếu `GetProcessTimes` (`parent_creation < self_creation`) chống PID reuse, và xác minh `QueryFullProcessImageNameW` trùng `%SystemRoot%\explorer.exe`.
     - `spawn_detached_gui(exe_path: &Path) -> SysResult<()>`: truyền `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`, đường dẫn chuẩn hóa không ghép chuỗi qua `cmd.exe`/`powershell.exe`.
   - **`crates/mesh-sys/src/gui_windows.rs`** (`ADR-020`, `ADR-021`, `ADR-023`, `ADR-026`):
     - `enable_per_monitor_v2_dpi()`: gọi `SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)` với fallback an toàn.
     - `Shell_NotifyIconW` (`NIM_ADD`, `NIM_MODIFY`, `NIM_DELETE`), `RegisterWindowMessageW("TaskbarCreated")`, xử lý `WM_CLOSE` (ẩn thay vì thoát) và `WM_QUERYENDSESSION`/`WM_ENDSESSION` (`NIM_DELETE` + hủy `CancellationToken` thoát `<= 2 s`).
     - `launch_elevated_worker(exe_path: &Path, handoff_pipe_name: &str) -> SysResult<OwnedWinHandle>`: gọi `ShellExecuteExW` (`lpVerb = "runas"`, `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`); map `ERROR_CANCELLED (1223)` về `SysError::PermissionDenied` hoặc `SysError::Cancelled` rõ ràng. **Assert kiểm biên** `handoff_pipe_name` bắt đầu bằng `\\.\pipe\mesh-gui-handoff-` và chỉ chứa `[a-f0-9]` sau tiền tố (`0` secret, `0` đường dẫn đích).
     - `HandoffPipeServer` & `HandoffPipeClient`: server tạo pipe với `FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS | FILE_FLAG_OVERLAPPED`, SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<CurrentUserSid>)`; client (`--elevated-worker`) mở bằng `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED` và gửi ngay Frame **`0x00 WorkerHello`** (`13` bytes); server kiểm `GetNamedPipeClientProcessId == child_pid`, đọc `WorkerHello` (`<= 5_000 ms`), rồi gọi `ImpersonateNamedPipeClient` (`SecurityIdentification`) → `OpenThreadToken` → `CheckTokenMembership` (`is_builtin_admin || is_local_system`) bọc trong `ImpersonationGuard` (`RevertToSelf`), **cấm** rẽ sang `OpenProcessToken` (`BLK-DGUI-G2-04`).
     - **`UnprivilegedSinkWriter` (`Atomic Temp-Sibling Sink Write`, `BLK-DGUI-G2-05`, `MED-DGUI-G2-02`)**: **cấm** mở thẳng tệp đích bằng `CREATE_NEW` / `O_CREAT | O_EXCL`. Kiểm tra `dest` ngoài thư mục hệ thống, mở `parent` bằng `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` xác nhận không phải reparse point, nếu `dest` tồn tại xác nhận là regular file; mở `parent/.mesh-bugreport-<128bit_hex>.tar.part` với `CREATE_NEW | FILE_FLAG_OPEN_REPARSE_POINT`, ghi chunk `<= 64 KiB`, kiểm `expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes <= 20_971_520` → `sync_all()` → đóng handle → re-check `dest` → `MoveFileExW(tmp, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` (RAII `Drop` xóa `.part` khi lỗi).
     - `open_anti_toctou_read_locked(path: &Path) -> SysResult<std::fs::File>`: mở với `FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT`, kiểm tra không phải reparse point để giữ khóa đọc xuyên suốt check `MESH_WINTUN_SHA256` → copy sang `%ProgramFiles%\Mesh\`.
     - `acquire_single_instance_mutex()` (`Local\MeshVpnGuiSingleInstance`) & `Local\MeshVpnGuiShutdownEvent`, quản lý `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` và xóa shortcut `.lnk` khi Uninstall qua `SHGetKnownFolderPath` + `CoTaskMemFree` + `std::fs::remove_file` (`BLK-DGUI-G2-02`); `Win32 Clipboard` (`SetTimer` `30_000 ms` + `GetClipboardSequenceNumber()` + `mesh_crypto::sha256_digest` trước khi `EmptyClipboard()`).

### 1.3. Bảo toàn Allowlist `.expose_secret()`, Framing `MGH1`, Reset Identity & Timeout 3 Tầng (`ADR-020..024`)

1. **Allowlist `.expose_secret()` (`crates/mesh-net/src/gui_handoff.rs`):**
   - Tuyệt đối không mở rộng danh sách allowlist 4 crate (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`) trong `scripts/check.{ps1,sh}`.
   - Mọi thao tác đọc giá trị bên trong `Secret<String>` / `PreAuthToken` để serialize `AgentUpRequest` / `AgentRotateKeyRequest` hoặc ghi vào framing `MGH1` phải nằm trong `crates/mesh-net/src/gui_handoff.rs`, trả ra `Zeroizing<Vec<u8>>` và zeroize ngay trong `Drop` hoặc sau khi ghi pipe xong (và `<= 100 ms` khi `ERROR_CANCELLED`).
2. **Đóng khung Nhị phân `MGH1` (Ephemeral Handoff Pipe):**
   - Cố định header `9` bytes: `[magic: b"MGH1" (4B)][frame_type: u8][len: u32 LE][payload: len bytes]`.
   - Kiểm tra biên trước khi cấp phát buffer: `frame_type ∈ {0x00, 0x01, 0x02, 0x03, 0x04}`; với `0x00` (`WorkerHello`) cố định `len == 4` (`u32 LE protocol_version = 1`, tổng `13` bytes); với `0x01`, `0x02`, `0x04` trần `len <= MAX_ADMIN_IPC_BODY_BYTES (65_536)`; với `0x03` (`BugreportChunk`) mỗi chunk `<= 65_536` bytes và tổng luồng tích lũy `<= MAX_BUGREPORT_ARCHIVE_BYTES (20 * 1024 * 1024)`. Cấm `slice[i]` (dùng `.get(...)` / `split_at_checked`).
3. **Chuẩn hóa `crates/mesh-client`, `crates/meshd`, `crates/mesh-proto`, `crates/mesh`, `crates/mesh-mobile-ffi`:**
   - `crates/mesh-proto/src/agent_ipc.rs`: **giữ nguyên** 13 trường của `AgentStatusResponse` (`#[serde(deny_unknown_fields)]`) không đổi tên hay thêm field phá `v0.1.0-rc1`; bổ sung `AgentVersionResponse { agent_version: String, protocol_version: u16, binary_name: String }` (`#[serde(deny_unknown_fields)]`) và `AgentResetIdentityRequest {}` (`#[serde(deny_unknown_fields)]`).
   - `crates/meshd/src/main.rs`: thêm `#[command(version)]` vào `DaemonArgs` (cùng nâng `[workspace.package] version = "0.3.0"` trong `Cargo.toml` — `HR-DGUI-G2-03`).
   - `crates/meshd/src/ipc_service.rs`: gắn header `X-Mesh-Agent-Version: <CARGO_PKG_VERSION>` (`"0.3.0"`); thêm `GET /v1/agent/version` vào cả `build_ro_router` & `build_admin_router`; thêm `POST /v1/agent/reset-identity` (bodyless/optional `{}`) và `POST /v1/agent/bugreport/stream` (bodyless/optional `{}`) **chỉ** vào `build_admin_router` (dùng **`GuardedBugreportStream { inner: Option<ReaderStream<tokio::fs::File>>, path: PathBuf }`** chạy `drop(self.inner.take())` **trước** `std::fs::remove_file(&self.path)` trong `Drop` — `HR-DGUI-G2-03`).
   - `crates/mesh-client/src/hooks.rs`, `session.rs` & `crates/mesh-mobile-ffi/src/bridge.rs:140`: thêm `ClientStateStore::delete_identity(&self) -> AppResult<()>` và triển khai đủ cho **`FileClientStateStore`**, **`InMemoryClientStateStore`** VÀ **`FfiStateStore`** (`BLK-DGUI-G2-01`), cùng `ClientSessionSupervisor::execute_reset_identity(&mut self)`; hợp nhất **`update_bootstrap_trust_preserving_next_pin(...)`** cho **cả `execute_up` (`session.rs:680`) lẫn `execute_set` (`session.rs:752`)** (`HR-DGUI-G2-04`).
   - `crates/mesh-net/src/ipc.rs`: áp dụng **3 tầng timeout IPC** (`IPC_CONNECT_TIMEOUT = 850 ms`, `IPC_RO_QUERY_TIMEOUT = 2_000 ms`, `IPC_NETCHECK_TIMEOUT = 10_000 ms`, `IPC_PING_MAX_TIMEOUT = 35_000 ms`, `IPC_ADMIN_MUTATION_TIMEOUT = 35_000 ms`), đọc response `meshd-ro` trần `MAX_HTTP_BODY_BYTES (65_536)`, và phân loại daemon `v0.1.0-rc1` (`404` `/version` + thiếu header, hoặc `meshd --version` exit `2`) là `LegacyPre030` (`MED-DGUI-G2-01`).
   - **Cấm** hardcode `:443` / `:3478` ngoài `crates/mesh-core::defaults` (`GNFR-11`).
4. **Structured Logging & Kiểm thử (`US-107`, `US-116`):**
   - `MeshVPN.exe` ghi JSON log (`ts` UTC, `level`, `component`, `event`) vào `%LOCALAPPDATA%\MeshVPN\logs` với rotation; dùng bộ lọc redaction chặn `mpk_*`, `mesh://join?...&key=...` và private key (`0` match ở mọi level).
   - Mọi unit/integration test tuân thủ `// Arrange`, `// Act`, `// Assert`, đặt tên `test_<unit>_<scenario>_<expected>`; parser URI/endpoint/MGH1 có `proptest!`; test cần Windows Admin thật gắn `#[ignore = "privileged"]`.

---

## 2. Quy chuẩn macOS Swift `6.0` (`desktop/macos/MeshVPNApp/`)

### 2.1. Cấu trúc Project, XcodeGen & SwiftLint (`ADR-025`)

| Hạng mục | Quy chuẩn bắt buộc | Công cụ cưỡng chế |
|---|---|---|
| **Project Spec (`XcodeGen`)** | Quản lý qua **`desktop/macos/project.yml`** (`MACOSX_DEPLOYMENT_TARGET = "13.0"`, `SWIFT_VERSION = "6.0"`, `SWIFT_STRICT_CONCURRENCY = complete`, `SWIFT_TREAT_WARNINGS_AS_ERRORS = "YES"`). **Cấm** commit `.xcodeproj/`, `.xcworkspace/`, `DerivedData/`, `.build/`. | `xcodegen generate` trong CI & local |
| **Phân tách Module** | **`MeshDesktopCore`** (Swift package/framework OS-neutral hoặc AppKit-light: `UdsIpcClient`, `AgentIpcModels`, `EndpointNormalizer`, `JoinUriParser`, `ClipboardRedactor`, `DesktopUiStateMachine`, `BugreportStreamWriter`, `SafeOsLogger` — kiểm thử 100% bằng `XCTest` ở `$0` CI) và **`MeshVPNApp`** (`AppDelegate` `NSStatusItem`, `DashboardWindowController`, `SwiftUI` views, `LaunchDaemonInstaller`). | `project.yml` & `xcodebuild test` |
| **Style & Cấm Force-Unwrap** | Indent **4 spaces**, độ dài dòng **`<= 100` cột**, UTF-8 No-BOM, **LF**. **CẤM TUYỆT ĐỐI** `!` (force-unwrap), `try!`, `as!`, `fatalError(...)`, `print(...)` trong code production (chỉ cho phép trong `MeshVPNAppTests/`). | `desktop/macos/.swiftlint.yml` (`swiftlint lint --strict`) |
| **Concurrency (`Sendable`)** | Mọi state chia sẻ & IPC transport đặt trong `actor` hoặc tuân thủ `Sendable` nghiêm ngặt dưới `SWIFT_STRICT_CONCURRENCY = complete`. **Cấm** `@unchecked Sendable` trừ khi bọc `NSLock`/`os_unfair_lock` được chứng minh ngay phía trên bằng comment `// SAFETY-SENDABLE: ...`. | `xcodebuild` Swift 6 compiler |

### 2.2. Quy tắc Bắt buộc Chống Tái phạm 3 Lỗi `mobile/ios/MeshApp` & Bảo mật macOS (`HR-DGUI-G1-02`, `DGUI-MAC-01..07`)

1. **Cấm tuyệt đối `UIKit` & iOS-only APIs (`HR-DGUI-G1-02`):**
   - **0** dòng `import UIKit`, `.navigationBarTitleDisplayMode`, `.navigationViewStyle(.stack)`, `.keyboardType`, `.textInputAutocapitalization`, `.navigationBarTrailing` trong `desktop/macos/`.
   - Dùng `AppKit` (`NSStatusItem`, `NSMenu`, `NSWindowController`, `NSPasteboard`, `NSSavePanel`, `NSApplication`) và macOS SwiftUI (`Settings`/`Form`/`Table`/`PasteButton`).
2. **Single-Window `LSUIElement` (`DGUI-MAC-01`):**
   - `Info.plist` đặt `LSUIElement = YES`; `AppDelegate.applicationShouldTerminateAfterLastWindowClosed(_:) -> Bool` trả về `false`.
   - Chỉ duy trì **1 `NSWindowController` duy nhất** cho Dashboard; chuyển `NSApp.setActivationPolicy(.regular)` khi mở cửa sổ và trả về `.accessory` trong `windowWillClose(_:)`.
   - Hộp thoại/Menu Bar luôn giữ 8 trạng thái `DesktopUiState` đồng bộ: `ServiceNotInstalled`, `ServiceStopped`, `Unconfigured`, `Connecting`, `Connected`, `ReauthRequired`, `Revoked`, `Error`.
3. **Chuẩn hóa `<host>:<effective_port>` & Khóa `System CA` trên IP Literal (`HR-DGUI-G1-02`):**
   - `EndpointNormalizer.normalize(host:portOverride:)` chuẩn hóa mọi đầu vào thiếu `:<port>` thành `<host>:<effective_port>` (lấy `portOverride` hoặc `DEFAULT_CONTROL_TCP_PORT = 443` khai báo tại một hằng số duy nhất trong `AgentDefaults`, hỗ trợ IPv6 `[...]:port`), **trước** khi dựng `AgentUpRequest` / `AgentSetRequest` hoặc `EnrollmentConfirmationDraft`.
   - Khi `EndpointNormalizer.isIpLiteral(host) == true`, UI **vô hiệu hóa/khóa lựa chọn `System CA`** và bắt buộc `SPKI Pin` (`sha256:<64_lowercase_hex>`). Không có nút "Skip TLS Verification" / TOFU.
4. **Clipboard Wipe `30 s` cho Cả `PasteButton` Lẫn `Cmd+V` (`HR-DGUI-G1-02`, `DGUI-SEC-03`):**
   - Mọi thao tác dán (`PasteButton`, nút Paste fallback, `Cmd+V` vào ô URI/`mpk_*`) đều gọi cùng hàm `handlePastedInput(_:)` và kích hoạt `ClipboardRedactor.scheduleWipeIfMatching(text, delay: .seconds(30))`.
   - `ClipboardRedactor` đọc `NSPasteboard.general.changeCount` + SHA-256 nội dung khi dán; khi timer nổ sau `30 s`, chỉ xóa `NSPasteboard.general.clearContents()` nếu `changeCount` chưa đổi hoặc chuỗi hiện tại vẫn khớp SHA-256.
   - Đóng/hủy sheet hoặc hoàn tất `confirmPendingEnrollment` phải xóa rỗng ngay `manualPreauthKey` trong `defer`.
5. **Non-Sandboxed, `0` URL Handler, Unprivileged Sink Write & `osascript` An toàn (`DGUI-MAC-03..06`):**
   - **Cấm** `com.apple.security.app-sandbox`, `CFBundleURLTypes`, `NSAllowsArbitraryLoads`, `spctl --master-disable`.
   - Kết nối trực tiếp `/var/run/meshd/meshd-ro.sock` & `/var/run/meshd/meshd-admin.sock` với 3 tầng timeout (`850 ms` connect, `2_000 ms` `ro`, `10_000 ms` `netcheck`, `<= 35_000 ms` `ping`/`admin`, tạm ngắt polling `ro` khi chờ admin).
   - Export Bugreport (`BugreportStreamWriter` / **Atomic Temp-Sibling Sink Write**, `BLK-DGUI-G2-05`, `MED-DGUI-G2-02`): user `admin` (`gid = 80`) gọi trực tiếp `POST /v1/agent/bugreport/stream` qua `meshd-admin.sock` (**`0` mật khẩu, `0` `osascript`**); kiểm `parent` non-symlink (`lstat`) và `dest` (nếu tồn tại) là regular file; mở tệp tạm cùng thư mục `parent/.mesh-bugreport-<128bit_hex>.tar.part` bằng `open(..., O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)`, ghi chunk `<= 64 KiB`, kiểm **`expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes <= 20_971_520`** → `fsync` → re-check `dest` → `rename` nguyên tử (hỗ trợ Replace tệp cũ êm; RAII xóa `.part` khi hủy/lỗi).
   - `/usr/bin/osascript`: **chỉ** gọi script cài đặt/gỡ/firewall cố định đóng gói trong `Contents/Resources/` với đường dẫn bundle đã kiểm tra không chứa byte NUL/ký tự điều khiển và bọc `quoted form of`; **cấm tuyệt đối** nội suy `mpk_*`, `server_endpoint`, `node_name`, hay đường dẫn `NSSavePanel` vào `osascript`.
   - `OSLog` (`os.Logger`): gắn `%{private}@` cho mọi tên peer, IP, đường dẫn tệp người dùng; đi qua `SafeOsLogger` canary filter bảo đảm `0` rò rỉ `mpk_*` hoặc `mesh://join?...&key=...` ở mọi cấp độ.

---

## 3. Mở rộng Hàng rào Kiểm tra Tĩnh `scripts/check.ps1` & `scripts/check.sh` (`HR-DGUI-G1-03`)

Tại Wave D-A, mở rộng bước `[2/5]` của cả [`scripts/check.ps1`](../../scripts/check.ps1) và [`scripts/check.sh`](../../scripts/check.sh) như sau (giữ nguyên toàn bộ kiểm tra hiện có trên `crates/`, `tools/`, `mobile/`):

1. **Quét UTF-8 No-BOM & LF trên `desktop/macos/`**:
   - Bao phủ tệp `.swift`, `.yml`, `.yaml`, `.plist`, `.entitlements`, `.strings`, `.xcstrings`, `.sh` trong `desktop/macos/`.
   - **Loại trừ** thư mục sinh tự động: `desktop/macos/.build/`, `desktop/macos/DerivedData/`, `desktop/macos/*.xcodeproj/`.
2. **Kiểm tra Vệ sinh & An toàn Riêng cho `desktop/macos/` (Desktop Hygiene):**
   - **Cấm** tệp artifact/signing nhạy cảm: `.p12`, `.mobileprovision`, `.cer`, `.dmg`, `.pkg`, `.app` (nhị phân đóng gói không được commit vào Git).
   - **Cấm** `com.apple.security.app-sandbox` trong mọi `.entitlements` / `.plist` / `project.yml`.
   - **Cấm** `CFBundleURLTypes` và `NSAllowsArbitraryLoads` trong mọi `.plist` / `project.yml`.
   - **Cấm** `import UIKit` trong mọi `.swift` thuộc `desktop/macos/`.
   - **Cấm** chuỗi `spctl --master-disable` trong toàn bộ `desktop/macos/`, `scripts/`, `crates/`.
   - **Cấm** `PasteButton` gọi handler mà không gọi `scheduleClipboardRedaction` / `ClipboardRedactor` (hoặc kiểm tra bắt buộc qua unit test + lint rule).
3. **Bảo toàn Không Nới Lỏng Hàng rào Rust:**
   - Giữ nguyên allowlist `unsafe` duy nhất tại `crates/mesh-sys/*` (bao gồm `crates/mesh-gui/*` bị **cấm 100%** `unsafe`).
   - Giữ nguyên allowlist `.expose_secret()` tại đúng 4 crate (`crates/mesh-crypto/*`, `crates/mesh-datapath/*`, `crates/mesh-net/*`, `crates/mesh/*`).
   - Giữ nguyên rule `GNFR-11` cấm `:443` / `:3478` ngoài `crates/mesh-core/*` và `*/tests/*` (và kiểm tra tương ứng không hardcode cổng trong logic nghiệp vụ Rust GUI).

---

## 4. Quy tắc Git & Bộ Lệnh Kiểm Định Chuẩn (Chặng 3)

### 4.1. Conventional Commits & Phạm vi Không Chồng chéo (`0% Overlap`)

- Kế thừa [coding-standards.md §6.2](./coding-standards.md): `<type>(<scope>): <subject>` (tiếng Anh, thức mệnh lệnh, `<= 72` chars) + `Refs: US-1xx, DGUI-xxx`.
- Bổ sung `<scope>` mới cho `v0.3.0`:
  - **`gui`** (`crates/mesh-gui`, `crates/mesh-sys/{gui_windows,process_windows}.rs`, `crates/mesh-net/src/gui_handoff.rs`)
  - **`macos`** (`desktop/macos/`)
  - **`ipc`** (`crates/mesh-proto/src/agent_ipc.rs`, `crates/meshd/src/ipc_service.rs`, `crates/mesh-client/`, `crates/mesh/src/client_cmds.rs`)
  - **`desktop-qa`** (`scripts/check.{ps1,sh}`, `scripts/install-*`, `.github/workflows/{ci,release}.yml`, QA docs)
- **Cấm commit (neo phạm vi rõ cho `.gitignore` và kiểm bằng `git check-ignore`, `LOW-DGUI-G2-01`):** `.exe`, `.dll`, `.pdb`, `Mesh VPN.app/`, `desktop/macos/*.xcodeproj/`, `desktop/macos/DerivedData/`, `desktop/macos/.build/`, `*.xcworkspace/`, `*.dmg`, `*.pkg`, `*.p12`, `*.pfx`, `*.mobileprovision`.

### 4.2. Bộ Lệnh Kiểm Định Chuẩn Bắt buộc Xanh 100%

```powershell
# Windows (tự chọn MSVC hoặc fallback +1.94.1-x86_64-pc-windows-gnu)
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
powershell -ExecutionPolicy Bypass -File scripts/check.ps1 -Cross
cargo build --release --locked --target x86_64-pc-windows-msvc --bin MeshVPN --bin mesh --bin meshd --bin mesh-server
cargo check --locked --target x86_64-pc-windows-gnu --bin MeshVPN --bin mesh --bin meshd --bin mesh-server
```

```sh
# Linux / macOS (CI ubuntu-latest & macos-15)
sh scripts/check.sh
sh scripts/check.sh --cross

# Trên macOS (desktop/macos/):
cd desktop/macos
xcodegen generate
swiftlint lint --strict
xcodebuild test \
  -project MeshVPNApp.xcodeproj \
  -scheme MeshVPNApp \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO
```
