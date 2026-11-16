# Desktop GUI Architecture Decision Records (`ADR-020..026`) — Mesh VPN (`v0.3.0`)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày lập | 2026-11-17 |
| Phiên bản | **1.0 (Chặng 2 — Desktop GUI Gate 2)** |
| Nhánh làm việc | `feat/desktop-gui` (không chạm `main`, `v0.1.0-rc1` và `v0.2.0`) |
| Trạng thái chung | **Proposed-for-Gate-2** (kế thừa và nối tiếp **`ADR-001..011`** trong [architecture-decision-record.md](./architecture-decision-record.md) và **`ADR-012..019`** trong [mobile-adr.md](./mobile-adr.md)) |
| Quyết định Gate 1 ràng buộc | `OQ-DGUI-01` (**A1** — Tray/Menu Bar + Full Dashboard) · `OQ-DGUI-02` (**A2** — Win32 `windows-sys` + macOS Swift 6/SwiftUI/AppKit) · `OQ-DGUI-03` (**A3** — 1-Click Service Install/Start) |
| Giải quyết bàn giao Gate 1 | Chốt dứt điểm **5/5 mục `*(KN)*`** tại [desktop-gui-product-backlog.md §5.2](../02-product-planning/desktop-gui-product-backlog.md#L422-L430) |
| Tài liệu đi kèm | [desktop-gui-tech-stack-decision.md](./desktop-gui-tech-stack-decision.md) · [desktop-gui-coding-standards.md](./desktop-gui-coding-standards.md) · [desktop-gui-system-architecture.md](./desktop-gui-system-architecture.md) · [desktop-gui-ipc-and-ui-contracts.md](./desktop-gui-ipc-and-ui-contracts.md) |

---

## Mục lục (`ADR-020..026`)

| ADR | Tiêu đề | `*(KN)*` / Truy vết chính |
|---|---|---|
| [ADR-020](#adr-020) | Crate `crates/mesh-gui` (`MeshVPN.exe`), Allowlist 4 Crate `.expose_secret()` (`crates/mesh-net/src/gui_handoff.rs`), Cô lập `unsafe` (`crates/mesh-sys`) & Tương thích MSVC + MinGW `gnu` + Non-Windows CI | **`*(KN)* #1`**, `US-102`, `US-103`, `DGUI-WIN-01`, `DGUI-SEC-01/06`, `HR-DGUI-G1-03` |
| [ADR-021](#adr-021) | Phân tách Đặc quyền Windows (`asInvoker` Medium Integrity + `ShellExecuteExW("runas")`) & Chốt **Cơ chế A — Ephemeral Authenticated Named Pipe Handoff (`MGH1`)** | **`*(KN)* #2`**, `US-104`, `US-105`, `DGUI-WIN-02/03/07`, `DGUI-SEC-01/05` |
| [ADR-022](#adr-022) | Lệnh `mesh gui`, Bảo toàn CLI `0-arg` Tự động hóa & Thuật toán An toàn Explorer 3 Điều kiện (`is_interactive_explorer_double_click`) | **`*(KN)* #3`**, `US-100`, `DGUI-UX-06`, `MED-DGUI-G1-02` |
| [ADR-023](#adr-023) | Endpoint Streaming Bugreport `POST /v1/agent/bugreport/stream` (`<= 20 MiB`, `Drop` Guard) & Bất biến **Unprivileged Sink Write** | **`*(KN)* #4`**, `US-101`, `US-105`, `US-107`, `US-112`, `DGUI-UX-07`, `BLK-DGUI-G1-01` |
| [ADR-024](#adr-024) | `POST /v1/agent/reset-identity`, Bảo toàn `bootstrap.next_pin` trong `execute_up`, Tách `1-Click Reconnect`, `GET /v1/agent/version` + `meshd --version` & **3 Tầng Timeout IPC** | **`*(KN)* #5`**, `US-101`, `US-104`, `US-110`, `US-113`, `DGUI-IPC-01..05`, `BLK-DGUI-G1-02/03`, `HR-DGUI-G1-01` |
| [ADR-025](#adr-025) | Kiến trúc `Mesh VPN.app` macOS (`LSUIElement`, Single-Window, Non-Sandboxed, `root:admin` `gid=80`), Khắc phục 3 Lỗi `mobile/ios/MeshApp` & `osascript` Chống Injection | `OQ-DGUI-02/03`, `US-109..112`, `DGUI-MAC-01..06`, `HR-DGUI-G1-02` |
| [ADR-026](#adr-026) | Cài đặt/Nâng cấp/Gỡ cài đặt Windows (`MESH_WINTUN_SHA256`, Anti-TOCTOU, `Local\MeshVpnGuiSingleInstance`, `HKCU\...\Run`) & CI Packaging (`release.yml` Tường minh `MeshVPN.exe` + macOS Thứ tự Ký mã) | `US-106`, `US-108`, `US-111`, `US-114..117`, `DGUI-WIN-04/06`, `DGUI-OPS-01..05`, `BLK-DGUI-G1-03`, `MED-DGUI-G1-03` |

---

<a id="adr-020"></a>
## ADR-020 — Crate `crates/mesh-gui` (`MeshVPN.exe`), Allowlist `.expose_secret()`, Cô lập `unsafe` & Tương thích MSVC + MinGW `gnu` + Non-Windows CI (`*(KN)* #1`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt **`*(KN)* #1`** của Backlog §5.2)
- **Ngày**: 2026-11-17

### Context
- Theo `OQ-DGUI-02`, giao diện Windows `MeshVPN.exe` dùng thuần `windows-sys` (đã có `windows-sys = "0.59"` trong `Cargo.toml:109` `[V]`) với `#![windows_subsystem = "windows"]`.
- Hàng rào tĩnh trong `scripts/check.ps1:98-114` và `scripts/check.sh:81-101` (`[V]`) cưỡng chế 2 quy tắc nghiêm ngặt:
  1. Cấm mọi từ khóa `unsafe` trong `crates/` và `tools/` ngoài `crates/mesh-sys/*`;
  2. Cấm gọi `.expose_secret()` ngoài đúng 4 crate allowlist: `mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`.
- Ngoài ra, `scripts/check.ps1:164-177` tự fallback sang toolchain `+1.94.1-x86_64-pc-windows-gnu` (MinGW-w64 UCRT) khi máy không cài MSVC `link.exe`, và `scripts/check.sh` chạy `cargo clippy --workspace --all-targets --all-features -- -D warnings` + `cargo test --workspace --all-features` trên Linux/macOS (`[V]`). Nếu `crates/mesh-gui` đặt cờ linker MSVC trần hoặc không có stub non-Windows, toàn bộ CI Linux/macOS và máy Windows dùng MinGW sẽ gãy (`HR-DGUI-G1-03`).

### Options
1. **Phương án A — Tạo binary crate `crates/mesh-gui` (`[[bin]] name = "MeshVPN"`, `[lints] workspace = true`), đặt đóng gói bí mật ở `crates/mesh-net/src/gui_handoff.rs` và toàn bộ Win32 FFI ở `crates/mesh-sys/src/{gui_windows,process_windows}.rs` (CHỌN)**:
   - Không sửa allowlist 4 crate `.expose_secret()` trong `scripts/check.{ps1,sh}`; không thay đổi `deny.toml`; giữ 100% `unsafe_code = "forbid"` cho `mesh-gui`; biên dịch xanh trên MSVC, MinGW `gnu` và non-Windows stub.
2. **Phương án B — Nhét `MeshVPN.exe` làm `[[bin]]` thứ 2 trong `crates/mesh` hoặc nới rộng allowlist `.expose_secret()` sang `mesh-gui`**:
   - Nhét vào `crates/mesh` làm CLI phình phụ thuộc UI/Tokio multi-thread/Win32 GUI, lẫn lộn ranh giới kiểm toán `SEC-01` của CLI và làm xấu cấu trúc crate. Nới allowlist `.expose_secret()` làm yếu quy tắc kiểm toán `HR-DGUI-G1-03`.

### Decision
1. **Tạo crate mới `crates/mesh-gui` (`package.name = "mesh-gui"`), nâng version workspace & cập nhật `Dockerfile`:**
   - Đặt `#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]` ở đầu `crates/mesh-gui/src/main.rs` (dùng `cfg_attr` thay cho `#![windows_subsystem = "windows"]` trần để không gây cảnh báo/hiệu ứng phụ trên non-Windows) với `[[bin]] name = "MeshVPN"`.
   - Đặt **`[lints] workspace = true`** (`unsafe_code = "forbid"`, cấm `.unwrap()`, `.expect()`, `panic!()`, `indexing_slicing`).
   - Tuân thủ bất biến `mesh-crypto` duy nhất import mật mã (`HR-DGUI-G2-02`): `crates/mesh-gui/Cargo.toml` phụ thuộc `mesh-crypto = { workspace = true, default-features = false }` (dùng `Secret<String>`, `sha256_digest`, `ct_eq_bytes`, `verify_file_sha256`), **cấm** import trực tiếp `sha2` hoặc `subtle`.
   - Cung cấp module `#[cfg(not(windows))]` stub trong `crates/mesh-gui/src/main.rs` (trả về thông báo rõ `"MeshVPN GUI binary is supported only on Windows"` và `ExitCode::FAILURE`) trong khi vẫn giữ các module logic OS-neutral (`state`, `validation`, `handoff_codec`, `logging`, `ipc_client`) biên dịch và chạy unit test trên cả Linux/macOS/Windows!
   - Cập nhật [`Dockerfile`](../../Dockerfile#L32-L66) Stage 1: bổ sung `COPY crates/mesh-gui/Cargo.toml crates/mesh-gui/Cargo.toml`, `mkdir -p crates/mesh-gui/src`, và thêm `mesh-gui` vào vòng lặp sinh dummy `main.rs` trước `cargo fetch --locked` để CI `docker-build-and-lab` & Release `build-server-container` luôn xanh (`BLK-DGUI-G2-03`).
   - Nâng `[workspace.package] version = "0.3.0"` (cùng version nội bộ tại `Cargo.toml:40-47`) đồng bộ với `desktop/macos/project.yml` (`MARKETING_VERSION = "0.3.0"` — `HR-DGUI-G2-03`).
2. **Giữ nguyên 100% allowlist 4 crate `.expose_secret()`**:
   - Thêm module **`crates/mesh-net/src/gui_handoff.rs`** (nằm trong `mesh-net`, vốn thuộc allowlist và có feature `desktop-os`):
     - Cung cấp các hàm đóng gói an toàn nhận `PreAuthToken` hoặc `&mesh_crypto::Secret<String>`: `build_up_handoff_payload(...) -> AppResult<Zeroizing<Vec<u8>>>` và `build_rotate_key_handoff_payload(...) -> AppResult<Zeroizing<Vec<u8>>>` (chỉ gọi `.expose_secret()` tại đây để dựng JSON `AgentUpRequest` / `AgentRotateKeyRequest` bên trong `Zeroizing<Vec<u8>>`).
     - `crates/mesh-gui` nắm giữ `Secret<String>` / `Zeroizing<String>` (hoặc `MobileJoinUri`) và truyền thẳng sang `mesh_net::gui_handoff`, **tuyệt đối không** gọi `.expose_secret()` trong `crates/mesh-gui`.
3. **Cô lập 100% Win32 `unsafe` FFI vào `crates/mesh-sys`**:
   - Thêm **`crates/mesh-sys/src/gui_windows.rs`** (Tray `Shell_NotifyIconW`, `TaskbarCreated`, `CreateWindowExW`, Common Controls `InitCommonControlsEx`, `SetProcessDpiAwarenessContext`, `ShellExecuteExW`, Named Pipe handoff `CreateNamedPipeW`/`GetNamedPipeClientProcessId`/`ImpersonateNamedPipeClient`, Clipboard + `SetTimer`, `HKCU\...\Run`, `SHGetKnownFolderPath` + `CoTaskMemFree` dọn shortcut `.lnk`, `Local\MeshVpnGuiSingleInstance` + `Local\MeshVpnGuiShutdownEvent`, `UnprivilegedSinkWriter` Atomic Temp-Sibling `.part` + `FILE_FLAG_OPEN_REPARSE_POINT`, anti-TOCTOU `FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT` copy, SCM read/write) và **`crates/mesh-sys/src/process_windows.rs`** (`is_interactive_explorer_double_click()`, detached process launch).
   - Toàn bộ HANDLE/HICON/HFONT/HMENU/HKEY trong `crates/mesh-sys` bọc trong RAII (`OwnedWinHandle` / `OwnedIcon` / `OwnedRegKey` / `OwnedGdiObj`) với `Drop` tự giải phóng và mọi khối `unsafe` đều có `// SAFETY:` comment.
4. **Tương thích MSVC + MinGW `x86_64-pc-windows-gnu` + Zero `embed-resource`/`winres`**:
   - Không dùng `embed-resource` hay `winres` (giữ `deny.toml` không đổi 100%).
   - Thiết lập DPI Awareness tại runtime ở dòng đầu tiên của `MeshVPN.exe` thông qua `mesh_sys::gui_windows::enable_per_monitor_v2_dpi()` (gọi `SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)`).
   - Nếu cần bất kỳ linker flag đặc thù Windows MSVC nào trong `crates/mesh-gui/build.rs`, **bắt buộc** rào điều kiện `if std::env::var_os("CARGO_CFG_TARGET_ENV").as_deref() == Some(std::ffi::OsStr::new("msvc"))`.

### Consequences
- **(+) Tích cực**: Giữ nguyên allowlist `.expose_secret()`, 0 `unsafe` trong `mesh-gui`, 0 thay đổi `deny.toml`, binary gọn `<= 4 MiB` (trần `<= 6 MiB`), xanh trên cả MSVC, MinGW `gnu` và Linux/macOS CI.
- **(−) Chi phí / Giảm thiểu**: Viết lớp bọc Win32 UI primitives (`CreateWindowExW`, controls, layout DPI-scaled) trong `crates/mesh-sys` đòi hỏi kỷ luật cao → quy chuẩn hóa toàn bộ trong [desktop-gui-coding-standards.md](./desktop-gui-coding-standards.md).

---

<a id="adr-021"></a>
## ADR-021 — Mô hình Đặc quyền Windows (`asInvoker` + `runas`) & Chốt Cơ chế A: Ephemeral Authenticated Named Pipe Handoff (`*(KN)* #2`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt **`*(KN)* #2`** của Backlog §5.2)
- **Ngày**: 2026-11-17

### Context
- Trên Windows 10/11, dịch vụ `MeshVpnAgent` (`meshd.exe --service`) chạy trong Session 0 (`NT AUTHORITY\SYSTEM`), mở:
  - `\\.\pipe\mesh-agent-ro` với `RO_PIPE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"` (`crates/mesh-net/src/ipc_windows.rs:23` `[V]`) → tài khoản Medium Integrity đọc được `status`/`peers`/`ping`/`netcheck`/`version` với **0 UAC**.
  - `\\.\pipe\mesh-agent-admin` với `ADMIN_PIPE_SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"` (`ipc_windows.rs:20` `[V]`) → từ chối Filtered Token Medium Integrity bằng `ERROR_ACCESS_DENIED` (`5`).
- Khi người dùng bấm thao tác ghi (`up`, `down`, `set`, `rotate-key`, `reset-identity`, `cleanup`, `bugreport/stream`, cài/bật/gỡ service), `MeshVPN.exe` gọi `ShellExecuteExW("runas")` để sinh tiến trình High Integrity `MeshVPN.exe --elevated-worker`. Vì `ShellExecuteExW` đi qua dịch vụ `AppInfo`: (i) **cấm** truyền `mpk_*` qua `lpParameters` (`argv`/PEB/WMI lộ khóa `SEC-01`), và (ii) `ShellExecuteExW` **không** kế thừa `stdin`/`stdout` từ tiến trình cha.

### Options
1. **Phương án A — Ephemeral Authenticated Memory Named Pipe Handoff (`\\.\pipe\mesh-gui-handoff-<128bit_hex>`) (CHỌN)**:
   - `0` chạm đĩa cho `mpk_*` và one-time payload; tận dụng kết cấu `CreateNamedPipeW` + `GetNamedPipeClientProcessId` + `ImpersonateNamedPipeClient` (`SecurityIdentification` sau `0x00 WorkerHello`) trong `crates/mesh-sys`; vừa truyền được bí mật chiều xuống (`UpWithSecret`, `RotateKeyWithSecret`), vừa stream ngược được bugreport `<= 20 MiB` chiều lên (`ExportBugreportStream`) cho **Unprivileged Sink Write** (`ADR-023`)!
2. **Phương án B — Tệp tạm SDDL hẹp (`%LOCALAPPDATA%\MeshVPN\tmp\...` qua `--authkey-file`)**:
   - Vẫn ghi `mpk_*` thô lên ổ đĩa dù có SDDL hẹp; không hỗ trợ stream ngược `.tar` `<= 20 MiB` về tiến trình Medium Integrity; dễ gặp lỗi dọn dẹp nếu tiến trình bị kill đột ngột.

### Decision
1. **Chốt Phương án A (`Ephemeral Authenticated Named Pipe Handoff`)** cho mọi tương tác giữa `MeshVPN.exe` (`asInvoker`, Medium Integrity) và worker nâng quyền `MeshVPN.exe --elevated-worker --handoff-pipe <pipe_name>` (High Integrity):
   - **Sinh tên pipe ngẫu nhiên CSPRNG (`128 bit`)**: `\\.\pipe\mesh-gui-handoff-<32_lowercase_hex>` tạo từ `rand::rngs::OsRng` (`getrandom`).
   - **Cờ tạo pipe chống Pipe Squatting & Remote Access**: `FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED` kết hợp `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS` (`PIPE_UNLIMITED_INSTANCES` hoặc max instances = `1`). Nếu `CreateNamedPipeW` trả `ERROR_ACCESS_DENIED` / pipe đã tồn tại, fail-closed ngay.
   - **SDDL Handoff Pipe & Cờ SQOS Phía Client (`BLK-DGUI-G2-04`)**:
     - Server tạo pipe với SDDL **`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<CurrentUserSid>)`** (cho phép `SYSTEM`, `BUILTIN\Administrators` và `CurrentUserSid` — hỗ trợ cả Split-Token UAC lẫn **Standard User Over-the-Shoulder (OTS) UAC**).
     - `HandoffPipeClient` (`--elevated-worker`, High Integrity) bắt buộc mở pipe qua `CreateFileW` với flags **`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED`** để khóa mức impersonation ở `SecurityIdentification` (chặn rủi ro server nâng quyền từ token client).
   - **Khởi chạy & Xác thực Peer 2 Lớp Không Rẽ `OpenProcessToken` (`SEE_MASK_NOCLOSEPROCESS`, `BLK-DGUI-G2-04`)**:
     - `MeshVPN.exe` gọi `ShellExecuteExW` với `lpVerb = "runas"`, `fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`, `lpFile = <canonical_abs_path_to_MeshVPN.exe>`, `lpParameters = "--elevated-worker --handoff-pipe \\\\.\\pipe\\mesh-gui-handoff-<hex>"` (**0 secret, 0 đường dẫn đích `SaveFileDialog` trong `lpParameters`**).
     - Lấy `child_pid = GetProcessId(sei.hProcess)` (bọc `hProcess` trong `OwnedWinHandle`).
     - Vì `inspect_named_pipe_peer` ở `0` byte đọc sẽ bị rơi vào `OpenProcess`/`OpenProcessToken` (nổ `ERROR_ACCESS_DENIED (5)` khi Medium-Integrity GUI kiểm tra High-Integrity hoặc OTS-Admin worker!), quy trình bắt tay bắt buộc tuân thủ trình tự:
       1. **`GetNamedPipeClientProcessId(pipe_handle) == child_pid`** (chặn mọi tiến trình khác cùng user nối trộm vào pipe);
       2. Đọc Frame **`0x00 = WorkerHello`** (`13` bytes, timeout `<= 5_000 ms`) do worker ghi ngay khi vừa kết nối (`>= 1` byte đã được ghi vào pipe);
       3. Gọi trực tiếp **`ImpersonateNamedPipeClient(pipe_handle)`** (nhân Windows cấp thread token mức `SecurityIdentification` mà **không** cần `SeImpersonatePrivilege` hay `OpenProcessToken`) bọc trong RAII `ImpersonationGuard` (`RevertToSelf`), rồi gọi `OpenThreadToken(..., TOKEN_QUERY, 1, ...)` + `CheckTokenMembership` xác nhận `is_builtin_admin || is_local_system` trước khi phát Frame `0x01` chứa `mpk_*` (**cấm** fallback sang `OpenProcessToken`).
   - **Wire Framing nhị phân `MGH1`**:
     - Mỗi bản tin có header `9` byte: `[magic: "MGH1" (4B)][frame_type: u8 (1B)][len: u32 LE (4B)][payload: len bytes]`:
       - `0x00` = `WorkerHello` (`Worker -> GUI`, `payload_len = 4`, payload `u32 LE protocol_version = 1`, tổng `13` bytes — ghi trước khi `GUI` xác thực & gửi `0x01`)
       - `0x01` = `HandoffRequest` (`GUI -> Worker`, JSON `<= 64 KiB` — dùng `Zeroizing<Vec<u8>>` khi chứa `UpWithSecret`/`RotateKeyWithSecret`)
       - `0x02` = `HandoffStreamHeader` (`Worker -> GUI`, `total_bytes: u64`, `scrubbed_items: u32`)
       - `0x03` = `BugreportChunk` (`Worker -> GUI`, raw `.tar` bytes, mỗi chunk `<= 64 KiB`, tổng `<= 20 MiB`)
       - `0x04` = `HandoffResponse` (`Worker -> GUI`, JSON `Result<AgentActionResponse, ErrorEnvelope>` `<= 64 KiB`)
   - **Zeroize & Hủy Nhanh Khi UAC Cancel (`ERROR_CANCELLED = 1223`) hoặc Timeout (`15 s`–`30 s`)**:
     - Ngay khi `ShellExecuteExW` trả lỗi `ERROR_CANCELLED` (`1223`) hoặc timeout chờ kết nối handoff (`15_000 ms` sau khi UAC trả về, tối đa `120_000 ms` trong lúc user đang nhìn hộp thoại UAC), `MeshVPN.exe` thực hiện `CancelIoEx`, đóng `OwnedWinHandle` của handoff pipe, và **`Zeroize::zeroize` toàn bộ `Zeroizing<Vec<u8>>` / `Secret<String>` trong `<= 100 ms`** (`DGUI-WIN-07`, `DGUI-PERF-04`). Không retry UAC lặp vô hạn.

### Consequences
- **(+) Tích cực**: `0` byte `mpk_*` chạm đĩa, `0` byte `mpk_*` trong `argv`/WMI/PEB, chặn pipe hijacking kể cả từ cùng user nhờ check `GetNamedPipeClientProcessId == child_pid` + `BA/SY`, hỗ trợ OTS UAC của Standard User, và dùng chung luôn cho Unprivileged Sink Write bugreport streaming.
- **(−) Chi phí / Giảm thiểu**: Phải giữ pipe listener sẵn sàng **trước** khi gọi `ShellExecuteExW` để tránh race condition khi worker vừa khởi động → thiết lập sẵn instance pipe trước khi gọi `ShellExecuteExW`, bọc bằng timeout & `CancellationToken`.

---

<a id="adr-022"></a>
## ADR-022 — Lệnh `mesh gui` & Thuật toán An toàn 0-arg Windows Explorer Double-Click (`*(KN)* #3`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt **`*(KN)* #3`** của Backlog §5.2)
- **Ngày**: 2026-11-17

### Context
- Tại `v0.1.0-rc1`, `crates/mesh/src/cli.rs:29-30` khai báo `command: TopCommand` bắt buộc; chạy `mesh.exe` từ Windows Explorer với `0` tham số (`argc == 1`) làm `Cli::parse()` (`crates/mesh/src/main.rs:52`) in lỗi ra `stderr` và thoát exit code `2` sau vài mili-giây ("cửa sổ đen chớp tắt").
- Tuy nhiên, nếu `mesh` tự ý mở GUI mọi lúc chạy 0-arg, mọi script automation, pipe, unit test `cli.rs`, CI runner, hay gọi `mesh` trong shell tương tác (`pwsh`/`cmd`/`bash`) hoặc `Task Scheduler` (`CREATE_NEW_CONSOLE`) sẽ bị treo hoặc sai exit code (`MED-DGUI-G1-02`).

### Options
1. **Phương án A — Giữ `mesh` `SUBSYSTEM:CONSOLE`, thêm `ClientCommand::Gui` (`mesh gui`), và chỉ auto-launch `MeshVPN.exe` trên Windows 0-arg khi thỏa đồng thời 3 điều kiện xác minh qua `mesh_sys::process_windows::is_interactive_explorer_double_click()` (CHỌN)**:
   - Không làm gãy bất kỳ hành vi CLI/script/test nào; giải quyết dứt điểm trải nghiệm người dùng Windows lỡ nhấp đúp `mesh.exe`.
2. **Phương án B — Chuyển `mesh.exe` sang `SUBSYSTEM:WINDOWS` + `AttachConsole` hoặc auto-launch chỉ bằng `GetConsoleProcessList == 1`**:
   - `AttachConsole` làm hỏng pipe redirection (`mesh status --json > out.json`) trên Windows; chỉ kiểm tra `GetConsoleProcessList == 1` dễ false-positive với `CREATE_NEW_CONSOLE` / Task Scheduler / test runner.

### Decision
1. **Thêm subcommand `Gui` vào `ClientCommand` (`crates/mesh/src/client_cmds.rs`) & Dependency `mesh-sys` (`BLK-DGUI-G2-02`)**:
   - Bổ sung `[target.'cfg(windows)'.dependencies] mesh-sys.workspace = true` vào `crates/mesh/Cargo.toml` để `crates/mesh` gọi trực tiếp `mesh_sys::process_windows`.
   - `mesh gui` tìm và khởi chạy tách tiến trình GUI không chặn shell:
     - **Windows**: tìm `MeshVPN.exe` theo thứ tự ưu tiên (1) cùng thư mục với `std::env::current_exe()` (`mesh.exe`), (2) `%ProgramFiles%\Mesh\MeshVPN.exe`; khởi chạy bằng `mesh_sys::process_windows::spawn_detached_gui(path)` (`CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`, `0` cửa sổ console con), rồi trả `ExitCode::SUCCESS`.
     - **macOS**: tìm `Mesh VPN.app` tại `/Applications/Mesh VPN.app` (hoặc cạnh bundle cài đặt); gọi `/usr/bin/open -a "/Applications/Mesh VPN.app"` (hoặc bundle path đã xác thực không có metacharacter) với stdin/stdout/stderr null, trả `ExitCode::SUCCESS`.
     - **Linux / Thiếu GUI binary / Headless**: fail-closed trả `AppError::not_found(...)` / `AppError::unavailable(...)` với thông báo có cấu trúc ra `stderr` và thoát `ExitCode::FAILURE` (`!= 0`), không treo.
2. **Thuật toán 0-arg Safe Dispatch trong `crates/mesh/src/main.rs` (trước `Cli::parse()`)**:
   - Giữ nguyên `#[command(subcommand)] pub(crate) command: TopCommand` trong `Cli` (bảo đảm `Cli::try_parse_from(["mesh"])` trong unit test luôn trả `Err`, giữ nguyên semantics `clap` 100%).
   - Chỉ trên `#[cfg(target_os = "windows")]`, khi `std::env::args_os().len() == 1`:
     - Kiểm tra lần lượt **3 điều kiện đồng thời (AND)**:
       1. `std::io::stdin().is_terminal() && std::io::stdout().is_terminal() && std::io::stderr().is_terminal()` **VÀ** không có biến môi trường `CI` (non-empty) hoặc `MESH_NO_GUI_AUTOLAUNCH` (non-empty);
       2. **`mesh_sys::process_windows::is_interactive_explorer_double_click()`** trả về `Ok(true)`:
          - **(a) `GetConsoleProcessList(&mut buf, 2) == 1`**: tiến trình `mesh.exe` là tiến trình duy nhất gắn với console mới được cấp phát (loại bỏ `cmd.exe`, `pwsh.exe`, `powershell.exe`, `wt.exe` IDE terminal);
          - **(b) Xác minh tiến trình cha trực tiếp là `explorer.exe`**: dùng `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` tìm `PROCESSENTRY32W` của `GetCurrentProcessId()` để lấy `th32ParentProcessID`, mở `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent_pid)`, kiểm tra **`GetProcessTimes` (`parent_creation_time < self_creation_time`)** chống tái sử dụng PID, và kiểm tra **`QueryFullProcessImageNameW`** khớp `<WindowsDir>\explorer.exe` (case-insensitive canonical match).
       3. Tồn tại tệp `MeshVPN.exe` hợp lệ (không phải symlink bất thường) ở cạnh `mesh.exe` hoặc `%ProgramFiles%\Mesh\MeshVPN.exe`.
     - Nếu đủ cả 3 điều kiện: gọi `spawn_detached_gui(&gui_exe)` và thoát `ExitCode::SUCCESS` (`0`).
     - Mọi trường hợp khác (terminal, pipe, `CI=1`, `MESH_NO_GUI_AUTOLAUNCH=1`, `CREATE_NEW_CONSOLE`, Task Scheduler, hoặc lỗi thiếu `MeshVPN.exe`): rơi xuống `Cli::parse()` bình thường → in usage + gợi ý 1 dòng *"Hint: run 'mesh gui' or open MeshVPN.exe / Mesh VPN.app for the desktop interface."* (qua `after_help` hoặc thông điệp bổ sung) và thoát **exit code `2`** trong `< 1 s`.

### Consequences
- **(+) Tích cực**: Double-click `mesh.exe` từ Windows Explorer mở ngay `MeshVPN.exe` không nháy đen; 100% script/pipe/test/CI/Task Scheduler vẫn nhận exit code `2` tất định.
- **(−) Chi phí / Giảm thiểu**: Nếu `MeshVPN.exe` chưa tồn tại ở thư mục giải nén lẫn `%ProgramFiles%\Mesh\`, fallback về `Cli::parse()` thoát mã `2` rõ ràng không bị kẹt.

---

<a id="adr-023"></a>
## ADR-023 — Endpoint Bugreport Streaming `POST /v1/agent/bugreport/stream` (`<= 20 MiB`) & Bất biến Unprivileged Sink Write (`*(KN)* #4`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt **`*(KN)* #4`** của Backlog §5.2)
- **Ngày**: 2026-11-17

### Context
- Trong `v0.1.0-rc1`, `POST /v1/agent/bugreport` (`crates/meshd/src/ipc_service.rs:163-195` `[V]`) tạo archive trong `state_dir/bugreports/` (`/var/db/mesh/bugreports/` `0700 root:wheel` trên macOS; `C:\ProgramData\Mesh\bugreports\` `SY+BA` trên Windows) rồi trả về đường dẫn `BugreportResponse.bundle_path`.
- GUI người dùng thường không đọc được trực tiếp thư mục đặc quyền đó (`BLK-DGUI-G1-01`). Mặt khác, nếu cho tiến trình đặc quyền (`meshd` hoặc `--elevated-worker`) tự mở và ghi thẳng vào đường dẫn `SaveFileDialog` / `NSSavePanel` do user chọn sẽ tạo lỗ hổng leo thang đặc quyền **Arbitrary File Overwrite (NTFS Junction/Oplock / Symlink TOCTOU EoP)**.

### Options
1. **Phương án A — Giữ `POST /v1/agent/bugreport` cho CLI, bổ sung `POST /v1/agent/bugreport/stream` trên `meshd-admin` (chunk `64 KiB`, giới hạn `<= 20 MiB`, RAII `Drop` guard xóa tạm) + Bất biến Unprivileged Sink Write ở tiến trình GUI không đặc quyền (CHỌN)**:
   - Bảo toàn 100% `0700 root:wheel` & `SY+BA` của `state_dir`, đạt `0` mật khẩu trên macOS `gid=80`, chặn hoàn toàn Arbitrary File Overwrite EoP trên cả 2 OS, và không cấp phát `Vec` `20 MiB` trong RAM.
2. **Phương án B — Cho `meshd` / worker `runas` nhận `dest_path` trong JSON và tự ghi ra thư mục user**:
   - Mở lỗ hổng EoP kinh điển (Symlink/Junction/Oplock race) và làm `meshd` phụ thuộc vào quyền truy cập thư mục cá nhân/TCC của user trên macOS (`~/Downloads` TCC prompt).

### Decision
1. **Giữ nguyên CLI Endpoint**: `POST /v1/agent/bugreport` trên `meshd-admin` và `BugreportResponse` (`crates/mesh-proto/src/agent_ipc.rs:348-355`) giữ nguyên 100% cho `mesh bugreport`.
2. **Bổ sung Endpoint Streaming `POST /v1/agent/bugreport/stream` (CHỈ trên `IpcService::build_admin_router`)**:
   - Chấp nhận bodyless `POST` (không yêu cầu `Json` body; bỏ qua/cho phép `{}` hoặc body rỗng).
   - Route `build_ro_router` không đăng ký endpoint này → tự động trả `404` / từ chối ở tầng `meshd-ro`.
   - `meshd` gọi `create_bugreport_tar_bundle` với trần `MAX_BUGREPORT_ARCHIVE_BYTES = 20 * 1024 * 1024` (`20_971_520` bytes = `DEFAULT_DESKTOP_MAX_BUGREPORT_BYTES` trong `crates/mesh-client/src/config.rs:36` `[V]`).
   - Nếu `resp.size_bytes > MAX_BUGREPORT_ARCHIVE_BYTES as u64`, từ chối fail-closed trước khi stream.
   - Bọc stream và đường dẫn tệp tạm `resp.bundle_path` trong **`GuardedBugreportStream { inner: Option<ReaderStream<tokio::fs::File>>, path: PathBuf }`**: trong `impl Drop`, bắt buộc chạy **`drop(self.inner.take())`** để đóng handle file **trước** khi gọi `std::fs::remove_file(&self.path)` — tránh lỗi khóa tệp đang mở trên Windows (`HR-DGUI-G2-03`) và bảo đảm dọn sạch khi client ngắt kết nối giữa chừng hoặc timeout!
   - Trả HTTP `200 OK` với headers:
     - `Content-Type: application/x-tar`
     - `Content-Length: <size_bytes>`
     - `X-Mesh-Scrubbed-Items: <scrubbed_items>`
     - `X-Mesh-Archive-Bytes: <size_bytes>`
     - `X-Mesh-Agent-Version: <CARGO_PKG_VERSION>` (bare SemVer, vd. `"0.3.0"`)
   - Body stream bằng `tokio_util::io::ReaderStream::with_capacity(tokio_file, 65_536)` (chunk `64 KiB`, bộ nhớ đệm tối đa `<= 64 KiB` ở cả server lẫn client).
3. **Khóa Bất biến Atomic Temp-Sibling Sink Write (`UnprivilegedSinkWriter` / `BugreportStreamWriter`, `BLK-DGUI-G2-05`, `MED-DGUI-G2-02`)**:
   - Để vừa chống Arbitrary File Overwrite EoP vừa hỗ trợ **Replace** tệp `.tar` đã tồn tại khi user xác nhận trên `NSSavePanel` / `GetSaveFileNameW`, **cấm** mở trực tiếp tệp đích bằng `O_CREAT | O_EXCL`; cả macOS và Windows đều dùng chung **Atomic Temp-Sibling Sink Write**:
     1. **Kiểm tra đích & thư mục cha**: Từ chối đường dẫn đích `dest` nằm trong thư mục hệ thống (`%SystemRoot%`, `%ProgramFiles%`, `%ProgramData%\Mesh`, `/System`, `/usr`, `/Library`, `/var/db/mesh`); xác minh thư mục cha `parent` không phải symlink/NTFS reparse point (`lstat` trên macOS; mở directory handle bằng `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` + `GetFileInformationByHandle` trên Windows); nếu `dest` đã tồn tại, xác minh `dest` là regular file (từ chối ngay nếu `dest` là symlink, reparse point, directory, FIFO/device).
     2. **Mở tệp tạm cùng thư mục `parent/.mesh-bugreport-<128bit_hex>.tar.part`**:
        - **macOS (`Mesh VPN.app`, `uid = 501` / user `gid = 80`)**: gọi trực tiếp `POST /v1/agent/bugreport/stream` qua `/var/run/meshd/meshd-admin.sock` (**`0` mật khẩu, `0` `osascript`**) và mở `.part` bằng `open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)`.
        - **Windows (`MeshVPN.exe`, Medium Integrity `asInvoker`)**: **tuyệt đối không** truyền `dest` xuống `--elevated-worker`. Worker chỉ forward frame `0x02` (`HandoffStreamHeader`), `0x03` (`BugreportChunk` `<= 64 KiB`) và `0x04` (`HandoffResponse`) qua Ephemeral Handoff Pipe `MGH1`; tiến trình Medium Integrity tự mở `.part` bằng `CreateFileW(tmp_path, GENERIC_WRITE, 0, null, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, 0)` và kiểm tra handle không mang `FILE_ATTRIBUTE_REPARSE_POINT`.
     3. **Kiểm khớp dung lượng & Atomic Rename**: Ghi tuần tự chunk `<= 64 KiB`, kiểm tra **`expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes && cumulative_bytes <= MAX_BUGREPORT_ARCHIVE_BYTES`** (từ `X-Mesh-Archive-Bytes`/`Content-Length` hoặc `HandoffStreamHeader.total_bytes`), gọi `sync_all()`, đóng handle `.part`, re-check `dest` không bị tráo thành symlink/reparse/dir, rồi thực hiện atomic rename (`libc::rename` trên macOS; `MoveFileExW(tmp, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` trên Windows). Bọc `tmp_path` trong RAII `Drop` guard tự xóa `.part` nếu stream bị cắt cụt, lỗi hoặc hủy.

### Consequences
- **(+) Tích cực**: Đóng triệt để `BLK-DGUI-G1-01`; RAM đỉnh khi xuất archive `20 MiB` chỉ tăng thêm `< 1 MiB` buffer streaming; 0 lỗ hổng EoP ghi tệp; `0` mật khẩu trên macOS `gid=80`.
- **(−) Chi phí / Giảm thiểu**: Nếu kết nối stream đứt giữa chừng, tệp sink tạm ở client bị xóa/hủy sạch và `TempBugreportFileGuard` trên `meshd` xóa tệp nguồn trong `state_dir/bugreports/`.

---

<a id="adr-024"></a>
## ADR-024 — Reset Node Identity, Bảo toàn `bootstrap.next_pin`, Tách `1-Click Reconnect`, `agent_version` Tương thích Ngược & 3 Tầng Timeout IPC (`*(KN)* #5`)

- **Trạng thái**: Proposed-for-Gate-2 (Chốt **`*(KN)* #5`** của Backlog §5.2)
- **Ngày**: 2026-11-17

### Context
- Đối chiếu mã nguồn cho thấy 4 lỗ hổng vận hành gắn trực tiếp tới `BLK-DGUI-G1-02`, `BLK-DGUI-G1-03` và `HR-DGUI-G1-01`:
  1. **`Revoked` dead-end**: `crates/mesh-store/src/nodes_repo.rs` từ chối mọi đăng ký lại bằng `pubkey` đã bị `NodeStatus::Revoked`, trong khi `execute_cleanup` (`session.rs:730-736`) chỉ dọn tài nguyên OS và giữ nguyên `keys.json` & `bootstrap.toml` → user bị kẹt chết trên GUI trừ khi tự xóa tay tệp trong `/var/db/mesh` hoặc `C:\ProgramData\Mesh`.
  2. **Mất `bootstrap.next_pin` (`SEC-04(d)`)**: `crates/mesh-client/src/session.rs:680` gọi `apply_pin_selection(&mut bootstrap, req.server_pin);` (`session.rs:2220-2231`) làm `bootstrap.next_pin = None` mỗi lần gọi `execute_up`, xóa mất pin dự phòng Server vừa push qua Netmap!
  3. **Bẫy `#[serde(deny_unknown_fields)]` trên `AgentStatusResponse` (`crates/mesh-proto/src/agent_ipc.rs:133-161`) & thiếu `meshd --version` (`crates/meshd/src/main.rs:32-44`)**: Nếu thêm field `agent_version` vào JSON của `GET /v1/agent/status`, mọi binary CLI `mesh` `v0.1.0-rc1` (vốn biên dịch với `#[serde(deny_unknown_fields)]`) sẽ lỗi `unknown field` khi gọi daemon mới!
  4. **Timeout IPC 1 tầng (`<= 1 s`) gãy `ping`/`netcheck`/`up`**: `IPC_CONNECT_TIMEOUT = 850 ms` (`crates/mesh/src/client_cmds.rs:35`) chỉ là connect timeout, còn `send_ipc_json_request` (`crates/mesh-net/src/ipc.rs:312-365`) chưa phân tầng read timeout cho `status`/`peers` (`<= 2 s`) vs `netcheck` (`10 s`) vs `ping` (`<= 35 s`) vs `meshd-admin` (`IPC_COMMAND_TIMEOUT = 30 s` tại `crates/meshd/src/ipc_service.rs:32`).

### Options
1. **Phương án A — Thêm `POST /v1/agent/reset-identity` + `ClientStateStore::delete_identity`, sửa cả `execute_up` lẫn `execute_set` giữ `next_pin`, giữ nguyên 13 trường `AgentStatusResponse` & dùng `GET /v1/agent/version` + header `X-Mesh-Agent-Version` + `meshd --version`, và chốt bảng 3 tầng timeout IPC (CHỌN)**:
   - Bảo toàn 100% tương thích ngược hai chiều với CLI `v0.1.0-rc1` (`#[serde(deny_unknown_fields)]`), giải quyết dứt điểm `Revoked`/`ReauthRequired`, `SEC-04(d)`, version check macOS/Windows, và phân tầng timeout không treo UI.
2. **Phương án B — Thêm trực tiếp `pub agent_version: String` vào `AgentStatusResponse`**:
   - Phá hỏng khả năng tương thích ngược của `mesh` CLI `v0.1.0-rc1` (có sẵn `#[serde(deny_unknown_fields)]`) khi nói chuyện với `meshd` `v0.3.0`.

### Decision
1. **Reset Node Identity (`POST /v1/agent/reset-identity` trên `meshd-admin` + CLI `mesh reset-identity`)**:
   - Đăng ký route `POST /v1/agent/reset-identity` **duy nhất trên `IpcService::build_admin_router`** (chấp nhận bodyless `POST` hoặc `{}`; trả về `AgentActionResponse { state: DaemonState::Stopped, message: "node identity reset; ready for onboarding" }`).
   - Bổ sung phương thức **`ClientStateStore::delete_identity(&self) -> AppResult<()>`** (trong `crates/mesh-client/src/hooks.rs`) và triển khai trên **đủ cả 3 implementors (`BLK-DGUI-G2-01`)**:
     - `FileClientStateStore` (`hooks.rs`): xóa nguyên tử/an toàn `keys.json` (bỏ qua `ErrorKind::NotFound`).
     - `InMemoryClientStateStore` (`hooks.rs`): xóa identity đang giữ trong RAM.
     - **`FfiStateStore` (`crates/mesh-mobile-ffi/src/bridge.rs:140`)**: gọi `self.run_bridge_io(|b| b.delete_state_file(SEALED_IDENTITY_FILENAME.to_owned())).map_err(|err| err.to_app_error())` (đối xứng `clear_netmap_cache` tại `bridge.rs:202-206`) để không lỗi `E0046` khi biên dịch workspace.
   - Trong `ClientSessionSupervisor::execute_reset_identity(&mut self)`:
     1. Chạy `self.stop_active_session_and_cleanup().await?` (hủy control/relay/datapath tasks + chạy `ResourceLedger::cleanup_all`);
     2. Xóa `netmap-cache.json` (`state_store.clear_netmap_cache()`), lưu `BootstrapConfig::default()` (`bootstrap.toml`), và gọi `self.state_store.delete_identity()?` (`keys.json`);
     3. Cập nhật `ClientRuntimeData` trong RAM (`daemon_state = DaemonState::Stopped`, `bootstrap = BootstrapConfig::default()`, `latest_netmap = None`, `peers.clear()`, `last_error = None`), **giữ tiến trình `meshd` sống 100%** (không thoát daemon, `meshd-ro`/`meshd-admin` sẵn sàng nhận enroll mới ngay).
   - Bổ sung CLI `mesh reset-identity [--yes]` (mặc định yêu cầu `--yes` nếu non-interactive hoặc hỏi xác nhận trên TTY tương tác) gọi `POST /v1/agent/reset-identity`.
2. **Bảo toàn `bootstrap.next_pin` trên CẢ `execute_up` lẫn `execute_set` (`HR-DGUI-G2-04`) & Tách 1-Click Reconnect**:
   - Đối chiếu `crates/mesh-client/src/session.rs:680` (`execute_up`) và `session.rs:752` (`execute_set`): cả hai hiện cùng gọi `apply_pin_selection(&mut bootstrap, req.server_pin)` làm `bootstrap.next_pin = None`.
   - Hợp nhất cả hai về một helper dùng chung **`update_bootstrap_trust_preserving_next_pin(&mut bootstrap, &endpoint, tls_auth_mode, req_pin, is_re_enrollment)`**:
     - Chỉ đặt `bootstrap.next_pin = None` khi `is_re_enrollment == true` (`req.preauth_key.is_some()`) **HOẶC** `bootstrap.server_endpoint.as_deref() != Some(endpoint.as_str())` **HOẶC** `bootstrap.tls_auth_mode != tls_auth_mode` **HOẶC** `bootstrap.active_pin != req_pin` (nếu chuyển pin sang `Some(new_pin)` trùng `bootstrap.next_pin` khi server vừa promote, đặt `active_pin = Some(new_pin)` và xóa `next_pin = None`).
     - Khi **1-Click Reconnect** (`execute_up` với `preauth_key: None` trên node `node_id.is_some()` cùng endpoint/mode/pin) hoặc `execute_set` giữ nguyên trust target, **giữ nguyên `bootstrap.next_pin`** (`SEC-04(d)`).
   - Trên UI (Windows & macOS):
     - **1-Click Reconnect** (node đã enroll `node_id != None` ở trạng thái `Stopped` / `Error`): gửi thẳng `AgentUpRequest { ..., preauth_key: None }` không bật modal xác nhận.
     - **Initial Enrollment / Re-enrollment có `mpk_*`**: luôn qua màn hình/modal `EnrollmentConfirmation` (hiển thị endpoint chuẩn hóa `<host>:<port>`, TLS Mode, full SPKI Fingerprint, `node_name`, và `mpk_*` đã che).
     - **`DaemonState::ReauthRequired`**: nút hành động chính điều hướng sang **Rotate Node Key** (`POST /v1/agent/rotate-key` kèm `mpk_*` `--for <node>`).
     - **`DaemonState::Revoked`**: nút hành động chính điều hướng sang **Reset Node Identity** (`POST /v1/agent/reset-identity`) về Onboarding.
3. **Đọc `agent_version` Tương thích Ngược, Nâng `Cargo.toml` `"0.3.0"` & Phân loại `LegacyPre030` (`HR-DGUI-G2-03`, `MED-DGUI-G2-01`)**:
   - Giữ nguyên 100% 13 trường của `AgentStatusResponse` (`#[serde(deny_unknown_fields)]`) để **0% rủi ro gãy `mesh` `v0.1.0-rc1`**.
   - Nâng `[workspace.package] version = "0.3.0"` trong `Cargo.toml` (khớp `desktop/macos/project.yml` `MARKETING_VERSION = "0.3.0"`); tách bạch bare SemVer `env!("CARGO_PKG_VERSION")` (`"0.3.0"`) trên header/endpoint `/v1/agent/version` khỏi chuỗi `"meshd/0.3.0"` trong `DaemonRuntimePaths`.
   - Bổ sung **`#[command(version)]`** vào `#[derive(Parser)] struct DaemonArgs` trong `crates/meshd/src/main.rs:32-44` (`meshd --version` in chuẩn SemVer của workspace).
   - Bổ sung route **`GET /v1/agent/version`** trên cả `build_ro_router` và `build_admin_router`, trả về `AgentVersionResponse` (`#[serde(deny_unknown_fields)]` trong `crates/mesh-proto/src/agent_ipc.rs`):
     ```rust
     pub struct AgentVersionResponse {
         pub agent_version: String,   // env!("CARGO_PKG_VERSION"), ví dụ "0.3.0"
         pub protocol_version: u16,   // CONTROL_PROTOCOL_VERSION (1)
         pub binary_name: String,     // DAEMON_BINARY_NAME ("meshd")
     }
     ```
   - Đồng thời gắn HTTP response header **`X-Mesh-Agent-Version: <CARGO_PKG_VERSION>`** trên mọi response của `IpcService` (via middleware/helper).
   - **Phân loại `LegacyPre030` đối với daemon `v0.1.0-rc1`**: vì `meshd` `v0.1.0-rc1` chưa có cờ `--version` (chạy `meshd --version` sẽ thoát mã `2`) và chưa có `/v1/agent/version` (`404`), phía GUI client quy ước:
     - Nếu `GET /v1/agent/status` trả `200 OK` mà thiếu header `X-Mesh-Agent-Version` **VÀ** `GET /v1/agent/version` trả `404 NotFound`, phân loại ngay `running_agent_version = LegacyPre030` và hiển thị banner **"Update Background Service"**;
     - Nếu daemon đang tắt và probe `/usr/local/libexec/mesh/meshd --version` trả exit code `2` (unknown argument `--version`), cũng phân loại là `LegacyPre030` (không báo lỗi hỏng binary).
4. **Bảng 3 Tầng Timeout IPC (Bắt buộc trên cả Rust & Swift UDS Client)**:

| Tầng | Phép toán / Endpoint | Timeout chuẩn | Quy tắc xử lý & Retry |
|---|---|---:|---|
| **Tầng 1 — Connect / Pipe-Open** | Kết nối UDS (`UnixStream::connect`) hoặc mở Named Pipe (`CreateFileW`) | **`850 ms`** (trần cứng **`1_000 ms`**) | Phát hiện daemon offline `< 1 s`. Trên Windows, nếu gặp `ERROR_PIPE_BUSY (231)`, retry backoff ngắn (vd. `50 ms`, `100 ms`, `150 ms`) trong tổng ngân sách **không vượt quá `1_000 ms`**. |
| **Tầng 2 — Read-Only Query Response** | `GET /v1/agent/status`, `GET /v1/agent/peers`, `GET /v1/agent/version` | **`2_000 ms`** | Áp dụng `tokio::time::timeout` / `DispatchWorkItem` cho toàn bộ handshake + gửi request + đọc response `<= 64 KiB` (`MAX_HTTP_BODY_BYTES`). Polling nền: **`2_000 ms`** khi Dashboard mở, **`8_000 ms`** (`5–10 s`) khi thu gọn ở Tray/Menu Bar. |
| **Tầng 3 — Active Probe & Admin Mutation / Stream** | - `POST /v1/agent/netcheck`<br>- `POST /v1/agent/ping`<br>- `meshd-admin` (`up`, `down`, `cleanup`, `set`, `rotate-key`, `reset-identity`, `bugreport`, `bugreport/stream`) | - **`10_000 ms`**<br>- **`min(count * timeout_ms + 2_000 ms, 35_000 ms)`**<br>- **`35_000 ms`** (`> IPC_COMMAND_TIMEOUT = 30 s`) | Khi đang thực thi bất kỳ lệnh Tầng 3 nào trên `meshd-admin`, GUI **tạm ngắt polling nền `meshd-ro`** (`pause_ro_polling`) để tránh nghẽn hoặc xung đột trạng thái chuyển tiếp; giải phóng và refresh ngay khi xong. |

### Consequences
- **(+) Tích cực**: Tương thích ngược 100% với `v0.1.0-rc1`, khép kín vòng đời `Revoked`/`ReauthRequired`/`next_pin`, loại bỏ 100% lỗi timeout giả `<= 1 s` khi chạy `ping`/`netcheck`/`up`/`bugreport`.
- **(−) Chi phí / Giảm thiểu**: Khi `MeshVPN.exe` / `Mesh VPN.app` kết nối tới `meshd` cũ `v0.1.0-rc1` (không có `/v1/agent/version`), giao diện hiện banner gợi ý cập nhật dịch vụ thay vì treo chờ version.

---

<a id="adr-025"></a>
## ADR-025 — Kiến trúc `Mesh VPN.app` macOS (`LSUIElement`, Single-Window, Non-Sandboxed, `gid = 80`), Sửa 3 Lỗi `MeshApp` & `osascript` An toàn

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-17

### Context
- `OQ-DGUI-02` và `OQ-DGUI-03` yêu cầu `Mesh VPN.app` trên macOS 13+ (`arm64` & `x86_64`) kết nối trực tiếp `/var/run/meshd/meshd-ro.sock` (`0666`) và `/var/run/meshd/meshd-admin.sock` (`0660 root:admin`, `MACOS_ADMIN_GID = 80` trong `crates/mesh-net/src/ipc_macos.rs:84` `[V]`), tái sử dụng UX từ `mobile/ios/MeshApp/Sources/` nhưng phải khắc phục 3 lỗi thực tế (`HR-DGUI-G1-02`), chạy single-window trên `LSUIElement` (`LOW-DGUI-G1-01`), và cài `LaunchDaemon` qua `/usr/bin/osascript` an toàn chống injection & LPE (`PLAT-06`).

### Options
1. **Phương án A — `desktop/macos/MeshVPNApp/` (XcodeGen `project.yml`, Swift 6, Non-Sandboxed `LSUIElement`, AppKit `NSStatusItem` + SwiftUI Single-Window `NSWindowController`, sửa 3 lỗi iOS, `/usr/bin/osascript` gọi script cố định từ `Contents/Resources/`) (CHỌN)**.
2. **Phương án B — Bật App Sandbox + XPC Service hoặc Mac App Store `NEPacketTunnelProvider`**:
   - App Sandbox chặn mọi kết nối tới `/var/run/meshd/*.sock` ngoài container (`DGUI-MAC-03`) và chặn `osascript`; còn `NEPacketTunnelProvider` đòi Apple Developer `$99/năm` (vi phạm mô hình `$0` của `v0.3.0`).

### Decision
1. **Non-Sandboxed + `LSUIElement` + Single-Window Dashboard**:
   - `Info.plist` đặt `LSUIElement = true`; entitlements **không** chứa `com.apple.security.app-sandbox`, `Info.plist` **không** chứa `NSAllowsArbitraryLoads` hay `CFBundleURLTypes`.
   - `AppDelegate` (`NSApplicationDelegate`) quản lý 1 `NSStatusItem` + `NSMenu` và duy nhất 1 `NSWindowController` bọc `NSHostingController<RootDashboardView>`.
   - `applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }`. Khi mở Dashboard gọi `NSApp.setActivationPolicy(.regular)` + `NSApp.activate(ignoringOtherApps: true)`; khi đóng cửa sổ trả về `NSApp.setActivationPolicy(.accessory)`. Chọn *Quit* trong Menu Bar hủy tác vụ IPC, xóa buffer nhạy cảm và thoát `<= 2 s` mà không dừng `internal.mesh.meshd`.
2. **Khắc phục 3 Lỗi Tái sử dụng từ `mobile/ios/MeshApp/Sources/`**:
   - Loại bỏ **100% `import UIKit`** và toàn bộ modifier iOS-only;
   - Tái cấu trúc `EndpointNormalizer` (đối xứng `validate_server_and_policy`) tự chuẩn hóa `<host>:<effective_port>` và **tự khóa `System CA` trên IP literal** ở cả Onboarding & `UpdateServerView`;
   - Thống nhất `ClipboardRedactor` gắn hẹn giờ xóa `NSPasteboard.general` sau `30 s` (theo `(changeCount, sha256)`) trên **cả `PasteButton` lẫn `Cmd+V`** / nút Paste fallback.
3. **Bảo mật `/usr/bin/osascript` & Đường dẫn Root**:
   - **Cấm** đưa `mpk_*`, `server_endpoint`, `node_name` hay đường dẫn `NSSavePanel` vào `osascript`.
   - Chỉ gọi `/usr/bin/osascript` khi cần cài/khởi động/nâng cấp/gỡ dịch vụ `internal.mesh.meshd` hoặc thêm ngoại lệ `socketfilterfw` opt-in, chạy bộ cài đặt cố định đóng gói trong `Contents/Resources/install-macos.sh` với đường dẫn nguồn lấy từ `Bundle.main.resourceURL` đã chuẩn hóa và kiểm tra **0** ký tự điều khiển (`\0`, `\r`, `\n`, `'`, `"`, `\`), truyền qua tham số shell đã bọc `quoted form of`.
   - `LaunchDaemon` **luôn** cài đặt tại `/usr/local/libexec/mesh/meshd` (`0755 root:wheel`), **tuyệt đối không** trỏ `ProgramArguments` vào bên trong `Mesh VPN.app`.
   - Khi user `admin` (`gid = 80`) bật/tắt VPN, xoay khóa, reset identity hoặc xuất bugreport stream (`POST /v1/agent/bugreport/stream`), giao tiếp trực tiếp qua `/var/run/meshd/meshd-admin.sock` với **`0` mật khẩu, `0` `osascript`**. Standard User (`gid != 80`) nhận `PermissionDenied` (`EACCES`) và được hướng dẫn rõ.

### Consequences
- **(+) Tích cực**: UX macOS mượt mà chuẩn native (`0` mật khẩu vận hành thường ngày cho user `admin`, `< 35 MiB` RSS idle, 1 cửa sổ duy nhất), không có LPE hay injection qua `osascript`, biên dịch kiểm chứng `$0` trên `macos-15`.
- **(−) Chi phí / Giảm thiểu**: Với bản phân phối `$0` ký ad-hoc (`US-114`), lần mở đầu tiên sau khi tải qua trình duyệt sẽ gặp Gatekeeper quarantine → tài liệu người dùng hướng dẫn trung thực mở bằng *Right-click → Open* / *Privacy & Security* hoặc script kiểm SHA-256, tuyệt đối cấm `spctl --master-disable`.

---

<a id="adr-026"></a>
## ADR-026 — Cài đặt, Nâng cấp Êm, Gỡ cài đặt Sạch & Đóng gói CI/Release (`release.yml`)

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-17

### Context
- Kiểm toán Gate 1 (`BLK-DGUI-G1-03`, `HR-DGUI-G1-03`, `MED-DGUI-G1-03`) phát hiện 4 rủi ro thực tế ở khâu cài đặt/nâng cấp/gỡ cài đặt/đóng gói:
  1. `.github/workflows/release.yml:277,283` dùng `sha256sum mesh*` — trên bash phân biệt hoa-thường sẽ bỏ sót `MeshVPN.exe`!
  2. `scripts/install-macos.sh:223-224` chạy `codesign --force -s -` vô điều kiện sau khi copy, làm thay đổi byte nhị phân so với `SHA256SUMS` và phá chữ ký thương mại Developer ID (`US-117`).
  3. Trên Windows, khi nâng cấp `MeshVPN.exe` từ `Downloads` trong lúc bản cũ đang chạy tại khay hệ thống (nắm giữ `Local\MeshVpnGuiSingleInstance` và image lock), `CopyFile` gặp **`ERROR_SHARING_VIOLATION (32)`**; đồng thời đọc `wintun.dll.sha256` từ `Downloads` dễ bị tấn công TOCTOU.
  4. Khi gỡ cài đặt trên Windows, chạy `runas` đổi ngữ cảnh user hoặc chạy dưới `SYSTEM` không xóa được `HKCU\...\Run` của user đang đăng nhập; đồng thời `install-windows.ps1:313` hiện chỉ liệt kê 4 tệp cũ mà bỏ sót `MeshVPN.exe`, `wintun.dll.sha256`, `README-WINTUN.md`.

### Options
1. **Phương án A — Chuẩn hóa đồng thời 1-click GUI installer, `install-windows.ps1`, `install-macos.sh` và `.github/workflows/release.yml` theo chuỗi toàn vẹn không đổi hash & chống TOCTOU (CHỌN)**.
2. **Phương án B — Chỉ sửa riêng GUI installer, giữ nguyên `install-windows.ps1` / `install-macos.sh` / `release.yml`**:
   - Gây lệch giữa cài bằng GUI và cài bằng script, sót `MeshVPN.exe` trong `SHA256SUMS`, và không hỗ trợ nâng cấp/gỡ sạch.

### Decision
1. **Windows 1-Click Install/Upgrade & Chống TOCTOU (`US-106`, `US-108`)**:
   - **Compile-time `MESH_WINTUN_SHA256`**: `crates/mesh-gui` đọc `option_env!("MESH_WINTUN_SHA256")` đồng bộ với `crates/meshd/src/config.rs:84` (`[V]`). Trong luồng 1-click Install/Upgrade của bản phát hành, **chỉ** chấp nhận `wintun.dll` khớp đúng `MESH_WINTUN_SHA256` nhúng sẵn (fail-closed nếu thiếu `MESH_WINTUN_SHA256` hoặc băm không khớp; không tin mù quáng tệp rời `wintun.dll.sha256` trong `Downloads`).
   - **Lock File Handle Chống TOCTOU**: trước khi băm SHA-256, mở cả 4 tệp nguồn (`MeshVPN.exe`, `meshd.exe`, `mesh.exe`, `wintun.dll`) với `FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT`, kiểm tra thuộc tính không phải reparse point/symlink, giữ nguyên các handle đang khóa đọc này suốt bước tính SHA-256 → ghi sang `%ProgramFiles%\Mesh\`.
   - **Bỏ qua Self-Copy**: chuẩn hóa canonical path nguồn vs `%ProgramFiles%\Mesh\`; nếu trùng thì bỏ qua tự ghi đè `MeshVPN.exe` (chỉ đăng ký/bật dịch vụ `MeshVpnAgent`).
   - **Giao thức Single-Instance & Đóng Êm Tray Cũ Tránh `ERROR_SHARING_VIOLATION (32)`**:
     - Mỗi thực thể `MeshVPN.exe` giữ Mutex **`Local\MeshVpnGuiSingleInstance`** (user session namespace) và lắng nghe sự kiện **`Local\MeshVpnGuiShutdownEvent`** (hoặc thông điệp `WM_APP_GRACEFUL_SHUTDOWN` gửi tới cửa sổ ẩn kèm kiểm tra phiên bản qua `SendMessageTimeoutW` / shared mapping nhỏ trong `Local\`).
     - Mở bản cùng hoặc cũ hơn → đưa cửa sổ hiện hữu lên tiền cảnh (`SetForegroundWindow`) và thoát `0`.
     - Mở bản **mới hơn** từ thư mục khác (hoặc chạy nâng cấp) → kích hoạt `Local\MeshVpnGuiShutdownEvent`, chờ thực thể cũ gọi `Shell_NotifyIconW(NIM_DELETE)`, đóng `Local\MeshVpnGuiSingleInstance` và thoát hoàn toàn (chờ handle/mutex tối đa `3_000 ms`) + dừng dịch vụ `MeshVpnAgent` trước khi ghi đè `%ProgramFiles%\Mesh\`.
   - **Gỡ cài đặt Sạch Đúng User Context (`US-115`)**:
     - Bước 1 (chạy trong **ngữ cảnh user đang đăng nhập, trước khi gọi `runas`**): xóa giá trị `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MeshVPN` và xóa các shortcut `.lnk` Mesh VPN trong Start Menu / Desktop của user hiện tại qua `SHGetKnownFolderPath` + `CoTaskMemFree` + `std::fs::remove_file` (`BLK-DGUI-G2-02`; việc tạo `.lnk` khi cài đặt do `scripts/install-windows.ps1` dùng `WScript.Shell`, không kéo crate `windows`).
     - Bước 2 (worker `runas` / `install-windows.ps1 -Uninstall`): đóng êm `MeshVPN.exe`, gọi `mesh.exe cleanup` / `ResourceLedger` cleanup, dừng và xóa service `MeshVpnAgent`, xóa đủ 8 tệp (`MeshVPN.exe`, `meshd.exe`, `mesh.exe`, `mesh-server.exe` nếu có, `wintun.dll`, `wintun.dll.sha256`, `WINTUN-LICENSE.txt`, `README-WINTUN.md`) trong `%ProgramFiles%\Mesh\`.
     - **Bảo toàn `keys.json` & `bootstrap.toml`** theo mặc định; chỉ xóa toàn bộ `C:\ProgramData\Mesh` khi người dùng chọn tường minh *"Purge identity keys"* (`-Purge`).
2. **macOS Thứ tự Ký mã Bảo toàn `SHA256SUMS` & Phân tách Uninstall (`US-111`, `US-114`, `US-115`, `US-117`)**:
   - Quy trình build/đóng gói trên `macos-15` (`.github/workflows/release.yml`):
     1. Biên dịch `meshd`, `mesh`, `mesh-server` (và ký ad-hoc `codesign --force -s -` hoặc Developer ID nếu có secrets `US-117`) **trước**;
     2. Tính `SHA256SUMS` cho `meshd`, `mesh`, `internal.mesh.meshd.plist` và đặt vào `Mesh VPN.app/Contents/Resources/`;
     3. Ký outer bundle `Mesh VPN.app` **KHÔNG dùng `--deep`** (`codesign --force -s - "Mesh VPN.app"` hoặc Developer ID + `notarytool`/`stapler`), rồi kiểm chứng `codesign -v --strict` và xác minh `shasum -a 256 -c` trong `Contents/Resources/` khớp 100%.
   - Trong `scripts/install-macos.sh` (và script đóng gói trong bundle): kiểm tra `/usr/bin/codesign -v "${DAEMON_BIN}" >/dev/null 2>&1` — **chỉ** chạy `codesign --force -s -` nếu `codesign -v` chưa hợp lệ; không tái ký đè lên chữ ký hợp lệ.
   - Phân tách rõ trên macOS: *"Uninstall Background Service"* (gỡ LaunchDaemon, `/usr/local/libexec/mesh/meshd`, `/usr/local/bin/mesh`, `ResourceLedger` cleanup, giữ `/var/db/mesh/{keys.json, bootstrap.toml}` trừ khi `--purge`) với hành động xóa `/Applications/Mesh VPN.app`.
3. **Sửa `.github/workflows/release.yml` (`DGUI-OPS-01`)**:
   - Windows job biên dịch `--bin MeshVPN --bin mesh --bin meshd --bin mesh-server` kèm `MESH_WINTUN_SHA256`, kiểm tra kích thước `MeshVPN.exe <= 6 * 1024 * 1024` bytes (cảnh báo nếu `> 4 MiB`), chạy `cargo check --target x86_64-pc-windows-gnu --bin MeshVPN ...`, và liệt kê tường minh `MeshVPN.exe mesh.exe meshd.exe mesh-server.exe wintun.dll` khi tạo `SHA256SUMS` (cấm glob `mesh*`).

### Consequences
- **(+) Tích cực**: Không còn lỗi `ERROR_SHARING_VIOLATION (32)` khi nâng cấp, không sót `MeshVPN.exe` trong `SHA256SUMS`, không vỡ hash macOS `SHA256SUMS`, tương thích liền mạch cả `$0` ad-hoc lẫn `US-117` Developer ID / Authenticode.
- **(−) Chi phí / Giảm thiểu**: Nếu máy Windows có nhiều tài khoản người dùng cục bộ khác nhau tự bật `HKCU\...\Run` riêng, tài liệu cài đặt ghi rõ giới hạn OS: mỗi tài khoản tự xóa `HKCU` của mình hoặc xóa thủ công khi gỡ ứng dụng trên máy dùng chung.
