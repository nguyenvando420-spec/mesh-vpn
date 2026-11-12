# Coding Standards — Mesh VPN (Rust 1.94.1)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-12 |
| Phiên bản | **2.2 (Gate 2 Round 2 Revision)** — Chuẩn kỹ thuật **Rust `1.94.1` (`edition = "2024"`)** cập nhật đồng bộ sau phản biện độc lập Vòng 1 & Vòng 2 của `agile-critic` & `agile-codex` |
| Áp dụng cho | `agile-developer`, `agile-qa`, `agile-devops` (và toàn bộ mã Rust, PowerShell, POSIX sh, TOML trong dự án) |
| Liên kết | [tech-stack-decision.md](./tech-stack-decision.md) · [architecture-decision-record.md](./architecture-decision-record.md) · Rule tự nạp [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) · Cấu hình [`rust-toolchain.toml`](../../rust-toolchain.toml), [`rustfmt.toml`](../../rustfmt.toml), [`clippy.toml`](../../clippy.toml), [`deny.toml`](../../deny.toml), [`.editorconfig`](../../.editorconfig) |
| Cưỡng chế | `scripts/check.ps1` (Windows) và `scripts/check.sh` (Linux/macOS) chạy cục bộ **và** trong CI; bắt buộc xanh 100% trước khi bàn giao |

> **Nguyên tắc tối thượng**: Dù có bao nhiêu `agile-developer` lập trình song song, toàn bộ codebase phải đọc như được viết bởi **một kỹ sư hệ thống Rust xuất sắc duy nhất**. Mọi quy tắc dưới đây được cưỡng chế tự động bằng trình biên dịch `rustc`, `rustfmt`, `clippy -D warnings`, `cargo-deny` và script kiểm tra tĩnh. **Cấm tự ý gắn `#[allow(clippy::...)]` để lách luật** nếu không có lý do kỹ thuật chính đáng ghi ngay trên dòng đó.

---

## 0. Ngôn ngữ trong Mã nguồn & Tài liệu

| Phạm vi | Ngôn ngữ bắt buộc |
|---|---|
| Mã nguồn (`.rs`), tên biến/hàm/kiểu, doc comment (`///`), comment nội dòng (`//`), thông điệp lỗi, trường log, thông báo CLI, tên test, commit message | **100% Tiếng Anh** |
| Tài liệu thiết kế và vận hành trong `docs/` | Tiếng Việt (giữ nguyên thuật ngữ kỹ thuật tiếng Anh) |

---

## 1. Formatting Rules (`rustfmt` & `.editorconfig`)

| Hạng mục | Quy tắc chuẩn | Công cụ cưỡng chế |
|---|---|---|
| **Formatter** | **`cargo fmt`** (`rustfmt` theo cấu hình `rustfmt.toml`, `edition = "2024"`, `style_edition = "2024"`) | `cargo fmt --all -- --check` |
| **Indent** | **4 dấu cách (spaces)** cho `.rs`; **2 dấu cách** cho `.toml`, `.yml`, `.json`, `.plist`, `.service`, `.sh`; **4 dấu cách** cho `.ps1` | `rustfmt.toml`, `.editorconfig` |
| **Độ rộng dòng** | Tối đa **100 cột** (`max_width = 100`) theo chuẩn chính thức của Rust Style Guide | `rustfmt.toml` |
| **Dấu nháy & Chuỗi** | Chuỗi chuẩn dùng `"..."`; regex hoặc đường dẫn Windows có nhiều `\` dùng raw string `r#"..."#` | `rustfmt` |
| **Dấu phẩy cuối (Trailing comma)** | Bắt buộc có dấu phẩy cuối ở các danh sách struct, enum, match arms và tham số hàm viết trên nhiều dòng | `rustfmt` |
| **Thứ tự `use` (Imports)** | Phân thành **3 nhóm** cách nhau bởi 1 dòng trống, sắp xếp theo bảng chữ cái (`reorder_imports = true`):<br>1. Thư viện chuẩn (`std::`, `core::`, `alloc::`)<br>2. Crates bên thứ ba (`tokio::`, `axum::`, `serde::`, `tracing::`…)<br>3. Crates nội bộ trong workspace & module hiện tại (`mesh_core::`, `crate::`, `super::`, `self::`)<br>**Cấm** dùng `use ...::*;` (wildcard import), trừ trong khối `#[cfg(test)] mod tests { use super::*; }` | `rustfmt`, `clippy::wildcard_imports` |
| **Bảng mã & Kết thúc dòng** | **UTF-8 KHÔNG BOM (No BOM)** cho mọi tệp trong repo (BOM làm lỗi parser TOML/Rust; `scripts/check.*` sẽ báo đỏ ngay nếu phát hiện BOM `0xEF 0xBB 0xBF`). Kết thúc dòng là **LF** cho mọi tệp, trừ `*.ps1`, `*.bat`, `*.cmd` dùng **CRLF** | `.editorconfig`, `.gitattributes`, `scripts/check.*` |

### Ví dụ nhóm `use` đúng chuẩn

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mesh_core::error::{AppError, ErrorKind};
use mesh_core::types::{NodeId, OverlayIp};
use crate::peer::PeerTable;
```

---

## 2. Naming Conventions & Cấu trúc Workspace

### 2.1. Quy tắc đặt tên định danh

| Đối tượng | Quy tắc | Ví dụ chuẩn |
|---|---|---|
| **Tên Crate (`crates/`)** | `kebab-case`, có tiền tố `mesh-` (trừ binary `mesh` và `meshd`) | `mesh-core`, `mesh-crypto`, `mesh-datapath`, `mesh-sys` |
| **Tên Module & File (`.rs`)** | `snake_case`, ngắn gọn, không dùng tên chung chung vô nghĩa (`util.rs`, `helpers.rs`, `common.rs` bị cấm) | `relay_map.rs`, `spki_pin.rs`, `hosts_block.rs`, `utun_macos.rs` |
| **Struct / Enum / Trait / Type alias** | `PascalCase`; từ viết tắt giữ chữ hoa đầu tiên theo chuẩn Rust API Guidelines (`Uuid`, `Http`, `Stun`, `Spki`, `Ip`, `Uds`) | `NodeRecord`, `SpkiPinVerifier`, `StunBindingRequest`, `OverlayIp` |
| **Enum Variant** | `PascalCase` (không lặp lại tên enum ở đầu variant) | `ErrorKind::PinMismatch`, `PathMode::Direct`, `PathMode::Relay` |
| **Hàm / Phương thức / Biến / Tham số** | `snake_case`; phương thức lấy giá trị (getter) **không** có tiền tố `get_` (`node.id()`, `node.overlay_ip()`) | `verify_spki_pin()`, `local_udp_port`, `peer_pubkey` |
| **Hàm chuyển đổi kiểu** | Tuân thủ chuẩn Rust: `as_*` (mượn rẻ `&self`), `to_*` (sao chép/cấp phát), `into_*` (tiêu thụ `self`) | `as_bytes()`, `to_socket_addr()`, `into_inner()` |
| **Hằng số (`const`) & Biến tĩnh (`static`)** | `SCREAMING_SNAKE_CASE`, luôn ghi rõ kiểu dữ liệu | `pub const DEFAULT_TUN_MTU: u16 = 1280;` |
| **Bảng & Khóa trong `redb` (`mesh-store`)** | Tên bảng `snake_case` số nhiều (`nodes`, `preauth_keys`, `audit_events`, `server_identity`); trường thời điểm kết thúc bằng `_at_ms` (`u64` Unix epoch milliseconds UTC) | `TABLE_NODES`, `expires_at_ms`, `created_at_ms` |
| **HTTP / WebSocket Endpoint** | Tiền tố `/v1/`, danh từ số nhiều `kebab-case`; trường JSON `snake_case` | `POST /v1/nodes/register`, `GET /v1/netmap/stream`, `GET /v1/relay` |
| **Listener Quan sát (`SEC-14`)** | Đúng 3 đường dẫn chỉ-đọc: `/healthz`, `/readyz`, `/metrics` trên listener tách biệt | `GET /healthz`, `GET /readyz`, `GET /metrics` |
| **Khóa cấu hình TOML & Biến môi trường** | TOML dùng `snake_case`; biến môi trường dùng `MESH_<UPPER_SNAKE_CASE>` | `control_tcp_port`, `trusted_proxies`, `MESH_AUTHKEY_FILE` |
| **Lệnh & Cờ CLI (`mesh`)** | `mesh <noun> <verb> --kebab-case-flag` | `mesh preauthkey create --for macbook --ttl 1h`, `mesh set --server-pin sha256:...` |
| **Sự kiện Log (`event`) & Metrics** | Log `event` dùng `snake_case` (`<noun>_<past_verb>`); Metric dùng `mesh_<subsystem>_<name>_<unit>` | `event = "node_registered"`, `mesh_relay_dropped_packets_total` |

### 2.2. Tổ chức Mã Đặc thù Hệ điều hành (`cfg(target_os)`) & Cô lập `mesh-sys`

1. **Logic cốt lõi phải độc lập hệ điều hành (OS-Neutral)**:
   - Toàn bộ `mesh-core`, `mesh-crypto`, `mesh-proto`, `mesh-store` và phần lõi của `mesh-datapath` không được chứa lệnh gọi syscall hệ điều hành trực tiếp, đảm bảo biên dịch và chạy unit test trên mọi máy.
2. **Trừu tượng hóa bằng Trait + Fake**:
   - Mọi thao tác chạm tới hệ điều hành trong `mesh-net` (`TunDevice`, `RouteManager`, `NetMonitor`, `HostsEditor`, `PrivilegeIpc`, `ServiceRunner`) được định nghĩa bằng **Trait an toàn** kèm một bản cài đặt giả lập trong bộ nhớ (`FakeTunDevice`, `FakeRouteManager`…) để kiểm thử toàn bộ luồng nghiệp vụ trên cả Windows, macOS và Linux mà không cần quyền `root`/Administrator.
3. **Tách tệp theo hệ điều hành rõ ràng**:
   - Cài đặt thực tế cho từng OS đặt trong tệp riêng: `<module>_linux.rs`, `<module>_macos.rs`, `<module>_windows.rs` (hoặc `<module>_unix.rs` cho phần dùng chung giữa Linux và macOS), được gắn thuộc tính `#[cfg(target_os = "...")]` tại khai báo `mod`.
   - **Cấm** dùng `std::env::consts::OS` để rẽ nhánh logic nghiệp vụ lúc chạy (chỉ được dùng để điền chuỗi метаdata `os`/`arch` khi báo cáo `OPS-10`).
4. **Ranh giới FFI duy nhất tại `crates/mesh-sys` & Cấu hình `[lints]` tránh lỗi `E0453`**:
   - Mọi lệnh gọi hàm C/OS không an toàn (`libc::ioctl`, `libc::setsockopt`, `windows_sys::Win32::...`) **chỉ được phép nằm trong `crates/mesh-sys`** và phải bọc thành hàm Rust an toàn trả về `Result<T, SysError>` trước khi xuất sang `mesh-net`.
   - Trong Rust, một crate kế thừa `[lints] workspace = true` (nơi `[workspace.lints.rust] unsafe_code = "forbid"`) **không thể** ghi đè bằng `#![allow(unsafe_code)]` (trình biên dịch sẽ báo lỗi `E0453: allow(unsafe_code) overruled by outer forbid(unsafe_code)`). Vì vậy:
     - **9/10 crates** (`mesh`, `meshd`, `mesh-server`, `mesh-core`, `mesh-crypto`, `mesh-proto`, `mesh-datapath`, `mesh-net`, `mesh-store`) khai báo `[lints] workspace = true` trong `Cargo.toml` của mình.
     - **Chỉ riêng `crates/mesh-sys/Cargo.toml` KHÔNG đặt `[lints] workspace = true`**, mà khai báo bảng lint riêng như sau:
       ```toml
       # crates/mesh-sys/Cargo.toml — ONLY crate allowed to perform OS FFI
       [lints.rust]
       unsafe_code = "allow"
       unsafe_op_in_unsafe_fn = "deny"
       missing_debug_implementations = "warn"
       unreachable_pub = "warn"

       [lints.clippy]
       undocumented_unsafe_blocks = "deny"
       unwrap_used = "deny"
       expect_used = "deny"
       panic = "deny"
       todo = "deny"
       unimplemented = "deny"
       dbg_macro = "deny"
       indexing_slicing = "deny"
       let_underscore_must_use = "deny"
       await_holding_lock = "deny"
       ```
     - Mọi khối `unsafe { ... }` bên trong `crates/mesh-sys` bắt buộc phải có chú thích `// SAFETY: ...` giải trình bất biến con trỏ, độ dài bộ đệm và vòng đời handle ngay phía trên.

---

## 3. Type Safety, Memory Safety & Error Handling

### 3.1. Cấm tuyệt đối trong Code Production (Clippy `-D warnings` sẽ chặn build)

| Hành vi bị cấm | Quy tắc Clippy / Cưỡng chế | Giải pháp bắt buộc thay thế |
|---|---|---|
| Từ khóa **`unsafe`** ngoài `crates/mesh-sys` | `[workspace.lints.rust] unsafe_code = "forbid"` (cho 9/10 crates; riêng `mesh-sys` tự khai báo `unsafe_op_in_unsafe_fn = "deny"` + `undocumented_unsafe_blocks = "deny"`) | Viết mã Rust an toàn 100%; nếu bắt buộc gọi OS API thì đóng gói vào `crates/mesh-sys` kèm chú thích `// SAFETY:` |
| **`.unwrap()`** và **`.expect(...)`** | `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"` | Dùng toán tử `?`, `ok_or(...)`, `ok_or_else(...)` hoặc xử lý nhánh `None`/`Err` tường minh |
| **`panic!(...)`**, **`todo!()`**, **`unimplemented!()`**, **`unreachable!()`** | `clippy::panic = "deny"`, `clippy::todo = "deny"`, `clippy::unimplemented = "deny"` | Trả về `Result<T, AppError>` (`ErrorKind::Internal` hoặc `ErrorKind::InvalidArgument`) |
| Truy cập mảng/slice trực tiếp **`slice[i]`** trong bộ parser mạng | `clippy::indexing_slicing = "deny"` | Dùng `.get(i)`, `.get(start..end)`, hoặc `split_at_checked()` để không bao giờ panic do `index out of bounds` khi nhận gói UDP/WebSocket dị dạng |
| Bỏ qua `Result`: **`let _ = fallible_fn();`** | `clippy::let_underscore_must_use = "deny"` | Xử lý lỗi, trả về qua `?`, hoặc ghi log `warn!`/`debug!` nếu cố tình bỏ qua khi dọn dẹp |
| **`dbg!(...)`**, **`println!(...)`**, **`eprintln!(...)`** trong daemon/thư viện | `clippy::dbg_macro = "deny"`, `clippy::print_stdout = "deny"`, `clippy::print_stderr = "deny"` | Dùng `tracing::{info, warn, error, debug}` (chỉ binary CLI `crates/mesh` được phép in kết quả ra stdout/stderr cho người dùng) |
| Ép kiểu số nguyên làm mất mát ngầm (`as u16`, `as usize`) trên dữ liệu mạng | `clippy::cast_possible_truncation = "warn"` | Dùng `u16::try_from(val)?` hoặc kiểm tra biên tường minh trước khi ép kiểu |
| Giữ `std::sync::MutexGuard` qua điểm `.await` | `clippy::await_holding_lock = "deny"` | Sao chép dữ liệu cần thiết rồi nhả lock trong một block `{ ... }` trước khi `.await` |
| Hằng số cổng `443` / `3478` rải rác (`GNFR-11`) | `scripts/check.{ps1,sh}` quét tĩnh | Chỉ khai báo tại `mesh_core::defaults` và đọc từ cấu hình / `relay_map` |

> *(Lưu ý: Trong khối `#[cfg(test)]` hoặc thư mục `tests/`, cho phép dùng `.unwrap()` / `.expect("...")` để mã kiểm thử ngắn gọn, rõ ràng).*

### 3.2. Thiết kế theo Kiểu Miền ("Parse, Don't Validate")

Dữ liệu đi vào từ biên (JSON, TOML, gói UDP, CLI, tệp `hosts`) phải được chuyển ngay thành các **Newtype đã kiểm chứng bất biến** trong `crates/mesh-core`:
- `NodeName`: kiểm chứng ngay trong `NodeName::parse(s: &str) -> Result<Self, AppError>` rằng độ dài `1..=63`, chỉ gồm `[a-z0-9-]`, không bắt đầu/kết thúc bằng `-`, không chứa `\n`, `\r`, `#`, khoảng trắng, và không nằm trong danh sách tên cấm (`localhost`, `broadcasthost`, `wpad`, `isatap`, `local`) (`US-004 AC3`, `US-038 AC5`).
- `OverlayIp`: bọc `std::net::Ipv4Addr` đã kiểm chứng thuộc dải CIDR overlay hợp lệ.
- `Port`: bọc `std::num::NonZeroU16` (`1..=65535`).
- `PublicKey`: bọc `[u8; 32]` (không dùng `Vec<u8>` hay `String` trần để giữ khóa trong bộ nhớ).
- `SpkiPin`: bọc `[u8; 32]` (băm SHA-256 của SPKI DER), parse từ chuỗi `"sha256:<64_hex_chars>"`.

### 3.3. Phân loại Lỗi Thống nhất (`mesh_core::error::AppError`)

Không dùng `anyhow` trong các crate thư viện. Toàn bộ hệ thống dùng `thiserror` kết hợp cấu trúc `AppError` phân tách rõ **nguyên nhân nội bộ (chỉ ghi log)** và **thông điệp công khai an toàn (được phép trả qua mạng/CLI)**:

```rust
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Internal,           // Lỗi nội bộ; không bao giờ tiết lộ chi tiết ra mạng
    InvalidArgument,    // Đầu vào sai định dạng
    Unauthenticated,    // Sai/hết hạn/đã dùng pre-auth key hoặc sai challenge (SEC-05: 1 thông báo chung)
    PermissionDenied,   // Không đủ quyền OS trên socket/pipe (SEC-14, PLAT-01, PLAT-06)
    NodeRevoked,        // Thiết bị đã bị thu hồi (US-029, US-034 AC5: dừng retry tự động)
    NodeKeyExpired,     // Khóa thiết bị đã hết hạn (US-031, US-034 AC5: dừng retry tự động)
    NotFound,
    Conflict,
    RateLimited,        // Vượt ngưỡng tốc độ (SEC-05, US-042)
    Unavailable,        // Lỗi tạm thời; client thử lại theo Exponential Backoff + Jitter (REL-04)
    ClockSkew,          // Đồng hồ máy lệch ra ngoài hạn chứng chỉ TLS (US-003 AC5)
    PinMismatch,        // Khóa công khai server không khớp SPKI Pin (SEC-04(c), US-003 AC7)
}

#[derive(Debug, Error)]
#[error("{op}: {public_msg}")]
pub struct AppError {
    pub kind: ErrorKind,
    pub op: &'static str,
    pub public_msg: String,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}
```

**Quy tắc xử lý lỗi**:
1. **Bảo mật thông báo xác thực (`SEC-05`, `US-004 AC4`, `US-042 AC2`)**: Khi `kind == ErrorKind::Unauthenticated`, phương thức trả lỗi ra mạng **luôn trả về duy nhất một chuỗi cố định** `"authentication failed"` và cùng một mã HTTP `401 Unauthorized` (tuyệt đối không phân biệt key không tồn tại, key hết hạn, key đã dùng hay key đã bị thu hồi).
2. **Xử lý đúng một lần (Log or Return, Never Both)**: Các tầng bên trong chỉ gắn ngữ cảnh (`op`) và trả lỗi lên trên bằng `?`; chỉ tầng biên (HTTP/WS handler, vòng lặp sự kiện nền của daemon, hoặc hàm `main`) mới ghi log lỗi.

---

## 4. Async / Tokio Concurrency & Vòng đời Tiến trình (`Graceful Shutdown ≤ 5 s`)

1. **Quản lý Vòng đời Tác vụ Nền (`CancellationToken` + `TaskTracker` / `JoinSet`)**:
   - **Cấm gọi `tokio::spawn(...)` mồ côi** không được theo dõi. Mọi tác vụ chạy nền (vòng lặp `MagicSocket`, `TunDevice`, `NetmapStream`, `DiscoScheduler`, `NetMonitor`, `AdminIpc`) phải:
     1. Nhận một `CancellationToken` (từ `tokio_util::sync::CancellationToken`).
     2. Chạy trong `tokio::task::JoinSet` hoặc `tokio_util::task::TaskTracker` của `ServiceSupervisor`.
     3. Lắng nghe `tokio::select! { _ = cancel.cancelled() => break, ... }` ở mọi vòng lặp chờ I/O hoặc timer.
2. **Ngân sách Graceful Shutdown ≤ 5 giây (`REL-08`, `US-055 AC1`)**:
   - Khi nhận tín hiệu dừng (`SIGTERM` / `SIGINT` trên Linux & macOS `launchd`, hoặc `ServiceControl::Stop` / `Shutdown` trên Windows Service):
     - `T + 0.0 s`: Kích hoạt `root_cancel.cancel()`, ngừng nhận kết nối mới.
     - `T + ≤ 1.0 s`: Đóng kết nối WebSocket Relay/Control (gửi frame Close báo offline).
     - `T + ≤ 4.0 s`: Thực thi `ResourceLedger::cleanup_all()` để gỡ route overlay, xóa khối `# BEGIN mesh … # END mesh` trong `hosts`, gỡ anchor `pf`/rule firewall và đóng đúng interface `utunN` / adapter Wintun của phiên.
     - `T + 5.0 s`: Hết hạn `tokio::time::timeout(Duration::from_secs(5), supervisor.wait())` → ghi log cảnh báo nếu còn task trễ và thoát sạch.
3. **Không bao giờ chặn Worker Thread của Tokio**:
   - Cấm gọi I/O đồng bộ nặng hoặc `std::thread::sleep` trên luồng async (dùng `tokio::time::sleep`).
   - Không giữ `std::sync::MutexGuard` hay `RwLockGuard` qua `.await` (`clippy::await_holding_lock = "deny"`).
4. **Hàng đợi Có Trần & Không Chặn cho Blind Relay (`US-025 AC6`)**:
   - Cấm dùng `tokio::sync::mpsc::unbounded_channel()` cho dữ liệu mạng.
   - Hàng đợi chuyển tiếp gói tới mỗi peer trên Relay bắt buộc dùng `mpsc::channel(256)` và đẩy gói bằng **`try_send()`**: nếu đầy thì drop gói của đích đang nghẽn ngay lập tức và tăng bộ đếm metric, tuyệt đối không gọi `.send().await` làm treo luồng đọc của người gửi.
5. **Timeout & Retry Backoff bắt buộc (`REL-04`, `GNFR-03`, `US-034`)**:
   - Mọi thao tác kết nối ra mạng phải bọc `tokio::time::timeout` (connect ≤ 10 s; đọc stream có khung heartbeat ≤ 60 s).
   - Mọi kết nối lại tới VPS dùng `mesh_core::backoff::ExponentialBackoff` (base 1 s, hệ số 2, trần 60 s cho lỗi mạng thường, trần 5 phút cho lỗi TLS/Captive Portal/clock skew/pin mismatch, kèm **full jitter** từ `OsRng`; chỉ dừng retry tự động khi nhận mã `node_revoked` hoặc `node_key_expired` trên kênh TLS đã xác thực hợp lệ theo `US-034 AC4/AC5`).

---

## 5. Security, Secret Memory Hygiene & Logging Standards

### 5.1. Bảo vệ Bí mật trong RAM bằng `Secret<T>` & `ZeroizeOnDrop` (`SEC-01`, `GNFR-02`)

Mọi khóa riêng (Node private key, Disco private key, Server identity private key) và Pre-Auth Key thô **bắt buộc** phải bọc trong kiểu `mesh_crypto::Secret<T>`:

```rust
use std::fmt;
use serde::{Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Restricted accessor: scripts/check.* verifies this is only called in allowlisted crates.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}
```

**Quy tắc cưỡng chế `SEC-01`**:
1. **Cấm** lưu khóa bí mật dưới dạng `String`, `Vec<u8>` hay `[u8; 32]` trần trong các struct cấu hình, trạng thái hay bản tin.
2. Phương thức `.expose_secret()` chỉ được phép xuất hiện trong: `crates/mesh-crypto`, `crates/mesh-datapath` (khi truyền khóa vào `Tunn::new`), `crates/mesh-net` (mô-đun `keystore` ghi tệp khóa `0600`), và `crates/mesh` (đúng 1 lần khi in pre-auth key vừa tạo từ lệnh `preauthkey create`). Script `scripts/check.{ps1,sh}` sẽ báo đỏ nếu phát hiện `.expose_secret()` ở bất kỳ tệp nào khác!
3. **Không nhận Pre-Auth Key qua tham số dòng lệnh mặc định**: ưu tiên `--authkey-file <path>`, `--authkey-stdin` hoặc biến môi trường `MESH_AUTHKEY_FILE` để tránh lộ khóa trên `ps aux` (`US-004 AC1`).

### 5.2. Chuẩn Structured Logging (`tracing` — `OPS-01`, `US-043`)

1. Toàn bộ log xuất qua `tracing` dưới định dạng JSON (mặc định) với các trường chuẩn hóa:
   - Bắt buộc ở mọi bản ghi: `ts` (UTC ISO-8601/RFC-3339), `level` (`ERROR`, `WARN`, `INFO`, `DEBUG`), `component` (`control`, `relay`, `stun`, `disco`, `wg`, `dns`, `route`, `store`, `admin`, `tls`, `lifecycle`), `event` (`snake_case`).
   - Trường ngữ cảnh (gắn qua `#[tracing::instrument]` hoặc span): `request_id` / `conn_id`, `node_id`, `peer_id`.
2. **Tuyệt đối cấm ghi vào log**: khóa riêng, pre-auth key, nội dung gói mạng, token, chuỗi cấu hình khóa, header `Authorization`. Bộ kiểm thử `test_no_secrets_in_outputs` chạy tự động trong CI ở cả mức `DEBUG` (`US-043 AC2/AC4`).

### 5.3. Quy tắc An toàn Máy thật & Hạ tầng (`G4`, `SEC-14`, `PLAT-01..06`)

1. **Kênh Admin IPC & Kênh Chỉ-Đọc Chẩn Đoán (`SEC-14`, `BLK-G2-03`, `Codex R2 #3`)**:
   - **Cấm tuyệt đối** mở Admin API trên TCP (`127.0.0.1`, IP overlay hay IP public).
   - **Trên Ubuntu Linux VPS (`mesh-server`)**: Sử dụng thư mục runtime riêng **`/run/mesh-server`** (`RuntimeDirectory=mesh-server`, mode **`0750`**, owner **`mesh:mesh-admin`**) và lắng nghe trên **`/run/mesh-server/admin.sock`** (mode **`0660`**, owner **`mesh:mesh-admin`**). Kiểm tra `SO_PEERCRED` kết hợp tra cứu nhóm phụ (supplementary groups) qua `getpwuid_r` + `getgrouplist` trong `mesh-sys::ipc_linux` để cho phép `uid == 0`, `uid == service_uid`, `gid == admin_gid`, hoặc thành viên nhóm `mesh-admin`.
   - **Trên Client (`meshd`)**: Sử dụng thư mục runtime riêng **`/var/run/meshd`** (trên Linux tương ứng `/run/meshd` qua `RuntimeDirectory=meshd`, mode **`0755`**, owner `root:wheel` trên macOS / `root:root` trên Linux; kiểm tra chống symlink trên các thành phần đường dẫn cha) để không bao giờ xung đột quyền/owner với `/run/mesh-server` khi VPS kiêm node (`US-056`), và tách làm **2 kênh IPC riêng biệt** trên cả 3 hệ điều hành:
     - **Kênh Admin (Read/Write — `up`, `down`, `cleanup`, `set`, `rotate-key`, `bugreport`)**: **`/var/run/meshd/meshd-admin.sock`** (`0660 root:admin` `gid = 80` trên macOS — `mesh-sys::ipc_macos` kiểm tra `getpeereid` `uid == 0` hoặc `LOCAL_PEERCRED` `xucred.cr_groups` chứa `gid == 80` kèm fallback `getgrouplist` khi `cr_ngroups == 16`; `0660 root:mesh-admin` hoặc `0600 root:root` nếu nhóm `mesh-admin` chưa tạo trên máy Linux lẻ, kiểm tra `SO_PEERCRED` + `getgrouplist`) và Windows Named Pipe **`\\.\pipe\mesh-agent-admin`** với SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (`SYSTEM` + `Administrators`) kèm `FILE_FLAG_FIRST_PIPE_INSTANCE`.
     - **Kênh Chỉ-Đọc (`status`, `peers`, `ping`, `netcheck` — 0 khóa bí mật, body ≤ 4 KiB)**: **`/var/run/meshd/meshd-ro.sock`** (`0666`, owner `root:wheel` / `root:root` trên macOS/Linux) và Windows Named Pipe **`\\.\pipe\mesh-agent-ro`** (`US-039 AC5`).
2. **Sổ cái Tài nguyên (`ResourceLedger` — `REL-08`, `US-055`, `US-056`)**: Ghi tên tài nguyên thật (`utunN`, adapter GUID, route CIDR, `ip rule` / `table 51820`, khối hosts, anchor `pf`, rule firewall) vào sổ cái `0600` (`/var/db/mesh/ledger.json` macOS, `/var/lib/meshd/ledger.json` Linux tách biệt khỏi `/var/lib/mesh/` của `mesh-server`, `C:\ProgramData\Mesh\ledger.json` Windows) **trước khi tạo**; lúc dừng hoặc khởi động lại sau crash chỉ dọn đúng tài nguyên trong sổ cái, tuyệt đối không đụng tới `utun` của iCloud Private Relay hay VPN khác (`US-060 AC3`).
3. **Khối `hosts` (`PLAT-04`, `US-038`)**: Chỉ sửa trong `# BEGIN mesh` … `# END mesh`; bảo toàn symlink `/etc/hosts -> /private/etc/hosts` và quyền `root:wheel 0644` trên macOS; bảo toàn ACL đọc cho `Users`/`Dnscache` trên Windows; hỗ trợ fallback ghi tại chỗ khi `/etc/hosts` là bind-mount trong container Linux.
4. **Chống Routing Loop (`REL-09`, `US-016`, `HR-G2-01`, `NOTE-G2-R2-03`)**: Mọi socket ngoại biên của agent phải ràng vào interface vật lý mặc định (`IP_BOUND_IF` trên macOS, `IP_UNICAST_IF` trên Windows, và trên Linux dùng `SO_MARK = 0x5d56` kết hợp bảng định tuyến `table 51820` + cặp `ip rule` `priority 51820 not fwmark 0x5d56 table 51820` & `priority 51810 table main suppress_prefixlength 0`) và ràng lại khi đổi mạng.
5. **Gọi lệnh hệ thống (`mesh_net::sysexec` — `HR-G2-01`)**: Chỉ dùng `tokio::process::Command` với **đường dẫn tuyệt đối cố định** nằm trong danh mục cho phép theo từng OS:
   - **macOS**: `/sbin/ifconfig`, `/sbin/route`, `/sbin/pfctl`, `/usr/bin/dscacheutil`, `/usr/bin/killall`, `/usr/libexec/ApplicationFirewall/socketfilterfw`, `/bin/launchctl`.
   - **Linux**: `/usr/sbin/ip`, `/sbin/ip`, `/usr/sbin/nft`, `/usr/sbin/iptables`, `/usr/sbin/ufw`, `/usr/bin/systemctl`.
   - **Windows**: Truy vấn thư mục hệ thống qua `GetSystemDirectoryW` để ghép đường dẫn tuyệt đối `...\System32\netsh.exe`, `...\System32\ipconfig.exe`, `...\System32\route.exe` (tuyệt đối không gọi tên lệnh trần như `"ipconfig.exe"` để chống hijacking đường dẫn hiện hành).
   - **Cấm** gọi qua shell (`sh -c`, `cmd /c`, `powershell -Command`) và cấm hướng dẫn `spctl --master-disable`.

---

## 6. Testing & Git Conventions

### 6.1. Quy tắc Kiểm thử (`cargo test` & `proptest`)

1. **Đặt tên & Cấu trúc**:
   - Tên hàm test theo mẫu: `test_<unit>_<scenario>_<expected>` (ví dụ: `test_register_duplicate_pubkey_returns_existing_node`).
   - Nội dung hàm test tuân thủ rõ 3 bước **`// Arrange` – `// Act` – `// Assert`**.
   - Ghi chú mã User Story & AC ngay trên hàm test: `// Traces: US-005 AC1`.
2. **Kiểm thử Dựa trên Thuộc tính / Fuzzing (`proptest`)**:
   - Mọi bộ phân tích dữ liệu đầu vào trong `mesh-proto` và `mesh-core` (STUN packet, Disco frame, Relay frame, `NodeName`, khối `hosts`, `SpkiPin`) **bắt buộc** phải có bộ test `proptest!` chạy với đầu vào ngẫu nhiên/đột biến để chứng minh 0 lần panic (`US-021 AC3`, `US-038 AC5`).
3. **Phân tách Test Thường và Test Cần Đặc quyền Hệ điều hành**:
   - `cargo test --workspace` mặc định phải chạy xanh 100% dưới tài khoản user thường trên cả Windows, macOS và Linux (nhờ hệ thống Trait + Fake trong `mesh-net`).
   - Các kịch bản chạm trực tiếp tới `/dev/net/tun`, `utun` kernel, Wintun driver hay bảng route thật được đánh dấu `#[ignore = "privileged"]` để `agile-qa` và CI chạy trong container lab (`--cap-add=NET_ADMIN --device /dev/net/tun` — `US-057`) hoặc trên runner/máy thật có quyền `root`/Administrator (`cargo test --workspace -- --ignored`).

### 6.2. Quy tắc Git & Conventional Commits

- Định dạng commit message (bằng **tiếng Anh**, thức mệnh lệnh, dòng tiêu đề ≤ 72 ký tự):
  ```text
  <type>(<scope>): <subject>

  <body giải thích lý do và thay đổi chính>

  Refs: US-0xx, SEC-0x
  ```
- `<type>` ∈ `{feat, fix, perf, refactor, test, docs, build, ci, chore, security}`.
- `<scope>` ∈ `{core, crypto, proto, datapath, net, store, sys, server, agent, cli, ci, deps, docs}`.
- **Cấm** commit tệp nhị phân biên dịch (`/target/`), khóa bí mật (`*.key`, `*.pem`), tệp DB (`*.db`, `*.redb`) hoặc `.env`.

---

## 7. Bộ Lệnh Kiểm Định Chuẩn (Standard Check Commands)

Mọi Developer bắt buộc phải chạy xanh 100% bộ lệnh kiểm định chuẩn trước khi bàn giao bất kỳ User Story nào:

| Hệ điều hành | Lệnh chạy một chạm (Standard Check Command) |
|---|---|
| **Windows (PowerShell)** | `powershell -ExecutionPolicy Bypass -File scripts/check.ps1` |
| **Linux / macOS (POSIX sh)** | `sh scripts/check.sh` |

### Các bước thực thi bên trong `scripts/check.{ps1,sh}`

1. **Kiểm tra Quy tắc Tĩnh của Repo (Repo Hygiene & Security Rules)**:
   - Quét UTF-8 BOM (`0xEF 0xBB 0xBF`) trên toàn bộ tệp nguồn/cấu hình.
   - Quét cấm từ khóa `unsafe` ngoài `crates/mesh-sys`.
   - Quét cấm gọi `.expose_secret()` ngoài danh sách 4 crate được phép (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`).
   - Quét cấm mã hóa cứng cổng `443` / `3478` ngoài `crates/mesh-core` (`GNFR-11`).
2. **Format Check**:
   ```bash
   cargo fmt --all -- --check
   ```
3. **Static Analysis & Linter (`clippy`)**:
   ```bash
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   ```
4. **Unit, Integration & Property Tests**:
   ```bash
   cargo test --workspace --all-features
   ```
5. **Kiểm tra Giấy phép (`AGPL`/`GPL`/`LGPL`), Lỗ hổng Bảo mật & Crate bị cấm (`cargo-deny`)**:
   ```bash
   cargo deny check advisories bans licenses sources
   ```
6. **Kiểm tra Cross-Target (`--cross` / CI)**:
   - Kiểm tra biên dịch cho `x86_64-pc-windows-*`, `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`.
