# Đặc tả Hợp đồng IPC & Giao diện UI Desktop — Mesh VPN (`v0.3.0`)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-architect` (`architect-gui`) |
| Ngày lập | 2026-11-17 |
| Phiên bản | **1.0 — Design Lock (Gate 2 — Chặng 2)** |
| Nhánh làm việc | `feat/desktop-gui` |
| Đầu vào chuẩn tắc | [desktop-gui-readiness-requirements.md](../01-discovery/desktop-gui-readiness-requirements.md) v1.1 (`DGUI-IPC-01..05`, `DGUI-UX-01..07`, `DGUI-SEC-01..08`) · [desktop-gui-product-backlog.md](../02-product-planning/desktop-gui-product-backlog.md) v1.1 (`US-100..117`) · [api-design.md](./api-design.md) §5 · `crates/mesh-proto/src/agent_ipc.rs` |
| Bộ tài liệu Gate 2 đi kèm (`0` mâu thuẫn) | [desktop-gui-system-architecture.md](./desktop-gui-system-architecture.md) · [desktop-gui-tech-stack-decision.md](./desktop-gui-tech-stack-decision.md) · [desktop-gui-adr.md](./desktop-gui-adr.md) (`ADR-020..026`) · [desktop-gui-coding-standards.md](./desktop-gui-coding-standards.md) |

> **Quy tắc Hợp đồng Bất biến (`v0.1.0` ↔ `v0.3.0`):**
> 1. Toàn bộ DTO trên `meshd-ro` và `meshd-admin` dùng JSON `snake_case`, thời gian `*_at_ms` (`u64` UTC ms), và gắn **`#[serde(deny_unknown_fields)]`**.
> 2. **Tuyệt đối không** sửa đổi tập trường đã phát hành của **`AgentStatusResponse`** trong `crates/mesh-proto/src/agent_ipc.rs` để bảo đảm client CLI `v0.1.0-rc1` (`#[serde(deny_unknown_fields)]`) không bao giờ gãy khi nói chuyện với `meshd v0.3.0`.
> 3. Giữ nguyên trần phân tầng: `MAX_RO_IPC_BODY_BYTES = 4_096` (`4 KiB` cho request đọc), `MAX_HTTP_BODY_BYTES = 65_536` (`64 KiB` cho JSON response/request admin — đủ `50` peers `> 4 KiB`), và **`MAX_BUGREPORT_ARCHIVE_BYTES = 20_971_520` (`20 * 1024 * 1024`)** cho duy nhất luồng stream `.tar` trên `meshd-admin`.
> 4. **0** Admin TCP listener (`SEC-14`), **0** `mpk_*` trong `argv`/log/lưu đĩa dài hạn (`SEC-01`), **0** bỏ qua TLS/TOFU (`SEC-04`), và **`ErrorKind::Unauthenticated`** luôn chỉ trả **`"authentication failed"`** (`SEC-05`).

---

## 1. Hợp đồng Dual-Channel IPC (`meshd-ro` & `meshd-admin`)

### 1.1. Bảng Định tuyến & Phân quyền Kênh (`crates/meshd/src/ipc_service.rs`)

| Kênh & Điểm cuối OS | Cơ chế Xác thực Kernel (`crates/mesh-net`, `crates/mesh-sys`) | Giới hạn Body (`DefaultBodyLimit`) | Danh sách Route Cho phép | Hành vi Khi Truy cập Trái Kênh |
|---|---|---|---|---|
| **`meshd-ro`**<br/>Win: `\\.\pipe\mesh-agent-ro`<br/>Mac: `/var/run/meshd/meshd-ro.sock`<br/>Linux: `/var/run/meshd/meshd-ro.sock` | Win SDDL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)` (`RO_PIPE_SDDL`)<br/>Mac: `0666 root:wheel` (`CallerPrivilege::ReadOnly` / `Admin`)<br/>Linux: `0666 root:root` | Request: `MAX_RO_IPC_BODY_BYTES` (`4_096 B`)<br/>Client JSON read cap: `MAX_HTTP_BODY_BYTES` (`65_536 B`) | - `GET /v1/agent/status`<br/>- `GET /v1/agent/peers`<br/>- `GET /v1/agent/version` *(MỚI)*<br/>- `POST /v1/agent/ping`<br/>- `POST /v1/agent/netcheck` | `handle_ro_fallback` trả HTTP `404 NotFound` (`ErrorKind::NotFound`); không gắn bất kỳ route mutation hay bugreport nào vào `build_ro_router`. |
| **`meshd-admin`**<br/>Win: `\\.\pipe\mesh-agent-admin`<br/>Mac: `/var/run/meshd/meshd-admin.sock`<br/>Linux: `/var/run/meshd/meshd-admin.sock` | Win SDDL: `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (`ADMIN_PIPE_SDDL`) + `verify_secured_pipe_peer` (`BA`/`SY`)<br/>Mac: `0660 root:admin` (`MACOS_ADMIN_GID = 80`) + `getpeereid` + `LOCAL_PEERCRED` + `getgrouplist`<br/>Linux: `0660 root:mesh-admin` (hoặc `0600 root:root`) + `SO_PEERCRED` + `getgrouplist` | JSON Request/Response: `MAX_ADMIN_IPC_BODY_BYTES` (`65_536 B`)<br/>Stream `.tar` duy nhất trên `/bugreport/stream`: `MAX_BUGREPORT_ARCHIVE_BYTES` (`20_971_520 B`) | Toàn bộ route `meshd-ro` **+** :<br/>- `POST /v1/agent/up`<br/>- `POST /v1/agent/down`<br/>- `POST /v1/agent/cleanup`<br/>- `POST /v1/agent/set`<br/>- `POST /v1/agent/rotate-key`<br/>- `POST /v1/agent/reset-identity` *(MỚI)*<br/>- `POST /v1/agent/bugreport`<br/>- `POST /v1/agent/bugreport/stream` *(MỚI)* | OS kernel trả `ERROR_ACCESS_DENIED (5)` / `EACCES (13)` trước khi vào HTTP; nếu lọt vào layer auth trả `403 Forbidden` (`ErrorKind::PermissionDenied`). |

### 1.2. Thương lượng Phiên bản Tương thích Ngược (`agent_version`, `ADR-024`, `DGUI-MAC-07`)

Để giải quyết triệt để mâu thuẫn giữa yêu cầu đọc phiên bản daemon chạy trong RAM với ràng buộc `#[serde(deny_unknown_fields)]` trên `AgentStatusResponse` (`crates/mesh-proto/src/agent_ipc.rs:133`):

1. **Giữ nguyên 100% 13 trường của `AgentStatusResponse`**:
   - Các trường: `daemon_state`, `node_id`, `node_name`, `fqdn`, `overlay_ip`, `overlay_cidr`, `tun_interface_name`, `tun_mtu`, `netmap_version`, `key_expires_at_ms`, `server_connection`, `self_network`, `peers`.
   - Tuyệt đối không chèn khóa JSON mới vào payload `GET /v1/agent/status` hay `GET /v1/agent/peers`.
2. **Nâng `version = "0.3.0"` & Bổ sung Header HTTP + Endpoint Riêng + Cờ CLI `meshd --version` (`HR-DGUI-G2-03`, `MED-DGUI-G2-01`)**:
   - **`Cargo.toml` (`[workspace.package]`)**: Nâng `version = "0.3.0"` (cùng các workspace crate `mesh-*` từ `"0.1.0"` -> `"0.3.0"`) khớp `MARKETING_VERSION = 0.3.0` của `desktop/macos/project.yml`, đồng thời tách bạch bare SemVer `env!("CARGO_PKG_VERSION")` (`"0.3.0"`) cho IPC khỏi chuỗi định danh `"meshd/0.3.0"` tại `DaemonRuntimePaths` (`crates/meshd/src/config.rs:88`).
   - **`DaemonArgs` (`crates/meshd/src/main.rs:32-44`)**: Thêm `version` vào `#[command(name = "meshd", version, about = "Mesh VPN background agent daemon")]`. Chạy `meshd --version` in ra `meshd <CARGO_PKG_VERSION>` (exit `0`).
   - **Header HTTP `X-Mesh-Agent-Version`**: Mọi phản hồi từ `IpcService` (`meshd-ro` và `meshd-admin`) gắn header HTTP `X-Mesh-Agent-Version: <semver>` (giá trị `env!("CARGO_PKG_VERSION")`, tức `"0.3.0"`). Client `v0.1.0-rc1` bỏ qua header HTTP chuẩn một cách tự nhiên, còn client `v0.3.0` đọc được phiên bản ngay cả trong chu kỳ polling `GET /v1/agent/status` mà không tốn thêm RTT.
   - **Endpoint `GET /v1/agent/version`** (gắn trên cả `build_ro_router` & `build_admin_router`):
     ```json
     {
       "agent_version": "0.3.0",
       "protocol_version": 1,
       "binary_name": "meshd"
     }
     ```
     Định nghĩa DTO trong `crates/mesh-proto/src/agent_ipc.rs`:
     ```rust
     #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
     #[serde(deny_unknown_fields)]
     pub struct AgentVersionResponse {
         pub agent_version: String,
         pub protocol_version: u16,
         pub binary_name: String,
     }
     ```
   - **Quy tắc Tương thích Ngược Khi Giao tiếp Với `meshd` Cũ (`v0.1.0-rc1` -> `LegacyPre030`)**:
     - Khi `GET /v1/agent/status` trả `200 OK` nhưng thiếu header `X-Mesh-Agent-Version` **và** `GET /v1/agent/version` trả `404 NotFound`, GUI **không báo lỗi**, phân loại ngay `running_agent_version = LegacyPre030` và hiển thị banner **"Update Background Service"**.
     - Khi daemon đang tắt và fallback kiểm tra `/usr/local/libexec/mesh/meshd --version` trả về exit code `2` (binary `v0.1.0-rc1` chưa có cờ `--version`), **cũng** phân loại ngay là **`LegacyPre030`** (tuyệt đối không báo lỗi hỏng tệp nhị phân).

### 1.3. Endpoint Mới `POST /v1/agent/bugreport/stream` (`ADR-023`, `DGUI-UX-07`)

Giữ nguyên `POST /v1/agent/bugreport` trả về `BugreportResponse` (`bundle_path`, `size_bytes`, `scrubbed_items`) cho CLI `mesh bugreport`. Bổ sung endpoint mới **chỉ trên `meshd-admin`**:

- **Request**: `POST /v1/agent/bugreport/stream` (chấp nhận body rỗng, `null`, hoặc `{}` — không dùng `Json` extractor bắt buộc).
- **Thực thi trên `meshd` (`crates/meshd/src/ipc_service.rs`)**:
  1. Thu thập `bootstrap`, `status`, và chạy `PingProbe::execute_netcheck` với timeout `2_000 ms` (`BUGREPORT_NETCHECK_TIMEOUT`).
  2. Gọi `create_bugreport_tar_bundle` sinh tệp `.tar` đã lọc sạch bí mật vào `state_dir/bugreports/mesh-bugreport-<ts>.tar` với giới hạn cứng `MAX_BUGREPORT_ARCHIVE_BYTES = 20 * 1024 * 1024` (`20_971_520` bytes).
  3. Mở `tokio::fs::File` và bọc qua `tokio_util::io::ReaderStream::with_capacity(file, 65_536)` (`64 KiB`/chunk) bên trong wrapper **`GuardedBugreportStream { inner: Option<ReaderStream<tokio::fs::File>>, path: PathBuf }`** gắn vào `axum::body::Body::from_stream(...)`. Trong **`impl Drop for GuardedBugreportStream`**, **BẮT BUỘC** thực thi `drop(self.inner.take());` (đóng hết OS handle `tokio::fs::File`) **trước khi** gọi `std::fs::remove_file(&self.path)` — loại bỏ 100% lỗi khóa tệp trên Windows khi stream kết thúc ở EOF, lỗi I/O hoặc client ngắt kết nối giữa chừng.
  4. Kiểm tra kích thước thực `0 < size_bytes <= MAX_BUGREPORT_ARCHIVE_BYTES` (`20_971_520`).
- **HTTP Response (`200 OK`)**:
  - Headers bắt buộc:
    - `Content-Type: application/x-tar`
    - `Content-Length: <size_bytes>`
    - `X-Mesh-Agent-Version: <semver>`
    - `X-Mesh-Archive-Bytes: <size_bytes>`
    - `X-Mesh-Scrubbed-Items: <scrubbed_items>`
    - `Cache-Control: no-store`
  - Thân phản hồi: dòng byte thô chuẩn POSIX ustar `.tar` (`1..=20_971_520` bytes).
- **Ràng buộc Atomic Temp-Sibling Sink Write phía Client (`UnprivilegedSinkWriter` / `BugreportStreamWriter`, `BLK-DGUI-G2-05`, `MED-DGUI-G2-02`)**:
  - Người dùng chọn `dest` trên `SaveFileDialog` (`OFN_OVERWRITEPROMPT`) / `NSSavePanel` (hỗ trợ cả tạo mới và **Replace** tệp `.tar` đã có).
  - Kiểm tra `dest` không nằm trong thư mục hệ thống (`C:\Windows`, `C:\Program Files`, `C:\ProgramData\Mesh`, `/System`, `/usr`, `/Library`, `/var/db/mesh`); xác minh thư mục cha `parent` không phải symlink/NTFS reparse point (`lstat` trên macOS; mở directory handle với `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` + `GetFileInformationByHandle` trên Windows); nếu `dest` đang tồn tại, xác minh `dest` là regular file (từ chối symlink/reparse/thư mục/FIFO/device).
  - Trước khi đọc stream, kiểm tra `expected_total_bytes` (từ `Content-Length` / `X-Mesh-Archive-Bytes` / `HandoffStreamHeader.total_bytes`) thỏa **`0 < expected_total_bytes <= 20_971_520`**.
  - Tạo tệp tạm độc nhất cùng thư mục `parent/.mesh-bugreport-<128bit_hex>.tar.part`:
    - macOS: `open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)`.
    - Windows: `CreateFileW(tmp_path, GENERIC_WRITE, 0, null, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, 0)` + kiểm tra handle không mang `FILE_ATTRIBUTE_REPARSE_POINT`.
  - Đọc tuần tự từng chunk `<= 64 KiB` (không cấp phát cả 20 MiB trong RAM), kiểm tra bất biến kết thúc luồng **`expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes <= 20_971_520`** (từ chối ngay nếu cắt cụt `< expected_total_bytes` hoặc vượt trần) → `sync_all()` → đóng handle tệp tạm → kiểm tra lại `dest` không bị tráo thành symlink/reparse/dir → atomic rename (`libc::rename` trên macOS; `MoveFileExW(tmp, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` trên Windows). RAII guard tự xóa `.part` ngay nếu hủy/lỗi và giữ nguyên tệp cũ của user.

### 1.4. Endpoint Mới `POST /v1/agent/reset-identity` & CLI `mesh reset-identity` (`ADR-024`, `DGUI-UX-02`)

Dùng để phục hồi node bị thu hồi (`DaemonState::Revoked`) hoặc chuyển sang mạng Mesh mới **mà không cần gỡ dịch vụ nền `meshd`**:

- **IPC Route (`meshd-admin` ONLY)**: `POST /v1/agent/reset-identity`
  - **Request**: chấp nhận body rỗng, `null`, hoặc `{}` (`AgentResetIdentityRequest {}` phía tài liệu/test nếu tuần tự hóa `{}`).
  - **Response (`200 OK`)**: `AgentActionResponse`:
    ```json
    {
      "state": "stopped",
      "message": "node identity reset cleanly; ready for enrollment"
    }
    ```
- **Thứ tự Thực thi Nguyên tử trong `ClientSessionSupervisor::execute_reset_identity` (`crates/mesh-client/src/session.rs`)**:
  1. Gọi `self.stop_active_session_and_cleanup().await?` — dừng Control/Relay/Datapath và chạy sạch `ResourceLedger::cleanup_all()` (xóa routes, khối `# BEGIN mesh ... # END mesh`, firewall, đóng TUN; nếu đã cleanup khi nhận `NodeRevoked` thì idempotent trả `Ok`).
  2. Gọi `self.state_store.clear_netmap_cache()?` — xóa `netmap-cache.json` (bỏ qua nếu không tồn tại).
  3. Gọi `self.state_store.save_bootstrap(&BootstrapConfig::default())?` — ghi đè nguyên tử `bootstrap.toml` về rỗng (`node_id: None`, `server_endpoint: None`, `active_pin: None`, `next_pin: None`) với quyền `0600` / SDDL `SY+BA`.
  4. Gọi `self.state_store.delete_identity()?` *(method mới trên trait `ClientStateStore` tại `crates/mesh-client/src/hooks.rs:140`, bắt buộc triển khai trên cả **3 implementors**: `FileClientStateStore` xóa `keys.json`/`.tmp` bỏ qua `NotFound`, `InMemoryClientStateStore` xóa RAM, và **`FfiStateStore` tại `crates/mesh-mobile-ffi/src/bridge.rs:140`** gọi `self.run_bridge_io(|b| b.delete_state_file(SEALED_IDENTITY_FILENAME.to_owned())).map_err(|err| err.to_app_error())` đối xứng với `clear_netmap_cache` tại `bridge.rs:222-225`)*.
  5. Cập nhật `ClientRuntimeData` dưới async write lock: đặt `daemon_state = DaemonState::Stopped`, `node_id = None`, `node_name = None`, `fqdn = None`, `overlay_ip = None`, `overlay_cidr = None`, `overlay_dns_ip = None`, `key_expires_at_ms = None`, `latest_netmap = None`, `bootstrap = BootstrapConfig::default()`, `control_connected = false`, `relay_rtt_ms = None`, `last_error = None`, `protocol_incompatible = false`, `migration_pending_endpoint = None`, `overlay_conflict_warning = None`, `lockdown_warning = None`, `private_dns_warning = None`, `local_candidates.clear()`.
  6. **Giữ sống dịch vụ `meshd`**, giữ nguyên `IpcService` (`meshd-ro`/`meshd-admin`) và `RoamingLoop`. Lần poll kế tiếp `GET /v1/agent/status` trả `daemon_state: "stopped"`, `node_id: null`, `server_connection: null` → GUI chuyển tự động sang trạng thái **`Unconfigured` (Onboarding)**.
- **CLI tương ứng (`crates/mesh/src/client_cmds.rs`)**:
  - `mesh reset-identity [--yes]`: nếu thiếu `--yes` trong TTY tương tác có thể yêu cầu xác nhận hoặc fail-closed yêu cầu truyền `--yes` khi non-TTY để tránh script xóa nhầm danh tính. Gửi `POST /v1/agent/reset-identity` qua `meshd-admin`.

### 1.5. Chuẩn hóa `update_bootstrap_trust_preserving_next_pin` Trên Cả `execute_up` & `execute_set` (`SEC-04(d)`, `HR-DGUI-G2-04`)

Sửa đồng bộ khiếm khuyết tại cả `execute_up` (`crates/mesh-client/src/session.rs:680`) và `execute_set` (`crates/mesh-client/src/session.rs:752`) bằng một helper dùng chung duy nhất:

```rust
fn update_bootstrap_trust_preserving_next_pin(
    bootstrap: &mut BootstrapConfig,
    endpoint: &str,
    tls_auth_mode: TlsAuthMode,
    req_pin: Option<SpkiPin>,
    is_re_enrollment: bool,
)
```

1. **Quy tắc `same_trust` chung cho cả `execute_up` (`POST /v1/agent/up`) & `execute_set` (`POST /v1/agent/set`)**:
   - Kiểm tra đầy đủ cả 3 trường trust:
     `let same_trust = bootstrap.server_endpoint.as_deref() == Some(endpoint) && bootstrap.tls_auth_mode == tls_auth_mode && bootstrap.active_pin == req_pin;`
   - Luôn gán `bootstrap.server_endpoint = Some(endpoint.to_owned()); bootstrap.tls_auth_mode = tls_auth_mode;`.
   - Nếu **`same_trust == true`**: **BẮT BUỘC giữ nguyên `bootstrap.active_pin` và `bootstrap.next_pin`** (không gọi `apply_pin_selection` xóa `next_pin = None`!).
   - Nếu **`same_trust == false`**:
     - Trường hợp edge-case vừa promote `next_pin` (`!is_re_enrollment && tls_auth_mode == TlsAuthMode::SpkiPin && req_pin.is_some() && req_pin == bootstrap.next_pin`): chuyển `bootstrap.active_pin = req_pin; bootstrap.next_pin = None;` sạch sẽ (vì pin dự phòng đã được đẩy lên làm active).
     - Ngược lại (đổi Control endpoint, chuyển sang `SystemCa`, hoặc cấu hình pin mới hoàn toàn): gọi `apply_pin_selection(bootstrap, req_pin)` (`active_pin = req_pin`, `next_pin = None`).
2. **Hành vi cụ thể theo Endpoint**:
   - **`POST /v1/agent/up` (`preauth_key: None` — 1-Click Reconnect)**: Chỉ hợp lệ khi `bootstrap.node_id.is_some()` (nếu `None` trả `400 InvalidArgument`). GUI đọc `server_connection` mới nhất từ `GET /v1/agent/status` để gửi đúng `control_endpoint` & `active_pin` hiện hành (kể cả khi daemon vừa tự promote `next_pin` qua Netmap trước đó) với `is_re_enrollment = false` -> bảo toàn 100% `bootstrap.next_pin`.
   - **`POST /v1/agent/up` (`preauth_key: Some("mpk_...")` — Initial Enrollment / Re-enrollment)**: Bắt buộc đi qua `EnrollmentConfirmationModal` trước khi gọi `/v1/agent/up`; truyền `is_re_enrollment = true`, sau đó `apply_registration_to_bootstrap` ghi đè `pin_set` mới từ `RegisterNodeResponse.netmap.pin_set`.
   - **`POST /v1/agent/set` (`AgentSetRequest`)**: Luôn gọi `update_bootstrap_trust_preserving_next_pin(..., is_re_enrollment = false)` nên giữ nguyên `NodeId`, `keys.json`, và `next_pin` nếu `endpoint`, `tls_auth_mode` và `active_pin` không đổi.

### 1.6. Tham chiếu Nhanh Toàn bộ DTOs `crates/mesh-proto/src/agent_ipc.rs`

Mọi DTO dưới đây đều mang `#[serde(deny_unknown_fields)]`:

| DTO | Route | Trường chính (`snake_case`) | Lưu ý Bảo mật & Kiểm biên |
|---|---|---|---|
| `AgentStatusResponse` | `GET /v1/agent/status`, `GET /v1/agent/peers` | `daemon_state`, `node_id`, `node_name`, `fqdn`, `overlay_ip`, `overlay_cidr`, `tun_interface_name`, `tun_mtu`, `netmap_version`, `key_expires_at_ms`, `server_connection`, `self_network`, `peers` | Giữ nguyên 13 trường; `0` secret; có thể > `4 KiB` khi 50 peers (`MAX_HTTP_BODY_BYTES = 65_536`). |
| `AgentVersionResponse` *(MỚI)* | `GET /v1/agent/version` | `agent_version: String`, `protocol_version: u16`, `binary_name: String` | Phản hồi `< 256 B`; `meshd` cũ trả `404` -> client coi là `None`. |
| `PingRequest` / `PingResponse` | `POST /v1/agent/ping` | Req: `target`, `count (1..=64)`, `force_direct`, `timeout_ms`<br/>Resp: `target_name`, `target_overlay_ip`, `samples[] { seq, via, endpoint, rtt_ms }`, `packets_sent`, `packets_received`, `loss_percent`, `rtt_{min,avg,max}_ms` | Chạy trên `meshd-ro`; timeout Tier 3 tối đa `35_000 ms`. |
| `NetcheckResponse` | `POST /v1/agent/netcheck` | `udp_egress_ok`, `stun_reachable`, `stun_endpoint_tested`, `reflexive_ipv4`, `ipv6_available`, `nat_mapping`, `nat_note`, `control_tcp_reachable`, `control_tcp_endpoint_tested`, `relay_rtt_ms`, `diagnostic_hint` | Chạy trên `meshd-ro`; timeout Tier 3 `10_000 ms`. |
| `AgentUpRequest` | `POST /v1/agent/up` | `server_endpoint`, `port_override: Option<Port>`, `server_pin: Option<SpkiPin>`, `preauth_key: Option<String>`, `node_name: Option<NodeName>` | `Drop` zeroize `preauth_key`; `Debug` in `"[REDACTED]"`. |
| `AgentSetRequest` | `POST /v1/agent/set` | `server_endpoint`, `server_pin: Option<SpkiPin>` | Không chứa `preauth_key`; bảo toàn `NodeId` & `keys.json`. |
| `AgentRotateKeyRequest` | `POST /v1/agent/rotate-key` | `preauth_key: String` | `Drop` zeroize; `Debug` in `"[REDACTED]"`. |
| `AgentActionResponse` | `up`, `down`, `cleanup`, `set`, `rotate-key`, `reset-identity` | `state: DaemonState`, `message: String` | — |
| `BugreportResponse` | `POST /v1/agent/bugreport` | `bundle_path: String`, `size_bytes: u64`, `scrubbed_items: u32` | Giữ nguyên cho CLI; GUI dùng `POST /v1/agent/bugreport/stream`. |
| `ErrorResponse` | Mọi lỗi HTTP 4xx/5xx | `error: { kind, code, message, request_id }` | `kind == "unauthenticated"` LUÔN có `message == "authentication failed"` (`SEC-05`). |

---

## 2. Giao thức Dây Ephemeral Handoff Pipe (`\\.\pipe\mesh-gui-handoff-<id>`, `ADR-021`, `ADR-023`)

### 2.1. Thông số Thiết lập & Xác thực Kênh Handoff Windows

| Thuộc tính | Giá trị Khóa cứng | Lý do Bảo mật |
|---|---|---|
| **Tên Pipe** | `\\.\pipe\mesh-gui-handoff-<32_hex_chars>` (128-bit CSPRNG từ `getrandom` / `OsRng`) | Không thể đoán trước; tránh race hoặc squat theo PID/timestamp. |
| **Cờ `CreateNamedPipeW` (Server GUI)** | `PIPE_ACCESS_DUPLEX \| FILE_FLAG_FIRST_PIPE_INSTANCE \| FILE_FLAG_OVERLAPPED` + `PIPE_TYPE_BYTE \| PIPE_READMODE_BYTE \| PIPE_WAIT \| PIPE_REJECT_REMOTE_CLIENTS` | Chặn squatter chiếm tên pipe và chặn kết nối từ mạng SMB/remote. |
| **Cờ `CreateFileW` (`HandoffPipeClient` Worker)** | `GENERIC_READ \| GENERIC_WRITE` + **`SECURITY_SQOS_PRESENT \| SECURITY_IDENTIFICATION \| FILE_FLAG_OVERLAPPED`** | Giới hạn mức impersonation xuống `SecurityIdentification` khi tiến trình High Integrity kết nối tới pipe của user thường. |
| **SDDL Pipe** | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<CurrentUserSid>)` | Cho phép `MeshVPN.exe` (`CurrentUserSid`) tạo pipe server và worker High Integrity (`BA`/`SY` — kể cả admin khác tài khoản trong **Over-The-Shoulder UAC**) mở pipe. |
| **Lệnh `ShellExecuteExW("runas")`** | `lpFile = <canonical_path_to_MeshVPN.exe>`, `lpParameters = "--elevated-worker --handoff-pipe \\\\.\\pipe\\mesh-gui-handoff-<32_hex>"`, `fMask = SEE_MASK_NOCLOSEPROCESS \| SEE_MASK_NOASYNC` | **0** secret (`mpk_*`), **0** user save path, **0** shell (`cmd.exe`/`powershell.exe`). Kiểm tra tham số không chứa metacharacter/NUL. |
| **Xác thực Peer 2 Lớp (`BLK-DGUI-G2-04`)** | 1. `GetNamedPipeClientProcessId(pipe) == GetProcessId(hProcess)`<br/>2. Đọc đủ `13` bytes Frame **`0x00 WorkerHello`** (`timeout <= 5_000 ms`, validate `MGH1` & `protocol_version == 1`)<br/>3. Gọi **`ImpersonateNamedPipeClient(pipe)`** (`SecurityIdentification`) -> **`OpenThreadToken(..., TOKEN_QUERY, 1, ...)`** -> **`CheckTokenMembership`** (`is_builtin_admin \|\| is_local_system`) + RAII `RevertToSelf` | Khắc phục hoàn toàn lỗi `ERROR_CANNOT_IMPERSONATE (1368)` -> `OpenProcessToken` bị **`ERROR_ACCESS_DENIED (5)`** từ Medium Integrity lên elevated/OTS worker; chặn 100% tiến trình Medium Integrity khác cùng user trước khi phát Frame `0x01`. **CẤM** gọi `OpenProcess`/`OpenProcessToken` từ Medium Integrity. |
| **Hủy & Timeout** | Nếu `ShellExecuteExW` trả `ERROR_CANCELLED (1223)` hoặc quá `15_000 ms` chờ worker connect sau khi `ShellExecuteExW` trả về (tổng trần chờ người dùng xác nhận hộp thoại UAC tối đa `120_000 ms`, hoặc `hProcess` thoát sớm): đóng pipe, zeroize `Zeroizing` RAM & đóng `hProcess` trong **`<= 100 ms`** | Bảo đảm `mpk_*` không tồn tại quá 100 ms sau khi bấm Cancel UAC (`DGUI-WIN-07`, `ADR-021`). |

### 2.2. Định dạng Khung Nhị phân `MGH1` (Binary Framing)

Mọi thông điệp đi qua `\\.\pipe\mesh-gui-handoff-<32_hex>` dùng khung 9-byte header cố định:

```text
+--------------------+------------------+-------------------------+----------------------------------+
| Bytes 0..4 (4 B)   | Byte 4 (1 B)     | Bytes 5..9 (4 B LE)     | Bytes 9..(9 + len)               |
| Magic = b"MGH1"    | frame_type (u8)  | payload_len (u32 LE)    | Payload bytes                    |
+--------------------+------------------+-------------------------+----------------------------------+
```

| `frame_type` | Tên Frame | Chiều | Trần `payload_len` | Định dạng & Ngữ nghĩa Payload |
|---:|---|---|---:|---|
| **`0x00`** | `WorkerHello` | Worker → GUI | `== 4 B` *(khung `13 B`)* | Payload `u32 LE protocol_version = 1`. Worker **bắt buộc** ghi ngay sau `CreateFileW` để kernel cho phép `GUI` gọi `ImpersonateNamedPipeClient` trước khi gửi `0x01`. |
| **`0x01`** | `HandoffRequest` | GUI → Worker | `<= 65_536 B` (`64 KiB`) | UTF-8 JSON `HandoffRequest` (chỉ được gửi **sau** khi `0x00 WorkerHello` + `CheckTokenMembership` đạt; cấp phát & đọc trong `Zeroizing<Vec<u8>>`, zeroize ngay sau sử dụng). |
| **`0x02`** | `HandoffStreamHeader` | Worker → GUI | `<= 4_096 B` | UTF-8 JSON `{ "total_bytes": u64, "scrubbed_items": u32 }`. GUI từ chối ngay nếu `total_bytes > 20_971_520`. |
| **`0x03`** | `BugreportChunk` | Worker → GUI | `1..=65_536 B` | Chunk raw bytes `.tar` đọc trực tiếp từ `POST /v1/agent/bugreport/stream`. GUI kiểm tra `cumulative_bytes + chunk.len() <= 20_971_520` và ghi vào Unprivileged Sink Handle. |
| **`0x04`** | `HandoffResponse` | Worker → GUI | `<= 65_536 B` | UTF-8 JSON mang kết quả chuẩn hóa tương đương `Result<AgentActionResponse, ErrorEnvelope>` (`ADR-021`), kèm trường tùy chọn `scrubbed_items` / `archive_bytes` cho `export_bugreport_stream`. |

### 2.3. Schema `HandoffRequest` & `HandoffResponse` (`crates/mesh-net/src/gui_handoff.rs`)

Tất cả biến thể dùng `#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]` (phía client cung cấp helper `build_up_handoff_payload()` & `build_rotate_key_handoff_payload()` gọi `.expose_secret()` bên trong `mesh-net`):

| `op` | Trường bổ sung | Hành vi Worker High Integrity (`--elevated-worker`) |
|---|---|---|
| `up_with_secret` | `server_endpoint: String`, `port_override: Option<u16>`, `server_pin: Option<String>`, `preauth_key: Option<String>`, `node_name: Option<String>` | Chuyển qua `crates/mesh-net/src/gui_handoff.rs` (gọi `.expose_secret()` tại `mesh-net`), gửi `POST /v1/agent/up` tới `\\.\pipe\mesh-agent-admin` (timeout `35_000 ms`). Hỗ trợ cả `Some(mpk_*)` lẫn `None` (1-Click Reconnect). |
| `rotate_key_with_secret` | `preauth_key: String` | Gửi `POST /v1/agent/rotate-key` tới `mesh-agent-admin` (timeout `35_000 ms`), zeroize ngay sau khi gửi. |
| `down` | *(không)* | Gửi `POST /v1/agent/down` tới `mesh-agent-admin`. |
| `cleanup` | *(không)* | Gửi `POST /v1/agent/cleanup` tới `mesh-agent-admin` (fallback offline `WindowsCleanupOps` + `ResourceLedger` nếu daemon tắt). |
| `set` | `server_endpoint: String`, `server_pin: Option<String>` | Gửi `POST /v1/agent/set` tới `mesh-agent-admin`. |
| `reset_identity` | *(không)* | Gửi `POST /v1/agent/reset-identity` tới `mesh-agent-admin`. |
| `export_bugreport_stream` | *(không — CẤM truyền đường dẫn lưu!)* | Gọi `POST /v1/agent/bugreport/stream` trên `mesh-agent-admin`, phát frame `0x02` + chuỗi frame `0x03` (`<= 64 KiB/chunk`, tổng `<= 20 MiB`) + frame `0x04`. |
| `install_or_start_service` | `source_dir: String`, `start_only: bool` | Nếu `!start_only`: kiểm tra `option_env!("MESH_WINTUN_SHA256")`, mở khóa đọc `FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT` trên `MeshVPN.exe`/`meshd.exe`/`mesh.exe`/`wintun.dll`, kiểm tra SHA-256, tránh self-copy, đóng Tray cũ qua `Local\MeshVpnGuiShutdownEvent` & `WM_APP_GRACEFUL_SHUTDOWN` nếu nâng cấp từ thư mục khác, dừng `MeshVpnAgent`, sao chép sang `%ProgramFiles%\Mesh\` (cùng `wintun.dll.sha256`, `WINTUN-LICENSE.txt`, `README-WINTUN.md`), đặt SDDL chuẩn (`ProgramData\Mesh` giữ `keys.json` & `bootstrap.toml`), đăng ký & bật `MeshVpnAgent` (`LocalSystem`, auto-start, recovery `5_000 ms`), chờ `mesh-agent-ro` sẵn sàng. |
| `update_service` | `source_dir: String`, `old_gui_pid: Option<u32>` | Tín hiệu đóng Tray cũ (`Local\MeshVpnGuiShutdownEvent` + `WM_APP_GRACEFUL_SHUTDOWN`, chờ `<= 3_000 ms`), dừng `MeshVpnAgent`, verify & thay thế nhị phân (`MESH_WINTUN_SHA256`), giữ `keys.json`/`bootstrap.toml`, khởi động lại `MeshVpnAgent`. |
| `uninstall_service` | `purge_keys: bool` | Dừng `MeshVpnAgent`, chạy `WindowsCleanupOps` + `ResourceLedger::cleanup_all`, xóa service SCM, xóa đầy đủ tệp `%ProgramFiles%\Mesh\`, giữ `C:\ProgramData\Mesh\{keys.json, bootstrap.toml}` trừ khi `purge_keys == true` (`HKCU\...\Run` & shortcut đã do GUI user xóa trước khi `runas`). |

**Schema `HandoffResponse` (`0x04`)** *(ánh xạ trực tiếp từ `Result<AgentActionResponse, ErrorEnvelope>` của `ADR-021`, mở rộng thêm `scrubbed_items`/`archive_bytes` bằng `null` cho các lệnh không stream)*:
```json
{
  "ok": true,
  "daemon_state": "connected",
  "message": "tunnel up",
  "scrubbed_items": null,
  "archive_bytes": null,
  "error": null
}
```
*(Khi thất bại: `"ok": false`, `"error": { "kind": "...", "code": "E_...", "message": "...", "request_id": "handoff" }`, giữ `"authentication failed"` cho `unauthenticated`).*

---

## 3. Phân tầng 3 Mức Timeout IPC, Polling Thích ứng & Ma trận Map Lỗi OS

### 3.1. Bảng 3 Tầng Timeout IPC Bắt buộc (`HR-DGUI-G1-01`, `DGUI-IPC-04`)

| Tầng | Hằng số Đề xuất (`mesh-net` / `MeshDesktopCore`) | Giá trị Khóa cứng | Thao tác Áp dụng | Quy tắc Thực thi |
|---|---|---:|---|---|
| **Tầng 1: Connect / Pipe-Open** | `IPC_CONNECT_TIMEOUT` | **`850 ms`** *(trần `<= 1_000 ms`)* | Mở UDS (`/var/run/meshd/*.sock`) hoặc Named Pipe (`\\.\pipe\mesh-agent-*`) | Bao gồm retry backoff ngắn (`50 ms`, `100 ms`, `150 ms` hoặc polling `25–50 ms`) cho `ERROR_PIPE_BUSY (231)` nằm gọn trong ngân sách `850 ms` → phát hiện daemon tắt trong `< 1 s` (`test_offline_daemon_fails_fast_under_one_second`). |
| **Tầng 2: Read-Only Query Response** | `IPC_RO_QUERY_TIMEOUT` | **`2_000 ms`** | `GET /v1/agent/status`, `GET /v1/agent/peers`, `GET /v1/agent/version` | Timeout bao trùm cả write HTTP request + read HTTP response (`<= 64 KiB`), chống treo nửa chừng nếu daemon bị đóng băng. |
| **Tầng 3a: Netcheck Probe** | `IPC_NETCHECK_TIMEOUT` | **`10_000 ms`** | `POST /v1/agent/netcheck` (`meshd-ro`) | Đủ cho STUN UDP probe + TCP Control probe qua mạng di động/Wi-Fi chậm. |
| **Tầng 3b: Disco Ping Probe** | `IPC_PING_MAX_TIMEOUT` | **`min(count * timeout_ms + 2_000 ms, 35_000 ms)`** | `POST /v1/agent/ping` (`meshd-ro`) | Khớp `count` (1..=64) * `timeout_ms` (`2_500 ms` mặc định) + `2 s` overhead, trần `35 s`. |
| **Tầng 3c: Admin Mutation / Stream** | `IPC_ADMIN_MUTATION_TIMEOUT` | **`35_000 ms`** | `up`, `down`, `cleanup`, `set`, `rotate-key`, `reset-identity`, `bugreport/stream` (`meshd-admin`) | Lớn hơn **`IPC_COMMAND_TIMEOUT = 30 s`** (`crates/meshd/src/ipc_service.rs:32`) để không cắt nhầm lệnh `up`/`rotate-key`/`bugreport` hợp lệ; với `bugreport/stream` áp dụng timeout không hoạt động giữa các chunk `<= 10_000 ms` và tổng trần `35_000 ms`. |

- **Quy tắc Polling Thích ứng (`DGUI-IPC-04`)**:
  - **Dashboard đang mở & active (`DASHBOARD_POLL_INTERVAL_MS`):** `2_000 ms`.
  - **Thu gọn về Tray / Menu Bar (`TRAY_IDLE_POLL_INTERVAL_MS`):** `8_000 ms` (trong biên `5–10 s`; gọi refresh tức thì khi user mở Menu Tray/Menu Bar hoặc khi nhận `NetworkChangeEvent`).
  - **Tạm ngắt polling `ro` khi chờ lệnh admin (`PollingSuspensionGuard`, `LOW-DGUI-G2-02`):** Khi GUI **bắt đầu** thực thi lệnh `meshd-admin` hoặc mở hộp thoại UAC/`osascript`, tạm hoãn polling `GET /v1/agent/status` để tránh tranh chấp pipe `ERROR_PIPE_BUSY` hay đảo UI về trạng thái cũ giữa chừng; ngay khi admin hoàn tất, kích hoạt refresh `status` tức thì (`<= 500 ms`). *(Với thao tác Bugreport: tuyệt đối **KHÔNG** bật `PollingSuspensionGuard` trong lúc người dùng đang mở hộp thoại chọn tệp `SaveFileDialog` / `NSSavePanel`; chỉ bật sau khi người dùng đã xác nhận đường dẫn lưu và bắt đầu luồng admin/UAC).*

### 3.2. Ma trận Ánh xạ Lỗi OS & Lỗi Giao thức IPC (`DGUI-IPC-05`, `DGUI-WIN-07`, `SEC-05`)

| Mã Lỗi Gốc (Windows / macOS / Wire) | Phân loại `ErrorKind` / `IpcClientError` | Trạng thái UI Đích (`DesktopUiState`) | Thông điệp Thân thiện & Hành động Phục hồi |
|---|---|---|---|
| Win `ERROR_FILE_NOT_FOUND (2)` / `ERROR_SERVICE_DOES_NOT_EXIST (1060)` · Mac `ENOENT (2)` / `ECONNREFUSED (61)` | `ServiceUnavailable` (`ErrorKind::Unavailable`) | `ServiceNotInstalled` (nếu thiếu service/plist) hoặc `ServiceStopped` | Hiển thị nút 1-click **"Install & Start Service"** hoặc **"Start Service"**. |
| Win `ERROR_ACCESS_DENIED (5)` · Mac `EACCES (13)` / HTTP `403 PermissionDenied` | `PermissionDenied` (`ErrorKind::PermissionDenied`) | `Error` (hoặc giữ màn hình hiện tại + banner lỗi quyền) | Win: hướng dẫn xác nhận UAC hoặc đăng nhập tài khoản Administrator; Mac: thông báo user không thuộc nhóm `admin (gid 80)` cần xác thực quản trị. **Tuyệt đối không** gợi ý nới `ADMIN_PIPE_SDDL` hay `0660`. |
| Win `ERROR_PIPE_BUSY (231)` (hết hạn `850 ms` vẫn bận) | `BusyRetryable` (`ErrorKind::Unavailable`) | Giữ trạng thái hiện tại, thử lại ở chu kỳ kế tiếp | Tự retry backoff ngắn (`50 ms`, `100 ms`, `150 ms` hoặc `25–50 ms`) trong ngân sách `850 ms`; nếu vẫn bận do admin mutation đang chạy, chờ xong mới đọc lại. |
| Win `ERROR_CANCELLED (1223)` hoặc Handoff UAC timeout (`15 s` worker / `120 s` UAC) / Mac `osascript` user canceled (`-128`) | `ElevationCancelled` | Giữ nguyên trạng thái trước khi bấm; zeroize ngay `mpk_*` (`<= 100 ms`) | Thông báo *"Administrator confirmation was cancelled."* — **0** tự bật lại UAC loop. |
| HTTP `401` / `E_UNAUTHENTICATED` | `ErrorKind::Unauthenticated` | `Error` (trên Onboarding / Rotate Key giữ ở form) | Hiển thị nguyên văn **`"authentication failed"`** (`SEC-05`), không lộ nguyên nhân key sai/hết hạn/đã dùng. |
| `E_NODE_REVOKED` / `daemon_state == "revoked"` | `ErrorKind::NodeRevoked` | **`Revoked`** | Dừng retry; nút chính **"Reset Node Identity"** (`POST /v1/agent/reset-identity`). |
| `E_KEY_EXPIRED` / `daemon_state == "reauth_required"` | `ErrorKind::NodeKeyExpired` | **`ReauthRequired`** | Dừng retry; nút chính **"Rotate Node Key"** (`POST /v1/agent/rotate-key` kèm `mpk_*` `--for <node>`). |
| `E_PIN_MISMATCH` / `E_CLOCK_SKEW` | `ErrorKind::PinMismatch` / `ErrorKind::ClockSkew` | **`Connected`** (nếu cache chạy) hoặc **`Error`** | Hiển thị rõ fingerprint lệch / lệch giờ hệ thống và nút **"Update Control Server / Pin"** (**0** nút bỏ qua TLS). |

---

## 4. Đặc tả UI State Machine & Action Contracts Cho Toàn Bộ Màn Hình Desktop

### 4.1. Quy tắc Chuẩn hóa Đầu vào & Bảo mật Nhập liệu Chung (`DGUI-SEC-02/03/04/05/08`, `US-102`)

Mọi biểu mẫu nhập Endpoint / URI / Token trên cả `MeshVPN.exe` (`crates/mesh-gui`) và `Mesh VPN.app` (`MeshDesktopCore`) phải thực thi cùng hợp đồng thuần (deterministic parity):

1. **Chuẩn hóa `EndpointNormalizer` (`<host>:<effective_port>` — khắc phục `split_host_port` `400` ở `crates/mesh-client/src/config.rs:553`)**:
   - Từ chối ngay nếu chuỗi rỗng, chứa scheme (`://`), chứa khoảng trắng/ký tự điều khiển (`\r`, `\n`, `\0`) hoặc metacharacter (`; | & $() ' "` `"`).
   - Xác định `(host, parsed_port)` (hỗ trợ IPv4 `203.0.113.10`, IPv4+port `203.0.113.10:8443`, IPv6 trần `2001:db8::1`, IPv6 ngoặc vuông `[2001:db8::1]` hoặc `[2001:db8::1]:8443`, DNS `vpn.example.com` hoặc `vpn.example.com:8443`).
   - Áp `port_override` (`1..=65535`) nếu người dùng nhập, else `parsed_port`, else `DEFAULT_CONTROL_TCP_PORT` (lấy từ `mesh_core::defaults` ở Rust và `AgentDefaults` ở `MeshDesktopCore`, không hardcode ngoài `mesh-core` ở Rust).
   - Kết xuất `normalized_endpoint`: `[<host>]:<port>` nếu `host` là IPv6, ngược lại `<host>:<port>`.
2. **Zero-TOFU & Khóa `System CA` trên IP Literal (`HR-DGUI-G1-02`, `DGUI-SEC-04`)**:
   - Ngay khi người dùng gõ hoặc dán `host` phân giải là IPv4 hoặc IPv6 literal (`is_ip_literal == true`):
     - UI **bắt buộc vô hiệu hóa** tùy chọn/radio `System CA` và tự chuyển sang `SPKI Pin`.
     - Validate từ chối ngay nếu thiếu `server_pin` hoặc không khớp `^sha256:[0-9a-f]{64}$` (không phân biệt hoa/thường khi nhập, chuẩn hóa lowercase).
   - Với DNS hostname: mặc định chọn `SPKI Pin`; nếu user chọn chủ động `System CA`, cho phép `server_pin = None`. **Tuyệt đối 0** checkbox *"Skip TLS Verification"*.
3. **Kiểm chứng `NodeName` & `PreAuthToken`**:
   - `NodeName` (nếu nhập): khớp RFC 1123 (`1..=63`, `[a-z0-9-]`, không `-` đầu/cuối), từ chối `RESERVED_HOSTNAMES` (`localhost`, `broadcasthost`, `wpad`, `isatap`, `local`) và từ chối trùng `host` của Control server.
   - `PreAuthToken`: chuẩn hóa thống nhất theo **`mesh_core::mobile_uri::validate_preauth_key`** (`crates/mesh-core/src/mobile_uri.rs:430-456`, re-export tại `crates/mesh-core/src/lib.rs`) — bắt buộc tiền tố `mpk_`, tổng độ dài `<= 256` ký tự, phần payload sau `mpk_` hợp lệ `BASE64URL_NOPAD` (`[A-Za-z0-9_-]`) giải mã ra **`>= 32` bytes (`>= 256-bit` entropy)**, zeroize ngay buffer giải mã; áp dụng **cùng quy tắc** cho cả URI lẫn Manual Form trên cả Rust (`crates/mesh-gui`) và Swift (`MeshDesktopCore`).
4. **Phân tích `mesh://join?v=1&...` (`MobileJoinUri`)**:
   - Tối đa `1_024` bytes, đúng tiền tố `mesh://join?`, đủ `v=1`, `ep=...`, `pin=...` (cấm `system-ca` đi cùng IP), `key=mpk_...`, optional `name=...`, từ chối fragment `#` và tham số lạ (implement bởi `JoinUriParser` trên `MeshDesktopCore` và `MobileJoinUri` ở `mesh-core`).
   - Sinh `masked_preauth_preview` dạng `mpk_<4_chars>...<4_chars>` (vd `mpk_7q2w...b5n6`); **không** giữ chuỗi `mesh://join` nguyên văn trong state UI sau khi tạo draft.
5. **Tự động Xóa Clipboard `<= 30 s` Trên Mọi Kênh Dán (`DGUI-SEC-03`, `HR-DGUI-G1-02`)**:
   - Kích hoạt bộ đếm `30 s` (`CLIPBOARD_WIPE_DELAY_SECS = 30`) trong **cả 4 trường hợp**:
     1. macOS `PasteButton` (`handlePastedText`)
     2. Nút Paste fallback (`NSButton` / Win32 Paste Button)
     3. Tổ hợp phím `Cmd+V` (macOS) / `Ctrl+V` (Windows) vào ô URI hoặc ô `mpk_*`
     4. Nút *"Copy Join URI"* nếu có (không xuất hiện ở desktop client, chỉ khi user dán vào).
   - **Điều kiện xóa an toàn:** Khi hết `30 s` (hoặc khi app thoát), chỉ xóa clipboard nếu nội dung hiện tại **vẫn khớp đúng SHA-256** của chuỗi bí mật vừa đọc (Swift `ClipboardRedactor` kiểm **`NSPasteboard.general.changeCount`**; Rust `ClipboardGuard` dùng **`GetClipboardSequenceNumber()`** + `mesh_crypto::{sha256_digest, ct_eq_bytes}` — **0** import `sha2`/`subtle` trực tiếp) để không bao giờ xóa nhầm dữ liệu người dùng vừa copy mới!
6. **Xóa Sạch Bí mật Form (`DGUI-SEC-08`)**:
   - Đóng sheet/cửa sổ Onboarding/Rotate Key, bấm Cancel, hoặc gửi xong `AgentUpRequest` / `AgentRotateKeyRequest` đều lập tức zeroize `manualPreauthKey` (Win32 `Zeroizing`, Swift xóa chuỗi & thay thế buffer rỗng) và hủy timer nền không rò handle.

### 4.2. Hợp đồng Hành vi Chi tiết Từng Màn hình (`Screen Action Contracts`)

| Màn hình / Thành phần | Trạng thái Áp dụng | Hành động Người dùng | Điều kiện Tiền quyết & Giao tiếp IPC | Kết quả Chuyển Trạng thái & Phản hồi UI |
|---|---|---|---|---|
| **1. System Tray / Menu Bar (`MeshVPN.exe` & `Mesh VPN.app`)** | Mọi `DesktopUiState` | - Click biểu tượng khay / mở menu<br/>- **Connect / Disconnect** (1-click)<br/>- **Copy My Overlay IP**<br/>- **Peers -> Click Peer**<br/>- **Open Dashboard**<br/>- **Install / Start / Update Service**<br/>- **Quit Mesh VPN UI** | - Mở menu kích hoạt refresh tức thì `GET /v1/agent/status` (`meshd-ro`).<br/>- **1-Click Connect** khi đã enroll (`node_id != None`): gọi thẳng `POST /v1/agent/up` với `preauth_key: None` (qua `runas` trên Win; UDS trực tiếp 0 mật khẩu trên Mac `gid=80`) **KHÔNG mở modal xác nhận** và giữ nguyên `bootstrap.next_pin`.<br/>- **Disconnect**: gọi `POST /v1/agent/down`. | - Icon & Tooltip phản ánh 6 nhóm hình ảnh: `Connected` (xanh), `Connecting`/`Degraded` (vàng/cam), `Stopped` (xám), `ServiceNotInstalled`/`ServiceStopped` (xám chấm hỏi/offline), `ReauthRequired`/`Revoked`/`Error` (đỏ/chấm than).<br/>- Copy Overlay IP/FQDN peer ghi vào clipboard (không hẹn giờ xóa vì là IP overlay công khai trong mesh).<br/>- **Open Dashboard**: Win `ShowWindow`/`SetForegroundWindow`; Mac mở single-instance `Window` + `NSApp.setActivationPolicy(.regular)`.<br/>- **Quit UI**: đóng UI `<= 2 s`, **KHÔNG dừng `meshd`**. |
| **2. Service Status / Setup Banner & Version Mismatch** | `ServiceNotInstalled`, `ServiceStopped`, hoặc `VersionMismatch` | - Bấm **Install & Start Service**<br/>- Bấm **Start Service**<br/>- Bấm **Update Background Service** (kèm checkbox opt-in `socketfilterfw` nếu macOS Firewall bật) | - Win: Handoff `install_or_start_service` / `update_service` qua `runas` (`MESH_WINTUN_SHA256` + `FILE_SHARE_READ \| FILE_FLAG_OPEN_REPARSE_POINT`).<br/>- Mac: `LaunchDaemonInstaller` gọi `/usr/bin/osascript` chạy `Contents/Resources/install-macos.sh` (xác minh `SHA256SUMS` + `root:wheel`, bảo toàn `codesign -v`, `launchctl bootstrap system`). | - Chờ `meshd-ro` trả `200 OK` trong `<= 10 s` (polling mỗi `500 ms` trong pha boot service).<br/>- Chuyển thẳng vào `Unconfigured` (Onboarding) hoặc `Connected`/`Connecting` (giữ nguyên `keys.json` & `OverlayIp`). |
| **3. Onboarding View** | `Unconfigured` | - Dán `mesh://join` (`PasteButton` / Paste / `Cmd+V` / `Ctrl+V`)<br/>- Hoặc điền Manual Form (`Endpoint`, `Port`, `TLS Mode`, `SPKI Pin`, `mpk_*`, `Node Name`) -> **Review & Enroll** | - Validate theo §4.1 (`EndpointNormalizer`, khóa `System CA` trên IP, RFC 1123 `NodeName`, `mpk_*` masked).<br/>- Kích hoạt clipboard wipe `<= 30 s` trên mọi luồng dán. | - Không gửi trực tiếp `/v1/agent/up`! Tạo `EnrollmentConfirmationDraft` (Win giữ `Secret<String>`; Swift giữ buffer tạm xóa ngay khi confirm/cancel) và mở **Enrollment Confirmation Modal**. |
| **4. Enrollment Confirmation Modal** | `Unconfigured` (Initial Enroll) hoặc `Connected`/`ReauthRequired` (Rotate Key) | - Đối chiếu thông tin ngoài băng<br/>- Bấm **Confirm & Enroll** / **Confirm Key Rotation**<br/>- Hoặc bấm **Cancel** | - Bắt buộc hiển thị: `Control Endpoint` đã chuẩn hóa `<host>:<port>`, `TLS Mode`, **toàn bộ `SPKI Fingerprint` `sha256:...`**, `Device Name`, `Token Preview` (`mpk_...` đã che), `Action` (`Enroll New Node` vs `Rotate Key`).<br/>- Confirm: Win qua Handoff `up_with_secret`/`rotate_key_with_secret`; Mac gọi trực tiếp `POST /v1/agent/up` hoặc `/v1/agent/rotate-key` trên `meshd-admin.sock` (`35_000 ms`). | - Confirm thành công: zeroize `mpk_*`, đóng modal, refresh `status` `<= 500 ms`, chuyển `Connecting` → `Connected`.<br/>- Cancel hoặc `ERROR_CANCELLED`: zeroize `mpk_*` `<= 100 ms`, đóng modal. |
| **5. Dashboard Main Window** | `Connected`, `Connecting`, `ReauthRequired`, `Revoked`, `Error` | - **Connect / Disconnect** (1-click)<br/>- **Copy Overlay IP / FQDN**<br/>- **Ping** trên từng dòng peer (`count=4`, `timeout_ms=2500`)<br/>- **Run Netcheck**<br/>- **Cleanup** (`POST /v1/agent/cleanup`)<br/>- CTA chính khi `ReauthRequired`: **Rotate Node Key**<br/>- CTA chính khi `Revoked` / Maintenance: **Reset Node Identity** | - Đọc `status`/`peers` mỗi `2_000 ms` (tạm ngắt khi chờ admin).<br/>- `Ping` & `Netcheck` gọi `meshd-ro` với Tier 3 timeout (`<= 35_000 ms` / `10_000 ms`).<br/>- Hiển thị banner cảnh báo: `overlay_conflict_warning`, `macos_firewall_warning` (kèm nút opt-in cấp quyền `socketfilterfw`), `server_connection.last_error`, `diagnostic_hint` từ Netcheck. | - Đóng cửa sổ (`WM_CLOSE` / nút đỏ macOS) **chỉ ẩn về Tray / Menu Bar** (`applicationShouldTerminateAfterLastWindowClosed == false`, Mac về `.accessory`).<br/>- `Revoked` -> hộp thoại xác nhận nguy hiểm -> `POST /v1/agent/reset-identity` -> về **Onboarding** (`Unconfigured`) giữ `meshd` sống. |
| **6. Settings / Update Server & Pin / Uninstall** | `Connected`, `Connecting`, `Error` | - **Update Control Server & Pin** (`POST /v1/agent/set`)<br/>- Win: Toggle **Launch at Windows sign-in** (`HKCU\...\Run`)<br/>- **Uninstall Service** (kèm checkbox **Purge identity keys**) | - Update Server chuẩn hóa `<host>:<port>` & khóa `System CA` trên IP.<br/>- Win Auto-Start: ghi/xóa `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MeshVPN` trực tiếp dưới user token (0 UAC).<br/>- Uninstall: dọn `HKCU\...\Run` + shortcut trong user context trước, rồi gọi `uninstall_service` (`runas`) / `osascript` macOS (`--uninstall [--purge]`). | - Update Server thành công -> đánh thức Control/Relay không mất `NodeId`/`OverlayIp`.<br/>- Uninstall không purge -> bảo toàn `keys.json` & `bootstrap.toml`; có purge -> xóa sạch toàn bộ state Mesh ngoài `ResourceLedger` nhưng giữ nguyên các VPN khác. |
| **7. Bugreport Save Dialog** | Mọi trạng thái có `meshd` chạy | - Bấm **Export Redacted Bugreport** -> Chọn đường dẫn `.tar` (tạo mới hoặc **Replace** tệp cũ) trên `SaveFileDialog` / `NSSavePanel` | - Khi hộp thoại lưu đang mở: **KHÔNG** bật `PollingSuspensionGuard`.<br/>- Sau khi user xác nhận path `dest`: từ chối path trong `C:\Windows`, `C:\Program Files`, `C:\ProgramData\Mesh`, `/System`, `/usr`, `/Library`, `/var/db/mesh`; kiểm `parent` không phải symlink/NTFS reparse; nếu `dest` tồn tại phải là regular file -> mới bật `PollingSuspensionGuard` và gọi `POST /v1/agent/bugreport/stream` (`<= 20 MiB`). | - Thực thi **Atomic Temp-Sibling Sink Write** (`UnprivilegedSinkWriter` trên Win / `BugreportStreamWriter` trên Mac): ghi `parent/.mesh-bugreport-<hex>.tar.part`, kiểm **`expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes <= 20_971_520`**, `sync_all()`, kiểm lại `dest`, atomic rename -> hiển thị `size_bytes` & `scrubbed_items`.<br/>- Hủy dialog / lỗi stream: RAII xóa `.part`, bảo toàn tệp cũ của user. |

---

## 5. Checklist Đồng bộ Kiểm chứng Liên Tài liệu Gate 2

| Hạng mục Khóa cứng | Xác nhận Đồng bộ với `@techlead-gui` (`#127`..`#138` & `critic-gui-g2`) | Truy vết Gate 1 |
|---|---|---|
| Crate & Binary Windows | `crates/mesh-gui` (`[[bin]] name = "MeshVPN"`, `version = "0.3.0"`, dùng `mesh-crypto` không `sha2`/`subtle` trực tiếp), `crates/mesh-sys/src/{gui_windows.rs,process_windows.rs}` (`CREATE_NEW_PROCESS_GROUP \| DETACHED_PROCESS`), `crates/mesh-net/src/gui_handoff.rs` | `US-100`, `US-103`, `ADR-020`, `HR-DGUI-G2-01..03` |
| macOS App Bundle | `desktop/macos/MeshVPNApp/` (`MeshDesktopCore` + `MeshVPNApp`), Swift 6, `LSUIElement`, Non-Sandboxed, `0 UIKit` (sửa `4/9` tệp `MeshApp` + `validate_preauth_key` + `LegacyPre030`), `osascript` cài `/usr/local/libexec/mesh/meshd` | `US-109..111`, `ADR-025`, `MED-DGUI-G2-01/03/04` |
| Backward-Compatible `agent_version` | Giữ nguyên 13 field `AgentStatusResponse`, nâng `Cargo.toml` `version = "0.3.0"` (tách `"0.3.0"` khỏi `"meshd/0.3.0"`), `X-Mesh-Agent-Version` + `GET /v1/agent/version` + `meshd --version` (`LegacyPre030`) | `US-101`, `US-113`, `ADR-024`, `HR-DGUI-G2-03`, `MED-DGUI-G2-01` |
| Bugreport Streaming & Sink Write | `POST /v1/agent/bugreport/stream` (`<= 20 MiB` + `GuardedBugreportStream` drop `inner.take()` trước `remove_file`), Atomic Temp-Sibling `UnprivilegedSinkWriter` / `BugreportStreamWriter` hỗ trợ **Replace** + `expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes`, `PollingSuspensionGuard` bật sau dialog | `US-101`, `US-105`, `US-107`, `US-112`, `ADR-023`, `BLK-DGUI-G2-05`, `HR-DGUI-G2-03`, `MED-DGUI-G2-02`, `LOW-DGUI-G2-02` |
| Reset Identity & `next_pin` | `POST /v1/agent/reset-identity` + `mesh reset-identity` + `ClientStateStore::delete_identity` (đủ `FileClientStateStore`, `InMemoryClientStateStore`, `FfiStateStore` tại `bridge.rs:140`), `update_bootstrap_trust_preserving_next_pin` chung cho cả `execute_up` & `execute_set` | `US-101`, `US-104`, `US-110`, `ADR-024`, `BLK-DGUI-G2-01`, `HR-DGUI-G2-04` |
| Handoff Pipe & Timeouts | `\\.\pipe\mesh-gui-handoff-<128bit_hex>` SDDL `SY+BA+<CurrentUserSid>`, `SECURITY_SQOS_PRESENT \| SECURITY_IDENTIFICATION`, `0x00 WorkerHello` (`13 B`) + `ImpersonateNamedPipeClient` + `CheckTokenMembership` (`0` `OpenProcessToken`), `0x01..0x04`, 3 tầng timeout `850 ms / 2_000 ms / 10_000–35_000 ms` | `US-101`, `US-105`, `ADR-021`, `ADR-024`, `BLK-DGUI-G2-04` |
