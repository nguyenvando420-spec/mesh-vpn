# Phản Biện Độc Lập Gói Nền Tảng `WP-S1-00` (`agile-critic` — Round 1 & Round 2 Final)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Gói công việc kiểm định** | **`WP-S1-00`** — Workspace Foundation, Core Domain, Isolated Crypto, Wire Codecs & OS Trait Skeletons (Wave 1.0 → mở khóa Wave 1.1) |
| **Người phản biện** | `agile-critic` (`gemini-4-carbon-high` — độc lập hoàn toàn với tác giả `gemini-4-hydrogen-xhigh`) |
| **Ngày kiểm định** | 2026-11-13 (Round 1: 07:07 · Round 2 Final: 07:43) |
| **Chế độ kiểm định** | Rà soát sâu mức byte, mật mã, hợp đồng wire/IPC và điều kiện chạy song song 0% đụng độ file cho 4 workers Wave 1.1 (`WP-S1-01..04`) & Wave 1.2 (`WP-S1-05`) |
| **Kết quả chạy kiểm chứng thực tế** | `scripts/check.ps1` → **PASS (`0`)** · `scripts/check.ps1 -Cross` (`zigbuild` Linux musl & macOS arm64/x86_64) → **PASS (`0`)** · `cargo clippy -p mesh-core -p mesh-sys --lib --target {x86_64-unknown-linux-musl,aarch64-apple-darwin} -- -D warnings` → **PASS (`0`)** |
| **Trạng thái Vòng 1 → Vòng 2** | **11/11 mục (`BLK-01..05`, `HR-01..04`, `IMP-01..02`) ĐÃ ĐÓNG DỨT ĐIỂM 100%** · Tồn đọng: **`0 🔴 Blocker` · `0 🟠 High Risk` · `0 🟡 Open Notes`** |
| **Phán quyết cuối (Vòng 2)** | **`[APPROVED FOR GATE]`** *(Đạt chuẩn khóa cứng `WP-S1-00` và mở khóa 4 workers chạy song song ở Wave 1.1)* |

---

## 1. Điểm Sáng Kỹ Thuật Đã Xác Minh Thực Nghiệm (Giữ Nguyên)

1. **Cô lập `unsafe` & Chuỗi cung ứng Pure-Rust `ring`**: `Cargo.toml` gốc khóa `unsafe_code = "forbid"` cho 9/10 crates; riêng `crates/mesh-sys/Cargo.toml` tách cấu hình `[lints]` độc lập tránh lỗi `E0453` và cưỡng chế `unsafe_op_in_unsafe_fn = "deny"` + `undocumented_unsafe_blocks = "deny"`. `cargo deny check` xác nhận sạch 100% (`0` `aws-lc-rs`, `openssl-sys`, `rusqlite`, `gotatun`).
2. **Định dạng gói nhị phân mức byte (`mesh-proto` & `mesh-crypto`)**:
   - `stun.rs`: `is_stun_rfc5389` dùng slice pattern matching (0 indexing), kiểm tra chính xác `(first_byte & 0b1100_0000) == 0`, `(msg_len_lo & 0b0000_0011) == 0`, magic cookie `0x2112A442`, và khớp 100% byte-by-byte cả STUN Test Vector 1 lẫn Test Vector 2 (`XOR-MAPPED-ADDRESS` IPv4/IPv6).
   - `disco_box.rs` & `disco.rs`: Khóa đúng `MIN_DISCO_PACKET_LEN = 172` (`6 + 32 + 24 + 16 + 94`), `AAD = b"MESHDSv1" || outer_sender_pubkey`, chống phản xạ hai chiều bằng `ConstantTimeEq` (`outer_sender != local_disco_pubkey`, `inner_sender == outer_sender`, `inner_recipient == local_disco_pubkey`), và `IngressSource::can_upgrade_to_direct()` chỉ bật trên `DirectUdp`.
   - `relay.rs`: Khóa chặt `0x01..0x04` trong ngân sách `MAX_FRAME_SIZE = 2048 B`, từ chối payload rỗng/nhỏ hơn 32 B.
3. **An toàn máy thật & chống tự khóa (`mesh-core` & `mesh-net`)**: `ErrorKind` đủ 12 biến thể (`Unauthenticated` luôn cố định `"authentication failed"`, `should_stop_auto_retry()` chỉ dừng ở `NodeRevoked | NodeKeyExpired`); `endpoint_filter.rs` tuân thủ chính xác `Codex R2 #4` (chỉ loại địa chỉ UDP của `stun_udp_endpoint`, không chặn nhầm số cổng TCP của `control_tcp_endpoint`); `keystore.rs` (`0600`, không ghi đè file khóa hỏng), `ledger.rs` và `sysexec.rs` (allowlist đường dẫn tuyệt đối, `env_clear()`, 0 shell) được cài đặt sạch.

---

## 2. Các Lỗi Chặn Đứng Thi Công Song Song Wave 1.1 / 1.2 (`🔴 Blocker`)

### 🔴 `BLK-01` — Chữ ký `extract_tls_exporter_binding(conn: &rustls::Connection)` không thể gọi từ `tokio_rustls::TlsStream`
- **Vị trí**: `crates/mesh-crypto/src/keys.rs:165` (`re-export` tại `crates/mesh-crypto/src/lib.rs:36`).
- **Phân tích**: `tokio_rustls::client::TlsStream::get_ref()` trả về `(&IO, &rustls::ClientConnection)` và `tokio_rustls::server::TlsStream::get_ref()` trả về `(&IO, &rustls::ServerConnection)`. Trong `rustls 0.23.46`, `rustls::Connection` là `enum` sở hữu theo giá trị (`Client(ClientConnection) | Server(ServerConnection)`), nên **không thể ép kiểu** `&ClientConnection` hoặc `&ServerConnection` về `&rustls::Connection`. Phương thức `export_keying_material` trong `rustls 0.23.46` (`src/conn.rs:484`) thực tế được định nghĩa trên `rustls::ConnectionCommon<Data>` (mà cả `ClientConnection`, `ServerConnection` lẫn `Connection` đều truy cập được qua `Deref`).
- **Hệ quả thực tế (Impact)**: Ở Wave 1.1 & 1.2, `WP-S1-01` (`mesh-server` Standalone TLS), `WP-S1-02` (`mesh-datapath/src/relay_client.rs`) và `WP-S1-05` (`meshd/src/control_loop.rs`) bị cấm sửa `crates/mesh-crypto/**` và cấm gọi trực tiếp API mật mã ngoài `mesh-crypto`. Các worker này sẽ **không thể trích xuất `tls_exporter_binding` (`EXPORTER-mesh-vpn-auth-v1`)** để tạo/kiểm chứng `ProofPayload` (`US-003`, `US-004`, `US-024`).
- **Đề xuất khắc phục (Actionable Remedy)**: Đổi chữ ký hàm trong `crates/mesh-crypto/src/keys.rs` thành generic:
  `pub fn extract_tls_exporter_binding<Data>(conn: &rustls::ConnectionCommon<Data>) -> AppResult<[u8; 32]>`
  (cả `&ClientConnection` và `&ServerConnection` đều truyền trực tiếp được qua deref coercion), kèm 1 unit test bắt tay cặp `ClientConnection` ↔ `ServerConnection` trong bộ nhớ xác nhận 2 đầu sinh cùng 32 bytes.

### 🔴 `BLK-02` — Bế tắc lưu trữ `ServerIdentity` xuống `redb` do xung đột giữa `Secret<T>::Serialize` và quy tắc tĩnh `SEC-01`
- **Vị trí**: `crates/mesh-store/src/identity_repo.rs:9-16`, `crates/mesh-crypto/src/secret.rs:51-57`, `crates/mesh-crypto/src/certgen.rs:28-35`, đối chiếu `scripts/check.ps1:93-101`, `scripts/check.sh:61-72` và `docs/03-system-design/database-design.md` §3.3(2) (dòng 346–358).
- **Phân tích**: Bảng `server_identity` trong `redb` (`WP-S1-01`) bắt buộc lưu bền `identity_pkcs8_der` và `acme_account_key_pkcs8_der` (Base64), còn `ServerIdentity` giữ `private_key_der: Secret<Vec<u8>>`. Tuy nhiên:
  1. `Secret<T>::Serialize` luôn ghi cố định chuỗi `"[REDACTED]"` và không cài `Deserialize`.
  2. `scripts/check.ps1` và `scripts/check.sh` chặn cứng lệnh gọi `.expose_secret()` bên ngoài 4 crates (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`) — tức **cấm tuyệt đối trong `mesh-store` và `mesh-server`**.
  3. `mesh-crypto` hiện không cung cấp hàm đóng gói/khôi phục lưu trữ nào cho khóa PKCS#8 DER của server hay khóa tài khoản ACME.
- **Hệ quả thực tế (Impact)**: Worker A (`WP-S1-01`, chỉ được sửa `crates/mesh-store/**` và `crates/mesh-server/**`) không thể lưu định danh ECDSA P-256 của server xuống `redb` (`US-007`, `US-047`) mà không làm gãy `scripts/check.ps1` hoặc ghi nhầm chuỗi `"[REDACTED]"` vào DB.
- **Đề xuất khắc phục (Actionable Remedy)**: Ngay trong `crates/mesh-crypto/src/certgen.rs` (nơi được phép gọi `.expose_secret()` hợp lệ theo `SEC-01`), bổ sung cặp hàm codec dành riêng cho keystore của server, ví dụ `encode_pkcs8_der_for_keystore(secret: &Secret<Vec<u8>>) -> zeroize::Zeroizing<String>` (Base64 chuẩn) và `decode_pkcs8_der_from_keystore(encoded: &str) -> AppResult<Secret<Vec<u8>>>` (kiểm tra DER không rỗng, tự `Zeroize` bộ đệm trung gian khi thoát).

### 🔴 `BLK-03` — Thiếu dependencies bắt buộc & vi phạm biên cô lập mật mã trong `Cargo.toml` (khóa cứng ở Wave 1.1 / 1.2)
- **Vị trí**: `crates/mesh-datapath/Cargo.toml`, `crates/mesh-server/Cargo.toml`, `crates/meshd/Cargo.toml`, `crates/mesh/Cargo.toml`, `crates/mesh-net/Cargo.toml`, đối chiếu `sprint-backlog.md` §2.1 & `system-architecture.md` §2.3 (dòng 236).
- **Phân tích**: Các worker Wave 1.1 & 1.2 không được sửa bất kỳ file `Cargo.toml` nào, nhưng cấu hình phụ thuộc hiện tại đang thiếu hụt nghiêm trọng đồng thời rò rỉ crate mật mã ra ngoài `mesh-crypto`:
  1. **`crates/mesh-datapath/Cargo.toml` (`WP-S1-02`)**: `tokio-tungstenite` ở workspace tắt TLS tích hợp (`default-features = false, features = ["connect", "handshake"]`), nên `RelayClient` (`relay_client.rs`) bắt buộc phải bọc `TcpStream` bằng `tokio_rustls::TlsConnector` + `rustls::ClientConfig` + `rustls_pki_types::ServerName` và mã hóa header `X-Mesh-*` bằng `base64`. Hiện `mesh-datapath/Cargo.toml` **thiếu toàn bộ** `tokio-rustls`, `rustls`, `rustls-pki-types`, `base64`! Ngoài ra `mesh-datapath` chưa có hàm sinh ngẫu nhiên 12-byte `tx_id` (`[u8; 12]`) cho STUN/Disco từ `mesh-crypto`, và chưa có hàm safe wrapper trong `mesh-net` bọc `mesh_sys::socket_{linux,macos,windows}` để `MagicSocket`/`SocketRebinder` gắn `SO_MARK` / `IP_BOUND_IF` / `IP_UNICAST_IF` mà không chạm `mesh-sys`. Ngược lại, `mesh-datapath/Cargo.toml` lại khai báo `ring.workspace = true` trực tiếp — vi phạm quy tắc cô lập mật mã.
  2. **`crates/meshd/Cargo.toml` & `crates/mesh/Cargo.toml` (`WP-S1-05`)**:
     - `meshd` (`control_loop.rs`, `ipc_service.rs`) thiếu `reqwest`, `tokio-rustls`, `rustls`, `rustls-pki-types`, `tokio-tungstenite`, `hyper`, `hyper-util`, `bytes`, `base64`.
     - `mesh` CLI (`admin_cmds.rs`, `client_cmds.rs`) phải gửi HTTP/1.1 JSON qua UDS & Windows Named Pipe (`api-design.md` §4–§5), nhưng `mesh/Cargo.toml` thiếu `hyper`, `hyper-util`, `bytes`, `tokio-util`, `base64` (dù `mesh-net/Cargo.toml` có khai báo `hyper`/`hyper-util`, `mesh-net/src/ipc.rs` hiện chưa có HTTP client transport và `WP-S1-05` bị cấm sửa `crates/mesh-net/**`).
  3. **`crates/mesh-server/Cargo.toml` (`WP-S1-01`) & `crates/mesh-net/Cargo.toml`**:
     - `mesh-server/Cargo.toml` thiếu `base64` (cần giải mã `X-Mesh-Node-Key`, `X-Mesh-Proof`, `disco_frame_b64`).
     - Cả `mesh-server/Cargo.toml` (`rcgen`, `rustls-webpki`, `rustls-native-certs`) lẫn `mesh-net/Cargo.toml` (`rustls-webpki`, `rustls-native-certs`) đang import trực tiếp các crate chứng chỉ/mật mã mà `system-architecture.md` §2.3 dòng 236 khóa độc quyền cho `mesh-crypto`.
- **Hệ quả thực tế (Impact)**: Chặn đứng biên dịch của `WP-S1-02`, `WP-S1-01` ở Wave 1.1 và `WP-S1-05` ở Wave 1.2; làm rò rỉ bề mặt phụ thuộc mật mã ra ngoài `mesh-crypto`.
- **Đề xuất khắc phục (Actionable Remedy)**:
  - Cập nhật `Cargo.toml` của `mesh-datapath`, `mesh-server`, `meshd`, `mesh` (hoặc `mesh-net` cho IPC HTTP transport) đầy đủ các crate nêu trên; gỡ `ring` khỏi `mesh-datapath` và gỡ `rcgen`, `rustls-webpki`, `rustls-native-certs` khỏi `mesh-server` & `mesh-net` (nếu `acme.rs` cần tạo CSR DER, xuất hàm helper tạo CSR từ `mesh-crypto::certgen`).
  - Bổ sung `pub fn random_bytes<const N: usize>() -> [u8; N]` trong `crates/mesh-crypto/src/keys.rs` và hàm điều phối OS-neutral `bind_udp_socket_underlay(...)` trong `crates/mesh-net` gọi xuống `mesh-sys::socket_*`.

### 🔴 `BLK-04` — Phụ thuộc chéo ngay trong Wave 1.1 giữa `WP-S1-01` (`mesh-server` Admin UDS) và `WP-S1-03` (`mesh-sys`/`mesh-net` Linux PeerCred) + chữ ký IPC thiếu tham số kết nối
- **Vị trí**: `crates/mesh-net/src/ipc_{linux,macos,windows}.rs`, `crates/mesh-sys/src/{ipc_linux.rs,fs_unix.rs}`, `crates/mesh-server/src/admin_service.rs`, đối chiếu `sprint-backlog.md` §3.2 (`WP-S1-01` `US-012` chạy song song với `WP-S1-03`).
- **Phân tích**:
  1. Các hàm `verify_unix_socket_peer(_channel: IpcChannelKind)`, `verify_macos_socket_peer(_channel: IpcChannelKind)`, `verify_named_pipe_peer(_channel: IpcChannelKind)` trong `crates/mesh-net/src/ipc_*.rs` **không nhận đối tượng kết nối (`&tokio::net::UnixStream` / `AsRawFd` / handle Named Pipe)** cũng không nhận cấu hình group (`mesh-admin` vs `admin`), khiến chữ ký hàm hiện tại không thể dùng để kiểm tra kết nối thật.
  2. `WP-S1-01` (`mesh-server`, `unsafe_code = "forbid"`) chạy **song song** với `WP-S1-03`, nhưng `US-012` của `WP-S1-01` đòi hỏi kiểm tra `/run/mesh-server` (`0750`, chống symlink) và xác thực `SO_PEERCRED` + `getgrouplist` cho `/run/mesh-server/admin.sock` — vốn đang nằm dạng `Err(NotImplemented)` trong các file thuộc quyền sở hữu của `WP-S1-03`.
- **Hệ quả thực tế (Impact)**: `WP-S1-01` không thể gọi xác thực PeerCred thật hoặc phải sửa chéo vào `mesh-net`/`mesh-sys` gây xung đột merge trực tiếp với `WP-S1-03`.
- **Đề xuất khắc phục (Actionable Remedy)**:
  - Định nghĩa trait `IpcPeerVerifier` kèm `FakeIpcPeerVerifier` trong `crates/mesh-net/src/ipc.rs` và sửa chữ ký hàm ở `ipc_{linux,macos,windows}.rs` nhận stream/fd thực tế + chính sách group (`UnixSocketAuthPolicy`).
  - Hiện thực sẵn phần nhỏ `fs_unix::verify_secure_runtime_dir` và `ipc_linux::verify_admin_peer_cred` ngay tại `WP-S1-00` (hoặc đảm bảo `mesh-net/src/ipc.rs` cung cấp sẵn trait + fake để `WP-S1-01` tích hợp sạch 100% không cần đợi `WP-S1-03`).

### 🔴 `BLK-05` — Lệch Hợp đồng Wire/IPC (`crates/mesh-proto` & `crates/mesh-crypto`) bị khóa đối với toàn bộ Wave 1.1 & 1.2
- **Vị trí**: `crates/mesh-proto/src/{control.rs,netmap.rs,admin_ipc.rs,agent_ipc.rs}` và `crates/mesh-crypto/src/auth_box.rs`, đối chiếu Context Packet §2.4, `api-design.md` dòng 15 & §1–§5, `database-design.md` §3–§4.
- **Phân tích**: `WP-S1-00` khóa cứng `crates/mesh-proto/**` cho cả Sprint 1 & Sprint 2, nhưng hiện có 5 điểm lệch hợp đồng bắt buộc:
  1. **Thiếu 100% `#[serde(deny_unknown_fields)]`**: Quy định bắt buộc tại `api-design.md` dòng 15 & Context Packet §2.4, nhưng hiện **0 struct/enum nào** trong `mesh-proto` và `ProofPayload` (`auth_box.rs`) gắn thuộc tính này.
  2. **`RevokeActionResponse` thiếu trường bắt buộc (`admin_ipc.rs:24-33`)**: Thiếu `pub revoked: bool` và `pub persisted: bool` đã khóa tại `api-design.md` §4.1 (dòng 511–523), `database-design.md` §4.2(b) và `US-013` (`persisted: false` khi rơi về `ram_only` do `EIO`).
  3. **Thiếu các DTO Admin IPC bắt buộc trong `admin_ipc.rs`**:
     - `AuditEventDto` & `ListAuditEventsResponse` (`GET /v1/admin/audit-events` — cần ngay ở `WP-S1-01` `US-013`).
     - `RenameNodeRequest` (`POST /v1/admin/nodes/{id}/rename` — cần ngay ở `WP-S1-01` `US-012`).
     - `BackupCreatedResponse`, `RestoreBackupRequest`, `RestoreBackupResponse` (`POST /v1/admin/backup`, `/restore` — `US-045` & CLI `mesh backup`/`restore`).
     - `MigrateEndpointRequest`/`Response` và `RotateTlsKeyRequest`/`Response` (`api-design.md` §4.1 — cần khóa sẵn để Sprint 2 `WP-S2-01` không phải mở khóa `mesh-proto`).
     - Trường `cli_join_command: String` (chuỗi gợi ý `mesh up --server ... --server-pin ... --authkey-file ...` của `US-002`) trên `PreAuthKeyCreatedResponse`, và `tls_auth_mode` / `relay_sessions_active` trên `ServerStatusResponse`.
  4. **Thiếu DTO/trường Agent IPC trong `agent_ipc.rs` cho `WP-S1-05` (`US-039`, `US-040`)**: `AgentStatusResponse` thiếu `tls_auth_mode` & `active_pin`; `PeerStatusDto` thiếu `last_handshake_at_ms`, `rx_bytes`, `tx_bytes`, `endpoints`; và hoàn toàn thiếu `AgentPingRequest` / `AgentPingSampleDto` / `AgentPingResponse` (cho `mesh ping <peer> [-c N] [--direct]`) cùng `AgentNetcheckResponse` (`mesh netcheck`).
  5. **Lệch kiểu dữ liệu API ↔ DB**: `ChallengeRequest.protocol_version` đang là `u32` (`control.rs:53`) thay vì `u16` (`database-design.md:292`); `CreatePreAuthKeyRequest.ephemeral_timeout_secs` đang là `Option<u64>` (`admin_ipc.rs:47`) thay vì `Option<u32>` (`database-design.md:282,325`).
- **Hệ quả thực tế (Impact)**: Các worker `WP-S1-01` (Server) và `WP-S1-05` (`meshd` + `mesh` CLI) sẽ lệch schema JSON hoặc buộc phải định nghĩa DTO trùng lặp cục bộ gây vỡ giao thức IPC.
- **Đề xuất khắc phục (Actionable Remedy)**: Gắn `#[serde(deny_unknown_fields)]` lên toàn bộ DTO/payload biên trong `mesh-proto` & `auth_box.rs`, bổ sung đầy đủ các trường/DTO còn thiếu và đồng bộ kiểu `u16`/`Option<u32>` khớp 1:1 với `api-design.md` & `database-design.md`, kèm unit test từ chối trường lạ (`unknown_field`).

---

## 3. Các Rủi Ro Cao Về Mật Mã, Định Tuyến & Độ Tin Cậy (`🟠 High Risk`)

### 🟠 `HR-01` — Bề mặt hạ cấp TLS 1.2 trên kênh Control/Relay, kho Root CA rỗng âm thầm, và race condition trên `SpkiPinVerifier::last_failure`
- **Vị trí**: `Cargo.toml:66`, `crates/mesh-crypto/src/tlspin.rs:49-53, 203, 220-232`, `crates/mesh-crypto/src/certgen.rs:163`.
- **Phân tích**:
  1. `build_pinned_client_config`, `build_system_ca_client_config` và `build_server_config_inner` đều gọi `.with_safe_default_protocol_versions()` trong khi workspace bật `rustls` feature `"tls12"`, cho phép hạ cấp kết nối Control/Relay xuống **TLS 1.2** trái với chuẩn khóa cứng **TLS 1.3** (`SEC-04`, `US-003`, RFC 8446 exporter).
  2. `build_system_ca_client_config` không kiểm tra `roots.is_empty()`, dẫn tới trả về `Ok(ClientConfig)` rỗng âm thầm nếu container thiếu kho chứng chỉ hệ thống.
  3. `SpkiPinVerifier` lưu lỗi cuối trong `last_failure: Mutex<Option<AppError>>` dùng chung trên `Arc<ClientConfig>`; khi `ControlLoop` và `RelayClient` bắt tay song song, hai luồng có thể ghi đè hoặc `.take()` chéo nguyên nhân lỗi (`ClockSkew` vs `PinMismatch`).
- **Hệ quả thực tế (Impact)**: Cho phép đàm phán TLS 1.2 ngoài thiết kế và gây lệch ngữ nghĩa exporter `Some(&[])`; phân loại sai nguyên nhân lỗi TLS dưới tải đồng thời khiến client hiển thị chẩn đoán sai.
- **Đề xuất khắc phục (Actionable Remedy)**:
  - Khóa cứng `.with_protocol_versions(&[&rustls::version::TLS13])` trong cả `tlspin.rs` lẫn `certgen.rs`.
  - Trả `Err(AppError::config("system trust store contains zero root certificates"))` khi `roots.is_empty()`.
  - Nhúng trực tiếp mã phân loại lỗi (`ClockSkew` / `PinMismatch`) vào `rustls::Error` (`CertificateError::Other(OtherError(Arc::new(app_err)))`) để trích xuất thẳng từ lỗi trả về của chính phiên handshake đó thay vì qua `Mutex` dùng chung.

### 🟠 `HR-02` — `PublicKey::from_bytes` bỏ lọt các điểm bậc thấp Curve25519; các DTO chứa `mpk_...` chưa `zeroize` bộ nhớ khi `Drop`
- **Vị trí**: `crates/mesh-core/src/types.rs:539-549`, `crates/mesh-proto/src/{control.rs:64-92, admin_ipc.rs:58-80, agent_ipc.rs:62-97}`.
- **Phân tích**:
  1. `PublicKey::from_bytes` mới chỉ từ chối mảng toàn `0` (`[0u8; 32]`), chưa từ chối các điểm bậc thấp (low-order torsion points) của Curve25519 (như `[1, 0, ..., 0]`, các điểm bậc 2/4/8 và biến thể non-canonical khiến phép nhân X25519 sinh shared secret toàn `0` theo RFC 7748 / `api-design.md` §1.1).
  2. 4 DTO vận chuyển khóa thô (`RegisterNodeRequest.preauth_key`, `PreAuthKeyCreatedResponse.raw_key`, `AgentUpRequest.preauth_key`, `AgentRotateKeyRequest.preauth_key`) đã che `[REDACTED]` trong `Debug` nhưng giữ `String` thường không `Zeroize` khi giải phóng (`SEC-01`).
- **Hệ quả thực tế (Impact)**: Chấp nhận khóa công khai suy biến vào bảng peer/SalsaBox; lưu lại bản sao chuỗi bí mật `mpk_...` trên vùng nhớ heap sau khi xử lý xong IPC/HTTP.
- **Đề xuất khắc phục (Actionable Remedy)**: Từ chối đầy đủ tập điểm bậc thấp Curve25519 (canonical + modulo $2^{255}-19$) ngay trong `PublicKey::from_bytes` (hoặc hàm kiểm định khóa X25519 tại `mesh-crypto`); cài `Drop` gọi `Zeroize::zeroize` cho 4 struct chứa `preauth_key`/`raw_key` trong `mesh-proto`.

### 🟠 `HR-03` — Sai lệch hằng số cổng/TTL (`9100` vs `9091`, `60s` vs `30s`), thiếu cờ `P` trong SDDL Windows, `OverlayCidr::contains` nhận cả địa chỉ `.0`/broadcast, và `hosts.rs` thiếu kiểm tra trùng IPv4 server
- **Vị trí**: `crates/mesh-core/src/defaults.rs:17, 80`, `crates/mesh-core/src/types.rs:398-402`, `crates/mesh-net/src/tun.rs:43`, `crates/mesh-net/src/ipc_windows.rs:8-11`, `crates/mesh-net/src/hosts.rs:80-112`.
- **Phân tích**:
  1. `DEFAULT_OBS_BIND_ADDR` đang là `"127.0.0.1:9100"` (xung đột cổng mặc định của Prometheus `node_exporter` trên VPS Linux) thay vì `"127.0.0.1:9091"` đã khóa trong `system-architecture.md:107,820`, `api-design.md:712`, `sprint-backlog.md:113`.
  2. `CHALLENGE_TTL_SECS` đang là `60` thay vì `30` đã khóa trong `system-architecture.md:278` và `api-design.md:47`.
  3. `ADMIN_PIPE_SDDL` & `RO_PIPE_SDDL` trong `crates/mesh-net/src/ipc_windows.rs` viết `"D:(A;;...)"` thiếu cờ **`P` (`SE_DACL_PROTECTED`)**, lệch với `"D:P(A;;...)"` trong `api-design.md:591` và `mesh-sys/src/ipc_windows.rs`.
  4. `OverlayCidr::contains(ip)` ghi chú *"usable host range inside this CIDR"* và được `TunConfig::new` sử dụng, nhưng thực tế trả `true` cho cả địa chỉ network (`100.115.0.0`) và directed broadcast (`100.115.255.255`)!
  5. `hosts.rs` (`HR-G2-04` yêu cầu hoàn thiện 100% tại `WP-S1-00` theo `US-038 AC4, AC5`) đã chặn trùng tên với `public_server_host`, nhưng chưa từ chối trường hợp `entry.overlay_ip` trùng với IPv4 của `public_server_host` (khi `public_server_host` là chuỗi địa chỉ IPv4).
- **Hệ quả thực tế (Impact)**: Đụng cổng `node_exporter` trên VPS Production; hở kế thừa ACE trên Named Pipe Windows; nguy cơ cấp phát nhầm địa chỉ `.0`/`.255.255` cho interface TUN làm lỗi định tuyến OS; hoặc ghi đè IP public của VPS trong `/etc/hosts` gây tự khóa kết nối Control.
- **Đề xuất khắc phục (Actionable Remedy)**:
  - Sửa `DEFAULT_OBS_BIND_ADDR = "127.0.0.1:9091"` và `CHALLENGE_TTL_SECS = 30` trong `defaults.rs`; thêm cờ `P` vào 2 hằng SDDL trong `crates/mesh-net/src/ipc_windows.rs`.
  - Tách rõ `OverlayCidr::contains_subnet_ip(Ipv4Addr)` (cho `endpoint_filter.rs`) và `OverlayCidr::contains_usable_host(OverlayIp)` (loại trừ địa chỉ network & broadcast với `prefix_len <= 30`, dùng cho `TunConfig::new` và bộ cấp phát IP).
  - Trong `hosts.rs::render_hosts_block`, nếu `public_server_host` parse được thành `Ipv4Addr`, từ chối mọi `HostsEntry` có `overlay_ip.as_ipv4() == server_ip`.

### 🟠 `HR-04` — `BoundedRotatingWriter` đặt lại `rotation_seq = 0` khi restart, ghi đè log cũ và xóa nhầm bản ghi mới nhất
- **Vị trí**: `crates/mesh-core/src/logging.rs:271, 280-331`.
- **Phân tích**: Mỗi khi tiến trình khởi động lại, `BoundedRotatingWriter::new` gán `rotation_seq: 0` mà không đọc số thứ tự lớn nhất hiện có trong `log_dir`. Ở lần xoay vòng đầu tiên sau restart, file log mới nhất bị đổi tên thành `<prefix>.0000000000000001.log` — **ghi đè mất file `.1.log` trước đó**. Hơn nữa, `prune_rotated_logs` sắp xếp tên file theo thứ tự từ điển tăng dần rồi xóa từ đầu mảng (`0000000000000001` trước `0000000000000005`), nghĩa là nó sẽ **xóa ngay bản log vừa mới xoay vòng xong** thay vì bản log cũ nhất của phiên trước khi tổng dung lượng vượt 100 MiB (`US-043`).
- **Hệ quả thực tế (Impact)**: Làm mất dữ liệu nhật ký chẩn đoán mới nhất ngay sau sự cố crash/restart dưới tải cao.
- **Đề xuất khắc phục (Actionable Remedy)**: Khi khởi tạo `BoundedRotatingWriter::new`, quét `log_dir` lấy `max_seq` hiện có để khởi tạo `rotation_seq = max_seq` (hoặc đặt hậu tố `<unix_ms>-<seq:06>.log`), kèm 1 unit test mô phỏng 2 chu kỳ khởi tạo liên tiếp vượt trần dung lượng và kiểm chứng các bản ghi mới nhất luôn được giữ lại.

---

## 4. Đề Xuất Hoàn Thiện Thêm (`🟡 Improvement`)

1. **`🟡 IMP-01` — Khóa sẵn kiểu kênh `NetworkChangeEvent` & `RebindHandle` cho Wave 1.2 / Sprint 2 (`Codex #14`)**: Định nghĩa sẵn kiểu thông điệp/handle điều khiển rebind dùng chung tại biên `mesh-net` / `mesh-datapath/src/rebind.rs` để `WP-S1-02` và `WP-S1-05` ghép nối khớp tuyệt đối mà không cần chạm chéo file ở Sprint 2.
2. **`🟡 IMP-02` — Chuẩn hóa nhãn Wave/WP trong doc-comment của các file stub**: Một số doc-comment trong `crates/mesh-datapath/src/*.rs` và `crates/mesh-server/src/*.rs` ghi `Wave 1.2` (thực tế thuộc `WP-S1-02` và `WP-S1-01` ở **Wave 1.1**), còn `crates/mesh-sys/src/*_macos.rs` ghi `WP-S1-02` (thực tế thuộc `WP-S1-03`). Nên chỉnh lại đúng mã WP khi cập nhật stub để tránh gây nhiễu ngữ cảnh cho 4 workers chạy song song.

---

## 5. Tái Thẩm Định Vòng 2 (`Round 2 Final Verification` — 2026-11-13)

### 5.1. Kiểm Chứng Thực Thi Độc Lập Trên Toàn Workspace
1. **`scripts/check.ps1` (Full 5-step suite)**: Chạy trực tiếp `powershell -ExecutionPolicy Bypass -File scripts/check.ps1` → **PASS (`exit code 0`)** (`rustc 1.94.1`, kiểm tĩnh UTF-8 No BOM / `unsafe` / `.expose_secret()` / hardcoded ports, `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, toàn bộ unit + `proptest` xanh 100%, `cargo deny check advisories bans licenses sources` sạch 100%).
2. **Đa nền tảng (`scripts/check.ps1 -Cross` & Cross-Target Clippy)**: Chạy `cargo zigbuild --workspace` cho `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin` → **PASS (`exit code 0`)**; chạy `cargo clippy -p mesh-core -p mesh-sys --lib --target {x86_64-unknown-linux-musl,aarch64-apple-darwin} -- -D warnings` → **PASS (`exit code 0`)**.
3. **Đối chiếu độc lập toán học Curve25519 & nhãn RFC 8446 Exporter**: Xác minh bằng script độc lập rằng cả 7 mảng 32-byte điểm bậc thấp trong `types.rs:563-595` (`0`, `1`, `e0eb...00`, `5f9c...57`, `p-1`, `p`, `p+1` sau mặt nạ `& 0x7f`) khớp chính xác từng byte với RFC 7748 §6.1, và nhãn `b"EXPORTER-mesh-control-v1"` cùng context `None` khớp 100% với `api-design.md:91,97`.

### 5.2. Ma Trận Xác Minh Đóng 100% Các Mục Vòng 1 (`BLK-01..05`, `HR-01..04`, `IMP-01..02`)

| Mã mục | Mức V1 | Bằng chứng xác minh trực tiếp trên mã nguồn ở Vòng 2 | Trạng thái |
| :--- | :---: | :--- | :---: |
| **`BLK-01`** | 🔴 Blocker | `crates/mesh-crypto/src/keys.rs:173-177,227-297`: Đổi sang `pub fn extract_tls_exporter_binding<Data>(conn: &ConnectionCommon<Data>) -> AppResult<[u8; 32]>`. Đã kiểm chứng bằng `test_tls_exporter_binding_matches_between_client_and_server` chạy bắt tay TLS 1.3 thật trong RAM giữa `ClientConnection` (`SpkiPinVerifier`) và `ServerConnection`, xác nhận hai đầu xuất cùng 32 bytes giống hệt nhau. | ✅ **CLOSED** |
| **`BLK-02`** | 🔴 Blocker | `crates/mesh-crypto/src/certgen.rs:160-241,316-349`: Bổ sung `encode_pkcs8_der_for_keystore(&Secret<Vec<u8>>) -> Zeroizing<String>`, `decode_pkcs8_der_from_keystore(&str) -> AppResult<Secret<Vec<u8>>>` (tự `zeroize` buffer giải mã khi lỗi, chặn chuỗi rỗng) và `generate_acme_csr_der(...)` (tái sử dụng khóa giữ nguyên `SpkiPin`). `WP-S1-01` lưu/đọc `redb` hợp chuẩn `SEC-01` mà không cần gọi `.expose_secret()`. | ✅ **CLOSED** |
| **`BLK-03`** | 🔴 Blocker | `crates/*/Cargo.toml`, `keys.rs:166`, `route.rs:226-348`: (1) `mesh-datapath` thêm `base64`, `rustls`, `rustls-pki-types`, `tokio-rustls` và gỡ `ring`; (2) `meshd` thêm `base64`, `bytes`, `hyper`, `hyper-util`, `reqwest`, `rustls`, `rustls-pki-types`, `tokio-rustls`, `tokio-tungstenite`; (3) `mesh` thêm `base64`, `bytes`, `hyper`, `hyper-util`, `tokio-util`; (4) `mesh-server` thêm `base64`; gỡ sạch `rcgen`, `rustls-webpki`, `rustls-native-certs` khỏi cả `mesh-server` lẫn `mesh-net` (cây `cargo deny` xác nhận chỉ `mesh-crypto` import các crate này); (5) Bổ sung `random_bytes<const N: usize>()` và các wrapper `bind_underlay_udp_socket`, `bind_underlay_socket2`, `disable_udp_dont_fragment` trong `mesh-net`. | ✅ **CLOSED** |
| **`BLK-04`** | 🔴 Blocker | `crates/mesh-net/src/ipc.rs:208-378,485-563`, `ipc_{linux,macos,windows}.rs`, `crates/mesh-sys/src/{ipc_*,fs_unix.rs}`: Khóa cứng chữ ký nhận `&UnixStream` / `&NamedPipeServer` / `RawFd` / `RawHandle` + `SecureDirPolicy` + `UnixSocketAuthPolicy` + `IpcPeerVerifier` + `FakeIpcPeerVerifier`, đồng thời hiện thực hoàn chỉnh cặp transport `send_ipc_json_request` (cưỡng chế `max_response_bytes`, bảo toàn `ErrorKind`) và `serve_ipc_http_connection` (`axum::Router` trên stream bất kỳ). `WP-S1-01` và `WP-S1-03` chạy song song 0% đụng độ file. | ✅ **CLOSED** |
| **`BLK-05`** | 🔴 Blocker | `crates/mesh-proto/src/{control.rs,netmap.rs,admin_ipc.rs,agent_ipc.rs}`, `auth_box.rs:18`: Gắn `#[serde(deny_unknown_fields)]` trên 100% struct & tagged enum biên kèm unit test từ chối trường lạ ở cả 5 module; bổ sung `revoked: bool` & `persisted: bool` vào `RevokeActionResponse`; bổ sung đầy đủ `RenameNodeRequest`, `ExpireNodeRequest`, `ServerAdminStatusResponse`, `Backup/Restore`, `MigrateEndpoint`, `RotateTlsKey`, `AuditEventDto`/`ListAuditEventsResponse`, `AgentStatusResponse`, `PingRequest`/`PingResponse`, `NetcheckResponse`, `BugreportResponse`; chuẩn hóa `protocol_version: u16` và `ephemeral_timeout_secs: Option<u32>`. | ✅ **CLOSED** |
| **`HR-01`** | 🟠 High Risk | `crates/mesh-crypto/src/tlspin.rs:20-36,110-143,233,254-262` & `certgen.rs:250`: Khóa cứng `.with_protocol_versions(&[&rustls::version::TLS13])` cho cả `ClientConfig` (Pinned & SystemCA) và `ServerConfig`; fail-closed khi `RootCertStore::is_empty()`; loại bỏ hoàn toàn `Mutex` dùng chung khỏi `SpkiPinVerifier`, nhúng `TlsVerifyFailure::{ClockSkew, PinMismatch}` vào `CertificateError::Other` và trích xuất phi trạng thái qua `classify_rustls_error`. | ✅ **CLOSED** |
| **`HR-02`** | 🟠 High Risk | `crates/mesh-core/src/types.rs:562-613,867-909` & `mesh-proto`: Chặn đủ 7 biểu diễn canonical/non-canonical của điểm bậc thấp Curve25519 sau khi xóa bit 255; cài `Drop` gọi `.zeroize()` trên cả 4 DTO giữ khóa thô (`RegisterNodeRequest`, `PreAuthKeyCreatedResponse`, `AgentUpRequest`, `AgentRotateKeyRequest`). | ✅ **CLOSED** |
| **`HR-03`** | 🟠 High Risk | `defaults.rs:17,80` (`DEFAULT_OBS_BIND_ADDR = "127.0.0.1:9091"`, `CHALLENGE_TTL_SECS = 30`); `ipc_windows.rs:13,16` (`"D:P(A;;...)"`); `types.rs:401-427` tách rõ `contains_subnet_ip(Ipv4Addr)` và `contains_usable_host(OverlayIp)` (loại `.0` & broadcast cho `prefix_len <= 30`); `hosts.rs:37-43,554-560` chặn `overlay_ip` trùng IPv4 của `public_server_host`. | ✅ **CLOSED** |
| **`HR-04`** | 🟠 High Risk | `crates/mesh-core/src/logging.rs:258-360`: `discover_max_rotation_seq` quét số thứ tự lớn nhất khi khởi động lại để không ghi đè `.0000000000000001.log`, và `prune_rotated_logs` sắp xếp theo `(seq, name)` xóa bản ghi cũ nhất trước; đã kiểm chứng bằng `test_bounded_rotating_writer_preserves_newest_across_restarts`. | ✅ **CLOSED** |
| **`IMP-01`** | 🟡 Improve | `crates/mesh-net/src/netmon.rs:45` (`NetworkChangeEvent`) & `crates/mesh-datapath/src/rebind.rs:8-62` (`RebindCommand`, `RebindHandle` kênh hữu hạn `32` kèm `try_send`/`send` và unit test). | ✅ **CLOSED** |
| **`IMP-02`** | 🟡 Improve | Đã chuẩn hóa doc-comment trong toàn bộ `crates/mesh-datapath/src/*.rs` về `WP-S1-02` *(4 file `crates/mesh-sys/src/*_macos.rs` sẽ được chính `WP-S1-03` ghi đè trực tiếp khi hiện thực FFI ở Wave 1.1)*. | ✅ **CLOSED** |

---

## 6. ⚖️ `Strategic Trade-offs` & Lưu Ý Nhỏ Khi Triển Khai Wave 1.1

1. **Đánh đổi thiết kế `TLS 1.3-only` trên kênh Control/Relay (`HR-01`) vs Tương thích hạ tầng ngoài**: Việc khóa cứng `&rustls::version::TLS13` trên `ClientConfig` và `ServerConfig` loại bỏ hoàn toàn bề mặt hạ cấp TLS 1.2 và bất đồng ngữ nghĩa RFC 5705/8446 exporter; trong chế độ `reverse_proxy`, quản trị viên cần đảm bảo Nginx/Caddy phía trước bật `TLSv1.3` (mặc định trên mọi bản phân phối hiện đại và sẽ được khóa sẵn trong mẫu cấu hình `deploy/reverse-proxy/` của `WP-S1-01`).
2. **Lưu ý thực thi cho Worker C (`WP-S1-03`) trên `ipc_linux.rs` (`api-design.md` §4 dòng 487)**: Khi hiện thực thân hàm `mesh_sys::ipc_linux::inspect_peer_creds` và `mesh_net::ipc_linux::verify_unix_socket_peer` ở Wave 1.1, ngoài `uid == 0` và thành viên nhóm `mesh-admin`, nhớ cho phép thêm trường hợp `creds.uid == geteuid()` trên kênh `IpcChannelKind::ServerAdmin` để chính tài khoản dịch vụ `mesh` chạy lệnh chẩn đoán cục bộ luôn được chấp nhận ngay cả khi chưa gán phụ vào nhóm `mesh-admin`.

---

[APPROVED FOR GATE]
