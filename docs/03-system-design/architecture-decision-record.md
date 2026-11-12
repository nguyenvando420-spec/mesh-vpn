# Architecture Decision Records (ADR) — Mesh VPN (Rust 1.94.1 Stack)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-12 |
| Phiên bản | **2.0** — Cập nhật đồng bộ 100% sang **Rust `1.94.1` Stack** theo quyết định của Người dùng (2026-11-12 21:01), trình Gate 2 |
| Trạng thái chung | **Accepted-by-User (ADR-001) / Proposed-for-Gate-2 (ADR-002..011)** |
| Phạm vi | Quyết định công nghệ và ranh giới an toàn hệ thống. Giao thức chi tiết (schema bản tin, DB tables, C4) do `agile-architect` thiết kế dựa trên các ràng buộc bất biến trong tài liệu này |
| Liên kết | [tech-stack-decision.md](./tech-stack-decision.md) · [coding-standards.md](./coding-standards.md) · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Đầu vào | `production-readiness-requirements.md` v1.2, `product-backlog.md` v1.2, `project-charter.md` v1.2, quyết định Gate 1 (D1–D4) & quyết định chọn Rust (2026-11-12 21:01) |

---

## Mục lục

| ADR | Tiêu đề | Yêu cầu truy vết chính |
|---|---|---|
| [ADR-001](#adr-001) | Ngôn ngữ **Rust `1.94.1`** (`edition = "2024"`), chiến lược **Pure-Rust / Zero-C**, cô lập `unsafe` vào `mesh-sys` & Cross-Compile 4 đích | G1, G4, C5, PERF-01/09, GNFR-12 |
| [ADR-002](#adr-002) | WireGuard Userspace Sans-I/O (`defguard_boringtun::noise::Tunn`) ghép trên **1 `tokio::net::UdpSocket` duy nhất** (`MagicSocket`) | SEC-02, REL-05/09/10, SEC-11, US-014/015/060/019/021 |
| [ADR-003](#adr-003) | Giao thức Control & Xác thực Khóa: TLS 1.3 (`rustls`) + Challenge–Response NaCl Box (`crypto_box`) + Pre-Auth Key SHA-256 + Disco Auth | SEC-02/03/05, REL-02, US-003/004/021 |
| [ADR-004](#adr-004) | Blind Relay trên WebSocket/TLS (`axum` + `tokio-tungstenite`) chung 1 cổng TCP & Hàng đợi `try_send` chống Head-of-Line Blocking | SEC-07, REL-06, PERF-11, US-024/025/027 |
| [ADR-005](#adr-005) | Cơ sở dữ liệu nhúng ACID thuần Rust **`redb`** trên VPS, khẩn cấp thu hồi trong RAM khi đầy đĩa & Hot Atomic Snapshot Backup | REL-11/12, SEC-08/09, US-007/013/045 |
| [ADR-006](#adr-006) | Kênh Admin IPC cục bộ kiểm chứng đặc quyền OS (`SEC-14`: Unix Socket `peer_cred` & Windows Named Pipe SDDL) tách rời Listener Quan sát | SEC-14, OPS-05/06/08, PLAT-01/06, US-012/044/046 |
| [ADR-007](#adr-007) | Tích hợp Nền tảng: macOS (`utun` + `launchd`), Windows (`Wintun` + Service), Linux (`/dev/net/tun` + `systemd`); Chống Routing Loop & Sổ cái Tài nguyên | REL-08/09, PLAT-01..06, US-016/035/036/038/052/055/073 |
| [ADR-008](#adr-008) | Vòng đời TLS (`rustls`): Chế độ IP + SPKI Pinning (`rcgen`, mặc định hạng nhất) · Standalone ACME (`instant-acme`) · Sau Reverse Proxy | SEC-04, SEC-05, US-003/034/042/047 |
| [ADR-009](#adr-009) | Cổng & Địa chỉ cấu hình được (`GNFR-11`); Di chuyển cấu hình không mất danh tính (`SEC-15`) qua `ListenerSet` song song & `relay_map` | GNFR-11, SEC-06/15, US-009/019/024/074 |
| [ADR-010](#adr-010) | Bảo vệ Bí mật trong RAM (`ZeroizeOnDrop` + Redacted `Secret<T>`) & Quan sát có cấu trúc (`tracing` JSON + Prometheus text) | SEC-01, OPS-01/06, GNFR-02, US-001/043/048 |
| [ADR-011](#adr-011) | Đóng gói & Toàn vẹn Bản phát hành (4 đích, `SHA256SUMS` ký số, kiểm SHA-256 `wintun.dll` trước khi nạp, ký ad-hoc Mach-O `arm64`) | PLAT-01/06, C5, R-11/R-18, US-015/073 |

---

<a id="adr-001"></a>
## ADR-001 — Ngôn ngữ Rust 1.94.1, Kiến trúc Pure-Rust / Zero-C & Cô lập `unsafe`

- **Trạng thái**: **Accepted (Người dùng đã chốt ngày 2026-11-12 21:01)**
- **Ngày**: 2026-11-12

### Context
- Hệ thống Mesh VPN gồm daemon chạy nền 24/7 với đặc quyền cao nhất của hệ điều hành (`root` trên macOS/Linux, `LocalSystem` trên Windows) và dịch vụ điều phối/chuyển tiếp (`mesh-server`) trên 1 VPS cá nhân (1–2 vCPU, 1–2 GB RAM, có thể đang chạy chung web cá nhân).
- Người dùng đặt ưu tiên cao nhất vào:
  1. **Không có Garbage Collector (GC)**, không có hiện tượng dừng thế giới (stop-the-world) hay phình heap ngầm.
  2. **Tiêu thụ tài nguyên tối thiểu**: RAM chạy nền ~4–10 MB trên client (`PERF-09 ≤ 50 MB`), ~8–18 MB trên VPS (`PERF-01 < 64 MB`), kích thước nhị phân nhỏ gọn (~3–6 MB).
  3. **An toàn bộ nhớ tuyệt đối** ngay ở bước biên dịch cho toàn bộ bộ phân tích gói tin mạng (WireGuard, STUN, Disco, Relay, Control) và khả năng xóa sạch khóa bí mật trong RAM ngay khi giải phóng (`SEC-01`).
- Máy phát triển Windows của người dùng đã cài sẵn `rustc 1.94.1`, `cargo 1.94.1`, `rustfmt`, `clippy`, `docker`, `wsl` `[V]`, nhưng chưa cài Visual Studio C++ Build Tools (6 GB) hay `zig` `[V]`. Phải hỗ trợ build và kiểm thử cho 4 đích MVP: `x86_64-pc-windows-*`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-*`.

### Options
1. **Phương án A — Rust `1.94.1` (`edition = "2024"`) với kỷ luật Pure-Rust / Zero-C (`redb`, `rustls`, `defguard_boringtun`) + cô lập FFI duy nhất ở `crates/mesh-sys` (CHỌN)**:
   - Không có GC; kiểm soát chính xác số worker threads của `tokio` và tái sử dụng buffer tĩnh; không kéo theo C-SQLite hay OpenSSL C.
2. **Phương án B — Go 1.27 (`CGO_ENABLED=0`)**:
   - Thuận tiện khi cross-compile nhưng có runtime GC, tốn RAM nền cao hơn (~20–45 MB), binary lớn hơn (~8–18 MB) và không thể xóa tất định vùng nhớ khóa do GC tự di chuyển object. (Người dùng đã loại để chọn Rust).
3. **Phương án C — C++20**:
   - Không có GC nhưng thiếu an toàn bộ nhớ ở tầng trình biên dịch; rủi ro lỗi buffer overflow / use-after-free cao khi chạy dưới quyền `root`/`SYSTEM`.

### Decision
1. Chốt **Rust `1.94.1`** (`edition = "2024"`, `rust-version = "1.94.1"`, ghim trong `rust-toolchain.toml`) cho toàn bộ dự án trong **1 Cargo Workspace** gồm 3 binaries (`mesh-server`, `meshd`, `mesh`) và 7 thư viện nội bộ (`crates/mesh-*`).
2. **Cấm `unsafe` mặc định toàn workspace**: đặt `[workspace.lints.rust] unsafe_code = "forbid"` trong `Cargo.toml` gốc. Chỉ duy nhất crate `crates/mesh-sys` được phép bật `#![allow(unsafe_code)]` kèm `#![deny(unsafe_op_in_unsafe_fn)]` và `#![deny(clippy::undocumented_unsafe_blocks)]` (mọi khối `unsafe` trong `mesh-sys` bắt buộc có chú thích `// SAFETY:` giải trình bất biến con trỏ/handle).
3. **Chiến lược Pure-Rust / Zero-C**: cấm các crate bọc thư viện C lớn (`openssl-sys`, `libsqlite3-sys`/`rusqlite`, `libsodium-sys`); tắt feature `aws-lc-rs` mặc định của `rustls` (vốn đòi CMake + NASM trên Windows) và dùng `ring` (kèm feature dự phòng thuần Rust `rustls-rustcrypto`).
4. **Cấu hình Release Profile nhỏ nhẹ**: `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`.
5. **Toolchain & Cross-compile (`scripts/bootstrap-toolchain.ps1`)**: hỗ trợ cả chế độ gọn nhẹ `-Mode PortableZig` (tải Zig portable kiểm SHA-256 + `cargo-zigbuild` + `cargo-deny` + `rcodesign` để build Windows, Linux `musl` và macOS `arm64`/`x86_64` không cần cài 6 GB Visual Studio) lẫn chế độ `-Mode Msvc` (Visual Studio BuildTools), kết hợp GitHub Actions matrix (`ubuntu-latest`, `windows-latest`, `macos-latest`) cho bản phát hành và kiểm thử OS native.

### Consequences
- **(+) Tích cực**: Đạt đúng mục tiêu của người dùng về hiệu năng, không GC, RAM ~4–18 MB, binary ~3–6 MB, xóa khóa tức thì bằng `ZeroizeOnDrop`, và loại trừ hoàn toàn lỗi bộ nhớ trong toàn bộ tầng giao thức.
- **(−) Chi phí / Giảm thiểu**: Thời gian biên dịch Rust lâu hơn Go và cần linker trên máy Windows → giảm thiểu bằng việc chạy `scripts/bootstrap-toolchain.ps1` một lần ở đầu Sprint 1 và tận dụng cache Cargo incremental.

---

<a id="adr-002"></a>
## ADR-002 — WireGuard Userspace Sans-I/O (`defguard_boringtun`) & Một UDP Socket Chung (`MagicSocket`)

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- Yêu cầu `SEC-02` / `GNFR-01` cấm tự cài đặt primitive mật mã hay tự lắp giao thức đường hầm; `A-04` chốt dùng giao thức WireGuard ở userspace trên macOS, Windows và Linux.
- Để đục lỗ NAT (`US-019`, `US-021`) và chuyển mạch tức thì sang Blind Relay (`REL-05`, `US-022`, `US-026`), gói STUN Binding, gói Authenticated Disco (`Ping`/`Pong`/`CallMeMaybe`) và gói dữ liệu WireGuard **bắt buộc phải gửi/nhận trên cùng một cổng UDP cục bộ** (được lưu bền qua các lần khởi động lại theo `US-019 AC1`).

### Options
1. **Phương án A — `defguard_boringtun` `0.6` (BSD-3-Clause) ở chế độ state machine Sans-I/O `noise::Tunn` ghép vào 1 `tokio::net::UdpSocket` (`MagicSocket`) (CHỌN)**:
   - `Tunn` chỉ nhận slice `&[u8]` và xuất ra kết quả `TunnResult` (`WriteToNetwork`, `WriteToTunnelV4`, `Done`, `Err`) trên buffer cấp sẵn `[u8; 2048]`, hoàn toàn không tự mở socket hay tạo thread ngầm.
2. **Phương án B — `gotatun` (MPL-2.0)**:
   - Dính giấy phép copyleft `MPL-2.0` và cấu trúc I/O nội bộ gắn chặt với Mullvad.
3. **Phương án C — Tự lắp `Noise_IKpsk2` bằng crate `snow`**:
   - Vi phạm nghiêm trọng `SEC-02` / `GNFR-01` (tự cài đặt lại state machine handshake/rekey/cookie/replay counter của WireGuard).

### Decision
1. Sử dụng **`defguard_boringtun` `0.6`** (BSD-3-Clause) duy nhất bên trong `crates/mesh-datapath`.
2. Xây dựng **`MagicSocket`** sở hữu **1 `tokio::net::UdpSocket`** (ưu tiên bind lại cổng UDP cục bộ đã lưu bền trong tệp trạng thái; tắt cờ ép cứng `DF=1` ở tầng UDP ngoài theo `US-017 AC3`).
3. **Bộ phân luồng gói đến (Ingress Demuxer)** không cấp phát heap:
   - Kiểm tra độ dài tối thiểu ≥ 20 byte và `pkt[4..8] == 0x2112A442` → chuyển cho `mesh_proto::stun`.
   - Kiểm tra tiền tố 6 byte `pkt[0..6] == b"MESHDS"` (`0x4d4553484453`) → chuyển cho `mesh_datapath::disco`.
   - Còn lại → định tuyến vào `Tunn::decapsulate` của peer tương ứng; kiểm tra chặt `AllowedIPs` = đúng `/32` Overlay IP của peer đó (`SEC-11`, `US-014 AC3/AC4`) trước khi bơm gói IPv4 vào `TunDevice`.
4. **Bộ chọn đường gửi (Egress Path Selector)**:
   - Sau khi `Tunn::encapsulate` mã hóa gói IP thành gói WireGuard, nếu peer đang có đường `Direct(SocketAddr)` còn hiệu lực thì gửi qua `UdpSocket`; nếu chưa có direct hoặc vừa mất 3 nhịp Pong liên tiếp / quá `REKEY_TIMEOUT` (`US-022`, `US-026`) thì bọc gói đã mã hóa đẩy qua kênh `BlindRelay` ngay lập tức (≤ 1 s).
5. **Áp dụng Netmap theo Diff (`REL-03`, `US-010`)**: bảng `PeerMap` chỉ khởi tạo mới `Tunn` cho peer mới, cập nhật endpoint cho peer đổi địa chỉ và xóa `Tunn` của peer bị thu hồi (`US-030`), giữ nguyên trạng thái phiên và bộ đếm của các peer không đổi (0% mất gói giữa các node cũ).
6. **MTU mặc định `1280`** (`REL-10`, `US-017`), cấu hình được trong khoảng `576..=1420`.

### Consequences
- **(+) Tích cực**: Không có goroutine/thread ngầm của thư viện đụng độ với vòng lặp sự kiện; dùng chung 1 UDP socket tự nhiên, RAM cực thấp và dễ dàng kiểm thử tất định (unit test `Tunn` + `MagicSocket` hoàn toàn trong bộ nhớ không cần mở card mạng thật!).
- **(−) Chi phí / Giảm thiểu**: `mesh-datapath` phải gọi `Tunn::update_timers` theo chu kỳ (mỗi 250 ms) và quản lý keepalive on-demand (`US-022 AC4`: giữ keepalive 25 s khi có lưu lượng trong cửa sổ 3–5 phút, tự nghỉ khi rảnh lâu để đạt `GNFR-07 ≤ 1 KB/s`).

---

<a id="adr-003"></a>
## ADR-003 — Giao thức Control & Xác thực Khóa (TLS 1.3 + NaCl Box Challenge + Disco Auth)

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- `SEC-01`: Khóa riêng Curve25519 sinh tại client, không bao giờ rời client.
- `SEC-02` & `US-003`: Kênh Control dùng TLS 1.3 + chứng minh sở hữu khóa node bằng challenge/nonce ngẫu nhiên từ server (không phụ thuộc đồng hồ tuyệt đối của client để tránh lỗi dual-boot Windows/Linux `US-003 AC5`). Vì khóa WireGuard là Curve25519 (X25519 — chỉ thực hiện Diffie-Hellman, không ký số EdDSA trực tiếp), phép chứng minh sở hữu phải dùng cấu trúc chuẩn dựa trên X25519.
- `SEC-03` & `SEC-05`: Pre-Auth Key ≥ 128 bit, one-time mặc định, có TTL, chỉ lưu băm, so sánh constant-time, trả về **cùng một thông điệp lỗi chung** cho mọi lỗi xác thực.
- `US-021`: Gói đục lỗ NAT (`Ping`/`Pong`/`CallMeMaybe`) phải được xác thực mật mã gắn với `disco_key` trong Netmap kèm `tx_id` ngẫu nhiên chống phát lại và chống đầu độc endpoint (Endpoint Poisoning).

### Options
1. **Phương án A — TLS 1.3 (`rustls`) + Challenge–Response bằng NaCl Box (`crypto_box`: X25519 + XSalsa20-Poly1305) + SHA-256 (`sha2` + `subtle::ConstantTimeEq`) (CHỌN)**:
   - Chuẩn mật mã đã kiểm định, dùng cùng một nguyên thủy `crypto_box` cho cả bước chứng minh khóa Control lẫn xác thực gói Disco; hoạt động tốt cả ở chế độ TLS trực tiếp lẫn sau Reverse Proxy.
2. **Phương án B — mTLS bằng chứng chỉ X.509 phía client**:
   - Không chạy được khi VPS đứng sau Reverse Proxy (`Nginx`/`Caddy`) sẵn có của người dùng mà không cấu hình lại proxy phức tạp.

### Decision
1. **Cô lập mật mã**: Tất cả các phép toán dưới đây được đóng gói duy nhất trong `crates/mesh-crypto`.
2. **Chứng minh sở hữu khóa Node (`US-003`)**:
   - Bước 1: Client mở kết nối TLS (đã xác minh SPKI Pin hoặc CA theo `ADR-008`) và gửi `Hello { node_pubkey, protocol_version, agent_version, os, arch }`.
   - Bước 2: Server sinh cặp khóa X25519 tạm thời theo phiên (`server_eph_secret`, `server_eph_pub`) và `challenge_nonce: [u8; 32]` từ `OsRng`, lưu trong RAM với TTL 30 s (dùng 1 lần).
   - Bước 3: Client dùng `crypto_box::SalsaBox::new(&server_eph_pub, &node_secret)` mã hóa xác thực (`seal`) bản tin `ProofPayload { challenge_nonce, session_id, node_pubkey, tls_exporter_binding }` với `box_nonce: [u8; 24]` ngẫu nhiên. (Khi kết nối TLS trực tiếp, `tls_exporter_binding` lấy từ `rustls::Connection::export_keying_material` nhãn `"EXPORTER-mesh-control-v1"`; khi qua Reverse Proxy được cấu hình tường minh thì dùng giá trị rỗng đã đánh dấu).
   - Bước 4: Server mở hộp (`open`) bằng `SalsaBox::new(&node_pubkey, &server_eph_secret)` và kiểm tra `challenge_nonce`. Chỉ bên nắm giữ `node_secret` mới tạo được ciphertext hợp lệ.
3. **Pre-Auth Key (`US-002`, `US-004`, `US-005`, `US-031`)**:
   - Định dạng hiển thị một lần: `mpk_<base32_nopad(32 bytes từ OsRng)>` (256-bit entropy).
   - Lưu trữ trong `redb`: chỉ lưu `sha256(raw_key)` (`[u8; 32]`). Khi kiểm tra, luôn băm đầu vào trước rồi so sánh bằng `subtle::ConstantTimeEq::ct_eq` (`US-042 AC2`).
   - Hỗ trợ trói đích danh `target_node_id: Option<NodeId>` (`--for <node>`) để phục vụ đăng ký lại khi hết hạn khóa (`US-031 AC5/AC6`) hoặc xoay khóa (`US-032`) mà không cho phép key thường chiếm đoạt tên/IP của node khác.
4. **Xác thực Disco (`US-021`)**:
   - Mỗi agent sinh cặp khóa `disco_key` (X25519) riêng biệt với khóa data plane (đảm bảo *domain separation*) và công bố `disco_pubkey` trong Netmap (`US-009 AC1`).
   - Mọi gói `Ping`, `Pong`, `CallMeMaybe` đều được niêm phong bằng `crypto_box` giữa `(self_disco_secret, peer_disco_pubkey)` và chứa `tx_id: [u8; 12]` ngẫu nhiên từ `OsRng`.
   - Agent giữ bảng `pending_pings` có giới hạn kích thước và TTL (10 s): chỉ chấp nhận `Pong` giải mã thành công từ `peer_disco_pubkey` thuộc Netmap hiện hành **và** khớp đúng `tx_id` đang chờ. Mọi gói sai xác thực hoặc phát lại đều bị **bỏ qua im lặng** (`US-021 AC5`).

### Consequences
- **(+) Tích cực**: Không phụ thuộc đồng hồ hệ thống ở tầng challenge; chống MITM, chống phát lại và chống đầu độc đường đi P2P trên mạng Wi-Fi công cộng; dùng chung 1 thư viện `crypto_box` nhỏ gọn.
- **(−) Chi phí / Giảm thiểu**: Cần kiểm thử kỹ vector xác thực và fuzz bộ giải mã gói Disco (`proptest` ≥ $10^5$ gói đột biến theo `US-021 AC3`).

---

<a id="adr-004"></a>
## ADR-004 — Blind Relay trên WebSocket/TLS Chung Cổng TCP & Hàng đợi `try_send` Chống Nghẽn Dây Chuyền

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- `REL-06` & `US-024`: Relay chạy trên cùng cổng TCP đã cấu hình của VPS (mặc định `443`, đổi được sang cổng bất kỳ như `8443`), hoạt động ở cả chế độ Standalone TLS lẫn sau Reverse Proxy (`Nginx`/`Caddy`).
- `SEC-07` & `US-025`: Relay chỉ chuyển tiếp mù gói đã mã hóa cho node hợp lệ, tự gắn `src_pubkey` đã xác thực của người gửi (không tin trường nguồn do client tự khai), giới hạn băng thông mỗi node (mặc định 20 Mbps, `US-027`), và **cô lập hàng đợi theo từng đích** để một peer đọc chậm không làm treo các peer khác (chống Cross-Peer Head-of-Line Blocking, `US-025 AC6`).

### Options
1. **Phương án A — WebSocket Binary Frames (`axum` + `tokio-tungstenite`) với kênh `tokio::sync::mpsc::channel(256)` + `try_send` cho mỗi đích (CHỌN)**:
   - Tương thích 100% với mọi Reverse Proxy chuẩn qua HTTP/1.1 `Upgrade: websocket`; cô lập hoàn toàn luồng đọc và luồng ghi.
2. **Phương án B — Giao thức TCP framing thô sau HTTP Hijack**:
   - Nhiều Reverse Proxy thương mại hoặc cấu hình chuẩn chỉ hỗ trợ chuyển tiếp luồng hai chiều khi là `Upgrade: websocket`.

### Decision
1. Trên cùng cổng TCP của `mesh-server`, router `axum` phục vụ:
   - `POST /v1/auth/challenge`, `POST /v1/nodes/register` (Control RPC).
   - `GET /v1/netmap/stream` (WebSocket đẩy Netmap snapshot + heartbeat ≤ 30 s).
   - `GET /v1/relay` (WebSocket Blind Relay, sau khi hoàn tất xác thực khóa node theo `ADR-003`).
2. **Định dạng Frame Nhị phân của Blind Relay (`US-025`)**:
   - Client $A \to$ Relay: `[dst_pubkey: 32 bytes][wg_or_disco_ciphertext: <= 1480 bytes]`.
   - Relay $\to$ Client $B$: `[src_pubkey: 32 bytes (do Relay gắn từ phiên xác thực của A)][wg_or_disco_ciphertext]`.
   - Cấu hình `tokio-tungstenite` đặt `max_frame_size = 2048` và `max_message_size = 2048` để chặn tấn công cấp phát bộ nhớ lớn (`US-025 AC3`).
3. **Kiến trúc Chống Nghẽn Dây Chuyền (`US-025 AC6`)**:
   - Mỗi phiên kết nối của node đích $B$ sở hữu một task ghi riêng đọc từ `mpsc::Receiver<Bytes>` có sức chứa cố định **256 gói** và áp `tokio::time::timeout(Duration::from_secs(5), ws_sink.send(...))`.
   - Khi luồng đọc của node $A$ chuyển gói tới $B$, Relay gọi **`tx_b.try_send(frame)`**: nếu hàng đợi của $B$ đầy, gói tới $B$ bị **drop ngay lập tức không chặn** và tăng bộ đếm `mesh_relay_dropped_total{dest=...}`, trong khi gói từ $A$ tới $C$ vẫn đi qua tức thì với độ trễ bằng 0!
4. **Giới hạn Băng thông & Cắt tức thì khi Thu hồi (`US-027`, `US-029`)**:
   - Mỗi node có một bộ điều tiết Token Bucket nguyên tử (mặc định 20 Mbps/node) kết hợp một Token Bucket trần tổng của VPS.
   - Mỗi phiên Relay gắn một `CancellationToken` theo `NodeId`: khi `node revoke` hoặc `node expire` được kích hoạt, token bị hủy tức thì, đóng kết nối WebSocket trong **< 100 ms** (vượt xa ngưỡng `≤ 5 s` của `SEC-07`).

### Consequences
- **(+) Tích cực**: Một cổng TCP duy nhất cho mọi nhu cầu; chạy mượt sau Nginx/Caddy; loại bỏ hoàn toàn hiện tượng một máy yếu mạng kéo sập toàn bộ Relay.
- **(−) Chi phí / Giảm thiểu**: Khi mạng chặn cổng khác `443`, agent phải phát hiện lỗi kết nối TCP và hiển thị chẩn đoán trung thực theo `REL-06(b)` / `US-024 AC7`.

---

<a id="adr-005"></a>
## ADR-005 — Lưu trữ ACID Thuần Rust (`redb`), Ưu tiên Thu hồi trong RAM khi Đầy Đĩa & Hot Atomic Backup

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- `REL-11` (`US-007`): Trạng thái Control phải đảm bảo giao dịch ACID (cấp IP + tạo node + đánh dấu key đã dùng trong **1 transaction duy nhất**), ràng buộc duy nhất trên `public_key` và `overlay_ip`, kiểm tra toàn vẹn lúc khởi động, và không hỏng dữ liệu khi `kill -9` hay đầy đĩa.
- `US-013 AC4`: Khi đĩa đầy khiến ghi audit thất bại, các thao tác tạo mới phải *fail-closed*, nhưng các lệnh phòng vệ khẩn cấp (`node revoke`, `preauthkey revoke`, `node expire`) **bắt buộc phải thực thi ngay trong RAM** và xuất audit ra `stderr`/`journald` để cắt kẻ xâm nhập tức thì.
- `REL-12` (`US-045`): Sao lưu nóng tự động không khóa ghi > 1 s, kèm mã kiểm tra toàn vẹn SHA-256, giữ 7 bản, **bao gồm khóa định danh server dùng cho SPKI Pin** để khôi phục không phải pin lại mọi máy.

### Options
1. **Phương án A — `redb` `2.4` (MIT/Apache-2.0, 100% Pure Rust ACID MVCC B-tree) (CHỌN)**:
   - Không có mã C, không có `unsafe` FFI C-SQLite; giao dịch `WriteTransaction` đảm bảo ACID nguyên tử trên nhiều bảng; `ReadTransaction` dùng MVCC không bao giờ chặn luồng ghi; footprint cực nhỏ.
2. **Phương án B — `rusqlite` (`bundled` C SQLite)**:
   - Kéo theo ~250.000 dòng mã C, cần trình biên dịch C khi cross-compile và tăng kích thước binary.

### Decision
1. Dùng **`redb` `2.4`** duy nhất trong `crates/mesh-store` với các bảng định kiểu (`TableDefinition`):
   - `schema_meta`: phiên bản schema hiện hành và lịch sử migration.
   - `server_identity`: khóa định danh server (đã bọc bảo vệ, quyền tệp DB `0600`), tập pin (`active_pin`, `next_pin`), cấu hình cổng/chế độ hiện hành.
   - `nodes`: `NodeId -> NodeRecord` (tên, `overlay_ip`, `node_pubkey`, `disco_pubkey`, `key_expiry`, `status`, `created_at`…).
   - `idx_nodes_pubkey`: `[u8; 32] -> NodeId` và `idx_nodes_overlay_ip`: `u32 -> NodeId` — kiểm tra và ghi cùng trong 1 `WriteTransaction` để cưỡng chế tính duy nhất tuyệt đối (`UNIQUE(public_key)`, `UNIQUE(overlay_ip)` — `REL-02`, `US-005`).
   - `preauth_keys`: `KeyId -> PreAuthKeyRecord` và `idx_preauth_hash`: `[u8; 32] -> KeyId`.
   - `audit_events`: `u64 (seq) -> AuditRecord` — tầng store chỉ cung cấp hàm `append_audit`, **không tồn tại bất kỳ hàm sửa/xóa bản ghi nào** (`US-013 AC2`).
2. **Kiểm tra toàn vẹn khi khởi động (`US-007 AC3`)**: Gọi `db.check_integrity()` khi mở DB; nếu phát hiện lỗi, dừng khởi động kèm thông báo hướng dẫn chạy `mesh-server restore`.
3. **Cơ chế Thu hồi Khẩn cấp trong RAM khi Đầy Đĩa (`US-013 AC4`)**:
   - `mesh-server` duy trì tập `RevokedSet` (`RwLock<HashSet<NodeId>>` và `HashSet<KeyId>`) trong bộ nhớ làm nguồn chặn tức thì trước mọi quyết định Control/Relay.
   - Với thao tác thông thường (`register`, `create key`, `rename`): nếu `write_tx.commit()` thất bại (vd. `ENOSPC`), thao tác bị từ chối (*fail-closed*) và `/readyz` chuyển sang `503` (`US-007 AC5`).
   - Với thao tác phòng vệ khẩn cấp (`node revoke`, `preauthkey revoke`, `node expire`): cập nhật `RevokedSet` trong RAM, tăng `netmap_version` trong RAM, đẩy Netmap mới và ngắt kết nối Relay/Control của kẻ xâm nhập **ngay lập tức**, sau đó cố gắng ghi `redb`; nếu ghi đĩa lỗi thì vẫn giữ hiệu lực thu hồi trong RAM và xuất bản ghi audit mức `CRITICAL` ra `stderr`/`journald`.
4. **Sao lưu nóng nguyên tử (`US-045`)**:
   - Mở `ReadTransaction` trên DB đang chạy (không chặn ghi), sao chép toàn bộ các bảng (bao gồm `server_identity`) sang tệp `redb` tạm trong thư mục backup (`0700`), gọi `commit()` + `sync_all()`, mở lại tệp tạm kiểm tra `check_integrity()`, tính băm SHA-256 ghi ra `<backup>.db.sha256`, đổi tên nguyên tử (`rename`) với quyền `0600`, và xoay vòng giữ 7 bản gần nhất.
   - Lệnh `restore <file>` kiểm tra khớp `.sha256`, kiểm tra `check_integrity()` và xác nhận có `server_identity` hợp lệ trước khi khôi phục (`US-045 AC4/AC6`).

### Consequences
- **(+) Tích cực**: 100% Pure Rust, không phụ thuộc C compiler, tốc độ đọc từ MVCC cực nhanh, sao lưu nóng an toàn không chặn luồng đăng ký.
- **(−) Chi phí / Giảm thiểu**: Các bảng chỉ mục phụ (`idx_nodes_pubkey`, `idx_nodes_overlay_ip`) được duy trì tường minh trong hàm giao dịch của `mesh-store` → bắt buộc có unit test và property test kiểm tra bất biến chỉ mục sau 100 lần crash/rollback mô phỏng (`US-007 AC2`).

---

<a id="adr-006"></a>
## ADR-006 — Kênh Admin IPC Cục bộ Kiểm chứng Đặc quyền OS (`SEC-14`) & Tách rời Listener Quan sát

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- `SEC-14` (`BLK-01`): Tuyệt đối cấm mở Admin API trên IP overlay, IP public hay TCP loopback `127.0.0.1` trần (vì MVP là full-mesh không ACL nên một laptop bị trộm trên mạng overlay hoặc một tiến trình web/container bị lỗi SSRF trên VPS dùng chung có thể gọi `127.0.0.1` chiếm quyền Admin).
- Trên máy client (macOS `PLAT-06(3)` / `US-073`, Windows `PLAT-01` / `US-052`), user thường không được phép gọi daemon thực hiện thao tác thay đổi mạng (`up`, `down`, `cleanup`, `set --server/--server-pin`).

### Options
1. **Phương án A — HTTP/1.1 JSON qua Unix Domain Socket kèm kiểm tra `peer_cred()` (`SO_PEERCRED` Linux / `LOCAL_PEERCRED` macOS) và Windows Named Pipe kèm SDDL DACL (`SYSTEM` + `Administrators`) (CHỌN)**:
   - Đặc quyền của tiến trình gọi được chính kernel hệ điều hành chứng thực; không dựa vào token tĩnh có thể bị lộ.
2. **Phương án B — TCP `127.0.0.1` kèm tệp token trên đĩa**:
   - Bị cấm trực tiếp bởi `SEC-14(2)(b)`.

### Decision
1. **Kênh Admin của `mesh-server` trên VPS Linux (`US-012`, `US-046`)**:
   - Chỉ lắng nghe trên Unix Domain Socket `/run/mesh/admin.sock` (thư mục `/run/mesh` quyền `0750` thuộc `mesh:mesh-admin`, socket quyền `0660`).
   - Ngay khi nhận kết nối `tokio::net::UnixStream`, gọi `stream.peer_cred()` (sử dụng `SO_PEERCRED` của kernel Linux) lấy `(uid, gid, pid)`: chỉ chấp nhận `uid == 0` (`root`), `uid == service_uid`, hoặc `gid == admin_gid`. Ghi `uid` và `pid` vào bản ghi Audit (`SEC-09`).
2. **Kênh IPC của `meshd` trên macOS (`US-073 AC3/AC4`)**:
   - Lắng nghe trên `/var/run/mesh/meshd.sock` (thư mục `/var/run/mesh` quyền `0755` thuộc `root:wheel`, kiểm tra chống symlink trên toàn bộ đường dẫn cha).
   - Khi nhận kết nối, gọi `stream.peer_cred()` (sử dụng `LOCAL_PEERCRED` trên macOS) để lấy `uid`/`gid` thực của người gọi:
     - Các thao tác thay đổi trạng thái (`up`, `down`, `cleanup`, `set`, `rotate-key`) **chỉ cho phép `uid == 0` (`root`) hoặc thành viên nhóm `admin` (`gid == 80`)**. User thường bị từ chối với lỗi `PermissionDenied` và ghi log cảnh báo.
     - Các thao tác chỉ-đọc chẩn đoán (`status`, `ping`, `netcheck`) được phép gọi nhưng phản hồi tuyệt đối không chứa bất kỳ khóa bí mật nào (`US-039 AC5`).
3. **Kênh IPC của `meshd` trên Windows (`US-052 AC3`)**:
   - Tạo Windows Named Pipe `\\.\pipe\mesh-agent-admin` bằng `windows-sys` (`CreateNamedPipeW`) với chuỗi bảo mật **SDDL**: `D:P(A;;GA;;;SY)(A;;GA;;;BA)` — chỉ cấp quyền cho `LocalSystem` (`SY`) và nhóm `Administrators` (`BA`) kèm cờ `FILE_FLAG_FIRST_PIPE_INSTANCE` (chống chiếm đoạt pipe trước khi service chạy).
   - Named pipe chỉ-đọc `\\.\pipe\mesh-agent-ro` (cho `mesh status`, `mesh ping`) chỉ mở các route đọc không nhạy cảm.
4. **Listener Quan sát Chỉ-Đọc riêng biệt (`OPS-05`, `OPS-06`, `US-044`, `US-048`)**:
   - Một instance `axum::Router` hoàn toàn độc lập, mặc định chỉ bind `127.0.0.1:<obs_port>` (hoặc IP overlay nếu bật tường minh), **chỉ đăng ký đúng 3 route `GET /healthz`, `GET /readyz`, `GET /metrics`**, không chia sẻ router hay middleware với kênh Admin.

### Consequences
- **(+) Tích cực**: Loại bỏ 100% nguy cơ leo thang đặc quyền từ mạng overlay, từ SSRF trên VPS dùng chung, hoặc từ user không có quyền quản trị trên máy macOS/Windows.
- **(−) Chi phí / Giảm thiểu**: Tách mã IPC theo OS trong `crates/mesh-net` + `crates/mesh-sys` và có bộ kiểm thử phân quyền trên cả 3 OS.

---

<a id="adr-007"></a>
## ADR-007 — Tích hợp Nền tảng, Chống Routing Loop & Tự Dọn Dẹp bằng Sổ cái Tài nguyên

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- Mục tiêu sống còn `G4`: **Không bao giờ làm hỏng mạng máy thật** kể cả khi daemon bị `kill -9`, mất điện, đổi Wi-Fi hay chạy chung với VPN khác / iCloud Private Relay (`REL-08`, `REL-09`, `PLAT-01..06`).
- Trên macOS (`PLAT-06`, `US-060`, `US-073`), không dùng chứng chỉ Apple Developer $99/năm (không dùng NetworkExtension), kernel tự cấp số `utunN` động, `/etc/hosts` là symlink tới `/private/etc/hosts`, và Application Firewall có thể chặn UDP inbound im lặng.

### Options & Decision
1. **Sổ cái Tài nguyên Nguyên tử (`ResourceLedger` — `REL-08`, `US-055`)**:
   - Trước khi `meshd` tạo hoặc sửa bất kỳ tài nguyên hệ thống nào (tên `utunN` thực tế trên macOS, GUID/tên adapter Wintun trên Windows, tên `mesh0` trên Linux, danh sách route CIDR đã thêm, anchor `pf`, rule firewall, khối hosts), nó **ghi nguyên tử mục đó vào tệp `/var/db/mesh/ledger.json` (macOS) / `/var/lib/mesh/ledger.json` (Linux) / `C:\ProgramData\Mesh\ledger.json` (Windows)** với quyền `0600`.
   - Khi tắt dịch vụ (`SIGTERM`, `launchctl bootout`, Windows Service Stop — ngân sách **≤ 5 s**) hoặc khi vừa khởi động lại sau crash (`kill -9`), `meshd` đọc `ledger.json` và **chỉ dọn đúng các tài nguyên được liệt kê trong sổ cái**. Tuyệt đối cấm quét xóa theo mẫu `utun*` (bảo vệ 100% iCloud Private Relay và các VPN khác theo `US-060 AC3`, `US-055 AC6`).
2. **Chống Routing Loop ở Tầng Socket (`REL-09`, `US-016`)**:
   - Mọi socket ngoại biên của `meshd` (`MagicSocket` UDP, kết nối TCP tới Control/Relay) bắt buộc được ràng cứng vào interface vật lý mặc định thông qua `mesh-sys` / `socket2` **trước khi gửi gói** và ràng lại mỗi khi sự kiện mạng báo đổi interface mặc định (`US-035 AC7`):
     - **macOS**: `setsockopt(..., IPPROTO_IP, IP_BOUND_IF, if_index)` và `IPV6_BOUND_IF`.
     - **Windows**: `setsockopt(..., IPPROTO_IP, IP_UNICAST_IF, if_index_be)` và `IPV6_UNICAST_IF`.
     - **Linux (VPS-node & Lab)**: `setsockopt(..., SOL_SOCKET, SO_MARK, fwmark)` kết hợp policy routing loại trừ `fwmark` khỏi bảng route tunnel.
   - Chỉ cài route cho đúng dải CIDR overlay (không cài default route `0.0.0.0/0` ở MVP); lọc bỏ mọi endpoint ứng viên nằm trong dải overlay hoặc thuộc các card ảo (`utun*`, `awdl0`, `llw0`, `bridge*`, `docker0`, `veth*`, WSL/Hyper-V — `US-020 AC2`).
3. **Quản lý Khối `hosts` & Xả Cache DNS (`PLAT-04`, `US-038`)**:
   - Chỉ thao tác bên trong cặp thẻ đánh dấu `# BEGIN mesh` … `# END mesh`.
   - Kiểm tra tên node bằng kiểu `NodeName` (chỉ `[a-z0-9-]`, 1–63 ký tự, từ chối `\n`, `\r`, `#`, khoảng trắng, từ chối danh sách cấm `localhost`, `broadcasthost`, `wpad`, `isatap`, `local` và hostname/IP public của chính Control/Relay/STUN — `US-004 AC3`, `US-038 AC5`).
   - Trên **macOS**: phân giải symlink `/etc/hosts` ra đường dẫn thật `/private/etc/hosts`, ghi nguyên tử giữ nguyên symlink và quyền `root:wheel 0644`, sau đó gọi `/usr/bin/dscacheutil -flushcache` và `/usr/bin/killall -HUP mDNSResponder` (không chạm `scutil --dns`).
   - Trên **Windows**: ghi giữ nguyên ACL đọc cho `Users` và `Dnscache` (kèm retry backoff ≤ 2 s nếu file đang bị khóa tạm), sau đó xả cache DNS.
   - Trên **Linux**: không chạm `/etc/resolv.conf`; nếu `/etc/hosts` là bind-mount trong container (`EBUSY`/`EXDEV` khi `rename`) thì tự động chuyển sang ghi đè tại chỗ có khóa tệp (`US-038 AC2(d)`).
4. **Theo dõi Sự kiện Mạng & Sleep/Wake (`PLAT-05`, `US-035`, `US-036`)**:
   - **macOS**: lắng nghe BSD routing socket `PF_ROUTE` (`RTM_IFINFO`, `RTM_NEWADDR`, `RTM_DELADDR`, `RTM_CHANGE`) kết hợp bộ dò nhảy đồng hồ hệ thống (so sánh `std::time::Instant` với `SystemTime` mỗi 2 s để bắt sự kiện thức dậy sau sleep hoặc đồng bộ NTP — `US-035 AC3/AC6`).
   - **Windows**: đăng ký `NotifyIpInterfaceChange` + nhận `ServiceControl::PowerEvent` từ Windows Service Control Manager + bộ dò nhảy đồng hồ (`US-036`).
   - **Linux**: lắng nghe socket Netlink route/addr/link (`US-035 AC8`).

### Consequences
- **(+) Tích cực**: Đảm bảo tính chất tự chữa lành sau crash, không đụng chạm VPN khác trên macOS/Windows/Linux, và phục hồi sau đổi mạng/sleep-wake trong P95 ≤ 15 s (`PERF-07`).
- **(−) Chi phí / Giảm thiểu**: Các lệnh hệ thống ngoài (`route`, `pfctl`, `dscacheutil`, `socketfilterfw`, `netsh`, `ipconfig`, `nft`) chỉ được gọi qua `mesh_net::sysexec` với đường dẫn tuyệt đối cố định, không qua shell.

---

<a id="adr-008"></a>
## ADR-008 — Vòng đời TLS (`rustls`): Chế độ IP + SPKI Pinning (Mặc định) · Standalone ACME · Reverse Proxy

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- Quyết định Gate 1 D3 (`SEC-04`, `US-003`, `US-047`): Trong giai đoạn đầu, người dùng **kết nối trực tiếp bằng địa chỉ IP của VPS (chưa có domain)**, nên chế độ **IP + SPKI Pin (`sha256:<hex>`) là luồng vận hành chính thức mặc định ngay từ Milestone 1**.
- Phải cấm tuyệt đối cơ chế tin-lần-đầu ngầm định (TOFU) và không có cờ bỏ qua kiểm tra chứng chỉ trong bản release. Đồng thời phải hỗ trợ xoay khóa server có kế hoạch bằng tập pin (`active` + `next`) và chuyển đổi mượt sang Standalone ACME (không cần cổng 80) hoặc chạy sau Reverse Proxy sẵn có (`trusted_proxies`).

### Options
1. **Phương án A — `rustls` + Custom `SpkiPinVerifier` (`mesh-crypto`) + `rcgen` (sinh cert IP) + `instant-acme` (`TLS-ALPN-01`/`DNS-01`) (CHỌN)**:
   - Kiểm soát hoàn toàn logic đối chiếu mã băm SHA-256 của trường `subjectPublicKeyInfo` (SPKI DER) bất kể chứng chỉ tự ký hay do CA cấp.

### Decision
1. **Chế độ (c) IP + SPKI Pinning — Luồng mặc định hạng nhất (`SEC-04(c)`, `US-003`, `US-047`)**:
   - Khi khởi tạo `mesh-server` lần đầu, nếu chưa có khóa định danh trong bảng `server_identity` (`redb`), server dùng `rcgen` sinh cặp khóa ECDSA P-256 bền vững, trích xuất `subjectPublicKeyInfo` DER và tính `sha256:<hex_lowercase>`.
   - Khi chứng chỉ tự ký sắp hết hạn hoặc khi server đổi địa chỉ IP (`US-074`), `rcgen` phát hành lại chứng chỉ X.509 mới từ **cùng cặp khóa định danh đó** → mã SPKI Pin không đổi, **không một máy client nào phải pin lại** (`US-047 AC3`).
   - Phía client (`mesh-crypto::tlspin::SpkiPinVerifier` cài đặt trait `rustls::client::danger::ServerCertVerifier`):
     - Trích xuất SPKI DER từ chứng chỉ lá của server, băm SHA-256 và so sánh constant-time với `PinSet` (`active_pin` và tùy chọn `next_pin` khi đang xoay khóa theo `US-047 AC5`).
     - Nếu `PinSet` rỗng mà cấu hình ở chế độ Pin → **từ chối ngay lập tức (fail-closed, cấm TOFU)** trước khi gửi bất kỳ dữ liệu nào (`US-003 AC6`).
     - Nếu không khớp pin (kể cả khi kẻ MITM trình chứng chỉ do CA công cộng hợp lệ cấp cho đúng IP đó) → từ chối kết nối, ghi log `WARN` (`event = "pin_mismatch"` kèm pin nhận được và pin kỳ vọng), không gửi secret, và chuyển sang thử lại theo backoff trần 5 phút (`US-003 AC7`, `US-034 AC4`).
2. **Chế độ (a) Standalone có Domain (`instant-acme`)**:
   - Nếu cổng TCP cấu hình = `443`, tự động xin và gia hạn chứng chỉ qua `TLS-ALPN-01` (nhận diện ALPN `acme-tls/1` ngay trên bộ lắng nghe `tokio-rustls` mà không cần mở cổng 80).
   - Nếu cổng TCP cấu hình ≠ `443`, bắt buộc dùng `DNS-01` hoặc từ chối cấu hình kèm hướng dẫn rõ ràng vì CA chỉ kiểm tra `TLS-ALPN-01` trên cổng 443 (`US-047 AC7`).
   - Nạp nóng chứng chỉ mới qua `ArcSwap` / `RwLock<Arc<CertifiedKey>>` trong `Acceptor` mà không làm rớt kết nối đang mở.
3. **Chế độ (b) Sau Reverse Proxy sẵn có (`SEC-05`, `US-042 AC6`)**:
   - `mesh-server` lắng nghe trên địa chỉ cục bộ; danh sách `trusted_proxies` mặc định **rỗng/tắt**. Chỉ khi kết nối đến từ IP nằm trong `trusted_proxies` đã được người dùng bật tường minh thì server mới đọc IP client thật từ header chuyển tiếp để áp rate-limit (không bao giờ khóa nhầm `127.0.0.1`).

### Consequences
- **(+) Tích cực**: Vận hành an toàn tuyệt đối chỉ với IP VPS; tái phát hành chứng chỉ không làm phiền client; chống MITM kể cả khi CA bị lạm dụng.
- **(−) Chi phí / Giảm thiểu**: Khóa định danh server trong `redb` là tài sản tối quan trọng — đã được đưa vào bản sao lưu tự động nguyên tử tại `ADR-005` (`US-045`).

---

<a id="adr-009"></a>
## ADR-009 — Cổng & Địa chỉ Cấu hình được (`GNFR-11`) và Di chuyển Cấu hình Không Mất Danh tính (`SEC-15`)

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- Quyết định Gate 1 D4 (`GNFR-11`, `SEC-04`, `SEC-06`, `SEC-15`, `US-074`): Cổng TCP (Control + Relay, mặc định `443`) và cổng UDP (STUN, mặc định `3478`) phải đổi được sang cổng bất kỳ lúc cài đặt hoặc về sau. Khi đổi cổng, đổi IP VPS, chuyển từ IP+Pin sang Domain ACME hoặc xoay khóa server, các máy client **không được mất danh tính node** (giữ nguyên node key, Overlay IP, tên; không cần nhập lại pre-auth key) và đường hầm P2P đang chạy không bị đứt.

### Decision
1. **Không mã hóa cứng cổng (`GNFR-11`)**: Giá trị mặc định `DEFAULT_CONTROL_TCP_PORT = 443` và `DEFAULT_STUN_UDP_PORT = 3478` chỉ được khai báo duy nhất trong `crates/mesh-core::defaults`. Script `scripts/check.{ps1,sh}` quét tĩnh cấm dùng hằng số cổng cứng ở các crate khác.
2. **Kiểm tra xung đột cổng trước khi bind (`SEC-06(1)`, `US-046 AC5`)**: Khi cài đặt hoặc khi nhận lệnh đổi cổng, `mesh-server` thử bind cổng mới trước; nếu cổng đang bị tiến trình khác chiếm (vd. Nginx đang giữ `443`), thao tác dừng ngay với thông báo rõ ràng, giữ nguyên cổng cũ và gợi ý cổng thay thế (vd. `8443`) hoặc chế độ Reverse Proxy.
3. **Phân phối `relay_map` qua Netmap & Lắng nghe Song song (`SEC-15`, `US-009 AC6`, `US-074`)**:
   - Cấu hình bootstrap của agent chỉ lưu tối thiểu `control_endpoint` và `PinSet`/chế độ xác thực (`US-004 AC7`). Địa chỉ/cổng của Relay và STUN được phân phối động trong trường `relay_map` của `NetmapSnapshot`.
   - Khi admin chạy lệnh đổi cổng/địa chỉ/xoay khóa qua kênh Admin cục bộ (`SEC-14`), `mesh-server` mở **bộ lắng nghe `ListenerSet` song song trên cả cổng cũ và cổng mới** trong khoảng thời gian chuyển tiếp cấu hình được (`transition_window`), tăng `netmap_version` và đẩy cấu hình mới qua luồng Control đã xác thực.
   - Các agent đang online kiểm chứng bản cập nhật đến từ kênh đã xác thực bằng pin/CA hiện hành (`SEC-15(e)`), ghi bền cấu hình mới vào đĩa và chuyển kết nối sang cổng mới mà không đụng tới `MagicSocket` P2P đang chạy (`0%` mất gói P2P).
   - Với máy tắt suốt giai đoạn chuyển tiếp, quản trị viên cục bộ của máy đó chạy `mesh set --server <IP:port> --server-pin sha256:…` qua kênh IPC phân quyền (`US-074 AC5`) để nối lại với đúng danh tính cũ.

### Consequences
- **(+) Tích cực**: Cho phép người dùng linh hoạt đổi cổng bất kỳ lúc nào trên VPS cá nhân dùng chung mà không phải đăng ký lại thiết bị.

---

<a id="adr-010"></a>
## ADR-010 — Bảo vệ Bí mật trong RAM (`ZeroizeOnDrop` + Redacted `Secret<T>`) & Quan sát Có cấu trúc (`tracing`)

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- `SEC-01` & `GNFR-02`: Tuyệt đối không được để lọt khóa riêng (Node private key, Disco private key, Server identity private key), Pre-Auth Key rõ hay token vào log, thông điệp lỗi, kết quả `mesh status`, DB hay bundle chẩn đoán `bugreport` (kể cả khi bật mức log `debug` — `US-043 AC4`).
- `OPS-01`: Log phải có cấu trúc (JSON) với đủ các trường bắt buộc và có xoay vòng dung lượng (`US-043 AC3`).

### Decision
1. **Kiểu bọc Bí mật Tự xóa Bộ nhớ (`mesh_crypto::Secret<T>`)**:
   - Mọi khóa bí mật bắt buộc phải bọc trong kiểu `Secret<T>` cài đặt `zeroize::Zeroize` và `#[derive(ZeroizeOnDrop)]`.
   - `impl Debug`, `impl Display`, `impl serde::Serialize` cho `Secret<T>` **luôn luôn xuất chuỗi cố định `"[REDACTED]"`**.
   - Không cài đặt `serde::Deserialize` trực tiếp cho khóa riêng trên các bản tin mạng (ngăn chặn việc vô tình thêm trường private key vào DTO giao thức — `SEC-01(a)`).
   - Phương thức truy cập giá trị thật `.expose_secret()` chỉ được phép gọi tại: (a) `mesh-crypto` (thực hiện phép toán DH/ký), (b) `mesh-datapath` (khởi tạo `defguard_boringtun::noise::Tunn`), (c) `mesh-net::keystore` (ghi tệp khóa nguyên tử `0600`), và (d) `mesh` CLI đúng 1 lần khi tạo `preauthkey create`. Script `scripts/check.{ps1,sh}` quét tĩnh mọi lệnh gọi `.expose_secret()` ngoài danh sách này.
2. **Structured Logging (`tracing` + `tracing-subscriber` + `tracing-appender`)**:
   - Định dạng JSON thống nhất với các trường bắt buộc: `ts` (UTC RFC 3339), `level`, `component` (`control`, `relay`, `stun`, `disco`, `wg`, `dns`, `route`, `store`, `admin`, `tls`, `lifecycle`), `event` (`snake_case`), kèm `request_id`/`conn_id`, `node_id`, `peer_id`.
   - Xoay vòng tệp log có trần tổng dung lượng (mặc định ≤ 100 MB/service — `US-043 AC3`).
3. **Kiểm thử Canary Tự động (`test_no_secrets_in_outputs`)**:
   - Bộ test tích hợp tạo khóa và pre-auth key có tiền tố nhận diện Canary, chạy qua toàn bộ luồng đăng ký, relay, lỗi xác thực, `status --json` và `bugreport`, rồi quét toàn bộ đầu ra để khẳng định **0 byte bí mật bị rò rỉ**.

### Consequences
- **(+) Tích cực**: Ngăn chặn rò rỉ khóa ngay ở tầng hệ thống kiểu của Rust và tự động xóa sạch khóa trong RAM khi tiến trình đóng phiên.

---

<a id="adr-011"></a>
## ADR-011 — Đóng gói, Kiểm chứng SHA-256 `wintun.dll` & Toàn vẹn Bản phát hành

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-12

### Context
- `C5` & `PLAT-01` (`US-015`): Trên Windows, `wintun.dll` phải được phân phối nguyên vẹn theo đúng *Prebuilt Binaries License*, và `meshd.exe` chạy dưới quyền `LocalSystem` không được phép nạp nhầm DLL giả mạo (DLL hijacking).
- `PLAT-06(1)` (`US-073`): Trên macOS Apple Silicon (`aarch64-apple-darwin`), kernel bắt buộc binary Mach-O phải có chữ ký mã (ad-hoc code signature là đủ khi không qua trình duyệt); luồng cài đặt phải kiểm tra SHA-256 và đặt binary vào đường dẫn chỉ `root` ghi được (`/usr/local/libexec/mesh/`), cấm hướng dẫn tắt Gatekeeper (`spctl --master-disable`).

### Decision
1. **Ma trận 4 Đích Phát hành**:
   - `x86_64-unknown-linux-musl` (hoặc `-gnu`): `mesh-server`, `meshd`, `mesh`.
   - `aarch64-apple-darwin`: `meshd`, `mesh` (ký ad-hoc Mach-O bằng `codesign -s -` trên runner macOS hoặc `rcodesign sign` khi cross-compile).
   - `x86_64-apple-darwin`: `meshd`, `mesh`.
   - `x86_64-pc-windows-msvc` (hoặc `-gnu`): `meshd.exe`, `mesh.exe` đi kèm `wintun.dll` nguyên bản và tệp giấy phép Wintun.
2. **Kiểm chứng `wintun.dll` trước khi nạp trên Windows (`US-015 AC3`, `mesh-sys`)**:
   - Trước khi gọi `LoadLibraryExW`, `mesh-sys` mở tệp `wintun.dll` tại đúng thư mục chứa `meshd.exe` (`C:\Program Files\Mesh\wintun.dll` — chỉ `SYSTEM` và `Administrators` có quyền ghi), tính mã băm SHA-256 bằng `sha2` và đối chiếu khớp với hằng số SHA-256 của bản `wintun.dll` chính thức đã ghim; sau đó nạp với cờ `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` (cấm tìm kiếm trong `PATH` hay thư mục hiện hành).
3. **Bảo vệ Đường dẫn Daemon trên macOS (`US-073 AC2/AC5`)**:
   - Lúc khởi động, `meshd` trên macOS tự kiểm tra (`stat`) chính tệp thực thi của mình, tệp `/Library/LaunchDaemons/internal.mesh.meshd.plist` và toàn bộ các thư mục cha phải thuộc sở hữu `uid == 0` (`root`) và không có bit `group-writable` hay `world-writable` (`mode & 0o022 == 0`); nếu phát hiện nằm trong thư mục user ghi được (như `/opt/homebrew` hay `~/…`), daemon **từ chối chạy ngay lập tức** để chặn leo thang đặc quyền cục bộ.
4. **Toàn vẹn Bản phát hành**: Mỗi bản build xuất kèm `SHA256SUMS` và chữ ký tách rời `SHA256SUMS.sig` (ký bằng `ssh-keygen -Y sign` với khóa Ed25519 của chủ dự án); script cài đặt kiểm tra khớp chữ ký và SHA-256 trước khi cài.

### Consequences
- **(+) Tích cực**: Tuân thủ chặt chẽ giấy phép Wintun, chống DLL hijacking trên Windows, chống leo thang đặc quyền qua LaunchDaemon trên macOS, và chạy mượt trên Apple Silicon mà không tốn $99/năm.
