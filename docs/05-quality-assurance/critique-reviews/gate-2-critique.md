# Gate 2 Independent Red-Team Critique — Rust 1.94.1 Tech Stack, Coding Standards, Architecture, DB/API Contracts & Sprint Plan

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Cổng kiểm định** | **Gate 2** — Tech Stack, Coding Standards, System Architecture, DB/API Contracts & Sprint Plan (Round 1) |
| **Người phản biện** | `agile-critic` (Principal Reviewer & Independent Red-Team Critic) |
| **Ngày kiểm định** | 2026-11-12 |
| **Thành phần AI/SLM** | **KHÔNG CÓ** (Dự án thuần hạ tầng mạng & hệ thống — không áp dụng khung kiểm định AI/SLM) |
| **Đầu vào đối chiếu (Gate 1 v1.2)** | `production-readiness-requirements.md`, `project-charter.md`, `product-backlog.md` (74 stories: 51 `Must` / 234 SP, 11 `Should` / 35 SP, 12 Phase 2+) |
| **Đầu ra đối chiếu (Gate 2)** | `tech-stack-decision.md`, `architecture-decision-record.md` (`ADR-001..011`), `coding-standards.md`, `.agents/rules/coding-standards.md`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.editorconfig`, `.gitignore`, `.gitattributes`, `scripts/{bootstrap-toolchain.ps1,check.ps1,check.sh}`, `system-architecture.md`, `database-design.md`, `api-design.md`, `sprint-backlog.md` |
| **Phán quyết** | **`[REVISION REQUIRED]`** — **4 `🔴 Blocker`**, **4 `🟠 High Risk`**, **3 `🟡 Improvement`** |

---

## 1. Tổng Quan Đánh Giá & Các Điểm Sáng Đã Xác Minh Thực Nghiệm

Đội ngũ `agile-tech-lead`, `agile-architect` và `agile-scrum-master` đã chuyển đổi toàn diện thiết kế sang **Rust `1.94.1` (`edition = "2024"`)** với chất lượng kỹ thuật rất cao. Trước khi đi vào danh sách lỗi cần sửa, Red-Team xác nhận các bất biến nền tảng sau **đã đạt 100%**:

1. **Sạch tàn dư thiết kế Go**: Quét toàn bộ tài liệu Gate 2 xác nhận **0 tàn dư Go** trong kiến trúc, DB, API, chuẩn code và Sprint Plan (từ khóa Go chỉ xuất hiện đúng chỗ tại bảng so sánh ngôn ngữ ở `tech-stack-decision.md` §1 và lịch sử quyết định tại `ADR-001`).
2. **Chuẩn hóa Rule tự động cho Subagents**: `.agents/rules/coding-standards.md` mở đầu chính xác bằng frontmatter `---\ntrigger: always_on\n---`, dung lượng **9,713 bytes (`< 10 KB`)**, mã hóa UTF-8 không BOM, dòng kết thúc LF. Chạy thực nghiệm `powershell -ExecutionPolicy Bypass -File scripts/check.ps1` trên máy host pass bước kiểm tĩnh với `rustc 1.94.1 (e408947bf 2026-03-25)`.
3. **Kiến trúc Siêu gọn nhẹ & Cô lập `unsafe`**: Thiết kế 1 Cargo Workspace (3 binaries + 7 library crates), dùng `defguard_boringtun::noise::Tunn` (BSD-3, sans-I/O, tránh hoàn toàn `MPL-2.0` của `gotatun` và `AGPLv3` của NetBird) ghép kênh với STUN RFC 5389 + Authenticated Disco (`b"MESHDS"`) trên **1 `tokio::net::UdpSocket` (`MagicSocket`) duy nhất**, tái sử dụng buffer tĩnh `[u8; 2048]` và giới hạn `worker_threads(2)` + stack `512 KiB` hoàn toàn khả thi để đạt ngưỡng ~4–10 MB RAM nền trên client và ~8–18 MB RAM trên VPS. Toàn bộ `unsafe` bị khóa chặt trong `crates/mesh-sys`.
4. **Tính toàn vẹn `redb` & Chống Head-of-Line Blocking**: `redb 2.4` thuần Rust (0 C-SQLite) đảm bảo ACID MVCC, kiểm tra idempotency + cấp phát IP/tên nguyên tử trong **1 `WriteTransaction`**, tách bảng `LAST_SEEN` không làm nổ `netmap_version` (`HR-03`), sao lưu nóng nguyên tử kèm `SERVER_IDENTITY` (`US-045`). Blind Relay (`GET /v1/relay`) áp dụng đúng `mpsc::channel(256)` mỗi đích + `try_send()` drop-tail không chặn (`US-025 AC6`).
5. **Khớp toán học Backlog 100%**: `sprint-backlog.md` bao phủ chính xác **51/51 User Stories `Must` (234 SP)** chia đúng 2 đợt bàn giao đã chốt tại Gate 1 (**Sprint 1 = 38 `Must` / 174 SP**, **Sprint 2 = 13 `Must` / 60 SP**), giữ nguyên 11 `Should` (35 SP) và 12 stories Phase 2+ (`US-061..072`). Chế độ kết nối mặc định **IP VPS + SPKI Pin (`sha256:...`, cấm TOFU)** và **đổi cổng TCP/UDP tùy ý (`SEC-15` / `US-074`)** đã xuyên suốt các tài liệu.

Tuy nhiên, kiểm tra thực nghiệm trên máy Windows host và đối chiếu sâu ở mức syscall hệ điều hành, luồng mật mã TLS/Reverse Proxy và kịch bản lỗi biên đã phát hiện **4 lỗi `🔴 Blocker`** và **4 rủi ro `🟠 High Risk`** chắc chắn sẽ gây gãy build ngay ở `WP-S1-00`, lỗi xác thực 100% ở một số chế độ triển khai, khóa nhầm quyền Admin IPC trên macOS/Linux, hoặc gây routing loop trên Linux VPS. Các mục này có thể khắc phục dứt điểm ngay trong tài liệu và script trước khi trình người dùng tại Gate 2.

---

## 2. Danh Sách Phát Hiện Mức `🔴 Blocker` (Bắt Buộc Khắc Phục Trước Gate 2)

### `BLK-G2-01` — Toolchain & Cross-Compile trên máy Windows hiện tại sập ngay từ bước đầu (`linker 'link.exe' not found`) + Lỗ hổng Supply-Chain Fail-Open trong `scripts/bootstrap-toolchain.ps1`
- **Tác giả chịu trách nhiệm**: `agile-tech-lead`
- **Tài liệu / File liên quan**: `scripts/bootstrap-toolchain.ps1:28,69-74,99-105`, `scripts/check.ps1:118,124`, `rust-toolchain.toml:3`, `docs/03-system-design/tech-stack-decision.md:97-99,118`, `docs/03-system-design/architecture-decision-record.md:363-402` (`ADR-011`)
- **Phân tích bằng chứng thực nghiệm**:
  Kiểm tra trực tiếp môi trường máy host Windows (`rustc -vV`, `Get-Command`) cho thấy: host đang cài `stable-x86_64-pc-windows-msvc` (`rustc 1.94.1`), nhưng **KHÔNG có** `link.exe`, `cl.exe`, `ml64.exe`, `gcc.exe`, `clang.exe`, `zig.exe`, `cargo-deny.exe` hay `cargo-zigbuild.exe`. Đối chiếu với bộ script hiện tại có **4 lỗi chặn đứng `WP-S1-00`**:
  1. **`cargo install` biên dịch từ mã nguồn cần `link.exe` (`bootstrap-toolchain.ps1:99-105`)**: Lệnh `cargo install --locked cargo-deny` và `cargo install --locked cargo-zigbuild` biên dịch binary cho host `x86_64-pc-windows-msvc` → sập ngay lập tức với lỗi `error: linker 'link.exe' not found` khi chạy chế độ `-Mode PortableZig`.
  2. **Thiếu trình liên kết & trình biên dịch C/ASM cho Windows target (`scripts/check.ps1:118,124` & `tech-stack-decision.md:97,99`)**: `scripts/check.ps1` chạy `cargo clippy --workspace --all-targets` và `cargo test --workspace` không truyền `--target`, mặc định rơi vào `x86_64-pc-windows-msvc` (vừa thiếu `link.exe`, vừa thiếu `ml64.exe` mà `ring 0.17` `build.rs` bắt buộc trên `-msvc`). Trong khi đó, nếu chuyển sang `x86_64-pc-windows-gnu`, Rust yêu cầu `x86_64-w64-mingw32-gcc` / `dlltool.exe`. Mặc dù `tech-stack-decision.md:97,99` tuyên bố dùng portable `llvm-mingw` / `w64devkit` và `apple-codesign` (`rcodesign`), `bootstrap-toolchain.ps1` **chưa hề tải hay cấu hình `llvm-mingw` và `rcodesign`**.
  3. **Sai mã băm SHA-256 của Zig 0.13.0 VÀ mở cửa hậu Fail-Open (`bootstrap-toolchain.ps1:28,69-74`)**: Giá trị `$ZigExpectedSha256 = "de8d63bb..."` trong script không khớp mã SHA-256 chính thức của `zig-windows-x86_64-0.13.0.zip` (`d859994725ef9402381e557c60bb57497215682e355204d754ee3df75ee3c158`). Nghiêm trọng hơn, khi sai SHA-256, dòng 71 chỉ in `Write-Warning` rồi **vẫn giải nén và chạy `zig.exe`** — vi phạm trực tiếp nguyên tắc fail-closed chống tấn công chuỗi cung ứng của chính `ADR-011` và `PLAT-01`.
  4. **Lệch ghim phiên bản trong `rust-toolchain.toml:3`**: File cấu hình ghi `channel = "stable"`, trái ngược với `tech-stack-decision.md:118` và `system-architecture.md:549` tuyên bố khóa cứng `channel = "1.94.1"`. Trên CI/máy mới, `channel = "stable"` sẽ tự trôi lên phiên bản Rust mới hơn và làm vỡ `clippy -D warnings`.
- **Hệ quả thực tế (Impact)**: Developer ở `WP-S1-00` không thể chạy `bootstrap-toolchain.ps1` lẫn `scripts/check.ps1` trên máy Windows hiện tại; kiểm tra SHA-256 của công cụ biên dịch bị vô hiệu hóa hoàn toàn.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Cập nhật `scripts/bootstrap-toolchain.ps1` (chế độ `PortableZig`): Tải các bản đóng gói dựng sẵn (prebuilt release binaries) cho Windows x64 của **`llvm-mingw`** (cung cấp `x86_64-w64-mingw32-gcc`, `dlltool.exe`, `clang` để build & chạy `cargo test --target x86_64-pc-windows-gnu` và biên dịch C/ASM của `ring` không cần Visual Studio), **`zig`**, **`cargo-deny`**, **`cargo-zigbuild`**, và **`apple-codesign` (`rcodesign`)**; đối chiếu mã SHA-256 thật sự chính xác và **`throw` dừng ngay lập tức (fail-closed)** nếu lệch 1 bit.
  2. Cập nhật `scripts/check.ps1`: Tự động phát hiện nếu máy Windows không có `link.exe` nhưng có `.tools/llvm-mingw/bin` (hoặc `x86_64-w64-mingw32-gcc` trong `PATH`) thì tự động thêm `.tools/...` vào `PATH` của phiên chạy và truyền `--target x86_64-pc-windows-gnu` cho `cargo clippy` và `cargo test`.
  3. Khóa `channel = "1.94.1"` trong `rust-toolchain.toml` (nếu trên máy local `rustup` chỉ cài tên toolchain `stable` đang trỏ tới `1.94.1`, `bootstrap-toolchain.ps1` cài thêm `rustup toolchain install 1.94.1 --profile minimal` hoặc kiểm tra `rustc --version` khớp `1.94.1`).

---

### `BLK-G2-02` — Hợp đồng Xác thực Control & Blind Relay (`ADR-003`, `api-design.md` §1.2, §1.4, §2) bị gãy ở chế độ Reverse Proxy và mâu thuẫn vòng đời `session_id` trên nhiều kết nối TCP
- **Tác giả chịu trách nhiệm**: `agile-architect` (phối hợp `agile-tech-lead` đồng bộ `ADR-003`)
- **Tài liệu / File liên quan**: `docs/03-system-design/api-design.md:36-45,73-84,151-160,192-215,274-282`, `docs/03-system-design/architecture-decision-record.md:125-138` (`ADR-003`), `docs/03-system-design/system-architecture.md:274-305`
- **Phân tích lỗi**:
  1. **100% thất bại xác thực khi chạy sau Reverse Proxy (`US-024 AC1(b)`, `US-051 AC1`, `SEC-04(b)`)**:
     Theo `api-design.md:77-80` và `ADR-003:127`, `meshd` trích xuất 32 byte `rustls::Connection::export_keying_material("EXPORTER-mesh-control-v1")` đưa vào `ProofPayload.tls_exporter_binding`; còn khi chạy sau Reverse Proxy thì Server chấp nhận `"reverse_proxy_mode"`. **Lỗ hổng tư duy**: Khi Nginx/Caddy đứng trước `mesh-server` để terminate TLS ở cổng `:443`, phía Client `meshd` vẫn nối TLS 1.3 thật tới Nginx `:443` và **hoàn toàn không biết phía sau Nginx là Reverse Proxy hay Standalone**! Do đó `meshd` luôn tính 32 byte exporter của phiên TLS `Client ↔ Nginx`. Ngược lại, `mesh-server` ở `127.0.0.1:8443` chỉ nhận HTTP thuần từ Nginx (không hề có khóa phiên TLS `Client ↔ Nginx`, cũng không nhận chuỗi `"reverse_proxy_mode"` từ Client). Kết quả: đối chiếu `tls_exporter_binding` sẽ **luôn luôn trượt 100%** ở chế độ Reverse Proxy!
  2. **Mâu thuẫn vòng đời `session_id` "dùng 1 lần, TTL 30s" với kiến trúc đa kết nối TCP/WebSocket + lỗ hổng Replay**:
     `api-design.md:43` và `ADR-003:127` quy định `session_id` / `challenge_nonce` có **TTL 30 giây và dùng 1 lần (single-use)**. Thế nhưng `api-design.md:155-159,195,207,279` lại yêu cầu node đã đăng ký gắn bộ header `X-Mesh-Session-Id` + `X-Mesh-Box-Nonce` + `X-Mesh-Auth-Proof` cho **4 lời gọi trên ít nhất 3 kết nối TCP/TLS riêng biệt**: (1) `GET /v1/netmap/stream` (WebSocket lâu dài #1), (2) `GET /v1/relay` (WebSocket lâu dài #2), và (3) `POST /v1/endpoints` + `POST /v1/disco/call-me-maybe` (HTTP REST #3, phát sinh sau hàng phút/hàng giờ khi đổi mạng!).
     - Mỗi kết nối TCP có `tls_exporter_binding` **khác nhau**!
     - Do `WP-S1-01` (Server) và `WP-S1-02`/`WP-S1-05` (Client) do các Developer khác nhau code dựa trên `mesh-proto` (`WP-S1-00`), Server xóa `session_id` ngay sau lần dùng đầu sẽ khiến `/v1/relay` và `/v1/endpoints` bị từ chối `401 authentication failed`. Ngược lại, nếu cho dùng lại `session_id` ở chế độ Reverse Proxy (nơi không có `tls_exporter_binding`) mà `ProofPayload` không ràng buộc `(method, path, body_sha256)`, kẻ nghe lén giữa Proxy và App hoặc mã độc nội bộ có thể phát lại header xác thực sang endpoint khác.
- **Hệ quả thực tế (Impact)**: Chế độ Reverse Proxy (`SEC-04(b)`, `US-051`) hỏng hoàn toàn; tích hợp giữa `WP-S1-01`, `WP-S1-02` và `WP-S1-05` ở Wave 1.2 chắc chắn đụng lỗi `401` khi mở đồng thời Control WS + Relay WS + gửi Endpoint updates.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  Khóa cứng một State Machine xác thực duy nhất, rõ ràng từng byte trong `api-design.md` §1.2–§1.4 & `ADR-003`:
  1. **Chuẩn hóa `Challenge` dùng 1 lần cho mọi bắt tay**: Đổi tên rõ thành `challenge_id` (TTL 30s, single-use, lưu trong bộ nhớ giới hạn `max = 4096` mục chống cạn RAM). Trước mỗi lần gọi `POST /v1/nodes/register`, nâng cấp `GET /v1/netmap/stream`, nâng cấp `GET /v1/relay`, hoặc gọi REST (`POST /v1/endpoints`, `POST /v1/disco/call-me-maybe`), Client gọi `POST /v1/auth/challenge` ngay trên **cùng kết nối HTTP/1.1 Keep-Alive (cùng phiên TLS)** rồi gửi request đích kèm `X-Mesh-Challenge-Id`, `X-Mesh-Node-Pubkey`, `X-Mesh-Box-Nonce`, `X-Mesh-Auth-Proof`. *(Tùy chọn tối ưu hơn cho REST: cho phép gửi `EndpointUpdate` và `CallMeMaybe` như các frame client→server ngay bên trong WebSocket `/v1/netmap/stream` đã xác thực, vừa bớt RTT xin challenge mỗi lần roaming vừa dùng chung 1 kết nối TCP!)*
  2. **Ràng buộc ngữ cảnh request vào `ProofPayload`**: Bổ sung `method: String`, `path: String`, `body_sha256: [u8; 32]` (với `GET` WebSocket là SHA-256 của chuỗi rỗng) vào `ProofPayload` trước khi đóng hộp `SalsaBox` với `server_control_pubkey`.
  3. **Xử lý `tls_exporter_binding` nhất quán giữa Standalone và Reverse Proxy**: Client **luôn luôn** trích 32 byte `tls_exporter_binding` từ phiên `rustls` của mình đặt vào `ProofPayload`. Phía `mesh-server`:
     - Khi `tls_mode == Standalone | Acme`: trích 32 byte exporter từ phiên TLS của kết nối TCP hiện tại và so sánh `ConstantTimeEq` với `proof.tls_exporter_binding` (chống MITM chuyển tiếp challenge).
     - Khi `tls_mode == ReverseProxy` (và peer IP nằm trong `trusted_proxies`): `mesh-server` bỏ qua bước so sánh `tls_exporter_binding`, dựa vào tính dùng-1-lần của `challenge_id` + chữ ký/mã hóa `SalsaBox(client_priv, server_control_pub)` trên `(challenge_nonce, timestamp_ms, method, path, body_sha256)`.

---

### `BLK-G2-03` — Kiểm tra đặc quyền Local IPC khóa nhầm Admin thật trên cả macOS (`LOCAL_PEERCRED`) lẫn Linux (`SO_PEERCRED`), đồng thời chặn user thường chạy `mesh status` trên macOS
- **Tác giả chịu trách nhiệm**: `agile-architect` & `agile-tech-lead`
- **Tài liệu / File liên quan**: `docs/03-system-design/architecture-decision-record.md:240-256` (`ADR-006`), `docs/03-system-design/api-design.md:369-375,426-435`, `docs/03-system-design/database-design.md:386-398`
- **Phân tích lỗi ở tầng Kernel OS**:
  1. **macOS từ chối 100% tài khoản Admin không gõ `sudo` (`US-073 AC3`)**:
     Trên macOS, mọi tài khoản Administrator có **Primary GID = `20` (`staff`)**; nhóm **`80` (`admin`) là Supplementary Group (nhóm phụ)**. `ADR-006:244` chỉ định dùng `tokio::net::UnixStream::peer_cred()`, hàm này trên macOS chỉ trả về `(uid, primary_gid)` (`cred.gid() == 20`) và vứt bỏ mảng `xucred.cr_groups`! Do đó biểu thức `uid == 0 || gid == 80` sẽ **luôn trả về `false`** cho mọi user Admin trên macOS nếu không chạy `sudo`, làm gãy `US-073 AC3`.
  2. **macOS chặn user thường chạy lệnh chỉ-đọc `mesh status` / `mesh ping` (`US-039 AC5`)**:
     `database-design.md:392` đặt quyền `/var/run/mesh/meshd.sock` là **`0660 root:admin`**, nhưng `api-design.md:430` và `US-039 AC5` yêu cầu user thường không đặc quyền phải gọi được các endpoint chỉ-đọc (`/v1/status`, `/v1/peers`, `/v1/ping`). Với mode `0660 root:admin`, nhân XNU sẽ chặn lời gọi `connect()` của user thường bằng lỗi `EACCES` ngay tại tầng VFS trước khi `meshd` kịp phân biệt lệnh đọc hay lệnh ghi!
  3. **Linux VPS từ chối 100% thành viên nhóm `mesh-admin` (`SEC-14 AC(c)`, `US-012 AC4`)**:
     Trên Ubuntu Linux, quản trị viên SSH được thêm vào nhóm quản trị qua `usermod -aG mesh-admin ubuntu` vẫn có Primary GID là `1000` (`ubuntu`), còn `mesh-admin` nằm trong danh sách nhóm phụ. Kernel cho phép `connect()` qua VFS `0660 mesh:mesh-admin`, nhưng `SO_PEERCRED` (`struct ucred`) **chỉ trả về Primary/Effective GID (`1000`)**, không chứa nhóm phụ! Logic tại `ADR-006:241` và `api-design.md:372` (`uid == 0 || uid == mesh_uid || gid == mesh_admin_gid`) sẽ trả `403 Forbidden` cho toàn bộ user thuộc nhóm `mesh-admin`!
- **Hệ quả thực tế (Impact)**: Admin trên cả macOS lẫn Ubuntu VPS bị khóa khỏi CLI quản trị dù đã cấu hình đúng nhóm hệ thống; user thường trên macOS không xem được `mesh status`.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  1. **Tách bạch 2 socket theo mức đặc quyền đồng nhất trên cả 3 OS** (giống hệt cách đã thiết kế rất tốt với 2 Named Pipe `meshd-admin` và `meshd-ro` trên Windows tại `api-design.md:431`):
     - Trên Client (`meshd` macOS/Linux): Mở `/var/run/mesh/meshd-admin.sock` (`0660 root:admin` trên macOS, `0660 root:root` trên Linux) gắn router mutating + read, VÀ `/var/run/mesh/meshd-ro.sock` (`0666`) **chỉ gắn router read-only** (`/v1/status`, `/v1/peers`, `/v1/netcheck`, `/v1/ping`), giới hạn `DefaultBodyLimit::max(4096)` và ẩn hoàn toàn khóa/token nhạy cảm.
  2. **Kiểm tra Supplementary Groups chuẩn xác trong `crates/mesh-sys`**:
     - **macOS (`mesh-sys::ipc_macos`)**: Gọi `libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERCRED, ...)` đọc đầy đủ `libc::xucred` và kiểm tra `uid == 0 || xucred.cr_groups[..cr_ngroups].contains(&80)` (kèm nhánh dự phòng `getpwuid_r` + `getgrouplist` nếu user có `> 16` nhóm làm tràn `XU_NGROUPS`).
     - **Linux (`mesh-sys::ipc_linux`)**: Đặt thư mục `/run/mesh` mode `0750 mesh:mesh-admin` + `/run/mesh/admin.sock` mode `0660 mesh:mesh-admin` (để VFS kernel kiểm tra supplementary groups ngay lúc `connect()`), đồng thời trong `mesh-sys` lấy `ucred.uid` từ `SO_PEERCRED` rồi tra danh sách nhóm của `ucred.uid` bằng `getpwuid_r` + `getgrouplist` (không đọc `/proc/<pid>/status` đơn lẻ để tránh TOCTOU PID reuse), chấp nhận khi `uid == 0 || uid == mesh_uid || groups.contains(&mesh_admin_gid)`.

---

### `BLK-G2-04` — Bẫy Default Feature `aws-lc-rs`, Xung đột Giấy phép `webpki-roots` với `deny.toml`, và Thiếu Crate X.509/WebPKI để hiện thực hóa `SpkiPinVerifier` & Domain Mode
- **Tác giả chịu trách nhiệm**: `agile-tech-lead` (phối hợp `agile-architect` cập nhật `mesh-crypto` / `system-architecture.md` §3.1)
- **Tài liệu / File liên quan**: `docs/03-system-design/tech-stack-decision.md:221-258`, `deny.toml:25-38,59-60`, `.agents/rules/coding-standards.md:15`, `docs/03-system-design/system-architecture.md:254-265`
- **Phân tích lỗi**:
  1. **`tokio-rustls` và `instant-acme` tự động kéo `aws-lc-rs` (bị cấm trong `deny.toml:59`)**:
     Trong hệ sinh thái `rustls 0.23+`, cả `tokio-rustls 0.26` lẫn `instant-acme 0.7/0.8` đều bật **`aws-lc-rs` làm default feature** (kéo theo C/C++/CMake/NASM và bị chặn cứng bởi `deny.toml:59-60`). Trong `tech-stack-decision.md:227,231`, chỉ có `rustls` được ghi chú tắt `aws-lc-rs`, còn `tokio-rustls`, `instant-acme` và `rcgen` chưa bắt buộc `default-features = false, features = ["ring", ...]`.
  2. **Xung đột giấy phép `webpki-roots` với `deny.toml:25-38`**:
     Khi bật TLS cho `reqwest` (`US-049` HTTPS Webhook) hoặc `instant-acme` (`hyper-rustls` gọi Let's Encrypt), cây phụ thuộc mặc định kéo `webpki-roots`: bản `0.26.x` mang giấy phép **`MPL-2.0`** (bị cấm tại `deny.toml:6`), còn bản `1.0.x` mang giấy phép **`CDLA-Permissive-2.0`** (chưa có trong `deny.toml` `allow` → `cargo deny check licenses` sẽ fail đỏ!).
  3. **Thiếu crate phân tích X.509 DER & kho CA hệ điều hành cho `SpkiPinVerifier` (`US-003 AC5, AC7`, `US-047 AC4`) và Domain CA Mode (`SEC-04(a)`)**:
     Trong `rustls 0.23`, `ServerCertVerifier::verify_server_cert` chỉ nhận `end_entity: &CertificateDer<'_>` dạng mảng byte DER thô. Nó **không tự động tách `subjectPublicKeyInfo` DER** (cho cả chứng chỉ ECDSA lẫn RSA — `US-003 AC7`), cũng **không tự động kiểm tra hạn `NotBefore` / `NotAfter`** (`US-003 AC5` phân biệt lỗi lệch đồng hồ `ClockSkew` và `US-047 AC4` từ chối cert hết hạn)! Ngoài ra, chế độ `SEC-04(a)` (Domain + Public CA) cần `rustls-webpki` + `rustls-native-certs` (MIT/Apache-2.0, đọc kho CA của macOS/Windows/Linux). Hiện tại danh mục Crates Được Phép (`tech-stack-decision.md` §7.1) chưa có `x509-cert` (hoặc `x509-parser`), `rustls-webpki` và `rustls-native-certs` — nếu Developer tự viết bộ đọc ASN.1 DER bằng tay sẽ rất dễ sinh lỗ hổng phân tích chứng chỉ X.509.
- **Hệ quả thực tế (Impact)**: `cargo deny check bans licenses` fail ngay ở `WP-S1-00`; Developer ở `WP-S1-00` / `WP-S1-02` bị kẹt vì không được phép thêm crate ngoài danh mục nhưng thiếu công cụ chuẩn để parse SPKI DER, kiểm tra hạn chứng chỉ X.509 và nạp OS Trust Store.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Bổ sung vào `tech-stack-decision.md` §7.1 và `.agents/rules/coding-standards.md` (giữ file rule `< 10 KB`):
     - `rustls-webpki` (`0.102+`, ISC) & `rustls-native-certs` (`0.8`, MIT/Apache-2.0) cho xác thực CA chuẩn và kết nối ACME/Webhook không dính `MPL-2.0`.
     - `x509-cert` (`0.2`, Apache-2.0/MIT, thuần Rust `RustCrypto`, `forbid(unsafe_code)`) để trích xuất chính xác `spki` DER nguyên bản và kiểm tra `validity` (`NotBefore`/`NotAfter`) trong `mesh-crypto`.
  2. Ghi rõ cấu hình `Cargo.toml` bắt buộc `default-features = false` dùng backend `ring` cho toàn bộ họ TLS: `rustls`, `tokio-rustls`, `instant-acme`, `rcgen`, `reqwest` (`rustls-tls-native-roots-no-provider`); nếu `instant-acme` kéo `webpki-roots 1.0`, thêm `"CDLA-Permissive-2.0"` (giấy phép dữ liệu mở không copyleft, vẫn giữ lệnh cấm `MPL-2.0` cho `<= 0.26`) vào `deny.toml`.
  3. Ghi rõ vào đặc tả `SpkiPinVerifier` (`system-architecture.md` §3.1): bắt buộc (a) parse `Certificate` bằng `x509-cert` để kiểm tra `NotBefore <= now <= NotAfter` (trả lỗi phân loại được `ClockSkew` theo `US-003 AC5` / `US-047 AC4`), (b) băm SHA-256 trên `tbs_certificate.subject_public_key_info` DER so khớp `ConstantTimeEq`, và (c) ủy quyền kiểm tra chữ ký handshake `verify_tls12_signature` / `verify_tls13_signature` cho `rustls::crypto::ring::default_provider()` (tuyệt đối không trả `HandshakeSignatureValid::assertion()` rỗng).

---

## 3. Danh Sách Rủi Ro Mức `🟠 High Risk` (Cần Sửa Ngay Cùng Đợt)

### `HR-G2-01` — Chống Routing Loop trên Linux (`SO_MARK`) thiếu bảng Policy Routing & Danh sách trắng `mesh_net::sysexec` thiếu lệnh cốt lõi trên macOS/Linux/Windows
- **Tác giả chịu trách nhiệm**: `agile-architect` & `agile-tech-lead`
- **Tài liệu / File liên quan**: `docs/03-system-design/system-architecture.md:513`, `docs/03-system-design/database-design.md:443-462`, `docs/03-system-design/coding-standards.md:243-247`
- **Phân tích lỗi**:
  1. **`SO_MARK` đơn lẻ không ngăn được vòng lặp định tuyến trên Linux (`REL-09`, `US-056`, `US-057`)**:
     `system-architecture.md:513` viết rằng đặt `SO_MARK` (`fwmark = 0x5d56`) giúp gói UDP ngoại biên của `meshd` *"đi theo routing table `main` ra NIC vật lý, không bị hút vào `mesh0`"*. Thực tế trên Linux: nếu route `100.115.0.0/16 dev mesh0` được cài ngay trong bảng `main`, gói tin dù có gắn `fwmark = 0x5d56` khi tra bảng `main` **vẫn khớp `100.115.0.0/16` và bị đẩy ngược vào `mesh0`** (gây vòng lặp vô tận nếu IP đích trùng hoặc có route chồng lấn)! Để `fwmark` phát huy tác dụng như WireGuard chuẩn (`wg-quick`), route overlay phải nằm ở bảng riêng (ví dụ `table 51820`) kèm 2 quy tắc policy routing: `ip rule add not fwmark 0x5d56 table 51820` và `ip rule add table main suppress_prefixlength 0`. Đồng thời `ledger.json` (`database-design.md:443-462`) hiện chưa có trường lưu `ip_rules` / `routing_table_id` để tự dọn sau `kill -9` (`US-014 AC7`).
  2. **Danh sách trắng cứng của `mesh_net::sysexec` (`coding-standards.md:245`) bỏ sót công cụ bắt buộc**:
     Danh sách cho phép hiện chỉ liệt kê `/sbin/route`, `/sbin/pfctl`, `/usr/bin/dscacheutil`, `/usr/bin/killall`, `netsh.exe`, `ipconfig.exe`:
     - Trên **macOS**: `/sbin/route` không thể gán địa chỉ IPv4 point-to-point và MTU `1280` cho giao diện `utunN` mới mở — bắt buộc phải gọi `/sbin/ifconfig utunN inet <ip> <peer_ip> netmask 255.255.0.0 mtu 1280 up` (hoặc viết hàng trăm dòng `ioctl` `SIOCAIFADDR` BSD phức tạp dễ lỗi trong `mesh-sys`).
     - Trên **Linux**: thiếu `/usr/sbin/ip` (và `/sbin/ip`) để cấu hình địa chỉ, MTU `1280`, `table 51820` và `ip rule` cho `mesh0` (viết bộ đóng gói nhị phân raw `NETLINK_ROUTE` cho cả addr + link + route + fib_rule trong `mesh-sys` là khối lượng không cần thiết và rủi ro lỗi cao cho MVP).
     - Trên **Windows**: `netsh.exe` và `ipconfig.exe` chưa ghi đường dẫn tuyệt đối `%SystemRoot%\System32\netsh.exe` / `ipconfig.exe` (dễ dính tấn công hijacking đường dẫn thực thi nếu gọi tên trần).
- **Hệ quả thực tế (Impact)**: Vòng lặp định tuyến trên Linux VPS/container lab (`US-056`, `US-057`) hoặc rò rỉ `ip rule` mồ côi sau crash; `WP-S1-03` và `WP-S1-04` bị chặn bởi chính rule `sysexec` khi cấu hình `utunN` trên macOS và `mesh0` trên Linux.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Cập nhật `system-architecture.md` §4.1 và `database-design.md` §6.2c (`ResourceLedger`): Chỉ định rõ trên Linux dùng bảng định tuyến riêng `table 51820` + `ip rule` (`not fwmark 0x5d56 table 51820` & `table main suppress_prefixlength 0`), ghi đầy đủ các rule này vào `ledger.json` trước khi tạo để `reconcile_on_startup()` dọn sạch sau `kill -9` (kèm lưu ý `sysctl net.ipv4.conf.all.src_valid_mark=1` khi cần trong container lab `US-057`).
  2. Cập nhật danh sách trắng đường dẫn tuyệt đối của `mesh_net::sysexec` trong `coding-standards.md` §5.3: thêm `/sbin/ifconfig` (macOS), `/usr/sbin/ip` & `/sbin/ip` (Linux), và buộc ghép từ `GetSystemDirectoryW` / `C:\Windows\System32\{netsh.exe,ipconfig.exe}` trên Windows.

---

### `HR-G2-02` — Lỗi Batching `find ... -exec awk ... {} +` trong `scripts/check.sh` bỏ lọt ngầm >95% file khi kiểm tra UTF-8 BOM và Cổng cứng `443`/`3478` trên CI Linux/macOS
- **Tác giả chịu trách nhiệm**: `agile-tech-lead`
- **Tài liệu / File liên quan**: `scripts/check.sh:29-34,67-70`
- **Phân tích lỗi**:
  1. **Bỏ lọt UTF-8 BOM (`scripts/check.sh:34`)**: Lệnh `find . ... -exec awk 'NR==1 && /^\xEF\xBB\xBF/ { print FILENAME }' {} +` gom hàng chục file vào **1 tiến trình `awk` duy nhất**. Trong `awk`, biến `NR` là tổng số dòng cộng dồn của toàn bộ các file, nên `NR==1` **chỉ kiểm tra dòng đầu tiên của duy nhất file thứ nhất**, bỏ qua hoàn toàn mọi file còn lại! Ngoài ra cú pháp `\xEF\xBB\xBF` không tương thích đồng nhất trên BSD `awk` (macOS) và `mawk` (mặc định trên Ubuntu).
  2. **Bỏ lọt cổng cứng `:443`/`:3478` (`GNFR-11`, `scripts/check.sh:70`)**: Lệnh `find crates ... -exec awk '/#\[cfg\(test\)\]/ { exit } /:(443|3478)([^0-9]|$)/ ...' {} +` gọi lệnh **`exit`** ngay khi gặp `#[cfg(test)]` ở file đầu tiên có unit test. Trong `awk`, `exit` **kết thúc luôn toàn bộ tiến trình `awk`**, khiến tất cả các file `.rs` đứng sau trong lô `find ... {} +` không bao giờ được quét!
- **Hệ quả thực tế (Impact)**: Cổng chất lượng `scripts/check.sh` trên CI Ubuntu và máy macOS báo xanh giả tạo (false negative), cho phép lọt file dính BOM và mã hóa cứng cổng `:443`/`:3478` vào nhánh chính.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  Sửa `scripts/check.sh` dùng biến `FNR` và cờ trạng thái theo từng file chuẩn POSIX `awk` (chạy đúng trên cả `gawk`, `mawk` Ubuntu và BSD `awk` macOS):
  - Với kiểm tra cổng cứng: `FNR==1 { in_test=0 } /#\[cfg\(test\)\]/ { in_test=1 } !in_test && /:(443|3478)([^0-9]|$)/ { print FILENAME ":" FNR ":" $0 }`
  - Với kiểm tra BOM: dùng vòng lặp đọc 3 byte đầu (`LC_ALL=C head -c 3 "$f"`) hoặc `awk` với `BEGIN { bom = sprintf("%c%c%c", 239, 187, 191) } FNR==1 && index($0, bom)==1 { print FILENAME }`.

---

### `HR-G2-03` — Khởi động lại `mesh-server` sau sự cố đầy đĩa (`ENOSPC`) làm "hồi sinh" node đã thu hồi & làm đóng băng `netmap_version` toàn mạng, kèm thiếu nhánh chặn `NodeStatus::Expired` khi `register`
- **Tác giả chịu trách nhiệm**: `agile-architect`
- **Tài liệu / File liên quan**: `docs/03-system-design/database-design.md:119-127,316-336,348-358`
- **Phân tích lỗi**:
  1. **Hồi sinh node bị đánh cắp & tụt lùi `netmap_version` sau `ENOSPC` (`US-013 AC4`, `US-009 AC3`, `US-029`)**:
     Theo `database-design.md:356`, khi đĩa VPS bị đầy (`ENOSPC`), lệnh khẩn cấp `mesh node revoke <stolen-laptop>` vẫn cập nhật `RevokedSet` trong RAM, tăng `netmap_version` trong RAM (ví dụ từ `42` lên `43`) và đẩy `NetmapDelta(v43)` tới 19 node đang online (các node này lưu `version = 43` xuống `netmap-cache.json`). Sau đó Admin dọn ổ đĩa và khởi động lại `mesh-server`: lúc này `control.redb` trên đĩa vẫn đang lưu `stolen-laptop = Active` và `netmap_version = 42`! Hậu quả kép cực kỳ nguy hiểm:
     - (a) Laptop bị đánh cắp **trở lại trạng thái `Active`** và nối lại vào mesh!
     - (b) Khi có thay đổi tiếp theo, `mesh-server` phát bản đồ `version = 43`, bị toàn bộ 19 node từ chối hoặc bỏ qua vì `version <= current_version (43)` theo đúng quy tắc chống phát lại của `US-009 AC3`!
  2. **Bỏ sót trạng thái `NodeStatus::Expired` trong giao dịch `register` (`database-design.md:316-336`)**:
     Tại Bước 1 của giao dịch `register`, thiết kế tra `IDX_NODES_PUBKEY` và rẽ nhánh cho `Active` (idempotent trả 200) và `Revoked` (trả 401), **nhưng quên xử lý `NodeStatus::Expired`**. Nếu một node đã hết hạn dùng lại đúng `node_pubkey` cũ gọi `register` kèm một pre-auth key thông thường (`target_node_id = None`), luồng thực thi sẽ rơi xuống Bước 3B tạo mới `NodeRecord` thứ hai và ghi đè lên `IDX_NODES_PUBKEY` thay vì từ chối (trái với `US-031 AC5` yêu cầu xoay khóa mới + key `--for <node>`). Đồng thời cần ghi chú rõ tại bảng `IDX_NODES_OVERLAY_IP` (`database-design.md:125,334`) rằng khi thu hồi lại IP của node `Revoked` quá 24h thì phải xóa mục trỏ cũ của node `Revoked` trong `IDX_NODES_OVERLAY_IP`.
- **Hệ quả thực tế (Impact)**: Mất an toàn thu hồi khẩn cấp (`SEC-06` / `US-013`) ngay sau khi khắc phục đầy đĩa, đóng băng đồng bộ bản đồ mạng, và hỏng bất biến chỉ mục `IDX_NODES_PUBKEY` khi node hết hạn đăng ký lại.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Khi khởi tạo `/var/lib/mesh`, cấp phát trước (pre-allocate `fallocate` / ghi sẵn đầy khối) một file cố định **`emergency-revocations.bin` (64 KiB, mode `0600`, kèm CRC32)**. Khi `redb` gặp `ENOSPC`, `mesh-server` ghi đè tại chỗ (`pwrite` không xin thêm block đĩa mới) danh sách `NodeId` bị thu hồi vào file này + thử đồng bộ nền lại vào `redb` khi đĩa trống; lúc khởi động `mesh-server` nạp và hợp nhất `emergency-revocations.bin` vào `control.redb` trước khi mở cổng lắng nghe.
  2. Khởi tạo/cập nhật `netmap_version` theo công thức đơn điệu theo thời gian: `next_version = max(current_version + 1, now_unix_ms)` để dù khởi động lại sau `ENOSPC` thì phiên bản mới phát ra luôn lớn hơn mọi bản cache ở client.
  3. Tại Bước 1 của `register` (`database-design.md` §4.1): chặn tường minh `NodeStatus::Expired` trả `401 authentication failed` (`SEC-05`), và khi tái sử dụng IP đã cách ly > 24h ở Bước 3B thì xóa key tương ứng khỏi `IDX_NODES_OVERLAY_IP` (đặt `overlay_ip: Option<OverlayIp>` hoặc xóa entry index của bản ghi `Revoked` cũ).

---

### `HR-G2-04` — Nguy cơ Đầu độc Đường truyền (`Path Poisoning`) khi `DiscoPong` đi qua Blind Relay & Đụng độ Sở hữu File khi chạy song song ở Sprint 1 và Sprint 2
- **Tác giả chịu trách nhiệm**: `agile-architect` (`api-design.md`) & `agile-scrum-master` (`sprint-backlog.md`)
- **Tài liệu / File liên quan**: `docs/03-system-design/api-design.md:209,296,356-365`, `docs/03-system-design/system-architecture.md:494`, `docs/04-sprint-management/sprint-backlog.md:97,144-160,217-220`
- **Phân tích lỗi**:
  1. **Nhập nhằng nguồn đến (`Direct UDP` vs `Blind Relay`) của gói `DiscoPong` (`api-design.md:296,363-364`)**:
     Theo `api-design.md:296` và `system-architecture.md:494`, gói `b"MESHDS"` cũng được bọc qua Blind Relay (`frame_type = 0x02`) để đo RTT `via relay` cho `mesh ping` (`US-040 AC1`). Tuy nhiên, `api-design.md:363-364` mô tả chung rằng khi nhận `DiscoPing` sẽ trả `DiscoPong { tx_id, observed_addr }`, và khi nhận `DiscoPong` khớp `tx_id` sẽ **nâng cấp đường truyền sang `Direct(addr)`**! Nếu `DiscoEngine` không phân tách cứng nguồn gói tin đến (`IngressPath::DirectUdp(SocketAddr)` vs `IngressPath::Relay`), một gói `DiscoPong` đi vòng qua Relay sẽ làm `PeerMap` tưởng nhầm đường UDP trực tiếp đang thông (hoặc ghi đè địa chỉ rỗng/sai vào `DirectAddr`), gây mất kết nối tức thì (blackhole)! Ngoài ra cần ghi rõ payload `encrypted_disco_payload_b64` trong `POST /v1/disco/call-me-maybe` (`api-design.md:209`) là hộp `SalsaBox` của `DiscoPayload` (`msg_type = 0x03`) hay nguyên khung `b"MESHDS"` để Server và Client không lệch định dạng.
  2. **Đụng độ phạm vi file giữa các Developer chạy song song trong `sprint-backlog.md`**:
     - **Sprint 1 (Wave 1.0 / 1.1)**: `WP-S1-03` (`sprint-backlog.md:144`) được giao *"US-038 (phần parser chung + macOS/Linux)"*, nhưng file `crates/mesh-net/src/hosts.rs` (nơi chứa parser chung) lại nằm trong danh sách sở hữu của `WP-S1-00` (`:97`) và **không có** trong danh sách file của `WP-S1-03` (`:147-149`); đồng thời `WP-S1-04` (`:158`) chạy song song cùng Wave 1.1 cũng cần parser chung đó cho `hosts_windows.rs`!
     - **Sprint 2 (Wave 2.1)**: `WP-S2-02` (`:218`, `US-029..034`) sở hữu `crates/mesh-datapath/**` và `crates/meshd/src/control_loop.rs`, trong khi `WP-S2-03` (`:219`, `US-035, US-036` Roaming & Sleep/Wake) chỉ sở hữu `crates/meshd/src/{roaming_loop.rs,service_windows.rs}` và không gói nào sở hữu `crates/meshd/src/{main.rs,supervisor.rs}`! Thực tế `roaming_loop.rs` bắt buộc phải gọi rebind + `IP_BOUND_IF`/`IP_UNICAST_IF` vào `MagicSocket` (thuộc `mesh-datapath`), đánh thức `ExponentialBackoff` trong `control_loop.rs` và đăng ký task vào `supervisor.rs`. Thêm vào đó, story `Should` `US-054` (đóng gói Linux desktop) nằm ở `WP-S2-03` nhưng chưa được cấp quyền sửa `scripts/install-linux.sh` / `deploy/`.
- **Hệ quả thực tế (Impact)**: Chuyển mạch nhầm sang Direct UDP ảo làm đứt kết nối giữa 2 Symmetric NAT; xung đột merge hoặc thiếu hàm chung giữa các Developer Subagents ở Wave 1.1 và Wave 2.1.
- **Đề xuất hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Trong `api-design.md` §3.3: Tách rõ `DiscoEngine::handle_packet(pkt, ingress: IngressSource)` — chỉ cập nhật `DirectAddr` và điền `observed_addr` thật khi `ingress == IngressSource::DirectUdp(remote_addr)`; khi `ingress == IngressSource::Relay` thì `observed_addr` đặt `0.0.0.0:0` và `DiscoPong` chỉ dùng để hoàn tất đo RTT `via relay` cho `mesh ping`, tuyệt đối không nâng cấp `ActivePath` sang `Direct`. Khóa rõ định dạng byte của `encrypted_disco_payload_b64` trong `POST /v1/disco/call-me-maybe`.
  2. Trong `sprint-backlog.md`:
     - Chuyển toàn bộ phần parser/validator OS-neutral `# BEGIN mesh … # END mesh` (`crates/mesh-net/src/hosts.rs` kèm unit test + `proptest!`) về hoàn tất ngay tại **`WP-S1-00` (Wave 1.0)**; ở Wave 1.1, `WP-S1-03` chỉ chạm `hosts_{linux,macos}.rs` và `WP-S1-04` chỉ chạm `hosts_windows.rs` (0% đụng độ).
     - Định nghĩa sẵn kênh tín hiệu `mpsc::Sender<NetworkChangeEvent>` / trait điều khiển roaming giữa `roaming_loop.rs`, `control_loop.rs` và `MagicSocket` ngay từ `WP-S1-05` (hoặc phân tách file handler riêng trong `mesh-datapath` + giao rõ quyền sửa `supervisor.rs` và `deploy/linux-desktop/*` ở Sprint 2).

---

## 4. Các Đề Xuất Cải Tiến Mức `🟡 Improvement` (Nên Gọt Sắc Luôn Trong Vòng Sửa)

1. **`IMP-G2-01` (`agile-architect` — `api-design.md:312`, `system-architecture.md:479`)**: **Sai số hằng số độ dài tối thiểu gói Disco UDP (`MIN_DISCO_PACKET_LEN`)**.
   Tài liệu ghi `len >= 62`, nhưng tính đúng tổng kích thước khung Disco tối thiểu là: `6B` (`"MESHDS"`) + `1B` (`version`) + `32B` (`src_pubkey`) + `24B` (`nonce`) + `21B` (`DiscoPayload` header tối thiểu) + `16B` (`Poly1305 tag`) = **`100 bytes`** (hoặc `101 bytes` nếu có `1B` body). Sửa hằng số chặn sớm thành `len >= 100` để bộ demux loại bỏ các gói rác kích thước 62..99 bytes ngay trước khi gọi giải mã `SalsaBox`.
2. **`IMP-G2-02` (`agile-architect` — `database-design.md:202-214`)**: **`ServerIdentityRecord` gắn `#[derive(Debug, Serialize)]` trực tiếp trên khóa bí mật PKCS#8 thô**.
   Hai trường `identity_pkcs8_der: Vec<u8>` và `staged_next_pkcs8_der: Option<Vec<u8>>` chứa khóa riêng ECDSA P-256 của Server. Việc gắn `#[derive(Debug, Serialize)]` trên struct miền này vi phạm trực tiếp quy tắc `SEC-01` (`coding-standards.md` §5.1: cấm lộ khóa bí mật qua `Debug`/`Serialize`, test `test_no_secrets_in_outputs` sẽ bắt lỗi). Cần bọc bằng kiểu `SecretBytes` (`ZeroizeOnDrop`, `Debug` in `"[REDACTED]"`) và chỉ chuyển sang DTO nhị phân nội bộ ngay bên trong hàm ghi trang `redb` của `crates/mesh-store`.
3. **`IMP-G2-03` (`agile-tech-lead` — `tech-stack-decision.md:191,221-258`, `.agents/rules/coding-standards.md`)**: **Đồng bộ crate `tower` và giữ trần dung lượng `< 10 KB` cho file rule**.
   `tech-stack-decision.md:191` nhắc đến `tower 0.5` nhưng bảng §7.1 Allowed Crates chưa liệt kê `tower` (có thể bỏ `tower` trực tiếp và chỉ dùng `axum::middleware::from_fn` + `axum::extract::DefaultBodyLimit`, hoặc thêm `tower` tường minh vào §7.1). Đồng thời lưu ý `.agents/rules/coding-standards.md` hiện có kích thước **`9,713 bytes`**, nên khi cập nhật thêm `x509-cert`, `rustls-webpki`, `rustls-native-certs` vào mục 1 cần rút gọn vài từ ngữ mô tả để giữ dung lượng nghiêm ngặt **`< 10,000 bytes`**.

---

## 5. Bảng Phân Công Khắc Phục Đích Danh (Round 1 Revision Plan)

| Subagent chịu trách nhiệm | Mã hạng mục cần xử lý | Danh sách file cần cập nhật | Tiêu chí nghiệm thu sau khi sửa |
| :--- | :--- | :--- | :--- |
| **`agile-tech-lead`** | `BLK-G2-01`, `BLK-G2-04`, `HR-G2-01` (phần `sysexec`), `HR-G2-02`, `IMP-G2-03` | `scripts/bootstrap-toolchain.ps1`, `scripts/check.ps1`, `scripts/check.sh`, `rust-toolchain.toml`, `deny.toml`, `docs/03-system-design/tech-stack-decision.md`, `docs/03-system-design/coding-standards.md`, `docs/03-system-design/architecture-decision-record.md` (`ADR-006`, `ADR-011`), `.agents/rules/coding-standards.md` | 1. `bootstrap-toolchain.ps1` cài prebuilt `llvm-mingw` + `zig` + `cargo-deny` + `cargo-zigbuild` + `rcodesign` với SHA-256 thật & `throw` fail-closed khi lệch.<br>2. `check.ps1` tự động build/test được trên máy Windows không có Visual Studio (`--target x86_64-pc-windows-gnu` qua `llvm-mingw`); `check.sh` sửa lỗi `awk` batching (`FNR` / BOM).<br>3. Bổ sung `rustls-webpki`, `rustls-native-certs`, `x509-cert`, khóa `default-features = false` + `ring`, đồng bộ `deny.toml` và giữ `.agents/rules/coding-standards.md` `< 10 KB`.<br>4. Bổ sung `/sbin/ifconfig`, `/usr/sbin/ip`, `/sbin/ip` và đường dẫn tuyệt đối Windows vào `sysexec` allowlist. |
| **`agile-architect`** | `BLK-G2-02`, `BLK-G2-03`, `BLK-G2-04` (phần `SpkiPinVerifier`), `HR-G2-01` (phần Linux PBR + `ResourceLedger`), `HR-G2-03`, `HR-G2-04` (phần Disco), `IMP-G2-01`, `IMP-G2-02` | `docs/03-system-design/api-design.md`, `docs/03-system-design/database-design.md`, `docs/03-system-design/system-architecture.md` (phối hợp `ADR-003`, `ADR-006`) | 1. Khóa chặt State Machine `challenge_id` + `ProofPayload` (`method`, `path`, `body_sha256`, xử lý `tls_exporter_binding` chạy đúng cho cả Standalone lẫn Reverse Proxy và đa kết nối WS/REST).<br>2. Sửa kiểm tra supplementary groups cho macOS (`xucred.cr_groups` chứa `80`) & Linux (`getgrouplist` chứa `mesh-admin`), tách socket read-only `meshd-ro.sock` (`0666`) trên Unix.<br>3. Đặc tả Linux `table 51820` + `ip rule` trong `system-architecture.md` & `ResourceLedger`.<br>4. Bổ sung `emergency-revocations.bin` pre-allocated + `netmap_version` đơn điệu theo thời gian sau `ENOSPC` + chặn `NodeStatus::Expired` trong `register` + bọc `SecretBytes` cho `ServerIdentityRecord`.<br>5. Phân biệt `IngressSource::{DirectUdp, Relay}` trong `DiscoEngine` và sửa `MIN_DISCO_PACKET_LEN = 100`. |
| **`agile-scrum-master`** | `HR-G2-04` (phần phân ranh giới file song song) | `docs/04-sprint-management/sprint-backlog.md` | 1. Đưa phần parser chung `crates/mesh-net/src/hosts.rs` về hoàn tất tại `WP-S1-00` (Wave 1.0) để `WP-S1-03` và `WP-S1-04` chạy song song 0% chồng lấn ở Wave 1.1.<br>2. Khóa ranh giới file & kênh giao tiếp giữa `WP-S2-02` và `WP-S2-03` trên `crates/meshd/src/{supervisor.rs,control_loop.rs,roaming_loop.rs}` và `deploy/` cho `US-054`. |

---

## 6. Ghi Nhận Sớm `⚖️ Strategic Trade-offs` (Chuẩn Bị Trình Người Dùng Khi Mở Gate 2)

*(Mục này được ghi nhận khách quan trước để Scrum Master sử dụng ở vòng duyệt cuối sau khi các lỗi `🔴`/`🟠` ở trên được đóng hoàn tất)*:

1. **Giữ nguyên ranh giới Sprint 1 (`OQ-14`: 38 `Must` / 174 SP) vs Đề xuất kéo sớm 3 Story bảo mật sang Sprint 1 (`OQ-15`: +11 SP = 185 SP)**:
   - `sprint-backlog.md` §1 đã tuân thủ đúng quy tắc bảo toàn baseline Gate 1 nhưng nêu câu hỏi `OQ-15` rất xác đáng: kéo `US-029` (ACL deny-by-default), `US-030` (1-time pre-auth key) và `US-034` (auto-reconnect) sang Sprint 1 sẽ giúp bản bàn giao Milestone 1 an toàn và tự phục hồi ngay khi chạy thử trên Internet thật, đổi lại tăng tải Sprint 1 thêm ~6.3% SP (từ 174 lên 185 SP, giảm Sprint 2 xuống 49 SP).
2. **Cơ sở dữ liệu nhúng thuần Rust `redb` vs SQLite (`rusqlite`)**:
   - Chọn `redb 2.4` loại bỏ hoàn toàn phụ thuộc C (`libsqlite3-sys`), giúp cross-compile ra 4 đích siêu sạch và giữ binary nhỏ nhẹ, đổi lại Admin không thể dùng công cụ `sqlite3` có sẵn trên Ubuntu để soi file DB mà sẽ thao tác qua các lệnh chuẩn hóa `mesh-server backup` / `restore` / `mesh node list`.
3. **Userspace WireGuard (`defguard_boringtun`) trên 1 `MagicSocket` vs Kernel WireGuard**:
   - Đạt yêu cầu chạy đồng nhất trên macOS, Windows và Linux container không cần kernel module riêng và cho phép ghép kênh chung 1 cổng UDP với STUN/Disco, đổi lại thông lượng tối đa thấp hơn kernel module ở mạng 10 Gbps+ (nhưng dư sức bão hòa đường truyền dân dụng/VPS 100 Mbps – 1 Gbps của quy mô ≤ 20 nodes).
4. **Chuỗi biên dịch Portable (`llvm-mingw` + `zig` + `cargo-zigbuild`) trên máy Windows không cài Visual Studio**:
   - Giúp dựng môi trường phát triển và cross-compile 4 nền tảng gọn nhẹ (~250 MB) ngay trong `.tools/` mà không bắt người dùng cài ~6 GB Visual Studio Build Tools, đổi lại Windows binary cục bộ dùng ABI `-pc-windows-gnu` (vẫn nạp `wintun.dll` và chạy Windows Service bình thường 100%).

---

## 7. Kết Luận Bắt Buộc

Phán quyết kiểm định Độc lập Gate 2 (Round 1): **`[REVISION REQUIRED]`** — yêu cầu **`agile-tech-lead`**, **`agile-architect`** và **`agile-scrum-master`** khắc phục dứt điểm **4 `🔴 Blocker` (`BLK-G2-01..04`)** và **4 `🟠 High Risk` (`HR-G2-01..04`)** (kèm 3 cải tiến nhỏ `IMP-G2-01..03`) theo bảng phân công tại Mục 5 trước khi trình người dùng phê duyệt tại Gate 2.
