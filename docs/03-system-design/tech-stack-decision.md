# Tech Stack Decision — Mesh VPN cá nhân kiểu Tailscale (Rust 1.94.1)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-12 |
| Phiên bản | **2.0** — Chốt **Rust Stack** theo quyết định trực tiếp của Người dùng (2026-11-12 21:01), trình Gate 2 |
| Giai đoạn | 3 — Thiết kế hệ thống (sau Gate 1 ✅ 2026-11-12) |
| Thành phần AI/SLM | **Không có** → bỏ qua mục AI/ML Stack (đúng persona mục 3) |
| Đầu vào | `reference-systems-benchmark.md`, `production-readiness-requirements.md` v1.2, `project-charter.md` v1.2, `product-backlog.md` v1.2 |
| Tài liệu đi kèm | [architecture-decision-record.md](./architecture-decision-record.md) (ADR-001…011) · [coding-standards.md](./coding-standards.md) · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Cấu hình công cụ | [`rust-toolchain.toml`](../../rust-toolchain.toml) · [`rustfmt.toml`](../../rustfmt.toml) · [`clippy.toml`](../../clippy.toml) · [`deny.toml`](../../deny.toml) · [`.editorconfig`](../../.editorconfig) · [`scripts/`](../../scripts) |

> **Quy ước kiểm chứng.** `[V]` = **đã kiểm chứng thực nghiệm** trên máy phát triển Windows của người dùng. `[N]` = dựa trên tài liệu/nguồn công khai của hệ sinh thái crate, **chưa** đo hiệu năng runtime thực tế tại đây. Mọi con số hiệu năng/RAM/throughput là **mục tiêu thiết kế / SLO đề xuất chưa đo** (`C6`); `agile-qa` đo thực nghiệm tại `US-058`.

---

## 1. Tóm tắt quyết định (TL;DR)

| Hạng mục | Quyết định chốt | Lý do cốt lõi |
|---|---|---|
| **Ngôn ngữ & Compiler** | **Rust `1.94.1`** (`edition = "2024"`, `rust-version = "1.94.1"`), `#![forbid(unsafe_code)]` mặc định toàn workspace | Quyết định trực tiếp của Người dùng: **0 Garbage Collector (GC)**, footprint cực nhỏ (RAM chạy nền mục tiêu ~4–10 MB trên client, ~8–18 MB trên VPS; binary ~3–6 MB), an toàn bộ nhớ tuyệt đối cho daemon chạy quyền `root`/`SYSTEM` |
| **Kiến trúc Workspace** | **1 Cargo Workspace** (`resolver = "3"`) gồm **3 binaries** (`mesh-server`, `meshd`, `mesh`) và **7 crates nội bộ** (`crates/mesh-*`) | Tách đặc quyền OS rõ ràng; cô lập 100% FFI vào duy nhất `crates/mesh-sys` và cô lập mật mã vào duy nhất `crates/mesh-crypto` |
| **Async Runtime** | **`tokio` `1.44`** (chế độ tiết kiệm tài nguyên: `meshd` giới hạn 2 worker threads + stack 512 KB; `mesh` CLI dùng `current_thread`) | Chuẩn công nghiệp Rust async I/O; kiểm soát chặt số OS threads để giữ RSS ở mức vài MB |
| **WireGuard Userspace (`SEC-02`)** | **`defguard_boringtun` `0.6`** (BSD-3-Clause — fork bảo trì tích cực của Cloudflare `boringtun`) | State machine `noise::Tunn` **sans-I/O** (`encapsulate`/`decapsulate`) thuần Rust, 0 thread/socket ngầm, ghép trực tiếp vào **1 `tokio::net::UdpSocket` duy nhất** cùng STUN + Disco + Blind Relay |
| **TUN đa nền tảng** | Adapter mỏng trong `mesh-net` + `mesh-sys`: Windows **`wintun.dll`** (kiểm SHA-256 + `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`), macOS **`utun`** (`com.apple.net.utun_control`), Linux **`/dev/net/tun`** | Kiểm soát tuyệt đối tên adapter cố định Windows (`US-015`), ghi nhận đúng `utunN` vào sổ cái tài nguyên macOS (`US-060`), không cần chứng chỉ Apple Developer $99/năm |
| **TLS 1.3 + SPKI Pin + ACME (`SEC-04`)** | **`rustls` `0.23`** + **`tokio-rustls` `0.26`** + **`rcgen` `0.13`** (chứng chỉ IP+Pin) + **`instant-acme` `0.7`** (ACME `TLS-ALPN-01`/`DNS-01`) | 100% không phụ thuộc OpenSSL C; verifier SPKI Pin (`sha256:<hex>`) tùy chỉnh fail-closed, cấm TOFU |
| **HTTP & WebSocket (Control + Relay)** | **`axum` `0.8`** + **`tokio-tungstenite` `0.26`** trên **1 cổng TCP cấu hình được** (mặc định `443`) | Ghép chung Control RPC, Netmap Stream và Blind Relay trên 1 cổng TCP; tương thích cả Standalone lẫn sau Reverse Proxy (`Nginx`/`Caddy`) |
| **Mật mã & Bảo vệ Khóa (`SEC-01`, `SEC-02`)** | **`crypto_box` `0.9`** (X25519 + XSalsa20-Poly1305) + **`x25519-dalek` `2.0`** + **`sha2` `0.10`** + **`subtle` `2.6`** + **`rand` `0.8` (`OsRng`)** + **`zeroize` `1.8` (`ZeroizeOnDrop`)** | Thuần Rust; tự động xóa sạch khóa trong RAM ngay khi `Drop` (`ZeroizeOnDrop`) và tự che `"[REDACTED]"` trên mọi đường `Debug`/`Display`/`Serialize` |
| **Embedded DB trên VPS (`REL-11`, `REL-12`)** | **`redb` `2.4`** (MIT/Apache-2.0 — **100% Pure-Rust ACID MVCC key-value store**) | **0 dòng mã C** (không cần biên dịch C-SQLite), giao dịch ACID đa bảng nguyên tử, kiểm tra toàn vẹn khi boot, hỗ trợ **hot snapshot backup nguyên tử kèm SHA-256** (`US-045`) |
| **CLI & Cấu hình** | **`clap` `4.5`** (`derive`, `env`) + **`toml` `0.8`** + **`serde` `1.0`** (`deny_unknown_fields`) | Kiểm tra kiểu cấu hình ngay lúc parse; CLI đồng nhất `mesh <noun> <verb>` trên cả 3 OS |
| **Logging & Metrics** | **`tracing` `0.1`** + **`tracing-subscriber` `0.3`** (JSON) + **`tracing-appender` `0.2`** + Prometheus text exposition nội bộ | Structured JSON log chuẩn `OPS-01`; không kéo collector nặng vào daemon |
| **OS IPC & Service (`SEC-14`, `PLAT-01..06`)** | Unix Domain Socket (`tokio::net::UnixListener::peer_cred` cho `SO_PEERCRED` / `LOCAL_PEERCRED`), Windows Named Pipe (`tokio` + `windows-sys` `0.59` SDDL DACL) + **`windows-service` `0.7`** + **`socket2` `0.5`** | Kiểm chứng đặc quyền người gọi ở tầng OS (`SEC-14`); ràng socket chống routing loop (`SO_MARK`, `IP_BOUND_IF`, `IP_UNICAST_IF`) |
| **Cưỡng chế Chất lượng & Giấy phép** | **`rustfmt`** + **`clippy` (`-D warnings`)** + **`cargo-deny`** (`deny.toml`) + `scripts/check.{ps1,sh}` | Chặn tự động `.unwrap()`, `.expect()`, `panic!`, `unsafe` ngoài `mesh-sys`, và chặn tuyệt đối crate `AGPL`/`GPL`/`LGPL` |

---

## 2. Đầu vào & Ràng buộc Quyết định

| Nguồn | Ràng buộc ảnh hưởng trực tiếp tới Tech Stack |
|---|---|
| **Quyết định Người dùng (2026-11-12 21:01)** | Chọn **Rust** thay vì Go/C++ để đạt nhị phân gọn nhẹ (~3–6 MB), **không có GC**, tốn tối thiểu RAM (~4–10 MB trên client, ~8–18 MB trên VPS) và an toàn bộ nhớ ở mức trình biên dịch |
| **Gate 1 D1 (Client P0)** | **macOS 13+** (`aarch64-apple-darwin` & `x86_64-apple-darwin`, dùng `utun` + `launchd`, không cần chứng chỉ Apple Developer $99/năm) và **Windows 10/11 x64** (`Wintun` + Windows Service) |
| **Gate 1 D2 (Server/Node P0)** | **Ubuntu Linux LTS x64** trên 1 VPS (1–2 vCPU, 1–2 GB RAM): chạy Control + Blind Relay + STUN, đồng thời hỗ trợ `/dev/net/tun` làm 1 node mesh (`US-056`) và chạy phòng lab NAT container (`US-057`) |
| **Gate 1 D3 & D4 (Kết nối & Cổng)** | Kết nối trực tiếp bằng **IP VPS + SPKI Pin (`sha256:…`)** là luồng chính thức mặc định từ ngày đầu (`SEC-04(c)`, cấm TOFU); cổng TCP (mặc định `443`) và UDP STUN (mặc định `3478`) **cấu hình đổi tùy ý** (`GNFR-11`, `SEC-15`) |
| **Ràng buộc Giấy phép (`C5`, `R-15`)** | **CẤM TUYỆT ĐỐI** phụ thuộc crate hoặc sao chép mã nguồn `AGPL` (như NetBird server AGPLv3), `GPL`, `LGPL`; phân phối `wintun.dll` nguyên vẹn cạnh `.exe` kèm kiểm tra SHA-256 theo đúng *Prebuilt Binaries License* |
| **Thực trạng máy phát triển (`[V]`)** | Máy Windows 10/11 x64 đã cài sẵn `rustc 1.94.1 (e408947bf 2026-03-25)`, `cargo 1.94.1`, `rustfmt 1.8.0-stable`, `clippy 0.1.94`, `git`, `docker`, `wsl`, `python 3.9` `[V]`; hiện chưa cài Visual Studio C++ Build Tools (`link.exe`) hay `zig` `[V]` → cần `scripts/bootstrap-toolchain.ps1` gọn nhẹ |

---

## 3. Ngôn ngữ & Compiler: Rust vs Go vs C++20 (Trade-off Matrix)

### 3.1. Ma trận so sánh trung thực

| Tiêu chí | Trọng số | **Rust 1.94.1 (Chốt)** | Go 1.27 | C++20 |
|---|---:|---|---|---|
| **Footprint bộ nhớ (RAM) & Không có GC** | 25 | **5/5** — Không có runtime GC; cấp phát tĩnh/arena cho packet buffer; RAM chạy nền kỳ vọng **~4–10 MB** (client) và **~8–18 MB** (VPS) `[N]`; xóa khóa tức thì trong RAM bằng `ZeroizeOnDrop` | **3/5** — Có Garbage Collector (GC) và runtime heap reserve; RAM chạy nền thường ~20–45 MB; GC có thể sao chép vùng nhớ chứa khóa trước khi thu hồi | **5/5** — Không có GC; footprint ~3–8 MB |
| **An toàn bộ nhớ & Bảo mật cho Daemon `root`/`SYSTEM`** | 25 | **5/5** — Đảm bảo an toàn bộ nhớ, không data race, không buffer overflow/use-after-free ngay lúc biên dịch với `#![forbid(unsafe_code)]` trên toàn bộ parser mạng (STUN, Disco, Relay, WireGuard) | **3.5/5** — An toàn con trỏ cơ bản nhưng vẫn có khả năng data race trên biến dùng chung hoặc panic do `nil` pointer nếu thiếu kiểm tra | **1.5/5** — Rủi ro cao về memory corruption (buffer overread, use-after-free) trong daemon chạy quyền `root`/`SYSTEM` khi xử lý gói UDP từ Internet |
| **Hiệu năng Data Plane (WireGuard ChaCha20-Poly1305) & Độ trễ P99** | 15 | **5/5** — State machine `defguard_boringtun` sans-I/O chạy trực tiếp trên buffer tầng ứng dụng, không bị GC pause làm vọt tail-latency | **4/5** — Đạt yêu cầu 300 Mbps nhưng tốn thêm chi phí điều phối goroutine/channel trong `wireguard-go` | **5/5** — Tốc độ tối đa |
| **Kích thước Binary phân phối** | 10 | **5/5** — **~3–6 MB** mỗi binary sau khi bật `lto = "thin"`, `strip = "symbols"`, `panic = "abort"` và dùng pure-Rust crates (`redb`) | **3/5** — ~8–18 MB mỗi binary do nhúng runtime Go + SQLite transpiled | **5/5** — ~2–5 MB |
| **Quản lý phụ thuộc & Cưỡng chế chuẩn code cho nhiều Subagent** | 15 | **4.5/5** — `cargo` + `rustfmt` + `clippy` (`-D warnings`, cấm `unwrap`/`expect`/`panic`) + `cargo-deny` kiểm soát chặt giấy phép và CVE; trình biên dịch cực kỳ nghiêm khắc | **5/5** — `gofumpt` + `golangci-lint`, cú pháp đơn giản | **2/5** — CMake/vcpkg/Conan phân mảnh, nhiều phương ngữ dễ lệch chuẩn giữa các Developer |
| **Trải nghiệm Cross-compile 4 đích từ Windows** | 10 | **3.5/5** — Cần linker gốc hoặc **Portable Zig (`cargo-zigbuild`)** khi ưu tiên **100% Pure-Rust (0 mã C)**; giải quyết dứt điểm bằng `scripts/bootstrap-toolchain.ps1` + GitHub Actions matrix | **5/5** — Cross-compile có sẵn với `CGO_ENABLED=0` | **1.5/5** — Rất phức tạp trên 3 hệ điều hành |
| **Điểm tổng hợp có trọng số (/100)** | **100** | **93.5 / 100** | 76.5 / 100 | 69.5 / 100 |

### 3.2. Chiến lược "100% Pure-Rust / Zero-C" để hóa giải bài toán Cross-Compile của Rust

Điểm nghẽn kinh điển khi cross-compile các dự án Rust là việc vô tình kéo theo các thư viện C ẩn (`openssl-sys`, `libsqlite3-sys` của `rusqlite`, hoặc `cmake`+`nasm` của `aws-lc-rs`). Để việc biên dịch trên máy Windows và cross-compile sang Linux/macOS diễn ra trơn tru, kiến trúc Rust của Mesh VPN áp dụng kỷ luật **Pure-Rust First**:

1. **Database thuần Rust 100%**: Dùng **`redb`** thay vì `rusqlite` (`bundled` C SQLite) → loại bỏ hoàn toàn hàng trăm nghìn dòng mã C khỏi cây biên dịch.
2. **TLS & Mật mã không cần CMake/NASM/OpenSSL**:
   - Cấm tuyệt đối `openssl-sys` và `native-tls`.
   - Cấu hình `rustls` với `default-features = false` để **tắt `aws-lc-rs`** (vốn đòi CMake + NASM trên Windows).
   - Cung cấp 2 feature chọn lọc cho `CryptoProvider` của `rustls`: **`ring`** (mặc định cho bản release tốc độ cao, biên dịch nhẹ qua MSVC hoặc `zig cc`) và **`rustls-rustcrypto`** (100% Pure-Rust, 0 dòng C/ASM — đảm bảo build được ngay cả khi môi trường không có trình dịch C).
3. **Cấu hình tối ưu Binary nhỏ nhẹ & Ít RAM (`Cargo.toml` gốc)**:
   ```toml
   [profile.release]
   opt-level = 3           # Tối ưu tốc độ mã hóa ChaCha20-Poly1305 & xử lý gói UDP
   lto = "thin"            # Loại bỏ mã chết xuyên crate, giảm mạnh kích thước binary
   codegen-units = 1       # Tối ưu hóa toàn cục mỗi crate
   strip = "symbols"       # Loại bỏ bảng ký hiệu debug khỏi binary phát hành (~3-6 MB)
   panic = "abort"         # Không nhúng mã unwinding stack, giảm kích thước & dừng tức thì khi lỗi bất biến
   ```

---

## 4. Toolchain & Bootstrap trên máy phát triển Windows (`[V]`)

### 4.1. Trạng thái thực tế đã kiểm chứng trên máy người dùng (`[V]`)
- **Đã có sẵn**: `rustc 1.94.1 (e408947bf 2026-03-25)`, `cargo 1.94.1`, `rustfmt 1.8.0-stable`, `clippy 0.1.94`, `git`, `docker`, `wsl`, `python 3.9` `[V]`.
- **Chưa cài sẵn**: Visual Studio C++ Build Tools (`link.exe` / `vswhere` chưa có trên máy), `zig`, `cargo-deny`, `cargo-zigbuild` `[V]`.

### 4.2. Giải pháp `scripts/bootstrap-toolchain.ps1` (Không bắt cài 6 GB Visual Studio nếu không muốn)

Script [`scripts/bootstrap-toolchain.ps1`](../../scripts/bootstrap-toolchain.ps1) hỗ trợ 2 chế độ rõ ràng để người dùng hoặc CI lựa chọn:

1. **Phương án A — Gọn nhẹ, không cần quyền Admin, không cần 6 GB Visual Studio (`-Mode PortableZig`, khuyến nghị)**:
   - Tải bản portable **Zig** (~45 MB, kiểm tra mã băm SHA-256 cố định) giải nén vào `%USERPROFILE%\sdk\zig` và portable **LLVM-MinGW / LLD** (hoặc dùng `zig cc` làm linker).
   - Thêm target `x86_64-pc-windows-gnu`, `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin` qua `rustup target add`.
   - Cài đặt binary `cargo-deny`, `cargo-zigbuild` và `apple-codesign` (`rcodesign`) để:
     - Build và chạy test cục bộ trên Windows mà không cần cài Visual Studio 2022.
     - Cross-compile trực tiếp từ Windows ra `x86_64-unknown-linux-musl` (binary tĩnh hoàn toàn cho VPS Ubuntu & container lab) và `aarch64-apple-darwin` / `x86_64-apple-darwin` (kèm ký ad-hoc Mach-O `arm64` bằng `rcodesign sign` theo yêu cầu `PLAT-06(1)`).
2. **Phương án B — Native MSVC (`-Mode Msvc`)**:
   - Cài đặt `Microsoft.VisualStudio.2022.BuildTools` (`--override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"`) qua `winget` cho target mặc định `x86_64-pc-windows-msvc`.
3. **Kết hợp Docker/WSL & GitHub Actions Matrix**:
   - Các kịch bản kiểm thử tích hợp Linux (`netlink`, `/dev/net/tun`, NAT lab `US-057`) chạy qua Docker/WSL ngay trên máy Windows.
   - Bản phát hành chính thức và bộ kiểm thử OS đặc quyền chạy trên GitHub Actions matrix (`ubuntu-latest`, `windows-latest`, `macos-latest`).

---

## 5. Kiến trúc Cargo Workspace & Phân tách Crates

Toàn bộ dự án nằm trong **1 Cargo Workspace** tại gốc `D:\Project\Idea\mesh-vpn\Cargo.toml` (`resolver = "3"`, `edition = "2024"`, `rust-version = "1.94.1"`):

```text
mesh-vpn/
├── Cargo.toml                 # Workspace root: [workspace.package], [workspace.dependencies], [workspace.lints], [profile.release]
├── Cargo.lock                 # Bắt buộc commit để khóa cứng phiên bản chính xác của mọi crate
├── rust-toolchain.toml        # Ghim channel = "1.94.1", components = ["rustfmt", "clippy"]
├── rustfmt.toml               # Chuẩn định dạng mã nguồn Rust
├── clippy.toml                # Ngưỡng độ phức tạp & danh sách hàm/kiểu bị cấm
├── deny.toml                  # Chính sách giấy phép (chặn AGPL/GPL/LGPL) & kiểm tra lỗ hổng CVE
├── scripts/
│   ├── bootstrap-toolchain.ps1
│   ├── check.ps1
│   └── check.sh
└── crates/
    ├── mesh/                  # [Binary: mesh] CLI cho người dùng & lệnh quản trị VPS qua IPC cục bộ
    ├── meshd/                 # [Binary: meshd] Agent daemon (root trên macOS/Linux, SYSTEM trên Windows)
    ├── mesh-server/           # [Binary: mesh-server] Control + Blind Relay + STUN + Observability (user không đặc quyền trên VPS Linux)
    ├── mesh-core/             # [Lib] Kiểu miền (NodeId, NodeName, OverlayIp, Port), AppError, Clock, Backoff, Defaults, Brand
    ├── mesh-crypto/           # [Lib] DUY NHẤT được import mật mã: Secret<T>/ZeroizeOnDrop, NaCl box, SHA-256, SPKI Pin Verifier
    ├── mesh-proto/            # [Lib] Định nghĩa & bộ parser có kiểm biên cho Control RPC/Stream, STUN (RFC 5389), Disco, Relay frame
    ├── mesh-datapath/         # [Lib] Tích hợp defguard_boringtun (Tunn sans-I/O), MagicSocket 1-UDP-socket demuxer, peer diff, failover
    ├── mesh-net/              # [Lib] Trừu tượng hóa OS (TunDevice, RouteManager, NetMonitor, HostsBlock, ResourceLedger, PrivilegeIpc, Sysexec)
    ├── mesh-store/            # [Lib] Lưu trữ ACID thuần Rust trên redb, migration, in-memory emergency revoke, hot atomic backup + SHA-256
    └── mesh-sys/              # [Lib] DUY NHẤT được phép dùng #[deny(unsafe_op_in_unsafe_fn)] cho FFI hệ điều hành (Windows/macOS/Linux)
```

### Quy tắc cô lập đặc quyền & an toàn bộ nhớ giữa các Crates
1. **Cô lập `unsafe` tuyệt đối**: `Cargo.toml` gốc đặt `[workspace.lints.rust] unsafe_code = "forbid"`. Chỉ riêng `crates/mesh-sys` được phép ghi đè `#![allow(unsafe_code)]` kèm `#![deny(unsafe_op_in_unsafe_fn)]` và `#![deny(clippy::undocumented_unsafe_blocks)]`. Mọi crate nghiệp vụ (`mesh-proto`, `mesh-datapath`, `mesh-store`, `mesh-server`, `meshd`, `mesh`) có **0 dòng `unsafe`**.
2. **Cô lập mật mã (`SEC-02`)**: Chỉ `crates/mesh-crypto` (và `defguard_boringtun` bên trong `crates/mesh-datapath`) được phép gọi các hàm nguyên thủy mật mã. Các crate khác chỉ gọi API cấp cao đã định kiểu của `mesh-crypto`.
3. **Tách tiến trình trên VPS (`SEC-06(4)`, `US-056`)**: Khi VPS tham gia mesh như một node (`vps.mesh.internal`), `mesh-server` chạy dưới user hệ thống `mesh` không đặc quyền (`CAP_NET_BIND_SERVICE` chỉ khi cổng < 1024), còn `meshd` chạy trong một unit `systemd` riêng biệt với `CAP_NET_ADMIN`.

---

## 6. Lựa chọn Crates theo từng Tầng Kiến trúc (Trade-off Matrices)

### 6.1. Async Runtime & Quản lý Tài nguyên

| Phương án | Giấy phép | Ưu điểm | Nhược điểm | Quyết định |
|---|---|---|---|---|
| **`tokio` `1.44`** + `tokio-util` `0.7` | MIT | Chuẩn de-facto của hệ sinh thái mạng Rust; hỗ trợ sẵn UDP, TCP, Unix Domain Socket (`peer_cred`), Windows Named Pipe, signal, timer; cho phép cấu hình số luồng linh hoạt | Nếu để mặc định `#[tokio::main]` trên máy nhiều nhân sẽ tạo nhiều worker threads | **CHỌN** — Cấu hình tường minh bằng `tokio::runtime::Builder`: `meshd` dùng `worker_threads(2)` + `thread_stack_size(512 * 1024)` (RAM nền ~4–10 MB); `mesh-server` dùng `worker_threads(2)`; `mesh` CLI dùng `new_current_thread()` |
| `smol` / `async-std` | Apache-2.0 / MIT | Nhỏ gọn | Không tương thích trực tiếp với `axum`, `hyper`, `tokio-tungstenite` (phải qua lớp cầu nối `async-compat`) | Loại |
| Luồng OS thuần (`std::thread`) | — | Không cần async state machine | Tốn stack cho mỗi kết nối WebSocket/Relay đồng thời; khó hủy tác vụ có thời hạn (`≤ 5 s` shutdown) | Loại |

### 6.2. WireGuard Userspace (`SEC-02`, `US-014`, `US-015`, `US-060`)

| Phương án | Giấy phép | Kiến trúc I/O | Đánh giá & Lý do | Quyết định |
|---|---|---|---|---|
| **`defguard_boringtun` `0.6`** | **BSD-3-Clause** | **Sans-I/O state machine** (`noise::Tunn`: `encapsulate`, `decapsulate`, `update_timers`) | Fork được bảo trì tích cực của Cloudflare `boringtun` (cập nhật RustCrypto/dalek mới); **không tự mở socket hay đẻ thread ngầm**, cho phép `mesh-datapath` đọc/ghi từ **1 `tokio::net::UdpSocket` duy nhất** dùng chung cho STUN, Disco và Blind Relay! | **CHỌN** |
| `boringtun` `0.5` (Cloudflare gốc) | BSD-3-Clause | Sans-I/O | Cloudflare đã lưu trữ (archive) repo gốc, phụ thuộc các bản `ring`/`x25519-dalek` cũ | Loại (dùng bản `defguard_boringtun` kế thừa cùng giấy phép BSD-3) |
| `gotatun` (Mullvad fork) | **MPL-2.0** | Gắn chặt runtime | Giấy phép copyleft từng file **MPL-2.0** (cần tránh theo chính sách ưu tiên MIT/BSD/Apache); API gắn với kiến trúc riêng của Mullvad | Loại |
| Tự lắp giao thức từ `snow` (`Noise_IKpsk2`) | Apache-2.0/MIT | Tự viết | **Vi phạm trực tiếp `SEC-02` / `GNFR-01`** ("Không tự viết mật mã / không tự lắp giao thức data plane") | **CẤM** |

> **Điểm sáng kiến trúc của `defguard_boringtun::noise::Tunn`**:
> Trong `mesh-datapath`, `MagicSocket` sở hữu duy nhất **1 `tokio::net::UdpSocket`** (bind lại cổng UDP cục bộ đã lưu bền theo `US-019 AC1`). Khi một gói UDP đến:
> 1. Nếu byte 4..8 là magic cookie STUN `0x2112A442` → chuyển cho bộ giải mã `mesh_proto::stun`.
> 2. Nếu 6 byte đầu là magic header Disco `b"MESHDS"` (`0x4d4553484453`) → chuyển cho `mesh_datapath::disco`.
> 3. Ngược lại → tra bảng peer và đưa thẳng slice gói tin vào `tunn.decapsulate(None, packet, &mut out_buf)` rồi ghi gói IP giải mã ra `TunDevice`.
> Khi gửi gói từ `TunDevice`: gọi `tunn.encapsulate(ip_packet, &mut wg_buf)`; nếu peer đã có đường `Direct(SocketAddr)` thì gửi qua `UdpSocket`, nếu chưa có hoặc direct vừa chết (`US-022`, `US-026`) thì đẩy ngay vào kênh `BlindRelay` qua WebSocket TLS! Không cần bất kỳ lớp giả lập socket phức tạp nào.

### 6.3. Thiết bị TUN & Tích hợp Mạng theo Hệ điều hành (`PLAT-01`, `PLAT-03`, `PLAT-06`)

| Phương án | Giấy phép | Đánh giá | Quyết định |
|---|---|---|---|
| **Adapter mỏng trong `mesh-net` + `mesh-sys`** (kết hợp `wintun-bindings` / FFI kiểm chứng SHA-256 trên Windows, `utun` socket trên macOS, `/dev/net/tun` `ioctl` trên Linux) | MIT / Apache-2.0 | Cho phép kiểm soát 100%: (1) Trên **Windows**, kiểm tra SHA-256 của `wintun.dll` đặt cạnh `meshd.exe` **trước khi** nạp bằng `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`, đặt tên adapter cố định và GUID cố định để chống adapter ma (`R-05`, `US-015`); (2) Trên **macOS**, mở `AF_SYSTEM` `com.apple.net.utun_control`, đọc tên `utunN` thực tế do kernel cấp qua `getsockopt(..., UTUN_OPT_IFNAME)` và **ghi ngay vào sổ cái tài nguyên (`ResourceLedger`) trước khi cài route** (`US-060`); (3) Trên **Linux**, mở `/dev/net/tun` với `IFF_TUN \| IFF_NO_PI` và đóng gói vào `tokio::io::unix::AsyncFd` | **CHỌN** |
| Crate `tun` / `tun-rs` nguyên khối | WTFPL / BSD / MIT | Tự động hóa một số bước tạo IP/route ngầm bên trong thư viện, khó ép buộc quy tắc "ghi vào sổ cái tài nguyên trước khi tạo" (`REL-08`) và không kiểm tra SHA-256 `wintun.dll` trước khi gọi `LoadLibrary` | Loại (chỉ tham khảo cấu trúc header packet 4-byte `AF_INET` của `utun` macOS) |

### 6.4. TLS 1.3, SPKI Pinning & ACME (`SEC-04`, `US-003`, `US-047`)

| Thành phần | Crate chọn | Thay thế bị loại | Lý do kỹ thuật |
|---|---|---|---|
| **TLS Engine** | **`rustls` `0.23`** + **`tokio-rustls` `0.26`** (`default-features = false`, bật TLS 1.3, provider `ring` `0.17` kèm feature dự phòng `rustls-rustcrypto`) | `native-tls` / `openssl-sys` | Không phụ thuộc OpenSSL C; tắt `aws-lc-rs` mặc định để không đòi CMake + NASM trên Windows; hỗ trợ `ServerCertVerifier` tùy chỉnh để kiểm tra SPKI Pin (`sha256:<hex>`) và hỗ trợ `ExportKeyingMaterial` (RFC 5705 / RFC 8446) làm channel binding cho bước chứng minh khóa node (`ADR-003`) |
| **Sinh chứng chỉ IP + Pin** | **`rcgen` `0.13`** + **`sha2` `0.10`** | Gọi lệnh `openssl` ngoài | Thuần Rust; sinh cặp khóa định danh server ECDSA P-256 bền vững, tính `sha256` trên phần DER của `subjectPublicKeyInfo` (SPKI), và cho phép tái phát hành chứng chỉ X.509 giữ nguyên khóa công khai để client không phải pin lại (`US-047 AC3`) |
| **ACME Client (`TLS-ALPN-01` & `DNS-01`)** | **`instant-acme` `0.7`** | `tokio-rustls-acme` (thiếu kiểm soát sâu `DNS-01` và cổng tùy chỉnh) | Thuần Rust, gọn nhẹ; cho phép `mesh-server` tự điều khiển vòng đời: dùng `TLS-ALPN-01` (ALPN `acme-tls/1`) khi cổng TCP = `443`, và bắt buộc chuyển sang `DNS-01` hoặc từ chối cấu hình có hướng dẫn khi cổng TCP ≠ `443` (`US-047 AC7`), hoàn toàn không cần mở cổng 80 |

### 6.5. HTTP Control Plane & WebSocket Blind Relay (`US-009`, `US-024`, `US-025`)

| Phương án | Giấy phép | Ưu điểm | Nhược điểm | Quyết định |
|---|---|---|---|---|
| **`axum` `0.8`** + **`tokio-tungstenite` `0.26`** + **`hyper` `1.6`** + **`tower` `0.5`** | MIT | Cùng hệ sinh thái chính chủ của `tokio`; định tuyến HTTP/1.1 + nâng cấp WebSocket (`GET /v1/netmap/stream` và `GET /v1/relay`) ngay trên **cùng 1 cổng TCP**; kiểm soát chặt `max_frame_size`/`max_message_size` theo MTU | — | **CHỌN** |
| `actix-web` | MIT/Apache-2.0 | Nhanh | Dùng mô hình runtime local riêng, dư thừa khi đã dùng `tokio` | Loại |
| `warp` | MIT | Nhẹ | Hệ thống kiểu filter phức tạp, bảo trì chậm | Loại |

### 6.6. Mật mã & Bảo vệ Bí mật trong RAM (`SEC-01`, `SEC-02`)

| Nhu cầu | Crate được chọn (100% Pure-Rust) | Vị trí cho phép duy nhất | Cơ chế an toàn |
|---|---|---|---|
| **Zeroization & Redaction (`SEC-01`)** | **`zeroize` `1.8`** (`Zeroize`, `ZeroizeOnDrop`) + kiểu bọc `Secret<T>` trong `mesh-crypto` | Định nghĩa tại `crates/mesh-crypto` | Khi biến chứa private key hoặc pre-auth key ra khỏi phạm vi (`Drop`), bộ nhớ RAM bị ghi đè bằng `0` thông qua phép ghi volatile chống trình biên dịch tối ưu hóa bỏ qua; `Debug`, `Display`, `Serialize` luôn xuất `"[REDACTED]"` |
| **Chứng minh khóa Node & Xác thực Disco (`SEC-02`, `US-003`, `US-021`)** | **`crypto_box` `0.9`** (NaCl box: X25519 + XSalsa20-Poly1305) + **`x25519-dalek` `2.0`** | `crates/mesh-crypto` | Chứng minh sở hữu khóa Curve25519 bằng challenge nonce 32-byte từ server + khóa ephemeral X25519 của server; xác thực gói Disco (`Ping`/`Pong`/`CallMeMaybe`) kèm `tx_id` 96-bit ngẫu nhiên chống phát lại |
| **Băm Pre-Auth Key & So sánh Constant-Time (`SEC-03`, `SEC-05`)** | **`sha2` `0.10`** + **`subtle` `2.6`** (`ConstantTimeEq`) | `crates/mesh-crypto` | Pre-auth key sinh từ `rand::rngs::OsRng` (≥ 256-bit); DB chỉ lưu băm SHA-256; đối chiếu bằng `ct_eq` |
| **STUN Binding (`US-019`)** | Tự hiện thực codec ~200 dòng trong **`crates/mesh-proto::stun`** + **`crc32fast` `1.4`** | `crates/mesh-proto` | Chỉ cài đặt đúng RFC 5389 / RFC 8489 Binding Request/Response (`XOR-MAPPED-ADDRESS`, `FINGERPRINT`), **không** kéo cả bộ stack WebRTC/DTLS khổng lồ của `webrtc-rs`/`stun` crate; bắt buộc kèm kiểm thử vector RFC 5769 và `proptest`/fuzz |

### 6.7. Cơ sở dữ liệu nhúng trên VPS (`REL-11`, `REL-12`, `US-007`, `US-045`)

| Phương án | Giấy phép | Mã C (FFI) | Đánh giá trung thực | Quyết định |
|---|---|---|---|---|
| **`redb` `2.4`** | **MIT OR Apache-2.0** | **0 dòng C (100% Pure Rust)** | Kho dữ liệu ACID nhúng viết hoàn toàn bằng Rust an toàn; dùng cây B-tree Copy-on-Write (MVCC): `begin_write()` tạo giao dịch ACID nguyên tử xuyên nhiều bảng (`nodes`, `nodes_by_pubkey`, `nodes_by_ip`, `preauth_keys`, `audit_events`, `server_identity`); `begin_read()` tạo snapshot đọc cô lập **không bao giờ chặn luồng ghi**; có sẵn `check_integrity()`; kích thước mã và RAM cực kỳ nhỏ (~1–2 MB) | **CHỌN** |
| `rusqlite` `0.33` (`bundled`) | MIT (SQLite Public Domain) | **Có (~250K dòng C)** | Rất chín muồi nhưng buộc phải biên dịch mã C (`libsqlite3-sys`), cần C toolchain khi cross-compile, làm phình binary và đưa một khối FFI `unsafe` lớn vào `mesh-server` | Loại (giữ đúng ưu tiên Pure-Rust / Zero-C) |
| `sled` | MIT/Apache-2.0 | Không | Chưa bao giờ ra bản 1.0 ổn định, tiêu tốn RAM và ghi đĩa nền nhiều | **CẤM** |
| `sqlx` / `sea-orm` / `diesel` | MIT/Apache-2.0 | Có | Quá nặng cho quy mô 3–20 node trên 1 VPS | **CẤM** |

---

## 7. Dependency Policy (Danh mục Crates Được phép & Bị cấm)

### 7.1. Danh mục Crates **ĐƯỢC PHÉP** (Ghim trong `[workspace.dependencies]` của `Cargo.toml`)

> **Quy tắc bất biến**: Một chức năng chỉ dùng đúng **một** crate trong bảng dưới đây. Mọi thay đổi/bổ sung crate ngoài bảng này là **thay đổi kiến trúc** → Developer phải **DỪNG LẠI và báo Scrum Master** (không tự ý chạy `cargo add`).

| Crate | Phiên bản | Giấy phép | Crate nội bộ được phép import | Mục đích sử dụng |
|---|---|---|---|---|
| `tokio` | `1.44` | MIT | `mesh`, `meshd`, `mesh-server`, `mesh-datapath`, `mesh-net` | Async runtime, TCP/UDP, UDS (`peer_cred`), Windows Named Pipe, signal, timer, sync |
| `tokio-util` | `0.7` | MIT | `meshd`, `mesh-server`, `mesh-datapath`, `mesh-net` | `CancellationToken`, `TaskTracker` (graceful shutdown ≤ 5 s), framing codec |
| `defguard_boringtun` | `0.6` | BSD-3-Clause | **Chỉ `mesh-datapath`** | State machine WireGuard userspace sans-I/O (`noise::Tunn`) |
| `rustls` | `0.23` | Apache-2.0 OR ISC OR MIT | `mesh-crypto`, `mesh-net`, `mesh-server` | TLS 1.3 client/server, custom `ServerCertVerifier` cho SPKI Pin |
| `tokio-rustls` | `0.26` | MIT OR Apache-2.0 | `mesh-net`, `mesh-server` | Tích hợp `rustls` với stream `tokio` |
| `rustls-pemfile` / `pki-types` (`rustls-pki-types`) | `2.1` / `1.11` | MIT OR Apache-2.0 | `mesh-crypto`, `mesh-server` | Kiểu dữ liệu chứng chỉ X.509 / DER / SPKI |
| `ring` *(hoặc `rustls-rustcrypto`)* | `0.17` | ISC / MIT | `mesh-crypto`, `mesh-datapath` | Provider mật mã cho `rustls` & `defguard_boringtun` |
| `rcgen` | `0.13` | MIT OR Apache-2.0 | **Chỉ `mesh-crypto` / `mesh-server`** | Sinh khóa định danh server & chứng chỉ tự ký cho chế độ IP + SPKI Pin (`US-047`) |
| `instant-acme` | `0.7` | Apache-2.0 | **Chỉ `mesh-server`** | Giao thức ACME thuần Rust (`TLS-ALPN-01` & `DNS-01`, không cần cổng 80) |
| `axum` | `0.8` | MIT | `mesh-server`, `mesh-net` (IPC/Observability) | HTTP/1.1 router cho Control Plane, `/healthz`, `/readyz`, `/metrics` và Admin IPC |
| `hyper` / `hyper-util` | `1.6` / `0.1` | MIT | `mesh-server`, `mesh-net` | Nền tảng HTTP/1.1 cấp thấp cho kết nối UDS / Named Pipe / `ListenerSet` |
| `tokio-tungstenite` | `0.26` | MIT | `mesh-server`, `mesh-datapath`, `mesh-net` | WebSocket binary stream cho Blind Relay (`US-024/025`) và Netmap Stream (`US-009`) |
| `reqwest` *(hoặc `hyper` client)* | `0.12` (`default-features = false`, `rustls-tls-manual-roots-no-provider`) | MIT OR Apache-2.0 | `mesh-net`, `mesh-server` (webhook cảnh báo `US-049`) | HTTP client dùng đúng `rustls` config đã gắn SPKI Pin Verifier |
| `crypto_box` | `0.9` | Apache-2.0 OR MIT | **Chỉ `mesh-crypto`** | NaCl box (X25519 + XSalsa20-Poly1305) cho chứng minh khóa node & xác thực Disco |
| `x25519-dalek` | `2.0` | BSD-3-Clause | **Chỉ `mesh-crypto`** | Khóa công khai/riêng tư Curve25519 |
| `chacha20poly1305` | `0.10` | Apache-2.0 OR MIT | **Chỉ `mesh-crypto`** | AEAD chuẩn |
| `sha2` | `0.10` | Apache-2.0 OR MIT | **Chỉ `mesh-crypto`** | Băm SHA-256 cho Pre-Auth Key, SPKI Pin và kiểm tra toàn vẹn `wintun.dll`/backup |
| `subtle` | `2.6` | BSD-3-Clause | **Chỉ `mesh-crypto`** | So sánh `ConstantTimeEq` chống timing attack (`SEC-03`, `SEC-05`) |
| `zeroize` | `1.8` | Apache-2.0 OR MIT | **`mesh-crypto`**, `mesh-core` | `Zeroize`, `ZeroizeOnDrop` xóa sạch khóa trong RAM ngay khi giải phóng (`SEC-01`) |
| `rand` / `getrandom` | `0.8` / `0.2` | MIT OR Apache-2.0 | `mesh-crypto`, `mesh-core` (`backoff`) | Sinh số ngẫu nhiên mật mã học (`OsRng`) và jitter backoff |
| `redb` | `2.4` | MIT OR Apache-2.0 | **Chỉ `mesh-store`** | Cơ sở dữ liệu ACID MVCC thuần Rust 100% trên VPS (`US-007`, `US-045`) |
| `serde` / `serde_json` | `1.0` | MIT OR Apache-2.0 | Toàn workspace | Tuần tự hóa JSON (Control RPC, Netmap cache, IPC, `status --json`) |
| `toml` | `0.8` | MIT OR Apache-2.0 | `mesh-core`, `meshd`, `mesh-server` | Đọc/ghi cấu hình TOML (`#[serde(deny_unknown_fields)]`) |
| `clap` | `4.5` | MIT OR Apache-2.0 | `mesh`, `meshd`, `mesh-server` | Phân tích dòng lệnh CLI (`derive`, `env`) |
| `thiserror` | `2.0` | MIT OR Apache-2.0 | Toàn workspace | Định nghĩa kiểu lỗi có cấu trúc (`AppError`, domain errors) |
| `tracing` / `tracing-subscriber` / `tracing-appender` | `0.1` / `0.3` / `0.2` | MIT | Toàn workspace | Structured JSON logging (`OPS-01`) & xoay vòng file log (`US-043`) |
| `bytes` | `1.10` | MIT | `mesh-proto`, `mesh-datapath`, `mesh-server` | Quản lý buffer gói mạng zero-copy |
| `crc32fast` | `1.4` | MIT OR Apache-2.0 | `mesh-proto` | Tính `FINGERPRINT` CRC-32 cho gói STUN (RFC 5389) |
| `base64` / `data-encoding` | `0.22` / `2.8` | MIT | `mesh-core`, `mesh-crypto` | Mã hóa hiển thị khóa công khai, fingerprint `sha256:…` và `mpk_…` |
| `socket2` | `0.5` | MIT OR Apache-2.0 | `mesh-sys`, `mesh-net`, `mesh-datapath` | Cấu hình socket cấp thấp (`SO_MARK`, `IP_BOUND_IF`, `IP_UNICAST_IF`, buffer size) |
| `libc` *(Unix)* | `0.2` | MIT OR Apache-2.0 | **Chỉ `mesh-sys`** (`cfg(unix)`) | Hằng số và cấu trúc syscall cho Linux (`/dev/net/tun`, `SO_PEERCRED`) & macOS (`utun`, `LOCAL_PEERCRED`, `PF_ROUTE`) |
| `windows-sys` *(Windows)* | `0.59` | MIT OR Apache-2.0 | **Chỉ `mesh-sys`** (`cfg(windows)`) | API Win32 chính chủ Microsoft (0 macro nặng): `LoadLibraryExW`, Named Pipe SDDL, IP Helper, `IP_UNICAST_IF` |
| `windows-service` *(Windows)* | `0.7` | MIT OR Apache-2.0 | `mesh-net` / `meshd` (`cfg(windows)`) | Tích hợp Windows Service Control Manager & nhận sự kiện `PowerEvent` (`US-036`, `US-052`) |
| `proptest` *(dev-dependencies)* | `1.6` | MIT OR Apache-2.0 | `[dev-dependencies]` | Kiểm thử dựa trên thuộc tính (Property-based testing / fuzzing) cho mọi bộ parser mạng & hosts |
| `tempfile` *(dev-dependencies)* | `3.17` | MIT OR Apache-2.0 | `[dev-dependencies]` | Tạo thư mục/tệp tạm tự dọn trong unit/integration test |

### 7.2. Danh mục Crates & Hành vi **BỊ CẤM** (Cưỡng chế bằng `deny.toml` & `clippy.toml`)

| Nhóm | Bị cấm tuyệt đối | Lý do & Giải pháp thay thế | Cơ chế cưỡng chế |
|---|---|---|---|
| **Giấy phép lây nhiễm** | **`AGPL-3.0`**, **`GPL-2.0`**, **`GPL-3.0`**, **`LGPL-*`**, **`SSPL-1.0`**, **`MPL-2.0`** (như `gotatun`, mã server NetBird) | Vi phạm ràng buộc `C5` / `R-15` | `cargo deny check licenses` (`deny.toml`) |
| **Thư viện C ẩn / OpenSSL** | `openssl`, `openssl-sys`, `native-tls`, `libsqlite3-sys`, `rusqlite`, `libsodium-sys`, `curl-sys` | Phá vỡ chiến lược Pure-Rust / Zero-C, gây lỗi cross-compile và tăng bề mặt lỗ hổng C | `deny.toml` (`[bans] deny`) |
| **Lỗi lỏng lẻo** | `anyhow`, `eyre` trong các crate thư viện (`mesh-core`, `mesh-crypto`, `mesh-proto`, `mesh-datapath`, `mesh-net`, `mesh-store`, `mesh-sys`) | Làm mất kiểu lỗi (`ErrorKind`), khiến tầng biên không phân biệt được lỗi cần retry (`Unavailable`), `PinMismatch` hay `Unauthenticated` → **bắt buộc dùng `thiserror` + `AppError`** | `deny.toml` + Clippy |
| **Trùng chức năng Async/HTTP/Log** | `async-std`, `smol`, `actix-web`, `warp`, `rocket`, `ureq`, `surf`, `log4rs`, `env_logger`, `fern`, `slog` | Tránh mỗi Developer cài một framework khác nhau; chỉ dùng `tokio` + `axum` + `tracing` | `deny.toml` (`[bans] deny`) |
| **DB nhúng không ổn định** | `sled`, `rocksdb`, `leveldb`, `diesel`, `sea-orm`, `sqlx` | Chỉ dùng `redb` | `deny.toml` (`[bans] deny`) |
| **Gây crash tiến trình** | `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, `unimplemented!()`, `dbg!()`, `println!()`, `eprintln!()` trong code production (trừ `crates/mesh` CLI in kết quả qua writer chuẩn) | VPN daemon chạy 24/7 dưới quyền `root`/`SYSTEM` không được phép panic khi gặp gói mạng dị dạng | `[workspace.lints.clippy]` (`unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`, `todo = "deny"`, `dbg_macro = "deny"`) |
| **Mã `unsafe` bừa bãi** | Từ khóa `unsafe` ở bất kỳ đâu ngoài `crates/mesh-sys` | Bảo đảm an toàn bộ nhớ tuyệt đối cho toàn bộ giao thức & nghiệp vụ | `[workspace.lints.rust] unsafe_code = "forbid"` |

---

## 8. Ngân sách Tài nguyên & Tinh chỉnh Runtime (Đáp ứng mục tiêu của Người dùng)

Để hiện thực hóa mục tiêu của người dùng (**RAM chạy nền ~4–10 MB trên client, ~8–18 MB trên VPS; binary ~3–6 MB**), kiến trúc áp dụng các kỹ thuật cấp phát tĩnh sau:

1. **Giới hạn Worker Threads & Stack của Tokio**:
   - Trên client (`meshd`): dùng `tokio::runtime::Builder::new_multi_thread().worker_threads(2).max_blocking_threads(2).thread_stack_size(512 * 1024)`.
   - Trên VPS (`mesh-server`): dùng `worker_threads(2)` (khớp VPS 1–2 vCPU).
2. **Pre-allocated Packet Buffers (Zero Heap Allocation trên đường nóng)**:
   - Vòng lặp đọc/ghi UDP (`MagicSocket`) và TUN (`TunDevice`) dùng mảng cố định cấp phát sẵn `[u8; 2048]` tái sử dụng cho `defguard_boringtun::noise::Tunn::encapsulate`/`decapsulate`, **không cấp phát `Vec<u8>` mới cho mỗi gói tin**.
3. **Bounded Queues ở mọi nơi (`US-025 AC6`)**:
   - Trong Blind Relay, mỗi node đích có đúng 1 kênh `tokio::sync::mpsc::channel(256)` cố định; gửi gói dùng `try_send()` (đầy thì drop-tail ngay lập tức và tăng counter `mesh_relay_dropped_total`, **tuyệt đối không `.send().await`** gây nghẽn dây chuyền Head-of-Line blocking hoặc phình RAM).
4. **Không bật `last_seen` broadcast (`US-009 AC1`)**:
   - `mesh-server` chỉ giữ thời điểm heartbeat mới nhất trong RAM và chỉ tăng `netmap_version` + đẩy snapshot khi có thay đổi thực sự về cấu trúc hoặc trạng thái `online ↔ offline` (có debounce), giữ CPU VPS lúc rảnh **< 1%** và băng thông nền **≤ 1 KB/s** (`PERF-02`, `PERF-10`).

---

## 9. Lịch sử sửa đổi

| Phiên bản | Ngày | Nội dung |
|---|---|---|
| 1.0 | 2026-11-12 | Bản đề xuất ban đầu (Go 1.27) |
| **2.0** | **2026-11-12** | **Ghi đè toàn bộ sang Rust `1.94.1` Stack theo quyết định của Người dùng (`"Tôi chọn 2. Đổi sang Rust"`)**: kiến trúc Cargo Workspace 3 binaries + 7 crates, `defguard_boringtun` sans-I/O trên 1 UDP socket, `redb` ACID thuần Rust, `rustls` + SPKI Pin, `ZeroizeOnDrop` xóa khóa trong RAM, cô lập `unsafe` vào duy nhất `mesh-sys`, và cưỡng chế bằng `rustfmt` + `clippy` + `cargo-deny` |
