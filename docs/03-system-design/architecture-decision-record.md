# Architecture Decision Records (ADR) — Mesh VPN

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-12 |
| Phiên bản | **1.0** — trình Gate 2 |
| Trạng thái chung | **Proposed → chờ Gate 2** (mọi ADR dưới đây là *Accepted-pending-Gate-2*; ADR bị người dùng bác ở Gate sẽ chuyển `Rejected` kèm lý do) |
| Phạm vi | Quyết định **công nghệ**. Giao thức chi tiết (schema bản tin, DB schema, C4) thuộc `agile-architect`; các ADR này là **ràng buộc đầu vào** cho Architect |
| Liên kết | [tech-stack-decision.md](./tech-stack-decision.md) · [coding-standards.md](./coding-standards.md) |
| Đầu vào | `production-readiness-requirements.md` v1.2, `product-backlog.md` v1.2, `project-charter.md` v1.2, quyết định Gate 1 (D1–D4) |

**Định dạng ADR:** Bối cảnh (Context) → Phương án (Options) → Quyết định (Decision) → Hệ quả (Consequences, gồm rủi ro/chi phí). Mã `[V]` = đã **kiểm chứng thực nghiệm** trong phiên này (xem [tech-stack-decision.md §14](./tech-stack-decision.md)); `[N]` = dựa trên tài liệu/nguồn, chưa đo.

## Mục lục

| ADR | Tiêu đề | Yêu cầu chính |
|---|---|---|
| [ADR-001](#adr-001) | Ngôn ngữ **Go 1.27** + chiến lược cross-compile `CGO_ENABLED=0` ra 4 đích | G1, G4, C5, GNFR-12 |
| [ADR-002](#adr-002) | WireGuard userspace (`wireguard-go`) + `conn.Bind` tùy biến: **một UDP socket chung** cho STUN/Disco/WireGuard | REL-05/09/10, SEC-11, US-019/021 |
| [ADR-003](#adr-003) | Giao thức Control & xác thực: TLS 1.3 + challenge–response NaCl box + Pre-Auth Key hash + Disco Auth | SEC-02/03/05, REL-02, US-003/021 |
| [ADR-004](#adr-004) | Blind Relay trên WebSocket/TLS (một cổng TCP) & chống Head-of-Line blocking | SEC-07, REL-06, US-024/025 |
| [ADR-005](#adr-005) | Lưu trữ nhúng SQLite thuần Go (`modernc.org/sqlite`, WAL) & backup nguyên tử | REL-11/12, US-007/045 |
| [ADR-006](#adr-006) | Kênh Admin IPC cục bộ kiểm chứng đặc quyền OS (`SEC-14`) tách khỏi listener quan sát | SEC-14, OPS-05/06/08, PLAT-01/06 |
| [ADR-007](#adr-007) | Tích hợp nền tảng: macOS `utun`+`launchd` (không cần Apple Developer $99), Windows `Wintun`+Service, Linux TUN+`systemd`; chống routing loop & dọn dẹp bằng sổ cái | REL-08/09, PLAT-01..06 |
| [ADR-008](#adr-008) | Vòng đời TLS: IP-Pinning SPKI / Standalone ACME (`TLS-ALPN-01`, `DNS-01`) / Reverse Proxy | SEC-04, SEC-05, US-047 |
| [ADR-009](#adr-009) | Cổng & địa chỉ cấu hình được; di chuyển cấu hình không mất danh tính (`SEC-15`) — lắng nghe song song, phân phối qua Netmap | GNFR-11, SEC-06/15, US-074 |
| [ADR-010](#adr-010) | Quan sát & kiểu bí mật: `log/slog` + `Redacted Secret Types` + metrics `VictoriaMetrics/metrics` | SEC-01, OPS-01/06, GNFR-02 |
| [ADR-011](#adr-011) | Phân phối & toàn vẹn bản phát hành (4 binary, `SHA256SUMS` có chữ ký, `wintun.dll` đúng giấy phép, không Gatekeeper-bypass) | PLAT-06(1), C5, R-11 |

---

<a id="adr-001"></a>
## ADR-001 — Ngôn ngữ Go 1.27 và chiến lược cross-compile không CGO

**Trạng thái:** Accepted-pending-Gate-2 · **Ngày:** 2026-11-12 · **Người quyết:** `agile-tech-lead`

### Context
- Phải phát hành **4 đích**: `windows/amd64`, `darwin/arm64`, `darwin/amd64`, `linux/amd64`; **máy dev là Windows** (`rustc 1.94.1`/`cargo` có, `go` chưa cài) và CI GitHub Actions. Không được đòi Xcode/macOS SDK hay C toolchain phức tạp trên máy dev (kể cả SQLite nhúng).
- Hệ thống cần: userspace WireGuard + TUN trên 3 OS (Wintun / `utun` / `/dev/net/tun`), mạng đồng thời cao nhưng quy mô nhỏ (≤ 20 node), daemon chạy 24/7 với RAM agent ≤ 50 MB (PERF-09), control ≤ 64 MB (PERF-01), giấy phép tránh AGPL/GPL (C5).
- Đội gồm **nhiều Subagent lập trình song song** → cần ngôn ngữ ít cách viết, build nhanh, lỗi biên dịch dễ hiểu, công cụ chuẩn hóa mạnh.
- Mục tiêu G3 (học bản chất) → có mã tham chiếu mở đọc được cho `magicsock`/`netmon`/`netns`/DERP (Tailscale, BSD-3).

### Options
| # | Phương án | Cross-compile từ Windows (4 đích) | Ghi chú trung thực |
|---|---|---|---|
| A | **Go** + `wireguard-go` + `modernc.org/sqlite` + `CGO_ENABLED=0` | **Một lệnh/đích, không C toolchain** `[V]`. Linker Go tự ký ad-hoc `darwin/arm64` (PLAT-06) | GC (cần `GOMEMLIMIT`); race detector cần cgo trên Windows (§Consequences) |
| B | **Rust** (`boringtun`/`gotatun`, `tokio`, `rustls`, `wintun`, `rusqlite`/`redb`) | **Khả thi nhưng mong manh:** `rustup target add aarch64-apple-darwin` chỉ cấp `std`; **linker + libSystem/SDK không có** trên Windows ⇒ cần `cargo-zigbuild` + Zig. `ring`/`aws-lc-rs` (rustls) và `rusqlite` (bundled) **biên dịch mã C** ⇒ phải đi qua `zig cc`. Dùng framework macOS (Security/SystemConfiguration/IOKit) cần SDK Apple — **giấy phép Xcode/SDK hạn chế dùng ngoài phần cứng Apple** `[N]`. Đường tránh: `redb` (thuần Rust) + `rustls` backend thuần Rust (chưa chín bằng) | An toàn bộ nhớ hơn Go; throughput tốt; nhưng hệ sinh thái *WG userspace + magicsock-lite + netmon* ít mã tham chiếu hơn; `gotatun` là **MPL-2.0** và còn mới (fork 2026) `[N]` |
| C | **Lai:** data plane Rust (FFI) + control Go | Hỏng bất biến CGO ⇒ **tệ nhất** cho cross-compile; thêm ranh giới FFI (chính Mullvad bỏ vì lỗi FFI) `[N]` | Loại |
| D | .NET NativeAOT / Node SEA | NativeAOT **không cross-OS** từ Windows; SEA nặng, không có WG/TUN userspace chín | Loại |

Chấm điểm có trọng số (1–5; trọng số tổng 100; *đánh giá chủ quan, không phải số đo*): xem [tech-stack-decision.md §3](./tech-stack-decision.md) → **Go 92 / Rust 66**.

### Decision
1. **Go 1.27.4** (đã kiểm: `go1.27.4` là bản stable mới nhất trên `go.dev/dl`, 2026-11-10) cho **toàn bộ** mã: `mesh-server`, `meshd`, `mesh`.
2. `go.mod`: `go 1.27.4`. Nâng cấp **bản vá 1.27.x** theo đợt (≤ 7 ngày sau bản vá bảo mật); nâng **minor** chỉ qua ADR.
3. **`CGO_ENABLED=0` là bất biến** (CI export `CGO_ENABLED=0` cho mọi `go build/vet/test` trừ bước race). SQLite = `modernc.org/sqlite` (thuần Go). Thư viện kéo cgo bị loại (depguard + `scripts/check.*`).
4. Build release: `go build -trimpath -buildvcs=true -ldflags "-s -w -X …buildinfo.Version=…"` cho 4 đích; `GOFLAGS=-mod=readonly`.
5. macOS: phát hành **2 binary native** (`darwin/arm64`, `darwin/amd64`), **không** `lipo`/Universal (cần công cụ Apple); script cài chọn theo `uname -m` + kiểm Rosetta (`sysctl -n hw.optional.arm64`).
6. Race detector chạy ở **Linux** (CI/WSL/Docker); `go test` thường chạy native trên 3 OS (xem coding-standards §10).

### Consequences
- (+) Máy dev Windows build đủ 4 đích mà không cài gì ngoài Go `[V]`; macOS arm64 binary chạy được nhờ chữ ký ad-hoc của linker.
- (+) Tái dùng trực tiếp `wireguard-go`, Wintun binding, `x/sys` (utun, `IP_BOUND_IF`, `SO_PEERCRED`, `LOCAL_PEERCRED`, SCM).
- (−) `CGO_ENABLED=0` trên macOS: resolver DNS là **pure-Go** (không qua `mDNSResponder`) — chấp nhận vì chế độ chính kết nối **bằng IP**; chế độ domain dùng pure-Go resolver `[N]`.
- (−) **Không gọi được IOKit (sleep/wake notification) không cgo.** Giảm thiểu: PF_ROUTE routing socket + phát hiện **nhảy đồng hồ** (PLAT-05 đã cho phép làm dự phòng). Nếu đo thực tế (PERF-07 trên MacBook) không đạt ⇒ ADR bổ sung xem `ebitengine/purego` (xin duyệt Gate; hiện **không** thuộc danh mục).
- (−) GC: đặt `GOMEMLIMIT` mềm (server 96 MiB, agent 40 MiB — giá trị khởi đầu, chỉnh sau US-058).
- (−) **Race detector cần cgo + trình biên dịch C ở mọi OS** (đã xác nhận `go: -race requires cgo` `[V]`) ⇒ dev Windows phải chạy qua Docker/WSL; bù bằng CI Linux bắt buộc.
- (−) Phụ thuộc Go toolchain cho dev: bootstrap bằng `scripts/bootstrap-toolchain.ps1` (tải zip, **kiểm SHA-256**, giải nén user-level, không cần admin).
- Quay lại phương án B nếu: PERF-01/09 không thể đạt với Go sau tối ưu, **và** có runner macOS + thời gian dựng Zig/SDK — cần ADR mới.

---

<a id="adr-002"></a>
## ADR-002 — WireGuard userspace + `conn.Bind` tùy biến, một UDP socket chung

**Trạng thái:** Accepted-pending-Gate-2

### Context
Data plane = giao thức WireGuard (giả định A-04), userspace trên Windows/macOS/Linux (PERF-04 chấp nhận userspace). NAT traversal cần STUN **từ chính socket** mà WireGuard dùng (để mapping NAT giống nhau — US-019), disco ping/pong qua cùng cổng, và khả năng **gửi gói WireGuard qua relay** khi direct chưa có (REL-05, US-026). SEC-02 cấm tự viết mật mã ⇒ không tự cài Noise/WireGuard.

### Options
| # | Phương án | Đánh giá |
|---|---|---|
| A | `golang.zx2c4.com/wireguard` (wireguard-go **upstream**, MIT) + **tự hiện thực `conn.Bind`** | Giao diện `conn.Bind` (Open/Close/SetMark/Send/ParseEndpoint/BatchSize) tồn tại đúng để thay lớp socket ⇒ ta demux STUN/disco/WG và route qua relay. Upstream, MIT, được dùng rộng. **Chọn** |
| B | Fork `tailscale/wireguard-go` | Có hook cho magicsock; nhưng gắn chặt Tailscale, thay đổi theo nhu cầu họ; ràng buộc bảo trì. Dự phòng |
| C | Tự cài Noise_IKpsk2 từ `flynn/noise` | **Vi phạm SEC-02/GNFR-01** (tự lắp giao thức) — loại |
| D | Kernel WireGuard (Linux), WireGuardNT (Win) | macOS không có; P2 (US-071) |
| E | `boringtun`/`gotatun` qua FFI | Vi phạm ADR-001 (Rust/CGO) |

### Decision
1. Dùng `golang.zx2c4.com/wireguard` **ghim bằng pseudo-version** (`v0.0.0-20261024220952-b3bc704ef0ee` tại thời điểm quyết định) — nâng cấp chỉ qua PR `build(deps)` kèm test netmap/relay.
2. Gói `internal/datapath` hiện thực **`conn.Bind` riêng ("magicbind")**: sở hữu socket UDP của agent (dual-stack; cổng cục bộ **lưu bền** — US-019), **demux theo byte đầu**: (i) STUN (magic cookie `0x2112A442` tại byte 4–8, RFC 5389/8489), (ii) Disco (tiền tố magic riêng 6 byte do Architect định nghĩa), (iii) còn lại ⇒ gói WireGuard trả về `ReceiveFunc`. `Send` chọn đường theo trạng thái peer: **direct `netip.AddrPort`** hay **relay** (Endpoint trừu tượng mang `PublicKey` đích).
3. `Bind.SetMark`/ràng interface thực hiện chống routing loop (ADR-007).
4. **STUN client** gửi từ chính socket này; **STUN server** (VPS) lắng nghe UDP ở cổng cấu hình được, **cùng binary `mesh-server`** (ADR-009).
5. Thiết lập thiết bị WireGuard qua UAPI `IpcSet`; **`AllowedIPs` mỗi peer = đúng `/32`** (SEC-11); áp netmap theo **diff** (thêm/sửa/xóa peer — REL-03/US-010).
6. `device.Logger` thay bằng adapter `slog` (mức ≥ `error`); chuỗi UAPI **không bao giờ** được log (chứa khóa).
7. MTU mặc định **1280**, cấu hình được (REL-10).

### Consequences
- (+) Không tự viết mật mã WireGuard; tái dùng mã đã được kiểm định; relay/disco tích hợp tự nhiên.
- (−) **Phải tự hiện thực magicbind** (độ phức tạp cao, 8 SP hole punching): rủi ro R-16. Giảm thiểu: lát cắt "Walking Skeleton relay-only trước, direct sau" (backlog 15.2), tham khảo thiết kế `magicsock` của Tailscale (BSD-3, **không import**, chỉ đọc).
- (−) `wireguard-go` upstream **không có tag phiên bản** ⇒ ghim commit + `go.sum`; chúng ta chịu trách nhiệm theo dõi bản vá (đăng ký watch repo; `govulncheck` trong CI).
- (−) Hiệu năng userspace thấp hơn kernel: chấp nhận (PERF-04 ≥ 70% tới 300 Mbps); `[N]` chưa đo — QA đo ở US-058.
- Quay lại phương án B nếu cần API hook mà upstream không có.

---

<a id="adr-003"></a>
## ADR-003 — Giao thức Control & xác thực khóa

**Trạng thái:** Accepted-pending-Gate-2

### Context
SEC-02: control dùng TLS ≥ 1.2 (khuyến nghị 1.3) + chứng minh sở hữu khóa node bằng cấu trúc chuẩn (NaCl box hoặc Noise IK) với challenge/nonce ngẫu nhiên **từ server**, không phụ thuộc đồng hồ client (US-003 AC1/AC5). **Curve25519 chỉ làm DH, không ký được** ⇒ "chứng minh sở hữu" phải dựa vào DH. Pre-Auth Key (SEC-03) ≥ 128 bit, one-time, TTL, chỉ lưu hash. Disco cần xác thực + chống phát lại (US-021). Hai chế độ triển khai: **TLS end-to-end** (Standalone/IP+Pin) và **sau Reverse Proxy** (TLS kết thúc ở proxy).

### Options
| # | Phương án | Đánh giá |
|---|---|---|
| A | **TLS 1.3 (stdlib) + challenge–response bằng NaCl box** (`x/crypto/nacl/box`) + **channel binding** bằng TLS exporter | Dùng primitive chuẩn, mã nguồn ngắn, chung họ với disco; chạy qua reverse proxy. **Chọn** |
| B | Noise IK qua `flynn/noise` (kiểu `ts2021`) | Mạnh nhưng thêm thư viện + thêm giao thức kiểu "tự lắp"; không cần cho 20 node |
| C | Ký chữ ký Ed25519 trên challenge | Cần **khóa ký thứ hai** (node key là Curve25519/WireGuard) ⇒ thêm bề mặt quản lý khóa; chỉ đáng khi làm US-069 |
| D | mTLS với chứng chỉ client | Gánh nặng PKI; không chạy sau Reverse Proxy kết thúc TLS |

### Decision
1. **Kênh:** HTTPS/1.1 (JSON) cho RPC + WebSocket cho luồng netmap — chạy trên **cùng một cổng TCP** với relay (ADR-004). TLS **tối thiểu 1.3**; **tắt HTTP/2** trên listener này (WebSocket cần HTTP/1.1; giảm bề mặt; tương thích reverse proxy).
2. **Chứng minh khóa node (hiện thực trong `internal/secure`):**
   1. client → server: `hello{node_pub, protocol_version, agent_version, os, arch}`;
   2. server → client: `challenge{server_eph_pub (X25519 mới mỗi phiên), nonce[32] (crypto/rand), session_id}`; server lưu (nonce, eph_priv) với TTL ngắn, **dùng một lần**;
   3. client → server: `proof = box.Seal( nonce ‖ session_id ‖ tls_exporter? ‖ node_pub ; box_nonce[24] random ; server_eph_pub ; node_priv )`;
   4. server: `box.Open(…; node_pub ; server_eph_priv)` + so khớp nội dung. Chỉ người nắm `node_priv` mới tạo được hộp hợp lệ (DH(node_priv, eph_pub)).
   - `tls_exporter` = `ExportKeyingMaterial("mesh-control-auth", nil, 32)` — **ràng buộc** bằng chứng vào phiên TLS **khi TLS kết thúc ở server** (IP+Pin/Standalone). Ở chế độ Reverse Proxy không có exporter đầu-cuối ⇒ bỏ trường này; nonce + ephemeral vẫn chống phát lại (đã ghi nhận trong mô hình đe dọa: proxy là đối tượng tin cậy).
3. **Pre-Auth Key:** `mpk_` + 32 byte `crypto/rand` mã hóa base32 (≥ 256 bit); DB lưu **SHA-256** (`PreAuthKeyHash`), tra theo digest, so sánh `subtle.ConstantTimeCompare`; one-time mặc định, TTL bắt buộc, thu hồi được. Đăng ký **idempotent theo `node_pub`** (REL-02): `UNIQUE(public_key)`, `UNIQUE(overlay_ip)`, cấp IP + tạo node trong **1 transaction**.
4. **Disco:** `disco_key` Curve25519 **riêng** (không dùng node key), công bố qua netmap; bản tin = `box.Seal` (24 byte nonce ngẫu nhiên) với `tx_id` 96 bit ngẫu nhiên; bên gửi giữ bảng `tx_id` đang chờ có TTL; Pong chỉ hợp lệ nếu khớp `tx_id` + nguồn khóa (chống phát lại/giả mạo — US-021).
5. Lỗi xác thực trả **một thông điệp công khai duy nhất** (SEC-05); rate-limit theo IP TCP (hoặc theo `trusted_proxies` — ADR-008).
6. Toàn bộ nằm sau API `internal/secure`; **nơi khác cấm import primitive** (depguard).

### Consequences
- (+) Không thêm thư viện mật mã ngoài `x/crypto` + stdlib; xác thực không phụ thuộc đồng hồ.
- (+) Cùng một họ (NaCl box) cho control-proof và disco ⇒ ít code, dễ kiểm.
- (−) NaCl box = XSalsa20-Poly1305 (không có forward secrecy cho riêng bản tin proof; chấp nhận vì chỉ chứng minh sở hữu + TLS 1.3 đã có FS cho kênh).
- (−) Chế độ Reverse Proxy không có channel binding ⇒ yếu hơn đôi chút; ghi trong Runbook.
- Cần **review độc lập** ADR-003 bởi `agile-critic`/Codex trước Gate (đây là mã bảo mật trọng yếu).

---

<a id="adr-004"></a>
## ADR-004 — Blind Relay trên WebSocket/TLS & chống Head-of-Line blocking

**Trạng thái:** Accepted-pending-Gate-2

### Context
REL-06: relay TCP là đường cuối; SEC-07: chỉ node hợp lệ, giới hạn băng thông, ngắt ≤ 5 s khi thu hồi. Phải chạy **trên cùng cổng TCP** với control và **qua Reverse Proxy** sẵn có (SEC-06(2)). Rủi ro R-08: một đích chậm làm nghẽn dây chuyền (HoL).

### Options
| # | Phương án | Đánh giá |
|---|---|---|
| A | **WebSocket binary frame trên TLS** (`github.com/coder/websocket`) | Qua được Nginx/Caddy (HTTP Upgrade); ping/pong + deadline có sẵn; NetBird cũng dùng WSS/443 [T26]. **Chọn** |
| B | HTTP Upgrade tự đóng khung (kiểu DERP) | Không thêm thư viện, nhưng tự viết framing/keepalive; khó qua một số proxy |
| C | QUIC/UDP (`quic-go`) | UDP có thể bị chặn (đúng tình huống relay phải giải quyết); P2 (US-065) |
| D | gRPC streaming | HTTP/2 + protobuf + codegen; xung đột reverse proxy/tắt h2 |

### Decision
1. `github.com/coder/websocket`; **tắt nén** (`CompressionDisabled` — payload đã mã hóa), `SetReadLimit` cố định theo MTU + header.
2. Frame relay: `dst_pubkey[32] ‖ payload` (client→server); server **gắn `src_pubkey` đã xác thực theo kết nối** rồi chuyển tiếp (Architect chốt chi tiết). Định tuyến theo **public key**, đích không tồn tại/không hợp lệ ⇒ drop.
3. **Chống HoL:** mỗi kết nối đích có **một goroutine ghi** + **hàng đợi có trần** (kích thước do Architect, khởi đầu 256 gói); gửi vào hàng đợi **không chặn, drop-tail** khi đầy (đếm metric `mesh_relay_dropped_total`); **write deadline** ngắn — quá hạn ⇒ đóng kết nối đích (không kéo các luồng khác); **không có khóa toàn cục** trên đường chuyển tiếp.
4. **Giới hạn băng thông:** token bucket mỗi node (mặc định 20 Mbps) + trần tổng (`golang.org/x/time/rate`).
5. Thu hồi node ⇒ đóng kết nối relay ≤ 5 s (SEC-07b) qua kênh hủy per-node (`context`).
6. **Heartbeat** WebSocket ping ≤ 60 s (GNFR-03); client dùng backoff+jitter (REL-04).

### Consequences
- (+) Một cổng, một TLS, chạy sau proxy; code nhỏ.
- (−) **TCP-over-TCP:** WireGuard (UDP) bọc trong TCP có thể gặp tail-latency khi mất gói; chấp nhận vì relay chỉ là đường cuối và luôn nâng cấp lên direct khi thành công (REL-05).
- (−) HoL ở tầng TCP **không thể loại bỏ** hoàn toàn; ADR chỉ cô lập ảnh hưởng theo từng đích. Ghi vào Runbook.
- (−) Phải test với Nginx/Caddy buffering (cần `proxy_buffering off`/upgrade headers) — task cho `agile-devops`/QA.

---

<a id="adr-005"></a>
## ADR-005 — Lưu trữ nhúng SQLite thuần Go & backup nguyên tử

**Trạng thái:** Accepted-pending-Gate-2

### Context
REL-11: ACID, cấp IP + tạo node trong 1 transaction, migration có version, `integrity_check` khi khởi động. REL-12/US-045: backup nóng nhất quán (không khóa ghi > 1 s), checksum, giữ 7 bản, restore đã diễn tập; backup **phải gồm khóa định danh server** (Pin). Không CGO (ADR-001). RAM < 64 MB.

### Options
| # | Phương án | Đánh giá |
|---|---|---|
| A | **`modernc.org/sqlite`** (SQLite chuyển mã sang Go, BSD-3) + `database/sql` | `UNIQUE`, transaction, WAL, `PRAGMA integrity_check`, `VACUUM INTO`; **CGO-free `[V]` 4 đích**. **Chọn** |
| B | `mattn/go-sqlite3` | Cần CGO + C toolchain ⇒ **vi phạm ADR-001** |
| C | `go.etcd.io/bbolt` | Thuần Go, ACID, snapshot `Tx.WriteTo`; nhưng không SQL ⇒ tự cài ràng buộc UNIQUE/index/migration/audit query ⇒ nhiều mã dễ lỗi |
| D | PostgreSQL/MySQL | Vượt ngân sách RAM 1–2 GB VPS dùng chung |

### Decision
1. `modernc.org/sqlite` + `database/sql`; **SQL thuần có tham số, không ORM/query-builder** (đồng nhất giữa nhiều dev, kiểm soát được). Truy cập qua `internal/store` với repository có kiểu.
2. Pragma khởi tạo (mỗi kết nối): `journal_mode=WAL`, `synchronous=FULL` (độ bền > tốc độ; ghi ít), `foreign_keys=ON`, `busy_timeout=5000`, `trusted_schema=OFF`. **Một kết nối ghi** (`SetMaxOpenConns` cho writer pool = 1) + pool đọc riêng.
3. **Migration:** thư mục `migrations/NNNN_*.sql` nhúng bằng `embed`; bảng `schema_migrations`; mỗi migration trong 1 transaction; **tự viết migrator nhỏ** (không thêm `goose`/`migrate`) để móc **backup trước migration** và `integrity_check`.
4. **Backup nguyên tử** (`backup now`, lịch hằng ngày, trước migration): `VACUUM INTO '<tmp>'` (đọc snapshot trong WAL, không chặn ghi lâu) → `fsync` → mở bản sao **read-only** chạy `PRAGMA integrity_check` → ghi `*.sha256` → `rename` nguyên tử sang tên cuối → `chmod 0600` (thư mục `0700`); giữ N=7. Restore từ chối nếu sai checksum/`integrity_check` (US-045 AC4).
5. **Khuyến nghị cho Architect (schema thuộc Architect):** lưu **khóa định danh server** (khóa riêng ECDSA P-256 của TLS Pin) **trong chính DB** (bảng `server_identity`) để backup nguyên tử luôn kèm khóa (REL-12, US-045 AC2/AC5) — DB là tệp `0600` cùng ranh giới tin cậy với tệp khóa. Pre-auth key **chỉ lưu hash**.
6. Audit log append-only: bảng `audit_events` + trigger chặn `UPDATE/DELETE`; cơ chế "thu hồi trong RAM khi đầy đĩa" (US-013 AC4) do Architect thiết kế.

### Consequences
- (+) Cross-compile sạch; sao lưu = một tệp; migration/constraint tận dụng SQL.
- (−) `modernc.org/sqlite` chậm hơn C-SQLite (cỡ 1.5–3×, `[N]`) và tăng cỡ binary (~vài chục MB) — không đáng kể với ≤ 20 node; **đo PERF-01** ở US-058.
- (−) Single-writer ⇒ không HA (chấp nhận — REL-15 là P2).
- (−) Chất lượng bản dịch C→Go: theo dõi issue tracker; kiểm thử chéo bằng `integrity_check` trong CI + khôi phục diễn tập.
- Phương án B (bbolt) là dự phòng nếu `modernc.org/sqlite` lộ vấn đề toàn vẹn.

---

<a id="adr-006"></a>
## ADR-006 — Kênh Admin IPC cục bộ kiểm chứng đặc quyền OS (`SEC-14`)

**Trạng thái:** Accepted-pending-Gate-2

### Context
BLK-01: kênh Admin **không** được ở TCP (kể cả loopback), IP overlay hay IP public; phải là kênh cục bộ mà **OS kiểm chứng được người gọi** (Unix Domain Socket + peer credential, hoặc thao tác trực tiếp dưới quyền quản trị qua SSH). Tương tự trên client: CLI ↔ `meshd` (PLAT-01, PLAT-06(3)). Kênh quan sát `/healthz` `/readyz` `/metrics` là listener **riêng**, chỉ-đọc (OPS-05/06).

### Options
| # | Phương án | Đánh giá |
|---|---|---|
| A | **HTTP/1.1 + JSON trên Unix Domain Socket** (Linux/macOS) và **named pipe + SDDL** (Windows, `go-winio`), peer credential kiểm trong `ConnContext` | Dùng lại `net/http`; kiểm chứng đặc quyền bằng OS. **Chọn** |
| B | gRPC trên UDS | Thêm protobuf/codegen; không cần |
| C | TCP loopback + token tĩnh | **BỊ CẤM** (SEC-14(2b)) |
| D | Chỉ CLI mở thẳng SQLite | Bỏ qua server đang chạy; race khóa DB; không có audit chuẩn |

### Decision
1. **Server (Linux):** socket `/run/<brand>/admin.sock` thuộc `root` hoặc user dịch vụ, nhóm quản trị riêng, `0600`/`0660`, thư mục cha `0750` không user khác ghi. Trong `http.Server.ConnContext`, lấy `*net.UnixConn` → `SyscallConn().Control` → `unix.GetsockoptUcred(fd, SOL_SOCKET, SO_PEERCRED)`; chỉ chấp nhận `uid==0`, `uid==service`, hoặc `gid∈admin group`; nhét `Peer{UID,GID,PID}` vào `context` để **audit (SEC-09)**.
2. **Agent macOS:** socket trong thư mục root (`/var/run/<brand>/`), `0600 root` hoặc `0660 root:admin`; peer cred bằng `unix.GetsockoptXucred(fd, SOL_LOCAL, LOCAL_PEERCRED)`; thao tác thay đổi mạng (`up/down/cleanup`, `set --server/--pin`) chỉ cho `root` hoặc nhóm `admin`; thao tác chỉ-đọc (`status`, `ping`) do Architect chốt (khuyến nghị: cho phép mọi user local, **không** lộ secret).
3. **Agent Windows:** named pipe tạo bằng `github.com/Microsoft/go-winio` với **SDDL** cho tác vụ thay đổi: `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (SYSTEM + Administrators); pipe chỉ-đọc (nếu có) tách riêng ACL.
4. **Listener quan sát** (`/healthz`,`/readyz`,`/metrics`): `http.Server` **riêng**, bind `127.0.0.1`/overlay theo cấu hình, **chỉ nhận GET**, không route nào thay đổi trạng thái (test: lập danh sách route + so với allowlist chỉ-đọc).
5. **Cấm kiểm tra tĩnh:** `net.Listen("tcp"…)` chỉ xuất hiện trong `internal/httpx` và gói listener công khai/quan sát; `scripts/check.*` fail nếu có nơi khác.
6. CLI `mesh` tự phân biệt: lệnh quản trị server (`mesh admin …` / `mesh preauthkey …`) nối vào socket server; lệnh client (`mesh up/status/ping`) nối vào socket agent. Cả hai cùng hạ tầng `internal/ipc`.

### Consequences
- (+) Quyền do **OS** quyết định, không có bí mật tĩnh để lộ; SSRF/`www-data`/container không gọi được.
- (−) Windows không có peer credential kiểu UDS ⇒ phụ thuộc đúng ACL của pipe; phải test (`privileged`) rằng user thường bị từ chối.
- (−) Hai nền IPC (UDS & named pipe) ⇒ trừu tượng `net.Listener` + `PeerCred` interface theo OS (coding-standards §2.2).
- (−) Container trong lab: UDS bind-mount cần `uid` khớp; kiểm thử riêng.

---

<a id="adr-007"></a>
## ADR-007 — Tích hợp nền tảng, chống routing loop, dọn dẹp bằng sổ cái

**Trạng thái:** Accepted-pending-Gate-2

### Context
G4: **không làm hỏng mạng máy thật**. Yêu cầu: macOS `utun` + `launchd` **không cần** Apple Developer ($99), Application Firewall/`pf` an toàn, `utunN` do kernel cấp động (PLAT-06); Windows `Wintun` + Service + firewall profile (PLAT-01/02); Linux `/dev/net/tun` + `systemd` + `CAP_NET_ADMIN` tối thiểu (PLAT-03a); REL-08 dọn tàn dư lúc khởi động; REL-09 chống routing loop; PLAT-05 sự kiện mạng/sleep-wake.

### Options & Decision (theo nền tảng)

| Chủ đề | Quyết định | Phương án bị loại |
|---|---|---|
| **TUN** | `golang.zx2c4.com/wireguard/tun` (`CreateTUN`): Linux `/dev/net/tun`; macOS kernel control `com.apple.net.utun_control` (`utun`, kernel cấp số) `[V]`; Windows **Wintun** (`golang.zx2c4.com/wintun` binding nạp `wintun.dll`) | `tun-rs` (Rust); `songgao/water` (không Wintun/utun chuẩn) |
| **macOS daemon** | Daemon **root** chạy foreground dưới `launchd` (`/Library/LaunchDaemons/<label>.plist`, `RunAtLoad` + `KeepAlive`, `ExitTimeOut=10`); binary/plist ở `/usr/local/libexec/<brand>/` do root sở hữu. **Không** NetworkExtension/System Extension | App Store/NetworkExtension (cần $99 + entitlement) |
| **Gatekeeper** | Binary `arm64` có **chữ ký ad-hoc do linker Go** `[V]` (đã kiểm: Mach-O cross-build từ Windows có `LC_CODE_SIGNATURE`, cờ ad-hoc bật); phân phối **không qua trình duyệt** (script cài kiểm `SHA256SUMS`) ⇒ không có `com.apple.quarantine`. **Cấm** hướng dẫn `spctl --master-disable`. Notarization/`.pkg` = P2 | Developer ID (không có) |
| **Windows Wintun** | Đặt `tun.WintunTunnelType` = tên sản phẩm (mặc định của thư viện là `"WireGuard"` `[V]` — không dùng tên WireGuard để quảng bá, theo license) và `tun.WintunStaticRequestedGUID` **cố định** để tái dùng adapter, tránh adapter ma (R-05); `wintun.dll` được nạp bởi binding với `LOAD_LIBRARY_SEARCH_APPLICATION_DIR\|SYSTEM32` `[V]` ⇒ đặt cạnh exe trong thư mục chỉ Administrators ghi được | Mặc định `"WireGuard"`/GUID ngẫu nhiên |
| **Windows service** | `golang.org/x/sys/windows/svc` (+ `svc/mgr` để cài, cấu hình **Recovery**); nhận `svc.PowerEvent` (resume) cho PLAT-05; `wintun.dll` đặt cạnh exe trong `Program Files\<brand>` (ghi được bởi Administrators) và **kiểm SHA-256 cố định trước khi nạp** | Dùng `kardianos/service` (thêm lớp trừu tượng; không phủ power event) |
| **Linux service** | Unit `systemd` `Type=notify` (gói `internal/sdnotify` ~30 dòng thay vì thư viện), `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`; **`mesh-server` chạy user `mesh` không đặc quyền**, `AmbientCapabilities=CAP_NET_BIND_SERVICE` chỉ khi cổng < 1024; **`meshd` (VPS-node) là unit riêng** với `CAP_NET_ADMIN` (SEC-06(4)) | Một tiến trình đặc quyền làm tất cả |
| **Route/addr/rule** | Linux: **netlink** (`vishvananda/netlink`). macOS: `/sbin/route` (đường dẫn tuyệt đối qua `sysexec`) + `golang.org/x/net/route` để **đọc/ theo dõi**. Windows: `winipcfg` (IP Helper) | Gọi `ip`/`netsh` cho route |
| **Chống routing loop (REL-09)** | Ràng socket vào interface vật lý mặc định, **ràng lại khi đổi**: Linux `SO_MARK` (qua `Bind.SetMark`) + policy rule loại trừ; macOS `IP_BOUND_IF`/`IPV6_BOUND_IF` (`x/sys/unix`); Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`. Lọc endpoint ứng viên thuộc dải overlay; MVP **chỉ route dải overlay, không default route** | Network namespace (vishvananda/netns) — không hợp daemon cắm vào máy người dùng |
| **Sự kiện mạng/sleep-wake (PLAT-05)** | Linux: netlink subscribe. macOS: **PF_ROUTE routing socket** (`RTM_IFINFO/NEWADDR/DELADDR`) + **phát hiện nhảy đồng hồ** (đồng hồ monotonic không chạy khi ngủ so với wall-clock). Windows: `NotifyIpInterfaceChange` (qua `winipcfg`) + `svc.PowerEvent`. IOKit power notification **cần cgo ⇒ không dùng**; dự phòng `purego` cần duyệt Gate (ADR-001) | IOKit/cgo |
| **Dọn dẹp (REL-08, US-055)** | **Sổ cái tài nguyên** (resource ledger): mọi `utunN`/adapter/route/khối hosts/anchor `pf`/rule firewall/ngoại lệ ALF được ghi vào tệp trạng thái `0600` **trước khi tạo**; dừng hoặc khởi động lại **chỉ** dọn theo sổ cái. Cấm đoán/xoá theo mẫu tên (`utun*`) — bảo đảm không đụng iCloud Private Relay/VPN khác | Quét và xóa interface "giống của mình" |
| **Hosts (PLAT-04)** | Khối `# BEGIN mesh … # END mesh`; ghi nguyên tử (`fsx`) trên **đường dẫn thật**, giữ owner/mode/ACL; macOS resolve symlink `/etc/hosts`; bind-mount ⇒ fallback ghi tại chỗ có khóa | Ghi đè cả file |
| **Firewall** | macOS: phát hiện ALF, đề xuất **opt-in** `socketfilterfw --add/--unblockapp` cho đúng binary; `pf` chỉ qua **anchor riêng**. Windows: profile adapter + rule dải overlay (`netsh advfirewall` qua `sysexec`). Linux: chỉ thêm rule cho cổng đã cấu hình, opt-in có dry-run + tự hoàn tác (SEC-06(3)) | Tự động bật deny-all |

### Consequences
- (+) Mỗi OS dùng cơ chế "native, không cần chứng chỉ trả phí"; hành vi dọn dẹp dự đoán được.
- (−) **Điểm rủi ro cao nhất của dự án** (R-02, R-05): phần OS không giả lập được — macOS cần **Mac thật/VM trên phần cứng Apple/runner macOS** (GNFR-12); QA phải có biên bản.
- (−) PF_ROUTE + clock-jump kém chính xác hơn IOKit (rủi ro PERF-07 trên MacBook) — đã nêu ở ADR-001.
- (−) Windows SmartScreen cảnh báo installer chưa ký (R-11, chấp nhận ở MVP).
- (−) Một số lệnh ngoài (`route`, `pfctl`, `netsh`…) vẫn cần ⇒ `internal/sysexec` + danh mục cho phép (coding-standards §5.5).

---

<a id="adr-008"></a>
## ADR-008 — Vòng đời TLS: IP-Pinning / Standalone ACME / Reverse Proxy

**Trạng thái:** Accepted-pending-Gate-2

### Context
SEC-04 (Gate 1 D3): **chế độ (c) IP + Pin là luồng mặc định hạng nhất từ ngày đầu**; (a) Standalone có domain (ACME không cần cổng 80: `TLS-ALPN-01` — CA kiểm tra **chỉ trên cổng 443** — hoặc `DNS-01`); (b) sau Reverse Proxy (`trusted_proxies`). Không TOFU, không cờ bỏ qua. Pin nên là **khóa công khai (SPKI)** để tái phát hành chứng chỉ không phải pin lại; hỗ trợ **tập pin (hiện tại + kế tiếp)**.

### Options (ACME)
| # | Thư viện | Đánh giá |
|---|---|---|
| A | **`github.com/go-acme/lego/v4`** (MIT) | Hỗ trợ `TLS-ALPN-01`, `DNS-01`, `HTTP-01`; ta **tự lái** vòng đời (renew loop, cảnh báo 14 ngày, tích hợp challenge cert vào `GetCertificate`) — phù hợp yêu cầu cổng tùy chỉnh. **Chọn** |
| B | `caddyserver/certmagic` | Tiện nhưng kéo `zap` (trùng chức năng logging ⇒ vi phạm "một log lib") và tự quản lý quá nhiều; khó ép hành vi cổng ≠ 443 |
| C | `x/crypto/acme/autocert` | Nhẹ, nhưng **không có DNS-01** |
| D | `mholt/acmez` trực tiếp | Mức thấp; ít ví dụ cho DNS-01 |

### Decision
1. **Chế độ (c) IP + Pin — mặc định:** server sinh **khóa định danh bền vững ECDSA P-256** lúc cài; chứng chỉ **tự ký** (gắn SAN = IP/domain hiện hành) phát hành lại được mà **giữ khóa**. **Pin = `sha256:<hex>` của SPKI DER** (`x509.MarshalPKIXPublicKey`). Hiển thị qua kênh Admin (ADR-006) và in sẵn vào lệnh tham gia (`IP:cổng` + pin + key — OPS-08).
2. **Client — `internal/tlspin`:** `tls.Config{ MinVersion: TLS13, InsecureSkipVerify: true /*chỉ ở đây*/, VerifyConnection: <so khớp SPKI với tập pin; fail-closed nếu tập pin rỗng; chỉ chấp nhận pin trong tập (hiện tại + kế tiếp)> }`. Đây là **nơi duy nhất** được chứa `InsecureSkipVerify` (lint + script kiểm). Chế độ CA dùng xác minh chuỗi chuẩn của stdlib. Không có pin & không có chế độ CA ⇒ **từ chối trước khi gửi secret** (không TOFU).
3. **Chế độ (a) Standalone:** `lego`; **`TLS-ALPN-01` chỉ khi cổng TCP = 443** (server trả challenge cert khi ALPN = `acme-tls/1` trong `GetConfigForClient`); cổng ≠ 443 ⇒ `DNS-01` hoặc **từ chối cấu hình kèm hướng dẫn** (US-047 AC7). Không phụ thuộc cổng 80. **MVP chưa nhúng provider DNS-01 nào** (chưa có domain/nhà cung cấp DNS) — thêm khi người dùng chốt (ADR bổ sung). Cảnh báo hết hạn 14 ngày (OPS-07).
4. **Chế độ (b) Reverse Proxy:** dịch vụ chỉ lắng nghe `127.0.0.1`/UDS, nhận HTTP + Upgrade; **`trusted_proxies` mặc định rỗng**; chỉ khi bật tường minh mới tin `X-Forwarded-For`/PROXY protocol (SEC-05b/c).
5. **Chuyển chế độ/xoay khóa** (c)→(a)/(b), đổi IP, xoay khóa với tập pin công bố trước ⇒ qua kênh Admin + phân phối qua Netmap (ADR-009), **giữ nguyên node key/IP overlay/tên** (SEC-15).
6. Chứng chỉ ACME và chứng chỉ tự ký đều lưu trong DB/thư mục trạng thái `0600` thuộc user dịch vụ.

### Consequences
- (+) Hoạt động ngay với **chỉ IP** (Gate 1 D3); MITM kể cả bằng chứng chỉ CA hợp lệ cho đúng IP vẫn bị từ chối (US-003 AC7).
- (+) Một đường kiểm tra pin duy nhất, dễ audit; không có cờ bypass.
- (−) `lego` kéo nhiều phụ thuộc bắc cầu (go-jose, miekg/dns…) ⇒ chỉ import các gói `lego`, `certificate`, `challenge/*` cần thiết; **không** import cả `providers/dns/...` hàng loạt; giấy phép đã kiểm (MIT/BSD/Apache).
- (−) Vòng đời chứng chỉ phải **tự viết** (renew loop, đa-pin) ⇒ cần test mạnh (US-047).
- (−) Let's Encrypt cấp chứng chỉ cho IP chỉ dạng ngắn hạn (~6 ngày) và xác thực trên cổng 80/443 `[T44]` ⇒ **không dùng làm thay thế Pin** ở cổng tùy chỉnh.

---

<a id="adr-009"></a>
## ADR-009 — Cổng/địa chỉ cấu hình được & di chuyển cấu hình (`SEC-15`)

**Trạng thái:** Accepted-pending-Gate-2

### Context
Gate 1 D4: cổng TCP (Control+Relay, mặc định 443) và UDP (STUN, mặc định 3478) **đổi sang cổng bất kỳ**; đổi về sau **không mất danh tính node** (SEC-15, US-074); GNFR-11: không mã hóa cứng. Agent bootstrap tối thiểu = `IP|domain:cổng` + pin/CA; địa chỉ/cổng Relay & STUN **phân phối qua Netmap** (kiểu "relay map" DERP [T3]).

### Options
| # | Phương án | Đánh giá |
|---|---|---|
| A | **Cấu hình server → netmap "server map" ký bởi kênh đã xác thực**; server **lắng nghe song song cổng cũ + mới** trong cửa sổ chuyển tiếp | Không mất node; agent online tự chuyển. **Chọn** |
| B | Bắt agent cấu hình lại thủ công | Vi phạm SEC-15 |
| C | Reverse DNS/SRV | Không áp dụng chế độ IP |

### Decision
1. Mặc định cổng nằm **duy nhất** ở `internal/defaults` (`DefaultControlTCPPort=443`, `DefaultSTUNUDPPort=3478`); mọi nơi khác nhận qua cấu hình/netmap. Script kiểm tra tĩnh cấm literal `443`/`3478` ngoài `defaults` & test (GNFR-11).
2. Server mở listener qua **`ListenerSet`** hỗ trợ **nhiều listener đồng thời**; đổi cổng = mở cổng mới → công bố `server_map{control_addr, relay_addr, stun_addr, pin_set}` **qua kênh control đã xác thực** → agent ghi bền → sau **cửa sổ chuyển tiếp** (cấu hình được) mới đóng cổng cũ. Kiểm tra **xung đột cổng lúc cài/đổi** (bind thử; không giành cổng — SEC-06(1)).
3. Agent chấp nhận cấu hình mới **chỉ** khi đến qua kênh đã xác thực bằng pin/CA hiện hành (SEC-15(e)); agent offline suốt cửa sổ ⇒ admin cục bộ chạy `mesh set --server … --pin …` (ADR-006: chỉ root/Administrator).
4. Tham số cổng UDP STUN và TCP **độc lập**; STUN dùng cùng binary, cùng cấu hình.
5. **Cổng < 1024** cho user không đặc quyền: `AmbientCapabilities=CAP_NET_BIND_SERVICE` trong unit; cổng ≥ 1024 không cần.

### Consequences
- (+) Test chạy ở cả `443/3478` và `8443/3479` (GNFR-11) với cùng mã.
- (−) Phải thiết kế `ListenerSet` + state machine chuyển tiếp (Architect) ⇒ độ phức tạp; có test chaos (đổi cổng khi 5 agent online — SEC-15(a)).
- (−) Mạng khóa cứng ngoài 80/443 sẽ chặn cổng khác 443 — **cảnh báo trung thực** đã có ở REL-06; `netcheck` chẩn đoán.

---

<a id="adr-010"></a>
## ADR-010 — Quan sát & kiểu bí mật: `log/slog`, Redacted Secret Types, metrics

**Trạng thái:** Accepted-pending-Gate-2

### Context
SEC-01 / GNFR-02: **0** secret trong log/DB/crash dump/bundle (kể cả `String()`, `%+v`, JSON, lỗi). OPS-01: log có cấu trúc. OPS-06: metrics Prometheus text trên listener riêng chỉ-đọc, RAM nhỏ.

### Options
| # | Lựa chọn | Đánh giá |
|---|---|---|
| Log | **`log/slog` (stdlib)** vs `zap`/`zerolog`/`logrus` | slog: 0 phụ thuộc, `LogValuer` để ẩn giá trị. **Chọn slog** |
| Secret | **Kiểu bọc `secure.PrivateKey/PreAuthKey` (`Format/String/GoString/MarshalJSON/MarshalText/LogValue`)** vs "nhớ đừng log" | Lỗi con người không thể loại bỏ bằng kỷ luật ⇒ phải ép bằng **kiểu**. **Chọn kiểu bọc** |
| Metrics | **`github.com/VictoriaMetrics/metrics`** vs `prometheus/client_golang` vs tự viết text | VM/metrics: rất nhỏ, text exposition, ít phụ thuộc; `client_golang` nặng hơn cho nhu cầu này. **Chọn VM/metrics** |

### Decision
1. Mọi log đi qua `internal/logx` (slog JSON). **Trường bắt buộc:** `ts` (UTC), `level`, `component`, `event`; khi có `request_id`, `node_id`, `peer_id`. (`component` = "module" trong persona; khớp OPS-01/US-043.)
2. **Kiểu bí mật** đặc tả đầy đủ ở coding-standards §5.1: `String/GoString/Format` ⇒ `[REDACTED]`; `MarshalJSON/MarshalText` ⇒ `"[REDACTED]"`; `UnmarshalJSON` ⇒ lỗi; `LogValue` ⇒ `[REDACTED]`; `Reveal()` chỉ gọi ở danh sách gói được phép (cưỡng chế bằng `scripts/check.*`).
3. `sloglint` cấm khóa log nguy hiểm (`password`, `token`, `private_key`…); logger của thư viện ngoài (`wireguard-go`, `lego`) bọc adapter → `logx`.
4. **Test canary** (`TestNoSecretsInOutputs`) trong CI: grep log+DB+wire+bundle+`status` = 0 (US-043 AC2/AC4, cả mức `debug`).
5. Bundle chẩn đoán (`bugreport`) dùng **allowlist** trường.
6. Metrics: `metrics.WritePrometheus` trên **listener quan sát riêng**; không nhãn chứa secret; số node nhãn có kiểm soát (≤ 20).
7. Log rotation có trần dung lượng (mặc định 100 MB/service — US-043 AC3) tại `internal/logx` (writer xoay vòng tự viết tối giản hoặc `lumberjack` — **chưa nằm danh mục**: MVP dùng `journald`/`launchd`-redirect + writer xoay vòng nội bộ; hỏi duyệt nếu cần thư viện).

### Consequences
- (+) Rò rỉ secret bị chặn ở tầng kiểu + lint + test, không dựa vào kỷ luật.
- (−) Cần kỷ luật dùng `LogValuer`/kiểu bọc cho **mọi** struct mới chứa bí mật (review + test canary).
- (−) Writer xoay vòng nội bộ là mã tự viết (nhỏ, có test) — chấp nhận để khỏi thêm `lumberjack`.
- (−) Prometheus nhãn theo node có thể tăng cardinality: giới hạn ≤ 20 node ở MVP.

---

<a id="adr-011"></a>
## ADR-011 — Phân phối & toàn vẹn bản phát hành

**Trạng thái:** Accepted-pending-Gate-2

### Context
PLAT-06(1): macOS không dùng Developer ID ⇒ luồng cài **không phụ thuộc trình duyệt**, **kiểm SHA-256/chữ ký phát hành**, cấm tắt Gatekeeper. Windows: **Wintun Prebuilt Binaries License** (chỉ phân phối **nguyên vẹn, đi kèm phần mềm dùng nó qua API `wintun.h`**, không chỉnh sửa/dịch ngược, không dùng tên WireGuard/Wintun để quảng bá) `[N]`; mã nguồn Wintun là GPLv2 nhưng ta **không** biên dịch/liên kết mã nguồn đó. C5/R-15: không AGPL.

### Options
| # | Phương án | Đánh giá |
|---|---|---|
| Checksum/chữ ký | **`SHA256SUMS` + chữ ký tách rời bằng `ssh-keygen -Y sign`** (OpenSSH có sẵn trên macOS/Windows/Linux) vs `cosign` vs `minisign` vs GPG | Không thêm công cụ cho người dùng cuối; khóa ký riêng của chủ dự án. **Chọn** (DevOps chốt chi tiết quy trình) |
| Wintun | **Đặt `wintun.dll` cạnh exe, nguyên vẹn, kiểm SHA-256 cố định** vs `go:embed` rồi giải nén | Phân phối cạnh exe tuân thủ chữ & tinh thần license; embed/giải nén có nguy cơ bị coi là sửa/đóng gói lại. **Chọn cạnh exe** |
| macOS đóng gói | 2 binary native + script cài vs Universal (`lipo`) vs `.pkg` | `lipo`/`pkgbuild` cần công cụ Apple ⇒ P2 |

### Decision
1. Mỗi release (tag `vX.Y.Z`): 4 gói (`mesh`, `meshd`, `mesh-server` cho Linux) × đích tương ứng, `SHA256SUMS`, `SHA256SUMS.sig`; build **reproducible-ish** (`-trimpath`, `-buildvcs=true`, thông tin phiên bản qua `-ldflags -X`).
2. Script cài (macOS/Linux `install.sh`, Windows `install.ps1`) **tải → kiểm `SHA256SUMS` + chữ ký bằng khóa công khai nhúng sẵn → cài vào đường dẫn chỉ root/Admin ghi được**; **không** gắn quarantine; **cấm** `spctl --master-disable`, `xattr -cr` hàng loạt trên cây hệ thống.
3. **Wintun:** vendored `wintun.dll` phiên bản đã chọn (**0.14.1**, bản prebuilt mới nhất `[N]` — DevOps xác minh trên `wintun.net` lúc đóng gói), kèm `prebuilt-binaries-license.txt` + `NOTICE`, SHA-256 hằng số trong mã; chỉ tải qua API `wintun.h` (binding `golang.zx2c4.com/wintun`).
4. **Kiểm giấy phép trong CI** (`scripts/check.* -Deps`): danh sách `allow` = MIT, BSD-2/3, Apache-2.0, ISC (+ ngoại lệ có tên cho Wintun DLL); **fail** nếu gặp AGPL/GPL/LGPL/SSPL/BUSL/không rõ ở bất kỳ phụ thuộc bắc cầu nào.
5. `THIRD_PARTY_NOTICES` sinh trong release.

### Consequences
- (+) Người dùng macOS cài được **không phí Apple**, an toàn khi tải về; tuân thủ license Wintun.
- (−) Không có notarization ⇒ **không** chạy được nếu người dùng tải bằng trình duyệt rồi nhấp đúp (đã ghi trong runbook; đường chính là script/`curl`).
- (−) Windows SmartScreen cảnh báo installer chưa ký (R-11, OQ-09).
- (−) Phải quản lý khóa ký phát hành (khóa riêng của chủ dự án, ngoài VPS).

---

## Phụ lục — Ma trận truy vết ADR → Yêu cầu

| ADR | SEC | REL | OPS | PLAT | GNFR / US |
|---|---|---|---|---|---|
| 001 | 02 | 08, 09 | 10 | 01, 03, 06 | GNFR-12; C5 |
| 002 | 02, 11 | 03, 05, 09, 10 | 03 | 05 | US-010, 019, 021, 026 |
| 003 | 02, 03, 05 | 02 | — | — | US-003, 004, 005, 021 |
| 004 | 07 | 04, 06 | 06 | — | US-024..028 |
| 005 | 03, 09 | 11, 12 | 08 | — | US-007, 013, 045 |
| 006 | 14, 09 | — | 05, 06, 08 | 01, 06 | US-012 |
| 007 | 01 | 07, 08, 09, 14 | 02 | 01..06 | US-014..016, 035, 036, 038, 052, 053, 055, 056, 060, 073 |
| 008 | 04, 05 | — | 07 | — | US-003, 047 |
| 009 | 04, 06, 15 | 06 | 04, 05 | — | GNFR-11, US-074, US-019, US-024 |
| 010 | 01, 09 | — | 01, 06, 09 | — | GNFR-02, US-043, 048 |
| 011 | — | — | 10 | 01, 06 | C5, R-11, R-15 |
