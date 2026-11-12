# Tech Stack Decision — Mesh VPN cá nhân kiểu Tailscale (Go 1.27)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-12 |
| Phiên bản | **1.0** — trình Gate 2 |
| Giai đoạn | 3 — Thiết kế hệ thống (sau Gate 1 ✅ 2026-11-12) |
| Thành phần AI/SLM | **Không có** → bỏ qua mục AI/ML Stack (đúng persona mục 3) |
| Đầu vào | `reference-systems-benchmark.md`, `production-readiness-requirements.md` v1.2, `project-charter.md` v1.2, `product-backlog.md` v1.2 |
| Tài liệu đi kèm | [architecture-decision-record.md](./architecture-decision-record.md) (ADR-001…011) · [coding-standards.md](./coding-standards.md) · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Cấu hình công cụ | [`.golangci.yml`](../../.golangci.yml) · [`.editorconfig`](../../.editorconfig) · [`go.mod`](../../go.mod) · [`tools/go.mod`](../../tools/go.mod) · [`scripts/`](../../scripts) |

> **Quy ước kiểm chứng.** `[V]` = **đã kiểm chứng thực nghiệm** trong phiên này (chi tiết §14). `[N]` = dựa trên tài liệu/nguồn công khai, **chưa** thử tại đây — không được đọc là số đo. Mọi con số hiệu năng/RAM là **đề xuất chưa đo** (C6); `agile-qa` đo ở US-058.

---

## 1. Tóm tắt quyết định (TL;DR)

| Hạng mục | Quyết định chốt | Lý do cốt lõi |
|---|---|---|
| **Ngôn ngữ / toolchain** | **Go 1.27.4** (`go.mod`: `go 1.27.4`), `CGO_ENABLED=0` bất biến | Cross-compile **một lệnh/đích** từ Windows ra `windows/amd64`, `darwin/arm64`, `darwin/amd64`, `linux/amd64` **không cần C toolchain/macOS SDK** `[V]`; hệ sinh thái WireGuard/TUN/netmon gốc của Tailscale là Go |
| **Binary** | `mesh-server` (Linux), `meshd` (agent root/SYSTEM), `mesh` (CLI) — một module Go | Tách đặc quyền: server không đặc quyền, agent đặc quyền tối thiểu, CLI không đặc quyền |
| **WireGuard userspace** | `golang.zx2c4.com/wireguard` (wireguard-go upstream, MIT) + **`conn.Bind` tự hiện thực** | Không tự viết mật mã (SEC-02); `conn.Bind` cho phép dùng chung 1 socket cho STUN/Disco/WG và đi qua relay `[V]` |
| **TUN** | `wireguard/tun`: Linux `/dev/net/tun`, macOS `utun`, Windows **Wintun** (DLL cạnh exe) | Cơ chế native, không cần chứng chỉ Apple trả phí |
| **Mật mã** | stdlib `crypto/*` + `golang.org/x/crypto` (**chỉ trong `internal/secure`**): X25519/NaCl box, SHA-256, `crypto/rand` | Chuẩn, đã kiểm định; ép bằng depguard |
| **Control/Relay** | HTTPS/1.1 JSON + **WebSocket** (`github.com/coder/websocket`) trên **một cổng TCP** | Chạy sau Reverse Proxy; heartbeat có sẵn |
| **TLS** | stdlib `crypto/tls` (TLS 1.3 tối thiểu) + `internal/tlspin` (SPKI pin) + `lego/v4` (ACME) | IP+Pin hạng nhất ngày đầu; ACME `TLS-ALPN-01`/`DNS-01` |
| **STUN** | **Tự viết `internal/stun`** (RFC 5389/8489 Binding, không auth) | `pion/stun/v3` kéo cả stack DTLS/transport (47 gói phụ thuộc) `[V]` — quá nặng cho ~200 dòng |
| **DB nhúng** | **`modernc.org/sqlite`** (thuần Go) + `database/sql`, WAL, `VACUUM INTO` | UNIQUE/transaction/migration; build **không CGO** `[V]` |
| **CLI** | `github.com/spf13/cobra` | Chuẩn de-facto, dễ đồng nhất lệnh `mesh <noun> <verb>` |
| **Config** | TOML (`go-toml/v2`, `DisallowUnknownFields`) | Dễ đọc, không YAML/viper |
| **Logging** | `log/slog` (stdlib) + kiểu bí mật `Redacted` | 0 phụ thuộc; ép bằng kiểu |
| **Metrics** | `github.com/VictoriaMetrics/metrics` (Prometheus text) | Rất nhỏ, đủ cho OPS-06 |
| **Service tích hợp** | Windows `x/sys/windows/svc`; macOS `launchd` (daemon foreground); Linux `systemd` `Type=notify` | Không cần thư viện bọc |
| **Test** | stdlib `testing` + `go-cmp` + `goleak` + `testing/synctest`; fuzz native | Một phong cách assertion |
| **Lint/Format** | `golangci-lint` v2.15.0 (ghim ở `tools/go.mod`) + `gofumpt` + `gci` | Cưỡng chế toàn đội |

> **Không có AI/ML Stack** (dự án không có thành phần AI/SLM).

---

## 2. Đầu vào & ràng buộc quyết định

| Nguồn | Ràng buộc ảnh hưởng stack |
|---|---|
| Gate 1 D1 | Client **macOS 13+ (`arm64` + `amd64`)** + **Windows 10/11 x64**; macOS không cần Apple Developer $99 |
| Gate 1 D2 | VPS **Ubuntu LTS x64** (Control+Relay+STUN + 1 node mesh + lab NAT container) |
| Gate 1 D3/D4 | Kết nối **IP + Pin** hạng nhất; cổng TCP/UDP **cấu hình được**, đổi không mất danh tính node |
| C5 / R-15 | **Cấm AGPL/GPL** (mã server NetBird…); Wintun đúng *Prebuilt Binaries License* |
| Máy dev | **Windows**; có `git`, `docker`, `wsl`, `python 3.9`, `rustc 1.94.1`/`cargo`; **chưa có `go`** `[V]` (`go`, `golangci-lint` không có trên PATH) |
| Build/CI | Phải ra **4 đích** từ Windows và GitHub Actions, ưu tiên `CGO_ENABLED=0` |
| PERF | RAM server < 64 MB (trần 128), RAM agent ≤ 50 MB, throughput direct ≥ 70% tới 300 Mbps — *đề xuất chưa đo* |
| Đội | Nhiều Subagent lập trình song song ⇒ ngôn ngữ ít cách viết, build nhanh, tooling cưỡng chế mạnh |

---

## 3. Ngôn ngữ & Runtime: Go vs Rust (Trade-off Matrix trung thực)

### 3.1. Phân tích cross-compile — điểm kỹ thuật quyết định

| Đích (build từ **Windows**, không máy Mac) | **Go 1.27, `CGO_ENABLED=0`** | **Rust** (`boringtun`/`gotatun` + `tokio` + `rustls` + `wintun`) |
|---|---|---|
| `windows/amd64` | Native, ✔ `[V]` (8.1 MB probe) | Native `x86_64-pc-windows-msvc` cần **MSVC Build Tools** (~GB) hoặc `-gnu` + MinGW ✔ có thể |
| `linux/amd64` | `GOOS=linux go build` ✔ `[V]` | Cần linker Linux: `cargo-zigbuild` + Zig, hoặc `cross` + **Docker** `[N]` |
| `darwin/amd64` | `GOOS=darwin GOARCH=amd64` ✔ `[V]` | `rustup target add` chỉ cấp `std`; **thiếu linker và libSystem/SDK** ⇒ cần `cargo-zigbuild` + Zig (Zig kèm stub libSystem) `[N]` |
| `darwin/arm64` | ✔ `[V]` — linker Go **tự ký ad-hoc** (Mach-O có `LC_CODE_SIGNATURE`, cờ ad-hoc bật) `[V]` | Như trên; **mã `arm64` phải có chữ ký** ⇒ cần bước `codesign`/`rcodesign` riêng `[N]` |
| Phụ thuộc mã C trong cây build | **0** (SQLite = `modernc.org/sqlite` thuần Go `[V]`) | `ring`/`aws-lc-rs` (backend của `rustls`) và `rusqlite` (bundled) **biên dịch mã C** ⇒ đi qua `zig cc`; tránh bằng `redb` (thuần Rust) + backend crypto thuần Rust (kém chín hơn) `[N]` |
| Framework hệ thống macOS (Security, SystemConfiguration, IOKit) | Không cần cho bản này (xem hạn chế IOKit ở §10.1) | Dùng crate như `security-framework`/`system-configuration` ⇒ cần **SDK Apple** — giấy phép Xcode/SDK **hạn chế dùng ngoài phần cứng Apple** `[N]` |
| Bước CI thay thế | Không cần runner macOS để **build** | Runner macOS (GitHub Actions) build native là đường **dễ nhất** — nhưng **không** đáp ứng yêu cầu "build từ máy dev Windows" |

> **Kết luận trung thực:** Rust **có thể** cross-compile sang macOS từ Windows (qua `cargo-zigbuild`) nhưng là chuỗi công cụ mong manh (Zig + SDK stub + `ring` C + ký ad-hoc thủ công); Go cho kết quả tương đương bằng **một biến môi trường** và đã được chứng minh trong phiên này. *Rust ở đây không bị loại vì "không làm được" mà vì chi phí/rủi ro vận hành cao hơn cho đội nhiều Subagent.* Chưa chạy thử Rust tại máy này để không thay đổi cấu hình `rustup` của người dùng.

### 3.2. Ma trận có trọng số (1–5; tổng trọng số 100; *đánh giá chủ quan của Tech Lead, không phải số đo*)

| Tiêu chí | Trọng số | **Go** | **Rust** | Lai (Rust data-plane FFI + Go control) |
|---|---:|:-:|:-:|:-:|
| Cross-compile 4 đích từ Windows, không C toolchain | 20 | **5** | 2 | 1 |
| Hệ sinh thái WG userspace + TUN + netmon + magicsock tham chiếu | 20 | **5** | 3 | 3 |
| An toàn Production & bảo mật (bộ nhớ, thư viện mật mã) | 15 | 3 | **5** | 3 |
| Hiệu năng & footprint (PERF-01/04/09) | 10 | 4 | **5** | 4 |
| Giấy phép (C5) | 10 | **5** (MIT/BSD) | 3 (`gotatun` MPL-2.0; `boringtun` BSD-3 nhưng ít bảo trì `[N]`) | 3 |
| Năng suất & đồng nhất khi nhiều Subagent code song song | 10 | **5** | 3 | 2 |
| Độ chín & hỗ trợ dài hạn thư viện then chốt | 10 | **5** | 3 | 2 |
| Học bản chất (G3): mã tham chiếu đọc được | 5 | **5** | 3 | 2 |
| **Tổng có trọng số /100** | | **92** | **66** | **49** |

**Điểm yếu thật của Go cần chấp nhận:** (1) GC ⇒ phải đặt `GOMEMLIMIT`; (2) không an toàn bộ nhớ tuyệt đối như Rust (có `unsafe`/data race) ⇒ bù bằng `-race`, `goleak`, fuzz, cấm `unsafe` ngoài `sys*`; (3) **race detector cần cgo** ⇒ chạy ở Linux (§4); (4) `CGO_ENABLED=0` ⇒ không gọi được IOKit; resolver DNS macOS là pure-Go (§10.1).
**Ngưỡng quay lại Rust:** chỉ khi PERF-01/PERF-09 **không thể** đạt với Go sau tối ưu **và** có runner macOS + đội chấp nhận dựng Zig/SDK — cần ADR mới.

### 3.3. Phiên bản chốt

| Thành phần | Phiên bản | Ghi chú |
|---|---|---|
| **Go** | **1.27.4** (stable mới nhất, phát hành 2026-11-10 — kiểm trên `go.dev/dl/?mode=json` `[V]`; nhánh cũ còn hỗ trợ: 1.26.11) | `go.mod: go 1.27.4`; nâng **bản vá 1.27.x** ≤ 7 ngày sau bản vá bảo mật; nâng minor chỉ qua ADR |
| Module path | `meshvpn.internal/mesh` | Tên giữ chỗ (dự án private, OQ-11); đổi 1 lần bằng `go mod edit -module` + codemod **trước Sprint 1** nếu cần |
| `GOTOOLCHAIN` | `local` | Không tải toolchain khác ngầm |

---

## 4. Toolchain & Bootstrap (máy dev chưa có Go)

**Cách 1 — khuyến nghị (không cần admin, không đổi PATH hệ thống):**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap-toolchain.ps1
# Tải go1.27.4.windows-amd64.zip, kiểm SHA-256 ghim sẵn trong script
# (178ab98950ac69ab25069307dc6ade79f3816e414cce95b4da166a115cde1e7e — đã đối chiếu với go.dev [V]),
# giải nén vào %USERPROFILE%\sdk\go1.27.4. scripts\check.ps1 tự tìm Go ở đây.
```

**Cách 2 — cài hệ thống:** `winget install --id GoLang.Go -e` (MSI, cần UAC) rồi xác nhận `go version` = `go1.27.4`.

**Công cụ lint/format/vuln/license — ghim bằng module công cụ riêng `tools/go.mod`** (Go ≥ 1.24 `tool` directive): không cần cài thủ công, không lẫn vào đồ thị phụ thuộc sản phẩm; chạy bằng `go tool '-modfile=tools/go.mod' <tên>` (⚠ **PowerShell phải đặt dấu nháy quanh `-modfile=...`** vì PowerShell cắt đối số tại dấu chấm `[V]` — `scripts/check.*` đã xử lý). Lần chạy đầu biên dịch `golangci-lint` (**≈ 35–40 s** trên máy dev `[V]`, sau đó được cache).

| Công cụ (trong `tools/go.mod`) | Phiên bản | Giấy phép | Dùng cho |
|---|---|---|---|
| `golangci-lint` | v2.15.0 | GPL-3.0 — **chỉ là công cụ dev, không liên kết vào sản phẩm**, tách module riêng, loại khỏi kiểm giấy phép sản phẩm | lint + `fmt` (gofumpt, gci) |
| `govulncheck` | v1.9.0 | BSD-3 | quét lỗ hổng |
| `go-licenses` | v2.0.1 | Apache-2.0 | kiểm giấy phép phụ thuộc |

> **Race detector:** `go test -race` **bắt buộc cgo + trình biên dịch C** (đã thử: `go: -race requires cgo` khi `CGO_ENABLED=0` `[V]`; máy này **không có `gcc`** `[V]`). Vì vậy bước race chạy **ở Linux** — CI `ubuntu-latest` (có gcc) hoặc `scripts/check.ps1 -Race` (Docker `golang:1.27.4`; *chưa thử tại máy này vì phải kéo image nặng* `[N]`) hoặc WSL. Đây là **ngoại lệ duy nhất** của `CGO_ENABLED=0`, và chỉ cho thực thi test, **không** cho binary release.
>
> **Lưu ý quan sát được:** lần chạy `go mod tidy` đầu tiên trên module cache **nguội** với Go 1.27.4 đã báo lỗi `golang.org/x/net/http3 … does not contain package` (liên quan test của `net/http` trong GOROOT) và **tự hết khi chạy lại** `[V]`. Nếu gặp: chạy lại; không đổi phiên bản `x/net` theo cảm tính.

---

## 5. Kiến trúc binary & bố cục mã

| Binary | Chạy ở đâu / quyền | Trách nhiệm | Gói chính |
|---|---|---|---|
| **`mesh-server`** | VPS Ubuntu, user `mesh` **không đặc quyền** (`CAP_NET_BIND_SERVICE` chỉ khi cổng < 1024) | Control plane (đăng ký, netmap, thu hồi), **Blind Relay**, **STUN server**, listener quan sát, **kênh Admin (UDS)**, backup | `internal/{server,store,relay,stun,adminapi,tlsmgr}` |
| **`meshd`** | macOS (root, `launchd`), Windows (SYSTEM, Service), Linux VPS-node (unit riêng, `CAP_NET_ADMIN`) | Data plane: `conn.Bind` (magicbind), WG device, TUN, route/hosts, NAT traversal, control client, dọn dẹp theo sổ cái, IPC cục bộ | `internal/{agent,datapath,disco,netmon,routes,hostsblock,tlspin,keystore,ipc}` |
| **`mesh`** | Người dùng (không đặc quyền cho lệnh chỉ-đọc; thao tác thay đổi đòi root/Admin) | CLI: `up/down/status/ping/netcheck/set`; trên VPS: `preauthkey`, `node`, `server info`, `backup`… qua socket cục bộ | `cmd/mesh` + `internal/{cli,ipc}` |

- **Một module Go**, toàn bộ mã trong `internal/` (không export API ngoài). Gói **xuyên suốt** do Tech Lead sở hữu: `apperr, brand, defaults, secure, logx, httpx, ids, clock, backoff, fsx, lifecycle, sysexec`. Ranh giới module nghiệp vụ chi tiết do `agile-architect` chốt (C4).
- `mesh-server` và `meshd` **cùng tồn tại trên VPS** (VPS là một node — US-056) nhưng là **hai tiến trình/hai unit** để tách đặc quyền (SEC-06(4)).
- Tên sản phẩm/label dịch vụ/đường dẫn lấy từ **`internal/brand`** (OQ-12 chưa chốt tên) ⇒ đổi tên = sửa một nơi.

---

## 6. Data plane: WireGuard, TUN, STUN, Disco

### 6.1. Thư viện WireGuard (Trade-off)

| Phương án | Giấy phép | Ưu | Nhược | Quyết định |
|---|---|---|---|---|
| **`golang.zx2c4.com/wireguard` upstream** | MIT `[V]` | Chính chủ; `conn.Bind` (Open/Close/SetMark/Send/ParseEndpoint/BatchSize `[V]`) cho phép thay lớp socket; dùng rộng | **Không có tag phiên bản** ⇒ ghim pseudo-version; ta tự hiện thực magicbind | **CHỌN** — `v0.0.0-20261024220952-b3bc704ef0ee` |
| Fork `tailscale/wireguard-go` | BSD/MIT | Có hook cho magicsock | Gắn chặt nhu cầu Tailscale | Dự phòng |
| `flynn/noise` tự lắp WG | BSD-3 | — | **Vi phạm SEC-02** | Loại |
| Kernel WG / WireGuardNT | GPLv2 (kernel) | Nhanh | macOS không có; license/driver phức tạp | P2 (US-071) |
| `boringtun`/`gotatun` (Rust, FFI) | BSD-3 / **MPL-2.0** | An toàn bộ nhớ | Vi phạm ADR-001 (CGO/FFI) | Loại |

### 6.2. TUN theo nền tảng

| OS | Cơ chế | Thư viện | Ghi chú |
|---|---|---|---|
| Linux | `/dev/net/tun` | `wireguard/tun` | Cần `CAP_NET_ADMIN` (unit `meshd` riêng); route/addr/rule/monitor qua **netlink** `vishvananda/netlink` |
| macOS | `utun` (kernel control `com.apple.net.utun_control`; **kernel cấp số `utunN`**) | `wireguard/tun` | Ghi tên thực tế vào sổ cái; chỉ route đúng interface đó (PLAT-06(2)) |
| Windows | **Wintun** | `wireguard/tun` → `golang.zx2c4.com/wintun` (binding MIT) nạp `wintun.dll` bằng `LoadLibraryEx(..., SEARCH_APPLICATION_DIR\|SEARCH_SYSTEM32)` `[V]` | Đặt `tun.WintunTunnelType` = tên sản phẩm (mặc định là `"WireGuard"` `[V]` — **không** dùng để quảng bá, theo license) và `tun.WintunStaticRequestedGUID` **cố định** để tái dùng adapter, tránh adapter ma (R-05); IP Helper qua `winipcfg` (MIT `[V]`) |

### 6.3. STUN — tự viết, không `pion/stun`

| Phương án | Phụ thuộc bắc cầu (đo bằng `go list -deps`) | Quyết định |
|---|---|---|
| `github.com/pion/stun/v3` v3.1.7 (MIT) | **47 gói** gồm `pion/dtls/v3` (cả stack DTLS + crypto), `pion/transport`, `pion/logging`, `wlynxg/anet` `[V]` | Loại: đưa thêm một stack mật mã **không dùng** vào binary, trái tinh thần SEC-02/“một chức năng một thư viện”, vì ~200 dòng đủ |
| **`internal/stun` tự viết** | 0 (stdlib: `encoding/binary`, `hash/crc32`, `net/netip`) | **CHỌN**: STUN **Binding** theo RFC 5389/8489 — request/response, `XOR-MAPPED-ADDRESS`, `FINGERPRINT`; **không** `MESSAGE-INTEGRITY`/TURN. Phải có `FuzzXxx` + test vector RFC 5769. *Không phải mật mã* (CRC32 không dùng cho bảo mật) |

Cổng UDP STUN cấu hình được (mặc định 3478 — chỉ ở `internal/defaults`); STUN server chạy **cùng binary `mesh-server`**; client gửi từ **chính socket magicbind** (US-019).

### 6.4. Disco, MTU

Disco = NaCl box (`golang.org/x/crypto/nacl/box`) + `disco_key` + `tx_id` (ADR-003 §4). MTU tunnel mặc định **1280** (REL-10). Chi tiết bản tin do Architect.

---

## 7. Mật mã & Giao thức xác thực (SEC-02)

| Nhu cầu (SEC-02) | Thư viện / cơ chế | Vị trí | Ghi chú |
|---|---|---|---|
| Khóa Curve25519 (node, disco) | `golang.org/x/crypto/nacl/box` (`GenerateKey`) + `crypto/rand` | `internal/secure` | Khóa là `[32]byte` bọc `PrivateKey` |
| Chứng minh sở hữu khóa node (challenge/nonce **từ server**) | NaCl box với **ephemeral X25519 của server** + nonce 32 B + (tùy chọn) **TLS exporter** làm channel binding | `internal/secure` | ADR-003 — không phụ thuộc đồng hồ client |
| Xác thực gói **Disco** (`disco_key` + `tx_id`) | NaCl box, nonce 24 B ngẫu nhiên, bảng `tx_id` đang chờ có TTL | `internal/secure` + `internal/disco` | Chống phát lại/giả mạo |
| Băm Pre-Auth Key | **SHA-256** (`crypto/sha256`) của khóa ≥ 256 bit; so sánh `crypto/subtle.ConstantTimeCompare`; DB chỉ lưu hash | `internal/secure` | Khóa entropy cao ⇒ không cần KDF chậm (bcrypt/argon2) |
| TLS | `crypto/tls`, **TLS 1.3 tối thiểu**; Pin = SHA-256 của **SPKI DER** | `internal/tlspin`, `internal/tlsmgr` | Khóa danh tính server **ECDSA P-256** |
| Ngẫu nhiên | `crypto/rand` | `internal/secure` | Cấm `math/rand` v1; jitter `math/rand/v2` chỉ ở `internal/backoff` |
| **Cấm** | tự cài cipher/MAC/KDF; MD5/SHA-1/DES/RC4; so sánh bí mật bằng `==` | — | depguard + gosec |

**Giao thức Control tóm tắt (chi tiết Architect):** HTTPS/1.1 JSON RPC (đăng ký, challenge) + WebSocket stream netmap, cùng cổng TCP với relay; tắt HTTP/2 trên listener này; không gRPC/protobuf/QUIC ở MVP (ADR-003/004).

---

## 8. TLS, ACME, Relay, Reverse Proxy

### 8.1. ACME (Trade-off)

| Phương án | Giấy phép | `TLS-ALPN-01` | `DNS-01` | Kéo logging lib khác? | Quyết định |
|---|---|:-:|:-:|:-:|---|
| **`go-acme/lego/v4`** v4.35.2 | MIT `[V]` | ✔ | ✔ | Không (dùng `log` chuẩn có thể thay) | **CHỌN** — ta tự lái vòng đời; chỉ import `lego`, `certificate`, `challenge/*` |
| `caddyserver/certmagic` | Apache-2.0 | ✔ | ✔ | **Có (`zap`)** ⇒ trùng chức năng log | Loại |
| `x/crypto/acme/autocert` | BSD-3 | ✔ | ✘ | Không | Loại (thiếu DNS-01) |

- **IP + Pin (mặc định):** khóa ECDSA P-256 sinh lúc cài; chứng chỉ tự ký giữ khóa khi tái phát hành; **Pin = `sha256:` SPKI**; tập pin (hiện tại + kế tiếp) cho xoay khóa; client `internal/tlspin` fail-closed, **không TOFU, không cờ bỏ qua** (ADR-008).
- **Standalone domain:** `TLS-ALPN-01` **chỉ khi cổng TCP = 443** (CA kiểm trên 443 — RFC 8737 `[T44]`), cổng khác ⇒ `DNS-01` hoặc **từ chối cấu hình có hướng dẫn**; không cần cổng 80. **MVP chưa nhúng provider DNS-01** (chưa có domain) — thêm khi người dùng chốt nhà cung cấp.
- **Reverse Proxy:** dịch vụ nghe `127.0.0.1`/UDS; `trusted_proxies` mặc định rỗng (SEC-05).
- Let's Encrypt cấp cert cho **IP** chỉ dạng ngắn hạn (~6 ngày) và xác thực trên cổng 80/443 `[T44]` ⇒ **không** thay được Pin ở cổng tùy chỉnh.

### 8.2. WebSocket cho Blind Relay & Control stream

| Phương án | Giấy phép | Nhận xét | Quyết định |
|---|---|---|---|
| **`github.com/coder/websocket`** v1.8.15 | ISC `[V]` | API `context`-first, `SetReadLimit`, ping/pong, tương thích Nginx/Caddy; (tiền thân `nhooyr.io/websocket`) | **CHỌN** |
| `gorilla/websocket` | BSD-2 | Phổ biến nhưng API không `context`-first | Loại (một thư viện WebSocket) |
| HTTP Upgrade tự đóng khung (kiểu DERP) | — | Tự viết framing/keepalive | Loại |
| QUIC (`quic-go`), gRPC | — | UDP có thể bị chặn / h2+protobuf | Loại ở MVP |

Chống HoL: hàng đợi per-đích có trần, **drop-tail không chặn**, write deadline ngắn, không khóa toàn cục (ADR-004). Giới hạn băng thông: `golang.org/x/time/rate`.

---

## 9. Lưu trữ nhúng (US-045 — backup nguyên tử)

| Phương án | Giấy phép | CGO | Ưu | Nhược | Quyết định |
|---|---|:-:|---|---|---|
| **`modernc.org/sqlite`** v1.62.0 | BSD-3 `[V]` | **Không** `[V]` | SQL, UNIQUE, WAL, `integrity_check`, `VACUUM INTO` | Chậm hơn C-SQLite (cỡ 1.5–3× `[N]`); binary lớn hơn | **CHỌN** |
| `mattn/go-sqlite3` | MIT | **Có** | Nhanh, chín | Vi phạm `CGO_ENABLED=0` | Loại |
| `go.etcd.io/bbolt` v1.5.0 | MIT | Không | Thuần Go, ACID, snapshot `Tx.WriteTo` | Không SQL ⇒ tự cài UNIQUE/index/migration/audit | Dự phòng |
| Postgres/MySQL | — | — | HA | Vượt ngân sách RAM VPS dùng chung | Loại |

**Quy ước truy cập (một phong cách cho mọi dev):** `database/sql` + **SQL thuần có tham số**, repository có kiểu trong `internal/store`; **không ORM/query-builder/sqlc**; migrator nhỏ tự viết (`embed` + `schema_migrations`, mỗi migration một transaction, backup trước migration + `integrity_check`).
**Pragma:** `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=5000`, `trusted_schema=OFF`; một kết nối ghi.
**Backup nguyên tử:** `VACUUM INTO <tmp>` → `fsync` → `integrity_check` trên bản sao (mở read-only) → `*.sha256` → `rename` → `0600`; giữ 7 bản; restore từ chối khi sai checksum. **Khuyến nghị cho Architect:** lưu khóa định danh server **trong DB** để backup luôn kèm khóa (REL-12).

---

## 10. Tích hợp nền tảng, CLI, cấu hình, quan sát, kiểm thử

### 10.1. Tích hợp nền tảng

| Nền tảng | Cơ chế chốt | Thư viện | Hạn chế trung thực |
|---|---|---|---|
| **macOS 13+** | Daemon root foreground dưới `launchd` (`/Library/LaunchDaemons`, `RunAtLoad`+`KeepAlive`); `utun`; không NetworkExtension; binary `arm64` ký ad-hoc bởi linker `[V]`; cài qua script kiểm checksum | `x/sys/unix` (`IP_BOUND_IF`, `LOCAL_PEERCRED`), `x/net/route` (PF_ROUTE), `/sbin/route` qua `sysexec` | **Không IOKit (cần cgo)**: sleep/wake dùng PF_ROUTE + **phát hiện nhảy đồng hồ**; DNS resolver pure-Go (cgo off). Nếu PERF-07 trên MacBook không đạt ⇒ xin duyệt `ebitengine/purego` (ngoài danh mục) |
| **Windows 10/11** | Service (`x/sys/windows/svc` + `svc/mgr`, Recovery), Wintun, named pipe + SDDL, `winipcfg` | `x/sys/windows`, `go-winio`, `wireguard/windows/tunnel/winipcfg` | `wintun.dll` kèm nguyên vẹn + kiểm SHA-256; firewall qua `netsh`; installer chưa ký ⇒ SmartScreen (R-11) |
| **Ubuntu LTS** | `systemd` `Type=notify` (`internal/sdnotify` ~30 dòng, không thư viện); `mesh-server` user `mesh`; `meshd` unit riêng `CAP_NET_ADMIN`; netlink | `x/sys/unix`, `vishvananda/netlink` | Test lab: `--cap-add=NET_ADMIN --device /dev/net/tun`, không `--privileged` |

Chi tiết quyết định ở **ADR-006/007**; chống routing loop: Linux `SO_MARK`, macOS `IP_BOUND_IF`/`IPV6_BOUND_IF`, Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`.

### 10.2. CLI, cấu hình, quan sát, kiểm thử

| Hạng mục | Chốt | Thay thế bị loại |
|---|---|---|
| **CLI** | `spf13/cobra` v1.10.2 (Apache-2.0 `[V]`) — `mesh <noun> <verb>` | `urfave/cli`, `kong`, `flag` thuần |
| **Config** | TOML `pelletier/go-toml/v2` v2.4.3 (MIT) strict | `viper`, YAML |
| **Validation** | **Không thư viện validate** — kiểu miền có constructor `(T, error)` (parse, don't validate) | `go-playground/validator` |
| **HTTP** | `net/http` + `ServeMux` (Go 1.22+ pattern) | gin/chi/echo/mux |
| **Logging** | `log/slog` + `internal/logx`; trường bắt buộc `ts, level, component, event` (+ `request_id`, `node_id`, `peer_id`) | zap/zerolog/logrus, package `log` |
| **Tracing** | Không OpenTelemetry ở MVP (single-process, 20 node) — `request_id` correlation đủ | OTel |
| **Metrics** | `VictoriaMetrics/metrics` v1.45.0 (MIT `[V]`), listener riêng chỉ-đọc | `prometheus/client_golang` |
| **Test** | stdlib `testing`, `google/go-cmp` v0.7.0, `go.uber.org/goleak` v1.3.0, `testing/synctest`, fuzz native | `testify` |
| **ID** | `internal/ids` (`crypto/rand`) | `uuid`, `ulid` |

---

## 11. Dependency Policy

### 11.1. Danh mục **ĐƯỢC PHÉP** (ghim; thêm = hỏi Scrum Master + ADR)

> Phiên bản = phiên bản `@latest` trên `proxy.golang.org` tại 2026-11-12 `[V]`; giấy phép = đọc từ file LICENSE trong module đã tải `[V]` trừ khi đánh dấu `[N]`.

| Thư viện | Phiên bản ghim | Giấy phép | Binary / OS | Gói duy nhất được import | Mục đích |
|---|---|---|---|---|---|
| Go stdlib | 1.27.4 | BSD-3 | tất cả | — | `net/http`, `crypto/*`, `log/slog`, `database/sql`, `embed`, `net/netip`, `testing/synctest`… |
| `golang.zx2c4.com/wireguard` | `v0.0.0-20261024220952-b3bc704ef0ee` | MIT | `meshd` | `internal/datapath/**` | `device`, `conn`, `tun`, `ipc` |
| `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | MIT | `meshd`/windows | (bắc cầu qua `wireguard/tun`) | binding nạp `wintun.dll` |
| `golang.zx2c4.com/wireguard/windows` | `v1.1.1` | MIT | `meshd`/windows | `internal/datapath` (`_windows.go`): `tunnel/winipcfg` **chỉ** | IP Helper |
| `golang.org/x/crypto` | `v0.59.0` | BSD-3 | server, `meshd` | `internal/secure/**` | `nacl/box` (+ gói cần thiết khác trong `secure`) |
| `golang.org/x/sys` | `v0.50.0` | BSD-3 | tất cả | các file `_<os>.go`, `internal/sys*` | `unix`, `windows`, `windows/svc`, `svc/mgr` |
| `golang.org/x/net` | `v0.62.0` | BSD-3 | `meshd` | `route`, `ipv4`, `ipv6` **chỉ** | PF_ROUTE, socket options |
| `golang.org/x/sync` | `v0.25.0` | BSD-3 | tất cả | `internal/lifecycle` | `errgroup` |
| `golang.org/x/time` | `v0.16.0` | BSD-3 | server | `internal/relay` | `rate` |
| `modernc.org/sqlite` | `v1.62.0` | BSD-3 (+ `libc`, `mathutil`, `memory` BSD-3) | server | `internal/store` | SQLite thuần Go |
| `github.com/coder/websocket` | `v1.8.15` | ISC | server, `meshd` | `internal/{relay,controlclient,...}` | WebSocket |
| `github.com/spf13/cobra` | `v1.10.2` | Apache-2.0 (+ `pflag` BSD-3, `mousetrap` Apache-2.0) | `mesh`, `meshd`, `mesh-server` | `cmd/**`, `internal/cli` | CLI |
| `github.com/pelletier/go-toml/v2` | `v2.4.3` | MIT | server, `meshd` | `internal/config` | Config TOML |
| `github.com/go-acme/lego/v4` | `v4.35.2` | MIT (+ `go-jose` Apache-2.0, `miekg/dns` BSD-3, `cenkalti/backoff` MIT) | **chỉ `mesh-server`** | `internal/tlsmgr` | ACME |
| `github.com/VictoriaMetrics/metrics` | `v1.45.0` | MIT (+ `valyala/histogram`, `fastrand` MIT) | server (`meshd` tùy) | `internal/obs` | Metrics Prometheus text |
| `github.com/Microsoft/go-winio` | `v0.6.4` | MIT | `meshd`/windows | `internal/ipc` (`_windows.go`) | Named pipe + SDDL |
| `github.com/vishvananda/netlink` | `v1.3.1` | Apache-2.0 (+ `netns` Apache-2.0) `[V]` | `meshd`+`mesh-server`/linux | `internal/{routes,netmon}` (`_linux.go`) | netlink |
| `github.com/google/go-cmp` | `v0.7.0` | BSD-3 | **test** | `_test.go` | So sánh/diff |
| `go.uber.org/goleak` | `v1.3.0` | MIT | **test** | `_test.go` | Rò goroutine |

*Thư viện bắc cầu* của các mục trên được phép khi `go-licenses` xác nhận giấy phép thuộc allowlist (§11.3). **Không** import trực tiếp thư viện bắc cầu nếu nó không có trong bảng.

**Phụ thuộc ngoài Go:** `wintun.dll` **0.14.1** (bản prebuilt mới nhất theo hiểu biết hiện tại `[N]` — DevOps xác minh trên `wintun.net` khi đóng gói) — *Prebuilt Binaries License*: phân phối **nguyên vẹn, đi kèm phần mềm dùng nó qua API `wintun.h`**, không sửa/dịch ngược, không dùng tên WireGuard/Wintun để quảng bá `[N]`; mã nguồn Wintun GPLv2 **không** được biên dịch/liên kết.

### 11.2. Danh mục **BỊ CẤM**

| Nhóm | Cấm | Lý do / Thay bằng | Cưỡng chế |
|---|---|---|---|
| **Giấy phép** | **AGPL**, **GPL**, **LGPL**, SSPL, BUSL, CC-BY-NC, giấy phép không rõ | C5/R-15 — lây nhiễm/không tương thích | `go-licenses` (CI) |
| **Mã nguồn đối thủ** | Sao chép/phụ thuộc `github.com/netbirdio/netbird` (server AGPLv3), `tailscale.com`, `juanfont/headscale` | AGPL / phụ thuộc khổng lồ ngoài danh mục — chỉ **tham khảo thiết kế** | depguard |
| **cgo** | `mattn/go-sqlite3`, bất kỳ gói `import "C"` | ADR-001 | depguard + `scripts/check` |
| **Mật mã** | Tự viết cipher/MAC/KDF; `crypto/md5`, `sha1`, `des`, `rc4`; `math/rand` v1 cho bảo mật; import primitive ngoài `internal/secure` | SEC-02/GNFR-01 | depguard (`crypto-only-in-secure`), gosec |
| **Trùng chức năng — log** | `zap`, `zerolog`, `logrus`, package `log` | Chỉ `slog` | depguard |
| **— HTTP/router** | `gin`, `chi`, `echo`, `gorilla/mux` | Chỉ `net/http` | depguard |
| **— WebSocket** | `gorilla/websocket`, `nhooyr.io/websocket`, `x/net/websocket` | Chỉ `coder/websocket` | depguard |
| **— CLI/config** | `urfave/cli`, `viper`, YAML (`yaml.v3`) runtime | Chỉ cobra + TOML | depguard |
| **— DB** | `sqlx`, `gorm`, ORM/query-builder, `glebarez/go-sqlite` | `database/sql` + SQL thuần; chỉ `modernc` | depguard |
| **— ACME** | `certmagic`, `autocert` | Chỉ `lego` | depguard |
| **— Metrics** | `prometheus/client_golang` | Chỉ `VictoriaMetrics/metrics` | depguard |
| **— STUN** | `pion/stun`, `pion/*` | Tự viết `internal/stun` (§6.3) | review |
| **— Test** | `testify` | `testing` + `go-cmp` | depguard |
| **— ID** | `google/uuid`, `oklog/ulid` | `internal/ids` | depguard |
| **Rust/FFI/WG khác** | `gotatun` (MPL-2.0), `boringtun`, kernel-WG binding | ADR-001/002 | depguard + review |
| **Hành vi** | `InsecureSkipVerify` ngoài `internal/tlspin`; shell qua `exec`; bỏ Gatekeeper (`spctl --master-disable`) | SEC-04, PLAT-06 | `scripts/check.*`, `forbidigo` |

### 11.3. Quy tắc thêm/nâng cấp & giấy phép cho phép

1. **Allowlist giấy phép:** `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `Apache-2.0`, `ISC` (+ ngoại lệ có tên cho `wintun.dll`). **MPL-2.0 chỉ khi có ADR riêng.** Mọi thứ khác ⇒ fail.
2. **Cách thêm đúng phiên bản ghim:** `go get <module>@<phiên-bản-trong-bảng-11.1>` (không dùng `go mod tidy` để tự chọn phiên bản — đã quan sát `tidy` chọn `go-toml/v2 v2.1.0` thay vì `v2.4.3` `[V]`).
3. **Thêm thư viện mới = thay đổi kiến trúc** → dừng, báo Scrum Master/Người dùng; kèm ADR ngắn: nhu cầu, phương án trong danh mục không đáp ứng, giấy phép, số gói bắc cầu (`go list -deps`), `CGO_ENABLED=0` trên 4 đích, kích thước binary.
4. **Ứng viên chờ duyệt (KHÔNG được dùng cho tới khi người dùng duyệt):** `ebitengine/purego` (IOKit macOS), provider DNS-01 của `lego` (khi có domain), thư viện xoay vòng log (`lumberjack`), công cụ ký phát hành ngoài OpenSSH.
5. **Nâng cấp:** PR riêng `build(deps): …`, chạy đủ `scripts/check.* -Deps`; `wireguard-go` và `lego` nâng cấp kèm test tích hợp; theo dõi CVE bằng `govulncheck`.
6. **Công cụ dev** (`tools/go.mod`) tách khỏi sản phẩm và không đi vào binary release.

---

## 12. Build, phát hành & CI

| Hạng mục | Quyết định |
|---|---|
| Lệnh build | `CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build -trimpath -buildvcs=true -ldflags "-s -w -X …/buildinfo.Version=<tag>" ./cmd/<bin>` |
| Ma trận | `linux/amd64` (`mesh-server`,`meshd`,`mesh`), `darwin/arm64` + `darwin/amd64` (`meshd`,`mesh`), `windows/amd64` (`meshd`,`mesh` + `wintun.dll`) |
| macOS | Hai binary native; **không** `lipo`/`.pkg`/notarization (P2); linker Go tự ký ad-hoc `arm64` `[V]`; luồng cài bằng script kiểm `SHA256SUMS` (không gắn quarantine) |
| Toàn vẹn | `SHA256SUMS` + chữ ký tách rời bằng `ssh-keygen -Y sign` (OpenSSH có sẵn 3 OS); DevOps chốt quy trình khóa ký (ADR-011) |
| CI (cưỡng chế cùng bộ lệnh) | `lint+vet` (ubuntu) · `test-race` (ubuntu, `CGO_ENABLED=1`) · `test` ma trận `ubuntu/windows/macos` · `cross-build` (4 đích) · `deps` (`govulncheck` + `go-licenses`) |
| Hạ tầng test macOS | **Mac thật / VM trên phần cứng Apple / runner macOS** (GNFR-12) — không giả lập trong container Linux |
| Tuning runtime (khởi điểm, chỉnh sau đo US-058) | `GOMEMLIMIT`: server **96 MiB**, agent **40 MiB** (giới hạn mềm); `GOGC` mặc định |

---

## 13. Rủi ro công nghệ & Câu hỏi cho Scrum Master

| # | Rủi ro / Điểm cần biết | Mức | Giảm thiểu |
|---|---|---|---|
| T1 | `wireguard-go` **không có tag** ⇒ ghim pseudo-version; tự theo dõi bản vá | Trung bình | Ghim + `govulncheck` + watch repo; test netmap/relay khi nâng |
| T2 | Tự hiện thực **magicbind** (disco/hole punching) — độ phức tạp cao (R-16) | Cao | Walking Skeleton relay-only trước (backlog 15.2); tham khảo (không import) `magicsock` |
| T3 | **macOS không có IOKit** (cgo off) ⇒ sleep/wake kém chính xác (PERF-07) | Trung bình | PF_ROUTE + nhảy đồng hồ; đo trên MacBook; nếu thiếu ⇒ xin duyệt `purego` |
| T4 | Race detector cần cgo ⇒ dev Windows phải dùng Docker/WSL | Thấp | CI Linux bắt buộc; `check.ps1 -Race` |
| T5 | `modernc.org/sqlite` chậm hơn/ít "battle-tested" hơn C-SQLite | Thấp | Đo PERF-01; `integrity_check`; dự phòng `bbolt` |
| T6 | Windows SmartScreen cảnh báo installer chưa ký (R-11); macOS cần cài không qua trình duyệt | Trung bình | Runbook; code-signing là P2 |
| T7 | ACME `TLS-ALPN-01` chỉ trên cổng 443; chưa có provider DNS-01 | Thấp | Từ chối cấu hình có hướng dẫn; xin chọn DNS provider khi có domain |
| T8 | Tuổi của `wintun.dll` 0.14.1 (2021) và binding `wintun` (2023) | Thấp | Ổn định, dùng bởi WireGuard; DevOps xác minh bản mới trên `wintun.net` |

**Cần Scrum Master chuyển người dùng (không chặn Gate 2, quyết trước Sprint 1):**
1. **Chấp nhận stack Go** + thay đổi so với giả định cũ "Rust có sẵn trên máy" (người dùng có `rustc` nhưng chưa có `go` — bootstrap ở §4).
2. **Module path** `meshvpn.internal/mesh` (tên giữ chỗ) — có muốn đổi sang `github.com/<owner>/<repo>` không (đổi rẻ nhất trước Sprint 1).
3. **Khóa ký phát hành** (`ssh-keygen -Y`): người dùng sẽ giữ khóa riêng ở đâu (ngoài VPS)?
4. **Hạ tầng macOS để QA**: Mac thật nào (Apple Silicon + Intel) hoặc runner CI?
5. **DNS provider** (nếu sau này có domain) để bật `DNS-01`.
6. **VPS kiến trúc**: xác nhận `linux/amd64` (nếu VPS là `arm64` ⇒ thêm đích `linux/arm64`, build đã hỗ trợ).

---

## 14. Bằng chứng kiểm chứng (phiên 2026-11-12, máy dev Windows)

Probe: module tạm `probe/` (trong thư mục scratch của phiên, **không** nằm trong repo) import đủ các thư viện chủ chốt (`wireguard/{conn,device,tun}`, `modernc.org/sqlite`, `coder/websocket`, `pion/stun/v3`, `x/crypto/nacl/box`, `lego/v4`, `VictoriaMetrics/metrics`, `cobra`; thêm `go-winio`, `x/sys/windows/svc`, `winipcfg` cho Windows) và biên dịch với `CGO_ENABLED=0`, Go 1.27.4 (zip chính thức, SHA-256 khớp go.dev).

| Đích | Kết quả | Kích thước probe (`-s -w`) | Ghi chú |
|---|---|---|---|
| `linux/amd64` | ✔ build | 8.1 MB | — |
| `darwin/arm64` | ✔ build | 7.7 MB | Mach-O `arm64`, **có `LC_CODE_SIGNATURE` (≈ 62 KB), cờ ad-hoc bật** (phân tích header bằng script) |
| `darwin/amd64` | ✔ build | 8.1 MB | Mach-O `x86_64`, không có chữ ký (không bắt buộc cho amd64) |
| `windows/amd64` | ✔ build | 8.1 MB | gồm `go-winio`, `svc`, `winipcfg` |

> Kích thước probe **không đại diện** cho binary thật (trình biên dịch loại mã chết; chỉ tham chiếu ký hiệu). Mục đích: chứng minh **liên kết được trên cả 4 đích mà không cần C toolchain**, kể cả SQLite nhúng.

**Đã kiểm chứng `[V]`:** phiên bản Go + SHA-256; bản mới nhất của mọi module trên `proxy.golang.org`; giấy phép MIT/BSD-3/ISC/Apache-2.0 đọc từ LICENSE của `wireguard`, `wireguard/windows`, `wintun`, `metrics`, `coder/websocket`, `cobra`, `go-winio`, `modernc/sqlite`, `lego`, `pion/stun`; chữ ký ad-hoc Mach-O; `conn.Bind` có đúng 6 phương thức; `wintun` nạp DLL với `SEARCH_APPLICATION_DIR|SYSTEM32` và `WintunTunnelType="WireGuard"` mặc định; `-race` cần cgo; `go`/`golangci-lint` chưa có trên máy; PowerShell cắt `-modfile=tools/go.mod`; số gói bắc cầu của `pion/stun`.

**Kiểm chứng bộ công cụ cưỡng chế `[V]` (sandbox mô phỏng repo, ngoài repo):** (1) `golangci-lint config verify` đạt với `.golangci.yml`; (2) mẫu mã **xấu** bị bắt đủ: `fmt.Println`, `log`, `time.Sleep`, `panic`, `os.Exit` (ngoài `cmd/*/main.go`), `x.(T)` không kiểm, `_ = f()`, `crypto/md5`, `crypto/aes` ngoài `internal/secure`, `math/rand`, `http.Get`, `InsecureSkipVerify` ngoài `internal/tlspin` — linter báo 25 issue trên file xấu (sau khi format) và **0 issue** trên mã mẫu "tốt" (kể cả `internal/secure` dùng `crypto/aes`, `internal/tlspin` dùng `InsecureSkipVerify`, `cmd/mesh` dùng `os.Exit`); (3) `scripts/check.ps1 -Deps` chạy **PASS toàn bộ trong ≈ 66 s** (toolchain → module → repo-rules → fmt → lint ×3 OS → vet+build ×4 đích → test → `govulncheck` "No vulnerabilities found" → `go-licenses` ×3 OS); (4) mẫu vi phạm (hằng số cổng `443`, `Reveal()` ngoài danh sách, file `.go` có BOM) ⇒ `CHECK FAILED`, exit 1; (5) probe bổ sung `vishvananda/netlink` (linux), `x/net/route` + `unix.GetsockoptXucred` + `unix.IP_BOUND_IF` (darwin), `go-toml/v2`: **build OK 4 đích, `CGO_ENABLED=0`**, mọi giấy phép ∈ {MIT, BSD-2/3, Apache-2.0, ISC}. Phát hiện kỹ thuật: depguard khớp **tiền tố** (`log` chặn cả `log/slog`) ⇒ dùng `log$`/`math/rand$`; `gofumpt` xóa dòng trống trước `if err != nil`; `extra-rules` của gofumpt đã deprecated ⇒ dùng `extra.group-params/clothe-returns`; một file có BOM làm hỏng `go.mod`/Go tooling (probe đầu tiên bị lỗi `unexpected input character '\ufeff'`) ⇒ đã thêm kiểm BOM vào `scripts/check.*`.

**Mức kiểm chứng của hai script:** `scripts/check.ps1` (+ `check-licenses.ps1`, `bootstrap-toolchain.ps1` chỉ kiểm cú pháp/băm) được chạy **end-to-end** như trên. `scripts/check.sh` + `check-licenses.sh`: cú pháp **đạt `dash`** (Debian/WSL); khối "repo rules" (awk + kiểm BOM) chạy đúng trên `dash`+`mawk` (bắt đủ 4 loại vi phạm, mã sạch ⇒ rc=0); **chưa chạy end-to-end trên macOS/Linux thật** (cần Go Linux/macOS) — `agile-devops` phải chạy thử ở CI Linux/macOS ngay Sprint 1 và báo lỗi nếu có.

**Chưa kiểm chứng `[N]` (cần Sprint/QA xác nhận):** Rust cross-compile qua `cargo-zigbuild` (không chạy thử để không đổi `rustup` của người dùng); `go test -race` trong Docker `golang:1.27.4`; hiệu năng/RAM/throughput (PERF-*); điều khoản chính xác của Wintun *Prebuilt Binaries License* (đọc từ nguồn công khai, DevOps đọc lại bản kèm trong ZIP); hành vi `modernc.org/sqlite` dưới tải thực; phiên bản `wintun.dll` mới nhất.

---

## 15. Lịch sử sửa đổi

| Phiên bản | Ngày | Nội dung |
|---|---|---|
| 1.0 | 2026-11-12 | Chốt Go 1.27.4 + stack, Dependency Policy, 11 ADR, chuẩn code & cưỡng chế tự động |
