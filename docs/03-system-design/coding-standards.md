# Coding Standards — Mesh VPN (Go 1.27)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-12 |
| Phiên bản | **1.0** — Chuẩn ban hành cho Gate 2 |
| Áp dụng cho | `agile-developer`, `agile-qa`, `agile-devops` (và mọi mã Go/PowerShell/sh/SQL trong repo) |
| Liên kết | [tech-stack-decision.md](./tech-stack-decision.md) · [architecture-decision-record.md](./architecture-decision-record.md) · rule tự nạp [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) · cấu hình [`.golangci.yml`](../../.golangci.yml), [`.editorconfig`](../../.editorconfig) |
| Cưỡng chế | `scripts/check.ps1` / `scripts/check.sh` (§11) chạy cục bộ **và** trong CI; xanh 100% mới được bàn giao |

> **Nguyên tắc tối thượng:** toàn bộ repo phải đọc như do **một kỹ sư** viết. Khi tài liệu này không nói gì, làm theo *Effective Go*, *Go Code Review Comments* và *Google Go Style Guide*; khi mâu thuẫn, tài liệu này thắng. Muốn phá luật: mở ADR/hỏi Scrum Master — **không** tự `//nolint` lách luật.

---

## 0. Ngôn ngữ & Phạm vi

| Đối tượng | Ngôn ngữ |
|---|---|
| Mã nguồn, định danh, comment, thông điệp lỗi, thông điệp log, văn bản CLI, commit message, tên test | **Tiếng Anh** |
| Tài liệu trong `docs/` | Tiếng Việt (thuật ngữ kỹ thuật giữ nguyên tiếng Anh) |

Lý do: hệ sinh thái công cụ/thư viện đều tiếng Anh; nhiều Subagent chạy song song cần một ngôn ngữ chung trong mã để grep/đọc đồng nhất.

---

## 1. Formatting Rules

| Hạng mục | Quy tắc | Cưỡng chế |
|---|---|---|
| Formatter | **`gofumpt`** (superset của `gofmt`, `extra-rules: true`) + **`gci`** cho import | `golangci-lint fmt` |
| Indent | **TAB** cho `.go`, `go.mod`; **2 dấu cách** cho TOML/YAML/JSON/plist/service/sh; **4 dấu cách** cho `.sql` | `.editorconfig` |
| Độ rộng dòng | **120 cột** (tab = 4) — linter `lll` | `.golangci.yml` |
| Dấu nháy | Chuỗi Go dùng `"..."`; chuỗi nhiều dòng/regex dùng raw string `` `...` ``. TOML/JSON/YAML dùng `"` | gofumpt |
| Dấu phẩy cuối | Bắt buộc ở danh sách/struct/call **nhiều dòng** (gofmt tự thêm) | gofmt |
| Kết thúc dòng | **LF** cho mọi file (trừ `*.ps1`, `*.bat`, `*.cmd` = **CRLF**, khớp `.gitattributes`); file luôn kết thúc bằng 1 newline; không khoảng trắng thừa | `.editorconfig`, `.gitattributes` |
| Thứ tự import | 3 nhóm, cách nhau 1 dòng trống: **(1) stdlib → (2) bên thứ ba → (3) `meshvpn.internal/mesh/...`**. Cấm `import .` và alias trừ khi trùng tên (alias phải mô tả, vd. `wgdevice`). `import _` chỉ cho driver SQL tại `internal/store` | `gci`, `revive` |
| Đặt tên file | `snake_case.go`; test = `<file>_test.go`; hậu tố OS theo §2.2 | — |
| Doc comment | Mọi identifier **exported** và mọi package có comment bắt đầu bằng tên của nó (`// Registrar creates...`). Comment giải thích **vì sao**, không lặp lại **cái gì**. Không để code bị comment-out | `revive` |
| Kích thước | Hàm ≤ ~60 dòng và cyclomatic ≤ 20 (`cyclop`); file ≤ ~600 dòng; tham số ≤ 5 (quá thì gom vào struct `Options`) | `cyclop`, review |

Ví dụ import đúng:

```go
import (
	"context"
	"fmt"
	"net/netip"

	"github.com/coder/websocket"
	"golang.org/x/sync/errgroup"

	"meshvpn.internal/mesh/internal/apperr"
	"meshvpn.internal/mesh/internal/secure"
)
```

---

## 2. Naming Conventions

### 2.1. Bảng quy tắc

| Đối tượng | Quy tắc | Ví dụ |
|---|---|---|
| Thư mục / package | chữ thường, **1 từ**, không `_`/`-`, không số nhiều vô nghĩa, không `util`/`common`/`helpers` | `relay`, `netmap`, `tlspin`, `sysexec` |
| Binary (`cmd/`) | đúng tên sản phẩm, `kebab-case` | `cmd/mesh`, `cmd/meshd`, `cmd/mesh-server` |
| File | `snake_case.go` | `preauth_key.go`, `bind_linux.go` |
| Type/struct/interface | `PascalCase`; interface nhỏ, đặt ở nơi **dùng**, tên theo hành vi (`Reader`, `Clock`); **không** tiền tố `I`, hậu tố `Impl` | `NodeStore`, `Clock` |
| Hàm/method | `PascalCase` (exported) / `camelCase`; động từ; getter **không** có `Get` | `node.Name()`, `registerNode()` |
| Biến | `camelCase`; ngắn khi phạm vi ngắn (`i`, `ctx`, `err`), đầy đủ khi phạm vi rộng; viết tắt giữ chuẩn Go (`ID`, `URL`, `IP`, `TLS`, `SPKI`, `UDP`) | `nodeID`, `peerKey` |
| Hằng số | `PascalCase`/`camelCase` (không `ALL_CAPS`); nhóm bằng `const (...)`; enum dùng kiểu riêng + `iota` hoặc string-typed | `DefaultMTU = 1280` |
| Sentinel error | `ErrXxx` | `ErrPinMismatch` |
| Kiểu lỗi | `XxxError` | `*apperr.Error` |
| Receiver | 1–2 chữ cái, nhất quán trong type, không `this/self` | `func (s *Store)` |
| Context | tham số **đầu tiên**, tên `ctx`; không lưu trong struct | `func (s *Store) Node(ctx context.Context, id NodeID)` |
| Test | `Test<Unit>_<Scenario>_<Expected>` | `TestRegister_DuplicateKey_ReturnsExistingNode` |
| Biến môi trường | `MESH_` + `UPPER_SNAKE` | `MESH_AUTHKEY_FILE` |
| Khóa cấu hình TOML | `snake_case` | `control_tcp_port`, `trusted_proxies` |
| CLI | `mesh <danh-từ> <động-từ>`; cờ `--kebab-case` | `mesh preauthkey create --ttl 1h`, `--server-pin` |
| Tên service OS | lấy từ `internal/brand` (một nơi duy nhất) | launchd label, Windows service, unit systemd |
| Bảng DB | `snake_case`, **số nhiều** | `nodes`, `preauth_keys`, `audit_events` |
| Cột DB | `snake_case`; PK = `id`; FK = `<bảng_số_ít>_id`; thời điểm = `<tên>_at` (INTEGER, **Unix ms UTC**); cờ boolean = `is_<…>` (INTEGER 0/1 + `CHECK`) | `node_id`, `expires_at`, `is_ephemeral` |
| Index/ràng buộc | `idx_<bảng>_<cột>`, `uq_<bảng>_<cột>`, `ck_<bảng>_<ý>` | `uq_nodes_public_key`, `uq_nodes_overlay_ip` |
| File migration | `NNNN_<mô_tả>.sql` (4 chữ số, tăng dần, **không sửa** file đã phát hành) | `0001_init.sql` |
| Endpoint HTTP | tiền tố **`/v1/`**, danh từ số nhiều `kebab-case`, hành động bằng method HTTP; JSON field `snake_case`; **cấm** hằng số `443`/`3478` ngoài `internal/defaults` (GNFR-11) | `POST /v1/nodes`, `GET /v1/netmap/stream` |
| Endpoint quan sát | đúng `/healthz`, `/readyz`, `/metrics` (listener riêng, chỉ-đọc — SEC-14) | — |
| Tên sự kiện log (`event`) | `snake_case` dạng `<danh_từ>_<quá_khứ>` | `node_registered`, `pin_mismatch` |
| Metric | `mesh_<subsystem>_<tên>_<đơn_vị>`; counter kết thúc `_total` | `mesh_relay_bytes_total{node=...}` |
| Nhánh Git | `<type>/<us-id>-<slug>` | `feat/us-014-linux-tun` |

### 2.2. Mã đặc thù hệ điều hành (build tag) — **bắt buộc**

Mục tiêu: **logic cốt lõi chạy và test được trên cả 3 OS**; chỉ phần chạm OS mới tách file.

1. Phần **OS-neutral** (giao thức, netmap, state machine, backoff, parser, hosts-block, validator…) nằm trong file **không hậu tố** và **không** import `syscall`/`golang.org/x/sys/{unix,windows}`.
2. Phần chạm OS được đặt sau **interface nhỏ** định nghĩa trong file OS-neutral (vd. `RouteManager`, `NetMonitor`, `TunFactory`, `ServiceHost`, `PeerCred`); mỗi OS có file riêng:
   - `<tên>_linux.go`, `<tên>_darwin.go`, `<tên>_windows.go` (hậu tố GOOS — tự động ràng buộc build);
   - mã dùng chung cho Linux+macOS: `<tên>_unix.go` **kèm** dòng đầu `//go:build unix` (hậu tố `_unix` **không** tự có hiệu lực — luôn ghi `//go:build`);
   - `<tên>_other.go` với `//go:build !linux && !darwin && !windows` trả `ErrUnsupportedPlatform` (để repo luôn biên dịch).
3. Mỗi file OS-specific phải có `//go:build` **và** (nếu là hậu tố) khớp tên. Cấm `runtime.GOOS == "..."` để rẽ nhánh logic nghiệp vụ (chỉ được dùng trong chẩn đoán/log).
4. Mỗi interface OS-specific có **fake** trong `internal/<pkg>/<pkg>test` để test OS-neutral chạy trên mọi máy.
5. Test chạy trên mọi OS **không** được cần quyền root/Admin. Test cần đặc quyền gắn tag `//go:build privileged` (mặc định không chạy; QA chạy trong lab/VM/máy thật).
6. **Ma trận biên dịch** mọi PR phải qua (`CGO_ENABLED=0`): `linux/amd64`, `darwin/arm64`, `darwin/amd64`, `windows/amd64` (§11).

### 2.3. Bố cục thư mục (khung — ranh giới module chi tiết do `agile-architect` chốt)

```
cmd/mesh/            # CLI người dùng (client) + lệnh quản trị server qua kênh cục bộ
cmd/meshd/           # agent daemon (root/SYSTEM): data plane, control client, dọn dẹp
cmd/mesh-server/     # control + relay + STUN (Linux)
internal/            # TOÀN BỘ mã nằm trong internal/ (không export API ra ngoài)
  apperr/ brand/ defaults/ secure/ logx/ httpx/ ids/ clock/ backoff/ fsx/ lifecycle/ sysexec/   # xuyên suốt (Tech Lead sở hữu)
  store/ netmap/ relay/ stun/ disco/ datapath/ tlspin/ hostsblock/ ...                           # nghiệp vụ (Architect sở hữu)
migrations/          # *.sql nhúng bằng embed
scripts/             # check.ps1, check.sh, bootstrap-toolchain.ps1
tools/               # go.mod riêng: ghim golangci-lint, govulncheck (§11)
```

---

## 3. Type Safety & Error Handling

### 3.1. Cấm tuyệt đối (CI đỏ)

| Cấm | Thay bằng |
|---|---|
| `any` / `interface{}` ngoài tham số generic và `encoding/json` decode vào kiểu cụ thể | Kiểu cụ thể, generics, `json.RawMessage` + decode có kiểu |
| Ép kiểu không kiểm tra `x.(T)` | `v, ok := x.(T)` (`forcetypeassert`) |
| Nuốt lỗi: `_ = f()`, `if err != nil {}` rỗng, `catch`-kiểu bỏ qua | Xử lý, trả về, hoặc `errors.Join` khi dọn dẹp. Ngoại lệ duy nhất: `defer f.Close()` trên file **chỉ đọc** |
| `panic` trong code production (kể cả `log.Fatal`) | Trả `error`. Ngoại lệ: invariant của lập trình viên, kèm `//nolint:forbidigo // <lý do>` |
| `os.Exit` ngoài `cmd/*/main.go` | Trả error lên `main` |
| `fmt.Print*`, `println`, package `log` | `slog` qua `internal/logx` |
| `math/rand` (v1) cho bất cứ gì liên quan bảo mật | `crypto/rand` qua `internal/secure`. Jitter: `math/rand/v2` **chỉ** trong `internal/backoff` |
| `time.Sleep`, `context.TODO()`, `http.Get/DefaultClient/ListenAndServe` | `time.NewTimer` + `select` với `ctx.Done()`; `internal/httpx` có timeout tường minh |
| `net.IP`/`string` để giữ địa chỉ | `net/netip` (`netip.Addr`, `netip.AddrPort`, `netip.Prefix`) |
| `int` để giữ thời lượng | `time.Duration` (tên field có đơn vị khi tuần tự hóa: `ttl_seconds`) |
| `unsafe` | Chỉ trong gói `sys*` của từng OS, có review của Tech Lead |
| Hằng số `443`, `3478`, `1280` rải rác | `internal/defaults` (GNFR-11) |

### 3.2. Kiểu hóa miền (parse, don't validate)

- Giá trị miền có ràng buộc dùng **kiểu riêng** với constructor trả `(T, error)`: `NodeID`, `NodeName` (RFC 1123 label), `Port` (`uint16`, 1–65535), `OverlayIP`, `PublicKey` (`[32]byte`), `PinSet`, `PreAuthKeyHash`. Sau khi qua constructor, giá trị luôn hợp lệ — không kiểm tra lại rải rác.
- Khóa mật mã là **mảng cố định** (`[32]byte`), không `[]byte`/`string` trần.
- `switch` trên enum phải **exhaustive** (`exhaustive`); không `default:` che đi case thiếu.
- Mọi dữ liệu từ biên (HTTP, WebSocket, UDP, file, CLI, IPC) được **giới hạn kích thước** (`http.MaxBytesReader`, `Conn.SetReadLimit`, độ dài frame) và **parse bằng parser có kiểm biên + fuzz test**.

### 3.3. Cấu trúc lỗi thống nhất: `internal/apperr`

Mọi lỗi vượt ranh giới package là `error` thường **được bọc có ngữ cảnh** bằng `%w`; lỗi mà nghiệp vụ phải phân loại là `*apperr.Error`:

```go
// Package apperr defines the single error taxonomy shared by server, agent and CLI.
package apperr

type Kind uint8

const (
	KindInternal         Kind = iota // bug or unexpected failure; message never exposed to peers
	KindInvalidArgument              // malformed input
	KindUnauthenticated              // bad/expired/used credential — ONE public message for all (SEC-05)
	KindPermissionDenied             // authenticated but not allowed (SEC-14, PLAT-01/06)
	KindNotFound
	KindConflict
	KindRateLimited
	KindUnavailable                  // transient; caller may retry with backoff (REL-04)
	KindClockSkew                    // local clock outside certificate validity (US-003 AC5)
	KindPinMismatch                  // server key != pin (SEC-04); never retried as success
)

// Error carries a stable Kind, the operation that failed, a SAFE public message, and the cause.
type Error struct {
	Kind   Kind
	Op     string // "store.CreateNode"
	Public string // safe to send to remote peers / print in CLI; never contains secrets or internals
	Err    error  // cause; may contain internals; only logged, never sent
}

func (e *Error) Error() string { /* "op: public: cause" */ }
func (e *Error) Unwrap() error { return e.Err }
```

Quy tắc:

1. **Bọc có ngữ cảnh:** `return fmt.Errorf("register node %s: %w", id, err)`. Thông điệp **chữ thường, không dấu chấm cuối**, không bắt đầu bằng "failed to"; mô tả hành động đang làm.
2. **Xử lý đúng một lần:** hoặc **log** hoặc **trả về** — không cả hai. Chỉ tầng biên (handler, `main`, vòng lặp nền) mới log lỗi.
3. Phân loại bằng `errors.Is/As` (`errorlint`); **cấm** so khớp chuỗi `err.Error()`.
4. Ánh xạ cố định: `Kind` → HTTP status, → mã thoát CLI, → mã lỗi giao thức. `Public` của `KindUnauthenticated` là **một chuỗi duy nhất** (không phân biệt "key sai" / "key hết hạn" — SEC-05).
5. Lỗi từ thư viện mật mã/DB **không** được lộ ra ngoài biên mạng; chỉ `Public` được gửi.
6. Dọn dẹp nhiều bước dùng `errors.Join`; không dừng giữa chừng khi một bước dọn dẹp lỗi (REL-08).
7. `recover()` chỉ ở ranh giới goroutine trong `internal/lifecycle` (log stack + kích hoạt shutdown có kiểm soát), **không** nuốt panic rồi chạy tiếp.

### 3.4. Biên mạng & dữ liệu ngoài

- Mọi `net.Conn`/HTTP/WebSocket có **deadline/timeout tường minh** (GNFR-03): connect ≤ 10 s, stream có heartbeat ≤ 60 s.
- SQL **chỉ** tham số hóa (`?`); cấm nối chuỗi vào câu SQL (`gosec` G201/G202). Không ORM.
- Không giả định cứng cổng/địa chỉ server (GNFR-11): lấy từ cấu hình/netmap.

### 3.5. Thời gian & ngẫu nhiên

- Mọi chỗ đọc giờ đi qua `clock.Clock` (inject) để test tất định; mọi thời điểm lưu/ truyền là **UTC**.
- Test thời gian dùng `testing/synctest` (bubble) thay vì `Sleep`.

### 3.6. Bảo vệ khỏi tràn số (thay cho `gosec G115`)

`G115` bị tắt vì nhiễu trong parser gói tin. Bù lại: mọi chuyển đổi số nguyên trong parser phải đứng **sau** kiểm biên tường minh và có **fuzz test** cho parser đó.

---

## 4. Concurrency & Vòng đời (graceful shutdown ≤ 5 s — `US-055`)

1. **Mọi goroutine nền** phải: (a) nhận `context.Context`, (b) thoát khi `ctx.Done()`, (c) được khởi chạy qua `lifecycle.Group` (bọc `golang.org/x/sync/errgroup` + recover + đặt tên) để có thể `Wait` khi tắt. Cấm `go func(){...}()` trần trong code production (review chặn; `goleak` bắt rò rỉ trong test).
2. **Ngân sách tắt máy tổng ≤ 5 s** (SIGTERM / `launchctl bootout` / Windows Service Stop): `T+0` ngừng nhận kết nối/ghi netmap → `T+≤1 s` đóng WebSocket/relay & báo offline → `T+≤4 s` gỡ route/hosts/`utunN`/adapter theo **sổ cái tài nguyên** (§5.6) → `T+5 s` hết hạn: log `shutdown_deadline_exceeded` và thoát (launchd/systemd/SCM còn timeout riêng). Mỗi `Close(ctx)` nhận context có hạn.
3. Mọi `time.Ticker`/`time.Timer` phải `Stop()`; mọi vòng lặp dùng `select { case <-ctx.Done(): ...; case <-t.C: ... }`.
4. **Không queue không giới hạn**: channel có dung lượng; hàng đợi relay per-destination có **trần** và **drop-tail không chặn** (ADR-004). Người gửi đóng channel; không bao giờ đóng channel từ phía nhận.
5. **Không giữ mutex khi làm I/O** (mạng, đĩa, `exec`). Ghi chú thứ tự khóa ở doc của type khi có >1 mutex. Dùng `sync/atomic` types (`atomic.Int64`, `atomic.Pointer[T]`) thay vì thao tác trên số nguyên trần.
6. Retry chỉ cho thao tác **idempotent**, dùng `internal/backoff` (base 1 s, ×2, trần 60 s — control stream trần 5 phút theo `US-034`, full jitter, reset sau ≥ 60 s ổn định; REL-04).
7. Dữ liệu chia sẻ giữa goroutine là **bất biến sau khi publish** (netmap = snapshot immutable thay bằng `atomic.Pointer`), không sửa tại chỗ.
8. **Race detector là bắt buộc** (`go test -race`) — xem §11 về cách chạy trên Windows.

---

## 5. Security & Logging Hygiene

### 5.1. Kiểu khóa bọc (`Redacted Secret Types`) — **SEC-01, bắt buộc**

Mọi bí mật (private key node/disco/server, pre-auth key thô, token, WireGuard preshared) **chỉ** tồn tại dưới các kiểu của `internal/secure`. Các kiểu này **tự ẩn giá trị** ở **mọi** đường format/serialize:

```go
// PrivateKey is a Curve25519 private key. The zero value is invalid.
type PrivateKey struct{ b [32]byte } // unexported field: no reflection-based dump by other packages' fmt of fields

func (PrivateKey) String() string                { return "[REDACTED]" }
func (PrivateKey) GoString() string              { return "secure.PrivateKey([REDACTED])" }
func (PrivateKey) Format(f fmt.State, _ rune)    { fmt.Fprint(f, "[REDACTED]") } // %v %+v %#v %s %q %x %d
func (PrivateKey) LogValue() slog.Value          { return slog.StringValue("[REDACTED]") }
func (PrivateKey) MarshalText() ([]byte, error)  { return []byte("[REDACTED]"), nil }
func (PrivateKey) MarshalJSON() ([]byte, error)  { return []byte(`"[REDACTED]"`), nil }
func (*PrivateKey) UnmarshalJSON([]byte) error   { return errSecretFromJSON } // never read secrets from JSON
func (k PrivateKey) Reveal() [32]byte            { return k.b }                // restricted callers only (below)
```

Quy tắc:

1. **Không** có field `string`/`[]byte`/`[32]byte` trần mang bí mật trong struct, DTO, config, log attr, lỗi, bundle chẩn đoán. Có bí mật trong struct phải dùng kiểu bọc.
2. `Reveal()` chỉ được gọi trong `internal/secure/**`, `internal/keystore/**` (ghi file khóa), `internal/datapath/wgcfg/**` (nạp khóa vào WireGuard) và — **cho đúng một lần in pre-auth key khi tạo** — `internal/adminapi/**`, `cmd/mesh/**`. Nơi khác gọi `Reveal` = lỗi review **và** `scripts/check.*` fail (bước "repo rules").
3. Cấu hình WireGuard qua UAPI (`IpcSet`) chứa khóa dạng hex: **không bao giờ** log/đưa vào lỗi chuỗi cấu hình đó. Logger của `wireguard-go` (`device.Logger`) được thay bằng adapter `slog` mức ≥ `error`, qua `logx` redaction.
4. Pre-auth key: ≥ 256 bit từ `crypto/rand`; DB chỉ lưu **SHA-256** (`PreAuthKeyHash`), tra cứu theo digest + so sánh `crypto/subtle.ConstantTimeCompare`. Bản thô chỉ hiển thị **một lần**.
5. **Không nhận bí mật qua argv** (lộ trong danh sách tiến trình): dùng `--authkey-file`, stdin hoặc `MESH_AUTHKEY_FILE`/`MESH_AUTHKEY` (US-004).
6. **Test canary bắt buộc** (`TestNoSecretsInOutputs`): chạy kịch bản đăng ký/relay/rotate/bundle với bí mật mẫu dạng `CANARY_...`, chụp log + DB + wire + bundle + `status`, và `strings.Contains` = 0 (GNFR-02, US-043 AC2/AC4, kể cả mức `debug`).

### 5.2. Mật mã (SEC-02, GNFR-01)

- **Cấm tự cài** cipher/MAC/KDF/ký/RNG. Mọi primitive: `crypto/*` stdlib hoặc `golang.org/x/crypto/*` — và **chỉ import trong `internal/secure/**`** (depguard `crypto-only-in-secure`). Nơi khác gọi API cấp cao: `secure.NewNodeKey()`, `secure.SealChallenge()`, `secure.OpenDisco()`, `secure.HashPreAuthKey()`.
- Ngẫu nhiên bảo mật: `crypto/rand` (`secure.RandomBytes`). So sánh bí mật: `subtle.ConstantTimeCompare`. Băm: SHA-256 (cấm MD5/SHA-1).
- Control: **TLS 1.3 tối thiểu** (`MinVersion: tls.VersionTLS13`) + chứng minh khóa node bằng challenge server-generated (ADR-003). Disco: NaCl box + `disco_key` + `tx_id` ngẫu nhiên, bảng tx đang chờ có TTL (chống phát lại).

### 5.3. TLS & Pinning (SEC-04)

- **Không** có cờ/biến môi trường/cấu hình bỏ qua kiểm tra chứng chỉ ở bản release. `InsecureSkipVerify` **chỉ** xuất hiện trong `internal/tlspin` (nơi hiện thực kiểm tra pin SPKI trong `VerifyConnection`, **fail-closed** nếu tập pin rỗng). `scripts/check.*` đếm: xuất hiện ở file khác ⇒ **fail**.
- Cấm TOFU ngầm; client không có pin và không ở chế độ CA ⇒ từ chối trước khi gửi bất kỳ secret nào.

### 5.4. Quyền file & kênh Admin (SEC-01(c), SEC-14, PLAT-01/06)

- Ghi file nhạy cảm **chỉ** qua `fsx.WriteFileAtomic(path, data, perm)` (file tạm cùng thư mục → `fsync` → `rename`; `0600`/thư mục `0700`; Windows: ACL chỉ SYSTEM + Administrators qua `internal/winacl`). Cấm `os.WriteFile` cho secret/hosts/state.
- **Cấm** mở Admin API trên TCP (kể cả `127.0.0.1`), IP overlay hay IP public. Kênh Admin = Unix Domain Socket (`0600/0660`) + kiểm tra peer credential trong `ConnContext` (Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED`), hoặc named pipe + SDDL (Windows). Listener `/healthz` `/readyz` `/metrics` là **listener riêng, chỉ-đọc**, không route thay đổi trạng thái. `net.Listen("tcp"...)` chỉ được xuất hiện trong `internal/httpx` và gói listener công khai/quan sát (script kiểm tra).
- Mọi thao tác Admin ghi **audit** (UID/SID người gọi) — `SEC-09`.

### 5.5. Gọi lệnh ngoài (`internal/sysexec`)

Chỉ qua `sysexec.Run(ctx, cmd, args...)`: `exec.CommandContext`, **đường dẫn tuyệt đối**, **không shell**, đối số dựng từ kiểu đã validate, có timeout, stdout/stderr bị giới hạn và đã lọc secret. **Danh mục được phép:**

| OS | Lệnh được phép (đường dẫn cố định) |
|---|---|
| macOS | `/sbin/route`, `/sbin/pfctl` (anchor riêng), `/usr/bin/dscacheutil`, `/usr/bin/killall` (chỉ `-HUP mDNSResponder`), `/usr/libexec/ApplicationFirewall/socketfilterfw`, `/bin/launchctl`, `/usr/sbin/scutil` (chỉ đọc), `/sbin/ifconfig` (chỉ đọc) |
| Windows | `%SystemRoot%\System32\netsh.exe`, `...\ipconfig.exe` (`/flushdns`), `...\route.exe` |
| Linux | `/usr/sbin/nft`, `/usr/sbin/iptables`, `/usr/sbin/ufw` (chỉ đường firewall opt-in), `/usr/bin/systemctl` (chỉ cài đặt) — route/addr/rule dùng **netlink**, không `ip` |

Lệnh ngoài danh mục ⇒ phải có ADR/duyệt Gate.

### 5.6. An toàn máy thật: route, hosts, interface (G4 — không làm hỏng mạng máy thật)

1. **Sổ cái tài nguyên (resource ledger):** mọi thứ agent tạo (tên `utunN`/adapter/`mesh0`, route, khối hosts, anchor `pf`, rule firewall, ngoại lệ ALF) được ghi **trước khi tạo** vào tệp trạng thái `0600` (ghi nguyên tử). Dọn dẹp lúc dừng/khởi động lại **chỉ** dựa trên sổ cái — **cấm** đoán theo tên/số (`utun*`) hay xóa theo mẫu.
2. **Hosts:** chỉ sửa trong khối `# BEGIN mesh … # END mesh`; không chạm ngoài khối; ghi nguyên tử trên **đường dẫn thật** (macOS: `/etc/hosts` là symlink → resolve), giữ owner/mode/ACL; bind-mount (container) → fallback ghi tại chỗ có khóa; xả cache DNS sau khi ghi; **chặn tên cấm** (`localhost`, `broadcasthost`, `wpad`, `isatap`, `local`, hostname/domain của Control/Relay/STUN) và **không ánh xạ tới IP public của VPS**; tên node phải qua `NodeName` (RFC 1123, từ chối `\n`, `#`, khoảng trắng) ở **cả server lẫn agent**.
3. **Route:** chỉ cài route cho **dải overlay** vào đúng interface của agent; **không** default route (MVP); kiểm tra xung đột dải (REL-14).
4. **Chống routing loop (REL-09, ADR-007):** socket UDP/TCP của agent bị ràng vào interface vật lý (Linux `SO_MARK` + policy rule; macOS `IP_BOUND_IF`/`IPV6_BOUND_IF`; Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`) và ràng lại khi interface mặc định đổi; lọc endpoint ứng viên thuộc dải overlay.
5. **macOS:** không đụng `utun`/route/pf/ALF không thuộc sổ cái; không `spctl --master-disable`; không flush `/etc/pf.conf`. **Windows:** `wintun.dll` kiểm SHA-256 cố định trước khi nạp; adapter tên cố định. **Linux:** không ghi đè `/etc/resolv.conf`.
6. Binary + plist/service/unit nằm ở đường dẫn **chỉ root/Administrators ghi được**; cấm để daemon đặc quyền nạp binary từ thư mục user ghi được.

### 5.7. Structured logging (OPS-01, US-043)

- Chỉ `log/slog` qua `internal/logx` (handler JSON, ghi stderr/file xoay vòng). Message là **hằng tĩnh** (`sloglint static-msg`); dữ liệu động đi vào attr **snake_case** dạng key-value; dùng `...Context(ctx, ...)` để mang `request_id`.
- **Trường bắt buộc** mọi dòng: `ts` (UTC RFC 3339), `level`, `component` (= tên module: `control`, `relay`, `stun`, `disco`, `wg`, `dns`, `route`, `store`, `admin`, `tls`, `lifecycle`…), `event`. Khi có: `request_id` (sinh ở biên, tái dùng làm `conn_id` cho kết nối dài), `node_id`, `peer_id`, `err`.
- **Cấm log:** private key, pre-auth key, token, challenge/nonce proof, nội dung gói tin, cấu hình UAPI WireGuard, header `Authorization`, body request đăng ký. Endpoint IP của peer: chỉ ở mức `debug` hoặc audit. Danh sách `forbidden-keys` đã ghi trong `.golangci.yml`; bundle chẩn đoán dùng **allowlist** trường (không phải denylist).
- Mức log: `error` (cần người xử lý), `warn` (tự hồi phục được/đáng chú ý, vd. `pin_mismatch`), `info` (sự kiện vòng đời), `debug` (mặc định tắt; **vẫn** không secret). Không log trong vòng lặp nóng theo gói tin ở mức `info`.
- Audit log (SEC-09) là kênh riêng append-only (bảng `audit_events`), không chứa secret.

---

## 6. Cấu hình & Phiên bản

- Cấu hình server/agent: **TOML** (`go-toml/v2`, **`DisallowUnknownFields`**), kiểu cấu hình tường minh, mặc định tập trung ở `internal/defaults`; không `viper`, không YAML.
- Trạng thái máy (khóa, sổ cái, netmap cache): JSON qua `fsx.WriteFileAtomic`; có trường `schema_version`.
- Phiên bản build: `-ldflags "-X meshvpn.internal/mesh/internal/buildinfo.Version=..."` + `debug.ReadBuildInfo()`; client gửi `protocol_version`, `agent_version`, `os`, `arch` (OPS-10).

---

## 7. Testing

| Quy tắc | Chi tiết |
|---|---|
| Framework | stdlib `testing` + `github.com/google/go-cmp/cmp` (so sánh/diff) + `go.uber.org/goleak`. **Cấm** `testify` |
| Cấu trúc | **Arrange – Act – Assert**: test đơn lẻ dùng chú thích `// Arrange`, `// Act`, `// Assert`. Test bảng (**table-driven**) là mặc định cho logic có nhiều trường hợp. *Lưu ý `gofumpt` xóa dòng trống đứng ngay trước kiểm tra lỗi đơn giản (`if err != nil`) — đừng dựa vào dòng trống để tách Act/Assert, hãy dựa vào comment* |
| Tên | `Test<Unit>_<Scenario>_<Expected>`; subtest `t.Run(tc.name, …)` với `name` mô tả tiếng Anh ngắn |
| Song song | `t.Parallel()` mặc định; bỏ khi chạm tài nguyên toàn cục (ghi chú lý do). Đọc lại biến vòng lặp không cần `tc := tc` (Go ≥ 1.22) |
| Tất định | Inject `clock.Clock`, nguồn ngẫu nhiên, filesystem (`fsx`), `sysexec` fake. **Không `time.Sleep`**; dùng `testing/synctest` |
| Race | `go test -race` bắt buộc trước bàn giao (xem §11) |
| Rò goroutine | Mỗi package có goroutine nền: `TestMain` gọi `goleak.VerifyTestMain` |
| Fuzz | Parser (STUN, disco, relay frame, hosts-block, `NodeName`, netmap decode, config) **phải có** `FuzzXxx`; CI chạy corpus seed; nightly chạy `-fuzztime=60s` |
| Tầng test | **unit** (mặc định, mọi OS, không đặc quyền) · `//go:build integration` (nhiều tiến trình/SQLite/WebSocket thật, lab container) · `//go:build privileged` (TUN/route/launchd/SCM — cần root/Admin/VM) · e2e do `agile-qa` |
| Test theo OS | `<tên>_windows_test.go`, `_darwin_test.go`, `_linux_test.go`; phần OS-neutral test trên cả 3 OS trong CI |
| Dữ liệu | Fixture ở `testdata/`; golden file cập nhật bằng cờ `-update`; bí mật mẫu luôn là chuỗi canary rõ ràng, không dùng khóa thật |
| Độ phủ mục tiêu | `internal/secure`, `internal/apperr`, parser: **≥ 90%**; còn lại **≥ 75%** (chỉ số tham khảo, không thay cho AC) |
| Mỗi AC của story | Có ít nhất 1 test truy vết được (`// US-0xx AC2` trong tên/ghi chú test) |

---

## 8. Git & Review

**Conventional Commits** (tiếng Anh, thức mệnh lệnh, chủ đề ≤ 72 ký tự, không dấu chấm):

```
<type>(<scope>): <subject>

[body: vì sao + cách tiếp cận; wrap 100 cột]

Refs: US-014, SEC-14
[BREAKING CHANGE: ...]
```

- `type`: `feat` `fix` `perf` `refactor` `test` `docs` `build` `ci` `chore` `revert` `security`.
- `scope`: `control` `agent` `relay` `stun` `disco` `wg` `dns` `route` `store` `admin` `tls` `cli` `win` `mac` `linux` `ci` `deps` `docs`.
- Ví dụ: `feat(tls): pin server SPKI in IP mode`, `fix(route): clean only ledger-owned utun on startup`.
- Một PR = một story (hoặc một phần story độc lập); PR nhỏ, **squash merge**; **không** `git push --force`/`reset --hard` lên nhánh chính. Cấm commit artifact build, khóa, DB, `.env` (đã chặn trong `.gitignore`).
- **Checklist PR (DoD tối thiểu):** `scripts/check.*` xanh · test cho mỗi AC · không secret (test canary) · không hằng số cổng · tài liệu CLI/runbook cập nhật nếu đổi hành vi · dependency mới đã có ADR (§9).

---

## 9. Dependency Policy — tóm tắt cưỡng chế

Danh mục đầy đủ (phiên bản, giấy phép, phạm vi) ở [tech-stack-decision.md §11](./tech-stack-decision.md). Quy tắc làm việc:

1. **Chỉ** import thư viện nằm trong danh mục **Được phép**. Muốn thêm: **dừng**, báo Scrum Master (đây là thay đổi kiến trúc — cần người dùng duyệt), kèm ADR ngắn (nhu cầu, phương án trong danh mục không đáp ứng, giấy phép, kích thước phụ thuộc bắc cầu, hỗ trợ `CGO_ENABLED=0` trên 4 target).
2. **Một chức năng — một thư viện.** Không thêm thư viện thứ hai cho cùng chức năng (HTTP, WebSocket, log, CLI, config, SQLite, ACME, metrics, ID…).
3. **Giấy phép cho phép:** MIT, BSD-2/3, Apache-2.0, ISC. **Cấm:** AGPL, GPL, LGPL, SSPL, BUSL, CC-BY-NC và giấy phép không rõ; **MPL-2.0** chỉ khi ADR riêng cho phép. **Ngoại lệ có điều kiện duy nhất:** `wintun.dll` (Prebuilt Binaries License — phân phối nguyên vẹn, kèm phần mềm của ta, kiểm SHA-256).
4. **Cấm tuyệt đối** phụ thuộc/sao chép mã `AGPL` (mã server NetBird…) hay GPL lây nhiễm. CI chạy kiểm giấy phép (`tools` — §11) trên toàn bộ phụ thuộc bắc cầu.
5. Mọi dependency **ghim phiên bản** trong `go.mod` (`go.sum` được commit); nâng cấp qua PR riêng `build(deps): ...`; `govulncheck` phải sạch.
6. `CGO_ENABLED=0` là bất biến: thư viện kéo theo cgo ⇒ bị loại.

---

## 10. Bộ lệnh Kiểm định Chuẩn (Standard Check Commands)

**Một lệnh cho tất cả** (khuyến nghị — chạy đúng chuỗi dưới đây, bên trong gọi các lệnh gốc):

| Nền tảng dev | Lệnh |
|---|---|
| Windows (PowerShell) | `pwsh -File scripts/check.ps1` (hoặc `powershell -File scripts/check.ps1`) |
| macOS / Linux | `sh scripts/check.sh` |

Các bước (mỗi bước **phải xanh 100%**; chạy từ gốc repo; đặt `CGO_ENABLED=0` trừ bước race):

| # | Bước | Lệnh gốc |
|---|---|---|
| 0 | Toolchain đúng phiên bản | `go version` phải là `go1.27.4` (hoặc bản vá 1.27.x mới hơn đã được Tech Lead nâng) |
| 1 | Module sạch | `go mod verify` · `go mod tidy -diff` |
| 2 | **Format check** | `go tool '-modfile=tools/go.mod' golangci-lint fmt --diff` *(PowerShell: **phải** đặt dấu nháy quanh `-modfile=…`, nếu không PowerShell cắt đối số tại dấu chấm — đã kiểm chứng; `scripts/check.*` xử lý sẵn)* |
| 3 | **Lint** (chạy cho từng OS đích) | `GOOS=linux\|darwin\|windows go tool -modfile=tools/go.mod golangci-lint run ./...` *(`run` đã gồm kiểm gofumpt + gci; tool được build ở host rồi chạy với `GOOS` đích — `go tool -n` lấy đường dẫn)* |
| 4 | **Typecheck / vet + build ma trận 4 đích** | `go vet ./...` và `go build ./...` với `GOOS/GOARCH` ∈ {`linux/amd64`, `darwin/arm64`, `darwin/amd64`, `windows/amd64`} |
| 5 | Quy tắc cấm bổ sung | `scripts/check.*` (InsecureSkipVerify ngoài `tlspin`, hằng số cổng, `net.Listen("tcp"` ngoài gói cho phép, `Reveal()` ngoài danh sách) |
| 6 | **Unit test** | `go test -shuffle=on -count=1 -timeout 5m ./...` |
| 7 | **Race** | `go test -race -shuffle=on -count=1 -timeout 10m ./...` (xem lưu ý) |
| 8 | Lỗ hổng & giấy phép *(CI bắt buộc; local khi đổi dependency)* | `go tool -modfile=tools/go.mod govulncheck ./...` · kiểm giấy phép `go-licenses check` cho từng `GOOS` (`scripts/check.* -Deps` / `--deps`; allowlist MIT, BSD-2/3, Apache-2.0, ISC) |

> **Lưu ý race:** Go race detector **cần cgo + trình biên dịch C** (đã xác nhận: `go: -race requires cgo` khi `CGO_ENABLED=0`; máy dev Windows không có `gcc`) — **trái** với bất biến `CGO_ENABLED=0`. Vì vậy bước 7 chạy **ở Linux** (CI `ubuntu-latest`, hoặc WSL/Docker `golang:1.27.4`) và `scripts/check.ps1 -Race` tự chuyển sang Docker nếu có. Bước 7 **không** được bỏ qua khi bàn giao: Developer trên Windows phải chạy qua `-Race` (Docker/WSL) hoặc chứng minh CI Linux xanh. Bước 6 vẫn chạy trên native Windows/macOS để bắt lỗi theo OS.

CI (devops dựng, **cưỡng chế cùng bộ lệnh**): job `lint+vet` (ubuntu), job `test-race` (ubuntu), job `test` ma trận `ubuntu/windows/macos-latest` (macOS runner chạy native `arm64`; `amd64` qua Rosetta/`macos-13` nếu còn), job `cross-build` (Linux, build 4 đích + `SHA256SUMS`), job `deps` (`govulncheck` + giấy phép). Test `privileged` chạy ở lab riêng (QA).

---

## 11. Phụ lục — Khung mã quy chuẩn (normative skeletons)

### 11.1. Vòng đời goroutine

```go
// Group runs named background tasks that all stop when ctx is cancelled.
type Group struct{ /* errgroup.Group + logger + recover wrapper */ }

func (g *Group) Go(name string, fn func(ctx context.Context) error)
func (g *Group) Shutdown(ctx context.Context) error // waits ≤ ctx deadline; logs stragglers
```

### 11.2. Mẫu test bảng + AAA

```go
func TestNodeName_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid label", input: "macbook-pro"},
		{name: "newline injection", input: "evil\n1.2.3.4 bank.example", wantErr: true},
		{name: "reserved localhost", input: "localhost", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Act
			_, err := hostsblock.ParseNodeName(tc.input)
			// Assert
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseNodeName(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}
```

### 11.3. Đóng gói lỗi tại biên

```go
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	node, err := h.svc.Register(r.Context(), req)
	if err != nil {
		h.fail(w, r, err) // maps *apperr.Error Kind → status; logs cause once; sends only Public
		return
	}
	h.ok(w, http.StatusCreated, node)
}
```

---

## 12. Lịch sử sửa đổi

| Phiên bản | Ngày | Nội dung |
|---|---|---|
| 1.0 | 2026-11-12 | Ban hành lần đầu theo quyết định Gate 1 (Go 1.27, `CGO_ENABLED=0`, macOS + Windows client, Ubuntu VPS) |
