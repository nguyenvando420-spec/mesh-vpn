---
trigger: always_on
---

# Mesh VPN — Coding Standards (BẮT BUỘC cho mọi Subagent)

Chuẩn đầy đủ: `docs/03-system-design/coding-standards.md` · Stack/thư viện: `docs/03-system-design/tech-stack-decision.md` · ADR: `docs/03-system-design/architecture-decision-record.md`. Cấu hình công cụ: `.golangci.yml`, `.editorconfig`, `tools/go.mod`. **Không tự `//nolint` để lách luật. Việc ngoài danh mục/kiến trúc ⇒ DỪNG, báo Scrum Master.**

## 1. Stack chốt (không tự đổi)
- **Go 1.27.4**, module `meshvpn.internal/mesh`, **`CGO_ENABLED=0` luôn luôn**. Build ra 4 đích: `linux/amd64`, `darwin/arm64`, `darwin/amd64`, `windows/amd64`. 3 binary: `cmd/mesh` (CLI), `cmd/meshd` (agent root/SYSTEM), `cmd/mesh-server` (control+relay+STUN, Linux). Toàn bộ mã nằm trong `internal/`.
- **Chỉ dùng thư viện được phép** (một chức năng = một thư viện): stdlib (`net/http` + `ServeMux`, `log/slog`, `crypto/*`, `database/sql`, `net/netip`, `embed`), `golang.zx2c4.com/wireguard` (+`/tun`,`/conn`), `golang.org/x/{crypto,sys,net,sync,time}`, `modernc.org/sqlite`, `github.com/coder/websocket`, `github.com/spf13/cobra`, `github.com/pelletier/go-toml/v2`, `github.com/go-acme/lego/v4`, `github.com/VictoriaMetrics/metrics`, `github.com/Microsoft/go-winio` (windows), `github.com/vishvananda/netlink` (linux), `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg` (windows), `github.com/google/go-cmp/cmp`, `go.uber.org/goleak` (test). Danh mục đầy đủ + phiên bản: tech-stack-decision §11.
- **CẤM**: AGPL/GPL/LGPL (cấm tuyệt đối mã server NetBird/AGPL), cgo & `mattn/go-sqlite3`, ORM/sqlx/gorm, `testify`, `zap/zerolog/logrus`/package `log`, `gorilla|nhooyr websocket`, gin/chi/echo/mux, urfave/cli, viper, YAML runtime config, `google/uuid`/`ulid`, `prometheus/client_golang`, certmagic/autocert, `tailscale.com`, `math/rand` (v1), MD5/SHA-1/DES/RC4, tự viết cipher/MAC/KDF.

## 2. Format & đặt tên
- Format: `gofumpt` + `gci` (import: stdlib → bên thứ ba → `meshvpn.internal/mesh/...`); tab; dòng ≤ 120; LF (`.ps1/.bat/.cmd` = CRLF); **UTF-8 KHÔNG BOM** (BOM làm hỏng `go.mod`; `check` sẽ fail). Code/comment/log/lỗi/commit bằng **tiếng Anh**.
- Package: 1 từ thường, cấm `util/common/helpers`. File `snake_case.go`. Type `PascalCase`; hằng `PascalCase` (không ALL_CAPS); sentinel `ErrXxx`; ctx là tham số đầu, không lưu trong struct; getter không có `Get`.
- DB: bảng/cột `snake_case`, bảng số nhiều, PK `id`, FK `<bảng_số_ít>_id`, thời điểm `*_at` (INTEGER Unix ms UTC), index `idx_/uq_/ck_`. API: `/v1/<danh-từ-số-nhiều>` kebab-case, JSON `snake_case`. Config TOML `snake_case`, env `MESH_*`, CLI `mesh <noun> <verb> --kebab-flag`. Log `event` = `noun_verb` snake_case. Tên service OS lấy từ `internal/brand`.
- **Mã theo OS**: logic cốt lõi OS-neutral (không import `syscall`/`x/sys`); chạm OS đặt sau interface nhỏ trong file riêng `_linux.go` / `_darwin.go` / `_windows.go` (dùng chung Linux+macOS: `_unix.go` **kèm** `//go:build unix`; fallback `_other.go`). Cấm `runtime.GOOS` rẽ nhánh nghiệp vụ. Mỗi interface OS có fake để test chạy mọi OS; test cần root/Admin gắn `//go:build privileged`.

## 3. Lỗi & kiểu (CI đỏ nếu vi phạm)
- Cấm: `any`/`interface{}` (trừ generic), `x.(T)` không `ok`, nuốt lỗi (`_ = f()`, `if err != nil {}`), `panic`, `os.Exit` ngoài `cmd/*/main.go`, `fmt.Print*`/`log.*`, `time.Sleep`, `context.TODO`, `http.Get/DefaultClient/ListenAndServe`, `net.IP`/string cho địa chỉ (dùng `net/netip`), `unsafe` ngoài gói `sys*`.
- Lỗi: bọc `fmt.Errorf("verb noun: %w", err)` (chữ thường, không dấu chấm), **xử lý một lần** (log HOẶC return), `errors.Is/As`, không so chuỗi lỗi. Phân loại bằng `*apperr.Error{Kind,Op,Public,Err}`; chỉ `Public` được gửi ra ngoài; xác thực sai trả **một** thông điệp duy nhất (SEC-05).
- Kiểu miền có constructor `(T, error)` (`NodeName` RFC1123, `Port`, `OverlayIP`, `PublicKey [32]byte`…). Thời lượng = `time.Duration`; giờ qua `clock.Clock`, luôn UTC. Mọi dữ liệu biên (HTTP/WS/UDP/file/IPC) có **giới hạn kích thước**, parser kiểm biên + `FuzzXxx`. SQL **chỉ tham số hóa**.

## 4. Concurrency / vòng đời (graceful shutdown ≤ 5 s)
- Mọi goroutine nền nhận `ctx`, thoát khi `ctx.Done()`, chạy qua `lifecycle.Group`; không `go func(){}` trần. Timer/Ticker phải `Stop()`. Không queue không giới hạn (relay: hàng đợi có trần, drop-tail không chặn). Không giữ mutex khi I/O. Mọi I/O mạng có timeout (connect ≤ 10 s, heartbeat ≤ 60 s). Retry chỉ cho thao tác idempotent qua `internal/backoff` (full jitter). Dừng: gỡ route/hosts/interface theo **sổ cái tài nguyên**.

## 5. Bảo mật khóa & log (SEC-01, SEC-02, SEC-04, SEC-14)
- **Mọi bí mật** (private key, pre-auth key thô, token, preshared) CHỈ tồn tại dưới `secure.PrivateKey/PreAuthKey…`: `String/GoString/Format/LogValue/MarshalJSON/MarshalText` → `[REDACTED]`, `UnmarshalJSON` → lỗi. **Không** field `string/[]byte/[32]byte` trần mang bí mật. `Reveal()` chỉ trong `internal/secure`, `keystore`, `datapath/wgcfg` (+ in key một lần ở `adminapi`, `cmd/mesh`). Không bí mật qua argv (dùng file/stdin/env). **Không log/lỗi/bundle** chứa key, nonce-proof, UAPI WireGuard, `Authorization`. Test canary `TestNoSecretsInOutputs` phải xanh.
- Mật mã chỉ import trong `internal/secure/**` (depguard). Control = TLS ≥ 1.3 + challenge NaCl box; random = `crypto/rand`; hash = SHA-256; so sánh bí mật = `subtle.ConstantTimeCompare`. Pre-auth key DB chỉ lưu SHA-256.
- **Không bỏ qua kiểm tra chứng chỉ**: `InsecureSkipVerify` chỉ trong `internal/tlspin` (SPKI pin, fail-closed). Cấm TOFU. Không giả định cứng cổng `443`/`3478` (chỉ `internal/defaults`).
- **Admin (SEC-14)**: chỉ Unix socket (`0600/0660` + `SO_PEERCRED`/`LOCAL_PEERCRED`) hoặc named pipe SDDL; **cấm** listener admin trên TCP/loopback/overlay/public. `/healthz /readyz /metrics` = listener riêng chỉ-đọc. File nhạy cảm ghi bằng `fsx.WriteFileAtomic` (`0600`; Windows ACL SYSTEM+Administrators).
- **Máy thật**: chỉ sửa trong khối `# BEGIN mesh … # END mesh` của hosts (ghi nguyên tử trên đường dẫn thật, giữ owner/mode/ACL; chặn `localhost, wpad, isatap, broadcasthost`, hostname Control/Relay/STUN; từ chối tên có `\n`/`#`/khoảng trắng). **Không chạm gì ngoài khối đó.** Chỉ route dải overlay, không default route. **Chống routing loop**: ràng socket vào NIC vật lý (Linux `SO_MARK`, macOS `IP_BOUND_IF`, Windows `IP_UNICAST_IF`). macOS: chỉ đụng đúng `utunN` ghi trong sổ cái, không flush `pf.conf`, không `spctl --master-disable`. Lệnh ngoài chỉ qua `internal/sysexec` (đường dẫn tuyệt đối, không shell, danh mục cho phép).
- Log: `log/slog` qua `internal/logx`, message tĩnh, attr snake_case; bắt buộc `ts`(UTC), `level`, `component`, `event`; có thì thêm `request_id`, `node_id`, `peer_id`.

## 6. Test & Git
- stdlib `testing` + `go-cmp`; **Arrange–Act–Assert**; table-driven; `Test<Unit>_<Scenario>_<Expected>`; `t.Parallel()`; không `Sleep` (dùng `testing/synctest`); `goleak.VerifyTestMain`; fuzz cho mọi parser; tag `integration` / `privileged`. Mỗi AC của story có ≥ 1 test.
- **Conventional Commits** tiếng Anh: `type(scope): subject` (≤ 72, mệnh lệnh) + `Refs: US-0xx`. 1 PR = 1 story, squash merge. Cấm force-push/`reset --hard` lên nhánh chính; không commit artifact/khóa/DB.

## 7. LỆNH KIỂM ĐỊNH CHUẨN — phải XANH 100% trước khi bàn giao
Từ gốc repo (đặt `CGO_ENABLED=0`):
```
Windows : pwsh -File scripts/check.ps1          (thêm -Race để chạy race qua Docker/WSL)
Mac/Linux: sh scripts/check.sh
```
Bên trong (có thể chạy riêng; **PowerShell phải đặt `'-modfile=tools/go.mod'` trong dấu nháy**, nếu không bị cắt tại dấu chấm):
1. `go mod verify` ; `go mod tidy -diff`
2. **fmt**: `go tool -modfile=tools/go.mod golangci-lint fmt --diff`
3. **lint** (lần lượt `GOOS=linux|darwin|windows`; đã gồm kiểm gofumpt+gci): `go tool -modfile=tools/go.mod golangci-lint run ./...`
4. **vet + build 4 đích**: `go vet ./...` và `go build ./...` với `GOOS/GOARCH` ∈ {linux/amd64, darwin/arm64, darwin/amd64, windows/amd64}
5. **unit test**: `go test -shuffle=on -count=1 -timeout 5m ./...`
6. **race** (Linux/CI/Docker): `go test -race -shuffle=on -count=1 ./...`
7. CI/khi đổi dependency: `go tool -modfile=tools/go.mod govulncheck ./...` + kiểm giấy phép.

Thêm dependency, đổi ranh giới module, API/DB contract, cổng/runtime/hạ tầng ⇒ **dừng và hỏi** (không tự quyết).
