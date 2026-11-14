# Kế Hoạch Kiểm Thử Độc Lập Sprint 1 & Sprint 2 — Gate 3 Release (Independent QA, AppSec, E2E & SLO Test Plan)

- **Dự án**: Mesh VPN (Self-Hosted Encrypted Overlay Network — Rust `1.94.1`, `edition = "2024"`)
- **Phạm vi Toàn Dự Án (Gate 3 Release)**:
  - **Sprint 1 Baseline**: `WP-S1-00` .. `WP-S1-06` (**38 `Must` User Stories / 174 SP**)
  - **Sprint 2 Hardening, Operations, Resilience & Release**: `WP-S2-01` .. `WP-S2-04` (**13 `Must` User Stories / 60 SP** + **11 `Should` User Stories / 35 SP**)
  - **Tổng hợp Gate 3**: **51 `Must` Stories (234 SP)** + **11 `Should` Stories (35 SP)** = **62 Stories / 269 SP** + **36 Chỉ tiêu NFR/SLO Wave 2.2**
- **Đơn vị thực hiện**: `agile-qa` (nhóm kiểm định độc lập hoàn toàn với các tác giả triển khai)
- **Ngày lập / Cập nhật Gate 3**: `2026-11-14`
- **Cổng phê duyệt đối chiếu**: Gate 1 (`2026-11-12`), Gate 2 (`2026-11-13`), Wave 2.1 Critique (`2026-11-14`), Gate 3 (`2026-11-14`)

---

## 1. Mục Tiêu Kiểm Định (Verification Objectives — Sprint 1 + Sprint 2 + Wave 2.2)

1. **Nghiệm thu 100% Acceptance Criteria của toàn bộ 51 `Must` Stories (234 SP) và 11 `Should` Stories (35 SP)** trong `docs/02-product-planning/product-backlog.md` và `docs/04-sprint-management/sprint-backlog.md`.
2. **Kiểm chứng tuân thủ chuẩn kỹ thuật & biên dịch chéo (`coding-standards.md`)**:
   - Toolchain khóa cứng `rustc 1.94.1 (e408947bf 2026-03-25)`, `edition = "2024"`, `resolver = "3"`.
   - Kiểm tra tĩnh kho mã nguồn: không có UTF-8 BOM, toàn bộ `.rs` và `.md` dùng LF (`\n`), cô lập `unsafe` duy nhất trong `crates/mesh-sys/`, cô lập `.expose_secret()` trong 4 crate được phép (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`), không có `#[allow(clippy::...)]`, không gán cứng `:443` / `:3478` ngoài `crates/mesh-core` (`GNFR-11`).
   - `cargo fmt --all -- --check` và `cargo clippy --workspace --all-targets --all-features -- -D warnings` đạt 100% (bao gồm cross-target `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`).
   - `cargo deny check advisories bans licenses sources` xanh 100% (chặn sạch `AGPL`, `GPL`, `LGPL`, `MPL-2.0`, `openssl-sys`, `aws-lc-rs`, `rusqlite`).
   - `wsl bash -n` trên toàn bộ **15 tập lệnh `.sh`** (`scripts/{check,install-linux,install-macos,install-server,run-slo-suite}.sh` và 10 kịch bản trong `lab/**/*.sh`).
3. **Kiểm thử Tích hợp, Concurrency & Bảo mật Ứng dụng Độc lập Sprint 1 (`qa_sprint1_*`)**:
   - Tạo Pre-Auth Key SHA-256 (`mpk_...`) không lưu văn bản rõ trên đĩa (`US-002`).
   - Đăng ký Idempotent dưới tải đồng thời (`Barrier::new(3)` với cùng `node_pubkey` và 1 one-time key chỉ cấp phát đúng 1 `NodeId` và 1 `OverlayIp` — `US-005 AC2`).
   - Xác thực `challenge_id` dùng một lần (Single-Use) kết hợp `SalsaBox` + `tls_exporter_binding`; phát lại `challenge_id` lần 2 bị chặn 100% với mã `401 "authentication failed"` (`US-003 AC4`, `SEC-05`).
   - Đồng bộ `NetmapSnapshot` vào `PeerMap`, chuyển tiếp mù Blind Relay `0x01` -> `0x02` đóng dấu `src_pubkey` xác thực bởi server và hàng đợi giới hạn `mpsc::channel(256)` + `try_send()` theo từng peer đích không gây nghẽn chéo (`US-025 AC6`).
   - Nâng cấp đường truyền sang Direct UDP qua `DiscoPing`/`DiscoPong` xác thực (`b"MESHDS"` >= `172 B`), chống phản xạ, chuyển dự phòng 3-strike (`<= 10 s`), và đảm bảo `DiscoPong` đi qua Relay **không bao giờ** đầu độc `direct_addr` (`US-021 AC5`, `HR-G2-04`).
   - Định tuyến khóa mật mã `AllowedIPs = /32` chặn gói tin giả mạo IP nguồn bên trong đường hầm WireGuard (`US-014 AC4`, `SEC-11`).
   - Hai nhánh lỗi phần cứng `EIO` kép đã duyệt tại Gate 2 (`EmergencySlot` -> `RamOnly` + gộp lại khi đĩa phục hồi; ngắt kết nối buộc xác thực lại khi cạn lease `MonotonicNetmapVersion` — `US-029`, `SEC-08`).
   - Kiểm thử canary `test_no_secrets_in_outputs` đảm bảo `0` byte khóa bí mật / `mpk_` lộ ra `Debug`, `Display`, JSON hoặc nhật ký kiểm toán (`SEC-01`).
4. **Kiểm thử Độc lập Sprint 2 — Resilience, Concurrency, AppSec & Live Process E2E (`qa_sprint2_*`)**:
   - **Store Resilience & Security (`qa_sprint2_store_resilience_and_security.rs`)**:
     - Hết hạn khóa node (`expire_node`), đặt không hết hạn (`set_node_expiry_never` / `--never`), và đăng ký lại bằng khóa `--for <node>` (`register_node`) giữ nguyên `NodeId` & `OverlayIp`, xóa trạng thái hết hạn trong `RevokedSet` RAM (`HR-W21-02`) nhưng giữ khóa công khai cũ trong danh sách chặn vĩnh viễn (`US-031 AC2/AC5`, `US-032`).
     - Thu hồi node với callback trước đĩa (`revoke_node_with_hook`) dưới lỗi `EIO` kép (`inject_redb_failure(true, true)` + lỗi ghi `EmergencySlot`), chứng minh khóa RAM được giữ trước khi chạm đĩa (`HR-W21-04`, `IMP-W21-01`), cách ly IP 24 giờ (`QUARANTINE_DURATION_MS` — `US-029 AC5`), và phát sinh `netmap_version` mới khi gộp (`HR-W21-12`).
     - Giới hạn `max_uses` của khóa dùng lại và tự động thu hồi Ephemeral Node đã offline quá hạn (`reap_expired_ephemeral_nodes`) trong khi giữ nguyên node đang online (`US-005`, `US-006`).
     - Xoay khóa TLS 2 bước (`stage_next_identity` -> `activate_staged_identity` — `US-047 AC5`), sao lưu nóng MVCC (`create_backup`) tự động gộp các mục thu hồi khẩn cấp chưa nén (`BLK-S1-04`), từ chối bản sao lưu bị sửa đổi `.sha256` (`US-045 AC4`), và cưỡng chế sàn `min_netmap_version` + `+1_000_000` khi `restore_backup` (`HR-W21-06`).
   - **Datapath Concurrency & AppSec (`qa_sprint2_datapath_concurrency_and_appsec.rs`)**:
     - Cắt phiên ngang hàng đang hoạt động trên `DatapathEngine` khi nhận Netmap diff loại bỏ peer trong `< 200 ms` (`<= 2 s` SLA), xả sạch hàng đợi `RelayClientHandle`, và phân giải DNS STUN bất đồng bộ không làm nghẽn vòng lặp sự kiện (`US-030 AC1/AC2`, `US-026`, `HR-W21-07`).
     - Bộ lọc gói tin phía Host (`parse_inbound_filter_spec`, `CryptokeyValidator`) chặn cổng bị cấm (`3389`, `5353`), chặn mảnh IPv4 không phải mảnh đầu tiên, và giữ nguyên chính sách hợp lệ cũ khi cấu hình mới bị lỗi cú pháp (`US-018`, `SEC-11`).
     - Đồng bộ hóa Rebind qua kênh `oneshot` (`begin_rebind`, `rebind_underlay`, `RebindCommand::RebindInterface`) khi chuyển mạng/thức dậy (`US-035`, `US-036`, `HR-W21-08`).
     - Giới hạn tốc độ `CallMeMaybe` (`10/phút` — `US-021 AC5`) và chặn gói Disco qua Relay có khóa nguồn bên trong lệch với khóa đã xác thực bởi server (`relay_src_pubkey_mismatch` — `US-027`).
   - **OS Resource Ledger, Hosts & Platform Safety (`qa_sprint2_ledger_hosts_and_platform.rs`)**:
     - Khôi phục sau sự cố (`crash recovery`) dựa trên `ResourceLedger` theo đúng thứ tự `routes -> linux_policy -> hosts -> firewall -> tun`, chỉ đóng đúng interface đã ghi (`utun7`) và đảm bảo tính lũy đẳng (`idempotent`) khi chạy lại (`US-055`, `US-060`, `US-073`, `G4`).
     - Chỉnh sửa file `hosts` bảo toàn dòng của người dùng và kiểu xuống dòng CRLF/LF, chặn tên dành riêng (`localhost`, `wpad`, `broadcasthost`, `isatap`, `local`) và xung đột với `public_server_host` (`US-038`, `US-056`, `PLAT-04`).
     - Phát hiện xung đột dải mạng vật lý CGNAT `100.64.0.0/10` (`apply_overlay_route_checked` trả về `ErrorKind::Conflict` — `US-037`), chờ DHCP sau khi thức dậy bỏ qua địa chỉ APIPA `169.254.x.x` (`US-036 AC4`), và phân biệt cổng TCP Control với cổng UDP STUN (`Codex R2 #4`).
     - `KeysFileStore` từ chối ghi đè file `keys.json` bị hỏng (`US-001 AC4`), che giấu khóa bí mật trong `Debug` (`SEC-01`), ma trận phân quyền IPC `DefaultPrivilegeIpc` trên Linux/macOS/Windows (`SEC-14`), và chặn ký tự NUL trong `CommandSpec::new` (`US-073`).
   - **Live Process E2E `mesh-server` & `mesh` CLI (`qa_sprint2_server_e2e_and_appsec.rs`, `qa_sprint2_cli_e2e.rs`)**:
     - Khởi chạy tiến trình thật `CARGO_BIN_EXE_mesh-server`, kiểm chứng nhánh `control_handlers.rs:371` khi `ProofPayload` hợp lệ nhưng `RegisterNodeRequest.disco_pubkey != proof.disco_pubkey` (kết hợp khóa `preauth_key` sai — `HR-W21-03`): mỗi lần thử trả về `401 "authentication failed"` không xóa bộ đếm lỗi, và lần thử thứ 11 bị khóa IP với mã `429 Too Many Requests` (`US-042 AC1/AC2`, `SEC-05`).
     - Kiểm tra từ chối `protocol_version = 0` với mã `400` (`US-050 AC1/AC2`) và phát lại đăng ký idempotent trên tiến trình thật (`US-005`).
     - Kiểm tra `/healthz` (`"alive"`), `/readyz` (`"ready"`), `/metrics` trên cổng quan sát chỉ đọc không rò rỉ bí mật (`US-044`, `US-048`, `SEC-01`) và xác nhận `/v1/admin/*` trả về `404` trên cổng TCP (`SEC-14`).
     - Khởi chạy tiến trình thật `CARGO_BIN_EXE_mesh`, xác nhận chặn cờ `--authkey` trên argv (`SEC-01`), cưỡng chế `--server-pin` khi `--server` là địa chỉ IP trên cả `mesh up` và `mesh set` (Zero-TOFU — `SEC-04`), kiểm tra ma trận `--help` của toàn bộ 19 lệnh con Sprint 1 + Sprint 2, và xử lý lỗi sạch (không panic, không lộ bí mật) khi IPC không kết nối được (`US-039`, `US-040`, `US-055`).

---

## 2. Kiến Trúc Tầng Kiểm Thử Tổng Hợp (Gate 3 Test Pyramid & Suites)

| Tầng Kiểm Thử | Vị Trí Thực Thi | Công Cụ & Cơ Chế | Số Lượng Bài Test |
| :--- | :--- | :--- | :--- |
| **1. Static & Supply-Chain Audit** | `scripts/check.ps1`, `scripts/check.sh`, `deny.toml` | PowerShell / POSIX `sh`, `rustfmt`, `clippy -D warnings`, `cargo-deny`, `wsl bash -n` | 5 cổng kiểm tĩnh + **15 scripts `.sh`** |
| **2. Unit, Property-Based & Wave 2.2 SLO Tests** | `crates/*/src/**` + `crates/{mesh-datapath,mesh-server}/tests/slo_wave2_suite.rs` | `cargo test --workspace --all-features`, `proptest!`, `scripts/run-slo-suite.ps1` | **282 bài test** (273 unit + 9 SLO Wave 2) |
| **3. Independent QA Sprint 1 Integration & AppSec Tests** | `crates/mesh-store/tests/qa_sprint1_store_security_and_eio.rs`<br>`crates/mesh-datapath/tests/qa_sprint1_e2e_datapath_and_appsec.rs` | Kiểm thử Concurrency `Barrier`, Dual `EIO`, E2E WireGuard + Relay + Disco + `/32` Cryptokey | **8 bài test tích hợp Sprint 1** |
| **4. Independent QA Sprint 2 Resilience, AppSec & Process E2E Tests** | `crates/mesh-store/tests/qa_sprint2_store_resilience_and_security.rs`<br>`crates/mesh-datapath/tests/qa_sprint2_datapath_concurrency_and_appsec.rs`<br>`crates/mesh-net/tests/qa_sprint2_ledger_hosts_and_platform.rs`<br>`crates/mesh-server/tests/qa_sprint2_server_e2e_and_appsec.rs`<br>`crates/mesh/tests/qa_sprint2_cli_e2e.rs` | Kiểm thử độc lập Sprint 2 (Store expiry/rotation/backup/quarantine, Datapath revocation/filter/rebind/Disco rate-limit, Ledger/Hosts/CGNAT/IPC, Live `mesh-server` & `mesh` CLI E2E) | **18 bài test tích hợp & E2E Sprint 2** |
| **5. Multi-Node NAT Lab, CI/CD & Ops Runbooks** | `lab/docker-compose.yml`, `.github/workflows/ci.yml`, `docs/06-operations/**`, `docs/06-release-deployment/**` | Mô phỏng NAT EIM/Hard Symmetric, chặn UDP chỉ mở TCP `:443`, tiêm lỗi `ENOSPC`/`EIO`, quy trình vận hành & phát hành đa nền tảng | **33 PASS / 0 FAIL / 1 `pending_external_lab` (`PERF-02`) / 2 `hardware_signoff_required` (`PLAT-05`, `PLAT-06`)** |

- **Tổng số bài kiểm thử Rust tự động toàn Workspace tại Gate 3**: **308 bài kiểm thử (`290` baseline + `18` bài kiểm thử độc lập Sprint 2 `qa_sprint2_*`)**.

---

## 3. Ma Trận Phân Bổ Gói Công Việc Sprint 1 & Sprint 2 (`sprint-backlog.md`)

### 3.1. Gói Công Việc Sprint 1 (`WP-S1-00` .. `WP-S1-06` — 38 `Must` / 174 SP)

| Work Package | Crates / Thành Phần Chính | Stories `Must` Sở Hữu Chính (`sprint-backlog.md` §3.2 & §5) | Trọng Tâm Kiểm Định QA & AppSec |
| :--- | :--- | :--- | :--- |
| **`WP-S1-00` (4 Stories / 19 SP)** | `mesh-core`, `mesh-crypto`, `mesh-proto`, `mesh-sys`, `mesh-net` (skeletons & `hosts.rs`) | `US-001 (3)`, `US-003 (5)`, `US-043 (3)`, `US-047 (8)` | `Secret<T>` (`ZeroizeOnDrop`, `"[REDACTED]"`), `SpkiPinVerifier` (`ConstantTimeEq`, `ErrorKind::ClockSkew`, cấm TOFU), JSON logging xoay vòng, parser giới hạn `<= 2048 B`, cô lập `unsafe` trong `mesh-sys`. |
| **`WP-S1-01` (13 Stories / 54 SP)** | `mesh-store`, `mesh-server`, `deploy/systemd/mesh-server.service`, `scripts/install-server.sh` | `US-002 (3)`, `US-004 (5)`, `US-005 (3)`, `US-007 (5)`, `US-008 (2)`, `US-009 (5)`, `US-012 (3)`, `US-013 (3)`, `US-024 (8)`, `US-025 (5)`, `US-044 (2)`, `US-046 (5)`, `US-051 (5)` | `redb` ACID 9 bảng, `MonotonicNetmapVersion` (`+1_024` lease), Single-Use `challenge_id`, Idempotent Register, Dual `EIO`, Blind Relay `0x01`->`0x02` `mpsc::channel(256)` `try_send()`, Admin UDS `0660`, `/healthz` + `/readyz`, VPS hardening. |
| **`WP-S1-02` (7 Stories / 36 SP)** | `mesh-datapath` | `US-010 (5)`, `US-017 (3)`, `US-019 (5)`, `US-020 (5)`, `US-021 (8)`, `US-022 (5)`, `US-026 (5)` | `MagicSocket` 1 cổng UDP duy nhất, demux `STUN -> Disco -> WireGuard`, `PeerMap` diff không rớt gói, MTU `1280`, `/32` cryptokey routing, Disco >= `172 B` chống đầu độc `direct_addr` qua Relay, 3-strike failover `<= 10 s`. |
| **`WP-S1-03` (6 Stories / 28 SP)** | `mesh-sys` & `mesh-net` (macOS/Linux), `deploy/launchd/`, `deploy/systemd/meshd.service`, `scripts/install-macos.sh` | `US-014 (5)`, `US-060 (5)`, `US-073 (5)`, `US-016 (5)`, `US-038 (5)`, `US-056 (3)` | Sổ cái `ResourceLedger` ghi trước khi chạm OS, `IP_BOUND_IF` (macOS) & `SO_MARK = 0x5d56` + `table 51820` (Linux), khối `# BEGIN mesh ... # END mesh` bảo toàn symlink `/etc/hosts`, IPC 2 kênh (`meshd-admin.sock` vs `meshd-ro.sock`), VPS-node. |
| **`WP-S1-04` (3 Stories / 13 SP)** | `mesh-sys` & `mesh-net` (Windows), `scripts/install-windows.ps1` | `US-015 (5)`, `US-052 (5)`, `US-053 (3)` | Kiểm tra SHA-256 `wintun.dll` + `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`, Windows Service `MeshVpnAgent`, SDDL Named Pipe (`SY`+`BA` cho admin, chỉ đọc `<= 4 KiB` cho ro), `IP_UNICAST_IF`, Windows Firewall & ACL `hosts`. |
| **`WP-S1-05` (3 Stories / 13 SP)** | `crates/meshd`, `crates/mesh` | `US-055 (5)`, `US-039 (5)`, `US-040 (3)` | `ServiceSupervisor` dừng sạch `<= 5 s` theo `ResourceLedger`, tự phục hồi sau `kill -9`, CLI `mesh status`, `mesh ping`, `mesh up`, `mesh down`, `mesh cleanup`. |
| **`WP-S1-06` (2 Stories / 11 SP)** | `lab/**`, `.github/workflows/**`, `Dockerfile*` | `US-057 (8)`, `US-028 (3)` | Môi trường Docker NAT Lab đa vùng không dùng `--privileged`, kịch bản nghiệm thu chặn UDP / chỉ mở TCP `443`, tiêm lỗi `ENOSPC`/`EIO`. |

### 3.2. Gói Công Việc Sprint 2 (`WP-S2-01` .. `WP-S2-04` — 13 `Must` / 60 SP + 11 `Should` / 35 SP)

| Work Package | Crates / Thành Phần Chính | Stories `Must` (`60 SP`) | Stories `Should` (`35 SP`) | Trọng Tâm Kiểm Định QA, AppSec & SLO |
| :--- | :--- | :--- | :--- | :--- |
| **`WP-S2-01` (Server Hardening, Revoke, Key Expiry, Rate-Limit, Quota, Backup & Migration)** | `crates/mesh-store/**`, `crates/mesh-server/**`, `crates/mesh/src/admin_cmds.rs` | **6 stories / 28 SP**:<br>- `US-027` (5 SP)<br>- `US-029` (5 SP)<br>- `US-031` (5 SP)<br>- `US-042` (5 SP)<br>- `US-045` (5 SP)<br>- `US-074` (3 SP) | **4 stories / 12 SP**:<br>- `US-006` (3 SP)<br>- `US-048` (3 SP)<br>- `US-049` (3 SP)<br>- `US-050` (3 SP) | `revoke_node_with_hook` khóa RAM trước đĩa (`< 100 ms`), cách ly IP 24h; `expire_node`, `--never`, đăng ký lại `--for <node>` xóa trạng thái hết hạn trong RAM (`HR-W21-02`); khóa IP sau 10 lần lỗi xác thực kể cả khi lệch `disco_pubkey` tại `control_handlers.rs:371` (`HR-W21-03`); Relay 20 Mbps/node; `create_backup`/`restore_backup` gộp `EmergencySlot` & nâng sàn `--min-netmap-version`; `ListenerSet` đổi cổng/IP/xoay khóa; `/metrics`, cảnh báo, `protocol_version`. |
| **`WP-S2-02` (Client Resilience: Live Peer Cut, Offline Cache, Smart Backoff, Filter & Diagnostics)** | `crates/mesh-datapath/src/{lib,magic_socket,stun_client,peer_map,cryptokey,disco_engine,relay_client,engine}.rs`, `crates/meshd/src/{config,netmap_cache,control_loop,ipc_service,ping_probe}.rs`, `crates/mesh/src/{client_cmds,output}.rs` | **3 stories / 11 SP**:<br>- `US-030` (3 SP)<br>- `US-033` (5 SP)<br>- `US-034` (3 SP) | **5 stories / 17 SP**:<br>- `US-011` (3 SP)<br>- `US-018` (3 SP)<br>- `US-023` (3 SP)<br>- `US-032` (5 SP)<br>- `US-041` (3 SP) | Cắt phiên ngang hàng bị thu hồi trong `<= 2 s` & xóa hàng đợi Relay (`HR-W21-07`); cache `netmap-cache.json` (`0600` + SHA-256 + `local_udp_port`); `ExponentialBackoff` + Full Jitter trần 5 phút chỉ dừng khi `node_revoked`/`node_key_expired` hợp lệ; kiểm tra tính hợp lệ Netmap; `parse_inbound_filter_spec` fail-closed; CLI `mesh netcheck`, `mesh rotate-key`, `mesh bugreport` (`0` secret), `mesh set`. |
| **`WP-S2-03` (Cross-OS Roaming, Sleep/Wake, CGNAT Conflict & Linux Desktop)** | `crates/mesh-sys/src/netmon_*.rs`, `crates/mesh-net/src/{netmon*,endpoint_filter}.rs`, `crates/mesh-datapath/src/rebind.rs`, `crates/meshd/src/{main,supervisor,roaming_loop,service_windows}.rs`, `deploy/linux-desktop/**`, `scripts/install-linux.sh` | **2 stories / 13 SP**:<br>- `US-035` (8 SP)<br>- `US-036` (5 SP) | **2 stories / 6 SP**:<br>- `US-037` (3 SP)<br>- `US-054` (3 SP) | Đồng bộ Rebind qua `oneshot` (`begin_rebind` -> `rebind_underlay` — `HR-W21-08`), phát hiện nhảy đồng hồ `> 30 s` sau khi thức dậy, chờ DHCP `<= 60 s` bỏ qua APIPA `169.254.x.x`, ràng lại `IP_BOUND_IF` / `IP_UNICAST_IF`; phát hiện xung đột dải CGNAT `100.64.0.0/10` (`ErrorKind::Conflict`); bộ cài dịch vụ Linux máy trạm (`scripts/install-linux.sh`). |
| **`WP-S2-04` (Automated NFR/SLO & Chaos Runner + Operational Runbook & Go-Live Checklist)** | `lab/scenarios/**`, `scripts/run-slo-suite.{ps1,sh}`, `docs/05-quality-assurance/**`, `docs/06-operations/**`, `docs/06-release-deployment/**` | **2 stories / 8 SP**:<br>- `US-058` (5 SP)<br>- `US-059` (3 SP) | — | `scripts/run-slo-suite.ps1` (`33 PASS / 0 FAIL / 1 pending_external_lab / 2 hardware_signoff_required`), xuất báo cáo `docs/05-quality-assurance/{slo-verification-report.md,slo-verification-report.json}`; tài liệu `docs/06-operations/{operational-runbook,go-live-checklist,hardware-sleep-wake-protocol}.md` và `docs/06-release-deployment/{release-plan,deployment-checklist,rollback-plan}.md`. |

---

## 4. Tiêu Chí Chấp Thuận & Đạt DoD Tại Gate 3 (Gate 3 Pass/Fail Criteria)

- **Đạt (`[PASS - ĐẠT DoD]`)**:
  - 100% kiểm tra tĩnh (`UTF-8 without BOM`, `LF` cho `.rs`/`.md`/`.toml`/`.sh`, không `unsafe` ngoài `mesh-sys`, không `.expose_secret()` trái phép, không `#[allow(clippy::...)]`, không gán cứng cổng `443`/`3478`) đạt `PASS`.
  - `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, và `cargo deny check advisories bans licenses sources` trả về mã thoát `0`.
  - `100%` bài kiểm thử đơn vị, tích hợp, AppSec, E2E và SLO (**308/308 bài kiểm thử Rust** across 10 crates + **15/15** kịch bản `.sh` qua `wsl bash -n` + **33/33** cổng SLO tự động) đạt `PASS`.
  - Toàn bộ **51 `Must` Stories (234 SP)** và **11 `Should` Stories (35 SP)** có bằng chứng thực thi và kiểm thử tự động truy xuất đầy đủ.
  - Không tồn tại lỗi bảo mật hay lỗi chức năng mức `Critical` hoặc `Major`.
- **Không đạt (`[FAIL - CẦN SỬA LỖI]`)**:
  - Bất kỳ vi phạm nào về chuẩn định dạng, Clippy (`-D warnings`), `cargo-deny`, lộ khóa bí mật (`SEC-01`), vượt rào khóa IP (`HR-W21-03`), đầu độc đường truyền qua Relay (`HR-G2-04`), hoặc rò rỉ tài nguyên mạng máy chủ (`G4`).
