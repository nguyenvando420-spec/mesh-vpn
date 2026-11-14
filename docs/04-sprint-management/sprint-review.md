# Báo Cáo Tổng Kết Sản Phẩm — Sprint 1 & Sprint 2 Review (`Gate 3 Release`)

- **Dự án**: Mesh VPN — Mạng Overlay Mã hóa Tự chủ (Self-Hosted Encrypted Overlay Network)
- **Công nghệ lõi**: Rust `1.94.1` (`edition = "2024"`, `resolver = "3"`), `defguard_boringtun`, `redb`, `rustls` (`ring` backend, Zero-TOFU SPKI Pinning), `axum`, `tokio`, `tokio-tungstenite`, `instant-acme`, `rcgen`, `x509-cert`
- **Ngày hoàn tất kiểm định Gate 3**: `2026-11-14`
- **Phạm vi hoàn thành tổng thể**: **`62 / 62 User Stories` (`269 / 269 SP` — `100%` Scope Cam Kết)**
  - **Sprint 1 (Milestone 1 — `WP-S1-00..06`)**: **`38 Must Stories / 174 SP`** (`100%` hoàn tất)
  - **Sprint 2 (Milestone 2 — `WP-S2-01..04`)**: **`13 Must Stories / 60 SP` + `11 Should Stories / 35 SP`** (`100%` hoàn tất)

---

## 1. Tóm Tắt Giá Trị Đã Bàn Giao Theo Gói Công Việc (`WP-S1-00` .. `WP-S2-04`)

### 1.1. Sprint 1 — Nền tảng Cốt lõi, Data Plane, OS Adapters & NAT Lab (`38 Must / 174 SP`)

| Gói Công Việc | Phạm Vi & Crates | Thành Tựu Nổi Bật | Trạng Thái |
| :--- | :--- | :--- | :---: |
| **`WP-S1-00` (19 SP)** | `mesh-core`, `mesh-crypto`, `mesh-proto`, `mesh-net/hosts.rs`, `mesh-sys` | Cô lập `unsafe` duy nhất trong `mesh-sys` (`unsafe_code = "forbid"` ở 9/10 crates); `Secret<T>` (`ZeroizeOnDrop` + `"[REDACTED]"`); `SpkiPinVerifier` Zero-TOFU + `ClockSkew`; parser giới hạn `<= 2048 B` kèm `proptest!`; JSON rotating logger `<= 100 MB`. | **Done** |
| **`WP-S1-01` (54 SP)** | `mesh-store`, `mesh-server`, `install-server.sh`, `mesh-server.service` | `redb` ACID 9 bảng + `MonotonicNetmapVersion` (`+1_024` lease); thu hồi khẩn cấp 3 tầng (`redb` -> `emergency-revocations.bin` 64 KiB -> `RamOnly` + cắt stream); Single-Use `challenge_id` + `SalsaBox`; Blind Relay `0x01`->`0x02`; `instant-acme` `TLS-ALPN-01` & `DNS-01`; `/healthz` & `/readyz`; UDS Admin `0660`. | **Done** |
| **`WP-S1-02` (36 SP)** | `mesh-datapath` | `MagicSocket` 1 cổng UDP (`STUN -> Disco -> WireGuard`); `defguard_boringtun` sans-I/O + MTU `1280` + `/32` cryptokey routing; Disco `>= 172 B` chống phản xạ & chống đầu độc `direct_addr` qua Relay; 3-strike Direct->Relay failover `<= 10 s`. | **Done** |
| **`WP-S1-03` (28 SP)** | `mesh-sys` & `mesh-net` (macOS/Linux), `launchd`/`systemd`, `install-macos.sh` | `ResourceLedger` ghi đĩa `0600` trước khi tạo tài nguyên OS; `utun` + `IP_BOUND_IF` + `LOCAL_PEERCRED` (`gid==80`) trên macOS; `/dev/net/tun` + `SO_MARK = 0x5d56` + `table 51820` trên Linux; khối `# BEGIN mesh ... # END mesh` bảo toàn symlink `/etc/hosts` & chế độ VPS-node (`US-056`). | **Done** |
| **`WP-S1-04` (13 SP)** | `mesh-sys` & `mesh-net` (Windows), `install-windows.ps1` | Nạp `wintun.dll` kiểm SHA-256 compile-time + `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`; Windows Service `MeshVpnAgent`; SDDL Named Pipe (`SY`+`BA` cho admin vs `ro` `<= 4 KiB`); `IP_UNICAST_IF`, firewall & ACL `hosts`. | **Done** |
| **`WP-S1-05` (13 SP)** | `meshd`, `mesh` CLI | `ServiceSupervisor` dừng sạch `<= 5 s` theo sổ cái; IPC 2 kênh; `SendPingProbe` khớp `tx_id`; đầy đủ lệnh `mesh {up,down,status,peers,ping,cleanup}` & `mesh server ...`. | **Done** |
| **`WP-S1-06` (11 SP)** | `lab/**`, `Dockerfile*`, `.github/workflows/ci.yml` | Docker NAT Lab đa vùng không dùng `--privileged` (`libfaketime`); kịch bản UDP-block / TCP `443`-only; CI matrix 4 target + `cargo-deny`. | **Done** |

### 1.2. Sprint 2 — Production Hardening, Resilience, Roaming & Release (`13 Must / 60 SP + 11 Should / 35 SP`)

| Gói Công Việc | Phạm Vi & Crates | Thành Tựu Nổi Bật | Trạng Thái |
| :--- | :--- | :--- | :---: |
| **`WP-S2-01` (40 SP)** | `mesh-store`, `mesh-server`, `mesh/admin_cmds.rs` | `revoke_node_with_hook` khóa RAM `< 1 ms` + cách ly IP 24h (`US-029`); `expire_node`/`--never`/`--for` xóa `RevokedSet` RAM giữ khóa cũ bị chặn (`US-031`); IP brute-force lockout `429` sau 10 lỗi kể cả lệch `disco_pubkey` tại `control_handlers.rs:371` (`US-042`); Relay `TokenBucket` 20 Mbps/node (`US-027`); hot MVCC `create_backup` + `.sha256` + offline/cold `--restore-from` nâng sàn `min_netmap_version` (`US-045`, `HR-G3-04`); `ListenerSet` (`US-074`); reusable/ephemeral preauth (`US-006`), `/metrics` (`US-048`), alert worker (`US-049`), `protocol_version` (`US-050`). | **Done** |
| **`WP-S2-02` (28 SP)** | `mesh-datapath`, `meshd`, `mesh/client_cmds.rs` | Cắt phiên WireGuard + xả hàng đợi Relay peer thu hồi trong `< 200 ms` không nghẽn DNS STUN (`US-030`); `netmap-cache.json` `0600` + SHA-256 + 24h offline grace (`US-033`); `ExponentialBackoff` + Full Jitter trần 5 phút + `mesh set` (`US-034`, chặn `://` scheme `HR-G3-02`); netmap sanity check (`US-011`), fail-closed packet filter (`US-018`), `mesh netcheck` (`US-023`), `mesh rotate-key` (`US-032`), `mesh bugreport` POSIX `.tar` `0` secret (`US-041`). | **Done** |
| **`WP-S2-03` (19 SP)** | `mesh-sys`, `mesh-net`, `mesh-datapath`, `meshd`, `install-linux.sh` | Phát hiện đổi mạng (`PF_ROUTE` / `NETLINK_ROUTE` / `NotifyIpInterfaceChange`), `ClockJumpDetector` (`> 30 s`), đồng bộ `oneshot` `begin_rebind` -> `rebind_underlay` + chờ DHCP bỏ qua APIPA `169.254.x.x` (`US-035`, `US-036`); chặn xung đột CGNAT `100.64.0.0/10` (`US-037`); gói dịch vụ & desktop Linux (`US-054`, ưu tiên hardened `meshd.service`). | **Done** |
| **`WP-S2-04` (8 SP)** | `scripts/run-slo-suite.{ps1,sh}`, `lab/scenarios/**`, `.github/workflows/ci.yml`, `docs/06-*` | Bộ kiểm thử SLO & Chaos tự động một lệnh `US-058` xuất JSON + Markdown chuẩn xác; bộ cài & CI release artifacts đồng bộ đa nền tảng; Runbook `<= 30 phút`, Hardware Sleep/Wake Protocol, 20-mục Go-Live Checklist, Release/Deployment/Rollback Plans (`US-059`). | **Done** |

---

## 2. Bằng Chứng Kiểm Định Thực Nghiệm Tổng Hợp (Verified On Host)

### 2.1. Tháp Kiểm Thử & Kiểm Toán Chuỗi Cung Ứng (`scripts/check.ps1 -Cross`)

- **Toolchain khóa cứng**: `rustc 1.94.1 (e408947bf 2026-03-25)`, `edition = "2024"`, `resolver = "3"`.
- **Kiểm tĩnh & Bảo mật mã nguồn**: `0` UTF-8 BOM, `0` CRLF trong `.rs`/`.md`/`.toml`/`.sh`/`.json`/`.yml`/`.plist`/`.service`, `0` `#[allow(clippy::...)]`, `0` `unsafe` ngoài `crates/mesh-sys/`, `0` `.expose_secret()` ngoài 4 crate cho phép, `0` `.unwrap()` / `.expect()` / `panic!()`.
- **Workspace Tests**: **`308 / 308 bài kiểm thử PASS` (`0 failed; 0 ignored`)** qua **26 suites**:
  - `273` unit & property-based tests (`mesh-core: 16`, `mesh-crypto: 13`, `mesh-proto: 12`, `mesh-store: 30`, `mesh-datapath: 43`, `mesh-net: 41`, `mesh-sys: 17`, `mesh-server: 40`, `meshd: 44`, `mesh: 17`).
  - `9` automated SLO tests (`slo_wave2_suite`: `mesh-datapath: 4` + `mesh-server: 5`).
  - `8` Independent QA Sprint 1 (`qa_sprint1_*`: `mesh-store: 4` + `mesh-datapath: 4`).
  - `18` Independent QA Sprint 2 (`qa_sprint2_*`: `mesh-store: 4` + `mesh-datapath: 4` + `mesh-net: 4` + `mesh-server: 3` + `mesh: 3`).
- **`cargo-deny`**: `advisories ok, bans ok, licenses ok, sources ok` (`0` crate GPL/AGPL/MPL-2.0/OpenSSL/`aws-lc-rs`/`rusqlite`).
- **Cross-Targets**: `cargo zigbuild --target x86_64-unknown-linux-musl` + `clippy --all-targets --all-features -- -D warnings` xanh trên Linux `musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, và `x86_64-pc-windows-gnu`.
- **Shell Syntax**: `15 / 15` tập lệnh `.sh` trong `scripts/` và `lab/` đạt `ALL_15_SH_OK` qua `wsl bash -n`.

### 2.2. Kết Quả Thực Nghiệm `US-058` NFR/SLO & Kích Thước Release Binary (`run-slo-suite.ps1`)

- **Tổng hợp SLO Report**: **`33 PASS / 0 FAIL / 1 pending_external_lab (PERF-02) / 2 hardware_signoff_required (PLAT-05, PLAT-06)`** ([slo-verification-report.md](../05-quality-assurance/slo-verification-report.md)).
- **Chỉ số đo đạc tiêu biểu**:
  - `PERF-01` (Live release `mesh-server.exe` `WorkingSet64` tại `/readyz 200 OK`): **`10.5 MiB`** (`11,010,048 B <= 128.0 MiB`).
  - `PERF-03` (BoringTun MTU-1280 P95 encap+decap): **`0.0044 ms`** (`<= 2.0 ms`).
  - `PERF-04` (In-memory WireGuard throughput): **`1,978.47 Mbps`** (`>= 210.0 Mbps`).
  - `PERF-08` (20-node Netmap WS broadcast P95): **`14.9918 ms`** (`<= 5,000.0 ms`).
  - `PERF-09` (Datapath live process RSS / 20 peers): **`12.54 MiB`** (`<= 50.0 MiB`; `struct_mib = 0.224770 MiB`).
  - `PERF-11` & `PERF-11-QUEUE` (Relay 20 Mbps TokenBucket & HoL isolation): luồng tốt `d->b` truyền `2.64 MB > 625 KB` burst đạt **`10.77 Mbps >= 2.0 Mbps`** trong khi luồng `a->c` bị `Throttled`; hàng đợi client drop-tail **`128 == 128 frames`**.
  - `SEC-08` (RAM revocation dưới Dual-`EIO`): **`0.2552 ms`** (`< 100.0 ms` cho 25 nodes).
  - `REL-08` (Graceful shutdown): **`31.06 ms`** (`<= 5,000.0 ms`).
  - `REL-12` (Hot backup + `.sha256` + restore): **`490.91 ms`** (`<= 5,000.0 ms`).
- **Release Binaries trên Host (`target/release/*.exe`)**:
  - `mesh.exe`: **`1,850,368 B`** (`1.765 MiB` / `1.76 MiB`)
  - `meshd.exe`: **`6,156,288 B`** (`5.871 MiB` / `5.87 MiB`)
  - `mesh-server.exe`: **`8,421,888 B`** (`8.032 MiB` / `8.03 MiB`) — nằm gọn dưới trần kiểm định CI `<= 16 MiB`.

### 2.3. Phán Quyết Nghiệm Thu & Phản Biện Độc Lập Trước Gate 3

- **`agile-qa` (`qa-s2`)**: **`[PASS - ĐẠT DoD]`** tại [sprint-2-dod-verification.md](../05-quality-assurance/sprint-2-dod-verification.md) & [dod-verification.md](../05-quality-assurance/dod-verification.md).
- **`agile-critic` (`critic-2`)**: **`[APPROVED FOR GATE]`** sau 2 vòng thẩm định tại [gate-3-critique.md](../05-quality-assurance/critique-reviews/gate-3-critique.md) (**`10 / 10 CLOSED`**: `4 HR-G3 + 4 MED-G3 + 2 LOW-G3`, `0 Blocker / 0 High Risk / 0 Medium / 0 Low`).

---

## 3. Hồ Sơ Vận Hành, Phát Hành & Các Hạng Mục Xác Nhận Thực Địa Trước Go-Live

- **Bộ tài liệu sẵn sàng sản xuất (`US-059`)**:
  - [operational-runbook.md](../06-operations/operational-runbook.md) (Cài VPS + DNS/IP Pin + Cold/Hot Restore DR `<= 5 phút`, `RTO`/`RPO`)
  - [go-live-checklist.md](../06-operations/go-live-checklist.md) (20 hạng mục ký duyệt Go-Live)
  - [hardware-sleep-wake-protocol.md](../06-operations/hardware-sleep-wake-protocol.md) (Biên bản thử nghiệm ngủ/thức dậy trên phần cứng thật `>= 4 phút`)
  - [release-plan.md](../06-release-deployment/release-plan.md), [deployment-checklist.md](../06-release-deployment/deployment-checklist.md), [rollback-plan.md](../06-release-deployment/rollback-plan.md)
- **Ba hạng mục ngoài sandbox giữ trạng thái Fail-Closed Minh bạch để nghiệm thu thực địa trước khi chuyển lưu lượng thật**:
  1. `PERF-02` (`pending_external_lab`): Đo CPU VPS nhàn rỗi `< 2%` trong 5 phút và chạy đủ 8 kịch bản chaos container (`lab/scenarios/run-all-chaos.sh`) trên Linux Docker host có `/dev/net/tun` + `NET_ADMIN`.
  2. `PLAT-05` & `PLAT-06` (`hardware_signoff_required`): Thực thi biên bản [hardware-sleep-wake-protocol.md](../06-operations/hardware-sleep-wake-protocol.md) trên MacBook 13+ và Laptop Windows 10/11 thật (`sleep >= 4m`, Wi-Fi <-> Hotspot `P95 <= 15 s`, `0` ghost adapter).
