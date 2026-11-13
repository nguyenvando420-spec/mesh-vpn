# Kế Hoạch Kiểm Thử Độc Lập Sprint 1 (Sprint 1 Independent QA & AppSec Test Plan)

- **Dự án**: Mesh VPN (Self-Hosted Encrypted Overlay Network — Rust `1.94.1`, `edition = "2024"`)
- **Phạm vi**: Sprint 1 (`WP-S1-00` .. `WP-S1-06`, **38 `Must` User Stories / 174 SP**)
- **Đơn vị thực hiện**: `agile-qa` (`gemini-4-argon-high` — biến thể model độc lập hoàn toàn với nhóm tác giả `hydrogen`)
- **Ngày lập**: `2026-11-13`
- **Cổng phê duyệt đối chiếu**: Gate 1 (`2026-11-12`), Gate 2 (`2026-11-13`)

---

## 1. Mục Tiêu Kiểm Định (Verification Objectives)

1. **Nghiệm thu 100% Acceptance Criteria (38/38 `Must` Stories — 174 SP)** trong `docs/02-product-planning/product-backlog.md` và `docs/04-sprint-management/sprint-backlog.md`.
2. **Kiểm chứng tuân thủ chuẩn kỹ thuật & biên dịch chéo (`coding-standards.md`)**:
   - Toolchain khóa cứng `rustc 1.94.1 (e408947bf 2026-03-25)`, `edition = "2024"`, `resolver = "3"`.
   - Kiểm tra tĩnh kho mã nguồn: không có UTF-8 BOM, cô lập `unsafe` duy nhất trong `crates/mesh-sys/`, cô lập `.expose_secret()` trong 4 crate được phép (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`), không có `#[allow(clippy::...)]`, không gán cứng `:443` / `:3478` ngoài `crates/mesh-core`.
   - `cargo fmt --all -- --check` và `cargo clippy --workspace --all-targets --all-features -- -D warnings` đạt 100% (bao gồm cả cross-target `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`).
   - `cargo deny check advisories bans licenses sources` xanh 100% (chặn sạch `AGPL`, `GPL`, `LGPL`, `MPL-2.0`, `openssl-sys`, `aws-lc-rs`, `rusqlite`).
   - `wsl bash -n` trên toàn bộ 12 tập lệnh `.sh` trong `scripts/` và `lab/`.
3. **Kiểm thử Tích hợp, Concurrency & Bảo mật Ứng dụng Độc lập (AppSec & E2E Loopback)**:
   - Tạo Pre-Auth Key SHA-256 (`mpk_...`) không lưu văn bản rõ trên đĩa (`US-002`).
   - Đăng ký Idempotent dưới tải đồng thời (3 luồng gọi đồng thời cùng `node_pubkey` và 1 one-time key chỉ cấp phát đúng 1 `NodeId` và 1 `OverlayIp` — `US-005 AC2`).
   - Xác thực `challenge_id` dùng một lần (Single-Use) kết hợp `SalsaBox` + `tls_exporter_binding`; phát lại `challenge_id` lần 2 bị chặn 100% với mã `401 "authentication failed"` (`US-003 AC4`, `SEC-05`).
   - Đồng bộ `NetmapSnapshot` vào `PeerMap`, chuyển tiếp mù Blind Relay `0x01` -> `0x02` đóng dấu `src_pubkey` xác thực bởi server và hàng đợi giới hạn `mpsc::channel(256)` + `try_send()` theo từng peer đích không gây nghẽn chéo (Cross-Peer Head-of-Line blocking — `US-025 AC6`).
   - Nâng cấp đường truyền sang Direct UDP qua `DiscoPing`/`DiscoPong` xác thực (`b"MESHDS"` >= `172 B`), chống phản xạ (anti-reflection), chuyển dự phòng 3-strike (`<= 10 s`), và đảm bảo `DiscoPong` đi qua Relay **không bao giờ** đầu độc `direct_addr` (`US-021 AC5`, `HR-G2-04`).
   - Định tuyến khóa mật mã `AllowedIPs = /32` chặn gói tin giả mạo IP nguồn bên trong đường hầm WireGuard (`US-014 AC4`, `SEC-11`).
   - Hai nhánh lỗi phần cứng `EIO` kép đã duyệt tại Gate 2: (a) thu hồi vào `RevokedSet` RAM + `EmergencySlot` -> `RamOnly` không đánh bật mục cũ và gộp lại vào `control.redb` khi đĩa phục hồi; (b) khi `EIO` kép trùng lúc cạn kiệt lease `MonotonicNetmapVersion`, không phát sinh `netmap_version` chưa bền vững mà đặt cờ ngắt kết nối buộc các peer xác thực lại (`US-029`, `SEC-08`).
   - Kiểm thử canary `test_no_secrets_in_outputs` đảm bảo `0` byte khóa bí mật / `mpk_` lộ ra `Debug`, `Display`, JSON hoặc nhật ký kiểm toán (`SEC-01`).

---

## 2. Kiến Trúc Tầng Kiểm Thử (Test Pyramid & Suites)

| Tầng Kiểm Thử | Vị Trí Thực Thi | Công Cụ & Cơ Chế | Số Lượng Bài Test |
| :--- | :--- | :--- | :--- |
| **1. Static & Supply-Chain Audit** | `scripts/check.ps1`, `scripts/check.sh`, `deny.toml` | PowerShell / POSIX `sh`, `rustfmt`, `clippy -D warnings`, `cargo-deny`, `wsl bash -n` | 5 cổng kiểm tĩnh + 12 scripts `.sh` |
| **2. Unit & Property-Based Tests** | `crates/*/src/**` (10 crates) | `cargo test --workspace --all-features`, `proptest!` (parsers STUN, Disco, Relay, Hosts, Ledger) | **215 bài test** |
| **3. Independent QA Integration & AppSec Tests** | `crates/mesh-store/tests/qa_sprint1_store_security_and_eio.rs`<br>`crates/mesh-datapath/tests/qa_sprint1_e2e_datapath_and_appsec.rs` | Kiểm thử hộp xám/đen độc lập do `agile-qa` viết mới (Concurrency `Barrier`, Dual `EIO`, E2E WireGuard + Relay + Disco + `/32` Cryptokey) | **8 bài test tích hợp chuyên sâu** |
| **4. Multi-Node NAT Lab & Host Safety Harness** | `lab/docker-compose.yml`, `lab/run-lab.sh`, `lab/acceptance/*.sh`, `lab/macos/verify-macos-host.sh` | Mô phỏng NAT EIM/Hard Symmetric, chặn UDP chỉ mở TCP `:443`, tiêm lỗi `ENOSPC`/`EIO`, kiểm toán `ResourceLedger` | 12 kịch bản Lab & Host Safety |

---

## 3. Ma Trận Phân Bổ Gói Công Việc Sprint 1 (`WP-S1-00` .. `WP-S1-06`)

| Work Package | Crates / Thành Phần Chính | Stories Bảo Phủ | Trọng Tâm Kiểm Định QA & AppSec |
| :--- | :--- | :--- | :--- |
| **`WP-S1-00`** | `mesh-core`, `mesh-crypto`, `mesh-proto`, `mesh-sys` | Nền tảng kiểu miền, mật mã, khung giao thức, FFI cô lập | `Secret<T>` (`ZeroizeOnDrop`, `"[REDACTED]"`), `SpkiPinVerifier` (`ConstantTimeEq`, `ErrorKind::ClockSkew`, cấm TOFU), parser giới hạn `<= 2048 B`, cô lập `unsafe` trong `mesh-sys`. |
| **`WP-S1-01`** | `mesh-store`, `mesh-server` | `US-001`..`US-009`, `US-012`, `US-013`, `US-023`..`US-025`, `US-029`, `US-031`, `US-047`, `US-051`, `US-074` | `redb` ACID 9 bảng, `MonotonicNetmapVersion` (`+1_024` lease, `+1_000_000` khi restore), Single-Use `challenge_id`, Idempotent Register, Dual `EIO` (`EmergencySlot` + `RamOnly`), Blind Relay `0x01`->`0x02` `mpsc::channel(256)` `try_send()`, Admin UDS `0660`, TLS 1.3 + ACME + SPKI Pin. |
| **`WP-S1-02`** | `mesh-datapath` | `US-010`, `US-014`, `US-018`..`US-022`, `US-026`, `US-034` | `MagicSocket` 1 cổng UDP duy nhất, demux `STUN -> Disco -> WireGuard`, `PeerMap` diff không rớt gói, `/32` cryptokey routing + `PacketFilterPolicy` fail-closed, Disco >= `172 B` chống đầu độc `direct_addr` qua Relay, 3-strike failover `<= 10 s`, dừng kết nối lại duy nhất khi nhận `node_revoked`/`node_key_expired` xác thực. |
| **`WP-S1-03`** | `mesh-net`, `meshd`, `mesh` (macOS & Core Daemon/CLI) | `US-011`, `US-015`, `US-019`, `US-032`, `US-035`..`US-038`, `US-048` | Sổ cái `ResourceLedger` ghi trước khi chạm OS, `IP_BOUND_IF` chống routing loop, khối `# BEGIN mesh ... # END mesh` bảo toàn symlink `/etc/hosts`, IPC 2 kênh (`meshd-admin.sock` `0660 root:admin` gid 80 vs `meshd-ro.sock` `0666` <= `4 KiB`, 0 secrets), CLI `mesh up/down/status/peers/ping/netcheck/admin`. |
| **`WP-S1-04`** | `mesh-net`, `meshd` (Windows Service & Wintun) | `US-016`, `US-039`, `US-040`, `US-050` | Kiểm tra SHA-256 `wintun.dll` + `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`, SDDL Named Pipe (`SY`+`BA` cho admin, `WD` chỉ đọc <= `4 KiB` cho ro), `IP_UNICAST_IF`, DPAPI khóa, bảo toàn ACL đọc `hosts`. |
| **`WP-S1-05`** | `mesh-net`, `meshd` (Linux Client & systemd) | `US-017`, `US-041`, `US-042` | `/dev/net/tun` `IFF_NO_PI`, `SO_MARK = 0x5d56` + `table 51820` + `suppress_prefixlength 0`, `SO_PEERCRED` + `getgrouplist` cho `mesh-admin`, systemd hardening (`ProtectSystem=strict`, `CapabilityBoundingSet=CAP_NET_ADMIN`). |
| **`WP-S1-06`** | `deploy/`, `lab/`, `scripts/` | `US-045`, `US-049`, `US-055`, `US-056`, `US-057` | `install-server.sh` tạo user không đặc quyền `mesh` + nhóm `mesh-admin`, `docker-compose.yml` multi-NAT lab không dùng `privileged: true`, kịch bản chặn hoàn toàn UDP chỉ mở TCP `:443`, tiêm lỗi `ENOSPC`/`EIO`. |

---

## 4. Tiêu Chí Chấp Thuận & Đạt DoD (Pass/Fail Criteria)

- **Đạt (`[PASS - ĐẠT DoD]`)**:
  - 100% lệnh trong `scripts/check.ps1 -Cross` và `wsl bash -n` trả về mã thoát `0`.
  - 100% bài kiểm thử đơn vị và tích hợp (`223/223` tests) PASS.
  - 38/38 `Must` User Stories (174 SP) có bằng chứng thực thi và kiểm thử tự động khớp hoàn toàn với `api-design.md`, `database-design.md`, `system-architecture.md` và `coding-standards.md`.
  - Không tồn tại lỗi bảo mật hay lỗi chức năng mức `Critical` hoặc `Major`.
- **Không đạt (`[FAIL - CẦN SỬA LỖI]`)**:
  - Bất kỳ vi phạm nào về chuẩn định dạng, Clippy (`-D warnings`), `cargo-deny`, lộ khóa bí mật (`SEC-01`), đầu độc đường truyền qua Relay (`HR-G2-04`), hoặc rò rỉ tài nguyên mạng máy chủ (`G4`).
