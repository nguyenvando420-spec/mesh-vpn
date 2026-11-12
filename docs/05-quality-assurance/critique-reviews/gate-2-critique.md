# Gate 2 Independent Red-Team Critique — Round 3 Final Verification (v2.2 / v1.2)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Cổng kiểm định** | **Gate 2** — Tech Stack, Coding Standards, System Architecture, DB/API Contracts & Sprint Plan (**Round 3 Final Verification — v2.2 / v1.2**) |
| **Người phản biện** | `agile-critic` (Principal Reviewer & Independent Red-Team Critic) |
| **Ngày kiểm định** | 2026-11-12 (Round 1: 22:08 · Round 2: 22:55 · Round 3 Final: 23:40) |
| **Thành phần AI/SLM** | **KHÔNG CÓ** (Dự án thuần hạ tầng mạng & hệ thống — không áp dụng khung kiểm định AI/SLM) |
| **Đầu vào đối chiếu (Gate 1 v1.2)** | `production-readiness-requirements.md`, `project-charter.md`, `product-backlog.md` (74 stories: 51 `Must` / 234 SP, 11 `Should` / 35 SP, 12 Phase 2+) |
| **Đầu ra đã kiểm chứng (`fd9cb0d` — v2.2 / v1.2)** | `tech-stack-decision.md` (v2.1), `architecture-decision-record.md` (v2.2 `ADR-001..011`), `coding-standards.md` (v2.2), `.agents/rules/coding-standards.md`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.editorconfig`, `.gitignore`, `.gitattributes`, `scripts/{bootstrap-toolchain.ps1,check.ps1,check.sh}`, `system-architecture.md` (v2.2), `database-design.md` (v2.2), `api-design.md` (v2.2), `sprint-backlog.md` (v1.2) |
| **Trạng thái Vòng 1** | **11/11 mục của `agile-critic`** (`BLK-G2-01..04`, `HR-G2-01..04`, `IMP-G2-01..03`) & **14/14 mục của `agile-codex`** (`#1..#14`): **ĐÃ ĐÓNG 100%** |
| **Trạng thái Vòng 2 (`fd9cb0d`)** | **6/6 mục của `agile-codex` R2** (5 `🟠 High Risk` + 1 `🟡 Improvement`) & **3/3 ghi chú `NOTE-G2-R2-01..03` của `agile-critic`**: **ĐÃ ĐÓNG DỨT ĐIỂM 100%** |
| **Lỗi tồn đọng** | **`0 🔴 Blocker` · `0 🟠 High Risk` · `0 🟡 Open Notes`** |
| **Phán quyết cuối** | **`[APPROVED FOR GATE]`** |

---

## 1. Kết Quả Kiểm Chứng Thực Nghiệm Vòng 3 (Commit `fd9cb0d` — v2.2 / v1.2)

### 1.1. Xác Minh Thực Thi Tự Động & Tính Nhất Quán Toàn Kho Mã
1. **`scripts/check.ps1`**: Chạy `powershell -ExecutionPolicy Bypass -File scripts/check.ps1` → **PASS (`exit code 0`)**, xác nhận `rustc 1.94.1 (e408947bf 2026-03-25)`, **0 tệp dính UTF-8 BOM** trên toàn bộ repo.
2. **`scripts/bootstrap-toolchain.ps1` (Cả 2 chế độ)**: Chạy `-Mode PortableZig -DryRun` và `-Mode Msvc -DryRun` → **PASS (`exit code 0`)**; cả hai chế độ đều dùng chung hàm `Install-CommonPrebuiltTools` kiểm chứng SHA-256 **fail-closed** (`Assert-FileSha256`) và xác minh thực thi qua `Invoke-CheckedVersion` (`$LASTEXITCODE -eq 0`).
3. **Rule tự nạp `.agents/rules/coding-standards.md`**: Mở đầu chính xác bằng frontmatter `---\ntrigger: always_on\n---`, mã hóa UTF-8 không BOM, kết thúc dòng LF, kích thước **`9,887 bytes` (`< 10,000 bytes`)**, đồng bộ 100% đường dẫn IPC mới (`/run/mesh-server/admin.sock` vs `/var/run/meshd/meshd-{admin,ro}.sock`), thư mục state (`/var/lib/meshd/`), và `priority 51820` / `51810`.
4. **Quét chéo chống sót chuỗi cũ (`git grep`)**: Quét toàn bộ `docs/03-system-design/`, `docs/04-sprint-management/`, `.agents/rules/` và `scripts/` cho các mẫu cũ (`/run/mesh/admin.sock`, `/var/run/mesh/meshd`, `/var/lib/mesh-agent`, `priority 5182`, `priority 5181`, `max(prev + 1, now`) → **`0` kết quả sót lại**.

### 1.2. Ma Trận Kiểm Chứng Đóng 100% Phát Hiện Vòng 2 (`agile-codex` R2 & `NOTE-G2-R2-01..03`)

| Mã phát hiện | Mức cũ | Vấn đề gốc ở Vòng 2 | Bằng chứng xác minh độc lập trong commit `fd9cb0d` (v2.2 / v1.2) | Trạng thái |
| :--- | :---: | :--- | :--- | :---: |
| **`Codex R2 #1`** | 🟠 High Risk | Sự kiện `online/offline` tăng version trong RAM không ghi đĩa, còn lúc boot lấy `max(db, slot, now_ms)` → nếu đồng hồ NTP bị kéo lùi + crash, server phát version nhỏ hơn bản client đang giữ (`US-009 AC3`). | `database-design.md:428-473,595-611,636-649` & `ADR-005:211-248`: Thiết kế `MonotonicNetmapVersion` theo **High-Watermark Lease (`VERSION_LEASE_STEP = 1_024`)**. Runtime tăng logic thuần túy `next = current.checked_add(1)?` (không gọi `max(..., now_unix_ms)`), giữ bất biến cứng `next <= persisted_watermark` (`schema_meta["netmap_version_watermark"]` + gương `min_netmap_version` trong `emergency-revocations.bin`, tốn 0 I/O cho 1.023/1.024 nhịp presence). Lúc boot lấy `boot_base = max(db_netmap_version, db_watermark, slot.min_netmap_version)` độc lập đồng hồ tường và ghi bền ngay `initial_watermark = boot_base + 1_024` (phát đầu tiên `boot_base + 1 > mọi version trước crash`). Lúc `restore` nhảy `+1_000_000`. Khóa 2 unit test bắt buộc trong `store.rs`. | ✅ **CLOSED** |
| **`Codex R2 #2`** | 🟠 High Risk | Tuyên bố ghi slot cấp cứu "luôn thành công" chưa xét lỗi phần cứng `EIO`/`EROFS`, tràn 500 mục chưa hợp nhất hoặc mất/hỏng cả 2 slot lúc boot. | `database-design.md:381-425,597-604` & `api-design.md:498-525`: (1) Trả trung thực `persistence_tier: "redb" \| "emergency_slot" \| "ram_only"` và `persisted: bool` (`ram_only` trả `persisted: false`, không ghi đè làm mất mục cũ trên đĩa, CLI in cảnh báo khẩn ra `stderr`); (2) Tự động compaction hợp nhất về `redb` và xóa sạch slot ngay khi đĩa ghi lại được; (3) **Fail-closed boot (`exit != 0`)** không mở cổng mạng nếu `control.redb` đã tồn tại mà thiếu `emergency-revocations.bin` hoặc hỏng cả `Slot A` & `Slot B`. Khóa 4 fault-injection tests trong `revoked_ram.rs`. | ✅ **CLOSED** |
| **`Codex R2 #3`** | 🟠 High Risk | Trên Ubuntu Linux (`/var/run -> /run`), `mesh-server` đòi `/run/mesh` `0750 mesh:mesh-admin` trong khi `meshd` đòi `/var/run/mesh` `0755 root:root` → xung đột quyền thư mục khi VPS kiêm node (`US-056`). | `ADR-006:256-283`, `api-design.md:482-485,556-573`, `database-design.md:487-504`, `system-architecture.md:29-48`, `sprint-backlog.md:23,145`: Tách hoàn toàn thành 2 hệ thư mục độc lập: `mesh-server` dùng `/run/mesh-server/admin.sock` (`RuntimeDirectory=mesh-server` `0750 mesh:mesh-admin`), state `/var/lib/mesh/` (`0700 mesh:mesh`), log `/var/log/mesh/`; `meshd` dùng `/var/run/meshd/meshd-{admin,ro}.sock` (`RuntimeDirectory=meshd` `0755 root:root`), state Linux `/var/lib/meshd/` (`0700 root:root`), log `/var/log/meshd/`. Khóa kịch bản test co-residency cả 2 thứ tự khởi động. | ✅ **CLOSED** |
| **`Codex R2 #4`** | 🟠 High Risk | Bộ lọc `CandidateEndpoint` từ chối trùng `SocketAddr` của `control_tcp_endpoint` (TCP), làm mất Direct P2P UDP của VPS khi đặt `Control TCP :51820` và `meshd UDP :51820`. | `api-design.md:37`, `system-architecture.md:546-548` & `sprint-backlog.md:128`: Phân biệt rõ giao thức tầng 4 — `CandidateEndpoint` (UDP) **chỉ** từ chối khi trùng `stun_udp_endpoint` (`<vps_ip>:<stun_udp_port>` UDP), cho phép trùng số cổng với `control_tcp_endpoint` (TCP). Khóa vector kiểm thử `203.0.113.10:51820` (`true`) vs `203.0.113.10:3478` (`false`). | ✅ **CLOSED** |
| **`Codex R2 #5`** | 🟠 High Risk | Nhánh thực thi thật của `-Mode Msvc` trong `bootstrap-toolchain.ps1` chỉ gọi `winget` và thiếu bước tải/kiểm SHA-256 cho `zig`, `cargo-deny`, `cargo-zigbuild`, `rcodesign`. | `scripts/bootstrap-toolchain.ps1:104-195,264-301` & `ADR-001:63`: Tách hàm dùng chung `Install-CommonPrebuiltTools -CommonArtifacts $Artifacts[1..4]` (kiểm SHA-256 fail-closed) và `Invoke-CheckedVersion` cho cả `PortableZig` lẫn `Msvc`, kèm kiểm tra `$LASTEXITCODE` của `winget` và `rustup target add`. | ✅ **CLOSED** |
| **`Codex R2 Imp` & `NOTE-G2-R2-03`** | 🟡 Improve | `ADR-007` viết `priority 5182/5181` lệch với `51820/51810` trong kiến trúc & `ledger.json`. | `ADR-007:299-300`, `coding-standards.md:272`, `.agents/rules/coding-standards.md:41`, `sprint-backlog.md:143`: Thống nhất 100% `priority 51820` (`not fwmark 0x5d56 table 51820`) và `priority 51810` (`table main suppress_prefixlength 0`). | ✅ **CLOSED** |
| **`NOTE-G2-R2-01`** | 🟡 Note | Minh họa `is_stun_rfc5389` trong `api-design.md` dùng `buf[0]`, `buf[3]`, `buf[4..8]` dễ vướng `clippy::indexing_slicing = "deny"`. | `api-design.md:364-389`: Viết lại hoàn toàn bằng slice pattern matching (`let [b0, _, len_hi, len_lo, 0x21, 0x12, 0xA4, 0x42, ..] = buf else { return false; };` và `matches!(buf, ...)`), **0 phép cắt chỉ số trực tiếp**. | ✅ **CLOSED** |
| **`NOTE-G2-R2-02`** | 🟡 Note | Đồng bộ 1:1 tên tệp con của `mesh-datapath` và `meshd` giữa `system-architecture.md` và `sprint-backlog.md` Wave 2.1. | `system-architecture.md:695-734` & `sprint-backlog.md:220-221`: Khớp chính xác 1:1 từng tên tệp (`magic_socket.rs`, `rebind.rs`, `stun_client.rs`, `peer_map.rs`, `cryptokey.rs`, `disco_engine.rs`, `relay_client.rs`, `engine.rs`, `netmap_cache.rs`), giao cắt tập file giữa `WP-S2-01`, `WP-S2-02`, `WP-S2-03` bằng **$\emptyset$ (0% overlap)**. | ✅ **CLOSED** |

---

## 2. Tổng Hợp Truy Vết Đóng 100% Phát Hiện Vòng 1 (`agile-critic` 11/11 & `agile-codex` 14/14)

| Nhóm kiểm định | Mã phát hiện Vòng 1 | Nội dung cốt lõi đã khắc phục và bảo toàn qua v2.2 / v1.2 | Trạng thái |
| :--- | :--- | :--- | :---: |
| **`agile-critic` Blocker (4/4)** | `BLK-G2-01..04` | Ghim `rustc 1.94.1` + 5 gói prebuilt SHA-256 fail-closed (`BLK-G2-01`); `challenge_id` 1 lần + `tls_exporter_binding` tương thích Reverse Proxy `trusted_proxies` (`BLK-G2-02`); kiểm tra supplementary groups `getgrouplist` / `xucred.cr_groups` (`gid=80`) + tách socket `admin` (`0660`) / `ro` (`0666`) (`BLK-G2-03`); chặn `aws-lc-rs` (`default-features = false` + `ring`), thêm `x509-cert`, `rustls-webpki`, `rustls-native-certs` & `CDLA-Permissive-2.0` (`BLK-G2-04`). | ✅ **CLOSED** |
| **`agile-critic` High Risk & Improve (7/7)** | `HR-G2-01..04`, `IMP-G2-01..03` | Linux PBR `table 51820` + `ip rule` trong `ledger.json` & allowlist `sysexec` (`HR-G2-01`); sửa `awk` `FNR == 1` trong `check.sh` (`HR-G2-02`); chặn `Expired` khi `register`, dọn `idx_nodes_overlay_ip`, `emergency-revocations.bin` 64 KiB (`HR-G2-03`); tách `IngressSource::{DirectUdp, Relay}` chống đầu độc endpoint & 0% đụng độ file song song (`HR-G2-04`); `MIN_DISCO_PACKET_LEN = 172` (`IMP-G2-01`); bọc `Secret<Vec<u8>>` cho `ServerIdentity` (`IMP-G2-02`); rule `< 10 KB` (`IMP-G2-03`). | ✅ **CLOSED** |
| **`agile-codex` R1 (14/14)** | `#1..#14` | Demux STUN `(len_lo & 3) == 0` + test vectors (`#1`); chống phản xạ `SalsaBox` bằng `magic_ctx` + `inner_sender`/`inner_recipient` (`#2`); ngoại lệ hẹp `sha1` chỉ cho `tungstenite` (`#3`); tránh `E0453` cho `crates/mesh-sys` (`#4`); đơn điệu `netmap_version` (`#5`), thu hồi cấp cứu (`#6`), che khóa `ServerIdentity` (`#7`), lọc endpoint cho `vps.mesh.internal` (`#8`), thống nhất byte đầu frame Relay `0x01..0x04` (`#9`), hash fail-closed (`#10`), IPC macOS (`#11`), `check.sh` (`#12`), ghim `1.94.1` (`#13`), tách `admin_cmds.rs`/`client_cmds.rs` (`#14`). | ✅ **CLOSED** |

---

## ⚖️ 3. Các Đánh Đổi Chiến Lược Khách Quan (`Strategic Trade-offs`) Trình Người Dùng Tại Gate 2

Toàn bộ kiến trúc, hợp đồng DB/API, chuẩn mã nguồn và kế hoạch phân tách Sprint đã đạt độ chặt chẽ Production-grade với **0 lỗi tồn đọng**. Dưới đây là **5 đánh đổi chiến lược khách quan** để Scrum Master trình bày minh bạch cho Người dùng quyết định tại **Gate 2**:

1. **Phân bổ Phạm vi Sprint 1 vs Sprint 2 (`OQ-15` trong `sprint-backlog.md` §1)**:
   - **Phương án Mặc định hiện tại (bám sát 100% Gate 1)**: Sprint 1 hoàn thành **38 `Must` / 174 SP** (Walking Skeleton + Direct P2P dùng hằng ngày trên macOS 13+, Windows 10/11, Ubuntu VPS kiêm node `vps.mesh.internal` với IP + SPKI Pin & đổi cổng tùy ý); Sprint 2 hoàn thành **13 `Must` / 60 SP** (Production Hardening, `node revoke`, Key Expiry, Roaming/Sleep-Wake, Rate-limit, Hot Backup, Port Migration live).
   - **Đánh đổi / Tùy chọn cho Người dùng**: Nếu muốn dùng thử trên Internet thật ngay cuối Sprint 1 mà đã có sẵn nút cắt khẩn cấp khi mất laptop và cơ chế tự nối lại thông minh, có thể kéo sớm 3 story (`US-029`, `US-030`, `US-034` = **11 SP**) từ Sprint 2 sang Sprint 1 (Sprint 1 = `41 Must / 185 SP`, Sprint 2 = `10 Must / 49 SP`, tổng `234 SP` không đổi).
2. **Kho dữ liệu nhúng thuần Rust `redb 2.4` + High-Watermark Lease + `emergency-revocations.bin` (`ADR-005`)**:
   - **Lợi ích đạt được**: Loại bỏ hoàn toàn ~250.000 dòng mã C của SQLite, giữ binary ~3–6 MB, hỗ trợ Hot Atomic Snapshot Backup, tốn **0 lượt ghi đĩa cho 1.023 / 1.024 sự kiện `online/offline`** mà vẫn chống lùi `netmap_version` khi đồng hồ lùi + crash, và chống hồi sinh node đã thu hồi khi đầy đĩa `ENOSPC` (kèm báo cáo trung thực `persistence_tier` & fail-closed lúc boot nếu hỏng cả 2 slot cấp cứu).
   - **Đánh đổi**: Không dùng CLI `sqlite3` đọc trực tiếp tệp DB thô; mọi thao tác kiểm tra/sao lưu/khôi phục thực hiện qua `mesh node list`, `mesh audit list`, `mesh server backup` và `mesh server restore`.
3. **WireGuard Userspace Sans-I/O (`defguard_boringtun`) trên 1 `MagicSocket` UDP vs Kernel WireGuard (`ADR-002`)**:
   - **Lợi ích đạt được**: Chạy đồng nhất trên macOS 13+ (không cần chứng chỉ Apple Developer $99/năm), Windows 10/11 và Linux container (`NET_ADMIN`, không `--privileged`), đồng thời ghép chung STUN + Authenticated Disco + WireGuard trên đúng 1 cổng UDP để đục lỗ NAT chính xác nhất.
   - **Đánh đổi**: Thông lượng đỉnh ở mạng siêu cao (10 Gbps+) thấp hơn module nhân Linux, nhưng dư sức bão hòa đường truyền cá nhân/VPS phổ thông (≥ 300 Mbps – 1 Gbps) cho quy mô ≤ 20 thiết bị với mức tiêu thụ RAM nền mục tiêu ~4–10 MB.
4. **Toolchain Gọn nhẹ `PortableZig` (`winlibs MinGW-w64` + `Zig 0.13.0`) vs `Msvc` trên Máy Phát triển Windows (`ADR-001`, `ADR-011`)**:
   - **Lợi ích đạt được**: Cho phép biên dịch, chạy `cargo test`, `clippy`, `cargo-deny` và cross-compile sang Linux `musl` / macOS ngay trên máy Windows không có Visual Studio chỉ với ~360 MB công cụ prebuilt kiểm chứng SHA-256 fail-closed (đồng thời hỗ trợ đầy đủ `-Mode Msvc` với cùng bộ 4 công cụ prebuilt nếu cài VS Build Tools).
   - **Đánh đổi**: Chế độ `PortableZig` cục bộ dùng ABI `-pc-windows-gnu` (vẫn nạp `wintun.dll` và chạy Windows Service tương thích 100%), kết hợp GitHub Actions CI matrix biên dịch và kiểm chứng thêm bản native trên từng hệ điều hành thật (`ubuntu-latest`, `windows-latest`, `macos-latest`).
5. **Chính sách Ngoại lệ Hẹp trong `deny.toml` (`sha1` cho WebSocket Handshake & `CDLA-Permissive-2.0` cho Dữ liệu CA)**:
   - **Lợi ích đạt được**: Vẫn chặn cứng 100% các giấy phép copyleft (`AGPL`, `GPL`, `LGPL`, `MPL-2.0`), chặn OpenSSL/`aws-lc-rs`/C-SQLite và cấm dùng SHA-1 trong toàn bộ mã của Mesh VPN, đồng thời cho phép `tokio-tungstenite` thực hiện bắt tay chuẩn RFC 6455 (`Sec-WebSocket-Accept`) và đọc dữ liệu CA công cộng hợp lệ.

---

## 4. Kết Luận & Phán Quyết Bắt Buộc

Phán quyết kiểm định Độc lập Gate 2 (Round 3 Final Verification — v2.2 / v1.2): **`[APPROVED FOR GATE]`**
