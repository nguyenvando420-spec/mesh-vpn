# Gate 2 Independent Red-Team Critique & Round 2 Re-Verification — Rust 1.94.1 Tech Stack, Coding Standards, Architecture, DB/API Contracts & Sprint Plan

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Cổng kiểm định** | **Gate 2** — Tech Stack, Coding Standards, System Architecture, DB/API Contracts & Sprint Plan (**Round 2 Re-Verification**) |
| **Người phản biện** | `agile-critic` (Principal Reviewer & Independent Red-Team Critic) |
| **Ngày kiểm định** | 2026-11-12 (Round 1: 22:08 · Round 2: 22:55) |
| **Thành phần AI/SLM** | **KHÔNG CÓ** (Dự án thuần hạ tầng mạng & hệ thống — không áp dụng khung kiểm định AI/SLM) |
| **Đầu vào đối chiếu (Gate 1 v1.2)** | `production-readiness-requirements.md`, `project-charter.md`, `product-backlog.md` (74 stories: 51 `Must` / 234 SP, 11 `Should` / 35 SP, 12 Phase 2+) |
| **Đầu ra đã kiểm chứng (Gate 2 v2.1 / v1.1)** | `tech-stack-decision.md` (v2.1), `architecture-decision-record.md` (v2.1 `ADR-001..011`), `coding-standards.md` (v2.1), `.agents/rules/coding-standards.md`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.editorconfig`, `.gitignore`, `.gitattributes`, `scripts/{bootstrap-toolchain.ps1,check.ps1,check.sh}`, `system-architecture.md` (v2.1), `database-design.md` (v2.1), `api-design.md` (v2.1), `sprint-backlog.md` (v1.1) |
| **Trạng thái lỗi Vòng 1** | **11/11 mục của `agile-critic`** (`BLK-G2-01..04`, `HR-G2-01..04`, `IMP-G2-01..03`) & **14/14 mục của `agile-codex`** (`#1..#14`): **ĐÃ ĐÓNG DỨT ĐIỂM 100%** |
| **Lỗi nghiêm trọng còn tồn đọng** | **`0 🔴 Blocker` · `0 🟠 High Risk`** *(chỉ kèm 3 lưu ý vệ sinh khi code `🟡 Implementation Notes` không chặn Gate)* |
| **Phán quyết cuối** | **`[APPROVED FOR GATE]`** |

---

## 1. Tổng Quan Kết Quả Tái Thẩm Định Thực Nghiệm (Round 2)

Sau vòng phản biện độc lập thứ nhất của `agile-critic` và `agile-codex`, đội ngũ `agile-tech-lead`, `agile-architect` và `agile-scrum-master` đã thực hiện bản sửa đổi đồng bộ (v2.1 / v1.1). Ở Vòng 2, `agile-critic` đã mở đọc trực tiếp từng dòng của tất cả các tệp cập nhật và chạy kiểm chứng thực nghiệm độc lập với kết quả sau:

1. **Kiểm chứng thực nghiệm Script, Toolchain & SHA-256 Chuỗi cung ứng**:
   - Chạy `powershell -ExecutionPolicy Bypass -File scripts/check.ps1` với `rust-toolchain.toml` đã ghim cứng `channel = "1.94.1"`: **PASS (`exit code 0`)**, xác nhận `rustc 1.94.1 (e408947bf 2026-03-25)`, **0 tệp dính UTF-8 BOM** trên toàn repo.
   - Chạy `powershell -ExecutionPolicy Bypass -File scripts/bootstrap-toolchain.ps1 -DryRun`: **PASS (`exit code 0`)**.
   - Truy vấn trực tiếp HTTP `HEAD` và đối chiếu mã băm SHA-256 độc lập cho **cả 5 gói công cụ prebuilt** trong `scripts/bootstrap-toolchain.ps1`: cả 5 URL đều sống (`HTTP 200 OK`) và **khớp bit-for-bit 100% mã SHA-256 chính thức** (`winlibs MinGW-w64 GCC 16.2.0-r3`, `Zig 0.13.0`, `cargo-deny 0.20.2`, `cargo-zigbuild v0.24.1`, `apple-codesign 0.29.0`), hàm `Assert-FileSha256` xóa tệp hỏng và `throw` ngay lập tức (fail-closed, 0 cờ bypass).
2. **Kiểm chứng Rule tự nạp cho Subagents**:
   - `.agents/rules/coding-standards.md` mở đầu đúng frontmatter `---\ntrigger: always_on\n---`, UTF-8 không BOM, kết thúc dòng LF, dung lượng chính xác **`9,907 bytes` (`< 10,000 bytes`)**, đồng bộ đầy đủ các quy tắc mới (`x509-cert`, `rustls-webpki`, `rustls-native-certs`, `E0453` cho `mesh-sys`, Dual IPC sockets, Linux `table 51820` + `ip rule`, `sysexec` allowlist).
3. **Kiểm chứng Toán học Giao thức Nhị phân & Cấu trúc Đĩa**:
   - **STUN Demux & Test Vectors (`api-design.md` §3.1–§3.2)**: Điều kiện `(buf[0] & 0b1100_0000) == 0 && (buf[3] & 0b0000_0011) == 0 && buf[4..8] == [0x21, 0x12, 0xA4, 0x42]` tuân thủ đúng RFC 5389 §6 cho cả Request (`0x0001`) lẫn Response (`0x0101`). Vector kiểm thử `198.51.100.77:51829` XOR với `0x2112A442` ra `[0xEB, 0x67, 0xE7, 0x21, 0xC0, 0x0F]` khớp chính xác từng bit.
   - **Authenticated Disco (`api-design.md` §3.3)**: Tổng kích thước `63B (Outer) + 93B (Inner header gồm magic_ctx + sender + recipient) + 16B (Poly1305) = 172 bytes` (`MIN_DISCO_PACKET_LEN = 172`) khớp chính xác tuyệt đối; cơ chế kiểm tra hai chiều `inner_sender == outer_sender` & `inner_recipient == self` triệt tiêu hoàn toàn tấn công phản xạ `SalsaBox`.
   - **Tệp cấp cứu `emergency-revocations.bin` (`database-design.md` §4.2)**: Mỗi Slot A/B có tổng `8 + 8 + 8 + 2 + 2 + 28_000 + 4_000 + 736 + 4 = 32_768 bytes` (`32 KiB` × 2 = đúng `65_536 bytes` = `64 KiB`), cấp phát trước bằng `posix_fallocate`, ghi đè tại chỗ 0 block mới khi `ENOSPC`.
4. **Kiểm chứng Toán học Backlog & Phân tách Song song (`sprint-backlog.md` v1.1)**:
   - Bảo toàn 100% **51 `Must` / 234 SP** (Sprint 1 = `38 Must / 174 SP`, Sprint 2 = `13 Must / 60 SP`), **11 `Should` / 35 SP**, và **12 stories Phase 2+** (`US-061..072`).
   - Giao cắt tập hợp file giữa các Work Package chạy song song trong cùng Wave 1.1 (`WP-S1-01..04`), Wave 1.2 (`WP-S1-05..06`) và Wave 2.1 (`WP-S2-01..03`) bằng **$\emptyset$ (0% file overlap)**.

---

## 2. Ma Trận Kiểm Chứng Đóng Toàn Bộ Phát Hiện Vòng 1 (`agile-critic` & `agile-codex`)

### 2.1. Các Phát Hiện Của `agile-critic` (11/11 Đã Đóng)

| Mã | Mức cũ | Nội dung tóm tắt | Bằng chứng xác minh trong bản sửa v2.1 / v1.1 | Trạng thái |
| :--- | :---: | :--- | :--- | :---: |
| **`BLK-G2-01`** | 🔴 Blocker | Thiếu `link.exe` trên máy Windows khi `cargo install`, thiếu `llvm-mingw`/`rcodesign`, sai & fail-open SHA-256 Zig, `rust-toolchain.toml` để `stable`. | `rust-toolchain.toml:2` ghim `channel = "1.94.1"`. `bootstrap-toolchain.ps1:35-100,131-235` cài `1.94.1-x86_64-pc-windows-gnu` + tải 5 bản prebuilt (`winlibs`, `zig`, `cargo-deny`, `cargo-zigbuild`, `rcodesign`) với SHA-256 chuẩn 100% & `Assert-FileSha256` fail-closed. `check.ps1:122-137` tự chuyển sang `+1.94.1-x86_64-pc-windows-gnu` khi thiếu `link.exe`. | ✅ **CLOSED** |
| **`BLK-G2-02`** | 🔴 Blocker | Hỏng xác thực `tls_exporter_binding` sau Reverse Proxy & mâu thuẫn vòng đời `session_id` dùng 1 lần trên nhiều kết nối TCP/WS. | `ADR-003:128-132` & `api-design.md:41-109,245-275`: thay bằng `challenge_id` dùng 1 lần (`TTL=30s`, `MAX=4096`) trên cùng kết nối Keep-Alive; `ProofPayload` trói `(method, path, body_sha256, challenge_nonce, timestamp_at_ms, tls_exporter_binding)`; Client luôn gửi exporter, Server chỉ bỏ qua bước so sánh exporter khi `tls_mode == ReverseProxy` + `trusted_proxies`; hỗ trợ gửi `EndpointUpdate`/`CallMeMaybe` qua WS `/v1/netmap/stream`. | ✅ **CLOSED** |
| **`BLK-G2-03`** | 🔴 Blocker | `peer_cred` khóa nhầm Admin nhóm phụ trên macOS (`gid 80`) & Linux (`mesh-admin`), socket `0660` chặn user thường chạy `mesh status` trên macOS. | `ADR-006:252-263`, `api-design.md:480-487,540-549`, `database-design.md:479-480`: Linux kiểm tra `SO_PEERCRED` + `getpwuid_r`/`getgrouplist`; Client tách `meshd-admin.sock` (`0660`, macOS đọc `xucred.cr_groups` chứa `80` + fallback `getgrouplist`) và `meshd-ro.sock` (`0666`, chỉ 4 route đọc, ≤ 4 KiB, 0 secret). | ✅ **CLOSED** |
| **`BLK-G2-04`** | 🔴 Blocker | Bẫy default feature `aws-lc-rs`, giấy phép `webpki-roots`, thiếu crate X.509/WebPKI cho `SpkiPinVerifier` (`ClockSkew`, RSA/ECDSA SPKI). | `tech-stack-decision.md:191-203,244-256` & `deny.toml:34,61-62`: thêm `x509-cert 0.2`, `rustls-webpki`, `rustls-native-certs`; ép `default-features = false` + `ring`; cho phép `CDLA-Permissive-2.0` (giữ cấm `MPL-2.0`). `ADR-008:332-337` khóa rõ kiểm tra hạn `ClockSkew` + SPKI DER + chữ ký TLS `ring`. | ✅ **CLOSED** |
| **`HR-G2-01`** | 🟠 High Risk | Linux `SO_MARK` thiếu bảng PBR `table 51820` + `ip rule` trong `ResourceLedger`; `sysexec` thiếu `/sbin/ifconfig`, `/usr/sbin/ip`, đường dẫn tuyệt đối Windows. | `system-architecture.md:520,796`, `database-design.md:531-568` ghi rõ `table 51820` + 2 `ip rule` lưu trước vào `ledger.json`. `coding-standards.md:274-278` bổ sung `/sbin/ifconfig`, `/usr/sbin/ip`, `/sbin/ip` và `GetSystemDirectoryW` + `System32\*.exe`. | ✅ **CLOSED** |
| **`HR-G2-02`** | 🟠 High Risk | Lỗi `awk` batching (`NR==1` và `exit`) trong `scripts/check.sh` bỏ sót >95% file trên Linux/macOS. | `scripts/check.sh:37-43,75-79` sửa sang `FNR == 1` cho kiểm tra BOM (dùng `sprintf("%c%c%c", 239, 187, 191)`) và đặt cờ `FNR == 1 { in_test = 0 }` theo từng file cho kiểm tra cổng cứng. | ✅ **CLOSED** |
| **`HR-G2-03`** | 🟠 High Risk | Sau `ENOSPC`, restart làm sống lại node đã thu hồi & tụt `netmap_version`; Bước 1 `register` quên chặn `NodeStatus::Expired`. | `database-design.md:352,367,380-452`: chặn `Expired` trả `401`; dọn `idx_nodes_overlay_ip` khi tái cấp IP hết quarantine; cấp phát sẵn `emergency-revocations.bin` (`64 KiB` A/B slots) + `MonotonicNetmapVersion` `AtomicU64` khởi tạo từ `max(db, slot, now_ms)`. | ✅ **CLOSED** |
| **`HR-G2-04`** | 🟠 High Risk | `DiscoPong` qua Blind Relay có nguy cơ đầu độc `DirectAddr`; đụng độ file `hosts.rs` (Wave 1.1) & `meshd` (Wave 2.1). | `api-design.md:459-475` tách `IngressSource::{DirectUdp, Relay}` (cấm nâng cấp `Direct` từ Relay) & khóa `disco_frame_b64`. `sprint-backlog.md:97,172-175,219-221` hoàn tất `hosts.rs` ở `WP-S1-00` và tách `admin_cmds.rs` / `client_cmds.rs` / `rebind.rs` với 0% đụng độ file. | ✅ **CLOSED** |
| **`IMP-G2-01`** | 🟡 Improve | Sai số độ dài tối thiểu gói Disco (`62` bytes). | `api-design.md:373,434-436` & `system-architecture.md:486` cập nhật chính xác `MIN_DISCO_PACKET_LEN = 172`. | ✅ **CLOSED** |
| **`IMP-G2-02`** | 🟡 Improve | `ServerIdentityRecord` lộ khóa riêng qua `#[derive(Debug, Serialize)]`. | `database-design.md:208-257` bọc `Secret<Vec<u8>>` trong `ServerIdentity` và tách `StoredServerIdentityDto` nội bộ (cấm `Debug`/`Clone`, xóa đệm JSON bằng `.zeroize()`). | ✅ **CLOSED** |
| **`IMP-G2-03`** | 🟡 Improve | Thừa tham chiếu `tower` & giữ `.agents/rules/coding-standards.md` `< 10 KB`. | `tech-stack-decision.md:209` bỏ `tower` rời; `.agents/rules/coding-standards.md` đạt `9,907 bytes` (`< 10,000 bytes`). | ✅ **CLOSED** |

### 2.2. Các Phát Hiện Song Song Của `agile-codex` (14/14 Đã Đóng)

| Mã Codex | Nội dung tóm tắt | Bằng chứng xác minh trong bản sửa v2.1 / v1.1 | Trạng thái |
| :--- | :--- | :--- | :---: |
| **`#1` (🔴)** | Điều kiện demux STUN kiểm tra nhầm `buf[1] & 3 == 0` thay vì `buf[3] & 3 == 0`, loại bỏ cả Request `0x0001` và Response `0x0101`. | `api-design.md:367,375-381,406-420` sửa thành `(buf[3] & 0b0000_0011) == 0` kèm kiểm tra `20 + msg_len <= buf.len()` và bổ sung 2 vector byte cụ thể (`0x0001` & `0x0101`). | ✅ **CLOSED** |
| **`#2` (🔴)** | `SalsaBox` đối xứng hai chiều thiếu định danh chiều gửi trong ciphertext Disco → nguy cơ tấn công phản xạ gói. | `ADR-003:138-145` & `api-design.md:438-458` đưa `magic_ctx = b"MESHDSv1"`, `inner_sender_disco_pubkey`, `inner_recipient_disco_pubkey` vào trong hộp mã hóa và cưỡng chế kiểm tra `ct_eq` trước khi xử lý. | ✅ **CLOSED** |
| **`#3` (🔴)** | `deny.toml` cấm cứng `sha1` làm chặn chính `tungstenite` (RFC 6455 WebSocket handshake). | `deny.toml:67` & `tech-stack-decision.md:285` cô lập ngoại lệ hẹp `{ name = "sha1", wrappers = ["tungstenite"] }`, tiếp tục cấm `sha1` ở mọi crate khác. | ✅ **CLOSED** |
| **`#4` (🔴)** | `crates/mesh-sys` kế thừa `unsafe_code = "forbid"` từ workspace sẽ bị lỗi trình biên dịch `E0453`. | `ADR-001:57-60` & `coding-standards.md:85-110` quy định `mesh-sys/Cargo.toml` khai báo bảng `[lints]` riêng (`unsafe_code = "allow"`, `unsafe_op_in_unsafe_fn = "deny"`, `undocumented_unsafe_blocks = "deny"`). | ✅ **CLOSED** |
| **`#5, #6, #7` (🟠)** | Hai nguồn `netmap_version` độc lập, mất trạng thái thu hồi sau `ENOSPC` restart, lộ khóa PKCS#8 trong `ServerIdentity`. | Đã đóng đồng bộ cùng `HR-G2-03` và `IMP-G2-02` (`MonotonicNetmapVersion`, `emergency-revocations.bin` 64 KiB A/B slots, `Secret<Vec<u8>>`). | ✅ **CLOSED** |
| **`#8` (🟠)** | Bộ lọc endpoint loại toàn bộ IP public của VPS làm `vps.mesh.internal` (`US-056`) mất khả năng Direct P2P UDP. | `system-architecture.md:538-540` & `api-design.md:37` sửa chỉ chặn đúng cặp `SocketAddr` (`<vps_ip>:<control_port>` và `<vps_ip>:<stun_port>`), cho phép `<vps_ip>:51820` chạy Direct P2P. | ✅ **CLOSED** |
| **`#9` (🟠)** | Ba tài liệu mô tả byte đầu của khung nhị phân Blind Relay lệch nhau (`0x01` vs `0x02`). | `ADR-004:174-179`, `system-architecture.md:309-311,499` và `api-design.md:347-353` đã thống nhất 100%: `0x01` (`Client->Relay`), `0x02` (`Relay->Client`), `0x03` (`KeepAlive`), `0x04` (`ControlNotice`). | ✅ **CLOSED** |
| **`#10, #11, #12, #13, #14`** | Hash Zig fail-open (`#10`), quyền IPC macOS (`#11`), `check.sh` batching (`#12`), ghim `1.94.1` (`#13`), owner CLI Sprint 2 (`#14`). | Đã đóng đồng bộ cùng `BLK-G2-01`, `BLK-G2-03`, `HR-G2-02` và `HR-G2-04` (`admin_cmds.rs` thuộc `WP-S2-01`, `client_cmds.rs` thuộc `WP-S2-02`). | ✅ **CLOSED** |

---

## 3. Lưu Ý Nhỏ Khi Hiện Thực Hóa Ở Sprint 1 (`🟡 Implementation Hygiene Notes` — Không Chặn Gate)

Các điểm dưới đây chỉ là lưu ý vệ sinh mã nguồn để các `agile-developer` lưu tâm khi bắt tay viết code ở Sprint 1 (không yêu cầu sửa lại tài liệu thiết kế trước Gate 2):

1. **`NOTE-G2-R2-01` (`WP-S1-00` — Viết `is_stun_rfc5389` không dùng `buf[i]` trực tiếp)**:
   Đoạn mã minh họa logic tại `api-design.md:375-381` viết `buf[0]`, `buf[3]`, `buf[4..8]` để dễ đọc công thức bit; khi hiện thực trong `crates/mesh-proto/src/lib.rs`, Developer dùng destructuring slice (`let [b0, _, len_hi, len_lo, 0x21, 0x12, 0xA4, 0x42, ..] = buf else { return false; };`) hoặc `.get(...)` để thỏa mãn tuyệt đối `clippy::indexing_slicing = "deny"`.
2. **`NOTE-G2-R2-02` (`WP-S1-02` / `WP-S1-05` — Đồng bộ tên tệp con trong `crates/mesh-datapath/src/`)**:
   Khi tạo cây tệp ở `WP-S1-02` và chuẩn bị stub `rebind.rs` ở cuối Sprint 1 (`WP-S1-05`), giữ thống nhất tên tệp module giữa `system-architecture.md:688-695` và bảng phân vùng của `sprint-backlog.md:220-221` để bước chạy song song ở Sprint 2 khớp 1:1.
3. **`NOTE-G2-R2-03` (`ADR-007:293` vs `database-design.md:549` — Hằng số `priority` của `ip rule` trên Linux)**:
   Chọn thống nhất một cặp hằng số (`51810` và `51820` như trong `system-architecture.md:520` & `database-design.md:549-555`) trong `crates/mesh-net/src/route_linux.rs` và luôn đọc đúng `priority` đã lưu trong `ledger.json` khi gỡ rule.

---

## ⚖️ 4. Các Đánh Đổi Chiến Lược Khách Quan (`Strategic Trade-offs`) Trình Người Dùng Tại Gate 2

Toàn bộ thiết kế kỹ thuật đã sạch lỗi nghiêm trọng và sẵn sàng mở Cổng Duyệt **Gate 2**. Dưới đây là **5 đánh đổi chiến lược khách quan** để Scrum Master trình bày minh bạch cho Người dùng xác nhận trước khi khởi chạy Sprint 1:

1. **Phân bổ Phạm vi Sprint 1 vs Sprint 2 (`OQ-15` trong `sprint-backlog.md` §1)**:
   - **Phương án Mặc định hiện tại (bám sát 100% Gate 1)**: Sprint 1 hoàn thành **38 `Must` / 174 SP** (Walking Skeleton + Direct P2P dùng hằng ngày trên macOS, Windows, Ubuntu VPS với IP + SPKI Pin & đổi cổng tùy ý); Sprint 2 hoàn thành **13 `Must` / 60 SP** (Production Hardening, `node revoke`, Key Expiry, Roaming/Sleep-Wake, Rate-limit, Hot Backup, Port Migration live).
   - **Đánh đổi / Tùy chọn cho Người dùng**: Nếu muốn dùng thử trên Internet thật ngay cuối Sprint 1 mà đã có sẵn nút cắt khẩn cấp khi mất laptop và cơ chế tự nối lại thông minh, có thể kéo sớm 3 story (`US-029`, `US-030`, `US-034` = **11 SP**) từ Sprint 2 sang Sprint 1 (Sprint 1 = `41 Must / 185 SP`, Sprint 2 = `10 Must / 49 SP`, tổng `234 SP` không đổi).
2. **Kho dữ liệu nhúng thuần Rust `redb 2.4` vs C-SQLite (`rusqlite`) (`ADR-005`)**:
   - **Lợi ích đạt được**: Loại bỏ hoàn toàn ~250.000 dòng mã C và khối `unsafe` FFI của SQLite, giúp cross-compile 4 nền tảng mượt mà, giữ kích thước binary ~3–6 MB và RAM rất thấp mà vẫn đảm bảo giao dịch ACID MVCC + Hot Atomic Snapshot Backup.
   - **Đánh đổi**: Không dùng công cụ dòng lệnh `sqlite3` có sẵn trên Linux để đọc trực tiếp tệp DB thô; mọi thao tác kiểm tra/sao lưu/khôi phục đều đi qua các lệnh chuẩn hóa `mesh node list`, `mesh audit list`, `mesh server backup` và `mesh server restore`.
3. **WireGuard Userspace Sans-I/O (`defguard_boringtun`) trên 1 `MagicSocket` UDP vs Kernel WireGuard (`ADR-002`)**:
   - **Lợi ích đạt được**: Chạy đồng nhất trên macOS 13+ (không cần chứng chỉ Apple Developer $99/năm), Windows 10/11 và Linux container (`NET_ADMIN`, không cần `--privileged`), đồng thời ghép chung STUN + Disco + WireGuard trên đúng 1 cổng UDP để đục lỗ NAT chính xác nhất.
   - **Đánh đổi**: Thông lượng đỉnh ở mạng tốc độ siêu cao (10 Gbps+) thấp hơn module trong nhân Linux, nhưng dư sức bão hòa đường truyền cá nhân/VPS phổ thông (≥ 300 Mbps – 1 Gbps) cho quy mô ≤ 20 thiết bị với mức tiêu thụ RAM nền ~4–10 MB.
4. **Toolchain Gọn nhẹ Không Cần Visual Studio (`PortableZig` = `winlibs MinGW-w64` + `Zig 0.13.0`) trên Máy Phát triển Windows (`ADR-001`, `ADR-011`)**:
   - **Lợi ích đạt được**: Cho phép biên dịch, chạy `cargo test`, `clippy`, `cargo-deny` và cross-compile sang Linux `musl` / macOS ngay trên máy Windows hiện tại chỉ với ~360 MB công cụ kiểm chứng SHA-256 fail-closed trong `%USERPROFILE%\sdk`, không bắt cài đặt ~6 GB Visual Studio Build Tools.
   - **Đánh đổi**: Bản chạy phát triển cục bộ trên máy Windows không có Visual Studio dùng ABI `-pc-windows-gnu` (vẫn nạp `wintun.dll` và chạy Windows Service tương thích 100%), trong khi GitHub Actions CI matrix sẽ biên dịch và kiểm chứng thêm cả bản native Windows/macOS/Linux trên từng hệ điều hành thật.
5. **Chính sách Ngoại lệ Hẹp trong `deny.toml` (`sha1` cho WebSocket Handshake & `CDLA-Permissive-2.0` cho Dữ liệu CA)**:
   - **Lợi ích đạt được**: Vẫn chặn cứng 100% các giấy phép copyleft (`AGPL`, `GPL`, `LGPL`, `MPL-2.0`), chặn OpenSSL/`aws-lc-rs`/C-SQLite và cấm dùng SHA-1 trong toàn bộ mã của Mesh VPN, đồng thời cho phép `tokio-tungstenite` thực hiện bắt tay chuẩn RFC 6455 (`Sec-WebSocket-Accept`) và đọc dữ liệu CA công cộng một cách hợp lệ.

---

## 5. Kết Luận & Phán Quyết Bắt Buộc

Phán quyết kiểm định Độc lập Gate 2 (Round 2): **`[APPROVED FOR GATE]`**
