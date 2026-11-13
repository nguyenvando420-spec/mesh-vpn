# Báo Cáo Kiểm Định & Nghiệm Thu Definition of Done — Sprint 1 (`sprint-1-dod-verification.md`)

- **Dự án**: Mesh VPN (Self-Hosted Encrypted Overlay Network — Rust `1.94.1`, `edition = "2024"`)
- **Sprint**: Sprint 1 (`WP-S1-00` .. `WP-S1-06`, **38 `Must` User Stories / 174 SP**)
- **Người kiểm định**: `agile-qa` (`gemini-4-argon-high` — biến thể model độc lập hoàn toàn với tác giả `hydrogen`)
- **Ngày nghiệm thu**: `2026-11-13`
- **Phán quyết tổng thể**: **`[PASS - ĐẠT DoD]`**

---

## 1. Bảng Tổng Hợp Kết Quả Thực Thi Thực Nghiệm

| Hạng Mục Kiểm Định | Lệnh Thực Thi Thực Nghiệm | Kết Quả | Chi Tiết Định Lượng |
| :--- | :--- | :---: | :--- |
| **1. Toolchain Pinned (`1.94.1`)** | `rustc --version` (trong `scripts/check.ps1`) | **PASS** | `rustc 1.94.1 (e408947bf 2026-03-25)`, `edition = "2024"`, `resolver = "3"`. |
| **2. Kiểm Tĩnh & Bảo Mật Kho Mã** | `scripts/check.ps1` Bước `[2/5]` | **PASS** | `0` file có UTF-8 BOM; `unsafe` cô lập 100% trong `crates/mesh-sys/`; `.expose_secret()` cô lập trong 4 crate cho phép; `0` cổng cứng `:443`/`:3478` ngoài `mesh-core`. |
| **3. Định Dạng Mã Nguồn (`rustfmt`)** | `cargo fmt --all -- --check` | **PASS** | 100% file `.rs` (4 spaces, `<= 100` cột, LF) tuân thủ `rustfmt.toml`. |
| **4. Phân Tích Tĩnh (`clippy -D warnings`)** | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **PASS** | `0` lỗi, `0` cảnh báo, `0` `#[allow(clippy::...)]`, tuân thủ ngưỡng `cognitive-complexity <= 20` và `too-many-lines <= 80`. |
| **5. Kiểm Thử Tự Động Toàn Workspace** | `cargo test --workspace --all-features` | **PASS** | **223 / 223 bài test PASS (`0` failed)**:<br>- Unit & Property-Based Tests: `215` passed<br>- Independent QA Integration & AppSec Tests: `8` passed |
| **6. Kiểm Toán Chuỗi Cung Ứng (`cargo-deny`)** | `cargo deny check advisories bans licenses sources` | **PASS** | `advisories ok, bans ok, licenses ok, sources ok` (`0` crate GPL/AGPL/MPL-2.0, `0` `openssl-sys`/`aws-lc-rs`/`rusqlite`). |
| **7. Biên Dịch & Kiểm Tra Chéo Đa Nền Tảng** | `scripts/check.ps1 -Cross` | **PASS** | `cargo zigbuild --workspace --target x86_64-unknown-linux-musl` + `cargo clippy --all-targets --all-features -- -D warnings` trên `x86_64-unknown-linux-musl`, `aarch64-apple-darwin`, `x86_64-apple-darwin`. |
| **8. Kiểm Tra Cú Pháp Shell POSIX/Bash** | `wsl bash -n` trên toàn bộ 12 scripts `.sh` | **PASS** | `0` lỗi cú pháp trên toàn bộ `scripts/*.sh` và `lab/**/*.sh`. |

---

## 2. Đối Chiếu Danh Mục Definition of Done (DoD Verification Checklist)

- [x] **100% Acceptance Criteria của các Stories trong Sprint đạt yêu cầu**:
  - Đã kiểm chứng toàn bộ **38/38 `Must` User Stories (174 SP)** thuộc `WP-S1-00..06` (chi tiết truy xuất tại `docs/05-quality-assurance/test-cases.md`).
  - Đã đóng toàn bộ các phát hiện từ vòng phản biện độc lập `wave-1-1-critique.md` (3 vòng) và `wave-1-2-critique.md` (2 vòng) của `agile-critic` + `agile-codex`.
- [x] **100% tuân thủ Code Format, Linter & Dependency Policy của `agile-tech-lead`**:
  - Không có `unwrap()`, `expect()`, `panic!()`, `todo!()`, `unimplemented!()`, `unreachable!()`, `dbg!()`, hoặc `slice[i]` trong code nghiệp vụ.
  - Mọi crate TLS (`rustls`, `tokio-rustls`, `reqwest`, `instant-acme`) dùng `default-features = false` + `ring`, chặn hoàn toàn `aws-lc-rs` và `openssl-sys`.
- [x] **100% khớp API Contract & DB Schema của `agile-architect`**:
  - Control REST & WebSocket (`/v1/auth/challenge`, `/v1/nodes/register`, `/v1/endpoints`, `/v1/disco/call-me-maybe`, `/v1/netmap/stream`, `/v1/relay`) khớp 100% với `docs/03-system-design/api-design.md`.
  - Lược đồ `redb` 9 bảng (`schema_meta`, `server_identity`, `nodes`, `idx_nodes_pubkey`, `idx_nodes_overlay_ip`, `idx_nodes_name`, `preauth_keys`, `idx_preauth_hash`, `audit_events`) kèm tiền tố envelope `0x01` và tệp dự phòng khẩn cấp `emergency-revocations.bin` (`64 KiB` Slot A/B) khớp 100% với `docs/03-system-design/database-design.md`.
- [x] **Đạt toàn bộ yêu cầu Bảo mật (AppSec), An toàn Máy thật (`G4`) & Production-Readiness**:
  - **`SEC-01` (Không rò rỉ khóa bí mật)**: `Secret<T>` (`ZeroizeOnDrop`) và `PreAuthToken` luôn in `"[REDACTED]"`; `test_no_secrets_in_outputs` xanh trên toàn bộ các crate (`mesh-core`, `mesh-crypto`, `mesh-store`, `mesh-datapath`, `mesh`).
  - **`SEC-04` (TLS 1.3 & SPKI Pinning mặc định, cấm TOFU)**: `SpkiPinVerifier` đối chiếu SHA-256 SPKI DER bằng `ConstantTimeEq`, kiểm tra hạn chứng chỉ trả `ErrorKind::ClockSkew`, hỗ trợ xoay khóa kép (`active_pin` + `next_pin`), từ chối kết nối IP thiếu `--server-pin`.
  - **`SEC-05` & `US-003 AC4` (Single-Use Challenge & Thông điệp lỗi đồng nhất)**: `challenge_id` bị xóa nguyên tử trước khi giải mã `SalsaBox`; phát lại `challenge_id` lần 2 bị chặn 100% với `HTTP 401` và thông điệp cố định `"authentication failed"`.
  - **`US-005 AC2` (Idempotent Concurrency)**: 3 yêu cầu đăng ký đồng thời cùng `node_pubkey` và 1 one-time pre-auth key chỉ tạo đúng 1 `NodeId` và cấp phát đúng 1 `OverlayIp`.
  - **`US-025 AC6` (Blind Relay `mpsc::channel(256)` + `try_send()`)**: Chuyển tiếp mù `0x01` -> `0x02` gắn `src_pubkey` đã xác thực; mỗi đích có hàng đợi giới hạn 256 gói dùng `try_send()` drop-tail, không gây Head-of-Line blocking sang các peer khác.
  - **`US-021 AC5` & `HR-G2-04` (Chống đầu độc `direct_addr` qua Relay)**: `DiscoPong` đi qua `IngressSource::Relay` chỉ đo RTT Relay, tuyệt đối không nâng cấp đường truyền lên `Direct` hoặc ghi đè `direct_addr`.
  - **`US-014 AC4` & `SEC-11` (`AllowedIPs = /32` Cryptokey Routing)**: `CryptokeyValidator::validate_inbound` chặn 100% gói tin IPv4 giải mã từ đường hầm WireGuard nếu IP nguồn bên trong khác với IP `/32` đã khóa của peer.
  - **Gate 2 Dual `EIO` (Nhánh (a) & Nhánh (b))**: Khi cả `redb` và `emergency-revocations.bin` gặp lỗi `EIO`, lệnh thu hồi vẫn có hiệu lực tức thì trong `RevokedSet` RAM (`PersistenceTier::RamOnly`), không đánh bật các mục `EmergencySlot` cũ và tự động gộp vào `control.redb` khi đĩa hồi phục; nếu trùng lúc cạn kiệt lease `MonotonicNetmapVersion`, server không phát sinh `netmap_version` chưa bền vững mà ngắt kết nối buộc các peer xác thực lại.
  - **`SEC-14` & `G4` (Bảo vệ IPC và Máy thật)**: Tách biệt kênh IPC `admin` và `ro` (`<= 4 KiB`, `0` secrets); `ResourceLedger` ghi đĩa `0600` trước khi tạo tài nguyên OS; chống vòng lặp định tuyến (`IP_BOUND_IF`, `IP_UNICAST_IF`, `SO_MARK = 0x5d56`); chỉ sửa khối `# BEGIN mesh ... # END mesh` trong `hosts`.
- [x] **Toàn bộ bộ test tự động PASS 100%, không còn Bug `Critical` / `Major`**:
  - Không có lỗi tồn đọng; không cần tạo `bug-reports.md`.

---

## 3. Kết Luận Nghiệm Thu

Toàn bộ mã nguồn, cấu hình triển khai và bộ kiểm thử tự động của **Sprint 1 (`WP-S1-00` .. `WP-S1-06`, 38 `Must` stories / 174 SP)** đã vượt qua 100% bài kiểm định thực nghiệm độc lập của QA & AppSec.

> **PHÁN QUYẾT CUỐI CÙNG: `[PASS - ĐẠT DoD]`** — Đủ điều kiện trình duyệt **Gate 3 (Sprint Review & Release)**.
