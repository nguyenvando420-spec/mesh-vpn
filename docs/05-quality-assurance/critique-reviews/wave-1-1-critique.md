# Phản Biện Độc Lập Sprint 1 — Wave 1.1 (`WP-S1-01`..`WP-S1-04`) (`agile-critic` — Round 1, Round 2 & Final Round 3 Sign-off)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Giai đoạn & Phạm vi kiểm định** | **Sprint 1 — Wave 1.1** (`WP-S1-01`, `WP-S1-02`, `WP-S1-03`, `WP-S1-04` — mã nguồn, FFI `unsafe`, dịch vụ hệ thống & kịch bản cài đặt) |
| **Người phản biện** | `agile-critic` (`gemini-4-carbon-high` — độc lập hoàn toàn với tác giả `gemini-4-hydrogen-xhigh`, Zero Confirmation Bias) |
| **Ngày kiểm định** | Vòng 1: `2026-11-13` · Vòng 2: `2026-11-13` · Vòng 3 (Sign-off): `2026-11-13` |
| **Tài liệu đối chiếu** | `.agents/rules/coding-standards.md`, `docs/03-system-design/{system-architecture.md,database-design.md,api-design.md,architecture-decision-record.md}`, `docs/02-product-planning/product-backlog.md`, `docs/04-sprint-management/sprint-backlog.md` |
| **Tổng hợp Vòng 1** | **`10` 🔴 Blocker** (`BLK-S1-01`..`BLK-S1-10`) · **`11` 🟠 High Risk** (`HR-S1-01`..`HR-S1-11`) · **`2` 🟡 Improvement** (`IMP-S1-01`..`IMP-S1-02`) → `[REVISION REQUIRED]` |
| **Tổng hợp Vòng 2** | Đóng `21 / 23` mục (`WP-S1-02`, `WP-S1-03`, `WP-S1-04` sạch `100%`); phát hiện **`1` 🔴 Blocker** (`BLK-S1-05-R2`) & **`1` 🟠 High Risk** (`HR-S1-12-R2`) trong `WP-S1-01` → `[REVISION REQUIRED]` |
| **Tổng hợp Vòng 3 (Cuối)** | **Đã đóng sạch `100%` (`23 / 23` mục Vòng 1 + `2 / 2` mục Vòng 2 · `0` Blocker · `0` High Risk · `0` `#[allow(clippy::...)]` trên toàn `crates/`)** |
| **Phán quyết Cuối (Vòng 3)** | **`[APPROVED FOR GATE]`** |

---

## 0. Tóm Tắt Kết Quả Thẩm Định Qua 3 Vòng (Executive Summary)

| Gói công việc | Tổng mục Vòng 1 | Đã đóng Vòng 2 | Đã đóng Vòng 3 (Cuối) | Mở còn lại | Trạng thái Cuối |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`WP-S1-01`** | 10 *(5 BLK, 5 HR)* | 8 / 10 *(phát sinh `BLK-S1-05-R2`, `HR-S1-12-R2`)* | **10 / 10 + 2 / 2 R2 (`100%`)** | **0** | **✅ ĐẠT CHUẨN 100%** |
| **`WP-S1-02`** | 3 *(3 HR)* | 3 / 3 | **3 / 3 (`100%`)** | **0** | **✅ ĐẠT CHUẨN 100%** |
| **`WP-S1-03`** | 6 *(3 BLK, 2 HR, 1 IMP)* | 6 / 6 | **6 / 6 (`100%`)** | **0** | **✅ ĐẠT CHUẨN 100%** |
| **`WP-S1-04`** | 5 *(3 BLK, 1 HR, 1 IMP)* | 5 / 5 | **5 / 5 (`100%`)** | **0** | **✅ ĐẠT CHUẨN 100%** |

*(Chi tiết đối chiếu từng dòng mã nguồn của Vòng 2 và xác nhận nghiệm thu cuối Vòng 3 kèm **⚖️ Strategic Trade-offs** nằm tại **Mục 5 & Mục 6** cuối tài liệu này.)*

---

## 1. Bảng Tổng Hợp Theo Gói Công Việc (`WP-S1-01`..`WP-S1-04`)

| Gói công việc | Phạm vi sở hữu tệp | 🔴 Blocker | 🟠 High Risk | 🟡 Improvement | Mã phát hiện |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **`WP-S1-01`** | `crates/mesh-store/src/**`, `crates/mesh-server/src/**`, `deploy/systemd/mesh-server.service`, `deploy/reverse-proxy/**`, `scripts/install-server.sh` | **5** *(gồm 1 phối hợp chéo `BLK-S1-05`)* | **5** | **0** | `BLK-S1-01`, `BLK-S1-02`, `BLK-S1-03`, `BLK-S1-04`, `BLK-S1-05` *(phần Server)*, `HR-S1-01`..`HR-S1-05` |
| **`WP-S1-02`** | `crates/mesh-datapath/src/**` | **0** | **3** | **0** | `HR-S1-06`, `HR-S1-07`, `HR-S1-08` |
| **`WP-S1-03`** | `crates/mesh-sys/src/{*_linux.rs,*_macos.rs,fs_unix.rs}`, `crates/mesh-net/src/{*_linux.rs,*_macos.rs}`, `deploy/launchd/internal.mesh.meshd.plist`, `deploy/systemd/meshd.service`, `scripts/install-macos.sh` | **3** *(gồm 1 phối hợp chéo `BLK-S1-05`)* | **2** | **1** | `BLK-S1-05` *(phần Unix FS)*, `BLK-S1-06`, `BLK-S1-07`, `HR-S1-09`, `HR-S1-10`, `IMP-S1-01` |
| **`WP-S1-04`** | `crates/mesh-sys/src/*_windows.rs`, `crates/mesh-net/src/*_windows.rs`, `scripts/install-windows.ps1` | **3** | **1** | **1** | `BLK-S1-08`, `BLK-S1-09`, `BLK-S1-10`, `HR-S1-11`, `IMP-S1-02` |

---

## 2. Các Bất Biến Kiến Trúc & Bảo Mật Đã Xác Minh Đạt Chuẩn

1. **`WP-S1-01` (`mesh-store` & `mesh-server`)**:
   - **Chính sách lỗi phần cứng `EIO` kép Gate 2(a)**: `Store::try_compact_emergency_revocations` (`crates/mesh-store/src/store.rs:640-715`) đọc `revoked.uncompacted_entries()` bao gồm **cả hai tầng** `PersistenceTier::EmergencySlot` lẫn `PersistenceTier::RamOnly`, ghi bền toàn bộ vào `control.redb` rồi mới gọi `clear_after_compaction` và xóa cờ `disk_degraded`. Không có đường rẽ nào bỏ sót mục `RamOnly` khi tiến trình còn sống và đĩa phục hồi.
   - **Chống Replay & Channel Binding**: `PendingChallengeStore::consume_for_verification` (`crates/mesh-server/src/challenge_store.rs:146-188`) xóa nguyên tử `nonce` khỏi bảng băm **trước** khi giải mã `SalsaBox`; kiểm chứng `tls_exporter_binding` tách bạch đúng chế độ `Standalone` (bắt buộc 32 bytes RFC 5705 khớp phiên TLS 1.3) và `ReverseProxy` (`None` chỉ khi kết nối TCP đến từ `trusted_proxies`).
   - **Blind Relay & Bảo mật biên**: `RelayHub` (`crates/mesh-server/src/relay_hub.rs:28, 224-279`) dùng `mpsc::channel(256)` + `try_send()` thuần túy (`0` `.send().await`, drop-tail khi đầy chống Head-of-Line blocking); `/healthz`, `/readyz` (`503` khi `disk_degraded` hoặc STUN lỗi) và `/metrics` không rò rỉ khóa bí mật; `ErrorKind::Unauthenticated` trả đồng nhất `"authentication failed"`; Admin API không mở listener TCP trên bất kỳ hệ điều hành nào.
2. **`WP-S1-02` (`mesh-datapath`)**:
   - **Cryptokey Routing & Lọc mảnh IPv4**: `CryptokeyValidator` (`crates/mesh-datapath/src/cryptokey.rs:124-205`) cưỡng chế `/32` `src_ip == expected_peer_ip` sau `tunn.decapsulate` và chặn gói phân mảnh IPv4 non-initial (`frag_offset > 0`) khi áp dụng bộ lọc cổng TCP/UDP.
   - **Bất biến chống hạ cấp đường truyền Disco (`SEC-06`)**: `DiscoEngine::handle_verified_inbound` (`crates/mesh-datapath/src/disco_engine.rs:424-476`) kiểm tra `verified_src_node_pubkey == peer.node_pubkey`, khóa single-use `tx_id` TTL 10 giây, **tuyệt đối không** nâng cấp `Direct` hay ghi `direct_addr` khi `DiscoPong` đến từ `IngressSource::Relay`, và tạm nghỉ keepalive khi rảnh quá `180..=300 s`.
   - **Giữ phiên khi cập nhật Netmap & Ghim TLS Relay**: `PeerMap::apply_diff` (`crates/mesh-datapath/src/peer_map.rs:256-326`) giữ nguyên phiên `defguard_boringtun::noise::Tunn` của các peer không đổi khóa; `TlsRelayConnector` (`crates/mesh-datapath/src/relay_client.rs:956-1075`) trích xuất `tls_exporter_binding` trên cùng kết nối TLS 1.3 dùng để nâng cấp WebSocket và dừng retry ngay khi nhận `NodeRevoked`/`NodeKeyExpired`.
3. **`WP-S1-03` (`mesh-sys` & `mesh-net` Linux/macOS)**:
   - **Kiểm chứng chuyên sâu `OwnedFd` → `UnixDatagram` trên Linux `/dev/net/tun`**: Đối chiếu mã nguồn `tokio-1.54.1` (`src/net/unix/datagram/socket.rs:412-415`) và `mio-1.2.4` (`src/net/uds/datagram.rs:99-103`, `src/io_source.rs:79-83`), đường dẫn `StdUnixDatagram::from(owned_fd)` → `mio::net::UnixDatagram::from_std` → `PollEvented::new` chỉ gọi `fcntl(F_GETFL)` và `epoll_ctl(EPOLL_CTL_ADD)` / `kevent` (mà `/dev/net/tun` hỗ trợ hợp lệ), **không** gọi `getsockopt` lúc mở (khác với `UnixDatagram::from_mio` có gọi `take_error()` → `getsockopt(SO_ERROR)`). Tuy nhiên việc ép kiểu character device fd thành `std::os::unix::net::UnixDatagram` vẫn phá vỡ bất biến kiểu của stdlib (ví dụ `Debug::fmt` gọi `getsockname` trả `ENOTSOCK`) — đã phân loại chính xác ở mức `🟠 High Risk` (`HR-S1-09`) để chuyển sang `AsyncFd<OwnedFd>`.
   - **An toàn `unsafe` FFI, `ResourceLedger` & chống Routing Loop**: Kích thước/căn chỉnh `TunIfReq`, `ctl_info`, `sockaddr_ctl`, `ucred`, `xucred`, `sockaddr_nl`, `rt_msghdr` chuẩn xác; đóng fd bằng `OwnedFd` RAII trên mọi nhánh lỗi; macOS ghi `utun[0-9]+` vào `ResourceLedger` trước `ifconfig` và chỉ dọn đúng giao diện đã tạo; giữ nguyên symlink `/etc/hosts -> /private/etc/hosts`; macOS `LOCAL_PEERCRED` kiểm tra `gid == 80` kèm fallback `getgrouplist` cho tài khoản `> 16` nhóm (`ipc_macos.rs:50`); Linux gắn `SO_MARK = 0x5d56` + `table 51820` + 2 `ip rule` ưu tiên `51820` & `51810`; `install-macos.sh` kiểm chứng SHA-256 + `codesign --force -s -` và không chứa `spctl --master-disable`.
4. **`WP-S1-04` (`mesh-sys` & `mesh-net` Windows)**:
   - **Socket & Named Pipe ACL**: `socket_windows.rs:15-59` phân biệt đúng byte-order `IP_UNICAST_IF` (`u32::to_be_bytes()` cho IPv4) và `IPV6_UNICAST_IF` (`u32::to_ne_bytes()` cho IPv6) kèm `IP_DONTFRAGMENT = 0`; `ipc_windows.rs` áp dụng SDDL chặt (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS` và kiểm tra token `BA`/`SY` qua `OpenThreadToken(..., SecurityIdentification)`; `netmon_windows.rs:101-123` đảm bảo `CancelMibChangeNotify2` chạy trước khi giải phóng context callback; `install-windows.ps1` dùng CRLF và kiểm tra quyền Administrator fail-closed.

---

## 3. Chi Tiết Phát Hiện Theo Từng Gói Công Việc

---

### PHẦN A — Gói `WP-S1-01` (`crates/mesh-store/src/**`, `crates/mesh-server/src/**`, `deploy/**`, `scripts/install-server.sh`)

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-01` [`WP-S1-01`] — Chiếm đoạt định danh Node (Identity Takeover) bằng Pre-Auth Key thường kết hợp `previous_node_pubkey` công khai
- **Vị trí**:
  - `crates/mesh-store/src/nodes_repo.rs:136-152, 656-691`
  - `crates/mesh-store/src/store.rs:496-522`
- **Nguyên nhân gốc rễ**:
  - Trong mạng Mesh, `node_pubkey` và `name` của mọi peer đang hoạt động đều được phát công khai trong `NetmapSnapshot`.
  - Khi đăng ký node mới với một pre-auth key chung không gắn tên (`bound_node_name == None`, ví dụ key tái sử dụng cho team dev), `register_node_with_preauth` (`nodes_repo.rs:145-152`) kiểm tra `if let Some(prev_pk) = req.previous_node_pubkey` và gọi thẳng `handle_key_rotation_registration` **mà không yêu cầu chữ ký chứng minh sở hữu `previous_node_pubkey` và cũng không bắt buộc pre-auth key phải được cấp đích danh `--for <node_name>`** (`bound_node_name == Some(existing_node.name)` theo `US-031 AC6` & `database-design.md:360-365`).
  - Ngoài ra, sau khi ghi đè `pubkey` của node nạn nhân sang khóa mới, `Store::register_node_with_preauth` (`store.rs:496-522`) không đưa `old_pubkey` vào `RevokedSet` RAM và `mesh-server` không ngắt phiên Control/Relay đang mở của khóa cũ.
- **Hệ quả thực tế (Impact)**: Bất kỳ ai cầm một pre-auth key chung chưa hết hạn đều có thể gửi `requested_name = "<ten-may-chu-prod>"` kèm `previous_node_pubkey = Some(<pubkey-cong-khai-cua-prod>)` để cướp nguyên `NodeId` và `OverlayIp` (`100.64.x.y`) của máy chủ Production mà không cần quyền Admin hay khóa bí mật cũ.
- **Hướng khắc phục trong phạm vi `WP-S1-01`**:
  1. Trong `crates/mesh-store/src/nodes_repo.rs` (`handle_key_rotation_registration`), bắt buộc kiểm tra `key_rec.bound_node_name.as_deref() == Some(existing.name.as_str())`; nếu key không gắn đích danh tên node đó thì từ chối ngay với `ErrorKind::Unauthenticated` (`"authentication failed"`).
  2. Trả thêm `replaced_pubkey: Option<PublicKey>` trong `RegistrationResult`; tại `Store::register_node_with_preauth` (`store.rs`), chèn `old_pubkey` vào `RevokedSet` RAM (đã lưu bền trong `TABLE_REVOKED_PUBKEYS` ở cùng giao dịch `redb`) và tại `control_handlers.rs` ngắt ngay phiên Control + Relay cũ của node vừa xoay khóa, kèm unit test chống chiếm đoạt bằng unbound key.

---

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-02` [`WP-S1-01`] — Đua tranh `tokio::select! { biased; }` làm rơi 100% thông báo `IdentityTerminated` / `RelayNoticeCode` khi thu hồi hoặc hết hạn khóa + thiếu gửi notice ở nhánh Gate 2(b)
- **Vị trí**:
  - `crates/mesh-server/src/control_handlers.rs:848-873, 943-978`
  - `crates/mesh-server/src/netmap_hub.rs:391-404`
  - `crates/mesh-server/src/relay_hub.rs:330-349`
  - `crates/mesh-server/src/admin_service.rs:534-538`
  - `crates/mesh-server/src/alert_worker.rs:239-242`
- **Nguyên nhân gốc rễ**:
  - `NetmapHub::terminate_node_stream` (`netmap_hub.rs:394-399`) và `RelayHub::disconnect_node` (`relay_hub.rs:334-345`) đều đẩy khung thông báo kết thúc (`ControlServerMessage::IdentityTerminated` hoặc khung `0x04` `RelayNoticeCode`) qua `tx.try_send(...)` rồi **ngay lập tức gọi `cancel.cancel()`** trên cùng luồng.
  - Ở phía vòng lặp đọc/ghi WebSocket (`pump_ws_duplex` tại `control_handlers.rs:849-853` và `pump_relay_ws` tại `control_handlers.rs:944-948`), `tokio::select! { biased; () = cancel.cancelled() => break, ... maybe_out = rx.recv() => ... }` luôn kiểm tra `cancel.cancelled()` **trước tiên** nên thoát vòng lặp ngay lập tức, hủy bỏ `rx` mà không bao giờ gửi khung `IdentityTerminated` / `NodeRevoked` / `NodeKeyExpired` xuống socket!
  - Đồng thời, ở nhánh lỗi phần cứng kép Gate 2(b) (`outcome.must_disconnect_all_peers_to_reauth`), cả `admin_service.rs:534-538` lẫn `alert_worker.rs:239-242` gọi thẳng `disconnect_all_streams_for_reauth()` và `disconnect_all_for_reauth()` mà quên gửi `IdentityTerminated` + `RelayNoticeCode` cho chính `outcome.node_id` vừa bị thu hồi/hết hạn.
- **Hệ quả thực tế (Impact)**: Phá vỡ trực tiếp `US-029 AC3`, `US-031 AC1` và `US-034 AC5`: daemon `meshd` và `RelayClient` của node bị thu hồi chỉ thấy đứt kết nối TCP/WS thông thường thay vì mã `node_revoked` / `node_key_expired`, dẫn tới tiếp tục vòng lặp reconnect vô ích thay vì dừng retry và xóa trạng thái phiên.
- **Hướng khắc phục trong phạm vi `WP-S1-01`**:
  1. Trong `pump_ws_duplex` và `pump_relay_ws` (`crates/mesh-server/src/control_handlers.rs`), khi nhánh `cancel.cancelled()` kích hoạt, rút cạn các thông điệp đang chờ sẵn bằng `while let Ok(msg) = rx.try_recv()` để ghi xuống sink WebSocket + gửi khung `Message::Close(None)` + `flush` dưới `tokio::time::timeout(Duration::from_millis(500), ...)` trước khi đóng kết nối.
  2. Trong `admin_service.rs:534-538` và `alert_worker.rs:239-242`, ở nhánh `must_disconnect_all_peers_to_reauth`, gọi `terminate_node_stream(outcome.node_id, ...)` và `relay_hub.disconnect_node(outcome.node_id, Some(...))` cho node đích trước khi ngắt toàn bộ các peer còn lại để ép xác thực lại.
  3. Bổ sung integration test xác nhận client nhận đủ khung `IdentityTerminated` và `0x04` `RelayNoticeCode` trước khi EOF.

---

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-03` [`WP-S1-01`] — `AcmeManager` chỉ là stub giả lập: tự sinh chứng chỉ self-signed và bỏ qua hoàn toàn quy trình cấp chứng chỉ ACME (`US-047`)
- **Vị trí**:
  - `crates/mesh-server/src/acme.rs:164-180, 296-344`
  - `crates/mesh-server/src/admin_service.rs:584-588`
- **Nguyên nhân gốc rễ**:
  - `US-047` (`TLS-ALPN-01` & `DNS-01` bằng `instant-acme` `0.7`) là hạng mục `Must` của Sprint 1 thuộc `WP-S1-01` (`sprint-backlog.md:93, 112`).
  - Thực tế trong `crates/mesh-server/src/acme.rs`: `AcmeManager::initialize` (`164-180`) tạo chứng chỉ **self-signed** làm chứng chỉ chạy chính; còn `attempt_acme_renewal` (`296-344`) chỉ gửi một lệnh `reqwest::Client::get(&acme_cfg.directory_url)`, khởi tạo biến `let _ = ChallengeType::TlsAlpn01;` rồi vứt bỏ, tạo CSR xong để không, và luôn trả về `Ok(false)` ("no live issuance occurred")!
  - Hàm `ListenerSet::set_acme_alpn_challenge` không bao giờ được nối vào ACME challenge; hook `DNS-01` không bao giờ được thực thi; chứng chỉ ACME và khóa tài khoản ACME không bao giờ được lưu vào `store`. Nghiêm trọng hơn, `admin_service.rs:584-588` khi thấy `tls_mode == Acme` lại hướng dẫn client join không ghim SPKI (`system_ca`) trong khi server thực chất đang phát chứng chỉ self-signed!
- **Hệ quả thực tế (Impact)**: Mọi triển khai cấu hình `tls_mode = "acme"` sẽ thất bại xác thực TLS 100% ở phía mọi client (`UntrustedCert`).
- **Hướng khắc phục trong phạm vi `WP-S1-01`**:
  1. Hiện thực hóa đầy đủ luồng `instant-acme` `0.7` trong `crates/mesh-server/src/acme.rs`: khởi tạo/khôi phục `Account` (lưu khóa tài khoản qua `identity_repo`), tạo `NewOrder` cho `domain`, duyệt `authorizations()`, cài đặt chứng chỉ tạm `acme-tls/1` qua `ListenerSet::set_acme_alpn_challenge` (cho `TLS-ALPN-01`) hoặc chạy hook provider theo cấu hình (cho `DNS-01`, dùng đường dẫn tuyệt đối không qua shell), gọi `set_ready()`, chờ `OrderStatus::Ready`, `finalize` bằng CSR DER, tải chuỗi chứng chỉ PEM/DER, lưu bền vào `store` và gọi `ListenerSet::reload_certified_key` + xóa `set_acme_alpn_challenge(None)`.
  2. Khi server ở chế độ `Acme` nhưng chưa có chứng chỉ CA hợp lệ (đang bootstrap), `readyz` báo chưa sẵn sàng chứng chỉ hoặc `admin_service.rs` không được phát hướng dẫn bỏ qua `--server-pin`.

---

#### ✅ `[CLOSED IN R3]` 🔴 `BLK-S1-04` [`WP-S1-01`] — Chuỗi 5 lỗi nghiêm trọng trong `create_backup` / `restore_backup` trực tuyến (Đảo ngược cờ xác minh pin, làm hỏng vĩnh viễn handle DB khi lỗi, xóa sớm file khẩn cấp & tụt lùi `netmap_version`)
- **Vị trí**:
  - `crates/mesh-server/src/admin_service.rs:721-727`
  - `crates/mesh-store/src/store.rs:732-742, 759-793`
  - `crates/mesh-store/src/backup.rs:155-197, 258-281`
- **Nguyên nhân gốc rễ**:
  1. **Đảo ngược ngữ nghĩa cờ bảo mật**: Tại `admin_service.rs:726`, tham số `allow_pin_change` được gán bằng `!parsed.verify_sha256` (`BackupRestoreRequest` mặc định `verify_sha256 = true`). Hai khái niệm hoàn toàn khác nhau bị trộn lẫn, và nếu caller truyền `verify_sha256: false` thì vô tình bật cờ cho phép đổi SPKI Pin trái phép (`--force-repin`).
  2. **Làm chết vĩnh viễn `Store` trên RAM khi bản sao lưu lỗi**: `Store::restore_backup` (`store.rs:768-792`) thực hiện `*db_guard = None` (đóng DB đang chạy) **trước khi** kiểm tra SHA-256, schema version hay SPKI Pin của file backup! Nếu file backup sai đường dẫn, hỏng checksum hoặc lệch SPKI Pin, hàm trả lỗi khi `db_guard` đã là `None`, biến toàn bộ `mesh-server` đang chạy thành xác sống lỗi DB 100% cho tới khi khởi động lại tiến trình.
  3. **Xóa mất `emergency-revocations.bin` trước khi rename và không giữ bản `.before-restore`**: `backup.rs:177-189` xóa `emergency-revocations.bin` ngay trước khi thay thế DB (nếu bước rename thất bại sẽ mất sạch dữ liệu thu hồi khẩn cấp đang có) và không đổi tên DB cũ sang `control.redb.before-restore` như quy định tại `database-design.md:647`.
  4. **Tụt lùi `netmap_version` sau khôi phục**: `bump_restored_db_watermark` (`backup.rs:265-277`) chỉ tính `current_in_backup + 1_000_000`, bỏ qua `local_db_watermark`, `emergency_slot_version` và `now_unix_ms` (`database-design.md:468, 645`). Nếu bản sao lưu cũ hơn `> 1_000_000` phiên bản so với mốc hiện tại của các peer đang online, các peer sẽ từ chối toàn bộ bản đồ mạng mới vì coi là gói cũ (`stale netmap_version`)!
  5. **`create_backup` bỏ sót mục thu hồi chưa compact**: `Store::create_backup` (`store.rs:732-742`) chỉ sao chép bảng trong `redb` mà không hợp nhất các mục thu hồi đang nằm trong `RevokedSet` RAM / `emergency-revocations.bin` vào ảnh chụp (`database-design.md:631`, `US-045 AC2`).
- **Hệ quả thực tế (Impact)**: Nguy cơ mất dữ liệu thu hồi node bị xâm nhập, tê liệt `mesh-server` ngay lập tức khi gõ nhầm đường dẫn file restore, và làm đứt đồng bộ bản đồ mạng của toàn bộ đội máy trạm sau DR.
- **Hướng khắc phục trong phạm vi `WP-S1-01`**:
  1. Bổ sung trường tường minh `force_repin: bool` (mặc định `false`) hoặc giữ `allow_pin_change = false` trừ khi yêu cầu khôi phục chỉ định rõ `force_repin`, tách biệt hoàn toàn với `verify_sha256`.
  2. Trong `Store::restore_backup` & `backup::restore_snapshot`: giải nén/kiểm tra SHA-256, `schema_version`, `expected_active_spki_pin`, và nâng `watermark = max(backup_wm, current_runtime_wm, emergency_slot_ver, now_ms) + 1_000_000` trên file tạm `control.redb.restore.tmp` **trước khi** đóng `*db_guard = None`; sao lưu `control.redb` hiện hữu sang `control.redb.before-restore`, hoán đổi nguyên tử, mở lại `Database::open` (nếu mở lỗi thì khôi phục lại từ `control.redb.before-restore`), và chỉ xóa `emergency-revocations.bin` sau khi DB mới đã mở thành công.
  3. Trong `Store::create_backup`, truyền danh sách `revoked.uncompacted_entries()` vào `backup::write_hot_snapshot` để ghi bổ sung vào bản chụp `redb` đích (và nâng watermark tương ứng trong ảnh chụp).

---

#### ✅ `[CLOSED IN R3]` 🔴 `BLK-S1-05` [`WP-S1-01` + `WP-S1-03` Phối hợp chéo] — `mesh-server` dưới `systemd` (user không đặc quyền `mesh`) luôn tự ngắt khi khởi động do lệch nhóm sở hữu `/run/mesh-server`
- **Vị trí**:
  - **Phần `WP-S1-01`**: `deploy/systemd/mesh-server.service:9-16`, `scripts/install-server.sh:131-140`, `crates/mesh-server/src/admin_service.rs:151-162`
  - **Phần `WP-S1-03`**: `crates/mesh-sys/src/fs_unix.rs:94-117, 135-158`
- **Nguyên nhân gốc rễ**:
  - `deploy/systemd/mesh-server.service:9-15` khai báo `User=mesh`, `Group=mesh`, `RuntimeDirectory=mesh-server`, `RuntimeDirectoryMode=0750`, nên `systemd` tạo `/run/mesh-server` với chủ sở hữu **`mesh:mesh`**. Trong `scripts/install-server.sh:131-140`, tài khoản `mesh` cũng không được thêm vào nhóm `mesh-admin`.
  - Khi `mesh-server` khởi động, `start_admin_ipc_listener` (`admin_service.rs:154-162`) tìm thấy GID của `mesh-admin` trong `/etc/group` và truyền `server_runtime_dir_policy(service_uid, Some(mesh_admin_gid))` xuống `prepare_secure_runtime_dir`.
  - Trong `crates/mesh-sys/src/fs_unix.rs`, cả `apply_root_group_if_privileged` (`138`) lẫn `set_path_group_if_root` (`96`) đều thoát sớm `if current_euid != 0 { return Ok(()); }`, không đổi nhóm của `/run/mesh-server` hay `admin.sock`. Ngay bước kế tiếp, `verify_leaf_metadata` (`fs_unix.rs:218-230`) kiểm tra `meta.gid() != expected_gid` (`mesh != mesh-admin`) và ném lỗi cứng `SysError::SecurityViolation`!
- **Hệ quả thực tế (Impact)**: Trên mọi máy chủ Linux Production cài đặt bằng `install-server.sh` + `mesh-server.service`, dịch vụ `mesh-server` crash-loop 100% ngay giây đầu tiên khởi động.
- **Hướng khắc phục phối hợp (không đụng độ tệp)**:
  1. **`WP-S1-01`**: Trong `deploy/systemd/mesh-server.service`, đặt `Group=mesh-admin` (hoặc `SupplementaryGroups=mesh-admin` kết hợp `Group=mesh-admin` để `RuntimeDirectory=mesh-server` sinh ra đúng `0750 mesh:mesh-admin`, đồng thời giữ `StateDirectoryMode=0700` bảo vệ `control.redb` chỉ cho `User=mesh`). Trong `scripts/install-server.sh:139`, thêm `mesh` vào nhóm phụ `mesh-admin` (`usermod -a -G "${ADMIN_GROUP}" "${SERVICE_USER}"`) và đảm bảo `/var/lib/mesh-server` có mode `0700`.
  2. **`WP-S1-03`**: Trong `crates/mesh-sys/src/fs_unix.rs` (`set_path_group_if_root` dòng `94-117` và `apply_root_group_if_privileged` dòng `135-158`), kiểm tra `open_leaf_nofollow_metadata` trước: nếu `meta.gid() == gid` thì trả `Ok(())` ngay; nếu `meta.gid() != gid` thì gọi `libc::lchown(c_path, u32::MAX, gid)` **kể cả khi `geteuid() != 0`** (chuẩn POSIX/Linux cho phép chủ sở hữu file không phải root đổi nhóm sang bất kỳ nhóm phụ nào mà tiến trình đang thuộc về).

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-01` [`WP-S1-01`] — Một lỗi đọc UDP tạm thời duy nhất làm chết vĩnh viễn STUN Server nhúng và kéo `/readyz` xuống `503`
- **Vị trí**: `crates/mesh-server/src/stun_service.rs:189-198`
- **Nguyên nhân gốc rễ**: Trong vòng lặp nhận gói của `spawn_stun_udp_listener`, mọi nhánh `Err(err)` từ `socket.recv_from(&mut rx_buf).await` đều gọi `state.set_healthy(false)` rồi `break` thoát hẳn task STUN. Trên Linux/Windows, UDP socket có thể trả lỗi tạm thời (`Interrupted`, `WouldBlock`, `ConnectionReset` ICMP port unreachable, hết bộ đệm tức thời).
- **Hệ quả thực tế (Impact)**: Chỉ một gói ICMP lỗi hoặc xung chấn mạng thoáng qua sẽ tắt vĩnh viễn dịch vụ STUN cho tới khi khởi động lại `mesh-server`, đồng thời làm `/readyz` báo `503 Service Unavailable`.
- **Hướng khắc phục trong phạm vi `WP-S1-01`**: Ghi log `warn!` giới hạn tần suất, ngủ ngắn (`tokio::time::sleep(Duration::from_millis(20))`) khi gặp lỗi `recv_from` và tiếp tục vòng lặp cho tới khi `shutdown.cancelled()`, chỉ đánh dấu `set_healthy(false)` nếu lỗi kéo dài liên tiếp vượt ngưỡng hoặc lúc khởi tạo bind thất bại.

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-02` [`WP-S1-01`] — `ListenerSet::check_migration_cutover` cắt cổng cũ chỉ sau 25 giây khi không có node nào đang online hoặc còn node laptop đang ngủ
- **Vị trí**: `crates/mesh-server/src/listener_set.rs:293-314`
- **Nguyên nhân gốc rễ**: Điều kiện cắt cổng cũ `let all_acked = total_online == 0 || m.acked_nodes.len() >= total_online;` (`296`) chỉ đếm các luồng WebSocket đang kết nối tức thời (`total_online`), thậm chí khi `total_online == 0` thì `all_acked` bằng `true` ngay lập tức!
- **Hệ quả thực tế (Impact)**: Nếu quản trị viên đổi cổng control/relay lúc ban đêm (khi 0 node online hoặc có các máy trạm đang gập màn hình offline), server sẽ đóng sập cổng cũ chỉ sau 25 giây (`ENDPOINT_MIGRATION_DRAIN_GRACE_MS`) thay vì giữ song song tới `cutover_window_secs` (`US-074 AC2`), khiến mọi máy đang offline mất hoàn toàn địa chỉ kết nối lại khi thức dậy!
- **Hướng khắc phục trong phạm vi `WP-S1-01`**: Đối chiếu `m.acked_nodes.len()` với **tổng số node `Active` đã đăng ký trong `mesh-store`** (`total_registered_active > 0 && m.acked_nodes.len() >= total_registered_active`), tuyệt đối không cắt sớm khi `total_registered_active == 0` hoặc khi còn bất kỳ node `Active` nào chưa xác nhận trước `deadline_ms`.

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-03` [`WP-S1-01`] — Sai lệch hợp đồng Admin IPC (`api-design.md` §4): thiếu 2 route chuẩn, bỏ qua `max_uses`, gán nhầm trường trong `PreAuthKeySummary`, ẩn node bị thu hồi và lệch cú pháp lệnh join/UFW
- **Vị trí**:
  - `crates/mesh-server/src/admin_service.rs:85-120, 292-324, 344-356, 843-875`
  - `crates/mesh-store/src/keys_repo.rs:23-70, 211-214`
  - `scripts/install-server.sh:174-184, 236`
- **Nguyên nhân gốc rễ**:
  1. Router Admin (`admin_service.rs:85-120`) thiếu 2 endpoint chuẩn trong `api-design.md` §4.1: `GET /v1/admin/nodes/{node_id}` và `POST /v1/admin/preauth-keys/{key_id}/revoke` (hiện mới chỉ có `DELETE /v1/admin/preauth-keys/{key_id}`).
  2. `create_preauth_key` (`admin_service.rs:297`) gán `let _ = parsed.max_uses;`, và `PreAuthKeyRecord` (`keys_repo.rs:23-39`) không lưu `max_uses` / `used_count`, khiến khóa `reusable = true` với `max_uses = 5` cho phép dùng vô hạn lần.
  3. `list_preauth_keys` (`admin_service.rs:348-355`) gán nhầm `used_by_node_id: k.bound_node_name` và `target_node_id: None` (tráo đổi trường cấu hình ràng buộc với trường kết quả sử dụng).
  4. `to_node_summary` (`admin_service.rs:845`) gọi `let overlay_ip = rec.overlay_ip?;`, âm thầm loại bỏ toàn bộ các node ở trạng thái `Revoked` (do `revoke_node` đã xóa `overlay_ip = None` để giải phóng IP) khỏi danh sách `mesh admin node list` (`US-028`)!
  5. `admin_service.rs:607` và `install-server.sh:236` in hướng dẫn `mesh up --auth-key <SECRET>` (truyền secret qua argv — bị cấm bởi `SEC-01` và lệch cờ CLI chuẩn `mesh up --server <IP:port> --server-pin <pin> --authkey-file <path>`), đồng thời `install-server.sh:174-184` tự động gọi `ufw --force enable` khi cài đặt mà không có cờ opt-in xác nhận (nguy cơ khóa SSH cổng tùy chỉnh của VPS).
- **Hệ quả thực tế (Impact)**: Ở Wave 1.2, CLI `mesh admin` (`WP-S1-05`) gọi đúng `api-design.md` sẽ gặp `404 Not Found`, không hiển thị được lịch sử các node đã thu hồi, không giới hạn được số lần dùng pre-auth key, và kịch bản cài đặt có thể tự khóa SSH quản trị viên.
- **Hướng khắc phục trong phạm vi `WP-S1-01`**:
  1. Bổ sung `GET /v1/admin/nodes/{id}` và alias `POST /v1/admin/preauth-keys/{id}/revoke` trong `admin_service.rs`.
  2. Thêm `#[serde(default)] pub max_uses: Option<u32>` và `#[serde(default)] pub used_count: u32` vào `PreAuthKeyRecord` (`keys_repo.rs`, tương thích ngược serde), kiểm tra và tăng bộ đếm nguyên tử trong `nodes_repo.rs` khi đăng ký node.
  3. Giữ `last_overlay_ip` hoặc hiển thị giá trị mặc định hợp lệ khi `rec.overlay_ip.is_none()` để `list_nodes` trả đầy đủ cả node `Revoked`/`Expired`; sửa ánh xạ `PreAuthKeySummary`.
  4. Cập nhật chuỗi hướng dẫn sang `--authkey-file` và chỉ cấu hình/bật UFW trong `install-server.sh` khi người dùng truyền cờ tường minh `--enable-ufw` (đồng thời giữ mở cổng SSH hiện tại nếu phát hiện từ `SSHD` / biến môi trường).

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-04` [`WP-S1-01`] — File khẩn cấp `emergency-revocations.bin` làm mất phân biệt `Expired` vs `Revoked` & `min_netmap_version`; thu hồi node quên dọn `TABLE_IDX_NODES_NAME`
- **Vị trí**:
  - `crates/mesh-store/src/revoked_ram.rs:580-595, 680`
  - `crates/mesh-store/src/nodes_repo.rs:236-290`
- **Nguyên nhân gốc rễ**:
  1. Định dạng nhị phân của `emergency-revocations.bin` (`revoked_ram.rs:580-595`) không lưu `reason` (`Revoked` hay `Expired`) và `min_netmap_version`. Khi khởi động lại từ file khẩn cấp (`load_emergency_file`, dòng `680`), mọi mục đều bị ép cứng thành `EmergencyNodeReason::Revoked` và `min_netmap_version = slot_version` — vi phạm `database-design.md:391, 457` (node hết hạn bị biến vĩnh viễn thành node thu hồi không thể gia hạn lại).
  2. `revoke_node` (`nodes_repo.rs:236-290`) giải phóng `TABLE_IDX_NODES_IP` nhưng không xóa `node.name` khỏi `TABLE_IDX_NODES_NAME`, trái với `database-design.md:88` ("chỉ chứa các node chưa bị `revoked`") và làm kẹt tên máy khi cấp lại node mới cùng tên.
- **Hệ quả thực tế (Impact)**: Sau sự cố đĩa + khởi động lại, các máy chỉ hết hạn khóa định kỳ bị khóa chết như bị thu hồi bảo mật, và tên máy của các node đã thu hồi không thể tái sử dụng sạch sẽ.
- **Hướng khắc phục trong phạm vi `WP-S1-01`**:
  1. Lưu đầy đủ `reason: u8` (`1 = Revoked`, `2 = Expired`) và `min_netmap_version: u64` cho từng bản ghi trong slot khẩn cấp (`revoked_ram.rs`).
  2. Trong `nodes_repo.rs::revoke_node`, xóa `existing.name.as_str()` khỏi `TABLE_IDX_NODES_NAME` trong cùng giao dịch ghi `redb`.

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-05` [`WP-S1-01`] — Control Plane thiếu lọc `CandidateEndpoint` phía server, thiếu xác minh `outer_sender_pubkey` trên `CallMeMaybe`, giới hạn khung WS lệch `64 KiB` và thiếu 2 cảnh báo vận hành
- **Vị trí**:
  - `crates/mesh-server/src/control_handlers.rs:50, 398-415, 625-626, 672-737, 1145-1158`
  - `crates/mesh-server/src/alert_worker.rs:143-149`
- **Nguyên nhân gốc rễ**:
  1. `MAX_CONTROL_WS_FRAME_BYTES` (`control_handlers.rs:50`) đặt `131_072` (`128 KiB`) thay vì `65_536` (`64 KiB`) theo `api-design.md:17`.
  2. Khi nhận `RegisterRequest` (`398-415`) và `EndpointUpdate` (`625-626`), server lưu nguyên `endpoints` do client gửi lên (không giới hạn số lượng phần tử và không lọc qua `mesh_net::endpoint_filter::is_valid_candidate_endpoint`), cho phép một peer độc hại phát tán IP loopback/link-local/multicast hoặc IP:port STUN của chính VPS vào `Netmap` của mọi peer khác.
  3. Trong `handle_call_me_maybe` (`672-737`), server không kiểm tra `dst_node.status == NodeStatus::Active` và không đối chiếu `mesh_crypto::disco_box::peek_outer_sender_pubkey(&frame_bytes) == Some(sender_node.disco_pubkey)` trước khi chuyển tiếp gói mồi Disco.
  4. Vòng lặp nhận khung Control WS (`handle_inbound_ws_text`) chưa kiểm tra lại hạn khóa (`expires_at_ms <= now_ms`) hoặc `store.is_pubkey_revoked(&node_pubkey)` trên từng thông điệp đến, và `alert_worker.rs:143-149` chưa đánh giá hai cảnh báo `AlertCode::RelaySaturation` và `AlertCode::DiskUsageHigh`.
- **Hệ quả thực tế (Impact)**: Mở bề mặt khuếch đại lưu lượng Disco giả mạo qua Control Plane, cho phép bơm danh sách endpoint rác làm phình `NetmapUpdate`, và thiếu cảnh báo sớm khi đĩa VPS sắp đầy hoặc Relay nghẽn.
- **Hướng khắc phục trong phạm vi `WP-S1-01`**:
  1. Hạ `MAX_CONTROL_WS_FRAME_BYTES` về `65_536`; lọc mọi `endpoints` đầu vào qua `is_valid_candidate_endpoint` và cắt tối đa `16` địa chỉ mỗi node.
  2. Trong `handle_call_me_maybe`, xác minh `dst_node` đang `Active` và `peek_outer_sender_pubkey(&frame_bytes)` khớp `sender_node.disco_pubkey`.
  3. Kiểm tra `is_pubkey_revoked` + `expires_at_ms` ngay đầu `handle_inbound_ws_text`; bổ sung kiểm tra tỷ lệ drop của `RelayHub` (`RelaySaturation`) và dung lượng trống thư mục dữ liệu (`DiskUsageHigh`) trong `alert_worker.rs`.

---

### PHẦN B — Gói `WP-S1-02` (`crates/mesh-datapath/src/**`)

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-06` [`WP-S1-02`] — Thời gian phát hiện đứt đường P2P Direct mất `53–78 giây` thay vì `P95 <= 10 giây` (`US-022` / `REL-02`)
- **Vị trí**: `crates/mesh-datapath/src/disco_engine.rs:492-516, 741-779`
- **Nguyên nhân gốc rễ**: Trong `DiscoEngine::tick_direct_keepalive` (`741-779`), ngay cả khi một probe đã quá hạn (`missed_direct_pongs` tăng lên `1` hoặc `2`) hoặc đang có lưu lượng gửi đi (`last_tx_at_ms`) nhưng không nhận được gói nào quay về (`last_rx_at_ms`), bộ lập lịch vẫn đợi trọn chu kỳ `keepalive_interval_ms = 25_000 ms` mới gửi gói `DiscoPing` kế tiếp! Tổng thời gian để tích lũy đủ `MAX_MISSED_DIRECT_PONGS = 3` lên tới `2 * 25 s + 3 s = 53 s` (hoặc `78 s` nếu đứt ngay sau một gói vừa nhận).
- **Hệ quả thực tế (Impact)**: Khi người dùng chuyển mạng Wi-Fi / 4G hoặc NAT binding bị rơi âm thầm, kết nối SSH/RDP qua VPN bị treo cứng hơn 1 phút thay vì tự động rơi về Blind Relay dưới 10 giây theo cam kết SLA `REL-02`.
- **Hướng khắc phục trong phạm vi `WP-S1-02`**:
  - Trong `crates/mesh-datapath/src/disco_engine.rs`: khi `missed_direct_pongs >= 1` **hoặc** khi peer đang ở chế độ `Direct` có lưu lượng gửi đi mà không thấy gói đến quá `2_000 ms` (`last_tx_at_ms > last_rx_at_ms.saturating_add(2_000)`), chuyển sang chế độ **Fast Suspect Probe** với chu kỳ gửi `1_000 ms` và hạn chờ Pong `1_500..=2_000 ms` để đủ 3 lần trượt và hạ cấp về `Relay` trong khoảng `4.5–8 giây` (`<= 10 s`). Thêm unit test kiểm chứng mốc thời gian chuyển mạch `<= 10_000 ms`.

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-07` [`WP-S1-02`] — `RelayClient` treo gói tin ở tải burst (`> 64` gói), reset nhầm `ExponentialBackoff` về `0` khi lỗi TLS, và không đọc được HTTP `Transfer-Encoding: chunked` sau Reverse Proxy
- **Vị trí**: `crates/mesh-datapath/src/relay_client.rs:420-423, 582-648, 1008-1122, 1253-1265`
- **Nguyên nhân gốc rễ**:
  1. **Treo hàng đợi gửi khi burst**: `tokio::sync::Notify` chỉ lưu tối đa 1 permit đánh thức. Khi datapath đẩy nhanh `200` gói vào hàng đợi (`mpsc::channel(256)`), `flush_outbound_batch` (`582-648`) chỉ rút tối đa `32` gói điều khiển + `32` gói dữ liệu rồi quay lại `wake.notified().await`! Các gói thứ `65..=200` bị bỏ quên trong bộ đệm suốt tối đa `25 giây` cho tới tận nhịp `ws_ping_interval` tiếp theo.
  2. **Reset backoff lỗi TLS**: Tại dòng `420-423`, mỗi lần gặp lỗi `tls_capped`, vòng lặp lại gọi `ExponentialBackoff::new(Duration::from_secs(1), TLS_PIN_CAP_BACKOFF).next_delay(&mut rng)` trên một struct mới tinh (`attempt == 0`), khiến client spam kết nối lại sau mỗi `0..1 giây` vĩnh viễn thay vì tăng dần lên trần `5 phút` (`US-034`), đồng thời `classify_connector_error` chưa xếp `ErrorKind::UntrustedCert` vào nhóm `tls_capped`.
  3. **Hỏng bắt tay `/v1/auth/challenge` qua Reverse Proxy (`US-024`)**: `read_bounded_http_response` (`1095-1121`) và `parse_content_length` (`1253-1265`) coi mọi phản hồi HTTP/1.1 không có header `Content-Length` là `content_len = 0`! Khi `mesh-server` đặt sau Nginx/Caddy/Traefik dùng `Transfer-Encoding: chunked`, phần thân JSON bị cắt thành rỗng (`""`) và bộ tách chuỗi thủ công `extract_json_string_field` thất bại 100%.
- **Hệ quả thực tế (Impact)**: Nghẽn độ trễ hàng chục giây khi truyền tải burst qua Relay, bão kết nối TLS khi lệch đồng hồ/captive portal, và gãy hoàn toàn kết nối Relay ở mô hình triển khai sau Reverse Proxy.
- **Hướng khắc phục trong phạm vi `WP-S1-02`**:
  1. Trong `flush_outbound_batch`, lặp rút theo lô `32` gói (có nhường lịch hợp tác hoặc gọi `wake.notify_one()` nếu sau một lô vẫn còn phần tử trong `ctrl_rx`/`data_rx`) cho tới khi cả hai kênh rỗng.
  2. Khởi tạo `let mut tls_backoff = ExponentialBackoff::new(...)` **bên ngoài** vòng lặp `run` (cùng cấp với `normal_backoff`), reset cả hai khi kết nối thành công, và đưa `ErrorKind::UntrustedCert` vào nhóm `tls_capped`.
  3. Hỗ trợ giải mã giới hạn kích thước cho `Transfer-Encoding: chunked` trong `read_bounded_http_response` và giải mã JSON phản hồi `/v1/auth/challenge` bằng `serde_json::from_slice` thay cho dò chuỗi thủ công.

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-08` [`WP-S1-02`] — `DatapathEngine::step_disco_tick` hủy sớm các gói thăm dò STUN chỉ sau `<= 250 ms` và làm rơi danh sách Reflexive Endpoints
- **Vị trí**:
  - `crates/mesh-datapath/src/engine.rs:386-392, 461-470, 735-784`
  - `crates/mesh-datapath/src/stun_client.rs:277-297`
- **Nguyên nhân gốc rễ**:
  - `step_disco_tick` chạy định kỳ mỗi `250 ms` (`engine.rs:386`) và kiểm tra `if self.stun.has_pending_requests() { let _report = self.stun.finish_probe_round(now_ms); }` (`737-739`).
  - Trong `StunClient::finish_probe_round` (`stun_client.rs:277-297`), hàm này lập tức `self.pending.clear()` bất kể hạn chờ `expires_at_ms` (`1_500..3_000 ms`) đã tới hay chưa! Hệ quả là mọi yêu cầu STUN có RTT `> 10..250 ms` (hoặc rơi đúng sát nhịp tick) bị xóa sạch khỏi bảng `pending`, câu trả lời STUN về sau bị vứt bỏ và `StunReport` kết luận sai `udp_blocked = true`.
  - Ngoài ra kết quả `StunReport` bị gán vào `let _report` rồi bỏ đi, không lưu vào trạng thái engine để `meshd` đọc `reflexive_addrs` / `udp_blocked` báo lên Control Plane và `mesh netcheck`.
- **Hệ quả thực tế (Impact)**: Làm hỏng phát hiện địa chỉ công khai NAT (`US-019`) trên các đường truyền quốc tế / di động và khiến `mesh netcheck` báo sai mạng chặn UDP.
- **Hướng khắc phục trong phạm vi `WP-S1-02`**:
  1. Bổ sung phương thức `pub fn is_probe_round_ready(&self, now_ms: u64) -> bool` trong `StunClient` (chỉ trả `true` khi mọi máy chủ STUN đã phản hồi đủ **hoặc** mọi yêu cầu còn chờ đều đã quá hạn `now_ms >= req.expires_at_ms`).
  2. Lưu `last_stun_report: Option<StunReport>` trong `DatapathEngine` (xuất qua `DatapathStatusSnapshot` và/hoặc phương thức getter không tiền tố `get_`) để hợp nhất `reflexive_addrs` vào tập ứng viên endpoint.

---

### PHẦN C — Gói `WP-S1-03` (`crates/mesh-sys/src/{*_linux,*_macos,fs_unix}.rs`, `crates/mesh-net/src/{*_linux,*_macos}.rs`, `deploy/**`, `scripts/install-macos.sh`)

*(Lưu ý: Worker `WP-S1-03` đồng thời thực hiện phần sửa `crates/mesh-sys/src/fs_unix.rs:94-158` của **`BLK-S1-05`** đã mô tả chi tiết ở Phần A.)*

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-06` [`WP-S1-03`] — `firewall_linux.rs` gọi `iptables -C INPUT -j MESH_VPN_INPUT` mà không bao giờ chèn jump rule, gây lỗi `exit code 1` 100% trên mọi máy chủ dùng `iptables` + thiếu cổng động và thiếu xóa rule `ufw` khi rollback
- **Vị trí**: `crates/mesh-net/src/firewall_linux.rs:109-135, 227-244, 344-399`
- **Nguyên nhân gốc rễ**:
  1. Trong `build_iptables_commands` (`344-399`), sau khi tạo chain mới `iptables -N MESH_VPN_INPUT` và thêm các rule `-A MESH_VPN_INPUT ...`, lệnh cuối cùng (`389-398`) lại là `iptables -C INPUT -j MESH_VPN_INPUT` (`-C` là **check**, không phải chèn!). Trên mọi máy mới chạy lần đầu, `INPUT` chưa hề có jump sang `MESH_VPN_INPUT`, nên `iptables -C` trả về mã thoát `1` (`iptables: Bad rule`), và `apply_optin_firewall_with_executor` (`124-131`) coi `status_code != 0` là lỗi thất bại! Kể cả khi chạy lại, hàm cũng không có bước nào thực thi `-I INPUT 1 -j MESH_VPN_INPUT`, đồng thời chạy lặp `-A` làm nhân bản các rule trong `MESH_VPN_INPUT`.
  2. Ở nhánh rollback của `Ufw` (`228-235`), hàm chỉ gọi `ufw delete allow 3478/udp` mà quên gọi `ufw delete allow <control_port>/tcp`, để sót cổng TCP mở sau khi gỡ bỏ.
  3. Toàn bộ `firewall_linux.rs` đang gắn cứng `DEFAULT_CONTROL_HTTPS_PORT` (`443`) và `DEFAULT_STUN_UDP_PORT` (`3478`) mà không có hàm nhận cổng tùy chỉnh của người dùng (`GNFR-11`, `US-074`).
- **Hệ quả thực tế (Impact)**: Chức năng cấu hình tường lửa opt-in gãy hoàn toàn trên các bản phân phối Linux dùng `iptables`, rò rỉ cổng mở khi rollback `ufw`, và mở sai cổng nếu quản trị viên triển khai `mesh-server` ở cổng tùy chỉnh (ví dụ `8443`/`3479`).
- **Hướng khắc phục trong phạm vi `WP-S1-03`**:
  1. Trong `firewall_linux.rs`: sau `iptables -N MESH_VPN_INPUT` (chấp nhận "Chain already exists"), chạy `iptables -F MESH_VPN_INPUT` để đảm bảo tính lũy đẳng, nạp các rule con, kiểm tra `iptables -C INPUT -j MESH_VPN_INPUT` — nếu trả mã `!= 0` thì thực thi `iptables -I INPUT 1 -j MESH_VPN_INPUT`!
  2. Bổ sung `ufw --force delete allow <control_port>/tcp` trong `rollback_optin_firewall`.
  3. Cung cấp hàm cấu hình nhận tham số `(tun_interface, control_tcp_port: Port, stun_udp_port: Port)` bên cạnh wrapper dùng giá trị mặc định từ `mesh_core::defaults` để giữ tương thích chữ ký hiện có.

---

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-07` [`WP-S1-03`] — `deploy/systemd/meshd.service` tước bỏ `CAP_CHOWN` trong `CapabilityBoundingSet`, khiến `meshd` bị lỗi `EPERM` khi gán nhóm `mesh-admin` cho `/var/run/meshd/meshd-admin.sock`
- **Vị trí**:
  - `deploy/systemd/meshd.service:21-22`
  - Đối chiếu `crates/mesh-net/src/ipc_linux.rs:57-59` và `crates/mesh-sys/src/fs_unix.rs:94-116`
- **Nguyên nhân gốc rễ**:
  - `deploy/systemd/meshd.service:10-11, 21-22` chạy `meshd` dưới `User=root`, `Group=root` nhưng khóa cứng `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`. Trên Linux, `CapabilityBoundingSet` tước bỏ mọi capability khác **ngay cả đối với UID `0`**, bao gồm cả `CAP_CHOWN`!
  - Khi nhóm `mesh-admin` tồn tại trên máy Linux client (`SEC-14`), `bind_linux_ipc_listener` (`ipc_linux.rs:58`) gọi `set_path_group_if_root("/var/run/meshd/meshd-admin.sock", mesh_admin_gid)` → `libc::lchown(path, -1, mesh_admin_gid)`. Vì tiến trình `root:root` không nằm trong nhóm phụ `mesh-admin` và đã bị tước `CAP_CHOWN`, nhân Linux trả về **`EPERM` (`Operation not permitted`)**, làm `meshd` không thể mở Admin IPC socket và dừng hoạt động!
- **Hệ quả thực tế (Impact)**: Trên mọi máy Linux Desktop/Server có tạo nhóm `mesh-admin` để phân quyền quản trị cục bộ theo thiết kế `SEC-14`, daemon `meshd` chạy dưới `systemd` sẽ chết ngay lúc khởi tạo IPC.
- **Hướng khắc phục trong phạm vi `WP-S1-03`**:
  - Trong `deploy/systemd/meshd.service:21-22`, bổ sung `CAP_CHOWN` (và `CAP_DAC_OVERRIDE` nếu `/etc/hosts` có quyền hạn chế đọc/ghi đặc biệt trên một số distro hardening, hoặc tối thiểu `CAP_CHOWN` vì `root` đã sở hữu `/etc/hosts` và `/var/lib/meshd`):
    `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN`
    `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN`

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-09` [`WP-S1-03`] — Bọc descriptor thiết bị ký tự `/dev/net/tun` (`S_IFCHR`) và socket định tuyến phi-UDS vào `std::os::unix::net::UnixDatagram` thay vì `tokio::io::unix::AsyncFd<OwnedFd>`
- **Vị trí**:
  - `crates/mesh-net/src/tun_linux.rs:4, 10, 17-21, 38`
  - `crates/mesh-net/src/tun_macos.rs:4, 10, 17-21, 36`
  - `crates/mesh-net/src/netmon_linux.rs:51`
  - `crates/mesh-net/src/netmon_macos.rs:50`
- **Nguyên nhân gốc rễ**:
  - Trên Linux, `/dev/net/tun` là **character device** (`S_IFCHR`), hoàn toàn không phải socket; trên macOS/Linux, `PF_SYSTEM`/`AF_SYS_CONTROL` (`utun`), `AF_NETLINK` và `PF_ROUTE` cũng không phải `AF_UNIX` datagram socket.
  - Việc ép `StdUnixDatagram::from(owned_fd)` vi phạm bất biến kiểu của thư viện chuẩn Rust (`std::os::unix::net::UnixDatagram` giả định fd là socket `AF_UNIX`). Cụ thể: `LinuxTunDevice` và `MacOsTunDevice` đều gắn `#[derive(Debug)]`, mà `StdUnixDatagram::fmt` gọi `getsockname()`/`getpeername()` trên fd → trả lỗi `ENOTSOCK` trên `/dev/net/tun`; đồng thời nếu bản vá tương lai của `tokio` đồng nhất `UnixDatagram::from_std` với `from_mio` (vốn gọi `io.take_error()` → `getsockopt(SOL_SOCKET, SO_ERROR)`), `LinuxTunDevice::open` sẽ vỡ ngay lập tức với `ENOTSOCK`!
  - Trong khi đó, `tokio` đã được bật `features = ["full"]` ở workspace, cung cấp sẵn `tokio::io::unix::AsyncFd<OwnedFd>` được thiết kế chính thức cho mọi non-blocking file descriptor hỗ trợ `epoll`/`kqueue` (gồm cả `/dev/net/tun`, `utun`, `netlink`, `PF_ROUTE`).
- **Hệ quả thực tế (Impact)**: Tiềm ẩn bẫy tương thích `ENOTSOCK` trên `/dev/net/tun` thật và vi phạm hợp đồng an toàn kiểu hệ thống của Rust/Tokio.
- **Hướng khắc phục trong phạm vi `WP-S1-03`**:
  - Thay `tokio::net::UnixDatagram` + `StdUnixDatagram` trong cả 4 tệp `tun_linux.rs`, `tun_macos.rs`, `netmon_linux.rs`, `netmon_macos.rs` bằng `tokio::io::unix::AsyncFd<OwnedFd>`, dùng `readable().await?.try_io(|inner| ...)` và `writable().await?.try_io(|inner| ...)` gọi các hàm đọc/ghi an toàn trong `mesh-sys`.

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-10` [`WP-S1-03`] — Kịch bản gỡ cài đặt `scripts/install-macos.sh` dò sai chuỗi đánh dấu khối `/etc/hosts`, bỏ sót toàn bộ bản ghi DNS nội bộ sau `--uninstall`
- **Vị trí**: `scripts/install-macos.sh:228-235` (đối chiếu `crates/mesh-core/src/brand.rs:34-37`)
- **Nguyên nhân gốc rễ**: Hằng chuẩn trong `mesh_core::brand` là `HOSTS_BEGIN_MARKER = "# BEGIN mesh managed hosts (do not edit manually)"` và `HOSTS_END_MARKER = "# END mesh managed hosts"`. Tuy nhiên hàm `strip_hosts_block_preserving_symlink` trong `scripts/install-macos.sh:229-230` lại so khớp dòng chính xác `/^# BEGIN mesh$/` và `/^# END mesh$/`, nên không bao giờ khớp được khối do `meshd` ghi ra!
- **Hệ quả thực tế (Impact)**: Khi chạy `sudo sh install-macos.sh --uninstall` (đặc biệt khi `meshd` đã bị kill hoặc binary không còn), các mục phân giải tên miền `.mesh.local` cũ vẫn nằm vĩnh viễn trong `/private/etc/hosts` của máy người dùng (`US-062 AC4`).
- **Hướng khắc phục trong phạm vi `WP-S1-03`**: Cập nhật biểu thức `awk` tại `scripts/install-macos.sh:228-235` khớp chính xác cả `^# BEGIN mesh managed hosts \(do not edit manually\)$` và `^# END mesh managed hosts$` (có thể chấp nhận luôn biến thể ngắn `# BEGIN mesh` / `# END mesh` để phòng thủ).

---

#### ✅ `[CLOSED IN R2]` 🟡 `IMP-S1-01` [`WP-S1-03`] — Xử lý đọc `0` byte trên `tun_linux`/`tun_macos` và dọn dẹp firewall opt-in trong `LinuxCleanupOps`
- **Vị trí**: `crates/mesh-net/src/tun_linux.rs:50-71`, `crates/mesh-net/src/tun_macos.rs:48-69`, `crates/mesh-net/src/route_linux.rs:278-285`
- **Ghi chú cải thiện**:
  1. Trong `LinuxTunDevice::read_packet` và `MacOsTunDevice::read_packet`, nếu tầng dưới trả `Ok(0)` (ví dụ gói `utun` chỉ có 4 byte family header rỗng), nên `continue` chờ gói kế tiếp thay vì trả `Ok(0)` lên datapath.
  2. Trong `LinuxCleanupOps::remove_firewall_rules` (`route_linux.rs:278-285`), nối sang `firewall_linux::rollback_optin_firewall` khi sổ cái có ghi nhận tên rule tường lửa opt-in thay vì chỉ `tracing::debug!` no-op.

---

### PHẦN D — Gói `WP-S1-04` (`crates/mesh-sys/src/*_windows.rs`, `crates/mesh-net/src/*_windows.rs`, `scripts/install-windows.ps1`)

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-08` [`WP-S1-04`] — Toàn bộ lệnh gọi `netsh.exe` trên Windows bỏ qua mã thoát lỗi (`CommandOutput::success()` không bao giờ được kiểm tra!) và thiếu `WindowsCleanupOps` cho `ResourceLedger`
- **Vị trí**:
  - `crates/mesh-net/src/tun_windows.rs:243, 252-259`
  - `crates/mesh-net/src/route_windows.rs:57-66`
  - `crates/mesh-net/src/firewall_windows.rs:112-121`
- **Nguyên nhân gốc rễ**:
  1. Theo hợp đồng của `mesh_net::sysexec::CommandExecutor::execute` (`crates/mesh-net/src/sysexec.rs:217-223`), hàm chỉ trả `Err` khi không khởi chạy được tiến trình hoặc quá thời gian chờ; nếu `netsh.exe` chạy xong và thất bại với `status_code = 1` (sai cú pháp, thiếu quyền, adapter chưa sẵn sàng, xung đột IP/route), `execute` trả về **`Ok(CommandOutput { status_code: 1, ... })`**!
  2. Mọi nơi gọi `netsh.exe` trong `tun_windows.rs` (`configure_adapter_address_and_mtu`), `route_windows.rs` (`run_netsh`) và `firewall_windows.rs` (`run_netsh_advfirewall`) đều viết `let _out = exec.execute(spec)?;` và vứt bỏ hoàn toàn `status_code`! (Ví dụ thực tế: lệnh `netsh interface ipv4 set subinterface "Mesh" mtu=1280 store=active` có thể thất bại trên một số bản ngôn ngữ/cấu hình Windows nếu không truyền `interface="Mesh"` hoặc nếu tên subinterface khác, nhưng `tun_windows.rs:258` vẫn báo `Ok(())`!).
  3. Không giống `route_linux.rs` (`LinuxCleanupOps`) và `route_macos.rs` (`MacOsCleanupOps`), `route_windows.rs` chưa cung cấp struct `WindowsCleanupOps` cài đặt trait `LedgerCleanupOps`, khiến ở Wave 1.2 daemon `meshd` trên Windows không có backend để gọi `ResourceLedger::cleanup_all` khi khởi động khôi phục sau crash hoặc khi tắt dịch vụ!
- **Hệ quả thực tế (Impact)**: Giao diện Wintun trên Windows có thể không có địa chỉ IP, không có MTU 1280, không có route overlay `100.64.0.0/10` và không có rule tường lửa nhưng `meshd` vẫn báo kết nối `"Connected"` xanh giả tạo — mất kết nối mạng overlay 100% mà không có bất kỳ log lỗi nào; đồng thời không dọn được tài nguyên mồ côi qua `ResourceLedger`.
- **Hướng khắc phục trong phạm vi `WP-S1-04`**:
  1. Trong `tun_windows.rs`, `route_windows.rs` và `firewall_windows.rs`: kiểm tra bắt buộc `if !out.success()` sau mọi lệnh `exec.execute(spec)?` và trả `AppError` kèm `status_code` + `stderr`/`stdout` đã cắt gọn (riêng các thao tác xóa route / xóa firewall rule khi dọn dẹp thì cho phép lũy đẳng nếu output báo không tìm thấy đối tượng). Dùng cú pháp tường minh `interface=<name>` khi đặt MTU subinterface.
  2. Bổ sung `pub struct WindowsCleanupOps<E>` cài đặt `LedgerCleanupOps` trong `crates/mesh-net/src/route_windows.rs` (xóa route theo sổ cái, gỡ firewall rules qua `firewall_windows`, xóa khối hosts qua `WindowsHostsEditor`, đóng adapter Wintun nếu cần) kèm unit test với fake `CommandExecutor` kiểm tra cả trường hợp `status_code = 1`.

---

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-09` [`WP-S1-04`] — Tự viết hàm băm mật mã SHA-256 & so sánh constant-time thủ công trong `mesh-sys` (vi phạm cứng `SEC-02`) + khe hở TOCTOU giữa bước kiểm tra hash và `LoadLibraryExW` của `wintun.dll`
- **Vị trí**:
  - `crates/mesh-sys/src/tun_windows.rs:38-115, 266-297, 685-830`
  - `crates/mesh-net/src/tun_windows.rs:93-105, 175-196`
- **Nguyên nhân gốc rễ**:
  1. **Vi phạm quy tắc cô lập mật mã (`coding-standards.md` §1 & `SEC-02`)**: Quy chuẩn kiến trúc khóa cứng `mesh-crypto` là crate **duy nhất** chứa cài đặt mật mã và **nghiêm cấm tự viết thuật toán mật mã**. Thế nhưng `crates/mesh-sys/src/tun_windows.rs:685-830` lại tự cài đặt tay toàn bộ thuật toán nén SHA-256 (`Sha256State`, `K`, `sha256_compress`, `sha256_digest`) dài hơn 140 dòng cùng vòng lặp `constant_time_eq_32` thủ công (`diff |= a ^ b` không có rào cản chống trình biên dịch LLVM tối ưu hóa rẽ nhánh như `subtle::ConstantTimeEq`). Trong khi đó `crates/mesh-net` đã có sẵn phụ thuộc hợp lệ `mesh-crypto` (`mesh_crypto::hash::verify_sha256_hex` dùng `sha2` + `subtle::ConstantTimeEq`)!
  2. **Khe hở đua tranh TOCTOU khi nạp `wintun.dll` với quyền `SYSTEM`**: Cả `verify_wintun_before_load` (`tun_windows.rs:96`) lẫn `WintunDll::load_verified` (`mesh-sys/src/tun_windows.rs:278`) đều mở `File::open(dll_path)`, đọc hết byte, **đóng `File` handle lại** rồi mới gọi `LoadLibraryExW`! Trong khoảng trống giữa lúc đóng file và lúc `LoadLibraryExW` mở lại đường dẫn, file hoặc reparse point có thể bị tráo đổi nếu thư mục bị cấu hình sai ACL; ngoài ra `validate_wintun_dll_path` chưa kiểm tra đường dẫn `wintun.dll` không phải reparse point/symlink và nằm cùng thư mục chứa thực thi ứng dụng.
- **Hệ quả thực tế (Impact)**: Vi phạm trực tiếp quy tắc cấm tự viết mật mã `SEC-02` (sẽ bị chặn ở cổng kiểm toán bảo mật Gate 3) và để hở cửa sổ TOCTOU trên tiến trình `NT AUTHORITY\SYSTEM`.
- **Hướng khắc phục trong phạm vi `WP-S1-04`**:
  1. Xóa bỏ hoàn toàn bộ cài đặt SHA-256 thủ công và `constant_time_eq_32` khỏi `crates/mesh-sys/src/tun_windows.rs`.
  2. Mở `wintun.dll` một lần duy nhất với `OpenOptions::new().read(true).share_mode(FILE_SHARE_READ)` (trên Windows, việc giữ mở handle chỉ cho phép `FILE_SHARE_READ` sẽ **khóa cứng ở mức kernel NTFS**, ngăn mọi tiến trình khác ghi đè, đổi tên hay xóa `wintun.dll`!), kiểm tra metadata trên handle đã mở (`is_file()`, không mang `FILE_ATTRIBUTE_REPARSE_POINT`, nằm trong thư mục ứng dụng hợp lệ).
  3. Tại `crates/mesh-net/src/tun_windows.rs`, đọc luồng byte từ chính `File` đang giữ khóa đọc đó và gọi `mesh_crypto::hash::verify_sha256` / `verify_sha256_hex` (`sha2` + `subtle`), sau đó truyền tham chiếu `&File` (vẫn đang mở giữ khóa đọc!) xuống `mesh_sys::tun_windows::WintunDll::load_with_read_lock(dll_path, &locked_file)` để `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR)` nạp xong DLL rồi mới nhả handle `locked_file`!

---

#### ✅ `[CLOSED IN R2]` 🔴 `BLK-S1-10` [`WP-S1-04`] — `scripts/install-windows.ps1` khai báo thiếu hậu tố `$HostsBeginMarker`, làm hỏng cấu trúc file `%SystemRoot%\System32\drivers\etc\hosts` khi gỡ cài đặt (`-Uninstall`)
- **Vị trí**: `scripts/install-windows.ps1:32-33, 152-166` (đối chiếu `crates/mesh-core/src/brand.rs:34-37`)
- **Nguyên nhân gốc rễ**:
  - `crates/mesh-core/src/brand.rs:34-37` định nghĩa:
    - `HOSTS_BEGIN_MARKER = "# BEGIN mesh managed hosts (do not edit manually)"`
    - `HOSTS_END_MARKER = "# END mesh managed hosts"`
  - Trong khi đó `scripts/install-windows.ps1:32-33` viết:
    - `$HostsBeginMarker = "# BEGIN mesh managed hosts"` *(bị cắt cụt mất ` (do not edit manually)`!)*
    - `$HostsEndMarker = "# END mesh managed hosts"` *(khớp chính xác!)*
  - Hậu quả cực kỳ tai hại trong `Remove-ManagedHostsBlock` (`152-166`): khi gặp dòng mở đầu `# BEGIN mesh managed hosts (do not edit manually)`, phép so sánh `$trimmed -eq $HostsBeginMarker` trả về **`$false`**, nên `$insideBlock` vẫn là `$false` và toàn bộ các dòng bản ghi DNS bên trong khối đều được giữ lại. Thế nhưng khi chạy tới dòng kết thúc `# END mesh managed hosts`, `$trimmed -eq $HostsEndMarker` lại trả về **`$true`**, bật `$changed = $true` và **xóa mất duy nhất dòng đóng `# END mesh managed hosts`**!
- **Hệ quả thực tế (Impact)**: Không những không dọn được bản ghi hosts khi gỡ cài đặt, kịch bản còn **làm hỏng cấu trúc file `hosts` của Windows** (để lại dòng `# BEGIN mesh managed hosts (do not edit manually)` mồ côi không có dòng `# END`), khiến nếu sau này người dùng cài lại Mesh VPN thì `locate_managed_block` (`crates/mesh-net/src/hosts.rs:285-291`) luôn báo lỗi `CorruptMarkers` vĩnh viễn!
- **Hướng khắc phục trong phạm vi `WP-S1-04`**: Sửa `$HostsBeginMarker = "# BEGIN mesh managed hosts (do not edit manually)"` tại `scripts/install-windows.ps1:32` (đồng thời chấp nhận khớp cả chuỗi cũ `# BEGIN mesh managed hosts` ở nhánh gỡ bỏ phòng trường hợp file đã tồn tại).

---

#### ✅ `[CLOSED IN R2]` 🟠 `HR-S1-11` [`WP-S1-04`] — `WindowsHostsEditor` chặn đứng luồng worker Tokio tối đa `2 giây` bằng `Condvar::wait_timeout` đồng bộ + `Command::output()`
- **Vị trí**: `crates/mesh-net/src/hosts_windows.rs:119-151, 244-265`
- **Nguyên nhân gốc rễ**:
  - Theo `.agents/rules/coding-standards.md` §1 & §4, daemon `meshd` chỉ chạy đúng **`worker_threads(2)`** để tiết kiệm RAM và nghiêm cấm ngủ chặn luồng OS bên trong ngữ cảnh async.
  - `WindowsHostsEditor::with_lock_backoff` gọi `backoff_wait` (`257-265`) dùng `std::sync::Condvar::wait_timeout` để lách kiểm tra tĩnh tên chuỗi `thread::sleep`, nhưng về mặt hệ điều hành nó **vẫn chặn cứng luồng OS đang gọi tới `2 giây`**, cộng thêm lệnh đồng bộ `std::process::Command::new(ipconfig).arg("/flushdns").output()` (`134-149`). Nếu `meshd` gọi `HostsEditor::apply` từ một task async, 1 trong 2 worker threads của cả tiến trình VPN sẽ bị đóng băng!
  - Thêm vào đó, `is_transient_lock_error` (`244-255`) coi mọi lỗi `ErrorKind::PermissionDenied` (`ERROR_ACCESS_DENIED = 5`) đều là khóa tạm thời của Antivirus, nên nếu file bị lỗi quyền vĩnh viễn nó luôn treo đủ trần `2 giây`.
- **Hệ quả thực tế (Impact)**: Gây giật cục độ trễ gói tin (jitter spike lên tới hàng trăm ms – 2 s) trên luồng dữ liệu WireGuard mỗi khi bản đồ mạng cập nhật danh sách tên máy trên Windows.
- **Hướng khắc phục trong phạm vi `WP-S1-04`**:
  1. Bổ sung phương thức async chuyên dụng `pub async fn apply_async(&self, entries: &[HostEntry]) -> AppResult<()>` và `pub async fn clear_async(&self) -> AppResult<()>` trên `WindowsHostsEditor` sử dụng `tokio::time::sleep` giữa các lần thử và bọc từng thao tác I/O đĩa / `ipconfig /flushdns` ngắn gọn bên trong `tokio::task::spawn_blocking`.
  2. Trong `is_transient_lock_error`, ưu tiên mã lỗi chia sẻ file của Windows (`ERROR_SHARING_VIOLATION = 32`, `ERROR_LOCK_VIOLATION = 33`), chỉ retry giới hạn ngắn đối với `ERROR_ACCESS_DENIED = 5` khi xảy ra đúng lúc `MoveFileExW` thay thế đích.

---

#### ✅ `[CLOSED IN R2]` 🟡 `IMP-S1-02` [`WP-S1-04`] — Tối ưu hóa cấp phát bộ nhớ trên đường nóng `WindowsTunDevice::read_packet`
- **Vị trí**: `crates/mesh-net/src/tun_windows.rs:274-292`
- **Ghi chú cải thiện**: Hiện tại mỗi lần đọc **1 gói tin** trên Windows, `read_packet` lại cấp phát mới một `Vec<u8>` kích thước `buf.len()` trên heap và tạo một task `tokio::task::spawn_blocking` mới (`276-277`). Ở lưu lượng cao hàng chục nghìn gói/giây, chi phí đồng bộ hóa pool `spawn_blocking` và cấp phát heap trên mỗi gói sẽ làm tăng CPU/RAM của `meshd`. Khuyến nghị dùng một luồng đọc nền chuyên trách gắn với vòng đời của `WindowsTunDevice` (hoặc tái sử dụng bộ đệm tĩnh `2048 B`) và đánh thức ngay khi `close()` thay vì đợi hết cửa sổ poll `250 ms`.

---

## 4. Kết Luận Kiểm Định Độc Lập (Vòng 1)

- Tổng cộng Vòng 1 phát hiện **`10` lỗi mức `🔴 Blocker`**, **`11` lỗi mức `🟠 High Risk`**, và **`2` đề xuất `🟡 Improvement`** trải đều trên 4 gói công việc `WP-S1-01`..`WP-S1-04`.
- Toàn bộ hướng dẫn khắc phục Vòng 1 đã được đóng khung chặt theo ranh giới sở hữu tệp của từng Worker để Scrum Master điều phối sửa lỗi **song song 4 luồng không xung đột git/file**.

---

## 5. Kết Quả Thẩm Định Thực Chứng Vòng 2 (`Round 2 Verification` — Đối Chiếu Từng Dòng Mã Nguồn)

### 5.1. Bảng Đối Chiếu Trạng Thái `23 / 23` Mục Từ Vòng 1

| Mã mục | Gói | Trạng thái Vòng 2 | Bằng chứng dòng mã nguồn đã mở kiểm chứng trực tiếp |
| :--- | :---: | :---: | :--- |
| **`BLK-S1-01`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-store/src/nodes_repo.rs:150-163, 689-729` bắt buộc `consumed_key.bound_node_name.as_deref() == Some(prev_record.node_name.as_str())`, từ chối key không gắn đích danh bằng `ErrorKind::Unauthenticated`; `crates/mesh-store/src/store.rs:546-550` đẩy `old_pk` vào `RevokedSet` RAM (`insert_rotated_pubkey`); `crates/mesh-server/src/control_handlers.rs:334-344` ngắt ngay luồng Control & Relay cũ. |
| **`BLK-S1-02`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-server/src/control_handlers.rs:848-856, 949-1046` dùng chung `pump_ws_duplex` cho cả Control WS và Relay WS: khi `stream_cancel.cancelled()` / `shutdown.cancelled()` kích hoạt, `drain_remaining_and_close_ws` rút cạn `direct_rx` + `hub_rx`, gửi xuống sink + `ws.close(None)` + `flush` dưới `WS_DRAIN_SHUTDOWN_TIMEOUT = 500ms`. Tại nhánh Gate 2(b) (`must_disconnect_all_peers_to_reauth`), `admin_service.rs:569-590` và `alert_worker.rs:333-343` gọi `terminate_node_stream` + `disconnect_node` cho `outcome.node_id` (đồng thời gỡ khỏi map tại `netmap_hub.rs:389` và `relay_hub.rs:332`) trước khi gọi `close_all_streams_for_reauth()` / `close_all_sessions()`. |
| **`BLK-S1-03`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-crypto/src/certgen.rs:249-367` (`generate_tls_alpn_01_challenge_cert` gắn OID `1.3.6.1.5.5.7.1.31` critical, `build_tls_alpn_certified_key_from_der`, `extract_cert_not_after_ms_from_der`) và `crates/mesh-server/src/acme.rs:397-739` hiện thực hóa trọn vẹn `instant-acme` `0.7` (`Account` lưu bền, `NewOrder`, `TLS-ALPN-01` với `AcmeAlpnCleanupGuard` & `DNS-01`, CSR `finalize`, live reload); `obs_service.rs:72-87` trả `503` trên `/readyz` khi `TlsMode::Acme && !ca_verified`; `admin_service.rs:307-315, 632-638` giữ ghim `--server-pin` khi chưa có chứng chỉ CA thật. |
| **`BLK-S1-04`** | `WP-S1-01` | ⚠️ **LOGIC CLOSED · CÒN `HR-S1-12-R2`** | 5 lỗi logic cốt lõi đã đóng sạch (`admin_service.rs:766-789` tách `query.allow_pin_change` khỏi `parsed.verify_sha256`; `store.rs:821-899` + `backup.rs:210-351` kiểm chứng trên `.restore-staged.redb.tmp` trước khi nhả `*db_guard = None`, nâng `watermark = max(...) + 1_000_000`, chỉ reset `emergency-revocations.bin` sau khi mở lại DB thành công; `store.rs:773-817` gộp mục thu hồi khẩn cấp vào `create_backup`). Tuy nhiên trong `crates/mesh-store/src/backup.rs` phát sinh `#[allow(clippy::too_many_arguments)]` cấm tại dòng `120` và xóa mất bản `.before-restore` tại dòng `269, 325` → xem **`HR-S1-12-R2`**. |
| **`BLK-S1-05`** | `WP-S1-01` + `WP-S1-03` | ⚠️ **`WP-S1-03` CLOSED · CÒN `BLK-S1-05-R2` (`WP-S1-01`)** | Phần `WP-S1-03` (`crates/mesh-sys/src/fs_unix.rs:98-189`) **đã đóng hoàn toàn** (`meta.gid() == gid` trả `Ok(())`, gọi `libc::lchown` cho cả user không đặc quyền). Tuy nhiên phần `WP-S1-01` (`deploy/systemd/mesh-server.service:9-16` đối chiếu `scripts/install-server.sh:140, 146, 172-173`) tạo hồi quy mất GID `mesh` gây lỗi **`EACCES`** khi đọc `/etc/mesh/server.toml` (`0640 root:mesh`) → xem **`BLK-S1-05-R2`**. |
| **`HR-S1-01`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-server/src/stun_service.rs:189-198` ghi log lỗi tạm thời `recv_from`, ngủ `20 ms` và tiếp tục vòng lặp thay vì làm chết vĩnh viễn STUN listener hay đánh sập `/readyz`. |
| **`HR-S1-02`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-server/src/listener_set.rs:305-340` đối chiếu `active_registered > 0 && acked >= active_registered` từ `store.list_nodes()` (`Active`), không cắt cổng cũ sớm khi `0` node online hoặc còn laptop offline. |
| **`HR-S1-03`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-server/src/admin_service.rs:96-107, 305-395, 630-660, 905-925` bổ sung `GET /v1/admin/nodes/{id}` & `POST /v1/admin/preauth-keys/{id}/revoke`, sửa ánh xạ `PreAuthKeySummary`; `keys_repo.rs:59-68, 226-233` lưu và cưỡng chế `max_uses`; `nodes_repo.rs:52-53, 261, 420` giữ `last_overlay_ip` để node bị thu hồi hiển thị đầy đủ; `install-server.sh:14, 178-192, 244` dùng `--authkey-file` và tường lửa opt-in bảo toàn cổng SSH. |
| **`HR-S1-04`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-store/src/revoked_ram.rs:28, 690-713, 798-823` mã hóa đầy đủ `min_netmap_version` (`8 B`) + `EmergencyNodeReason` (`1 = Revoked`, `2 = Expired`) trong mỗi bản ghi `65 B`; `nodes_repo.rs:264-271, 311-317` xóa `node_name` khỏi `TABLE_IDX_NODES_NAME` khi thu hồi. |
| **`HR-S1-05`** | `WP-S1-01` | ✅ **CLOSED** | `crates/mesh-server/src/control_handlers.rs:56-58, 428-433, 518-526, 696-708, 780, 798-804, 1279-1344` hạ trần khung WS về `65_536 B`, lọc endpoint qua `is_valid_candidate_endpoint` (`<= 16`), kiểm tra `peek_outer_sender_pubkey == sender_disco_pubkey` & đích `Active` trên `CallMeMaybe`, kiểm tra thu hồi/hết hạn trên mọi thông điệp WS; `alert_worker.rs:171-242` + `mesh_sys::filesystem_usage_percent` (`fs_unix.rs:423-471`, `netmon_windows.rs:418-480`) đánh giá đủ `RelaySaturation` & `DiskUsageHigh`. |
| **`HR-S1-06`** | `WP-S1-02` | ✅ **CLOSED** | `crates/mesh-datapath/src/disco_engine.rs:525-545` bật chế độ **Fast Suspect Probe** (`DISCO_SUSPECT_PROBE_INTERVAL_MS = 1_000ms`) khi trượt Pong hoặc bất đối xứng TX/RX, đảm bảo chuyển mạch `Direct -> Relay <= 10 s`. |
| **`HR-S1-07`** | `WP-S1-02` | ✅ **CLOSED** | `crates/mesh-datapath/src/relay_client.rs:382-388, 452, 708-727, 1295-1517` rút cạn hàng đợi burst theo vòng lặp có `yield_now()`, giữ bền `ReconnectBackoffs` ngoài vòng lặp `run` (bao phủ cả `ClockSkew`, `PinMismatch` và lỗi chứng chỉ `"TLS ..."` từ `tlspin.rs:117-143`), hỗ trợ giải mã HTTP `Transfer-Encoding: chunked` có trần kích thước và `serde_json::from_slice`. |
| **`HR-S1-08`** | `WP-S1-02` | ✅ **CLOSED** | `crates/mesh-datapath/src/stun_client.rs:301-307` bổ sung `is_probe_round_ready(now_ms)` không cắt ngang yêu cầu STUN ở nhịp `250 ms`; `engine.rs:398-402, 476-480, 764-776, 809` lưu `last_stun_report` và `reflexive_addrs`. |
| **`BLK-S1-06`** | `WP-S1-03` | ✅ **CLOSED** | `crates/mesh-net/src/firewall_linux.rs:255-305, 386-420, 613-650` chạy lũy đẳng `iptables -F MESH_VPN_INPUT`, kiểm tra `-C INPUT -j MESH_VPN_INPUT` và chèn `-I INPUT 1 -j MESH_VPN_INPUT` khi chưa có, xóa đủ rule TCP + UDP + TUN khi rollback `ufw`, hỗ trợ cổng tùy chỉnh. |
| **`BLK-S1-07`** | `WP-S1-03` | ✅ **CLOSED** | `deploy/systemd/meshd.service:21-22` bổ sung `CAP_CHOWN` vào cả `AmbientCapabilities` và `CapabilityBoundingSet`. |
| **`HR-S1-09`** | `WP-S1-03` | ✅ **CLOSED** | `crates/mesh-net/src/{tun_linux,tun_macos,netmon_linux,netmon_macos}.rs` chuyển hoàn toàn khỏi `UnixDatagram` sang `tokio::net::unix::pipe::{Receiver, Sender}::from_owned_fd_unchecked` (`0` khối `unsafe` trong `mesh-net`, không gọi bất kỳ syscall chỉ dành cho socket nào nên không bao giờ phát sinh `ENOTSOCK`). |
| **`HR-S1-10`** | `WP-S1-03` | ✅ **CLOSED** | `scripts/install-macos.sh:228-235` cập nhật `awk` khớp chuẩn `# BEGIN mesh managed hosts (do not edit manually)` / `# END mesh managed hosts` (kèm nhánh phòng thủ tiền tố ngắn). |
| **`IMP-S1-01`** | `WP-S1-03` | ✅ **CLOSED** | `tun_linux.rs` / `tun_macos.rs` lặp `Ok(0) => continue`; `crates/mesh-net/src/route_linux.rs:278-284` nối `LinuxCleanupOps::remove_firewall_rules` vào `rollback_from_ledger_rules`. |
| **`BLK-S1-08`** | `WP-S1-04` | ✅ **CLOSED** | `crates/mesh-net/src/{tun_windows,route_windows,firewall_windows}.rs` kiểm tra `!out.success()` trên mọi lệnh `netsh.exe`, truyền tường minh `interface={adapter_name}` trên `subinterface`, và cài đặt đầy đủ `WindowsCleanupOps: LedgerCleanupOps` tại `route_windows.rs:210-295`. |
| **`BLK-S1-09`** | `WP-S1-04` | ✅ **CLOSED** | `crates/mesh-sys/src/tun_windows.rs:40-315, 557-674` xóa sạch 100% SHA-256 & `constant_time_eq_32` tự viết; giữ nguyên handle `LockedWintunFile` (`FILE_SHARE_READ` + `FILE_FLAG_OPEN_REPARSE_POINT` + `GetFileInformationByHandle`) xuyên suốt bước kiểm tra `mesh_crypto` SHA-256 tại `crates/mesh-net/src/tun_windows.rs:95-215` và `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`. |
| **`BLK-S1-10`** | `WP-S1-04` | ✅ **CLOSED** | `scripts/install-windows.ps1:32-33, 154-166` đặt đúng `$HostsBeginMarker = "# BEGIN mesh managed hosts (do not edit manually)"` và dọn sạch không để lại marker mồ côi. |
| **`HR-S1-11`** | `WP-S1-04` | ✅ **CLOSED** | `crates/mesh-net/src/hosts_windows.rs:106-155, 324-342` bổ sung `apply_async` / `clear_async` dùng `tokio::time::sleep` + `spawn_blocking` + `CommandExecutor` DNS flush, đồng thời loại trừ `ERROR_ACCESS_DENIED = 5` khỏi lỗi khóa tạm thời. |
| **`IMP-S1-02`** | `WP-S1-04` | ✅ **CLOSED** | `crates/mesh-net/src/tun_windows.rs:368-518` dùng luồng đọc nền gắn vòng đời session, tái sử dụng pool bộ đệm và đánh thức tức thì bằng `SetEvent` (`wake_reader()`) khi `close()`. |

---

### 5.2. Chi Tiết `2` Điểm Tồn Đọng / Hồi Quy Tại Vòng 2 (Chỉ Thuộc `WP-S1-01`)

#### ✅ `[CLOSED IN R3]` 🔴 `BLK-S1-05-R2` [`WP-S1-01`] — Hồi quy quyền nhóm trong `deploy/systemd/mesh-server.service`: đặt `Group=mesh-admin` làm mất GID `mesh` khỏi tiến trình, gây lỗi `EACCES` 100% khi đọc `/etc/mesh/server.toml` (`0640 root:mesh`)
- **Vị trí**:
  - `deploy/systemd/mesh-server.service:9-16`
  - Đối chiếu `scripts/install-server.sh:140, 146, 172-173` và `crates/mesh-server/src/main.rs:61`
- **Nguyên nhân gốc rễ (Chứng minh từng bước ở mức Linux/systemd)**:
  1. Trong `scripts/install-server.sh`:
     - Dòng `140`: `useradd --system --gid mesh --no-create-home --shell /usr/sbin/nologin mesh` tạo tài khoản `mesh` với nhóm chính `mesh` trong `/etc/passwd` (`pw_gid = mesh`), **không** ghi `"mesh"` vào danh sách thành viên phụ `gr_mem` của nhóm `mesh` trong `/etc/group`.
     - Dòng `143`: `usermod -a -G mesh-admin mesh` chỉ thêm `"mesh"` vào `gr_mem` của nhóm `mesh-admin` trong `/etc/group`.
     - Dòng `146` & `172-173`: tạo `/etc/mesh` (`0750 root:mesh`) và ghi `/etc/mesh/server.toml` với quyền **`0640 root:mesh`** (chỉ `root` hoặc tiến trình mang GID `mesh` mới đọc được).
  2. Trong bản vá Vòng 1, `deploy/systemd/mesh-server.service:9-16` đổi thành:
     ```ini
     User=mesh
     Group=mesh-admin
     ...
     ConfigurationDirectory=mesh
     ConfigurationDirectoryMode=0750
     ```
     mà **không có `SupplementaryGroups=mesh`** và `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (không có `CAP_DAC_READ_SEARCH`).
  3. Khi `systemd` khởi chạy unit với `User=mesh` và `Group=mesh-admin`:
     - `systemd` gọi `initgroups("mesh", gid_of("mesh-admin"))` + `setresgid(gid_of("mesh-admin"))` + `setresuid(uid_of("mesh"))`. Vì `initgroups(3)` chỉ quét cột `gr_mem` trong `/etc/group` (nơi chỉ có `mesh-admin`) cộng với tham số base group (`mesh-admin`), **GID `mesh` bị loại bỏ hoàn toàn khỏi tập nhóm của tiến trình `mesh-server`** (`uid=mesh, gid=mesh-admin, groups=[mesh-admin]`)!
     - Đồng thời `ConfigurationDirectory=mesh` chỉ đổi quyền thư mục `/etc/mesh` sang `mesh:mesh-admin` (làm mất quyền sở hữu `root` bảo vệ thư mục `/etc/mesh` dưới `ProtectSystem=strict`), nhưng **không** đổi quyền tệp `/etc/mesh/server.toml` đã do `install-server.sh` tạo trước đó (`0640 root:mesh`).
     - Ngay khi `ExecStart=/usr/local/bin/mesh-server --config /etc/mesh/server.toml` chạy tới `ServerConfig::load_from_toml(path)` (`crates/mesh-server/src/main.rs:61`), nhân Linux trả về **`EACCES` (`Permission denied`)**, `mesh-server` thoát với `ExitCode::FAILURE` và rơi vào crash-loop 100%!
- **Hướng khắc phục dứt điểm trong phạm vi `WP-S1-01` (chỉ sửa `deploy/systemd/mesh-server.service`)**:
  - Do `WP-S1-03` đã hoàn thành sửa `crates/mesh-sys/src/fs_unix.rs:98-189` (cho phép chủ sở hữu `User=mesh` gọi `lchown` đổi nhóm `/run/mesh-server` và `admin.sock` sang nhóm phụ `mesh-admin`), trong `deploy/systemd/mesh-server.service` chỉ cần đặt:
    ```ini
    User=mesh
    Group=mesh
    SupplementaryGroups=mesh-admin
    RuntimeDirectory=mesh-server
    RuntimeDirectoryMode=0750
    StateDirectory=mesh
    StateDirectoryMode=0700
    ```
    và **xóa 2 dòng `ConfigurationDirectory=mesh` / `ConfigurationDirectoryMode=0750`**. Khi đó:
    - Tiến trình chạy với `uid=mesh, gid=mesh, groups=[mesh, mesh-admin]`: đọc hợp lệ `/etc/mesh/server.toml` (`0640 root:mesh`, chỉ-đọc hoàn toàn dưới `ProtectSystem=strict`), sở hữu riêng `/var/lib/mesh` (`0700 mesh:mesh`), và tự chuyển `/run/mesh-server` (`0750 mesh:mesh-admin`) + `/run/mesh-server/admin.sock` (`0660 mesh:mesh-admin`) qua `prepare_secure_runtime_dir` không lỗi!

---

#### ✅ `[CLOSED IN R3]` 🟠 `HR-S1-12-R2` [`WP-S1-01`] — Vi phạm quy tắc cứng cấm `#[allow(clippy::...)]` tại `crates/mesh-store/src/backup.rs:120` và tự xóa mất bản lưu `control.redb.before-restore` tại dòng `269, 325`
- **Vị trí**: `crates/mesh-store/src/backup.rs:120, 269, 325`
- **Nguyên nhân gốc rễ**:
  1. **Vi phạm cứng `.agents/rules/coding-standards.md` dòng 3 (`Cấm tự #[allow(clippy::...)] lách luật.`)**: Khi bổ sung hàm `BackupManager::create_snapshot_with_emergency` (8 tham số) tại `crates/mesh-store/src/backup.rs:120`, tác giả đã gắn thuộc tính `#[allow(clippy::too_many_arguments)]` thay vì gom nhóm tham số vào struct. *(Đã quét tự động toàn bộ `crates/**/*.rs`: đây là vị trí `#[allow(clippy::...)]` duy nhất trong toàn bộ workspace).*
  2. **Xóa mất bản sao lưu an toàn trước khôi phục (`.before-restore`)**: Theo đặc tả `docs/03-system-design/database-design.md:647` và yêu cầu `BLK-S1-04`, khi thực hiện `restore`, hệ thống phải đổi tên `control.redb` hiện tại sang `control.redb.before-restore` và giữ lại tệp này (`0600`) để quản trị viên có đường lùi tức thì nếu khôi phục nhầm bản snapshot cũ. Hiện tại `swap_and_verify_staged_db` (`backup.rs:269, 325`) đặt tên tạm `.control.redb.rollback` rồi gọi **`remove_if_exists(&rollback_path)` ngay tại dòng `325`** sau khi mở DB mới thành công, làm mất bản `.before-restore`.
- **Hướng khắc phục dứt điểm trong phạm vi `WP-S1-01` (chỉ sửa `crates/mesh-store/src/backup.rs` & điểm gọi trong `store.rs` nếu đổi chữ ký)**:
  1. Đóng gói các tham số overlay khẩn cấp (`pending_nodes`, `pending_keys`, `min_netmap_version`) vào một struct nhỏ (ví dụ `pub struct EmergencySnapshotOverlay<'a>`) để hàm `create_snapshot_with_emergency` chỉ còn `<= 6` tham số và **xóa bỏ hoàn toàn `#[allow(clippy::too_many_arguments)]`**.
  2. Trong `swap_and_verify_staged_db` (`backup.rs:269-333`), đổi đường dẫn lưu bản cũ thành `<target_db_path>.before-restore` (ví dụ `with_file_name(format!("{file_name}.before-restore"))`), áp quyền `0600` (`restrict_file_permissions`), dùng chính tệp đó để rollback tự động nếu bước `verify_res` thất bại, và **giữ nguyên tệp `.before-restore` trên đĩa** (không xóa ở dòng `325`) khi khôi phục thành công, kèm khẳng định trong unit test.

---

### 5.3. Kết Luận Thẩm Định Vòng 2

- **Độ hoàn thiện ở cuối Vòng 2**: **`21 / 23`** phát hiện Vòng 1 đã được xử lý triệt để, sạch sẽ và có unit test bảo vệ. Cả 3 gói **`WP-S1-02`**, **`WP-S1-03`**, **`WP-S1-04`** đạt chuẩn **100% (`0` vấn đề mở)**.
- **Phạm vi chuyển sang Vòng 3**: Chỉ còn đúng **`2` tệp thuộc duy nhất gói `WP-S1-01`** (`deploy/systemd/mesh-server.service` cho `BLK-S1-05-R2` và `crates/mesh-store/src/backup.rs` cho `HR-S1-12-R2`).

---

## 6. Kết Quả Nghiệm Thu Cuối Vòng 3 (`Round 3 Final Sign-off`) & ⚖️ `Strategic Trade-offs`

### 6.1. Kiểm Chứng Thực Chứng Dòng Mã Nguồn Cho `2 / 2` Mục Vòng 2 (`WP-S1-01`)

| Mã mục Vòng 2 | Trạng thái Vòng 3 | Bằng chứng dòng mã nguồn đã mở kiểm chứng trực tiếp |
| :--- | :---: | :--- |
| **`BLK-S1-05-R2`** | ✅ **CLOSED** | `deploy/systemd/mesh-server.service:9-15` đã đặt chuẩn `User=mesh`, `Group=mesh`, `SupplementaryGroups=mesh-admin`, `RuntimeDirectory=mesh-server` (`0750`), `StateDirectory=mesh` (`0700`) và **xóa bỏ hoàn toàn** `ConfigurationDirectory=mesh` / `ConfigurationDirectoryMode=0750`. Tiến trình `mesh-server` chạy với tập thông tin xác thực `uid=mesh, gid=mesh, groups=[mesh, mesh-admin]`: đọc hợp lệ `/etc/mesh/server.toml` (`0640 root:mesh`, chỉ-đọc dưới `ProtectSystem=strict`), sở hữu độc quyền `/var/lib/mesh` (`0700 mesh:mesh`), và gọi `lchown` an toàn chuyển `/run/mesh-server` (`0750 mesh:mesh-admin`) + `admin.sock` (`0660 mesh:mesh-admin`) qua `prepare_secure_runtime_dir` (`crates/mesh-sys/src/fs_unix.rs:98-189`). |
| **`HR-S1-12-R2`** | ✅ **CLOSED** | 1) `crates/mesh-store/src/backup.rs:94-101, 129-136` & `crates/mesh-store/src/store.rs:794-805` đã đóng gói các trường thu hồi khẩn cấp vào `EmergencySnapshotOverlay<'a>`, giảm chữ ký `create_snapshot_with_emergency` xuống `6` tham số và xóa sạch thuộc tính cấm (quét tự động toàn bộ `crates/**/*.rs` xác nhận **`ALLOW_CLIPPY_COUNT = 0`**).<br/>2) `crates/mesh-store/src/backup.rs:269-341` đổi tên tệp lưu trữ trước khôi phục thành `<target_db_path>.before-restore` (`control.redb.before-restore`), cưỡng chế quyền `0600` (`restrict_file_permissions`), tự động hoàn tác nếu bước mở/kiểm tra bảng DB mới thất bại, và **giữ nguyên bản `.before-restore` (`0600`) trên đĩa** sau khi khôi phục thành công theo đúng `database-design.md:647`, kèm unit test chuyên biệt `test_restore_retains_before_restore_copy_with_restricted_permissions` (`backup.rs:899-987`). |

---

### 6.2. ⚖️ `Strategic Trade-offs` (Các Đánh Đổi Kiến Trúc & Vận Hành Khách Quan Của Wave 1.1)

Để Scrum Master và Người dùng nắm rõ bức tranh kỹ thuật minh bạch khi chuyển sang tích hợp CLI/Daemon ở Wave 1.2 và cổng nghiệm thu sau này:

1. **Chính sách dừng phát `netmap_version` chưa lưu bền dưới lỗi phần cứng kép `EIO` (Gate 2 Policy `b`)**:
   - *Đánh đổi*: Khi cả `control.redb` lẫn `emergency-revocations.bin` đồng thời hỏng phần cứng (`EIO`) đúng lúc cạn kiệt dải thuê bao phiên bản (`1_024`), `mesh-server` ưu tiên **tính toàn vẹn chống tụt lùi `netmap_version` và tính tức thời của thu hồi bảo mật** bằng cách chèn khóa bị thu hồi vào `RevokedSet` RAM và chủ động đóng các phiên WebSocket để ép toàn bộ peer xác thực lại (thay vì phát số phiên bản chưa được ghi bền).
   - *Hệ quả chấp nhận có chủ đích*: Gây một nhịp kết nối lại ngắn trên các peer đang online trong kịch bản thảm họa đĩa kép hiếm gặp, đổi lại loại bỏ 100% nguy cơ kẹt bản đồ mạng sau khi thay ổ cứng/khởi động lại VPS.
2. **Chuyển mạch nhanh P2P Direct sang Blind Relay (`Fast Suspect Probe` `1 s` -> failover `<= 10 s`)**:
   - *Đánh đổi*: Khi phát hiện trượt Pong đầu tiên hoặc lưu lượng gửi một chiều không phản hồi quá `2 s`, `DiscoEngine` tăng nhịp thăm dò lên `1 gói/giây` trong tối đa `3 nhịp` trước khi hạ cấp về `Relay`.
   - *Hệ quả chấp nhận có chủ đích*: Tốn thêm ~`3` gói UDP nhỏ (`< 300 B`) mỗi khi đường truyền Wi-Fi/4G chập chờn thoáng qua, đổi lại đạt cam kết SLA chuyển mạch mượt dưới `10 giây` (`REL-02`) không làm treo phiên SSH/RDP.
3. **Bọc descriptor TUN/Netlink/Route Unix qua `tokio::net::unix::pipe` thay vì `UnixDatagram`**:
   - *Đánh đổi*: Giữ trọn vẹn bất biến `unsafe_code = "forbid"` trong `mesh-net` (chỉ chuyển quyền sở hữu `OwnedFd` qua `from_owned_fd_unchecked` an toàn, không gọi bất kỳ syscall chỉ dành cho socket như `getsockname`/`getsockopt` trên character device `/dev/net/tun`), đồng thời duy trì đường dẫn I/O bất đồng bộ gọn nhẹ trên `epoll`/`kqueue`.
4. **Luồng đọc nền chuyên biệt kèm Pool tái sử dụng bộ đệm cho Wintun trên Windows (`IMP-S1-02`)**:
   - *Đánh đổi*: Duy trì 1 OS thread đọc vòng đệm Wintun (`WaitForSingleObject` + đánh thức tức thì bằng `SetEvent` khi đóng) trên mỗi phiên `WindowsTunDevice` đang mở, đổi lại loại bỏ hoàn toàn chi phí cấp phát heap + `spawn_blocking` trên từng gói tin và giữ độ trễ dừng dịch vụ dưới `5 giây`.

---

### 6.3. Phán Quyết Cuối Cùng Của `agile-critic` Cho Sprint 1 — Wave 1.1 (`WP-S1-01`..`WP-S1-04`)

Toàn bộ **`23 / 23`** phát hiện Vòng 1 và **`2 / 2`** phát hiện Vòng 2 trên cả 4 gói công việc `WP-S1-01`, `WP-S1-02`, `WP-S1-03`, `WP-S1-04` đã được xác minh thực chứng từng dòng mã nguồn là **ĐÃ ĐÓNG SẠCH 100% (`0` Blocker · `0` High Risk · `0` `#[allow(clippy::...)]`)**.

**`[APPROVED FOR GATE]`**
