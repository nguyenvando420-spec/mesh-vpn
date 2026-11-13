# Báo Cáo Phản Biện Độc Lập — Sprint 2 Wave 2.1 (`WP-S2-01` .. `WP-S2-03`)

- **Người phản biện**: `agile-critic` (`gemini-4-carbon-high` — Independent Red-Team Reviewer, tích hợp xác thực báo cáo kiểm toán `wave-2-1-codex.md`)
- **Ngày kiểm định**: `2026-11-13`
- **Phạm vi kiểm định**:
  - **`WP-S2-01` (Server Admin, Lifecycle, Backup/Restore, Live Migration, Rate-Limit & Observability)**: `crates/mesh-store/**`, `crates/mesh-server/**`, `crates/mesh/src/admin_cmds.rs` (`US-027`, `US-029`, `US-030`, `US-031`, `US-042`, `US-045`, `US-074`, `US-006`, `US-011`, `US-048`, `US-049`, `US-050`)
  - **`WP-S2-02` (Client Datapath, Key Rotation, Cache/Reconnect, Netcheck & Bugreport)**: `crates/mesh-datapath/**`, `crates/meshd/**`, `crates/mesh/src/{client_cmds.rs,output.rs}` (`US-030`, `US-031`, `US-032`, `US-033`, `US-034`, `US-018`, `US-023`, `US-041`)
  - **`WP-S2-03` (OS Roaming, Sleep/Wake, CGNAT Conflict & Linux Desktop Package)**: `crates/mesh-net/**`, `crates/mesh-sys/**`, `scripts/install-{linux.sh,windows.ps1}`, `deploy/linux-desktop/**`, `deploy/systemd/meshd.service` (`US-035`, `US-036`, `US-037`, `US-054`)
- **Đối chiếu chuẩn**: `.agents/rules/coding-standards.md`, `docs/03-system-design/{coding-standards,system-architecture,database-design,api-design}.md`, `docs/02-product-planning/product-backlog.md` (v1.2), `docs/04-sprint-management/sprint-backlog.md`, `docs/05-quality-assurance/codex-reviews/wave-2-1-codex.md`
- **Phán quyết Vòng 1**: 🔴 `[REVISION REQUIRED]` *(1 Blocker, 12 High Risk, 2 Improvement — 15 hạng mục mở)*
- **Phán quyết Vòng 2 (Hiện hành — `HEAD 76f57a6`)**: 🟢 **`[APPROVED FOR GATE]`** *(15/15 hạng mục `CLOSED` đã xác minh trực tiếp trên mã nguồn & kiểm thử hồi quy; `scripts/check.ps1 -Cross` xanh 100% với `275/275` tests pass, `0` clippy warnings, `cargo-deny` pass, `wsl bash -n` pass)*

---

## 1. Tóm Tắt Điều Hành & Bảng Theo Dõi Hợp Nhất (Unified Tracking Table)

Kiểm định tĩnh và định dạng trên toàn bộ working tree của Wave 2.1 ghi nhận kỷ luật biên dịch tốt: `rustc 1.94.1` chuẩn xác, quy tắc tĩnh kho mã (`scripts/check.ps1` bước `[1/5]..[3/5]`: UTF-8 không BOM, LF/CRLF đúng loại tệp, `cargo fmt --all -- --check`) **XANH 100%**, cô lập `unsafe` nghiêm ngặt trong `crates/mesh-sys` kèm đầy đủ `// SAFETY:` (gồm `CancelMibChangeNotify2` đồng bộ trước `Arc::from_raw` trên Windows), **0** `#[allow(clippy::...)]`, và **0** `.unwrap()`/`.expect()`/`panic!()` ngoài `#[cfg(test)]`.

Ở Vòng 1, kiểm định luồng thực thi sâu xác nhận **10/10 phát hiện từ `wave-2-1-codex.md` (`#1..#10`) đều là lỗi thật** (trong đó các mục `#3`, `#4`, `#5`, `#9` có phạm vi ảnh hưởng rộng hơn báo cáo ban đầu), đồng thời phát hiện thêm **3 lỗi mức 🟠 `High Risk`** (`HR-W21-11`, `HR-W21-12`, `HR-W21-13`) và **2 điểm 🟡 `Improvement`** (`IMP-W21-01`, `IMP-W21-02`). Sau đợt khắc phục song song của `dev-server` (`c48a391`) và `dev-client` (`19d4928`) hợp nhất tại `76f57a6`, **tái thẩm định độc lập Vòng 2 xác nhận toàn bộ 15/15 hạng mục đã đóng triệt để (`CLOSED`)**:

| Mã theo dõi | Tham chiếu gốc | Phân vùng sở hữu | Mức độ | Story / NFR | Tệp & Dòng chính | Tóm tắt vấn đề cốt lõi | Trạng thái |
|---|---|---|---|---|---|---|---|
| `BLK-W21-01` | Codex `#1` (Verified) | `dev-client` | 🔴 Blocker | `US-003`, `US-032`, `US-033` | `crates/meshd/src/supervisor.rs:1303, 1364` | `dp_handle.apply_netmap(snap).await` chờ `oneshot` trước khi `engine.run(...)` được spawn ở dòng `1364`, gây deadlock 100% khi `mesh up`, `mesh rotate-key` và khi tự khôi phục từ `netmap-cache.json`. | `CLOSED` (Vòng 2) |
| `HR-W21-02` | Codex `#2` (Verified) | `dev-server` | 🟠 High Risk | `US-031 AC5` | `crates/mesh-store/src/store.rs:548-552, 1074, 1134, 1340`, `crates/mesh-server/src/control_handlers.rs:808, 981, 1347` | `expire_node` và `populate_revoked_ram_from_db` ghi `node_id` vào `RevokedSet.nodes`, nhưng `register_node` (`--for <node>`) không gỡ `node_id` khỏi `RevokedSet.nodes` và `pending_nodes`, khiến node gia hạn khóa bị từ chối như `node_revoked`. | `CLOSED` (Vòng 2) |
| `HR-W21-03` | Codex `#3` (Verified + Expanded) | `dev-server` | 🟠 High Risk | `US-042 AC1`, `SEC-05` | `crates/mesh-server/src/control_handlers.rs:343, 1225, 1335` | `verify_signed_proof` gọi `record_auth_success(client_ip)` ngay khi mở hộp `SalsaBox` — **trước** khi kiểm tra `preauth_key` (`/v1/register`) **và trước** `find_node_by_pubkey` (`/v1/endpoints`, `/v1/netmap/stream`, `/v1/relay`), vô hiệu hóa hoàn toàn khóa IP 10 lần sai. | `CLOSED` (Vòng 2) |
| `HR-W21-04` | Codex `#4` (Verified + Expanded) | `dev-server` | 🟠 High Risk | `US-030 AC1`, `US-045`, `REL-01` | `crates/mesh-store/src/store.rs:465-486, 1044-1068`, `crates/mesh-server/src/admin_service.rs:490, 527, 560, 565, 915-928` | Thu hồi node/key đọc & ghi `redb` **trước** khi cập nhật `revoked_ram` và ngắt phiên; khi ổ đĩa lỗi thật (Dual-`EIO` hỏng cả đọc `redb`), `resolve_node_ref` trả `503` sớm và `known_pubkey` rơi về `[0u8; 32]` không chặn được pubkey trong RAM. | `CLOSED` (Vòng 2) |
| `HR-W21-05` | Codex `#5` (Verified + Expanded) | `dev-server` | 🟠 High Risk | `US-074`, `US-006`, `US-042 AC6` | `crates/mesh-server/src/listener_set.rs:279, 407`, `control_handlers.rs:1290, 1355`, `rate_limit.rs:63, 90` | Sau `migrate-endpoint --tls-mode ...`, cả `verify_signed_proof` lẫn `ClientIpExtractor` (`RateLimiter`) vẫn đọc `state.config.tls_mode` lúc boot thay vì `tls_mode` của từng listener, làm gãy xác thực TLS exporter và trích xuất IP `X-Forwarded-For`. | `CLOSED` (Vòng 2) |
| `HR-W21-06` | Codex `#6` (Verified) | `dev-server` | 🟠 High Risk | `US-045` | `crates/mesh-server/src/admin_service.rs:812-813`, `crates/mesh-store/src/backup.rs:66-67, 453-462` | `mesh server restore --min-netmap-version` gán nhầm vào điều kiện từ chối bản sao lưu cũ (`min_required_snapshot_version`) còn `min_netmap_version` gán cứng `0`, trái hợp đồng nâng sàn `netmap_version` đơn điệu sau khôi phục thảm họa. | `CLOSED` (Vòng 2) |
| `HR-W21-07` | Codex `#7` (Verified) | `dev-client` | 🟠 High Risk | `US-030 AC1`, `PERF-02` | `crates/mesh-datapath/src/engine.rs:660-664`, `stun_client.rs:366-385` | Nhánh `ApplyNetmap` trong vòng lặp đơn `DatapathEngine::run` chờ `lookup_host` STUN (tới `5 s`/hostname) **trước** khi gọi `peer_map.apply_diff`, làm nghẽn toàn bộ gói TUN/UDP và phá SLO cắt peer bị thu hồi `<= 2 s`. | `CLOSED` (Vòng 2) |
| `HR-W21-08` | Codex `#8` (Verified) | `dev-client` | 🟠 High Risk | `US-035`, `US-036`, `REL-09` | `crates/meshd/src/supervisor.rs:1629-1662, 1740-1792`, `crates/mesh-datapath/src/engine.rs:388-419, 998-1021` | Lệnh `RebindInterface` (`rebind_rx`) đua bất định với `TriggerStunProbe`/`InitiateHolePunch` (`cmd_rx`) chỉ cách nhau `yield_now()`; lỗi rebind socket chỉ `warn!` mà không retry hay chặn phát gói trên NIC cũ. | `CLOSED` (Vòng 2) |
| `HR-W21-09` | Codex `#9` (Verified + Expanded) | `dev-client` | 🟠 High Risk | `US-054`, `G4`, `PLAT-04` | `scripts/install-linux.sh:224-252, 319` | `cleanup_network_artifacts` chạy vô điều kiện khi `--uninstall`, xóa thẳng `table 51820` và `ip rule 51810` (trùng đúng bảng mặc định của `wg-quick`!), xóa `mesh0` và ghi đè `/etc/hosts` qua `mv -f` không theo `ResourceLedger`. | `CLOSED` (Vòng 2) |
| `HR-W21-10` | Codex `#10` (Verified) | `dev-client` | 🟠 High Risk | `US-041 AC2`, `SEC-01` | `crates/meshd/src/config.rs:708-773` | `redact_secret_kv_line` giới hạn cứng `for _pass in 0..8` (mỗi vòng thay tối đa 1 khóa do `break`), làm lộ nguyên văn mọi bí mật thứ 9 trở đi trên cùng một dòng log JSON dài. | `CLOSED` (Vòng 2) |
| `HR-W21-11` | Critic Deep Audit | `dev-server` | 🟠 High Risk | `US-074`, `US-006`, `US-011`, `SEC-04`, `SEC-05` | `crates/mesh-server/src/listener_set.rs:235-353`, `admin_service.rs:308, 313, 863` | `migrate-endpoint` bỏ qua kiểm tra bảo mật `trusted_proxies` / `control_bind_ip` (có thể mở HTTP trần trên `0.0.0.0` khi chuyển sang `reverse_proxy`), không cấp lại SAN chứng chỉ khi đổi `--host`, làm mất `--host` ở lần migrate kế tiếp và để `preauthkey create` / `rotate-tls-key` đọc cấu hình cũ lúc boot. | `CLOSED` (Vòng 2) |
| `HR-W21-12` | Critic Deep Audit | `dev-server` | 🟠 High Risk | `US-029`, `US-030 AC1`, `US-045`, `REL-01` | `crates/mesh-server/src/netmap_hub.rs:269-272`, `admin_service.rs:943`, `alert_worker.rs:340-349`, `crates/mesh-store/src/store.rs:849-855` | Khi `redb` suy giảm (`EmergencySlot`/`RamOnly`), `NetmapHub::build_snapshot` và `node list/inspect` không lọc `is_node_revoked_ram`, tiếp tục phát tán node đã bị thu hồi như `Active`; khi `redb` hồi phục và compact xong lại vứt bỏ `netmap_version` (`let _ = ver;`) không broadcast cho đội node. | `CLOSED` (Vòng 2) |
| `HR-W21-13` | Critic Deep Audit | `dev-client` | 🟠 High Risk | `US-031 AC4` | `crates/meshd/src/control_loop.rs:146, 173`, `supervisor.rs:709-715, 1337` | Gia hạn ân hạn 24 giờ khi khóa cục bộ hết hạn lúc offline (`US-031 AC4`) bị bỏ rỗng trên thực tế: `DaemonRuntimeState::new` truyền cứng `local_key_expires_at_ms = None`, mất `key_expires_at_ms` sau khi khởi động lại daemon và không thu hồi phiên cục bộ khi quá hạn `> 24h` offline. | `CLOSED` (Vòng 2) |
| `IMP-W21-01` | Critic Deep Audit | `dev-server` | 🟡 Improvement | `US-045`, `coding-standards.md` §3 | `crates/mesh-store/src/store.rs:850, 860-895` | Xóa `let _ = ver;` trong `try_compact_emergency_revocations` (trả về `Option<u64>` phục vụ broadcast) và bổ sung chế độ giả lập lỗi đọc `redb` trong `inject_redb_failure` để kiểm chứng trọn vẹn kịch bản Dual-`EIO`. | `CLOSED` (Vòng 2) |
| `IMP-W21-02` | Critic Deep Audit | `dev-client` | 🟡 Improvement | `US-023 AC4` | `crates/meshd/src/ping_probe.rs:126-159, 404` | Khi cả STUN, Control TCP và Relay TCP (khác cổng) đều bị chặn đen hoàn toàn, tổng thời gian tuần tự của `execute_netcheck` có thể lên tới `~5.6–6.5 s`; cần gom deadline chung `<= 4.5 s` (hoặc `tokio::join!`) để luôn đạt ngưỡng `<= 5 s`. | `CLOSED` (Vòng 2) |

---

## 2. Chi Tiết Các Hạng Mục Cần Sửa Theo 2 Phân Vùng Sở Hữu Không Chồng Lấn

### 2.1. Phân Vùng Server (`dev-server`)
> **Phạm vi tệp được phép chạm**: `crates/mesh-store/**`, `crates/mesh-server/**`, `crates/mesh/src/admin_cmds.rs`, `deploy/systemd/mesh-server.service`, `deploy/reverse-proxy/**`, `scripts/install-server.sh`.

#### 🟠 `[HR-W21-02]` (Codex `#2`) Cờ thu hồi theo `NodeId` làm hỏng vĩnh viễn luồng tái ghi danh `--for <node>` sau khi hết hạn khóa (`US-031 AC5`)
- **Vị trí**:
  - [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L548-L552), [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L1074-L1138), [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L1335-L1346)
  - [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L808-L815), [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L980-L986), [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L1345-L1352)
- **Nguyên nhân gốc**:
  - `expire_node` (`store.rs:1074`) dùng chung `revoke_or_expire_node(..., NodeStatus::KeyExpired)` và đẩy cả `node_id` lẫn `old_pubkey` vào `RevokedSet`; tương tự lúc khởi động lại, `populate_revoked_ram_from_db` (`store.rs:1340`) đẩy mọi bản ghi `rec.status != NodeStatus::Active` (gồm cả `KeyExpired`) vào `RevokedSet.nodes`.
  - Khi quản trị viên cấp pre-auth key mới bằng `--for <node>` để gia hạn (`US-031 AC5`), `register_node` (`store.rs:548-552`) đặt lại `NodeStatus::Active` trong `redb` và chỉ giữ `old_pubkey` trong `RevokedSet.pubkeys`, nhưng **không gỡ `node_id` khỏi `RevokedSet.nodes`** (và cũng không dọn mục `EmergencyNodeReason::Expired` tương ứng trong `emergency_state.pending_nodes`).
  - Mọi nhánh hậu ghi danh (`update_node_endpoints`, `/v1/netmap/stream`, `/v1/relay`) đều chặn `is_node_revoked_ram(node.node_id)`.
- **Hệ quả**: Node vừa gia hạn khóa hợp lệ nhận ngay lỗi `node_revoked`, tự dừng reconnect vĩnh viễn (`US-034`), mất hoàn toàn kết nối cho tới khi khởi động lại `mesh-server`.
- **Hướng khắc phục (`crates/mesh-store/src/{revoked_ram.rs,store.rs}`)**:
  1. Bổ sung phương thức gỡ `node_id` khỏi `RevokedSet.nodes` (nhưng **giữ nguyên** `old_pubkey` đã hết hạn/xoay vòng trong `RevokedSet.pubkeys`) và dọn mọi mục `EmergencyNodeReason::Expired` của `node_id` trong `emergency_state.pending_nodes` khi `register_node` kích hoạt lại thành công một node `KeyExpired` (theo `--for <node>`).
  2. Tách biệt rõ ngữ nghĩa trong `populate_revoked_ram_from_db`: `NodeStatus::Revoked` khóa cả `node_id` + `pubkey`; `NodeStatus::KeyExpired` vẫn chặn kết nối bằng `pubkey` cũ (và `node_id` cho tới khi được kích hoạt lại hợp lệ qua `--for <node>`).
  3. Viết integration test đầy đủ: `expire_node` -> `preauthkey create --for <node>` -> `register_node` -> `update_node_endpoints` + `authenticate_active_node` xanh 100% trong khi `old_pubkey` vẫn bị chặn.

---

#### 🟠 `[HR-W21-03]` (Codex `#3` + Mở rộng) `verify_signed_proof` xóa bộ đếm lỗi xác thực trước khi kiểm tra `preauth_key` và trạng thái đăng ký của node (`US-042 AC1`, `SEC-05`)
- **Vị trí**: [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L343-L355), [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L1220-L1228), [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L1330-L1352)
- **Nguyên nhân gốc**:
  - `verify_signed_proof` gọi `state.rate_limiter.record_auth_success(client_ip)` ở dòng `1225` ngay khi giải mã thành công hộp `SalsaBox` với cặp khóa X25519 do chính client tự sinh.
  - Phía sau bước đó, `handle_register_node` mới kiểm tra `preauth_key` (`dòng 343`), còn `authenticate_active_node` (dùng cho `/v1/endpoints`, `/v1/disco/call-me-maybe`, `/v1/netmap/stream`, `/v1/relay`) mới kiểm tra `find_node_by_pubkey` và trạng thái thu hồi/hết hạn (`dòng 1335-1350`).
- **Hệ quả**: Kẻ tấn công tự sinh cặp khóa X25519 bất kỳ rồi vét cạn `mpk_...` trên `/v1/register` (hoặc dò quét các endpoint `/v1/endpoints`, `/v1/relay` bằng khóa lạ/khóa đã bị thu hồi) sẽ liên tục đưa `failures_in_window` về `0 -> 1 -> 0 -> 1`, **không bao giờ kích hoạt khóa IP 15 phút sau 10 lần thất bại**.
- **Hướng khắc phục (`crates/mesh-server/src/control_handlers.rs`)**:
  - Xóa hoàn toàn lời gọi `record_auth_success` bên trong `verify_signed_proof`.
  - Chỉ gọi `state.rate_limiter.record_auth_success(client_ip)` ở **cuối** luồng xác thực sau khi mọi điều kiện ủy quyền đã thành công (`register_node` thành công hoặc `authenticate_active_node` xác nhận `NodeRecord` đang `Active` và không nằm trong `revoked_ram`). Bổ sung test gửi 10 yêu cầu có challenge proof hợp lệ nhưng sai `mpk_...` (và 10 yêu cầu với `node_pubkey` chưa đăng ký) phải bị trả `429` ở lần thứ 11.

---

#### 🟠 `[HR-W21-04]` (Codex `#4` + Mở rộng Dual-`EIO`) Thu hồi node/key chạm `redb` trước khi chặn RAM & ngắt phiên, sập `503` khi lỗi đọc `redb` trong kịch bản Dual-`EIO` (`US-030 AC1`, `US-045`, `REL-01`)
- **Vị trí**:
  - [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L465-L486), [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L1044-L1095)
  - [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L490-L535), [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L560-L575), [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L915-L928)
- **Nguyên nhân gốc**:
  1. Khi admin gọi `mesh node revoke <name-or-id>`, `admin_service.rs:490` gọi `resolve_node_ref` đọc thẳng bảng `nodes` trong `redb`, sau đó `store.revoke_or_expire_node` (`store.rs:1044-1068`) lại đọc và mở transaction ghi `redb` đồng bộ **trước** khi chèn vào `revoked_ram` (`dòng 1074`) và **trước** khi `admin_service.rs:527` gọi `netmap_hub.disconnect_node` / `relay_hub.disconnect_node`. `revoke_preauth_key` (`store.rs:465-486`) cũng ghi `redb` trước rồi mới chèn `revoked_ram.insert_key_hash`.
  2. Nghiêm trọng hơn: hàm giả lập lỗi `inject_redb_failure` hiện tại chỉ chặn nhánh **ghi** `redb`, che khuất thực tế rằng khi đĩa VPS bị `EIO` thật, cả `db.begin_read()` cũng thất bại hoặc treo I/O kernel: lúc đó `resolve_node_ref` trả lỗi `503` ngay từ vòng gửi xe (chưa kịp tới `revoke_node`), còn `store.rs:1044-1049` fallback `known_pubkey = PublicKey::from_bytes([0_u8; 32])` khiến `revoked_ram.pubkeys` hoàn toàn không chặn được khóa công khai thật của node trên Blind Relay!
- **Hệ quả**: Vi phạm trực tiếp bất biến thiết kế `database-design.md` §5.3 & `US-030 AC1` / `US-045` (thu hồi RAM + cắt phiên `<= 100 ms` bất chấp `ENOSPC`/Dual-`EIO`).
- **Hướng khắc phục (`crates/mesh-store/src/store.rs`, `crates/mesh-server/src/admin_service.rs`)**:
  1. Duy trì chỉ mục danh bạ gọn nhẹ trong RAM bên trong `ControlStore` (`HashMap<NodeId, (NodeName, PublicKey)>` + `HashMap<NodeName, NodeId>`) được nạp lúc `open` và cập nhật đồng bộ khi `register_node`/`delete_node`.
  2. Trong `handle_revoke_node` / `handle_delete_node` / `handle_revoke_preauth_key`: tra cứu danh bạ RAM -> ghi ngay `node_id` + `real_pubkey` (hoặc `key_hash`) vào `revoked_ram` -> ngắt tức thì phiên `netmap_hub` & `relay_hub` (`< 100 ms`) -> **sau đó** mới ghi bền vững xuống `redb` / `EmergencySlot`.

---

#### 🟠 `[HR-W21-05]` (Codex `#5` + Mở rộng `RateLimiter`) Lệch `tls_mode` giữa listener mới và `state.config` sau `migrate-endpoint` làm gãy xác thực TLS exporter và `X-Forwarded-For` (`US-074`, `US-006`, `US-042 AC6`)
- **Vị trí**:
  - [listener_set.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/listener_set.rs#L279-L295), [listener_set.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/listener_set.rs#L407-L445)
  - [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L1290-L1312), [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L1353-L1362)
  - [rate_limit.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/rate_limit.rs#L58-L98)
- **Nguyên nhân gốc**:
  - `ListenerSet::migrate_endpoint` khởi chạy listener mới theo `target_tls_mode` (ví dụ `ReverseProxy` gán `tls_exporter_b64: None`), nhưng `verify_signed_proof` (`control_handlers.rs:1290`) và `ClientIpExtractor` trong `RateLimiter` (`rate_limit.rs:63, 90`) vẫn đọc `state.config.tls_mode` bất biến từ lúc khởi động.
- **Hệ quả**:
  - Di chuyển sống từ `ip_pinned`/`acme` sang `reverse_proxy`: 100% node chuyển sang listener mới bị từ chối xác thực vì thiếu TLS exporter.
  - Di chuyển ngược từ `reverse_proxy` sang `ip_pinned`/`acme`: listener TLS mới lại chấp nhận cả proof có `tls_exporter_b64: None` (hạ cấp chống MITM `SEC-04`), đồng thời `ClientIpExtractor` vẫn tin header `X-Forwarded-For` hoặc ngừng đọc `X-Forwarded-For` sai chế độ (`US-042 AC6`).
- **Hướng khắc phục (`crates/mesh-server/src/{listener_set.rs,control_handlers.rs,rate_limit.rs}`)**:
  - Đính kèm `listener_tls_mode: TlsMode` trực tiếp vào `ConnectionTlsContext` của từng kết nối nhận từ listener; dùng `conn_ctx.listener_tls_mode` trong cả `verify_signed_proof` lẫn hàm trích xuất IP client của `RateLimiter`.

---

#### 🟠 `[HR-W21-06]` (Codex `#6`) Cờ `mesh server restore --min-netmap-version` bị nối nhầm thành bộ lọc từ chối bản sao lưu cũ thay vì nâng sàn `netmap_version` (`US-045`)
- **Vị trí**:
  - [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L808-L820)
  - [backup.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/backup.rs#L62-L72), [backup.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/backup.rs#L453-L465)
- **Nguyên nhân gốc**: `handle_restore_backup` ánh xạ `req.min_netmap_version` vào `RestoreOptions.min_required_snapshot_version` (từ chối khôi phục nếu `snapshot_version < min_req`) và gán cứng `min_netmap_version: 0`.
- **Hệ quả**: Khi khôi phục thảm họa từ một bản backup cũ hơn trạng thái hiện tại nhưng quản trị viên muốn ép `netmap_version` nhảy vọt vượt qua cache cũ của đội node (`max(snapshot + 1_000_000, min_netmap_version)` theo `database-design.md` §5.2 & `US-045`), lệnh `restore` lại báo lỗi `InvalidArgument` từ chối khôi phục.
- **Hướng khắc phục (`crates/mesh-server/src/admin_service.rs`, `crates/mesh-store/src/backup.rs`)**:
  - Ánh xạ `req.min_netmap_version.unwrap_or(0)` vào đúng `RestoreOptions.min_netmap_version` để nâng sàn bộ đếm `netmap_version` sau khôi phục; để `min_required_snapshot_version: None` (trừ khi có cờ kiểm tra tối thiểu riêng biệt) và viết unit test khôi phục snapshot `version = 50` với `--min-netmap-version 5_000_000` sinh ra `post_restore_version >= 5_000_000`.

---

#### 🟠 `[HR-W21-11]` (Phát hiện mới) `ListenerSet::migrate_endpoint` bỏ qua kiểm tra an toàn TLS (`SEC-04`/`SEC-05`), làm mất `--host` đã di chuyển và lệch cấu hình với Admin API (`US-074`, `US-006`, `US-011`)
- **Vị trí**:
  - [listener_set.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/listener_set.rs#L235-L353)
  - [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L308-L315), [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L860-L875)
- **Nguyên nhân gốc**:
  1. **Mở cổng HTTP trần không mã hóa trên `0.0.0.0`**: Lúc khởi động ở chế độ mặc định `IpPinned`, `control_bind_ip = "0.0.0.0"` và `trusted_proxies = []`. Khi gọi `migrate-endpoint --tls-mode reverse_proxy --tcp-port <p>`, `listener_set.rs:254` không kiểm tra `!trusted_proxies.is_empty()` (`SEC-05` — vốn bị chặn lúc boot ở `config.rs:229`) và không ép bind loopback, dẫn tới việc mở listener **HTTP thuần không TLS** ngay trên `0.0.0.0:<p>`! Tương tự, chuyển sang `acme` không gọi `validate_acme_settings`, và đổi `--host <new-ip>` ở chế độ `ip_pinned` không cấp lại chứng chỉ TLS chứa SAN `<new-ip>` (`reissue_cert_same_key`).
  2. **Mất `public_host` ở lần migrate tiếp theo**: `ActivePortState` không lưu `public_host` hiện hành; dòng `315` luôn lấy `req.new_public_host.unwrap_or(self.config.public_host)`, nên lần gọi kế tiếp chỉ đổi `--tcp-port` sẽ âm thầm quay ngược `public_host` về giá trị cũ lúc boot.
  3. **Admin API đọc cấu hình chết lúc boot**: `handle_create_preauth_key` (`admin_service.rs:308, 313` — sinh câu lệnh `mesh up --server ...`), `handle_rotate_tls_key` (`dòng 863`) và `handle_server_status` vẫn đọc `state.config` lúc khởi động thay vì trạng thái sống của `ListenerSet`.
- **Hướng khắc phục (`crates/mesh-server/src/{listener_set.rs,admin_service.rs}`)**:
  1. Trong `migrate_endpoint`, kiểm tra đầy đủ điều kiện an toàn của `target_tls_mode`: với `ReverseProxy` bắt buộc `!trusted_proxies.is_empty()` và chỉ cho phép bind trên loopback (hoặc từ chối fail-closed nếu `control_bind_ip` không phải loopback); với `Acme` kiểm tra cấu hình `acme.domain`; với `IpPinned` khi đổi `--host` tự động gọi `reissue_cert_same_key` cập nhật SAN trước khi mở listener mới.
  2. Lưu `active_public_host` + `active_tls_mode` trong `ActivePortState` của `ListenerSet`, xuất snapshot trạng thái sống để `handle_create_preauth_key`, `handle_rotate_tls_key` và `handle_server_status` luôn dùng đúng endpoint & `tls_mode` hiện hành.

---

#### 🟠 `[HR-W21-12]` (Phát hiện mới) Chế độ suy giảm `redb` làm rò rỉ node đã thu hồi vào `NetmapSnapshot` / `node list`, và quá trình hồi phục compact không phát bản tin cắt peer (`US-029`, `US-030 AC1`, `US-045`, `REL-01`)
- **Vị trí**:
  - [netmap_hub.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/netmap_hub.rs#L269-L275)
  - [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L943-L962)
  - [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L849-L855)
  - [alert_worker.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/alert_worker.rs#L340-L349)
- **Nguyên nhân gốc**:
  1. Khi `redb` gặp `ENOSPC`/`EIO` (lệnh thu hồi ghi vào `EmergencySlot` hoặc `RamOnly`, trong khi bản ghi trên `redb` vẫn mang `NodeStatus::Active`), `NetmapHub::build_snapshot` (`netmap_hub.rs:269`) và `node_record_to_dto` (`admin_service.rs:943`) chỉ kiểm tra `rec.status` đọc từ `redb` mà **không đối chiếu `self.store.is_node_revoked_ram(rec.node_id)`**. Do đó mọi peer mới kết nối hoặc tải lại netmap vẫn nhận node đã bị thu hồi như một peer `Active` hợp lệ!
  2. Khi ổ đĩa hồi phục và `AlertWorker` gọi `try_compact_emergency_revocations()` (`store.rs:849-855`), hàm cấp phát `ver = self.versions.allocate_next(...)` rồi bỏ đi bằng `let _ = ver;`, và `alert_worker.rs:341` không gọi `ctx.netmap_hub.broadcast_snapshot(ver)`. Các peer đang mở kết nối P2P trực tiếp với node bị thu hồi không bao giờ nhận được bản cập nhật `NetmapDelta` để xóa phiên WireGuard `Tunn`!
- **Hướng khắc phục (`crates/mesh-server/src/{netmap_hub.rs,admin_service.rs,alert_worker.rs}`, `crates/mesh-store/src/store.rs`)**:
  1. Trong `NetmapHub::build_snapshot`, loại bỏ mọi bản ghi có `self.store.is_node_revoked_ram(rec.node_id)` (hoặc `is_pubkey_revoked_ram(&rec.node_pubkey)`); trong `admin_service::node_record_to_dto`, hiển thị trạng thái hiệu lực `Revoked` nếu cờ RAM đã bật.
  2. Đổi chữ ký `try_compact_emergency_revocations` trả về `AppResult<Option<u64>>` (phiên bản `netmap_version` mới khi `compacted > 0`), và tại `alert_worker.rs` gọi `ctx.netmap_hub.broadcast_snapshot(ver)` ngay khi compact thành công (cũng như phát ngay `broadcast_snapshot` từ bộ lọc RAM tại thời điểm thu hồi trong `admin_service.rs`).

---

#### 🟡 `[IMP-W21-01]` (Cải tiến `dev-server`) Xóa `let _ = ver;` và mở rộng `inject_redb_failure` kiểm thử cả lỗi đọc `redb` (`coding-standards.md` §3, `US-045`)
- **Vị trí**: [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L850), [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L860-L895)
- **Khuyến nghị**: Kết hợp trực tiếp khi sửa `HR-W21-04` và `HR-W21-12`: loại bỏ hoàn toàn `let _ = ver;` (tuân thủ quy tắc cấm `let _ = f()`) và thêm cờ giả lập lỗi đọc `redb` trong `#[cfg(test)]` / hook kiểm thử của `ControlStore` để bài test Dual-`EIO` chứng minh được thu hồi `< 100 ms` ngay cả khi cả đọc lẫn ghi `redb` đều trả `EIO`.

---

### 2.2. Phân Vùng Client & OS (`dev-client`)
> **Phạm vi tệp được phép chạm**: `crates/mesh-datapath/**`, `crates/meshd/**`, `crates/mesh/src/{client_cmds.rs,output.rs}`, `crates/mesh-net/**`, `crates/mesh-sys/**`, `scripts/install-{linux.sh,macos.sh,windows.ps1}`, `deploy/linux-desktop/**`, `deploy/launchd/**`, `deploy/systemd/meshd.service`.

#### 🔴 `[BLK-W21-01]` (Codex `#1`) Deadlock 100% khi khởi tạo phiên do `dp_handle.apply_netmap().await` chạy trước khi spawn `DatapathEngine::run` (`US-003`, `US-032`, `US-033`)
- **Vị trí**: [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1296-L1306), [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1361-L1372)
- **Nguyên nhân gốc**:
  - Trong `DaemonSupervisor::start_enrolled_session_with_identity`, khi có `initial_netmap` (mọi lần chạy `mesh up` ghi danh mới, mọi lần `mesh rotate-key`, và mọi lần daemon tự khởi động lại có `netmap-cache.json` hợp lệ), dòng `1303` gọi `dp_handle.apply_netmap(snap.clone()).await`.
  - `DatapathHandle::apply_netmap` gửi `DatapathCommand::ApplyNetmap { snapshot, reply }` vào `cmd_tx` rồi chờ `reply_rx.await` (`oneshot`), nhưng vòng lặp tiêu thụ `cmd_rx` (`engine.run(...)`) lại nằm mãi ở dòng `1364` chưa hề được `tracker.spawn`!
- **Hệ quả**: Toàn bộ luồng `mesh up`, `mesh rotate-key` và tự phục hồi offline (`US-033`) treo cứng cho tới khi hết hạn `IPC_COMMAND_TIMEOUT = 30 s` rồi báo lỗi timeout trên mọi hệ điều hành.
- **Hướng khắc phục (`crates/meshd/src/supervisor.rs`)**:
  - `tracker.spawn` tác vụ `engine.run(...)` **trước** khi gọi `dp_handle.apply_netmap(snap.clone()).await` (hoặc nạp `initial_netmap` đồng bộ vào `DatapathEngine` trước khi tách `run`), kèm bài test tích hợp chạy `execute_up` và auto-resume từ `netmap-cache.json` phải hoàn tất trong `< 1 s`.

---

#### 🟠 `[HR-W21-07]` (Codex `#7`) Phân giải DNS STUN chặn đứng vòng lặp đơn `DatapathEngine::run` tới `5 s`, phá vỡ SLO thu hồi peer `<= 2 s` (`US-030 AC1`, `PERF-02`)
- **Vị trí**:
  - [engine.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/engine.rs#L658-L675)
  - [stun_client.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/stun_client.rs#L366-L388)
- **Nguyên nhân gốc**: Trong vòng `tokio::select!` đơn luồng xử lý cả gói TUN lẫn UDP của `DatapathEngine::run`, nhánh `DatapathCommand::ApplyNetmap` gọi `self.stun_client.sync_and_resolve_relay_map(&snapshot.relay_map).await` (`lookup_host` với timeout `5 s` cho từng STUN hostname) **trước** khi gọi `self.peer_map.apply_diff(&snapshot)`.
- **Hệ quả**: Trên mạng có DNS chậm/mất gói hoặc captive portal, việc gỡ bỏ khóa `Tunn` của peer vừa bị thu hồi bị trễ `>= 5 s` (vi phạm `US-030 AC1` `<= 2 s`), đồng thời làm đóng băng toàn bộ lưu lượng dữ liệu của các peer đang hoạt động.
- **Hướng khắc phục (`crates/mesh-datapath/src/{engine.rs,stun_client.rs}`)**:
  1. Thực thi đồng bộ `self.peer_map.apply_diff(&snapshot)` + `self.disco.remove_peers(&diff.removed)` **ngay lập tức** ở đầu nhánh `ApplyNetmap` (`< 1 ms`) và trả `reply` ngay sau khi cập nhật bảng peer.
  2. Tách việc phân giải DNS `stun_udp_endpoints` sang tác vụ nền có `CancellationToken` (hoặc phân giải sẵn ở `ControlLoop` trước khi đẩy địa chỉ `SocketAddr` đã phân giải vào `DatapathEngine`), tuyệt đối không `.await` DNS bên trong vòng lặp gói tin.

---

#### 🟠 `[HR-W21-08]` (Codex `#8`) Đua kênh khi Roaming (`rebind_rx` vs `cmd_rx`) và nuốt lỗi `SocketRebinder`, có nguy cơ kẹt socket trên card mạng cũ (`US-035`, `US-036`, `REL-09`)
- **Vị trí**:
  - [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1629-L1662), [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1740-L1792)
  - [engine.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/engine.rs#L388-L419), [engine.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/engine.rs#L998-L1021)
- **Nguyên nhân gốc**:
  1. Khi đổi mạng (Wi-Fi <-> Ethernet / thức dậy sau sleep), `supervisor.rs` gửi `RebindCommand::RebindInterface` qua `rebind_tx`, chỉ gọi `tokio::task::yield_now().await`, rồi lập tức gửi `TriggerStunProbe` và `InitiateHolePunch` qua `cmd_tx`. Vì `tokio::select!` trong `engine.rs` không đặt thứ tự ưu tiên hoặc chờ xác nhận hoàn tất, STUN probe và gói đấm lỗ có thể bắn ra trên **socket/NIC cũ** trước khi `rebind_rx` được xử lý.
  2. Trong `engine.rs:1005-1019`, nếu `SocketRebinder::apply_command` thất bại (ví dụ NIC mới trên macOS/Windows vừa lên nhưng kernel từ chối `IP_BOUND_IF`/`IP_UNICAST_IF` tạm thời), lỗi chỉ được `warn!` rồi bị bỏ qua hoàn toàn: không báo ngược cho `RoamingLoop` để retry và không ngăn phát gói ra giao diện cũ.
- **Hướng khắc phục (`crates/mesh-datapath/src/engine.rs`, `crates/meshd/src/{supervisor.rs,roaming_loop.rs}`)**:
  1. Hợp nhất lệnh rebind có `oneshot::Sender<AppResult<u16>>` (ví dụ `DatapathCommand::RebindUnderlay { if_index, reply }`) hoặc gắn `oneshot` vào `RebindCommand` để `supervisor.rs` **chờ rebind thành công** rồi mới thu thập ứng viên mới, chạy `TriggerStunProbe` và `InitiateHolePunch`.
  2. Nếu rebind thất bại, trả `Err` về `RoamingLoop` để xếp lịch thử lại theo backoff ngắn (`500 ms -> 4 s`, có `CancellationToken`) thay vì bỏ mặc socket ghim chết ở NIC cũ.

---

#### 🟠 `[HR-W21-09]` (Codex `#9` + Mở rộng va chạm `wg-quick` & Symlink) `scripts/install-linux.sh --uninstall` xóa mù bảng định tuyến `51820` và sửa `/etc/hosts` không qua `ResourceLedger` (`G4`, `US-054`, `PLAT-04`)
- **Vị trí**: [install-linux.sh](file:///D:/Project/Idea/mesh-vpn/scripts/install-linux.sh#L224-L252), [install-linux.sh](file:///D:/Project/Idea/mesh-vpn/scripts/install-linux.sh#L304-L331)
- **Nguyên nhân gốc**:
  1. Hàm `cleanup_network_artifacts` (`dòng 241-252`, được gọi vô điều kiện ở dòng `319` cho mọi lệnh `--uninstall` kể cả không có `--purge`) chạy thẳng `ip rule del priority 51810 table main suppress_prefixlength 0` và `ip route flush table 51820` mà không kiểm tra `/var/lib/meshd/ledger.json`. Trên Linux, **`51820` và `suppress_prefixlength 0` chính là bảng định tuyến mặc định của WireGuard `wg-quick` (`wg0`)**! Nếu người dùng đang chạy `wg-quick` song song mà `meshd` chưa từng chiếm hữu `table 51820` trong `ledger.json`, việc gỡ cài đặt `mesh` sẽ đánh sập ngay đường hầm WireGuard hiện hữu của máy chủ/desktop (vi phạm nghiêm trọng quy tắc bất khả xâm phạm `G4`).
  2. `remove_hosts_block_in_place` (`dòng 224-239`) dùng `mktemp` + `mv -f` (làm đứt symlink `/etc/hosts` trên NixOS/ostree hoặc lỗi `EXDEV` trên bind-mount, dùng cờ không chuẩn POSIX `chmod --reference`, và nếu thiếu dòng `# END mesh managed hosts` sẽ xóa sạch phần còn lại của `/etc/hosts`), trong khi `${CLI_BIN} cleanup` ở dòng `306` vốn đã dọn an toàn theo đúng `ResourceLedger`.
- **Hướng khắc phục (`scripts/install-linux.sh`)**:
  1. Trong `do_uninstall`: dừng `meshd.service` trước (để daemon thực hiện graceful cleanup theo `ledger.json` trong `<= 5 s`), sau đó gọi `"${CLI_BIN}" cleanup` để thu dọn phần tài nguyên còn sót **chỉ khi được ghi nhận trong `/var/lib/meshd/ledger.json`**.
  2. Tuyệt đối không chạy `ip route flush table 51820`, `ip rule del priority 51810 ...`, `ip link del dev mesh0`, hay sửa `/etc/hosts` nếu không có xác nhận quyền sở hữu tương ứng trong `ledger.json` (chỉ gỡ bảng `nftables inet mesh_vpn` / chuỗi riêng `iptables MESH_VPN` do chính `install-linux.sh` tạo và gắn nhãn riêng).

---

#### 🟠 `[HR-W21-10]` (Codex `#10`) Bộ lọc che dấu bí mật `bugreport` giới hạn 8 lần thay thế trên mỗi dòng, làm lộ bí mật thứ 9+ (`US-041 AC2`, `SEC-01`)
- **Vị trí**: [config.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/config.rs#L708-L773)
- **Nguyên nhân gốc**: `redact_secret_kv_line` lặp cứng `for _pass in 0..8` và thoát vòng quét ký tự ngay sau lần thay thế đầu tiên của mỗi lượt (`break` tại dòng `763, 765`). Với một dòng JSON hoặc dòng nối ghép chứa từ 9 trường khóa nhạy cảm trở lên (`private_key`, `preauth_key`, `secret`, `token`, ...), toàn bộ các trường từ vị trí thứ 9 trở đi bị giữ nguyên văn trong tệp `.tar`.
- **Hướng khắc phục (`crates/meshd/src/config.rs`)**:
  - Viết lại `redact_secret_kv_line` quét tiến một lượt theo con trỏ vị trí `cursor` từ đầu đến cuối chuỗi (`while cursor < current.len()`, luôn tịnh tiến `cursor` vượt qua đoạn `[REDACTED]` vừa ghi để đảm bảo độ phức tạp tuyến tính $O(N)$ và không bao giờ lặp vô hạn), che 100% số lượng trường bí mật bất kỳ trên cùng một dòng. Bổ sung unit test với 15 canary secrets trên cùng một dòng JSON dài.

---

#### 🟠 `[HR-W21-13]` (Phát hiện mới) Cơ chế ân hạn 24 giờ khi khóa cục bộ hết hạn lúc offline (`US-031 AC4`) bị truyền cứng `None` trên đường chạy thật
- **Vị trí**:
  - [control_loop.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/control_loop.rs#L140-L152), [control_loop.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/control_loop.rs#L170-L182)
  - [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L709-L716), [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1335-L1342)
  - [netmap_cache.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/netmap_cache.rs#L106-L118)
- **Nguyên nhân gốc**:
  - Hàm `NetmapCacheFile::snapshot_for_offline_recovery` đã được viết tham số `local_key_expires_at_ms: Option<u64>`, nhưng trên đường chạy production tại `DaemonRuntimeState::new` (`control_loop.rs:146`), tham số này **luôn bị truyền cứng là `None`**, và `key_expires_at_ms` trong `DaemonRuntimeData` cũng khởi tạo `None` (`dòng 173`).
  - Tại `supervisor.rs:1337`, `g.key_expires_at_ms` chỉ nhận giá trị từ `initial_reg` (tức chỉ có mặt ở đúng phiên `mesh up` đầu tiên, bằng `None` ở mọi lần khởi động lại daemon), đồng thời `ControlLoop::apply_netmap_update` không trích xuất `key_expires_at_ms` của node cục bộ từ `snapshot.peers` (dù server có gửi kèm bản ghi của chính node đó trong `snapshot.peers`) và cũng không có kiểm tra định kỳ để hạ đường hầm khi đang offline mà `now_ms > key_expires_at_ms + 24h`.
- **Hệ quả**: Nếu một node có khóa đã hết hạn hơn 24 giờ trong lúc mất kết nối tới Control Server (hoặc bị chặn tường lửa tới Control), `meshd` vẫn giữ nguyên đường hầm WireGuard vô thời hạn qua cả các lần khởi động lại máy, vi phạm trực tiếp `US-031 AC4`.
- **Hướng khắc phục (`crates/meshd/src/{netmap_cache.rs,control_loop.rs,supervisor.rs}` — không cần chạm `mesh-proto`)**:
  1. Trích xuất `local_key_expires_at_ms` của chính `local_node_id` từ `cached.netmap.peers` (hoặc lưu thêm trường `#[serde(default)] local_key_expires_at_ms: Option<u64>` trong `NetmapCacheFile` / `BootstrapConfig` để giữ nguyên giá trị từ `RegisterNodeResponse` và cập nhật mỗi lần nhận `NetmapSnapshot`).
  2. Truyền đúng `local_key_expires_at_ms` vào `snapshot_for_offline_recovery` lúc boot, hiển thị chính xác trong `mesh status`, và kiểm tra định kỳ trong `ControlLoop` khi đang offline: ngay khi vượt quá `key_expires_at_ms + 86_400_000 ms`, chuyển trạng thái sang hết hạn khóa và gọi `Supervisor` dọn sạch TUN/route/`hosts`/peers giống luồng `NodeKeyExpired`.

---

#### 🟡 `[IMP-W21-02]` (Cải tiến `dev-client`) Gom ngân sách thời gian tổng của `mesh netcheck` để đảm bảo cứng ngưỡng `<= 5 s` khi mất mạng hoàn toàn (`US-023 AC4`)
- **Vị trí**: [ping_probe.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/ping_probe.rs#L126-L159), [ping_probe.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/ping_probe.rs#L404-L429)
- **Khuyến nghị**: Hiện tại khi đường hầm dừng và mạng bị cắt đen hoàn toàn (UDP STUN timeout `1.5 s` + Control TCP timeout `2.5 s` + Relay TCP khác địa chỉ timeout thêm `2.5 s`), tổng thời gian chạy tuần tự có thể chạm `6.5 s` (vượt ngưỡng `US-023 AC4` `<= 5 s`). Nên chạy song song probe STUN UDP và các probe TCP bằng `tokio::join!` với tổng hạn chót chung `<= 4.0 s`.

---

## 3. Đối Chiếu Ma Trận Bảo Mật (`SEC`), Chịu Lỗi (`REL`), An Toàn Máy Thật (`G4`) & Chuẩn Rust `1.94.1` (Sau Vòng 2)

| Nhóm kiểm định | Kết quả Vòng 1 | Kết quả Vòng 2 | Ghi chú bằng chứng xác minh |
|---|---|---|---|
| **Rust `1.94.1`, Format, UTF-8 không BOM, 0 `#[allow]`, 0 `.unwrap()`/`.expect()`/`panic!()`** | ⚠️ Đạt 99% (`let _ = ver;`) | ✅ **Đạt 100%** | `scripts/check.ps1 -Cross` xanh toàn bộ 5 cổng; `store.rs:1069-1083` trả `AppResult<Option<u64>>`, 0 `let _ = f()`, 0 `#[allow]` trên toàn workspace. |
| **Cô lập FFI `unsafe` & An toàn bộ nhớ (`mesh-sys`)** | ✅ Đạt 100% | ✅ **Đạt 100%** | Chỉ `mesh-sys` dùng `unsafe`, đầy đủ `// SAFETY:`; `CancelMibChangeNotify2` đồng bộ trước `Arc::from_raw`; `freeifaddrs` giải phóng đúng 1 lần. |
| **Concurrency, Lock qua `.await` & Graceful Shutdown `<= 5 s`** | 🔴 Lỗi `BLK-W21-01`, `HR-W21-07`, `HR-W21-08` | ✅ **Đạt 100%** | `supervisor.rs:1397-1420` spawn `engine.run` trước `apply_netmap`; DNS STUN tách task nền `dns_tracker`; `rebind_underlay` đồng bộ `oneshot` + retry backoff. |
| **Bảo mật Bí mật, Xác thực & Chống Vét Cạn (`SEC-01`, `SEC-04`, `SEC-05`)** | 🟠 Lỗi `HR-W21-03`, `HR-W21-05`, `HR-W21-10`, `HR-W21-11` | ✅ **Đạt 100%** | `record_auth_success` dời xuống cuối luồng ủy quyền; `listener_tls_mode` gắn trên từng kết nối; `migrate-endpoint` chặn mở HTTP trần trên `0.0.0.0`; `redact_secret_kv_line` quét tuyến tính $O(N)$ không giới hạn số khóa. |
| **Chịu lỗi Đĩa Đầy / Dual-`EIO` & Sao lưu (`REL-01`, `US-045`)** | 🟠 Lỗi `HR-W21-04`, `HR-W21-06`, `HR-W21-12` | ✅ **Đạt 100%** | `RamDirectory` + `revoke_node_with_hook` khóa RAM & ngắt phiên trước mọi I/O đĩa; lọc `is_node_revoked_ram` trong `build_snapshot`; phát `broadcast_snapshot` sau compact; sửa đúng `min_netmap_version`. |
| **An toàn Máy Thật & Đóng gói OS (`G4`, `REL-09`, `PLAT-04`, `US-054`)** | 🟠 Lỗi `HR-W21-09` | ✅ **Đạt 100%** | `scripts/install-linux.sh` bỏ hoàn toàn xóa mù `table 51820` / `mv -f /etc/hosts`, dừng `meshd.service` và ủy quyền `mesh cleanup` dọn đúng theo `ResourceLedger`. |

---

## 4. Tiêu Chí Đóng Vòng Phản Biện (Exit Criteria cho Vòng 2)

1. **`dev-server`** đóng trọn vẹn **8 hạng mục**: `HR-W21-02`, `HR-W21-03`, `HR-W21-04`, `HR-W21-05`, `HR-W21-06`, `HR-W21-11`, `HR-W21-12`, `IMP-W21-01` kèm unit/integration tests chứng minh cho từng lỗi. -> **ĐÃ ĐẠT (`c48a391`)**.
2. **`dev-client`** đóng trọn vẹn **7 hạng mục**: `BLK-W21-01`, `HR-W21-07`, `HR-W21-08`, `HR-W21-09`, `HR-W21-10`, `HR-W21-13`, `IMP-W21-02` kèm unit/integration tests chứng minh cho từng lỗi. -> **ĐÃ ĐẠT (`19d4928`)**.
3. Toàn bộ 5 cổng kiểm định trong `powershell -ExecutionPolicy Bypass -File scripts/check.ps1` (`rustc 1.94.1`, static rules, `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace --all-features`, `cargo deny check`) **XANH 100%** không có bất kỳ ngoại lệ `#[allow(...)]` nào. -> **ĐÃ ĐẠT (`HEAD 76f57a6`, bao gồm `-Cross` và `wsl bash -n`)**.

---

## 5. Kết Quả Tái Thẩm Định Độc Lập Vòng 2 (`git diff b779b93..76f57a6`)

### 5.1. Phương Pháp & Cổng Kiểm Định Đã Xác Minh
- Rà soát trực tiếp từng dòng mã nguồn và kiểm thử hồi quy trên 22 tệp thay đổi của Vòng 2 (`git diff b779b93..76f57a6`, `+4697/-595`) cùng quét mẫu cấm trên toàn bộ `crates/**/src/*.rs`.
- Đối chiếu kết quả chạy cổng kiểm định toàn kho trên máy chủ build:
  - `powershell -ExecutionPolicy Bypass -File scripts/check.ps1 -Cross`: **PASS 100%** (`275/275` bài kiểm thử xanh trên toàn bộ crates, `0` failed, `0` ignored, `0` cảnh báo Clippy `-D warnings` trên host + 3 cross targets + `cargo zigbuild --release --target x86_64-unknown-linux-musl`, `cargo deny check` xanh).
  - `wsl bash -n scripts/install-linux.sh scripts/install-macos.sh scripts/install-server.sh scripts/check.sh`: **PASS (`exit 0`)**.

### 5.2. Bảng Bằng Chứng Đóng Triệt Để 15/15 Hạng Mục

| Mã hạng mục | Phân vùng | Vị trí sửa thực tế (`file:line`) | Bằng chứng kỹ thuật & Bài kiểm thử hồi quy | Kết luận |
|---|---|---|---|---|
| `BLK-W21-01` | `dev-client` | [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1397-L1425) | `session_tracker.spawn(relay_client.run(...))` (`1397`) và `session_tracker.spawn(engine.run(...))` (`1403`) chạy **trước** `apply_dp_handle.apply_netmap(snap).await` (`1420`). Test: `test_up_and_offline_auto_resume_do_not_deadlock`. | ✅ `CLOSED` |
| `HR-W21-02` | `dev-server` | [revoked_ram.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/revoked_ram.rs#L46-L125), [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L712-L738) | Tách `RevokedSet.expired_nodes` khỏi `nodes` vĩnh viễn; `register_node` gọi `clear_expired_node` + `clear_pending_expired_node` khi gia hạn hợp lệ `--for <node>`, giữ `replaced_pubkey` trong `RevokedSet.pubkeys` và không bao giờ mở khóa `NodeStatus::Revoked`. Test: `test_expired_node_renewal_clears_ram_and_emergency_expiry_while_revoked_stays_blocked`. | ✅ `CLOSED` |
| `HR-W21-03` | `dev-server` | [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L380-L401), [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L1425-L1461), [rate_limit.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/rate_limit.rs#L265-L287) | Bỏ hoàn toàn `record_auth_success` khỏi `verify_signed_proof`; chỉ reset bộ đếm sau khi `register_node` (`385`) hoặc `authenticate_active_node` (`1459`) thành công trọn vẹn; ghi nhận lỗi cho `pubkey` lạ (`1430`) và chặn `enforce_ip_lockout` trên mọi endpoint xác thực. Test: `test_rate_limiter_locks_out_valid_proofs_with_bad_preauth_or_unknown_pubkey`. | ✅ `CLOSED` |
| `HR-W21-04` | `dev-server` | [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L143-L220), [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L1266-L1445), [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L536-L623) | Duy trì `RamDirectory` đồng bộ trong `ControlStore`; `revoke_node_with_hook` / `expire_node_with_hook` tra `known_pubkey` từ RAM, khóa `revoked_ram` và gọi `terminate_node_sessions` (`< 100 ms`) **trước** mọi thao tác đọc/ghi `redb` hoặc `EmergencySlot`. Tests: `test_revoke_fires_ram_and_hook_before_slow_disk_and_survives_dual_eio`, `test_admin_revoke_under_dual_eio_enforces_ram_and_disconnects`. | ✅ `CLOSED` |
| `HR-W21-05` | `dev-server` | [listener_set.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/listener_set.rs#L521-L536), [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L1382-L1385), [rate_limit.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/rate_limit.rs#L248-L334) | `ConnectionTlsContext.listener_tls_mode` được đóng dấu theo từng listener nhận kết nối và điều khiển đồng nhất cả kiểm tra TLS exporter (`SEC-04`) lẫn trích xuất `X-Forwarded-For` (`*_for_mode`, `US-042 AC6`). Test: `test_per_listener_tls_mode_drives_exporter_and_xff_extraction`. | ✅ `CLOSED` |
| `HR-W21-06` | `dev-server` | [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L832-L841) | `handle_restore` nối đúng `query.min_netmap_version.unwrap_or(0)` vào `RestoreOptions.min_netmap_version` và đặt `min_required_snapshot_version: None`. Test: `test_admin_restore_min_netmap_version_raises_floor_for_older_snapshot`. | ✅ `CLOSED` |
| `HR-W21-07` | `dev-client` | [engine.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/engine.rs#L729-L778), [stun_client.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/stun_client.rs#L410-L470) | `ApplyNetmap` thực thi `peer_map.apply_diff`, `disco.remove_peers`, `relay.remove_peer_queues` và trả `oneshot` ngay tức thì (`< 1 ms`); việc phân giải DNS STUN tách sang `dns_tracker` có `CancellationToken` và timeout `5 s`. Test: `test_apply_netmap_revokes_peer_immediately_without_waiting_for_stun_dns`. | ✅ `CLOSED` |
| `HR-W21-08` | `dev-client` | [engine.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/engine.rs#L833-L873), [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1669-L1779), [roaming_loop.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/roaming_loop.rs#L205-L270) | `BeginRebind` khóa phát gói UDP trực tiếp trên NIC cũ (`direct_udp_blocked = true`), `rebind_underlay` chờ `oneshot` hoàn tất trước khi quét ứng viên / STUN / đấm lỗ, và báo lỗi ngược về `RoamingLoop` để retry có trần `500 ms -> 4 s`. Tests: `test_rebind_underlay_blocks_stale_egress_on_failure_and_recovers_on_retry`, `test_roaming_loop_retries_failed_rebind_until_confirmed`. | ✅ `CLOSED` |
| `HR-W21-09` | `dev-client` | [install-linux.sh](file:///D:/Project/Idea/mesh-vpn/scripts/install-linux.sh#L267-L295), [client_cmds.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh/src/client_cmds.rs#L192-L257) | Xóa bỏ hoàn toàn lệnh xóa mù `table 51820` / `ip rule 51810` / `mesh0` / `mv -f /etc/hosts`; `do_uninstall` dừng `meshd.service` trước rồi gọi `mesh cleanup` (bổ sung fallback offline đọc đúng `ResourceLedger`, tuyệt đối không chạm tài nguyên ngoài sổ cái). Test: `test_offline_ledger_cleanup_noop_when_ledger_missing_or_clean`. | ✅ `CLOSED` |
| `HR-W21-10` | `dev-client` | [config.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/config.rs#L708-L940) | `redact_secret_kv_line` viết lại theo con trỏ tiến một lượt tuyến tính $O(N)$ (`while cursor < current.len()`), xử lý cả dấu ngoặc kép thoát `\"` và đối tượng/mảng JSON lồng nhau, không giới hạn số lượng khóa nhạy cảm trên một dòng. Test: `test_redact_secret_text_redacts_15_canary_secrets_on_single_json_line`. | ✅ `CLOSED` |
| `HR-W21-11` | `dev-server` | [listener_set.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/listener_set.rs#L256-L330), [listener_set.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/listener_set.rs#L587-L635), [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L308-L322) | `validate_migration_target` chặn fail-closed `ReverseProxy` khi `trusted_proxies` rỗng hoặc `control_bind_ip` không phải loopback (`SEC-05`), kiểm tra `Acme`, bắt buộc cổng TCP mới khi đổi chế độ TLS, gọi `reissue_cert_same_key` cập nhật SAN khi đổi `--host` ở `IpPinned`, lưu `public_host` + `tls_mode` sống trong `ActivePortState` và đồng bộ toàn bộ Admin API. Tests: `test_migrate_endpoint_validates_sec05_updates_san_persists_host_and_keeps_dual_stack_tls_modes`, `test_admin_endpoints_reflect_live_migrated_host_and_ports`. | ✅ `CLOSED` |
| `HR-W21-12` | `dev-server` | [netmap_hub.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/netmap_hub.rs#L270-L284), [admin_service.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs#L976-L987), [alert_worker.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/alert_worker.rs#L340-L352) | `NetmapHub::build_snapshot` lọc sạch `is_node_revoked_ram`, `is_pubkey_revoked_ram` và khóa quá hạn; `record_to_admin_summary` phản ánh trạng thái RAM suy giảm; `try_compact_emergency_revocations` trả `Ok(Some(ver))` để `AlertWorker` phát `broadcast_snapshot(compacted_ver)` ngay khi đĩa hồi phục. Tests: `test_build_snapshot_filters_ram_revoked_and_expired_nodes_during_degraded_store`, `test_compaction_recovery_broadcasts_updated_netmap_snapshot`. | ✅ `CLOSED` |
| `HR-W21-13` | `dev-client` | [config.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/config.rs#L62-L64), [netmap_cache.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/netmap_cache.rs#L40-L135), [control_loop.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/control_loop.rs#L551-L625), [supervisor.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs#L1334-L1377) | Lưu bền vững `key_expires_at_ms` qua khởi động lại (`BootstrapConfig` + `NetmapCacheFile` có SHA-256 digest), chặn khôi phục offline khi quá ân hạn `> 24h` lúc boot và tự động hạ phiên (`NodeKeyExpired` dọn sạch TUN/route/`hosts`) khi vượt trần 24 giờ trong lúc đang chạy offline. Tests: `test_offline_key_expiry_within_and_beyond_24h_grace_across_restart`, `test_control_loop_tears_down_session_when_offline_key_grace_exceeds_24h`. | ✅ `CLOSED` |
| `IMP-W21-01` | `dev-server` | [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L232-L233), [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L1069-L1083) | Xóa sạch `let _ = ver;`, trả về `AppResult<Option<u64>>`, và bổ sung `inject_redb_failure(read_fail, write_fail)` kiểm thử đầy đủ lỗi đọc + ghi `redb` đồng thời. | ✅ `CLOSED` |
| `IMP-W21-02` | `dev-client` | [ping_probe.rs](file:///D:/Project/Idea/mesh-vpn/crates/meshd/src/ping_probe.rs#L126-L175) | `execute_netcheck` chạy song song STUN UDP và Control/Relay TCP bằng `tokio::join!` bọc trong hạn chót tổng `NETCHECK_OVERALL_DEADLINE = 4 s` (`<= 5 s` `US-023 AC4`). Test: `test_execute_netcheck_blackhole_stays_under_5s_budget`. | ✅ `CLOSED` |

### 5.3. Đánh Đổi Chiến Lược Đã Chấp Thuận (`Strategic Trade-offs`) & Điều Kiện Chuyển Bước
- **Ghi chú quan sát mức `Low` (không chặn Gate)**: Trong `crates/mesh-server/src/control_handlers.rs:371`, `handle_register_node` vẫn truyền `&state.config.public_host` (giá trị lúc khởi động) vào kiểm tra trùng tên máy chủ khi đăng ký mới, trong khi `handle_rename_node` đã đọc `state.listeners.active_public_host()`. Rủi ro thực tế bằng **0** vì trình quản lý `/etc/hosts` ở phía client (`mesh-net` — `PLAT-04`) độc lập chặn cả hostname lẫn IP công khai hiện hành của Control Server từ `NetmapSnapshot`; có thể đồng bộ nốt 1 dòng sang `active_public_host` khi tiện ở đợt dọn dẹp tiếp theo.
- **Kết luận Phê duyệt Cổng Chất lượng**: Toàn bộ `WP-S2-01`, `WP-S2-02`, `WP-S2-03` đạt chuẩn kiến trúc, bảo mật (`SEC-01..15`), chịu lỗi (`REL-01..14`, Dual-`EIO`), an toàn máy thật (`G4` `ResourceLedger`) và chuẩn mã nguồn Rust `1.94.1`. Chính thức cấp phán quyết 🟢 **`[APPROVED FOR GATE]`** để chuyển sang Wave 2.2 (`WP-S2-04` & `WP-S2-05`).
