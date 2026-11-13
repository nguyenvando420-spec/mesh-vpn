# Báo Cáo Phản Biện Độc Lập — Sprint 1 Wave 1.2 (`WP-S1-05` & `WP-S1-06`)

- **Người phản biện**: `agile-critic` (`gemini-4-carbon-high` — Independent Red-Team Reviewer, độc lập biến thể với tác giả `hydrogen-xhigh` / `hydrogen-high`)
- **Ngày kiểm định**: `2026-11-13`
- **Phạm vi kiểm định**:
  - **`WP-S1-05`** (`US-055`, `US-039`, `US-040` + tích hợp CLI/Daemon cho `US-003`, `US-004`, `US-020`, `US-021`, `US-033`, `US-034`, `US-073`, `US-074`, `SEC-14`, `SEC-15`, `HR-G2-04`): `crates/meshd/**`, `crates/mesh/**`
  - **`WP-S1-06`** (`US-057`, `US-028`, `GNFR-11`, `GNFR-12`): `Dockerfile`, `lab/**`, `.github/workflows/{ci.yml,release.yml}`
- **Đối chiếu chuẩn**: `.agents/rules/coding-standards.md`, `docs/03-system-design/api-design.md`, `docs/02-product-planning/product-backlog.md`, `docs/04-sprint-management/sprint-backlog.md`
- **Phán quyết Vòng 1**: 🔴 `[REVISION REQUIRED]` *(7 Blocker, 6 High Risk, 2 Improvement)*
- **Phán quyết Vòng 2 (Hiện hành)**: 🟢 **`[APPROVED FOR GATE]`** *(15/15 hạng mục Vòng 1 + kiểm tra nhóm phụ `mesh-admin` đã đóng `CLOSED`)*

---

## 1. Tóm Tắt Điều Hành (Executive Summary)

Quá trình kiểm định độc lập từng dòng trên toàn bộ **29 tệp** mã nguồn, Dockerfile, kịch bản NAT Lab và GitHub Actions của Wave 1.2 ghi nhận kỷ luật tuân thủ chuẩn biên dịch và an toàn tĩnh rất tốt: **0** UTF-8 BOM, **100% LF**, **0** `#[allow(clippy::...)]`, **0** `println!`/`eprintln!`/`dbg!`/`todo!`/`unreachable!`, **0** `.unwrap()`/`.expect()`/`panic!()` trong mã production, **0** cổng cứng `:443`/`:3478` ngoài `mesh-core`, và **0** `privileged: true` trong toàn bộ `lab/docker-compose.nat-lab.yml`.

Tuy nhiên, đối chiếu sâu theo luồng chạy thực tế (runtime control/data-plane, Windows SCM, CI/Release packaging và Docker NAT Lab) phát hiện **7 lỗi mức 🔴 `Blocker`** (4 lỗi ở `WP-S1-05`, 3 lỗi ở `WP-S1-06`), **6 lỗi mức 🟠 `High Risk`** (4 lỗi ở `WP-S1-05`, 2 lỗi ở `WP-S1-06`) và **2 điểm 🟡 `Improvement`** cần khắc phục trước khi khép Sprint 1 / mở Sprint 2:

| Mã phát hiện | Mức độ | Gói việc | Tệp & Dòng chính | Tóm tắt vấn đề cốt lõi |
|---|---|---|---|---|
| `BLK-W12-01` | 🔴 Blocker | `WP-S1-05` | `crates/meshd/src/main.rs:32-41`, `service_windows.rs:27` | `meshd.exe` thiếu cờ `--service` (bị `install-windows.ps1` truyền vào) và lệch tên Windows Service (`MeshVPNService` vs `MeshVpnAgent`), làm dịch vụ Windows sập 100% lúc khởi động. |
| `BLK-W12-02` | 🔴 Blocker | `WP-S1-05` | `crates/meshd/src/ping_probe.rs:44, 190-296` | `mesh ping` không gửi gói probe thực tế theo từng `seq`: trên `Relay` tự bịa RTT ~`1 ms` từ IPC nội bộ và báo **0% loss ngay cả khi peer đích tắt nguồn/offline**; trên `Direct` đọc lại `rtt_ms` cũ trong RAM. |
| `BLK-W12-03` | 🔴 Blocker | `WP-S1-05` | `crates/meshd/src/control_loop.rs:486-520` | `ControlLoop::run` gọi `net_backoff.reset(); tls_backoff.reset();` vô điều kiện ngay sau mỗi lần hết timer ngủ, khiến backoff kẹt vĩnh viễn ở `attempt 0` (`<= 500 ms` reconnect storm vô tận). |
| `BLK-W12-04` | 🔴 Blocker | `WP-S1-05` | `crates/meshd/src/control_loop.rs:98, 964-978, 1246-1274`, `supervisor.rs:830` | Chưa thu thập ứng viên LAN IPv4 / global IPv6 (`local_candidates` luôn `[]`), vứt bỏ payload `CallMeMaybeRelay` trên kênh Control và để `control_tcp_endpoint: None` trong bộ lọc chống khuếch đại. |
| `BLK-W12-05` | 🔴 Blocker | `WP-S1-06` | `.github/workflows/ci.yml:328-334`, `lab/docker-compose.nat-lab.yml:25` | Job `docker-build-and-lab` build ảnh `mesh-vpn/mesh-server:lab` nhưng bước kiểm tra UID lại chạy `docker run ... mesh-server:lab` (thiếu tiền tố `mesh-vpn/`), làm CI đỏ 100%. |
| `BLK-W12-06` | 🔴 Blocker | `WP-S1-06` | `.github/workflows/release.yml:134, 172-182`, `ci.yml:272` | Build Windows trong CI & Release không truyền `MESH_WINTUN_SHA256` (khiến `meshd.exe` fail-closed 100% lúc mở TUN) và gói `.zip` Windows bỏ quên cả `wintun.dll` lẫn `scripts/install-windows.ps1`. |
| `BLK-W12-07` | 🔴 Blocker | `WP-S1-06` | `lab/node/entrypoint.sh:64-70`, `lab/faults/inject-fault.sh:184-199` | Cấu hình sai biến môi trường `libfaketime`: dùng `FAKETIME_FOLLOW_FILE` (đọc `mtime` khi có `FAKETIME="%"`) thay vì `FAKETIME_TIMESTAMP_FILE` + `FAKETIME_NO_CACHE=1`, khiến lệnh `power-resume --jump-secs 240` nhảy **0 giây**. |
| `HR-W12-01` | 🟠 High Risk | `WP-S1-05` | `crates/meshd/src/control_loop.rs:1002-1026`, `supervisor.rs:623-661, 805-819` | Báo ACK sớm `acked_endpoint_version` trước khi chuyển sang endpoint mới (`US-074`) và không cập nhật/khởi động lại `RelayClient` khi chạy `mesh set` hoặc đổi endpoint/pin. |
| `HR-W12-02` | 🟠 High Risk | `WP-S1-05` | `crates/meshd/src/control_loop.rs:499-502, 1304-1324` | Khi bị thu hồi/hết hạn (`NodeRevoked`/`NodeKeyExpired`), `ControlLoop` thoát nhưng không gọi `Supervisor` dọn TUN, route, `hosts` và `RelayClient`. |
| `HR-W12-03` | 🟠 High Risk | `WP-S1-05` | `crates/meshd/src/supervisor.rs:889-892` | `self.roaming_control_rx.take()` rút cạn receiver ở phiên đầu tiên; mọi phiên sau `mesh down` + `mesh up` hoặc `mesh rotate-key` bị đứt vĩnh viễn kênh `RoamingLoop -> ControlLoop`. |
| `HR-W12-04` | 🟠 High Risk | `WP-S1-05` | `crates/meshd/src/control_loop.rs:1438-1455, 1648-1716`, `ping_probe.rs:402-429`, `supervisor.rs:1131-1151` | Socket TCP Control/Netcheck chưa gắn `bind_underlay_socket2` (`SO_MARK`/`IP_BOUND_IF`/`IP_UNICAST_IF`); kiểm tra quyền root trên macOS chỉ `warn!` thay vì fail-closed; `netcheck` TCP chờ `10 s` vượt trần `<= 5 s` (`US-023 AC4`). |
| `HR-W12-05` | 🟠 High Risk | `WP-S1-06` | `lab/run-lab.sh:160-176, 201-213, 221-228`, `lab/vps/proxy-entrypoint.sh:15-28` | Chế độ `--tls-mode reverse_proxy` dùng `--server-pin` của Nginx nhưng ngay bản `NetmapSnapshot` đầu tiên bị ghi đè bằng `active_pin` nội bộ của `mesh-server` gây `PinMismatch`; thiếu bước chờ `meshd-admin.sock` trước `mesh up`. |
| `HR-W12-06` | 🟠 High Risk | `WP-S1-06` | `lab/acceptance/test-udp-blocked-443-only.sh:80-99, 218-231` | Kiểm chứng `US-028 AC4` dùng `|| true` kèm regex chứa chữ `relay`/`8443` luôn khớp giả tạo trên `status --json`; chưa kiểm tra gói IPv4 thật qua TUN và thiếu script smoke tự động cho ma trận lỗi `US-057`. |
| `IMP-W12-01` | 🟡 Improvement | `WP-S1-05` | `crates/meshd/src/control_loop.rs:48`, `supervisor.rs:717-735` | `/v1/netmap/stream` chưa truyền `?known_version=<u64>` (`api-design.md` §1.7); `execute_bugreport` mới xuất JSON tạm (chờ hoàn thiện gói nén ở Sprint 2 `US-041`). |
| `IMP-W12-02` | 🟡 Improvement | `WP-S1-06` | `.github/workflows/ci.yml:106, 337-339` | Ghim phiên bản `dtolnay/rust-toolchain` cụ thể thay cho `@master` và bật chế độ smoke nhanh (`60s`) cho NAT Lab trên nhánh tích hợp chính. |

---

## 2. Các Bất Biến Kiến Trúc & Bảo Mật Đã Được Xác Minh Tốt

1. **Giới hạn tài nguyên Runtime `meshd` (`PERF-05`, `coding-standards.md` §1)**: `crates/meshd/src/main.rs:28-30, 81-85` và `service_windows.rs:173-177` khóa cứng `worker_threads(2)`, `max_blocking_threads(2)`, `thread_stack_size(512 * 1024)`.
2. **Dọn tàn dư Crash Recovery theo Sổ cái & Graceful Shutdown `<= 5 s` (`US-055`, `G4`)**: `DaemonSupervisor::boot` (`crates/meshd/src/supervisor.rs:351-365`) chỉ dọn đúng tài nguyên đã ghi trong `ledger.json` (tuyệt đối không xóa vơ đũa `utun*`); luồng dừng dùng `CancellationToken` + `TaskTracker` + `tokio::time::timeout(5s)` (`supervisor.rs:429-437, 941-949`).
3. **Zero-TOFU, `bootstrap.toml` tối giản & `netmap-cache.json` chống sửa đổi (`SEC-04`, `SEC-15`, `US-033`)**: `BootstrapConfig` (`crates/meshd/src/config.rs:33-59`) bật `#[serde(deny_unknown_fields)]`, không lưu cứng cổng STUN/Relay, từ chối kết nối IP thiếu `--server-pin`, và `NetmapCacheStore` (`netmap_cache.rs:42-66`) đối chiếu SHA-256 bằng hằng thời gian (`ct_eq_bytes`).
4. **Tách biệt hoàn toàn 2 Router IPC (`SEC-14`, `BLK-G2-03`, `US-039 AC5`)**: `crates/meshd/src/ipc_service.rs:51-77` tách riêng `meshd-ro` (`DefaultBodyLimit::max(4096)`, chỉ đúng 4 route đọc `status`/`peers`/`ping`/`netcheck`, 0 bí mật) khỏi `meshd-admin` (`LOCAL_PEERCRED` `gid == 80` trên macOS, `SO_PEERCRED` + `getgrouplist` trên Linux, Named Pipe SDDL `SY+BA` trên Windows).
5. **Tách rạch ròi CLI & Bảo vệ khóa trên CLI (`SEC-01`, `HR-G2-04`)**: `crates/mesh/src/` tách sạch `client_cmds.rs` và `admin_cmds.rs`, cấm cờ `--authkey` trên argv, in `raw_key` đúng 1 lần, khóa `stdout`/`stderr` (0 `println!`/`eprintln!`), và trả lỗi `"meshd daemon is not running"` trong `<= 850 ms` (`< 1 s`) khi daemon tắt.
6. **Không đặc quyền hóa Container Lab (`US-057 AC1`)**: `lab/docker-compose.nat-lab.yml` không chứa bất kỳ `privileged: true` nào; node chỉ dùng `cap_add: [NET_ADMIN]` + `/dev/net/tun` + `net.ipv4.conf.all.src_valid_mark=1`, còn `vps` chạy dưới user `mesh` không đặc quyền (`CAP_NET_BIND_SERVICE`).

---

## 3. Phân Tích Chi Tiết Lỗ Hổng Gói `WP-S1-05` (`crates/meshd/**` & `crates/mesh/**`)

### 🔴 `[BLK-W12-01]` Dịch vụ Windows (`meshd.exe`) sập 100% lúc khởi động do thiếu cờ `--service` và lệch tên SCM Service (`US-052`, `US-055`)
- **Vị trí**:
  - `crates/meshd/src/main.rs:32-41, 103-112`
  - `crates/meshd/src/service_windows.rs:27, 65, 187`
  - Đối chiếu hợp đồng cài đặt (`WP-S1-04`): `scripts/install-windows.ps1:27, 246-249` và `docs/04-sprint-management/sprint-backlog.md:157`
- **Nguyên nhân gốc**:
  1. `scripts/install-windows.ps1:248` đăng ký dịch vụ Windows với lệnh khởi chạy `binPath= "\"$meshdDest\" --service"`, nhưng `DaemonArgs` trong `crates/meshd/src/main.rs:32-41` chỉ khai báo `--check-config` và `--foreground`. Khi Windows Service Control Manager (SCM) gọi `meshd.exe --service`, `DaemonArgs::parse()` lập tức báo lỗi tham số lạ và thoát mã `2` trước khi vào `service_dispatcher::start`.
  2. Ngay cả khi bỏ qua lỗi cờ CLI, `service_windows.rs:27` đặt cứng `WINDOWS_SERVICE_NAME = "MeshVPNService"`, trong khi `install-windows.ps1:27` và `sprint-backlog.md:157` đăng ký tên dịch vụ chuẩn là `"MeshVpnAgent"`.
- **Hệ quả thực tế (Impact)**: Cài đặt mới trên Windows 10/11 qua `install-windows.ps1` không thể khởi chạy `meshd.exe` dưới SCM (`Error 1053` / thoát tức thì 100%).
- **Hướng khắc phục cụ thể (Actionable Remedy — trong `crates/meshd/src/{main.rs,service_windows.rs}`)**:
  1. Bổ sung `#[arg(long)] service: bool` vào `DaemonArgs` (`main.rs`), ưu tiên nhánh `if args.service` gọi `service_windows::run_windows_service()` trên Windows, kèm unit test `DaemonArgs::try_parse_from(["meshd", "--service"])`.
  2. Đổi `WINDOWS_SERVICE_NAME` trong `service_windows.rs:27` thành `"MeshVpnAgent"` khớp 100% với `scripts/install-windows.ps1`.

---

### 🔴 `[BLK-W12-02]` `mesh ping` (`ping_probe.rs`) không gửi gói probe đầu-cuối thật mà đo độ trễ RAM cục bộ, báo `0% loss` ngay cả khi peer đích đã tắt nguồn (`US-040 AC1–AC4`, `api-design.md` §3.3(d))
- **Vị trí**: `crates/meshd/src/ping_probe.rs:44, 190-296`
- **Nguyên nhân gốc**:
  - `find_peer` (`line 44`) bỏ qua trạng thái `_online: peer.online`.
  - Trong `measure_single_sample` (`lines 190-247`), khi đường đi của peer đang là `PeerActivePath::Relay`, miễn là WebSocket từ daemon **cục bộ** lên VPS Relay còn sống (`snap.relay_state == RelayConnectionState::Connected`), hàm lập tức trả về `PingSample { seq, via: PingVia::Relay, rtt_ms: Some(1.0_f64.max(started.elapsed())) }` — thực chất chỉ đo thời gian gọi `datapath.query_status().await` trong RAM cục bộ (~`1 ms`), **không hề gửi bất kỳ gói `DiscoPing` nào qua Relay tới peer đích và không chờ `DiscoPong` phản hồi**!
  - Tương tự trên nhánh `PeerActivePath::Direct` (`lines 250-296`), hàm không phát probe mới theo từng `seq` mà chỉ đọc lại giá trị `rtt_ms` cũ lưu sẵn trong `PeerActivePath::Direct`.
- **Hệ quả thực tế (Impact)**:
  - Khi một node peer bị rút điện/sập hoàn toàn hoặc bị tường lửa cắt đứt, quản trị viên chạy `mesh ping <offline-peer>` vẫn nhận kết quả giả tạo `5 packets transmitted, 5 received, 0.0% packet loss, ~1.0 ms via relay` (vi phạm trực tiếp `US-040 AC3`).
  - Làm mất hiệu lực kiểm chứng của `lab/acceptance/test-udp-blocked-443-only.sh:95` (`US-028`), vì `mesh ping` trả `PASS` mà không chứng minh được gói tin thực sự đi xuyên qua Blind Relay sang node bên kia.
- **Hướng khắc phục cụ thể (Actionable Remedy)**:
  - Bổ sung lệnh probe có đối chiếu `tx_id` một-một (ví dụ `DatapathCommand::SendPingProbe` hoặc cơ chế đăng ký waiter `tx_id -> oneshot::Sender<(PingVia, Option<SocketAddr>, f64)>` trong `DiscoEngine`/`DatapathEngine` — Scrum Master điều phối mở quyền chạm hẹp `crates/mesh-datapath/src/{disco_engine.rs,engine.rs}` nếu cần) để mỗi nhịp `seq` của `ping_probe.rs`:
    1. Thực sự gửi 1 gói `DiscoPing` mã hóa tới `peer_id` (qua `Direct` nếu đang `Direct` hoặc `--direct`; qua `Relay` nếu đang `Relay`, đồng thời kích `InitiateHolePunch` khi `!force_direct` để quan sát nâng cấp `via relay -> via direct`).
    2. Chờ đúng gói `DiscoPong` khớp `tx_id` từ peer đích trong `timeout_ms`; nếu quá hạn trả `PingVia::Timeout` (`rtt_ms: None`), để `client_cmds.rs:207` trả mã thoát `!= 0` khi mất 100% gói.

---

### 🔴 `[BLK-W12-03]` `ExponentialBackoff` bị `reset()` về 0 ngay sau mỗi lần ngủ retry, gây bão kết nối lại `<= 500 ms` vô tận (`US-034 AC1/AC2/AC4`)
- **Vị trí**: `crates/meshd/src/control_loop.rs:479-520, 560-577`
- **Nguyên nhân gốc**:
  - Tại `control_loop.rs:507-519`: sau khi `run_single_session` thất bại, vòng lặp tính `delay = backoff.next_delay()`, chờ `wait_backoff_or_wake(&mut ctx, delay).await` (`line 514`), rồi **gọi thẳng `net_backoff.reset(); tls_backoff.reset();` ở dòng `517-518`** bất cứ khi nào hàm chờ trả `true` — bao gồm cả trường hợp hết giờ ngủ bình thường (`_ = tokio::time::sleep(delay) => true` ở dòng `567`)!
  - Ngoài ra, ở dòng `486-490`, backoff cũng bị reset ngay cả khi phiên vừa kết nối xong đã đứt sau vài mili-giây (chưa kiểm tra ngưỡng phiên ổn định `> 60 s` theo `US-034 AC1`).
- **Hệ quả thực tế (Impact)**: Cả `net_backoff` (trần `60 s`) lẫn `tls_backoff` (trần `5 phút` khi gặp Captive Portal / lệch giờ / sai SPKI pin) không bao giờ tăng quá `attempt = 0` (`0..500 ms`). Khi VPS bảo trì hoặc máy khách vào Wi-Fi khách sạn có Captive Portal, toàn bộ đội node sẽ bắn hàng loạt kết nối TLS mới mỗi vài trăm mili-giây, tự kích hoạt khóa IP rate-limit (`US-042`) trên chính VPS của mình.
- **Hướng khắc phục cụ thể (Actionable Remedy — trong `crates/meshd/src/control_loop.rs`)**:
  - Đổi kiểu trả về của `wait_backoff_or_wake` thành enum tường minh (`TimerExpired`, `WakeSignal`, `Shutdown`): **tuyệt đối không** reset backoff khi `TimerExpired`; chỉ reset khi `WakeSignal` (sự kiện mạng mới / lệnh `mesh set`) hoặc sau khi phiên Control duy trì lành mạnh liên tục `>= 60_000 ms` (`US-034 AC1`). Bổ sung unit test kiểm chứng chuỗi trần backoff tăng dần qua nhiều lần lỗi liên tiếp.

---

### 🔴 `[BLK-W12-04]` Thiếu thu thập ứng viên LAN cục bộ (`US-020 AC1`), bỏ rơi nội dung `CallMeMaybeRelay` trên kênh Control (`US-021`) và để trống `control_tcp_endpoint` trong bộ lọc chống khuếch đại (`US-020 AC3`)
- **Vị trí**:
  - `crates/meshd/src/control_loop.rs:98, 158, 964-978, 1246-1274`
  - `crates/meshd/src/supervisor.rs:830`
- **Nguyên nhân gốc**:
  1. `send_endpoint_update_over_ws` (`control_loop.rs:1246-1274`) chỉ lấy `report.reflexive_addrs` từ STUN, không thu thập địa chỉ IPv4 LAN / IPv6 global trên các card mạng vật lý gắn với `local_udp_port`, không đẩy vào `DatapathCommand::SetAdvertisedEndpoints`, và trường `DaemonRuntimeData::local_candidates` (`line 98`) không bao giờ được ghi (luôn trả `[]` trong `mesh status`).
  2. Khi nhận `ServerControlFrame::CallMeMaybeRelay { src_node_id, src_node_pubkey, disco_frame_b64 }` trên WebSocket Control (`control_loop.rs:964-978`), code bỏ qua hoàn toàn `src_node_pubkey` và `disco_frame_b64` thay vì giải mã base64 và chuyển gói Disco vào `DatapathEngine` để lấy danh sách endpoint ứng viên mới nhất của peer.
  3. `supervisor.rs:830` gán cứng `control_tcp_endpoint: None` trong `DatapathConfig`, khiến `CandidateFilterContext.control_tcp_endpoint` (`engine.rs:781`) không thể chặn ứng viên giả mạo trùng địa chỉ TCP của chính Control Server (`US-020 AC3`).
- **Hệ quả thực tế (Impact)**: Hai máy nằm cùng mạng LAN nội bộ (hoặc sau router không hỗ trợ NAT hairpinning khi STUN UDP bị chặn) không thể thiết lập kết nối P2P LAN trực tiếp; ứng viên gửi qua `/v1/disco/call-me-maybe` bị rơi vào hố đen; thiếu lớp chặn phản xạ vào địa chỉ Control Server.
- **Hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Thu thập danh sách IP vật lý hợp lệ của host kết hợp `local_udp_port`, lọc qua `mesh_net::endpoint_filter::is_valid_candidate_endpoint`, cập nhật vào `local_candidates`, gọi `DatapathCommand::SetAdvertisedEndpoints` và gộp cùng `reflexive_addrs` khi gửi `EndpointUpdate`.
  2. Truyền `control_tcp_endpoint` đã phân giải vào `DatapathConfig` tại `supervisor.rs:830`.
  3. Chuyển khung `disco_frame_b64` đã giải mã từ `CallMeMaybeRelay` kèm `verified_src_node_pubkey` xuống `DatapathEngine` để `DiscoEngine::handle_incoming` kích hoạt đấm lỗ đồng thời đúng chuẩn.

---

### 🟠 `[HR-W12-01]` Xác nhận khống `acked_endpoint_version` trước khi chuyển cổng/IP (`US-074`) và `RelayClient` không cập nhật khi chạy `mesh set`
- **Vị trí**: `crates/meshd/src/control_loop.rs:1002-1026`, `crates/meshd/src/supervisor.rs:623-661, 805-819`
- **Nguyên nhân gốc**:
  - Trong `apply_netmap_update` (`control_loop.rs:1002-1020`), ngay khi nhận `NetmapSnapshot` có `endpoint_version` mới, agent lập tức gán `g.bootstrap.acked_endpoint_version = ep_ver` và gửi `EndpointUpdate` xác nhận `ep_ver` ngay trên kết nối cũ **mà chưa cập nhật `g.bootstrap.server_endpoint` (`bootstrap.toml`), chưa kết nối thử sang `control_tcp_endpoint` mới và chưa cập nhật `RelayClient`**.
  - Trong `execute_set` (`supervisor.rs:623-661`), lệnh `mesh set --server ...` chỉ sửa `bootstrap` và đánh thức `ControlLoop`, nhưng `RelayClient` (khởi tạo một lần ở `supervisor.rs:805-819`) vẫn giữ nguyên endpoint và `pin_set` cũ; ngoài ra khi đổi sang `--ca-tls`, `active_pin`/`next_pin` cũ không được xóa khỏi `BootstrapConfig`.
- **Hệ quả thực tế (Impact)**: Khi admin chạy di chuyển cổng sống (`US-074`), server tưởng toàn bộ node đã chuyển sang cổng mới nên đóng cổng cũ, làm toàn bộ đội node mất kết nối vì `bootstrap.toml` vẫn trỏ cổng cũ. Khi chạy `mesh set` (bao gồm kịch bản `US-028 AC4`), kênh Blind Relay vẫn ghim chết ở cổng cũ.
- **Hướng khắc phục cụ thể (Actionable Remedy)**:
  - Chỉ tăng `acked_endpoint_version` và ghi `server_endpoint` mới vào `bootstrap.toml` sau khi kết nối TLS tới endpoint mới thành công; đồng thời khởi tạo lại phiên `RelayClient` (hoặc cấp kênh cập nhật `RelayClientConfig` động) khi `execute_set` hoặc `RelayMap` đổi `relay_tcp_endpoint` / `pin_set`. Xóa `active_pin = None; next_pin = None` khi chuyển sang `TlsAuthMode::SystemCa`.

---

### 🟠 `[HR-W12-02]` Khi nhận `NodeRevoked` / `NodeKeyExpired`, `ControlLoop` dừng nhưng bỏ mặc TUN, route, `hosts` và `RelayClient` tiếp tục chạy (`US-029`, `US-031`, `US-034 AC5`)
- **Vị trí**: `crates/meshd/src/control_loop.rs:499-502, 1304-1324`, `crates/meshd/src/supervisor.rs:885-922`
- **Nguyên nhân gốc**: `handle_terminal_revocation` chỉ đổi `daemon_state` sang `DaemonState::IdentityTerminated` rồi `break` khỏi `ControlLoop::run`, không phát tín hiệu cho `DaemonSupervisor` hủy `session_cancel` và dọn `ResourceLedger`.
- **Hệ quả thực tế (Impact)**: Node đã bị thu hồi hoặc hết hạn khóa vẫn giữ nguyên giao diện TUN `mesh0`/`utunN`, bảng định tuyến overlay, `/etc/hosts` và tiến trình `RelayClient` chạy ngầm trái với `api-design.md:315`.
- **Hướng khắc phục cụ thể (Actionable Remedy)**: Gửi sự kiện thu hồi từ `ControlLoop` về `DaemonSupervisor` để gọi ngay quy trình tháo dỡ datapath + `ledger.cleanup_all` trong khi vẫn giữ `DaemonState::IdentityTerminated { reason }` cho `mesh status`.

---

### 🟠 `[HR-W12-03]` `self.roaming_control_rx.take()` làm đứt vĩnh viễn kênh sự kiện Roaming sau lần `mesh down` / `mesh rotate-key` đầu tiên
- **Vị trí**: `crates/meshd/src/supervisor.rs:321, 889-892`
- **Nguyên nhân gốc**: `RoamingLoop` được tạo 1 lần lúc boot daemon giữ `roaming_control_tx`, còn `start_tunnel_session` gọi `self.roaming_control_rx.take().unwrap_or_else(|| mpsc::channel(...).1)`. Từ phiên thứ hai trở đi (sau `mesh down && mesh up` hoặc `mesh rotate-key`), `ControlLoop` nhận một `Receiver` mồ côi không có `Sender`, còn `roaming_control_tx` trong `RoamingLoop` bị đóng đầu nhận vĩnh viễn.
- **Hệ quả thực tế (Impact)**: Phá vỡ hợp đồng kênh Roaming mở khóa cho Sprint 2 (`HR-G2-04`) ngay sau bất kỳ thao tác bật/tắt phiên hoặc xoay khóa nào.
- **Hướng khắc phục cụ thể (Actionable Remedy)**: Bọc `roaming_control_rx` trong `Arc<tokio::sync::Mutex<mpsc::Receiver<NetEvent>>>` dùng chung qua các phiên (hoặc dùng `tokio::sync::broadcast::channel`) để không bao giờ làm rơi đầu nhận khi tái tạo phiên tunnel.

---

### 🟠 `[HR-W12-04]` Socket TCP Control/Netcheck thiếu ràng buộc NIC vật lý (`REL-09`), macOS chỉ `warn!` khi sai quyền file gốc (`US-073 AC2`), và `netcheck` vượt trần timeout `5 s` (`US-023 AC4`)
- **Vị trí**:
  - `crates/meshd/src/control_loop.rs:1438-1455, 1648-1716`
  - `crates/meshd/src/ping_probe.rs:402-429`
  - `crates/meshd/src/supervisor.rs:1131-1151`
- **Nguyên nhân gốc**:
  1. `connect_tcp_with_timeout` (`control_loop.rs:1438-1455`) và `probe_tcp_reachability` (`ping_probe.rs:418`) gọi thẳng `TcpStream::connect` thay vì đi qua `mesh_net::bind_underlay_socket2` (`SO_MARK = 0x5d56` trên Linux, `IP_BOUND_IF` trên macOS, `IP_UNICAST_IF` trên Windows như `RelayClient` đã làm).
  2. `verify_startup_path_security_best_effort` (`supervisor.rs:1131-1151`) chỉ ghi `warn!` khi `/usr/local/libexec/mesh/meshd` hoặc plist trên macOS có quyền ghi group/world hoặc không thuộc `root`, vi phạm quy tắc fail-closed của `US-073 AC2` và `coding-standards.md` §5 `G4`.
  3. `probe_tcp_reachability` (`ping_probe.rs:417-420`) dùng `CONNECT_TIMEOUT_MS` (`10_000 ms`) cho từng địa chỉ IP phân giải được, làm `mesh netcheck` treo `> 10.3 s` khi tường lửa chặn gói SYN (vượt trần cứng `<= 5 s` của `US-023 AC4`); đồng thời `read_chunked_body` (`control_loop.rs:1648-1716`) chưa bọc `tokio::time::timeout` tổng thể (`GNFR-03`).
- **Hệ quả thực tế (Impact)**: Nguy cơ vòng lặp định tuyến trên socket Control TCP, kẽ hở leo thang đặc quyền trên macOS nếu thư mục cài đặt bị sửa quyền, và treo lệnh `mesh netcheck` quá ngân sách thời gian.
- **Hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Tạo socket TCP Control & Netcheck qua `socket2` + `mesh_net::bind_underlay_socket2` trước khi chuyển sang `tokio::net::TcpStream`.
  2. Trên macOS khi chạy với `euid == 0` và tồn tại đường dẫn cài đặt chuẩn, trả lỗi `Err(...)` từ chối khởi chạy nếu `verify_macos_daemon_startup_paths` thất bại.
  3. Giới hạn tổng ngân sách `probe_tcp_reachability` trong `netcheck` xuống `<= 3_000 ms` (để tổng thời gian `netcheck` luôn `< 5 s`) và bọc toàn bộ `read_http_response` trong `tokio::time::timeout`.

---

### 🟡 `[IMP-W12-01]` Bổ sung `?known_version=<u64>` trên `/v1/netmap/stream` và ghi chú phạm vi `execute_bugreport`
- **Vị trí**: `crates/meshd/src/control_loop.rs:48, 1344-1350`, `crates/meshd/src/supervisor.rs:717-735`
- **Chi tiết & Khuyến nghị**:
  - Đính kèm `?known_version=<u64>` khi mở `/v1/netmap/stream` theo `api-design.md` §1.7 để giảm băng thông đồng bộ lại Netmap khi sóng chập chờn.
  - `execute_bugreport` hiện mới xuất file `.json` trạng thái (chưa đóng gói `.tar.gz`/`.zip` kèm log và bảng route); vì `US-041` là story `Should` thuộc `WP-S2-02`, cần ghi chú rõ hoặc hoàn thiện đúng chuẩn khi kéo `US-041` ở Sprint 2.

---

## 4. Phân Tích Chi Tiết Lỗ Hổng Gói `WP-S1-06` (`Dockerfile*`, `lab/**`, `.github/workflows/**`)

### 🔴 `[BLK-W12-05]` Job `docker-build-and-lab` trong `.github/workflows/ci.yml` gãy 100% do sai tên tag Docker Image (`mesh-server:lab` vs `mesh-vpn/mesh-server:lab`)
- **Vị trí**:
  - `.github/workflows/ci.yml:326-335`
  - `lab/docker-compose.nat-lab.yml:25`
- **Nguyên nhân gốc**: Bước build tại `ci.yml:328` chạy `docker compose -f lab/docker-compose.nat-lab.yml --profile reverse-proxy build`, tạo ra image mang tên **`mesh-vpn/mesh-server:lab`** (`docker-compose.nat-lab.yml:25`). Ngay bước kế tiếp (`ci.yml:332`), workflow lại gọi `docker run --rm --entrypoint id mesh-server:lab -u` (thiếu `mesh-vpn/`). Docker không tìm thấy image cục bộ, cố pull `library/mesh-server:lab` từ Docker Hub và báo lỗi thất bại 100%.
- **Hệ quả thực tế (Impact)**: Toàn bộ pipeline `CI Gate` trên GitHub Actions luôn đỏ ở job `docker-build-and-lab`.
- **Hướng khắc phục cụ thể (Actionable Remedy — trong `.github/workflows/ci.yml:332`)**: Đổi thành `mesh-vpn/mesh-server:lab`.

---

### 🔴 `[BLK-W12-06]` Pipeline CI & Release cho Windows thiếu `MESH_WINTUN_SHA256`, `wintun.dll` và `scripts/install-windows.ps1`, tạo ra bản phát hành Windows hỏng 100% lúc chạy (`US-052`, `US-053`, `SEC-15`, `G4`)
- **Vị trí**:
  - `.github/workflows/release.yml:133-135, 172-182`
  - `.github/workflows/ci.yml:271-276`
  - Đối chiếu mã nguồn: `crates/meshd/src/config.rs:242` & `crates/meshd/src/supervisor.rs:168-172`
- **Nguyên nhân gốc**:
  1. `meshd` trên Windows cưỡng chế fail-closed tại `supervisor.rs:168-172`: nếu biến môi trường lúc biên dịch `option_env!("MESH_WINTUN_SHA256")` là `None`, mọi lệnh `mesh up` đều bị từ chối với lỗi `"wintun.dll SHA-256 pin is required at compile time (MESH_WINTUN_SHA256)"`. Tuy nhiên cả `ci.yml:272` lẫn `release.yml:134` đều build target Windows mà **không thiết lập `MESH_WINTUN_SHA256`**.
  2. Tại bước đóng gói `release.yml:172-182`, workflow chỉ copy script cài đặt cho `linux` và `macos`, bỏ trống hoàn toàn nhánh `windows` — khiến gói `mesh-windows-x86_64-msvc.zip` thiếu cả `scripts/install-windows.ps1` lẫn `wintun.dll` đã ghim mã băm.
- **Hệ quả thực tế (Impact)**: Bản phát hành Windows (`mesh-windows-x86_64-msvc.zip`) không thể cài đặt qua script chuẩn và nhị phân `meshd.exe` từ chối mở giao diện Wintun 100% trên mọi máy Windows thật.
- **Hướng khắc phục cụ thể (Actionable Remedy — trong `.github/workflows/{ci.yml,release.yml}`)**:
  1. Trên runner Windows trong `ci.yml` và `release.yml`, tải gói Wintun chính thức (`wintun-0.14.1.zip`), kiểm chứng SHA-256 của gói nén, trích xuất `wintun/bin/amd64/wintun.dll`, tính/đối chiếu SHA-256 của `wintun.dll` và xuất `MESH_WINTUN_SHA256` vào `$GITHUB_ENV` **trước** bước `cargo build --release`.
  2. Bổ sung nhánh `elif [ "${{ matrix.platform }}" = "windows" ]` trong `release.yml:172-182` để đóng gói kèm `wintun.dll` (cùng thư mục với `meshd.exe` theo `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`) và `scripts/install-windows.ps1`, đồng thời ghi SHA-256 của `wintun.dll` vào `SHA256SUMS`.

---

### 🔴 `[BLK-W12-07]` Cấu hình sai biến môi trường `libfaketime` trong `lab/node/entrypoint.sh` khiến kịch bản `power-resume` (nhảy đồng hồ `> 180 s`) không hề làm thay đổi thời gian (`US-057 AC3`, `US-036 AC2`)
- **Vị trí**:
  - `lab/node/entrypoint.sh:64-70`
  - `lab/faults/inject-fault.sh:184-199`
- **Nguyên nhân gốc**:
  - `inject-fault.sh:197` ghi chuỗi độ lệch `"+240s"` vào `/var/lib/meshd/faketime.rc`.
  - Thế nhưng `lab/node/entrypoint.sh:66` lại đặt `FAKETIME_FOLLOW_FILE="${FAKETIME_FILE}"` mà không đặt `FAKETIME_TIMESTAMP_FILE`. Trong thư viện `wolfcw/libfaketime`, `FAKETIME_FOLLOW_FILE` chỉ hoạt động khi có `FAKETIME="%"` và chỉ đọc `mtime` của tệp chứ **hoàn toàn bỏ qua nội dung chuỗi `"+240s"` bên trong tệp**! Ngoài ra, thiếu `FAKETIME_NO_CACHE=1` khiến `libfaketime` giữ cache 10 giây mặc định, làm sai lệch phép đo SLO phục hồi `<= 10 s` / `<= 15 s`.
- **Hệ quả thực tế (Impact)**: Chạy `inject-fault.sh power-resume node-1 --jump-secs 240` không làm `CLOCK_REALTIME` của `meshd` nhảy thêm giây nào; cả `ClockJumpDetector` lẫn tình huống hết hạn phiên WireGuard `REJECT_AFTER_TIME` (`180 s`) đều không thực sự được kiểm thử trong NAT Lab.
- **Hướng khắc phục cụ thể (Actionable Remedy — trong `lab/node/entrypoint.sh` & `lab/faults/inject-fault.sh`)**:
  - Đổi `FAKETIME_FOLLOW_FILE="${FAKETIME_FILE}"` thành `FAKETIME_TIMESTAMP_FILE="${FAKETIME_FILE}"` kèm `FAKETIME_NO_CACHE=1` và `FAKETIME_DONT_FAKE_MONOTONIC=1` trong `lab/node/entrypoint.sh:65-67`.
  - Trong `inject-fault.sh power-resume`, in xác nhận chênh lệch thời gian thực tế dưới `LD_PRELOAD` trước và sau khi cập nhật `faketime.rc`.

---

### 🟠 `[HR-W12-05]` Chế độ `--tls-mode reverse_proxy` trong `lab/run-lab.sh` bị lỗi `PinMismatch` sau lần đồng bộ Netmap đầu tiên và có race condition khi bootstrap `mesh up`
- **Vị trí**:
  - `lab/run-lab.sh:160-176, 201-213, 221-228`
  - `lab/vps/proxy-entrypoint.sh:15-28`
  - `lab/docker-compose.nat-lab.yml:33, 65`
- **Nguyên nhân gốc**:
  1. `vps-proxy` (Nginx) tự sinh chứng chỉ riêng (`proxy.pin`), trong khi `mesh-server` phía sau tự sinh chứng chỉ riêng trong `ControlStore` (`server.pin != proxy.pin`). `run-lab.sh:207-211` đăng ký node bằng `--server-pin "${pin}"` (`proxy.pin`). Ngay khi nhận `NetmapSnapshot` đầu tiên, `meshd` ghi đè `bootstrap.active_pin` bằng `snapshot.pin_set.active_pin` (`server.pin`), khiến mọi kết nối lại hoặc kết nối `RelayClient` tới Nginx thất bại vì `PinMismatch`!
  2. Nếu chạy `run-lab.sh up --tls-mode reverse_proxy --tcp-port 8443`, `mesh-server` quảng bá `172.28.0.12:8443` trong `RelayMap` nhưng `vps-proxy` chỉ lắng nghe cứng ở cổng `443`.
  3. `bootstrap_nodes` (`run-lab.sh:201-213`) gọi `docker exec ... mesh up` ngay sau khi `vps` `/readyz` mà chưa chờ socket `/var/run/meshd/meshd-admin.sock` trên `node-1..5` khởi tạo xong.
- **Hệ quả thực tế (Impact)**: Topology `reverse_proxy` của `US-057 AC1` gãy kết nối sau lần nhận Netmap đầu tiên; `run-lab.sh up` dễ gặp lỗi ngẫu nhiên `"meshd daemon is not running"` trên máy CI tải cao.
- **Hướng khắc phục cụ thể (Actionable Remedy)**:
  1. Trong chế độ `reverse_proxy` (vốn đại diện cho mô hình domain + chứng chỉ CA công khai theo `US-046`/`US-051`), sinh chứng chỉ từ một Lab Root CA cho tên miền `vpn.mesh.internal`, cài Lab Root CA vào kho tin cậy của container `node-1..5` (`update-ca-certificates`) + ánh xạ `172.28.0.12 vpn.mesh.internal`, và chạy `mesh up --server https://vpn.mesh.internal:${TCP_PORT} --ca-tls`; đồng thời đồng bộ `PROXY_LISTEN_PORT` với `TCP_PORT` và tách cổng upstream nội bộ của `vps` (ví dụ `8080`).
  2. Bổ sung vòng lặp chờ `test -S /var/run/meshd/meshd-admin.sock` (tối đa `15 s`) trên cả 5 container node trước khi gọi `mesh up`.

---

### 🟠 `[HR-W12-06]` Kiểm tra chẩn đoán trong `test-udp-blocked-443-only.sh` (`US-028 AC4`) luôn khớp giả tạo và thiếu kiểm chứng luồng gói IPv4 qua TUN / kịch bản smoke `US-057`
- **Vị trí**: `lab/acceptance/test-udp-blocked-443-only.sh:80-99, 218-231`
- **Nguyên nhân gốc**:
  1. Ở dòng `220-230` (`US-028 AC4`), cả `mesh netcheck --json` lẫn `mesh status --json` đều gắn `|| true`, sau đó dòng `227` kiểm tra `grep -qiE '8443|443|unreachable|cannot reach|relay'`. Vì đầu ra `mesh status --json` **luôn luôn** chứa chuỗi `"relay"` (`"relay_home"`, `"active_path": "relay"`) và `"8443"` (`"server_endpoint"`), phép kiểm tra này luôn trả `PASS` ngay cả khi `mesh netcheck` bị treo timeout hoặc không sinh bất kỳ gợi ý chẩn đoán nào!
  2. `verify_all_ten_pairs` (`lines 80-99`) mới gọi `mesh ping` mà chưa gửi gói ICMP/TCP thực qua giao diện TUN (`ping -c 1 -W 3 <peer_overlay_ip>`) để chứng minh mặt phẳng dữ liệu WireGuard Sans-I/O + Blind Relay thực sự chuyển tiếp gói IPv4 đầu-cuối.
  3. Thư mục `lab/acceptance/` chưa có kịch bản smoke tự động kiểm chứng các chế độ bắt buộc của `US-057` (`eim` nâng cấp `direct`, `apdm` giữ `relay`, `mtu-1400` truyền gói lớn khi chặn ICMP frag-needed, từ chối `captive-portal` & `mitm-wrong-pin` rồi tự hồi phục khi `restore-tls`, `kill-agent --restart` dọn sạch `ledger.json`).
- **Hệ quả thực tế (Impact)**: Nguy cơ lọt lỗi data-plane hoặc lỗi treo `netcheck` qua bài test nghiệm thu tự động.
- **Hướng khắc phục cụ thể (Actionable Remedy — trong `lab/acceptance/`)**:
  1. Trong `verify_all_ten_pairs` của `test-udp-blocked-443-only.sh`, lấy thêm `overlay_ip` của từng peer từ `status --json` và chạy `ping -c 1 -W 3 "${peer_overlay_ip}"` xuyên qua TUN song song với `mesh ping`.
  2. Ở mục `AC4`, chạy `timeout 6 docker exec mesh-lab-node-1 /usr/local/bin/mesh netcheck --json` (không nuốt lỗi timeout) và dùng `jq -e` kiểm chứng chặt `.control_tcp_reachable == false and .udp_egress_ok == false and (.diagnostic_hint != null) and (.diagnostic_hint | test("443|TLS|firewall"; "i"))`.
  3. Bổ sung script smoke tự động `lab/acceptance/test-us057-lab-smoke.sh` chạy kiểm chứng nhanh các chế độ `eim`, `apdm`, `mtu-1400`, `captive-portal`, `mitm-wrong-pin`, `kill-agent --restart` và `power-resume`.

---

### 🟡 `[IMP-W12-02]` Củng cố tính tái lập của GitHub Actions (`ci.yml` & `release.yml`)
- **Vị trí**: `.github/workflows/ci.yml:106, 137, 173, 251, 337-339`, `.github/workflows/release.yml:61`
- **Chi tiết & Khuyến nghị**:
  - Đổi `dtolnay/rust-toolchain@master` sang nhánh/commit cố định hoặc cấu hình dựa trực tiếp trên `rust-toolchain.toml` để tránh rủi ro thay đổi upstream action ngoài ý muốn.
  - Cân nhắc chạy tự động kịch bản smoke nhanh (`--flap-duration 30`) trong job `docker-build-and-lab` khi push vào `main`/`sprint/**`, giữ vòng lặp 10 phút (`600s`) cho `workflow_dispatch` / trước Gate.

---

## 5. ⚖️ Đánh Đổi Chiến Lược & Lưu Ý Ranh Giới Sprint 1 → Sprint 2 (`Strategic Trade-offs`)

1. **Độ trung thực của `mesh ping` qua Disco vs ICMP trong mặt phẳng dữ liệu**:
   - Thiết kế hiện tại (`api-design.md` §3.3(d)) chọn gửi gói `DiscoPing`/`DiscoPong` có xác thực mật mã để phân biệt chính xác từng nhịp đi qua `relay` hay `direct` kèm địa chỉ `IP:port` vật lý (điều mà gói ICMP thuần trong TUN không tự biết được). Khi sửa `BLK-W12-02`, giữ cơ chế `DiscoPing` theo `tx_id` trong `ping_probe.rs` kết hợp kiểm thử `ping <overlay_ip>` thực tế ở `WP-S1-06` sẽ đảm bảo kiểm chứng trọn vẹn cả mặt phẳng điều khiển đường đi lẫn mặt phẳng mã hóa WireGuard.
2. **Phân tách phạm vi Sprint 1 (`WP-S1-05`/`06`) vs Sprint 2 (`WP-S2-01..04`)**:
   - Một số hook nâng cao đã được tạo sẵn khung trong `meshd` (`execute_bugreport`, `RoamingLoop` -> `RebindHandle`). Các lỗi làm hỏng hành vi ngay trong Sprint 1 (`BLK-W12-01..07`, `HR-W12-01..06`) **bắt buộc sửa ngay ở vòng Revise của Wave 1.2**; riêng việc đóng gói nén đầy đủ cho `mesh bugreport` (`US-041`) và tự động re-handshake sâu khi ngủ/thức trên phần cứng thật (`US-035`/`US-036`) giữ đúng lộ trình Sprint 2 sau khi kênh `roaming_control_rx` (`HR-W12-03`) và `libfaketime` (`BLK-W12-07`) đã được sửa sạch.

---

## 6. Bảng Phân Công Khắc Phục Theo Đúng Sở Hữu File (Action Plan)

| Gói việc chịu trách nhiệm | Danh sách mã lỗi cần xử lý dứt điểm | Phạm vi tệp được phép sửa |
|---|---|---|
| **`WP-S1-05`** (`agile-developer`) *(Scrum Master mở quyền chạm hẹp `mesh-datapath` cho `BLK-W12-02` nếu cần)* | `BLK-W12-01`, `BLK-W12-02`, `BLK-W12-03`, `BLK-W12-04`, `HR-W12-01`, `HR-W12-02`, `HR-W12-03`, `HR-W12-04`, `IMP-W12-01` | `crates/meshd/src/**`, `crates/mesh/src/**` *(+ hook probe hẹp trong `crates/mesh-datapath/src/{disco_engine.rs,engine.rs}` dưới điều phối của Scrum Master)* |
| **`WP-S1-06`** (`agile-devops` / `agile-qa`) | `BLK-W12-05`, `BLK-W12-06`, `BLK-W12-07`, `HR-W12-05`, `HR-W12-06`, `IMP-W12-02` | `.github/workflows/{ci.yml,release.yml}`, `Dockerfile`, `lab/**` |

---

## 7. Kết Luận Phán Quyết

- **Trạng thái**: 🔴 **`[REVISION REQUIRED]`**
- **Điều kiện thông qua vòng kiểm định kế tiếp**:
  1. Khắc phục triệt để **7 lỗi 🔴 `Blocker`** (`BLK-W12-01` .. `BLK-W12-07`) và **6 lỗi 🟠 `High Risk`** (`HR-W12-01` .. `HR-W12-06`) kèm unit/integration test hồi quy tương ứng.
  2. Toàn bộ bộ lệnh chuẩn `scripts/check.ps1 -Cross` / `scripts/check.sh`, `bash -n` trên mọi script `.sh`, và kịch bản nghiệm thu Docker NAT Lab chạy xanh thực chất (không dùng biểu thức khớp giả tạo).

---

## 8. Phụ Lục Tái Thẩm Định Vòng 2 (Round 2 Re-Verification)

- **Ngày tái thẩm định**: `2026-11-13`
- **Người tái thẩm định**: `agile-critic` (`gemini-4-carbon-high`)
- **Kết quả quét bất biến tĩnh (Read-Only Static Scan)**:
  - Đã kiểm tra trực tiếp **23 tệp Rust** (`crates/{meshd,mesh,mesh-datapath}/src/**/*.rs`) và **14 tệp DevOps/Lab/CI** (`Dockerfile`, `lab/**`, `.github/workflows/{ci.yml,release.yml}`): **0** UTF-8 BOM, **0** CRLF (**100% LF**), **0** `#[allow(...)]`, **0** `println!`/`eprintln!`/`dbg!`/`todo!`/`unimplemented!`, **0** `.unwrap()`/`.expect()`/`panic!()`/`unreachable!()` trong mã production, **0** `privileged: true` trong `lab/docker-compose.nat-lab.yml`.
  - Xác nhận đối chiếu chéo với `crates/mesh-server/src/control_handlers.rs:550-560` và `crates/mesh-server/src/listener_set.rs:347-349`: chữ ký thách thức cho `/v1/netmap/stream?known_version=<u64>` và upstream HTTP của `tls_mode = "reverse_proxy"` khớp 100% hợp đồng giữa Client, Reverse Proxy và Server.

### 8.1. Bảng Kiểm Chứng Từng Hạng Mục (`15/15 CLOSED` + Nhóm Phụ `mesh-admin`)

| Mã hạng mục | Gói việc | Trạng thái | Bằng chứng mã nguồn & Kiểm thử hồi quy (Line-by-Line Evidence) |
|---|---|---|---|
| `BLK-W12-01` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/meshd/src/main.rs:41-44, 186-198` bổ sung `#[arg(long, conflicts_with = "foreground")] service: bool`, định tuyến sang `service_windows::run_as_service(&paths)` trên Windows và từ chối tường minh ngoài SCM/ngoài Windows; `crates/meshd/src/service_windows.rs:27, 85-92` đồng bộ `WINDOWS_SERVICE_NAME = "MeshVpnAgent"` khớp `scripts/install-windows.ps1:27`. Có unit test `test_meshd_service_flag_parses_and_conflicts_with_foreground` (`main.rs:297-309`) và `service_windows.rs:353-354`. |
| `BLK-W12-02` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/meshd/src/ping_probe.rs:192-218` gọi `datapath.send_ping_probe(...)` thật trên mỗi `seq`; `crates/mesh-datapath/src/disco_engine.rs:375-442, 1009-1052` sinh `DiscoPing` mã hóa với `tx_id` ngẫu nhiên 96-bit (`count_toward_failover: false` để không làm lệch bộ đếm 3-strike nền); `crates/mesh-datapath/src/engine.rs:365-370, 779-909` chờ đúng `DiscoPong` khớp `tx_id` và trả `PingProbePath::Timeout` khi peer đích tắt nguồn/offline dù kênh Blind Relay cục bộ đang mở. Có test hồi quy `test_execute_ping_offline_peer_returns_100_percent_loss` (`ping_probe.rs:461-567`) và `test_datapath_send_ping_probe_returns_timeout_when_peer_offline_despite_relay_connected` / `test_datapath_send_ping_probe_and_handle_relayed_disco_return_measured_rtt` (`engine.rs:1894-2122`). |
| `BLK-W12-03` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/meshd/src/control_loop.rs:512-545, 1898-1927`: `wait_backoff_or_wake` trả `BackoffWaitOutcome::{TimerExpired, WakeSignal, Shutdown}` mà không tự ý xóa bộ đếm; `ControlLoop::run` chỉ gọi `reset()` khi phiên sống ổn định `>= 60 s` (`STABLE_SESSION_RESET_THRESHOLD`), khi chuyển cổng `ReconnectImmediately`, hoặc khi nhận `WakeSignal` (`ConfigUpdated` / sự kiện `RoamingLoop`), giữ nguyên đà tăng luỹ thừa tới trần `60 s` / `5 phút` khi hết timer ngủ bình thường. Có unit test `test_control_backoff_progresses_to_caps_and_resets_only_on_wake` (`control_loop.rs:2442-2525`). |
| `BLK-W12-04` | `WP-S1-05` | ✅ **`CLOSED`** | (1) `crates/meshd/src/control_loop.rs:1633-1843` thu thập ứng viên LAN IPv4 & global IPv6 qua `mesh_net::sysexec` (`ip`/`ifconfig`) + `probe_udp_routing_candidates`, lọc bỏ giao diện TUN và `CandidateFilterContext`; (2) `control_loop.rs:1645-1658` đẩy `DatapathCommand::SetAdvertisedEndpoints` xuống `DatapathEngine` (`engine.rs:655-665`); (3) `crates/meshd/src/supervisor.rs:935, 946, 1149-1162` phân giải và truyền `control_tcp_endpoint` vào `DatapathConfig` (`engine.rs:1066-1072`); (4) `control_loop.rs:1057-1066, 1092-1137` giải mã giới hạn kích thước và chuyển tiếp `CallMeMaybeRelay` qua `handle.handle_relayed_disco(...)` (`engine.rs:751-777`). Có unit test tại `control_loop.rs:2528-2598, 2764-2783` và `engine.rs:2078-2122`. |
| `HR-W12-01` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/meshd/src/control_loop.rs:1234-1248, 1292-1399` tách bước `stage_and_apply_control_migration`: thử nghiệm kết nối TLS 1.3 + `POST /v1/auth/challenge` tới endpoint mới thành công rồi mới lưu `server_endpoint` & nâng `acked_endpoint_version` vào `bootstrap.toml`; `crates/mesh-datapath/src/relay_client.rs:191-202, 429-439, 532-534, 576, 685` bổ sung `RelayClientHandle::update_config` qua `watch::channel` để đánh thức và chuyển nóng kênh Blind Relay ngay khi chạy `mesh set` hoặc nhận `RelayMap`/`PinSet` mới; `supervisor.rs:703-708` xóa sạch `active_pin`/`next_pin` khi chuyển sang `--ca-tls`. Có test `test_staged_control_migration_rolls_back_on_failure_and_commits_on_verified_tls` (`control_loop.rs:2630-2761`) và `test_supervisor_execute_set_clears_pins_on_system_ca_mode` (`supervisor.rs:1579-1613`). |
| `HR-W12-02` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/meshd/src/control_loop.rs:503-509` phát tín hiệu qua `termination_tx` khi nhận `NodeRevoked`/`NodeKeyExpired` trên kênh TLS xác thực; `crates/meshd/src/supervisor.rs:492-495, 509-542` thực thi `handle_verified_identity_termination`: hủy toàn bộ phiên datapath/relay/roaming, chạy `ledger.cleanup_all(...)` dọn sạch TUN/route/`hosts` và giữ nguyên trạng thái `DaemonState::Revoked` / `DaemonState::ReauthRequired` kèm `last_error` cho `mesh status`. Có unit test `test_supervisor_revocation_tears_down_datapath_and_cleans_ledger` (`supervisor.rs:1529-1576`). |
| `HR-W12-03` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/meshd/src/supervisor.rs:325, 431, 1010` lưu `roaming_control_rx: Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>` bền vững xuyên suốt vòng đời daemon và chia sẻ cho mọi `ControlLoopContext` mới thay vì `.take()`. Có unit test `test_supervisor_roaming_channel_persists_across_multiple_sessions` (`supervisor.rs:1489-1527`). |
| `HR-W12-04` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/mesh-datapath/src/relay_client.rs:984-1025` cung cấp `connect_bound_tcp_with_timeout` gắn `bind_underlay_socket2` (`IP_BOUND_IF`/`IP_UNICAST_IF`/`SO_MARK`) cho cả `connect_control_tls` (`control_loop.rs:2010-2031`) và `probe_tcp_reachability` (`ping_probe.rs:324-358`); `netcheck` giới hạn tổng ngân sách TCP `2.5 s` + STUN `0.6 s` (`~3.1 s < 5 s`, test tại `ping_probe.rs:571-582`); `supervisor.rs:109-111, 363, 1277-1313` fail-closed trên macOS khi binary/plist sai quyền `root` (`mode & 0o022 != 0`, test tại `supervisor.rs:1616-1634`); `read_http_response_exact` bọc timeout toàn cục (`control_loop.rs:2144-2157, 2612-2627`). |
| `IMP-W12-01` | `WP-S1-05` | ✅ **`CLOSED`** | `crates/meshd/src/control_loop.rs:682-685, 718-723` truyền `/v1/netmap/stream?known_version=<u64>` khi `known_version > 0` và vẫn ký canonical path `"/v1/netmap/stream"` (`line 667`) khớp tuyệt đối với `crates/mesh-server/src/control_handlers.rs:556-560`. Có unit test `test_build_netmap_stream_target_formats_known_version_query` (`control_loop.rs:2601-2609`). |
| `BLK-W12-05` + `USER mesh` | `WP-S1-06` | ✅ **`CLOSED`** | `Dockerfile:89-95, 105` tạo user `mesh` thuộc nhóm phụ `mesh-admin`, đặt `/run/mesh-server` `0750 mesh:mesh-admin` và dùng `USER mesh` (không ghi `:mesh` để OCI runtime giữ nguyên supplementary groups); `lab/docker-compose.nat-lab.yml:25, 28-30` khai báo `image: mesh-vpn/mesh-server:lab`, `user: mesh`, `group_add: [mesh-admin]`; `.github/workflows/ci.yml:360-367` và `.github/workflows/release.yml:278-281` kiểm chứng cả `uid != 0` lẫn `id -Gn` chứa `mesh-admin`. |
| `BLK-W12-06` | `WP-S1-06` | ✅ **`CLOSED`** | `.github/workflows/ci.yml:271-300` và `.github/workflows/release.yml:133-173, 222-246` tải `wintun-0.14.1.zip`, kiểm chứng cứng SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`, trích xuất `amd64\wintun.dll`, xuất `MESH_WINTUN_SHA256` vào `$GITHUB_ENV` **trước khi** biên dịch `meshd.exe`, và đóng gói đầy đủ `wintun.dll`, `wintun.dll.sha256`, `WINTUN-LICENSE.txt`, `scripts/install-windows.ps1` cùng `SHA256SUMS`. |
| `BLK-W12-07` | `WP-S1-06` | ✅ **`CLOSED`** | `lab/node/entrypoint.sh:65-68` nạp `FAKETIME_TIMESTAMP_FILE="${FAKETIME_FILE}"` + `FAKETIME_NO_CACHE=1` + `FAKETIME_DONT_FAKE_MONOTONIC=1`; `lab/faults/inject-fault.sh:186-215` cập nhật nguyên tử `faketime.rc` và đối chiếu `after_ts - before_ts >= jump_secs - 2`, thoát mã lỗi `!= 0` nếu đồng hồ không thực sự nhảy. |
| `HR-W12-05` | `WP-S1-06` | ✅ **`CLOSED`** | `lab/vps/proxy-entrypoint.sh:20-56, 78-89` sinh Lab Root CA (`CA:TRUE`) + chứng chỉ lá `SAN=DNS:vpn.mesh.internal,IP:172.28.0.12` và chuyển tiếp HTTP/1.1 + Upgrade sang upstream `mesh-server` (`listener_set.rs:347-349`); `lab/run-lab.sh:155-174, 183-254` chờ sẵn sàng `meshd-admin.sock` trên cả 5 node, cài `ca.crt` vào trust store hệ thống (`update-ca-certificates`) và đăng ký bằng `--ca-tls` (`TlsAuthMode::SystemCa`, tải động qua `rustls_native_certs` ở `tlspin.rs:244-251`) nên không bao giờ bị `PinMismatch` khi nhận `NetmapSnapshot`. |
| `HR-W12-06` | `WP-S1-06` | ✅ **`CLOSED`** | `lab/acceptance/test-udp-blocked-443-only.sh:101-110, 231-242` kiểm tra đồng thời `mesh ping` và `ping -c 1 -W 3 <peer_overlay_ip>` qua TUN thực cho cả 10/10 cặp, đồng thời dùng `mesh netcheck --json | jq -e` kiểm chứng chặt `.control_tcp_reachable == false and .udp_egress_ok == false and .stun_reachable == false`; bổ sung mới `lab/acceptance/test-us057-lab-smoke.sh:1-234` bao phủ tự động toàn bộ 6 kịch bản ma trận lỗi `US-057`. |
| `IMP-W12-02` | `WP-S1-06` | ✅ **`CLOSED`** | `.github/workflows/ci.yml:106-108, 137-139, 173-175, 251-253` và `.github/workflows/release.yml:61-63` đã ghim `dtolnay/rust-toolchain@stable` kèm `toolchain: "1.94.1"` đồng nhất toàn bộ workflow. |

---

### 8.2. ⚖️ Đánh Đổi Chiến Lược & Lưu Ý Bàn Giao (`Strategic Trade-offs`)

1. **Cấu trúc thư mục gói `.zip` Windows khi chạy `scripts/install-windows.ps1` (UX / Sprint 2 Polish)**:
   - Trong `.github/workflows/release.yml:222-228`, các tệp thực thi (`meshd.exe`, `mesh.exe`, `wintun.dll`, `wintun.dll.sha256`) đặt ở thư mục gốc của gói `.zip`, còn bộ cài đặt nằm tại `scripts/install-windows.ps1` (với mặc định `$SourceDir = $PSScriptRoot` ở `scripts/install-windows.ps1:17`). Khi quản trị viên giải nén và chạy từ thư mục gốc cần truyền `.\scripts\install-windows.ps1 -SourceDir .` (nếu quên, script tự động fail-closed an toàn với thông báo thiếu `wintun.dll.sha256` chứ không cài đặt sai). Có thể bổ sung fallback tìm `Split-Path -Parent $PSScriptRoot` ở gói hoàn thiện bộ cài Windows trong Sprint 2.
2. **Phạm vi STUN UDP trong chế độ `--tls-mode reverse_proxy` của Lab**:
   - Khi bật `--tls-mode reverse_proxy`, `vpn.mesh.internal` trỏ tới container Nginx `172.28.0.12` (chấm dứt TLS trên TCP 443), trong khi dịch vụ STUN UDP 3478 nằm trên container `vps` `172.28.0.10`. Topo này kiểm chứng trọn vẹn mặt phẳng Control + Blind Relay qua Reverse Proxy TCP 443 bằng SystemCA; nếu cần đo thêm nâng cấp P2P STUN qua tên miền chung trong các bài test mở rộng Sprint 2 có thể bật thêm `stream` UDP proxy trên Nginx hoặc tách bản ghi STUN.
3. **Bàn giao sạch sang Sprint 2 / QA Gate**:
   - Toàn bộ nền tảng CLI, Daemon Supervisor, IPC 2 kênh, Control/Data-plane, Docker NAT Lab không đặc quyền (`NET_ADMIN` + `/dev/net/tun`) và CI/CD 4-target của Sprint 1 Wave 1.2 đã khép kín, không còn nợ kỹ thuật mức `Blocker` hay `High Risk`.

---

### 8.3. Phán Quyết Cuối Cùng Vòng 2

- **Phán quyết**: 🟢 **`[APPROVED FOR GATE]`**
- **Tóm tắt**: Toàn bộ **7/7 `Blocker`**, **6/6 `High Risk`**, **2/2 `Improvement`** và cấu hình nhóm phụ `USER mesh` / `mesh-admin` đã được khắc phục triệt để, có kiểm thử hồi quy xác thực và tuân thủ 100% chuẩn kiến trúc/bảo mật của dự án. Đủ điều kiện chuyển sang bước kiểm thử độc lập `agile-qa` và trình duyệt Cổng Gate tiếp theo.
