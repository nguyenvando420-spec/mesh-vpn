# Production-Readiness Requirements — Mesh VPN cá nhân kiểu Tailscale trên 1 VPS

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-researcher` |
| Ngày | 2026-11-12 |
| Giai đoạn | 1 — Discovery (trước Gate 1) |
| Đầu vào | [reference-systems-benchmark.md](./reference-systems-benchmark.md) (mã nguồn `[Tn]` dùng chung với file này) |
| Người nhận | `agile-po-ba` (chuyển thành User Stories/NFR), `agile-architect`, `agile-tech-lead` |
| Thành phần AI | **Không có** → không áp dụng mục chất lượng/guardrails AI |

> **Quy ước**
> - Mã yêu cầu: `SEC-*` (Security), `REL-*` (Reliability), `OPS-*` (Observability & Operations), `PERF-*` (Performance/SLO), `PLAT-*` (Đặc thù nền tảng Windows/Linux).
> - Mức ưu tiên: **P0** = bắt buộc cho MVP (không có thì không được dùng 24/7); **P1** = nên có trong MVP/ngay sau; **P2** = Phase 2+.
> - Con số SLO là **đề xuất ban đầu của researcher** (chưa đo), trừ chỗ có dẫn nguồn. `agile-mlops-eval` không áp dụng; `agile-qa` sẽ đo thực tế.

> [!IMPORTANT]
> **Ranh giới Gate 1 (What) và Gate 2 (How) — khắc phục `IMP-01`**
> Mọi **tên công nghệ, thư viện hoặc cơ chế cụ thể** trong tài liệu này được đánh dấu *(KN)*. Ví dụ: `SQLite chế độ WAL`, `PRAGMA integrity_check`, `VACUUM INTO`/SQLite Online Backup API, `Prometheus text exposition`, `goroutine`, `Wintun`, `wireguard-go`, `ufw/nftables`, `systemd`, `Unix Domain Socket`, `named pipe`, `NaCl box/Noise IK`, `TLS-ALPN-01`.
> Các mục *(KN)* là **khuyến nghị tham chiếu mặc định rút ra từ nghiên cứu hệ thống thực tế**, **không phải** quyết định đã chốt. Quyết định cuối cùng thuộc **ADR của `agile-tech-lead`** và **thiết kế của `agile-architect` tại Gate 2**.
> Phần **bắt buộc (P0)** của mỗi yêu cầu là **hành vi/thuộc tính quan sát được** ghi trong cột *Tiêu chí chấp nhận*. Nếu thay bằng công nghệ khác thì công nghệ đó phải đạt cùng tiêu chí.

### Lịch sử sửa đổi

| Phiên bản | Ngày | Nội dung |
|---|---|---|
| v1.0 | 2026-11-12 | Bản đầu trình `agile-critic` |
| v1.1 | 2026-11-12 | Khắc phục `gate-1-critique.md` vòng 1: **`BLK-01`** (tách kênh Admin khỏi kênh quan sát chỉ-đọc; thêm SEC-14; viết lại SEC-06, OPS-05, OPS-06, OPS-08), **`HR-01`** phần thuộc tài liệu này (firewall opt-in, giữ SSH/dịch vụ sẵn có, chế độ chạy sau Reverse Proxy, `trusted_proxies` ở SEC-05, ACME ở SEC-04), **`IMP-01`** (đánh dấu *(KN)*) |

---

## 0. Mô hình mối đe dọa tóm tắt (để hiểu vì sao có các yêu cầu bên dưới)

| Tác nhân/Sự cố | Mục tiêu/Hậu quả | Yêu cầu phòng vệ chính |
|---|---|---|
| Kẻ quét Internet đánh vào VPS | Đoán pre-auth key, DoS control plane | SEC-04, SEC-05, SEC-06 |
| Người lạ dùng ké relay | Tiêu hao băng thông/quota VPS | SEC-07 |
| Mất/bị trộm laptop | Truy cập vào mạng nhà | SEC-03, SEC-08 |
| Node bị trộm/bị chiếm (MVP full-mesh không có ACL) gọi API quản trị của VPS qua tunnel | Tự tạo pre-auth key, tắt hạn khóa, thu hồi ngược máy của chủ mạng → **chiếm toàn mạng** (`BLK-01`) | **SEC-14**, SEC-06 |
| Tiến trình không đặc quyền khác trên VPS dùng chung (web app cá nhân, container, lỗi SSRF) gọi cổng TCP `127.0.0.1` | Chiếm quyền Admin Control Plane (`BLK-01`) | **SEC-14** |
| Cài đặt/hardening áp lên VPS đang chạy dịch vụ khác | Sập web cá nhân sẵn có, khóa mất SSH cổng tùy chỉnh (`HR-01`) | SEC-06 |
| VPS bị chiếm quyền | Đọc metadata, chèn node giả vào netmap [T19] | SEC-01, SEC-09, SEC-10 (P2: ký node key) |
| Mạng chặn UDP / CGNAT kép | Không kết nối được | REL-05, REL-06 |
| VPS khởi động lại / mất mạng | Đứt toàn bộ kết nối | REL-01 |
| Agent crash / tắt máy đột ngột | Hỏng mạng máy thật (route/DNS/adapter mồ côi) | REL-08, PLAT-01..04 |

---

## 1. Security & Zero-Trust Identity

| Mã | Ưu tiên | Yêu cầu | Tiêu chí chấp nhận (kiểm chứng được) | Nguồn/Lý do |
|---|---|---|---|---|
| **SEC-01** | P0 | **Khóa Curve25519 sinh tại client, private key không bao giờ rời client.** Server chỉ nhận/lưu public key. | (a) Không API/thông điệp nào của server có trường private key; (b) review mã + test grep log/DB/traffic không có private key; (c) file khóa: Linux `0600` owner root, Windows ACL chỉ SYSTEM + Administrators *(KN: hoặc DPAPI)*; (d) private key không xuất hiện trong log, crash dump, lệnh `status`/bundle chẩn đoán | Tailscale [T2], innernet [T30], DERP [T3] |
| **SEC-02** | P0 | **Không tự viết mật mã.** Data plane dùng WireGuard (thư viện chuẩn); kênh control dùng TLS 1.2+ (khuyến nghị 1.3) + chứng minh sở hữu khóa node bằng cấu trúc chuẩn *(KN: NaCl box hoặc Noise IK)* với challenge/nonce ngẫu nhiên từ server. | Không có mã tự cài đặt cipher/MAC/KDF; mọi primitive lấy từ thư viện được kiểm định; tài liệu ADR ghi rõ thư viện | Nguyên tắc "Don't roll your own crypto"; Curve25519 chỉ DH, không ký được [T3][T7] |
| **SEC-03** | P0 | **Pre-Auth Key**: ngẫu nhiên ≥128 bit, **one-time** mặc định (tùy chọn reusable có giới hạn số lần), **TTL** bắt buộc (mặc định đề xuất 1 giờ, tối đa 90 ngày như Tailscale), tùy chọn **ephemeral** (node tự xóa khi offline quá X phút). Chỉ lưu **hash** (vd. SHA-256 có so sánh constant-time). Thu hồi được trước hạn. | (a) Dùng lại key one-time → bị từ chối; (b) key hết TTL → từ chối; (c) DB không chứa key dạng rõ; (d) node ephemeral offline > ngưỡng → biến mất khỏi netmap | Tailscale auth keys 1–90 ngày, one-off/reusable/ephemeral [T15] |
| **SEC-04** | P0 | **TLS cho Control Plane và Relay** trên 443. Ba trường hợp: (a) **Standalone**: dịch vụ tự giữ cổng 443, xin chứng chỉ ACME bằng phương thức **không cần mở cổng 80** *(KN: `TLS-ALPN-01` trên 443, hoặc `DNS-01`)*; (b) **Sau Reverse Proxy sẵn có** (xem SEC-06): TLS kết thúc ở proxy của người dùng, đoạn proxy → dịch vụ chỉ đi qua loopback/socket cục bộ; (c) **Không có domain**: client **pin** khóa/chứng chỉ server được phân phối lúc cài đặt. Bản release không có chế độ "bỏ qua kiểm tra chứng chỉ". | Test MITM với chứng chỉ giả → client từ chối; ở chế độ (a) chứng chỉ tự gia hạn được khi cổng 80 đóng; cảnh báo trước hạn 14 ngày | Gánh nặng TLS của Headscale [T22]; `HR-01` |
| **SEC-05** | P0 | **Rate limiting & chống brute-force** trên endpoint đăng ký/xác thực: giới hạn theo IP nguồn (vd. đề xuất ≤10 lần thất bại/5 phút/IP → khóa tạm 15 phút, tăng dần), giới hạn tổng số yêu cầu đăng ký/phút; phản hồi lỗi **không phân biệt** "key sai" và "key hết hạn". **IP nguồn thật**: mặc định chỉ dùng địa chỉ của kết nối TCP. Header IP chuyển tiếp (vd. `X-Forwarded-For`, PROXY protocol) **chỉ được tin** khi kết nối đến từ một nguồn trong danh sách `trusted_proxies` mà người dùng **bật tường minh** (mặc định rỗng/tắt). | (a) Test bắn 100 key sai/phút → bị chặn sau ngưỡng; log audit có ghi; (b) chế độ Standalone: gửi header `X-Forwarded-For` giả → bị bỏ qua, rate-limit vẫn áp theo IP TCP; (c) chế độ Reverse Proxy có `trusted_proxies`: rate-limit áp theo IP client thật, **không** khóa nhầm `127.0.0.1` (không làm sập toàn bộ đăng ký) | Persona: chống lạm dụng; `HR-01` |
| **SEC-06** | P0 | **Giảm bề mặt tấn công nhưng an toàn với VPS đang dùng chung.** (1) **Cổng public tối thiểu của dịch vụ**: 443/TCP (control + relay, hoặc do reverse proxy sẵn có đảm nhiệm), 3478/UDP (STUN), cổng UDP của agent trên VPS (nếu VPS là một node). Không cổng nào khác của dịch vụ được lắng nghe trên địa chỉ public. **Không có cổng Admin trên mạng** (xem SEC-14). (2) **Hai chế độ triển khai cổng 443**: **Standalone** (tự giữ 443) hoặc **sau Reverse Proxy sẵn có** của người dùng (Nginx/Caddy…): dịch vụ chỉ lắng nghe cục bộ, nhận chuyển tiếp HTTP + HTTP Upgrade/WebSocket cho relay. Chế độ thứ hai bắt buộc kèm cấu hình `trusted_proxies` (SEC-05). (3) **Firewall là `opt-in` có xác nhận**: trình cài đặt/hardening **không được tự động** bật chính sách mặc định deny. Nếu người dùng chọn bật: (i) tự phát hiện và **giữ cổng SSH đang hoạt động** (kể cả cổng tùy chỉnh khác 22, đọc từ cấu hình `sshd` và socket đang lắng nghe); (ii) liệt kê các **cổng dịch vụ đang lắng nghe sẵn có** trên VPS và mặc định giữ nguyên; (iii) hiển thị bộ quy tắc sẽ áp (dry-run), yêu cầu xác nhận, có cơ chế **tự hoàn tác** nếu không xác nhận lại kết nối trong khoảng thời gian ngắn *(KN: kiểu "confirm or rollback" sau 60–120 s)*. Chỉ **thêm** quy tắc cho cổng của dịch vụ, không xóa quy tắc có sẵn. (4) **Đặc quyền tối thiểu**: dịch vụ chạy dưới user hệ thống riêng, không đặc quyền; chỉ cấp capability mạng cần thiết khi VPS là node *(KN: `CAP_NET_ADMIN`, unit systemd có `NoNewPrivileges`, `ProtectSystem`)*. | (a) `nmap` từ ngoài: dịch vụ chỉ lộ đúng các cổng ở (1); **không có cổng admin nào** trên IP public lẫn IP overlay; (b) cài lên VPS mẫu đang chạy web 443 + SSH cổng 2222 ở chế độ Reverse Proxy: web cũ vẫn chạy, SSH 2222 vẫn vào được, không có quy tắc firewall nào bị thay đổi khi người dùng không opt-in; (c) opt-in firewall nhưng không xác nhận → quy tắc tự hoàn tác, SSH không bị khóa; (d) tiến trình dịch vụ không chạy dưới root (trừ thành phần cần cấu hình mạng khi VPS là node) | Hardening chuẩn; `BLK-01`, `HR-01` |
| **SEC-14** | P0 | **Tách kênh Quản trị (Admin Control) khỏi kênh Quan sát chỉ-đọc (khắc phục `BLK-01`).** (1) **Kênh Admin** gồm mọi thao tác thay đổi trạng thái: tạo/thu hồi pre-auth key, thu hồi/hết hạn/đổi tên node, đổi cấu hình, backup/restore, thay đổi ACL sau này. Kênh này **chỉ** được truy cập qua một **kênh cục bộ trên VPS mà OS kiểm chứng được đặc quyền của bên gọi**, cụ thể là một trong hai: (i) **Unix Domain Socket** thuộc `root` hoặc user dịch vụ, nhóm quản trị dịch vụ riêng, quyền `0600`/`0660`, nằm trong thư mục không cho user khác ghi; server **xác minh thêm danh tính tiến trình gọi** *(KN: `SO_PEERCRED`)* và chỉ chấp nhận `root`/user dịch vụ/thành viên nhóm quản trị; (ii) **thao tác trực tiếp dưới quyền quản trị qua SSH** (CLI chạy trên VPS, đọc/ghi qua (i) hoặc thao tác cục bộ có khóa DB). (2) **TUYỆT ĐỐI CẤM**: (a) mở Admin API (dù có hay không có xác thực bằng token tĩnh) trên **IP overlay**, vì MVP là full-mesh không ACL nên một node bị trộm sẽ chiếm được quyền Admin; (b) mở Admin API trên **TCP `127.0.0.1`/`::1` trần**, vì VPS dùng chung còn chạy web/container/dịch vụ khác và TCP loopback không phân biệt được `root` với tiến trình không đặc quyền hay lỗi SSRF; (c) mở Admin API trên IP public; (d) chèn endpoint Admin vào cùng listener với control/relay public. (3) **Kênh quan sát chỉ-đọc** (`/healthz`, `/readyz`, `/metrics`) là listener **riêng**, **không có bất kỳ hành động thay đổi trạng thái nào**, không trả về secret (xem OPS-05/OPS-06). (4) Phase 2 (khi có Web UI/quản trị từ xa): Admin từ xa phải có **xác thực quản trị riêng** (không suy ra từ việc "là node trong mesh") kèm ACL giới hạn node quản trị. Đây là mục P2, ngoài MVP. | (a) Từ một node mesh bất kỳ (mô phỏng laptop bị trộm): quét toàn bộ cổng TCP/UDP trên IP overlay của VPS → **không** có endpoint nào thực hiện được thao tác Admin; (b) trên VPS, dưới user không đặc quyền (vd. `www-data`, tiến trình trong container): gọi CLI admin/kết nối socket admin → **bị từ chối** (lỗi quyền OS + server kiểm tra peer credential); (c) dưới `root` hoặc thành viên nhóm quản trị qua SSH → thao tác thành công và sinh audit log (SEC-09) ghi UID/user gọi; (d) `ss -ltnp` không có listener admin trên TCP; (e) request SSRF giả lập tới mọi cổng loopback TCP của dịch vụ → không thực hiện được thao tác thay đổi trạng thái nào | `BLK-01`; Headscale quản trị qua CLI cục bộ [T21] |
| **SEC-07** | P0 | **Relay chỉ phục vụ node đã đăng ký và còn hiệu lực**: kết nối relay phải chứng minh sở hữu node key; frame tới public key không tồn tại/không được phép → drop; **giới hạn băng thông mỗi node** (đề xuất cấu hình được, mặc định vd. 20 Mbps/node) và **trần tổng** để bảo vệ quota VPS; ngắt ngay kết nối relay của node bị thu hồi. | (a) Client không đăng ký kết nối relay → bị từ chối; (b) node bị thu hồi → kết nối relay bị đóng trong ≤5 s; (c) test vượt hạn mức → bị throttle | Lỗ hổng relay mở; `derper -verify-clients` [T24] |
| **SEC-08** | P0 | **Node Revocation & Key Expiry**: lệnh admin `revoke <node>` có hiệu lực tức thì: xóa khỏi netmap mọi node, agent các peer **gỡ peer khỏi WireGuard (cắt cả tunnel đang sống)**, relay ngắt kết nối. Node key có **hạn sử dụng** (đề xuất mặc định 180 ngày như Tailscale, cho phép tắt cho server tin cậy); node hết hạn phải đăng ký lại. | Thu hồi laptop → trong ≤10 s (P95, khi control online) không peer nào còn handshake được với laptop đó; test key hết hạn | Tailscale key expiry 180 ngày [T16]; bài học Nebula blocklist thủ công [T29] |
| **SEC-09** | P0 | **Audit Log** cho thao tác quan trọng: tạo/thu hồi pre-auth key, đăng ký node, thu hồi/hết hạn node, đổi tên/IP, đăng nhập admin, lỗi xác thực vượt ngưỡng. Log dạng append-only có timestamp UTC, actor, node_id, IP nguồn; **không chứa secret**. | Mỗi thao tác trên sinh đúng 1 bản ghi; không có pre-auth key rõ/private key trong log | Persona: Audit log |
| **SEC-10** | P1 | **Agent kiểm tra tính hợp lệ netmap**: từ chối peer có IP overlay ngoài dải, trùng IP, public key trùng; chỉ chấp nhận cập nhật có `netmap_version` tăng; cảnh báo khi số peer thay đổi bất thường. | Test chèn netmap độc → agent từ chối và log cảnh báo | Rủi ro control bị chiếm [T19] |
| **SEC-11** | P1 | **Packet filter tối thiểu trong agent**: chỉ nhận traffic từ dải overlay trên interface tunnel; tùy chọn chặn inbound tới một số cổng; tôn trọng `AllowedIPs` = đúng /32 của từng peer (không cấp dải rộng). | `AllowedIPs` mỗi peer chỉ là IP overlay /32 (và /128 nếu có IPv6) | Cryptokey routing [T12] |
| **SEC-12** | P2 | Ký node key bằng khóa trên thiết bị tin cậy (kiểu **Tailnet Lock**) để VPS bị chiếm vẫn không chèn được node giả. | — | [T19] |
| **SEC-13** | P2 | OIDC/SSO, đa người dùng, ACL theo nhóm/tag. | — | Headscale, NetBird [T21][T25] |

---

## 2. Reliability & Network Resilience

| Mã | Ưu tiên | Yêu cầu | Tiêu chí chấp nhận | Nguồn/Lý do |
|---|---|---|---|---|
| **REL-01** | P0 | **Tách rời Control Plane và Data Plane**: khi control server restart/mất kết nối, agent giữ **netmap đã cache** (cả trong RAM và trên đĩa), tunnel P2P đang chạy **không bị gỡ**, keepalive/rekey WireGuard tiếp tục. Agent khởi động lại khi control offline vẫn dựng lại tunnel từ cache (trong hạn key). | Kịch bản test: 5 node đang P2P → `systemctl stop` control 30 phút → ping giữa các node **0% mất gói do control** (chỉ chấp nhận mất do mạng); restart agent khi control offline → tunnel P2P lên lại từ cache | Tailscale: tunnel đang chạy tiếp tục khi coordination server chết [T5] |
| **REL-02** | P0 | **Đăng ký idempotent**: định danh node theo public key; gửi lại yêu cầu đăng ký cùng public key (do timeout/retry) **không tạo node trùng**, **không cấp IP mới**, **không tiêu hao pre-auth key thêm lần nữa** nếu lần trước đã thành công. IP overlay **bền vững** qua các lần khởi động lại. | Test: gửi cùng yêu cầu đăng ký 3 lần song song → đúng 1 node, 1 IP; DB có ràng buộc UNIQUE(public_key), UNIQUE(overlay_ip) | Persona: Idempotency |
| **REL-03** | P0 | **Netmap có version**: mỗi thay đổi tăng `netmap_version` đơn điệu; agent bỏ qua bản cũ hơn; khi kết nối lại gửi version đang có, server trả snapshot đầy đủ (MVP) hoặc delta (P2). Áp dụng netmap vào WireGuard theo kiểu **diff (thêm/sửa/xóa peer)**, không gỡ toàn bộ rồi dựng lại. | Áp netmap mới không làm rớt tunnel của peer không thay đổi (test: thêm 1 node → không mất gói giữa các node cũ) | Tailscale full + delta [T7] |
| **REL-04** | P0 | **Kết nối lại với Exponential Backoff + Jitter** cho mọi kết nối tới VPS (control stream, relay, STUN): ví dụ đề xuất base 1 s, hệ số 2, trần 60 s, full jitter; reset backoff khi kết nối ổn định > 1 phút; **timeout** rõ ràng cho mọi I/O mạng (connect ≤10 s, đọc stream có heartbeat ≤60 s). | Khi VPS chết 10 phút với 20 agent: không có "bão kết nối" đồng bộ khi VPS sống lại (phân bố thời điểm kết nối lại trải đều) | Persona: Retry/Timeout; WireGuard cũng dùng jitter cho handshake [T34] |
| **REL-05** | P0 | **Phát hiện peer chết & chuyển mạch P2P ↔ Relay**: disco ping/heartbeat định kỳ trên đường direct (đề xuất mỗi 5–10 s khi có traffic); nếu mất N pong liên tiếp hoặc không có handshake WireGuard mới trong khoảng tương ứng `REKEY_TIMEOUT` → chuyển gói sang relay **ngay**; tiếp tục dò direct ở nền và **nâng cấp lại** khi direct thông. Lưu lượng **luôn có đường đi** (relay là đường khởi đầu mặc định cho tới khi direct được xác nhận). | Xem PERF-05/PERF-06; test chặn UDP giữa 2 node bằng firewall → traffic tiếp tục qua relay trong ngưỡng | Tailscale: bắt đầu qua DERP rồi nâng cấp [T1]; disco heartbeat [T8]; timers WG [T34] |
| **REL-06** | P0 | **Relay TLS/TCP 443 luôn khả dụng làm đường cuối**: kể cả mạng chỉ cho phép 80/443 TCP (khách sạn, công ty) vẫn kết nối được. | Test trên mạng giả lập chặn toàn bộ UDP → mọi cặp node vẫn ping được qua relay | DERP 443 [T3]; innernet không relay → thất bại [T32] |
| **REL-07** | P0 | **Xử lý roaming & sleep/wake**: theo dõi sự kiện đổi mạng của OS; khi đổi IP/gateway hoặc phát hiện nhảy thời gian sau sleep: rebind socket (có retry khi interface chưa sẵn sàng), STUN lại, đẩy endpoint mới lên control, disco ping lại, dùng relay trong lúc chờ. NAT keepalive ~25 s trên đường direct. | Xem PERF-07; test chuyển Wi-Fi → hotspot 4G, sleep 30 phút → wake | Tailscale sleep/wake issues [T14]; keepalive 25 s [T12] |
| **REL-08** | P0 | **Graceful Shutdown & tự dọn dẹp**: khi dừng service (SIGTERM, `systemctl stop`, Windows Service Stop, tắt máy) agent phải gỡ route overlay, khôi phục DNS/hosts, xóa interface/adapter tunnel, đóng kết nối relay/control (báo offline). **Khi khởi động** agent phải phát hiện và dọn tàn dư của lần crash trước (adapter ma, route mồ côi, khối hosts cũ) trước khi dựng mới. Có lệnh `down`/`cleanup` thủ công. | Test: `kill -9` agent → khởi động lại → không còn route/adapter/hosts trùng lặp; máy vẫn ra Internet bình thường ở mọi bước; dừng service → bảng route và DNS trở về như trước khi cài | Windows adapter ma/route mồ côi [T20] |
| **REL-09** | P0 | **Chống routing loop**: socket UDP của agent **không bao giờ** đi qua interface tunnel *(KN: Linux dùng `fwmark` + policy rule kiểu `wg-quick`; Windows dùng cơ chế tách đường socket/route do Architect chốt ở Gate 2 để không để lại route mồ côi)*; lọc endpoint ứng viên thuộc dải overlay; MVP chỉ cài route cho dải overlay (không default route). | Test: VPS vừa là relay vừa là node; thêm route sai cố ý → agent phát hiện và từ chối; không trường hợp nào máy mất kết nối Internet | WireGuard netns/fwmark [T36] |
| **REL-10** | P0 | **MTU an toàn**: MTU interface tunnel mặc định **1280**, cấu hình được; frame relay tính đủ header. | Test SCP file 100 MB + `curl` HTTPS trang lớn qua tunnel trên đường PPPoE/4G mô phỏng (MTU ngoài 1400) không treo | Tailscale 1280 [T11]; overhead WG 60/80 byte [T37] |
| **REL-11** | P0 | **Toàn vẹn dữ liệu Control Server**: lưu trữ bền vững có giao dịch ACID *(KN: `SQLite chế độ WAL`)*, thao tác cấp IP + tạo node trong **1 transaction**; migration schema có version và chạy được lại; kiểm tra tính toàn vẹn DB khi khởi động *(KN: `PRAGMA integrity_check`)*. | Kill -9 server giữa lúc đăng ký → không có node "nửa vời"/IP bị cấp mà không có node | Headscale/innernet SQLite [T21][T31] |
| **REL-12** | P0 | **Backup & Restore** DB control: backup tự động định kỳ (đề xuất mỗi ngày + trước mỗi migration) bằng cơ chế sao lưu nóng an toàn khi đang chạy *(KN: SQLite Online Backup API / `VACUUM INTO`)*, giữ N bản (vd. 7 ngày), kiểm tra checksum (tùy chọn P1: đồng bộ bản sao mã hóa ra ngoài VPS); **quy trình restore đã được diễn tập**. Backup **không cần** chứa private key client (vì server không có). | Diễn tập: xóa DB → restore bản gần nhất → mọi node kết nối lại với IP cũ không cần đăng ký lại | Persona: chiến lược sao lưu |
| **REL-13** | P1 | **Supervisor tự khởi động lại**: trình quản lý dịch vụ của OS tự khởi động lại khi lỗi *(KN: `systemd` `Restart=on-failure` cho server/agent Linux; Windows Service Recovery cho agent Windows)*; agent tự chạy khi boot. | Kill tiến trình → tự sống lại ≤10 s | Vận hành 24/7 |
| **REL-14** | P1 | **Xử lý xung đột dải IP**: khi khởi động agent kiểm tra dải overlay có trùng địa chỉ interface vật lý (vd. WAN CGNAT 100.64.x.x) → cảnh báo rõ ràng, không cài route chồng chéo. | Test giả lập interface vật lý 100.64.1.5/10 | RFC 6598 [T33] |
| **REL-15** | P2 | HA control plane, nhiều relay/region, relay UDP/QUIC, đục lỗ hard NAT (birthday paradox). | — | [T1][T26] |

---

## 3. Observability & Operations

| Mã | Ưu tiên | Yêu cầu | Tiêu chí chấp nhận | Nguồn/Lý do |
|---|---|---|---|---|
| **OPS-01** | P0 | **Structured logging** (JSON hoặc logfmt) ở cả server và agent: `ts`, `level`, `component` *(KN: tên module theo thiết kế Gate 2, vd. control/relay/stun/disco/wg/dns/route)*, `node_id`, `peer_id`, `conn_id`/`request_id` (correlation), `event`. Log rotation có giới hạn dung lượng. **Cấm** log secret (private key, pre-auth key, token). | Kiểm tra mẫu log; test grep secret = 0 kết quả; log không vượt hạn mức dung lượng cấu hình | Persona: Structured logging |
| **OPS-02** | P0 | **CLI chẩn đoán `status`**: liệt kê mỗi peer: tên, IP overlay, online/offline, **đường đi hiện tại (direct `ip:port` / relay)**, RTT gần nhất, handshake WireGuard gần nhất, rx/tx bytes; trạng thái kết nối control & relay; netmap version; endpoints của chính mình (LAN/STUN). | Lệnh trả kết quả ≤1 s; đường đi phản ánh đúng thực tế khi chặn/mở UDP | Tailscale `status` [T17] |
| **OPS-03** | P0 | **CLI `ping <peer>`**: ping ở tầng disco/overlay, in **từng lần** đi qua đâu (relay → direct khi nâng cấp) + RTT; tùy chọn ép thử direct. | Quan sát được lần ping đầu qua relay, sau đó "pong from … via direct ip:port" | Tailscale `ping` [T17] |
| **OPS-04** | P1 | CLI `netcheck`: kiểm tra UDP ra ngoài, STUN, phân loại mapping NAT (EIM hay phụ thuộc đích — so sánh port trả về từ 2 đích STUN khác nhau), độ trễ tới relay, có IPv6 không. | Báo đúng "hard NAT" trên mạng 4G CGNAT thử nghiệm | Tailscale netcheck; RFC 4787 [T10] |
| **OPS-05** | P0 | **Healthcheck trên VPS**: `/healthz` (liveness: tiến trình sống) và `/readyz` (readiness: DB mở được, listener 443 + STUN 3478 hoạt động, relay nhận kết nối). Đây là **listener quan sát chỉ-đọc riêng biệt**, tuyệt đối **không dùng chung với kênh Admin** (tham chiếu `SEC-14`), không có bất kỳ thao tác thay đổi trạng thái hệ thống nào và không lộ thông tin nhạy cảm/secret. | `curl` trả 200 khi khỏe, 503 khi DB lỗi; listener không chứa bất kỳ route quản trị nào (`SEC-14`) | Persona: Healthcheck; `BLK-01` |
| **OPS-06** | P1 | **Metrics tối thiểu** *(KN: định dạng `Prometheus text exposition`)* trên **listener quan sát chỉ-đọc riêng biệt** (chỉ bind localhost/overlay tùy cấu hình, tuyệt đối **không dùng chung với kênh Admin** theo `SEC-14`, không thay đổi trạng thái hệ thống và không lộ secret): số node online, số kết nối relay, bytes relay theo node, số lần đăng ký thành công/thất bại, số lần rate-limit, độ dài long-poll đang mở, RAM và số luồng thực thi *(KN: `goroutine`/thread)*. Agent: số peer direct vs relay. | Endpoint `/metrics` chỉ-đọc hoạt động, không lộ secret và tách rời hoàn toàn khỏi kênh Admin (`SEC-14`); có tài liệu danh mục metric | Persona: Metrics; `BLK-01`, `IMP-01` |
| **OPS-07** | P1 | **Cảnh báo cá nhân tối giản**: script/timer kiểm tra `/readyz`, hạn chứng chỉ TLS (<14 ngày), dung lượng đĩa, băng thông relay vượt ngưỡng, node key sắp hết hạn (<7 ngày) → gửi thông báo (email/Telegram/webhook — tùy người dùng). | Mô phỏng từng điều kiện → nhận được thông báo | Persona: Alerting |
| **OPS-08** | P0 | **CLI quản trị server**: `preauthkey create/list/revoke`, `node list/rename/revoke/expire`, `backup now`, `version`. Giao tiếp **chỉ** qua kênh cục bộ kiểm chứng được đặc quyền OS theo `SEC-14` *(KN: Unix Domain Socket quyền `0600`/`0660` kèm kiểm tra `SO_PEERCRED`, hoặc thao tác trực tiếp dưới quyền quản trị qua SSH)*, **tuyệt đối không** đi qua TCP loopback trần hay IP overlay. Không cần Web UI ở MVP. | Thao tác end-to-end bằng CLI dưới quyền root/admin qua SSH thành công; user thường trên VPS hoặc node trên mạng overlay bị từ chối (`SEC-14`) | Headscale CLI [T21]; `BLK-01` |
| **OPS-09** | P1 | **Bundle chẩn đoán** (`bugreport`): gom log gần nhất, `status`, bảng route, cấu hình đã **lọc secret** để tự gỡ lỗi. | Bundle không chứa private key/pre-auth key | Thực hành Tailscale |
| **OPS-10** | P1 | **Versioning & tương thích giao thức**: client gửi `protocol_version`/`agent_version`; server từ chối rõ ràng phiên bản quá cũ; nâng cấp server không làm đứt tunnel đang chạy (nhờ REL-01). | Test client phiên bản N-1 với server N | Vận hành lâu dài |

---

## 4. Performance & Resource Targets (SLO đề xuất)

> Hồ sơ phần cứng VPS giả định: 1–2 vCPU, 1–2 GB RAM, 3–20 node. **Tất cả là đề xuất ban đầu**, cần `agile-qa` đo xác nhận; chỉ con số có nguồn mới được coi là tham chiếu ngành.

| Mã | Chỉ số | Mục tiêu đề xuất | Cách đo | Tham chiếu |
|---|---|---|---|---|
| **PERF-01** | RAM control+STUN+relay trên VPS khi rảnh (20 node, không có traffic relay) | **< 64 MB** RSS (mục tiêu), **≤ 128 MB** (trần chấp nhận) | `ps`/cgroup memory sau 24 h chạy | Headscale báo cáo cộng đồng ~50–100 MB idle [T23] (nguồn thứ cấp) |
| **PERF-02** | CPU VPS khi rảnh | **< 2%** của 1 vCPU trung bình 5 phút | `pidstat` | Headscale < 1% idle [T23] (thứ cấp) |
| **PERF-03** | Độ trễ cộng thêm trên đường **direct P2P** so với ping gốc giữa 2 máy | **≤ 2 ms** ở P95 (cùng LAN hoặc qua Internet) | So sánh `ping` IP thật vs IP overlay, 1000 mẫu | Đề xuất (WireGuard userspace overhead thấp) |
| **PERF-04** | Throughput direct P2P (máy desktop phổ thông, WireGuard userspace *(KN: `wireguard-go`)*) | ≥ 70% throughput mạng gốc tới 300 Mbps; không yêu cầu line-rate Gbps ở MVP | `iperf3` qua overlay vs IP thật | WireGuardNT nhanh hơn userspace rõ rệt [T13] → lý do kernel là P2 |
| **PERF-05** | Thời gian thiết lập **P2P direct** (từ lúc có traffic đầu tiên tới khi chuyển sang direct) với Easy NAT ở ít nhất một phía | **P95 ≤ 5 s** (mục tiêu ≤ 3 s); traffic đầu tiên đi relay ngay trong **≤ 1 s** sau khi agent đã kết nối relay | Log timestamp disco + `ping` liên tục | Mô hình "bắt đầu qua DERP rồi nâng cấp" [T1] |
| **PERF-06** | **Failover direct → relay** khi đường UDP bị chặn đột ngột | **P95 ≤ 10 s** mất kết nối (mục tiêu ≤ 5 s) | Chặn UDP bằng firewall giữa lúc `ping -i 0.2` | Đề xuất dựa trên `REKEY_TIMEOUT` 5 s [T34] |
| **PERF-07** | Phục hồi sau **đổi mạng** (Wi-Fi → 4G) hoặc **wake từ sleep** | **P95 ≤ 15 s** tới khi ping overlay thông lại (qua relay hoặc direct) | Kịch bản tự động trong lab (20 vòng) + kiểm chứng phần cứng thật | Đề xuất; tránh chờ hết `REJECT_AFTER_TIME` 180 s [T34] |
| **PERF-08** | Lan truyền thay đổi netmap (thêm node / thu hồi) tới mọi agent online | **P95 ≤ 5 s** | Timestamp audit log vs log agent | Long-poll stream [T7] |
| **PERF-09** | RAM agent trên máy client khi rảnh | **≤ 50 MB** (đề xuất) | Task Manager / `ps` | Đề xuất |
| **PERF-10** | Băng thông nền (keepalive + heartbeat + control) mỗi node khi rảnh | **≤ 1 KB/s** trung bình | Đếm bytes 1 giờ | Keepalive 25 s [T12] |
| **PERF-11** | Thông lượng relay mỗi node | Giới hạn cấu hình được (SEC-07); VPS phải phục vụ ≥ 2 luồng relay đồng thời ở mức hạn mức mà không vượt PERF-01 trần + 64 MB | `iperf3` qua relay | Đề xuất |
| **PERF-12** | Khả dụng control plane (cá nhân) | ≥ 99% theo tháng; **data plane không phụ thuộc** (REL-01) | Uptime probe từ OPS-07 | Đề xuất |

---

## 5. Yêu cầu đặc thù nền tảng (Windows & Linux)

| Mã | Ưu tiên | Yêu cầu | Tiêu chí chấp nhận | Nguồn |
|---|---|---|---|---|
| **PLAT-01** | P0 | **Windows**: dùng driver TUN userspace ổn định *(KN: **Wintun** — đóng gói `wintun.dll` đúng giấy phép phân phối kèm)*, adapter **tên cố định**, chạy dưới dạng **Windows Service** (LocalSystem hoặc tài khoản dịch vụ có quyền cấu hình mạng), CLI giao tiếp service qua kênh IPC cục bộ có ACL chặt *(KN: `named pipe` có ACL chỉ cho phép SYSTEM/Administrators cho tác vụ thay đổi cấu hình)*. | Cài/gỡ không để lại adapter ma; CLI user thường bị từ chối thao tác quản trị | Wintun [T35]; adapter ma [T20] |
| **PLAT-02** | P0 | **Windows Firewall**: xử lý profile mạng của adapter tunnel (tránh mặc định Public chặn hết) và/hoặc tạo rule cho dải overlay; gỡ rule khi gỡ cài đặt. | Ping/SMB/RDP giữa node hoạt động trên Windows mới cài | [T20] |
| **PLAT-03** | P0 | **Linux**: chạy dưới trình quản lý dịch vụ hệ thống *(KN: `systemd`)*, cần `CAP_NET_ADMIN` (+`CAP_NET_RAW` nếu cần), tạo TUN qua `/dev/net/tun`; tương thích tường lửa hệ thống *(KN: `nftables`/`iptables`)*; không ghi đè trực tiếp `/etc/resolv.conf`. | Chạy được trên Ubuntu LTS hiện hành; gỡ service không để lại rule | Tailscale + systemd-resolved [T18] |
| **PLAT-04** | P0 | **DNS/tên máy**: MVP quản lý một **khối có đánh dấu** trong hosts file (`# BEGIN mesh … # END mesh`), cập nhật nguyên tử (bảo toàn ACL đọc trên Windows và xử lý được bind-mount trên container), chặn tên cấm hệ thống (`localhost`, `wpad`, `isatap`, hostname của Control/Relay/STUN), xóa sạch khi tắt/gỡ; không đụng phần còn lại của file. | Test tắt đột ngột → khởi động lại → khối được viết lại đúng, không nhân bản, không gây vòng lặp DNS | MagicDNS bản rút gọn [T18]; `HR-02` |
| **PLAT-05** | P1 | Theo dõi sự kiện mạng: Linux netlink (route/addr/link); Windows `NotifyIpInterfaceChange`/`NotifyRouteChange2`; xử lý sự kiện power resume. | Kích hoạt REL-07 đúng lúc | [T14] |
| **PLAT-06** | P2 | macOS (utun), Android/iOS (VpnService/NetworkExtension). | — | Phase 2 |

---

## 6. Danh mục kiểm tra Go-Live cá nhân (checklist cho Gate 3)

- [ ] SEC-01: Đã review mã + grep log/DB/traffic — không có private key rời client.
- [ ] SEC-03/05: Pre-auth key one-time + TTL + rate limit (kèm kiểm tra `trusted_proxies`) hoạt động.
- [ ] SEC-04/06: Hỗ trợ cả Standalone TLS 443 và chạy sau Reverse Proxy sẵn có; firewall `opt-in` giữ nguyên SSH/dịch vụ hiện có trên VPS.
- [ ] SEC-14/OPS-05/OPS-06/OPS-08: Kênh Admin chỉ truy cập được qua kênh cục bộ kiểm chứng đặc quyền OS (Unix socket `0600`/`0660` + `SO_PEERCRED` hoặc CLI dưới quyền quản trị qua SSH); **không** lộ Admin API lên IP overlay hay TCP loopback trần; `/healthz`, `/readyz`, `/metrics` chỉ-đọc và tách biệt hoàn toàn.
- [ ] SEC-07: Client chưa đăng ký không dùng được relay; có giới hạn băng thông.
- [ ] SEC-08: Kịch bản "mất laptop" — thu hồi xong ≤10 s, tunnel đang sống bị cắt.
- [ ] REL-01: Tắt control 30 phút — tunnel P2P không đứt.
- [ ] REL-06: Mạng chặn hoàn toàn UDP — vẫn kết nối qua relay 443.
- [ ] REL-08/PLAT-01: `kill -9` agent trên Windows và Linux — khởi động lại sạch, Internet máy thật không bị ảnh hưởng.
- [ ] REL-09: Không có routing loop khi VPS vừa là node vừa là relay.
- [ ] REL-10: SCP/HTTPS file lớn qua tunnel trên đường MTU thấp không treo.
- [ ] REL-12: Diễn tập backup → restore thành công.
- [ ] OPS-02/03: `status` và `ping` hiển thị đúng direct/relay + RTT.
- [ ] PERF-01, 05, 06, 07: đo và ghi kết quả thật vào báo cáo QA.

---

## 7. Gợi ý chuyển hóa thành Epic/Story cho `agile-po-ba`

| Epic gợi ý | Nhóm yêu cầu |
|---|---|
| E1 — Định danh & Onboarding thiết bị an toàn | SEC-01, SEC-02, SEC-03, SEC-04, SEC-05, REL-02 |
| E2 — Coordination Server, Quản trị cục bộ & Netmap | REL-03, REL-11, REL-12, SEC-06, SEC-09, SEC-10, **SEC-14**, OPS-08 |
| E3 — Data Plane WireGuard & Routing an toàn | REL-09, REL-10, SEC-11, PLAT-01, PLAT-03 |
| E4 — NAT Traversal & Disco | REL-05, REL-07, PERF-05, OPS-04 |
| E5 — Relay DERP-lite | REL-06, SEC-07, PERF-06, PERF-11 |
| E6 — Vòng đời thiết bị & Thu hồi | SEC-08, REL-01 |
| E7 — Vận hành, Bảo mật VPS & Chẩn đoán | SEC-05, SEC-06, **SEC-14**, OPS-01..07, OPS-09, OPS-10, REL-13 |
| E8 — Tích hợp nền tảng & Dọn dẹp | REL-08, PLAT-02, PLAT-04, PLAT-05, REL-14 |
