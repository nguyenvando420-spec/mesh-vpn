# Vision Statement — Mesh VPN Cá Nhân (kiểu Tailscale, tự host trên 1 VPS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-po-ba` |
| Ngày | 2026-11-12 |
| Giai đoạn | 1 — Discovery (Gate 1 ✅ đã duyệt 2026-11-12) |
| Phiên bản | **1.1** — Đồng bộ quyết định Gate 1: client macOS + Windows, VPS Ubuntu kiêm node, kết nối bằng IP + Pin, cổng cấu hình được, CLI `mesh` / `.mesh.internal` |
| Đầu vào | [reference-systems-benchmark.md](./reference-systems-benchmark.md), [production-readiness-requirements.md](./production-readiness-requirements.md) |
| Tên mã tạm | `Mesh` (chưa chốt tên sản phẩm — xem Câu hỏi mở trong [project-charter.md](./project-charter.md)) |
| Thành phần AI/SLM | **Không có** |

---

## 1. Tuyên ngôn tầm nhìn (Vision)

> **Dành cho** một cá nhân sở hữu nhiều máy tính (PC ở nhà, laptop di động, NAS/home-server, 1 VPS) **muốn** truy cập mọi máy của mình như đang ở chung một mạng LAN riêng — an toàn, tự động, không phải mở cổng router, không phải giao dữ liệu cho bên thứ ba;
> **sản phẩm Mesh** là một **mạng overlay mã hóa đầu-cuối tự host** (agent trên từng máy + 1 máy chủ điều phối trên VPS)
> **khác với** WireGuard hub-and-spoke thủ công (mọi gói đi vòng qua VPS, thêm máy phải sửa config tay) **và** Tailscale SaaS (phụ thuộc dịch vụ ngoài),
> **ở chỗ** các máy tự đăng ký bằng khóa dùng-một-lần, **tự tìm đường P2P trực tiếp** (NAT traversal), **tự rơi về relay mù trên VPS** khi P2P không khả thi, và **tunnel đang chạy không chết khi VPS chết**.

**Một câu:** *"Cài agent, nhập một khóa, và máy nào của tôi cũng gọi được máy nào — thẳng nếu có thể, qua VPS nếu bắt buộc, và VPS không bao giờ đọc được nội dung."*

## 2. Vấn đề cần giải quyết

| # | Nỗi đau hiện tại | Hệ quả |
|---|---|---|
| 1 | PC nhà/NAS nằm sau NAT, nhiều khả năng **CGNAT**; laptop dùng Wi-Fi quán cà phê/4G | Không truy cập từ ngoài được nếu không có VPN/relay |
| 2 | WireGuard thủ công kiểu hub-and-spoke: sửa config ở hub mỗi lần thêm máy, mọi traffic đi vòng qua VPS | Tốn công, tốn băng thông VPS, hub chết = mất toàn bộ mạng |
| 3 | Công cụ "WireGuard UI" thường để server sinh và phát private key | Rò rỉ khóa; không chấp nhận được về bảo mật |
| 4 | Dịch vụ SaaS (Tailscale) tiện nhưng là hộp đen, người dùng muốn **hiểu bản chất và tự chủ dữ liệu** | Mục tiêu kép: **dùng thật hằng ngày + học sâu** |
| 5 | Tự code VPN dễ làm hỏng mạng máy thật: routing loop, MTU blackhole, adapter ma sau crash, treo sau sleep/wake | Phải thiết kế phòng thủ ngay từ MVP, không thể "vá sau" |

## 3. Giá trị cốt lõi (Value Proposition)

1. **Zero-config kết nối**: đăng ký bằng pre-auth key, không mở cổng, không sửa config thủ công ở các máy khác.
2. **Riêng tư thật sự**: private key sinh tại máy, không rời máy; VPS chỉ thấy metadata + gói đã mã hóa.
3. **Nhanh khi có thể, chắc khi cần**: P2P trực tiếp (ưu tiên LAN > IPv6 > IPv4 reflexive); relay TLS 443 làm "đường cuối luôn thông".
4. **Chịu lỗi**: control plane (VPS) chết ≠ data plane chết; agent tự phục hồi sau đổi mạng, sleep/wake, crash.
5. **Vận hành được**: CLI `status` / `ping` nói rõ đang direct hay relay; log, healthcheck, backup/restore được diễn tập.
6. **Không phình phạm vi**: một chủ sở hữu, một VPS, full-mesh, CLI + service — không OIDC, không Web UI, không HA ở MVP.

## 4. Tư duy kế thừa từ hệ thống tham chiếu

| Học từ | Điểm hay kế thừa | Cạm bẫy phòng tránh |
|---|---|---|
| **Tailscale** | Tách Control/Data plane; netmap snapshot có version; `status`/`ping` hiện direct vs relay; MTU 1280; key expiry; pre-auth key có TTL | Treo sau sleep/wake; adapter ma Windows; control bị chiếm chèn node giả |
| **Headscale** | Chứng minh 1 binary + 1 file DB đủ cho cá nhân; CLI quản trị đủ dùng, không cần Web UI | Single-writer = SPOF control (chấp nhận được nhờ REL-01); gánh nặng TLS/backup; "feature lag" khi bám giao thức đóng |
| **NetBird** | Relay kiểu WSS 443 đơn giản hơn TURN; tách rõ vai trò control/signal/relay | Quá nhiều thành phần cho 1 VPS; tính năng thời thượng bị deprecate (Rosenpass); **AGPLv3 — không sao chép mã server** |
| **Nebula** | Hole punching do bên thứ ba điều phối rồi "bước ra"; relay node làm dự phòng | Thu hồi thủ công từng node, không cắt tunnel đang sống |
| **Innernet** | Onboarding bằng lời mời dùng-một-lần; client tự sinh khóa; server không biết private key | **Không có relay → hai máy sau CGNAT không nói chuyện được** ⇒ relay là bắt buộc |

## 5. Chỉ số thành công (Outcome Metrics — định lượng, đo bằng `agile-qa`)

> Các số liệu lấy từ SLO đề xuất trong `production-readiness-requirements.md` (mục 4); sẽ được hiệu chỉnh khi đo thật.

| Mã | Chỉ số | Mục tiêu |
|---|---|---|
| OM-1 | Thời gian từ lúc có traffic đầu tiên tới khi chuyển sang đường direct (Easy NAT ≥ 1 phía) | P95 ≤ 5 s (PERF-05) |
| OM-2 | Traffic đầu tiên đi relay sau khi agent đã kết nối relay | ≤ 1 s (PERF-05) |
| OM-3 | Mất kết nối khi UDP direct bị chặn đột ngột | P95 ≤ 10 s (PERF-06) |
| OM-4 | Phục hồi sau đổi mạng / wake từ sleep | P95 ≤ 15 s (PERF-07) |
| OM-5 | Thu hồi thiết bị có hiệu lực (control online) | P95 ≤ 10 s (SEC-08); relay ngắt ≤ 5 s (SEC-07) |
| OM-6 | Control server chết 30 phút — mất gói do control | 0% (REL-01) |
| OM-7 | RAM server idle (20 node) / RAM agent idle | < 64 MB (trần 128 MB) / ≤ 50 MB (PERF-01, PERF-09) |
| OM-8 | Độ trễ cộng thêm trên đường direct | ≤ 2 ms P95 (PERF-03) |
| OM-9 | Số lần máy mất kết nối Internet "thật" do agent (routing loop/route mồ côi) trong test chaos | **0** (REL-08, REL-09) |
| OM-10 | Có private key trong log/DB/traffic/bundle | **0** lần xuất hiện (SEC-01) |

## 6. Phạm vi tầm nhìn theo thời gian

| Giai đoạn | Nội dung |
|---|---|
| **MVP** | 3–20 thiết bị; **client macOS 13+ (Apple Silicon `arm64` + Intel `amd64`) và Windows 10/11**; **1 VPS Ubuntu Linux** chạy Control + Relay + STUN và đồng thời là 1 node mesh (`vps.mesh.internal`); CLI **`mesh`** + service nền (`launchd` / Windows Service / `systemd`); full-mesh; P2P + relay TLS; **kết nối trực tiếp bằng IP VPS + Pin khóa server `sha256:…` (cấm TOFU, chưa cần domain)**; **cổng TCP Control/Relay (mặc định 443) và UDP STUN (mặc định 3478) cấu hình được, đổi về sau không mất danh tính node**; pre-auth key; thu hồi/hết hạn; backup/restore; observability tối thiểu; hậu tố tên máy `.mesh.internal`. Giao 2 Milestone: **M1** Walking Skeleton + Direct P2P dùng hằng ngày macOS + Windows ↔ VPS → **M2** Roaming/Sleep-Wake, Key Expiry, Hardening, Rate-limit/Quota, NAT Chaos Lab & Packaging |
| **Phase 2** | Gói Linux máy trạm desktop (`Should` trong backlog, sau macOS + Windows); bản macOS ký Developer ID/notarize/`.pkg`/GUI; tách machine/node key; netmap delta; hard-NAT↔hard-NAT; split DNS chuẩn; ACL nhóm; subnet router/exit node; relay UDP/QUIC/nhiều relay; metrics/alert hoàn chỉnh |
| **Phase 3+** | Android/iOS; Web UI; OIDC/SSO; ký node key kiểu Tailnet Lock; HA control |

## 7. Nguyên tắc sản phẩm (Guiding Principles)

1. **Không tự viết mật mã** — dùng giao thức/thư viện chuẩn đã kiểm định (SEC-02).
2. **Khóa không rời máy** (SEC-01).
3. **Luôn có đường đi** — relay là đường khởi đầu mặc định cho tới khi direct được xác nhận (REL-05).
4. **Không bao giờ làm hỏng mạng máy thật** — dọn dẹp khi dừng, tự sửa khi khởi động, không default route ở MVP (REL-08/09).
5. **Control chết, data sống** (REL-01).
6. **Mặc định an toàn, mặc định đơn giản** — full-mesh trong phạm vi một chủ sở hữu; mọi thứ khác là Phase 2+.
7. **Tự định nghĩa giao thức** thay vì bám giao thức đóng của bên khác (✅ đã chốt Gate 1, OQ-01).
8. **Không tin ngầm server**: kết nối bằng IP phải có pin; không TOFU, không cờ bỏ qua kiểm tra (SEC-04); đổi cổng/IP/pin không buộc cài lại danh tính node (SEC-15).
