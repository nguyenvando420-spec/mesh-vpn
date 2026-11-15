# Mobile Product Backlog — Mesh VPN (`v0.2.0` — Android & iOS Clients)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-po-ba` |
| Ngày lập | 2026-11-15 |
| Phiên bản | **1.1** — Chỉnh sửa Vòng 2 theo [mobile-gate-1-critique.md](../05-quality-assurance/critique-reviews/mobile-gate-1-critique.md) & [mobile-readiness-requirements.md](../01-discovery/mobile-readiness-requirements.md) Vòng 2 (xử lý `BLK-MOB-01..03`, `HR-MOB-01..04`, `MED-MOB-01..03`, `LOW-MOB-01`) |
| Nhánh phát triển | `feat/mobile-clients` (giữ nguyên `main`, `v0.1.0-rc1` và toàn bộ [product-backlog.md](./product-backlog.md) v1.2 `US-001..074`) |
| Tài liệu đầu vào | [mobile-readiness-requirements.md](../01-discovery/mobile-readiness-requirements.md) · [project-charter.md](../01-discovery/project-charter.md) · [vision-statement.md](../02-product-planning/vision-statement.md) · [user-personas.md](./user-personas.md) · [product-backlog.md](./product-backlog.md) |
| Thành phần AI/SLM | **Không có** ⇒ không áp dụng AI/Data Epic |

> [!IMPORTANT]
> **Nguyên tắc bảo toàn `v0.1.0` & Ranh giới Gate 1 (What) vs Gate 2 (How):**
> 1. Tài liệu này chỉ hoạch định Milestone `v0.2.0` (`EP-13..EP-16`, `US-075..099`), **không sửa đổi** `US-001..074` hay ma trận truy vết Desktop/Server trong [product-backlog.md](./product-backlog.md) v1.2.
> 2. **Không khóa công nghệ ở Gate 1:** Mọi gợi ý thư viện, UI framework, công cụ build hoặc khung FFI cụ thể (ví dụ `*(KN)*: Jetpack Compose`, `*(KN)*: SwiftUI`, `*(KN)*: UniFFI` vs `jni + C-ABI`, `*(KN)*: rustls-platform-verifier`, `*(KN)*: cargo-ndk`, `*(KN)*: BiometricPrompt` / `LocalAuthentication` / `PasteButton`) chỉ mang tính khuyến nghị (`*(KN)*`), để `agile-tech-lead` và `agile-architect` chốt quyết định kiến trúc qua ADR tại **Gate 2** (riêng chủ trương ngoại lệ giấy phép `MPL-2.0` trình Người dùng chốt tại Gate 1 qua `OQ-MOB-05`).
> 3. Toàn bộ chuẩn bảo mật `v0.1.0` (`SEC-01..15`, `GNFR-01..03`, `GNFR-11`) giữ nguyên hiệu lực, **không nới lỏng** trên di động.

---

## 0. Quy ước, DoR & DoD Di động

### 0.1. Định dạng Story
- **ID**: `EP-13..EP-16`, `US-075..US-099` (tiếp nối sau `US-074`; riêng story trích xuất lõi Client Control Plane bổ sung từ phản biện `BLK-MOB-01` mang mã `US-099` đặt cuối `EP-13` để giữ ổn định các mã `US-075..098` đang đối chiếu).
- **SP (Story Points)** ∈ `{1, 2, 3, 5, 8}`, **không story nào > 8 SP**.
- **MoSCoW**: `Must` = bắt buộc cho Milestone `v0.2.0`; `Should` = giá trị cao thuộc `v0.2.0` nhưng có thể cắt/trượt nếu trễ; `Could` = mở rộng tự động hóa sau khi lõi ổn định (`v0.2.1+`).
- **Platform**: `Shared` (Rust Mobile Core, Control Extraction, FFI & `mesh-server`/`mesh`) · `Android` · `iOS` · `Mobile QA & CI`.
- **Trace**: ánh xạ trực tiếp tới 34 mã `MOB-*` trong [mobile-readiness-requirements.md](../01-discovery/mobile-readiness-requirements.md) và `GNFR-*`/`M-GNFR-*`.
- **Acceptance Criteria (AC)** viết theo `Given / When / Then`, gắn nhãn **[H]** Happy path · **[E]** Edge case · **[F]** Failure handling · **[N]** Non-functional/SLO (có ngưỡng đo kiểm).

### 0.2. Definition of Ready (DoR) & Definition of Done (DoD)
- **DoR**: Story có Persona/Platform rõ, **AC đủ cả `[H]`, `[E]`, `[F]`** (kèm `[N]` khi có SLO), Dependencies không vòng lặp, `SP <= 8`, không khóa công nghệ thuộc Gate 2.
- **DoD (mọi story `Must`)**:
  1. Toàn bộ AC đạt bằng unit/integration test tự động trên Rust core + platform tests (và giữ xanh 100% regression tests của `meshd` Desktop khi tách lõi Control Plane), hoặc biên bản kiểm thử thiết bị thật theo `MOB-OPS-05` đối với hành vi phụ thuộc phần cứng/OS.
  2. `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test` và `cargo deny check` xanh trên đủ 5 mobile targets; không lọt `openssl-sys`, `aws-lc-rs`, `native-tls`.
  3. Không rò rỉ bí mật trong log hệ thống (`logcat`/`OSLog`), crash dump, cloud backup hay `bugreport` Share Sheet (`0` kết quả grep).
  4. Không tạo routing loop (`protect(fd)` 100% trên Android; `includedRoutes` chỉ chứa dải overlay trên iOS), hoạt động trên mạng IPv6-only NAT64, và không làm gãy DNS công cộng.
  5. Cập nhật Runbook/Checklist di động nếu thay đổi thao tác người dùng hoặc quy trình ký số.

---

## 1. Mobile Product Vision (`v0.2.0`) & Ràng buộc Phạm vi

### 1.1. Tuyên ngôn Tầm nhìn Di động (`v0.2.0`)

> **Dành cho** chủ mạng cá nhân (`Minh`, `Lan`) và thành viên được mời đang mang theo **điện thoại/máy tính bảng Android và iPhone/iPad** khi đi công tác hoặc di chuyển qua 4G/5G (kể cả IPv6-only NAT64/CGNAT) và Wi-Fi công cộng, **muốn** truy cập an toàn các máy trong mạng mesh tại nhà/VPS (như `nas.mesh.internal`, `dev.mesh.internal`, `vps.mesh.internal`) ngay từ thiết bị di động mà không phải mở cổng router hay giao dữ liệu cho dịch vụ SaaS bên thứ ba;
> **Mesh VPN `v0.2.0`** tái sử dụng chung lõi Client Control Plane & Datapath Rust sans-I/O sang ứng dụng gốc trên **Android (`VpnService`)** và **iOS (`NEPacketTunnelProvider`)**
> **khác với** các VPN di động dùng runtime có Garbage Collector dễ bị iOS Jetsam tiêu diệt hoặc yêu cầu cấu hình WireGuard tĩnh thiếu NAT traversal/relay,
> **ở chỗ** dùng chung một máy trạng thái giao thức Rust bảo mật cao (SPKI Pin mặc định, không TOFU, `Secret<T>`), tự chuyển vùng Wi-Fi ↔ 4G/5G (kể cả IPv6-only NAT64) và fallback Blind Relay 443 dưới CGNAT kép, phân giải riêng `.mesh.internal` chuẩn RFC 4074 không làm hỏng DNS công cộng, tối ưu đánh thức radio về `RRC_IDLE`, và **tương thích ngược 100% với Desktop `v0.1.0-rc1`**.

**Một câu:** *"Quét QR hoặc dán link `mesh://` vào điện thoại Android hay iPhone, xác nhận đúng Pin VPS, và truy cập homelab mọi lúc trên mọi mạng 4G/5G/Wi-Fi — không routing loop, không phá mạng thường ngày, không cần nâng cấp máy tính cũ."*

### 1.2. Kế thừa Global NFRs (`v0.1.0`) & Bổ sung Mobile Global NFRs (`M-GNFR-*`)

#### A. Các Global NFR kế thừa bắt buộc từ `v0.1.0`
| Mã kế thừa | Quy tắc bắt buộc trên Mobile `v0.2.0` | Trace |
|---|---|---|
| **GNFR-01** | Không tự viết primitive mật mã; 100% crypto đi qua `mesh-crypto` / `mesh-datapath` chuẩn (`ring`, `defguard_boringtun`, `crypto_box`, `chacha20poly1305`), không C ẩn (`openssl-sys`, `aws-lc-rs`, `native-tls`). | `SEC-02`, `MOB-SEC-03` |
| **GNFR-02** | Không xuất hiện secret (`node_key`, `disco_key`, `mpk_*`, WireGuard session key) trong log (`logcat`/`OSLog`), crash dump, cloud backup hay `bugreport` (`0` kết quả). | `SEC-01`, `MOB-SEC-05` |
| **GNFR-03** | Mọi I/O mạng có timeout: kết nối `<= 10 s` (`CONNECT_TIMEOUT_MS`), stream heartbeat `<= 60 s` (`HEARTBEAT_TIMEOUT_MS`), không I/O chặn vô hạn. | `REL-04`, `MOB-REL-01` |
| **GNFR-11** | **Cổng và địa chỉ server không bao giờ mã hóa cứng:** cổng TCP Control/Relay (mặc định `443`) và UDP STUN (mặc định `3478`) cấu hình được từ QR/URI/nhập tay và nhận `relay_map` động qua Netmap; kết nối IP + SPKI Pin là mặc định hạng nhất, **cấm TOFU**, không công tắc bỏ qua pin. | `SEC-04`, `SEC-15`, `MOB-SEC-03` |

#### B. Mobile Global NFRs mới (`M-GNFR-*`)
| Mã | Mobile Global NFR | Ngưỡng / Tiêu chí đo kiểm | Trace |
|---|---|---|---|
| **M-GNFR-01** | **Ngân sách RAM iOS Network Extension (Chống Jetsam)** | Đỉnh **`RSS <= 25 MiB` (mục tiêu thiết kế đề xuất)** dưới tải liên tục, giữ biên an toàn tối thiểu 50% dưới trần cứng **`~50 MiB` Jetsam (`EXC_RESOURCE`)** của Apple; dùng buffer `[u8; 2048]`, queue `256` (`try_send()`), hạ `MAX_CONTROL_WS_FRAME_BYTES <= 256 KiB` trên mobile, khóa `max_blocking_threads <= 2`, kiểm tra `os_proc_available_memory()`, và xuất `bugreport` qua tệp App Group (cấm nhồi `1 MiB` qua `handleAppMessage`). | `MOB-PERF-01`, `MOB-PLAT-IOS-02` |
| **M-GNFR-02** | **Ngân sách RAM dịch vụ nền Android** | Tổng **`RSS <= 48 MiB` (mục tiêu thiết kế đề xuất)** gồm cả ART heap + Rust `.so` trong phiên `<= 50` peer, tránh bị `lmkd` thu hồi. | `MOB-PERF-02` |
| **M-GNFR-03** | **Zero Routing Loop (An toàn mạng máy thật `G4`)** | **0 lần** mất Internet thật do routing loop: Android bắt buộc `VpnService.protect(fd)` đồng bộ cho **100%** socket underlay trước `connect`/`send_to` (fail-closed nếu `false`); iOS chỉ đặt `includedRoutes = [overlay_cidr]` (bao gồm `overlay_dns_ip`), tuyệt đối không đặt `0.0.0.0/0`. | `MOB-PLAT-AND-02`, `MOB-PLAT-IOS-04` |
| **M-GNFR-04** | **Split-DNS `.mesh.internal` chuẩn RFC 4074 & An toàn Private DNS** | Tuân thủ **RFC 4074 §3** (`A` → `OverlayIp`, `AAAA` peer tồn tại → **`NOERROR NODATA`**, `PTR` → FQDN, không tồn tại → `NXDOMAIN`, UDP+TCP `:53`); tách `overlay_dns_ip:53` trước `CryptokeyValidator`; Android trả **`TCP RST` tức thì trên `:853`** cho Opportunistic DoT, kiểm tra `LinkProperties.isPrivateDnsActive()` cảnh báo Strict Private DNS, đọc upstream từ `LinkProperties.getDnsServers()` của mạng vật lý underlay + `addSearchDomain`; iOS dùng `NEDNSSettings(matchDomains: ["mesh.internal"])`; **0 gói** `.mesh.internal` rò ra `wlan0`/`rmnet_data*`. | `MOB-PLAT-AND-05`, `MOB-PLAT-IOS-05` |
| **M-GNFR-05** | **Tương thích ngược `v0.1.0-rc1` & Dùng chung Lõi Control Plane** | Trích xuất lõi Client Control Plane (`control_loop`, `NetmapCacheStore`, `roaming_loop`, `ping_probe`) khỏi adapter OS Desktop của `crates/meshd` dùng chung cho Desktop & Mobile (100% regression tests `meshd` Desktop xanh); giữ nguyên `protocol_version = 1` và schema `NetmapSnapshot`/`PeerEntry`; nâng cấp `mesh-server`, `mesh-proto` và `RelayClient::current_target_os_str()` cho `TargetOs::{Android, Ios}` không migrate `redb`; Desktop `v0.1.0-rc1` liên thông 100% **không phải nâng cấp**. | `MOB-OPS-03`, `MOB-REL-01` |
| **M-GNFR-06** | **Tuân thủ Đồ thị Phụ thuộc, Ranh giới `unsafe` & 5 Target Mobile** | Feature-gate loại bỏ `axum`/`hyper`/`hyper-util`/`redb`/`clap` (`mesh-net`/`mesh-datapath`) và **`rustls-native-certs`/`rcgen`** (`mesh-crypto`) khỏi build mobile; bổ sung nhánh `android`/`ios` trong `mesh-net/src/route.rs`; `cargo deny check` xanh trên cả 5 target triples; chốt minh bạch chính sách `MPL-2.0` (`OQ-MOB-05`) tại Gate 1 và ranh giới `unsafe` (`mesh-sys` vs `mesh-mobile-ffi`) tại Gate 2. | `MOB-PERF-05`, `MOB-OPS-03` |
| **M-GNFR-07** | **Hiệu năng Chuyển vùng, Pin `RRC_IDLE` & Chẩn đoán giới hạn** | Handshake đầu `<= 2 s`; phục hồi chuyển vùng Wi-Fi ↔ 4G/5G `<= 5 s`; dừng êm `<= 5 s`; pin nền idle mục tiêu **`<= 1.5% / giờ`**: chuyển timer `DatapathEngine` (`250 ms`) sang **idle-aware / coalesced ticks** và đồng bộ/giãn heartbeat/Relay trong biên `60 s` khi rỗi để radio 4G/5G hạ về `RRC_IDLE`; log ring-buffer `<= 1 MiB`; **0 TCP endpoint** Admin/Health trên app di động. | `MOB-REL-02/03/06`, `MOB-PERF-03/04`, `MOB-OPS-04` |
| **M-GNFR-08** | **Kích thước nhị phân native Rust tối giản** | Mỗi ABI Rust (`.so` / slice `.xcframework`) đạt **mục tiêu thiết kế `<= 6 MiB`** ở profile release (`opt-level = 3`, `lto = "thin"`, `strip = "symbols"`). | `MOB-PERF-05` |
| **M-GNFR-09** | **Tương thích Mạng Di động IPv6-only NAT64/DNS64 (Apple Guideline 2.5)** | Hỗ trợ chế độ mặc định **IPv4 literal + SPKI Pin** kết nối thành công qua mạng cellular **IPv6-only NAT64 (`64:ff9b::/96`)** bằng khám phá Pref64 / tổng hợp địa chỉ IPv6 (`getaddrinfo AF_UNSPEC/AI_DEFAULT`, RFC 7050 `ipv4only.arpa`, `NWPath` Pref64) + dual-stack/IPv6 `MagicSocket`, tránh lỗi `ENETUNREACH` mà vẫn giữ nguyên đối chiếu `SpkiPinVerifier`. | `MOB-REL-02`, `MOB-PLAT-IOS-04`, `MOB-SEC-03` |

### 1.3. Ràng buộc Phạm vi Milestone `v0.2.0`
- **IN-SCOPE (`v0.2.0`)**: Client Android (API 26+, ưu tiên kiểm chứng máy thật Android 14+/API 34+) và Client iOS (iOS 15+, iPhone/iPad); trích xuất lõi Client Control Plane dùng chung từ `meshd`; nâng cấp tương thích `TargetOs::{Android, Ios}` trên `mesh-proto`/`mesh-server`/`RelayClient`; Split-Tunnel vào `overlay_cidr` + `.mesh.internal` chuẩn RFC 4074; tương thích IPv6-only NAT64; Onboarding qua QR Camera / dán trực tiếp URI `mesh://` trong app (cấm deep-link OS cho `mpk_*`) / nhập tay `IP:cổng + SPKI Pin`; P2P + Blind Relay 443; roaming, Doze/App Nap, Captive Portal, thu hồi nút.
- **OUT-OF-SCOPE (hoãn sang `v0.3.0+`)**: Exit Node di động (route `0.0.0.0/0` qua VPS) và Subnet Router di động (`US-068`); chia sẻ đa người dùng / OIDC / ACL nhóm (`US-067`, `US-070`); Apple Watch / CarPlay / Android TV; tự động xoay khóa không đăng ký lại (`US-062`).

---

## 2. Mobile Personas & Threat Actors (`v0.2.0`)

### 2.1. Mở rộng Persona `P5` từ [user-personas.md](./user-personas.md)

Trong `v0.1.0`, `P5` (người dùng mobile) bị hoãn sang Phase 2+. Tại Milestone `v0.2.0`, `P5` được cụ thể hóa cho bộ đôi người dùng cốt lõi (**Minh `P1` & Lan `P3`**) trên cả Android lẫn iOS cùng một kịch bản thành viên được mời dùng thiết bị di động (vẫn trong mô hình single-owner/full-mesh):

| Mã Persona | Tên & Ngữ cảnh sử dụng | Thiết bị & Hạ tầng | Nỗi đau & Thách thức di động | Kỳ vọng & Tiêu chí "Đủ tốt" |
|---|---|---|---|---|
| **P5-AND** | **Minh / Lan — Người dùng Android khi công tác** | Điện thoại/Tablet **Android** (API 26–35+) mang theo khi di chuyển qua 4G/5G (CGNAT kép, IPv6-only NAT64) và Wi-Fi khách sạn/sân bay; kết nối về homelab (`nas.mesh.internal`) & VPS (`v0.1.0-rc1` đã chạy sẵn Desktop/Linux). | Nhập dòng lệnh/pin 64 ký tự hex bằng bàn phím ảo dễ sai; VPN khác bật lên gây routing loop hoặc Private DNS (`DoT :853`) / `addDnsServer()` làm hỏng phân giải `.mesh.internal` hay web công cộng; app bị Android 14+ giết vì thiếu `specialUse` hoặc crash ở Direct Boot; sợ Google Drive Auto Backup sao lưu khóa riêng; bật Lockdown làm mất Internet máy thật. | Cài `.apk` trực tiếp từ GitHub Release (`$0`); quét QR hoặc dán URI `mesh://` trong app (hoặc nhập tay `IP:cổng + Pin`), xác nhận fingerprint 1 chạm; đổi Wi-Fi ↔ 4G/5G không rớt kết nối quá 5 s; web công cộng & Captive Portal mở bình thường; idle cả ngày `<= 1.5%/giờ`. |
| **P5-IOS** | **Minh / Lan — Người dùng iPhone/iPad khi công tác** | **iPhone / iPad** (iOS 15+) đi kèm MacBook (`P1`/`P3`); bật tunnel khi cần xem dashboard homelab, gọi SSH/HTTP nội bộ qua 4G/5G (IPv6-only NAT64). | iOS Network Extension bị Jetsam (`~50 MiB`) giết âm thầm khi WS buffer/log phình to; IPv4 literal gặp `ENETUNREACH` trên 4G/5G IPv6-only; truy vấn `AAAA` sai chuẩn làm gãy Happy Eyeballs; khóa trong Keychain bị đồng bộ lên iCloud; vướng rào cản ký số Apple Developer `$99/năm` khi cài máy thật. | Kiến trúc 2 tiến trình mượt mà; giao diện di động (`*(KN: SwiftUI)*`) hiển thị rõ `direct`/`relay`; On-Demand tự kích hoạt (và tắt sạch khi nhấn Disconnect); `RSS <= 25 MiB` không crash; chia sẻ `bugreport` qua App Group + Share Sheet sạch 100% bí mật; nắm rõ lộ trình Simulator `$0` vs ký máy thật `$99/năm`. |
| **P5-INV** | **Thành viên được mời dùng di động (Kịch bản thiết bị phụ / người thân tin cậy)** | Điện thoại Android hoặc iPhone cá nhân được Minh (`P1`) cấp **1 pre-auth key one-time TTL ngắn** để truy cập dịch vụ nội bộ trong mesh (chưa có ACL/OIDC — do chủ mạng cấp phát tập trung). | Không biết SSH, không hiểu CLI `mesh`; nếu bấm link `mesh://` qua deep-link OS có nguy cơ bị app khác cướp `mpk_*`; nếu làm mất điện thoại phải cắt quyền ngay để tránh lộ dịch vụ nhà. | Chủ mạng chạy `mesh` CLI trên VPS lấy QR/URI `mesh://` gửi qua kênh riêng; người nhận quét QR hoặc dán trực tiếp vào app, xác nhận rõ Endpoint + Pin; khi mất máy, Minh chạy `node revoke` là máy đó bị ngắt tức thì. |

### 2.2. Bảng Threat Actors Di động (`T-MOB-01..09`)

| Mã | Kịch bản mối đe dọa di động | Tác động | Biện pháp giảm thiểu bắt buộc | Story / M-GNFR phủ |
|---|---|---|---|---|
| **T-MOB-01** | **Mất hoặc bị trộm điện thoại** (đã mở khóa lần đầu sau reboot hoặc bị trích xuất flash khi chưa mở khóa sau reboot) | Kẻ tấn công trích xuất `Secret<[u8; 32]>` để giả mạo node truy cập mạng nội bộ. | Lưu khóa bằng Android Keystore `AES-256-GCM` / iOS Keychain `AfterFirstUnlockThisDeviceOnly`; xử lý an toàn Direct Boot (`ACTION_USER_UNLOCKED`) và `errSecInteractionNotAllowed`; hỗ trợ `node_revoked` ngắt tunnel tức thì & xóa khóa phiên. | `US-082`, `US-085`, `US-088`, `US-084`, `US-091`, `US-095`, `US-099` |
| **T-MOB-02** | **MITM trên Wi-Fi công cộng / Hotspot giả mạo** (proxy chặn TLS, trình chứng chỉ giả hoặc chứng chỉ CA công cộng cấp cho IP) | Đánh cắp proof xác thực, đầu độc Netmap hoặc chèn peer giả. | Kế thừa `SEC-04`: `SpkiPinVerifier` đối chiếu hằng thời gian ở chế độ IP mặc định (kể cả qua địa chỉ NAT64 tổng hợp), **fail-closed**, **cấm TOFU**, không cờ bỏ qua pin; Domain + CA dùng native trust store (`*(KN)*: rustls-platform-verifier` + JNI Context sớm). | `US-078`, `US-084`, `US-091`, `US-099`, `GNFR-11`, `M-GNFR-09` |
| **T-MOB-03** | **Captive Portal Wi-Fi khách sạn/sân bay** (chặn/chuyển hướng HTTP/HTTPS `:443` sang trang đăng nhập) | Client hiểu nhầm bị MITM rồi treo, hoặc VPN nuốt hết traffic khiến người dùng không mở được trang đăng nhập Wi-Fi. | Split-tunnel không chiếm `0.0.0.0/0`; engine phát hiện lỗi TLS/portal dùng `ExponentialBackoff` trần `300_000 ms` + kích hoạt lại khi đổi mạng; UI phân biệt rõ Captive Portal / Clock Skew / Pin Mismatch. | `US-078`, `US-084`, `US-091`, `US-095` |
| **T-MOB-04** | **VPN Routing Loop / Lockdown Blackout làm mất Internet toàn thiết bị (`G4`)** (socket underlay bị đẩy ngược vào TUN, hoặc bật Android Lockdown Mode khi chạy Split-Tunnel) | Đốt 100% CPU/pin hoặc Android chặn 100% lưu lượng Internet (`0.0.0.0/0`) của mọi app khác trên máy. | Android **bắt buộc `VpnService.protect(fd)`** đồng bộ cho 100% socket underlay (fail-closed) + cảnh báo nổi bật khi `isLockdownEnabled()` active trên Split-Tunnel; iOS **bắt buộc `includedRoutes = [overlay_cidr]`** không đặt `0.0.0.0/0`. | `US-077`, `US-081`, `US-085`, `US-089`, `M-GNFR-03` |
| **T-MOB-05** | **Rò rỉ DNS `.mesh.internal`, treo Private DNS (`DoT :853`) hoặc gãy Happy Eyeballs/Web** | `.mesh.internal` lọt ra ISP/Google/Cloudflare DoT (`Strict`), `AAAA` trả `NXDOMAIN`/IPv4 làm gãy Happy Eyeballs, `CryptokeyValidator` drop gói tới `overlay_dns_ip`, hoặc tự loop forward DNS. | Tuân thủ **RFC 4074 §3** (`AAAA` peer tồn tại trả `NOERROR NODATA`), tách `overlay_dns_ip:53` trước `CryptokeyValidator`, Android trả **`TCP RST`** trên `:853` + cảnh báo `isPrivateDnsActive()` + upstream `LinkProperties.getDnsServers()` + `addSearchDomain` + kiểm soát IPv6 DNS; iOS dùng `NEDNSSettings(matchDomains: ["mesh.internal"])`. | `US-080`, `US-083`, `US-090`, `M-GNFR-04` |
| **T-MOB-06** | **Rò rỉ khóa riêng qua Cloud/ADB Backup** (Google Drive Auto Backup, `adb backup`, iCloud Backup/Keychain Sync) | Khóa riêng thoát khỏi sandbox phần cứng thiết bị lên cloud/máy khác. | Android `allowBackup="false"` + `dataExtractionRules` + `noBackupFilesDir`; iOS `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` + `kSecAttrSynchronizable = false`. | `US-082`, `US-088`, `US-096` |
| **T-MOB-07** | **Chiếm đoạt / lộ Pre-Auth Key (`mpk_*`) qua Custom URL Scheme Hijacking, Clipboard hoặc QR** | App độc hại đăng ký trùng scheme `mesh://` cướp `mpk_*` qua OS deep-link, đọc clipboard, hoặc chụp màn hình mã QR. | **Cấm đăng ký OS-wide clickable deep-link intent cho URI chứa `mpk_*`**; chỉ quét QR bằng camera nội bộ hoặc dán trong app (`*(KN)*: PasteButton`/`UIPasteControl` trên iOS 16+); xóa/hết hạn clipboard + xóa `mpk_*` khỏi RAM/đĩa sau enroll; `FLAG_SECURE` Android. | `US-080`, `US-084`, `US-091`, `US-096` |
| **T-MOB-08** | **iOS Jetsam kết liễu Network Extension (`~50 MiB`) hoặc `lmkd` thu hồi Android Service** | Extension chết âm thầm (`EXC_RESOURCE`) khi WS frame `4 MiB`, `spawn_blocking` DNS, hoặc IPC `bugreport` nhân bản RAM. | Thiết kế Rust sans-I/O không GC, đỉnh **`RSS <= 25 MiB`** iOS / **`<= 48 MiB`** Android, hạ WS frame `<= 256 KiB`, `max_blocking_threads <= 2`, queue `256` + `try_send()`, buffer `2048 B`, `os_proc_available_memory()`, `bugreport` qua tệp App Group. | `US-076`, `US-077`, `US-079`, `US-082`, `US-087`, `US-089`, `US-097`, `M-GNFR-01/02/08` |
| **T-MOB-09** | **Lộ bí mật trong `logcat`, `OSLog` hoặc `bugreport` Share Sheet** | Người dùng gửi gói chẩn đoán ra ngoài mang theo private key, token hoặc `mpk_*`. | Bọc mọi bí mật bằng `mesh_crypto::Secret<T>`; dùng `%{private}@` trên iOS `OSLog`; lớp sanitize trên FFI/exporter + bộ test tự động `test_no_secrets_in_outputs` (`0` leak). | `US-078`, `US-079`, `US-084`, `US-088`, `US-091`, `US-096`, `GNFR-02` |

---

## 3. Cấu trúc 4 Epics Mới (`EP-13..EP-16`)

Bảng tổng hợp dưới đây thống kê toàn bộ các Epics thuộc Milestone **`v0.2.0` — Mobile Clients** (`US-075..099`), tách biệt khỏi 12 Epics `v0.1.0` (`US-001..074`):

| Epic | Tên Epic | Platform | Mã `MOB-*` bao phủ | Stories (ID) | Tổng Story | Must (Story / SP) | Should (Story / SP) | Could (Story / SP) | Tổng SP |
|---|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **EP-13** | Shared Client Control/Datapath Core, FFI Bridge & `mesh-server` Compatibility | `Shared` | `MOB-OPS-03`, `MOB-SEC-03/04/05`, `MOB-REL-01/03/04/05/06`, `MOB-PLAT-AND-02/05`, `MOB-PLAT-IOS-03/05`, `MOB-PERF-03/04/05`, `MOB-OPS-04` | `US-075..080`, `US-099` | 7 | 7 / 34 | 0 / 0 | 0 / 0 | 34 |
| **EP-14** | Android Native Client (`VpnService` & Mobile UI `*(KN: Jetpack Compose)*`) | `Android` | `MOB-PLAT-AND-01..06`, `MOB-SEC-01/04/05/06`, `MOB-REL-02/04/06`, `MOB-PERF-02/05`, `MOB-OPS-AND-01`, `MOB-OPS-04` | `US-081..086` | 6 | 5 / 23 | 1 / 3 | 0 / 0 | 26 |
| **EP-15** | iOS Native Client (`NEPacketTunnelProvider` & Mobile UI `*(KN: SwiftUI)*`) | `iOS` | `MOB-PLAT-IOS-01..06`, `MOB-SEC-02/04/05/06`, `MOB-REL-02/04/06`, `MOB-PERF-01/04/05`, `MOB-OPS-IOS-01`, `MOB-OPS-04` | `US-087..093` | 7 | 6 / 31 | 1 / 3 | 0 / 0 | 34 |
| **EP-16** | Mobile QA, Compatibility, Privacy & Multi-OS CI/Release | `Mobile QA & CI` | `MOB-REL-01..05`, `MOB-SEC-01/02/04/05/06`, `MOB-PERF-01..04`, `MOB-OPS-IOS-01`, `MOB-OPS-AND-01`, `MOB-OPS-03/04/05` | `US-094..098` | 5 | 4 / 20 | 0 / 0 | 1 / 3 | 23 |
| | **Tổng cộng Milestone `v0.2.0` (`EP-13..EP-16`)** | | **34 / 34 mã `MOB-*`** | **`US-075..099`** | **25** | **22 / 108** | **2 / 6** | **1 / 3** | **117** |

> **Kiểm toán nhất quán số đếm:** `22 (Must) + 2 (Should) + 1 (Could) = 25 stories` · `108 (Must SP) + 6 (Should SP) + 3 (Could SP) = 117 SP` · `7 + 6 + 7 + 5 = 25 stories` · `34 + 26 + 34 + 23 = 117 SP`.

---

## 4. Chi tiết Epics & INVEST User Stories (`US-075..US-099`)

---

### 4.1. EP-13 — Shared Client Control/Datapath Core, FFI Bridge & `mesh-server` Compatibility

> Mục tiêu: Trích xuất toàn bộ Client Control Plane (`control_loop`, `NetmapCacheStore`, `roaming_loop`, `ping_probe`) khỏi adapter OS Desktop của `crates/meshd` dùng chung cho Desktop & Mobile; tách phụ thuộc Desktop/Server; hỗ trợ `TargetOs::{Android, Ios}` + `RelayClient`; bảo đảm `SocketProtector`, `PacketFlowTun`, NAT64/DNS64, RFC 4074 Split-DNS, timer **idle-aware**, và giữ mở quyết định `MPL-2.0`/`unsafe` cho Gate 1/2.

#### US-075 — Mở rộng `TargetOs::{Android, Ios}` trên `mesh-proto`, `mesh-server` & `RelayClient` giữ tương thích ngược `v0.1.0-rc1`
- **Epic**: `EP-13` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `Shared`
- **Dependencies**: Không (dựa trên codebase `v0.1.0-rc1` hiện hành).
- **Trace**: `MOB-OPS-03`, `M-GNFR-05`
- **Story**: Là *chủ mạng (`P1`)*, tôi muốn `mesh-server` và `RelayClient` nhận biết chính xác thiết bị Android và iOS khi xác thực mà vẫn giữ nguyên tương thích với các máy tính Desktop `v0.1.0-rc1`, để không phải nâng cấp ép buộc hay cài lại các máy tính hiện có.
- **AC**:
  1. **[H]** *Given* `ChallengeRequest` trong `mesh-proto` bổ sung `TargetOs::Android` (`"android"`) và `TargetOs::Ios` (`"ios"`) cùng `TargetArch`, đồng thời sửa `RelayClient::current_target_os_str()` (`relay_client.rs`) để gửi đúng `"android"`/`"ios"` thay vì fallback cứng `"linux"`, *When* client di động xác thực Control (`POST /v1/auth/challenge`, `POST /v1/nodes/register`) và Relay với `protocol_version = 1`, *Then* `mesh-server` xử lý thành công, lưu `os_arch` vào `redb` không cần migration schema DB và hiển thị đúng OS trong CLI `node list`.
  2. **[H]** *Given* `NetmapSnapshot` và `PeerEntry` vẫn gắn `#[serde(deny_unknown_fields)]` và không chứa trường `os`/`arch`, *When* client Desktop `v0.1.0-rc1` (chưa nâng cấp) nhận snapshot có chứa node Android và iOS, *Then* Desktop parse thành công 100% và trao đổi lưu lượng bình thường với các node di động.
  3. **[E]** *Given* một mạng mesh hỗn hợp gồm `Darwin`, `Windows`, `Linux` (`v0.1.0-rc1`) cùng `Android` và `Ios` (`v0.2.0`) đăng ký và đổi tên/endpoint luân phiên, *When* `mesh-server` phát tán `NetmapSnapshot`, *Then* mọi node giữ nguyên `OverlayIp` và không phát sinh lỗi giải mã hay ghi trùng bản ghi trong `redb`.
  4. **[F]** *Given* client gửi chuỗi `os` lạ không thuộc tập `TargetOs` hợp lệ hoặc thừa trường JSON không xác định, *When* gửi tới `POST /v1/auth/challenge`, *Then* server từ chối rõ ràng với lỗi giải mã chuẩn (`4xx`), không panic và không ghi dữ liệu rác.

#### US-076 — Feature-gate tách phụ thuộc Desktop/Server (`mesh-net`, `mesh-datapath`, `mesh-crypto`), xử lý `route.rs` & tối ưu nhị phân Mobile
- **Epic**: `EP-13` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Shared`
- **Dependencies**: Không.
- **Trace**: `MOB-PERF-05`, `MOB-OPS-03`, `M-GNFR-06`, `M-GNFR-08`
- **Story**: Là *kỹ sư phát triển di động đại diện cho `P5-IOS`/`P5-AND`*, tôi muốn bản biên dịch Rust cho mobile loại bỏ hoàn toàn các phụ thuộc chỉ dành cho Desktop/Server (`axum`, `hyper`, `redb`, `clap`, `rustls-native-certs`, `rcgen`), biên dịch sạch `route.rs` trên 5 target mobile và vượt qua `cargo deny check`, để nhị phân nhẹ dưới trần Jetsam và không lọt thư viện C bị cấm.
- **AC**:
  1. **[H]** *Given* cấu hình Cargo feature flags tách phần trait/filter cốt lõi khỏi phần Desktop/Server trong `mesh-net`, `mesh-datapath` và **`mesh-crypto` (`crates/mesh-crypto/Cargo.toml`)**, đồng thời bổ sung xử lý `#[cfg]` `android`/`ios` hợp lệ cho `crates/mesh-net/src/route.rs` (`bind_underlay_udp_socket`, `bind_underlay_socket2`, `disable_udp_dont_fragment` `DF=0` tránh lỗi `E0308`), *When* chạy `cargo check` và `cargo tree` cho target mobile, *Then* biên dịch sạch trên cả 5 target mobile và có **0 sự xuất hiện** của `axum`, `hyper`, `hyper-util`, `redb`, `clap`, `rustls-native-certs`, `rcgen`, `windows-sys`, `windows-service` và các module `hosts_*`/`firewall_*`/`sysexec`.
  2. **[H]** *Given* bổ sung 5 target triples mobile (`aarch64-linux-android`, `x86_64-linux-android`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`) vào `deny.toml`, *When* chạy `cargo deny check advisories bans licenses sources`, *Then* pass 100% và xác nhận không kéo `openssl-sys`, `aws-lc-rs` hay `native-tls` vào bất kỳ target mobile nào.
  3. **[E]** *Given* build Desktop/Server chuẩn (`meshd`, `mesh-server`, `mesh`) trên Linux/macOS/Windows với default features, *When* chạy bộ `cargo test --workspace`, *Then* mọi tính năng Desktop (`axum` IPC, `redb`, `rustls-native-certs`, `rcgen`, `route.rs` Desktop) vẫn được bật đầy đủ và không gãy bất kỳ test `v0.1.0` nào.
  4. **[N]** *Given* build profile release (`opt-level = 3`, `lto = "thin"`, `strip = "symbols"`) cho `aarch64-linux-android` và `aarch64-apple-ios`, *When* đo dung lượng nhị phân native đã strip, *Then* đạt mục tiêu thiết kế **`<= 6 MiB`** mỗi ABI.
  5. **[F]** *Given* một phụ thuộc mới kéo theo thư viện C cấm (`openssl-sys`/`aws-lc-rs`) hoặc giấy phép bị cấm trên target mobile, *When* chạy kiểm tra trong CI, *Then* `cargo deny check` trả về mã thoát khác 0 và chặn hợp nhất.

#### US-077 — Trừu tượng hóa `SocketProtector`, `MobileTunAdapter`, hỗ trợ IPv6-only NAT64 & Timer Idle-Aware trong `mesh-datapath`
- **Epic**: `EP-13` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Shared`
- **Dependencies**: `US-076`.
- **Trace**: `MOB-PLAT-AND-02`, `MOB-PLAT-IOS-03`, `MOB-REL-01`, `MOB-REL-02`, `MOB-REL-03`, `MOB-REL-05`, `MOB-PERF-03`, `M-GNFR-01`, `M-GNFR-03`, `M-GNFR-09`
- **Story**: Là *người dùng di động (`P5-AND`, `P5-IOS`)*, tôi muốn lõi datapath bảo vệ mọi socket underlay qua callback OS, hỗ trợ cả mạng 4G/5G IPv6-only NAT64 ở chế độ IPv4 literal + Pin, dùng `tun_fd`/`PacketFlowTun` gọn nhẹ và tự giãn timer lúc rỗi, để không tạo routing loop, không lỗi `ENETUNREACH` và không hao pin.
- **AC**:
  1. **[H]** *Given* trait `SocketProtector` được tiêm vào `DatapathEngine`, `MagicSocket`, `StunClient`, `RelayClient` và kênh Control TLS, *When* mở hoặc rebind bất kỳ socket UDP/TCP underlay nào (kể cả trên mạng cellular **IPv6-only NAT64 `64:ff9b::/96`** bằng khám phá Pref64 / tổng hợp địa chỉ IPv6 qua `*(KN)*: getaddrinfo AF_UNSPEC/AI_DEFAULT` / RFC 7050 / `NWPath` Pref64 + dual-stack/IPv6 `MagicSocket` — tránh lỗi `ENETUNREACH`), *Then* `protect(raw_fd)` được gọi **đồng bộ trước** khi `connect()`/`send_to()`, không phụ thuộc `SO_MARK` (`EPERM` trên Android non-root).
  2. **[H]** *Given* adapter TUN hỗ trợ `tun_fd` (Android) và bounded async `PacketFlowTun` (iOS `NEPacketTunnelFlow`), *When* truyền nhận gói qua `defguard_boringtun::noise::Tunn`, *Then* dùng buffer tĩnh `MAX_FRAME_SIZE = 2048 B` (`MTU = 1280`), hàng đợi Relay `RELAY_QUEUE_CAPACITY = 256` với `try_send()` (drop-tail, không HoL blocking), và tiếp tục chuyển tiếp dữ liệu P2P/Relay khi Control offline (`MOB-REL-01`).
  3. **[E]** *Given* hệ thống chuyển sang trạng thái rỗi (không có traffic ứng dụng hay phiên handshake mở) và sau đó có gói tin mới từ TUN/socket, *When* chạy vòng lặp `DatapathEngine` (vốn dùng tick cứng `250 ms` 8 Hz ở Desktop), *Then* engine chạy theo cơ chế **idle-aware / coalesced ticks** (tạm dừng/giãn chu kỳ tick khi rỗi để không đánh thức CPU vô ích, nhưng thức tức thì khi có gói TUN/socket mới hoặc tới hạn timer WireGuard thực tế); đồng thời khi burst 1.000 gói vào peer đọc chậm thì hàng đợi 256 drop-tail êm, không cấp phát bộ nhớ tăng vô hạn.
  4. **[F]** *Given* mock `SocketProtector` trả về `false`/lỗi khi tạo/rebind socket, hoặc không tổng hợp được địa chỉ hợp lệ trên mạng bị cô lập, *When* chuẩn bị gửi dữ liệu, *Then* socket bị **đóng ngay (fail-closed)**, ghi log cấu trúc và **0 gói tin** được gửi ra ngoài.

#### US-078 — Xác thực TLS đa nền tảng (`SpkiPinVerifier` + Native Trust Store), Backoff Lỗi TLS & Lọc Bí mật
- **Epic**: `EP-13` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Shared`
- **Dependencies**: `US-076`.
- **Trace**: `MOB-SEC-03`, `MOB-SEC-05`, `MOB-REL-04`, `MOB-PERF-04`, `MOB-OPS-04`, `GNFR-01`, `GNFR-02`, `M-GNFR-07`, `M-GNFR-09`
- **Story**: Là *chủ mạng quan tâm bảo mật (`P1`)*, tôi muốn ứng dụng di động thực thi chặt chẽ IP + SPKI Pin (kể cả qua kết nối NAT64 tổng hợp), hỗ trợ xác thực CA gốc Android/iOS ở chế độ Domain, phân loại đúng lỗi Captive Portal/Clock Skew và không bao giờ ghi bí mật vào log, để an toàn trên Wi-Fi công cộng và mạng 4G/5G.
- **AC**:
  1. **[H]** *Given* cấu hình mặc định IP + SPKI Pin (`sha256:<hex>`), *When* client di động kết nối Control hoặc Relay WSS trên cổng mặc định hoặc cổng tùy chọn (`GNFR-11`), *Then* dùng `SpkiPinVerifier` (`x509-cert` + `ring` + `subtle`) so sánh hằng thời gian và kiểm tra `NotBefore`/`NotAfter`, hoàn tất bắt tay trong **`<= 2 s`** (`MOB-PERF-04`) trên mạng ổn định.
  2. **[H]** *Given* cấu hình chế độ Domain + CA hệ thống (`SEC-04(a)`), *When* kết nối từ Android (kể cả khi `VpnService` chạy nền không mở `MainActivity`, với điểm **khởi tạo sớm JNI `Context` trong `Application.onCreate()` / `VpnService.onCreate()`**) hoặc iOS, *Then* xác thực qua trust store gốc của OS (`*(KN)*: rustls-platform-verifier` gọi `TrustManager` Android / `Security.framework` iOS), tôn trọng chứng chỉ CA doanh nghiệp và thu hồi OS mà không dùng `openssl-sys`/`aws-lc-rs`.
  3. **[E]** *Given* client kết nối bằng IPv4 literal + SPKI Pin nhưng đường truyền TCP đi qua địa chỉ IPv6 tổng hợp NAT64 (`64:ff9b::<ipv4>`), *When* `SpkiPinVerifier` xác thực chứng chỉ TLS từ `mesh-server`, *Then* kiểm chứng SPKI Pin vẫn thực thi nghiêm ngặt trên chứng chỉ nhận được mà không bị hạ cấp hay bỏ qua bước kiểm pin.
  4. **[F]** *Given* cấu hình thiếu pin khi dùng IP, chứng chỉ MITM/Captive Portal sai pin, hoặc đồng hồ thiết bị lệch ngoài hạn chứng chỉ, *When* kết nối, *Then* **fail-closed ngay (0 secret/proof gửi đi)**, phân loại tường minh 3 mã lỗi (`PinMismatch` vs `CaptivePortalSuspected` vs `ClockSkew`), áp dụng `ExponentialBackoff` trần `300_000 ms` (`BACKOFF_TLS_MAX_MS`) — không tồn tại chế độ TOFU; đồng thời mọi biến bí mật bọc `mesh_crypto::Secret<T>` xuất log JSON chuẩn `OPS-01` vào ring-buffer `<= 1 MiB` cho kết quả `0` secret / `0` `mpk_` ở cả mức `debug`.

#### US-079 — Lớp cầu nối FFI Di động (`mesh-mobile-ffi`) & Vòng đời Engine, Giới hạn Jetsam & Radio `RRC_IDLE`
- **Epic**: `EP-13` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Shared`
- **Dependencies**: `US-075`, `US-077`, `US-078`, `US-099`.
- **Trace**: `MOB-OPS-03`, `MOB-REL-03`, `MOB-REL-06`, `MOB-PERF-01`, `MOB-PERF-03`, `MOB-OPS-04`, `MOB-SEC-05`, `M-GNFR-01`, `M-GNFR-06`, `M-GNFR-07`
- **Story**: Là *kỹ sư tích hợp nền tảng Android/iOS*, tôi muốn một lớp cầu nối FFI sạch với hợp đồng vòng đời đầy đủ (khởi động, dừng êm, báo đổi mạng, xuất `bugreport` ra tệp, kiểm soát bộ nhớ/luồng Tokio và giãn nhịp radio khi tắt màn hình), để app Android và iOS giao tiếp đồng nhất với lõi Rust mà không chạm trần Jetsam hay giữ sóng `RRC_CONNECTED`.
- **AC**:
  1. **[H]** *Given* hợp đồng API FFI (giữ mở lựa chọn cơ chế tại Gate 1/Gate 2: `*(KN)*: UniFFI` theo kết quả `OQ-MOB-05` vs `jni` + `C-ABI` tối giản, và chốt tại Gate 2 ranh giới `unsafe_code = "forbid"` đặt primitive `unsafe` trong `mesh-sys` hay phê duyệt crate `mesh-mobile-ffi`), *When* lớp nền gọi `start` → `on_network_change` → `status`/`peers`/`ping`/`netcheck` → `export_bugreport_to_file(path)` → `stop`, *Then* mỗi lệnh hoạt động an toàn luồng (thread-safe), không panic qua ranh giới FFI, và trả mã lỗi có cấu trúc.
  2. **[N]** *Given* cấu hình tài nguyên cho môi trường di động, *When* runtime Tokio và kênh WebSocket Control khởi tạo, *Then* giới hạn **`max_blocking_threads <= 2`** (cho `tokio::net::lookup_host`), hạ trần **`MAX_CONTROL_WS_FRAME_BYTES <= 256 KiB`**, phản hồi `status`/`peers` qua IPC giới hạn `<= 4 KiB`, và teardown qua `CancellationToken` hoàn tất **`<= 5_000 ms`** (`GRACEFUL_SHUTDOWN_BUDGET_MS`).
  3. **[E]** *Given* thiết bị tỉnh dậy sau Doze / App Nap với độ lệch đồng hồ `> CLOCK_JUMP_THRESHOLD_MS (30_000 ms)`, hoặc nhận tín hiệu tắt màn hình/rỗi (`set_power_saving_mode`), *When* xử lý, *Then* thức dậy kiểm tra lại ngay Control TLS/Netmap; còn khi idle, engine đồng bộ pha hoặc giãn chu kỳ heartbeat 2 luồng Control+Relay trong biên an toàn `HEARTBEAT_TIMEOUT_MS = 60 s` (hoặc tạm đóng kênh Relay rỗi khi không có lưu lượng/peer cần relay) giúp modem 4G/5G hạ về **`RRC_IDLE`** (`MOB-PERF-03`).
  4. **[F]** *Given* lỗi đọc/ghi tệp đích khi gọi `export_bugreport_to_file(path)` hoặc tham số `path` không hợp lệ/tràn bộ nhớ, *When* thực thi, *Then* FFI trả lỗi rõ ràng, tuyệt đối không nhồi payload `<= 1 MiB` vào kênh status `<= 4 KiB`, không mở bất kỳ TCP listener nào trên app di động, và `0` bí mật xuất hiện trong tệp xuất ra (`MOB-SEC-05`).

#### US-080 — Bộ phân giải Split-DNS `.mesh.internal` chuẩn RFC 4074 & Bộ phân tích/sinh URI `mesh://` (`crates/mesh` CLI)
- **Epic**: `EP-13` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `Shared`
- **Dependencies**: `US-075`, `US-078`.
- **Trace**: `MOB-PLAT-AND-05`, `MOB-PLAT-IOS-05`, `MOB-SEC-04`, `M-GNFR-04`
- **Story**: Là *người dùng di động (`P5-AND`, `P5-IOS`, `P5-INV`)*, tôi muốn phân giải `.mesh.internal` đúng chuẩn RFC 4074 (không gãy Happy Eyeballs hay bị `CryptokeyValidator` drop) và có công cụ trên CLI quản trị `crates/mesh` sinh QR/URI `mesh://` tương thích `PreAuthKeyCreatedResponse`, để vào homelab bằng tên miền nội bộ và onboarding không cần gõ tay chuỗi khóa dài.
- **AC**:
  1. **[H]** *Given* địa chỉ `overlay_dns_ip` nằm trong dải route vào TUN nhưng **không bao giờ trùng `OverlayIp` của bất kỳ peer nào**, gói IP L3 đích `overlay_dns_ip:53` (UDP & TCP) được tách **trước khi** đi vào `CryptokeyValidator`, *When* nhận truy vấn tên miền kết thúc bằng `.mesh.internal` (`domain_suffix` của `NetmapSnapshot`), *Then* DNS responder nhúng tuân thủ **RFC 4074 §3**: với peer tồn tại trả `A` → `OverlayIp`, `PTR` → FQDN `.mesh.internal`, và **`AAAA` (cùng QTYPE rỗng khác) trả `NOERROR` (`RCODE=0`) với `ANCOUNT=0` (`NODATA`)**; với tên không tồn tại trả `NXDOMAIN` — và **0 gói** `.mesh.internal` thoát ra mạng vật lý.
  2. **[H]** *Given* quản trị viên (`P1`) dùng **CLI quản trị `crates/mesh`** trên VPS kết nối `/run/mesh-server/admin.sock` tạo pre-auth key (sử dụng dữ liệu từ `PreAuthKeyCreatedResponse` vốn gắn `#[serde(deny_unknown_fields)]`), *When* yêu cầu xuất thông số onboarding di động, *Then* `crates/mesh` dựng chuỗi URI `mesh://` (và mã QR tùy chọn) mang `server_endpoint`, `active_pin` (`sha256:<hex>` hoặc chế độ CA), `raw_key` (`mpk_*`) và gợi ý `node_name`, không lưu URI chứa `mpk_*` vào DB/log và không làm gãy tương thích IPC hiện hành.
  3. **[E]** *Given* truy vấn DNS `.mesh.internal` qua **TCP `:53`** (khi bản ghi lớn > 512 B) hoặc gói probe **Opportunistic DoT TCP `:853`** tới `overlay_dns_ip:853` (từ `netd` Android), *When* responder nhận, *Then* xử lý chuẩn truy vấn TCP `:53` và trả **TCP `RST` (hoặc ICMP Port Unreachable) tức thì** cho `:853` để OS hạ về `:53` ngay không timeout.
  4. **[F]** *Given* đầu vào URI `mesh://` sai định dạng, thiếu `sha256:` pin khi dùng IP, chứa ký tự điều khiển hoặc tên node nằm trong danh sách tên cấm (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`), *When* parser trong lõi mobile kiểm tra, *Then* từ chối ngay với lỗi rõ ràng, giữ `mpk_*` trong `Secret<String>` và zeroize sau khi dùng hoặc khi bị từ chối (**không đăng ký OS-wide deep-link intent cho URI chứa `mpk_*`** — `MED-MOB-02`).

#### US-099 — Trích xuất & tái sử dụng lõi Client Control Plane (`control_loop`, `NetmapCacheStore`, `roaming_loop`, `ping_probe`) khỏi `crates/meshd`
*(Đặt mã `US-099` ở cuối `EP-13` để giữ nguyên ổn định các mã `US-075..098` đang đối chiếu; về thứ tự thực thi thuộc **Wave A — Shared Core**.)*
- **Epic**: `EP-13` · **SP**: `8` · **MoSCoW**: `Must` · **Platform**: `Shared`
- **Dependencies**: `US-075`, `US-076`.
- **Trace**: `MOB-REL-01`, `MOB-SEC-03`, `MOB-SEC-05`, `MOB-OPS-03`, `M-GNFR-05`
- **Story**: Là *kiến trúc sư/chủ mạng (`P1`)*, tôi muốn toàn bộ lõi Client Control Plane (~3.641 dòng `control_loop.rs`, `netmap_cache.rs`, `roaming_loop.rs`, `ping_probe.rs` hiện nằm trong binary `crates/meshd`) được trừu tượng hóa khỏi các adapter OS Desktop (`FileHostsEditor`, `ResourceLedger`, `StdCommandExecutor`) và trích xuất sang thư viện OS-neutral dùng chung cho cả `meshd` Desktop và Mobile FFI, để không viết trùng hàng nghìn dòng logic mật mã/đồng bộ và giữ đồng nhất hành vi giữa Desktop và Mobile.
- **AC**:
  1. **[H]** *Given* lõi Client Control Plane được tách khỏi `FileHostsEditor`, `ResourceLedger` và `StdCommandExecutor` thông qua trait/adapter OS-neutral (vị trí crate cụ thể trong workspace do Gate 2 chốt theo chuẩn), *When* cả `meshd` Desktop và Mobile FFI sử dụng chung máy trạng thái này (`POST /v1/auth/challenge`, `seal_proof` + `tls-exporter` RFC 9266, `POST /v1/nodes/register`, WebSocket `/v1/netmap/stream`, `US-034`, `US-074`, `roaming_loop`, `ping_probe`), *Then* cả hai nền tảng chạy chung 100% logic giao thức và **toàn bộ regression tests hiện có của `crates/meshd` Desktop vẫn PASS 100%**.
  2. **[E]** *Given* `mesh-server` offline khi client khởi động lại hoặc mất kết nối Control giữa chừng, *When* `NetmapCacheStore` OS-neutral nạp cache cục bộ (đọc qua file phân quyền chặt ở Desktop hoặc vùng lưu mã hóa/App Group ở Mobile), *Then* tôn trọng chính sách ân hạn tối đa 24h (`US-033`) và cập nhật tức thì ngay khi `NetmapSnapshot` mới có `netmap_version` cao hơn về tới qua stream; đồng thời phản ứng đồng nhất với `TerminationReason::{NodeRevoked, NodeKeyExpired}`.
  3. **[F]** *Given* dữ liệu `NetmapCacheStore` bị cắt cụt/hỏng checksum hoặc kênh TLS lỗi xác thực `tls-exporter` channel binding, *When* lõi Control Plane xử lý, *Then* từ chối fail-closed cache hỏng hoặc proof không hợp lệ, không ghi đè danh tính node và chuyển về trạng thái backoff an toàn mà không panic.

---

### 4.2. EP-14 — Android Native Client (`VpnService` & Mobile UI `*(KN: Jetpack Compose)*`)

> Mục tiêu: Xây dựng ứng dụng Android thuần Kotlin + giao diện `*(KN: Jetpack Compose)*` tích hợp `VpnService` tuân thủ Android 14+ `specialUse`, `protect(fd)` 100% socket, Keystore `AES-256-GCM` chống Cloud Backup, Split-DNS RFC 4074 + Private DNS `:853`, Direct Boot & cảnh báo Lockdown, và CI tạo `.apk`/`.aab` chi phí `$0`.

#### US-081 — Khởi tạo `VpnService` không root, chống Routing Loop 100% bằng `protect(fd)` & Android 14+ `specialUse`
- **Epic**: `EP-14` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Android`
- **Dependencies**: `US-077`, `US-079`.
- **Trace**: `MOB-PLAT-AND-01`, `MOB-PLAT-AND-02`, `MOB-PLAT-AND-03`, `M-GNFR-03`
- **Story**: Là *người dùng Android (`P5-AND`)*, tôi muốn ứng dụng dựng đường hầm VPN không cần root trên Android 14/15/16 và bảo vệ 100% socket underlay bằng `VpnService.protect(fd)`, để vào mạng mesh ổn định mà không bao giờ bị hệ điều hành giết service hay mất Internet do routing loop.
- **AC**:
  1. **[H]** *Given* người dùng cấp quyền VPN hệ thống qua `VpnService.prepare`, *When* khởi động tunnel, *Then* `VpnService.Builder` thiết lập `addAddress(overlay_ip, prefix)`, `addRoute(overlay_cidr)`, `setMtu(1280)` (`DEFAULT_TUN_MTU`) và **không thêm route `0.0.0.0/0`**, nhận `ParcelFileDescriptor` (`tun_fd`) qua `Builder.establish()`, truyền an toàn sang Rust engine và đóng sạch khi dừng.
  2. **[H]** *Given* callback `SocketProtector` gắn vào `VpnService.protect(fd)` và Android 14+ (API 34/35/36), *When* `VpnService` chạy `startForeground()` (với `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_SPECIAL_USE`, `foregroundServiceType="specialUse"`, `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`), *Then* service chạy ổn định không phát sinh `MissingForegroundServiceTypeException` / `ForegroundServiceStartNotAllowedException`, và **100% socket underlay** (UDP `MagicSocket`, TCP Control TLS, TCP Relay WSS, UDP STUN, DNS forwarder) đều qua `protect(fd)` đồng bộ trước `connect()`/`send_to()`.
  3. **[E]** *Given* ứng dụng chuyển vùng hoặc khởi động lại tunnel tạo socket underlay mới và `ParcelFileDescriptor` mới, *When* rebind diễn ra, *Then* socket mới vẫn bắt buộc qua `protect(fd)` trước khi gửi gói đầu tiên và `tun_fd` cũ được đóng trước khi thay thế, không rò fd.
  4. **[F]** *Given* `VpnService.protect(fd)` trả về `false` hoặc `Builder.establish()` trả về `null` (quyền VPN bị thu hồi/chặn), *When* khởi tạo hoặc mở socket, *Then* đóng ngay socket/phiên (**fail-closed**), ghi log cấu trúc, **0 gói tin** thoát ra ngoài và cập nhật trạng thái lỗi rõ ràng trên UI.

#### US-082 — Lưu trữ khóa Android Keystore (`AES-256-GCM`), Chống Cloud/ADB Backup & Ngân sách RAM `<= 48 MiB`
- **Epic**: `EP-14` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Android`
- **Dependencies**: `US-076`, `US-078`.
- **Trace**: `MOB-SEC-01`, `MOB-PERF-02`, `M-GNFR-02`, `M-GNFR-08`
- **Story**: Là *chủ mạng (`P1`, `P5-AND`)*, tôi muốn khóa riêng trên điện thoại Android được mã hóa bằng Android Keystore phần cứng và chặn tuyệt đối Google Drive/ADB Backup, đồng thời tiến trình nền gọn nhẹ dưới `48 MiB`, để không rò khóa khi đồng bộ đám mây và không bị Android đóng ngầm.
- **AC**:
  1. **[H]** *Given* thiết bị enroll thành công nhận `Secret<[u8; 32]>`, *When* lưu khóa và trạng thái nhạy cảm xuống bộ nhớ thiết bị, *Then* khóa chủ nằm trong **Android Keystore (`AES-256-GCM`)**, dữ liệu mã hóa lưu vào `context.noBackupFilesDir` với quyền riêng tư app (`0600`) — không dùng `EncryptedSharedPreferences` đã deprecated (`*(KN)*`).
  2. **[N]** *Given* `VpnService` Android hoạt động liên tục với `<= 50` peer trong Netmap (truyền dữ liệu và idle), *When* đo bằng Android Studio Profiler, *Then* tổng bộ nhớ RSS (ART heap + Rust `.so`) đạt mục tiêu thiết kế **`<= 48 MiB`**.
  3. **[E]** *Given* tệp khóa mã hóa trong `noBackupFilesDir` bị hỏng hoặc khóa chủ Android Keystore bị vô hiệu hóa (ví dụ user xóa khóa/đặt lại bảo mật thiết bị), *When* dịch vụ đọc khóa khi khởi động, *Then* **không** âm thầm sinh khóa mới ghi đè danh tính cũ; báo lỗi rõ ràng yêu cầu người dùng đăng ký lại nút.
  4. **[F]** *Given* `AndroidManifest.xml` đặt `android:allowBackup="false"` và cấu hình `android:dataExtractionRules` (API 31+) chặn toàn bộ cloud backup & device-to-device transfer, *When* kiểm thử trích xuất bằng `adb backup` hoặc quét XML rules, *Then* thu được **0 byte** khóa riêng hoặc cấu hình nhạy cảm.

#### US-083 — Split-DNS `.mesh.internal` chuẩn RFC 4074 trên Android, Private DNS `:853`, Roaming `NetworkCallback` & `onRevoke()`
- **Epic**: `EP-14` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Android`
- **Dependencies**: `US-080`, `US-081`.
- **Trace**: `MOB-PLAT-AND-05`, `MOB-PLAT-AND-06`, `MOB-REL-02`, `MOB-REL-04`, `MOB-REL-06`, `M-GNFR-04`, `M-GNFR-07`
- **Story**: Là *người dùng di động (`P5-AND`)*, tôi muốn truy cập `nas.mesh.internal` trên trình duyệt/app Android (kể cả khi bật Private DNS) mà vẫn mở được web công cộng, tự nối lại nhanh khi đổi Wi-Fi ↔ 4G/5G và tắt sạch khi hệ thống thu hồi quyền VPN, để dùng cả ngày không cần tắt bật lại.
- **AC**:
  1. **[H]** *Given* `VpnService.Builder.addDnsServer(overlay_dns_ip)` + `addSearchDomain(domain_suffix)`, danh sách upstream lấy từ **`LinkProperties.getDnsServers()` của mạng vật lý underlay hiện hành** (loại trừ `overlay_dns_ip`), *When* app truy vấn `nas.mesh.internal` (`A` & `AAAA`) và `example.com` đồng thời, *Then* `.mesh.internal` được resolver nhúng (`US-080` chuẩn RFC 4074) trả lời tức thì, `example.com` được chuyển tiếp qua socket đã `protect(fd)`/`network.bindSocket` thành công, và bắt gói trên `wlan0`/`rmnet_data*` cho thấy **0 gói `.mesh.internal`** thoát ra ngoài (kể cả IPv6 DNS).
  2. **[N]** *Given* thiết bị đang truyền luồng TCP/ICMP nội bộ trên Wi-Fi, *When* tắt Wi-Fi chuyển sang 4G/5G (kể cả IPv6-only NAT64) và ngược lại, *Then* `ConnectivityManager.NetworkCallback` đánh thức `on_network_change`, rebind + `protect(fd)` trên mạng mới, cập nhật lại danh sách `LinkProperties.getDnsServers()` vật lý, và phục hồi kết nối trong **`<= 5 s`** (sau khi interface mới có địa chỉ).
  3. **[E]** *Given* thiết bị đang bật Android 9+ **Private DNS**: (a) ở chế độ *Automatic*, khi `netd` probe `overlay_dns_ip:853`, resolver trả **`TCP RST` tức thì** để hạ về `:53` không timeout; (b) ở chế độ *Strict*, khi `LinkProperties.isPrivateDnsActive()` (`getPrivateDnsServerName() != null`) trả về `true`, ứng dụng hiển thị cảnh báo rõ trên UI/Notification rằng tên `.mesh.internal` có thể bị đẩy ra DoT ngoài VPN.
  4. **[F]** *Given* hệ điều hành thu hồi quyền VPN (`VpnService.onRevoke()`), hoặc người dùng bật **Airplane Mode** (mất sạch mọi mạng vật lý), hoặc DNS upstream vật lý timeout, *When* xảy ra, *Then* `onRevoke()` teardown sạch trong **`<= 5 s`** cập nhật UI "Đã ngắt"; Airplane Mode tạm ngừng vòng retry bắn gói vô ích tới khi có `onAvailable`; và DNS upstream timeout trả `SERVFAIL` gọn không treo TUN hay crash tunnel.

#### US-084 — Giao diện Android `*(KN: Jetpack Compose)*` Onboarding an toàn (QR / Dán URI / Nhập tay), Chẩn đoán & Xuất `bugreport` sạch
- **Epic**: `EP-14` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Android`
- **Dependencies**: `US-079`, `US-080`, `US-082`.
- **Trace**: `MOB-SEC-04`, `MOB-SEC-05`, `MOB-SEC-06`, `MOB-REL-04`, `MOB-OPS-04`
- **Story**: Là *người dùng Android (`P5-AND`, `P5-INV`)*, tôi muốn thêm máy bằng quét QR camera nội bộ, dán URI `mesh://` trong app hoặc nhập tay `IP:cổng + Pin`, xem danh sách peer/`ping`/`netcheck` và xuất `bugreport` sạch bí mật, để tự vận hành và gỡ lỗi ngay trên điện thoại.
- **AC**:
  1. **[H]** *Given* người dùng mở màn hình Onboarding (`*(KN: Jetpack Compose)*`), *When* quét mã QR bằng camera nội bộ, dán URI `mesh://` vào ô nhập trong app (**không đăng ký OS-wide clickable deep-link intent cho URI chứa `mpk_*`** — `MED-MOB-02`) hoặc nhập tay `IP:cổng + sha256:<pin> + mpk_*`, *Then* ứng dụng hiển thị màn hình **xác nhận rõ ràng Endpoint + Fingerprint Pin** trước khi gửi proof (không có tùy chọn bỏ qua pin hay TOFU), đặt `FLAG_SECURE` chống chụp/quay màn hình trên trang chứa khóa, xóa clipboard chứa `mpk_*` sau khi đọc (Android 13+ `ClipboardManager.clearPrimaryClip()`) và xóa `mpk_*` khỏi RAM/đĩa ngay sau enroll.
  2. **[H]** *Given* thiết bị đã kết nối mesh, *When* người dùng mở màn hình Trạng thái/Chẩn đoán, *Then* xem được trạng thái tunnel, IP overlay, `server endpoint` + Pin, danh sách peer (`direct` vs `relay`, RTT), chạy `ping <peer>` và `netcheck`, và xuất tệp `bugreport` đã sanitize qua Android Share Intent (`0` bí mật / `0` `mpk_*` — `MOB-SEC-05`).
  3. **[E]** *Given* mã QR bị mờ/cắt cụt hoặc người dùng nhập sai định dạng `sha256:` pin / cổng không hợp lệ, *When* xác nhận, *Then* UI báo lỗi kiểm chứng cục bộ rõ ràng từng trường và không gửi bất kỳ gói mạng nào tới server.
  4. **[F]** *Given* lỗi kết nối TLS/mạng hoặc Control gửi `node_revoked`/`node_key_expired` qua kênh TLS hợp lệ, *When* app nhận mã từ lõi Rust, *Then* UI phân biệt rõ **Captive Portal Wi-Fi**, **Lệch giờ (`ClockSkew`)** hay **Sai SPKI Pin (Nghi ngờ MITM)**; riêng thu hồi/hết hạn thì ngắt tunnel ngay, dừng reconnect, xóa khóa phiên cục bộ khỏi Keystore/đĩa và hiển thị rõ lý do (`MOB-SEC-06`).

#### US-085 — Hỗ trợ Always-On VPN (kèm Direct Boot), Cảnh báo Lockdown Mode (`G4`) & Xác thực sinh trắc học trên Android
- **Epic**: `EP-14` · **SP**: `3` · **MoSCoW**: `Should` · **Platform**: `Android`
- **Dependencies**: `US-081`, `US-084`.
- **Trace**: `MOB-PLAT-AND-04`, `MOB-SEC-06`
- **Story**: Là *người dùng Android nâng cao (`P5-AND`)*, tôi muốn bật Always-On VPN tự khởi động an toàn qua Direct Boot sau reboot, nhận cảnh báo rõ ràng nếu lỡ bật Lockdown Mode làm mất Internet máy thật (`G4`) và có xác thực sinh trắc học cho thao tác nhạy cảm, để điện thoại an toàn mà không bao giờ mất mạng âm thầm.
- **AC**:
  1. **[H]** *Given* người dùng bật **Always-On VPN** trong Cài đặt hệ thống Android, *When* khởi động lại điện thoại và mở khóa thiết bị, *Then* `VpnService` tự khởi động tunnel mà không cần mở Main UI.
  2. **[E]** *Given* điện thoại khởi động vào **Direct Boot (`LOCKED_BOOT_COMPLETED`) trước khi người dùng mở khóa lần đầu** (lúc `noBackupFilesDir` chưa đọc được), *When* Android gọi `VpnService` tự khởi chạy, *Then* service **không crash**, hiển thị Notification trạng thái *"Đang chờ mở khóa thiết bị để nạp khóa VPN"* và đăng ký lắng nghe **`ACTION_USER_UNLOCKED`** để tự nạp khóa & dựng tunnel ngay sau khi mở khóa lần đầu (`HR-MOB-02`).
  3. **[F]** *Given* người dùng bật **"Chặn kết nối không có VPN" (`VpnService.isLockdownEnabled() == true`)** trên Android 10+ (API 29+) khi Mesh VPN `v0.2.0` đang chạy Split-Tunnel (không có `0.0.0.0/0`), *When* kiểm tra trạng thái, *Then* socket `protect(fd)` vẫn kết nối Control/Relay bình thường (tuyệt đối không đẩy Control/Relay vào TUN), **nhưng** ứng dụng hiển thị **cảnh báo nổi bật trên Notification & Main UI** cho biết Android Lockdown đang chặn toàn bộ Internet ngoài VPN của mọi app khác và hướng dẫn tắt Lockdown để bảo toàn `G4`.
  4. **[F]** *Given* người dùng mở thông số Pin quản trị chi tiết hoặc xóa danh tính nút trong cài đặt app nhưng hủy xác thực (`*(KN)*: BiometricPrompt` / Device Credential) hoặc máy chưa cài khóa màn hình, *When* thực hiện, *Then* từ chối thao tác nhạy cảm an toàn, không lộ thông tin và không xóa khóa.

#### US-086 — Workflow CI `ubuntu-latest` biên dịch Android NDK & Đóng gói `.apk`/`.aab` cài đặt `$0`
- **Epic**: `EP-14` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `Android`
- **Dependencies**: `US-076`, `US-081`.
- **Trace**: `MOB-OPS-AND-01`, `MOB-PERF-05`, `M-GNFR-06`, `M-GNFR-08`
- **Story**: Là *chủ mạng (`P1`)*, tôi muốn CI trên `ubuntu-latest` tự động biên dịch các ABI Android, chạy unit/lint test và xuất tệp `.apk` + `.aab`, để tôi cài thử nghiệm lên điện thoại Android với chi phí `$0`.
- **AC**:
  1. **[H]** *Given* mã nguồn Android + lõi FFI trên nhánh `feat/mobile-clients`, *When* workflow CI GitHub Actions (`ubuntu-latest`) chạy, *Then* biên dịch thành công `aarch64-linux-android` và `x86_64-linux-android` (`*(KN)*: cargo-ndk`), chạy unit test Kotlin/Gradle + lint, và đóng gói artifact `.apk` (cài sideload USB `$0` kiểm chứng app mở & nạp thư viện native thành công; nghiệm thu kết nối E2E đầy đủ thuộc `US-097`) cùng `.aab`.
  2. **[E]** *Given* tệp `.apk`/`.aab` đóng gói đa ABI (`arm64-v8a` + `x86_64`), *When* kiểm tra cấu trúc đóng gói và kích thước thư viện native, *Then* mỗi ABI `.so` đạt mục tiêu `<= 6 MiB` và manifest chứa đúng quyền `FOREGROUND_SERVICE_SPECIAL_USE` + `allowBackup="false"`.
  3. **[F]** *Given* kích thước mỗi `.so` vượt quá ngân sách, xuất hiện thư viện C cấm, hoặc bước `lint`/unit test Kotlin thất bại, *When* chạy CI, *Then* pipeline trả mã lỗi khác 0 và không xuất bản artifact.

---

### 4.3. EP-15 — iOS Native Client (`NEPacketTunnelProvider` & Mobile UI `*(KN: SwiftUI)*`)

> Mục tiêu: Xây dựng ứng dụng iOS tuân thủ chặt App Store Review (2 tiến trình, `packetFlow` chính thống, Keychain non-sync, `NEDNSSettings` RFC 4074, IPv6-only NAT64 Guideline 2.5), giữ `RSS <= 25 MiB` dưới trần `50 MiB` Jetsam, xuất `bugreport` qua tệp App Group, và làm rõ lộ trình CI Simulator miễn phí vs Apple Developer `$99/năm` cho máy thật.

#### US-087 — Kiến trúc 2 tiến trình iOS (`*(KN: SwiftUI)*` App + `NEPacketTunnelProvider`), App Group & IPC `sendProviderMessage`
- **Epic**: `EP-15` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `iOS`
- **Dependencies**: `US-079`.
- **Trace**: `MOB-PLAT-IOS-01`, `MOB-PLAT-IOS-02`, `MOB-OPS-04`, `M-GNFR-01`, `M-GNFR-07`
- **Story**: Là *người dùng iPhone/iPad (`P5-IOS`)*, tôi muốn giao diện người dùng tách biệt hoàn toàn khỏi tiến trình Network Extension và giao tiếp điều khiển qua IPC gốc của Apple (còn file `bugreport` trao đổi qua thư mục App Group thay vì nhồi `1 MiB` qua IPC), để đáp ứng `SEC-14`, tránh Jetsam và qua App Store Review.
- **AC**:
  1. **[H]** *Given* project Xcode gồm 2 target: Main Container App (`<app_id>`, `*(KN: SwiftUI)*`) và Network Extension (`<app_id>.PacketTunnel`), *When* khởi chạy VPN, *Then* toàn bộ lõi Rust Control/Datapath chạy cô lập trong `NEPacketTunnelProvider`; Main App tuyệt đối không tự mở socket VPN hay giữ tunnel engine chạy nền.
  2. **[H]** *Given* Main App và Extension dùng chung App Group (`group.<bundle_id>`), *When* Main App gửi lệnh điều khiển hoặc đọc trạng thái (`start`/`stop`/`status`/`peers`/`ping`/`netcheck`) qua **`NETunnelProviderSession.sendProviderMessage`** / **`NEPacketTunnelProvider.handleAppMessage`**, *Then* gói phản hồi trạng thái giới hạn chặt **`<= 4 KiB`**; riêng lệnh **`export_bugreport`** (`<= 1 MiB`) chỉ ra lệnh Extension ghi/sanitize log ra tệp trong **`group.<bundle_id>/diagnostics/`** và trả về đường dẫn/metadata `<= 4 KiB` (`HR-MOB-04`).
  3. **[E]** *Given* Main App gọi `sendProviderMessage` trong lúc `NEPacketTunnelProvider` đang ở trạng thái `Disconnected` (tiến trình Extension chưa chạy), *When* `sendProviderMessage` trả về `nil`/lỗi không khả dụng, *Then* Main App không crash và hiển thị trạng thái "Đã ngắt" cùng cấu hình tóm tắt đọc từ cache App Group không nhạy cảm.
  4. **[F]** *Given* kiểm tra bề mặt mạng của Main App và Extension trên iOS, *When* rà soát mã nguồn và socket mở, *Then* **0 TCP/HTTP server** (không có Admin API, không có `/healthz` hay `/metrics` TCP trên localhost).

#### US-088 — Lưu trữ khóa iOS Keychain Access Group (`AfterFirstUnlockThisDeviceOnly`, Non-Sync)
- **Epic**: `EP-15` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `iOS`
- **Dependencies**: `US-078`, `US-087`.
- **Trace**: `MOB-SEC-02`, `MOB-SEC-05`, `M-GNFR-07`
- **Story**: Là *chủ mạng (`P1`, `P5-IOS`)*, tôi muốn khóa riêng của iPhone được lưu trong Keychain Access Group dùng chung giữa Main App và Extension nhưng tuyệt đối không đồng bộ lên iCloud, và xử lý an toàn khi Extension chạy lúc máy vừa reboot chưa mở khóa, để vừa ổn định vừa chống mất khóa/rò khóa.
- **AC**:
  1. **[H]** *Given* Main App hoàn tất đăng ký node, *When* ghi khóa riêng và thông số xác thực nhạy cảm vào Keychain Access Group dùng chung với Extension, *Then* mọi item đặt bắt buộc **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** và **`kSecAttrSynchronizable = false`**.
  2. **[H]** *Given* iPhone vừa khởi động lại (reboot) và người dùng đã mở khóa màn hình lần đầu sau boot, *When* `NEPacketTunnelProvider` khởi chạy nền (kể cả khi màn hình khóa lại sau đó), *Then* Extension đọc được khóa từ Keychain và khôi phục kết nối mesh thành công.
  3. **[E]** *Given* Extension được OS kích hoạt tự động sau reboot **trước khi người dùng mở khóa thiết bị lần đầu**, *When* truy cập Keychain trả về **`errSecInteractionNotAllowed` (`-25308`)**, *Then* Extension thoát/tạm dừng gọn với trạng thái chờ mở khóa, **tuyệt đối không xóa nhầm** khóa hoặc cấu hình hiện có và tự khôi phục bình thường ở lần chạy sau khi đã mở khóa.
  4. **[F]** *Given* kiểm tra iCloud Backup / iCloud Keychain Sync và `OSLog`, *When* quét thuộc tính Keychain và sử dụng `%{private}@` trong `OSLog`, *Then* `0` item có thể sync qua iCloud và `0` chuỗi bí mật hiển thị ở Console/OSLog.

#### US-089 — Cầu nối `packetFlow` Async TUN, Split-Tunnel `includedRoutes` & Kiểm soát trần RAM Jetsam (`<= 25 MiB` RSS)
- **Epic**: `EP-15` · **SP**: `8` · **MoSCoW**: `Must` · **Platform**: `iOS`
- **Dependencies**: `US-077`, `US-079`, `US-087`.
- **Trace**: `MOB-PLAT-IOS-03`, `MOB-PLAT-IOS-04`, `MOB-PERF-01`, `MOB-PERF-04`, `M-GNFR-01`, `M-GNFR-03`, `M-GNFR-09`
- **Story**: Là *người dùng iPhone/iPad (`P5-IOS`)*, tôi muốn Network Extension truyền gói tin chính thống qua `packetFlow`, chỉ route dải overlay, hoạt động qua mạng cellular IPv6-only NAT64 và giữ bộ nhớ dưới `25 MiB` RSS, để không bị Jetsam giết đột ngột giữa phiên làm việc và đạt App Store Review Guideline 2.5.
- **AC**:
  1. **[H]** *Given* `NEPacketTunnelProvider` bắt đầu tunnel, *When* thiết lập `NEPacketTunnelNetworkSettings` (`NEIPv4Settings`), *Then* cấu hình **`includedRoutes = [NEIPv4Route(overlay_cidr)]`** (bao phủ cả `overlay_dns_ip`), `MTU = 1280`, **KHÔNG** đặt default route `0.0.0.0/0`, đọc/ghi gói IP L3 hoàn chỉnh qua **`packetFlow.readPackets`** / **`packetFlow.writePackets`** nối với `PacketFlowTun`, và kết nối tới VPS/Relay/STUN (kể cả qua IPv6-only NAT64) qua giao diện vật lý mà không bị hút ngược vào tunnel.
  2. **[N]** *Given* phiên truyền tải dữ liệu liên tục qua peer WireGuard/Relay với cấu hình bộ nhớ cố định (buffer `[u8; 2048]`, queue `256` + `try_send()`, Tokio worker giới hạn + `max_blocking_threads <= 2`, `MAX_CONTROL_WS_FRAME_BYTES <= 256 KiB`, ring-buffer log `<= 1 MiB`), *When* đo bằng Xcode Instruments Allocation/VM Tracker, *Then* đỉnh bộ nhớ đạt mục tiêu thiết kế **`RSS <= 25 MiB`** (dưới trần cứng `~50 MiB` Jetsam `EXC_RESOURCE`).
  3. **[E]** *Given* lưu lượng burst lớn đẩy vào `packetFlow.readPackets` theo batch trong khi đường truyền Relay/peer đọc chậm, *When* hàng đợi bounded `256` gói đầy, *Then* áp dụng drop-tail qua `try_send()` mà không cấp phát `Vec` tăng vô hạn và không nghẽn luồng đọc `packetFlow`.
  4. **[F]** *Given* rà soát mã nguồn iOS và giám sát **`os_proc_available_memory()`**, *When* kiểm tra code hoặc khi bộ nhớ khả dụng của Extension giảm dưới ngưỡng an toàn (ví dụ `< 10 MiB`), *Then* **0 lời gọi** private hack dò `utun` fd (`getsockopt`/`sysctl`), và Extension kích hoạt backpressure/drop-tail sớm + xả bộ đệm tạm để tránh bị kernel kết liễu `EXC_RESOURCE`.

#### US-090 — Split-DNS nguyên bản (`NEDNSSettings` RFC 4074), Roaming `NWPathMonitor` & Teardown êm trên iOS
- **Epic**: `EP-15` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `iOS`
- **Dependencies**: `US-080`, `US-089`.
- **Trace**: `MOB-PLAT-IOS-05`, `MOB-REL-02`, `MOB-REL-04`, `MOB-REL-06`, `M-GNFR-04`, `M-GNFR-07`, `M-GNFR-09`
- **Story**: Là *người dùng iPhone/iPad (`P5-IOS`)*, tôi muốn phân giải tên `.mesh.internal` bằng `NEDNSSettings` gốc chuẩn RFC 4074 mà không ảnh hưởng DNS mạng thường, tự chuyển vùng mượt từ Wi-Fi sang 4G/5G IPv6-only NAT64 và ngắt gọn trong `<= 5 s`, để trải nghiệm mượt như VPN gốc hệ thống.
- **AC**:
  1. **[H]** *Given* Extension áp dụng `NEDNSSettings(servers: [overlay_dns_ip])` với **`matchDomains = ["mesh.internal"]`** (`domain_suffix` của `NetmapSnapshot`, `overlay_dns_ip` nằm trong `includedRoutes` và không trùng peer IP), *When* truy vấn `*.mesh.internal` (`A` & `AAAA`, UDP & TCP `:53`), *Then* gói đi qua `packetFlow`, tách trước `CryptokeyValidator` và trả lời đúng **RFC 4074 §3** (`A` → `OverlayIp`, `AAAA` → `NOERROR NODATA` tránh gãy Happy Eyeballs của `mDNSResponder`), trong khi web công cộng tiếp tục dùng DNS mặc định nhà mạng/Wi-Fi.
  2. **[N]** *Given* iPhone đang giữ luồng kết nối nội bộ qua Wi-Fi IPv4, *When* người dùng tắt Wi-Fi chuyển sang 4G/5G (bao gồm mạng IPv6-only NAT64) và ngược lại, *Then* `NWPathMonitor` trong Extension gọi ngay `on_network_change` của Rust để rebind/tổng hợp Pref64/STUN/Disco và phục hồi luồng trong **`<= 5 s`** (sau khi path mới khả dụng).
  3. **[E]** *Given* người dùng bấm Ngắt kết nối hoặc iOS gọi `stopTunnel(with:completionHandler:)`, *When* thực thi, *Then* Extension dừng engine Rust, đóng toàn bộ socket và gọi `completionHandler` trong **`<= 5 s`** (`MOB-REL-06`).
  4. **[F]** *Given* iPhone bật **Airplane Mode** (`NWPath.Status.unsatisfied`, không còn interface mạng nào) hoặc cấu hình `NEPacketTunnelNetworkSettings` lỗi khi áp dụng (`setTunnelNetworkSettings` trả error), *When* xảy ra, *Then* ở Airplane Mode engine tạm dừng vòng thử vô ích chờ `.satisfied` từ `NWPathMonitor`; còn khi `setTunnelNetworkSettings` lỗi thì gọi `completionHandler(error)` dọn sạch Extension không treo ở trạng thái "Connecting" vô hạn.

#### US-091 — Giao diện iOS `*(KN: SwiftUI)*` Onboarding (QR / Dán URI / Nhập tay), Chẩn đoán & Share Sheet `bugreport` qua App Group
- **Epic**: `EP-15` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `iOS`
- **Dependencies**: `US-079`, `US-080`, `US-087`, `US-088`.
- **Trace**: `MOB-SEC-04`, `MOB-SEC-05`, `MOB-SEC-06`, `MOB-REL-04`, `MOB-OPS-04`
- **Story**: Là *người dùng iPhone/iPad (`P5-IOS`, `P5-INV`)*, tôi muốn onboarding bằng camera QR, dán URI `mesh://` trong app hoặc nhập tay `IP:cổng + Pin`, xem trạng thái peer/`ping`/`netcheck` và gửi `bugreport` qua Share Sheet (đọc từ tệp App Group đã lọc bí mật), để dễ thiết lập và tự xử lý sự cố.
- **AC**:
  1. **[H]** *Given* màn hình Onboarding (`*(KN: SwiftUI)*`), *When* người dùng quét QR bằng camera nội bộ, dán URI `mesh://` trong app (`*(KN)*: PasteButton` / `UIPasteControl` trên iOS 16+ để tránh popup pasteboard liên tục — **không đăng ký OS-wide clickable deep-link scheme cho URI chứa `mpk_*`**, `MED-MOB-02`) hoặc nhập tay `IP:cổng + sha256:<pin> + mpk_*`, *Then* ứng dụng hiển thị màn hình **xác nhận rõ ràng Endpoint + Fingerprint Pin** trước khi enroll (cấm TOFU, không nút bỏ qua pin), đặt expiration ngắn nếu đọc từ pasteboard (hoặc cảnh báo xóa clipboard) và xóa `mpk_*` khỏi RAM/Keychain ngay sau đăng ký.
  2. **[H]** *Given* tunnel đang chạy hoặc chờ kết nối, *When* người dùng mở tab Trạng thái/Chẩn đoán, *Then* nhận qua `sendProviderMessage` (`<= 4 KiB`) danh sách peer (`direct`/`relay`, RTT), IP overlay, thông tin Pin, kết quả `ping`/`netcheck`; khi bấm Xuất `bugreport`, Main App đọc tệp đã sanitize do Extension ghi trong `group.<bundle_id>/diagnostics/` (`HR-MOB-04`), mở Share Sheet (`UIActivityViewController`) và xóa tệp tạm sau khi đóng Share Sheet (`0` secret / `0` `mpk_*`).
  3. **[E]** *Given* mã QR không hợp lệ hoặc người dùng nhập sai định dạng pin/endpoint trên form nhập tay, *When* bấm Tiếp tục, *Then* UI báo lỗi kiểm chứng tại chỗ, không gửi bất kỳ gói tin nào ra mạng.
  4. **[F]** *Given* lỗi kết nối tới `mesh-server`, hoặc nhận `node_revoked`/`node_key_expired` qua TLS hợp lệ, hoặc tệp `bugreport` trong App Group không đọc được, *When* xảy ra, *Then* UI phân biệt rõ **Captive Portal / Clock Skew / Pin Mismatch**, xử lý lỗi đọc tệp Share Sheet an toàn không crash, và nếu bị thu hồi/hết hạn thì dừng tunnel, xóa khóa phiên trong Keychain và hiển thị rõ lý do.

#### US-092 — Hỗ trợ `NEOnDemandRule` tự kết nối (tắt sạch khi Disconnect) & Xác thực `LocalAuthentication` trên iOS
- **Epic**: `EP-15` · **SP**: `3` · **MoSCoW**: `Should` · **Platform**: `iOS`
- **Dependencies**: `US-088`, `US-090`.
- **Trace**: `MOB-PLAT-IOS-06`, `MOB-SEC-06`
- **Story**: Là *người dùng iPhone/iPad (`P5-IOS`)*, tôi muốn bật chế độ On-Demand tự nối VPN khi đổi mạng hoặc truy cập `*.mesh.internal` (nhưng không tự bật lại khi tôi chủ động bấm Ngắt) và khóa thao tác nhạy cảm bằng Face ID/Touch ID, để tiện lợi hơn khi di chuyển.
- **AC**:
  1. **[H]** *Given* người dùng bật tùy chọn On-Demand trong ứng dụng, *When* thiết lập `isOnDemandEnabled = true` với `NEOnDemandRuleConnect` (hoặc `NEOnDemandRuleEvaluateConnection` cho `*.mesh.internal`), *Then* iOS tự kích hoạt Extension khi chuyển mạng hoặc khi truy cập tên miền `.mesh.internal` mà không cần mở Main App (sau lần mở khóa đầu tiên nếu reboot).
  2. **[E]** *Given* On-Demand đang bật và người dùng bấm **Ngắt kết nối (Disconnect)** thủ công trong ứng dụng, *When* thực hiện ngắt, *Then* ứng dụng đồng thời lưu `isOnDemandEnabled = false` vào `NETunnelProviderManager` trước khi gọi `stopTunnel`, bảo đảm iOS không tự khởi động lại VPN ngay sau đó (`MED-MOB-01`).
  3. **[F]** *Given* người dùng hủy xác thực Face ID/Touch ID/Passcode (`*(KN)*: LocalAuthentication`) hoặc thiết bị chưa thiết lập Passcode khi muốn xem Pin quản trị chi tiết hoặc xóa nút, *When* thực hiện, *Then* hủy thao tác nhạy cảm an toàn, không lộ thông tin và không làm thay đổi trạng thái tunnel/Keychain.

#### US-093 — Workflow CI `macos-latest` build `.xcframework` + Simulator miễn phí & Quy trình Ký số Máy thật (`$99/năm`)
- **Epic**: `EP-15` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `iOS`
- **Dependencies**: `US-076`, `US-087`, `US-089`.
- **Trace**: `MOB-OPS-IOS-01`, `MOB-PERF-05`, `M-GNFR-06`, `M-GNFR-08`
- **Story**: Là *chủ mạng (`P1`)*, tôi muốn CI `macos-latest` tự động đóng gói `.xcframework` và kiểm thử build Swift trên iOS Simulator hoàn toàn miễn phí, đồng thời chuẩn bị sẵn template Entitlements/Provisioning cho tài khoản Apple Developer Program (`$99/năm`) khi cài máy thật, để không bị bất ngờ về chi phí và điều kiện ký số của Apple.
- **AC**:
  1. **[H]** *Given* GitHub Actions runner `macos-latest` không có chứng chỉ Apple trả phí, *When* workflow CI chạy, *Then* biên dịch thành công 3 slice Rust (`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`), đóng gói `.xcframework` (mỗi slice `<= 6 MiB`), và build + chạy unit test Swift App + Extension trên **iOS Simulator với `CODE_SIGNING_ALLOWED=NO`** ở chi phí `$0`.
  2. **[E]** *Given* cấu hình Xcode và tài liệu phát hành chuẩn bị cho iPhone/iPad thật (Ad-Hoc/TestFlight), *When* rà soát template entitlements và tài liệu CI, *Then* có sẵn entitlements (`com.apple.developer.networking.networkextension` = `packet-tunnel-provider`, App Group, Keychain Access Group) và nêu rõ ranh giới: Simulator chỉ kiểm chứng compile/link/UI/FFI (không chạy kernel `NEPacketTunnelProvider`), còn chạy máy thật bắt buộc tài khoản **Apple Developer Program `$99/năm`** (Personal Team miễn phí không cấp được entitlement).
  3. **[F]** *Given* bất kỳ slice `.xcframework` nào vượt ngưỡng `6 MiB`, thiếu một trong 3 kiến trúc mục tiêu, hoặc bước build/unit test Simulator thất bại, *When* chạy CI, *Then* workflow trả mã thoát khác 0 và chặn hợp nhất.

---

### 4.4. EP-16 — Mobile QA, Compatibility, Privacy & Multi-OS CI/Release

> Mục tiêu: Đảm bảo chất lượng Production trước khi phát hành `v0.2.0` — tương thích ngược `v0.1.0-rc1` (cùng lõi Control dùng chung), tương thích IPv6-only NAT64, chịu lỗi mạng di động, không rò rỉ bí mật, đo pin `RRC_IDLE` / RAM Jetsam, và nghiệm thu trên thiết bị thật Android + iOS.

#### US-094 — Bộ kiểm thử Tương thích Ngược E2E (`v0.2.0` Mobile ↔ `v0.1.0-rc1` Desktop & `mesh-server`)
- **Epic**: `EP-16` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Mobile QA & CI`
- **Dependencies**: `US-075`, `US-077`, `US-079`, `US-099`.
- **Trace**: `MOB-OPS-03`, `MOB-REL-01`, `MOB-REL-05`, `M-GNFR-05`, `M-GNFR-09`, `GNFR-11`
- **Story**: Là *chủ mạng / QA (`P1`)*, tôi muốn bộ test E2E xác minh `mesh-server` đã nâng cấp làm việc mượt mà với cả client di động (kể cả qua NAT64) lẫn Desktop `v0.1.0-rc1` trên cổng tùy chọn, kể cả khi Control tắt hoặc dưới CGNAT kép, để nâng cấp VPS an toàn tuyệt đối.
- **AC**:
  1. **[H]** *Given* cụm lab gồm `mesh-server` mới + peer Desktop chạy hợp đồng `v0.1.0-rc1` (không nâng cấp) + các node mô phỏng `TargetOs::Android` và `TargetOs::Ios` qua lõi FFI (`RelayClient` trả đúng `"android"`/`"ios"`), *When* chạy ở cả cổng mặc định (`443`/`3478`) lẫn cổng tùy chọn (`8443`/`3479`), *Then* 100% cặp node đăng ký, nhận `NetmapSnapshot` và trao đổi dữ liệu qua tunnel thành công.
  2. **[E]** *Given* peer Mobile kết nối tới `mesh-server` IPv4 literal thông qua đường truyền giả lập **IPv6-only NAT64 (`64:ff9b::/96`)** và các phiên P2P/Relay đang chạy khi dừng `mesh-server` trong 30 phút (`MOB-REL-01`), *When* kiểm tra, *Then* `0%` gói dữ liệu tunnel bị rớt do Control tắt, NAT64 vẫn xác thực đúng `SpkiPinVerifier`, và node di động tự reconnect theo `ExponentialBackoff` có jitter khi server lên lại.
  3. **[F]** *Given* kịch bản chặn UDP (Double-CGNAT) giữa 2 peer qua Mobile FFI với peer đích đọc chậm gây đầy hàng đợi `256` gói, *When* đục lỗ Disco thất bại, *Then* lưu lượng tự chuyển qua Blind Relay với `RELAY_QUEUE_CAPACITY = 256` + `try_send()` (drop-tail không HoL blocking cho peer khác), và regression tests `meshd` Desktop vẫn PASS 100%.

#### US-095 — Bộ kiểm thử Chịu lỗi Di động (Roaming `<= 5 s`, NAT64, Captive Portal, Clock Skew, Doze & Node Revocation)
- **Epic**: `EP-16` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Mobile QA & CI`
- **Dependencies**: `US-078`, `US-079`, `US-083`, `US-090`.
- **Trace**: `MOB-REL-02`, `MOB-REL-03`, `MOB-REL-04`, `MOB-SEC-06`, `MOB-PERF-04`, `M-GNFR-07`, `M-GNFR-09`
- **Story**: Là *người dùng di động / QA (`P5-AND`, `P5-IOS`)*, tôi muốn bộ kiểm thử tự động và kịch bản mô phỏng chứng minh client di động phục hồi chuyển vùng `<= 5 s` (kể cả sang IPv6-only NAT64), giữ timer idle-aware khi nghỉ, xử lý đúng Captive Portal/Clock Skew/Doze và cắt hoàn toàn khi bị thu hồi, để yên tâm sử dụng khi công tác.
- **AC**:
  1. **[H]** *Given* bộ test handshake & chuyển vùng 10 vòng chuyển đổi đường đi mạng (Wi-Fi IPv4 ↔ 4G/5G IPv6-only NAT64 ↔ Wi-Fi), *When* thực hiện kịch bản chuẩn, *Then* kết nối ổn định không phải khởi động lại tunnel thủ công và giữ nguyên Overlay IP.
  2. **[N]** *Given* 10 vòng chuyển vùng nêu trên, *When* đo thời gian handshake ban đầu và thời gian phục hồi luồng sau mỗi lần đổi mạng, *Then* handshake đầu đạt **`<= 2 s`** và phục hồi chuyển vùng đạt **`<= 5 s`** (`MOB-REL-02`, `MOB-PERF-04`).
  3. **[E]** *Given* trạng thái idle dài không có traffic ứng dụng và kịch bản ngủ Doze/App Nap kèm nhảy đồng hồ `> 30_000 ms` (`CLOCK_JUMP_THRESHOLD_MS`), *When* theo dõi tần suất đánh thức timer và sự kiện đánh thức, *Then* ở trạng thái idle không xuất hiện wakeup cứng `8 Hz` (`250 ms`), chu kỳ keepalive giữ trong biên `60 s` hỗ trợ hạ `RRC_IDLE`, và khi thức dậy sau nhảy đồng hồ engine kiểm tra lại ngay phiên Control TLS & Netmap.
  4. **[F]** *Given* môi trường giả lập **Captive Portal**, **Clock Skew**, **Airplane Mode** và lệnh thu hồi `node_revoked`/`node_key_expired` qua TLS hợp lệ, *When* xảy ra, *Then* Portal/Clock Skew tuân thủ backoff `300_000 ms` + trả đúng 3 mã phân biệt UI (không chặn portal); Airplane Mode tạm dừng gửi gói vô ích tới khi có path; và thu hồi/hết hạn buộc dừng retry, ngắt tunnel, xóa khóa phiên (`MOB-SEC-06`).

#### US-096 — Kiểm toán Quyền riêng tư & Chống rò rỉ Bí mật Di động (`test_no_secrets_in_outputs`, Backup, Deep-Link & No-TCP)
- **Epic**: `EP-16` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Mobile QA & CI`
- **Dependencies**: `US-078`, `US-079`, `US-082`, `US-084`, `US-087`, `US-088`, `US-091`.
- **Trace**: `MOB-SEC-01`, `MOB-SEC-02`, `MOB-SEC-04`, `MOB-SEC-05`, `MOB-OPS-04`, `GNFR-02`
- **Story**: Là *chủ mạng / QA bảo mật (`P1`)*, tôi muốn có bộ kiểm toán tự động xác minh `0` rò rỉ bí mật qua log, `bugreport`, clipboard, deep-link, Cloud Backup và `0` cổng TCP mở trên app di động, để đảm bảo an toàn dữ liệu ngang chuẩn `v0.1.0`.
- **AC**:
  1. **[H]** *Given* luồng vận hành tiêu chuẩn trên FFI, Android và iOS (kết nối, xoay trạng thái, xuất `bugreport` qua tệp App Group/Share Intent và dọn tệp tạm), *When* chạy bộ kiểm toán tự động `test_no_secrets_in_outputs` và kiểm tra tĩnh manifest/entitlements, *Then* bộ test hoàn tất xanh 100%, tệp tạm `bugreport` được xóa sau chia sẻ và không có cảnh báo rò rỉ giả (false positive).
  2. **[E]** *Given* bật mức log **`debug`**, đồng thời bơm các mẫu dữ liệu lỗi (`mpk_*` sai định dạng, chứng chỉ lỗi, `PreAuthKeyCreatedResponse` mẫu) qua parser URI, log `OPS-01` và `bugreport`, *When* grep toàn bộ tệp log và đầu ra FFI, *Then* kết quả vẫn là **`0` chuỗi bí mật thật** và **`0` tiền tố `mpk_` nguyên vẹn**.
  3. **[F]** *Given* kiểm tra cấu hình đóng gói và bề mặt mạng runtime của app Android & iOS, *When* rà soát, *Then* Android có `allowBackup="false"`, `dataExtractionRules`, `noBackupFilesDir`, `FLAG_SECURE`, và **0 intent-filter deep-link cho `mpk_*`**; iOS có `AfterFirstUnlockThisDeviceOnly` + `kSecAttrSynchronizable = false` + không đăng ký URL Scheme cho `mpk_*`; và **0 socket TCP** mở cho Admin API hay `/healthz`/`/readyz`/`/metrics` (`MOB-OPS-04`).

#### US-097 — Đo đạc RAM/Pin Thực địa, Ma trận Nghiệm thu Máy thật & Runbook/Go-Live Mobile Checklist (`v0.2.0`)
- **Epic**: `EP-16` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Mobile QA & CI`
- **Dependencies**: `US-086`, `US-093`, `US-094`, `US-095`, `US-096`.
- **Trace**: `MOB-PERF-01`, `MOB-PERF-02`, `MOB-PERF-03`, `MOB-OPS-IOS-01`, `MOB-OPS-05`, `M-GNFR-01`, `M-GNFR-02`, `M-GNFR-07`, `M-GNFR-09`
- **Story**: Là *chủ mạng (`P1`)*, tôi muốn có quy trình đo đạc RAM/Pin thực địa, biên bản nghiệm thu tối thiểu 1 Android 14+ & 1 iPhone thật và Runbook/Go-Live Checklist cho `v0.2.0`, để tự tin phát hành và vận hành hằng ngày.
- **AC**:
  1. **[H]** *Given* tài liệu **Runbook & Go-Live Mobile Checklist (`v0.2.0`)**, *When* người dùng làm theo từ đầu, *Then* hoàn tất được các quy trình: cài `.apk` Android, chuẩn bị Apple Developer `$99/năm` & ký Extension iOS, tạo QR/URI `mesh://` từ CLI `mesh`, xử lý Captive Portal/Clock Skew/Strict Private DNS/Lockdown Mode, và thu hồi điện thoại bị mất.
  2. **[N]** *Given* tối thiểu **1 máy Android 14+ (API 34+) thật** cài `.apk` và tối thiểu **1 iPhone thật** cài TestFlight/Ad-Hoc (sau khi có Apple Developer `$99/năm`), *When* chạy nghiệm thu thực tế (`protect(fd)`, `specialUse`, Private DNS `:853`, IPv6-only NAT64, `packetFlow`, Split-DNS `AAAA` NODATA, Keychain sau reboot, roaming `<= 5 s`), *Then* đo Android Studio Profiler đạt **`RSS <= 48 MiB`**, Xcode Instruments đạt **`RSS <= 25 MiB`** (dưới trần Jetsam `50 MiB`), và Battery Historian / Energy Log 4 giờ idle trên 4G/Wi-Fi đạt mục tiêu **`<= 1.5%/giờ`** (`RRC_IDLE`).
  3. **[E]** *Given* kịch bản áp lực bộ nhớ trên iPhone (kiểm thử ngưỡng **`os_proc_available_memory()`**) và kịch bản **Direct Boot** sau reboot trên Android trước mở khóa, *When* chạy trên thiết bị thật, *Then* Extension áp dụng backpressure/drop-tail kịp thời không bị `EXC_RESOURCE` Jetsam và Android chờ `ACTION_USER_UNLOCKED` không crash.
  4. **[F]** *Given* bất kỳ hạng mục `P0` nào trong Go-Live Mobile Checklist chưa đạt hoặc thiếu bằng chứng thiết bị thật / Apple Developer sign-off cho bản phát hành iOS thật, *When* chạy kiểm tra phát hành Gate 3, *Then* chặn gắn tag phát hành `v0.2.0` đầy đủ (hoặc ghi rõ chỉ xuất `.apk` Android beta `$0` nếu người dùng chọn trì hoãn `$99/năm`).

#### US-098 — Kênh phân phối Google Play Internal Testing / TestFlight tự động hóa
- **Epic**: `EP-16` · **SP**: `3` · **MoSCoW**: `Could` · **Platform**: `Mobile QA & CI`
- **Dependencies**: `US-086`, `US-093`, `US-097`.
- **Trace**: `MOB-OPS-AND-01`, `MOB-OPS-IOS-01`, `MOB-OPS-05`
- **Story**: Là *chủ mạng (`P1`)*, tôi muốn khi gắn tag phát hành `v0.2.x`, pipeline tự động đẩy bản `.aab` lên Google Play Internal Testing và bản `.ipa` lên TestFlight, để cập nhật thiết bị thử nghiệm tiện lợi mà không phải upload thủ công.
- **AC**:
  1. **[H]** *Given* tag `v0.2.*` cùng secrets ký số Store/App Store Connect đã cấu hình trên GitHub Actions, *When* workflow phát hành chạy, *Then* tải lên thành công track nội bộ Google Play (`$25` một lần) và App Store Connect TestFlight (`$99/năm`).
  2. **[E]** *Given* workflow được kích hoạt lại với cùng số phiên bản build hoặc ở chế độ dry-run kiểm tra metadata, *When* chạy, *Then* xử lý idempotent (tự tăng/kiểm tra `versionCode`/`CFBundleVersion` hoặc báo rõ trạng thái dry-run) mà không làm hỏng bản đang phát hành.
  3. **[F]** *Given* thiếu secret ký số Store ở repo fork/chưa mua tài khoản Store, *When* chạy CI thường ngày, *Then* bước upload tự bỏ qua an toàn với thông báo rõ mà không làm đỏ pipeline build `.apk`/`.xcframework` miễn phí.

---

## 5. Ma trận Truy vết Đầy đủ (`MOB-*` → `US-075..099` & `M-GNFR-*`)

Bảng sau chứng minh **34/34 mã `MOB-*`** trong [mobile-readiness-requirements.md](../01-discovery/mobile-readiness-requirements.md) (gồm `25 P0`, `8 P1`, `1 P2`) được phủ đầy đủ, không bỏ sót bất kỳ yêu cầu nào:

| STT | Mã `MOB-*` | Mức NC | Tên yêu cầu (tóm tắt) | Story (`US-075..099`) phủ | M-GNFR / GNFR liên đới |
|:-:|:---|:-:|---|---|---|
| 1 | `MOB-SEC-01` | P0 | Lưu trữ khóa an toàn & Cấm Cloud Backup Android | `US-082`, `US-096` | `M-GNFR-02`, `GNFR-02` |
| 2 | `MOB-SEC-02` | P0 | Lưu trữ khóa Keychain Access Group iOS & Cấm iCloud Sync | `US-088`, `US-096` | `GNFR-02` |
| 3 | `MOB-SEC-03` | P0 | TLS, SPKI Pin, Chống TOFU & Khởi tạo Native Trust Store | `US-078`, `US-099` | `GNFR-01`, `GNFR-11`, `M-GNFR-09` |
| 4 | `MOB-SEC-04` | P0 | Onboarding QR / Dán URI `mesh://`, Chống Scheme Hijacking | `US-080`, `US-084`, `US-091`, `US-096` | `GNFR-02` |
| 5 | `MOB-SEC-05` | P0 | Chống rò rỉ bí mật qua Log hệ thống & `bugreport` Share Sheet | `US-078`, `US-079`, `US-084`, `US-088`, `US-091`, `US-096`, `US-099` | `GNFR-02` |
| 6 | `MOB-SEC-06` | P1 | Thu hồi nút từ xa & Xác thực thao tác nhạy cảm trên UI | `US-084`, `US-085` *(Should)*, `US-091`, `US-092` *(Should)*, `US-095` | — |
| 7 | `MOB-REL-01` | P0 | Tách biệt Control Plane / Data Plane khi mất VPS | `US-077`, `US-094`, `US-099` | `GNFR-03`, `M-GNFR-05` |
| 8 | `MOB-REL-02` | P0 | Chuyển vùng Wi-Fi ↔ 4G/5G (`<= 5 s`) & Mạng IPv6-only NAT64 | `US-077`, `US-083`, `US-090`, `US-095` | `M-GNFR-07`, `M-GNFR-09` |
| 9 | `MOB-REL-03` | P0 | Sleep, Doze, Clock Jump (`30_000 ms`) & Timer Idle-Aware (`RRC_IDLE`) | `US-077`, `US-079`, `US-095` | `M-GNFR-07` |
| 10 | `MOB-REL-04` | P0 | Xử lý Captive Portal, Clock Skew (`300_000 ms`) & Airplane Mode | `US-078`, `US-083`, `US-084`, `US-090`, `US-091`, `US-095` | `GNFR-03` |
| 11 | `MOB-REL-05` | P0 | Dự phòng Blind Relay ổn định dưới CGNAT kép (`256` + `try_send`) | `US-077`, `US-094` | `M-GNFR-01` |
| 12 | `MOB-REL-06` | P1 | Dừng êm (Graceful Teardown) `<= 5 s` | `US-079`, `US-083`, `US-090` | `M-GNFR-07` |
| 13 | `MOB-PLAT-AND-01` | P0 | Khởi tạo TUN không root qua `android.net.VpnService` | `US-081` | `M-GNFR-03` |
| 14 | `MOB-PLAT-AND-02` | P0 | Chống Routing Loop tuyệt đối bằng `VpnService.protect(fd)` | `US-077`, `US-081` | `M-GNFR-03` |
| 15 | `MOB-PLAT-AND-03` | P0 | Tuân thủ Android 14+ (API 34+) Foreground Service (`specialUse`) | `US-081` | — |
| 16 | `MOB-PLAT-AND-04` | P1 | Always-On VPN, Direct Boot & Cảnh báo Lockdown Mode (`G4`) | `US-085` *(Should)* | `M-GNFR-03` |
| 17 | `MOB-PLAT-AND-05` | P0 | Split-DNS `.mesh.internal` RFC 4074 & Android Private DNS (`:853`) | `US-080`, `US-083` | `M-GNFR-04` |
| 18 | `MOB-PLAT-AND-06` | P1 | Xử lý thu hồi quyền VPN (`onRevoke`) & Quản lý vòng đời | `US-083` | `M-GNFR-07` |
| 19 | `MOB-PLAT-IOS-01` | P0 | Kiến trúc 2 tiến trình cách ly (Main App + `NEPacketTunnelProvider`) | `US-087` | — |
| 20 | `MOB-PLAT-IOS-02` | P0 | App Group & IPC nội bộ (`sendProviderMessage`, `bugreport` file) | `US-087` | `M-GNFR-01`, `M-GNFR-07` |
| 21 | `MOB-PLAT-IOS-03` | P0 | Truyền gói tin chính thống qua `packetFlow` (cấm private hack) | `US-077`, `US-089` | `M-GNFR-01` |
| 22 | `MOB-PLAT-IOS-04` | P0 | Split-Tunnel `includedRoutes` chống Routing Loop & Hỗ trợ NAT64 iOS | `US-089` | `M-GNFR-03`, `M-GNFR-09` |
| 23 | `MOB-PLAT-IOS-05` | P0 | Split-DNS nguyên bản chuẩn RFC 4074 qua `NEDNSSettings` | `US-080`, `US-090` | `M-GNFR-04` |
| 24 | `MOB-PLAT-IOS-06` | P1 | Quy tắc tự kết nối On-Demand (`NEOnDemandRule`) & Tắt VPN chủ động | `US-092` *(Should)* | — |
| 25 | `MOB-PERF-01` | P0 | Ngân sách RAM iOS Extension (`<= 25 MiB` RSS dưới `50 MiB` Jetsam) | `US-079`, `US-089`, `US-097` | `M-GNFR-01` |
| 26 | `MOB-PERF-02` | P0 | Ngân sách RAM dịch vụ nền Android (`<= 48 MiB` tổng RSS) | `US-082`, `US-097` | `M-GNFR-02` |
| 27 | `MOB-PERF-03` | P1 | Giới hạn tiêu thụ pin nền khi Idle (`<= 1.5%/giờ`, hạ `RRC_IDLE`) | `US-077`, `US-079`, `US-097` | `M-GNFR-07` |
| 28 | `MOB-PERF-04` | P1 | Độ trễ Handshake (`<= 2 s`) & Phục hồi chuyển vùng (`<= 5 s`), MTU `1280` | `US-078`, `US-089`, `US-095` | `M-GNFR-07` |
| 29 | `MOB-PERF-05` | P0 | Tinh gọn nhị phân (`<= 6 MiB`/ABI) & Feature-gate tách dep thừa | `US-076`, `US-086`, `US-093` | `M-GNFR-06`, `M-GNFR-08` |
| 30 | `MOB-OPS-IOS-01` | P0 | Ký số & Phân phối Apple (`$99/năm` máy thật vs CI Simulator `$0`) | `US-093`, `US-097`, `US-098` *(Could)* | `M-GNFR-06` |
| 31 | `MOB-OPS-AND-01` | P0 | Quy trình Build CI `.apk`/`.aab` & Cài đặt Android thật `$0` | `US-086`, `US-098` *(Could)* | `M-GNFR-06` |
| 32 | `MOB-OPS-03` | P0 | Nâng cấp `mesh-server`/`RelayClient`/`route.rs`, tách `meshd` & `deny.toml` | `US-075`, `US-076`, `US-079`, `US-094`, `US-099` | `M-GNFR-05`, `M-GNFR-06` |
| 33 | `MOB-OPS-04` | P1 | Chẩn đoán giới hạn dung lượng (`<= 1 MiB` ring-buffer, không TCP) | `US-078`, `US-079`, `US-084`, `US-087`, `US-091`, `US-096` | `M-GNFR-07` |
| 34 | `MOB-OPS-05` | P2 | Ma trận Thiết bị Nghiệm thu Thực tế tối thiểu (1 Android 14+ & 1 iPhone) | `US-097`, `US-098` *(Could)* | `M-GNFR-01/02/07/09` |

> **Ghi chú quy ước & hiệu chỉnh ưu tiên:**
> - Hai mã `MOB-OPS-IOS-01` và `MOB-OPS-AND-01` tương ứng vị trí `01`/`02` trước `MOB-OPS-03..05` (tổng 34 mã `MOB-*`).
> - Xử lý thu hồi từ xa `node_revoked`/`node_key_expired` (`MOB-SEC-06` P1), dừng êm `<= 5 s` (`MOB-REL-06` P1), `onRevoke()` (`MOB-PLAT-AND-06` P1), chẩn đoán sạch không TCP (`MOB-OPS-04` P1), pin/độ trễ (`MOB-PERF-03/04` P1) và ma trận nghiệm thu máy thật + Runbook (`MOB-OPS-05` P2) được đặt ở mức **`Must`** vì cần thiết cho vận hành di động an toàn. Always-On/Direct Boot/Lockdown/Biometric Android (`US-085`) và `NEOnDemandRule`/FaceID iOS (`US-092`) ở mức **`Should`**; tự động upload Play Store/TestFlight (`US-098`) ở mức **`Could`**.

---

## 6. Lộ trình Phân phối (Release Slicing) & Câu hỏi Mở Gate 1 (`OQ-MOB-*`)

### 6.1. Đề xuất Phương án Bàn giao (Release Slicing)

Tổng khối lượng Milestone `v0.2.0`: **22 story `Must` / 108 SP** (+ **2 `Should` / 6 SP** + **1 `Could` / 3 SP** = **25 story / 117 SP**). Có 2 phương án lộ trình bàn giao để Người dùng lựa chọn tại Gate 1:

#### Phương án A (Đề xuất): Wave A (Shared Core + Control Extraction) → Song song Wave B1 (Android) & Wave B2 (iOS) → Wave C (QA & Release)
| Làn / Wave | Nội dung bàn giao | Stories `Must` | Must (Story / SP) | Should / Could | Mục tiêu & Rủi ro giảm thiểu |
|---|---|---|:-:|:-:|---|
| **Wave A — Shared Core, Control Extraction & Server Compat** | `TargetOs::{Android, Ios}` + `RelayClient`; feature-gate `mesh-net`/`mesh-datapath`/`mesh-crypto` + `route.rs`; trích xuất `control_loop`/`NetmapCacheStore` từ `meshd` (`US-099`); `SocketProtector`, NAT64 & `PacketFlowTun`; `SpkiPinVerifier` + native CA; FFI contract + RFC 4074 Split-DNS + `mesh` CLI URI/QR | `US-075, 076, 077, 078, 079, 080, 099` | **7 / 34** | — | Mở khóa đồng thời cả Android & iOS trên một lõi Client Control/Datapath duy nhất; kiểm chứng sớm liên thông `v0.1.0-rc1` & `cargo deny` 5 targets. |
| **Wave B1 — Android Client** | `VpnService` + `protect(fd)` + Android 14+ `specialUse`; Keystore `AES-256-GCM` + `allowBackup="false"`; Split-DNS RFC 4074 + Private DNS `:853` + `NetworkCallback` + `onRevoke`; UI QR/URI/`bugreport`; CI `.apk`/`.aab` | `US-081, 082, 083, 084, 086` | **5 / 23** | `US-085` (3 SP `Should`) | Cài ngay `.apk` lên máy thật Android với chi phí `$0` để thử lửa 4G/5G/Doze/Private DNS trước cả khi xong ký số iOS. |
| **Wave B2 — iOS Client** | 2 tiến trình App + `NEPacketTunnelProvider` + `sendProviderMessage` + App Group `bugreport`; Keychain non-sync; `packetFlow` + `includedRoutes` + `RSS <= 25 MiB`; `NEDNSSettings` + `NWPathMonitor`; UI QR/Paste/`bugreport`; CI `.xcframework` + Simulator | `US-087, 088, 089, 090, 091, 093` | **6 / 31** | `US-092` (3 SP `Should`) | CI `macos-latest` kiểm chứng compile/link/UI trên Simulator `$0` song song với Android; sẵn sàng ký máy thật ngay khi có tài khoản `$99/năm`. |
| **Wave C — Mobile QA, Hardening & Go-Live** | E2E `v0.1.0-rc1` compat + Control offline; Roaming `<= 5 s` + NAT64 + Captive Portal/Clock Skew/Doze/Revoke; `test_no_secrets_in_outputs` + Backup/Deep-Link/No-TCP audit; đo RAM/Pin máy thật & Runbook `v0.2.0` | `US-094, 095, 096, 097` | **4 / 20** | `US-098` (3 SP `Could`) | Khép kín toàn bộ Go-Live Mobile Checklist (`US-097`) trước khi gắn tag `v0.2.0`. |
| **Tổng cộng** | | `US-075..099` | **22 / 108** | **2 Should (6 SP) + 1 Could (3 SP)** | **Tổng toàn bộ: 25 story / 117 SP** |

#### Phương án B (Tuần tự theo chi phí & độ chắc): Wave A → Android hoàn chỉnh trước (`v0.2.0-alpha` `$0`) → iOS sau
- Triển khai **Wave A (`7 / 34 SP`)** → hoàn thành **Wave B1 Android (`5 / 23 SP`)** + phần kiểm thử E2E/Android của Wave C để phát hành trước bản Android `.apk` miễn phí trên GitHub Release (`$0`) → sau đó triển khai **Wave B2 iOS (`6 / 31 SP`)** và nghiệm thu iPhone thật khi tài khoản Apple Developer Program `$99/năm` sẵn sàng.
- **Ưu điểm:** Tập trung kiểm chứng thực địa 4G/5G thật trên Android với chi phí `$0` sớm nhất; kinh nghiệm sửa lỗi từ Android tự động hưởng lợi cho iOS; không nghẽn nếu chưa mở tài khoản Apple `$99/năm`. **Nhược điểm:** Chậm ngày iPhone/iPad gia nhập mạng mesh.

---

### 6.2. Câu hỏi Mở đã chốt tại Gate 1 (`OQ-MOB-*`)

| Mã | Câu hỏi Mở tại Gate 1 | Các phương án lựa chọn | Quyết định của Người dùng (`[ĐÃ CHỐT TẠI GATE 1 — 2026-11-15]`) | Ảnh hưởng tới Gate 2 & Thực thi |
|---|---|---|---|---|
| **OQ-MOB-01** | **Chiến lược phát triển Android ↔ iOS:** Sau khi xong Wave A (Shared Core + tách `meshd`), triển khai **song song Android & iOS** (Phương án A) hay **tuần tự Android `.apk` thật trước → iOS sau** (Phương án B)? | (A) Song song Android + iOS sau Wave A<br>(B) Tuần tự Android `.apk` trước → iOS sau | **[ĐÃ CHỐT TẠI GATE 1 — 2026-11-15]: Phương án A (Song song Wave B1 Android + Wave B2 iOS ngay sau Wave A)**. | Wave A (`US-075..080, 099` = 34 SP) mở khóa Wave B1 (`23 SP Must`) + Wave B2 (`31 SP Must`) chạy song song, `0%` trùng lặp file. |
| **OQ-MOB-02** | **Kênh phân phối & Ngân sách Apple Developer Program (`$99/năm`):** Android phát hành `.apk` qua GitHub Release (`$0`). iOS trên CI `macos-latest` chỉ build `.xcframework` + Simulator (`CODE_SIGNING_ALLOWED=NO`, `$0`) chứ **không chạy được VPN trên iPhone thật** nếu chưa có entitlement trả phí. | (1) Dùng/đăng ký Apple Developer `$99/năm` cho `v0.2.0`<br>(2) Giữ iOS ở `.xcframework` + Simulator `$0`, ưu tiên chạy máy thật Android (`.apk` `$0`) trước | **[ĐÃ CHỐT TẠI GATE 1 — 2026-11-15]: Phương án (2) — Chưa chi `$99/năm` ngay (`$0` Mode)**. | Android kiểm chứng & phát hành `.apk` máy thật (`$0`). iOS hoàn thiện đủ mã `NEPacketTunnelProvider` + SwiftUI + `.xcframework`, kiểm chứng build & unit/UI test trên iOS Simulator (`CODE_SIGNING_ALLOWED=NO`, `$0` trên CI `macos-latest`); riêng hạng mục chạy tunnel thật trên iPhone vật lý (`US-097 AC2`) gắn cờ `hardware_signoff_required (chờ Apple Developer $99/năm)` (tương tự cơ chế `v0.1.0-rc1`). |
| **OQ-MOB-03** | **UX Onboarding Di động & Chống Scheme Hijacking:** Phương thức nhập cấu hình kết nối trên mobile? | (1) Hỗ trợ cả 3 luồng nhập trong app (QR camera + dán URI `mesh://` + nhập tay), cấm OS deep-link cho `mpk_*`<br>(2) Chỉ nhập tay IP:port + Pin trước | **[ĐÃ CHỐT TẠI GATE 1 — 2026-11-15]: Phương án (1) — Hỗ trợ cả 3 luồng nhập trong app; CẤM đăng ký OS-wide clickable deep-link cho `mpk_*`**. | Thực hiện đầy đủ `US-080`, `US-084`, `US-091` (màn hình xác nhận Endpoint + SPKI Pin, quét QR offline, `PasteButton` iOS 16+ tránh popup, triệt tiêu `T-MOB-07`). |
| **OQ-MOB-04** | **Phạm vi định tuyến Di động `v0.2.0`:** Split-Tunnel hay bao gồm Exit Node (`0.0.0.0/0`)? | (1) Chỉ Split-Tunnel dải mesh + `.mesh.internal` ở `v0.2.0`; hoãn Exit Node sang `v0.3.0`<br>(2) Kéo Exit Node di động (`US-068`) vào `v0.2.0` | **[ĐÃ CHỐT TẠI GATE 1 — 2026-11-15]: Phương án (1) — Chỉ Split-Tunnel dải overlay động (`NetmapSnapshot.overlay_cidr`) + `.mesh.internal`; hoãn Exit Node sang `v0.3.0`**. | Bảo toàn pin, giữ Captive Portal hoạt động; Android app phát hiện & cảnh báo nổi bật nếu bật VPN Lockdown hoặc Strict Private DNS. |
| **OQ-MOB-05** | **Chủ trương Giấy phép FFI (`MPL-2.0` của `UniFFI` vs Giữ cấm 100% của Charter `C5`/`deny.toml`):** | (1) Mở ngoại lệ `MPL-2.0` **giới hạn riêng cho `uniffi*`** trong `mesh-mobile-ffi`<br>(2) Giữ lệnh cấm `MPL-2.0` 100% và viết cầu nối thủ công bằng `jni` + `extern "C"` C-ABI | **[ĐÃ CHỐT TẠI GATE 1 — 2026-11-15]: Phương án (1) — Mở ngoại lệ `MPL-2.0` giới hạn riêng cho nhóm crate `uniffi*` ở lớp FFI mobile (`crates/mesh-mobile-ffi`)**. | Tech Lead thiết kế cụ thể ngoại lệ `MPL-2.0` + wrapper `anyhow` giới hạn cho `uniffi*` trong `deny.toml` tại Gate 2; `mesh-server`, `meshd`, `mesh` và toàn bộ core crates giữ nguyên 100% `MIT`/`Apache-2.0`/`BSD`. |

> [!NOTE]
> **Bàn giao mở cho Gate 2 (`agile-tech-lead` & `agile-architect`):**
> Sau khi Người dùng chốt `OQ-MOB-01..05` tại Gate 1, Gate 2 cần chốt 4 quyết định kiến trúc qua ADR:
> 1. **Cấu trúc Workspace khi trích xuất Control Plane từ `crates/meshd` (`US-099`)**: đặt vào crate hiện có hay crate thư viện mới tuân thủ chuẩn Workspace trong `.agents/rules/coding-standards.md`.
> 2. **Ranh giới `unsafe_code = "forbid"` (`US-079`)**: giữ `unsafe` FFI (`#[unsafe(no_mangle)] extern "C"`, `jni`, `from_raw_fd`, `os_proc_available_memory()`) trong `crates/mesh-sys` hay phê duyệt cập nhật chuẩn Workspace cho crate FFI mobile riêng.
> 3. **Triển khai FFI theo kết quả `OQ-MOB-05`** (`UniFFI` kèm ngoại lệ `MPL-2.0` giới hạn vs `jni` + `extern "C"` C-ABI).
> 4. **Cấu hình `*(KN)*: rustls-platform-verifier` + điểm khởi tạo JNI `Context` sớm** (`Application.onCreate()`/`VpnService.onCreate()`) và kiến trúc cụ thể của native UI (`*(KN: Jetpack Compose)*` / `*(KN: SwiftUI)*`).
