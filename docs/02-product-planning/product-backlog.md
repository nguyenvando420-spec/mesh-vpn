# Product Backlog — Mesh VPN Cá Nhân (kiểu Tailscale, tự host trên 1 VPS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-po-ba` |
| Ngày | 2026-11-12 |
| Phiên bản | **1.2** — Đồng bộ quyết định Gate 1 (người dùng duyệt 2026-11-12): macOS + Windows là client hạng nhất; kết nối bằng IP VPS + Pin; cổng TCP/UDP cấu hình được; di chuyển cấu hình không mất danh tính (`SEC-15`) |
| Nguồn | [reference-systems-benchmark.md](../01-discovery/reference-systems-benchmark.md) · [production-readiness-requirements.md](../01-discovery/production-readiness-requirements.md) |
| Liên kết | [vision-statement.md](../01-discovery/vision-statement.md) · [project-charter.md](../01-discovery/project-charter.md) · [user-personas.md](./user-personas.md) |
| Thành phần AI/SLM | **Không có** ⇒ không có AI/Data Epic |

### Lịch sử sửa đổi

| Phiên bản | Ngày | Nội dung |
|---|---|---|
| 1.0 | 2026-11-12 | Bản đầu trình `agile-critic` |
| 1.1 | 2026-11-12 | Khắc phục triệt để phản biện Gate 1 Vòng 1 (`gate-1-critique.md`): **`BLK-01`** (`US-012`, `US-046`, ma trận truy vết `SEC-14`), **`BLK-02`** (`US-034`, `US-003`, `US-047`), **`BLK-03`** (`US-009`, `US-021`, `US-025`, `US-031`), **`HR-01`** (`US-024`, `US-042`, `US-046`, `US-047`, `US-051`), **`HR-02`** (`US-004`, `US-012`, `US-038`), **`HR-03`** (`US-009`, `US-013`, `US-019`, `US-022`, `US-033`, `US-036`), **`IMP-01..04`** (`US-004`, `US-016`, `US-017`, `US-019`, `US-020`, `US-023`, `US-032`, `US-042`, `US-043`, `US-045`, `US-059`, `US-066`) |
| **1.2** | 2026-11-12 | **Đồng bộ Gate 1 đã duyệt + `production-readiness-requirements.md` v1.2.** (1) **macOS lên hạng nhất (`Must`)**: chuyển `US-060` ra khỏi `EP-12` thành story `Must` 5 SP trong `EP-03`; thêm **`US-073`** (macOS Daemon `launchd`, IPC phân quyền, cài/gỡ sạch — `EP-10`); cập nhật `US-001`, `US-014`, `US-016`, `US-017`, `US-020`, `US-033`, `US-035` (nay là macOS + Linux VPS/Lab), `US-036`, `US-038`, `US-039`, `US-041`, `US-050`, `US-055`, `US-056`; `US-054` (Linux máy trạm) hạ `Must` → `Should` — phần `systemd`/quyền tối thiểu của VPS-node chuyển sang `US-056`, `US-014`, `US-051` để vẫn phủ `PLAT-03(a)` P0. (2) **Kết nối bằng IP VPS + Pin (`SEC-04(c)`) là luồng chính thức từ Milestone 1; cổng TCP (mặc định 443) và UDP STUN (mặc định 3478) cấu hình được**: cập nhật `US-002`, `US-003`, `US-004`, `US-009`, `US-012`, `US-019`, `US-023`, `US-024`, `US-028`, `US-034`, `US-044`, `US-045`, `US-046`, `US-047`, `US-051`; thêm **`US-074`** (đổi cổng/IP/chế độ xác thực server không mất danh tính — `SEC-15`, `EP-09`). (3) **Tái ước lượng có giải trình**: `US-035` 5→8, `US-046` 3→5, `US-047` 5→8, `US-056` 2→3. (4) **Tính lại toàn bộ số đếm**: Must **51 story / 234 SP**, Should **11 / 35**, Phase 2+ **12**, tổng **74** story; ma trận truy vết mục 14 phủ `SEC-01..15`, `REL-01..15`, `OPS-01..10`, `PERF-01..12`, `PLAT-01..07`; mục 15 chia **2 Milestone** (OQ-14) và áp dụng ghi chú của Critic (khung IPC Admin `US-012` vào `S1` cùng `US-002`; gom `US-046` + `US-051` cùng nhóm triển khai VPS). (5) **Bảo toàn 100%** `SEC-14`, `BLK-01..03`, `HR-01..03`, `IMP-01..04` (không nới lỏng AC nào) |

---

## 0. Quy ước

### 0.1. Định dạng Story
- **ID**: `EP-xx`, `US-xxx`. **SP** (Story Points) ∈ {1, 2, 3, 5, 8}, **không story nào > 8**. **MoSCoW**: `Must` = MVP bắt buộc; `Should` / `Could` / `Won't` = Phase 2+ hoặc cắt được.
- **Trace**: mã yêu cầu nghiên cứu (`SEC-*`, `REL-*`, `OPS-*`, `PERF-*`, `PLAT-*`) được phủ bởi story đó.
- **Acceptance Criteria (AC)** dạng `Given / When / Then`, gắn nhãn: **[H]** Happy path · **[E]** Edge case · **[F]** Failure handling · **[N]** Non-functional/SLO (có ngưỡng định lượng). Mọi AC phải **đo kiểm tự động được** (test tích hợp/chaos trong phòng lab US-057) hoặc có kịch bản thủ công có biên bản cho case phụ thuộc hệ điều hành/phần cứng.
- **Các thuật ngữ**: *Agent* = tiến trình nền trên mỗi thiết bị; *Control* = máy chủ điều phối trên VPS; *Relay* = bộ chuyển tiếp mù trên VPS; *Netmap* = bản đồ peer do Control phân phối; *Overlay IP* = IP ảo của thiết bị; *Direct* = P2P trực tiếp; *Pin* = dấu vân tay khóa công khai của server dạng `sha256:<…>` (SPKI pin) mà client đối chiếu khi kết nối bằng IP; *Server endpoint* = `IP|domain:cổng TCP` của Control/Relay; *`mesh`* = tên CLI chính thức (OQ-12) — các lệnh trong Backlog viết tắt (`up`, `down`, `status`, `set`…) tương ứng `mesh up`, `mesh down`, `mesh status`, `mesh set`…; việc nhóm lệnh server/client do `agile-architect` chốt ở Gate 2; hậu tố miền nội bộ chính thức: `.mesh.internal` (OQ-12).

### 0.2. Ranh giới công nghệ (KHÔNG khóa trong Backlog)
Backlog **không** chỉ định ngôn ngữ lập trình, framework, thư viện hay DB cụ thể — do `agile-tech-lead` (ADR) và `agile-architect` (schema, giao thức) quyết ở Gate 2. Backlog chỉ nêu **hành vi và ràng buộc quan sát được** (vd. "UNIQUE trên public key", "ACID transaction", "dùng giao thức WireGuard chuẩn" theo đề xuất nghiên cứu/giả định A-04).

### 0.3. Definition of Ready (DoR)
Story có Persona + giá trị rõ; AC đủ [H]/[E]/[F]; phụ thuộc đã nêu; ước lượng ≤ 8 SP; câu hỏi mở liên quan (OQ-xx) đã chốt hoặc có giả định.

### 0.4. Definition of Done (DoD) cho mọi story Must
1. AC đạt bằng test tự động (unit + tích hợp; chaos/lab khi có); 2. Không log/xuất secret (private key, pre-auth key, token) — kiểm tra bằng test grep; 3. Format/Lint pass theo chuẩn của Tech Lead; 4. Có log có cấu trúc cho sự kiện chính (US-043); 5. Tài liệu CLI/runbook cập nhật nếu đổi hành vi vận hành; 6. QA độc lập duyệt.

### 0.5. NFR toàn cục (áp cho mọi story — "Global Acceptance Criteria")
| Mã | NFR | Ngưỡng | Trace |
|---|---|---|---|
| GNFR-01 | Không tự cài đặt primitive mật mã; mọi crypto qua thư viện chuẩn | 0 mã cipher/MAC/KDF tự viết | SEC-02 |
| GNFR-02 | Không có secret trong log/DB/crash dump/bundle | 0 kết quả grep | SEC-01, OPS-01 |
| GNFR-03 | Mọi I/O mạng có timeout: connect ≤ 10 s; stream có heartbeat ≤ 60 s | 100% kết nối ra VPS | REL-04 |
| GNFR-04 | RAM Control+STUN+Relay (20 node idle) | < 64 MB (trần 128 MB) | PERF-01 |
| GNFR-05 | RAM Agent idle | ≤ 50 MB | PERF-09 |
| GNFR-06 | CPU Control idle (trung bình 5 phút) | < 2% của 1 vCPU | PERF-02 |
| GNFR-07 | Băng thông nền mỗi node idle (1 giờ) | ≤ 1 KB/s trung bình | PERF-10 |
| GNFR-08 | Overhead trễ đường direct | ≤ 2 ms P95 | PERF-03 |
| GNFR-09 | Throughput direct | ≥ 70% throughput mạng gốc tới 300 Mbps | PERF-04 |
| GNFR-10 | Khả dụng control (cá nhân) — data plane không phụ thuộc | ≥ 99%/tháng | PERF-12 |
| GNFR-11 | **Cổng và địa chỉ server không bao giờ mã hóa cứng**: cổng TCP Control/Relay (mặc định `443`) và cổng UDP STUN (mặc định `3478`) là tham số cài đặt, đổi được sang cổng bất kỳ (vd. `8443`, `9443`, `3479`) mà không đổi danh tính node; test chạy ở cả cổng mặc định lẫn cổng tùy chọn | 0 hằng số `443`/`3478` ngoài giá trị mặc định cấu hình (kiểm tra tĩnh) + bộ test chạy với `8443`/`3479` PASS | SEC-04, SEC-06, SEC-15, REL-06 |
| GNFR-12 | **Ma trận nền tảng MVP**: mọi AC nêu hành vi "trên OS" phải được kiểm chứng trên **macOS 13+ (`arm64` Apple Silicon và `amd64` Intel)**, **Windows 10/11 x64**, và **Ubuntu LTS (VPS-node + container lab)**. macOS **không** giả lập được trong lab container Linux ⇒ kịch bản phụ thuộc `utun`/`launchd`/Gatekeeper/sleep-wake chạy trên **máy Mac thật, VM trên phần cứng Apple hoặc runner CI macOS**, có biên bản | 100% AC phụ thuộc OS có kết quả PASS trên đủ 3 OS (hoặc biên bản thủ công) | PLAT-01, PLAT-03, PLAT-05, PLAT-06 |

### 0.6. Phạm vi nền tảng & kết nối MVP (quyết định Gate 1 — người dùng duyệt 2026-11-12)

| # | Quyết định | Tác động Backlog |
|---|---|---|
| D1 | **Client ưu tiên: macOS (13+, `arm64` + `amd64`) và Windows 10/11** | `US-060`, `US-073` (macOS) cùng `US-015`, `US-052`, `US-053` (Windows) đều `Must`; `US-035`/`US-036`/`US-038`/`US-055` phủ cả hai |
| D2 | **VPS vẫn là Ubuntu Linux** (Control + Relay + STUN, đồng thời là 1 node mesh — `US-056`; phục vụ lab NAT container — `US-057`); Linux `/dev/net/tun` tối thiểu (`US-014`, `Must`); gói dịch vụ Linux **máy trạm** (`US-054`) hạ `Should` | `US-014`, `US-056`, `US-051` giữ `PLAT-03(a)` P0; `US-054` = `PLAT-03(b)` P1 |
| D3 | **Kết nối bằng IP VPS + Pin (`SEC-04(c)`) là luồng chính thức mặc định ngay Milestone 1**, chưa cần domain; **cấm TOFU ngầm**, **không có cờ bỏ qua pin** | `US-003`, `US-047` (S1), `US-004`, `US-002`, `US-012`, `US-045` |
| D4 | **Cổng TCP (Control+Relay, mặc định 443) và UDP (STUN, mặc định 3478) cấu hình được và đổi được về sau không đổi danh tính node** (`SEC-15`) | `GNFR-11`, `US-009`, `US-019`, `US-024`, `US-046`, `US-051`, **`US-074`** |
| D5 | CLI chính thức **`mesh`**; hậu tố miền nội bộ **`.mesh.internal`**; VPS là node `vps.mesh.internal` (OQ-03); tự định nghĩa giao thức (OQ-01); 2 Milestone (OQ-14) | `US-038`, `US-056`, mục 15 |

---

## 1. Danh sách Epics

| Epic | Tên | Loại | Nhóm yêu cầu nghiên cứu | Stories (ID) | Tổng story | Must (story / SP) | Should (story / SP) |
|---|---|---|---|---|:-:|:-:|:-:|
| **EP-01** | Đăng ký & Xác thực thiết bị an toàn (kết nối bằng IP + Pin) | Functional | SEC-01..04, REL-02 | US-001..006 | 6 | 5 / 19 | 1 / 3 |
| **EP-02** | Đồng bộ Netmap & Quản lý Peer (Coordination) | Functional | REL-03, REL-11, SEC-09, SEC-10, SEC-14, SEC-15(1), OPS-08, REL-14 | US-007..013 | 7 | 6 / 23 | 1 / 3 |
| **EP-03** | Đường hầm mã hóa & Routing an toàn (Data Plane — **macOS + Windows + Linux VPS-node/lab**) | Functional | REL-09, REL-10, SEC-11, PLAT-01, PLAT-03(a), PLAT-06 | US-014..018, **US-060** | 6 | 5 / 23 | 1 / 3 |
| **EP-04** | P2P NAT Traversal / Hole Punching | Functional | REL-05, PERF-05, OPS-04 | US-019..023 | 5 | 4 / 23 | 1 / 3 |
| **EP-05** | Chuyển tiếp Relay qua VPS (cổng TCP cấu hình được) & Chống lạm dụng | Functional + Security | REL-06, SEC-07, PERF-06, PERF-11 | US-024..028 | 5 | 5 / 26 | 0 / 0 |
| **EP-06** | Vòng đời thiết bị: Thu hồi / Key Expiry & Control-Data tách rời | Production-Readiness | SEC-08, REL-01, REL-04 | US-029..034 | 6 | 5 / 21 | 1 / 5 |
| **EP-07** | Tự khôi phục: Đổi mạng, Sleep/Wake (macOS + Windows), xung đột dải IP | Production-Readiness | REL-07, PLAT-05, REL-14 | US-035..037 | 3 | 2 / 13 | 1 / 3 |
| **EP-08** | Tên máy nội bộ (MagicDNS-lite) & CLI chẩn đoán | Functional | OPS-02/03/09, PLAT-04 | US-038..041 | 4 | 3 / 13 | 1 / 3 |
| **EP-09** | Vận hành & Bảo mật: Rate-limit, Log, Healthcheck, Backup, Hardening, Xác thực server, **Đổi cổng/IP không mất danh tính** | Production-Readiness / Ops | SEC-04/05/06/14/15, OPS-01/05/06/07/10, REL-12/13 | US-042..051, **US-074** | 11 | 8 / 36 | 3 / 9 |
| **EP-10** | Tích hợp nền tảng (**macOS/Windows client**, Linux VPS-node/máy trạm) & Dọn dẹp | Production-Readiness | PLAT-01..03, PLAT-06, REL-08, REL-09, REL-13 | US-052..056, **US-073** | 6 | 5 / 21 | 1 / 3 |
| **EP-11** | Kiểm thử NFR/SLO, Phòng lab mạng & Runbook | Enabler | Go-Live checklist, PERF-* | US-057..059 | 3 | 3 / 16 | 0 / 0 |
| **EP-12** | Phase 2+ (Mở rộng) | Roadmap | Mục 7 benchmark; SEC-12/13; REL-15; PLAT-07 | US-061..072 | 12 | — | — |
| | **Tổng cộng** | | | US-001..074 | **74** | **51 / 234** | **11 / 35** |

**Tổng Must-have (MVP): 51 story / 234 SP · Should (cắt được): 11 story / 35 SP · Phase 2+ (EP-12): 12 story (không tính SP) · Tổng: 74 story.** (Kiểm: 62 story MVP+Should = 51 + 11; 62 + 12 = 74.)

---

## 2. EP-01 — Đăng ký & Xác thực thiết bị an toàn

> Mục tiêu: máy mới vào mạng an toàn bằng pre-auth key dùng-một-lần; private key không rời máy; đăng ký lặp không tạo trùng. (Persona P1, P2)

### US-001 — Sinh khóa & lưu khóa an toàn tại client
- **Epic**: EP-01 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-01, SEC-02, PLAT-01, PLAT-03, PLAT-06
- **Story**: Là *chủ mạng*, tôi muốn agent **tự sinh cặp khóa ngay trên thiết bị** và chỉ gửi public key đi, để private key không bao giờ rời máy.
- **Phụ thuộc**: không (story khởi đầu).
- **AC**:
  1. **[H]** *Given* thiết bị chưa có khóa, *When* chạy agent lần đầu, *Then* một cặp khóa (curve theo giao thức data plane) được sinh cục bộ và lưu bền vững; private key không xuất hiện trong bất kỳ thông điệp mạng nào gửi tới Control/Relay (kiểm tra bằng bắt gói + schema thông điệp không có trường private key).
  2. **[H]** *Given* khóa đã tồn tại, *When* agent khởi động lại, *Then* dùng lại đúng khóa (public key không đổi).
  3. **[E]** *Given* **macOS 13+ (`arm64` và `amd64`)**, *When* kiểm tra quyền file khóa, *Then* file khóa là `0600` owner **`root:wheel`**, nằm trong thư mục trạng thái `0700` thuộc root (đường dẫn cụ thể do Architect chốt; Keychain là tùy chọn Phase 2) — user thường/nhóm `admin` không đọc được; *Given* Linux (VPS-node/lab), *Then* chỉ owner root đọc được (mode 0600); *Given* Windows, *Then* ACL chỉ gồm SYSTEM và Administrators (hoặc lưu bằng cơ chế bảo vệ của OS). Kiểm bằng `stat`/ACL dump trên cả 3 OS (GNFR-12).
  4. **[E]** *Given* file khóa bị hỏng/cắt cụt, *When* agent khởi động, *Then* **không** tự sinh khóa mới ghi đè âm thầm; agent thoát với mã lỗi rõ ràng và hướng dẫn (vì khóa mới = danh tính mới).
  5. **[F]** *Given* mọi đường ra: log, kết quả `status`, crash dump, bundle chẩn đoán, *When* chạy test grep chuỗi private key (base64/hex), *Then* 0 kết quả (GNFR-02).

### US-002 — Admin tạo/liệt kê/thu hồi pre-auth key (one-time, TTL, chỉ lưu hash)
- **Epic**: EP-01 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-03, SEC-14, OPS-08, SEC-09
- **Story**: Là *chủ mạng*, tôi muốn tạo pre-auth key dùng-một-lần có hạn trên VPS bằng CLI, để cấp quyền cho đúng một thiết bị mới trong thời gian ngắn.
- **Phụ thuộc**: US-007, US-012.
- **AC**:
  1. **[H]** *Given* admin có quyền quản trị trên VPS (giao tiếp qua kênh cục bộ kiểm chứng đặc quyền OS theo `SEC-14` / `US-012 AC4`), *When* chạy `preauthkey create` (hỗ trợ tùy chọn `--for <node>` để trói đích danh cho việc đăng ký lại/xoay khóa ở `US-031`/`US-032`), *Then* sinh key ngẫu nhiên ≥128 bit entropy từ CSPRNG, mặc định **one-time**, **TTL mặc định 1 giờ**, in key **đúng một lần**; ghi audit (US-013).
  2. **[H]** *When* chạy `preauthkey list`, *Then* hiển thị id, trạng thái (active/used/expired/revoked), hạn, node đích danh (nếu có), thiết bị đã dùng — **không** hiển thị giá trị key.
  3. **[E]** *Given* TTL yêu cầu > 90 ngày hoặc ≤ 0, *When* tạo key, *Then* bị từ chối với thông báo rõ ràng (tối đa 90 ngày).
  4. **[E]** *Given* key chưa dùng, *When* chạy `preauthkey revoke <id>`, *Then* key không còn đăng ký được (đăng ký bằng key đó bị từ chối; thực thi ngay trong RAM kể cả khi đĩa đầy theo `US-013 AC4`).
  5. **[F]** *Given* DB bị dump, *When* kiểm tra bảng key, *Then* chỉ có **hash** (so sánh constant-time), không có key rõ; test grep key rõ trong DB/log = 0.
  6. **[H]** *Given* chủ mạng tạo key để thêm máy mới (kể cả khi server dùng cổng tùy chọn như `8443` và chế độ IP + Pin), *When* chạy `preauthkey create`, *Then* CLI **in sẵn lệnh tham gia** hoàn chỉnh cho client (`mesh up --server <IP|domain>:<cổng TCP> --server-pin sha256:<…> --authkey-file <path> --name <tên>`, kèm biến thể `stdin`/env cho máy headless; không in key vào dòng lệnh dạng cờ `--authkey` mặc định) để copy-paste không sai `IP:cổng`/pin; lệnh dùng nguyên văn chạy được trên macOS, Windows và Linux. Lấy pin/cổng hiện hành từ cấu hình server (`US-047`, `US-012 AC6`).

### US-003 — Kênh control bảo mật: TLS + xác thực server (IP + Pin mặc định, hoặc CA) + chứng minh sở hữu khóa node bằng challenge/nonce ngẫu nhiên
- **Epic**: EP-01 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-02, SEC-04, SEC-15
- **Story**: Là *chủ mạng*, tôi muốn agent nói chuyện với Control qua kênh TLS đã xác thực và chứng minh nó nắm private key của node bằng challenge ngẫu nhiên từ server, để kẻ MITM hay kẻ mạo danh không chèn được và không bị lỗi lệch múi giờ dual-boot.
- **Phụ thuộc**: US-001, US-047 (sinh khóa/pin server), OQ-02 ✅ (Gate 1 đã chốt: hỗ trợ cả 3 chế độ; **IP + Pin là luồng mặc định hạng nhất từ Milestone 1**).
- **AC**:
  1. **[H]** *Given* agent kết nối tới `server endpoint` dạng **`IP:cổng TCP` + `--server-pin sha256:<…>` (chế độ chính thức mặc định — `SEC-04(c)`; cổng mặc định `443`, cấu hình được sang bất kỳ cổng nào như `8443`, GNFR-11)** — hoặc tới domain có chứng chỉ hợp lệ (ACME Standalone hoặc qua Reverse Proxy sẵn có trên VPS, chế độ `SEC-04(a)/(b)`), *When* agent kết nối, *Then* agent chỉ chấp nhận server có **khóa công khai khớp pin** (SPKI pin — tái phát hành chứng chỉ giữ nguyên khóa thì client không phải làm gì) hoặc chuỗi CA hợp lệ cho đúng domain; TLS ≥ 1.2 (ưu tiên 1.3) thành công và bước chứng minh sở hữu khóa node dùng **server-generated random challenge/nonce theo phiên** trên cấu trúc mật mã chuẩn (không phụ thuộc đồng hồ tuyệt đối của client) hoàn tất ≤ 2 s trong điều kiện RTT ≤ 100 ms.
  2. **[F]** *Given* một MITM/Captive Portal trình chứng chỉ giả hoặc không khớp pin, *When* agent kết nối, *Then* agent **từ chối**, log cảnh báo, **không** gửi bất kỳ pre-auth key/public key nào, và chuyển sang cơ chế thử lại an toàn (`US-034 AC4`).
  3. **[F]** *Given* build release, *When* tìm cờ/tham số "bỏ qua xác minh chứng chỉ", *Then* không tồn tại (kiểm tra tĩnh + test cấu hình).
  4. **[F]** *Given* node trình public key khác khóa mà nó chứng minh được (hoặc phát lại challenge của phiên cũ), *When* thử đăng nhập control, *Then* Control từ chối và ghi audit.
  5. **[E]** *Given* bước chứng minh khóa dùng nonce ngẫu nhiên của server, *When* đồng hồ client lệch nhẹ hoặc lệch múi giờ dual-boot Windows/Linux (vài giờ) nhưng vẫn nằm trong khoảng hiệu lực `NotBefore`..`NotAfter` thực tế của chứng chỉ TLS, *Then* kết nối vẫn thành công bình thường; *When* đồng hồ máy chưa đồng bộ (vd. máy headless vừa bật lại sau mất điện trước khi NTP chạy) làm thời gian rơi ra ngoài `NotBefore`/`NotAfter` của chứng chỉ TLS, *Then* agent từ chối kết nối an toàn, ghi log nêu rõ hạn chứng chỉ kèm **nghi vấn lệch đồng hồ hệ thống (clock skew)** và tự thử lại theo `US-034 AC4` (kết nối lại ngay khi NTP đồng bộ giờ). *(Ở chế độ Pin, việc có kiểm tra hạn `NotBefore`/`NotAfter` của chứng chỉ chứa khóa được pin do Architect chốt Gate 2; nhưng **không bao giờ** được bỏ qua việc đối chiếu pin.)*
  6. **[F]** *Given* client **không có pin và không ở chế độ domain/CA** (vd. chỉ truyền `IP:cổng`), *When* chạy `up`/kết nối, *Then* agent **từ chối kết nối ngay**, không gửi bất kỳ secret nào, in hướng dẫn "cần `--server-pin sha256:…` lấy từ `mesh` trên VPS qua SSH" — **cấm tin-lần-đầu ngầm định (TOFU)**; kiểm tra tĩnh: không tồn tại cờ/biến môi trường/giá trị cấu hình nào tắt kiểm tra pin hoặc cho phép chấp nhận khóa lạ trong bản release.
  7. **[F]** *Given* kẻ MITM trình **chứng chỉ do CA công cộng hợp lệ cấp cho đúng IP** nhưng khóa công khai khác pin (hoặc khóa/chứng chỉ tự ký giả), *When* agent kết nối ở chế độ IP + Pin, *Then* agent từ chối, log `WARN` rõ "pin mismatch" (kèm fingerprint nhận được và fingerprint kỳ vọng — không lộ secret), không gửi pre-auth key/public key, và tiếp tục thử lại theo `US-034 AC4`.
  8. **[E]** *Given* cổng TCP của server là cổng tùy chọn (vd. `8443`) hoặc cổng mặc định `443`, *When* chạy bộ test xác thực ở cả hai cổng, *Then* kết quả giống nhau (không có logic giả định cứng `443`).

### US-004 — Đăng ký thiết bị bằng pre-auth key & cấp Overlay IP bền vững
- **Epic**: EP-01 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-03, REL-02, REL-11, PLAT-04
- **Story**: Là *người dùng thiết bị*, tôi muốn chạy một lệnh cài đặt kèm pre-auth key (truyền an toàn không lộ trên danh sách tiến trình) để máy tự có tên hợp lệ và IP overlay cố định, để không phải cấu hình thủ công ở máy khác.
- **Phụ thuộc**: US-001, US-002, US-003, US-007, US-008, US-047 (pin/cấu hình server).
- **AC**:
  1. **[H]** *Given* key one-time hợp lệ, *When* chạy `up --server <IP|domain>:<cổng> --server-pin sha256:<…>` (cổng mặc định 443, cấu hình được; luồng IP + Pin hạng nhất — `US-003`) truyền key qua `--authkey-file <path>`, `stdin` (`--authkey-stdin`), biến môi trường (khuyến nghị cho máy headless để **không lộ key trong `ps aux` / `/proc/<pid>/cmdline` / shell history**; cờ `--authkey` chỉ dùng tương tác kèm cảnh báo) cùng `--name <tên>`, *Then* node được tạo, cấp **Overlay IP duy nhất** trong dải overlay, key chuyển sang `used`, các peer online nhận netmap mới (PERF-08: P95 ≤ 5 s).
  2. **[E]** *Given* thiết bị khởi động lại/mất điện, *When* agent lên lại, *Then* **Overlay IP không đổi** (bền vững theo node).
  3. **[F]** *Given* tên yêu cầu vi phạm định dạng (`[a-z0-9-]`, 1–63 ký tự, không mở đầu/kết thúc bằng `-`), trùng tên node đang có, **hoặc nằm trong danh sách tên cấm** (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`, và chính hostname/domain cấu hình của Control/Relay/STUN — chống vòng lặp DNS `US-038`), *When* đăng ký, *Then* Server từ chối với lỗi rõ ràng (với trường hợp trùng tên thường có thể gợi ý hậu tố) — không bao giờ nhận tên cấm hoặc trùng tên.
  4. **[F]** *Given* key hết TTL / đã dùng / đã thu hồi / sai, *When* đăng ký, *Then* bị từ chối với **cùng một mã và thông báo lỗi chung** (không phân biệt key sai hay hết hạn), không tạo node, không cấp IP.
  5. **[F]** *Given* dải overlay đã hết địa chỉ, *When* đăng ký, *Then* từ chối với lỗi rõ ràng, không hỏng dữ liệu hiện có.
  6. **[F]** *Given* Control sập giữa lúc đăng ký (kill -9), *When* khởi động lại, *Then* không có node "nửa vời" hay IP bị cấp mà thiếu node (REL-11).
  7. **[E]** *Given* đăng ký thành công, *When* agent ghi cấu hình bootstrap bền vững, *Then* cấu hình **chỉ gồm** `server endpoint` (`IP|domain:cổng TCP`) + thông tin xác thực server (pin hoặc chế độ CA); địa chỉ/cổng Relay và STUN **không** được ghi cứng vào cấu hình mà nhận từ Netmap (`US-009`) — để đổi cổng STUN/Relay về sau không phải sửa từng máy (`SEC-15(1)`, `US-074`).

### US-005 — Đăng ký idempotent (retry an toàn)
- **Epic**: EP-01 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-02
- **Story**: Là *người dùng thiết bị*, tôi muốn gửi lại yêu cầu đăng ký khi timeout mà không tạo thiết bị trùng, để mạng chập chờn không làm hỏng trạng thái.
- **Phụ thuộc**: US-004.
- **AC**:
  1. **[H]** *Given* đăng ký đã thành công nhưng phản hồi bị mất, *When* agent gửi lại **cùng public key + cùng key one-time**, *Then* trả về **cùng node & cùng Overlay IP**, không tiêu hao key thêm.
  2. **[E]** *Given* 3 yêu cầu đăng ký song song cùng public key, *When* xử lý đồng thời, *Then* DB có đúng **1 node, 1 IP** (ràng buộc UNIQUE trên public key và Overlay IP — quan sát được qua test, không quy định công nghệ).
  3. **[F]** *Given* key one-time đã dùng bởi **public key khác**, *When* public key mới thử dùng lại, *Then* bị từ chối (chống dùng lại key).
  4. **[F]** *Given* Control phản hồi lỗi tạm (5xx/timeout), *When* agent thử lại, *Then* theo backoff+jitter (US-034) và không tạo trùng.

### US-006 — Pre-auth key reusable & ephemeral
- **Epic**: EP-01 · **SP**: 3 · **MoSCoW**: **Should** (chờ OQ-06) · **Trace**: SEC-03
- **Story**: Là *home-lab self-hoster*, tôi muốn key dùng nhiều lần (giới hạn số lần) và node ephemeral tự xóa khi offline, để chạy container/VM thử nghiệm không phải tạo key liên tục.
- **Phụ thuộc**: US-002, US-004.
- **AC**:
  1. **[H]** *Given* key reusable `--max-uses 3`, *When* 3 thiết bị khác nhau đăng ký, *Then* cả 3 thành công; *When* thiết bị thứ 4 đăng ký, *Then* bị từ chối.
  2. **[H]** *Given* node ephemeral offline vượt ngưỡng X phút (cấu hình được), *When* hết ngưỡng, *Then* node biến mất khỏi netmap trong ≤ 60 s và IP được giải phóng; ghi audit.
  3. **[E]** *Given* key reusable bị thu hồi, *When* thiết bị đã đăng ký trước đó đang chạy, *Then* chúng **không** bị gỡ (thu hồi key ≠ thu hồi node); chỉ chặn đăng ký mới.
  4. **[F]** *Given* ephemeral node tạm mất mạng ngắn hơn ngưỡng, *When* nối lại, *Then* vẫn giữ nguyên danh tính & IP.

---

## 3. EP-02 — Đồng bộ Netmap & Quản lý Peer (Coordination Server)

> Mục tiêu: một nguồn sự thật duy nhất về peer, an toàn trước crash, lan truyền gần thời gian thực, quản trị bằng CLI. (Persona P1)

### US-007 — Kho dữ liệu Control transactional, toàn vẹn & migration
- **Epic**: EP-02 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-11
- **Story**: Là *chủ mạng*, tôi muốn trạng thái Control luôn nhất quán sau crash/restart, để không bao giờ có node nửa vời hoặc IP trùng.
- **Phụ thuộc**: không.
- **AC**:
  1. **[H]** *Given* thao tác "cấp IP + tạo node + đánh dấu key đã dùng", *When* thực hiện, *Then* diễn ra trong **một giao dịch ACID duy nhất** (cả ba thành công hoặc không cái nào).
  2. **[F]** *Given* kill -9 Control ngẫu nhiên 100 lần trong lúc đăng ký lặp, *When* khởi động lại, *Then* 0 node nửa vời, 0 IP mồ côi, 0 key bị tiêu hao mà không có node.
  3. **[H]** *Given* Control khởi động, *When* chạy kiểm tra toàn vẹn kho dữ liệu, *Then* kiểm tra pass, hoặc từ chối chạy với lỗi rõ + gợi ý restore (US-045).
  4. **[E]** *Given* migration schema có version, *When* chạy lại migration đã áp, *Then* idempotent (không lỗi, không đổi dữ liệu); tự động backup trước mỗi migration (REL-12).
  5. **[F]** *Given* đĩa đầy khi ghi, *When* ghi thất bại, *Then* Control trả lỗi có kiểm soát, `readyz` = 503 (US-044), không hỏng dữ liệu cũ.

### US-008 — Dải overlay cấu hình được & cấp IP không trùng
- **Epic**: EP-02 · **SP**: 2 · **MoSCoW**: Must · **Trace**: REL-14, RFC 6598 (T33), REL-02
- **Story**: Là *chủ mạng*, tôi muốn chọn dải IP overlay lúc cài Control, để tránh trùng với mạng nhà/CGNAT.
- **Phụ thuộc**: US-007.
- **AC**:
  1. **[H]** *Given* cấu hình dải hợp lệ (CIDR, ≥ 64 địa chỉ khả dụng), *When* Control khởi động, *Then* dùng dải đó để cấp IP; mỗi IP chỉ thuộc một node.
  2. **[E]** *Given* dải không hợp lệ / quá nhỏ / trùng dải loopback/link-local/multicast, *When* khởi động, *Then* Control từ chối chạy với thông báo rõ.
  3. **[E]** *Given* dải đã đổi sau khi có node, *When* khởi động, *Then* Control từ chối đổi dải âm thầm (cần thao tác migration có xác nhận) — không đổi IP đang dùng.
  4. **[F]** *Given* dải trùng `100.64.0.0/10` mà hệ thống phát hiện, *When* khởi động, *Then* log cảnh báo `WARN` kèm giải thích rủi ro CGNAT (xử lý phía agent: US-037).

### US-009 — Phân phối Netmap snapshot có version qua stream (không bão `last_seen`)
- **Epic**: EP-02 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-03, PERF-08, PERF-10, SEC-02, SEC-15
- **Story**: Là *người dùng thiết bị*, tôi muốn agent nhận danh sách peer cập nhật gần thời gian thực khi có thay đổi thực sự mà không gây bão lưu lượng nền lúc rảnh, để thêm/xóa máy thì mọi máy biết ngay.
- **Phụ thuộc**: US-004, US-007.
- **AC**:
  1. **[H]** *Given* agent đã đăng ký, *When* mở stream tới Control (gửi `netmap_version` đang có), *Then* nhận **snapshot đầy đủ** gồm mỗi peer: `node_id`, tên, overlay IP, public key data plane, **khóa xác thực đường đi `disco_key`** (hoặc cơ chế khóa tương đương giữ *domain separation* với khóa data plane do Architect chốt tại Gate 2 — phục vụ `US-021`), `endpoints[]`, `relay_home`, `key_expiry`, trạng thái `online` (`true`/`false`), cùng **bản đồ Relay/STUN (`relay_map`)** gồm địa chỉ `IP|domain:cổng` TCP của Relay và `IP:cổng` UDP của STUN mà server đang phục vụ (cấu hình được, **không** mã hóa cứng — `SEC-15(1)`, GNFR-11) và `netmap_version` **tăng đơn điệu**; Control **chỉ tăng `netmap_version` và đẩy bản mới** khi thay đổi cấu trúc/peer/tên/khóa/`endpoints[]`/`relay_map`/thu hồi/hết hạn hoặc khi peer chuyển trạng thái `online ↔ offline` (có debounce) — **tuyệt đối không tăng version hay bắn lại snapshot cho mỗi nhịp heartbeat `last_seen`** (giữ `GNFR-07 ≤ 1 KB/s` và `GNFR-06 < 2% CPU`).
  2. **[N]** *Given* 20 agent online, *When* thêm/thu hồi một node, *Then* tất cả agent online nhận bản mới trong **P95 ≤ 5 s** (đo từ timestamp audit tới log agent).
  3. **[E]** *Given* agent ngắt rồi kết nối lại, *When* gửi version cũ, *Then* nhận snapshot mới nhất; *Given* Control gửi bản có version ≤ đã có, *Then* agent bỏ qua.
  4. **[F]** *Given* stream im lặng > 60 s không có khung heartbeat nhẹ của kênh stream, *When* quá hạn, *Then* agent coi stream chết, đóng và kết nối lại theo backoff (US-034).
  5. **[E]** *Given* 3–20 node, *When* đo kích thước snapshot, *Then* ≤ 64 KB (xác nhận không cần delta ở MVP).
  6. **[H]** *Given* admin đổi cổng STUN/Relay hoặc IP server qua `US-074`, *When* `relay_map` đổi, *Then* Control tăng `netmap_version`, mọi agent online nhận `relay_map` mới trong **P95 ≤ 5 s** (PERF-08) **qua stream đã xác thực pin/CA hiện hành** và ghi bền; *Given* `relay_map`/cấu hình server đến qua kênh không xác thực hoặc từ server sai pin, *Then* agent từ chối, giữ cấu hình cũ và log `WARN` (test chèn cấu hình giả = 100% bị từ chối — `SEC-15(e)`).

### US-010 — Agent áp Netmap vào data plane theo diff (không rớt tunnel cũ)
- **Epic**: EP-02 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-03
- **Story**: Là *người dùng thiết bị*, tôi muốn khi có máy mới thì kết nối giữa các máy cũ không bị gián đoạn, để việc đang làm (SSH, copy file) không đứt.
- **Phụ thuộc**: US-009, US-014/US-015.
- **AC**:
  1. **[H]** *Given* 5 node đang ping liên tục 0.2 s, *When* thêm node thứ 6, *Then* **0 gói mất** do việc áp netmap giữa 5 node cũ (chỉ thêm peer mới).
  2. **[H]** *Given* netmap đổi tên/endpoint của một peer, *When* áp dụng, *Then* chỉ peer đó được cập nhật; peer khác không bị gỡ/dựng lại.
  3. **[E]** *Given* netmap bỏ một peer, *When* áp dụng, *Then* chỉ peer đó bị gỡ khỏi data plane.
  4. **[F]** *Given* lỗi áp dụng một peer (vd. endpoint không hợp lệ), *When* xảy ra, *Then* các peer còn lại vẫn được áp dụng và lỗi được log kèm `peer_id`; không rollback toàn bộ.

### US-011 — Agent kiểm tra tính hợp lệ của Netmap (chống netmap độc)
- **Epic**: EP-02 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: SEC-10
- **Story**: Là *chủ mạng*, tôi muốn agent từ chối netmap bất thường, để nếu Control bị lỗi/bị chiếm thì thiệt hại bị giới hạn.
- **Phụ thuộc**: US-009.
- **AC**:
  1. **[F]** *Given* netmap chứa peer có overlay IP ngoài dải, trùng IP, hoặc trùng public key, *When* agent nhận, *Then* từ chối **toàn bộ** bản đó, giữ netmap cũ, log `WARN` kèm lý do.
  2. **[F]** *Given* netmap có `netmap_version` không tăng, *When* nhận, *Then* bỏ qua.
  3. **[E]** *Given* số peer thay đổi > 50% trong một bản cập nhật (ngưỡng cấu hình), *When* nhận, *Then* vẫn áp dụng nhưng ghi cảnh báo `WARN` "thay đổi bất thường".
  4. **[F]** *Given* endpoint ứng viên của peer thuộc dải overlay hoặc interface tunnel, *When* áp dụng, *Then* endpoint đó bị loại (liên quan US-016).

### US-012 — CLI quản trị server qua kênh cục bộ kiểm chứng đặc quyền OS (`SEC-14`)
- **Epic**: EP-02 · **SP**: 3 · **MoSCoW**: Must · **Trace**: OPS-08, SEC-14, SEC-06, SEC-15, PLAT-04
- **Story**: Là *chủ mạng*, tôi muốn quản trị hoàn toàn bằng CLI qua SSH trên kênh cục bộ được OS kiểm chứng quyền quản trị, để không cần Web UI ở MVP và không ai trong mesh hay tiến trình phụ trên VPS leo thang chiếm quyền được.
- **Phụ thuộc**: US-007. (`preauthkey` ở US-002; `revoke` ở US-029; `backup now` ở US-045; đổi cổng/IP/pin ở US-074.) **Lát cắt: khung kênh IPC Admin cục bộ (AC4 — Unix Domain Socket quyền + xác minh danh tính tiến trình gọi) được kéo vào `S1` cùng `US-002`** để mọi lệnh quản trị sau này (kể cả `preauthkey create`) đi qua kênh đã khóa ngay từ đầu; các lệnh `node expire`/`version` hoàn thiện đầy đủ khi `US-031` hoàn tất.
- **AC**:
  1. **[H]** *When* chạy `node list`, *Then* hiển thị id, tên, overlay IP, trạng thái online/offline, `last_seen`, `key_expiry`, phiên bản agent; kết quả ≤ 1 s với 20 node.
  2. **[H]** *When* chạy `node rename <id|tên> <tên mới>`, *Then* kiểm tra định dạng + từ chối danh sách tên cấm/trùng lặp giống hệt `US-004 AC3` (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`, và hostname/domain của Control/Relay/STUN); nếu hợp lệ thì cập nhật, các peer nhận tên mới trong P95 ≤ 5 s và ghi audit.
  3. **[H]** *When* chạy `node expire <node>` hoặc `version`, *Then* hành vi đúng (`expire` = buộc đăng ký lại bằng key mới, xem US-031).
  4. **[F]** *Given* yêu cầu tách biệt hoàn toàn kênh Admin khỏi listener quan sát chỉ-đọc (`SEC-14`), *When* kiểm tra kiến trúc kênh và thử gọi trái phép, *Then* CLI quản trị chỉ giao tiếp qua **kênh cục bộ trên VPS có kiểm chứng đặc quyền OS** (vd. Unix Domain Socket quyền `0600`/`0660` thuộc `root`/nhóm quản trị riêng kèm xác minh danh tính tiến trình gọi ở phía server, hoặc thao tác cục bộ trực tiếp dưới quyền quản trị qua SSH) và ghi `UID`/user gọi vào audit; **tuyệt đối cấm** mở Admin API trên `IP overlay`, `IP public` hay TCP `127.0.0.1`/`::1` trần — quét từ node bất kỳ trong mesh hoặc gọi từ user thường/`www-data`/container/SSRF trên VPS đều bị từ chối.
  5. **[F]** *Given* tên/ID không tồn tại, *When* gõ lệnh, *Then* mã thoát khác 0 và thông báo rõ, không thay đổi dữ liệu.
  6. **[H]** *When* chạy `server info` (chỉ-đọc, qua kênh Admin cục bộ — `OPS-08`), *Then* hiển thị: `IP|domain` + **cổng TCP** (Control/Relay) và **cổng UDP** (STUN) đang lắng nghe, chế độ xác thực server (`pin`/`CA`), **fingerprint `sha256:<…>` hiện hành (và pin kế tiếp nếu đang xoay)**, chế độ triển khai (Standalone/Reverse Proxy), danh sách agent chưa xác nhận cấu hình mới (khi đang chuyển tiếp — `US-074`); không hiển thị khóa riêng của server.

### US-013 — Audit log append-only & ưu tiên thu hồi khẩn cấp khi đầy đĩa
- **Epic**: EP-02 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-09, SEC-08
- **Story**: Là *chủ mạng*, tôi muốn có nhật ký append-only của mọi thao tác nhạy cảm và đảm bảo lệnh thu hồi khẩn cấp không bao giờ bị kẹt khi đầy đĩa, để điều tra sự cố và cắt kẻ xâm nhập tức thì.
- **Phụ thuộc**: US-007.
- **AC**:
  1. **[H]** *Given* các thao tác: tạo/thu hồi key, đăng ký node, thu hồi/hết hạn node, đổi tên/IP, **đổi cổng/địa chỉ/chế độ xác thực server, xoay khóa/pin server (`SEC-15`, `US-074`)**, gọi CLI admin, vượt ngưỡng xác thực lỗi, *When* mỗi thao tác xảy ra, *Then* sinh **đúng 1** bản ghi gồm timestamp UTC, actor (`UID`/user hoặc `node_id`), `node_id` đích, IP nguồn (nếu qua mạng), kết quả, đồng thời xuất bản ghi ra luồng log hệ thống (`journald`/`stderr`).
  2. **[E]** *Given* bản ghi audit đã ghi, *When* thử sửa/xóa bản ghi bằng bất kỳ CLI/API nào của sản phẩm, *Then* không tồn tại đường nào làm được (append-only ở tầng ứng dụng; không yêu cầu chuỗi băm `hash-chain` ở MVP trên 1 VPS đơn).
  3. **[F]** *Given* kiểm tra nội dung, *When* grep pre-auth key rõ/private key trong audit, *Then* 0 kết quả.
  4. **[F]** *Given* ghi audit vào DB thất bại (đầy đĩa/lỗi I/O), *When* thực hiện thao tác cấp mới/thay đổi thông thường (đăng ký node, tạo key, đổi tên…), *Then* thao tác **bị từ chối (fail-closed)** và báo lỗi rõ; **riêng với lệnh phòng vệ khẩn cấp (`node revoke`, `preauthkey revoke`, `node expire`)**, *Then* hệ thống **bắt buộc thực thi ngay trong bộ nhớ (RAM)** để cắt kết nối tunnel/relay của kẻ trộm tức thì, kèm xuất bản ghi audit + cảnh báo `CRITICAL` ra `stderr`/`syslog`/`journald`.

---

## 4. EP-03 — Đường hầm mã hóa & Routing an toàn (Data Plane)

> Mục tiêu: dựng tunnel WireGuard-based, không làm hỏng routing máy thật. (Persona P3, P1)

### US-014 — Dựng đường hầm mã hóa trên Linux tối thiểu (VPS-node & lab container; interface, route, AllowedIPs /32)
- **Epic**: EP-03 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-02, SEC-11, REL-10, PLAT-03(a)
- **Story**: Là *chủ mạng*, tôi muốn agent Linux (chạy trên **VPS Ubuntu làm 1 node** — `US-056` — và trong **container lab NAT** — `US-057`) tạo interface overlay qua `/dev/net/tun` và route tới đúng các peer, để ping/SSH giữa VPS, macOS và Windows bằng Overlay IP. *(Gói cài dịch vụ Linux cho máy trạm desktop là `US-054` — `Should`, sau macOS + Windows.)*
- **Phụ thuộc**: US-004, US-009.
- **AC**:
  1. **[H]** *Given* agent Linux đã đăng ký, *When* khởi động, *Then* interface tunnel được tạo với Overlay IP, route **chỉ cho dải overlay**; không có default route nào được thêm.
  2. **[H]** *Given* hai node Linux có đường (relay hoặc direct), *When* `ping <overlay_ip_peer>`, *Then* ICMP thành công; gói trên dây là gói WireGuard đã mã hóa (xác nhận bằng bắt gói: không thấy ICMP plaintext).
  3. **[E]** *Given* mỗi peer, *When* kiểm tra cấu hình, *Then* `AllowedIPs` của peer là đúng `/32` overlay IP của peer đó, không rộng hơn (SEC-11).
  4. **[F]** *Given* gói tới từ peer A mang IP nguồn bên trong thuộc peer B, *When* nhận, *Then* bị loại (cryptokey routing).
  5. **[N]** *Given* hai node cùng LAN, *When* đo `ping` IP thật vs overlay (1000 mẫu), *Then* chênh lệch ≤ 2 ms P95 (GNFR-08); `iperf3` direct ≥ 70% mạng gốc tới 300 Mbps (GNFR-09).
  6. **[E]** *Given* agent Linux chạy trong **container lab** (`US-057`), *When* khởi động với quyền tối thiểu (`--cap-add=NET_ADMIN --device /dev/net/tun`, **không `--privileged`**), *Then* tạo TUN, route và ping peer thành công (KN: cờ docker theo PLAT-03(a); kiểm bằng cấu hình container trong lab).
  7. **[E]** *Given* agent Linux chạy (VPS-node hoặc lab), *When* kiểm tra cấu hình hệ thống, *Then* **`/etc/resolv.conf` không bị ghi đè**, và các rule `nftables`/`iptables`/`ufw` sẵn có **không bị flush/xóa** (so sánh dump trước/sau); gỡ agent không để lại interface/route/rule do agent tạo.
  8. **[H]** *Given* VPS-node Linux và một node macOS hoặc Windows cùng mesh, *When* `ping`/`ssh` qua Overlay IP theo cả hai chiều, *Then* thành công (qua relay hoặc direct).

### US-015 — Dựng đường hầm mã hóa trên Windows (adapter tên cố định)
- **Epic**: EP-03 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PLAT-01, REL-08, REL-09, SEC-11
- **Story**: Là *người dùng di động*, tôi muốn agent Windows tạo adapter tunnel ổn định, để dùng RDP/SSH/SMB đến các máy khác.
- **Phụ thuộc**: US-004, US-009. (Cấu hình dịch vụ: US-052.)
- **AC**:
  1. **[H]** *Given* Windows 10/11 x64, *When* agent khởi động, *Then* tạo adapter TUN L3 có **tên cố định** và Overlay IP; route chỉ cho dải overlay; ping peer **macOS và Linux VPS-node** thành công.
  2. **[E]** *Given* tồn tại adapter cùng tên (tàn dư), *When* khởi động, *Then* tái sử dụng/dọn đúng cách, **không** sinh adapter "#2" nhân bản.
  3. **[E]** *Given* driver TUN dùng phân phối kèm, *When* build release, *Then* binary driver nguyên vẹn, đúng điều khoản license phân phối lại (kiểm tra checksum nguyên bản + file license kèm theo).
  4. **[F]** *Given* thiếu quyền Administrator, *When* chạy, *Then* lỗi rõ ràng "cần quyền quản trị", không tạo trạng thái dở dang.
  5. **[N]** `AllowedIPs` /32 và overhead như US-014.

### US-060 — Dựng đường hầm mã hóa trên macOS (`utun`, route L3, AllowedIPs /32)
- **Epic**: EP-03 · **SP**: 5 · **MoSCoW**: Must *(nâng từ Phase 2 theo quyết định Gate 1 D1)* · **Trace**: PLAT-06, SEC-02, SEC-11, REL-08, REL-09, REL-10
- **Story**: Là *chủ mạng kiêm người dùng di động (MacBook)*, tôi muốn agent macOS tạo interface tunnel `utun` đúng chuẩn kernel và chỉ route dải overlay, để SSH/ping/Git giữa MacBook, máy Windows và VPS bằng Overlay IP mà không đụng tới VPN/iCloud Private Relay khác trên máy.
- **Phụ thuộc**: US-004, US-009; dịch vụ nền `launchd` & IPC: US-073; chống routing loop kiểm chứng tại US-016; theo dõi mạng/sleep-wake: US-035.
- **AC**:
  1. **[H]** *Given* macOS 13+ (**cả Apple Silicon `arm64` và Intel `amd64`** — 2 binary native hoặc 1 Universal), *When* agent khởi động sau khi đã đăng ký, *Then* mở interface kernel `utun` **với số `utunN` do kernel cấp động** (chỉ chấp nhận tên dạng `utun[0-9]+`), gán Overlay IP, cài route **chỉ cho dải overlay** qua đúng interface đó, **không có default route** (`0.0.0.0/0`/`::/0`); `ping` và `ssh` Overlay IP giữa **macOS ↔ Windows ↔ Linux VPS-node** thành công theo cả hai chiều; bắt gói trên dây chỉ thấy gói WireGuard mã hóa (không thấy ICMP/TCP plaintext).
  2. **[H]** *Given* agent đã mở `utunN`, *When* ghi trạng thái phiên, *Then* **tên `utunN` thực tế được ghi vào tệp trạng thái** (thư mục root `0700`) và hiển thị trong `status` (`US-039 AC7`); mọi thao tác route/dọn dẹp chỉ áp trên đúng interface đó.
  3. **[E]** *Given* **iCloud Private Relay hoặc một ứng dụng VPN/WireGuard khác đang chạy** (đã giữ các `utunK` riêng), *When* agent khởi động, chạy 10 vòng `up`/`down`/`cleanup`, *Then* agent nhận một số `utun` khác, **không sửa/xóa bất kỳ `utun`/route/cấu hình nào không phải của mình** (so sánh `ifconfig`, `netstat -rn` trước/sau: phần của ứng dụng khác giữ nguyên byte-by-byte).
  4. **[E]** *Given* mỗi peer, *When* kiểm tra cấu hình, *Then* `AllowedIPs` là đúng `/32` overlay IP của peer (SEC-11); MTU `utunN` mặc định **1280**, cấu hình được trong 576–1420 (REL-10, `US-017`).
  5. **[F]** *Given* **chống routing loop trên macOS** (REL-09), *When* agent chạy với nhiều card mạng (Wi-Fi + Ethernet/hotspot) và interface mặc định đổi, *Then* socket UDP/TCP điều khiển, STUN, disco và gói mã hóa của agent **luôn đi qua interface vật lý mặc định, không bao giờ vào `utunN`** (cơ chế như ràng socket vào interface vật lý — KN `IP_BOUND_IF`/`IPV6_BOUND_IF`, hoặc host route qua gateway vật lý — do Architect chốt Gate 2) và được ràng lại khi interface mặc định đổi; thêm route sai cố ý → agent phát hiện/từ chối; endpoint ứng viên thuộc dải overlay/`utunN` bị loại; probe HTTP ra Internet không gián đoạn > 3 s ở mọi bước.
  6. **[F]** *Given* thiếu quyền root (chạy ngoài daemon), *When* thử mở `utun`/cài route, *Then* lỗi rõ ràng "cần quyền quản trị", không tạo trạng thái dở dang.
  7. **[F]** *Given* `kill -9` agent rồi khởi động lại (hoặc mất điện), *When* khởi động, *Then* dọn tàn dư (route, khối hosts, `utunN` của phiên trước) **dựa trên tệp trạng thái phiên trước, không đoán theo số `utun`**, trước khi dựng mới; không route/khối hosts trùng lặp (REL-08, `US-055`).
  8. **[N]** *Given* Apple Silicon (≥ 1 máy) và Intel (máy thật hoặc VM trên phần cứng Apple), *When* đo `ping` IP thật vs overlay (1000 mẫu) và `iperf3` direct, *Then* chênh lệch ≤ 2 ms P95 (GNFR-08), throughput ≥ 70% mạng gốc tới 300 Mbps (GNFR-09), RAM agent idle ≤ 50 MB (GNFR-05); kết quả ghi biên bản (macOS không giả lập được trong lab container — GNFR-12).

### US-016 — Chống routing loop (hành vi cô lập lưu lượng điều khiển & đường hầm)
- **Epic**: EP-03 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-09, REL-07, PLAT-06
- **Story**: Là *chủ mạng*, tôi muốn lưu lượng điều khiển và gói mã hóa của agent không bao giờ bị đẩy ngược vào chính tunnel, để máy không bao giờ mất Internet do vòng lặp.
- **Phụ thuộc**: US-014, US-015, US-060, US-056.
- **AC**:
  1. **[H]** *Given* VPS vừa chạy Control/Relay/STUN vừa là một node mesh (`US-056`), *When* mesh hoạt động trên **macOS, Windows và Linux VPS-node** (kể cả máy có đồng thời nhiều card mạng vật lý LAN + Wi-Fi, hoặc khi **kết nối bằng IP VPS** nên không có tên miền để phân giải), *Then* **0 gói điều khiển/STUN/disco/mã hóa đường hầm của agent đi vào interface tunnel** — 100% đi qua đường mạng nền thực tế (cơ chế cô lập socket/routing cụ thể theo từng OS do `agile-architect` chốt tại Gate 2).
  2. **[F]** *Given* một peer quảng bá endpoint thuộc dải overlay hoặc địa chỉ interface tunnel, *When* agent nhận, *Then* endpoint đó bị loại bỏ và ghi log `WARN`.
  3. **[F]** *Given* kịch bản kiểm thử hỗn loạn (cấu hình mạng ngoài bất lợi, hoặc `kill -9` agent rồi đổi Wi-Fi), *When* agent đang chạy hoặc khởi động lại, *Then* agent ngăn chặn vòng lặp mà **không để lại host route mồ côi làm chặn đường tới VPS** (trên **cả macOS, Windows và Linux VPS-node**; trên macOS không đụng `utun` của hệ thống/VPN khác), và **máy thật luôn truy cập Internet bình thường ở mọi bước** (probe HTTP liên tục không gián đoạn > 3 s).
  4. **[E]** *Given* MVP, *When* kiểm tra bảng route hệ thống, *Then* không có default route (`0.0.0.0/0` hay `::/0`) nào do agent cài đặt.

### US-017 — MTU an toàn mặc định 1280 & cấu hình được
- **Epic**: EP-03 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-10
- **Story**: Là *người dùng di động*, tôi muốn SSH/HTTPS qua overlay không bị treo trên mạng 4G/PPPoE, để làm việc ổn định mọi nơi.
- **Phụ thuộc**: US-014, US-015, US-026.
- **AC**:
  1. **[H]** *Given* cấu hình mặc định, *When* kiểm tra interface tunnel (**`utunN` trên macOS, adapter cố định trên Windows, interface TUN trên Linux**), *Then* MTU = **1280**; giá trị cấu hình được trong khoảng hợp lệ (576–1420) và bị từ chối ngoài khoảng.
  2. **[N]** *Given* lab mô phỏng đường ngoài MTU 1400 (PPPoE/4G) và ICMP "Fragmentation Needed" bị chặn, *When* SCP file 100 MB và `curl` HTTPS trang lớn qua overlay (cả direct và relay), *Then* hoàn tất không treo, 0 timeout.
  3. **[E]** *Given* đường relay (bọc thêm header frame) và đường UDP ngoài, *When* gửi gói kích thước tối đa MTU 1280, *Then* frame relay không bị cắt/rơi (ngân sách MTU tính đủ header relay) và **socket UDP ngoài của đường hầm không ép cứng cờ `DF=1`** để tránh rơi gói tầng ngoài trên mạng di động CLAT/tunnel lồng nhau có MTU sát 1280.
  4. **[H]** *When* chạy ping bên trong overlay (không phân mảnh ở tầng trong) với kích thước payload tương ứng tổng gói IP trong = MTU (1280 byte), *Then* thành công; lớn hơn MTU của interface tunnel thì báo lỗi "message too long" có kiểm soát.

### US-018 — Packet filter tối thiểu trong agent
- **Epic**: EP-03 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: SEC-11
- **Story**: Là *chủ mạng*, tôi muốn agent chỉ nhận traffic đến từ dải overlay trên interface tunnel và có thể chặn một số cổng inbound, để giảm bề mặt tấn công nội bộ.
- **Phụ thuộc**: US-014, US-015.
- **AC**:
  1. **[H]** *Given* gói tới interface tunnel có IP nguồn ngoài dải overlay, *When* nhận, *Then* bị loại và đếm vào metric.
  2. **[H]** *Given* cấu hình chặn inbound cổng 3389 từ overlay, *When* peer kết nối cổng đó, *Then* bị từ chối; cổng khác không bị ảnh hưởng.
  3. **[E]** *Given* không có cấu hình chặn, *When* mặc định, *Then* full-mesh cho phép mọi cổng (A-08).
  4. **[F]** *Given* quy tắc filter không hợp lệ, *When* nạp cấu hình, *Then* từ chối cấu hình, giữ cấu hình cũ (fail-safe), log lỗi.

---

## 5. EP-04 — P2P NAT Traversal / Hole Punching

> Mục tiêu: các máy tìm đường trực tiếp với nhau; luôn có đường đi (relay) trong lúc dò. (Persona P2, P3)

### US-019 — STUN trên VPS, lưu bền cổng UDP cục bộ & gửi STUN từ chính socket tunnel
- **Epic**: EP-04 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-01, REL-07, §4.3, pitfall 5.6.5
- **Story**: Là *người dùng thiết bị*, tôi muốn agent giữ cổng UDP cục bộ ổn định qua các lần restart và biết địa chỉ `public:port` mà NAT cấp cho socket tunnel, để peer khác có thể gửi trực tiếp tới kể cả khi khởi động lại lúc Control offline.
- **Phụ thuộc**: US-014/US-015.
- **AC**:
  1. **[H]** *Given* STUN lắng nghe UDP **trên cổng đã cấu hình (mặc định 3478; chạy được với cổng tùy chọn như `3479`; địa chỉ `IP:cổng` STUN agent lấy từ `relay_map` của Netmap — `US-009`, GNFR-11, không mã hóa cứng)** trên VPS, *When* agent gửi Binding Request từ **cùng socket UDP với tunnel và disco**, *Then* nhận Binding Response và `public ip:port` khớp với tuple mà VPS quan sát (so sánh log VPS); **agent lưu bền số cổng UDP cục bộ đã dùng** và ưu tiên bind lại đúng cổng đó ở các lần khởi động sau (chỉ fallback sang cổng mới do OS cấp nếu cổng cũ đang bị tiến trình khác chiếm — phục vụ `US-033 AC2`).
  2. **[E]** *Given* cơ chế phân loại NAT (RFC 5780), *When* chỉ có 1 IP VPS (`C1`, mở 2 cổng STUN trên cùng IP), *Then* agent phát hiện chính xác **Port-Dependent Mapping (`APDM` — "hard NAT")** so với nhóm không đổi port theo cổng đích (`EIM/ADM`), và chỉ phân tách riêng `ADM` khỏi `EIM` khi người dùng cấu hình thêm một đích STUN phụ khác IP; kết quả và giới hạn 1-IP được lưu rõ để `status`/`netcheck` hiển thị trung thực (`US-023`).
  3. **[F]** *Given* STUN không đáp (UDP bị chặn), *When* hết timeout ≤ 5 s, *Then* agent đánh dấu "UDP không khả dụng", bỏ qua direct, dùng relay; **không** treo khởi động.
  4. **[F]** *Given* STUN chỉ phục vụ binding request hợp lệ, *When* nhận gói rác/flood > 100 pkt/s/IP, *Then* giới hạn tốc độ và không khuếch đại phản hồi (response ≤ request về kích thước).
  5. **[E]** *Given* admin đổi cổng UDP STUN (vd. `3478 → 3479`) qua `US-074`, *When* agent nhận `relay_map` mới, *Then* lần STUN kế tiếp dùng cổng mới (trong P95 ≤ 5 s sau khi nhận — PERF-08), `netcheck`/`status` phản ánh cổng mới, P2P/hole punching hoạt động lại; *Given* cổng UDP STUN bị mạng client chặn, *Then* chỉ mất khả năng dò P2P — dữ liệu vẫn đi qua relay TCP (`REL-06`).

### US-020 — Thu thập & công bố Endpoints (LAN + reflexive), lọc interface ảo & endpoint nguy hiểm
- **Epic**: EP-04 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-07, REL-09, §4.3
- **Story**: Là *người dùng thiết bị*, tôi muốn agent công bố các địa chỉ thực sự có thể tiếp cận được của mình (LAN, IPv6, reflexive) và loại bỏ các card mạng ảo nội bộ, để peer thử đúng các đường khả thi.
- **Phụ thuộc**: US-019, US-009.
- **AC**:
  1. **[H]** *Given* máy có IP LAN, IPv6 public và reflexive IPv4, *When* agent khởi động/đổi mạng, *Then* đẩy lên Control danh sách `endpoints[]` kèm nguồn (`lan`/`ipv6`/`reflexive`) trong ≤ 2 s sau khi STUN xong.
  2. **[E]** *Given* interface là chính adapter tunnel, địa chỉ thuộc dải overlay, **hoặc các virtual/bridge adapter cục bộ phổ biến** (`docker0`, `br-*`, `veth*`, `virbr*`, `cni*`, card ảo WSL/Hyper-V, **và trên macOS: `utun*` (kể cả của iCloud Private Relay/VPN khác), `awdl0`, `llw0`, `bridge*`, `anpi*`, `gif*`, `stf*`, `vmnet*`/`vboxnet*`, `lo0`** — danh sách lọc cấu hình được), *When* thu thập, *Then* **không** đưa vào `endpoints[]` (chống routing loop và tránh quảng bá IP container nội bộ vô nghĩa lên Netmap).
  3. **[E]** *Given* hai máy cùng LAN, *When* chọn đường, *Then* thứ tự ưu tiên LAN > IPv6 public > IPv4 reflexive > relay.
  4. **[F]** *Given* endpoint chứa địa chỉ link-local/loopback/multicast/unspecified, *When* công bố hoặc nhận từ peer, *Then* bị loại bỏ.

### US-021 — Hole punching đồng thời có xác thực mật mã & chống phát lại (Authenticated Disco)
- **Epic**: EP-04 · **SP**: 8 · **MoSCoW**: Must · **Trace**: REL-05, SEC-02, PERF-05, §4.3
- **Story**: Là *người dùng thiết bị*, tôi muốn hai máy sau NAT tự đục lỗ bằng các bản tin dò đường đã xác thực mật mã, để kết nối P2P nhanh mà kẻ tấn công cùng mạng Wi-Fi công cộng không thể giả mạo `Pong` đầu độc đường đi.
- **Phụ thuộc**: US-009, US-020, US-024..026.
- **AC**:
  1. **[H]** *Given* A và B đều sau Easy NAT (EIM), *When* có traffic đầu tiên A→B, *Then* traffic đi qua relay ngay (≤ 1 s) rồi A, B trao đổi tín hiệu `CallMeMaybe`-lite và bắn **đồng thời** disco `Ping` tới mọi endpoint ứng viên của nhau — mọi gói điều khiển đường đi (`Ping`/`Pong`/`CallMeMaybe`) đều được **xác thực mật mã gắn với danh tính/`disco_key` của peer trong Netmap kèm mã giao dịch ngẫu nhiên (`tx_id`/nonce từ CSPRNG)** — và nâng cấp sang **direct** trong **P95 ≤ 5 s** (mục tiêu ≤ 3 s) (PERF-05).
  2. **[H]** *Given* `Ping`/`Pong` hợp lệ thành công trên nhiều đường, *When* chọn đường, *Then* agent chỉ chấp nhận `Pong` đã xác thực mật mã khớp đúng `tx_id` của `Ping` vừa gửi đi trong cửa sổ hiệu lực ngắn, chọn đường có RTT tốt nhất theo thứ tự ưu tiên `US-020` và giữ relay làm dự phòng.
  3. **[E]** *Given* gói disco và gói tunnel chạy chung trên một socket UDP, *When* nhận gói, *Then* phân tách đúng bằng tiền tố nhận dạng + kiểm tra độ dài chặt chẽ; 0 gói disco lọt vào tunnel, 0 gói tunnel bị hiểu nhầm là disco, không panic khi fuzz $10^5$ gói ngẫu nhiên/đột biến.
  4. **[F]** *Given* cả hai phía đều là hard NAT (Port-Dependent), *When* đục lỗ thất bại sau ≤ 10 s, *Then* **ở lại relay**, không retry dồn dập: dò lại theo backoff (tối thiểu 30 s → trần 5 phút) và vẫn thông traffic (A-10).
  5. **[F]** *Given* gói `Ping`/`Pong`/`CallMeMaybe` mang khóa nguồn không thuộc Netmap hiện hành, sai xác thực mật mã, hoặc `Pong` mang `tx_id` lạ/phát lại (replay — ví dụ kẻ tấn công trên cùng Wi-Fi bắn `Pong` giả với `RTT = 1 ms`), *When* nhận, *Then* agent **bỏ qua im lặng** (không phản hồi, **không** cập nhật endpoint WireGuard của peer) và đếm lỗi — chống triệt để Endpoint Poisoning / Blackhole DoS và khuếch đại UDP.
  6. **[N]** Thu thập timestamp (disco, chuyển đường) trong log để đo PERF-05 trong 20 lần chạy/cặp NAT.

### US-022 — Phát hiện peer chết & chuyển mạch Direct ↔ Relay (keepalive on-demand)
- **Epic**: EP-04 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-05, PERF-06, PERF-10
- **Story**: Là *người dùng di động*, tôi muốn khi đường direct chết thì traffic tự chuyển sang relay trong vài giây, tự quay lại direct khi thông và tự nghỉ keepalive khi rảnh lâu, để kết nối không treo mà vẫn tiết kiệm pin/băng thông nền.
- **Phụ thuộc**: US-021, US-026.
- **AC**:
  1. **[H]** *Given* đường direct đang chạy có traffic ứng dụng, *When* gửi heartbeat disco mỗi 5–10 s và mất N=3 pong hợp lệ liên tiếp (hoặc không có handshake mới trong ≈ `REKEY_TIMEOUT`), *Then* chuyển lưu lượng sang relay ngay.
  2. **[N]** *Given* chặn UDP giữa 2 node bằng firewall lúc `ping -i 0.2`, *When* đo thời gian mất liên lạc, *Then* **P95 ≤ 10 s** (mục tiêu ≤ 5 s) (PERF-06) rồi ping thông lại qua relay.
  3. **[H]** *Given* đường direct được mở lại, *When* dò nền thành công, *Then* nâng cấp lại direct mà không rớt tunnel (0 gói mất liên quan đến chuyển đổi, hoặc ≤ 2 gói).
  4. **[E]** *Given* đường direct không còn lưu lượng ứng dụng, *When* mới rảnh trong cửa sổ giữ nóng cấu hình được (mặc định vài phút, vd. 3–5 phút), *Then* gửi keepalive ≈ 25 s để giữ NAT mapping; *When* rảnh vượt quá ngưỡng đó, *Then* **tạm nghỉ keepalive 25 s (on-demand)** và tự động dựng lại ngay khi có gói ứng dụng mới (đi relay ≤ 1 s rồi nâng cấp direct — có tùy chọn giữ persistent keepalive cố định cho server headless nếu bật), đảm bảo băng thông nền trung bình ≤ 1 KB/s (`GNFR-07`).
  5. **[F]** *Given* relay cũng không khả dụng, *When* direct chết, *Then* `status` hiển thị "no path", agent tiếp tục thử lại theo backoff (US-034), không crash, không busy-loop (CPU ≤ 5% của 1 core).

### US-023 — CLI `netcheck`
- **Epic**: EP-04 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: OPS-04
- **Story**: Là *chủ mạng*, tôi muốn kiểm tra nhanh mạng hiện tại cho phép P2P hay không, để hiểu vì sao đang đi relay.
- **Phụ thuộc**: US-019.
- **AC**:
  1. **[H]** *When* chạy `netcheck`, *Then* báo trong ≤ 10 s: UDP ra ngoài được/không, STUN OK, phân loại NAT mapping theo đúng khả năng cấu hình STUN hiện có (`Port-Dependent / hard NAT` vs `EIM/ADM` khi chỉ có 1 IP VPS, hoặc phân tách đầy đủ `EIM`/`ADM`/`APDM` khi có cấu hình STUN phụ khác IP — khớp `US-019 AC2`), độ trễ tới relay, có IPv6 không.
  2. **[E]** *Given* mạng 4G CGNAT hoặc lab mô phỏng Port-Dependent Mapping (APDM), *When* chạy `netcheck`, *Then* báo đúng `Port-Dependent ("hard NAT")` và ghi chú rõ nếu chỉ đang dùng 1 IP STUN.
  3. **[F]** *Given* UDP bị chặn, *When* chạy, *Then* báo "UDP blocked, relay-only" thay vì treo.
  4. **[E]** *Given* cổng TCP Control/Relay đã cấu hình (mặc định 443; vd. `8443`), *When* chạy `netcheck`, *Then* kiểm tra và báo **khả năng tới `IP:cổng TCP` và cổng UDP STUN đã cấu hình**; nếu cổng khác `443` không tới được trong khi mạng nghi chỉ cho phép 80/443, in gợi ý rõ "không tới được Control/Relay `IP:<cổng>` — mạng có thể chỉ cho phép 443; cân nhắc đặt dịch vụ ở cổng 443" (REL-06(b), OPS-04).

---

## 6. EP-05 — Chuyển tiếp Relay qua VPS & Chống lạm dụng

> Mục tiêu: đường cuối luôn thông (TLS 443 ở cả chế độ Standalone lẫn sau Reverse Proxy), VPS không đọc được nội dung, không nghẽn chéo giữa các peer, người lạ không dùng ké. (Persona P2, P3)

### US-024 — Relay endpoint trên cổng TCP cấu hình được (mặc định 443; Standalone hoặc sau Reverse Proxy) & xác thực khóa node
- **Epic**: EP-05 · **SP**: 8 · **MoSCoW**: Must · **Trace**: REL-06, SEC-04, SEC-06, SEC-07, SEC-02, SEC-15
- **Story**: Là *người dùng di động*, tôi muốn agent mở kết nối lâu dài tới relay qua **cổng TCP đã cấu hình của VPS (mặc định 443, đổi được sang `8443`…)** (dù VPS chạy độc lập hay đang đứng sau Nginx/Caddy có sẵn), để mạng chỉ cho phép 80/443 vẫn dùng được khi relay đặt ở cổng 443 mà không phá các web cá nhân trên VPS.
- **Phụ thuộc**: US-003, US-001.
- **AC**:
  1. **[H]** *Given* mạng client chặn toàn bộ UDP và chỉ cho phép TCP 443, *When* agent kết nối tới `IP|domain:443` của VPS (cổng mặc định `443`; **bộ AC này được chạy lặp lại với cổng tùy chọn như `8443`** — GNFR-11, `SEC-04(e)`), *Then* hoàn tất kết nối + chứng minh sở hữu khóa node (bằng random challenge/nonce từ server theo `US-003`) trong ≤ 3 s ở **cả hai chế độ triển khai trên VPS**: **(a) Standalone TLS 443** (dịch vụ tự giữ TLS 443, dùng chung cổng với Control qua phân luồng path/ALPN/HTTP Upgrade) và **(b) Sau Reverse Proxy sẵn có** (Nginx/Caddy… kết thúc TLS 443 và chuyển tiếp HTTP + Upgrade/WebSocket vào cổng loopback/socket nội bộ của dịch vụ).
  2. **[F]** *Given* client chưa đăng ký / khóa không trong netmap / đã thu hồi, *When* xác thực, *Then* bị từ chối; không tạo phiên relay (liên quan US-027).
  3. **[F]** *Given* chứng chỉ giả (MITM/Captive Portal), *When* kết nối, *Then* agent từ chối gửi secret và thử lại theo `US-034 AC4` (như US-003).
  4. **[E]** *Given* kết nối relay idle, *When* không có frame, *Then* gửi heartbeat ≤ 30 s để tránh bị middlebox/reverse proxy ngắt; mất kết nối > 60 s kích hoạt reconnect backoff.
  5. **[E]** *Given* cùng node mở kết nối relay thứ hai, *When* xác thực hợp lệ, *Then* kết nối cũ bị thay thế (một phiên hoạt động/node), tránh rò rỉ phiên.
  6. **[N]** Relay (idle, 20 node đăng nhập) dùng RAM < 64 MB cùng Control+STUN (GNFR-04).
  7. **[F]** *Given* mạng client **chỉ cho outbound TCP 80/443** và relay đang đặt ở cổng khác `443` (vd. `8443`), *When* agent không tới được `IP:8443`, *Then* `status`/`netcheck`/log báo rõ nguyên nhân "không tới được Control/Relay `IP:8443` — mạng có thể chỉ cho phép 443" thay vì treo im lặng (REL-06(b)); *Given* cùng mạng đó nhưng relay ở `443`, *Then* kết nối thành công ≤ 3 s. Đây là **giới hạn đã biết** ghi trong Runbook (`US-059`), không phải lỗi.
  8. **[E]** *Given* VPS đổi cổng TCP qua `US-074`, *When* relay nghe song song cổng cũ + mới trong giai đoạn chuyển tiếp, *Then* phiên relay hiện có không bị cắt đột ngột; agent chuyển sang cổng mới theo `relay_map` (`US-009 AC6`) và chỉ sau giai đoạn chuyển tiếp cổng cũ mới đóng.

### US-025 — Chuyển tiếp mù gắn `src_pubkey` xác thực & hàng đợi không chặn theo đích
- **Epic**: EP-05 · **SP**: 5 · **MoSCoW**: Must · **Trace**: §4.4, SEC-02, SEC-07, PERF-11
- **Story**: Là *chủ mạng*, tôi muốn relay chỉ chuyển nguyên gói đã mã hóa kèm danh tính nguồn do chính relay chứng thực và cô lập hàng đợi từng đích, để VPS không đọc được nội dung, không ai giả mạo nguồn qua relay và một máy nghẽn mạng không làm treo các máy khác.
- **Phụ thuộc**: US-024.
- **AC**:
  1. **[H]** *Given* A và B cùng đã xác thực phiên relay (`US-024`), *When* A gửi frame `{dest_pubkey=B, payload}`, *Then* Relay chuyển cho B frame `{src_pubkey=A, payload}` trong đó **`src_pubkey=A` do chính Relay gắn từ phiên đã xác thực của A** (không tin trường nguồn do client tự khai — chống giả mạo nguồn qua Relay); B nhận đúng `payload` bit-by-bit; Relay không giải mã và không giữ bất kỳ private key client nào.
  2. **[F]** *Given* frame gửi tới `dest_pubkey` không đang kết nối hoặc không thuộc Netmap hợp lệ, *When* Relay nhận, *Then* **drop** im lặng (có đếm metric), không gây lỗi cho phiên của người gửi.
  3. **[E]** *Given* kích thước `payload` vượt quá ngân sách MTU/giới hạn frame tối đa, *When* nhận, *Then* drop và đếm lỗi; Relay giới hạn kích thước frame cố định, không cấp phát bộ nhớ vô hạn.
  4. **[E]** *Given* bắt gói tại VPS, *When* kiểm tra nội dung payload, *Then* chỉ thấy ciphertext của tunnel (không thấy plaintext ICMP/TCP của overlay).
  5. **[N]** *Given* ≥ 2 luồng relay đồng thời ở hạn mức, *When* chạy `iperf3` qua relay, *Then* RAM Control+Relay không vượt trần PERF-01 + 64 MB (PERF-11).
  6. **[F]** *Given* A gửi lưu lượng qua Relay đồng thời tới B (đường TCP tới B bị nghẽn/đọc chậm) và C (mạng bình thường) trên cùng kết nối TLS 443 của A, *When* **hàng đợi giới hạn kích thước cố định** dành riêng cho đích B trên Relay bị đầy, *Then* Relay thực hiện **drop không chặn (non-blocking drop)** đối với gói về B và tăng metric, **tuyệt đối không ghi chặn (blocking write)** làm treo luồng đọc từ A hay ảnh hưởng độ trễ/thông lượng giữa A và C (chống Cross-Peer Head-of-Line Blocking và TCP-over-TCP meltdown).

### US-026 — Agent: luôn có đường đi, khởi đầu qua relay rồi nâng cấp direct
- **Epic**: EP-05 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-05, REL-06, PERF-05
- **Story**: Là *người dùng thiết bị*, tôi muốn kết nối ra lệnh ngay lập tức dù chưa đục lỗ xong, để không phải chờ.
- **Phụ thuộc**: US-024, US-025, US-014/US-015.
- **AC**:
  1. **[H]** *Given* agent đã kết nối relay, *When* gửi packet đầu tiên đến peer chưa có direct, *Then* gói đi relay trong ≤ **1 s** (PERF-05).
  2. **[H]** *Given* agent nhận frame `{src_pubkey, payload}` từ relay, *When* kiểm tra `src_pubkey` thuộc peer hợp lệ trong Netmap hiện hành, *Then* đưa `payload` vào tunnel tương ứng với peer đó (ghi nhận nguồn "relay"); nếu `src_pubkey` lạ/đã bị gỡ thì drop ngay.
  3. **[F]** *Given* mạng chặn UDP hoàn toàn (lab), *When* ping mọi cặp node, *Then* 100% cặp ping được qua relay (REL-06).
  4. **[E]** *Given* đường relay và direct cùng khả dụng, *When* có gói trùng, *Then* tunnel xử lý trùng lặp bình thường (không rớt phiên); không lặp vô hạn.

### US-027 — Relay chỉ phục vụ node hợp lệ & giới hạn băng thông (chống lạm dụng)
- **Epic**: EP-05 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-07, PERF-11, pitfall 5.6.2
- **Story**: Là *chủ mạng*, tôi muốn người lạ không thể dùng ké relay và mỗi node bị giới hạn băng thông, để bảo vệ quota/chi phí VPS.
- **Phụ thuộc**: US-024, US-013.
- **AC**:
  1. **[F]** *Given* client không đăng ký (biết domain/URL relay), *When* kết nối relay và gửi dữ liệu, *Then* bị từ chối trước khi chuyển tiếp bất kỳ byte nào; ghi audit/log kèm IP nguồn.
  2. **[N]** *Given* hạn mức mặc định **20 Mbps/node** (cấu hình được) và trần tổng của relay, *When* một node gửi vượt hạn mức qua relay, *Then* bị throttle ≈ hạn mức (sai số ±10%) mà các node khác không bị ảnh hưởng > 10%.
  3. **[H]** *Given* node bị thu hồi (US-029), *When* control đẩy lệnh, *Then* kết nối relay của node bị đóng trong **≤ 5 s** (SEC-07b).
  4. **[E]** *Given* tổng băng thông relay chạm trần, *When* node mới gửi, *Then* áp dụng chia sẻ công bằng; `status`/metrics cho thấy "relay throttled".
  5. **[F]** *Given* 50 kết nối relay xác thực lỗi/giây từ một IP, *When* vượt ngưỡng (US-042), *Then* IP bị chặn tạm và relay vẫn phục vụ node hợp lệ bình thường.

### US-028 — Kịch bản nghiệm thu: mạng chặn UDP / chỉ cho 443
- **Epic**: EP-05 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-06, PERF-06
- **Story**: Là *người dùng di động*, tôi muốn có bằng chứng tự động rằng mọi cặp node vẫn kết nối khi UDP bị chặn, để tin tưởng dùng ở khách sạn/công ty.
- **Phụ thuộc**: US-026, US-057.
- **AC**:
  1. **[H]** *Given* lab chặn UDP egress (trừ DNS), *When* chạy bộ test kết nối 5 node (≥ 10 cặp), *Then* 10/10 cặp ping thành công qua relay, `status` hiển thị `relay` cho cả 10 cặp.
  2. **[F]** *Given* lab chặn cả TCP ngoài 443, *When* chạy, *Then* vẫn thành công.
  3. **[E]** *Given* lab dùng proxy/NAT thay đổi IP mỗi 30 s, *When* chạy 10 phút, *Then* mọi cặp phục hồi trong P95 ≤ 15 s sau mỗi lần đổi.
  4. **[F]** *Given* lab chỉ cho outbound TCP 80/443 và relay đặt ở cổng tùy chọn `8443`, *When* chạy bộ test, *Then* các node trong lab báo rõ "không tới được Control/Relay `IP:8443` — mạng có thể chỉ cho phép 443" (không treo); *When* cấu hình lại relay ở `443` (hoặc sau Reverse Proxy 443), *Then* 10/10 cặp thành công — kiểm chứng đúng ghi chú trung thực `REL-06`.

---

## 7. EP-06 — Vòng đời thiết bị: Thu hồi / Key Expiry & Tách rời Control–Data Plane

> Mục tiêu: mất laptop xử lý được ngay; control chết vẫn có mạng; lỗi môi trường tạm thời không bao giờ khóa chết máy từ xa. (Persona P1, P2, P3)

### US-029 — Thu hồi thiết bị tức thì (server-side)
- **Epic**: EP-06 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-08, SEC-07, SEC-09, SEC-14
- **Story**: Là *chủ mạng*, tôi muốn thu hồi một thiết bị bị mất ngay lập tức, để kẻ nhặt được máy không vào được mạng nhà.
- **Phụ thuộc**: US-009, US-012, US-027.
- **AC**:
  1. **[H]** *Given* node L online, *When* admin chạy `node revoke L` qua kênh quản trị cục bộ (`SEC-14`), *Then* Control: xóa L khỏi netmap của **mọi** node, tăng `netmap_version`, ngắt kết nối relay/control của L, ghi audit (actor/UID, node — thực thi ngay trong RAM kể cả khi đĩa đầy theo `US-013 AC4`).
  2. **[N]** *Given* Control online và 20 agent, *When* thu hồi, *Then* sau **P95 ≤ 10 s** không peer nào còn handshake được với L (kiểm tra bằng thử handshake/ping từ mỗi peer), relay ngắt L trong ≤ 5 s.
  3. **[E]** *Given* L đang offline lúc thu hồi, *When* L online lại, *Then* L bị Control từ chối (trả mã `node_revoked` trong kênh TLS hợp lệ — `US-034 AC5`), peer khác không bao giờ nhận L trở lại.
  4. **[E]** *Given* thu hồi node đã bị thu hồi / không tồn tại, *When* chạy lệnh, *Then* idempotent hoặc lỗi rõ ràng, không tác dụng phụ.
  5. **[F]** *Given* IP của node bị thu hồi, *When* cấp cho node mới, *Then* chỉ cấp lại sau thời gian cách ly cấu hình được (mặc định 24 h) để tránh nhầm danh tính trong log/ACL.

### US-030 — Agent gỡ peer bị thu hồi khỏi data plane & cắt tunnel đang sống
- **Epic**: EP-06 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-08, pitfall 5.6.3
- **Story**: Là *chủ mạng*, tôi muốn các máy còn lại ngắt ngay phiên đang chạy với máy bị thu hồi, để không còn đường hầm "đang sống" sót lại.
- **Phụ thuộc**: US-029, US-010.
- **AC**:
  1. **[H]** *Given* A đang có phiên SSH qua tunnel với L, *When* nhận netmap không còn L, *Then* A gỡ L khỏi data plane trong ≤ 2 s (phiên SSH đứt, không gói nào tiếp tục tới L).
  2. **[E]** *Given* L giữ khóa session cũ, *When* L tiếp tục bắn gói tới A trong 180 s, *Then* A không nhận (không còn peer tương ứng); *Given* L gửi qua relay, *Then* relay drop (không phục vụ node bị thu hồi).
  3. **[F]** *Given* A offline lúc thu hồi, *When* A online và nhận netmap mới, *Then* L bị gỡ ngay ở lần áp dụng netmap đầu tiên; **trước đó** (nếu Control chết cùng lúc) xem giới hạn tại US-033.

### US-031 — Node key expiry (hết hạn khóa) & đăng ký lại bằng cặp khóa mới
- **Epic**: EP-06 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-08, SEC-03, REL-01
- **Story**: Là *chủ mạng*, tôi muốn khóa node hết hạn sau một thời gian (mặc định 180 ngày), có thể tắt cho server tin cậy, và khi đăng ký lại bắt buộc sinh khóa mới với pre-auth key trói đích danh để giảm rủi ro lộ khóa mà không ai chiếm đoạt được tên/IP của máy khác.
- **Phụ thuộc**: US-002, US-009, US-012.
- **AC**:
  1. **[H]** *Given* node có `key_expiry` = hôm nay, *When* tới hạn, *Then* Control loại node khỏi netmap các peer và trả mã tường minh `node_key_expired` trên kênh TLS hợp lệ; agent dừng retry liên tục (`US-034 AC5`) và hiện lỗi rõ "node key expired, cần đăng ký lại bằng pre-auth key mới".
  2. **[E]** *Given* node đặt `expiry = never` (server tin cậy), *When* quá 180 ngày, *Then* node không hết hạn; hành động đặt `never` được ghi audit.
  3. **[E]** *Given* node sắp hết hạn trong < 7 ngày, *When* `status`/`node list` được gọi, *Then* hiển thị cảnh báo (cho US-049).
  4. **[F]** *Given* Control **đang offline** đúng lúc key hết hạn, *When* hết hạn, *Then* peers (đã có cache) **không** tự cắt mà áp dụng chính sách grace tối đa 24 h cấu hình được (ghi rõ rủi ro) — quá grace thì cắt khi Control sống lại (tránh mất mạng do VPS chết như pitfall T5).
  5. **[H]** *Given* node `X` đã hết hạn cần đăng ký lại mà vẫn **giữ nguyên tên và Overlay IP cũ**, *When* admin cấp `pre-auth key` đã trói đích danh cho `X` trên server (`preauthkey create --for X` hoặc thao tác xác nhận quản trị trên server) và agent đăng ký lại (hỗ trợ `--authkey-file`/`stdin`/env), *Then* client **bắt buộc sinh cặp khóa node mới** (vô hiệu hóa hoàn toàn khóa cũ trên Control/Relay và mọi peer), gắn khóa mới vào tên + Overlay IP cũ của `X`, và ghi audit.
  6. **[F]** *Given* một `pre-auth key` thông thường (không được admin trói `--for X` trên server), *When* client tự truyền tham số đòi thay thế hoặc trùng tên/IP của node `X` đang tồn tại, *Then* Control **từ chối** và ghi cảnh báo audit (cấm dùng cờ `--replace` tự do từ phía client với key thường để chống chiếm đoạt danh tính node).

### US-032 — `rotate-key`: xoay khóa node thủ công (giữ tên & IP)
- **Epic**: EP-06 · **SP**: 5 · **MoSCoW**: **Should** · **Trace**: SEC-08 (Key Rotation), P2 trong benchmark
- **Story**: Là *chủ mạng*, tôi muốn xoay khóa của một thiết bị khi nghi ngờ lộ khóa mà không phải đổi IP/tên hay làm lộ pre-auth key trên dòng lệnh, để khôi phục an toàn nhanh.
- **Phụ thuộc**: US-004, US-029.
- **AC**:
  1. **[H]** *Given* admin tạo key one-time trói đích danh cho node X (`preauthkey create --for X`), *When* agent X chạy `rotate-key` truyền key qua `--authkey-file <path>`, `stdin` hoặc biến môi trường (không lộ key trên `ps aux` / shell history), *Then* sinh cặp khóa mới tại client, đăng ký, giữ nguyên tên + Overlay IP; **public key cũ bị vô hiệu ngay** (tunnel/relay của khóa cũ bị cắt ≤ 10 s).
  2. **[F]** *Given* rotate thất bại giữa chừng (mất mạng), *When* agent khởi động lại, *Then* giữ khóa cũ còn hiệu lực nếu Control chưa xác nhận; không để node ở trạng thái mất khóa.
  3. **[E]** *Given* khóa cũ đã rotate, *When* kẻ giữ khóa cũ kết nối relay/control, *Then* bị từ chối.

### US-033 — Tách rời Control/Data Plane: cache Netmap phân quyền chặt & tunnel sống khi Control chết
- **Epic**: EP-06 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-01, SEC-01, PERF-12
- **Story**: Là *người dùng thiết bị*, tôi muốn khi VPS restart hay mất mạng thì kết nối P2P đang chạy không đứt và khởi động lại agent vẫn nối lại được từ cache an toàn, để SSH/copy file vẫn tiếp tục.
- **Phụ thuộc**: US-009, US-010, US-019, US-021.
- **AC**:
  1. **[H]** *Given* 5 node đang P2P direct, *When* dừng Control 30 phút, *Then* ping giữa các node đang direct **0% mất gói do control** (chỉ chấp nhận mất do mạng); rekey/keepalive tiếp tục.
  2. **[H]** *Given* Control đang offline, *When* agent khởi động lại, *Then* agent nạp Netmap từ **cache trên đĩa** (nếu còn trong hạn key & grace), **bind lại đúng cổng UDP cục bộ đã lưu bền (`US-019 AC1`)**, và dựng lại được tunnel P2P direct (khi NAT mapping/LAN của peer còn hợp lệ) hoặc qua Relay (nếu Relay còn sống).
  3. **[E]** *Given* cache không tồn tại hoặc không vượt qua kiểm tra toàn vẹn (bị cắt cụt/sai checksum), *When* Control offline lúc agent khởi động, *Then* agent từ chối cache hỏng, ở trạng thái "chờ control" với backoff, không crash; ghi rõ trong `status`.
  4. **[E]** *Given* cache chứa peer đã bị thu hồi **trong lúc Control offline**, *When* Control sống lại, *Then* netmap mới loại peer đó ngay (giới hạn rủi ro được ghi rõ trong runbook: thu hồi không hiệu lực khi Control chết).
  5. **[F]** *Given* Control trở lại sau 10 phút với 20 agent, *When* kết nối lại, *Then* thời điểm kết nối lại **phân bố đều** (backoff+jitter) — không bão kết nối đồng bộ (đỉnh ≤ 30% agent trong 1 s).
  6. **[F]** *Given* thư mục và tệp cache Netmap trên đĩa, *When* kiểm tra phân quyền hệ điều hành, *Then* chỉ cho phép `root` trên Linux (thư mục `0700`, tệp `0600`) hoặc `SYSTEM` + `Administrators` trên Windows, hoặc **`root:wheel` trên macOS (thư mục `0700`, tệp `0600`)** đọc/ghi — ngăn chặn user thường trên máy sửa cache để chèn peer giả khi offline.

### US-034 — Reconnect với Exponential Backoff + Jitter, không tự khóa chết khi lỗi TLS tạm thời
- **Epic**: EP-06 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-04, REL-07, SEC-04
- **Story**: Là *chủ mạng*, tôi muốn agent thử lại kết nối tới VPS thông minh và tự phục hồi sau các lỗi mạng/Captive Portal/lệch giờ tạm thời, để VPS sống lại không bị bão kết nối và máy headless ở xa không bao giờ bị tự khóa chết vĩnh viễn.
- **Phụ thuộc**: US-003, US-009, US-024.
- **AC**:
  1. **[H]** *Given* kết nối mạng tới Control/Relay/STUN thất bại (timeout, từ chối kết nối, lỗi 5xx), *When* thử lại, *Then* dùng Exponential Backoff base 1 s, hệ số 2, trần 60 s, **full jitter**; reset backoff khi kết nối ổn định > 1 phút.
  2. **[N]** *Given* VPS chết 10 phút với 20 agent, *When* sống lại, *Then* thời điểm kết nối lại của 20 agent phân bố trải trong cửa sổ ≥ 20 s (độ lệch chuẩn ≥ 5 s); không có > 6 agent kết nối trong cùng 1 s.
  3. **[F]** *Given* mọi I/O mạng, *When* thao tác không phản hồi, *Then* timeout: connect ≤ 10 s; đọc stream có heartbeat ≤ 60 s (GNFR-03); không có I/O chặn vô hạn (kiểm tra bằng test chèn độ trễ vô hạn).
  4. **[F]** *Given* lỗi xác minh TLS/chứng chỉ (ví dụ: Wi-Fi khách sạn có **Captive Portal** chặn cổng 443, thiết bị headless vừa bật lại sau mất điện **trước khi NTP đồng bộ giờ**, hoặc chứng chỉ VPS **trễ gia hạn**), *When* xảy ra, *Then* agent không gửi bất kỳ secret nào (`US-003 AC2`), ghi log rõ nguyên nhân, nhưng **BẮT BUỘC tiếp tục thử lại** theo Exponential Backoff + Jitter có trần thưa hơn (vd. trần **5 phút**) **VÀ kích hoạt thử lại ngay lập tức** khi nhận sự kiện đổi mạng hoặc nhảy đồng hồ hệ thống (`US-035`, `US-036`) — tuyệt đối **không dừng thử lại vĩnh viễn** làm chết thiết bị từ xa (*Fleet Bricking*). Trường hợp **`pin mismatch`** (kẻ MITM hoặc server vừa xoay khóa mà chưa công bố pin kế tiếp) cũng áp dụng đúng quy tắc: không gửi secret, log rõ, tiếp tục thử lại thưa (trần 5 phút) — tự khôi phục khi server trình pin hợp lệ trong tập pin đã công bố (`US-047`) hoặc khi admin máy client chạy `mesh set` cục bộ (`US-074 AC5`).
  5. **[E]** *Given* kênh TLS tới Control đã xác thực chứng chỉ **hợp lệ**, *When* nhận mã từ chối danh tính tường minh từ server (`node_revoked` hoặc `node_key_expired`), *Then* agent mới **dừng thử lại tự động** và báo lỗi cụ thể trong `status`/log (không hammer VPS).

---

## 8. EP-07 — Tự khôi phục: Đổi mạng, Sleep/Wake, xung đột dải IP

> Mục tiêu: laptop di động không phải "khởi động lại VPN" thủ công. (Persona P3)

### US-035 — macOS (+ Linux VPS-node/lab): phát hiện đổi mạng, sleep/wake & phục hồi (rebind → STUN → republish → relay trong lúc chờ)
- **Epic**: EP-07 · **SP**: 8 *(tái ước lượng 5→8: macOS là client roaming chính + thêm Linux VPS/lab, hai cơ chế sự kiện OS khác nhau)* · **MoSCoW**: Must · **Trace**: REL-07, REL-09, PLAT-05, PLAT-06, PERF-07
- **Story**: Là *người dùng di động (MacBook)*, tôi muốn khi đổi Wi-Fi sang hotspot 4G hoặc mở nắp sau khi sleep thì kết nối tự phục hồi mà không phải khởi động lại daemon, để không phải làm gì; *VPS-node Linux và lab dùng cùng chuỗi phục hồi qua sự kiện `netlink`.*
- **Phụ thuộc**: US-019, US-020, US-022, US-026, US-034, US-060 (macOS data plane), US-073 (daemon macOS).
- **AC**:
  1. **[H]** *Given* agent **macOS** đang chạy (daemon `launchd`, `US-073`), *When* nhận sự kiện thay đổi interface/địa chỉ/route từ OS (KN: routing socket `PF_ROUTE` hoặc `SCDynamicStore`/`NWPathMonitor` — Architect chốt Gate 2), *Then* đánh thức ngay bộ đếm retry Control/Relay nếu đang chờ backoff (kể cả sau lỗi TLS/Captive Portal — `US-034 AC4`) và thực hiện chuỗi: rebind socket UDP (ưu tiên cổng cũ đã lưu bền, retry backoff 0.5→8 s nếu interface chưa có IP), STUN lại, đẩy endpoints mới lên Control, disco ping lại; trong lúc chờ dùng relay.
  2. **[N]** *Given* kịch bản chuyển Wi-Fi → hotspot 4G **trên MacBook (script đổi interface/route trên máy Mac hoặc runner macOS, lặp 20 lần)** kết hợp **2–3 lần đóng nắp/sleep ≥ 4 phút (> 180 s) trên MacBook thật có biên bản** (macOS không giả lập được trong lab container Linux — GNFR-12), *When* đo thời gian từ khi mạng mới có IP đến khi ping overlay thông (qua relay hoặc direct), *Then* **P95 ≤ 15 s** (PERF-07) trên tập 20 lần và 100% lần kiểm chứng phần cứng thật ≤ 15 s; 0 lần phải khởi động lại agent thủ công.
  3. **[E]** *Given* phát hiện "nhảy thời gian" (wall-clock jump > 30 s so với monotonic clock sau suspend/resume hoặc sau khi NTP đồng bộ giờ), *When* xảy ra, *Then* buộc thử lại ngay kênh Control/Relay nếu đang chờ (`US-034 AC4`) và kiểm tra lại toàn bộ đường đi data plane (không chờ hết 180 s `REJECT_AFTER_TIME`).
  4. **[F]** *Given* rebind khi interface chưa sẵn sàng, *When* bind thất bại, *Then* retry theo backoff, **không** để agent ở trạng thái treo báo "Connected" giả (trạng thái `status` phản ánh đúng "rebinding"/"no path").
  5. **[E]** *Given* sự kiện thay đổi mạng dồn dập (flapping > 10 lần/10 s), *When* nhận, *Then* gộp (debounce ≥ 1 s) để không bão STUN/Control.
  6. **[H]** *Given* MacBook vào sleep rồi wake (đóng/mở nắp), *When* hệ thống phát sự kiện nguồn "system has powered on" (KN: `IORegisterForSystemPower`/`IOPMrootDomain`) hoặc agent phát hiện nhảy đồng hồ khi bỏ lỡ sự kiện, *Then* thực hiện đúng chuỗi phục hồi của AC1 và `status` không bao giờ báo "Connected" giả trong lúc đang rebind (PLAT-05).
  7. **[F]** *Given* interface mặc định đổi (Wi-Fi ↔ Ethernet/hotspot) trên macOS, *When* rebind, *Then* socket điều khiển/STUN/disco/tunnel **được ràng lại vào interface vật lý mặc định mới trước khi gửi gói** và không có gói nào đi vào `utunN` (REL-09, `US-016`); *Given* mạng mới có CGNAT 100.64/10, *Then* cảnh báo xung đột theo `US-037` (nếu bật).
  8. **[H]** *Given* **Linux VPS-node/lab**, *When* nhận sự kiện `netlink` (route/addr/link) hoặc đổi IP của VPS/container lab, *Then* thực hiện cùng chuỗi AC1 (không cần khởi động lại agent) — kiểm tự động 20 vòng trong lab (`US-057`) với P95 ≤ 15 s.

### US-036 — Windows: phát hiện đổi mạng, power resume & phục hồi
- **Epic**: EP-07 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-07, PLAT-05, PERF-07
- **Story**: Như US-035 nhưng trên Windows (laptop di động của Lan).
- **Phụ thuộc**: US-015, US-019, US-020, US-022, US-026, US-034.
- **AC**:
  1. **[H]** *Given* agent chạy dạng service Windows, *When* nhận sự kiện thay đổi interface/route hoặc sự kiện power resume / nhảy đồng hồ từ OS, *Then* đánh thức ngay bộ đếm retry Control/Relay (`US-034 AC4`) và thực hiện chuỗi phục hồi như US-035 AC1.
  2. **[N]** *Given* bộ kiểm thử phục hồi sleep/wake gồm: **(a) 20 vòng kiểm thử tự động trong lab (`US-057`)** mô phỏng sự kiện OS power-resume + nhảy đồng hồ > 180 s (`REJECT_AFTER_TIME`) + xóa bảng NAT mapping, **kết hợp với (b) 2–3 lần kiểm chứng sleep/hibernate phần cứng thật ≥ 4 phút** (> 180 s) có biên bản, *When* đo thời gian tới khi ping overlay thông lại, *Then* **P95 ≤ 15 s** (PERF-07) trên tập tự động và 100% lần kiểm chứng phần cứng thật ≤ 15 s; 0 lần cần can thiệp thủ công.
  3. **[E]** *Given* đổi profile mạng (Public ↔ Private) hoặc VPN khác bật lên, *When* xảy ra, *Then* adapter tunnel vẫn hoạt động (rule firewall US-053 không mất) và lưu lượng điều khiển/mã hóa tới VPS vẫn không đi vào tunnel (US-016).
  4. **[F]** *Given* Wi-Fi vừa kết nối nhưng chưa có IP (DHCP chậm), *When* rebind, *Then* retry tới khi có IP (tối đa 60 s) rồi mới báo lỗi; không crash, không CPU > 5% core.

### US-037 — Cảnh báo xung đột dải overlay với interface vật lý (CGNAT 100.64/10)
- **Epic**: EP-07 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: REL-14, T33
- **Story**: Là *người dùng thiết bị*, tôi muốn agent cảnh báo khi dải overlay trùng với mạng vật lý của tôi, để tránh route sai.
- **Phụ thuộc**: US-008, US-014/US-015.
- **AC**:
  1. **[F]** *Given* lab giả lập interface vật lý `100.64.1.5/10` và dải overlay `100.64.0.0/10`, *When* agent khởi động hoặc đổi mạng, *Then* **không cài route chồng chéo**, in cảnh báo nêu rõ interface xung đột và cách khắc phục; `status` hiển thị trạng thái "overlay conflict".
  2. **[E]** *Given* không trùng, *When* khởi động, *Then* không cảnh báo (0 false positive trong 20 cấu hình mạng thường gặp: 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12).
  3. **[E]** *Given* xung đột chỉ xuất hiện khi chuyển sang mạng khác (4G CGNAT), *When* đổi mạng, *Then* cảnh báo xuất hiện và tự hết khi quay lại mạng không xung đột.

---

## 9. EP-08 — Tên máy nội bộ (MagicDNS-lite) & CLI chẩn đoán

> Mục tiêu: gọi máy bằng tên an toàn không gây vòng lặp DNS; biết ngay đang direct hay relay. (Persona P1, P3)

### US-038 — Quản lý tên máy bằng khối đánh dấu trong `hosts` file (chống vòng lặp DNS & giữ ACL đọc)
- **Epic**: EP-08 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PLAT-04, PLAT-06, REL-08, REL-09
- **Story**: Là *người dùng thiết bị*, tôi muốn gọi `ssh nas` hoặc `ssh nas.mesh.internal` thay vì gõ IP overlay mà không bao giờ làm hỏng DNS hệ thống hay gây vòng lặp mạng, để dùng thuận tiện và an toàn.
- **Phụ thuộc**: US-009.
- **AC**:
  1. **[H]** *Given* netmap có peer `nas`, `pc`, *When* agent áp dụng, *Then* file `hosts` có khối `# BEGIN mesh … # END mesh` ánh xạ Overlay IP tới tên đầy đủ kèm **hậu tố miền nội bộ riêng** (mặc định `<name>.mesh.internal` — cấu hình được, tránh `.local` của mDNS) bên cạnh tên ngắn `<name>` (tùy chọn bật/tắt); `ping nas.mesh.internal` và `ping nas` phân giải đúng; phần ngoài khối giữ nguyên byte-by-byte.
  2. **[E]** *Given* agent cập nhật file `hosts`, *When* thực hiện ghi, *Then*: (a) ưu tiên ghi nguyên tử (file tạm cùng thư mục rồi thay thế) để tắt đột ngột không bao giờ cắt cụt file; (b) **bảo toàn quyền đọc chuẩn của hệ thống và user** (`0644` `root` trên Linux; **`root:wheel 0644` trên macOS, nơi `/etc/hosts` là symlink tới `/private/etc/hosts` — ghi trên đường dẫn thật và giữ nguyên symlink, không thay bằng file thường**; giữ nguyên quyền `Read` cho `Users`, `NetworkService` / `Dnscache` trên Windows — không làm kế thừa ACL hẹp từ thư mục tạm của Service); (c) có **retry ngắn với backoff** (vd. ≤ 2 s) khi file `hosts` trên Windows bị `Dnscache`/AV khóa tạm; (d) xử lý an toàn trường hợp `/etc/hosts` là **bind-mount đơn lẻ** (`EBUSY`/`EXDEV`) trong container Linux (`US-057`) bằng ghi trực tiếp có khóa mà không văng lỗi.
  3. **[E]** *Given* agent tắt đột ngột (kill -9) rồi khởi động lại, *When* khởi động, *Then* khối được viết lại **đúng một lần**, không nhân bản.
  4. **[E]** *Given* dừng service/gỡ cài đặt, *When* hoàn tất, *Then* khối bị **xóa sạch** (REL-08).
  5. **[F]** *Given* tên peer chứa ký tự ngoài `[a-z0-9-]` (≤ 63 ký tự)/xuống dòng/khoảng trắng/`#` (vd. tên `evil\n1.2.3.4 bank.example` — kiểm cả ở server `US-004`/`US-012` lẫn agent, `SEC-10`), nằm trong **danh sách tên hệ thống cấm** (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`…), **hoặc trùng với chính hostname/domain trong URL của Control/Relay/STUN, hoặc có mục nào sẽ ánh xạ tới địa chỉ IP public của VPS đang làm Control/Relay/STUN** (khi kết nối bằng IP — chống tự chiếm đường tới server), *When* agent áp dụng vào `hosts`, *Then* agent **từ chối ghi mục đó** và log `WARN` — chặn tuyệt đối chiếm đoạt `localhost`/`wpad` và chặn vòng lặp DNS đẩy lưu lượng Control vào tunnel khi VPS là node (`US-056`).
  6. **[F]** *Given* vẫn không thể ghi `hosts` sau khi hết retry (file bị khóa cứng/chỉ-đọc), *When* xảy ra, *Then* log lỗi rõ ràng, tunnel data plane vẫn hoạt động bình thường (tên chỉ là tiện ích).
  7. **[H]** *Given* **macOS**, *When* agent vừa cập nhật khối `hosts`, *Then* agent **xả cache DNS** (KN: `dscacheutil -flushcache` + gửi `HUP` cho `mDNSResponder`) và `dscacheutil -q host -a name <node>.mesh.internal` trả đúng Overlay IP mới ngay (không chờ hết TTL); `/etc/hosts` vẫn là symlink tới `/private/etc/hosts`; **`scutil --dns` và `/etc/resolver/*` không đổi** so với trước khi cài (agent không ghi đè cấu hình DNS gốc).
  8. **[H]** *Given* **Windows**, *When* cập nhật `hosts`, *Then* xả cache DNS client (KN: `DnsFlushResolverCache`/tương đương `ipconfig /flushdns`) và tên mới phân giải ngay cho user thường; **Linux** không đụng `/etc/resolv.conf`.

### US-039 — CLI `status`
- **Epic**: EP-08 · **SP**: 5 · **MoSCoW**: Must · **Trace**: OPS-02, SEC-01, GNFR-02
- **Story**: Là *chủ mạng*, tôi muốn biết từng peer đang đi direct hay relay, để chẩn đoán vì sao chậm.
- **Phụ thuộc**: US-009, US-021, US-022.
- **AC**:
  1. **[H]** *When* chạy `status`, *Then* với mỗi peer in: tên, Overlay IP, online/offline, **đường hiện tại (`direct ip:port` | `relay`)**, RTT gần nhất, handshake gần nhất, rx/tx bytes; phía trên in trạng thái Control & Relay, `netmap_version`, endpoints của chính mình (LAN/reflexive), loại NAT.
  2. **[N]** *Given* 20 peer, *When* chạy `status`, *Then* trả kết quả ≤ **1 s**.
  3. **[E]** *Given* chặn rồi mở UDP giữa 2 node, *When* chạy `status` sau mỗi thay đổi, *Then* đường đi phản ánh đúng thực tế trong ≤ 15 s sau thay đổi.
  4. **[F]** *Given* agent không chạy, *When* chạy `status`, *Then* thông báo rõ "agent không chạy" và mã thoát khác 0 (không treo).
  5. **[F]** *Given* user thường trên **macOS/Windows/Linux**, *When* gọi `status` (lệnh đọc), *Then* chỉ trả thông tin không nhạy cảm; **không bao giờ** in private key (GNFR-02); lệnh quản trị bị từ chối cho user thường (US-052 Windows, US-073 macOS).
  6. **[E]** Hỗ trợ `--json` có schema ổn định để script/kiểm thử tự động đọc.
  7. **[H]** *When* chạy `status`, *Then* phần trên còn hiển thị **địa chỉ server `IP:cổng` (TCP Control/Relay, UDP STUN)**, **chế độ xác thực server (`pin`/`CA`) và fingerprint `sha256:<…>` đang dùng**, và **tên interface tunnel thực tế** (vd. `utunN` trên macOS, tên adapter trên Windows) (OPS-02, SEC-04(g)); khi đang trong giai đoạn đổi cổng (`US-074`) hiển thị cấu hình cũ/mới.

### US-040 — CLI `ping <peer>`
- **Epic**: EP-08 · **SP**: 3 · **MoSCoW**: Must · **Trace**: OPS-03
- **Story**: Là *chủ mạng*, tôi muốn ping ở tầng overlay và thấy từng lần đi qua đâu, để quan sát relay → direct upgrade.
- **Phụ thuộc**: US-021, US-026.
- **AC**:
  1. **[H]** *Given* peer chưa direct, *When* chạy `ping <peer>`, *Then* lần đầu in `pong from <peer> via relay in X ms`, sau đó (khi nâng cấp) in `via direct ip:port in Y ms`.
  2. **[E]** *Given* tham số `--direct` (ép thử direct), *When* không thể direct trong 10 s, *Then* in kết quả "direct không khả dụng" kèm nguyên nhân (NAT loại gì), không treo.
  3. **[F]** *Given* peer không tồn tại / offline, *When* chạy, *Then* báo lỗi rõ + thoát khác 0 sau timeout ≤ 10 s.
  4. **[E]** *Given* cờ `-c N`, *Then* dừng đúng N lần và in thống kê gói mất/RTT min/avg/max.

### US-041 — Bundle chẩn đoán `bugreport` (đã lọc secret)
- **Epic**: EP-08 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: OPS-09, SEC-01
- **Story**: Là *chủ mạng*, tôi muốn gom nhanh thông tin để tự gỡ lỗi mà không sợ lộ khóa.
- **Phụ thuộc**: US-039, US-043.
- **AC**:
  1. **[H]** *When* chạy `bugreport`, *Then* sinh một tệp nén gồm: log gần nhất, `status`, bảng route (`netstat -rn` macOS / `route print` Windows / `ip route` Linux), cấu hình đã lọc, phiên bản.
  2. **[F]** *Given* bundle, *When* grep private key / pre-auth key / token, *Then* 0 kết quả (chạy với dữ liệu tổng hợp chứa secret mẫu để chắc chắn bộ lọc hoạt động).
  3. **[E]** *Given* dung lượng log lớn, *When* tạo bundle, *Then* ≤ 20 MB và hoàn tất ≤ 30 s.

---

## 10. EP-09 — Vận hành & Bảo mật (Rate-limit, Log, Healthcheck, Backup, Hardening)

> Mục tiêu: chạy 24/7 an toàn trên 1 VPS (kể cả VPS đang chạy sẵn dịch vụ cá nhân), tách bạch kênh Admin, tự phục hồi và biết khi có sự cố. (Persona P1, P2)

### US-042 — Rate-limit, chống brute-force & xử lý `trusted_proxies` an toàn
- **Epic**: EP-09 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-05, PERF-02
- **Story**: Là *chủ mạng*, tôi muốn Control/Relay chặn kẻ đoán pre-auth key theo đúng IP thật của client (dù chạy trực tiếp hay sau Reverse Proxy), để VPS không bị tấn công hay tự khóa nhầm proxy cục bộ.
- **Phụ thuộc**: US-004, US-013.
- **AC**:
  1. **[N]** *Given* ngưỡng mặc định **≤ 10 lần thất bại/5 phút/IP**, *When* một IP thử 100 key sai trong 1 phút, *Then* từ lần thứ 11 bị chặn tạm **15 phút** (tăng dần khi tái phạm: ×2, trần 24 h) và các yêu cầu tiếp theo trả lỗi giới hạn tốc độ ngay (không tra cứu DB).
  2. **[F]** *Given* phản hồi lỗi xác thực pre-auth key, *When* đối chiếu giữa key sai, key hết hạn, key đã dùng và key đã thu hồi, *Then* server luôn **băm (hash) đầu vào trước khi tra cứu**, dùng phép **so sánh hash `constant-time`** và trả về **cùng mã trạng thái + thông báo lỗi chung** (chống dò quét/enumeration mà không gây flaky test bởi ngưỡng thời gian cứng).
  3. **[H]** *Given* thiết bị hợp lệ đăng ký đúng, *When* IP khác đang bị chặn, *Then* không bị ảnh hưởng.
  4. **[E]** *Given* tổng số yêu cầu đăng ký > N/phút (cấu hình, mặc định 60/phút toàn cục), *When* vượt, *Then* trả 429-tương đương kèm thời gian thử lại; Control CPU < 20% trong test flood 1000 req/s trong 30 s (không sập).
  5. **[F]** *Given* mỗi lần chặn/vượt ngưỡng, *When* xảy ra, *Then* có bản ghi audit (US-013) và tăng metric.
  6. **[F]** *Given* quy tắc lấy IP nguồn (`SEC-05`), *When* ở chế độ mặc định (`trusted_proxies` tắt/rỗng — Standalone), *Then* hệ thống **chỉ lấy IP từ kết nối TCP trực tiếp** và bỏ qua mọi header IP chuyển tiếp giả mạo (`X-Forwarded-For`…); *When* chạy sau Reverse Proxy và admin bật tường minh `trusted_proxies` (vd. `127.0.0.1`/socket proxy), *Then* rate-limit tính theo IP thật của client do proxy gắn và **không bao giờ khóa nhầm `127.0.0.1`** làm sập dịch vụ.

### US-043 — Structured logging không rò secret & log rotation
- **Epic**: EP-09 · **SP**: 3 · **MoSCoW**: Must · **Trace**: OPS-01, GNFR-02
- **Story**: Là *chủ mạng*, tôi muốn log JSON/logfmt có ngữ cảnh để truy vết sự cố mà không lộ secret.
- **Phụ thuộc**: không.
- **AC**:
  1. **[H]** *Given* server và agent, *When* chạy, *Then* mọi dòng log có `ts` (UTC), `level`, `component` (danh sách tên module chuẩn hóa đối chiếu theo kiến trúc module chốt tại Gate 2, bao phủ điều phối, relay, STUN, đường đi UDP/NAT, đường hầm, DNS, định tuyến), `node_id`, `peer_id` (nếu có), `request_id/conn_id`, `event`.
  2. **[F]** *Given* chạy toàn bộ kịch bản đăng ký/relay/rotate với dữ liệu mẫu chứa secret, *When* grep log, *Then* 0 secret (private key, pre-auth key, token) — chạy trong CI.
  3. **[E]** *Given* giới hạn dung lượng log cấu hình (mặc định 100 MB/service), *When* vượt, *Then* xoay vòng/xóa bản cũ; không đầy đĩa do log (test ghi 1 GB log → tổng ≤ giới hạn).
  4. **[E]** *Given* mức log `debug`, *When* bật, *Then* vẫn không in secret (kiểm tra cùng test).

### US-044 — Listener quan sát chỉ-đọc: Healthcheck `/healthz` & `/readyz`
- **Epic**: EP-09 · **SP**: 2 · **MoSCoW**: Must · **Trace**: OPS-05, SEC-06, SEC-14
- **Story**: Là *chủ mạng*, tôi muốn script kiểm tra nhanh Control còn sống và sẵn sàng trên một listener chỉ-đọc tách biệt khỏi kênh Admin, để giám sát tự động an toàn.
- **Phụ thuộc**: US-007, US-019, US-024.
- **AC**:
  1. **[H]** *Given* mọi thành phần khỏe (kiểm ở cả cổng mặc định và cổng tùy chọn), *When* `curl /healthz` & `/readyz`, *Then* cả hai trả 200 trong ≤ 200 ms.
  2. **[F]** *Given* DB không mở được, *When* gọi `/readyz`, *Then* 503 và nêu lý do không nhạy cảm; `/healthz` vẫn 200 (liveness ≠ readiness).
  3. **[F]** *Given* listener UDP STUN hoặc listener TCP relay/control **trên đúng cổng đã cấu hình (mặc định `443`/`3478` hoặc cổng tùy chọn như `8443`/`3479`)** không hoạt động, *When* gọi `/readyz`, *Then* 503.
  4. **[F]** *Given* nguyên tắc tách biệt `SEC-14`, *When* kiểm tra listener chứa `/healthz` và `/readyz`, *Then* mặc định chỉ bind loopback `127.0.0.1` (hoặc thêm IP overlay khi bật tường minh), **hoàn toàn không chứa bất kỳ endpoint Admin/thay đổi trạng thái nào**, không trả secret, và không truy cập được từ Internet (`nmap` IP public).

### US-045 — Backup cục bộ tự động, kiểm tra checksum & diễn tập Restore
- **Epic**: EP-09 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-12, OPS-08, SEC-14
- **Story**: Là *chủ mạng*, tôi muốn có bản sao lưu DB control cục bộ nhất quán kèm checksum và quy trình khôi phục đã thử, để VPS hỏng dữ liệu không phải đăng ký lại mọi máy.
- **Phụ thuộc**: US-007, US-012.
- **AC**:
  1. **[H]** *Given* Control đang chạy, *When* đến lịch (mặc định hằng ngày), chạy `backup now` (qua kênh `SEC-14`) hoặc trước mỗi migration, *Then* tạo bản backup cục bộ nhất quán bằng cơ chế an toàn khi đang chạy (không khóa ghi > 1 s); giữ N=7 bản gần nhất.
  2. **[H]** *Given* diễn tập: xóa toàn bộ DB, *When* chạy `restore <file>` từ bản gần nhất, *Then* Control chạy lại; **mọi node kết nối lại với IP cũ không cần đăng ký lại và không cần pin lại** (khóa định danh server được khôi phục cùng bản backup — REL-12); thời gian khôi phục ≤ 5 phút (RTO) với 20 node.
  3. **[E]** *Given* mỗi tệp backup tạo ra, *When* hoàn tất ghi, *Then* sinh kèm tệp/mã **checksum** kiểm tra toàn vẹn và đặt quyền truy cập chặt (`0600` chỉ cho user dịch vụ/`root`), sẵn sàng để đồng bộ mã hóa ra ngoài VPS bằng công cụ chuẩn của OS theo hướng dẫn trong Runbook (`US-059` — không nhồi tính năng quản lý khóa mã hóa & giao thức upload lưu trữ ngoài vào phần mềm ở MVP).
  4. **[F]** *Given* backup hỏng hoặc sai checksum, *When* chạy `restore`, *Then* từ chối khôi phục với lỗi rõ ràng để không ghi đè dữ liệu hỏng; cho phép chỉ định bản kế tiếp.
  5. **[F]** *Given* tệp backup, *When* kiểm tra nội dung, *Then* **không chứa private key client** (vì server không có) và không chứa pre-auth key rõ; bản backup **có chứa khóa định danh server dùng cho Pin (`SEC-04(c)`)** nên tệp/thư mục backup được đặt quyền `0600`, đánh dấu "chứa khóa server" và Runbook (`US-059`) yêu cầu **mã hóa khi chép ra ngoài VPS**.
  6. **[F]** *Given* bản backup không chứa khóa định danh server (định dạng cũ/hỏng) hoặc khóa không khớp pin đang công bố, *When* chạy `restore`, *Then* từ chối hoặc cảnh báo rõ "mọi client sẽ phải pin lại thủ công" và yêu cầu xác nhận tường minh; không âm thầm sinh khóa mới.

### US-046 — Hardening VPS an toàn với dịch vụ sẵn có & tách kênh Admin (`SEC-14`)
- **Epic**: EP-09 · **SP**: 5 *(tái ước lượng 3→5: thêm kiểm tra xung đột cổng, cổng cấu hình được, nhắc cloud security group)* · **MoSCoW**: Must · **Trace**: SEC-06, SEC-14, SEC-04, SEC-15
- **Story**: Là *chủ mạng*, tôi muốn dịch vụ trên VPS chạy với quyền tối thiểu, khóa chặt kênh Admin theo quyền OS và hỗ trợ hardening firewall có xác nhận mà không đánh sập web hay SSH sẵn có trên VPS cá nhân.
- **Phụ thuộc**: US-012, US-051.
- **AC**:
  1. **[H]** *Given* VPS cài đặt dịch vụ (cả VPS sạch lẫn VPS đang chạy sẵn dịch vụ cá nhân và/hoặc SSH cổng khác 22), *When* quét bề mặt mạng của riêng dịch vụ Mesh từ ngoài (`nmap` TCP+UDP), *Then* dịch vụ chỉ mở public: **đúng 1 cổng TCP đã cấu hình** cho Control+Relay (mặc định `443`, hoặc cổng tùy chọn như `8443`; chế độ Standalone — ở chế độ sau Reverse Proxy dịch vụ chỉ bind cục bộ), **đúng 1 cổng UDP STUN đã cấu hình** (mặc định `3478`, hoặc vd. `3479`) và cổng UDP của agent VPS (nếu là node) — `nmap` phản ánh đúng **cấu hình hiện hành**, không cổng nào khác (GNFR-11); **việc bật firewall mặc định deny là tùy chọn `opt-in` có xác nhận** — khi chọn bật, công cụ tự phát hiện cổng SSH đang hoạt động (kể cả khác 22), liệt kê và mặc định giữ nguyên các cổng dịch vụ sẵn có trên VPS, hiển thị `dry-run` trước khi áp, và **tự hoàn tác (auto-rollback) sau 60–120 s** nếu mất kết nối không xác nhận lại; firewall chỉ **thêm** quy tắc cho **đúng các cổng đã cấu hình**, không xóa quy tắc có sẵn; khi đổi cổng (`US-074`) quy tắc của cổng cũ chỉ được gỡ sau khi giai đoạn chuyển tiếp kết thúc.
  2. **[H]** *Given* service Control/Relay, *When* kiểm tra tiến trình, *Then* chạy bằng user hệ thống riêng **không đặc quyền**, chỉ cấp capability mạng tối thiểu cần thiết; unit service bật các cờ cô lập (`NoNewPrivileges`, `ProtectSystem`… hoặc tương đương).
  3. **[F]** *Given* yêu cầu tách kênh `SEC-14`, *When* kiểm tra các socket lắng nghe và thử tấn công từ các ngữ cảnh, *Then*: (a) **không có bất kỳ listener Admin nào trên TCP** (cấm tuyệt đối mở Admin API trên `IP overlay`, `IP public` hay TCP `127.0.0.1`/`::1` trần); quét từ một node trong mesh hoặc gọi từ user thường/`www-data`/container/SSRF trên VPS đều bị từ chối không đổi được trạng thái nào; (b) listener chỉ-đọc (`/healthz`, `/readyz`, `/metrics`) nằm riêng, chỉ bind loopback (hoặc thêm IP overlay khi bật tường minh) và bị từ chối từ Internet.
  4. **[F]** *Given* lệnh tự kiểm `hardening-check`, *When* cấu hình vi phạm an toàn (chạy dưới `root`, quyền socket Admin lỏng hơn `0660`, bật Reverse Proxy mà thiếu `trusted_proxies`, lộ listener nội bộ ra public), *Then* báo FAIL rõ từng hạng mục.
  5. **[F]** *Given* VPS đang có tiến trình khác giữ cổng người dùng chọn (vd. Nginx giữ `443`, hoặc cổng UDP STUN đang bận), *When* cài đặt hoặc đổi cổng, *Then* trình cài **dừng có thông báo rõ, không giành cổng, không ảnh hưởng dịch vụ đang giữ cổng**, và gợi ý cổng thay thế (vd. `8443`) hoặc chế độ Reverse Proxy; web cũ trên `443` + SSH cổng tùy chỉnh (vd. `2222`) vẫn hoạt động 100%, không quy tắc firewall nào bị đổi khi người dùng không `opt-in`.
  6. **[E]** *Given* cổng đã chọn `< 1024` và service chạy bằng user không đặc quyền, *When* cài đặt, *Then* chỉ cấp capability bind cổng đặc quyền cần thiết (KN: `CAP_NET_BIND_SERVICE`); cổng `≥ 1024` không cấp capability này. *When* cài đặt/đổi cổng hoàn tất, *Then* trình cài **in nhắc mở đúng các cổng TCP/UDP tương ứng trên tường lửa của nhà cung cấp cloud (security group)** — việc nằm ngoài VPS, không tự động hóa.

### US-047 — Xác thực server & vòng đời khóa/chứng chỉ TLS: IP + Pin (mặc định) · Standalone ACME (không cần cổng 80) · Reverse Proxy
- **Epic**: EP-09 · **SP**: 8 *(tái ước lượng 5→8: Pin là chế độ hạng nhất + khóa định danh server bền vững + xoay khóa bằng tập pin, ngoài ACME/Reverse Proxy)* · **MoSCoW**: Must · **Trace**: SEC-04, SEC-15, OPS-07, REL-12, T22, T44
- **Story**: Là *chủ mạng*, tôi muốn kết nối máy client thẳng bằng **IP VPS + pin khóa server** ngay từ ngày đầu (chưa cần domain), TLS trên cổng TCP đã cấu hình luôn hợp lệ dù sau này chuyển sang Standalone ACME (không cần mở cổng 80) hay Reverse Proxy sẵn có, và nếu lỡ trễ hạn/xoay khóa thì toàn bộ máy tự nối lại được mà không phải đăng ký lại hay pin lại thủ công.
- **Phụ thuộc**: US-003, US-024, US-034, OQ-02 ✅. **Lát cắt: nằm trong `S1` (Milestone 1)** vì không có pin thì client không được phép kết nối (cấm TOFU).
- **AC**:
  1. **[H]** *Given* VPS có domain: ở chế độ **Standalone**, *When* xin mới hoặc chứng chỉ còn ≤ 30 ngày, *Then* Control tự xin/gia hạn ACME bằng phương thức **không cần mở cổng TCP 80** (vd. `TLS-ALPN-01` ngay trên cổng 443 hoặc `DNS-01`) và nạp nóng (hot-reload) không làm rớt kết nối agent hiện có; ở chế độ **Sau Reverse Proxy sẵn có**, cho phép tắt ACME nội bộ để proxy của người dùng quản lý TLS 443 mà vẫn kiểm tra được hạn chứng chỉ đầu ngoài; nếu gia hạn thất bại, thử lại ≥ 3 lần/ngày và log lỗi.
  2. **[F]** *Given* chứng chỉ TLS đang phục vụ còn < 14 ngày mà chưa được gia hạn, *When* kiểm tra định kỳ, *Then* ghi log mức `ERROR`, hiển thị trong chẩn đoán server và kích hoạt cảnh báo (`US-049` nếu bật).
  3. **[H]** *Given* VPS **không có domain** (kết nối bằng IP — **chế độ chính thức mặc định `SEC-04(c)` từ Milestone 1**), *When* cài server (tại cổng TCP cấu hình, vd. `443` hoặc `8443`), *Then* server sinh **khóa định danh bền vững** + chứng chỉ phục vụ, hiển thị **fingerprint `sha256:<…>` của khóa công khai (SPKI pin)** qua kênh Admin cục bộ (`US-012 AC6`, qua SSH) và đưa vào lệnh tham gia in sẵn (`US-002 AC6`); client chỉ chấp nhận server có khóa khớp pin; **tái phát hành/gia hạn chứng chỉ giữ nguyên khóa thì không client nào phải làm gì** (kiểm: phát hành lại chứng chỉ → 5 agent online giữ kết nối, không pin lại).
  4. **[F]** *Given* chứng chỉ trên VPS lỡ hết hạn thực sự, *When* agent kết nối, *Then* agent từ chối bắt tay TLS (không gửi secret, không bỏ qua kiểm tra), đường hầm P2P direct đang chạy vẫn sống (`US-033`), và agent tiếp tục thử lại theo backoff trần 5 phút (`US-034 AC4`) để **tự động nối lại ngay khi chứng chỉ trên VPS được gia hạn xong**.
  5. **[E]** *Given* quản trị viên **xoay khóa server có kế hoạch** (qua kênh Admin — SEC-14), *When* server công bố **tập pin (hiện tại + kế tiếp) trước** qua kênh đã xác thực và chỉ chuyển sang khóa mới sau cửa sổ cấu hình được, *Then* **không client online nào mất kết nối** (đo trên 5 agent macOS/Windows/Linux); agent offline qua cửa sổ khôi phục theo `US-074 AC5`; mọi thao tác sinh audit (US-013); không có cờ bỏ qua pin.
  6. **[F]** *Given* client không có pin và không ở chế độ domain/CA, hoặc kẻ MITM trình chứng chỉ **CA công cộng hợp lệ cho đúng IP** nhưng khóa khác pin, *When* kết nối ở chế độ IP + Pin, *Then* client từ chối ("pin mismatch"), không gửi secret, không TOFU (kiểm cùng `US-003 AC6/AC7`).
  7. **[E]** *Given* chế độ Standalone có domain mà dịch vụ chạy ở **cổng TCP khác `443`**, *When* xin chứng chỉ ACME, *Then* hệ thống không dùng `TLS-ALPN-01` (CA chỉ kiểm tra trên cổng 443) mà dùng `DNS-01` hoặc từ chối cấu hình với hướng dẫn rõ (đặt cổng 443 hoặc chạy sau Reverse Proxy 443); không phụ thuộc cổng 80.
  8. **[E]** *Given* chuyển từ chế độ IP + Pin sang domain ACME (hoặc sang Reverse Proxy) hay đổi IP VPS, *When* thực hiện qua `US-074`, *Then* không node nào phải nhập lại pre-auth key; node giữ nguyên node key, tên và Overlay IP (`SEC-15(c)`).

### US-048 — Metrics tối thiểu (trên listener quan sát chỉ-đọc)
- **Epic**: EP-09 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: OPS-06, SEC-14
- **Story**: Là *chủ mạng*, tôi muốn xem số liệu vận hành trên kênh chỉ-đọc để biết relay có đang bị lạm dụng không.
- **Phụ thuộc**: US-025, US-027, US-042, US-044.
- **AC**:
  1. **[H]** *When* `GET /metrics` trên listener quan sát chỉ-đọc (mặc định loopback `127.0.0.1`, hoặc IP overlay nếu bật tường minh — tách biệt hoàn toàn khỏi kênh Admin theo `SEC-14`), *Then* có: số node online, số kết nối relay, bytes relay theo node, số gói relay drop theo đích, đăng ký thành công/thất bại, số lần rate-limit, số stream mở, RAM/thread; agent: số peer direct vs relay.
  2. **[E]** *Given* tài liệu danh mục metric, *When* so sánh với `/metrics`, *Then* khớp 100% tên metric và 0 secret bị lộ.
  3. **[F]** *Given* truy cập từ Internet, *When* gọi `/metrics`, *Then* bị từ chối.

### US-049 — Cảnh báo cá nhân tối giản
- **Epic**: EP-09 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: OPS-07, PERF-12
- **Story**: Là *chủ mạng*, tôi muốn nhận thông báo khi VPS/chứng chỉ/đĩa/relay/key sắp có vấn đề, để xử lý trước khi mất mạng.
- **Phụ thuộc**: US-044, US-047, OQ-07.
- **AC**:
  1. **[H]** *Given* mô phỏng từng điều kiện: `/readyz` 503 > 2 phút, chứng chỉ < 14 ngày, đĩa > 85%, băng thông relay vượt ngưỡng, node key < 7 ngày, *When* điều kiện xảy ra, *Then* nhận được 1 thông báo qua kênh đã cấu hình (webhook/email/Telegram — OQ-07) trong ≤ 5 phút.
  2. **[E]** *Given* điều kiện kéo dài, *When* lặp, *Then* không spam (tối đa 1 thông báo/điều kiện/giờ) và có thông báo "đã phục hồi".
  3. **[F]** *Given* kênh thông báo lỗi, *When* gửi thất bại, *Then* ghi log, thử lại tối đa 3 lần với backoff, không ảnh hưởng dịch vụ chính.

### US-050 — Versioning & tương thích giao thức
- **Epic**: EP-09 · **SP**: 3 · **MoSCoW**: **Should** · **Trace**: OPS-10, REL-01
- **Story**: Là *chủ mạng*, tôi muốn nâng cấp server mà không làm đứt tunnel, và client quá cũ bị từ chối rõ ràng.
- **Phụ thuộc**: US-009, US-033.
- **AC**:
  1. **[H]** *Given* client gửi `protocol_version`, `agent_version` **và OS/kiến trúc (`darwin/arm64`, `darwin/amd64`, `windows/amd64`, `linux/amd64`…)**, *When* kết nối, *Then* Control ghi nhận và hiển thị trong `node list`.
  2. **[F]** *Given* client có phiên bản dưới mức tối thiểu hỗ trợ, *When* kết nối, *Then* bị từ chối với thông báo "cần nâng cấp agent" (không treo/không lỗi mơ hồ).
  3. **[E]** *Given* client phiên bản N-1 với server N, *When* chạy bộ test tương thích, *Then* đăng ký/netmap/relay hoạt động; nâng cấp server (restart) không làm rớt tunnel P2P đang chạy (0 mất gói do control).

### US-051 — Cài đặt/nâng cấp server an toàn (VPS sạch hoặc VPS đang dùng) & tự khởi động lại
- **Epic**: EP-09 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-13, SEC-06, REL-12, SEC-04, PLAT-03(a)
- **Story**: Là *chủ mạng*, tôi muốn cài/nâng cấp Control+STUN+Relay trên VPS (dù là VPS sạch hay VPS đang chạy sẵn web/SSH tùy chỉnh) bằng quy trình lặp lại được và tự sống lại khi crash, để vận hành 24/7 mà không làm sập dịch vụ hiện có.
- **Phụ thuộc**: US-007, US-024, US-046.
- **AC**:
  1. **[H]** *Given* VPS Ubuntu LTS (cả **VPS sạch** lẫn **VPS đang chạy sẵn dịch vụ cá nhân** như Nginx/Caddy trên cổng 443 và SSH cổng khác 22), *When* chạy quy trình cài đặt chọn chế độ Standalone hoặc chế độ sau Reverse Proxy (sinh kèm cấu hình mẫu chuyển tiếp HTTP + Upgrade cho Nginx/Caddy), *Then* Control+STUN+Relay chạy dưới service manager **trên cổng TCP/UDP do người cài chọn (mặc định `443`/`3478`; ví dụ `8443`/`3479` — GNFR-11); nếu cổng đã bị tiến trình khác chiếm (vd. web đang giữ `443`) thì trình cài dừng, báo rõ, không giành cổng và gợi ý cổng khác hoặc chế độ Reverse Proxy (`US-046 AC5`)**, tự bật khi boot, `readyz` = 200 sau ≤ 60 s; **mặc định không tự động bật firewall deny hay xóa rule hiện có nếu người dùng không `opt-in` (`US-046 AC1`)**, các web cá nhân và phiên SSH hiện có vẫn hoạt động 100%; chạy lặp lại (idempotent) không phá cấu hình/dữ liệu.
  2. **[H]** *Given* tiến trình Control bị `kill -9`, *When* supervisor phát hiện, *Then* tự sống lại ≤ **10 s** và agent kết nối lại (REL-13, US-034).
  3. **[E]** *Given* nâng cấp phiên bản, *When* thực hiện, *Then* tự backup trước (US-045, **gồm khóa định danh server để restore không phải pin lại**), migrate (US-007) và có đường **rollback** (bản cũ + backup) được ghi trong runbook; tunnel P2P đang chạy không đứt.
  4. **[F]** *Given* crash-loop (> 5 lần/phút), *When* xảy ra, *Then* supervisor backoff, log rõ và (Should) cảnh báo; không làm đầy đĩa log.
  5. **[H]** *Given* cài server ở chế độ IP + Pin (chưa có domain), *When* quy trình cài đặt hoàn tất, *Then* in **địa chỉ `IP:cổng TCP`, cổng UDP STUN, fingerprint `sha256:<…>` và một lệnh tham gia mẫu** (`US-002 AC6`) để chép sang máy macOS/Windows/Linux; chạy lại quy trình (idempotent) không làm đổi khóa định danh server/pin đã có.
  6. **[E]** *Given* VPS cũng là một node mesh (`US-056`), *When* cài đặt, *Then* tiến trình Control/Relay/STUN chạy dưới user không đặc quyền riêng và thành phần agent (cần `CAP_NET_ADMIN`) chạy tách biệt theo `US-056 AC4` (SEC-06(4)). *(US-046 + US-051 được gom cùng nhóm triển khai VPS ở mục 15.2 vì phụ thuộc vòng.)*

### US-074 — Đổi cổng / IP / chế độ xác thực server mà không mất danh tính node (`SEC-15`)
- **Epic**: EP-09 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-15, SEC-04, SEC-14, SEC-09
- **Story**: Là *chủ mạng*, tôi muốn đổi cổng TCP/UDP, đổi IP VPS, chuyển IP + Pin sang domain ACME hoặc xoay khóa server bằng một thao tác trên VPS mà các máy macOS/Windows/Linux **không phải đăng ký lại** (giữ node key, Overlay IP, tên; không cần pre-auth key mới) và tunnel P2P đang chạy không đứt, để tôi dời dịch vụ/đổi cổng khi bị quét hay xung đột mà không mất danh tính hệ thống.
- **Phụ thuộc**: US-009 (`relay_map` phân phối qua Netmap), US-012 (kênh Admin + `server info`), US-013 (audit), US-019, US-024, US-033 (tunnel sống khi Control đổi), US-034, US-046 (kiểm tra cổng/firewall), US-047 (tập pin), US-052/US-073/US-056 (kênh IPC cục bộ phân quyền của agent).
- **AC**:
  1. **[H]** *Given* 5 agent online (≥ 1 macOS, ≥ 1 Windows, VPS-node Linux) đang kết nối server ở cổng TCP `443`, *When* admin đổi sang `8443` qua kênh Admin cục bộ (SEC-14), *Then* server **lắng nghe song song cổng cũ và mới trong một giai đoạn chuyển tiếp cấu hình được**, công bố cấu hình mới **qua kênh đã xác thực** (`relay_map`/stream — `US-009 AC6`), cả 5 agent ghi bền và tự chuyển sang cổng mới **không đăng ký lại**, Overlay IP/tên/node key không đổi, tunnel P2P direct đang chạy **0% mất gói do thao tác** (`REL-01`), cấu hình mới đến mọi agent online P95 ≤ 5 s (PERF-08); sinh đúng 1 bản ghi audit (actor/UID, cấu hình cũ→mới, `SEC-09`).
  2. **[H]** *Given* admin đổi cổng UDP STUN (vd. `3478 → 3479`), *When* công bố, *Then* agent nhận cổng mới qua Netmap ≤ PERF-08 (P95 ≤ 5 s) và STUN/P2P hoạt động lại (`US-019 AC5`).
  3. **[F]** *Given* cổng mới đang bị tiến trình khác chiếm, hoặc firewall/cloud security group chưa mở, *When* admin áp dụng đổi cổng, *Then* hệ thống **từ chối, không đổi gì, cổng cũ vẫn phục vụ**, báo rõ nguyên nhân và gợi ý cổng khác (`US-046 AC5/AC6`); không bao giờ giành cổng của dịch vụ khác.
  4. **[F]** *Given* một cấu hình server mới được gửi tới agent qua kênh **không xác thực** hoặc từ server **sai pin/sai CA hiện hành** (test chèn cấu hình giả), *When* agent nhận, *Then* agent **từ chối 100%**, giữ cấu hình cũ và log `WARN` (`SEC-15(e)`).
  5. **[E]** *Given* một agent **offline suốt giai đoạn chuyển tiếp** (cổng cũ đã đóng), *When* quản trị viên cục bộ của máy đó (`Administrator`/`root`/thành viên nhóm `admin` macOS) chạy `mesh set --server <IP|domain>:<cổng> --server-pin sha256:<…>` qua kênh IPC cục bộ phân quyền (`US-052` named pipe ACL / `US-073` socket `LOCAL_PEERCRED`), *Then* agent kết nối lại với **đúng node key, tên và Overlay IP cũ, không cần pre-auth key mới**; *When* **user thường** (không phải quản trị viên) chạy cùng lệnh, *Then* **bị từ chối** (lỗi quyền kênh IPC); thao tác được log (không lộ secret).
  6. **[E]** *Given* đổi IP VPS, hoặc chuyển chế độ IP + Pin → domain ACME / Reverse Proxy, hoặc xoay khóa server có kế hoạch (tập pin hiện tại + kế tiếp — `US-047 AC5`), *When* thực hiện, *Then* không node nào phải nhập lại pre-auth key; agent online tự chuyển; giữ nguyên danh tính (`SEC-15(c)`).
  7. **[F]** *Given* giai đoạn chuyển tiếp sắp kết thúc mà còn agent chưa xác nhận cấu hình mới, *When* admin chạy `server info` (`US-012 AC6`), *Then* thấy danh sách agent chưa chuyển và có thể **gia hạn giai đoạn chuyển tiếp** trước khi đóng cổng cũ; cổng cũ chỉ đóng và quy tắc firewall cũ chỉ gỡ **sau** khi giai đoạn kết thúc (`US-046`).
  8. **[N]** *Given* kịch bản AC1 lặp 10 lần trong lab (`US-057`, bao gồm cả cổng `443↔8443`), *Then* 0 lần phải đăng ký lại, 0 thay đổi Overlay IP, thời gian relay/control kết nối lại cổng mới P95 ≤ 15 s (đề xuất, đo bởi `US-058`).

---

## 11. EP-10 — Tích hợp nền tảng (macOS & Windows client; Linux VPS-node/máy trạm) & Dọn dẹp

> Mục tiêu: cài/gỡ/chạy ổn định như phần mềm hệ thống thật trên **macOS (13+, `arm64`/`amd64`) và Windows** (client hạng nhất), Linux (VPS-node; máy trạm sau); không để lại rác làm hỏng mạng. (Persona P1, P2, P3)

### US-052 — Windows Service, CLI qua kênh có ACL & cài/gỡ sạch
- **Epic**: EP-10 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PLAT-01, SEC-01, REL-13, R-11
- **Story**: Là *người dùng di động*, tôi muốn agent chạy như dịch vụ Windows tự khởi động và gỡ ra không để lại gì, để máy luôn sạch.
- **Phụ thuộc**: US-015.
- **AC**:
  1. **[H]** *Given* installer Windows, *When* cài, *Then* đăng ký service (tự chạy khi boot, Recovery: restart sau crash ≤ 10 s), cài driver TUN đúng license, tạo adapter tên cố định.
  2. **[H]** *When* gỡ cài đặt, *Then* xóa service, adapter, route, rule firewall, khối hosts, file khóa chỉ bị xóa khi có xác nhận `--purge` (mặc định giữ để cài lại giữ danh tính); **0 adapter ma** còn lại sau 10 vòng cài/gỡ.
  3. **[F]** *Given* CLI chạy bởi user thường, *When* gọi lệnh quản trị (`up`, `down`, `cleanup`, `set` — đổi server/pin theo `SEC-15`/`US-074 AC5`), *Then* bị từ chối (kênh giao tiếp service dùng named pipe với ACL chỉ Administrators/SYSTEM); lệnh đọc (`status`) cho phép nếu cấu hình.
  4. **[E]** *Given* cài đặt khi chưa có Admin/UAC từ chối, *When* chạy, *Then* dừng sạch, không cài dở.

### US-053 — Windows Firewall: profile adapter & rule dải overlay
- **Epic**: EP-10 · **SP**: 3 · **MoSCoW**: Must · **Trace**: PLAT-02, pitfall 5.6.4
- **Story**: Là *người dùng di động*, tôi muốn RDP/SMB/ping tới máy Windows hoạt động ngay sau cài đặt, không phải sửa firewall.
- **Phụ thuộc**: US-052.
- **AC**:
  1. **[H]** *Given* Windows mới cài agent, *When* peer ping/SMB/RDP tới máy, *Then* thành công nếu dịch vụ đích bật (adapter không bị gán Public chặn hết; có rule cho **dải overlay** riêng).
  2. **[E]** *Given* adapter bị Windows gán lại profile Public sau crash/restart, *When* agent khởi động, *Then* sửa lại profile/rule trong ≤ 10 s.
  3. **[E]** *Given* gỡ cài đặt, *When* hoàn tất, *Then* rule do agent tạo bị xóa; rule của hệ thống/người dùng khác không bị đụng.
  4. **[F]** *Given* rule chỉ cho phép từ dải overlay, *When* gói từ ngoài overlay tới adapter, *Then* bị chặn.

### US-073 — macOS Daemon (`launchd`), IPC cục bộ có phân quyền & cài/gỡ sạch
- **Epic**: EP-10 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PLAT-06, SEC-01, REL-08, REL-13
- **Story**: Là *chủ mạng kiêm người dùng di động (MacBook)*, tôi muốn agent chạy như daemon hệ thống của macOS tự khởi động trước khi đăng nhập, CLI `mesh` chỉ quản trị viên máy mới điều khiển được, cài bằng luồng an toàn không cần chứng chỉ Apple trả phí và gỡ ra không để lại gì, để MacBook luôn sạch và không bị leo thang đặc quyền cục bộ.
- **Phụ thuộc**: US-060 (data plane `utun`), US-001 (quyền file khóa), US-038 (hosts), US-055 (cleanup). Hạ tầng kiểm thử: máy Mac thật/VM trên phần cứng Apple/runner macOS (GNFR-12).
- **AC**:
  1. **[H]** *Given* macOS 13+ (**Apple Silicon `arm64` và Intel `amd64`**), *When* cài đặt, *Then* agent chạy dạng **daemon hệ thống** (KN: plist trong `/Library/LaunchDaemons`, `root:wheel 0644`, `RunAtLoad` + `KeepAlive`) — **không bắt buộc** Apple Developer Program ($99/năm), Developer ID hay NetworkExtension entitlement; sau khi khởi động lại máy, daemon **tự chạy trước khi user đăng nhập** và tham gia mesh (kiểm: reboot → `status` từ SSH khi chưa đăng nhập GUI); phát hành 2 binary native hoặc 1 Universal.
  2. **[F]** *Given* **đường dẫn cài đặt**, *When* kiểm tra quyền, *Then* **binary, plist, thư mục trạng thái và thư mục socket nằm ở đường dẫn chỉ root ghi được** (KN: vd. `/usr/local/libexec/<app>`; thư mục trạng thái `0700` root) — **cấm** để LaunchDaemon root nạp binary từ thư mục user ghi được (`/opt/homebrew`, `~/…`): trình cài **từ chối cài** và daemon **từ chối khởi động** nếu binary/plist hay bất kỳ thư mục cha nào ghi được bởi user không phải root (kiểm bằng `stat`/`find -perm` + test thử ghi bằng user thường = bị từ chối).
  3. **[H]** *Given* CLI `mesh` giao tiếp daemon qua **Unix Domain Socket** trong thư mục root (KN: `/var/run/<app>/`; quyền `0600` root hoặc `0660 root:admin`), *When* CLI gọi, *Then* daemon **xác minh danh tính tiến trình gọi** (KN: `LOCAL_PEERCRED`/`getpeereid`) và chỉ cho `root`/thành viên nhóm `admin` thực hiện thao tác thay đổi (`up`/`down`/`cleanup`/`set` — `SEC-15`); chính sách `status`/`ping` chỉ-đọc cho user thường do Architect chốt Gate 2 và **không bao giờ** in secret.
  4. **[F]** *Given* user **không thuộc nhóm `admin`** (hoặc tiến trình dưới uid khác), *When* chạy `mesh up`/`down`/`cleanup`/`set` hoặc tự kết nối socket (kể cả thử thay socket/thư mục bằng symlink), *Then* **bị từ chối** (lỗi quyền socket + kiểm tra peer credential), không đổi trạng thái nào, ghi log từ chối.
  5. **[H]** *Given* cài đặt, *When* chạy **luồng cài không phụ thuộc trình duyệt** (KN: build tại chỗ từ mã nguồn, hoặc script tải bản release rồi **kiểm tra SHA-256/chữ ký phát hành** trước khi cài vào đường dẫn root), *Then* binary `arm64` (ad-hoc signed) chạy được trên Apple Silicon và **không bị Gatekeeper chặn do thuộc tính `com.apple.quarantine`** (không đi qua trình duyệt); *Given* checksum không khớp, *Then* dừng, không cài gì; **tài liệu/trình cài không bao giờ hướng dẫn tắt Gatekeeper toàn hệ thống** (`spctl --master-disable`). *(Developer ID + notarization + `.pkg` là Phase 2+, `PLAT-07`.)*
  6. **[E]** *Given* **Application Firewall** của macOS, *When* cài đặt, *Then* trình cài **phát hiện trạng thái firewall**; nếu đang bật thì **đề xuất (opt-in, có xác nhận)** thêm ngoại lệ cho đúng binary daemon (KN: `socketfilterfw --add`/`--unblockapp`); *When* người dùng từ chối, *Then* kết nối vẫn đi qua relay và `status` giải thích lý do P2P hạn chế; *When* bật "Block all incoming"/stealth, *Then* cảnh báo P2P có thể giảm; **`pf`: không flush/ghi đè `/etc/pf.conf`**, nếu cần quy tắc chỉ dùng **anchor riêng** của agent và gỡ khi gỡ cài đặt.
  7. **[E]** *Given* `/etc/hosts` trên macOS là symlink tới `/private/etc/hosts`, *When* agent cập nhật khối hosts (`US-038`), *Then* **symlink được giữ nguyên**, file thật giữ `root:wheel 0644`, `scutil --dns` không đổi (kiểm tích hợp trên macOS thật).
  8. **[H]** *Given* daemon chạy, *When* `kill -9` tiến trình, *Then* `launchd` khởi động lại **≤ 10 s**, agent dọn tàn dư trước khi dựng mới, không route/khối hosts trùng lặp, Internet máy thật không gián đoạn > 3 s (REL-13, REL-08).
  9. **[H]** *Given* gỡ cài đặt, *When* chạy uninstall, *Then* dừng và gỡ LaunchDaemon, xóa binary/plist/socket, khối hosts, anchor `pf`, ngoại lệ firewall; `ifconfig` không còn `utun` của agent; `/etc/hosts`, `pf` và firewall trở về như trước khi cài; **khóa node chỉ bị xóa khi có `--purge`** (mặc định giữ để cài lại giữ danh tính); **0 tàn dư sau 10 vòng cài/gỡ**; `utun` của iCloud Private Relay/VPN khác không bị đụng tới.
  10. **[F]** *Given* macOS < 13, kiến trúc không hỗ trợ, hoặc chạy cài đặt không có quyền quản trị (từ chối `sudo`), *When* cài, *Then* dừng sạch với thông báo rõ, không cài dở.

### US-054 — Linux máy trạm desktop: gói cài dịch vụ systemd & tích hợp desktop (sau macOS + Windows)
- **Epic**: EP-10 · **SP**: 3 · **MoSCoW**: **Should** *(hạ từ Must theo Gate 1 D2: máy trạm Linux ưu tiên sau macOS + Windows)* · **Trace**: PLAT-03(b), REL-13
- **Story**: Là *home-lab self-hoster*, tôi muốn cài agent lên **máy trạm/NAS Linux desktop** như service chuẩn trên Ubuntu LTS và không phá cấu hình mạng khác (NetworkManager/`systemd-resolved`), để cài lên NAS yên tâm. **Tái sử dụng** agent Linux (`US-014`) và unit `systemd` quyền tối thiểu đã làm cho VPS-node ở `US-056 AC4`; **phần systemd/capability/quyền tối thiểu của VPS-node và container lab nằm ở `US-056`, `US-014`, `US-051` (đều `Must`) nên `PLAT-03(a)` P0 vẫn được phủ.**
- **Phụ thuộc**: US-014, US-056; `US-060` và `US-015` phải đạt DoD trước (ưu tiên macOS + Windows).
- **AC**:
  1. **[H]** *Given* **sau khi macOS + Windows đã đạt DoD**, trên một bản Linux desktop/Ubuntu LTS phổ biến, *When* cài và chạy, *Then* service tự bật khi boot, chạy với `CAP_NET_ADMIN` (+`CAP_NET_RAW` nếu cần), tạo TUN qua `/dev/net/tun`; tự sống lại ≤ 10 s sau `kill -9`.
  2. **[E]** *Given* hệ thống dùng nftables hoặc iptables, *When* agent chạy, *Then* tương thích cả hai; không flush rule có sẵn.
  3. **[E]** *Given* chạy agent, *When* kiểm tra `/etc/resolv.conf`, *Then* **không bị ghi đè**.
  4. **[F]** *Given* gỡ service, *When* hoàn tất, *Then* không còn rule/route/interface do agent tạo.

### US-055 — Graceful shutdown, dọn dẹp lúc khởi động & lệnh `down`/`cleanup`
- **Epic**: EP-10 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-08, REL-09, PLAT-04, PLAT-06
- **Story**: Là *chủ mạng*, tôi muốn dù agent bị tắt/crash thế nào (**trên macOS, Windows hay Linux**), máy vẫn ra Internet bình thường và lần khởi động sau tự dọn rác, để VPN không bao giờ làm hỏng mạng máy chính.
- **Phụ thuộc**: US-014, US-015, US-060, US-073, US-038.
- **AC**:
  1. **[H]** *Given* dừng service (SIGTERM, `systemctl stop`, **`launchctl bootout`/dừng LaunchDaemon trên macOS**, Windows Service Stop, tắt máy), *When* dừng, *Then* trong ≤ 5 s agent: gỡ route overlay, khôi phục hosts, xóa interface/adapter (**macOS: chỉ đúng `utunN` của chính phiên agent; gỡ anchor `pf`/ngoại lệ firewall do agent tạo**), đóng kết nối relay/control (báo offline); bảng route và DNS trở về như trước khi chạy.
  2. **[F]** *Given* `kill -9` agent (**macOS, Windows và Linux VPS-node**), *When* khởi động lại, *Then* phát hiện & dọn tàn dư (adapter ma, **`utunN` cũ**, route mồ côi, khối hosts cũ, **anchor `pf`/quy tắc firewall của chính agent**) **dựa trên tệp trạng thái phiên trước** **trước khi** dựng mới; không trùng lặp; Internet máy thật **không bị gián đoạn > 3 s ở mọi bước** (probe liên tục).
  3. **[H]** *When* chạy `down` hoặc `cleanup` thủ công, *Then* trả máy về trạng thái sạch, idempotent (chạy 2 lần không lỗi).
  4. **[F]** *Given* thiết bị mất điện đột ngột, *When* bật lại, *Then* như (2).
  5. **[E]** *Given* tắt agent khi đang có phiên TCP qua tunnel, *When* dừng, *Then* các phiên đó đứt gọn (không treo máy/không chiếm CPU).
  6. **[E]** *Given* macOS đang chạy **iCloud Private Relay hoặc VPN/WireGuard khác** (có `utunK` riêng), *When* chạy `down`/`cleanup`/uninstall hoặc agent crash rồi khởi động lại, *Then* **chỉ tài nguyên của agent** (đúng `utunN` ghi trong tệp trạng thái, route overlay, khối hosts, anchor `pf`, ngoại lệ firewall) bị gỡ; `ifconfig`/`netstat -rn`/`pfctl -s rules` của phần không thuộc agent giữ nguyên trước/sau (REL-08).

### US-056 — VPS là một node của mesh (agent Linux dưới `systemd`, quyền tối thiểu)
- **Epic**: EP-10 · **SP**: 3 *(tái ước lượng 2→3: gánh phần `systemd`/capability/quyền tối thiểu của `PLAT-03(a)` chuyển từ `US-054`)* · **MoSCoW**: Must (theo A-05/OQ-03 ✅ đã chốt Gate 1: `vps.mesh.internal`) · **Trace**: REL-09, SEC-14, SEC-06, PLAT-03(a), §4.1
- **Story**: Là *chủ mạng*, tôi muốn truy cập các dịch vụ riêng tư trên VPS qua IP overlay, để không phải mở thêm cổng dịch vụ ra Internet.
- **Phụ thuộc**: US-004, US-014, US-016, US-038.
- **AC**:
  1. **[H]** *Given* agent cài trên VPS như một node (với tên node khác domain public của Control/Relay/STUN theo `US-004 AC3`, vd. `vps`), *When* các máy khác (**macOS, Windows**) `ssh <overlay_ip_vps>` hoặc `ssh vps.mesh.internal`, *Then* kết nối thành công mà không mở thêm cổng dịch vụ ra Internet (lưu ý: kênh Admin của Control vẫn khóa cục bộ trên VPS theo `SEC-14`, không mở trên `overlay_ip_vps`).
  2. **[F]** *Given* VPS vừa chạy Control/Relay/STUN vừa là node, *When* chạy đồng thời test routing loop (`US-016`), test ghi `hosts` (`US-038 AC5`) và test relay/STUN, *Then* 0 sự cố vòng lặp mạng/DNS, 0 mất Internet/mất dịch vụ.
  3. **[E]** *Given* (OQ-03 đã chốt **Có**; nếu sau này đổi thành Không) không muốn VPS là node, *When* bỏ qua, *Then* các story còn lại không bị ảnh hưởng.
  4. **[H]** *Given* agent trên VPS Ubuntu LTS, *When* cài và chạy, *Then* chạy dưới `systemd` (tự bật khi boot; tự sống lại ≤ 10 s sau `kill -9`), **thành phần agent** có `CAP_NET_ADMIN` (+`CAP_NET_RAW` nếu cần) tạo TUN qua `/dev/net/tun` và **tách biệt** khỏi tiến trình Control/Relay/STUN chạy user không đặc quyền (SEC-06(4), `US-051 AC6`); unit bật các cờ cô lập (`NoNewPrivileges`, `ProtectSystem`… hoặc tương đương).
  5. **[E]** *Given* VPS dùng `nftables`/`iptables`/`ufw` hoặc đang chạy dịch vụ cá nhân, *When* agent VPS-node chạy, *Then* tương thích cả hai, **không flush/xóa rule có sẵn**, **`/etc/resolv.conf` không bị ghi đè**; agent VPS-node áp dụng đầy đủ chống routing loop (`US-016`) vì VPS vừa là relay vừa là node.
  6. **[F]** *Given* gỡ service agent trên VPS (hoặc dừng container lab), *When* hoàn tất, *Then* không còn rule/route/interface do agent tạo; Control/Relay/STUN vẫn chạy bình thường.

---

## 12. EP-11 — Kiểm thử NFR/SLO, Phòng lab mạng & Runbook (Enabler)

> Mục tiêu: các cam kết Production được **đo** chứ không chỉ nói. (Persona P1; phục vụ `agile-qa`)

### US-057 — Phòng lab mạng giả lập (NAT, chặn UDP, MTU thấp, mất gói, đổi IP, sleep/wake)
- **Epic**: EP-11 · **SP**: 8 · **MoSCoW**: Must · **Trace**: Go-Live checklist, R-12
- **Story**: Là *chủ mạng/QA*, tôi muốn môi trường lặp lại được để mô phỏng Easy/Hard NAT, chặn UDP, Captive Portal, MTU 1400, mất gói, đổi IP và nhảy đồng hồ sau sleep, để kiểm chứng tự động các tiêu chí chịu lỗi.
- **Phụ thuộc**: không (làm sớm; chặn US-021/022/028/035/036).
- **AC**:
  1. **[H]** *When* khởi chạy lab bằng một lệnh, *Then* dựng ≥ 5 node (container Linux với quyền tối thiểu `NET_ADMIN` + `/dev/net/tun`, **không `--privileged`**; **Windows và macOS qua VM/runner/máy thật khi có — macOS không giả lập được trong container Linux**) + 1 "VPS" mô phỏng (hỗ trợ topo Standalone cổng mặc định `443`, Standalone **cổng tùy chọn `8443` + UDP `3479`**, **chế độ IP + Pin** và sau Reverse Proxy) với các kịch bản: EIM, Port-Dependent NAT (APDM), UDP-block, 443-only, **chỉ cho outbound TCP 80/443 (kèm relay ở cổng khác 443)**, Captive Portal/TLS giả, **MITM với chứng chỉ CA hợp lệ cho đúng IP nhưng sai pin**, MTU 1400 + chặn ICMP frag-needed, độ trễ/mất gói cấu hình được.
  2. **[E]** *Given* kịch bản, *When* chạy lại 10 lần, *Then* kết quả lặp lại (flaky < 5%).
  3. **[H]** *Given* các hành động: `kill -9` agent/Control, chặn/mở UDP, đổi IP (flap), mô phỏng `power-resume + nhảy đồng hồ > 180 s + xóa bảng NAT mapping` (phục vụ 20 vòng tự động của `US-036 AC2`), *When* script hóa, *Then* gọi được từ test tự động (CI hoặc chạy cục bộ).
  4. **[F]** *Given* lab dọn dẹp, *When* kết thúc, *Then* không để lại cấu hình mạng trên máy chủ chạy lab (kiểm tra trước/sau).
  5. **[E]** *Given* các kịch bản **phụ thuộc macOS** (`utun`/`launchd`/Application Firewall/Gatekeeper/sleep-wake/`LOCAL_PEERCRED` — `US-060`, `US-073`, `US-035`) vốn không chạy được trong lab container Linux, *When* lập kế hoạch kiểm thử, *Then* có **bộ script chạy trên máy Mac thật/VM trên phần cứng Apple/runner macOS** (kể cả Apple Silicon + Intel) và **biên bản thủ công** cho phần không tự động hóa được; hạ tầng macOS được liệt kê rõ làm điều kiện tiên quyết (GNFR-12).

### US-058 — Bộ kiểm thử NFR/SLO & Go-Live tự động
- **Epic**: EP-11 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PERF-01..12, SEC-14, SEC-15, PLAT-06, Go-Live checklist
- **Story**: Là *chủ mạng/QA*, tôi muốn một lệnh chạy toàn bộ kiểm tra SLO & checklist Go-Live và xuất báo cáo, để quyết định lên Production có cơ sở.
- **Phụ thuộc**: US-057, và các story liên quan.
- **AC**:
  1. **[H]** *When* chạy bộ test, *Then* xuất báo cáo (JSON + Markdown) cho: PERF-01/02/03/04/05/06/07/08/09/10/11, REL-01/06/08/09/10/12, SEC-01/03/04/05/06/07/08/14/15, PLAT-04/05/06, OPS-02/03 với giá trị đo, ngưỡng, PASS/FAIL (các phép đo phía client chạy trên **macOS — Apple Silicon + Intel — và Windows**; kết quả macOS lấy từ biên bản/script trên máy Mac thật).
  2. **[E]** *Given* SLO là đề xuất chưa đo, *When* kết quả không đạt, *Then* báo cáo ghi rõ "lệch so với đề xuất" và số liệu thực để Gate 3 quyết định hiệu chỉnh (không âm thầm đổi ngưỡng).
  3. **[F]** *Given* một mục go-live FAIL, *When* chạy, *Then* mã thoát khác 0 (chặn release trong CI).

### US-059 — Runbook vận hành & Go-Live checklist
- **Epic**: EP-11 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-12, SEC-06, SEC-08, R-09
- **Story**: Là *chủ mạng*, tôi muốn có tài liệu từng bước để cài đặt an toàn trên VPS đang dùng và xử lý sự cố mà không phải nhớ, để 3 tháng sau vẫn thao tác chuẩn xác.
- **Phụ thuộc**: US-029, US-045, US-051, US-073, US-074.
- **AC**:
  1. **[H]** *Given* runbook, *When* người thứ hai làm theo (diễn tập kiểm chứng) các quy trình: cài server (cả Standalone lẫn sau Nginx/Caddy có sẵn; **chế độ IP + Pin, chọn cổng `8443`…, xử lý xung đột cổng, nhắc cloud security group**), **thêm MacBook (cài LaunchDaemon bằng luồng không phụ thuộc trình duyệt + kiểm SHA-256, xử lý Application Firewall opt-in) và máy Windows bằng lệnh tham gia `IP:cổng + pin`**, thêm máy headless bằng `--authkey-file`, **mất laptop (MacBook/Windows) → thu hồi** (kể cả kịch bản đầy đĩa), restore backup (**kèm khóa định danh server, không phải pin lại**) + công thức mẫu đồng bộ backup mã hóa ra ngoài VPS bằng công cụ chuẩn (`restic`/`rclone`… — `US-045 AC3`), nâng cấp & rollback, xoay chứng chỉ/khóa server, **đổi cổng/IP/chế độ xác thực server (`US-074`) và cập nhật máy offline bằng `mesh set` cục bộ**, xử lý "Control chết" — *Then* hoàn thành mỗi quy trình trong ≤ 30 phút không cần hỏi thêm.
  2. **[E]** *Given* runbook, *When* kiểm tra, *Then* nêu rõ **giới hạn đã biết**: thu hồi không hiệu lực khi Control chết (`US-033`/`US-031`), hard NAT↔hard NAT luôn đi relay (`A-10`), VPS là root of trust (`A-09`), giới hạn phân loại NAT khi chỉ dùng 1 IP STUN (`US-019 AC2`), **cổng TCP khác `443` không lọt được mạng khóa cứng ngoài 80/443 (`REL-06`, `US-024 AC7`), cổng UDP STUN bị chặn chỉ mất P2P (vẫn có relay), bản macOS MVP chưa ký Developer ID/notarize (cài qua luồng không phụ thuộc trình duyệt; `.pkg` notarized là Phase 2+), Application Firewall macOS có thể giảm P2P nếu người dùng từ chối ngoại lệ (relay vẫn chạy), mất khóa định danh server buộc pin lại toàn bộ máy (`US-045`), cloud security group nằm ngoài VPS nên không tự động hóa được**.
  3. **[F]** *Given* checklist Go-Live, *When* mỗi mục, *Then* có bằng chứng (đường dẫn log/báo cáo) từ US-058 và biên bản sleep phần cứng thật của `US-036 AC2`.

---

## 13. EP-12 — Phase 2+ (Mở rộng, **không** thuộc MVP)

> Mục tiêu: giữ lại tầm nhìn mà không phình phạm vi. Mỗi story bên dưới chỉ được kéo vào Sprint khi **điều kiện kích hoạt** đạt và được người dùng duyệt qua Gate. AC rút gọn (sẽ chi tiết hóa ở Backlog Refinement).

| Story | Tên | SP | MoSCoW | Điều kiện kích hoạt | AC rút gọn (Given/When/Then) |
|---|---|:-:|:-:|---|---|
| **US-061** | Client Android/iOS | 8 | **Won't** (kỳ này) | Có nhu cầu di động | *Given* app VpnService/NetworkExtension, *When* bật, *Then* truy cập máy trong mesh; pin/băng thông nền đo được — **chưa lên lịch** |
| **US-062** | Tách machine key / node key + xoay tự động | 8 | Could | Cần xoay khóa không đăng ký lại | *Given* node key sắp hết hạn, *When* agent tự xoay, *Then* tunnel không đứt và machine identity giữ nguyên; node key cũ bị vô hiệu ≤ 10 s |
| **US-063** | Netmap delta | 5 | Could | > 50 node/churn cao | *Given* 100 node, *When* 1 thay đổi, *Then* bản cập nhật ≤ 5% kích thước snapshot; áp dụng đúng và có đường fallback sang snapshot khi lệch version |
| **US-064** | Hard-NAT ↔ Hard-NAT (birthday paradox) + UPnP/NAT-PMP/PCP | 8 | Could | Relay chiếm tỉ lệ cao ở `status` | *Given* 2 node hard NAT (lab), *When* đục lỗ, *Then* tỉ lệ direct ≥ 60% trong 30 s; không bị coi là quét cổng (giới hạn tốc độ ≤ 100 pkt/s/peer) |
| **US-065** | Relay UDP/QUIC, nhiều relay/region, peer relay | 8 | Could | Băng thông VPS thành nút cổ chai | *Given* ≥ 2 relay, *When* một relay chết, *Then* node chuyển sang relay khác ≤ 10 s; relay UDP đạt throughput ≥ 1.5× relay TCP trong lab mất gói 1% |
| **US-066** | Split DNS chuẩn (resolver cục bộ, NRPT / systemd-resolved) | 8 | Could | Hosts file không đủ | *Given* resolver cục bộ, *When* phân giải `nas.mesh`, *Then* trả Overlay IP đúng ≤ 20 ms P95, truy vấn khác đi DNS gốc không đổi; tắt agent → DNS khôi phục |
| **US-067** | ACL theo nhóm/tag + packet filter nâng cao | 8 | Could | Chia sẻ mạng với người khác | *Given* chính sách `group:family → tag:nas:445`, *When* node family kết nối cổng khác, *Then* bị chặn ở agent **và** peer không xuất hiện trong netmap ngoài chính sách |
| **US-068** | Subnet router & Exit node (kèm xử lý routing loop đầy đủ) | 8 | Could | Cần truy cập LAN nhà/duyệt qua VPS | *Given* exit node bật, *When* client dùng default route qua overlay, *Then* socket agent vẫn đi qua interface vật lý (0 routing loop), tắt tính năng khôi phục route 100% |
| **US-069** | Ký node key kiểu Tailnet Lock | 8 | Could | Muốn giảm tin cậy VPS | *Given* Control bị chiếm và chèn node giả, *When* agent nhận netmap, *Then* peer thiếu chữ ký hợp lệ bị từ chối (test chèn node giả = 100% bị từ chối) |
| **US-070** | OIDC/SSO, Web UI, đa người dùng | 8 | **Won't** (kỳ này) | Có người dùng ngoài bản thân | *Given* IdP OIDC, *When* đăng nhập, *Then* cấp node theo user; — **chưa lên lịch** (OQ-10) |
| **US-071** | Kernel WireGuard / WireGuardNT để tăng throughput | 5 | Could | CPU thành nút cổ chai | *Given* kernel mode, *When* `iperf3` direct, *Then* throughput ≥ 1.5× userspace (PERF-04) mà STUN/disco vẫn đục lỗ được |
| **US-072** | HA control plane / multi-region / multi-tenant | 8 | **Won't** | Không dự kiến | — (không áp dụng ở tầm nhìn hiện tại) |

> [!NOTE]
> **`US-060` (Client macOS) đã được chuyển ra khỏi EP-12 và nâng lên `Must` trong `EP-03`** theo quyết định Gate 1 D1 (2026-11-12); daemon `launchd` tương ứng là `US-073` (`EP-10`). Phần **`PLAT-07` (P2)** còn lại — bản macOS có GUI/menu bar hoặc System/Network Extension kèm **Developer ID + notarization + `.pkg`**, Windows on ARM (`arm64`), gói Linux desktop có GUI, split DNS chuẩn macOS `/etc/resolver` — **chưa có story riêng**: sẽ được tách thành story khi Backlog Refinement kích hoạt (gần nhất: `US-061` cho di động, `US-066` cho split DNS). Mọi story Phase 2+ chỉ được kéo vào Sprint qua Gate.

---

## 14. Ma trận truy vết Yêu cầu Production → Story

> Đảm bảo **không bỏ sót** yêu cầu sống còn của `production-readiness-requirements.md`.

| Yêu cầu | Ưu tiên NC | Story phủ | Ghi chú |
|---|:-:|---|---|
| SEC-01 | P0 | US-001, US-033, US-039, US-041, US-043, US-073, GNFR-02 | Bao gồm phân quyền chặt thư mục/tệp khóa & cache Netmap trên **macOS (`root:wheel`, `0700`/`0600`)**, Windows, Linux |
| SEC-02 | P0 | US-003, US-009, US-014, US-060, US-021, US-024, US-025, GNFR-01 | ADR thư viện & tách khóa disco do Tech Lead/Architect chốt Gate 2 |
| SEC-03 | P0 | US-002, US-004, US-005, US-031 (one-time/TTL/hash/revoke/`--for`); US-006 (reusable/ephemeral — Should, xem OQ-06) | **Điều chỉnh có chủ đích**: phần "tùy chọn" hạ xuống Should để Gate 1 xác nhận |
| SEC-04 | P0 | US-003, US-024, US-034, US-047, US-046, US-051, US-074, GNFR-11 | **IP + Pin là luồng chính thức từ M1 (cấm TOFU, không cờ bỏ qua pin)**; Standalone ACME không cần cổng 80 (`TLS-ALPN-01` chỉ ở cổng 443, cổng khác dùng `DNS-01`), Reverse Proxy; **cổng TCP/UDP cấu hình được** |
| SEC-05 | P0 | US-042 | Kèm `trusted_proxies` tường minh, constant-time hash compare |
| SEC-06 | P0 | US-046, US-051, US-024, US-044, US-048, US-056, US-074, GNFR-11 | An toàn với VPS dùng chung; firewall mặc định deny là `opt-in` có auto-rollback |
| SEC-14 | P0 | US-012, US-046, US-002, US-029, US-044, US-048, US-058, US-074 | **Khắc phục `BLK-01`**: tách kênh Admin cục bộ kiểm chứng quyền OS khỏi listener chỉ-đọc; cấm mở Admin trên IP overlay / TCP `127.0.0.1` trần |
| SEC-15 | P0 | US-074, US-009, US-003, US-004, US-012, US-047, US-046, US-045, US-052, US-073, US-019, US-024, US-013 | **Mới ở v1.2**: (1) bootstrap tối giản, `relay_map` (Relay/STUN `IP:cổng`) phân phối qua Netmap `US-009 AC6`/`US-004 AC7`; (2) đổi cổng/IP/chế độ xác thực/xoay khóa server qua kênh Admin, nghe song song cổng cũ+mới (`US-074`); (3) agent offline → `mesh set --server … --server-pin …` bởi admin máy cục bộ, user thường bị từ chối (`US-052`/`US-073`); (4) giữ node key/Overlay IP/tên, không cần pre-auth key mới; backup gồm khóa định danh server (`US-045`) |
| SEC-07 | P0 | US-024, US-025, US-027, US-029 | Kèm `src_pubkey` do Relay gắn + hàng đợi giới hạn mỗi đích drop không chặn |
| SEC-08 | P0 | US-029, US-030, US-031, US-013, US-032 | Key rotation thủ công: US-032 (Should); `revoke` chạy trong RAM khi đĩa đầy |
| SEC-09 | P0 | US-013, US-074 | Append-only ứng dụng + xuất journald/stderr |
| SEC-10 | P1 | US-011, US-038 | Kiểm tên node chống chèn dòng `hosts` (server + agent) |
| SEC-11 | P1 | US-014, US-015, US-060, US-018 | AllowedIPs /32 là Must (trong US-014/015) |
| SEC-12/13 | P2 | US-069, US-067, US-070 | Phase 2+ |
| REL-01 | P0 | US-033, US-019, US-050, US-074 | Lưu bền cổng UDP cục bộ để P2P cache hoạt động qua NAT khi Control offline |
| REL-02 | P0 | US-004, US-005 | |
| REL-03 | P0 | US-009, US-010 | Không tăng `netmap_version` mỗi nhịp `last_seen` |
| REL-04 | P0 | US-034, GNFR-03 | Không dừng retry vĩnh viễn khi lỗi chứng chỉ/TLS môi trường |
| REL-05 | P0 | US-021, US-022, US-026 | Disco có xác thực mật mã + chống replay; keepalive on-demand |
| REL-06 | P0 | US-024, US-026, US-028, US-023 | Cổng TCP cấu hình được; ghi chú trung thực: chỉ cổng `443` lọt mạng khóa ngoài 80/443; agent chẩn đoán rõ khi cổng khác 443 không tới được (`US-024 AC7`, `US-028 AC4`, `US-023 AC4`) |
| REL-07 | P0 | US-035, US-036 | macOS (+ Linux VPS/lab) ở `US-035`; Windows ở `US-036` |
| REL-08 | P0 | US-055, US-052, US-038, US-060, US-073 | macOS: chỉ đúng `utunN` của phiên, không đụng `utun` khác |
| REL-09 | P0 | US-016, US-020, US-038, US-056, US-060, US-035 | Bao gồm chặn tên cấm/domain Control/Relay + IP public VPS trong `hosts`, lọc interface ảo (kể cả `utun*`/`awdl0` macOS); ràng socket vào interface vật lý trên macOS/Windows/Linux |
| REL-10 | P0 | US-017, US-060 | MTU 1280; socket UDP ngoài không ép cứng `DF=1` |
| REL-11 | P0 | US-007 | |
| REL-12 | P0 | US-045, US-051, US-059, US-047 | Backup cục bộ nhất quán + checksum + restore **gồm khóa định danh server (không phải pin lại)**; đồng bộ mã hóa ngoài qua Runbook |
| REL-13 | P1 | US-051, US-052, US-073, US-056, US-054 | Đưa lên Must vì cần 24/7 (macOS `launchd` `US-073`; Linux VPS-node `US-056`/`US-051`; Windows `US-052`); `US-054` (Should) cho máy trạm Linux |
| REL-14 | P1 | US-008, US-037 | |
| REL-15 | P2 | US-064, US-065, US-072 | |
| OPS-01 | P0 | US-043 | |
| OPS-02 | P0 | US-039 | Hiển thị `IP:cổng` server, chế độ pin/CA + fingerprint, tên interface (`utunN`) — `US-039 AC7` |
| OPS-03 | P0 | US-040 | |
| OPS-04 | P1 | US-023, US-019 | Ghi rõ giới hạn phân loại NAT khi chỉ có 1 IP STUN; báo khả năng tới cổng TCP/UDP đã cấu hình (`US-023 AC4`) |
| OPS-05 | P0 | US-044 | Listener chỉ-đọc riêng; `/readyz` kiểm đúng cổng đã cấu hình |
| OPS-06 | P1 | US-048 | Listener chỉ-đọc riêng |
| OPS-07 | P1 | US-049, US-047 | |
| OPS-08 | P0 | US-002, US-012, US-029, US-045, US-074 | Truy cập qua kênh cục bộ kiểm chứng đặc quyền OS (`SEC-14`); lệnh tham gia in sẵn `IP:cổng` + pin + key (`US-002 AC6`); `server info` (`US-012 AC6`); đổi cổng/pin (`US-074`) |
| OPS-09 | P1 | US-041 | |
| OPS-10 | P1 | US-050 | Gửi kèm OS + kiến trúc (`darwin/arm64`, `darwin/amd64`, `windows/amd64`, `linux/amd64`) |
| PERF-01/02 | — | GNFR-04/06, US-009, US-024, US-058 | |
| PERF-03/04 | — | GNFR-08/09, US-014, US-060, US-058 | Đo trên macOS (Apple Silicon + Intel), Windows, Linux VPS-node |
| PERF-05 | — | US-021, US-026, US-058 | |
| PERF-06 | — | US-022, US-028, US-058 | |
| PERF-07 | — | US-035, US-036, US-058 | 20 vòng tự động + 2–3 lần kiểm chứng sleep phần cứng thật ≥ 4 phút **trên MacBook và laptop Windows** |
| PERF-08 | — | US-004, US-009, US-074, US-058 | Gồm lan truyền đổi cổng STUN/Relay (`SEC-15`) |
| PERF-09/10 | — | GNFR-05/07, US-009, US-022, US-060, US-058 | RAM agent idle đo trên macOS/Windows |
| PERF-11 | — | US-025, US-027 | |
| PERF-12 | — | GNFR-10, US-033, US-049 | |
| PLAT-01 | P0 | US-015, US-052 | |
| PLAT-02 | P0 | US-053 | |
| PLAT-03 | **(a) P0** / (b) P1 | (a) US-014, US-051, US-056; (b) US-054 (Should) | (a) Linux VPS-node + container lab: `systemd`, `CAP_NET_ADMIN`, không flush firewall, không ghi đè `resolv.conf`, lab không `--privileged`; (b) máy trạm Linux sau macOS + Windows |
| PLAT-04 | P0 | US-004, US-012, US-038, US-055, US-073 | Bảo toàn ACL đọc Windows, symlink `/etc/hosts` macOS (`root:wheel 0644`, xả cache `dscacheutil`/`mDNSResponder`, `scutil --dns` không đổi) & hỗ trợ bind-mount `/etc/hosts` trong container |
| PLAT-05 | **P0** (macOS, Windows) / P1 (Linux VPS) | US-035, US-036 | REL-07 (P0) phụ thuộc; macOS + Windows là thiết bị roaming chính |
| PLAT-06 | **P0** | US-060, US-073, US-035, US-038, US-055, US-016, US-017, US-001 | macOS 13+ `arm64` + `amd64`: `utun`, `launchd` daemon (đường dẫn root-only), IPC `LOCAL_PEERCRED`, cài không phụ thuộc trình duyệt + SHA-256, Application Firewall opt-in + `pf` anchor riêng, gỡ sạch |
| PLAT-07 | P2 | US-061, US-066 (một phần) | Phase 2+: notarize/`.pkg`, GUI, Windows ARM, Linux desktop GUI, split DNS — chưa có story riêng (xem ghi chú EP-12) |

**Hiệu chỉnh ưu tiên so với nghiên cứu (minh bạch)**: (a) REL-13 (P1) → Must vì REL-07/24-7 phụ thuộc; PLAT-05 đã là P0 (macOS, Windows) ở `production-readiness-requirements.md` v1.2; (b) SEC-03 phần reusable/ephemeral → Should; (c) SEC-10, SEC-11 phần packet filter, OPS-04/06/07/09/10, REL-14 → Should (P1, cắt được khi trễ); (d) **`PLAT-03(b)` (gói Linux máy trạm, P1) = `US-054` Should**, còn `PLAT-03(a)` (P0) là Must qua `US-014`/`US-051`/`US-056`.

> [!NOTE]
> **Kiểm tra phủ yêu cầu v1.2:** `SEC-01..15` (15/15), `REL-01..15` (15/15), `OPS-01..10` (10/10), `PERF-01..12` (12/12), `PLAT-01..07` (7/7, riêng PLAT-07 là P2 chưa có story riêng) đều có ít nhất 1 story/NFR phủ. Chốt chặn Gate 1 vòng 2 được bảo toàn: `SEC-14` → `US-012`, `US-046`, `US-044`, `US-048`; `BLK-01..03`, `HR-01..03`, `IMP-01..04` giữ nguyên AC (chỉ mở rộng sang macOS/cổng/pin).

---

## 15. Tóm tắt phạm vi & Gợi ý lát cắt phân phối (để Scrum Master/Tech Lead tham khảo — **không** phải Sprint Plan)

### 15.1. Tổng quan

| Nhóm | Số story | Tổng SP | Ghi chú |
|---|:-:|:-:|---|
| Must (MVP) | 51 | **234** | = Milestone 1 (38 story / 174 SP) + Milestone 2 (13 story / 60 SP) — xem 15.3 |
| Should (cắt được, vẫn thuộc MVP+) | 11 | **35** | `US-006, 011, 018, 023, 032, 037, 041, 048, 049, 050, 054` |
| Phase 2+ (Could / Won't — EP-12) | 12 | (không tính) | `US-061..072` |
| **Tổng** | **74** | | `US-001..074` |

**Đối chiếu v1.1 → v1.2 (để chứng minh không lệch):** v1.1 = 49 Must / 215 SP, 10 Should / 32 SP, 13 Phase 2+ (72 story). Thay đổi: `+US-060` (EP-12 → Must, +5 SP, −1 Phase 2+) · `+US-073` (Must, +5 SP) · `+US-074` (Must, +3 SP) · `US-054` Must → Should (−3 SP Must, +3 SP Should) · tái ước lượng `US-035` +3, `US-046` +2, `US-047` +3, `US-056` +1 (= +9 SP Must). ⇒ Must: 49 + 3 − 1 = **51** story; SP: 215 + 5 + 5 + 3 − 3 + 9 = **234**. Should: 10 + 1 = **11** story; 32 + 3 = **35** SP. Phase 2+: 13 − 1 = **12**. Tổng story: 72 + 2 (`US-073`, `US-074`) = **74**.

### 15.2. Gợi ý lát cắt giá trị theo 2 Milestone (OQ-14 ✅ — Walking Skeleton → Dùng hằng ngày → An toàn & Production)

> Mỗi story `Must` được gán vào **đúng 1** lát cắt (không đếm trùng). Số liệu từng lát cắt và tổng đã đối soát với 15.1.

#### Milestone 1 — Walking Skeleton + Direct P2P dùng hằng ngày trên macOS + Windows ↔ VPS (**38 story / 174 SP**)

| Lát cắt | Nội dung | Story `Must` | Story / SP | Lý do |
|---|---|---|:-:|---|
| **S0 — Nền kiểm thử** | Phòng lab container Linux + structured log | US-057, US-043 | 2 / 11 | Giảm rủi ro R-12; mọi AC chịu lỗi cần lab; macOS/Windows thật kiểm bằng biên bản (GNFR-12) |
| **S1 — Walking Skeleton + kênh Admin + IP/Pin (relay-only; VPS-node Linux ↔ node lab/macOS)** | Khóa → pre-auth key → kênh control TLS **pin** → đăng ký → netmap (`relay_map`) → tunnel Linux qua relay; **khung IPC Admin cục bộ `US-012` + `US-002` + audit `US-013` cùng lát cắt** (ghi chú Critic) | US-001, 002, 003, 004, 005, 007, 008, 009, 010, 012, 013, 014, 024, 025, 026, 047 | 16 / 73 | Có mạng dùng được sớm; `US-047` (Pin) vào S1 vì **không có pin thì client không được phép kết nối** (cấm TOFU); `US-013` cần cho audit của `US-002`; `US-012` AC4 khóa kênh Admin ngay từ đầu (`SEC-14`/`BLK-01`) |
| **S2 — Direct P2P + chẩn đoán** | STUN (cổng cấu hình được), hole punching có xác thực, chuyển mạch direct↔relay, `status`/`ping`, kịch bản UDP-block | US-019, 020, 021, 022, 028, 039, 040 | 7 / 34 | Giá trị chính "P2P trực tiếp"; `US-021` phụ thuộc relay (S1) |
| **S3 — Nhóm triển khai VPS** | Cài/nâng cấp server tự khởi động, hardening + kiểm tra xung đột cổng + firewall `opt-in`, listener `/healthz` `/readyz` | **US-046 + US-051** (gom cùng nhóm vì phụ thuộc vòng), US-044 | 3 / 12 | Ghi chú Critic: gom `US-046` + `US-051`; cổng TCP/UDP cấu hình được ngay từ lần cài đầu (GNFR-11) |
| **S4 — Client macOS + Windows, dọn dẹp, VPS-node** | `utun` macOS, daemon `launchd`, adapter + service + firewall Windows, chống routing loop, MTU, hosts `.mesh.internal` (+ xả cache DNS macOS/Windows), graceful shutdown/cleanup, VPS là node | US-060, 073, 015, 052, 053, 016, 017, 038, 055, 056 | 10 / 44 | Chặn R-02/R-05 trước khi dùng thật; macOS + Windows ↔ VPS dùng hằng ngày (D1) |

#### Milestone 2 — Roaming/Sleep-Wake, Key Expiry, Hardening, Rate-limit/Quota, NAT Chaos & Packaging (**13 story / 60 SP**)

| Lát cắt | Nội dung | Story `Must` | Story / SP | Lý do |
|---|---|---|:-:|---|
| **S5 — Vòng đời & chịu lỗi** | Thu hồi tức thì + gỡ peer sống, **Key Expiry** + đăng ký lại `--for`, control chết data sống (cache phân quyền), reconnect backoff + jitter | US-029, 030, 031, 033, 034 | 5 / 21 | Yêu cầu sống còn Production (SEC-08, REL-01, REL-04) |
| **S6 — Roaming & Sleep/Wake** | Đổi mạng/sleep-wake macOS (+ Linux VPS/lab) và Windows; P95 ≤ 15 s | US-035, 036 | 2 / 13 | PERF-07 trên MacBook + laptop Windows thật |
| **S7 — Hardening, Rate-limit/Quota & đổi cổng** | Rate-limit/anti brute-force + `trusted_proxies`, hạn mức băng thông relay, backup/restore (gồm khóa server), **đổi cổng/IP/pin không mất danh tính** | US-042, 027, 045, 074 | 4 / 18 | Đủ 24/7; `US-074` (`SEC-15`) cần `US-009` (`relay_map`) đã có từ S1 |
| **S8 — NAT Chaos Lab đầy đủ, nghiệm thu Go-Live & Packaging** | Bộ NFR/SLO + chaos tự động, runbook (cài macOS/Windows/VPS, đổi cổng, restore) | US-058, 059 | 2 / 8 | Gate 3; lab nền `US-057` đã dựng ở S0 (cần sớm cho `US-021/022/028`), S8 chạy toàn bộ kịch bản chaos & đóng gói tài liệu |

| Tổng kiểm | Story | SP |
|---|:-:|:-:|
| Milestone 1 (S0+S1+S2+S3+S4) | 2 + 16 + 7 + 3 + 10 = **38** | 11 + 73 + 34 + 12 + 44 = **174** |
| Milestone 2 (S5+S6+S7+S8) | 5 + 2 + 4 + 2 = **13** | 21 + 13 + 18 + 8 = **60** |
| **Must (MVP)** | **51** | **234** |

#### Lát cắt Should-have (cắt được; kéo vào lát cắt phù hợp nếu còn năng lực) — **11 story / 35 SP**

| Story `Should` | Gợi ý gắn vào | SP |
|---|---|:-:|
| US-006 (pre-auth key reusable/ephemeral) | Sau S1 | 3 |
| US-011 (agent validate netmap) | Sau S1 | 3 |
| US-023 (`netcheck`) | Sau S2 | 3 |
| US-018 (packet filter agent) | Sau S4 | 3 |
| US-054 (gói dịch vụ Linux máy trạm) | **Sau khi macOS + Windows đạt DoD** (S4) | 3 |
| US-032 (`rotate-key` thủ công) | Cùng S5 | 5 |
| US-037 (cảnh báo xung đột CGNAT) | Cùng S6 | 3 |
| US-048, US-049, US-050 (metrics, cảnh báo, versioning) | Cùng S7 | 3 + 3 + 3 |
| US-041 (`bugreport`) | Cùng S8 | 3 |
| **Tổng** | **11 story** | **35** (= 3+3+3+3+3+5+3+9+3) |

> **Lưu ý phụ thuộc vòng:** `US-021` phụ thuộc relay (`US-024..026`) — S1 làm relay trước S2 (mô hình "bắt đầu qua relay, nâng cấp direct"); `US-016` ↔ `US-056` và `US-046` ↔ `US-051` là phụ thuộc vòng nên được gom cùng lát cắt (S4, S3).
>
> **Rủi ro sử dụng Milestone 1 (minh bạch):** thu hồi thiết bị (`US-029/030`), reconnect backoff (`US-034`), rate-limit (`US-042`) và hạn mức relay (`US-027`) thuộc Milestone 2 theo quyết định OQ-14. Trong thời gian dùng M1 hằng ngày, chỉ nên kết nối thiết bị cá nhân tin cậy, dùng pre-auth key one-time TTL ngắn (`US-002`), bật firewall `opt-in` của VPS (`US-046`) và chấp nhận chưa có thu hồi tức thì. Đề xuất giảm rủi ro (câu hỏi mở **OQ-15** trong [project-charter.md](../01-discovery/project-charter.md)): kéo `US-029`, `US-030`, `US-034` (11 SP) từ S5 vào M1 ⇒ M1 = 41 story / 185 SP, M2 = 10 story / 49 SP; tổng không đổi (51 / 234).
