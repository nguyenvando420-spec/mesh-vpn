# Product Backlog — Mesh VPN Cá Nhân (kiểu Tailscale, tự host trên 1 VPS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-po-ba` |
| Ngày | 2026-11-12 |
| Phiên bản | 1.1 — Đã xử lý phản biện Gate 1 Vòng 1 |
| Nguồn | [reference-systems-benchmark.md](../01-discovery/reference-systems-benchmark.md) · [production-readiness-requirements.md](../01-discovery/production-readiness-requirements.md) |
| Liên kết | [vision-statement.md](../01-discovery/vision-statement.md) · [project-charter.md](../01-discovery/project-charter.md) · [user-personas.md](./user-personas.md) |
| Thành phần AI/SLM | **Không có** ⇒ không có AI/Data Epic |

### Lịch sử sửa đổi

| Phiên bản | Ngày | Nội dung |
|---|---|---|
| 1.0 | 2026-11-12 | Bản đầu trình `agile-critic` |
| 1.1 | 2026-11-12 | Khắc phục triệt để phản biện Gate 1 Vòng 1 (`gate-1-critique.md`): **`BLK-01`** (`US-012`, `US-046`, ma trận truy vết `SEC-14`), **`BLK-02`** (`US-034`, `US-003`, `US-047`), **`BLK-03`** (`US-009`, `US-021`, `US-025`, `US-031`), **`HR-01`** (`US-024`, `US-042`, `US-046`, `US-047`, `US-051`), **`HR-02`** (`US-004`, `US-012`, `US-038`), **`HR-03`** (`US-009`, `US-013`, `US-019`, `US-022`, `US-033`, `US-036`), **`IMP-01..04`** (`US-004`, `US-016`, `US-017`, `US-019`, `US-020`, `US-023`, `US-032`, `US-042`, `US-043`, `US-045`, `US-059`, `US-066`) |

---

## 0. Quy ước

### 0.1. Định dạng Story
- **ID**: `EP-xx`, `US-xxx`. **SP** (Story Points) ∈ {1, 2, 3, 5, 8}, **không story nào > 8**. **MoSCoW**: `Must` = MVP bắt buộc; `Should` / `Could` / `Won't` = Phase 2+ hoặc cắt được.
- **Trace**: mã yêu cầu nghiên cứu (`SEC-*`, `REL-*`, `OPS-*`, `PERF-*`, `PLAT-*`) được phủ bởi story đó.
- **Acceptance Criteria (AC)** dạng `Given / When / Then`, gắn nhãn: **[H]** Happy path · **[E]** Edge case · **[F]** Failure handling · **[N]** Non-functional/SLO (có ngưỡng định lượng). Mọi AC phải **đo kiểm tự động được** (test tích hợp/chaos trong phòng lab US-057) hoặc có kịch bản thủ công có biên bản cho case phụ thuộc hệ điều hành/phần cứng.
- **Các thuật ngữ**: *Agent* = tiến trình nền trên mỗi thiết bị; *Control* = máy chủ điều phối trên VPS; *Relay* = bộ chuyển tiếp mù trên VPS; *Netmap* = bản đồ peer do Control phân phối; *Overlay IP* = IP ảo của thiết bị; *Direct* = P2P trực tiếp.

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

---

## 1. Danh sách Epics

| Epic | Tên | Loại | Nhóm yêu cầu nghiên cứu | Stories | SP Must |
|---|---|---|---|---|---|
| **EP-01** | Đăng ký & Xác thực thiết bị an toàn | Functional | SEC-01..04, REL-02 | US-001..006 | 19 |
| **EP-02** | Đồng bộ Netmap & Quản lý Peer (Coordination) | Functional | REL-03, REL-11, SEC-09, SEC-10, SEC-14, OPS-08, REL-14 | US-007..013 | 23 |
| **EP-03** | Đường hầm mã hóa & Routing an toàn (Data Plane) | Functional | REL-09, REL-10, SEC-11, PLAT-01/03 | US-014..018 | 18 |
| **EP-04** | P2P NAT Traversal / Hole Punching | Functional | REL-05, PERF-05, OPS-04 | US-019..023 | 23 |
| **EP-05** | Chuyển tiếp Relay qua VPS & Chống lạm dụng | Functional + Security | REL-06, SEC-07, PERF-06, PERF-11 | US-024..028 | 26 |
| **EP-06** | Vòng đời thiết bị: Thu hồi / Key Expiry & Control-Data tách rời | Production-Readiness | SEC-08, REL-01, REL-04 | US-029..034 | 21 |
| **EP-07** | Tự khôi phục: Đổi mạng, Sleep/Wake, xung đột dải IP | Production-Readiness | REL-07, PLAT-05, REL-14 | US-035..037 | 10 |
| **EP-08** | Tên máy nội bộ (MagicDNS-lite) & CLI chẩn đoán | Functional | OPS-02/03/09, PLAT-04 | US-038..041 | 13 |
| **EP-09** | Vận hành & Bảo mật: Rate-limit, Log, Healthcheck, Backup, Hardening | Production-Readiness / Ops | SEC-04/05/06/14, OPS-01/05/06/07/10, REL-12/13 | US-042..051 | 28 |
| **EP-10** | Tích hợp nền tảng (Windows/Linux) & Dọn dẹp | Production-Readiness | PLAT-01..03, REL-08, REL-09 | US-052..056 | 18 |
| **EP-11** | Kiểm thử NFR/SLO, Phòng lab mạng & Runbook | Enabler | Go-Live checklist, PERF-* | US-057..059 | 16 |
| **EP-12** | Phase 2+ (Mở rộng) | Roadmap | Mục 7 benchmark; SEC-12/13; REL-15; PLAT-06 | US-060..072 | — |

**Tổng Must-have (MVP): 49 story / 215 SP · Should (cắt được): 10 story / 32 SP · Phase 2+ (EP-12): 13 story (không tính SP).**

---

## 2. EP-01 — Đăng ký & Xác thực thiết bị an toàn

> Mục tiêu: máy mới vào mạng an toàn bằng pre-auth key dùng-một-lần; private key không rời máy; đăng ký lặp không tạo trùng. (Persona P1, P2)

### US-001 — Sinh khóa & lưu khóa an toàn tại client
- **Epic**: EP-01 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-01, SEC-02, PLAT-01, PLAT-03
- **Story**: Là *chủ mạng*, tôi muốn agent **tự sinh cặp khóa ngay trên thiết bị** và chỉ gửi public key đi, để private key không bao giờ rời máy.
- **Phụ thuộc**: không (story khởi đầu).
- **AC**:
  1. **[H]** *Given* thiết bị chưa có khóa, *When* chạy agent lần đầu, *Then* một cặp khóa (curve theo giao thức data plane) được sinh cục bộ và lưu bền vững; private key không xuất hiện trong bất kỳ thông điệp mạng nào gửi tới Control/Relay (kiểm tra bằng bắt gói + schema thông điệp không có trường private key).
  2. **[H]** *Given* khóa đã tồn tại, *When* agent khởi động lại, *Then* dùng lại đúng khóa (public key không đổi).
  3. **[E]** *Given* Linux, *When* kiểm tra quyền file khóa, *Then* chỉ owner root đọc được (mode 0600); *Given* Windows, *Then* ACL chỉ gồm SYSTEM và Administrators (hoặc lưu bằng cơ chế bảo vệ của OS).
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

### US-003 — Kênh control bảo mật: TLS + chứng minh sở hữu khóa node bằng challenge/nonce ngẫu nhiên
- **Epic**: EP-01 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-02, SEC-04
- **Story**: Là *chủ mạng*, tôi muốn agent nói chuyện với Control qua kênh TLS đã xác thực và chứng minh nó nắm private key của node bằng challenge ngẫu nhiên từ server, để kẻ MITM hay kẻ mạo danh không chèn được và không bị lỗi lệch múi giờ dual-boot.
- **Phụ thuộc**: US-001, OQ-02 (chế độ triển khai TLS/domain hay pin).
- **AC**:
  1. **[H]** *Given* Control sử dụng chứng chỉ hợp lệ (ACME ở chế độ Standalone hoặc qua Reverse Proxy sẵn có trên VPS) **hoặc** chứng chỉ được pin lúc cài đặt (`SEC-04`), *When* agent kết nối, *Then* TLS ≥ 1.2 (ưu tiên 1.3) thành công và bước chứng minh sở hữu khóa node dùng **server-generated random challenge/nonce theo phiên** trên cấu trúc mật mã chuẩn (không phụ thuộc đồng hồ tuyệt đối của client) hoàn tất ≤ 2 s trong điều kiện RTT ≤ 100 ms.
  2. **[F]** *Given* một MITM/Captive Portal trình chứng chỉ giả hoặc không khớp pin, *When* agent kết nối, *Then* agent **từ chối**, log cảnh báo, **không** gửi bất kỳ pre-auth key/public key nào, và chuyển sang cơ chế thử lại an toàn (`US-034 AC4`).
  3. **[F]** *Given* build release, *When* tìm cờ/tham số "bỏ qua xác minh chứng chỉ", *Then* không tồn tại (kiểm tra tĩnh + test cấu hình).
  4. **[F]** *Given* node trình public key khác khóa mà nó chứng minh được (hoặc phát lại challenge của phiên cũ), *When* thử đăng nhập control, *Then* Control từ chối và ghi audit.
  5. **[E]** *Given* bước chứng minh khóa dùng nonce ngẫu nhiên của server, *When* đồng hồ client lệch nhẹ hoặc lệch múi giờ dual-boot Windows/Linux (vài giờ) nhưng vẫn nằm trong khoảng hiệu lực `NotBefore`..`NotAfter` thực tế của chứng chỉ TLS, *Then* kết nối vẫn thành công bình thường; *When* đồng hồ máy chưa đồng bộ (vd. máy headless vừa bật lại sau mất điện trước khi NTP chạy) làm thời gian rơi ra ngoài `NotBefore`/`NotAfter` của chứng chỉ TLS, *Then* agent từ chối kết nối an toàn, ghi log nêu rõ hạn chứng chỉ kèm **nghi vấn lệch đồng hồ hệ thống (clock skew)** và tự thử lại theo `US-034 AC4` (kết nối lại ngay khi NTP đồng bộ giờ).

### US-004 — Đăng ký thiết bị bằng pre-auth key & cấp Overlay IP bền vững
- **Epic**: EP-01 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-03, REL-02, REL-11, PLAT-04
- **Story**: Là *người dùng thiết bị*, tôi muốn chạy một lệnh cài đặt kèm pre-auth key (truyền an toàn không lộ trên danh sách tiến trình) để máy tự có tên hợp lệ và IP overlay cố định, để không phải cấu hình thủ công ở máy khác.
- **Phụ thuộc**: US-001, US-002, US-003, US-007, US-008.
- **AC**:
  1. **[H]** *Given* key one-time hợp lệ, *When* chạy `up` truyền key qua `--authkey-file <path>`, `stdin` (`--authkey-stdin`), biến môi trường (khuyến nghị cho máy headless để **không lộ key trong `ps aux` / `/proc/<pid>/cmdline` / shell history**; cờ `--authkey` chỉ dùng tương tác kèm cảnh báo) cùng `--name <tên>`, *Then* node được tạo, cấp **Overlay IP duy nhất** trong dải overlay, key chuyển sang `used`, các peer online nhận netmap mới (PERF-08: P95 ≤ 5 s).
  2. **[E]** *Given* thiết bị khởi động lại/mất điện, *When* agent lên lại, *Then* **Overlay IP không đổi** (bền vững theo node).
  3. **[F]** *Given* tên yêu cầu vi phạm định dạng (`[a-z0-9-]`, 1–63 ký tự, không mở đầu/kết thúc bằng `-`), trùng tên node đang có, **hoặc nằm trong danh sách tên cấm** (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`, và chính hostname/domain cấu hình của Control/Relay/STUN — chống vòng lặp DNS `US-038`), *When* đăng ký, *Then* Server từ chối với lỗi rõ ràng (với trường hợp trùng tên thường có thể gợi ý hậu tố) — không bao giờ nhận tên cấm hoặc trùng tên.
  4. **[F]** *Given* key hết TTL / đã dùng / đã thu hồi / sai, *When* đăng ký, *Then* bị từ chối với **cùng một mã và thông báo lỗi chung** (không phân biệt key sai hay hết hạn), không tạo node, không cấp IP.
  5. **[F]** *Given* dải overlay đã hết địa chỉ, *When* đăng ký, *Then* từ chối với lỗi rõ ràng, không hỏng dữ liệu hiện có.
  6. **[F]** *Given* Control sập giữa lúc đăng ký (kill -9), *When* khởi động lại, *Then* không có node "nửa vời" hay IP bị cấp mà thiếu node (REL-11).

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
- **Epic**: EP-02 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-03, PERF-08, PERF-10, SEC-02
- **Story**: Là *người dùng thiết bị*, tôi muốn agent nhận danh sách peer cập nhật gần thời gian thực khi có thay đổi thực sự mà không gây bão lưu lượng nền lúc rảnh, để thêm/xóa máy thì mọi máy biết ngay.
- **Phụ thuộc**: US-004, US-007.
- **AC**:
  1. **[H]** *Given* agent đã đăng ký, *When* mở stream tới Control (gửi `netmap_version` đang có), *Then* nhận **snapshot đầy đủ** gồm mỗi peer: `node_id`, tên, overlay IP, public key data plane, **khóa xác thực đường đi `disco_key`** (hoặc cơ chế khóa tương đương giữ *domain separation* với khóa data plane do Architect chốt tại Gate 2 — phục vụ `US-021`), `endpoints[]`, `relay_home`, `key_expiry`, trạng thái `online` (`true`/`false`), cùng `netmap_version` **tăng đơn điệu**; Control **chỉ tăng `netmap_version` và đẩy bản mới** khi thay đổi cấu trúc/peer/tên/khóa/`endpoints[]`/thu hồi/hết hạn hoặc khi peer chuyển trạng thái `online ↔ offline` (có debounce) — **tuyệt đối không tăng version hay bắn lại snapshot cho mỗi nhịp heartbeat `last_seen`** (giữ `GNFR-07 ≤ 1 KB/s` và `GNFR-06 < 2% CPU`).
  2. **[N]** *Given* 20 agent online, *When* thêm/thu hồi một node, *Then* tất cả agent online nhận bản mới trong **P95 ≤ 5 s** (đo từ timestamp audit tới log agent).
  3. **[E]** *Given* agent ngắt rồi kết nối lại, *When* gửi version cũ, *Then* nhận snapshot mới nhất; *Given* Control gửi bản có version ≤ đã có, *Then* agent bỏ qua.
  4. **[F]** *Given* stream im lặng > 60 s không có khung heartbeat nhẹ của kênh stream, *When* quá hạn, *Then* agent coi stream chết, đóng và kết nối lại theo backoff (US-034).
  5. **[E]** *Given* 3–20 node, *When* đo kích thước snapshot, *Then* ≤ 64 KB (xác nhận không cần delta ở MVP).

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
- **Epic**: EP-02 · **SP**: 3 · **MoSCoW**: Must · **Trace**: OPS-08, SEC-14, SEC-06, PLAT-04
- **Story**: Là *chủ mạng*, tôi muốn quản trị hoàn toàn bằng CLI qua SSH trên kênh cục bộ được OS kiểm chứng quyền quản trị, để không cần Web UI ở MVP và không ai trong mesh hay tiến trình phụ trên VPS leo thang chiếm quyền được.
- **Phụ thuộc**: US-007. (`preauthkey` ở US-002; `revoke` ở US-029; `backup now` ở US-045.)
- **AC**:
  1. **[H]** *When* chạy `node list`, *Then* hiển thị id, tên, overlay IP, trạng thái online/offline, `last_seen`, `key_expiry`, phiên bản agent; kết quả ≤ 1 s với 20 node.
  2. **[H]** *When* chạy `node rename <id|tên> <tên mới>`, *Then* kiểm tra định dạng + từ chối danh sách tên cấm/trùng lặp giống hệt `US-004 AC3` (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`, và hostname/domain của Control/Relay/STUN); nếu hợp lệ thì cập nhật, các peer nhận tên mới trong P95 ≤ 5 s và ghi audit.
  3. **[H]** *When* chạy `node expire <node>` hoặc `version`, *Then* hành vi đúng (`expire` = buộc đăng ký lại bằng key mới, xem US-031).
  4. **[F]** *Given* yêu cầu tách biệt hoàn toàn kênh Admin khỏi listener quan sát chỉ-đọc (`SEC-14`), *When* kiểm tra kiến trúc kênh và thử gọi trái phép, *Then* CLI quản trị chỉ giao tiếp qua **kênh cục bộ trên VPS có kiểm chứng đặc quyền OS** (vd. Unix Domain Socket quyền `0600`/`0660` thuộc `root`/nhóm quản trị riêng kèm xác minh danh tính tiến trình gọi ở phía server, hoặc thao tác cục bộ trực tiếp dưới quyền quản trị qua SSH) và ghi `UID`/user gọi vào audit; **tuyệt đối cấm** mở Admin API trên `IP overlay`, `IP public` hay TCP `127.0.0.1`/`::1` trần — quét từ node bất kỳ trong mesh hoặc gọi từ user thường/`www-data`/container/SSRF trên VPS đều bị từ chối.
  5. **[F]** *Given* tên/ID không tồn tại, *When* gõ lệnh, *Then* mã thoát khác 0 và thông báo rõ, không thay đổi dữ liệu.

### US-013 — Audit log append-only & ưu tiên thu hồi khẩn cấp khi đầy đĩa
- **Epic**: EP-02 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-09, SEC-08
- **Story**: Là *chủ mạng*, tôi muốn có nhật ký append-only của mọi thao tác nhạy cảm và đảm bảo lệnh thu hồi khẩn cấp không bao giờ bị kẹt khi đầy đĩa, để điều tra sự cố và cắt kẻ xâm nhập tức thì.
- **Phụ thuộc**: US-007.
- **AC**:
  1. **[H]** *Given* các thao tác: tạo/thu hồi key, đăng ký node, thu hồi/hết hạn node, đổi tên/IP, gọi CLI admin, vượt ngưỡng xác thực lỗi, *When* mỗi thao tác xảy ra, *Then* sinh **đúng 1** bản ghi gồm timestamp UTC, actor (`UID`/user hoặc `node_id`), `node_id` đích, IP nguồn (nếu qua mạng), kết quả, đồng thời xuất bản ghi ra luồng log hệ thống (`journald`/`stderr`).
  2. **[E]** *Given* bản ghi audit đã ghi, *When* thử sửa/xóa bản ghi bằng bất kỳ CLI/API nào của sản phẩm, *Then* không tồn tại đường nào làm được (append-only ở tầng ứng dụng; không yêu cầu chuỗi băm `hash-chain` ở MVP trên 1 VPS đơn).
  3. **[F]** *Given* kiểm tra nội dung, *When* grep pre-auth key rõ/private key trong audit, *Then* 0 kết quả.
  4. **[F]** *Given* ghi audit vào DB thất bại (đầy đĩa/lỗi I/O), *When* thực hiện thao tác cấp mới/thay đổi thông thường (đăng ký node, tạo key, đổi tên…), *Then* thao tác **bị từ chối (fail-closed)** và báo lỗi rõ; **riêng với lệnh phòng vệ khẩn cấp (`node revoke`, `preauthkey revoke`, `node expire`)**, *Then* hệ thống **bắt buộc thực thi ngay trong bộ nhớ (RAM)** để cắt kết nối tunnel/relay của kẻ trộm tức thì, kèm xuất bản ghi audit + cảnh báo `CRITICAL` ra `stderr`/`syslog`/`journald`.

---

## 4. EP-03 — Đường hầm mã hóa & Routing an toàn (Data Plane)

> Mục tiêu: dựng tunnel WireGuard-based, không làm hỏng routing máy thật. (Persona P3, P1)

### US-014 — Dựng đường hầm mã hóa trên Linux (interface, route, AllowedIPs /32)
- **Epic**: EP-03 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-02, SEC-11, REL-10, PLAT-03
- **Story**: Là *chủ mạng*, tôi muốn agent Linux tạo interface overlay và route tới đúng các peer, để ping/SSH giữa các máy bằng Overlay IP.
- **Phụ thuộc**: US-004, US-009.
- **AC**:
  1. **[H]** *Given* agent Linux đã đăng ký, *When* khởi động, *Then* interface tunnel được tạo với Overlay IP, route **chỉ cho dải overlay**; không có default route nào được thêm.
  2. **[H]** *Given* hai node Linux có đường (relay hoặc direct), *When* `ping <overlay_ip_peer>`, *Then* ICMP thành công; gói trên dây là gói WireGuard đã mã hóa (xác nhận bằng bắt gói: không thấy ICMP plaintext).
  3. **[E]** *Given* mỗi peer, *When* kiểm tra cấu hình, *Then* `AllowedIPs` của peer là đúng `/32` overlay IP của peer đó, không rộng hơn (SEC-11).
  4. **[F]** *Given* gói tới từ peer A mang IP nguồn bên trong thuộc peer B, *When* nhận, *Then* bị loại (cryptokey routing).
  5. **[N]** *Given* hai node cùng LAN, *When* đo `ping` IP thật vs overlay (1000 mẫu), *Then* chênh lệch ≤ 2 ms P95 (GNFR-08); `iperf3` direct ≥ 70% mạng gốc tới 300 Mbps (GNFR-09).

### US-015 — Dựng đường hầm mã hóa trên Windows (adapter tên cố định)
- **Epic**: EP-03 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PLAT-01, REL-08, REL-09, SEC-11
- **Story**: Là *người dùng di động*, tôi muốn agent Windows tạo adapter tunnel ổn định, để dùng RDP/SSH/SMB đến các máy khác.
- **Phụ thuộc**: US-004, US-009. (Cấu hình dịch vụ: US-052.)
- **AC**:
  1. **[H]** *Given* Windows 10/11 x64, *When* agent khởi động, *Then* tạo adapter TUN L3 có **tên cố định** và Overlay IP; route chỉ cho dải overlay; ping peer Linux thành công.
  2. **[E]** *Given* tồn tại adapter cùng tên (tàn dư), *When* khởi động, *Then* tái sử dụng/dọn đúng cách, **không** sinh adapter "#2" nhân bản.
  3. **[E]** *Given* driver TUN dùng phân phối kèm, *When* build release, *Then* binary driver nguyên vẹn, đúng điều khoản license phân phối lại (kiểm tra checksum nguyên bản + file license kèm theo).
  4. **[F]** *Given* thiếu quyền Administrator, *When* chạy, *Then* lỗi rõ ràng "cần quyền quản trị", không tạo trạng thái dở dang.
  5. **[N]** `AllowedIPs` /32 và overhead như US-014.

### US-016 — Chống routing loop (hành vi cô lập lưu lượng điều khiển & đường hầm)
- **Epic**: EP-03 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-09
- **Story**: Là *chủ mạng*, tôi muốn lưu lượng điều khiển và gói mã hóa của agent không bao giờ bị đẩy ngược vào chính tunnel, để máy không bao giờ mất Internet do vòng lặp.
- **Phụ thuộc**: US-014, US-015, US-056.
- **AC**:
  1. **[H]** *Given* VPS vừa chạy Control/Relay/STUN vừa là một node mesh (`US-056`), *When* mesh hoạt động trên Linux và Windows (kể cả máy có đồng thời nhiều card mạng vật lý LAN + Wi-Fi), *Then* **0 gói điều khiển/STUN/disco/mã hóa đường hầm của agent đi vào interface tunnel** — 100% đi qua đường mạng nền thực tế (cơ chế cô lập socket/routing cụ thể theo từng OS do `agile-architect` chốt tại Gate 2).
  2. **[F]** *Given* một peer quảng bá endpoint thuộc dải overlay hoặc địa chỉ interface tunnel, *When* agent nhận, *Then* endpoint đó bị loại bỏ và ghi log `WARN`.
  3. **[F]** *Given* kịch bản kiểm thử hỗn loạn (cấu hình mạng ngoài bất lợi, hoặc `kill -9` agent rồi đổi Wi-Fi), *When* agent đang chạy hoặc khởi động lại, *Then* agent ngăn chặn vòng lặp mà **không để lại host route mồ côi làm chặn đường tới VPS**, và **máy thật luôn truy cập Internet bình thường ở mọi bước** (probe HTTP liên tục không gián đoạn > 3 s).
  4. **[E]** *Given* MVP, *When* kiểm tra bảng route hệ thống, *Then* không có default route (`0.0.0.0/0` hay `::/0`) nào do agent cài đặt.

### US-017 — MTU an toàn mặc định 1280 & cấu hình được
- **Epic**: EP-03 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-10
- **Story**: Là *người dùng di động*, tôi muốn SSH/HTTPS qua overlay không bị treo trên mạng 4G/PPPoE, để làm việc ổn định mọi nơi.
- **Phụ thuộc**: US-014, US-015, US-026.
- **AC**:
  1. **[H]** *Given* cấu hình mặc định, *When* kiểm tra interface tunnel, *Then* MTU = **1280**; giá trị cấu hình được trong khoảng hợp lệ (576–1420) và bị từ chối ngoài khoảng.
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
  1. **[H]** *Given* STUN lắng nghe UDP 3478 trên VPS, *When* agent gửi Binding Request từ **cùng socket UDP với tunnel và disco**, *Then* nhận Binding Response và `public ip:port` khớp với tuple mà VPS quan sát (so sánh log VPS); **agent lưu bền số cổng UDP cục bộ đã dùng** và ưu tiên bind lại đúng cổng đó ở các lần khởi động sau (chỉ fallback sang cổng mới do OS cấp nếu cổng cũ đang bị tiến trình khác chiếm — phục vụ `US-033 AC2`).
  2. **[E]** *Given* cơ chế phân loại NAT (RFC 5780), *When* chỉ có 1 IP VPS (`C1`, mở 2 cổng STUN trên cùng IP), *Then* agent phát hiện chính xác **Port-Dependent Mapping (`APDM` — "hard NAT")** so với nhóm không đổi port theo cổng đích (`EIM/ADM`), và chỉ phân tách riêng `ADM` khỏi `EIM` khi người dùng cấu hình thêm một đích STUN phụ khác IP; kết quả và giới hạn 1-IP được lưu rõ để `status`/`netcheck` hiển thị trung thực (`US-023`).
  3. **[F]** *Given* STUN không đáp (UDP bị chặn), *When* hết timeout ≤ 5 s, *Then* agent đánh dấu "UDP không khả dụng", bỏ qua direct, dùng relay; **không** treo khởi động.
  4. **[F]** *Given* STUN chỉ phục vụ binding request hợp lệ, *When* nhận gói rác/flood > 100 pkt/s/IP, *Then* giới hạn tốc độ và không khuếch đại phản hồi (response ≤ request về kích thước).

### US-020 — Thu thập & công bố Endpoints (LAN + reflexive), lọc interface ảo & endpoint nguy hiểm
- **Epic**: EP-04 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-07, REL-09, §4.3
- **Story**: Là *người dùng thiết bị*, tôi muốn agent công bố các địa chỉ thực sự có thể tiếp cận được của mình (LAN, IPv6, reflexive) và loại bỏ các card mạng ảo nội bộ, để peer thử đúng các đường khả thi.
- **Phụ thuộc**: US-019, US-009.
- **AC**:
  1. **[H]** *Given* máy có IP LAN, IPv6 public và reflexive IPv4, *When* agent khởi động/đổi mạng, *Then* đẩy lên Control danh sách `endpoints[]` kèm nguồn (`lan`/`ipv6`/`reflexive`) trong ≤ 2 s sau khi STUN xong.
  2. **[E]** *Given* interface là chính adapter tunnel, địa chỉ thuộc dải overlay, **hoặc các virtual/bridge adapter cục bộ phổ biến** (`docker0`, `br-*`, `veth*`, `virbr*`, `cni*`, card ảo WSL/Hyper-V — danh sách lọc cấu hình được), *When* thu thập, *Then* **không** đưa vào `endpoints[]` (chống routing loop và tránh quảng bá IP container nội bộ vô nghĩa lên Netmap).
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

---

## 6. EP-05 — Chuyển tiếp Relay qua VPS & Chống lạm dụng

> Mục tiêu: đường cuối luôn thông (TLS 443 ở cả chế độ Standalone lẫn sau Reverse Proxy), VPS không đọc được nội dung, không nghẽn chéo giữa các peer, người lạ không dùng ké. (Persona P2, P3)

### US-024 — Relay endpoint cổng 443 (Standalone hoặc sau Reverse Proxy) & xác thực khóa node
- **Epic**: EP-05 · **SP**: 8 · **MoSCoW**: Must · **Trace**: REL-06, SEC-04, SEC-06, SEC-07, SEC-02
- **Story**: Là *người dùng di động*, tôi muốn agent mở kết nối lâu dài tới relay qua cổng 443 của VPS (dù VPS chạy độc lập hay đang đứng sau Nginx/Caddy có sẵn), để mạng chỉ cho phép 80/443 vẫn dùng được mà không phá các web cá nhân trên VPS.
- **Phụ thuộc**: US-003, US-001.
- **AC**:
  1. **[H]** *Given* mạng client chặn toàn bộ UDP và chỉ cho phép TCP 443, *When* agent kết nối tới địa chỉ 443 của VPS, *Then* hoàn tất kết nối + chứng minh sở hữu khóa node (bằng random challenge/nonce từ server theo `US-003`) trong ≤ 3 s ở **cả hai chế độ triển khai trên VPS**: **(a) Standalone TLS 443** (dịch vụ tự giữ TLS 443, dùng chung cổng với Control qua phân luồng path/ALPN/HTTP Upgrade) và **(b) Sau Reverse Proxy sẵn có** (Nginx/Caddy… kết thúc TLS 443 và chuyển tiếp HTTP + Upgrade/WebSocket vào cổng loopback/socket nội bộ của dịch vụ).
  2. **[F]** *Given* client chưa đăng ký / khóa không trong netmap / đã thu hồi, *When* xác thực, *Then* bị từ chối; không tạo phiên relay (liên quan US-027).
  3. **[F]** *Given* chứng chỉ giả (MITM/Captive Portal), *When* kết nối, *Then* agent từ chối gửi secret và thử lại theo `US-034 AC4` (như US-003).
  4. **[E]** *Given* kết nối relay idle, *When* không có frame, *Then* gửi heartbeat ≤ 30 s để tránh bị middlebox/reverse proxy ngắt; mất kết nối > 60 s kích hoạt reconnect backoff.
  5. **[E]** *Given* cùng node mở kết nối relay thứ hai, *When* xác thực hợp lệ, *Then* kết nối cũ bị thay thế (một phiên hoạt động/node), tránh rò rỉ phiên.
  6. **[N]** Relay (idle, 20 node đăng nhập) dùng RAM < 64 MB cùng Control+STUN (GNFR-04).

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
  6. **[F]** *Given* thư mục và tệp cache Netmap trên đĩa, *When* kiểm tra phân quyền hệ điều hành, *Then* chỉ cho phép `root` trên Linux (thư mục `0700`, tệp `0600`) hoặc `SYSTEM` + `Administrators` trên Windows đọc/ghi — ngăn chặn user thường trên máy sửa cache để chèn peer giả khi offline.

### US-034 — Reconnect với Exponential Backoff + Jitter, không tự khóa chết khi lỗi TLS tạm thời
- **Epic**: EP-06 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-04, REL-07, SEC-04
- **Story**: Là *chủ mạng*, tôi muốn agent thử lại kết nối tới VPS thông minh và tự phục hồi sau các lỗi mạng/Captive Portal/lệch giờ tạm thời, để VPS sống lại không bị bão kết nối và máy headless ở xa không bao giờ bị tự khóa chết vĩnh viễn.
- **Phụ thuộc**: US-003, US-009, US-024.
- **AC**:
  1. **[H]** *Given* kết nối mạng tới Control/Relay/STUN thất bại (timeout, từ chối kết nối, lỗi 5xx), *When* thử lại, *Then* dùng Exponential Backoff base 1 s, hệ số 2, trần 60 s, **full jitter**; reset backoff khi kết nối ổn định > 1 phút.
  2. **[N]** *Given* VPS chết 10 phút với 20 agent, *When* sống lại, *Then* thời điểm kết nối lại của 20 agent phân bố trải trong cửa sổ ≥ 20 s (độ lệch chuẩn ≥ 5 s); không có > 6 agent kết nối trong cùng 1 s.
  3. **[F]** *Given* mọi I/O mạng, *When* thao tác không phản hồi, *Then* timeout: connect ≤ 10 s; đọc stream có heartbeat ≤ 60 s (GNFR-03); không có I/O chặn vô hạn (kiểm tra bằng test chèn độ trễ vô hạn).
  4. **[F]** *Given* lỗi xác minh TLS/chứng chỉ (ví dụ: Wi-Fi khách sạn có **Captive Portal** chặn cổng 443, thiết bị headless vừa bật lại sau mất điện **trước khi NTP đồng bộ giờ**, hoặc chứng chỉ VPS **trễ gia hạn**), *When* xảy ra, *Then* agent không gửi bất kỳ secret nào (`US-003 AC2`), ghi log rõ nguyên nhân, nhưng **BẮT BUỘC tiếp tục thử lại** theo Exponential Backoff + Jitter có trần thưa hơn (vd. trần **5 phút**) **VÀ kích hoạt thử lại ngay lập tức** khi nhận sự kiện đổi mạng hoặc nhảy đồng hồ hệ thống (`US-035`, `US-036`) — tuyệt đối **không dừng thử lại vĩnh viễn** làm chết thiết bị từ xa (*Fleet Bricking*).
  5. **[E]** *Given* kênh TLS tới Control đã xác thực chứng chỉ **hợp lệ**, *When* nhận mã từ chối danh tính tường minh từ server (`node_revoked` hoặc `node_key_expired`), *Then* agent mới **dừng thử lại tự động** và báo lỗi cụ thể trong `status`/log (không hammer VPS).

---

## 8. EP-07 — Tự khôi phục: Đổi mạng, Sleep/Wake, xung đột dải IP

> Mục tiêu: laptop di động không phải "khởi động lại VPN" thủ công. (Persona P3)

### US-035 — Linux: phát hiện đổi mạng & phục hồi (rebind → STUN → republish → relay trong lúc chờ)
- **Epic**: EP-07 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-07, PLAT-05, PERF-07
- **Story**: Là *người dùng di động*, tôi muốn khi đổi Wi-Fi sang hotspot 4G hoặc wake từ sleep thì kết nối tự phục hồi, để không phải làm gì.
- **Phụ thuộc**: US-019, US-020, US-022, US-026, US-034.
- **AC**:
  1. **[H]** *Given* agent Linux đang chạy, *When* nhận sự kiện thay đổi địa chỉ/route/link từ OS (netlink), *Then* đánh thức ngay bộ đếm retry Control/Relay nếu đang chờ backoff (kể cả sau lỗi TLS/Captive Portal — `US-034 AC4`) và thực hiện chuỗi: rebind socket UDP (ưu tiên cổng cũ đã lưu bền, retry backoff 0.5→8 s nếu interface chưa có IP), STUN lại, đẩy endpoints mới lên Control, disco ping lại; trong lúc chờ dùng relay.
  2. **[N]** *Given* kịch bản chuyển Wi-Fi → hotspot 4G, lặp 20 lần, *When* đo thời gian từ khi mạng mới có IP đến khi ping overlay thông (qua relay hoặc direct), *Then* **P95 ≤ 15 s** (PERF-07), 0 lần phải khởi động lại agent thủ công.
  3. **[E]** *Given* phát hiện "nhảy thời gian" (wall-clock jump > 30 s so với monotonic clock sau suspend/resume hoặc sau khi NTP đồng bộ giờ), *When* xảy ra, *Then* buộc thử lại ngay kênh Control/Relay nếu đang chờ (`US-034 AC4`) và kiểm tra lại toàn bộ đường đi data plane (không chờ hết 180 s `REJECT_AFTER_TIME`).
  4. **[F]** *Given* rebind khi interface chưa sẵn sàng, *When* bind thất bại, *Then* retry theo backoff, **không** để agent ở trạng thái treo báo "Connected" giả (trạng thái `status` phản ánh đúng "rebinding"/"no path").
  5. **[E]** *Given* sự kiện thay đổi mạng dồn dập (flapping > 10 lần/10 s), *When* nhận, *Then* gộp (debounce ≥ 1 s) để không bão STUN/Control.

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
- **Epic**: EP-08 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PLAT-04, REL-08, REL-09
- **Story**: Là *người dùng thiết bị*, tôi muốn gọi `ssh nas` hoặc `ssh nas.mesh.internal` thay vì gõ IP overlay mà không bao giờ làm hỏng DNS hệ thống hay gây vòng lặp mạng, để dùng thuận tiện và an toàn.
- **Phụ thuộc**: US-009.
- **AC**:
  1. **[H]** *Given* netmap có peer `nas`, `pc`, *When* agent áp dụng, *Then* file `hosts` có khối `# BEGIN mesh … # END mesh` ánh xạ Overlay IP tới tên đầy đủ kèm **hậu tố miền nội bộ riêng** (mặc định `<name>.mesh.internal` — cấu hình được, tránh `.local` của mDNS) bên cạnh tên ngắn `<name>` (tùy chọn bật/tắt); `ping nas.mesh.internal` và `ping nas` phân giải đúng; phần ngoài khối giữ nguyên byte-by-byte.
  2. **[E]** *Given* agent cập nhật file `hosts`, *When* thực hiện ghi, *Then*: (a) ưu tiên ghi nguyên tử (file tạm cùng thư mục rồi thay thế) để tắt đột ngột không bao giờ cắt cụt file; (b) **bảo toàn quyền đọc chuẩn của hệ thống và user** (`0644` trên Linux; giữ nguyên quyền `Read` cho `Users`, `NetworkService` / `Dnscache` trên Windows — không làm kế thừa ACL hẹp từ thư mục tạm của Service); (c) có **retry ngắn với backoff** (vd. ≤ 2 s) khi file `hosts` trên Windows bị `Dnscache`/AV khóa tạm; (d) xử lý an toàn trường hợp `/etc/hosts` là **bind-mount đơn lẻ** (`EBUSY`/`EXDEV`) trong container Linux (`US-057`) bằng ghi trực tiếp có khóa mà không văng lỗi.
  3. **[E]** *Given* agent tắt đột ngột (kill -9) rồi khởi động lại, *When* khởi động, *Then* khối được viết lại **đúng một lần**, không nhân bản.
  4. **[E]** *Given* dừng service/gỡ cài đặt, *When* hoàn tất, *Then* khối bị **xóa sạch** (REL-08).
  5. **[F]** *Given* tên peer chứa ký tự ngoài `[a-z0-9-]` (≤ 63 ký tự)/xuống dòng, nằm trong **danh sách tên hệ thống cấm** (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`…), **hoặc trùng với chính hostname/domain trong URL của Control/Relay/STUN**, *When* agent áp dụng vào `hosts`, *Then* agent **từ chối ghi mục đó** và log `WARN` — chặn tuyệt đối chiếm đoạt `localhost`/`wpad` và chặn vòng lặp DNS đẩy lưu lượng Control vào tunnel khi VPS là node (`US-056`).
  6. **[F]** *Given* vẫn không thể ghi `hosts` sau khi hết retry (file bị khóa cứng/chỉ-đọc), *When* xảy ra, *Then* log lỗi rõ ràng, tunnel data plane vẫn hoạt động bình thường (tên chỉ là tiện ích).

### US-039 — CLI `status`
- **Epic**: EP-08 · **SP**: 5 · **MoSCoW**: Must · **Trace**: OPS-02, SEC-01, GNFR-02
- **Story**: Là *chủ mạng*, tôi muốn biết từng peer đang đi direct hay relay, để chẩn đoán vì sao chậm.
- **Phụ thuộc**: US-009, US-021, US-022.
- **AC**:
  1. **[H]** *When* chạy `status`, *Then* với mỗi peer in: tên, Overlay IP, online/offline, **đường hiện tại (`direct ip:port` | `relay`)**, RTT gần nhất, handshake gần nhất, rx/tx bytes; phía trên in trạng thái Control & Relay, `netmap_version`, endpoints của chính mình (LAN/reflexive), loại NAT.
  2. **[N]** *Given* 20 peer, *When* chạy `status`, *Then* trả kết quả ≤ **1 s**.
  3. **[E]** *Given* chặn rồi mở UDP giữa 2 node, *When* chạy `status` sau mỗi thay đổi, *Then* đường đi phản ánh đúng thực tế trong ≤ 15 s sau thay đổi.
  4. **[F]** *Given* agent không chạy, *When* chạy `status`, *Then* thông báo rõ "agent không chạy" và mã thoát khác 0 (không treo).
  5. **[F]** *Given* user thường trên Windows/Linux, *When* gọi `status` (lệnh đọc), *Then* chỉ trả thông tin không nhạy cảm; **không bao giờ** in private key (GNFR-02); lệnh quản trị bị từ chối cho user thường (US-052).
  6. **[E]** Hỗ trợ `--json` có schema ổn định để script/kiểm thử tự động đọc.

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
  1. **[H]** *When* chạy `bugreport`, *Then* sinh một tệp nén gồm: log gần nhất, `status`, bảng route, cấu hình đã lọc, phiên bản.
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
  1. **[H]** *Given* mọi thành phần khỏe, *When* `curl /healthz` & `/readyz`, *Then* cả hai trả 200 trong ≤ 200 ms.
  2. **[F]** *Given* DB không mở được, *When* gọi `/readyz`, *Then* 503 và nêu lý do không nhạy cảm; `/healthz` vẫn 200 (liveness ≠ readiness).
  3. **[F]** *Given* listener STUN hoặc relay không hoạt động, *When* gọi `/readyz`, *Then* 503.
  4. **[F]** *Given* nguyên tắc tách biệt `SEC-14`, *When* kiểm tra listener chứa `/healthz` và `/readyz`, *Then* mặc định chỉ bind loopback `127.0.0.1` (hoặc thêm IP overlay khi bật tường minh), **hoàn toàn không chứa bất kỳ endpoint Admin/thay đổi trạng thái nào**, không trả secret, và không truy cập được từ Internet (`nmap` IP public).

### US-045 — Backup cục bộ tự động, kiểm tra checksum & diễn tập Restore
- **Epic**: EP-09 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-12, OPS-08, SEC-14
- **Story**: Là *chủ mạng*, tôi muốn có bản sao lưu DB control cục bộ nhất quán kèm checksum và quy trình khôi phục đã thử, để VPS hỏng dữ liệu không phải đăng ký lại mọi máy.
- **Phụ thuộc**: US-007, US-012.
- **AC**:
  1. **[H]** *Given* Control đang chạy, *When* đến lịch (mặc định hằng ngày), chạy `backup now` (qua kênh `SEC-14`) hoặc trước mỗi migration, *Then* tạo bản backup cục bộ nhất quán bằng cơ chế an toàn khi đang chạy (không khóa ghi > 1 s); giữ N=7 bản gần nhất.
  2. **[H]** *Given* diễn tập: xóa toàn bộ DB, *When* chạy `restore <file>` từ bản gần nhất, *Then* Control chạy lại; **mọi node kết nối lại với IP cũ không cần đăng ký lại**; thời gian khôi phục ≤ 5 phút (RTO) với 20 node.
  3. **[E]** *Given* mỗi tệp backup tạo ra, *When* hoàn tất ghi, *Then* sinh kèm tệp/mã **checksum** kiểm tra toàn vẹn và đặt quyền truy cập chặt (`0600` chỉ cho user dịch vụ/`root`), sẵn sàng để đồng bộ mã hóa ra ngoài VPS bằng công cụ chuẩn của OS theo hướng dẫn trong Runbook (`US-059` — không nhồi tính năng quản lý khóa mã hóa & giao thức upload lưu trữ ngoài vào phần mềm ở MVP).
  4. **[F]** *Given* backup hỏng hoặc sai checksum, *When* chạy `restore`, *Then* từ chối khôi phục với lỗi rõ ràng để không ghi đè dữ liệu hỏng; cho phép chỉ định bản kế tiếp.
  5. **[F]** *Given* tệp backup, *When* kiểm tra nội dung, *Then* không chứa private key client (vì server không có) và không chứa pre-auth key rõ.

### US-046 — Hardening VPS an toàn với dịch vụ sẵn có & tách kênh Admin (`SEC-14`)
- **Epic**: EP-09 · **SP**: 3 · **MoSCoW**: Must · **Trace**: SEC-06, SEC-14
- **Story**: Là *chủ mạng*, tôi muốn dịch vụ trên VPS chạy với quyền tối thiểu, khóa chặt kênh Admin theo quyền OS và hỗ trợ hardening firewall có xác nhận mà không đánh sập web hay SSH sẵn có trên VPS cá nhân.
- **Phụ thuộc**: US-012, US-051.
- **AC**:
  1. **[H]** *Given* VPS cài đặt dịch vụ (cả VPS sạch lẫn VPS đang chạy sẵn dịch vụ cá nhân và/hoặc SSH cổng khác 22), *When* quét bề mặt mạng của riêng dịch vụ Mesh từ ngoài (`nmap` TCP+UDP), *Then* dịch vụ chỉ mở public: TCP 443 (chế độ Standalone; ở chế độ sau Reverse Proxy dịch vụ chỉ bind cục bộ), UDP 3478 (STUN) và cổng UDP của agent VPS (nếu là node); **việc bật firewall mặc định deny là tùy chọn `opt-in` có xác nhận** — khi chọn bật, công cụ tự phát hiện cổng SSH đang hoạt động (kể cả khác 22), liệt kê và mặc định giữ nguyên các cổng dịch vụ sẵn có trên VPS, hiển thị `dry-run` trước khi áp, và **tự hoàn tác (auto-rollback) sau 60–120 s** nếu mất kết nối không xác nhận lại.
  2. **[H]** *Given* service Control/Relay, *When* kiểm tra tiến trình, *Then* chạy bằng user hệ thống riêng **không đặc quyền**, chỉ cấp capability mạng tối thiểu cần thiết; unit service bật các cờ cô lập (`NoNewPrivileges`, `ProtectSystem`… hoặc tương đương).
  3. **[F]** *Given* yêu cầu tách kênh `SEC-14`, *When* kiểm tra các socket lắng nghe và thử tấn công từ các ngữ cảnh, *Then*: (a) **không có bất kỳ listener Admin nào trên TCP** (cấm tuyệt đối mở Admin API trên `IP overlay`, `IP public` hay TCP `127.0.0.1`/`::1` trần); quét từ một node trong mesh hoặc gọi từ user thường/`www-data`/container/SSRF trên VPS đều bị từ chối không đổi được trạng thái nào; (b) listener chỉ-đọc (`/healthz`, `/readyz`, `/metrics`) nằm riêng, chỉ bind loopback (hoặc thêm IP overlay khi bật tường minh) và bị từ chối từ Internet.
  4. **[F]** *Given* lệnh tự kiểm `hardening-check`, *When* cấu hình vi phạm an toàn (chạy dưới `root`, quyền socket Admin lỏng hơn `0660`, bật Reverse Proxy mà thiếu `trusted_proxies`, lộ listener nội bộ ra public), *Then* báo FAIL rõ từng hạng mục.

### US-047 — Vòng đời chứng chỉ TLS (Standalone ACME không cần cổng 80, Reverse Proxy hoặc Pin)
- **Epic**: EP-09 · **SP**: 5 · **MoSCoW**: Must · **Trace**: SEC-04, OPS-07, T22
- **Story**: Là *chủ mạng*, tôi muốn TLS trên cổng 443 luôn hợp lệ dù chạy Standalone (không cần mở cổng 80), chạy sau Reverse Proxy sẵn có hay chế độ pin chứng chỉ, và nếu lỡ trễ hạn thì khi gia hạn lại toàn bộ máy tự nối lại được.
- **Phụ thuộc**: US-003, US-024, US-034, OQ-02.
- **AC**:
  1. **[H]** *Given* VPS có domain: ở chế độ **Standalone**, *When* xin mới hoặc chứng chỉ còn ≤ 30 ngày, *Then* Control tự xin/gia hạn ACME bằng phương thức **không cần mở cổng TCP 80** (vd. `TLS-ALPN-01` ngay trên cổng 443 hoặc `DNS-01`) và nạp nóng (hot-reload) không làm rớt kết nối agent hiện có; ở chế độ **Sau Reverse Proxy sẵn có**, cho phép tắt ACME nội bộ để proxy của người dùng quản lý TLS 443 mà vẫn kiểm tra được hạn chứng chỉ đầu ngoài; nếu gia hạn thất bại, thử lại ≥ 3 lần/ngày và log lỗi.
  2. **[F]** *Given* chứng chỉ TLS đang phục vụ còn < 14 ngày mà chưa được gia hạn, *When* kiểm tra định kỳ, *Then* ghi log mức `ERROR`, hiển thị trong chẩn đoán server và kích hoạt cảnh báo (`US-049` nếu bật).
  3. **[E]** *Given* không có domain (chế độ pin), *When* cài đặt, *Then* sinh khóa/chứng chỉ tự ký, in **fingerprint** để pin lúc cài agent; quy trình **xoay chứng chỉ** có hướng dẫn và hỗ trợ danh sách pin cũ+mới trong giai đoạn chuyển tiếp.
  4. **[F]** *Given* chứng chỉ trên VPS lỡ hết hạn thực sự, *When* agent kết nối, *Then* agent từ chối bắt tay TLS (không gửi secret, không bỏ qua kiểm tra), đường hầm P2P direct đang chạy vẫn sống (`US-033`), và agent tiếp tục thử lại theo backoff trần 5 phút (`US-034 AC4`) để **tự động nối lại ngay khi chứng chỉ trên VPS được gia hạn xong**.

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
  1. **[H]** *Given* client gửi `protocol_version` & `agent_version`, *When* kết nối, *Then* Control ghi nhận và hiển thị trong `node list`.
  2. **[F]** *Given* client có phiên bản dưới mức tối thiểu hỗ trợ, *When* kết nối, *Then* bị từ chối với thông báo "cần nâng cấp agent" (không treo/không lỗi mơ hồ).
  3. **[E]** *Given* client phiên bản N-1 với server N, *When* chạy bộ test tương thích, *Then* đăng ký/netmap/relay hoạt động; nâng cấp server (restart) không làm rớt tunnel P2P đang chạy (0 mất gói do control).

### US-051 — Cài đặt/nâng cấp server an toàn (VPS sạch hoặc VPS đang dùng) & tự khởi động lại
- **Epic**: EP-09 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-13, SEC-06, REL-12
- **Story**: Là *chủ mạng*, tôi muốn cài/nâng cấp Control+STUN+Relay trên VPS (dù là VPS sạch hay VPS đang chạy sẵn web/SSH tùy chỉnh) bằng quy trình lặp lại được và tự sống lại khi crash, để vận hành 24/7 mà không làm sập dịch vụ hiện có.
- **Phụ thuộc**: US-007, US-024, US-046.
- **AC**:
  1. **[H]** *Given* VPS Ubuntu LTS (cả **VPS sạch** lẫn **VPS đang chạy sẵn dịch vụ cá nhân** như Nginx/Caddy trên cổng 443 và SSH cổng khác 22), *When* chạy quy trình cài đặt chọn chế độ Standalone hoặc chế độ sau Reverse Proxy (sinh kèm cấu hình mẫu chuyển tiếp HTTP + Upgrade cho Nginx/Caddy), *Then* Control+STUN+Relay chạy dưới service manager, tự bật khi boot, `readyz` = 200 sau ≤ 60 s; **mặc định không tự động bật firewall deny hay xóa rule hiện có nếu người dùng không `opt-in` (`US-046 AC1`)**, các web cá nhân và phiên SSH hiện có vẫn hoạt động 100%; chạy lặp lại (idempotent) không phá cấu hình/dữ liệu.
  2. **[H]** *Given* tiến trình Control bị `kill -9`, *When* supervisor phát hiện, *Then* tự sống lại ≤ **10 s** và agent kết nối lại (REL-13, US-034).
  3. **[E]** *Given* nâng cấp phiên bản, *When* thực hiện, *Then* tự backup trước (US-045), migrate (US-007) và có đường **rollback** (bản cũ + backup) được ghi trong runbook; tunnel P2P đang chạy không đứt.
  4. **[F]** *Given* crash-loop (> 5 lần/phút), *When* xảy ra, *Then* supervisor backoff, log rõ và (Should) cảnh báo; không làm đầy đĩa log.

---

## 11. EP-10 — Tích hợp nền tảng (Windows/Linux) & Dọn dẹp

> Mục tiêu: cài/gỡ/chạy ổn định như phần mềm hệ thống thật; không để lại rác làm hỏng mạng. (Persona P2, P3)

### US-052 — Windows Service, CLI qua kênh có ACL & cài/gỡ sạch
- **Epic**: EP-10 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PLAT-01, SEC-01, REL-13, R-11
- **Story**: Là *người dùng di động*, tôi muốn agent chạy như dịch vụ Windows tự khởi động và gỡ ra không để lại gì, để máy luôn sạch.
- **Phụ thuộc**: US-015.
- **AC**:
  1. **[H]** *Given* installer Windows, *When* cài, *Then* đăng ký service (tự chạy khi boot, Recovery: restart sau crash ≤ 10 s), cài driver TUN đúng license, tạo adapter tên cố định.
  2. **[H]** *When* gỡ cài đặt, *Then* xóa service, adapter, route, rule firewall, khối hosts, file khóa chỉ bị xóa khi có xác nhận `--purge` (mặc định giữ để cài lại giữ danh tính); **0 adapter ma** còn lại sau 10 vòng cài/gỡ.
  3. **[F]** *Given* CLI chạy bởi user thường, *When* gọi lệnh quản trị (`up`, `down`, `cleanup`), *Then* bị từ chối (kênh giao tiếp service dùng named pipe với ACL chỉ Administrators/SYSTEM); lệnh đọc (`status`) cho phép nếu cấu hình.
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

### US-054 — Linux: chạy dưới systemd, capability tối thiểu, không ghi đè resolv.conf
- **Epic**: EP-10 · **SP**: 3 · **MoSCoW**: Must · **Trace**: PLAT-03, REL-13
- **Story**: Là *home-lab self-hoster*, tôi muốn agent chạy như service chuẩn trên Ubuntu LTS và không phá cấu hình mạng khác, để cài lên NAS yên tâm.
- **Phụ thuộc**: US-014.
- **AC**:
  1. **[H]** *Given* Ubuntu LTS hiện hành, *When* cài và chạy, *Then* service tự bật khi boot, chạy với `CAP_NET_ADMIN` (+`CAP_NET_RAW` nếu cần), tạo TUN qua `/dev/net/tun`; tự sống lại ≤ 10 s sau `kill -9`.
  2. **[E]** *Given* hệ thống dùng nftables hoặc iptables, *When* agent chạy, *Then* tương thích cả hai; không flush rule có sẵn.
  3. **[E]** *Given* chạy agent, *When* kiểm tra `/etc/resolv.conf`, *Then* **không bị ghi đè**.
  4. **[F]** *Given* gỡ service, *When* hoàn tất, *Then* không còn rule/route/interface do agent tạo.

### US-055 — Graceful shutdown, dọn dẹp lúc khởi động & lệnh `down`/`cleanup`
- **Epic**: EP-10 · **SP**: 5 · **MoSCoW**: Must · **Trace**: REL-08, REL-09, PLAT-04
- **Story**: Là *chủ mạng*, tôi muốn dù agent bị tắt/crash thế nào, máy vẫn ra Internet bình thường và lần khởi động sau tự dọn rác, để VPN không bao giờ làm hỏng mạng máy chính.
- **Phụ thuộc**: US-014, US-015, US-038.
- **AC**:
  1. **[H]** *Given* dừng service (SIGTERM, `systemctl stop`, Windows Service Stop, tắt máy), *When* dừng, *Then* trong ≤ 5 s agent: gỡ route overlay, khôi phục hosts, xóa interface/adapter, đóng kết nối relay/control (báo offline); bảng route và DNS trở về như trước khi chạy.
  2. **[F]** *Given* `kill -9` agent (Windows và Linux), *When* khởi động lại, *Then* phát hiện & dọn tàn dư (adapter ma, route mồ côi, khối hosts cũ) **trước khi** dựng mới; không trùng lặp; Internet máy thật **không bị gián đoạn > 3 s ở mọi bước** (probe liên tục).
  3. **[H]** *When* chạy `down` hoặc `cleanup` thủ công, *Then* trả máy về trạng thái sạch, idempotent (chạy 2 lần không lỗi).
  4. **[F]** *Given* thiết bị mất điện đột ngột, *When* bật lại, *Then* như (2).
  5. **[E]** *Given* tắt agent khi đang có phiên TCP qua tunnel, *When* dừng, *Then* các phiên đó đứt gọn (không treo máy/không chiếm CPU).

### US-056 — VPS là một node của mesh
- **Epic**: EP-10 · **SP**: 2 · **MoSCoW**: Must (theo A-05/OQ-03) · **Trace**: REL-09, SEC-14, §4.1
- **Story**: Là *chủ mạng*, tôi muốn truy cập các dịch vụ riêng tư trên VPS qua IP overlay, để không phải mở thêm cổng dịch vụ ra Internet.
- **Phụ thuộc**: US-004, US-014, US-016, US-038.
- **AC**:
  1. **[H]** *Given* agent cài trên VPS như một node (với tên node khác domain public của Control/Relay/STUN theo `US-004 AC3`, vd. `vps`), *When* các máy khác `ssh <overlay_ip_vps>` hoặc `ssh vps.mesh.internal`, *Then* kết nối thành công mà không mở thêm cổng dịch vụ ra Internet (lưu ý: kênh Admin của Control vẫn khóa cục bộ trên VPS theo `SEC-14`, không mở trên `overlay_ip_vps`).
  2. **[F]** *Given* VPS vừa chạy Control/Relay/STUN vừa là node, *When* chạy đồng thời test routing loop (`US-016`), test ghi `hosts` (`US-038 AC5`) và test relay/STUN, *Then* 0 sự cố vòng lặp mạng/DNS, 0 mất Internet/mất dịch vụ.
  3. **[E]** *Given* không muốn VPS là node (OQ-03 = Không), *When* bỏ qua, *Then* các story còn lại không bị ảnh hưởng.

---

## 12. EP-11 — Kiểm thử NFR/SLO, Phòng lab mạng & Runbook (Enabler)

> Mục tiêu: các cam kết Production được **đo** chứ không chỉ nói. (Persona P1; phục vụ `agile-qa`)

### US-057 — Phòng lab mạng giả lập (NAT, chặn UDP, MTU thấp, mất gói, đổi IP, sleep/wake)
- **Epic**: EP-11 · **SP**: 8 · **MoSCoW**: Must · **Trace**: Go-Live checklist, R-12
- **Story**: Là *chủ mạng/QA*, tôi muốn môi trường lặp lại được để mô phỏng Easy/Hard NAT, chặn UDP, Captive Portal, MTU 1400, mất gói, đổi IP và nhảy đồng hồ sau sleep, để kiểm chứng tự động các tiêu chí chịu lỗi.
- **Phụ thuộc**: không (làm sớm; chặn US-021/022/028/035/036).
- **AC**:
  1. **[H]** *When* khởi chạy lab bằng một lệnh, *Then* dựng ≥ 5 node (Linux; Windows qua VM/runner khi có) + 1 "VPS" mô phỏng (hỗ trợ cả topo Standalone 443 lẫn sau Reverse Proxy) với các kịch bản: EIM, Port-Dependent NAT (APDM), UDP-block, 443-only, Captive Portal/TLS giả, MTU 1400 + chặn ICMP frag-needed, độ trễ/mất gói cấu hình được.
  2. **[E]** *Given* kịch bản, *When* chạy lại 10 lần, *Then* kết quả lặp lại (flaky < 5%).
  3. **[H]** *Given* các hành động: `kill -9` agent/Control, chặn/mở UDP, đổi IP (flap), mô phỏng `power-resume + nhảy đồng hồ > 180 s + xóa bảng NAT mapping` (phục vụ 20 vòng tự động của `US-036 AC2`), *When* script hóa, *Then* gọi được từ test tự động (CI hoặc chạy cục bộ).
  4. **[F]** *Given* lab dọn dẹp, *When* kết thúc, *Then* không để lại cấu hình mạng trên máy chủ chạy lab (kiểm tra trước/sau).

### US-058 — Bộ kiểm thử NFR/SLO & Go-Live tự động
- **Epic**: EP-11 · **SP**: 5 · **MoSCoW**: Must · **Trace**: PERF-01..12, SEC-14, Go-Live checklist
- **Story**: Là *chủ mạng/QA*, tôi muốn một lệnh chạy toàn bộ kiểm tra SLO & checklist Go-Live và xuất báo cáo, để quyết định lên Production có cơ sở.
- **Phụ thuộc**: US-057, và các story liên quan.
- **AC**:
  1. **[H]** *When* chạy bộ test, *Then* xuất báo cáo (JSON + Markdown) cho: PERF-01/02/03/04/05/06/07/08/09/10/11, REL-01/06/08/09/10/12, SEC-01/03/05/06/07/08/14, OPS-02/03 với giá trị đo, ngưỡng, PASS/FAIL.
  2. **[E]** *Given* SLO là đề xuất chưa đo, *When* kết quả không đạt, *Then* báo cáo ghi rõ "lệch so với đề xuất" và số liệu thực để Gate 3 quyết định hiệu chỉnh (không âm thầm đổi ngưỡng).
  3. **[F]** *Given* một mục go-live FAIL, *When* chạy, *Then* mã thoát khác 0 (chặn release trong CI).

### US-059 — Runbook vận hành & Go-Live checklist
- **Epic**: EP-11 · **SP**: 3 · **MoSCoW**: Must · **Trace**: REL-12, SEC-06, SEC-08, R-09
- **Story**: Là *chủ mạng*, tôi muốn có tài liệu từng bước để cài đặt an toàn trên VPS đang dùng và xử lý sự cố mà không phải nhớ, để 3 tháng sau vẫn thao tác chuẩn xác.
- **Phụ thuộc**: US-029, US-045, US-051.
- **AC**:
  1. **[H]** *Given* runbook, *When* người thứ hai làm theo (diễn tập kiểm chứng) các quy trình: cài server (cả Standalone lẫn sau Nginx/Caddy có sẵn), thêm máy headless bằng `--authkey-file`, **mất laptop → thu hồi** (kể cả kịch bản đầy đĩa), restore backup + công thức mẫu đồng bộ backup mã hóa ra ngoài VPS bằng công cụ chuẩn (`restic`/`rclone`… — `US-045 AC3`), nâng cấp & rollback, xoay chứng chỉ, xử lý "Control chết" — *Then* hoàn thành mỗi quy trình trong ≤ 30 phút không cần hỏi thêm.
  2. **[E]** *Given* runbook, *When* kiểm tra, *Then* nêu rõ **giới hạn đã biết**: thu hồi không hiệu lực khi Control chết (`US-033`/`US-031`), hard NAT↔hard NAT luôn đi relay (`A-10`), VPS là root of trust (`A-09`), giới hạn phân loại NAT khi chỉ dùng 1 IP STUN (`US-019 AC2`).
  3. **[F]** *Given* checklist Go-Live, *When* mỗi mục, *Then* có bằng chứng (đường dẫn log/báo cáo) từ US-058 và biên bản sleep phần cứng thật của `US-036 AC2`.

---

## 13. EP-12 — Phase 2+ (Mở rộng, **không** thuộc MVP)

> Mục tiêu: giữ lại tầm nhìn mà không phình phạm vi. Mỗi story bên dưới chỉ được kéo vào Sprint khi **điều kiện kích hoạt** đạt và được người dùng duyệt qua Gate. AC rút gọn (sẽ chi tiết hóa ở Backlog Refinement).

| Story | Tên | SP | MoSCoW | Điều kiện kích hoạt | AC rút gọn (Given/When/Then) |
|---|---|:-:|:-:|---|---|
| **US-060** | Client macOS (utun) | 8 | Could | Win/Linux ổn định; Gate duyệt | *Given* macOS, *When* `up`, *Then* ping peer Win/Linux thành công, đổi mạng/sleep P95 ≤ 15 s; cleanup REL-08 đạt như Linux |
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

---

## 14. Ma trận truy vết Yêu cầu Production → Story

> Đảm bảo **không bỏ sót** yêu cầu sống còn của `production-readiness-requirements.md`.

| Yêu cầu | Ưu tiên NC | Story phủ | Ghi chú |
|---|:-:|---|---|
| SEC-01 | P0 | US-001, US-033, US-039, US-041, US-043, GNFR-02 | Bao gồm phân quyền chặt thư mục/tệp khóa & cache Netmap |
| SEC-02 | P0 | US-003, US-009, US-014, US-021, US-024, US-025, GNFR-01 | ADR thư viện & tách khóa disco do Tech Lead/Architect chốt Gate 2 |
| SEC-03 | P0 | US-002, US-004, US-005, US-031 (one-time/TTL/hash/revoke/`--for`); US-006 (reusable/ephemeral — Should, xem OQ-06) | **Điều chỉnh có chủ đích**: phần "tùy chọn" hạ xuống Should để Gate 1 xác nhận |
| SEC-04 | P0 | US-003, US-024, US-034, US-047 | Hỗ trợ Standalone ACME không cần cổng 80, Reverse Proxy và Pin |
| SEC-05 | P0 | US-042 | Kèm `trusted_proxies` tường minh, constant-time hash compare |
| SEC-06 | P0 | US-046, US-051, US-024, US-044, US-048 | An toàn với VPS dùng chung; firewall mặc định deny là `opt-in` có auto-rollback |
| SEC-14 | P0 | US-012, US-046, US-002, US-029, US-044, US-048, US-058 | **Khắc phục `BLK-01`**: tách kênh Admin cục bộ kiểm chứng quyền OS khỏi listener chỉ-đọc; cấm mở Admin trên IP overlay / TCP `127.0.0.1` trần |
| SEC-07 | P0 | US-024, US-025, US-027, US-029 | Kèm `src_pubkey` do Relay gắn + hàng đợi giới hạn mỗi đích drop không chặn |
| SEC-08 | P0 | US-029, US-030, US-031, US-013, US-032 | Key rotation thủ công: US-032 (Should); `revoke` chạy trong RAM khi đĩa đầy |
| SEC-09 | P0 | US-013 | Append-only ứng dụng + xuất journald/stderr |
| SEC-10 | P1 | US-011 | |
| SEC-11 | P1 | US-014, US-015, US-018 | AllowedIPs /32 là Must (trong US-014/015) |
| SEC-12/13 | P2 | US-069, US-067, US-070 | Phase 2+ |
| REL-01 | P0 | US-033, US-019, US-050 | Lưu bền cổng UDP cục bộ để P2P cache hoạt động qua NAT khi Control offline |
| REL-02 | P0 | US-004, US-005 | |
| REL-03 | P0 | US-009, US-010 | Không tăng `netmap_version` mỗi nhịp `last_seen` |
| REL-04 | P0 | US-034, GNFR-03 | Không dừng retry vĩnh viễn khi lỗi chứng chỉ/TLS môi trường |
| REL-05 | P0 | US-021, US-022, US-026 | Disco có xác thực mật mã + chống replay; keepalive on-demand |
| REL-06 | P0 | US-024, US-026, US-028 | |
| REL-07 | P0 | US-035, US-036 | |
| REL-08 | P0 | US-055, US-052, US-038 | |
| REL-09 | P0 | US-016, US-020, US-038, US-056 | Bao gồm chặn tên cấm/domain Control trong `hosts` và lọc interface ảo |
| REL-10 | P0 | US-017 | MTU 1280; socket UDP ngoài không ép cứng `DF=1` |
| REL-11 | P0 | US-007 | |
| REL-12 | P0 | US-045, US-051, US-059 | Backup cục bộ nhất quán + checksum + restore; đồng bộ mã hóa ngoài qua Runbook |
| REL-13 | P1 | US-051, US-052, US-054 | Đưa lên Must vì cần 24/7 |
| REL-14 | P1 | US-008, US-037 | |
| REL-15 | P2 | US-064, US-065, US-072 | |
| OPS-01 | P0 | US-043 | |
| OPS-02 | P0 | US-039 | |
| OPS-03 | P0 | US-040 | |
| OPS-04 | P1 | US-023, US-019 | Ghi rõ giới hạn phân loại NAT khi chỉ có 1 IP STUN |
| OPS-05 | P0 | US-044 | Listener chỉ-đọc riêng |
| OPS-06 | P1 | US-048 | Listener chỉ-đọc riêng |
| OPS-07 | P1 | US-049, US-047 | |
| OPS-08 | P0 | US-002, US-012, US-029, US-045 | Truy cập qua kênh cục bộ kiểm chứng đặc quyền OS (`SEC-14`) |
| OPS-09 | P1 | US-041 | |
| OPS-10 | P1 | US-050 | |
| PERF-01/02 | — | GNFR-04/06, US-009, US-024, US-058 | |
| PERF-03/04 | — | GNFR-08/09, US-014, US-058 | |
| PERF-05 | — | US-021, US-026, US-058 | |
| PERF-06 | — | US-022, US-028, US-058 | |
| PERF-07 | — | US-035, US-036, US-058 | 20 vòng lab tự động + 2–3 lần kiểm chứng sleep phần cứng thật ≥ 4 phút |
| PERF-08 | — | US-004, US-009, US-058 | |
| PERF-09/10 | — | GNFR-05/07, US-009, US-022, US-058 | |
| PERF-11 | — | US-025, US-027 | |
| PERF-12 | — | GNFR-10, US-033, US-049 | |
| PLAT-01 | P0 | US-015, US-052 | |
| PLAT-02 | P0 | US-053 | |
| PLAT-03 | P0 | US-014, US-054 | |
| PLAT-04 | P0 | US-004, US-012, US-038, US-055 | Bảo toàn ACL đọc Windows & hỗ trợ bind-mount `/etc/hosts` trong container |
| PLAT-05 | P1 | US-035, US-036 | Đưa lên Must vì REL-07 (P0) phụ thuộc |
| PLAT-06 | P2 | US-060, US-061 | |

**Hiệu chỉnh ưu tiên so với nghiên cứu (minh bạch)**: (a) REL-13, PLAT-05 (P1) → Must vì REL-07/24-7 phụ thuộc; (b) SEC-03 phần reusable/ephemeral → Should; (c) SEC-10, SEC-11 phần packet filter, OPS-04/06/07/09/10, REL-14 → Should (P1, cắt được khi trễ).

---

## 15. Tóm tắt phạm vi & Gợi ý lát cắt phân phối (để Scrum Master/Tech Lead tham khảo — **không** phải Sprint Plan)

### 15.1. Tổng quan

| Nhóm | Số story | Tổng SP |
|---|:-:|:-:|
| Must (MVP) | 49 | **215** |
| Should (cắt được, vẫn thuộc MVP+) | 10 | **32** |
| Phase 2+ (Could / Won't — EP-12) | 13 | (không tính) |
| **Tổng** | **72** | |

### 15.2. Gợi ý lát cắt giá trị (Walking Skeleton → An toàn → Production)

| Lát cắt | Nội dung | Story chính | Lý do |
|---|---|---|---|
| **S0 — Nền kiểm thử** | Phòng lab + log | US-057, US-043 | Giảm rủi ro R-12; mọi AC chịu lỗi cần lab |
| **S1 — Walking Skeleton (relay-only, Linux↔Linux)** | Đăng ký → netmap → tunnel qua relay | US-001..005, 007..010, 014, 024..026 | Có mạng dùng được sớm; bằng chứng khả thi E2E |
| **S2 — Direct P2P + chẩn đoán** | STUN, hole punching, chuyển mạch, `status`/`ping` | US-019..022, 028, 039, 040 | Giá trị chính "P2P trực tiếp" |
| **S3 — Windows & Dọn dẹp** | Data plane Windows, service, firewall, cleanup, routing loop, MTU | US-015..017, 052..056 | Chặn R-02/R-05 trước khi dùng thật |
| **S4 — Vòng đời & Chịu lỗi** | Thu hồi, expiry, control chết, backoff, đổi mạng/sleep | US-029..031, 033, 034, 035, 036 | Yêu cầu sống còn Production |
| **S5 — Vận hành & Bảo mật** | Rate-limit, hardening, TLS, backup/restore, health, cài đặt, hosts, audit | US-042, 044..047, 051, 038, 012, 013 | Đủ 24/7 |
| **S6 — Nghiệm thu Go-Live** | Bộ NFR/SLO, runbook, Should-have | US-058, 059 (+ Should khả thi) | Gate 3 |

> Lưu ý phụ thuộc vòng: US-021 phụ thuộc relay (US-024..026) — đó là lý do S1 làm relay trước S2 (đúng mô hình "bắt đầu qua relay, nâng cấp direct").
