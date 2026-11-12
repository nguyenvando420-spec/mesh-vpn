# Báo Cáo Phản Biện Độc Lập (Red-Team Critique) — Gate 1: Nghiên Cứu & Product Backlog

| Thuộc tính | Giá trị |
|---|---|
| **Người phản biện** | `agile-critic` (Independent Principal Reviewer & Devil's Advocate) |
| **Ngày thực hiện** | 2026-11-12 |
| **Cổng kiểm duyệt** | **Gate 1** — Discovery Research & Product Backlog |
| **Vòng thẩm định** | **Vòng 2 (Tái thẩm định sau khi `agile-researcher` & `agile-po-ba` sửa Vòng 1)** |
| **Phạm vi đối chiếu** | `reference-systems-benchmark.md` (442 dòng), `production-readiness-requirements.md` v1.1 (173 dòng), `vision-statement.md` (85 dòng), `project-charter.md` v1.1 (159 dòng), `user-personas.md` (82 dòng), `product-backlog.md` v1.1 (861 dòng) |
| **Thành phần AI/SLM** | **Không có** (Dự án thuần hạ tầng mạng & hệ thống → Mục phản biện AI không áp dụng) |
| **Phán quyết Vòng 1** | `[REVISION REQUIRED]` (3 🔴 `Blocker`, 3 🟠 `High Risk`, 4 🟡 `Improvement`) |
| **Phán quyết cuối cùng (Vòng 2)** | **`[APPROVED FOR GATE]`** (10/10 hạng mục đã khắc phục triệt để; 0 lỗi `Blocker`/`High Risk` còn mở) |

---

## 1. Kết Quả Tái Thẩm Định Vòng 2 (Verification Summary)

Sau Vòng sửa 1 của `agile-researcher` và `agile-po-ba`, `agile-critic` đã kiểm tra độc lập từng dòng sửa đổi và đối chiếu chéo toàn bộ ma trận truy vết, điểm số Story Points (`49 Must = 215 SP`, `10 Should = 32 SP`, không có story > 8 SP) cũng như luồng tương tác giao thức. **Toàn bộ 10/10 phát hiện (3 🔴 `Blocker`, 3 🟠 `High Risk`, 4 🟡 `Improvement`) đã được xử lý triệt để, nhất quán và không phát sinh lỗ hổng bảo mật hay mâu thuẫn kiến trúc mới.**

### Bảng Trạng Thái Khắc Phục Từng Hạng Mục

| Mã | Mức độ gốc | Tóm tắt vấn đề Vòng 1 | Bằng chứng khắc phục ở Vòng 2 | Trạng thái |
|---|:-:|---|---|:-:|
| **`BLK-01`** | 🔴 `Blocker` | Lộ cổng Admin qua `IP overlay` (mạng full-mesh không ACL) và TCP `127.0.0.1` trên VPS dùng chung | Thêm mới `SEC-14` (P0) và cập nhật `SEC-06`, `OPS-05/06/08` trong `production-readiness-requirements.md` (dòng 58–59, 100–103); cập nhật `US-012 AC4`, `US-044 AC4`, `US-046 AC3/AC4`, `US-048 AC1`, `US-056 AC1` trong `product-backlog.md` — tách cứng kênh Admin chỉ qua kênh cục bộ kiểm chứng đặc quyền OS (Unix socket `0600`/`0660` + peer-cred hoặc CLI quản trị qua SSH), cấm tuyệt đối mở Admin trên `IP overlay`, `IP public` hay TCP loopback trần. | ✅ **Đã khắc phục** |
| **`BLK-02`** | 🔴 `Blocker` | Xếp lỗi chứng chỉ TLS vào nhóm dừng retry vĩnh viễn gây khóa chết máy từ xa (Captive Portal, lệch giờ trước NTP, trễ ACME) & sai lệch giả định clock skew 5 phút | Cập nhật `SEC-02` (dòng 54), `US-003 AC1/AC2/AC5` (dòng 106–110), `US-034 AC4/AC5` (dòng 466–467), `US-035 AC1/AC3`, `US-036 AC1`, `US-047 AC4`: dùng random challenge/nonce từ server (miễn nhiễm lệch giờ dual-boot); lỗi TLS không gửi secret nhưng bắt buộc retry backoff (trần 5 phút) + đánh thức ngay khi đổi mạng/nhảy đồng hồ; chỉ dừng retry khi nhận `node_revoked`/`node_key_expired` bên trong kênh TLS hợp lệ. | ✅ **Đã khắc phục** |
| **`BLK-03`** | 🔴 `Blocker` | Thiếu xác thực mật mã gói Disco (dễ bị đầu độc endpoint P2P), Relay thiếu `src_pubkey` xác thực & hàng đợi drop không chặn, lỗ hổng `--replace` chiếm node | Cập nhật `US-009 AC1` (dòng 176, thêm `disco_key`), `US-021 AC1/AC2/AC5` (dòng 312–316, xác thực mật mã + `tx_id` chống replay), `US-025 AC1/AC6` & `US-026 AC2` (dòng 362–375, Relay tự gắn `src_pubkey` từ phiên xác thực + hàng đợi giới hạn mỗi đích drop không chặn chống Head-of-Line blocking), `US-002 AC1` & `US-031 AC5/AC6` (dòng 95, 434–435, bắt buộc sinh khóa mới + chỉ thay thế khi admin cấp key `--for <node>`, cấm `--replace` tự do). | ✅ **Đã khắc phục** |
| **`HR-01`** | 🟠 `High Risk` | Nguy cơ làm sập web sẵn có trên cổng 443, lỗi ACME khi đóng cổng 80, khóa mất SSH cổng tùy chỉnh hoặc khóa nhầm `127.0.0.1` sau Reverse Proxy | Cập nhật `SEC-04/05/06` (dòng 56–58), `A-01`, `A-13`, `R-17`, `OQ-02` trong `project-charter.md`, và `US-024 AC1`, `US-042 AC6`, `US-046 AC1`, `US-047 AC1`, `US-051 AC1`: hỗ trợ cả Standalone TLS 443 (`TLS-ALPN-01`/`DNS-01` không cần cổng 80) lẫn chạy sau Reverse Proxy sẵn có kèm `trusted_proxies` tường minh; firewall mặc định deny là `opt-in` có `dry-run`, tự giữ cổng SSH/dịch vụ đang chạy và tự rollback sau 60–120 s nếu mất kết nối. | ✅ **Đã khắc phục** |
| **`HR-02`** | 🟠 `High Risk` | Vòng lặp DNS qua file `hosts` khi trùng domain VPS, chiếm tên `localhost`/`wpad`, mất ACL đọc trên Windows và lỗi `EBUSY` bind-mount trên container | Cập nhật `PLAT-04` (dòng 137), `US-004 AC3` (dòng 119), `US-012 AC2` (dòng 208), `US-038 AC1/AC2/AC5` (dòng 516–520), `US-056 AC1/AC2`: chặn danh sách tên cấm (`localhost`, `wpad`, `isatap`, `broadcasthost`, `local`, hostname của Control/Relay/STUN) ở cả Server và Agent; thêm hậu tố `.mesh.internal`; bảo toàn quyền Read cho `Users`/`Dnscache` trên Windows + retry khi file bị khóa tạm + xử lý bind-mount `/etc/hosts` trong container. | ✅ **Đã khắc phục** |
| **`HR-03`** | 🟠 `High Risk` | Bão Netmap do `last_seen`, mất cổng UDP khi restart offline làm tạch `US-033 AC2`, Audit `fail-closed` chặn `revoke` khi đầy đĩa, và test sleep 10 giờ | Cập nhật `US-009 AC1` & `US-022 AC4` (không tăng `netmap_version` theo `last_seen`; keepalive direct nghỉ on-demand khi rảnh lâu), `US-019 AC1` & `US-033 AC2/AC6` (lưu bền cổng UDP cục bộ + khóa quyền `0700`/`0600` thư mục cache Netmap), `US-013 AC2/AC4` (bỏ `hash-chain` khỏi `Must`; ưu tiên thực thi `revoke`/`expire` ngay trong RAM khi đầy đĩa kèm log `CRITICAL` ra stderr/journald), `US-036 AC2` & `US-057 AC3` (20 vòng lab tự động + 2–3 lần sleep phần cứng thật ≥ 4 phút). | ✅ **Đã khắc phục** |
| **`IMP-01`** | 🟡 `Improvement` | Rò rỉ tên công nghệ/cơ chế OS của Gate 2 vào yêu cầu P0 và AC của Gate 1 | Thêm khung quy ước `*(KN)*` đầu `production-readiness-requirements.md` (dòng 17–21); viết lại `US-016 AC1/AC3` (dòng 256–258) theo hành vi quan sát được và `US-043 AC1` (dòng 577) tham chiếu danh mục component chốt ở Gate 2. | ✅ **Đã khắc phục** |
| **`IMP-02`** | 🟡 `Improvement` | Lộ pre-auth key qua `ps aux`/shell history & ngưỡng cứng timing `5 ms` gây flaky CI | Bổ sung `--authkey-file`, `--authkey-stdin`, biến môi trường ở `US-004 AC1`, `US-031 AC5`, `US-032 AC1`, `US-059 AC1`; thay ngưỡng `5 ms` ở `US-042 AC2` (dòng 566) bằng băm trước tra cứu + `constant-time compare` + trả cùng mã/thông báo lỗi. | ✅ **Đã khắc phục** |
| **`IMP-03`** | 🟡 `Improvement` | Giới hạn phân loại NAT với 1 IP VPS, lọc card mạng ảo Docker/WSL2, và cờ `DF` socket ngoài | Ghi rõ giới hạn RFC 5780 1-IP ở `A-01`, `US-019 AC2`, `US-023 AC1/AC2`, `US-059 AC2`; lọc `docker0`/`br-*`/`veth*`/`virbr*`/`cni*`/WSL ở `US-020 AC2`; không ép cứng `DF=1` trên socket UDP ngoài ở `US-017 AC3`. | ✅ **Đã khắc phục** |
| **`IMP-04`** | 🟡 `Improvement` | Tách đồng bộ backup mã hóa ngoài VPS khỏi `Must` & đồng bộ nhãn `US-066` | Thu gọn `US-045 AC3` (dòng 599) về backup cục bộ nhất quán + checksum + quyền `0600`, chuyển hướng dẫn đồng bộ mã hóa ngoài sang Runbook `US-059 AC1`; đổi `US-066` (dòng 764) thành `Could`, khớp 100% thống kê `Should = 10 story / 32 SP`. | ✅ **Đã khắc phục** |

> **Lưu ý nhỏ chuyển giao sang Gate 2 (Khi lập `sprint-backlog.md`, không chặn Gate 1)**:
> - Trong gợi ý lát cắt mục 15.2 của `product-backlog.md`, `US-002` (thuộc lát cắt `S1`) có phụ thuộc vào khung kênh IPC quản trị cục bộ của `US-012` (đang liệt kê ở `S5`), và `US-046` ↔ `US-051` tham chiếu chéo nhau cùng nhóm cài đặt/systemd unit. Khi Scrum Master và Tech Lead chia Sprint ở Gate 2, chỉ cần kéo phần khung socket Admin của `US-012` lên làm cùng `US-002` ở Sprint đầu và xếp `US-046` + `US-051` vào chung một gói công việc DevOps để tránh phụ thuộc vòng.

---

## 2. ⚖️ Đánh Đổi Chiến Lược Khách Quan (`Strategic Trade-offs` — Trình Người Dùng Quyết Định Tại Gate 1)

Bộ tài liệu hiện đã đạt chuẩn an toàn kiến trúc và sẵn sàng lên Production cho nhu cầu cá nhân. Để Người dùng ra quyết định minh bạch tại **Gate 1**, Scrum Master cần làm rõ 4 đánh đổi chiến lược sau (gắn với các câu hỏi mở `OQ-01`, `OQ-02`, `OQ-13`, `OQ-14` trong `project-charter.md`):

1. **Mô hình Triển khai trên VPS Có Sẵn (`OQ-02`): Standalone Cổng 443 vs Chạy Sau Reverse Proxy Sẵn Có**:
   - Nếu VPS của người dùng đang chạy sẵn Nginx/Caddy phục vụ web cá nhân trên cổng 443, chế độ **Sau Reverse Proxy** giúp dùng chung cổng 443 an toàn tuyệt đối mà không đụng dịch vụ cũ, đổi lại người dùng cần thêm một khối cấu hình chuyển tiếp HTTP Upgrade/WebSocket trên proxy sẵn có (được sinh mẫu tự động ở `US-051`) và bật `trusted_proxies`. Nếu VPS dành riêng cổng 443, chế độ **Standalone** tự động lo trọn gói TLS qua `TLS-ALPN-01` mà không cần mở cổng 80.
2. **Ngân Sách Thực Thi MVP (`OQ-14`): Trọn Gói `49 Must / 215 SP` vs Phát Hành Theo 2 Cột Mốc Nội Bộ**:
   - Đề bài đã loại bỏ hoàn toàn Scope Creep doanh nghiệp, nhưng để một phần mềm VPN mức hệ điều hành chạy 24/7 trên cả **Windows + Linux** mà *không bao giờ làm hỏng mạng máy thật* thì các cơ chế bảo vệ (chống routing loop, dọn adapter ma, roaming/sleep-wake, relay chống nghẽn chéo, phòng lab NAT) là không thể cắt bỏ, dẫn tới quy mô MVP 215 SP. Người dùng có thể chọn duyệt chạy thẳng toàn bộ MVP hoặc nghiệm thu sử dụng sớm ngay sau **Milestone 1** (Walking Skeleton + Direct P2P cơ bản, lát cắt `S0..S3`) trước khi hoàn tất **Milestone 2** (Full Roaming/Expiry/Hardening/SLO, lát cắt `S4..S6`).
3. **Tự Định Nghĩa Giao Thức Tối Giản (`OQ-01`) vs Tương Thích App Di Động Có Sẵn**:
   - Tự thiết kế giao thức Control/Relay/Disco giúp nắm trọn bản chất kỹ thuật từ gốc, mã nguồn gọn nhẹ và không bị trói vào giao thức đóng `ts2021` của Tailscale; đánh đổi là ở MVP chưa dùng ngay được ứng dụng Tailscale iOS/Android chính thức (nhu cầu mobile thuộc Phase 3 `US-061`).
4. **Đơn Điểm Sự Cố (SPOF) trên 1 VPS (`OQ-13` & `REL-01`) vs Chi Phí Hạ Tầng Cá Nhân**:
   - Với 1 VPS duy nhất kiêm Control + STUN + Relay: khi VPS khởi động lại hoặc đứt mạng, các kết nối **P2P Direct đã thiết lập vẫn sống bình thường (`US-033`)**, nhưng việc thu hồi node mới (`US-029`) và lưu lượng của các cặp máy bắt buộc đi qua Relay (hai đầu cùng sau CGNAT cứng hoặc mạng khách sạn chặn sạch UDP) sẽ tạm gián đoạn cho tới khi VPS hoạt động lại; đồng thời ở MVP các máy tin cậy netmap do VPS cấp (`A-09`, chưa dùng chữ ký khóa kiểu Tailnet Lock `US-069`). Đây là sự đánh đổi hợp lý và kinh tế nhất cho quy mô cá nhân 3–20 máy.

---

## 3. Hồ Sơ Lưu Trữ Các Phát Hiện Vòng 1 (Đối Chiếu Lịch Sử Kiểm Toán)

### 🔴 Nhóm `Blocker` Đã Xử Lý
- **`BLK-01` (Đã đóng)**: Tách kênh Admin Control khỏi kênh quan sát chỉ-đọc; khóa cứng truy cập Admin qua kênh cục bộ kiểm chứng đặc quyền OS (`SEC-14`, `US-012 AC4`, `US-046 AC3`).
- **`BLK-02` (Đã đóng)**: Loại bỏ hành vi dừng retry vĩnh viễn khi gặp lỗi chứng chỉ/TLS môi trường tạm thời (Captive Portal, máy headless bật trước NTP, trễ gia hạn ACME) và chuyển bước chứng minh khóa sang dùng server random nonce (`US-003 AC1/AC5`, `US-034 AC4/AC5`).
- **`BLK-03` (Đã đóng)**: Bổ sung xác thực mật mã + `tx_id` chống replay cho Disco (`US-009 AC1`, `US-021`), gắn `src_pubkey` xác thực + hàng đợi giới hạn mỗi đích drop không chặn trên Relay (`US-025`), và bắt buộc sinh khóa mới kèm `preauthkey --for <node>` khi đăng ký lại sau hết hạn (`US-031 AC5/AC6`).

### 🟠 Nhóm `High Risk` Đã Xử Lý
- **`HR-01` (Đã đóng)**: Hỗ trợ triển khai song song Standalone TLS 443 (`TLS-ALPN-01`) và sau Reverse Proxy sẵn có kèm `trusted_proxies`; chuyển firewall mặc định deny sang `opt-in` có `dry-run`, bảo toàn SSH/dịch vụ hiện hữu và `auto-rollback` (`SEC-04/05/06`, `US-024`, `US-042`, `US-046`, `US-047`, `US-051`).
- **`HR-02` (Đã đóng)**: Chặn danh sách tên cấm hệ thống & hostname Control/Relay/STUN chống vòng lặp DNS, hỗ trợ hậu tố `.mesh.internal`, bảo toàn quyền Read của `Dnscache`/`Users` trên Windows và hỗ trợ bind-mount `/etc/hosts` trong container (`PLAT-04`, `US-004`, `US-012`, `US-038`).
- **`HR-03` (Đã đóng)**: Chặn bão Netmap do `last_seen` (`US-009 AC1`), thêm keepalive on-demand (`US-022 AC4`), lưu bền cổng UDP cục bộ + khóa quyền thư mục cache Netmap (`US-019 AC1`, `US-033 AC2/AC6`), cho phép thực thi khẩn cấp `revoke` trong RAM khi đĩa đầy + bỏ `hash-chain` khỏi `Must` (`US-013 AC2/AC4`), và thay 10 giờ sleep vật lý bằng 20 vòng lab tự động + 2–3 lần sleep thật ≥ 4 phút (`US-036 AC2`).

### 🟡 Nhóm `Improvement` Đã Xử Lý
- **`IMP-01..04` (Đã đóng)**: Đánh dấu khuyến nghị công nghệ `*(KN)*` chờ Gate 2 (`production-readiness-requirements.md`, `US-016`, `US-043`); hỗ trợ `--authkey-file`/`stdin`/env và bỏ ngưỡng cứng timing `5 ms` (`US-004`, `US-032`, `US-042`); ghi rõ giới hạn RFC 5780 1-IP STUN, lọc bridge ảo Docker/WSL2 và không ép `DF=1` socket ngoài (`US-017`, `US-019`, `US-020`, `US-023`); thu gọn `US-045 AC3` và đồng bộ `US-066` sang `Could`.
