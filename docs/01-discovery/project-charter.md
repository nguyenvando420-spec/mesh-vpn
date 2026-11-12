# Project Charter — Mesh VPN Cá Nhân (kiểu Tailscale, tự host trên 1 VPS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-po-ba` |
| Ngày | 2026-11-12 |
| Phiên bản | 1.1 — Đã xử lý phản biện Gate 1 Vòng 1 |
| Giai đoạn | 1 — Discovery (trình Gate 1) |
| Chủ sở hữu sản phẩm | Người dùng (Product Owner kiêm Owner/Admin duy nhất) |
| Liên kết | [vision-statement.md](./vision-statement.md) · [reference-systems-benchmark.md](./reference-systems-benchmark.md) · [production-readiness-requirements.md](./production-readiness-requirements.md) · [user-personas.md](../02-product-planning/user-personas.md) · [product-backlog.md](../02-product-planning/product-backlog.md) |
| Thành phần AI/SLM | **Không có** — không áp dụng AI/Data Epic, Golden Test Set, guardrails AI |

---

## 1. Mục tiêu dự án

| # | Mục tiêu | Tiêu chí đo |
|---|---|---|
| G1 | Kết nối **3–20 thiết bị** (Windows + Linux) thành mạng overlay mã hóa đầu-cuối, tự host trên **1 VPS** | 20 node online đồng thời; mọi cặp ping được qua overlay |
| G2 | **Dùng thật 24/7** cá nhân (đủ Production-Readiness) | 100% mục Go-Live checklist (mục 6 của `production-readiness-requirements.md`) đạt ở Gate 3 |
| G3 | **Học sâu bản chất** mesh VPN (control/data plane, NAT traversal, relay) | Tài liệu ADR + backlog bám nguồn nghiên cứu; không bê nguyên hộp đen |
| G4 | **Không làm hỏng mạng máy thật** | 0 lần mất Internet do agent trong bộ test chaos (kill -9, sleep/wake, đổi mạng) |

## 2. Phạm vi

### 2.1. IN-SCOPE — MVP (Must-have)

| Nhóm | Hạng mục MVP | Epic |
|---|---|---|
| Onboarding | Khóa sinh tại client; pre-auth key one-time + TTL + hash (hỗ trợ truyền qua file/stdin/env); đăng ký idempotent; cấp IP overlay bền vững; kênh control TLS 443 (Standalone ACME không cần cổng 80, chạy sau Reverse Proxy sẵn có, hoặc pin chứng chỉ) + chứng minh khóa bằng nonce ngẫu nhiên từ server | EP-01 |
| Coordination | Control server trên VPS; lưu trữ transactional; netmap snapshot có version qua stream (chỉ đẩy khi đổi cấu trúc/trạng thái, không bão `last_seen`); agent áp diff; audit log append-only (ưu tiên thu hồi trong RAM khi đầy đĩa); CLI quản trị tách biệt qua kênh cục bộ kiểm chứng đặc quyền OS (`SEC-14`) | EP-02 |
| Data plane | WireGuard-based tunnel (userspace, chung socket với STUN/disco); Linux + Windows; MTU 1280; chống routing loop; chỉ route dải overlay | EP-03 |
| NAT traversal | STUN trên VPS (lưu bền cổng UDP cục bộ của agent); trao đổi endpoint (lọc interface ảo/bridge/overlay); disco Ping/Pong/CallMeMaybe-lite có xác thực mật mã + chống replay; phát hiện peer chết & chuyển direct↔relay (keepalive on-demand) | EP-04 |
| Relay | Relay mù TLS 443 theo public key (gắn `src_pubkey` xác thực + hàng đợi giới hạn mỗi đích drop không chặn); chỉ node đã đăng ký; rate-limit băng thông/node + trần tổng; luôn là đường cuối | EP-05 |
| Vòng đời | Thu hồi tức thì (cắt cả tunnel đang sống); node key expiry (đăng ký lại sinh khóa mới với key trói đích danh `--for`); control chết data vẫn sống (cache netmap phân quyền chặt); reconnect backoff+jitter (tự phục hồi sau lỗi TLS tạm thời/Captive Portal/lệch giờ) | EP-06 |
| Chịu lỗi mạng | Đổi mạng, sleep/wake: rebind + STUN lại + republish endpoint + fallback relay | EP-07 |
| Tên máy & Chẩn đoán | Khối hosts quản lý tự động (chặn tên hệ thống & domain Control/Relay/STUN chống vòng lặp DNS, kèm hậu tố miền nội bộ, giữ quyền đọc OS/container); CLI `status`, `ping` | EP-08 |
| Vận hành & Bảo mật | Rate-limit/anti brute-force (kèm `trusted_proxies` tường minh); structured log (không secret); listener chỉ-đọc riêng cho `/healthz` `/readyz`; backup cục bộ nhất quán + diễn tập restore; hardening VPS an toàn với VPS dùng chung (firewall `opt-in` có dry-run & auto-rollback, giữ SSH/dịch vụ sẵn có); vòng đời TLS; cài đặt + supervisor | EP-09 |
| Nền tảng | Windows Service + named pipe ACL + firewall profile/rule; Linux systemd; graceful shutdown + dọn dẹp lúc khởi động; VPS là một node mesh | EP-10 |
| Chất lượng | Phòng lab mạng giả lập (NAT/UDP block/MTU thấp); bộ kiểm thử NFR/SLO tự động; runbook (kèm hướng dẫn đồng bộ backup mã hóa ra ngoài VPS) & Go-Live checklist | EP-11 |

### 2.2. "Should-have" — vẫn thuộc vòng đời MVP nhưng cắt được nếu trễ (P1 của nghiên cứu)

`US-006` pre-auth key reusable/ephemeral · `US-011` agent validate netmap · `US-018` packet filter · `US-023` `netcheck` · `US-032` `rotate-key` thủ công · `US-037` cảnh báo xung đột dải IP/CGNAT · `US-041` `bugreport` · `US-048` metrics · `US-049` cảnh báo cá nhân · `US-050` versioning/tương thích giao thức.

### 2.3. OUT-OF-SCOPE — Phase 2+ (Could/Won't)

| Hạng mục | Story | Điều kiện kích hoạt (từ nghiên cứu) |
|---|---|---|
| macOS, Android, iOS | US-060, US-061 | Sau khi Windows/Linux ổn định |
| Tách machine key / node key, xoay node key tự động | US-062 | Khi cần xoay khóa không đăng ký lại |
| Netmap delta | US-063 | > 50 node hoặc churn cao |
| Đục lỗ hard-NAT ↔ hard-NAT (birthday paradox), UPnP/NAT-PMP/PCP | US-064 | Khi `status` cho thấy relay chiếm tỉ lệ cao |
| Relay UDP/QUIC, nhiều relay/region, peer relay | US-065 | Khi băng thông VPS thành nút cổ chai |
| Split DNS chuẩn (NRPT / systemd-resolved) | US-066 | Khi hosts file không đủ |
| ACL theo nhóm/tag + packet filter nâng cao | US-067 | Khi chia sẻ mạng với người khác |
| Subnet router, Exit node (kèm xử lý routing loop đầy đủ) | US-068 | Cần truy cập LAN nhà/duyệt web qua VPS |
| Ký node key kiểu Tailnet Lock | US-069 | Muốn giảm tin cậy vào VPS |
| OIDC/SSO, Web UI, đa người dùng | US-070 | Có người dùng ngoài bản thân |
| Kernel WireGuard/WireGuardNT | US-071 | CPU thành nút cổ chai |
| HA control plane, multi-tenant, multi-region | US-072 | Không dự kiến |

### 2.4. Loại trừ vĩnh viễn trong tầm nhìn hiện tại (Won't)

- Tương thích client Tailscale chính thức (viết lại Headscale) — *đề xuất, chờ Gate 1 xác nhận (OQ-01)*.
- Sao chép mã nguồn server AGPLv3 (NetBird) vào dự án.
- Tự phát minh thuật toán mật mã / giao thức xác thực từ nguyên thủy.
- Post-quantum (Rosenpass) — NetBird đã deprecate.

## 3. Ràng buộc (Constraints)

| # | Ràng buộc |
|---|---|
| C1 | Hạ tầng duy nhất: **1 VPS** Linux (giả định 1–2 vCPU, 1–2 GB RAM, Public IPv4 cố định); không có HA |
| C2 | Quy mô: 3–20 node; một chủ sở hữu; một tenant |
| C3 | Client MVP: **Windows + Linux** |
| C4 | Không khóa ngôn ngữ/framework/DB trong backlog — do `agile-tech-lead` (ADR) và `agile-architect` quyết định ở Gate 2 |
| C5 | Giấy phép phụ thuộc: ưu tiên MIT/BSD; **loại AGPL**; Wintun binary phân phối đúng Prebuilt Binaries License [T35] |
| C6 | Mọi SLO là **đề xuất chưa đo** — `agile-qa` đo thật; số liệu thực tế có thể điều chỉnh sau Gate 3 |
| C7 | Không có thành phần AI/SLM ⇒ giới hạn phần cứng AI (RTX 2060 6 GB, Colab/Kaggle) **không áp dụng** |

## 4. Giả định (Assumptions)

| Mã | Giả định | Nếu sai thì |
|---|---|---|
| A-01 | VPS là Linux (Ubuntu LTS) có **1 Public IPv4 cố định** (`C1`) — có thể là **VPS sạch** hoặc **VPS cá nhân đang chạy sẵn dịch vụ khác** (vd. Nginx/Caddy trên cổng 443, SSH cổng tùy chỉnh ≠ 22); mở được UDP 3478 (STUN) và kết nối TCP 443 **trực tiếp (Standalone)** hoặc **chuyển tiếp qua Reverse Proxy sẵn có** | Không thể STUN/relay; phải đổi nhà cung cấp. Lưu ý: chỉ với 1 IP VPS, nếu không cấu hình STUN phụ khác IP thì chỉ tách riêng được *Port-Dependent Mapping* (RFC 5780) |
| A-02 | Người dùng là chủ sở hữu duy nhất, đồng thời là admin; quản trị qua **SSH + CLI trên kênh cục bộ kiểm chứng đặc quyền OS (`SEC-14`)**, tuyệt đối không mở Admin API qua IP overlay hay TCP `127.0.0.1` trần | Cần Web UI/quản trị từ xa/RBAC ⇒ Phase 2 (US-070) |
| A-03 | **Tự định nghĩa giao thức** control/relay/disco (không tương thích client Tailscale) | Nếu muốn tương thích ⇒ dự án thành "viết lại Headscale"; backlog phải làm lại |
| A-04 | Data plane dùng **giao thức WireGuard** (userspace, chung socket với STUN/disco) — thư viện cụ thể do Tech Lead chọn | Nếu Tech Lead loại ⇒ cần ADR thay thế + cập nhật REL-09/10 |
| A-05 | **VPS cũng là một node mesh** (truy cập dịch vụ trên VPS qua IP overlay) | Nếu không: bỏ US-056, đơn giản hóa test routing loop |
| A-06 | Overlay **IPv4 only** ở MVP; underlay IPv4/IPv6 đều được ưu tiên LAN > IPv6 > IPv4 reflexive | IPv6 overlay ⇒ Phase 2 |
| A-07 | **Dải overlay cấu hình được**; giá trị mặc định do Architect đề xuất, phải tránh xung đột `100.64.0.0/10` của CGNAT khi có thể | — |
| A-08 | Full-mesh mặc định: mọi thiết bị của chủ thấy mọi thiết bị khác; không ACL ở MVP | ACL ⇒ US-067 |
| A-09 | **VPS là root of trust ở MVP** (đã hardening + TLS + audit); chưa có ký node key | Giảm tin cậy ⇒ US-069 |
| A-10 | Hai máy cùng sau **hard NAT** sẽ **luôn đi relay** ở MVP (chấp nhận) | Nếu tỉ lệ relay quá cao ⇒ US-064 |
| A-11 | Windows 10/11 x64 và Ubuntu LTS (x64) là nền tảng được hỗ trợ chính thức; ARM/distro khác là best-effort | Mở rộng ⇒ thêm story |
| A-12 | Backup chỉ cần DB control (lưu cục bộ nhất quán + checksum; đồng bộ mã hóa ra ngoài VPS thực hiện qua công cụ chuẩn theo Runbook); **không** chứa private key client | — |
| A-13 | Người dùng tự chịu trách nhiệm TLS theo 1 trong 3 mô hình: **(a)** Standalone có domain (ACME không cần cổng 80: `TLS-ALPN-01`/`DNS-01`), **(b)** Sau Reverse Proxy sẵn có trên VPS dùng chung, hoặc **(c)** Không có domain thì pin fingerprint chứng chỉ | Xem OQ-02 |
| A-14 | Người dùng có quyền Administrator/root trên các máy cài agent | — |

## 5. Rủi ro (Risk Register)

| Mã | Rủi ro | Khả năng | Tác động | Giảm thiểu trong Backlog | Chủ trì |
|---|---|---|---|---|---|
| R-01 | **NAT traversal thất bại thường xuyên** (CGNAT kép, 4G) ⇒ phụ thuộc relay | Cao | Trung bình | Relay 443 là Must (US-024..027); `status` đo tỉ lệ direct/relay (US-039); Phase 2 US-064 | Architect/Dev |
| R-02 | **Routing loop / vòng lặp DNS qua `hosts` / mất mạng máy thật** | Trung bình | **Rất cao** | US-016, US-038 (chặn tên hệ thống & domain Control/Relay/STUN), US-055, US-057 (chaos), OM-9 = 0 | Dev/QA |
| R-03 | **MTU blackhole** khiến SSH/HTTPS treo | Cao | Trung bình | US-017 (1280, socket ngoài không ép cứng `DF=1`), test PPPoE/4G mô phỏng | Dev/QA |
| R-04 | **Sleep/wake, đổi mạng hoặc lỗi TLS tạm thời (Captive Portal/lệch giờ)** làm treo vĩnh viễn | Cao | Cao | US-034 AC4 (retry backoff + sự kiện mạng/đồng hồ), US-035, US-036; PERF-07 | Dev/QA |
| R-05 | **Adapter ma / route mồ côi / firewall Public profile / hỏng ACL `hosts`** trên Windows | Cao | Cao | US-038 AC2, US-052, US-053, US-055 | Dev |
| R-06 | **VPS bị chiếm hoặc leo thang đặc quyền Admin từ node bị trộm / SSRF trên VPS dùng chung** | Thấp | **Rất cao** | Tách kênh Admin cục bộ kiểm chứng quyền OS (`SEC-14`: US-012, US-046), US-013 audit, US-011 validate; Phase 2 US-069 | DevOps/Tech Lead |
| R-07 | **Lộ pre-auth key / brute-force / đầu độc endpoint P2P** | Trung bình | Cao | US-002 (hash, TTL), US-004 (`--authkey-file`/stdin), US-042 rate limit + `trusted_proxies`, US-021 (xác thực mật mã disco) | Dev |
| R-08 | **Relay bị lạm dụng hoặc nghẽn dây chuyền (Head-of-Line blocking)** | Trung bình | Trung bình | US-025 (hàng đợi giới hạn mỗi đích drop không chặn + `src_pubkey`), US-027, US-048, US-049 | Dev |
| R-09 | **VPS SPOF của control** (restart, đầy đĩa, cert hết hạn) | Trung bình | Trung bình | US-033 (cache + giữ cổng UDP), US-013 AC4 (`revoke` trong RAM khi đầy đĩa), US-045 (backup/restore), US-047 (cert), US-051 (supervisor) | DevOps |
| R-10 | **Phình phạm vi** (OIDC, GUI, HA, post-quantum) | Cao | Cao | MoSCoW cứng; mục 2.3/2.4; mọi thay đổi MVP phải qua Gate | PO/SM |
| R-11 | **Bắt buộc Windows driver/ký số**: SmartScreen cảnh báo installer chưa ký; Wintun phải đúng giấy phép | Trung bình | Trung bình | US-052 (tuân thủ license); OQ-09 về code-signing | Tech Lead/DevOps |
| R-12 | **Tăng tải kiểm thử mạng** (NAT giả lập, chặn UDP, MTU thấp) khó dựng | Trung bình | Cao | US-057 là Must, làm sớm | QA/DevOps |
| R-13 | **SLO đề xuất chưa đo** có thể không khả thi (vd. P95 ≤ 5 s direct) | Trung bình | Trung bình | US-058 đo sớm; cho phép hiệu chỉnh có ghi chú tại Gate 3 | QA |
| R-14 | **Xung đột dải overlay với CGNAT** | Trung bình | Trung bình | US-008, US-037 | Architect/Dev |
| R-15 | **Giấy phép**: vô tình dùng mã AGPL | Thấp | Cao | Ràng buộc C5; kiểm tra license trong ADR | Tech Lead |
| R-16 | **Năng lực đội/độ phức tạp** (8 điểm cho hole punching; 215 SP Must) lớn so với 1 cá nhân | Cao | Cao | Gợi ý lát cắt (Walking Skeleton relay-only trước, direct sau) trong backlog mục 15.2 | PO/SM |
| R-17 | **Cài đặt/hardening làm sập dịch vụ sẵn có hoặc khóa mất SSH trên VPS đang dùng (`HR-01`)** | Cao | **Rất cao** | Hỗ trợ chạy sau Reverse Proxy + Standalone ACME không cần cổng 80; firewall mặc định deny là `opt-in` có dry-run, tự giữ SSH/dịch vụ sẵn có và tự rollback (US-024, US-046, US-047, US-051) | DevOps/Dev |

## 6. Câu hỏi mở cần người dùng chốt tại Gate 1

| Mã | Câu hỏi | Đề xuất của PO | Ảnh hưởng nếu đổi |
|---|---|---|---|
| **OQ-01** | Tự định nghĩa giao thức (học bản chất) hay tương thích client Tailscale (viết lại Headscale)? | **Tự định nghĩa** | Toàn bộ EP-01/02/04/05 |
| **OQ-02** | **Mô hình cổng 443 & TLS trên VPS của bạn**: (1) VPS đang chạy sẵn Reverse Proxy/web trên 443 (và/hoặc SSH cổng khác 22) hay dành riêng cổng 443 (Standalone)? (2) Có **domain** (dùng ACME `TLS-ALPN-01`/`DNS-01` không cần cổng 80, hoặc TLS tại Reverse Proxy sẵn có) hay không có domain (pin fingerprint chứng chỉ tự ký)? | Hỗ trợ **cả hai chế độ** (Standalone TLS 443 không cần cổng 80 **và** chạy sau Reverse Proxy sẵn có kèm `trusted_proxies`) + chế độ pin khi không có domain; firewall là `opt-in` | US-003, US-024, US-042, US-046, US-047, US-051 |
| **OQ-03** | VPS có tham gia mesh như một **node** không? | **Có** | US-056, test REL-09 |
| **OQ-04** | Dải IP overlay mặc định? (Phát hiện/tránh xung đột CGNAT thế nào?) | Cấu hình được; để Architect chọn mặc định | US-008, US-037 |
| **OQ-05** | Chấp nhận hai máy sau hard NAT **luôn đi relay** ở MVP? | **Chấp nhận** | US-064 hoãn |
| **OQ-06** | Pre-auth key **reusable/ephemeral** là Must hay Should? (nghiên cứu xếp là tùy chọn trong SEC-03 P0) | **Should** (one-time + TTL + revoke là Must) | US-006; ảnh hưởng onboarding máy ephemeral |
| **OQ-07** | Kênh cảnh báo cá nhân ưu tiên: email / Telegram / webhook? | Webhook chung (1 kênh) | US-049 |
| **OQ-08** | Hạn mức relay mặc định (đề xuất 20 Mbps/node + trần tổng) và quota băng thông tháng của VPS? | 20 Mbps/node; trần tổng = tuỳ quota VPS | US-027 |
| **OQ-09** | Nền tảng hỗ trợ chính thức: Windows 10/11 x64 + Ubuntu LTS x64? Có sẵn chứng chỉ **code-signing** cho installer Windows không? | Như đề xuất; chưa ký ở MVP, chấp nhận SmartScreen | US-052 |
| **OQ-10** | Chấp nhận **không có Web UI** và quản trị chỉ bằng CLI/SSH qua kênh cục bộ kiểm chứng quyền OS (`SEC-14`) ở MVP? | **Chấp nhận** | US-070 hoãn |
| **OQ-11** | Giấy phép dự án (open-source/private)? Chốt chính sách tránh AGPL. | Private/MIT tùy chọn; tránh AGPL | Ràng buộc C5 |
| **OQ-12** | Tên sản phẩm chính thức (ảnh hưởng tên adapter, tên service, tên CLI, hậu tố miền nội bộ `.mesh.internal`)? | Chưa chốt — dùng tên mã `Mesh` | US-038, US-052, US-054 |
| **OQ-13** | Chấp nhận **VPS là root of trust** ở MVP (chưa ký node key)? | **Chấp nhận** | US-069 hoãn |
| **OQ-14** | Ngân sách thời gian/đội: duyệt trọn gói **49 Must stories / 215 SP** hay giải ngân theo 2 cột mốc nội bộ (**Milestone 1**: Walking Skeleton + Direct P2P dùng hằng ngày → **Milestone 2**: Roaming/Key-Expiry/Chaos SLO)? | Theo lát cắt mục 15.2 backlog | Kế hoạch Sprint (Gate 2) |

## 7. Tiêu chí hoàn thành MVP (Definition of Done cấp sản phẩm)

1. Tất cả story **Must-have** đạt Acceptance Criteria bằng test tự động (hoặc kịch bản thủ công có biên bản cho các case phần cứng/hệ điều hành).
2. **Go-Live checklist** (mục 6 `production-readiness-requirements.md`) đạt 100%; kết quả đo PERF-01, 05, 06, 07 ghi vào báo cáo QA.
3. Không còn lỗi mức `Blocker`/`High` mở từ `agile-qa` / `agile-critic`.
4. Có Runbook (cài đặt, nâng cấp, backup/restore, thu hồi thiết bị, xử lý sự cố) — US-059.
5. Kiểm tra giấy phép phụ thuộc: không có mã AGPL; Wintun tuân thủ license.

## 8. Các bên liên quan & RACI rút gọn

| Vai trò | Trách nhiệm |
|---|---|
| Người dùng (PO + Owner) | Duyệt 3 Gate; trả lời Câu hỏi mở; chấp nhận phạm vi |
| `agile-po-ba` | Vision, Charter, Personas, Backlog |
| `agile-tech-lead` | Ngôn ngữ/runtime, thư viện WireGuard/STUN/TLS, chuẩn code (Gate 2) |
| `agile-architect` | C4, schema, giao thức/API contract, dải overlay mặc định (Gate 2) |
| `agile-developer` / `agile-qa` / `agile-devops` | Hiện thực, kiểm thử, đóng gói (sau Gate 2) |
| `agile-critic` | Phản biện trước mỗi Gate |
