# User Personas — Mesh VPN Cá Nhân

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-po-ba` |
| Ngày | 2026-11-12 |
| Phiên bản | **1.1** — Đồng bộ Gate 1: MacBook/macOS vào MVP (P1, P3); bỏ P6 khỏi danh sách hoãn |
| Phạm vi | Cá nhân tự host (self-hoster / developer cá nhân), 3–20 thiết bị, **macOS + Windows (client) + Ubuntu Linux VPS kiêm node** ở MVP |
| Ghi chú | Không có persona doanh nghiệp. Cả 3 persona chính đều là **cùng một loại người dùng ở các ngữ cảnh khác nhau**; vai trò hệ thống duy nhất ở MVP là **Chủ mạng (Owner/Admin)**. |

---

## 1. Persona chính

### P1 — Minh, "Chủ mạng kiêm quản trị" (Owner / Admin)

| | |
|---|---|
| Chân dung | 29 tuổi, developer backend freelance; có 1 PC desktop ở nhà (Windows, dual-boot Linux), **1 MacBook (macOS, Apple Silicon) dùng làm máy chính khi di chuyển**, 1 laptop Windows, 1 VPS Ubuntu 1–2 GB RAM đang chạy vài dịch vụ cá nhân (kết nối thẳng bằng **IP VPS + pin**, chưa có domain) |
| Mục tiêu | SSH/RDP/SMB/Git/dev-server giữa các máy bằng IP/tên cố định; học bản chất mesh VPN bằng cách tự xây; tự chủ dữ liệu |
| Kỹ năng | Quen CLI, SSH, systemd, firewall cơ bản; **không** muốn vận hành một hệ thống phức tạp như Kubernetes |
| Nỗi đau | WireGuard thủ công: sửa config hub mỗi lần thêm máy; đã từng bị "treo SSH sau khi đổi Wi-Fi"; sợ cài VPN làm hỏng mạng PC chính; sợ lộ khóa |
| Kỳ vọng vận hành | Quản trị hoàn toàn bằng CLI qua SSH tới VPS; backup tự động; biết ngay khi VPS/chứng chỉ có vấn đề; mất laptop thì thu hồi ≤ 10 s |
| Tiêu chí "đủ tốt" | Chạy 24/7 cả tuần không cần chạm vào; `status` trả lời được "vì sao máy này chậm — direct hay relay?" |
| Story chủ yếu | Onboarding (lệnh tham gia `IP:cổng` + pin), thu hồi, backup/restore, hardening VPS, đổi cổng/IP không mất danh tính (`US-074`), cài macOS daemon (`US-073`), `status`, audit log |

### P2 — Tuấn, "Home-lab self-hoster headless" (thiết bị không có người ngồi trước)

| | |
|---|---|
| Chân dung | 34 tuổi, sysadmin chạy NAS/mini-PC Linux ở nhà sau **CGNAT** của nhà mạng; thiết bị chạy không màn hình |
| Mục tiêu | NAS/home-server luôn truy cập được từ laptop dù không mở được cổng router |
| Nỗi đau | Hai đầu cùng sau NAT cứng ⇒ không P2P được; innernet-style không relay là bất khả thi; khi mất điện/restart thì phải tự lên lại không cần người |
| Kỳ vọng | Đăng ký **không tương tác** bằng pre-auth key (có thể ephemeral cho container/VM thử nghiệm); service tự chạy khi boot; tự phục hồi sau crash; vẫn thông qua relay khi mạng chỉ cho 443 |
| Story chủ yếu | Onboarding headless, relay fallback, supervisor/tự khởi động, graceful cleanup, node key expiry (tắt cho server tin cậy) |

### P3 — Lan, "Người dùng di động" (Nomad laptop)

| | |
|---|---|
| Chân dung | 26 tuổi, developer remote; **MacBook (macOS Apple Silicon) là máy chính, kèm laptop Windows**; dùng Wi-Fi nhà → quán cà phê → hotspot 4G → khách sạn (thường chặn UDP, chỉ cho 80/443) |
| Mục tiêu | Mở MacBook/laptop ở đâu cũng vào được dev-server ở nhà/VPS trong vài giây; sleep/wake (đóng/mở nắp) không phải khởi động lại VPN |
| Nỗi đau | Treo sau sleep/wake dù UI báo "Connected"; mạng khách sạn chặn UDP; SSH vào được nhưng `ls` dài thì treo (MTU blackhole); sợ VPN macOS đụng `utun` của iCloud Private Relay/VPN khác hoặc bị Gatekeeper/Application Firewall chặn âm thầm |
| Kỳ vọng | Phục hồi ≤ 15 s sau đổi mạng/wake (MacBook và Windows); luôn có đường (relay, cổng 443 khi mạng chỉ cho 80/443); cài/gỡ không để lại adapter ma/`utun`/route/khối hosts, không phá Wi-Fi/Internet của máy; user thường không điều khiển được daemon |
| Story chủ yếu | Roaming/sleep-wake (`US-035` macOS, `US-036` Windows), relay, MTU, macOS `utun` + daemon `launchd` (`US-060`, `US-073`), Windows service/firewall, tên máy `.mesh.internal`, `ping` |

---

## 2. Tác nhân phi-người dùng (Threat actors — dùng để viết Failure/Abuse case)

| Mã | Tác nhân | Hành vi | Story phòng vệ chính |
|---|---|---|---|
| TA-1 | Kẻ quét Internet | Đoán pre-auth key, DoS endpoint đăng ký | US-042 (rate limit), US-002 (key entropy/hash) |
| TA-2 | Người lạ dùng ké relay | Kết nối relay không đăng ký để dùng băng thông VPS | US-027 |
| TA-3 | Kẻ nhặt được laptop (MacBook/Windows) bị mất | Dùng tunnel vào mạng nhà | US-029, US-030, US-031 |
| TA-4 | Kẻ chiếm được VPS / MITM (kể cả khi client kết nối thẳng bằng IP, không có CA) | Chèn node giả vào netmap, đọc metadata, giả server để lấy pre-auth key | US-003, US-047 (Pin, cấm TOFU), US-011; Phase 2: US-069 |
| TA-5 | Sự cố mạng (CGNAT kép, chặn UDP, đổi IP) | Không kết nối / treo | US-021, US-024..US-026, US-035, US-036 |

## 3. Persona phụ (Phase 2+ — **không** thiết kế ở MVP)

| Mã | Persona | Vì sao hoãn |
|---|---|---|
| P4 | **Thành viên gia đình / bạn bè** được chia sẻ một vài máy | Cần ACL theo nhóm/tag, đa người dùng, OIDC (US-067, US-070) |
| P5 | **Người dùng mobile** (Android/iOS) | Cần client riêng (US-061) |

> **P6 (người dùng macOS) không còn trong danh sách hoãn**: macOS 13+ (`arm64` + `amd64`) là client hạng nhất ở MVP, được phủ bởi P1 Minh và P3 Lan (`US-060`, `US-073`, `US-035`, `US-038`, `US-055`).

## 4. Bản đồ Persona → Epic

| Epic | P1 Minh | P2 Tuấn | P3 Lan |
|---|:--:|:--:|:--:|
| EP-01 Onboarding & Định danh | ● | ● | ○ |
| EP-02 Coordination & Netmap | ● | ○ | ○ |
| EP-03 Data Plane & Routing an toàn | ○ | ○ | ● |
| EP-04 NAT Traversal | ○ | ● | ● |
| EP-05 Relay | ○ | ● | ● |
| EP-06 Vòng đời thiết bị & Chịu lỗi Control | ● | ● | ● |
| EP-07 Roaming/Sleep-Wake | ○ | ○ | ● |
| EP-08 Tên máy & CLI chẩn đoán | ● | ○ | ● |
| EP-09 Vận hành & Bảo mật | ● | ● | ○ |
| EP-10 Tích hợp nền tảng & Dọn dẹp | ○ | ● | ● |
| EP-11 Kiểm thử NFR & Runbook | ● | ○ | ○ |

(● chính, ○ phụ) — Cột P1/P3 nay bao gồm cả **MacBook/macOS** (EP-03 `US-060`, EP-07 `US-035`, EP-10 `US-073`).
