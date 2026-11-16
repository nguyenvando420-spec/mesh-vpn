# Mesh VPN `v0.2.0` — Biên Bản Nghiệm Thu Phần Cứng Di Động (`US-097`)

**Phiên bản:** `0.2.0` | **Phân tách chế độ (`OQ-MOB-02`):**
- **Android 14+ (Sideload `$0`):** Thực thi trực tiếp trên máy Android thật bằng file `.apk` xuất từ CI `$0` + `adb`.
- **iPhone vật lý (`hardware_signoff_required — chờ Apple Developer $99/năm`):** Bắt buộc ký entitlement `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) và đo bằng Xcode Instruments trên thiết bị thật.

> **Quy tắc liêm chính dữ liệu:** Runner CI và iOS Simulator không đo được radio 4G/5G vật lý, Doze modem `RRC_IDLE`, hay giới hạn Jetsam `EXC_RESOURCE` thật. Người kiểm thử **bắt buộc** thực thi trên thiết bị thật và điền số liệu đo thực tế vào Sổ cái (§4). **Tuyệt đối không bịa hoặc điền trước số đo.**

---

## 1. Chuẩn Bị Môi Trường Kiểm Thử Thực Địa

1. **VPS Control `v0.2.0`:**
   - Đang chạy `mesh-server` `v0.2.0+` (hoặc thử nghiệm thêm 1 VPS `v0.1.0-rc1` cho bài kiểm tra lỗi nâng cấp).
   - Xác nhận sẵn ít nhất 1 peer đích đang trực tuyến (ví dụ `vps.mesh.internal`, `100.64.0.1`).
2. **Mạng kiểm thử:**
   - Wi-Fi nội bộ (IPv4/dual-stack) và SIM 4G/5G (ưu tiên mạng di động IPv6-only NAT64 `64:ff9b::/96` nếu có).
3. **Sinh khóa onboarding (không truyền key qua argv):**
   ```bash
   mesh preauthkey create --ttl 2h --emit-uri --qr
   ```

---

## 2. Kịch Bản Nghiệm Thu Android 14+ (Sideload `$0`)

**Thiết bị mục tiêu:** Điện thoại Android 14 / 15+ (`arm64-v8a`), kết nối USB Debugging (`adb`).

### `M-AND-01` — Cài đặt Sideload `$0`, Onboarding & Bảo Vệ Backup/Chụp Màn Hình (`US-082`, `US-084`)
1. Xác minh checksum và cài `.apk`:
   ```bash
   sha256sum -c SHA256SUMS
   adb install -r app-release.apk   # hoặc app-debug.apk nếu chưa ký keystore thương mại
   ```
2. Thử onboarding đủ 3 luồng: QR CameraX+ZXing, Dán URI `mesh://join?...` (kiểm tra clipboard bị xóa sau khi đọc), Nhập tay `CharArray`.
3. Xác minh `FLAG_SECURE` (thử chụp màn hình bằng `adb exec-out screencap` tại màn hình nhập key phải ra ảnh đen hoặc bị chặn) và kiểm tra manifest `allowBackup="false"`:
   ```bash
   adb shell dumpsys package dev.meshvpn.android | grep -E "ALLOW_BACKUP|flags"
   ```
- **Tiêu chí Đạt:** Kết nối thành công vào mesh, hiển thị đúng Endpoint + SPKI Pin trước khi join, không lộ `mpk_*` trong `adb logcat`.

### `M-AND-02` — Đo RAM `RSS <= 48 MiB` (`US-082`, `M-GNFR-02`)
1. Giữ tunnel kết nối ổn định và truyền thử dữ liệu (ví dụ `ping` / tải HTTPS qua peer trong mesh 2 phút).
2. Đo bộ nhớ bằng `adb shell dumpsys meminfo`:
   ```bash
   # Thay bằng dev.meshvpn.android.debug nếu chạy bản debug APK
   adb shell dumpsys meminfo dev.meshvpn.android | grep -E "TOTAL PSS|TOTAL RSS|Native Heap|Dalvik Heap"
   ```
- **Tiêu chí Đạt:** `TOTAL RSS` (và `TOTAL PSS`) của tiến trình `dev.meshvpn.android` duy trì **`<= 48 MiB` (`<= 49_152 KiB`)**.

### `M-AND-03` — Split-DNS `.mesh.internal` & Private DNS `:853` (`US-083`, `ADR-015`)
1. Khi **Private DNS = Automatic**:
   - Phân giải `<peer>.mesh.internal` trong trình duyệt / Termux: kiểm tra bản ghi `A` trả `100.x.y.z`, truy vấn `AAAA` trả `NOERROR` `NODATA` (không treo Happy Eyeballs), truy vấn public domain (ví dụ `example.com`) đi qua DNS nhà mạng vật lý (`0` loop).
2. Chuyển **Private DNS = Private DNS provider hostname** (Strict, ví dụ `dns.google`):
   - Quan sát UI/Notification của Mesh VPN hiển thị tức thì cảnh báo **`AndroidPrivateDnsStrict`**.
3. Chuyển lại **Automatic**.

### `M-AND-04` — Roaming Wi-Fi ↔ 4G/5G NAT64, Doze Standby & Airplane Mode (`US-083`, `US-095`)
1. Chạy ping liên tục tới peer đích qua mesh:
   - Tắt Wi-Fi chuyển sang dữ liệu di động 4G/5G (ghi lại thời gian `T_roam_cell` đến khi có phản hồi lại).
   - Bật lại Wi-Fi (ghi `T_roam_wifi`).
   - Kiểm tra màn hình chi tiết xem có nhận diện NAT64 (`64:ff9b::/96` nếu 4G IPv6-only) và Internet công cộng bên ngoài vẫn thông (`Split-Tunnel` không chứa `0.0.0.0/0`).
2. Ép máy vào trạng thái Doze để kiểm tra `TimerMode::IdleAware`:
   ```bash
   adb shell dumpsys battery unplug
   adb shell dumpsys deviceidle force-idle
   # Chờ 5 phút rồi đo mức tiêu thụ / trạng thái giữ kết nối:
   adb shell dumpsys deviceidle unforce
   adb shell dumpsys battery reset
   ```
3. Bật **Airplane Mode** 30 giây rồi tắt, xác nhận phục hồi kết nối `<= 5 s`; test ngắt từ Android VPN Settings (`onRevoke`) xác nhận dọn sạch không crash.
- **Tiêu chí Đạt:** Mọi pha roaming & Airplane Mode phục hồi **`<= 5.0 s`**; `0` crash; `0` rò rỉ `mpk_*` trong `adb logcat` hay tệp `mesh-bugreport-*.tar`.

---

## 3. Kịch Bản Nghiệm Thu iPhone Vật Lý (`hardware_signoff_required — Apple Developer $99/năm`)

**Thiết bị mục tiêu:** iPhone vật lý chạy iOS `15.0+` (khuyến nghị kiểm tra thêm iOS 17/18+), ký bằng `APPLE_TEAM_ID` với đủ entitlements (`packet-tunnel-provider`, `group.dev.meshvpn.ios`, `keychain-access-groups`).

### `M-IOS-01` — Xcode Instruments Jetsam & Đỉnh `RSS <= 25 MiB` (`US-089`, `M-GNFR-01`)
1. Cài bản signed `MeshApp` (Debug/Release với Profile Instruments) lên iPhone thật.
2. Mở **Xcode → Open Developer Tool → Instruments → Allocations & Activity Monitor**, gắn trực tiếp vào tiến trình extension **`MeshPacketTunnel`** (`dev.meshvpn.ios.PacketTunnel`).
3. Thực hiện 3 pha tải liên tiếp trong khi ghi nhận **Resident Size (RSS)**:
   - Pha A: Kết nối idle 2 phút.
   - Pha B: Truyền burst TCP/UDP qua đường hầm mesh trong 60 giây.
   - Pha C: Kích hoạt **Export Bugreport** (`group.dev.meshvpn.ios/diagnostics/mesh-bugreport-{ts}.tar <= 1 MiB`) từ `MeshApp`.
- **Tiêu chí Đạt:** Đỉnh `RSS` của `MeshPacketTunnel` trong suốt 3 pha **`<= 25 MiB`**, **0** sự kiện `EXC_RESOURCE` / Jetsam kill.

### `M-IOS-02` — Xcode Energy Log `<= 1.5%/giờ` (`TimerMode::IdleAware` / `RRC_IDLE`, `US-089`)
1. Sạc iPhone lên `>= 90%`, rút cáp (hoặc dùng **Xcode Energy Log** qua wireless debugging / `sysdiagnose` Battery Life), bật Mesh VPN trên kết nối 4G/5G.
2. Khóa màn hình iPhone và để nghỉ liên tục **tối thiểu 60 phút** (không chạy ứng dụng nền khác).
3. Đọc tốc độ tiêu hao pin quy đổi theo giờ và tần suất đánh thức nền của `MeshPacketTunnel`.
- **Tiêu chí Đạt:** Mức tiêu hao pin bổ sung do Mesh VPN **`<= 1.5%/giờ`**, heartbeat giãn nhịp `45 s ± 2 s`, không có tick `250 ms` khi rỗi.

### `M-IOS-03` — Lock / Unlock Keychain (`-25308`) & On-Demand Disconnect (`US-088`, `US-092`)
1. Đặt iPhone có Passcode, khởi động lại máy, **chưa mở khóa** (*Before First Unlock*): kiểm tra log nếu Extension được gọi sớm trả trạng thái `DeviceLocked` (`-25308`) êm ái không crash; sau khi mở khóa lần đầu, bật lại VPN thành công (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrSynchronizable = false`).
2. Bật chế độ On-Demand trong app, sau đó nhấn nút **Disconnect** thủ công trong `MeshApp`:
   - Quan sát trong **Settings → VPN** rằng **Connect On Demand** đã tắt (`isOnDemandEnabled = false`) và tunnel không tự bật lại khi mở Safari.

### `M-IOS-04` — Roaming Wi-Fi ↔ 4G/5G NAT64 & Export Bugreport (`US-090`, `US-091`)
1. Giữ phiên ping / SSH tới `<peer>.mesh.internal` đang mở qua tunnel.
2. Tắt Wi-Fi sang 4G/5G IPv6-only NAT64, sau đó bật lại Wi-Fi, sau đó thử Airplane Mode 30 giây.
3. Xuất bugreport từ `MeshApp`, chia sẻ về máy Mac, kiểm tra `.tar <= 1_048_576` bytes và tệp tạm trong App Group đã bị xóa sau khi đóng Share Sheet.
- **Tiêu chí Đạt:** Roaming phục hồi **`<= 5.0 s`**, `0` leak DNS/route, `0` bí mật trong `.tar`.

---

## 4. Sổ Cái Nghiệm Thu Phần Cứng (`Operator Hardware Sign-Off Ledger`)

> **Hướng dẫn:** Điền giá trị đo thực tế sau khi chạy kịch bản §2 (Android `$0`) và §3 (iPhone `$99/năm`). Không chỉnh sửa hoặc bịa số liệu cho các dòng chưa kiểm thử.

### 4.1. Bảng Android 14+ (`$0` Sideload Ready)

| Thiết bị & Phiên bản OS | Người đo | Ngày (UTC) | `M-AND-01` Onboarding & `FLAG_SECURE` | `M-AND-02` `TOTAL RSS` (`<= 48 MiB`) | `M-AND-03` Split-DNS & `:853` Alert | `M-AND-04` Roam `T_recover` (`<= 5 s`) & Doze | Kết Quả |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Android 14+ — Máy 1: `________________` | `________` | `__________` | `[ ] PASS  [ ] FAIL` | `_____ MiB` | `[ ] PASS  [ ] FAIL` | Wi-Fi->4G: `___ s` / 4G->Wi-Fi: `___ s` | `[ ] PASS  [ ] FAIL` |
| Android 15+ — Máy 2: `________________` | `________` | `__________` | `[ ] PASS  [ ] FAIL` | `_____ MiB` | `[ ] PASS  [ ] FAIL` | Wi-Fi->4G: `___ s` / 4G->Wi-Fi: `___ s` | `[ ] PASS  [ ] FAIL` |

### 4.2. Bảng iPhone Vật Lý (`hardware_signoff_required — Apple Developer $99/năm`)

| Thiết bị & Phiên bản iOS | Người đo | Ngày (UTC) | `M-IOS-01` Extension Peak RSS (`<= 25 MiB`) | `M-IOS-02` Energy Log (`<= 1.5%/h`) | `M-IOS-03` `-25308` & On-Demand Off | `M-IOS-04` Roam `T_recover` (`<= 5 s`) & `.tar <= 1 MiB` | Kết Quả |
| --- | --- | --- | --- | --- | --- | --- | --- |
| iPhone — Máy 1: `________________` | `________` | `__________` | `_____ MiB` (`0` Jetsam) | `____ %/h` (`___ min`) | `[ ] PASS  [ ] FAIL` | Wi-Fi->4G: `___ s` / `.tar`: `______ B` | `[ ] PASS  [ ] FAIL  [ ] DEFERRED ($0)` |
| iPhone — Máy 2: `________________` | `________` | `__________` | `_____ MiB` (`0` Jetsam) | `____ %/h` (`___ min`) | `[ ] PASS  [ ] FAIL` | Wi-Fi->4G: `___ s` / `.tar`: `______ B` | `[ ] PASS  [ ] FAIL  [ ] DEFERRED ($0)` |

**Xác Nhận Cuối Cùng:**
- Commit / Tag kiểm định: `______________________`
- Người kiểm định & Chữ ký: `______________________`
- Thời điểm ký (UTC): `______________________`
- Trạng thái tổng thể: `[ ] ANDROID $0 PASSED   [ ] IPHONE $99 HARDWARE PASSED   [ ] DEFERRED (Pending $99 Apple Developer)`
