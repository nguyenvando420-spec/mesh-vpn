# Mesh VPN `v0.2.0` — Tài Liệu Vận Hành Di Động (Android & iOS)

**Phiên bản:** `0.2.0` | **Phạm vi:** Triển khai/nâng cấp VPS Control `v0.2.0`, sinh URI/QR onboarding `mesh://join`, vận hành Android (`VpnService`) & iOS (`NEPacketTunnelProvider`), và xử lý sự cố thực địa.
**Quy tắc bảo mật bất biến (`SEC-01`, `OQ-MOB-03`):**
- Tuyệt đối **không** truyền pre-auth key thô (`mpk_*`) qua tham số dòng lệnh (`--authkey` bị vô hiệu hóa; chỉ dùng `mesh preauthkey create --emit-uri --qr` hoặc file `0600` / stdin trên Linux).
- Tuyệt đối **không** đăng ký OS-wide clickable deep-link (`android:scheme="mesh"` / `CFBundleURLTypes`) cho `mpk_*`.

---

## Mục Lục

1. [Nâng Cấp & Triển Khai VPS Control `v0.2.0` (Tương Thích Ngược `v0.1.0-rc1`)](#1-nâng-cấp--triển-khai-vps-control-v020-tương-thích-ngược-v010-rc1)
2. [Sinh Pre-Auth URI & Mã QR Di Động (`mesh preauthkey create --emit-uri --qr`)](#2-sinh-pre-auth-uri--mã-qr-di-động-mesh-preauthkey-create---emit-uri---qr)
3. [Onboarding & Xoay Khóa Trên Android (`VpnService`)](#3-onboarding--xoay-khóa-trên-android-vpnservice)
4. [Onboarding & Xoay Khóa Trên iOS (`MeshApp` + `NEPacketTunnelProvider`)](#4-onboarding--xoay-khóa-trên-ios-meshapp--nepackettunnelprovider)
5. [Bảng Xử Lý Sự Cố Di Động (`Troubleshooting Playbook`)](#5-bảng-xử-lý-sự-cố-di-động-troubleshooting-playbook)
6. [Thu Thập & Gửi Bugreport An Toàn (`.tar <= 1 MiB`)](#6-thu-thập--gửi-bugreport-an-toàn-tar--1-mib)

---

## 1. Nâng Cấp & Triển Khai VPS Control `v0.2.0` (Tương Thích Ngược `v0.1.0-rc1`)

### 1.1. Tương Thích Ngược Với Desktop `v0.1.0-rc1`
- `mesh-server` `v0.2.0` giữ nguyên `protocol_version = 1`, `redb` `SCHEMA_VERSION = 1` (`/var/lib/mesh/control.redb`), `NetmapSnapshot`/`PeerEntry` (`#[serde(deny_unknown_fields)]`), và bổ sung `TargetOs::{Android, Ios}` (`"android"`, `"ios"`).
- Toàn bộ node Desktop `v0.1.0-rc1` (Windows, macOS, Linux) đang chạy kết nối vào VPS `v0.2.0` **không cần** đăng ký lại hay đổi SPKI pin (`server_identity` giữ nguyên 100%).
- Ngược lại, **VPS đang chạy `mesh-server` `v0.1.0-rc1` cũ** chưa nhận diện variant `"android"` / `"ios"` và sẽ trả **HTTP `400`** (`ProtocolIncompatible`) khi thiết bị di động kết nối. Cần nâng cấp `mesh-server` lên `v0.2.0` trước khi onboard Android/iOS.

### 1.2. Quy Trình Nâng Cấp An Toàn VPS Lên `v0.2.0`
Thực hiện theo [operational-runbook.md](./operational-runbook.md) (Procedure 5 & 7.2):

```bash
# 1. Sao lưu nóng atomic trên VPS trước khi thay nhị phân (bắt buộc)
mesh server backup
ls -la /var/lib/mesh/backups/

# 2. Kiểm tra cấu hình hiện tại & trạng thái pin/port
mesh server status
mesh server hardening-check

# 3. Cài nhị phân mesh-server & mesh v0.2.0 mới (cùng server_identity, không chạm control.redb)
sudo install -m 0755 ./dist/mesh-server /usr/local/bin/mesh-server
sudo install -m 0755 ./dist/mesh /usr/local/bin/mesh
sudo systemctl restart mesh-server

# 4. Xác minh sẵn sàng sau khi khởi động lại
curl -fsS http://127.0.0.1:9091/healthz
curl -fsS http://127.0.0.1:9091/readyz
mesh node list
```

> **Lưu ý mạng IPv6-only / NAT64 & Tường lửa Cloud:**
> Thiết bị di động trên 4G/5G IPv6-only tự động tổng hợp địa chỉ qua `Pref64` (`64:ff9b::/96` hoặc RFC 7050 `ipv4only.arpa`) trỏ tới IP/cổng công khai của VPS (`443/tcp` + `3478/udp`, hoặc cổng tùy chọn như `8443/tcp` + `3479/udp`). Đảm bảo Security Group của nhà cung cấp VPS mở đúng TCP Control và UDP STUN, giữ `9091/tcp` chỉ nghe `127.0.0.1`.

---

## 2. Sinh Pre-Auth URI & Mã QR Di Động (`mesh preauthkey create --emit-uri --qr`)

Trên VPS Control (với tài khoản thuộc nhóm `mesh-admin`, giao tiếp qua `/run/mesh-server/admin.sock`), dùng lệnh `mesh preauthkey create` kèm `--emit-uri` và/hoặc `--qr`:

```bash
# Sinh pre-auth key 1 lần kèm URI mesh://join và mã QR Unicode trên terminal:
mesh preauthkey create \
  --ttl 1h \
  --for pixel-8 \
  --emit-uri \
  --qr

# Khi dùng cổng tùy chọn hoặc reverse proxy / domain khác địa chỉ bind mặc định:
mesh preauthkey create \
  --ttl 30m \
  --server 203.0.113.10:8443 \
  --pin sha256:<64_HEX_SPKI_PIN> \
  --name iphone-work \
  --emit-uri \
  --qr
```

Định dạng URI chuẩn (`ADR-019`, `mesh_core::mobile_uri`):
```text
mesh://join?v=1&ep=<URL_ENCODED_HOST_PORT>&pin=sha256%3A<64_HEX>&key=mpk_<TOKEN>[&name=<NODE_NAME>]
```

- Khi dùng `tls_mode = "acme"` hoặc `"reverse_proxy"` với chứng chỉ CA công khai, tham số `pin` có thể được bỏ qua để app dùng chế độ `SystemCa` (`rustls-platform-verifier`), trong khi chế độ mặc định IP + SPKI Pin (`SpkiPin`) luôn yêu cầu `pin=sha256%3A...` (Zero-TOFU, fail-closed).
- **Bảo mật hiển thị (`SEC-01`):** `mpk_*` chỉ hiển thị **1 lần** ngay tại stdout của phiên tạo khóa; `mesh-server` chỉ lưu hash trong `redb`. Không chụp màn hình QR gửi qua kênh chat không mã hóa; xóa terminal scrollback sau khi quét xong.

---

## 3. Onboarding & Xoay Khóa Trên Android (`VpnService`)

### 3.1. Cài Đặt APK `$0` (Sideload Hoặc Bản Ký Release)
1. Tải `.apk` (hoặc `.aab` đã ký) và tệp `SHA256SUMS` từ GitHub Release `v0.2.*` (hoặc CI artifact `mesh-android-release-bundle`).
2. Kiểm tra checksum SHA-256 trước khi cài:
   ```bash
   sha256sum -c SHA256SUMS
   adb install -r app-release.apk   # hoặc app-debug.apk trong chế độ $0 sideload
   ```
3. Đảm bảo thiết bị dùng `arm64-v8a` hoặc `x86_64` (Android 8.0 API 26 trở lên; tương thích chuẩn `16 KB` page size trên Android 15+).

### 3.2. Ba Luồng Onboarding Trong App (`OQ-MOB-03`)
Trên màn hình Onboarding (được bảo vệ bởi `FLAG_SECURE` chống chụp màn hình/recent-apps thumbnail):
1. **Quét QR Nội Bộ (Khuyến nghị):** Dùng CameraX + `zxing-core` (100% offline, không Google ML Kit/GMS) quét trực tiếp mã QR sinh từ `--qr`.
2. **Dán URI Trong App:** Sao chép `mesh://join?...` và nhấn nút dán trong app. App tự động gọi `ClipboardManager.clearPrimaryClip()` (API 33+) ngay sau khi phân tích `parse_mobile_join_uri`.
3. **Nhập Tay:** Nhập `IP:cổng`, `sha256:<64hex>` (hoặc chọn `SystemCa`), và token `mpk_*` vào bộ đệm `CharArray` (tự động xóa trắng `\u0000` sau khi gọi `create_pending_join_session`).

Cả 3 luồng đều bắt buộc người dùng xem lại **Endpoint + SPKI Pin** trên màn hình xác nhận trước khi nhấn **Enroll & Connect** và cấp quyền `VpnService`.

### 3.3. Kiến Trúc Lưu Trữ & Xoay Khóa Android
- **Khởi tạo JNI:** `MeshNativeInit.initPlatformVerifier(applicationContext)` chạy idempotent trong `MeshApplication.onCreate()` và `MeshVpnService.onCreate()` để `rustls-platform-verifier` hoạt động kể cả khi khởi động qua Always-On VPN / Direct Boot.
- **Lưu trữ khóa (`noBackupFilesDir`):** Android Keystore (`AES-256-GCM`) bọc Master DEK 32-byte (`dek.enc`), giải mã tạm trong RAM để `mesh-crypto` (`ChaCha20Poly1305`) mở/niêm phong tệp **`identity.sealed.bin`** trong `context.noBackupFilesDir` (`android:allowBackup="false"`).
- **Xoay khóa định kỳ (180 ngày) hoặc khẩn cấp:**
  1. Trên VPS: `mesh preauthkey create --for <NODE_NAME> --ttl 1h --emit-uri --qr`.
  2. Trên Android app: vào **Settings → Rotate Node Key**, xác thực sinh trắc học (`BiometricPrompt` nếu bật), quét QR / dán URI mới; `MobileEngine::rotate_key` cập nhật khóa giữ nguyên Overlay IP (`100.x.y.z`).

---

## 4. Onboarding & Xoay Khóa Trên iOS (`MeshApp` + `NEPacketTunnelProvider`)

> **Lưu ý `OQ-MOB-02` (`$0` Mode vs Apple Developer `$99/năm`):**
> Bản iOS cần tài khoản Apple Developer trả phí (`$99/năm`) để ký entitlement `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`) khi chạy trên iPhone vật lý. Ở chế độ `$0`, toàn bộ logic `MeshCoreKit`, `MeshApp`, `MeshPacketTunnel`, và `MeshMobileFFI.xcframework` được kiểm chứng qua `xcodebuild test` trên iOS Simulator (`CODE_SIGNING_ALLOWED=NO`).

### 4.1. Luồng Onboarding & Bàn Giao Giữa 2 Tiến Trình (`ADR-018`)
1. `MeshApp` (tiến trình UI) nhận URI qua camera `AVCaptureMetadataOutput`, `PasteButton` (`#available(iOS 16.0, *)`) / nút dán `UIPasteboard` (iOS 15), hoặc nhập tay.
2. Sau khi người dùng xác nhận Endpoint + SPKI Pin, `MeshApp` gọi trực tiếp **`mobile_enroll_or_rotate_node(...)`**:
   - Giao tiếp Control `POST /v1/auth/challenge` + `POST /v1/nodes/register`.
   - Niêm phong `identity.sealed.bin` bằng Master DEK lưu trong Keychain Access Group (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrSynchronizable = false`) và ghi non-secret `bootstrap.toml` vào App Group (`group.dev.meshvpn.ios`).
   - Xóa trắng `MobilePendingJoinSession` trong RAM (`0` byte `mpk_*` đi qua `providerConfiguration`, App Group hay `sendProviderMessage`).
3. `MeshApp` yêu cầu người dùng cấp quyền VPN (`NETunnelProviderManager.saveToPreferences`) và khởi động `MeshPacketTunnel` (`dev.meshvpn.ios.PacketTunnel`).
4. `MeshPacketTunnel` cấu hình `NEIPv4Settings` với prefix **`/32`** (`255.255.255.255`), `includedRoutes = [overlay_cidr]` (hoặc danh sách `/32` + `overlay_dns_ip/32` khi trùng LAN), và `NEDNSSettings(matchDomains: ["mesh.internal"])`.

### 4.2. Xoay Khóa & Ngắt Kết Nối On-Demand Trên iOS
- **Xoay khóa:** Sinh key mới trên VPS bằng `mesh preauthkey create --for <NODE_NAME> --emit-uri --qr`. Trong `MeshApp`, xác thực `LocalAuthentication` (Face ID / Touch ID / Passcode) và thực hiện rotate qua `mobile_enroll_or_rotate_node(..., rotate_existing_identity: true)` rồi reload tunnel.
- **Ngắt kết nối thủ công (On-Demand):** Khi người dùng nhấn **Disconnect**, `MeshApp` **bắt buộc** đặt `manager.isOnDemandEnabled = false` và lưu cấu hình (`saveToPreferences`) **trước** khi gọi `stopTunnel()`, tránh iOS tự kích hoạt lại VPN ngay khi có gói mạng mới.

---

## 5. Bảng Xử Lý Sự Cố Di Động (`Troubleshooting Playbook`)

| Mã / Triệu chứng | Nguyên nhân gốc | Hành động xử lý chuẩn |
|---|---|---|
| **`ServerUpgradeRequired`** (HTTP `400`, `E_SERVER_UPGRADE_REQUIRED`) | `mesh-server` đang chạy bản `v0.1.0` cũ chưa có `TargetOs::{Android, Ios}`. Client chủ động **dừng retry** để tránh bão kết nối. | 1. Trên VPS chạy `mesh server backup` rồi nâng cấp `mesh-server` lên `v0.2.0+` (Mục 1.2).<br>2. Nhấn **Reconnect** trên app di động (không cần re-enroll). |
| **`DeviceLocked`** (iOS `-25308` `errSecInteractionNotAllowed` / Android Direct Boot) | Thiết bị vừa khởi động lại và người dùng chưa mở khóa màn hình lần đầu (*Before First Unlock*), nên Keychain `AfterFirstUnlockThisDeviceOnly` hoặc Android `noBackupFilesDir` chưa giải mã được. | 1. Mở khóa màn hình thiết bị 1 lần.<br>2. Trên Android, `BootReceiver` lắng nghe `ACTION_USER_UNLOCKED` và tự kết nối lại Always-On VPN.<br>3. Trên iOS, mở lại app hoặc bật lại toggle VPN sau khi mở khóa. |
| **`KeystoreInvalidated`** (`E_KEYSTORE_INVALIDATED`) | Khóa KEK phần cứng Android bị vô hiệu hóa (xóa mật khẩu màn hình, xóa toàn bộ vân tay/khuôn mặt) hoặc `identity.sealed.bin` bị hỏng. Hệ thống fail-closed, **cấm** tự tạo khóa giả. | 1. Trên VPS, thu hồi/cấp lại key gắn đúng node cũ: `mesh preauthkey create --for <NODE_NAME> --ttl 1h --emit-uri --qr`.<br>2. Trên app, chọn **Reset & Re-Enroll**, quét QR mới để đăng ký lại sạch sẽ. |
| **Captive Portal** (`CaptivePortalSuspected` / không ra Internet ở Wi-Fi công cộng) | Wi-Fi khách sạn/sân bay chặn TLS cổng `443`/`8443` bằng trang đăng nhập HTTP/TLS giả. | 1. Vì Mesh VPN chạy **Split-Tunnel** (không chiếm `0.0.0.0/0`), người dùng mở trình duyệt hoặc nhấn thông báo Captive Portal của OS để đăng nhập Wi-Fi bình thường.<br>2. Ngay sau khi Wi-Fi thông, client tự nối lại theo `ExponentialBackoff` (trần `5 phút`). |
| **Android Strict Private DNS (`:853`)** (`AndroidPrivateDnsStrict`) | Người dùng bật **Private DNS = Private DNS provider hostname** (DoT Strict `dns.google` / `one.one.cloudflare-dns.com`). Android `netd` có thể ép mọi truy vấn DNS (kể cả `.mesh.internal`) đi DoT `:853` bỏ qua DNS của VPN. *(Lưu ý: chế độ `Automatic`/Opportunistic hoạt động bình thường nhờ Mesh FFI trả `TCP RST|ACK` tức thì cho probe `:853`.)* | 1. Chuyển **Settings → Network & internet → Private DNS** sang **Automatic** hoặc **Off** nếu cần phân giải tên `*.mesh.internal`.<br>2. Nếu buộc giữ Strict Private DNS, dùng trực tiếp **Overlay IP** (`100.x.y.z`) của peer. |
| **iOS VPN Tự Kết Nối Lại Sau Khi Disconnect** | `NEOnDemandRule` vẫn bật (`isOnDemandEnabled = true`) khi gọi `stopTunnel`. | 1. Ngắt bằng nút **Disconnect** trong `MeshApp` (luôn set `isOnDemandEnabled = false` + `saveToPreferences` trước `stopTunnel`).<br>2. Nếu lỡ tắt từ Control Center, vào `MeshApp` nhấn Disconnect để đồng bộ lại preference. |
| **Android Lockdown Mode** (`AndroidLockdownActive`, `isLockdownEnabled()`) | Bật *"Block connections without VPN"* trong Android VPN Settings. | Các socket đã `protect(fd)` của Mesh giữ kết nối P2P/Relay, nhưng lưu ý nếu tắt Mesh VPN khi bật Lockdown, toàn bộ Internet của máy sẽ bị OS chặn. |
| **`PinMismatch` / `ClockSkew`** | Đồng hồ máy lệch quá hạn chứng chỉ (`ClockSkew`) hoặc VPS đổi IP/TLS pin (`PinMismatch`, Zero-TOFU từ chối kết nối). | 1. `ClockSkew`: bật đồng bộ ngày giờ tự động (*Automatic date & time*) trên điện thoại.<br>2. `PinMismatch`: xác minh pin thật trên VPS bằng `mesh server status` và cập nhật qua `update_server_config` / re-enroll nếu VPS vừa đổi chứng chỉ ngoài cửa sổ `next_pin`. |

---

## 6. Thu Thập & Gửi Bugreport An Toàn (`.tar <= 1 MiB`)

Cả Android và iOS dùng chung hàm `MobileEngine::export_bugreport_to_file(dest_path)` tạo tệp **`mesh-bugreport-{ts}.tar`** kích thước tối đa **`1_048_576` bytes (`1 MiB`)** bằng cơ chế streaming `BufWriter` `8 KiB`, tự động lọc đỏ mọi khóa bí mật (`mpk_*`, private key, DEK, proof, token) và **không** gọi `sysexec`.

### 6.1. Android
1. Vào **Diagnostics → Export Bugreport**.
2. Nếu có bật khóa bảo vệ, xác thực `BiometricPrompt` -> engine xuất `.tar` vào thư mục cache riêng và mở Android **Share Sheet** qua `FileProvider` (`${applicationId}.fileprovider`).
3. Sau khi gửi tệp cho đội vận hành, app dọn sạch tệp `.tar` tạm.

### 6.2. iOS
1. Vào **Diagnostics → Export Bugreport** (xác thực Face ID / Touch ID / Passcode).
2. `MeshPacketTunnel` ghi streaming trực tiếp ra App Group container **`group.dev.meshvpn.ios/diagnostics/mesh-bugreport-{ts}.tar`** (`<= 1 MiB`) — tuyệt đối **không** truyền qua `sendProviderMessage` (`<= 4 KiB`). Nếu RAM khả dụng iOS giảm dưới `6 MiB` (`JETSAM_SHED_THRESHOLD_BYTES`), thao tác export từ chối an toàn để tránh Jetsam `SIGKILL`.
3. `MeshApp` mở `UIActivityViewController` để chia sẻ tệp `.tar` và tự xóa tệp tạm ngay khi Share Sheet đóng.

### 6.3. Kiểm Tra Tệp Bugreport Phía Người Vận Hành
```bash
# Giải nén và kiểm tra nhanh 0 bí mật lọt vào bundle:
tar -tzf mesh-bugreport-*.tar
tar -xOf mesh-bugreport-*.tar | grep -E 'mpk_|PRIVATE KEY|secret|dek' || echo "Clean: 0 secrets found"
```
