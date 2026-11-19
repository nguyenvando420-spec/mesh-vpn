# Hướng Dẫn Cài Đặt & Sử Dụng trên Android (`v0.3.0`)

Tài liệu này hướng dẫn cài đặt, quét mã QR đăng ký thiết bị, vận hành và xử lý sự cố ứng dụng **Mesh VPN trên Android 8.0+ (API 26+)**.

---

## 1. Tải gói cài đặt ở đâu?

Tải tại trang phát hành **[Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**:

| Tệp tải về | Kích thước | Mục đích |
| --- | --- | --- |
| [`MeshVPN-android-debug.apk`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-android-debug.apk) | 35.19 MiB | **Khuyên dùng để sideload miễn phí (`$0`):** cài trực tiếp lên điện thoại Android hoặc máy ảo (`arm64-v8a` & `x86_64`, hỗ trợ chuẩn `16 KB` page size trên Android 15+). |
| [`MeshVPN-android-release.apk`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-android-release.apk) | 18.40 MiB | Gói Release (ký lại bằng keystore riêng nếu chưa ký, hoặc cài trực tiếp nếu đã ký keystore release). |
| [`MeshVPN-android-release.aab`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-android-release.aab) | 10.31 MiB | Android App Bundle dùng khi xuất bản lên Google Play Console. |

---

## 2. Cài đặt APK lên thiết bị

### Cách 1: Cài trực tiếp trên điện thoại
1. Tải `MeshVPN-android-debug.apk` về máy Android.
2. Mở tệp `.apk` -> cho phép **Install unknown apps** nếu hệ thống hỏi -> bấm **Install**.

### Cách 2: Cài từ máy tính qua ADB (và kiểm tra SHA-256)
```bash
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-android-debug.apk
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS

adb install -r MeshVPN-android-debug.apk
```

---

## 3. Kết nối vào mạng Mesh VPN (3 cách Onboarding)

Trên máy chủ VPS (xem [hướng dẫn VPS Server](./vps-server.md)), tạo mã QR & URI đăng ký:

```bash
mesh preauthkey create --ttl 1h --name android-phone --emit-uri --qr
```

Mở ứng dụng **Mesh VPN** trên điện thoại (màn hình Onboarding có `FLAG_SECURE` chống chụp lén) và chọn 1 trong 3 cách:

1. **Quét mã QR (Khuyên dùng):** Quét trực tiếp mã QR hiển thị trên VPS bằng camera (hoạt động 100% offline qua CameraX + ZXing).
2. **Dán URI `mesh://join?...`:** Sao chép chuỗi `mesh://join?v=1&...` và nhấn nút **Paste URI** trong app *(ứng dụng tự xóa clipboard ngay sau khi phân tích trên Android 13+)*.
3. **Nhập thủ công:** Nhập Control Endpoint (`<IP_HOAC_DOMAIN>:443`), `SPKI Pin` (`sha256:<64_HEX>`) hoặc chọn `System CA` (chỉ khi dùng tên miền HTTPS hợp lệ), và khóa `mpk_*`.

Sau đó kiểm tra lại **Endpoint + SPKI Pin** trên màn hình xác nhận -> bấm **Enroll & Connect** -> đồng ý hộp thoại cấp quyền **`VpnService`** của Android.

---

## 4. Vận hành & Tính năng chính

- **Always-On VPN & Direct Boot:** Có thể bật *Always-on VPN* trong *Settings -> Network & internet -> VPN -> Mesh VPN*. Khóa thiết bị được niêm phong bằng Android Keystore (`AES-256-GCM`) trong `noBackupFilesDir`.
- **Xoay khóa thiết bị (Rotate Key):**
  1. Trên VPS tạo khóa gắn đúng node: `mesh preauthkey create --for android-phone --ttl 1h --emit-uri --qr`.
  2. Trên app Android vào **Settings -> Rotate Node Key** -> xác thực vân tay/mã PIN -> quét QR/dán URI mới (giữ nguyên Overlay IP).
- **Xuất báo cáo chẩn đoán:** Vào **Diagnostics -> Export Bugreport** để chia sẻ gói `.tar` (`<= 1 MiB`, đã loại bỏ toàn bộ secret).

---

## 5. Xử lý sự cố thường gặp

| Triệu chứng / Mã lỗi | Nguyên nhân | Cách khắc phục |
| --- | --- | --- |
| **`AndroidPrivateDnsStrict`** (Không phân giải được tên `*.mesh.internal`) | Máy bật **Private DNS = Private DNS provider hostname** (ép toàn bộ DNS qua DoT `:853`). | Chuyển **Settings -> Network & internet -> Private DNS** sang **Automatic** hoặc **Off** (nếu buộc giữ Strict, kết nối bằng IP `100.x.y.z`). |
| **`DeviceLocked`** | Máy vừa khởi động lại chưa mở khóa màn hình lần đầu (*Before First Unlock*). | Mở khóa màn hình điện thoại 1 lần để giải mã Keystore và tự kết nối lại. |
| **`KeystoreInvalidated`** | Người dùng xóa toàn bộ khóa màn hình/vân tay hoặc đổi bảo mật khiến khóa phần cứng bị hủy. | Tạo key mới trên VPS (`--for <node-name>`) -> trong app chọn **Reset & Re-Enroll** và quét lại QR. |
| **Chế độ Lockdown (*Block connections without VPN*)** | Ngắt Mesh VPN sẽ chặn toàn bộ Internet của máy. | Muốn dùng Internet không qua Mesh VPN, tắt tùy chọn *Block connections without VPN* trong VPN Settings của Android. |
| **Wi-Fi khách sạn / sân bay (Captive Portal)** | Wi-Fi chặn TLS để bắt đăng nhập qua trình duyệt. | Mesh chạy Split-Tunnel nên vẫn mở trình duyệt đăng nhập Wi-Fi bình thường; sau khi thông mạng app tự nối lại. |
