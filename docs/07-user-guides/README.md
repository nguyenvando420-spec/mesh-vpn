# Hướng Dẫn Sử Dụng Mesh VPN theo Từng Môi Trường (`v0.3.0`)

Trang tổng hợp các tài liệu hướng dẫn tải về, cài đặt và sử dụng chi tiết cho **từng môi trường riêng biệt** của **Mesh VPN `v0.3.0`**.

Tất cả bộ cài nhị phân, gói `.deb`, `.dmg`, `.zip`, `.apk`, `.aab`, `.ipa`, Docker image và tệp kiểm tra toàn vẹn `SHA256SUMS` đều được phát hành thống nhất tại:
> **[GitHub Release Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**

---

## Danh sách hướng dẫn theo từng môi trường

| Môi trường | Gói tải về trên Release `v0.3.0` | Tài liệu chi tiết |
| --- | --- | --- |
| **1. VPS Linux Server** *(Control + Blind Relay + STUN)* | `mesh-linux-x86_64-musl.tar.gz` *(khuyên dùng)* hoặc `mesh-server-image-linux-amd64.tar.gz` *(Docker)* | [Hướng dẫn VPS Server](./vps-server.md) |
| **2. VPS / Server Linux Client** *(CLI không giao diện)* | `mesh-linux-x86_64-musl.tar.gz` | [Hướng dẫn VPS Linux Client](./vps-linux-client.md) |
| **3. Ubuntu / Debian / Linux Desktop** *(GUI + `.deb`)* | `mesh-vpn-linux-amd64.deb` *(hoặc `mesh-linux-x86_64-musl.tar.gz`)* | [Hướng dẫn Linux Desktop](./linux-desktop.md) |
| **4. Windows 10/11** *(Desktop GUI `MeshVPN.exe` + Service)* | `mesh-windows-x86_64-msvc.zip` | [Hướng dẫn Windows](./windows.md) |
| **5. macOS 13+** *(Universal `Mesh VPN.app` + DMG)* | `MeshVPN-macos-universal.dmg` / `MeshVPN-macos-universal.app.zip` | [Hướng dẫn macOS](./macos.md) |
| **6. Android 8.0+** *(APK / AAB)* | `MeshVPN-android-debug.apk`, `MeshVPN-android-release.apk`, `MeshVPN-android-release.aab` | [Hướng dẫn Android](./android.md) |
| **7. iOS 15.0+** *(IPA / Simulator App)* | `MeshVPN-ios-unsigned.ipa`, `MeshVPN-ios-device.app.zip`, `MeshVPN-ios-simulator.app.zip` | [Hướng dẫn iOS](./ios.md) |

---

## Luồng triển khai nhanh toàn mạng trong 5 phút

1. **Cài Server trên VPS:** Mở [Hướng dẫn VPS Server](./vps-server.md) -> chạy `scripts/install-server.sh` -> mở cổng `443/tcp` + `3478/udp`.
2. **Tạo khóa / QR kết nối cho từng thiết bị trên VPS:**
   ```bash
   mesh preauthkey create --ttl 1h --name laptop-01 --emit-uri --qr
   ```
3. **Cài Client & kết nối:** Chọn đúng tài liệu cho Windows, macOS, Ubuntu/Debian Desktop, VPS Linux, Android hoặc iOS ở bảng trên -> dán URI `mesh://join?...` (hoặc quét QR trên điện thoại / chạy `mesh up --authkey-stdin` trên VPS) -> kiểm tra thông mạng bằng `mesh status` và `mesh ping <peer>`.
