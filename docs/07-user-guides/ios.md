# Hướng Dẫn Cài Đặt & Sử Dụng trên iOS 15.0+ (`v0.3.0`)

Tài liệu này hướng dẫn cài đặt, cấp chứng chỉ ký (`NEPacketTunnelProvider`), kết nối và sử dụng **Mesh VPN trên iPhone / iPad (iOS 15.0+) và iOS Simulator**.

---

## 1. Tải gói cài đặt ở đâu?

Tải tại trang phát hành **[Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**:

| Tệp tải về | Kích thước | Mục đích |
| --- | --- | --- |
| [`MeshVPN-ios-unsigned.ipa`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-ios-unsigned.ipa) | 4.69 MiB | Gói `.ipa` cho iPhone/iPad vật lý (`arm64`, chưa ký Profile thương mại — cần ký lại trước khi cài). |
| [`MeshVPN-ios-device.app.zip`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-ios-device.app.zip) | 4.69 MiB | Thư mục `MeshApp.app` (`Release-iphoneos`) dành cho quy trình re-sign bằng công cụ tự động. |
| [`MeshVPN-ios-simulator.app.zip`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-ios-simulator.app.zip) | 14.45 MiB | Bản chạy miễn phí (`$0`) trên **iOS Simulator** của macOS Xcode. |

> **Lưu ý quan trọng về chính sách Apple (`NetworkExtension`):**
> Trên iPhone/iPad thật, Apple yêu cầu ứng dụng VPN phải được ký bằng tài khoản **Apple Developer (`$99/năm`)** kèm Provisioning Profile có quyền **`com.apple.developer.networking.networkextension`** (`packet-tunnel-provider`) và **App Group** cho cả app chính (`MeshApp`) lẫn extension (`MeshPacketTunnel`). Không thể cài thẳng `.ipa` chưa ký lên iPhone thật bằng tài khoản Apple ID miễn phí (vì tài khoản miễn phí không cấp entitlement `packet-tunnel-provider`).

---

## 2. Cài đặt lên iPhone / iPad thật (có Apple Developer Account)

### Cách A: Tự build & ký trực tiếp bằng Xcode trên máy Mac (Khuyên dùng)

Cách này đơn giản và ít lỗi chứng chỉ nhất vì Xcode tự quản lý Provisioning Profile cho cả 2 target:

```bash
# 1. Cài công cụ nếu chưa có: Rust 1.94.1, xcodegen, swiftlint
# 2. Build Rust XCFramework & sinh Swift UniFFI bindings
bash scripts/build-ios-xcframework.sh

# 3. Sinh file Xcode project
xcodegen generate --spec mobile/ios/project.yml
open mobile/ios/MeshApp.xcodeproj
```

Trong Xcode, thực hiện cho cả 2 target **`MeshApp`** (Bundle ID mặc định `dev.meshvpn.ios`) và **`MeshPacketTunnel`** (`dev.meshvpn.ios.PacketTunnel`):
1. Chọn **Team** Apple Developer của bạn ở mục *Signing & Capabilities*.
2. Nếu cần đổi Bundle ID cho duy nhất tên miền của bạn (ví dụ `com.yourorg.meshvpn` và `com.yourorg.meshvpn.PacketTunnel`), đồng bộ thêm:
   - App Group **`group.dev.meshvpn.ios`** (hoặc cập nhật khớp [`MeshConstants.swift`](../../mobile/ios/MeshCoreKit/Sources/MeshConstants.swift) & entitlement `.entitlements`)
   - Capability **Network Extensions -> Packet Tunnel**
   - Keychain Sharing (`$(AppIdentifierPrefix)dev.meshvpn.ios.shared`)
3. Chọn iPhone thật kết nối USB -> bấm **Run (Cmd + R)**.

### Cách B: Ký lại gói `MeshVPN-ios-unsigned.ipa` đã build sẵn

Nếu dùng công cụ re-sign hoặc MDM doanh nghiệp:
1. Giải nén `MeshVPN-ios-unsigned.ipa` (hoặc `MeshVPN-ios-device.app.zip`).
2. Ký theo thứ tự từ trong ra ngoài (tránh dùng cờ `--deep`):
   - Mọi framework trong `Payload/MeshApp.app/Frameworks/*.framework`
   - Extension `Payload/MeshApp.app/PlugIns/MeshPacketTunnel.appex` (với Profile & entitlement có `packet-tunnel-provider` + App Group + Keychain)
   - App chính `Payload/MeshApp.app` (với Profile & entitlement chính)
3. Nén lại thành `.ipa` và cài qua Xcode (*Window -> Devices and Simulators*), Apple Configurator hoặc TestFlight nội bộ.

---

## 3. Chạy thử miễn phí (`$0`) trên iOS Simulator (macOS)

```sh
unzip MeshVPN-ios-simulator.app.zip
xcrun simctl boot "iPhone 16" || true
xcrun simctl install booted MeshApp.app
xcrun simctl launch booted dev.meshvpn.ios
```

---

## 4. Kết nối & Sử dụng trên iPhone / iPad

1. Trên VPS Server (xem [hướng dẫn VPS Server](./vps-server.md)), sinh mã QR / URI:
   ```bash
   mesh preauthkey create --ttl 1h --name iphone-16 --emit-uri --qr
   ```
2. Mở app **Mesh VPN** trên iPhone, chọn 1 trong 3 cách:
   - **Quét QR** bằng camera trong app (`AVCaptureMetadataOutput`).
   - **Dán URI** `mesh://join?...` bằng nút dán trong app (`PasteButton`).
   - **Nhập thủ công** Endpoint + SPKI Pin (`sha256:<64_HEX>` hoặc `System CA`) + khóa `mpk_*`.
3. Xác nhận thông tin server -> bấm **Enroll & Connect** -> bấm **Allow** khi iOS hỏi thêm cấu hình VPN.

---

## 5. Ngắt kết nối đúng cách, Xoay khóa & Xử lý sự cố

- **Ngắt VPN khi bật On-Demand:** Luôn nhấn nút **Disconnect** ở trong ứng dụng **Mesh VPN** thay vì gạt trong Control Center. App sẽ chủ động tắt `isOnDemandEnabled = false` rồi lưu cấu hình trước khi gọi `stopTunnel()`, tránh việc iOS tự bật lại VPN ngay lập tức khi có lưu lượng mạng mới.
- **Xoay khóa (Rotate Key):** Sinh khóa mới trên VPS bằng `--for <ten-thiet-bi>`, trong app xác thực Face ID / Touch ID / Passcode để xoay khóa giữ nguyên IP Mesh.
- **Xuất Bugreport:** Vào **Diagnostics -> Export Bugreport** -> xác thực sinh trắc học để lưu/gửi tệp `.tar` (`<= 1 MiB`, đã lọc sạch secret).
- **Lỗi `DeviceLocked` (`-25308`) sau khi khởi động lại máy:** Mở khóa màn hình iPhone 1 lần để mở Keychain `AfterFirstUnlockThisDeviceOnly` rồi bật lại kết nối.
- **Lỗi `PinMismatch` / `ClockSkew`:** Kiểm tra bật *Settings -> General -> Date & Time -> Set Automatically*; kiểm tra SPKI Pin mới nhất trên VPS qua `mesh server status`.
