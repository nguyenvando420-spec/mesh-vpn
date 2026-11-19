# Mesh VPN (`v0.3.0`)

Mạng **Mesh VPN P2P / Blind Relay** tự chủ (self-hosted), xây dựng bằng Rust (`1.94.1`), bảo mật Zero-TOFU theo mặc định (IP + SPKI Pin / System CA), hỗ trợ đầy đủ **5 nền tảng Client + VPS Server**:

- **Control Plane + Blind Relay + Embedded STUN (`mesh-server`)** trên Linux VPS (`systemd` hoặc Docker OCI).
- **Desktop GUI & Daemon (`meshd` + `mesh`):** Windows 10/11 (`MeshVPN.exe` + Wintun), macOS 13+ (`Mesh VPN.app` Universal Swift 6), Ubuntu/Debian/Linux (`MeshVPN` + `.deb`).
- **VPS / Headless Linux Client:** CLI `mesh` + `meshd` tĩnh `musl`.
- **Mobile Apps:** Android 8.0+ (Kotlin/Compose + `VpnService` + UniFFI) và iOS 15.0+ (Swift 6 + `NEPacketTunnelProvider` + UniFFI XCFramework).

> **Tải bộ cài đặt mới nhất:** **[GitHub Release v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**

---

## Hướng dẫn cài đặt & sử dụng theo từng môi trường

| Môi trường | Bộ cài `v0.3.0` | Tài liệu hướng dẫn riêng |
| --- | --- | --- |
| **VPS Linux Server** *(Control / Relay / STUN)* | `mesh-linux-x86_64-musl.tar.gz` / `mesh-server-image-linux-amd64.tar.gz` | [`docs/07-user-guides/vps-server.md`](docs/07-user-guides/vps-server.md) |
| **VPS / Headless Linux Client** *(CLI)* | `mesh-linux-x86_64-musl.tar.gz` | [`docs/07-user-guides/vps-linux-client.md`](docs/07-user-guides/vps-linux-client.md) |
| **Ubuntu / Debian / Linux Desktop** *(GUI)* | `mesh-vpn-linux-amd64.deb` / `mesh-linux-x86_64-musl.tar.gz` | [`docs/07-user-guides/linux-desktop.md`](docs/07-user-guides/linux-desktop.md) |
| **Windows 10/11** *(GUI + Service)* | `mesh-windows-x86_64-msvc.zip` | [`docs/07-user-guides/windows.md`](docs/07-user-guides/windows.md) |
| **macOS 13+** *(Universal `.dmg` / `.app`)* | `MeshVPN-macos-universal.dmg` / `MeshVPN-macos-universal.app.zip` | [`docs/07-user-guides/macos.md`](docs/07-user-guides/macos.md) |
| **Android 8.0+** *(APK / AAB)* | `MeshVPN-android-debug.apk` / `MeshVPN-android-release.apk` / `.aab` | [`docs/07-user-guides/android.md`](docs/07-user-guides/android.md) |
| **iOS 15.0+** *(IPA / Simulator)* | `MeshVPN-ios-unsigned.ipa` / `MeshVPN-ios-device.app.zip` / `MeshVPN-ios-simulator.app.zip` | [`docs/07-user-guides/ios.md`](docs/07-user-guides/ios.md) |

Xem mục lục tổng hợp tại [`docs/07-user-guides/README.md`](docs/07-user-guides/README.md).

---

## Cấu trúc mã nguồn chính

- `crates/`: Lõi Rust workspace (`mesh-core`, `mesh-crypto`, `mesh-proto`, `mesh-datapath`, `mesh-net`, `mesh-store`, `mesh-client`, `mesh-mobile-ffi`, `mesh-sys`, `mesh-server`, `meshd`, `mesh`, `mesh-gui`).
- `desktop/macos/`: Ứng dụng macOS Menu Bar + Dashboard (`MeshVPNApp` Swift 6 + `MeshDesktopCore`).
- `mobile/android/` & `mobile/ios/`: Ứng dụng Android (Kotlin/Compose) và iOS (`MeshApp` + `MeshPacketTunnel`).
- `scripts/` & `deploy/`: Script cài đặt/đóng gói đa nền tảng và cấu hình `systemd`, `launchd`, Polkit, reverse proxy.
- `docs/`: Tài liệu thiết kế, QA, vận hành (`06-operations`, `06-release-deployment`) và hướng dẫn người dùng (`07-user-guides`).

---

## Kiểm định cho nhà phát triển

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
```

```sh
# Linux / macOS
sh scripts/check.sh
```
