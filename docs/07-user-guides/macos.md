# Hướng Dẫn Cài Đặt & Sử Dụng trên macOS 13+ (`v0.3.0`)

Tài liệu này hướng dẫn cài đặt **Mesh VPN.app** (Universal binary chạy native trên cả Apple Silicon `arm64` lẫn Intel `x86_64`), daemon nền `internal.mesh.meshd` và CLI `mesh` trên macOS 13 trở lên.

---

## 1. Tải gói cài đặt ở đâu?

Tải tại trang phát hành **[Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**:

| Gói cài đặt | Tệp tải về | Khi nào dùng |
| --- | --- | --- |
| **Desktop GUI Universal (Khuyên dùng)** | [`MeshVPN-macos-universal.dmg`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-macos-universal.dmg) *(9.00 MiB)*<br>hoặc [`MeshVPN-macos-universal.app.zip`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/MeshVPN-macos-universal.app.zip) *(8.19 MiB)* | Chứa `Mesh VPN.app` kèm sẵn nhị phân Universal `meshd`, `mesh`, `internal.mesh.meshd.plist`, `install-macos.sh` và `SHA256SUMS`. |
| **Chỉ dùng CLI (tùy chọn)** | [`mesh-darwin-arm64.tar.gz`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-darwin-arm64.tar.gz) / [`mesh-darwin-x86_64.tar.gz`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-darwin-x86_64.tar.gz) | Máy chỉ cần CLI `mesh`, daemon `meshd` hoặc chạy test server cục bộ. |

---

## 2. Cài đặt `Mesh VPN.app` và Dịch vụ nền `meshd`

### Bước 1: Kiểm tra checksum và đưa ứng dụng vào `/Applications`

```sh
shasum -a 256 MeshVPN-macos-universal.dmg
```

1. Mở `MeshVPN-macos-universal.dmg` (hoặc giải nén `MeshVPN-macos-universal.app.zip`).
2. Kéo **`Mesh VPN.app`** thả vào thư mục **`/Applications`**.
3. **Lần mở đầu tiên (`$0` Ad-Hoc Signed):** Vì bản miễn phí không có Apple Developer Notarization, nhấn **chuột phải (Control + Click)** vào `/Applications/Mesh VPN.app` -> chọn **Open** (hoặc mở *System Settings -> Privacy & Security -> Open Anyway*). **Tuyệt đối không tắt Gatekeeper toàn hệ thống.**

### Bước 2: Cài đặt và khởi chạy LaunchDaemon `internal.mesh.meshd`

`Mesh VPN.app` cần daemon nền `meshd` chạy quyền `root` để tạo giao diện `utun` và điều khiển route. Chọn **1 trong 2 cách**:

- **Cách 1 — Trực tiếp từ giao diện (Khuyên dùng):**
  1. Mở `Mesh VPN.app` -> trên Dashboard bấm **Install Background Service** (hoặc **Start Service** nếu đã cài trước đó).
  2. Nhập mật khẩu quản trị macOS khi hộp thoại hệ thống hiện lên.
- **Cách 2 — Từ Terminal:**
  ```sh
  sudo /bin/sh "/Applications/Mesh VPN.app/Contents/Resources/install-macos.sh" \
    --from "/Applications/Mesh VPN.app/Contents/Resources" \
    --sha256-file "/Applications/Mesh VPN.app/Contents/Resources/SHA256SUMS" \
    --plist "/Applications/Mesh VPN.app/Contents/Resources/internal.mesh.meshd.plist"
  ```

### Xử lý nhanh nếu gặp thông báo `meshd is installed at /usr/local/libexec/mesh/meshd, but is not listening on /var/run/meshd/meshd-ro.sock`

Điều này xảy ra khi bạn mới chép `Mesh VPN.app` vào `/Applications` hoặc LaunchDaemon `internal.mesh.meshd` đang dừng. Hãy xử lý bằng một trong hai lệnh sau trong Terminal:

```sh
# Nếu service đã cài nhưng bị dừng:
sudo launchctl kickstart -kp system/internal.mesh.meshd

# Hoặc cài/sửa đồng bộ lại toàn bộ daemon + plist + quyền thư mục:
sudo /bin/sh "/Applications/Mesh VPN.app/Contents/Resources/install-macos.sh" \
  --from "/Applications/Mesh VPN.app/Contents/Resources" \
  --sha256-file "/Applications/Mesh VPN.app/Contents/Resources/SHA256SUMS" \
  --plist "/Applications/Mesh VPN.app/Contents/Resources/internal.mesh.meshd.plist"
```

Nếu vẫn chưa chạy, kiểm tra nhật ký lỗi tại `/var/log/mesh/`.

---

## 3. Kết nối vào mạng Mesh VPN

1. Bấm biểu tượng **Mesh VPN** trên Menu Bar (hoặc chạy `mesh gui` từ Terminal).
2. Chọn phương thức đăng ký:
   - **Dán URI `mesh://join?v=1&...`:** Dán chuỗi nhận từ server vào ô Onboarding. *(Clipboard tự xóa an toàn sau 30 giây nếu không bị thay đổi).*
   - **Nhập tay:** Nhập `<IP_HOAC_DOMAIN>:443`, `sha256:<64_HEX>` SPKI Pin (bắt buộc nếu dùng IP trần) và khóa `mpk_*`.
3. Kiểm tra Endpoint + Pin rồi bấm **Enroll & Connect**. (Tài khoản macOS thuộc nhóm `admin` (`gid=80`) giao tiếp trực tiếp qua `/var/run/meshd/meshd-admin.sock`).

---

## 4. Lệnh CLI & Bảo trì hàng ngày

```sh
mesh status
mesh peers
mesh netcheck
mesh ping <PEER>
```

- **Launch at Login:** Bật trong Dashboard (`SMAppService.mainApp`).
- **Xoay khóa / Reset danh tính / Export Bugreport:** Có sẵn nút thao tác trên Dashboard (tệp `.tar` được lưu qua `NSSavePanel`, đã lọc bỏ secret).

---

## 5. Gỡ cài đặt sạch

- Gỡ app và daemon nhưng **giữ lại khóa thiết bị** (`/var/db/mesh/keys.json`):
  ```sh
  sudo /bin/sh "/Applications/Mesh VPN.app/Contents/Resources/install-macos.sh" --uninstall
  ```
- Gỡ hoàn toàn bao gồm khóa, `/var/db/mesh/` và nhật ký `/var/log/mesh/`:
  ```sh
  sudo /bin/sh "/Applications/Mesh VPN.app/Contents/Resources/install-macos.sh" --uninstall --purge
  ```
