# Hướng Dẫn Cài Đặt & Sử Dụng trên Windows 10/11 (`v0.3.0`)

Tài liệu này hướng dẫn cài đặt **Mesh VPN Desktop GUI (`MeshVPN.exe`)**, Windows Service `MeshVpnAgent` (`meshd.exe`), driver `wintun.dll` và CLI `mesh.exe` trên Windows 10/11 (`x86_64`).

---

## 1. Tải gói cài đặt ở đâu?

Tải tại trang phát hành **[Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**:

- Tệp tải về: [`mesh-windows-x86_64-msvc.zip`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-windows-x86_64-msvc.zip) *(8.28 MiB)*
- Tệp chứa đầy đủ: `MeshVPN.exe`, `mesh.exe`, `meshd.exe`, `mesh-server.exe`, `wintun.dll` (`0.14.1`), `wintun.dll.sha256`, `scripts\install-windows.ps1` và `SHA256SUMS`.

### Kiểm tra SHA-256 (khuyên làm trước khi chạy)

```powershell
Get-FileHash .\mesh-windows-x86_64-msvc.zip -Algorithm SHA256
```

Đối chiếu kết quả với tệp [`SHA256SUMS`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/SHA256SUMS).

---

## 2. Cài đặt

Giải nén toàn bộ `mesh-windows-x86_64-msvc.zip` vào một thư mục tạm (ví dụ `C:\Temp\mesh-vpn\`), sau đó chọn **1 trong 2 cách**:

### Cách A: Cài nhanh bằng PowerShell Administrator (Khuyên dùng)

Mở **PowerShell** bằng quyền **Run as Administrator**, `cd` vào thư mục vừa giải nén và chạy:

```powershell
# (Tùy chọn) Kiểm thử trước không thay đổi hệ thống:
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -DryRun

# Cài đặt đầy đủ vào C:\Program Files\Mesh\ và bật dịch vụ MeshVpnAgent:
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1
```

Script [`install-windows.ps1`](../../scripts/install-windows.ps1) sẽ tự động:
1. Kiểm tra SHA-256 của `wintun.dll` trước và sau khi chép vào `C:\Program Files\Mesh\`.
2. Tạo thư mục dữ liệu bảo mật `C:\ProgramData\Mesh\` (chỉ `SYSTEM` và `Administrators` có quyền đọc/ghi).
3. Đăng ký và khởi chạy Windows Service `MeshVpnAgent` (`LocalSystem`, tự phục hồi nếu lỗi).
4. Tạo shortcut **Mesh VPN** trên Start Menu và Desktop.

### Cách B: Mở trực tiếp từ GUI

1. Nhấp đúp `MeshVPN.exe` trong thư mục giải nén.
2. *(Nếu Windows Defender SmartScreen hiện cảnh báo do bản build `$0` chưa mua chứng chỉ thương mại)*: bấm **More info** -> **Run anyway**.
3. Trên cửa sổ Mesh VPN, bấm **Install & Start Service** và đồng ý hộp thoại **UAC** để cài đặt dịch vụ nền.

---

## 3. Kết nối vào mạng Mesh VPN

1. Mở **Mesh VPN** từ Start Menu / khay hệ thống (System Tray) hoặc chạy `mesh gui` trong Terminal.
2. Tại màn hình Onboarding:
   - **Cách nhanh:** Dán URI `mesh://join?v=1&...` nhận từ máy chủ vào ô Join URI. *(Ứng dụng tự xóa clipboard theo cơ chế an toàn sau 30 giây nếu dữ liệu clipboard không bị bạn thay đổi.)*
   - **Cách thủ công:** Nhập địa chỉ server `<IP_HOAC_DOMAIN>:443`, `sha256:<64_HEX>` SPKI Pin (bắt buộc khi dùng IP trần; chọn `System CA` nếu dùng domain HTTPS chuẩn) và khóa `mpk_*`.
3. Kiểm tra lại Endpoint + SPKI Pin và bấm **Enroll & Connect** -> chấp nhận UAC handoff 1 lần (`MGH1` ephemeral named pipe).

---

## 4. Vận hành hàng ngày trên Windows

- **Khay hệ thống & Tự khởi động:** Nhấn chuột phải vào biểu tượng khay hệ thống để bật/tắt **Connect / Disconnect**, bật **Launch at Login** hoặc mở lại Dashboard.
- **Lệnh CLI dùng chung:** Mở Command Prompt / PowerShell thường (không cần Admin để xem trạng thái):
  ```powershell
  "C:\Program Files\Mesh\mesh.exe" status
  "C:\Program Files\Mesh\mesh.exe" peers
  "C:\Program Files\Mesh\mesh.exe" netcheck
  "C:\Program Files\Mesh\mesh.exe" ping <PEER>
  ```
- **Xoay khóa / Đặt lại danh tính:** Thao tác trực tiếp trong Dashboard (**Rotate Key** / **Reset Device Identity**).
- **Xuất Bugreport:** Mở tab **Diagnostics** -> **Export Bugreport...** -> chọn nơi lưu tệp `.tar` (không chứa khóa bí mật).

---

## 5. Gỡ cài đặt sạch

Mở **PowerShell (Run as Administrator)** tại thư mục đã giải nén chứa `scripts\install-windows.ps1`:

- Gỡ phần mềm, dịch vụ `MeshVpnAgent`, rule firewall và tunnel nhưng **giữ lại khóa thiết bị** (`C:\ProgramData\Mesh\keys.json`):
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -Uninstall
  ```
- Gỡ **sạch hoàn toàn** bao gồm `keys.json` và nhật ký trong `C:\ProgramData\Mesh\`:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -Uninstall -PurgeData
  ```
