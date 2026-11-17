# Giao Thức Nghiệm Thu Phần Cứng Vật Lý (Physical Hardware UAT Protocol) — Desktop GUI (`v0.3.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Phiên bản mục tiêu** | `v0.3.0` (Sprint 5 — Native Desktop GUI & Tray Companion cho Windows 10/11 & macOS 13+) |
| **Mã tài liệu** | `OPS-UAT-DGUI-001` |
| **Phiên bản tài liệu** | `1.0` |
| **Ngày cập nhật** | `2026-11-17` |
| **Tác giả** | QA & Operations Engineering (`@qa-d-c2` / `WP-D-C2` — `US-116`) |
| **Đối tượng áp dụng** | Máy thật Windows 10 (`22H2`) / Windows 11 (`23H2+`) `x86_64` và máy thật Mac Apple Silicon (`M1/M2/M3/M4`) / Intel `x86_64` chạy macOS 13 Ventura trở lên |
| **Trạng thái** | **MANDATORY PHYSICAL HARDWARE RELEASE GATE (`hardware_signoff_required = true`)** |

---

## 1. Mục đích & Nguyên tắc Bắt buộc (Purpose & Mandatory Rules)

Giao thức này quy định quy trình nghiệm thu từng bước trên **phần cứng máy tính vật lý thực tế** trước khi phát hành chính thức `v0.3.0`. Dù hệ thống kiểm thử tự động (`scripts/run-desktop-qa.{ps1,sh}`, `qa_desktop_e2e_ipc.rs`, `qa_desktop_security_audit.rs`) đã kiểm chứng `100%` giao thức IPC, khung nhị phân `MGH1`, máy trạng thái `UiAppState` và các bất biến đóng gói, các hành vi sau đây **chỉ có thể được xác nhận trên hệ điều hành và phần cứng thật**:
1. Tương tác với Windows Explorer System Tray (`Shell_NotifyIconW`, sự kiện `TaskbarCreated` khi khởi động lại `explorer.exe`) và macOS Menu Bar (`MenuBarExtra`, chuyển đổi `NSApp.setActivationPolicy(.regular)` / `.accessory`).
2. Nhấp đúp biểu tượng `MeshVPN.exe` / `Mesh VPN.app` từ Desktop hoặc Finder không mở cửa sổ `conhost.exe` đen và chỉ kích hoạt đúng 1 cửa sổ Dashboard duy nhất.
3. Hộp thoại nâng quyền thật của hệ điều hành: Windows UAC (`ShellExecuteExW("runas")`) trên tài khoản Standard User và macOS `osascript` (`do shell script ... with administrator privileges`) hoặc luồng `gid=80` (`admin`) không hỏi mật khẩu khi kết nối qua `/var/run/meshd/meshd-admin.sock`.
4. Ghi đè nguyên tử (`Replace`) tệp `.tar` đang tồn tại thông qua hộp thoại `GetSaveFileNameW` (`OFN_OVERWRITEPROMPT`) trên Windows và `NSSavePanel` trên macOS.
5. Kiểm tra Application Firewall thực tế của macOS (`/usr/libexec/ApplicationFirewall/socketfilterfw`) và `wintun.dll` + dịch vụ `MeshVpnAgent` trên Windows.
6. Đo đạc thực tế ngân sách bộ nhớ RAM (`Working Set` / `phys_footprint`), mức sử dụng CPU khi thu gọn (`0% CPU`), và thời gian thoát sạch (`<= 2s`).

---

## 2. Chuẩn bị Môi trường & Thiết bị Vật lý (Lab Prerequisites)

### 2.1. Cấu hình Trạm Kiểm thử
1. **Control & Relay Server (`mesh-server v0.3.0`)**:
   - Đang hoạt động trên VPS Linux với chứng chỉ TLS hợp lệ hoặc SPKI Pin đã biết (`sha256:<64-hex>`).
   - Có sẵn ít nhất `1` node peer khác đang trực tuyến (`100.64.0.2`) để kiểm thử `Ping`, `Search Peers` và `Exit Node`.
   - Sinh sẵn `2` khóa `Pre-Auth Key` (`mpk_...`) hợp lệ để kiểm thử đăng ký qua `mesh://join` URI và biểu mẫu thủ công.
2. **Máy trạm Windows Vật lý (`DUT-WIN`)**:
   - Hệ điều hành: Windows 10 `22H2` hoặc Windows 11 `23H2/24H2` (`x86_64`), màn hình hỗ trợ chỉnh tỷ lệ DPI `100%`, `125%`, `150%`, `200%`.
   - Chuẩn bị **2 tài khoản cục bộ**: `1` tài khoản thuộc nhóm `Administrators` (bật UAC mặc định) và `1` tài khoản `Standard User` (không thuộc `Administrators`).
   - Artifact cài đặt: `MeshVPN-v0.3.0-x86_64-pc-windows-msvc.zip` giải nén gồm `MeshVPN.exe`, `mesh.exe`, `meshd.exe`, `mesh-server.exe`, `wintun.dll`, `SHA256SUMS`, `scripts/install-windows.ps1`.
3. **Máy trạm macOS Vật lý (`DUT-MAC`)**:
   - Hệ điều hành: macOS 13 Ventura, macOS 14 Sonoma hoặc macOS 15 Sequoia (ưu tiên kiểm trên Apple Silicon `arm64`).
   - Chuẩn bị **2 tài khoản cục bộ**: `1` tài khoản `Administrator` (`gid=80` — nhóm `admin`) và `1` tài khoản `Standard User` (không thuộc `gid=80`).
   - Artifact cài đặt: `MeshVPN-macos-universal.dmg` (hoặc `Mesh VPN.app` đã đóng gói qua `scripts/package-macos-app.sh`).

---

## 3. Giao thức Nghiệm thu trên Windows 10/11 (`WIN-UAT-01` .. `WIN-UAT-16`)

### `WIN-UAT-01` — Cài đặt, Khởi chạy từ Explorer & Không nháy Cửa sổ Console (`US-100`, `US-115`)
1. Mở PowerShell (Run as Administrator) tại thư mục giải nén và chạy:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1
   ```
2. Xác nhận kịch bản kiểm tra `SHA256SUMS` cho cả 5 tệp (`MeshVPN.exe`, `mesh.exe`, `meshd.exe`, `mesh-server.exe`, `wintun.dll`), cài dịch vụ `MeshVpnAgent`, và tạo shortcut `Mesh VPN.lnk` trên Desktop & Start Menu.
3. Nhấp đúp trực tiếp vào biểu tượng **`Mesh VPN`** trên Desktop từ Windows Explorer.
4. **Kỳ vọng**:
   - **Tuyệt đối không** xuất hiện cửa sổ `cmd.exe` hoặc `conhost.exe` đen dù chỉ trong một khung hình (`PE Subsystem == 2`).
   - Biểu tượng `Mesh VPN` xuất hiện ngay trên khay hệ thống (System Tray) và cửa sổ Dashboard mở lên chính giữa màn hình.

### `WIN-UAT-02` — Khóa Đơn Phiên bản (`Single-Instance`), Thu gọn xuống Tray & Phục hồi khi `explorer.exe` Khởi động lại (`US-100`)
1. Khi cửa sổ Dashboard đang mở, nhấn nút `X` ở góc trên bên phải cửa sổ.
2. **Kỳ vọng**: Cửa sổ Dashboard ẩn xuống System Tray (`SW_HIDE`), tiến trình `MeshVPN.exe` vẫn chạy trong Task Manager.
3. Nhấp đúp lại vào biểu tượng `Mesh VPN` trên Desktop (hoặc chạy `MeshVPN.exe` lần thứ hai).
4. **Kỳ vọng**: Không có tiến trình `MeshVPN.exe` thứ hai nào được tạo; cửa sổ Dashboard của tiến trình đầu tiên tự động hiện lên và nhận tiêu điểm (`SetForegroundWindow`).
5. Mở Task Manager -> tìm `Windows Explorer` (`explorer.exe`) -> nhấn **Restart**.
6. **Kỳ vọng**: Ngay khi thanh Taskbar xuất hiện lại, biểu tượng `Mesh VPN` trên System Tray tự động đăng ký lại nhờ thông điệp `TaskbarCreated` mà không cần khởi động lại ứng dụng.

### `WIN-UAT-03` — Trạng thái Chưa đăng ký (`Unconfigured`) & Phát hiện Dịch vụ (`US-102`)
1. Trên máy chưa từng chạy `mesh up`, mở Dashboard `Mesh VPN`.
2. **Kỳ vọng**: Trạng thái hiển thị rõ ràng là `Unconfigured` (`Chưa thiết lập`), hiển thị thẻ hướng dẫn **Onboarding** với 2 lựa chọn: nhập `mesh://join` URI hoặc điền biểu mẫu thủ công.

### `WIN-UAT-04` — Luồng Nâng quyền UAC `runas` & Giao thức Handoff `MGH1` (`US-103`, `IG-DGUI-WA-02`)
1. Đăng nhập vào tài khoản **Standard User** trên Windows (hoặc tài khoản bật UAC chuẩn).
2. Thực hiện thao tác yêu cầu quyền quản trị từ GUI (ví dụ: nhấn **Connect / Enroll** lần đầu với `Pre-Auth Key`).
3. **Kỳ vọng**:
   - Hộp thoại **Windows User Account Control (UAC)** chuẩn hiển thị yêu cầu xác nhận nâng quyền cho `MeshVPN.exe --elevated-worker`.
   - Kiểm tra trong Task Manager (cột `Command line`): dòng lệnh của tiến trình worker chỉ chứa `--elevated-worker --pipe \\.\pipe\mesh-gui-handoff-<32-hex>`, **tuyệt đối không** chứa `mpk_` hay URI trong `argv`.
   - Nếu nhấn **No / Cancel** ở hộp thoại UAC: GUI không bị treo hay văng, hiển thị biểu ngữ thông báo rõ ràng rằng người dùng đã từ chối nâng quyền.

### `WIN-UAT-05` — Nhập `mesh://join` từ Clipboard & Tự động Xóa Clipboard Nguyên tử sau `30s` (`US-104`, `IG-DGUI-WA-01`)
1. Sao chép một chuỗi `mesh://join?server=https://198.51.100.10:443&key=mpk_...&pin=sha256:...&name=win-laptop` vào Clipboard của Windows.
2. Trên màn hình Onboarding của `Mesh VPN`, nhấn nút **Import from Clipboard**.
3. **Kỳ vọng**:
   - Các trường `Server Endpoint`, `SPKI Pin`, `Node Name` được điền tự động; khóa `mpk_` được che kín (`••••••••`).
   - **Trường hợp A (Không chạm vào Clipboard trong 30s)**: Đợi đủ `31 giây`, mở Notepad và nhấn `Ctrl+V` -> Clipboard đã được xóa trống hoàn toàn.
   - **Trường hợp B (Người dùng copy văn bản khác trước 30s)**: Thực hiện lại **Import from Clipboard**, sau `5 giây` copy chữ `"hello-user"` trong Notepad. Đợi qua mốc `31 giây` và nhấn `Ctrl+V` -> chữ `"hello-user"` vẫn còn nguyên nhờ kiểm tra nguyên tử `GetClipboardSequenceNumber()` + hàm băm SHA-256 trong `ClipboardGuard`.

### `WIN-UAT-06` — Biểu mẫu Thủ công, Chống TOFU cho IPv4/IPv6 & Kết nối 1-Chạm (`US-102`, `US-105`, `IG-DGUI-WA-04`, `IG-DGUI-WA-06`)
1. Trong biểu mẫu thủ công, nhập `Server Endpoint` là địa chỉ IPv4 (`https://198.51.100.10:443`) hoặc IPv6 (`https://[2001:db8::1]:443`).
2. **Kỳ vọng**: Tùy chọn `System CA` bị khóa cứng, giao diện tự động chuyển sang `Pinned SPKI` và bắt buộc nhập `sha256:<64-hex>` (`Zero-TOFU`).
3. Nhập khóa `mpk_` không hợp lệ (ngắn hơn `32 bytes` sau giải mã base64url) -> nút **Connect** báo lỗi định dạng ngay tại chỗ, không gọi UAC.
4. Nhập đầy đủ thông tin hợp lệ và nhấn **Connect** -> chấp nhận UAC -> trạng thái chuyển sang `Connected`, hiển thị địa chỉ Overlay IP (`100.64.x.y`).
5. Nhấn **Disconnect** -> trạng thái chuyển sang `Disconnected`. Nhấn lại **Connect** -> hệ thống kết nối lại ngay lập tức (**1-Click Reconnect**) bằng `server_endpoint` và `spki_pin` đã lưu trong phiên mà không bắt người dùng nhập lại biểu mẫu.

### `WIN-UAT-07` — Danh sách Peer, Tìm kiếm Thời gian thực, Sao chép IP & Quick Ping (`US-106`, `BLK-DGUI-G2-04`)
1. Khi đang `Connected`, mở thẻ **Peers**.
2. Nhập tên node hoặc một phần IP (`100.64.`) vào ô tìm kiếm -> danh sách lọc tức thời.
3. Nhấn nút **Copy IP** cạnh một peer -> dán vào Notepad để xác nhận đúng địa chỉ Overlay IP.
4. Nhấn nút **Ping** cạnh peer trực tuyến -> hiển thị kết quả RTT (`ms`) và đường truyền (`DIRECT` hoặc `RELAY`).

### `WIN-UAT-08` — Chọn Exit Node & Trạng thái Chống Vòng lặp Định tuyến (`US-107`, `REL-09`)
1. Trong mục **Exit Node**, chọn một peer hợp lệ làm Exit Node -> xác nhận trạng thái chuyển sang `Full-Tunnel Active` kèm huy hiệu `Loop Guard Active (IP_UNICAST_IF)`.
2. Chọn lại `None (Split-Tunnel)` -> xác nhận lưu lượng Internet quay về đường truyền mặc định của máy.

### `WIN-UAT-09` — Cài đặt Tự khởi động (`HKCU\...\Run`), MagicDNS & Đổi ngôn ngữ Việt/Anh (`US-108`, `US-113`)
1. Trong mục **Settings**, bật **Launch at Login** -> kiểm tra Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MeshVPN` đã được tạo. Tắt **Launch at Login** -> giá trị Registry bị xóa sạch.
2. Chuyển đổi ngôn ngữ giữa **Tiếng Việt (`VI`)** và **English (`EN`)** -> toàn bộ nhãn giao diện và menu chuột phải ở System Tray cập nhật tức thời.

### `WIN-UAT-10` — Xoay khóa (`Rotate Key`), Đặt lại Danh tính (`Reset Identity`) & Tạm dừng Polling (`US-109`, `BLK-DGUI-G2-05`, `IG-DGUI-WA-03`)
1. Nhấn **Rotate Node Key** -> hộp thoại xác nhận hiện ra (trong lúc hộp thoại mở, giao diện không bị giật hay đóng hộp thoại do vòng lặp poll 2s nhờ `PollingSuspensionGuard`). Xác nhận -> khóa mới được xoay thành công.
2. Nhấn **Reset Identity** và xác nhận -> trạng thái quay về `Unconfigured` ngay lập tức, trong khi dịch vụ Windows `MeshVpnAgent` (`meshd.exe`) **vẫn đang ở trạng thái `Running`** trong `services.msc`.

### `WIN-UAT-11` — Netcheck, Nhật ký Đã làm sạch (`LogSanitizer`) & Xuất Bugreport Ghi đè (`Replace`) (`US-110`, `BLK-DGUI-G2-06`)
1. Mở thẻ **Diagnostics**, nhấn **Run Netcheck** -> hiển thị kết quả UDP/STUN/HTTPS Relay.
2. Kiểm tra khung nhật ký trực tiếp: mọi chuỗi `mpk_` hoặc `mesh://join` đều hiển thị dưới dạng `[REDACTED]`.
3. Nhấn **Export Bugreport** -> hộp thoại `Save As` (`GetSaveFileNameW`) mở ra -> lưu thành `C:\Users\<user>\Desktop\mesh-report.tar`.
4. Nhấn **Export Bugreport** lần thứ hai và chọn lại chính tệp `C:\Users\<user>\Desktop\mesh-report.tar` -> hộp thoại hỏi xác nhận ghi đè (`Replace`) -> chọn **Yes**.
5. **Kỳ vọng**: Tệp `mesh-report.tar` được cập nhật nguyên tử qua `UnprivilegedSinkWriter` (quyền sở hữu tệp thuộc về tài khoản người dùng hiện tại, không phải `SYSTEM`), và không còn tệp `.part` nào sót lại trên Desktop.

### `WIN-UAT-12` — Phát hiện Daemon Cũ `LegacyPre030` & Thông báo Lỗi Chuẩn hóa (`US-111`, `BLK-DGUI-G2-03`, `SEC-05`)
1. Nếu kết nối tới daemon `meshd` bản cũ (`v0.1.0`/`v0.2.0` không có `/v1/agent/version`): giao diện hiển thị rõ trạng thái `LegacyPre030` hướng dẫn nâng cấp `meshd` lên `v0.3.0`.
2. Khi máy chủ từ chối xác thực (`ErrorKind::Unauthenticated`), thông báo lỗi chỉ hiển thị chuỗi chuẩn hóa `"authentication failed"`.

### `WIN-UAT-13` — Tích hợp Lệnh `mesh gui` trên Terminal (`US-112`)
1. Mở PowerShell hoặc Command Prompt thông thường và chạy:
   ```powershell
   mesh gui status --json
   mesh gui open
   ```
2. **Kỳ vọng**: `mesh gui status --json` trả về JSON hợp lệ (`gui_installed: true`); `mesh gui open` kích hoạt cửa sổ `MeshVPN.exe` và trả quyền điều khiển về dấu nhắc lệnh trong **`<= 1 giây`**.

### `WIN-UAT-14` — Điều hướng Bàn phím, High-DPI (`125%`/`150%`/`200%`) & Dark/Light Mode (`US-113`)
1. Nhấn phím `Tab` / `Shift+Tab` trên cửa sổ Dashboard -> khung tiêu điểm (`WS_TABSTOP`) di chuyển tuần tự qua các nút điều khiển.
2. Thay đổi Display Scale trong Windows Settings từ `100%` sang `150%` và `200%` -> phông chữ và bố cục cửa sổ tự co giãn sắc nét (`WM_DPICHANGED`), không bị vỡ chữ hay mờ nhòe.
3. Chuyển đổi Windows Theme giữa Dark và Light -> thanh tiêu đề (`DwmSetWindowAttribute`) và bảng màu giao diện thích ứng đồng bộ.

### `WIN-UAT-15` — Gỡ cài đặt Sạch (`-Uninstall`) & Xóa Dữ liệu (`-PurgeData`) (`US-115`, `IG-DGUI-WA-05`)
1. Trong khi `MeshVPN.exe` đang chạy ở System Tray, mở PowerShell (Administrator) và chạy:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -Uninstall
   ```
2. **Kỳ vọng**:
   - Kịch bản phát tín hiệu `Local\MeshVpnGuiShutdownEvent` làm `MeshVPN.exe` tự gỡ biểu tượng Tray và thoát sạch trong `<= 2 giây`.
   - `mesh.exe cleanup` thu hồi sổ cái `ResourceLedger`, dịch vụ `MeshVpnAgent` bị dừng và xóa, khóa `HKCU\...\Run\MeshVPN` và các shortcut `.lnk` bị xóa sạch.
   - Tệp định danh `C:\ProgramData\Mesh\keys.json` **vẫn được bảo toàn** để phục vụ cài đặt nâng cấp.
3. Chạy tiếp với cờ `-PurgeData`:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -Uninstall -PurgeData
   ```
   -> Thư mục `C:\ProgramData\Mesh` (bao gồm `keys.json`) bị xóa hoàn toàn.

### `WIN-UAT-16` — Đo đạc Ngân sách Tài nguyên Thực tế trên Windows (`D-GNFR-01`, `D-GNFR-04`)
1. Mở Task Manager (thẻ Details, bật cột `Memory (active private working set)` và `CPU`).
2. **Kỳ vọng bắt buộc**:
   - Khi thu gọn xuống System Tray: RAM `<= 15 MiB` (trần cứng), CPU `== 0%` (không có vòng lặp poll khi cửa sổ ẩn).
   - Khi mở cửa sổ Dashboard đang hoạt động: RAM `<= 30 MiB` (trần cứng).
   - Khi chọn **Quit Mesh VPN** từ menu chuột phải ở Tray: biểu tượng biến mất ngay và tiến trình kết thúc trong **`<= 2 giây`**.

---

## 4. Giao thức Nghiệm thu trên macOS 13+ (`MAC-UAT-01` .. `MAC-UAT-16`)

### `MAC-UAT-01` — Mở `.dmg`, Khởi chạy `Mesh VPN.app` & Chế độ Menu Bar-Only (`LSUIElement`) (`US-101`, `US-114`)
1. Mở `MeshVPN-macos-universal.dmg`, kéo `Mesh VPN.app` vào `/Applications`.
2. Trên bản build `$0 Ad-Hoc Mode` (không có chứng chỉ Apple Developer ID trả phí): thực hiện đúng quy trình chuẩn của macOS (chuột phải vào `/Applications/Mesh VPN.app` -> chọn **Open** -> hoặc vào **System Settings -> Privacy & Security -> Open Anyway**; **tuyệt đối không** dùng lệnh `spctl` `--master-disable`).
3. **Kỳ vọng**:
   - Biểu tượng `Mesh VPN` xuất hiện ngay trên thanh **macOS Menu Bar** (góc trên bên phải màn hình).
   - Khi chưa mở cửa sổ Dashboard: ứng dụng chạy ở chế độ `.accessory` (`LSUIElement = true`), không chiếm chỗ trên thanh Dock.
   - Ngay từ lúc khởi động (`MeshApp.init()`), trạng thái daemon trong popover Menu Bar đã được cập nhật nhờ `initialStore.startMonitoring()` (`BLK-DGUI-G2-01`).

### `MAC-UAT-02` — Đơn Cửa sổ Dashboard (`Window(id: "dashboard")`) & Chuyển đổi Chính sách Dock `.regular` / `.accessory` (`US-101`)
1. Nhấp vào biểu tượng `Mesh VPN` trên Menu Bar -> nhấn **Open Dashboard**.
2. **Kỳ vọng**:
   - Cửa sổ Dashboard xuất hiện và biểu tượng ứng dụng hiện lên thanh Dock (`NSApp.setActivationPolicy(.regular)`).
   - Nhấn tổ hợp phím `Cmd+N` hoặc nhấp lại **Open Dashboard** nhiều lần -> **chỉ có duy nhất 1 cửa sổ Dashboard** tồn tại (`CommandGroup(replacing: .newItem) {}`).
3. Đóng cửa sổ Dashboard (`Cmd+W` hoặc nút đỏ góc trái) -> cửa sổ đóng lại, ứng dụng tự động rút khỏi thanh Dock về lại `.accessory` trên Menu Bar, tiến trình vẫn chạy ngầm.

### `MAC-UAT-03` — Cài đặt Dịch vụ Nền từ `.app` Bundle & Phân quyền `gid=80` (`US-103`, `BLK-DGUI-G2-07`, `ADR-026`)
1. Nếu `meshd` chưa được cài đặt (`ServiceMissing`), nhấn nút **Install Background Service** ngay trên Dashboard `Mesh VPN.app`.
2. **Kỳ vọng**:
   - Hộp thoại xác thực quản trị viên gốc của macOS (`osascript` — `do shell script ... with administrator privileges`) xuất hiện.
   - `PrivilegeHelper` kiểm tra chữ ký `codesign --verify --strict` và `SHA256SUMS` trước khi chạy `install-macos.sh --from-app-bundle`, sao chép `meshd` và `mesh` vào `/usr/local/libexec/mesh/` (`0755 root:wheel`), tạo symlink tại `/usr/local/bin/`, và nạp `LaunchDaemon` `internal.mesh.meshd`.
3. Kiểm tra phân quyền nhóm `admin` (`gid=80`):
   - Trên tài khoản thuộc nhóm **Administrator (`gid=80`)**: các thao tác `Connect`, `Disconnect`, `Set Exit Node`, `Ping`, `Netcheck`, `Rotate Key` đi thẳng qua `/var/run/meshd/meshd-admin.sock` (`0660 root:admin`) với **`0` hộp thoại hỏi mật khẩu**.
   - Trên tài khoản **Standard User (không thuộc `gid=80`)**: khi thực hiện thao tác quản trị, hệ thống hiển thị hộp thoại `osascript` yêu cầu xác thực quản trị viên một lần và không làm lộ khóa `mpk_` qua `ps aux`.

### `MAC-UAT-04` .. `MAC-UAT-10` — Kiểm thử Tương đương Chức năng trên macOS (`US-102` .. `US-109`)
Thực hiện lần lượt các kịch bản tương đương với Windows trên giao diện SwiftUI của `Mesh VPN.app`:
- **`MAC-UAT-04` (`US-104`)**: Nhập `mesh://join` từ `NSPasteboard`, xác nhận tự động xóa sau `30s` nếu `changeCount` và hàm băm SHA-256 không đổi, và bảo toàn nếu người dùng đã copy nội dung khác.
- **`MAC-UAT-05` (`US-105`, `IG-DGUI-WA-06`)**: Nhập IPv4 (`198.51.100.10`) và IPv6 (`[2001:db8::1]:443`) trên biểu mẫu thủ công -> xác nhận `System CA` bị khóa cứng (`Pinned SPKI` bắt buộc) và kiểm tra `mpk_` `>= 32 B` đồng nhất với Windows.
- **`MAC-UAT-06` (`US-102`, `IG-DGUI-WA-04`)**: Kết nối -> Ngắt kết nối -> nhấn **Connect** lại -> xác nhận **1-Click Reconnect** hoạt động không cần nhập lại thông tin.
- **`MAC-UAT-07` (`US-106`, `BLK-DGUI-G2-04`)**: Tìm kiếm danh sách Peer, sao chép IP vào `NSPasteboard`, và chạy **Ping** hiển thị RTT.
- **`MAC-UAT-08` (`US-107`)**: Bật/tắt **Exit Node** và xác nhận huy hiệu `Loop Guard Active (IP_BOUND_IF)`.
- **`MAC-UAT-09` (`US-108`)**: Bật/tắt **Launch at Login** (`SMAppService.mainApp` / `LaunchAgents`), chuyển đổi ngôn ngữ `VI` / `EN`.
- **`MAC-UAT-10` (`US-109`, `BLK-DGUI-G2-05`)**: Chạy **Rotate Key** và **Reset Identity** -> xác nhận `meshd` vẫn sống ở trạng thái `Unconfigured`.

### `MAC-UAT-11` — Xuất Bugreport qua `NSSavePanel` (Ghi đè `Replace`) & Kiểm tra `socketfilterfw` (`US-110`, `BLK-DGUI-G2-06`)
1. Trong thẻ **Diagnostics**, nhấn **Export Bugreport** -> chọn lưu tệp `~/Desktop/mesh-report.tar` qua `NSSavePanel`.
2. Nhấn **Export Bugreport** lần thứ hai và chọn lại chính tệp `~/Desktop/mesh-report.tar` -> chọn **Replace** trên hộp thoại của macOS.
3. **Kỳ vọng**: Luồng ghi thông qua tệp tạm `.part` và `FileManager.default.replaceItemAt` thành công nguyên tử dưới quyền user hiện tại (`0` tệp `.part` tồn đọng).
4. Kiểm tra trạng thái Application Firewall của macOS trên Terminal:
   ```sh
   /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
   ```
   Xác nhận `meshd` hoạt động ổn định cùng cấu hình tường lửa của máy mà không cần tắt bảo vệ hệ thống.

### `MAC-UAT-12` .. `MAC-UAT-15` — Thông báo, CLI `mesh gui`, Trợ năng Retina & Gỡ cài đặt macOS (`US-111` .. `US-114`)
- **`MAC-UAT-12` (`US-111`)**: Kiểm tra biểu ngữ `LegacyPre030` và chuỗi lỗi xác thực `"authentication failed"`.
- **`MAC-UAT-13` (`US-112`)**: Chạy `mesh gui status --json` và `mesh gui open` trên Terminal macOS -> xác nhận kiểm tra `codesign -v` thành công và mở ứng dụng trong `<= 1s`.
- **`MAC-UAT-14` (`US-113`)**: Kiểm tra hiển thị Retina (`2x`), chuyển đổi Dark/Light Mode của macOS và điều hướng bàn phím/VoiceOver.
- **`MAC-UAT-15` (`US-114`)**: Chạy gỡ cài đặt sạch:
  ```sh
  sudo sh /Applications/Mesh\ VPN.app/Contents/Resources/install-macos.sh --uninstall
  ```
  Xác nhận `Mesh VPN.app` được đóng sạch, `internal.mesh.meshd` được gỡ, `/etc/hosts` và `pf` được hoàn nguyên theo `ResourceLedger`, và `/var/db/mesh/keys.json` được giữ lại trừ khi truyền thêm `--purge-data`.

### `MAC-UAT-16` — Đo đạc Ngân sách Tài nguyên Thực tế trên macOS (`D-GNFR-01`, `D-GNFR-04`)
1. Mở **Activity Monitor** (hoặc chạy `footprint -p $(pgrep "Mesh VPN")` trên Terminal).
2. **Kỳ vọng bắt buộc**:
   - Khi đóng cửa sổ Dashboard (chỉ chạy ở Menu Bar): `Memory (phys_footprint)` `<= 35 MiB`, `% CPU == 0.0%`.
   - Khi mở cửa sổ Dashboard đang hoạt động: `Memory (phys_footprint)` `<= 60 MiB`.
   - Khi nhấn `Cmd+Q` hoặc chọn **Quit Mesh VPN**: tiến trình thoát sạch trong **`<= 2 giây`**.

---

## 5. Sổ Cái Ký Duyệt Nghiệm Thu Phần Cứng (Operator Physical Sign-Off Ledger)

> [!WARNING]
> Các dòng mang trạng thái `PENDING_PHYSICAL_UAT` dưới đây **không được phép** chuyển sang `SIGNED_OFF` nếu chưa thực thi trực tiếp trên máy thật tương ứng.

| Mã Kịch bản | Nền tảng | Thiết bị / OS Thực tế | Kết quả Đo đạc (RAM / CPU / Thời gian) | Trạng thái | Người ký & Ngày (UTC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `WIN-UAT-01..03` | Windows 10/11 `x86_64` | `TBD (Physical Windows Host)` | `PE Subsystem = 2` (Verified in CI); Explorer UAT: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-04..06` | Windows 10/11 `x86_64` | `TBD (Physical Windows Host)` | UAC `runas` + `30s` Clipboard + Zero-TOFU: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-07..11` | Windows 10/11 `x86_64` | `TBD (Physical Windows Host)` | Peers + Exit Node + Reset + Replace `.tar`: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-12..15` | Windows 10/11 `x86_64` | `TBD (Physical Windows Host)` | `mesh gui` `<= 1s` + DPI + Clean Uninstall: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-16` | Windows 10/11 `x86_64` | `TBD (Physical Windows Host)` | Tray RAM (`<= 15 MiB`): `TBD`; Open RAM (`<= 30 MiB`): `TBD`; Quit (`<= 2s`): `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-01..03` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac Host)` | `LSUIElement` + Single Window + `gid=80` / `osascript`: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-04..10` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac Host)` | Clipboard + Zero-TOFU + Peers + Exit Node + Reset: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-11..15` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac Host)` | `NSSavePanel` Replace + `socketfilterfw` + `mesh gui` + Uninstall: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-16` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac Host)` | MenuBar RAM (`<= 35 MiB`): `TBD`; Open RAM (`<= 60 MiB`): `TBD`; Quit (`<= 2s`): `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
