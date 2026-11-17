# Giao Thức Nghiệm Thu Phần Cứng Vật Lý (Physical Hardware UAT Protocol) — Desktop GUI (`v0.3.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Phiên bản mục tiêu** | `v0.3.0` (`EP-17..EP-20`, `US-100..US-117 = 78 SP`) |
| **Mã tài liệu** | `OPS-UAT-DGUI-001` |
| **Phiên bản tài liệu** | `1.1` |
| **Ngày cập nhật** | `2026-11-17` |
| **Tác giả** | QA & Operations Engineering (`WP-D-C2` — `US-116`) |
| **Đối tượng áp dụng** | Máy thật Windows 10 (`22H2`) / Windows 11 (`23H2+`) `x86_64` và máy thật Mac Apple Silicon (`arm64`) / Intel (`x86_64`) chạy macOS 13 Ventura trở lên |
| **Trạng thái** | **MANDATORY PHYSICAL HARDWARE RELEASE GATE (`hardware_signoff_required = true`)** |

---

## 1. Mục đích & Nguyên tắc Phân tách Bằng chứng

Giao thức này quy định các kịch bản kiểm thử **bắt buộc thao tác trên máy tính vật lý thực tế** trước khi gắn thẻ phát hành `v0.3.0` (`hardware_signoff_required`). Các lớp kiểm chứng tự động khác được phân tách rõ ràng:
- **`VERIFIED_ON_WINDOWS_HOST`**: Đã kiểm chứng tự động qua `scripts/run-desktop-qa.ps1` và `scripts/check.ps1 -Cross` (protocol `MGH1`, 8-state machine, Zero-TOFU, `UnprivilegedSinkWriter`, `ResourceLedger` dry-run).
- **`PENDING_CI_RUNNER`**: Chờ thực thi trên GitHub Actions `macos-15` (`desktop-macos`, `package-macos-desktop`) và `windows-latest` (`check-windows`, `verify-and-build`).
- **`hardware_signoff_required`**: Các hành vi gắn với desktop session thật (System Tray Explorer, Menu Bar `LSUIElement`, hộp thoại UAC / `osascript`, tỷ lệ DPI/Retina, `socketfilterfw`, `wintun.dll`, đo RAM/CPU và thời gian thoát `<= 2 s`).

> [!IMPORTANT]
> **Phạm vi Đúng của `v0.3.0`**: Giao thức UAT chỉ kiểm thử các tính năng nằm trong `US-100..US-117` (`78 SP`). **Không** kiểm thử Exit Node GUI hay chuyển đổi ngôn ngữ VI/EN (các tính năng ngoài phạm vi `v0.3.0`).

---

## 2. Chuẩn bị Trạm Kiểm thử Vật lý

1. **Control & Relay Server (`mesh-server`)**:
   - Đang chạy trên VPS Linux với chứng chỉ TLS (hoặc SPKI Pin `sha256:<64-hex>`).
   - Có sẵn tối thiểu `1` node peer trực tuyến (ví dụ `100.64.0.2`) để kiểm thử danh sách Peers và `Ping`.
   - Sinh sẵn `2` Pre-Auth Key (`mpk_...`) hợp lệ để kiểm thử đăng ký `mesh://join` và xoay khóa (`Rotate Key`).
2. **Máy trạm Windows Vật lý (`DUT-WIN`)**:
   - Windows 10 `22H2` hoặc Windows 11 `23H2+` (`x86_64`), hỗ trợ thay đổi Scale DPI (`100%`, `125%`, `150%`, `200%`), **không** cài sẵn WebView2 Runtime bổ sung.
   - `2` tài khoản cục bộ: `1` tài khoản thuộc nhóm `Administrators` (bật UAC) và `1` tài khoản `Standard User`.
   - Gói phát hành `mesh-windows-x86_64-msvc.zip` (`MeshVPN.exe`, `mesh.exe`, `meshd.exe`, `mesh-server.exe`, `wintun.dll`, `wintun.dll.sha256`, `WINTUN-LICENSE.txt`, `README-WINTUN.md`, `SHA256SUMS`, `scripts/install-windows.ps1`).
3. **Máy trạm macOS Vật lý (`DUT-MAC`)**:
   - macOS 13+ (`arm64` hoặc `x86_64`).
   - `2` tài khoản cục bộ: `1` tài khoản `Administrator` (`gid = 80`) và `1` tài khoản `Standard User` (`gid != 80`).
   - Gói phát hành `MeshVPN-macos-universal.dmg` (chứa `Mesh VPN.app`, bundle ID `dev.meshvpn.macos`).

---

## 3. Kịch bản Nghiệm thu Windows 10/11 (`WIN-UAT-01` .. `WIN-UAT-16`)

### `WIN-UAT-01` — Cài đặt, Khởi chạy từ Explorer & Không nháy Console (`US-103`, `US-114`, `US-115`)
1. Giải nén `mesh-windows-x86_64-msvc.zip`, mở PowerShell (Administrator) và chạy:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1
   ```
2. Xác nhận `MeshVPN.exe`, `meshd.exe`, `mesh.exe`, `mesh-server.exe`, `wintun.dll` và `wintun.dll.sha256` được cài vào `C:\Program Files\Mesh\`, dịch vụ `MeshVpnAgent` chạy, và shortcut `Mesh VPN.lnk` có trên Desktop / Start Menu.
3. Nhấp đúp `Mesh VPN.lnk` (hoặc `C:\Program Files\Mesh\MeshVPN.exe`) từ Windows Explorer.
4. **Kỳ vọng**: Không có cửa sổ `cmd.exe`/`conhost.exe` đen xuất hiện (`PE Subsystem == 2`); biểu tượng Tray và cửa sổ Dashboard mở lên bình thường.

### `WIN-UAT-02` — Single-Instance (`Local\`), Ẩn Tray & Khôi phục `TaskbarCreated` (`US-103`, `US-108`)
1. Đang mở Dashboard, bấm nút `X` góc trên phải -> cửa sổ ẩn về System Tray (`MeshVPN.exe` vẫn chạy).
2. Mở lại `MeshVPN.exe` lần 2 -> không sinh thêm tiến trình mới; cửa sổ cũ tự bật lên (`SetForegroundWindow`).
3. Mở Task Manager -> Restart `Windows Explorer` (`explorer.exe`) -> biểu tượng Tray tự khôi phục qua thông điệp `TaskbarCreated`.

### `WIN-UAT-03` — Trạng thái Chưa đăng ký (`NotEnrolled`) & Phát hiện Dịch vụ (`US-104`)
1. Khi `MeshVpnAgent` chạy nhưng máy chưa enroll -> Dashboard hiển thị trạng thái `Not Enrolled` (`Set Up Mesh VPN`) cùng biểu mẫu dán `mesh://join` và nhập tay.

### `WIN-UAT-04` — Nâng quyền UAC `runas` & Giao thức `MGH1` (`US-105`)
1. Thực hiện thao tác ghi (ví dụ Enroll / Connect lần đầu) từ tài khoản có UAC.
2. **Kỳ vọng**:
   - UAC hiển thị `MeshVPN.exe --elevated-worker --pipe \\.\pipe\mesh-gui-handoff-<32_hex>`.
   - Kiểm tra cột `Command line` trong Task Manager / Process Explorer: **0** chuỗi `mpk_` hay `mesh://join` lộ trong `argv`.
   - Nếu bấm **No / Cancel** ở UAC: UI không treo, hiển thị thông báo đã hủy nâng quyền an toàn.

### `WIN-UAT-05` — Dán `mesh://join` / `mpk_*` & Tự động Xóa Clipboard Nguyên tử `30 s` (`US-104`)
1. Copy `mesh://join?v=1&ep=198.51.100.10:443&pin=sha256:...&key=mpk_...` (hoặc `mpk_...` kèm `\n` cuối chuỗi) vào Clipboard.
2. Nhấn nút Paste hoặc `Ctrl+V` trên ô nhập liệu Onboarding.
3. **Kỳ vọng**:
   - **Ca A**: Đợi `31 s` không copy gì thêm -> `Ctrl+V` trong Notepad thấy clipboard trống (`ClipboardGuard` đã xóa).
   - **Ca B**: Sau `5 s` copy chữ `"hello-user"` ở Notepad -> đợi qua `31 s` kiểm tra lại -> `"hello-user"` còn nguyên do `GetClipboardSequenceNumber()` đã đổi.

### `WIN-UAT-06` — Zero-TOFU IPv4/IPv6, Biểu mẫu Thủ công & 1-Click Reconnect (`US-102`, `US-104`)
1. Nhập `198.51.100.10` hoặc `[2001:db8::1]:443` ở Endpoint -> radio `System CA` tự khóa, bắt buộc nhập SPKI Pin `sha256:<64-hex>`.
2. Nhập đầy đủ thông tin hợp lệ -> Confirm -> UAC -> trạng thái chuyển `Connected`, hiển thị Overlay IP (`100.64.x.y`).
3. Bấm **Disconnect** -> trạng thái chuyển `Disconnected`. Bấm **Connect** lại -> kết nối lại thẳng bằng `1-Click Reconnect` (`preauth_key: None`) giữ nguyên `bootstrap.next_pin`.

### `WIN-UAT-07` — Danh sách Peer, Bộ lọc, Copy & `Ping` (`US-104`)
1. Ở trạng thái `Connected`, tìm kiếm peer theo tên/IP, kiểm tra trạng thái `Direct`/`Relay`, `rtt_ms`, `rx/tx`, bấm **Ping Peer** -> hiển thị RTT chính xác.

### `WIN-UAT-08` — 1-Click Install / Start / Upgrade Dịch vụ & `wintun.dll` (`US-106`, `US-108`)
1. Giải nén gói mới vào `Downloads` khi chưa cài (hoặc khi bản cũ đang chạy ở Tray) và bấm **Install / Start Service** (UAC) -> xác nhận `MeshVpnAgent` chạy, `C:\ProgramData\Mesh` giữ ACL `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)` và `C:\Program Files\Mesh` giữ ACL `D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)`, `keys.json` được bảo toàn.
2. Chạy `MeshVPN.exe` ngay từ `C:\Program Files\Mesh` và bấm kiểm tra Start/Repair Service -> không lỗi tự sao chép đè chính mình (`windows_paths_equivalent`).

### `WIN-UAT-09` — Launch at Sign-in (`HKCU\...\Run\MeshVPN`) (`US-108`)
1. Bật checkbox **Launch at Windows sign-in** -> kiểm tra Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MeshVPN` có giá trị `"C:\Program Files\Mesh\MeshVPN.exe" --minimized`.
2. Tắt checkbox -> giá trị Registry bị xóa sạch.

### `WIN-UAT-10` — Xoay khóa (`Rotate Key`), Đặt lại Danh tính (`Reset Identity`) & `PollingSuspensionGuard` (`US-104`, `US-105`)
1. Xoay khóa khi cần thiết -> UAC handoff chạy mượt trong khi vòng poll `ro` được tạm dừng (`PollingControl::suspend()`), không giật UI.
2. Bấm **Reset Identity** -> xác nhận -> trạng thái quay về `Not Enrolled`, trong khi dịch vụ `MeshVpnAgent` (`meshd.exe`) **vẫn tiếp tục `Running`**.

### `WIN-UAT-11` — Netcheck, Log Lọc Secret & Xuất Bugreport Ghi đè (`UnprivilegedSinkWriter`) (`US-107`)
1. Bấm **Run Netcheck** -> hiển thị kết quả STUN/UDP/NAT/Control TCP.
2. Kiểm tra log tại `%LOCALAPPDATA%\MeshVPN\logs\meshvpn-gui.*.log`: không có chuỗi `mpk_` hay `mesh://join` thô.
3. Bấm **Export Bugreport** -> lưu `Desktop\mesh-report.tar` -> bấm Export lần 2 chọn ghi đè (`Replace`) chính tệp đó -> kiểm tra file thuộc quyền sở hữu của user hiện hành và không còn tệp `.part`.

### `WIN-UAT-12` — Phát hiện `LegacyPre030` & Lỗi `SEC-05` (`US-101`, `US-104`)
1. Kết nối tới daemon `< 0.3.0` (thiếu `/v1/agent/version` & `X-Mesh-Agent-Version`) -> hiển thị banner nâng cấp `LegacyPre030`.
2. Khi server trả lỗi `Unauthenticated` -> UI chỉ hiển thị `"authentication failed"`.

### `WIN-UAT-13` — Tích hợp CLI `mesh gui` & Bảo toàn 0-Arg (`US-100`)
1. Trong PowerShell chạy `mesh` (0 tham số) -> thoát mã `2` với gợi ý `mesh gui` trong `< 1 s`.
2. Chạy `mesh gui` -> kích hoạt `MeshVPN.exe` detached và trả prompt ngay với exit code `0`.
3. Nhấp đúp trực tiếp `mesh.exe` từ Windows Explorer cạnh `MeshVPN.exe` -> mở `MeshVPN.exe` không kẹt console đen.

### `WIN-UAT-14` — Điều hướng Bàn phím & High-DPI (`125%`/`150%`/`200%`) (`US-103`)
1. Bấm `Tab` / `Shift+Tab` di chuyển qua toàn bộ các nút/ô nhập trên Dashboard.
2. Chỉnh Display Scale `100%` -> `150%` -> `200%` -> bố cục và phông chữ co giãn sắc nét (`WM_DPICHANGED`), không cắt chữ.

### `WIN-UAT-15` — Gỡ cài đặt Sạch (`-Uninstall`) & Xóa Dữ liệu (`-PurgeData`) (`US-115`)
1. Khi `MeshVPN.exe` đang chạy ở Tray, chạy:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -Uninstall
   ```
   -> `Local\MeshVpnGuiShutdownEvent` đóng Tray `<= 2 s`, `mesh.exe cleanup` dọn `ResourceLedger`, xóa `MeshVpnAgent`, `HKCU\...\Run\MeshVPN`, shortcut và toàn bộ 12 tệp bundle, **giữ nguyên `C:\ProgramData\Mesh\keys.json` và `bootstrap.toml`**.
2. Chạy thêm `-PurgeData` -> xóa toàn bộ `C:\ProgramData\Mesh` (gồm `keys.json`, `logs\`, `bugreports\`).

### `WIN-UAT-16` — Đo đạc RAM / CPU / Thoát sạch Windows (`US-103`)
1. Đo qua Task Manager (Details -> Working Set & CPU):
   - Ẩn ở System Tray: mục tiêu `<= 15 MiB` Working Set, CPU nền `< 0.5%`.
   - Mở Dashboard: mục tiêu `<= 30 MiB` Working Set.
   - Chọn *Quit* hoặc restart máy (`WM_QUERYENDSESSION`): xóa icon Tray & thoát `<= 2 s` (tunnel `meshd` vẫn sống nếu chọn Keep Connected).

---

## 4. Kịch bản Nghiệm thu macOS 13+ (`MAC-UAT-01` .. `MAC-UAT-16`)

### `MAC-UAT-01` — Mở `.dmg`, Gatekeeper `$0` Mode & Menu Bar `LSUIElement` (`US-109`, `US-114`)
1. Mở `MeshVPN-macos-universal.dmg`, kéo `Mesh VPN.app` vào `/Applications`.
2. Trên bản `$0` Ad-Hoc Mode: chuột phải `/Applications/Mesh VPN.app` -> **Open** (hoặc *System Settings -> Privacy & Security -> Open Anyway*; **tuyệt đối không** dùng `spctl` + `--master-disable`).
3. **Kỳ vọng**: Biểu tượng `Mesh VPN` xuất hiện ngay trên Menu Bar (`LSUIElement = true`); `MeshApp.init()` tự gọi `startMonitoring()` cập nhật trạng thái ngay từ lúc khởi chạy.

### `MAC-UAT-02` — Single-Window Dashboard & `.regular` / `.accessory` (`US-109`)
1. Bấm **Open Dashboard** nhiều lần hoặc nhấn `Cmd+N` -> luôn chỉ có **duy nhất 1 cửa sổ Dashboard** (`Window("Mesh VPN", id: "dashboard")`, `CommandGroup(replacing: .newItem) {}`) và icon hiện tạm trên Dock (`.regular`).
2. Đóng cửa sổ Dashboard (`Cmd+W` / nút đỏ) -> rút khỏi Dock về `.accessory`, giữ tiến trình Menu Bar sống.

### `MAC-UAT-03` — Cài đặt `LaunchDaemon` via `osascript` & Phân quyền `gid = 80` (`US-110`, `US-111`)
1. Khi dịch vụ chưa cài, bấm **Install Background Service** (với tùy chọn firewall opt-in) -> nhập mật khẩu macOS 1 lần trên hộp thoại `osascript`.
2. Xác nhận `meshd` cài tại `/usr/local/libexec/mesh/meshd` (`0755 root:wheel`), `mesh` tại `/usr/local/bin/mesh`, plist tại `/Library/LaunchDaemons/internal.mesh.meshd.plist` (`ProgramArguments` không trỏ `.app`).
3. **Phân quyền `gid = 80`**:
   - Tài khoản thuộc `admin` (`gid = 80`): Connect, Disconnect, Update Server, Rotate Key, Reset Identity, Export Bugreport hoạt động với **`0` mật khẩu** qua `/var/run/meshd/meshd-admin.sock` (`0660 root:admin`).
   - Tài khoản `Standard User` (`gid != 80`): đọc `meshd-ro.sock` bình thường, nhưng mọi lệnh admin bị từ chối rõ ràng với thông báo cần quyền Administrator.

### `MAC-UAT-04` .. `MAC-UAT-10` — Chuỗi Chức năng macOS (`US-109..US-113`)
- **`MAC-UAT-04` (`US-110`)**: Dán `mesh://join` (qua `PasteButton`, nút Paste, hoặc `Cmd+V` kèm `\n` vào `SecureField`) -> kiểm tra `NSPasteboard.general` tự xóa sau `30 s` nếu `changeCount` và SHA-256 khớp, và bảo toàn nếu user copy text khác.
- **`MAC-UAT-05` (`US-102`, `US-110`)**: Nhập IPv4/IPv6 ở form thủ công -> `System CA` tự vô hiệu hóa, bắt buộc SPKI Pin `sha256:...` (`Zero-TOFU`).
- **`MAC-UAT-06` (`US-110`)**: Connect -> Disconnect -> Connect lại (**1-Click Reconnect**, `preauthKey: nil`) giữ nguyên `bootstrap.next_pin`.
- **`MAC-UAT-07` (`US-110`)**: Lọc Peers, Copy Overlay IP / FQDN, chạy **Ping Peer** và **Run Netcheck**.
- **`MAC-UAT-08` (`US-111`)**: Khi bật Application Firewall (`socketfilterfw --getglobalstate`), thử bật ngoại lệ opt-in cho `/usr/local/libexec/mesh/meshd`.
- **`MAC-UAT-09` (`US-109`)**: Bật/tắt **Launch at Login** (`SMAppService.mainApp`) từ Menu Bar / Dashboard.
- **`MAC-UAT-10` (`US-110`)**: Chạy **Rotate Key** và **Reset Identity** -> xác nhận daemon `internal.mesh.meshd` vẫn chạy và UI quay về `Not Enrolled`.

### `MAC-UAT-11` — Xuất Bugreport `NSSavePanel` (`Darwin.rename`) & `OSLog` (`US-112`)
1. Ở Diagnostics, bấm **Export Bugreport...** -> chọn lưu ra tệp **mới tinh** `~/Desktop/mesh-report-new.tar` (`NSSavePanel`) -> xác nhận file được tạo thành công (`0` mật khẩu, `0` `.part` tồn đọng).
2. Bấm **Export Bugreport...** lần 2 -> chọn ghi đè (`Replace`) lên tệp cũ -> xác nhận cập nhật nguyên tử qua `Darwin.rename`, `/var/db/mesh` vẫn là `0700 root:wheel`.
3. Kiểm tra Unified Log (`log show --predicate 'subsystem == "dev.meshvpn.macos"'`) -> dữ liệu động ẩn `<private>` và `0` secret `mpk_*`.

### `MAC-UAT-12` .. `MAC-UAT-15` — Version Banner, CLI `mesh gui`, Retina & Uninstall Service (`US-100`, `US-113`, `US-115`)
- **`MAC-UAT-12` (`US-113`)**: Kiểm tra banner `LegacyPre030` / version mismatch và nút **Update Service** giữ `/var/db/mesh/keys.json`.
- **`MAC-UAT-13` (`US-100`)**: Chạy `mesh gui` trên Terminal -> mở `Mesh VPN.app` và thoát exit code `0`.
- **`MAC-UAT-14` (`US-109`)**: Kiểm tra Retina, Dark/Light system appearance và điều hướng bàn phím macOS.
- **`MAC-UAT-15` (`US-115`)**:
  - Bấm **Uninstall Service...** trong Dashboard (`AdminPrivilegeHelper` gọi `install-macos.sh --uninstall --keep-app`) -> xác nhận gỡ `internal.mesh.meshd`, dọn `ResourceLedger`, **giữ `/var/db/mesh/keys.json` và giữ nguyên `/Applications/Mesh VPN.app` đang mở** (không tự xóa app!).
  - Thử lại tùy chọn **Purge keys** (`--uninstall --keep-app --purge`) -> xóa sạch `/var/db/mesh`.

### `MAC-UAT-16` — Đo đạc RAM / CPU / Thoát sạch macOS (`US-109`)
1. Kiểm tra Activity Monitor / `footprint -p $(pgrep "Mesh VPN")`:
   - Menu Bar idle: mục tiêu `<= 35 MiB` RSS, CPU `< 0.5%`.
   - Mở Dashboard: mục tiêu `<= 60 MiB` RSS.
   - *Quit (Keep Connected)* hoặc *Disconnect & Quit*: thoát `<= 2 s`.

---

## 5. Sổ Cái Ký Duyệt Nghiệm Thu Phần Cứng (Operator Physical Sign-Off Ledger)

> [!WARNING]
> Các dòng `PENDING_PHYSICAL_UAT` dưới đây **bắt buộc** giữ nguyên trạng thái cho đến khi kỹ sư thực thi trực tiếp trên máy thật và điền số liệu đo đạc + chữ ký.

| Mã Kịch bản | Nền tảng | Thiết bị / OS Thực tế | Kết quả Đo đạc | Trạng thái | Người ký & Ngày (UTC) |
|---|---|---|---|---|---|
| `WIN-UAT-01..03` | Windows 10/11 `x86_64` | `TBD (Physical Windows)` | `PE Subsystem = 2` (Host Verified); Explorer UAT: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-04..07` | Windows 10/11 `x86_64` | `TBD (Physical Windows)` | UAC `runas` + `30 s` Clipboard + Zero-TOFU + Peers/Ping: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-08..11` | Windows 10/11 `x86_64` | `TBD (Physical Windows)` | 1-Click Install/Self-Copy + Autostart + Reset + Replace `.tar`: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-12..15` | Windows 10/11 `x86_64` | `TBD (Physical Windows)` | `LegacyPre030` + `mesh gui` + DPI + Clean Uninstall: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `WIN-UAT-16` | Windows 10/11 `x86_64` | `TBD (Physical Windows)` | Tray RAM (`<= 15 MiB`): `TBD`; Open RAM (`<= 30 MiB`): `TBD`; Quit (`<= 2 s`): `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-01..03` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac)` | Gatekeeper `$0` + Single Window + `gid = 80` / `osascript`: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-04..10` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac)` | Clipboard `\n` + Zero-TOFU + Reconnect + Peers + Firewall + Reset: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-11..15` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac)` | `NSSavePanel` New & Replace (`Darwin.rename`) + `--keep-app` Uninstall: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `MAC-UAT-16` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac)` | MenuBar RAM (`<= 35 MiB`): `TBD`; Open RAM (`<= 60 MiB`): `TBD`; Quit (`<= 2 s`): `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
