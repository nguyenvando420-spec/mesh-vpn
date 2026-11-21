# Giao Thức Nghiệm Thu Phần Cứng Vật Lý (Physical Hardware UAT Protocol) — Unified UI (`v0.4.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Phiên bản mục tiêu** | `v0.4.0` (Unified UI: Windows 10/11 · macOS 13+ · Android API 26+ Phone/Tablet · iOS/iPadOS 15.0+) |
| **Mã tài liệu** | `OPS-UAT-UUI-001` |
| **Phiên bản tài liệu** | `1.0` |
| **Ngày cập nhật** | `2026-11-21` |
| **Tác giả** | `WP-U-D0` QA & Operations Engineering |
| **Kế thừa bắt buộc** | `docs/06-operations/desktop-gui-hardware-acceptance-protocol.md` (`v0.3.0` core desktop UAT vẫn giữ nguyên hiệu lực) |
| **Trạng thái** | **MANDATORY PHYSICAL HARDWARE RELEASE GATE (`hardware_signoff_required = true`)** |

---

## 1. Phân tách Minh bạch 3 Tầng Bằng chứng

1. **`VERIFIED_ON_WINDOWS_HOST`**: Toàn bộ bộ kiểm thử tự động Rust `mesh-gui` (gồm GDI leak gate `100` chu kỳ `delta == 0`, kiểm thử `WM_GETDLGCODE`, `SPI_GETHIGHCONTRAST`, `213` khóa i18n, đồng nhất nhãn trạng thái, và kích thước `MeshVPN.exe <= 6 MiB`).
2. **`PENDING_CI_RUNNER`**: Biên dịch & unit tests native trên GitHub Actions `macos-15` (macOS + iOS) và `ubuntu-latest` / `windows-latest` (Android Gradle + Linux `musl` + Windows MSVC).
3. **`hardware_signoff_required`**: Các kịch bản tương tác trực quan, hỗ trợ tiếp cận (Narrator / High-Contrast), và thích ứng màn hình Tablet/iPad bên dưới **bắt buộc** thực hiện trên thiết bị thật trước khi phát hành `v0.4.0`.

---

## 2. Kịch bản Nghiệm thu Windows 10/11 (`UUI-UAT-WIN-01` .. `UUI-UAT-WIN-06`)

- **`UUI-UAT-WIN-01` — 3-Zone Navigation & Modals (`ADR-028`)**: Sau khi enroll, xác nhận form Onboarding ẩn hoàn toàn, thanh 3 tab `Status · Peers · Diagnostics & Settings` hiển thị xuyên suốt kể cả ở `ReauthRequired` / `Revoked` / `ErrorRecoverable`, và nút `Rotate Node Key` / `Update Server / Pin` mở được modal từ Zone 3.
- **`UUI-UAT-WIN-02` — Dark/Light Mode, DWM Titlebar & Live `WM_SETTINGCHANGE` (`ADR-027`, `US-125`)**: Đổi chế độ `System / Light / Dark` trong Zone 3 và đổi Windows Personalization Dark/Light lúc app đang mở -> thanh tiêu đề DWM và các thẻ/nút `BS_OWNERDRAW` cập nhật tức thì không nhấp nháy (`WS_CLIPCHILDREN` + double-buffer).
- **`UUI-UAT-WIN-03` — Live Bilingual `System / Tiếng Việt / English` (`ADR-029`, `US-131`)**: Đổi qua lại giữa `Tiếng Việt` và `English` khi tunnel đang `Connected` -> toàn bộ Dashboard và Tray menu 9 mục đổi ngôn ngữ ngay tức thì, **0** gián đoạn tunnel, **0** restart `MeshVpnAgent`; kiểm tra `%LOCALAPPDATA%\MeshVPN\ui-prefs.json` chỉ chứa `{"theme":...,"locale":...}` (0 secret) và log JSON giữ nguyên tiếng Anh (`OPS-01`).
- **`UUI-UAT-WIN-04` — Điều hướng Bàn phím `Tab`/`Shift+Tab` (`US-135`)**: Thao tác 100% bằng bàn phím (`Tab`, `Shift+Tab`, `Space`/`Enter`) đi qua đủ thanh 3 tab, các nút hành động, bộ lọc Peers, nút Copy IP/FQDN, chọn Theme/Locale và các ô nhập modal mà không bị kẹt focus.
- **`UUI-UAT-WIN-05` — Windows High-Contrast Mode (`US-135`)**: Bật Windows Contrast Themes (ví dụ *Aquatic* / *Desert*) -> kiểm tra văn bản, viền thẻ, nút focus rect rõ ràng, độ tương phản cao, không bị mất chữ.
- **`UUI-UAT-WIN-06` — Windows Narrator / MSAA Screen Reader (`US-139`)**: Bật Windows Narrator (`Win+Ctrl+Enter`), chuyển tab và kết nối/ngắt kết nối -> Narrator đọc đúng nhãn trạng thái chuẩn (`Status: Connected ...` / `Trạng thái: Đã kết nối ...`) và thông báo toast khi Copy Overlay IP/FQDN.

---

## 3. Kịch bản Nghiệm thu macOS 13+ (`UUI-UAT-MAC-01` .. `UUI-UAT-MAC-04`)

- **`UUI-UAT-MAC-01` — 3-Tab Xuyên suốt & Canonical Labels (`US-132`, `ADR-028`, `ADR-030`)**: Xác nhận Segmented Picker 3 tab (`Status / Peers / Diagnostics & Settings`) hiện ở mọi trạng thái enrolled; kiểm tra nhãn trạng thái `Re-auth Required` (tint Amber `#D97706`/`#FBBF24`, biểu tượng `key.slash`), `Agent Unavailable`, `Device Revoked`, `Attention Required`.
- **`UUI-UAT-MAC-02` — 3-Way Theme & Live Bilingual `vi`/`en` (`US-128`, `US-131`)**: Chuyển đổi `System / Light / Dark` và `System / Tiếng Việt / English` trong Diagnostics & Settings -> Dashboard và Menu Bar cập nhật tức thì mà không restart `internal.mesh.meshd`.
- **`UUI-UAT-MAC-03` — Peers Filter Chips & Non-Secret Copy (`US-120`, `US-121`)**: Tìm theo `node_id`/IP/FQDN, bấm 4 filter chips có bộ đếm, Copy Overlay IP/FQDN -> không kích hoạt tự xóa clipboard 30s (`ClipboardAutoClear` chỉ dành cho `mpk_*` / `mesh://join`).
- **`UUI-UAT-MAC-04` — Bugreport `NSSavePanel` (`IG-DGUI-WA-03`)**: Mở `NSSavePanel`, giữ hộp thoại mở 10 giây rồi lưu `.tar` mới và ghi đè `.tar` cũ -> polling vẫn khỏe khi hộp thoại đang mở và chỉ tạm dừng trong lúc stream `.tar`.

---

## 4. Kịch bản Nghiệm thu Android Phone & Tablet (`UUI-UAT-AND-01` .. `UUI-UAT-AND-05`)

- **`UUI-UAT-AND-01` — Canonical State Labels & `FLAG_SECURE` Boundary (`US-132`, `ADR-030`)**: Kiểm tra màn Status hiển thị nhãn chuẩn từ `R.string.*` (không có chuỗi enum thô kiểu `REAUTH_REQUIRED`), tab Peers cho phép chụp ảnh màn hình bình thường (`FLAG_SECURE` tắt), trong khi Onboarding và SPKI Pin reveal bật `FLAG_SECURE`.
- **`UUI-UAT-AND-02` — Live Bilingual `System / Tiếng Việt / English` (`US-129`, `US-131`)**: Đổi ngôn ngữ trực tiếp trên Settings -> toàn bộ 3 tab và notification channel đổi ngôn ngữ tức thì mà không làm đứt `MeshVpnService`; kiểm tra `BiometricPrompt` vẫn mở được bình thường (nhờ `ContextWrapper(activity)` giữ gốc `FragmentActivity`).
- **`UUI-UAT-AND-03` — Notification Semantic Color Badge (`US-137`)**: Kiểm tra thanh thông báo Android hiển thị màu sắc ngữ nghĩa khớp trạng thái (`#16A34A` Connected, `#D97706` Connecting/Degraded/Re-auth Required, `#DC2626` Revoked/Error, `#6B7280` Stopped/Waiting for Unlock).
- **`UUI-UAT-AND-04` — Copy Overlay IP/FQDN (`US-121`)**: Chạm Copy IP/FQDN trên Peers -> dán ra ứng dụng ngoài thành công, hiện toast xác nhận, không xóa clipboard nền.
- **`UUI-UAT-AND-05` — Android Tablet Adaptive 2-Column Layout (`US-138`)**: Trên máy tính bảng Android (hoặc chế độ ngang `>= 600 dp`), mở tab Peers -> danh sách peer hiển thị **2 cột** đều nhau (`LazyVerticalGrid`); xoay dọc về `< 600 dp` -> tự chuyển về **1 cột**, không cắt chữ, không lỗi cuộn.

---

## 5. Kịch bản Nghiệm thu iPhone & iPad (`UUI-UAT-IOS-01` .. `UUI-UAT-IOS-05`)

- **`UUI-UAT-IOS-01` — 3-Tab `MainTabView` & `StatusBadge` (`US-137`, `ADR-028`)**: Kiểm tra 3 tab `Status / Peers / Settings` và pill `StatusBadge` khớp màu ngữ nghĩa cả Light Mode và Dark Mode trên iOS 15.0+.
- **`UUI-UAT-IOS-02` — Live Bilingual `System / Tiếng Việt / English` (`US-130`, `US-131`)**: Chuyển ngôn ngữ trong Settings -> UI cập nhật tức thì thông qua `LocaleManager` & `L10n.tr`, giữ nguyên kết nối `NEPacketTunnelProvider`.
- **`UUI-UAT-IOS-03` — Biometric Gate (`BiometricAuthorizer.swift`)**: Xác nhận Face ID / Touch ID / Passcode vẫn hoạt động nguyên vẹn khi xoay khóa hoặc thao tác nhạy cảm.
- **`UUI-UAT-IOS-04` — Copy IP/FQDN (`US-121`)**: Copy IP/FQDN trên Peers hiện toast xác nhận, không hiện banner dán giả trên iOS 16+ và không kích hoạt timer xóa 30s của `mpk_*`.
- **`UUI-UAT-IOS-05` — iPad Adaptive 2-Column Layout (`US-138`)**: Trên iPad (`.regular` horizontalSizeClass), mở tab Peers -> hiển thị lưới **2 cột** (`LazyVGrid`); thử Split View thu nhỏ sang `.compact` (hoặc trên iPhone) -> tự chuyển về **1 cột** mượt mà.

---

## 6. Sổ Cái Ký Duyệt Nghiệm Thu Phần Cứng (Operator Physical Sign-Off Ledger)

> [!WARNING]
> Tất cả các dòng `PENDING_PHYSICAL_UAT` dưới đây **bắt buộc** giữ nguyên cho đến khi kỹ sư thực thi trực tiếp trên thiết bị thật, điền số liệu quan sát và ký xác nhận.

| Mã kịch bản | Nền tảng | Thiết bị / OS Thực tế | Ghi chú kết quả đo đạc | Trạng thái | Người ký & Ngày (UTC) |
|---|---|---|---|---|---|
| `UUI-UAT-WIN-01..03` | Windows 10/11 `x86_64` | `TBD (Physical Windows)` | 3-Zone + DWM Dark/Light + Live VI/EN: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `UUI-UAT-WIN-04..06` | Windows 10/11 `x86_64` | `TBD (Physical Windows)` | Tab Traversal + High-Contrast + Narrator MSAA: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `UUI-UAT-MAC-01..04` | macOS 13+ (`arm64`/`x86_64`) | `TBD (Physical Mac)` | 3-Tab + Amber Re-auth + Live VI/EN + SavePanel: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `UUI-UAT-AND-01..04` | Android Phone (API 26+) | `TBD (Physical Android)` | Canonical labels + Live VI/EN + Biometric + Notif color: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `UUI-UAT-AND-05` | Android Tablet (`>= 600 dp`) | `TBD (Physical Tablet)` | 2-column landscape `>= 600 dp` & 1-column portrait `< 600 dp`: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `UUI-UAT-IOS-01..04` | iPhone (iOS 15.0+) | `TBD (Physical iPhone)` | 3-Tab + StatusBadge + Live VI/EN + FaceID: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
| `UUI-UAT-IOS-05` | iPad (iPadOS 15.0+) | `TBD (Physical iPad)` | 2-column `.regular` & 1-column `.compact` Split View: `TBD` | `PENDING_PHYSICAL_UAT` | `TBD` |
