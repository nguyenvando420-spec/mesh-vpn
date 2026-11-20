# Báo Cáo Phản Biện Độc Lập (Red-Team Critique) — Unified UI Gate 1 (`v0.4.0` — Unified Cross-Platform UI & Bilingual Experience)

| Thuộc tính | Giá trị |
|---|---|
| **Người phản biện** | `agile-critic` (`critic-ui-g1` — Independent Principal Reviewer & Devil's Advocate) |
| **Ngày thực hiện** | 2026-11-20 |
| **Cổng kiểm duyệt** | **Unified UI Gate 1 (Milestone `v0.4.0`)** — Discovery Research & Product Backlog (`DEC-UI-01..04`) |
| **Vòng thẩm định** | **Vòng 2 — Tái Thẩm định Độc lập (Round 2 Independent Re-Verification)** sau khi `agile-researcher` & `agile-po-ba` cập nhật bản **v1.1** |
| **Nhánh đối chứng** | `feat/desktop-gui` (chuẩn bị tách `feat/unified-ui` sau khi chốt sạch working tree) |
| **Tài liệu thẩm định (Vòng 2)** | [unified-ui-readiness-requirements.md](../../01-discovery/unified-ui-readiness-requirements.md) **v1.1** (`1.140` dòng LF / `78.331` B, UTF-8 no BOM, `38` mã `UUI-01..UUI-38`, `213` Canonical Glossary keys) · [unified-ui-product-backlog.md](../../02-product-planning/unified-ui-product-backlog.md) **v1.1** (`656` dòng LF / `82.603` B, UTF-8 no BOM, `4` Epics `EP-21..EP-24`, `22` Stories `US-118..US-139` = `93 SP`) |
| **Mã nguồn & Hợp đồng đối chứng `[V]`** | [agile-state.md](../../04-sprint-management/agile-state.md), [`.agents/rules/coding-standards.md`](../../../.agents/rules/coding-standards.md), [desktop-gui-adr.md](../../03-system-design/desktop-gui-adr.md) (`ADR-020..026`), [scripts/check.ps1](../../../scripts/check.ps1), [Cargo.toml](../../../Cargo.toml), [crates/mesh-sys/Cargo.toml](../../../crates/mesh-sys/Cargo.toml), [crates/mesh-gui/Cargo.toml](../../../crates/mesh-gui/Cargo.toml), `crates/mesh-gui/src/{main.rs,app.rs,window.rs,onboarding.rs,peers_view.rs,diagnostics_view.rs,clipboard.rs,icons.rs,tray.rs,linux_gui.rs}`, `crates/mesh-gui/tests/gui_unit_tests.rs`, `crates/mesh-sys/src/gui_windows.rs`, `desktop/macos/{project.yml,MeshDesktopCore/Package.swift}`, `desktop/macos/MeshVPNApp/Sources/{MeshApp.swift,DashboardWindowView.swift,PeersTableView.swift,DiagnosticsSheetView.swift,OnboardingSheetView.swift,DashboardBannersAndCards.swift}`, `desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Models/DesktopUiState.swift`, `desktop/macos/MeshDesktopCore/Tests/MeshDesktopCoreTests/DesktopStoreTests.swift`, `mobile/android/{gradle/libs.versions.toml,app/build.gradle.kts,app/src/main/AndroidManifest.xml,app/src/main/res/values/strings.xml}`, `mobile/android/app/src/main/kotlin/dev/meshvpn/android/{MainActivity.kt,vpn/MeshVpnService.kt,ui/MeshMainViewModel.kt,ui/UiSecurityBridges.kt,ui/status/StatusScreen.kt,ui/settings/SettingsScreen.kt,ui/onboarding/OnboardingScreen.kt,ui/theme/MeshTheme.kt}`, `mobile/android/app/src/{test/kotlin/dev/meshvpn/android/ui/MeshMainViewModelTest.kt,androidTest/kotlin/dev/meshvpn/android/OnboardingComposeUiTest.kt}`, `mobile/ios/MeshApp/{Resources/Localizable.xcstrings,Sources/MeshApp.swift,Sources/AppViewModel.swift,Sources/AppViewModel+Actions.swift,Sources/DashboardView.swift,Sources/OnboardingView.swift}`, `mobile/ios/MeshVPNTests/{TunnelLifecycleAndAppViewModelTests.swift,UniFFIBindingsAndSecurityTests.swift}` |
| **Thành phần AI/SLM** | **Không có** (Hạ tầng mạng & ứng dụng native 4 nền tảng → Không áp dụng mục phản biện AI/SLM) |
| **Phán quyết Vòng 1** | `[REVISION REQUIRED]` (**4 🔴 `Blocker`** · **3 🟠 `High Risk`** · **3 🟡 `Medium`** · **1 🟢 `Low`** — `11` phát hiện) |
| **Phán quyết Cuối cùng (Vòng 2)** | **`[APPROVED FOR GATE]`** (**`11/11` phát hiện Vòng 1 đã được khắc phục triệt để trong đặc tả chuẩn tắc v1.1**; **`0 Blocker` / `0 High Risk` / `0 Medium` / `0 Low` còn mở**; ghi nhận **`3` lưu ý vệ sinh biên tập không chặn cổng `IG-UUI-G1-01..03`** cho Gate 2) |

---

## 1. Kết Quả Tái Thẩm Định Độc Lập Vòng 2 (`Round 2 Independent Re-Verification`)

`agile-critic` đã đọc lại và chạy kiểm toán tự động trên toàn bộ nội dung bản **v1.1** của `unified-ui-readiness-requirements.md` (`1.140` dòng, `78.331` bytes) và `unified-ui-product-backlog.md` (`656` dòng, `82.603` bytes), đối chiếu chéo với mã nguồn thực tế trên 4 nền tảng (**Windows**, **macOS**, **Android**, **iOS**) cùng nhánh chia sẻ `linux_gui.rs`.

### 1.1. Kiểm Toán Định Lượng Toán Học Backlog, Truy Vết Hai Chiều, Glossary & DoR (`100% PASS`)

1. **Vệ sinh tệp & Ranh giới phạm vi (`100% PASS`)**:
   - `docs/01-discovery/unified-ui-readiness-requirements.md`: `78.331` B, `1.140` dòng, **`BOM = False`**, **`CR = False`** (`100%` LF).
   - `docs/02-product-planning/unified-ui-product-backlog.md`: `82.603` B, `656` dòng, **`BOM = False`**, **`CR = False`** (`100%` LF).
   - Không có bất kỳ tệp tài liệu `v0.1.0` / `v0.2.0` / `v0.3.0` nào bị sửa đổi ngoài phạm vi.

2. **Toán học Epics, Story Points & Fibonacci (`100% PASS`)**:
   - **Số lượng**: **`4` Epics (`EP-21..EP-24`)** · **`22` User Stories (`US-118..US-139`)**.
   - **Chuẩn Fibonacci**: **`22/22` stories (`100%`)** có `SP ∈ {2, 3, 5, 8}` (`0` story ngoài tập `{1, 2, 3, 5, 8}`, không có story nào `> 8 SP`).
   - **Đối chiếu tổng hợp giữa §3, §4 và §6.1 khớp tuyệt đối `100%`**:
     - **`EP-21`** (`US-118..121`): `4 Must` (`8 + 5 + 5 + 3`) = **`21 SP`** · `0 Should` · `0 Could` = **`4 stories / 21 SP`**.
     - **`EP-22`** (`US-122..126`): `3 Must` (`8 + 3 + 5 = 16 SP`) + `2 Should` (`3 + 3 = 6 SP`) + `0 Could` = **`5 stories / 22 SP`**.
     - **`EP-23`** (`US-127..131`): `5 Must` (`5 + 5 + 5 + 3 + 5`) = **`23 SP`** · `0 Should` · `0 Could` = **`5 stories / 23 SP`**.
     - **`EP-24`** (`US-132..139`): `4 Must` (`2 + 5 + 3 + 5 = 15 SP`) + `2 Should` (`3 + 3 = 6 SP`) + `2 Could` (`3 + 3 = 6 SP`) = **`8 stories / 27 SP`**.
     - **Tổng toàn Milestone `v0.4.0`**: **`16 Must = 75 SP`** + **`4 Should = 12 SP`** + **`2 Could = 6 SP`** = **`22 Stories / 93 SP`**.

3. **Truy vết hai chiều `38/38` mã `UUI-01..UUI-38` & Canonical Glossary (`100% PASS`)**:
   - Đủ **`38/38` mã `UUI-*`** (`24 P0 + 12 P1 + 2 P2 = 38`) tại Phần 6 của Discovery v1.1 và tại cả Bảng Epic §3 (`38/38` unique, `0` thiếu, `0` trùng), dòng `Trace:` §4 và Bảng §5 của Backlog v1.1.
   - **`24/24` mã `P0` (`100%`)** đều được bao phủ bởi ít nhất một User Story mức `Must`; `UUI-30` (`P2`) tách sạch sang story `US-139` (`Could`, `3 SP`); `UUI-35` (`P1`) được phủ tường minh trong `Trace:` và AC của `US-126`, `US-127`, `US-128`.
   - **Canonical Glossary (§4.1 Discovery v1.1)**: mở rộng từ `69` lên **`213` khóa duy nhất (`213/213` unique keys)** với bản dịch `en`/`vi` chuẩn tắc cho toàn bộ Navigation, States, Headlines, Actions, Warnings, Errors, Tray Tooltips, Appearance/Theme, Language, Peer Filters/Badges/Copy, Mobile 3-tab Onboarding, Desktop 2-tab Onboarding, Key Rotation, Enrollment Confirmation, Settings, macOS/Windows Service Lifecycle, Biometric Prompts và Android Notifications.

4. **Độ phủ DoR (`[H]/[E]/[F]`) & Thứ tự Topo Đồ thị Phụ thuộc Waves A–E (`100% PASS`)**:
   - **`22/22` User Stories (`100%`)** đều có đầy đủ tối thiểu 1 tiêu chí **`[H]`**, **`[E]`**, **`[F]`** (cùng các nhãn `[S]`, `[T]`, `[N]`, `[A]`), có phân tách rõ **`CI ($0)`** vs **`Máy thật (hardware_signoff_required)`**.
   - **`22/22` stories** được phân bổ đầy đủ vào **5 Waves (`Wave A..E`)** tại §6.2 của Backlog v1.1 theo đúng thứ tự topo phụ thuộc (**`0` vi phạm thứ tự phụ thuộc**; `US-132` nằm ở Wave D sau Wave C i18n; `US-133`, `US-134` khóa sổ tại Wave E).

---

### 1.2. Bảng Đối Chứng Đóng `11/11` Phát Hiện Vòng 1

| Mã phát hiện | Mức gốc | Tóm tắt vấn đề Vòng 1 | Bằng chứng khắc phục đã kiểm chứng trong v1.1 | Trạng thái |
|---|:-:|---|---|:-:|
| **`BLK-UUI-G1-01`** | 🔴 `Blocker` | Ẩn Onboarding khi `is_enrolled == true` làm mất `Rotate Key` & `Update Server` trên Windows; hiểu sai cửa sổ macOS là popover & khóa đường vào Settings ở 7/8 state; bỏ sót `linux_gui.rs`. | Cập nhật Discovery v1.1 (§1.4 `L110–133`, §3.1 `L266–307`, §5.1.7 `L881–887`) và Backlog v1.1 (`[!IMPORTANT] #5–#7` `L26–28`, `US-118` AC1–AC5 `L143–147`, `US-127` AC5 `L320`, `US-134` AC5 `L445`): xác định đúng macOS `Window("Mesh VPN", id: "dashboard") + MenuBarExtra`, giữ 3 tab hiển thị trên **mọi trạng thái đã enroll**, chuyển `Rotate Node Key` & `Update Control Server / SPKI Pin` sang Zone 3 modals + CTA `ReauthRequired` ở Zone 1, cho phép truy cập Language/Theme cả khi chưa enroll, và khóa kiểm tra biên dịch `linux_gui.rs` trên `x86_64-unknown-linux-musl`. | ✅ **Đã đóng** |
| **`BLK-UUI-G1-02`** | 🔴 `Blocker` | Gộp sai `HDC` vào `OwnedGdiObj` (`DeleteObject`), gọi hàm ma `DestroyFont` & API ẩn `ShouldAppsUseDarkMode()`, xung đột `WS_EX_COMPOSITED` + child controls và thiếu features `windows-sys`. | Cập nhật Discovery v1.1 (§5.1.1–§5.1.3 `L795–846`) và Backlog v1.1 (`US-122` AC6–AC7 `L228–229`, `US-123` AC2/AC4 `L244–246`, `US-125` AC1 `L278`, `US-136` AC3 `L477`): tách bạch `OwnedGdiObj` (`DeleteObject` sau khi khôi phục stock `SelectObject`) vs `OwnedMemDc` (`DeleteDC`) vs `PaintGuard` (`EndPaint`); xóa `DestroyFont` và `ShouldAppsUseDarkMode()` (chỉ đọc registry `AppsUseLightTheme` + `SPI_GETHIGHCONTRAST`); đẩy chiến lược `WS_EX_CLIPCHILDREN` + `WM_CTLCOLOR*` sang `*(KN)*` Gate 2; ghi nhận bật `Win32_Graphics_Dwm` & `Win32_UI_Accessibility` trong `crates/mesh-sys/Cargo.toml`. | ✅ **Đã đóng** |
| **`BLK-UUI-G1-03`** | 🔴 `Blocker` | Bất khả thi với `AppCompatDelegate` trên `FragmentActivity` (không có `appcompat`), nhận định sai về `OnboardingComposeUiTest.kt:78`, và nhầm tệp iOS / thiếu `Locale` động trên macOS/iOS. | Cập nhật Discovery v1.1 (§5.3.4 `L981–999`, §5.4.3 `L1028–1037`) và Backlog v1.1 (`US-128` AC1/AC2/AC4 `L333–336`, `US-129` AC2/AC4/AC5 `L351–354`, `US-130` AC2 `L367`): gỡ bỏ `AppCompatDelegate` và `Locale.preferredLanguages`, gắn `*(KN)*` Gate 2 cho cơ chế live-locale (`CompositionLocalProvider`/`createConfigurationContext` + `LocaleManager` API 33+ trên Android; `.environment(\.locale, ...)` + `defaultLocalization: "en"` trong `MeshDesktopCore/Package.swift` trên macOS/iOS); liệt kê đúng 6 tệp Swift macOS; giữ `OnboardingComposeUiTest.kt` chạy ở locale `en` mặc định và tách test riêng cho `vi`. | ✅ **Đã đóng** |
| **`BLK-UUI-G1-04`** | 🔴 `Blocker` | `US-131` đặt `SP = 4` ngoài Fibonacci, sai số học §3/§6.1, mất dấu `UUI-30`/`UUI-35` trong §4, thiếu `UUI-23..27` ở §3, `13/21` stories thiếu `[H]/[E]/[F]`, và Wave A ngược Dependencies. | Cập nhật Backlog v1.1 (§3 `L109–124`, §4 `US-118..139`, §5 `L535–580`, §6.1 `L587–599`, §6.2 `L603–609`): đổi `US-131` sang `5 SP`, thêm `US-139` (`3 SP Could` cho `UUI-30`), khớp tuyệt đối `16 Must (75 SP) + 4 Should (12 SP) + 2 Could (6 SP) = 22 stories / 93 SP`; phủ đủ `38/38 UUI-*` không trùng lặp ở §3, §4 (`UUI-35` tại `US-126..128`) và §5; `22/22` stories đạt `100%` `[H]/[E]/[F]`; sắp xếp lại 5 Waves `A..E` đúng thứ tự phụ thuộc. | ✅ **Đã đóng** |
| **`HR-UUI-G1-01`** | 🟠 `High Risk` | Canonical Glossary (§4.1) chỉ có 69 keys, thiếu toàn bộ nhãn mới của `DEC-UI-01/03/04` (Theme, Language, Peer Filter, Copy IP, Onboarding, Settings, Service, Biometric, Notifications). | Mở rộng §4.1 Discovery v1.1 (`L424–771`) lên **`213` unique keys** phủ trọn mọi phân khu và phương thức Onboarding (3 tab Mobile vs 2 tab Desktop); cập nhật đúng số lượng `17` `<string>` trong `strings.xml` Android (`L98, L478, L983`) và `13` keys trong `Localizable.xcstrings` iOS (`L98, L479, L1025`). | ✅ **Đã đóng** |
| **`HR-UUI-G1-02`** | 🟠 `High Risk` | Ngộ nhận macOS `copyToPasteboard()` có 30s wipe & `filteredPeers` có `nodeId`; ép 30s wipe + `FLAG_SECURE` lên Copy IP/FQDN gây lỗi Android 10+ / iOS 16+ / Windows `ClipboardSecretGuard`. | Cập nhật Discovery v1.1 (§3.5 `L389–407`, `UUI-04..06` `L1065–1067`) và Backlog v1.1 (`[!IMPORTANT] #3` `L24`, `US-120` AC1–AC2 `L180–181`, `US-121` AC1–AC6 `L198–203`, `US-133` AC5 `L428`): giữ 30s wipe & `FLAG_SECURE` độc quyền cho bí mật `SEC-01` (`mpk_*`, `mesh://join?...`), đổi Copy IP/FQDN sang simple copy + toast (không bật `FLAG_SECURE`, không đọc ngược clipboard nền, không đụng timer `ClipboardSecretGuard` trên Windows), bổ sung `macOS` vào `US-120` cho `nodeId` search + count badge, và sửa đúng mô tả `UniFFIBindingsAndSecurityTests.swift`. | ✅ **Đã đóng** |
| **`HR-UUI-G1-03`** | 🟠 `High Risk` | Nhãn state #5 `"Connected"` sai khi VPN tắt trên Windows, lệch màu `ReauthRequired` trên macOS, thiếu 3-way Theme Selector ở `UUI-11` Android, và yêu cầu sai về notification icon trên iOS. | Cập nhật Discovery v1.1 (§1.1 `L52–71`, §2.4 `L236–242`, `UUI-11` `L1077`, `UUI-15` `L1081`, `UUI-33` `L1114`, `UUI-36` `L1117`) và Backlog v1.1 (`US-124` AC2/AC4 `L261–263`, `US-126` AC1 `L294`, `US-132` AC1–AC5 `L407–411`, `US-137` AC1–AC2 `L490–491`): phân biệt nhãn theo `TunnelSubState` (`Disconnected` / `Degraded` / `Connected`), thống nhất `ReauthRequired` sang màu `Amber` và nhãn `"Re-auth Required"`, thêm 3-way Theme Selector vào `UUI-11` Android, và tách rõ `NotificationCompat.Builder.setColor()` (Android) vs in-app `StatusBadge` (iOS). | ✅ **Đã đóng** |
| **`MED-UUI-G1-01`** | 🟡 `Medium` | Chưa có điều kiện tiên quyết chốt sạch 20 tệp đang `M` trên `feat/desktop-gui` trước khi tách `feat/unified-ui`. | Bổ sung `[!IMPORTANT] #9` (`L30`) và ghi chú điều kiện tiên quyết tại Wave A (`L605`) trong Backlog v1.1. | ✅ **Đã đóng** |
| **`MED-UUI-G1-02`** | 🟡 `Medium` | Chưa chốt vị trí hiển thị `Netcheck` và `Ping` result trên 3 tab Mobile (`Status / Peers / Settings`). | Bổ sung bảng **Mobile Zone-to-Tab mapping** tại Discovery v1.1 §3.3 (`L353–366`) và Backlog v1.1 `US-119` AC1 (`L162`): `SelfTelemetry` ở `Status`, `Ping` result inline ở `Peers`, `Netcheck` + `Bugreport` ở `Settings`. | ✅ **Đã đóng** |
| **`MED-UUI-G1-03`** | 🟡 `Medium` | Thiếu AC khóa `isAdminPinsRevealed = false` khi chuyển `SETTINGS -> PEERS` trên Android & chiến lược đồng bộ SemVer `0.4.0`. | Bổ sung `US-119` AC3 (`L164`) kiểm thử `SETTINGS -> PEERS` đặt `isAdminPinsRevealed = false`, và thêm `[!IMPORTANT] #10` (`L31`) giao Gate 2 chốt đồng bộ SemVer `0.4.0` toàn workspace. | ✅ **Đã đóng** |
| **`LOW-UUI-G1-01`** | 🟢 `Low` | Nhầm mã Persona ở `US-127/129/133`, lỗi chính tả `US-130`, lệch số đếm `Localizable.xcstrings` (`13`) & nhãn ngắn/dài Export Bugreport. | Sửa toàn bộ mã Persona (`P4-DGUI, P1-WIN`, `P5-AND`, `P1-WIN`), sửa chính tả `US-130` (`L372`), cập nhật `13` keys iOS / `17` strings Android, và bổ sung các biến thể nhãn ngắn/dài (`diag.export_button`, `win.bugreport`, `settings.export_share`) kèm ghi chú ở `US-126` AC2 (`L295`). | ✅ **Đã đóng** |

---

### 1.3. Lưu Ý Vệ Sinh Biên Tập Không Chặn Cổng (`Informational Hygiene Notes` — Chuyển Tiếp Sang Gate 2)

Quá trình đối chiếu từng dòng phát hiện **3 chi tiết biên tập nhỏ ở phần ghi chú/tóm tắt của `unified-ui-product-backlog.md` v1.1**. Do toàn bộ đặc tả chuẩn tắc trong `unified-ui-readiness-requirements.md` v1.1 và toàn bộ bảng cấu trúc/AC chuẩn tắc (§3, §4, §6.1, §6.2) của Backlog v1.1 đã chính xác và khớp nhau hai chiều, các điểm này **không gây rủi ro kỹ thuật hay sai lệch hợp đồng** (xếp mức `Informational` — không chặn Gate 1), được ghi nhận để `agile-tech-lead` & `agile-architect` lấy đúng nguồn chuẩn ở Gate 2:

- **`IG-UUI-G1-01` (Chữ nháp trong ô Lịch sử sửa đổi & con số ước lượng cũ `"60+ keys"` ở văn bản dẫn Backlog v1.1)**:
  - Ô mô tả lịch sử sửa đổi dòng `18` còn sót cụm nháp trong ngoặc `(21 Must+5 Should+1 Could=27 stories nếu kể US-139...)`, trong khi bảng chuẩn tắc §3 (`L115`) và §6.1 (`L589–598`) đã chuẩn xác `100%` là **`16 Must (75 SP) + 4 Should (12 SP) + 2 Could (6 SP) = 22 stories / 93 SP`**.
  - Một vài câu dẫn trong Backlog (`L79, L307, L359, L364, L626` ghi `"60+ keys"`, `L100` ghi `"30% vi"`) chưa thay con số mới **`213` keys** (`~25%` trên iOS) của Discovery v1.1 §4.1; tuy nhiên mọi AC của `US-127..130` đều tham chiếu trực tiếp tới *"toàn bộ Canonical Glossary §4.1"*, nên bảng `213` keys tại Discovery v1.1 §4.1 là Nguồn Chân Lý Duy Nhất.
- **`IG-UUI-G1-02` (Cột `Platforms` tóm tắt ở Bảng §5 `UUI-04..06` & ký hiệu `OwnedGdiObj<T>`)**:
  - Tại Bảng §5 (`L540–542`), cột `Platforms` của `UUI-04..06` còn in `W, A, I` dù ngay ô `Story Coverage` kế bên và `US-120` (`L175`) cùng Discovery v1.1 §6.1 (`L1065–1067`) đã cập nhật đầy đủ `W, M, A, I` (macOS bổ sung `nodeId` search + count badge và giữ nguyên `copyToPasteboard()`); tương tự `UUI-20` ở §5 (`L556`) ghi story chính `US-131` (trong khi `US-127..130` cũng đính kèm `UUI-20` ở dòng `Trace:`), và `UUI-14` có AC chi tiết đặt tại `US-122` AC7 (`L229`) song song với `Trace:` ở `US-123` (`L240, L550`).
  - Backlog (`L77, L228, L244`) viết ký hiệu `OwnedGdiObj<T>`, trong khi `crates/mesh-sys/src/gui_windows.rs:332` và Discovery v1.1 §5.1.2 (`L812–817`) định nghĩa kiểu cụ thể không generic `pub struct OwnedGdiObj(HGDIOBJ)` đi kèm `OwnedMemDc` (`DeleteDC`) và `PaintGuard` (`EndPaint`). Ở Gate 2, `agile-tech-lead` dùng đúng kiểu `OwnedGdiObj(HGDIOBJ)` hiện có của `mesh-sys`.
- **`IG-UUI-G1-03` (Giữ nguyên 100% tệp `OnboardingComposeUiTest.kt` theo `US-129` AC4)**:
  - `US-129` AC4 (`L353`) và Discovery v1.1 §5.3.4 (`L994–999`) đã chốt quy tắc chuẩn: giữ nguyên `OnboardingComposeUiTest.kt` chạy ở locale mặc định `en` và tạo **test mới riêng biệt** cho locale `vi`. Ở Chặng 3, developer tuân thủ `US-129` AC4 (không sửa tham số hóa trực tiếp vào `OnboardingComposeUiTest.kt` như vế phụ còn sót ở `L25, L166`).

---

## 2. ⚖️ Đánh Đổi Chiến Lược Khách Quan (`Strategic Trade-offs` — Trình Người Dùng Quyết Định Tại Unified UI Gate 1)

Hồ sơ Nghiên cứu và Product Backlog của Milestone **`v0.4.0` — Unified Cross-Platform UI & Bilingual Experience (`4 Epics EP-21..EP-24` · `22 Stories US-118..US-139` = `93 SP`: `16 Must = 75 SP` · `4 Should = 12 SP` · `2 Could = 6 SP`)** đã hội tụ đầy đủ về kiến trúc thông tin, hệ thống màu, từ điển song ngữ `213` khóa và các bất biến bảo mật. Để Người dùng phê duyệt Gate 1 với góc nhìn toàn diện, Scrum Master cần trình bày minh bạch **5 đánh đổi chiến lược** sau:

1. **Giao diện Bản địa Thuần Từng Hệ điều hành (`Win32 GDI/DWM` + `SwiftUI/AppKit` + `Jetpack Compose` + `SwiftUI iOS` — `DEC-UI-02`) vs Bộ Khung Đa Nền tảng Dùng Chung (WebView2/Tauri/Flutter)**:
   - **Lợi ích**: Bảo toàn tuyệt đối ngân sách nhị phân và bộ nhớ đã đạt chuẩn ở `v0.2.0`/`v0.3.0` (`MeshVPN.exe <= 6 MiB` — thực tế `2.43 MiB`, `0` phụ thuộc WebView2 Runtime, RAM khay hệ thống `<= 15 MiB` trên Windows và `<= 35 MiB` trên macOS `LSUIElement`; Mobile RSS `<= 48 MiB` Android / `<= 25 MiB` iOS), đồng thời giữ **`0` crate ngoài danh mục** trong `Cargo.lock` / `deny.toml` và `unsafe_code = "forbid"` trong `crates/mesh-gui`.
   - **Đánh đổi**: Đội ngũ phải triển khai và đồng bộ bảng màu Design Token (§2.1) cùng từ điển `213` khóa (§4.1) trên 4 tầng UI riêng biệt (`93 SP`), được kiểm soát rủi ro bằng bảng chuẩn hóa tập trung ở Discovery v1.1 và bộ kiểm thử tự động kiểm tra độ lệch chuỗi/trạng thái ở Wave E (`US-132..134`).

2. **Đổi Ngôn ngữ Trực tiếp Trong Ứng dụng (`System / Tiếng Việt / English` — `DEC-UI-04`) Không Khởi động lại Daemon & Không Kéo Thêm Thư viện Nặng (`androidx.appcompat`)**:
   - **Lợi ích**: Người dùng chuyển đổi tức thì giữa Tiếng Việt và Tiếng Anh ngay trong màn Settings mà không làm gián đoạn đường hầm WireGuard hay phiên `meshd`; đồng thời chuỗi lỗi giao thức `SEC-05` (`"authentication failed"`) và nhật ký JSON `OPS-01` giữ nguyên tiếng Anh 100% để không làm hỏng công cụ giám sát/đối soát bảo mật.
   - **Đánh đổi**: Vì Android `MainActivity` kế thừa `FragmentActivity` (không dùng `appcompat`) và Swift `String(localized:)` mặc định gắn với `Locale` lúc khởi chạy tiến trình, ở **Gate 2 (`*(KN)*`)** kiến trúc sư sẽ chuẩn hóa lớp truyền `Locale` tường minh gọn nhẹ (`createConfigurationContext` + Compose `CompositionLocalProvider` / `LocaleManager` API 33+ trên Android; `.environment(\.locale, ...)` + tra cứu `Bundle.module` trên macOS/iOS; bảng chuỗi tĩnh trong RAM trên Windows).

3. **Giới hạn Nghiêm ngặt Phạm vi Xóa Clipboard `30s` & `FLAG_SECURE` Đúng Ranh giới Bí mật `SEC-01` (`UUI-06` / `US-121`)**:
   - **Lợi ích**: Giữ cơ chế xóa clipboard tự động `<= 30s` (`ClipboardSecretGuard` / `ClipboardAutoClear` / `ClipboardAccess`) và cờ chống chụp màn hình `FLAG_SECURE` **chỉ áp dụng cho dữ liệu bí mật/nhạy cảm** (`mpk_*`, `mesh://join?...`, hiện SPKI Pin, hộp thoại xác nhận) giúp thao tác **Copy Overlay IP / FQDN** trong tab Peers hoạt động mượt mà: không gây chớp đen màn hình trên Android, không kích hoạt hộp thoại cảnh báo *"pasted from"* giả trên iOS 16+, không vướng lệnh cấm đọc clipboard nền của Android 10+, và không bao giờ hủy nhầm bộ đếm xóa `mpk_*` đang chạy trên Windows.
   - **Đánh đổi**: Địa chỉ Overlay IP (`100.64.0.x`) và FQDN nội bộ (`*.mesh.internal`) khi người dùng chủ động bấm Copy sẽ lưu lại trong clipboard như các ứng dụng mạng tiêu chuẩn cho tới khi người dùng sao chép nội dung mới.

4. **Hiển thị Cố định Thanh Điều hướng 3 Phân khu Trên Mọi Trạng thái Đã Enroll (`DEC-UI-01` / `US-118`) vs Màn Hình Đơn Từng Trạng thái**:
   - **Lợi ích**: Duy trì Header Hero + 3 tab (`Status` / `Peers` / `Diagnostics & Settings`) ngay cả khi daemon đang `connecting`, `degraded`, `reauthRequired`, `revoked`, `disconnected` hay `error` đảm bảo người dùng không bao giờ bị khóa đường vào **Rotate Node Key**, **Update Control Server / SPKI Pin**, **Netcheck**, **Export Bugreport**, hoặc đổi **Ngôn ngữ / Giao diện Sáng–Tối**.
   - **Đánh đổi**: Cần tái cấu trúc `DashboardWindowView.swift` trên macOS (vốn chỉ bật tab khi `.connected`) và tách cụm `Rotate Key` / `Update Server` trên Windows ra khỏi form Onboarding cũ để đưa vào Zone 3 modals + nút hành động nhanh trên Zone 1 (`US-118`, `8 SP`).

5. **Phân lớp Ưu tiên MoSCoW (`16 Must = 75 SP` vs `4 Should = 12 SP` + `2 Could = 6 SP`) & Nghiệm thu `$0` CI vs Ký Duyệt Thị Giác Máy Thật (`hardware_signoff_required`)**:
   - **Lợi ích**: Toàn bộ `24/24` yêu cầu `P0` nằm gọn trong `16` stories `Must` (`75 SP`), trong khi các tính năng nâng cao `P2` như bố cục 2 cột trên Tablet/iPad (`US-138`, `3 SP`) và đọc màn hình Windows Narrator MSAA/UIA (`US-139`, `3 SP`) được tách bạch thành `Could` để làm vùng đệm tiến độ an toàn.
   - **Đánh đổi**: GitHub Actions `$0` kiểm chứng tự động 100% logic chuyển trạng thái, bảng từ điển `vi`/`en`, `0` rò rỉ GDI handle (`GetGuiResources` delta `== 0`), `linux_gui.rs` cross-build và toàn bộ test bảo mật/UI hiện có; riêng độ sắc nét thẩm mỹ của custom-drawn Win32 GDI/DWM ở DPI `125%–200%`, chế độ High-Contrast và cảm nhận thực tế trên MacBook/iPhone/Android vật lý sẽ được nghiệm thu gộp trong đợt ký `hardware_signoff_required` trên thiết bị thật.

---

## 3. Hồ Sơ Lưu Trữ Phản Biện Vòng 1 (`Round 1 Critique Archive` — Đối Chiếu Lịch Sử Kiểm Toán)

### 🔴 Nhóm `Blocker` Vòng 1 (Đã đóng `4/4` ở Vòng 2)
- **`BLK-UUI-G1-01` (Đã đóng)**: Nguy cơ mất giao diện `Rotate Key` & `Update Server/Pin` trên Windows khi ẩn Onboarding lúc `is_enrolled == true`, gọi sai cửa sổ macOS là *"Dashboard popover"* và khóa đường vào Settings ở 7/8 trạng thái ngoài `.connected`, cùng nguy cơ vỡ cross-build `crates/mesh-gui/src/linux_gui.rs` → Đã giải quyết triệt để trong Discovery v1.1 (§1.4, §3.1, §5.1.7) và Backlog v1.1 (`US-118`, `US-127`, `US-134`).
- **`BLK-UUI-G1-02` (Đã đóng)**: Gộp sai `HDC` vào `OwnedGdiObj` (`DeleteObject` thay vì `DeleteDC`/`EndPaint` + thiếu trả stock `SelectObject`), viện dẫn hàm ma `DestroyFont` & API ẩn `ShouldAppsUseDarkMode()`, xung đột `WS_EX_COMPOSITED` với child controls cổ điển và thiếu ghi nhận features `Win32_Graphics_Dwm` / `Win32_UI_Accessibility` trong `crates/mesh-sys/Cargo.toml` → Đã chuẩn hóa trong Discovery v1.1 (§5.1.1–§5.1.3) và Backlog v1.1 (`US-122`, `US-123`, `US-125`, `US-136`).
- **`BLK-UUI-G1-03` (Đã đóng)**: Khóa cứng `AppCompatDelegate.setApplicationLocales()` trên `FragmentActivity` không có `androidx.appcompat`, phát biểu sai sự thật về `OnboardingComposeUiTest.kt:78`, và ghi nhầm tệp iOS `DashboardView.swift` / thiếu cơ chế `Locale` động cho `MeshDesktopCore` & iOS → Đã khắc phục trong Discovery v1.1 (§5.3.4, §5.4.3) và Backlog v1.1 (`US-128..131`).
- **`BLK-UUI-G1-04` (Đã đóng)**: `US-131` đặt `SP = 4` ngoài dãy Fibonacci, lệch tổng số học giữa §3/§4/§6.1, thiếu `UUI-30` & `UUI-35` trong §4, bỏ sót `UUI-23..27` ở §3, `13/21` stories thiếu `[H]/[E]/[F]`, và Wave A xếp ngược Dependencies → Đã chuẩn hóa lên `22` stories (`US-118..139`) = `93 SP` khớp `100%`, đủ `38/38 UUI-*`, `22/22` `[H]/[E]/[F]` và 5 Waves `A..E` đúng thứ tự topo.

### 🟠 Nhóm `High Risk` Vòng 1 (Đã đóng `3/3` ở Vòng 2)
- **`HR-UUI-G1-01` (Đã đóng)**: Canonical Glossary (§4.1) thiếu hơn 60% nhãn thực tế → Đã mở rộng lên `213` unique keys đầy đủ cho cả 4 nền tảng.
- **`HR-UUI-G1-02` (Đã đóng)**: Ngộ nhận macOS `copyToPasteboard()` có 30s wipe & `filteredPeers` có `nodeId`, và áp nhầm `FLAG_SECURE` + background clipboard wipe lên Copy IP/FQDN → Đã tách bạch ranh giới `SEC-01` và bổ sung `macOS` vào `US-120`.
- **`HR-UUI-G1-03` (Đã đóng)**: Báo sai `"Status: Connected"` khi `TunnelSubState::Disconnected` trên Windows, lệch màu `ReauthRequired` trên macOS, thiếu 3-way Theme Selector ở `UUI-11` Android, và yêu cầu notification bar icon không tồn tại trên iOS → Đã đồng bộ trong `UUI-11`, `UUI-15`, `UUI-33`, `UUI-36` và `US-124`, `US-126`, `US-132`, `US-137`.

### 🟡 Nhóm `Medium` & 🟢 `Low` Vòng 1 (Đã đóng `4/4` ở Vòng 2)
- **`MED-UUI-G1-01` (Đã đóng)**: Đã thêm điều kiện tiên quyết chốt sạch working tree `feat/desktop-gui` trước khi tách `feat/unified-ui` (`L30, L605`).
- **`MED-UUI-G1-02` (Đã đóng)**: Đã chốt bảng ánh xạ phân khu Mobile (`SelfTelemetry` → `Status`, `Ping` result → `Peers`, `Netcheck` + `Bugreport` → `Settings`).
- **`MED-UUI-G1-03` (Đã đóng)**: Đã thêm AC khóa `isAdminPinsRevealed = false` khi chuyển `SETTINGS -> PEERS` (`US-119` AC3) và mục `*(KN)*` đồng bộ SemVer `0.4.0` (`L31`).
- **`LOW-UUI-G1-01` (Đã đóng)**: Đã sửa đúng mã Persona, lỗi chính tả, số đếm `13` keys iOS / `17` strings Android và bổ sung các biến thể nhãn ngắn/dài cho nút Bugreport.

---

## 4. Kết Luận Phán Quyết Cổng Gate 1 (`Final Gate 1 Verdict`)

> **PHÁN QUYẾT CUỐI CÙNG (VÒNG 2): `[APPROVED FOR GATE]`**
> - **Trạng thái rủi ro**: **`0 Blocker`** · **`0 High Risk`** · **`0 Medium`** · **`0 Low`** còn mở (**`11/11` phát hiện Vòng 1 đã đóng dứt điểm**; kèm `3` ghi chú vệ sinh biên tập không chặn cổng `IG-UUI-G1-01..03` chuyển tiếp sang Gate 2).
> - **Đủ điều kiện trình Người dùng phê duyệt Unified UI Gate 1 (`v0.4.0` — `4 Epics EP-21..EP-24`, `22 Stories US-118..US-139 = 93 SP`, phủ `38/38 UUI-*` & `213` Canonical Glossary keys)** và chuyển sang **Chặng 2 (Gate 2 — `agile-tech-lead`, `agile-architect`, `agile-scrum-master`)** để chốt các quyết định kỹ thuật gắn nhãn `*(KN)*`.
