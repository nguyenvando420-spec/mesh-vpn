# Unified UI Product Backlog — Mesh VPN (`v0.4.0` — Unified Cross-Platform UI & Bilingual Experience)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-po-ba` |
| Ngày lập | 2026-11-20 |
| Phiên bản | **1.1** — Cập nhật theo phán quyết Gate 1 (`BLK-UUI-G1-01..04`, `HR-UUI-G1-01..03`, `MED-UUI-G1-01..03`, `LOW-UUI-G1-01`) từ `critic-ui-g1`; đồng bộ với [unified-ui-readiness-requirements.md](../01-discovery/unified-ui-readiness-requirements.md) v1.1 |
| Phiên bản trước | 1.0 — 2026-11-20 (Phiên bản đầu) |
| Nhánh phát triển | `feat/unified-ui` (tách từ `feat/desktop-gui`; giữ nguyên `main`, `v0.1.0-rc1`, `feat/mobile-clients @ v0.2.0`, `feat/desktop-gui @ v0.3.0`) |
| Tài liệu đầu vào | [unified-ui-readiness-requirements.md](../01-discovery/unified-ui-readiness-requirements.md) v1.1 (`38` mã `UUI-*`) · [desktop-gui-product-backlog.md](./desktop-gui-product-backlog.md) v1.1 · [mobile-product-backlog.md](./mobile-product-backlog.md) v1.1 · [agile-state.md](../04-sprint-management/agile-state.md) · [desktop-gui-adr.md](../03-system-design/desktop-gui-adr.md) · [desktop-gui-ipc-and-ui-contracts.md](../03-system-design/desktop-gui-ipc-and-ui-contracts.md) |
| Thành phần AI/SLM | **Không có** ⇒ không áp dụng AI/Data Epic |

### Lịch sử sửa đổi

| Phiên bản | Ngày | Nội dung |
|---|---|---|
| 1.0 | 2026-11-20 | Phiên bản đầu: `4 Epics EP-21..EP-24`, `21 Stories US-118..US-138`, `38/38 UUI-*` |
| 1.1 | 2026-11-20 | Đóng 11/11 phát hiện Gate 1: sửa SP US-131 (4→5), sửa toán học §3/§6.1 (21 Must+5 Should+1 Could=27 stories nếu kể US-139; 22 stories US-118..US-139), bổ sung US-139 (MSAA/UIA), fix UUI-30/35 trace, fix Wave DAG §6.2, fix persona codes, sửa macOS arch (Window+MenuBarExtra), fix clipboard semantics US-121, fix Win32 RAII (OwnedGdiObj/OwnedMemDc/PaintGuard), fix locale mechanism, bổ sung [H]/[E]/[F] 100% stories, thêm MED/LOW fixes |

> [!IMPORTANT]
> **Nguyên tắc bảo toàn & Ranh giới Gate 1 (What) vs Gate 2 (How):**
> 1. Tài liệu này chỉ hoạch định Milestone `v0.4.0` (`EP-21..EP-24`, `US-118..US-139`), **không sửa đổi** `US-001..US-117` hay bất kỳ file tài liệu nào thuộc `v0.1.0` / `v0.2.0` / `v0.3.0`.
> 2. **Kế thừa bất biến bảo mật 100%:** `ADR-020` (`MeshVPN.exe` ≤ 6 MiB, thuần `windows-sys`, `0` WebView, `unsafe_code = "forbid"` trong `mesh-gui`), `ADR-025` (macOS Swift 6, `SWIFT_STRICT_CONCURRENCY = complete`), Mobile `UniFFI 0.29.5`, 13 trường `AgentStatusResponse`, `SEC-01` (`Secret<T>`, không lộ `mpk_*`), `SEC-04` (Zero-TOFU, SPKI Pin), `SEC-05` (`"authentication failed"` wire level luôn tiếng Anh), `SEC-14` (IPC 2 kênh), `G4` (`ResourceLedger`), `OPS-01` (JSON log tiếng Anh), `FLAG_SECURE` (Android — chỉ áp dụng trên Onboarding, pin reveal, confirmation modals; **không** áp dụng lên Copy IP/FQDN trong tab Peers vì sẽ blackout Peers tab), Biometric gate (iOS `BiometricAuthorizer.swift`).
> 3. **Clipboard Wipe semantics (đã làm rõ v1.1):** 30s auto-wipe (`ClipboardSecretGuard` Windows / `clipboardWipeDelaySeconds` macOS / `ClipboardAccess` Android) **chỉ áp dụng cho SEC-01 secrets** (`mpk_*` pre-auth keys, `mesh://join?...` URIs, private keys). Copy IP/FQDN (overlay IP, FQDN — không phải secret theo SEC-01) dùng standard clipboard copy + toast xác nhận, **không** kích hoạt FLAG_SECURE hay background wipe timer. Trên Windows, Copy IP/FQDN **không được** dùng chung timer với `ClipboardSecretGuard mpk_*` (tránh cancel wipe secret sớm).
> 4. **Bảo toàn tương thích test:** Android `testTag("daemon_state_label")`, `testTag("toggle_tunnel_button")`, `testTag("error_card")`, `testTag("warning_lockdown")`, `testTag("warning_private_dns")` trong `OnboardingComposeUiTest.kt` chuỗi `"Verify Control Server Identity"` (`OnboardingComposeUiTest.kt:68-78 [V]` — test assert trực tiếp UI text, **không chỉ testTag**; nếu locale=vi khi test chạy, cần đảm bảo en fallback hoặc parameterize) và toàn bộ `testTag` hiện có phải giữ nguyên 100%. macOS `DesktopStoreTests`, `DesktopCoreTests` và iOS `MeshVPNTests` (5 file) phải xanh 100%. Windows 23/23 unit tests phải xanh 100%.
> 5. **macOS Architecture (đã làm rõ v1.1):** `Mesh VPN.app` dùng `Window("Mesh VPN", id: "dashboard")` + `MenuBarExtra` (`MeshApp.swift:111-138 [V]`), **không phải popover**. Dashboard window hiện tại chỉ hiển thị Segmented `Picker` 2 tabs (`Peers` / `Diagnostics & Settings`) trong `.connected` state (`DashboardWindowView.swift:203-222 [V]`); 7 trạng thái còn lại render `DashboardCenteredCard` full-frame. DEC-UI-01 yêu cầu 3 tabs visible across **all enrolled states** (kể cả `connecting`, `reauthRequired`, `degraded`, `revoked`, `error`).
> 6. **Windows Rotate Key & Update Server (đã làm rõ v1.1):** `window.rs` Onboarding form hiện phục vụ 3 mục tiêu: initial enrollment, Rotate Key (`window.rs:745-749`), Update Server/Pin (`window.rs:740-743,1105-1120`). Khi ẩn form khi `is_enrolled == true`, các action này **phải di chuyển sang Zone 3** (Diagnostics & Settings) dưới dạng CTA modal riêng; đồng thời Zone 1 Header Hero khi `ReauthRequired` hiển thị CTA "Rotate Key".
> 7. **`linux_gui.rs` compatibility:** `crates/mesh-gui/src/linux_gui.rs` gọi `filter_peers()`, `ui_state.label()`, `ui_state.headline()`, `ui_state.tray_tooltip_summary()`. Mọi thay đổi signature của shared modules phải maintain `cargo clippy -D warnings` trên `x86_64-unknown-linux-musl` via `scripts/check.ps1 -Cross`.
> 8. **Ranh giới Gate 1 vs Gate 2:** Chi tiết triển khai cụ thể (tên module i18n, cơ chế lưu trữ locale preference, kiến trúc tab widget Win32, cơ chế live-locale Android/iOS) gắn nhãn **`*(KN)*`** để `agile-tech-lead` và `agile-architect` chốt qua ADR tại **Gate 2**.
> 9. **Working tree prerequisite:** Coordinator phải xác nhận `feat/desktop-gui` working tree sạch (`0` modified files) trước khi tạo nhánh `feat/unified-ui`.
> 10. **SemVer sync `*(KN)*`:** Toàn bộ workspace (`Cargo.toml:6`, `crates/mesh-gui/Cargo.toml:20`, `desktop/macos/project.yml:18`, `DesktopUiState.swift:36`, `mobile/android/app/build.gradle.kts:21`) phải nâng version đồng bộ lên `0.4.0` tại Chặng 3 để tránh cảnh báo `AgentVersionIndicator::Mismatch` / `DaemonVersionBannerState.mismatch`. Gate 2 chốt thời điểm và phương pháp.

---

## 0. Quy ước, DoR & DoD Unified UI (`v0.4.0`)

### 0.1. Định dạng Story

- **ID**: `EP-21..EP-24`, `US-118..US-139` (tiếp nối liên tục sau `US-117` của Milestone `v0.3.0`).
- **SP (Story Points)** ∈ `{1, 2, 3, 5, 8}`, **không story nào > 8 SP**.
- **MoSCoW**:
  - `Must`: Bắt buộc cho Milestone `v0.4.0` (đóng gói giải pháp đầy đủ theo `DEC-UI-01..04` và toàn bộ `24 P0` `UUI-*`).
  - `Should`: Giá trị vận hành cao trong `v0.4.0` (`12 P1` `UUI-*`), có thể trượt sang `v0.4.1` nếu cần giữ lịch phát hành.
  - `Could`: Mở rộng trải nghiệm sau khi lõi ổn định (`2 P2` `UUI-*`, tablet/iPad layout, MSAA/UIA).
- **Platform**: `Shared` (truy vết & kiểm tra chéo) · `Windows` (`MeshVPN.exe` / `crates/mesh-gui`) · `macOS` (`Mesh VPN.app` / `desktop/macos`) · `Android` (`mobile/android`) · `iOS` (`mobile/ios`).
- **Trace**: Ánh xạ trực tiếp và tường minh tới **38/38 mã `UUI-*`** trong [unified-ui-readiness-requirements.md](../01-discovery/unified-ui-readiness-requirements.md).
- **Acceptance Criteria (AC)** viết theo `Given / When / Then`, gắn nhãn **`[H]`** Happy path · **`[E]`** Edge case · **`[F]`** Failure handling · **`[S]`** Security/invariant · **`[A]`** Accessibility · **`[T]`** Test-compat · **`[N]`** Non-functional/SLO.

### 0.2. Definition of Ready (DoR) & Definition of Done (DoD)

- **DoR**: Story có Persona/Platform rõ, **AC đủ cả `[H]`, `[E]`, `[F]`** (kèm `[S]`, `[A]`, `[T]`, `[N]` khi áp dụng), Dependencies rõ ràng không vòng lặp, `SP <= 8`, giữ nguyên ranh giới Gate 2 (`*(KN)*`).
- **DoD (mọi story `Must`)**:
  1. Toàn bộ AC đạt bằng test tự động (Rust `cargo test`, `scripts/check.{ps1,sh}`, Swift `XCTest`, Android `./gradlew test`).
  2. `scripts/check.ps1 -Cross` / `scripts/check.sh` (UTF-8 No-BOM, 100% LF, `0` `unsafe` ngoài `crates/mesh-sys/`, allowlist 4 crate `.expose_secret()`, `0` hardcode `:443`/`:3478`), `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo deny check advisories bans licenses sources` đều xanh 100%.
  3. macOS: `swiftlint --strict` + `SWIFT_STRICT_CONCURRENCY = complete` + `xcodebuild test` xanh 100%. Android: `ktlint`, `detekt`, `lintDebug`, `testDebugUnitTest` xanh 100%. iOS: 21/21 XCTest xanh 100%.
  4. Test `test_no_secrets_in_outputs` xác nhận `0` chuỗi `mpk_*`/private key rò rỉ.
  5. Android `testTag` hiện có không bị xóa hay đổi tên; `OnboardingComposeUiTest.kt` chuỗi `"Verify Control Server Identity"` vẫn pass.
  6. `MeshVPN.exe <= 6 MiB` (ADR-020), `Mesh VPN.app` không bị App Sandbox, không WebView. Daemon wire `"authentication failed"` luôn tiếng Anh (`SEC-05`). JSON log `OPS-01` luôn tiếng Anh.
  7. Không phá vỡ hành vi CLI `crates/mesh`, không nới lỏng `ADMIN_PIPE_SDDL` hay `meshd-admin.sock`.

---

## 1. Product Vision, Goals & Global NFRs (`v0.4.0`)

### 1.1. Tuyên ngôn Tầm nhìn Unified UI (`v0.4.0`)

> **Dành cho** chủ mạng và toàn bộ người dùng Mesh VPN trên **Windows 10/11**, **macOS 13+**, **Android API 26+** và **iOS 15+** — những người sau `v0.3.0` vẫn thấy giao diện 4 nền tảng mỗi nơi mỗi kiểu (Windows chưa có Dark Mode / tab riêng, Android còn 2 tab, iOS còn 1 màn scrollable, không nơi nào nói tiếng Việt), và Peers chưa có bộ lọc 4 trạng thái + Copy IP/FQDN thống nhất trên mọi nền tảng;
> **Mesh VPN `v0.4.0` Unified UI** đồng bộ giao diện 4 nền tảng theo kiến trúc 3 phân khu thống nhất (`Status` · `Peers` · `Diagnostics & Settings`) + `Onboarding` tách riêng, bảng màu Design Token Light/Dark và song ngữ Tiếng Việt / Tiếng Anh đổi trực tiếp không khởi động lại daemon;
> **khác với** các bản cập nhật UI đơn thuần, **ở chỗ** giữ nguyên 100% bất biến bảo mật (`ADR-020`, `ADR-025`, `SEC-01/04/05/14`, `FLAG_SECURE` scope-limited, Biometric, clipboard 30s wipe cho secrets, 13-field `AgentStatusResponse`, `OPS-01` log tiếng Anh) và tương thích test hiện có (Android `testTag`, macOS XCTest, iOS XCTest, Windows unit tests).

**Một câu:** *"Mở Mesh VPN trên bất kỳ thiết bị nào — Windows, Mac, Android, iPhone — và thấy ngay giao diện thống nhất 3 tab, bảng màu tối/sáng thương hiệu, danh sách Peers có tìm kiếm + lọc 4 trạng thái + Copy IP, và toàn bộ nhãn hiển thị bằng tiếng Việt hoặc tiếng Anh tùy chọn."*

### 1.2. Mục tiêu Sản phẩm (`v0.4.0` Goals)

1. **Thống nhất Kiến trúc Thông tin 3 Phân khu (`DEC-UI-01`)**: Desktop 3 tab ngang (Header Hero + Tab bar), Mobile Bottom Nav 3 tab; Onboarding tách biệt, ẩn khi đã enroll; Rotate Key / Update Server di chuyển sang Zone 3.
2. **Nâng cấp Peers Zone trên mọi nền tảng (`DEC-UI-01`)**: Search + 4-state filter + Path Badge + RTT + Copy IP/FQDN + Ping thống nhất trên Windows, Android, iOS (macOS đã có, cần bổ sung nodeId search & count badge).
3. **Windows GDI/DWM hiện đại (`DEC-UI-02`, `ADR-020`)**: Dark/Light titlebar, rounded cards, status pills, 3-tab, double-buffering, DPI Per-Monitor V2, `OwnedGdiObj<T>` RAII (`DeleteObject`), `OwnedMemDc` (`DeleteDC`), `PaintGuard` (`EndPaint`) — giữ binary ≤ 6 MiB.
4. **Bảng màu thương hiệu thống nhất (`DEC-UI-03`)**: Design Token Light/Dark trên cả 4 nền tảng; tùy chọn `System / Light / Dark`.
5. **Song ngữ vi/en (`DEC-UI-04`)**: Canonical Glossary 60+ keys; đổi ngôn ngữ trực tiếp trong Settings không restart daemon; wire `SEC-05` và log `OPS-01` luôn tiếng Anh.

### 1.3. Global NFRs UI (`UUI-GNFR-*`)

| Mã | NFR | Tiêu chí đo kiểm |
|---|---|---|
| **UUI-GNFR-01** | **Bảo toàn ADR-020 & ADR-025** | `MeshVPN.exe <= 6 MiB`, `unsafe_code = "forbid"` trong `mesh-gui`, `0` WebView; macOS `SWIFT_STRICT_CONCURRENCY = complete`, `swiftlint --strict` xanh |
| **UUI-GNFR-02** | **Bảo mật bất biến 100%** | `SEC-01/04/05/14`, Biometric, `FLAG_SECURE` (scope-limited), clipboard 30s wipe cho secrets, 13-field `AgentStatusResponse` — toàn bộ test bảo mật hiện có PASS |
| **UUI-GNFR-03** | **Tương thích test 100%** | Android `testTag` hiện có không thay đổi; `OnboardingComposeUiTest.kt` `"Verify Control Server Identity"` PASS; macOS XCTest/iOS XCTest/Windows 23/23 unit tests PASS |
| **UUI-GNFR-04** | **Wire & log tiếng Anh** | `"authentication failed"` wire `SEC-05` không đổi; JSON log `OPS-01` không bị localize bất kể locale UI |
| **UUI-GNFR-05** | **Hiệu năng & footprint không thoái lui** | Windows idle Tray ≤ 15 MiB; macOS idle Menu Bar ≤ 35 MiB; Mobile RSS không vượt ngưỡng `M-GNFR-01/02` hiện có |

---

## 2. Personas (`v0.4.0`)

| Mã | Ngữ cảnh | Nỗi đau UI hiện tại | Kỳ vọng `v0.4.0` |
|---|---|---|---|
| **P1-WIN** | Minh — Windows 10/11, Administrators | Giao diện đơn thuần 1 màn, không Dark Mode, không tab Peers riêng, không tiếng Việt | 3 tab, Dark/Light toggle, Peers có Search+Filter, nhãn tiếng Việt |
| **P1-MAC** | Minh — macOS 13+ `arm64`/`x86_64` | Dashboard chỉ hiện 2 tabs khi `.connected`, không tùy chọn ngôn ngữ trong Settings | 3 tab Desktop visible across all enrolled states, Language selector, Peers Copy IP đồng bộ labels vi/en |
| **P5-AND** | Lan — Android API 26+ | 2 tab STATUS/SETTINGS, không có tab Peers riêng, không có bộ lọc 4 trạng thái, không tiếng Việt | Bottom Nav 3 tab, Peers zone đầy đủ, `values-vi/strings.xml` |
| **P5-IOS** | Lan — iPhone/iPad iOS 15+ | Single NavigationView scrollable, không tab, không bộ lọc Peers, 30% vi translation | TabView 3 tab, Peers zone đầy đủ, `Localizable.xcstrings` đầy đủ |
| **P4-DGUI** | Người dùng cuối chưa quen CLI | Không hiểu trạng thái, không tìm được IP peer | Trạng thái rõ ràng bằng tiếng Việt, Copy IP 1 chạm |

---

## 3. Cấu trúc 4 Epics Mới (`EP-21..EP-24`)

Bảng tổng hợp 4 Epics thuộc Milestone **`v0.4.0` — Unified Cross-Platform UI & Bilingual Experience** (`US-118..US-139`), kế tiếp trực tiếp sau `EP-20` (`US-117`):

| Epic | Tên Epic | Platform | Mã `UUI-*` bao phủ | Stories (ID) | Tổng Story | Must (Story / SP) | Should (Story / SP) | Could (Story / SP) | Tổng SP |
|---|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **EP-21** | Unified Information Architecture — 3-Zone Navigation & Peers Zone | W, M, A, I | `UUI-01..07`, `UUI-33` | `US-118..US-121` | 4 | 4 / 21 | 0 / 0 | 0 / 0 | 21 |
| **EP-22** | Unified Design System — Color Tokens, Theme Toggle & Windows GDI/DWM | W, M, A, I | `UUI-08..15`, `UUI-23..27`, `UUI-32` | `US-122..US-126` | 5 | 3 / 16 | 2 / 6 | 0 / 0 | 22 |
| **EP-23** | Bilingual Experience — Canonical Glossary, i18n Implementation & Locale Selector | W, M, A, I | `UUI-16..22`, `UUI-35` | `US-127..US-131` | 5 | 5 / 23 | 0 / 0 | 0 / 0 | 23 |
| **EP-24** | Cross-Platform Quality, Accessibility & Regression Safety | W, M, A, I | `UUI-28..31`, `UUI-34`, `UUI-36..38` | `US-132..US-139` | 8 | 4 / 15 | 2 / 6 | 2 / 6 | 27 |
| | **Tổng cộng Milestone `v0.4.0` (`EP-21..EP-24`)** | | **38 / 38 mã `UUI-*`** | **`US-118..US-139`** | **22** | **16 / 75** | **4 / 12** | **2 / 6** | **93** |

> **Kiểm toán nhất quán số đếm (v1.1):**
> - Theo MoSCoW: `16 (Must) + 4 (Should) + 2 (Could) = 22 stories` · `75 (Must SP) + 12 (Should SP) + 6 (Could SP) = 93 SP`.
> - Theo Epic: `4 + 5 + 5 + 8 = 22 stories` · `21 + 22 + 23 + 27 = 93 SP`.
> - Mọi `24 P0` `UUI-*` được phủ bởi tối thiểu một story `Must`.
> - `US-139` (EP-24, `Could`, 3 SP) bổ sung MSAA/UIA (`UUI-30`) tách riêng.
> - **EP-22 SP breakdown**: US-122(8)+US-123(3)+US-124(5) = 16 Must · US-125(3)+US-126(3) = 6 Should · Total 22 SP ✓
> - **EP-23 SP breakdown**: US-127(5)+US-128(5)+US-129(5)+US-130(3)+US-131(5) = 23 Must ✓
> - **EP-24 SP breakdown**: US-132(2)+US-133(5)+US-134(3)+US-135(5) = 15 Must · US-136(3)+US-137(3) = 6 Should · US-138(3)+US-139(3) = 6 Could · Total 27 SP ✓

---

## 4. Chi tiết Epics & INVEST User Stories (`US-118..US-139`)

---

### 4.1. EP-21 — Unified Information Architecture: 3-Zone Navigation & Peers Zone

> **Mục tiêu**: Triển khai kiến trúc 3 phân khu thống nhất (`Status` · `Peers` · `Diagnostics & Settings`) + tách `Onboarding`, đồng bộ Peers Zone đầy đủ (Search + 4-state filter + Copy IP/FQDN + Path Badge + RTT + Ping) trên 4 nền tảng. macOS đã có `PeersTableView` với `PeerFilter` và `Copy Overlay IP`/`Copy FQDN` nhưng thiếu `nodeId` search và count badge — cần bổ sung. Windows/Android/iOS cần implement toàn bộ Peers Zone từ đầu. Rotate Key / Update Server phải di chuyển từ Onboarding form Windows sang Zone 3 khi enrolled.

#### US-118 — 3-Tab Navigation Desktop (Windows & macOS) + Onboarding tách biệt + Zone 3 Maintenance CTAs

- **Epic**: `EP-21` · **SP**: `8` · **MoSCoW**: `Must` · **Platform**: `Windows, macOS`
- **Dependencies**: Không (dựa trên `crates/mesh-gui/src/window.rs`, `crates/mesh-gui/src/app.rs`, `desktop/macos/MeshVPNApp/Sources/MeshApp.swift`, `DashboardWindowView.swift`).
- **Trace**: `UUI-01`, `UUI-03`, `UUI-33`
- **Story**: Là *người dùng Desktop Windows và macOS (`P1-WIN`, `P1-MAC`)*, tôi muốn Dashboard có Header Hero và 3 tab ngang (`Status` / `Peers` / `Diagnostics & Settings`) visible across **all enrolled states** (không chỉ `.connected`), form Onboarding được ẩn hoàn toàn sau khi enroll, và các action Rotate Key / Update Server/Pin có thể truy cập từ Zone 3 hoặc banner CTA trong Zone 1, để không bị lẫn lộn trạng thái kết nối với cài đặt mạng.
- **AC**:
  1. **[H]** *Given* `MeshVPN.exe` đã khởi động và `is_enrolled == true`, *When* người dùng mở Dashboard, *Then* hiển thị Header Hero (trạng thái, Overlay IP, nút Connect/Disconnect) và 3 tab (`Status`, `Peers`, `Diagnostics & Settings`); mỗi tab click hiển thị đúng nội dung phân khu tương ứng; không có form Onboarding nào hiển thị trong 3 tab này.
  2. **[H]** *Given* `Mesh VPN.app` macOS đã enroll, *When* người dùng mở Dashboard (`Window("Mesh VPN", id: "dashboard")` — `MeshApp.swift:111-122`), *Then* Header Hero + 3-tab Segmented `Picker` (`Status`, `Peers`, `Diagnostics & Settings`) hiển thị cho **tất cả** enrolled states, không chỉ `.connected`; macOS hiện có 2 tabs chỉ trong `.connected` (`DashboardWindowView.swift:203-222`) — phải mở rộng sang các trạng thái `connecting`, `reauthRequired`, `degraded`, `revoked`, `error`; dùng `NSSegmentedControl` hoặc SwiftUI `Picker` Segmented style (`*(KN)*`).
  3. **[H]** *Given* `is_enrolled == true` và trạng thái `ReauthRequired`, *When* Header Hero hiển thị, *Then* CTA "Rotate Node Key" xuất hiện trong Zone 1 banner; Zone 3 `Diagnostics & Settings` chứa dedicated "Rotate Node Key" modal và "Update Control Server / SPKI Pin" modal — các action này không còn nằm trong Onboarding form (`window.rs:740-749`).
  4. **[E]** *Given* người dùng chưa enroll (`is_enrolled == false`), *When* mở Dashboard, *Then* hiển thị màn hình Onboarding (flow riêng biệt, không phải 1 trong 3 tab); sau khi enroll thành công, chuyển tự động sang tab `Status` và ẩn vĩnh viễn form Onboarding khỏi navigation chính; Language/Theme settings vẫn truy cập được qua Settings surface rút gọn hoặc entry point riêng ngay cả khi chưa enroll.
  5. **[E]** *Given* thay đổi signature của `app.rs`, `peers_view.rs`, `diagnostics_view.rs`, `onboarding.rs`, *When* build với `scripts/check.ps1 -Cross` target `x86_64-unknown-linux-musl`, *Then* `linux_gui.rs:574-602` vẫn compile thành công — `filter_peers()`, `ui_state.label()`, `ui_state.headline()`, `ui_state.tray_tooltip_summary()` signatures không bị break.
  6. **[S]** *Given* toàn bộ navigation refactoring, *When* build với `cargo clippy --workspace --all-targets --all-features -- -D warnings` và `swiftlint --strict`, *Then* `0` `unsafe` mới trong `mesh-gui` (ADR-020), `0` WebView, `MeshVPN.exe <= 6 MiB`, Swift 6 `SWIFT_STRICT_CONCURRENCY = complete` PASS.
  7. **[T]** *Given* refactoring Windows GUI, *When* chạy `scripts/run-desktop-qa.ps1`, *Then* 23/23 `mesh-gui` unit tests PASS và `DesktopStoreTests` / `DesktopCoreTests` macOS XCTest PASS.
  8. **[F]** *Given* IPC `meshd-ro` timeout hoặc daemon offline, *When* user click tab bất kỳ, *Then* tab content hiển thị trạng thái lỗi phù hợp (thông báo theo locale đang chọn), không crash, không treo UI thread.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit tests `window.rs` tab switch logic; `linux_gui.rs` compile test `x86_64-unknown-linux-musl`; macOS XCTest tab navigation across all 8 states; `scripts/check.ps1 -Cross` PASS.
  - **Máy thật (`hardware_signoff_required`)**: Tab click trực quan Windows 10/11, macOS 13+; verify 3 tabs visible in `reauthRequired` state.

#### US-119 — Bottom Tab Bar Mobile (Android & iOS) 3 tabs + Onboarding tách biệt + SPKI Pin auto-lock

- **Epic**: `EP-21` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Android, iOS`
- **Dependencies**: Không (dựa trên `mobile/android/.../MeshMainViewModel.kt`, `mobile/ios/MeshApp/Sources/DashboardView.swift`).
- **Trace**: `UUI-02`, `UUI-03`, `UUI-33`
- **Story**: Là *người dùng di động Android và iOS (`P5-AND`, `P5-IOS`)*, tôi muốn Bottom Tab Bar 3 tab (`Status` / `Peers` / `Settings`) thay cho cấu trúc hiện tại (Android 2-tab, iOS single scrollable list), Onboarding tách biệt không lẫn với màn chính, và SPKI Pin ẩn tự động khi rời tab Settings, để điều hướng nhất quán và bảo mật.
- **AC**:
  1. **[H]** *Given* `MeshVPN` Android đã enroll, *When* người dùng mở app, *Then* `BottomNavigation` hiển thị 3 tab (`Status`, `Peers`, `Settings`); `MainTab` enum mở rộng từ 2 → 3 mục (`*(KN)*`); swipe hoặc tap tab chuyển đúng màn. Mobile Zone mapping: Status = connection toggle/state/telemetry; Peers = search/filter/list/ping result inline; Settings = Netcheck/Bugreport/Theme/Language/Rotate Key/Update Server.
  2. **[H]** *Given* `MeshApp` iOS đã enroll, *When* người dùng mở app, *Then* `TabView` 3 tab (`Status`, `Peers`, `Settings`) thay thế `NavigationView` scrollable đơn (`DashboardView.swift:16-101`); swipe hoặc tap tab hoạt động đúng.
  3. **[H]** *Given* `MeshMainViewModel.selectTab()` (`MeshMainViewModel.kt:108-113`), *When* user chuyển từ `SETTINGS` sang tab `PEERS`, *Then* `isAdminPinsRevealed = false` được gọi ngay lập tức; `FLAG_SECURE` tắt sau khi rời Settings (nếu đang reveal); unit test `MeshMainViewModelTest.kt` bổ sung case `SETTINGS → PEERS` assert `isAdminPinsRevealed == false`.
  4. **[E]** *Given* người dùng chưa enroll, *When* mở app, *Then* màn `OnboardingScreen` / `OnboardingView` hiện như flow riêng biệt; sau enroll thành công chuyển về tab `Status` và bottom bar hiển thị bình thường.
  5. **[T]** *Given* thay đổi navigation Android, *When* chạy `OnboardingComposeUiTest.kt`, *Then* toàn bộ test PASS, chuỗi `"Verify Control Server Identity"` vẫn match (test assert trực tiếp UI text `OnboardingComposeUiTest.kt:68-78`; nếu locale=vi khi test chạy, cần đảm bảo en fallback hoặc parameterize locale trong test), `testTag("daemon_state_label")` và `testTag("toggle_tunnel_button")` vẫn tồn tại trong `StatusScreen`.
  6. **[S]** *Given* navigation refactoring, *When* Compose renders `BottomNavigation`, *Then* `FLAG_SECURE` vẫn áp dụng đúng trên Onboarding screen, pin reveal và confirmation modals (theo `requireFlagSecure` `MeshMainViewModel.kt:64-69`); **không** áp dụng `FLAG_SECURE` lên tab `Peers` (tránh screen blackout); iOS Keychain ACL không thay đổi.
  7. **[F]** *Given* FFI `status()` trả lỗi khi daemon offline, *When* user ở tab `Status`, *Then* hiển thị error state phù hợp; các tab `Peers` và `Settings` vẫn navigate được.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: `./gradlew testDebugUnitTest` với test `selectTab(PEERS)` asserts `isAdminPinsRevealed == false`; `OnboardingComposeUiTest.kt` PASS; iOS `xcodebuild test` 21/21 PASS.
  - **Máy thật (`hardware_signoff_required`)**: Tab tap visual trên Android 14+, iPhone vật lý; SPKI pin visibility after tab switch.

#### US-120 — Peers Zone: Search + 4-State Filter + Count Badge trên Windows, macOS (bổ sung), Android, iOS

- **Epic**: `EP-21` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Windows, macOS, Android, iOS`
- **Dependencies**: `US-118` (Windows tab), `US-119` (Mobile tab).
- **Trace**: `UUI-04`, `UUI-05`
- **Story**: Là *người dùng (`P1-WIN`, `P1-MAC`, `P5-AND`, `P5-IOS`)*, tôi muốn Peers Zone có Search bar substring filter (name/FQDN/IP/**nodeId**) và 4-state filter chips (`All / Online / Direct / Relay`) với count badge, giống macOS (đã có `PeerFilter` + `PeersTableView.filteredPeers`), để nhanh chóng tìm peer theo tên/IP/nodeId và lọc theo đường truyền.
- **AC**:
  1. **[H]** *Given* Peers Zone đang hiển thị danh sách peers, *When* người dùng gõ chuỗi vào Search bar, *Then* danh sách lọc case-insensitive theo tên, FQDN, Overlay IP và **nodeId**; xóa chuỗi → hiển thị lại tất cả. Windows: mở rộng `filter_peers()` `peers_view.rs:27-48`; macOS: thêm `nodeId` vào `PeersTableView.filteredPeers:38-41` (hiện thiếu); Android: thêm search trong tab Peers; iOS: thêm search trong tab Peers.
  2. **[H]** *Given* Peers Zone, *When* người dùng chọn filter chip `Online / Direct / Relay / All`, *Then* danh sách chỉ hiển thị peers thoả điều kiện; **count badge** trên mỗi chip cập nhật theo filter (macOS hiện có `PeerFilter` nhưng thiếu count badge `PeersTableView.swift:73-79` — cần bổ sung); filter hoạt động đồng thời với search.
  3. **[E]** *Given* danh sách 50 peers, *When* filter `Relay` chọn nhưng không có peer qua Relay, *Then* hiển thị empty state thân thiện (`diag.no_peers` localized); không crash.
  4. **[E]** *Given* peers list với peer có nodeId dài 64 ký tự hex, *When* user search bằng prefix 8 ký tự đầu, *Then* peer xuất hiện trong kết quả; count badge cập nhật chính xác.
  5. **[T]** *Given* Android Peers tab, *When* thêm filter chip, *Then* thêm `testTag("peers_filter_all")`, `testTag("peers_filter_online")`, `testTag("peers_filter_direct")`, `testTag("peers_filter_relay")` để instrumented tests có thể assert; không xóa bất kỳ `testTag` hiện có.
  6. **[N]** *Given* danh sách 50 peers với search+filter active, *When* user gõ từng ký tự, *Then* danh sách cập nhật trong `<= 100 ms` trên UI thread (debounce `>= 150 ms` cho network lookup nếu có).
  7. **[F]** *Given* `peers` FFI/IPC trả rỗng hoặc timeout, *When* Peers tab active, *Then* hiển thị empty state hoặc error message rõ ràng; filter chip vẫn hiển thị (disable không crash).
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Windows unit test `filter_peers()` mở rộng với nodeId; macOS XCTest `filteredPeers` nodeId test + count badge test; Android ViewModel unit test filter logic; iOS XCTest filter logic.
  - **Máy thật**: Visual trên từng nền tảng.

#### US-121 — Peers Zone: Copy IP/FQDN Clipboard (Simple Copy + Toast) trên Windows, Android, iOS

- **Epic**: `EP-21` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `Windows, Android, iOS`
- **Dependencies**: `US-120`, `US-118` (Windows), `US-119` (Mobile).
- **Trace**: `UUI-06`, `UUI-07`
- **Story**: Là *người dùng (`P1-WIN`, `P5-AND`, `P5-IOS`, `P4-DGUI`)*, tôi muốn nút Copy IP và Copy FQDN trong Peers Zone (macOS đã có `copyToPasteboard()` nhưng không có wipe timer), clipboard với simple copy + toast xác nhận (không phải 30s wipe vì IP/FQDN không phải SEC-01 secret), để chia sẻ địa chỉ nội bộ nhanh chóng.
- **AC**:
  1. **[H]** *Given* Peers Zone đang hiển thị peer entry, *When* người dùng bấm nút Copy IP hoặc Copy FQDN, *Then* Overlay IP hoặc FQDN được copy vào clipboard; toast/snackbar feedback xác nhận ngay lập tức (ví dụ: "Copied to clipboard"); không có 30s wipe timer kích hoạt cho action này.
  2. **[S]** *Given* Copy IP/FQDN action trên bất kỳ nền tảng nào, *When* thực hiện, *Then* Overlay IP và FQDN **không phải** SEC-01 secrets (`mpk_*`, `mesh://join?...`); do đó: (a) Windows — Copy IP/FQDN **không** dùng chung `ClipboardSecretGuard` timer với `mpk_*` (tránh cancel wipe secret sớm); (b) Android — `FLAG_SECURE` **không** kích hoạt cho Copy IP/FQDN (tránh Peers tab blackout); (c) không ghi IP/FQDN vào bất kỳ log nào. 30s wipe `ClipboardSecretGuard` / `ClipboardAccess` chỉ dành riêng cho pre-auth keys và join URIs.
  3. **[S]** *Given* copy action trên macOS (đã có `copyToPasteboard()` nhưng thiếu wipe), *When* user copy IP/FQDN, *Then* hành vi standard copy (consistent với UI-platform convention); macOS `clipboardWipeDelaySeconds = 30.0` chỉ áp dụng cho pre-auth key copy path, không apply lên IP/FQDN path.
  4. **[E]** *Given* peer có FQDN dài > 253 ký tự (edge), *When* copy, *Then* copy toàn bộ chuỗi hợp lệ hoặc truncate với thông báo rõ; không crash.
  5. **[E]** *Given* Android API 33+ với OS-level clipboard read restrictions, *When* copy IP/FQDN, *Then* simple copy hoàn tất; không gọi background clipboard read-back (blocked by OS trên Android 10+); không trigger iOS 16+ privacy paste banner.
  6. **[T]** *Given* iOS copy action, *When* chạy `UniFFIBindingsAndSecurityTests.swift`, *Then* test `MeshSecretScrubber.scrub` PASS (test scrub trên log strings, không phải clipboard wipe); không làm hỏng test hiện có.
  7. **[N]** Copy IP/FQDN hoàn tất trong `<= 100 ms`.
  8. **[F]** *Given* clipboard API không sẵn sàng (Android < 26 hoặc iOS restricted), *When* copy attempt, *Then* hiển thị lỗi thân thiện; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Windows: unit test xác nhận Copy IP/FQDN path **không** gọi `ClipboardSecretGuard` timer; Android: unit test xác nhận `FLAG_SECURE` không được set cho IP copy; iOS: `UniFFIBindingsAndSecurityTests` scrub PASS.
  - **Máy thật**: Visual confirm toast và clipboard content trên từng nền tảng.

---

### 4.2. EP-22 — Unified Design System: Color Tokens, Theme Toggle & Windows GDI/DWM

> **Mục tiêu**: Triển khai bảng màu Design Token (`DEC-UI-03`) thống nhất Light/Dark trên 4 nền tảng; tùy chọn `System / Light / Dark`; Windows GDI/DWM hiện đại (rounded cards, status pills, 3-tab widget, double-buffering memory DC, DPI V2, `OwnedGdiObj<T>` RAII cho `HBRUSH`/`HFONT`/`HPEN`/`HBITMAP` via `DeleteObject`, `OwnedMemDc` via `DeleteDC`, `PaintGuard` via `EndPaint`, dark titlebar via `DwmSetWindowAttribute`). Lưu ý: `ShouldAppsUseDarkMode()` là internal undocumented API — dùng registry key thay thế.

#### US-122 — Windows GDI/DWM Modern: Rounded Cards, Status Pills, 3-Tab Widget & Dark Titlebar

- **Epic**: `EP-22` · **SP**: `8` · **MoSCoW**: `Must` · **Platform**: `Windows`
- **Dependencies**: `US-118` (3-tab structure).
- **Trace**: `UUI-08`, `UUI-09`, `UUI-23`, `UUI-24`, `UUI-25`, `UUI-32`
- **Story**: Là *người dùng Windows (`P1-WIN`, `P4-DGUI`)*, tôi muốn `MeshVPN.exe` có giao diện Win32 hiện đại (rounded cards, status pills semantic color, 3-tab bar custom-drawn, Dark/Light titlebar via `DwmSetWindowAttribute`) với bảng màu Design Token, để trải nghiệm thẩm mỹ ngang tầm ứng dụng hệ thống Windows 11.
- **AC**:
  1. **[H]** *Given* `MeshVPN.exe` chạy trên Windows 10 1903+ (build 18362+), *When* khởi động với Dark theme, *Then* `DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE, &TRUE, 4)` được gọi; titlebar sử dụng dark theme; nền client area dùng token `surface.background = #0F172A`; guard với runtime version check (no-op trên Windows < 1903).
  2. **[H]** *Given* Status Hero hiển thị, *When* trạng thái `Connected`, *Then* Status Hero card có rounded corners (GDI `RoundRect`), status pill background `semantic.success` (`#16A34A` Light / `#4ADE80` Dark); typography: headline 20sp `FW_SEMIBOLD` `"Segoe UI"`. Tương tự cho các trạng thái Connecting (Amber `#D97706`), Revoked/Error (Red `#DC2626`), Disconnected/Stopped (Gray `#6B7280`).
  3. **[H]** *Given* 3-tab bar custom control, *When* user click tab `Peers`, *Then* tab active state highlight với `brand.cobalt` (Light) / `brand.sky` (Dark); inactive tabs `surface.text.secondary`; keyboard arrow keys `←`/`→` di chuyển focus giữa tabs; Enter activate tab được focus.
  4. **[E]** *Given* Windows 10 < 1903 (build < 18362), *When* `DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE)` gọi, *Then* fail gracefully với no-op; fallback Light theme áp dụng; không crash.
  5. **[E]** *Given* số GDI objects tiếp cận giới hạn Windows (10,000 per process), *When* `GetGuiResources` report > 5,000, *Then* log warning; custom-drawn controls không tạo thêm handle mà không giải phóng.
  6. **[S]** *Given* toàn bộ GDI changes, *When* build `cargo build --release --target x86_64-pc-windows-msvc`, *Then* `MeshVPN.exe <= 6 MiB`; `0` `unsafe` trong `crates/mesh-gui` (mọi Win32 call bọc trong `crates/mesh-sys`); `unsafe_code = "forbid"` trong `mesh-gui/Cargo.toml`. Phân biệt rõ: `OwnedGdiObj<T>` drop qua `DeleteObject` (cho `HBRUSH`, `HFONT`, `HPEN`, `HBITMAP`); `OwnedMemDc` drop qua `DeleteDC` (cho memory DC); `PaintGuard` drop qua `EndPaint` (cho paint DC từ `BeginPaint`). **Không** bọc `HDC` từ `BeginPaint` vào `OwnedGdiObj` vì cần `EndPaint`, không `DeleteObject`.
  7. **[N]** *Given* window resize hoặc tab switch, *When* repaint, *Then* double-buffering memory DC pattern (`CreateCompatibleDC` → `CreateCompatibleBitmap` → paint to memory DC → `BitBlt`) không flicker; `*(KN)*` Gate 2: quyết định áp dụng `WS_EX_COMPOSITED` hay memory DC pattern — `WS_EX_COMPOSITED` có thể conflict với `EDIT`/`LISTBOX` child controls; fallback phải test trước khi ship.
  8. **[A]** *Given* high-contrast mode bật (`SystemParametersInfoW(SPI_GETHIGHCONTRAST)`), *When* repaint, *Then* fallback sang system colors; text luôn readable; `WM_GETDLGCODE` returns `DLGC_WANTTAB` cho custom controls.
  9. **[F]** *Given* `DwmSetWindowAttribute` thất bại (API error), *When* gọi, *Then* fail gracefully, không crash; sử dụng fallback light theme.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test `OwnedGdiObj` không leak; unit test `OwnedMemDc` lifecycle; `cargo clippy` xanh; binary size check `<= 6 MiB`.
  - **Máy thật**: Visual DPI test trên 125%/150%/200%; Dark/Light toggle; High-contrast mode.

#### US-123 — Windows DPI Per-Monitor V2 & `OwnedGdiObj` RAII Gate Test

- **Epic**: `EP-22` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `Windows`
- **Dependencies**: `US-122`.
- **Trace**: `UUI-13`, `UUI-14`, `UUI-26`, `UUI-31`, `UUI-32`
- **Story**: Là *người dùng Windows với màn hình High-DPI hoặc multi-monitor (`P1-WIN`)*, tôi muốn `MeshVPN.exe` xử lý đúng `WM_DPICHANGED` (layout recalculate, icon regenerate) và bọc tất cả GDI handles mới trong đúng loại RAII wrapper để zero leak, để UI không bị mờ/vỡ khi kéo giữa các màn hình.
- **AC**:
  1. **[H]** *Given* `MeshVPN.exe` đang hiển thị, *When* user kéo window từ màn hình 96 DPI sang màn hình 192 DPI, *Then* `WM_DPICHANGED` trigger; toàn bộ layout metrics recalculate; procedural icons regenerate qua `create_status_icon_for_px()` `icons.rs:127`; font sizes recalc `lfHeight = -MulDiv(pt, dpi, 72)`.
  2. **[H]** *Given* toàn bộ GDI handles mới (`HBRUSH`, `HFONT`, `HPEN`, `HBITMAP`) cho rounded cards/pills/tab bar, *When* window lifecycle (create → show → close → reopen), *Then* `GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS)` delta == 0; `OwnedGdiObj<T>` drop via `DeleteObject` (không gọi `DestroyFont` — hàm này không tồn tại trong Win32); memory DC drop via `OwnedMemDc` → `DeleteDC`.
  3. **[E]** *Given* single monitor setup (no DPI change events), *When* window create/destroy 100x, *Then* GDI delta == 0; không accumulate leak.
  4. **[N]** `GetGuiResources` delta phải == 0 — gate criterion ADR-020; alert log nếu count > 5,000 (Windows limit 10,000). `Win32_Graphics_Dwm` và `Win32_UI_Accessibility` features cần được thêm vào `crates/mesh-sys/Cargo.toml` nếu chưa có (`*(KN)*` Gate 2).
  5. **[T]** Unit test simulate `WM_DPICHANGED` → verify icon px size correct; simulate window create+destroy 100x → verify GDI delta == 0.
  6. **[F]** *Given* `get_dpi_for_window()` không khả dụng (không có `Shcore.dll`), *When* khởi động, *Then* fallback về DPI 96 chuẩn; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test GDI lifecycle, DPI mock; `cargo clippy` xanh.
  - **Máy thật**: Visual trên multi-monitor Windows với DPI khác nhau.

#### US-124 — Design Token Color System: macOS, Android, iOS Theme Selector

- **Epic**: `EP-22` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `macOS, Android, iOS`
- **Dependencies**: `US-118` (macOS tab), `US-119` (Mobile tab).
- **Trace**: `UUI-10`, `UUI-11`, `UUI-12`, `UUI-15`
- **Story**: Là *người dùng macOS, Android, iOS (`P1-MAC`, `P5-AND`, `P5-IOS`)*, tôi muốn tùy chọn `System / Light / Dark` trong Settings và bảng màu Design Token thống nhất (`DEC-UI-03`) trên cả 3 nền tảng (bao gồm 3-way Theme Selector cho Android), để trải nghiệm thẩm mỹ nhất quán.
- **AC**:
  1. **[H]** *Given* macOS, *When* user chọn `Dark` trong Settings, *Then* `NSApp.appearance = NSAppearance(named: .darkAqua)`; Menu Bar SF Symbol icons adapt; persisted across launches. System: theo `@Environment(\.colorScheme)`. Light: `.aqua`.
  2. **[H]** *Given* Android, *When* user chọn `Dark` trong Settings **3-way selector** (`System / Light / Dark`), *Then* `MeshTheme.kt` force Dark scheme (không dùng `isSystemInDarkTheme()` cho manual override); verify hex values match canonical tokens: `brand.cobalt = #0B57D0` (Light primary), `surface.background = #0F172A` (Dark). `M-GNFR-02` RSS không tăng. **Lưu ý**: `UUI-11` yêu cầu 3-way Theme Selector cho Android — không chỉ verify colors.
  3. **[H]** *Given* iOS, *When* user chọn `Light` trong Settings 3-way selector, *Then* `preferredColorScheme` hoặc `UIUserInterfaceStyle` override applied. System: theo system appearance.
  4. **[E]** *Given* Android `MeshTheme.kt:14` hiện có `brand.cobalt = 0xFF0B57D0`, *When* verify Design Token table (§2.1), *Then* tất cả semantic colors match canonical hex: `semantic.success = #16A34A` Light / `#4ADE80` Dark; `semantic.warning = #D97706` / `#FBBF24`; `semantic.error = #DC2626` / `#F87171`; `semantic.neutral = #6B7280` / `#9CA3AF`.
  5. **[E]** *Given* theme preference store corrupt, *When* khởi động, *Then* fallback về `System`; không crash.
  6. **[T]** macOS: `DesktopStoreTests` PASS. Android: `testDebugUnitTest` PASS, theme selector không break `testTag` hiện có; thêm `testTag("theme_selector")` vào Settings screen. iOS: `TunnelLifecycleAndAppViewModelTests.swift` PASS.
  7. **[F]** *Given* theme preference file missing, *When* khởi động, *Then* fallback về `System`; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: macOS XCTest color scheme; Android ViewModel theme unit test 3-way; iOS XCTest appearance.
  - **Máy thật**: Visual Light/Dark toggle trên từng nền tảng.

#### US-125 — Windows: `WM_SETTINGCHANGE` / Registry Live Theme Reload

- **Epic**: `EP-22` · **SP**: `3` · **MoSCoW**: `Should` · **Platform**: `Windows`
- **Dependencies**: `US-122`, `US-123`.
- **Trace**: `UUI-27`
- **Story**: Là *người dùng Windows (`P1-WIN`)*, tôi muốn `MeshVPN.exe` tự động cập nhật theme khi tôi thay đổi Dark/Light mode trong Windows Settings (không cần restart app), để không bị "mắc kẹt" theme cũ.
- **AC**:
  1. **[H]** *Given* `MeshVPN.exe` đang chạy, *When* user đổi từ Light → Dark trong Windows Settings (gửi `WM_SETTINGCHANGE` và `WM_THEMECHANGED`), *Then* re-query registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme` (value `0` = Dark); `DwmSetWindowAttribute` toggle dark titlebar; toàn bộ cached brushes/pens invalidate và rebuild từ Design System §2.1. **Không** gọi `ShouldAppsUseDarkMode()` (undocumented internal API — không stable).
  2. **[E]** *Given* `WM_SETTINGCHANGE` arrives nhưng app không focused (minimized to tray), *When* user restore window sau đó, *Then* theme đã được update đúng; không cần additional message.
  3. **[E]** *Given* multiple rapid theme switches (5 lần trong 2 giây), *When* messages arrive, *Then* cuối cùng theme đúng được apply; không crash, không deadlock.
  4. **[N]** Theme reload hoàn tất trong 1 frame repaint (không delay visible).
  5. **[F]** *Given* registry key `AppsUseLightTheme` không tồn tại hoặc không đọc được, *When* nhận `WM_THEMECHANGED`, *Then* fallback về Light theme; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test mock `WM_SETTINGCHANGE` → verify color rebuild; test registry read → dark/light determination.
  - **Máy thật**: Manual theme toggle Windows 10/11.

#### US-126 — Tray/Menu Bar Icon Semantic Color Mapping (Windows & macOS)

- **Epic**: `EP-22` · **SP**: `3` · **MoSCoW**: `Should` · **Platform**: `Windows, macOS`
- **Dependencies**: `US-124` (tokens), `US-122` (Windows GDI).
- **Trace**: `UUI-15`, `UUI-35`
- **Story**: Là *người dùng Desktop (`P1-WIN`, `P1-MAC`)*, tôi muốn icon Tray/Menu Bar và context menu items (bilingual) khớp chính xác bảng màu §2.4 cho tất cả 10 state+sub-state combinations và hiển thị theo locale đang chọn, để nhận biết trạng thái VPN ngay từ góc màn hình.
- **AC**:
  1. **[H]** *Given* 10 state+sub-state combinations từ §3.4 requirements, *When* `DesktopUiState` chuyển state, *Then* icon tone (Windows RGB / macOS SF Symbol) khớp bảng §2.4: Connected=Green `#16A34A` / `checkmark.shield.fill`; Connecting/Degraded=Amber `#D97706` / `bolt.shield.fill`; Disconnected/NotEnrolled/Stopped=Gray `#6B7280` / `shield`; Warning/Error/Revoked=Red `#DC2626` / `exclamationmark.shield.fill`.
  2. **[H]** *Given* locale `vi` đang được chọn, *When* Tray context menu (Windows) / MenuBar tooltip (macOS) render, *Then* 9 Tray items (Windows: `IDM_STATUS_HEADER..IDM_DISCONNECT_AND_QUIT`) và Menu Bar labels hiển thị tiếng Việt từ Canonical Glossary §4.1; `IDM_*` command IDs không thay đổi (`count_non_separator_entries()` vẫn assert 9 items `tray.rs:149-154`). Tray Windows: dùng nhãn ngắn cho menu items (không dùng nhãn dài iOS `"Export Redacted Bugreport"` — dùng `"Export Bugreport (.tar)..."` tại `tray.rs:116`). `UUI-35` coverage.
  3. **[E]** *Given* state `Connected` + `TunnelSubState::Degraded`, *When* Tray renders, *Then* Amber tone (không phải Green).
  4. **[E]** *Given* locale `fr-FR` (không được support), *When* Tray renders, *Then* fallback `en` labels; không crash.
  5. **[T]** Windows: `count_non_separator_entries()` vẫn assert 9 Tray items `tray.rs:149-154`; test icon tone cho mỗi state; test locale switch → Tray labels vi/en. macOS: `DesktopStoreTests` icon mapping tests PASS.
  6. **[F]** *Given* icon render lỗi, *When* `create_status_icon_for_px()` fail, *Then* fallback sang placeholder icon; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test icon tone cho 10 states; tray item count assert; locale-aware label test.

---

### 4.3. EP-23 — Bilingual Experience: Canonical Glossary, i18n Implementation & Locale Selector

> **Mục tiêu**: Triển khai song ngữ `vi` / `en` trên 4 nền tảng theo Canonical Glossary §4.1 (60+ keys). Windows: string table module `*(KN)*`. macOS: `String(localized:)` + `.xcstrings` (6 source files: `MeshApp.swift`, `DashboardWindowView.swift`, `PeersTableView.swift`, `DiagnosticsSheetView.swift`, `OnboardingSheetView.swift`, `DashboardBannersAndCards.swift`). Android: `values-vi/strings.xml` + locale mechanism `*(KN)*` Gate 2. iOS: extend `Localizable.xcstrings` từ 13 keys hiện có. Locale selector 3-way trong Settings. Giữ nguyên wire `SEC-05` và log `OPS-01` tiếng Anh tuyệt đối.

#### US-127 — Windows i18n String Table Module (`en` / `vi`) + Tray Bilingual

- **Epic**: `EP-23` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Windows`
- **Dependencies**: `US-118` (tab structure).
- **Trace**: `UUI-16`, `UUI-20`, `UUI-21`, `UUI-22`, `UUI-35`
- **Story**: Là *người dùng Windows nói tiếng Việt (`P4-DGUI`, `P1-WIN`)*, tôi muốn `MeshVPN.exe` hiển thị toàn bộ nhãn UI bằng tiếng Việt khi tôi chọn `Tiếng Việt` trong Settings — bao gồm cả 9 Tray context menu items — và chuyển lại tiếng Anh ngay lập tức, mà không cần khởi động lại daemon hay app.
- **AC**:
  1. **[H]** *Given* `MeshVPN.exe` với locale `vi`, *When* render Dashboard, *Then* tất cả chuỗi UI-facing từ Canonical Glossary §4.1 hiển thị bằng tiếng Việt: `tab.status = "Trạng thái"`, `state.connected = "Đã kết nối"`, `action.connect = "Kết nối"`, tray tooltips tiếng Việt; `0` chuỗi hardcoded tiếng Anh nằm trong render path (`app.rs`, `window.rs`, `peers_view.rs`, `diagnostics_view.rs`).
  2. **[H]** *Given* user chọn `English` trong Settings, *When* locale switch, *Then* toàn bộ nhãn chuyển về `en` ngay lập tức trong cùng window (`*(KN)*`: reload window content không restart process); không restart daemon; Tray labels cũng cập nhật.
  3. **[S]** *Given* locale `vi`, *When* `meshd` trả `ErrorKind::Unauthenticated`, *Then* wire-level string `"authentication failed"` không bị localize — `SEC-05` giữ nguyên. JSON log `OPS-01` vẫn tiếng Anh (`ts`, `level`, `component`, `event` không bị translate).
  4. **[E]** *Given* string table thiếu key (edge — translation không đầy đủ), *When* render, *Then* fallback về `en` canonical cho key đó; không hiển thị key raw hay crash.
  5. **[E]** *Given* thay đổi signature của shared modules (`app.rs`, `peers_view.rs`), *When* build với `scripts/check.ps1 -Cross`, *Then* `linux_gui.rs` vẫn compile trên `x86_64-unknown-linux-musl`.
  6. **[T]** Unit test: load string table `vi`; assert `tab.status == "Trạng thái"`; assert `error.auth_failed == "authentication failed"` (không đổi dù locale=vi); assert tray label `IDM_CONNECT = "Kết nối"` khi locale=vi. `scripts/check.ps1` xanh.
  7. **[F]** *Given* locale preference file corrupt, *When* khởi động, *Then* fallback `System` locale (Windows system locale detection); không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: String table unit tests; `SEC-05` wire string invariant test; Tray label locale test.

#### US-128 — macOS i18n: `String(localized:)` + `.xcstrings` Full Glossary + Locale Live Switch

- **Epic**: `EP-23` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `macOS`
- **Dependencies**: `US-118` (tab structure).
- **Trace**: `UUI-17`, `UUI-20`, `UUI-21`, `UUI-22`, `UUI-35`
- **Story**: Là *người dùng macOS nói tiếng Việt (`P1-MAC`)*, tôi muốn `Mesh VPN.app` hỗ trợ toàn bộ Canonical Glossary §4.1 bằng `String(localized:)` / `NSLocalizedString` với `.xcstrings` (Xcode 15+ String Catalog format), bao gồm Menu Bar context menu items tiếng Việt, để không còn chuỗi hardcoded tiếng Anh trong Swift source.
- **AC**:
  1. **[H]** *Given* `Mesh VPN.app` với locale `vi`, *When* render Dashboard macOS, *Then* tất cả `displayTitle`, menu labels, sheet titles, tooltip strings trong 6 source files (`MeshApp.swift`, `DashboardWindowView.swift`, `PeersTableView.swift`, `DiagnosticsSheetView.swift`, `OnboardingSheetView.swift`, `DashboardBannersAndCards.swift`) dùng `String(localized:)` hoặc `NSLocalizedString` với key từ Canonical Glossary §4.1; `0` hardcoded `String` literal tiếng Anh trong render path. **Không** dùng `DashboardView.swift` (iOS file — không thuộc macOS source).
  2. **[H]** *Given* user chọn `English` trong Settings, *When* locale switch, *Then* chuỗi chuyển về `en` ngay; không restart daemon. Live switch cần `.environment(\.locale, selectedLocale)` injection hoặc `Bundle` override (`*(KN)*` Gate 2 — `String(localized:)` chỉ đọc `Locale.current` tại call time; live switch cần mechanism bổ sung).
  3. **[H]** *Given* locale `vi`, *When* MenuBar extra tooltip hiển thị, *Then* labels từ `tray.connected/tray.reauth/...` hiển thị tiếng Việt. `UUI-35` coverage: Menu Bar items bilingual.
  4. **[E]** *Given* `MeshDesktopCore` Package.swift thiếu `defaultLocalization: "en"`, *When* build, *Then* Swift compiler warning hoặc xcstrings không load — phải đảm bảo `defaultLocalization` và resource bundle declared (`*(KN)*` Gate 2 xác nhận setup).
  5. **[S]** *Given* locale `vi`, *When* `MeshSecretScrubber.scrub()` xử lý output, *Then* wire error `"authentication failed"` không bị localize. `SafeOsLogger` log tiếng Anh không đổi.
  6. **[T]** macOS `DesktopStoreTests` và `DesktopCoreTests` PASS 100%; `swiftlint --strict` PASS; `SWIFT_STRICT_CONCURRENCY = complete` PASS.
  7. **[F]** *Given* `Localizable.xcstrings` thiếu key `vi`, *When* render, *Then* fallback `en`; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: macOS XCTest localization; `xcodebuild test` 100% PASS; `swiftlint --strict`.

#### US-129 — Android i18n: `values-vi/strings.xml` + Locale Mechanism

- **Epic**: `EP-23` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Android`
- **Dependencies**: `US-119` (tab structure).
- **Trace**: `UUI-18`, `UUI-20`, `UUI-21`, `UUI-22`
- **Story**: Là *người dùng Android nói tiếng Việt (`P5-AND`)*, tôi muốn toàn bộ Canonical Glossary §4.1 khả dụng bằng tiếng Việt qua `values-vi/strings.xml` và runtime locale switch không cần kill/restart app.
- **AC**:
  1. **[H]** *Given* Mesh VPN Android với locale `vi`, *When* render `StatusScreen`, `SettingsScreen`, `OnboardingScreen`, *Then* tất cả `@string/` resources dùng `values-vi/strings.xml`; mọi nhãn từ Canonical Glossary §4.1 hiển thị tiếng Việt. `adb shell setprop persist.sys.locale vi-VN` → restart → toàn bộ strings tiếng Việt.
  2. **[H]** *Given* user chọn `Tiếng Việt` trong Settings 3-way selector, *When* locale switch mechanism trigger (`*(KN)*` Gate 2 — `MainActivity` extends `FragmentActivity` không phải `AppCompatActivity`; không có `androidx.appcompat` trong project; không thể dùng `AppCompatDelegate.setApplicationLocales()`; phương án: API 33+ `LocaleManager`, API 26-32 `CompositionLocalProvider` hoặc manual `Resources.updateConfiguration()` — Gate 2 chốt), *Then* strings thay đổi không cần kill app; không restart daemon; `MeshSessionRepository` không bị reinitialize.
  3. **[S]** `FfiErrorMapper` ánh xạ `Unauthenticated` vẫn trả `"authentication failed"` không localize. `logcat` log tiếng Anh không đổi. `FLAG_SECURE` vẫn áp dụng đúng scope.
  4. **[T]** `OnboardingComposeUiTest.kt` PASS 100%; `testTag` hiện có không thay đổi; test chạy với locale `en` để bảo toàn `"Verify Control Server Identity"` text assertion (`OnboardingComposeUiTest.kt:68-78` assert trực tiếp UI text — nếu locale=vi thì string display đổi, test FAIL); thêm separate parameterized test cho vi locale display (không xóa test hiện tại).
  5. **[E]** *Given* `MainActivity` extends `FragmentActivity` (không có `AppCompatDelegate`), *When* locale switch API 33+, *Then* dùng `LocaleManager.setApplicationLocales()` nếu available; API < 33 fallback `*(KN)*`.
  6. **[F]** *Given* `values-vi/strings.xml` thiếu resource, *When* render với locale `vi`, *Then* Android fallback `values/strings.xml` (en); không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: `./gradlew testDebugUnitTest`; `OnboardingComposeUiTest` PASS (locale=en); SEC-05 invariant test.

#### US-130 — iOS i18n: `Localizable.xcstrings` Full Glossary (~60+ keys)

- **Epic**: `EP-23` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `iOS`
- **Dependencies**: `US-119` (tab structure).
- **Trace**: `UUI-19`, `UUI-20`, `UUI-21`, `UUI-22`
- **Story**: Là *người dùng iPhone nói tiếng Việt (`P5-IOS`)*, tôi muốn `MeshApp` iOS có toàn bộ Canonical Glossary §4.1 (60+ keys) trong `Localizable.xcstrings` (mở rộng từ **13 keys** `vi` hiện có — `Localizable.xcstrings:4-134`), để UI hiển thị tiếng Việt hoàn chỉnh khi switch locale.
- **AC**:
  1. **[H]** *Given* `MeshApp` iOS với locale `vi` (iOS Settings → Language), *When* render `DashboardView`, `OnboardingView`, Settings tab, *Then* tất cả chuỗi từ Canonical Glossary §4.1 hiển thị tiếng Việt; không còn hardcoded English string trong render path; đặc biệt: `state.connected = "Đã kết nối"` (iOS `Localizable.xcstrings:29` hiện có, giữ nguyên key).
  2. **[H]** *Given* user chọn `Tiếng Việt` trong Settings 3-way selector (`*(KN)*`: override `Bundle` hoặc `.environment(\.locale, selectedLocale)` injection — `String(localized:)` không tự live-switch khi `Locale.current` không đổi), *When* locale switch, *Then* chuỗi đổi ngay; không restart daemon.
  3. **[E]** *Given* xcstrings key chưa có translation `vi`, *When* render với locale `vi`, *Then* fallback `en`; không crash; không hiển thị key raw.
  4. **[S]** `confirmationDialog` reset destructive (`DashboardView.swift:88-99`) vẫn hiển thị tiếng Anh nếu locale `en`; wire error `"authentication failed"` không localize; Keychain ACL không thay đổi.
  5. **[T]** `TunnelLifecycleAndAppViewModelTests.swift` PASS; `UniFFIBindingsAndSecurityTests.swift` PASS; `xcodebuild test` 21/21 PASS.
  6. **[F]** *Given* locale `vi` nhưng key chưa translated, *When* render, *Then* fallback `en`; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: iOS `xcodebuild test` 21/21 PASS; `swiftlint --strict` PASS.

#### US-131 — 3-Way Locale Selector trong Settings (System / Tiếng Việt / English) — All Platforms

- **Epic**: `EP-23` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Windows, macOS, Android, iOS`
- **Dependencies**: `US-127` (Win), `US-128` (macOS), `US-129` (Android), `US-130` (iOS).
- **Trace**: `UUI-20`, `UUI-21`, `UUI-22`
- **Story**: Là *người dùng bất kỳ nền tảng (`P1-WIN`, `P1-MAC`, `P5-AND`, `P5-IOS`, `P4-DGUI`)*, tôi muốn 3-way locale selector `System / Tiếng Việt / English` trong màn `Diagnostics & Settings` (Desktop) / tab `Settings` (Mobile), để kiểm soát ngôn ngữ giao diện độc lập với ngôn ngữ hệ thống.
- **AC**:
  1. **[H]** *Given* user mở Settings trên bất kỳ nền tảng nào, *When* thấy locale selector, *Then* 3 tùy chọn: `System` (theo OS locale), `Tiếng Việt`, `English`; selector hiển thị tùy chọn hiện tại; selection persisted per-app (không sync daemon).
  2. **[H]** *Given* user chọn `Tiếng Việt`, *When* selector apply, *Then* toàn bộ UI strings đổi ngay lập tức không cần restart daemon; daemon wire protocol không bị ảnh hưởng.
  3. **[H]** *Given* user chọn `System`, *When* OS locale là `en-US`, *Then* hiển thị tiếng Anh; nếu OS locale là `vi-VN`, hiển thị tiếng Việt.
  4. **[S]** *Given* locale bất kỳ, *When* daemon trả `"authentication failed"`, *Then* wire string giữ nguyên `"authentication failed"` (`SEC-05`). JSON logs `OPS-01` luôn tiếng Anh (`UUI-22`).
  5. **[E]** *Given* OS locale không phải `vi` hay `en` (e.g. `fr-FR`), *When* `System` selected, *Then* fallback `en` (default supported locale).
  6. **[E]** *Given* locale mechanism Android `*(KN)*` Gate 2, *When* implementation pending, *Then* locale selector UI hiển thị và persists selection; actual string switch mechanism là Gate 2 deliverable; fallback: `adb setprop persist.sys.locale vi-VN` + restart.
  7. **[T]** Trên mỗi nền tảng: unit test assert locale switch không restart daemon; assert `"authentication failed"` invariant; `testTag("locale_selector")` thêm vào Android Settings screen (new, không conflict existing tags).
  8. **[F]** *Given* locale preference store lỗi, *When* khởi động, *Then* fallback `System`; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Platform-specific unit tests; `SEC-05` / `OPS-01` invariant tests; locale persistence test.
  - **Máy thật**: Manual locale switch on each platform.

---

### 4.4. EP-24 — Cross-Platform Quality, Accessibility & Regression Safety

> **Mục tiêu**: Đảm bảo tất cả UI stories không phá vỡ test infrastructure hiện có; bổ sung accessibility Windows (Tab traversal, High-contrast, MSAA/UIA); GDI leak gate; Notification badge semantic color; tablet/iPad layout (Could). Kiểm tra chéo 100% `UUI-*` truy vết.

#### US-132 — Canonical State Label Glossary — All Platforms + TunnelSubState Display Logic

- **Epic**: `EP-24` · **SP**: `2` · **MoSCoW**: `Must` · **Platform**: `Windows, macOS, Android, iOS`
- **Dependencies**: `US-127` (Win string table), `US-128` (macOS i18n), `US-129` (Android i18n), `US-130` (iOS i18n).
- **Trace**: `UUI-33`
- **Story**: Là *người dùng bất kỳ nền tảng (`P1-WIN`, `P1-MAC`, `P5-AND`, `P5-IOS`)*, tôi muốn state labels đồng nhất trên 4 platforms theo §1.1 requirements: Windows state #5 hiển thị `"Connected"` (không phải `"Enrolled"`), và khi `TunnelSubState::Disconnected` hiển thị `"Disconnected"` (không phải `"Connected"`), Android không còn raw enum print, để không nhầm lẫn trạng thái kết nối.
- **AC**:
  1. **[H]** *Given* `DesktopUiState::Connected` với `TunnelSubState::Connected`, *When* `derive_desktop_ui_state()` `app.rs:195` xử lý, *Then* headline label = `"Connected to Mesh Network"` (EN) / `"Đã kết nối mạng Mesh"` (VI) — không còn `"Enrolled"`.
  2. **[H]** *Given* `DesktopUiState::Connected` với `TunnelSubState::Disconnected` (`app.rs:281-287`), *When* tray tooltip và status header render, *Then* label hiển thị `"Disconnected (Enrolled — Ready to Reconnect)"` (không phải `"Status: Connected"`); `display_label(sub_state)` phân biệt sub-state.
  3. **[H]** *Given* state table §1.1 requirements, *When* tất cả 8 desktop states render trên Windows và macOS, *Then* labels đồng nhất canonical: state #6 `ReauthRequired` = `"Re-auth Required"` / `"Yêu cầu xác thực lại"` (macOS hiện dùng `"Key Rotation Required"` trong displayTitle — phải đồng bộ); state #1 `AgentUnavailable` = `"Agent Unavailable"` (macOS hiện dùng `"Service Not Installed"` — phải unify).
  4. **[H]** *Given* Android `StatusScreen.kt:118` hiện print raw `"State: ${session.daemonState.name}"` vào `testTag("daemon_state_label")`, *When* refactoring, *Then* thay bằng canonical display label từ `values-vi/strings.xml` hoặc `values/strings.xml`; `testTag("daemon_state_label")` vẫn tồn tại.
  5. **[E]** *Given* `TunnelSubState::Degraded` trên Windows, *When* render, *Then* `"Connected (Degraded: Control Stream Offline)"` — không phải `"Connected to Mesh Network"`.
  6. **[T]** Windows unit test `derive_desktop_ui_state()` updated: assert state #5 + sub-state variations; assert state #6 = "Re-auth Required"; `scripts/run-desktop-qa.ps1` 23/23 PASS. macOS `DesktopStoreTests` state label tests không bị ảnh hưởng. Android unit test assert canonical display label (không raw enum).
  7. **[F]** *Given* string table thiếu key `state.connected`, *When* render, *Then* fallback `"Connected"` EN.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Windows/macOS/Android/iOS state label unit tests; sub-state display logic test.

#### US-133 — Security Invariants Preservation Regression Suite

- **Epic**: `EP-24` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Windows, macOS, Android, iOS`
- **Dependencies**: `US-118..US-131`.
- **Trace**: `UUI-34`
- **Story**: Là *kỹ sư bảo mật (`P1-WIN`)*, tôi muốn toàn bộ bất biến bảo mật §1.6 (SEC-01, SEC-04, SEC-05, FLAG_SECURE scope-limited, Biometric, MGH1, clipboard 30s wipe cho secrets, 13-field AgentStatusResponse) được kiểm tra tự động sau mỗi UI story, để UI refactoring không vô tình vi phạm bất biến bảo mật.
- **AC**:
  1. **[H]** *Given* toàn bộ UI changes từ `US-118..US-131`, *When* chạy bộ security regression tests, *Then*: `test_no_secrets_in_outputs` (Windows+macOS+Android+iOS) `0` leak; `ClipboardSecretGuard` 30s wipe timer test PASS (Windows — chỉ cho `mpk_*` path, **không** cho IP/FQDN path); `BiometricAuthorizer.swift` iOS test PASS; `FLAG_SECURE` Android test PASS (scope: Onboarding/pin reveal/confirmation, NOT Peers tab); `MeshSecretScrubber.scrub()` macOS test PASS.
  2. **[S]** *Given* 13 trường `AgentStatusResponse` trong `crates/mesh-proto/src/agent_ipc.rs`, *When* UI code read status, *Then* tất cả 13 fields được parse đúng qua IPC; `diagnostics_view.rs:14` không break; macOS IPC không break; Mobile `MobileStatusSnapshot` via FFI không break.
  3. **[S]** *Given* Wire error path, *When* `ErrorKind::Unauthenticated` trên bất kỳ nền tảng nào, *Then* user-facing string = `"authentication failed"` invariant (SEC-05) — unit test trên 4 platforms.
  4. **[S]** *Given* MGH1 handoff `build_handoff_payload()` Windows (`onboarding.rs:88-106`), *When* Onboarding flow trigger elevation, *Then* không lộ `mpk_*` qua argv; `D-GNFR-02` test PASS.
  5. **[E]** *Given* Copy IP/FQDN action trigger, *When* security audit, *Then* `ClipboardSecretGuard` timer **không** được khởi động (verify unit test assert guard NOT active after IP copy); `FLAG_SECURE` **không** được set (verify Android unit test).
  6. **[T]** `DesktopStoreTests` PASS; `DesktopCoreTests` PASS; `MeshVPNTests` iOS PASS; `OnboardingComposeUiTest` Android PASS; Windows 23/23 unit tests PASS.
  7. **[F]** *Given* security test failure on any platform, *When* CI runs, *Then* build fail với clear error message identifying which invariant violated; không skip security tests.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Toàn bộ test suites trên 4 platforms xanh; clipboard security audit test.

#### US-134 — Existing Test Suite Regression Safety (All Platforms)

- **Epic**: `EP-24` · **SP**: `3` · **MoSCoW**: `Must` · **Platform**: `Windows, macOS, Android, iOS`
- **Dependencies**: `US-118..US-131`.
- **Trace**: `UUI-37`
- **Story**: Là *kỹ sư QA (`P4-DGUI`)*, tôi muốn chạy `scripts/check.ps1`, `scripts/check.sh`, `./gradlew test`, `xcodebuild test` sau mọi UI story và xác nhận `0` regression, để đảm bảo Milestone `v0.4.0` không phá vỡ nền tảng CI `v0.3.0` / `v0.2.0`.
- **AC**:
  1. **[H]** `scripts/check.ps1 -Cross` exit `0`; `cargo fmt --all -- --check` PASS; `cargo clippy --workspace --all-targets --all-features -- -D warnings` PASS; `cargo test --workspace --all-features` PASS; `cargo deny check advisories bans licenses sources` PASS.
  2. **[T]** macOS: `swiftlint --strict` PASS; `xcodebuild test` (macOS XCTest) PASS; `DesktopStoreTests` + `DesktopCoreTests` PASS.
  3. **[T]** Android: `./gradlew ktlintCheck detekt lintDebug testDebugUnitTest` PASS; `OnboardingComposeUiTest.kt` PASS (locale=en); `testTag("daemon_state_label")`, `testTag("toggle_tunnel_button")`, `testTag("error_card")`, `testTag("warning_lockdown")`, `testTag("warning_private_dns")` tồn tại và PASS.
  4. **[T]** iOS: `xcodebuild test CODE_SIGNING_ALLOWED=NO` 21/21 XCTest PASS; `swiftlint --strict` PASS; `TunnelLifecycleAndAppViewModelTests`, `UniFFIBindingsAndSecurityTests` PASS.
  5. **[E]** *Given* `linux_gui.rs` compatibility requirement, *When* `scripts/check.ps1 -Cross` target `x86_64-unknown-linux-musl`, *Then* compile thành công; `0` clippy warnings.
  6. **[N]** `MeshVPN.exe` release binary `<= 6 MiB` PE Subsystem `2`; `libmesh_mobile_ffi.so <= 6 MiB`.
  7. **[F]** *Given* any test failure, *When* CI pipeline runs, *Then* fail fast với clear error; không continue với broken tests.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Full CI pipeline tất cả jobs PASS.

#### US-135 — Windows Keyboard Tab Traversal & High-Contrast Mode

- **Epic**: `EP-24` · **SP**: `5` · **MoSCoW**: `Must` · **Platform**: `Windows`
- **Dependencies**: `US-122`, `US-123`.
- **Trace**: `UUI-28`, `UUI-29`
- **Story**: Là *người dùng Windows sử dụng bàn phím hoặc hỗ trợ tiếp cận (`P4-DGUI`)*, tôi muốn `MeshVPN.exe` cho phép điều hướng toàn bộ controls bằng Tab key và hiển thị đúng trong high-contrast mode.
- **AC**:
  1. **[H]** *Given* focus trên bất kỳ control nào, *When* nhấn `Tab`, *Then* focus chuyển theo thứ tự: Status Hero → Tab Bar → Active Tab Content → Onboarding fields (nếu visible); `WS_TABSTOP` được set trên mọi interactive control; `WM_GETDLGCODE` returns `DLGC_WANTTAB` cho custom controls (tab bar, rounded cards).
  2. **[H]** *Given* keyboard focus trên Tab Bar, *When* nhấn `←`/`→` arrow keys, *Then* selection moves giữa tabs; `Enter` activates focused tab.
  3. **[A]** *Given* high-contrast mode active (`SystemParametersInfoW(SPI_GETHIGHCONTRAST)`), *When* repaint, *Then* fallback sang system colors; text luôn readable; không hide bất kỳ element nào behind design token colors.
  4. **[E]** *Given* single-monitor setup, no DPI change, *When* Tab traversal, *Then* focus order consistent; không bị skip control.
  5. **[N]** Tab key không focus vào non-interactive elements (labels, decorative icons).
  6. **[F]** *Given* focus lost (click outside window), *When* click window lại, *Then* focus restore đúng control; không reset về Tab bar.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test `WM_GETDLGCODE` returns `DLGC_WANTTAB`; tab order logic test.
  - **Máy thật**: Manual keyboard Tab traversal; high-contrast mode visual; Narrator screen reader verify.

#### US-136 — Windows GDI Handle Leak Gate Test

- **Epic**: `EP-24` · **SP**: `3` · **MoSCoW**: `Should` · **Platform**: `Windows`
- **Dependencies**: `US-123`.
- **Trace**: `UUI-31`
- **Story**: Là *kỹ sư QA Windows (`P1-WIN`)*, tôi muốn automated gate test xác nhận `0` GDI handle leak sau window create/destroy cycle, để bảo đảm `OwnedGdiObj` RAII đúng và `ADR-020` không bị vi phạm.
- **AC**:
  1. **[H]** *Given* test `test_gdi_handle_lifecycle`, *When* tạo window với tất cả custom-drawn elements (rounded cards, pills, tab bar) → hiển thị → đóng → mở lại, *Then* `GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS)` before và after **delta == 0**.
  2. **[H]** *Given* 100 lần create+destroy cycles, *When* chạy, *Then* delta vẫn == 0; không leak accumulate.
  3. **[E]** *Given* `PaintGuard` (wraps `BeginPaint`/`EndPaint`) vs `OwnedMemDc` (wraps `CreateCompatibleDC`/`DeleteDC`) vs `OwnedGdiObj` (wraps `DeleteObject`), *When* window lifecycle, *Then* mỗi loại wrapper drop đúng API; không có cross-call (`DeleteObject` trên `BeginPaint` HDC hoặc ngược lại).
  4. **[N]** Alert trong log nếu count > 5,000 (Windows limit 10,000); gate criterion: delta == 0.
  5. **[F]** *Given* `GetGuiResources` returns error, *When* test runs, *Then* test fails with clear diagnostic; không silently pass.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test `test_gdi_handle_lifecycle` trong `mesh-gui` test suite; `scripts/run-desktop-qa.ps1` PASS.

#### US-137 — Notification Badge/Status Semantic Color Mapping (Android & iOS)

- **Epic**: `EP-24` · **SP**: `3` · **MoSCoW**: `Should` · **Platform**: `Android, iOS`
- **Dependencies**: `US-124` (tokens), `US-119` (tab).
- **Trace**: `UUI-36`
- **Story**: Là *người dùng Mobile (`P5-AND`, `P5-IOS`)*, tôi muốn notification badge Android và Status badge iOS sử dụng đúng màu semantic (§2.4) theo trạng thái kết nối, để nhận biết trạng thái VPN từ notification/status area mà không cần mở app.
- **AC**:
  1. **[H]** *Given* Android `MobileDaemonState::CONNECTED`, *When* notification renders (`MeshVpnService.kt` `NotificationCompat.Builder`), *Then* `NotificationCompat.Builder.setColor()` dùng `semantic.success` color (`#16A34A` Light). `DEGRADED` → Amber `#D97706`; `REVOKED`/`REAUTH_REQUIRED` → Red `#DC2626`; `STOPPED` → Gray `#6B7280`. **Không** có persistent VPN notification với color trên iOS (iOS chỉ hiển thị system `[VPN]` badge từ NetworkExtension).
  2. **[H]** *Given* iOS, *When* `StatusBadge` composable trong `DashboardView.swift:339-360` render, *Then* badge sử dụng semantic colors từ Design Token §2.4 theo connection state; không phải notification bar color (iOS không support custom VPN notification color).
  3. **[E]** *Given* state transition trong render cycle, *When* `MobileDaemonState` changes từ `CONNECTED` → `DEGRADED`, *Then* notification color updates kịp thời; không render stale color.
  4. **[T]** Android: unit test state → `NotificationCompat.Builder.setColor()` color mapping; `testTag("status_notification_icon")` trong `StatusScreen` test. iOS: `StatusBadge` `DashboardView.swift:339-360` visual test via SwiftUI previews; `xcodebuild test` PASS.
  5. **[F]** *Given* state unknown or null, *When* render, *Then* Gray neutral fallback; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Android ViewModel unit test state→color mapping; iOS XCTest `StatusBadge`.

#### US-138 — Tablet/iPad Adaptive Layout: 2-Column Peers Zone

- **Epic**: `EP-24` · **SP**: `3` · **MoSCoW**: `Could` · **Platform**: `Android, iOS`
- **Dependencies**: `US-120` (Peers Zone).
- **Trace**: `UUI-38`
- **Story**: Là *người dùng tablet Android hoặc iPad (`P5-AND`, `P5-IOS`)*, tôi muốn Peers list hiển thị 2-column grid khi landscape trên màn hình rộng, để tận dụng không gian màn hình lớn và xem được nhiều peer hơn cùng lúc.
- **AC**:
  1. **[H]** *Given* thiết bị tablet/iPad với màn hình rộng (≥ 600 dp Android / iPad landscape iOS), *When* Peers tab active, *Then* `LazyVerticalGrid` (Android, `*(KN)*`) hoặc `LazyVGrid` (iOS, `*(KN)*`) 2-column render thay cho list 1-column.
  2. **[H]** *Given* orientation change portrait → landscape trên tablet, *When* layout changes, *Then* adaptive: 1-column portrait, 2-column landscape; không crash.
  3. **[E]** *Given* rotation mid-load (data đang fetch khi orientation changes), *When* layout recompose, *Then* không crash, không data loss; existing peers displayed correctly after rotation.
  4. **[T]** Không break existing Peers tests (search, filter, copy IP); `testTag` không thay đổi.
  5. **[F]** *Given* thiết bị phone (screen width < 600 dp), *When* render, *Then* 1-column layout như bình thường; không apply 2-column.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test breakpoint logic (600 dp threshold); Android `testDebugUnitTest`; iOS `xcodebuild test`.
  - **Máy thật (`hardware_signoff_required`)**: Visual trên tablet Android và iPad.

#### US-139 — Windows MSAA/UIA Screen Reader Accessibility Names

- **Epic**: `EP-24` · **SP**: `3` · **MoSCoW**: `Could` · **Platform**: `Windows`
- **Dependencies**: `US-122` (custom GDI controls), `US-135` (Tab traversal).
- **Trace**: `UUI-30`
- **Story**: Là *người dùng Windows sử dụng Narrator hoặc screen reader (`P4-DGUI`)*, tôi muốn `MeshVPN.exe` cung cấp MSAA/UIA accessibility names cho status badge, peer list items và action buttons, để Narrator đọc đúng thông tin trạng thái VPN.
- **AC**:
  1. **[H]** *Given* Narrator đang active và `MeshVPN.exe` đang chạy, *When* screen reader focus di chuyển tới Status Hero badge, *Then* Narrator announces state label (e.g. "Connected to Mesh Network" hay locale equivalent); không đọc control class name raw.
  2. **[H]** *Given* Narrator focus trên Peers list, *When* di chuyển qua các peer items, *Then* Narrator announces peer name, Overlay IP, path badge (Direct/Relay), RTT; không silent.
  3. **[H]** *Given* Narrator focus trên action buttons (Connect, Disconnect, Copy IP, Ping), *When* focus, *Then* Narrator announces button label tiếng Anh hoặc tiếng Việt tùy locale.
  4. **[E]** *Given* empty peers list, *When* Narrator focus on peers area, *Then* announces "No peers visible yet" (en) / "Chưa có thiết bị nào" (vi).
  5. **[N]** MSAA/UIA provider implementation method `*(KN)*` Gate 2 (IAccessible vs UIA Element Provider); Gate 1 chỉ yêu cầu specification và AC.
  6. **[F]** *Given* UIA/MSAA provider init fails, *When* window create, *Then* fallback graceful — UI functional mặc dù không có accessibility names; không crash.
- **Phân tách kiểm chứng**:
  - **CI (`$0`)**: Unit test MSAA name exists for status badge and primary controls; `cargo clippy` xanh.
  - **Máy thật**: Manual Narrator test; Inspect.exe verify UIA properties.

---

## 5. Bảng Truy vết 100% `UUI-01..UUI-38` ↔ `US-*`

| Mã UUI | Priority | Platforms | Story Coverage | MoSCoW |
|---|---|---|---|---|
| **UUI-01** | P0 | W, M | US-118 | Must |
| **UUI-02** | P0 | A, I | US-119 | Must |
| **UUI-03** | P0 | W, M, A, I | US-118, US-119 | Must |
| **UUI-04** | P0 | W, A, I | US-120 _(macOS bổ sung `nodeId` search & count badge trong US-120)_ | Must |
| **UUI-05** | P0 | W, A, I | US-120 _(macOS bổ sung count badge; W/A/I implement 4-state filter)_ | Must |
| **UUI-06** | P1 | W, A, I | US-121 _(macOS đã có `copyToPasteboard()` — simple copy, no wipe)_ | Must |
| **UUI-07** | P1 | A, I | US-121 | Must |
| **UUI-08** | P0 | W | US-122 | Must |
| **UUI-09** | P0 | W | US-122 | Must |
| **UUI-10** | P0 | M | US-124 | Must |
| **UUI-11** | P0 | A | US-124 _(3-way Theme Selector for Android)_ | Must |
| **UUI-12** | P0 | I | US-124 | Must |
| **UUI-13** | P1 | W | US-123 | Must |
| **UUI-14** | P1 | W | US-123 _(double-buffering memory DC — `*(KN)*` WS_EX_COMPOSITED conflict)_ | Must |
| **UUI-15** | P1 | W, M | US-124, US-126 | Should |
| **UUI-16** | P0 | W | US-127 | Must |
| **UUI-17** | P0 | M | US-128 | Must |
| **UUI-18** | P0 | A | US-129 | Must |
| **UUI-19** | P0 | I | US-130 | Must |
| **UUI-20** | P0 | W, M, A, I | US-131 | Must |
| **UUI-21** | P0 | W, M, A, I | US-127, US-128, US-129, US-130, US-131 | Must |
| **UUI-22** | P0 | W, M, A, I | US-127, US-128, US-129, US-130, US-131 | Must |
| **UUI-23** | P0 | W | US-122 | Must |
| **UUI-24** | P0 | W | US-122 | Must |
| **UUI-25** | P0 | W | US-122 | Must |
| **UUI-26** | P0 | W | US-123 | Must |
| **UUI-27** | P1 | W | US-125 | Should |
| **UUI-28** | P1 | W | US-135 | Must |
| **UUI-29** | P1 | W | US-135 | Must |
| **UUI-30** | P2 | W | US-139 _(MSAA/UIA — story tách biệt `Could`)_ | Could |
| **UUI-31** | P1 | W | US-123, US-136 | Should |
| **UUI-32** | P0 | W | US-122, US-123 | Must |
| **UUI-33** | P0 | W, M, A, I | US-118, US-119, US-132 | Must |
| **UUI-34** | P0 | W, M, A, I | US-133 | Must |
| **UUI-35** | P1 | W, M | US-126, US-127, US-128 | Should |
| **UUI-36** | P1 | A, I | US-137 | Should |
| **UUI-37** | P1 | W, M, A, I | US-134 | Must |
| **UUI-38** | P2 | A, I | US-138 | Could |

> **Kiểm toán truy vết**: 38/38 `UUI-*` được phủ. Tất cả `24 P0` được phủ bởi story `Must`. `12 P1` được phủ bởi story `Must` hoặc `Should`. `2 P2` được phủ bởi story `Could`.

> [!NOTE]
> `UUI-14` (double-buffering) covered bởi `US-123` (DPI/RAII) với constraint `*(KN)*` Gate 2 cho `WS_EX_COMPOSITED` conflict với `EDIT`/`LISTBOX` child controls. `UUI-30` (MSAA/UIA P2) có story riêng `US-139` (`Could`, 3 SP) thay vì merge vào `US-132`. `UUI-35` covered bởi `US-126` (Tray icon color + bilingual labels), `US-127` (Windows string table + Tray), `US-128` (macOS Menu Bar bilingual).

---

## 6. Priority Matrix & Sprint Planning Guidance

### 6.1 MoSCoW Priority Summary

| MoSCoW | Story Count | Total SP | Stories |
|---|---|---|---|
| **Must** | 16 | 75 | US-118, US-119, US-120, US-121, US-122, US-123, US-124, US-127, US-128, US-129, US-130, US-131, US-132, US-133, US-134, US-135 |
| **Should** | 4 | 12 | US-125 (3 SP), US-126 (3 SP), US-136 (3 SP), US-137 (3 SP) |
| **Could** | 2 | 6 | US-138 (3 SP — Tablet/iPad), US-139 (3 SP — MSAA/UIA) |
| **Total** | **22** | **93** | US-118..US-139 |

> **Kiểm toán MoSCoW:**
> - Must: US-118(8)+US-119(5)+US-120(5)+US-121(3)+US-122(8)+US-123(3)+US-124(5)+US-127(5)+US-128(5)+US-129(5)+US-130(3)+US-131(5)+US-132(2)+US-133(5)+US-134(3)+US-135(5) = **75 SP** ✓ (16 stories)
> - Should: US-125(3)+US-126(3)+US-136(3)+US-137(3) = **12 SP** ✓ (4 stories)
> - Could: US-138(3)+US-139(3) = **6 SP** ✓ (2 stories)
> - **Total: 22 stories, 93 SP** ✓
> - Mọi `24 P0` `UUI-*` được phủ bởi story `Must`. ✓

### 6.2 Platform Wave Proposal (`*(KN)*` — Gate 2 chốt)

| Wave | Stories | Focus | Platforms | Notes |
|---|---|---|---|---|
| **Wave A — Navigation Structure** | US-118, US-119 | 3-tab structure all platforms; Rotate Key/Update Server → Zone 3 | W, M, A, I | Prerequisite: `feat/desktop-gui` working tree clean |
| **Wave B — Peers & Design** | US-120, US-121, US-122, US-123, US-124, US-126 | Peers zone + Design system + Windows GDI | W, M, A, I | US-126 depends on US-124 |
| **Wave C — i18n** | US-127, US-128, US-129, US-130, US-131, US-125 | Full bilingual; US-125 `WM_SETTINGCHANGE` depends on US-122 | W, M, A, I | US-125 requires US-122 (Wave B) |
| **Wave D — Cross-Platform Quality** | US-132, US-135, US-136, US-137, US-138, US-139 | State label unification + Accessibility; US-132 depends on Wave C i18n | W, M, A, I | US-132 depends on US-127+ |
| **Wave E — Regression Gates** | US-133, US-134 | Security + test regression suites; depend on all above | W, M, A, I | Run after all feature stories |

### 6.3 Dependency Graph

```
US-118 (Win 3-tab + Zone 3 CTAs) ──┐
US-119 (Mob 3-tab + SPKI lock) ─────┼─→ US-120 (Peers Search+Filter+NodeId+Badge) ──→ US-121 (Copy IP — simple)
                                     │
US-122 (Win GDI Modern) ────────────┼─→ US-123 (DPI/RAII leak gate)
                                     │      ├─→ US-125 (WM_SETTINGCHANGE) [Should]
                                     │      └─→ US-136 (GDI Leak Gate Test) [Should]
                                     │
US-124 (macOS/And/iOS tokens+3-way) ─┴─→ US-126 (Tray icons + UUI-35 bilingual) [Should]
                                     │
US-127 (Win i18n + Tray vi) ────────┐
US-128 (macOS i18n + Menu Bar vi) ──┤
US-129 (Android i18n + locale KN) ──┼─→ US-131 (3-way locale selector)
US-130 (iOS xcstrings 60+ keys) ────┘
                                     │
                                     └─→ US-132 (Canonical state labels — W/M/A/I + TunnelSubState)
                                              └─→ US-133 (Security regression)
                                                       └─→ US-134 (Test suite regression)

US-122 + US-135 (Tab traversal + High-contrast) ──→ US-139 (MSAA/UIA) [Could]
US-120 ──→ US-138 (Tablet 2-col) [Could]
US-124 + US-119 ──→ US-137 (Notification badge colors) [Should]
US-123 ──→ US-136 (GDI Leak Gate Test) [Should]
```

---

## Appendix A — Truy vết ngược từ Story về Design Decision

| Story | DEC-UI | ADR | SEC/GNFR |
|---|---|---|---|
| US-118, US-119 | DEC-UI-01 | ADR-020, ADR-025 | SEC-14, UUI-GNFR-03 |
| US-120, US-121 | DEC-UI-01 | ADR-020, ADR-025 | SEC-01 (clipboard wipe scope-limited), D-GNFR-02 |
| US-122, US-123 | DEC-UI-02 | ADR-020 | D-GNFR-03, D-GNFR-04 |
| US-124, US-125, US-126 | DEC-UI-03 | ADR-020, ADR-025 | UUI-GNFR-01 |
| US-127..US-131 | DEC-UI-04 | — | SEC-05, OPS-01, UUI-GNFR-04 |
| US-132 | DEC-UI-01, DEC-UI-04 | ADR-020 | UUI-GNFR-03 |
| US-133 | — | ADR-020, ADR-025 | SEC-01/04/05, UUI-GNFR-02 |
| US-134 | — | — | UUI-GNFR-03 |
| US-135 | DEC-UI-02 | ADR-020 | UUI-GNFR-01 (Accessibility) |
| US-136 | DEC-UI-02 | ADR-020 | D-GNFR-04 |
| US-137 | DEC-UI-03 | — | UUI-GNFR-02 |
| US-138 | DEC-UI-01 | — | UUI-GNFR-03 |
| US-139 | DEC-UI-02 | ADR-020 | UUI-GNFR-01 (Accessibility/MSAA) |
