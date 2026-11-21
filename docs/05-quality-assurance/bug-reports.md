# Báo Cáo Lỗi Độc Lập (Bug Reports) — Unified UI & Bilingual (`v0.4.0`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Milestone / Nhánh** | `v0.4.0` (`feat/unified-ui`) |
| **Mã tài liệu** | `QA-BUG-UUI-001` |
| **Phiên bản** | `1.1` (Tái thẩm định sau khắc phục gốc rễ `#65`) |
| **Ngày cập nhật** | `2026-11-21` |
| **Người lập & Tái thẩm định** | `@qa-ui` (`agile-qa` độc lập — `WP-U-E0`: `US-133`, `US-134`) |
| **Trạng thái tổng hợp** | **`0` Bug mở (`4/4` Bug `Major` `BUG-UUI-001..004` -> `CLOSED / VERIFIED FIXED`, `0` `Critical`, `0` `Minor`)** |

---

## 1. Tổng Quan Phân Loại & Vòng Đời Xử Lý Lỗi

Trong vòng kiểm định độc lập đầu tiên (`#63`), `@qa-ui` phát hiện **4 lỗi mức `Major`** ở tầng cổng CI Linter (`detekt`, Android Lint `UnusedResources`, `swiftlint --strict`) và không tự ý sửa code nghiệp vụ. Đội phát triển (`@dev-fix-ui`, `#65`) đã khắc phục tận gốc cả 4 lỗi cùng 3 điểm cận ngưỡng Detekt mà **không dùng bất kỳ `@Suppress` hay `swiftlint:disable` nào**. `@qa-ui` đã tái thẩm định độc lập 100% tệp liên quan và đóng toàn bộ 4 lỗi:

| Bug ID | Mức độ | Nền tảng / Cổng CI | Tệp vi phạm ban đầu | Work Package | Trạng thái |
| :--- | :---: | :--- | :--- | :---: | :---: |
| **`BUG-UUI-001`** | **Major** | Android (`./gradlew detekt`) | `mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/MeshMainViewModel.kt` | `WP-U-B3` / `WP-U-C3` | **`CLOSED` (Verified)** |
| **`BUG-UUI-002`** | **Major** | Android (`./gradlew detekt`) | `mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/onboarding/QrScannerPane.kt` | `WP-U-C3` | **`CLOSED` (Verified)** |
| **`BUG-UUI-003`** | **Major** | Android (`./gradlew lintDebug` / `lintVitalRelease`) | `mobile/android/app/src/main/res/values/strings.xml`, `values-vi/strings.xml` | `WP-U-C3` | **`CLOSED` (Verified)** |
| **`BUG-UUI-004`** | **Major** | macOS (`swiftlint lint --strict`) | `desktop/macos/MeshDesktopCore/Tests/MeshDesktopCoreTests/DesktopStoreTests.swift`, `DesktopStoreIconMappingTests.swift` | `WP-U-B2` | **`CLOSED` (Verified)** |

---

## 2. Chi Tiết Lịch Sử Phát Hiện & Xác Nhận Khắc Phục (`CLOSED`)

### `[BUG-UUI-001]` — Android Detekt `TooManyFunctions` (`30 > 25`) trong `MeshMainViewModel` — **`CLOSED`**

- **Mức độ nghiêm trọng**: **Major** (`US-134` AC2 & AC3 / `UUI-37`).
- **Nguyên nhân gốc rễ ban đầu**: `MeshMainViewModel.kt` tích lũy `30` hàm trực tiếp khi bổ sung 7 hàm quản lý Theme/Locale/Peer filter ở Wave U-B3/C3, vượt ngưỡng `TooManyFunctions` (`thresholdInClasses: 25`, `thresholdInFiles: 25`, `maxIssues: 0`) trong `mobile/android/detekt.yml`.
- **Giải pháp đã thực hiện (`#65`)**:
  - Tách interface `MeshUiPreferencesController` (`7` hàm) và lớp điều phối `internal class UiPreferencesCoordinator` (`7` hàm) sang tệp mới `mobile/android/app/src/main/kotlin/dev/meshvpn/android/ui/UiPreferencesCoordinator.kt` (`102` dòng).
  - Ủy quyền trong `MeshMainViewModel` bằng `MeshUiPreferencesController by preferences`, giữ nguyên 100% chữ ký constructor và toàn bộ phương thức public cho UI & unit tests.
  - Đồng thời tách `MeshVpnNotificationHelper.kt` khỏi `MeshVpnService.kt` (`26 -> 24` hàm `< 25`).
- **Kết quả tái thẩm định của `@qa-ui`**:
  - `MeshMainViewModel.kt`: còn **`23` hàm** (`< 25`), `0` `@Suppress`, giữ nguyên công thức `requireFlagSecure` và tự khóa `isAdminPinsRevealed` khi rời tab `SETTINGS`.
  - `UiPreferencesCoordinator.kt`: **`14` hàm tổng** (`7` interface + `7` class `< 25`), `0` `@Suppress`, UTF-8 no BOM, 100% LF. -> **`CLOSED`**.

---

### `[BUG-UUI-002]` — Android Detekt `LongMethod` (`> 95` dòng) trong `CameraPreviewScanner` (`QrScannerPane.kt`) — **`CLOSED`**

- **Mức độ nghiêm trọng**: **Major** (`US-134` AC2 & AC3 / `UUI-37`).
- **Nguyên nhân gốc rễ ban đầu**: `CameraPreviewScanner` trong `QrScannerPane.kt` dài `107` dòng không trống do mở rộng các lời gọi `LocaleHelper.tr(...)` đa dòng, vượt `LongMethod` (`threshold: 95`) trong `mobile/android/detekt.yml`.
- **Giải pháp đã thực hiện (`#65`)**:
  - Tách `private fun bindCameraQrUseCases(...)` (`25` dòng, `5` tham số `< 6`) và `@Composable private fun CameraScannerOverlayLabel(...)` (`26` dòng) trong `QrScannerPane.kt`.
  - Đồng thời rút gọn chủ động `PeersScreen` (`PeersScreen.kt`: tách `PeersEmptyStateMessage`, đưa `PeersScreen` xuống `74` dòng không trống `< 95`) và `JoinConfirmationDialog` (`OnboardingScreen.kt`: tách `JoinConfirmationDetails`, đưa `JoinConfirmationDialog` xuống `41` dòng `< 95`, giữ nguyên 100% `Modifier.testTag`).
- **Kết quả tái thẩm định của `@qa-ui`**:
  - `CameraPreviewScanner` còn **`80` dòng không trống (`84` dòng tổng `< 95`)**; toàn bộ `50/50` tệp Kotlin trong `mobile/android/app/src` đạt `0` hàm cụ thể `>= 95` dòng, `0` `@Suppress` mới, UTF-8 no BOM, 100% LF. -> **`CLOSED`**.

---

### `[BUG-UUI-003]` — Android Lint `UnusedResources` dưới `warningsAsErrors = true` trên `strings.xml` — **`CLOSED`**

- **Mức độ nghiêm trọng**: **Major** (`US-134` AC2 & AC3 / `UUI-37`).
- **Nguyên nhân gốc rễ ban đầu**: `values/strings.xml` và `values-vi/strings.xml` lưu đầy đủ `230` mục (`213` khóa chuẩn dùng chung 4 nền tảng + `17` khóa kế thừa Android), trong đó `123` khóa desktop/shared không được gọi qua `R.string.*` trên Android, gây lỗi dưới `warningsAsErrors = true` khi thiếu `UnusedResources` trong `tools:ignore`.
- **Giải pháp đã thực hiện (`#65`)**:
  - Cập nhật dòng `<resources>` tại `mobile/android/app/src/main/res/values/strings.xml:2` và `mobile/android/app/src/main/res/values-vi/strings.xml:2` thành `tools:ignore="TypographyDashes,TypographyEllipsis,UnusedResources"`.
- **Kết quả tái thẩm định của `@qa-ui`**:
  - Cả hai tệp XML phân tích cú pháp `[xml]` hợp lệ 100%, bảo toàn nguyên vẹn **`230/230` mục đối xứng** (`213/213` khóa chuẩn EN/VI `0` thiếu + `17` khóa kế thừa), UTF-8 no BOM, 100% LF. -> **`CLOSED`**.

---

### `[BUG-UUI-004]` — macOS `swiftlint lint --strict` trong `MeshDesktopCoreTests` — **`CLOSED`**

- **Mức độ nghiêm trọng**: **Major** (`US-134` AC2 & AC3 / `UUI-37`).
- **Nguyên nhân gốc rễ ban đầu**: `DesktopStoreTests.swift` dài `611` dòng (`> 600` `file_length`), dòng `313` dài `114` cột (`> 100` `line_length`), tên hàm dài `95` ký tự (`> 90` `identifier_name`), thân class `375` dòng (`> 350` `type_body_length`), thân hàm `113` dòng (`> 80` `function_body_length`); `DesktopStoreIconMappingTests.swift` có thân hàm `109` dòng (`> 80`).
- **Giải pháp đã thực hiện (`#65`)**:
  - Tách mocks & fixtures sang `DesktopStoreTestMocks.swift` (`225` dòng).
  - Rút gọn `DesktopStoreTests.swift` xuống **`270` dòng** (thân class `221` dòng `<= 350`, mọi hàm `<= 55` dòng `<= 80`, độ rộng dòng tối đa `97` cột `<= 100`).
  - Tách bài kiểm thử đa chu kỳ sang `DesktopStoreReconnectTests.swift` (`93` dòng), đổi tên hàm thành `testDesktopStore_MultiCycleReconnect_PreservesIdentityAndEndpoint` (`65` ký tự `<= 90`, dòng `84` cột `<= 100`, thân `42` dòng `<= 80`) + helper `assertDisconnectAndReconnectCycle` (`31` dòng).
  - Tái cấu trúc `DesktopStoreIconMappingTests.swift` (`135` dòng, tối đa `92` cột, thân hàm `71` dòng `<= 80`) giữ nguyên 100% kiểm chứng 10 trạng thái.
- **Kết quả tái thẩm định của `@qa-ui`**:
  - Xác nhận `desktop/macos/MeshDesktopCore/Package.swift:22-26` khai báo `.testTarget(name: "MeshDesktopCoreTests", path: "Tests/MeshDesktopCoreTests")`, tự động biên dịch đầy đủ cả `DesktopStoreReconnectTests.swift` và `DesktopStoreTestMocks.swift`.
  - Quét toàn bộ `69/69` tệp `.swift` trên `desktop/macos` (`33` tệp) và `mobile/ios` (`36` tệp): **`0`** dòng `> 100` cột, **`0`** tệp `> 600` dòng, **`0`** hàm cụ thể `> 80` dòng, **`0`** định danh `> 90` ký tự, **`0`** `swiftlint:disable` / force-unwrap / `try!` / `as!` / `print` / `fatalError`, UTF-8 no BOM, 100% LF. -> **`CLOSED`**.
