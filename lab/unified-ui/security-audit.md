# Báo Cáo Kiểm Toán Bảo Mật — Unified UI & Bilingual (`v0.4.0` · `US-133`)

| Trường thông tin | Chi tiết |
| :--- | :--- |
| **Tên dự án** | Mesh VPN — Self-Hosted Secure Mesh Overlay Network |
| **Milestone / Nhánh** | `v0.4.0` (`feat/unified-ui`, Wave U-A..U-E + Gate 3 Remediation) |
| **Work Package / Story** | `WP-U-E0` — `US-133` (`UUI-34`: Security Invariants Preservation Audit) |
| **Mã tài liệu** | `LAB-UUI-SEC-001` |
| **Ngày kiểm toán** | `2026-11-21` |
| **Người thực hiện** | `@qa-ui` (`agile-qa` độc lập) & `@coordinator` (host re-verification sau Gate 3 Round 1) |
| **Kết quả kiểm toán `US-133`** | **PASS 100% (`9/9` bài kiểm thử bắt buộc trong `security_regression_unified_ui` [`17/17` tests total] + `12/12` `qa_desktop_security_audit` + `16/16` `audit-mobile-security.ps1`, `0` rò rỉ bí mật, `0` sai lệch hợp đồng IPC)** |

---

## 1. Phạm Vi & Phương Pháp Kiểm Toán Độc Lập

Kiểm toán này xác minh độc lập rằng toàn bộ thay đổi kiến trúc giao diện và song ngữ trực tiếp (`vi` / `en`) trong **Wave U-A .. Wave U-D (`US-118..US-139`)** trên cả 4 nền tảng (**Windows `MeshVPN.exe`**, **macOS `Mesh VPN.app`**, **Android Jetpack Compose**, **iOS SwiftUI**) bảo toàn **100%** các bất biến an toàn thông tin của Mesh VPN (`SEC-01`, `SEC-04`, `SEC-05`, `SEC-14`, `D-GNFR-02`, `ADR-018`, `ADR-020`, `ADR-021`, `ADR-025`, `ADR-030`, `ADR-031`).

Nguyên tắc phân tách bằng chứng 3 tầng được áp dụng xuyên suốt:
- **`VERIFIED_ON_WINDOWS_HOST`**: Thực thi trực tiếp bộ kiểm thử tích hợp Rust `crates/mesh-gui/tests/security_regression_unified_ui.rs`, `qa_desktop_security_audit.rs`, `mesh-sys -- gui_windows`, `cargo-deny check bans licenses sources`, và kịch bản `lab/mobile/audit-mobile-security.ps1` trên máy chủ Windows.
- **`PENDING_CI_RUNNER`**: Các bài XCTest / JUnit native chạy trên `macos-15` và `ubuntu-latest`.
- **`hardware_signoff_required`**: Kiểm chứng trực quan `FLAG_SECURE` chống chụp màn hình trên thiết bị Android thật và prompt Face ID / Touch ID trên thiết bị iOS thật.

---

## 2. Ma Trận 9 Bài Kiểm Thử Hồi Quy Bảo Mật Bắt Buộc (`US-133`)

Tệp kiểm thử sở hữu độc quyền: `crates/mesh-gui/tests/security_regression_unified_ui.rs` (`0` `unsafe`, `0` `#[allow(clippy::...)]`, `0` `.unwrap()`/`.expect()`/`panic!()`).

| STT | Tên hàm kiểm thử (`security_regression_unified_ui.rs`) | Quy tắc / ADR đối chiếu | Nội dung xác minh chi tiết | Trạng thái |
| :---: | :--- | :--- | :--- | :---: |
| **1** | `test_no_secrets_in_outputs` | `SEC-01`, `ADR-020`, `ADR-031` | Bơm canary `mpk_*`, `mesh://join?...`, và khóa bí mật giả lập qua `Secret<T>`, `OnboardingFormInput`, `OnboardingValidatedDraft` (`EnrollNewNode` & `RotateKey`), `ClipboardSecretGuard`, `sanitize_gui_log_text`, `derive_desktop_ui_state`, và bản tóm tắt xác nhận tiếng Việt (`LocaleMode::Vi`) -> khẳng định **0 lần xuất hiện** canary; kiểm chứng tĩnh `MeshSecretScrubber` (macOS/iOS), `SafeLogger.kt` & `rawPreauthKey.fill('\u0000')` (Android). | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **2** | `test_clipboard_secret_guard_timer_active_for_mpk_only` | `SEC-01`, `IG-DGUI-WA-01`, `ADR-030` §4 | Khẳng định `CLIPBOARD_WIPE_DELAY_MS == 30_000`; `ClipboardSecretGuard` kiểm tra đồng thời `expected_seq` (`GetClipboardSequenceNumber`) + băm SHA-256 thời gian hằng (`ConstantTimeEq`), không xóa nhầm khi sequence thay đổi; xác minh `window.rs` chỉ gọi `arm_clipboard_wipe` tại **2 điểm dán bí mật** (`trigger_paste_uri_button` và bộ gác dán `IDC_EDIT_PREAUTH`/`looks_like_sensitive_paste`), tương đồng `ClipboardAutoClear.swift` (`recordedChangeCount`, `30.0s`) trên macOS. | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **3** | `test_clipboard_no_secret_guard_on_ip_copy` | `US-121` AC5, `ADR-030` §4 | Khẳng định sao chép `CopyKind::OverlayIp` và `CopyKind::Fqdn` trả `uses_secret_guard == false`, **không kích hoạt** bộ hẹn giờ xóa 30 giây và **không hủy** `ClipboardSecretGuard` đang canh gác `mpk_*` trước đó; đối chiếu mã nguồn cả 4 nền tảng (`window.rs`, `PeersTableView.swift`, `PeersScreen.kt`, `PeersView.swift`) đều không gọi hàm wipe clipboard bí mật khi copy IP/FQDN. | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **4** | `test_android_flag_secure_scope_not_peers_tab` | `US-119`, `US-121` AC6, `ADR-030` | Kiểm tra vét cạn bảng chân trị của `requireFlagSecure` cho người dùng đã enroll trên tab `Peers` (`!isEnrolled == false`, `pendingConfirmation == null`, `activeTab == MainTab.PEERS`) -> luôn trả `false`; đồng thời khẳng định `FLAG_SECURE` vẫn bật đầy đủ khi `!session.isEnrolled`, khi mở hộp thoại xác nhận `pendingConfirmation != null`, hoặc khi `activeTab == MainTab.SETTINGS && (isAdminPinsRevealed || isSensitiveModalOpen)`, và tự khóa `isAdminPinsRevealed = false` ngay khi chuyển tab khỏi `SETTINGS`. | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **5** | `test_ios_biometric_authorizer_unmodified` | `US-133` AC1, `ADR-018` | Xác minh `mobile/ios/MeshApp/Sources/BiometricAuthorizer.swift` bảo toàn nguyên vẹn `LAContext` với chính sách `.deviceOwnerAuthentication` (Face ID / Touch ID / Passcode fallback) kèm `MeshSecretScrubber.scrub(...)`, và `AppViewModel+Actions.swift` giữ đủ **4 thao tác nhạy cảm** bắt buộc qua `await biometricAuthorizer.authorize(...)` (Rotate Key, Update Server, Export Bugreport, Factory Reset). | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **6** | `test_mgh1_handoff_no_mpk_in_argv` | `D-GNFR-02`, `SEC-01`, `ADR-020`, `ADR-021` | Khẳng định tên Named Pipe ngẫu nhiên (`\\.\pipe\mesh-gui-handoff-*`) không chứa `mpk_*`, `HandoffFrame`/`HandoffRequest` ẩn khóa trong `Debug`, `zeroize_handoff_payload` xóa sạch bộ đệm về rỗng, `parse_gui_launch_args` chỉ chấp nhận `--minimized` và `--elevated-worker --pipe <pipe>` (từ chối mọi cờ lạ như `--preauth-key`), và `gui_windows.rs::launch_elevated_worker` chỉ truyền `--elevated-worker --pipe {pipe_name}` qua `ShellExecuteExW("runas")`. | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **7** | `test_agent_status_response_13_fields` | `ADR-031`, `US-039`, `US-133` AC2 | Tuần tự hóa `AgentStatusResponse` sang `serde_json::Value` -> khẳng định chính xác **13 trường gốc** (`daemon_state`, `node_id`, `node_name`, `fqdn`, `overlay_ip`, `overlay_cidr`, `tun_interface_name`, `tun_mtu`, `netmap_version`, `key_expires_at_ms`, `server_connection`, `self_network`, `peers`), round-trip `100%`, từ chối mọi trường lạ (`locale`, `theme`, `display_label`) nhờ `#[serde(deny_unknown_fields)]`, và đối chiếu khớp đủ 13 khóa với `AgentIpcModels.swift` trên macOS. | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **8** | `test_sec05_auth_failed_wire_en_all_platforms` | `SEC-05`, `UUI-21`, `US-128..131` | Xác minh `AppError::unauthenticated`, `HandoffResponse::from_error`, `format_user_facing_error`, và `t_for("error.auth_failed", LocaleMode::{En, Vi, System})` trên Rust/Windows, `en.lproj` & `vi.lproj` trên macOS, `FfiErrorMapper.kt` + `values`/`values-vi/strings.xml` trên Android, và `MeshErrorMapper.swift` + `Localizable.xcstrings` (`en` & `vi`) trên iOS đều trả **chính xác chuỗi bất biến `"authentication failed"`**. | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |
| **9** | `test_prefs_no_secrets_in_ui_prefs_json` | `ADR-031`, `US-124`, `US-128`, `US-133` | Kiểm tra cả `9` tổ hợp `(ThemeMode, LocaleMode)` ghi ra `ui-prefs.json` chỉ chứa đúng **2 khóa JSON** (`"theme"` thuộc `{"system","light","dark"}` và `"locale"` thuộc `{"system","en","vi"}`, `0` token nhạy cảm); kiểm chứng khi `ui-prefs.json` bị chèn giá trị lạ chứa `"mpk_SECRET_LEAK"`, bộ nạp lập tức xóa tệp hỏng và khôi phục `UiPrefs::default()`. | **PASS** (`VERIFIED_ON_WINDOWS_HOST`) |

---

## 3. Kết Quả Kiểm Toán Tĩnh Chuyên Sâu Trên 4 Nền Tảng

### 3.1. Cô lập `unsafe`, Mật mã & Ranh giới Crate (`SEC-01`, `SEC-02`, `ADR-020`)
- **`crates/mesh-gui`**: `[lints] workspace = true` kế thừa `unsafe_code = "forbid"`; kiểm tra mã nguồn `crates/mesh-gui/src/*.rs` có **`0` từ khóa `unsafe`**, **`0` lời gọi `.expose_secret()`**, **`0` `#[allow(clippy::...)]`**.
- **`crates/mesh-sys/src/gui_windows.rs`**: Mọi khối `unsafe` Win32/GDI/Shell/MSAA đều có chú thích `// SAFETY:` đầy đủ, vượt qua `clippy -p mesh-sys --all-targets --all-features -- -D warnings` và `cargo test -p mesh-sys -- gui_windows` (`12/12` PASS; `windows::tests` `30/30` PASS).
- **`cargo-deny check advisories bans licenses sources`**: **PASS** (`advisories ok, bans ok, licenses ok, sources ok`) — `0` crate C/TLS/SQL bị cấm, `0` phụ thuộc mới được thêm vào `Cargo.toml` trong toàn bộ Milestone `v0.4.0`.

### 3.2. Kiểm toán Bảo mật Di động (`lab/mobile/audit-mobile-security.ps1`)
Thực thi trực tiếp `powershell -ExecutionPolicy Bypass -File lab/mobile/audit-mobile-security.ps1`: **`16/16` cổng PASS (`0` failed)**:
- `MOB-SEC-01..06`: `0` dòng `unsafe` viết tay trong `mesh-mobile-ffi`, `0` phụ thuộc `jni` ngoài `mesh-sys`, `0` import `UIKit` trên iOS PacketTunnel / macOS App, `0` `.expose_secret()` rò rỉ ở tầng FFI.
- `MOB-SEC-07..12`: Android `network_security_config.xml` chặn cleartext (`cleartextTrafficPermitted="false"`), `allowBackup="false"`, `SafeLogger` lọc bí mật, `EncryptedSharedPreferences` / Keystore DEK cô lập hoàn toàn với `ThemePreferencesStore` & `LocalePreferencesStore` (chỉ lưu `"system"|"light"|"dark"` và `"system"|"en"|"vi"`).
- `MOB-SEC-13..16`: iOS App Group `group.io.meshvpn.app` chỉ lưu cấu hình không nhạy cảm (`mesh_theme_mode`, `mesh_locale_mode` trong `UserDefaults`), khóa DEK nằm trong Keychain `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, Zero-TOFU SPKI Pin được giữ nguyên trên mọi luồng Onboarding & Settings.

### 3.3. Bất biến Zero-TOFU & Tách Kênh IPC (`SEC-04`, `SEC-14`, `D-FR-02`)
- Trên cả 4 nền tảng, khi người dùng nhập địa chỉ IP thô (`198.51.100.10:8443` hoặc `[2001:db8::1]:8443`), chế độ `System CA` bị khóa cứng (`should_lock_system_ca_for_endpoint == true`), bắt buộc cung cấp `SpkiPin` hợp lệ (`sha256:<64 hex>`) và hiển thị hộp thoại xác nhận **Out-of-Band Verification** trước khi gửi yêu cầu enroll/rotate/set-server.
- Kênh IPC Read-Only (`\\.\pipe\mesh-agent-ro` / `/var/run/meshd/meshd-ro.sock`) và Admin (`\\.\pipe\mesh-agent-admin` / `/var/run/meshd/meshd-admin.sock`) giữ nguyên phân quyền SDDL / POSIX mode, không thêm bất kỳ lệnh IPC mới nào trong `v0.4.0`.

---

## 4. Kết Luận Kiểm Toán Bảo Mật (`US-133`)

Toàn bộ các yêu cầu bảo mật của **`US-133` (`UUI-34`) ĐẠT 100% (`PASS`)**: không có bất kỳ hồi quy bảo mật, rò rỉ khóa `mpk_*`/private key, mở rộng sai phạm vi `FLAG_SECURE`/clipboard timer, hay biến đổi hợp đồng dây `AgentStatusResponse` / `SEC-05` nào trên cả 4 nền tảng.
