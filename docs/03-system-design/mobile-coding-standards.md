# Mobile Coding Standards — Mesh VPN (`v0.2.0`: Rust Mobile + Android + iOS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-15 |
| Phiên bản | **1.1 (Chặng 2 — Gate 2 Revision R1)** |
| Nhánh làm việc | `feat/mobile-clients` (không chạm `main` và `v0.1.0-rc1`) |
| Áp dụng cho | `agile-developer`, `agile-qa`, `agile-devops` (Wave A, Wave B1 Android, Wave B2 iOS, Wave C QA) |
| Kế thừa bắt buộc | [coding-standards.md](./coding-standards.md) v2.2 · [`.agents/rules/coding-standards.md`](../../.agents/rules/coding-standards.md) |
| Tài liệu thiết kế đi kèm | [mobile-tech-stack-decision.md](./mobile-tech-stack-decision.md) · [mobile-adr.md](./mobile-adr.md) (`ADR-012..019`) |

> **Nguyên tắc kế thừa & Kỷ luật Đa ngôn ngữ:** Mọi quy tắc trong [coding-standards.md](./coding-standards.md) giữ nguyên **100% hiệu lực** đối với mã Rust, TOML, Markdown, Shell và Git. Tài liệu này bổ sung các quy chuẩn bắt buộc cho lớp **Rust Mobile/FFI** (`mesh-client`, `mesh-mobile-ffi`, `tools/uniffi-bindgen`), **Android Kotlin** (`mobile/android/`), và **iOS Swift** (`mobile/ios/`) sao cho mọi thành phần do nhiều subagent viết song song đạt chất lượng đồng nhất như từ một kỹ sư duy nhất.

---

## 0. Ngôn ngữ, Mã hóa Tệp & Kết thúc dòng (File Hygiene)

| Quy tắc | Phạm vi áp dụng | Cưỡng chế tự động |
|---|---|---|
| **Ngôn ngữ mã nguồn** | Tên biến, hàm, struct/class/enum, doc comment, inline comment, log, thông điệp lỗi nội bộ, tên test, commit message: **100% Tiếng Anh**. Tài liệu thiết kế/vận hành trong `docs/`: **Tiếng Việt** (giữ thuật ngữ kỹ thuật tiếng Anh). Chuỗi hiển thị UI người dùng đặt trong resource chuẩn (`strings.xml` / `Localizable.xcstrings`). | Review & Lint |
| **Bảng mã UTF-8 KHÔNG BOM** | **100% tệp** (`.rs`, `.toml`, `.md`, `.kt`, `.kts`, `.xml`, `.swift`, `.yml`, `.plist`, `.sh`, `.json`). **Cấm tuyệt đối** byte BOM `0xEF 0xBB 0xBF`. | `scripts/check.{ps1,sh}` (mở rộng phạm vi quét sang `crates/`, `tools/`, `mobile/` với `.kt`, `.kts`, `.swift`, `.xml`, `.yml`, `.plist`, `.pbxproj`) |
| **Kết thúc dòng `LF` (`\n`)** | **100% LF** cho mọi tệp nguồn & cấu hình di động (`.rs`, `.kt`, `.kts`, `.xml`, `.swift`, `.yml`, `.toml`, `.md`, `.sh`). Chỉ `*.ps1`, `*.bat`, `*.cmd` dùng `CRLF`. | `.editorconfig` + `.gitattributes` + `scripts/check.{ps1,sh}` |

---

## 1. Quy chuẩn Rust Mở rộng (`mesh-client`, `mesh-mobile-ffi`, `mesh-sys`, `tools/uniffi-bindgen`)

### 1.1. Cấu hình `[lints]` cho `crates/mesh-mobile-ffi/Cargo.toml` (Tránh `E0453` nhưng Giữ Cấm `unsafe` Viết tay)

1. **Tất cả crate lõi** (bao gồm `crates/mesh-client` mới và `tools/uniffi-bindgen`) **BẮT BUỘC** khai báo `[lints] workspace = true` (`unsafe_code = "forbid"`).
2. **Chỉ `crates/mesh-mobile-ffi/Cargo.toml`** (ngoài `crates/mesh-sys`) KHÔNG đặt `[lints] workspace = true` vì trong Rust `1.94.1` (`edition = "2024"`), macro `uniffi::setup_scaffolding!()` và `#[uniffi::export]` (`uniffi >= 0.29.5`, tối thiểu `>= 0.29.2`) sinh mã `#[unsafe(no_mangle)] pub extern "C"` gây lỗi `E0453` nếu `unsafe_code = "forbid"`. Cấu hình bắt buộc của `crates/mesh-mobile-ffi/Cargo.toml`:
   ```toml
   [lints.rust]
   unsafe_code = "allow"
   unsafe_op_in_unsafe_fn = "deny"
   missing_debug_implementations = "warn"
   unreachable_pub = "warn"

   [lints.clippy]
   undocumented_unsafe_blocks = "deny"
   unwrap_used = "deny"
   expect_used = "deny"
   panic = "deny"
   todo = "deny"
   unimplemented = "deny"
   dbg_macro = "deny"
   indexing_slicing = "deny"
   let_underscore_must_use = "deny"
   await_holding_lock = "deny"
   print_stdout = "deny"
   print_stderr = "deny"
   wildcard_imports = "deny"
   ```
3. **BẤT BIẾN KIỂM TĨNH (`scripts/check.ps1` & `scripts/check.sh` — `BLK-MOB-G2-01/06`):**
   - **MỞ RỘNG** kiểm tra tĩnh sang `crates/`, `tools/` và `mobile/` (`tools/` cũng bị cấm `unsafe` và `.expose_secret()`), giữ nguyên **100%** quy tắc cấm viết từ khóa `unsafe` (`unsafe fn`, `unsafe trait`, `unsafe impl`, `unsafe { ... }`, `unsafe extern`) trong mọi tệp `.rs` ngoài `crates/mesh-sys/*`!
   - Lớp `mesh-mobile-ffi` không được chứa **bất kỳ từ khóa `unsafe` viết tay nào** (chỉ có macro expansion của UniFFI ở thời điểm biên dịch, và gọi `mesh_sys::ensure_jni_symbols_linked()` trên Android). Mọi primitive FFI di động — gồm `adopt_raw_tun_fd`, `jni_android.rs` (`Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier`, **0 phụ thuộc TLS trong `mesh-sys`**), `memory_ios.rs` (**`unsafe extern "C" { fn os_proc_available_memory() -> usize; }`** trong `#[cfg(target_os = "ios")]` kèm fallback `usize::MAX` ngoài iOS), `disable_ipv4_dont_fragment` Android/iOS — **phải đặt trong `crates/mesh-sys`** kèm chú thích `// SAFETY:`.

### 1.2. Bảo toàn Allowlist `.expose_secret()` & Cấm Truyền Khóa Trần qua FFI (`HR-MOB-G2-03`)

- **Không mở rộng** danh sách allowlist `.expose_secret()` sang `mesh-client`, `mesh-mobile-ffi` hay `tools/`:
  - `mesh-client` sử dụng `NodeKeypair`, `DiscoKeypair`, `PreAuthToken` qua API cấp cao của `mesh-crypto` và `mesh-datapath` (giống `crates/meshd/src/` hiện hành vốn gọi `0` lần `.expose_secret()`).
  - **Cấm truyền khóa bí mật trần qua `Vec<u8>` (`RustBuffer`) hay trả `mpk_*` qua `java.lang.String` (`HR-MOB-G2-03`):**
    - Không thiết kế `load_identity_secret_bytes` / `save_identity_secret_bytes` bằng plaintext JSON `Vec<u8>`. Trên Android, Keystore `AES-256-GCM` mở khóa Master DEK 32-byte thành `ByteArray(32)` (gọi `.fill(0)` ngay trong `finally`), nạp vào hàm `ChaCha20Poly1305` của **`mesh-crypto`** và chỉ truyền **ciphertext** đã niêm phong sang `save_state_file`. Trên iOS, dùng cơ chế DEK tương tự với Keychain Access Group (hoặc zeroize `Data` tạm ngay bằng `resetBytes(in:)` trong `defer`).
    - Hàm `parse_mobile_join_uri` **chỉ** trả về trường hiển thị đã che **`preauth_key_masked: String`** và giữ `mesh_crypto::Secret<String>` bên trong `Arc<MobilePendingJoinSession>` (`#[derive(uniffi::Object)]`, `ZeroizeOnDrop`). Nhập tay `mpk_*` cũng tạo `MobilePendingJoinSession` và xóa buffer ký tự sớm nhất có thể.

### 1.3. Quy tắc Bắt buộc cho Code Rust Mobile (`ADR-012..016`, `BLK-MOB-G2-03/05/06`, `HR-MOB-G2-01/04`)

- **Cấm `anyhow`/`eyre` trong toàn bộ `crates/mesh-*`** (kể cả `mesh-mobile-ffi`). Mọi lỗi FFI định nghĩa bằng `#[derive(thiserror::Error, uniffi::Error)]` ánh xạ từ `mesh_core::error::ErrorKind`, giữ nguyên chính sách `SEC-05` (`Unauthenticated` chỉ trả thông báo chung).
- **`crates/mesh-client` bỏ `reqwest` (giữ `toml`)** (`HR-MOB-G2-01`); `mesh-crypto` feature `mobile-platform-verifier` chỉ kích hoạt mã nền tảng trong `#[cfg(any(target_os = "android", target_os = "ios"))]` để `--all-features` Desktop luôn xanh (`BLK-MOB-G2-06`).
- **Cấm hardcoded port `443`/`3478`** ngoài `crates/mesh-core::defaults` (`GNFR-11`).
- **Cấm `unbounded_channel` & `std::thread::sleep`:** Duy trì `mpsc::channel(256)` + `try_send()` cho datapath/Relay; sử dụng `tokio::time::timeout` cho mọi I/O.
- **Tài nguyên Mobile, Chống Starvation & Anti-Deadlock (`ADR-016`, `BLK-MOB-G2-05`):**
  - Không dùng `tokio::main` mặc định trong `mesh-mobile-ffi`; khởi tạo runtime tường minh với **`worker_threads(1)` + `max_blocking_threads(4)` (`keep_alive(10s)`) trên iOS**, **`worker_threads(2)` + `max_blocking_threads(6)` trên Android**, `thread_stack_size(512 * 1024)`, `MAX_CONTROL_WS_FRAME_BYTES = 256 KiB`, và `DatapathEngine` chế độ `TimerMode::IdleAware` (`45_000 ms ± 2_000 ms` heartbeat).
  - **Cấm đẩy `protect_socket(fd)` vào `spawn_blocking` dùng chung với `getaddrinfo`:** phải gọi `bridge.protect_socket(raw_fd)` đồng bộ trực tiếp bên ngoài mọi Rust lock (cả ở `MagicSocket`, Control, Relay, `StunClient`, `probe_udp_routing_candidates`, `PingProbe::execute_netcheck`, DNS forwarder).
  - **Quy tắc cứng iOS (`worker_threads = 1`):** Mọi I/O đĩa/Keychain/`NSFileCoordinator` chạy trên `spawn_blocking`; mọi event callback sang Swift/Kotlin (`on_status_changed`, `on_platform_warning`, `on_route_changed`, `on_tun_packets`) phải **O(1) non-blocking** (chỉ enqueue vào queue/channel, tuyệt đối không lock/await ngược về `MobileEngine` hay hàng đợi chính `NEPacketTunnelProvider`).
- **Bugreport Streaming (`HR-MOB-G2-04`):** `export_bugreport_to_file` ghi streaming thẳng vào `BufWriter<File>` (`8 KiB` buffer) theo định dạng thống nhất **`diagnostics/mesh-bugreport-{ts}.tar <= 1 MiB`** (`DEFAULT_MOBILE_MAX_BUGREPORT_BYTES = 1_048_576`), tuyệt đối **không** giữ `20 MiB` `Vec<u8>` trong RAM và **không** gọi `collect_os_route_table()`/`sysexec` trên mobile.
- **Property-based Testing (`proptest!`):** Bắt buộc bổ sung `proptest!` cho **bộ phân tích URI `mesh://join`**, **bộ phân tích/đóng gói DNS RFC 4074 + Bounded Single-Transaction L3 TCP `:53` Responder (`16` LRU slots, TTL `3_000 ms`, `<= 1_232 B` req / `<= 4_096 B` resp, `TCP RST|ACK` khi tràn/lỗi) + EDNS0 `1232 B` + `:853 RST|ACK`**, và **bộ tổng hợp địa chỉ NAT64 (`Pref64`, gồm octet `u = 0x00` RFC 6052 §2.2)** để chứng minh `0` lần panic với đầu vào đột biến.

---

## 2. Quy chuẩn Android (`mobile/android/` — Kotlin `2.1+`)

### 2.1. Formatting & Static Analysis (`ktlint` + `detekt` + Android Lint)

| Hạng mục | Quy chuẩn bắt buộc | Công cụ cưỡng chế |
|---|---|---|
| **Style & Format** | Theo **Kotlin Official Coding Conventions** & **Android Kotlin Style Guide** (indent **4 spaces**, max line length **100 cột**, trailing comma trên danh sách nhiều dòng, UTF-8 no BOM, **LF**). | `ktlintCheck` (Gradle plugin `org.jlleitschuh.gradle.ktlint` hoặc Spotless `ktlint`) |
| **Static Analysis** | Độ phức tạp hàm hợp lý, cấm nuốt exception rỗng (`catch (e: Exception) {}`), cấm `GlobalScope`, cấm `println` trong release code. | `detekt` (`warningsAsErrors = true` trong `detekt.yml`) + `./gradlew lintRelease` (`abortOnError = true`) |
| **Package & Naming** | Package gốc `dev.meshvpn.android` (phân lớp `ui/`, `vpn/`, `data/keystore/`, `data/dns/`, `ffi/`, `di/`); file/class `PascalCase`; hàm/biến `camelCase`; hằng số `SCREAMING_SNAKE_CASE`; Composable function đặt tên `PascalCase` theo danh từ (`OnboardingScreen`, `PeerStatusCard`). | `ktlint` + `detekt` |
| **Cấm Force-Unwrap** | **CẤM TUYỆT ĐỐI toán tử `!!`** trong mọi file production `.kt`. Thay bằng safe call `?.`, Elvis `?:`, `requireNotNull(...)` với lỗi có cấu trúc hoặc `Result<T>`. | `detekt` rule `UnsafeCallOnNullableType` (mức `error`) |
| **Thứ tự Import** | Không dùng wildcard import (`import foo.*` bị cấm trừ Compose/test khi cần thiết — khuyến nghị tắt wildcard hoàn toàn); sắp xếp theo bảng chữ cái không gộp nhóm thủ công sai chuẩn `ktlint`. | `ktlint` |

### 2.2. Structured Concurrency, Vòng đời & Nền tảng Android (`ADR-014`, `ADR-015`, `ADR-017`)

1. **Structured Concurrency:**
   - **Cấm `GlobalScope.launch`**.
   - Trong `MeshVpnService`: sở hữu `private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)` và gọi `serviceScope.cancel()` trong `onDestroy()` / `onRevoke()` (bảo đảm hoàn tất teardown `<= 5_000 ms`).
   - Trong `ViewModel`: dùng `viewModelScope` và đẩy trạng thái UI bất biến qua `StateFlow<UiState>` (`collectAsStateWithLifecycle()` trong Jetpack Compose).
   - Mọi thao tác Keystore, đọc ghi `noBackupFilesDir`, gọi hàm FFI chặn hoặc quét `ConnectivityManager` chạy trên `Dispatchers.IO` (không bao giờ chặn `Dispatchers.Main`).
2. **Bảo vệ JNI Context, Local Maven & `VpnService` (`BLK-MOB-G2-01/02`, `HR-MOB-G2-02/03`, `MOB-SEC-03`, `MOB-PLAT-AND-01..04`):**
   - `System.loadLibrary("mesh_mobile_ffi")` + **`MeshNativeInit.initPlatformVerifier(applicationContext)`** (vào `crates/mesh-sys/src/jni_android.rs` qua `jni = "0.21"`, **không dùng `ndk-context`**) **phải** chạy idempotent trong **`MeshApplication.onCreate()`** VÀ **`MeshVpnService.onCreate()`**.
   - `mobile/android/settings.gradle.kts` cấu hình local `maven` repository cho `rustls-platform-verifier-android` AAR (tra qua `cargo metadata`), và `proguard-rules.pro` bắt buộc có **`-keep,includedescriptorclasses class org.rustls.platformverifier.** { *; }`**.
   - `SocketProtector` callback gọi `vpnService.protect(fd)` **đồng bộ trực tiếp** ngoài mọi Rust lock, bắt mọi exception trả `false` để phía Rust fail-closed.
   - Giao diện TUN qua `VpnService.Builder` **luôn đặt prefix `/32`** (`addAddress(localOverlayIp, 32)`); cho phép `MobileUpConfig.android_tun_fd = None` lúc khởi đầu và trả `new_android_tun_fd` sau `establish()` thông qua `complete_route_change`.
   - Không dùng `EncryptedSharedPreferences`; dùng Android Keystore `AES-256-GCM` bọc 32-byte Master DEK (`dek.enc`), giải mã tạm ra `ByteArray(32)` (gọi `.fill(0)` trong `finally`) cho `mesh-crypto` niêm phong ciphertext lưu trong `context.noBackupFilesDir`, kèm `android:allowBackup="false"` và `dataExtractionRules`.
   - Khai báo `FOREGROUND_SERVICE_SPECIAL_USE`, xử lý `LOCKED_BOOT_COMPLETED` / `ACTION_USER_UNLOCKED`, cảnh báo `isLockdownEnabled()` và `LinkProperties.isPrivateDnsActive()`.
3. **Thư viện QR & Chính sách không GMS:**
   - Chỉ dùng CameraX `ImageAnalysis` + `com.google.zxing:core`; cấm kéo `com.google.mlkit` hay Google Play Services.

### 2.3. Bảo mật Log, UI & Phân tách Kiểm thử Android

- **Log Hygiene (`SEC-01`, `MOB-SEC-05`):** Cấm dùng `android.util.Log` trực tiếp ngoài wrapper `SafeLogger` (hoặc chặn toàn bộ `Log.d`/`Log.v` chứa payload trong bản release via R8/ProGuard `assumenosideeffects` + lint). Tuyệt đối không log private key, `mpk_*`, URI `mesh://join` nguyên vẹn, clipboard text hoặc payload gói mạng.
- **Màn hình nhạy cảm:** Bắt buộc đặt `WindowManager.LayoutParams.FLAG_SECURE` khi hiển thị/nhập thông số bí mật (`mpk_*`, pin quản trị); gọi `ClipboardManager.clearPrimaryClip()` (API 33+) ngay sau khi đọc URI `mesh://join`; dùng `CharArray` cho ô nhập `mpk_*` thủ công và `.fill('\u0000')` ngay sau khi tạo `MobilePendingJoinSession`.
- **Phân tách Kiểm thử Android:**
  - **`src/test/` (JVM Unit Tests — chạy không cần emulator/device trong CI `ubuntu-latest`):** kiểm thử ViewModel state, parser/validator URI `mesh://join` ở tầng UI, logic kiểm tra `LinkProperties` DNS filtering, logic xử lý Direct Boot & Lockdown warning bằng mock/fake (`./gradlew testDebugUnitTest`).
  - **`src/androidTest/` (Instrumented / Real Device Tests):** gắn chú thích rõ (`@LargeTest` / phân tách task Gradle), kiểm thử `VpnService.Builder`, Android Keystore `AES-256-GCM`, CameraX + ZXing QR decode, và E2E roaming/Private DNS trên emulator/máy thật Android 14+ (`US-097`).

---

## 3. Quy chuẩn iOS (`mobile/ios/` — Swift `6`)

### 3.1. Formatting & Static Analysis (`swift-format` + `SwiftLint`)

| Hạng mục | Quy chuẩn bắt buộc | Công cụ cưỡng chế |
|---|---|---|
| **Compiler & Concurrency** | **Swift `6`** (`SWIFT_VERSION = 6.0`, `SWIFT_STRICT_CONCURRENCY = complete`, **`IPHONEOS_DEPLOYMENT_TARGET = 15.0` (`iOS 15.0+`)**). | `xcodebuild` (`TREAT_WARNINGS_AS_ERRORS = YES` cho app target) |
| **Style & Format** | Theo **Apple Swift API Design Guidelines** & **`swift-format`** (indent **4 spaces**, line length **100 cột**, UTF-8 no BOM, **LF**). | `swift-format lint --strict` (hoặc `swiftlint lint --strict`) |
| **Project Spec** | Quản lý cấu hình target/entitlements bằng **`mobile/ios/project.yml` (XcodeGen)**. Không commit `.xcodeproj` sinh tay gây conflict. | `xcodegen generate` trong CI & local |
| **Naming & Structure** | Module tách rõ `MeshCoreKit` (framework/package chia sẻ giữa App & Extension: Keychain, AppGroup IPC, FFI wrapper), `MeshApp` (SwiftUI UI), `MeshPacketTunnel` (`NEPacketTunnelProvider`). Type/Protocol `PascalCase`; biến/hàm `camelCase`; tránh viết tắt mơ hồ. | `SwiftLint` |
| **Cấm Force-Unwrap & Crash** | **CẤM TUYỆT ĐỐI** force-unwrap **`!`**, **`try!`**, **`as!`**, **`fatalError(...)`** trong code production (`MeshApp`, `MeshPacketTunnel`, `MeshCoreKit`). Chỉ dùng `guard let` / `if let` / `throws` / typed `Error`. *(Chỉ cho phép `!` / `try!` trong `@IBOutlet` nếu có — không áp dụng vì dùng SwiftUI — hoặc trong XCTest/Swift Testing).* | `SwiftLint` rules (`force_unwrapping: error`, `force_try: error`, `force_cast: error`, `fatal_error_message: error`) |

### 3.2. Swift 6 Structured Concurrency & Tích hợp NetworkExtension (`ADR-018`)

1. **Structured Concurrency (`Sendable`, `Actor` & Anti-Deadlock `BLK-MOB-G2-05`):**
   - Toàn bộ trạng thái dùng chung giữa `NEPacketTunnelProvider` và callback bất đồng bộ từ Rust UniFFI phải đặt trong `actor` hoặc tuân thủ `Sendable` nghiêm ngặt dưới `SWIFT_STRICT_CONCURRENCY = complete` (cấm `@unchecked Sendable` trừ trường hợp bọc mutex OS được chứng minh bằng comment `// SAFETY-SENDABLE:`).
   - Mọi callback sự kiện từ Rust (`on_status_changed`, `on_platform_warning`, `on_route_changed`, `on_tun_packets`) phải **O(1) non-blocking** (chỉ đẩy vào `AsyncStream`/queue, tuyệt đối không gọi đồng bộ hoặc `await` ngược về `MobileEngine` hay hàng đợi `NEPacketTunnelProvider`).
   - Vòng đọc `packetFlow.readPackets` hủy sạch qua `Task` cancellation / `stopTunnel(with:completionHandler:)` trong `<= 5 s`.
2. **Quy tắc Tuyệt đối trên iOS (`MOB-PLAT-IOS-*`, `BLK-MOB-G2-02`, `HR-MOB-G2-02/04`, `MED-MOB-G2-01`):**
   - **Cấm** dò file descriptor `utun` bằng `getsockopt`/`sysctl` — chỉ dùng `packetFlow.readPackets`/`writePackets`; `NEIPv4Settings` luôn đặt `subnetMasks: ["255.255.255.255"]` (`/32`).
   - **Enroll trước ở `MeshApp` (`BLK-MOB-G2-02`):** `MeshApp` thực hiện `mobile_enroll_or_rotate_node(...)` để niêm phong identity vào Keychain Access Group + ghi `bootstrap.toml` vào App Group trước khi bật `MeshPacketTunnel`; **cấm** ghi `mpk_*` vào `providerConfiguration`, App Group file hay `sendProviderMessage`.
   - **Cấm** nhồi `bugreport` (`<= 1 MiB`) qua `NETunnelProviderSession.sendProviderMessage` / `handleAppMessage` (`<= 4 KiB`) — ghi streaming ra **`group.<bundle_id>/diagnostics/mesh-bugreport-{ts}.tar`** (`<= 1 MiB`) và xóa tệp tạm sau khi Share Sheet đóng.
   - **Cấm** đặt `kSecAttrSynchronizable = true` hoặc dùng accessibility yếu hơn `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; xử lý êm `errSecInteractionNotAllowed` (`-25308`).
   - Khi người dùng bấm Disconnect thủ công, bắt buộc đặt `manager.isOnDemandEnabled = false` và `saveToPreferences` trước `stopTunnel()`.
   - Dùng **`if #available(iOS 16.0, *) { PasteButton(...) }`** cho dán URI `mesh://join` trên iOS 16+ (fallback nút dán `UIPasteboard.general` chuẩn trên iOS 15); cấm đăng ký `CFBundleURLTypes` cho `mpk_*`.

### 3.3. Bảo mật `OSLog` & Phân tách Kiểm thử iOS (`$0` Simulator CI vs `$99/năm`)

- **Log Hygiene (`SEC-01`, `MOB-SEC-05`):** Dùng `os.Logger` (`OSLog`). Mọi tham số động không phải hằng số tĩnh đều phải gắn rõ mức độ bảo mật: dùng **`%{private}@`** (hoặc tránh log hoàn toàn) đối với địa chỉ, tên peer, đường dẫn tệp người dùng; **cấm log** khóa riêng, `mpk_*`, proof, hoặc URI `mesh://join` ở bất kỳ cấp độ nào (`debug`/`info`/`error`).
- **Phân tách Kiểm thử iOS (`OQ-MOB-02`):**
  - **Simulator Unit & UI Tests (`$0` trên `macos-latest` với `CODE_SIGNING_ALLOWED=NO`):** Tách toàn bộ logic nghiệp vụ (`MeshUriParserWrapper`, `TunnelNetworkSettingsBuilder`, `AppGroupFileExchange`, `KeychainErrorMapper`, `PacketFlowRingBridge`, SwiftUI ViewModels) vào thư viện kiểm thử được trên iOS Simulator bằng `xcodebuild test`.
  - **Physical Device Tunnel Tests (`hardware_signoff_required` — chờ Apple Developer `$99/năm`):** Chạy `NEPacketTunnelProvider` thật, đo Xcode Instruments `RSS <= 25 MiB` (Jetsam `os_proc_available_memory()`), đo Energy Log `<= 1.5%/giờ`, và kiểm chứng Wi-Fi ↔ 4G/5G IPv6-only NAT64 trên iPhone vật lý.

---

## 4. Quy tắc Git & Conventional Commits Mở rộng (`v0.2.0`)

Kế thừa [coding-standards.md §6.2](./coding-standards.md):
- Định dạng: `<type>(<scope>): <subject>` (tiếng Anh, thức mệnh lệnh, `<= 72` ký tự) + `Refs: US-0xx, MOB-xxx`.
- Bổ sung `<scope>` mới cho `v0.2.0`:
  - **`client`** (`crates/mesh-client`)
  - **`ffi`** (`crates/mesh-mobile-ffi`, `tools/uniffi-bindgen`)
  - **`android`** (`mobile/android/`)
  - **`ios`** (`mobile/ios/`)
  - **`mobile-qa`** (`US-094..098`)
- **Cấm commit:** `.apk`, `.aab`, `.ipa`, `.xcframework`, `.so`, `.a`, `.xcodeproj/` (sinh từ `project.yml`), thư mục bindings sinh tự động nếu cấu hình build tự generate, `local.properties`, `keystore.jks`, `*.mobileprovision`, `*.p12`.

---

## 5. Bộ Lệnh Kiểm Định Chuẩn Toàn Diện (Standard Check Commands — Chặng 3)

### 5.1. Lệnh kiểm tra Rust & Repo Hygiene (Bắt buộc mọi Wave)
- **Windows:** `powershell -ExecutionPolicy Bypass -File scripts/check.ps1` (và `-Cross` dùng `--workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen` cho `zigbuild` Desktop/clippy cross-targets — `BLK-MOB-G2-06`)
- **Linux / macOS:** `sh scripts/check.sh` (và `--cross` dùng `--workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen`)
- **Kiểm tra đồ thị & Cross-targets Mobile (`cargo-deny` 0 warning & cross-compile theo đúng môi trường):**
  ```sh
  cargo deny check advisories bans licenses sources
  cargo deny check --target aarch64-linux-android --target aarch64-apple-ios
  # Trên CI ubuntu-latest có Android NDK r27c+ (đặt CC_aarch64_linux_android):
  cargo check -p mesh-mobile-ffi --target aarch64-linux-android
  cargo check -p mesh-mobile-ffi --target x86_64-linux-android
  # Trên CI macos-latest có Xcode SDK:
  cargo check -p mesh-mobile-ffi --target aarch64-apple-ios
  cargo check -p mesh-mobile-ffi --target aarch64-apple-ios-sim
  cargo check -p mesh-mobile-ffi --target x86_64-apple-ios
  ```
  *(Lưu ý `BLK-MOB-G2-06`: biên dịch thực sự `ring` cho Android cần Android NDK `clang`, cho iOS cần `macos-latest` Xcode; trên máy phát triển Windows/Linux không gắn NDK/Xcode, kiểm định đồ thị phụ thuộc mobile bằng `cargo metadata` và `cargo deny check --target <triple>`.)*

### 5.2. Lệnh kiểm tra Android (`mobile/android/` — Wave B1 & CI `ubuntu-latest` `$0`)
```sh
cd mobile/android
./gradlew ktlintCheck detekt lintDebug testDebugUnitTest assembleDebug
```
- Khi build release / kiểm tra kích thước `.so` & 16 KB page alignment:
  - Biên dịch `.so` với `RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384"` (`cargo ndk -t arm64-v8a -t x86_64 ...`), xác minh mỗi `.so` `<= 6 MiB` (`6_291_456` bytes) và ELF `LOAD` alignment `>= 0x4000` (`16384`).

### 5.3. Lệnh kiểm tra iOS (`mobile/ios/` — Wave B2 & CI `macos-latest` `$0`)
```sh
cd mobile/ios
xcodegen generate
swiftlint lint --strict
xcodebuild test \
  -project MeshVPN.xcodeproj \
  -scheme MeshApp \
  -destination 'platform=iOS Simulator,name=iPhone 16' \
  CODE_SIGNING_ALLOWED=NO
```
- Xác minh `MeshMobileFFI.xcframework` chứa đủ 3 slices (`ios-arm64`, `ios-arm64_x86_64-simulator`) và mỗi thư viện tĩnh/slice `<= 6 MiB`.
- *(Các bước cài đặt/chạy tunnel trên iPhone vật lý và `xcodebuild archive` ký số gắn cổng `hardware_signoff_required` theo `OQ-MOB-02`.)*
