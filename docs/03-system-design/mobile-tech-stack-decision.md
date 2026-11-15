# Mobile Tech Stack Decision — Mesh VPN (`v0.2.0`: Android & iOS)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-15 |
| Phiên bản | **1.1 (Chặng 2 — Gate 2 Revision R1)** |
| Nhánh làm việc | `feat/mobile-clients` (không chạm `main` và `v0.1.0-rc1`) |
| Thành phần AI/SLM | **Không có** → bỏ qua mục AI/ML Stack |
| Đầu vào bắt buộc | [mobile-readiness-requirements.md](../01-discovery/mobile-readiness-requirements.md) (`34` `MOB-*`), [mobile-product-backlog.md](../02-product-planning/mobile-product-backlog.md) v1.1 (`OQ-MOB-01..05` đã chốt ngày `2026-11-15`), [mobile-gate-1-critique.md](../05-quality-assurance/critique-reviews/mobile-gate-1-critique.md), [agile-state.md](../04-sprint-management/agile-state.md) |
| Kế thừa nền tảng | [tech-stack-decision.md](./tech-stack-decision.md) v2.2 · [architecture-decision-record.md](./architecture-decision-record.md) (`ADR-001..011`) · [coding-standards.md](./coding-standards.md) v2.2 |
| Tài liệu đi kèm | [mobile-adr.md](./mobile-adr.md) (`ADR-012..019`) · [mobile-coding-standards.md](./mobile-coding-standards.md) |

> **Quy ước kiểm chứng:** `[V]` = đã đối chiếu trực tiếp trong codebase/toolchain thực tế của repo (`Cargo.toml`, `deny.toml`, `scripts/check.{ps1,sh}`, `crates/*`, `cargo-deny 0.20.2`, `rustc 1.94.1`). `[N]` = thiết kế dựa trên tài liệu chuẩn của hệ sinh thái mục tiêu (chưa biên dịch hoặc chạy thực địa ở Chặng 2; sẽ được kiểm chứng trong Wave A/B/C ở Chặng 3).

---

## 1. Tóm tắt Quyết định Công nghệ Di động (TL;DR)

| Tầng / Nền tảng | Quyết định chốt (`v0.2.0`) | Tham chiếu ADR & Gate 1 |
|---|---|---|
| **Kiến trúc Workspace & Lõi Dùng chung** | Mở rộng Cargo Workspace (`Rust 1.94.1`, `edition = "2024"`, `resolver = "3"`) thêm **`crates/mesh-client`** (trích xuất lõi Control Plane OS-neutral từ `meshd` — `US-099`), **`crates/mesh-mobile-ffi`** (`cdylib` + `staticlib` + `lib`) và **`tools/uniffi-bindgen`** (`mesh-uniffi-bindgen`, nằm ngoài `crates/mesh-*`). | `ADR-012`, `US-099`, `M-GNFR-05` |
| **Cầu nối FFI & Giấy phép** | **`UniFFI` `0.29.5`** (`>= 0.29.2` để sinh `#[unsafe(no_mangle)]` trên `edition = "2024"`, proc-macro `uniffi::setup_scaffolding!()`, `#[uniffi::export]`). Ngoại lệ `MPL-2.0` trong `deny.toml` (`[[licenses.exceptions]]`) giới hạn riêng cho `uniffi*` (tỉa khớp `Cargo.lock` để `0` warning); **`anyhow`** chỉ mở qua `[bans]` `wrappers` cho `uniffi*` (cấm 100% trong toàn bộ `crates/mesh-*`); giữ **Pure-Rust `ring`** và cấm `aws-lc-rs`/`gotatun`. | `OQ-MOB-05`, `ADR-013`, `M-GNFR-06` |
| **Cô lập `unsafe` & Bí mật** | `crates/mesh-mobile-ffi/Cargo.toml` tự khai báo `[lints.rust]` (`unsafe_code = "allow"` cho macro expansion của UniFFI, tránh lỗi `E0453` + `unsafe_op_in_unsafe_fn = "deny"`), **nhưng** `scripts/check.{ps1,sh}` vẫn **CẤM 100%** từ khóa `unsafe` viết tay ngoài `crates/mesh-sys/*`. Mọi OS FFI di động (`FromRawFd`, `jni_android`, `unsafe extern "C"` `os_proc_available_memory`, `DF=0`) đặt trong `crates/mesh-sys`. Giữ nguyên allowlist `.expose_secret()`; không truyền khóa trần qua `Vec<u8>`/`java.lang.String`. | `ADR-013`, `SEC-01` |
| **TLS, Native CA & IPv6 NAT64** | Mặc định **IP + SPKI Pin** qua `SpkiPinVerifier` (`x509-cert` + `ring` + `subtle`, fail-closed, cấm TOFU). Chế độ Domain + CA dùng **`rustls-platform-verifier` `0.6`** (feature `mobile-platform-verifier`) thay thế `rustls-native-certs`; Android dùng **`jni = "0.21"`** trong `crates/mesh-sys/src/jni_android.rs` (`initPlatformVerifier` + `OnceLock` + `with_attached_env_and_context`) để `mesh-crypto` gọi `android::init_hosted` (0 `unsafe` ngoài `mesh-sys`), kèm local Maven AAR + R8 keep rule. Hỗ trợ IPv6-only **NAT64 (`64:ff9b::/96`)** cho Control, Relay, STUN, `MagicSocket`, `PingProbe`. | `ADR-014`, `MOB-SEC-03`, `M-GNFR-09` |
| **Định tuyến & Split-DNS** | **Chỉ Split-Tunnel** (`NetmapSnapshot.overlay_cidr` + `.mesh.internal`, giao diện TUN đặt `/32`, luôn kèm `overlay_dns_ip/32`, hoãn Exit Node sang `v0.3.0`). Embedded DNS Responder tách L3 `overlay_dns_ip:53` trước `CryptokeyValidator` chuẩn **RFC 4074 §3** (`AAAA` peer tồn tại trả `NOERROR NODATA`), xử lý `TCP :53` bằng **Bounded Single-Transaction L3 TCP `:53` Responder** (`16` phiên LRU, TTL `3_000 ms`, 0 `smoltcp`) + EDNS0 `1232 B`, Android `:853` trả `TCP RST|ACK`, iOS dùng `NEDNSSettings(matchDomains)`. | `OQ-MOB-04`, `ADR-015`, `M-GNFR-04` |
| **Tối ưu Pin & Trần RAM Jetsam** | `DatapathEngine` dùng **idle-aware / coalesced ticks** (thay `250 ms` 8 Hz cố định), giãn/đồng bộ heartbeat về **`45_000 ms ± 2_000 ms`** để hạ modem về **`RRC_IDLE`**. iOS Extension khóa `worker_threads(1)`, `max_blocking_threads(4)` (Android `6`), `protect_socket(fd)` gọi đồng bộ trực tiếp ngoài Rust lock (không xếp sau `getaddrinfo`), `MAX_CONTROL_WS_FRAME_BYTES = 256 KiB`, `os_proc_available_memory()`, streaming **`diagnostics/mesh-bugreport-{ts}.tar <= 1 MiB`** (`<= 25 MiB` RSS dưới trần `50 MiB` Jetsam). | `ADR-016`, `M-GNFR-01`, `M-GNFR-07` |
| **Android Stack (`mobile/android/`)** | **Kotlin `2.1+`**, Gradle Kotlin DSL (`.kts`) + Version Catalog, `minSdk = 26` / `targetSdk = 35`, **Jetpack Compose**, `VpnService` (`specialUse` + `protect(fd)` đồng bộ + cập nhật `new_android_tun_fd` qua `complete_route_change`), NDK r27+ **`-Wl,-z,max-page-size=16384`** (16 KB page size), **Android Keystore `AES-256-GCM`** bọc Master DEK 32-byte (`.fill(0)` trong `finally`) + `ChaCha20Poly1305` từ `mesh-crypto`, local Maven AAR `rustls-platform-verifier-android` + R8 keep rule, QR thuần OSS (**CameraX `ImageAnalysis` + `com.google.zxing:core`**). Phát hành `.apk` `$0`. | `OQ-MOB-02/03`, `ADR-017` |
| **iOS Stack (`mobile/ios/`)** | **Swift `6`** (`IPHONEOS_DEPLOYMENT_TARGET = 15.0` / **iOS `15.0+`**, `if #available(iOS 16.0, *)` dùng `PasteButton`, iOS 15 dùng nút `UIPasteboard`), **SwiftUI**, 2 tiến trình (`MeshApp` enroll trước qua `mobile_enroll_or_rotate_node` + `MeshPacketTunnel` `NEPacketTunnelProvider` + `packetFlow` + `NWPathMonitor`), Keychain `ThisDeviceOnly` non-sync, QR native **`AVCaptureMetadataOutput`** (0 thư viện ngoài), quản lý dự án bằng **`project.yml` (XcodeGen)**. CI `macos-latest` build `.xcframework` + Simulator `CODE_SIGNING_ALLOWED=NO` (`$0`); tunnel máy thật gắn `hardware_signoff_required ($99/năm)`. | `OQ-MOB-02/03`, `ADR-018` |

---

## 2. Ràng buộc Đầu vào & Quyết định Gate 1 (`OQ-MOB-01..05`)

Tất cả lựa chọn kỹ thuật trong tài liệu này khóa cứng theo 5 quyết định của Người dùng tại Gate 1 (`2026-11-15`):

1. **`OQ-MOB-01` (Phương án A — Song song sau Wave A):** Triển khai Wave A (`Shared Core`, `US-075..080, 099` = `34 SP`) trước để mở khóa song song Wave B1 (`Android`, `mobile/android/`) và Wave B2 (`iOS`, `mobile/ios/`), rồi hội tụ tại Wave C (`Mobile QA`).
2. **`OQ-MOB-02` (`$0` Mode — Chưa chi `$99/năm` Apple):**
   - **Android**: biên dịch CI `ubuntu-latest` miễn phí, xuất `.apk` cài sideload trên điện thoại Android thật với chi phí `$0`.
   - **iOS**: hoàn thiện 100% mã SwiftUI, `NEPacketTunnelProvider`, entitlements template, `MeshMobileFFI.xcframework` (`3` slices) và kiểm chứng compile/link/unit-test trên iOS Simulator (`CODE_SIGNING_ALLOWED=NO`, `$0` trên `macos-latest`); riêng hạng mục chạy tunnel vật lý trên iPhone thật đánh dấu cổng **`hardware_signoff_required (chờ Apple Developer $99/năm)`**.
3. **`OQ-MOB-03` (Onboarding 3 luồng trong app, cấm OS deep-link `mpk_*`):** Hỗ trợ đầy đủ quét QR camera nội bộ, dán URI `mesh://` từ CLI `crates/mesh` (`PreAuthKeyCreatedResponse`), và nhập tay `IP:port + sha256:<pin> + mpk_*`, kèm màn hình xác nhận tường minh Endpoint + SPKI Pin; **cấm đăng ký** OS-wide clickable custom URL scheme / App Links / Universal Links mang `mpk_*`.
4. **`OQ-MOB-04` (Chỉ Split-Tunnel `v0.2.0`):** Chỉ route dải overlay động từ `NetmapSnapshot.overlay_cidr` và `.mesh.internal`; hoãn Exit Node (`0.0.0.0/0`) sang `v0.3.0`; Android app phát hiện và cảnh báo nổi bật khi bật VPN Lockdown Mode hoặc Strict Private DNS.
5. **`OQ-MOB-05` (Ngoại lệ `MPL-2.0` hẹp cho `uniffi*`):** Mở ngoại lệ `MPL-2.0` giới hạn riêng cho nhóm crate `uniffi*` ở lớp FFI di động (`mesh-mobile-ffi` và công cụ `mesh-uniffi-bindgen`); giữ nguyên 100% giấy phép permissive (`MIT`/`Apache-2.0`/`BSD`/`ISC`) cho `mesh-server`, `meshd`, `mesh` và toàn bộ các crate lõi.

---

## 3. Cấu trúc Cargo Workspace Mở rộng & Feature Flags (`US-075`, `US-076`, `US-099`)

### 3.1. Sơ đồ Workspace Mới (Chỉ thực thi tại Wave A Chặng 3)

Hiện tại `[V]`, `Cargo.toml` có `members = ["crates/*"]` gồm 3 binaries (`mesh`, `meshd`, `mesh-server`) và 7 thư viện (`mesh-core`, `mesh-sys`, `mesh-crypto`, `mesh-proto`, `mesh-net`, `mesh-store`, `mesh-datapath`). Để trích xuất ~3.641 dòng `control_loop.rs`, `netmap_cache.rs`, `roaming_loop.rs` và `ping_probe.rs` khỏi binary `crates/meshd` (`US-099`) và cung cấp cầu nối FFI di động (`US-079`), cấu trúc mới bổ sung đúng 2 crate trong `crates/` và 1 công cụ phụ trợ trong `tools/`:

```text
mesh-vpn/
├── Cargo.toml                     # members = ["crates/*", "tools/uniffi-bindgen"]
├── deny.toml                      # Bổ sung 5 mobile targets, [[licenses.exceptions]] uniffi*, [bans] wrappers
├── crates/
│   ├── mesh-core/                 # [Lib] Không đổi vai trò (~100% reuse)
│   ├── mesh-sys/                  # [Lib] Duy nhất chứa `unsafe` viết tay (`jni_android.rs`, `memory_ios.rs`, `tun_android.rs`, `socket_{android,ios}.rs`)
│   ├── mesh-crypto/               # [Lib] Feature-gate `rustls-native-certs`, `rcgen`, `rustls-platform-verifier`
│   ├── mesh-proto/                # [Lib] Thêm `TargetOs::{Android, Ios}` giữ `protocol_version = 1`
│   ├── mesh-net/                  # [Lib] Feature-gate `desktop-os`/`desktop-ipc`; nhánh `android`/`ios` trong `route.rs`, `nat64.rs`
│   ├── mesh-datapath/             # [Lib] Feature-gate `desktop-os`; `SocketProtector`, NAT64, `TimerMode::IdleAware`
│   ├── mesh-client/               # [Lib MỚI — US-099] Lõi Client Control Plane OS-neutral tách từ `meshd` (giữ `toml`, 0 `reqwest`)
│   ├── mesh-mobile-ffi/           # [Lib MỚI — US-079] `cdylib` + `staticlib` + `lib` (UniFFI 0.29.5 + RFC 4074 DNS + Bounded TCP :53 + `mesh://join` parser)
│   ├── mesh-store/                # [Lib] Chỉ VPS (`mesh-server`)
│   ├── mesh/                      # [Bin] CLI Desktop & VPS Admin (thêm `--emit-uri` & `--qr` từ `PreAuthKeyCreatedResponse`)
│   ├── meshd/                     # [Bin] Vỏ Daemon Desktop (gọi `mesh-client` + adapter OS Desktop)
│   └── mesh-server/               # [Bin] VPS Control + Relay + STUN (nhận `TargetOs::{Android, Ios}`)
├── tools/
│   └── uniffi-bindgen/            # [Bin MỚI] `package.name = "mesh-uniffi-bindgen"`, ghim `uniffi` `features = ["cli"]` theo `Cargo.lock`
└── mobile/
    ├── android/                   # Kotlin 2.1+, Gradle Kotlin DSL, Jetpack Compose, VpnService
    └── ios/                       # Swift 6 (iOS 15.0+), SwiftUI, NEPacketTunnelProvider, `project.yml` (XcodeGen)
```

### 3.2. Ma trận Feature Flags & Cô lập Phụ thuộc Mobile

Mục tiêu `US-076` và `M-GNFR-06/08` là **0 sự xuất hiện** của `axum`, `hyper`, `hyper-util`, `redb`, `clap`, `rustls-native-certs`, `rcgen`, `windows-sys`, `windows-service` trong đồ thị biên dịch của `mesh-mobile-ffi`, đồng thời giữ **100% default features** cho bản build Desktop/Server (`meshd`, `mesh-server`, `mesh`):

| Crate | Features mới đề xuất | Default (Desktop/Server) | Build Mobile (`default-features = false`) | Điểm kỹ thuật bắt buộc |
|---|---|---|---|---|
| **`mesh-crypto`** | `desktop-certs = ["dep:rustls-native-certs"]`<br>`certgen = ["dep:rcgen"]`<br>`mobile-platform-verifier = ["dep:rustls-platform-verifier"]` | `default = ["desktop-certs", "certgen"]` | `features = ["mobile-platform-verifier"]` | `SpkiPinVerifier` (`x509-cert` + `ring` + `subtle`) luôn biên dịch ở lõi không cần feature flag; mã dùng `rustls-platform-verifier` bắt buộc bọc `#[cfg(any(target_os = "android", target_os = "ios"))]` để `--all-features` Desktop luôn biên dịch xanh (`BLK-MOB-G2-06`). `certgen` & `rustls-native-certs` bị cắt khỏi mobile. |
| **`mesh-net`** | `desktop-ipc = ["dep:axum", "dep:hyper", "dep:hyper-util"]`<br>`desktop-os = ["desktop-ipc", "dep:windows-service"]` | `default = ["desktop-os"]` | `default-features = false` | Giữ `endpoint_filter`, `nat64`, `tun` traits, `netmon` traits, `keystore` traits, `route` (`bind_underlay_*`, `disable_udp_dont_fragment` với nhánh `android`/`ios` mới), `mesh-sys`, `socket2`, `rustls`, `tokio`. Cắt `axum`/`hyper*`/`hosts_*`/`firewall_*`/`ipc_*`/`sysexec` trên mobile. |
| **`mesh-datapath`** | `desktop-os = ["mesh-net/desktop-os"]` | `default = ["desktop-os"]` | `default-features = false` | Truyền `default-features = false` xuống `mesh-net` và `mesh-crypto`; sửa `RelayClient::current_target_os_str()` (`relay_client.rs:1879`) trả `"android"`/`"ios"`; thêm `SocketProtector`, `Nat64Synthesizer` (kể cả `StunClient`), đọc HTTP `400` `ErrorEnvelope` trong `RelayClient::map_http_status_error`, và `TimerMode::IdleAware`. |
| **`mesh-client`** *(mới)* | `desktop-os = ["mesh-net/desktop-os", "mesh-datapath/desktop-os"]` | `default = ["desktop-os"]` | `default-features = false` | Trích xuất `control_loop`, `NetmapCacheStore`, `roaming_loop`, `ping_probe` (`meshd/src/`). **Giữ `toml` và bỏ `reqwest`** (`0 reqwest`, `HR-MOB-G2-01`); truyền `SocketProtector` + `Nat64Synthesizer` cho `probe_udp_routing_candidates` và `PingProbe::execute_netcheck`; trừu tượng hóa OS hooks qua `ClientPlatformHooks` + `ClientStateStore`. |
| **`mesh-mobile-ffi`** *(mới)* | Không mở `"cli"` trên `uniffi` | *(Chỉ build cho mobile/FFI test)* | Phụ thuộc `mesh-client` (`default-features = false`), `mesh-crypto` (`mobile-platform-verifier`), `mesh-datapath` (`default-features = false`), `mesh-net` (`default-features = false`), `mesh-sys`, `uniffi = "0.29.5"` (`features = ["tokio"]`). | `crate-type = ["cdylib", "staticlib", "lib"]`; gọi `mesh_sys::ensure_jni_symbols_linked()` trên Android để linker giữ symbol JNI; dùng `tools/uniffi-bindgen` riêng để sinh Kotlin/Swift nên `uniffi_bindgen` không lọt vào `.so`/`.xcframework`. |

### 3.3. Yêu cầu cập nhật `scripts/check.{ps1,sh}` tại Wave A (`BLK-MOB-G2-06`)
Khi đưa `crates/mesh-mobile-ffi` và `tools/uniffi-bindgen` vào `[workspace] members`:
1. **Mở rộng vùng quét tĩnh:** Bao phủ cả `crates/`, `tools/` và `mobile/` (kiểm tra UTF-8 no-BOM, 100% LF, cấm hardcoded `:443/:3478`; trong `tools/` cấm tuyệt đối `unsafe` và `.expose_secret()`).
2. **Giữ `-Cross` / `--cross` Desktop luôn xanh:** Các lệnh `cargo zigbuild` (`x86_64-unknown-linux-musl`) và cross-`clippy` Desktop (`aarch64-apple-darwin`) dùng `--workspace --exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen` để tránh cảnh báo `dropping unsupported crate type cdylib for target x86_64-unknown-linux-musl` và tránh kéo nhánh Apple/Android vào cross-target Desktop.
3. **Phân tách môi trường biên dịch cross-target:** Biên dịch `aarch64-linux-android` / `x86_64-linux-android` (`ring` C/ASM) yêu cầu Android NDK toolchain (`CC_aarch64_linux_android`, chạy trên CI `ubuntu-latest` + NDK r27c+); biên dịch `aarch64-apple-ios*` yêu cầu Xcode SDK trên `macos-latest`. Trên Windows/Linux host chưa gắn NDK/Xcode, kiểm định đồ thị phụ thuộc bằng `cargo metadata` và `cargo deny check --target <mobile_triple>`.

---

## 4. So sánh & Chốt Công nghệ Cầu nối FFI (`UniFFI` vs `jni` + `C-ABI`)

Theo quyết định `OQ-MOB-05` tại Gate 1, Người dùng đã phê duyệt mở ngoại lệ `MPL-2.0` giới hạn riêng cho `uniffi*`. Dưới đây là ma trận đối chiếu xác nhận tính đúng đắn về mặt kỹ thuật:

| Tiêu chí | **`UniFFI 0.29.5` (CHỐT theo `OQ-MOB-05`, `>= 0.29.2`)** | `jni` + `extern "C"` C-ABI thủ công |
|---|---|---|
| **An toàn kiểu & Bộ nhớ qua ranh giới FFI** | **5/5** — Tự sinh scaffolding C-ABI + JNI + Swift FFI đồng bộ từ 1 nguồn Rust (`#[derive(uniffi::Record, Enum, Error)]`, `#[uniffi::export]`), tự quản lý lifetime `Arc<T>`, `RustBuffer`, và async Future/`CallbackInterface`. | **2/5** — Phải tự viết và bảo trì 2 bộ FFI song song (`JNIEnv` + `jobject`/`GlobalRef` cho Kotlin và `extern "C"` pointer + `free_*` cho Swift), dễ rò rỉ bộ nhớ hoặc UB khi đổi schema. |
| **Giấy phép & `cargo-deny 0.20.2`** | **4/5** — `uniffi*` dùng `MPL-2.0` (weak file-level copyleft) và kéo `anyhow` nội bộ → cô lập sạch bằng `[[licenses.exceptions]]` + `[bans] wrappers` trong `deny.toml`; 0 ảnh hưởng tới `mesh-server`/`meshd`/`mesh`/core crates. | **5/5** — Thuần `MIT OR Apache-2.0`, nhưng tăng gấp đôi rủi ro bug bảo mật FFI và trễ tiến độ Wave B1/B2 song song. |
| **Kích thước nhị phân & `E0453`** | Overhead runtime `uniffi_core` ~150–300 KiB (`strip = "symbols"`, `lto = "thin"`), vẫn nằm gọn dưới trần `<= 6 MiB`/ABI. Cần cấu hình `[lints.rust]` riêng cho `mesh-mobile-ffi` để tránh `E0453` từ macro `#[unsafe(no_mangle)]` của UniFFI. | Nhỏ hơn ~150 KiB nhưng vẫn cần `unsafe_code = "allow"` trong crate JNI/C-ABI. |

---

## 5. Thiết kế `deny.toml` Dự thảo cho Wave A (`cargo-deny 0.20.2`)

Mọi quy tắc trong `deny.toml` hiện hành (`[V]`: đã kiểm chứng cú pháp bằng `cargo-deny 0.20.2` trên máy phát triển) được nâng cấp cho Wave A như sau:

1. **Mở rộng `[graph] targets`** thêm đủ **5 mobile target triples** bên cạnh 6 Desktop/Server targets hiện tại:
   - `aarch64-linux-android`
   - `x86_64-linux-android`
   - `aarch64-apple-ios`
   - `aarch64-apple-ios-sim`
   - `x86_64-apple-ios`
2. **Giữ `MPL-2.0` BỊ CẤM toàn cục** trong `[licenses].allow` (đảm bảo `gotatun` và mọi crate không thuộc danh sách ngoại lệ vẫn bị chặn). Chỉ thêm `[[licenses.exceptions]]` với cú pháp `crate = "..."`, `allow = ["MPL-2.0"]` cho đúng tập crate thuộc họ `uniffi*` thực tế có mặt trong `Cargo.lock` (nhóm ứng viên dự kiến: `uniffi`, `uniffi_core`, `uniffi_macros`, `uniffi_meta`, `uniffi_build`, `uniffi_udl`, `uniffi_pipeline`, `uniffi_internal_macros`, `uniffi_checksum_derive`, `uniffi_bindgen`).
   - **Quy tắc chống warning `MED-MOB-G2-03`:** Vì `cargo-deny 0.20.2` phát cảnh báo `warning[license-exception-not-encountered]` nếu liệt kê một crate `uniffi_*` không có trong `Cargo.lock` (ví dụ khi không dùng UDL), tại bước `WP-M-A0` sau khi chạy `cargo generate-lockfile`, **bắt buộc tỉa `[[licenses.exceptions]]` và `[bans] wrappers` khớp 1-1 với `Cargo.lock`** để `cargo deny check advisories bans licenses sources` ra **0 error, 0 warning**.
3. **Cô lập `uniffi*`, `jni` & Giải quyết bẫy `anyhow` qua `[bans]` `wrappers`**:
   - Khối `[bans] deny` hiện tại đang chặn toàn cục `{ name = "anyhow" }` (`deny.toml:81`). Vì `uniffi_core` và `uniffi_bindgen` phụ thuộc trực tiếp vào `anyhow`, nếu giữ nguyên sẽ báo lỗi toàn workspace.
   - **Giải pháp chuẩn:** Sửa mục `anyhow` thành quy tắc `wrappers` chỉ cho phép các crate nội bộ của `uniffi*` thực có trong `Cargo.lock` kéo `anyhow`:
     ```toml
     { name = "anyhow", wrappers = [
         "uniffi",
         "uniffi_core",
         "uniffi_macros",
         "uniffi_meta",
         "uniffi_build",
         "uniffi_internal_macros",
         "uniffi_checksum_derive",
         "uniffi_bindgen",
         # Tỉa khớp 100% danh sách uniffi* thực tế có trong Cargo.lock tại WP-M-A0
     ], reason = "anyhow is strictly banned in all mesh-* crates; allowed only inside transitive uniffi* FFI crates" },
     ```
   - Đồng thời bổ sung `wrappers` cho chính `uniffi*` để **CHỈ `mesh-mobile-ffi` và `mesh-uniffi-bindgen`** (plus nội bộ `uniffi*`) được phép depend vào `uniffi*`: nếu `mesh-core`, `mesh-crypto`, `mesh-client`, `meshd` hay `mesh-server` vô tình thêm `uniffi`, `cargo deny check bans` lập tức báo lỗi! Crate `jni = "0.21"` (và các crate phụ trợ `MIT`/`Apache-2.0` của nó, gated `cfg(target_os = "android")`) chỉ được import trong `mesh-sys`.
   - Toàn bộ lệnh cấm `openssl`, `openssl-sys`, `native-tls`, `aws-lc-rs`, `aws-lc-sys`, `rusqlite`, `libsqlite3-sys`, `libsodium-sys`, `gotatun` giữ nguyên **100%**.

---

## 6. Công nghệ TLS, NAT64 & Phân giải Tên Miền Di động

### 6.1. TLS Xác thực Đa nền tảng (`rustls` + `SpkiPinVerifier` + `rustls-platform-verifier`)

| Chế độ xác thực (`TlsAuthMode`) | Thành phần sử dụng | Hành vi trên Android | Hành vi trên iOS |
|---|---|---|---|
| **`SpkiPin` (Mặc định hạng nhất — IP + Pin)** | `mesh_crypto::tlspin::SpkiPinVerifier` (`x509-cert` + `ring` + `subtle`) | Xác thực DER SPKI SHA-256 hằng thời gian + `NotBefore`/`NotAfter` (`ClockSkew`), fail-closed khi thiếu pin, cấm TOFU (`MOB-SEC-03`). | Tương tự Android; hoạt động đồng nhất kể cả khi kết nối đi qua địa chỉ IPv6 tổng hợp NAT64 (`64:ff9b::/96`). |
| **`SystemCa` (Domain + CA hệ thống — `SEC-04(a)`)** | **`rustls-platform-verifier` `0.6`** (bật qua feature `mobile-platform-verifier` của `mesh-crypto`, provider `ring`, bọc `#[cfg(any(target_os = "android", target_os = "ios"))]`) | Gọi `TrustManager` hệ thống qua `rustls_platform_verifier::android::init_hosted(env, context)` (tuyệt đối KHÔNG phụ thuộc `ndk-context` vì `0.6` không tự đọc `ndk-context`). Kotlin gọi `MeshNativeInit.initPlatformVerifier(applicationContext)` **idempotent** tại `MeshApplication.onCreate()` & `MeshVpnService.onCreate()`, nối vào `crates/mesh-sys/src/jni_android.rs` (0 `unsafe` ở `mesh-crypto`). | Gọi thẳng `Security.framework` (`SecTrustEvaluateWithError`) của Apple — không cần khởi tạo context thủ công. |

> **Chú ý cho `mesh-sys` / `mesh-crypto` (`rustls-platform-verifier 0.6` trên Android — `BLK-MOB-G2-01`):**
> 1. **`crates/mesh-sys/src/jni_android.rs` (`#[cfg(target_os = "android")]`)** giữ **duy nhất** hàm JNI `#[unsafe(no_mangle)] pub unsafe extern "system" fn Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier(...) -> jboolean` (lưu `JavaVM` + `GlobalRef(applicationContext)` an toàn vào `OnceLock`, không panic) và hàm an toàn `with_attached_env_and_context`; `mesh-sys` có **0 phụ thuộc TLS**; `crates/mesh-crypto` gọi `rustls_platform_verifier::android::init_hosted(env, context)` bên trong closure an toàn đó (`0` dòng `unsafe` trong `mesh-crypto`). `mesh-mobile-ffi` gọi `mesh_sys::ensure_jni_symbols_linked()`.
> 2. **`mobile/android/` Gradle & R8:** `settings.gradle.kts` phải cấu hình local `maven` repository trỏ tới thư mục Maven đóng gói trong crate `rustls-platform-verifier-android` (tra cứu tự động qua `cargo metadata` lúc build Gradle/NDK), `app/build.gradle.kts` khai báo implementation `rustls:rustls-platform-verifier:...`, và `proguard-rules.pro` bổ sung **`-keep,includedescriptorclasses class org.rustls.platformverifier.** { *; }`** để R8 không strip class JNI Java ở bản release.

### 6.2. Hỗ trợ IPv6-only NAT64 / DNS64 (`BLK-MOB-02`, `M-GNFR-09`)
- **Nguyên nhân:** Tại `v0.1.0`, `RelayClient::connect_tls_transport` (`relay_client.rs:1002`), `StunClient` (`stun_client.rs:161,417`) và `MagicSocket::bind_single_socket` (`magic_socket.rs:333`) giả định IPv4 literal kết nối trực tiếp qua socket IPv4, sẽ gặp `ENETUNREACH` trên mạng cellular 4G/5G IPv6-only NAT64 (và bị Apple App Store Guideline 2.5 từ chối).
- **Giải pháp công nghệ chốt cho Wave A (`mesh-datapath`):**
  1. **Dual-stack / IPv6 `MagicSocket`:** Hỗ trợ socket IPv6 `SocketAddr` cho Control TLS, Relay WSS, STUN và P2P candidate (không chỉ map `::ffff:a.b.c.d`, mà dùng địa chỉ IPv6 tổng hợp NAT64 thật từ Pref64).
  2. **Khám phá Pref64 & Tổng hợp IPv6 (`Nat64Synthesizer`):**
     - Khi cần kết nối tới IPv4 literal `A.B.C.D` trong lúc hệ thống chỉ có underlay IPv6 (hoặc socket IPv4 trả `ENETUNREACH`/`EHOSTUNREACH`):
       - **Bước 1 (OS native):** Trên iOS/Android hỗ trợ `getaddrinfo` với `AI_DEFAULT` / `AF_UNSPEC` (trên Apple, `getaddrinfo` tự tổng hợp IPv6 từ IPv4 literal theo RFC 7050 của `NWPath` nếu mạng đang bật NAT64) hoặc truyền trực tiếp Pref64 prefix từ `NWPath` / Android `LinkProperties.getNat64Prefix()` (API 30+).
       - **Bước 2 (Fallback OS-neutral RFC 7050):** Nếu OS không cung cấp sẵn Pref64, thực hiện truy vấn DNS `AAAA ipv4only.arpa` (`192.0.0.170` / `192.0.0.171`) qua resolver underlay (qua `protect(fd)` trên Android) để trích xuất `Pref64::/96` (mặc định chuẩn `64:ff9b::/96`), rồi tổng hợp `<Pref64>::A.B.C.D`.
  3. **Bảo toàn SPKI Pin:** `SpkiPinVerifier` vẫn nhận đúng `ServerName::IpAddress` gốc và xác thực SPKI SHA-256 trên chứng chỉ trả về từ TLS handshake qua socket IPv6 NAT64 — **0 hạ cấp bảo mật**.

---

## 7. Tech Stack Chi tiết Nền tảng Android (`mobile/android/`)

| Hạng mục | Quyết định công nghệ chốt | Phiên bản / Cấu hình | Lý do & Tham chiếu yêu cầu |
|---|---|---|---|
| **Ngôn ngữ & Build** | **Kotlin `2.1+`** + **Gradle Kotlin DSL** (`build.gradle.kts` + `gradle/libs.versions.toml`) + **Android Gradle Plugin (`AGP 8.7+`)** | `minSdk = 26` (Android 8.0)<br>`compileSdk = 35`<br>`targetSdk = 35` (Android 15) | Đáp ứng chính sách Google Play API 34/35 (`FOREGROUND_SERVICE_SPECIAL_USE`), hỗ trợ `isLockdownEnabled()` (API 29+) & `getNat64Prefix()` (API 30+). |
| **Giao diện (UI)** | **Jetpack Compose** + Material 3 + Navigation Compose + `Lifecycle` `ViewModel` (`StateFlow`) | Compose BOM `2025.x` | Khớp đề xuất Gate 1, code khai báo sạch, dễ kiểm thử UI state không cần device. |
| **Biên dịch Rust NDK & 16 KB Page Size** | **`cargo-ndk`** + **Android NDK `r27c+`** cho `aarch64-linux-android` (`arm64-v8a`) & `x86_64-linux-android` (`x86_64`) | Linker flag bắt buộc:<br>**`-Wl,-z,max-page-size=16384`** | **Bắt buộc cho Android 15+ (16 KB page size)** theo yêu cầu Google Play và thiết bị ARM64 mới; đảm bảo `PT_LOAD` ELF segment align `16 KiB` và kích thước mỗi `.so` `<= 6 MiB`. |
| **VPN & Foreground Service** | `android.net.VpnService` + `ConnectivityManager.NetworkCallback` | `foregroundServiceType="specialUse"` + `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE">` | Tuân thủ Android 14+ (`MOB-PLAT-AND-03`); `VpnService.protect(fd)` đồng bộ trực tiếp ngoài Rust lock (không qua `spawn_blocking` chung với `getaddrinfo`); truyền `new_android_tun_fd` sau `establish()` qua `complete_route_change`; `onRevoke()` teardown `<= 5 s`. |
| **Lưu trữ Khóa & Chống Backup** | **Android Keystore (`AES-256-GCM`)** bọc Master DEK 32-byte + `ChaCha20Poly1305` sealed blob trong **`context.noBackupFilesDir`** (`0600`) | `android:allowBackup="false"`<br>`android:dataExtractionRules` (API 31+)<br>`android:fullBackupContent` (API 26–30) | **CẤM `EncryptedSharedPreferences`**; `ByteArray(32)` DEK gọi `.fill(0)` trong `finally` ngay sau khi nạp vào `mesh-crypto` (**0** plaintext JSON qua `Vec<u8>`/`RustBuffer`); hỗ trợ Direct Boot (`LOCKED_BOOT_COMPLETED` → chờ `ACTION_USER_UNLOCKED`) không crash (`MOB-SEC-01`, `HR-MOB-G2-03`). |
| **Quét mã QR (`OQ-MOB-03`)** | **AndroidX CameraX (`camera-camera2`, `camera-lifecycle`, `camera-view`) + `com.google.zxing:core`** (`Apache-2.0`) | 100% Offline Open-Source (`ImageAnalysis`) | **KHÔNG phụ thuộc Google Play Services ML Kit** (tránh binary độc quyền của Google & chạy tốt trên Android AOSP/GrapheneOS/không GMS). |
| **Khởi tạo JNI `Context` & R8** | `System.loadLibrary("mesh_mobile_ffi")` + `MeshNativeInit.initPlatformVerifier(applicationContext)` + local Maven AAR `rustls-platform-verifier-android` | Gọi trong **`MeshApplication.onCreate()`** và idempotent trong **`MeshVpnService.onCreate()`**; R8 keep `-keep,includedescriptorclasses class org.rustls.platformverifier.** { *; }` | Đảm bảo Always-On VPN / Direct Boot chạy nền có sẵn `JavaVM` + `Context` (`init_hosted` trong `mesh-crypto` qua `mesh-sys::jni_android`) để không `SIGABRT` khi TLS `SystemCa` (`BLK-MOB-G2-01`). |
| **Chẩn đoán & Bảo mật UI** | `FLAG_SECURE` trên màn hình Onboarding/Pin/Key; `ClipboardManager.clearPrimaryClip()` (API 33+); `BiometricPrompt` (`US-085` Should) | `FileProvider` nội bộ chia sẻ **`diagnostics/mesh-bugreport-{ts}.tar` (`<= 1 MiB`)** | Chống chụp màn hình `mpk_*`, xóa clipboard sau đọc, `0` leak `mpk_*`/key qua `logcat`, `java.lang.String` dài hạn hay Share Intent (`T-MOB-07`, `HR-MOB-G2-03/04`). |

---

## 8. Tech Stack Chi tiết Nền tảng iOS (`mobile/ios/`)

| Hạng mục | Quyết định công nghệ chốt | Phiên bản / Cấu hình | Lý do & Tham chiếu yêu cầu |
|---|---|---|---|
| **Ngôn ngữ & Nền tảng** | **Swift `6`** (`SWIFT_STRICT_CONCURRENCY = complete`, Swift Testing / XCTest) | **`IPHONEOS_DEPLOYMENT_TARGET = 15.0` (`iOS 15.0+`)** | Khớp 100% Gate 1 Backlog (`MED-MOB-G2-01`); Swift 6 ép data-race safety lúc biên dịch; dùng **`if #available(iOS 16.0, *)`** bật `SwiftUI.PasteButton` tránh popup pasteboard lặp trên iOS 16+, fallback nút đọc `UIPasteboard` chuẩn trên iOS 15. |
| **Quản lý Project & CI `$0`** | **`XcodeGen` (`mobile/ios/project.yml`)** + **`MeshMobileFFI.xcframework`** (`3` slices: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`) | CI `macos-latest`: build Simulator với **`CODE_SIGNING_ALLOWED=NO`** (`$0`) | Sinh `.xcodeproj` sạch hoàn toàn từ `project.yml` (không commit `.xcodeproj` xung đột git); đạt `$0` Mode theo `OQ-MOB-02`; target vật lý sẵn sàng template Entitlements khi có tài khoản `$99/năm`. |
| **Giao diện (UI)** | **SwiftUI** (`if #available(iOS 16.0, *) PasteButton` cho dán URI `mesh://join?...`, `UIActivityViewController` Share Sheet) | 0 framework UI bên thứ ba | Gọn nhẹ, tích hợp mượt `NETunnelProviderManager`, `mobile_enroll_or_rotate_node` (enroll trực tiếp từ `MeshApp`), `LocalAuthentication` (`US-092` Should). |
| **Kiến trúc 2 Tiến trình & VPN** | Main Container App (`<app_id>`) + Network Extension (`<app_id>.PacketTunnel`: **`NEPacketTunnelProvider`**) | `NEIPv4Settings` với **prefix `/32` (`"255.255.255.255"`)**, `includedRoutes` (`[overlay_cidr]` hoặc `/32` + `overlay_dns_ip/32`)<br>`NEDNSSettings(matchDomains: ["mesh.internal"])`<br>`NWPathMonitor` | `MeshApp` thực hiện `mobile_enroll_or_rotate_node` (cất identity vào Keychain + `bootstrap.toml` vào App Group, 0 `mpk_*` lọt vào `providerConfiguration`); Extension chỉ đọc Keychain + `packetFlow.readPackets`/`writePackets` (**cấm** hack dò `utun` fd), đạt App Store Review + IPv6 NAT64 Guideline 2.5 (`BLK-MOB-G2-02`, `HR-MOB-G2-02`). |
| **IPC & `bugreport` Chống Jetsam** | **App Group (`group.<bundle_id>`)** + `NETunnelProviderSession.sendProviderMessage` / `handleAppMessage` | Status IPC `<= 4 KiB`; `bugreport` streaming **`diagnostics/mesh-bugreport-{ts}.tar` (`<= 1 MiB`)** vào **`group.<bundle_id>/diagnostics/`** | Tránh nhồi `1 MiB` qua `handleAppMessage` và tránh giữ `20 MiB` `Vec<u8>` trong RAM gây nổ trần Jetsam `50 MiB` (`HR-MOB-04`, `HR-MOB-G2-04`); **0 TCP/HTTP server** trên localhost (`SEC-14`). |
| **Lưu trữ Khóa** | **iOS Keychain Access Group** (`Security.framework`) | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`<br>`kSecAttrSynchronizable = false` | Cấm đồng bộ iCloud Backup / iCloud Keychain (`T-MOB-06`); xử lý êm `errSecInteractionNotAllowed` (`-25308`) trước mở khóa đầu sau reboot (`MOB-SEC-02`). |
| **Quét mã QR (`OQ-MOB-03`)** | **`AVFoundation` (`AVCaptureMetadataOutput`)** | Native Apple SDK (**0 thư viện ngoài**) | Nhanh, miễn phí, không tăng dung lượng binary hay kéo thêm dependency giấy phép lạ. |
| **Kiểm soát Jetsam & Anti-Deadlock** | Ngân sách **`RSS <= 25 MiB`** dưới trần cứng **`~50 MiB`** (`EXC_RESOURCE`) | `os_proc_available_memory()` (`unsafe extern "C"`), `worker_threads(1)`, **`max_blocking_threads(4)`** (`keep_alive(10s)`), `MAX_CONTROL_WS_FRAME_BYTES = 256 KiB` | Mọi disk/Keychain/`NSFileCoordinator` chạy trên `spawn_blocking`; callback sự kiện sang Swift phải O(1) non-blocking tránh deadlock 1-worker (`BLK-MOB-G2-05`, `M-GNFR-01`). |

---

## 9. Danh mục Phụ thuộc Di động Được phép & Bị cấm (Bổ sung `tech-stack-decision.md §7`)

### 9.1. Thư viện Rust Mới Được phép (Bổ sung `[workspace.dependencies]` tại Wave A)

| Crate | Phiên bản | Giấy phép | Crate nội bộ được phép import | Mục đích & Ghi chú |
|---|---|---|---|---|
| `uniffi` | **`0.29.5`** (`>= 0.29.2`) | `MPL-2.0` *(Ngoại lệ `OQ-MOB-05`)* | **Chỉ `mesh-mobile-ffi`** (`features = ["tokio"]`) và **`tools/uniffi-bindgen`** (`features = ["cli"]`) | Sinh `#[unsafe(no_mangle)]` tương thích Rust `edition = "2024"` (`BLK-MOB-G2-06`) & bindings Kotlin/Swift an toàn kiểu; cô lập bằng `[bans] wrappers` + `[[licenses.exceptions]]`. |
| `rustls-platform-verifier` | `0.6` | `MIT OR Apache-2.0` | **Chỉ `mesh-crypto`** (sau feature `mobile-platform-verifier`, bọc `#[cfg(any(target_os = "android", target_os = "ios"))]`) | Xác thực CA hệ điều hành trên Android (`init_hosted` qua `mesh_sys::jni_android`) & iOS (`Security.framework`) cho `TlsAuthMode::SystemCa`. |
| **`jni`** | **`0.21`** | `MIT OR Apache-2.0` | **Chỉ `mesh-sys`** (`cfg(target_os = "android")`) | Khởi tạo/lưu `JavaVM` + `GlobalRef(applicationContext)` trong `OnceLock` tại `crates/mesh-sys/src/jni_android.rs` và cung cấp `with_attached_env_and_context` an toàn cho `mesh-crypto` (`BLK-MOB-G2-01`). |

### 9.2. Danh sách Cấm Tuyệt đối trên Mobile (`v0.2.0`)
- **Rust:** Cấm `anyhow`/`eyre` trong mọi `crates/mesh-*` (kể cả `mesh-mobile-ffi`); cấm `aws-lc-rs`, `openssl-sys`, `native-tls`, `gotatun`, `rustls-native-certs` trong target mobile; cấm `tun`/`tun-rs` nguyên khối.
- **Android:** Cấm Google Play Services ML Kit / Firebase / GMS Analytics; cấm `EncryptedSharedPreferences` (deprecated); cấm OS-wide `<intent-filter>` deep-link cho URI mang `mpk_*`; cấm mở HTTP/TCP local server.
- **iOS:** Cấm thư viện QR bên thứ ba (dùng `AVCaptureMetadataOutput`); cấm dò private `utun` fd (`getsockopt`/`sysctl`); cấm `UIWebView`/WKWebView nhúng không cần thiết; cấm `CFBundleURLSchemes` nhận `mpk_*`; cấm nhồi `bugreport` qua `handleAppMessage`.
