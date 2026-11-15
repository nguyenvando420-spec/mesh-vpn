# Mobile Architecture Decision Records (`ADR-012..019`) — Mesh VPN (`v0.2.0`)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-tech-lead` |
| Ngày | 2026-11-15 |
| Phiên bản | **1.1 (Chặng 2 — Gate 2 Revision R1)** |
| Nhánh làm việc | `feat/mobile-clients` (không chạm `main` và `v0.1.0-rc1`) |
| Trạng thái chung | **Proposed-for-Gate-2** (kế thừa và nối tiếp **`ADR-001..011`** trong [architecture-decision-record.md](./architecture-decision-record.md)) |
| Quyết định Gate 1 ràng buộc | `OQ-MOB-01` (Wave A → song song B1/B2 → C) · `OQ-MOB-02` (`$0` Mode) · `OQ-MOB-03` (QR/Paste/Manual, cấm OS deep-link `mpk_*`) · `OQ-MOB-04` (Split-Tunnel only) · `OQ-MOB-05` (`MPL-2.0` chỉ cho `uniffi*`) |
| Tài liệu đi kèm | [mobile-tech-stack-decision.md](./mobile-tech-stack-decision.md) · [mobile-coding-standards.md](./mobile-coding-standards.md) · [architecture-decision-record.md](./architecture-decision-record.md) |

---

## Mục lục (`ADR-012..019`)

| ADR | Tiêu đề | Yêu cầu / Story truy vết chính |
|---|---|---|
| [ADR-012](#adr-012) | Cấu trúc Workspace mở rộng (`mesh-client`, `mesh-mobile-ffi`, `tools/uniffi-bindgen`), Feature-Gating & Tương thích ngược `TargetOs::{Android, Ios}` | `US-075`, `US-076`, `US-099`, `M-GNFR-05/06/08` |
| [ADR-013](#adr-013) | Cầu nối FFI `UniFFI 0.29.5`, Ngoại lệ `MPL-2.0`/`anyhow` trong `deny.toml`, Giải quyết `E0453` (`unsafe_code`) & Ranh giới `.expose_secret()` | `OQ-MOB-05`, `US-079`, `US-076`, `M-GNFR-06` |
| [ADR-014](#adr-014) | Xác thực TLS Di động (`SpkiPinVerifier` + `rustls-platform-verifier`), Khởi tạo JNI `Context` (`jni = "0.21"`) & Mạng IPv6-only NAT64 (`Guideline 2.5`) | `MOB-SEC-03`, `MOB-REL-02`, `US-077/078`, `M-GNFR-09` |
| [ADR-015](#adr-015) | Split-Tunnel Di động (`OQ-MOB-04`), Split-DNS `.mesh.internal` chuẩn RFC 4074 (kèm Bounded TCP `:53` Responder) & Chống Routing Loop / Private DNS `:853` | `OQ-MOB-04`, `MOB-PLAT-AND-02/05`, `MOB-PLAT-IOS-04/05`, `US-080/081/083/089/090`, `M-GNFR-03/04` |
| [ADR-016](#adr-016) | Bộ định thời Idle-Aware (`RRC_IDLE`) & Ngân sách RAM Di động Chống iOS Jetsam (`<= 25 MiB` RSS) / Android `lmkd` (`<= 48 MiB`) | `MOB-PERF-01/02/03`, `MOB-REL-03`, `US-077/079/082/089`, `M-GNFR-01/02/07` |
| [ADR-017](#adr-017) | Kiến trúc Nền tảng Android (`Kotlin 2.1+`, `Jetpack Compose`, `VpnService specialUse`, Android Keystore DEK, QR `zxing-core`, NDK `16 KB`) | `OQ-MOB-02/03`, `MOB-SEC-01`, `MOB-PLAT-AND-01..06`, `US-081..086` |
| [ADR-018](#adr-018) | Kiến trúc Nền tảng iOS (`Swift 6`, `iOS 15.0+`, `SwiftUI`, `NEPacketTunnelProvider`, Keychain `ThisDeviceOnly`, `XcodeGen`, CI `$0` vs Sign-off `$99/năm`) | `OQ-MOB-02/03`, `MOB-SEC-02`, `MOB-PLAT-IOS-01..06`, `US-087..093` |
| [ADR-019](#adr-019) | Onboarding Di động An toàn (`mesh://join` URI & QR `--emit-uri`/`--qr` từ CLI `mesh`, Cấm Deep-Link `mpk_*`), Chẩn đoán Không-TCP & Lọc Bí mật | `OQ-MOB-03`, `MOB-SEC-04/05/06`, `MOB-OPS-04`, `US-080/084/091/096` |

---

<a id="adr-012"></a>
## ADR-012 — Cấu trúc Workspace mở rộng (`mesh-client`, `mesh-mobile-ffi`, `tools/uniffi-bindgen`), Feature-Gating & Tương thích ngược `TargetOs`

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-15

### Context
- Kiểm toán mã nguồn thực tế (`BLK-MOB-01`) chỉ ra toàn bộ Client Control Plane (`crates/meshd/src/control_loop.rs` ~3.641 dòng, `netmap_cache.rs`, `roaming_loop.rs`, `ping_probe.rs`, `config.rs`) hiện nằm bên trong binary crate `crates/meshd` và nhập trực tiếp `FileHostsEditor`, `ResourceLedger`, `StdCommandExecutor` (`control_loop.rs:49-52`). Thư viện FFI không thể depend vào binary crate `meshd`.
- `crates/mesh-crypto/Cargo.toml` (`[V]`: dòng 19, 22) đang kéo cứng `rcgen` và `rustls-native-certs` (không hỗ trợ Android/iOS). `crates/mesh-net/Cargo.toml` (`[V]`: dòng 17, 20-21, 32) đang kéo cứng `axum`, `hyper`, `hyper-util`, `windows-service` và `crates/mesh-net/src/route.rs:260-382` chưa có nhánh `#[cfg]` cho `android`/`ios` (gây lỗi biên dịch `E0308`).
- `crates/mesh-proto/src/control.rs:27-34` chỉ có `TargetOs::{Darwin, Windows, Linux}`; `crates/mesh-server/src/control_handlers.rs:1758-1763` match toàn diện trên `TargetOs`; `crates/mesh-datapath/src/relay_client.rs:1879-1892` (`current_target_os_str`) và `crates/meshd/src/control_loop.rs:2771-2779` (`current_target_os`) fallback cứng `"linux"`/`TargetOs::Linux` ngoài macOS/Windows.

### Options
1. **Phương án A — Tạo crate thư viện OS-neutral `crates/mesh-client` + crate FFI `crates/mesh-mobile-ffi` + công cụ workspace `tools/uniffi-bindgen`, kèm feature-gate cho `mesh-crypto`/`mesh-net`/`mesh-datapath` (CHỌN)**:
   - Tách rạch ròi: `mesh-client` thuần Rust OS-neutral (chạy được cả unit test in-memory không cần quyền admin/device), `meshd` trở thành vỏ daemon Desktop mảnh, `mesh-mobile-ffi` đóng gói giao diện UniFFI cho Android/iOS, và `tools/uniffi-bindgen` giữ đồng nhất checksum UniFFI mà không nhét `uniffi_bindgen` vào `.so`/`.xcframework`.
2. **Phương án B — Nhét Control Plane vào `crates/mesh-datapath` hoặc copy sang `mesh-mobile-ffi`**:
   - Nhét vào `mesh-datapath` làm phình trách nhiệm (Data Plane lẫn Control Plane + WebSocket/HTTP/Cache); còn copy sang `mesh-mobile-ffi` vi phạm nguyên tắc single source of truth và gây lệch hành vi bảo mật giữa Desktop và Mobile.

### Decision
1. **Tạo 2 crate thư viện mới trong `crates/` và 1 crate công cụ trong `tools/`** (triển khai ở Wave A Chặng 3):
   - **`crates/mesh-client`**: chứa toàn bộ Client Control Plane (`control_loop`, `netmap_cache`, `roaming_loop`, `ping_probe`, `bootstrap_config` & bộ trait `ClientPlatformHooks`, `ClientStateStore`, `DnsUpstreamHook`). Cả `crates/meshd` (Desktop) và `crates/mesh-mobile-ffi` (Mobile) đều dùng chung 100% logic từ `mesh-client`. **`crates/mesh-client/Cargo.toml` giữ `toml` nhưng loại bỏ hoàn toàn `reqwest`** (`0 reqwest`, `HR-MOB-G2-01`).
   - **`crates/mesh-mobile-ffi`**: `crate-type = ["cdylib", "staticlib", "lib"]`, cung cấp lớp bọc vòng đời `MobileEngine`, `mobile_enroll_or_rotate_node`, `MobilePendingJoinSession`, callback interface `PlatformNetworkBridge`, `PacketFlowAdapter` (adapter nội bộ cài `TunDevice`), RFC 4074 Split-DNS Responder (kèm Bounded TCP `:53` Responder) và bộ phân tích URI `mesh://join`. Trên Android gọi `mesh_sys::ensure_jni_symbols_linked()` để giữ biểu tượng JNI.
   - **`tools/uniffi-bindgen`** (`package.name = "mesh-uniffi-bindgen"`): workspace member ngoài `crates/mesh-*`, chỉ chứa `fn main() { uniffi::uniffi_bindgen_main(); }` với `uniffi = { workspace = true, features = ["cli"] }`. Nhờ nằm tách biệt, `mesh-mobile-ffi` KHÔNG bật feature `"cli"` nên `.so`/`.xcframework` không bao giờ kéo `uniffi_bindgen`/`goblin`/`askama`.
2. **Cấu hình Feature Flags bảo toàn 100% `v0.1.0` Desktop/Server**:
   - **`mesh-crypto`**: `default = ["desktop-certs", "certgen"]`, `desktop-certs = ["dep:rustls-native-certs"]`, `certgen = ["dep:rcgen"]`, `mobile-platform-verifier = ["dep:rustls-platform-verifier"]`. Mã dùng `rustls-platform-verifier` được bọc trong `#[cfg(any(target_os = "android", target_os = "ios"))]` để `--all-features` Desktop (`scripts/check.{ps1,sh}`) luôn biên dịch xanh mà không kéo Android/Apple SDK (`BLK-MOB-G2-06`). Bản build mobile dùng `default-features = false, features = ["mobile-platform-verifier"]`.
   - **`mesh-net`**: `default = ["desktop-os"]`, `desktop-ipc = ["dep:axum", "dep:hyper", "dep:hyper-util"]`, `desktop-os = ["desktop-ipc", "dep:windows-service"]`. Khi `desktop-os` tắt, chỉ biên dịch các module OS-neutral (`endpoint_filter`, `tun` traits, `netmon` traits, `keystore` traits, `route` underlay helpers với nhánh `#[cfg(any(target_os = "android", target_os = "ios"))]` mới trong `route.rs`).
   - **`mesh-datapath`**: `default = ["desktop-os"]`, `desktop-os = ["mesh-net/desktop-os"]`.
   - **`mesh-client`**: `default = ["desktop-os"]`, `desktop-os = ["mesh-net/desktop-os", "mesh-datapath/desktop-os"]`.
3. **Mở rộng `TargetOs` giữ tương thích ngược `v0.1.0-rc1`**:
   - Bổ sung `TargetOs::Android` (`"android"`) và `TargetOs::Ios` (`"ios"`) vào `crates/mesh-proto/src/control.rs`.
   - Cập nhật `mesh-server/src/control_handlers.rs::os_label()`, `RelayClient::current_target_os_str()`, và `mesh-client::current_target_os()`.
   - Giữ nguyên `protocol_version = 1`, schema `redb` (`os_arch: String`), và giữ nguyên `NetmapSnapshot`/`PeerEntry` (`#[serde(deny_unknown_fields)]`, không chứa `os`/`arch`) → Desktop `v0.1.0-rc1` tương thích 100% không cần nâng cấp.

### Consequences
- **(+) Tích cực**: Một lõi Control + Datapath duy nhất cho 5 nền tảng (Windows, macOS, Linux, Android, iOS); đồ thị build mobile sạch 0 byte `axum`/`redb`/`rcgen`/`rustls-native-certs`; `meshd` giữ xanh 100% regression tests.
- **(−) Chi phí / Giảm thiểu**: Wave A cần refactor cẩn thận `crates/meshd/src/` sang `crates/mesh-client/src/` với lớp trait `ClientPlatformHooks` → khóa cứng hợp đồng trait này trong tài liệu Architecture của `architect-mob` trước khi code Wave A.

---

<a id="adr-013"></a>
## ADR-013 — Cầu nối FFI `UniFFI 0.29.5`, Ngoại lệ `MPL-2.0`/`anyhow` trong `deny.toml`, Giải quyết `E0453` & Ranh giới `.expose_secret()`

- **Trạng thái**: Proposed-for-Gate-2 (thực thi quyết định `OQ-MOB-05` của Người dùng)
- **Ngày**: 2026-11-15

### Context
- Tại Gate 1 (`OQ-MOB-05`), Người dùng đã chốt mở ngoại lệ `MPL-2.0` giới hạn riêng cho nhóm crate `uniffi*` ở lớp FFI mobile, đồng thời giữ 100% permissive cho `mesh-server`, `meshd`, `mesh` và các crate lõi.
- Có 4 hố bẫy kỹ thuật thực tế trong repo cần giải quyết đồng bộ:
  1. **`anyhow` trap (`deny.toml:81`)**: `uniffi_core` và `uniffi_bindgen` phụ thuộc `anyhow`, trong khi `deny.toml:81` đang chặn toàn cục `{ name = "anyhow" }`.
  2. **`unsafe_code = "forbid"` (`E0453`), floor `uniffi >= 0.29.2` & `scripts/check.ps1:93` (`check.sh:66`)**: Trong Rust `1.94.1` (`edition = "2024"`), các bản `uniffi < 0.29.2` sinh `#[no_mangle]` bị từ chối cứng (bắt buộc **`uniffi >= 0.29.5`** để sinh `#[unsafe(no_mangle)]`), và các block `extern "C"` trong `mesh-sys` phải là `unsafe extern "C"`. Nếu `crates/mesh-mobile-ffi/Cargo.toml` dùng `[lints] workspace = true` (`unsafe_code = "forbid"`), `rustc` báo lỗi **`E0453`**. Ngược lại, không được cho phép viết `unsafe` tùy tiện trong `mesh-mobile-ffi` hay `tools/`.
  3. **`.expose_secret()` allowlist (`scripts/check.ps1:100-109`, `check.sh:75-85`)**: Hiện chỉ cho phép `.expose_secret()` trong `mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`.
  4. **`scripts/check.{ps1,sh}` phạm vi quét & `-Cross` (`BLK-MOB-G2-06`)**: Hiện chỉ quét `crates/`, bỏ sót `tools/` & `mobile/`, và lệnh `-Cross` (`zigbuild`/`clippy`) trên Desktop sẽ gãy nếu chạy qua `mesh-mobile-ffi` và `mesh-uniffi-bindgen`.

### Options
1. **Phương án A — Cô lập `UniFFI 0.29.5` bằng `[[licenses.exceptions]]` + `[bans] wrappers` khớp đúng `Cargo.lock`; tách `[lints]` riêng cho `mesh-mobile-ffi` nhưng GIỮ NGUYÊN rule cấm `unsafe` viết tay ngoài `crates/mesh-sys/*`; giữ nguyên `.expose_secret()` và cập nhật `scripts/check.{ps1,sh}` `-Cross` `--exclude` (CHỌN)**:
   - Giải quyết triệt để `E0453` cho macro mở rộng của UniFFI, vẫn đảm bảo **0 dòng `unsafe` viết tay** trong `mesh-mobile-ffi` & `tools/`, **0 `anyhow`** trong mọi `crates/mesh-*`, **0 cảnh báo `cargo-deny 0.20.2`**, và **0 mở rộng `.expose_secret()`**.
2. **Phương án B — Nới lỏng `scripts/check.{ps1,sh}` cho phép `unsafe` và `.expose_secret()` trong `mesh-mobile-ffi`**:
   - Làm suy yếu hàng rào bảo vệ `SEC-01` và an toàn bộ nhớ của workspace mà không cần thiết.

### Decision
1. **Cấu hình `deny.toml` (`cargo-deny 0.20.2`) dự thảo cho Wave A**:
   - `[graph].targets`: bổ sung `aarch64-linux-android`, `x86_64-linux-android`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`.
   - `[licenses].allow`: **KHÔNG thêm `MPL-2.0`** (giữ `gotatun` bị cấm). Dùng `[[licenses.exceptions]]` với cú pháp `crate = "..."` và `allow = ["MPL-2.0"]` **chỉ liệt kê đúng tập `uniffi*` thực tế có mặt trong `Cargo.lock`** (tỉa sạch các crate `uniffi_*` không dùng tại `WP-M-A0` để đạt `0` `warning[license-exception-not-encountered]`, `MED-MOB-G2-03`).
   - `[bans].deny`:
     - Thay `{ name = "anyhow" }` bằng `{ name = "anyhow", wrappers = [<đúng các crate uniffi* trong Cargo.lock>], reason = "..." }` — bất kỳ `crates/mesh-*` nào (kể cả `mesh-mobile-ffi`) tự import `anyhow` sẽ bị `cargo deny` chặn ngay!
     - Thêm quy tắc `wrappers = ["mesh-mobile-ffi", "mesh-uniffi-bindgen", ...]` cho chính các crate `uniffi*` để **cấm mọi crate lõi/desktop/server depend vào `uniffi*`**.
     - Thêm `jni = "0.21"` (`MIT OR Apache-2.0`, `cfg(target_os = "android")`) chỉ dùng bên trong `crates/mesh-sys` (`BLK-MOB-G2-01`).
2. **Giải quyết `E0453` & `edition = "2024"` mà KHÔNG nới lỏng `unsafe` viết tay**:
   - Khóa **`uniffi = "0.29.5"`** (`>= 0.29.2`) trong `[workspace.dependencies]`.
   - `crates/mesh-mobile-ffi/Cargo.toml` **KHÔNG** đặt `[lints] workspace = true`; thay vào đó khai báo `[lints.rust]` (`unsafe_code = "allow"`, `unsafe_op_in_unsafe_fn = "deny"`, `missing_debug_implementations = "warn"`, `unreachable_pub = "warn"`) + toàn bộ `[lints.clippy]` nghiêm ngặt (`undocumented_unsafe_blocks = "deny"`, `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`, `indexing_slicing = "deny"`, `let_underscore_must_use = "deny"`, `await_holding_lock = "deny"`, `print_stdout = "deny"`, `print_stderr = "deny"`, `wildcard_imports = "deny"`) — đồng bộ 100% với `crates/mesh-sys/Cargo.toml`.
   - **QUY TẮC CỨNG:** `scripts/check.{ps1,sh}` **MỞ RỘNG** quét tĩnh sang `crates/`, `tools/` và `mobile/` (`tools/` cũng bị cấm `unsafe` và `.expose_secret()`), giữ nguyên quy tắc cấm 100% từ khóa `unsafe` viết tay ngoài `crates/mesh-sys/*`. Mọi OS FFI thô của mobile — gồm `adopt_raw_tun_fd(raw_fd: i32)` (`FromRawFd::from_raw_fd`), `jni_android.rs` (`Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier`, 0 phụ thuộc TLS trong `mesh-sys`), `memory_ios.rs` (`unsafe extern "C" { fn os_proc_available_memory() -> usize; }` với fallback `usize::MAX` ngoài iOS), `disable_ipv4_dont_fragment` Android/iOS — **bắt buộc đặt trong `crates/mesh-sys`** kèm `// SAFETY:` comment đầy đủ!
   - Cập nhật `scripts/check.{ps1,sh}` chế độ `-Cross` / `--cross`: thêm `--exclude mesh-mobile-ffi --exclude mesh-uniffi-bindgen` cho các lệnh `zigbuild`/`clippy` Desktop để không sinh cảnh báo `cdylib` trên `musl` và không lỗi cross-target Desktop.
3. **Bảo toàn Allowlist `.expose_secret()` (`scripts/check.ps1:100-109`)**:
   - Kiểm chứng mã thực tế cho thấy `crates/meshd/src/` gọi `0` lần `.expose_secret()` (mọi thao tác mật mã/keystore đều đóng gói trong `mesh-crypto`, `mesh-datapath`, `mesh-net::keystore`).
   - Do đó, **`mesh-client` và `mesh-mobile-ffi` KHÔNG cần gọi `.expose_secret()`**: việc chuyển đổi/bọc khóa giữa OS Keystore DEK / iOS Keychain (`[u8; 32]`) với `NodeKeypair`/`DiscoKeypair` và `PreAuthToken` đi qua hàm đóng gói chuyên biệt trong **`crates/mesh-crypto`** hoặc **`crates/mesh-net::keystore`** (cùng mẫu `certgen.rs`), giữ nguyên vẹn allowlist 4 crate (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`) trong `scripts/check.{ps1,sh}`.

### Consequences
- **(+) Tích cực**: Tuân thủ tuyệt đối `OQ-MOB-05`, đóng triệt để `BLK-MOB-G2-01/06` & `MED-MOB-G2-03`, giữ hàng rào zero-`unsafe` & zero-`anyhow` & zero-`.expose_secret()` cho mọi code mới ở tầng FFI, `tools/` và Client Control Plane.
- **(−) Chi phí / Giảm thiểu**: Mỗi lần nâng patch `uniffi`, cần đối chiếu lại `Cargo.lock` để tỉa/bổ sung danh sách trong `deny.toml` và chạy ngay `cargo deny check` trên cả 5 mobile targets.

---

<a id="adr-014"></a>
## ADR-014 — Xác thực TLS Di động (`SpkiPinVerifier` + `rustls-platform-verifier`), Khởi tạo JNI `Context` Sớm & Mạng IPv6-only NAT64

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-15

### Context
- `rustls-native-certs` không hỗ trợ Android và iOS (`MOB-SEC-03`). Thực tế mã nguồn `rustls-platform-verifier 0.6` trên Android **không tự đọc `ndk-context`**, mà bắt buộc gọi `rustls_platform_verifier::android::init_hosted(&mut env, context)` (hoặc `init_external`), đi kèm crate `jni`, local Maven artifact `rustls:rustls-platform-verifier`, và R8 keep rule — nếu bỏ sót, lần kết nối TLS `SystemCa` đầu tiên sẽ `panic!` gây **`SIGABRT`** dưới `panic = "abort"` (`BLK-MOB-G2-01`). Đồng thời `scripts/check.{ps1,sh}` cấm `unsafe` ngoài `crates/mesh-sys/*`.
- Trên mạng 4G/5G **IPv6-only NAT64 (`64:ff9b::/96`)**, cấu hình mặc định của Mesh VPN dùng IPv4 literal + SPKI Pin (`SEC-04(c)`). Không chỉ `RelayClient::connect_tls_transport` (`relay_client.rs:1002`), `StunClient` (`stun_client.rs:161,417`) và `MagicSocket` (`magic_socket.rs:464`), mà cả `probe_udp_routing_candidates` (`control_loop.rs:2197`) và `PingProbe::execute_netcheck` (`ping_probe.rs:154,225,444`) đều cần `SocketProtector` + `Nat64Synthesizer` để tránh `ENETUNREACH` và routing loop (`BLK-MOB-02`, `HR-MOB-G2-01`).

### Options
1. **Phương án A — Giữ `SpkiPinVerifier` cho IP+Pin (kể cả qua NAT64) + dùng `rustls-platform-verifier 0.6` (`ring`) + `jni = "0.21"` trong `crates/mesh-sys/src/jni_android.rs` + `Nat64Synthesizer` (OS Pref64 + RFC 7050 `ipv4only.arpa`) trên mọi đường socket (CHỌN)**:
   - Không kéo `openssl-sys`/`aws-lc-rs`, tôn trọng quy tắc 0 `unsafe` ngoài `mesh-sys`, vượt qua mạng IPv6-only NAT64, và giữ 100% fail-closed SPKI Pin.
2. **Phương án B — Dùng `webpki-roots` tĩnh cho Domain+CA hoặc dựa vào `ndk-context`**:
   - `webpki-roots` bỏ qua CA nội bộ/doanh nghiệp và kiểm tra thu hồi OS; `ndk-context` không khởi tạo được `OnceLock` của `rustls-platform-verifier 0.6` gây `SIGABRT`.

### Decision
1. **TLS Dual-Mode (`mesh-crypto`)**:
   - **IP + SPKI Pin (Mặc định):** Luôn dùng `SpkiPinVerifier` (`x509-cert` + `ring` + `subtle`), fail-closed khi thiếu pin, cấm TOFU, phân biệt rõ `PinMismatch` / `ClockSkew` / `CaptivePortalSuspected` (`BACKOFF_TLS_MAX_MS = 300_000 ms`).
   - **Domain + System CA (`TlsAuthMode::SystemCa`):** Trên mobile (feature `mobile-platform-verifier`, bọc `#[cfg(any(target_os = "android", target_os = "ios"))]`), dùng **`rustls-platform-verifier` `0.6`** với `ring` provider (cấm `aws-lc-rs`). Khi có thêm `PinSet`, bọc `SpkiPinVerifier` ngoài kiểm tra của `rustls-platform-verifier` (kiểm tra đồng thời cả CA chuỗi lẫn SPKI Pin).
2. **Khởi tạo JNI `Context` An toàn trên Android (`BLK-MOB-G2-01`, `MOB-SEC-03 (3)`)**:
   - **Bỏ hoàn toàn `ndk-context`**; bổ sung **`jni = "0.21"`** (`cfg(target_os = "android")`) chỉ cho `crates/mesh-sys`.
   - `crates/mesh-sys/src/jni_android.rs` giữ duy nhất entrypoint JNI:
     `#[unsafe(no_mangle)] pub unsafe extern "system" fn Java_dev_meshvpn_android_ffi_MeshNativeInit_initPlatformVerifier(...) -> jboolean`
     (lưu `JavaVM` + `GlobalRef(applicationContext)` idempotent vào `OnceLock`, không panic) và hàm an toàn `with_attached_env_and_context`. **`mesh-sys` không có phụ thuộc TLS.**
   - **`crates/mesh-crypto`** gọi `rustls_platform_verifier::android::init_hosted(env, context)` bên trong `with_attached_env_and_context` (**0 `unsafe` trong `mesh-crypto`**). **`crates/mesh-mobile-ffi`** gọi `mesh_sys::ensure_jni_symbols_linked()` để linker giữ symbol JNI.
   - Kotlin nạp `System.loadLibrary("mesh_mobile_ffi")` và gọi `MeshNativeInit.initPlatformVerifier(applicationContext)` **idempotent** tại cả **`MeshApplication.onCreate()`** lẫn **`MeshVpnService.onCreate()`** (cho Always-On VPN / Direct Boot).
   - Gradle `mobile/android/` cấu hình local **`maven`** repository trỏ tới `rustls-platform-verifier-android` AAR (tra qua `cargo metadata`) và thêm R8 rule **`-keep,includedescriptorclasses class org.rustls.platformverifier.** { *; }`**.
3. **Tổng hợp NAT64 (`Nat64Synthesizer`) & Bao phủ 100% Đường Socket (`HR-MOB-G2-01`)**:
   - Truyền `Arc<dyn SocketProtector>` + `Nat64Synthesizer` đồng bộ cho **tất cả** đường kết nối: Control TLS TCP, `RelayClient` WSS TCP (kể cả đọc `ErrorEnvelope` HTTP `400` trong `RelayClient::map_http_status_error` để chuyển sạch sang `ProtocolIncompatible`/`ServerUpgradeRequired`), `StunClient::resolve_stun_target_addrs`, `MagicSocket`, `probe_udp_routing_candidates` (`control_loop.rs:2197`), `PingProbe::execute_netcheck` (`ping_probe.rs:154,225,444`, cả UDP lẫn TCP) và DNS upstream forwarder.
   - Khi underlay là IPv6-only hoặc gặp `ENETUNREACH`/`EHOSTUNREACH`, tổng hợp IPv6 theo `Pref64` từ OS (`LinkProperties.getNat64Prefix()` / `NWPath` Pref64) hoặc fallback RFC 7050 `AAAA ipv4only.arpa` (`64:ff9b::/96`), giữ nguyên `ServerName::IpAddress(ipv4)` cho `SpkiPinVerifier`.

### Consequences
- **(+) Tích cực**: Kết nối trơn tru trên mạng di động IPv6-only NAT64 với cấu hình IP+Pin mặc định; đạt chuẩn Apple App Store Guideline 2.5; Always-On VPN Android xác thực TLS không lỗi thiếu `JNIEnv`.
- **(−) Chi phí / Giảm thiểu**: Cần bộ kiểm thử mô phỏng NAT64 (`64:ff9b::/96` prefix) trong Wave A & Wave C (`US-094 AC2`, `US-095 AC1`).

---

<a id="adr-015"></a>
## ADR-015 — Split-Tunnel Di động (`OQ-MOB-04`), Split-DNS `.mesh.internal` chuẩn RFC 4074 & Chống Routing Loop

- **Trạng thái**: Proposed-for-Gate-2 (thực thi quyết định `OQ-MOB-04` của Người dùng)
- **Ngày**: 2026-11-15

### Context
- `OQ-MOB-04` khóa cứng `v0.2.0` chỉ hỗ trợ **Split-Tunnel** (overlay CIDR động từ `NetmapSnapshot` + `.mesh.internal`), hoãn Exit Node (`0.0.0.0/0`) sang `v0.3.0`.
- Phản biện Gate 1 (`BLK-MOB-03`) phát hiện 5 lỗ hổng kinh điển của Split-DNS trên di động: (1) trả `NXDOMAIN` cho truy vấn `AAAA` của tên `.mesh.internal` khiến `mDNSResponder` (iOS) / `netd` (Android) gãy Happy Eyeballs; (2) `CryptokeyValidator` drop gói L3 đi tới `overlay_dns_ip:53` nếu không tách trước; (3) Android 9+ Private DNS probe TCP `:853` gây timeout hoặc rò ra DoT Strict; (4) forward DNS công cộng qua đường hầm tạo loop nếu không đọc DNS từ mạng vật lý; (5) thiếu `protect(fd)` đồng bộ gây routing loop.

### Options
1. **Phương án A — Embedded RFC 4074 DNS Responder tách L3 trước `CryptokeyValidator` + `SocketProtector` đồng bộ 100% + Android `:853` `TCP RST` & `LinkProperties` + iOS `NEDNSSettings` (CHỌN)**.
2. **Phương án B — Chỉnh `/etc/hosts` hoặc bỏ qua DNS `:53` chỉ dùng IP**: Không thể thực hiện trên Android/iOS non-root và phá vỡ trải nghiệm `nas.mesh.internal`.

### Decision
1. **Chỉ Split-Tunnel & Giao diện TUN luôn đặt Prefix `/32` (`OQ-MOB-04`, `HR-MOB-G2-02`)**:
   - **Prefix giao diện TUN là `/32`:** Trên cả Android (`VpnService.Builder.addAddress(local_overlay_ip, 32)`) lẫn iOS (`NEIPv4Settings(addresses: [local_overlay_ip], subnetMasks: ["255.255.255.255"])`), **BẮT BUỘC đặt `/32`** thay vì prefix `/16` của `overlay_cidr` để nhân Linux/XNU **không** tự cài implicit connected route `/16` vào `tun0`/`utunN`.
   - Phạm vi định tuyến kiểm soát 100% qua danh sách route (`addRoute` trên Android, `includedRoutes` trên iOS, `MTU = 1280`, **tuyệt đối không** thêm `0.0.0.0/0`):
     - Bình thường: cài `[overlay_cidr]`.
     - Khi phát hiện trùng LAN/CGNAT `100.64.0.0/10` (`US-037`): thu hẹp xuống danh sách `[peer_ip/32..., overlay_dns_ip/32]` — **bắt buộc luôn kèm `overlay_dns_ip/32`** để Split-DNS không bị rò ra gateway vật lý!
   - Khi `VpnService.isLockdownEnabled() == true` (API 29+), duy trì `protect(fd)` và hiển thị cảnh báo nổi bật trên Notification & UI (`G4`).
2. **Tách gói L3 tới `overlay_dns_ip:53` (và `:853`) trước `CryptokeyValidator` + Bounded L3 TCP `:53` Responder (`BLK-MOB-G2-03`)**:
   - Địa chỉ `overlay_dns_ip` được chọn sao cho không trùng bất kỳ `OverlayIp` của peer nào và **không trùng với bất kỳ IP vật lý / `underlay_dns_servers` nào** (nếu trùng thì dịch sang địa chỉ cuối dải `nth_usable_ip(usable_host_count() - 1 - k)`), và khai báo làm DNS server của TUN.
   - Ở tầng đọc gói L3 thô ra từ TUN (`tun_fd` / `PacketFlowAdapter`), kiểm tra header IPv4 trước khi đưa vào `CryptokeyValidator` / `PeerMap::encapsulate`:
     - **UDP `:53`** tới `overlay_dns_ip:53`: đưa thẳng vào **Embedded Split-DNS Responder** trong `mesh-mobile-ffi`; khi forward UDP ra upstream vật lý luôn đính kèm/tôn trọng **EDNS0 `1232 B`** để `99.9%` truy vấn vừa khít 1 gói UDP mà không cần fallback TCP.
     - **TCP `:53` (`BLK-MOB-G2-03`)**: KHÔNG xử lý bằng "đọc 2-byte framing từ 1 gói L3 đơn lẻ" và KHÔNG kéo `smoltcp`. Chốt **Bounded Single-Transaction L3 TCP `:53` Responder** thuần Rust trong `mesh-mobile-ffi`: bảng LRU tối đa **`16` phiên**, TTL **`3_000 ms`**, thực thi máy trạng thái gọn `SYN -> SYN|ACK -> PSH|ACK -> FIN|ACK` nhận đúng **`1` giao dịch DNS / kết nối** (`request <= 1_232 B`, `response <= 4_096 B`), phân mảnh MSS `<= 1_240 B`; khi hết slot LRU, quá hạn hoặc gói sai trạng thái trả ngay **`TCP RST|ACK`** (đáp ứng trọn vẹn `US-080 AC1/AC3`).
     - **TCP `:853`** (`SYN` Android `netd` Opportunistic Private DNS probe): tổng hợp ngay **`TCP RST|ACK`** trả ngược về TUN với độ trễ `~0 ms` để Android hạ cấp tức thì về `:53`.
3. **Tuân thủ RFC 4074 §3 tuyệt đối (`BLK-MOB-03`)**:
   - Tên miền kết thúc bằng `.mesh.internal` (`domain_suffix` từ `NetmapSnapshot`):
     - Nếu hostname tồn tại trong `NetmapSnapshot`: `A` → trả `OverlayIp` (`TTL = 30 s`); **`AAAA` (và mọi QTYPE hợp lệ chưa có bản ghi như `HTTPS`/`SVCB`) → trả `RCODE = 0` (`NOERROR`), `ANCOUNT = 0` (`NODATA`) kèm SOA tối giản chuẩn RFC 4074 §3** — tuyệt đối không trả `NXDOMAIN`!
     - Nếu hostname không tồn tại → trả `NXDOMAIN` (`RCODE = 3`).
     - Truy vấn `PTR` trong `overlay_cidr` → trả FQDN `<node>.mesh.internal` (hoặc `NXDOMAIN` nếu không có).
   - Truy vấn ngoài `.mesh.internal` trên Android: đọc danh sách DNS upstream từ `LinkProperties.getDnsServers()` của mạng vật lý underlay hiện hành (lọc bỏ `overlay_dns_ip`, xử lý cả IPv4 và IPv6) và chuyển tiếp qua socket đã gọi `SocketProtector::protect(fd)` đồng bộ, trả `SERVFAIL` gọn khi timeout. Trên iOS, `NEDNSSettings(servers: [overlay_dns_ip])` với `matchDomains = ["mesh.internal"]` chỉ dẫn `.mesh.internal` vào `packetFlow`.
   - Kiểm tra `LinkProperties.isPrivateDnsActive()` trên Android: nếu bật **Strict Private DNS**, hiển thị cảnh báo rõ trên UI/Notification.
4. **`SocketProtector` Fail-Closed trên Android (`MOB-PLAT-AND-02`, `BLK-MOB-G2-05`)**:
   - Mọi socket underlay (`MagicSocket`, Control TLS, Relay WSS, STUN, `probe_udp_routing_candidates`, `PingProbe`, DNS upstream forwarder, RFC 7050 `ipv4only.arpa`) bắt buộc gọi `SocketProtector::protect(raw_fd)` **đồng bộ trực tiếp ngoài mọi Rust lock** trước `connect()`/`send_to()` (**cấm** đẩy vào `spawn_blocking` dùng chung với `getaddrinfo`). Nếu trả `false` hoặc lỗi → đóng socket tức thì (fail-closed).

### Consequences
- **(+) Tích cực**: `0` routing loop, `0` rò rỉ `.mesh.internal` ra DNS nhà mạng/ISP, Happy Eyeballs hoạt động chuẩn xác trên cả Safari/Chrome/SSH mobile, và mở Captive Portal bình thường.
- **(−) Chi phí / Giảm thiểu**: Cần viết bộ kiểm thử gói DNS raw (`A`, `AAAA` `NODATA`, `PTR`, `TCP :53`, `TCP :853 RST`, `proptest!` fuzzing parser DNS) trong `mesh-mobile-ffi` (Wave A).

---

<a id="adr-016"></a>
## ADR-016 — Bộ định thời Idle-Aware (`RRC_IDLE`) & Ngân sách RAM Chống iOS Jetsam (`<= 25 MiB` RSS)

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-15

### Context
- Hai rủi ro tài nguyên nghiêm trọng được phát hiện ở Gate 1 (`HR-MOB-03`, `HR-MOB-04`):
  1. `DatapathEngine` (`crates/mesh-datapath/src/engine.rs:38-39`) đặt tick cố định `250 ms` (`8 Hz` = `28.800` wakeup/giờ) và `CONTROL_HEARTBEAT_INTERVAL = 25 s` + `RELAY_KEEPALIVE_INTERVAL = 25 s` giữ modem 4G/5G kẹt ở trạng thái năng lượng cao `RRC_CONNECTED`.
  2. iOS áp đặt trần **Jetsam `~50 MiB` (`EXC_RESOURCE`)** lên `NEPacketTunnelProvider`. Giá trị Desktop `MAX_CONTROL_WS_FRAME_BYTES = 4 MiB` (`control_loop.rs:73`), `spawn_blocking` không chặn luồng DNS và đẩy `bugreport` `1 MiB` qua `handleAppMessage` (`<= 4 KiB`) sẽ gây tràn RAM tức thì.

### Options
1. **Phương án A — Timer Idle-Aware / Coalesced (`45_000 ms ± 2_000 ms`) trong `DatapathEngine` + Runtime Profile Mobile chống starvation/deadlock (`worker_threads(1)`, `max_blocking_threads(4)` iOS / `(6)` Android, `protect_socket` đồng bộ trực tiếp, `WS <= 256 KiB`) + `os_proc_available_memory()` + Streaming `.tar <= 1 MiB` (CHỌN)**.
2. **Phương án B — Giữ nguyên cấu hình Desktop trên Mobile**: Chắc chắn chạm trần Jetsam `50 MiB`, cạn pool `max_blocking_threads(2)` khi `getaddrinfo` nghẽn và vi phạm mục tiêu pin `<= 1.5%/giờ`.

### Decision
1. **Timer Idle-Aware / Coalesced (`DatapathEngine`)**:
   - Bổ sung chế độ `TimerMode::IdleAware` (bật trên mobile; Desktop giữ tương thích ngược mặc định `250 ms` hoặc cấu hình được):
     - Khi **đang có phiên hoạt động** (có gói qua TUN/socket trong cửa sổ hoạt động gần đây, hoặc đang trong quá trình WireGuard handshake/rekey, hoặc có Disco probe đang chạy): tick ở độ phân giải `250 ms`.
     - Khi **rỗi (Idle)**: tạm dừng `tokio::time::interval(250 ms)` hoàn toàn, tính thời điểm deadline thực sự kế tiếp (từ `Tunn` / `DiscoEngine` hoặc hết hạn key) và dùng `tokio::select!` chờ đồng thời `sleep_until(next_deadline)` + tín hiệu đánh thức `Notify` từ gói TUN/socket mới (`0` CPU wakeup khi thực sự nghỉ!).
   - Khi nhận `set_power_saving_mode(true)` (màn hình tắt / Doze / App Nap): đồng bộ pha (coalesce) và giãn chu kỳ heartbeat Control & Relay về **`45_000 ms` (`± 2_000 ms` jitter)** (`MED-MOB-G2-02`) — giữ biên an toàn `~15 s` dưới ngưỡng `HEARTBEAT_TIMEOUT_MS = 60_000 ms` trên `mesh-server`, và đặt kênh Relay ở chế độ kết nối theo nhu cầu để modem 4G/5G hạ về **`RRC_IDLE`**.
2. **Ngân sách RAM iOS Extension `<= 25 MiB` RSS, Android `<= 48 MiB` RSS & Chống Starvation/Deadlock (`BLK-MOB-G2-05`)**:
   - Tokio Runtime: **iOS Extension** dùng `worker_threads(1)`, **`max_blocking_threads(4)`** (`keep_alive(10s)` — thu hồi nhanh khi nhàn rỗi); **Android** dùng `worker_threads(2)`, **`max_blocking_threads(6)`**, `thread_stack_size(512 * 1024)`.
   - **Không đẩy `protect_socket(fd)` vào `spawn_blocking` dùng chung với `getaddrinfo`:** gọi `bridge.protect_socket(raw_fd)` đồng bộ trực tiếp bên ngoài mọi Rust lock (`BLK-MOB-G2-05`). Trên iOS (`worker_threads = 1`), mọi disk/Keychain/`NSFileCoordinator` I/O chạy trên `spawn_blocking`, còn mọi event callback sang Swift/Kotlin phải **O(1) non-blocking** (chỉ enqueue, cấm lock/await ngược về `MobileEngine`).
   - `MAX_CONTROL_WS_FRAME_BYTES` dùng hằng số cấu hình theo nền tảng: `4 MiB` trên Desktop, **`256 KiB` (`256 * 1024`)** trên Mobile.
   - Giữ buffer tĩnh `[u8; 2048]` (`MAX_FRAME_SIZE`) và bounded queue `256` + `try_send()`.
   - Log ring-buffer trong RAM giới hạn chặt `<= 1 MiB` (lọc đỏ trước khi lưu).
   - Trên iOS, `crates/mesh-sys/src/memory_ios.rs` bọc **`unsafe extern "C" { fn os_proc_available_memory() -> usize; }`** (`#[cfg(target_os = "ios")]`, kèm nhánh fallback `usize::MAX` ngoài iOS — `BLK-MOB-G2-06`) để vòng lặp datapath kiểm tra định kỳ khi xử lý burst: nếu bộ nhớ còn lại giảm dưới **`10 MiB`**, kích hoạt drop-tail sớm và xả bộ đệm tạm không thiết yếu để tránh `EXC_RESOURCE`.
   - `export_bugreport_to_file(path)` (**`HR-MOB-G2-04`**): Chốt **1 định dạng thống nhất duy nhất** **`diagnostics/mesh-bugreport-{ts}.tar`** với trần **`DEFAULT_MOBILE_MAX_BUGREPORT_BYTES = 1_048_576` (`1 MiB`)** trong `mesh-core::defaults`, ghi **streaming** thẳng ra `BufWriter<File>` (`8 KiB` buffer, tuyệt đối không cấp phát `Vec<u8>` `20 MiB` trong RAM như Desktop) và thay `collect_os_route_table()` (`sysexec`) bằng serialize snapshot `MobileTunnelNetworkConfig` + `MobileUnderlayState` trong RAM. **Tuyệt đối không** trả qua IPC `handleAppMessage`.

### Consequences
- **(+) Tích cực**: Giữ đỉnh RSS iOS Extension `<= 25 MiB` (biên an toàn 50% dưới Jetsam) và cho phép modem 4G/5G ngủ về `RRC_IDLE`.
- **(−) Chi phí / Giảm thiểu**: Khi iPhone/Android đang ngủ sâu trên CGNAT, gói đầu tiên đánh thức peer có thể đi qua Blind Relay trong vài trăm ms đầu trước khi Disco nâng cấp lại lên Direct UDP.

---

<a id="adr-017"></a>
## ADR-017 — Kiến trúc Nền tảng Android (`Kotlin 2.1+`, `Jetpack Compose`, `VpnService specialUse`, Android Keystore, Offline QR `zxing-core`, NDK `16 KB`)

- **Trạng thái**: Proposed-for-Gate-2
- **Ngày**: 2026-11-15

### Context
- Cần ứng dụng Android thuần không cần root, biên dịch hoàn toàn miễn phí (`$0` qua GitHub Actions `ubuntu-latest`), tương thích Android 8.0 (`API 26`) đến Android 15+ (`API 35+`), tuân thủ Foreground Service Android 14+, hỗ trợ Google Play **16 KB ELF page size**, quét QR không phụ thuộc Google Play Services độc quyền, chống Cloud/ADB Backup, và an toàn qua Direct Boot / Lockdown Mode.

### Options
1. **Phương án A — Kotlin `2.1+` + Gradle Kotlin DSL + Jetpack Compose + `VpnService` (`specialUse`) + Android Keystore `AES-256-GCM` + CameraX & `zxing-core` + NDK r27c+ `-Wl,-z,max-page-size=16384` (CHỌN)**.
2. **Phương án B — Google ML Kit Barcode Scanning + `EncryptedSharedPreferences`**: ML Kit kéo proprietary GMS binaries không chạy được trên máy AOSP/không GMS; `EncryptedSharedPreferences` đã bị Google deprecate.

### Decision
1. **Cấu trúc & SDK Android (`mobile/android/`)**:
   - `minSdk = 26`, `compileSdk = 35`, `targetSdk = 35`; Gradle Kotlin DSL (`.kts`) + `gradle/libs.versions.toml`; **Kotlin `2.1+`**, **Jetpack Compose** (Material 3, MVVM `ViewModel` + `StateFlow`).
   - Build native Rust bằng `cargo-ndk` với NDK `r27c+` cho `arm64-v8a` (`aarch64-linux-android`) và `x86_64` (`x86_64-linux-android`), truyền bắt buộc cờ linker **`-Wl,-z,max-page-size=16384`** qua `RUSTFLAGS` để đạt chuẩn **16 KB page size** của Android 15+ và kích thước mỗi `.so` `<= 6 MiB`.
2. **Vòng đời `VpnService`, Bàn giao `android_tun_fd` & Khởi tạo JNI (`BLK-MOB-G2-01/02`)**:
   - Khai báo `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_SPECIAL_USE`, `android:foregroundServiceType="specialUse"`, và `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" ...>` trong `AndroidManifest.xml`.
   - Khởi tạo `System.loadLibrary("mesh_mobile_ffi")` và gọi **`MeshNativeInit.initPlatformVerifier(applicationContext)`** (vào `crates/mesh-sys/src/jni_android.rs` qua `jni = "0.21"`, không dùng `ndk-context`) **idempotent** tại cả **`MeshApplication.onCreate()`** lẫn **`MeshVpnService.onCreate()`**.
   - Cấu hình local `maven` repository cho **`rustls-platform-verifier-android`** AAR (tra qua `cargo metadata`) trong Gradle và thêm R8 rule **`-keep,includedescriptorclasses class org.rustls.platformverifier.** { *; }`**.
   - **Vòng đời `tun_fd` (`BLK-MOB-G2-02`):** Cho phép `MobileUpConfig.android_tun_fd = None` khi chưa có cấu hình cache ban đầu; khi nhận `on_route_changed(op_id, MobileTunnelNetworkConfig)` (lần đầu nhận netmap hoặc khi đổi `overlay_cidr`/route), Kotlin gọi `VpnService.Builder.addAddress(local_overlay_ip, 32)` + `addRoute(...)` + `establish()` rồi trả descriptor mới qua **`MobileEngine::complete_route_change(op_id, ok, new_android_tun_fd, error_message)`** để `DatapathEngine` hoán đổi nguyên tử `AsyncFd<OwnedFd>` mới.
   - Lắng nghe `ConnectivityManager.NetworkCallback` (cập nhật `LinkProperties.getDnsServers()`, `isPrivateDnsActive()`, `getNat64Prefix()`, đổi mạng gọi `on_network_change` của Rust) và xử lý `VpnService.onRevoke()` teardown `<= 5 s`.
   - Direct Boot (`US-085` Should): dịch vụ gắn `directBootAware`, nếu khởi chạy lúc `LOCKED_BOOT_COMPLETED` khi `noBackupFilesDir` chưa mở khóa thì hiển thị Notification chờ mở khóa và lắng nghe `ACTION_USER_UNLOCKED` (không crash); kiểm tra `isLockdownEnabled()` cảnh báo mất Internet ngoài VPN (`G4`).
3. **Bảo mật Khóa (DEK Wrapping), Backup & QR Offline (`HR-MOB-G2-03`)**:
   - **Android Keystore (`AES-256-GCM`) bọc Master DEK 32-byte (`dek.enc`):** Không truyền JSON danh tính trần qua `Vec<u8>`/`RustBuffer`. Khi đọc/ghi, Kotlin dùng Keystore mở khóa `dekBytes = ByteArray(32)`, truyền vào `mesh-crypto` thực hiện `ChaCha20Poly1305` niêm phong/mở niêm phong và lưu **chỉ ciphertext** vào **`context.noBackupFilesDir`** (`0600`), đồng thời gọi `dekBytes.fill(0)` trong khối **`finally`**. Không dùng `EncryptedSharedPreferences`.
   - `AndroidManifest.xml` đặt `android:allowBackup="false"`, `android:dataExtractionRules` (API 31+), `android:fullBackupContent` (API 26–30).
   - Quét QR dùng **CameraX `ImageAnalysis` + `com.google.zxing:core`** (`Apache-2.0`, 100% offline mã nguồn mở).
   - Đặt `FLAG_SECURE` trên màn hình Onboarding/Pin/Key; gọi `ClipboardManager.clearPrimaryClip()` (API 33+) sau khi đọc URI `mesh://join`.

### Consequences
- **(+) Tích cực**: `.apk` chạy trực tiếp `$0` trên máy Android 8–15+ (kể cả thiết bị không Google Play Services và trang nhớ 16 KB), không crash `SIGABRT` khi dùng `SystemCa`, không kẹt vòng đời `establish()` lúc onboarding, an toàn tuyệt đối khỏi Cloud/ADB backup và rò khóa RAM.
- **(−) Chi phí / Giảm thiểu**: Yêu cầu test kỹ vòng đời Android Keystore khi khóa bị vô hiệu hóa (user xóa lockscreen) → không âm thầm sinh lại khóa mới mà báo lỗi yêu cầu re-enroll (`US-082 AC3`).

---

<a id="adr-018"></a>
## ADR-018 — Kiến trúc Nền tảng iOS (`Swift 6`, `iOS 15.0+`, `SwiftUI`, `NEPacketTunnelProvider`, Keychain `ThisDeviceOnly`, `XcodeGen`, `$0` Simulator CI)

- **Trạng thái**: Proposed-for-Gate-2 (thực thi quyết định `OQ-MOB-02` của Người dùng)
- **Ngày**: 2026-11-15

### Context
- Apple bắt buộc kiến trúc 2 tiến trình (Main App + `NEPacketTunnelProvider`), giới hạn Network Extension ở `~50 MiB` Jetsam, cấm truy cập `utun` fd qua private API, và chỉ cấp entitlement `packet-tunnel-provider` cho tài khoản Apple Developer Program trả phí (`$99/năm`).
- Tại Gate 1 (`OQ-MOB-02`), Người dùng quyết định **chưa chi `$99/năm` ngay (`$0` Mode)**: hoàn thiện đầy đủ mã nguồn + `.xcframework` + build & unit test trên iOS Simulator (`CODE_SIGNING_ALLOWED=NO`, `$0` trên CI `macos-latest`), và tách phần chạy tunnel thật trên iPhone vật lý sang cổng `hardware_signoff_required`. Đồng thời Gate 1 Backlog chốt ngưỡng tối thiểu **`iOS 15+`** (`MED-MOB-G2-01`).

### Options
1. **Phương án A — Swift `6` (`IPHONEOS_DEPLOYMENT_TARGET = 15.0`) + SwiftUI (`if #available(iOS 16.0, *)` `PasteButton`, fallback nút `UIPasteboard` trên iOS 15) + Enroll ở `MeshApp` + `NEPacketTunnelProvider` + `XcodeGen` (`project.yml`) + `AVCaptureMetadataOutput` + `$0` Simulator CI (CHỌN)**.
2. **Phương án B — Nâng cứng lên iOS 16.0+ hoặc truyền `mpk_*` qua `providerConfiguration` sang Extension**: Nâng lên iOS 16 thu hẹp phạm vi Gate 1 khi chưa có phê duyệt PO/BA; còn truyền `mpk_*` qua `providerConfiguration` khiến `nesessionmanager` ghi cleartext plist ra đĩa vi phạm `SEC-01` (`BLK-MOB-G2-02`).

### Decision
1. **Swift `6` & `IPHONEOS_DEPLOYMENT_TARGET = 15.0` (`iOS 15.0+`) với `XcodeGen` (`mobile/ios/project.yml`)**:
   - Bật `SWIFT_STRICT_CONCURRENCY = complete` (`Swift 6`), đặt **`IPHONEOS_DEPLOYMENT_TARGET = 15.0`** khớp 100% Gate 1 Backlog (`MED-MOB-G2-01`). Dùng **`if #available(iOS 16.0, *)`** bật `SwiftUI.PasteButton` tránh popup pasteboard liên tục trên iOS 16+, và fallback nút dán `UIPasteboard.general` chuẩn trên iOS 15.
   - Toàn bộ cấu hình target (`MeshApp`, `MeshPacketTunnel`, `MeshAppTests`), App Group (`group.<bundle_id>`), Keychain Access Group và Entitlements template (`com.apple.developer.networking.networkextension = packet-tunnel-provider`) khai báo tường minh trong **`mobile/ios/project.yml`**; CI & dev sinh `.xcodeproj` bằng `xcodegen generate` (không commit `.xcodeproj` vào git).
2. **Kiến trúc 2 Tiến trình, Bàn giao Enroll & `packetFlow` (`BLK-MOB-G2-02`, `HR-MOB-G2-02/04`)**:
   - **Enroll / Rotate trước khi bật Tunnel (`MeshApp` Process 1):** Cung cấp hàm FFI độc lập **`mobile_enroll_or_rotate_node(...)`** (nhận `Arc<MobilePendingJoinSession>`), để `MeshApp` thực hiện `POST /v1/auth/challenge` + `POST /v1/nodes/register`, niêm phong identity vào Storage/Keychain Access Group + ghi non-secret `bootstrap.toml` vào App Group + zeroize `mpk_*` ngay trong RAM `MeshApp`. Nhờ đó `MeshPacketTunnel` khởi động đồng nhất cho cả App launch, Settings.app VPN toggle và `NEOnDemandRule` mà **0 byte `mpk_*` lọt vào `providerConfiguration`, App Group file hay `sendProviderMessage`**.
   - Main Container App (`SwiftUI` + `NETunnelProviderManager`) chỉ quản lý UI, Onboarding, đọc **`group.<bundle_id>/diagnostics/mesh-bugreport-{ts}.tar` (`<= 1 MiB`)** mở `UIActivityViewController` Share Sheet (xóa tệp tạm ngay sau khi đóng), và gửi lệnh điều khiển qua `NETunnelProviderSession.sendProviderMessage` (`<= 4 KiB`).
   - `NEPacketTunnelProvider` (`<app_id>.PacketTunnel`) chạy `MeshMobileFFI.xcframework`, đọc/ghi L3 IP packets qua `packetFlow.readPackets`/`writePackets` (tuyệt đối cấm hack dò `utun` fd), cấu hình `NEIPv4Settings(addresses: [local_overlay_ip], subnetMasks: ["255.255.255.255"])` (**prefix `/32`**), `includedRoutes` (`[overlay_cidr]` hoặc `/32` + `overlay_dns_ip/32`), `NEDNSSettings(matchDomains: ["mesh.internal"])`, theo dõi mạng bằng `NWPathMonitor`, và teardown `<= 5 s` trong `stopTunnel(with:completionHandler:)`.
   - Khi người dùng bấm Disconnect thủ công, app đặt `isOnDemandEnabled = false` và lưu cấu hình trước khi gọi `stopTunnel` (`US-092 AC2`).
3. **Keychain Access Group & Native QR**:
   - Lưu bí mật trong Keychain Access Group dùng chung với **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** và **`kSecAttrSynchronizable = false`**. Nếu Extension khởi chạy trước lần mở khóa đầu sau reboot và nhận `errSecInteractionNotAllowed` (`-25308`), thoát/chờ gọn với trạng thái chờ mở khóa — **tuyệt đối không xóa nhầm khóa**. Không để lại `Vec<u8>` JSON trần qua biên FFI (dùng DEK 32-byte từ Keychain + `ChaCha20Poly1305` sealed blob hoặc zeroize `resetBytes(in:)` ngay trong `defer`).
   - Quét QR bằng **`AVFoundation` (`AVCaptureMetadataOutput`)** — 0 thư viện ngoài.
4. **Quy trình CI `$0` vs Cổng Ký số `$99/năm` (`OQ-MOB-02`)**:
   - CI `macos-latest` biên dịch 3 slice Rust (`aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`), đóng gói `MeshMobileFFI.xcframework` (mỗi slice `<= 6 MiB`), chạy `xcodegen generate` và `xcodebuild test` trên iOS Simulator với **`CODE_SIGNING_ALLOWED=NO`** (`$0`).
   - Chạy tunnel `NEPacketTunnelProvider` trên iPhone vật lý (`US-097 AC2`) được đánh dấu cổng **`hardware_signoff_required (chờ Apple Developer $99/năm)`**.

### Consequences
- **(+) Tích cực**: Giữ nguyên phạm vi `iOS 15.0+` đã duyệt tại Gate 1; toàn bộ code iOS và FFI kiểm chứng compile/link/unit-test tự động với `$0` trong mỗi PR; enroll không để lại `mpk_*` ở `providerConfiguration`; sẵn sàng ký Ad-Hoc/TestFlight ngay khi kích hoạt tài khoản Apple `$99/năm`.
- **(−) Chi phí / Giảm thiểu**: iOS Simulator không khởi chạy kernel `NEPacketTunnelProvider` → logic Swift của provider (`PacketFlowBridge`, `KeychainStore`, `AppGroupIpc`, `TunnelSettingsBuilder`) phải được tách khỏi subclass hệ thống thành protocol/type kiểm thử được bằng unit test trên Simulator!

---

<a id="adr-019"></a>
## ADR-019 — Onboarding Di động An toàn (`mesh://join` URI & QR `--emit-uri`/`--qr` từ CLI `mesh`), Cấm Deep-Link `mpk_*` & Chẩn đoán Không-TCP

- **Trạng thái**: Proposed-for-Gate-2 (thực thi quyết định `OQ-MOB-03` của Người dùng)
- **Ngày**: 2026-11-15

### Context
- `OQ-MOB-03` yêu cầu hỗ trợ 3 phương thức nhập cấu hình trong app: quét QR camera nội bộ, dán URI `mesh://` sinh ra từ CLI `crates/mesh` (`PreAuthKeyCreatedResponse`), và nhập tay `IP:port + sha256:<pin> + mpk_*`, nhưng **cấm** đăng ký OS-wide clickable deep-link cho `mpk_*` để triệt tiêu tấn công Custom URL Scheme Hijacking (`T-MOB-07`).
- `PreAuthKeyCreatedResponse` (`crates/mesh-proto/src/admin_ipc.rs:60-87`) gắn `#[serde(deny_unknown_fields)]` và đã chứa sẵn `server_endpoint`, `active_pin`, `raw_key` (`mpk_*`).
- `SEC-14` cấm mở bất kỳ TCP listener nào cho Admin API trên app di động, và `HR-MOB-G2-03` nghiêm cấm rò `mpk_*` qua `java.lang.String` bất biến trên tầng UI Android/iOS.

### Options
1. **Phương án A — Sinh URI `mesh://join?...` & QR qua `--emit-uri` / `--qr` ngay tại `crates/mesh` CLI từ `PreAuthKeyCreatedResponse` + Parser `mesh://join` trong Rust giữ bí mật trong `Arc<MobilePendingJoinSession>` (chỉ trả `preauth_key_masked` cho UI) + Cấm OS deep-link `mpk_*` (CHỌN)**.
2. **Phương án B — Trả `preauth_key: String` thô qua FFI UI hoặc đăng ký scheme `mesh://` ở cấp OS**: Trả chuỗi thô qua FFI tạo `java.lang.String` bất biến chứa `mpk_*` không zeroize được trên JVM heap; còn đăng ký OS scheme `mesh://` tạo lỗ hổng scheme hijacking `T-MOB-07`.

### Decision
1. **Định dạng URI `mesh://join` chuẩn hóa & Sinh từ `crates/mesh` CLI (`BLK-MOB-G2-04`, `US-080 AC2`)**:
   - `crates/mesh` (khi chạy `mesh preauthkey create --emit-uri` hoặc `--qr`) dựng URI ngay phía CLI từ `PreAuthKeyCreatedResponse` (`server_endpoint`, `active_pin`, `raw_key`) mà **không cần phá vỡ** `PreAuthKeyCreatedResponse` (`#[serde(deny_unknown_fields)]`):
     ```text
     mesh://join?v=1&ep=<urlenc_endpoint>&pin=<sha256%3A64hex|system-ca>&key=<mpk_...>[&name=<node_name>]
     ```
     *(Giá trị pin gốc luôn dùng chuẩn **`sha256:<64_hex>`** khớp `mesh_core::types::SpkiPin`; chỉ encode `%3A` cho dấu `:` khi đặt làm query parameter trong URI.)*
   - `crates/mesh` **không ghi URI chứa `mpk_*` ra log hay DB** (chỉ in ra stdout/terminal theo yêu cầu quản trị viên).
2. **Parser, `MobilePendingJoinSession` & Bảo vệ `mpk_*` (`HR-MOB-G2-03`, kèm `proptest!`)**:
   - Yêu cầu host/authority là `"join"` và `v=1`; kiểm tra `ep` hợp lệ (host/IP + port `1..=65535`, không chứa scheme lồng `://`); nếu `pin` không phải `system-ca` (chỉ cho phép khi host là tên miền hợp lệ) thì **bắt buộc** khớp `sha256:<64_hex>` (cấm TOFU tuyệt đối!); kiểm tra `key` bắt đầu bằng `mpk_` và bọc ngay vào **`mesh_crypto::Secret<String>`**; kiểm tra `name` (nếu có) qua `NodeName::parse()` (chặn ký tự điều khiển, `localhost`, `wpad`, `isatap`, `local`).
   - **Không trả `mpk_*` thô về UI (`HR-MOB-G2-03`):** Hàm FFI `parse_mobile_join_uri(raw_uri)` chỉ trả metadata hiển thị đã che (**`preauth_key_masked: String`**, ví dụ `"mpk_AbCd...6789"`) cùng handle **`Arc<MobilePendingJoinSession>`** (`#[derive(uniffi::Object)]`, giữ `Secret<String>` `ZeroizeOnDrop` trong Rust) để truyền thẳng vào `start_tunnel` hoặc `mobile_enroll_or_rotate_node`. Trường hợp nhập tay cũng tạo `MobilePendingJoinSession` và xóa buffer ký tự sớm nhất có thể (`CharArray.fill('\0')` / zeroize).
   - Màn hình xác nhận UI (Android & iOS) **bắt buộc** hiển thị rõ `Control Endpoint` và `SPKI Pin` (hoặc cảnh báo chế độ `System CA` cho Domain) cùng `preauth_key_masked` để người dùng bấm xác nhận trước khi gửi bất kỳ gói mạng nào.
   - Sau khi đăng ký xong (hoặc khi parser/đăng ký lỗi và bị hủy), hủy `MobilePendingJoinSession` (`ZeroizeOnDrop`) và xóa sạch khỏi clipboard/UI state.
3. **Cấm OS-Wide Clickable Deep-Link (`T-MOB-07`)**:
   - Android `AndroidManifest.xml`: **0** `<intent-filter>` chứa `<data android:scheme="mesh" />`.
   - iOS `Info.plist`: **0** `CFBundleURLTypes` chứa `mesh` và **0** `Associated Domains` cho enroll `mpk_*`.
4. **Chẩn đoán Không-TCP & Bảo vệ Bí mật (`MOB-OPS-04`, `MOB-SEC-05`)**:
   - Mobile app mở **0 socket TCP listener** (`0` `/healthz`, `/readyz`, `/metrics`, `0` localhost HTTP).
   - Mọi trạng thái (`status`, `peers`, `ping`, `netcheck`) đi qua IPC nội bộ an toàn (Android Binder / iOS `sendProviderMessage <= 4 KiB`); `bugreport` xuất streaming ra **`diagnostics/mesh-bugreport-{ts}.tar` (`<= 1 MiB`)** được sanitize và kiểm chứng bằng `test_no_secrets_in_outputs` ở mức `DEBUG` (`0` private key, `0` `mpk_*` nguyên vẹn).

### Consequences
- **(+) Tích cực**: Tương thích 100% với `mesh-server v0.1.0-rc1+` và CLI `mesh`; đóng kín bề mặt cướp khóa qua OS deep-link; trải nghiệm onboarding 3 cách đồng nhất trên Android & iOS.
- **(−) Chi phí / Giảm thiểu**: Người dùng cần mở app Mesh VPN trước khi quét QR hoặc dán URI (chấp nhận 1 thao tác chạm để đổi lấy miễn nhiễm hoàn toàn trước scheme hijacking `T-MOB-07`).
