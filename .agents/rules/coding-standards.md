---
trigger: always_on
---

# Mesh VPN — Rust Coding Standards (BẮT BUỘC cho mọi Subagent)

Chuẩn đầy đủ: `docs/03-system-design/coding-standards.md` · Stack: `docs/03-system-design/tech-stack-decision.md` · ADR: `docs/03-system-design/architecture-decision-record.md`. Công cụ: `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.editorconfig`. **Cấm tự `#[allow(clippy::...)]` để lách luật. Thay đổi crate/ranh giới module/API/DB contract ⇒ DỪNG, báo Scrum Master.**

## 1. Stack & Kiến trúc Workspace chốt (không tự đổi)
- **Rust `1.94.1`** (`edition = "2024"`, `rust-version = "1.94.1"`), 1 Cargo Workspace (`resolver = "3"`). Đích phát hành: `x86_64-unknown-linux-musl` (hoặc `-gnu`), `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` (hoặc `-gnu`).
- **3 Binaries + 7 Library Crates trong `crates/*`**:
  - Binaries: `crates/mesh` (CLI client + admin), `crates/meshd` (agent daemon `root`/`SYSTEM`), `crates/mesh-server` (Control + Blind Relay + STUN + Observability, chạy user không đặc quyền trên VPS Linux).
  - Libraries: `mesh-core` (domain types, `AppError`, `Clock`, `Backoff`, `defaults`, `brand`), `mesh-crypto` (**duy nhất** import mật mã & `Secret<T>`), `mesh-proto` (wire messages & bounded parsers: Control, STUN RFC 5389, Disco, Relay), `mesh-datapath` (`defguard_boringtun::noise::Tunn` sans-I/O trên **1 `tokio::net::UdpSocket` duy nhất** `MagicSocket`), `mesh-net` (OS traits + fakes: TUN, route, netmon, hosts, `ResourceLedger`, IPC, `sysexec`), `mesh-store` (`redb` ACID thuần Rust + hot atomic backup), `mesh-sys` (**duy nhất** được dùng `unsafe` cho OS FFI).
- **Release & Runtime nhỏ nhẹ**: `[profile.release]` bật `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`. `meshd` giới hạn `tokio` `worker_threads(2)` + `thread_stack_size(512 * 1024)` + tái sử dụng buffer tĩnh `[u8; 2048]` (RAM nền ~4–10 MB client, ~8–18 MB VPS).
- **Chỉ dùng Crates Được phép** (1 chức năng = 1 crate): `tokio`, `tokio-util`, `defguard_boringtun` (`0.6`, BSD-3), `rustls` (`0.23`, tắt `aws-lc-rs`, dùng `ring` / `rustls-rustcrypto`), `tokio-rustls`, `rustls-pemfile`, `rustls-pki-types`, `rcgen`, `instant-acme`, `axum`, `hyper`, `hyper-util`, `tokio-tungstenite`, `reqwest` (rustls), `crypto_box`, `x25519-dalek`, `chacha20poly1305`, `sha2`, `subtle`, `zeroize`, `rand`, `getrandom`, `redb` (`2.4`), `serde`, `serde_json`, `toml`, `clap` (derive), `thiserror`, `tracing`, `tracing-subscriber`, `tracing-appender`, `bytes`, `crc32fast`, `base64`, `data-encoding`, `socket2`, `libc` (unix, chỉ `mesh-sys`), `windows-sys` (windows, chỉ `mesh-sys`), `windows-service` (windows), và dev-deps `proptest`, `tempfile`.
- **CẤM (`deny.toml`)**: Mọi crate/mã `AGPL` (NetBird server AGPLv3), `GPL`, `LGPL`, `MPL-2.0` (`gotatun`); thư viện C ẩn (`openssl-sys`, `native-tls`, `rusqlite`/`libsqlite3-sys`, `libsodium-sys`, `aws-lc-rs`); `anyhow`/`eyre` trong crate thư viện; `async-std`, `actix-web`, `warp`, `sled`, `sqlx`, `diesel`, `sea-orm`, `env_logger`, `log4rs`; tự viết cipher/MAC/KDF/handshake (`SEC-02`).

## 2. Format, Đặt tên & Tổ chức Mã theo OS
- **Format (`rustfmt.toml`)**: 4 spaces cho `.rs` (2 spaces cho `.toml/.json/.yml/.sh`), dòng ≤ 100 cột, LF (`.ps1/.bat/.cmd` = CRLF), **UTF-8 KHÔNG BOM**. Code, comment, log, lỗi, commit bằng **tiếng Anh**.
- **Thứ tự `use`**: (1) `std`/`core`/`alloc` → (2) external crates → (3) `mesh_*`/`crate`/`super`/`self`. Cấm `use ...::*;` ngoài `mod tests`.
- **Đặt tên**: Crate `kebab-case`; module/file/fn/var `snake_case` (cấm `util.rs`/`common.rs`/`helpers.rs`, getter không có `get_`); struct/enum/trait `PascalCase`; const/static `SCREAMING_SNAKE_CASE`; bảng `redb` & trường JSON/TOML `snake_case`; thời điểm `*_at_ms` (`u64` UTC); env `MESH_*`; CLI `mesh <noun> <verb> --kebab-flag`.
- **Mã theo OS (`cfg(target_os)`)**: Logic cốt lõi OS-neutral. Phần chạm OS định nghĩa bằng Trait trong `mesh-net` kèm Fake trong bộ nhớ để `cargo test` chạy xanh trên mọi OS không cần root/Admin. Cài đặt OS tách file `<name>_linux.rs`, `<name>_macos.rs`, `<name>_windows.rs` với `#[cfg(target_os = "...")]`. Cấm `std::env::consts::OS` rẽ nhánh nghiệp vụ.

## 3. An toàn Bộ nhớ, Kiểu & Xử lý Lỗi (Clippy `-D warnings`)
- **Cô lập `unsafe`**: Toàn workspace đặt `unsafe_code = "forbid"`. Chỉ riêng `crates/mesh-sys` được dùng `unsafe` với `#![deny(unsafe_op_in_unsafe_fn)]` và `#![deny(clippy::undocumented_unsafe_blocks)]` kèm comment `// SAFETY:` bắt buộc.
- **Cấm gây panic trong code production**: Cấm `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, `unimplemented!()`, `unreachable!()`, `dbg!()`, `println!()`/`eprintln!()` (trừ CLI `crates/mesh`), truy cập mảng `slice[i]` (dùng `.get(...)` / `split_at_checked`), và bỏ qua `Result` (`let _ = f()`).
- **Kiểu miền (`mesh-core`)**: Parse ngay tại biên thành newtype (`NodeId`, `NodeName` RFC 1123 1..=63 `[a-z0-9-]`, `OverlayIp`, `Port`, `PublicKey([u8; 32])`, `SpkiPin`). Frame mạng ≤ 2048 B. Cấm mã hóa cứng cổng `443`/`3478` ngoài `mesh_core::defaults` (`GNFR-11`).
- **Lỗi (`thiserror` + `AppError`)**: Phân loại qua `ErrorKind`. Khi `ErrorKind::Unauthenticated`, luôn trả **duy nhất một thông báo công khai** `"authentication failed"` (`SEC-05`). Xử lý lỗi một lần (return `?` HOẶC log ở biên).

## 4. Async / Tokio Concurrency & Vòng đời (`Graceful Shutdown ≤ 5 s`)
- Mọi task nền nhận `CancellationToken`, chạy trong `TaskTracker`/`JoinSet` (cấm `tokio::spawn` mồ côi) và thoát **≤ 5 s** khi dừng (gỡ route, hosts, `utunN`/adapter theo `ResourceLedger`).
- Cấm giữ `std::sync::MutexGuard` qua `.await` (`clippy::await_holding_lock = "deny"`). Cấm `std::thread::sleep` trong async.
- **Blind Relay (`US-025 AC6`)**: Cấm `unbounded_channel`. Mỗi đích dùng `mpsc::channel(256)` + **`try_send()`** (đầy thì drop-tail không chặn + tăng metric, cấm `.send().await` gây Head-of-Line blocking).
- Mọi I/O mạng có `tokio::time::timeout` (connect ≤ 10 s, heartbeat ≤ 60 s). Reconnect dùng `ExponentialBackoff` + full jitter; lỗi TLS/Captive Portal/clock skew/pin mismatch tiếp tục retry trần 5 phút (chỉ dừng khi nhận `node_revoked`/`node_key_expired` qua kênh TLS hợp lệ — `US-034`).

## 5. Bảo mật Khóa, Kênh Admin & An toàn Máy thật (`SEC-01`, `SEC-04`, `SEC-14`, `G4`)
- **Bí mật trong RAM (`SEC-01`)**: Private key và pre-auth key thô chỉ tồn tại trong `mesh_crypto::Secret<T>` (`ZeroizeOnDrop`; `Debug`/`Display`/`Serialize` → `"[REDACTED]"`). `.expose_secret()` chỉ gọi trong `mesh-crypto`, `mesh-datapath`, `mesh-net` (keystore) và `mesh` (in key 1 lần). Không nhận key qua argv mặc định. Test `test_no_secrets_in_outputs` phải xanh.
- **TLS & SPKI Pin (`SEC-04`)**: IP + SPKI Pin (`sha256:<hex>`) là mặc định hạng nhất; `SpkiPinVerifier` đối chiếu SHA-256 của SPKI DER bằng `ConstantTimeEq`, fail-closed khi thiếu pin, **cấm TOFU**, không cờ bypass.
- **Kênh Admin IPC (`SEC-14`)**: Chỉ Unix Domain Socket (`0600`/`0660` + `peer_cred()` `SO_PEERCRED` Linux / `LOCAL_PEERCRED` macOS) hoặc Windows Named Pipe SDDL (`SYSTEM` + `Administrators`). **Cấm** mở Admin API trên TCP (`127.0.0.1`, overlay, public). `/healthz`, `/readyz`, `/metrics` ở listener riêng chỉ-đọc.
- **Bảo vệ Máy thật (`G4`)**:
  - **Sổ cái (`ResourceLedger`)**: Ghi tài nguyên thật (`utunN`, adapter GUID, route, hosts, anchor `pf`, firewall rule) vào đĩa (`0600`) **trước khi tạo**; chỉ dọn theo sổ cái (cấm xóa `utun*`, bảo vệ iCloud Private Relay/VPN khác).
  - **Chống Routing Loop (`REL-09`)**: Ràng socket ngoại biên vào NIC vật lý (`SO_MARK` Linux, `IP_BOUND_IF` macOS, `IP_UNICAST_IF` Windows) và ràng lại khi đổi mạng; chỉ route dải overlay.
  - **Khối `hosts` (`PLAT-04`)**: Chỉ sửa trong `# BEGIN mesh … # END mesh`; giữ symlink `/etc/hosts` macOS và ACL đọc Windows; chặn `localhost, broadcasthost, wpad, isatap, local` và hostname/IP public của VPS.
  - **Windows & macOS**: Kiểm SHA-256 `wintun.dll` trước khi nạp (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR`); macOS kiểm binary/plist thuộc `root` (`mode & 0o022 == 0`), cấm `spctl --master-disable`. Lệnh ngoài chỉ qua `mesh_net::sysexec` (đường dẫn tuyệt đối, không shell).
- **Log (`OPS-01`)**: `tracing` JSON; bắt buộc có `ts` (UTC), `level`, `component`, `event`.

## 6. Testing & Git
- Test theo `// Arrange` – `// Act` – `// Assert`; tên `test_<unit>_<scenario>_<expected>`; mọi parser có `proptest!`; test cần root/Admin gắn `#[ignore = "privileged"]`.
- **Conventional Commits** tiếng Anh: `type(scope): subject` (≤ 72 ký tự) + `Refs: US-0xx`.

## 7. BỘ LỆNH KIỂM ĐỊNH CHUẨN — Phải XANH 100% trước khi bàn giao
```text
Windows   : powershell -ExecutionPolicy Bypass -File scripts/check.ps1
Linux/Mac : sh scripts/check.sh
```
Các bước bên trong: (1) Kiểm tĩnh repo (không BOM, không `unsafe` ngoài `mesh-sys`, không `.expose_secret()` trái phép, không cổng cứng `443`/`3478` ngoài `mesh-core`) → (2) `cargo fmt --all -- --check` → (3) `cargo clippy --workspace --all-targets --all-features -- -D warnings` → (4) `cargo test --workspace --all-features` → (5) `cargo deny check advisories bans licenses sources`.
