---
trigger: always_on
---

# Mesh VPN — Rust Coding Standards (BẮT BUỘC)

Chuẩn: `docs/03-system-design/{coding-standards,tech-stack-decision,architecture-decision-record}.md`. Công cụ: `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.editorconfig`. **Cấm tự `#[allow(clippy::...)]` lách luật. Đổi crate/ranh giới module/API/DB contract ⇒ DỪNG, báo Scrum Master.**

## 1. Stack & Kiến trúc Workspace chốt
- **Rust `1.94.1`** (`edition = "2024"`, `rust-version = "1.94.1"`, `channel = "1.94.1"`), 1 Workspace (`resolver = "3"`). Đích: `x86_64-unknown-linux-musl` (`-gnu`), `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc` (`-gnu`).
- **3 Binaries + 7 Libs trong `crates/*`**:
  - Binaries: `crates/mesh` (CLI), `crates/meshd` (daemon `root`/`SYSTEM`), `crates/mesh-server` (Control + Blind Relay + STUN + Observability, user không đặc quyền trên VPS Linux).
  - Libs: `mesh-core` (domain types, `AppError`, `Clock`, `Backoff`, `defaults`, `brand`), `mesh-crypto` (**duy nhất** import mật mã & `Secret<T>`), `mesh-proto` (wire messages & bounded parsers: Control, STUN RFC 5389, Disco, Relay), `mesh-datapath` (`defguard_boringtun::noise::Tunn` sans-I/O trên **1 `tokio::net::UdpSocket`** `MagicSocket`), `mesh-net` (OS traits + fakes: TUN, route, netmon, hosts, `ResourceLedger`, IPC, `sysexec`), `mesh-store` (`redb` ACID + hot atomic backup), `mesh-sys` (**duy nhất** dùng `unsafe` cho OS FFI).
- **Release & Runtime**: `[profile.release]` `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`. `meshd`: `tokio` `worker_threads(2)` + `thread_stack_size(512 * 1024)` + buffer `[u8; 2048]` (RAM ~4–10 MB client, ~8–18 MB VPS).
- **Crates Được phép** (1 chức năng = 1 crate): `tokio`, `tokio-util`, `defguard_boringtun` (`0.6`, BSD-3), `rustls` (`0.23`), `tokio-rustls` (`0.26`), `rustls-pemfile`, `rustls-pki-types`, `rustls-webpki` (`0.102+`), `rustls-native-certs` (`0.8`), `x509-cert` (`0.2`, chỉ `mesh-crypto`), `rcgen` (`0.13`), `instant-acme` (`0.7`), `reqwest` (`0.12`) — **bắt buộc `default-features = false` + `ring` trên mọi crate TLS để chặn `aws-lc-rs`**; `axum`, `hyper`, `hyper-util`, `tokio-tungstenite`, `crypto_box`, `x25519-dalek`, `chacha20poly1305`, `sha2`, `subtle`, `zeroize`, `rand`, `getrandom`, `redb` (`2.4`), `serde`, `serde_json`, `toml`, `clap` (derive), `thiserror`, `tracing`, `tracing-subscriber`, `tracing-appender`, `bytes`, `crc32fast`, `base64`, `data-encoding`, `socket2`, `libc` (unix, chỉ `mesh-sys`), `windows-sys` (windows, chỉ `mesh-sys`), `windows-service` (windows), dev-deps `proptest`, `tempfile`.
- **CẤM (`deny.toml`)**: `AGPL` (NetBird server), `GPL`, `LGPL`, `MPL-2.0` (`gotatun`); C ẩn (`openssl-sys`, `native-tls`, `rusqlite`/`libsqlite3-sys`, `libsodium-sys`, `aws-lc-rs`); `sha1` ngoài `wrappers = ["tungstenite"]` (RFC 6455); `anyhow`/`eyre` trong lib; `async-std`, `actix-web`, `warp`, `sled`, `sqlx`, `diesel`, `sea-orm`, `env_logger`, `log4rs`; tự viết mật mã/handshake (`SEC-02`).

## 2. Format, Đặt tên & Tổ chức Mã theo OS
- **Format (`rustfmt.toml`)**: 4 spaces `.rs` (2 spaces `.toml/.json/.yml/.sh`), ≤ 100 cột, LF (`.ps1/.bat/.cmd` = CRLF), **UTF-8 KHÔNG BOM**. Code, comment, log, lỗi, commit bằng **tiếng Anh**.
- **Thứ tự `use`**: (1) `std`/`core`/`alloc` → (2) external crates → (3) `mesh_*`/`crate`/`super`/`self`. Cấm `use ...::*;` ngoài `mod tests`.
- **Đặt tên**: Crate `kebab-case`; module/file/fn/var `snake_case` (cấm `util.rs`/`common.rs`/`helpers.rs`, getter không `get_`); struct/enum/trait `PascalCase`; const/static `SCREAMING_SNAKE_CASE`; bảng `redb` & JSON/TOML `snake_case`; thời điểm `*_at_ms` (`u64` UTC); env `MESH_*`; CLI `mesh <noun> <verb> --kebab-flag`.
- **Mã theo OS (`cfg(target_os)`)**: Logic lõi OS-neutral. Phần chạm OS định nghĩa bằng Trait trong `mesh-net` kèm Fake trong RAM để `cargo test` xanh trên mọi OS không cần root/Admin. Tách `<name>_{linux,macos,windows}.rs` với `#[cfg(target_os = "...")]`. Cấm `std::env::consts::OS` rẽ nhánh nghiệp vụ.

## 3. An toàn Bộ nhớ, Kiểu & Xử lý Lỗi (Clippy `-D warnings`)
- **Cô lập `unsafe` (tránh `E0453`)**: `[workspace.lints.rust] unsafe_code = "forbid"` cho 9/10 crates (`[lints] workspace = true`). Riêng `crates/mesh-sys/Cargo.toml` KHÔNG đặt `[lints] workspace = true`, tự khai báo `[lints.rust]` (`unsafe_code = "allow"`, `unsafe_op_in_unsafe_fn = "deny"`) + `[lints.clippy]` (`undocumented_unsafe_blocks = "deny"`, `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`, `indexing_slicing = "deny"`) kèm `// SAFETY:`.
- **Cấm panic**: Cấm `.unwrap()`, `.expect()`, `panic!()`, `todo!()`, `unimplemented!()`, `unreachable!()`, `dbg!()`, `println!()`/`eprintln!()` (trừ CLI `crates/mesh`), `slice[i]` (dùng `.get(...)`/`split_at_checked`), `let _ = f()`.
- **Kiểu miền (`mesh-core`)**: Parse tại biên thành newtype (`NodeId`, `NodeName` RFC 1123 1..=63 `[a-z0-9-]`, `OverlayIp`, `Port`, `PublicKey([u8; 32])`, `SpkiPin`). Frame ≤ 2048 B. Cấm cứng cổng `443`/`3478` ngoài `mesh_core::defaults` (`GNFR-11`).
- **Lỗi (`thiserror` + `AppError`)**: Khi `ErrorKind::Unauthenticated`, luôn trả **duy nhất** `"authentication failed"` (`SEC-05`). Xử lý lỗi 1 lần (return `?` HOẶC log ở biên).

## 4. Async / Tokio Concurrency & Vòng đời (`Graceful Shutdown ≤ 5 s`)
- Task nền nhận `CancellationToken`, chạy trong `TaskTracker`/`JoinSet` (cấm `tokio::spawn` mồ côi) và thoát **≤ 5 s** khi dừng (dọn theo `ResourceLedger`). Cấm giữ `std::sync::MutexGuard` qua `.await` (`await_holding_lock = "deny"`). Cấm `std::thread::sleep` trong async.
- **Blind Relay (`US-025 AC6`)**: Cấm `unbounded_channel`. Mỗi đích dùng `mpsc::channel(256)` + **`try_send()`** (đầy thì drop-tail + tăng metric, cấm `.send().await` gây Head-of-Line blocking).
- I/O mạng có `tokio::time::timeout` (connect ≤ 10 s, heartbeat ≤ 60 s). Reconnect dùng `ExponentialBackoff` + full jitter; lỗi TLS/Captive Portal/clock skew/pin mismatch retry trần 5 phút (chỉ dừng khi nhận `node_revoked`/`node_key_expired` qua kênh TLS hợp lệ — `US-034`).

## 5. Bảo mật Khóa, Kênh Admin & An toàn Máy thật (`SEC-01`, `SEC-04`, `SEC-14`, `G4`)
- **Bí mật trong RAM (`SEC-01`)**: Private key & pre-auth key thô chỉ nằm trong `mesh_crypto::Secret<T>` (`ZeroizeOnDrop`; `Debug`/`Display`/`Serialize` → `"[REDACTED]"`). `.expose_secret()` chỉ gọi trong `mesh-crypto`, `mesh-datapath`, `mesh-net` (keystore) và `mesh` (in key 1 lần). Không nhận key qua argv mặc định. Test `test_no_secrets_in_outputs` phải xanh.
- **TLS & SPKI Pin (`SEC-04`)**: IP + SPKI Pin (`sha256:<hex>`) mặc định hạng nhất; `SpkiPinVerifier` dùng `x509-cert` lấy `tbs_certificate.subject_public_key_info` DER + kiểm hạn `NotBefore`/`NotAfter` (`ErrorKind::ClockSkew`), so sánh SHA-256 `ConstantTimeEq`, fail-closed khi thiếu pin, **cấm TOFU**, không cờ bypass.
- **IPC (`SEC-14`)**: Server Linux: `/run/mesh/admin.sock` (`0660 mesh:mesh-admin`, `SO_PEERCRED` + `getgrouplist`). Client `meshd` tách **2 kênh**: (1) Admin `/var/run/mesh/meshd-admin.sock` (`0660 root:admin` macOS kiểm `xucred.cr_groups` `gid==80` + fallback `getgrouplist`; `0660` Linux) / `\\.\pipe\mesh-agent-admin` SDDL (`SY`+`BA`) và (2) Read-only (`status`/`peers`/`ping`/`netcheck`, 0 secrets, ≤ 4 KiB) `/var/run/mesh/meshd-ro.sock` (`0666`) / `\\.\pipe\mesh-agent-ro`. **Cấm** Admin API trên TCP. `/healthz`, `/readyz`, `/metrics` ở listener riêng chỉ-đọc.
- **Bảo vệ Máy thật (`G4`)**:
  - **Sổ cái (`ResourceLedger`)**: Ghi (`utunN`, adapter GUID, route, `ip rule`/`table 51820`, hosts, `pf`, firewall) vào đĩa (`0600`) **trước khi tạo**; chỉ dọn theo sổ cái (cấm xóa `utun*`).
  - **Chống Routing Loop (`REL-09`)**: Ràng socket ngoại biên vào NIC vật lý (`IP_BOUND_IF` macOS, `IP_UNICAST_IF` Windows, Linux `SO_MARK = 0x5d56` + `table 51820` + `ip rule` `not fwmark 0x5d56 table 51820` & `table main suppress_prefixlength 0`); chỉ route dải overlay.
  - **Khối `hosts` (`PLAT-04`)**: Chỉ sửa `# BEGIN mesh … # END mesh`; giữ symlink `/etc/hosts` macOS và ACL đọc Windows; chặn `localhost, broadcasthost, wpad, isatap, local` và hostname/IP public của VPS.
  - **Windows, macOS & `sysexec`**: Kiểm SHA-256 `wintun.dll` trước khi nạp (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR`); macOS kiểm binary/plist thuộc `root` (`mode & 0o022 == 0`), cấm `spctl --master-disable`. Lệnh ngoài chỉ qua `mesh_net::sysexec` với đường dẫn tuyệt đối (`/sbin/{ifconfig,route,pfctl}`, `/usr/bin/{dscacheutil,killall,systemctl}`, `/usr/libexec/ApplicationFirewall/socketfilterfw`, `/bin/launchctl`, `/usr/sbin/{ip,nft,iptables,ufw}`, `/sbin/ip`, Windows `GetSystemDirectoryW` + `System32\{netsh,ipconfig,route}.exe`, cấm shell).
- **Log (`OPS-01`)**: `tracing` JSON; bắt buộc `ts` (UTC), `level`, `component`, `event`.

## 6. Testing, Git & Bộ Lệnh Kiểm Định Chuẩn (Phải XANH 100%)
- Test `// Arrange` – `// Act` – `// Assert`; tên `test_<unit>_<scenario>_<expected>`; parser có `proptest!`; test cần root/Admin gắn `#[ignore = "privileged"]`. Commit tiếng Anh: `type(scope): subject` (≤ 72 ký tự) + `Refs: US-0xx`.
```text
Windows   : powershell -ExecutionPolicy Bypass -File scripts/check.ps1
Linux/Mac : sh scripts/check.sh
```
Các bước: (1) Kiểm tĩnh → (2) `cargo fmt --all -- --check` → (3) `cargo clippy --workspace --all-targets --all-features -- -D warnings` → (4) `cargo test --workspace --all-features` → (5) `cargo deny check advisories bans licenses sources`.
