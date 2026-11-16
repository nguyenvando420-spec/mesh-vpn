# Mesh VPN `v0.2.0` — Mobile Go-Live Checklist (`$0` Mode vs `hardware_signoff_required`)

**Tham chiếu bắt buộc:**
- Quyết định Gate 1 **`OQ-MOB-02` (`$0` Mode)**, [mobile-sprint-backlog.md](../04-sprint-management/mobile-sprint-backlog.md) (`WP-M-C1`, `WP-M-C2`, `US-097`, `US-098`)
- Runner QA hợp nhất: `scripts/run-mobile-qa.ps1` / `scripts/run-mobile-qa.sh` → `lab/.tmp/mobile-qa-report.json` & `lab/.tmp/mobile-qa-summary.md`
- Workflow phát hành: [mobile-release.yml](../../.github/workflows/mobile-release.yml), [mobile-android.yml](../../.github/workflows/mobile-android.yml), [mobile-ios.yml](../../.github/workflows/mobile-ios.yml)
- Nghi thức đo phần cứng thực địa: [mobile-hardware-acceptance-protocol.md](./mobile-hardware-acceptance-protocol.md)

> **Chính sách Cổng Phát Hành (`OQ-MOB-02`):**
> Bảng dưới đây phân tách rạch ròi giữa **(A) Hạng mục `$0` Ready & Verified** (chạy và nghiệm thu đầy đủ ngay không tốn chi phí tài khoản Store) và **(B) Hạng mục `hardware_signoff_required (chờ Apple Developer $99/năm)`** (chạy tunnel `NEPacketTunnelProvider` trên iPhone vật lý & TestFlight). **Không bao giờ đánh `[x]` giả cho hạng mục chưa chạy trên phần cứng thật.**

---

## 1. Lệnh Kiểm Chứng Tự Động Trước Khi Ký Duyệt

```powershell
# Windows: kiểm tra toàn workspace + 5 mobile targets + ELF <= 6 MiB + UniFFI codegen + security audit
powershell -ExecutionPolicy Bypass -File scripts/run-mobile-qa.ps1
```

```bash
# Linux / macOS:
sh scripts/run-mobile-qa.sh

# Trên Linux có Android NDK r27c+:
bash scripts/build-android-ffi.sh
cd mobile/android && ./gradlew ktlintCheck detekt lintRelease testDebugUnitTest assembleDebug assembleRelease bundleRelease

# Trên macOS có Xcode + XcodeGen + SwiftLint ($0 Simulator):
bash scripts/build-ios-xcframework.sh
xcodegen generate --spec mobile/ios/project.yml
(cd mobile/ios && swiftlint lint --strict)
xcodebuild -project mobile/ios/MeshApp.xcodeproj -scheme MeshApp -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO build test
```

---

## 2. Bảng Đối Soát Go-Live `v0.2.0` (Tách Rạch Ròi `$0` vs `$99/năm`)

| # | Mã Yêu Cầu | Hạng Mục Kiểm Chứng | (A) `$0` Ready & Verified (Chạy ngay `$0`) | (B) `hardware_signoff_required` (Chờ Apple Developer `$99/năm`) | Bằng Chứng / Lệnh Xác Nhận | Trạng Thái |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `MOB-OPS-03`, `M-GNFR-05` | **Tương thích ngược `v0.1.0-rc1` & `TargetOs`** | `mesh-server` nhận `TargetOs::{Android, Ios}`, giữ `protocol_version = 1` & `redb` `SCHEMA_VERSION = 1`; client dừng retry sạch khi gặp HTTP `400` `ServerUpgradeRequired` | — | `scripts/run-mobile-qa.{ps1,sh}`; `cargo test -p mesh-client -p mesh-server` | `[ ]` |
| 2 | `MOB-PERF-05`, `M-GNFR-06` | **Đồ thị dependency & `cargo-deny` 5 targets** | `cargo-deny --target <t> check advisories bans licenses sources` xanh `0` warning trên cả 5 mobile targets; `mesh-mobile-ffi` không kéo `axum`/`hyper`/`redb`/`clap`/`ndk-context`/`aws-lc-rs`/`openssl-sys` | — | `scripts/run-mobile-qa.{ps1,sh}` (Step 2) | `[ ]` |
| 3 | `MOB-SEC-01/05`, `M-GNFR-08` | **Cấu trúc FFI & `0` rò bí mật** | `0` `unsafe` ngoài `mesh-sys`, `0` `.expose_secret()` ngoài 4 crate allowlist, `test_no_secrets_in_outputs` mức `DEBUG` xanh, `identity.sealed.bin` được mã hóa AEAD trước khi ghi | — | `scripts/check.{ps1,sh}`; `cargo test -p mesh-mobile-ffi test_no_secrets_in_outputs` | `[ ]` |
| 4 | `MOB-PLAT-AND-05`, `MOB-PLAT-IOS-05`, `M-GNFR-04` | **Split-Tunnel `/32` & Split-DNS RFC 4074** | TUN prefix `/32` + `overlay_dns_ip/32`, cấm `0.0.0.0/0`; Responder UDP `:53` + Bounded L3 TCP `:53` (`16` LRU / `3 s`) + `:853 TCP RST|ACK`; `AAAA` trả `NODATA` (`RCODE=0`) đúng RFC 4074; `proptest!` xanh | — | `cargo test -p mesh-mobile-ffi --all-features` | `[ ]` |
| 5 | `MOB-REL-02/03`, `M-GNFR-07/09` | **IPv6 NAT64, `SocketProtector` & `TimerMode::IdleAware`** | Tổng hợp RFC 6052 §2.2 (byte `u = 0x00`) + RFC 7050 `ipv4only.arpa`, fail-closed khi `protect_socket` trả `false`, idle `0` wakeup `8 Hz` & coalesced heartbeat `45_000 ms ± 2_000 ms` | — | `cargo test -p mesh-datapath -p mesh-net -p mesh-client` | `[ ]` |
| 6 | `MOB-SEC-04`, `OQ-MOB-03` | **Onboarding `mesh://join` & `--emit-uri --qr`** | `mesh preauthkey create --emit-uri --qr`, `parse_mobile_join_uri` & `MobilePendingJoinSession` (`ZeroizeOnDrop`), `0` `<intent-filter>` `android:scheme="mesh"`, `0` `CFBundleURLTypes` | — | `scripts/run-mobile-qa.{ps1,sh}` (Step 3 & 4) | `[ ]` |
| 7 | `MOB-PERF-05`, `US-076 AC4` | **Ngân sách kích thước nhị phân `<= 6 MiB` & UniFFI Codegen** | `libmesh_mobile_ffi.so` (`<= 6_291_456 B`), `mesh-uniffi-bindgen` sinh Kotlin & Swift có đủ `9/9` symbol cốt lõi | — | `scripts/run-mobile-qa.{ps1,sh}` (Step 3); `scripts/build-android-ffi.sh`; `scripts/build-ios-xcframework.sh` | `[ ]` |
| 8 | `MOB-PLAT-AND-01..06`, `US-086` | **Android Build `.apk`/`.aab`, `16 KB` ELF & Static Hygiene** | CI `ubuntu-latest` build `arm64-v8a` + `x86_64`, `PT_LOAD p_align >= 16384`, `ktlintCheck`, `detekt`, `lintRelease`, `testDebugUnitTest`, `allowBackup="false"`, `0` `!!`, `0` GMS/ML Kit | — | `.github/workflows/mobile-android.yml`; `.github/workflows/mobile-release.yml` (`android-release`) | `[ ]` |
| 9 | `MOB-PERF-02`, `US-097` | **Android 14+ Máy thật (Sideload `$0`)** | Cài `.apk` sideload `$0` lên máy Android 14+; đo `adb shell dumpsys meminfo` xác nhận **`RSS <= 48 MiB`**, roaming Wi-Fi ↔ 4G/5G NAT64 `<= 5 s`, Doze idle, Strict Private DNS warning | — | Biên bản [mobile-hardware-acceptance-protocol.md](./mobile-hardware-acceptance-protocol.md) (§2 & §4) | `[ ]` |
| 10 | `MOB-PLAT-IOS-01..06`, `US-093` | **iOS `.xcframework` (`3` slices) & Simulator XCTest (`$0`)** | CI `macos-15` tạo `MeshMobileFFI.xcframework` (`3` slices `<= 6 MiB`), `xcodegen generate`, `swiftlint lint --strict`, `xcodebuild test` Simulator `CODE_SIGNING_ALLOWED=NO`, `0` `!`/`try!`/`as!`/`fatalError`, `0` `NSAllowsArbitraryLoads` | — | `.github/workflows/mobile-ios.yml`; `.github/workflows/mobile-release.yml` (`ios-release` `$0` steps) | `[ ]` |
| 11 | `MOB-PERF-01`, `M-GNFR-01` | **iPhone Vật lý: `NEPacketTunnelProvider` & Jetsam `RSS <= 25 MiB`** | *(Không thể chạy trên Simulator không có kernel `utun`/Jetsam thật)* | Cấp Apple Developer `$99/năm` (`packet-tunnel-provider`), chạy Xcode Instruments Allocations/Jetsam trên iPhone thật đo đỉnh **`RSS <= 25 MiB`** | Biên bản [mobile-hardware-acceptance-protocol.md](./mobile-hardware-acceptance-protocol.md) (§3 `M-IOS-01`) | `[ ]` *(hardware_signoff_required)* |
| 12 | `MOB-PERF-03`, `MOB-REL-03` | **iPhone Vật lý: Energy Log `<= 1.5%/giờ` & Roaming LTE/NAT64** | *(Simulator không có modem 4G/5G/RRC thật)* | Đo Xcode Energy Log `>= 60 phút` khóa màn hình (**`<= 1.5%/giờ`**), roaming Wi-Fi ↔ 4G/5G NAT64 `<= 5 s`, Lock/Unlock `-25308`, On-Demand Disconnect | Biên bản [mobile-hardware-acceptance-protocol.md](./mobile-hardware-acceptance-protocol.md) (§3 `M-IOS-02..04`) | `[ ]` *(hardware_signoff_required)* |
| 13 | `US-098` | **Store Release Pipeline (`.github/workflows/mobile-release.yml`)** | Tag `v0.2.*` tạo `.apk` + `.aab` + `MeshMobileFFI.xcframework.tar.gz` + `SHA256SUMS` lên GitHub Release (`$0`, tự bỏ qua an toàn khi thiếu secrets Store) | Cấu hình `APPLE_TEAM_ID` + `APP_STORE_CONNECT_API_KEY_JSON` (và `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` + keystore nếu đẩy Play Internal) để ký `.ipa` & đẩy TestFlight | `.github/workflows/mobile-release.yml` | `[ ]` |

---

## 3. Khối Ký Duyệt Phát Hành (`Go-Live Sign-Off Block`)

- **Phiên bản mục tiêu:** `v0.2.0`
- **Cam kết / Tag CI:** `____________________`
- **Báo cáo QA (`lab/.tmp/mobile-qa-report.json`):** `[ ] PASS   [ ] FAIL`
- **Phạm vi `$0` Ready & Verified (Hạng mục 1–10 & phần `$0` mục 13):** `[ ] APPROVED   [ ] BLOCKED`
- **Phạm vi `hardware_signoff_required` (iPhone vật lý — Apple Developer `$99/năm`, Hạng mục 11–13):** `[ ] SIGNED   [ ] DEFERRED ($0 Mode)`
- **Engineering Lead / Tech Lead:** `____________________` Ngày: `____________`
- **DevOps / Release Owner:** `____________________` Ngày: `____________`
- **Quyết định Phát hành:** `[ ] GO ($0 Android + iOS Source/XCFramework)   [ ] FULL STORE GO (Android + TestFlight)   [ ] NO-GO`
