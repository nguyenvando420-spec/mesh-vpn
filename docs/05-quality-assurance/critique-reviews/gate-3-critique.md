# Báo cáo Phản biện Độc lập Trước Gate 3 (Independent Pre-Gate-3 Red-Team Critique — Round 1 & Round 2 Re-Verification)

- **Người phản biện**: `agile-critic` (`critic-2` — Independent Pre-Gate-3 Red-Team Reviewer)
- **Ngày kiểm định**: `2026-11-14` (Round 1 Audit & Round 2 Independent Re-Verification)
- **Phạm vi kiểm định tổng thể trước Gate 3**:
  - **Quản trị & Yêu cầu gốc**: [agile-state.md](file:///D:/Project/Idea/mesh-vpn/docs/04-sprint-management/agile-state.md), [sprint-backlog.md](file:///D:/Project/Idea/mesh-vpn/docs/04-sprint-management/sprint-backlog.md), [production-readiness-requirements.md](file:///D:/Project/Idea/mesh-vpn/docs/01-discovery/production-readiness-requirements.md), [product-backlog.md](file:///D:/Project/Idea/mesh-vpn/docs/02-product-planning/product-backlog.md) (`51 Must / 234 SP` + `11 Should / 35 SP` = `62 User Stories / 269 SP`)
  - **Thiết kế & Quy chuẩn Kỹ thuật**: [coding-standards.md](file:///D:/Project/Idea/mesh-vpn/.agents/rules/coding-standards.md), [coding-standards.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/coding-standards.md), [tech-stack-decision.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/tech-stack-decision.md), [architecture-decision-record.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/architecture-decision-record.md), [system-architecture.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/system-architecture.md), [database-design.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/database-design.md), [api-design.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/api-design.md)
  - **Mã nguồn 10 Crates & Kịch bản QA / SLO**: `crates/{mesh-core,mesh-sys,mesh-crypto,mesh-proto,mesh-net,mesh-store,mesh-datapath,mesh-server,meshd,mesh}`, bộ test QA độc lập `qa_sprint1_*.rs` & `qa_sprint2_*.rs`, bộ test SLO [slo_wave2_suite.rs (server)](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/tests/slo_wave2_suite.rs) & [slo_wave2_suite.rs (datapath)](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/tests/slo_wave2_suite.rs)
  - **Hạ tầng Đóng gói, CI/CD, QA & Vận hành (`WP-S2-04`)**: [ci.yml](file:///D:/Project/Idea/mesh-vpn/.github/workflows/ci.yml), [run-slo-suite.ps1](file:///D:/Project/Idea/mesh-vpn/scripts/run-slo-suite.ps1), [run-slo-suite.sh](file:///D:/Project/Idea/mesh-vpn/scripts/run-slo-suite.sh), `scripts/install-*.{sh,ps1}`, [run-all-chaos.sh](file:///D:/Project/Idea/mesh-vpn/lab/scenarios/run-all-chaos.sh), [slo-verification-report.json](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/slo-verification-report.json), [slo-verification-report.md](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/slo-verification-report.md), [operational-runbook.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/operational-runbook.md), [hardware-sleep-wake-protocol.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/hardware-sleep-wake-protocol.md), [go-live-checklist.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/go-live-checklist.md), [release-plan.md](file:///D:/Project/Idea/mesh-vpn/docs/06-release-deployment/release-plan.md), [deployment-checklist.md](file:///D:/Project/Idea/mesh-vpn/docs/06-release-deployment/deployment-checklist.md), [rollback-plan.md](file:///D:/Project/Idea/mesh-vpn/docs/06-release-deployment/rollback-plan.md), [dod-verification.md](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/dod-verification.md)
- **Đối chiếu phản biện trước**: [wave-2-1-critique.md](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/critique-reviews/wave-2-1-critique.md) (`16/16 CLOSED`)

---

## 1. Đánh giá Tổng quan Kiến trúc, Kỷ luật Mã nguồn & Đóng lỗi Trước đó

1. **Kỷ luật Rust `1.94.1` & Ranh giới Kiến trúc 10 Crates (Kiểm chứng tĩnh độc lập sau Round 2)**:
   - Quét AST/regex toàn bộ kho mã (`.rs`, `.toml`, `.md`, `.ps1`, `.sh`, `.json`, `.yml`, `.yaml`, `.plist`, `.service`) xác nhận:
     - **`0` file chứa UTF-8 BOM**, **`0` file LF chứa `CRLF`**, **`0` file `.ps1/.bat/.cmd` chứa bare `LF`**.
     - **`0` `#[allow(clippy::...)]`**, **`0` `unsafe` ngoài `crates/mesh-sys/`**, **`0` `.expose_secret()` ngoài 4 crate được cấp phép** (`mesh-crypto`, `mesh-datapath`, `mesh-net`, `mesh`).
     - **`0` `.unwrap()` / `.expect()` / `panic!()` / `todo!()` / `unimplemented!()` / `unreachable!()` / `dbg!()`** và **`0` `println!()` / `eprintln!()`** trong mã nghiệp vụ của cả 10 crates (ngoài CLI `crates/mesh`; kể cả lệnh `--restore-from` của `mesh-server` dùng `writeln!(stdout.lock(), ...)` có xử lý `AppError` chuẩn mực tại [main.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/main.rs#L215-L221)).
   - Cô lập phụ thuộc đúng tuyệt đối theo ADR: `x509-cert` chỉ ở `mesh-crypto`, `defguard_boringtun` chỉ ở `mesh-datapath`, `redb` chỉ ở `mesh-store`, `libc` & `windows-sys` chỉ ở `mesh-sys` (`undocumented_unsafe_blocks = "deny"` tại [crates/mesh-sys/Cargo.toml](file:///D:/Project/Idea/mesh-vpn/crates/mesh-sys/Cargo.toml#L17-L31)), toàn bộ TLS crate tắt `default-features` và ép `ring` ([Cargo.toml](file:///D:/Project/Idea/mesh-vpn/Cargo.toml#L55-L66), [deny.toml](file:///D:/Project/Idea/mesh-vpn/deny.toml#L51-L83)).
   - Cổng kiểm chứng thực nghiệm trên Host (`main` sau Round 2): `scripts/check.ps1 -Cross` -> `EXIT 0` (**`308 passed; 0 failed; 0 ignored`** trên 26 test suites, `cargo-deny` sạch cho 6 target triples, cross-check `linux-musl` + `apple-darwin` xanh), `wsl bash -n` trên 15 `.sh` scripts -> `EXIT 0`, và `scripts/run-slo-suite.ps1 -SkipStaticChecks` -> `EXIT 0` (**`33 PASS / 0 FAIL / 1 pending_external_lab / 2 hardware_signoff_required`**).
2. **Đóng trọn vẹn 16/16 phát hiện của Wave 2.1 + Vá triệt để lỗ hổng `disco_pubkey` Lockout**:
   - Tại [control_handlers.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs#L371-L396), nhánh `req.disco_pubkey != auth.proof.disco_pubkey` gọi `record_auth_failure_with_audit(...)` kích hoạt khóa IP ở lần thứ 11 (`429 Too Many Requests`, kiểm chứng bởi [qa_sprint2_server_e2e_and_appsec.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/tests/qa_sprint2_server_e2e_and_appsec.rs#L350-L423)), đồng thời `handle_register_node` dùng `active_public_host(&state)` đóng lưu ý `§5.3` của Wave 2.1.

### Tổng hợp Trạng thái Các Phát hiện Qua 2 Vòng Kiểm định Gate 3

| Mã Phát hiện | Mức độ R1 | Tóm tắt Vấn đề (Round 1) | Trạng thái Round 2 |
| :--- | :---: | :--- | :---: |
| `HR-G3-01` | `🟠 High Risk` | Đứt gãy đóng gói `ci.yml` (`wintun.dll`, `SHA256SUMS`, units), lỗi thiếu fallback `.plist` ở `install-macos.sh`, sai thứ tự unit mặc định ở `install-linux.sh` | **`CLOSED`** |
| `HR-G3-02` | `🟠 High Risk` | `install-server.sh` in `--server https://...` khiến `client_cmds.rs` bọc nhầm IPv6 `"[https://...]:443"` | **`CLOSED`** |
| `HR-G3-03` | `🟠 High Risk` | Độ trung thực SLO (`US-058`): `PERF-09` tự nới `64 MiB` & đo `size_of`, `PERF-01` đo cỡ file `.redb`, `OPS-02/03` ghi nhầm Docker Lab, `PERF-11` trùng khóa & chưa vượt burst | **`CLOSED`** |
| `HR-G3-04` | `🟠 High Risk` | Deadlock khôi phục thảm họa (`mesh server restore`) khi `control.redb` hỏng hoặc dựng VPS thay thế (`Pin_TEMP`) | **`CLOSED`** |
| `MED-G3-01` | `🟡 Medium` | `check-macos` thiếu `run-slo-suite.sh`, `docker-build-and-lab` chạy trùng kịch bản S1, quét BOM/LF hẹp trong `ci.yml` | **`CLOSED`** |
| `MED-G3-02` | `🟡 Medium` | Ngoại lệ `docs/04-sprint-management` trong `check.{ps1,sh}` che giấu BOM/CRLF thật và lệch đuôi tệp trong `check.sh` | **`CLOSED`** |
| `MED-G3-03` | `🟡 Medium` | Thiếu cảnh báo biến biên dịch `MESH_WINTUN_SHA256` khi tự `cargo build --release` trên Windows | **`CLOSED`** |
| `MED-G3-04` | `🟡 Medium` | Chênh lệch kích thước binary release `mesh-server` (`8.03 MiB`) so với ước tính ban đầu (`~3–6 MB`) trong `tech-stack-decision.md` | **`CLOSED`** |
| `LOW-G3-01` | `🟢 Low` | Đường dẫn ví dụ `/run/mesh/preauth.key` không tồn tại mặc định trong `install-server.sh` | **`CLOSED`** |
| `LOW-G3-02` | `🟢 Low` | Đồng bộ tổng số bài kiểm thử tự động (`308/308 PASS`, `33/36 SLO PASS`) trong hồ sơ QA | **`CLOSED`** |

---

## 2. Hồ sơ Phát hiện Round 1 & Xác minh Độc lập Round 2 (`10 / 10 CLOSED`)

### `🔴 Blockers`
*Không có phát hiện mức `🔴 Blocker` ở cả Round 1 lẫn Round 2.*

---

### `🟠 High Risks` (Đã xác minh đóng sạch 4/4 tại Round 2)

#### `HR-G3-01` — Đứt gãy Chuỗi Đóng gói Release (`ci.yml`) & Lỗi Installer macOS / Linux (`US-051`, `US-052`, `US-059`) — **`[CLOSED — R2 Verified]`**
- **Phát hiện Round 1**:
  1. `scripts/install-macos.sh` gán cứng `PLIST_SRC="${FROM_DIR}/deploy/launchd/internal.mesh.meshd.plist"` không có fallback về `${REPO_ROOT}`, khiến câu lệnh cài đặt trong Runbook/Checklist/Hardware Protocol thoát lỗi `exit 1`.
  2. `.github/workflows/ci.yml` (`release-build-matrix`) chỉ copy 3 binary trần vào `dist/<target>/`, bỏ rơi `wintun.dll` + `wintun.dll.sha256` (vốn đã ghim vào `meshd.exe` lúc compile), `WINTUN-LICENSE.txt`, `SHA256SUMS` và các service unit/plist trái với `release-plan.md`.
  3. `scripts/install-linux.sh` (`resolve_unit_src()`) ưu tiên `meshd-desktop.service` trước `deploy/systemd/meshd.service` (hardened).
- **Xác minh Độc lập Round 2**:
  - [install-macos.sh](file:///D:/Project/Idea/mesh-vpn/scripts/install-macos.sh#L161-L178): Đã bổ sung chuỗi fallback đầy đủ (`${FROM_DIR}/internal.mesh.meshd.plist` -> `${FROM_DIR}/deploy/launchd/internal.mesh.meshd.plist` -> `${SCRIPT_DIR}/internal.mesh.meshd.plist` -> `${REPO_ROOT}/deploy/launchd/internal.mesh.meshd.plist`) và tự động nhận `${FROM_DIR}/SHA256SUMS`.
  - [install-linux.sh](file:///D:/Project/Idea/mesh-vpn/scripts/install-linux.sh#L95-L140): `resolve_unit_src()` đã ưu tiên bản cứng hóa `deploy/systemd/meshd.service` trên cả `${FROM_DIR}`, `${SCRIPT_DIR}` và `${REPO_ROOT}` trước khi fallback sang `meshd-desktop.service` — khớp 100% với `operational-runbook.md` Mục 2.4.
  - [ci.yml](file:///D:/Project/Idea/mesh-vpn/.github/workflows/ci.yml#L367-L369) & [ci.yml](file:///D:/Project/Idea/mesh-vpn/.github/workflows/ci.yml#L411-L458): Job `release-build-matrix` đã đóng gói đầy đủ `wintun.dll`, `WINTUN-LICENSE.txt`, `wintun.dll.sha256`, `scripts/install-windows.ps1` cho Windows; `deploy/systemd/*`, `deploy/linux-desktop/*`, `scripts/install-{linux,server}.sh`, `SHA256SUMS` cho Linux; và `deploy/launchd/internal.mesh.meshd.plist`, `scripts/install-macos.sh`, `SHA256SUMS` cho cả 2 target macOS.

#### `HR-G3-02` — Lệnh Onboarding `install-server.sh` & Bọc Nhầm Ngoặc Vuông IPv6 trên URL Scheme (`US-004`, `US-050`, `US-059`) — **`[CLOSED — R2 Verified]`**
- **Phát hiện Round 1**: `install-server.sh:244` in `mesh up --server https://...`, khiến `split_endpoint_host_and_port` trong `client_cmds.rs` cắt theo `rsplit_once(':')` và bọc nhầm `host.contains(':')` thành `"[https://...]:443"`.
- **Xác minh Độc lập Round 2**:
  - [install-server.sh](file:///D:/Project/Idea/mesh-vpn/scripts/install-server.sh#L243-L246): Đã bỏ `https://` và chuyển mẫu lệnh sang `--server ${PUBLIC_HOST}:${TCP_PORT} --server-pin ${ACTIVE_PIN} --authkey-stdin` (kèm ví dụ `--authkey-file ./preauth.key` `0600`, đồng thời đóng luôn `LOW-G3-01`).
  - [client_cmds.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh/src/client_cmds.rs#L408-L413): `split_endpoint_host_and_port` chặn ngay `if input.contains("://")` ở đầu hàm với thông báo rõ ràng `"server endpoint must be <host:port> without URL scheme (omit https:// or http://)"` cho cả `mesh up` và `mesh set`, có bài kiểm thử hồi quy `test_up_and_set_reject_server_url_scheme_https` tại [client_cmds.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh/src/client_cmds.rs#L976-L1050).

#### `HR-G3-03` — Tính Toàn vẹn Bằng chứng & Ngưỡng Bộ Kiểm chứng SLO Tự động (`US-058 AC2/AC3`) — **`[CLOSED — R2 Verified]`**
- **Phát hiện Round 1**: `PERF-09` tự ý nới ngưỡng từ `<= 50 MB` lên `<= 64.0 MiB` và chỉ nhân `size_of`; `PERF-01` trên Windows fallback sang kích thước file `.redb`; `OPS-02/03` báo đã chạy Docker Lab khi thực tế `pending_external_lab`; `PERF-11` bị ghi đè khóa và gửi lưu lượng nhỏ hơn burst bucket.
- **Xác minh Độc lập Round 2**:
  - **Khôi phục ngưỡng `PERF-09 <= 50.0 MiB` & đo RSS tiến trình sống**: [slo_wave2_suite.rs (datapath)](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/tests/slo_wave2_suite.rs#L661-L764) đo RSS/WorkingSet thực tế trên Linux (`/proc/self/status`), macOS (`/bin/ps -o rss=`) và Windows (`WorkingSet64`), ghi nhận `12.54 MiB <= 50.0 MiB` (`struct_mib = 0.224770 MiB < 5.0 MiB`) tại [slo-verification-report.json](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/slo-verification-report.json#L118-L126).
  - **Đo RSS/WorkingSet bản Release `mesh-server` cho `PERF-01`**: [run-slo-suite.ps1](file:///D:/Project/Idea/mesh-vpn/scripts/run-slo-suite.ps1#L219-L349), [run-slo-suite.sh](file:///D:/Project/Idea/mesh-vpn/scripts/run-slo-suite.sh#L185-L298) và [slo_wave2_suite.rs (server)](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/tests/slo_wave2_suite.rs#L799-L879) khởi chạy tiến trình release `mesh-server` và đo `WorkingSet64`/RSS ngay tại thời điểm `/readyz` đạt `200 OK` (`10.5 MiB <= 128.0 MiB` tại [slo-verification-report.json](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/slo-verification-report.json#L48-L56)).
  - **Tách `PERF-11` (`Mbps`) & `PERF-11-QUEUE` (`frames`) và ép vượt burst**: [slo_wave2_suite.rs (server)](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/tests/slo_wave2_suite.rs#L892-L1138) truyền `2,200 x 1,200 B = 2.64 MB` (`> 625 KB` burst) trên luồng tốt `d->b` đạt `10.77 Mbps >= 2.0 Mbps` đồng thời bắt buộc `assert!(got_throttle)` (`RelayNoticeCode::Throttled`) trên luồng bão hòa `a->c`; phía client tách thành `PERF-11-QUEUE` ([slo_wave2_suite.rs (datapath)](file:///D:/Project/Idea/mesh-vpn/crates/mesh-datapath/tests/slo_wave2_suite.rs#L600-L607)).
  - **Trung thực nguồn bằng chứng `OPS-02/03`**: [run-slo-suite.ps1](file:///D:/Project/Idea/mesh-vpn/scripts/run-slo-suite.ps1#L464) và [run-slo-suite.sh](file:///D:/Project/Idea/mesh-vpn/scripts/run-slo-suite.sh#L366) kiểm tra `$chaosStatus -eq "PASS"`, ghi rõ `(Docker lab pending_external_lab)` tại [slo-verification-report.json](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/slo-verification-report.json#L375-L385) khi chưa bật `-WithDockerLab`.

#### `HR-G3-04` — Deadlock Khôi phục Thảm họa khi `control.redb` Hỏng hoặc Khôi phục sang VPS Mới (`US-045`, `REL-12`, `US-059`) — **`[CLOSED — R2 Verified]`**
- **Phát hiện Round 1**: `mesh server restore` đòi UDS `/run/mesh-server/admin.sock`, nhưng `mesh-server` thoát lỗi trước khi mở UDS nếu `control.redb` hỏng, hoặc sinh `Pin_TEMP` xung đột trên VPS mới trống; hướng dẫn `age -d` thiếu `chown mesh:mesh` và `.sha256` sidecar.
- **Xác minh Độc lập Round 2**:
  - [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L1268-L1317) & [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L1644-L1662): Bổ sung `ControlStore::restore_offline_with_clock(...)` giữ `redb` cô lập 100% trong `mesh-store`. Khi `db_path` chưa tồn tại (VPS mới) hoặc bị hỏng không đọc được, hàm đặt `expected_published_pin = None` nhưng vẫn giữ nguyên chốt chặn yêu cầu snapshot phải có `server_identity` (trừ khi bật `--allow-pin-change`), kiểm tra `.sha256` fail-closed, hoán đổi nguyên tử và nâng `netmap_version_watermark` `>= +1_000_000`. Nếu DB đích đang khỏe với một pin khác, hàm từ chối với `ErrorKind::Conflict` nếu không truyền `--allow-pin-change`.
  - [main.rs (mesh-server)](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/main.rs#L57-L66) & [main.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/main.rs#L99-L221): Bổ sung cờ `--restore-from <PATH>`, `--min-netmap-version <U64>` và `--allow-pin-change` chạy trước khi mở DB live hay bind socket, xuất JSON không chứa bí mật. Đã có 4 bài kiểm thử toàn diện tại [store.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs#L2575-L2627) và [main.rs](file:///D:/Project/Idea/mesh-vpn/crates/mesh-server/src/main.rs#L578-L770).
  - [operational-runbook.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/operational-runbook.md#L389-L426) và [rollback-plan.md](file:///D:/Project/Idea/mesh-vpn/docs/06-release-deployment/rollback-plan.md#L53-L85): Tách bạch rõ **Cold / Offline Restore** (`systemctl stop mesh-server` -> giải mã `.redb` + `.sha256` -> `chown mesh:mesh` + `chmod 0600` -> `sudo -u mesh mesh-server --config /etc/mesh/server.toml --restore-from ...`) và **Hot Restore** qua UDS khi daemon đang chạy khỏe.

---

### `🟡 Medium / Improvements` & `🟢 Low / Nitpicks` (Đã xác minh đóng sạch 6/6 tại Round 2)

- **`MED-G3-01` (`CLOSED`)**: [ci.yml](file:///D:/Project/Idea/mesh-vpn/.github/workflows/ci.yml#L55-L64) mở rộng quét UTF-8 no-BOM + LF sang `docs`, `scripts`, `deploy`; [ci.yml](file:///D:/Project/Idea/mesh-vpn/.github/workflows/ci.yml#L191-L200) chạy `run-slo-suite.sh` và upload `slo-report-macos` trên `check-macos`; [ci.yml](file:///D:/Project/Idea/mesh-vpn/.github/workflows/ci.yml#L480-L491) gỡ bỏ lệnh gọi trùng `test-udp-blocked-443-only.sh`.
- **`MED-G3-02` (`CLOSED`)**: [check.ps1](file:///D:/Project/Idea/mesh-vpn/scripts/check.ps1#L52-L74) và [check.sh](file:///D:/Project/Idea/mesh-vpn/scripts/check.sh#L37-L61) đã gỡ bỏ ngoại lệ `docs/04-sprint-management` và đồng bộ đầy đủ đuôi tệp; `agile-state.md` và `model-performance.md` đã chuẩn hóa UTF-8 no-BOM + LF (`0` vi phạm trên toàn repo).
- **`MED-G3-03` (`CLOSED`)**: Đã bổ sung cảnh báo biến biên dịch `$env:MESH_WINTUN_SHA256` trước `cargo build --release` cho bản tự build trên Windows tại [operational-runbook.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/operational-runbook.md#L194-L199), [hardware-sleep-wake-protocol.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/hardware-sleep-wake-protocol.md#L32) và [release-plan.md](file:///D:/Project/Idea/mesh-vpn/docs/06-release-deployment/release-plan.md#L24).
- **`MED-G3-04` (`CLOSED`)**: [tech-stack-decision.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/tech-stack-decision.md#L60) & [tech-stack-decision.md](file:///D:/Project/Idea/mesh-vpn/docs/03-system-design/tech-stack-decision.md#L317) đã ghi nhận minh bạch số đo thực tế bản release (`mesh 1.76 MiB`, `meshd 5.87 MiB`, `mesh-server 8.03 MiB`), nằm gọn dưới trần cứng `<= 16 MiB` của CI.
- **`LOW-G3-01` & `LOW-G3-02` (`CLOSED`)**: Đã cập nhật mẫu lệnh authkey tại [install-server.sh](file:///D:/Project/Idea/mesh-vpn/scripts/install-server.sh#L243-L246) và đồng bộ số liệu `308 / 308 PASS` + `33 / 36 SLO PASS` xuyên suốt [test-plan.md](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/test-plan.md#L60-L67), [sprint-2-dod-verification.md](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/sprint-2-dod-verification.md#L21-L22), và [dod-verification.md](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/dod-verification.md#L22-L45).

---

## 3. `⚖️ Strategic Trade-offs` — Các Đánh đổi Chiến lược Để Người Dùng Cân nhắc tại Gate 3

Toàn bộ phần mềm, bộ kiểm thử tự động (`308/308`), cổng kiểm chứng SLO trên máy phát triển (`33/36`), quy trình CI/CD và bộ tài liệu vận hành / khôi phục thảm họa đã đạt chuẩn kỹ thuật xuất sắc để trình **Gate 3**. Để quyết định nghiệm thu & đưa vào vận hành thực tế (`Go-Live`) hoàn toàn minh bạch, người dùng cần lưu ý **4 đánh đổi chiến lược theo thiết kế (`by-design`)** dưới đây:

1. **Ba Hạng mục Kiểm chứng Môi trường Ngoài Sandbox (`PERF-02`, `PLAT-05`, `PLAT-06`) Cần Thực thi Trước khi Cắt băng Go-Live Thật**:
   - **Hiện trạng minh bạch (`US-058 AC2`, `GNFR-12`)**: Báo cáo [slo-verification-report.md](file:///D:/Project/Idea/mesh-vpn/docs/05-quality-assurance/slo-verification-report.md#L45-L62) giữ trung thực tuyệt đối không giả lập số liệu cho:
     - `PERF-02` (`pending_external_lab`): Đo CPU nhàn rỗi `< 2%` trong 5 phút và bộ 8 kịch bản chaos mạng (`lab/scenarios/run-all-chaos.sh`) trên Linux Docker host có `/dev/net/tun` + `NET_ADMIN` (hoặc kích hoạt job `docker-build-and-lab` với `run_live_nat_lab = true` trên GitHub Actions).
     - `PLAT-05` & `PLAT-06` (`hardware_signoff_required`): Kiểm tra gập nắp máy ngủ `>= 4 phút` (`P95 <= 15 s`), chuyển mạng Wi-Fi <-> 4G/5G Hotspot, `utun` / `launchd` / `LOCAL_PEERCRED` / macOS Firewall và Windows Modern Standby (`S0ix`/`S3`) không sinh ghost adapter `#2` trên MacBook thật và Laptop Windows thật.
   - **Khuyến nghị điều hành**: Duyệt **Gate 3 (Hoàn tất Phát triển & Kiểm thử Phần mềm `v0.1.0`)**, sau đó chạy biên bản 15–20 phút tại [hardware-sleep-wake-protocol.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/hardware-sleep-wake-protocol.md#L118-L139) và đánh dấu đủ 20 mục trong [go-live-checklist.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/go-live-checklist.md#L41-L65) trên VPS + laptop thật trước khi chuyển lưu lượng Production.

2. **Đánh đổi giữa Tính Sống sót khi Sập Control (`REL-01`) và Độ trễ Thu hồi khi Control Cô lập Mạng (`SEC-08`)**:
   - Khi VPS Control còn trực tuyến (kể cả khi hỏng đĩa kép `Dual-EIO`), lệnh `mesh node revoke` khóa RAM `< 1 ms` (`0.26 ms` thực đo) và cắt đường truyền ngang hàng trong `<= 2 s`.
   - Tuy nhiên, nếu bản thân VPS Control mất kết nối Internet hoàn toàn, kiến trúc ưu tiên giữ sống các đường hầm P2P đã xác lập dựa trên cache cục bộ (`REL-01`), đồng nghĩa lệnh thu hồi mới chỉ có thể áp xuống các peer đang ngoại tuyến ngay khi chúng kết nối lại Control hoặc khi hết hạn phiên/khóa ([operational-runbook.md](file:///D:/Project/Idea/mesh-vpn/docs/06-operations/operational-runbook.md#L537)).

3. **Đóng gói macOS MVP Không Tốn Phí Apple Developer `$99/năm` (`PLAT-01`, `US-051`) vs Bộ cài GUI `.pkg` Đã Notarize**:
   - Phiên bản `0.1.0` phân phối tarball kèm `SHA256SUMS` qua `scripts/install-macos.sh` (kiểm tra SHA-256 fail-closed, chỉ gỡ cờ quarantine trên binary đã xác thực băm và ký ad-hoc `codesign --force -s -` tại chỗ, giữ nguyên Gatekeeper toàn hệ thống).
   - Đánh đổi: Cần chạy một lệnh `sudo sh scripts/install-macos.sh ...` trên Terminal thay vì trình cài đặt đồ họa `.pkg` (có thể nâng cấp ở Phase 2 nếu mua tài khoản Apple Developer ID).

4. **Embedded Single-IP STUN (`ADR-008`, `US-023`) & Dung lượng Binary `mesh-server` Tất-cả-trong-một (`8.03 MiB`)**:
   - Việc gộp cả 4 vai trò (**Control Plane + Blind Relay + STUN + ACME/Obs**) vào đúng **1 binary tĩnh `mesh-server` (`8.03 MiB`, RAM sống `10.5 MiB`) trên 1 VPS / 1 IPv4** giúp tối giản tối đa chi phí và vận hành (không cần VPS thứ hai cho RFC 5780 Dual-IP STUN, không cần Nginx/Caddy hay `coturn` bắt buộc), đổi lại kích thước file thực thi nhỉnh hơn mức ước tính sơ bộ `6 MiB` ban đầu khoảng `2 MiB` (vẫn thấp hơn 2 lần trần cứng `16 MiB`).

---

## 4. Phán quyết Cuối cùng Trước Gate 3 (Final Verdict)

Toàn bộ **10/10 phát hiện của Round 1** (bao gồm cả **4/4 mục `🟠 High Risk`**, **4/4 mục `🟡 Medium`** và **2/2 mục `🟢 Low`**) đã được khắc phục triệt để, có kiểm thử tự động chống hồi quy đầy đủ (`308/308 PASS`), tuân thủ tuyệt đối chuẩn mã hóa và bảo mật của dự án (`0 Blocker`, `0 High Risk`, `0 #[allow(clippy::...)]`, `0 UTF-8 BOM / CRLF`). Hồ sơ sẵn sàng để trình Người dùng phê duyệt tại **Gate 3**.

**Kết luận Phán quyết:** **`[APPROVED FOR GATE]`**
