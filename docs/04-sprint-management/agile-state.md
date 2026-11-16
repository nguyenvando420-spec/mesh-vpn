# Agile State — Trạng Thái Điều Phối Dự Án

> Main Agent (Scrum Master) cập nhật file này sau mỗi bước quan trọng và đọc lại đầu mỗi phiên / sau khi server restart.

## Giai đoạn hiện tại

- **Thư mục gốc dự án**: `D:\Project\Idea\mesh-vpn`
- **Nhánh làm việc hiện hành**: `feat/mobile-clients` (tách từ `main` `bb25ee57d8e74d1074eb4f2b5bd7b4ae65cfde0d`; giữ nguyên `main` và GitHub Pre-release **`v0.1.0-rc1`** đang chờ ký 4 mục phần cứng vật lý)
- **Giai đoạn Milestone 1 (`v0.1.0` Desktop + Server trên `main`)**: `Gate 3 Pre-release (v0.1.0-rc1) — Giữ tag GA v0.1.0 tới khi đủ 20/20 Go-Live Checklist trên MacBook + Laptop Windows thật`
- **Giai đoạn Milestone 2 (`v0.2.0` Mobile Clients — Android & iOS trên `feat/mobile-clients`)**: **`Chặng 3 Đang thực hiện — Hoàn tất Wave A + Wave B + Wave C (117/117 SP) → Nghiệm thu Độc lập QA & Gate 3 Critique`**
- **Phạm vi Chặng 1, 2 & 3 Mobile (`v0.2.0`)**: `4 Epics (EP-13..EP-16) · 25 Stories (US-075..099) = 117 SP (22 Must = 108 SP · 2 Should = 6 SP · 1 Could = 3 SP) · 9 Work Packages (WP-M-A0..WP-M-C2) · Phủ 34/34 mã MOB-* (25 P0, 8 P1, 1 P2)`
- **Bước tiếp theo**: `Independent QA (qa-mob) & Gate 3 Critique (critic-mob-g3) → Trình duyệt Mobile Gate 3`

## Trạng thái Gate — Phase 2 / Milestone `v0.2.0` (Mobile: Android & iOS)

| Gate | Trạng thái | Ngày | Ghi chú & Tài liệu nghiệm thu |
|---|---|---|---|
| Mobile Gate 1 — Nghiên cứu & Backlog (`v0.2.0`) | ✅ **Đã duyệt** (`[APPROVED FOR GATE]` bởi `critic-mob-g1` Vòng 2) | 2026-11-15 | [mobile-readiness-requirements.md](../01-discovery/mobile-readiness-requirements.md) (`34` `MOB-*`), [mobile-product-backlog.md](../02-product-planning/mobile-product-backlog.md) v1.1 (`25 Stories / 117 SP`, `22 Must = 108 SP`), [mobile-gate-1-critique.md](../05-quality-assurance/critique-reviews/mobile-gate-1-critique.md) (`11/11 Đã đóng`). **5 quyết định Người dùng đã chốt (`OQ-MOB-01..05`)**: (1) `OQ-MOB-01` **Phương án A** (Wave A → **song song** Wave B1 Android + Wave B2 iOS → Wave C QA); (2) `OQ-MOB-02` **Chưa chi `$99/năm` Apple ngay (`$0` Mode)**: phát hành `.apk` máy thật Android (`$0`), iOS hoàn thiện đủ mã nguồn & kiểm chứng build `.xcframework` + iOS Simulator (`CODE_SIGNING_ALLOWED=NO`, `$0` trên CI), tách chạy tunnel iPhone vật lý sang cổng `hardware_signoff_required (chờ Apple Developer $99/năm)`; (3) `OQ-MOB-03` Hỗ trợ cả 3 luồng nhập trong app (**QR camera + dán URI `mesh://` + nhập tay**) kèm màn hình xác nhận Endpoint+Pin và **cấm OS deep-link cho `mpk_*`**; (4) `OQ-MOB-04` **Chỉ Split-Tunnel** (overlay CIDR động từ Netmap + `.mesh.internal`, hoãn Exit Node sang `v0.3.0`, cảnh báo Lockdown/Strict Private DNS); (5) `OQ-MOB-05` **Mở ngoại lệ `MPL-2.0` giới hạn riêng cho `uniffi*`** tại lớp FFI mobile (giữ `MIT/Apache-2.0/BSD` 100% cho `mesh-server`/`meshd`/`mesh`/core crates). |
| Mobile Gate 2 — Stack/FFI, Architecture & Sprint Plan (`v0.2.0`) | ✅ **Đã duyệt** (`[APPROVED FOR GATE]` bởi `critic-mob-g2` Vòng 2; Người dùng duyệt `A1/A2/A3`) | 2026-11-15 | Người dùng xác nhận 3 hạng mục Gate 2 (`2026-11-15`): (1) Duyệt thiết kế `ADR-012..019`, kiến trúc `mesh-client`, `UniFFI` & 9 Work Packages (`WP-M-A0..WP-M-C2`); (2) Duyệt mở rộng Workspace (`crates/mesh-client`, `crates/mesh-mobile-ffi`, `tools/uniffi-bindgen`) + ngoại lệ hẹp `uniffi = "0.29.5"` (`MPL-2.0`/`anyhow`) + `rustls-platform-verifier = "0.6"` + `jni = "0.21"` cô lập trong `mesh-sys`; (3) Duyệt trọn gói `25/25 User Stories = 117 SP`. Hồ sơ: [mobile-tech-stack-decision.md](../03-system-design/mobile-tech-stack-decision.md), [mobile-adr.md](../03-system-design/mobile-adr.md), [mobile-coding-standards.md](../03-system-design/mobile-coding-standards.md), [mobile-system-architecture.md](../03-system-design/mobile-system-architecture.md), [mobile-ffi-and-storage-design.md](../03-system-design/mobile-ffi-and-storage-design.md), [mobile-sprint-backlog.md](./mobile-sprint-backlog.md) v1.1, [mobile-gate-2-critique.md](../05-quality-assurance/critique-reviews/mobile-gate-2-critique.md) (`15/15 CLOSED`, `8/8 EC`). |
| Mobile Gate 3 — Sprint Execution, Mobile QA & Release (`v0.2.0`) | 🔵 **Đang thực hiện** | 2026-11-16 | **Wave A (`00d8cc0`) + Wave B (`6bf7449`) + Wave C hoàn tất (`117/117 SP`)**: `WP-M-C1` (3 bộ `qa_mobile_*` E2E/Resilience/Security tests, `lab/mobile/*`, `mobile-{test-plan,security-audit}.md`) & `WP-M-C2` (`run-mobile-qa.{ps1,sh}`, `.github/workflows/mobile-release.yml`, `mobile-{operational-runbook,go-live-checklist,hardware-acceptance-protocol}.md`); `scripts/run-mobile-qa.ps1` (bao hàm `scripts/check.ps1 -Cross`) PASS 100% (`libmesh_mobile_ffi.so = 4,375,280 B <= 6 MiB`). Đang tiến hành **Nghiệm thu Độc lập `qa-mob` + `critic-mob-g3`**. |

### Đội hình Swarm Mobile `v0.2.0` (Chặng 1 & Chặng 2 — Đã hoàn tất & đóng toàn bộ worker)

| Chặng | Vai trò | Model đơn pha | Tên worker | Nhiệm vụ | Trạng thái |
|---|---|---|---|---|---|
| Chặng 1 | `agile-researcher` | `gemini-4-hydrogen-xhigh` | `researcher-mob` | Hoàn tất `mobile-readiness-requirements.md` Vòng 2 (`34` mã `MOB-*`, vá `BLK-MOB-01..03` & `HR-MOB-01..04`) | ✅ Done (Killed) |
| Chặng 1 | `agile-po-ba` | `gemini-4-hydrogen-high` | `poba-mob` | Hoàn tất `mobile-product-backlog.md` v1.1 (`25 Stories / 117 SP`, `100%` DoR `[H]/[E]/[F]`, `OQ-MOB-01..05`) | ✅ Done (Killed) |
| Chặng 1 | `agile-critic` | `gemini-4-carbon-high` | `critic-mob-g1` | Phản biện Gate 1 Vòng 1 (`[REVISION REQUIRED]`) + Tái thẩm định Vòng 2 (`[APPROVED FOR GATE]`, `11/11 Đã đóng`) | ✅ Done (Killed) |
| Chặng 2 | `agile-tech-lead` | `gemini-4-hydrogen-high` | `techlead-mob` | Hoàn tất `mobile-tech-stack-decision.md`, `mobile-adr.md` (`ADR-012..019`), `mobile-coding-standards.md` (R1 + R2) | ✅ Done (Killed) |
| Chặng 2 | `agile-architect` | `gemini-4-hydrogen-xhigh` | `architect-mob` | Hoàn tất `mobile-system-architecture.md`, `mobile-ffi-and-storage-design.md` (C4, `mesh-client`, `UniFFI 0.29.5`, DEK AEAD, Bounded TCP `:53`, NAT64) | ✅ Done (Killed) |
| Chặng 2 | `agile-scrum-master` | `gemini-4-hydrogen-high` | `sm-mob` | Hoàn tất `mobile-sprint-backlog.md` v1.1 (`WP-M-A0..WP-M-C2`, `25 Stories / 117 SP`, `0% File Overlap`) | ✅ Done (Killed) |
| Chặng 2 | `agile-critic` | `gemini-4-carbon-high` | `critic-mob-g2` | Phản biện Gate 2 Vòng 1 (`[REVISION REQUIRED]`: `6B/5H/3M/1L`) + Tái thẩm định Vòng 2 (`[APPROVED FOR GATE]`, `15/15 CLOSED`, `8/8 EC`) | ✅ Done (Killed) |

## Trạng thái Gate — Phase 1 / Milestone `v0.1.0` (Desktop + Server — Đã khóa tại `v0.1.0-rc1` trên `main`)

| Gate | Trạng thái | Ngày duyệt | Ghi chú của người dùng |
|---|---|---|---|
| Gate 1 — Nghiên cứu & Backlog | ✅ Đã duyệt | 2026-11-12 | (1) Ưu tiên làm Client cho **macOS và Windows trước** (Server chạy trên Ubuntu Linux VPS + hỗ trợ Linux TUN cho VPS làm node & phòng lab NAT); (2) Tạm thời **kết nối trực tiếp bằng IP VPS** (chế độ Pin chứng chỉ/khóa `SEC-04c`) và **hỗ trợ đổi port TCP/UDP tùy ý** (không khóa cứng 443/3478); (3) Giữ các mặc định: chia **2 đợt bàn giao** (Milestone 1 → Milestone 2), tự định nghĩa giao thức, tên CLI **`mesh`** (`.mesh.internal`), quản trị CLI/SSH cục bộ. |
| Gate 2 — Stack/Model, Code Format, Thiết kế & Sprint | ✅ Đã duyệt | 2026-11-13 | Người dùng duyệt gói Rust `1.94.1` v2.2 / Sprint Plan v1.2 kèm 2 mặc định khuyến nghị: (1) **`OQ-15` Mặc định A**: giữ **Sprint 1 = `38 Must / 174 SP`** & **Sprint 2 = `13 Must / 60 SP`** (+ `11 Should / 35 SP`); (2) **Chính sách lỗi phần cứng `EIO` kép**: compaction hợp nhất toàn bộ mục thu hồi chưa bền vững trong RAM (kể cả `ram_only`) trước khi gỡ `disk_degraded`; khi hết lease version đúng lúc cả 2 tầng đĩa lỗi `EIO`, vẫn cắt tức thì phiên Control/Relay của node bị thu hồi trong RAM và đóng stream buộc các peer xác thực lại (không phát version chưa lưu đĩa). |
| Gate 3 — Sprint Review, QA/AI Eval & Release | 🟡 Đã duyệt Pre-release `v0.1.0-rc1` (chờ ký phần cứng trước `v0.1.0`) | 2026-11-15 | Chặng 2A + 2B hoàn tất: `62 Stories / 269 SP`, `5/5` Docker NAT/Chaos Lab (`chaos-report.json` PASS), `PERF-02` 5-min VPS soak (`0.0262%` CPU PASS), `34/36` SLO PASS (`0 pending_external_lab`, `2 hardware_signoff_required`), `Go-Live Checklist` `16/20` `[x]`, `CI Gate` `a42ce23` xanh `9/9`. Tại Gate 3 (`2026-11-15`), người dùng chọn phát hành **pre-release `v0.1.0-rc1`** (gói cài 4 nền tảng + `mesh-server` OCI + `SHA256SUMS`) để nghiệm thu 4 mục phần cứng vật lý MacBook & Windows (`#11, #17, #18, #20`) và chỉ gắn tag chính thức `v0.1.0` sau khi đủ `20/20`. |

## Các Vai trò trong Team (13 Vai trò Chuẩn Plugin v3.1.0: Orchestrator + Swarm)

| Vai trò | Model | conversationId / tên worker | Nhiệm vụ gần nhất | Trạng thái |
|---|---|---|---|---|
| agile-scrum-master (Nhạc trưởng 2 pha / Swarm Coordinator) | `gemini-pro-orchestrator` (Orchestrator Carbon) | Main Agent | Hoàn tất Chặng 2B, sửa CI Gate xanh `9/9` (`a42ce23`) và thực thi quyết định Gate 3 của người dùng: cắt pre-release `v0.1.0-rc1` (giữ `v0.1.0` chờ ký phần cứng) | ✅ Done (`v0.1.0-rc1` Released) |
| agile-researcher | `claude-opus-5-5-high` (dự phòng: `gemini-4-argon-high`) | dae2b634-a323-4894-9519-7698811e921b | Hoàn tất đồng bộ v1.2 `production-readiness-requirements.md` (macOS P0 `PLAT-06`, IP+Pin `SEC-04c`, custom port & `SEC-15`) | ✅ Done (v1.2) |
| agile-po-ba | `claude-sonnet-5-5-high` (dự phòng: `gemini-4-carbon-high`) | 61249fa4-f35a-4f0e-9bd0-eaec4d8d4074 | Hoàn tất đồng bộ v1.2 `product-backlog.md` (997 dòng, 51 Must = 234 SP), `charter`, `vision`, `personas` | ✅ Done (v1.2) |
| agile-tech-lead | `gemini-4-argon-high` (dự phòng cho `claude-sonnet-5-5-high`) | 111ccb61-76da-4415-aa05-654afdb784c6 | Hoàn tất `scripts/check.ps1 -Cross` & `.gitignore` `*.o` | ✅ Done (`check.ps1 -Cross`) |
| agile-architect | `gemini-4-argon-high` (dự phòng cho `claude-opus-5-5-high`) | 991a5bee-a698-49a3-b364-1ee99581e4f1 | Hoàn tất Rust v2.2 (`system-architecture.md`, `database-design.md`, `api-design.md`) | ✅ Done (Rust v2.2) |
| agile-critic | `gemini-4-carbon-high` (dự phòng: `gemini-4-argon-high`) | `critic-2` (Swarm Gate 3 — đã đóng) | Hoàn tất Tái thẩm định Gate 3 Vòng 2 (`[APPROVED FOR GATE]`, `10/10 CLOSED`) | ✅ Done (`Gate 3 R2`) |
| agile-ai-data-engineer | — (Chưa kích hoạt - dự án thuần hạ tầng mạng) | | | ⚪ Inactive |
| agile-slm-trainer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-ai-engineer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-developer | `gemini-4-hydrogen-xhigh` (dự phòng: `gemini-4-hydrogen-high`) | `dev-s2`, `dev-fix-g3` (Swarm `share` — đã land & đóng) | Hoàn tất `WP-S2-04` (`control_handlers.rs:371`, `slo_wave2_suite.rs`, `run-slo-suite.ps1`) & đóng `HR-G3-02..04` (`308/308` tests PASS) | ✅ Done (`Gate 3 Fix`) |
| agile-qa | `gemini-4-argon-high` (dự phòng: `gemini-4-carbon-high`) | `qa-s2` (Swarm Stage B — đã đóng) | Hoàn tất Nghiệm thu độc lập Sprint 2 + Gate 3 (`[PASS - ĐẠT DoD]`, `5` bộ `qa_sprint2_*` = `18` tests, `62 Stories / 269 SP`) | ✅ Done (`Gate 3 QA`) |
| agile-mlops-eval | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-devops | `gemini-4-hydrogen-high` (dự phòng: `gemini-3.8-flash-high`) | `devops-s2`, `devops-fix-g3` (Swarm `share` — đã land & đóng) | Hoàn tất `WP-S2-04` (`US-058`/`US-059` Runbooks, CI matrix) & đóng `HR-G3-01..04`, `MED-G3-01..04`, `LOW-G3-01` | ✅ Done (`Gate 3 Fix`) |

## Kết luận Critic gần nhất

- `Gate 1 Vòng 2 (2026-11-12): [APPROVED FOR GATE] — Người dùng đã duyệt Gate 1 lúc 19:48 ngày 2026-11-12 kèm điều chỉnh ưu tiên macOS + Windows trước và kết nối bằng IP + custom port.`
- `Gate 2 Vòng 1 (2026-11-12): agile-critic [REVISION REQUIRED] (4B/4H/3M) + agile-codex [REVISION REQUIRED] (4B/8H/2M) — Đã hoàn tất Vòng sửa 1.`
- `Gate 2 Vòng 2 (2026-11-12): agile-critic [APPROVED FOR GATE] (0B/0H/3 Notes) + agile-codex [REVISION REQUIRED] (0B/5H/1M) — Đã hoàn tất Vòng sửa 2.`
- `Gate 2 Vòng 3 Cuối (2026-11-12): agile-critic [APPROVED FOR GATE] (0B/0H/0 Notes) + agile-codex (0B / 2 lưu ý nhánh lỗi phần cứng EIO kép) — Người dùng đã duyệt Gate 2 ngày 2026-11-13.`
- `Sprint 1 Wave 1.0 WP-S1-00 Vòng 2 (2026-11-13): agile-critic [APPROVED FOR GATE] (11/11 CLOSED) — Đã commit & push 664c5de.`
- `Sprint 1 Wave 1.1 WP-S1-01..04 Vòng 3 (2026-11-13): agile-critic [APPROVED FOR GATE] (23/23 R1 + 2/2 R2 = 100% CLOSED, 173 tests pass) — Đã commit & push d5a74f2.`
- `Sprint 1 Wave 1.2 WP-S1-05..06 Vòng 2 (2026-11-13): agile-critic [APPROVED FOR GATE] (15/15 R1 + USER mesh supplementary group = 100% CLOSED, 215 tests pass) — Đã commit & push edb836d.`
- `Sprint 1 Independent QA (2026-11-13): agile-qa [PASS - ĐẠT DoD] (38/38 Must = 174 SP, 0 lỗi mở, 223/223 tests pass qua scripts/check.ps1 -Cross).`
- `Sprint 2 Wave 2.1 WP-S2-01..03 Vòng 2 (2026-11-13): agile-critic [APPROVED FOR GATE] (15/15 CLOSED: 1B/12H/2I, 275/275 tests pass qua scripts/check.ps1 -Cross + wsl bash -n exit 0).`
- `Sprint 2 Independent QA (2026-11-14): agile-qa [PASS - ĐẠT DoD] (5 bộ test qa_sprint2_* mới, 62/62 Stories = 269 SP, cập nhật tổng 308/308 tests pass & 33/36 SLO PASS tại dod-verification.md).`
- `Gate 3 Critique Vòng 1 (2026-11-14): agile-critic [REVISION REQUIRED] (0B / 4H HR-G3-01..04 / 4M MED-G3-01..04 / 2L LOW-G3-01..02) — Đã giao dev-fix-g3 & devops-fix-g3 xử lý trọn vẹn.`
- `Gate 3 Critique Vòng 2 Cuối (2026-11-14): agile-critic [APPROVED FOR GATE] (10/10 CLOSED, 0B / 0H / 0M / 0L, 308/308 tests PASS qua check.ps1 -Cross, 33/36 SLO PASS, 15/15 .sh scripts PASS, 0 UTF-8 BOM / CRLF).`
- `Chặng 2B Verification (2026-11-14): Live 5-scenario Docker NAT Chaos Lab (US-057, REL-01, US-074 AC8, REL-12, US-028) = 5/5 PASS (chaos-report.json); PERF-02 5m VPS idle soak = 0.0262% of 1 vCPU PASS (perf02-idle-cpu-soak.json); Full 36-SLO suite = 34/36 PASS, 0 FAIL, 0 pending_external_lab, 2 hardware_signoff_required (slo-verification-report.json/.md); Go-Live Checklist = 16/20 [x].`
- `Mobile Gate 1 Vòng 2 (2026-11-15): critic-mob-g1 [APPROVED FOR GATE] (11/11 Đã đóng, 0B / 0H) — Người dùng đã duyệt Gate 1 kèm 5 quyết định OQ-MOB-01..05 (Phương án A song song, $0 iOS Simulator + $99/năm hardware_signoff_required, QR/Paste/Manual cấm OS deep-link mpk_*, Split-Tunnel only, MPL-2.0 giới hạn cho uniffi*).`
- `Mobile Gate 2 Vòng 1 & Vòng 2 (2026-11-15): critic-mob-g2 Vòng 1 [REVISION REQUIRED] (6B/5H/3M/1L) → 3 tác giả (techlead-mob, architect-mob, sm-mob) đồng bộ v1.1 → Vòng 2 [APPROVED FOR GATE] (15/15 CLOSED, 8/8 Exit Criteria Đạt, 0 tồn đọng; kèm 5 Strategic Trade-offs và 3 IG-MOB-G2-01..03 đã làm sạch).`
- `Mobile Wave A Vòng 1 & Vòng 2 (2026-11-16): critic-mob-wa Vòng 1 [CHANGES REQUIRED] (2B/4H/1M/1L) → dev-m-afix sửa đủ 8/8 + Coordinator bổ sung idle_wakeup_count tất định → Vòng 2 [APPROVED FOR WAVE B] (8/8 Closed, 0B/0H/0M/0L; libmesh_mobile_ffi.so = 4,375,280 B; check.ps1 -Cross + 5 mobile targets + Kotlin/Swift UniFFI bindgen PASS).`

## Việc còn dở / Vấn đề mở

- ✅ **Đã hoàn tất 100% phạm vi phát triển, kiểm thử phần mềm & Docker NAT/Chaos Lab (`Sprint 1` + `Sprint 2` = `62 User Stories / 269 SP`, `0 pending_external_lab`, `34/36` SLO PASS, `16/20` Go-Live Checklist `[x]`)**.
- ⏳ **Chỉ còn 2 Hạng mục Phần cứng Vật lý ngoài Lab (`hardware_signoff_required` — `#11`, `#17`, `#18`, `#20` trên `go-live-checklist.md`) trước khi cắt băng `v0.1.0`**:
  1. `PLAT-05` & `REL-07`: Chạy biên bản `docs/06-operations/hardware-sleep-wake-protocol.md` (`sleep >= 4 phút`, roaming Wi-Fi -> 4G, `P95 <= 15 s`, `0` ghost adapter) trên **MacBook + Laptop Windows 10/11 thật**.
  2. `PLAT-06` & Windows Host Install: Chạy `sudo bash lab/macos/verify-macos-host.sh` trên macOS thật và kiểm chứng cài đặt dịch vụ Windows (`MeshVpnAgent` + SHA-256 `wintun.dll`) với quyền Admin thật.
