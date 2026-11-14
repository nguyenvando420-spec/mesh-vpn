# Agile State — Trạng Thái Điều Phối Dự Án

> Main Agent (Scrum Master) cập nhật file này sau mỗi bước quan trọng và đọc lại đầu mỗi phiên / sau khi server restart.

## Giai đoạn hiện tại

- **Thư mục gốc dự án**: `D:\Project\Idea\mesh-vpn`
- **Giai đoạn**: `Gate 3 Pre-release (v0.1.0-rc1) — Đóng gói bản cài 4 nền tảng & mesh-server OCI phục vụ nghiệm thu 4 mục phần cứng vật lý (MacBook + Laptop Windows); giữ tag GA v0.1.0 tới khi đủ 20/20 Go-Live Checklist`
- **Sprint hiện tại**: `Sprint 2 (Hoàn tất 100%: 13 Must / 60 SP + 11 Should / 35 SP; lũy kế toàn dự án 62 Stories / 269 SP)`
- **Bước tiếp theo**: `Người dùng tải gói cài từ GitHub Pre-release v0.1.0-rc1 để nghiệm thu 4 mục phần cứng vật lý (#11, #17, #18, #20 trên go-live-checklist.md theo hardware-sleep-wake-protocol.md & lab/macos/verify-macos-host.sh), sau đó gắn tag chính thức v0.1.0`

## Trạng thái Gate

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

## Việc còn dở / Vấn đề mở

- ✅ **Đã hoàn tất 100% phạm vi phát triển, kiểm thử phần mềm & Docker NAT/Chaos Lab (`Sprint 1` + `Sprint 2` = `62 User Stories / 269 SP`, `0 pending_external_lab`, `34/36` SLO PASS, `16/20` Go-Live Checklist `[x]`)**.
- ⏳ **Chỉ còn 2 Hạng mục Phần cứng Vật lý ngoài Lab (`hardware_signoff_required` — `#11`, `#17`, `#18`, `#20` trên `go-live-checklist.md`) trước khi cắt băng `v0.1.0`**:
  1. `PLAT-05` & `REL-07`: Chạy biên bản `docs/06-operations/hardware-sleep-wake-protocol.md` (`sleep >= 4 phút`, roaming Wi-Fi -> 4G, `P95 <= 15 s`, `0` ghost adapter) trên **MacBook + Laptop Windows 10/11 thật**.
  2. `PLAT-06` & Windows Host Install: Chạy `sudo bash lab/macos/verify-macos-host.sh` trên macOS thật và kiểm chứng cài đặt dịch vụ Windows (`MeshVpnAgent` + SHA-256 `wintun.dll`) với quyền Admin thật.
