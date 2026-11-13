# Agile State — Trạng Thái Điều Phối Dự Án

> Main Agent (Scrum Master) cập nhật file này sau mỗi bước quan trọng và đọc lại đầu mỗi phiên / sau khi server restart.

## Giai đoạn hiện tại

- **Thư mục gốc dự án**: `D:\Project\Idea\mesh-vpn`
- **Giai đoạn**: `3 - Sprint Execution & Parallel Implementation`
- **Sprint hiện tại**: `Sprint 2 (Milestone 2 — 13 Must / 60 SP + 11 Should / 35 SP)`
- **Bước tiếp theo**: `Sẵn sàng mở Swarm thực thi Wave 2.2 — WP-S2-04 (US-058 Automated NFR/SLO & Chaos Runner + US-059 Operational Runbook & Release/Rollback Docs)` -> Kiểm định độc lập `agile-qa` & `agile-critic` -> Gate 3

## Trạng thái Gate

| Gate | Trạng thái | Ngày duyệt | Ghi chú của người dùng |
|---|---|---|---|
| Gate 1 — Nghiên cứu & Backlog | ✅ Đã duyệt | 2026-11-12 | (1) Ưu tiên làm Client cho **macOS và Windows trước** (Server chạy trên Ubuntu Linux VPS + hỗ trợ Linux TUN cho VPS làm node & phòng lab NAT); (2) Tạm thời **kết nối trực tiếp bằng IP VPS** (chế độ Pin chứng chỉ/khóa `SEC-04c`) và **hỗ trợ đổi port TCP/UDP tùy ý** (không khóa cứng 443/3478); (3) Giữ các mặc định: chia **2 đợt bàn giao** (Milestone 1 → Milestone 2), tự định nghĩa giao thức, tên CLI **`mesh`** (`.mesh.internal`), quản trị CLI/SSH cục bộ. |
| Gate 2 — Stack/Model, Code Format, Thiết kế & Sprint | ✅ Đã duyệt | 2026-11-13 | Người dùng duyệt gói Rust `1.94.1` v2.2 / Sprint Plan v1.2 kèm 2 mặc định khuyến nghị: (1) **`OQ-15` Mặc định A**: giữ **Sprint 1 = `38 Must / 174 SP`** & **Sprint 2 = `13 Must / 60 SP`** (+ `11 Should / 35 SP`); (2) **Chính sách lỗi phần cứng `EIO` kép**: compaction hợp nhất toàn bộ mục thu hồi chưa bền vững trong RAM (kể cả `ram_only`) trước khi gỡ `disk_degraded`; khi hết lease version đúng lúc cả 2 tầng đĩa lỗi `EIO`, vẫn cắt tức thì phiên Control/Relay của node bị thu hồi trong RAM và đóng stream buộc các peer xác thực lại (không phát version chưa lưu đĩa). |
| Gate 3 — Sprint Review, QA/AI Eval & Release | ⏳ Chưa trình | | |

## Các Vai trò trong Team (13 Vai trò Chuẩn Plugin v3.1.0: Orchestrator + Swarm)

| Vai trò | Model | conversationId / tên worker | Nhiệm vụ gần nhất | Trạng thái |
|---|---|---|---|---|
| agile-scrum-master (Nhạc trưởng 2 pha / Swarm Coordinator) | `gemini-pro-orchestrator` (Orchestrator Carbon) | Main Agent | Điều phối Swarm khép kín Sprint 2 Wave 2.1 (`WP-S2-01..03`) | 🟢 Active |
| agile-researcher | `claude-opus-5-5-high` (dự phòng: `gemini-4-argon-high`) | dae2b634-a323-4894-9519-7698811e921b | Hoàn tất đồng bộ v1.2 `production-readiness-requirements.md` (macOS P0 `PLAT-06`, IP+Pin `SEC-04c`, custom port & `SEC-15`) | ✅ Done (v1.2) |
| agile-po-ba | `claude-sonnet-5-5-high` (dự phòng: `gemini-4-carbon-high`) | 61249fa4-f35a-4f0e-9bd0-eaec4d8d4074 | Hoàn tất đồng bộ v1.2 `product-backlog.md` (997 dòng, 51 Must = 234 SP), `charter`, `vision`, `personas` | ✅ Done (v1.2) |
| agile-tech-lead | `gemini-4-argon-high` (dự phòng cho `claude-sonnet-5-5-high`) | 111ccb61-76da-4415-aa05-654afdb784c6 | Hoàn tất `scripts/check.ps1 -Cross` & `.gitignore` `*.o` | ✅ Done (`check.ps1 -Cross`) |
| agile-architect | `gemini-4-argon-high` (dự phòng cho `claude-opus-5-5-high`) | 991a5bee-a698-49a3-b364-1ee99581e4f1 | Hoàn tất Rust v2.2 (`system-architecture.md`, `database-design.md`, `api-design.md`) | ✅ Done (Rust v2.2) |
| agile-critic | `gemini-4-carbon-high` (dự phòng: `gemini-4-argon-high`) | `critic` (Swarm Wave 2.1 — đã đóng) | Hoàn tất Tái thẩm định Wave 2.1 Vòng 2 (`[APPROVED FOR GATE]`, `15/15 CLOSED`) | ✅ Done (`Wave 2.1 R2`) |
| agile-ai-data-engineer | — (Chưa kích hoạt - dự án thuần hạ tầng mạng) | | | ⚪ Inactive |
| agile-slm-trainer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-ai-engineer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-developer | `gemini-4-hydrogen-xhigh` (dự phòng: `gemini-4-hydrogen-high`) | `dev-server`, `dev-client` (Swarm `share` — đã merge & đóng) | Hoàn tất Wave 2.1 (`WP-S2-01..03`, `15/15` mục đóng, `275/275` tests pass qua `check.ps1 -Cross`) | ✅ Done (`Wave 2.1`) |
| agile-qa | `gemini-4-argon-high` (dự phòng: `gemini-4-carbon-high`) | 45988c3a-c359-4dc0-96f5-d89777a38085 | Đã nghiệm thu độc lập Sprint 1 `[PASS - ĐẠT DoD]` (`38/38` Must, `223` tests pass); chờ Wave 2.2 | ✅ Done (`Sprint 1 QA`) |
| agile-mlops-eval | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-devops | `gemini-4-hydrogen-high` (dự phòng: `gemini-3.8-flash-high`) | 9ff5c3f2-1a8a-422a-92f1-15dd8fee9bba | Hoàn tất & PASS Critic R2 cho `WP-S1-06`; chuẩn bị `WP-S2-04` ngay sau Wave 2.1 | ✅ Ready (`WP-S2-04`) |

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

## Việc còn dở / Vấn đề mở

- ✅ **Đã chốt & áp dụng (2026-11-13 — Chuẩn hóa Plugin `agile-scrum-team` v3.1.0)**: Chuyển hoàn toàn sang điều phối **Orchestrator Carbon (`gemini-pro-orchestrator`) + Native Swarm** với **13 vai trò nội bộ** (thuần `agile-critic` Carbon + `agile-qa` Argon, không gọi Codex CLI ngoài; 4 vai trò AI giữ Inactive).
- ✅ **Gate 2 đã được người dùng duyệt lúc 05:47 ngày 2026-11-13**.
- ✅ **Sprint 1 (`38 Must / 174 SP`) đã hoàn tất 100% và đạt `[PASS - ĐẠT DoD]` (`223` tests pass)**.
- ✅ **Sprint 2 — Wave 2.1 (`WP-S2-01..03`) Hoàn tất & `[APPROVED FOR GATE]`** (`15/15` mục đóng, `275/275` tests pass qua `scripts/check.ps1 -Cross` & `wsl bash -n` exit `0`).
- ⏳ **Bước tiếp theo**: Thực thi **Wave 2.2 (`WP-S2-04`: `US-058` Automated NFR/SLO & Chaos Runner + `US-059` Operational Runbook & Release/Rollback Docs)** → Kiểm định cuối `agile-qa` + Phản biện `agile-critic` → **Gate 3**.
