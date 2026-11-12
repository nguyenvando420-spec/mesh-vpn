# Agile State — Trạng Thái Điều Phối Dự Án

> Main Agent (Scrum Master) cập nhật file này sau mỗi bước quan trọng và đọc lại đầu mỗi phiên / sau khi server restart.

## Giai đoạn hiện tại

- **Thư mục gốc dự án**: `D:\Project\Idea\mesh-vpn`
- **Giai đoạn**: `2 - Tech Stack, Coding Standards, System Design & Sprint Planning`
- **Sprint hiện tại**: `Sprint 0 (Design)`
- **Bước tiếp theo**: `Tái thẩm định cuối cùng trước Gate 2 (Vòng 3 sau 2 vòng sửa tối đa): chạy song song agile-critic + agile-codex (review-design) rồi trình người dùng duyệt Gate 2`

## Trạng thái Gate

| Gate | Trạng thái | Ngày duyệt | Ghi chú của người dùng |
|---|---|---|---|
| Gate 1 — Nghiên cứu & Backlog | ✅ Đã duyệt | 2026-11-12 | (1) Ưu tiên làm Client cho **macOS và Windows trước** (Server chạy trên Ubuntu Linux VPS + hỗ trợ Linux TUN cho VPS làm node & phòng lab NAT); (2) Tạm thời **kết nối trực tiếp bằng IP VPS** (chế độ Pin chứng chỉ/khóa `SEC-04c`) và **hỗ trợ đổi port TCP/UDP tùy ý** (không khóa cứng 443/3478); (3) Giữ các mặc định: chia **2 đợt bàn giao** (Milestone 1 → Milestone 2), tự định nghĩa giao thức, tên CLI **`mesh`** (`.mesh.internal`), quản trị CLI/SSH cục bộ. |
| Gate 2 — Stack/Model, Code Format, Thiết kế & Sprint | ⏳ Đang thực hiện | | Người dùng chốt sớm ngôn ngữ ngày 2026-11-12 21:01: **Chọn Rust (`rustc 1.94.1`)** thay vì Go/C++ để phần mềm siêu gọn nhẹ (~4–10 MB RAM, không GC, tốc độ sát phần cứng) và an toàn bộ nhớ. |
| Gate 3 — Sprint Review, QA/AI Eval & Release | ⏳ Chưa trình | | |

## Các Vai trò trong Team (14 Vai trò: Scrum Master + 12 Subagents + Codex)

| Vai trò | Model | conversationId / tên worker | Nhiệm vụ gần nhất | Trạng thái |
|---|---|---|---|---|
| agile-scrum-master (Dual-mode: Main Agent / Subagent) | Gemini 4 Carbon (High) | 61ff2afa-a00e-406b-acba-ec4bf1a4eb39 | Ghi nhận duyệt Gate 1 & điều phối Giai đoạn 2 | 🟢 Active |
| agile-researcher | claude-opus-5-5-high | dae2b634-a323-4894-9519-7698811e921b | Hoàn tất đồng bộ v1.2 `production-readiness-requirements.md` (macOS P0 `PLAT-06`, IP+Pin `SEC-04c`, custom port & `SEC-15`) | ✅ Done (v1.2) |
| agile-po-ba | claude-sonnet-5-5-high | 61249fa4-f35a-4f0e-9bd0-eaec4d8d4074 | Hoàn tất đồng bộ v1.2 `product-backlog.md` (997 dòng, 51 Must = 234 SP), `charter`, `vision`, `personas` | ✅ Done (v1.2) |
| agile-tech-lead | gemini-4-argon-high (dự phòng — nhóm Claude chạm trần tuần, reset ~2026-11-18 13:43) | 111ccb61-76da-4415-aa05-654afdb784c6 | Hoàn tất Vòng sửa 2 Gate 2 (`bootstrap-toolchain.ps1` Msvc parity, tách `/run/mesh-server` vs `/var/run/meshd`, `ADR-005..007` & `coding-standards` v2.2, rule 9,887 B) | ✅ Done (Rust v2.2) |
| agile-architect | gemini-4-argon-high (dự phòng — nhóm Claude chạm trần tuần, reset ~2026-11-18 13:43) | 991a5bee-a698-49a3-b364-1ee99581e4f1 | Hoàn tất Vòng sửa 2 Gate 2 (`system-architecture.md`, `database-design.md`, `api-design.md` v2.2: High-Watermark Lease `1_024`, `persistence_tier`, tách IPC/state dir, UDP filter) | ✅ Done (Rust v2.2) |
| agile-critic | gemini-4-carbon-high | 32d66da7-b094-4e7b-9120-b3be756e00c5 | Đang xác nhận bản v2.2 cuối trước Gate 2 (`gate-2-critique.md`) | 🟡 Running (G2 R3) |
| agile-ai-data-engineer | — (Chưa kích hoạt - dự án thuần hạ tầng mạng) | | | ⚪ Inactive |
| agile-slm-trainer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-ai-engineer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-developer | claude-sonnet-5-5-high | | | ⚪ Pending |
| agile-qa | gemini-4-argon-high | | | ⚪ Pending |
| agile-mlops-eval | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-devops | gemini-3.8-flash-high | | | ⚪ Pending |
| agile-codex (Codex CLI, ngoài Antigravity) | gpt-6.1-sol | (gọi qua codex_task.py) | Đang tái thẩm định cuối cùng bản v2.2 trước Gate 2 (`review-design` -> `gate-2-codex.md`) | 🟡 Running (G2 R3) |

## Kết luận Critic gần nhất

- `Gate 1 Vòng 2 (2026-11-12): [APPROVED FOR GATE] — Người dùng đã duyệt Gate 1 lúc 19:48 ngày 2026-11-12 kèm điều chỉnh ưu tiên macOS + Windows trước và kết nối bằng IP + custom port.`
- `Gate 2 Vòng 1 (2026-11-12): agile-critic [REVISION REQUIRED] (4B/4H/3M) + agile-codex [REVISION REQUIRED] (4B/8H/2M) — Đã hoàn tất Vòng sửa 1.`
- `Gate 2 Vòng 2 (2026-11-12): agile-critic [APPROVED FOR GATE] (0B/0H/3 Notes) + agile-codex [REVISION REQUIRED] (0B/5H/1M) — Đang thực thi Vòng sửa 2 (vòng cuối trước Gate 2).`

## Việc còn dở / Vấn đề mở

- Thực thi Vòng sửa 2 (`agile-tech-lead` + `agile-architect` + `sprint-backlog.md` v1.2) → Kiểm định cuối cùng (`agile-critic` + `agile-codex`) → Trình người dùng duyệt Gate 2.
