# Agile State — Trạng Thái Điều Phối Dự Án

> Main Agent (Scrum Master) cập nhật file này sau mỗi bước quan trọng và đọc lại đầu mỗi phiên / sau khi server restart.

## Giai đoạn hiện tại

- **Thư mục gốc dự án**: `D:\Project\Idea\mesh-vpn`
- **Giai đoạn**: `2 - Tech Stack, Coding Standards, System Design & Sprint Planning`
- **Sprint hiện tại**: `Sprint 0 (Design)`
- **Bước tiếp theo**: `🛑 DỪNG TẠI GATE 2 — Chờ người dùng phê duyệt gói Tech Stack Rust 1.94.1, Code Format, Thiết kế Kiến trúc/DB/API v2.2 & Kế hoạch Sprint 1–2 (kèm chốt OQ-15 và chính sách nhánh lỗi phần cứng EIO kép)`

## Trạng thái Gate

| Gate | Trạng thái | Ngày duyệt | Ghi chú của người dùng |
|---|---|---|---|
| Gate 1 — Nghiên cứu & Backlog | ✅ Đã duyệt | 2026-11-12 | (1) Ưu tiên làm Client cho **macOS và Windows trước** (Server chạy trên Ubuntu Linux VPS + hỗ trợ Linux TUN cho VPS làm node & phòng lab NAT); (2) Tạm thời **kết nối trực tiếp bằng IP VPS** (chế độ Pin chứng chỉ/khóa `SEC-04c`) và **hỗ trợ đổi port TCP/UDP tùy ý** (không khóa cứng 443/3478); (3) Giữ các mặc định: chia **2 đợt bàn giao** (Milestone 1 → Milestone 2), tự định nghĩa giao thức, tên CLI **`mesh`** (`.mesh.internal`), quản trị CLI/SSH cục bộ. |
| Gate 2 — Stack/Model, Code Format, Thiết kế & Sprint | ⏸️ Đang chờ người dùng duyệt | | Đã hoàn tất 2 vòng sửa & 3 vòng kiểm định độc lập (`agile-critic` `[APPROVED FOR GATE]` 0B/0H; `agile-codex` `0 Blocker` + 2 lưu ý nhánh lỗi `EIO` kép trình minh bạch). Chờ người dùng duyệt Gate 2 trước khi viết dòng code `.rs` đầu tiên. |
| Gate 3 — Sprint Review, QA/AI Eval & Release | ⏳ Chưa trình | | |

## Các Vai trò trong Team (14 Vai trò: Scrum Master + 12 Subagents + Codex)

| Vai trò | Model | conversationId / tên worker | Nhiệm vụ gần nhất | Trạng thái |
|---|---|---|---|---|
| agile-scrum-master (Dual-mode: Main Agent / Subagent) | Gemini 4 Carbon (High) | 61ff2afa-a00e-406b-acba-ec4bf1a4eb39 | Ghi nhận duyệt Gate 1 & điều phối Giai đoạn 2 | 🟢 Active |
| agile-researcher | claude-opus-5-5-high | dae2b634-a323-4894-9519-7698811e921b | Hoàn tất đồng bộ v1.2 `production-readiness-requirements.md` (macOS P0 `PLAT-06`, IP+Pin `SEC-04c`, custom port & `SEC-15`) | ✅ Done (v1.2) |
| agile-po-ba | claude-sonnet-5-5-high | 61249fa4-f35a-4f0e-9bd0-eaec4d8d4074 | Hoàn tất đồng bộ v1.2 `product-backlog.md` (997 dòng, 51 Must = 234 SP), `charter`, `vision`, `personas` | ✅ Done (v1.2) |
| agile-tech-lead | gemini-4-argon-high (dự phòng — nhóm Claude chạm trần tuần, reset ~2026-11-18 13:43) | 111ccb61-76da-4415-aa05-654afdb784c6 | Hoàn tất Vòng sửa 2 Gate 2 (`bootstrap-toolchain.ps1` Msvc parity, tách `/run/mesh-server` vs `/var/run/meshd`, `ADR-005..007` & `coding-standards` v2.2, rule 9,887 B) | ✅ Done (Rust v2.2) |
| agile-architect | gemini-4-argon-high (dự phòng — nhóm Claude chạm trần tuần, reset ~2026-11-18 13:43) | 991a5bee-a698-49a3-b364-1ee99581e4f1 | Hoàn tất Vòng sửa 2 Gate 2 (`system-architecture.md`, `database-design.md`, `api-design.md` v2.2: High-Watermark Lease `1_024`, `persistence_tier`, tách IPC/state dir, UDP filter) | ✅ Done (Rust v2.2) |
| agile-critic | gemini-4-carbon-high | 05cc28db-eaaa-4f04-b9b0-28fc69d2fd89 | Hoàn tất Thẩm định cuối Gate 2 Vòng 3: `[APPROVED FOR GATE]` (0B / 0H / 0 Notes) | ✅ Done (G2 R3) |
| agile-ai-data-engineer | — (Chưa kích hoạt - dự án thuần hạ tầng mạng) | | | ⚪ Inactive |
| agile-slm-trainer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-ai-engineer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-developer | claude-sonnet-5-5-high | | | ⚪ Pending |
| agile-qa | gemini-4-argon-high | | | ⚪ Pending |
| agile-mlops-eval | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-devops | gemini-3.8-flash-high | | | ⚪ Pending |
| agile-codex (Codex CLI, ngoài Antigravity) | gpt-6.1-sol | (gọi qua codex_task.py) | Hoàn tất Thẩm định cuối Gate 2 Vòng 3: `0 Blocker` + 2 lưu ý nhánh lỗi `EIO` kép (trình minh bạch tại Gate 2 theo trần 2 vòng sửa) | ✅ Done (G2 R3) |

## Kết luận Critic gần nhất

- `Gate 1 Vòng 2 (2026-11-12): [APPROVED FOR GATE] — Người dùng đã duyệt Gate 1 lúc 19:48 ngày 2026-11-12 kèm điều chỉnh ưu tiên macOS + Windows trước và kết nối bằng IP + custom port.`
- `Gate 2 Vòng 1 (2026-11-12): agile-critic [REVISION REQUIRED] (4B/4H/3M) + agile-codex [REVISION REQUIRED] (4B/8H/2M) — Đã hoàn tất Vòng sửa 1.`
- `Gate 2 Vòng 2 (2026-11-12): agile-critic [APPROVED FOR GATE] (0B/0H/3 Notes) + agile-codex [REVISION REQUIRED] (0B/5H/1M) — Đã hoàn tất Vòng sửa 2.`
- `Gate 2 Vòng 3 Cuối (2026-11-12): agile-critic [APPROVED FOR GATE] (0B/0H/0 Notes) + agile-codex (0B / 2 lưu ý nhánh lỗi phần cứng EIO kép) — Đang trình người dùng duyệt Gate 2.`

## Việc còn dở / Vấn đề mở

- Chờ người dùng duyệt **Gate 2** (xác nhận gói thiết kế Rust 1.94.1 v2.2, lựa chọn `OQ-15` cho Sprint 1 vs Sprint 2, và chính sách xử lý nhánh lỗi phần cứng `EIO` kép khi thực thi `WP-S1-01`), sau đó mới khởi chạy Sprint 1 (`WP-S1-00`).
