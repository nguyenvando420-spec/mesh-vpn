# Agile State — Trạng Thái Điều Phối Dự Án

> Main Agent (Scrum Master) cập nhật file này sau mỗi bước quan trọng và đọc lại đầu mỗi phiên / sau khi server restart.

## Giai đoạn hiện tại

- **Thư mục gốc dự án**: `D:\Project\Idea\mesh-vpn`
- **Giai đoạn**: `2 - Tech Stack, Coding Standards, System Design & Sprint Planning`
- **Sprint hiện tại**: `Sprint 0 (Design)`
- **Bước tiếp theo**: `Chạy Bước 2.2 (agile-architect) trên Rust 1.94.1 Stack đã khóa cứng, sau đó lập sprint-backlog.md và chạy phản biện song song (agile-critic + agile-codex)`

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
| agile-tech-lead | gemini-4-argon-high (dự phòng — nhóm Claude chạm trần tuần, reset ~2026-11-18 13:43) | ffd94c65-24c6-4115-9801-012205be6731 | Hoàn tất Rust 1.94.1 Stack v2.0 (`tech-stack-decision.md`, 11 ADRs, `coding-standards.md`, `.agents/rules/coding-standards.md`, `rustfmt/clippy/deny.toml`, `scripts/check.*`) | ✅ Done (Rust v2.0) |
| agile-architect | gemini-4-argon-high (dự phòng — nhóm Claude chạm trần tuần, reset ~2026-11-18 13:43) | | Đang thiết kế C4 System Architecture, `redb` Schema & Wire/API/IPC Contracts khớp 10 crates Rust | 🟡 Running |
| agile-critic | gemini-4-carbon-high | abbcf2d4-c88b-4653-a079-79223667caa1 | Hoàn tất Gate 1 Vòng 2 (`[APPROVED FOR GATE]`); chờ phản biện Gate 2 | ⚪ Ready |
| agile-ai-data-engineer | — (Chưa kích hoạt - dự án thuần hạ tầng mạng) | | | ⚪ Inactive |
| agile-slm-trainer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-ai-engineer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-developer | claude-sonnet-5-5-high | | | ⚪ Pending |
| agile-qa | gemini-4-argon-high | | | ⚪ Pending |
| agile-mlops-eval | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-devops | gemini-3.8-flash-high | | | ⚪ Pending |
| agile-codex (Codex CLI, ngoài Antigravity) | gpt-6.1-sol | (gọi qua codex_task.py) | Chờ phản biện thiết kế song song trước Gate 2 (`review-design`) | ⚪ Pending |

## Kết luận Critic gần nhất

- `Gate 1 Vòng 2 (2026-11-12): [APPROVED FOR GATE] — Người dùng đã duyệt Gate 1 lúc 19:48 ngày 2026-11-12 kèm điều chỉnh ưu tiên macOS + Windows trước và kết nối bằng IP + custom port.`

## Việc còn dở / Vấn đề mở

- Thực thi liền mạch Giai đoạn 2 còn lại: `agile-architect` → `sprint-backlog.md` → `agile-critic` + `agile-codex` (`review-design` song song) → Trình Gate 2.
