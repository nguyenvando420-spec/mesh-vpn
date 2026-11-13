# Agile State — Trạng Thái Điều Phối Dự Án

> Main Agent (Scrum Master) cập nhật file này sau mỗi bước quan trọng và đọc lại đầu mỗi phiên / sau khi server restart.

## Giai đoạn hiện tại

- **Thư mục gốc dự án**: `D:\Project\Idea\mesh-vpn`
- **Giai đoạn**: `3 - Sprint Execution & Parallel Implementation`
- **Sprint hiện tại**: `Sprint 1 (Milestone 1 — 38 Must / 174 SP)`
- **Bước tiếp theo**: `Wave 1.1 (WP-S1-01..04) đã đạt [APPROVED FOR GATE] (23/23 R1 + 2/2 R2 CLOSED, 173 tests xanh, pass check.ps1 -Cross) -> Commit & Push origin/main -> Đang thực thi song song Wave 1.2 (WP-S1-05 meshd + mesh CLI & WP-S1-06 Docker NAT Lab + 4-target CI/CD)`

## Trạng thái Gate

| Gate | Trạng thái | Ngày duyệt | Ghi chú của người dùng |
|---|---|---|---|
| Gate 1 — Nghiên cứu & Backlog | ✅ Đã duyệt | 2026-11-12 | (1) Ưu tiên làm Client cho **macOS và Windows trước** (Server chạy trên Ubuntu Linux VPS + hỗ trợ Linux TUN cho VPS làm node & phòng lab NAT); (2) Tạm thời **kết nối trực tiếp bằng IP VPS** (chế độ Pin chứng chỉ/khóa `SEC-04c`) và **hỗ trợ đổi port TCP/UDP tùy ý** (không khóa cứng 443/3478); (3) Giữ các mặc định: chia **2 đợt bàn giao** (Milestone 1 → Milestone 2), tự định nghĩa giao thức, tên CLI **`mesh`** (`.mesh.internal`), quản trị CLI/SSH cục bộ. |
| Gate 2 — Stack/Model, Code Format, Thiết kế & Sprint | ✅ Đã duyệt | 2026-11-13 | Người dùng duyệt gói Rust `1.94.1` v2.2 / Sprint Plan v1.2 kèm 2 mặc định khuyến nghị: (1) **`OQ-15` Mặc định A**: giữ **Sprint 1 = `38 Must / 174 SP`** & **Sprint 2 = `13 Must / 60 SP`** (+ `11 Should / 35 SP`); (2) **Chính sách lỗi phần cứng `EIO` kép**: compaction hợp nhất toàn bộ mục thu hồi chưa bền vững trong RAM (kể cả `ram_only`) trước khi gỡ `disk_degraded`; khi hết lease version đúng lúc cả 2 tầng đĩa lỗi `EIO`, vẫn cắt tức thì phiên Control/Relay của node bị thu hồi trong RAM và đóng stream buộc các peer xác thực lại (không phát version chưa lưu đĩa). |
| Gate 3 — Sprint Review, QA/AI Eval & Release | ⏳ Chưa trình | | |

## Các Vai trò trong Team (14 Vai trò: Scrum Master + 12 Subagents + Codex)

| Vai trò | Model | conversationId / tên worker | Nhiệm vụ gần nhất | Trạng thái |
|---|---|---|---|---|
| agile-scrum-master (Dual-mode: Main Agent / Subagent) | Gemini 4 Carbon (High) (dự phòng chuyên biệt: `gemini-pro-orchestrator`) | 61ff2afa-a00e-406b-acba-ec4bf1a4eb39 | Ghi nhận duyệt Gate 2 (`2026-11-13`) & điều phối thực thi Sprint 1 Wave 1.0 (`WP-S1-00`) | 🟢 Active |
| agile-researcher | claude-opus-5-5-high | dae2b634-a323-4894-9519-7698811e921b | Hoàn tất đồng bộ v1.2 `production-readiness-requirements.md` (macOS P0 `PLAT-06`, IP+Pin `SEC-04c`, custom port & `SEC-15`) | ✅ Done (v1.2) |
| agile-po-ba | claude-sonnet-5-5-high | 61249fa4-f35a-4f0e-9bd0-eaec4d8d4074 | Hoàn tất đồng bộ v1.2 `product-backlog.md` (997 dòng, 51 Must = 234 SP), `charter`, `vision`, `personas` | ✅ Done (v1.2) |
| agile-tech-lead | gemini-4-argon-high (dự phòng tiếp theo: `gemini-4-hydrogen-xhigh` — nhóm Claude chạm trần tuần tới ~2026-11-18 13:41) | 111ccb61-76da-4415-aa05-654afdb784c6 | Đã hoàn tất nâng cấp `scripts/check.ps1 -Cross` (`zig cc` shim + cross-clippy `--all-targets`) & `.gitignore` `*.o` | ✅ Done (`check.ps1 -Cross`) |
| agile-architect | gemini-4-argon-high (dự phòng tiếp theo: `gemini-4-hydrogen-xhigh` — nhóm Claude chạm trần tuần tới ~2026-11-18 13:41) | 991a5bee-a698-49a3-b364-1ee99581e4f1 | Hoàn tất Vòng sửa 2 Gate 2 (`system-architecture.md`, `database-design.md`, `api-design.md` v2.2: High-Watermark Lease `1_024`, `persistence_tier`, tách IPC/state dir, UDP filter) | ✅ Done (Rust v2.2) |
| agile-critic | gemini-4-carbon-high | 5f0e59f6-e355-49aa-9c7f-2bf1c6bf3aae | Hoàn tất Phản biện Wave 1.1 R1 (`wave-1-1-critique.md`): `[REVISION REQUIRED]` (`10B/11H/2M`) | ✅ Done (`Wave 1.1 R1`) |
| agile-ai-data-engineer | — (Chưa kích hoạt - dự án thuần hạ tầng mạng) | | | ⚪ Inactive |
| agile-slm-trainer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-ai-engineer | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-developer | gemini-4-hydrogen-xhigh (dự phòng cho `claude-sonnet-5-5-high` — nhóm Claude chạm trần tuần tới ~2026-11-18 13:41; tách biệt biến thể với QA `argon` & Critic `carbon`) | S1-01:`bd18233a`, S1-02:`1ac515a0`, S1-03:`9b29b7ab`, S1-04:`97e9a6ea` | Đang chạy song song Vòng sửa 1 cho cả 4 gói Wave 1.1 (`BLK-S1-01..10`, `HR-S1-01..11`, `IMP-S1-01..02`) | 🟢 Active (`Wave 1.1 Rev1 x4`) |
| agile-qa | gemini-4-argon-high | | | ⚪ Pending |
| agile-mlops-eval | — (Chưa kích hoạt) | | | ⚪ Inactive |
| agile-devops | gemini-4-hydrogen-high (nâng cấp từ `gemini-3.8-flash-high` ngày 2026-11-13) | | | ⚪ Pending |
| agile-codex (Codex CLI, ngoài Antigravity) | gpt-6.1-sol / gpt-6-astra / gpt-6.1-terra | (gọi qua codex_task.py) | Cửa sổ quota ChatGPT báo chạm hạn mức tới `14:35+07:00` khi gọi lúc `11:26`; tạm duy trì phản biện khác biến thể `agile-critic` (`carbon-high`) + `agile-qa` (`argon-high`) tới `14:35` | ⏳ Quota Reset `14:35` |

## Kết luận Critic gần nhất

- `Gate 1 Vòng 2 (2026-11-12): [APPROVED FOR GATE] — Người dùng đã duyệt Gate 1 lúc 19:48 ngày 2026-11-12 kèm điều chỉnh ưu tiên macOS + Windows trước và kết nối bằng IP + custom port.`
- `Gate 2 Vòng 1 (2026-11-12): agile-critic [REVISION REQUIRED] (4B/4H/3M) + agile-codex [REVISION REQUIRED] (4B/8H/2M) — Đã hoàn tất Vòng sửa 1.`
- `Gate 2 Vòng 2 (2026-11-12): agile-critic [APPROVED FOR GATE] (0B/0H/3 Notes) + agile-codex [REVISION REQUIRED] (0B/5H/1M) — Đã hoàn tất Vòng sửa 2.`
- `Gate 2 Vòng 3 Cuối (2026-11-12): agile-critic [APPROVED FOR GATE] (0B/0H/0 Notes) + agile-codex (0B / 2 lưu ý nhánh lỗi phần cứng EIO kép) — Đang trình người dùng duyệt Gate 2.`

## Việc còn dở / Vấn đề mở

- ✅ **Đã chốt & áp dụng (2026-11-13 05:19 — Nâng cấp Plugin v2.4.0)**: Đã bổ sung `gemini-pro-orchestrator`, `gemini-4-hydrogen-{low,medium,high,xhigh}` (`agy 1.5.7`), dải `gpt-6-astra` / `gpt-6.1-terra` / `gpt-6-luna` + `--effort` / `--ephemeral` / `--diff-*` (`Codex CLI 0.167.2`), và mở khóa khai báo tool `swarm` / `schedule` / `ask_question` trong `agile-scrum-master.md` đồng bộ trên cả `D:\Project\Codex` và `~/.gemini/config/plugins/agile-scrum-team`.
- ✅ **Gate 2 đã được người dùng duyệt lúc 05:47 ngày 2026-11-13**.
- Đang thực thi **Sprint 1 — Wave 1.0 (`WP-S1-00`)** → Wave 1.1 (`WP-S1-01..04` song song) → Wave 1.2 (`WP-S1-05..06` song song) → Kiểm định `agile-qa` + `agile-codex` + `agile-critic`.
