# Model Performance — Đánh Giá Thực Tế Theo Vai Trò

> Scrum Master ghi sau **mỗi lần bàn giao** và tổng hợp tại **mỗi Gate 3**. Cách đánh giá: `model-routing.md` mục 6.
> **Người dùng chọn ngày 12/11/2026**: đây là căn cứ CHÍNH để điều chỉnh model (2 benchmark đều chạm trần, không tách được 5 model mạnh).
> Chỉ ghi số liệu Scrum Master **đã tự kiểm chứng** (mở file, chạy lại lệnh, đọc log thật) — không chép lại lời tự báo của agent.

## Nhật ký bàn giao

| Ngày | Sprint/Gate | Vai trò | Model | Nhiệm vụ | Vòng sửa | Lỗi bị phát hiện (B/H/M) | Báo cáo sai sự thật | Thời gian | Hết quota? | Phản hồi người dùng |
|---|---|---|---|---|---|---|---|---|---|---|
| 2026-11-12 | Gate 1 | agile-researcher | claude-opus-5-5-high | Khảo sát 5 hệ thống Mesh VPN & Production-Readiness (Bản 1.0) | 1 | 1B / 0H / 1M (BLK-01 SEC-06, IMP-01) | Không | 569.9 s | Không | Chờ Gate 1 |
| 2026-11-12 | Gate 1 | agile-po-ba | claude-sonnet-5-5-high | Xây dựng Vision, Charter, Personas & Product Backlog (Bản 1.0) | 1 | 3B / 3H / 4M (BLK-01..03, HR-01..03, IMP-01..04) | Không | 477.7 s | Không | Chờ Gate 1 |
| 2026-11-12 | Gate 1 | agile-critic | gemini-4-carbon-high | Phản biện độc lập Gate 1 Vòng 1 | 0 | 0 (Phát hiện chính xác 3B/3H/4M thực chất) | Không (đã kiểm chứng từng dòng đối chiếu) | 627.6 s | Không | Chờ Gate 1 |
| 2026-11-12 | Gate 1 | agile-researcher | gemini-4-argon-high | Vòng sửa 1: Cập nhật production-readiness-requirements.md v1.1 | 0 | 0 (Đã PASS Critic V2) | Không (đã kiểm chứng SEC-14, OPS-05/06/08, nhãn KN) | 166.4 s | Không | Chờ Gate 1 |
| 2026-11-12 | Gate 1 | agile-po-ba | gemini-4-carbon-high | Vòng sửa 1: Cập nhật Product Backlog v1.1 & Charter v1.1 | 0 | 0 (Đã PASS Critic V2) | Không (đã kiểm chứng đủ 861 + 159 dòng, xử lý đủ BLK/HR/IMP) | 1035.8 s | Không | Chờ Gate 1 |
| 2026-11-12 | Gate 1 | agile-critic | gemini-4-carbon-high | Tái thẩm định độc lập Gate 1 Vòng 2 | 0 | 0 (Xác nhận 10/10 mục đóng, `[APPROVED FOR GATE]`) | Không (đã đối chiếu chéo từng mã AC & yêu cầu) | 195.7 s | Không | Duyệt Gate 1 |
| 2026-11-12 | Gate 2 (Sync) | agile-researcher | claude-opus-5-5-high | Đồng bộ `production-readiness-requirements.md` v1.2 (macOS `PLAT-06`, IP Pinning, custom port, `SEC-15`) | 0 | Chờ Critic/Codex Gate 2 | Không (đã kiểm chứng 222 dòng, 8 nguồn mới `[T38..T45]`) | 451.3 s | Không | Theo yêu cầu người dùng tại Gate 1 |
| 2026-11-12 | Gate 2 (Sync) | agile-po-ba | claude-sonnet-5-5-high | Đồng bộ `product-backlog.md` v1.2 (997 dòng), `charter` v1.2, `vision` v1.1, `personas` v1.1 | 0 | Chờ Critic/Codex Gate 2 | Không (đã kiểm chứng khớp 100% số đếm 51 Must / 234 SP & ma trận truy vết) | 972.9 s | Không | Theo yêu cầu người dùng tại Gate 1 |
| 2026-11-12 | Gate 2 | agile-tech-lead | claude-sonnet-5-5-high | Chốt Tech Stack (Go 1.27.4 `CGO_ENABLED=0`), 11 ADRs, Coding Standards, `.agents/rules/coding-standards.md`, `.golangci.yml`, `scripts/check.*` | 0 | Thay thế bởi Rust v2.0 | Không (đã kiểm chứng đủ 12 file hoàn chỉnh 100%, không bị cắt dòng, frontmatter `always_on` < 10 KB; phiên CLI hết 1800s ngay sau khi ghi xong) | 1800.0 s | Không | Người dùng đổi sang Rust 21:01 |
| 2026-11-12 | Gate 2 | agile-tech-lead | gemini-4-argon-high | Chốt Tech Stack v2.0 (**Rust 1.94.1** `edition="2024"`, 10 crates, `defguard_boringtun`, `redb`, `rustls`), 11 ADRs, Coding Standards, `.agents/rules/coding-standards.md`, `rustfmt/clippy/deny.toml`, `scripts/check.*` | 1 | 2B / 2H / 2M (`BLK-G2-01/04`, Codex `#3/#4`, `HR-G2-01/02`, `IMP-G2-03`, Codex `#13`) | Không (đã kiểm chứng từng file + chạy `scripts/check.ps1` exit 0, frontmatter `always_on` 9.7 KB < 10 KB) | 1017.8 s | Không | Chờ Gate 2 |
| 2026-11-12 | Gate 2 | agile-architect | gemini-4-argon-high | Thiết kế `system-architecture.md` (C4 L1-L3, 6 sequence diagrams, anti-routing-loop, layout 10 crates), `database-design.md` (9 bảng `redb`, ACID idempotency, `RevokedSet` RAM, hot backup), `api-design.md` (`/v1/*`, Relay/STUN/Disco wire bytes, IPC, 12 `ErrorKind`) | 1 | 4B / 4H / 2M (`BLK-G2-02/03`, Codex `#1` STUN / `#2` Disco, `HR-G2-01/03/04`, Codex `#5-#9`, `IMP-G2-01/02`) | Không (đã kiểm chứng đủ 3 file 808+511+647 dòng hoàn chỉnh, khớp 100% tên crate/bảng/route của Tech Lead) | 850.0 s | Không | Chờ Gate 2 |
| 2026-11-12 | Gate 2 | agile-scrum-master | gemini-4-carbon-high | Lập `sprint-backlog.md` v1.0 (Sprint 1 `WP-S1-00..06` = 38 Must / 174 SP; Sprint 2 `WP-S2-01..04` = 13 Must / 60 SP + 11 Should / 35 SP) | 1 | 0B / 1H / 1M (`HR-G2-04` ranh giới `hosts.rs` & Sprint 2, Codex `#14`) | Không (khớp 100% toán học 51 Must / 234 SP) | — | Không | Chờ Gate 2 |
| 2026-11-12 | Gate 2 | agile-codex | gpt-6.1-sol (Codex CLI) | Phản biện độc lập thiết kế Gate 2 Vòng 1 (`review-design` → `gate-2-codex.md`): phát hiện `[REVISION REQUIRED]` (4B / 8H / 2M) | 0 | 0 (Bắt trúng lỗi thật mức byte: STUN `buf[1]&3`, Disco `SalsaBox` reflection, `tungstenite` `sha1`, `E0453` `forbid(unsafe_code)`) | Không (đã kiểm chứng phép toán từng byte & manifest crate) | 484.0 s | Không | Chờ Gate 2 |
| 2026-11-12 | Gate 2 | agile-critic | gemini-4-carbon-high | Phản biện độc lập thiết kế Gate 2 Vòng 1 (`gate-2-critique.md`): phát hiện `[REVISION REQUIRED]` (4B / 4H / 3M) | 0 | 0 (Bắt trúng lỗi thật mức OS/TLS: Windows thiếu `link.exe` & SHA-256 fail-open, Reverse Proxy `tls_exporter_binding`, macOS/Linux supplementary groups IPC, `ENOSPC` revocation) | Không (đã kiểm chứng thực nghiệm trên host & đối chiếu chéo tài liệu) | 798.7 s | Không | Chờ Gate 2 |

## Chỉ số riêng cho vai trò AI (ghi thêm khi vai trò AI bàn giao)

| Ngày | Vai trò | Model | Notebook chạy được trên Colab/Kaggle lần đầu? | Vượt ngân sách (VRAM > 5 GB / phiên > 10 h)? | Rò rỉ dữ liệu bị MLOps-Eval phát hiện? | Số liệu tự báo lệch với số đo lại? | Ghi chú |
|---|---|---|---|---|---|---|---|

## Nhật ký chuyển model (quota)

| Thời điểm | Vai trò | Từ model | Sang model | Lý do | Quota reset lúc | Đã quay lại model chính? |
|---|---|---|---|---|---|---|
| 2026-11-12 18:19 | agile-researcher | claude-opus-5-5-high | gemini-4-argon-high | Hết nhóm quota Claude (`RESOURCE_EXHAUSTED 429`, bao gồm cả dự phòng `claude-sonnet-5-5-high`) giữa Vòng sửa 1 | ~19:05+07:00 (sau 45m21s) | Có (quay lại `claude-opus-5-5-high` lúc 19:51) |
| 2026-11-12 18:19 | agile-po-ba | claude-sonnet-5-5-high | gemini-4-carbon-high | Hết nhóm quota Claude (`RESOURCE_EXHAUSTED 429`) khi bắt đầu Vòng sửa 1; chuyển đúng model dự phòng trong `model-routing.md` | ~19:05+07:00 (sau 45m28s) | Có (quay lại `claude-sonnet-5-5-high` lúc 20:01) |
| 2026-11-12 21:11 | agile-tech-lead | claude-sonnet-5-5-high | gemini-4-argon-high | Chạm trần nhóm quota tuần của Claude (`RESOURCE_EXHAUSTED 429`, `Resets in 136h31m20s`) khi chạy Rust Stack; chuyển sang đúng model dự phòng trong `model-routing.md` | ~2026-11-18 13:43+07:00 | Chưa |
| 2026-11-12 21:11 | agile-architect | claude-opus-5-5-high | gemini-4-argon-high | Nhóm quota tuần của Claude đã cạn (`Resets in 136h31m20s`); chuyển sang đúng model dự phòng trong `model-routing.md` (độc lập họ model ở Gate 2 vẫn được bảo toàn nhờ `agile-codex` họ OpenAI `gpt-6.1-sol`) | ~2026-11-18 13:43+07:00 | Chưa |

## Tổng hợp tại Gate 3

| Sprint | Vai trò | Model | Tổng vòng sửa | Tổng lỗi B/H | Báo cáo sai | Thời gian TB/bàn giao | Đề xuất (giữ / đổi sang …) | Người dùng duyệt? |
|---|---|---|---|---|---|---|---|---|
