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

## Chỉ số riêng cho vai trò AI (ghi thêm khi vai trò AI bàn giao)

| Ngày | Vai trò | Model | Notebook chạy được trên Colab/Kaggle lần đầu? | Vượt ngân sách (VRAM > 5 GB / phiên > 10 h)? | Rò rỉ dữ liệu bị MLOps-Eval phát hiện? | Số liệu tự báo lệch với số đo lại? | Ghi chú |
|---|---|---|---|---|---|---|---|

## Nhật ký chuyển model (quota)

| Thời điểm | Vai trò | Từ model | Sang model | Lý do | Quota reset lúc | Đã quay lại model chính? |
|---|---|---|---|---|---|---|
| 2026-11-12 18:19 | agile-researcher | claude-opus-5-5-high | gemini-4-argon-high | Hết nhóm quota Claude (`RESOURCE_EXHAUSTED 429`, bao gồm cả dự phòng `claude-sonnet-5-5-high`) giữa Vòng sửa 1 | ~19:05+07:00 (sau 45m21s) | Có (quay lại `claude-opus-5-5-high` lúc 19:51) |
| 2026-11-12 18:19 | agile-po-ba | claude-sonnet-5-5-high | gemini-4-carbon-high | Hết nhóm quota Claude (`RESOURCE_EXHAUSTED 429`) khi bắt đầu Vòng sửa 1; chuyển đúng model dự phòng trong `model-routing.md` | ~19:05+07:00 (sau 45m28s) | Có (quay lại `claude-sonnet-5-5-high` lúc 20:01) |

## Tổng hợp tại Gate 3

| Sprint | Vai trò | Model | Tổng vòng sửa | Tổng lỗi B/H | Báo cáo sai | Thời gian TB/bàn giao | Đề xuất (giữ / đổi sang …) | Người dùng duyệt? |
|---|---|---|---|---|---|---|---|---|
