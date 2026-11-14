# Đúc Kết & Cải Tiến Quy Trình — Sprint 1 & Sprint 2 Retrospective (`Gate 3`)

- **Dự án**: Mesh VPN (Rust `1.94.1`, `edition = "2024"`)
- **Ngày tổng kết**: `2026-11-14`
- **Phạm vi nhìn lại**: Toàn bộ 2 Sprint (`WP-S1-00..06` và `WP-S2-01..04` — `62 User Stories / 269 SP`), quy trình Multi-Agent Agile Team v3.1.0 (`Orchestrator + Native Swarm`) và chuỗi kiểm định Gate 1 -> Gate 3.

---

## 1. Điểm Làm Tốt (What Went Well)

1. **Chiến lược "Khóa Khung Trước — Lấp Ruột Song Song Sau" (`0% File Overlap`)**:
   - Việc tách `WP-S1-00` định nghĩa sẵn toàn bộ Traits, Fake RAM và phân tách tệp `*_linux.rs`, `*_macos.rs`, `*_windows.rs` giúp 4 worker Wave 1.1, 2 worker Wave 1.2, 3 worker Wave 2.1 và 2 worker sửa lỗi Gate 3 chạy song song trên worktree cô lập (`workspace: "share"`) mà **không xảy ra xung đột `Cargo.toml` hay ghi đè chéo**.
   - Tỷ lệ kiểm thử tăng đều và bền vững qua từng đợt: `63 -> 173 -> 215 -> 223 -> 275 -> 285 -> 303 -> 308 passed / 0 failed / 0 ignored` (đầy đủ unit, `proptest!`, `Barrier` concurrency, Dual-`EIO`, Live Process E2E, và SLO benchmarks).
2. **Kiến trúc Pure-Rust Zero-C & Bảo vệ Máy Thật (`G4`)**:
   - Lựa chọn `redb` + `rustls` (`ring`) + `defguard_boringtun` loại bỏ hoàn toàn OpenSSL C / SQLite C / `aws-lc-rs`, giúp `check.ps1 -Cross` kiểm tra chéo được cả Linux `musl`, macOS `arm64/x86_64` và Windows GNU ngay từ máy trạm Windows.
   - Cơ chế `ResourceLedger` ghi sổ cái trước khi chạm OS và Fake Traits trong `mesh-net` cho phép 100% logic mạng/phân quyền/dọn dẹp chạy xanh tự động không cần quyền `root`/`Admin` và không rủi ro làm hỏng cấu hình mạng của máy phát triển.
3. **Giá trị Thực Chiến của Bộ Đôi Phản Biện & QA Độc Lập (`agile-critic` & `agile-qa`)**:
   - Mô hình phản biện nhiều vòng (`critic-2` họ `carbon-high` + `qa-s2` họ `argon-high` độc lập với tác giả `hydrogen-xhigh`) đã bắt được đúng những lỗi sẽ gãy trực tiếp trên Production thật:
     - `HR-G3-04`: Deadlock `mesh server restore` đòi UDS khi `control.redb` hỏng hoặc xung đột `Pin_TEMP` khi dựng VPS mới (được giải quyết bằng `ControlStore::restore_offline_with_clock` và `mesh-server --restore-from`).
     - `HR-G3-01` & `HR-G3-02`: Thiếu fallback `.plist` trên macOS, sai thứ tự ưu tiên unit hardened trên Linux, thiếu `wintun.dll`/`SHA256SUMS` trong bundle CI, và `https://` bị `client_cmds.rs` bọc ngoặc IPv6.
     - `HR-G3-03`: Bảo vệ tính liêm chính của báo cáo SLO (khôi phục `PERF-09 <= 50.0 MiB` đo RSS thật, đo `WorkingSet64` bản release `mesh-server.exe`, ép burst `PERF-11` vượt ngưỡng `625 KB`, và ghi nhận trung thực trạng thái `pending_external_lab`).

---

## 2. Điểm Cần Cải Thiện & Thách Thức Đã Xử Lý (Challenges & Learnings)

1. **Hành vi Sandbox trên Windows (`.cargo-lock`, `.git/index.lock`, Named Pipe & WSL Pipe)**:
   - *Hiện tượng*: Sandbox Windows chặn khóa `.cargo-lock` / Named Pipe (`os error 5`), chặn copy trực tiếp ra workspace chính từ worktree cô lập, và `wsl.exe` bị treo chờ `EOF` trên stdin khi chạy không có `< NUL` / `"" | wsl`.
   - *Cách xử lý chuẩn hóa*: Thiết lập quy trình gọn nhẹ: chạy worker viết/test trong worktree cô lập, Coordinator review diff và đồng bộ sạch vào `main`, luôn truyền `"" | wsl bash -n` để đóng stdin ngay lập tức, và tuân thủ thử sandbox trước -> chỉ bật `BypassSandbox: true` với cùng `toolSummary` cho lệnh host cần lock/pipe thật.
2. **Độ trễ & Đồng bộ Số liệu Giữa Bộ Test SLO và Tài liệu QA**:
   - *Hiện tượng*: Ở lần đầu chạy `run-slo-suite`, 2 tệp JSON trùng ID `PERF-11` và phần ghi `$opsSuffix` tự gắn nhãn Docker lab, cùng việc thêm test ở vòng sửa sau QA khiến tổng số test nhảy `303 -> 308`.
   - *Bài học*: Mỗi metric SLO phải có ID duy nhất (`PERF-11` vs `PERF-11-QUEUE`), điều kiện báo cáo nguồn phải bám trực tiếp biến trạng thái chạy thực tế (`$chaosStatus -eq "PASS"`), và mọi vòng sửa sau QA cần đồng bộ lại tài liệu QA trước khi khép Gate.
3. **Ngoại lệ Kiểm tĩnh BOM/LF (`MED-G3-02`)**:
   - *Hiện tượng*: Việc miễn trừ tạm `docs/04-sprint-management` khỏi bộ lọc BOM/LF trong `check.{ps1,sh}` đã vô tình che giấu BOM và CRLF trong `agile-state.md` và `model-performance.md`.
   - *Khắc phục*: Đã chuẩn hóa UTF-8 no-BOM + LF trên toàn kho mã và gỡ hoàn toàn ngoại lệ khỏi `scripts/check.{ps1,sh}`.
4. **Điều phối Quota Model Dự phòng**:
   - *Hiện tượng*: Nhóm quota Claude và ChatGPT chạm ngưỡng sớm trong quá trình phát triển. Nhờ quy tắc `model-routing.md` định tuyến rõ model đơn pha cho Swarm (`hydrogen-xhigh`, `hydrogen-high`, `argon-high`, `carbon-high`), tiến độ không bị đứt quãng mà vẫn giữ được tính độc lập giữa người viết code và người kiểm định/phản biện.

---

## 3. Hành Động Tiếp Theo Cho Vận Hành Production & Phase 2 (Action Items)

| Hạng Mục | Chủ Sở Hữu | Điều Kiện Kích Hoạt / Mốc Thời Gian |
| :--- | :--- | :--- |
| **1. Nghiệm thu 5-minute VPS Soak & 8 Kịch bản Docker Chaos (`PERF-02`)** | Người vận hành / CI (`ubuntu-latest` hoặc VPS staging) | Chạy `sh lab/scenarios/run-all-chaos.sh` & `sh scripts/run-slo-suite.sh --with-docker-lab` trước Go-Live chính thức. |
| **2. Ký Biên bản Sleep/Wake & Roaming trên Phần cứng Thật (`PLAT-05`, `PLAT-06`)** | Người dùng / QA thực địa | Chạy đủ 20 hạng mục [go-live-checklist.md](../06-operations/go-live-checklist.md) theo [hardware-sleep-wake-protocol.md](../06-operations/hardware-sleep-wake-protocol.md) trên MacBook 13+ và Laptop Windows 10/11. |
| **3. Trình bày & Ký Cân nhắc Đánh đổi Phase 2 (Notarized `.pkg` & EV Authenticode)** | Product Owner / Người dùng | Cân nhắc sau khi bản MVP `v0.1.0` vận hành ổn định trong mạng cá nhân/đội nhóm nhỏ (mục `EP-12` trong `product-backlog.md`). |
