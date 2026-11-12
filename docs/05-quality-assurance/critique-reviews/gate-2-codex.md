Đã xác nhận **`fd9cb0dbd990a301590cf09527938aee5a6583ff`**; 22 file tài liệu/script khớp Git object. **Còn 2 🟠 High Risk; chưa có 🔴 Blocker.**

| Mục R2 | Kết quả kiểm chứng |
|---|---|
| #1 — Version lùi khi clock rollback + crash | Ca gốc đã được xử lý bằng lease bền vững; còn nhánh hết lease dưới đây. |
| #2 — Emergency persistence | Đã bổ sung `persisted`, ba tier, bảo vệ sức chứa và fail-closed boot; phục hồi `ram_only` chưa đầy đủ. |
| #3 — Xung đột runtime IPC | **Đóng ở mức thiết kế**: đường dẫn/quyền đã tách và có yêu cầu test hai thứ tự khởi động. |
| #4 — Lọc nhầm TCP/UDP | **Đóng ở mức thiết kế**: contract, kiến trúc và vector kiểm thử thống nhất. |
| #5 — Bootstrap Msvc | **Đóng ở mức đọc mã**: dùng chung installer, kiểm tra exit code. Chưa chạy cài đặt. |
| Improvement — Priority, slice pattern, tên file | **Đóng** tại các vị trí được chỉ định. |

1. **🟠 High Risk — Compaction bỏ sót thu hồi `ram_only`.**  
   [database-design.md:411](D:/Project/Idea/mesh-vpn/docs/03-system-design/database-design.md:411) và [dòng 415](D:/Project/Idea/mesh-vpn/docs/03-system-design/database-design.md:415) → thu hồi mới được giữ trong RAM khi ghi thất bại, nhưng compaction chỉ hợp nhất các mục nằm trong file emergency rồi xóa `disk_degraded`. Ví dụ: A đã lưu slot, B chỉ nằm trong RAM; đĩa phục hồi, compaction chỉ lưu A → `/readyz` có thể trở lại bình thường nhưng restart làm B sống lại. **Cách sửa:** theo dõi toàn bộ thu hồi chưa bền vững, gồm cả `ram_only`; hợp nhất chúng vào giao dịch phục hồi, chỉ bỏ trạng thái degraded khi không còn mục chưa lưu. Thêm test `ram_only → disk recovery → compaction → restart`.

2. **🟠 High Risk — Chưa khóa hành vi thu hồi khi hết lease và cả hai tầng lưu đều lỗi.**  
   [database-design.md:454](D:/Project/Idea/mesh-vpn/docs/03-system-design/database-design.md:454), [dòng 458](D:/Project/Idea/mesh-vpn/docs/03-system-design/database-design.md:458) và [system-architecture.md:355](D:/Project/Idea/mesh-vpn/docs/03-system-design/system-architecture.md:355) → bất biến cấm phát `next > persisted_watermark`, nhưng nhánh lỗi chỉ quy định dừng presence; luồng revoke vẫn yêu cầu cấp version và phát Netmap trước khi ghi bền. Khi `current = watermark = W`, không thể cấp `W+1` đúng bất biến. Nếu vẫn phát, restart có thể phát lại `W+1`; nếu allocation thất bại, luồng chưa quy định việc tiếp tục cắt phiên. **Cách sửa:** đặc tả riêng nhánh này, bảo đảm chặn RAM/cancel phiên vẫn thực hiện khi không cấp được version; bổ sung test hết lease + lỗi cả hai tầng + restart.

**Cần người dùng quyết định:** chính sách phân phối thu hồi tới peer trong nhánh suy giảm ở mục 2; và `OQ-15` về việc kéo 11 SP sang Milestone 1 vẫn giữ để trình Gate 2.

Chưa có mã Rust nên chưa kiểm chứng runtime; các tình huống trên được đối chiếu bằng mô hình trong bộ nhớ. Không có AI/SLM nên giới hạn RTX 2060 không áp dụng; file compute-profile tại đường dẫn project được chỉ định không tồn tại.

[REVISION REQUIRED]
