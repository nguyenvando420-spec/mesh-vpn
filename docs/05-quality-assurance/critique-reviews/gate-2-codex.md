**Chưa đủ điều kiện qua Gate 2.** Đối chiếu tại HEAD `0061271537080319dc1a7d3376b30dd1e2ee745e`: các điểm vòng 1 **#1, #2, #3, #4, #7, #9, #11, #12, #13, #14** đã được xử lý ở mức tài liệu/script; **#5, #6, #8, #10** còn thiếu. Có thêm xung đột IPC khi VPS kiêm node.

1. **🟠 High Risk — #5: version vẫn có thể lùi sau restart.**  
   [database-design.md:429](D:/Project/Idea/mesh-vpn/docs/03-system-design/database-design.md:429), dòng 461 → presence chỉ tăng RAM, lúc boot lấy `max(db, slot, now_ms)` nên không bảo toàn version đã công bố nếu đồng hồ lùi. Tính toán chỉ-đọc xác nhận: đã phát `1700000060000`, sau restart có thể phát `1700000030001` → agent bỏ qua bản mới theo `US-009 AC3`, ảnh hưởng cả thu hồi. **Sửa:** đặc tả high-watermark bền vững cho version, kể cả cập nhật RAM; bổ sung test clock rollback → crash → restart và restore.

2. **🟠 High Risk — #6: nhánh phục hồi thu hồi chưa đầy đủ.**  
   [database-design.md:383](D:/Project/Idea/mesh-vpn/docs/03-system-design/database-design.md:383), dòng 391–410 → khẳng định ghi slot “luôn thành công”, nhưng chưa quy định khi `pwrite`/`sync_data` lỗi, slot hết sức chứa hoặc cả hai slot hỏng. Pre-allocation không loại bỏ lỗi I/O → chưa bảo đảm chống hồi sinh sau restart trong các trường hợp này. **Sửa:** chỉ báo `persisted=true` sau ghi và sync thành công; khóa hành vi RAM-only, xử lý tràn/thu gọn journal và điều kiện boot fail-closed; bổ sung fault-injection. **Chưa chạy thử filesystem.**

3. **🟠 High Risk — mới: hai dịch vụ tranh quyền thư mục IPC.**  
   [api-design.md:480](D:/Project/Idea/mesh-vpn/docs/03-system-design/api-design.md:480) và [api-design.md:548](D:/Project/Idea/mesh-vpn/docs/03-system-design/api-design.md:548) → server yêu cầu `/run/mesh` là `0750 mesh:mesh-admin`, daemon yêu cầu cùng thư mục là `0755 root:root` (`/var/run` alias `/run`). Khi VPS kiêm node, một thư mục không đáp ứng đồng thời: server có thể không bind được socket hoặc user thường không truy cập được kênh đọc. **Sửa đề xuất:** tách thư mục runtime riêng cho hai dịch vụ, đồng bộ installer/systemd/CLI và kiểm thử cả hai thứ tự khởi động.

4. **🟠 High Risk — #8: bộ lọc vẫn nhầm TCP với UDP.**  
   [api-design.md:37](D:/Project/Idea/mesh-vpn/docs/03-system-design/api-design.md:37) → loại candidate UDP nếu trùng `SocketAddr` của Control TCP. Cấu hình hợp lệ `Control TCP :51820`, `meshd UDP :51820`, `STUN UDP :3478` sẽ mất endpoint Direct của VPS dù hai transport không xung đột → trái yêu cầu cổng tùy ý. **Sửa:** phân biệt transport khi so endpoint; thêm vector TCP/UDP trùng số cổng.

5. **🟠 High Risk — #10: bootstrap MSVC chưa cài đủ công cụ.**  
   [bootstrap-toolchain.ps1:236](D:/Project/Idea/mesh-vpn/scripts/bootstrap-toolchain.ps1:236) → nhánh thật chỉ gọi `winget` và thêm target; không tải cargo-deny/cargo-zigbuild/rcodesign như DryRun mô tả → máy sạch vẫn thất bại tại bước cargo-deny của `check.ps1`. **Sửa:** dùng chung bước cài prebuilt đã kiểm hash cho cả hai mode, kiểm tra exit code và executable cuối bước. **Chưa chạy installer.**

**🟡 Improvement:** [ADR-007:293](D:/Project/Idea/mesh-vpn/docs/03-system-design/architecture-decision-record.md:293) dùng priority `5182/5181`, trong khi kiến trúc và ledger dùng `51820/51810` → worker có thể cài và dọn khác rule. **Sửa:** thống nhất giá trị và kiểm chứng cleanup theo ledger.

**Cần người dùng quyết định:** cơ chế version bền vững, chính sách khi journal thu hồi không ghi được và phương án tách thư mục IPC. `OQ-15` tiếp tục trình riêng; giữ baseline **38 Must/174 SP** và **13 Must/60 SP**.

Đã xác nhận `rustc 1.94.1`, rule **9.907 byte**, không BOM. Hash MinGW và cargo-deny khớp metadata phát hành chính thức ([MinGW](https://github.com/brechtsanders/winlibs_mingw/releases/expanded_assets/16.2.0posix-23.1.3-14.0.0-ucrt-r3), [cargo-deny](https://github.com/EmbarkStudios/cargo-deny/releases/expanded_assets/0.20.2)). Chưa có `Cargo.toml`, nên build/test/lint và footprint RAM **chưa kiểm chứng**. Không có AI/SLM; compute profile không áp dụng.

[REVISION REQUIRED]
