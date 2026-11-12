Thiết kế chưa sẵn sàng qua Gate 2. Các đường dẫn thiết kế dưới đây thuộc `docs/03-system-design/`.

**🔴 Blocker**

1. **`api-design.md:313` → STUN hợp lệ bị loại.** Cả Binding Request `0x0001` và Response `0x0101` đều có `buf[1] = 1`, trái điều kiện `(buf[1] & 3) == 0` → STUN không hoạt động. **Sửa:** kiểm tra đúng message type, cookie và message length; thêm vector Request/Response hợp lệ vào test demux. Đã kiểm chứng phép toán chỉ-đọc.

2. **`api-design.md:343–364` → Disco thiếu ràng buộc chiều gửi và danh tính bên trong ciphertext.** `SalsaBox` dùng cùng khóa đối xứng cho hai chiều. Theo contract hiện tại, kẻ quan sát có thể đổi header sender rồi phản xạ Ping và Pong về chính người gửi, tạo Pong khớp `pending_pings` → đầu độc đường Direct/DoS. **Sửa:** xác thực thêm protocol context, sender và recipient trong plaintext; kiểm tra trước khi xử lý Ping/Pong; bổ sung test phản xạ. Đây là suy luận từ contract và [cấu trúc SalsaBox](https://docs.rs/crypto_box/0.9.1/crypto_box/), **chưa chạy PoC**.

3. **`deny.toml:64` + `tech-stack-decision.md:191` → chính sách dependency chặn chính WebSocket stack đã chọn.** Feature `handshake` của `tungstenite 0.26.2` kéo `sha1` → `cargo deny` không thể xanh với luồng HTTP Upgrade đã thiết kế. **Sửa:** đề xuất ngoại lệ hẹp cho SHA-1 phục vụ WebSocket handshake, tiếp tục cấm dùng cho xác thực/băm bảo mật của ứng dụng. [Manifest chính chủ](https://raw.githubusercontent.com/snapview/tungstenite-rs/v0.26.2/Cargo.toml).

4. **`tech-stack-decision.md:140`, `architecture-decision-record.md:57` → ngoại lệ `unsafe` không thực hiện được như mô tả.** Crate kế thừa `unsafe_code = "forbid"` không thể hạ bằng `#![allow(unsafe_code)]` → `mesh-sys` không biên dịch khi chứa FFI. **Sửa:** quy định rõ `mesh-sys` không kế thừa lint `forbid` này, đồng thời giữ đầy đủ các lint an toàn còn lại; các crate nghiệp vụ vẫn `forbid`. [Quy tắc Rust E0453](https://doc.rust-lang.org/stable/error_codes/E0453.html).

**🟠 High Risk**

5. **`database-design.md:339,356,375` → `netmap_version` có hai nguồn tăng độc lập.** Presence/revoke tăng trong RAM, transaction tăng trong DB; chưa có quy tắc đồng bộ hoặc phục hồi sau restart → version có thể lùi, khiến agent bỏ qua cập nhật, kể cả thu hồi. **Sửa:** khóa một cơ chế cấp version thống nhất và hành vi restart/restore/ENOSPC; kiểm thử xen kẽ presence → register → revoke → restart theo `REL-03`.

6. **`database-design.md:354–361` → thu hồi RAM mất hiệu lực sau restart khi persist thất bại.** Khi boot chỉ nạp trạng thái DB cũ; `disk_degraded` cũng chỉ nằm trong RAM → node đã báo thu hồi có thể được chấp nhận trở lại. **Sửa:** bổ sung cơ chế phục hồi thu hồi khẩn cấp bền vững hoặc trạng thái khởi động fail-closed cần đối soát; test chuỗi ENOSPC → revoke → crash → restart.

7. **`database-design.md:202–213` → khóa server nằm trong struct `Debug + Clone` dưới dạng `Vec<u8>` trần.** `Debug` có thể xuất toàn bộ PKCS#8; các bản sao không được zeroize → trái `coding-standards.md:187,228` và `SEC-01`. **Sửa:** tách codec lưu trữ có chủ đích khỏi kiểu bí mật runtime; redact `Debug`, zeroize buffer và hạn chế sao chép; giữ test canary ở mức DEBUG.

8. **`api-design.md:35` → bộ lọc endpoint loại mọi địa chỉ mang IP public của VPS.** Điều này loại luôn endpoint WireGuard hợp lệ của `vps.mesh.internal`, dù ví dụ tại dòng 138 lại công bố chính địa chỉ đó → VPS-node khó có Direct qua IP public, phải đi Relay. **Sửa:** phân biệt endpoint data plane của VPS-node với endpoint Control/Relay/STUN; không cấm toàn bộ IP VPS.

9. **`system-architecture.md:305,492`, `api-design.md:295–296`, ADR-004 dòng 166–167 → ba mô tả Relay không thống nhất.** Kiến trúc dùng `0x01` cho chiều nhận, API dùng `0x02`, ADR không mô tả type byte → các worker có thể tạo encoder/decoder không tương thích. **Sửa:** thống nhất một layout chuẩn và vector byte hai chiều dùng chung.

10. **`scripts/bootstrap-toolchain.ps1:28,70–74` → kiểm hash Zig fail-open, hằng số hash cũng sai.** Hash lệch chỉ cảnh báo rồi vẫn giải nén và chạy executable → chuỗi cung ứng chưa được bảo vệ như ADR cam kết. **Sửa:** dùng hash đúng từ [Zig chính thức](https://ziglang.org/download/index.json), dừng bằng lỗi trước giải nén khi không khớp, bỏ bypass. Ngoài ra, dòng 101–104 dùng `cargo install` nhưng chưa thiết lập linker cho phương án máy thiếu MSVC; chưa cài `rcodesign` như tài liệu hứa → cần chứng minh bootstrap trên máy sạch.

11. **`api-design.md:430`, `database-design.md:392` → quyền IPC macOS không khớp contract.** Socket `0660 root:admin` chặn user thường trước middleware, trong khi API cho phép họ đọc. `peer_cred().gid() == 80` cũng không chứng minh membership nhóm phụ → admin có thể bị từ chối. **Sửa:** chốt quyền truy cập đọc và kiểm tra membership từ danh tính kernel; kiểm thử user thường, admin có primary group khác 80 và root. [Tokio chỉ trả một GID](https://raw.githubusercontent.com/tokio-rs/tokio/tokio-1.44.0/tokio/src/net/unix/ucred.rs).

12. **`scripts/check.sh:34,70` → kiểm tra nhiều file có thể báo xanh sai.** `NR==1` chỉ xét file đầu của mỗi batch; `exit` tại `#[cfg(test)]` dừng toàn bộ batch → BOM hoặc port cứng ở file sau bị bỏ sót. **Sửa:** dùng `FNR==1` và trạng thái bỏ qua riêng từng file; thêm fixture nhiều file. Chưa chạy kiểm chứng shell trong môi trường này.

**🟡 Improvement**

13. **`rust-toolchain.toml:3` → đang dùng `stable`, không ghim `1.94.1`.** Máy mới hoặc cập nhật toolchain có thể dùng compiler khác quyết định đã duyệt. **Sửa:** đặt `channel = "1.94.1"` và kiểm tra phiên bản chính xác trong script.

14. **`sprint-backlog.md:217–219` → chưa thấy đụng file trực tiếp, nhưng thiếu bàn giao phần CLI Sprint 2.** Gói server sở hữu backup/restore/migration, còn `crates/mesh/**` thuộc worker khác → dễ thiếu lệnh hoặc phát sinh sửa ngoài phạm vi. **Sửa:** bổ sung owner và phụ thuộc rõ cho các lệnh CLI này.

**Cần người dùng quyết định**

- Thay đổi contract Disco để chống phản xạ; cơ chế version và phục hồi thu hồi sau ENOSPC.
- Ngoại lệ SHA-1 giới hạn cho WebSocket handshake.
- Quyền đọc IPC macOS và lựa chọn OQ-15 đã nêu trong Sprint Backlog.

Rule `always_on` đúng frontmatter, dung lượng **9.713 byte**, có lệnh kiểm tra chuẩn. Chưa có `Cargo.toml`, nên **chưa kiểm chứng build/test, tương thích feature đa nền tảng hoặc footprint RAM**. Không có AI/SLM; compute profile không áp dụng.

[REVISION REQUIRED]