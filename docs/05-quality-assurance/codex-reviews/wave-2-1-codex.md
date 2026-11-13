[CHANGES REQUESTED]

1. **🔴 Blocker — Khởi tạo tunnel bị chờ vô hạn.**  
   [supervisor.rs:1303](D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs:1303) gọi `apply_netmap(...).await`, chờ phản hồi từ engine; nhưng `engine.run()` chỉ được spawn tại dòng 1364. Khi đăng ký nhận Netmap hoặc khôi phục cache, không có consumer trả lời → `mesh up`/auto-resume treo. **Sửa:** chạy engine trước khi chờ apply, hoặc áp snapshot trực tiếp trước khi vào vòng lặp; thêm test khởi động có Netmap với timeout.

2. **🟠 High Risk — Re-auth thành công trong DB nhưng vẫn bị RAM chặn.**  
   [store.rs:548](D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs:548) chỉ thêm public key cũ vào blacklist. Trong khi đó, expire tại dòng 1074 đã blacklist cả `NodeId`; không có thao tác gỡ trạng thái hết hạn của ID này. Sau re-auth giữ nguyên `NodeId`, `authenticate_active_node()` tại `control_handlers.rs:1347` vẫn trả `node_revoked` → khóa mới không dùng được. **Sửa:** sau commit re-auth hợp lệ, đồng bộ trạng thái RAM và pending expiry, giữ blacklist khóa cũ; kiểm thử xuyên `ControlStore` đến Control/Relay, không chỉ repository.

3. **🟠 High Risk — Bypass khóa IP khi đoán pre-auth key.**  
   [control_handlers.rs:1225](D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs:1225) gọi `record_auth_success()` ngay khi proof hợp lệ, trước khi kiểm tra pre-auth key tại dòng 343. Kẻ thử key có thể tự tạo keypair và proof hợp lệ: mỗi lần thử lại xóa số lỗi trước đó, rồi tăng lên 1 → không bao giờ đạt 10 lỗi/5 phút. **Sửa:** chỉ reset sau khi xác thực đầy đủ; thêm test 10 request có proof đúng nhưng pre-auth key sai.

4. **🟠 High Risk — Thu hồi RAM phải chờ I/O đĩa.**  
   [store.rs:1052](D:/Project/Idea/mesh-vpn/crates/mesh-store/src/store.rs:1052) thực hiện write transaction, commit và cấp version trước khi cập nhật `RevokedSet` tại dòng 1072; nhánh lỗi cũng chỉ cập nhật RAM sau khi I/O trả về. Đĩa kẹt/ghi chậm khiến node tiếp tục được chấp nhận, không bảo đảm `<100 ms` của US-029. **Sửa:** chặn RAM và ngắt phiên trước thao tác persistence có thể chặn; sau đó hoàn tất các tầng lưu bền và trả đúng `persistence_tier`. Kiểm thử backend trì hoãn I/O, không chỉ trả lỗi tức thì.

5. **🟠 High Risk — Migration sang reverse proxy dùng chính sách xác thực cũ.**  
   [listener_set.rs:279](D:/Project/Idea/mesh-vpn/crates/mesh-server/src/listener_set.rs:279) mở listener theo `target_tls_mode`, nhưng [control_handlers.rs:1290](D:/Project/Idea/mesh-vpn/crates/mesh-server/src/control_handlers.rs:1290) vẫn quyết định proxy bằng `state.config.tls_mode` lúc boot. Chuyển IP-pinned → reverse proxy khiến kết nối mới không có TLS exporter nhưng handler vẫn yêu cầu nó → mọi proof bị từ chối. **Sửa:** gắn chính sách xác thực và xử lý forwarded headers với từng listener, để listener cũ/mới cùng hoạt động đúng trong transition window.

6. **🟠 High Risk — Sai contract của `--min-netmap-version`.**  
   [admin_service.rs:812](D:/Project/Idea/mesh-vpn/crates/mesh-server/src/admin_service.rs:812) truyền flag vào `min_required_snapshot_version`, rồi [backup.rs:453](D:/Project/Idea/mesh-vpn/crates/mesh-store/src/backup.rs:453) từ chối backup có watermark thấp hơn. Contract `database-design.md:645` yêu cầu dùng giá trị này làm **sàn version sau restore**, trước bước `+1_000_000`. Backup cũ hợp lệ vì vậy bị từ chối đúng lúc cần phục hồi. **Sửa:** đưa flag vào `min_netmap_version`; test backup cũ vẫn restore và version mới vượt sàn yêu cầu.

7. **🟠 High Risk — DNS nằm trước thao tác cắt peer.**  
   [engine.rs:660](D:/Project/Idea/mesh-vpn/crates/mesh-datapath/src/engine.rs:660) chờ resolve STUN trước `peer_map.apply_diff()`. `stun_client.rs:375` cho phép chờ 5 giây **mỗi hostname**, kể cả danh sách không đổi → vượt ngân sách cắt peer ≤2 giây, đồng thời chặn xử lý datapath của mọi peer. **Sửa:** áp diff và purge trạng thái peer ngay; tách DNS khỏi vòng xử lý packet, tái dùng kết quả khi endpoint không đổi. Test DNS bị treo khi nhận Netmap thu hồi.

8. **🟠 High Risk — Chưa bảo đảm rebind xong trước TX.**  
   [supervisor.rs:1629](D:/Project/Idea/mesh-vpn/crates/meshd/src/supervisor.rs:1629) chỉ enqueue rebind rồi tiếp tục dispatch reprobe. Engine chọn ngẫu nhiên giữa kênh command, rebind và TUN tại `engine.rs:388`; lỗi rebind tại dòng 1012 chỉ được log. Vì vậy probe/packet có thể gửi qua NIC cũ, và bind thất bại không có retry bảo đảm. **Sửa:** thực hiện rebind rồi reprobe tuần tự trong datapath, chặn TX liên quan khi chưa bind thành công và retry theo backoff của US-035/036.

9. **🟠 High Risk — Uninstall Linux có thể xóa tài nguyên của ứng dụng khác.**  
   [install-linux.sh:241](D:/Project/Idea/mesh-vpn/scripts/install-linux.sh:241) flush toàn bộ table `51820`, xóa rule và interface `mesh0` theo tên cố định, không đối chiếu ledger. Máy có tài nguyên trùng tên/số sẽ bị mất route/interface, trái G4. **Sửa:** cleanup theo `ResourceLedger` và xác minh ownership; khi thiếu ledger phải giữ tài nguyên không chứng minh được thuộc Mesh. Test uninstall với table/interface trùng tên do bên khác tạo.

10. **🟠 High Risk — Bộ lọc bugreport để lọt secret thứ chín.**  
    [config.rs:708](D:/Project/Idea/mesh-vpn/crates/meshd/src/config.rs:708) chỉ chạy 8 lượt; mỗi lượt thay đúng một giá trị rồi `break`. Một dòng log chứa 9 trường secret được nhận diện sẽ giữ nguyên ít nhất một giá trị trong archive → không đạt “0 secret leakage” của US-041. **Sửa:** xử lý hết các trường bằng lượt quét có tiến triển được bảo đảm; bổ sung canary cho ≥9 secret trên một dòng, giá trị có escape và cấu trúc lồng nhau.

**Giới hạn kiểm chứng:** Các phát hiện trên dựa trên mã hiện tại và contract trong `docs/`; chưa chạy test/lint hoặc đo SLO thực tế. `git` không khả dụng trong PATH nên chưa xác định lỗi nào đã tồn tại ở baseline `1a916ed`. File compute-profile tại đường dẫn cung cấp không tồn tại; phần đối chiếu tài liệu đó **chưa kiểm chứng**. Không sửa file hay chạy thao tác thay đổi trạng thái.

[CHANGES REQUESTED]