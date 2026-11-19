# Hướng Dẫn Cài Đặt & Sử Dụng Mesh Client trên VPS Linux (CLI) (`v0.3.0`)

Tài liệu này dành cho **VPS / server Linux không có giao diện đồ họa** (`x86_64`, dùng CLI `mesh` và daemon `meshd`). Nếu bạn dùng Ubuntu/Debian Desktop có màn hình GUI, xem thêm [hướng dẫn Linux Desktop](./linux-desktop.md).

---

## 1. Tải gói cài đặt ở đâu?

Trên VPS không cần giao diện, hãy tải gói static `musl` từ **[Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**:

- Tệp tải về: [`mesh-linux-x86_64-musl.tar.gz`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-linux-x86_64-musl.tar.gz) *(9.44 MiB)*
- Bao gồm: `meshd`, `mesh`, `mesh-server`, `MeshVPN`, `scripts/install-linux.sh`, `deploy/systemd/meshd.service` và `SHA256SUMS`.
- Hỗ trợ mọi bản phân phối Linux dùng `systemd` (Ubuntu, Debian, Rocky, AlmaLinux, CentOS, Arch, v.v.).

---

## 2. Kiểm tra điều kiện trên VPS

1. Đảm bảo thiết bị nhân `/dev/net/tun` tồn tại:
   ```bash
   ls -l /dev/net/tun || sudo modprobe tun
   ```
   *(Nếu là container OpenVZ/LXC báo thiếu `/dev/net/tun`, hãy bật tùy chọn **TUN/TAP** trong bảng điều khiển của nhà cung cấp VPS).*
2. Lấy sẵn thông tin kết nối từ máy chủ (`mesh server status` & `mesh preauthkey create` — xem [hướng dẫn VPS Server](./vps-server.md)):
   - Địa chỉ Control Server (`<IP_HOAC_DOMAIN>:<PORT>`, mặc định `443`).
   - Mã `sha256:<64_HEX>` SPKI Pin (nếu dùng chế độ mặc định IP + SPKI Pin).
   - Khóa đăng ký `mpk_...` (hoặc lấy phần `key=...` trong URI `mesh://join?...`).

---

## 3. Tải về & Cài đặt `meshd` + `mesh`

```bash
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-linux-x86_64-musl.tar.gz
mkdir -p mesh-vpn && tar -xzf mesh-linux-x86_64-musl.tar.gz -C mesh-vpn
cd mesh-vpn
sha256sum -c SHA256SUMS

sudo sh ./scripts/install-linux.sh --from . --sha256-file ./SHA256SUMS
```

Tùy chọn thêm khi cài đặt qua [`install-linux.sh`](../../scripts/install-linux.sh):
- `--no-firewall`: Bỏ qua việc tự thêm rule `nftables`/`iptables` (dùng khi bạn tự quản lý firewall nghiêm ngặt). Lưu ý mặc định script chỉ thêm bảng/chain tách biệt cho interface `mesh0` và **không** xóa rule UFW/Docker hiện có.
- Cho phép user hiện tại chạy `mesh up` / `mesh down` mà không cần `sudo`:
  ```bash
  sudo usermod -aG mesh-admin "$USER"
  newgrp mesh-admin
  ```

### Đường dẫn chính sau khi cài

- Nhị phân: `/usr/bin/meshd`, `/usr/bin/mesh`
- Dịch vụ `systemd`: `/etc/systemd/system/meshd.service`
- Dữ liệu & danh tính node: `/var/lib/meshd/` (`0700 root:root`)
- IPC socket:
  - Kênh đọc (`mesh status`, `mesh peers`, `mesh ping`, `mesh netcheck`): `/var/run/meshd/meshd-ro.sock` (`0666`)
  - Kênh ghi đặc quyền (`mesh up`, `mesh down`, `mesh rotate-key`): `/var/run/meshd/meshd-admin.sock` (`0660 root:mesh-admin`)

---

## 4. Kết nối VPS vào mạng Mesh VPN

Vì lý do bảo mật (`SEC-01`, tránh lộ khóa trong `ps aux` / shell history), CLI **cấm** truyền khóa thô qua `--authkey <key>` trên dòng lệnh. Hãy dùng `--authkey-stdin` hoặc `--authkey-file`:

### Cách A: Kết nối bằng IP + SPKI Pin (Mặc định)

```bash
printf '%s\n' '<PREAUTH_KEY>' | sudo mesh up \
  --server <IP_VPS_SERVER>:443 \
  --server-pin sha256:<64_HEX_PIN> \
  --name vps-node-01 \
  --authkey-stdin
```

### Cách B: Kết nối qua Tên miền có chứng chỉ CA công khai (ACME / Reverse Proxy)

```bash
printf '%s\n' '<PREAUTH_KEY>' | sudo mesh up \
  --server vpn.example.com:443 \
  --ca-tls \
  --name vps-node-01 \
  --authkey-stdin
```

### Cách C: Dùng file khóa `0600`

```bash
umask 077
printf '%s\n' '<PREAUTH_KEY>' > /tmp/mesh-preauth.key
sudo mesh up --server <IP_VPS_SERVER>:443 --server-pin sha256:<64_HEX_PIN> --authkey-file /tmp/mesh-preauth.key
rm -f /tmp/mesh-preauth.key
```

*(Lưu ý: với node **VPS đã đăng ký trước đó**, khi khởi động lại hoặc bật lại VPN chỉ cần chạy `sudo mesh up --server ...` mà không cần nhập lại pre-auth key.)*

---

## 5. Các lệnh kiểm tra & vận hành hàng ngày

| Mục đích | Lệnh |
| --- | --- |
| Xem IP Mesh của VPS & trạng thái kết nối | `mesh status` (hoặc `mesh status --json`) |
| Xem danh sách peer & đường đi (`direct` / `relay`) | `mesh peers` |
| Kiểm tra NAT & khả năng đục lỗ UDP STUN | `mesh netcheck` |
| Ping kiểm tra kết nối tới peer khác | `mesh ping <TEN_PEER_HOAC_OVERLAY_IP> -c 4` |
| Kiểm tra kết nối P2P trực tiếp | `mesh ping <PEER> --direct` |
| Ngắt VPN tạm thời (daemon vẫn chạy) | `sudo mesh down` |
| Đổi endpoint hoặc pin server mới | `sudo mesh set --server <HOST:PORT> --server-pin sha256:<HEX>` |
| Xoay khóa node (giữ nguyên Overlay IP) | `printf '%s\n' '<SCOPED_KEY>' \| sudo mesh rotate-key --authkey-stdin` |
| Xuất gói chẩn đoán `.tar` (đã lọc secret) | `sudo mesh bugreport` |
| Xem log daemon | `journalctl -u meshd -n 100 --no-pager` |

---

## 6. Gỡ cài đặt sạch

- Gỡ nhị phân & `meshd.service` nhưng **giữ lại danh tính node** trong `/var/lib/meshd`:
  ```bash
  sudo sh ./scripts/install-linux.sh --uninstall
  ```
- Gỡ hoàn toàn bao gồm khóa node, cấu hình và log:
  ```bash
  sudo sh ./scripts/install-linux.sh --uninstall --purge
  ```
