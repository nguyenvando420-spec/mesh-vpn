# Hướng Dẫn Cài Đặt & Vận Hành Mesh Server trên VPS Linux (`v0.3.0`)

Tài liệu này hướng dẫn cài đặt, cấp khóa kết nối và vận hành **`mesh-server`** (Control Plane + Blind Relay + STUN) trên VPS Linux (`x86_64`).

---

## 1. Tải gói cài đặt ở đâu?

Tải tại trang phát hành chính thức **[Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**:

| Hình thức triển khai | Tệp tải về | Ghi chú |
| --- | --- | --- |
| **Native `systemd` (Khuyên dùng)** | [`mesh-linux-x86_64-musl.tar.gz`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-linux-x86_64-musl.tar.gz) | Nhị phân tĩnh `musl`, chạy trên mọi distro Linux `x86_64` (Ubuntu, Debian, Rocky/Alma, CentOS, Alpine). Gồm sẵn `mesh-server`, `mesh`, `meshd`, `scripts/install-server.sh`, `deploy/systemd/mesh-server.service` và `SHA256SUMS`. |
| **Docker container** *(tùy chọn)* | [`mesh-server-image-linux-amd64.tar.gz`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-server-image-linux-amd64.tar.gz) | Image OCI sẵn `mesh-server` + `mesh` chạy dưới UID không đặc quyền `mesh`. |
| **Kiểm tra toàn vẹn** | [`SHA256SUMS`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/SHA256SUMS) | Danh sách SHA-256 thống nhất cho toàn bộ tệp phát hành `v0.3.0`. |

---

## 2. Yêu cầu trước khi cài (Pre-flight)

1. Kiểm tra cổng `443/tcp` (Control + Blind Relay), `3478/udp` (STUN) và cổng SSH đang chạy trên VPS:
   ```bash
   sudo ss -tulpn | grep -E ':(22|443|3478|8443|9091)\b'
   sudo ss -tlnp | grep sshd
   ```
2. Mở inbound firewall / Cloud Security Group của nhà cung cấp VPS:
   - **TCP `443`** (hoặc cổng tùy chọn nếu đổi, ví dụ `8443`).
   - **UDP `3478`** (hoặc cổng STUN tùy chọn).
   - **Không** mở ra ngoài cổng `9091/tcp` (endpoint `/healthz`, `/readyz`, `/metrics` mặc định chỉ bind `127.0.0.1:9091`).

---

## 3. Cài đặt bằng `systemd` (Khuyên dùng)

### Bước 1: Tải và kiểm tra SHA-256

```bash
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-linux-x86_64-musl.tar.gz
mkdir -p mesh-vpn && tar -xzf mesh-linux-x86_64-musl.tar.gz -C mesh-vpn
cd mesh-vpn
sha256sum -c SHA256SUMS
```

### Bước 2: Cài `mesh` CLI và chạy `install-server.sh`

```bash
sudo install -m 0755 ./mesh /usr/local/bin/mesh
sudo bash ./scripts/install-server.sh \
  --binary ./mesh-server \
  --public-host <IP_CONG_KHAI_HOAC_TEN_MIEN_VPS>
```

Các tùy chọn hay dùng của [`install-server.sh`](../../scripts/install-server.sh):
- `--tcp-port 8443` / `--stun-port 3479`: Dùng khi cổng `443` đã bị Nginx/Caddy chiếm.
- `--overlay-cidr 100.115.0.0/16`: Tùy chỉnh dải IP mạng riêng (`>= 64` host).
- `--enable-firewall` (hoặc `--enable-ufw`): Mở UFW tự động (tự phát hiện cổng SSH đang chạy, mở TCP/UDP đã chọn và giữ SSH an toàn).

> **Lưu ý tránh lỗi `Permission denied (os error 13)` trên cổng `443`:**
> Tuyệt đối không chạy trực tiếp `./mesh-server` bằng user thường trên cổng `< 1024`. Hãy luôn khởi chạy qua `systemd` (`mesh-server.service` chạy user `mesh` và được cấp riêng `CAP_NET_BIND_SERVICE`), hoặc chọn `--tcp-port 8443`.

### Bước 3: Cấp quyền quản trị cho tài khoản Linux hiện tại

Script cài đặt tạo nhóm `mesh-admin` để nói chuyện với `/run/mesh-server/admin.sock` (`0660 mesh:mesh-admin`):

```bash
sudo usermod -aG mesh-admin "$USER"
newgrp mesh-admin
```

### Những gì được cài lên VPS

- Nhị phân: `/usr/local/bin/mesh-server`, `/usr/local/bin/mesh`
- Dịch vụ `systemd`: `/etc/systemd/system/mesh-server.service`
- Cấu hình: `/etc/mesh/server.toml` (`0640 root:mesh`)
- Cơ sở dữ liệu `redb`: `/var/lib/mesh/` (`0700 mesh:mesh`)
- Socket quản trị cục bộ (UDS): `/run/mesh-server/admin.sock`
- Endpoint sức khỏe nội bộ: `http://127.0.0.1:9091/{healthz,readyz,metrics}`

---

## 4. Triển khai bằng Docker *(tùy chọn)*

Nếu muốn chạy `mesh-server` bằng container từ `mesh-server-image-linux-amd64.tar.gz`:

```bash
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-server-image-linux-amd64.tar.gz
docker load -i mesh-server-image-linux-amd64.tar.gz

docker volume create mesh-server-state
docker run -d \
  --name mesh-server \
  --restart unless-stopped \
  -p 443:443/tcp \
  -p 3478:3478/udp \
  -v mesh-server-state:/var/lib/mesh \
  -e MESH_PUBLIC_HOST=<IP_CONG_KHAI_HOAC_TEN_MIEN_VPS> \
  -e MESH_CONTROL_TCP_PORT=443 \
  -e MESH_STUN_UDP_PORT=3478 \
  mesh-server:release
```

*(Container chạy bằng `USER mesh`, hãy dùng named volume `mesh-server-state` để Docker tự giữ quyền ghi `/var/lib/mesh`.)*

---

## 5. Chạy sau Reverse Proxy Nginx / Caddy *(tùy chọn)*

Nếu VPS đang chạy sẵn web trên cổng `443`, sửa `/etc/mesh/server.toml` để `mesh-server` lắng nghe nội bộ `127.0.0.1:8443` với `tls_mode = "reverse_proxy"` và danh sách proxy tin cậy (bắt buộc không được rỗng):

```toml
control_bind_ip = "127.0.0.1"
control_tcp_port = 8443
stun_bind_ip = "0.0.0.0"
stun_udp_port = 3478
tls_mode = "reverse_proxy"
trusted_proxies = ["127.0.0.1"]
```

Tham khảo mẫu cấu hình tại [`deploy/reverse-proxy/Caddyfile.example`](../../deploy/reverse-proxy/Caddyfile.example) và [`deploy/reverse-proxy/nginx-mesh.conf.example`](../../deploy/reverse-proxy/nginx-mesh.conf.example), sau đó kiểm tra và khởi động lại:

```bash
sudo -u mesh /usr/local/bin/mesh-server --config /etc/mesh/server.toml --check-config
sudo systemctl restart mesh-server
```

---

## 6. Kiểm tra trạng thái & Cấp khóa cho các máy Client

```bash
# Xem SPKI Pin đang hoạt động và trạng thái server
mesh server status
mesh server hardening-check
curl -fsS http://127.0.0.1:9091/readyz
```

### Tạo khóa đăng ký (Pre-Auth Key) & mã QR / URI `mesh://join`

Mỗi khóa thô `mpk_*` chỉ được in ra **đúng 1 lần** (`SEC-01`). Dùng một trong các lệnh sau trên VPS:

```bash
# Cho thiết bị mới (xuất cả URI mesh://join lẫn mã QR để quét trên Mobile)
mesh preauthkey create --ttl 1h --name my-device --emit-uri --qr

# Khóa dùng được nhiều máy (ví dụ nạp nhanh cho cả nhóm tối đa 5 máy trong 2 giờ)
mesh preauthkey create --ttl 2h --reusable --max-uses 5 --emit-uri

# Cấp khóa xoay (rotate key) cho thiết bị đã tồn tại (giữ nguyên Overlay IP)
mesh preauthkey create --ttl 1h --for my-device --emit-uri --qr
```

---

## 7. Quản trị hàng ngày & Sao lưu / Nâng cấp

| Thao tác | Lệnh thực hiện |
| --- | --- |
| Liệt kê thiết bị trong mạng | `mesh node list` |
| Xem chi tiết một thiết bị | `mesh node inspect <NODE_NAME_OR_ID>` |
| Thu hồi khẩn cấp máy bị mất (`<= 2 s`) | `mesh node revoke <NODE_NAME_OR_ID>` |
| Xem nhật ký audit | `mesh audit list --limit 20` |
| Sao lưu nóng database `redb` | `mesh server backup` *(lưu tại `/var/lib/mesh/backups/`)* |
| Xem log dịch vụ `mesh-server` | `journalctl -u mesh-server -n 100 --no-pager` |

### Quy trình nâng cấp phiên bản an toàn

```bash
mesh server backup
sudo install -m 0755 ./mesh-server /usr/local/bin/mesh-server
sudo install -m 0755 ./mesh /usr/local/bin/mesh
sudo systemctl restart mesh-server
mesh server status
```
