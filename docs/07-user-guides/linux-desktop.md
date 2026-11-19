# Hướng Dẫn Cài Đặt & Sử Dụng trên Ubuntu / Debian / Linux Desktop (`v0.3.0`)

Tài liệu này hướng dẫn cài đặt và sử dụng **Mesh VPN Desktop GUI (`MeshVPN`)** cùng daemon `meshd` và CLI `mesh` trên máy tính Ubuntu, Debian và các distro Linux khác.

---

## 1. Tải gói cài đặt ở đâu?

Tải từ trang phát hành **[Mesh VPN v0.3.0](https://github.com/nguyenvando420-spec/mesh-vpn/releases/tag/v0.3.0)**:

| Hệ điều hành Linux | Tệp tải về | Thành phần bên trong |
| --- | --- | --- |
| **Ubuntu / Debian / Linux Mint / Pop!_OS (`amd64`)** | [`mesh-vpn-linux-amd64.deb`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-vpn-linux-amd64.deb) *(5.52 MiB)* | Gói cài đặt chuẩn Debian gồm `MeshVPN`, `mesh`, `meshd`, `mesh-server`, `meshd.service`, icon, shortcut `.desktop` và Polkit policy. |
| **Fedora / Arch / openSUSE / Distro khác (`x86_64`)** | [`mesh-linux-x86_64-musl.tar.gz`](https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-linux-x86_64-musl.tar.gz) *(9.44 MiB)* | Nhị phân tĩnh `musl` kèm script `install-linux.sh`. |

---

## 2. Cài đặt

### Cách A: Ubuntu / Debian (`.deb` — Khuyên dùng)

```bash
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-vpn-linux-amd64.deb
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS

sudo apt update
sudo apt install ./mesh-vpn-linux-amd64.deb
```

Sau khi cài đặt xong, hệ thống tự động:
1. Cài đặt `/usr/bin/MeshVPN`, `/usr/bin/mesh`, `/usr/bin/meshd`, `/usr/bin/mesh-server`.
2. Tạo nhóm `mesh-admin`, thư mục trạng thái `/var/lib/meshd` và bật chạy ngay dịch vụ nền `meshd.service`.
3. Đăng ký biểu tượng **Mesh VPN** vào Menu ứng dụng (`mesh-vpn.desktop`) và rule Polkit (`internal.mesh.pkexec.policy`).

*(Tùy chọn: chạy `sudo usermod -aG mesh-admin "$USER"` rồi đăng xuất/đăng nhập lại để chạy các thao tác quản trị mà ít phải nhập mật khẩu hơn.)*

### Cách B: Distro Linux không dùng `.deb` (`.tar.gz`)

```bash
curl -fLO https://github.com/nguyenvando420-spec/mesh-vpn/releases/download/v0.3.0/mesh-linux-x86_64-musl.tar.gz
mkdir -p mesh-vpn && tar -xzf mesh-linux-x86_64-musl.tar.gz -C mesh-vpn
cd mesh-vpn
sha256sum -c SHA256SUMS

sudo sh ./scripts/install-linux.sh --from . --sha256-file ./SHA256SUMS
```

---

## 3. Mở giao diện & Kết nối vào mạng Mesh

1. **Khởi động GUI:**
   - Tìm và mở **Mesh VPN** trong Menu ứng dụng của GNOME / KDE / XFCE, **hoặc**
   - Mở Terminal và chạy:
     ```bash
     mesh gui
     ```
2. **Đăng ký thiết bị (Onboarding):**
   - **Cách nhanh (Dán URI):** Dán chuỗi `mesh://join?v=1&ep=...&pin=sha256%3A...&key=mpk_...` được cấp từ VPS Server vào ô **Join URI** -> kiểm tra Endpoint & SPKI Pin -> bấm **Enroll & Connect**.
   - **Cách thủ công:** Điền địa chỉ Control Server (`<IP_HOAC_TEN_MIEN>:443`), chọn chế độ xác thực (`SPKI Pin` mặc định hoặc `System CA` cho tên miền hợp lệ) và dán khóa `mpk_*`.
3. Khi thực hiện thao tác thay đổi kết nối (kết nối, ngắt, xoay khóa, đặt lại danh tính), nếu user hiện tại chưa thuộc `mesh-admin`, hộp thoại **Polkit (`pkexec`)** sẽ hỏi mật khẩu quản trị Linux 1 lần để giao tiếp an toàn với `meshd`.

---

## 4. Các tính năng trên giao diện & CLI hỗ trợ

- **Theo dõi trạng thái:** Xem Overlay IP (`100.115.x.x`), trạng thái STUN/NAT, kết nối Relay/Direct và danh sách các máy peer ngay trong giao diện mà không cần quyền `root` (đọc qua `/var/run/meshd/meshd-ro.sock`).
- **Kiểm tra đường truyền:** Dùng tab **Peers / Diagnostics** hoặc chạy lệnh `mesh peers`, `mesh netcheck`, `mesh ping <peer>`.
- **Xoay khóa (Rotate Key):** Nhập khóa mới được server cấp theo `--for <ten-may>` để làm mới cặp khóa WireGuard mà giữ nguyên IP Mesh.
- **Đặt lại danh tính (Reset Identity):** Dùng nút trên giao diện (hoặc `mesh reset-identity --yes`) khi muốn chuyển sang mạng Mesh mới.
- **Xuất báo cáo lỗi:** Bấm **Export Bugreport** trên giao diện để lưu tệp `.tar` (đã loại bỏ toàn bộ secret).

---

## 5. Gỡ cài đặt

- **Nếu cài từ gói `.deb`:**
  - Gỡ phần mềm nhưng giữ lại danh tính node:
    ```bash
    sudo apt remove mesh-vpn
    ```
  - Gỡ sạch hoàn toàn cả khóa và nhật ký `/var/lib/meshd`:
    ```bash
    sudo apt purge mesh-vpn
    ```
- **Nếu cài từ `.tar.gz`:**
  ```bash
  sudo sh ./scripts/install-linux.sh --uninstall --purge
  ```
