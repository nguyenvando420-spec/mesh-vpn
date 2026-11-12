# API & Wire Protocol Contracts — Mesh VPN (Rust 1.94.1)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-architect` |
| Ngày | 2026-11-12 |
| Phiên bản | **2.0** — Khóa cứng 100% Hợp đồng Giao tiếp (REST, WebSocket, Binary Relay, STUN/Disco/WG UDP, Local IPC, Observability) |
| Trạng thái | **Proposed-for-Gate-2** |
| Thành phần AI | **Không có** (Không có JSON Schema đầu ra AI) |
| Đầu vào | [production-readiness-requirements.md](../01-discovery/production-readiness-requirements.md) (v1.2) · [product-backlog.md](../02-product-planning/product-backlog.md) (v1.2) · [tech-stack-decision.md](./tech-stack-decision.md) (v2.0) · [architecture-decision-record.md](./architecture-decision-record.md) (v2.0 `ADR-002..010`) · [coding-standards.md](./coding-standards.md) (v2.0) |
| Crate thực thi | `crates/mesh-proto` (DTOs & parsers), `crates/mesh-datapath`, `crates/mesh-server`, `crates/meshd`, `crates/mesh` |

> **Quy tắc Hợp đồng Bất biến**:
> 1. Mọi endpoint HTTP/WebSocket dùng tiền tố **`/v1/`** (`coding-standards.md` §2.1).
> 2. Mọi trường JSON dùng **`snake_case`**, mọi trường thời gian kết thúc bằng **`_at_ms`** (`u64` Unix epoch milliseconds UTC), gắn `#[serde(deny_unknown_fields)]` ở đầu vào.
> 3. **Không một DTO mạng nào có trường chứa khóa riêng (`private_key`)** (`SEC-01(a)`).
> 4. Giới hạn kích thước body HTTP tối đa **`MAX_HTTP_BODY_BYTES = 65_536` (64 KiB)**; giới hạn khung nhị phân WebSocket/UDP tối đa **`MAX_FRAME_SIZE = 2048` bytes**.

---

## 1. Control Public HTTPS & WebSocket API (Trên Cổng TCP Cấu Hình Được, Mặc Định `443`)

Toàn bộ các endpoint trong mục này chạy trên cổng TCP công khai do người dùng cấu hình (mặc định `DEFAULT_CONTROL_TCP_PORT = 443` trong `mesh_core::defaults`, đổi được sang bất kỳ cổng nào như `8443` theo `GNFR-11`, `US-074`), hỗ trợ cả 3 chế độ TLS (`ADR-008`):
- **Chế độ (c) IP + SPKI Pinning (Mặc định hạng nhất — `SEC-04(c)`, `US-003`, `US-047`)**: Client kiểm chứng mã băm `sha256:<64_hex>` của `subjectPublicKeyInfo` DER bằng `SpkiPinVerifier` (`ConstantTimeEq`), **cấm TOFU**.
- **Chế độ (a) Standalone Domain ACME (`instant-acme`)**: `TLS-ALPN-01` khi cổng = `443`, `DNS-01` khi cổng ≠ `443`.
- **Chế độ (b) Sau Reverse Proxy sẵn có (`Nginx`/`Caddy`)**: đi kèm `trusted_proxies` bật tường minh (`US-042 AC6`).

### 1.1. Quy tắc Kiểm chứng Đầu vào Chung (Validation Rules — `US-004 AC3`, `US-038 AC5`)

| Kiểu Miền (`mesh-core`) | Quy tắc Kiểm chứng Bắt buộc tại Biên |
|---|---|
| `NodeName` | Độ dài `1..=63` ký tự ASCII; chỉ gồm `[a-z0-9-]`; không bắt đầu hoặc kết thúc bằng `'-'`; cấm tuyệt đối `\n`, `\r`, `#`, khoảng trắng; **từ chối danh sách tên cấm**: `localhost`, `broadcasthost`, `wpad`, `isatap`, `local`, và chính `public_host`/domain của Control/Relay/STUN. |
| `PublicKey` | Chuỗi Base64 chuẩn (44 ký tự) hoặc Hex (64 ký tự) giải mã ra đúng `[u8; 32]`, không phải điểm bậc thấp (low-order point) trên Curve25519. |
| `SpkiPin` | Định dạng `"sha256:<64_hex_lowercase>"` giải mã ra đúng `[u8; 32]`. |
| `CandidateEndpoint` | `SocketAddr` hợp lệ; **từ chối** địa chỉ thuộc `overlay_cidr`, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, broadcast, unspecified (`0.0.0.0`, `::`), và địa chỉ IP public của chính VPS (`US-020 AC2/AC4`, `US-038 AC5`). |

---

### 1.2. `POST /v1/auth/challenge` — Khởi Tạo Phiên & Nhận Thách Đố Mật Mã (`US-003`, `ADR-003`)

- **Ánh xạ User Story**: `US-003 AC1/AC4/AC5`, `US-050 AC1/AC2`.
- **Xác thực**: Chưa cần token (nhưng phải qua kênh TLS đã xác minh SPKI Pin hoặc CA; chịu giới hạn tốc độ theo IP nguồn `US-042`).
- **Mục đích**: Client gửi khóa công khai và thông tin phiên bản; Server kiểm tra `protocol_version` tối thiểu (`US-050 AC2`) và sinh cặp khóa X25519 tạm thời (`server_eph_pubkey`) kèm `challenge_nonce` ngẫu nhiên 32 byte có TTL **30 giây** (dùng 1 lần).

#### Request JSON (`ChallengeRequest`)
```json
{
  "node_pubkey": "bWVzaC1ub2RlLXB1YmtleS0zMi1ieXRlcy1iYXNlNjQ=",
  "disco_pubkey": "bWVzaC1kaXNjby1wdWJrZXktMzItYnl0ZXMtYmFzZTY0",
  "protocol_version": 1,
  "agent_version": "0.1.0",
  "os": "darwin",
  "arch": "arm64"
}
```
*(Giá trị `os` ∈ `{"darwin", "windows", "linux"}`; `arch` ∈ `{"arm64", "amd64"}` theo `OPS-10` / `US-050 AC1`).*

#### Response JSON (`200 OK` — `ChallengeResponse`)
```json
{
  "session_id": "019321c0-1122-7333-8444-5566778899aa",
  "server_eph_pubkey": "c2VydmVyLWVwaGVtZXJhbC14MjU1MTktcHVia2V5LTI=",
  "challenge_nonce": "Y2hhbGxlbmdlLW5vbmNlLTMyLWJ5dGVzLWZyb20tb3Nybmc=",
  "server_time_at_ms": 1762958151000,
  "expires_at_ms": 1762958181000
}
```

#### Cấu trúc `ProofPayload` được Client niêm phong bằng `crypto_box::SalsaBox` (`ADR-003`)
Client tạo mảng byte JSON của cấu trúc dưới đây rồi gọi `SalsaBox::new(&server_eph_pubkey, node_secret.expose_secret()).encrypt(&box_nonce, payload_bytes)`:
```json
{
  "session_id": "019321c0-1122-7333-8444-5566778899aa",
  "challenge_nonce": "Y2hhbGxlbmdlLW5vbmNlLTMyLWJ5dGVzLWZyb20tb3Nybmc=",
  "node_pubkey": "bWVzaC1ub2RlLXB1YmtleS0zMi1ieXRlcy1iYXNlNjQ=",
  "disco_pubkey": "bWVzaC1kaXNjby1wdWJrZXktMzItYnl0ZXMtYmFzZTY0",
  "tls_exporter_binding": "dGxzLTEuMy1leHBvcnRlci0zMi1ieXRlcy1iaW5kaW5n"
}
```
> **Ghi chú `tls_exporter_binding`**: Lấy 32 byte từ `rustls::Connection::export_keying_material(..., b"EXPORTER-mesh-control-v1", None)`. Nếu kết nối đi qua Reverse Proxy (`trusted_proxies` bật), server chấp nhận giá trị binding của kết nối TLS hoặc cờ `"reverse_proxy_mode"`. Nhờ dùng `challenge_nonce` ngẫu nhiên của server, bước chứng minh khóa **không phụ thuộc đồng hồ hệ thống của client** (chống lỗi lệch giờ dual-boot Windows/Linux theo `US-003 AC5`).

---

### 1.3. `POST /v1/nodes/register` — Đăng Ký Thiết Bị Idempotent / Re-auth / Xoay Khóa (`US-004`, `US-005`, `US-031`, `US-032`)

- **Ánh xạ User Story**: `US-004 AC1..AC7`, `US-005 AC1..AC4`, `US-006`, `US-031 AC5/AC6`, `US-032 AC1..AC3`.
- **Idempotency**: Khóa Idempotency tự nhiên là `node_pubkey` (đã được chứng minh sở hữu qua `proof_ciphertext`). Gửi lại cùng `node_pubkey` + cùng `preauth_key` trả về `200 OK` với đúng `NodeId` và `OverlayIp` đã cấp, không tiêu hao thêm lượt dùng key (`US-005 AC1`).

#### Request JSON (`RegisterNodeRequest`)
```json
{
  "session_id": "019321c0-1122-7333-8444-5566778899aa",
  "node_pubkey": "bWVzaC1ub2RlLXB1YmtleS0zMi1ieXRlcy1iYXNlNjQ=",
  "disco_pubkey": "bWVzaC1kaXNjby1wdWJrZXktMzItYnl0ZXMtYmFzZTY0",
  "box_nonce": "MjQtYnl0ZXMtbm9uY2UtZm9yLW5hY2xib3g=",
  "proof_ciphertext": "c2Fsc2Fib3gtY2lwaGVydGV4dC1wcm92aW5nLW5vZGUta2V5",
  "preauth_key": "mpk_7q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0z1x2c3v4b5n6m",
  "node_name": "macbook-pro",
  "previous_node_pubkey": null
}
```
*(Khi xoay khóa `US-032` hoặc đăng ký lại sau khi hết hạn khóa `US-031 AC5` bằng pre-auth key đã được admin trói `--for <node>`, client sinh cặp khóa mới, truyền `previous_node_pubkey` để server thu hồi khóa cũ tức thì trong cùng giao dịch ACID).*

#### Response JSON (`200 OK` — `RegisterNodeResponse`)
```json
{
  "node_id": "019321b4-7c8a-7000-8000-010203040506",
  "node_name": "macbook-pro",
  "fqdn": "macbook-pro.mesh.internal",
  "overlay_ip": "100.115.0.2",
  "overlay_cidr": "100.115.0.0/16",
  "key_expires_at_ms": 1778510151000,
  "netmap": {
    "netmap_version": 12,
    "generated_at_ms": 1762958151000,
    "overlay_cidr": "100.115.0.0/16",
    "domain_suffix": "mesh.internal",
    "relay_map": {
      "endpoint_version": 1,
      "control_tcp_endpoint": "203.0.113.10:443",
      "relay_tcp_endpoint": "203.0.113.10:443",
      "stun_udp_endpoints": ["203.0.113.10:3478"]
    },
    "pin_set": {
      "active_pin": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "next_pin": null
    },
    "peers": [
      {
        "node_id": "019321b0-0000-7000-8000-000000000001",
        "name": "vps",
        "fqdn": "vps.mesh.internal",
        "overlay_ip": "100.115.0.1",
        "node_pubkey": "dnBzLW5vZGUtcHVibGljLWtleS0zMi1ieXRlcy1iNjQ=",
        "disco_pubkey": "dnBzLWRpc2NvLXB1YmxpYy1rZXktMzItYnl0ZXMtYjY0",
        "endpoints": [
          {
            "addr": "203.0.113.10:51820",
            "source": "reflexive"
          }
        ],
        "relay_home": "203.0.113.10:443",
        "key_expires_at_ms": null,
        "online": true
      }
    ]
  }
}
```

---

### 1.4. Header Xác Thực Phiên Cho Node Đã Đăng Ký (`X-Mesh-Auth-*`)

Sau khi đã đăng ký, đối với các endpoint cập nhật trạng thái (`POST /v1/endpoints`, `POST /v1/disco/call-me-maybe`) và khi nâng cấp WebSocket (`GET /v1/netmap/stream`, `GET /v1/relay`), client lấy `session_id` từ `POST /v1/auth/challenge` và đính kèm 3 header chứng minh sở hữu `node_pubkey` (không bao giờ dùng bearer token tĩnh):
- `X-Mesh-Session-Id: <uuid>`
- `X-Mesh-Box-Nonce: <base64_24_bytes>`
- `X-Mesh-Auth-Proof: <base64_salsabox_ciphertext>`

---

### 1.5. `POST /v1/endpoints` — Công Bố Candidate Endpoints & Xác Nhận Đổi Cổng (`US-019`, `US-020`, `US-074`)

- **Ánh xạ User Story**: `US-019 AC1/AC2`, `US-020 AC1..AC4`, `US-074 AC1/AC7`.
- **Hành vi**: Cập nhật danh sách địa chỉ ứng viên (`lan`, `ipv6`, `reflexive`), loại NAT quan sát được, và phiên bản cấu hình server (`acked_endpoint_version`) mà agent vừa áp dụng thành công. Chỉ khi danh sách `endpoints` thực sự thay đổi so với bản đang lưu thì server mới tăng `netmap_version` và đẩy bản cập nhật cho các peer.

#### Request JSON (`UpdateEndpointsRequest`)
```json
{
  "endpoints": [
    {
      "addr": "192.168.1.45:51829",
      "source": "lan"
    },
    {
      "addr": "[2001:db8::abcd]:51829",
      "source": "ipv6"
    },
    {
      "addr": "198.51.100.77:51829",
      "source": "reflexive"
    }
  ],
  "nat_type": "eim_or_adm",
  "acked_endpoint_version": 2
}
```

#### Response JSON (`200 OK`)
```json
{
  "netmap_version": 13,
  "updated_at_ms": 1762958160000
}
```

---

### 1.6. `POST /v1/disco/call-me-maybe` — Tín Hiệu Khởi Động Đục Lỗ NAT Đồng Thời (`US-021`)

- **Ánh xạ User Story**: `US-021 AC1/AC5`.
- **Hành vi**: Khi Node A muốn bắt đầu đục lỗ NAT tới Node B, A gửi kèm một hộp mật mã `disco_ciphertext` (được niêm phong bằng `SalsaBox(A_disco_secret, B_disco_pubkey)` chứa `tx_id`, `sent_at_ms` và danh sách `endpoints[]` mới nhất của A). Server kiểm tra A và B đều đang `Active` rồi chuyển tiếp tức thì qua WebSocket `/v1/netmap/stream` cho B.

#### Request JSON (`CallMeMaybeRequest`)
```json
{
  "dst_node_id": "019321b4-9999-7000-8000-010203040507",
  "box_nonce": "MjQtYnl0ZXMtbm9uY2UtZm9yLWRpc2NvLWJveA==",
  "disco_ciphertext": "c2Fsc2Fib3gtZW5jcnlwdGVkLWNhbGwtbWUtbWF5YmUtcGF5bG9hZA=="
}
```

---

### 1.7. `GET /v1/netmap/stream?known_version=<u64>` — Luồng Đồng Bộ Netmap Thời Gian Thực (`US-009`, `US-029`, `US-031`, `US-074`)

- **Ánh xạ User Story**: `US-009 AC1..AC6`, `US-029 AC1..AC3`, `US-031 AC1`, `US-034 AC5`, `US-074 AC1/AC2`.
- **Giao thức**: HTTP/1.1 `Upgrade: websocket` (khung JSON Text/Binary ≤ 64 KiB).
- **Quy tắc chống bão lưu lượng nền (`US-009 AC1`, `GNFR-07`)**:
  - Server gửi khung `heartbeat` nhẹ mỗi **25 giây** để giữ kết nối qua NAT/Reverse Proxy; nếu quá **60 giây** không có khung nào, client đóng và kết nối lại (`US-009 AC4`).
  - Server **TUYỆT ĐỐI KHÔNG** tăng `netmap_version` hay đẩy lại `NetmapSnapshot` cho các nhịp heartbeat `last_seen`.

#### Các Loại Bản Tin Từ Server $\to$ Client (`ControlStreamServerEvent`)

```json
{
  "event_type": "netmap_snapshot",
  "sent_at_ms": 1762958170000,
  "netmap": {
    "netmap_version": 14,
    "generated_at_ms": 1762958170000,
    "overlay_cidr": "100.115.0.0/16",
    "domain_suffix": "mesh.internal",
    "relay_map": {
      "endpoint_version": 2,
      "control_tcp_endpoint": "203.0.113.10:8443",
      "relay_tcp_endpoint": "203.0.113.10:8443",
      "stun_udp_endpoints": ["203.0.113.10:3479"]
    },
    "pin_set": {
      "active_pin": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "next_pin": null
    },
    "peers": []
  }
}
```

- **Sự kiện chuyển tiếp đục lỗ NAT (`call_me_maybe`)**:
```json
{
  "event_type": "call_me_maybe",
  "src_node_id": "019321b4-7c8a-7000-8000-010203040506",
  "src_disco_pubkey": "bWVzaC1kaXNjby1wdWJrZXktMzItYnl0ZXMtYmFzZTY0",
  "box_nonce": "MjQtYnl0ZXMtbm9uY2UtZm9yLWRpc2NvLWJveA==",
  "disco_ciphertext": "c2Fsc2Fib3gtZW5jcnlwdGVkLWNhbGwtbWUtbWF5YmUtcGF5bG9hZA==",
  "sent_at_ms": 1762958172000
}
```

- **Sự kiện Chấm dứt Danh tính Tức thì (`identity_terminated` — `US-029 AC3`, `US-031 AC1`, `US-034 AC5`)**:
  Khi và chỉ khi nhận được bản tin này trên **kênh TLS đã xác thực Pin/CA hợp lệ**, `meshd` lập tức gỡ đường hầm, đóng Relay và **dừng tự động retry**:
```json
{
  "event_type": "identity_terminated",
  "error_kind": "node_revoked",
  "public_msg": "node has been revoked by administrator",
  "occurred_at_ms": 1762958180000
}
```
*(Hoặc `"error_kind": "node_key_expired"`).*

---

## 2. Blind Relay Wire Protocol (`GET /v1/relay` WebSocket Binary Frames — `ADR-004`, `US-024`, `US-025`, `US-027`)

- **Ánh xạ User Story**: `US-024 AC1..AC8`, `US-025 AC1..AC6`, `US-026 AC1..AC4`, `US-027 AC1..AC5`.
- **Bước chứng minh khóa trước khi nâng cấp (`US-024 AC1/AC2`, `US-027 AC1`)**:
  - Yêu cầu `GET /v1/relay` (`Upgrade: websocket`) bắt buộc đính kèm `X-Mesh-Session-Id`, `X-Mesh-Box-Nonce`, `X-Mesh-Auth-Proof` đã xác thực sở hữu `node_pubkey` thuộc Netmap hiện hành và chưa bị thu hồi/hết hạn. Nếu sai hoặc chưa đăng ký, server trả HTTP `401`/`403` ngay từ bước HTTP handshake, **không mở phiên WebSocket và không chuyển tiếp bất kỳ byte nào**.
  - Nếu cùng một `NodeId` mở kết nối Relay mới hợp lệ, kết nối Relay cũ của `NodeId` đó bị đóng ngay lập tức (đảm bảo tối đa 1 phiên Relay hoạt động/node — `US-024 AC5`).
- **Giới hạn kích thước Frame (`US-025 AC3`)**:
  - `tokio-tungstenite` cấu hình cứng `max_frame_size = Some(2048)` và `max_message_size = Some(2048)`. Với MTU đường hầm `1280` bytes + overhead WireGuard tối đa `80` bytes + header Relay `33` bytes = `1393` bytes (< `2048` bytes, thỏa mãn `US-017 AC3`).

### 2.1. Định Dạng Byte-Level Của Từng Loại Binary Frame Trên `/v1/relay`

```text
+------------------+------------------------------------------------------------+
| Byte 0           | Bytes 1..N                                                 |
| frame_type (u8)  | Payload theo từng loại frame                               |
+------------------+------------------------------------------------------------+
```

| `frame_type` | Tên Frame | Chiều | Cấu trúc Byte Chính Xác | Quy tắc Xử lý trên Relay & Agent |
|---:|---|---|---|---|
| **`0x01`** | `ClientToPeerPacket` | Client $A \to$ Relay | `[0x01: 1B][dst_pubkey: 32B][ciphertext: 1..=1480B]`<br/>*(Tổng độ dài: `34..=1513` bytes)* | Relay kiểm tra Token Bucket của $A$ (mặc định **20 Mbps**, `US-027 AC2`). Tra phiên của `dst_pubkey` ($B$). Nếu $B$ không online hoặc không thuộc Netmap $\to$ **drop im lặng** + tăng metric (`US-025 AC2`). Nếu $B$ online $\to$ tạo frame `0x02` với **`src_pubkey = pubkey_đã_xác_thực_của_A`** và gọi **`tx_b.try_send(frame)`** trên kênh `mpsc::channel(256)` của $B$ (`US-025 AC1/AC6`). |
| **`0x02`** | `RelayToClientPacket` | Relay $\to$ Client $B$ | `[0x02: 1B][src_pubkey: 32B (do Relay chứng thực)][ciphertext: 1..=1480B]`<br/>*(Tổng độ dài: `34..=1513` bytes)* | Agent $B$ kiểm tra `src_pubkey` có thuộc `PeerMap` trong Netmap hiện hành không (`US-026 AC2`); nếu hợp lệ thì chuyển `ciphertext` vào `DiscoEngine` (nếu bắt đầu bằng `b"MESHDS"`) hoặc `Tunn::decapsulate`. |
| **`0x03`** | `RelayKeepAlive` | Hai chiều | `[0x03: 1B][sent_at_ms: u64 big-endian (8B)]`<br/>*(Tổng độ dài: đúng `9` bytes)* | Gửi mỗi **25 giây** khi kết nối Relay rảnh để giữ NAT/Reverse Proxy không ngắt (`US-024 AC4`). |
| **`0x04`** | `RelayControlNotice` | Relay $\to$ Client | `[0x04: 1B][notice_code: 1B][reserved: 6B]`<br/>`notice_code`: `0x01` = `Throttled`, `0x02` = `NodeRevoked`, `0x03` = `NodeKeyExpired`, `0x04` = `ServerMigratingPort` | Thông báo trạng thái điều tiết băng thông (`US-027 AC4`) hoặc lý do đóng phiên. |

---

## 3. Shared UDP Wire Protocol (`MagicSocket` — Data Plane + STUN + Authenticated Disco)

Trên mỗi thiết bị chạy `meshd`, `MagicSocket` mở duy nhất **1 `tokio::net::UdpSocket`** (ưu tiên bind lại cổng `local_udp_port` đã lưu bền trong `netmap-cache.json` theo `US-019 AC1`; tắt cờ ép cứng `DF=1` ở tầng UDP ngoài theo `US-017 AC3`).

### 3.1. Bảng Phân Loại Gói Tin Đến Không Mơ Hồ (Zero-Allocation Demultiplexing Table)

Khi `MagicSocket::recv_from(&mut buf[0..2048])` nhận được một gói UDP có độ dài `len`:

| Thứ tự kiểm tra | Giao thức | Điều kiện Byte Đầu Tiên Chính Xác (Không thể trùng lặp) | Lý do Không Giao Nhau Toán Học |
|---:|---|---|---|
| **1** | **Authenticated Disco** (`US-021`) | `len >= 62 && buf.get(0..6) == Some(b"MESHDS")` (`[0x4D, 0x45, 0x53, 0x48, 0x44, 0x53]`) | Byte `0` = `0x4D` (`'M'`, có 2 bit đầu `01` $\neq 00$ của STUN và `0x4D` $\notin 1..=4$ của WireGuard). |
| **2** | **STUN RFC 5389 / 8489** (`US-019`) | `len >= 20 && (buf[0] & 0b1100_0000) == 0 && (buf[1] & 0b0000_0011) == 0 && buf.get(4..8) == Some(&[0x21, 0x12, 0xA4, 0x42])` | Gói STUN luôn có 2 bit đầu bằng `00`, `msg_type` (`0x0001` Request / `0x0101` Response) và 4 byte Magic Cookie cố định `0x2112A442` ở vị trí `4..8`. |
| **3** | **WireGuard (`defguard_boringtun`)** (`US-014..017`) | `len >= 32 && matches!(buf[0], 1..=4) && buf.get(1..4) == Some(&[0x00, 0x00, 0x00])` | WireGuard chỉ có 4 loại gói (`1` = Handshake Init 148B, `2` = Handshake Resp 92B, `3` = Cookie Reply 64B, `4` = Transport Data ≥ 32B) và 3 byte reserved `1..4` luôn bằng `[0, 0, 0]`. |
| **4** | **Gói Lạ / Nhiễu Internet** | Mọi gói không thỏa 3 điều kiện trên | **Drop im lặng ngay lập tức** (0 cấp phát heap, 0 panic, 0 phản hồi để chống khuếch đại UDP — `US-021 AC3/AC5`). |

---

### 3.2. Layout Byte-Level Của Gói STUN Binding (`crates/mesh-proto::stun` — RFC 5389)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie (0x2112A442)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits / 12 bytes)       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attributes: XOR-MAPPED-ADDRESS (0x0020) + FINGERPRINT (0x8028)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **STUN Binding Request (`0x0001`)**: độ dài `28` bytes (Header `20` bytes + Attribute `FINGERPRINT` `8` bytes: `CRC32(bytes) ^ 0x5354554e`).
- **STUN Binding Response (`0x0101`)**: độ dài `40` bytes (IPv4) hoặc `52` bytes (IPv6), gồm `XOR-MAPPED-ADDRESS` (`0x0020`, cổng XOR với `0x2112`, IP XOR với `0x2112A442` + `tx_id`) và `FINGERPRINT` (`0x8028`). Phản hồi luôn nhỏ hơn hoặc bằng giới hạn an toàn, giới hạn tốc độ **100 pkt/s/IP** trên VPS để chống khuếch đại UDP (`US-019 AC4`).

---

### 3.3. Layout Byte-Level Của Gói Authenticated Disco (`crates/mesh-proto::disco` — `US-021`)

Mọi gói Disco đi trên UDP (`MagicSocket`) hoặc đi qua Blind Relay đều có cùng định dạng nhị phân đã xác thực mật mã bằng `crypto_box::SalsaBox(sender_disco_secret, recipient_disco_pubkey)`:

```text
+-------------------+--------------+-------------------------+-------------------+------------------------------+
| Bytes 0..6 (6B)   | Byte 6 (1B)  | Bytes 7..39 (32B)       | Bytes 39..63 (24B)| Bytes 63..N (>= 37B)         |
| Magic: b"MESHDS"  | Version=0x01 | sender_disco_pubkey     | box_nonce (OsRng) | SalsaBox Ciphertext + Poly1305|
+-------------------+--------------+-------------------------+-------------------+------------------------------+
```

#### Cấu trúc Plaintext Bên Trong `SalsaBox Ciphertext` (Sau khi giải mã & xác thực Poly1305 MAC 16-byte)

```text
+-------------------+------------------------+--------------------------+---------------------------------------+
| Byte 0 (1B)       | Bytes 1..13 (12B)      | Bytes 13..21 (8B BE)     | Bytes 21..M                           |
| msg_type (u8)     | tx_id ([u8; 12] OsRng) | sent_at_ms (u64 UTC)     | Body theo msg_type                    |
+-------------------+------------------------+--------------------------+---------------------------------------+
```

| `msg_type` | Tên Bản Tin | Nội dung `Body` (Bytes `21..M`) | Quy tắc Chống Phát Lại & Chống Đầu Độc Đường Đi (`US-021 AC2/AC5`) |
|---:|---|---|---|
| **`0x01`** | `DiscoPing` | `[protocol_version: u16 BE (2B)][padding: 0B]` | Bên nhận chỉ giải mã nếu `sender_disco_pubkey` thuộc một peer `Active` trong Netmap hiện hành. Nếu giải mã thành công, phản hồi `DiscoPong` mang **đúng `tx_id` vừa nhận** kèm `observed_addr` (IP:port nguồn thực tế mà socket nhận được). |
| **`0x02`** | `DiscoPong` | `[addr_family: 1B (0x04=IPv4, 0x06=IPv6)][observed_port: u16 BE][observed_ip: 4B hoặc 16B]` | Bên nhận tra `tx_id` trong bảng `pending_pings` (TTL **10 giây**, xóa ngay sau khi khớp 1 lần). **Nếu `tx_id` không tồn tại trong `pending_pings`, đã quá 10 s, hoặc sai `sender_disco_pubkey` $\to$ BỎ QUA IM LẶNG 100%**, tuyệt đối không cập nhật endpoint của peer (triệt tiêu hoàn toàn tấn công Endpoint Poisoning giả `RTT = 1 ms` trên Wi-Fi công cộng!). |
| **`0x03`** | `DiscoCallMeMaybe` | `[endpoint_count: u8 (<= 16)]` theo sau bởi danh sách `[family: 1B][port: u16 BE][ip: 4B/16B]` | Nhận qua Control/Relay; kích hoạt bắn `DiscoPing` đồng thời tới các `endpoints` hợp lệ của peer (có giới hạn tốc độ ≤ 10 đợt/phút/peer). |

---

## 4. Server Local Admin IPC API (`SEC-14`, `ADR-006`, `US-012`)

- **Kênh truyền tải duy nhất**: HTTP/1.1 JSON qua **Unix Domain Socket `/run/mesh/admin.sock`** (quyền thư mục `/run/mesh` là `0750 mesh:mesh-admin`, quyền socket `0660`).
- **Kiểm chứng đặc quyền OS bắt buộc**: Middleware đầu tiên của `admin_service.rs` đọc `UnixStream::peer_cred()` (`SO_PEERCRED` trên Linux) lấy `(uid, gid, pid)`. Chỉ cho phép `uid == 0` (`root`), `uid == mesh_uid`, hoặc `gid == mesh_admin_gid`; mọi tiến trình khác (vd. `www-data`, container, user thường) bị từ chối ngay với `403 Forbidden` (`ErrorKind::PermissionDenied`) và ghi vào `audit_events` (`SEC-14(1)`).
- **Tuyệt đối cấm** gắn router này vào bất kỳ TCP listener nào (`127.0.0.1`, IP overlay hay IP public).

### 4.1. Bảng Toàn Bộ Các Endpoint Quản Trị Trên `/run/mesh/admin.sock`

| Method & Path | Ánh xạ `US-xxx` | Lệnh CLI `mesh` Tương Ứng | Mô tả Hành vi & Ghi Audit |
|---|---|---|---|
| `POST /v1/admin/preauth-keys` | `US-002`, `US-006`, `US-031` | `mesh preauthkey create [--ttl 1h] [--reusable --max-uses N] [--ephemeral] [--for <node>]` | Sinh key 256-bit từ `OsRng`, chỉ lưu `sha256` vào `redb`, trả `raw_key` **đúng 1 lần** kèm chuỗi `join_command` đầy đủ (`IP:port` + `active_pin`). Ghi audit `preauthkey_created`. |
| `GET /v1/admin/preauth-keys` | `US-002 AC2` | `mesh preauthkey list` | Liệt kê danh sách metadata của các key (`key_id`, `status`, `expires_at_ms`, `target_node_id`, `used_count`/`max_uses`); **không bao giờ trả key rõ**. |
| `POST /v1/admin/preauth-keys/{key_id}/revoke` | `US-002 AC4`, `US-013 AC4` | `mesh preauthkey revoke <key_id>` | Đưa `key_id` vào `RevokedSet` RAM ngay lập tức (< 100 ms) rồi cập nhật `redb` + ghi audit `preauthkey_revoked` (vẫn có hiệu lực trong RAM kể cả khi đĩa đầy `ENOSPC`). |
| `GET /v1/admin/nodes` | `US-012 AC1`, `US-050 AC1` | `mesh node list` | Liệt kê toàn bộ node kèm `overlay_ip`, `status`, `online`, `last_seen_at_ms`, `key_expires_at_ms`, `os`/`arch`, `agent_version` (≤ 1 s). |
| `GET /v1/admin/nodes/{node_ref}` | `US-012 AC1` | `mesh node inspect <id\|name>` | Xem chi tiết 1 node theo `NodeId` hoặc `name_normalized`. |
| `POST /v1/admin/nodes/{node_ref}/rename` | `US-012 AC2` | `mesh node rename <id\|name> <new_name>` | Kiểm tra `NodeName` hợp lệ + không thuộc danh sách cấm/trùng lặp (`US-004 AC3`), cập nhật `idx_nodes_name`, tăng `netmap_version`, đẩy Netmap mới (P95 ≤ 5 s) và ghi audit `node_renamed`. |
| `POST /v1/admin/nodes/{node_ref}/revoke` | `US-029`, `US-013 AC4` | `mesh node revoke <id\|name>` | **Khẩn cấp**: Đưa vào `RevokedSet` RAM + ngắt Relay/Control (< 100 ms) + đẩy Netmap xóa peer tới toàn mạng + cách ly IP 24h (`US-029 AC5`) + ghi audit `node_revoked` (fallback `stderr`/`journald` nếu đầy đĩa). |
| `POST /v1/admin/nodes/{node_ref}/expire` | `US-012 AC3`, `US-031 AC1/AC2` | `mesh node expire <id\|name> [--never]` | Hết hạn khóa node ngay lập tức (buộc đăng ký lại bằng key `--for <node>`) hoặc đặt `key_expires_at_ms = None` (`--never` cho server tin cậy); ghi audit `node_expiry_updated`. |
| `GET /v1/admin/server/status` | `US-012 AC6`, `US-074 AC7` | `mesh server status` (hoặc `mesh server info`) | Trả về cổng TCP/UDP hiện hành, `tls_mode`, `active_pin`, `next_pin`, hạn chứng chỉ TLS, trạng thái `ListenerSet` và **danh sách các node chưa xác nhận `endpoint_version` mới** khi đang chuyển tiếp cổng. |
| `POST /v1/admin/server/backup` | `US-045 AC1` | `mesh server backup` | Thực thi Hot Atomic Snapshot Backup ngay lập tức (kèm `server_identity` và `.sha256`, giữ 7 bản); ghi audit `server_backup_created`. |
| `POST /v1/admin/server/migrate-endpoint` | `US-074 AC1..AC8`, `SEC-15` | `mesh server migrate-endpoint [--host ...] [--tcp-port ...] [--stun-port ...] [--tls-mode ...] [--extend-window 24h]` | Kiểm tra cổng mới không bị chiếm (`US-046 AC5`), mở `ListenerSet` nghe song song cổng cũ + mới trong `transition_window`, tăng `endpoint_version` & `netmap_version`, đẩy `relay_map` mới qua kênh đã xác thực; ghi audit `server_endpoint_migrated`. |
| `POST /v1/admin/server/rotate-tls-key` | `US-047 AC5` | `mesh server rotate-tls-key --stage \| --promote` | `--stage`: sinh khóa ECDSA P-256 kế tiếp, công bố `next_pin` trong `PinSet` qua Netmap trước; `--promote`: chuyển `next_pin` thành `active_pin` mà không làm rớt bất kỳ client online nào. |
| `GET /v1/admin/audit-events` | `US-013 AC1/AC2` | `mesh audit list [--limit 100]` | Đọc danh sách bản ghi từ bảng append-only `audit_events`. |

#### Mẫu DTO `POST /v1/admin/preauth-keys` (`US-002 AC1/AC6`)
Request:
```json
{
  "ttl_secs": 3600,
  "reusable": false,
  "max_uses": 1,
  "is_ephemeral": false,
  "ephemeral_timeout_secs": null,
  "target_node": null
}
```
Response (`201 Created`):
```json
{
  "key_id": "019321d0-aaaa-7bbb-8ccc-ddddeeeeffff",
  "raw_key": "mpk_7q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0z1x2c3v4b5n6m",
  "created_at_ms": 1762958151000,
  "expires_at_ms": 1762961751000,
  "reusable": false,
  "max_uses": 1,
  "target_node_id": null,
  "server_endpoint": "203.0.113.10:443",
  "active_pin": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "join_command_file": "mesh up --server 203.0.113.10:443 --server-pin sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --authkey-file ./preauth.key --name <device-name>",
  "join_command_stdin": "mesh up --server 203.0.113.10:443 --server-pin sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --authkey-stdin --name <device-name>"
}
```

---

## 5. Client Local CLI ↔ Daemon IPC API (`ADR-006`, `PLAT-01`, `PLAT-06`, `US-039..041`, `US-052`, `US-073`, `US-074`)

### 5.1. Cơ Chế Phân Quyền Ở Tầng Hệ Điều Hành Giữa Nhóm Lệnh Chỉ-Đọc và Nhóm Lệnh Đặc Quyền

| Hệ điều hành | Đường dẫn IPC | Kiểm chứng cho Nhóm Chỉ-Đọc (`status`, `ping`, `netcheck`, `bugreport`) | Kiểm chứng cho Nhóm Đặc Quyền (`up`, `down`, `cleanup`, `set`, `rotate-key`) |
|---|---|---|---|
| **macOS 13+** (`US-073 AC3/AC4`) | `/var/run/mesh/meshd.sock` | Cho phép user cục bộ gọi; phản hồi **0 secret** (`SEC-01`, `US-039 AC5`). | Kiểm tra `LOCAL_PEERCRED`: **bắt buộc `uid == 0` (`root`) hoặc thuộc nhóm `admin` (`gid == 80`)**. User thường bị từ chối với `403 PermissionDenied`! |
| **Windows 10/11** (`US-052 AC3`) | 2 Named Pipes tách biệt:<br/>- `\\.\pipe\mesh-agent-ro`<br/>- `\\.\pipe\mesh-agent-admin` | Đi qua `\\.\pipe\mesh-agent-ro` (chỉ gắn 4 route chỉ-đọc, 0 secret). | Đi qua `\\.\pipe\mesh-agent-admin` được tạo với SDDL DACL **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** (chỉ `LocalSystem` và `Administrators` mở được pipe). |
| **Linux (Node/Lab)** (`US-056`) | `/run/mesh/meshd.sock` | Cho phép đọc trạng thái không nhạy cảm (0 secret). | Kiểm tra `SO_PEERCRED`: **bắt buộc `uid == 0` (`root`)** hoặc nhóm `mesh-admin`. |

---

### 5.2. Đặc Tả Các Endpoint Trên Local Agent IPC

#### (1) `GET /v1/agent/status` — Trạng Thái Toàn Diện Của Agent & Peer (`US-039 AC1..AC7`)
Response (`200 OK` — hoàn tất ≤ 1 s, hỗ trợ `mesh status` và `mesh status --json`):
```json
{
  "daemon_state": "connected",
  "node_id": "019321b4-7c8a-7000-8000-010203040506",
  "node_name": "macbook-pro",
  "fqdn": "macbook-pro.mesh.internal",
  "overlay_ip": "100.115.0.2",
  "overlay_cidr": "100.115.0.0/16",
  "tun_interface_name": "utun7",
  "tun_mtu": 1280,
  "netmap_version": 14,
  "key_expires_at_ms": 1778510151000,
  "server_connection": {
    "control_endpoint": "203.0.113.10:443",
    "relay_endpoint": "203.0.113.10:443",
    "stun_endpoints": ["203.0.113.10:3478"],
    "tls_auth_mode": "spki_pin",
    "active_pin": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "next_pin": null,
    "control_connected": true,
    "relay_connected": true,
    "relay_rtt_ms": 18,
    "migration_pending_endpoint": null,
    "last_error": null
  },
  "self_network": {
    "local_udp_port": 51829,
    "bound_physical_interface": "en0",
    "nat_type": "eim_or_adm",
    "nat_classification_note": "single_stun_ip_mode",
    "overlay_conflict_warning": null,
    "macos_firewall_warning": null,
    "candidates": [
      { "addr": "192.168.1.45:51829", "source": "lan" },
      { "addr": "198.51.100.77:51829", "source": "reflexive" }
    ]
  },
  "peers": [
    {
      "node_id": "019321b0-0000-7000-8000-000000000001",
      "name": "vps",
      "fqdn": "vps.mesh.internal",
      "overlay_ip": "100.115.0.1",
      "online": true,
      "active_path": "direct",
      "direct_endpoint": "203.0.113.10:51820",
      "rtt_ms": 16,
      "last_handshake_at_ms": 1762958140000,
      "rx_bytes": 1048576,
      "tx_bytes": 524288
    }
  ]
}
```

#### (2) `POST /v1/agent/ping` — Ping Tầng Disco/Overlay Quan Sát Nâng Cấp Relay $\to$ Direct (`US-040`)
Request:
```json
{
  "target": "vps",
  "count": 4,
  "force_direct": false,
  "timeout_ms": 10000
}
```
Response (`200 OK`):
```json
{
  "target_name": "vps",
  "target_overlay_ip": "100.115.0.1",
  "samples": [
    { "seq": 1, "via": "relay", "endpoint": "203.0.113.10:443", "rtt_ms": 22.4 },
    { "seq": 2, "via": "direct", "endpoint": "203.0.113.10:51820", "rtt_ms": 15.1 },
    { "seq": 3, "via": "direct", "endpoint": "203.0.113.10:51820", "rtt_ms": 14.8 },
    { "seq": 4, "via": "direct", "endpoint": "203.0.113.10:51820", "rtt_ms": 14.9 }
  ],
  "packets_sent": 4,
  "packets_received": 4,
  "loss_percent": 0.0,
  "rtt_min_ms": 14.8,
  "rtt_avg_ms": 16.8,
  "rtt_max_ms": 22.4
}
```

#### (3) `POST /v1/agent/netcheck` — Chẩn Đoán NAT, UDP, STUN & Cổng TCP Tùy Chỉnh (`US-023`, `REL-06`)
Response (`200 OK`):
```json
{
  "udp_egress_ok": true,
  "stun_reachable": true,
  "stun_endpoint_tested": "203.0.113.10:3478",
  "reflexive_ipv4": "198.51.100.77:51829",
  "ipv6_available": false,
  "nat_mapping": "eim_or_adm",
  "nat_note": "1-IP STUN mode distinguishes Port-Dependent (APDM/hard NAT) from EIM/ADM",
  "control_tcp_reachable": true,
  "control_tcp_endpoint_tested": "203.0.113.10:443",
  "relay_rtt_ms": 18.2,
  "diagnostic_hint": null
}
```
*(Nếu `control_tcp_reachable == false` khi dùng cổng khác `443` như `8443`, `diagnostic_hint` trả rõ: `"cannot reach Control/Relay at 203.0.113.10:8443 — current network may only allow outbound TCP 80/443; consider hosting or proxying on port 443"` theo `US-023 AC4`, `US-024 AC7`).*

#### (4) `POST /v1/agent/bugreport` — Tạo Bundle Chẩn Đoán Đã Lọc Sạch Secret (`US-041`)
Response (`200 OK`): trả về đường dẫn tệp nén `.tar.gz`/`.zip` (≤ 20 MB) chứa log đã lọc, `status --json`, bảng route và cấu hình đã che `"[REDACTED]"` (`0` byte private key / pre-auth key).

#### (5) Nhóm Lệnh Đặc Quyền (`POST /v1/agent/up`, `down`, `cleanup`, `set`, `rotate-key`)
- **`POST /v1/agent/up`** (`US-004`):
  ```json
  {
    "server_endpoint": "203.0.113.10:443",
    "server_pin": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "preauth_key": "mpk_...",
    "node_name": "macbook-pro"
  }
  ```
- **`POST /v1/agent/set`** (`US-074 AC5` — Cập nhật địa chỉ/pin cho máy offline mà giữ nguyên danh tính):
  ```json
  {
    "server_endpoint": "203.0.113.10:8443",
    "server_pin": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  }
  ```
- **`POST /v1/agent/rotate-key`** (`US-032` — Xoay khóa node giữ nguyên tên & `OverlayIp`):
  ```json
  {
    "preauth_key": "mpk_..."
  }
  ```
- **`POST /v1/agent/down`** & **`POST /v1/agent/cleanup`** (`US-055 AC3`): Thực thi `ResourceLedger::cleanup_all()` idempotent, gỡ route, xóa khối `# BEGIN mesh … # END mesh` trong `hosts`, đóng `utunN`/Wintun và trả máy về trạng thái sạch.

---

## 6. Read-Only Observability HTTP API (`OPS-05..07`, `SEC-14`, `US-044`, `US-048`)

Chạy trên một listener riêng biệt (mặc định `127.0.0.1:9091` trên `mesh-server`), **chỉ có đúng 3 route `GET` chỉ-đọc**, không có bất kỳ thao tác thay đổi trạng thái nào và không lộ secret:

### 6.1. `GET /healthz` & `GET /readyz` (`US-044 AC1..AC4`)

- **`GET /healthz`** (Liveness): Trả `200 OK` `{"status": "alive"}` trong ≤ 50 ms miễn là tiến trình còn chạy.
- **`GET /readyz`** (Readiness):
  - Trả **`200 OK`** khi và chỉ khi: (1) `redb` mở được và không ở trạng thái `disk_degraded` (`ENOSPC`), (2) Listener TCP Control/Relay trên đúng cổng đã cấu hình đang hoạt động, và (3) Listener UDP STUN trên đúng cổng đã cấu hình đang hoạt động.
  - Trả **`503 Service Unavailable`** kèm lý do không nhạy cảm nếu vi phạm bất kỳ điều kiện nào trên:
    ```json
    {
      "status": "not_ready",
      "db_healthy": false,
      "control_tcp_listener_healthy": true,
      "stun_udp_listener_healthy": true,
      "reason": "storage write degraded (disk full or I/O error)"
    }
    ```

### 6.2. `GET /metrics` — Danh Mục Chuẩn Hóa Prometheus Metrics (`US-048 AC1/AC2`)

Định dạng `text/plain; version=0.0.4` (Prometheus text exposition):

| Tên Metric (`mesh_<subsystem>_<name>_<unit>`) | Kiểu | Nhãn (Labels) | Ý nghĩa Vận hành & Truy vết |
|---|---|---|---|
| `mesh_control_nodes_total` | `gauge` | `status="active\|expired\|revoked"` | Tổng số node trong DB theo trạng thái (`US-048 AC1`). |
| `mesh_control_nodes_online` | `gauge` | — | Số node đang mở luồng Control online. |
| `mesh_control_netmap_version` | `gauge` | — | Phiên bản `netmap_version` hiện hành (`US-009`). |
| `mesh_control_registrations_total` | `counter` | `outcome="success\|unauthenticated\|conflict\|rate_limited"` | Số lần đăng ký thiết bị thành công/thất bại (`US-048 AC1`). |
| `mesh_control_rate_limited_requests_total` | `counter` | `endpoint="challenge\|register\|relay"` | Số yêu cầu bị chặn bởi bộ giới hạn tốc độ (`US-042 AC5`). |
| `mesh_control_active_streams` | `gauge` | — | Số kết nối WebSocket `/v1/netmap/stream` đang mở. |
| `mesh_control_tls_cert_expiry_seconds` | `gauge` | `mode="ip_pinned\|acme\|reverse_proxy"` | Số giây còn lại trước khi chứng chỉ TLS hết hạn (`US-047 AC2`, `US-049`). |
| `mesh_relay_active_sessions` | `gauge` | — | Số phiên WebSocket `/v1/relay` đang hoạt động (`US-024`). |
| `mesh_relay_forwarded_bytes_total` | `counter` | `node_id` | Tổng số byte đã chuyển tiếp qua Blind Relay theo từng node (`US-048 AC1`). |
| `mesh_relay_dropped_packets_total` | `counter` | `reason="dest_offline\|dest_queue_full\|oversized\|unauthenticated"` | Số gói bị drop trên Relay, bao gồm `dest_queue_full` khi `try_send()` đầy (`US-025 AC2/AC3/AC6`). |
| `mesh_relay_throttled_bytes_total` | `counter` | `scope="per_node\|global"` | Số byte bị điều tiết bởi Token Bucket 20 Mbps (`US-027 AC2/AC4`). |
| `mesh_stun_requests_total` | `counter` | `outcome="ok\|rate_limited\|malformed"` | Số gói STUN Binding xử lý trên cổng UDP cấu hình (`US-019`). |
| `mesh_agent_peers_by_path` | `gauge` | `path="direct\|relay\|none"` | Số lượng peer của agent theo đường đi hiện tại (`US-048 AC1`). |
| `mesh_agent_spoofed_packets_dropped_total` | `counter` | — | Số gói bị chặn do vi phạm `AllowedIPs = /32` hoặc ngoài dải overlay (`SEC-11`, `US-014 AC4`, `US-018 AC1`). |
| `mesh_process_resident_memory_bytes` | `gauge` | — | Dung lượng RAM RSS hiện tại của tiến trình (`PERF-01`, `PERF-09`). |

---

## 7. Bảng Mã Lỗi Thống Nhất (`ErrorKind` ↔ HTTP Status ↔ Wire Code ↔ Hành Vi Retry Của Agent)

Toàn bộ phản hồi lỗi JSON trên HTTP/IPC đều tuân thủ cấu trúc duy nhất:
```json
{
  "error": {
    "kind": "unauthenticated",
    "code": "E_UNAUTHENTICATED",
    "message": "authentication failed",
    "request_id": "req_019321e0aabbccdd"
  }
}
```

### Bảng Ánh Xạ Khóa Cứng 12 Biến Thể `mesh_core::error::ErrorKind` (`coding-standards.md` §3.3)

| `ErrorKind` (Rust) | Giá trị JSON `kind` | Mã Wire `code` | HTTP Status | Thông điệp Công khai (`public_msg`) | Hành vi Retry Tự động của `meshd` (`US-034 AC1/AC4/AC5`) |
|---|---|---|---:|---|---|
| `ErrorKind::Internal` | `"internal"` | `E_INTERNAL` | `500` | `"internal server error"` *(không lộ chi tiết nội bộ)* | **Retry** theo `ExponentialBackoff` (base 1 s, factor 2, trần **60 s** + full jitter). |
| `ErrorKind::InvalidArgument` | `"invalid_argument"` | `E_INVALID_ARG` | `400` | Mô tả trường sai định dạng (vd. `"invalid node name: reserved hostname"`). | **Không retry** đối với lệnh CLI tương tác; giữ nguyên cấu hình cũ. |
| `ErrorKind::Unauthenticated` | `"unauthenticated"` | `E_UNAUTHENTICATED` | **`401`** | **Luôn cố định 100%: `"authentication failed"`** (`SEC-05`, `US-004 AC4`, `US-042 AC2` — cấm phân biệt key sai/hết hạn/đã dùng/đã thu hồi). | Nếu là lỗi challenge phiên tạm thời $\to$ xin challenge mới theo backoff; nếu là key đăng ký sai khi gõ `mesh up` $\to$ báo lỗi ra CLI. |
| `ErrorKind::PermissionDenied` | `"permission_denied"` | `E_PERM_DENIED` | `403` | `"operation requires administrator/root privileges"` (`SEC-14`, `US-052 AC3`, `US-073 AC4`). | **Không retry**; CLI thoát với mã lỗi `!= 0`. |
| `ErrorKind::NodeRevoked` | `"node_revoked"` | `E_NODE_REVOKED` | `403` | `"node has been revoked by administrator"` (`US-029`). | **DỪNG RETRY TỰ ĐỘNG** *(chỉ khi nhận qua kênh TLS đã xác thực Pin/CA hợp lệ — `US-034 AC5`)*. Gỡ đường hầm và hiển thị trong `mesh status`. |
| `ErrorKind::NodeKeyExpired` | `"node_key_expired"` | `E_KEY_EXPIRED` | `403` | `"node key expired; re-authenticate with a new pre-auth key"` (`US-031 AC1`). | **DỪNG RETRY TỰ ĐỘNG** *(chỉ khi nhận qua kênh TLS đã xác thực Pin/CA hợp lệ — `US-034 AC5`)*. Hiển thị hướng dẫn đăng ký lại trong `mesh status`. |
| `ErrorKind::NotFound` | `"not_found"` | `E_NOT_FOUND` | `404` | `"requested resource not found"` | **Không retry**. |
| `ErrorKind::Conflict` | `"conflict"` | `E_CONFLICT` | `409` | `"node name already exists or overlay address pool exhausted"` (`US-004 AC3/AC5`). | **Không retry** tự động khi đăng ký tên trùng; báo rõ cho người dùng. |
| `ErrorKind::RateLimited` | `"rate_limited"` | `E_RATE_LIMITED` | `429` | `"rate limit exceeded; please retry later"` (kèm header `Retry-After`) (`US-042`). | **Retry** tôn trọng `Retry-After` kết hợp `ExponentialBackoff` + full jitter. |
| `ErrorKind::Unavailable` | `"unavailable"` | `E_UNAVAILABLE` | `503` | `"service temporarily unavailable"` (`US-007 AC5`, `US-044 AC2`). | **Retry** theo `ExponentialBackoff` (base 1 s, trần **60 s** + full jitter); giữ nguyên đường hầm P2P từ cache (`US-033`). |
| `ErrorKind::ClockSkew` | `"clock_skew"` | `E_CLOCK_SKEW` | *(Local TLS)* | `"TLS certificate validity check failed; possible system clock skew"` (`US-003 AC5`). | **BẮT BUỘC TIẾP TỤC RETRY** (trần **5 phút** + đánh thức ngay khi `ClockJumpDetector` hoặc `NetMonitor` báo sự kiện — `US-034 AC4`). Tuyệt đối không khóa chết máy từ xa! |
| `ErrorKind::PinMismatch` | `"pin_mismatch"` | `E_PIN_MISMATCH` | *(Local TLS)* | `"server SPKI pin mismatch (expected sha256:..., got sha256:...)"` (`SEC-04(c)`, `US-003 AC7`). | **Không gửi bất kỳ secret nào**, ghi log `WARN`, **BẮT BUỘC TIẾP TỤC RETRY** (trần **5 phút** + đánh thức khi đổi mạng hoặc khi admin chạy `mesh set` — `US-034 AC4`, `US-074 AC5`). |
