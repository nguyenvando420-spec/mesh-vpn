# API & Wire Protocol Contracts — Mesh VPN (Rust 1.94.1)

| Thuộc tính | Giá trị |
|---|---|
| Tác giả | `agile-architect` |
| Ngày | 2026-11-12 |
| Phiên bản | **2.2** — Gate 2 Round 2 Revision: Khóa cứng 100% Hợp đồng Giao tiếp (Tách thư mục IPC `/run/mesh-server` & `/var/run/meshd`, lọc `CandidateEndpoint` phân biệt UDP vs TCP, ngữ nghĩa `persistence_tier` cho thu hồi khẩn cấp, slice pattern matching cho `is_stun_rfc5389`) |
| Trạng thái | **Proposed-for-Gate-2 (Revised Round 2)** |
| Thành phần AI | **Không có** (Không có JSON Schema đầu ra AI) |
| Đầu vào | [production-readiness-requirements.md](../01-discovery/production-readiness-requirements.md) (v1.2) · [product-backlog.md](../02-product-planning/product-backlog.md) (v1.2) · [tech-stack-decision.md](./tech-stack-decision.md) (v2.0) · [architecture-decision-record.md](./architecture-decision-record.md) (v2.2 `ADR-002..010`) · [coding-standards.md](./coding-standards.md) (v2.2) |
| Crate thực thi | `crates/mesh-proto` (DTOs & parsers), `crates/mesh-datapath`, `crates/mesh-server`, `crates/meshd`, `crates/mesh` |

> **Quy tắc Hợp đồng Bất biến**:
> 1. Mọi endpoint HTTP/WebSocket dùng tiền tố **`/v1/`** (`coding-standards.md` §2.1).
> 2. Mọi trường JSON dùng **`snake_case`**, mọi trường thời gian kết thúc bằng **`_at_ms`** (`u64` Unix epoch milliseconds UTC), gắn `#[serde(deny_unknown_fields)]` ở đầu vào.
> 3. **Không một DTO mạng nào có trường chứa khóa riêng (`private_key`)** (`SEC-01(a)`).
> 4. Giới hạn kích thước body HTTP tối đa **`MAX_HTTP_BODY_BYTES = 65_536` (64 KiB)** (riêng kênh IPC chỉ-đọc `meshd-ro` giới hạn `4096` bytes); giới hạn khung nhị phân WebSocket/UDP tối đa **`MAX_FRAME_SIZE = 2048` bytes**.

---

## 1. Control Public HTTPS & WebSocket API (Trên Cổng TCP Cấu Hình Được, Mặc Định `443`)

Toàn bộ các endpoint trong mục này chạy trên cổng TCP công khai do người dùng cấu hình (mặc định `DEFAULT_CONTROL_TCP_PORT = 443` trong `mesh_core::defaults`, đổi được sang bất kỳ cổng nào như `8443` theo `GNFR-11`, `US-074`), hỗ trợ cả 3 chế độ TLS (`ADR-008`, `BLK-G2-04`):
- **Chế độ (c) IP + SPKI Pinning (Mặc định hạng nhất — `SEC-04(c)`, `US-003`, `US-047`, `BLK-G2-04`)**:
  - `SpkiPinVerifier` trong `crates/mesh-crypto::tlspin` giải mã chứng chỉ lá DER bằng **`x509-cert` (`0.2`, `RustCrypto`)** để: (1) kiểm tra `validity.not_before <= now <= validity.not_after` (nếu lệch giờ thì phân loại `ErrorKind::ClockSkew` theo `US-003 AC5` và từ chối chứng chỉ hết hạn theo `US-047 AC4`), (2) trích xuất nguyên vẹn lát cắt DER của `tbs_certificate.subject_public_key_info` (hỗ trợ cả ECDSA P-256 và RSA theo `US-003 AC7`), tính SHA-256 và đối chiếu `ConstantTimeEq` với `PinSet` (`active_pin` / `next_pin`), **cấm TOFU**.
  - Kiểm tra chữ ký bắt tay TLS (`verify_tls12_signature`, `verify_tls13_signature`) bắt buộc ủy quyền cho `rustls::crypto::ring::default_provider().signature_verification_algorithms`.
- **Chế độ (a) Standalone Domain ACME (`instant-acme`)**: `TLS-ALPN-01` khi cổng = `443`, `DNS-01` khi cổng ≠ `443`; client xác thực bằng `rustls-webpki` + `rustls-native-certs` (hoặc kết hợp SPKI Pin).
- **Chế độ (b) Sau Reverse Proxy sẵn có (`Nginx`/`Caddy`)**: đi kèm `trusted_proxies` bật tường minh (`US-042 AC6`).

### 1.1. Quy tắc Kiểm chứng Đầu vào Chung (Validation Rules — `US-004 AC3`, `US-038 AC5`, `US-056`, `Codex #8`, `Codex R2 #4`)

| Kiểu Miền (`mesh-core`) | Quy tắc Kiểm chứng Bắt buộc tại Biên |
|---|---|
| `NodeName` | Độ dài `1..=63` ký tự ASCII; chỉ gồm `[a-z0-9-]`; không bắt đầu hoặc kết thúc bằng `'-'`; cấm tuyệt đối `\n`, `\r`, `#`, khoảng trắng; **từ chối danh sách tên cấm**: `localhost`, `broadcasthost`, `wpad`, `isatap`, `local`, và chính `public_host`/domain của Control/Relay/STUN. |
| `PublicKey` | Chuỗi Base64 chuẩn (44 ký tự) hoặc Hex (64 ký tự) giải mã ra đúng `[u8; 32]`, không phải điểm bậc thấp (low-order point) trên Curve25519. |
| `SpkiPin` | Định dạng `"sha256:<64_hex_lowercase>"` giải mã ra đúng `[u8; 32]`. |
| `CandidateEndpoint` | `SocketAddr` (`IP:port`) **UDP** hợp lệ; **từ chối** địa chỉ thuộc `overlay_cidr`, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, broadcast, unspecified (`0.0.0.0`, `::`), các interface ảo (`mesh*`, `utun*`, `wg*`, `tailscale*`, `docker*`, `veth*`), **VÀ chỉ từ chối khi trùng cặp `SocketAddr` UDP của `stun_udp_endpoint` (`<vps_ip>:<stun_udp_port>`)** (`US-020 AC2/AC4`, `Codex R2 #4`). **KHÔNG từ chối** khi trùng số cổng với `control_tcp_endpoint` (khác giao thức tầng 4 TCP vs UDP!).<br/>- **Vector kiểm thử bắt buộc (`Codex R2 #4`)**: Với `control_tcp_endpoint = 203.0.113.10:51820 (TCP)` và `stun_udp_endpoint = 203.0.113.10:3478 (UDP)` $\to$ ứng viên UDP `203.0.113.10:51820` được **CHẤP NHẬN (`true`)** cho Direct P2P của `vps.mesh.internal` (`US-056`), còn ứng viên UDP `203.0.113.10:3478` bị **TỪ CHỐI (`false`)**! |

---

### 1.2. `POST /v1/auth/challenge` — Xin Thách Đố Dùng Một Lần (`challenge_id` — `US-003`, `ADR-003`, `BLK-G2-02`)

- **Ánh xạ User Story**: `US-003 AC1/AC4/AC5`, `US-050 AC1/AC2`.
- **Xác thực**: Chưa cần token (nhưng phải qua kênh TLS đã xác minh SPKI Pin hoặc CA; chịu giới hạn tốc độ theo IP nguồn `US-042`).
- **Mục đích & Ràng buộc Single-Use (`BLK-G2-02`)**:
  - Trước mỗi lần gọi `POST /v1/nodes/register`, nâng cấp WebSocket `GET /v1/netmap/stream`, nâng cấp WebSocket `GET /v1/relay`, hoặc gọi REST dự phòng, Client gửi `POST /v1/auth/challenge` trên **cùng kết nối HTTP/1.1 Keep-Alive (cùng phiên TLS 1.3)**.
  - Server kiểm tra `protocol_version` tối thiểu (`US-050 AC2`), sinh `challenge_id` (UUIDv4), cặp khóa X25519 tạm thời (`server_eph_pubkey`) và `challenge_nonce` ngẫu nhiên 32 byte từ `OsRng`, lưu vào bảng trong bộ nhớ có giới hạn cứng **`MAX_PENDING_CHALLENGES = 4096`** với **`TTL = 30_000 ms` (30 giây)**.
  - Mỗi `challenge_id` **chỉ dùng được đúng 1 lần**: ngay khi request kế tiếp gửi kèm `X-Mesh-Challenge-Id`, server thực hiện `pending_challenges.remove(&challenge_id)` nguyên tử trước khi giải mã (chống phát lại 100%).

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
  "challenge_id": "019321c0-1122-7333-8444-5566778899aa",
  "server_eph_pubkey": "c2VydmVyLWVwaGVtZXJhbC14MjU1MTktcHVia2V5LTI=",
  "challenge_nonce": "Y2hhbGxlbmdlLW5vbmNlLTMyLWJ5dGVzLWZyb20tb3Nybmc=",
  "server_time_at_ms": 1762958151000,
  "expires_at_ms": 1762958181000
}
```

#### Cấu trúc `ProofPayload` được Client niêm phong bằng `crypto_box::SalsaBox` (`ADR-003`, `BLK-G2-02`)
Client tạo mảng byte JSON của cấu trúc dưới đây rồi gọi `SalsaBox::new(&server_eph_pubkey, node_secret.expose_secret()).encrypt(&box_nonce, payload_bytes)`:
```json
{
  "challenge_id": "019321c0-1122-7333-8444-5566778899aa",
  "challenge_nonce": "Y2hhbGxlbmdlLW5vbmNlLTMyLWJ5dGVzLWZyb20tb3Nybmc=",
  "method": "POST",
  "path": "/v1/nodes/register",
  "body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "node_pubkey": "bWVzaC1ub2RlLXB1YmtleS0zMi1ieXRlcy1iYXNlNjQ=",
  "disco_pubkey": "bWVzaC1kaXNjby1wdWJrZXktMzItYnl0ZXMtYmFzZTY0",
  "timestamp_at_ms": 1762958151120,
  "tls_exporter_binding": "dGxzLTEuMy1leHBvcnRlci0zMi1ieXRlcy1iaW5kaW5n"
}
```
> **Quy tắc kiểm chứng nhất quán `ProofPayload` & `tls_exporter_binding` (`BLK-G2-02`)**:
> 1. **Phía Client (`meshd`)**:
>    - **Luôn luôn** trích xuất 32 byte từ `rustls::Connection::export_keying_material(..., b"EXPORTER-mesh-control-v1", None)` trên kết nối TLS 1.3 hiện tại để điền vào `tls_exporter_binding` (Client không cần biết Server đang chạy Standalone hay sau Reverse Proxy).
>    - Tính `body_sha256 = SHA256(raw_http_body)` (đối với yêu cầu `GET` nâng cấp WebSocket `/v1/netmap/stream` hoặc `/v1/relay`, `body_sha256 = SHA256(b"")`).
>    - Tính `timestamp_at_ms = challenge_resp.server_time_at_ms + elapsed_monotonic_ms` (giúp không bao giờ bị lỗi lệch đồng hồ hệ thống dual-boot Windows/Linux theo `US-003 AC5`).
> 2. **Phía Server (`mesh-server`)**:
>    - Lấy và xóa nguyên tử `challenge_id` khỏi `pending_challenges` (nếu không tồn tại hoặc đã quá `expires_at_ms` $\to$ trả `401 "authentication failed"`).
>    - Mở hộp `SalsaBox` bằng `(server_eph_secret, node_pubkey, box_nonce)` và kiểm tra khớp chính xác: `challenge_id`, `ConstantTimeEq(challenge_nonce)`, `method`, `path`, `ConstantTimeEq(body_sha256)`, `node_pubkey`, `disco_pubkey`, và `|now_ms - timestamp_at_ms| <= 60_000`.
>    - **Khi `tls_mode` là `StandalonePinned` (`ip_pinned`) hoặc `StandaloneAcme` (`acme_tls_alpn_01` / `acme_dns_01`)**: Server trích xuất 32 byte `export_keying_material(..., b"EXPORTER-mesh-control-v1", None)` từ `rustls::ServerConnection` của chính kết nối đó và bắt buộc đối chiếu `ConstantTimeEq(server_exporter, proof.tls_exporter_binding)`.
>    - **Khi `tls_mode == ReverseProxy` (`reverse_proxy`) VÀ địa chỉ IP của kết nối TCP nằm trong `trusted_proxies`**: Server **chỉ bỏ qua bước so sánh `tls_exporter_binding`** (vì TLS kết thúc tại Nginx/Caddy; tính chống phát lại và toàn vẹn request đã được khóa chặt bởi `challenge_id` dùng 1 lần + `SalsaBox` trói `(challenge_nonce, method, path, body_sha256)`). Nếu IP kết nối TCP không nằm trong `trusted_proxies`, từ chối ngay với `401 "authentication failed"`.

---

### 1.3. Header Xác Thực Chuẩn Hóa Cho Mọi Yêu Cầu Đã Có `challenge_id` (`X-Mesh-*` — `BLK-G2-02`)

Mọi yêu cầu cần chứng minh sở hữu `node_pubkey` (`POST /v1/nodes/register`, `GET /v1/netmap/stream`, `GET /v1/relay`, `POST /v1/endpoints`, `POST /v1/disco/call-me-maybe`) đều truyền **4 header chuẩn**:
- `X-Mesh-Challenge-Id: <uuid_v4>`
- `X-Mesh-Node-Pubkey: <base64_32_bytes>`
- `X-Mesh-Box-Nonce: <base64_24_bytes>`
- `X-Mesh-Auth-Proof: <base64_salsabox_ciphertext_of_ProofPayload>`

---

### 1.4. `POST /v1/nodes/register` — Đăng Ký Thiết Bị Idempotent / Re-auth / Xoay Khóa (`US-004`, `US-005`, `US-031`, `US-032`)

- **Ánh xạ User Story**: `US-004 AC1..AC7`, `US-005 AC1..AC4`, `US-006`, `US-031 AC5/AC6`, `US-032 AC1..AC3`.
- **Headers**: Bắt buộc đính kèm 4 header `X-Mesh-Challenge-Id`, `X-Mesh-Node-Pubkey`, `X-Mesh-Box-Nonce`, `X-Mesh-Auth-Proof` (§1.3).
- **Idempotency & Chặn Node hết hạn (`HR-G2-03`)**:
  - Khóa Idempotency tự nhiên là `node_pubkey` (đã được chứng minh sở hữu qua `X-Mesh-Auth-Proof`). Gửi lại cùng `node_pubkey` đang `Active` + cùng `preauth_key` trả về `200 OK` với đúng `NodeId` và `OverlayIp` đã cấp, không tiêu hao thêm lượt dùng key (`US-005 AC1`).
  - Nếu `node_pubkey` thuộc một node có `status == Expired` hoặc `status == Revoked`: từ chối ngay với `401 "authentication failed"` (`SEC-05`, buộc client sinh khóa mới + dùng key `--for <node>`).

#### Request JSON (`RegisterNodeRequest`)
```json
{
  "node_pubkey": "bWVzaC1ub2RlLXB1YmtleS0zMi1ieXRlcy1iYXNlNjQ=",
  "disco_pubkey": "bWVzaC1kaXNjby1wdWJrZXktMzItYnl0ZXMtYmFzZTY0",
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

### 1.5. `POST /v1/endpoints` — Công Bố Candidate Endpoints & Xác Nhận Đổi Cổng (`US-019`, `US-020`, `US-074`)

- **Ánh xạ User Story**: `US-019 AC1/AC2`, `US-020 AC1..AC4`, `US-074 AC1/AC7`.
- **Xác thực**: Đính kèm 4 header `X-Mesh-*` (§1.3) với một `challenge_id` mới (hoặc gửi trực tiếp khung `ClientControlFrame::EndpointUpdate` trên luồng WebSocket `/v1/netmap/stream` đang mở — xem §1.7).
- **Hành vi**: Cập nhật danh sách địa chỉ ứng viên (`lan`, `ipv6`, `reflexive`), loại NAT quan sát được, và phiên bản cấu hình server (`acked_endpoint_version`) mà agent vừa áp dụng thành công. Chỉ khi danh sách `endpoints` thực sự thay đổi so với bản đang lưu thì server mới cấp `netmap_version` mới qua `MonotonicNetmapVersion::allocate_next` và đẩy bản cập nhật cho các peer.

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

### 1.6. `POST /v1/disco/call-me-maybe` — Tín Hiệu Khởi Động Đục Lỗ NAT Đồng Thời (`US-021`, `HR-G2-04`)

- **Ánh xạ User Story**: `US-021 AC1/AC5`.
- **Xác thực**: Đính kèm 4 header `X-Mesh-*` (§1.3) (hoặc gửi trực tiếp `ClientControlFrame::CallMeMaybe` qua WebSocket `/v1/netmap/stream` đang mở — §1.7).
- **Khóa định dạng `disco_frame_b64` (`HR-G2-04`)**:
  - Khi Node A muốn bắt đầu đục lỗ NAT tới Node B, A tạo một **khung nhị phân `b"MESHDS"` hoàn chỉnh (`msg_type = 0x03 = DiscoCallMeMaybe`, độ dài `172..=1024 bytes` theo đúng đặc tả §3.3)** đã được mã hóa `SalsaBox(A_disco_secret, B_disco_pubkey)` (bên trong có `magic_ctx = *b"MESHDSv1"`, `inner_sender_disco_pubkey = A_disco_pub`, `inner_recipient_disco_pubkey = B_disco_pub`, `tx_id`, `sent_at_ms` và danh sách `endpoints[]` của A) rồi mã hóa Base64 vào trường `disco_frame_b64`.
  - Server kiểm tra: (1) A và B đều đang `Active`, (2) `disco_frame_b64` giải mã ra mảng byte có độ dài `172..=1024` bytes, (3) 7 byte đầu là `b"MESHDS\x01"`, và (4) `outer_sender_disco_pubkey` (`bytes[7..39]`) khớp 100% với `disco_pubkey` đã đăng ký của A. Nếu hợp lệ, server chuyển tiếp nguyên vẹn `disco_frame_b64` qua WebSocket `/v1/netmap/stream` cho B trong sự kiện `ServerControlFrame::CallMeMaybeRelay`.

#### Request JSON (`CallMeMaybeRequest`)
```json
{
  "dst_node_id": "019321b4-9999-7000-8000-010203040507",
  "disco_frame_b64": "TUVTSERTAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=..."
}
```

---

### 1.7. `GET /v1/netmap/stream?known_version=<u64>` — Luồng Đồng Bộ Netmap & Tín Hiệu Điều Khiển Hai Chiều (`US-009`, `US-029`, `US-031`, `US-074`, `BLK-G2-02`, `HR-G2-04`)

- **Ánh xạ User Story**: `US-009 AC1..AC6`, `US-029 AC1..AC3`, `US-031 AC1`, `US-034 AC5`, `US-074 AC1/AC2`.
- **Xác thực khi nâng cấp (`BLK-G2-02`)**: Yêu cầu `GET /v1/netmap/stream` (`Upgrade: websocket`) bắt buộc đính kèm 4 header `X-Mesh-Challenge-Id`, `X-Mesh-Node-Pubkey`, `X-Mesh-Box-Nonce`, `X-Mesh-Auth-Proof` (§1.3, với `method = "GET"`, `path = "/v1/netmap/stream"`, `body_sha256 = SHA256(b"")`).
- **Quy tắc chống bão lưu lượng nền (`US-009 AC1`, `GNFR-07`)**:
  - Server và Client gửi khung `heartbeat` nhẹ mỗi **25 giây** để giữ kết nối qua NAT/Reverse Proxy; nếu quá **60 giây** không có khung nào, bên kia đóng và kết nối lại (`US-009 AC4`).
  - Server **TUYỆT ĐỐI KHÔNG** tăng `netmap_version` hay đẩy lại `NetmapSnapshot` cho các nhịp heartbeat `last_seen`.

#### (a) Các Loại Bản Tin Từ Client $\to$ Server Trên `/v1/netmap/stream` (`ClientControlFrame` — `BLK-G2-02`)
Sau khi luồng WebSocket `/v1/netmap/stream` đã được xác thực và nâng cấp, Client có thể gửi trực tiếp 3 loại khung JSON sau mà không tốn thêm RTT xin `challenge_id`:
1. **`endpoint_update`**:
   ```json
   {
     "frame_type": "endpoint_update",
     "endpoints": [
       { "addr": "192.168.1.45:51829", "source": "lan" },
       { "addr": "198.51.100.77:51829", "source": "reflexive" }
     ],
     "nat_type": "eim_or_adm",
     "acked_endpoint_version": 2
   }
   ```
2. **`call_me_maybe`**:
   ```json
   {
     "frame_type": "call_me_maybe",
     "dst_node_id": "019321b4-9999-7000-8000-010203040507",
     "disco_frame_b64": "TUVTSERTAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=..."
   }
   ```
3. **`heartbeat`**:
   ```json
   {
     "frame_type": "heartbeat",
     "sent_at_ms": 1762958170000,
     "acked_netmap_version": 14
   }
   ```

#### (b) Các Loại Bản Tin Từ Server $\to$ Client Trên `/v1/netmap/stream` (`ServerControlFrame`)

- **Sự kiện đồng bộ bản đồ mạng (`netmap_snapshot` / `netmap_delta`)**:
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

- **Sự kiện chuyển tiếp đục lỗ NAT (`call_me_maybe_relay` — `HR-G2-04`)**:
```json
{
  "event_type": "call_me_maybe_relay",
  "src_node_id": "019321b4-7c8a-7000-8000-010203040506",
  "src_node_pubkey": "bWVzaC1ub2RlLXB1YmtleS0zMi1ieXRlcy1iYXNlNjQ=",
  "disco_frame_b64": "TUVTSERTAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=...",
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

## 2. Blind Relay Wire Protocol (`GET /v1/relay` WebSocket Binary Frames — `ADR-004`, `US-024`, `US-025`, `US-027`, `BLK-G2-02`)

- **Ánh xạ User Story**: `US-024 AC1..AC8`, `US-025 AC1..AC6`, `US-026 AC1..AC4`, `US-027 AC1..AC5`.
- **Bước chứng minh khóa bằng Single-Use `challenge_id` trước khi nâng cấp (`US-024 AC1/AC2`, `US-027 AC1`, `BLK-G2-02`)**:
  - Trước khi mở kết nối Relay, Client gọi `POST /v1/auth/challenge` trên cùng kết nối HTTP/1.1 Keep-Alive (cùng phiên TLS 1.3) để lấy `challenge_id` dùng 1 lần, rồi gửi `GET /v1/relay` (`Upgrade: websocket`) kèm 4 header `X-Mesh-Challenge-Id`, `X-Mesh-Node-Pubkey`, `X-Mesh-Box-Nonce`, `X-Mesh-Auth-Proof` (§1.3, với `method = "GET"`, `path = "/v1/relay"`, `body_sha256 = SHA256(b"")`).
  - Nếu `challenge_id` không hợp lệ/đã dùng hoặc `node_pubkey` chưa đăng ký/đã bị thu hồi/hết hạn, server trả HTTP `401`/`403` ngay từ bước HTTP handshake, **không mở phiên WebSocket và không chuyển tiếp bất kỳ byte nào**.
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
| **`0x01`** | `ClientToPeerPacket` | Client $A \to$ Relay | `[0x01: 1B][dst_pubkey: 32B][ciphertext: 1..=1480B]`<br/>*(Tổng độ dài: `34..=1513` bytes)* | Relay kiểm tra Token Bucket của $A$ (mặc định **20 Mbps**, `US-027 AC2`). Tra phiên của `dst_pubkey` ($B$). Nếu $B$ không online hoặc không thuộc Netmap $\to$ **drop im lặng** + tăng metric (`US-025 AC2`). Nếu $B$ online $\to$ tạo frame **`0x02`** với **`src_pubkey = pubkey_đã_xác_thực_của_A`** và gọi **`tx_b.try_send(frame)`** trên kênh `mpsc::channel(256)` của $B$ (`US-025 AC1/AC6`). |
| **`0x02`** | `RelayToClientPacket` | Relay $\to$ Client $B$ | `[0x02: 1B][src_pubkey: 32B (do Relay chứng thực)][ciphertext: 1..=1480B]`<br/>*(Tổng độ dài: `34..=1513` bytes)* | Agent $B$ kiểm tra `src_pubkey` có thuộc `PeerMap` trong Netmap hiện hành không (`US-026 AC2`); nếu hợp lệ thì chuyển `ciphertext` vào `DiscoEngine` kèm **`IngressSource::Relay { verified_src_node_pubkey: src_pubkey }`** (nếu bắt đầu bằng `b"MESHDS"` và `len >= 172`) hoặc `Tunn::decapsulate`. |
| **`0x03`** | `RelayKeepAlive` | Hai chiều | `[0x03: 1B][sent_at_ms: u64 big-endian (8B)]`<br/>*(Tổng độ dài: đúng `9` bytes)* | Gửi mỗi **25 giây** khi kết nối Relay rảnh để giữ NAT/Reverse Proxy không ngắt (`US-024 AC4`). |
| **`0x04`** | `RelayControlNotice` | Relay $\to$ Client | `[0x04: 1B][notice_code: 1B][reserved: 6B]`<br/>`notice_code`: `0x01` = `Throttled`, `0x02` = `NodeRevoked`, `0x03` = `NodeKeyExpired`, `0x04` = `ServerMigratingPort` | Thông báo trạng thái điều tiết băng thông (`US-027 AC4`) hoặc lý do đóng phiên. |

---

## 3. Shared UDP Wire Protocol (`MagicSocket` — Data Plane + STUN + Authenticated Disco)

Trên mỗi thiết bị chạy `meshd`, `MagicSocket` mở duy nhất **1 `tokio::net::UdpSocket`** (ưu tiên bind lại cổng `local_udp_port` đã lưu bền trong `netmap-cache.json` theo `US-019 AC1`; tắt cờ ép cứng `DF=1` ở tầng UDP ngoài theo `US-017 AC3`).

### 3.1. Bảng Phân Loại Gói Tin Đến Không Mơ Hồ (Zero-Allocation Demultiplexing Table — `Codex #1`, `IMP-G2-01`)

Khi `MagicSocket::recv_from(&mut buf[0..2048])` nhận được một gói UDP có độ dài `len` (`let buf = &buf[..len];`):

| Thứ tự kiểm tra | Giao thức | Điều kiện Byte Chính Xác (Không thể trùng lặp, 0 `buf[i]`) | Lý do Không Giao Nhau Toán Học |
|---:|---|---|---|
| **1** | **Authenticated Disco** (`US-021`, `IMP-G2-01`) | `buf.len() >= 172 && matches!(buf, [b'M', b'E', b'S', b'H', b'D', b'S', 0x01, ..])` (`MIN_DISCO_PACKET_LEN = 172`) | Byte `0` = `0x4D` (`'M'`, có 2 bit đầu `01` $\neq 00$ của STUN và `0x4D` $\notin 1..=4$ của WireGuard). Độ dài tối thiểu `172` bytes khớp chính xác `63B (outer) + 93B (inner header) + 16B (Poly1305 tag)`. |
| **2** | **STUN RFC 5389 / 8489** (`US-019`, `Codex #1`, `NOTE-G2-R2-01`) | `is_stun_rfc5389(buf)` (slice pattern `[b0, _, len_hi, len_lo, 0x21, 0x12, 0xA4, 0x42, ..]` với `buf.len() >= 20`, `(b0 & 0b1100_0000) == 0`, `(len_lo & 0b0000_0011) == 0`, `20 + msg_len <= buf.len()`) | Theo RFC 5389 §6, 2 bit cao nhất của byte `0` bằng `00`, **2 bit thấp nhất của Message Length (`len_lo & 0b0000_0011 == 0`) bằng `00`** (vì mọi attribute STUN đều căn lề 4 byte; byte `1` có thể bằng `0x01` cho cả Binding Request `0x0001` lẫn Success Response `0x0101`!), kèm 4 byte Magic Cookie `0x2112A442` ở byte `4..8`. |
| **3** | **WireGuard (`defguard_boringtun`)** (`US-014..017`) | `buf.len() >= 32 && matches!(buf, [1..=4, 0x00, 0x00, 0x00, ..])` | WireGuard chỉ có 4 loại gói (`1` = Handshake Init 148B, `2` = Handshake Resp 92B, `3` = Cookie Reply 64B, `4` = Transport Data ≥ 32B) và 3 byte reserved `1..4` luôn bằng `[0, 0, 0]`. |
| **4** | **Gói Lạ / Nhiễu Internet** | Mọi gói không thỏa 3 điều kiện trên | **Drop im lặng ngay lập tức** (0 cấp phát heap, 0 panic, 0 phản hồi để chống khuếch đại UDP — `US-021 AC3/AC5`). |

#### Hàm Demux Chuẩn Hóa Trong `crates/mesh-proto/src/lib.rs` (Tuân thủ `clippy::indexing_slicing = "deny"` — `NOTE-G2-R2-01`)
```rust
pub const MIN_DISCO_PACKET_LEN: usize = 172; // 63 (outer) + 93 (inner) + 16 (Poly1305 tag)

pub fn is_stun_rfc5389(buf: &[u8]) -> bool {
    let [b0, _, len_hi, len_lo, 0x21, 0x12, 0xA4, 0x42, ..] = buf else {
        return false;
    };
    buf.len() >= 20
        && (b0 & 0b1100_0000) == 0
        && (len_lo & 0b0000_0011) == 0
        && (20 + usize::from(u16::from_be_bytes([*len_hi, *len_lo]))) <= buf.len()
}
```

---

### 3.2. Layout Byte-Level & Vector Kiểm Thử Của Gói STUN Binding (`crates/mesh-proto::stun` — RFC 5389, `Codex #1`)

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
- **STUN Binding Request (`0x0001`)**: độ dài `28` bytes (Header `20` bytes + Attribute `FINGERPRINT` `8` bytes: `CRC32(bytes[0..20]) ^ 0x5354554e`).
- **STUN Binding Success Response (`0x0101`)**: độ dài `40` bytes (IPv4) hoặc `52` bytes (IPv6), gồm `XOR-MAPPED-ADDRESS` (`0x0020`, 12B cho IPv4: cổng XOR với `0x2112`, IPv4 XOR với `0x2112A442`) và `FINGERPRINT` (`0x8028`, 8B). Giới hạn tốc độ **100 pkt/s/IP** trên VPS để chống khuếch đại UDP (`US-019 AC4`).

#### Vector Kiểm Thử Byte Cụ Thể Bắt Buộc Trong Unit Test Của Demuxer & `stun.rs` (`Codex #1`)
1. **Vector 1 — STUN Binding Request (`msg_type = 0x0001`, `msg_len = 0x0008`, tổng `28` bytes)**:
   - `buf[0..4] = [0x00, 0x01, 0x00, 0x08]` (lưu ý `buf[1] == 0x01` có bit 0 bằng `1`, trong khi `buf[3] == 0x08` có 2 bit thấp bằng `00`).
   - `buf[4..8] = [0x21, 0x12, 0xA4, 0x42]` (Magic Cookie).
   - `buf[8..20] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]` (`tx_id`).
   - `buf[20..28] = [0x80, 0x28, 0x00, 0x04, ...]` (`FINGERPRINT` attribute).
   - **Kỳ vọng**: `is_stun_rfc5389(&req_vec) == true` và `demux_packet(&req_vec)` trả về `DemuxPacket::Stun`.
2. **Vector 2 — STUN Binding Success Response (`msg_type = 0x0101`, `msg_len = 0x0014` (`20` bytes), tổng `40` bytes, phản xạ `198.51.100.77:51829`)**:
   - `buf[0..4] = [0x01, 0x01, 0x00, 0x14]` (`buf[1] == 0x01`, `buf[3] == 0x14` có `0x14 & 0b11 == 0`).
   - `buf[4..8] = [0x21, 0x12, 0xA4, 0x42]`.
   - `buf[8..20] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]`.
   - `buf[20..32]` (`XOR-MAPPED-ADDRESS`): `[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xEB, 0x67, 0xE7, 0x21, 0xC0, 0x0F]`.
   - `buf[32..40]` (`FINGERPRINT`): `[0x80, 0x28, 0x00, 0x04, ...]`.
   - **Kỳ vọng**: `is_stun_rfc5389(&resp_vec) == true` và giải mã ra đúng `SocketAddr::from(([198, 51, 100, 77], 51829))`.

---

### 3.3. Layout Byte-Level Của Gói Authenticated Disco Chống Phản Xạ & Tách `IngressSource` (`crates/mesh-proto::disco` — `US-021`, `Codex #2`, `HR-G2-04`, `IMP-G2-01`)

Vì `crypto_box::SalsaBox(A_priv, B_pub)` và `SalsaBox(B_priv, A_pub)` cùng dẫn xuất ra một khóa chia sẻ đối xứng X25519–XSalsa20–Poly1305, nếu bên trong bản rõ đã mã hóa không ràng buộc tường minh danh tính người gửi và người nhận, kẻ tấn công trên mạng có thể sửa `outer_sender_disco_pubkey` trong header ngoài thành `B_pub` rồi dội ngược (reflect) gói của A về chính A! Để **triệt tiêu 100% tấn công phản xạ hai chiều (`Codex #2`) và tấn công đầu độc đường đi qua Relay (`HR-G2-04`)**, định dạng gói Disco được khóa cứng như sau:

#### (a) Outer Header Không Mã Hóa (`63 bytes` cố định) + `SalsaBox` Ciphertext (`>= 109 bytes`)
```text
+-------------------+--------------+-------------------------------+-------------------+----------------------------------+
| Bytes 0..6 (6B)   | Byte 6 (1B)  | Bytes 7..39 (32B)             | Bytes 39..63 (24B)| Bytes 63..N (>= 93B + 16B MAC)   |
| Magic: b"MESHDS"  | Version=0x01 | outer_sender_disco_pubkey     | box_nonce (OsRng) | SalsaBox Ciphertext + Poly1305   |
+-------------------+--------------+-------------------------------+-------------------+----------------------------------+
```
- **Hằng số `MIN_DISCO_PACKET_LEN = 172` (`IMP-G2-01`)**:
  $$\text{MIN\_DISCO\_PACKET\_LEN} = 63\text{ B (Outer Header)} + 93\text{ B (Inner DiscoPayload Header)} + 16\text{ B (Poly1305 Tag)} = 172\text{ bytes}$$
  (Đúng bằng kích thước một gói `DiscoPing` hoàn chỉnh vì body của `DiscoPing` là `0 B`).

#### (b) Inner Encrypted `DiscoPayload` Header (`93 bytes` cố định + Body theo `msg_type`)
Sau khi mở hộp `SalsaBox` và xác thực Poly1305 tag 16-byte:
```text
+--------------------+---------------+-------------------+----------------------+----------------------------+-------------------------------+-------------+
| Bytes 0..8 (8B)    | Byte 8 (1B)   | Bytes 9..21 (12B) | Bytes 21..29 (8B BE) | Bytes 29..61 (32B)         | Bytes 61..93 (32B)            | Bytes 93..M |
| magic_ctx="MESHDSv1"| msg_type (u8) | tx_id ([u8; 12])  | sent_at_ms (u64 UTC) | inner_sender_disco_pubkey  | inner_recipient_disco_pubkey  | Body        |
+--------------------+---------------+-------------------+----------------------+----------------------------+-------------------------------+-------------+
```

#### (c) Quy Tắc Kiểm Chứng Chống Phản Xạ Bắt Buộc Trước Khi Xử Lý (`Codex #2`)
Khi node `Self` (có khóa `self_disco_pubkey`) nhận được một khung `b"MESHDS"` (`buf.len() >= 172`):
1. **Kiểm tra trước giải mã**:
   - Kiểm tra `buf[0..6] == *b"MESHDS"` và `buf[6] == 0x01`.
   - Đọc `outer_sender_disco_pubkey = buf[7..39]`. **Bắt buộc `outer_sender_disco_pubkey != self_disco_pubkey`** (loại bỏ ngay gói tự phản xạ trước khi tốn CPU giải mã).
   - Tra `outer_sender_disco_pubkey` trong `PeerMap`: phải thuộc một peer đang `Active`.
2. **Kiểm tra sau khi mở `SalsaBox` (`plaintext.len() >= 93`)**:
   - Kiểm tra `plaintext[0..8] == *b"MESHDSv1"`.
   - Kiểm tra **`bool::from(plaintext[29..61].ct_eq(&outer_sender_disco_pubkey))`** (`inner_sender == outer_sender`).
   - Kiểm tra **`bool::from(plaintext[61..93].ct_eq(self_disco_pubkey.as_bytes()))`** (`inner_recipient == self_disco_pubkey`).
   - Nếu bất kỳ điều kiện nào trên thất bại $\to$ **hủy gói ngay lập tức**, tăng bộ đếm `mesh_agent_disco_invalid_packets_total` và tuyệt đối không phản hồi hay cập nhật trạng thái! (Bắt buộc có unit test chứng minh gói `Ping`/`Pong` của A bị kẻ tấn công sửa `outer_sender_disco_pubkey = B_pub` rồi dội ngược về A bị từ chối 100%).

#### (d) Tách Biệt `IngressSource` Chống Đầu Độc Đường Đi Qua Blind Relay (`HR-G2-04`)
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressSource {
    /// Arrived directly on MagicSocket UDP from `remote_addr`.
    DirectUdp(SocketAddr),
    /// Arrived via Blind Relay WebSocket frame `0x02` with `src_node_pubkey` authenticated by mesh-server.
    Relay { verified_src_node_pubkey: PublicKey },
}
```

| `msg_type` | Tên Bản Tin | Nội dung `Body` (Bytes `93..M`) | Quy tắc Xử lý theo `IngressSource` (`Codex #2`, `HR-G2-04`, `US-021 AC2/AC5`) |
|---:|---|---|---|
| **`0x01`** | `DiscoPing` | *(Rỗng — `0 bytes`; tổng gói = đúng `172 bytes`)* | - Nếu `IngressSource::Relay { verified_src_node_pubkey }`: kiểm tra thêm `peer.node_pubkey == verified_src_node_pubkey` (chống peer C mạo danh khóa disco qua Relay); phản hồi `DiscoPong` qua Relay với `observed_addr = 0.0.0.0:0`.<br/>- Nếu `IngressSource::DirectUdp(remote_addr)`: phản hồi `DiscoPong` trực tiếp qua UDP tới `remote_addr` mang đúng `tx_id` vừa nhận và `observed_addr = remote_addr` (có giới hạn tốc độ chống bão). |
| **`0x02`** | `DiscoPong` | `[addr_family: 1B (0x04=IPv4, 0x06=IPv6)][observed_ip: 4B hoặc 16B][observed_port: u16 BE (2B)]`<br/>*(`7 bytes` cho IPv4 $\to$ tổng gói `179 B`; `19 bytes` cho IPv6 $\to$ tổng gói `191 B`)* | Tra `tx_id` trong bảng `pending_pings` (TTL **10 giây**, xóa ngay sau khi khớp 1 lần) và kiểm tra `pending.peer_disco_pubkey == inner_sender_disco_pubkey`.<br/>- **Nếu đến từ `IngressSource::Relay { verified_src_node_pubkey }`**: kiểm tra `peer.node_pubkey == verified_src_node_pubkey` rồi **CHỈ ghi nhận mẫu RTT `via: "relay"` cho lệnh `mesh ping` (`US-040 AC1`); TUYỆT ĐỐI CẤM cập nhật `PeerSession::direct_addr` hoặc nâng cấp `ActivePath` sang `Direct`!**<br/>- **Chỉ khi đến từ `IngressSource::DirectUdp(remote_addr)`** (và `remote_addr` hợp lệ qua `is_valid_candidate_endpoint`): mới được phép cập nhật `PeerSession::direct_addr = Some(remote_addr)` và nâng cấp `ActivePath` sang `Direct(remote_addr)`! |
| **`0x03`** | `DiscoCallMeMaybe` | `[endpoint_count: u8 (1..=16)]` theo sau bởi danh sách `[addr_family: 1B][ip: 4B/16B][port_be: 2B]` | Nhận qua `ServerControlFrame::CallMeMaybeRelay` (hoặc Relay); sau khi vượt qua kiểm tra chống phản xạ (mục c), lọc các `endpoints` qua `is_valid_candidate_endpoint()` và kích hoạt bắn `DiscoPing` đồng thời trên `MagicSocket` UDP tới các ứng viên của peer (giới hạn ≤ 10 đợt/phút/peer). |

---

## 4. Server Local Admin IPC API (`SEC-14`, `ADR-006`, `US-012`, `US-056`, `BLK-G2-03`, `Codex R2 #2, #3`)

- **Kênh truyền tải duy nhất**: HTTP/1.1 JSON qua **Unix Domain Socket `/run/mesh-server/admin.sock`** (thư mục runtime **`/run/mesh-server`** qua `RuntimeDirectory=mesh-server`, mode **`0750`**, owner **`mesh:mesh-admin`**; quyền socket **`0660`**, owner **`mesh:mesh-admin`**).
  - **Tách riêng thư mục runtime IPC khỏi `meshd` (`Codex R2 #3`)**: Trên Ubuntu Linux, `/var/run` là symlink tới `/run`. Việc đặt socket của `mesh-server` tại `/run/mesh-server/admin.sock` (`0750 mesh:mesh-admin`) tách biệt hoàn toàn với thư mục `/var/run/meshd` (`/run/meshd` `0755 root:root`) của `meshd` khi VPS kiêm node `vps.mesh.internal` (`US-056`), ngăn chặn 100% lỗi hai dịch vụ ghi đè quyền thư mục của nhau theo bất kỳ thứ tự khởi động nào.
- **Kiểm chứng đặc quyền OS bắt buộc (Bao gồm cả Supplementary Groups — `BLK-G2-03`, `US-012 AC4`, `SEC-14 AC(c)`)**:
  - Middleware đầu tiên của `admin_service.rs` gọi `crates/mesh-sys::ipc_linux::verify_admin_peer_cred(stream, mesh_uid, mesh_admin_gid)`:
    1. Đọc `(pid, uid, primary_gid)` từ `getsockopt(fd, SOL_SOCKET, SO_PEERCRED)`.
    2. Nếu `uid == 0` (`root`), `uid == mesh_uid`, hoặc `primary_gid == mesh_admin_gid` $\to$ **Chấp nhận ngay**.
    3. Ngược lại, truy vấn tên user từ `uid` bằng `libc::getpwuid_r` (buffer `4096 B` trên stack/vec) rồi gọi **`libc::getgrouplist`** để lấy toàn bộ danh sách **nhóm phụ (supplementary groups)** của `uid`: nếu danh sách nhóm phụ chứa `mesh_admin_gid` $\to$ **Chấp nhận** (đảm bảo tài khoản admin chạy SSH thuộc nhóm phụ `mesh-admin` với primary group `uid == 1000` không bao giờ bị từ chối nhầm!).
    4. Mọi tiến trình khác (vd. `www-data`, container, user thường không thuộc `mesh-admin`) bị từ chối ngay với `403 Forbidden` (`ErrorKind::PermissionDenied`) và ghi vào `audit_events` (`SEC-14(1)`).
- **Tuyệt đối cấm** gắn router này vào bất kỳ TCP listener nào (`127.0.0.1`, IP overlay hay IP public).

### 4.1. Bảng Toàn Bộ Các Endpoint Quản Trị Trên `/run/mesh-server/admin.sock`

| Method & Path | Ánh xạ `US-xxx` | Lệnh CLI `mesh` Tương Ứng | Mô tả Hành vi & Ghi Audit |
|---|---|---|---|
| `POST /v1/admin/preauth-keys` | `US-002`, `US-006`, `US-031` | `mesh preauthkey create [--ttl 1h] [--reusable --max-uses N] [--ephemeral] [--for <node>]` | Sinh key 256-bit từ `OsRng`, chỉ lưu `sha256` vào `redb`, trả `raw_key` **đúng 1 lần** kèm chuỗi `join_command` đầy đủ (`IP:port` + `active_pin`). Ghi audit `preauthkey_created`. |
| `GET /v1/admin/preauth-keys` | `US-002 AC2` | `mesh preauthkey list` | Liệt kê danh sách metadata của các key (`key_id`, `status`, `expires_at_ms`, `target_node_id`, `used_count`/`max_uses`); **không bao giờ trả key rõ**. |
| `POST /v1/admin/preauth-keys/{key_id}/revoke` | `US-002 AC4`, `US-013 AC4`, `Codex R2 #2` | `mesh preauthkey revoke <key_id>` | Đưa `key_id` vào `RevokedSet` RAM ngay lập tức (< 100 ms, `ram_enforced: true`) rồi ghi bền và trả rõ `persistence_tier: "redb" \| "emergency_slot" \| "ram_only"` (xem mẫu response bên dưới). |
| `GET /v1/admin/nodes` | `US-012 AC1`, `US-050 AC1` | `mesh node list` | Liệt kê toàn bộ node kèm `overlay_ip`, `status`, `online`, `last_seen_at_ms`, `key_expires_at_ms`, `os`/`arch`, `agent_version` (≤ 1 s). |
| `GET /v1/admin/nodes/{node_ref}` | `US-012 AC1` | `mesh node inspect <id\|name>` | Xem chi tiết 1 node theo `NodeId` hoặc `name_normalized`. |
| `POST /v1/admin/nodes/{node_ref}/rename` | `US-012 AC2` | `mesh node rename <id\|name> <new_name>` | Kiểm tra `NodeName` hợp lệ + không thuộc danh sách cấm/trùng lặp (`US-004 AC3`), cập nhật `idx_nodes_name`, cấp `netmap_version` mới qua `MonotonicNetmapVersion`, đẩy Netmap mới (P95 ≤ 5 s) và ghi audit `node_renamed`. |
| `POST /v1/admin/nodes/{node_ref}/revoke` | `US-029`, `US-013 AC4`, `HR-G2-03`, `Codex R2 #2` | `mesh node revoke <id\|name>` | **Khẩn cấp**: Đưa vào `RevokedSet` RAM + ngắt Relay/Control (< 100 ms, `ram_enforced: true`) + đẩy Netmap xóa peer tới toàn mạng + cách ly IP 24h (`US-029 AC5`) + ghi bền theo 3 mức `persistence_tier: "redb" \| "emergency_slot" \| "ram_only"`. |
| `POST /v1/admin/nodes/{node_ref}/expire` | `US-012 AC3`, `US-031 AC1/AC2`, `Codex R2 #2` | `mesh node expire <id\|name> [--never]` | Hết hạn khóa node ngay lập tức (buộc đăng ký lại bằng key `--for <node>`, trả rõ `persistence_tier`) hoặc đặt `key_expires_at_ms = None` (`--never` cho server tin cậy); ghi audit `node_expiry_updated`. |
| `GET /v1/admin/server/status` | `US-012 AC6`, `US-074 AC7` | `mesh server status` (hoặc `mesh server info`) | Trả về cổng TCP/UDP hiện hành, `tls_mode`, `active_pin`, `next_pin`, hạn chứng chỉ TLS, trạng thái `ListenerSet` và **danh sách các node chưa xác nhận `endpoint_version` mới** khi đang chuyển tiếp cổng. |
| `POST /v1/admin/server/backup` | `US-045 AC1` | `mesh server backup` | Thực thi Hot Atomic Snapshot Backup ngay lập tức (kèm `server_identity` và `.sha256`, giữ 7 bản); ghi audit `server_backup_created`. |
| `POST /v1/admin/server/migrate-endpoint` | `US-074 AC1..AC8`, `SEC-15` | `mesh server migrate-endpoint [--host ...] [--tcp-port ...] [--stun-port ...] [--tls-mode ...] [--extend-window 24h]` | Kiểm tra cổng mới không bị chiếm (`US-046 AC5`), mở `ListenerSet` nghe song song cổng cũ + mới trong `transition_window`, tăng `endpoint_version` & `netmap_version`, đẩy `relay_map` mới qua kênh đã xác thực; ghi audit `server_endpoint_migrated`. |
| `POST /v1/admin/server/rotate-tls-key` | `US-047 AC5` | `mesh server rotate-tls-key --stage \| --promote` | `--stage`: sinh khóa ECDSA P-256 kế tiếp, công bố `next_pin` trong `PinSet` qua Netmap trước; `--promote`: chuyển `next_pin` thành `active_pin` mà không làm rớt bất kỳ client online nào. |
| `GET /v1/admin/audit-events` | `US-013 AC1/AC2` | `mesh audit list [--limit 100]` | Đọc danh sách bản ghi từ bảng append-only `audit_events`. |

#### Mẫu DTO `POST /v1/admin/nodes/{node_ref}/revoke`, `expire` & `POST /v1/admin/preauth-keys/{key_id}/revoke` (`US-013 AC4`, `US-029`, `Codex R2 #2`)
Response (`200 OK`):
```json
{
  "revoked": true,
  "ram_enforced": true,
  "persisted": true,
  "persistence_tier": "redb"
}
```
> **Ngữ nghĩa 3 giá trị của `persistence_tier` (`Codex R2 #2`)**:
> 1. **`"redb"`** (`persisted: true, ram_enforced: true`): Đã cắt kết nối trong RAM (`< 100 ms`) và đã commit bền vững vào `/var/lib/mesh/control.redb`.
> 2. **`"emergency_slot"`** (`persisted: true, ram_enforced: true`): `redb` gặp lỗi đầy đĩa (`ENOSPC`), nhưng đã ghi đè tại chỗ (`pwrite` + `sync_data`, 0 xin thêm block filesystem mới) thành công vào `Slot A/B` của `/var/lib/mesh/emergency-revocations.bin`; đặt `disk_degraded = true`, `/readyz = 503`, xuất log `CRITICAL`.
> 3. **`"ram_only"`** (`persisted: false, ram_enforced: true`): Cả `redb` lẫn `pwrite`+`sync_data` trên slot cấp cứu đều gặp lỗi phần cứng (`EIO`/`EROFS`) hoặc số mục chưa hợp nhất đã chạm trần cứng (`500` nodes / `250` keys). Vẫn cắt kết nối ngay trong `RevokedSet` RAM (`< 100 ms`), không ghi đè làm mất mục thu hồi cũ trên đĩa, đặt `disk_degraded = true`, `/readyz = 503`, xuất log `CRITICAL`, và CLI `mesh` in cảnh báo khẩn cấp ra `stderr` yêu cầu quản trị viên sửa ổ đĩa trước khi khởi động lại `mesh-server`.

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

## 5. Client Local CLI ↔ Daemon IPC API (`ADR-006`, `BLK-G2-03`, `Codex #11`, `Codex R2 #3`, `US-039..041`, `US-052`, `US-056`, `US-073`, `US-074`)

### 5.1. Kiến Trúc Tách 2 Điểm Cuối IPC Theo Mức Đặc Quyền (`meshd-ro` vs `meshd-admin` — `BLK-G2-03`, `Codex #11`, `Codex R2 #3`, `US-039 AC5`)

Để đảm bảo tài khoản người dùng thường (non-admin / không `sudo`) luôn chạy được `mesh status`, `mesh peers`, `mesh ping`, `mesh netcheck` (`US-039 AC5`) trong khi mọi thao tác thay đổi cấu hình/mạng hoặc xuất bundle chẩn đoán (`up`, `down`, `cleanup`, `set`, `rotate-key`, `bugreport`) đều bị khóa cứng ở cả tầng quyền tệp OS lẫn tầng xác thực credential của kernel — đồng thời không bao giờ xung đột thư mục runtime với `/run/mesh-server` trên Ubuntu Linux (`Codex R2 #3`) — `meshd` trên cả 3 hệ điều hành đều mở **2 listener IPC tách biệt với 2 `axum::Router` hoàn toàn độc lập**:

| Hệ điều hành | **Kênh 1: Read-Only IPC (`meshd-ro`)**<br/>Chỉ gắn 4 route đọc: `GET /v1/agent/status`, `GET /v1/agent/peers`, `POST /v1/agent/ping`, `POST /v1/agent/netcheck` (`DefaultBodyLimit::max(4096)`, **0 secret**) | **Kênh 2: Privileged Admin IPC (`meshd-admin`)**<br/>Gắn toàn bộ route đặc quyền (`up`, `down`, `cleanup`, `set`, `rotate-key`, `bugreport`) + các route đọc |
|---|---|---|
| **macOS 13+** (`US-073 AC3/AC4`, `BLK-G2-03`, `Codex #11`, `Codex R2 #3`) | **`/var/run/meshd/meshd-ro.sock`**<br/>- Thư mục **`/var/run/meshd`** (`0755 root:wheel`, kiểm tra chống symlink trên các thành phần cha)<br/>- Socket mode **`0666 root:wheel`**<br/>- Cho phép mọi user cục bộ gọi `mesh status` / `mesh ping` / `mesh netcheck` không cần `sudo`. | **`/var/run/meshd/meshd-admin.sock`**<br/>- Thư mục **`/var/run/meshd`** (`0755 root:wheel`)<br/>- Socket mode **`0660 root:admin`** (`gid = 80`)<br/>- Kiểm tra trong `crates/mesh-sys::ipc_macos`: lấy `euid` qua `libc::getpeereid(fd)` và đọc đầy đủ `libc::xucred` qua `getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, ...)`. Chỉ chấp nhận nếu **`euid == 0` (`root`) HOẶC mảng `xucred.cr_groups[..xucred.cr_ngroups as usize]` chứa `80` (`admin`)** (kèm fallback `getpwuid_r` + `getgrouplist` khi `cr_ngroups == XU_NGROUPS` = 16). |
| **Windows 10/11** (`US-052 AC3`, `BLK-G2-03`) | **`\\.\pipe\mesh-agent-ro`**<br/>- Tạo với `FILE_FLAG_FIRST_PIPE_INSTANCE` + SDDL DACL **`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)`** (cho phép `Authenticated Users` mở pipe chỉ-đọc). | **`\\.\pipe\mesh-agent-admin`**<br/>- Tạo với `FILE_FLAG_FIRST_PIPE_INSTANCE` + SDDL DACL **`D:P(A;;GA;;;SY)(A;;GA;;;BA)`** (chỉ `LocalSystem` và `Administrators` mở được pipe). |
| **Linux (Node/Lab & `vps.mesh.internal`)** (`US-056`, `BLK-G2-03`, `Codex R2 #3`) | **`/var/run/meshd/meshd-ro.sock`** *(tương ứng `/run/meshd/meshd-ro.sock` qua `RuntimeDirectory=meshd`)*<br/>- Thư mục **`/var/run/meshd`** (`0755 root:root`, kiểm tra chống symlink trên các thành phần cha)<br/>- Socket mode **`0666 root:root`**. | **`/var/run/meshd/meshd-admin.sock`** *(tương ứng `/run/meshd/meshd-admin.sock` qua `RuntimeDirectory=meshd`)*<br/>- Thư mục **`/var/run/meshd`** (`0755 root:root`)<br/>- Socket mode **`0660 root:mesh-admin`** (hoặc **`0600 root:root`** nếu nhóm `mesh-admin` chưa tồn tại trên máy lẻ)<br/>- Kiểm tra `SO_PEERCRED` (`uid == 0` hoặc `primary_gid == mesh_admin_gid`) + `getpwuid_r` & `getgrouplist` kiểm tra nhóm phụ `mesh-admin`. |

> **Kiểm thử Co-Residency bắt buộc cho `US-056` (`Codex R2 #3`)**: Kịch bản kiểm thử tự động bắt buộc xác minh khởi động `mesh-server` trước `meshd` **VÀ** `meshd` trước `mesh-server` trên cùng Ubuntu Linux host đều giữ nguyên quyền của cả 3 socket (`/run/mesh-server/admin.sock`, `/var/run/meshd/meshd-admin.sock`, `/var/run/meshd/meshd-ro.sock`).

---

### 5.2. Đặc Tả Các Endpoint Trên Local Agent IPC

#### (1) `GET /v1/agent/status` & `GET /v1/agent/peers` — Trạng Thái Toàn Diện Của Agent & Peer (`US-039 AC1..AC7`, trên cả `meshd-ro` & `meshd-admin`)
Response (`200 OK` — hoàn tất ≤ 1 s, hỗ trợ `mesh status`, `mesh status --json`, `mesh peers`):
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

#### (2) `POST /v1/agent/ping` — Ping Tầng Disco/Overlay Quan Sát Nâng Cấp Relay $\to$ Direct (`US-040`, trên cả `meshd-ro` & `meshd-admin`)
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

#### (3) `POST /v1/agent/netcheck` — Chẩn Đoán NAT, UDP, STUN & Cổng TCP Tùy Chỉnh (`US-023`, `REL-06`, trên cả `meshd-ro` & `meshd-admin`)
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

#### (4) `POST /v1/agent/bugreport` — Tạo Bundle Chẩn Đoán Đã Lọc Sạch Secret (`US-041`, CHỈ trên `meshd-admin`)
Response (`200 OK`): trả về đường dẫn tệp nén `.tar.gz`/`.zip` (≤ 20 MB) chứa log đã lọc, `status --json`, bảng route và cấu hình đã che `"[REDACTED]"` (`0` byte private key / pre-auth key).

#### (5) Nhóm Lệnh Đặc Quyền (`POST /v1/agent/up`, `down`, `cleanup`, `set`, `rotate-key` — CHỈ trên `meshd-admin`)
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
- **`POST /v1/agent/down`** & **`POST /v1/agent/cleanup`** (`US-055 AC3`): Thực thi `ResourceLedger::cleanup_all()` idempotent, gỡ route (và `ip rule`/bảng `51820` trên Linux), xóa khối `# BEGIN mesh … # END mesh` trong `hosts`, đóng `utunN`/Wintun và trả máy về trạng thái sạch.

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
| `mesh_agent_disco_invalid_packets_total` | `counter` | `reason="self_reflection\|recipient_mismatch\|sender_mismatch\|bad_mac\|tx_miss"` | Số gói Disco bị hủy do phản xạ hai chiều, sai khóa người nhận/người gửi hoặc sai MAC (`Codex #2`, `HR-G2-04`). |
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
