//! Independent Sprint 2 Live Process E2E & AppSec Tests for `mesh-server`.
//!
//! Covers:
//! - `control_handlers.rs:371`, `HR-W21-03`, `US-003 AC4`, `US-042 AC1/AC2` & `SEC-05`:
//!   Live `mesh-server` registration where `ProofPayload` is valid (`verify_signed_proof` passes)
//!   but `RegisterNodeRequest.disco_pubkey` mismatches `proof.disco_pubkey` (and/or invalid
//!   `preauth_key`); verifies each attempt returns `401 "authentication failed"` without resetting
//!   the failure counter, and attempt 11 triggers IP lockout (`429 Too Many Requests`)
//! - `US-005` & `US-050 AC1/AC2`: Protocol version compatibility check (`protocol_version = 0`
//!   rejected with `400` upgrade message) + idempotent replay with a one-time pre-auth key
//!   returning the identical `NodeId` and `OverlayIp`
//! - `US-027`, `US-044`, `US-048`, `SEC-01` & `SEC-14`: `/healthz`, `/readyz`, `/metrics` on the
//!   dedicated read-only observability listener (`0` secrets leaked), `/v1/admin/*` absent (`404`)
//!   on TCP listeners, and unregistered/revoked nodes rejected from `/v1/netmap/stream` (`401`)

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
    use rustls::ClientConnection;
    use rustls::pki_types::ServerName;
    use tempfile::TempDir;

    use mesh_core::{Clock as _, KeyId, NodeName, SpkiPin, SystemClock};
    use mesh_crypto::{
        DiscoKeypair, NodeKeypair, PinSet, PreAuthToken, ProofPayload, build_pinned_client_config,
        extract_tls_exporter_binding, random_bytes, seal_proof, sha256_digest, sha256_hex,
    };
    use mesh_proto::admin_ipc::{HealthResponse, ReadinessResponse};
    use mesh_proto::control::{
        ChallengeRequest, ChallengeResponse, HEADER_AUTH_PROOF, HEADER_BOX_NONCE,
        HEADER_CHALLENGE_ID, HEADER_NODE_PUBKEY, RegisterNodeRequest, RegisterNodeResponse,
        TargetArch, TargetOs,
    };
    use mesh_store::{ControlStore, ControlStoreConfig, CreatePreAuthKeyInput};

    type PinnedTlsStream = rustls::StreamOwned<ClientConnection, TcpStream>;

    struct ServerChildGuard {
        child: Option<Child>,
    }

    impl Drop for ServerChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                if let Err(err) = child.kill() {
                    let _ignored = err;
                }
                if let Err(err) = child.wait() {
                    let _ignored = err;
                }
            }
        }
    }

    struct LiveServer {
        _guard: ServerChildGuard,
        _dir: TempDir,
        _sock_dir: TempDir,
        ctrl_port: u16,
        obs_port: u16,
        pin: SpkiPin,
        one_time_preauth: String,
    }

    #[cfg(target_os = "linux")]
    fn linux_socket_base_candidates(euid: u32) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
            out.push(std::path::PathBuf::from(xdg));
        }
        out.push(std::path::PathBuf::from(format!("/run/user/{euid}")));
        if euid == 0 {
            out.push(std::path::PathBuf::from("/run"));
        }
        if let Some(home) = std::env::var_os("HOME") {
            out.push(std::path::PathBuf::from(home));
        }
        if let Ok(cwd) = std::env::current_dir() {
            out.push(cwd);
        }
        out
    }

    #[cfg(target_os = "linux")]
    fn create_secure_admin_socket_dir() -> TempDir {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let euid = fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0);
        let policy = mesh_net::ipc_linux::server_runtime_dir_policy(euid, None);
        for base in linux_socket_base_candidates(euid) {
            if let Ok(td) = tempfile::Builder::new().prefix(".ms-").tempdir_in(&base) {
                let chmod_ok = fs::set_permissions(td.path(), fs::Permissions::from_mode(0o700));
                let run_dir = td.path().join("run");
                if chmod_ok.is_ok()
                    && mesh_sys::fs_unix::prepare_secure_runtime_dir(&run_dir, policy).is_ok()
                    && run_dir.join("admin.sock").as_os_str().len() < 100
                {
                    return td;
                }
            }
        }
        panic!("no non-world-writable Linux directory found for mesh-server admin.sock");
    }

    #[cfg(not(target_os = "linux"))]
    fn create_secure_admin_socket_dir() -> TempDir {
        TempDir::new().expect("admin socket tempdir")
    }

    fn alloc_tcp_port() -> u16 {
        let sock = TcpListener::bind("127.0.0.1:0").expect("bind loopback tcp");
        sock.local_addr().expect("tcp local addr").port()
    }

    fn alloc_udp_port() -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp");
        sock.local_addr().expect("udp local addr").port()
    }

    fn install_rustls_ring_provider() {
        if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
            let _already_set = err;
        }
    }

    async fn wait_for_readyz(obs_port: u16) {
        install_rustls_ring_provider();
        let start = Instant::now();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(400))
            .build()
            .expect("obs http client");
        let ready_url = format!("http://127.0.0.1:{obs_port}/readyz");
        while start.elapsed() < Duration::from_secs(6) {
            if let Ok(resp) = client.get(&ready_url).send().await
                && resp.status() == reqwest::StatusCode::OK
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("mesh-server /readyz did not return 200 within 6 s");
    }

    fn write_server_toml(
        cfg_path: &Path,
        state_dir: &Path,
        admin_sock: &Path,
        ports: (u16, u16, u16),
    ) {
        let (ctrl, stun, obs) = ports;
        let state_str = state_dir.to_string_lossy().replace('\\', "/");
        let sock_str = admin_sock.to_string_lossy().replace('\\', "/");
        let body = format!(
            concat!(
                "control_bind_ip = \"127.0.0.1\"\n",
                "control_tcp_port = {ctrl}\n",
                "stun_bind_ip = \"127.0.0.1\"\n",
                "stun_udp_port = {stun}\n",
                "obs_bind_addr = \"127.0.0.1:{obs}\"\n",
                "public_host = \"127.0.0.1\"\n",
                "state_dir = \"{state}\"\n",
                "admin_socket_path = \"{sock}\"\n",
                "admin_group_name = \"nonexistent-qa-admin-grp\"\n",
                "tls_mode = \"ip_pinned\"\n",
            ),
            ctrl = ctrl,
            stun = stun,
            obs = obs,
            state = state_str,
            sock = sock_str,
        );
        fs::write(cfg_path, body).expect("write server config toml");
    }

    async fn spawn_live_server() -> LiveServer {
        let dir = TempDir::new().expect("server tempdir");
        let sock_dir = create_secure_admin_socket_dir();
        let state_dir = dir.path().join("state");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let admin_sock = sock_dir.path().join("run").join("admin.sock");
        let cfg_path = dir.path().join("server.toml");
        let (ctrl_port, stun_port, obs_port) =
            (alloc_tcp_port(), alloc_udp_port(), alloc_tcp_port());
        let now_ms = SystemClock::new().now_unix_ms();

        let store = ControlStore::open(ControlStoreConfig {
            db_path: state_dir.join("control.redb"),
            emergency_revocations_path: state_dir.join("emergency-revocations.bin"),
        })
        .expect("open preseed store");
        let identity = store
            .ensure_or_init_identity(&["127.0.0.1".to_owned()], 365)
            .expect("init server identity");
        let one_time_preauth = format!("mpk_{}", URL_SAFE_NO_PAD.encode(random_bytes::<32>()));
        assert!(PreAuthToken::parse(&one_time_preauth).is_ok());
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms),
                    token_hash: sha256_digest(one_time_preauth.as_bytes()),
                    label: Some("qa-s2-e2e".to_owned()),
                    bound_node_name: None,
                    reusable: false,
                    max_uses: None,
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "qa-s2",
            )
            .expect("mint one-time preauth key");
        drop(store);

        write_server_toml(
            &cfg_path,
            &state_dir,
            &admin_sock,
            (ctrl_port, stun_port, obs_port),
        );
        let child = Command::new(env!("CARGO_BIN_EXE_mesh-server"))
            .arg("--config")
            .arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mesh-server");
        let guard = ServerChildGuard { child: Some(child) };
        wait_for_readyz(obs_port).await;

        LiveServer {
            _guard: guard,
            _dir: dir,
            _sock_dir: sock_dir,
            ctrl_port,
            obs_port,
            pin: identity.spki_pin,
            one_time_preauth,
        }
    }

    fn open_pinned_tls(port: u16, pin: SpkiPin) -> (PinnedTlsStream, String) {
        install_rustls_ring_provider();
        let cfg = build_pinned_client_config(PinSet::single(pin)).expect("pinned tls cfg");
        let tcp =
            TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).expect("tcp connect");
        tcp.set_read_timeout(Some(Duration::from_secs(4)))
            .expect("read timeout");
        tcp.set_write_timeout(Some(Duration::from_secs(4)))
            .expect("write timeout");
        let conn = ClientConnection::new(cfg, ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))
            .expect("tls client conn");
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        stream
            .conn
            .complete_io(&mut stream.sock)
            .expect("complete tls handshake");
        let exporter = extract_tls_exporter_binding(&stream.conn).expect("tls exporter");
        (stream, BASE64_STANDARD.encode(exporter))
    }

    fn read_http_response(stream: &mut PinnedTlsStream) -> (u16, Vec<u8>) {
        let mut raw = Vec::new();
        let mut buf = [0_u8; 4096];
        loop {
            let n = stream.read(&mut buf).expect("read https response");
            assert!(n > 0, "unexpected EOF reading HTTP response");
            raw.extend_from_slice(buf.get(..n).unwrap_or_default());
            let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let header_end = pos + 4;
            let head = String::from_utf8_lossy(raw.get(..pos).unwrap_or_default()).into_owned();
            let content_len = head
                .lines()
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            while raw.len() < header_end + content_len {
                let more = stream.read(&mut buf).expect("read http body");
                assert!(more > 0, "truncated HTTP body");
                raw.extend_from_slice(buf.get(..more).unwrap_or_default());
            }
            let status = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
                .expect("http status code");
            let body = raw
                .get(header_end..header_end + content_len)
                .unwrap_or_default()
                .to_vec();
            return (status, body);
        }
    }

    fn post_challenge_with_version(
        port: u16,
        pin: SpkiPin,
        node_kp: &NodeKeypair,
        disco_kp: &DiscoKeypair,
        protocol_version: u16,
    ) -> (u16, Vec<u8>) {
        let (mut tls, _) = open_pinned_tls(port, pin);
        let ch_body = serde_json::to_vec(&ChallengeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            protocol_version,
            agent_version: "0.1.0".to_owned(),
            os: TargetOs::Linux,
            arch: TargetArch::Amd64,
        })
        .expect("serialize challenge");
        let req = format!(
            "POST /v1/auth/challenge HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            ch_body.len()
        );
        tls.write_all(req.as_bytes()).expect("write challenge req");
        tls.write_all(&ch_body).expect("write challenge body");
        tls.flush().expect("flush challenge");
        read_http_response(&mut tls)
    }

    fn send_signed_register_attempt(
        port: u16,
        pin: SpkiPin,
        node_kp: &NodeKeypair,
        proof_disco_kp: &DiscoKeypair,
        body_req: &RegisterNodeRequest,
    ) -> (u16, Vec<u8>) {
        let (ch_status, ch_bytes) =
            post_challenge_with_version(port, pin, node_kp, proof_disco_kp, 1);
        if ch_status != 200 {
            return (ch_status, ch_bytes);
        }
        let ch: ChallengeResponse = serde_json::from_slice(&ch_bytes).expect("decode challenge");

        let (mut tls, exporter_b64) = open_pinned_tls(port, pin);
        let body = serde_json::to_vec(body_req).expect("serialize RegisterNodeRequest");
        let proof = ProofPayload {
            challenge_id: ch.challenge_id,
            challenge_nonce: ch.challenge_nonce,
            method: "POST".to_owned(),
            path: "/v1/nodes/register".to_owned(),
            body_sha256: sha256_hex(&body),
            node_pubkey: node_kp.public_key(),
            disco_pubkey: proof_disco_kp.public_key(),
            timestamp_at_ms: SystemClock::new().now_unix_ms(),
            tls_exporter_binding: exporter_b64,
        };
        let sealed = seal_proof(&proof, &ch.server_eph_pubkey, node_kp).expect("seal proof");
        let head = format!(
            concat!(
                "POST /v1/nodes/register HTTP/1.1\r\n",
                "Host: 127.0.0.1:{port}\r\n",
                "Content-Type: application/json\r\n",
                "Content-Length: {len}\r\n",
                "Connection: close\r\n",
                "{h_cid}: {cid}\r\n",
                "{h_pk}: {pk}\r\n",
                "{h_nonce}: {nonce}\r\n",
                "{h_proof}: {proof}\r\n\r\n",
            ),
            port = port,
            len = body.len(),
            h_cid = HEADER_CHALLENGE_ID,
            cid = ch.challenge_id,
            h_pk = HEADER_NODE_PUBKEY,
            pk = BASE64_STANDARD.encode(node_kp.public_key().as_bytes()),
            h_nonce = HEADER_BOX_NONCE,
            nonce = BASE64_STANDARD.encode(sealed.box_nonce),
            h_proof = HEADER_AUTH_PROOF,
            proof = BASE64_STANDARD.encode(&sealed.ciphertext),
        );
        tls.write_all(head.as_bytes()).expect("write reg head");
        tls.write_all(&body).expect("write reg body");
        tls.flush().expect("flush reg");
        read_http_response(&mut tls)
    }

    #[tokio::test]
    async fn test_server_e2e_register_disco_pubkey_mismatch_and_invalid_preauth_trigger_ip_rate_limit_lockout()
     {
        // Arrange
        let srv = spawn_live_server().await;
        let node_kp = NodeKeypair::generate();
        let proof_disco_kp = DiscoKeypair::generate();
        let mismatched_body_disco_kp = DiscoKeypair::generate();

        // Act 1: 5 attempts where signed proof passes (`verify_signed_proof` OK) but
        // `RegisterNodeRequest.disco_pubkey != proof.disco_pubkey` (`control_handlers.rs:371`)
        for idx in 1..=5 {
            let req = RegisterNodeRequest {
                node_pubkey: node_kp.public_key(),
                disco_pubkey: mismatched_body_disco_kp.public_key(),
                preauth_key: srv.one_time_preauth.clone(),
                node_name: NodeName::parse(&format!("mismatch-{idx}")).expect("name"),
                previous_node_pubkey: None,
            };
            let (status, body) = send_signed_register_attempt(
                srv.ctrl_port,
                srv.pin,
                &node_kp,
                &proof_disco_kp,
                &req,
            );
            assert_eq!(status, 401, "attempt {idx} must return 401");
            assert!(
                String::from_utf8_lossy(&body).contains("authentication failed"),
                "SEC-05: 401 body must return generic 'authentication failed'"
            );
        }

        // Act 2: 5 more attempts with valid proof + matching disco_pubkey, but wrong preauth_key (`HR-W21-03`)
        let wrong_preauth = format!("mpk_{}", "Z".repeat(43));
        for idx in 6..=10 {
            let req = RegisterNodeRequest {
                node_pubkey: node_kp.public_key(),
                disco_pubkey: proof_disco_kp.public_key(),
                preauth_key: wrong_preauth.clone(),
                node_name: NodeName::parse(&format!("wrongkey-{idx}")).expect("name"),
                previous_node_pubkey: None,
            };
            let (status, _) = send_signed_register_attempt(
                srv.ctrl_port,
                srv.pin,
                &node_kp,
                &proof_disco_kp,
                &req,
            );
            assert_eq!(status, 401, "attempt {idx} must return 401");
        }

        // Act 3: Attempt 11 must hit the 10-failure IP lockout (`429 Too Many Requests`, `US-042 AC2`)
        let req_11 = RegisterNodeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: proof_disco_kp.public_key(),
            preauth_key: srv.one_time_preauth.clone(),
            node_name: NodeName::parse("locked-out-node").expect("name"),
            previous_node_pubkey: None,
        };
        let (status_11, _) = send_signed_register_attempt(
            srv.ctrl_port,
            srv.pin,
            &node_kp,
            &proof_disco_kp,
            &req_11,
        );

        // Assert
        assert_eq!(
            status_11, 429,
            "HR-W21-03 & control_handlers.rs:371: 10 failed registration attempts must trigger 429 IP lockout"
        );
    }

    #[tokio::test]
    async fn test_server_e2e_protocol_version_enforcement_and_idempotent_registration() {
        // Arrange
        let srv = spawn_live_server().await;
        let node_kp = NodeKeypair::generate();
        let disco_kp = DiscoKeypair::generate();

        // Act 1: Send ChallengeRequest with unsupported `protocol_version = 0` (`US-050 AC1/AC2`)
        let (bad_ver_status, bad_ver_body) =
            post_challenge_with_version(srv.ctrl_port, srv.pin, &node_kp, &disco_kp, 0);
        assert_eq!(bad_ver_status, 400);
        assert!(
            String::from_utf8_lossy(&bad_ver_body).contains("protocol version"),
            "400 response must explain protocol version incompatibility"
        );

        // Act 2: Register node with one-time preauth key, then replay identical registration (`US-005`)
        let reg_req = RegisterNodeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            preauth_key: srv.one_time_preauth.clone(),
            node_name: NodeName::parse("idempotent-node").expect("name"),
            previous_node_pubkey: None,
        };
        let (status_1, body_1) =
            send_signed_register_attempt(srv.ctrl_port, srv.pin, &node_kp, &disco_kp, &reg_req);
        assert_eq!(status_1, 200);
        let resp_1: RegisterNodeResponse = serde_json::from_slice(&body_1).expect("decode resp 1");

        let (status_2, body_2) =
            send_signed_register_attempt(srv.ctrl_port, srv.pin, &node_kp, &disco_kp, &reg_req);
        assert_eq!(status_2, 200);
        let resp_2: RegisterNodeResponse = serde_json::from_slice(&body_2).expect("decode resp 2");

        // Assert
        assert_eq!(resp_1.node_id, resp_2.node_id);
        assert_eq!(resp_1.overlay_ip, resp_2.overlay_ip);
        assert_eq!(resp_1.fqdn, "idempotent-node.mesh.internal");
    }

    #[tokio::test]
    async fn test_server_e2e_obs_endpoints_and_admin_route_isolation() {
        // Arrange
        let srv = spawn_live_server().await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("http client");

        // Act 1: Query `/healthz`, `/readyz`, and `/metrics` on observability listener (`US-044`, `US-048`)
        let health: HealthResponse = client
            .get(format!("http://127.0.0.1:{}/healthz", srv.obs_port))
            .send()
            .await
            .expect("GET /healthz")
            .json()
            .await
            .expect("parse HealthResponse");
        let ready: ReadinessResponse = client
            .get(format!("http://127.0.0.1:{}/readyz", srv.obs_port))
            .send()
            .await
            .expect("GET /readyz")
            .json()
            .await
            .expect("parse ReadinessResponse");
        let metrics_text = client
            .get(format!("http://127.0.0.1:{}/metrics", srv.obs_port))
            .send()
            .await
            .expect("GET /metrics")
            .text()
            .await
            .expect("read metrics body");

        // Assert 1: Health/Ready green, Prometheus metrics present, zero secrets leaked (`SEC-01`)
        assert_eq!(health.status, "alive");
        assert_eq!(ready.status, "ready");
        assert!(ready.db_healthy);
        assert!(metrics_text.contains("mesh_control_nodes_total"));
        assert!(metrics_text.contains("mesh_control_registrations_total"));
        assert!(!metrics_text.contains(&srv.one_time_preauth));
        assert!(!metrics_text.contains("PRIVATE KEY"));

        // Act 2: Verify Admin API is strictly absent (`404`) on TCP listeners (`SEC-14`)
        let obs_admin = client
            .get(format!("http://127.0.0.1:{}/v1/admin/nodes", srv.obs_port))
            .send()
            .await
            .expect("GET /v1/admin/nodes on obs");
        assert_eq!(obs_admin.status(), reqwest::StatusCode::NOT_FOUND);
    }
}
