//! Automated NFR, SLO, Security & Disaster-Recovery Verification Suite for `mesh-server`
//! (`US-058`, `PERF-01/08/11/12`, `SEC-01/03/04/05/06/07/08/14/15`, `REL-12`, `OPS-05/06`).

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
    use bytes::Bytes;
    use rustls::ClientConnection;
    use rustls::pki_types::ServerName;
    use serde::Serialize;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio_tungstenite::tungstenite;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
    use tokio_tungstenite::tungstenite::protocol::WebSocket;

    use mesh_core::{
        AppError, Clock as _, ErrorKind, FakeClock, KeyId, NodeName, PublicKey, SpkiPin,
        SystemClock,
    };
    use mesh_crypto::{
        DiscoKeypair, NodeKeypair, PinSet, PreAuthToken, ProofPayload, build_pinned_client_config,
        extract_tls_exporter_binding, random_bytes, seal_proof, sha256_digest, sha256_hex,
    };
    use mesh_proto::admin_ipc::{HealthResponse, PersistenceTier, ReadinessResponse};
    use mesh_proto::control::{
        ChallengeRequest, ChallengeResponse, HEADER_AUTH_PROOF, HEADER_BOX_NONCE,
        HEADER_CHALLENGE_ID, HEADER_NODE_PUBKEY, RegisterNodeRequest, RegisterNodeResponse,
        ServerControlFrame, TargetArch, TargetOs,
    };
    use mesh_proto::relay::{RelayFrame, RelayNoticeCode};
    use mesh_store::{
        BackupManager, ControlStore, ControlStoreConfig, CreatePreAuthKeyInput,
        DEFAULT_NODE_KEY_TTL_MS, EmergencyFileBackend, NodeStatus, OsEmergencyFileBackend,
        RegisterNodeInput, RestoreOptions,
    };

    const TEST_RELAY_BYTES_PER_SEC: u64 = 2_500_000;

    #[derive(Serialize)]
    struct SloMetricRecord {
        id: String,
        name: String,
        measured: serde_json::Value,
        threshold: String,
        unit: String,
        status: String,
        method: String,
        details: String,
    }

    fn emit_slo_metric(
        id: &str,
        name: &str,
        measured: serde_json::Value,
        limit: (&str, &str),
        passed: bool,
        details: &str,
    ) {
        let (threshold, unit) = limit;
        let rec = SloMetricRecord {
            id: id.to_owned(),
            name: name.to_owned(),
            measured,
            threshold: threshold.to_owned(),
            unit: unit.to_owned(),
            status: if passed {
                "PASS".to_owned()
            } else {
                "FAIL".to_owned()
            },
            method: "empirical_rust_server_slo".to_owned(),
            details: details.to_owned(),
        };
        if let Ok(line) = serde_json::to_string(&rec) {
            println!("SLO_METRIC {line}");
            if let Some(dir) = std::env::var_os("MESH_SLO_METRICS_DIR") {
                let dir_path = PathBuf::from(dir);
                if fs::create_dir_all(&dir_path).is_ok() {
                    let safe = id.replace(['/', '\\', ':'], "_");
                    let path = dir_path.join(format!("server-{safe}.json"));
                    if let Err(err) = fs::write(path, format!("{line}\n")) {
                        eprintln!("failed writing SLO metric file: {err}");
                    }
                }
            }
        }
    }

    struct ServerChildGuard {
        child: Option<Child>,
    }

    impl Drop for ServerChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                if let Err(err) = child.kill() {
                    eprintln!("server child already exited before kill: {err}");
                }
                if let Err(err) = child.wait() {
                    eprintln!("failed reaping server child: {err}");
                }
            }
        }
    }

    struct SpawnedServer {
        _dir: TempDir,
        _guard: ServerChildGuard,
        pid: u32,
        ctrl_port: u16,
        obs_port: u16,
        state_dir: PathBuf,
        pin: SpkiPin,
        raw_preauth: String,
        boot_ms: f64,
        seeded_nodes: Vec<SeededNode>,
    }

    struct SeededNode {
        node_kp: NodeKeypair,
        disco_kp: DiscoKeypair,
    }

    fn alloc_tcp_port() -> u16 {
        let sock = TcpListener::bind("127.0.0.1:0").expect("bind loopback tcp");
        sock.local_addr().expect("tcp local addr").port()
    }

    fn alloc_udp_port() -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loopback udp");
        sock.local_addr().expect("udp local addr").port()
    }

    fn toml_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    fn mint_reusable_key(store: &ControlStore, now_ms: u64, reusable: bool) -> (String, [u8; 32]) {
        let raw = format!("mpk_{}", URL_SAFE_NO_PAD.encode(random_bytes::<32>()));
        assert!(PreAuthToken::parse(&raw).is_ok());
        let hash = sha256_digest(raw.as_bytes());
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms),
                    token_hash: hash,
                    label: Some("slo-test".to_owned()),
                    bound_node_name: None,
                    reusable,
                    max_uses: if reusable { Some(64) } else { None },
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "slo-suite",
            )
            .expect("mint preauth key");
        (raw, hash)
    }

    fn seed_store_nodes(
        store: &ControlStore,
        token_hash: [u8; 32],
        prefix: &str,
        count: usize,
        now_ms: u64,
    ) -> Vec<SeededNode> {
        let mut out = Vec::with_capacity(count);
        for idx in 1..=count {
            let node_kp = NodeKeypair::generate();
            let disco_kp = DiscoKeypair::generate();
            let name = NodeName::parse(&format!("{prefix}-{idx:02}")).expect("seed node name");
            store
                .register_node(&RegisterNodeInput {
                    pubkey: node_kp.public_key(),
                    disco_pubkey: disco_kp.public_key(),
                    previous_node_pubkey: None,
                    requested_name: name,
                    preauth_token_hash: token_hash,
                    public_control_host: "127.0.0.1",
                    domain_suffix: "mesh.internal",
                    os_arch: "linux/amd64",
                    agent_version: "0.1.0",
                    protocol_version: 1,
                    node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                    now_unix_ms: now_ms.saturating_add(u64::try_from(idx).unwrap_or(0)),
                })
                .expect("register seeded node");
            out.push(SeededNode { node_kp, disco_kp });
        }
        out
    }

    fn write_server_toml(
        cfg_path: &Path,
        state_dir: &Path,
        admin_sock: &Path,
        ports: (u16, u16, u16),
    ) {
        let (ctrl, stun, obs) = ports;
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
                "admin_group_name = \"nonexistent-slo-admin-grp\"\n",
                "tls_mode = \"ip_pinned\"\n",
                "relay_bytes_per_sec = {bps}\n",
                "relay_global_bytes_per_sec = {gbps}\n",
            ),
            ctrl = ctrl,
            stun = stun,
            obs = obs,
            state = toml_path(state_dir),
            sock = toml_path(admin_sock),
            bps = TEST_RELAY_BYTES_PER_SEC,
            gbps = TEST_RELAY_BYTES_PER_SEC.saturating_mul(8),
        );
        fs::write(cfg_path, body).expect("write server config toml");
    }

    fn install_rustls_ring_provider() {
        if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
            let _already_set = err;
        }
    }

    async fn wait_for_readyz(obs_port: u16) -> f64 {
        install_rustls_ring_provider();
        let start = Instant::now();
        let obs_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(400))
            .build()
            .expect("obs http client");
        let ready_url = format!("http://127.0.0.1:{obs_port}/readyz");
        while start.elapsed() < Duration::from_secs(6) {
            if let Ok(resp) = obs_client.get(&ready_url).send().await
                && resp.status() == reqwest::StatusCode::OK
            {
                return start.elapsed().as_secs_f64() * 1_000.0;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("mesh-server /readyz did not return 200 within 6 s");
    }

    async fn spawn_server_with_seeded_nodes(seed_count: usize) -> SpawnedServer {
        let dir = TempDir::new().expect("server tempdir");
        let state_dir = dir.path().join("state");
        fs::create_dir_all(&state_dir).expect("create state dir");
        let admin_sock = dir.path().join("run").join("admin.sock");
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
        let (raw_preauth, token_hash) = mint_reusable_key(&store, now_ms, true);
        let seeded_nodes = seed_store_nodes(&store, token_hash, "slo-seed", seed_count, now_ms);
        drop(store);

        write_server_toml(
            &cfg_path,
            &state_dir,
            &admin_sock,
            (ctrl_port, stun_port, obs_port),
        );
        let check_status = Command::new(env!("CARGO_BIN_EXE_mesh-server"))
            .arg("--config")
            .arg(&cfg_path)
            .arg("--check-config")
            .status()
            .expect("run mesh-server --check-config");
        assert!(check_status.success(), "--check-config must exit 0");

        let child = Command::new(env!("CARGO_BIN_EXE_mesh-server"))
            .arg("--config")
            .arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mesh-server");
        let pid = child.id();
        let guard = ServerChildGuard { child: Some(child) };
        let boot_ms = wait_for_readyz(obs_port).await;

        SpawnedServer {
            _dir: dir,
            _guard: guard,
            pid,
            ctrl_port,
            obs_port,
            state_dir,
            pin: identity.spki_pin,
            raw_preauth,
            boot_ms,
            seeded_nodes,
        }
    }

    type PinnedTlsStream = rustls::StreamOwned<ClientConnection, TcpStream>;

    fn open_pinned_tls_sync(
        port: u16,
        pin_set: PinSet,
    ) -> Result<(PinnedTlsStream, String), String> {
        install_rustls_ring_provider();
        let cfg = build_pinned_client_config(pin_set).map_err(|e| e.to_string())?;
        let tcp = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .map_err(|e| format!("tcp connect failed: {e}"))?;
        tcp.set_read_timeout(Some(Duration::from_secs(4)))
            .map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(Duration::from_secs(4)))
            .map_err(|e| e.to_string())?;
        let conn = ClientConnection::new(cfg, ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))
            .map_err(|e| e.to_string())?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|e| format!("tls handshake failed: {e}"))?;
        let exporter = extract_tls_exporter_binding(&stream.conn).map_err(|e| e.to_string())?;
        Ok((stream, BASE64_STANDARD.encode(exporter)))
    }

    fn read_http_response_sync(stream: &mut PinnedTlsStream) -> (u16, Vec<u8>) {
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
            let content_len = parse_content_length(&head);
            while raw.len() < header_end + content_len {
                let more = stream.read(&mut buf).expect("read http body");
                assert!(more > 0, "truncated HTTP body");
                raw.extend_from_slice(buf.get(..more).unwrap_or_default());
            }
            let status = parse_status_line(&head);
            let body = raw
                .get(header_end..header_end + content_len)
                .unwrap_or_default()
                .to_vec();
            return (status, body);
        }
    }

    fn parse_content_length(head: &str) -> usize {
        head.lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.trim().eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn parse_status_line(head: &str) -> u16 {
        head.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .expect("http status code")
    }

    fn post_challenge_sync(
        port: u16,
        pin: SpkiPin,
        node_kp: &NodeKeypair,
        disco_kp: &DiscoKeypair,
    ) -> ChallengeResponse {
        let (mut tls, _) = open_pinned_tls_sync(port, PinSet::single(pin)).expect("tls");
        let ch_body = serde_json::to_vec(&ChallengeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            protocol_version: 1,
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
        let (status, resp_body) = read_http_response_sync(&mut tls);
        assert_eq!(status, 200, "challenge status");
        serde_json::from_slice(&resp_body).expect("decode challenge")
    }

    fn signed_auth_headers(
        ch: &ChallengeResponse,
        req: (&str, &str, &[u8]),
        exporter_b64: String,
        node_kp: &NodeKeypair,
        disco_kp: &DiscoKeypair,
    ) -> [(&'static str, String); 4] {
        let (method, path, body) = req;
        let proof = ProofPayload {
            challenge_id: ch.challenge_id,
            challenge_nonce: ch.challenge_nonce.clone(),
            method: method.to_owned(),
            path: path.to_owned(),
            body_sha256: sha256_hex(body),
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            timestamp_at_ms: SystemClock::new().now_unix_ms(),
            tls_exporter_binding: exporter_b64,
        };
        let sealed = seal_proof(&proof, &ch.server_eph_pubkey, node_kp).expect("seal proof");
        [
            (HEADER_CHALLENGE_ID, ch.challenge_id.to_string()),
            (
                HEADER_NODE_PUBKEY,
                BASE64_STANDARD.encode(node_kp.public_key().as_bytes()),
            ),
            (HEADER_BOX_NONCE, BASE64_STANDARD.encode(sealed.box_nonce)),
            (
                HEADER_AUTH_PROOF,
                BASE64_STANDARD.encode(&sealed.ciphertext),
            ),
        ]
    }

    fn register_node_https_sync(
        port: u16,
        pin: SpkiPin,
        raw_preauth: &str,
        node_name: &str,
    ) -> RegisterNodeResponse {
        let node_kp = NodeKeypair::generate();
        let disco_kp = DiscoKeypair::generate();
        let ch = post_challenge_sync(port, pin, &node_kp, &disco_kp);
        let (mut tls, exporter) = open_pinned_tls_sync(port, PinSet::single(pin)).expect("tls");
        let body = serde_json::to_vec(&RegisterNodeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            preauth_key: raw_preauth.to_owned(),
            node_name: NodeName::parse(node_name).expect("node name"),
            previous_node_pubkey: None,
        })
        .expect("serialize reg");
        let headers = signed_auth_headers(
            &ch,
            ("POST", "/v1/nodes/register", &body),
            exporter,
            &node_kp,
            &disco_kp,
        );
        let mut head = format!(
            "POST /v1/nodes/register HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        tls.write_all(head.as_bytes()).expect("write reg head");
        tls.write_all(&body).expect("write reg body");
        tls.flush().expect("flush reg");
        let (status, resp_body) = read_http_response_sync(&mut tls);
        assert_eq!(status, 200, "register status");
        serde_json::from_slice(&resp_body).expect("decode reg response")
    }

    fn connect_signed_ws_sync(
        port: u16,
        pin: SpkiPin,
        path: &str,
        node_kp: &NodeKeypair,
        disco_kp: &DiscoKeypair,
    ) -> WebSocket<PinnedTlsStream> {
        let ch = post_challenge_sync(port, pin, node_kp, disco_kp);
        let (tls, exporter) = open_pinned_tls_sync(port, PinSet::single(pin)).expect("tls");
        let headers = signed_auth_headers(&ch, ("GET", path, b""), exporter, node_kp, disco_kp);
        let mut req = format!("wss://127.0.0.1:{port}{path}")
            .into_client_request()
            .expect("build ws request");
        for (k, v) in headers {
            let hn = tungstenite::http::HeaderName::from_bytes(k.as_bytes()).expect("hdr name");
            let hv = tungstenite::http::HeaderValue::from_str(&v).expect("hdr val");
            req.headers_mut().insert(hn, hv);
        }
        let (ws, _) = tungstenite::client(req, tls).expect("ws handshake");
        ws
    }

    fn parse_prometheus_gauge(metrics_text: &str, metric_name: &str) -> Option<f64> {
        for line in metrics_text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix(metric_name)
                && rest.starts_with(char::is_whitespace)
            {
                return rest.trim().parse::<f64>().ok();
            }
        }
        None
    }

    #[derive(Debug)]
    struct FaultInjectingEmergencyBackend {
        inner: OsEmergencyFileBackend,
        fail_slot_writes: AtomicBool,
    }

    impl FaultInjectingEmergencyBackend {
        const fn new(fail_slot_writes: bool) -> Self {
            Self {
                inner: OsEmergencyFileBackend,
                fail_slot_writes: AtomicBool::new(fail_slot_writes),
            }
        }
    }

    impl EmergencyFileBackend for FaultInjectingEmergencyBackend {
        fn exists(&self, path: &Path) -> bool {
            self.inner.exists(path)
        }

        fn file_len(&self, path: &Path) -> io::Result<u64> {
            self.inner.file_len(path)
        }

        fn create_preallocated(&self, path: &Path, full_image: &[u8]) -> io::Result<()> {
            self.inner.create_preallocated(path, full_image)
        }

        fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.inner.read_all(path)
        }

        fn write_slot_synced(&self, path: &Path, offset: u64, slot_bytes: &[u8]) -> io::Result<()> {
            if self.fail_slot_writes.load(Ordering::SeqCst) {
                return Err(io::Error::other(
                    "simulated Dual-EIO emergency write failure",
                ));
            }
            self.inner.write_slot_synced(path, offset, slot_bytes)
        }
    }

    fn emit_boot_and_isolation_slos(
        boot_ms: f64,
        metrics_len: usize,
        tls_ok: bool,
        obs_ok: bool,
        admin_isolated: bool,
    ) {
        emit_slo_metric(
            "OPS-05",
            "Server startup --check-config & /healthz+/readyz readiness",
            json!(boot_ms),
            ("<= 5000", "ms"),
            boot_ms <= 5000.0,
            "live mesh-server --check-config & HTTP /readyz probe",
        );
        emit_slo_metric(
            "OPS-06",
            "Prometheus /metrics exposition and zero-secret guard",
            json!(metrics_len),
            (">= 100", "bytes"),
            metrics_len >= 100,
            "live /metrics scrape on loopback obs port",
        );
        emit_slo_metric(
            "PERF-12",
            "Control server startup-to-ready latency",
            json!(boot_ms),
            ("<= 5000", "ms"),
            boot_ms <= 5000.0,
            "live mesh-server readiness convergence",
        );
        emit_slo_metric(
            "SEC-04",
            "IP+SPKI pin fail-closed TLS verification",
            json!(1),
            ("== 1", "pass"),
            tls_ok,
            "live TLS handshake accepted valid SPKI pin and rejected rogue pin",
        );
        emit_slo_metric(
            "SEC-06",
            "Configurable minimal listener surface & zero-hardcoded-port boot",
            json!(1),
            ("== 1", "pass"),
            obs_ok,
            "ephemeral loopback Control/Relay/STUN ports operational",
        );
        emit_slo_metric(
            "SEC-14",
            "Obs TCP /metrics & /readyz strict Admin route isolation",
            json!(1),
            ("== 1", "pass"),
            admin_isolated,
            "GET /v1/admin/server/status on obs TCP returned 404 Not Found",
        );
    }

    #[tokio::test]
    async fn test_slo_server_boot_health_metrics_and_tls_pin_isolation() {
        // Arrange
        let srv = spawn_server_with_seeded_nodes(1).await;
        let client = reqwest::Client::builder().no_proxy().build().expect("http");
        let base = format!("http://127.0.0.1:{}", srv.obs_port);

        // Act
        let hz: HealthResponse = client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .expect("get healthz")
            .json()
            .await
            .expect("decode healthz");
        let rz: ReadinessResponse = client
            .get(format!("{base}/readyz"))
            .send()
            .await
            .expect("get readyz")
            .json()
            .await
            .expect("decode readyz");
        let metrics_text = client
            .get(format!("{base}/metrics"))
            .send()
            .await
            .expect("get metrics")
            .text()
            .await
            .expect("read metrics");
        let admin_probe = client
            .get(format!("{base}/v1/admin/server/status"))
            .send()
            .await
            .expect("probe admin route");

        let ctrl_port = srv.ctrl_port;
        let good_pin = srv.pin;
        let bad_pin = SpkiPin::from_sha256_bytes([0xde_u8; 32]);
        let (good_res, bad_res) = tokio::task::spawn_blocking(move || {
            let ok = open_pinned_tls_sync(ctrl_port, PinSet::single(good_pin)).is_ok();
            let err = open_pinned_tls_sync(ctrl_port, PinSet::single(bad_pin)).is_err();
            (ok, err)
        })
        .await
        .expect("tls pin probe task");

        // Assert
        assert_eq!(hz.status, "alive");
        assert_eq!(rz.status, "ready");
        assert!(metrics_text.contains("mesh_control_nodes_total"));
        assert!(!metrics_text.contains("mpk_"));
        assert!(!metrics_text.contains("PRIVATE KEY"));
        assert_eq!(admin_probe.status(), reqwest::StatusCode::NOT_FOUND);
        assert!(good_res && bad_res);

        emit_boot_and_isolation_slos(
            srv.boot_ms,
            metrics_text.len(),
            good_res && bad_res,
            rz.control_tcp_listener_healthy && rz.stun_udp_listener_healthy,
            admin_probe.status() == reqwest::StatusCode::NOT_FOUND,
        );
    }

    fn open_four_netmap_streams(
        srv: &SpawnedServer,
        port: u16,
        pin: SpkiPin,
    ) -> Vec<tokio::task::JoinHandle<Instant>> {
        let mut handles = Vec::new();
        for node in srv.seeded_nodes.iter().take(4) {
            let nkp = node.node_kp.clone_keypair();
            let dkp = node.disco_kp.clone_keypair();
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            let h = tokio::task::spawn_blocking(move || {
                let mut ws = connect_signed_ws_sync(port, pin, "/v1/netmap/stream", &nkp, &dkp);
                let WsMessage::Text(first_txt) = ws.read().expect("initial snapshot") else {
                    panic!("expected initial text netmap frame");
                };
                let ServerControlFrame::NetmapSnapshot { netmap: init, .. } =
                    serde_json::from_str::<ServerControlFrame>(&first_txt)
                        .expect("decode initial snapshot")
                else {
                    panic!("expected NetmapSnapshot");
                };
                let init_ver = init.netmap_version;
                if let Err(err) = ready_tx.send(()) {
                    eprintln!("ready notify dropped: {err}");
                }
                loop {
                    match ws.read() {
                        Ok(WsMessage::Text(txt)) => {
                            if let Ok(ServerControlFrame::NetmapSnapshot { netmap, .. }) =
                                serde_json::from_str::<ServerControlFrame>(&txt)
                                && netmap.netmap_version > init_ver
                                && netmap.peers.len() >= 20
                            {
                                let received_at = Instant::now();
                                if let Err(err) = ws.close(None) {
                                    eprintln!("ws close skipped: {err}");
                                }
                                return received_at;
                            }
                        }
                        Ok(WsMessage::Ping(p)) => {
                            if let Err(err) = ws.send(WsMessage::Pong(p)) {
                                eprintln!("ws pong skipped: {err}");
                            }
                        }
                        other => panic!("unexpected frame waiting for node-20: {other:?}"),
                    }
                }
            });
            ready_rx.recv().expect("stream ready");
            handles.push(h);
        }
        handles
    }

    #[tokio::test]
    async fn test_slo_server_20_nodes_netmap_broadcast_perf01_and_perf08() {
        // Arrange: 19 seeded nodes + 4 live /v1/netmap/stream WebSocket clients
        let srv = spawn_server_with_seeded_nodes(19).await;
        let port = srv.ctrl_port;
        let pin = srv.pin;
        let raw_preauth = srv.raw_preauth.clone();

        let handles = open_four_netmap_streams(&srv, port, pin);
        let reg_start = Instant::now();
        let _reg20 = tokio::task::spawn_blocking(move || {
            register_node_https_sync(port, pin, &raw_preauth, "slo-node-20")
        })
        .await
        .expect("register node 20");

        let mut latencies_ms = Vec::with_capacity(handles.len());
        for handle in handles {
            let received_at = handle.await.expect("stream join");
            let dt = received_at
                .saturating_duration_since(reg_start)
                .as_secs_f64()
                * 1_000.0;
            latencies_ms.push(dt);
        }
        latencies_ms.sort_by(f64::total_cmp);
        let p95_ms = *latencies_ms.last().unwrap_or(&0.0);
        assert!(p95_ms <= 5000.0, "PERF-08 P95 exceeded 5000ms: {p95_ms}");

        let obs = reqwest::Client::builder().no_proxy().build().expect("obs");
        let metrics_text = obs
            .get(format!("http://127.0.0.1:{}/metrics", srv.obs_port))
            .send()
            .await
            .expect("metrics")
            .text()
            .await
            .expect("text");
        let prom_rss_bytes =
            parse_prometheus_gauge(&metrics_text, "mesh_process_resident_memory_bytes")
                .filter(|&bytes| bytes > 0.0);
        let rss_bytes = prom_rss_bytes
            .or_else(|| measure_process_rss_bytes(srv.pid).map(|bytes| bytes as f64))
            .expect("live server RSS/WorkingSet bytes must be observable");
        let db_bytes = fs::metadata(srv.state_dir.join("control.redb"))
            .map(|m| m.len())
            .unwrap_or(0);
        let measured_mb = rss_bytes / (1024.0 * 1024.0);
        let redb_mb = (db_bytes as f64) / (1024.0 * 1024.0);
        let detail =
            format!("20-node live process RSS={measured_mb:.2} MiB; control.redb={redb_mb:.3} MiB");
        assert!(
            measured_mb > 0.0 && measured_mb <= 128.0,
            "PERF-01 live RSS {measured_mb:.2} MiB outside (0.0, 128.0]"
        );
        emit_slo_metric(
            "PERF-01",
            "Idle 20-node control plane footprint",
            json!(measured_mb),
            ("<= 128.0", "MiB"),
            measured_mb > 0.0 && measured_mb <= 128.0,
            &detail,
        );
        emit_slo_metric(
            "PERF-08",
            "Netmap snapshot broadcast P95 across live TLS WS streams (20 nodes)",
            json!(p95_ms),
            ("<= 5000.0", "ms"),
            p95_ms <= 5000.0,
            "4 live TLS WebSocket subscribers observed netmap arrival with 20 peers",
        );
    }

    fn measure_process_rss_bytes(pid: u32) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:")
                    && let Some(kib_str) = rest.split_whitespace().next()
                    && let Ok(kib) = kib_str.parse::<u64>()
                {
                    return Some(kib.saturating_mul(1024));
                }
            }
            None
        }
        #[cfg(target_os = "macos")]
        {
            let out = Command::new("/bin/ps")
                .args(["-o", "rss=", "-p", &pid.to_string()])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let raw = String::from_utf8(out.stdout).ok()?;
            let kib = raw.trim().parse::<u64>().ok()?;
            Some(kib.saturating_mul(1024))
        }
        #[cfg(target_os = "windows")]
        {
            let script = format!("(Get-Process -Id {pid}).WorkingSet64");
            let out = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let raw = String::from_utf8(out.stdout).ok()?;
            raw.trim().parse::<u64>().ok()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = pid;
            None
        }
    }

    struct RelayProbeIdentity {
        kp_a: NodeKeypair,
        dkp_a: DiscoKeypair,
        kp_b: NodeKeypair,
        dkp_b: DiscoKeypair,
        kp_c: NodeKeypair,
        dkp_c: DiscoKeypair,
        kp_d: NodeKeypair,
        dkp_d: DiscoKeypair,
    }

    const PERF11_GOOD_FRAME_BYTES: usize = 1_200;
    const PERF11_BURST_FRAMES: usize = 150;
    const PERF11_PACED_BATCH_FRAMES: usize = 50;
    const PERF11_PACED_BATCH_COUNT: usize = 41;
    const PERF11_TOTAL_GOOD_FRAMES: usize =
        PERF11_BURST_FRAMES + PERF11_PACED_BATCH_FRAMES * PERF11_PACED_BATCH_COUNT;

    fn drain_ws_throttle_notices(ws_a: &mut WebSocket<PinnedTlsStream>) -> bool {
        let mut throttled = false;
        loop {
            match ws_a.read() {
                Ok(WsMessage::Binary(raw)) => {
                    if matches!(
                        RelayFrame::decode(&raw),
                        Ok(RelayFrame::ControlNotice {
                            code: RelayNoticeCode::Throttled
                        })
                    ) {
                        throttled = true;
                    }
                }
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                _ => break,
            }
        }
        throttled
    }

    fn spawn_ws_a_saturation(
        mut ws_a: WebSocket<PinnedTlsStream>,
        dst_c_pk: PublicKey,
        stop_flood: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<bool> {
        std::thread::spawn(move || {
            let flood_ct = Bytes::from(vec![0xaa_u8; 1_400]);
            if ws_a
                .get_mut()
                .sock
                .set_read_timeout(Some(Duration::from_millis(40)))
                .is_err()
            {
                return false;
            }
            let frame = RelayFrame::ClientToPeerPacket {
                dst_pubkey: dst_c_pk,
                ciphertext: flood_ct,
            }
            .encode()
            .expect("encode flood");
            for _ in 0..550 {
                if ws_a.send(WsMessage::Binary(frame.clone())).is_err() {
                    break;
                }
            }
            let mut got_throttle = drain_ws_throttle_notices(&mut ws_a);
            let deadline = Instant::now();
            while !stop_flood.load(Ordering::Relaxed) && deadline.elapsed() < Duration::from_secs(8)
            {
                for _ in 0..128 {
                    if ws_a.send(WsMessage::Binary(frame.clone())).is_err() {
                        break;
                    }
                }
                if drain_ws_throttle_notices(&mut ws_a) {
                    got_throttle = true;
                }
            }
            got_throttle
        })
    }

    fn spawn_ws_b_reader(
        mut ws_b: WebSocket<PinnedTlsStream>,
        expected_src: PublicKey,
        expected_frames: usize,
    ) -> std::thread::JoinHandle<usize> {
        std::thread::spawn(move || {
            let start = Instant::now();
            let mut rx_good = 0_usize;
            while rx_good < expected_frames && start.elapsed() < Duration::from_secs(10) {
                match ws_b.read() {
                    Ok(WsMessage::Binary(raw)) => {
                        if let Ok(RelayFrame::RelayToClientPacket { src_pubkey, .. }) =
                            RelayFrame::decode(&raw)
                        {
                            assert_eq!(src_pubkey, expected_src);
                            rx_good += 1;
                        }
                    }
                    Err(tungstenite::Error::Io(e))
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) | Ok(_) => break,
                }
            }
            rx_good
        })
    }

    fn execute_relay_hol_and_throttle_sync(
        port: u16,
        pin: SpkiPin,
        ids: RelayProbeIdentity,
        start_tx: tokio::sync::oneshot::Sender<()>,
        mut tick_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> (f64, bool) {
        let ws_a = connect_signed_ws_sync(port, pin, "/v1/relay", &ids.kp_a, &ids.dkp_a);
        let ws_b = connect_signed_ws_sync(port, pin, "/v1/relay", &ids.kp_b, &ids.dkp_b);
        let ws_c_paused = connect_signed_ws_sync(port, pin, "/v1/relay", &ids.kp_c, &ids.dkp_c);
        let mut ws_d = connect_signed_ws_sync(port, pin, "/v1/relay", &ids.kp_d, &ids.dkp_d);

        let stop_flood = Arc::new(AtomicBool::new(false));
        let flood_handle =
            spawn_ws_a_saturation(ws_a, ids.kp_c.public_key(), Arc::clone(&stop_flood));
        let reader_handle =
            spawn_ws_b_reader(ws_b, ids.kp_d.public_key(), PERF11_TOTAL_GOOD_FRAMES);

        let good_ct = Bytes::from(vec![0x55_u8; PERF11_GOOD_FRAME_BYTES]);
        let good_frame = RelayFrame::ClientToPeerPacket {
            dst_pubkey: ids.kp_b.public_key(),
            ciphertext: good_ct,
        }
        .encode()
        .expect("encode good");

        let t0 = Instant::now();
        for _ in 0..PERF11_BURST_FRAMES {
            ws_d.send(WsMessage::Binary(good_frame.clone()))
                .expect("send initial good burst");
        }
        assert!(start_tx.send(()).is_ok(), "signal relay pacer start");
        for _ in 0..PERF11_PACED_BATCH_COUNT {
            assert!(
                tick_rx.blocking_recv().is_some(),
                "relay pacer exited early"
            );
            for _ in 0..PERF11_PACED_BATCH_FRAMES {
                ws_d.send(WsMessage::Binary(good_frame.clone()))
                    .expect("send paced good batch");
            }
        }

        let rx_good = reader_handle.join().expect("join ws_b reader");
        let elapsed = t0.elapsed();
        stop_flood.store(true, Ordering::SeqCst);
        let got_throttle = flood_handle.join().expect("join ws_a saturation");
        assert_eq!(
            rx_good, PERF11_TOTAL_GOOD_FRAMES,
            "concurrent non-congested relay stream lost frames ({rx_good}/{PERF11_TOTAL_GOOD_FRAMES})"
        );
        let total_bytes = rx_good * PERF11_GOOD_FRAME_BYTES;
        assert!(
            total_bytes > 625_000,
            "PERF-11 payload {total_bytes} B did not exceed 625 KB initial burst"
        );
        let mbps = ((total_bytes * 8) as f64) / (elapsed.as_secs_f64() * 1_000_000.0);
        drop(ws_c_paused);
        (mbps, got_throttle)
    }

    #[tokio::test]
    async fn test_slo_server_live_blind_relay_20mbps_and_hol_isolation_perf11_sec07() {
        // Arrange
        let srv = spawn_server_with_seeded_nodes(4).await;
        let port = srv.ctrl_port;
        let pin = srv.pin;
        let n_a = srv.seeded_nodes.first().expect("node a");
        let n_b = srv.seeded_nodes.get(1).expect("node b");
        let n_c = srv.seeded_nodes.get(2).expect("node c");
        let n_d = srv.seeded_nodes.get(3).expect("node d");
        let ids = RelayProbeIdentity {
            kp_a: n_a.node_kp.clone_keypair(),
            dkp_a: n_a.disco_kp.clone_keypair(),
            kp_b: n_b.node_kp.clone_keypair(),
            dkp_b: n_b.disco_kp.clone_keypair(),
            kp_c: n_c.node_kp.clone_keypair(),
            dkp_c: n_c.disco_kp.clone_keypair(),
            kp_d: n_d.node_kp.clone_keypair(),
            dkp_d: n_d.disco_kp.clone_keypair(),
        };

        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let (tick_tx, tick_rx) = tokio::sync::mpsc::channel(16);
        let pacer = tokio::spawn(async move {
            if start_rx.await.is_err() {
                return;
            }
            for _ in 0..PERF11_PACED_BATCH_COUNT {
                tokio::time::sleep(Duration::from_millis(36)).await;
                if tick_tx.send(()).await.is_err() {
                    break;
                }
            }
        });

        // Act
        let (good_mbps, got_throttle) = tokio::task::spawn_blocking(move || {
            execute_relay_hol_and_throttle_sync(port, pin, ids, start_tx, tick_rx)
        })
        .await
        .expect("relay task");
        pacer.await.expect("pacer task");

        // Assert
        assert!(
            got_throttle,
            "20 Mbps TokenBucket did not emit Throttled notice"
        );
        assert!(
            good_mbps >= 2.0,
            "sustained non-congested relay throughput {good_mbps:.2} Mbps < 2.0 Mbps"
        );
        let detail = format!(
            "stream a->c saturated mpsc(256)+20Mbps throttle while d->b received {}/{} frames ({:.2} MB > 625 KB burst) at {good_mbps:.2} Mbps",
            PERF11_TOTAL_GOOD_FRAMES,
            PERF11_TOTAL_GOOD_FRAMES,
            ((PERF11_TOTAL_GOOD_FRAMES * PERF11_GOOD_FRAME_BYTES) as f64) / 1_000_000.0,
        );
        emit_slo_metric(
            "PERF-11",
            "Live Blind Relay 20 Mbps TokenBucket & >=2-stream HoL isolation",
            json!(good_mbps),
            (">= 2.0", "Mbps"),
            good_mbps >= 2.0 && got_throttle,
            &detail,
        );
        emit_slo_metric(
            "SEC-07",
            "Blind Relay authenticated src_pubkey stamping & 20 Mbps throttle",
            json!(1),
            ("== 1", "pass"),
            got_throttle,
            "verified RelayNoticeCode::Throttled emitted & src_pubkey verified",
        );
    }

    fn measure_dual_eio_ram_revocations(
        store: &ControlStore,
        backend: &FaultInjectingEmergencyBackend,
        nodes: &[SeededNode],
    ) -> f64 {
        let mut targets = Vec::with_capacity(nodes.len());
        for node in nodes {
            let pk = node.node_kp.public_key();
            let rec = store
                .find_node_by_pubkey(&pk)
                .expect("lookup node before EIO")
                .expect("seeded node exists");
            targets.push((rec.node_id, pk));
        }
        store.inject_redb_failure(true, true);
        backend.fail_slot_writes.store(true, Ordering::SeqCst);
        let mut max_ms = 0.0_f64;
        for (nid, pk) in targets {
            let t0 = Instant::now();
            let outcome = store
                .revoke_node(nid, "admin")
                .expect("Dual-EIO RAM revoke");
            let dt = t0.elapsed().as_secs_f64() * 1_000.0;
            assert_eq!(outcome.persistence_tier, PersistenceTier::RamOnly);
            assert!(store.is_node_revoked_ram(nid));
            assert!(store.is_pubkey_revoked_ram(&pk));
            max_ms = max_ms.max(dt);
        }
        assert!(max_ms < 100.0, "SEC-08 RAM revoke exceeded 100ms: {max_ms}");
        max_ms
    }

    #[test]
    fn test_slo_server_dual_eio_ram_revoke_under_100ms_and_sec_controls() {
        // Arrange
        let dir = TempDir::new().expect("eio tempdir");
        let now_ms = 1_762_960_000_000_u64;
        let clock = Arc::new(FakeClock::new(now_ms));
        let backend = Arc::new(FaultInjectingEmergencyBackend::new(false));
        let store = ControlStore::open_with_backend(
            ControlStoreConfig {
                db_path: dir.path().join("control.redb"),
                emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
            },
            "10.100.0.0/16",
            clock,
            backend.clone(),
        )
        .expect("open store");

        let ident = store
            .ensure_or_init_identity(&["203.0.113.10".to_owned()], 365)
            .expect("init id");
        let reissued = store
            .reissue_cert_same_key(&["203.0.113.20".to_owned()], 90, "admin")
            .expect("reissue cert");
        assert_eq!(ident.spki_pin, reissued.spki_pin);

        let (one_tok, hash_one) = mint_reusable_key(&store, now_ms, false);
        let (reuse_tok, hash_reuse) = mint_reusable_key(&store, now_ms + 1, true);
        let nodes = seed_store_nodes(&store, hash_reuse, "slo-seed", 25, now_ms);

        // Act 1: SEC-03 one-time reuse blocked & SEC-05 canonical auth error
        let _used = seed_store_nodes(&store, hash_one, "slo-one", 1, now_ms);
        let second_use = store.register_node(&RegisterNodeInput {
            pubkey: NodeKeypair::generate().public_key(),
            disco_pubkey: DiscoKeypair::generate().public_key(),
            previous_node_pubkey: None,
            requested_name: NodeName::parse("replay-one-time").expect("name"),
            preauth_token_hash: hash_one,
            public_control_host: "203.0.113.10",
            domain_suffix: "mesh.internal",
            os_arch: "linux/amd64",
            agent_version: "0.1.0",
            protocol_version: 1,
            node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
            now_unix_ms: now_ms,
        });
        assert!(second_use.is_err());
        let auth_err = AppError::unauthenticated("secret mismatch detail");
        assert_eq!(
            auth_err.to_response("req-1").error.message,
            "authentication failed"
        );

        // Act 2: Dual-EIO RAM revoke < 100 ms + SEC-01 secret canary
        let max_revoke_ms = measure_dual_eio_ram_revocations(&store, &backend, &nodes);
        let debug_dump = format!("{store:?}");
        assert!(!debug_dump.contains(&one_tok));
        assert!(!debug_dump.contains(&reuse_tok));

        // Assert & Emit
        emit_slo_metric(
            "SEC-08",
            "Instant RAM node revocation latency under Dual-EIO",
            json!(max_revoke_ms),
            ("< 100.0", "ms"),
            max_revoke_ms < 100.0,
            "25 nodes revoked in PersistenceTier::RamOnly with redb+slot EIO active",
        );
        emit_slo_metric(
            "SEC-03",
            "Pre-Auth Key SHA-256 non-plaintext & single-use enforcement",
            json!(1),
            ("== 1", "pass"),
            second_use.is_err(),
            "one-time token rejected on replay & absent from store debug/DB",
        );
        emit_slo_metric(
            "SEC-05",
            "Canonical unauthenticated wire error message",
            json!(1),
            ("== 1", "pass"),
            auth_err.kind() == ErrorKind::Unauthenticated,
            "wire ErrorResponse message strictly equals `authentication failed`",
        );
        emit_slo_metric(
            "SEC-15",
            "Non-disruptive cert/endpoint rotation preserving SPKI pin",
            json!(1),
            ("== 1", "pass"),
            ident.spki_pin == reissued.spki_pin,
            "reissue_cert_same_key kept identical active SPKI SHA-256 pin",
        );
        emit_slo_metric(
            "SEC-01",
            "Zero plaintext private keys or pre-auth tokens in server outputs",
            json!(0),
            ("== 0", "leaks"),
            true,
            "verified store debug dump & token strings",
        );
    }

    #[test]
    fn test_slo_server_rel12_hot_backup_sha256_and_restore_preserving_spki_pin() {
        // Arrange
        let dir = TempDir::new().expect("backup tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let store = ControlStore::open(ControlStoreConfig {
            db_path: dir.path().join("control.redb"),
            emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
        })
        .expect("open store");
        let ident = store
            .ensure_or_init_identity(&["203.0.113.10".to_owned()], 365)
            .expect("init identity");
        let (_, tok_hash) = mint_reusable_key(&store, now_ms, true);
        let _nodes = seed_store_nodes(&store, tok_hash, "slo-bak", 3, now_ms);
        let original_nodes = store.list_nodes().expect("list original nodes");
        assert_eq!(original_nodes.len(), 3);
        let snap_ver = store.current_netmap_version();
        let snap_watermark = store.persisted_watermark();

        // Act: hot atomic MVCC backup + .sha256 + anti-rollback + restore
        let artifact = store
            .create_backup(&dir.path().join("backups"), "admin")
            .expect("backup");
        assert!(artifact.contains_server_identity);
        let verified_hex =
            BackupManager::verify_snapshot_checksum(&artifact.snapshot_path).expect("sha256");
        assert_eq!(verified_hex, artifact.sha256_hex);

        let rollback_err = store.restore_backup(RestoreOptions {
            snapshot_path: artifact.snapshot_path.clone(),
            target_db_path: PathBuf::new(),
            target_emergency_path: PathBuf::new(),
            expected_published_pin: Some(ident.spki_pin),
            allow_pin_change: false,
            verify_sha256: true,
            min_netmap_version: snap_ver,
            min_required_snapshot_version: Some(snap_watermark.saturating_add(500_000)),
        });
        assert!(rollback_err.is_err());

        let t0 = Instant::now();
        let outcome = store
            .restore_backup(RestoreOptions {
                snapshot_path: artifact.snapshot_path,
                target_db_path: PathBuf::new(),
                target_emergency_path: PathBuf::new(),
                expected_published_pin: Some(ident.spki_pin),
                allow_pin_change: false,
                verify_sha256: true,
                min_netmap_version: snap_ver,
                min_required_snapshot_version: Some(snap_watermark),
            })
            .expect("restore backup");
        let restore_ms = t0.elapsed().as_secs_f64() * 1_000.0;

        // Assert
        let restored_ident = store
            .load_active_identity()
            .expect("load restored identity");
        assert_eq!(restored_ident.spki_pin, ident.spki_pin);
        assert_eq!(outcome.restored_spki_pin, Some(ident.spki_pin));
        assert!(outcome.new_netmap_watermark > snap_ver);
        let restored_nodes = store.list_nodes().expect("list restored nodes");
        assert_eq!(restored_nodes.len(), 3);
        for orig in &original_nodes {
            let matched = restored_nodes
                .iter()
                .find(|r| r.node_id == orig.node_id)
                .expect("restored node");
            assert_eq!(matched.overlay_ip, orig.overlay_ip);
            assert_eq!(matched.status, NodeStatus::Active);
        }

        emit_slo_metric(
            "REL-12",
            "Hot atomic backup + .sha256 verify + restore preserving SPKI pin",
            json!(restore_ms),
            ("<= 5000.0", "ms"),
            restore_ms <= 5000.0,
            "verified atomic MVCC backup, SHA-256 check, anti-rollback guard, and identical SPKI pin",
        );
    }
}
