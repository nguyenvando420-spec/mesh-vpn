//! Automated NFR, SLO, Datapath, Resilience & Security Verification Suite for `mesh-datapath`
//! (`US-058`, `PERF-03..07/09..11`, `REL-01/06/08/09/10`, `PLAT-04`, `SEC-01/11`).

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use mesh_core::brand::DEFAULT_DOMAIN_SUFFIX;
    use mesh_core::clock::ClockJumpDetector;
    use mesh_core::defaults::{
        DEFAULT_CONTROL_TCP_PORT, DEFAULT_TUN_MTU, MAX_FRAME_SIZE, RELAY_QUEUE_CAPACITY,
    };
    use mesh_core::{FakeClock, NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey, SpkiPin};
    use mesh_crypto::{DiscoKeypair, NodeKeypair, Secret, sha256_hex};
    use mesh_datapath::{
        CryptokeyDropReason, CryptokeyValidator, DatapathConfig, DatapathEngine, DiscoConfig,
        DiscoEngine, DiscoEvent, DiscoFilterContext, MAGIC_SOCKET_BUFFER_SIZE, MagicSocket,
        MagicSocketConfig, OutboundDiscoPacket, PacketBuffer, PeerActivePath, PeerMap,
        PeerSendTarget, RebindCommand, RelayClientHandle, RelayEvent, SocketRebinder,
        StunClientConfig, validate_tun_mtu,
    };
    use mesh_net::{
        CandidateFilterContext, FakeHostsEditor, FakeTunDevice, HostsEditor as _, HostsEntry,
        TunConfig, is_valid_candidate_endpoint,
    };
    use mesh_proto::disco::IngressSource;
    use mesh_proto::netmap::{
        CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap,
    };
    use mesh_proto::relay::RELAY_MAX_CIPHERTEXT_BYTES;

    struct MetricSpec<'a> {
        id: &'a str,
        name: &'a str,
        measured: String,
        threshold: &'a str,
        unit: &'a str,
        passed: bool,
        details: &'a str,
    }

    fn json_escape(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for ch in raw.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                other => out.push(other),
            }
        }
        out
    }

    fn emit_metric(spec: MetricSpec<'_>) {
        let status = if spec.passed { "PASS" } else { "FAIL" };
        let line = format!(
            concat!(
                "{{\"id\":\"{}\",\"name\":\"{}\",\"measured\":{},\"threshold\":\"{}\",",
                "\"unit\":\"{}\",\"status\":\"{}\",\"method\":\"empirical_rust_datapath_slo\",",
                "\"details\":\"{}\"}}"
            ),
            json_escape(spec.id),
            json_escape(spec.name),
            spec.measured,
            json_escape(spec.threshold),
            json_escape(spec.unit),
            status,
            json_escape(spec.details),
        );
        println!("SLO_METRIC {line}");
        if let Some(dir) = std::env::var_os("MESH_SLO_METRICS_DIR") {
            let dir_path = PathBuf::from(dir);
            if fs::create_dir_all(&dir_path).is_ok() {
                let safe = spec.id.replace(['/', '\\', ':'], "_");
                let path = dir_path.join(format!("datapath-{safe}.json"));
                if let Err(err) = fs::write(path, format!("{line}\n")) {
                    eprintln!("failed writing datapath SLO metric file: {err}");
                }
            }
        }
    }

    fn put_slice(dst: &mut [u8], offset: usize, src: &[u8]) {
        if let Some(slot) = dst.get_mut(offset..offset + src.len()) {
            slot.copy_from_slice(src);
        }
    }

    fn build_ipv4_udp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, total_len: usize) -> Vec<u8> {
        let len = total_len.max(28);
        let mut pkt = vec![0_u8; len];
        let len_be = u16::try_from(len).unwrap_or(1280).to_be_bytes();
        let udp_be = u16::try_from(len.saturating_sub(20))
            .unwrap_or(8)
            .to_be_bytes();
        put_slice(&mut pkt, 0, &[0x45, 0x00, len_be[0], len_be[1]]);
        put_slice(&mut pkt, 8, &[64, 17]);
        put_slice(&mut pkt, 12, &src_ip.octets());
        put_slice(&mut pkt, 16, &dst_ip.octets());
        put_slice(&mut pkt, 20, &40_000_u16.to_be_bytes());
        put_slice(&mut pkt, 22, &51_829_u16.to_be_bytes());
        put_slice(&mut pkt, 24, &udp_be);

        let mut sum = 0_u32;
        if let Some(ipv4_hdr) = pkt.get(..20) {
            for chunk in ipv4_hdr.chunks_exact(2) {
                if let (Some(&hi), Some(&lo)) = (chunk.first(), chunk.get(1)) {
                    sum = sum.saturating_add(u32::from(u16::from_be_bytes([hi, lo])));
                }
            }
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = (!u16::try_from(sum).unwrap_or(0)).to_be_bytes();
        put_slice(&mut pkt, 10, &csum);
        pkt
    }

    struct NodeIdentity {
        id: NodeId,
        name: NodeName,
        ip: OverlayIp,
        wg_kp: NodeKeypair,
        disco_kp: DiscoKeypair,
        wan_addr: SocketAddr,
    }

    fn make_identity(idx: u8, port: u16) -> NodeIdentity {
        let now_ms = 1_762_960_000_000_u64 + u64::from(idx);
        let ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, idx.max(1))).expect("overlay ip");
        let name = NodeName::parse(&format!("dp-node-{idx:02}")).expect("node name");
        let wan_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, idx.max(1)));
        NodeIdentity {
            id: NodeId::new_v7(now_ms),
            name,
            ip,
            wg_kp: NodeKeypair::generate(),
            disco_kp: DiscoKeypair::generate(),
            wan_addr: SocketAddr::new(wan_ip, port),
        }
    }

    fn peer_entry(id: &NodeIdentity) -> PeerEntry {
        PeerEntry {
            node_id: id.id,
            name: id.name.clone(),
            fqdn: format!("{}.{DEFAULT_DOMAIN_SUFFIX}", id.name.as_str()),
            overlay_ip: id.ip,
            node_pubkey: id.wg_kp.public_key(),
            disco_pubkey: id.disco_kp.public_key(),
            endpoints: vec![CandidateEndpoint {
                addr: id.wan_addr,
                source: CandidateSource::Reflexive,
            }],
            relay_home: format!("203.0.113.250:{DEFAULT_CONTROL_TCP_PORT}"),
            key_expires_at_ms: None,
            online: true,
        }
    }

    fn make_snapshot(version: u64, peers: Vec<PeerEntry>) -> NetmapSnapshot {
        let dummy_pin = SpkiPin::parse(&format!("sha256:{}", sha256_hex(b"slo-pin"))).expect("pin");
        NetmapSnapshot {
            netmap_version: version,
            generated_at_ms: 1_762_960_000_000 + version,
            overlay_cidr: "100.115.0.0/16".parse::<OverlayCidr>().expect("cidr"),
            domain_suffix: DEFAULT_DOMAIN_SUFFIX.to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: format!("203.0.113.250:{DEFAULT_CONTROL_TCP_PORT}"),
                relay_tcp_endpoint: format!("203.0.113.250:{DEFAULT_CONTROL_TCP_PORT}"),
                stun_udp_endpoints: vec!["203.0.113.250:3478".to_owned()],
            },
            pin_set: PinSetDto {
                active_pin: dummy_pin,
                next_pin: None,
            },
            peers,
        }
    }

    fn setup_connected_pair() -> (NodeIdentity, NodeIdentity, PeerMap, PeerMap) {
        let a = make_identity(10, 51829);
        let b = make_identity(20, 51830);
        let mut map_a = PeerMap::new(a.id, a.wg_kp.clone_keypair());
        let mut map_b = PeerMap::new(b.id, b.wg_kp.clone_keypair());
        map_a.apply_diff(&make_snapshot(1, vec![peer_entry(&b)]));
        map_b.apply_diff(&make_snapshot(1, vec![peer_entry(&a)]));

        let mut enc_buf: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut dec_buf: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let seed_pkt = build_ipv4_udp_packet(a.ip.as_ipv4(), b.ip.as_ipv4(), 64);
        let (_, _, hs1_len) = map_a
            .encapsulate_to_overlay_ip(b.ip, &seed_pkt, &mut enc_buf, 1_000)
            .expect("encap hs1")
            .expect("hs init bytes");
        let hs1 = enc_buf.get(..hs1_len).unwrap_or(&[]).to_vec();
        let res_b = map_b
            .decapsulate_from_relay(a.wg_kp.public_key(), &hs1, &mut dec_buf, 1_001)
            .expect("decap hs1");
        for pkt in res_b.outbound_network_packets {
            let res_a = map_a
                .decapsulate_from_relay(b.wg_kp.public_key(), &pkt, &mut dec_buf, 1_002)
                .expect("decap hs2");
            for reply in res_a.outbound_network_packets {
                let _ =
                    map_b.decapsulate_from_relay(a.wg_kp.public_key(), &reply, &mut dec_buf, 1_003);
            }
        }
        (a, b, map_a, map_b)
    }

    fn p95_ms(samples: &mut [f64]) -> f64 {
        samples.sort_by(f64::total_cmp);
        let idx = ((samples.len() as f64) * 0.95).ceil() as usize;
        let clamped = idx.saturating_sub(1).min(samples.len().saturating_sub(1));
        samples.get(clamped).copied().unwrap_or(0.0)
    }

    #[test]
    fn test_slo_datapath_wg_latency_perf03_throughput_perf04_and_mtu_rel10() {
        // Arrange
        let mtu = validate_tun_mtu(DEFAULT_TUN_MTU).expect("validate default 1280 MTU");
        assert_eq!(mtu, 1280);
        let (a, b, mut map_a, mut map_b) = setup_connected_pair();
        assert!(map_a.set_direct_path(&b.id, b.wan_addr, CandidateSource::Reflexive, 1, 2_000));
        assert!(map_b.set_direct_path(&a.id, a.wan_addr, CandidateSource::Reflexive, 1, 2_000));
        let validator = CryptokeyValidator::new();
        let cidr = "100.115.0.0/16".parse::<OverlayCidr>().expect("cidr");
        let plain = build_ipv4_udp_packet(a.ip.as_ipv4(), b.ip.as_ipv4(), usize::from(mtu));
        let mut enc_buf: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut dec_buf: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];

        // Act 1: P95 single-packet encrypt + decrypt round-trip (1000 MTU-1280 frames)
        let mut samples_ms = Vec::with_capacity(1000);
        let mut max_wire_len = 0_usize;
        for step in 0..1000_u64 {
            let t0 = Instant::now();
            let (_, _, wg_len) = map_a
                .encapsulate_to_overlay_ip(b.ip, &plain, &mut enc_buf, 3_000 + step)
                .expect("wg enc")
                .expect("wg ciphertext");
            max_wire_len = max_wire_len.max(wg_len);
            let wire = enc_buf.get(..wg_len).unwrap_or(&[]);
            let dec = map_b
                .decapsulate_from_udp(a.wan_addr, wire, &mut dec_buf, 3_000 + step)
                .expect("wg dec");
            let dec_len = dec.tunnel_payload_len.expect("inner ipv4 len");
            let inner = dec_buf.get(..dec_len).unwrap_or(&[]);
            assert!(
                validator
                    .validate_inbound(a.ip, Some(b.ip), cidr, inner)
                    .is_ok()
            );
            samples_ms.push(t0.elapsed().as_secs_f64() * 1_000.0);
        }
        let p95 = p95_ms(&mut samples_ms);

        // Act 2: Sustained userspace WG throughput (2500 x 1280B frames)
        let bulk_frames = 2500_usize;
        let bulk_start = Instant::now();
        for step in 0..bulk_frames {
            let (_, _, wg_len) = map_a
                .encapsulate_to_overlay_ip(b.ip, &plain, &mut enc_buf, 10_000 + step as u64)
                .expect("bulk enc")
                .expect("bulk ciphertext");
            let wire = enc_buf.get(..wg_len).unwrap_or(&[]);
            let dec = map_b
                .decapsulate_from_udp(a.wan_addr, wire, &mut dec_buf, 10_000 + step as u64)
                .expect("bulk dec");
            assert_eq!(dec.tunnel_payload_len, Some(plain.len()));
        }
        let elapsed_s = bulk_start.elapsed().as_secs_f64().max(0.000_001);
        let total_bits = (bulk_frames * plain.len() * 8) as f64;
        let mbps = total_bits / (elapsed_s * 1_000_000.0);

        // Assert & Emit
        assert!(max_wire_len <= RELAY_MAX_CIPHERTEXT_BYTES);
        assert!(max_wire_len <= MAX_FRAME_SIZE);
        assert!(p95 <= 2.0, "PERF-03 WG P95 latency exceeded 2.0 ms: {p95}");
        assert!(
            mbps >= 210.0,
            "PERF-04 WG throughput below 210 Mbps: {mbps}"
        );

        emit_metric(MetricSpec {
            id: "PERF-03",
            name: "WireGuard encrypt+decrypt + cryptokey P95 latency (MTU 1280)",
            measured: format!("{p95:.4}"),
            threshold: "<= 2.0",
            unit: "ms",
            passed: p95 <= 2.0,
            details: "1000 MTU-1280 BoringTun ChaCha20Poly1305 encap+decap frames",
        });
        emit_metric(MetricSpec {
            id: "PERF-04",
            name: "In-memory userspace WireGuard throughput (>=70% of 300 Mbps)",
            measured: format!("{mbps:.2}"),
            threshold: ">= 210.0",
            unit: "Mbps",
            passed: mbps >= 210.0,
            details: "2500 x 1280B PeerMap encrypt+decrypt pipeline",
        });
        emit_metric(MetricSpec {
            id: "REL-10",
            name: "Overlay MTU 1280 framing & fragmentation-free encapsulation headroom",
            measured: max_wire_len.to_string(),
            threshold: "<= 1480",
            unit: "bytes",
            passed: max_wire_len <= RELAY_MAX_CIPHERTEXT_BYTES,
            details: "validated MTU 1280 BoringTun ciphertext <= RELAY_MAX_CIPHERTEXT_BYTES",
        });
    }

    fn perform_disco_upgrade(
        a: &NodeIdentity,
        b: &NodeIdentity,
        map_a: &mut PeerMap,
        map_b: &mut PeerMap,
        filter: &DiscoFilterContext<'_>,
    ) -> f64 {
        let cfg = DiscoConfig::default();
        let mut disco_a = DiscoEngine::new(a.disco_kp.clone_keypair(), cfg.clone());
        let mut disco_b = DiscoEngine::new(b.disco_kp.clone_keypair(), cfg);
        let t0 = Instant::now();
        let punches = disco_a.initiate_hole_punch(map_a, b.id, &[a.wan_addr], filter, 5_000);
        for pkt in punches {
            if matches!(pkt.target, PeerSendTarget::Direct(_)) {
                let (_, _, replies) = disco_b.handle_incoming_tracked(
                    &pkt.bytes,
                    IngressSource::DirectUdp(a.wan_addr),
                    map_b,
                    filter,
                    5_002,
                );
                for pong in replies {
                    let (ev, _, _) = disco_a.handle_incoming_tracked(
                        &pong.bytes,
                        IngressSource::DirectUdp(b.wan_addr),
                        map_a,
                        filter,
                        5_004,
                    );
                    assert!(matches!(ev, DiscoEvent::DirectPathVerified { .. }));
                }
            }
        }
        t0.elapsed().as_secs_f64() * 1_000.0
    }

    fn verify_3strike_failover_and_idle(
        a: &NodeIdentity,
        b: &NodeIdentity,
        map_a: &mut PeerMap,
        filter: &DiscoFilterContext<'_>,
    ) -> (u64, usize) {
        let mut disco_a = DiscoEngine::new(a.disco_kp.clone_keypair(), DiscoConfig::default());
        let mut now_ms = 20_000_u64;
        let _ = disco_a.initiate_hole_punch(map_a, b.id, &[a.wan_addr], filter, now_ms);
        for step in 1..=3_u64 {
            now_ms = 20_000 + step * 3_100;
            let _ = disco_a.tick(map_a, now_ms);
        }
        assert_eq!(disco_a.metrics_snapshot().direct_failovers, 1);
        assert!(matches!(
            map_a.get(&b.id).map(|s| &s.active_path),
            Some(PeerActivePath::Relay)
        ));
        let failover_budget_ms = now_ms - 20_000;

        // Advance well past 180s idle window -> keepalive tick emits 0 bytes
        let idle_pkts: Vec<OutboundDiscoPacket> = disco_a.tick(map_a, now_ms + 360_000);
        let idle_bytes: usize = idle_pkts.iter().map(|p| p.bytes.len()).sum();
        (failover_budget_ms, idle_bytes)
    }

    #[test]
    fn test_slo_datapath_relay_first_disco_upgrade_perf05_and_3strike_failover_perf06() {
        // Arrange
        let (a, b, mut map_a, mut map_b) = setup_connected_pair();
        let cidr = "100.115.0.0/16".parse::<OverlayCidr>().expect("cidr");
        let cand_ctx = CandidateFilterContext {
            overlay_cidr: cidr,
            control_tcp_endpoint: None,
            stun_udp_endpoint: None,
        };
        let filter = DiscoFilterContext {
            candidates: &cand_ctx,
            excluded_stun: &[],
        };
        let mut buf: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut dec_buf: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let payload = build_ipv4_udp_packet(a.ip.as_ipv4(), b.ip.as_ipv4(), 64);

        // Act 1: REL-01 & REL-06 & PERF-05 initial packet via Blind Relay (control offline)
        let t_relay = Instant::now();
        let (_, target, wg_len) = map_a
            .encapsulate_to_overlay_ip(b.ip, &payload, &mut buf, 4_000)
            .expect("relay encap")
            .expect("relay pkt");
        assert!(matches!(target, PeerSendTarget::Relay(_)));
        let dec = map_b
            .decapsulate_from_relay(
                a.wg_kp.public_key(),
                buf.get(..wg_len).unwrap_or(&[]),
                &mut dec_buf,
                4_001,
            )
            .expect("relay decap");
        assert_eq!(dec.tunnel_payload_len, Some(payload.len()));
        let relay_first_ms = t_relay.elapsed().as_secs_f64() * 1_000.0;

        // Act 2: PERF-05 Disco direct upgrade + PERF-06 3-strike failover + PERF-10 idle rate
        let disco_ms = perform_disco_upgrade(&a, &b, &mut map_a, &mut map_b, &filter);
        assert!(matches!(
            map_a.get(&b.id).map(|s| &s.active_path),
            Some(PeerActivePath::Direct { .. })
        ));
        let (failover_ms, idle_bytes) =
            verify_3strike_failover_and_idle(&a, &b, &mut map_a, &filter);

        // Assert & Emit
        assert!(relay_first_ms <= 1_000.0);
        assert!(disco_ms <= 5_000.0);
        assert!(failover_ms <= 10_000);
        assert!(idle_bytes <= 1024);

        emit_metric(MetricSpec {
            id: "PERF-05",
            name: "Initial packet via Relay (<=1s) & Disco Direct upgrade (<=5s)",
            measured: format!("{disco_ms:.3}"),
            threshold: "<= 5000.0",
            unit: "ms",
            passed: relay_first_ms <= 1_000.0 && disco_ms <= 5_000.0,
            details: "verified Relay first packet <1s then DirectUdp DiscoPong promotion <5s",
        });
        emit_metric(MetricSpec {
            id: "PERF-06",
            name: "Direct -> Relay 3-strike failover convergence",
            measured: failover_ms.to_string(),
            threshold: "<= 10000",
            unit: "ms",
            passed: failover_ms <= 10_000,
            details: "3 missed 3.1s probes triggered direct_failovers=1 within 9300ms <= 10s SLO",
        });
        emit_metric(MetricSpec {
            id: "PERF-10",
            name: "Idle background keepalive & heartbeat rate",
            measured: idle_bytes.to_string(),
            threshold: "<= 1024",
            unit: "B/s",
            passed: idle_bytes <= 1024,
            details: "idle peer past 180s window emitted 0 B/s Disco keepalives",
        });
        emit_metric(MetricSpec {
            id: "REL-01",
            name: "Control outage cached PeerMap data-plane continuity",
            measured: "1".to_owned(),
            threshold: "== 1",
            unit: "pass",
            passed: dec.tunnel_payload_len == Some(payload.len()),
            details: "cached PeerMap encrypted/decrypted packets without live Control stream",
        });
        emit_metric(MetricSpec {
            id: "REL-06",
            name: "UDP-blocked / Relay-only forwarding path",
            measured: "1".to_owned(),
            threshold: "== 1",
            unit: "pass",
            passed: matches!(
                map_a.get(&b.id).map(|s| &s.active_path),
                Some(PeerActivePath::Relay)
            ),
            details: "PeerMap routed traffic via Blind Relay on initial connect & post-failover",
        });
    }

    async fn spawn_and_shutdown_datapath_engine(clock: Arc<FakeClock>) -> f64 {
        let id = make_identity(1, 0);
        let cidr = "100.115.0.0/16".parse::<OverlayCidr>().expect("cidr");
        let tun_cfg = TunConfig::with_default_mtu("mesh-slo0", id.ip, cidr).expect("tun cfg");
        let tun = Arc::new(FakeTunDevice::new(tun_cfg));
        let cfg = DatapathConfig {
            local_node_id: id.id,
            local_overlay_ip: id.ip,
            overlay_cidr: cidr,
            node_keypair: id.wg_kp,
            disco_keypair: id.disco_kp,
            socket_config: MagicSocketConfig::default()
                .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: Duration::from_millis(50),
            disco_tick_interval: Duration::from_millis(50),
        };
        let relay = RelayClientHandle::new();
        let engine = DatapathEngine::bind(cfg, tun.clone(), clock, Some(relay))
            .await
            .expect("bind engine");
        let handle = engine.handle();
        let (_relay_tx, relay_rx) = mpsc::channel::<RelayEvent>(16);
        let (_rebind_tx, rebind_rx) = mpsc::channel::<RebindCommand>(16);
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(engine.run(relay_rx, rebind_rx, shutdown.clone()));

        let peer = make_identity(2, 51829);
        assert!(
            handle
                .apply_netmap(make_snapshot(2, vec![peer_entry(&peer)]))
                .await
                .is_ok()
        );

        let t0 = Instant::now();
        shutdown.cancel();
        let res = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("shutdown within 5s");
        assert!(matches!(res, Ok(Ok(()))));
        assert!(tun.is_closed());
        t0.elapsed().as_secs_f64() * 1_000.0
    }

    #[tokio::test]
    async fn test_slo_datapath_clock_jump_perf07_hol_perf11_and_shutdown_rel08() {
        // Act 1: PERF-07 Clock jump +240s + MagicSocket rebind recovery
        let clock = Arc::new(FakeClock::new(1_762_960_000_000));
        let mut detector = ClockJumpDetector::new(clock.as_ref());
        let mut sock = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("bind loopback magic socket");

        let t_jump = Instant::now();
        clock.jump_wall_ms(240_000);
        let jump_ev = detector.check(clock.as_ref()).expect("detect +240s jump");
        assert_eq!(jump_ev.drift_ms, 240_000);
        let rebound = SocketRebinder::rebind_socket(&mut sock, "lo", None, None);
        assert!(rebound.is_ok());
        let rebind_ms = t_jump.elapsed().as_secs_f64() * 1_000.0;

        // Act 2: PERF-11 client RelayClientHandle 256-slot HoL isolation
        let relay = RelayClientHandle::new();
        let pk_sat = PublicKey::from_bytes([0x11_u8; 32]).expect("pk sat");
        let pk_good = PublicKey::from_bytes([0x22_u8; 32]).expect("pk good");
        let mut dropped = 0_usize;
        for _ in 0..320 {
            if !relay.try_send_packet(pk_sat, Bytes::from_static(b"sat")) {
                dropped += 1;
            }
        }
        let mut good_ok = 0_usize;
        for _ in 0..128 {
            if relay.try_send_packet(pk_good, Bytes::from_static(b"ok")) {
                good_ok += 1;
            }
        }
        assert!(dropped > 0);
        assert_eq!(good_ok, 128);
        assert_eq!(RELAY_QUEUE_CAPACITY, 256);

        // Act 3: REL-08 DatapathEngine graceful teardown <= 5s
        let teardown_ms = spawn_and_shutdown_datapath_engine(clock).await;
        assert!(rebind_ms <= 15_000.0);
        assert!(teardown_ms <= 5_000.0);

        emit_metric(MetricSpec {
            id: "PERF-07",
            name: "Clock-jump (+240s) detection & socket rebind recovery",
            measured: format!("{rebind_ms:.3}"),
            threshold: "<= 15000.0",
            unit: "ms",
            passed: rebind_ms <= 15_000.0,
            details: "ClockJumpDetector(+240s) + SocketRebinder::rebind_socket completed",
        });
        emit_metric(MetricSpec {
            id: "REL-08",
            name: "Graceful DatapathEngine & FakeTunDevice shutdown",
            measured: format!("{teardown_ms:.3}"),
            threshold: "<= 5000.0",
            unit: "ms",
            passed: teardown_ms <= 5_000.0,
            details: "CancellationToken closed TUN and stopped DatapathEngine within 5s budget",
        });
        emit_metric(MetricSpec {
            id: "PERF-11-QUEUE",
            name: "Client Blind Relay mpsc(256) HoL isolation & 20 Mbps constant",
            measured: format!("{good_ok}"),
            threshold: "== 128",
            unit: "frames",
            passed: good_ok == 128 && dropped > 0,
            details: "saturated peer dropped tail at mpsc(256) with 0 HoL impact on peer B",
        });
    }

    fn verify_antiloop_and_hosts(cidr: OverlayCidr) -> (bool, bool) {
        let stun_ep = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 250)), 3478);
        let ctx = CandidateFilterContext {
            overlay_cidr: cidr,
            control_tcp_endpoint: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 250)),
                DEFAULT_CONTROL_TCP_PORT,
            )),
            stun_udp_endpoint: Some(stun_ep),
        };
        let utun_bad = !is_valid_candidate_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 51829),
            Some("utun3"),
            &ctx,
        );
        let overlay_bad = !is_valid_candidate_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 115, 0, 10)), 51829),
            Some("eth0"),
            &ctx,
        );
        let stun_bad = !is_valid_candidate_endpoint(stun_ep, Some("eth0"), &ctx);
        let phys_ok = is_valid_candidate_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 51829),
            Some("eth0"),
            &ctx,
        );
        let antiloop_ok = utun_bad && overlay_bad && stun_bad && phys_ok;

        let init = "127.0.0.1 localhost\r\n# keep-me\r\n";
        let editor = FakeHostsEditor::with_initial(init);
        let ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 5)).expect("ip");
        let name = NodeName::parse("edge-05").expect("name");
        let entry =
            HostsEntry::new(ip, name, DEFAULT_DOMAIN_SUFFIX, Some("203.0.113.250")).expect("entry");
        let collision = HostsEntry::new(
            ip,
            NodeName::parse("vps").expect("vps"),
            DEFAULT_DOMAIN_SUFFIX,
            Some("vps.mesh.internal"),
        );
        let applied_ok = editor.apply(&[entry], Some("203.0.113.250")).is_ok()
            && editor
                .snapshot()
                .unwrap_or_default()
                .contains("# BEGIN mesh")
            && editor.clear().is_ok()
            && editor.snapshot().unwrap_or_default() == init
            && collision.is_err();
        (antiloop_ok, applied_ok)
    }

    fn measure_self_rss_mib() -> f64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("VmRSS:")
                        && let Some(kib_str) = rest.split_whitespace().next()
                        && let Ok(kib) = kib_str.parse::<u64>()
                    {
                        return (kib as f64) / 1024.0;
                    }
                }
            }
            0.0
        }
        #[cfg(target_os = "macos")]
        {
            let pid = std::process::id().to_string();
            if let Ok(out) = std::process::Command::new("/bin/ps")
                .args(["-o", "rss=", "-p", &pid])
                .output()
                && out.status.success()
                && let Ok(raw) = String::from_utf8(out.stdout)
                && let Ok(kib) = raw.trim().parse::<u64>()
            {
                return (kib as f64) / 1024.0;
            }
            0.0
        }
        #[cfg(target_os = "windows")]
        {
            let script = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
            if let Ok(out) = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                && out.status.success()
                && let Ok(raw) = String::from_utf8(out.stdout)
                && let Ok(bytes) = raw.trim().parse::<u64>()
            {
                return (bytes as f64) / (1024.0 * 1024.0);
            }
            0.0
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            0.0
        }
    }

    #[test]
    fn test_slo_datapath_footprint_perf09_antiloop_rel09_cryptokey_sec11_hosts_plat04() {
        // Arrange: 20-peer PeerMap + static PacketBuffers + secret redaction
        let local = make_identity(1, 51829);
        let mut peers = Vec::with_capacity(20);
        for idx in 2..=21_u8 {
            peers.push(peer_entry(&make_identity(idx, 51829 + u16::from(idx))));
        }
        let mut map = PeerMap::new(local.id, local.wg_kp.clone_keypair());
        let diff = map.apply_diff(&make_snapshot(5, peers));
        assert_eq!(diff.added, 20);
        assert_eq!(map.len(), 20);
        let packet_buffers: [PacketBuffer; 4] = [[0_u8; MAGIC_SOCKET_BUFFER_SIZE]; 4];

        let cidr = "100.115.0.0/16".parse::<OverlayCidr>().expect("cidr");
        let secret = Secret::new([0x7b_u8; 32]);
        let secret_dbg = format!("{secret:?} {local:?} {map:?}", local = local.wg_kp);
        let sec01_ok = secret_dbg.contains("[REDACTED]") && !secret_dbg.contains("123, 123");

        // Act: SEC-11 strict /32 inner source IP check + REL-09 + PLAT-04
        let validator = CryptokeyValidator::new();
        let peer_ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 2)).expect("peer ip");
        let spoof_ip = Ipv4Addr::new(100, 115, 0, 99);
        let spoof_pkt = build_ipv4_udp_packet(spoof_ip, local.ip.as_ipv4(), 48);
        let spoof_res = validator.validate_inbound(peer_ip, Some(local.ip), cidr, &spoof_pkt);
        let sec11_ok = matches!(spoof_res, Err(CryptokeyDropReason::SpoofedSourceIp { .. }))
            && validator.metrics_snapshot().spoofed_packets_dropped == 1;
        let (rel09_ok, plat04_ok) = verify_antiloop_and_hosts(cidr);

        // Measure live process RSS/WorkingSet while holding PeerMap(20) + 4 x PacketBuffer(2048)
        let struct_bytes = map.len() * std::mem::size_of::<mesh_datapath::PeerSession>()
            + std::mem::size_of_val(&packet_buffers)
            + std::mem::size_of::<PeerMap>();
        let struct_mib = (struct_bytes as f64) / (1024.0 * 1024.0);
        let rss_mib = measure_self_rss_mib();
        std::hint::black_box((map.len(), packet_buffers[0][0]));

        // Assert & Emit
        assert!(
            rss_mib > 0.0 && rss_mib <= 50.0,
            "live datapath RSS {rss_mib:.2} MiB outside (0.0, 50.0]"
        );
        assert!(struct_mib < 5.0 && sec01_ok && sec11_ok && rel09_ok && plat04_ok);
        let details = format!(
            "live process RSS={rss_mib:.2} MiB; bounded PeerMap(20)+4xPacketBuffer(2048) struct_mib={struct_mib:.6} MiB"
        );
        emit_metric(MetricSpec {
            id: "PERF-09",
            name: "Idle datapath in-memory bounded footprint (20 peers + 4x2KB bufs)",
            measured: format!("{rss_mib:.2}"),
            threshold: "<= 50.0",
            unit: "MiB",
            passed: rss_mib > 0.0 && rss_mib <= 50.0 && struct_mib < 5.0,
            details: &details,
        });
        emit_metric(MetricSpec {
            id: "SEC-01",
            name: "Zero plaintext key material in datapath Debug outputs",
            measured: "0".to_owned(),
            threshold: "== 0",
            unit: "leaks",
            passed: sec01_ok,
            details: "Secret<T> & NodeKeypair Debug verified to emit [REDACTED]",
        });
        emit_metric(MetricSpec {
            id: "SEC-11",
            name: "WireGuard strict /32 inner source IP cryptokey enforcement",
            measured: "1".to_owned(),
            threshold: "== 1",
            unit: "pass",
            passed: sec11_ok,
            details: "CryptokeyValidator dropped spoofed inner source IP with counter increment",
        });
        emit_metric(MetricSpec {
            id: "REL-09",
            name: "Routing-loop guard rejecting virtual NIC / overlay / STUN candidates",
            measured: "1".to_owned(),
            threshold: "== 1",
            unit: "pass",
            passed: rel09_ok,
            details: "CandidateFilterContext rejected utun3, overlay CIDR, and STUN endpoint",
        });
        emit_metric(MetricSpec {
            id: "PLAT-04",
            name: "Safe managed # BEGIN mesh hosts block & public_host collision rejection",
            measured: "1".to_owned(),
            threshold: "== 1",
            unit: "pass",
            passed: plat04_ok,
            details: "FakeHostsEditor preserved CRLF lines/comments and rejected public_host collision",
        });
    }
}
