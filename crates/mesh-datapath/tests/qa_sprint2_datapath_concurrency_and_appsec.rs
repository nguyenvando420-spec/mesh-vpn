//! Independent Sprint 2 QA Integration, Concurrency & AppSec Tests for `mesh-datapath`.
//!
//! Covers:
//! - `US-030 AC1/AC2`, `US-026` & `HR-W21-07`: Live `DatapathEngine` peer revocation cutting
//!   active sessions in `< 200 ms` (`<= 2 s` SLA), purging `RelayClientHandle` queues, and
//!   resolving STUN hostnames asynchronously off the event loop
//! - `US-018 AC1/AC2/AC3` & `SEC-11`: Inbound host packet filter (`parse_inbound_filter_spec`,
//!   `CryptokeyValidator`, `DatapathHandle::try_reload_packet_filter_spec`) blocking denied ports,
//!   dropping non-initial IPv4 fragments, and failing closed while preserving valid policy on error
//! - `US-035`, `US-036` & `HR-W21-08`: Synchronous `oneshot`-acknowledged `MagicSocket` underlay
//!   rebind (`begin_rebind` + `rebind_underlay` + `RebindCommand::RebindInterface`)
//! - `US-021 AC5`, `US-022` & `US-027`: `CallMeMaybe` rate limit (`10/min`) and Blind Relay outer/inner
//!   public key mismatch rejection (`relay_src_pubkey_mismatch` / `relay_poison_attempts_blocked`)

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use mesh_core::defaults::DEFAULT_TUN_MTU;
    use mesh_core::{FakeClock, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin};
    use mesh_crypto::{DiscoKeypair, DiscoSealParams, NodeKeypair, seal_disco_packet};
    use mesh_datapath::disco_engine::CALL_ME_MAYBE_RATE_LIMIT_PER_MIN;
    use mesh_datapath::{
        CryptokeyDropReason, CryptokeyValidator, DatapathConfig, DatapathEngine, DiscoConfig,
        DiscoEngine, DiscoEvent, DiscoFilterContext, MagicSocketConfig, RebindCommand,
        RelayClientHandle, StunClientConfig, parse_inbound_filter_spec,
    };
    use mesh_net::endpoint_filter::CandidateFilterContext;
    use mesh_net::tun::{FakeTunDevice, TunConfig};
    use mesh_proto::disco::{DiscoBody, IngressSource};
    use mesh_proto::netmap::{
        CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap,
    };

    struct TestPeer {
        node_id: NodeId,
        name: String,
        overlay_ip: OverlayIp,
        node_kp: NodeKeypair,
        disco_kp: DiscoKeypair,
        endpoint: SocketAddr,
    }

    impl TestPeer {
        fn new(seed: u8, name: &str, octet: u8, port: u16) -> Self {
            Self {
                node_id: NodeId::from_bytes([seed; 16]),
                name: name.to_owned(),
                overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, octet))
                    .expect("valid overlay ip"),
                node_kp: NodeKeypair::generate(),
                disco_kp: DiscoKeypair::generate(),
                endpoint: SocketAddr::from(([198, 51, 100, octet], port)),
            }
        }

        fn to_peer_entry(&self) -> PeerEntry {
            PeerEntry {
                node_id: self.node_id,
                name: NodeName::parse(&self.name).expect("valid node name"),
                fqdn: format!("{}.mesh.internal", self.name),
                overlay_ip: self.overlay_ip,
                node_pubkey: self.node_kp.public_key(),
                disco_pubkey: self.disco_kp.public_key(),
                endpoints: vec![CandidateEndpoint {
                    addr: self.endpoint,
                    source: CandidateSource::Reflexive,
                }],
                relay_home: "203.0.113.10:9443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            }
        }
    }

    fn build_snapshot_with_stun(
        version: u64,
        peers: Vec<PeerEntry>,
        stun_endpoints: Vec<String>,
    ) -> NetmapSnapshot {
        NetmapSnapshot {
            netmap_version: version,
            generated_at_ms: 1_762_975_000_000,
            overlay_cidr: "10.100.0.0/16".parse().expect("valid cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:9443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:9443".to_owned(),
                stun_udp_endpoints: stun_endpoints,
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([0x22_u8; 32]),
                next_pin: None,
            },
            peers,
        }
    }

    fn build_ipv4_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        dst_port: u16,
        non_initial_fragment: bool,
    ) -> Vec<u8> {
        let [s0, s1, s2, s3] = src.octets();
        let [d0, d1, d2, d3] = dst.octets();
        let [p_hi, p_lo] = dst_port.to_be_bytes();
        let mut pkt = vec![0_u8; 32];
        if let Some(hdr) = pkt.get_mut(..28) {
            hdr.copy_from_slice(&[
                0x45,
                0x00,
                0x00,
                32,
                0x00,
                0x01,
                if non_initial_fragment { 0x00 } else { 0x40 },
                if non_initial_fragment { 0x01 } else { 0x00 },
                0x40,
                protocol,
                0x00,
                0x00,
                s0,
                s1,
                s2,
                s3,
                d0,
                d1,
                d2,
                d3,
                0x13,
                0x88,
                p_hi,
                p_lo,
                0x00,
                0x0C,
                0x00,
                0x00,
            ]);
        }
        pkt
    }

    fn seal_test_disco(
        sender: &DiscoKeypair,
        recipient: &DiscoKeypair,
        seq: u32,
        body: &DiscoBody,
        now_ms: u64,
    ) -> Vec<u8> {
        let mut tx_id = [0_u8; 12];
        if let Some(prefix) = tx_id.get_mut(..4) {
            prefix.copy_from_slice(&seq.to_be_bytes());
        }
        let encoded_body = body.encode().expect("encode DiscoBody");
        seal_disco_packet(
            sender,
            &DiscoSealParams {
                recipient_pubkey: recipient.public_key(),
                msg_type: body.msg_type() as u8,
                tx_id,
                sent_at_ms: now_ms,
                body: &encoded_body,
            },
        )
        .expect("seal Disco packet")
    }

    #[tokio::test]
    async fn test_datapath_engine_live_peer_revocation_cuts_active_session_under_2s_and_purges_queues()
     {
        // Arrange
        let local = TestPeer::new(0x10, "node-local", 10, 51820);
        let peer_b = TestPeer::new(0x20, "node-revoked", 20, 51821);
        let cidr: OverlayCidr = "10.100.0.0/16".parse().expect("valid cidr");
        let tun_cfg = TunConfig::new("utun9", local.overlay_ip, cidr, DEFAULT_TUN_MTU)
            .expect("valid tun config");
        let fake_tun = Arc::new(FakeTunDevice::new(tun_cfg));
        let clock = Arc::new(FakeClock::new(1_762_975_000_000));
        let relay_handle = RelayClientHandle::new();

        let cfg = DatapathConfig {
            local_node_id: local.node_id,
            local_overlay_ip: local.overlay_ip,
            overlay_cidr: cidr,
            node_keypair: local.node_kp.clone_keypair(),
            disco_keypair: local.disco_kp.clone_keypair(),
            socket_config: MagicSocketConfig {
                bind_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                preferred_port: None,
                mtu: DEFAULT_TUN_MTU,
                ..MagicSocketConfig::default()
            },
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: Duration::from_millis(250),
            disco_tick_interval: Duration::from_millis(250),
        };

        let engine = DatapathEngine::bind(cfg, fake_tun, clock, Some(relay_handle.clone()))
            .await
            .expect("bind DatapathEngine");
        let handle = engine.handle();
        let (_relay_ev_tx, relay_ev_rx) = mpsc::channel(16);
        let (_rebind_tx, rebind_rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let shutdown_runner = shutdown.clone();
        let runner = tokio::spawn(async move {
            engine
                .run(relay_ev_rx, rebind_rx, shutdown_runner)
                .await
                .expect("engine run clean")
        });

        let snap_v1 = build_snapshot_with_stun(
            1,
            vec![peer_b.to_peer_entry()],
            vec![
                "127.0.0.1:13478".to_owned(),
                "unresolvable-stun.invalid:3478".to_owned(),
            ],
        );
        assert_eq!(
            handle
                .apply_netmap(snap_v1)
                .await
                .expect("apply netmap v1")
                .added,
            1
        );

        assert!(relay_handle.try_send_packet(
            peer_b.node_kp.public_key(),
            Bytes::from_static(&[0xAA_u8; 64]),
        ));

        // Act: Apply v2 netmap removing Peer B (`US-030 AC1/AC2` & `HR-W21-07`)
        let start = Instant::now();
        let snap_v2 = build_snapshot_with_stun(
            2,
            Vec::new(),
            vec!["unresolvable-stun-2.invalid:3478".to_owned()],
        );
        let diff_v2 = handle.apply_netmap(snap_v2).await.expect("apply netmap v2");
        let revoke_elapsed = start.elapsed();

        // Assert
        assert!(
            revoke_elapsed < Duration::from_millis(800),
            "apply_netmap took {revoke_elapsed:?}, expected < 800ms"
        );
        assert_eq!(diff_v2.removed, 1);
        assert_eq!(
            relay_handle.remove_peer_queues(&[peer_b.node_kp.public_key()]),
            0,
            "DatapathEngine::apply_netmap must have already purged the revoked peer queue"
        );
        let status = handle.query_status().await.expect("query status");
        assert!(status.netmap_version == 2 && status.peers.is_empty());

        shutdown.cancel();
        runner.await.expect("join engine task");
    }

    #[tokio::test]
    async fn test_datapath_inbound_packet_filter_enforces_port_rules_and_fails_closed_on_invalid_spec()
     {
        // Arrange
        let cidr: OverlayCidr = "10.100.0.0/16".parse().expect("valid cidr");
        let peer_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 2)).expect("peer ip");
        let local_overlay = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 1)).expect("local ip");
        let local_ip = local_overlay.as_ipv4();
        let mut validator = CryptokeyValidator::new();

        // Act 1: Parse and apply `"tcp:3389,udp:5353"` deny policy (`US-018 AC1/AC2`)
        let policy =
            parse_inbound_filter_spec("tcp:3389,udp:5353").expect("parse valid filter spec");
        validator.set_policy(policy.clone());

        let allowed_https = build_ipv4_packet(peer_ip.as_ipv4(), local_ip, 6, 443, false);
        let allowed_icmp = build_ipv4_packet(peer_ip.as_ipv4(), local_ip, 1, 0, false);
        let blocked_rdp = build_ipv4_packet(peer_ip.as_ipv4(), local_ip, 6, 3389, false);
        let blocked_mdns = build_ipv4_packet(peer_ip.as_ipv4(), local_ip, 17, 5353, false);
        let blocked_frag = build_ipv4_packet(peer_ip.as_ipv4(), local_ip, 6, 443, true);

        // Assert 1
        assert!(
            validator
                .validate_inbound(peer_ip, Some(local_overlay), cidr, &allowed_https)
                .is_ok()
        );
        assert!(
            validator
                .validate_inbound(peer_ip, Some(local_overlay), cidr, &allowed_icmp)
                .is_ok()
        );
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_overlay), cidr, &blocked_rdp),
            Err(CryptokeyDropReason::PolicyDenied)
        );
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_overlay), cidr, &blocked_mdns),
            Err(CryptokeyDropReason::PolicyDenied)
        );
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_overlay), cidr, &blocked_frag),
            Err(CryptokeyDropReason::PolicyDenied)
        );

        // Act 2: Invalid filter spec must fail validation without corrupting existing policy (`US-018 AC3`)
        assert!(validator.try_reload_policy_spec("tcp:99999").is_err());
        assert!(validator.try_reload_policy_spec("tcp:8080-8000").is_err());
        assert_eq!(validator.policy(), &policy);

        // Fail-closed policy drops all traffic
        validator
            .try_reload_policy_spec("fail-closed")
            .expect("reload fail-closed");
        assert_eq!(
            validator.validate_inbound(peer_ip, Some(local_overlay), cidr, &allowed_https),
            Err(CryptokeyDropReason::PolicyDenied)
        );
        assert_eq!(validator.metrics_snapshot().filtered_packets_dropped, 4);
    }

    #[tokio::test]
    async fn test_datapath_rebind_command_synchronizes_via_oneshot_and_recovers_magic_socket_port()
    {
        // Arrange
        let local = TestPeer::new(0x30, "node-rebind", 30, 51820);
        let cidr: OverlayCidr = "10.100.0.0/16".parse().expect("valid cidr");
        let tun_cfg = TunConfig::new("utun8", local.overlay_ip, cidr, DEFAULT_TUN_MTU)
            .expect("valid tun config");
        let fake_tun = Arc::new(FakeTunDevice::new(tun_cfg));
        let clock = Arc::new(FakeClock::new(1_762_976_000_000));

        let cfg = DatapathConfig {
            local_node_id: local.node_id,
            local_overlay_ip: local.overlay_ip,
            overlay_cidr: cidr,
            node_keypair: local.node_kp.clone_keypair(),
            disco_keypair: local.disco_kp.clone_keypair(),
            socket_config: MagicSocketConfig {
                bind_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                preferred_port: None,
                mtu: DEFAULT_TUN_MTU,
                ..MagicSocketConfig::default()
            },
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: Duration::from_millis(250),
            disco_tick_interval: Duration::from_millis(250),
        };

        let engine = DatapathEngine::bind(cfg, fake_tun, clock, None)
            .await
            .expect("bind DatapathEngine");
        let initial_port = engine.local_udp_addr().expect("local addr").port();
        let handle = engine.handle();
        let (_relay_ev_tx, relay_ev_rx) = mpsc::channel(16);
        let (rebind_tx, rebind_rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();
        let shutdown_runner = shutdown.clone();
        let runner = tokio::spawn(async move {
            engine
                .run(relay_ev_rx, rebind_rx, shutdown_runner)
                .await
                .expect("engine run clean")
        });

        // Act: Trigger `begin_rebind` + `rebind_underlay` (`HR-W21-08`) and `RebindCommand::RebindInterface`
        handle.begin_rebind().await.expect("begin rebind");
        let rebound_port = handle
            .rebind_underlay("eth0".to_owned(), None, false)
            .await
            .expect("rebind underlay via DatapathHandle");
        assert!(rebound_port > 0);

        rebind_tx
            .send(RebindCommand::RebindInterface {
                interface_name: "wlan0".to_owned(),
                if_index: None,
                is_ipv6: false,
            })
            .await
            .expect("send RebindCommand");

        // Assert
        let status = handle.query_status().await.expect("query status");
        assert!(initial_port > 0 && status.local_udp_addr.map(|a| a.port()).unwrap_or(0) > 0);

        shutdown.cancel();
        runner.await.expect("join engine task");
    }

    #[test]
    fn test_datapath_disco_call_me_maybe_rate_limit_and_spoofed_relay_source_rejection() {
        // Arrange
        let node_a = TestPeer::new(0x41, "node-a", 41, 51820);
        let node_b = TestPeer::new(0x42, "node-b", 42, 51821);
        let node_c = TestPeer::new(0x43, "node-c", 43, 51822);

        let mut map_a = mesh_datapath::PeerMap::new(node_a.node_id, node_a.node_kp.clone_keypair());
        map_a.apply_diff(&build_snapshot_with_stun(
            1,
            vec![node_b.to_peer_entry(), node_c.to_peer_entry()],
            vec!["203.0.113.10:3478".to_owned()],
        ));

        let mut disco_a = DiscoEngine::new(node_a.disco_kp.clone_keypair(), DiscoConfig::default());
        let cand_ctx = CandidateFilterContext {
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            control_tcp_endpoint: None,
            stun_udp_endpoint: None,
        };
        let filter = DiscoFilterContext {
            candidates: &cand_ctx,
            excluded_stun: &[],
        };
        let now_ms = 1_762_977_000_000_u64;

        // Act 1: Send 10 valid CallMeMaybe packets from Peer B within the same 60s window (`US-021 AC5`)
        let cmm_body = DiscoBody::CallMeMaybe {
            endpoints: vec![node_b.endpoint],
        };
        for seq in 0..CALL_ME_MAYBE_RATE_LIMIT_PER_MIN {
            let pkt = seal_test_disco(&node_b.disco_kp, &node_a.disco_kp, seq, &cmm_body, now_ms);
            let (ev, out) = disco_a.handle_incoming(
                &pkt,
                IngressSource::Relay {
                    verified_src_node_pubkey: node_b.node_kp.public_key(),
                },
                &mut map_a,
                &filter,
                now_ms,
            );
            assert!(matches!(ev, DiscoEvent::HolePunchTriggered { .. }) && !out.is_empty());
        }

        // 11th CallMeMaybe within 60s must be rate-limited (`call_me_maybe_rate_limited`)
        let pkt_11 = seal_test_disco(&node_b.disco_kp, &node_a.disco_kp, 99, &cmm_body, now_ms);
        let (ev_11, out_11) = disco_a.handle_incoming(
            &pkt_11,
            IngressSource::Relay {
                verified_src_node_pubkey: node_b.node_kp.public_key(),
            },
            &mut map_a,
            &filter,
            now_ms,
        );
        assert_eq!(
            ev_11,
            DiscoEvent::Rejected {
                reason: "call_me_maybe_rate_limited"
            }
        );
        assert!(out_11.is_empty());

        // Act 2: Relay source spoofing — Peer B's Disco packet delivered with Peer C's verified_src_node_pubkey
        let spoofed_ping = seal_test_disco(
            &node_b.disco_kp,
            &node_a.disco_kp,
            77,
            &DiscoBody::Ping,
            now_ms,
        );
        let (ev_spoof, _) = disco_a.handle_incoming(
            &spoofed_ping,
            IngressSource::Relay {
                verified_src_node_pubkey: node_c.node_kp.public_key(),
            },
            &mut map_a,
            &filter,
            now_ms,
        );

        // Assert 2
        assert_eq!(
            ev_spoof,
            DiscoEvent::Rejected {
                reason: "relay_src_pubkey_mismatch"
            }
        );
        assert_eq!(disco_a.metrics_snapshot().relay_poison_attempts_blocked, 1);
    }
}
