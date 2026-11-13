//! Independent Sprint 1 QA Integration, E2E Loopback & AppSec Tests for `mesh-datapath`.
//!
//! Covers:
//! - `US-009` & `US-010`: `NetmapSnapshot` synchronization into `PeerMap`
//! - `US-024` & `US-025 AC6`: Blind Relay `0x01`->`0x02` forwarding stamping verified `src_pubkey`
//!   + per-destination `mpsc::channel(256)` `try_send()` queue isolation (no Cross-Peer HoL blocking)
//! - `US-021 AC5` & `HR-G2-04`: Authenticated Disco (`b"MESHDS"` >= 172 B), anti-reflection,
//!   Direct UDP upgrade, 3-strike failover, and proof that `DiscoPong` via Relay never poisons `direct_addr`
//! - `US-014 AC4` & `SEC-11`: `AllowedIPs = /32` cryptokey routing dropping spoofed inner source IPv4
//! - `SEC-01`: `test_no_secrets_in_outputs` canary verification on datapath configs & status

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use bytes::Bytes;

    use mesh_core::defaults::RELAY_QUEUE_CAPACITY;
    use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey, SpkiPin};
    use mesh_crypto::{DiscoKeypair, NodeKeypair};
    use mesh_datapath::disco_engine::{DISCO_MAX_MISSED_PONGS, DISCO_PROBE_TIMEOUT_MS};
    use mesh_datapath::{
        CryptokeyDropReason, CryptokeyValidator, DatapathConfig, DiscoConfig, DiscoEngine,
        DiscoEvent, DiscoFilterContext, MAGIC_SOCKET_BUFFER_SIZE, MagicSocketConfig, PacketBuffer,
        PeerActivePath, PeerMap, PeerSendTarget, RelayClientHandle, StunClientConfig,
    };
    use mesh_net::endpoint_filter::CandidateFilterContext;
    use mesh_proto::disco::IngressSource;
    use mesh_proto::netmap::{
        CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap,
    };
    use mesh_proto::relay::RelayFrame;

    struct TestNodeIdentity {
        node_id: NodeId,
        name: String,
        overlay_ip: OverlayIp,
        node_kp: NodeKeypair,
        disco_kp: DiscoKeypair,
        endpoint: SocketAddr,
    }

    impl TestNodeIdentity {
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

    fn build_snapshot(version: u64, peers: Vec<PeerEntry>) -> NetmapSnapshot {
        NetmapSnapshot {
            netmap_version: version,
            generated_at_ms: 1_762_960_000_000,
            overlay_cidr: "10.100.0.0/16".parse().expect("valid cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:9443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:9443".to_owned(),
                stun_udp_endpoints: vec!["203.0.113.10:13478".to_owned()],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([0x11_u8; 32]),
                next_pin: None,
            },
            peers,
        }
    }

    fn build_ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total_len = 28 + payload.len();
        let mut pkt = Vec::with_capacity(total_len);
        pkt.extend_from_slice(&[0x45, 0x00]);
        pkt.extend_from_slice(&(u16::try_from(total_len).unwrap_or(28)).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, 17, 0x00, 0x00]);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(&5000_u16.to_be_bytes());
        pkt.extend_from_slice(&8080_u16.to_be_bytes());
        pkt.extend_from_slice(&(u16::try_from(8 + payload.len()).unwrap_or(8)).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(payload);
        pkt
    }

    fn complete_wg_handshake_over_blind_relay(
        map_a: &mut PeerMap,
        pk_a: PublicKey,
        ip_a: OverlayIp,
        map_b: &mut PeerMap,
        pk_b: PublicKey,
        ip_b: OverlayIp,
    ) {
        let mut buf_a: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut buf_b: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let probe_ip = build_ipv4_udp_packet(ip_a.as_ipv4(), ip_b.as_ipv4(), b"wg-init");

        // Node A encapsulates initial packet -> emits WireGuard Handshake Initiation over `0x01`
        let (_, target_ab, init_len) = map_a
            .encapsulate_to_overlay_ip(ip_b, &probe_ip, &mut buf_a, 1_000)
            .expect("encapsulate init")
            .expect("handshake initiation bytes");
        assert_eq!(target_ab, PeerSendTarget::Relay(pk_b));
        let frame_0x01 = RelayFrame::ClientToPeerPacket {
            dst_pubkey: pk_b,
            ciphertext: Bytes::copy_from_slice(buf_a.get(..init_len).expect("init slice")),
        }
        .encode()
        .expect("encode 0x01");

        // Blind Relay rewrites `0x01` -> `0x02` stamping verified `src_pubkey = pk_a`
        let RelayFrame::ClientToPeerPacket {
            dst_pubkey,
            ciphertext,
        } = RelayFrame::decode(&frame_0x01).expect("decode 0x01")
        else {
            panic!("expected ClientToPeerPacket");
        };
        assert_eq!(dst_pubkey, pk_b);
        let frame_0x02 = RelayFrame::RelayToClientPacket {
            src_pubkey: pk_a,
            ciphertext,
        }
        .encode()
        .expect("encode 0x02");

        let RelayFrame::RelayToClientPacket {
            src_pubkey,
            ciphertext: relay_init_ct,
        } = RelayFrame::decode(&frame_0x02).expect("decode 0x02")
        else {
            panic!("expected RelayToClientPacket");
        };
        let dec_b = map_b
            .decapsulate_from_relay(src_pubkey, &relay_init_ct, &mut buf_b, 1_010)
            .expect("decapsulate handshake initiation on Node B");
        let resp_wg = dec_b
            .outbound_network_packets
            .first()
            .expect("handshake response packet");

        // Node B replies over Blind Relay `0x02` (`src_pubkey = pk_b`) -> Node A completes handshake
        let dec_a = map_a
            .decapsulate_from_relay(pk_b, resp_wg, &mut buf_a, 1_020)
            .expect("decapsulate handshake response on Node A");
        for queued_pkt in &dec_a.outbound_network_packets {
            let _ = map_b.decapsulate_from_relay(pk_a, queued_pkt, &mut buf_b, 1_030);
        }
    }

    // Traces: US-009, US-010, US-024, US-025 AC6
    #[test]
    fn test_e2e_netmap_sync_blind_relay_forwarding_and_per_peer_queue_isolation() {
        // Arrange
        let node_a = TestNodeIdentity::new(1, "node-a", 2, 51821);
        let node_b = TestNodeIdentity::new(2, "node-b", 3, 51822);
        let node_c = TestNodeIdentity::new(3, "node-c", 4, 51823);

        let mut map_a = PeerMap::new(node_a.node_id, node_a.node_kp.clone_keypair());
        let mut map_b = PeerMap::new(node_b.node_id, node_b.node_kp.clone_keypair());

        let snap_for_a = build_snapshot(1, vec![node_b.to_peer_entry(), node_c.to_peer_entry()]);
        let snap_for_b = build_snapshot(1, vec![node_a.to_peer_entry(), node_c.to_peer_entry()]);
        assert_eq!(map_a.apply_diff(&snap_for_a).added, 2);
        assert_eq!(map_b.apply_diff(&snap_for_b).added, 2);

        // Act 1: complete WireGuard Noise handshake and forward encrypted IPv4 via Blind Relay 0x01->0x02
        complete_wg_handshake_over_blind_relay(
            &mut map_a,
            node_a.node_kp.public_key(),
            node_a.overlay_ip,
            &mut map_b,
            node_b.node_kp.public_key(),
            node_b.overlay_ip,
        );

        let mut wg_tx: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut wg_rx: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let clear_ipv4 = build_ipv4_udp_packet(
            node_a.overlay_ip.as_ipv4(),
            node_b.overlay_ip.as_ipv4(),
            b"qa-e2e",
        );
        let (_, target, ct_len) = map_a
            .encapsulate_to_overlay_ip(node_b.overlay_ip, &clear_ipv4, &mut wg_tx, 2_000)
            .expect("encapsulate data")
            .expect("ciphertext");
        assert_eq!(target, PeerSendTarget::Relay(node_b.node_kp.public_key()));

        let dec = map_b
            .decapsulate_from_relay(
                node_a.node_kp.public_key(),
                wg_tx.get(..ct_len).expect("ciphertext slice"),
                &mut wg_rx,
                2_005,
            )
            .expect("decapsulate relayed data");
        let plain_len = dec.tunnel_payload_len.expect("decrypted inner IPv4 length");
        assert_eq!(wg_rx.get(..plain_len), Some(clear_ipv4.as_slice()));

        // Act 2: saturate Peer B's bounded 256-slot relay queue (`US-025 AC6`) and verify Peer C is unaffected
        let relay_handle = RelayClientHandle::new();
        let sample_ct = Bytes::from_static(&[0xAA_u8; 64]);
        for _ in 0..RELAY_QUEUE_CAPACITY {
            assert!(relay_handle.try_send_packet(node_b.node_kp.public_key(), sample_ct.clone()));
        }
        let overflow_b =
            relay_handle.try_send_packet(node_b.node_kp.public_key(), sample_ct.clone());
        let healthy_c = relay_handle.try_send_packet(node_c.node_kp.public_key(), sample_ct);

        // Assert: Peer B drops tail non-blockingly (`dropped_tail_packets == 1`), Peer C succeeds
        assert!(!overflow_b);
        assert!(healthy_c);
        assert_eq!(relay_handle.metrics_snapshot().dropped_tail_packets, 1);
    }

    // Traces: US-021 AC5, US-022, HR-G2-04
    #[test]
    fn test_disco_direct_upgrade_anti_reflection_and_relay_pong_never_poisons_direct_addr() {
        // Arrange
        let node_a = TestNodeIdentity::new(10, "disco-a", 10, 51830);
        let node_b = TestNodeIdentity::new(11, "disco-b", 11, 51831);
        let node_c = TestNodeIdentity::new(12, "disco-c", 12, 51832);

        let mut map_a = PeerMap::new(node_a.node_id, node_a.node_kp.clone_keypair());
        let mut map_b = PeerMap::new(node_b.node_id, node_b.node_kp.clone_keypair());
        map_a.apply_diff(&build_snapshot(
            1,
            vec![node_b.to_peer_entry(), node_c.to_peer_entry()],
        ));
        map_b.apply_diff(&build_snapshot(1, vec![node_a.to_peer_entry()]));

        let mut disco_a = DiscoEngine::new(node_a.disco_kp.clone_keypair(), DiscoConfig::default());
        let mut disco_b = DiscoEngine::new(node_b.disco_kp.clone_keypair(), DiscoConfig::default());
        let cidr: OverlayCidr = "10.100.0.0/16".parse().expect("cidr");
        let cand_ctx = CandidateFilterContext {
            overlay_cidr: cidr,
            control_tcp_endpoint: None,
            stun_udp_endpoint: None,
        };
        let filter = DiscoFilterContext {
            candidates: &cand_ctx,
            excluded_stun: &[],
        };

        // Act 1: Node A initiates hole punch to Node B (`b"MESHDS"` >= 172 B)
        let punch_pkts =
            disco_a.initiate_hole_punch(&map_a, node_b.node_id, &[node_a.endpoint], &filter, 1_000);
        let direct_ping = punch_pkts
            .iter()
            .find(|p| matches!(p.target, PeerSendTarget::Direct(_)))
            .expect("direct DiscoPing generated");
        assert!(direct_ping.bytes.len() >= 172);
        assert_eq!(direct_ping.bytes.get(..6), Some(b"MESHDS".as_slice()));

        // Act 2: Anti-reflection — reflecting Node A's own Ping back to Node A (even with rewritten outer key)
        let mut forged_reflection = direct_ping.bytes.clone();
        if let Some(outer_pk_slice) = forged_reflection.get_mut(8..40) {
            outer_pk_slice.copy_from_slice(node_b.disco_kp.public_key().as_bytes());
        }
        let (refl_ev, _) = disco_a.handle_incoming(
            &forged_reflection,
            IngressSource::DirectUdp(node_b.endpoint),
            &mut map_a,
            &filter,
            1_005,
        );
        assert!(matches!(refl_ev, DiscoEvent::Rejected { .. }));
        assert_eq!(disco_a.metrics_snapshot().invalid_packets, 1);

        // Act 3: Node B processes valid Ping and produces Pong; deliver Pong via Relay (`HR-G2-04`)
        let (_, b_replies) = disco_b.handle_incoming(
            &direct_ping.bytes,
            IngressSource::DirectUdp(node_a.endpoint),
            &mut map_b,
            &filter,
            1_010,
        );
        let pong_bytes = &b_replies.first().expect("DiscoPong reply").bytes;

        let (relay_pong_ev, _) = disco_a.handle_incoming(
            pong_bytes,
            IngressSource::Relay {
                verified_src_node_pubkey: node_b.node_kp.public_key(),
            },
            &mut map_a,
            &filter,
            1_025,
        );

        // Assert (`US-021 AC5`, `HR-G2-04`): Relay Pong measures RTT only and NEVER promotes Direct path!
        assert!(matches!(relay_pong_ev, DiscoEvent::RelayRttMeasured { .. }));
        assert_eq!(
            map_a.get(&node_b.node_id).expect("peer b").active_path,
            PeerActivePath::Relay,
            "DiscoPong arriving via Blind Relay must never poison direct_addr or upgrade to Direct"
        );

        // Act 4: Deliver fresh DirectUdp Pong -> upgrades to `PeerActivePath::Direct`, then test 3-strike failover
        let punch2 =
            disco_a.initiate_hole_punch(&map_a, node_b.node_id, &[node_a.endpoint], &filter, 2_000);
        let ping2 = punch2
            .iter()
            .find(|p| matches!(p.target, PeerSendTarget::Direct(_)))
            .expect("second direct ping");
        let (_, b_replies2) = disco_b.handle_incoming(
            &ping2.bytes,
            IngressSource::DirectUdp(node_a.endpoint),
            &mut map_b,
            &filter,
            2_005,
        );
        let pong2 = &b_replies2.first().expect("second pong").bytes;
        let (direct_ev, _) = disco_a.handle_incoming(
            pong2,
            IngressSource::DirectUdp(node_b.endpoint),
            &mut map_a,
            &filter,
            2_015,
        );
        assert!(matches!(
            direct_ev,
            DiscoEvent::DirectPathVerified { addr, .. } if addr == node_b.endpoint
        ));
        assert!(matches!(
            map_a.get(&node_b.node_id).expect("peer b").active_path,
            PeerActivePath::Direct { addr, .. } if addr == node_b.endpoint
        ));

        // Simulate 3 missed direct keepalive probes -> falls back to Relay (`US-022`)
        if let Some(peer_b_mut) = map_a.get_mut(&node_b.node_id) {
            peer_b_mut.last_tx_at_ms = 3_000;
        }
        let mut now_cursor = 30_000_u64;
        for _ in 0..DISCO_MAX_MISSED_PONGS {
            let _ = disco_a.tick(&mut map_a, now_cursor);
            now_cursor += DISCO_PROBE_TIMEOUT_MS + 500;
            let _ = disco_a.tick(&mut map_a, now_cursor);
        }
        assert_eq!(
            map_a.get(&node_b.node_id).expect("peer b").active_path,
            PeerActivePath::Relay
        );
        assert_eq!(disco_a.metrics_snapshot().direct_failovers, 1);
    }

    // Traces: US-014 AC4, SEC-11
    #[test]
    fn test_cryptokey_allowed_ips_slash32_drops_inner_source_spoofing_in_wireguard_tunnel() {
        // Arrange
        let node_a = TestNodeIdentity::new(21, "wg-a", 20, 51840);
        let node_b = TestNodeIdentity::new(22, "wg-b", 21, 51841);
        let spoofed_ip = Ipv4Addr::new(10, 100, 0, 99);
        let cidr: OverlayCidr = "10.100.0.0/16".parse().expect("cidr");

        let mut map_a = PeerMap::new(node_a.node_id, node_a.node_kp.clone_keypair());
        let mut map_b = PeerMap::new(node_b.node_id, node_b.node_kp.clone_keypair());
        map_a.apply_diff(&build_snapshot(1, vec![node_b.to_peer_entry()]));
        map_b.apply_diff(&build_snapshot(1, vec![node_a.to_peer_entry()]));

        complete_wg_handshake_over_blind_relay(
            &mut map_a,
            node_a.node_kp.public_key(),
            node_a.overlay_ip,
            &mut map_b,
            node_b.node_kp.public_key(),
            node_b.overlay_ip,
        );

        let mut wg_tx: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut wg_rx: PacketBuffer = [0_u8; MAGIC_SOCKET_BUFFER_SIZE];

        // Act: Node B encapsulates an inner IPv4 packet with spoofed source IP `10.100.0.99` (`!= 10.100.0.21`)
        let forged_inner =
            build_ipv4_udp_packet(spoofed_ip, node_a.overlay_ip.as_ipv4(), b"spoofed-payload");
        let (_, _, ct_len) = map_b
            .encapsulate_to_overlay_ip(node_a.overlay_ip, &forged_inner, &mut wg_tx, 5_000)
            .expect("wg encapsulate")
            .expect("wg ciphertext");

        let dec = map_a
            .decapsulate_from_relay(
                node_b.node_kp.public_key(),
                wg_tx.get(..ct_len).expect("ct slice"),
                &mut wg_rx,
                5_005,
            )
            .expect("wg decapsulate");
        let inner_len = dec.tunnel_payload_len.expect("inner packet len");
        let decrypted_slice = wg_rx.get(..inner_len).expect("decrypted slice");

        let validator = CryptokeyValidator::new();
        let check = validator.validate_inbound(
            dec.peer_overlay_ip,
            Some(node_a.overlay_ip),
            cidr,
            decrypted_slice,
        );

        // Assert: strictly rejected by `/32` cryptokey source check and counted (`US-014 AC4`)
        assert_eq!(
            check,
            Err(CryptokeyDropReason::SpoofedSourceIp {
                expected: node_b.overlay_ip.as_ipv4(),
                observed: spoofed_ip,
            })
        );
        assert_eq!(validator.spoofed_packets_dropped(), 1);
    }

    // Traces: SEC-01
    #[test]
    fn test_no_secrets_in_outputs_datapath_config_and_keypairs() {
        // Arrange
        let node = TestNodeIdentity::new(31, "sec-node", 31, 51851);
        let cfg = DatapathConfig {
            local_node_id: node.node_id,
            local_overlay_ip: node.overlay_ip,
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            node_keypair: node.node_kp.clone_keypair(),
            disco_keypair: node.disco_kp.clone_keypair(),
            socket_config: MagicSocketConfig::default(),
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: std::time::Duration::from_millis(250),
            disco_tick_interval: std::time::Duration::from_millis(250),
        };

        // Act
        let cfg_debug = format!("{cfg:?}");
        let node_kp_debug = format!("{:?}", node.node_kp);
        let disco_kp_debug = format!("{:?}", node.disco_kp);

        // Assert
        assert!(!cfg_debug.contains("secret"));
        assert!(node_kp_debug.contains("[REDACTED]"));
        assert!(disco_kp_debug.contains("[REDACTED]"));
    }
}
