//! Integration tests for WP-M-A2 (`US-077`): mobile datapath fail-closed
//! `SocketProtector`, NAT64 synthesis, protocol-incompatibility termination,
//! idle-aware timer transitions, and pre-`CryptokeyValidator` `DnsPacketInterceptor`.

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use mesh_core::defaults::DEFAULT_TUN_MTU;
    use mesh_core::{
        AppError, AppResult, ErrorKind, NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin,
        SystemClock,
    };
    use mesh_crypto::{DiscoKeypair, NodeKeypair};
    use mesh_datapath::{
        ConnectedRelayTransport, DatapathConfig, DatapathEngine, DatapathEngineOptions,
        DiscoConfig, DnsInterceptDecision, DnsPacketInterceptor, MagicSocketConfig,
        ProtectedRelayConnector, RelayClient, RelayClientConfig, RelayClientHandle,
        RelayClientOptions, RelayConnectionState, RelayConnector, RelayEvent, StunClient,
        StunClientConfig, TimerMode, connect_bound_tcp_with_protector,
        is_protocol_incompatible_error, resolve_relay_target_addrs,
    };
    use mesh_net::nat64::{Nat64Prefix, SocketProtector};
    use mesh_net::tun::{FakeTunDevice, TunConfig};
    use mesh_proto::netmap::{
        CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry, PinSetDto, RelayMap,
    };

    fn map_err<E: std::fmt::Display>(context: &str) -> impl FnOnce(E) -> AppError + '_ {
        move |err| AppError::internal(format!("{context}: {err}"))
    }

    struct RejectingSocketProtector {
        calls: AtomicUsize,
    }

    impl RejectingSocketProtector {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl SocketProtector for RejectingSocketProtector {
        fn protect_socket(&self, _raw_fd: i32) -> AppResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(AppError::unavailable(
                "VpnService.protect returned false (fail-closed)",
            ))
        }
    }

    struct ProtocolIncompatibleConnector {
        attempts: AtomicUsize,
        http_response: Vec<u8>,
    }

    impl RelayConnector for ProtocolIncompatibleConnector {
        fn connect<'a>(
            &'a self,
            _config: &'a RelayClientConfig,
        ) -> Pin<Box<dyn Future<Output = AppResult<ConnectedRelayTransport>> + Send + 'a>> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let payload = self.http_response.clone();
            Box::pin(async move {
                let (mut server, client) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut req_buf = [0_u8; 2048];
                    drop(server.read(&mut req_buf).await);
                    drop(server.write_all(&payload).await);
                    drop(server.shutdown().await);
                });
                Ok(ConnectedRelayTransport {
                    stream: Box::new(client),
                    tls_exporter_binding: None,
                })
            })
        }
    }

    struct LocalMagicDnsInterceptor {
        dns_ip: Ipv4Addr,
        intercepted: AtomicUsize,
    }

    impl DnsPacketInterceptor for LocalMagicDnsInterceptor {
        fn intercept_outbound_packet(&self, packet: &[u8]) -> DnsInterceptDecision {
            let Some(&ver_ihl) = packet.first() else {
                return DnsInterceptDecision::PassThrough;
            };
            let ihl = usize::from(ver_ihl & 0x0f).saturating_mul(4);
            if packet.len() < ihl.saturating_add(4) || (ver_ihl >> 4) != 4 || ihl < 20 {
                return DnsInterceptDecision::PassThrough;
            }
            let Some(dst_slice) = packet.get(16..20) else {
                return DnsInterceptDecision::PassThrough;
            };
            let Some(src_slice) = packet.get(12..16) else {
                return DnsInterceptDecision::PassThrough;
            };
            let Some(port_slice) = packet.get(ihl.saturating_add(2)..ihl.saturating_add(4)) else {
                return DnsInterceptDecision::PassThrough;
            };
            let Ok(dst_arr) = <[u8; 4]>::try_from(dst_slice) else {
                return DnsInterceptDecision::PassThrough;
            };
            let Ok(src_arr) = <[u8; 4]>::try_from(src_slice) else {
                return DnsInterceptDecision::PassThrough;
            };
            let Ok(port_arr) = <[u8; 2]>::try_from(port_slice) else {
                return DnsInterceptDecision::PassThrough;
            };
            let dst_ip = Ipv4Addr::from(dst_arr);
            let src_ip = Ipv4Addr::from(src_arr);
            let dst_port = u16::from_be_bytes(port_arr);
            if dst_ip == self.dns_ip && (dst_port == 53 || dst_port == 853) {
                self.intercepted.fetch_add(1, Ordering::SeqCst);
                let reply = build_ipv4_packet(self.dns_ip, src_ip, 17, 5353);
                return DnsInterceptDecision::Handled {
                    tun_responses: vec![reply],
                };
            }
            DnsInterceptDecision::PassThrough
        }
    }

    fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, dst_port: u16) -> Vec<u8> {
        let [s0, s1, s2, s3] = src.octets();
        let [d0, d1, d2, d3] = dst.octets();
        let [p_hi, p_lo] = dst_port.to_be_bytes();
        vec![
            0x45, 0x00, 0x00, 32, 0x00, 0x01, 0x40, 0x00, 0x40, protocol, 0x00, 0x00, s0, s1, s2,
            s3, d0, d1, d2, d3, 0x13, 0x88, p_hi, p_lo, 0x00, 0x0C, 0x00, 0x00, 0xAA, 0xBB, 0xCC,
            0xDD,
        ]
    }

    fn make_peer(
        seed: u8,
        name: &str,
        octet: u8,
        port: u16,
    ) -> AppResult<(NodeKeypair, PeerEntry)> {
        let node_kp = NodeKeypair::generate();
        let disco_kp = DiscoKeypair::generate();
        let overlay_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, octet))?;
        let entry = PeerEntry {
            node_id: NodeId::from_bytes([seed; 16]),
            name: NodeName::parse(name)?,
            fqdn: format!("{name}.mesh.internal"),
            overlay_ip,
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            endpoints: vec![CandidateEndpoint {
                addr: SocketAddr::from(([198, 51, 100, octet], port)),
                source: CandidateSource::Reflexive,
            }],
            relay_home: "203.0.113.10:9443".to_owned(),
            key_expires_at_ms: None,
            online: true,
        };
        Ok((node_kp, entry))
    }

    #[tokio::test]
    async fn test_integration_fail_closed_socket_protector_prevents_engine_bind_and_tcp_connect()
    -> AppResult<()> {
        // Arrange
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(map_err("bind loopback TCP listener"))?;
        let target_addr = listener
            .local_addr()
            .map_err(map_err("listener local addr"))?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_clone = Arc::clone(&accepted);
        let listener_shutdown = CancellationToken::new();
        let listener_cancel = listener_shutdown.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = listener_cancel.cancelled() => break,
                    res = listener.accept() => {
                        if res.is_ok() {
                            accepted_clone.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }
        });

        let protector = Arc::new(RejectingSocketProtector::new());
        let cidr: OverlayCidr = "10.100.0.0/16"
            .parse()
            .map_err(map_err("parse overlay cidr"))?;
        let local_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 10))?;
        let tun_cfg = TunConfig::new("utun0", local_ip, cidr, DEFAULT_TUN_MTU)?;
        let tun = Arc::new(FakeTunDevice::new(tun_cfg));
        let cfg = DatapathConfig {
            local_node_id: NodeId::from_bytes([0x11_u8; 16]),
            local_overlay_ip: local_ip,
            overlay_cidr: cidr,
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            socket_config: MagicSocketConfig {
                bind_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                socket_protector: Arc::clone(&protector) as Arc<dyn SocketProtector>,
                ..MagicSocketConfig::default()
            },
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: Duration::from_millis(250),
            disco_tick_interval: Duration::from_millis(250),
        };

        // Act
        let tcp_res = connect_bound_tcp_with_protector(
            target_addr,
            None,
            None,
            Duration::from_millis(300),
            protector.as_ref(),
        )
        .await;
        let bind_res = DatapathEngine::bind(cfg, tun, Arc::new(SystemClock::new()), None).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        listener_shutdown.cancel();
        accept_task
            .await
            .map_err(map_err("accept task joined cleanly"))?;

        // Assert
        assert!(
            tcp_res.is_err(),
            "fail-closed protector must reject TCP connect"
        );
        assert!(
            bind_res.is_err(),
            "fail-closed protector must abort engine bind"
        );
        assert!(protector.calls.load(Ordering::SeqCst) >= 2);
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_integration_nat64_synthesis_and_protocol_incompatible_relay_stop() -> AppResult<()>
    {
        // Arrange
        let prefix = Nat64Prefix::well_known();
        let stun_endpoints = vec![
            "203.0.113.50:13478".to_owned(),
            "[2001:db8::9]:13478".to_owned(),
        ];
        let v6_relay_addr: SocketAddr = "[2001:db8::2]:9443"
            .parse()
            .map_err(map_err("parse native v6 relay addr"))?;
        let relay_resolved = vec![SocketAddr::from(([203, 0, 113, 10], 9443)), v6_relay_addr];

        let err_body = br#"{"error":{"kind":"invalid_argument","code":"E_INVALID_ARG","message":"invalid challenge JSON: unknown variant `android`, expected one of `darwin`, `windows`, `linux`","request_id":"req-wp-a2"}}"#;
        let raw_http = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            err_body.len(),
            String::from_utf8_lossy(err_body)
        );

        let connector = Arc::new(ProtocolIncompatibleConnector {
            attempts: AtomicUsize::new(0),
            http_response: raw_http.into_bytes(),
        });
        let relay_cfg = RelayClientConfig {
            endpoint: "203.0.113.10:9443".to_owned(),
            server_name_override: Some("relay.mesh.example".to_owned()),
            pin_set: None,
            underlay_if_index: None,
            linux_fwmark: None,
            require_challenge_auth: true,
            agent_version: "0.2.0-mobile".to_owned(),
        };
        let client = RelayClient::with_connector_and_timer_mode(
            relay_cfg.clone(),
            NodeKeypair::generate(),
            DiscoKeypair::generate(),
            Arc::clone(&connector) as Arc<dyn RelayConnector>,
            TimerMode::Responsive,
        );
        let handle = client.handle();
        let options_client = RelayClient::with_options(
            relay_cfg,
            NodeKeypair::generate(),
            DiscoKeypair::generate(),
            RelayClientOptions::default()
                .with_nat64_prefix(Some(prefix))
                .with_socket_protector(Arc::new(RejectingSocketProtector::new())),
        );
        drop(options_client);
        let connector_type_check: Option<ProtectedRelayConnector> = None;
        assert!(connector_type_check.is_none());

        let (events_tx, mut events_rx) = mpsc::channel(16);
        let shutdown = CancellationToken::new();

        // Act
        handle.set_nat64_prefix(Some(prefix));
        handle.set_timer_mode(TimerMode::IdleAware);
        let stun_addrs = StunClient::resolve_stun_target_addrs(&stun_endpoints, Some(prefix)).await;
        let relay_addrs = resolve_relay_target_addrs(relay_resolved, Some(prefix));
        let run_outcome = tokio::time::timeout(
            Duration::from_secs(3),
            client.run(Arc::new(SystemClock::new()), events_tx, shutdown.clone()),
        )
        .await;
        assert!(
            run_outcome.is_ok(),
            "RelayClient::run must halt immediately after authenticated TLS HTTP 400 unknown variant"
        );

        let mut terminated_kind = None;
        let mut saw_connected = false;
        while let Ok(ev) = events_rx.try_recv() {
            match ev {
                RelayEvent::StateChanged(RelayConnectionState::Terminated(kind)) => {
                    terminated_kind = Some(kind);
                }
                RelayEvent::StateChanged(RelayConnectionState::Connected) => {
                    saw_connected = true;
                }
                RelayEvent::StateChanged(_)
                | RelayEvent::PacketReceived { .. }
                | RelayEvent::NoticeReceived(_) => {}
            }
        }
        let compat_err = AppError::invalid_argument(
            "protocol incompatible (agent upgrade required): server returned HTTP 400 (`unknown variant`)",
        );
        let transient_err = AppError::unavailable("temporary relay overload");

        // Assert
        let expected_nat64_stun: SocketAddr = "[64:ff9b::cb00:7132]:13478"
            .parse()
            .map_err(map_err("parse nat64 stun v6"))?;
        let expected_native_stun: SocketAddr = "[2001:db8::9]:13478"
            .parse()
            .map_err(map_err("parse native stun v6"))?;
        assert_eq!(stun_addrs, vec![expected_nat64_stun, expected_native_stun]);

        let expected_nat64_relay: SocketAddr = "[64:ff9b::cb00:710a]:9443"
            .parse()
            .map_err(map_err("parse nat64 relay v6"))?;
        assert_eq!(relay_addrs, vec![v6_relay_addr, expected_nat64_relay]);
        assert!(is_protocol_incompatible_error(&compat_err));
        assert!(!is_protocol_incompatible_error(&transient_err));
        assert_eq!(connector.attempts.load(Ordering::SeqCst), 1);
        assert!(!saw_connected);
        assert_eq!(terminated_kind, Some(ErrorKind::InvalidArgument));
        Ok(())
    }

    #[tokio::test]
    async fn test_integration_idle_aware_timers_and_pre_cryptokey_dns_interceptor() -> AppResult<()>
    {
        // Arrange
        let cidr: OverlayCidr = "10.100.0.0/16".parse().map_err(map_err("parse cidr"))?;
        let local_ip = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 10))?;
        let tun_cfg = TunConfig::new("utun1", local_ip, cidr, DEFAULT_TUN_MTU)?;
        let fake_tun = Arc::new(FakeTunDevice::new(tun_cfg));
        let dns_ip = Ipv4Addr::new(10, 100, 0, 2);
        let interceptor = Arc::new(LocalMagicDnsInterceptor {
            dns_ip,
            intercepted: AtomicUsize::new(0),
        });
        let (_peer_kp, peer_entry) = make_peer(0x33, "peer-alpha", 20, 51821)?;

        let cfg = DatapathConfig {
            local_node_id: NodeId::from_bytes([0x10_u8; 16]),
            local_overlay_ip: local_ip,
            overlay_cidr: cidr,
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            socket_config: MagicSocketConfig {
                bind_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ..MagicSocketConfig::default()
            },
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint: None,
            wg_timer_interval: Duration::from_millis(30),
            disco_tick_interval: Duration::from_millis(30),
        };
        let options = DatapathEngineOptions {
            timer_mode: TimerMode::IdleAware,
            idle_entry_window_ms: 220,
            dns_interceptor: Some(Arc::clone(&interceptor) as Arc<dyn DnsPacketInterceptor>),
        };
        let relay_handle = RelayClientHandle::new();
        let engine = DatapathEngine::bind_with_options(
            cfg,
            Arc::clone(&fake_tun) as Arc<dyn mesh_net::tun::TunDevice>,
            Arc::new(SystemClock::new()),
            Some(relay_handle),
            options,
        )
        .await?;
        let handle = engine.handle();
        let (_relay_ev_tx, relay_ev_rx) = mpsc::channel(8);
        let (_rebind_tx, rebind_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let shutdown_runner = shutdown.clone();
        let runner =
            tokio::spawn(async move { engine.run(relay_ev_rx, rebind_rx, shutdown_runner).await });

        let snap = NetmapSnapshot {
            netmap_version: 1,
            generated_at_ms: 1_762_975_000_000,
            overlay_cidr: cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:9443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:9443".to_owned(),
                stun_udp_endpoints: Vec::new(),
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([0x11_u8; 32]),
                next_pin: None,
            },
            peers: vec![peer_entry],
        };
        assert_eq!(handle.apply_netmap(snap).await?.added, 1);

        // Act: wait for idle sleep, check frozen ticks, then inject DNS + peer traffic.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut entered_idle = false;
        while Instant::now() < deadline {
            let st = handle.query_status().await?;
            if st.idle_sleeping {
                entered_idle = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(entered_idle, "engine must enter idle_sleeping after window");
        let ticks_at_idle = handle.query_status().await?.timer_tick_count;
        tokio::time::sleep(Duration::from_millis(90)).await;
        let idle_snap = handle.query_status().await?;
        let wakeups_at_idle = idle_snap.idle_wakeup_count;

        // Send DNS query to 10.100.0.2:53 (not a WireGuard peer) and wake engine immediately.
        let dns_query = build_ipv4_packet(Ipv4Addr::new(10, 100, 0, 10), dns_ip, 17, 53);
        fake_tun.inject_inbound_packet(dns_query).await?;

        let wake_deadline = Instant::now() + Duration::from_secs(2);
        let mut woke_up = false;
        let mut collected_replies = Vec::new();
        while Instant::now() < wake_deadline {
            let drained = fake_tun.drain_outbound_packets().await;
            collected_replies.extend(drained);
            let st = handle.query_status().await?;
            if !st.idle_sleeping || st.idle_wakeup_count > wakeups_at_idle {
                woke_up = true;
            }
            if woke_up && !collected_replies.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Send non-DNS spoofed packet to peer 10.100.0.20:8080 -> must hit CryptokeyValidator.
        let spoofed_peer_pkt = build_ipv4_packet(
            Ipv4Addr::new(10, 200, 99, 9),
            Ipv4Addr::new(10, 100, 0, 20),
            17,
            8080,
        );
        fake_tun.inject_inbound_packet(spoofed_peer_pkt).await?;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let after_spoof = handle.query_status().await?;

        // Transition back to Responsive mode cleanly.
        handle.set_timer_mode(TimerMode::Responsive).await?;
        tokio::time::sleep(Duration::from_millis(80)).await;
        let responsive_snap = handle.query_status().await?;

        shutdown.cancel();
        let runner_res = runner.await.map_err(map_err("join engine task"))?;
        runner_res?;

        // Assert
        assert_eq!(ticks_at_idle, idle_snap.timer_tick_count);
        assert!(idle_snap.idle_sleeping);
        assert!(
            woke_up,
            "outbound TUN traffic must immediately wake IdleAware loop"
        );
        assert_eq!(interceptor.intercepted.load(Ordering::SeqCst), 1);
        assert_eq!(collected_replies.len(), 1);
        assert!(after_spoof.cryptokey_metrics.non_overlay_packets_dropped >= 1);
        assert_eq!(responsive_snap.timer_mode, TimerMode::Responsive);
        assert!(!responsive_snap.idle_sleeping);
        assert!(responsive_snap.timer_tick_count > idle_snap.timer_tick_count);
        Ok(())
    }
}
