//! Interactive Disco ping probing (`Relay` -> `Direct`, `--direct`) and STUN/TCP `netcheck` (`US-040`, `US-023`).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::net::lookup_host;
use tracing::debug;

use mesh_core::defaults::{CONNECT_TIMEOUT_MS, DEFAULT_CONTROL_TCP_PORT};
use mesh_core::{AppError, AppResult, NodeId, NodeName, OverlayIp};
use mesh_datapath::{
    DatapathCommand, DatapathHandle, PingProbePath, connect_bound_tcp_with_timeout,
};
use mesh_proto::agent_ipc::{NetcheckResponse, PingRequest, PingResponse, PingSample, PingVia};
use mesh_proto::netmap::NatMappingKind;

use crate::config::split_host_port;
use crate::control_loop::DaemonRuntimeState;

const MIN_PING_COUNT: u16 = 1;
const MAX_PING_COUNT: u16 = 64;
const MIN_PING_TIMEOUT_MS: u64 = 200;
const MAX_PING_TIMEOUT_MS: u64 = 15_000;
const STUN_REFRESH_WAIT: Duration = Duration::from_millis(600);
const NETCHECK_TCP_TOTAL_BUDGET: Duration = Duration::from_millis(2_500);

/// Executes live datapath ping probes and STUN/TCP diagnostics for `meshd-ro` IPC routes.
#[derive(Debug)]
pub(crate) struct PingProbe;

impl PingProbe {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "ping_probe:ready"
    }

    /// Runs `count` sequenced Disco ping probes toward `req.target` (`US-040`).
    pub(crate) async fn execute_ping(
        state: &DaemonRuntimeState,
        req: &PingRequest,
    ) -> AppResult<PingResponse> {
        let (peer_id, peer_name, peer_ip, _) =
            state.find_peer(&req.target).await.ok_or_else(|| {
                AppError::not_found(format!("peer '{}' not found in netmap", req.target))
            })?;

        let (datapath, relay_endpoint) = {
            let g = state.inner.read().await;
            let handle = g.datapath_handle.clone().ok_or_else(|| {
                AppError::unavailable("tunnel is stopped; run `mesh up` before probing peers")
            })?;
            let relay_ep = g
                .latest_netmap
                .as_ref()
                .map(|n| n.relay_map.relay_tcp_endpoint.clone())
                .or_else(|| g.bootstrap.server_endpoint.clone());
            (handle, relay_ep)
        };

        let count = req.count.clamp(MIN_PING_COUNT, MAX_PING_COUNT);
        let timeout_ms = req
            .timeout_ms
            .clamp(MIN_PING_TIMEOUT_MS, MAX_PING_TIMEOUT_MS);

        let ctx = PingProbeTarget {
            peer_id,
            relay_endpoint: relay_endpoint.as_deref(),
            force_direct: req.force_direct,
            timeout_ms,
        };
        let samples = collect_ping_samples(&datapath, &ctx, count).await?;
        Ok(summarize_ping_samples(peer_name, peer_ip, samples))
    }

    /// Evaluates STUN UDP reachability, NAT mapping behavior, and Control TCP egress (`US-023`).
    pub(crate) async fn execute_netcheck(
        state: &DaemonRuntimeState,
    ) -> AppResult<NetcheckResponse> {
        let (
            datapath_opt,
            control_endpoint,
            cached_relay_rtt,
            stun_list,
            underlay_if_index,
            linux_fwmark,
        ) = {
            let g = state.inner.read().await;
            let ctrl = g.bootstrap.server_endpoint.clone();
            let stuns = g
                .latest_netmap
                .as_ref()
                .map_or_else(Vec::new, |n| n.relay_map.stun_udp_endpoints.clone());
            (
                g.datapath_handle.clone(),
                ctrl,
                g.relay_rtt_ms,
                stuns,
                g.underlay_if_index,
                g.linux_fwmark,
            )
        };

        let dp_snapshot = match datapath_opt {
            Some(ref handle) => refresh_stun_snapshot(handle).await,
            None => None,
        };

        let tcp_probe = match control_endpoint.as_deref() {
            Some(ep) => Some(probe_tcp_reachability(ep, underlay_if_index, linux_fwmark).await),
            None => None,
        };

        let (control_tcp_reachable, tcp_rtt_ms) = match tcp_probe {
            Some((ok, rtt)) => (ok, rtt),
            None => (false, None),
        };

        let relay_rtt_ms = cached_relay_rtt.map(|v| v as f64).or(tcp_rtt_ms);

        let report = dp_snapshot.and_then(|s| s.last_stun_report);
        let (
            udp_egress_ok,
            stun_reachable,
            stun_tested,
            reflexive_ipv4,
            ipv6_available,
            nat_mapping,
            nat_note,
        ) = extract_stun_fields(report.as_ref(), &stun_list);

        let diagnostic_hint = build_netcheck_hint(
            control_endpoint.as_deref(),
            control_tcp_reachable,
            udp_egress_ok,
        );

        Ok(NetcheckResponse {
            udp_egress_ok,
            stun_reachable,
            stun_endpoint_tested: stun_tested,
            reflexive_ipv4,
            ipv6_available,
            nat_mapping,
            nat_note,
            control_tcp_reachable,
            control_tcp_endpoint_tested: control_endpoint,
            relay_rtt_ms,
            diagnostic_hint,
        })
    }
}

async fn refresh_stun_snapshot(
    handle: &DatapathHandle,
) -> Option<mesh_datapath::DatapathStatusSnapshot> {
    if let Err(err) = handle.send(DatapathCommand::TriggerStunProbe).await {
        debug!(
            component = "meshd.ping_probe",
            event = "stun_probe_trigger_failed",
            error = %err,
            "failed triggering STUN refresh via datapath handle"
        );
    }
    tokio::time::sleep(STUN_REFRESH_WAIT).await;
    handle.query_status().await.ok()
}

struct PingProbeTarget<'a> {
    peer_id: NodeId,
    relay_endpoint: Option<&'a str>,
    force_direct: bool,
    timeout_ms: u64,
}

async fn collect_ping_samples(
    datapath: &DatapathHandle,
    target: &PingProbeTarget<'_>,
    count: u16,
) -> AppResult<Vec<PingSample>> {
    let mut samples = Vec::with_capacity(usize::from(count));
    for seq in 1..=count {
        let sample = measure_single_sample(datapath, target, seq).await?;
        samples.push(sample);
        if seq < count {
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
    }
    Ok(samples)
}

async fn measure_single_sample(
    datapath: &DatapathHandle,
    target: &PingProbeTarget<'_>,
    seq: u16,
) -> AppResult<PingSample> {
    let outcome = datapath
        .send_ping_probe(
            target.peer_id,
            target.force_direct,
            !target.force_direct && seq == 1,
            target.timeout_ms,
        )
        .await?;

    let (via, endpoint) = match outcome.path {
        PingProbePath::Direct { addr } => (PingVia::Direct, Some(addr.to_string())),
        PingProbePath::Relay => (PingVia::Relay, target.relay_endpoint.map(str::to_owned)),
        PingProbePath::Timeout => (PingVia::Timeout, None),
    };

    Ok(PingSample {
        seq,
        via,
        endpoint,
        rtt_ms: outcome.rtt_ms,
    })
}

/// Computes `packets_sent`, `packets_received`, `loss_percent`, and RTT min/avg/max.
#[must_use]
pub(crate) fn summarize_ping_samples(
    target_name: NodeName,
    target_overlay_ip: OverlayIp,
    samples: Vec<PingSample>,
) -> PingResponse {
    let packets_sent = u16::try_from(samples.len()).unwrap_or(u16::MAX);
    let mut packets_received: u16 = 0;
    let mut sum: f64 = 0.0;
    let mut min_opt: Option<f64> = None;
    let mut max_opt: Option<f64> = None;

    for s in &samples {
        if let Some(rtt) = s.rtt_ms
            && s.via != PingVia::Timeout
        {
            packets_received = packets_received.saturating_add(1);
            sum += rtt;
            min_opt = Some(match min_opt {
                Some(cur) if cur < rtt => cur,
                _ => rtt,
            });
            max_opt = Some(match max_opt {
                Some(cur) if cur > rtt => cur,
                _ => rtt,
            });
        }
    }

    let loss_percent = if packets_sent == 0 {
        100.0
    } else {
        let lost = packets_sent.saturating_sub(packets_received);
        (f64::from(lost) / f64::from(packets_sent)) * 100.0
    };
    let rtt_avg_ms = if packets_received > 0 {
        Some(sum / f64::from(packets_received))
    } else {
        None
    };

    PingResponse {
        target_name,
        target_overlay_ip,
        samples,
        packets_sent,
        packets_received,
        loss_percent,
        rtt_min_ms: min_opt,
        rtt_avg_ms,
        rtt_max_ms: max_opt,
    }
}

fn extract_stun_fields(
    report: Option<&mesh_datapath::StunProbeReport>,
    configured_stuns: &[String],
) -> (
    bool,
    bool,
    Option<String>,
    Option<String>,
    bool,
    NatMappingKind,
    String,
) {
    match report {
        Some(rep) => {
            let udp_ok = !rep.udp_blocked;
            let stun_ok = udp_ok && !rep.reflexive_addrs.is_empty();
            let tested = rep
                .observations
                .first()
                .map(|o| o.server_endpoint.to_string())
                .or_else(|| configured_stuns.first().cloned());
            let reflexive_v4 = rep
                .reflexive_addrs
                .iter()
                .find(|a| a.is_ipv4())
                .map(ToString::to_string);
            let ipv6 = rep.reflexive_addrs.iter().any(|a| a.is_ipv6());
            (
                udp_ok,
                stun_ok,
                tested,
                reflexive_v4,
                ipv6,
                rep.nat_mapping,
                rep.nat_note.clone(),
            )
        }
        None => (
            false,
            false,
            configured_stuns.first().cloned(),
            None,
            false,
            NatMappingKind::Unknown,
            "STUN probe unavailable while tunnel is stopped".to_owned(),
        ),
    }
}

async fn probe_tcp_reachability(
    endpoint: &str,
    underlay_if_index: Option<u32>,
    linux_fwmark: Option<u32>,
) -> (bool, Option<f64>) {
    let Ok((host, port)) = split_host_port(endpoint) else {
        return (false, None);
    };
    let budget = NETCHECK_TCP_TOTAL_BUDGET.min(Duration::from_millis(CONNECT_TIMEOUT_MS));
    let deadline = Instant::now() + budget;
    let Ok(Ok(addrs)) = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        lookup_host((host.as_str(), port.get())),
    )
    .await
    else {
        return (false, None);
    };

    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let connect_start = Instant::now();
        if let Ok(stream) =
            connect_bound_tcp_with_timeout(addr, underlay_if_index, linux_fwmark, remaining).await
        {
            drop(stream);
            let rtt = connect_start.elapsed().as_secs_f64() * 1000.0;
            return (true, Some(rtt));
        }
    }
    (false, None)
}

fn build_netcheck_hint(
    control_endpoint: Option<&str>,
    control_tcp_reachable: bool,
    udp_egress_ok: bool,
) -> Option<String> {
    if !control_tcp_reachable {
        if let Some(ep) = control_endpoint
            && let Ok((host, port)) = split_host_port(ep)
            && port.get() != DEFAULT_CONTROL_TCP_PORT
        {
            let suffix = if host.parse::<IpAddr>().is_ok() {
                "consider terminating Control TLS behind a domain/HTTPS proxy on the standard TLS port"
            } else {
                "verify outbound corporate firewall rules allow this custom Control TCP port"
            };
            return Some(format!(
                "Control TCP endpoint {ep} is unreachable on non-standard port {}; {suffix}",
                port.get()
            ));
        }
        return Some(
            "Control TCP endpoint is unreachable; verify network connectivity and firewall rules"
                .to_owned(),
        );
    }
    if !udp_egress_ok {
        return Some(
            "Outbound UDP STUN appears blocked; Blind Relay over TLS/WebSocket will carry traffic"
                .to_owned(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use mesh_core::clock::SystemClock;
    use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, SpkiPin};
    use mesh_crypto::{DiscoKeypair, NodeKeypair};
    use mesh_datapath::{
        DatapathConfig, DatapathEngine, DiscoConfig, MagicSocketConfig, StunClientConfig,
    };
    use mesh_net::tun::{FakeTunDevice, TunConfig};
    use mesh_proto::agent_ipc::{PingRequest, PingSample, PingVia};
    use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};
    use tempfile::tempdir;

    use super::{PingProbe, build_netcheck_hint, probe_tcp_reachability, summarize_ping_samples};
    use crate::config::{BootstrapConfig, BootstrapStore};
    use crate::control_loop::DaemonRuntimeState;
    use crate::netmap_cache::NetmapCacheStore;

    #[test]
    fn test_ping_summarize_relay_upgrade_direct_and_loss() {
        // Arrange
        let name: NodeName = "vps-node".parse().expect("name");
        let ip: OverlayIp = "100.115.0.2".parse().expect("ip");
        let samples = vec![
            PingSample {
                seq: 1,
                via: PingVia::Relay,
                endpoint: Some("203.0.113.10:8443".to_owned()),
                rtt_ms: Some(32.0),
            },
            PingSample {
                seq: 2,
                via: PingVia::Direct,
                endpoint: Some("203.0.113.20:41641".to_owned()),
                rtt_ms: Some(12.0),
            },
            PingSample {
                seq: 3,
                via: PingVia::Timeout,
                endpoint: None,
                rtt_ms: None,
            },
        ];

        // Act
        let resp = summarize_ping_samples(name, ip, samples);
        let hint = build_netcheck_hint(Some("203.0.113.10:8443"), false, false);

        // Assert
        assert_eq!(resp.packets_sent, 3);
        assert_eq!(resp.packets_received, 2);
        assert!((resp.loss_percent - 33.333_333_3).abs() < 0.01);
        assert_eq!(resp.rtt_min_ms, Some(12.0));
        assert_eq!(resp.rtt_avg_ms, Some(22.0));
        assert_eq!(resp.rtt_max_ms, Some(32.0));
        assert!(hint.is_some());
    }

    // Traces: BLK-W12-02
    #[tokio::test]
    async fn test_execute_ping_offline_peer_returns_100_percent_loss() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let cidr: OverlayCidr = "100.115.0.0/16".parse().expect("cidr");
        let local_ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 1)).expect("ip1");
        let peer_ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 2)).expect("ip2");
        let tun = Arc::new(FakeTunDevice::new(
            TunConfig::with_default_mtu("utun-mesh-ping", local_ip, cidr).expect("tun cfg"),
        ));
        let engine = DatapathEngine::bind(
            DatapathConfig {
                local_node_id: NodeId::from_bytes([0x81; 16]),
                local_overlay_ip: local_ip,
                overlay_cidr: cidr,
                node_keypair: NodeKeypair::generate(),
                disco_keypair: DiscoKeypair::generate(),
                socket_config: MagicSocketConfig::default()
                    .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                stun_config: StunClientConfig::default(),
                disco_config: DiscoConfig::default(),
                control_tcp_endpoint: None,
                wg_timer_interval: Duration::from_millis(250),
                disco_tick_interval: Duration::from_millis(250),
            },
            tun,
            Arc::new(SystemClock::new()),
            None,
        )
        .await
        .expect("bind engine");
        let dp_handle = engine.handle();
        let (_ev_tx, ev_rx) = mpsc::channel(8);
        let (_reb_tx, reb_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let engine_task = tokio::spawn(engine.run(ev_rx, reb_rx, shutdown.clone()));

        let peer_id = NodeId::from_bytes([0x82; 16]);
        let ep: SocketAddr = "127.0.0.1:18443".parse().expect("ep");
        let netmap = NetmapSnapshot {
            netmap_version: 1,
            generated_at_ms: 1_700_000_000_000,
            overlay_cidr: cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: ep.to_string(),
                relay_tcp_endpoint: ep.to_string(),
                stun_udp_endpoints: vec![],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([1u8; 32]),
                next_pin: None,
            },
            peers: vec![PeerEntry {
                node_id: peer_id,
                name: NodeName::parse("offline-peer").expect("peer name"),
                fqdn: "offline-peer.mesh.internal".to_owned(),
                overlay_ip: peer_ip,
                node_pubkey: NodeKeypair::generate().public_key(),
                disco_pubkey: DiscoKeypair::generate().public_key(),
                endpoints: vec![],
                relay_home: ep.to_string(),
                key_expires_at_ms: None,
                online: false,
            }],
        };
        dp_handle
            .apply_netmap(netmap.clone())
            .await
            .expect("apply netmap");

        let state = DaemonRuntimeState::new(
            BootstrapConfig::default(),
            BootstrapStore::new(dir.path().join("bootstrap.toml")),
            NetmapCacheStore::new(dir.path().join("netmap-cache.json")),
            None,
            1280,
        );
        {
            let mut g = state.inner.write().await;
            g.datapath_handle = Some(dp_handle);
            g.latest_netmap = Some(netmap);
        }

        // Act
        let resp = PingProbe::execute_ping(
            &state,
            &PingRequest {
                target: "offline-peer".to_owned(),
                count: 3,
                timeout_ms: 200,
                force_direct: false,
            },
        )
        .await
        .expect("execute_ping returns loss report cleanly");

        shutdown.cancel();
        engine_task.await.expect("engine exit").expect("engine ok");

        // Assert
        assert_eq!(resp.packets_sent, 3);
        assert_eq!(resp.packets_received, 0);
        assert!((resp.loss_percent - 100.0).abs() < f64::EPSILON);
        assert_eq!(resp.rtt_avg_ms, None);
        assert!(resp.samples.iter().all(|s| s.via == PingVia::Timeout));
    }

    // Traces: HR-W12-04
    #[tokio::test]
    async fn test_probe_tcp_reachability_enforces_total_budget_under_3s() {
        // Arrange
        let started = Instant::now();

        // Act
        let (reachable, rtt) = probe_tcp_reachability("192.0.2.1:65432", None, None).await;

        // Assert
        assert!(!reachable);
        assert_eq!(rtt, None);
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
