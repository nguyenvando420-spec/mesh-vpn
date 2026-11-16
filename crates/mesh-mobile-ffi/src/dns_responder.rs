//! L3 RFC 4074 Split-DNS interceptor, bounded TCP `:53` state machine, and `:853` RST|ACK responder.
//!
//! Runs inline ahead of WireGuard encapsulation inside `DatapathEngine` (`US-079`, `US-080`):
//! - UDP `:53` targeting `overlay_dns_ip` answers `.mesh.internal` (and `overlay_cidr` PTR) locally,
//!   returns RFC 4074 `NOERROR` empty `NODATA` for `AAAA`/`HTTPS`/`SVCB` on IPv4-only nodes,
//!   clamps UDP DNS responses to EDNS0 `<= 1232 B` (`512 B` without OPT) with `TC=1` on truncation,
//!   and offloads non-mesh queries asynchronously over a `SocketProtector`-guarded UDP socket.
//! - TCP `:53` enforces `<= 16` LRU slots, hard `3_000 ms` slot TTL, `MSS <= 1240 B`,
//!   request `<= 1232 B`, and total frame buffer `<= 4096 B`, emitting `TCP RST|ACK` on violations.
//! - TCP `:853` (DoT) emits immediate `TCP RST|ACK` so OS private-DNS probes fail fast.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind as IoErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Duration;

use mesh_core::{Clock, NodeName, OverlayCidr, OverlayIp, SystemClock};
use mesh_datapath::{DnsInterceptDecision, DnsPacketInterceptor};
use mesh_net::nat64::{Nat64Prefix, Nat64Synthesizer};
use mesh_net::{SocketProtector, TunDevice};
use mesh_proto::netmap::NetmapSnapshot;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
const DEFAULT_DOMAIN_SUFFIX: &str = "mesh.internal";
const DEFAULT_DNS_ANSWER_TTL_SECS: u32 = 30;
const CLASSIC_UDP_DNS_PAYLOAD: usize = 512;
const MAX_UDP_DNS_PAYLOAD: usize = 1232;
const MAX_TCP_DNS_SLOTS: usize = 16;
const TCP_DNS_SLOT_TTL_MS: u64 = 3_000;
const MAX_TCP_DNS_MSS: u16 = 1240;
const MAX_TCP_DNS_REQUEST_BYTES: usize = 1232;
const MAX_TCP_DNS_FRAME_BYTES: usize = 4096;
const MAX_OUTBOUND_DNS_INFLIGHT: usize = 64;
const UPSTREAM_DNS_TIMEOUT_MS: u64 = 2_000;
const DNS_HEADER_LEN: usize = 12;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_NS: u16 = 2;
const DNS_TYPE_SOA: u16 = 6;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_OPT: u16 = 41;
const DNS_TYPE_ANY: u16 = 255;
const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_ANY: u16 = 255;

#[cfg(test)]
const DNS_TYPE_AAAA: u16 = 28;
#[cfg(test)]
const DNS_TYPE_HTTPS: u16 = 65;

const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_FORMERR: u8 = 1;
const DNS_RCODE_SERVFAIL: u8 = 2;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const DNS_RCODE_NOTIMP: u8 = 4;

#[derive(Debug, Clone)]
struct SplitDnsState {
    overlay_dns_ipv4: Option<Ipv4Addr>,
    nat64_overlay_dns_ipv6: Option<Ipv6Addr>,
    overlay_cidr: Option<OverlayCidr>,
    domain_suffix: String,
    records_by_fqdn: HashMap<String, Ipv4Addr>,
    ptr_by_ip: HashMap<Ipv4Addr, String>,
    underlay_dns_servers: Vec<IpAddr>,
    nat64_prefix: Option<Nat64Prefix>,
    underlay_if_index: Option<u32>,
    linux_fwmark: Option<u32>,
}

impl Default for SplitDnsState {
    fn default() -> Self {
        Self {
            overlay_dns_ipv4: None,
            nat64_overlay_dns_ipv6: None,
            overlay_cidr: None,
            domain_suffix: DEFAULT_DOMAIN_SUFFIX.to_owned(),
            records_by_fqdn: HashMap::new(),
            ptr_by_ip: HashMap::new(),
            underlay_dns_servers: Vec::new(),
            nat64_prefix: None,
            underlay_if_index: None,
            linux_fwmark: None,
        }
    }
}

impl SplitDnsState {
    fn matches_target_ip(&self, dst_ip: IpAddr) -> bool {
        let Some(dns_v4) = self.overlay_dns_ipv4 else {
            return false;
        };
        match dst_ip {
            IpAddr::V4(v4) => v4 == dns_v4,
            IpAddr::V6(v6) => {
                v6 == dns_v4.to_ipv6_mapped()
                    || self.nat64_overlay_dns_ipv6.is_some_and(|syn| v6 == syn)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
}

#[derive(Debug)]
struct TcpDnsSlot {
    key: TcpFlowKey,
    rcv_nxt: u32,
    snd_nxt: u32,
    rx_buf: Vec<u8>,
    created_at_ms: u64,
    last_active_at_ms: u64,
    mss: u16,
    query_in_flight: bool,
}

#[derive(Debug, Default)]
struct TcpDnsTable {
    slots: VecDeque<TcpDnsSlot>,
    next_isn: u32,
}

#[derive(Debug, Clone)]
enum TcpWireFrameMode {
    Udp { max_payload: usize },
    Tcp { slot_key: TcpFlowKey },
}

#[derive(Debug, Clone)]
struct UpstreamDnsJob {
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    query_bytes: Vec<u8>,
    frame_mode: TcpWireFrameMode,
    underlay_servers: Vec<IpAddr>,
    nat64_prefix: Option<Nat64Prefix>,
    underlay_if_index: Option<u32>,
    linux_fwmark: Option<u32>,
}

/// Live-updatable RFC 4074 Split-DNS, bounded TCP `:53`, and `:853` RST|ACK engine.
#[derive(Clone)]
pub struct MobileSplitDnsInterceptor {
    clock: Arc<dyn Clock>,
    state: Arc<StdRwLock<Arc<SplitDnsState>>>,
    tcp_table: Arc<StdMutex<TcpDnsTable>>,
    active_tun: Arc<StdRwLock<Option<Arc<dyn TunDevice>>>>,
    socket_protector: Arc<StdRwLock<Option<Arc<dyn SocketProtector>>>>,
    upstream_tx: Arc<StdRwLock<Option<mpsc::Sender<UpstreamDnsJob>>>>,
    upstream_port_override: Arc<StdRwLock<Option<u16>>>,
}

impl std::fmt::Debug for MobileSplitDnsInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .state
            .read()
            .map(|g| g.records_by_fqdn.len())
            .unwrap_or(0);
        let tcp_slots = self.tcp_table.lock().map(|g| g.slots.len()).unwrap_or(0);
        f.debug_struct("MobileSplitDnsInterceptor")
            .field("mesh_dns_records", &count)
            .field("tcp_dns_slots", &tcp_slots)
            .finish_non_exhaustive()
    }
}

impl Default for MobileSplitDnsInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock::new()))
    }
}

impl MobileSplitDnsInterceptor {
    /// Creates an empty Split-DNS interceptor bound to `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            state: Arc::new(StdRwLock::new(Arc::new(SplitDnsState::default()))),
            tcp_table: Arc::new(StdRwLock::new(())).into_tcp_table(),
            active_tun: Arc::new(StdRwLock::new(None)),
            socket_protector: Arc::new(StdRwLock::new(None)),
            upstream_tx: Arc::new(StdRwLock::new(None)),
            upstream_port_override: Arc::new(StdRwLock::new(None)),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_test_upstream_port(&self, port: Option<u16>) {
        if let Ok(mut g) = self.upstream_port_override.write() {
            *g = port;
        }
    }

    fn upstream_port(&self) -> u16 {
        self.upstream_port_override
            .read()
            .ok()
            .and_then(|g| *g)
            .unwrap_or(DNS_PORT)
    }

    /// Attaches the active TUN writer + `SocketProtector` and spawns the bounded non-blocking
    /// upstream forwarder task (`<= 64` concurrent queries, `<= 2_000 ms` timeout).
    #[must_use]
    pub fn start_upstream_forwarder(
        &self,
        tun: Option<Arc<dyn TunDevice>>,
        protector: Option<Arc<dyn SocketProtector>>,
        shutdown: CancellationToken,
    ) -> JoinHandle<()> {
        if let Ok(mut g) = self.active_tun.write() {
            *g = tun;
        }
        if let Ok(mut g) = self.socket_protector.write() {
            *g = protector;
        }
        let (tx, mut rx) = mpsc::channel::<UpstreamDnsJob>(MAX_OUTBOUND_DNS_INFLIGHT);
        if let Ok(mut g) = self.upstream_tx.write() {
            *g = Some(tx);
        }

        let interceptor = self.clone();
        tokio::spawn(async move {
            let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_OUTBOUND_DNS_INFLIGHT));
            let idle_notify = Arc::new(Notify::new());
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    maybe_job = rx.recv() => {
                        let Some(job) = maybe_job else {
                            break;
                        };
                        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                            interceptor.emit_async_servfail(&job).await;
                            continue;
                        };
                        let ic = interceptor.clone();
                        let job_cancel = shutdown.child_token();
                        let notify = Arc::clone(&idle_notify);
                        tokio::spawn(async move {
                            tokio::select! {
                                () = job_cancel.cancelled() => {}
                                () = ic.process_upstream_dns_job(job) => {}
                            }
                            drop(permit);
                            notify.notify_one();
                        });
                    }
                }
            }
            if let Ok(mut g) = interceptor.upstream_tx.write() {
                *g = None;
            }
        })
    }

    /// Updates active TUN sink dynamically without restarting the forwarder.
    pub fn set_active_tun(&self, tun: Option<Arc<dyn TunDevice>>) {
        if let Ok(mut g) = self.active_tun.write() {
            *g = tun;
        }
    }

    /// Updates `SocketProtector` dynamically.
    pub fn set_socket_protector(&self, protector: Option<Arc<dyn SocketProtector>>) {
        if let Ok(mut g) = self.socket_protector.write() {
            *g = protector;
        }
    }

    /// Replaces active `.mesh.internal` DNS records from `snapshot` + self node identity.
    pub fn update_netmap(
        &self,
        snapshot: &NetmapSnapshot,
        self_ip: Option<OverlayIp>,
        self_name: Option<&NodeName>,
        overlay_dns_ip: Option<OverlayIp>,
    ) {
        let suffix = normalize_dns_name(&snapshot.domain_suffix);
        let active_suffix = if suffix.is_empty() {
            DEFAULT_DOMAIN_SUFFIX.to_owned()
        } else {
            suffix
        };

        let mut records = HashMap::new();
        let mut ptrs = HashMap::new();

        if let (Some(ip), Some(name)) = (self_ip, self_name) {
            let v4 = ip.as_ipv4();
            let short = normalize_dns_name(name.as_str());
            if !short.is_empty() {
                let canonical = format!("{short}.{active_suffix}");
                records.insert(canonical.clone(), v4);
                records.insert(format!("{short}.{DEFAULT_DOMAIN_SUFFIX}"), v4);
                ptrs.insert(v4, canonical);
            }
        }

        for peer in &snapshot.peers {
            let v4 = peer.overlay_ip.as_ipv4();
            let short = normalize_dns_name(peer.name.as_str());
            let fqdn = normalize_dns_name(&peer.fqdn);
            if !fqdn.is_empty() {
                records.insert(fqdn.clone(), v4);
            }
            if !short.is_empty() {
                let suffixed = format!("{short}.{active_suffix}");
                records.insert(suffixed.clone(), v4);
                records.insert(format!("{short}.{DEFAULT_DOMAIN_SUFFIX}"), v4);
                let ptr_target = if fqdn.is_empty() { suffixed } else { fqdn };
                ptrs.entry(v4).or_insert(ptr_target);
            }
        }

        let Ok(mut guard) = self.state.write() else {
            return;
        };
        let mut next = (**guard).clone();
        let dns_v4 = overlay_dns_ip.map(|ip| ip.as_ipv4());
        next.overlay_dns_ipv4 = dns_v4;
        next.nat64_overlay_dns_ipv6 = compute_nat64_dns_v6(dns_v4, next.nat64_prefix);
        next.overlay_cidr = Some(snapshot.overlay_cidr);
        next.domain_suffix = active_suffix;
        next.records_by_fqdn = records;
        next.ptr_by_ip = ptrs;
        *guard = Arc::new(next);
    }

    /// Updates physical underlay DNS servers, NAT64 prefix, and underlay socket binding.
    pub fn update_underlay(
        &self,
        dns_servers: Vec<IpAddr>,
        nat64_prefix: Option<Nat64Prefix>,
        underlay_if_index: Option<u32>,
        linux_fwmark: Option<u32>,
    ) {
        let Ok(mut guard) = self.state.write() else {
            return;
        };
        let mut next = (**guard).clone();
        next.underlay_dns_servers = dns_servers;
        next.nat64_prefix = nat64_prefix;
        next.nat64_overlay_dns_ipv6 = compute_nat64_dns_v6(next.overlay_dns_ipv4, nat64_prefix);
        next.underlay_if_index = underlay_if_index;
        next.linux_fwmark = linux_fwmark;
        *guard = Arc::new(next);
    }

    /// Clears Split-DNS peer records and active TCP `:53` slots on tunnel shutdown.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.state.write() {
            let mut next = (**guard).clone();
            next.records_by_fqdn.clear();
            next.ptr_by_ip.clear();
            next.overlay_cidr = None;
            next.overlay_dns_ipv4 = None;
            next.nat64_overlay_dns_ipv6 = None;
            *guard = Arc::new(next);
        }
        if let Ok(mut table) = self.tcp_table.lock() {
            table.slots.clear();
        }
    }

    /// Reaps expired TCP `:53` slots (`> 3_000 ms` idle) and returns active slot count (for tests/metrics).
    #[must_use]
    pub fn active_tcp_slot_count(&self) -> usize {
        let now_ms = self.clock.monotonic_ms();
        let Ok(mut table) = self.tcp_table.lock() else {
            return 0;
        };
        reap_expired_slots(&mut table.slots, now_ms);
        table.slots.len()
    }

    fn current_state(&self) -> Arc<SplitDnsState> {
        self.state
            .read()
            .map(|g| Arc::clone(&g))
            .unwrap_or_else(|_| Arc::new(SplitDnsState::default()))
    }

    async fn process_upstream_dns_job(&self, job: UpstreamDnsJob) {
        let response_wire = match job.frame_mode {
            TcpWireFrameMode::Tcp { .. } => self.resolve_upstream_tcp(&job).await,
            TcpWireFrameMode::Udp { .. } => match self.resolve_upstream_udp(&job).await {
                Some(udp_resp) if is_dns_tc_truncated(&udp_resp) => {
                    self.resolve_upstream_tcp(&job).await.or(Some(udp_resp))
                }
                other => other,
            },
        };
        let dns_payload = match response_wire {
            Some(bytes) => bytes,
            None => build_simple_error_response(&job.query_bytes, DNS_RCODE_SERVFAIL),
        };
        if dns_payload.is_empty() {
            return;
        }
        self.deliver_async_dns_reply(&job, &dns_payload).await;
    }

    async fn emit_async_servfail(&self, job: &UpstreamDnsJob) {
        let servfail = build_simple_error_response(&job.query_bytes, DNS_RCODE_SERVFAIL);
        if !servfail.is_empty() {
            self.deliver_async_dns_reply(job, &servfail).await;
        }
    }

    async fn deliver_async_dns_reply(&self, job: &UpstreamDnsJob, dns_wire: &[u8]) {
        let packets = match job.frame_mode {
            TcpWireFrameMode::Udp { max_payload } => {
                let clamped = clamp_dns_udp_response(dns_wire, max_payload);
                vec![build_l3_udp_packet(
                    job.server_ip,
                    job.client_ip,
                    job.server_port,
                    job.client_port,
                    &clamped,
                )]
            }
            TcpWireFrameMode::Tcp { slot_key } => self.build_tcp_reply_segments(slot_key, dns_wire),
        };
        let tun = self.active_tun.read().ok().and_then(|g| g.clone());
        let Some(tun_dev) = tun else {
            return;
        };
        for pkt in packets {
            if let Err(err) = tun_dev.write_packet(&pkt).await {
                debug!(
                    component = "mesh_mobile_ffi.dns",
                    event = "async_dns_tun_write_failed",
                    error = %err,
                    "failed writing async upstream DNS reply to TUN"
                );
            }
        }
    }

    fn build_tcp_reply_segments(&self, key: TcpFlowKey, dns_wire: &[u8]) -> Vec<Vec<u8>> {
        let framed = frame_tcp_dns_response(dns_wire);
        let Ok(mut table) = self.tcp_table.lock() else {
            return Vec::new();
        };
        let Some(pos) = table.slots.iter().position(|s| s.key == key) else {
            return Vec::new();
        };
        let Some(mut slot) = table.slots.remove(pos) else {
            return Vec::new();
        };
        emit_tcp_data_segments(&mut slot, &framed, true)
    }

    async fn resolve_upstream_udp(&self, job: &UpstreamDnsJob) -> Option<Vec<u8>> {
        if job.underlay_servers.is_empty() {
            return None;
        }
        let protector = self.socket_protector.read().ok().and_then(|g| g.clone());
        let port = self.upstream_port();
        for &server in &job.underlay_servers {
            let target = synthesize_upstream_target(server, job.nat64_prefix);
            let sock = match bind_protected_udp_socket(
                target.is_ipv6(),
                protector.as_deref(),
                job.underlay_if_index,
                job.linux_fwmark,
            ) {
                Ok(s) => s,
                Err(err) => {
                    warn!(
                        component = "mesh_mobile_ffi.dns",
                        event = "upstream_dns_socket_bind_failed",
                        error = %err,
                        "fail-closed upstream DNS socket bind denied"
                    );
                    return None;
                }
            };
            let target_addr = SocketAddr::new(target, port);
            let Ok(Ok(_)) = tokio::time::timeout(
                Duration::from_millis(UPSTREAM_DNS_TIMEOUT_MS),
                sock.send_to(&job.query_bytes, target_addr),
            )
            .await
            else {
                continue;
            };
            let mut rx_buf = vec![0_u8; MAX_TCP_DNS_FRAME_BYTES];
            let Ok(Ok((len, _))) = tokio::time::timeout(
                Duration::from_millis(UPSTREAM_DNS_TIMEOUT_MS),
                sock.recv_from(&mut rx_buf),
            )
            .await
            else {
                continue;
            };
            if let Some(slice) = rx_buf.get(..len)
                && slice.len() >= DNS_HEADER_LEN
            {
                return Some(slice.to_vec());
            }
        }
        None
    }

    async fn resolve_upstream_tcp(&self, job: &UpstreamDnsJob) -> Option<Vec<u8>> {
        if job.underlay_servers.is_empty() || job.query_bytes.len() > MAX_TCP_DNS_REQUEST_BYTES {
            return None;
        }
        let Ok(req_len) = u16::try_from(job.query_bytes.len()) else {
            return None;
        };
        let mut framed_req = Vec::with_capacity(2 + job.query_bytes.len());
        framed_req.extend_from_slice(&req_len.to_be_bytes());
        framed_req.extend_from_slice(&job.query_bytes);

        let protector = self.socket_protector.read().ok().and_then(|g| g.clone());
        let port = self.upstream_port();
        for &server in &job.underlay_servers {
            let target = synthesize_upstream_target(server, job.nat64_prefix);
            let target_addr = SocketAddr::new(target, port);
            let timeout = Duration::from_millis(UPSTREAM_DNS_TIMEOUT_MS);
            let deadline = tokio::time::Instant::now() + timeout;

            let mut stream = match connect_protected_tcp_socket(
                target_addr,
                protector.as_deref(),
                job.underlay_if_index,
                job.linux_fwmark,
                timeout,
            )
            .await
            {
                Ok(s) => s,
                Err(TcpConnectFailure::FailClosed(err)) => {
                    warn!(
                        component = "mesh_mobile_ffi.dns",
                        event = "upstream_tcp_dns_socket_fail_closed",
                        error = %err,
                        "fail-closed upstream TCP DNS socket protection/bind denied"
                    );
                    return None;
                }
                Err(TcpConnectFailure::ConnectTimeoutOrIo(err)) => {
                    tracing::debug!(
                        component = "mesh_mobile_ffi.dns",
                        event = "upstream_tcp_dns_connect_failed",
                        target = %target_addr,
                        error = %err,
                        "upstream TCP DNS connect attempt failed"
                    );
                    continue;
                }
            };

            if !matches!(
                tokio::time::timeout_at(deadline, stream.write_all(&framed_req)).await,
                Ok(Ok(()))
            ) {
                continue;
            }
            let mut len_buf = [0_u8; 2];
            if !matches!(
                tokio::time::timeout_at(deadline, stream.read_exact(&mut len_buf)).await,
                Ok(Ok(_))
            ) {
                continue;
            }
            let resp_len = usize::from(u16::from_be_bytes(len_buf));
            if !(DNS_HEADER_LEN..=MAX_TCP_DNS_FRAME_BYTES).contains(&resp_len) {
                continue;
            }
            let mut body = vec![0_u8; resp_len];
            if !matches!(
                tokio::time::timeout_at(deadline, stream.read_exact(&mut body)).await,
                Ok(Ok(_))
            ) {
                continue;
            }
            return Some(body);
        }
        None
    }

    fn handle_udp_dns(
        &self,
        state: &SplitDnsState,
        flow: L3Tuple,
        payload: &[u8],
    ) -> DnsInterceptDecision {
        let L3Tuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        } = flow;
        let Some(query) = parse_dns_query(payload) else {
            if let Some(err_wire) = build_simple_error_from_header(payload, DNS_RCODE_FORMERR) {
                let pkt = build_l3_udp_packet(dst_ip, src_ip, dst_port, src_port, &err_wire);
                return DnsInterceptDecision::Handled {
                    tun_responses: vec![pkt],
                };
            }
            return DnsInterceptDecision::Handled {
                tun_responses: Vec::new(),
            };
        };

        if let Some(local_wire) = resolve_local_dns_query(state, &query) {
            let clamped = clamp_dns_udp_response(&local_wire, query.max_udp_payload);
            let pkt = build_l3_udp_packet(dst_ip, src_ip, dst_port, src_port, &clamped);
            return DnsInterceptDecision::Handled {
                tun_responses: vec![pkt],
            };
        }

        if let Some(tx) = self.upstream_tx.read().ok().and_then(|g| g.clone())
            && !state.underlay_dns_servers.is_empty()
        {
            let job = UpstreamDnsJob {
                client_ip: src_ip,
                server_ip: dst_ip,
                client_port: src_port,
                server_port: dst_port,
                query_bytes: payload.to_vec(),
                frame_mode: TcpWireFrameMode::Udp {
                    max_payload: query.max_udp_payload,
                },
                underlay_servers: state.underlay_dns_servers.clone(),
                nat64_prefix: state.nat64_prefix,
                underlay_if_index: state.underlay_if_index,
                linux_fwmark: state.linux_fwmark,
            };
            if tx.try_send(job).is_ok() {
                return DnsInterceptDecision::Handled {
                    tun_responses: Vec::new(),
                };
            }
        }

        let servfail = build_simple_error_response(payload, DNS_RCODE_SERVFAIL);
        let pkt = build_l3_udp_packet(dst_ip, src_ip, dst_port, src_port, &servfail);
        DnsInterceptDecision::Handled {
            tun_responses: vec![pkt],
        }
    }

    fn handle_tcp_dns(
        &self,
        state: &SplitDnsState,
        flow: L3Tuple,
        tcp_payload: &[u8],
    ) -> DnsInterceptDecision {
        let L3Tuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        } = flow;
        let Some(seg) = parse_tcp_segment(tcp_payload) else {
            return DnsInterceptDecision::Handled {
                tun_responses: Vec::new(),
            };
        };

        if seg.flags & TCP_FLAG_RST != 0 {
            let key = TcpFlowKey {
                client_ip: src_ip,
                client_port: src_port,
                server_ip: dst_ip,
                server_port: dst_port,
            };
            if let Ok(mut table) = self.tcp_table.lock() {
                table.slots.retain(|s| s.key != key);
            }
            return DnsInterceptDecision::Handled {
                tun_responses: Vec::new(),
            };
        }

        let now_ms = self.clock.monotonic_ms();
        let key = TcpFlowKey {
            client_ip: src_ip,
            client_port: src_port,
            server_ip: dst_ip,
            server_port: dst_port,
        };

        let mut responses = Vec::new();
        let mut upstream_jobs = Vec::new();

        {
            let Ok(mut table) = self.tcp_table.lock() else {
                return DnsInterceptDecision::Handled {
                    tun_responses: Vec::new(),
                };
            };
            reap_expired_slots(&mut table.slots, now_ms);

            if seg.flags & TCP_FLAG_SYN != 0 {
                if seg.flags & (TCP_FLAG_ACK | TCP_FLAG_FIN) != 0
                    || !seg.payload.is_empty()
                    || seg.mss_opt.is_some_and(|mss| mss == 0)
                {
                    responses.push(build_stateless_tcp_rst_ack(
                        src_ip, dst_ip, src_port, dst_port, &seg,
                    ));
                    return DnsInterceptDecision::Handled {
                        tun_responses: responses,
                    };
                }

                table.slots.retain(|s| s.key != key);
                if table.slots.len() >= MAX_TCP_DNS_SLOTS
                    && let Some(evicted) = table.slots.pop_front()
                {
                    responses.push(build_l3_tcp_packet(TcpSegmentSpec {
                        src_ip: evicted.key.server_ip,
                        dst_ip: evicted.key.client_ip,
                        src_port: evicted.key.server_port,
                        dst_port: evicted.key.client_port,
                        seq: evicted.snd_nxt,
                        ack: evicted.rcv_nxt,
                        flags: TCP_FLAG_RST | TCP_FLAG_ACK,
                        window: 0,
                        mss_opt: None,
                        payload: &[],
                    }));
                }

                table.next_isn = table.next_isn.wrapping_add(65_537);
                let server_isn = table.next_isn;
                let rcv_nxt = seg.seq.wrapping_add(1);
                let negotiated_mss = seg
                    .mss_opt
                    .map_or(MAX_TCP_DNS_MSS, |m| m.min(MAX_TCP_DNS_MSS));
                responses.push(build_l3_tcp_packet(TcpSegmentSpec {
                    src_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: server_isn,
                    ack: rcv_nxt,
                    flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                    window: u16::try_from(MAX_TCP_DNS_FRAME_BYTES).unwrap_or(4096),
                    mss_opt: Some(MAX_TCP_DNS_MSS),
                    payload: &[],
                }));
                table.slots.push_back(TcpDnsSlot {
                    key,
                    rcv_nxt,
                    snd_nxt: server_isn.wrapping_add(1),
                    rx_buf: Vec::new(),
                    created_at_ms: now_ms,
                    last_active_at_ms: now_ms,
                    mss: negotiated_mss.max(256),
                    query_in_flight: false,
                });
                return DnsInterceptDecision::Handled {
                    tun_responses: responses,
                };
            }

            let Some(pos) = table.slots.iter().position(|s| s.key == key) else {
                responses.push(build_stateless_tcp_rst_ack(
                    src_ip, dst_ip, src_port, dst_port, &seg,
                ));
                return DnsInterceptDecision::Handled {
                    tun_responses: responses,
                };
            };

            let Some(mut slot) = table.slots.remove(pos) else {
                return DnsInterceptDecision::Handled {
                    tun_responses: responses,
                };
            };

            if now_ms.saturating_sub(slot.created_at_ms) > TCP_DNS_SLOT_TTL_MS
                || seg.seq != slot.rcv_nxt
                || seg.payload.len() > usize::from(MAX_TCP_DNS_MSS)
                || slot.rx_buf.len().saturating_add(seg.payload.len()) > MAX_TCP_DNS_FRAME_BYTES
            {
                responses.push(build_l3_tcp_packet(TcpSegmentSpec {
                    src_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: slot.snd_nxt,
                    ack: seg.seq.wrapping_add(seg.payload.len() as u32),
                    flags: TCP_FLAG_RST | TCP_FLAG_ACK,
                    window: 0,
                    mss_opt: None,
                    payload: &[],
                }));
                return DnsInterceptDecision::Handled {
                    tun_responses: responses,
                };
            }

            slot.last_active_at_ms = now_ms;
            if slot.query_in_flight && !seg.payload.is_empty() {
                responses.push(build_l3_tcp_packet(TcpSegmentSpec {
                    src_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: slot.snd_nxt,
                    ack: slot.rcv_nxt,
                    flags: TCP_FLAG_RST | TCP_FLAG_ACK,
                    window: 0,
                    mss_opt: None,
                    payload: &[],
                }));
                return DnsInterceptDecision::Handled {
                    tun_responses: responses,
                };
            }

            if !seg.payload.is_empty() {
                slot.rx_buf.extend_from_slice(seg.payload);
                slot.rcv_nxt = slot.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                responses.push(build_l3_tcp_packet(TcpSegmentSpec {
                    src_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: slot.snd_nxt,
                    ack: slot.rcv_nxt,
                    flags: TCP_FLAG_ACK,
                    window: u16::try_from(MAX_TCP_DNS_FRAME_BYTES).unwrap_or(4096),
                    mss_opt: None,
                    payload: &[],
                }));
            }

            let mut protocol_error = false;
            let mut slot_completed_sync = false;
            if !slot.query_in_flight
                && slot.rx_buf.len() >= 2
                && let (Some(len_hi), Some(len_lo)) =
                    (slot.rx_buf.first().copied(), slot.rx_buf.get(1).copied())
            {
                let frame_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
                if !(DNS_HEADER_LEN..=MAX_TCP_DNS_REQUEST_BYTES).contains(&frame_len) {
                    protocol_error = true;
                } else if slot.rx_buf.len() > 2 + frame_len {
                    // Single-transaction TCP `:53` policy: reject pipelining / extra bytes
                    // immediately with `TCP RST|ACK` (`BLK-MOB-G2-03`, `HIGH-MOB-WA-06`).
                    protocol_error = true;
                } else if slot.rx_buf.len() == 2 + frame_len {
                    let req_bytes: Vec<u8> = slot.rx_buf.drain(..2 + frame_len).collect();
                    if let Some(query_bytes) = req_bytes.get(2..) {
                        if let Some(local_wire) = parse_dns_query(query_bytes)
                            .and_then(|q| resolve_local_dns_query(state, &q))
                        {
                            let framed = frame_tcp_dns_response(&local_wire);
                            responses.extend(emit_tcp_data_segments(&mut slot, &framed, true));
                            slot_completed_sync = true;
                        } else if parse_dns_query(query_bytes).is_none() {
                            let formerr =
                                build_simple_error_response(query_bytes, DNS_RCODE_FORMERR);
                            let framed = frame_tcp_dns_response(&formerr);
                            responses.extend(emit_tcp_data_segments(&mut slot, &framed, true));
                            slot_completed_sync = true;
                        } else if !state.underlay_dns_servers.is_empty()
                            && let Some(tx) = self.upstream_tx.read().ok().and_then(|g| g.clone())
                        {
                            slot.query_in_flight = true;
                            upstream_jobs.push((
                                tx,
                                UpstreamDnsJob {
                                    client_ip: src_ip,
                                    server_ip: dst_ip,
                                    client_port: src_port,
                                    server_port: dst_port,
                                    query_bytes: query_bytes.to_vec(),
                                    frame_mode: TcpWireFrameMode::Tcp { slot_key: key },
                                    underlay_servers: state.underlay_dns_servers.clone(),
                                    nat64_prefix: state.nat64_prefix,
                                    underlay_if_index: state.underlay_if_index,
                                    linux_fwmark: state.linux_fwmark,
                                },
                            ));
                        } else {
                            let servfail =
                                build_simple_error_response(query_bytes, DNS_RCODE_SERVFAIL);
                            let framed = frame_tcp_dns_response(&servfail);
                            responses.extend(emit_tcp_data_segments(&mut slot, &framed, true));
                            slot_completed_sync = true;
                        }
                    } else {
                        protocol_error = true;
                    }
                }
            }

            if protocol_error {
                responses.push(build_l3_tcp_packet(TcpSegmentSpec {
                    src_ip: dst_ip,
                    dst_ip: src_ip,
                    src_port: dst_port,
                    dst_port: src_port,
                    seq: slot.snd_nxt,
                    ack: slot.rcv_nxt,
                    flags: TCP_FLAG_RST | TCP_FLAG_ACK,
                    window: 0,
                    mss_opt: None,
                    payload: &[],
                }));
                return DnsInterceptDecision::Handled {
                    tun_responses: responses,
                };
            }

            if slot_completed_sync {
                // Single-transaction FIN|ACK was already emitted in `emit_tcp_data_segments`;
                // slot is closed immediately and not pushed back into `table.slots`.
            } else if seg.flags & TCP_FLAG_FIN != 0 {
                slot.rcv_nxt = slot.rcv_nxt.wrapping_add(1);
                if slot.query_in_flight {
                    table.slots.push_back(slot);
                } else {
                    responses.push(build_l3_tcp_packet(TcpSegmentSpec {
                        src_ip: dst_ip,
                        dst_ip: src_ip,
                        src_port: dst_port,
                        dst_port: src_port,
                        seq: slot.snd_nxt,
                        ack: slot.rcv_nxt,
                        flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
                        window: u16::try_from(MAX_TCP_DNS_FRAME_BYTES).unwrap_or(4096),
                        mss_opt: None,
                        payload: &[],
                    }));
                }
            } else {
                table.slots.push_back(slot);
            }
        }

        for (tx, job) in upstream_jobs {
            if let Err(mpsc::error::TrySendError::Full(rejected))
            | Err(mpsc::error::TrySendError::Closed(rejected)) = tx.try_send(job)
            {
                let servfail =
                    build_simple_error_response(&rejected.query_bytes, DNS_RCODE_SERVFAIL);
                responses.extend(self.build_tcp_reply_segments(key, &servfail));
            }
        }

        DnsInterceptDecision::Handled {
            tun_responses: responses,
        }
    }
}

impl DnsPacketInterceptor for MobileSplitDnsInterceptor {
    fn intercept_outbound_packet(&self, packet: &[u8]) -> DnsInterceptDecision {
        let Some(l3) = parse_l3_packet(packet) else {
            return DnsInterceptDecision::PassThrough;
        };
        let state = self.current_state();
        if !state.matches_target_ip(l3.dst_ip) {
            return DnsInterceptDecision::PassThrough;
        }

        match l3.proto {
            IP_PROTO_UDP => {
                let Some((src_port, dst_port, udp_payload)) = parse_udp_datagram(l3.payload) else {
                    return DnsInterceptDecision::PassThrough;
                };
                if dst_port != DNS_PORT {
                    return DnsInterceptDecision::PassThrough;
                }
                self.handle_udp_dns(
                    &state,
                    L3Tuple {
                        src_ip: l3.src_ip,
                        dst_ip: l3.dst_ip,
                        src_port,
                        dst_port,
                    },
                    udp_payload,
                )
            }
            IP_PROTO_TCP => {
                let Some((src_port, dst_port)) = parse_tcp_ports(l3.payload) else {
                    return DnsInterceptDecision::PassThrough;
                };
                if dst_port == DOT_PORT {
                    let Some(seg) = parse_tcp_segment(l3.payload) else {
                        return DnsInterceptDecision::Handled {
                            tun_responses: Vec::new(),
                        };
                    };
                    if seg.flags & TCP_FLAG_RST != 0 {
                        return DnsInterceptDecision::Handled {
                            tun_responses: Vec::new(),
                        };
                    }
                    let rst =
                        build_stateless_tcp_rst_ack(l3.src_ip, l3.dst_ip, src_port, dst_port, &seg);
                    return DnsInterceptDecision::Handled {
                        tun_responses: vec![rst],
                    };
                }
                if dst_port == DNS_PORT {
                    return self.handle_tcp_dns(
                        &state,
                        L3Tuple {
                            src_ip: l3.src_ip,
                            dst_ip: l3.dst_ip,
                            src_port,
                            dst_port,
                        },
                        l3.payload,
                    );
                }
                DnsInterceptDecision::PassThrough
            }
            _ => DnsInterceptDecision::PassThrough,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct L3Tuple {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

trait TcpTableWrapExt {
    fn into_tcp_table(self) -> Arc<StdMutex<TcpDnsTable>>;
}

impl TcpTableWrapExt for Arc<StdRwLock<()>> {
    fn into_tcp_table(self) -> Arc<StdMutex<TcpDnsTable>> {
        Arc::new(StdMutex::new(TcpDnsTable {
            slots: VecDeque::with_capacity(MAX_TCP_DNS_SLOTS),
            next_isn: 0x5D56_1001,
        }))
    }
}

fn reap_expired_slots(slots: &mut VecDeque<TcpDnsSlot>, now_ms: u64) {
    slots.retain(|s| {
        now_ms.saturating_sub(s.last_active_at_ms) <= TCP_DNS_SLOT_TTL_MS
            && now_ms.saturating_sub(s.created_at_ms) <= TCP_DNS_SLOT_TTL_MS
    });
}

fn emit_tcp_data_segments(slot: &mut TcpDnsSlot, payload: &[u8], fin: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let chunk_size = usize::from(slot.mss).max(256);
    let total_chunks = payload.chunks(chunk_size).len();
    for (idx, chunk) in payload.chunks(chunk_size).enumerate() {
        let is_last = idx + 1 == total_chunks;
        let flags = if fin && is_last {
            TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ACK
        } else {
            TCP_FLAG_PSH | TCP_FLAG_ACK
        };
        out.push(build_l3_tcp_packet(TcpSegmentSpec {
            src_ip: slot.key.server_ip,
            dst_ip: slot.key.client_ip,
            src_port: slot.key.server_port,
            dst_port: slot.key.client_port,
            seq: slot.snd_nxt,
            ack: slot.rcv_nxt,
            flags,
            window: u16::try_from(MAX_TCP_DNS_FRAME_BYTES).unwrap_or(4096),
            mss_opt: None,
            payload: chunk,
        }));
        slot.snd_nxt = slot.snd_nxt.wrapping_add(chunk.len() as u32);
        if fin && is_last {
            slot.snd_nxt = slot.snd_nxt.wrapping_add(1);
        }
    }
    if fin && total_chunks == 0 {
        out.push(build_l3_tcp_packet(TcpSegmentSpec {
            src_ip: slot.key.server_ip,
            dst_ip: slot.key.client_ip,
            src_port: slot.key.server_port,
            dst_port: slot.key.client_port,
            seq: slot.snd_nxt,
            ack: slot.rcv_nxt,
            flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
            window: u16::try_from(MAX_TCP_DNS_FRAME_BYTES).unwrap_or(4096),
            mss_opt: None,
            payload: &[],
        }));
        slot.snd_nxt = slot.snd_nxt.wrapping_add(1);
    }
    out
}

fn is_dns_tc_truncated(wire: &[u8]) -> bool {
    wire.len() >= DNS_HEADER_LEN && wire.get(2).is_some_and(|b| (b & 0x02) != 0)
}

fn frame_tcp_dns_response(dns_wire: &[u8]) -> Vec<u8> {
    let max_body = MAX_TCP_DNS_FRAME_BYTES.saturating_sub(2);
    let body = clamp_dns_udp_response(dns_wire, max_body);
    let len_u16 = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let mut framed = Vec::with_capacity(2 + body.len());
    framed.extend_from_slice(&len_u16.to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

fn compute_nat64_dns_v6(
    dns_v4: Option<Ipv4Addr>,
    nat64_prefix: Option<Nat64Prefix>,
) -> Option<Ipv6Addr> {
    let v4 = dns_v4?;
    let prefix = nat64_prefix?;
    Some(Nat64Synthesizer::new(prefix).synthesize_ip(v4))
}

fn synthesize_upstream_target(server: IpAddr, nat64_prefix: Option<Nat64Prefix>) -> IpAddr {
    match (server, nat64_prefix) {
        (IpAddr::V4(v4), Some(prefix)) => {
            IpAddr::V6(Nat64Synthesizer::new(prefix).synthesize_ip(v4))
        }
        _ => server,
    }
}

enum TcpConnectFailure {
    FailClosed(mesh_core::AppError),
    ConnectTimeoutOrIo(mesh_core::AppError),
}

fn configure_protected_underlay_socket(
    socket: &Socket,
    is_ipv6: bool,
    protector: Option<&dyn SocketProtector>,
    underlay_if_index: Option<u32>,
    linux_fwmark: Option<u32>,
) -> mesh_core::AppResult<()> {
    socket.set_nonblocking(true).map_err(|err| {
        mesh_core::AppError::internal(format!(
            "failed setting upstream DNS socket nonblocking: {err}"
        ))
    })?;

    if let Some(prot) = protector {
        let raw_fd = extract_socket2_raw_fd(socket)?;
        prot.protect_socket(raw_fd)?;
    }

    #[cfg(target_os = "linux")]
    {
        let _unused = (is_ipv6, underlay_if_index);
        if let Some(mark) = linux_fwmark {
            let raw_fd = extract_socket2_raw_fd(socket)?;
            mesh_sys::socket_linux::set_socket_fwmark(raw_fd, mark)?;
        }
    }
    #[cfg(target_os = "ios")]
    {
        let _unused = linux_fwmark;
        if let Some(if_index) = underlay_if_index
            && if_index > 0
        {
            let raw_fd = extract_socket2_raw_fd(socket)?;
            mesh_sys::socket_ios::bind_socket_to_interface_index(raw_fd, is_ipv6, if_index)?;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "ios")))]
    let _unused = (is_ipv6, underlay_if_index, linux_fwmark);
    Ok(())
}

fn bind_protected_udp_socket(
    is_ipv6: bool,
    protector: Option<&dyn SocketProtector>,
    underlay_if_index: Option<u32>,
    linux_fwmark: Option<u32>,
) -> mesh_core::AppResult<UdpSocket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
        mesh_core::AppError::internal(format!("failed creating upstream DNS UDP socket: {err}"))
    })?;
    configure_protected_underlay_socket(
        &socket,
        is_ipv6,
        protector,
        underlay_if_index,
        linux_fwmark,
    )?;

    let bind_addr: SocketAddr = if is_ipv6 {
        SocketAddr::from(([0_u16; 8], 0))
    } else {
        SocketAddr::from(([0_u8; 4], 0))
    };
    socket.bind(&bind_addr.into()).map_err(|err| {
        mesh_core::AppError::internal(format!("failed binding upstream DNS UDP socket: {err}"))
    })?;
    let std_udp: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_udp).map_err(|err| {
        mesh_core::AppError::internal(format!(
            "failed adopting upstream DNS socket into tokio: {err}"
        ))
    })
}

async fn connect_protected_tcp_socket(
    target_addr: SocketAddr,
    protector: Option<&dyn SocketProtector>,
    underlay_if_index: Option<u32>,
    linux_fwmark: Option<u32>,
    timeout: Duration,
) -> Result<TcpStream, TcpConnectFailure> {
    let is_ipv6 = target_addr.is_ipv6();
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(|err| {
        TcpConnectFailure::FailClosed(mesh_core::AppError::internal(format!(
            "failed creating upstream DNS TCP socket: {err}"
        )))
    })?;
    configure_protected_underlay_socket(
        &socket,
        is_ipv6,
        protector,
        underlay_if_index,
        linux_fwmark,
    )
    .map_err(TcpConnectFailure::FailClosed)?;

    if let Err(err) = socket.connect(&target_addr.into())
        && err.kind() != IoErrorKind::WouldBlock
        && err.raw_os_error() != Some(115)
        && err.raw_os_error() != Some(36)
        && err.raw_os_error() != Some(10035)
    {
        return Err(TcpConnectFailure::ConnectTimeoutOrIo(
            mesh_core::AppError::unavailable(format!("upstream TCP DNS connect failed: {err}")),
        ));
    }

    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream).map_err(|err| {
        TcpConnectFailure::ConnectTimeoutOrIo(mesh_core::AppError::unavailable(format!(
            "failed adopting upstream TCP DNS stream into tokio: {err}"
        )))
    })?;
    tokio::time::timeout(timeout, stream.writable())
        .await
        .map_err(|_| {
            TcpConnectFailure::ConnectTimeoutOrIo(mesh_core::AppError::unavailable(
                "upstream TCP DNS connect timed out",
            ))
        })?
        .map_err(|err| {
            TcpConnectFailure::ConnectTimeoutOrIo(mesh_core::AppError::unavailable(format!(
                "upstream TCP DNS writable wait failed: {err}"
            )))
        })?;
    if let Ok(Some(so_err)) = stream.take_error() {
        return Err(TcpConnectFailure::ConnectTimeoutOrIo(
            mesh_core::AppError::unavailable(format!("upstream TCP DNS socket error: {so_err}")),
        ));
    }
    Ok(stream)
}

fn extract_socket2_raw_fd(socket: &Socket) -> mesh_core::AppResult<i32> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        Ok(socket.as_raw_fd())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket as _;
        let raw = socket.as_raw_socket();
        if raw == u64::MAX {
            return Err(mesh_core::AppError::unavailable(
                "invalid OS socket descriptor",
            ));
        }
        Ok(i32::try_from(raw).unwrap_or((raw & 0x7FFF_FFFF) as i32))
    }
}

struct ParsedL3<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    proto: u8,
    payload: &'a [u8],
}

fn parse_l3_packet(packet: &[u8]) -> Option<ParsedL3<'_>> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => None,
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Option<ParsedL3<'_>> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = usize::from(packet.first()? & 0x0F) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    if total_len < ihl || total_len > packet.len() {
        return None;
    }
    let frag_field = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    if frag_field & 0x3FFF != 0 {
        return None;
    }
    let proto = *packet.get(9)?;
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        *packet.get(12)?,
        *packet.get(13)?,
        *packet.get(14)?,
        *packet.get(15)?,
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        *packet.get(16)?,
        *packet.get(17)?,
        *packet.get(18)?,
        *packet.get(19)?,
    ));
    let payload = packet.get(ihl..total_len)?;
    Some(ParsedL3 {
        src_ip,
        dst_ip,
        proto,
        payload,
    })
}

fn parse_ipv6_packet(packet: &[u8]) -> Option<ParsedL3<'_>> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
    let total_len = 40_usize.checked_add(payload_len)?;
    if packet.len() < total_len {
        return None;
    }
    let src_octets: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
    let dst_octets: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
    let mut next_hdr = *packet.get(6)?;
    let mut offset = 40_usize;

    for _ in 0..4 {
        if next_hdr == IP_PROTO_UDP || next_hdr == IP_PROTO_TCP {
            break;
        }
        // Hop-by-Hop (0), Routing (43), Destination Options (60)
        if matches!(next_hdr, 0 | 43 | 60) {
            let hdr_next = *packet.get(offset)?;
            let ext_len = usize::from(*packet.get(offset + 1)?).saturating_add(1) * 8;
            let next_offset = offset.checked_add(ext_len)?;
            if next_offset > total_len {
                return None;
            }
            next_hdr = hdr_next;
            offset = next_offset;
        } else {
            break;
        }
    }

    let payload = packet.get(offset..total_len)?;
    Some(ParsedL3 {
        src_ip: IpAddr::V6(Ipv6Addr::from(src_octets)),
        dst_ip: IpAddr::V6(Ipv6Addr::from(dst_octets)),
        proto: next_hdr,
        payload,
    })
}

fn parse_udp_datagram(udp: &[u8]) -> Option<(u16, u16, &[u8])> {
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([*udp.first()?, *udp.get(1)?]);
    let dst_port = u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]);
    let declared_len = usize::from(u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]));
    if declared_len < 8 || udp.len() < declared_len {
        return None;
    }
    Some((src_port, dst_port, udp.get(8..declared_len)?))
}

fn parse_tcp_ports(tcp: &[u8]) -> Option<(u16, u16)> {
    if tcp.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([*tcp.first()?, *tcp.get(1)?]);
    let dst_port = u16::from_be_bytes([*tcp.get(2)?, *tcp.get(3)?]);
    Some((src_port, dst_port))
}

struct ParsedTcpSegment<'a> {
    seq: u32,
    ack: u32,
    flags: u8,
    mss_opt: Option<u16>,
    payload: &'a [u8],
}

fn parse_tcp_segment(tcp: &[u8]) -> Option<ParsedTcpSegment<'_>> {
    if tcp.len() < 20 {
        return None;
    }
    let data_offset = usize::from((*tcp.get(12)? >> 4) & 0x0F) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }
    let seq = u32::from_be_bytes([*tcp.get(4)?, *tcp.get(5)?, *tcp.get(6)?, *tcp.get(7)?]);
    let ack = u32::from_be_bytes([*tcp.get(8)?, *tcp.get(9)?, *tcp.get(10)?, *tcp.get(11)?]);
    let flags = *tcp.get(13)?;
    let mss_opt = tcp.get(20..data_offset).and_then(parse_tcp_mss_option);
    let payload = tcp.get(data_offset..)?;
    Some(ParsedTcpSegment {
        seq,
        ack,
        flags,
        mss_opt,
        payload,
    })
}

fn parse_tcp_mss_option(opts: &[u8]) -> Option<u16> {
    let mut i = 0_usize;
    while let Some(&kind) = opts.get(i) {
        match kind {
            0 => break,
            1 => i += 1,
            2 => {
                let len = *opts.get(i + 1)?;
                if len != 4 {
                    return None;
                }
                return Some(u16::from_be_bytes([*opts.get(i + 2)?, *opts.get(i + 3)?]));
            }
            _ => {
                let len = usize::from(*opts.get(i + 1)?);
                if len < 2 {
                    break;
                }
                i = i.saturating_add(len);
            }
        }
    }
    None
}

fn build_stateless_tcp_rst_ack(
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    seg: &ParsedTcpSegment<'_>,
) -> Vec<u8> {
    if seg.flags & TCP_FLAG_SYN != 0 || seg.flags & TCP_FLAG_ACK == 0 {
        let ack_num = seg
            .seq
            .wrapping_add(u32::from(seg.flags & TCP_FLAG_SYN != 0))
            .wrapping_add(seg.payload.len() as u32);
        build_l3_tcp_packet(TcpSegmentSpec {
            src_ip: server_ip,
            dst_ip: client_ip,
            src_port: server_port,
            dst_port: client_port,
            seq: 0,
            ack: ack_num,
            flags: TCP_FLAG_RST | TCP_FLAG_ACK,
            window: 0,
            mss_opt: None,
            payload: &[],
        })
    } else {
        let ack_num = seg
            .seq
            .wrapping_add(seg.payload.len() as u32)
            .wrapping_add(u32::from(seg.flags & TCP_FLAG_FIN != 0));
        build_l3_tcp_packet(TcpSegmentSpec {
            src_ip: server_ip,
            dst_ip: client_ip,
            src_port: server_port,
            dst_port: client_port,
            seq: seg.ack,
            ack: ack_num,
            flags: TCP_FLAG_RST | TCP_FLAG_ACK,
            window: 0,
            mss_opt: None,
            payload: &[],
        })
    }
}

struct ParsedDnsQuery {
    id: u16,
    flags: u16,
    raw_question: Vec<u8>,
    qname: String,
    qtype: u16,
    qclass: u16,
    has_opt: bool,
    max_udp_payload: usize,
}

fn parse_dns_query(wire: &[u8]) -> Option<ParsedDnsQuery> {
    if wire.len() < DNS_HEADER_LEN {
        return None;
    }
    let id = u16::from_be_bytes([*wire.first()?, *wire.get(1)?]);
    let flags = u16::from_be_bytes([*wire.get(2)?, *wire.get(3)?]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([*wire.get(4)?, *wire.get(5)?]);
    if qdcount != 1 {
        return None;
    }
    let ancount = u16::from_be_bytes([*wire.get(6)?, *wire.get(7)?]);
    let nscount = u16::from_be_bytes([*wire.get(8)?, *wire.get(9)?]);
    let arcount = u16::from_be_bytes([*wire.get(10)?, *wire.get(11)?]);

    let (qname, q_after_name) = parse_dns_name(wire, DNS_HEADER_LEN)?;
    if wire.len() < q_after_name + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([*wire.get(q_after_name)?, *wire.get(q_after_name + 1)?]);
    let qclass = u16::from_be_bytes([*wire.get(q_after_name + 2)?, *wire.get(q_after_name + 3)?]);
    let q_end = q_after_name + 4;
    let raw_question = wire.get(DNS_HEADER_LEN..q_end)?.to_vec();

    let mut pos = q_end;
    for _ in 0..(ancount.saturating_add(nscount)) {
        pos = skip_dns_rr(wire, pos)?;
    }
    let mut has_opt = false;
    let mut max_udp_payload = CLASSIC_UDP_DNS_PAYLOAD;
    for _ in 0..arcount {
        let (_, name_end) = parse_dns_name(wire, pos)?;
        if wire.len() < name_end + 10 {
            return None;
        }
        let rr_type = u16::from_be_bytes([*wire.get(name_end)?, *wire.get(name_end + 1)?]);
        let rr_class = u16::from_be_bytes([*wire.get(name_end + 2)?, *wire.get(name_end + 3)?]);
        let rdlen = usize::from(u16::from_be_bytes([
            *wire.get(name_end + 8)?,
            *wire.get(name_end + 9)?,
        ]));
        let next_pos = name_end + 10 + rdlen;
        if wire.len() < next_pos {
            return None;
        }
        if rr_type == DNS_TYPE_OPT {
            has_opt = true;
            max_udp_payload =
                usize::from(rr_class).clamp(CLASSIC_UDP_DNS_PAYLOAD, MAX_UDP_DNS_PAYLOAD);
        }
        pos = next_pos;
    }

    Some(ParsedDnsQuery {
        id,
        flags,
        raw_question,
        qname: normalize_dns_name(&qname),
        qtype,
        qclass,
        has_opt,
        max_udp_payload,
    })
}

fn parse_dns_name(wire: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut idx = start;
    let mut jumped = false;
    let mut end_after_first_ptr = start;
    let mut steps = 0_usize;

    loop {
        steps += 1;
        if steps > 128 {
            return None;
        }
        let len_byte = *wire.get(idx)?;
        if len_byte == 0 {
            if !jumped {
                end_after_first_ptr = idx + 1;
            }
            break;
        }
        if len_byte & 0xC0 == 0xC0 {
            let next_byte = *wire.get(idx + 1)?;
            let ptr = usize::from(u16::from_be_bytes([len_byte & 0x3F, next_byte]));
            if ptr >= wire.len() {
                return None;
            }
            if !jumped {
                end_after_first_ptr = idx + 2;
                jumped = true;
            }
            idx = ptr;
            continue;
        }
        if len_byte & 0xC0 != 0 {
            return None;
        }
        let label_len = usize::from(len_byte);
        let label_start = idx + 1;
        let label_end = label_start + label_len;
        let slice = wire.get(label_start..label_end)?;
        let label = std::str::from_utf8(slice).ok()?;
        labels.push(label.to_ascii_lowercase());
        idx = label_end;
        if !jumped {
            end_after_first_ptr = idx;
        }
    }

    Some((labels.join("."), end_after_first_ptr))
}

fn skip_dns_rr(wire: &[u8], start: usize) -> Option<usize> {
    let (_, name_end) = parse_dns_name(wire, start)?;
    if wire.len() < name_end + 10 {
        return None;
    }
    let rdlen = usize::from(u16::from_be_bytes([
        *wire.get(name_end + 8)?,
        *wire.get(name_end + 9)?,
    ]));
    let next = name_end + 10 + rdlen;
    (wire.len() >= next).then_some(next)
}

fn normalize_dns_name(raw: &str) -> String {
    raw.trim().trim_matches('.').to_ascii_lowercase()
}

fn resolve_local_dns_query(state: &SplitDnsState, query: &ParsedDnsQuery) -> Option<Vec<u8>> {
    let opcode = (query.flags >> 11) & 0x0F;
    if opcode != 0 {
        return Some(build_dns_response(query, DNS_RCODE_NOTIMP, false, &[], &[]));
    }

    if let Some(rev_ip) = parse_in_addr_arpa(&query.qname) {
        let in_overlay = state
            .overlay_cidr
            .is_some_and(|cidr| cidr.contains_subnet_ip(rev_ip));
        if !in_overlay {
            return None;
        }
        if query.qclass != DNS_CLASS_IN && query.qclass != DNS_CLASS_ANY {
            return Some(build_dns_response(
                query,
                DNS_RCODE_NOERROR,
                true,
                &[],
                &[build_soa_authority_rr(&state.domain_suffix)],
            ));
        }
        if let Some(target_fqdn) = state.ptr_by_ip.get(&rev_ip) {
            if matches!(query.qtype, DNS_TYPE_PTR | DNS_TYPE_ANY) {
                let ptr_rr = build_ptr_rr(target_fqdn);
                return Some(build_dns_response(
                    query,
                    DNS_RCODE_NOERROR,
                    true,
                    &[ptr_rr],
                    &[],
                ));
            }
            return Some(build_dns_response(
                query,
                DNS_RCODE_NOERROR,
                true,
                &[],
                &[build_soa_authority_rr(&state.domain_suffix)],
            ));
        }
        return Some(build_dns_response(
            query,
            DNS_RCODE_NXDOMAIN,
            true,
            &[],
            &[build_soa_authority_rr(&state.domain_suffix)],
        ));
    }

    if !matches_mesh_zone(&query.qname, &state.domain_suffix) {
        return None;
    }

    if query.qclass != DNS_CLASS_IN && query.qclass != DNS_CLASS_ANY {
        return Some(build_dns_response(
            query,
            DNS_RCODE_NOERROR,
            true,
            &[],
            &[build_soa_authority_rr(&state.domain_suffix)],
        ));
    }

    if query.qname == state.domain_suffix || query.qname == DEFAULT_DOMAIN_SUFFIX {
        let soa_rr = build_soa_authority_rr(&state.domain_suffix);
        return match query.qtype {
            DNS_TYPE_SOA => Some(build_dns_response(
                query,
                DNS_RCODE_NOERROR,
                true,
                &[soa_rr],
                &[],
            )),
            DNS_TYPE_NS => {
                let ns_rr = build_ns_rr(&state.domain_suffix);
                Some(build_dns_response(
                    query,
                    DNS_RCODE_NOERROR,
                    true,
                    &[ns_rr],
                    &[],
                ))
            }
            _ => Some(build_dns_response(
                query,
                DNS_RCODE_NOERROR,
                true,
                &[],
                &[soa_rr],
            )),
        };
    }

    if let Some(&ipv4) = state.records_by_fqdn.get(&query.qname) {
        return match query.qtype {
            DNS_TYPE_A | DNS_TYPE_ANY => {
                let a_rr = build_a_rr(ipv4);
                Some(build_dns_response(
                    query,
                    DNS_RCODE_NOERROR,
                    true,
                    &[a_rr],
                    &[],
                ))
            }
            // RFC 4074 Section 3: existing name lacking AAAA/HTTPS/SVCB MUST return NOERROR empty NODATA.
            _ => Some(build_dns_response(
                query,
                DNS_RCODE_NOERROR,
                true,
                &[],
                &[build_soa_authority_rr(&state.domain_suffix)],
            )),
        };
    }

    Some(build_dns_response(
        query,
        DNS_RCODE_NXDOMAIN,
        true,
        &[],
        &[build_soa_authority_rr(&state.domain_suffix)],
    ))
}

fn matches_mesh_zone(qname: &str, domain_suffix: &str) -> bool {
    is_same_or_subdomain(qname, domain_suffix) || is_same_or_subdomain(qname, DEFAULT_DOMAIN_SUFFIX)
}

fn is_same_or_subdomain(qname: &str, zone: &str) -> bool {
    qname == zone
        || (qname.len() > zone.len()
            && qname.ends_with(zone)
            && qname
                .as_bytes()
                .get(qname.len() - zone.len() - 1)
                .is_some_and(|&b| b == b'.'))
}

fn parse_in_addr_arpa(qname: &str) -> Option<Ipv4Addr> {
    let prefix = qname.strip_suffix(".in-addr.arpa")?;
    let mut parts = prefix.split('.');
    let d: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let a: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(Ipv4Addr::new(a, b, c, d))
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let trimmed = name.trim().trim_matches('.');
    if trimmed.is_empty() {
        return vec![0];
    }
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        let len = u8::try_from(label.len()).unwrap_or(63);
        let bounded = &label.as_bytes().get(..usize::from(len)).unwrap_or(&[]);
        out.push(len);
        out.extend_from_slice(bounded);
    }
    out.push(0);
    out
}

fn build_a_rr(ip: Ipv4Addr) -> Vec<u8> {
    let mut rr = Vec::with_capacity(16);
    rr.extend_from_slice(&[0xC0, 0x0C]); // pointer to QNAME at offset 12
    rr.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    rr.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    rr.extend_from_slice(&DEFAULT_DNS_ANSWER_TTL_SECS.to_be_bytes());
    rr.extend_from_slice(&4_u16.to_be_bytes());
    rr.extend_from_slice(&ip.octets());
    rr
}

fn build_ptr_rr(fqdn: &str) -> Vec<u8> {
    let target = encode_dns_name(fqdn);
    let mut rr = Vec::with_capacity(12 + target.len());
    rr.extend_from_slice(&[0xC0, 0x0C]);
    rr.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
    rr.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    rr.extend_from_slice(&DEFAULT_DNS_ANSWER_TTL_SECS.to_be_bytes());
    let rdlen = u16::try_from(target.len()).unwrap_or(0);
    rr.extend_from_slice(&rdlen.to_be_bytes());
    rr.extend_from_slice(&target);
    rr
}

fn build_ns_rr(zone: &str) -> Vec<u8> {
    let ns_name = encode_dns_name(&format!("ns.{zone}"));
    let mut rr = Vec::with_capacity(12 + ns_name.len());
    rr.extend_from_slice(&[0xC0, 0x0C]);
    rr.extend_from_slice(&DNS_TYPE_NS.to_be_bytes());
    rr.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    rr.extend_from_slice(&DEFAULT_DNS_ANSWER_TTL_SECS.to_be_bytes());
    let rdlen = u16::try_from(ns_name.len()).unwrap_or(0);
    rr.extend_from_slice(&rdlen.to_be_bytes());
    rr.extend_from_slice(&ns_name);
    rr
}

fn build_soa_authority_rr(zone: &str) -> Vec<u8> {
    let owner = encode_dns_name(zone);
    let mname = encode_dns_name(&format!("ns.{zone}"));
    let rname = encode_dns_name(&format!("hostmaster.{zone}"));
    let rdata_len = mname.len() + rname.len() + 20;
    let mut rr = Vec::with_capacity(owner.len() + 10 + rdata_len);
    rr.extend_from_slice(&owner);
    rr.extend_from_slice(&DNS_TYPE_SOA.to_be_bytes());
    rr.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    rr.extend_from_slice(&DEFAULT_DNS_ANSWER_TTL_SECS.to_be_bytes());
    let rdlen = u16::try_from(rdata_len).unwrap_or(0);
    rr.extend_from_slice(&rdlen.to_be_bytes());
    rr.extend_from_slice(&mname);
    rr.extend_from_slice(&rname);
    rr.extend_from_slice(&1_u32.to_be_bytes()); // serial
    rr.extend_from_slice(&60_u32.to_be_bytes()); // refresh
    rr.extend_from_slice(&30_u32.to_be_bytes()); // retry
    rr.extend_from_slice(&300_u32.to_be_bytes()); // expire
    rr.extend_from_slice(&DEFAULT_DNS_ANSWER_TTL_SECS.to_be_bytes()); // minimum TTL
    rr
}

fn build_opt_rr(max_udp: u16) -> Vec<u8> {
    let mut rr = Vec::with_capacity(11);
    rr.push(0); // root
    rr.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
    rr.extend_from_slice(&max_udp.to_be_bytes());
    rr.extend_from_slice(&0_u32.to_be_bytes()); // extended RCODE / version / DO
    rr.extend_from_slice(&0_u16.to_be_bytes()); // rdlen = 0
    rr
}

fn build_dns_response(
    query: &ParsedDnsQuery,
    rcode: u8,
    aa: bool,
    answers: &[Vec<u8>],
    authorities: &[Vec<u8>],
) -> Vec<u8> {
    let rd = query.flags & 0x0100;
    let resp_flags: u16 = 0x8000 // QR = 1
        | rd
        | 0x0080 // RA = 1
        | if aa { 0x0400 } else { 0 }
        | u16::from(rcode & 0x0F);
    let additionals = if query.has_opt {
        vec![build_opt_rr(
            u16::try_from(MAX_UDP_DNS_PAYLOAD).unwrap_or(1232),
        )]
    } else {
        Vec::new()
    };

    let mut out = Vec::with_capacity(DNS_HEADER_LEN + query.raw_question.len() + 96);
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&u16::try_from(answers.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&u16::try_from(authorities.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&u16::try_from(additionals.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&query.raw_question);
    for rr in answers {
        out.extend_from_slice(rr);
    }
    for rr in authorities {
        out.extend_from_slice(rr);
    }
    for rr in additionals {
        out.extend_from_slice(&rr);
    }
    out
}

fn build_simple_error_from_header(wire: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if wire.len() < DNS_HEADER_LEN {
        return None;
    }
    Some(build_simple_error_response(wire, rcode))
}

fn build_simple_error_response(wire: &[u8], rcode: u8) -> Vec<u8> {
    if wire.len() < DNS_HEADER_LEN {
        return Vec::new();
    }
    let id_hi = wire.first().copied().unwrap_or(0);
    let id_lo = wire.get(1).copied().unwrap_or(0);
    let req_flags = u16::from_be_bytes([
        wire.get(2).copied().unwrap_or(0),
        wire.get(3).copied().unwrap_or(0),
    ]);
    let rd = req_flags & 0x0100;
    let resp_flags = 0x8000 | rd | 0x0080 | u16::from(rcode & 0x0F);

    if let Some(parsed) = parse_dns_query(wire) {
        return build_dns_response(&parsed, rcode, false, &[], &[]);
    }

    let mut out = Vec::with_capacity(DNS_HEADER_LEN);
    out.extend_from_slice(&[id_hi, id_lo]);
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes()); // QDCOUNT=0 for malformed question
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out
}

/// Enforces `<= limit` on a DNS response packet by trimming trailing sections or setting `TC=1`.
fn clamp_dns_udp_response(wire: &[u8], limit: usize) -> Vec<u8> {
    if wire.len() <= limit {
        return wire.to_vec();
    }
    let mut out = wire.get(..limit).unwrap_or(wire).to_vec();
    if out.len() >= DNS_HEADER_LEN {
        if let Some(flags_hi) = out.get_mut(2) {
            *flags_hi |= 0x02; // TC = 1 (truncated)
        }
        // If question fits, preserve header + question with zero RRs and TC=1 for RFC 2181 safety.
        if let Some(parsed) = parse_dns_query_question_end(wire)
            && parsed <= limit
        {
            out.truncate(parsed);
            if let Some(counts) = out.get_mut(6..12) {
                counts.fill(0);
            }
        } else {
            out.truncate(DNS_HEADER_LEN.min(limit));
            if let Some(counts) = out.get_mut(4..12) {
                counts.fill(0);
            }
        }
    }
    out
}

fn parse_dns_query_question_end(wire: &[u8]) -> Option<usize> {
    if wire.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([*wire.get(4)?, *wire.get(5)?]);
    if qdcount == 0 {
        return Some(DNS_HEADER_LEN);
    }
    let (_, q_after_name) = parse_dns_name(wire, DNS_HEADER_LEN)?;
    let end = q_after_name + 4;
    (wire.len() >= end).then_some(end)
}

fn build_l3_udp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8_usize.saturating_add(payload.len());
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());
    udp.extend_from_slice(&0_u16.to_be_bytes());
    udp.extend_from_slice(payload);

    let cksum = transport_checksum(src_ip, dst_ip, IP_PROTO_UDP, &udp);
    if let Some(csum_bytes) = udp.get_mut(6..8) {
        let final_cksum = if cksum == 0 { 0xFFFF } else { cksum };
        csum_bytes.copy_from_slice(&final_cksum.to_be_bytes());
    }

    wrap_l3_packet(src_ip, dst_ip, IP_PROTO_UDP, &udp)
}

struct TcpSegmentSpec<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss_opt: Option<u16>,
    payload: &'a [u8],
}

fn build_l3_tcp_packet(spec: TcpSegmentSpec<'_>) -> Vec<u8> {
    let opt_len = if spec.mss_opt.is_some() {
        4_usize
    } else {
        0_usize
    };
    let header_len = 20 + opt_len;
    let data_offset_byte = u8::try_from(header_len / 4).unwrap_or(5) << 4;
    let mut tcp = Vec::with_capacity(header_len + spec.payload.len());
    tcp.extend_from_slice(&spec.src_port.to_be_bytes());
    tcp.extend_from_slice(&spec.dst_port.to_be_bytes());
    tcp.extend_from_slice(&spec.seq.to_be_bytes());
    tcp.extend_from_slice(&spec.ack.to_be_bytes());
    tcp.push(data_offset_byte);
    tcp.push(spec.flags);
    tcp.extend_from_slice(&spec.window.to_be_bytes());
    tcp.extend_from_slice(&0_u16.to_be_bytes()); // checksum placeholder
    tcp.extend_from_slice(&0_u16.to_be_bytes()); // urgent pointer
    if let Some(mss) = spec.mss_opt {
        tcp.push(2); // Kind = MSS
        tcp.push(4); // Length = 4
        tcp.extend_from_slice(&mss.to_be_bytes());
    }
    tcp.extend_from_slice(spec.payload);

    let cksum = transport_checksum(spec.src_ip, spec.dst_ip, IP_PROTO_TCP, &tcp);
    if let Some(csum_bytes) = tcp.get_mut(16..18) {
        csum_bytes.copy_from_slice(&cksum.to_be_bytes());
    }

    wrap_l3_packet(spec.src_ip, spec.dst_ip, IP_PROTO_TCP, &tcp)
}

fn wrap_l3_packet(src_ip: IpAddr, dst_ip: IpAddr, proto: u8, transport: &[u8]) -> Vec<u8> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let total_len = 20_usize.saturating_add(transport.len());
            let mut pkt = Vec::with_capacity(total_len);
            pkt.push(0x45); // v4, IHL = 5
            pkt.push(0);
            pkt.extend_from_slice(&u16::try_from(total_len).unwrap_or(u16::MAX).to_be_bytes());
            pkt.extend_from_slice(&0_u16.to_be_bytes()); // ID
            pkt.extend_from_slice(&0x4000_u16.to_be_bytes()); // DF
            pkt.push(64); // TTL
            pkt.push(proto);
            pkt.extend_from_slice(&0_u16.to_be_bytes()); // header checksum
            pkt.extend_from_slice(&src_v4.octets());
            pkt.extend_from_slice(&dst_v4.octets());
            let hdr_sum = ipv4_header_checksum(pkt.get(..20).unwrap_or(&[]));
            if let Some(csum_bytes) = pkt.get_mut(10..12) {
                csum_bytes.copy_from_slice(&hdr_sum.to_be_bytes());
            }
            pkt.extend_from_slice(transport);
            pkt
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let payload_len = u16::try_from(transport.len()).unwrap_or(u16::MAX);
            let mut pkt = Vec::with_capacity(40 + transport.len());
            pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // v6
            pkt.extend_from_slice(&payload_len.to_be_bytes());
            pkt.push(proto);
            pkt.push(64); // hop limit
            pkt.extend_from_slice(&src_v6.octets());
            pkt.extend_from_slice(&dst_v6.octets());
            pkt.extend_from_slice(transport);
            pkt
        }
        _ => Vec::new(),
    }
}

fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let sum = ones_complement_sum(0, hdr);
    !finalize_ones_complement(sum)
}

fn transport_checksum(src_ip: IpAddr, dst_ip: IpAddr, proto: u8, segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum = ones_complement_sum(sum, &s.octets());
            sum = ones_complement_sum(sum, &d.octets());
            let len_bytes = u16::try_from(segment.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes();
            sum = ones_complement_sum(sum, &[0, proto]);
            sum = ones_complement_sum(sum, &len_bytes);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum = ones_complement_sum(sum, &s.octets());
            sum = ones_complement_sum(sum, &d.octets());
            let len_bytes = u32::try_from(segment.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes();
            sum = ones_complement_sum(sum, &len_bytes);
            sum = ones_complement_sum(sum, &[0, 0, 0, proto]);
        }
        _ => {}
    }
    sum = ones_complement_sum(sum, segment);
    !finalize_ones_complement(sum)
}

fn ones_complement_sum(mut acc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        let word = u16::from_be_bytes([
            pair.first().copied().unwrap_or(0),
            pair.get(1).copied().unwrap_or(0),
        ]);
        acc = acc.saturating_add(u32::from(word));
    }
    if let Some(&rem) = chunks.remainder().first() {
        acc = acc.saturating_add(u32::from(rem) << 8);
    }
    acc
}

fn finalize_ones_complement(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    u16::try_from(sum & 0xFFFF).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use mesh_core::{FakeClock, NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey};
    use mesh_datapath::{DnsInterceptDecision, DnsPacketInterceptor};
    use mesh_net::{Nat64Prefix, SocketProtector, TunDevice};
    use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};
    use proptest::prelude::*;
    use tokio_util::sync::CancellationToken;

    use super::{
        DEFAULT_DOMAIN_SUFFIX, DNS_CLASS_IN, DNS_HEADER_LEN, DNS_RCODE_NOERROR, DNS_RCODE_NXDOMAIN,
        DNS_RCODE_SERVFAIL, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_HTTPS, DNS_TYPE_OPT, DNS_TYPE_PTR,
        DOT_PORT, IP_PROTO_TCP, IP_PROTO_UDP, MAX_TCP_DNS_FRAME_BYTES, MAX_TCP_DNS_MSS,
        MAX_TCP_DNS_SLOTS, MAX_UDP_DNS_PAYLOAD, MobileSplitDnsInterceptor, TCP_DNS_SLOT_TTL_MS,
        TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TcpSegmentSpec,
        build_a_rr, build_dns_response, build_l3_tcp_packet, build_l3_udp_packet, encode_dns_name,
        parse_dns_query, parse_l3_packet, parse_tcp_segment, parse_udp_datagram,
    };

    fn sample_netmap() -> Result<(NetmapSnapshot, OverlayIp, NodeName, OverlayIp), String> {
        let cidr = OverlayCidr::from_str("100.64.0.0/10").map_err(|e| e.to_string())?;
        let self_ip =
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 10)).map_err(|e| e.to_string())?;
        let peer_ip =
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 20)).map_err(|e| e.to_string())?;
        let dns_ip =
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 100, 100, 100)).map_err(|e| e.to_string())?;
        let self_name = NodeName::parse("phone-ios").map_err(|e| e.to_string())?;
        let peer_name = NodeName::parse("nas-home").map_err(|e| e.to_string())?;

        let snap = NetmapSnapshot {
            netmap_version: 5,
            generated_at_ms: 1_700_000_000_000,
            overlay_cidr: cidr,
            domain_suffix: DEFAULT_DOMAIN_SUFFIX.to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "198.51.100.10:8443".to_owned(),
                relay_tcp_endpoint: "198.51.100.10:8443".to_owned(),
                stun_udp_endpoints: vec!["198.51.100.10:13478".to_owned()],
            },
            pin_set: PinSetDto {
                active_pin: mesh_core::SpkiPin::from_sha256_bytes([0_u8; 32]),
                next_pin: None,
            },
            peers: vec![PeerEntry {
                node_id: NodeId::new_v7(1_700_000_000_000),
                name: peer_name,
                fqdn: "nas-home.mesh.internal".to_owned(),
                overlay_ip: peer_ip,
                node_pubkey: PublicKey::from_bytes([11_u8; 32]).map_err(|e| e.to_string())?,
                disco_pubkey: PublicKey::from_bytes([22_u8; 32]).map_err(|e| e.to_string())?,
                endpoints: Vec::new(),
                relay_home: "198.51.100.10:8443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            }],
        };
        Ok((snap, self_ip, self_name, dns_ip))
    }

    fn build_dns_query_bytes(id: u16, qname: &str, qtype: u16, edns_size: Option<u16>) -> Vec<u8> {
        let mut wire = Vec::with_capacity(64);
        wire.extend_from_slice(&id.to_be_bytes());
        wire.extend_from_slice(&0x0100_u16.to_be_bytes()); // standard query, RD=1
        wire.extend_from_slice(&1_u16.to_be_bytes()); // QDCOUNT = 1
        wire.extend_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
        wire.extend_from_slice(&0_u16.to_be_bytes()); // NSCOUNT
        wire.extend_from_slice(&u16::from(edns_size.is_some()).to_be_bytes()); // ARCOUNT
        wire.extend_from_slice(&encode_dns_name(qname));
        wire.extend_from_slice(&qtype.to_be_bytes());
        wire.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        if let Some(udp_max) = edns_size {
            wire.push(0); // root
            wire.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
            wire.extend_from_slice(&udp_max.to_be_bytes());
            wire.extend_from_slice(&0_u32.to_be_bytes());
            wire.extend_from_slice(&0_u16.to_be_bytes());
        }
        wire
    }

    fn extract_dns_header_fields(dns_wire: &[u8]) -> Option<(u16, u16, u16, u16, u16)> {
        if dns_wire.len() < DNS_HEADER_LEN {
            return None;
        }
        let id = u16::from_be_bytes([*dns_wire.first()?, *dns_wire.get(1)?]);
        let flags = u16::from_be_bytes([*dns_wire.get(2)?, *dns_wire.get(3)?]);
        let ancount = u16::from_be_bytes([*dns_wire.get(6)?, *dns_wire.get(7)?]);
        let nscount = u16::from_be_bytes([*dns_wire.get(8)?, *dns_wire.get(9)?]);
        let arcount = u16::from_be_bytes([*dns_wire.get(10)?, *dns_wire.get(11)?]);
        Some((id, flags, ancount, nscount, arcount))
    }

    #[test]
    fn test_udp_mesh_a_rfc4074_nodata_ptr_and_nxdomain() -> Result<(), String> {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let interceptor = MobileSplitDnsInterceptor::new(clock);
        let (snap, self_ip, self_name, dns_ip) = sample_netmap()?;
        interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
        let src_ip = IpAddr::V4(self_ip.as_ipv4());
        let dst_ip = IpAddr::V4(dns_ip.as_ipv4());

        // Act & Assert 1: Known A record returns AA=1 NOERROR ANCOUNT=1 with peer IPv4.
        let a_query =
            build_dns_query_bytes(0x1234, "nas-home.mesh.internal", DNS_TYPE_A, Some(1232));
        let a_pkt = build_l3_udp_packet(src_ip, dst_ip, 40_001, 53, &a_query);
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&a_pkt)
        else {
            return Err("expected A query to be handled".to_owned());
        };
        assert_eq!(tun_responses.len(), 1);
        let first_resp = tun_responses.first().ok_or("missing A response")?;
        let l3 = parse_l3_packet(first_resp).ok_or("invalid response L3")?;
        let (_, _, dns_wire) = parse_udp_datagram(l3.payload).ok_or("invalid response UDP")?;
        let (id, flags, ancount, _, _) =
            extract_dns_header_fields(dns_wire).ok_or("missing DNS header")?;
        assert_eq!(id, 0x1234);
        assert_eq!(flags & 0x0F, u16::from(DNS_RCODE_NOERROR));
        assert_ne!(flags & 0x0400, 0, "AA bit must be set");
        assert_eq!(ancount, 1);
        assert!(
            dns_wire.ends_with(&[100, 64, 0, 20])
                || dns_wire.windows(4).any(|w| w == [100, 64, 0, 20])
        );

        // Act & Assert 2: RFC 4074 Section 3 - AAAA/HTTPS on IPv4-only peer returns NOERROR ANCOUNT=0.
        for qtype in [DNS_TYPE_AAAA, DNS_TYPE_HTTPS] {
            let nodata_q = build_dns_query_bytes(0x2222, "nas-home.mesh.internal", qtype, None);
            let nodata_pkt = build_l3_udp_packet(src_ip, dst_ip, 40_002, 53, &nodata_q);
            let DnsInterceptDecision::Handled { tun_responses } =
                interceptor.intercept_outbound_packet(&nodata_pkt)
            else {
                return Err("expected RFC 4074 query to be handled".to_owned());
            };
            let resp = tun_responses.first().ok_or("missing NODATA resp")?;
            let l3 = parse_l3_packet(resp).ok_or("invalid NODATA L3")?;
            let (_, _, dns_wire) = parse_udp_datagram(l3.payload).ok_or("invalid NODATA UDP")?;
            let (_, flags, ancount, nscount, _) =
                extract_dns_header_fields(dns_wire).ok_or("invalid NODATA header")?;
            assert_eq!(flags & 0x0F, u16::from(DNS_RCODE_NOERROR));
            assert_eq!(ancount, 0);
            assert_eq!(nscount, 1, "RFC 2308 negative SOA cache authority expected");
        }

        // Act & Assert 3: Unknown peer in .mesh.internal returns NXDOMAIN.
        let nx_q = build_dns_query_bytes(0x3333, "missing.mesh.internal", DNS_TYPE_A, None);
        let nx_pkt = build_l3_udp_packet(src_ip, dst_ip, 40_003, 53, &nx_q);
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&nx_pkt)
        else {
            return Err("expected NXDOMAIN query to be handled".to_owned());
        };
        let resp = tun_responses.first().ok_or("missing NXDOMAIN resp")?;
        let l3 = parse_l3_packet(resp).ok_or("invalid NXDOMAIN L3")?;
        let (_, _, dns_wire) = parse_udp_datagram(l3.payload).ok_or("invalid NXDOMAIN UDP")?;
        let (_, flags, ancount, _, _) =
            extract_dns_header_fields(dns_wire).ok_or("invalid NXDOMAIN header")?;
        assert_eq!(flags & 0x0F, u16::from(DNS_RCODE_NXDOMAIN));
        assert_eq!(ancount, 0);

        // Act & Assert 4: PTR reverse query inside overlay_cidr returns peer FQDN.
        let ptr_q = build_dns_query_bytes(0x4444, "20.0.64.100.in-addr.arpa", DNS_TYPE_PTR, None);
        let ptr_pkt = build_l3_udp_packet(src_ip, dst_ip, 40_004, 53, &ptr_q);
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&ptr_pkt)
        else {
            return Err("expected PTR query to be handled".to_owned());
        };
        let resp = tun_responses.first().ok_or("missing PTR resp")?;
        let l3 = parse_l3_packet(resp).ok_or("invalid PTR L3")?;
        let (_, _, dns_wire) = parse_udp_datagram(l3.payload).ok_or("invalid PTR UDP")?;
        let (_, flags, ancount, _, _) =
            extract_dns_header_fields(dns_wire).ok_or("invalid PTR header")?;
        assert_eq!(flags & 0x0F, u16::from(DNS_RCODE_NOERROR));
        assert_eq!(ancount, 1);

        // Non-DNS peer traffic passes through to WireGuard datapath untouched.
        let peer_pkt = build_l3_udp_packet(
            src_ip,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20)),
            50_000,
            80,
            b"hello",
        );
        assert!(matches!(
            interceptor.intercept_outbound_packet(&peer_pkt),
            DnsInterceptDecision::PassThrough
        ));
        Ok(())
    }

    #[test]
    fn test_udp_edns0_clamp_sets_tc_bit_and_respects_budget() -> Result<(), String> {
        // Arrange: create a DNS response larger than 512 and larger than 1232 bytes.
        let oversized = vec![0xAA_u8; MAX_UDP_DNS_PAYLOAD + 300];
        let query = build_dns_query_bytes(0x7777, "nas-home.mesh.internal", DNS_TYPE_A, Some(4096));
        let mut big_wire = query.clone();
        if let Some(flags_hi) = big_wire.get_mut(2) {
            *flags_hi |= 0x80;
        }
        big_wire.extend_from_slice(&oversized);

        // Act
        let clamped = super::clamp_dns_udp_response(&big_wire, MAX_UDP_DNS_PAYLOAD);

        // Assert
        assert!(clamped.len() <= MAX_UDP_DNS_PAYLOAD);
        let (_, flags, ancount, _, _) =
            extract_dns_header_fields(&clamped).ok_or("clamped header missing")?;
        assert_ne!(flags & 0x0200, 0, "TC=1 truncation bit must be set");
        assert_eq!(ancount, 0);
        Ok(())
    }

    #[test]
    fn test_udp_non_mesh_without_underlay_emits_servfail() -> Result<(), String> {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let interceptor = MobileSplitDnsInterceptor::new(clock);
        let (snap, self_ip, self_name, dns_ip) = sample_netmap()?;
        interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
        let query = build_dns_query_bytes(0x5555, "example.com", DNS_TYPE_A, None);
        let pkt = build_l3_udp_packet(
            IpAddr::V4(self_ip.as_ipv4()),
            IpAddr::V4(dns_ip.as_ipv4()),
            41_000,
            53,
            &query,
        );

        // Act
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&pkt)
        else {
            return Err("expected non-mesh fallback handling".to_owned());
        };

        // Assert
        let resp = tun_responses.first().ok_or("missing SERVFAIL resp")?;
        let l3 = parse_l3_packet(resp).ok_or("invalid SERVFAIL L3")?;
        let (_, _, dns_wire) = parse_udp_datagram(l3.payload).ok_or("invalid SERVFAIL UDP")?;
        let (_, flags, _, _, _) =
            extract_dns_header_fields(dns_wire).ok_or("missing SERVFAIL header")?;
        assert_eq!(flags & 0x0F, u16::from(DNS_RCODE_SERVFAIL));
        Ok(())
    }

    #[test]
    fn test_tcp_853_emits_immediate_rst_ack() -> Result<(), String> {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let interceptor = MobileSplitDnsInterceptor::new(clock);
        let (snap, self_ip, self_name, dns_ip) = sample_netmap()?;
        interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
        let syn = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip: IpAddr::V4(self_ip.as_ipv4()),
            dst_ip: IpAddr::V4(dns_ip.as_ipv4()),
            src_port: 52_000,
            dst_port: DOT_PORT,
            seq: 10_000,
            ack: 0,
            flags: TCP_FLAG_SYN,
            window: 65_535,
            mss_opt: Some(MAX_TCP_DNS_MSS),
            payload: &[],
        });

        // Act
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&syn)
        else {
            return Err("expected DoT :853 to be handled".to_owned());
        };

        // Assert
        assert_eq!(tun_responses.len(), 1);
        let rst = tun_responses.first().ok_or("missing RST")?;
        let l3 = parse_l3_packet(rst).ok_or("invalid RST L3")?;
        assert_eq!(l3.proto, IP_PROTO_TCP);
        let seg = parse_tcp_segment(l3.payload).ok_or("invalid RST TCP")?;
        assert_eq!(seg.flags, TCP_FLAG_RST | TCP_FLAG_ACK);
        assert_eq!(seg.ack, 10_001);
        Ok(())
    }

    #[test]
    fn test_tcp_53_16_lru_ttl_3s_mss_1240_and_frame_4096_bounds() -> Result<(), String> {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let interceptor =
            MobileSplitDnsInterceptor::new(Arc::clone(&clock) as Arc<dyn mesh_core::Clock>);
        let (snap, self_ip, self_name, dns_ip) = sample_netmap()?;
        interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
        let src_ip = IpAddr::V4(self_ip.as_ipv4());
        let dst_ip = IpAddr::V4(dns_ip.as_ipv4());

        // Act 1: 16 concurrent slots accepted, 17th evicts LRU slot (max stays 16) with RST|ACK.
        for port in 50_000..(50_000 + u16::try_from(MAX_TCP_DNS_SLOTS).unwrap_or(16)) {
            let syn = build_l3_tcp_packet(TcpSegmentSpec {
                src_ip,
                dst_ip,
                src_port: port,
                dst_port: 53,
                seq: 100,
                ack: 0,
                flags: TCP_FLAG_SYN,
                window: 8192,
                mss_opt: Some(1460),
                payload: &[],
            });
            let DnsInterceptDecision::Handled { tun_responses } =
                interceptor.intercept_outbound_packet(&syn)
            else {
                return Err("expected TCP 53 SYN to be handled".to_owned());
            };
            assert_eq!(tun_responses.len(), 1);
            let l3 = parse_l3_packet(tun_responses.first().ok_or("missing SYN-ACK")?)
                .ok_or("bad SYN-ACK L3")?;
            let seg = parse_tcp_segment(l3.payload).ok_or("bad SYN-ACK TCP")?;
            assert_eq!(seg.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
            assert_eq!(seg.mss_opt, Some(MAX_TCP_DNS_MSS));
        }
        assert_eq!(interceptor.active_tcp_slot_count(), MAX_TCP_DNS_SLOTS);

        let syn17 = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: 50_099,
            dst_port: 53,
            seq: 200,
            ack: 0,
            flags: TCP_FLAG_SYN,
            window: 8192,
            mss_opt: Some(MAX_TCP_DNS_MSS),
            payload: &[],
        });
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&syn17)
        else {
            return Err("expected 17th SYN handled".to_owned());
        };
        assert_eq!(
            tun_responses.len(),
            2,
            "must emit RST for evicted slot + SYN|ACK for new slot"
        );
        assert_eq!(interceptor.active_tcp_slot_count(), MAX_TCP_DNS_SLOTS);

        // Act 2: Send RFC 1035 DNS query over active slot 50_099.
        let syn_ack_l3 = parse_l3_packet(tun_responses.get(1).ok_or("missing 17th SYN-ACK")?)
            .ok_or("bad 17th L3")?;
        let syn_ack_seg = parse_tcp_segment(syn_ack_l3.payload).ok_or("bad 17th TCP")?;
        let query = build_dns_query_bytes(0x9999, "nas-home.mesh.internal", DNS_TYPE_A, None);
        let q_len = u16::try_from(query.len()).map_err(|e| e.to_string())?;
        let mut framed_req = Vec::with_capacity(2 + query.len());
        framed_req.extend_from_slice(&q_len.to_be_bytes());
        framed_req.extend_from_slice(&query);
        let psh = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: 50_099,
            dst_port: 53,
            seq: 201,
            ack: syn_ack_seg.seq.wrapping_add(1),
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            window: 8192,
            mss_opt: None,
            payload: &framed_req,
        });
        let DnsInterceptDecision::Handled {
            tun_responses: data_resps,
        } = interceptor.intercept_outbound_packet(&psh)
        else {
            return Err("expected TCP DNS query handled".to_owned());
        };
        assert!(data_resps.len() >= 2, "ACK + DNS response segment expected");
        let resp_l3 = parse_l3_packet(data_resps.last().ok_or("missing DNS TCP resp")?)
            .ok_or("bad TCP DNS L3")?;
        let resp_seg = parse_tcp_segment(resp_l3.payload).ok_or("bad TCP DNS seg")?;
        assert_eq!(resp_seg.flags, TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert!(resp_seg.payload.len() > 2 && resp_seg.payload.len() <= MAX_TCP_DNS_FRAME_BYTES);
        let resp_wire = resp_seg.payload.get(2..).ok_or("missing TCP DNS wire")?;
        let (id, flags, ancount, _, _) =
            extract_dns_header_fields(resp_wire).ok_or("missing TCP DNS header")?;
        assert_eq!(id, 0x9999);
        assert_eq!(flags & 0x0F, u16::from(DNS_RCODE_NOERROR));
        assert_eq!(ancount, 1);

        // Act 3: Advancing clock > 3_000 ms expires slots and triggers RST|ACK on next segment.
        clock.advance(TCP_DNS_SLOT_TTL_MS + 10);
        assert_eq!(interceptor.active_tcp_slot_count(), 0);
        let stale_ack = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: 50_099,
            dst_port: 53,
            seq: 201_u32.wrapping_add(u32::try_from(framed_req.len()).unwrap_or(0)),
            ack: syn_ack_seg.seq.wrapping_add(1),
            flags: TCP_FLAG_ACK,
            window: 8192,
            mss_opt: None,
            payload: &[],
        });
        let DnsInterceptDecision::Handled {
            tun_responses: rst_resps,
        } = interceptor.intercept_outbound_packet(&stale_ack)
        else {
            return Err("expected expired slot RST".to_owned());
        };
        let rst_l3 = parse_l3_packet(rst_resps.first().ok_or("missing expired RST")?)
            .ok_or("bad expired RST L3")?;
        let rst_seg = parse_tcp_segment(rst_l3.payload).ok_or("bad expired RST TCP")?;
        assert_eq!(rst_seg.flags, TCP_FLAG_RST | TCP_FLAG_ACK);
        Ok(())
    }

    #[test]
    fn test_ipv6_nat64_and_mapped_dns_interception() -> Result<(), String> {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let interceptor = MobileSplitDnsInterceptor::new(clock);
        let (snap, self_ip, self_name, dns_ip) = sample_netmap()?;
        interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
        interceptor.update_underlay(Vec::new(), Some(Nat64Prefix::well_known()), None, None);

        let mapped_dns_v6 = IpAddr::V6(dns_ip.as_ipv4().to_ipv6_mapped());
        let client_v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let q = build_dns_query_bytes(0xABCD, "phone-ios.mesh.internal", DNS_TYPE_A, None);
        let pkt = build_l3_udp_packet(client_v6, mapped_dns_v6, 55_123, 53, &q);

        // Act
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&pkt)
        else {
            return Err("expected IPv6-mapped overlay DNS to be intercepted".to_owned());
        };

        // Assert
        let resp = tun_responses.first().ok_or("missing v6 resp")?;
        let l3 = parse_l3_packet(resp).ok_or("invalid v6 L3")?;
        assert_eq!(l3.src_ip, mapped_dns_v6);
        assert_eq!(l3.dst_ip, client_v6);
        assert_eq!(l3.proto, IP_PROTO_UDP);
        let (_, _, wire) = parse_udp_datagram(l3.payload).ok_or("invalid v6 UDP")?;
        let (id, flags, ancount, _, _) =
            extract_dns_header_fields(wire).ok_or("missing v6 DNS header")?;
        assert_eq!(id, 0xABCD);
        assert_eq!(flags & 0x0F, u16::from(DNS_RCODE_NOERROR));
        assert_eq!(ancount, 1);
        Ok(())
    }

    #[test]
    fn test_tcp_53_single_transaction_emits_psh_fin_ack_and_rejects_second_query_with_rst_ack()
    -> Result<(), String> {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let interceptor = MobileSplitDnsInterceptor::new(clock);
        let (snap, self_ip, self_name, dns_ip) = sample_netmap()?;
        interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
        let src_ip = IpAddr::V4(self_ip.as_ipv4());
        let dst_ip = IpAddr::V4(dns_ip.as_ipv4());
        let client_port = 51_234_u16;

        let syn = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: client_port,
            dst_port: 53,
            seq: 1_000,
            ack: 0,
            flags: TCP_FLAG_SYN,
            window: 8192,
            mss_opt: Some(1240),
            payload: &[],
        });
        let DnsInterceptDecision::Handled { tun_responses } =
            interceptor.intercept_outbound_packet(&syn)
        else {
            return Err("expected SYN handled".to_owned());
        };
        let syn_ack_l3 = parse_l3_packet(tun_responses.first().ok_or("missing SYN-ACK")?)
            .ok_or("bad SYN-ACK L3")?;
        let syn_ack_seg = parse_tcp_segment(syn_ack_l3.payload).ok_or("bad SYN-ACK TCP")?;

        let query1 = build_dns_query_bytes(0x1111, "nas-home.mesh.internal", DNS_TYPE_A, None);
        let mut framed1 = Vec::with_capacity(2 + query1.len());
        framed1.extend_from_slice(
            &(u16::try_from(query1.len()).map_err(|e| e.to_string())?).to_be_bytes(),
        );
        framed1.extend_from_slice(&query1);

        // Act 1: First query completes with PSH|FIN|ACK and closes the slot immediately.
        let psh1 = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: client_port,
            dst_port: 53,
            seq: 1_001,
            ack: syn_ack_seg.seq.wrapping_add(1),
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            window: 8192,
            mss_opt: None,
            payload: &framed1,
        });
        let DnsInterceptDecision::Handled {
            tun_responses: resps1,
        } = interceptor.intercept_outbound_packet(&psh1)
        else {
            return Err("expected first TCP query handled".to_owned());
        };
        let resp1_l3 = parse_l3_packet(resps1.last().ok_or("missing resp1")?).ok_or("bad L3")?;
        let resp1_seg = parse_tcp_segment(resp1_l3.payload).ok_or("bad seg1")?;
        assert_eq!(resp1_seg.flags, TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert_eq!(interceptor.active_tcp_slot_count(), 0);

        // Act 2: Second query on the closed flow receives RST|ACK.
        let psh2 = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: client_port,
            dst_port: 53,
            seq: 1_001_u32.wrapping_add(u32::try_from(framed1.len()).unwrap_or(0)),
            ack: resp1_seg
                .seq
                .wrapping_add(u32::try_from(resp1_seg.payload.len()).unwrap_or(0))
                .wrapping_add(1),
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            window: 8192,
            mss_opt: None,
            payload: &framed1,
        });
        let DnsInterceptDecision::Handled {
            tun_responses: resps2,
        } = interceptor.intercept_outbound_packet(&psh2)
        else {
            return Err("expected 2nd query handled with RST".to_owned());
        };
        let rst2_l3 =
            parse_l3_packet(resps2.first().ok_or("missing rst2")?).ok_or("bad rst2 L3")?;
        let rst2_seg = parse_tcp_segment(rst2_l3.payload).ok_or("bad rst2 seg")?;
        assert_eq!(rst2_seg.flags, TCP_FLAG_RST | TCP_FLAG_ACK);

        // Act 3: Same-segment pipelined [query1][query1] rejects immediately with RST|ACK & 0 slots.
        let syn2 = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: 51_235,
            dst_port: 53,
            seq: 2_000,
            ack: 0,
            flags: TCP_FLAG_SYN,
            window: 8192,
            mss_opt: Some(1240),
            payload: &[],
        });
        let DnsInterceptDecision::Handled {
            tun_responses: syn2_resps,
        } = interceptor.intercept_outbound_packet(&syn2)
        else {
            return Err("expected syn2 handled".to_owned());
        };
        let syn2_ack_seg = parse_tcp_segment(
            parse_l3_packet(syn2_resps.first().ok_or("missing syn2 ack")?)
                .ok_or("bad syn2 l3")?
                .payload,
        )
        .ok_or("bad syn2 seg")?;
        let mut pipelined = framed1.clone();
        pipelined.extend_from_slice(&framed1);
        let psh_pipe = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip,
            dst_ip,
            src_port: 51_235,
            dst_port: 53,
            seq: 2_001,
            ack: syn2_ack_seg.seq.wrapping_add(1),
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            window: 8192,
            mss_opt: None,
            payload: &pipelined,
        });
        let DnsInterceptDecision::Handled {
            tun_responses: pipe_resps,
        } = interceptor.intercept_outbound_packet(&psh_pipe)
        else {
            return Err("expected pipelined packet handled with RST".to_owned());
        };
        let pipe_rst_seg = parse_tcp_segment(
            parse_l3_packet(pipe_resps.last().ok_or("missing pipe rst")?)
                .ok_or("bad pipe l3")?
                .payload,
        )
        .ok_or("bad pipe seg")?;

        // Assert
        assert_eq!(pipe_rst_seg.flags, TCP_FLAG_RST | TCP_FLAG_ACK);
        assert_eq!(interceptor.active_tcp_slot_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_upstream_dns_tcp_protected_socket_and_udp_tc1_fallback() -> Result<(), String> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{TcpListener, UdpSocket};

        // Arrange: bind matching UDP+TCP mock upstream DNS listeners on an ephemeral localhost port
        #[derive(Debug, Default)]
        struct CountingProtector(AtomicUsize);
        impl SocketProtector for CountingProtector {
            fn protect_socket(&self, _raw_fd: i32) -> mesh_core::AppResult<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        #[derive(Debug, Default)]
        struct RecordingTun(StdMutex<Vec<Vec<u8>>>);
        impl TunDevice for RecordingTun {
            fn interface_name(&self) -> &str {
                "tun-test"
            }
            fn mtu(&self) -> u16 {
                1280
            }
            fn read_packet<'a>(
                &'a self,
                _buf: &'a mut [u8],
            ) -> mesh_net::tun::BoxFuture<'a, mesh_core::AppResult<usize>> {
                Box::pin(futures_pending_forever())
            }
            fn write_packet<'a>(
                &'a self,
                buf: &'a [u8],
            ) -> mesh_net::tun::BoxFuture<'a, mesh_core::AppResult<()>> {
                if let Ok(mut g) = self.0.lock() {
                    g.push(buf.to_vec());
                }
                Box::pin(async { Ok(()) })
            }
            fn close<'a>(&'a self) -> mesh_net::tun::BoxFuture<'a, mesh_core::AppResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        async fn futures_pending_forever() -> mesh_core::AppResult<usize> {
            std::future::pending::<mesh_core::AppResult<usize>>().await
        }

        let udp_srv = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = udp_srv.local_addr().map_err(|e| e.to_string())?.port();
        let tcp_srv = TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| e.to_string())?;

        // Build full NOERROR A response (1 answer -> TC=0) vs truncated UDP response (TC=1).
        let q = build_dns_query_bytes(0x4242, "example.org", DNS_TYPE_A, None);
        let mut udp_tc1_resp = q.clone();
        if let Some([b2, b3]) = udp_tc1_resp.get_mut(2..4) {
            *b2 = 0x82; // QR=1, TC=1
            *b3 = 0x80;
        }
        let parsed_q = parse_dns_query(&q).ok_or("parse mock query")?;
        let full_tcp_resp = build_dns_response(
            &parsed_q,
            DNS_RCODE_NOERROR,
            false,
            &[build_a_rr(Ipv4Addr::new(93, 184, 216, 34))],
            &[],
        );

        let udp_task = tokio::spawn(async move {
            let mut buf = [0_u8; 512];
            if let Ok((_, peer)) = udp_srv.recv_from(&mut buf).await {
                let _sent = udp_srv.send_to(&udp_tc1_resp, peer).await;
            }
        });
        let tcp_task = tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut conn, _)) = tcp_srv.accept().await {
                    let mut len_buf = [0_u8; 2];
                    if conn.read_exact(&mut len_buf).await.is_ok() {
                        let req_len = usize::from(u16::from_be_bytes(len_buf));
                        let mut req = vec![0_u8; req_len];
                        if conn.read_exact(&mut req).await.is_ok() {
                            let rlen = u16::try_from(full_tcp_resp.len()).unwrap_or(0);
                            let mut out = Vec::with_capacity(2 + full_tcp_resp.len());
                            out.extend_from_slice(&rlen.to_be_bytes());
                            out.extend_from_slice(&full_tcp_resp);
                            let _w = conn.write_all(&out).await;
                        }
                    }
                }
            }
        });

        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let interceptor = MobileSplitDnsInterceptor::new(clock);
        let (snap, self_ip, self_name, dns_ip) = sample_netmap()?;
        interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
        interceptor.update_underlay(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], None, None, None);
        interceptor.set_test_upstream_port(Some(port));

        let protector = Arc::new(CountingProtector::default());
        let tun = Arc::new(RecordingTun::default());
        let cancel = CancellationToken::new();
        let fwd_handle = interceptor.start_upstream_forwarder(
            Some(tun.clone()),
            Some(protector.clone()),
            cancel.clone(),
        );

        // Act 1: Intercept UDP query targeting overlay DNS IP for external domain -> triggers UDP TC=1 -> TCP fallback
        let client_ip = IpAddr::V4(self_ip.as_ipv4());
        let server_ip = IpAddr::V4(dns_ip.as_ipv4());
        let udp_pkt = build_l3_udp_packet(client_ip, server_ip, 52_000, 53, &q);
        let DnsInterceptDecision::Handled { .. } = interceptor.intercept_outbound_packet(&udp_pkt)
        else {
            return Err("expected external UDP DNS query queued".to_owned());
        };

        // Act 2: Intercept TCP `:53` query for external domain -> uses resolve_upstream_tcp & emits PSH|FIN|ACK
        let syn = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip: client_ip,
            dst_ip: server_ip,
            src_port: 52_001,
            dst_port: 53,
            seq: 10,
            ack: 0,
            flags: TCP_FLAG_SYN,
            window: 8192,
            mss_opt: Some(1240),
            payload: &[],
        });
        let DnsInterceptDecision::Handled {
            tun_responses: syn_resps,
        } = interceptor.intercept_outbound_packet(&syn)
        else {
            return Err("expected external TCP SYN handled".to_owned());
        };
        let syn_ack = parse_tcp_segment(
            parse_l3_packet(syn_resps.first().ok_or("missing syn_ack")?)
                .ok_or("bad syn_ack l3")?
                .payload,
        )
        .ok_or("bad syn_ack seg")?;
        let mut framed_q = Vec::with_capacity(2 + q.len());
        framed_q
            .extend_from_slice(&(u16::try_from(q.len()).map_err(|e| e.to_string())?).to_be_bytes());
        framed_q.extend_from_slice(&q);
        let psh = build_l3_tcp_packet(TcpSegmentSpec {
            src_ip: client_ip,
            dst_ip: server_ip,
            src_port: 52_001,
            dst_port: 53,
            seq: 11,
            ack: syn_ack.seq.wrapping_add(1),
            flags: TCP_FLAG_PSH | TCP_FLAG_ACK,
            window: 8192,
            mss_opt: None,
            payload: &framed_q,
        });
        let DnsInterceptDecision::Handled { .. } = interceptor.intercept_outbound_packet(&psh)
        else {
            return Err("expected external TCP query queued".to_owned());
        };

        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        let _j1 = fwd_handle.await;
        let _j2 = udp_task.await;
        let _j3 = tcp_task.await;

        // Assert: protector was called for UDP + TCP fallback + direct TCP (>= 3 times),
        // and both UDP fallback reply (TC=0, ancount=1) and TCP reply (PSH|FIN|ACK, ancount=1) reached TUN.
        assert!(protector.0.load(Ordering::Relaxed) >= 3);
        let written = tun.0.lock().map_err(|_| "tun lock".to_owned())?.clone();
        assert_eq!(written.len(), 2);

        let mut saw_udp_full = false;
        let mut saw_tcp_fin = false;
        for pkt in &written {
            let l3 = parse_l3_packet(pkt).ok_or("bad written l3")?;
            if l3.proto == IP_PROTO_UDP {
                let (_, _, dns) = parse_udp_datagram(l3.payload).ok_or("bad udp reply")?;
                let (id, flags, ancount, _, _) =
                    extract_dns_header_fields(dns).ok_or("bad udp dns header")?;
                if id == 0x4242 && (flags & 0x0200) == 0 && ancount == 1 {
                    saw_udp_full = true;
                }
            } else if l3.proto == IP_PROTO_TCP {
                let seg = parse_tcp_segment(l3.payload).ok_or("bad tcp reply")?;
                assert_eq!(seg.flags, TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ACK);
                let wire = seg.payload.get(2..).ok_or("bad tcp dns wire")?;
                let (id, _, ancount, _, _) =
                    extract_dns_header_fields(wire).ok_or("bad tcp dns header")?;
                if id == 0x4242 && ancount == 1 {
                    saw_tcp_fin = true;
                }
            }
        }
        assert!(
            saw_udp_full,
            "UDP TC=1 fallback must deliver full TCP answer"
        );
        assert!(
            saw_tcp_fin,
            "upstream TCP DNS must deliver PSH|FIN|ACK answer"
        );
        assert_eq!(interceptor.active_tcp_slot_count(), 0);
        Ok(())
    }

    proptest! {
        #[test]
        fn test_fuzz_dns_interceptor_never_panics_on_arbitrary_l3_bytes(
            raw in prop::collection::vec(any::<u8>(), 0..=2048)
        ) {
            let clock = Arc::new(FakeClock::new(1_700_000_000_000));
            let interceptor = MobileSplitDnsInterceptor::new(clock);
            if let Ok((snap, self_ip, self_name, dns_ip)) = sample_netmap() {
                interceptor.update_netmap(&snap, Some(self_ip), Some(&self_name), Some(dns_ip));
            }
            let decision = interceptor.intercept_outbound_packet(&raw);
            if let DnsInterceptDecision::Handled { tun_responses } = decision {
                for resp in tun_responses {
                    prop_assert!(resp.len() <= MAX_TCP_DNS_FRAME_BYTES + 64);
                }
            }
        }
    }
}
