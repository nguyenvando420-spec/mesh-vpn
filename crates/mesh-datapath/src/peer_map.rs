//! Diff-based WireGuard `defguard_boringtun` `Tunn` peer state map (`US-010`, `SEC-11`).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;

use defguard_boringtun::noise::{Tunn, TunnResult};
use defguard_boringtun::x25519::{PublicKey as WgPublicKey, StaticSecret as WgStaticSecret};
use tracing::{info, warn};

use mesh_core::{AppError, AppResult, NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey};
use mesh_crypto::{NodeKeypair, Secret};
use mesh_proto::netmap::{CandidateEndpoint, CandidateSource, NetmapSnapshot, PeerEntry};

use crate::magic_socket::{MAGIC_SOCKET_BUFFER_SIZE, PacketBuffer};

/// Maximum queued handshake/data packets drained from one `Tunn::decapsulate` call.
const MAX_TUNN_DRAIN_ITERATIONS: usize = 32;
/// Mask ensuring distinct BoringTun local sender indices stay inside 24 bits.
const WG_INDEX_MASK: u32 = 0x00ff_ffff;

/// Active transport route currently selected for a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerActivePath {
    /// End-to-end encrypted packets are forwarded via home Blind Relay (`<= 1 s` initial path).
    Relay,
    /// End-to-end encrypted packets travel directly over UDP P2P (`US-021`).
    Direct {
        /// Validated UDP endpoint verified by authenticated `DiscoPong` on `DirectUdp`.
        addr: SocketAddr,
        /// Candidate source priority (`Lan > Ipv6 > Reflexive`).
        source: CandidateSource,
        /// Latest measured RTT in milliseconds.
        rtt_ms: u64,
        /// Monotonic timestamp (Unix ms) when direct path was activated or confirmed.
        confirmed_at_ms: u64,
    },
}

/// Resolved outbound network destination for a WireGuard or Disco payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSendTarget {
    /// Transmit directly to the peer's verified UDP endpoint via `MagicSocket`.
    Direct(SocketAddr),
    /// Transmit encapsulated in `RelayFrame::ClientToPeerPacket` to `dst_node_pubkey`.
    Relay(PublicKey),
}

/// Summary of applying an atomic `NetmapSnapshot` diff to [`PeerMap`] (`US-010`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyDiffReport {
    /// Snapshot `netmap_version` that produced this report.
    pub netmap_version: u64,
    /// Number of newly added peers.
    pub added: usize,
    /// Number of peers whose key/IP changed (Tunn recreated) or metadata/endpoints refreshed.
    pub updated: usize,
    /// Number of peers kept completely intact with existing `Tunn` and `Direct` path.
    pub preserved_tunnels: usize,
    /// Number of peers removed immediately due to absence/revocation.
    pub removed: usize,
    /// Peers skipped because of invalid/conflicting configuration (`US-010 AC4`).
    pub skipped_peers: Vec<(NodeId, String)>,
}

/// Zero-alloc result for a single decapsulated WireGuard datagram on the hot path.
#[derive(Debug)]
pub struct DecapsulateResult {
    /// Authenticated sending peer identifier.
    pub peer_id: NodeId,
    /// Locked `/32` source overlay IP expected inside the decrypted IPv4 packet.
    pub peer_overlay_ip: OverlayIp,
    /// Verified peer public key.
    pub peer_node_pubkey: PublicKey,
    /// Preferred outbound destination for any immediate handshake responses.
    pub send_target: PeerSendTarget,
    /// Number of plaintext IPv4 bytes written into the caller's `tunnel_out` buffer, if any.
    pub tunnel_payload_len: Option<usize>,
    /// Handshake replies or queued encrypted packets emitted by `Tunn` to send over network.
    pub outbound_network_packets: Vec<Vec<u8>>,
}

struct WireGuardTunn(Tunn);

impl fmt::Debug for WireGuardTunn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardTunn").finish_non_exhaustive()
    }
}

/// Stateful per-peer session managed by [`PeerMap`].
#[derive(Debug)]
pub struct PeerSession {
    /// Unique peer UUID.
    pub node_id: NodeId,
    /// RFC 1123 node label.
    pub name: NodeName,
    /// Fully-qualified internal domain name.
    pub fqdn: String,
    /// Locked `/32` overlay IPv4 address (`AllowedIPs`).
    pub overlay_ip: OverlayIp,
    /// WireGuard X25519 public key.
    pub node_pubkey: PublicKey,
    /// Authenticated Disco X25519 public key.
    pub disco_pubkey: PublicKey,
    /// Candidate P2P UDP endpoints published via Control.
    pub endpoints: Vec<CandidateEndpoint>,
    /// Assigned home Blind Relay endpoint.
    pub relay_home: String,
    /// Optional key expiration UTC ms.
    pub key_expires_at_ms: Option<u64>,
    /// Online indicator from latest Control NetmapSnapshot.
    pub online: bool,
    /// Currently active send path (`Relay` or `Direct`).
    pub active_path: PeerActivePath,
    /// Transmitted plaintext overlay bytes.
    pub tx_bytes: u64,
    /// Received validated plaintext overlay bytes.
    pub rx_bytes: u64,
    /// Latest packet transmit timestamp (Unix ms) used for on-demand keepalive idle window.
    pub last_tx_at_ms: u64,
    /// Latest packet receive timestamp (Unix ms).
    pub last_rx_at_ms: u64,
    /// Latest authenticated UDP endpoint that successfully decapsulated WireGuard traffic.
    pub last_verified_udp_addr: Option<SocketAddr>,
    tunn: WireGuardTunn,
}

impl PeerSession {
    /// Returns the preferred outbound destination (`Direct` or `Relay`) for this peer.
    #[must_use]
    pub fn send_target(&self) -> PeerSendTarget {
        match self.active_path {
            PeerActivePath::Direct { addr, .. } => PeerSendTarget::Direct(addr),
            PeerActivePath::Relay => PeerSendTarget::Relay(self.node_pubkey),
        }
    }

    /// Returns true if the WireGuard `Tunn` currently holds an established Noise transport session.
    #[must_use]
    pub fn has_established_handshake(&self) -> bool {
        self.tunn.0.stats().0.is_some()
    }
}

/// Diff-based collection of WireGuard peer sessions enforcing `1:1` `/32` mappings (`US-010`).
pub struct PeerMap {
    local_node_id: NodeId,
    local_keypair: NodeKeypair,
    overlay_cidr: Option<OverlayCidr>,
    netmap_version: u64,
    next_wg_index: u32,
    peers: HashMap<NodeId, PeerSession>,
    by_overlay_ip: HashMap<OverlayIp, NodeId>,
    by_node_pubkey: HashMap<PublicKey, NodeId>,
    by_disco_pubkey: HashMap<PublicKey, NodeId>,
}

impl fmt::Debug for PeerMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerMap")
            .field("local_node_id", &self.local_node_id)
            .field("netmap_version", &self.netmap_version)
            .field("peer_count", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl PeerMap {
    /// Creates an empty `PeerMap` bound to the local node's WireGuard keypair.
    #[must_use]
    pub fn new(local_node_id: NodeId, local_keypair: NodeKeypair) -> Self {
        Self {
            local_node_id,
            local_keypair,
            overlay_cidr: None,
            netmap_version: 0,
            next_wg_index: 1,
            peers: HashMap::new(),
            by_overlay_ip: HashMap::new(),
            by_node_pubkey: HashMap::new(),
            by_disco_pubkey: HashMap::new(),
        }
    }

    /// Returns the latest applied `netmap_version`.
    #[must_use]
    pub const fn netmap_version(&self) -> u64 {
        self.netmap_version
    }

    /// Returns the active overlay CIDR from the most recent snapshot, if any.
    #[must_use]
    pub const fn overlay_cidr(&self) -> Option<OverlayCidr> {
        self.overlay_cidr
    }

    /// Returns total active peer sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Returns true if no peers are currently configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Returns an immutable reference to a peer session by `NodeId`.
    #[must_use]
    pub fn get(&self, node_id: &NodeId) -> Option<&PeerSession> {
        self.peers.get(node_id)
    }

    /// Returns a mutable reference to a peer session by `NodeId`.
    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut PeerSession> {
        self.peers.get_mut(node_id)
    }

    /// Resolves a peer session by its `/32` overlay IP.
    #[must_use]
    pub fn get_by_overlay_ip(&self, ip: OverlayIp) -> Option<&PeerSession> {
        self.by_overlay_ip
            .get(&ip)
            .and_then(|id| self.peers.get(id))
    }

    /// Resolves a peer session by its WireGuard public key.
    #[must_use]
    pub fn get_by_node_pubkey(&self, pubkey: &PublicKey) -> Option<&PeerSession> {
        self.by_node_pubkey
            .get(pubkey)
            .and_then(|id| self.peers.get(id))
    }

    /// Resolves a peer session by its Disco public key.
    #[must_use]
    pub fn get_by_disco_pubkey(&self, pubkey: &PublicKey) -> Option<&PeerSession> {
        self.by_disco_pubkey
            .get(pubkey)
            .and_then(|id| self.peers.get(id))
    }

    /// Iterates over all active peer sessions.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &PeerSession)> {
        self.peers.iter()
    }

    /// Iterates mutably over all active peer sessions.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&NodeId, &mut PeerSession)> {
        self.peers.iter_mut()
    }

    /// Applies an atomic `NetmapSnapshot` by diffing against existing sessions (`US-010`).
    ///
    /// Preserves untouched peer `Tunn` state machines and `Direct` paths with zero packet drop,
    /// immediately removes deleted peers, and isolates invalid peer configs with `WARN` logs.
    pub fn apply_diff(&mut self, snapshot: &NetmapSnapshot) -> ApplyDiffReport {
        self.overlay_cidr = Some(snapshot.overlay_cidr);
        self.netmap_version = snapshot.netmap_version;

        let mut report = ApplyDiffReport {
            netmap_version: snapshot.netmap_version,
            ..ApplyDiffReport::default()
        };

        let valid_entries = self.filter_valid_entries(snapshot, &mut report);
        let desired_ids: HashSet<NodeId> =
            valid_entries.iter().map(|entry| entry.node_id).collect();
        report.removed = self.remove_absent_peers(&desired_ids);

        for entry in valid_entries {
            self.upsert_peer(entry, &mut report);
        }

        self.rebuild_lookup_indexes();

        info!(
            component = "datapath.peer_map",
            event = "netmap_diff_applied",
            netmap_version = report.netmap_version,
            added = report.added,
            updated = report.updated,
            preserved_tunnels = report.preserved_tunnels,
            removed = report.removed,
            skipped = report.skipped_peers.len(),
            "applied NetmapSnapshot diff to PeerMap"
        );

        report
    }

    /// Promotes a peer to `PeerActivePath::Direct` after verified `DirectUdp` `DiscoPong`.
    pub fn set_direct_path(
        &mut self,
        node_id: &NodeId,
        addr: SocketAddr,
        source: CandidateSource,
        rtt_ms: u64,
        now_ms: u64,
    ) -> bool {
        let Some(session) = self.peers.get_mut(node_id) else {
            return false;
        };
        session.active_path = PeerActivePath::Direct {
            addr,
            source,
            rtt_ms,
            confirmed_at_ms: now_ms,
        };
        true
    }

    /// Demotes a peer back to `PeerActivePath::Relay` on dead direct path / UDP block.
    pub fn fallback_to_relay(&mut self, node_id: &NodeId, reason: &str) -> bool {
        let Some(session) = self.peers.get_mut(node_id) else {
            return false;
        };
        if matches!(session.active_path, PeerActivePath::Relay) {
            return false;
        }
        warn!(
            component = "datapath.peer_map",
            event = "peer_fallback_to_relay",
            peer_id = %node_id,
            reason,
            "falling back peer path from Direct to BlindRelay"
        );
        session.active_path = PeerActivePath::Relay;
        true
    }

    /// Encapsulates an outbound plaintext IPv4 packet addressed to `dst_overlay_ip`.
    ///
    /// Returns `(PeerId, PeerSendTarget, usize)` writing ciphertext into `out_buf`, or
    /// `Ok(None)` when `Tunn` queued the packet while initiating a handshake (`Done`? No: handshake
    /// initiation packet IS returned in `WriteToNetwork` so the caller must transmit it!).
    pub fn encapsulate_to_overlay_ip(
        &mut self,
        dst_overlay_ip: OverlayIp,
        plaintext_ipv4: &[u8],
        out_buf: &mut PacketBuffer,
        now_ms: u64,
    ) -> AppResult<Option<(NodeId, PeerSendTarget, usize)>> {
        let peer_id = *self.by_overlay_ip.get(&dst_overlay_ip).ok_or_else(|| {
            AppError::not_found(format!("no peer mapped for overlay IP {dst_overlay_ip}"))
        })?;
        let session = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| AppError::internal("peer index out of sync with PeerMap"))?;

        session.last_tx_at_ms = now_ms;
        match session.tunn.0.encapsulate(plaintext_ipv4, out_buf) {
            TunnResult::Done => Ok(None),
            TunnResult::WriteToNetwork(wg_slice) => {
                session.tx_bytes = session.tx_bytes.saturating_add(plaintext_ipv4.len() as u64);
                Ok(Some((peer_id, session.send_target(), wg_slice.len())))
            }
            TunnResult::Err(err) => Err(AppError::unavailable(format!(
                "wireguard encapsulate failed for peer {peer_id}: {err:?}"
            ))),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => Err(
                AppError::internal("unexpected tunnel write result from Tunn::encapsulate"),
            ),
        }
    }

    /// Decapsulates a WireGuard packet received via authenticated Blind Relay `0x02` frame.
    pub fn decapsulate_from_relay(
        &mut self,
        verified_src_node_pubkey: PublicKey,
        datagram: &[u8],
        tunnel_out: &mut PacketBuffer,
        now_ms: u64,
    ) -> Option<DecapsulateResult> {
        let peer_id = *self.by_node_pubkey.get(&verified_src_node_pubkey)?;
        self.decapsulate_for_peer(peer_id, None, datagram, tunnel_out, now_ms)
    }

    /// Decapsulates a WireGuard datagram arriving directly on UDP from `remote_addr`.
    pub fn decapsulate_from_udp(
        &mut self,
        remote_addr: SocketAddr,
        datagram: &[u8],
        tunnel_out: &mut PacketBuffer,
        now_ms: u64,
    ) -> Option<DecapsulateResult> {
        if let Some(candidate_id) = self.find_candidate_peer_for_udp(remote_addr)
            && let Some(res) = self.decapsulate_for_peer(
                candidate_id,
                Some(remote_addr),
                datagram,
                tunnel_out,
                now_ms,
            )
        {
            return Some(res);
        }

        // Roaming or initial direct handshake from a peer whose NAT port shifted: try remaining
        // peers whose Noise keys decrypt/authenticate the packet without promoting `active_path`.
        let fallback_ids: Vec<NodeId> = self.peers.keys().copied().collect();
        for peer_id in fallback_ids {
            if let Some(res) =
                self.decapsulate_for_peer(peer_id, Some(remote_addr), datagram, tunnel_out, now_ms)
            {
                return Some(res);
            }
        }
        None
    }

    /// Advances WireGuard per-peer Noise timers (`update_timers`) and collects outbound packets.
    pub fn tick_timers(
        &mut self,
        scratch: &mut PacketBuffer,
    ) -> Vec<(NodeId, PeerSendTarget, Vec<u8>)> {
        let mut outbound = Vec::new();
        for (&peer_id, session) in &mut self.peers {
            match session.tunn.0.update_timers(scratch) {
                TunnResult::Done => {}
                TunnResult::WriteToNetwork(pkt) => {
                    outbound.push((peer_id, session.send_target(), pkt.to_vec()));
                }
                TunnResult::Err(err) => {
                    warn!(
                        component = "datapath.peer_map",
                        event = "wireguard_timer_error",
                        peer_id = %peer_id,
                        error = ?err,
                        "wireguard update_timers reported error"
                    );
                }
                TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {}
            }
        }
        outbound
    }

    fn decapsulate_for_peer(
        &mut self,
        peer_id: NodeId,
        udp_src: Option<SocketAddr>,
        datagram: &[u8],
        tunnel_out: &mut PacketBuffer,
        now_ms: u64,
    ) -> Option<DecapsulateResult> {
        let session = self.peers.get_mut(&peer_id)?;
        let src_ip = udp_src.map(|addr| addr.ip());
        let mut outbound_network_packets = Vec::new();
        let mut tunnel_payload_len = None;

        match session.tunn.0.decapsulate(src_ip, datagram, tunnel_out) {
            TunnResult::Done => {}
            TunnResult::Err(_) => return None,
            TunnResult::WriteToTunnelV4(inner, _) => {
                tunnel_payload_len = Some(inner.len());
                session.rx_bytes = session.rx_bytes.saturating_add(inner.len() as u64);
                session.last_rx_at_ms = now_ms;
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                // Overlay is IPv4-only; ignore inner IPv6 safely while still updating auth proof.
                session.last_rx_at_ms = now_ms;
            }
            TunnResult::WriteToNetwork(first) => {
                outbound_network_packets.push(first.to_vec());
                drain_tunn_network_queue(&mut session.tunn.0, &mut outbound_network_packets);
                session.last_rx_at_ms = now_ms;
            }
        }

        if let Some(addr) = udp_src {
            // Remember verified UDP source purely for future decapsulate lookup order.
            // Promotion to `ActivePath::Direct` MUST still pass Disco (`HR-G2-04`).
            session.last_verified_udp_addr = Some(addr);
        }

        Some(DecapsulateResult {
            peer_id,
            peer_overlay_ip: session.overlay_ip,
            peer_node_pubkey: session.node_pubkey,
            send_target: session.send_target(),
            tunnel_payload_len,
            outbound_network_packets,
        })
    }

    fn find_candidate_peer_for_udp(&self, remote_addr: SocketAddr) -> Option<NodeId> {
        self.peers
            .iter()
            .find(|(_, session)| {
                matches!(session.active_path, PeerActivePath::Direct { addr, .. } if addr == remote_addr)
                    || session.last_verified_udp_addr == Some(remote_addr)
                    || session.endpoints.iter().any(|ep| ep.addr == remote_addr)
            })
            .map(|(&id, _)| id)
    }

    fn filter_valid_entries<'a>(
        &self,
        snapshot: &'a NetmapSnapshot,
        report: &mut ApplyDiffReport,
    ) -> Vec<&'a PeerEntry> {
        let local_pubkey = self.local_keypair.public_key();
        let mut seen_ids = HashSet::new();
        let mut seen_ips = HashSet::new();
        let mut seen_node_keys = HashSet::new();
        let mut valid = Vec::with_capacity(snapshot.peers.len());

        for entry in &snapshot.peers {
            if entry.node_id == self.local_node_id || entry.node_pubkey == local_pubkey {
                report
                    .skipped_peers
                    .push((entry.node_id, "peer collides with local node".into()));
                warn!(
                    component = "datapath.peer_map",
                    event = "peer_config_invalid",
                    peer_id = %entry.node_id,
                    "skipping peer colliding with local identity"
                );
                continue;
            }
            if !snapshot.overlay_cidr.contains_usable_host(entry.overlay_ip) {
                let reason = format!(
                    "overlay_ip {} outside snapshot CIDR {}",
                    entry.overlay_ip, snapshot.overlay_cidr
                );
                warn!(
                    component = "datapath.peer_map",
                    event = "peer_config_invalid",
                    peer_id = %entry.node_id,
                    reason = %reason,
                    "skipping invalid peer during diff apply"
                );
                report.skipped_peers.push((entry.node_id, reason));
                continue;
            }
            if !seen_ids.insert(entry.node_id)
                || !seen_ips.insert(entry.overlay_ip)
                || !seen_node_keys.insert(entry.node_pubkey)
            {
                let reason =
                    "duplicate peer_id, overlay_ip, or node_pubkey in NetmapSnapshot".to_owned();
                warn!(
                    component = "datapath.peer_map",
                    event = "peer_config_conflict",
                    peer_id = %entry.node_id,
                    reason = %reason,
                    "skipping conflicting peer during diff apply"
                );
                report.skipped_peers.push((entry.node_id, reason));
                continue;
            }
            valid.push(entry);
        }

        valid
    }

    fn remove_absent_peers(&mut self, desired_ids: &HashSet<NodeId>) -> usize {
        let before = self.peers.len();
        self.peers.retain(|id, _| desired_ids.contains(id));
        before.saturating_sub(self.peers.len())
    }

    fn upsert_peer(&mut self, entry: &PeerEntry, report: &mut ApplyDiffReport) {
        if let Some(existing) = self.peers.get_mut(&entry.node_id)
            && existing.node_pubkey == entry.node_pubkey
            && existing.overlay_ip == entry.overlay_ip
        {
            let endpoints_or_disco_changed = existing.endpoints != entry.endpoints
                || existing.disco_pubkey != entry.disco_pubkey
                || existing.name != entry.name
                || existing.fqdn != entry.fqdn
                || existing.relay_home != entry.relay_home
                || existing.online != entry.online
                || existing.key_expires_at_ms != entry.key_expires_at_ms;

            existing.name.clone_from(&entry.name);
            existing.fqdn.clone_from(&entry.fqdn);
            existing.disco_pubkey = entry.disco_pubkey;
            existing.endpoints.clone_from(&entry.endpoints);
            existing.relay_home.clone_from(&entry.relay_home);
            existing.key_expires_at_ms = entry.key_expires_at_ms;
            existing.online = entry.online;

            // Keep active Tunn & Direct path intact! Disco probe handles liveness verification.
            report.preserved_tunnels = report.preserved_tunnels.saturating_add(1);
            if endpoints_or_disco_changed {
                report.updated = report.updated.saturating_add(1);
            }
            return;
        }

        let wg_idx = self.alloc_wg_index();
        let tunn = build_wireguard_tunn(&self.local_keypair, entry.node_pubkey, wg_idx);
        let replaced = self
            .peers
            .insert(entry.node_id, build_peer_session(entry, tunn))
            .is_some();
        if replaced {
            report.updated = report.updated.saturating_add(1);
        } else {
            report.added = report.added.saturating_add(1);
        }
    }

    fn alloc_wg_index(&mut self) -> u32 {
        let idx = self.next_wg_index & WG_INDEX_MASK;
        self.next_wg_index = self.next_wg_index.wrapping_add(1).max(1);
        idx
    }

    fn rebuild_lookup_indexes(&mut self) {
        self.by_overlay_ip.clear();
        self.by_node_pubkey.clear();
        self.by_disco_pubkey.clear();
        for (&id, session) in &self.peers {
            self.by_overlay_ip.insert(session.overlay_ip, id);
            self.by_node_pubkey.insert(session.node_pubkey, id);
            self.by_disco_pubkey.insert(session.disco_pubkey, id);
        }
    }
}

fn build_wireguard_tunn(
    local_keypair: &NodeKeypair,
    peer_pubkey: PublicKey,
    index: u32,
) -> WireGuardTunn {
    let secret_buf = Secret::new(*local_keypair.secret_bytes().expose_secret());
    let static_secret = WgStaticSecret::from(*secret_buf.expose_secret());
    let remote_pub = WgPublicKey::from(*peer_pubkey.as_bytes());
    WireGuardTunn(Tunn::new(
        static_secret,
        remote_pub,
        None,
        None,
        index,
        None,
    ))
}

fn build_peer_session(entry: &PeerEntry, tunn: WireGuardTunn) -> PeerSession {
    PeerSession {
        node_id: entry.node_id,
        name: entry.name.clone(),
        fqdn: entry.fqdn.clone(),
        overlay_ip: entry.overlay_ip,
        node_pubkey: entry.node_pubkey,
        disco_pubkey: entry.disco_pubkey,
        endpoints: entry.endpoints.clone(),
        relay_home: entry.relay_home.clone(),
        key_expires_at_ms: entry.key_expires_at_ms,
        online: entry.online,
        active_path: PeerActivePath::Relay,
        tx_bytes: 0,
        rx_bytes: 0,
        last_tx_at_ms: 0,
        last_rx_at_ms: 0,
        last_verified_udp_addr: None,
        tunn,
    }
}

fn drain_tunn_network_queue(tunn: &mut Tunn, out: &mut Vec<Vec<u8>>) {
    let mut scratch: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];
    for _ in 0..MAX_TUNN_DRAIN_ITERATIONS {
        match tunn.decapsulate(None, &[], &mut scratch) {
            TunnResult::WriteToNetwork(next) => out.push(next.to_vec()),
            TunnResult::Done
            | TunnResult::Err(_)
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mesh_core::SpkiPin;
    use mesh_crypto::DiscoKeypair;
    use mesh_proto::netmap::{PinSetDto, RelayMap};

    use super::*;

    fn mk_peer(id_seed: u8, octet: u8, name: &str) -> (PeerEntry, NodeKeypair) {
        let kp = NodeKeypair::generate();
        let dk = DiscoKeypair::generate();
        let entry = PeerEntry {
            node_id: NodeId::from_bytes([id_seed; 16]),
            name: NodeName::parse(name).expect("valid name"),
            fqdn: format!("{name}.mesh.internal"),
            overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, octet)).expect("ip"),
            node_pubkey: kp.public_key(),
            disco_pubkey: dk.public_key(),
            endpoints: vec![],
            relay_home: "127.0.0.1:14430".to_owned(),
            key_expires_at_ms: None,
            online: true,
        };
        (entry, kp)
    }

    fn mk_snapshot(version: u64, peers: Vec<PeerEntry>) -> NetmapSnapshot {
        NetmapSnapshot {
            netmap_version: version,
            generated_at_ms: 1_000_000,
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "127.0.0.1:14430".to_owned(),
                relay_tcp_endpoint: "127.0.0.1:14430".to_owned(),
                stun_udp_endpoints: vec![],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([1u8; 32]),
                next_pin: None,
            },
            peers,
        }
    }

    fn build_sample_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 28 + payload.len();
        let mut pkt = Vec::with_capacity(total);
        pkt.extend_from_slice(&[0x45, 0]);
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&[0; 5]);
        pkt.push(17);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(&5000u16.to_be_bytes());
        pkt.extend_from_slice(&5001u16.to_be_bytes());
        pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(payload);
        pkt
    }

    // Traces: US-010 AC1/AC2/AC3/AC4
    #[test]
    fn test_peer_map_diff_preserves_untouched_tunnels_and_isolates_invalid_peers() {
        // Arrange
        let local_kp = NodeKeypair::generate();
        let mut map = PeerMap::new(NodeId::from_bytes([1; 16]), local_kp);
        let (peer_a, _) = mk_peer(2, 10, "node-a");
        let (peer_b, _) = mk_peer(3, 11, "node-b");

        let r1 = map.apply_diff(&mk_snapshot(1, vec![peer_a.clone(), peer_b.clone()]));
        assert_eq!(r1.added, 2);
        let direct_ep: SocketAddr = "203.0.113.5:51820".parse().expect("ep");
        assert!(map.set_direct_path(
            &peer_a.node_id,
            direct_ep,
            CandidateSource::Reflexive,
            12,
            5_000,
        ));

        // Act: add peer_c, remove peer_b, include one invalid-CIDR peer_d, keep peer_a unchanged
        let (peer_c, _) = mk_peer(4, 12, "node-c");
        let (mut peer_d, _) = mk_peer(5, 99, "node-bad");
        peer_d.overlay_ip = OverlayIp::from_ipv4(Ipv4Addr::new(192, 168, 50, 5)).expect("ip");

        let r2 = map.apply_diff(&mk_snapshot(
            2,
            vec![peer_a.clone(), peer_c.clone(), peer_d],
        ));

        // Assert
        assert_eq!(r2.preserved_tunnels, 1);
        assert_eq!(r2.added, 1);
        assert_eq!(r2.removed, 1);
        assert_eq!(r2.skipped_peers.len(), 1);
        assert!(map.get(&peer_b.node_id).is_none());
        assert!(map.get(&peer_c.node_id).is_some());
        assert!(matches!(
            map.get(&peer_a.node_id).expect("a").active_path,
            PeerActivePath::Direct { addr, .. } if addr == direct_ep
        ));
    }

    // Traces: US-010, US-026
    #[test]
    fn test_peer_map_two_peers_complete_wireguard_handshake_and_exchange_ipv4_sans_io() {
        // Arrange
        let kp_a = NodeKeypair::generate();
        let kp_b = NodeKeypair::generate();
        let dk_a = DiscoKeypair::generate();
        let dk_b = DiscoKeypair::generate();

        let id_a = NodeId::from_bytes([0xaa; 16]);
        let id_b = NodeId::from_bytes([0xbb; 16]);
        let ip_a = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 2)).expect("ip a");
        let ip_b = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 3)).expect("ip b");

        let entry_b_for_a = PeerEntry {
            node_id: id_b,
            name: NodeName::parse("peer-b").expect("name"),
            fqdn: "peer-b.mesh.internal".to_owned(),
            overlay_ip: ip_b,
            node_pubkey: kp_b.public_key(),
            disco_pubkey: dk_b.public_key(),
            endpoints: vec![],
            relay_home: "127.0.0.1:14430".to_owned(),
            key_expires_at_ms: None,
            online: true,
        };
        let entry_a_for_b = PeerEntry {
            node_id: id_a,
            name: NodeName::parse("peer-a").expect("name"),
            fqdn: "peer-a.mesh.internal".to_owned(),
            overlay_ip: ip_a,
            node_pubkey: kp_a.public_key(),
            disco_pubkey: dk_a.public_key(),
            endpoints: vec![],
            relay_home: "127.0.0.1:14430".to_owned(),
            key_expires_at_ms: None,
            online: true,
        };

        let mut map_a = PeerMap::new(id_a, kp_a.clone_keypair());
        let mut map_b = PeerMap::new(id_b, kp_b.clone_keypair());
        map_a.apply_diff(&mk_snapshot(1, vec![entry_b_for_a]));
        map_b.apply_diff(&mk_snapshot(1, vec![entry_a_for_b]));

        let mut wg_buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];
        let mut tun_buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];
        let app_msg = build_sample_ipv4_packet(ip_a.as_ipv4(), ip_b.as_ipv4(), b"hello-mesh");

        // Act: A encapsulates app_msg -> triggers HandshakeInit
        let (_, _, init_len) = map_a
            .encapsulate_to_overlay_ip(ip_b, &app_msg, &mut wg_buf, 100)
            .expect("encap ok")
            .expect("emits handshake init");

        // B decapsulates HandshakeInit -> emits HandshakeResponse
        let dec_b1 = map_b
            .decapsulate_from_relay(
                kp_a.public_key(),
                wg_buf.get(..init_len).expect("init slice"),
                &mut tun_buf,
                101,
            )
            .expect("B accepts handshake init");
        assert_eq!(dec_b1.outbound_network_packets.len(), 1);

        // A decapsulates HandshakeResponse -> drains queued encrypted TransportData!
        let dec_a = map_a
            .decapsulate_from_relay(
                kp_b.public_key(),
                dec_b1.outbound_network_packets.first().expect("hs reply"),
                &mut tun_buf,
                102,
            )
            .expect("A accepts handshake response");
        assert!(!dec_a.outbound_network_packets.is_empty());

        // B decapsulates queued TransportData -> recovers plaintext inner IPv4!
        let mut received = None;
        for wg_pkt in &dec_a.outbound_network_packets {
            let dec_b2 = map_b
                .decapsulate_from_relay(kp_a.public_key(), wg_pkt, &mut tun_buf, 103)
                .expect("B accepts data");
            if let Some(len) = dec_b2.tunnel_payload_len {
                received = Some(tun_buf.get(..len).expect("tun payload").to_vec());
            }
        }

        // Assert
        assert_eq!(received.as_deref(), Some(app_msg.as_slice()));
        assert!(
            map_a
                .get(&id_b)
                .expect("b session")
                .has_established_handshake()
        );
    }
}
