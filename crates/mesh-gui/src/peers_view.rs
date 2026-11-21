//! Peer table filtering, human byte formatting, and Disco ping output formatting (`US-106`).

use mesh_proto::agent_ipc::{ActivePathKind, AgentPeerStatus, PingResponse, PingVia};

/// Four-state filter chip mode for Peers Zone 2 (`ADR-030`, `US-120`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) enum PeerFilterMode {
    /// Show every known peer regardless of online/path status.
    #[default]
    All,
    /// Show peers currently online on the Control plane.
    Online,
    /// Show online peers actively using a direct P2P UDP tunnel.
    Direct,
    /// Show online peers actively routed through the Blind Relay.
    Relay,
}

/// Per-category peer counts powering the 4-state filter chip badges (`US-120`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PeerFilterCounts {
    pub(crate) all: usize,
    pub(crate) online: usize,
    pub(crate) direct: usize,
    pub(crate) relay: usize,
}

/// Filters peers by [`PeerFilterMode`] (`ADR-030`).
///
/// Additive companion to [`filter_peers`] (whose 2-parameter signature stays intact for
/// `linux_gui.rs` and existing tests).
#[must_use]
pub(crate) fn filter_peers_by_mode(
    peers: &[AgentPeerStatus],
    mode: PeerFilterMode,
) -> Vec<&AgentPeerStatus> {
    peers
        .iter()
        .filter(|peer| match mode {
            PeerFilterMode::All => true,
            PeerFilterMode::Online => peer.online,
            PeerFilterMode::Direct => peer.online && peer.active_path == ActivePathKind::Direct,
            PeerFilterMode::Relay => peer.online && peer.active_path == ActivePathKind::Relay,
        })
        .collect()
}

/// Computes count badges for all 4 peer filter chips (`All`, `Online`, `Direct`, `Relay`).
#[must_use]
pub(crate) fn count_peers_by_mode(peers: &[AgentPeerStatus]) -> PeerFilterCounts {
    let mut counts = PeerFilterCounts {
        all: peers.len(),
        ..PeerFilterCounts::default()
    };
    for peer in peers {
        if peer.online {
            counts.online += 1;
            match peer.active_path {
                ActivePathKind::Direct => counts.direct += 1,
                ActivePathKind::Relay => counts.relay += 1,
                ActivePathKind::None => {}
            }
        }
    }
    counts
}

/// Applies both [`PeerFilterMode`] and case-insensitive search (`name`, `fqdn`, `overlay_ip`,
/// `node_id`) together for the Peers Zone list (`US-120`).
#[must_use]
pub(crate) fn filter_peers_combined<'a>(
    peers: &'a [AgentPeerStatus],
    query: &str,
    mode: PeerFilterMode,
) -> Vec<&'a AgentPeerStatus> {
    let needle = query.trim().to_ascii_lowercase();
    peers
        .iter()
        .filter(|peer| {
            let mode_ok = match mode {
                PeerFilterMode::All => true,
                PeerFilterMode::Online => peer.online,
                PeerFilterMode::Direct => peer.online && peer.active_path == ActivePathKind::Direct,
                PeerFilterMode::Relay => peer.online && peer.active_path == ActivePathKind::Relay,
            };
            if !mode_ok {
                return false;
            }
            if needle.is_empty() {
                return true;
            }
            peer.name.as_str().to_ascii_lowercase().contains(&needle)
                || peer.fqdn.to_ascii_lowercase().contains(&needle)
                || peer.overlay_ip.to_string().contains(&needle)
                || peer
                    .node_id
                    .to_string()
                    .to_ascii_lowercase()
                    .contains(&needle)
        })
        .collect()
}

/// Formats a filter chip label with its live count badge (e.g. `"Direct (2)"`).
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn format_filter_chip_label(
    mode: PeerFilterMode,
    counts: PeerFilterCounts,
    localized_label: Option<&str>,
) -> String {
    let (fallback, count) = match mode {
        PeerFilterMode::All => ("All", counts.all),
        PeerFilterMode::Online => ("Online", counts.online),
        PeerFilterMode::Direct => ("Direct", counts.direct),
        PeerFilterMode::Relay => ("Relay", counts.relay),
    };
    let base = localized_label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback);
    format!("{base} ({count})")
}

/// Formats a byte counter into compact IEC binary units (`B`, `KiB`, `MiB`, `GiB`).
#[must_use]
pub(crate) fn format_human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        let tenths = (bytes * 10) / KIB;
        format!("{}.{} KiB", tenths / 10, tenths % 10)
    } else if bytes < GIB {
        let tenths = (bytes * 10) / MIB;
        format!("{}.{} MiB", tenths / 10, tenths % 10)
    } else {
        let tenths = (bytes * 10) / GIB;
        format!("{}.{} GiB", tenths / 10, tenths % 10)
    }
}

/// Filters peers by case-insensitive substring match against peer name, FQDN, overlay IP, or ID.
#[must_use]
pub(crate) fn filter_peers<'a>(
    peers: &'a [AgentPeerStatus],
    query: &str,
) -> Vec<&'a AgentPeerStatus> {
    let needle = query.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return peers.iter().collect();
    }
    peers
        .iter()
        .filter(|peer| {
            peer.name.as_str().to_ascii_lowercase().contains(&needle)
                || peer.fqdn.to_ascii_lowercase().contains(&needle)
                || peer.overlay_ip.to_string().contains(&needle)
                || peer
                    .node_id
                    .to_string()
                    .to_ascii_lowercase()
                    .contains(&needle)
        })
        .collect()
}

/// Formats a single concise ListBox line for a peer entry (`Name | IP | Path | RTT | Traffic`).
#[must_use]
pub(crate) fn format_peer_list_entry(peer: &AgentPeerStatus) -> String {
    let status_tag = if !peer.online {
        "Offline".to_owned()
    } else {
        let rtt = peer
            .rtt_ms
            .map_or_else(|| "-".to_owned(), |ms| format!("{ms}ms"));
        match peer.active_path {
            ActivePathKind::Direct => format!("Direct {rtt}"),
            ActivePathKind::Relay => format!("Relay {rtt}"),
            ActivePathKind::None => "Online (Idle)".to_owned(),
        }
    };
    format!(
        "{:<18} {:<15} [{:<13}] TX {} / RX {}",
        peer.name.as_str(),
        peer.overlay_ip,
        status_tag,
        format_human_bytes(peer.tx_bytes),
        format_human_bytes(peer.rx_bytes),
    )
}

/// Formats detailed peer diagnostics for the selected peer inspector pane.
#[must_use]
pub(crate) fn format_peer_detail_summary(peer: &AgentPeerStatus) -> String {
    let path_str = match peer.active_path {
        ActivePathKind::Direct => "Direct P2P UDP",
        ActivePathKind::Relay => "Blind Relay WebSocket",
        ActivePathKind::None => "No Active Tunnel",
    };
    let endpoint = peer.direct_endpoint.as_deref().unwrap_or("-");
    let rtt = peer
        .rtt_ms
        .map_or_else(|| "-".to_owned(), |ms| format!("{ms} ms"));
    let hs = peer
        .last_handshake_at_ms
        .map_or_else(|| "never".to_owned(), |ts| format!("{ts} ms UTC"));
    format!(
        "Peer: {} ({})\r\n\
         Overlay IP : {}\r\n\
         Node ID    : {}\r\n\
         Online     : {}\r\n\
         Path       : {} (endpoint: {})\r\n\
         RTT        : {}\r\n\
         Handshake  : {}\r\n\
         Traffic    : TX {} / RX {}",
        peer.name.as_str(),
        peer.fqdn,
        peer.overlay_ip,
        peer.node_id,
        if peer.online { "yes" } else { "no" },
        path_str,
        endpoint,
        rtt,
        hs,
        format_human_bytes(peer.tx_bytes),
        format_human_bytes(peer.rx_bytes),
    )
}

/// Formats `POST /v1/agent/ping` output into readable multiline diagnostics (`PingVia` + summary).
#[must_use]
pub(crate) fn format_ping_response(resp: &PingResponse) -> String {
    let mut lines = Vec::with_capacity(resp.samples.len() + 3);
    lines.push(format!(
        "Ping {} ({}) — {} sent, {} received, {:.1}% loss",
        resp.target_name.as_str(),
        resp.target_overlay_ip,
        resp.packets_sent,
        resp.packets_received,
        resp.loss_percent
    ));
    for sample in &resp.samples {
        let via = match sample.via {
            PingVia::Direct => "direct",
            PingVia::Relay => "relay",
            PingVia::Timeout => "timeout",
        };
        let ep = sample.endpoint.as_deref().unwrap_or("-");
        let rtt = sample
            .rtt_ms
            .map_or_else(|| "*".to_owned(), |ms| format!("{ms:.2} ms"));
        lines.push(format!(
            "  #{} via={} endpoint={} rtt={}",
            sample.seq, via, ep, rtt
        ));
    }
    if let (Some(min_ms), Some(avg_ms), Some(max_ms)) =
        (resp.rtt_min_ms, resp.rtt_avg_ms, resp.rtt_max_ms)
    {
        lines.push(format!(
            "RTT min/avg/max = {min_ms:.2} / {avg_ms:.2} / {max_ms:.2} ms"
        ));
    }
    lines.join("\r\n")
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mesh_core::{NodeId, NodeName, OverlayIp};
    use mesh_proto::agent_ipc::{
        ActivePathKind, AgentPeerStatus, PingResponse, PingSample, PingVia,
    };

    use super::{
        PeerFilterCounts, PeerFilterMode, count_peers_by_mode, filter_peers_by_mode,
        filter_peers_combined, format_human_bytes, format_peer_detail_summary,
        format_peer_list_entry, format_ping_response,
    };

    #[test]
    fn test_peers_view_empty_mode_counts_and_chip_labels() {
        // Arrange
        let empty = [];

        // Act
        let counts = count_peers_by_mode(&empty);

        // Assert
        assert_eq!(counts, PeerFilterCounts::default());
        for mode in [
            PeerFilterMode::All,
            PeerFilterMode::Online,
            PeerFilterMode::Direct,
            PeerFilterMode::Relay,
        ] {
            assert!(filter_peers_by_mode(&empty, mode).is_empty());
            assert!(filter_peers_combined(&empty, "", mode).is_empty());
            #[cfg(target_os = "windows")]
            assert!(super::format_filter_chip_label(mode, counts, None).ends_with("(0)"));
        }

        assert_eq!(format_human_bytes(1024), "1.0 KiB");
        if let (Ok(name), Ok(ip)) = (
            NodeName::parse("peer-test"),
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 22)),
        ) {
            let peer = AgentPeerStatus {
                node_id: NodeId::from_bytes([3_u8; 16]),
                name: name.clone(),
                fqdn: "peer-test.mesh.internal".to_owned(),
                overlay_ip: ip,
                online: true,
                active_path: ActivePathKind::Direct,
                direct_endpoint: Some("203.0.113.1:51820".to_owned()),
                rtt_ms: Some(9),
                last_handshake_at_ms: Some(1_700_000_000_000),
                rx_bytes: 512,
                tx_bytes: 1024,
            };
            assert!(format_peer_list_entry(&peer).contains("peer-test"));
            assert!(format_peer_detail_summary(&peer).contains("Direct P2P UDP"));
            let ping = PingResponse {
                target_name: name,
                target_overlay_ip: ip,
                samples: vec![PingSample {
                    seq: 1,
                    via: PingVia::Direct,
                    endpoint: Some("203.0.113.1:51820".to_owned()),
                    rtt_ms: Some(9.5),
                }],
                packets_sent: 1,
                packets_received: 1,
                loss_percent: 0.0,
                rtt_min_ms: Some(9.5),
                rtt_avg_ms: Some(9.5),
                rtt_max_ms: Some(9.5),
            };
            assert!(format_ping_response(&ping).contains("9.50"));
        }
    }
}
