//! Peer table filtering, human byte formatting, and Disco ping output formatting (`US-106`).

use mesh_proto::agent_ipc::{ActivePathKind, AgentPeerStatus, PingResponse, PingVia};

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
