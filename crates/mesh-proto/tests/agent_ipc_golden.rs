//! Golden JSON fixture tests locking `mesh-proto::agent_ipc` backward compatibility (`ADR-024`, `US-101`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, Port, SpkiPin};
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentActionResponse, AgentPeerStatus, AgentResetIdentityRequest,
    AgentRotateKeyRequest, AgentSetRequest, AgentStatusResponse, AgentUpRequest,
    AgentVersionResponse, BugreportResponse, DaemonState, NetcheckResponse, PingRequest,
    PingResponse, PingSample, PingVia, SelfNetworkStatus, ServerConnectionStatus, TlsAuthMode,
};
use mesh_proto::netmap::{CandidateEndpoint, CandidateSource, NatMappingKind};

#[test]
fn test_agent_status_response_preserves_exact_13_fields_and_rejects_unknown_fields() {
    // Arrange
    let Ok(overlay_ip) = "100.115.0.2".parse::<OverlayIp>() else {
        assert!("100.115.0.2".parse::<OverlayIp>().is_ok());
        return;
    };
    let Ok(overlay_cidr) = "100.115.0.0/16".parse::<OverlayCidr>() else {
        assert!("100.115.0.0/16".parse::<OverlayCidr>().is_ok());
        return;
    };
    let Ok(node_name) = NodeName::parse("laptop-win") else {
        assert!(NodeName::parse("laptop-win").is_ok());
        return;
    };
    let Ok(peer_name) = NodeName::parse("peer-mac") else {
        assert!(NodeName::parse("peer-mac").is_ok());
        return;
    };
    let Ok(peer_ip) = "100.115.0.3".parse::<OverlayIp>() else {
        assert!("100.115.0.3".parse::<OverlayIp>().is_ok());
        return;
    };
    let pin = SpkiPin::from_sha256_bytes([0xaa_u8; 32]);
    let next_pin = SpkiPin::from_sha256_bytes([0xbb_u8; 32]);

    let status = AgentStatusResponse {
        daemon_state: DaemonState::Connected,
        node_id: Some(NodeId::from_bytes([0x11_u8; 16])),
        node_name: Some(node_name),
        fqdn: Some("laptop-win.mesh.internal".to_owned()),
        overlay_ip: Some(overlay_ip),
        overlay_cidr: Some(overlay_cidr),
        tun_interface_name: Some("MeshVPN".to_owned()),
        tun_mtu: 1280,
        netmap_version: 42,
        key_expires_at_ms: Some(1_800_000_000_000),
        server_connection: Some(ServerConnectionStatus {
            control_endpoint: "203.0.113.10:8443".to_owned(),
            relay_endpoint: "203.0.113.10:8443".to_owned(),
            stun_endpoints: vec!["203.0.113.10:3478".to_owned()],
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(pin),
            next_pin: Some(next_pin),
            control_connected: true,
            relay_connected: true,
            relay_rtt_ms: Some(18),
            migration_pending_endpoint: None,
            last_error: None,
        }),
        self_network: SelfNetworkStatus {
            local_udp_port: 51820,
            bound_physical_interface: Some("Ethernet".to_owned()),
            nat_type: NatMappingKind::EimOrAdm,
            nat_classification_note: Some("single STUN vantage".to_owned()),
            overlay_conflict_warning: None,
            macos_firewall_warning: None,
            candidates: vec![CandidateEndpoint {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51820),
                source: CandidateSource::Reflexive,
            }],
        },
        peers: vec![AgentPeerStatus {
            node_id: NodeId::from_bytes([0x22_u8; 16]),
            name: peer_name,
            fqdn: "peer-mac.mesh.internal".to_owned(),
            overlay_ip: peer_ip,
            online: true,
            active_path: ActivePathKind::Direct,
            direct_endpoint: Some("198.51.100.2:51820".to_owned()),
            rtt_ms: Some(12),
            last_handshake_at_ms: Some(1_799_999_990_000),
            rx_bytes: 1024,
            tx_bytes: 2048,
        }],
    };

    // Act
    let Ok(value) = serde_json::to_value(&status) else {
        assert!(serde_json::to_value(&status).is_ok());
        return;
    };
    let Ok(json_str) = serde_json::to_string(&status) else {
        assert!(serde_json::to_string(&status).is_ok());
        return;
    };
    let roundtrip = serde_json::from_str::<AgentStatusResponse>(&json_str);

    // Assert exact 13 top-level keys (preserves v0.1.0-rc1 deny_unknown_fields clients)
    let keys: Vec<&str> = value
        .as_object()
        .map(|obj| obj.keys().map(String::as_str).collect())
        .unwrap_or_default();
    assert_eq!(keys.len(), 13);
    assert_eq!(roundtrip.ok(), Some(status));

    if let Some(mut obj) = value.as_object().cloned() {
        obj.insert(
            "agent_version".to_owned(),
            serde_json::Value::String("0.3.0".to_owned()),
        );
        let injected = serde_json::Value::Object(obj).to_string();
        let rejected = serde_json::from_str::<AgentStatusResponse>(&injected);
        assert!(rejected.is_err());
    }
}

#[test]
fn test_agent_version_and_reset_identity_golden_json_contracts() {
    // Arrange
    let version_json = r#"{"agent_version":"0.3.0","protocol_version":1,"binary_name":"meshd"}"#;
    let reset_json = r#"{}"#;

    // Act
    let parsed_version = serde_json::from_str::<AgentVersionResponse>(version_json);
    let parsed_reset = serde_json::from_str::<AgentResetIdentityRequest>(reset_json);
    let unknown_version = serde_json::from_str::<AgentVersionResponse>(
        r#"{"agent_version":"0.3.0","protocol_version":1,"binary_name":"meshd","extra":true}"#,
    );
    let unknown_reset = serde_json::from_str::<AgentResetIdentityRequest>(r#"{"purge":true}"#);

    // Assert
    assert_eq!(
        parsed_version.as_ref().ok().map(|v| (
            v.agent_version.as_str(),
            v.protocol_version,
            v.binary_name.as_str()
        )),
        Some(("0.3.0", 1, "meshd"))
    );
    assert_eq!(parsed_reset.ok(), Some(AgentResetIdentityRequest {}));
    assert!(unknown_version.is_err());
    assert!(unknown_reset.is_err());
    assert_eq!(
        serde_json::to_string(&AgentResetIdentityRequest {}).ok(),
        Some("{}".to_owned())
    );
}

#[test]
fn test_agent_ipc_remaining_dtos_roundtrip_and_redact_secrets() {
    // Arrange
    let pin = SpkiPin::from_sha256_bytes([0xcd_u8; 32]);
    let Ok(port) = Port::from_u16(8443) else {
        assert!(Port::from_u16(8443).is_ok());
        return;
    };
    let Ok(node_name) = NodeName::parse("win-node") else {
        assert!(NodeName::parse("win-node").is_ok());
        return;
    };
    let Ok(peer_ip) = "100.115.0.5".parse::<OverlayIp>() else {
        assert!("100.115.0.5".parse::<OverlayIp>().is_ok());
        return;
    };

    let up_req = AgentUpRequest {
        server_endpoint: "203.0.113.10:8443".to_owned(),
        port_override: Some(port),
        server_pin: Some(pin),
        preauth_key: Some("mpk_golden_canary_secret_123456".to_owned()),
        node_name: Some(node_name.clone()),
    };
    let set_req = AgentSetRequest {
        server_endpoint: "vpn.example.com:8443".to_owned(),
        server_pin: None,
    };
    let rot_req = AgentRotateKeyRequest {
        preauth_key: "mpk_rotate_canary_secret_987654".to_owned(),
    };
    let ping_req = PingRequest {
        target: "peer-mac".to_owned(),
        count: 4,
        force_direct: false,
        timeout_ms: 2500,
    };
    let ping_resp = PingResponse {
        target_name: node_name,
        target_overlay_ip: peer_ip,
        samples: vec![PingSample {
            seq: 1,
            via: PingVia::Direct,
            endpoint: Some("198.51.100.2:51820".to_owned()),
            rtt_ms: Some(11.5),
        }],
        packets_sent: 1,
        packets_received: 1,
        loss_percent: 0.0,
        rtt_min_ms: Some(11.5),
        rtt_avg_ms: Some(11.5),
        rtt_max_ms: Some(11.5),
    };
    let netcheck_resp = NetcheckResponse {
        udp_egress_ok: true,
        stun_reachable: true,
        stun_endpoint_tested: Some("203.0.113.10:3478".to_owned()),
        reflexive_ipv4: Some("198.51.100.55:44001".to_owned()),
        ipv6_available: false,
        nat_mapping: NatMappingKind::EimOrAdm,
        nat_note: "ok".to_owned(),
        control_tcp_reachable: true,
        control_tcp_endpoint_tested: Some("203.0.113.10:8443".to_owned()),
        relay_rtt_ms: Some(21.0),
        diagnostic_hint: None,
    };
    let action_resp = AgentActionResponse {
        state: DaemonState::Stopped,
        message: "node identity reset cleanly; ready for enrollment".to_owned(),
    };
    let bugreport_resp = BugreportResponse {
        bundle_path: "/var/db/mesh/bugreports/mesh-bugreport.tar".to_owned(),
        size_bytes: 10240,
        scrubbed_items: 2,
    };

    // Act
    let up_dbg = format!("{up_req:?}");
    let rot_dbg = format!("{rot_req:?}");

    // Assert
    assert!(!up_dbg.contains("mpk_golden_canary_secret_123456"));
    assert!(up_dbg.contains("[REDACTED]"));
    assert!(!rot_dbg.contains("mpk_rotate_canary_secret_987654"));
    assert!(rot_dbg.contains("[REDACTED]"));

    assert_eq!(
        serde_json::to_string(&up_req)
            .ok()
            .and_then(|s| serde_json::from_str::<AgentUpRequest>(&s).ok()),
        Some(up_req)
    );
    assert_eq!(
        serde_json::to_string(&set_req)
            .ok()
            .and_then(|s| serde_json::from_str::<AgentSetRequest>(&s).ok()),
        Some(set_req)
    );
    assert_eq!(
        serde_json::to_string(&rot_req)
            .ok()
            .and_then(|s| serde_json::from_str::<AgentRotateKeyRequest>(&s).ok()),
        Some(rot_req)
    );
    assert_eq!(
        serde_json::to_string(&ping_req)
            .ok()
            .and_then(|s| serde_json::from_str::<PingRequest>(&s).ok()),
        Some(ping_req)
    );
    assert_eq!(
        serde_json::to_string(&ping_resp)
            .ok()
            .and_then(|s| serde_json::from_str::<PingResponse>(&s).ok()),
        Some(ping_resp)
    );
    assert_eq!(
        serde_json::to_string(&netcheck_resp)
            .ok()
            .and_then(|s| serde_json::from_str::<NetcheckResponse>(&s).ok()),
        Some(netcheck_resp)
    );
    assert_eq!(
        serde_json::to_string(&action_resp)
            .ok()
            .and_then(|s| serde_json::from_str::<AgentActionResponse>(&s).ok()),
        Some(action_resp)
    );
    assert_eq!(
        serde_json::to_string(&bugreport_resp)
            .ok()
            .and_then(|s| serde_json::from_str::<BugreportResponse>(&s).ok()),
        Some(bugreport_resp)
    );
}
