//! Integration tests for WP-D-A1 (`US-101`, `ADR-024`, `HR-DGUI-G2-04`):
//! - `ClientStateStore::delete_identity` on `FileClientStateStore`
//! - `ClientSessionSupervisor::execute_reset_identity` clearing disk + RAM while keeping daemon alive
//! - `update_bootstrap_trust_preserving_next_pin` across `execute_up` (1-click reconnect) & `execute_set`

use std::fs;
use std::sync::Arc;

use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

use mesh_client::ClientRuntimeConfig;
use mesh_client::config::BootstrapConfig;
use mesh_client::hooks::{
    ClientPlatformHooks, ClientStateStore, FileClientStateStore, InMemoryClientPlatformHooks,
};
use mesh_client::netmap_cache::NetmapCacheFile;
use mesh_client::session::{
    ClientSessionOptions, ClientSessionSupervisor, update_bootstrap_trust_preserving_next_pin,
};
use mesh_core::clock::SystemClock;
use mesh_core::{NodeId, NodeName, OverlayIp, Port, SpkiPin};
use mesh_net::netmon::FakeNetMonitor;
use mesh_proto::agent_ipc::{AgentSetRequest, AgentUpRequest, DaemonState, TlsAuthMode};
use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};

#[tokio::test]
async fn test_file_backed_reset_identity_and_next_pin_preservation_e2e() -> Result<(), String> {
    // Arrange
    let dir = tempdir().map_err(|e| e.to_string())?;
    let hooks = Arc::new(InMemoryClientPlatformHooks::default());
    let store = Arc::new(FileClientStateStore::from_dir(dir.path().to_path_buf()));
    let now_ms = 1_700_000_000_000_u64;

    let _identity = store
        .load_or_create_identity(now_ms)
        .map_err(|e| e.to_string())?;
    let node_id = NodeId::new_v7(now_ms);
    let _saved_id = store
        .set_identity_node_id(node_id)
        .map_err(|e| e.to_string())?;

    let pin_active = SpkiPin::from_sha256_bytes([0x11_u8; 32]);
    let pin_next = SpkiPin::from_sha256_bytes([0x22_u8; 32]);
    let bootstrap = BootstrapConfig {
        node_id: Some(node_id),
        node_name: "win-node".parse::<NodeName>().ok(),
        overlay_ip: "100.115.0.8".parse::<OverlayIp>().ok(),
        server_endpoint: Some("203.0.113.10:8443".to_owned()),
        tls_auth_mode: TlsAuthMode::SpkiPin,
        active_pin: Some(pin_active),
        next_pin: Some(pin_next),
        ..BootstrapConfig::default()
    };
    store
        .save_bootstrap(&bootstrap)
        .map_err(|e| e.to_string())?;

    let snap = NetmapSnapshot {
        netmap_version: 3,
        generated_at_ms: now_ms,
        overlay_cidr: "100.115.0.0/16".parse().map_err(|e| format!("{e}"))?,
        domain_suffix: "mesh.internal".to_owned(),
        relay_map: RelayMap {
            endpoint_version: 1,
            control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
            relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
            stun_udp_endpoints: vec![],
        },
        pin_set: PinSetDto {
            active_pin: pin_active,
            next_pin: Some(pin_next),
        },
        peers: vec![PeerEntry {
            node_id: NodeId::new_v7(now_ms + 1),
            name: "peer-a".parse::<NodeName>().map_err(|e| format!("{e}"))?,
            fqdn: "peer-a.mesh.internal".to_owned(),
            overlay_ip: "100.115.0.9"
                .parse::<OverlayIp>()
                .map_err(|e| format!("{e}"))?,
            node_pubkey: mesh_crypto::NodeKeypair::generate().public_key(),
            disco_pubkey: mesh_crypto::DiscoKeypair::generate().public_key(),
            endpoints: vec![],
            relay_home: "203.0.113.10:8443".to_owned(),
            key_expires_at_ms: None,
            online: true,
        }],
    };
    let cache = NetmapCacheFile::new_signed(
        Port::from_u16(51820).map_err(|e| format!("{e}"))?,
        snap,
        now_ms,
        None,
    )
    .map_err(|e| format!("{e}"))?;
    store.save_netmap_cache(&cache).map_err(|e| e.to_string())?;

    // Also stage a stale `.tmp` file beside `keys.json`
    let stale_tmp = dir.path().join("keys.json.tmp.42424");
    fs::write(&stale_tmp, b"stale-temp-keys").map_err(|e| e.to_string())?;

    let mut supervisor = ClientSessionSupervisor::boot(
        ClientSessionOptions::new(ClientRuntimeConfig::for_desktop()),
        Arc::new(SystemClock::new()),
        Arc::clone(&hooks) as Arc<dyn ClientPlatformHooks>,
        Arc::clone(&store) as Arc<dyn ClientStateStore>,
    )
    .map_err(|e| e.to_string())?;

    // Act 1: 1-click reconnect `execute_up` + `execute_set` keep `next_pin` on disk
    let shutdown = CancellationToken::new();
    supervisor
        .execute_up(
            AgentUpRequest {
                server_endpoint: "203.0.113.10:8443".to_owned(),
                port_override: None,
                server_pin: Some(pin_active),
                preauth_key: None,
                node_name: None,
            },
            &shutdown,
        )
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        store.load_bootstrap().map_err(|e| e.to_string())?.next_pin,
        Some(pin_next)
    );

    supervisor
        .execute_set(AgentSetRequest {
            server_endpoint: "203.0.113.10:8443".to_owned(),
            server_pin: Some(pin_active),
        })
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        store.load_bootstrap().map_err(|e| e.to_string())?.next_pin,
        Some(pin_next)
    );

    // Promote next_pin via execute_set -> becomes active_pin, next_pin cleared
    let mut promoted_cfg = store.load_bootstrap().map_err(|e| e.to_string())?;
    update_bootstrap_trust_preserving_next_pin(
        &mut promoted_cfg,
        "203.0.113.10:8443",
        TlsAuthMode::SpkiPin,
        Some(pin_next),
        false,
    );
    assert_eq!(promoted_cfg.active_pin, Some(pin_next));
    assert_eq!(promoted_cfg.next_pin, None);

    // Act 2: execute_reset_identity removes keys.json, keys.json.tmp.*, netmap-cache.json, and resets bootstrap.toml
    let reset_resp = supervisor
        .execute_reset_identity()
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(reset_resp.state, DaemonState::Stopped);
    assert!(!dir.path().join("keys.json").exists());
    assert!(!stale_tmp.exists());
    assert!(!dir.path().join("netmap-cache.json").exists());
    assert_eq!(
        store.load_bootstrap().map_err(|e| e.to_string())?,
        BootstrapConfig::default()
    );

    // Act 3: supervisor loop remains alive after reset-identity
    let run_shutdown = CancellationToken::new();
    let runtime = supervisor.runtime_state();
    let sup_task =
        tokio::spawn(supervisor.run(Arc::new(FakeNetMonitor::new()), run_shutdown.clone()));
    let status = runtime.build_status_response().await;
    assert_eq!(status.daemon_state, DaemonState::Stopped);
    assert_eq!(status.node_id, None);
    assert!(status.peers.is_empty());
    run_shutdown.cancel();
    let _done = sup_task.await;
    Ok(())
}
