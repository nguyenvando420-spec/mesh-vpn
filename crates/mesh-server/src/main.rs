//! Mesh Control, Blind Relay, and STUN server binary entrypoint (`WP-S1-01`).

pub mod acme;
pub mod admin_service;
pub mod alert_worker;
pub mod config;
pub mod control_handlers;
pub mod listener_set;
pub mod netmap_hub;
pub mod obs_service;
pub mod rate_limit;
pub mod relay_hub;
pub mod stun_service;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use mesh_core::defaults::GRACEFUL_SHUTDOWN_BUDGET_MS;
use mesh_core::{AppResult, LoggingConfig, init_json_logging};
use mesh_store::{ControlStore, ControlStoreConfig};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::acme::AcmeManager;
use crate::admin_service::{AdminAppState, start_admin_ipc_listener};
use crate::alert_worker::{AlertEvaluator, run_background_maintenance};
use crate::config::ServerConfig;
use crate::control_handlers::{ControlAppState, PendingChallengeStore};
use crate::listener_set::ListenerSet;
use crate::netmap_hub::NetmapHub;
use crate::obs_service::{ObsAppState, start_obs_listener};
use crate::rate_limit::{ClientIpExtractor, RateLimiter};
use crate::relay_hub::RelayHub;
use crate::stun_service::StunServiceState;

#[derive(Debug, Parser)]
#[command(
    name = "mesh-server",
    version,
    about = "Mesh VPN Control, Blind Relay, and STUN server"
)]
struct ServerCliArgs {
    /// Optional path to `mesh-server` TOML configuration file.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Override persistent storage directory (`control.redb`, backups, emergency log).
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// Validate configuration invariants and exit cleanly without binding sockets.
    #[arg(long)]
    check_config: bool,
}

fn main() -> ExitCode {
    let args = ServerCliArgs::parse();
    let mut cfg = match &args.config {
        Some(path) => match ServerConfig::load_from_toml(path) {
            Ok(c) => c,
            Err(err) => {
                tracing::error!(component = "mesh-server", event = "config_load_failed", error = %err);
                return ExitCode::FAILURE;
            }
        },
        None => ServerConfig::default(),
    };
    if let Some(dir) = args.state_dir {
        cfg.state_dir = dir;
    }
    if let Err(err) = cfg.validate() {
        tracing::error!(component = "mesh-server", event = "config_validation_failed", error = %err);
        return ExitCode::FAILURE;
    }
    if args.check_config {
        return ExitCode::SUCCESS;
    }

    let _log_guard = match init_json_logging(&LoggingConfig::for_component("mesh-server")) {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(component = "mesh-server", event = "logging_init_failed", error = %err);
            return ExitCode::FAILURE;
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(component = "mesh-server", event = "tokio_runtime_failed", error = %err);
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(run_server(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(component = "mesh-server", event = "server_fatal", error = %err);
            ExitCode::FAILURE
        }
    }
}

async fn run_server(cfg: ServerConfig) -> AppResult<()> {
    crate::acme::ensure_rustls_ring_provider();
    let config = Arc::new(cfg);
    let store = Arc::new(ControlStore::open_with_clock(
        ControlStoreConfig {
            db_path: config.db_path(),
            emergency_revocations_path: config.emergency_revocations_path(),
        },
        &config.overlay_cidr,
        Arc::new(mesh_core::SystemClock::new()),
    )?);

    let acme = AcmeManager::initialize(&config, Arc::clone(&store))?;
    let trusted_proxies = Arc::new(config.trusted_proxy_set());
    let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
        config.tls_mode,
        (*trusted_proxies).clone(),
    )));
    let challenges = Arc::new(PendingChallengeStore::new());
    let netmap_hub = Arc::new(NetmapHub::new(
        Arc::clone(&store),
        config.public_control_endpoint(),
        config.public_control_endpoint(),
        vec![config.public_stun_endpoint()],
        config.domain_suffix.clone(),
    ));
    let relay_hub = Arc::new(RelayHub::new(
        Arc::clone(&store),
        config.relay_bytes_per_sec,
        config.relay_global_bytes_per_sec,
    ));

    let tracker = TaskTracker::new();
    let shutdown = CancellationToken::new();

    let control_state = ControlAppState {
        config: Arc::clone(&config),
        trusted_proxies,
        store: Arc::clone(&store),
        rate_limiter: Arc::clone(&rate_limiter),
        challenges: Arc::clone(&challenges),
        netmap_hub: Arc::clone(&netmap_hub),
        relay_hub: Arc::clone(&relay_hub),
        ws_tracker: tracker.clone(),
        shutdown: shutdown.clone(),
    };
    let listeners = ListenerSet::bind_and_start(control_state, Arc::clone(&acme)).await?;

    let obs_state = ObsAppState {
        store: Arc::clone(&store),
        listeners: Arc::clone(&listeners),
        netmap_hub: Arc::clone(&netmap_hub),
        relay_hub: Arc::clone(&relay_hub),
        challenges,
        rate_limiter,
    };
    let obs_addr: std::net::SocketAddr = config
        .obs_bind_addr
        .parse()
        .map_err(|_| mesh_core::AppError::invalid_argument("invalid obs_bind_addr"))?;
    let _bound_obs =
        start_obs_listener(obs_addr, obs_state.clone(), &tracker, shutdown.clone()).await?;

    let admin_state = AdminAppState {
        config: Arc::clone(&config),
        store: Arc::clone(&store),
        acme: Arc::clone(&acme),
        listeners,
        netmap_hub: Arc::clone(&netmap_hub),
        relay_hub: Arc::clone(&relay_hub),
    };
    start_admin_ipc_listener(admin_state, &tracker, shutdown.clone()).await?;

    let evaluator = Arc::new(
        AlertEvaluator::new(
            config.alert_webhook_url.clone(),
            config.relay_alert_threshold_pct,
            config.relay_global_bytes_per_sec,
        )
        .with_telegram_chat_id(config.alert_telegram_chat_id.clone())
        .with_disk_threshold(config.disk_alert_threshold_pct),
    );
    let maint_ctx = alert_worker::MaintenanceContext {
        store,
        acme,
        netmap_hub,
        relay_hub,
        obs_state,
        evaluator,
        cancel: shutdown.clone(),
    };
    tracker.spawn(async move {
        run_background_maintenance(maint_ctx).await;
    });

    tracing::info!(
        component = "mesh-server",
        event = "server_started",
        control_port = config.control_tcp_port,
        stun_port = config.stun_udp_port,
        tls_mode = config.tls_mode.as_str(),
        "mesh-server started cleanly"
    );

    wait_for_shutdown_signal().await;
    tracing::info!(
        component = "mesh-server",
        event = "server_shutdown_requested",
        "initiating graceful shutdown"
    );
    shutdown.cancel();
    tracker.close();
    if timeout(
        Duration::from_millis(GRACEFUL_SHUTDOWN_BUDGET_MS),
        tracker.wait(),
    )
    .await
    .is_err()
    {
        tracing::warn!(
            component = "mesh-server",
            event = "shutdown_timeout_exceeded",
            budget_ms = GRACEFUL_SHUTDOWN_BUDGET_MS,
            "graceful shutdown exceeded 5s budget"
        );
    }
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term_stream = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(ref mut s) = term_stream {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(
                component = "mesh-server",
                event = "ctrl_c_listen_failed",
                error = %err,
                "failed listening for ctrl-c shutdown signal"
            );
        }
    }
}

/// Collects non-empty readiness labels across all `mesh-server` subsystems (`WP-S1-00`).
#[must_use]
pub fn collect_subsystem_labels() -> Vec<&'static str> {
    vec![
        config::ServerConfig::default().public_host_label(),
        listener_set::ListenerSet::status_label(),
        acme::AcmeManager::status_label(),
        rate_limit::RateLimiter::status_label(),
        control_handlers::ControlAppState::status_label(),
        netmap_hub::NetmapHub::status_label(),
        relay_hub::RelayHub::status_label(),
        StunServiceState::status_label(),
        admin_service::AdminAppState::status_label(),
        obs_service::status_label(),
        alert_worker::AlertEvaluator::status_label(),
    ]
}

trait ServerConfigLabelExt {
    fn public_host_label(&self) -> &'static str;
}

impl ServerConfigLabelExt for ServerConfig {
    fn public_host_label(&self) -> &'static str {
        "server_config:ready"
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mesh_core::{Clock as _, FakeClock, SystemClock};
    use mesh_proto::control::RegisterNodeRequest;
    use mesh_proto::netmap::PinSetDto;
    use mesh_store::{ControlStore, ControlStoreConfig};
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::collect_subsystem_labels;
    use crate::acme::AcmeManager;
    use crate::config::ServerConfig;
    use crate::control_handlers::{ControlAppState, PendingChallengeStore};
    use crate::listener_set::ListenerSet;
    use crate::netmap_hub::NetmapHub;
    use crate::obs_service::{ObsAppState, render_prometheus_metrics};
    use crate::rate_limit::{ClientIpExtractor, RateLimiter};
    use crate::relay_hub::RelayHub;

    #[test]
    fn test_mesh_server_subsystems_compile_cleanly() {
        // Arrange & Act
        let labels = collect_subsystem_labels();

        // Assert
        assert_eq!(labels.len(), 11);
        assert!(labels.iter().all(|label| !label.is_empty()));
    }

    #[tokio::test]
    async fn test_no_secrets_in_outputs() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock,
            )
            .expect("open store"),
        );

        let tcp_p = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let udp_p = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp");
        let tcp_port = tcp_p.local_addr().expect("addr").port();
        let udp_port = udp_p.local_addr().expect("addr").port();
        drop((tcp_p, udp_p));

        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: tcp_port,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: udp_port,
            ..ServerConfig::default()
        });
        let acme = AcmeManager::initialize(&cfg, store.clone()).expect("acme");
        let id = store.load_active_identity().expect("active identity");
        let pin_set: PinSetDto = id.to_pin_set_dto(now_ms);
        assert_eq!(pin_set.active_pin, id.spki_pin);

        // Act: format Debug representations across store, identity, config, metrics & DTOs
        let id_debug = format!("{id:?}");
        let store_debug = format!("{store:?}");
        let reg_req = RegisterNodeRequest {
            node_pubkey: mesh_core::PublicKey::from_bytes([0x11_u8; 32]).expect("pk"),
            disco_pubkey: mesh_core::PublicKey::from_bytes([0x12_u8; 32]).expect("dpk"),
            preauth_key: "mpk_SuperSecretPreauthTokenShouldBeRedactedHere".to_owned(),
            node_name: mesh_core::NodeName::parse("laptop").expect("name"),
            previous_node_pubkey: None,
        };
        let req_debug = format!("{reg_req:?}");

        let tracker = TaskTracker::new();
        let shutdown = CancellationToken::new();
        let netmap_hub = Arc::new(NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            cfg.trusted_proxy_set(),
        )));
        let challenges = Arc::new(PendingChallengeStore::new());
        let listeners = ListenerSet::bind_and_start(
            ControlAppState {
                config: cfg,
                trusted_proxies: Arc::new(Default::default()),
                store: store.clone(),
                rate_limiter: rate_limiter.clone(),
                challenges: challenges.clone(),
                netmap_hub: netmap_hub.clone(),
                relay_hub: relay_hub.clone(),
                ws_tracker: tracker.clone(),
                shutdown: shutdown.clone(),
            },
            acme,
        )
        .await
        .expect("bind");
        let metrics_text = render_prometheus_metrics(&ObsAppState {
            store,
            listeners,
            netmap_hub,
            relay_hub,
            challenges,
            rate_limiter,
        });

        // Assert: zero secret leaks in Debug or Prometheus outputs (`SEC-01`)
        assert!(id_debug.contains("[REDACTED]"));
        assert!(!id_debug.contains("BEGIN PRIVATE KEY"));
        assert!(!store_debug.contains("BEGIN PRIVATE KEY"));
        assert!(!req_debug.contains("SuperSecretPreauthToken"));
        assert!(req_debug.contains("[REDACTED]"));
        assert!(!metrics_text.contains("mpk_"));
        assert!(!metrics_text.contains("BEGIN PRIVATE KEY"));

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }
}
