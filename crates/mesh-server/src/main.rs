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

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use mesh_core::defaults::GRACEFUL_SHUTDOWN_BUDGET_MS;
use mesh_core::{AppError, AppResult, Clock, LoggingConfig, SystemClock, init_json_logging};
use mesh_store::{ControlStore, ControlStoreConfig, RestoreOutcome};
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
    /// Perform an offline/cold restore from a verified `.redb` snapshot (with `.sha256` sidecar) and exit.
    #[arg(long, value_name = "PATH", conflicts_with = "check_config")]
    restore_from: Option<PathBuf>,
    /// Require restored snapshot watermark to be at least `<U64>` (fail closed if older).
    #[arg(long, value_name = "U64", requires = "restore_from")]
    min_netmap_version: Option<u64>,
    /// Explicitly allow changing the active SPKI pin (or restoring a snapshot lacking `server_identity`).
    #[arg(long, requires = "restore_from")]
    allow_pin_change: bool,
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

    if let Some(snapshot_path) = &args.restore_from {
        return handle_offline_restore_cli(
            &cfg,
            snapshot_path,
            args.min_netmap_version,
            args.allow_pin_change,
        );
    }

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

fn handle_offline_restore_cli(
    cfg: &ServerConfig,
    snapshot_path: &Path,
    min_required_snapshot_version: Option<u64>,
    allow_pin_change: bool,
) -> ExitCode {
    match run_offline_restore_with_clock(
        cfg,
        Arc::new(SystemClock::new()),
        snapshot_path,
        min_required_snapshot_version,
        allow_pin_change,
    ) {
        Ok(outcome) => {
            let pin_label = outcome
                .restored_spki_pin
                .map_or_else(|| "none".to_owned(), |pin| pin.to_string());
            tracing::info!(
                component = "mesh-server",
                event = "offline_restore_completed",
                state_dir = %cfg.state_dir.display(),
                restored_spki_pin = %pin_label,
                new_netmap_watermark = outcome.new_netmap_watermark,
                verified_sha256_hex = %outcome.verified_sha256_hex,
                "offline restore completed cleanly"
            );
            match format_offline_restore_json(cfg, &outcome).and_then(|s| write_stdout_line(&s)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    tracing::error!(
                        component = "mesh-server",
                        event = "offline_restore_output_failed",
                        error = %err
                    );
                    ExitCode::FAILURE
                }
            }
        }
        Err(err) => {
            tracing::error!(
                component = "mesh-server",
                event = "offline_restore_failed",
                state_dir = %cfg.state_dir.display(),
                error = %err,
                "offline restore failed"
            );
            ExitCode::FAILURE
        }
    }
}

fn run_offline_restore_with_clock(
    cfg: &ServerConfig,
    clock: Arc<dyn Clock>,
    snapshot_path: &Path,
    min_required_snapshot_version: Option<u64>,
    allow_pin_change: bool,
) -> AppResult<RestoreOutcome> {
    let store_cfg = ControlStoreConfig {
        db_path: cfg.db_path(),
        emergency_revocations_path: cfg.emergency_revocations_path(),
    };
    ControlStore::restore_offline_with_clock(
        store_cfg,
        clock,
        snapshot_path,
        min_required_snapshot_version,
        allow_pin_change,
    )
}

fn format_offline_restore_json(cfg: &ServerConfig, outcome: &RestoreOutcome) -> AppResult<String> {
    let payload = serde_json::json!({
        "status": "restored",
        "state_dir": cfg.state_dir,
        "db_path": cfg.db_path(),
        "verified_sha256_hex": outcome.verified_sha256_hex,
        "restored_spki_pin": outcome.restored_spki_pin.map(|pin| pin.to_string()),
        "new_netmap_watermark": outcome.new_netmap_watermark,
    });
    serde_json::to_string(&payload).map_err(|err| {
        AppError::internal(format!("failed serializing offline restore JSON: {err}"))
    })
}

fn write_stdout_line(line: &str) -> AppResult<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "{line}")
        .and_then(|()| handle.flush())
        .map_err(|err| AppError::internal(format!("failed writing stdout: {err}")))
}

async fn run_server(mut cfg: ServerConfig) -> AppResult<()> {
    crate::acme::ensure_rustls_ring_provider();
    if (cfg!(target_os = "macos") || cfg!(windows))
        && cfg.state_dir == Path::new("/var/lib/mesh")
        && let Err(err) = std::fs::create_dir_all(&cfg.state_dir)
        && matches!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::NotFound
                | std::io::ErrorKind::ReadOnlyFilesystem
        )
    {
        let fallback_dir = PathBuf::from("./mesh-server-data");
        tracing::warn!(
            component = "mesh-server",
            event = "state_dir_fallback",
            configured = %cfg.state_dir.display(),
            fallback = %fallback_dir.display(),
            error = %err,
            "default state_dir unavailable without root privileges; using local fallback directory"
        );
        cfg.state_dir = fallback_dir;
    }
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

    let active_spki_pin = acme
        .status()
        .map_or_else(|| "none".to_owned(), |s| s.active_pin.to_string());
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
        spki_pin = %active_spki_pin,
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

    fn init_server_state_with_identity(
        state_dir: &std::path::Path,
        clock: Arc<FakeClock>,
    ) -> (ServerConfig, mesh_core::SpkiPin, u64) {
        let cfg = ServerConfig {
            state_dir: state_dir.to_path_buf(),
            ..ServerConfig::default()
        };
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: cfg.db_path(),
                    emergency_revocations_path: cfg.emergency_revocations_path(),
                },
                &cfg.overlay_cidr,
                Arc::clone(&clock) as Arc<dyn mesh_core::Clock>,
            )
            .expect("open control store"),
        );
        let _acme = AcmeManager::initialize(&cfg, Arc::clone(&store)).expect("init identity");
        let pin = store.load_active_identity().expect("active id").spki_pin;
        let wm = store.current_netmap_version();
        drop(store);
        (cfg, pin, wm)
    }

    #[test]
    fn test_cli_offline_restore_flags_require_restore_from() {
        // Arrange & Act (`HR-G3-04`)
        use clap::Parser as _;

        let missing_base_ver =
            super::ServerCliArgs::try_parse_from(["mesh-server", "--min-netmap-version", "42"]);
        let missing_base_pin =
            super::ServerCliArgs::try_parse_from(["mesh-server", "--allow-pin-change"]);
        let valid_args = super::ServerCliArgs::try_parse_from([
            "mesh-server",
            "--state-dir",
            "/tmp/mesh-state",
            "--restore-from",
            "/tmp/snap.redb",
            "--min-netmap-version",
            "100",
            "--allow-pin-change",
        ]);

        // Assert
        assert!(missing_base_ver.is_err());
        assert!(missing_base_pin.is_err());
        let parsed = valid_args.expect("valid offline restore flags");
        assert_eq!(
            parsed.restore_from,
            Some(std::path::PathBuf::from("/tmp/snap.redb"))
        );
        assert_eq!(parsed.min_netmap_version, Some(100));
        assert!(parsed.allow_pin_change);
    }

    fn create_prod_backup(
        base_dir: &std::path::Path,
        base_ms: u64,
    ) -> (mesh_core::SpkiPin, u64, mesh_store::BackupArtifact) {
        let prod_clock = Arc::new(FakeClock::new(base_ms));
        let prod_dir = base_dir.join("prod");
        let (prod_cfg, pin_prod, src_wm) =
            init_server_state_with_identity(&prod_dir, Arc::clone(&prod_clock));
        let store_prod = ControlStore::open_with_clock(
            ControlStoreConfig {
                db_path: prod_cfg.db_path(),
                emergency_revocations_path: prod_cfg.emergency_revocations_path(),
            },
            &prod_cfg.overlay_cidr,
            Arc::clone(&prod_clock) as Arc<dyn mesh_core::Clock>,
        )
        .expect("reopen prod store");
        let backup_dir = base_dir.join("backups");
        let artifact = store_prod
            .create_backup(&backup_dir, "operator")
            .expect("create prod backup");
        drop(store_prod);
        (pin_prod, src_wm, artifact)
    }

    #[test]
    fn test_offline_restore_empty_state_dir_and_corrupt_redb() {
        // Arrange (`HR-G3-04`)
        let dir = TempDir::new().expect("tempdir");
        let base_ms = 1_750_000_000_000_u64;
        let (pin_prod, src_wm, artifact) = create_prod_backup(dir.path(), base_ms);

        // Act 1: empty state_dir succeeds preserving Pin_PROD and emits non-secret JSON
        let empty_cfg = ServerConfig {
            state_dir: dir.path().join("empty-target"),
            ..ServerConfig::default()
        };
        let empty_outcome = super::run_offline_restore_with_clock(
            &empty_cfg,
            Arc::new(FakeClock::new(base_ms + 500)),
            &artifact.snapshot_path,
            Some(src_wm),
            false,
        )
        .expect("restore onto empty state_dir");
        let empty_json =
            super::format_offline_restore_json(&empty_cfg, &empty_outcome).expect("format json");

        // Assert 1
        assert_eq!(empty_outcome.restored_spki_pin, Some(pin_prod));
        assert!(empty_json.contains(&pin_prod.to_string()));
        assert!(!empty_json.contains("BEGIN PRIVATE KEY"));
        let reopened_empty = ControlStore::open(ControlStoreConfig {
            db_path: empty_cfg.db_path(),
            emergency_revocations_path: empty_cfg.emergency_revocations_path(),
        })
        .expect("open restored empty store");
        assert_eq!(
            reopened_empty
                .load_active_identity()
                .expect("restored id")
                .spki_pin,
            pin_prod
        );
        drop(reopened_empty);

        // Act 2: corrupt control.redb overwritten cleanly & watermark advances >= +1_000_000
        let corrupt_cfg = ServerConfig {
            state_dir: dir.path().join("corrupt-target"),
            ..ServerConfig::default()
        };
        std::fs::create_dir_all(&corrupt_cfg.state_dir).expect("mkdir corrupt state_dir");
        std::fs::write(corrupt_cfg.db_path(), b"corrupt").expect("write corrupt redb");
        let corrupt_clock_ms = base_ms + 2_000;
        let corrupt_outcome = super::run_offline_restore_with_clock(
            &corrupt_cfg,
            Arc::new(FakeClock::new(corrupt_clock_ms)),
            &artifact.snapshot_path,
            None,
            false,
        )
        .expect("restore over corrupt redb");

        // Assert 2
        assert_eq!(corrupt_outcome.restored_spki_pin, Some(pin_prod));
        assert!(corrupt_outcome.new_netmap_watermark >= src_wm.max(corrupt_clock_ms) + 1_000_000);
        let reopened_corrupt = ControlStore::open(ControlStoreConfig {
            db_path: corrupt_cfg.db_path(),
            emergency_revocations_path: corrupt_cfg.emergency_revocations_path(),
        })
        .expect("open restored corrupt store");
        assert_eq!(
            reopened_corrupt
                .load_active_identity()
                .expect("restored corrupt id")
                .spki_pin,
            pin_prod
        );
    }

    #[test]
    fn test_offline_restore_rejects_bad_sha256_and_mismatched_pin_without_override() {
        // Arrange (`HR-G3-04`)
        let dir = TempDir::new().expect("tempdir");
        let base_ms = 1_750_000_000_000_u64;
        let (pin_prod, _src_wm, artifact) = create_prod_backup(dir.path(), base_ms);

        // Act 1: tampered .sha256 sidecar fails closed without creating control.redb
        let bad_snap = dir.path().join("bad-copy.redb");
        let mut bad_sha_os = bad_snap.as_os_str().to_os_string();
        bad_sha_os.push(".sha256");
        std::fs::copy(&artifact.snapshot_path, &bad_snap).expect("copy snap");
        std::fs::write(
            std::path::PathBuf::from(bad_sha_os),
            format!("{}  bad-copy.redb\n", "0".repeat(64)),
        )
        .expect("write bad sha256");
        let bad_sha_cfg = ServerConfig {
            state_dir: dir.path().join("bad-sha-target"),
            ..ServerConfig::default()
        };
        let bad_sha_res = super::run_offline_restore_with_clock(
            &bad_sha_cfg,
            Arc::new(FakeClock::new(base_ms + 3_000)),
            &bad_snap,
            None,
            false,
        );

        // Assert 1
        assert!(bad_sha_res.is_err());
        assert!(!bad_sha_cfg.db_path().exists());

        // Act 2: healthy existing DB with different pin fails closed unless --allow-pin-change
        let other_dir = dir.path().join("healthy-other-pin");
        let (other_cfg, pin_other, _) =
            init_server_state_with_identity(&other_dir, Arc::new(FakeClock::new(base_ms + 4_000)));
        assert_ne!(pin_other, pin_prod);
        let pin_mismatch_err = super::run_offline_restore_with_clock(
            &other_cfg,
            Arc::new(FakeClock::new(base_ms + 5_000)),
            &artifact.snapshot_path,
            None,
            false,
        )
        .expect_err("different active pin must fail closed without --allow-pin-change");

        // Assert 2a: refused cleanly
        assert_eq!(pin_mismatch_err.kind(), mesh_core::ErrorKind::Conflict);

        // Act 2b: with --allow-pin-change, pin rotation succeeds cleanly
        let allowed_outcome = super::run_offline_restore_with_clock(
            &other_cfg,
            Arc::new(FakeClock::new(base_ms + 6_000)),
            &artifact.snapshot_path,
            None,
            true,
        )
        .expect("offline restore with --allow-pin-change");
        assert_eq!(allowed_outcome.restored_spki_pin, Some(pin_prod));
    }
}
