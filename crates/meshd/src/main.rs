//! Privileged client agent daemon binary (`meshd`).

mod config;
mod control_loop;
mod ipc_service;
mod netmap_cache;
mod ping_probe;
mod roaming_loop;
#[cfg(target_os = "windows")]
mod service_windows;
mod supervisor;

use std::io::Write as _;
use std::sync::Arc;

use clap::Parser;
use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use mesh_core::clock::SystemClock;
use mesh_core::{AppError, AppResult, LoggingConfig, init_json_logging};

use config::{BootstrapStore, DaemonRuntimePaths};
use roaming_loop::create_platform_net_monitor;
use supervisor::{DaemonSupervisor, ProductionPlatformAdapters};

const DAEMON_WORKER_THREADS: usize = 2;
pub(crate) const DAEMON_MAX_BLOCKING_THREADS: usize = 32;
const DAEMON_THREAD_STACK_BYTES: usize = 512 * 1024;

#[derive(Debug, Parser)]
#[command(name = "meshd", version, about = "Mesh VPN background agent daemon")]
struct DaemonArgs {
    /// Validate bootstrap config and initialized subsystems without touching host interfaces.
    #[arg(long)]
    check_config: bool,
    /// Force foreground console execution instead of attaching to OS service managers.
    #[arg(long)]
    foreground: bool,
    /// Run explicitly as a Windows Service Control Manager (SCM) service (fail-closed outside SCM).
    #[arg(long, conflicts_with = "foreground")]
    service: bool,
}

fn collect_subsystem_labels() -> Vec<String> {
    let cfg = BootstrapStore::new(DaemonRuntimePaths::system_default().bootstrap_path);
    let base_labels = vec![
        format!("bootstrap_store:{}", cfg.path().display()),
        netmap_cache::NetmapCacheStore::status_label().to_owned(),
        supervisor::DaemonSupervisor::status_label(),
        control_loop::ControlLoop::status_label().to_owned(),
        roaming_loop::RoamingLoop::status_label().to_owned(),
        ipc_service::IpcService::status_label().to_owned(),
        ping_probe::PingProbe::status_label().to_owned(),
    ];
    #[cfg(target_os = "windows")]
    let labels = {
        let mut items = base_labels;
        items.push(service_windows::status_label());
        items
    };
    #[cfg(not(target_os = "windows"))]
    let labels = base_labels;
    labels
}

fn check_daemon_config(paths: &DaemonRuntimePaths) -> AppResult<()> {
    let store = BootstrapStore::new(paths.bootstrap_path.clone());
    let bootstrap = store.load_or_default()?;
    bootstrap.validate()?;
    let labels = collect_subsystem_labels();
    info!(
        component = "meshd",
        event = "daemon_bootstrap_check",
        subsystems = ?labels,
        has_server_endpoint = bootstrap.server_endpoint.is_some(),
        "meshd configuration and subsystems validated"
    );
    Ok(())
}

fn build_daemon_runtime() -> AppResult<tokio::runtime::Runtime> {
    Builder::new_multi_thread()
        .worker_threads(DAEMON_WORKER_THREADS)
        .max_blocking_threads(DAEMON_MAX_BLOCKING_THREADS)
        .thread_stack_size(DAEMON_THREAD_STACK_BYTES)
        .enable_all()
        .build()
        .map_err(|err| {
            AppError::internal(format!("failed constructing meshd Tokio runtime: {err}"))
        })
}

async fn wait_for_os_shutdown_signal(root_shutdown: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let term_res = signal(SignalKind::terminate());
        let int_res = signal(SignalKind::interrupt());
        match (term_res, int_res) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    () = root_shutdown.cancelled() => return,
                    _ = term.recv() => {
                        info!(
                            component = "meshd",
                            event = "sigterm_received",
                            "received SIGTERM; starting <= 5 s graceful shutdown"
                        );
                    }
                    _ = int.recv() => {
                        info!(
                            component = "meshd",
                            event = "sigint_received",
                            "received SIGINT; starting <= 5 s graceful shutdown"
                        );
                    }
                }
            }
            (Err(err), _) | (_, Err(err)) => {
                warn!(
                    component = "meshd",
                    event = "unix_signal_setup_failed",
                    error = %err,
                    "failed registering Unix SIGTERM/SIGINT handlers; waiting on ctrl_c"
                );
                tokio::select! {
                    () = root_shutdown.cancelled() => return,
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            () = root_shutdown.cancelled() => return,
            res = tokio::signal::ctrl_c() => {
                if let Err(err) = res {
                    warn!(
                        component = "meshd",
                        event = "ctrl_c_wait_failed",
                        error = %err,
                        "ctrl_c signal handler reported error"
                    );
                } else {
                    info!(
                        component = "meshd",
                        event = "ctrl_c_received",
                        "received Ctrl+C; starting <= 5 s graceful shutdown"
                    );
                }
            }
        }
    }

    root_shutdown.cancel();
}

fn run_foreground_daemon(paths: DaemonRuntimePaths) -> AppResult<()> {
    let runtime = build_daemon_runtime()?;
    runtime.block_on(async move {
        let adapters = Arc::new(ProductionPlatformAdapters::new(paths.wintun_sha256.clone()));
        let supervisor = DaemonSupervisor::boot(paths, Arc::new(SystemClock::new()), adapters)?;
        let (monitor, _power_tx) = create_platform_net_monitor();
        let root_shutdown = CancellationToken::new();
        let signal_shutdown = root_shutdown.clone();
        let (run_res, ()) = tokio::join!(
            supervisor.run(monitor, root_shutdown.clone()),
            wait_for_os_shutdown_signal(signal_shutdown),
        );
        run_res
    })
}

fn run_entry(args: &DaemonArgs) -> AppResult<()> {
    let paths = DaemonRuntimePaths::system_default();
    if args.check_config {
        return check_daemon_config(&paths);
    }

    #[cfg(target_os = "windows")]
    if args.service {
        return service_windows::run_as_service(&paths);
    }

    #[cfg(not(target_os = "windows"))]
    if args.service {
        warn!(
            component = "meshd",
            event = "service_flag_ignored",
            "ignoring --service flag on non-Windows host and running normal daemon loop"
        );
    }

    #[cfg(target_os = "windows")]
    if !args.foreground
        && service_windows::try_run_as_service(&paths)?
            == service_windows::ServiceDispatchOutcome::RanAsService
    {
        return Ok(());
    }

    run_foreground_daemon(paths)
}

fn main() -> std::process::ExitCode {
    let args = DaemonArgs::parse();
    let _log_guard = match init_json_logging(&LoggingConfig::for_component("meshd")) {
        Ok(guard) => guard,
        Err(err) => {
            let mut stderr = std::io::stderr().lock();
            if writeln!(stderr, "failed initializing meshd logging: {err}").is_err() {
                return std::process::ExitCode::FAILURE;
            }
            return std::process::ExitCode::FAILURE;
        }
    };

    match run_entry(&args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            error!(
                component = "meshd",
                event = "daemon_exit_error",
                error = %err,
                "meshd exited with error"
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use tempfile::TempDir;

    use crate::config::DaemonRuntimePaths;

    use super::{DaemonArgs, check_daemon_config, collect_subsystem_labels};

    #[test]
    fn test_meshd_subsystems_compile_cleanly() {
        // Arrange / Act
        let labels = collect_subsystem_labels();

        // Assert
        assert!(
            labels
                .iter()
                .any(|item| item.starts_with("bootstrap_store:"))
        );
        assert!(labels.iter().any(|item| item == "netmap_cache:ready"));
        assert!(
            labels
                .iter()
                .any(|item| item.starts_with("supervisor:ready"))
        );
        assert!(labels.iter().any(|item| item == "control_loop:ready"));
        assert!(labels.iter().any(|item| item == "roaming_loop:ready"));
        assert!(labels.iter().any(|item| item == "ipc_service:ready"));
        assert!(labels.iter().any(|item| item == "ping_probe:ready"));
    }

    #[test]
    fn test_meshd_check_config_validates_without_side_effects() {
        // Arrange
        let tmp = TempDir::new().expect("temp dir");
        let paths = DaemonRuntimePaths::for_temp_dir(tmp.path(), "check");

        // Act
        let result = check_daemon_config(&paths);

        // Assert
        assert!(result.is_ok(), "check-config failed: {result:?}");
        assert!(!paths.ledger_path.exists());
    }

    #[test]
    fn test_meshd_cli_flags_parse_expected_modes() {
        // Arrange / Act
        let args = DaemonArgs::try_parse_from(["meshd", "--check-config", "--foreground"])
            .expect("parse flags");

        // Assert
        assert!(args.check_config);
        assert!(args.foreground);
        assert!(!args.service);
    }

    #[test]
    fn test_meshd_version_flag_displays_bare_workspace_semver() {
        // Arrange & Act
        let res = DaemonArgs::try_parse_from(["meshd", "--version"]);

        // Assert
        match res {
            Err(err) => {
                assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
                let rendered = err.to_string();
                assert!(rendered.contains(env!("CARGO_PKG_VERSION")));
                assert_eq!(
                    rendered.trim(),
                    format!("meshd {}", env!("CARGO_PKG_VERSION"))
                );
            }
            Ok(parsed) => {
                assert!(!parsed.foreground, "expected --version to short-circuit");
            }
        }
    }

    #[test]
    fn test_meshd_service_flag_parses_and_conflicts_with_foreground() {
        // Arrange / Act
        let service_args =
            DaemonArgs::try_parse_from(["meshd", "--service"]).expect("parse --service");
        let conflict = DaemonArgs::try_parse_from(["meshd", "--service", "--foreground"]);

        // Assert
        assert!(service_args.service);
        assert!(!service_args.foreground);
        assert!(conflict.is_err());
        #[cfg(target_os = "windows")]
        assert_eq!(crate::service_windows::WINDOWS_SERVICE_NAME, "MeshVpnAgent");
    }

    #[test]
    fn test_meshd_runtime_initializes_platform_monitor_from_sync_main_thread() {
        // Arrange: start from a plain OS thread (no `#[tokio::test]` reactor on the caller thread)
        let tmp = TempDir::new().expect("temp dir");
        let paths = DaemonRuntimePaths::for_temp_dir(tmp.path(), "syncboot");
        let runtime = super::build_daemon_runtime().expect("build daemon runtime");

        // Act
        let boot_res = runtime.block_on(async move {
            let adapters =
                std::sync::Arc::new(crate::supervisor::InMemoryPlatformAdapters::default());
            let supervisor = super::DaemonSupervisor::boot(
                paths,
                std::sync::Arc::new(mesh_core::clock::SystemClock::new()),
                adapters,
            );
            let (_monitor, _power_tx) = super::create_platform_net_monitor();
            supervisor
        });

        // Assert
        assert!(
            boot_res.is_ok(),
            "supervisor boot inside runtime failed: {:?}",
            boot_res.err()
        );
    }
}
