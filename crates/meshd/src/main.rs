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

use clap::Parser;
use mesh_core::AppResult;
use tokio::runtime::Builder;

#[derive(Debug, Parser)]
#[command(name = "meshd", about = "Mesh VPN background agent daemon")]
struct DaemonArgs {
    /// Print initialized subsystem summary and exit without touching host interfaces.
    #[arg(long)]
    check_config: bool,
}

fn collect_subsystem_labels() -> Vec<String> {
    let cfg = config::BootstrapConfig::default();
    let base_labels = vec![
        format!("bootstrap:pins={}", cfg.pins.len()),
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

fn run_daemon(args: &DaemonArgs) -> AppResult<()> {
    let labels = collect_subsystem_labels();
    tracing::info!(
        component = "meshd",
        event = "daemon_bootstrap_check",
        subsystems = ?labels,
        check_only = args.check_config,
        "meshd subsystem workspace skeleton loaded"
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args = DaemonArgs::parse();
    let runtime = match Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(
                component = "meshd",
                event = "runtime_init_failed",
                error = %err,
                "failed to construct meshd Tokio runtime"
            );
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(async move { run_daemon(&args) }) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(
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
    use super::collect_subsystem_labels;

    #[test]
    fn test_meshd_subsystems_compile_cleanly() {
        // Arrange / Act
        let labels = collect_subsystem_labels();

        // Assert
        if cfg!(target_os = "windows") {
            assert_eq!(labels.len(), 8);
        } else {
            assert_eq!(labels.len(), 7);
        }
    }
}
