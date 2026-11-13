//! Control plane + Blind Relay + STUN + Obs + Admin IPC server binary (`mesh-server`).

mod acme;
mod admin_service;
mod alert_worker;
mod config;
mod control_handlers;
mod listener_set;
mod netmap_hub;
mod obs_service;
mod rate_limit;
mod relay_hub;
mod stun_service;

use clap::Parser;
use mesh_core::AppResult;
use tokio::runtime::Builder;

#[derive(Debug, Parser)]
#[command(
    name = "mesh-server",
    about = "Mesh VPN control, relay, and STUN server"
)]
struct CliArgs {
    /// Print initialized subsystem summary and exit without binding ports.
    #[arg(long)]
    check_config: bool,
}

fn collect_subsystem_labels() -> Vec<String> {
    let cfg = config::ServerConfig::default();
    vec![
        format!(
            "config:control={},stun={},obs={},cidr={}",
            cfg.control_tcp_port, cfg.stun_udp_port, cfg.obs_bind_addr, cfg.overlay_cidr
        ),
        listener_set::ListenerSet::status_label().to_owned(),
        acme::AcmeManager::status_label().to_owned(),
        rate_limit::RateLimiter::status_label().to_owned(),
        control_handlers::ControlRouter::status_label().to_owned(),
        netmap_hub::NetmapHub::status_label().to_owned(),
        relay_hub::RelayHub::status_label(),
        stun_service::StunService::status_label().to_owned(),
        admin_service::AdminService::status_label().to_owned(),
        obs_service::ObsService::status_label().to_owned(),
        alert_worker::AlertWorker::status_label().to_owned(),
    ]
}

fn run_server(args: &CliArgs) -> AppResult<()> {
    let labels = collect_subsystem_labels();
    tracing::info!(
        component = "mesh-server",
        event = "server_bootstrap_check",
        subsystems = ?labels,
        check_only = args.check_config,
        "mesh-server subsystem workspace skeleton loaded"
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args = CliArgs::parse();
    let runtime = match Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(
                component = "mesh-server",
                event = "runtime_init_failed",
                error = %err,
                "failed to construct Tokio runtime"
            );
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(async move { run_server(&args) }) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(
                component = "mesh-server",
                event = "server_exit_error",
                error = %err,
                "mesh-server exited with error"
            );
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::collect_subsystem_labels;

    #[test]
    fn test_mesh_server_subsystems_compile_cleanly() {
        // Arrange / Act
        let labels = collect_subsystem_labels();

        // Assert
        assert_eq!(labels.len(), 11);
    }
}
