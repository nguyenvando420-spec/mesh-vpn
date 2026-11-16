//! Unified CLI binary (`mesh`) orchestrating client (`meshd-ro`/`meshd-admin`) and
//! server-admin (`/run/mesh-server/admin.sock`) subcommands (`WP-S1-05`).

mod admin_cmds;
mod cli;
mod client_cmds;
mod output;
mod qr;

use std::process::ExitCode;

use clap::Parser;
use mesh_core::AppResult;
use tokio::runtime::Builder;

use admin_cmds::{AdminDispatchConfig, handle_admin_command};
use cli::{Cli, TopCommand};
use client_cmds::{ClientDispatchConfig, handle_client_command};
use output::write_stderr;

#[cfg(test)]
fn collect_subsystem_labels() -> Vec<&'static str> {
    vec![
        cli::status_label(),
        client_cmds::status_label(),
        admin_cmds::status_label(),
        output::status_label(),
    ]
}

async fn dispatch_cli(parsed: Cli) -> AppResult<()> {
    match parsed.command {
        TopCommand::Client(cmd) => {
            let cfg = ClientDispatchConfig {
                json: parsed.json,
                ro_ipc_override: parsed.ro_ipc,
                admin_ipc_override: parsed.admin_ipc,
            };
            handle_client_command(&cmd, &cfg).await
        }
        TopCommand::Admin(cmd) => {
            let cfg = AdminDispatchConfig {
                json: parsed.json,
                server_admin_socket_override: parsed.server_admin_socket,
            };
            handle_admin_command(&cmd, &cfg).await
        }
    }
}

fn main() -> ExitCode {
    let parsed = Cli::parse();
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            if write_stderr(&format!(
                "error: failed constructing mesh CLI runtime: {err}"
            ))
            .is_err()
            {
                return ExitCode::FAILURE;
            }
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(dispatch_cli(parsed)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if write_stderr(&format!("error: {err}")).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::collect_subsystem_labels;

    #[test]
    fn test_mesh_cli_subsystems_compile_cleanly() {
        // Arrange / Act
        let labels = collect_subsystem_labels();

        // Assert
        assert_eq!(
            labels,
            vec![
                "cli:ready",
                "client_cmds:ready",
                "admin_cmds:ready",
                "output:ready",
            ]
        );
    }
}
