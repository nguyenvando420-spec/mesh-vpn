//! Unified CLI binary (`mesh`) dispatching client daemon and server administration commands.

mod admin_cmds;
mod cli;
mod client_cmds;
mod output;

use clap::Parser;
use mesh_core::AppResult;
use tokio::runtime::Builder;

use crate::cli::{Cli, TopCommand};
use crate::output::CommandResultView;

fn dispatch_command(cli: &Cli) -> AppResult<CommandResultView> {
    match &cli.command {
        TopCommand::Status => client_cmds::run_ro_query("status", None),
        TopCommand::Peers => client_cmds::run_ro_query("peers", None),
        TopCommand::Ping { target } => client_cmds::run_ro_query("ping", Some(target)),
        TopCommand::Netcheck => client_cmds::run_ro_query("netcheck", None),
        TopCommand::Up { server } => client_cmds::run_admin_mutation("up", server.as_deref()),
        TopCommand::Down => client_cmds::run_admin_mutation("down", None),
        TopCommand::Set => client_cmds::run_admin_mutation("set", None),
        TopCommand::RotateKey => client_cmds::run_admin_mutation("rotate-key", None),
        TopCommand::Cleanup => client_cmds::run_admin_mutation("cleanup", None),
        TopCommand::Bugreport => client_cmds::run_admin_mutation("bugreport", None),
        TopCommand::Preauthkey { action } => admin_cmds::run_preauthkey(action),
        TopCommand::Node { action } => admin_cmds::run_node(action),
        TopCommand::Server { action } => admin_cmds::run_server(action),
        TopCommand::Backup => admin_cmds::run_maintenance("backup", None),
        TopCommand::Restore { path } => admin_cmds::run_maintenance("restore", Some(path)),
        TopCommand::HardeningCheck => admin_cmds::run_maintenance("hardening-check", None),
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            let app_err = mesh_core::AppError::internal(format!(
                "failed to construct CLI Tokio runtime: {err}"
            ));
            let _write_ignored = output::write_error(&app_err, cli.json);
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(async { dispatch_command(&cli) }) {
        Ok(view) => {
            if output::write_success(&view, cli.json).is_err() {
                return std::process::ExitCode::FAILURE;
            }
            std::process::ExitCode::SUCCESS
        }
        Err(err) => {
            let _write_ignored = output::write_error(&err, cli.json);
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::Cli;
    use crate::dispatch_command;

    #[test]
    fn test_cli_parses_kebab_flags_and_json_flag() {
        // Arrange
        let parsed = Cli::try_parse_from(["mesh", "--json", "hardening-check"]);

        // Act / Assert
        let cli = match parsed {
            Ok(c) => c,
            Err(err) => {
                assert_eq!(err.to_string(), "cli parse failed");
                return;
            }
        };
        assert!(cli.json);
        assert!(dispatch_command(&cli).is_err());
    }
}
