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

#[cfg(target_os = "windows")]
fn is_env_flag_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|val| !val.is_empty())
}

#[cfg(any(target_os = "windows", test))]
const fn should_attempt_explorer_autolaunch(
    argc: usize,
    stdin_tty: bool,
    stdout_tty: bool,
    stderr_tty: bool,
    ci_set: bool,
    no_autolaunch_set: bool,
) -> bool {
    argc == 1 && stdin_tty && stdout_tty && stderr_tty && !ci_set && !no_autolaunch_set
}

#[cfg(target_os = "windows")]
fn try_windows_explorer_gui_autolaunch() -> bool {
    use std::io::IsTerminal as _;

    // Condition (i): 0-arg, interactive TTY on stdin/stdout/stderr, and no CI/opt-out env vars.
    let argc = std::env::args_os().count();
    let stdin_tty = std::io::stdin().is_terminal();
    let stdout_tty = std::io::stdout().is_terminal();
    let stderr_tty = std::io::stderr().is_terminal();
    let ci_set = is_env_flag_set("CI");
    let no_autolaunch_set = is_env_flag_set("MESH_NO_GUI_AUTOLAUNCH");
    if !should_attempt_explorer_autolaunch(
        argc,
        stdin_tty,
        stdout_tty,
        stderr_tty,
        ci_set,
        no_autolaunch_set,
    ) {
        return false;
    }

    // Condition (ii): launched directly via interactive Windows Explorer double-click.
    if !matches!(
        mesh_sys::process_windows::is_interactive_explorer_double_click(),
        Ok(true)
    ) {
        return false;
    }

    // Condition (iii): valid MeshVPN.exe exists next to mesh.exe or in %ProgramFiles%\Mesh\.
    let Some(gui_exe) = client_cmds::find_windows_gui_executable() else {
        return false;
    };

    mesh_sys::process_windows::spawn_detached_gui(&gui_exe).is_ok()
}

#[cfg(not(target_os = "windows"))]
const fn try_windows_explorer_gui_autolaunch() -> bool {
    false
}

fn main() -> ExitCode {
    if try_windows_explorer_gui_autolaunch() {
        return ExitCode::SUCCESS;
    }
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
    use super::{collect_subsystem_labels, should_attempt_explorer_autolaunch};

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

    #[test]
    fn test_explorer_autolaunch_condition_requires_zero_arg_tty_and_no_optout() {
        // Arrange / Act / Assert
        assert!(should_attempt_explorer_autolaunch(
            1, true, true, true, false, false
        ));
        assert!(!should_attempt_explorer_autolaunch(
            2, true, true, true, false, false
        ));
        assert!(!should_attempt_explorer_autolaunch(
            1, false, true, true, false, false
        ));
        assert!(!should_attempt_explorer_autolaunch(
            1, true, false, true, false, false
        ));
        assert!(!should_attempt_explorer_autolaunch(
            1, true, true, false, false, false
        ));
        assert!(!should_attempt_explorer_autolaunch(
            1, true, true, true, true, false
        ));
        assert!(!should_attempt_explorer_autolaunch(
            1, true, true, true, false, true
        ));
    }
}
