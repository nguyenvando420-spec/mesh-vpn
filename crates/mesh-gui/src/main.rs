//! Native Win32 Desktop GUI & System Tray client for Mesh VPN (`MeshVPN.exe`, `ADR-020`).
//!
//! Enforces strict privilege separation (`asInvoker` unprivileged UI + `--elevated-worker`
//! ephemeral `MGH1` Named Pipe handoff), zero `unsafe` (`workspace = true`), and zero secret
//! exposure outside `mesh-crypto` / `mesh_net::gui_handoff`.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
mod app;
#[cfg(target_os = "windows")]
mod autostart;
#[cfg(target_os = "windows")]
mod clipboard;
#[cfg(target_os = "windows")]
mod diagnostics_view;
#[cfg(target_os = "windows")]
mod elevation_worker;
#[cfg(target_os = "windows")]
mod icons;
#[cfg(target_os = "windows")]
mod ipc_poller;
#[cfg(target_os = "windows")]
mod onboarding;
#[cfg(target_os = "windows")]
mod peers_view;
#[cfg(target_os = "windows")]
mod single_instance;
#[cfg(target_os = "windows")]
mod tray;
#[cfg(target_os = "windows")]
mod window;

#[cfg(target_os = "windows")]
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "windows")]
use mesh_core::logging::{LogGuard, LoggingConfig, init_json_logging};

#[cfg(target_os = "windows")]
use crate::app::gui_log_directory;
#[cfg(target_os = "windows")]
use crate::elevation_worker::{GuiLaunchMode, parse_gui_launch_args, run_elevated_worker_mode};
#[cfg(target_os = "windows")]
use crate::window::run_gui_entrypoint;

#[cfg(target_os = "windows")]
const GUI_LOG_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
#[cfg(target_os = "windows")]
const GUI_LOG_MAX_TOTAL_BYTES: u64 = 20 * 1024 * 1024;

#[cfg(target_os = "windows")]
fn init_gui_logging(is_worker: bool) -> Option<LogGuard> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let log_dir = gui_log_directory(local_app_data.as_deref());
    let (component, file_prefix) = if is_worker {
        ("mesh-gui-worker", "meshvpn-worker")
    } else {
        ("mesh-gui", "meshvpn-gui")
    };
    let mut cfg = LoggingConfig::for_component(component);
    cfg.log_dir = log_dir;
    cfg.file_prefix = file_prefix.to_owned();
    cfg.max_file_bytes = GUI_LOG_MAX_FILE_BYTES;
    cfg.max_total_bytes = GUI_LOG_MAX_TOTAL_BYTES;
    match init_json_logging(&cfg) {
        Ok(guard) => Some(guard),
        Err(_) => {
            cfg.log_dir = None;
            init_json_logging(&cfg).ok()
        }
    }
}

fn main() -> ExitCode {
    #[cfg(not(target_os = "windows"))]
    {
        tracing::info!(
            component = "mesh-gui",
            event = "non_windows_stub_exit",
            "MeshVPN.exe native Win32 GUI is supported only on Windows targets"
        );
        ExitCode::SUCCESS
    }

    #[cfg(target_os = "windows")]
    {
        let mode = match parse_gui_launch_args(std::env::args()) {
            Ok(parsed) => parsed,
            Err(err) => {
                let _guard = init_gui_logging(false);
                tracing::error!(
                    component = "mesh-gui",
                    event = "invalid_cli_args",
                    error = %err,
                    "rejecting invalid command-line arguments"
                );
                return ExitCode::from(2);
            }
        };

        match mode {
            GuiLaunchMode::ElevatedWorker { handoff_pipe } => {
                let _log_guard = init_gui_logging(true);
                match run_elevated_worker_mode(&handoff_pipe) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(err) => {
                        let safe = app::sanitize_gui_log_text(&err);
                        tracing::error!(
                            component = "mesh-gui-worker",
                            event = "elevated_worker_failed",
                            error = %safe,
                            "elevated handoff worker exited with error"
                        );
                        ExitCode::from(1)
                    }
                }
            }
            GuiLaunchMode::Normal { start_minimized } => {
                let _log_guard = init_gui_logging(false);
                match run_gui_entrypoint(start_minimized) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(err) => {
                        let safe = app::sanitize_gui_log_text(&err);
                        tracing::error!(
                            component = "mesh-gui",
                            event = "gui_entrypoint_failed",
                            error = %safe,
                            "MeshVPN GUI terminated with error"
                        );
                        ExitCode::from(1)
                    }
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use std::fs;
    use std::path::Path;

    use mesh_net::gui_handoff::generate_handoff_pipe_name;
    use tempfile::tempdir;

    use crate::app::{
        DerivedUiSnapshot, DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState,
        derive_desktop_ui_state,
    };
    use crate::clipboard::ClipboardSecretGuard;
    use crate::elevation_worker::{
        GuiLaunchMode, parse_gui_launch_args, parse_sha256_sidecar_hex,
        resolve_expected_wintun_sha256, resolve_program_files_mesh_dir, verify_wintun_path_sha256,
    };
    use crate::ipc_poller::{
        DASHBOARD_POLL_INTERVAL_MS, PollingControl, TRAY_IDLE_POLL_INTERVAL_MS,
        next_poll_interval_ms,
    };
    use crate::tray::{
        IDM_TOGGLE_AUTOSTART, TrayMenuItemModel, build_tray_menu_model, count_non_separator_entries,
    };

    #[test]
    fn test_worker_cli_args_and_wintun_preflight_verification() {
        assert_eq!(
            parse_gui_launch_args(["MeshVPN.exe".to_owned(), "--minimized".to_owned()]),
            Ok(GuiLaunchMode::Normal {
                start_minimized: true
            })
        );
        let pipe = generate_handoff_pipe_name();
        assert_eq!(
            parse_gui_launch_args([
                "MeshVPN.exe".to_owned(),
                "--elevated-worker".to_owned(),
                "--pipe".to_owned(),
                pipe.clone()
            ]),
            Ok(GuiLaunchMode::ElevatedWorker { handoff_pipe: pipe })
        );
        assert!(parse_gui_launch_args(["MeshVPN.exe".to_owned(), "--bogus".to_owned()]).is_err());

        let Ok(dir) = tempdir() else {
            return;
        };
        let dll = dir.path().join("wintun.dll");
        let sidecar = dir.path().join("wintun.dll.sha256");
        assert!(fs::write(&dll, b"fake-wintun-binary-bytes").is_ok());
        let expected_hex = mesh_crypto::sha256_hex(b"fake-wintun-binary-bytes");
        assert!(fs::write(&sidecar, format!("{expected_hex}  wintun.dll\n")).is_ok());

        assert_eq!(
            parse_sha256_sidecar_hex(&format!("{expected_hex}  wintun.dll")),
            Ok(expected_hex.clone())
        );
        // Fresh untrusted install MUST reject missing MESH_WINTUN_SHA256 even if sidecar exists.
        assert!(resolve_expected_wintun_sha256(None, &sidecar, false).is_err());
        // Start-only already-installed fallback accepts admin-protected sidecar
        assert_eq!(
            resolve_expected_wintun_sha256(None, &sidecar, true),
            Ok(expected_hex.clone())
        );
        // Disagreement between sidecar and MESH_WINTUN_SHA256 fails closed
        let wrong_hex = "a".repeat(64);
        assert!(resolve_expected_wintun_sha256(Some(&wrong_hex), &sidecar, false).is_err());
        assert_eq!(
            resolve_expected_wintun_sha256(Some(&expected_hex), &sidecar, false),
            Ok(expected_hex.clone())
        );
        assert!(verify_wintun_path_sha256(&dll, &expected_hex).is_ok());
        assert!(verify_wintun_path_sha256(&dll, &wrong_hex).is_err());
        assert_eq!(
            resolve_program_files_mesh_dir(Some(Path::new(r"C:\Program Files"))),
            Path::new(r"C:\Program Files\Mesh")
        );
    }

    #[test]
    fn test_tray_9_item_menu_and_polling_suspension_guard() {
        let snapshot: DerivedUiSnapshot = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.3.0",
            service_probe: ServiceProbeKind::Stopped,
            ipc_connected: false,
            status: None,
            version_status: None,
            ipc_error: None,
            active_action_error: None,
        });
        assert_eq!(snapshot.ui_state, DesktopUiState::ServiceStopped);
        assert_eq!(snapshot.tunnel_sub_state, TunnelSubState::NotEnrolled);

        let menu = build_tray_menu_model(&snapshot, Some("100.64.0.2"), true);
        assert_eq!(count_non_separator_entries(&menu), 9);
        assert!(menu.iter().any(|entry| matches!(
            entry,
            TrayMenuItemModel::Action {
                id,
                checked: true,
                ..
            } if *id == IDM_TOGGLE_AUTOSTART
        )));

        assert_eq!(next_poll_interval_ms(true), DASHBOARD_POLL_INTERVAL_MS);
        assert_eq!(next_poll_interval_ms(false), TRAY_IDLE_POLL_INTERVAL_MS);
        let ctrl = PollingControl::new(true);
        assert!(!ctrl.is_paused());
        assert!(ctrl.dashboard_visible());
        {
            let _guard = ctrl.suspend();
            assert!(ctrl.is_paused());
        }
        assert!(!ctrl.is_paused());

        let mut clip = ClipboardSecretGuard::arm(77, "mpk_bin_test_guard");
        assert!(clip.is_armed());
        assert_eq!(clip.expected_seq(), 77);
        assert!(clip.evaluate_clear(77, Some("mpk_bin_test_guard")));
        clip.disarm();
        assert!(!clip.is_armed());
    }
}
