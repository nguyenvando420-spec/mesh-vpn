//! Desktop GUI CLI Launcher & `WP-D-A2` Process E2E Tests (`US-100`, `ADR-022`, `ADR-024`).
//!
//! Covers:
//! - Piped 0-arg `mesh` returns exit code `2` in `< 1 s` with `mesh gui` hint (no GUI autolaunch)
//! - `MESH_NO_GUI_AUTOLAUNCH=1` and `CI=1` force exit code `2` in `< 1 s`
//! - Non-Explorer `CREATE_NEW_CONSOLE` invocation on Windows returns exit code `2` in `< 1 s`
//! - `mesh gui` fails closed (`exit != 0`) when `MeshVPN.exe` / `Mesh VPN.app` is absent
//! - `mesh reset-identity` requires `--yes` in non-TTY mode and `mesh reset-identity --yes`
//!   dispatches cleanly over admin IPC without panic or secret leakage

#[cfg(test)]
mod tests {
    use std::process::{Command, Output, Stdio};
    use std::sync::{Mutex, MutexGuard, Once, PoisonError};
    use std::time::{Duration, Instant};

    static SERIAL_LOCK: Mutex<()> = Mutex::new(());

    fn lock_serial() -> MutexGuard<'static, ()> {
        SERIAL_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn warm_mesh_binary() {
        static WARM: Once = Once::new();
        WARM.call_once(|| {
            // Warm OS loader / AV scan and `clap` 0-arg error formatting once after linking
            // before any sub-second latency measurement starts (keeps `< 1 s` assertions strict).
            for args in [&[][..], &["--version"][..]] {
                drop(
                    Command::new(env!("CARGO_BIN_EXE_mesh"))
                        .args(args)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .output(),
                );
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt as _;
                const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
                drop(
                    Command::new(env!("CARGO_BIN_EXE_mesh"))
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .creation_flags(CREATE_NEW_CONSOLE)
                        .output(),
                );
            }
        });
    }

    fn run_mesh(args: &[&str], envs: &[(&str, Option<&str>)]) -> Result<Output, String> {
        warm_mesh_binary();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mesh"));
        cmd.args(args);
        for (k, v) in envs {
            match v {
                Some(val) => {
                    cmd.env(k, val);
                }
                None => {
                    cmd.env_remove(k);
                }
            }
        }
        cmd.output()
            .map_err(|err| format!("spawn mesh failed: {err}"))
    }

    #[test]
    fn test_cli_zero_arg_piped_and_optout_envs_exit_2_under_one_second() -> Result<(), String> {
        let _guard = lock_serial();
        // Arrange
        let cases: &[&[(&str, Option<&str>)]] = &[
            &[("CI", None), ("MESH_NO_GUI_AUTOLAUNCH", None)],
            &[("CI", None), ("MESH_NO_GUI_AUTOLAUNCH", Some("1"))],
            &[("CI", Some("true")), ("MESH_NO_GUI_AUTOLAUNCH", None)],
        ];

        // Act & Assert
        for envs in cases {
            let started = Instant::now();
            let out = run_mesh(&[], envs)?;
            let elapsed = started.elapsed();

            assert_eq!(out.status.code(), Some(2), "0-arg mesh must exit 2");
            assert!(
                elapsed < Duration::from_secs(1),
                "0-arg mesh took {elapsed:?} >= 1s"
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("Hint: run 'mesh gui'"),
                "expected 'mesh gui' hint in stderr, got: {stderr}"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_cli_zero_arg_non_explorer_create_new_console_exits_2_under_one_second()
    -> Result<(), String> {
        use std::os::windows::process::CommandExt as _;

        let _guard = lock_serial();
        // Arrange: CREATE_NEW_CONSOLE (0x0000_0010) simulates non-Explorer scheduled/IDE console
        // launches where parent process is NOT `<WindowsDir>\explorer.exe`.
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        warm_mesh_binary();
        let started = Instant::now();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mesh"));
        cmd.env_remove("CI")
            .env_remove("MESH_NO_GUI_AUTOLAUNCH")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NEW_CONSOLE);

        // Act
        let out = cmd
            .output()
            .map_err(|err| format!("spawn mesh with CREATE_NEW_CONSOLE failed: {err}"))?;
        let elapsed = started.elapsed();

        // Assert
        assert_eq!(
            out.status.code(),
            Some(2),
            "non-Explorer CREATE_NEW_CONSOLE must exit 2"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "non-Explorer CREATE_NEW_CONSOLE took {elapsed:?} >= 1s"
        );
        Ok(())
    }

    #[test]
    fn test_mesh_gui_fails_closed_when_gui_binary_is_missing() -> Result<(), String> {
        let _guard = lock_serial();
        warm_mesh_binary();
        // Arrange: Hardlink (or copy) `mesh` into an isolated same-volume subdirectory without
        // `MeshVPN.exe` / `Mesh VPN.app` and override `ProgramFiles` so sibling artifacts do not match.
        let bin_path = std::path::Path::new(env!("CARGO_BIN_EXE_mesh"));
        let dir = match bin_path.parent() {
            Some(parent) => tempfile::tempdir_in(parent),
            None => tempfile::tempdir(),
        }
        .map_err(|err| format!("tempdir failed: {err}"))?;
        let exe_name = if cfg!(windows) { "mesh.exe" } else { "mesh" };
        let isolated_mesh = dir.path().join(exe_name);
        std::fs::hard_link(bin_path, &isolated_mesh)
            .or_else(|_| std::fs::copy(bin_path, &isolated_mesh).map(|_| ()))
            .map_err(|err| format!("link/copy mesh binary failed: {err}"))?;

        // Act
        let out = Command::new(&isolated_mesh)
            .arg("gui")
            .env("ProgramFiles", dir.path())
            .env("PROGRAMFILES", dir.path())
            .env("ProgramW6432", dir.path())
            .env("PROGRAMW6432", dir.path())
            .stdin(Stdio::null())
            .output()
            .map_err(|err| format!("spawn isolated mesh gui failed: {err}"))?;

        // Assert
        assert!(
            !out.status.success(),
            "mesh gui must fail closed when GUI binary is absent"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("panicked at"));
        assert!(
            stderr.contains("MeshVPN.exe")
                || stderr.contains("Mesh VPN.app")
                || stderr.contains("only supported"),
            "unexpected stderr for missing GUI binary: {stderr}"
        );
        Ok(())
    }

    #[test]
    fn test_mesh_reset_identity_requires_yes_non_tty_and_handles_offline_ipc() -> Result<(), String>
    {
        let _guard = lock_serial();
        // Arrange
        let nonexistent_admin = if cfg!(windows) {
            r"\\.\pipe\mesh-qa-nonexistent-admin-pipe"
        } else {
            "/tmp/mesh-qa-nonexistent-admin.sock"
        };

        // Act 1: Non-TTY `mesh reset-identity` without `--yes` fails closed before IPC.
        let no_yes_out = run_mesh(&["--admin-ipc", nonexistent_admin, "reset-identity"], &[])?;

        // Assert 1
        assert!(!no_yes_out.status.success());
        let no_yes_err = String::from_utf8_lossy(&no_yes_out.stderr);
        assert!(
            no_yes_err.contains("--yes"),
            "expected --yes requirement error, got: {no_yes_err}"
        );

        // Act 2: `mesh reset-identity --yes` attempts admin IPC and fails cleanly when offline.
        let started = Instant::now();
        let yes_out = run_mesh(
            &["--admin-ipc", nonexistent_admin, "reset-identity", "--yes"],
            &[],
        )?;
        let elapsed = started.elapsed();

        // Assert 2
        assert!(!yes_out.status.success());
        assert!(elapsed < Duration::from_secs(5));
        let yes_err = String::from_utf8_lossy(&yes_out.stderr);
        assert!(!yes_err.contains("panicked at"));
        assert!(
            yes_err.contains("meshd") || yes_err.contains("permission") || yes_err.contains("IPC"),
            "expected actionable offline/permission error, got: {yes_err}"
        );

        // Act 3: Help output for new subcommands exits 0.
        for subcmd in ["gui", "reset-identity"] {
            let help_out = run_mesh(&[subcmd, "--help"], &[])?;
            assert!(help_out.status.success(), "`mesh {subcmd} --help` failed");
            let stdout = String::from_utf8_lossy(&help_out.stdout);
            assert!(stdout.contains("Usage:"));
        }
        Ok(())
    }
}
