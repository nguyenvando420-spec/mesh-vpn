//! Independent Sprint 2 Process E2E & AppSec Tests for the `mesh` CLI binary.
//!
//! Covers:
//! - `US-001`, `US-003 AC6`, `US-004 AC1`, `SEC-01` & `SEC-04`: Rejection of `--authkey` on CLI
//!   argv (process listing leak prevention) and strict zero-TOFU `--server-pin` enforcement when
//!   `--server` is an IP address on both `mesh up` and `mesh set`
//! - `US-023`, `US-032`, `US-041`, `US-045`, `US-054` & `US-074`: Sprint 2 subcommand `--help`
//!   matrix (`set`, `rotate-key`, `bugreport`, `netcheck`, `cleanup`, `server backup`,
//!   `server restore`, `server migrate-endpoint`, `server rotate-tls-key`, `node revoke`,
//!   `node expire`, `audit`) and argument validation
//! - `US-039`, `US-040`, `US-055` & `SEC-01`: Clean actionable error output (zero panic, zero
//!   secret leakage) when `meshd-ro` or `meshd-admin` IPC is unreachable

#[cfg(test)]
mod tests {
    use std::process::{Command, Output};

    fn run_mesh_cli(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mesh"))
            .args(args)
            .output()
            .expect("spawn mesh CLI binary")
    }

    #[test]
    fn test_cli_e2e_rejects_raw_authkey_argv_and_enforces_ip_server_pin_zero_tofu() {
        // Arrange / Act 1: Passing `--authkey` on argv must be rejected by Clap (`SEC-01`, `US-004 AC1`)
        let raw_authkey_out = run_mesh_cli(&[
            "up",
            "--server",
            "203.0.113.10:8443",
            "--authkey",
            "mpk_secret_should_never_be_accepted_on_argv",
        ]);
        assert!(!raw_authkey_out.status.success());
        let stderr_auth = String::from_utf8_lossy(&raw_authkey_out.stderr);
        assert!(stderr_auth.contains("--authkey"));

        // Act 2: `mesh up --server 203.0.113.10:8443` without `--server-pin` must fail closed (`SEC-04`, `US-003 AC6`)
        let missing_pin_up = run_mesh_cli(&["up", "--server", "203.0.113.10:8443"]);
        assert!(!missing_pin_up.status.success());
        let stderr_up = String::from_utf8_lossy(&missing_pin_up.stderr);
        assert!(
            stderr_up.contains("--server-pin"),
            "mesh up with IP endpoint must require --server-pin (zero TOFU), got: {stderr_up}"
        );

        // Act 3: `mesh up --server 203.0.113.10:8443 --ca-tls` with an IP must also fail closed (`SEC-04`)
        let ip_ca_tls_up = run_mesh_cli(&["up", "--server", "203.0.113.10:8443", "--ca-tls"]);
        assert!(!ip_ca_tls_up.status.success());

        // Act 4: `mesh set --server 203.0.113.10:8443` without `--server-pin` must fail closed (`US-023`)
        let missing_pin_set = run_mesh_cli(&["set", "--server", "203.0.113.10:8443"]);
        assert!(!missing_pin_set.status.success());
        let stderr_set = String::from_utf8_lossy(&missing_pin_set.stderr);
        assert!(stderr_set.contains("--server-pin"));
    }

    #[test]
    fn test_cli_e2e_subcommand_help_matrix_and_argument_validation() {
        // Arrange: All Sprint 1 + Sprint 2 client and server-admin subcommands
        let help_commands: &[&[&str]] = &[
            &["--help"],
            &["status", "--help"],
            &["peers", "--help"],
            &["ping", "--help"],
            &["netcheck", "--help"],
            &["up", "--help"],
            &["down", "--help"],
            &["cleanup", "--help"],
            &["set", "--help"],
            &["rotate-key", "--help"],
            &["bugreport", "--help"],
            &["preauthkey", "create", "--help"],
            &["node", "revoke", "--help"],
            &["node", "expire", "--help"],
            &["audit", "--help"],
            &["server", "backup", "--help"],
            &["server", "restore", "--help"],
            &["server", "migrate-endpoint", "--help"],
            &["server", "rotate-tls-key", "--help"],
        ];

        // Act & Assert 1: Every subcommand `--help` exits 0 and emits usage text
        for cmd in help_commands {
            let out = run_mesh_cli(cmd);
            assert!(
                out.status.success(),
                "`mesh {}` failed with stderr: {}",
                cmd.join(" "),
                String::from_utf8_lossy(&out.stderr)
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("Usage:"));
        }

        // Act & Assert 2: Invalid node name or port is rejected before touching IPC
        let bad_name = run_mesh_cli(&[
            "up",
            "--server",
            "203.0.113.10:8443",
            "--server-pin",
            &format!("sha256:{}", "a".repeat(64)),
            "--name",
            "localhost",
        ]);
        assert!(!bad_name.status.success());
    }

    #[test]
    fn test_cli_e2e_unreachable_ipc_returns_clean_actionable_error_without_panic() {
        // Arrange
        let nonexistent_ro = if cfg!(windows) {
            r"\\.\pipe\mesh-qa-nonexistent-ro-pipe"
        } else {
            "/tmp/mesh-qa-nonexistent-ro.sock"
        };

        // Act: Run read-only commands against an unreachable IPC endpoint
        for subcmd in ["status", "peers", "netcheck"] {
            let out = run_mesh_cli(&["--json", "--ro-ipc", nonexistent_ro, subcmd]);

            // Assert: Non-zero exit code, actionable error message, zero Rust panic, zero secrets
            assert!(!out.status.success());
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(!combined.contains("panicked at"));
            assert!(!combined.contains("PRIVATE KEY"));
            assert!(
                combined.contains("meshd")
                    || combined.contains("daemon")
                    || combined.contains("IPC"),
                "error output for `{subcmd}` must mention meshd/daemon/IPC, got: {combined}"
            );
        }
    }
}
