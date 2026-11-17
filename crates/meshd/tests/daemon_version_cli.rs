//! Integration tests verifying `meshd --version` output and `LegacyPre030` probe contract (`ADR-024`, `US-101`).

use std::process::Command;

use mesh_net::ipc::{AgentVersionStatus, classify_cli_version_probe_exit_code};

#[test]
fn test_meshd_binary_version_flag_outputs_workspace_semver() -> Result<(), String> {
    // Arrange
    let bin = env!("CARGO_BIN_EXE_meshd");

    // Act
    let output = Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|err| format!("failed spawning meshd --version: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let probe = classify_cli_version_probe_exit_code(output.status.code(), &stdout)
        .map_err(|err| format!("version probe failed: {err}"))?;

    // Assert
    assert!(output.status.success());
    assert_eq!(
        stdout.trim(),
        format!("meshd {}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        probe,
        AgentVersionStatus::Version(env!("CARGO_PKG_VERSION").to_owned())
    );
    Ok(())
}
