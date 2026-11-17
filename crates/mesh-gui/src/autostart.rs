//! HKCU per-user autostart command formatting (`US-103`, `US-107`, `ADR-026`).

use std::path::Path;

/// Registry value name under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
pub(crate) const AUTOSTART_REG_VALUE_NAME: &str = "MeshVPN";

/// Formats the canonical `--minimized` autostart command stored in `HKCU\...\Run\MeshVPN`.
#[must_use]
pub(crate) fn format_autostart_command_line(exe_path: &Path) -> String {
    format!("\"{}\" --minimized", exe_path.display())
}
