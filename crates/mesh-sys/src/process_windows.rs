//! Windows Explorer double-click detection and detached GUI launcher (`ADR-022`, `US-100`).

use std::path::Path;

use crate::error::{SysError, SysResult};

/// Returns `true` only when the current Windows console process was launched directly by
/// interactive Windows Explorer double-click:
/// 1. `GetConsoleProcessList == 1` (not launched inside an existing shell/terminal),
/// 2. Parent PID creation time strictly precedes self creation time (anti-PID-reuse),
/// 3. Parent image path matches `<WindowsDir>\explorer.exe` case-insensitively.
pub fn is_interactive_explorer_double_click() -> SysResult<bool> {
    // Compile-green stub locked by WP-D-A0; full Win32 implementation is owned by WP-D-A2.
    Ok(false)
}

/// Spawns the Windows GUI executable (`MeshVPN.exe`) detached from any console
/// (`CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`) without invoking any shell (`ADR-022`).
pub fn spawn_detached_gui(exe_path: &Path) -> SysResult<()> {
    if exe_path.as_os_str().is_empty() {
        return Err(SysError::io(
            "process_windows::spawn_detached_gui",
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty GUI executable path",
            ),
        ));
    }
    Err(SysError::NotImplemented(
        "process_windows::spawn_detached_gui",
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::error::SysError;

    use super::{is_interactive_explorer_double_click, spawn_detached_gui};

    #[test]
    fn test_process_windows_stub_signatures_reject_empty_path() {
        // Arrange & Act
        let explorer = is_interactive_explorer_double_click();
        let empty_spawn = spawn_detached_gui(Path::new(""));

        // Assert
        assert!(matches!(explorer, Ok(false)));
        assert!(matches!(empty_spawn, Err(SysError::Io { .. })));
    }
}
