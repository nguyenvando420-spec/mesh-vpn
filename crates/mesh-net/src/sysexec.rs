//! Strict allowlisted system-command execution with zero shell invocation.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use mesh_core::error::{AppError, AppResult};

/// Fixed allowlist of OS binaries that `mesh-net` may execute directly.
///
/// Shells (`sh`, `bash`, `cmd.exe`, `powershell.exe`) are intentionally excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedBinary {
    /// `/sbin/ifconfig` on macOS.
    MacOsIfconfig,
    /// `/sbin/route` on macOS.
    MacOsRoute,
    /// `/sbin/pfctl` on macOS.
    MacOsPfctl,
    /// `/usr/bin/dscacheutil` on macOS.
    MacOsDscacheutil,
    /// `/usr/bin/killall` on macOS.
    MacOsKillall,
    /// `/usr/libexec/ApplicationFirewall/socketfilterfw` on macOS.
    MacOsSocketFilterFw,
    /// `/bin/launchctl` on macOS.
    MacOsLaunchctl,
    /// `/usr/sbin/ip` on Linux.
    LinuxIpUsrSbin,
    /// `/sbin/ip` on Linux.
    LinuxIpSbin,
    /// `/usr/sbin/nft` on Linux.
    LinuxNft,
    /// `/usr/sbin/iptables` on Linux.
    LinuxIptables,
    /// `/usr/sbin/ufw` on Linux.
    LinuxUfw,
    /// `/usr/bin/systemctl` on Linux.
    LinuxSystemctlUsrBin,
    /// `/usr/bin/resolvectl` on Linux.
    LinuxResolvectl,
    /// `%SystemRoot%\System32\netsh.exe` on Windows.
    WindowsNetsh,
    /// `%SystemRoot%\System32\ipconfig.exe` on Windows.
    WindowsIpconfig,
    /// `%SystemRoot%\System32\route.exe` on Windows.
    WindowsRoute,
}

impl AllowedBinary {
    /// Returns the hardcoded absolute path for Unix binaries.
    #[must_use]
    pub const fn unix_path(self) -> Option<&'static str> {
        match self {
            Self::MacOsIfconfig => Some("/sbin/ifconfig"),
            Self::MacOsRoute => Some("/sbin/route"),
            Self::MacOsPfctl => Some("/sbin/pfctl"),
            Self::MacOsDscacheutil => Some("/usr/bin/dscacheutil"),
            Self::MacOsKillall => Some("/usr/bin/killall"),
            Self::MacOsSocketFilterFw => Some("/usr/libexec/ApplicationFirewall/socketfilterfw"),
            Self::MacOsLaunchctl => Some("/bin/launchctl"),
            Self::LinuxIpUsrSbin => Some("/usr/sbin/ip"),
            Self::LinuxIpSbin => Some("/sbin/ip"),
            Self::LinuxNft => Some("/usr/sbin/nft"),
            Self::LinuxIptables => Some("/usr/sbin/iptables"),
            Self::LinuxUfw => Some("/usr/sbin/ufw"),
            Self::LinuxSystemctlUsrBin => Some("/usr/bin/systemctl"),
            Self::LinuxResolvectl => Some("/usr/bin/resolvectl"),
            Self::WindowsNetsh | Self::WindowsIpconfig | Self::WindowsRoute => None,
        }
    }

    /// Returns the fixed executable name inside `System32` for Windows binaries.
    #[must_use]
    pub const fn windows_system32_exe(self) -> Option<&'static str> {
        match self {
            Self::WindowsNetsh => Some("netsh.exe"),
            Self::WindowsIpconfig => Some("ipconfig.exe"),
            Self::WindowsRoute => Some("route.exe"),
            _ => None,
        }
    }

    /// Resolves the canonical absolute path for the binary using an explicit Windows System32 root
    /// when applicable.
    pub fn resolve_path(self, windows_system32_dir: Option<&Path>) -> AppResult<PathBuf> {
        if let Some(unix_path) = self.unix_path() {
            return Ok(PathBuf::from(unix_path));
        }

        let exe = self
            .windows_system32_exe()
            .ok_or_else(|| AppError::internal("sysexec: binary missing platform path mapping"))?;

        let base = match windows_system32_dir {
            Some(dir) if dir.is_absolute() => dir.to_path_buf(),
            Some(_) => {
                return Err(AppError::invalid_argument(
                    "sysexec: windows system directory must be an absolute path",
                ));
            }
            None => default_windows_system32_dir()?,
        };
        Ok(base.join(exe))
    }
}

fn default_windows_system32_dir() -> AppResult<PathBuf> {
    if let Some(root) = std::env::var_os("SystemRoot") {
        let candidate = PathBuf::from(root).join("System32");
        if candidate.is_absolute() {
            return Ok(candidate);
        }
    }
    Ok(PathBuf::from(r"C:\Windows\System32"))
}

/// Validated non-shell command invocation specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// Target allowlisted executable.
    pub binary: AllowedBinary,
    /// Arguments passed directly to `execve`/`CreateProcess` without shell expansion.
    pub args: Vec<String>,
}

impl CommandSpec {
    /// Constructs a validated command specification.
    pub fn new(binary: AllowedBinary, args: impl IntoIterator<Item = String>) -> AppResult<Self> {
        let collected: Vec<String> = args.into_iter().collect();
        for arg in &collected {
            if arg.contains('\0') {
                return Err(AppError::invalid_argument(
                    "sysexec: command argument must not contain NUL bytes",
                ));
            }
        }
        Ok(Self {
            binary,
            args: collected,
        })
    }
}

/// Captured output from an executed system command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit code (`-1` if terminated by signal without status code).
    pub status_code: i32,
    /// UTF-8 lossy stdout text.
    pub stdout: String,
    /// UTF-8 lossy stderr text.
    pub stderr: String,
}

impl CommandOutput {
    /// Returns `true` when exit status was zero.
    #[must_use]
    pub const fn success(&self) -> bool {
        self.status_code == 0
    }
}

/// Abstraction over allowlisted OS command execution so tests run in memory without privileges.
pub trait CommandExecutor: Send + Sync + std::fmt::Debug {
    /// Executes an allowlisted system binary without a shell.
    fn execute(&self, spec: &CommandSpec) -> AppResult<CommandOutput>;
}

/// Production command executor that invokes hardcoded OS binaries directly.
#[derive(Debug, Clone, Default)]
pub struct StdCommandExecutor {
    windows_system32_dir: Option<PathBuf>,
}

impl StdCommandExecutor {
    /// Creates an executor using platform defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            windows_system32_dir: None,
        }
    }

    /// Overrides the `System32` directory path resolved via `GetSystemDirectoryW`.
    pub fn with_windows_system32_dir(system32_dir: PathBuf) -> AppResult<Self> {
        if !system32_dir.is_absolute() {
            return Err(AppError::invalid_argument(
                "sysexec: System32 directory override must be absolute",
            ));
        }
        Ok(Self {
            windows_system32_dir: Some(system32_dir),
        })
    }
}

impl CommandExecutor for StdCommandExecutor {
    fn execute(&self, spec: &CommandSpec) -> AppResult<CommandOutput> {
        let exe_path = spec
            .binary
            .resolve_path(self.windows_system32_dir.as_deref())?;
        if !exe_path.is_absolute() {
            return Err(AppError::internal(
                "sysexec: resolved executable path must be absolute",
            ));
        }

        let output = Command::new(&exe_path)
            .args(&spec.args)
            .output()
            .map_err(|err| {
                AppError::unavailable(format!("failed to execute {}: {err}", exe_path.display()))
            })?;

        let status_code = output.status.code().unwrap_or(-1);
        Ok(CommandOutput {
            status_code,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Recorded command call captured by [`FakeCommandExecutor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCommand {
    /// Binary invoked.
    pub binary: AllowedBinary,
    /// Arguments passed.
    pub args: Vec<String>,
}

/// Thread-safe in-memory fake command executor for unit tests.
#[derive(Debug, Clone, Default)]
pub struct FakeCommandExecutor {
    state: Arc<Mutex<FakeExecutorState>>,
}

#[derive(Debug, Default)]
struct FakeExecutorState {
    recorded: Vec<RecordedCommand>,
    canned: VecDeque<AppResult<CommandOutput>>,
}

impl FakeCommandExecutor {
    /// Creates an empty fake executor (returns exit code `0` by default).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes a scripted output or error for the next execution call.
    pub fn push_result(&self, result: AppResult<CommandOutput>) -> AppResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("sysexec: fake command executor mutex poisoned"))?;
        guard.canned.push_back(result);
        Ok(())
    }

    /// Returns a snapshot of all recorded command invocations.
    pub fn recorded(&self) -> AppResult<Vec<RecordedCommand>> {
        let guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("sysexec: fake command executor mutex poisoned"))?;
        Ok(guard.recorded.clone())
    }
}

impl CommandExecutor for FakeCommandExecutor {
    fn execute(&self, spec: &CommandSpec) -> AppResult<CommandOutput> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("sysexec: fake command executor mutex poisoned"))?;
        guard.recorded.push(RecordedCommand {
            binary: spec.binary,
            args: spec.args.clone(),
        });
        if let Some(next) = guard.canned.pop_front() {
            return next;
        }
        Ok(CommandOutput {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, FakeCommandExecutor,
        StdCommandExecutor,
    };

    #[test]
    fn test_sysexec_unix_allowlist_paths_are_absolute_and_non_shell() {
        // Arrange
        let unix_bins = [
            AllowedBinary::MacOsIfconfig,
            AllowedBinary::MacOsRoute,
            AllowedBinary::MacOsPfctl,
            AllowedBinary::MacOsDscacheutil,
            AllowedBinary::MacOsKillall,
            AllowedBinary::MacOsSocketFilterFw,
            AllowedBinary::MacOsLaunchctl,
            AllowedBinary::LinuxIpUsrSbin,
            AllowedBinary::LinuxIpSbin,
            AllowedBinary::LinuxNft,
            AllowedBinary::LinuxIptables,
            AllowedBinary::LinuxUfw,
            AllowedBinary::LinuxSystemctlUsrBin,
            AllowedBinary::LinuxResolvectl,
        ];

        // Act / Assert
        for bin in unix_bins {
            let path = bin.unix_path().unwrap_or("");
            assert!(path.starts_with('/'));
            assert!(!path.ends_with("/sh"));
            assert!(!path.ends_with("/bash"));
        }
    }

    #[test]
    fn test_sysexec_windows_system32_resolution_rejects_relative_dir() {
        // Arrange
        let rel = PathBuf::from("System32");

        // Act
        let override_err = StdCommandExecutor::with_windows_system32_dir(rel.clone());
        let resolve_err = AllowedBinary::WindowsNetsh.resolve_path(Some(&rel));

        // Assert
        assert!(override_err.is_err());
        assert!(resolve_err.is_err());

        let abs = if cfg!(windows) {
            PathBuf::from(r"C:\Windows\System32")
        } else {
            PathBuf::from("/windows/System32")
        };
        let resolved = AllowedBinary::WindowsRoute.resolve_path(Some(&abs));
        assert!(resolved.is_ok());
    }

    #[test]
    fn test_sysexec_rejects_nul_byte_and_records_fake_calls() {
        // Arrange
        let bad = CommandSpec::new(AllowedBinary::LinuxIpSbin, ["addr\0".to_owned()]);
        let good = CommandSpec::new(
            AllowedBinary::MacOsRoute,
            ["-n".to_owned(), "delete".to_owned()],
        );
        let fake = FakeCommandExecutor::new();

        // Act
        assert!(bad.is_err());
        let spec = match good {
            Ok(val) => val,
            Err(err) => {
                assert_eq!(err.to_string(), "expected valid command spec");
                return;
            }
        };
        assert!(
            fake.push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: "deleted".to_owned(),
                stderr: String::new(),
            }))
            .is_ok()
        );
        let out = fake.execute(&spec);
        let recorded = fake.recorded();

        // Assert
        assert!(matches!(out, Ok(ref o) if o.success() && o.stdout == "deleted"));
        assert!(matches!(
            recorded.as_deref(),
            Ok([item]) if item.binary == AllowedBinary::MacOsRoute
        ));
    }
}
