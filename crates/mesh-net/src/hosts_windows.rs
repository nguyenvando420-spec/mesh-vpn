//! Windows ACL-preserving `hosts` editor + bounded backoff retry + DNS flush (`US-038`, `WP-S1-04`).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mesh_core::{AppError, AppResult, ErrorKind};
use mesh_sys::netmon_windows::windows_system_directory;

use crate::hosts::{
    FileHostsEditor, HostsEditor, HostsEntry, remove_hosts_block, render_hosts_with_block,
};
use crate::sysexec::{AllowedBinary, CommandExecutor, CommandSpec, StdCommandExecutor};

const MAX_WINDOWS_HOSTS_BACKOFF: Duration = Duration::from_secs(2);
const BACKOFF_STEPS_MS: [u64; 6] = [25, 50, 100, 200, 400, 500];
const WIN_ERROR_SHARING_VIOLATION: i32 = 32;
const WIN_ERROR_LOCK_VIOLATION: i32 = 33;
const WIN_ERROR_ACCESS_DENIED: i32 = 5;

/// Returns the canonical Windows `%SystemRoot%\System32\drivers\etc\hosts` path via `GetSystemDirectoryW`.
pub fn windows_hosts_path() -> AppResult<PathBuf> {
    let sys_dir = windows_system_directory().map_err(AppError::from)?;
    Ok(sys_dir.join("drivers").join("etc").join("hosts"))
}

/// Returns a [`FileHostsEditor`] targeting Windows `%SystemRoot%\System32\drivers\etc\hosts`.
#[must_use]
pub fn windows_hosts_editor() -> FileHostsEditor {
    FileHostsEditor::default_system()
}

/// Flushes Windows DNS resolver cache best-effort using `GetSystemDirectoryW` + `ipconfig.exe /flushdns`
/// (`US-038 AC8`).
pub fn flush_dns_cache_best_effort() -> AppResult<()> {
    let sys_dir = windows_system_directory().map_err(AppError::from)?;
    let exec = StdCommandExecutor::with_windows_system32_dir(sys_dir)?;
    flush_dns_cache_with(&exec)
}

/// Executes `ipconfig.exe /flushdns` using `executor`, warning instead of breaking data plane on failure.
pub fn flush_dns_cache_with(executor: &dyn CommandExecutor) -> AppResult<()> {
    let spec = CommandSpec::new(AllowedBinary::WindowsIpconfig, vec!["/flushdns".to_owned()])?;
    match executor.execute(&spec) {
        Ok(out) => {
            if !out.success() {
                tracing::warn!(
                    target: "mesh::net::hosts_windows",
                    status_code = out.status_code,
                    stderr = %out.stderr,
                    "ipconfig /flushdns returned non-zero status"
                );
            }
            Ok(())
        }
        Err(err) => {
            tracing::warn!(
                target: "mesh::net::hosts_windows",
                error = %err,
                "Failed to flush Windows DNS cache; data plane continues unaffected"
            );
            Ok(())
        }
    }
}

/// Windows ACL-preserving `hosts` editor (`US-038 AC2b/c`):
/// - Updates existing `hosts` in-place so inherited `Users` / `Dnscache` Read ACLs remain intact
///   (never inheriting narrow `%TEMP%` ACLs from a service temp directory).
/// - Retries transient Windows file locks (`Dnscache`/AV) with bounded backoff (`<= 2 s`).
#[derive(Clone)]
pub struct WindowsHostsEditor {
    hosts_path: PathBuf,
    max_retry_budget: Duration,
    flush_executor: Option<Arc<dyn CommandExecutor>>,
}

impl std::fmt::Debug for WindowsHostsEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsHostsEditor")
            .field("hosts_path", &self.hosts_path)
            .field("max_retry_budget", &self.max_retry_budget)
            .finish()
    }
}

impl WindowsHostsEditor {
    /// Creates an editor targeting `%SystemRoot%\System32\drivers\etc\hosts` (`<= 2 s` lock backoff).
    pub fn system_default() -> AppResult<Self> {
        Ok(Self {
            hosts_path: windows_hosts_path()?,
            max_retry_budget: MAX_WINDOWS_HOSTS_BACKOFF,
            flush_executor: None,
        })
    }

    /// Creates an editor targeting an explicit file path (for isolated tests).
    #[must_use]
    pub fn with_path(
        hosts_path: PathBuf,
        max_retry_budget: Duration,
        flush_executor: Option<Arc<dyn CommandExecutor>>,
    ) -> Self {
        Self {
            hosts_path,
            max_retry_budget: max_retry_budget.min(MAX_WINDOWS_HOSTS_BACKOFF),
            flush_executor,
        }
    }

    fn flush_dns(&self) -> AppResult<()> {
        if let Some(exec) = &self.flush_executor {
            return flush_dns_cache_with(exec.as_ref());
        }
        flush_dns_cache_best_effort()
    }

    async fn flush_dns_async(&self) -> AppResult<()> {
        let exec = self.flush_executor.as_ref().map(Arc::clone);
        tokio::task::spawn_blocking(move || match exec {
            Some(custom) => flush_dns_cache_with(custom.as_ref()),
            None => flush_dns_cache_best_effort(),
        })
        .await
        .map_err(|err| AppError::internal(format!("Windows DNS flush join error: {err}")))?
    }

    /// Asynchronously updates the managed block using `spawn_blocking` for short disk I/O and
    /// `tokio::time::sleep` between transient file-lock retries so Tokio workers never block (`HR-S1-11`).
    pub async fn apply_async(&self, entries: &[HostsEntry]) -> AppResult<()> {
        self.apply_with_public_host_async(entries, None).await
    }

    /// Async variant of [`HostsEditor::apply`] supporting `public_server_host` collision checks.
    pub async fn apply_with_public_host_async(
        &self,
        entries: &[HostsEntry],
        public_server_host: Option<&str>,
    ) -> AppResult<()> {
        let owned_entries = entries.to_vec();
        let owned_host = public_server_host.map(str::to_owned);
        self.update_hosts_with_retry_async(move |existing| {
            render_hosts_with_block(existing, &owned_entries, owned_host.as_deref())
        })
        .await
    }

    /// Asynchronously removes the managed block and flushes Windows DNS via `CommandExecutor` (`HR-S1-11`).
    pub async fn clear_async(&self) -> AppResult<()> {
        if !self.hosts_path.exists() {
            return Ok(());
        }
        self.update_hosts_with_retry_async(remove_hosts_block).await
    }

    async fn update_hosts_with_retry_async<F>(&self, transform: F) -> AppResult<()>
    where
        F: Fn(&str) -> AppResult<String> + Send + Sync + 'static,
    {
        let start = Instant::now();
        let mut attempt: usize = 0;
        let transform = Arc::new(transform);

        loop {
            let path = self.hosts_path.clone();
            let tf = Arc::clone(&transform);
            let step_res = tokio::task::spawn_blocking(move || {
                try_update_in_place(&path, &mut |existing| tf(existing))
            })
            .await
            .map_err(|err| AppError::internal(format!("Windows hosts task join error: {err}")))?;

            match step_res {
                Ok(()) => return self.flush_dns_async().await,
                Err(HostsWriteError::App(app_err)) => return Err(app_err),
                Err(HostsWriteError::Io(io_err)) => {
                    let wait_for =
                        next_retry_delay(&io_err, start.elapsed(), self.max_retry_budget, attempt);
                    let Some(wait_for) = wait_for else {
                        return Err(map_hosts_io_error(&self.hosts_path, &io_err));
                    };
                    tokio::time::sleep(wait_for).await;
                    attempt += 1;
                }
            }
        }
    }

    fn update_hosts_with_retry<F>(&self, mut transform: F) -> AppResult<()>
    where
        F: FnMut(&str) -> AppResult<String>,
    {
        let start = Instant::now();
        let mut attempt: usize = 0;

        loop {
            match try_update_in_place(&self.hosts_path, &mut transform) {
                Ok(()) => return self.flush_dns(),
                Err(HostsWriteError::App(app_err)) => return Err(app_err),
                Err(HostsWriteError::Io(io_err)) => {
                    let Some(wait_for) =
                        next_retry_delay(&io_err, start.elapsed(), self.max_retry_budget, attempt)
                    else {
                        return Err(map_hosts_io_error(&self.hosts_path, &io_err));
                    };
                    backoff_wait(wait_for);
                    attempt += 1;
                }
            }
        }
    }
}

impl HostsEditor for WindowsHostsEditor {
    fn apply(&self, entries: &[HostsEntry], public_server_host: Option<&str>) -> AppResult<()> {
        self.update_hosts_with_retry(|existing| {
            render_hosts_with_block(existing, entries, public_server_host)
        })
    }

    fn clear(&self) -> AppResult<()> {
        if !self.hosts_path.exists() {
            return Ok(());
        }
        self.update_hosts_with_retry(remove_hosts_block)
    }

    fn canonical_real_path(&self) -> AppResult<Option<PathBuf>> {
        if !self.hosts_path.exists() {
            return Ok(Some(self.hosts_path.clone()));
        }
        fs::canonicalize(&self.hosts_path)
            .map(Some)
            .map_err(|err| map_hosts_io_error(&self.hosts_path, &err))
    }
}

enum HostsWriteError {
    App(AppError),
    Io(io::Error),
}

fn map_hosts_io_error(path: &Path, err: &io::Error) -> AppError {
    let kind = if err.kind() == io::ErrorKind::PermissionDenied {
        ErrorKind::PermissionDenied
    } else {
        ErrorKind::Internal
    };
    AppError::new(
        kind,
        format!("updating Windows hosts file '{}': {err}", path.display()),
    )
}

fn try_update_in_place<F>(path: &Path, transform: &mut F) -> Result<(), HostsWriteError>
where
    F: FnMut(&str) -> AppResult<String>,
{
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(HostsWriteError::Io)?;
    }

    // When `hosts` already exists, open in-place (`create(false)`) without truncate first so
    // NTFS preserves the existing Security Descriptor / `Users` / `Dnscache` read ACL (`US-038 AC2b`).
    let mut file = if path.exists() {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(HostsWriteError::Io)?
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(HostsWriteError::Io)?
    };

    let mut current = String::new();
    let _read = file
        .read_to_string(&mut current)
        .map_err(HostsWriteError::Io)?;
    let updated = transform(&current).map_err(HostsWriteError::App)?;
    if updated == current {
        return Ok(());
    }

    write_in_place_contents(&mut file, updated.as_bytes()).map_err(HostsWriteError::Io)
}

fn write_in_place_contents(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    let target_len = u64::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hosts payload too large"))?;
    file.set_len(target_len)?;
    file.sync_all()
}

fn next_retry_delay(
    err: &io::Error,
    elapsed: Duration,
    max_retry_budget: Duration,
    attempt: usize,
) -> Option<Duration> {
    if !is_transient_lock_error(err) || elapsed >= max_retry_budget {
        return None;
    }
    let delay_ms = BACKOFF_STEPS_MS.get(attempt).copied()?;
    let remaining = max_retry_budget.saturating_sub(elapsed);
    let wait_for = Duration::from_millis(delay_ms).min(remaining);
    if wait_for.is_zero() {
        return None;
    }
    Some(wait_for)
}

fn is_transient_lock_error(err: &io::Error) -> bool {
    // Only retry kernel sharing/lock contention (`Dnscache`/AV) — permanent `ERROR_ACCESS_DENIED`
    // (`5` / `PermissionDenied`) must fail immediately instead of stalling 2 seconds (`HR-S1-11`).
    if err.raw_os_error() == Some(WIN_ERROR_ACCESS_DENIED)
        || err.kind() == io::ErrorKind::PermissionDenied
    {
        return false;
    }
    if matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        return true;
    }
    matches!(
        err.raw_os_error(),
        Some(WIN_ERROR_SHARING_VIOLATION | WIN_ERROR_LOCK_VIOLATION)
    )
}

pub(crate) fn backoff_wait(duration: Duration) {
    let lock = Mutex::new(false);
    let cv = Condvar::new();
    if let Ok(guard) = lock.lock()
        && !*guard
    {
        let _timeout = cv.wait_timeout(guard, duration);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::net::Ipv4Addr;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use mesh_core::{NodeName, OverlayIp};
    use tempfile::tempdir;

    use super::{
        MAX_WINDOWS_HOSTS_BACKOFF, WindowsHostsEditor, flush_dns_cache_with,
        is_transient_lock_error,
    };
    use crate::hosts::{HostsEditor, HostsEntry};
    use crate::sysexec::{AllowedBinary, FakeCommandExecutor};

    fn sample_hosts_entry() -> Option<HostsEntry> {
        let overlay_ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 15)).ok()?;
        let name = NodeName::parse("nas").ok()?;
        HostsEntry::new(overlay_ip, name, "mesh.internal", None).ok()
    }

    #[test]
    fn test_hosts_windows_flush_dns_uses_ipconfig_via_sysexec() {
        // Arrange
        let fake_exec = FakeCommandExecutor::new();

        // Act
        let res = flush_dns_cache_with(&fake_exec);

        // Assert
        assert!(res.is_ok());
        let recorded = fake_exec.recorded();
        assert!(recorded.is_ok());
        if let Ok(calls) = recorded {
            assert_eq!(calls.len(), 1);
            if let Some(first) = calls.first() {
                assert_eq!(first.binary, AllowedBinary::WindowsIpconfig);
                assert_eq!(first.args, vec!["/flushdns".to_owned()]);
            }
        }
    }

    #[test]
    fn test_hosts_windows_preserves_existing_content_and_readonly_retries_within_2s() {
        // Arrange
        let dir = tempdir();
        assert!(dir.is_ok());
        let Ok(dir) = dir else {
            return;
        };
        let hosts_path = dir.path().join("hosts");
        assert!(fs::write(&hosts_path, "127.0.0.1 localhost\r\n").is_ok());
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let editor = WindowsHostsEditor::with_path(
            hosts_path.clone(),
            Duration::from_millis(60),
            Some(Arc::clone(&fake_exec) as _),
        );
        let entry = sample_hosts_entry();
        assert!(entry.is_some());
        let Some(entry) = entry else {
            return;
        };

        // Act: writable update preserves non-managed lines and flushes DNS; readonly bounds backoff <= 2s.
        let ok_res = editor.apply(std::slice::from_ref(&entry), None);
        assert!(ok_res.is_ok(), "apply failed: {ok_res:?}");

        let content_after_apply = fs::read_to_string(&hosts_path);
        assert!(content_after_apply.is_ok());
        if let Ok(text) = content_after_apply {
            assert!(text.contains("127.0.0.1 localhost"));
            assert!(text.contains("nas.mesh.internal"));
        }

        let lock_holder = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&hosts_path);
        assert!(lock_holder.is_ok(), "exclusive share_mode(0) lock failed");
        let started = Instant::now();
        let locked_res = editor.apply(&[entry], None);
        let elapsed = started.elapsed();
        drop(lock_holder);

        // Assert
        assert!(locked_res.is_err());
        assert!(elapsed <= MAX_WINDOWS_HOSTS_BACKOFF);
        let clear_res = editor.clear();
        assert!(clear_res.is_ok());
    }

    #[test]
    fn test_hosts_windows_sharing_violation_classified_transient() {
        // Arrange
        let sharing = std::io::Error::from_raw_os_error(32);
        let lock_violation = std::io::Error::from_raw_os_error(33);
        let access_denied = std::io::Error::from_raw_os_error(5);
        let perm_denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

        // Act / Assert
        assert!(is_transient_lock_error(&sharing));
        assert!(is_transient_lock_error(&lock_violation));
        assert!(!is_transient_lock_error(&access_denied));
        assert!(!is_transient_lock_error(&perm_denied));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_hosts_windows_apply_async_and_clear_async_non_blocking() {
        // Arrange
        let dir = tempdir();
        assert!(dir.is_ok());
        let Ok(dir) = dir else {
            return;
        };
        let hosts_path = dir.path().join("hosts");
        assert!(fs::write(&hosts_path, "127.0.0.1 localhost\r\n").is_ok());
        let fake_exec = Arc::new(FakeCommandExecutor::new());
        let editor = WindowsHostsEditor::with_path(
            hosts_path.clone(),
            Duration::from_millis(80),
            Some(Arc::clone(&fake_exec) as _),
        );
        let entry = sample_hosts_entry();
        assert!(entry.is_some());
        let Some(entry) = entry else {
            return;
        };

        // Act: transient sharing lock exercises async `tokio::time::sleep` retry, then clean apply/clear.
        let lock_holder = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&hosts_path);
        assert!(lock_holder.is_ok());
        let locked_err = editor.apply_async(std::slice::from_ref(&entry)).await;
        drop(lock_holder);
        assert!(locked_err.is_err());

        let ok_apply = editor.apply_async(&[entry]).await;
        let ok_clear = editor.clear_async().await;

        // Assert
        assert!(ok_apply.is_ok(), "apply_async failed: {ok_apply:?}");
        assert!(ok_clear.is_ok(), "clear_async failed: {ok_clear:?}");
        let recorded = fake_exec.recorded();
        assert!(recorded.is_ok());
        if let Ok(calls) = recorded {
            assert_eq!(calls.len(), 2);
            assert!(
                calls
                    .iter()
                    .all(|c| c.binary == AllowedBinary::WindowsIpconfig)
            );
        }
    }
}
