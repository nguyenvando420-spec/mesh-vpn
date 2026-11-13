//! Structured UTC JSON logging and size-bounded rotating file writer (`US-043`, `OPS-01`).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::registry::LookupSpan;

use crate::defaults::{DEFAULT_LOG_FILE_ROTATE_BYTES, DEFAULT_LOG_MAX_BYTES};
use crate::error::{AppError, AppResult};

/// Configuration for initializing structured JSON logging.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Logical component identifier written to the mandatory `component` JSON field.
    pub component: String,
    /// Minimum log directive parsed by `EnvFilter` (e.g. `"info"` or `"debug"`).
    pub level_filter: String,
    /// Optional directory path for size-bounded rotating `.log` files.
    pub log_dir: Option<PathBuf>,
    /// File name prefix when writing rotated files (`<prefix>.log`).
    pub file_prefix: String,
    /// Single-file rotation threshold in bytes (default 10 MiB).
    pub max_file_bytes: u64,
    /// Cumulative directory size cap across active and rotated files (default 100 MiB).
    pub max_total_bytes: u64,
}

impl LoggingConfig {
    /// Returns default production logging settings for the specified component name.
    #[must_use]
    pub fn for_component(component: impl Into<String>) -> Self {
        let comp = component.into();
        let prefix = comp.clone();
        Self {
            component: comp,
            level_filter: "info".to_owned(),
            log_dir: None,
            file_prefix: prefix,
            max_file_bytes: DEFAULT_LOG_FILE_ROTATE_BYTES,
            max_total_bytes: DEFAULT_LOG_MAX_BYTES,
        }
    }
}

/// Guard keeping the asynchronous non-blocking log writer flushed until drop.
pub struct LogGuard {
    _guard: Option<WorkerGuard>,
}

impl fmt::Debug for LogGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogGuard").finish()
    }
}

/// JSON event formatter guaranteeing mandatory `ts`, `level`, `component`, and `event` fields.
#[derive(Debug, Clone)]
pub struct MeshJsonFormatter {
    default_component: String,
}

impl MeshJsonFormatter {
    /// Creates a formatter tagging events with `default_component` if none is supplied.
    #[must_use]
    pub fn new(default_component: impl Into<String>) -> Self {
        Self {
            default_component: default_component.into(),
        }
    }
}

struct JsonFieldVisitor {
    component: Option<String>,
    event_name: Option<String>,
    message: Option<String>,
    extras: Map<String, Value>,
}

impl JsonFieldVisitor {
    fn new() -> Self {
        Self {
            component: None,
            event_name: None,
            message: None,
            extras: Map::new(),
        }
    }

    fn insert_field(&mut self, name: &str, value: Value) {
        match name {
            "component" => {
                if let Value::String(s) = value {
                    self.component = Some(s);
                }
            }
            "event" => {
                if let Value::String(s) = value {
                    self.event_name = Some(s);
                }
            }
            "message" => {
                if let Value::String(s) = value {
                    self.message = Some(s);
                }
            }
            "ts" | "level" => {}
            other => {
                self.extras.insert(other.to_owned(), value);
            }
        }
    }
}

impl Visit for JsonFieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert_field(field.name(), Value::String(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert_field(field.name(), Value::String(value.to_owned()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert_field(field.name(), Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert_field(field.name(), Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert_field(field.name(), Value::from(value));
    }
}

impl<S, N> FormatEvent<S, N> for MeshJsonFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut visitor = JsonFieldVisitor::new();
        event.record(&mut visitor);

        let metadata = event.metadata();
        let component = visitor
            .component
            .unwrap_or_else(|| self.default_component.clone());
        let event_val = visitor
            .event_name
            .or_else(|| visitor.message.clone())
            .unwrap_or_else(|| metadata.name().to_owned());

        let mut root = Map::new();
        root.insert("ts".to_owned(), Value::String(format_utc_now_rfc3339()));
        root.insert(
            "level".to_owned(),
            Value::String(metadata.level().as_str().to_owned()),
        );
        root.insert("component".to_owned(), Value::String(component));
        root.insert("event".to_owned(), Value::String(event_val));
        if let Some(msg) = visitor.message {
            root.insert("message".to_owned(), Value::String(msg));
        }
        for (k, v) in visitor.extras {
            root.insert(k, v);
        }

        let serialized = serde_json::to_string(&Value::Object(root)).map_err(|_| fmt::Error)?;
        writeln!(writer, "{serialized}")
    }
}

/// Formats a UTC Unix timestamp in milliseconds into RFC 3339 `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn format_utc_ms_rfc3339(unix_ms: u64) -> String {
    let total_secs = i64::try_from(unix_ms / 1_000).unwrap_or(i64::MAX);
    let millis = unix_ms % 1_000;
    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn format_utc_now_rfc3339() -> String {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    format_utc_ms_rfc3339(unix_ms)
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    let month = u32::try_from(m).unwrap_or(1);
    let day = u32::try_from(d).unwrap_or(1);
    (year, month, day)
}

#[derive(Debug)]
struct RotatingState {
    dir: PathBuf,
    file_prefix: String,
    max_file_bytes: u64,
    max_total_bytes: u64,
    current_file: File,
    current_bytes: u64,
    rotation_seq: u64,
}

/// Thread-safe size-bounded rotating file writer enforcing cumulative directory caps (`US-043 AC3`).
#[derive(Debug, Clone)]
pub struct BoundedRotatingWriter {
    inner: Arc<Mutex<RotatingState>>,
}

impl BoundedRotatingWriter {
    /// Opens or creates `<dir>/<file_prefix>.log` and enforces the cumulative size limit.
    pub fn new(
        dir: impl AsRef<Path>,
        file_prefix: impl Into<String>,
        max_file_bytes: u64,
        max_total_bytes: u64,
    ) -> AppResult<Self> {
        let dir_path = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir_path)
            .map_err(|err| AppError::internal(format!("failed to create log directory: {err}")))?;
        let prefix = file_prefix.into();
        let active_path = dir_path.join(format!("{prefix}.log"));
        let current_bytes = fs::metadata(&active_path).map_or(0, |m| m.len());
        let max_seq = discover_max_rotation_seq(&dir_path, &prefix).map_err(|err| {
            AppError::internal(format!("failed to scan existing log files: {err}"))
        })?;
        let current_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)
            .map_err(|err| AppError::internal(format!("failed to open active log file: {err}")))?;

        let writer = Self {
            inner: Arc::new(Mutex::new(RotatingState {
                dir: dir_path,
                file_prefix: prefix,
                max_file_bytes: max_file_bytes.max(128),
                max_total_bytes: max_total_bytes.max(max_file_bytes.max(128)),
                current_file,
                current_bytes,
                rotation_seq: max_seq,
            })),
        };
        Ok(writer)
    }

    fn rotate_and_prune(state: &mut RotatingState) -> io::Result<()> {
        state.current_file.flush()?;
        state.rotation_seq = state.rotation_seq.saturating_add(1);
        let active = state.dir.join(format!("{}.log", state.file_prefix));
        let rotated = state.dir.join(format!(
            "{}.{:016}.log",
            state.file_prefix, state.rotation_seq
        ));
        if active.exists() {
            fs::rename(&active, &rotated)?;
        }
        state.current_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&active)?;
        state.current_bytes = 0;
        prune_rotated_logs(&state.dir, &state.file_prefix, state.max_total_bytes)
    }
}

fn parse_rotated_seq(file_name: &str, prefix: &str) -> Option<u64> {
    let rotated_prefix = format!("{prefix}.");
    let seq_str = file_name
        .strip_prefix(&rotated_prefix)?
        .strip_suffix(".log")?;
    if seq_str.is_empty() || !seq_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    seq_str.parse::<u64>().ok()
}

fn discover_max_rotation_seq(dir: &Path, prefix: &str) -> io::Result<u64> {
    let mut max_seq = 0_u64;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(seq) = parse_rotated_seq(name, prefix) {
            max_seq = max_seq.max(seq);
        }
    }
    Ok(max_seq)
}

fn prune_rotated_logs(dir: &Path, prefix: &str, max_total_bytes: u64) -> io::Result<()> {
    let active_name = format!("{prefix}.log");
    let mut active_size = 0_u64;
    let mut rotated_files: Vec<(u64, String, PathBuf, u64)> = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let len = entry.metadata()?.len();
        if name == active_name {
            active_size = len;
        } else if let Some(seq) = parse_rotated_seq(name, prefix) {
            rotated_files.push((seq, name.to_owned(), path, len));
        }
    }

    rotated_files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut total_size = active_size.saturating_add(
        rotated_files
            .iter()
            .fold(0_u64, |acc, item| acc.saturating_add(item.3)),
    );
    for (_, _, path, size) in rotated_files {
        if total_size <= max_total_bytes {
            break;
        }
        fs::remove_file(path)?;
        total_size = total_size.saturating_sub(size);
    }
    Ok(())
}

impl io::Write for BoundedRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("log writer mutex poisoned"))?;
        let incoming = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if state.current_bytes > 0
            && state.current_bytes.saturating_add(incoming) > state.max_file_bytes
        {
            Self::rotate_and_prune(&mut state)?;
        }
        state.current_file.write_all(buf)?;
        state.current_bytes = state.current_bytes.saturating_add(incoming);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("log writer mutex poisoned"))?;
        state.current_file.flush()
    }
}

/// Shared handle implementing `tracing_subscriber::fmt::MakeWriter`.
#[derive(Debug, Clone)]
pub struct SharedLogWriter {
    writer: BoundedRotatingWriter,
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = BoundedRotatingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.writer.clone()
    }
}

/// Initializes the global structured JSON `tracing` subscriber.
pub fn init_json_logging(config: &LoggingConfig) -> AppResult<LogGuard> {
    let filter = EnvFilter::try_new(&config.level_filter).map_err(|err| {
        AppError::invalid_argument(format!(
            "invalid log filter `{}`: {err}",
            config.level_filter
        ))
    })?;
    let formatter = MeshJsonFormatter::new(config.component.clone());

    if let Some(dir) = &config.log_dir {
        let writer = BoundedRotatingWriter::new(
            dir,
            config.file_prefix.clone(),
            config.max_file_bytes,
            config.max_total_bytes,
        )?;
        let (non_blocking, guard) = tracing_appender::non_blocking(writer);
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(non_blocking)
            .event_format(formatter)
            .try_init()
            .map_err(|err| AppError::internal(format!("failed to init logger: {err}")))?;
        Ok(LogGuard {
            _guard: Some(guard),
        })
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .event_format(formatter)
            .try_init()
            .map_err(|err| AppError::internal(format!("failed to init stderr logger: {err}")))?;
        Ok(LogGuard { _guard: None })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Write as _};
    use std::sync::{Arc, Mutex};

    use serde_json::Value;
    use tempfile::TempDir;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::error::AppError;
    use crate::types::{NodeId, NodeName, PublicKey, SpkiPin};

    use super::{BoundedRotatingWriter, MeshJsonFormatter, format_utc_ms_rfc3339};

    #[derive(Clone, Default)]
    struct CaptureBuf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CaptureBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Ok(mut guard) = self.0.lock() {
                guard.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureBuf {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn test_utc_rfc3339_formatting() {
        // Arrange
        let ts_ms = 1_731_480_000_123_u64;

        // Act
        let formatted = format_utc_ms_rfc3339(ts_ms);

        // Assert
        assert!(formatted.starts_with("2024-11-13T"));
        assert!(formatted.ends_with(".123Z"));
    }

    #[test]
    fn test_bounded_rotating_writer_enforces_total_cap() {
        // Arrange
        let Ok(tmp) = tempfile::tempdir() else {
            return;
        };
        let Ok(mut writer) = BoundedRotatingWriter::new(tmp.path(), "meshd", 200, 500) else {
            return;
        };

        // Act
        let payload = [b'x'; 120];
        for _ in 0..8 {
            assert!(writer.write_all(&payload).is_ok());
        }
        assert!(writer.flush().is_ok());

        // Assert
        let total: u64 = fs::read_dir(tmp.path())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        assert!(total <= 500);
    }

    #[test]
    fn test_bounded_rotating_writer_preserves_newest_across_restarts() {
        // Arrange
        let Ok(tmp) = TempDir::new() else {
            return;
        };
        let old_marker = b"OLD_PRE_RESTART_RECORD_";
        let new_marker = b"LATEST_POST_RESTART_REC";
        let mut first_block = [b'a'; 150];
        if let Some(head) = first_block.get_mut(..old_marker.len()) {
            head.copy_from_slice(old_marker);
        }

        // Phase 1: write several rotations before simulated restart
        {
            let Ok(mut writer1) = BoundedRotatingWriter::new(tmp.path(), "meshd", 140, 500) else {
                return;
            };
            for _ in 0..4 {
                assert!(writer1.write_all(&first_block).is_ok());
            }
            assert!(writer1.flush().is_ok());
        }

        // Phase 2: restart writer on same directory and push latest records past cap
        let mut second_block = [b'b'; 150];
        if let Some(head) = second_block.get_mut(..new_marker.len()) {
            head.copy_from_slice(new_marker);
        }
        {
            let Ok(mut writer2) = BoundedRotatingWriter::new(tmp.path(), "meshd", 140, 500) else {
                return;
            };
            for _ in 0..4 {
                assert!(writer2.write_all(&second_block).is_ok());
            }
            assert!(writer2.flush().is_ok());
        }

        // Assert: rotated sequence continued past phase 1, oldest .1 removed, newest preserved
        assert!(!tmp.path().join("meshd.0000000000000001.log").exists());
        let mut combined = Vec::new();
        for entry in fs::read_dir(tmp.path()).into_iter().flatten().flatten() {
            if let Ok(bytes) = fs::read(entry.path()) {
                combined.extend_from_slice(&bytes);
            }
        }
        let all_text = String::from_utf8_lossy(&combined);
        assert!(all_text.contains("LATEST_POST_RESTART_REC"));
    }

    #[test]
    fn test_no_secrets_in_outputs() {
        // Arrange
        let buf = CaptureBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(buf.clone())
            .event_format(MeshJsonFormatter::new("mesh-core"))
            .finish();

        let secret_token = "mpk_super_secret_preauth_token_never_log";
        let auth_err = AppError::unauthenticated(format!("bad token {secret_token}"));
        let node_id = NodeId::new_v7(1_731_480_000_000);
        let node_name = NodeName::parse("alice-mac").ok();
        let pub_key = PublicKey::from_bytes([0x11_u8; 32]).ok();
        let pin = SpkiPin::from_sha256_bytes([0x22_u8; 32]);

        // Act
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                event = "auth_rejected",
                node_id = %node_id,
                node_name = ?node_name,
                public_key = ?pub_key,
                spki_pin = %pin,
                wire_error = %auth_err.public_message(),
                "debug trace check"
            );
        });

        // Assert
        let raw = buf
            .0
            .lock()
            .map(|g| String::from_utf8_lossy(&g).into_owned())
            .unwrap_or_default();
        assert!(!raw.contains(secret_token));
        let line = raw.lines().next().unwrap_or("");
        let parsed: Result<Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok());
        if let Ok(json) = parsed {
            assert!(json.get("ts").is_some());
            assert_eq!(json.get("level").and_then(Value::as_str), Some("DEBUG"));
            assert_eq!(
                json.get("component").and_then(Value::as_str),
                Some("mesh-core")
            );
            assert_eq!(
                json.get("event").and_then(Value::as_str),
                Some("auth_rejected")
            );
        }
    }
}
