//! Managed `# BEGIN mesh ... # END mesh` hosts-file editor and symlink-safe atomic writer (`US-038`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mesh_core::brand::{DEFAULT_DOMAIN_SUFFIX, HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
use mesh_core::{AppError, AppResult, NodeName, OverlayIp};

/// Validated peer mapping written inside `# BEGIN mesh ... # END mesh`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsEntry {
    /// Assigned peer overlay IPv4 address.
    pub overlay_ip: OverlayIp,
    /// Validated single-label node name (`RFC 1123`).
    pub node_name: NodeName,
    /// Mesh domain suffix (defaults to `mesh.internal`).
    pub domain_suffix: String,
}

impl HostsEntry {
    /// Constructs a validated hosts entry, rejecting collisions with `public_server_host`
    /// or unsafe characters in `domain_suffix`.
    pub fn new(
        overlay_ip: OverlayIp,
        node_name: NodeName,
        domain_suffix: &str,
        public_server_host: Option<&str>,
    ) -> AppResult<Self> {
        let normalized_suffix = validate_domain_suffix(domain_suffix)?;
        if let Some(public_host) = public_server_host {
            let trimmed_host = public_host.trim();
            if !trimmed_host.is_empty() {
                node_name.validate_against_public_host(trimmed_host, &normalized_suffix)?;
                if let Ok(server_ip) = trimmed_host.parse::<Ipv4Addr>()
                    && overlay_ip.as_ipv4() == server_ip
                {
                    return Err(AppError::invalid_argument(
                        "hosts entry overlay IP cannot equal public server IP",
                    ));
                }
            }
        }
        Ok(Self {
            overlay_ip,
            node_name,
            domain_suffix: normalized_suffix,
        })
    }

    /// Formats a single hosts line: `<ip> <node>.<suffix> <node>`.
    #[must_use]
    pub fn format_line(&self) -> String {
        let fqdn = self.node_name.fqdn(&self.domain_suffix);
        format!("{} {} {}", self.overlay_ip, fqdn, self.node_name)
    }
}

/// Validates a domain suffix (`[a-z0-9.-]`, RFC-1123 dot-separated labels).
pub fn validate_domain_suffix(raw: &str) -> AppResult<String> {
    if raw.len() != raw.trim().len() || raw.contains(['\n', '\r', '#', ' ', '\t']) {
        return Err(AppError::invalid_argument(
            "domain suffix contains forbidden whitespace or comment characters",
        ));
    }
    let normalized = raw.trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(AppError::invalid_argument(
            "domain suffix must be 1..=253 ASCII characters",
        ));
    }
    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(AppError::invalid_argument(
                "domain suffix label length must be 1..=63",
            ));
        }
        let bytes = label.as_bytes();
        let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
            return Err(AppError::invalid_argument("empty domain suffix label"));
        };
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
            return Err(AppError::invalid_argument(
                "domain suffix label must start and end with ASCII alphanumeric character",
            ));
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err(AppError::invalid_argument(
                "domain suffix contains invalid characters",
            ));
        }
    }
    Ok(normalized)
}

/// Renders the full `# BEGIN mesh ... # END mesh` block using the specified line ending.
pub fn render_hosts_block(
    entries: &[HostsEntry],
    public_server_host: Option<&str>,
    line_ending: &str,
) -> AppResult<String> {
    let mut out = String::new();
    out.push_str(HOSTS_BEGIN_MARKER);
    out.push_str(line_ending);

    for entry in entries {
        // Re-verify against public_server_host in case caller built struct fields directly.
        let validated = HostsEntry::new(
            entry.overlay_ip,
            entry.node_name.clone(),
            &entry.domain_suffix,
            public_server_host,
        )?;
        out.push_str(&validated.format_line());
        out.push_str(line_ending);
    }

    out.push_str(HOSTS_END_MARKER);
    out.push_str(line_ending);
    Ok(out)
}

struct LineSpan<'a> {
    start: usize,
    end_incl_nl: usize,
    content: &'a str,
}

fn scan_lines(text: &str) -> Vec<LineSpan<'_>> {
    let mut spans = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0_usize;
    let mut idx = 0_usize;

    while let Some(&b) = bytes.get(idx) {
        if b == b'\n' {
            let end_excl_lf = idx;
            let raw_slice = text.get(start..end_excl_lf).unwrap_or("");
            let content = raw_slice.strip_suffix('\r').unwrap_or(raw_slice);
            spans.push(LineSpan {
                start,
                end_incl_nl: idx + 1,
                content,
            });
            idx += 1;
            start = idx;
        } else {
            idx += 1;
        }
    }

    if start < text.len() {
        let raw_slice = text.get(start..).unwrap_or("");
        let content = raw_slice.strip_suffix('\r').unwrap_or(raw_slice);
        spans.push(LineSpan {
            start,
            end_incl_nl: text.len(),
            content,
        });
    }

    spans
}

fn locate_managed_block(text: &str) -> AppResult<Option<(usize, usize)>> {
    let spans = scan_lines(text);
    let mut begin_byte: Option<usize> = None;
    let mut found_range: Option<(usize, usize)> = None;

    for span in spans {
        if span.content == HOSTS_BEGIN_MARKER {
            if begin_byte.is_some() || found_range.is_some() {
                return Err(AppError::invalid_argument(
                    "duplicate # BEGIN mesh marker in hosts file",
                ));
            }
            begin_byte = Some(span.start);
        } else if span.content == HOSTS_END_MARKER {
            let Some(start) = begin_byte.take() else {
                return Err(AppError::invalid_argument(
                    "orphaned # END mesh marker without matching # BEGIN mesh",
                ));
            };
            found_range = Some((start, span.end_incl_nl));
        }
    }

    if begin_byte.is_some() {
        return Err(AppError::invalid_argument(
            "unclosed # BEGIN mesh marker without matching # END mesh",
        ));
    }

    Ok(found_range)
}

/// Inserts or replaces ONLY the `# BEGIN mesh ... # END mesh` section, preserving all unrelated
/// lines outside the markers verbatim.
pub fn render_hosts_with_block(
    existing: &str,
    entries: &[HostsEntry],
    public_server_host: Option<&str>,
) -> AppResult<String> {
    if entries.is_empty() {
        return remove_hosts_block(existing);
    }

    let line_ending = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let block = render_hosts_block(entries, public_server_host, line_ending)?;

    match locate_managed_block(existing)? {
        Some((start, end)) => {
            let prefix = existing.get(..start).unwrap_or("");
            let suffix = existing.get(end..).unwrap_or("");
            Ok(format!("{prefix}{block}{suffix}"))
        }
        None => {
            if existing.is_empty() {
                return Ok(block);
            }
            if existing.ends_with('\n') {
                Ok(format!("{existing}{block}"))
            } else {
                Ok(format!("{existing}{line_ending}{block}"))
            }
        }
    }
}

/// Removes ONLY the `# BEGIN mesh ... # END mesh` block while leaving every other line intact.
pub fn remove_hosts_block(existing: &str) -> AppResult<String> {
    let Some((start, end)) = locate_managed_block(existing)? else {
        return Ok(existing.to_owned());
    };
    let prefix = existing.get(..start).unwrap_or("");
    let suffix = existing.get(end..).unwrap_or("");
    Ok(format!("{prefix}{suffix}"))
}

/// Hosts file editor abstraction enabling deterministic in-memory unit testing.
pub trait HostsEditor: Send + Sync + std::fmt::Debug {
    /// Applies the full set of peer hosts entries under `# BEGIN mesh ... # END mesh`.
    fn apply(&self, entries: &[HostsEntry], public_server_host: Option<&str>) -> AppResult<()>;
    /// Removes the managed `# BEGIN mesh ... # END mesh` section.
    fn clear(&self) -> AppResult<()>;
    /// Resolves the canonical underlying file path (`None` for purely in-memory fakes).
    fn canonical_real_path(&self) -> AppResult<Option<PathBuf>>;
}

/// In-memory fake hosts editor preserving non-mesh content identically.
#[derive(Debug, Clone, Default)]
pub struct FakeHostsEditor {
    content: Arc<Mutex<String>>,
}

impl FakeHostsEditor {
    /// Creates a fake hosts editor seeded with initial hosts file contents.
    #[must_use]
    pub fn with_initial(initial: impl Into<String>) -> Self {
        Self {
            content: Arc::new(Mutex::new(initial.into())),
        }
    }

    /// Returns a snapshot of the current fake hosts file text.
    pub fn snapshot(&self) -> AppResult<String> {
        let guard = self
            .content
            .lock()
            .map_err(|_| AppError::internal("fake hosts mutex poisoned"))?;
        Ok(guard.clone())
    }
}

impl HostsEditor for FakeHostsEditor {
    fn apply(&self, entries: &[HostsEntry], public_server_host: Option<&str>) -> AppResult<()> {
        let mut guard = self
            .content
            .lock()
            .map_err(|_| AppError::internal("fake hosts mutex poisoned"))?;
        let updated = render_hosts_with_block(&guard, entries, public_server_host)?;
        *guard = updated;
        Ok(())
    }

    fn clear(&self) -> AppResult<()> {
        let mut guard = self
            .content
            .lock()
            .map_err(|_| AppError::internal("fake hosts mutex poisoned"))?;
        let updated = remove_hosts_block(&guard)?;
        *guard = updated;
        Ok(())
    }

    fn canonical_real_path(&self) -> AppResult<Option<PathBuf>> {
        Ok(None)
    }
}

/// Atomic filesystem hosts editor that preserves symlinks (such as macOS `/etc/hosts -> /private/etc/hosts`)
/// and falls back cleanly on container bind mounts (`US-038 AC2d`).
#[derive(Debug, Clone)]
pub struct FileHostsEditor {
    configured_path: PathBuf,
}

impl FileHostsEditor {
    /// Returns the OS default path for the system `hosts` file.
    #[must_use]
    pub fn default_hosts_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
        }
        #[cfg(not(target_os = "windows"))]
        {
            PathBuf::from("/etc/hosts")
        }
    }

    /// Creates a filesystem hosts editor targeting `path`.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self {
            configured_path: path,
        }
    }

    /// Creates an editor using the default OS hosts path.
    #[must_use]
    pub fn default_system() -> Self {
        Self::new(Self::default_hosts_path())
    }

    fn resolve_target(&self) -> AppResult<PathBuf> {
        fs::canonicalize(&self.configured_path).map_err(|err| {
            AppError::internal(format!(
                "failed to canonicalize hosts path {}: {err}",
                self.configured_path.display()
            ))
        })
    }

    fn write_target_atomic(&self, real_path: &Path, content: &[u8]) -> AppResult<()> {
        let parent = real_path
            .parent()
            .ok_or_else(|| AppError::internal("resolved hosts path has no parent directory"))?;
        let tmp_name = format!(
            ".{}.mesh.tmp.{}",
            real_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("hosts"),
            std::process::id()
        );
        let tmp_path = parent.join(tmp_name);

        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o644);
        }

        let write_tmp_res = (|| -> std::io::Result<()> {
            let mut tmp_file = opts.open(&tmp_path)?;
            tmp_file.write_all(content)?;
            tmp_file.sync_all()?;
            drop(tmp_file);
            fs::rename(&tmp_path, real_path)?;
            Ok(())
        })();

        match write_tmp_res {
            Ok(()) => Ok(()),
            Err(err) => {
                // Cleanup temp file if left behind; fall back to in-place truncate+write for
                // container bind mounts where rename(2) fails across mount points (EXDEV/EBUSY).
                if let Err(rm_err) = fs::remove_file(&tmp_path)
                    && rm_err.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(
                        component = "hosts",
                        event = "tmp_cleanup_failed",
                        error = %rm_err,
                        "failed to remove temporary hosts file"
                    );
                }

                tracing::debug!(
                    component = "hosts",
                    event = "atomic_rename_fallback",
                    error = %err,
                    "falling back to in-place hosts write for bind mount"
                );
                let mut file = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(real_path)
                    .map_err(|open_err| {
                        AppError::internal(format!(
                            "failed to write hosts {}: {open_err}",
                            real_path.display()
                        ))
                    })?;
                file.write_all(content).map_err(|w_err| {
                    AppError::internal(format!(
                        "failed to flush hosts {}: {w_err}",
                        real_path.display()
                    ))
                })?;
                file.sync_all().map_err(|s_err| {
                    AppError::internal(format!(
                        "failed to sync hosts {}: {s_err}",
                        real_path.display()
                    ))
                })
            }
        }
    }
}

impl HostsEditor for FileHostsEditor {
    fn apply(&self, entries: &[HostsEntry], public_server_host: Option<&str>) -> AppResult<()> {
        let real_path = self.resolve_target()?;
        let existing = fs::read_to_string(&real_path).map_err(|err| {
            AppError::internal(format!(
                "failed to read hosts {}: {err}",
                real_path.display()
            ))
        })?;
        let updated = render_hosts_with_block(&existing, entries, public_server_host)?;
        self.write_target_atomic(&real_path, updated.as_bytes())
    }

    fn clear(&self) -> AppResult<()> {
        let real_path = self.resolve_target()?;
        let existing = fs::read_to_string(&real_path).map_err(|err| {
            AppError::internal(format!(
                "failed to read hosts {}: {err}",
                real_path.display()
            ))
        })?;
        let updated = remove_hosts_block(&existing)?;
        if updated != existing {
            self.write_target_atomic(&real_path, updated.as_bytes())?;
        }
        Ok(())
    }

    fn canonical_real_path(&self) -> AppResult<Option<PathBuf>> {
        Ok(Some(self.resolve_target()?))
    }
}

/// Default domain suffix re-exported for callers building [`HostsEntry`] items.
#[must_use]
pub const fn default_domain_suffix() -> &'static str {
    DEFAULT_DOMAIN_SUFFIX
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mesh_core::brand::{DEFAULT_DOMAIN_SUFFIX, HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
    use mesh_core::{NodeName, OverlayIp};
    use proptest::prelude::*;

    use super::{
        FakeHostsEditor, HostsEditor, HostsEntry, remove_hosts_block, render_hosts_with_block,
    };

    #[test]
    fn test_hosts_rejects_public_host_collision_and_unclosed_marker() {
        // Arrange
        let ip = match OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 2)) {
            Ok(v) => v,
            Err(err) => {
                assert_eq!(err.to_string(), "ip parse failed");
                return;
            }
        };
        let name = match NodeName::parse("vps") {
            Ok(n) => n,
            Err(err) => {
                assert_eq!(err.to_string(), "name parse failed");
                return;
            }
        };

        // Act
        let collision = HostsEntry::new(ip, name, DEFAULT_DOMAIN_SUFFIX, Some("vps.mesh.internal"));
        let unclosed_input = format!("127.0.0.1 localhost\n{HOSTS_BEGIN_MARKER}\n");
        let unclosed = remove_hosts_block(&unclosed_input);

        // Assert
        assert!(collision.is_err());
        assert!(unclosed.is_err());
    }

    #[test]
    fn test_hosts_fake_editor_preserves_unrelated_lines_and_crlf() {
        // Arrange
        let initial = "127.0.0.1 localhost\r\n::1 localhost\r\n# user comment\r\n";
        let editor = FakeHostsEditor::with_initial(initial);
        let ip = match OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 10)) {
            Ok(v) => v,
            Err(err) => {
                assert_eq!(err.to_string(), "ip parse failed");
                return;
            }
        };
        let name = match NodeName::parse("laptop-01") {
            Ok(n) => n,
            Err(err) => {
                assert_eq!(err.to_string(), "name parse failed");
                return;
            }
        };
        let entry =
            match HostsEntry::new(ip, name, DEFAULT_DOMAIN_SUFFIX, Some("control.example.com")) {
                Ok(e) => e,
                Err(err) => {
                    assert_eq!(err.to_string(), "entry build failed");
                    return;
                }
            };

        // Act
        assert!(
            editor
                .apply(std::slice::from_ref(&entry), Some("control.example.com"))
                .is_ok()
        );
        let with_block = editor.snapshot().unwrap_or_default();
        assert!(with_block.contains("100.115.0.10 laptop-01.mesh.internal laptop-01\r\n"));
        assert!(editor.clear().is_ok());
        let cleared = editor.snapshot().unwrap_or_default();

        // Assert
        assert_eq!(cleared, initial);
        let ip_collision_res = HostsEntry::new(
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 10)).unwrap_or(entry.overlay_ip),
            entry.node_name.clone(),
            DEFAULT_DOMAIN_SUFFIX,
            Some("100.115.0.10"),
        );
        assert!(ip_collision_res.is_err());
    }

    #[test]
    fn test_hosts_file_editor_updates_canonical_file_cleanly() {
        // Arrange
        let dir = match tempfile::TempDir::new() {
            Ok(d) => d,
            Err(err) => {
                assert_eq!(err.to_string(), "tempdir failed");
                return;
            }
        };
        let hosts_path = dir.path().join("hosts");
        let original = "127.0.0.1 localhost\n";
        assert!(std::fs::write(&hosts_path, original).is_ok());
        let editor = super::FileHostsEditor::new(hosts_path.clone());
        let ip = match OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 15)) {
            Ok(v) => v,
            Err(err) => {
                assert_eq!(err.to_string(), "ip parse failed");
                return;
            }
        };
        let name = match NodeName::parse("vps-edge") {
            Ok(n) => n,
            Err(err) => {
                assert_eq!(err.to_string(), "name parse failed");
                return;
            }
        };
        let entry = match HostsEntry::new(ip, name, DEFAULT_DOMAIN_SUFFIX, Some("vpn.example.net"))
        {
            Ok(e) => e,
            Err(err) => {
                assert_eq!(err.to_string(), "entry build failed");
                return;
            }
        };

        // Act
        assert!(editor.apply(&[entry], Some("vpn.example.net")).is_ok());
        let updated = std::fs::read_to_string(&hosts_path).unwrap_or_default();
        assert!(updated.contains("100.115.0.15 vps-edge.mesh.internal vps-edge"));
        assert!(editor.canonical_real_path().is_ok_and(|p| p.is_some()));
        assert!(editor.clear().is_ok());
        let final_text = std::fs::read_to_string(&hosts_path).unwrap_or_default();

        // Assert
        assert_eq!(final_text, original);
    }

    proptest! {
        #[test]
        fn prop_hosts_round_trip_preserves_unrelated_lines(
            prefix_lines in proptest::collection::vec("[a-z0-9. -]{1,40}", 1..8),
            node_label in "[a-z][a-z0-9]{1,12}",
            host_octet in 2_u8..250_u8,
        ) {
            prop_assume!(!mesh_core::brand::RESERVED_HOSTNAMES.contains(&node_label.as_str()));
            let original = format!("{}\n", prefix_lines.join("\n"));
            let ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, host_octet))
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let name = NodeName::parse(&node_label).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let entry = HostsEntry::new(ip, name, DEFAULT_DOMAIN_SUFFIX, Some("vpn.example.org"))
                .map_err(|e| TestCaseError::fail(e.to_string()))?;

            let rendered = render_hosts_with_block(&original, &[entry], Some("vpn.example.org"))
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let restored = remove_hosts_block(&rendered)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;

            prop_assert!(rendered.contains(HOSTS_BEGIN_MARKER));
            prop_assert!(rendered.contains(HOSTS_END_MARKER));
            prop_assert_eq!(restored, original);
        }
    }
}
