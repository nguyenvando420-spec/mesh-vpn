//! Scrubbed streaming POSIX ustar bugreport archive builder (`US-041`, `HR-MOB-G2-04`, `ADR-016`).

use std::fs::{self, File};
use std::io::{BufWriter, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use mesh_core::defaults::DEFAULT_MOBILE_MAX_BUGREPORT_BYTES;
use mesh_core::{AppError, AppResult};
use mesh_proto::agent_ipc::{AgentStatusResponse, BugreportResponse, NetcheckResponse};
use mesh_proto::control::TargetOs;

use crate::config::{
    BootstrapConfig, create_private_file_handle, current_target_arch, current_target_os,
    promote_private_temp_file, remove_temp_best_effort, temp_sibling_path,
};
use crate::hooks::ClientPlatformHooks;

/// Streaming `BufWriter` buffer size used when emitting `.tar` archives (`8 KiB`, `ADR-016`).
pub const TAR_STREAM_BUFFER_BYTES: usize = 8 * 1024;

const TAR_BLOCK_SIZE: usize = 512;
const TAR_END_MARKER_BYTES: usize = 1024;
const REDACTED_SECRET_PLACEHOLDER: &str = "[REDACTED_SECRET]";
const REDACTED_BEARER_PLACEHOLDER: &str = "[REDACTED_BEARER]";

/// Inputs for generating a scrubbed, streaming `.tar` diagnostic archive.
pub struct BugreportBuildOptions<'a> {
    /// Target directory where `mesh-bugreport-<now_unix_ms>.tar` is atomically written.
    pub output_dir: &'a Path,
    /// Hard archive byte ceiling (`<= 1 MiB` on Mobile, `<= 20 MiB` on Desktop).
    pub max_total_bytes: usize,
    /// Reported component/binary name inside `version.txt`.
    pub binary_name: &'a str,
    /// Reported software version inside `version.txt`.
    pub agent_version: &'a str,
    /// Current bootstrap config (sanitized before inclusion).
    pub bootstrap: &'a BootstrapConfig,
    /// Latest agent status snapshot.
    pub status: &'a AgentStatusResponse,
    /// Latest netcheck outcome or offline error summary.
    pub netcheck: Result<&'a NetcheckResponse, &'a str>,
    /// Platform hooks providing OS-safe route diagnostics (`0 sysexec` on Mobile).
    pub platform_hooks: &'a dyn ClientPlatformHooks,
    /// Directories scanned for rotated `.log` / `*mesh*` log files.
    pub log_dirs: &'a [PathBuf],
    /// Optional in-memory ring-buffer log text supplied by mobile extensions.
    pub in_memory_logs: Option<&'a str>,
    /// UTC timestamp in milliseconds for `version.txt`, tar mtime, and output filename.
    pub now_unix_ms: u64,
}

impl std::fmt::Debug for BugreportBuildOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BugreportBuildOptions")
            .field("output_dir", &self.output_dir)
            .field("max_total_bytes", &self.max_total_bytes)
            .field("binary_name", &self.binary_name)
            .field("agent_version", &self.agent_version)
            .field("now_unix_ms", &self.now_unix_ms)
            .finish_non_exhaustive()
    }
}

/// Streaming pure-Rust POSIX ustar `.tar` archive builder backed by an 8 KiB [`BufWriter`].
pub struct BoundedTarArchive<W: std::io::Write> {
    writer: BufWriter<W>,
    written_bytes: usize,
    max_total_bytes: usize,
    mtime_secs: u64,
}

impl<W: std::io::Write> std::fmt::Debug for BoundedTarArchive<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedTarArchive")
            .field("written_bytes", &self.written_bytes)
            .field("max_total_bytes", &self.max_total_bytes)
            .field("mtime_secs", &self.mtime_secs)
            .finish_non_exhaustive()
    }
}

impl<W: std::io::Write> BoundedTarArchive<W> {
    /// Creates a streaming archive writing into `writer` with `8 KiB` internal buffering.
    pub fn new(writer: W, max_total_bytes: usize, mtime_secs: u64) -> Self {
        Self {
            writer: BufWriter::with_capacity(TAR_STREAM_BUFFER_BYTES, writer),
            written_bytes: 0,
            max_total_bytes: max_total_bytes.max(TAR_END_MARKER_BYTES + TAR_BLOCK_SIZE * 2),
            mtime_secs,
        }
    }

    /// Creates a mobile-bounded (`<= 1 MiB`) streaming archive builder.
    pub fn new_mobile(writer: W, mtime_secs: u64) -> Self {
        Self::new(writer, DEFAULT_MOBILE_MAX_BUGREPORT_BYTES, mtime_secs)
    }

    /// Returns remaining 512-byte-aligned payload room before hitting `max_total_bytes`.
    #[must_use]
    pub fn remaining_payload_budget(&self) -> usize {
        let reserved = self
            .written_bytes
            .saturating_add(TAR_BLOCK_SIZE)
            .saturating_add(TAR_END_MARKER_BYTES);
        let raw = self.max_total_bytes.saturating_sub(reserved);
        (raw / TAR_BLOCK_SIZE).saturating_mul(TAR_BLOCK_SIZE)
    }

    /// Streams one archive member up to [`Self::remaining_payload_budget`], padded to 512 bytes.
    pub fn append_text_entry(&mut self, name: &str, content: &[u8]) -> AppResult<()> {
        let budget = self.remaining_payload_budget();
        if budget == 0 {
            return Ok(());
        }
        let write_len = content.len().min(budget);
        let header = build_ustar_header(name, write_len, self.mtime_secs);
        self.write_all_counted(&header)?;
        if let Some(slice) = content.get(..write_len) {
            self.write_all_counted(slice)?;
        }
        let rem = write_len % TAR_BLOCK_SIZE;
        if rem != 0 {
            let pad = [0_u8; TAR_BLOCK_SIZE];
            if let Some(pad_slice) = pad.get(..(TAR_BLOCK_SIZE - rem)) {
                self.write_all_counted(pad_slice)?;
            }
        }
        Ok(())
    }

    /// Appends an in-memory log string, preserving only the newest newline-aligned lines on budget overflow.
    pub fn append_tail_truncated_log(&mut self, archive_name: &str, text: &str) -> AppResult<()> {
        let budget = self.remaining_payload_budget();
        if budget == 0 {
            return Ok(());
        }
        let raw = text.as_bytes();
        if raw.len() <= budget {
            return self.append_text_entry(archive_name, raw);
        }
        let truncated = truncate_bytes_to_tail(raw, budget, self.max_total_bytes);
        self.append_text_entry(archive_name, &truncated)
    }

    /// Streams ONLY the tail (`<= remaining_payload_budget`) of an on-disk log file, scrubbing secrets
    /// without ever reading an entire oversized log file into RAM (`HR-MOB-G2-04`).
    pub fn append_stream_tail_log_file(
        &mut self,
        archive_name: &str,
        file_path: &Path,
    ) -> AppResult<usize> {
        let budget = self.remaining_payload_budget();
        if budget < TAR_BLOCK_SIZE * 2 {
            return Ok(0);
        }
        let mut file = File::open(file_path).map_err(|err| {
            AppError::internal(format!(
                "failed opening log file {} for bugreport: {err}",
                file_path.display()
            ))
        })?;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let window = u64::try_from(budget).unwrap_or(u64::MAX);
        let truncated_head = file_len > window;
        if truncated_head {
            let skip = file_len.saturating_sub(window);
            file.seek(SeekFrom::Start(skip)).map_err(|err| {
                AppError::internal(format!(
                    "failed seeking tail of {}: {err}",
                    file_path.display()
                ))
            })?;
        }
        let tail_buf = read_bounded_chunks(&mut file, budget)?;
        let lossy = String::from_utf8_lossy(&tail_buf);
        let aligned = if truncated_head {
            skip_partial_leading_line(&lossy)
        } else {
            lossy.as_ref()
        };
        let (clean, scrubbed_cnt) = scrub_diagnostic_secrets(aligned);
        if truncated_head {
            let banner = truncation_banner_bytes(self.max_total_bytes);
            let combined = combine_banner_and_tail(banner, clean.as_bytes(), budget);
            self.append_text_entry(archive_name, &combined)?;
        } else {
            self.append_tail_truncated_log(archive_name, &clean)?;
        }
        Ok(scrubbed_cnt)
    }

    /// Writes the POSIX 1024-byte end-of-archive marker, flushes the `BufWriter`, and returns total bytes.
    pub fn finish(mut self) -> AppResult<usize> {
        let end_marker = [0_u8; TAR_END_MARKER_BYTES];
        self.write_all_counted(&end_marker)?;
        self.writer
            .flush()
            .map_err(|err| AppError::internal(format!("failed flushing bugreport tar: {err}")))?;
        Ok(self.written_bytes)
    }

    fn write_all_counted(&mut self, data: &[u8]) -> AppResult<()> {
        self.writer
            .write_all(data)
            .map_err(|err| AppError::internal(format!("failed writing bugreport stream: {err}")))?;
        self.written_bytes = self.written_bytes.saturating_add(data.len());
        Ok(())
    }
}

fn read_bounded_chunks(file: &mut File, max_bytes: usize) -> AppResult<Vec<u8>> {
    let mut out = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut chunk = [0_u8; TAR_STREAM_BUFFER_BYTES];
    while out.len() < max_bytes {
        let room = max_bytes.saturating_sub(out.len()).min(chunk.len());
        let Some(slice) = chunk.get_mut(..room) else {
            break;
        };
        let read_n = file
            .read(slice)
            .map_err(|err| AppError::internal(format!("failed reading log chunk: {err}")))?;
        if read_n == 0 {
            break;
        }
        if let Some(filled) = slice.get(..read_n) {
            out.extend_from_slice(filled);
        }
    }
    Ok(out)
}

fn skip_partial_leading_line(s: &str) -> &str {
    match s.find('\n') {
        Some(pos) => s.get(pos + 1..).unwrap_or(""),
        None => s,
    }
}

fn truncation_banner_bytes(max_total_bytes: usize) -> Vec<u8> {
    let label = if max_total_bytes <= DEFAULT_MOBILE_MAX_BUGREPORT_BYTES {
        "1 MiB"
    } else {
        "20 MiB"
    };
    format!("[... older log lines truncated to obey {label} bugreport limit ...]\n").into_bytes()
}

fn truncate_bytes_to_tail(raw: &[u8], budget: usize, max_total_bytes: usize) -> Vec<u8> {
    let banner = truncation_banner_bytes(max_total_bytes);
    combine_banner_and_tail(banner, raw, budget)
}

fn combine_banner_and_tail(banner: Vec<u8>, raw: &[u8], budget: usize) -> Vec<u8> {
    let tail_room = budget.saturating_sub(banner.len());
    if raw.len() <= tail_room {
        let mut combined = Vec::with_capacity(banner.len() + raw.len());
        combined.extend_from_slice(&banner);
        combined.extend_from_slice(raw);
        return combined;
    }
    let tail_start = raw.len().saturating_sub(tail_room);
    let aligned_start = raw
        .get(tail_start..)
        .and_then(|s| s.iter().position(|&b| b == b'\n'))
        .map_or(tail_start, |pos| (tail_start + pos + 1).min(raw.len()));
    let mut combined = Vec::with_capacity(budget);
    combined.extend_from_slice(&banner);
    if let Some(tail) = raw.get(aligned_start..) {
        let copy_len = tail.len().min(budget.saturating_sub(combined.len()));
        if let Some(sl) = tail.get(..copy_len) {
            combined.extend_from_slice(sl);
        }
    }
    combined
}

/// Streams a scrubbed, bounded POSIX `.tar` diagnostic archive to `<output_dir>/mesh-bugreport-<ts>.tar`.
pub fn create_bugreport_tar_bundle(
    opts: BugreportBuildOptions<'_>,
) -> AppResult<BugreportResponse> {
    let bundle_path = opts
        .output_dir
        .join(format!("mesh-bugreport-{}.tar", opts.now_unix_ms));
    let tmp_path = temp_sibling_path(opts.output_dir, &bundle_path);
    let tmp_file = create_private_file_handle(opts.output_dir, &tmp_path)?;

    let mtime_secs = opts.now_unix_ms / 1000;
    let mut archive = BoundedTarArchive::new(tmp_file, opts.max_total_bytes, mtime_secs);
    let mut scrubbed_total = 0usize;

    let res = populate_bugreport_archive(&mut archive, &opts, &mut scrubbed_total);
    if let Err(err) = res {
        drop(archive);
        remove_temp_best_effort(&tmp_path);
        return Err(err);
    }

    let size_bytes = match finish_archive_to_file(archive) {
        Ok((file, total)) => {
            promote_private_temp_file(file, &tmp_path, &bundle_path)?;
            total
        }
        Err(err) => {
            remove_temp_best_effort(&tmp_path);
            return Err(err);
        }
    };

    Ok(BugreportResponse {
        bundle_path: bundle_path.to_string_lossy().into_owned(),
        size_bytes: u64::try_from(size_bytes).unwrap_or(u64::MAX),
        scrubbed_items: u32::try_from(scrubbed_total).unwrap_or(u32::MAX),
    })
}

fn finish_archive_to_file(mut archive: BoundedTarArchive<File>) -> AppResult<(File, usize)> {
    let end_marker = [0_u8; TAR_END_MARKER_BYTES];
    archive.write_all_counted(&end_marker)?;
    archive
        .writer
        .flush()
        .map_err(|err| AppError::internal(format!("failed flushing bugreport tar: {err}")))?;
    let written = archive.written_bytes;
    let file = archive
        .writer
        .into_inner()
        .map_err(|err| AppError::internal(format!("failed finalizing bugreport writer: {err}")))?;
    Ok((file, written))
}

fn populate_bugreport_archive(
    archive: &mut BoundedTarArchive<File>,
    opts: &BugreportBuildOptions<'_>,
    scrubbed_total: &mut usize,
) -> AppResult<()> {
    let version_text = build_version_text(opts);
    append_scrubbed_entry(archive, "version.txt", &version_text, scrubbed_total)?;

    let status_json = serde_json::to_string_pretty(opts.status)
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
    append_scrubbed_entry(archive, "status.json", &status_json, scrubbed_total)?;

    let netcheck_json = match opts.netcheck {
        Ok(nc) => {
            serde_json::to_string_pretty(nc).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        }
        Err(err) => format!(
            "{{\"error\":{}}}",
            serde_json::to_string(err).unwrap_or_default()
        ),
    };
    append_scrubbed_entry(archive, "netcheck.json", &netcheck_json, scrubbed_total)?;

    let bootstrap_toml = toml::to_string_pretty(opts.bootstrap).unwrap_or_default();
    append_scrubbed_entry(
        archive,
        "bootstrap-sanitized.toml",
        &bootstrap_toml,
        scrubbed_total,
    )?;

    let routes_raw = opts.platform_hooks.collect_route_diagnostics();
    append_scrubbed_entry(archive, "routes.txt", &routes_raw, scrubbed_total)?;

    if let Some(mem_logs) = opts.in_memory_logs {
        let (clean, cnt) = scrub_diagnostic_secrets(mem_logs);
        *scrubbed_total = scrubbed_total.saturating_add(cnt);
        archive.append_tail_truncated_log("logs/mobile-ring.log", &clean)?;
    }

    for log_path in collect_sorted_log_paths(opts.log_dirs) {
        if archive.remaining_payload_budget() < TAR_BLOCK_SIZE * 4 {
            break;
        }
        let fname = log_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("meshd.log");
        if let Ok(cnt) = archive.append_stream_tail_log_file(&format!("logs/{fname}"), &log_path) {
            *scrubbed_total = scrubbed_total.saturating_add(cnt);
        }
    }
    Ok(())
}

fn append_scrubbed_entry(
    archive: &mut BoundedTarArchive<File>,
    name: &str,
    raw: &str,
    scrubbed_total: &mut usize,
) -> AppResult<()> {
    let (clean, cnt) = scrub_diagnostic_secrets(raw);
    *scrubbed_total = scrubbed_total.saturating_add(cnt);
    archive.append_text_entry(name, clean.as_bytes())
}

fn build_version_text(opts: &BugreportBuildOptions<'_>) -> String {
    let target_os = match current_target_os() {
        TargetOs::Android => "android",
        TargetOs::Ios => "ios",
        TargetOs::Darwin => "macos",
        TargetOs::Windows => "windows",
        TargetOs::Linux => "linux",
    };
    let arch = match current_target_arch() {
        mesh_proto::control::TargetArch::Amd64 => "amd64",
        mesh_proto::control::TargetArch::Arm64 => "arm64",
    };
    format!(
        "binary={}\nversion={}\nos={target_os}\narch={arch}\ncreated_at_ms={}\n",
        opts.binary_name, opts.agent_version, opts.now_unix_ms
    )
}

fn collect_sorted_log_paths(log_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut log_paths: Vec<PathBuf> = Vec::new();
    for dir in log_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for ent in entries.flatten() {
                let p = ent.path();
                if p.is_file() {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.contains("mesh") || name.ends_with(".log") {
                        log_paths.push(p);
                    }
                }
            }
        }
    }
    log_paths.sort_by(|a, b| {
        let ma = fs::metadata(a).and_then(|m| m.modified()).ok();
        let mb = fs::metadata(b).and_then(|m| m.modified()).ok();
        mb.cmp(&ma).then_with(|| a.cmp(b))
    });
    log_paths.dedup();
    log_paths
}

fn build_ustar_header(name: &str, size: usize, mtime_secs: u64) -> [u8; TAR_BLOCK_SIZE] {
    let mut hdr = [0_u8; TAR_BLOCK_SIZE];
    let safe_name: String = name
        .trim_start_matches(['/', '\\'])
        .replace("..", "_")
        .chars()
        .take(99)
        .collect();
    write_tar_bytes(hdr.get_mut(0..100), safe_name.as_bytes());
    write_tar_bytes(hdr.get_mut(100..108), b"0000644\0");
    write_tar_bytes(hdr.get_mut(108..116), b"0000000\0");
    write_tar_bytes(hdr.get_mut(116..124), b"0000000\0");
    let size_oct = format!("{size:011o}\0");
    write_tar_bytes(hdr.get_mut(124..136), size_oct.as_bytes());
    let mtime_oct = format!("{mtime_secs:011o}\0");
    write_tar_bytes(hdr.get_mut(136..148), mtime_oct.as_bytes());
    write_tar_bytes(hdr.get_mut(148..156), b"        ");
    if let Some(t) = hdr.get_mut(156) {
        *t = b'0';
    }
    write_tar_bytes(hdr.get_mut(257..263), b"ustar\0");
    write_tar_bytes(hdr.get_mut(263..265), b"00");
    let checksum: u32 = hdr.iter().map(|&b| u32::from(b)).sum();
    let chk_oct = format!("{checksum:06o}\0 ");
    write_tar_bytes(hdr.get_mut(148..156), chk_oct.as_bytes());
    hdr
}

fn write_tar_bytes(dest: Option<&mut [u8]>, src: &[u8]) {
    if let Some(buf) = dest {
        let n = buf.len().min(src.len());
        if let (Some(d), Some(s)) = (buf.get_mut(..n), src.get(..n)) {
            d.copy_from_slice(s);
        }
    }
}

/// Sanitizes diagnostic text by redacting all pre-auth tokens (`mpk_*`), Bearer/JWT tokens,
/// PEM private keys, and secret key-value fields (`US-041 AC2`).
#[must_use]
pub fn scrub_diagnostic_secrets(input: &str) -> (String, usize) {
    let mut scrubbed_count = 0usize;
    let pem_redacted = redact_pem_private_keys(input, &mut scrubbed_count);
    let mpk_redacted = redact_prefixed_tokens(&pem_redacted, "mpk_", &mut scrubbed_count);
    let bearer_redacted = redact_bearer_tokens(&mpk_redacted, &mut scrubbed_count);

    let mut out = String::with_capacity(bearer_redacted.len());
    for (idx, line) in bearer_redacted.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let cleaned_line = redact_secret_kv_line(line, &mut scrubbed_count);
        out.push_str(&cleaned_line);
    }
    (out, scrubbed_count)
}

fn redact_pem_private_keys(input: &str, count: &mut usize) -> String {
    const BEGIN_MARKER: &str = "-----BEGIN ";
    const END_MARKER: &str = "-----END ";
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(BEGIN_MARKER) {
        let prefix = rest.get(..start).unwrap_or("");
        out.push_str(prefix);
        let after_begin = rest.get(start..).unwrap_or("");
        if let Some(first_line_end) = after_begin.find('\n') {
            let header = after_begin.get(..first_line_end).unwrap_or("");
            if header.contains("PRIVATE KEY")
                && let Some(end_idx) = after_begin.find(END_MARKER)
                && let Some(after_end) = after_begin.get(end_idx..)
            {
                let close_offset = after_end.find('\n').map_or(after_end.len(), |p| p + 1);
                out.push_str("[REDACTED_PRIVATE_KEY]\n");
                *count = count.saturating_add(1);
                rest = after_end.get(close_offset..).unwrap_or("");
                continue;
            }
        }
        out.push_str(BEGIN_MARKER);
        rest = rest.get(start + BEGIN_MARKER.len()..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

fn redact_prefixed_tokens(input: &str, prefix: &str, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let lower_prefix = prefix.to_ascii_lowercase();
    let mut idx = 0usize;
    while idx < input.len() {
        let slice_lower = lower.get(idx..).unwrap_or("");
        let Some(rel_pos) = slice_lower.find(&lower_prefix) else {
            out.push_str(input.get(idx..).unwrap_or(""));
            break;
        };
        let abs_pos = idx + rel_pos;
        out.push_str(input.get(idx..abs_pos).unwrap_or(""));
        let token_tail = input.get(abs_pos..).unwrap_or("");
        let tok_len = token_tail
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+'))
            .count();
        if tok_len > prefix.len() {
            out.push_str(REDACTED_SECRET_PLACEHOLDER);
            *count = count.saturating_add(1);
            idx = abs_pos + tok_len;
        } else {
            out.push_str(input.get(abs_pos..abs_pos + prefix.len()).unwrap_or(prefix));
            idx = abs_pos + prefix.len();
        }
    }
    out
}

fn redact_bearer_tokens(input: &str, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let needle = "bearer ";
    let mut idx = 0usize;
    while idx < input.len() {
        let slice_lower = lower.get(idx..).unwrap_or("");
        let Some(rel) = slice_lower.find(needle) else {
            out.push_str(input.get(idx..).unwrap_or(""));
            break;
        };
        let abs = idx + rel;
        out.push_str(input.get(idx..abs + needle.len()).unwrap_or(""));
        let rest = input.get(abs + needle.len()..).unwrap_or("");
        let tok_len = rest
            .bytes()
            .take_while(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/' | b'=' | b'~')
            })
            .count();
        if tok_len > 0 {
            out.push_str(REDACTED_BEARER_PLACEHOLDER);
            *count = count.saturating_add(1);
            idx = abs + needle.len() + tok_len;
        } else {
            idx = abs + needle.len();
        }
    }
    out
}

fn redact_secret_kv_line(line: &str, count: &mut usize) -> String {
    const SECRET_KEYS: [&str; 22] = [
        "node_secret",
        "disco_secret",
        "tls_private_key",
        "private_key",
        "secret_key",
        "preauth_key",
        "pre_auth_key",
        "pre_auth_token",
        "authkey",
        "password",
        "passphrase",
        "api_token",
        "access_token",
        "secret_bytes",
        "wireguard_key",
        "noise_key",
        "node_privkey_hex",
        "disco_privkey_hex",
        "x-mesh-auth-proof",
        "x-mesh-box-nonce",
        "authorization",
        "jwt",
    ];

    let lower = line.to_ascii_lowercase();
    let bytes = line.as_bytes();
    let lower_bytes = lower.as_bytes();
    let mut out = String::with_capacity(line.len() + 24);
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let Some(rel_sep) = bytes
            .get(cursor..)
            .and_then(|rest| rest.iter().position(|&b| b == b':' || b == b'='))
        else {
            break;
        };
        let sep_idx = cursor + rel_sep;
        let next_after_sep = advance_to_char_boundary(line, sep_idx + 1);
        let Some(key_end) = trim_kv_key_padding_before_sep(bytes, cursor, sep_idx) else {
            out.push_str(line.get(cursor..next_after_sep).unwrap_or(""));
            cursor = next_after_sep;
            continue;
        };
        let matched = lower.get(..key_end).is_some_and(|prefix| {
            matches_secret_key_suffix(prefix, lower_bytes, cursor, &SECRET_KEYS)
        });
        if !matched {
            out.push_str(line.get(cursor..next_after_sep).unwrap_or(""));
            cursor = next_after_sep;
            continue;
        }
        cursor = write_redacted_kv_value(line, cursor, sep_idx, next_after_sep, &mut out, count);
    }

    if cursor < line.len() {
        out.push_str(line.get(cursor..).unwrap_or(""));
    }
    out
}

fn write_redacted_kv_value(
    line: &str,
    cursor: usize,
    sep_idx: usize,
    next_after_sep: usize,
    out: &mut String,
    count: &mut usize,
) -> usize {
    let bytes = line.as_bytes();
    let val_start = skip_ascii_ws(bytes, sep_idx + 1);
    if val_start >= bytes.len() {
        out.push_str(line.get(cursor..next_after_sep).unwrap_or(""));
        return next_after_sep;
    }
    let val_rest = line.get(val_start..).unwrap_or("");
    if let Some(already_len) = already_redacted_prefix_len(val_rest) {
        let next = advance_to_char_boundary(line, val_start + already_len);
        out.push_str(line.get(cursor..next).unwrap_or(""));
        return next.max(next_after_sep);
    }
    let first = bytes.get(val_start).copied().unwrap_or(0);
    out.push_str(line.get(cursor..val_start).unwrap_or(""));
    let val_end = match first {
        b'"' | b'\'' => {
            let end = scan_quoted_value_end(line, val_start, first);
            let quote_ch = char::from(first);
            out.push(quote_ch);
            out.push_str(REDACTED_SECRET_PLACEHOLDER);
            out.push(quote_ch);
            end
        }
        b'{' | b'[' => {
            let end = scan_nested_json_value_end(line, val_start);
            out.push('"');
            out.push_str(REDACTED_SECRET_PLACEHOLDER);
            out.push('"');
            end
        }
        _ => {
            let end = scan_unquoted_value_end(line, val_start);
            out.push_str(REDACTED_SECRET_PLACEHOLDER);
            end
        }
    };
    *count = count.saturating_add(1);
    advance_to_char_boundary(line, val_end.max(next_after_sep))
}

fn trim_kv_key_padding_before_sep(bytes: &[u8], cursor: usize, sep_idx: usize) -> Option<usize> {
    let mut i = sep_idx;
    while i > cursor {
        let prev = bytes.get(i - 1).copied()?;
        if matches!(prev, b'"' | b'\'' | b' ' | b'\t') {
            i -= 1;
            if matches!(prev, b'"' | b'\'')
                && i > cursor
                && bytes.get(i - 1).copied() == Some(b'\\')
            {
                i -= 1;
            }
        } else {
            break;
        }
    }
    (i > cursor).then_some(i)
}

fn matches_secret_key_suffix(
    lower_prefix: &str,
    lower_bytes: &[u8],
    min_start: usize,
    secret_keys: &[&str],
) -> bool {
    let key_end = lower_prefix.len();
    for &key in secret_keys {
        if key_end >= min_start + key.len() && lower_prefix.ends_with(key) {
            let key_start = key_end - key.len();
            if key_start == 0 {
                return true;
            }
            let prev = lower_bytes.get(key_start - 1).copied().unwrap_or(b' ');
            if !prev.is_ascii_alphanumeric() && prev != b'_' {
                return true;
            }
        }
    }
    false
}

fn skip_ascii_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if matches!(bytes.get(i).copied(), Some(b' ' | b'\t')) {
            i += 1;
        } else {
            break;
        }
    }
    i
}

fn already_redacted_prefix_len(val_rest: &str) -> Option<usize> {
    if val_rest.starts_with(REDACTED_BEARER_PLACEHOLDER) {
        return Some(REDACTED_BEARER_PLACEHOLDER.len());
    }
    if val_rest.starts_with(REDACTED_SECRET_PLACEHOLDER) {
        return Some(REDACTED_SECRET_PLACEHOLDER.len());
    }
    let quoted_len = REDACTED_SECRET_PLACEHOLDER.len() + 2;
    if (val_rest.starts_with('"') || val_rest.starts_with('\''))
        && val_rest
            .get(1..)
            .is_some_and(|inner| inner.starts_with(REDACTED_SECRET_PLACEHOLDER))
    {
        return Some(val_rest.len().min(quoted_len));
    }
    None
}

fn advance_to_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn scan_quoted_value_end(line: &str, val_start: usize, quote: u8) -> usize {
    let bytes = line.as_bytes();
    let mut i = val_start + 1;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes.get(i).copied().unwrap_or(0);
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if b == quote {
            return advance_to_char_boundary(line, i + 1);
        }
        i += 1;
    }
    line.len()
}

fn scan_nested_json_value_end(line: &str, val_start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut i = val_start;
    let mut depth = 0usize;
    let mut in_string: Option<u8> = None;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes.get(i).copied().unwrap_or(0);
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == quote {
                in_string = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => in_string = Some(b),
            b'{' | b'[' => depth = depth.saturating_add(1),
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return advance_to_char_boundary(line, i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    line.len()
}

fn scan_unquoted_value_end(line: &str, val_start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut i = val_start;
    while i < bytes.len() {
        let b = bytes.get(i).copied().unwrap_or(0);
        if matches!(
            b,
            b' ' | b'\t' | b'\r' | b',' | b'}' | b']' | b';' | b'"' | b'\''
        ) {
            break;
        }
        i += 1;
    }
    advance_to_char_boundary(line, i)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use mesh_core::defaults::DEFAULT_MOBILE_MAX_BUGREPORT_BYTES;
    use mesh_proto::agent_ipc::{AgentStatusResponse, DaemonState, SelfNetworkStatus};
    use mesh_proto::netmap::NatMappingKind;
    use tempfile::tempdir;

    use super::{BugreportBuildOptions, create_bugreport_tar_bundle};
    use crate::config::BootstrapConfig;
    use crate::hooks::InMemoryClientPlatformHooks;

    fn empty_status() -> AgentStatusResponse {
        AgentStatusResponse {
            daemon_state: DaemonState::Connected,
            node_id: None,
            node_name: None,
            fqdn: None,
            overlay_ip: None,
            overlay_cidr: None,
            tun_interface_name: None,
            tun_mtu: 1280,
            netmap_version: 1,
            key_expires_at_ms: None,
            server_connection: None,
            self_network: SelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: None,
                nat_type: NatMappingKind::EimOrAdm,
                nat_classification_note: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                candidates: Vec::new(),
            },
            peers: Vec::new(),
        }
    }

    #[test]
    fn test_streaming_mobile_bugreport_caps_at_1_mib_and_scrubs_secrets() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("mkdir");
        let log_path = log_dir.join("mesh-mobile.log");
        let mut f = std::fs::File::create(&log_path).expect("create log");
        writeln!(
            f,
            "early mpk_EARLY_SHOULD_TRUNCATE_AND_MASK Authorization: Bearer JWT_SECRET_A"
        )
        .expect("write");
        let line = b"INFO client heartbeat ok overlay=100.115.0.2\n";
        for _ in 0..80_000 {
            f.write_all(line).expect("write filler");
        }
        writeln!(
            f,
            "tail mpk_TAIL_CANARY_XYZ node_privkey_hex=deadbeefcafebabe"
        )
        .expect("tail");
        f.sync_all().expect("sync");

        let hooks = InMemoryClientPlatformHooks::default();
        let status = empty_status();

        // Act
        let resp = create_bugreport_tar_bundle(BugreportBuildOptions {
            output_dir: dir.path(),
            max_total_bytes: DEFAULT_MOBILE_MAX_BUGREPORT_BYTES,
            binary_name: "mesh-mobile",
            agent_version: "0.2.0",
            bootstrap: &BootstrapConfig::default(),
            status: &status,
            netcheck: Err("offline"),
            platform_hooks: &hooks,
            log_dirs: &[log_dir],
            in_memory_logs: Some("inmem pre_auth_token=mpk_INMEM_CANARY\n"),
            now_unix_ms: 1_700_000_000_000,
        })
        .expect("bugreport");

        // Assert
        let archive_bytes = std::fs::read(&resp.bundle_path).expect("read tar");
        assert!(archive_bytes.len() <= DEFAULT_MOBILE_MAX_BUGREPORT_BYTES);
        assert_eq!(resp.size_bytes as usize, archive_bytes.len());
        assert_eq!(archive_bytes.len() % 512, 0);
        assert!(resp.scrubbed_items >= 3);
        let text = String::from_utf8_lossy(&archive_bytes);
        assert!(!text.contains("mpk_EARLY_SHOULD_TRUNCATE_AND_MASK"));
        assert!(!text.contains("mpk_TAIL_CANARY_XYZ"));
        assert!(!text.contains("deadbeefcafebabe"));
        assert!(!text.contains("mpk_INMEM_CANARY"));
        assert!(text.contains("fake-in-memory-route-table"));
    }

    #[test]
    fn test_redact_secret_kv_line_scrubs_15_plus_canary_secrets_escaped_and_nested() {
        // Arrange
        let json_line = concat!(
            "{",
            "\"safe_node\":\"macbook-1\",",
            "\"node_secret\":\"CANARY_01_escaped\\\"quote\",",
            "\"disco_secret\":\"CANARY_02_secret\",",
            "\"tls_private_key\":\"CANARY_03_pem_body\",",
            "\"private_key\":\"CANARY_04_raw_hex\",",
            "\"secret_key\":{\"nested_inner\":\"CANARY_05_nested_obj\",\"arr\":[\"CANARY_06_arr\"]},",
            "\"preauth_key\":\"CANARY_07_preauth\",",
            "\"pre_auth_key\":\"CANARY_08_pre_auth\",",
            "\"authkey\":\"CANARY_09_authkey\",",
            "\"password\":\"CANARY_10_pw\\\"escaped\",",
            "\"passphrase\":\"CANARY_11_passphrase\",",
            "\"api_token\":\"CANARY_12_api_tok\",",
            "\"access_token\":\"CANARY_13_access_tok\",",
            "\"secret_bytes\":[1,2,\"CANARY_14_bytes\"],",
            "\"wireguard_key\":\"CANARY_15_wg_key\",",
            "\"noise_key\":\"CANARY_16_noise_key\",",
            "\"x-mesh-auth-proof\":\"CANARY_17_proof\",",
            "\"x-mesh-box-nonce\":\"CANARY_18_nonce\",",
            "\"authorization\":\"CANARY_19_authz\",",
            "\"jwt\":\"CANARY_20_jwt_tail\"",
            "}"
        );

        // Act
        let (scrubbed, scrubbed_count) = super::scrub_diagnostic_secrets(json_line);

        // Assert
        assert!(
            scrubbed_count >= 19,
            "expected all 19 secret fields redacted, got {scrubbed_count}: {scrubbed}"
        );
        for idx in 1..=20 {
            let marker = format!("CANARY_{idx:02}_");
            assert!(
                !scrubbed.contains(&marker),
                "leaked canary {marker} in redacted output: {scrubbed}"
            );
        }
        assert!(scrubbed.contains("\"safe_node\":\"macbook-1\""));
        assert!(
            serde_json::from_str::<serde_json::Value>(&scrubbed).is_ok(),
            "redacted JSON structure corrupted: {scrubbed}"
        );
    }
}
