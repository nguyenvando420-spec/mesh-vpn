//! Streaming bounded bugreport export (`<= 1 MiB`, `0 sysexec`) and scrubbed memory log ring
//! buffer for Android/iOS extensions (`HR-MOB-G2-04`, `US-080`).

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use mesh_client::{
    BootstrapConfig, BugreportBuildOptions, ClientPlatformHooks, create_bugreport_tar_bundle,
    scrub_diagnostic_secrets,
};
use mesh_core::defaults::DEFAULT_MOBILE_MAX_BUGREPORT_BYTES;
use mesh_core::{AppError, AppResult};
use mesh_proto::agent_ipc::{AgentStatusResponse, NetcheckResponse};

/// Default in-memory ring-buffer capacity on mobile extensions (`256 KiB`).
pub(crate) const MOBILE_LOG_RING_DEFAULT_BYTES: usize = 256 * 1024;
/// Jetsam soft-pressure trimmed log ring capacity (`64 KiB`).
pub(crate) const MOBILE_LOG_RING_TRIMMED_BYTES: usize = 64 * 1024;
const BUGREPORT_EXPORT_TIMEOUT_MS: u64 = 4_500;

#[derive(Debug)]
struct LogRingInner {
    lines: VecDeque<String>,
    total_bytes: usize,
    max_bytes: usize,
}

/// Thread-safe bounded in-memory log ring buffer whose entries are pre-scrubbed on ingestion.
#[derive(Debug, Clone)]
pub(crate) struct LogRingBuffer {
    inner: Arc<StdMutex<LogRingInner>>,
}

impl Default for LogRingBuffer {
    fn default() -> Self {
        Self::new(MOBILE_LOG_RING_DEFAULT_BYTES)
    }
}

impl LogRingBuffer {
    /// Creates an empty ring buffer bounded at `max_bytes`.
    #[must_use]
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(StdMutex::new(LogRingInner {
                lines: VecDeque::new(),
                total_bytes: 0,
                max_bytes: max_bytes.max(1024),
            })),
        }
    }

    /// Scrubs `raw_line` for secrets (`mpk_*`, keys, tokens) and pushes it into the bounded ring.
    pub(crate) fn push_line(&self, raw_line: &str) {
        let (clean, _) = scrub_diagnostic_secrets(raw_line);
        let trimmed = clean.trim_end_matches(&['\r', '\n'][..]).to_owned();
        if trimmed.is_empty() {
            return;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let entry_len = trimmed.len().saturating_add(1);
        if entry_len > guard.max_bytes {
            return;
        }
        guard.total_bytes = guard.total_bytes.saturating_add(entry_len);
        guard.lines.push_back(trimmed);
        evict_to_budget(&mut guard);
    }

    /// Shrinks the in-memory ring buffer cap and evicts oldest entries (used during Jetsam `< 15 MiB`).
    pub(crate) fn trim_to_max_bytes(&self, new_max: usize) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        guard.max_bytes = new_max.max(1024);
        evict_to_budget(&mut guard);
    }

    /// Restores default log ring budget once memory pressure clears.
    pub(crate) fn restore_default_budget(&self) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        guard.max_bytes = MOBILE_LOG_RING_DEFAULT_BYTES;
    }

    /// Returns a newline-delimited snapshot of scrubbed lines (`<= max_bytes`).
    #[must_use]
    pub(crate) fn dump_text(&self) -> String {
        let Ok(guard) = self.inner.lock() else {
            return String::new();
        };
        let mut out = String::with_capacity(guard.total_bytes);
        for line in &guard.lines {
            out.push_str(line);
            out.push('\n');
        }
        out
    }
}

fn evict_to_budget(inner: &mut LogRingInner) {
    while inner.total_bytes > inner.max_bytes {
        let Some(oldest) = inner.lines.pop_front() else {
            inner.total_bytes = 0;
            break;
        };
        inner.total_bytes = inner
            .total_bytes
            .saturating_sub(oldest.len().saturating_add(1));
    }
}

/// Parameters required to stream a bounded (`<= 1 MiB`) bugreport tarball onto `dest_path`.
pub(crate) struct MobileBugreportParams {
    /// Destination file path chosen by Android/iOS host.
    pub dest_path: PathBuf,
    /// Latest agent status snapshot.
    pub status: AgentStatusResponse,
    /// Latest netcheck outcome or offline error text.
    pub netcheck: Result<NetcheckResponse, String>,
    /// Current bootstrap configuration (automatically sanitized before inclusion).
    pub bootstrap: BootstrapConfig,
    /// Platform hooks used for `0-sysexec` route diagnostics.
    pub platform_hooks: Arc<dyn ClientPlatformHooks>,
    /// Optional directories holding rotated log files.
    pub log_dirs: Vec<PathBuf>,
    /// Optional scrubbed in-memory ring logs.
    pub in_memory_logs: Option<String>,
    /// Current UTC timestamp in milliseconds.
    pub now_unix_ms: u64,
    /// Mobile extension/app component identifier for `version.txt`.
    pub binary_name: String,
    /// Software version label for `version.txt`.
    pub agent_version: String,
}

impl std::fmt::Debug for MobileBugreportParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MobileBugreportParams")
            .field("dest_path", &self.dest_path)
            .field("binary_name", &self.binary_name)
            .field("now_unix_ms", &self.now_unix_ms)
            .finish_non_exhaustive()
    }
}

/// Generates a scrubbed streaming `.tar` bugreport (`<= 1 MiB`) inside `spawn_blocking`,
/// returning `(size_bytes, scrubbed_items)`.
pub(crate) async fn export_scrubbed_bugreport_to_path(
    params: MobileBugreportParams,
) -> AppResult<(u64, u32)> {
    tokio::time::timeout(
        Duration::from_millis(BUGREPORT_EXPORT_TIMEOUT_MS),
        tokio::task::spawn_blocking(move || export_blocking(params)),
    )
    .await
    .map_err(|_| AppError::unavailable("mobile bugreport export timed out"))?
    .map_err(|err| AppError::internal(format!("mobile bugreport task failed: {err}")))?
}

fn export_blocking(params: MobileBugreportParams) -> AppResult<(u64, u32)> {
    if params.dest_path.as_os_str().is_empty() {
        return Err(AppError::invalid_argument(
            "bugreport dest_path cannot be empty",
        ));
    }
    let parent_dir = params
        .dest_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent_dir).map_err(|err| {
        AppError::internal(format!(
            "failed creating bugreport parent directory {}: {err}",
            parent_dir.display()
        ))
    })?;

    let netcheck_ref = match &params.netcheck {
        Ok(ok) => Ok(ok),
        Err(msg) => Err(msg.as_str()),
    };

    let resp = create_bugreport_tar_bundle(BugreportBuildOptions {
        output_dir: parent_dir,
        max_total_bytes: DEFAULT_MOBILE_MAX_BUGREPORT_BYTES,
        binary_name: &params.binary_name,
        agent_version: &params.agent_version,
        bootstrap: &params.bootstrap,
        status: &params.status,
        netcheck: netcheck_ref,
        platform_hooks: params.platform_hooks.as_ref(),
        log_dirs: &params.log_dirs,
        in_memory_logs: params.in_memory_logs.as_deref(),
        now_unix_ms: params.now_unix_ms,
    })?;

    let generated = PathBuf::from(&resp.bundle_path);
    if generated != params.dest_path {
        fs::rename(&generated, &params.dest_path).map_err(|err| {
            let _ignore_rm = fs::remove_file(&generated);
            AppError::internal(format!(
                "failed moving bugreport archive to {}: {err}",
                params.dest_path.display()
            ))
        })?;
    }

    if resp.size_bytes > u64::try_from(DEFAULT_MOBILE_MAX_BUGREPORT_BYTES).unwrap_or(1_048_576) {
        return Err(AppError::internal(format!(
            "mobile bugreport archive exceeded 1 MiB ceiling: {} bytes",
            resp.size_bytes
        )));
    }

    Ok((resp.size_bytes, resp.scrubbed_items))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use mesh_client::{BootstrapConfig, InMemoryClientPlatformHooks};
    use mesh_core::defaults::DEFAULT_MOBILE_MAX_BUGREPORT_BYTES;
    use mesh_proto::agent_ipc::{
        AgentStatusResponse, DaemonState, NetcheckResponse, SelfNetworkStatus,
        ServerConnectionStatus, TlsAuthMode,
    };
    use mesh_proto::netmap::NatMappingKind;
    use tempfile::TempDir;

    use super::{LogRingBuffer, MobileBugreportParams, export_scrubbed_bugreport_to_path};

    #[tokio::test]
    async fn test_mobile_bugreport_streams_within_1mib_and_scrubs_secrets() -> Result<(), String> {
        // Arrange
        let dir = TempDir::new().map_err(|e| e.to_string())?;
        let dest = dir.path().join("mobile-export.tar");
        let log_dir = dir.path().join("logs");
        fs::create_dir_all(&log_dir).map_err(|e| e.to_string())?;

        // Write a 2 MiB oversized log containing secrets to guarantee streaming tail + scrubbing.
        let mut raw_disk = String::with_capacity(2 * 1024 * 1024);
        for idx in 0..24_000 {
            raw_disk.push_str(&format!(
                "line={idx:06} preauth_key=mpk_SecretTokenShouldNeverLeak987654321 \
node_privkey_hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            ));
        }
        fs::write(log_dir.join("meshd.log"), raw_disk.as_bytes()).map_err(|e| e.to_string())?;

        let ring = LogRingBuffer::default();
        ring.push_line("event=test token=mpk_RingSecretValue1234567890abcdef");
        let hooks = Arc::new(InMemoryClientPlatformHooks::default());

        let status = AgentStatusResponse {
            daemon_state: DaemonState::Connected,
            node_id: None,
            node_name: None,
            fqdn: None,
            overlay_ip: None,
            overlay_cidr: None,
            tun_interface_name: Some("utun9".to_owned()),
            tun_mtu: 1280,
            netmap_version: 3,
            key_expires_at_ms: None,
            server_connection: Some(ServerConnectionStatus {
                control_endpoint: "198.51.100.10:8443".to_owned(),
                relay_endpoint: "198.51.100.10:8443".to_owned(),
                stun_endpoints: vec!["198.51.100.10:13478".to_owned()],
                tls_auth_mode: TlsAuthMode::SpkiPin,
                active_pin: None,
                next_pin: None,
                control_connected: true,
                relay_connected: true,
                relay_rtt_ms: Some(12),
                migration_pending_endpoint: None,
                last_error: None,
            }),
            self_network: SelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: Some("en0".to_owned()),
                nat_type: NatMappingKind::Unknown,
                nat_classification_note: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                candidates: Vec::new(),
            },
            peers: Vec::new(),
        };

        let netcheck = NetcheckResponse {
            udp_egress_ok: true,
            stun_reachable: true,
            stun_endpoint_tested: Some("198.51.100.10:13478".to_owned()),
            reflexive_ipv4: None,
            ipv6_available: false,
            nat_mapping: NatMappingKind::EimOrAdm,
            nat_note: "ok".to_owned(),
            control_tcp_reachable: true,
            control_tcp_endpoint_tested: Some("198.51.100.10:8443".to_owned()),
            relay_rtt_ms: Some(12.0),
            diagnostic_hint: Some("healthy".to_owned()),
        };

        // Act
        let (bytes_written, scrubbed_items) =
            export_scrubbed_bugreport_to_path(MobileBugreportParams {
                dest_path: dest.clone(),
                status,
                netcheck: Ok(netcheck),
                bootstrap: BootstrapConfig::default(),
                platform_hooks: hooks,
                log_dirs: vec![log_dir],
                in_memory_logs: Some(ring.dump_text()),
                now_unix_ms: 1_700_000_000_000,
                binary_name: "mesh-mobile-test".to_owned(),
                agent_version: "0.1.0".to_owned(),
            })
            .await
            .map_err(|e| e.to_string())?;

        // Assert
        assert!(bytes_written > 0);
        assert!(scrubbed_items > 0);
        assert!(
            bytes_written <= u64::try_from(DEFAULT_MOBILE_MAX_BUGREPORT_BYTES).unwrap_or(1_048_576),
            "bugreport must obey <= 1 MiB mobile ceiling, got {bytes_written}"
        );
        let raw_tar = fs::read(&dest).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&raw_tar);
        assert!(!text.contains("mpk_SecretTokenShouldNeverLeak987654321"));
        assert!(!text.contains("mpk_RingSecretValue1234567890abcdef"));
        assert!(!text.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        Ok(())
    }
}
