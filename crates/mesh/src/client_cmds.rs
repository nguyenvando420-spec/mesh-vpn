//! Client-side CLI subcommands routed exclusively over local `meshd-ro` and `meshd-admin` IPC
//! (`US-004`, `US-039`, `US-040`, `US-055`, `HR-G2-04`).

use std::io::{BufRead as _, IsTerminal as _, Read as _, Write as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};

use mesh_core::defaults::{DEFAULT_CONTROL_TCP_PORT, MAX_HTTP_BODY_BYTES};
#[cfg(unix)]
use mesh_core::defaults::{UNIX_AGENT_ADMIN_SOCKET, UNIX_AGENT_RO_SOCKET};
#[cfg(windows)]
use mesh_core::defaults::{WINDOWS_AGENT_ADMIN_PIPE, WINDOWS_AGENT_RO_PIPE};
use mesh_core::{AppError, AppResult, ErrorKind, NodeName, Port, SpkiPin};
use mesh_crypto::PreAuthToken;
#[cfg(windows)]
use mesh_net::ipc::connect_agent_named_pipe;
#[cfg(unix)]
use mesh_net::ipc::connect_agent_unix_socket;
use mesh_net::ipc::{IpcOperationTier, send_ipc_json_request_with_timeout};
use mesh_net::ledger::{LedgerCleanupOps, ResourceLedger};
use mesh_proto::agent_ipc::{
    AgentActionResponse, AgentResetIdentityRequest, AgentRotateKeyRequest, AgentSetRequest,
    AgentStatusResponse, AgentUpRequest, BugreportResponse, DaemonState, NetcheckResponse,
    PingRequest, PingResponse, PingVia,
};

use crate::output::{
    format_agent_action, format_bugreport, format_netcheck, format_peers, format_ping,
    format_status, render_json_string, write_stdout,
};

const ENV_AUTHKEY_FILE: &str = "MESH_AUTHKEY_FILE";

/// Global routing/formatting options passed to client command handlers.
#[derive(Debug, Clone)]
pub(crate) struct ClientDispatchConfig {
    pub(crate) json: bool,
    pub(crate) ro_ipc_override: Option<String>,
    pub(crate) admin_ipc_override: Option<String>,
}

/// Client subcommands handled via `meshd` dual-channel IPC (`HR-G2-04`).
#[derive(Debug, Subcommand)]
pub(crate) enum ClientCommand {
    /// Show local agent status, control/relay connectivity, NAT status, and peers (`meshd-ro`).
    Status,
    /// List overlay peers and current transport paths (`meshd-ro`).
    Peers,
    /// Probe end-to-end peer reachability across Relay and Direct paths (`meshd-ro`, `US-040`).
    Ping(PingArgs),
    /// Inspect local UDP egress, STUN reachability, and NAT mapping (`meshd-ro`).
    Netcheck,
    /// Authenticate (if needed) and bring the overlay tunnel up (`meshd-admin`).
    Up(UpArgs),
    /// Tear down active tunnel cleanly without exiting the daemon (`meshd-admin`).
    Down,
    /// Force idempotent OS route/TUN/hosts cleanup using `ResourceLedger` (`meshd-admin`).
    Cleanup,
    /// Update pinned Control server endpoint and certificate pins (`meshd-admin`).
    Set(SetArgs),
    /// Rotate local node WireGuard identity keypair cleanly (`meshd-admin`).
    RotateKey(RotateKeyArgs),
    /// Clear local node enrollment identity and keys while keeping `meshd` running (`meshd-admin`, `ADR-024`).
    ResetIdentity {
        /// Confirm identity reset without an interactive prompt (required in non-TTY mode).
        #[arg(long)]
        yes: bool,
    },
    /// Generate a redacted non-secret diagnostic archive (`meshd-admin`).
    Bugreport,
    /// Launch the Mesh VPN desktop tray and dashboard interface (`US-100`, `ADR-022`).
    Gui,
}

#[derive(Debug, Args)]
pub(crate) struct PingArgs {
    /// Target peer name, FQDN, or overlay IPv4 address.
    pub(crate) peer: String,
    /// Number of sequential probe samples (`1..=64`).
    #[arg(short = 'c', long, default_value_t = 4)]
    pub(crate) count: u16,
    /// Require direct UDP connectivity within probe timeout and diagnose failures clearly.
    #[arg(long)]
    pub(crate) direct: bool,
    /// Per-probe wait timeout in milliseconds (`100..=30000`).
    #[arg(long, default_value_t = 2500)]
    pub(crate) timeout_ms: u64,
}

#[derive(Debug, Args)]
pub(crate) struct UpArgs {
    /// Control plane endpoint (`<host_or_ip>:<port>` or `<host_or_ip>` with `--port`).
    #[arg(long)]
    pub(crate) server: String,
    /// Explicit Control TCP port override (`1..=65535`).
    #[arg(long)]
    pub(crate) port: Option<u16>,
    /// Mandatory pinned server certificate SPKI fingerprint (`sha256:<64hex>`) for IP endpoints.
    #[arg(long)]
    pub(crate) server_pin: Option<String>,
    /// Explicitly trust public/system CAs for DNS hostnames (prohibited for raw IP endpoints).
    #[arg(long)]
    pub(crate) ca_tls: bool,
    /// Path to a local file holding the pre-auth key (`MESH_AUTHKEY_FILE` fallback).
    #[arg(long)]
    pub(crate) authkey_file: Option<PathBuf>,
    /// Read the pre-auth key securely from stdin (`--authkey` CLI argv is intentionally disabled).
    #[arg(long)]
    pub(crate) authkey_stdin: bool,
    /// Optional RFC 1123 node label (`[a-z0-9-]`).
    #[arg(long)]
    pub(crate) name: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct SetArgs {
    /// Updated Control server endpoint (`<host_or_ip>:<port>` or `<host_or_ip>`).
    #[arg(long)]
    pub(crate) server: String,
    /// Optional explicit TCP port (`1..=65535`).
    #[arg(long)]
    pub(crate) port: Option<u16>,
    /// Pinned server certificate SPKI fingerprint (`sha256:<64hex>`).
    #[arg(long)]
    pub(crate) server_pin: Option<String>,
    /// Explicitly select system CA verification for DNS hostnames.
    #[arg(long)]
    pub(crate) ca_tls: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RotateKeyArgs {
    /// Path to a local file holding a fresh scoped `--for` pre-auth key (`MESH_AUTHKEY_FILE` fallback).
    #[arg(long)]
    pub(crate) authkey_file: Option<PathBuf>,
    /// Read the scoped pre-auth key securely from stdin.
    #[arg(long)]
    pub(crate) authkey_stdin: bool,
}

/// Returns diagnostic subsystem label.
#[cfg(test)]
#[must_use]
pub(crate) const fn status_label() -> &'static str {
    "client_cmds:ready"
}

/// Executes any [`ClientCommand`] against local `meshd` IPC endpoints.
pub(crate) async fn handle_client_command(
    cmd: &ClientCommand,
    cfg: &ClientDispatchConfig,
) -> AppResult<()> {
    match cmd {
        ClientCommand::Status => {
            let resp: AgentStatusResponse = send_ro_request(
                cfg,
                hyper::Method::GET,
                "/v1/agent/status",
                None::<&()>,
                IpcOperationTier::ReadOnlyQuery,
            )
            .await?;
            emit_formatted(&resp, cfg.json, format_status)
        }
        ClientCommand::Peers => {
            let resp: AgentStatusResponse = send_ro_request(
                cfg,
                hyper::Method::GET,
                "/v1/agent/peers",
                None::<&()>,
                IpcOperationTier::ReadOnlyQuery,
            )
            .await?;
            emit_formatted(&resp, cfg.json, format_peers)
        }
        ClientCommand::Ping(args) => handle_ping(args, cfg).await,
        ClientCommand::Netcheck => {
            let resp: NetcheckResponse = send_ro_request(
                cfg,
                hyper::Method::POST,
                "/v1/agent/netcheck",
                Some(&()),
                IpcOperationTier::NetcheckProbe,
            )
            .await?;
            emit_formatted(&resp, cfg.json, format_netcheck)
        }
        ClientCommand::Up(args) => handle_up(args, cfg).await,
        ClientCommand::Down => {
            let resp: AgentActionResponse =
                send_admin_request(cfg, hyper::Method::POST, "/v1/agent/down", Some(&())).await?;
            emit_formatted(&resp, cfg.json, format_agent_action)
        }
        ClientCommand::Cleanup => {
            let resp = execute_cleanup_with_offline_fallback(cfg).await?;
            emit_formatted(&resp, cfg.json, format_agent_action)
        }
        ClientCommand::Set(args) => handle_set(args, cfg).await,
        ClientCommand::RotateKey(args) => handle_rotate_key(args, cfg).await,
        ClientCommand::ResetIdentity { yes } => handle_reset_identity(*yes, cfg).await,
        ClientCommand::Bugreport => {
            let resp: BugreportResponse =
                send_admin_request(cfg, hyper::Method::POST, "/v1/agent/bugreport", Some(&()))
                    .await?;
            emit_formatted(&resp, cfg.json, format_bugreport)
        }
        ClientCommand::Gui => handle_gui(),
    }
}

async fn execute_cleanup_with_offline_fallback(
    cfg: &ClientDispatchConfig,
) -> AppResult<AgentActionResponse> {
    match send_admin_request::<(), AgentActionResponse>(
        cfg,
        hyper::Method::POST,
        "/v1/agent/cleanup",
        Some(&()),
    )
    .await
    {
        Ok(resp) => Ok(resp),
        Err(err) if err.kind() == ErrorKind::Unavailable && cfg.admin_ipc_override.is_none() => {
            let ledger_path = ResourceLedger::default_ledger_path();
            cleanup_offline_ledger_with_platform_ops(&ledger_path)
        }
        Err(err) => Err(err),
    }
}

fn cleanup_offline_ledger_with_platform_ops(ledger_path: &Path) -> AppResult<AgentActionResponse> {
    #[cfg(target_os = "linux")]
    {
        let ops = mesh_net::route_linux::LinuxCleanupOps::new();
        cleanup_offline_ledger_if_present(ledger_path, &ops)
    }
    #[cfg(target_os = "macos")]
    {
        let ops = mesh_net::route_macos::MacOsCleanupOps::new();
        cleanup_offline_ledger_if_present(ledger_path, &ops)
    }
    #[cfg(target_os = "windows")]
    {
        let ops = mesh_net::route_windows::WindowsCleanupOps::new();
        cleanup_offline_ledger_if_present(ledger_path, &ops)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let ops = mesh_net::ledger::FakeLedgerCleanupOps::new();
        cleanup_offline_ledger_if_present(ledger_path, &ops)
    }
}

fn cleanup_offline_ledger_if_present(
    ledger_path: &Path,
    ops: &dyn LedgerCleanupOps,
) -> AppResult<AgentActionResponse> {
    if !ledger_path.exists() {
        return Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "daemon offline and no ledger present; skipping cleanup".to_owned(),
        });
    }
    let mut ledger = ResourceLedger::load_or_init(ledger_path.to_path_buf())?;
    if !ledger.needs_stale_recovery() {
        return Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "daemon offline and ledger already clean".to_owned(),
        });
    }
    ledger.cleanup_all(ops)?;
    Ok(AgentActionResponse {
        state: DaemonState::Stopped,
        message: "offline ledger cleanup completed idempotently".to_owned(),
    })
}

async fn handle_ping(args: &PingArgs, cfg: &ClientDispatchConfig) -> AppResult<()> {
    let req = PingRequest {
        target: args.peer.clone(),
        count: args.count,
        force_direct: args.direct,
        timeout_ms: args.timeout_ms,
    };
    let tier = IpcOperationTier::PingProbe {
        count: args.count,
        per_probe_timeout_ms: args.timeout_ms,
    };
    let resp: PingResponse =
        send_ro_request(cfg, hyper::Method::POST, "/v1/agent/ping", Some(&req), tier).await?;
    emit_formatted(&resp, cfg.json, |dto| format_ping(dto, args.direct))?;
    if args.direct && !resp.samples.iter().any(|s| s.via == PingVia::Direct) {
        return Err(AppError::unavailable(
            "direct UDP path could not be established during --direct probe window",
        ));
    }
    if resp.packets_received == 0 {
        return Err(AppError::unavailable("all ping probes timed out"));
    }
    Ok(())
}

async fn handle_up(args: &UpArgs, cfg: &ClientDispatchConfig) -> AppResult<()> {
    let (server_endpoint, port_override, server_pin) = validate_server_and_policy(
        &args.server,
        args.port,
        args.server_pin.as_deref(),
        args.ca_tls,
    )?;
    let node_name = args.name.as_deref().map(NodeName::parse).transpose()?;
    let env_authkey = env_authkey_path();
    let token = load_preauth_token(
        args.authkey_file.as_deref(),
        env_authkey.as_deref(),
        args.authkey_stdin,
        false,
    )?;
    let req = AgentUpRequest {
        server_endpoint,
        port_override,
        server_pin,
        preauth_key: token
            .as_ref()
            .map(|t| t.as_secret().expose_secret().clone()),
        node_name,
    };
    let resp: AgentActionResponse =
        send_admin_request(cfg, hyper::Method::POST, "/v1/agent/up", Some(&req)).await?;
    emit_formatted(&resp, cfg.json, format_agent_action)
}

async fn handle_set(args: &SetArgs, cfg: &ClientDispatchConfig) -> AppResult<()> {
    let (server_endpoint, _port, server_pin) = validate_server_and_policy(
        &args.server,
        args.port,
        args.server_pin.as_deref(),
        args.ca_tls,
    )?;
    let req = AgentSetRequest {
        server_endpoint,
        server_pin,
    };
    let resp: AgentActionResponse =
        send_admin_request(cfg, hyper::Method::POST, "/v1/agent/set", Some(&req)).await?;
    emit_formatted(&resp, cfg.json, format_agent_action)
}

async fn handle_rotate_key(args: &RotateKeyArgs, cfg: &ClientDispatchConfig) -> AppResult<()> {
    let env_authkey = env_authkey_path();
    let Some(token) = load_preauth_token(
        args.authkey_file.as_deref(),
        env_authkey.as_deref(),
        args.authkey_stdin,
        true,
    )?
    else {
        return Err(AppError::invalid_argument(
            "pre-auth key is required via --authkey-file, MESH_AUTHKEY_FILE, or --authkey-stdin",
        ));
    };
    let req = AgentRotateKeyRequest {
        preauth_key: token.as_secret().expose_secret().clone(),
    };
    let resp: AgentActionResponse =
        send_admin_request(cfg, hyper::Method::POST, "/v1/agent/rotate-key", Some(&req)).await?;
    emit_formatted(&resp, cfg.json, format_agent_action)
}

async fn handle_reset_identity(yes: bool, cfg: &ClientDispatchConfig) -> AppResult<()> {
    let is_tty = std::io::stdin().is_terminal();
    require_reset_confirmation(yes, is_tty, prompt_reset_confirmation)?;
    let resp: AgentActionResponse = send_admin_request(
        cfg,
        hyper::Method::POST,
        "/v1/agent/reset-identity",
        Some(&AgentResetIdentityRequest {}),
    )
    .await?;
    emit_formatted(&resp, cfg.json, format_agent_action)
}

pub(crate) fn require_reset_confirmation<F>(yes: bool, is_tty: bool, prompt_fn: F) -> AppResult<()>
where
    F: FnOnce() -> AppResult<bool>,
{
    if yes {
        return Ok(());
    }
    if !is_tty {
        return Err(AppError::invalid_argument(
            "reset-identity requires --yes in non-interactive mode",
        ));
    }
    if prompt_fn()? {
        Ok(())
    } else {
        Err(AppError::invalid_argument(
            "identity reset aborted; node keys preserved",
        ))
    }
}

fn prompt_reset_confirmation() -> AppResult<bool> {
    {
        let mut err_out = std::io::stderr().lock();
        err_out
            .write_all(b"Reset local node identity and delete enrollment keys? [y/N]: ")
            .map_err(|err| AppError::internal(format!("failed writing prompt: {err}")))?;
        err_out
            .flush()
            .map_err(|err| AppError::internal(format!("failed flushing prompt: {err}")))?;
    }
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|err| AppError::internal(format!("failed reading confirmation: {err}")))?;
    let trimmed = answer.trim();
    Ok(trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes"))
}

#[cfg(any(target_os = "windows", test))]
fn is_regular_non_symlink_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

#[cfg(any(target_os = "macos", test))]
fn is_regular_non_symlink_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_dir())
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn resolve_windows_gui_exe_from(
    current_exe: Option<&Path>,
    program_files: Option<&Path>,
) -> Option<PathBuf> {
    let sibling = current_exe
        .and_then(Path::parent)
        .map(|dir| dir.join("MeshVPN.exe"));
    if let Some(candidate) = sibling.filter(|p| is_regular_non_symlink_file(p)) {
        return Some(candidate);
    }

    let installed = program_files.map(|pf| pf.join("Mesh").join("MeshVPN.exe"));
    installed.filter(|p| is_regular_non_symlink_file(p))
}

#[cfg(target_os = "windows")]
pub(crate) fn find_windows_gui_executable() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok();
    let program_files = std::env::var_os("ProgramFiles")
        .or_else(|| std::env::var_os("PROGRAMFILES"))
        .map(PathBuf::from);
    resolve_windows_gui_exe_from(current_exe.as_deref(), program_files.as_deref())
}

#[cfg(any(target_os = "macos", test))]
fn resolve_macos_gui_app_from(
    current_exe: Option<&Path>,
    applications_dir: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(exe) = current_exe {
        for ancestor in exe.ancestors() {
            if ancestor.file_name().and_then(|n| n.to_str()) == Some("Mesh VPN.app")
                && is_regular_non_symlink_dir(ancestor)
            {
                return Some(ancestor.to_path_buf());
            }
        }
        if let Some(sibling) = exe.parent().map(|dir| dir.join("Mesh VPN.app"))
            && is_regular_non_symlink_dir(&sibling)
        {
            return Some(sibling);
        }
    }

    applications_dir
        .map(|dir| dir.join("Mesh VPN.app"))
        .filter(|p| is_regular_non_symlink_dir(p))
}

fn handle_gui() -> AppResult<()> {
    #[cfg(target_os = "windows")]
    {
        let Some(gui_exe) = find_windows_gui_executable() else {
            return Err(AppError::not_found(
                "MeshVPN.exe was not found next to mesh.exe or under %ProgramFiles%\\Mesh\\MeshVPN.exe",
            ));
        };
        mesh_sys::process_windows::spawn_detached_gui(&gui_exe).map_err(AppError::from)
    }

    #[cfg(target_os = "macos")]
    {
        let current_exe = std::env::current_exe().ok();
        let Some(app_bundle) =
            resolve_macos_gui_app_from(current_exe.as_deref(), Some(Path::new("/Applications")))
        else {
            return Err(AppError::not_found(
                "Mesh VPN.app was not found in /Applications or alongside mesh",
            ));
        };
        let app_str = app_bundle.to_str().ok_or_else(|| {
            AppError::invalid_argument("Mesh VPN.app path contains invalid UTF-8")
        })?;
        if app_str.chars().any(char::is_control) {
            return Err(AppError::invalid_argument(
                "Mesh VPN.app path contains control characters",
            ));
        }
        let status = std::process::Command::new("/usr/bin/open")
            .arg("-a")
            .arg(&app_bundle)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|err| {
                AppError::unavailable(format!("failed launching /usr/bin/open: {err}"))
            })?;
        if !status.success() {
            return Err(AppError::unavailable(
                "failed launching Mesh VPN.app via /usr/bin/open (headless or desktop session unavailable)",
            ));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Err(AppError::unavailable(
            "mesh gui is only supported on Windows and macOS desktop environments",
        ))
    }
}

fn emit_formatted<T, F>(value: &T, json_mode: bool, human_fmt: F) -> AppResult<()>
where
    T: Serialize,
    F: FnOnce(&T) -> String,
{
    let text = if json_mode {
        render_json_string(value)?
    } else {
        human_fmt(value)
    };
    write_stdout(&text)
}

/// Validates `--server`, optional `--port`, and strict Zero-TOFU policy (`US-003 AC6`, `SEC-04`).
pub(crate) fn validate_server_and_policy(
    server: &str,
    port_override_raw: Option<u16>,
    server_pin_raw: Option<&str>,
    ca_tls: bool,
) -> AppResult<(String, Option<Port>, Option<SpkiPin>)> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return Err(AppError::invalid_argument(
            "server endpoint must not be empty",
        ));
    }
    let (host, parsed_port) = split_endpoint_host_and_port(trimmed)?;
    let port_override = port_override_raw.map(Port::from_u16).transpose()?;
    let final_port = match (port_override, parsed_port) {
        (Some(explicit), _) => explicit,
        (None, Some(embedded)) => embedded,
        (None, None) => Port::from_u16(DEFAULT_CONTROL_TCP_PORT)?,
    };
    let normalized_endpoint = if host.contains(':') {
        format!("[{host}]:{}", final_port.get())
    } else {
        format!("{host}:{}", final_port.get())
    };

    let is_ip_literal = host.parse::<IpAddr>().is_ok();
    let pin = server_pin_raw.map(SpkiPin::parse).transpose()?;

    if is_ip_literal {
        if ca_tls {
            return Err(AppError::invalid_argument(
                "cannot combine --ca-tls with an IP address endpoint; pass --server-pin sha256:<hex>",
            ));
        }
        if pin.is_none() {
            return Err(AppError::invalid_argument(
                "Zero-TOFU policy requires --server-pin sha256:<hex> when connecting to an IP address",
            ));
        }
    } else if pin.is_none() && !ca_tls {
        return Err(AppError::invalid_argument(
            "Zero-TOFU policy requires --server-pin sha256:<hex> or explicit --ca-tls",
        ));
    }

    Ok((normalized_endpoint, port_override, pin))
}

fn split_endpoint_host_and_port(input: &str) -> AppResult<(String, Option<Port>)> {
    if input.contains("://") {
        return Err(AppError::invalid_argument(
            "server endpoint must be <host:port> without URL scheme (omit https:// or http://)",
        ));
    }

    if let Some(rest) = input.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err(AppError::invalid_argument(
                "malformed bracketed IPv6 server endpoint",
            ));
        };
        if suffix.is_empty() {
            return Ok((host.to_owned(), None));
        }
        let port_str = suffix
            .strip_prefix(':')
            .ok_or_else(|| AppError::invalid_argument("invalid port after bracketed host"))?;
        let port_num: u16 = port_str
            .parse()
            .map_err(|_| AppError::invalid_argument("invalid TCP port in server endpoint"))?;
        return Ok((host.to_owned(), Some(Port::from_u16(port_num)?)));
    }

    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok((ip.to_string(), None));
    }

    if let Some((host, port_str)) = input.rsplit_once(':') {
        if host.is_empty() {
            return Err(AppError::invalid_argument(
                "missing host in server endpoint",
            ));
        }
        let port_num: u16 = port_str
            .parse()
            .map_err(|_| AppError::invalid_argument("invalid TCP port in server endpoint"))?;
        return Ok((host.to_owned(), Some(Port::from_u16(port_num)?)));
    }

    Ok((input.to_owned(), None))
}

fn env_authkey_path() -> Option<PathBuf> {
    std::env::var(ENV_AUTHKEY_FILE)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Reads a pre-auth key from `--authkey-file`, `MESH_AUTHKEY_FILE`, or `--authkey-stdin` (`SEC-01`).
pub(crate) fn load_preauth_token(
    cli_file: Option<&Path>,
    env_file: Option<&Path>,
    from_stdin: bool,
    required: bool,
) -> AppResult<Option<PreAuthToken>> {
    if cli_file.is_some() && from_stdin {
        return Err(AppError::invalid_argument(
            "cannot combine --authkey-file with --authkey-stdin",
        ));
    }
    if from_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .lock()
            .read_to_string(&mut buf)
            .map_err(|err| {
                AppError::internal(format!("failed reading pre-auth key from stdin: {err}"))
            })?;
        return Ok(Some(PreAuthToken::parse(&buf)?));
    }
    if let Some(path) = cli_file.or(env_file) {
        let raw = std::fs::read_to_string(path).map_err(|err| {
            AppError::invalid_argument(format!(
                "failed reading pre-auth key file {}: {err}",
                path.display()
            ))
        })?;
        return Ok(Some(PreAuthToken::parse(&raw)?));
    }
    if required {
        return Err(AppError::invalid_argument(
            "pre-auth key required via --authkey-file, MESH_AUTHKEY_FILE, or --authkey-stdin",
        ));
    }
    Ok(None)
}

/// Dispatches a JSON request over an already-connected duplex or IPC stream with an explicit
/// 3-tier IPC timeout (`ADR-024`).
pub(crate) async fn call_agent_stream_with_tier<S, Req, Resp>(
    stream: S,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
    tier: IpcOperationTier,
) -> AppResult<Resp>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Req: Serialize,
    Resp: DeserializeOwned,
{
    send_ipc_json_request_with_timeout(
        stream,
        method,
        path,
        body,
        MAX_HTTP_BODY_BYTES,
        tier.response_timeout(),
    )
    .await
}

/// Dispatches a JSON request over an already-connected duplex or IPC stream.
#[cfg(test)]
pub(crate) async fn call_agent_stream<S, Req, Resp>(
    stream: S,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
) -> AppResult<Resp>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Req: Serialize,
    Resp: DeserializeOwned,
{
    call_agent_stream_with_tier(stream, method, path, body, IpcOperationTier::AdminMutation).await
}

async fn send_ro_request<Req, Resp>(
    cfg: &ClientDispatchConfig,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
    tier: IpcOperationTier,
) -> AppResult<Resp>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let endpoint = cfg
        .ro_ipc_override
        .as_deref()
        .unwrap_or(default_ro_endpoint());
    connect_and_send(endpoint, false, method, path, body, tier).await
}

async fn send_admin_request<Req, Resp>(
    cfg: &ClientDispatchConfig,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
) -> AppResult<Resp>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let endpoint = cfg
        .admin_ipc_override
        .as_deref()
        .unwrap_or(default_admin_endpoint());
    connect_and_send(
        endpoint,
        true,
        method,
        path,
        body,
        IpcOperationTier::AdminMutation,
    )
    .await
}

#[cfg(unix)]
fn default_ro_endpoint() -> &'static str {
    UNIX_AGENT_RO_SOCKET
}

#[cfg(windows)]
fn default_ro_endpoint() -> &'static str {
    WINDOWS_AGENT_RO_PIPE
}

#[cfg(unix)]
fn default_admin_endpoint() -> &'static str {
    UNIX_AGENT_ADMIN_SOCKET
}

#[cfg(windows)]
fn default_admin_endpoint() -> &'static str {
    WINDOWS_AGENT_ADMIN_PIPE
}

#[cfg(unix)]
async fn connect_and_send<Req, Resp>(
    endpoint: &str,
    is_admin: bool,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
    tier: IpcOperationTier,
) -> AppResult<Resp>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let stream = connect_agent_unix_socket(endpoint, is_admin).await?;
    call_agent_stream_with_tier(stream, method, path, body, tier).await
}

#[cfg(windows)]
async fn connect_and_send<Req, Resp>(
    pipe_name: &str,
    is_admin: bool,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
    tier: IpcOperationTier,
) -> AppResult<Resp>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let stream = connect_agent_named_pipe(pipe_name, is_admin).await?;
    call_agent_stream_with_tier(stream, method, path, body, tier).await
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::time::Instant;

    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use mesh_core::ErrorKind;
    use mesh_core::defaults::DEFAULT_CONTROL_TCP_PORT;
    use mesh_crypto::PreAuthToken;
    use mesh_proto::agent_ipc::{AgentStatusResponse, DaemonState, SelfNetworkStatus};
    use mesh_proto::netmap::NatMappingKind;

    use super::{
        ClientDispatchConfig, call_agent_stream, load_preauth_token, validate_server_and_policy,
    };

    #[test]
    fn test_zero_tofu_rejects_ip_without_pin_and_allows_pinned_ip() {
        // Arrange
        let pin = format!("sha256:{}", "a".repeat(64));

        // Act
        let missing_pin = validate_server_and_policy("203.0.113.10:8443", None, None, false);
        let ip_with_ca = validate_server_and_policy("203.0.113.10:8443", None, None, true);
        let dns_no_policy = validate_server_and_policy("vpn.example.com:8443", None, None, false);
        let pinned_ok = validate_server_and_policy("203.0.113.10", Some(8443), Some(&pin), false);
        let dns_ca_ok = validate_server_and_policy("vpn.example.com", None, None, true);

        // Assert
        assert_eq!(
            missing_pin.err().map(|e| e.kind()),
            Some(ErrorKind::InvalidArgument)
        );
        assert_eq!(
            ip_with_ca.err().map(|e| e.kind()),
            Some(ErrorKind::InvalidArgument)
        );
        assert_eq!(
            dns_no_policy.err().map(|e| e.kind()),
            Some(ErrorKind::InvalidArgument)
        );
        let (ep, port, parsed_pin) = pinned_ok.expect("pinned IP accepted");
        assert_eq!(ep, "203.0.113.10:8443");
        assert_eq!(port.map(|p| p.get()), Some(8443));
        assert!(parsed_pin.is_some());
        let (ca_ep, _, ca_pin) = dns_ca_ok.expect("dns CA accepted");
        assert_eq!(ca_ep, format!("vpn.example.com:{DEFAULT_CONTROL_TCP_PORT}"));
        assert!(ca_pin.is_none());
    }

    #[test]
    fn test_load_preauth_token_from_file_without_argv() {
        // Arrange
        let tok = PreAuthToken::generate();
        let mut f = NamedTempFile::new().expect("temp file");
        writeln!(f, "{}", tok.as_secret().expose_secret()).expect("write key");

        // Act
        let parsed = load_preauth_token(Some(f.path()), None, false, true)
            .expect("load token")
            .expect("some token");

        // Assert
        assert_eq!(
            parsed.as_secret().expose_secret(),
            tok.as_secret().expose_secret()
        );
    }

    #[tokio::test]
    async fn test_offline_daemon_fails_fast_under_one_second() {
        // Arrange
        let cfg = ClientDispatchConfig {
            json: false,
            #[cfg(windows)]
            ro_ipc_override: Some(r"\\.\pipe\mesh-nonexistent-test-ro-9999".to_owned()),
            #[cfg(unix)]
            ro_ipc_override: Some("/tmp/mesh-nonexistent-test-ro-9999.sock".to_owned()),
            admin_ipc_override: None,
        };
        let started = Instant::now();

        // Act
        let err = super::send_ro_request::<(), AgentStatusResponse>(
            &cfg,
            hyper::Method::GET,
            "/v1/agent/status",
            None,
            mesh_net::ipc::IpcOperationTier::ReadOnlyQuery,
        )
        .await
        .expect_err("offline pipe/sock must fail");

        // Assert
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "took {:?} >= 1s",
            started.elapsed()
        );
        assert!(err.to_string().contains("meshd daemon is not running"));
    }

    #[tokio::test]
    async fn test_call_agent_stream_roundtrips_status_response() {
        // Arrange
        let (client_io, mut server_io) = tokio::io::duplex(32 * 1024);
        let status = AgentStatusResponse {
            daemon_state: DaemonState::Stopped,
            node_id: None,
            node_name: None,
            fqdn: None,
            overlay_ip: None,
            overlay_cidr: None,
            tun_interface_name: None,
            tun_mtu: 1380,
            netmap_version: 0,
            key_expires_at_ms: None,
            server_connection: None,
            self_network: SelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: None,
                nat_type: NatMappingKind::Unknown,
                nat_classification_note: None,
                overlay_conflict_warning: None,
                macos_firewall_warning: None,
                candidates: vec![],
            },
            peers: vec![],
        };
        let payload = serde_json::to_vec(&status).expect("serialize status");

        // Act
        let client_fut = call_agent_stream::<_, (), AgentStatusResponse>(
            client_io,
            hyper::Method::GET,
            "/v1/agent/status",
            None,
        );
        let server_fut = async move {
            let mut buf = [0_u8; 4096];
            let n = server_io.read(&mut buf).await.expect("read req");
            let req_text = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).into_owned();
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                payload.len()
            );
            server_io
                .write_all(reply.as_bytes())
                .await
                .expect("write head");
            server_io.write_all(&payload).await.expect("write body");
            server_io.flush().await.expect("flush");
            req_text
        };
        let (got_res, req_text) = tokio::join!(client_fut, server_fut);
        let got = got_res.expect("call status");

        // Assert
        assert!(req_text.starts_with("GET /v1/agent/status HTTP/1.1"));
        assert_eq!(got.daemon_state, DaemonState::Stopped);
        assert_eq!(got.tun_mtu, 1380);
    }

    #[tokio::test]
    async fn test_set_and_rotate_key_wire_contracts_and_error_safety() {
        use mesh_proto::agent_ipc::{
            AgentActionResponse, AgentRotateKeyRequest, AgentSetRequest, DaemonState,
        };
        use tempfile::tempdir;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

        // Arrange: US-074 AC5 Zero-TOFU validation for IP vs pin
        assert!(validate_server_and_policy("203.0.113.10:8443", None, None, false).is_err());
        assert!(validate_server_and_policy("203.0.113.10:8443", None, None, true).is_err());
        let valid_pin = format!("sha256:{}", "ab".repeat(32));
        let (ep, _port, parsed_pin) =
            validate_server_and_policy("203.0.113.10:8443", None, Some(&valid_pin), false)
                .expect("pinned IP accepted");
        assert_eq!(ep, "203.0.113.10:8443");
        assert!(parsed_pin.is_some());

        // Act 1: POST /v1/agent/set over mock duplex admin IPC
        let (client_set, mut server_set) = duplex(16 * 1024);
        let set_req = AgentSetRequest {
            server_endpoint: ep.clone(),
            server_pin: parsed_pin,
        };
        let action_ok = AgentActionResponse {
            state: DaemonState::Connecting,
            message: "Control endpoint updated; reconnecting".to_owned(),
        };
        let ok_bytes = serde_json::to_vec(&action_ok).expect("serialize action");
        let set_client_fut = call_agent_stream::<_, AgentSetRequest, AgentActionResponse>(
            client_set,
            hyper::Method::POST,
            "/v1/agent/set",
            Some(&set_req),
        );
        let set_server_fut = async move {
            let mut buf = [0_u8; 4096];
            let n = server_set.read(&mut buf).await.expect("read set req");
            let req_text = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).into_owned();
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                ok_bytes.len()
            );
            server_set.write_all(reply.as_bytes()).await.expect("hdr");
            server_set.write_all(&ok_bytes).await.expect("body");
            server_set.flush().await.expect("flush");
            req_text
        };
        let (set_res, set_wire) = tokio::join!(set_client_fut, set_server_fut);
        assert!(set_wire.starts_with("POST /v1/agent/set HTTP/1.1"));
        assert!(set_wire.contains("203.0.113.10:8443"));
        assert_eq!(set_res.expect("set ok").state, DaemonState::Connecting);

        // Act 2: US-032 authkey file load + failed /v1/agent/rotate-key error preserves secrecy
        let dir = tempdir().expect("tempdir");
        let auth_file = dir.path().join("rotate.key");
        let canary_tok = PreAuthToken::generate();
        let canary_key = canary_tok.as_secret().expose_secret().clone();
        std::fs::write(&auth_file, format!("{canary_key}\n")).expect("write key");
        let loaded = load_preauth_token(Some(&auth_file), None, false, true)
            .expect("load token ok")
            .expect("token present");
        let (client_rot, mut server_rot) = duplex(16 * 1024);
        let rot_req = AgentRotateKeyRequest {
            preauth_key: loaded.as_secret().expose_secret().clone(),
        };
        let err_json = br#"{"error":{"kind":"unavailable","message":"Control unreachable; existing identity preserved"}}"#;
        let rot_client_fut = call_agent_stream::<_, AgentRotateKeyRequest, AgentActionResponse>(
            client_rot,
            hyper::Method::POST,
            "/v1/agent/rotate-key",
            Some(&rot_req),
        );
        let rot_server_fut = async move {
            let mut buf = [0_u8; 4096];
            let _n = server_rot.read(&mut buf).await.expect("read rot req");
            let reply = format!(
                "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                err_json.len()
            );
            server_rot.write_all(reply.as_bytes()).await.expect("hdr");
            server_rot.write_all(err_json).await.expect("body");
            server_rot.flush().await.expect("flush");
        };
        let (rot_res, ()) = tokio::join!(rot_client_fut, rot_server_fut);

        // Assert: error propagates cleanly without leaking preauth canary key
        let rot_err = rot_res.expect_err("offline rotate-key fails safely");
        assert!(!rot_err.to_string().contains(&canary_key));
    }

    #[test]
    fn test_cleanup_offline_ledger_if_present_skips_when_missing_and_cleans_only_recorded() {
        // Arrange (`HR-W21-09`)
        let Ok(dir) = tempfile::tempdir() else {
            return;
        };
        let missing_ledger = dir.path().join("missing-ledger.json");
        let fake_ops_missing = mesh_net::ledger::FakeLedgerCleanupOps::new();

        // Act 1: missing ledger does nothing
        let res_missing =
            super::cleanup_offline_ledger_if_present(&missing_ledger, &fake_ops_missing);

        // Assert 1
        assert!(res_missing.is_ok());
        assert!(
            fake_ops_missing
                .recorded_steps()
                .ok()
                .is_some_and(|steps| steps.is_empty())
        );

        // Arrange 2: dirty ledger with recorded resources
        let active_ledger = dir.path().join("ledger.json");
        let Ok(mut ledger) = mesh_net::ledger::ResourceLedger::load_or_init(active_ledger.clone())
        else {
            return;
        };
        assert!(
            ledger
                .record_tun_before_create("mesh0".to_owned(), None, 999, 1_700_000_000_000)
                .is_ok()
        );
        assert!(
            ledger
                .record_route_before_add(mesh_net::ledger::LedgerRouteEntry {
                    destination_cidr: "100.115.0.0/16".to_owned(),
                    interface_name: "mesh0".to_owned(),
                    table: Some(51820),
                })
                .is_ok()
        );
        let fake_ops_active = mesh_net::ledger::FakeLedgerCleanupOps::new();

        // Act 2: cleanup reads ledger and removes only recorded items
        let res_active = super::cleanup_offline_ledger_if_present(&active_ledger, &fake_ops_active);

        // Assert 2
        assert!(res_active.is_ok());
        let Ok(steps) = fake_ops_active.recorded_steps() else {
            return;
        };
        assert!(steps.iter().any(|s| s.contains("mesh0")));
        assert!(steps.iter().any(|s| s.contains("100.115.0.0/16")));
    }

    #[tokio::test]
    async fn test_up_and_set_reject_server_url_scheme_https() {
        // Arrange (`HR-G3-02`)
        use clap::Parser as _;

        use crate::cli::{Cli, TopCommand};

        let pin = format!("sha256:{}", "a".repeat(64));
        let dispatch_cfg = ClientDispatchConfig {
            json: false,
            ro_ipc_override: None,
            admin_ipc_override: Some("unused-admin-ipc".to_owned()),
        };

        let up_parsed = Cli::try_parse_from([
            "mesh",
            "up",
            "--server",
            "https://203.0.113.10:443",
            "--server-pin",
            &pin,
        ]);
        assert!(up_parsed.is_ok());
        let Ok(Cli {
            command: TopCommand::Client(up_cmd),
            ..
        }) = up_parsed
        else {
            return;
        };

        let set_parsed = Cli::try_parse_from([
            "mesh",
            "set",
            "--server",
            "https://203.0.113.10:443",
            "--server-pin",
            &pin,
        ]);
        assert!(set_parsed.is_ok());
        let Ok(Cli {
            command: TopCommand::Client(set_cmd),
            ..
        }) = set_parsed
        else {
            return;
        };

        // Act
        let up_res = super::handle_client_command(&up_cmd, &dispatch_cfg).await;
        let set_res = super::handle_client_command(&set_cmd, &dispatch_cfg).await;
        let http_res =
            validate_server_and_policy("http://203.0.113.10:443", None, Some(&pin), false);

        // Assert
        assert!(up_res.is_err());
        assert!(set_res.is_err());
        assert!(http_res.is_err());
        let Err(up_err) = up_res else {
            return;
        };
        let Err(set_err) = set_res else {
            return;
        };
        let Err(http_err) = http_res else {
            return;
        };
        assert_eq!(up_err.kind(), ErrorKind::InvalidArgument);
        assert!(up_err.to_string().contains("without URL scheme"));
        assert!(!up_err.to_string().contains("[https://"));
        assert_eq!(set_err.kind(), ErrorKind::InvalidArgument);
        assert!(set_err.to_string().contains("without URL scheme"));
        assert!(!set_err.to_string().contains("[https://"));
        assert_eq!(http_err.kind(), ErrorKind::InvalidArgument);
        assert!(http_err.to_string().contains("without URL scheme"));
    }

    #[test]
    fn test_gui_executable_resolvers_prefer_sibling_and_reject_directories() {
        // Arrange
        let Ok(dir) = tempfile::tempdir() else {
            return;
        };
        let cli_dir = dir.path().join("bin");
        let pf_dir = dir.path().join("ProgramFiles");
        let pf_mesh_dir = pf_dir.join("Mesh");
        assert!(std::fs::create_dir_all(&cli_dir).is_ok());
        assert!(std::fs::create_dir_all(&pf_mesh_dir).is_ok());

        let fake_cli = cli_dir.join("mesh.exe");
        let pf_gui = pf_mesh_dir.join("MeshVPN.exe");
        assert!(std::fs::write(&pf_gui, b"stub").is_ok());

        // Act 1: falls back to %ProgramFiles%\Mesh\MeshVPN.exe when sibling missing.
        let found_pf = super::resolve_windows_gui_exe_from(Some(&fake_cli), Some(&pf_dir));
        assert_eq!(found_pf.as_deref(), Some(pf_gui.as_path()));

        // Act 2: sibling MeshVPN.exe takes precedence over ProgramFiles.
        let sibling_gui = cli_dir.join("MeshVPN.exe");
        assert!(std::fs::write(&sibling_gui, b"stub").is_ok());
        let found_sibling = super::resolve_windows_gui_exe_from(Some(&fake_cli), Some(&pf_dir));
        assert_eq!(found_sibling.as_deref(), Some(sibling_gui.as_path()));

        // Act 3: missing everywhere returns None.
        let missing = super::resolve_windows_gui_exe_from(
            Some(&dir.path().join("absent").join("mesh.exe")),
            Some(&dir.path().join("absent-pf")),
        );
        assert!(missing.is_none());

        // Act 4: macOS bundle & sibling resolution.
        let apps_dir = dir.path().join("Applications");
        let bundle = apps_dir.join("Mesh VPN.app");
        assert!(std::fs::create_dir_all(&bundle).is_ok());
        let found_mac = super::resolve_macos_gui_app_from(None, Some(&apps_dir));
        assert_eq!(found_mac.as_deref(), Some(bundle.as_path()));
    }

    #[test]
    fn test_reset_identity_confirmation_policy_requires_yes_when_non_tty() {
        // Arrange & Act
        let non_tty_no_yes = super::require_reset_confirmation(false, false, || Ok(true));
        let non_tty_with_yes = super::require_reset_confirmation(true, false, || Ok(false));
        let tty_declined = super::require_reset_confirmation(false, true, || Ok(false));
        let tty_accepted = super::require_reset_confirmation(false, true, || Ok(true));

        // Assert
        assert_eq!(
            non_tty_no_yes.err().map(|e| e.kind()),
            Some(ErrorKind::InvalidArgument)
        );
        assert!(non_tty_with_yes.is_ok());
        assert_eq!(
            tty_declined.err().map(|e| e.kind()),
            Some(ErrorKind::InvalidArgument)
        );
        assert!(tty_accepted.is_ok());
    }

    #[tokio::test]
    async fn test_reset_identity_wire_contract_and_3_tier_ipc_timeouts() {
        use mesh_net::ipc::{
            IPC_ADMIN_MUTATION_TIMEOUT, IPC_NETCHECK_TIMEOUT, IPC_RO_QUERY_TIMEOUT,
            IpcOperationTier,
        };
        use mesh_proto::agent_ipc::{AgentActionResponse, AgentResetIdentityRequest, DaemonState};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

        // Arrange
        assert_eq!(
            IpcOperationTier::ReadOnlyQuery.response_timeout(),
            IPC_RO_QUERY_TIMEOUT
        );
        assert_eq!(
            IpcOperationTier::NetcheckProbe.response_timeout(),
            IPC_NETCHECK_TIMEOUT
        );
        assert_eq!(
            IpcOperationTier::AdminMutation.response_timeout(),
            IPC_ADMIN_MUTATION_TIMEOUT
        );
        assert_eq!(
            IpcOperationTier::PingProbe {
                count: 4,
                per_probe_timeout_ms: 2_500
            }
            .response_timeout(),
            std::time::Duration::from_millis(12_000)
        );

        let (client_io, mut server_io) = duplex(16 * 1024);
        let resp_dto = AgentActionResponse {
            state: DaemonState::Stopped,
            message: "node identity reset cleanly; ready for enrollment".to_owned(),
        };
        let Ok(resp_bytes) = serde_json::to_vec(&resp_dto) else {
            return;
        };

        // Act
        let client_fut = super::call_agent_stream_with_tier::<
            _,
            AgentResetIdentityRequest,
            AgentActionResponse,
        >(
            client_io,
            hyper::Method::POST,
            "/v1/agent/reset-identity",
            Some(&AgentResetIdentityRequest {}),
            IpcOperationTier::AdminMutation,
        );
        let server_fut = async move {
            let mut buf = [0_u8; 4096];
            let Ok(n) = server_io.read(&mut buf).await else {
                return String::new();
            };
            let req_text = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).into_owned();
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                resp_bytes.len()
            );
            let _head = server_io.write_all(reply.as_bytes()).await;
            let _body = server_io.write_all(&resp_bytes).await;
            let _flush = server_io.flush().await;
            req_text
        };
        let (client_res, wire_req) = tokio::join!(client_fut, server_fut);

        // Assert
        assert!(wire_req.starts_with("POST /v1/agent/reset-identity HTTP/1.1"));
        assert!(matches!(
            client_res,
            Ok(AgentActionResponse {
                state: DaemonState::Stopped,
                ..
            })
        ));
    }
}
