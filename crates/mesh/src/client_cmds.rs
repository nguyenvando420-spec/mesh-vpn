//! Client-side CLI subcommands routed exclusively over local `meshd-ro` and `meshd-admin` IPC
//! (`US-004`, `US-039`, `US-040`, `US-055`, `HR-G2-04`).

use std::io::Read as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
use mesh_net::ipc::send_ipc_json_request;
use mesh_net::ledger::{LedgerCleanupOps, ResourceLedger};
use mesh_proto::agent_ipc::{
    AgentActionResponse, AgentRotateKeyRequest, AgentSetRequest, AgentStatusResponse,
    AgentUpRequest, BugreportResponse, DaemonState, NetcheckResponse, PingRequest, PingResponse,
    PingVia,
};

use crate::output::{
    format_agent_action, format_bugreport, format_netcheck, format_peers, format_ping,
    format_status, render_json_string, write_stdout,
};

const ENV_AUTHKEY_FILE: &str = "MESH_AUTHKEY_FILE";
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_millis(850);
#[cfg(windows)]
const WIN_ERROR_FILE_NOT_FOUND: i32 = 2;
#[cfg(windows)]
const WIN_ERROR_ACCESS_DENIED: i32 = 5;
#[cfg(windows)]
const WIN_ERROR_PIPE_BUSY: i32 = 231;

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
    /// Generate a redacted non-secret diagnostic archive (`meshd-admin`).
    Bugreport,
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
            let resp: AgentStatusResponse =
                send_ro_request(cfg, hyper::Method::GET, "/v1/agent/status", None::<&()>).await?;
            emit_formatted(&resp, cfg.json, format_status)
        }
        ClientCommand::Peers => {
            let resp: AgentStatusResponse =
                send_ro_request(cfg, hyper::Method::GET, "/v1/agent/peers", None::<&()>).await?;
            emit_formatted(&resp, cfg.json, format_peers)
        }
        ClientCommand::Ping(args) => handle_ping(args, cfg).await,
        ClientCommand::Netcheck => {
            let resp: NetcheckResponse =
                send_ro_request(cfg, hyper::Method::POST, "/v1/agent/netcheck", Some(&())).await?;
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
        ClientCommand::Bugreport => {
            let resp: BugreportResponse =
                send_admin_request(cfg, hyper::Method::POST, "/v1/agent/bugreport", Some(&()))
                    .await?;
            emit_formatted(&resp, cfg.json, format_bugreport)
        }
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
    let resp: PingResponse =
        send_ro_request(cfg, hyper::Method::POST, "/v1/agent/ping", Some(&req)).await?;
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

/// Dispatches a JSON request over an already-connected duplex or IPC stream.
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
    send_ipc_json_request(stream, method, path, body, MAX_HTTP_BODY_BYTES).await
}

async fn send_ro_request<Req, Resp>(
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
        .ro_ipc_override
        .as_deref()
        .unwrap_or(default_ro_endpoint());
    connect_and_send(endpoint, false, method, path, body).await
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
    connect_and_send(endpoint, true, method, path, body).await
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
) -> AppResult<Resp>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let stream = match tokio::time::timeout(
        IPC_CONNECT_TIMEOUT,
        tokio::net::UnixStream::connect(endpoint),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(err)) => return Err(map_unix_connect_error(endpoint, is_admin, &err)),
        Err(_) => {
            return Err(AppError::unavailable(format!(
                "meshd daemon is not running (timed out connecting to {endpoint})"
            )));
        }
    };
    call_agent_stream(stream, method, path, body).await
}

#[cfg(unix)]
fn map_unix_connect_error(endpoint: &str, is_admin: bool, err: &std::io::Error) -> AppError {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied if is_admin => AppError::permission_denied(format!(
            "permission denied accessing meshd admin socket {endpoint}: run as administrator/mesh-admin"
        )),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            AppError::unavailable(format!("meshd daemon is not running ({endpoint}: {err})"))
        }
        _ => AppError::unavailable(format!(
            "meshd daemon is not running (failed opening {endpoint}: {err})"
        )),
    }
}

#[cfg(windows)]
async fn connect_and_send<Req, Resp>(
    pipe_name: &str,
    is_admin: bool,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
) -> AppResult<Resp>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let stream = connect_windows_named_pipe(pipe_name, is_admin).await?;
    call_agent_stream(stream, method, path, body).await
}

#[cfg(windows)]
async fn connect_windows_named_pipe(
    pipe_name: &str,
    is_admin: bool,
) -> AppResult<tokio::net::windows::named_pipe::NamedPipeClient> {
    let deadline = tokio::time::Instant::now() + IPC_CONNECT_TIMEOUT;
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(WIN_ERROR_PIPE_BUSY) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(AppError::unavailable(format!(
                        "meshd daemon is not running (busy pipe timeout on {pipe_name})"
                    )));
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) if err.raw_os_error() == Some(WIN_ERROR_ACCESS_DENIED) && is_admin => {
                return Err(AppError::permission_denied(format!(
                    "permission denied accessing {pipe_name}: run from an elevated Administrator prompt"
                )));
            }
            Err(err) if err.raw_os_error() == Some(WIN_ERROR_FILE_NOT_FOUND) => {
                return Err(AppError::unavailable(format!(
                    "meshd daemon is not running (pipe {pipe_name} unavailable)"
                )));
            }
            Err(err) => {
                return Err(AppError::unavailable(format!(
                    "meshd daemon is not running (failed opening {pipe_name}: {err})"
                )));
            }
        }
    }
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
}
