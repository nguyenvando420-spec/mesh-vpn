//! Server administration CLI subcommands routed exclusively over `/run/mesh-server/admin.sock`
//! (`US-002`, `US-012`, `US-013`, `US-045`, `US-046`, `US-047`, `US-056`, `US-074`).

#[cfg(unix)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(any(unix, test))]
use tokio::io::{AsyncRead, AsyncWrite};

use mesh_core::defaults::LINUX_SERVER_ADMIN_SOCKET;
#[cfg(any(unix, test))]
use mesh_core::defaults::MAX_HTTP_BODY_BYTES;
use mesh_core::{AppError, AppResult, NodeName, Port};
#[cfg(any(unix, test))]
use mesh_net::ipc::send_ipc_json_request;
use mesh_proto::admin_ipc::{
    AdminNodeSummary, BackupCreatedResponse, CreatePreAuthKeyRequest, ExpireNodeRequest,
    HardeningCheckResponse, ListAuditEventsResponse, MigrateEndpointRequest,
    MigrateEndpointResponse, PreAuthKeyCreatedResponse, PreAuthKeySummary, RenameNodeRequest,
    RestoreBackupRequest, RestoreBackupResponse, RevokeActionResponse, RotateTlsKeyAction,
    RotateTlsKeyRequest, RotateTlsKeyResponse, ServerAdminStatusResponse,
};

use crate::output::{
    format_audit_events, format_backup_created, format_hardening_check, format_migrate_endpoint,
    format_node_inspect, format_node_list, format_preauth_key_created, format_preauth_key_list,
    format_restore_backup, format_revoke_action, format_rotate_tls_key, format_server_status,
    render_json_string, write_stderr, write_stdout,
};

#[cfg(unix)]
const SERVER_IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const KEY_EXPIRY_WARNING_MS: u64 = 7 * 86_400 * 1_000;

/// Global routing/formatting options passed to Server Admin handlers.
#[derive(Debug, Clone)]
pub(crate) struct AdminDispatchConfig {
    pub(crate) json: bool,
    pub(crate) server_admin_socket_override: Option<String>,
}

/// Top-level Server Admin command tree (`mesh {preauthkey, node, server, audit}`).
#[derive(Debug, Subcommand)]
pub(crate) enum AdminCommand {
    /// Create, list, or revoke enrollment pre-authentication keys (`US-002`).
    Preauthkey(PreauthkeyArgs),
    /// List, inspect, rename, expire, or immediately revoke mesh nodes (`US-012`).
    Node(NodeArgs),
    /// Inspect status, hardening, backups, endpoint migration, and TLS rotation.
    Server(ServerArgs),
    /// Query append-only security and administration audit logs (`US-013`).
    Audit(AuditArgs),
}

#[derive(Debug, Args)]
pub(crate) struct PreauthkeyArgs {
    #[command(subcommand)]
    pub(crate) action: PreauthkeySubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PreauthkeySubcommand {
    /// Generate a new pre-authentication token (plaintext raw key is shown ONCE).
    Create(PreauthkeyCreateArgs),
    /// List non-secret pre-auth key metadata.
    List,
    /// Immediately revoke an unused or reusable pre-auth key.
    Revoke {
        /// Key UUID (`KeyId`) to revoke.
        id: String,
    },
}

#[derive(Debug, Args)]
pub(crate) struct PreauthkeyCreateArgs {
    /// Token lifetime (e.g. `300s`, `15m`, `1h`, `7d`).
    #[arg(long, default_value = "1h")]
    pub(crate) ttl: String,
    /// Scope key exclusively for re-authenticating an existing node UUID or name.
    #[arg(long = "for")]
    pub(crate) for_node: Option<String>,
    /// Allow registering multiple devices with this key.
    #[arg(long)]
    pub(crate) reusable: bool,
    /// Maximum uses allowed (`1` when single-use; defaults to `10` when `--reusable`).
    #[arg(long)]
    pub(crate) max_uses: Option<u32>,
    /// Auto-reap registered nodes once offline beyond timeout.
    #[arg(long)]
    pub(crate) ephemeral: bool,
    /// Offline reap timeout in seconds for `--ephemeral` nodes.
    #[arg(long)]
    pub(crate) ephemeral_timeout_secs: Option<u32>,
}

#[derive(Debug, Args)]
pub(crate) struct NodeArgs {
    #[command(subcommand)]
    pub(crate) action: NodeSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum NodeSubcommand {
    /// List registered mesh nodes and endpoint acknowledgement versions.
    List,
    /// Inspect detailed metadata for a node UUID or name (`GET /v1/admin/nodes/{id}`).
    Inspect {
        /// Target node UUID or RFC 1123 name.
        node: String,
    },
    /// Rename an existing node (`RFC 1123` label).
    Rename {
        /// Target node UUID or name.
        node: String,
        /// Replacement RFC 1123 label.
        new_name: String,
    },
    /// Immediately revoke a node in RAM, close active streams, and persist revocation.
    Revoke {
        /// Target node UUID or name.
        node: String,
    },
    /// Expire node identity key immediately or clear expiration (`--never`).
    Expire {
        /// Target node UUID or name.
        node: String,
        /// Clear key expiry indefinitely (`--never`, intended for trusted servers).
        #[arg(long)]
        never: bool,
    },
}

#[derive(Debug, Args)]
pub(crate) struct ServerArgs {
    #[command(subcommand)]
    pub(crate) action: ServerSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServerSubcommand {
    /// Display live server Control/Relay/STUN ports, pins, Netmap version, and DB state.
    Status,
    /// Alias displaying server configuration and migration status.
    Info,
    /// Run fail-closed Linux server hardening self-checks (`US-056`).
    HardeningCheck,
    /// Create a verified atomic hot backup of `redb` state and `.sha256` sidecar.
    Backup,
    /// Verify and restore an archived snapshot (`US-045`).
    Restore(RestoreArgs),
    /// Migrate public host, TCP Control/Relay port, UDP STUN port, or TLS mode (`US-074`).
    MigrateEndpoint(MigrateEndpointArgs),
    /// Stage or promote TLS server identity keypair (`US-047 AC5`).
    RotateTlsKey(RotateTlsKeyArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RestoreArgs {
    /// Path to backup snapshot archive to verify and restore.
    pub(crate) file: String,
    /// Enforce restored `netmap_version >= N` anti-rollback threshold (`US-045`).
    #[arg(long)]
    pub(crate) min_netmap_version: Option<u64>,
    /// Explicitly authorize changing published SPKI pin (`?allow_pin_change=true`).
    #[arg(long)]
    pub(crate) force_repin: bool,
    /// Disable sidecar SHA-256 verification (not recommended).
    #[arg(long)]
    pub(crate) skip_sha256: bool,
}

#[derive(Debug, Args)]
pub(crate) struct MigrateEndpointArgs {
    /// Updated public hostname or IP address advertised in Netmap `RelayMap`.
    #[arg(long)]
    pub(crate) host: Option<String>,
    /// Replacement Control/Relay HTTPS TCP port (`1..=65535`).
    #[arg(long)]
    pub(crate) tcp_port: Option<u16>,
    /// Replacement embedded STUN UDP port (`1..=65535`).
    #[arg(long)]
    pub(crate) stun_port: Option<u16>,
    /// Replacement TLS mode (`ip_pinned`, `acme`, `reverse_proxy`).
    #[arg(long)]
    pub(crate) tls_mode: Option<String>,
    /// Dual-listener grace window duration in seconds during live port migration.
    #[arg(long)]
    pub(crate) transition_window_secs: Option<u64>,
    /// Extend an ongoing transition window by N seconds (`--extend-window`).
    #[arg(long)]
    pub(crate) extend_window: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct RotateTlsKeyArgs {
    /// Stage secondary `next_pin` keypair and distribute via Netmap before promotion.
    #[arg(long)]
    pub(crate) stage: bool,
    /// Promote previously staged `next_pin` to primary `active_pin`.
    #[arg(long)]
    pub(crate) promote: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AuditArgs {
    #[command(subcommand)]
    pub(crate) action: AuditSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuditSubcommand {
    /// List recent immutable audit trail entries.
    List {
        /// Maximum number of recent events to fetch.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

/// Returns diagnostic subsystem label.
#[cfg(test)]
#[must_use]
pub(crate) const fn status_label() -> &'static str {
    "admin_cmds:ready"
}

/// Dispatches any [`AdminCommand`] over `/run/mesh-server/admin.sock`.
pub(crate) async fn handle_admin_command(
    cmd: &AdminCommand,
    cfg: &AdminDispatchConfig,
) -> AppResult<()> {
    match cmd {
        AdminCommand::Preauthkey(args) => handle_preauthkey(args, cfg).await,
        AdminCommand::Node(args) => handle_node(args, cfg).await,
        AdminCommand::Server(args) => handle_server(args, cfg).await,
        AdminCommand::Audit(args) => handle_audit(args, cfg).await,
    }
}

async fn handle_preauthkey(args: &PreauthkeyArgs, cfg: &AdminDispatchConfig) -> AppResult<()> {
    match &args.action {
        PreauthkeySubcommand::Create(create) => {
            let req = build_create_preauth_request(create)?;
            let resp: PreAuthKeyCreatedResponse = send_server_admin(
                cfg,
                hyper::Method::POST,
                "/v1/admin/preauth-keys",
                Some(&req),
            )
            .await?;
            emit_admin(&resp, cfg.json, format_preauth_key_created)
        }
        PreauthkeySubcommand::List => {
            let resp: Vec<PreAuthKeySummary> = send_server_admin(
                cfg,
                hyper::Method::GET,
                "/v1/admin/preauth-keys",
                None::<&()>,
            )
            .await?;
            emit_admin(&resp, cfg.json, |items| format_preauth_key_list(items))
        }
        PreauthkeySubcommand::Revoke { id } => {
            let clean_id = validate_path_segment(id)?;
            let path = format!("/v1/admin/preauth-keys/{clean_id}/revoke");
            let resp: RevokeActionResponse =
                send_server_admin(cfg, hyper::Method::POST, &path, Some(&())).await?;
            emit_revoke_result("preauthkey_revoke", &resp, cfg.json)
        }
    }
}

async fn handle_node(args: &NodeArgs, cfg: &AdminDispatchConfig) -> AppResult<()> {
    match &args.action {
        NodeSubcommand::List => {
            let resp: Vec<AdminNodeSummary> =
                send_server_admin(cfg, hyper::Method::GET, "/v1/admin/nodes", None::<&()>).await?;
            emit_admin(&resp, cfg.json, |items| format_node_list(items))?;
            if !cfg.json
                && let Some(warn) = format_expiring_nodes_warning(&resp, current_unix_ms())
            {
                write_stderr(&warn)?;
            }
            Ok(())
        }
        NodeSubcommand::Inspect { node } => {
            let clean = validate_path_segment(node)?;
            let path = format!("/v1/admin/nodes/{clean}");
            let resp: AdminNodeSummary =
                send_server_admin(cfg, hyper::Method::GET, &path, None::<&()>).await?;
            emit_admin(&resp, cfg.json, format_node_inspect)?;
            if !cfg.json
                && let Some(warn) =
                    format_expiring_nodes_warning(std::slice::from_ref(&resp), current_unix_ms())
            {
                write_stderr(&warn)?;
            }
            Ok(())
        }
        NodeSubcommand::Rename { node, new_name } => {
            let clean = validate_path_segment(node)?;
            let req = RenameNodeRequest {
                new_name: NodeName::parse(new_name)?,
            };
            let path = format!("/v1/admin/nodes/{clean}/rename");
            let resp: AdminNodeSummary =
                send_server_admin(cfg, hyper::Method::POST, &path, Some(&req)).await?;
            emit_admin(&resp, cfg.json, format_node_inspect)
        }
        NodeSubcommand::Revoke { node } => {
            let clean = validate_path_segment(node)?;
            let path = format!("/v1/admin/nodes/{clean}/revoke");
            let resp: RevokeActionResponse =
                send_server_admin(cfg, hyper::Method::POST, &path, Some(&())).await?;
            emit_revoke_result("node_revoke", &resp, cfg.json)
        }
        NodeSubcommand::Expire { node, never } => {
            let clean = validate_path_segment(node)?;
            let path = format!("/v1/admin/nodes/{clean}/expire");
            let req = ExpireNodeRequest { never: *never };
            let resp: RevokeActionResponse =
                send_server_admin(cfg, hyper::Method::POST, &path, Some(&req)).await?;
            emit_revoke_result("node_expire", &resp, cfg.json)
        }
    }
}

async fn handle_server(args: &ServerArgs, cfg: &AdminDispatchConfig) -> AppResult<()> {
    match &args.action {
        ServerSubcommand::Status | ServerSubcommand::Info => {
            let resp: ServerAdminStatusResponse = send_server_admin(
                cfg,
                hyper::Method::GET,
                "/v1/admin/server/status",
                None::<&()>,
            )
            .await?;
            emit_admin(&resp, cfg.json, format_server_status)
        }
        ServerSubcommand::HardeningCheck => {
            let resp: HardeningCheckResponse = send_server_admin(
                cfg,
                hyper::Method::GET,
                "/v1/admin/hardening-check",
                None::<&()>,
            )
            .await?;
            emit_admin(&resp, cfg.json, format_hardening_check)?;
            if !resp.all_passed {
                return Err(AppError::permission_denied(
                    "server hardening check failed one or more security baseline items",
                ));
            }
            Ok(())
        }
        ServerSubcommand::Backup => {
            let resp: BackupCreatedResponse =
                send_server_admin(cfg, hyper::Method::POST, "/v1/admin/backup", Some(&())).await?;
            emit_admin(&resp, cfg.json, format_backup_created)
        }
        ServerSubcommand::Restore(restore) => {
            let path =
                build_restore_path_with_options(restore.force_repin, restore.min_netmap_version);
            let req = RestoreBackupRequest {
                snapshot_path: restore.file.clone(),
                verify_sha256: !restore.skip_sha256,
            };
            let resp: RestoreBackupResponse =
                send_server_admin(cfg, hyper::Method::POST, &path, Some(&req)).await?;
            emit_admin(&resp, cfg.json, format_restore_backup)?;
            validate_min_netmap_version(restore.min_netmap_version, resp.netmap_version)
        }
        ServerSubcommand::MigrateEndpoint(mig) => {
            let req = MigrateEndpointRequest {
                host: mig.host.clone(),
                tcp_port: mig.tcp_port.map(Port::from_u16).transpose()?,
                stun_port: mig.stun_port.map(Port::from_u16).transpose()?,
                tls_mode: mig.tls_mode.clone(),
                transition_window_secs: mig.transition_window_secs,
                extend_window_secs: mig.extend_window,
            };
            let resp: MigrateEndpointResponse = send_server_admin(
                cfg,
                hyper::Method::POST,
                "/v1/admin/server/migrate-endpoint",
                Some(&req),
            )
            .await?;
            emit_admin(&resp, cfg.json, format_migrate_endpoint)
        }
        ServerSubcommand::RotateTlsKey(rot) => {
            let action = match (rot.stage, rot.promote) {
                (true, false) => RotateTlsKeyAction::Stage,
                (false, true) => RotateTlsKeyAction::Promote,
                _ => {
                    return Err(AppError::invalid_argument(
                        "specify exactly one of --stage or --promote",
                    ));
                }
            };
            let req = RotateTlsKeyRequest { action };
            let resp: RotateTlsKeyResponse = send_server_admin(
                cfg,
                hyper::Method::POST,
                "/v1/admin/server/rotate-tls-key",
                Some(&req),
            )
            .await?;
            emit_admin(&resp, cfg.json, format_rotate_tls_key)
        }
    }
}

async fn handle_audit(args: &AuditArgs, cfg: &AdminDispatchConfig) -> AppResult<()> {
    match &args.action {
        AuditSubcommand::List { limit } => {
            let path = format!("/v1/admin/audit-events?limit={limit}");
            let resp: ListAuditEventsResponse =
                send_server_admin(cfg, hyper::Method::GET, &path, None::<&()>).await?;
            emit_admin(&resp, cfg.json, format_audit_events)
        }
    }
}

/// Builds the REST path for `POST /v1/admin/restore`, adding `?allow_pin_change=true` on `--force-repin`.
#[cfg(test)]
#[must_use]
pub(crate) const fn build_restore_path(force_repin: bool) -> &'static str {
    if force_repin {
        "/v1/admin/restore?allow_pin_change=true"
    } else {
        "/v1/admin/restore"
    }
}

/// Builds the REST path for `POST /v1/admin/restore` including optional server-side
/// `min_netmap_version` anti-rollback query enforcement (`US-045`).
#[must_use]
pub(crate) fn build_restore_path_with_options(
    force_repin: bool,
    min_netmap_version: Option<u64>,
) -> String {
    match (force_repin, min_netmap_version) {
        (false, None) => "/v1/admin/restore".to_owned(),
        (true, None) => "/v1/admin/restore?allow_pin_change=true".to_owned(),
        (false, Some(min_ver)) => format!("/v1/admin/restore?min_netmap_version={min_ver}"),
        (true, Some(min_ver)) => {
            format!("/v1/admin/restore?allow_pin_change=true&min_netmap_version={min_ver}")
        }
    }
}

fn current_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    u64::try_from(millis).unwrap_or(u64::MAX)
}

pub(crate) fn format_expiring_nodes_warning(
    nodes: &[AdminNodeSummary],
    now_ms: u64,
) -> Option<String> {
    let mut soon = Vec::new();
    for node in nodes {
        if node.status != "active" {
            continue;
        }
        if let Some(exp_ms) = node.key_expires_at_ms {
            let remaining_ms = exp_ms.saturating_sub(now_ms);
            if remaining_ms <= KEY_EXPIRY_WARNING_MS {
                let hours = remaining_ms.div_ceil(3_600 * 1_000);
                soon.push(format!("{} ({hours}h remaining)", node.name));
            }
        }
    }
    if soon.is_empty() {
        None
    } else {
        Some(format!(
            "WARN: node key(s) expiring within 7 days: {}; renew with a preauth key (--for <node>) or run `mesh node expire <node> --never`.\n",
            soon.join(", ")
        ))
    }
}

/// Enforces optional `--min-netmap-version` anti-rollback verification (`US-045`).
pub(crate) fn validate_min_netmap_version(
    min_required: Option<u64>,
    restored_version: u64,
) -> AppResult<()> {
    if let Some(min_ver) = min_required
        && restored_version < min_ver
    {
        return Err(AppError::invalid_argument(format!(
            "restored netmap_version {restored_version} is below --min-netmap-version {min_ver}"
        )));
    }
    Ok(())
}

/// Validates `--ttl` duration syntax (`30s`, `15m`, `1h`, `7d`) cleanly into positive seconds.
pub(crate) fn parse_ttl_secs(raw: &str) -> AppResult<u64> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return Err(AppError::invalid_argument(format!(
            "invalid --ttl '{raw}': expected <integer><s|m|h|d>, e.g. 1h"
        )));
    }
    let split_at = trimmed.len().saturating_sub(1);
    let (digits, unit) = trimmed.split_at(split_at);
    let qty: u64 = digits
        .parse()
        .map_err(|_| AppError::invalid_argument(format!("invalid --ttl quantity in '{raw}'")))?;
    let multiplier = match unit {
        "s" | "S" => 1_u64,
        "m" | "M" => 60_u64,
        "h" | "H" => 3600_u64,
        "d" | "D" => 86_400_u64,
        _ => {
            return Err(AppError::invalid_argument(format!(
                "invalid --ttl unit '{unit}': expected s, m, h, or d"
            )));
        }
    };
    let secs = qty
        .checked_mul(multiplier)
        .ok_or_else(|| AppError::invalid_argument("pre-auth key --ttl overflows u64 seconds"))?;
    if secs == 0 {
        return Err(AppError::invalid_argument(
            "pre-auth key --ttl must be > 0 seconds",
        ));
    }
    Ok(secs)
}

/// Builds a validated `CreatePreAuthKeyRequest` enforcing single-use vs `--reusable` invariants.
pub(crate) fn build_create_preauth_request(
    args: &PreauthkeyCreateArgs,
) -> AppResult<CreatePreAuthKeyRequest> {
    let ttl_secs = parse_ttl_secs(&args.ttl)?;
    let max_uses = match (args.reusable, args.max_uses) {
        (false, None) => 1,
        (false, Some(1)) => 1,
        (false, Some(_other)) => {
            return Err(AppError::invalid_argument(
                "--max-uses != 1 requires --reusable",
            ));
        }
        (true, None) => 10,
        (true, Some(n)) if n >= 1 => n,
        (true, Some(_)) => {
            return Err(AppError::invalid_argument("--max-uses must be >= 1"));
        }
    };
    let target_node = args
        .for_node
        .as_deref()
        .map(validate_path_segment)
        .transpose()?
        .map(str::to_owned);
    Ok(CreatePreAuthKeyRequest {
        ttl_secs,
        reusable: args.reusable,
        max_uses,
        is_ephemeral: args.ephemeral,
        ephemeral_timeout_secs: args.ephemeral_timeout_secs,
        target_node,
    })
}

fn validate_path_segment(raw: &str) -> AppResult<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains(['/', '\\', '?', '#', ' ', '\t', '\r', '\n'])
        || trimmed == "."
        || trimmed == ".."
    {
        return Err(AppError::invalid_argument(format!(
            "invalid node/key identifier reference '{raw}'"
        )));
    }
    Ok(trimmed)
}

fn emit_admin<T, F>(value: &T, json_mode: bool, human_fmt: F) -> AppResult<()>
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

fn emit_revoke_result(
    action_label: &str,
    resp: &RevokeActionResponse,
    json_mode: bool,
) -> AppResult<()> {
    let (human_line, stderr_warn) = format_revoke_action(action_label, resp);
    if let Some(warning) = stderr_warn {
        write_stderr(&warning)?;
    }
    if json_mode {
        let json_out = render_json_string(resp)?;
        write_stdout(&json_out)
    } else {
        write_stdout(&human_line)
    }
}

/// Dispatches a JSON request over an already-connected Server Admin stream (UDS or test duplex).
#[cfg(any(unix, test))]
pub(crate) async fn call_server_admin_stream<S, Req, Resp>(
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

async fn send_server_admin<Req, Resp>(
    cfg: &AdminDispatchConfig,
    method: hyper::Method,
    path: &str,
    body: Option<&Req>,
) -> AppResult<Resp>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let socket_path = cfg
        .server_admin_socket_override
        .as_deref()
        .unwrap_or(LINUX_SERVER_ADMIN_SOCKET);

    #[cfg(unix)]
    {
        let stream = match tokio::time::timeout(
            SERVER_IPC_CONNECT_TIMEOUT,
            tokio::net::UnixStream::connect(socket_path),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                let mapped = match err.kind() {
                    std::io::ErrorKind::PermissionDenied => AppError::permission_denied(format!(
                        "permission denied accessing {socket_path}: caller must belong to mesh-admin group"
                    )),
                    _ => AppError::unavailable(format!(
                        "mesh-server admin socket {socket_path} is unreachable: {err}"
                    )),
                };
                return Err(mapped);
            }
            Err(_) => {
                return Err(AppError::unavailable(format!(
                    "timed out connecting to mesh-server admin socket {socket_path}"
                )));
            }
        };
        call_server_admin_stream(stream, method, path, body).await
    }

    #[cfg(not(unix))]
    {
        let _unused = (method, path, body);
        Err(AppError::invalid_argument(format!(
            "mesh server admin commands target Linux UDS {socket_path}; execute on the mesh-server host"
        )))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use mesh_core::{ErrorKind, NodeName};
    use mesh_proto::admin_ipc::{AdminNodeSummary, RestoreBackupResponse};

    use super::{
        PreauthkeyCreateArgs, build_create_preauth_request, build_restore_path,
        build_restore_path_with_options, call_server_admin_stream, format_expiring_nodes_warning,
        parse_ttl_secs, validate_min_netmap_version, validate_path_segment,
    };

    #[test]
    fn test_ttl_parser_and_preauth_request_validation() {
        // Arrange / Act
        assert_eq!(parse_ttl_secs("30s").expect("seconds"), 30);
        assert_eq!(parse_ttl_secs("15m").expect("minutes"), 900);
        assert_eq!(parse_ttl_secs("2h").expect("hours"), 7200);
        assert_eq!(parse_ttl_secs("7d").expect("days"), 604_800);
        assert!(parse_ttl_secs("0h").is_err());
        assert!(parse_ttl_secs("1w").is_err());

        let single_args = PreauthkeyCreateArgs {
            ttl: "1h".to_owned(),
            for_node: Some("laptop-01".to_owned()),
            reusable: false,
            max_uses: None,
            ephemeral: false,
            ephemeral_timeout_secs: None,
        };
        let bad_single = PreauthkeyCreateArgs {
            max_uses: Some(5),
            ..single_args
        };
        let good_single = PreauthkeyCreateArgs {
            ttl: "1h".to_owned(),
            for_node: Some("laptop-01".to_owned()),
            reusable: false,
            max_uses: None,
            ephemeral: false,
            ephemeral_timeout_secs: None,
        };

        // Assert
        assert!(build_create_preauth_request(&bad_single).is_err());
        let req = build_create_preauth_request(&good_single).expect("valid single req");
        assert_eq!(req.max_uses, 1);
        assert_eq!(req.target_node.as_deref(), Some("laptop-01"));
    }

    #[test]
    fn test_restore_force_repin_path_and_anti_rollback_check() {
        // Arrange / Act
        assert_eq!(build_restore_path(false), "/v1/admin/restore");
        assert_eq!(
            build_restore_path(true),
            "/v1/admin/restore?allow_pin_change=true"
        );
        assert!(validate_min_netmap_version(Some(10), 12).is_ok());
        let rollback = validate_min_netmap_version(Some(15), 12);

        // Assert
        assert_eq!(
            rollback.err().map(|e| e.kind()),
            Some(ErrorKind::InvalidArgument)
        );
        assert!(validate_path_segment("../etc/passwd").is_err());
        assert!(validate_path_segment("node-alpha-1").is_ok());
    }

    #[tokio::test]
    async fn test_call_server_admin_stream_sends_allow_pin_change_query() {
        // Arrange
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let resp = RestoreBackupResponse {
            restored: true,
            netmap_version: 22,
            node_count: 5,
        };
        let payload = serde_json::to_vec(&resp).expect("serialize restore");
        let path = build_restore_path(true);

        // Act
        let client_fut = call_server_admin_stream::<_, (), RestoreBackupResponse>(
            client_io,
            hyper::Method::POST,
            path,
            Some(&()),
        );
        let server_fut = async move {
            let mut buf = [0_u8; 4096];
            let n = server_io.read(&mut buf).await.expect("read req");
            let req_text = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).into_owned();
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                payload.len()
            );
            server_io.write_all(reply.as_bytes()).await.expect("head");
            server_io.write_all(&payload).await.expect("body");
            server_io.flush().await.expect("flush");
            req_text
        };
        let (got_res, req_text) = tokio::join!(client_fut, server_fut);
        let got = got_res.expect("restore response");

        // Assert
        assert!(req_text.starts_with("POST /v1/admin/restore?allow_pin_change=true HTTP/1.1"));
        assert!(got.restored);
        assert_eq!(got.netmap_version, 22);
    }

    #[test]
    fn test_restore_path_with_min_netmap_version_and_expiring_node_warning() {
        // Arrange
        assert_eq!(
            build_restore_path_with_options(false, Some(42)),
            "/v1/admin/restore?min_netmap_version=42"
        );
        assert_eq!(
            build_restore_path_with_options(true, Some(99)),
            "/v1/admin/restore?allow_pin_change=true&min_netmap_version=99"
        );

        let now_ms = 1_762_958_151_000_u64;
        let nodes = vec![
            AdminNodeSummary {
                node_id: mesh_core::NodeId::new_v7(now_ms),
                name: NodeName::parse("safe-node").expect("name"),
                overlay_ip: "10.100.0.2".parse().expect("ip"),
                status: "active".to_owned(),
                online: true,
                last_seen_at_ms: now_ms,
                key_expires_at_ms: Some(now_ms + 30 * 86_400 * 1_000),
                os: "linux".to_owned(),
                arch: "amd64".to_owned(),
                agent_version: "0.1.0".to_owned(),
                acked_endpoint_version: 0,
            },
            AdminNodeSummary {
                node_id: mesh_core::NodeId::new_v7(now_ms + 1),
                name: NodeName::parse("never-node").expect("name"),
                overlay_ip: "10.100.0.3".parse().expect("ip"),
                status: "active".to_owned(),
                online: true,
                last_seen_at_ms: now_ms,
                key_expires_at_ms: None,
                os: "linux".to_owned(),
                arch: "amd64".to_owned(),
                agent_version: "0.1.0".to_owned(),
                acked_endpoint_version: 0,
            },
            AdminNodeSummary {
                node_id: mesh_core::NodeId::new_v7(now_ms + 2),
                name: NodeName::parse("soon-node").expect("name"),
                overlay_ip: "10.100.0.4".parse().expect("ip"),
                status: "active".to_owned(),
                online: false,
                last_seen_at_ms: now_ms,
                key_expires_at_ms: Some(now_ms + 2 * 86_400 * 1_000),
                os: "linux".to_owned(),
                arch: "amd64".to_owned(),
                agent_version: "0.1.0".to_owned(),
                acked_endpoint_version: 0,
            },
        ];

        // Act
        let warn = format_expiring_nodes_warning(&nodes, now_ms).expect("warning expected");

        // Assert
        assert!(warn.contains("soon-node"));
        assert!(!warn.contains("safe-node"));
        assert!(!warn.contains("never-node"));
    }
}
