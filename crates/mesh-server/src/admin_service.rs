//! Local Unix-domain-socket-only Server Admin API (`/run/mesh-server/admin.sock`, `SEC-14`,
//! `US-002`, `US-012`, `US-013`, `US-045`, `US-047 AC5`, `US-074`, `WP-S1-01`).
//!
//! Strictly forbidden from binding to any TCP address (`SEC-14`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mesh_core::brand::PREAUTH_KEY_PREFIX;
use mesh_core::defaults::MAX_ADMIN_IPC_BODY_BYTES;
use mesh_core::{AppError, AppResult, KeyId, NodeId, NodeName};
use mesh_crypto::{PreAuthToken, random_bytes, sha256_digest};
use mesh_net::serve_ipc_http_connection;
use mesh_proto::admin_ipc::{
    AdminNodeSummary, AuditEventDto, BackupCreatedResponse, CreatePreAuthKeyRequest,
    ExpireNodeRequest, HardeningCheckItem, HardeningCheckResponse, ListAuditEventsResponse,
    MigrateEndpointRequest, PersistenceTier, PreAuthKeyCreatedResponse, PreAuthKeySummary,
    RenameNodeRequest, RestoreBackupRequest, RestoreBackupResponse, RevokeActionResponse,
    RotateTlsKeyAction, RotateTlsKeyRequest, RotateTlsKeyResponse, ServerAdminStatusResponse,
};
use mesh_proto::control::TerminationReason;
use mesh_proto::relay::RelayNoticeCode;
use mesh_store::{
    AuditQuery, ControlStore, CreatePreAuthKeyInput, MAX_PREAUTH_TTL_SECS, NodeStatus,
    RestoreOptions, StoredNodeRecord,
};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::acme::AcmeManager;
use crate::config::{ServerConfig, TlsMode};
use crate::control_handlers::{error_response, json_response};
use crate::listener_set::ListenerSet;
use crate::netmap_hub::NetmapHub;
use crate::relay_hub::RelayHub;

const TLS_ROTATE_GRACE_MS: u64 = 7 * 86_400 * 1_000;

/// Authenticated local OS caller principal extracted from kernel peer credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerPrincipal(pub String);

impl Default for CallerPrincipal {
    fn default() -> Self {
        Self("local-admin".to_owned())
    }
}

/// Shared dependencies injected into all local Server Admin UDS routes.
#[derive(Clone, Debug)]
pub struct AdminAppState {
    /// Active server configuration.
    pub config: Arc<ServerConfig>,
    /// Control ACID store (`redb` + emergency log + backups).
    pub store: Arc<ControlStore>,
    /// Active TLS & ACME certificate manager.
    pub acme: Arc<AcmeManager>,
    /// Public Control/Relay & STUN listener coordinator.
    pub listeners: Arc<ListenerSet>,
    /// Active `/v1/netmap/stream` subscriber hub.
    pub netmap_hub: Arc<NetmapHub>,
    /// Active `/v1/relay` Blind Relay forwarding hub.
    pub relay_hub: Arc<RelayHub>,
}

impl AdminAppState {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "admin_service:ready"
    }
}

/// Builds the Axum router serving local Admin IPC operations (`/v1/admin/*`).
pub fn build_admin_router(state: AdminAppState) -> Router {
    Router::new()
        .route(
            "/v1/admin/preauth-keys",
            get(handle_list_preauth_keys).post(handle_create_preauth_key),
        )
        .route(
            "/v1/admin/preauth-keys/{id}",
            axum::routing::delete(handle_revoke_preauth_key),
        )
        .route(
            "/v1/admin/preauth-keys/{id}/revoke",
            post(handle_revoke_preauth_key),
        )
        .route("/v1/admin/nodes", get(handle_list_nodes))
        .route("/v1/admin/nodes/{id}/rename", post(handle_rename_node))
        .route("/v1/admin/nodes/{id}/expire", post(handle_expire_node))
        .route("/v1/admin/nodes/{id}/revoke", post(handle_revoke_node))
        .route(
            "/v1/admin/nodes/{id}",
            get(handle_get_node).delete(handle_revoke_node),
        )
        .route("/v1/admin/server/status", get(handle_server_status))
        .route("/v1/admin/hardening-check", get(handle_hardening_check))
        .route("/v1/admin/audit-events", get(handle_list_audit_events))
        .route("/v1/admin/backup", post(handle_backup))
        .route("/v1/admin/server/backup", post(handle_backup))
        .route("/v1/admin/restore", post(handle_restore))
        .route("/v1/admin/server/restore", post(handle_restore))
        .route(
            "/v1/admin/server/migrate-endpoint",
            post(handle_migrate_endpoint),
        )
        .route(
            "/v1/admin/server/rotate-tls-key",
            post(handle_rotate_tls_key),
        )
        .layer(DefaultBodyLimit::max(MAX_ADMIN_IPC_BODY_BYTES))
        .with_state(state)
}

/// Serves an already-authenticated local admin IPC stream (UDS on Linux, duplex stream in tests).
pub async fn serve_admin_ipc_stream<S>(
    stream: S,
    state: AdminAppState,
    principal: CallerPrincipal,
) -> AppResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let router = build_admin_router(state).layer(axum::Extension(principal));
    serve_ipc_http_connection(stream, router).await
}

/// Binds and serves the local Admin API strictly over Unix Domain Socket on Linux (`SEC-14`).
///
/// On non-Linux development hosts this starts cleanly without opening any network or TCP socket.
#[cfg(target_os = "linux")]
pub async fn start_admin_ipc_listener(
    state: AdminAppState,
    tracker: &TaskTracker,
    shutdown: CancellationToken,
) -> AppResult<()> {
    use std::os::linux::fs::MetadataExt as _;

    use mesh_net::ipc::IpcChannelKind;
    use mesh_net::ipc_linux::{
        bind_linux_ipc_listener, server_runtime_dir_policy, verify_unix_socket_peer,
    };

    let service_uid = std::fs::metadata("/proc/self")
        .map(|m| m.st_uid())
        .unwrap_or(0);
    let admin_gid = lookup_linux_group_gid(&state.config.admin_group_name);
    let sock_mode = if admin_gid.is_some() { 0o660 } else { 0o600 };

    let listener = bind_linux_ipc_listener(
        &state.config.admin_socket_path,
        server_runtime_dir_policy(service_uid, admin_gid),
        sock_mode,
        admin_gid,
    )?;

    let loop_tracker = tracker.clone();
    tracker.spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                accept_res = listener.accept() => {
                    if let Ok((stream, _)) = accept_res {
                        let st = state.clone();
                        match verify_unix_socket_peer(
                            &stream,
                            IpcChannelKind::ServerAdmin,
                            Some(&st.config.admin_group_name),
                        ) {
                            Ok(mesh_net::CallerPrivilege::Admin { principal }) => {
                                let cancel = shutdown.clone();
                                loop_tracker.spawn(async move {
                                    let res = tokio::select! {
                                        () = cancel.cancelled() => Ok(()),
                                        res = serve_admin_ipc_stream(stream, st, CallerPrincipal(principal)) => res,
                                    };
                                    if let Err(err) = res {
                                        tracing::debug!(
                                            component = "admin_service",
                                            event = "admin_ipc_stream_ended",
                                            error = %err,
                                            "admin IPC stream ended with error"
                                        );
                                    }
                                });
                            }
                            Ok(mesh_net::CallerPrivilege::ReadOnly { .. }) | Err(_) => {}
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

/// Non-Linux hosts never bind a TCP fallback for the Linux server Admin socket (`SEC-14`).
#[cfg(not(target_os = "linux"))]
pub async fn start_admin_ipc_listener(
    _state: AdminAppState,
    _tracker: &TaskTracker,
    _shutdown: CancellationToken,
) -> AppResult<()> {
    tracing::info!(
        component = "admin_service",
        event = "admin_uds_skipped_non_linux",
        "server Admin IPC Unix socket is only bound on Linux production hosts"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn lookup_linux_group_gid(group_name: &str) -> Option<u32> {
    let content = std::fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let mut parts = line.split(':');
        if parts.next() == Some(group_name) {
            let _passwd = parts.next();
            if let Some(gid_str) = parts.next()
                && let Ok(gid) = gid_str.parse::<u32>()
            {
                return Some(gid);
            }
        }
    }
    None
}

async fn handle_create_preauth_key(
    State(state): State<AdminAppState>,
    req: Request<Body>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let actor = caller_principal_from_req(&req);
    let parsed: CreatePreAuthKeyRequest = match read_admin_json(req).await {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };

    if parsed.ttl_secs == 0 || parsed.ttl_secs > MAX_PREAUTH_TTL_SECS {
        return error_response(
            &AppError::invalid_argument(format!(
                "pre-auth key TTL must be 1..={MAX_PREAUTH_TTL_SECS} seconds"
            )),
            &req_id,
        );
    }

    let now_ms = state.store.clock().now_unix_ms();
    let (target_node_id, bound_name) = match parsed.target_node.as_deref() {
        Some(target_ref) => match resolve_node_ref(&state.store, target_ref) {
            Ok(rec) => match NodeName::parse(&rec.node_name) {
                Ok(n) => (Some(rec.node_id), Some(n)),
                Err(e) => return error_response(&e, &req_id),
            },
            Err(err) => return error_response(&err, &req_id),
        },
        None => (None, None),
    };

    let entropy = random_bytes::<32>();
    let encoded = URL_SAFE_NO_PAD.encode(entropy);
    let raw_key = format!("{PREAUTH_KEY_PREFIX}{encoded}");
    if let Err(err) = PreAuthToken::parse(&raw_key) {
        return error_response(&err, &req_id);
    }
    let token_hash = sha256_digest(raw_key.as_bytes());
    let key_id = KeyId::new_v7(now_ms);

    let max_uses_cap = if parsed.reusable && parsed.max_uses > 0 {
        Some(parsed.max_uses)
    } else {
        None
    };
    let rec = match state.store.create_preauth_key(
        &CreatePreAuthKeyInput {
            key_id,
            token_hash,
            label: None,
            bound_node_name: bound_name,
            reusable: parsed.reusable,
            max_uses: max_uses_cap,
            ephemeral: parsed.is_ephemeral,
            ttl_secs: parsed.ttl_secs,
            now_unix_ms: now_ms,
        },
        &actor,
    ) {
        Ok(r) => r,
        Err(err) => return error_response(&err, &req_id),
    };

    let tls_status = state.acme.status();
    let acme_ca_verified = state.config.tls_mode == TlsMode::Acme
        && tls_status.as_ref().is_some_and(|s| s.ca_verified);
    let active_pin = tls_status
        .map(|s| s.active_pin)
        .filter(|_| !acme_ca_verified);
    let server_endpoint = format!("https://{}", state.config.public_control_endpoint());
    let pin_flag = active_pin
        .map(|p| format!(" --server-pin {p}"))
        .unwrap_or_default();
    let cli_join_command = format!(
        "mesh up --server {server_endpoint}{pin_flag} --authkey-file /run/mesh/preauth.key"
    );
    let join_command_file =
        format!("mesh up --server {server_endpoint}{pin_flag} --authkey-file /path/to/key.txt");
    let join_command_stdin =
        format!("mesh up --server {server_endpoint}{pin_flag} --authkey-stdin < key.txt");

    json_response(
        StatusCode::CREATED,
        &PreAuthKeyCreatedResponse {
            key_id: rec.key_id,
            raw_key,
            created_at_ms: rec.created_at_ms,
            expires_at_ms: rec.expires_at_ms,
            reusable: rec.reusable,
            max_uses: rec.max_uses.unwrap_or(if rec.reusable { 0 } else { 1 }),
            target_node_id,
            server_endpoint,
            active_pin,
            cli_join_command,
            join_command_file,
            join_command_stdin,
        },
    )
}

async fn handle_list_preauth_keys(State(state): State<AdminAppState>) -> Response {
    let req_id = new_admin_req_id(&state);
    let now_ms = state.store.clock().now_unix_ms();
    let nodes_by_name: HashMap<String, NodeId> = state
        .store
        .list_nodes()
        .unwrap_or_default()
        .into_iter()
        .map(|n| (n.node_name.to_ascii_lowercase(), n.node_id))
        .collect();
    match state.store.list_preauth_keys() {
        Ok(keys) => {
            let summaries: Vec<PreAuthKeySummary> = keys
                .into_iter()
                .map(|k| {
                    let exhausted = (!k.reusable && k.used_count > 0)
                        || k.max_uses.is_some_and(|cap| cap > 0 && k.used_count >= cap);
                    let status = if k.revoked_at_ms.is_some() {
                        "revoked"
                    } else if now_ms >= k.expires_at_ms {
                        "expired"
                    } else if exhausted {
                        "exhausted"
                    } else {
                        "active"
                    };
                    let target_node_id = k.used_by_node_id.or_else(|| {
                        k.bound_node_name
                            .as_deref()
                            .and_then(|name| nodes_by_name.get(&name.to_ascii_lowercase()).copied())
                    });
                    PreAuthKeySummary {
                        key_id: k.key_id,
                        status: status.to_owned(),
                        created_at_ms: k.created_at_ms,
                        expires_at_ms: k.expires_at_ms,
                        reusable: k.reusable,
                        used_count: k.used_count,
                        max_uses: k.max_uses.unwrap_or(if k.reusable { 0 } else { 1 }),
                        is_ephemeral: k.ephemeral,
                        target_node_id,
                    }
                })
                .collect();
            json_response(StatusCode::OK, &summaries)
        }
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_revoke_preauth_key(
    State(state): State<AdminAppState>,
    Path(id_raw): Path<String>,
    req: Request<Body>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let actor = caller_principal_from_req(&req);
    let key_id: KeyId = match id_raw.trim().parse() {
        Ok(k) => k,
        Err(err) => return error_response(&err, &req_id),
    };
    let now_ms = state.store.clock().now_unix_ms();
    match state.store.revoke_preauth_key(key_id, &actor) {
        Ok(tier) => json_response(
            StatusCode::OK,
            &RevokeActionResponse {
                target_id: key_id.to_string(),
                revoked: true,
                ram_enforced: true,
                persisted: tier != PersistenceTier::RamOnly,
                persistence_tier: tier,
                acted_at_ms: now_ms,
            },
        ),
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_list_nodes(State(state): State<AdminAppState>) -> Response {
    let req_id = new_admin_req_id(&state);
    let nodes = match state.store.list_nodes() {
        Ok(n) => n,
        Err(err) => return error_response(&err, &req_id),
    };
    let mut out = Vec::with_capacity(nodes.len());
    for rec in nodes {
        if let Some(dto) = record_to_admin_summary(&state, &rec) {
            out.push(dto);
        }
    }
    json_response(StatusCode::OK, &out)
}

async fn handle_get_node(
    State(state): State<AdminAppState>,
    Path(target_ref): Path<String>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let rec = match resolve_node_ref(&state.store, &target_ref) {
        Ok(r) => r,
        Err(err) => return error_response(&err, &req_id),
    };
    match record_to_admin_summary(&state, &rec) {
        Some(dto) => json_response(StatusCode::OK, &dto),
        None => error_response(&AppError::internal("invalid stored node record"), &req_id),
    }
}

async fn handle_rename_node(
    State(state): State<AdminAppState>,
    Path(target_ref): Path<String>,
    req: Request<Body>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let rec = match resolve_node_ref(&state.store, &target_ref) {
        Ok(r) => r,
        Err(err) => return error_response(&err, &req_id),
    };
    let parsed: RenameNodeRequest = match read_admin_json(req).await {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };
    match state.store.rename_node(
        rec.node_id,
        parsed.new_name,
        &state.config.public_host,
        &state.config.domain_suffix,
    ) {
        Ok((updated, ver)) => {
            broadcast_netmap_best_effort(&state.netmap_hub, ver, "rename_node_broadcast_failed");
            match record_to_admin_summary(&state, &updated) {
                Some(dto) => json_response(StatusCode::OK, &dto),
                None => error_response(&AppError::internal("invalid stored node record"), &req_id),
            }
        }
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_expire_node(
    State(state): State<AdminAppState>,
    Path(target_ref): Path<String>,
    req: Request<Body>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let actor = caller_principal_from_req(&req);
    let rec = match resolve_node_ref(&state.store, &target_ref) {
        Ok(r) => r,
        Err(err) => return error_response(&err, &req_id),
    };
    let body: ExpireNodeRequest = match read_admin_json(req).await {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };
    if body.never {
        return error_response(
            &AppError::invalid_argument("--never clearing requires direct node-key update"),
            &req_id,
        );
    }

    let now_ms = state.store.clock().now_unix_ms();
    match state.store.expire_node(rec.node_id, &actor) {
        Ok(outcome) => {
            enforce_revocation_disconnect(
                &state,
                &outcome,
                TerminationReason::NodeKeyExpired,
                RelayNoticeCode::NodeKeyExpired,
                "node key expired by administrator",
                now_ms,
            );
            json_response(
                StatusCode::OK,
                &RevokeActionResponse {
                    target_id: outcome.node_id.to_string(),
                    revoked: true,
                    ram_enforced: true,
                    persisted: outcome.persistence_tier != PersistenceTier::RamOnly,
                    persistence_tier: outcome.persistence_tier,
                    acted_at_ms: now_ms,
                },
            )
        }
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_revoke_node(
    State(state): State<AdminAppState>,
    Path(target_ref): Path<String>,
    req: Request<Body>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let actor = caller_principal_from_req(&req);
    let rec = match resolve_node_ref(&state.store, &target_ref) {
        Ok(r) => r,
        Err(err) => return error_response(&err, &req_id),
    };
    let now_ms = state.store.clock().now_unix_ms();
    match state.store.revoke_node(rec.node_id, &actor) {
        Ok(outcome) => {
            enforce_revocation_disconnect(
                &state,
                &outcome,
                TerminationReason::NodeRevoked,
                RelayNoticeCode::NodeRevoked,
                "node revoked by administrator",
                now_ms,
            );
            json_response(
                StatusCode::OK,
                &RevokeActionResponse {
                    target_id: outcome.node_id.to_string(),
                    revoked: true,
                    ram_enforced: true,
                    persisted: outcome.persistence_tier != PersistenceTier::RamOnly,
                    persistence_tier: outcome.persistence_tier,
                    acted_at_ms: now_ms,
                },
            )
        }
        Err(err) => error_response(&err, &req_id),
    }
}

fn enforce_revocation_disconnect(
    state: &AdminAppState,
    outcome: &mesh_store::RevokeStoreOutcome,
    term_reason: TerminationReason,
    relay_code: RelayNoticeCode,
    public_msg: &str,
    now_ms: u64,
) {
    // Queue direct termination notices BEFORE cancelling/closing streams so the acted-on node
    // always drains IdentityTerminated + RelayNoticeCode cleanly even on Gate 2 policy (b).
    state
        .netmap_hub
        .terminate_node_stream(outcome.node_id, term_reason, public_msg, now_ms);
    state.relay_hub.disconnect_node(outcome.node_id, relay_code);

    // Gate 2 policy (b): if dual-EIO exhausted lease prevented a durable netmap_version bump,
    // sever remaining open control & relay sessions so peers re-auth against RAM RevokedSet cleanly!
    if outcome.must_disconnect_all_peers_to_reauth {
        state.netmap_hub.close_all_streams_for_reauth();
        state.relay_hub.close_all_sessions();
        return;
    }

    if let Some(new_ver) = outcome.netmap_version {
        broadcast_netmap_best_effort(
            &state.netmap_hub,
            new_ver,
            "disconnect_outcome_broadcast_failed",
        );
    }
}

fn broadcast_netmap_best_effort(hub: &NetmapHub, netmap_ver: u64, event: &'static str) {
    if let Err(err) = hub.broadcast_snapshot(netmap_ver) {
        tracing::warn!(
            component = "admin_service",
            event = event,
            netmap_version = netmap_ver,
            error = %err,
            "failed broadcasting netmap snapshot after admin action"
        );
    }
}

fn reload_acme_best_effort(acme: &AcmeManager, event: &'static str) {
    if let Err(err) = acme.reload_from_store() {
        tracing::warn!(
            component = "admin_service",
            event = event,
            error = %err,
            "failed reloading TLS identity into active resolver"
        );
    }
}

async fn handle_server_status(State(state): State<AdminAppState>) -> Response {
    let (tcp_port, stun_port) = state.listeners.active_ports();
    let (ep_ver, _, _) = state.netmap_hub.current_endpoints();
    let nodes = state.store.list_nodes().unwrap_or_default();
    let unacked = state.netmap_hub.unacked_migration_nodes(&nodes);
    let tls_status = state.acme.status();
    let relay = state.relay_hub.metrics_snapshot();

    let acme_ca_verified = state.config.tls_mode == TlsMode::Acme
        && tls_status.as_ref().is_some_and(|s| s.ca_verified);
    let tls_auth_mode = if acme_ca_verified {
        "system_ca"
    } else {
        "spki_pin"
    };

    json_response(
        StatusCode::OK,
        &ServerAdminStatusResponse {
            control_tcp_listen: format!("{}:{}", state.config.control_bind_ip, tcp_port),
            stun_udp_listen: format!("{}:{}", state.config.stun_bind_ip, stun_port),
            tls_mode: state.config.tls_mode.as_str().to_owned(),
            tls_auth_mode: tls_auth_mode.to_owned(),
            active_pin: tls_status.as_ref().map(|s| s.active_pin),
            next_pin: tls_status.as_ref().and_then(|s| s.next_pin),
            cert_expires_at_ms: tls_status.map(|s| s.cert_not_after_ms),
            netmap_version: state.store.current_netmap_version(),
            endpoint_version: ep_ver,
            relay_sessions_active: u64::try_from(relay.active_sessions).unwrap_or(0),
            unacked_migration_nodes: unacked,
            db_degraded: state.store.is_disk_degraded(),
        },
    )
}

async fn handle_hardening_check(State(state): State<AdminAppState>) -> Response {
    let mut items = Vec::new();
    items.push(HardeningCheckItem {
        check_id: "tls_13_only".to_owned(),
        passed: state.acme.build_rustls_config().is_ok(),
        detail: "TLS 1.3 rustls provider active".to_owned(),
    });
    items.push(HardeningCheckItem {
        check_id: "obs_loopback_only".to_owned(),
        passed: !state.config.obs_allow_non_loopback,
        detail: format!("obs_bind_addr={}", state.config.obs_bind_addr),
    });
    let proxy_ok =
        state.config.tls_mode != TlsMode::ReverseProxy || !state.config.trusted_proxies.is_empty();
    items.push(HardeningCheckItem {
        check_id: "reverse_proxy_trust".to_owned(),
        passed: proxy_ok,
        detail: format!(
            "trusted_proxies count={}",
            state.config.trusted_proxies.len()
        ),
    });
    items.push(HardeningCheckItem {
        check_id: "storage_integrity".to_owned(),
        passed: !state.store.is_disk_degraded() && state.store.check_integrity().is_ok(),
        detail: "primary redb integrity verified".to_owned(),
    });
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::fs::MetadataExt as _;
        let is_non_root = std::fs::metadata("/proc/self")
            .map(|m| m.st_uid() != 0)
            .unwrap_or(false);
        items.push(HardeningCheckItem {
            check_id: "non_root_uid".to_owned(),
            passed: is_non_root,
            detail: "mesh-server running under unprivileged service UID".to_owned(),
        });
    }

    let all_passed = items.iter().all(|i| i.passed);
    json_response(
        StatusCode::OK,
        &HardeningCheckResponse { all_passed, items },
    )
}

#[derive(Debug, Deserialize)]
struct AuditQueryParams {
    limit: Option<usize>,
    before_seq: Option<u64>,
    actor: Option<String>,
    action: Option<String>,
}

async fn handle_list_audit_events(
    State(state): State<AdminAppState>,
    Query(params): Query<AuditQueryParams>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let query = AuditQuery {
        limit: params.limit.unwrap_or(100),
        before_seq: params.before_seq,
        actor: params.actor,
        action: params.action,
    };
    match state.store.list_audit_events(&query) {
        Ok(events) => {
            let dtos = events
                .into_iter()
                .map(|e| AuditEventDto {
                    seq: e.seq,
                    occurred_at_ms: e.occurred_at_ms,
                    actor: e.actor,
                    action: e.action,
                    target_id: Some(e.target),
                    outcome: e.outcome,
                    detail: Some(e.metadata.to_string()),
                })
                .collect();
            json_response(StatusCode::OK, &ListAuditEventsResponse { events: dtos })
        }
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_backup(State(state): State<AdminAppState>, req: Request<Body>) -> Response {
    let req_id = new_admin_req_id(&state);
    let actor = caller_principal_from_req(&req);
    let now_ms = state.store.clock().now_unix_ms();
    let backup_dir = state.config.backup_dir();
    match state.store.create_backup(&backup_dir, &actor) {
        Ok(artifact) => json_response(
            StatusCode::OK,
            &BackupCreatedResponse {
                snapshot_path: artifact.snapshot_path.display().to_string(),
                sha256_hex: artifact.sha256_hex,
                size_bytes: artifact.size_bytes,
                created_at_ms: now_ms,
            },
        ),
        Err(err) => error_response(&err, &req_id),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RestoreQueryParams {
    allow_pin_change: bool,
}

async fn handle_restore(
    State(state): State<AdminAppState>,
    Query(query): Query<RestoreQueryParams>,
    req: Request<Body>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let parsed: RestoreBackupRequest = match read_admin_json(req).await {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };
    let expected_pin = state.acme.status().map(|s| s.active_pin);
    let opts = RestoreOptions {
        snapshot_path: PathBuf::from(&parsed.snapshot_path),
        target_db_path: state.config.db_path(),
        target_emergency_path: state.config.emergency_revocations_path(),
        expected_published_pin: expected_pin,
        verify_sha256: parsed.verify_sha256,
        allow_pin_change: query.allow_pin_change,
        min_netmap_version: 0,
    };

    match state.store.restore_backup(opts) {
        Ok(_) => {
            reload_acme_best_effort(&state.acme, "restore_acme_reload_failed");
            state.netmap_hub.close_all_streams_for_reauth();
            state.relay_hub.close_all_sessions();
            let node_count = state
                .store
                .list_nodes()
                .map(|v| u64::try_from(v.len()).unwrap_or(0))
                .unwrap_or(0);
            json_response(
                StatusCode::OK,
                &RestoreBackupResponse {
                    restored: true,
                    netmap_version: state.store.current_netmap_version(),
                    node_count,
                },
            )
        }
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_migrate_endpoint(
    State(state): State<AdminAppState>,
    req: Request<Body>,
) -> Response {
    let req_id = new_admin_req_id(&state);
    let actor = caller_principal_from_req(&req);
    let parsed: MigrateEndpointRequest = match read_admin_json(req).await {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };
    match state.listeners.migrate_endpoints(&parsed, &actor).await {
        Ok(resp) => json_response(StatusCode::OK, &resp),
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_rotate_tls_key(State(state): State<AdminAppState>, req: Request<Body>) -> Response {
    let req_id = new_admin_req_id(&state);
    let actor = caller_principal_from_req(&req);
    let parsed: RotateTlsKeyRequest = match read_admin_json(req).await {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };

    let sans = state.config.default_tls_sans();
    match parsed.action {
        RotateTlsKeyAction::Stage => match state.store.stage_next_identity(&sans, 90, &actor) {
            Ok((id, netmap_ver)) => {
                reload_acme_best_effort(&state.acme, "stage_tls_acme_reload_failed");
                broadcast_netmap_best_effort(
                    &state.netmap_hub,
                    netmap_ver,
                    "stage_tls_broadcast_failed",
                );
                json_response(
                    StatusCode::OK,
                    &RotateTlsKeyResponse {
                        active_pin: Some(id.spki_pin),
                        next_pin: id.staged_next.map(|s| s.spki_pin),
                        netmap_version: netmap_ver,
                        staged: true,
                        promoted: false,
                    },
                )
            }
            Err(err) => error_response(&err, &req_id),
        },
        RotateTlsKeyAction::Promote => {
            match state
                .store
                .activate_staged_identity(TLS_ROTATE_GRACE_MS, &actor)
            {
                Ok((id, netmap_ver)) => {
                    reload_acme_best_effort(&state.acme, "promote_tls_acme_reload_failed");
                    broadcast_netmap_best_effort(
                        &state.netmap_hub,
                        netmap_ver,
                        "promote_tls_broadcast_failed",
                    );
                    json_response(
                        StatusCode::OK,
                        &RotateTlsKeyResponse {
                            active_pin: Some(id.spki_pin),
                            next_pin: id.previous_spki_pin,
                            netmap_version: netmap_ver,
                            staged: false,
                            promoted: true,
                        },
                    )
                }
                Err(err) => error_response(&err, &req_id),
            }
        }
    }
}

fn resolve_node_ref(store: &ControlStore, target_ref: &str) -> AppResult<StoredNodeRecord> {
    let trimmed = target_ref.trim();
    if let Ok(node_id) = trimmed.parse::<NodeId>() {
        return store
            .find_node_by_id(node_id)?
            .ok_or_else(|| AppError::not_found("node not found"));
    }
    let normalized = trimmed.to_ascii_lowercase();
    store
        .list_nodes()?
        .into_iter()
        .find(|n| n.node_name.eq_ignore_ascii_case(&normalized))
        .ok_or_else(|| AppError::not_found("node not found"))
}

fn record_to_admin_summary(
    state: &AdminAppState,
    rec: &StoredNodeRecord,
) -> Option<AdminNodeSummary> {
    let name = NodeName::parse(&rec.node_name).ok()?;
    let overlay_ip = rec.overlay_ip.or(rec.last_overlay_ip)?;
    let runtime = state.netmap_hub.node_runtime_info(rec.node_id);
    let online = runtime.is_some();
    let (last_seen_at_ms, acked_endpoint_version) = runtime.unwrap_or((rec.last_seen_at_ms, 0));
    let mut os_arch_parts = rec.os_arch.split('/');
    let os = os_arch_parts.next().unwrap_or("unknown").to_owned();
    let arch = os_arch_parts.next().unwrap_or("unknown").to_owned();
    let status = match rec.status {
        NodeStatus::Active => "active",
        NodeStatus::Revoked => "revoked",
        NodeStatus::Expired => "expired",
    }
    .to_owned();

    Some(AdminNodeSummary {
        node_id: rec.node_id,
        name,
        overlay_ip,
        status,
        online,
        last_seen_at_ms,
        key_expires_at_ms: Some(rec.key_expires_at_ms),
        os,
        arch,
        agent_version: rec.agent_version.clone(),
        acked_endpoint_version,
    })
}

async fn read_admin_json<T: serde::de::DeserializeOwned>(req: Request<Body>) -> AppResult<T> {
    let bytes = axum::body::to_bytes(req.into_body(), MAX_ADMIN_IPC_BODY_BYTES)
        .await
        .map_err(|_| AppError::invalid_argument("admin request body exceeded 64 KiB"))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| AppError::invalid_argument(format!("invalid admin JSON payload: {err}")))
}

fn caller_principal_from_req(req: &Request<Body>) -> String {
    req.extensions()
        .get::<CallerPrincipal>()
        .map_or_else(|| "local-admin".to_owned(), |p| p.0.clone())
}

fn new_admin_req_id(state: &AdminAppState) -> String {
    NodeId::new_v7(state.store.clock().now_unix_ms()).to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::Method;
    use mesh_core::defaults::MAX_ADMIN_IPC_BODY_BYTES;
    use mesh_core::{Clock as _, FakeClock, NodeId, NodeName, PublicKey, SystemClock};
    use mesh_net::send_ipc_json_request;
    use mesh_proto::admin_ipc::{
        AdminNodeSummary, CreatePreAuthKeyRequest, PersistenceTier, PreAuthKeyCreatedResponse,
        RevokeActionResponse, ServerAdminStatusResponse,
    };
    use mesh_store::{
        ControlStore, ControlStoreConfig, CreatePreAuthKeyInput, DEFAULT_NODE_KEY_TTL_MS,
        RegisterNodeInput,
    };
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::{AdminAppState, CallerPrincipal, serve_admin_ipc_stream};
    use crate::acme::AcmeManager;
    use crate::config::ServerConfig;
    use crate::control_handlers::{ControlAppState, PendingChallengeStore};
    use crate::listener_set::ListenerSet;
    use crate::netmap_hub::NetmapHub;
    use crate::rate_limit::{ClientIpExtractor, RateLimiter};
    use crate::relay_hub::RelayHub;

    async fn spawn_admin_ipc_pair(state: AdminAppState) -> tokio::io::DuplexStream {
        let (client_io, server_io) = tokio::io::duplex(65_536);
        tokio::spawn(async move {
            if let Err(err) = serve_admin_ipc_stream(
                server_io,
                state,
                CallerPrincipal("unix:uid=0,gid=0".to_owned()),
            )
            .await
            {
                tracing::debug!(error = %err, "test admin IPC server stream ended");
            }
        });
        client_io
    }

    #[tokio::test]
    async fn test_admin_ipc_preauth_creation_node_listing_and_revoke_gate2b_disconnects() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock,
            )
            .expect("open store"),
        );

        let probe_tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let probe_udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp");
        let tcp_port = probe_tcp.local_addr().expect("addr").port();
        let udp_port = probe_udp.local_addr().expect("addr").port();
        drop((probe_tcp, probe_udp));

        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: tcp_port,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: udp_port,
            state_dir: dir.path().to_path_buf(),
            public_host: "203.0.113.10".to_owned(),
            ..ServerConfig::default()
        });

        let acme = AcmeManager::initialize(&cfg, store.clone()).expect("init acme");
        let netmap_hub = Arc::new(NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            cfg.trusted_proxy_set(),
        )));
        let tracker = TaskTracker::new();
        let shutdown = CancellationToken::new();
        let ctrl_state = ControlAppState {
            config: cfg.clone(),
            trusted_proxies: Arc::new(Default::default()),
            store: store.clone(),
            rate_limiter,
            challenges: Arc::new(PendingChallengeStore::new()),
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
            ws_tracker: tracker.clone(),
            shutdown: shutdown.clone(),
        };
        let listeners = ListenerSet::bind_and_start(ctrl_state, acme.clone())
            .await
            .expect("bind listeners");
        let admin_state = AdminAppState {
            config: cfg,
            store: store.clone(),
            acme,
            listeners,
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
        };

        // Act 1: mint preauth key over local IPC
        let io1 = spawn_admin_ipc_pair(admin_state.clone()).await;
        let created: PreAuthKeyCreatedResponse = send_ipc_json_request(
            io1,
            Method::POST,
            "/v1/admin/preauth-keys",
            Some(&CreatePreAuthKeyRequest {
                ttl_secs: 3_600,
                reusable: false,
                max_uses: 1,
                is_ephemeral: false,
                ephemeral_timeout_secs: None,
                target_node: None,
            }),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("create key");
        assert!(created.raw_key.starts_with("mpk_"));

        // Register a live peer using the hashed token
        let token_hash = mesh_crypto::sha256_digest(created.raw_key.as_bytes());
        let (reg, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: PublicKey::from_bytes([0x66_u8; 32]).expect("pk"),
                disco_pubkey: PublicKey::from_bytes([0x67_u8; 32]).expect("dpk"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("server-test").expect("name"),
                preauth_token_hash: token_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .expect("register");
        let sub = netmap_hub.subscribe(reg.record.node_id, now_ms);
        let other_sub = netmap_hub.subscribe(NodeId::new_v7(now_ms + 99), now_ms);
        let _ = other_sub;

        let io2 = spawn_admin_ipc_pair(admin_state.clone()).await;
        let nodes: Vec<AdminNodeSummary> = send_ipc_json_request::<_, (), _>(
            io2,
            Method::GET,
            "/v1/admin/nodes",
            None,
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("list nodes");
        assert_eq!(nodes.len(), 1);
        assert!(nodes.first().expect("expected one node").online);

        let io3 = spawn_admin_ipc_pair(admin_state.clone()).await;
        let status: ServerAdminStatusResponse = send_ipc_json_request::<_, (), _>(
            io3,
            Method::GET,
            "/v1/admin/server/status",
            None,
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("server status");
        assert_eq!(status.tls_mode, "ip_pinned");

        let io4 = spawn_admin_ipc_pair(admin_state).await;
        let revoke_resp: RevokeActionResponse = send_ipc_json_request::<_, (), _>(
            io4,
            Method::DELETE,
            &format!("/v1/admin/nodes/{}", reg.record.node_id),
            None,
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("revoke node");
        assert!(revoke_resp.revoked);
        assert_eq!(revoke_resp.persistence_tier, PersistenceTier::Redb);
        assert!(sub.cancel.is_cancelled());

        let _ = CreatePreAuthKeyInput::clone;
        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }

    #[tokio::test]
    async fn test_admin_get_node_key_max_uses_revoke_route_restore_pin_gate_and_gate2b_notices() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock,
            )
            .expect("open store"),
        );

        let probe_tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let probe_udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp");
        let tcp_port = probe_tcp.local_addr().expect("addr").port();
        let udp_port = probe_udp.local_addr().expect("addr").port();
        drop((probe_tcp, probe_udp));

        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: tcp_port,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: udp_port,
            state_dir: dir.path().to_path_buf(),
            public_host: "203.0.113.10".to_owned(),
            ..ServerConfig::default()
        });

        let acme = AcmeManager::initialize(&cfg, store.clone()).expect("init acme");
        let initial_pin = acme.status().expect("status").active_pin;
        let netmap_hub = Arc::new(NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            cfg.trusted_proxy_set(),
        )));
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let ctrl_state = ControlAppState {
            config: cfg.clone(),
            trusted_proxies: Arc::new(Default::default()),
            store: store.clone(),
            rate_limiter,
            challenges: Arc::new(PendingChallengeStore::new()),
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
            ws_tracker: tracker.clone(),
            shutdown: shutdown.clone(),
        };
        let listeners = ListenerSet::bind_and_start(ctrl_state, acme.clone())
            .await
            .expect("bind listeners");
        let admin_state = AdminAppState {
            config: cfg,
            store: store.clone(),
            acme: acme.clone(),
            listeners,
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
        };

        // Act 1: mint reusable key with max_uses = 2 and verify API join command flags
        let created: PreAuthKeyCreatedResponse = send_ipc_json_request(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::POST,
            "/v1/admin/preauth-keys",
            Some(&CreatePreAuthKeyRequest {
                ttl_secs: 3_600,
                reusable: true,
                max_uses: 2,
                is_ephemeral: false,
                ephemeral_timeout_secs: None,
                target_node: None,
            }),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("create reusable key");
        assert!(created.cli_join_command.contains("--server-pin "));
        assert!(created.cli_join_command.contains("--authkey-file "));
        assert!(created.join_command_stdin.contains("--authkey-stdin"));
        assert_eq!(created.max_uses, 2);

        // Register a node and verify GET /v1/admin/nodes/{id}
        let token_hash = mesh_crypto::sha256_digest(created.raw_key.as_bytes());
        let peer_pk = PublicKey::from_bytes([0x68_u8; 32]).expect("pk");
        let (reg, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: peer_pk,
                disco_pubkey: PublicKey::from_bytes([0x69_u8; 32]).expect("dpk"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("get-node").expect("name"),
                preauth_token_hash: token_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .expect("register");

        let single: AdminNodeSummary = send_ipc_json_request::<_, (), _>(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::GET,
            &format!("/v1/admin/nodes/{}", reg.record.node_id),
            None,
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("get single node");
        assert_eq!(single.node_id, reg.record.node_id);
        assert_eq!(single.name.as_str(), "get-node");

        // Verify POST /v1/admin/preauth-keys/{id}/revoke works (`HR-S1-04`)
        let revoke_key: RevokeActionResponse = send_ipc_json_request::<_, (), _>(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::POST,
            &format!("/v1/admin/preauth-keys/{}/revoke", created.key_id),
            None,
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("revoke preauth key via POST /revoke");
        assert!(revoke_key.revoked);

        // Act 2: verify record_to_admin_summary retains last_overlay_ip after IP reclaim (`HR-S1-04`)
        let mut reclaimed_rec = reg.record.clone();
        let saved_ip = reclaimed_rec.overlay_ip;
        reclaimed_rec.overlay_ip = None;
        reclaimed_rec.last_overlay_ip = saved_ip;
        reclaimed_rec.status = mesh_store::NodeStatus::Expired;
        let summary_reclaimed =
            super::record_to_admin_summary(&admin_state, &reclaimed_rec).expect("summary");
        assert_eq!(summary_reclaimed.overlay_ip, saved_ip.expect("ip"));
        assert_eq!(summary_reclaimed.status, "expired");

        // Act 3: backup, rotate TLS pin twice, verify restore with verify_sha256:false STILL rejects pin mismatch (`BLK-S1-04`)
        let backup_resp: mesh_proto::admin_ipc::BackupCreatedResponse = send_ipc_json_request(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::POST,
            "/v1/admin/backup",
            Some(&serde_json::json!({})),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("backup");
        let _: mesh_proto::admin_ipc::RotateTlsKeyResponse = send_ipc_json_request(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::POST,
            "/v1/admin/server/rotate-tls-key",
            Some(&mesh_proto::admin_ipc::RotateTlsKeyRequest {
                action: mesh_proto::admin_ipc::RotateTlsKeyAction::Stage,
            }),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("stage rotate");
        let promoted: mesh_proto::admin_ipc::RotateTlsKeyResponse = send_ipc_json_request(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::POST,
            "/v1/admin/server/rotate-tls-key",
            Some(&mesh_proto::admin_ipc::RotateTlsKeyRequest {
                action: mesh_proto::admin_ipc::RotateTlsKeyAction::Promote,
            }),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("promote rotate");
        let new_pin = promoted.active_pin.expect("promoted pin");
        assert_ne!(new_pin, initial_pin);

        let rejected = send_ipc_json_request::<_, _, mesh_proto::admin_ipc::RestoreBackupResponse>(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::POST,
            "/v1/admin/restore",
            Some(&mesh_proto::admin_ipc::RestoreBackupRequest {
                snapshot_path: backup_resp.snapshot_path.clone(),
                verify_sha256: false,
            }),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await;
        assert!(
            rejected.is_err(),
            "verify_sha256:false must NEVER bypass SPKI pin continuity check"
        );
        assert_eq!(acme.status().expect("status").active_pin, new_pin);

        let allowed: mesh_proto::admin_ipc::RestoreBackupResponse = send_ipc_json_request(
            spawn_admin_ipc_pair(admin_state.clone()).await,
            Method::POST,
            "/v1/admin/restore?allow_pin_change=true",
            Some(&mesh_proto::admin_ipc::RestoreBackupRequest {
                snapshot_path: backup_resp.snapshot_path,
                verify_sha256: true,
            }),
            MAX_ADMIN_IPC_BODY_BYTES,
        )
        .await
        .expect("restore with allow_pin_change=true");
        assert!(allowed.restored);
        assert_eq!(acme.status().expect("restored").active_pin, initial_pin);

        // Act 4: verify enforce_revocation_disconnect sends notices to node_id BEFORE closing streams (`BLK-S1-02`)
        let mut target_sub = netmap_hub.subscribe(reg.record.node_id, now_ms);
        let mut target_relay = relay_hub.register_session(reg.record.node_id, peer_pk, now_ms);
        let peer_sub = netmap_hub.subscribe(NodeId::new_v7(now_ms + 77), now_ms);
        super::enforce_revocation_disconnect(
            &admin_state,
            &mesh_store::RevokeStoreOutcome {
                node_id: reg.record.node_id,
                persistence_tier: PersistenceTier::RamOnly,
                netmap_version: None,
                must_disconnect_all_peers_to_reauth: true,
                record: None,
            },
            mesh_proto::control::TerminationReason::NodeRevoked,
            mesh_proto::relay::RelayNoticeCode::NodeRevoked,
            "revoked under dual EIO",
            now_ms + 50,
        );
        assert!(target_sub.cancel.is_cancelled());
        assert!(target_relay.cancel.is_cancelled());
        assert!(peer_sub.cancel.is_cancelled());
        assert!(matches!(
            target_sub.rx.try_recv(),
            Ok(
                mesh_proto::control::ServerControlFrame::IdentityTerminated {
                    error_kind: mesh_proto::control::TerminationReason::NodeRevoked,
                    ..
                }
            )
        ));
        let notice_bytes = target_relay.rx.try_recv().expect("relay notice queued");
        assert!(matches!(
            mesh_proto::relay::RelayFrame::decode(&notice_bytes).expect("decode notice"),
            mesh_proto::relay::RelayFrame::ControlNotice {
                code: mesh_proto::relay::RelayNoticeCode::NodeRevoked
            }
        ));

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }
}
