//! Control-plane HTTPS REST & WebSocket handlers (`/v1/auth/challenge`, `/v1/nodes/register`,
//! `/v1/endpoints`, `/v1/disco/call-me-maybe`, `/v1/netmap/stream`, `/v1/relay`, `WP-S1-01`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use mesh_core::defaults::{
    CHALLENGE_TTL_SECS, DEFAULT_OVERLAY_CIDR, MAX_FRAME_SIZE, MAX_HTTP_BODY_BYTES,
};
use mesh_core::{AppError, AppResult, ErrorKind, ErrorResponse, NodeId, OverlayCidr, PublicKey};
use mesh_crypto::{
    ExpectedProofClaims, NodeKeypair, ProofPayload, open_proof, peek_outer_sender_pubkey,
    random_bytes, sha256_digest, sha256_hex, verify_proof_claims,
};
use mesh_net::{CandidateFilterContext, is_valid_candidate_endpoint};
use mesh_proto::control::{
    CallMeMaybeRequest, ChallengeRequest, ChallengeResponse, ClientControlFrame, HEADER_AUTH_PROOF,
    HEADER_BOX_NONCE, HEADER_CHALLENGE_ID, HEADER_NODE_PUBKEY, RegisterNodeRequest,
    RegisterNodeResponse, ServerControlFrame, TargetArch, TargetOs, TerminationReason,
    UpdateEndpointsRequest, UpdateEndpointsResponse,
};
use mesh_proto::netmap::CandidateEndpoint;
use mesh_proto::relay::RelayNoticeCode;
use mesh_proto::{MIN_DISCO_PACKET_LEN, is_disco_packet};
use mesh_store::{
    AuditEventInput, ControlStore, DEFAULT_NODE_KEY_TTL_MS, NodeStatus, RegisterNodeInput,
};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocket, WebSocketConfig};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::{ServerConfig, TlsMode};
use crate::netmap_hub::NetmapHub;
use crate::rate_limit::{RateLimitDecision, RateLimitEndpoint, RateLimiter, RegistrationOutcome};
use crate::relay_hub::{RelayForwardOutcome, RelayHub};

/// Hard memory ceiling on outstanding single-use challenges (`4096` entries, `api-design.md` §1.2).
pub const MAX_PENDING_CHALLENGES: usize = 4_096;

const MAX_CONTROL_WS_FRAME_BYTES: usize = 65_536;
const MAX_DISCO_FRAME_BYTES: usize = 1_024;
const MAX_CANDIDATE_ENDPOINTS: usize = 16;
const WS_DRAIN_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULT_PROTOCOL_TAG: &str = "unknown";

/// Per-connection TLS & network context injected by [`crate::listener_set::ListenerSet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTlsContext {
    /// Direct TCP peer address connected to `mesh-server`.
    pub peer_addr: SocketAddr,
    /// RFC 5705 TLS exporter binding base64 extracted on direct TLS connections (`None` behind proxy).
    pub tls_exporter_b64: Option<String>,
    /// Effective TLS mode of the listener that accepted this TCP connection (`HR-W21-05`).
    pub listener_tls_mode: TlsMode,
}

impl Default for ConnectionTlsContext {
    fn default() -> Self {
        Self {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            tls_exporter_b64: None,
            listener_tls_mode: TlsMode::IpPinned,
        }
    }
}

#[derive(Debug)]
struct PendingChallenge {
    id: NodeId,
    server_eph_keypair: NodeKeypair,
    challenge_nonce_b64: String,
    expires_at_ms: u64,
    client_os_arch: String,
    agent_version: String,
    protocol_version: u16,
}

/// Thread-safe bounded single-use challenge map (`MAX_PENDING_CHALLENGES = 4096`, `TTL = 30s`).
#[derive(Debug, Default)]
pub struct PendingChallengeStore {
    entries: Mutex<HashMap<NodeId, PendingChallenge>>,
}

impl PendingChallengeStore {
    /// Creates an empty single-use challenge store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues and stores a single-use challenge carrying a fresh server ephemeral X25519 keypair.
    pub fn issue(&self, req: &ChallengeRequest, now_ms: u64) -> AppResult<ChallengeResponse> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| AppError::internal("challenge store mutex poisoned"))?;
        guard.retain(|_, c| c.expires_at_ms >= now_ms);

        if guard.len() >= MAX_PENDING_CHALLENGES {
            return Err(AppError::rate_limited(
                "pending authentication challenge queue saturated",
            ));
        }

        let challenge_id = NodeId::new_v7(now_ms);
        let eph = NodeKeypair::generate();
        let eph_pub = eph.public_key();
        let nonce_bytes = random_bytes::<32>();
        let nonce_b64 = BASE64_STANDARD.encode(nonce_bytes);
        let expires_at_ms = now_ms.saturating_add(CHALLENGE_TTL_SECS.saturating_mul(1_000));
        let os_arch = format!("{}/{}", os_label(req.os), arch_label(req.arch));

        guard.insert(
            challenge_id,
            PendingChallenge {
                id: challenge_id,
                server_eph_keypair: eph,
                challenge_nonce_b64: nonce_b64.clone(),
                expires_at_ms,
                client_os_arch: os_arch,
                agent_version: sanitize_short_label(&req.agent_version, 64),
                protocol_version: req.protocol_version,
            },
        );

        Ok(ChallengeResponse {
            challenge_id,
            server_eph_pubkey: eph_pub,
            challenge_nonce: nonce_b64,
            server_time_at_ms: now_ms,
            expires_at_ms,
        })
    }

    /// Atomically removes a single-use challenge BEFORE attempting decryption (`api-design.md` §1.3).
    fn consume(&self, id: NodeId) -> Option<PendingChallenge> {
        self.entries.lock().ok()?.remove(&id)
    }

    /// Number of active pending challenges (`GET /metrics`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Returns `true` when no challenges are pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Shared application state injected into Control & Blind Relay Axum routes.
#[derive(Clone, Debug)]
pub struct ControlAppState {
    /// Control plane static server config.
    pub config: Arc<ServerConfig>,
    /// Precomputed trusted reverse-proxy source IP whitelist.
    pub trusted_proxies: Arc<HashSet<IpAddr>>,
    /// Durable ACID store (`redb` + emergency revocation state).
    pub store: Arc<ControlStore>,
    /// Brute-force IP rate limiter & forwarded header extractor.
    pub rate_limiter: Arc<RateLimiter>,
    /// Bounded single-use challenge store (`4096`).
    pub challenges: Arc<PendingChallengeStore>,
    /// Active `/v1/netmap/stream` subscriber broadcast hub.
    pub netmap_hub: Arc<NetmapHub>,
    /// Active `/v1/relay` Blind Relay forwarding hub.
    pub relay_hub: Arc<RelayHub>,
    /// Task tracker owning spawned upgraded WebSocket stream pumps.
    pub ws_tracker: TaskTracker,
    /// Graceful server shutdown cancellation token (`<= 5 s`).
    pub shutdown: CancellationToken,
}

impl ControlAppState {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "control_handlers:ready"
    }
}

/// Builds the public HTTPS Axum router exposing Control REST, `/v1/netmap/stream`, and `/v1/relay`.
///
/// Admin endpoints are strictly forbidden on this TCP router (`SEC-14`).
pub fn build_control_router(state: ControlAppState) -> Router {
    Router::new()
        .route("/v1/auth/challenge", post(handle_auth_challenge))
        .route("/v1/nodes/register", post(handle_register_node))
        .route("/v1/endpoints", post(handle_update_endpoints))
        .route("/v1/disco/call-me-maybe", post(handle_call_me_maybe))
        .route("/v1/netmap/stream", get(handle_netmap_stream_ws))
        .route("/v1/relay", get(handle_relay_ws))
        .with_state(state)
}

async fn handle_auth_challenge(
    State(state): State<ControlAppState>,
    req: Request<Body>,
) -> Response {
    let req_id = new_request_id(&state);
    let conn_ctx_opt = req.extensions().get::<ConnectionTlsContext>();
    let listener_tls_mode = conn_ctx_opt.map_or(state.config.tls_mode, |c| c.listener_tls_mode);
    let client_ip =
        resolve_request_client_ip(&state, listener_tls_mode, req.headers(), conn_ctx_opt);
    let now_ms = state.store.clock().now_unix_ms();

    if let Some(resp) = enforce_auth_rate_limit(
        &state,
        listener_tls_mode,
        RateLimitEndpoint::Challenge,
        client_ip,
        now_ms,
        &req_id,
    ) {
        return resp;
    }

    let body = match read_bounded_body(req.into_body()).await {
        Ok(b) => b,
        Err(err) => return error_response(&err, &req_id),
    };
    let parsed: ChallengeRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return error_response(
                &AppError::invalid_argument(format!("invalid challenge JSON: {err}")),
                &req_id,
            );
        }
    };

    if parsed.protocol_version < state.config.min_protocol_version {
        return error_response(
            &AppError::invalid_argument(format!(
                "agent upgrade required: client protocol version {} unsupported (min {})",
                parsed.protocol_version, state.config.min_protocol_version
            )),
            &req_id,
        );
    }

    match state.challenges.issue(&parsed, now_ms) {
        Ok(resp) => json_response(StatusCode::OK, &resp),
        Err(err) => error_response(&err, &req_id),
    }
}

fn active_public_host(state: &ControlAppState) -> String {
    let (_, ctrl_ep, _) = state.netmap_hub.current_endpoints();
    let trimmed = ctrl_ep.trim();
    if trimmed.is_empty() {
        return state.config.public_host.clone();
    }
    if let Ok(sock) = trimmed.parse::<std::net::SocketAddr>() {
        return sock.ip().to_string();
    }
    if let Some(after_bracket) = trimmed.strip_prefix('[')
        && let Some((host, _)) = after_bracket.split_once(']')
        && !host.is_empty()
    {
        return host.to_owned();
    }
    if let Some((host, port_str)) = trimmed.rsplit_once(':')
        && port_str.parse::<u16>().is_ok()
        && !host.is_empty()
    {
        return host.to_owned();
    }
    trimmed.to_owned()
}

async fn handle_register_node(
    State(state): State<ControlAppState>,
    req: Request<Body>,
) -> Response {
    let req_id = new_request_id(&state);
    let now_ms = state.store.clock().now_unix_ms();
    let conn_ctx = req
        .extensions()
        .get::<ConnectionTlsContext>()
        .cloned()
        .unwrap_or_else(|| ConnectionTlsContext {
            listener_tls_mode: state.config.tls_mode,
            ..ConnectionTlsContext::default()
        });
    let client_ip = resolve_request_client_ip(
        &state,
        conn_ctx.listener_tls_mode,
        req.headers(),
        Some(&conn_ctx),
    );

    if let Some(resp) = enforce_auth_rate_limit(
        &state,
        conn_ctx.listener_tls_mode,
        RateLimitEndpoint::Register,
        client_ip,
        now_ms,
        &req_id,
    ) {
        return resp;
    }

    let headers = req.headers().clone();
    let body = match read_bounded_body(req.into_body()).await {
        Ok(b) => b,
        Err(err) => return error_response(&err, &req_id),
    };

    let auth = match verify_signed_proof(
        &state,
        &conn_ctx,
        client_ip,
        &headers,
        ProofRequestMeta {
            method: "POST",
            path: "/v1/nodes/register",
            body: &body,
            now_ms,
        },
    ) {
        Ok(a) => a,
        Err(err) => {
            state
                .rate_limiter
                .record_registration_outcome(RegistrationOutcome::Unauthenticated);
            return error_response(&err, &req_id);
        }
    };

    if auth.protocol_version < state.config.min_protocol_version {
        return error_response(
            &AppError::invalid_argument(format!(
                "agent upgrade required: client protocol version {} unsupported (min {})",
                auth.protocol_version, state.config.min_protocol_version
            )),
            &req_id,
        );
    }

    let parsed: RegisterNodeRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return error_response(
                &AppError::invalid_argument(format!("invalid register JSON: {err}")),
                &req_id,
            );
        }
    };
    if parsed.node_pubkey != auth.pubkey || parsed.disco_pubkey != auth.proof.disco_pubkey {
        state
            .rate_limiter
            .record_registration_outcome(RegistrationOutcome::Unauthenticated);
        record_auth_failure_with_audit(
            &state,
            conn_ctx.listener_tls_mode,
            client_ip,
            now_ms,
            "/v1/nodes/register",
        );
        return error_response(
            &AppError::unauthenticated("register payload key mismatch"),
            &req_id,
        );
    }

    let active_host = active_public_host(&state);
    let token_hash = sha256_digest(parsed.preauth_key.trim().as_bytes());
    let reg_outcome = state.store.register_node(&RegisterNodeInput {
        pubkey: parsed.node_pubkey,
        disco_pubkey: parsed.disco_pubkey,
        previous_node_pubkey: parsed.previous_node_pubkey,
        requested_name: parsed.node_name.clone(),
        preauth_token_hash: token_hash,
        public_control_host: &active_host,
        domain_suffix: &state.config.domain_suffix,
        os_arch: &auth.client_os_arch,
        agent_version: &auth.agent_version,
        protocol_version: auth.protocol_version,
        node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
        now_unix_ms: now_ms,
    });

    let (outcome, netmap_ver) = match reg_outcome {
        Ok(pair) => {
            state
                .rate_limiter
                .record_registration_outcome(RegistrationOutcome::Success);
            state.rate_limiter.record_auth_success(client_ip);
            pair
        }
        Err(err) => {
            match err.kind() {
                ErrorKind::Unauthenticated => {
                    state
                        .rate_limiter
                        .record_registration_outcome(RegistrationOutcome::Unauthenticated);
                    record_auth_failure_with_audit(
                        &state,
                        conn_ctx.listener_tls_mode,
                        client_ip,
                        now_ms,
                        "/v1/nodes/register",
                    );
                }
                ErrorKind::Conflict => {
                    state
                        .rate_limiter
                        .record_registration_outcome(RegistrationOutcome::Conflict);
                    tracing::warn!(
                        component = "control_handlers",
                        event = "node_registration_conflict",
                        client_ip = %client_ip,
                        node_name = %parsed.node_name,
                        error = %err,
                        "rejected node registration due to name/identity conflict"
                    );
                    state.store.record_audit_best_effort(&AuditEventInput {
                        occurred_at_ms: now_ms,
                        actor: "control:register",
                        action: "node_registration_conflict",
                        target: parsed.node_name.as_str(),
                        outcome: "denied",
                        metadata: json!({
                            "client_ip": client_ip.to_string(),
                            "node_name": parsed.node_name,
                        }),
                    });
                }
                _ => {}
            }
            return error_response(&err, &req_id);
        }
    };

    if outcome.replaced_pubkey.is_some() {
        state.netmap_hub.terminate_node_stream(
            outcome.record.node_id,
            TerminationReason::NodeRevoked,
            "node key rotated; reconnect with new identity key",
            now_ms,
        );
        state
            .relay_hub
            .disconnect_node(outcome.record.node_id, RelayNoticeCode::NodeRevoked);
    }

    if outcome.state_changed
        && let Err(err) = state.netmap_hub.broadcast_snapshot(netmap_ver)
    {
        tracing::warn!(
            component = "control_handlers",
            event = "broadcast_snapshot_failed",
            error = %err,
            "failed broadcasting netmap snapshot after registration"
        );
    }

    let snapshot = match state.netmap_hub.build_snapshot(Some(netmap_ver)) {
        Ok(s) => s,
        Err(err) => return error_response(&err, &req_id),
    };
    let Ok(node_name) = mesh_core::NodeName::parse(&outcome.record.node_name) else {
        return error_response(&AppError::internal("stored node_name invalid"), &req_id);
    };
    let Some(overlay_ip) = outcome.record.overlay_ip else {
        return error_response(
            &AppError::internal("registered active node missing overlay_ip"),
            &req_id,
        );
    };

    let resp = RegisterNodeResponse {
        node_id: outcome.record.node_id,
        fqdn: format!("{node_name}.{}", state.config.domain_suffix),
        node_name,
        overlay_ip,
        overlay_cidr: snapshot.overlay_cidr,
        key_expires_at_ms: outcome.record.key_expires_at_ms,
        netmap: snapshot,
    };
    json_response(StatusCode::OK, &resp)
}

async fn handle_update_endpoints(
    State(state): State<ControlAppState>,
    req: Request<Body>,
) -> Response {
    let req_id = new_request_id(&state);
    let now_ms = state.store.clock().now_unix_ms();
    let conn_ctx = req
        .extensions()
        .get::<ConnectionTlsContext>()
        .cloned()
        .unwrap_or_else(|| ConnectionTlsContext {
            listener_tls_mode: state.config.tls_mode,
            ..ConnectionTlsContext::default()
        });
    let client_ip = resolve_request_client_ip(
        &state,
        conn_ctx.listener_tls_mode,
        req.headers(),
        Some(&conn_ctx),
    );
    if let Some(resp) = enforce_ip_lockout(
        &state,
        conn_ctx.listener_tls_mode,
        "/v1/endpoints",
        client_ip,
        now_ms,
        &req_id,
    ) {
        return resp;
    }

    let headers = req.headers().clone();
    let body = match read_bounded_body(req.into_body()).await {
        Ok(b) => b,
        Err(err) => return error_response(&err, &req_id),
    };

    let rec = match authenticate_active_node(
        &state,
        &conn_ctx,
        client_ip,
        &headers,
        ProofRequestMeta {
            method: "POST",
            path: "/v1/endpoints",
            body: &body,
            now_ms,
        },
    ) {
        Ok((node, _)) => node,
        Err(err) => return error_response(&err, &req_id),
    };

    let parsed: UpdateEndpointsRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return error_response(
                &AppError::invalid_argument(format!("invalid endpoints JSON: {err}")),
                &req_id,
            );
        }
    };

    let filtered_endpoints = sanitize_candidate_endpoints(
        &state.store,
        &state.netmap_hub,
        &state.config,
        parsed.endpoints,
    );
    state
        .netmap_hub
        .record_acked_endpoint_version(rec.node_id, parsed.acked_endpoint_version);
    match state
        .store
        .update_node_endpoints(rec.node_id, filtered_endpoints)
    {
        Ok((_, maybe_ver)) => {
            if let Some(new_ver) = maybe_ver
                && let Err(err) = state.netmap_hub.broadcast_snapshot(new_ver)
            {
                tracing::warn!(
                    component = "control_handlers",
                    event = "endpoint_update_broadcast_failed",
                    error = %err,
                    "failed broadcasting netmap snapshot after endpoint update"
                );
            }
            json_response(
                StatusCode::OK,
                &UpdateEndpointsResponse {
                    netmap_version: state.store.current_netmap_version(),
                    updated_at_ms: now_ms,
                },
            )
        }
        Err(err) => error_response(&err, &req_id),
    }
}

async fn handle_call_me_maybe(
    State(state): State<ControlAppState>,
    req: Request<Body>,
) -> Response {
    let req_id = new_request_id(&state);
    let now_ms = state.store.clock().now_unix_ms();
    let conn_ctx = req
        .extensions()
        .get::<ConnectionTlsContext>()
        .cloned()
        .unwrap_or_else(|| ConnectionTlsContext {
            listener_tls_mode: state.config.tls_mode,
            ..ConnectionTlsContext::default()
        });
    let client_ip = resolve_request_client_ip(
        &state,
        conn_ctx.listener_tls_mode,
        req.headers(),
        Some(&conn_ctx),
    );
    if let Some(resp) = enforce_ip_lockout(
        &state,
        conn_ctx.listener_tls_mode,
        "/v1/disco/call-me-maybe",
        client_ip,
        now_ms,
        &req_id,
    ) {
        return resp;
    }

    let headers = req.headers().clone();
    let body = match read_bounded_body(req.into_body()).await {
        Ok(b) => b,
        Err(err) => return error_response(&err, &req_id),
    };

    let (rec, verified_pubkey) = match authenticate_active_node(
        &state,
        &conn_ctx,
        client_ip,
        &headers,
        ProofRequestMeta {
            method: "POST",
            path: "/v1/disco/call-me-maybe",
            body: &body,
            now_ms,
        },
    ) {
        Ok(pair) => pair,
        Err(err) => return error_response(&err, &req_id),
    };

    let parsed: CallMeMaybeRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(err) => {
            return error_response(
                &AppError::invalid_argument(format!("invalid call-me-maybe JSON: {err}")),
                &req_id,
            );
        }
    };

    let sender_disco_pubkey = match PublicKey::from_bytes(rec.disco_pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return error_response(
                &AppError::internal("stored node disco_pubkey invalid"),
                &req_id,
            );
        }
    };
    if let Err(err) = validate_call_me_maybe_relay(
        &state.store,
        sender_disco_pubkey,
        parsed.dst_node_id,
        &parsed.disco_frame_b64,
        now_ms,
    ) {
        return error_response(&err, &req_id);
    }

    let _relayed = state.netmap_hub.relay_call_me_maybe(
        rec.node_id,
        verified_pubkey,
        parsed.dst_node_id,
        parsed.disco_frame_b64,
    );
    StatusCode::NO_CONTENT.into_response()
}

async fn handle_netmap_stream_ws(
    State(state): State<ControlAppState>,
    mut req: Request<Body>,
) -> Response {
    let req_id = new_request_id(&state);
    let now_ms = state.store.clock().now_unix_ms();
    let conn_ctx = req
        .extensions()
        .get::<ConnectionTlsContext>()
        .cloned()
        .unwrap_or_else(|| ConnectionTlsContext {
            listener_tls_mode: state.config.tls_mode,
            ..ConnectionTlsContext::default()
        });
    let client_ip = resolve_request_client_ip(
        &state,
        conn_ctx.listener_tls_mode,
        req.headers(),
        Some(&conn_ctx),
    );
    if let Some(resp) = enforce_ip_lockout(
        &state,
        conn_ctx.listener_tls_mode,
        "/v1/netmap/stream",
        client_ip,
        now_ms,
        &req_id,
    ) {
        return resp;
    }

    let (rec, pubkey) = match authenticate_active_node(
        &state,
        &conn_ctx,
        client_ip,
        req.headers(),
        ProofRequestMeta {
            method: "GET",
            path: "/v1/netmap/stream",
            body: b"",
            now_ms,
        },
    ) {
        Ok(pair) => pair,
        Err(err) => return error_response(&err, &req_id),
    };

    let ws_accept = match extract_ws_accept_header(req.headers()) {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };

    let Ok(disco_pubkey) = PublicKey::from_bytes(rec.disco_pubkey) else {
        return error_response(
            &AppError::internal("stored node disco_pubkey invalid"),
            &req_id,
        );
    };
    let upgrade_fut = hyper::upgrade::on(&mut req);
    let task_state = state.clone();
    state.ws_tracker.spawn(async move {
        let Ok(upgraded) = upgrade_fut.await else {
            return;
        };
        run_netmap_ws_session(
            task_state,
            rec.node_id,
            pubkey,
            disco_pubkey,
            rec.key_expires_at_ms,
            hyper_util::rt::TokioIo::new(upgraded),
        )
        .await;
    });

    build_ws_switching_response(&ws_accept)
}

async fn handle_relay_ws(State(state): State<ControlAppState>, mut req: Request<Body>) -> Response {
    let req_id = new_request_id(&state);
    let now_ms = state.store.clock().now_unix_ms();
    let conn_ctx = req
        .extensions()
        .get::<ConnectionTlsContext>()
        .cloned()
        .unwrap_or_else(|| ConnectionTlsContext {
            listener_tls_mode: state.config.tls_mode,
            ..ConnectionTlsContext::default()
        });
    let client_ip = resolve_request_client_ip(
        &state,
        conn_ctx.listener_tls_mode,
        req.headers(),
        Some(&conn_ctx),
    );

    if let Some(resp) = enforce_auth_rate_limit(
        &state,
        conn_ctx.listener_tls_mode,
        RateLimitEndpoint::Relay,
        client_ip,
        now_ms,
        &req_id,
    ) {
        return resp;
    }

    let (rec, pubkey) = match authenticate_active_node(
        &state,
        &conn_ctx,
        client_ip,
        req.headers(),
        ProofRequestMeta {
            method: "GET",
            path: "/v1/relay",
            body: b"",
            now_ms,
        },
    ) {
        Ok(pair) => pair,
        Err(err) => {
            if state
                .rate_limiter
                .should_emit_lockout_audit(client_ip, now_ms)
            {
                state.store.record_audit_best_effort(&AuditEventInput {
                    occurred_at_ms: now_ms,
                    actor: "relay:auth",
                    action: "relay_auth_rejected",
                    target: &client_ip.to_string(),
                    outcome: "denied",
                    metadata: json!({
                        "client_ip": client_ip.to_string(),
                        "error_kind": format!("{:?}", err.kind()),
                    }),
                });
            }
            return error_response(&err, &req_id);
        }
    };

    let ws_accept = match extract_ws_accept_header(req.headers()) {
        Ok(v) => v,
        Err(err) => return error_response(&err, &req_id),
    };

    let upgrade_fut = hyper::upgrade::on(&mut req);
    let task_state = state.clone();
    state.ws_tracker.spawn(async move {
        let Ok(upgraded) = upgrade_fut.await else {
            return;
        };
        run_relay_ws_session(
            task_state,
            rec.node_id,
            pubkey,
            rec.key_expires_at_ms,
            hyper_util::rt::TokioIo::new(upgraded),
        )
        .await;
    });

    build_ws_switching_response(&ws_accept)
}

async fn run_netmap_ws_session<S>(
    state: ControlAppState,
    node_id: NodeId,
    pubkey: PublicKey,
    disco_pubkey: PublicKey,
    _initial_key_expires_at_ms: Option<u64>,
    io: S,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let now_ms = state.store.clock().now_unix_ms();
    let mut sub = state.netmap_hub.subscribe(node_id, now_ms);
    if let Ok(initial) = state.netmap_hub.build_snapshot(None) {
        let frame = ServerControlFrame::NetmapSnapshot {
            sent_at_ms: now_ms,
            netmap: Box::new(initial),
        };
        if let Ok(text) = serde_json::to_string(&frame) {
            let (out_tx, mut out_rx) = mpsc::channel::<WsMessage>(64);
            if let Err(err) = out_tx.try_send(WsMessage::Text(text.into())) {
                tracing::debug!(
                    component = "control_handlers",
                    event = "initial_snapshot_queue_failed",
                    error = %err,
                    "failed queueing initial netmap snapshot frame"
                );
            }
            let hub_clone = Arc::clone(&state.netmap_hub);
            let store_clone = Arc::clone(&state.store);
            let config_clone = Arc::clone(&state.config);
            let shutdown = state.shutdown.clone();
            let stream_cancel = sub.cancel.clone();
            let seq = sub.session_seq;

            let mut bridge_cfg = WebSocketConfig::default();
            bridge_cfg.max_message_size = Some(MAX_CONTROL_WS_FRAME_BYTES);
            bridge_cfg.max_frame_size = Some(MAX_CONTROL_WS_FRAME_BYTES);

            pump_ws_duplex(
                io,
                WsDuplexControl {
                    ws_cfg: bridge_cfg,
                    stream_cancel,
                    shutdown,
                    hub_rx: &mut sub.rx,
                    direct_rx: &mut out_rx,
                },
                move |msg| {
                    let check_ms = store_clone.clock().now_unix_ms();
                    let still_active = !store_clone.is_pubkey_revoked_ram(&pubkey)
                        && !store_clone.is_node_revoked_ram(node_id)
                        && store_clone
                            .find_node_by_pubkey(&pubkey)
                            .ok()
                            .flatten()
                            .is_some_and(|n| {
                                n.status == NodeStatus::Active && !n.is_key_expired_at(check_ms)
                            });
                    if !still_active {
                        return false;
                    }
                    match msg {
                        WsMessage::Text(raw_txt) => {
                            let peer_ctx = ControlWsPeerCtx {
                                store: &store_clone,
                                hub: &hub_clone,
                                config: &config_clone,
                                node_id,
                                pubkey,
                                disco_pubkey,
                                session_seq: seq,
                            };
                            handle_client_control_ws_text(&peer_ctx, raw_txt.as_str(), &out_tx);
                            true
                        }
                        WsMessage::Binary(_) | WsMessage::Ping(_) | WsMessage::Pong(_) => true,
                        WsMessage::Close(_) | WsMessage::Frame(_) => false,
                    }
                },
                |frame| {
                    serde_json::to_string(&frame)
                        .ok()
                        .map(|txt| WsMessage::Text(txt.into()))
                },
            )
            .await;
        }
    }
    state.netmap_hub.unsubscribe(node_id, sub.session_seq);
    if state.netmap_hub.node_runtime_info(node_id).is_none()
        && let Err(err) = state.store.touch_node_last_seen(node_id)
    {
        tracing::debug!(
            component = "control_handlers",
            event = "touch_last_seen_failed",
            node_id = %node_id,
            error = %err,
            "failed updating last_seen_at_ms on netmap disconnect"
        );
    }
}

struct ControlWsPeerCtx<'a> {
    store: &'a ControlStore,
    hub: &'a NetmapHub,
    config: &'a ServerConfig,
    node_id: NodeId,
    pubkey: PublicKey,
    disco_pubkey: PublicKey,
    session_seq: u64,
}

fn handle_client_control_ws_text(
    ctx: &ControlWsPeerCtx<'_>,
    raw_txt: &str,
    direct_reply_tx: &mpsc::Sender<WsMessage>,
) {
    let Ok(parsed) = serde_json::from_str::<ClientControlFrame>(raw_txt) else {
        return;
    };
    let now_ms = ctx.store.clock().now_unix_ms();
    match parsed {
        ClientControlFrame::Heartbeat { .. } => {
            // Explicitly NEVER bumps `netmap_version` (`US-009`)
            ctx.hub
                .record_heartbeat(ctx.node_id, ctx.session_seq, now_ms);
            if let Ok(reply) =
                serde_json::to_string(&ServerControlFrame::Heartbeat { sent_at_ms: now_ms })
                && let Err(err) = direct_reply_tx.try_send(WsMessage::Text(reply.into()))
            {
                tracing::debug!(
                    component = "control_handlers",
                    event = "heartbeat_reply_dropped",
                    error = %err,
                    "dropped WS heartbeat reply on full outbound queue"
                );
            }
        }
        ClientControlFrame::EndpointUpdate {
            endpoints,
            acked_endpoint_version,
            ..
        } => {
            let filtered = sanitize_candidate_endpoints(ctx.store, ctx.hub, ctx.config, endpoints);
            ctx.hub
                .record_acked_endpoint_version(ctx.node_id, acked_endpoint_version);
            if let Ok((_, Some(new_ver))) = ctx.store.update_node_endpoints(ctx.node_id, filtered)
                && let Err(err) = ctx.hub.broadcast_snapshot(new_ver)
            {
                tracing::warn!(
                    component = "control_handlers",
                    event = "ws_endpoint_broadcast_failed",
                    error = %err,
                    "failed broadcasting netmap snapshot after WS endpoint update"
                );
            }
        }
        ClientControlFrame::CallMeMaybe {
            dst_node_id,
            disco_frame_b64,
        } => {
            if let Err(err) = validate_call_me_maybe_relay(
                ctx.store,
                ctx.disco_pubkey,
                dst_node_id,
                &disco_frame_b64,
                now_ms,
            ) {
                tracing::debug!(
                    component = "control_handlers",
                    event = "ws_call_me_maybe_rejected",
                    dst_node_id = %dst_node_id,
                    error = %err,
                    "rejected WS call_me_maybe frame"
                );
                return;
            }
            if !ctx
                .hub
                .relay_call_me_maybe(ctx.node_id, ctx.pubkey, dst_node_id, disco_frame_b64)
            {
                tracing::trace!(
                    component = "control_handlers",
                    event = "call_me_maybe_target_offline",
                    dst_node_id = %dst_node_id,
                    "call_me_maybe target peer offline or stream queue full"
                );
            }
        }
    }
}

async fn run_relay_ws_session<S>(
    state: ControlAppState,
    node_id: NodeId,
    pubkey: PublicKey,
    key_expires_at_ms: Option<u64>,
    io: S,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let now_ms = state.store.clock().now_unix_ms();
    let mut handle = state.relay_hub.register_session(node_id, pubkey, now_ms);
    let (_dummy_tx, mut dummy_rx) = mpsc::channel::<WsMessage>(1);

    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = Some(MAX_FRAME_SIZE + 64);
    cfg.max_frame_size = Some(MAX_FRAME_SIZE + 64);

    let relay_hub = Arc::clone(&state.relay_hub);
    let store = Arc::clone(&state.store);
    pump_ws_duplex(
        io,
        WsDuplexControl {
            ws_cfg: cfg,
            stream_cancel: handle.cancel.clone(),
            shutdown: state.shutdown.clone(),
            hub_rx: &mut handle.rx,
            direct_rx: &mut dummy_rx,
        },
        move |msg| {
            let check_ms = store.clock().now_unix_ms();
            let expired = key_expires_at_ms.is_some_and(|exp| check_ms >= exp);
            if store.is_pubkey_revoked_ram(&pubkey) || store.is_node_revoked_ram(node_id) || expired
            {
                return false;
            }
            match msg {
                WsMessage::Binary(bin) => {
                    let outcome = relay_hub.handle_inbound_frame(node_id, pubkey, &bin, check_ms);
                    outcome != RelayForwardOutcome::Disconnect
                }
                WsMessage::Ping(_) | WsMessage::Pong(_) => true,
                WsMessage::Text(_) | WsMessage::Close(_) | WsMessage::Frame(_) => false,
            }
        },
        |bytes: Bytes| Some(WsMessage::Binary(bytes)),
    )
    .await;

    state.relay_hub.remove_session(node_id, handle.session_seq);
}

#[derive(Default)]
struct WsPipeBridge {
    inbound: VecDeque<u8>,
    outbound: Vec<u8>,
}

impl Read for WsPipeBridge {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.inbound.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "awaiting socket read",
            ));
        }
        let mut written = 0_usize;
        while written < buf.len() {
            let Some(byte) = self.inbound.pop_front() else {
                break;
            };
            if let Some(slot) = buf.get_mut(written) {
                *slot = byte;
                written = written.saturating_add(1);
            }
        }
        Ok(written)
    }
}

impl Write for WsPipeBridge {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct WsDuplexControl<'a, T> {
    ws_cfg: WebSocketConfig,
    stream_cancel: CancellationToken,
    shutdown: CancellationToken,
    hub_rx: &'a mut mpsc::Receiver<T>,
    direct_rx: &'a mut mpsc::Receiver<WsMessage>,
}

async fn pump_ws_duplex<S, T, FIn, FOut>(
    io: S,
    mut ctrl: WsDuplexControl<'_, T>,
    mut on_inbound: FIn,
    mut to_ws_msg: FOut,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    FIn: FnMut(WsMessage) -> bool,
    FOut: FnMut(T) -> Option<WsMessage>,
{
    let (mut rd, mut wr) = tokio::io::split(io);
    let mut ws =
        WebSocket::from_raw_socket(WsPipeBridge::default(), Role::Server, Some(ctrl.ws_cfg));
    let mut read_scratch = [0_u8; 4096];

    loop {
        if !drain_ws_outbound(&mut ws, &mut wr).await {
            break;
        }
        tokio::select! {
            biased;
            () = ctrl.stream_cancel.cancelled() => {
                drain_remaining_and_close_ws(&mut ws, &mut wr, &mut ctrl, &mut to_ws_msg).await;
                break;
            }
            () = ctrl.shutdown.cancelled() => {
                drain_remaining_and_close_ws(&mut ws, &mut wr, &mut ctrl, &mut to_ws_msg).await;
                break;
            }
            Some(msg) = ctrl.direct_rx.recv() => {
                if ws.send(msg).is_err() {
                    break;
                }
            }
            maybe_item = ctrl.hub_rx.recv() => {
                let Some(item) = maybe_item else {
                    close_ws_gracefully(&mut ws, &mut wr).await;
                    break;
                };
                if let Some(ws_msg) = to_ws_msg(item)
                    && ws.send(ws_msg).is_err()
                {
                    break;
                }
            }
            read_res = rd.read(&mut read_scratch) => {
                match read_res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let Some(chunk) = read_scratch.get(..n) else {
                            break;
                        };
                        ws.get_mut().inbound.extend(chunk);
                        if !process_ws_inbound(&mut ws, &mut on_inbound) {
                            close_ws_gracefully(&mut ws, &mut wr).await;
                            break;
                        }
                    }
                }
            }
        }
    }
}

async fn drain_remaining_and_close_ws<W, T, FOut>(
    ws: &mut WebSocket<WsPipeBridge>,
    wr: &mut W,
    ctrl: &mut WsDuplexControl<'_, T>,
    to_ws_msg: &mut FOut,
) where
    W: AsyncWrite + Unpin,
    FOut: FnMut(T) -> Option<WsMessage>,
{
    if tokio::time::timeout(WS_DRAIN_SHUTDOWN_TIMEOUT, async {
        while let Ok(msg) = ctrl.direct_rx.try_recv() {
            if ws.send(msg).is_err() {
                return;
            }
        }
        while let Ok(item) = ctrl.hub_rx.try_recv() {
            if let Some(ws_msg) = to_ws_msg(item)
                && ws.send(ws_msg).is_err()
            {
                return;
            }
        }
        close_ws_gracefully(ws, wr).await;
    })
    .await
    .is_err()
    {
        tracing::debug!(
            component = "control_handlers",
            event = "ws_drain_shutdown_timeout",
            "timed out draining queued control/relay frames before WS close"
        );
    }
}

async fn close_ws_gracefully<W>(ws: &mut WebSocket<WsPipeBridge>, wr: &mut W)
where
    W: AsyncWrite + Unpin,
{
    if let Err(err) = ws.close(None) {
        tracing::trace!(
            component = "control_handlers",
            event = "ws_close_frame_skipped",
            error = %err,
            "skipping close frame on already-closing WebSocket"
        );
    }
    if !drain_ws_outbound(ws, wr).await {
        tracing::trace!(
            component = "control_handlers",
            event = "ws_close_flush_ended",
            "socket closed while flushing WebSocket close frame"
        );
    }
}

fn process_ws_inbound<FIn>(ws: &mut WebSocket<WsPipeBridge>, on_inbound: &mut FIn) -> bool
where
    FIn: FnMut(WsMessage) -> bool,
{
    loop {
        match ws.read() {
            Ok(msg) => {
                if !on_inbound(msg) {
                    return false;
                }
            }
            Err(WsError::Io(ref io_err)) if io_err.kind() == io::ErrorKind::WouldBlock => {
                return true;
            }
            Err(WsError::AlreadyClosed | WsError::ConnectionClosed) | Err(_) => {
                return false;
            }
        }
    }
}

async fn drain_ws_outbound<W>(ws: &mut WebSocket<WsPipeBridge>, wr: &mut W) -> bool
where
    W: AsyncWrite + Unpin,
{
    let pending = std::mem::take(&mut ws.get_mut().outbound);
    if pending.is_empty() {
        return true;
    }
    wr.write_all(&pending).await.is_ok() && wr.flush().await.is_ok()
}

#[derive(Clone, Copy)]
struct ProofRequestMeta<'a> {
    method: &'a str,
    path: &'a str,
    body: &'a [u8],
    now_ms: u64,
}

struct VerifiedAuthProof {
    pubkey: PublicKey,
    proof: ProofPayload,
    client_os_arch: String,
    agent_version: String,
    protocol_version: u16,
}

fn record_auth_failure_with_audit(
    state: &ControlAppState,
    listener_tls_mode: TlsMode,
    client_ip: IpAddr,
    now_ms: u64,
    path: &str,
) {
    if let Some(locked_until_ms) =
        state
            .rate_limiter
            .record_auth_failure_for_mode(listener_tls_mode, client_ip, now_ms)
        && state
            .rate_limiter
            .should_emit_lockout_audit(client_ip, now_ms)
    {
        state.store.record_audit_best_effort(&AuditEventInput {
            occurred_at_ms: now_ms,
            actor: "control:rate_limiter",
            action: "rate_limit_ip_locked",
            target: &client_ip.to_string(),
            outcome: "denied",
            metadata: json!({
                "path": path,
                "locked_until_ms": locked_until_ms,
            }),
        });
    }
}

fn verify_signed_proof(
    state: &ControlAppState,
    conn_ctx: &ConnectionTlsContext,
    client_ip: IpAddr,
    headers: &HeaderMap,
    meta: ProofRequestMeta<'_>,
) -> AppResult<VerifiedAuthProof> {
    match verify_signed_proof_inner(state, conn_ctx, headers, meta) {
        Ok(verified) => Ok(verified),
        Err(err) => {
            record_auth_failure_with_audit(
                state,
                conn_ctx.listener_tls_mode,
                client_ip,
                meta.now_ms,
                meta.path,
            );
            Err(err)
        }
    }
}

fn verify_signed_proof_inner(
    state: &ControlAppState,
    conn_ctx: &ConnectionTlsContext,
    headers: &HeaderMap,
    meta: ProofRequestMeta<'_>,
) -> AppResult<VerifiedAuthProof> {
    let challenge_id_str = required_header_str(headers, HEADER_CHALLENGE_ID)?;
    let challenge_id: NodeId = challenge_id_str
        .parse()
        .map_err(|_| AppError::unauthenticated("invalid challenge_id header"))?;
    let pubkey_raw = decode_header_base64(headers, HEADER_NODE_PUBKEY)?;
    let pk_arr = <[u8; 32]>::try_from(pubkey_raw.as_slice())
        .map_err(|_| AppError::unauthenticated("invalid node_pubkey byte length"))?;
    let claimed_pubkey = PublicKey::from_bytes(pk_arr)
        .map_err(|_| AppError::unauthenticated("invalid node_pubkey"))?;

    let nonce_raw = decode_header_base64(headers, HEADER_BOX_NONCE)?;
    let box_nonce = <[u8; 24]>::try_from(nonce_raw.as_slice())
        .map_err(|_| AppError::unauthenticated("invalid box_nonce length"))?;
    let ciphertext = decode_header_base64(headers, HEADER_AUTH_PROOF)?;

    // Single-use atomic removal BEFORE decryption (`api-design.md` §1.3)
    let pending = state
        .challenges
        .consume(challenge_id)
        .ok_or_else(|| AppError::unauthenticated("challenge not found or already used"))?;
    if meta.now_ms > pending.expires_at_ms {
        return Err(AppError::unauthenticated("challenge expired"));
    }

    let opened = open_proof(
        &ciphertext,
        &box_nonce,
        &claimed_pubkey,
        pending.server_eph_keypair.secret_bytes(),
    )?;

    let trusted_reverse_proxy = conn_ctx.listener_tls_mode == TlsMode::ReverseProxy
        && state.trusted_proxies.contains(&conn_ctx.peer_addr.ip());

    let expected_tls_exporter_b64 = if trusted_reverse_proxy {
        None
    } else {
        let exporter = conn_ctx
            .tls_exporter_b64
            .as_deref()
            .ok_or_else(|| AppError::unauthenticated("missing TLS exporter binding"))?;
        Some(exporter)
    };

    let body_hash = sha256_hex(meta.body);
    verify_proof_claims(
        &opened,
        &ExpectedProofClaims {
            challenge_id: pending.id,
            challenge_nonce_b64: &pending.challenge_nonce_b64,
            method: meta.method,
            path: meta.path,
            body_sha256_hex: &body_hash,
            claimed_node_pubkey: claimed_pubkey,
            now_unix_ms: meta.now_ms,
            expected_tls_exporter_b64,
        },
    )?;

    Ok(VerifiedAuthProof {
        pubkey: claimed_pubkey,
        proof: opened,
        client_os_arch: pending.client_os_arch,
        agent_version: pending.agent_version,
        protocol_version: pending.protocol_version,
    })
}

fn authenticate_active_node(
    state: &ControlAppState,
    conn_ctx: &ConnectionTlsContext,
    client_ip: IpAddr,
    headers: &HeaderMap,
    meta: ProofRequestMeta<'_>,
) -> AppResult<(mesh_store::StoredNodeRecord, PublicKey)> {
    let auth = verify_signed_proof(state, conn_ctx, client_ip, headers, meta)?;
    let rec = match state.store.find_node_by_pubkey(&auth.pubkey) {
        Ok(Some(r)) => r,
        Ok(None) => {
            record_auth_failure_with_audit(
                state,
                conn_ctx.listener_tls_mode,
                client_ip,
                meta.now_ms,
                meta.path,
            );
            return Err(AppError::unauthenticated("unknown node public key"));
        }
        Err(err) => {
            if state.store.is_pubkey_revoked_ram(&auth.pubkey) {
                return Err(AppError::node_revoked("node identity has been revoked"));
            }
            return Err(err);
        }
    };
    if state.store.is_node_permanently_revoked_ram(rec.node_id) || rec.status == NodeStatus::Revoked
    {
        return Err(AppError::node_revoked("node identity has been revoked"));
    }
    if state.store.is_node_expired_ram(rec.node_id)
        || rec.status == NodeStatus::Expired
        || rec.is_key_expired_at(meta.now_ms)
    {
        return Err(AppError::node_key_expired("node key has expired"));
    }
    if state.store.is_pubkey_revoked_ram(&auth.pubkey) {
        return Err(AppError::node_revoked("node identity has been revoked"));
    }
    state.rate_limiter.record_auth_success(client_ip);
    Ok((rec, auth.pubkey))
}

fn resolve_request_client_ip(
    state: &ControlAppState,
    listener_tls_mode: TlsMode,
    headers: &HeaderMap,
    conn_ctx: Option<&ConnectionTlsContext>,
) -> IpAddr {
    let peer_ip = conn_ctx
        .map(|c| c.peer_addr.ip())
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::LOCALHOST));
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let x_real = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    state
        .rate_limiter
        .resolve_client_ip_for_mode(listener_tls_mode, peer_ip, xff, x_real)
}

fn build_rate_limited_response(retry_after_secs: u64, req_id: &str) -> Response {
    let err = AppError::rate_limited("rate limit exceeded");
    let mut resp = error_response(&err, req_id);
    if let Ok(hdr_val) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert("retry-after", hdr_val);
    }
    resp
}

fn enforce_ip_lockout(
    state: &ControlAppState,
    listener_tls_mode: TlsMode,
    path: &str,
    client_ip: IpAddr,
    now_ms: u64,
    req_id: &str,
) -> Option<Response> {
    let retry_after_secs =
        state
            .rate_limiter
            .check_ip_lockout_for_mode(listener_tls_mode, client_ip, now_ms)?;
    if state
        .rate_limiter
        .should_emit_lockout_audit(client_ip, now_ms)
    {
        state.store.record_audit_best_effort(&AuditEventInput {
            occurred_at_ms: now_ms,
            actor: "control:rate_limiter",
            action: "rate_limit_ip_locked",
            target: &client_ip.to_string(),
            outcome: "denied",
            metadata: json!({
                "path": path,
                "retry_after_secs": retry_after_secs,
            }),
        });
    }
    Some(build_rate_limited_response(retry_after_secs, req_id))
}

fn enforce_auth_rate_limit(
    state: &ControlAppState,
    listener_tls_mode: TlsMode,
    endpoint: RateLimitEndpoint,
    client_ip: IpAddr,
    now_ms: u64,
    req_id: &str,
) -> Option<Response> {
    match state.rate_limiter.check_endpoint_request_for_mode(
        listener_tls_mode,
        endpoint,
        client_ip,
        now_ms,
    ) {
        RateLimitDecision::Allowed => None,
        RateLimitDecision::IpLocked { retry_after_secs } => {
            if endpoint == RateLimitEndpoint::Register {
                state
                    .rate_limiter
                    .record_registration_outcome(RegistrationOutcome::RateLimited);
            }
            if state
                .rate_limiter
                .should_emit_lockout_audit(client_ip, now_ms)
            {
                state.store.record_audit_best_effort(&AuditEventInput {
                    occurred_at_ms: now_ms,
                    actor: "control:rate_limiter",
                    action: "rate_limit_ip_locked",
                    target: &client_ip.to_string(),
                    outcome: "denied",
                    metadata: json!({
                        "endpoint": format!("{endpoint:?}"),
                        "retry_after_secs": retry_after_secs,
                    }),
                });
            }
            Some(build_rate_limited_response(retry_after_secs, req_id))
        }
        RateLimitDecision::GlobalLimitExceeded { retry_after_secs } => {
            if endpoint == RateLimitEndpoint::Register {
                state
                    .rate_limiter
                    .record_registration_outcome(RegistrationOutcome::RateLimited);
            }
            if state.rate_limiter.should_emit_global_limit_audit(now_ms) {
                state.store.record_audit_best_effort(&AuditEventInput {
                    occurred_at_ms: now_ms,
                    actor: "control:rate_limiter",
                    action: "rate_limit_global_exceeded",
                    target: "global",
                    outcome: "denied",
                    metadata: json!({
                        "endpoint": format!("{endpoint:?}"),
                        "retry_after_secs": retry_after_secs,
                    }),
                });
            }
            Some(build_rate_limited_response(retry_after_secs, req_id))
        }
    }
}

async fn read_bounded_body(body: Body) -> AppResult<Vec<u8>> {
    to_bytes(body, MAX_HTTP_BODY_BYTES)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| {
            AppError::invalid_argument(format!("request body exceeded {MAX_HTTP_BODY_BYTES} bytes"))
        })
}

fn required_header_str<'a>(headers: &'a HeaderMap, name: &str) -> AppResult<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::unauthenticated(format!("missing header {name}")))
}

fn decode_header_base64(headers: &HeaderMap, name: &str) -> AppResult<Vec<u8>> {
    let raw = required_header_str(headers, name)?;
    BASE64_STANDARD
        .decode(raw)
        .map_err(|_| AppError::unauthenticated(format!("invalid base64 header {name}")))
}

fn sanitize_candidate_endpoints(
    store: &ControlStore,
    netmap_hub: &NetmapHub,
    config: &ServerConfig,
    endpoints: Vec<CandidateEndpoint>,
) -> Vec<CandidateEndpoint> {
    let Ok(overlay_cidr) = store
        .load_overlay_cidr()
        .or_else(|_| OverlayCidr::parse(&config.overlay_cidr))
        .or_else(|_| OverlayCidr::parse(DEFAULT_OVERLAY_CIDR))
    else {
        return Vec::new();
    };
    let (_, ctrl_ep, stun_eps) = netmap_hub.current_endpoints();
    let ctx = CandidateFilterContext {
        overlay_cidr,
        control_tcp_endpoint: ctrl_ep.parse::<SocketAddr>().ok(),
        stun_udp_endpoint: stun_eps.first().and_then(|s| s.parse::<SocketAddr>().ok()),
    };
    let mut seen = HashSet::new();
    endpoints
        .into_iter()
        .filter(|ep| is_valid_candidate_endpoint(ep.addr, None, &ctx) && seen.insert(ep.addr))
        .take(MAX_CANDIDATE_ENDPOINTS)
        .collect()
}

fn validate_call_me_maybe_relay(
    store: &ControlStore,
    sender_disco_pubkey: PublicKey,
    dst_node_id: NodeId,
    frame_b64: &str,
    now_ms: u64,
) -> AppResult<()> {
    let raw = BASE64_STANDARD
        .decode(frame_b64.trim())
        .map_err(|_| AppError::invalid_argument("invalid base64 disco_frame_b64"))?;
    if raw.len() < MIN_DISCO_PACKET_LEN
        || raw.len() > MAX_DISCO_FRAME_BYTES
        || !is_disco_packet(&raw)
    {
        return Err(AppError::invalid_argument(
            "invalid MESHDS disco packet length or magic prefix",
        ));
    }
    if store.is_node_revoked_ram(dst_node_id) {
        return Err(AppError::not_found("target peer is revoked"));
    }
    let Some(dst) = store.find_node_by_id(dst_node_id)? else {
        return Err(AppError::not_found("target peer not found"));
    };
    if dst.status != NodeStatus::Active || dst.is_key_expired_at(now_ms) {
        return Err(AppError::not_found("target peer is not active"));
    }
    let dst_disco_pubkey = PublicKey::from_bytes(dst.disco_pubkey)
        .map_err(|_| AppError::internal("stored target node disco_pubkey invalid"))?;
    let outer_sender = peek_outer_sender_pubkey(&raw, &dst_disco_pubkey).map_err(|_| {
        AppError::invalid_argument("disco frame outer sender failed anti-reflection check")
    })?;
    if outer_sender != sender_disco_pubkey {
        return Err(AppError::invalid_argument(
            "disco frame outer sender pubkey does not match authenticated peer",
        ));
    }
    Ok(())
}

fn extract_ws_accept_header(headers: &HeaderMap) -> AppResult<String> {
    let is_ws = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if !is_ws {
        return Err(AppError::invalid_argument("expected Upgrade: websocket"));
    }
    let key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::invalid_argument("missing Sec-WebSocket-Key"))?;
    Ok(derive_accept_key(key.as_bytes()))
}

fn build_ws_switching_response(ws_accept: &str) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade");
    if let Ok(accept_hdr) = HeaderName::from_bytes(b"sec-websocket-accept")
        && let Ok(accept_val) = HeaderValue::from_str(ws_accept)
    {
        builder = builder.header(accept_hdr, accept_val);
    }
    builder
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub(crate) fn json_response<T: serde::Serialize>(status: StatusCode, payload: &T) -> Response {
    let body_bytes = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub(crate) fn error_response(err: &AppError, request_id: &str) -> Response {
    let status = StatusCode::from_u16(err.kind().http_status_code())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let envelope = ErrorResponse {
        error: mesh_core::ErrorEnvelope {
            kind: err.kind(),
            code: err.kind().wire_code().to_owned(),
            message: err.public_message().to_owned(),
            request_id: request_id.to_owned(),
        },
    };
    json_response(status, &envelope)
}

fn new_request_id(state: &ControlAppState) -> String {
    NodeId::new_v7(state.store.clock().now_unix_ms()).to_string()
}

const fn os_label(os: TargetOs) -> &'static str {
    match os {
        TargetOs::Darwin => "darwin",
        TargetOs::Windows => "windows",
        TargetOs::Linux => "linux",
        TargetOs::Android => "android",
        TargetOs::Ios => "ios",
    }
}

const fn arch_label(arch: TargetArch) -> &'static str {
    match arch {
        TargetArch::Arm64 => "arm64",
        TargetArch::Amd64 => "amd64",
    }
}

fn sanitize_short_label(raw: &str, max_len: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_PROTOCOL_TAG.to_owned();
    }
    trimmed
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(max_len)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use hyper::client::conn::http1 as hyper_client_http1;
    use hyper::server::conn::http1 as hyper_server_http1;
    use hyper::service::{Service as _, service_fn};
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use mesh_core::{
        Clock as _, ErrorKind, ErrorResponse, FakeClock, KeyId, NodeId, NodeName, PublicKey,
        SystemClock,
    };
    use mesh_crypto::{
        DiscoKeypair, NodeKeypair, PreAuthToken, ProofPayload, seal_proof, sha256_digest,
        sha256_hex,
    };
    use mesh_proto::control::{
        CallMeMaybeRequest, ChallengeRequest, ChallengeResponse, HEADER_AUTH_PROOF,
        HEADER_BOX_NONCE, HEADER_CHALLENGE_ID, HEADER_NODE_PUBKEY, RegisterNodeRequest,
        RegisterNodeResponse, ServerControlFrame, TargetArch, TargetOs, TerminationReason,
        UpdateEndpointsRequest,
    };
    use mesh_proto::netmap::CandidateEndpoint;
    use mesh_proto::relay::RelayNoticeCode;
    use mesh_store::{ControlStore, ControlStoreConfig, CreatePreAuthKeyInput};
    use tempfile::TempDir;
    use tokio_tungstenite::tungstenite::Error as WsError;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::tungstenite::protocol::{Role, WebSocket};
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::{
        ConnectionTlsContext, ControlAppState, MAX_PENDING_CHALLENGES, PendingChallengeStore,
        build_control_router, os_label,
    };
    use crate::config::{ServerConfig, TlsMode};
    use crate::netmap_hub::NetmapHub;
    use crate::rate_limit::{ClientIpExtractor, RateLimiter};
    use crate::relay_hub::RelayHub;

    async fn send_router_req(
        router: axum::Router,
        ctx: ConnectionTlsContext,
        req: Request<Body>,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, bytes) = send_router_req_with_headers(router, ctx, req).await;
        (status, bytes)
    }

    async fn send_router_req_with_headers(
        router: axum::Router,
        ctx: ConnectionTlsContext,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let (client_io, server_io) = tokio::io::duplex(65_536);
        let svc = service_fn(move |hreq: Request<hyper::body::Incoming>| {
            let r = router.clone();
            let c = ctx.clone();
            async move {
                let (parts, incoming) = hreq.into_parts();
                let mut areq = Request::from_parts(parts, Body::new(incoming));
                areq.extensions_mut().insert(c);
                TowerToHyperService::new(r).call(areq).await
            }
        });
        let srv_task = tokio::spawn(async move {
            hyper_server_http1::Builder::new()
                .serve_connection(TokioIo::new(server_io), svc)
                .await
        });
        let (mut sender, conn) = hyper_client_http1::handshake(TokioIo::new(client_io))
            .await
            .expect("client handshake");
        let conn_task = tokio::spawn(conn);
        let resp = sender.send_request(req).await.expect("send request");
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = to_bytes(Body::new(resp.into_body()), 131_072)
            .await
            .expect("read resp bytes")
            .to_vec();
        drop(sender);
        if let Ok(Err(err)) = conn_task.await {
            tracing::debug!(error = %err, "client http conn closed in test");
        }
        if let Ok(Err(err)) = srv_task.await {
            tracing::debug!(error = %err, "server http conn closed in test");
        }
        (status, headers, bytes)
    }

    fn test_state(dir: &TempDir, now_ms: u64) -> (ControlAppState, String) {
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
        let token = PreAuthToken::generate();
        let raw_token = "mpk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        let raw_hash = mesh_crypto::sha256_digest(raw_token.as_bytes());
        let _unused = token.sha256_digest();
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms),
                    token_hash: raw_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: None,
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .expect("mint preauth key");

        let cfg = Arc::new(ServerConfig {
            public_host: "203.0.113.10".to_owned(),
            ..ServerConfig::default()
        });
        let _acme =
            crate::acme::AcmeManager::initialize(&cfg, store.clone()).expect("init tls identity");
        let trusted = cfg.trusted_proxy_set();
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            trusted.clone(),
        )));
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
        let state = ControlAppState {
            config: cfg,
            trusted_proxies: Arc::new(trusted),
            store,
            rate_limiter,
            challenges: Arc::new(PendingChallengeStore::new()),
            netmap_hub,
            relay_hub,
            ws_tracker: TaskTracker::new(),
            shutdown: CancellationToken::new(),
        };
        (state, raw_token)
    }

    #[tokio::test]
    async fn test_challenge_single_use_and_tls_exporter_binding_enforced() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (state, raw_token) = test_state(&dir, now_ms);
        let router = build_control_router(state.clone());
        let node_kp = NodeKeypair::generate();
        let disco_kp = DiscoKeypair::generate();
        let exporter_b64 = BASE64_STANDARD.encode([0x77_u8; 32]);
        let conn_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.44:50000".parse().expect("addr"),
            tls_exporter_b64: Some(exporter_b64.clone()),
            listener_tls_mode: TlsMode::IpPinned,
        };

        // Act 1: Request challenge
        let ch_body = serde_json::to_vec(&ChallengeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            protocol_version: 1,
            agent_version: "0.1.0".to_owned(),
            os: TargetOs::Darwin,
            arch: TargetArch::Arm64,
        })
        .expect("serialize challenge req");
        let ch_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .header("content-type", "application/json")
            .body(Body::from(ch_body))
            .expect("build req");
        let (ch_status, ch_bytes) = send_router_req(router.clone(), conn_ctx.clone(), ch_req).await;
        assert_eq!(ch_status, StatusCode::OK);
        let challenge: ChallengeResponse =
            serde_json::from_slice(&ch_bytes).expect("decode challenge");

        // Act 2: Seal register request
        let reg_body = serde_json::to_vec(&RegisterNodeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            preauth_key: raw_token,
            node_name: NodeName::parse("macbook-pro").expect("name"),
            previous_node_pubkey: None,
        })
        .expect("serialize register");
        let proof = ProofPayload {
            challenge_id: challenge.challenge_id,
            challenge_nonce: challenge.challenge_nonce.clone(),
            method: "POST".to_owned(),
            path: "/v1/nodes/register".to_owned(),
            body_sha256: sha256_hex(&reg_body),
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            timestamp_at_ms: now_ms,
            tls_exporter_binding: exporter_b64,
        };
        let sealed = seal_proof(&proof, &challenge.server_eph_pubkey, &node_kp).expect("seal");

        let build_reg_req = || {
            Request::builder()
                .method(Method::POST)
                .uri("/v1/nodes/register")
                .header(HEADER_CHALLENGE_ID, challenge.challenge_id.to_string())
                .header(
                    HEADER_NODE_PUBKEY,
                    BASE64_STANDARD.encode(node_kp.public_key().as_bytes()),
                )
                .header(HEADER_BOX_NONCE, BASE64_STANDARD.encode(sealed.box_nonce))
                .header(
                    HEADER_AUTH_PROOF,
                    BASE64_STANDARD.encode(&sealed.ciphertext),
                )
                .body(Body::from(reg_body.clone()))
                .expect("reg req")
        };

        // Valid register consumes single-use challenge cleanly
        let (ok_status, ok_bytes) =
            send_router_req(router.clone(), conn_ctx.clone(), build_reg_req()).await;
        assert_eq!(ok_status, StatusCode::OK);
        let reg_parsed: RegisterNodeResponse =
            serde_json::from_slice(&ok_bytes).expect("decode reg resp");
        assert_eq!(reg_parsed.node_name.as_str(), "macbook-pro");

        // Replaying the EXACT same signed challenge -> MUST fail with 401 "authentication failed"
        let (replay_status, replay_bytes) =
            send_router_req(router, conn_ctx, build_reg_req()).await;
        assert_eq!(replay_status, StatusCode::UNAUTHORIZED);
        let replay_text = String::from_utf8(replay_bytes).expect("utf8");
        assert!(replay_text.contains("authentication failed"));
        assert_eq!(MAX_PENDING_CHALLENGES, 4_096);
    }

    #[tokio::test]
    async fn test_tls_exporter_mismatch_rejected_standalone_and_skipped_for_trusted_reverse_proxy()
    {
        // Arrange: Standalone server rejects mismatched exporter binding
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (standalone_state, _) = test_state(&dir, now_ms);
        let standalone_router = build_control_router(standalone_state.clone());
        let node_kp = NodeKeypair::generate();
        let disco_kp = DiscoKeypair::generate();

        let ch_body = serde_json::to_vec(&ChallengeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            protocol_version: 1,
            agent_version: "0.1.0".to_owned(),
            os: TargetOs::Linux,
            arch: TargetArch::Amd64,
        })
        .expect("serialize challenge req");
        let ch_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .header("content-type", "application/json")
            .body(Body::from(ch_body))
            .expect("build req");
        let conn_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.44:50000".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x11_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };
        let (ch_st, ch_bytes) =
            send_router_req(standalone_router.clone(), conn_ctx.clone(), ch_req).await;
        assert_eq!(ch_st, StatusCode::OK);
        let ch: ChallengeResponse = serde_json::from_slice(&ch_bytes).expect("challenge");

        let ep_body = serde_json::to_vec(&mesh_proto::control::UpdateEndpointsRequest {
            endpoints: Vec::new(),
            nat_type: mesh_proto::netmap::NatMappingKind::Unknown,
            acked_endpoint_version: 0,
        })
        .expect("ep body");
        let wrong_exporter = BASE64_STANDARD.encode([0x22_u8; 32]);
        let proof = ProofPayload {
            challenge_id: ch.challenge_id,
            challenge_nonce: ch.challenge_nonce,
            method: "POST".to_owned(),
            path: "/v1/endpoints".to_owned(),
            body_sha256: sha256_hex(&ep_body),
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            timestamp_at_ms: now_ms,
            tls_exporter_binding: wrong_exporter,
        };
        let sealed = seal_proof(&proof, &ch.server_eph_pubkey, &node_kp).expect("seal");
        let ep_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/endpoints")
            .header(HEADER_CHALLENGE_ID, ch.challenge_id.to_string())
            .header(
                HEADER_NODE_PUBKEY,
                BASE64_STANDARD.encode(node_kp.public_key().as_bytes()),
            )
            .header(HEADER_BOX_NONCE, BASE64_STANDARD.encode(sealed.box_nonce))
            .header(
                HEADER_AUTH_PROOF,
                BASE64_STANDARD.encode(&sealed.ciphertext),
            )
            .body(Body::from(ep_body))
            .expect("ep req");
        let (bad_st, bad_bytes) = send_router_req(standalone_router, conn_ctx, ep_req).await;
        assert_eq!(bad_st, StatusCode::UNAUTHORIZED);
        assert!(
            String::from_utf8(bad_bytes)
                .expect("utf8")
                .contains("authentication failed")
        );

        // Arrange: ReverseProxy mode skips exporter check ONLY when peer IP is in trusted_proxies
        let dir2 = TempDir::new().expect("tempdir2");
        let (base_state, raw_token) = test_state(&dir2, now_ms);
        let proxy_ip: std::net::IpAddr = "127.0.0.1".parse().expect("ip");
        let proxy_cfg = Arc::new(ServerConfig {
            tls_mode: crate::config::TlsMode::ReverseProxy,
            trusted_proxies: vec![proxy_ip],
            public_host: "203.0.113.10".to_owned(),
            ..ServerConfig::default()
        });
        let trusted = proxy_cfg.trusted_proxy_set();
        let proxy_state = ControlAppState {
            config: proxy_cfg,
            trusted_proxies: Arc::new(trusted.clone()),
            rate_limiter: Arc::new(RateLimiter::new(ClientIpExtractor::new(
                crate::config::TlsMode::ReverseProxy,
                trusted,
            ))),
            ..base_state
        };
        let proxy_router = build_control_router(proxy_state);
        let ch_req2 = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&ChallengeRequest {
                    node_pubkey: node_kp.public_key(),
                    disco_pubkey: disco_kp.public_key(),
                    protocol_version: 1,
                    agent_version: "0.1.0".to_owned(),
                    os: TargetOs::Linux,
                    arch: TargetArch::Amd64,
                })
                .expect("ch"),
            ))
            .expect("req");
        let proxy_ctx = ConnectionTlsContext {
            peer_addr: std::net::SocketAddr::new(proxy_ip, 44444),
            tls_exporter_b64: None,
            listener_tls_mode: TlsMode::ReverseProxy,
        };
        let (st2, b2) = send_router_req(proxy_router.clone(), proxy_ctx.clone(), ch_req2).await;
        assert_eq!(st2, StatusCode::OK);
        let ch2: ChallengeResponse = serde_json::from_slice(&b2).expect("ch2");
        let reg_body2 = serde_json::to_vec(&RegisterNodeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            preauth_key: raw_token,
            node_name: NodeName::parse("proxy-node").expect("name"),
            previous_node_pubkey: None,
        })
        .expect("reg");
        let proof2 = ProofPayload {
            challenge_id: ch2.challenge_id,
            challenge_nonce: ch2.challenge_nonce,
            method: "POST".to_owned(),
            path: "/v1/nodes/register".to_owned(),
            body_sha256: sha256_hex(&reg_body2),
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            timestamp_at_ms: now_ms,
            tls_exporter_binding: String::new(),
        };
        let sealed2 = seal_proof(&proof2, &ch2.server_eph_pubkey, &node_kp).expect("seal2");
        let reg_req2 = Request::builder()
            .method(Method::POST)
            .uri("/v1/nodes/register")
            .header(HEADER_CHALLENGE_ID, ch2.challenge_id.to_string())
            .header(
                HEADER_NODE_PUBKEY,
                BASE64_STANDARD.encode(node_kp.public_key().as_bytes()),
            )
            .header(HEADER_BOX_NONCE, BASE64_STANDARD.encode(sealed2.box_nonce))
            .header(
                HEADER_AUTH_PROOF,
                BASE64_STANDARD.encode(&sealed2.ciphertext),
            )
            .body(Body::from(reg_body2))
            .expect("reg2");
        let (ok2, _) = send_router_req(proxy_router, proxy_ctx, reg_req2).await;
        assert_eq!(ok2, StatusCode::OK);
    }

    struct TestSignedClient<'a> {
        router: &'a Router,
        conn_ctx: &'a ConnectionTlsContext,
        node_kp: &'a NodeKeypair,
        disco_kp: &'a DiscoKeypair,
        now_ms: u64,
    }

    async fn sign_register_node(
        client: &TestSignedClient<'_>,
        preauth_key: &str,
        node_name: &str,
        previous_node_pubkey: Option<PublicKey>,
    ) -> RegisterNodeResponse {
        let reg_body = serde_json::to_vec(&RegisterNodeRequest {
            node_pubkey: client.node_kp.public_key(),
            disco_pubkey: client.disco_kp.public_key(),
            preauth_key: preauth_key.to_owned(),
            node_name: NodeName::parse(node_name).expect("name"),
            previous_node_pubkey,
        })
        .expect("reg body");
        let (ok_st, ok_bytes) = send_signed_post(client, "/v1/nodes/register", reg_body, 0).await;
        assert_eq!(ok_st, StatusCode::OK);
        serde_json::from_slice(&ok_bytes).expect("reg resp")
    }

    async fn send_signed_post(
        client: &TestSignedClient<'_>,
        path: &str,
        body: Vec<u8>,
        offset_ms: u64,
    ) -> (StatusCode, Vec<u8>) {
        let ch_body = serde_json::to_vec(&ChallengeRequest {
            node_pubkey: client.node_kp.public_key(),
            disco_pubkey: client.disco_kp.public_key(),
            protocol_version: 1,
            agent_version: "0.1.0".to_owned(),
            os: TargetOs::Linux,
            arch: TargetArch::Amd64,
        })
        .expect("ch body");
        let ch_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .header("content-type", "application/json")
            .body(Body::from(ch_body))
            .expect("ch req");
        let (st, ch_bytes) =
            send_router_req(client.router.clone(), client.conn_ctx.clone(), ch_req).await;
        assert_eq!(st, StatusCode::OK);
        let ch: ChallengeResponse = serde_json::from_slice(&ch_bytes).expect("ch decode");

        let proof = ProofPayload {
            challenge_id: ch.challenge_id,
            challenge_nonce: ch.challenge_nonce,
            method: "POST".to_owned(),
            path: path.to_owned(),
            body_sha256: sha256_hex(&body),
            node_pubkey: client.node_kp.public_key(),
            disco_pubkey: client.disco_kp.public_key(),
            timestamp_at_ms: client.now_ms + offset_ms,
            tls_exporter_binding: client.conn_ctx.tls_exporter_b64.clone().unwrap_or_default(),
        };
        let sealed = seal_proof(&proof, &ch.server_eph_pubkey, client.node_kp).expect("seal");
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(HEADER_CHALLENGE_ID, ch.challenge_id.to_string())
            .header(
                HEADER_NODE_PUBKEY,
                BASE64_STANDARD.encode(client.node_kp.public_key().as_bytes()),
            )
            .header(HEADER_BOX_NONCE, BASE64_STANDARD.encode(sealed.box_nonce))
            .header(
                HEADER_AUTH_PROOF,
                BASE64_STANDARD.encode(&sealed.ciphertext),
            )
            .body(Body::from(body))
            .expect("req");
        send_router_req(client.router.clone(), client.conn_ctx.clone(), req).await
    }

    #[tokio::test]
    async fn test_ws_duplex_drains_termination_and_relay_notice_before_close() {
        // Arrange: Control WebSocket duplex receives NetmapSnapshot, then IdentityTerminated before Close
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (state, raw_token) = test_state(&dir, now_ms);
        let router = build_control_router(state.clone());
        let conn_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.44:50000".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x33_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };
        let kp = NodeKeypair::generate();
        let dkp = DiscoKeypair::generate();
        let drain_client = TestSignedClient {
            router: &router,
            conn_ctx: &conn_ctx,
            node_kp: &kp,
            disco_kp: &dkp,
            now_ms,
        };
        let reg = sign_register_node(&drain_client, &raw_token, "drain-node", None).await;
        let expires_ms = reg.key_expires_at_ms;
        assert!(expires_ms.is_some());

        let (mut client_ctrl, server_ctrl) = tokio::io::duplex(65_536);
        let ctrl_task = tokio::spawn(super::run_netmap_ws_session(
            state.clone(),
            reg.node_id,
            kp.public_key(),
            dkp.public_key(),
            expires_ms,
            server_ctrl,
        ));

        let mut client_ws =
            WebSocket::from_raw_socket(super::WsPipeBridge::default(), Role::Client, None);
        let mut buf = [0_u8; 4096];
        let mut frames = Vec::new();
        let mut terminated = false;
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut client_ctrl, &mut buf)
                .await
                .expect("read");
            if n == 0 {
                break;
            }
            let chunk = buf.get(..n).expect("slice");
            client_ws.get_mut().inbound.extend(chunk);
            loop {
                match client_ws.read() {
                    Ok(WsMessage::Text(txt)) => {
                        let decoded: ServerControlFrame =
                            serde_json::from_str(txt.as_str()).expect("control frame json");
                        frames.push(decoded);
                        if !terminated {
                            terminated = true;
                            state.netmap_hub.terminate_node_stream(
                                reg.node_id,
                                TerminationReason::NodeRevoked,
                                "revoked during drain test",
                                now_ms + 1,
                            );
                        }
                    }
                    Ok(WsMessage::Close(_)) => break,
                    Ok(_) => {}
                    Err(WsError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        ctrl_task.await.expect("ctrl ws task");
        assert!(
            frames.iter().any(|f| matches!(
                f,
                ServerControlFrame::IdentityTerminated {
                    error_kind: TerminationReason::NodeRevoked,
                    ..
                }
            )),
            "expected IdentityTerminated control frame before WS close, got {frames:?}"
        );

        // Arrange 2: Relay WebSocket duplex receives RelayFrame::ControlNotice(NodeRevoked) before Close
        let (mut client_relay, server_relay) = tokio::io::duplex(65_536);
        let relay_task = tokio::spawn(super::run_relay_ws_session(
            state.clone(),
            reg.node_id,
            kp.public_key(),
            expires_ms,
            server_relay,
        ));
        for _ in 0..64 {
            if state.relay_hub.metrics_snapshot().active_sessions == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        state
            .relay_hub
            .disconnect_node(reg.node_id, RelayNoticeCode::NodeRevoked);

        let mut relay_ws =
            WebSocket::from_raw_socket(super::WsPipeBridge::default(), Role::Client, None);
        let mut relay_notices = Vec::new();
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut client_relay, &mut buf)
                .await
                .expect("read relay");
            if n == 0 {
                break;
            }
            let chunk = buf.get(..n).expect("slice");
            relay_ws.get_mut().inbound.extend(chunk);
            loop {
                match relay_ws.read() {
                    Ok(WsMessage::Binary(bin)) => {
                        let decoded =
                            mesh_proto::relay::RelayFrame::decode(&bin).expect("relay frame");
                        relay_notices.push(decoded);
                    }
                    Ok(WsMessage::Close(_)) => break,
                    Ok(_) => {}
                    Err(WsError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        relay_task.await.expect("relay ws task");
        assert!(
            relay_notices.iter().any(|f| matches!(
                f,
                mesh_proto::relay::RelayFrame::ControlNotice {
                    code: RelayNoticeCode::NodeRevoked
                }
            )),
            "expected RelayFrame::ControlNotice(NodeRevoked) before WS close, got {relay_notices:?}"
        );
    }

    #[tokio::test]
    async fn test_register_rotation_closes_existing_ws_and_blocks_old_pubkey_inbound() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (state, raw_token) = test_state(&dir, now_ms);
        let router = build_control_router(state.clone());
        let conn_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.44:50000".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x44_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };
        let kp_old = NodeKeypair::generate();
        let dkp_old = DiscoKeypair::generate();
        let old_client = TestSignedClient {
            router: &router,
            conn_ctx: &conn_ctx,
            node_kp: &kp_old,
            disco_kp: &dkp_old,
            now_ms,
        };
        let first = sign_register_node(&old_client, &raw_token, "rot-node", None).await;

        let sub_old = state.netmap_hub.subscribe(first.node_id, now_ms);
        let relay_old =
            state
                .relay_hub
                .register_session(first.node_id, kp_old.public_key(), now_ms);

        // Mint bound key for rot-node to authorize key rotation (`BLK-S1-01`)
        let bound_raw = "mpk_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned();
        state
            .store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms + 1),
                    token_hash: sha256_digest(bound_raw.as_bytes()),
                    label: None,
                    bound_node_name: Some(NodeName::parse("rot-node").expect("name")),
                    reusable: false,
                    max_uses: None,
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .expect("mint bound key");

        // Act: rotate node key to kp_new
        let kp_new = NodeKeypair::generate();
        let dkp_new = DiscoKeypair::generate();
        let new_client = TestSignedClient {
            router: &router,
            conn_ctx: &conn_ctx,
            node_kp: &kp_new,
            disco_kp: &dkp_new,
            now_ms: now_ms + 100,
        };
        let rotated = sign_register_node(
            &new_client,
            &bound_raw,
            "rot-node",
            Some(kp_old.public_key()),
        )
        .await;

        // Assert: same node_id kept, old key revoked in RAM, old streams cancelled, old key rejected
        assert_eq!(rotated.node_id, first.node_id);
        assert!(sub_old.cancel.is_cancelled());
        assert!(relay_old.cancel.is_cancelled());
        assert!(state.store.is_pubkey_revoked_ram(&kp_old.public_key()));

        let ep_body = serde_json::to_vec(&UpdateEndpointsRequest {
            endpoints: Vec::new(),
            nat_type: mesh_proto::netmap::NatMappingKind::Unknown,
            acked_endpoint_version: 0,
        })
        .expect("ep");
        let (old_st, _) = send_signed_post(&old_client, "/v1/endpoints", ep_body, 200).await;
        assert_eq!(old_st, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_endpoints_filtered_and_call_me_maybe_rejects_spoofed_sender_or_inactive_dst() {
        // Arrange: register two active nodes
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (state, raw_token) = test_state(&dir, now_ms);
        let router = build_control_router(state.clone());
        let conn_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.44:50000".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x55_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };
        let kp_a = NodeKeypair::generate();
        let dkp_a = DiscoKeypair::generate();
        let client_a = TestSignedClient {
            router: &router,
            conn_ctx: &conn_ctx,
            node_kp: &kp_a,
            disco_kp: &dkp_a,
            now_ms,
        };
        let node_a = sign_register_node(&client_a, &raw_token, "peer-a", None).await;

        let raw_b = "mpk_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned();
        state
            .store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms + 1),
                    token_hash: sha256_digest(raw_b.as_bytes()),
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: None,
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .expect("key b");
        let kp_b = NodeKeypair::generate();
        let dkp_b = DiscoKeypair::generate();
        let client_b = TestSignedClient {
            router: &router,
            conn_ctx: &conn_ctx,
            node_kp: &kp_b,
            disco_kp: &dkp_b,
            now_ms,
        };
        let node_b = sign_register_node(&client_b, &raw_b, "peer-b", None).await;

        // Act 1: endpoints include loopback, overlay CIDR, STUN server, plus 20 valid candidates
        let stun_ep_str = format!("203.0.113.10:{}", state.config.stun_udp_port);
        let mut candidates = vec![
            CandidateEndpoint {
                addr: "127.0.0.1:51820".parse().expect("lo"),
                source: mesh_proto::netmap::CandidateSource::Lan,
            },
            CandidateEndpoint {
                addr: "10.100.0.5:51820".parse().expect("overlay"),
                source: mesh_proto::netmap::CandidateSource::Lan,
            },
            CandidateEndpoint {
                addr: stun_ep_str.parse().expect("stun"),
                source: mesh_proto::netmap::CandidateSource::Reflexive,
            },
        ];
        for i in 1_u8..=20 {
            candidates.push(CandidateEndpoint {
                addr: format!("198.51.100.{i}:51820").parse().expect("pub"),
                source: mesh_proto::netmap::CandidateSource::Reflexive,
            });
        }
        let ep_body = serde_json::to_vec(&UpdateEndpointsRequest {
            endpoints: candidates,
            nat_type: mesh_proto::netmap::NatMappingKind::EimOrAdm,
            acked_endpoint_version: 0,
        })
        .expect("ep body");
        let (ep_st, _) = send_signed_post(&client_a, "/v1/endpoints", ep_body, 10).await;
        assert_eq!(ep_st, StatusCode::OK);
        let stored_a = state
            .store
            .find_node_by_id(node_a.node_id)
            .expect("find")
            .expect("present");
        assert_eq!(stored_a.endpoints.len(), 16);
        assert!(
            stored_a
                .endpoints
                .iter()
                .all(|e| !e.addr.ip().is_loopback() && e.addr.to_string() != stun_ep_str)
        );

        // Act 2: forged outer sender Disco pubkey is rejected
        let mut sub_b = state.netmap_hub.subscribe(node_b.node_id, now_ms);
        let forged_dkp = DiscoKeypair::generate();
        let forged_pkt = mesh_crypto::seal_disco_packet(
            &forged_dkp,
            &mesh_crypto::disco_box::DiscoSealParams {
                recipient_pubkey: dkp_b.public_key(),
                msg_type: 0x03,
                tx_id: [1_u8; 12],
                sent_at_ms: now_ms,
                body: b"",
            },
        )
        .expect("seal forged");
        let forged_req = serde_json::to_vec(&CallMeMaybeRequest {
            dst_node_id: node_b.node_id,
            disco_frame_b64: BASE64_STANDARD.encode(&forged_pkt),
        })
        .expect("req");
        let (forged_st, _) =
            send_signed_post(&client_a, "/v1/disco/call-me-maybe", forged_req, 20).await;
        assert_eq!(forged_st, StatusCode::BAD_REQUEST);
        assert!(sub_b.rx.try_recv().is_err());

        // Act 3: unknown destination node rejected with 404
        let valid_pkt = mesh_crypto::seal_disco_packet(
            &dkp_a,
            &mesh_crypto::disco_box::DiscoSealParams {
                recipient_pubkey: dkp_b.public_key(),
                msg_type: 0x03,
                tx_id: [2_u8; 12],
                sent_at_ms: now_ms,
                body: b"",
            },
        )
        .expect("seal valid");
        let unknown_req = serde_json::to_vec(&CallMeMaybeRequest {
            dst_node_id: NodeId::new_v7(now_ms + 999),
            disco_frame_b64: BASE64_STANDARD.encode(&valid_pkt),
        })
        .expect("unknown");
        let (unk_st, _) =
            send_signed_post(&client_a, "/v1/disco/call-me-maybe", unknown_req, 30).await;
        assert_eq!(unk_st, StatusCode::NOT_FOUND);

        // Act 4: valid CallMeMaybe targeting active peer succeeds and is relayed
        let ok_req = serde_json::to_vec(&CallMeMaybeRequest {
            dst_node_id: node_b.node_id,
            disco_frame_b64: BASE64_STANDARD.encode(&valid_pkt),
        })
        .expect("ok req");
        let (ok_st, _) = send_signed_post(&client_a, "/v1/disco/call-me-maybe", ok_req, 40).await;
        assert_eq!(ok_st, StatusCode::NO_CONTENT);
        assert!(matches!(
            sub_b.rx.try_recv(),
            Ok(ServerControlFrame::CallMeMaybeRelay { .. })
        ));
    }

    #[tokio::test]
    async fn test_control_protocol_n_minus_1_revoked_expired_status_and_lockout_audit() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (mut state, raw_token) = test_state(&dir, now_ms);
        let mut cfg_updated = (*state.config).clone();
        cfg_updated.min_protocol_version = 2;
        state.config = Arc::new(cfg_updated);
        let router = build_control_router(state.clone());
        let conn_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.77:44444".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x77_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };

        // Act 1: N-2 client rejected with explicit agent upgrade required message (`US-050 AC2`)
        let old_proto_kp = NodeKeypair::generate();
        let old_proto_dkp = DiscoKeypair::generate();
        let old_proto_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .body(Body::from(
                serde_json::to_vec(&ChallengeRequest {
                    node_pubkey: old_proto_kp.public_key(),
                    disco_pubkey: old_proto_dkp.public_key(),
                    protocol_version: 1,
                    agent_version: "0.0.1".to_owned(),
                    os: TargetOs::Linux,
                    arch: TargetArch::Amd64,
                })
                .expect("json"),
            ))
            .expect("req");
        let (st, raw_body) = send_router_req(router.clone(), conn_ctx.clone(), old_proto_req).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let err_json: ErrorResponse = serde_json::from_slice(&raw_body).expect("err json");
        assert!(err_json.error.message.contains("agent upgrade required"));

        // Lower min_protocol_version back to 1 for authenticated node checks
        let mut cfg_v1 = (*state.config).clone();
        cfg_v1.min_protocol_version = 1;
        state.config = Arc::new(cfg_v1);
        let router = build_control_router(state.clone());

        let kp = NodeKeypair::generate();
        let dkp = DiscoKeypair::generate();
        let client = TestSignedClient {
            router: &router,
            conn_ctx: &conn_ctx,
            node_kp: &kp,
            disco_kp: &dkp,
            now_ms,
        };
        let node = sign_register_node(&client, &raw_token, "exp-node", None).await;

        // Act 2: Expired node returns 403 NodeKeyExpired over verified TLS channel (`US-031 AC4`)
        state
            .store
            .expire_node(node.node_id, "admin")
            .expect("expire node");
        let ep_body = serde_json::to_vec(&UpdateEndpointsRequest {
            endpoints: Vec::new(),
            nat_type: mesh_proto::netmap::NatMappingKind::Unknown,
            acked_endpoint_version: 0,
        })
        .expect("ep");
        let (exp_st, exp_raw) =
            send_signed_post(&client, "/v1/endpoints", ep_body.clone(), 5).await;
        assert_eq!(exp_st, StatusCode::FORBIDDEN);
        let exp_err: ErrorResponse = serde_json::from_slice(&exp_raw).expect("err json");
        assert_eq!(exp_err.error.kind, ErrorKind::NodeKeyExpired);

        // Act 3: Revoked node returns 403 NodeRevoked over verified TLS channel (`US-029`)
        state
            .store
            .revoke_node(node.node_id, "admin")
            .expect("revoke node");
        let (rev_st, rev_raw) = send_signed_post(&client, "/v1/endpoints", ep_body, 6).await;
        assert_eq!(rev_st, StatusCode::FORBIDDEN);
        let rev_err: ErrorResponse = serde_json::from_slice(&rev_raw).expect("err json");
        assert_eq!(rev_err.error.kind, ErrorKind::NodeRevoked);

        // Act 4: 10 bad auth proofs trigger IP lockout (429 + Retry-After + audit row, `US-042`)
        let attacker_ctx = ConnectionTlsContext {
            peer_addr: "203.0.113.199:55555".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x88_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };
        for _ in 0..10 {
            let bad_req = Request::builder()
                .method(Method::POST)
                .uri("/v1/nodes/register")
                .body(Body::from(b"{}".to_vec()))
                .expect("req");
            let (bad_st, _) = send_router_req(router.clone(), attacker_ctx.clone(), bad_req).await;
            assert_eq!(bad_st, StatusCode::UNAUTHORIZED);
        }
        let locked_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .body(Body::from(b"{}".to_vec()))
            .expect("req");
        let (locked_st, locked_hdrs, _) =
            send_router_req_with_headers(router.clone(), attacker_ctx, locked_req).await;
        assert_eq!(locked_st, StatusCode::TOO_MANY_REQUESTS);
        assert!(locked_hdrs.contains_key("retry-after"));
        let audits = state
            .store
            .list_audit_events(&mesh_store::AuditQuery {
                limit: 50,
                ..Default::default()
            })
            .expect("audits");
        assert!(audits.iter().any(|a| a.action == "rate_limit_ip_locked"));
    }

    #[tokio::test]
    async fn test_valid_proof_with_invalid_preauth_or_unknown_pubkey_triggers_ip_lockout() {
        // Arrange (`HR-W21-03`)
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (state, _) = test_state(&dir, now_ms);
        let router = build_control_router(state.clone());

        // Part A: valid SalsaBox proof + invalid preauth_key on /v1/nodes/register must NOT reset failures
        let kp_a = NodeKeypair::generate();
        let dkp_a = DiscoKeypair::generate();
        let reg_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.201:40000".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x91_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };
        let reg_client = TestSignedClient {
            router: &router,
            conn_ctx: &reg_ctx,
            node_kp: &kp_a,
            disco_kp: &dkp_a,
            now_ms,
        };
        let bad_reg_body = serde_json::to_vec(&RegisterNodeRequest {
            node_pubkey: kp_a.public_key(),
            disco_pubkey: dkp_a.public_key(),
            preauth_key: "mpk_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".to_owned(),
            node_name: NodeName::parse("rogue-reg").expect("name"),
            previous_node_pubkey: None,
        })
        .expect("bad reg body");
        for i in 0..10_u64 {
            let (st, _) =
                send_signed_post(&reg_client, "/v1/nodes/register", bad_reg_body.clone(), i).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
        }
        let reg_locked = Request::builder()
            .method(Method::POST)
            .uri("/v1/auth/challenge")
            .body(Body::from(b"{}".to_vec()))
            .expect("req");
        let (reg_11_st, reg_11_hdrs, _) =
            send_router_req_with_headers(router.clone(), reg_ctx, reg_locked).await;
        assert_eq!(reg_11_st, StatusCode::TOO_MANY_REQUESTS);
        assert!(reg_11_hdrs.contains_key("retry-after"));

        // Part B: valid SalsaBox proof for unregistered pubkey on /v1/endpoints locks IP after 10 failures
        let kp_b = NodeKeypair::generate();
        let dkp_b = DiscoKeypair::generate();
        let unk_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.202:40001".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x92_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };
        let unk_client = TestSignedClient {
            router: &router,
            conn_ctx: &unk_ctx,
            node_kp: &kp_b,
            disco_kp: &dkp_b,
            now_ms,
        };
        let ep_body = serde_json::to_vec(&UpdateEndpointsRequest {
            endpoints: Vec::new(),
            nat_type: mesh_proto::netmap::NatMappingKind::Unknown,
            acked_endpoint_version: 0,
        })
        .expect("ep body");
        for i in 0..10_u64 {
            let (st, _) = send_signed_post(&unk_client, "/v1/endpoints", ep_body.clone(), i).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
        }
        let locked_ep_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/endpoints")
            .body(Body::from(ep_body))
            .expect("ep11 req");
        let (ep_11_st, ep_11_hdrs, _) =
            send_router_req_with_headers(router, unk_ctx, locked_ep_req).await;
        assert_eq!(ep_11_st, StatusCode::TOO_MANY_REQUESTS);
        assert!(ep_11_hdrs.contains_key("retry-after"));
    }

    #[tokio::test]
    async fn test_per_listener_tls_mode_overrides_boot_config_for_proof_and_rate_limiter() {
        // Arrange Direction 1 (`HR-W21-05`): server booted as IpPinned, connection accepted by ReverseProxy listener
        let dir1 = TempDir::new().expect("tempdir1");
        let now_ms = SystemClock::new().now_unix_ms();
        let (mut ip_boot_state, raw_token) = test_state(&dir1, now_ms);
        let proxy_ip: std::net::IpAddr = "127.0.0.10".parse().expect("proxy ip");
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(proxy_ip);
        let mut cfg1 = (*ip_boot_state.config).clone();
        cfg1.tls_mode = crate::config::TlsMode::IpPinned;
        cfg1.trusted_proxies = vec![proxy_ip];
        ip_boot_state.config = Arc::new(cfg1);
        ip_boot_state.trusted_proxies = Arc::new(trusted.clone());
        ip_boot_state.rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            crate::config::TlsMode::IpPinned,
            trusted.clone(),
        )));
        let router1 = build_control_router(ip_boot_state);

        // ReverseProxy listener context (no TLS exporter) succeeds AND honors X-Forwarded-For per client IP
        let reverse_proxy_ctx = ConnectionTlsContext {
            peer_addr: std::net::SocketAddr::new(proxy_ip, 44444),
            tls_exporter_b64: None,
            listener_tls_mode: crate::config::TlsMode::ReverseProxy,
        };
        let kp_p = NodeKeypair::generate();
        let dkp_p = DiscoKeypair::generate();
        let ch_body = serde_json::to_vec(&ChallengeRequest {
            node_pubkey: kp_p.public_key(),
            disco_pubkey: dkp_p.public_key(),
            protocol_version: 1,
            agent_version: "0.1.0".to_owned(),
            os: TargetOs::Linux,
            arch: TargetArch::Amd64,
        })
        .expect("ch");
        let (st_ch, b_ch) = send_router_req(
            router1.clone(),
            reverse_proxy_ctx.clone(),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/challenge")
                .header("x-forwarded-for", "203.0.113.55")
                .body(Body::from(ch_body.clone()))
                .expect("ch req"),
        )
        .await;
        assert_eq!(st_ch, StatusCode::OK);
        let ch: ChallengeResponse = serde_json::from_slice(&b_ch).expect("ch json");
        let reg_body = serde_json::to_vec(&RegisterNodeRequest {
            node_pubkey: kp_p.public_key(),
            disco_pubkey: dkp_p.public_key(),
            preauth_key: raw_token,
            node_name: NodeName::parse("proxy-listener-node").expect("name"),
            previous_node_pubkey: None,
        })
        .expect("reg");
        let proof = ProofPayload {
            challenge_id: ch.challenge_id,
            challenge_nonce: ch.challenge_nonce,
            method: "POST".to_owned(),
            path: "/v1/nodes/register".to_owned(),
            body_sha256: sha256_hex(&reg_body),
            node_pubkey: kp_p.public_key(),
            disco_pubkey: dkp_p.public_key(),
            timestamp_at_ms: now_ms,
            tls_exporter_binding: String::new(),
        };
        let sealed = seal_proof(&proof, &ch.server_eph_pubkey, &kp_p).expect("seal");
        let (ok_reg, _) = send_router_req(
            router1.clone(),
            reverse_proxy_ctx.clone(),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/nodes/register")
                .header("x-forwarded-for", "203.0.113.55")
                .header(HEADER_CHALLENGE_ID, ch.challenge_id.to_string())
                .header(
                    HEADER_NODE_PUBKEY,
                    BASE64_STANDARD.encode(kp_p.public_key().as_bytes()),
                )
                .header(HEADER_BOX_NONCE, BASE64_STANDARD.encode(sealed.box_nonce))
                .header(
                    HEADER_AUTH_PROOF,
                    BASE64_STANDARD.encode(&sealed.ciphertext),
                )
                .body(Body::from(reg_body))
                .expect("reg req"),
        )
        .await;
        assert_eq!(ok_reg, StatusCode::OK);

        // Lock out XFF IP `203.0.113.55` without affecting another client IP behind the same proxy
        for _ in 0..10 {
            let (bad_st, _) = send_router_req(
                router1.clone(),
                reverse_proxy_ctx.clone(),
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/nodes/register")
                    .header("x-forwarded-for", "203.0.113.55")
                    .body(Body::from(b"{}".to_vec()))
                    .expect("bad"),
            )
            .await;
            assert_eq!(bad_st, StatusCode::UNAUTHORIZED);
        }
        let (locked_xff_st, _) = send_router_req(
            router1.clone(),
            reverse_proxy_ctx.clone(),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/challenge")
                .header("x-forwarded-for", "203.0.113.55")
                .body(Body::from(ch_body.clone()))
                .expect("locked"),
        )
        .await;
        assert_eq!(locked_xff_st, StatusCode::TOO_MANY_REQUESTS);
        let (other_xff_st, _) = send_router_req(
            router1,
            reverse_proxy_ctx,
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/challenge")
                .header("x-forwarded-for", "203.0.113.56")
                .body(Body::from(ch_body.clone()))
                .expect("other"),
        )
        .await;
        assert_eq!(other_xff_st, StatusCode::OK);

        // Arrange Direction 2 (`HR-W21-05`): server booted as ReverseProxy, connection accepted by IpPinned listener
        let dir2 = TempDir::new().expect("tempdir2");
        let (mut proxy_boot_state, _) = test_state(&dir2, now_ms);
        let mut cfg2 = (*proxy_boot_state.config).clone();
        cfg2.tls_mode = crate::config::TlsMode::ReverseProxy;
        cfg2.trusted_proxies = vec![proxy_ip];
        proxy_boot_state.config = Arc::new(cfg2);
        proxy_boot_state.trusted_proxies = Arc::new(trusted.clone());
        proxy_boot_state.rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            crate::config::TlsMode::ReverseProxy,
            trusted,
        )));
        let router2 = build_control_router(proxy_boot_state);

        let ip_pinned_ctx = ConnectionTlsContext {
            peer_addr: std::net::SocketAddr::new(proxy_ip, 55555),
            tls_exporter_b64: None,
            listener_tls_mode: crate::config::TlsMode::IpPinned,
        };
        for _ in 0..10 {
            let (st, _) = send_router_req(
                router2.clone(),
                ip_pinned_ctx.clone(),
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/nodes/register")
                    .header("x-forwarded-for", "203.0.113.88")
                    .body(Body::from(b"{}".to_vec()))
                    .expect("bad pinned"),
            )
            .await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
        }
        // IpPinned listener ignores XFF and enforces lockout on peer_addr (`127.0.0.10`), not exempting proxy!
        let (pinned_locked_st, _) = send_router_req(
            router2,
            ip_pinned_ctx,
            Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/challenge")
                .header("x-forwarded-for", "203.0.113.89")
                .body(Body::from(ch_body))
                .expect("pinned locked"),
        )
        .await;
        assert_eq!(pinned_locked_st, StatusCode::TOO_MANY_REQUESTS);
    }

    fn alloc_loopback_tcp_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral tcp");
        probe.local_addr().expect("tcp local addr").port()
    }

    fn alloc_loopback_udp_port() -> u16 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp");
        probe.local_addr().expect("udp local addr").port()
    }

    #[tokio::test]
    async fn test_register_node_rejects_live_migrated_public_host() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (mut state, raw_token) = test_state(&dir, now_ms);
        let mut cfg = (*state.config).clone();
        cfg.control_bind_ip = "127.0.0.1".to_owned();
        cfg.control_tcp_port = alloc_loopback_tcp_port();
        cfg.stun_bind_ip = "127.0.0.1".to_owned();
        cfg.stun_udp_port = alloc_loopback_udp_port();
        cfg.public_host = "boot-vps".to_owned();
        let cfg = Arc::new(cfg);
        state.config = Arc::clone(&cfg);
        state.netmap_hub = Arc::new(NetmapHub::new(
            state.store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let acme =
            crate::acme::AcmeManager::initialize(&cfg, state.store.clone()).expect("init acme");
        let router = build_control_router(state.clone());
        let listeners = crate::listener_set::ListenerSet::bind_and_start(state.clone(), acme)
            .await
            .expect("bind listeners");

        // Act: live endpoint migration shifts `public_host` from `boot-vps` to `migrated-vps`
        let next_tcp = mesh_core::Port::from_u16(alloc_loopback_tcp_port()).expect("valid port");
        let migrated = listeners
            .migrate_endpoints(
                &mesh_proto::admin_ipc::MigrateEndpointRequest {
                    host: Some("migrated-vps".to_owned()),
                    tcp_port: Some(next_tcp),
                    stun_port: None,
                    tls_mode: None,
                    transition_window_secs: Some(30),
                    extend_window_secs: None,
                },
                "admin",
            )
            .await
            .expect("migrate endpoints");
        assert!(migrated.control_tcp_endpoint.starts_with("migrated-vps:"));
        assert_eq!(listeners.active_public_host(), "migrated-vps");

        let node_kp = NodeKeypair::generate();
        let disco_kp = DiscoKeypair::generate();
        let conn_ctx = ConnectionTlsContext {
            peer_addr: "127.0.0.1:41000".parse().expect("peer addr"),
            tls_exporter_b64: Some("exporter-migrated-host".to_owned()),
            listener_tls_mode: TlsMode::IpPinned,
        };
        let client = TestSignedClient {
            router: &router,
            conn_ctx: &conn_ctx,
            node_kp: &node_kp,
            disco_kp: &disco_kp,
            now_ms,
        };
        let body = serde_json::to_vec(&RegisterNodeRequest {
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            preauth_key: raw_token,
            node_name: NodeName::parse("migrated-vps").expect("node name"),
            previous_node_pubkey: None,
        })
        .expect("reg body");
        let (st, resp_bytes) = send_signed_post(&client, "/v1/nodes/register", body, 0).await;

        // Assert
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let text = String::from_utf8(resp_bytes).expect("utf8");
        assert!(text.contains("collides with control server public host"));
        state.shutdown.cancel();
        state.ws_tracker.close();
        state.ws_tracker.wait().await;
    }

    #[tokio::test]
    async fn test_control_registers_android_ios_and_linux_preserving_redb_v1() {
        // Arrange
        assert_eq!(os_label(TargetOs::Android), "android");
        assert_eq!(os_label(TargetOs::Ios), "ios");
        assert_eq!(mesh_store::SCHEMA_VERSION, 1);

        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let (state, _single_token) = test_state(&dir, now_ms);
        let router = build_control_router(state.clone());
        let reusable_raw = "mpk_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned();
        state
            .store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms + 1),
                    token_hash: sha256_digest(reusable_raw.as_bytes()),
                    label: Some("mobile-compat".to_owned()),
                    bound_node_name: None,
                    reusable: true,
                    max_uses: Some(4),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .expect("mint reusable key");

        let conn_ctx = ConnectionTlsContext {
            peer_addr: "198.51.100.77:51000".parse().expect("addr"),
            tls_exporter_b64: Some(BASE64_STANDARD.encode([0x55_u8; 32])),
            listener_tls_mode: TlsMode::IpPinned,
        };

        // Act: Register one Android node, one iOS node, and one legacy Linux v0.1.0-rc1 node
        for (idx, (os, arch, name)) in [
            (TargetOs::Android, TargetArch::Arm64, "pixel-mobile"),
            (TargetOs::Ios, TargetArch::Arm64, "iphone-mobile"),
            (TargetOs::Linux, TargetArch::Amd64, "legacy-linux"),
        ]
        .into_iter()
        .enumerate()
        {
            let node_kp = NodeKeypair::generate();
            let disco_kp = DiscoKeypair::generate();
            let ch_body = serde_json::to_vec(&ChallengeRequest {
                node_pubkey: node_kp.public_key(),
                disco_pubkey: disco_kp.public_key(),
                protocol_version: 1,
                agent_version: "0.2.0".to_owned(),
                os,
                arch,
            })
            .expect("ch body");
            let ch_req = Request::builder()
                .method(Method::POST)
                .uri("/v1/auth/challenge")
                .header("content-type", "application/json")
                .body(Body::from(ch_body))
                .expect("ch req");
            let (ch_status, ch_bytes) =
                send_router_req(router.clone(), conn_ctx.clone(), ch_req).await;
            assert_eq!(ch_status, StatusCode::OK);
            let ch: ChallengeResponse = serde_json::from_slice(&ch_bytes).expect("ch");

            let reg_body = serde_json::to_vec(&RegisterNodeRequest {
                node_pubkey: node_kp.public_key(),
                disco_pubkey: disco_kp.public_key(),
                preauth_key: reusable_raw.clone(),
                node_name: NodeName::parse(name).expect("name"),
                previous_node_pubkey: None,
            })
            .expect("reg body");
            let proof = ProofPayload {
                challenge_id: ch.challenge_id,
                challenge_nonce: ch.challenge_nonce,
                method: "POST".to_owned(),
                path: "/v1/nodes/register".to_owned(),
                body_sha256: sha256_hex(&reg_body),
                node_pubkey: node_kp.public_key(),
                disco_pubkey: disco_kp.public_key(),
                timestamp_at_ms: now_ms + u64::try_from(idx).unwrap_or(0),
                tls_exporter_binding: BASE64_STANDARD.encode([0x55_u8; 32]),
            };
            let sealed = seal_proof(&proof, &ch.server_eph_pubkey, &node_kp).expect("seal");
            let reg_req = Request::builder()
                .method(Method::POST)
                .uri("/v1/nodes/register")
                .header(HEADER_CHALLENGE_ID, ch.challenge_id.to_string())
                .header(
                    HEADER_NODE_PUBKEY,
                    BASE64_STANDARD.encode(node_kp.public_key().as_bytes()),
                )
                .header(HEADER_BOX_NONCE, BASE64_STANDARD.encode(sealed.box_nonce))
                .header(
                    HEADER_AUTH_PROOF,
                    BASE64_STANDARD.encode(&sealed.ciphertext),
                )
                .body(Body::from(reg_body))
                .expect("reg req");
            let (reg_status, reg_bytes) =
                send_router_req(router.clone(), conn_ctx.clone(), reg_req).await;
            assert_eq!(reg_status, StatusCode::OK);
            let reg_resp: RegisterNodeResponse =
                serde_json::from_slice(&reg_bytes).expect("decode reg");
            assert_eq!(reg_resp.netmap.peers.len(), idx + 1);
        }

        // Assert: Verify redb SCHEMA_VERSION = 1 store preserves all 3 os_arch triplets cleanly
        let stored_nodes = state.store.list_nodes().expect("list nodes");
        assert_eq!(stored_nodes.len(), 3);
        let os_arch_values: Vec<String> = stored_nodes.into_iter().map(|n| n.os_arch).collect();
        assert!(os_arch_values.contains(&"android/arm64".to_owned()));
        assert!(os_arch_values.contains(&"ios/arm64".to_owned()));
        assert!(os_arch_values.contains(&"linux/amd64".to_owned()));

        drop(router);
        drop(state);
        let reopened = ControlStore::open_with_clock(
            ControlStoreConfig {
                db_path: dir.path().join("control.redb"),
                emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
            },
            "10.100.0.0/24",
            Arc::new(FakeClock::new(now_ms + 1_000)),
        )
        .expect("reopen SCHEMA_VERSION=1 store");
        assert_eq!(reopened.list_nodes().expect("reopened list").len(), 3);
    }
}
