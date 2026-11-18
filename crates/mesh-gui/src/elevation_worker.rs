//! Dual-mode CLI dispatch (`--minimized` vs `--elevated-worker --pipe`), UAC `MGH1` server
//! handoff, worker execution, anti-TOCTOU `wintun.dll` SHA-256 verification, SCM install/update/
//! uninstall, and non-buffered 100%-safe HTTP/1.1 streaming bugreport export (`US-104`,
//! `US-106`, `US-107`, `ADR-020`, `ADR-021`, `ADR-023`, `ADR-026`).

use std::fs;
#[cfg(target_os = "windows")]
use std::fs::File;
#[cfg(target_os = "windows")]
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use hyper::Method;
#[cfg(target_os = "windows")]
use mesh_core::SpkiPin;
#[cfg(target_os = "windows")]
use mesh_core::defaults::{
    MAX_ADMIN_IPC_BODY_BYTES, WINDOWS_AGENT_ADMIN_PIPE, WINDOWS_AGENT_RO_PIPE,
};
#[cfg(target_os = "windows")]
use mesh_core::error::ErrorResponse;
#[cfg(target_os = "windows")]
use mesh_core::{AppError, AppResult};
use mesh_crypto::verify_file_sha256;
use mesh_net::gui_handoff::validate_handoff_pipe_name;
#[cfg(target_os = "windows")]
use mesh_net::gui_handoff::{
    HANDOFF_PIPE_CONNECT_TIMEOUT, HANDOFF_UAC_WAIT_TIMEOUT, HANDOFF_WORKER_HELLO_TIMEOUT,
    HandoffFrame, HandoffRequest, HandoffResponse, HandoffStreamHeaderPayload, MGH1_HEADER_LEN,
    MGH1_MAX_BUGREPORT_CHUNK_BYTES, decode_mgh1_frame, decode_mgh1_header, encode_mgh1_frame,
    generate_handoff_pipe_name, handoff_request_to_agent_rotate_key, handoff_request_to_agent_up,
    parse_handoff_request_payload, zeroize_handoff_payload,
};
#[cfg(target_os = "windows")]
use mesh_net::ipc::{
    HEADER_MESH_ARCHIVE_BYTES, HEADER_MESH_SCRUBBED_ITEMS, IPC_ADMIN_MUTATION_TIMEOUT,
    IPC_RO_QUERY_TIMEOUT, IPC_STREAM_CHUNK_IDLE_TIMEOUT, connect_agent_named_pipe,
    send_ipc_json_request_with_timeout,
};
#[cfg(target_os = "windows")]
use mesh_net::ledger::ResourceLedger;
#[cfg(target_os = "windows")]
use mesh_net::route_windows::WindowsCleanupOps;
#[cfg(target_os = "windows")]
use mesh_proto::agent_ipc::{
    AgentActionResponse, AgentResetIdentityRequest, AgentSetRequest, DaemonState,
};
#[cfg(target_os = "windows")]
use mesh_sys::gui_windows::{
    HandoffPipeClient, HandoffPipeServer, UnprivilegedSinkWriter, WINDOWS_SERVICE_NAME,
    ensure_and_start_windows_service, get_process_id, is_current_process_elevated,
    is_uac_cancelled_error, launch_elevated_worker, open_anti_toctou_read_locked,
    schedule_delete_on_reboot, set_directory_sddl_acl, stop_and_optionally_delete_windows_service,
};
#[cfg(target_os = "windows")]
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt as _, BufReader};
#[cfg(target_os = "windows")]
use zeroize::Zeroizing;

#[cfg(target_os = "windows")]
const ADMIN_DATA_DIR: &str = r"C:\ProgramData\Mesh";

#[cfg(any(target_os = "windows", test))]
pub(crate) const PROGRAM_DATA_DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

#[cfg(any(target_os = "windows", test))]
pub(crate) const INSTALL_DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)";

#[cfg(target_os = "windows")]
const MAX_HTTP_HEADER_BLOCK_BYTES: usize = 8 * 1024;

#[cfg(any(target_os = "windows", test))]
pub(crate) const WINDOWS_BUNDLE_REMOVAL_LIST: &[&str] = &[
    "MeshVPN.exe",
    "MeshVPN.exe.new",
    "meshd.exe",
    "mesh.exe",
    "mesh-server.exe",
    "wintun.dll",
    "wintun.dll.sha256",
    "WINTUN-LICENSE.txt",
    "README-WINTUN.md",
    "LICENSE",
    "NOTICE",
    "README.txt",
];

#[cfg(target_os = "windows")]
const PROGRAM_DATA_PURGE_FILES: &[&str] = &[
    "keys.json",
    "bootstrap.toml",
    "ledger.json",
    "netmap-cache.json",
    "meshd-state.redb",
];

#[cfg(target_os = "windows")]
const PROGRAM_DATA_EPHEMERAL_FILES: &[&str] = &["ledger.json", "netmap-cache.json"];

/// Normalizes two Windows filesystem paths (resolving symlinks if present, stripping `\\?\`,
/// normalizing separators, and ignoring ASCII case) so self-copy checks never fail on casing or
/// trailing slashes (`HR-DGUI-G3-02`).
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn windows_paths_equivalent(lhs: &Path, rhs: &Path) -> bool {
    fn norm(path: &Path) -> String {
        let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let text = resolved.to_string_lossy().replace('/', r"\");
        let stripped = text.strip_prefix(r"\\?\").unwrap_or(&text);
        stripped.trim_end_matches('\\').to_ascii_lowercase()
    }
    norm(lhs) == norm(rhs)
}

/// Returns `true` when replacing a running `MeshVPN.exe` failed due to Windows file locking
/// (`ERROR_ACCESS_DENIED (5)` | `ERROR_SHARING_VIOLATION (32)`), using `raw_os_error()` first
/// with a textual fallback (`HR-DGUI-G3-02`).
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn is_locked_binary_replace_error(raw_os_error: Option<i32>, err_msg: &str) -> bool {
    if matches!(raw_os_error, Some(5 | 32)) {
        return true;
    }
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("sharing violation")
        || lower.contains("access is denied")
        || lower.contains("os error 5")
        || lower.contains("os error 32")
}

/// Parsed `MeshVPN.exe` invocation mode (`--minimized` vs `--elevated-worker --pipe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GuiLaunchMode {
    Normal { start_minimized: bool },
    ElevatedWorker { handoff_pipe: String },
}

/// Parses and strictly validates `MeshVPN.exe` process arguments (`ADR-020`, `ADR-021`).
pub(crate) fn parse_gui_launch_args<I>(args: I) -> Result<GuiLaunchMode, String>
where
    I: IntoIterator<Item = String>,
{
    let mut start_minimized = false;
    let mut elevated_worker = false;
    let mut pipe_name: Option<String> = None;

    let mut iter = args.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--minimized" => start_minimized = true,
            "--elevated-worker" => elevated_worker = true,
            "--pipe" | "--handoff-pipe" => {
                let value = iter
                    .next()
                    .ok_or_else(|| format!("missing pipe name after `{arg}`"))?;
                if pipe_name.is_some() {
                    return Err("duplicate `--pipe` argument".to_owned());
                }
                pipe_name = Some(value);
            }
            other => return Err(format!("unsupported argument `{other}`")),
        }
    }

    if elevated_worker {
        if start_minimized {
            return Err("`--minimized` cannot be combined with `--elevated-worker`".to_owned());
        }
        let pipe = pipe_name.ok_or_else(|| "`--elevated-worker` requires `--pipe`".to_owned())?;
        validate_handoff_pipe_name(&pipe).map_err(|err| err.to_string())?;
        return Ok(GuiLaunchMode::ElevatedWorker { handoff_pipe: pipe });
    }

    if pipe_name.is_some() {
        return Err("`--pipe` requires `--elevated-worker`".to_owned());
    }

    Ok(GuiLaunchMode::Normal { start_minimized })
}

/// Parses a `wintun.dll.sha256` sidecar file (`<64_hex>` or `<64_hex>  wintun.dll`).
pub(crate) fn parse_sha256_sidecar_hex(contents: &str) -> Result<String, String> {
    let token = contents
        .split_whitespace()
        .next()
        .ok_or_else(|| "empty wintun.dll.sha256 sidecar".to_owned())?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid 64-hex SHA-256 digest in wintun.dll.sha256".to_owned());
    }
    Ok(token.to_ascii_lowercase())
}

/// Verifies `wintun.dll` SHA-256 on disk against `expected_sha256_hex` (`ADR-026`).
pub(crate) fn verify_wintun_path_sha256(
    path: &Path,
    expected_sha256_hex: &str,
) -> Result<(), String> {
    verify_file_sha256(path, expected_sha256_hex)
        .map(|_digest| ())
        .map_err(|err| err.to_string())
}

/// Resolves the expected SHA-256 hex digest for `wintun.dll`:
/// - Fresh install/upgrade (`allow_sidecar_fallback == false`): requires `compile_time_pin`
///   (`option_env!("MESH_WINTUN_SHA256")`), rejecting any spoofed untrusted sidecar that disagrees.
/// - Start existing already-installed service (`allow_sidecar_fallback == true`): accepts
///   `compile_time_pin`, or falls back to admin-protected `%ProgramFiles%\Mesh\wintun.dll.sha256`.
pub(crate) fn resolve_expected_wintun_sha256(
    compile_time_pin: Option<&str>,
    sidecar_path: &Path,
    allow_sidecar_fallback: bool,
) -> Result<String, String> {
    let sidecar_hex = match fs::read_to_string(sidecar_path) {
        Ok(raw) => Some(parse_sha256_sidecar_hex(&raw)?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(format!("failed reading {}: {err}", sidecar_path.display())),
    };

    if let Some(pin) = compile_time_pin.map(str::trim).filter(|s| !s.is_empty()) {
        let parsed_pin = parse_sha256_sidecar_hex(pin)?;
        if let Some(sidecar) = &sidecar_hex
            && !mesh_crypto::ct_eq_bytes(parsed_pin.as_bytes(), sidecar.as_bytes())
        {
            return Err(
                "wintun.dll.sha256 disagrees with compile-time MESH_WINTUN_SHA256".to_owned(),
            );
        }
        return Ok(parsed_pin);
    }

    if allow_sidecar_fallback && let Some(sidecar) = sidecar_hex {
        return Ok(sidecar);
    }

    Err(
        "wintun.dll integrity verification blocked: MESH_WINTUN_SHA256 digest unavailable"
            .to_owned(),
    )
}

/// Default `%ProgramFiles%\Mesh` installation directory helper.
#[must_use]
pub(crate) fn resolve_program_files_mesh_dir(program_files_env: Option<&Path>) -> PathBuf {
    let base = program_files_env
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(r"C:\Program Files"));
    base.join("Mesh")
}

/// Runs the unprivileged GUI-side handoff for an `HandoffRequest` command payload (`ADR-020`).
/// Executes directly in-process if already running elevated, avoiding redundant UAC prompts.
#[cfg(target_os = "windows")]
pub(crate) fn run_privileged_handoff(
    mut payload: Zeroizing<Vec<u8>>,
) -> Result<HandoffResponse, String> {
    if is_current_process_elevated().unwrap_or(false) {
        let req = parse_handoff_request_payload(payload.as_slice()).map_err(|e| e.to_string())?;
        zeroize_handoff_payload(&mut payload);
        return execute_request_direct_sync(&req);
    }

    let pipe_name = generate_handoff_pipe_name();
    let server = HandoffPipeServer::bind(&pipe_name).map_err(|err| err.to_string())?;
    let exe_path = std::env::current_exe().map_err(|err| err.to_string())?;
    let child_proc = match launch_elevated_worker(&exe_path, &pipe_name) {
        Ok(proc_handle) => proc_handle,
        Err(err) if is_uac_cancelled_error(&err) => {
            zeroize_handoff_payload(&mut payload);
            return Err("UAC prompt cancelled by user".to_owned());
        }
        Err(err) => {
            zeroize_handoff_payload(&mut payload);
            return Err(err.to_string());
        }
    };

    let child_pid = get_process_id(&child_proc).map_err(|err| err.to_string())?;
    let wait_ms = u32::try_from(HANDOFF_PIPE_CONNECT_TIMEOUT.as_millis()).unwrap_or(15_000);
    let _creds = server
        .accept_and_verify_worker_watching_process(&child_proc, child_pid, wait_ms)
        .map_err(|err| err.to_string())?;

    let frame = HandoffFrame::HandoffRequest(payload);
    let encoded = encode_mgh1_frame(&frame).map_err(|err| err.to_string())?;
    drop(frame);
    server
        .write_all_blocking(encoded.as_slice())
        .map_err(|err| err.to_string())?;
    drop(encoded);

    let uac_wait_ms = u32::try_from(HANDOFF_UAC_WAIT_TIMEOUT.as_millis()).unwrap_or(120_000);
    let response_frame = read_mgh1_frame_from_server(&server, uac_wait_ms)?;
    match response_frame {
        HandoffFrame::HandoffResponse(bytes) => {
            serde_json::from_slice::<HandoffResponse>(&bytes).map_err(|err| err.to_string())
        }
        other => Err(format!("unexpected MGH1 frame during action: {other:?}")),
    }
}

/// Runs the unprivileged GUI-side streamed bugreport handoff (`US-106`, `ADR-021`, `ADR-023`).
/// Never passes `dest_path` to the elevated worker; writes chunks exclusively unprivileged via
/// `UnprivilegedSinkWriter` Atomic `.part` Replace.
#[cfg(target_os = "windows")]
pub(crate) fn run_bugreport_stream_handoff(dest_path: &Path) -> Result<(u32, u64), String> {
    if is_current_process_elevated().unwrap_or(false) {
        return execute_direct_bugreport_export(dest_path);
    }

    let pipe_name = generate_handoff_pipe_name();
    let server = HandoffPipeServer::bind(&pipe_name).map_err(|err| err.to_string())?;
    let exe_path = std::env::current_exe().map_err(|err| err.to_string())?;
    let child_proc = match launch_elevated_worker(&exe_path, &pipe_name) {
        Ok(proc_handle) => proc_handle,
        Err(err) if is_uac_cancelled_error(&err) => {
            return Err("UAC prompt cancelled by user".to_owned());
        }
        Err(err) => return Err(err.to_string()),
    };

    let child_pid = get_process_id(&child_proc).map_err(|err| err.to_string())?;
    let wait_ms = u32::try_from(HANDOFF_PIPE_CONNECT_TIMEOUT.as_millis()).unwrap_or(15_000);
    let _creds = server
        .accept_and_verify_worker_watching_process(&child_proc, child_pid, wait_ms)
        .map_err(|err| err.to_string())?;

    let req_payload = serde_json::to_vec(&HandoffRequest::ExportBugreportStream)
        .map_err(|err| err.to_string())?;
    let req_frame = HandoffFrame::HandoffRequest(Zeroizing::new(req_payload));
    let encoded_req = encode_mgh1_frame(&req_frame).map_err(|err| err.to_string())?;
    server
        .write_all_blocking(encoded_req.as_slice())
        .map_err(|err| err.to_string())?;

    let stream_timeout_ms = u32::try_from(IPC_ADMIN_MUTATION_TIMEOUT.as_millis()).unwrap_or(35_000);
    let hdr_frame = read_mgh1_frame_from_server(&server, stream_timeout_ms)?;
    let header_meta = match hdr_frame {
        HandoffFrame::HandoffStreamHeader(meta) => meta,
        HandoffFrame::HandoffResponse(err_bytes) => {
            let resp: HandoffResponse =
                serde_json::from_slice(&err_bytes).map_err(|err| err.to_string())?;
            return resp
                .into_action_result()
                .map(|_| (0, 0))
                .map_err(|err| err.to_string());
        }
        other => return Err(format!("expected HandoffStreamHeader, got {other:?}")),
    };
    header_meta.validate().map_err(|err| err.to_string())?;

    let mut sink = UnprivilegedSinkWriter::create(dest_path, header_meta.total_bytes)
        .map_err(|err| err.to_string())?;
    let mut cumulative: u64 = 0;

    while cumulative < header_meta.total_bytes {
        let chunk_timeout_ms =
            u32::try_from(IPC_STREAM_CHUNK_IDLE_TIMEOUT.as_millis()).unwrap_or(10_000);
        match read_mgh1_frame_from_server(&server, chunk_timeout_ms)? {
            HandoffFrame::BugreportChunk(chunk) => {
                sink.write_chunk(&chunk).map_err(|err| err.to_string())?;
                cumulative = cumulative
                    .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| "bugreport stream size overflow".to_owned())?;
            }
            HandoffFrame::HandoffResponse(err_bytes) => {
                let resp: HandoffResponse =
                    serde_json::from_slice(&err_bytes).map_err(|err| err.to_string())?;
                return resp
                    .into_action_result()
                    .map(|_| (0, 0))
                    .map_err(|err| err.to_string());
            }
            other => {
                return Err(format!("unexpected MGH1 frame in stream: {other:?}"));
            }
        }
    }

    let final_frame = read_mgh1_frame_from_server(&server, stream_timeout_ms)?;
    let resp = match final_frame {
        HandoffFrame::HandoffResponse(bytes) => {
            serde_json::from_slice::<HandoffResponse>(&bytes).map_err(|err| err.to_string())?
        }
        other => {
            return Err(format!(
                "expected final HandoffResponse after chunks, got {other:?}"
            ));
        }
    };
    if !resp.ok {
        return resp
            .into_action_result()
            .map(|_| (0, 0))
            .map_err(|err| err.to_string());
    }

    let finalized_bytes = sink.finalize().map_err(|err| err.to_string())?;
    Ok((
        resp.scrubbed_items.unwrap_or(header_meta.scrubbed_items),
        finalized_bytes,
    ))
}

#[cfg(target_os = "windows")]
fn read_mgh1_frame_from_server(
    server: &HandoffPipeServer,
    timeout_ms: u32,
) -> Result<HandoffFrame, String> {
    let mut header = [0_u8; MGH1_HEADER_LEN];
    server
        .read_exact_blocking(&mut header, timeout_ms)
        .map_err(|err| err.to_string())?;
    let (_frame_type, payload_len) = decode_mgh1_header(&header).map_err(|err| err.to_string())?;
    let mut packet = Zeroizing::new(vec![0_u8; MGH1_HEADER_LEN + payload_len]);
    if let Some(hdr_dst) = packet.get_mut(..MGH1_HEADER_LEN) {
        hdr_dst.copy_from_slice(&header);
    }
    if let Some(body_dst) = packet.get_mut(MGH1_HEADER_LEN..) {
        server
            .read_exact_blocking(body_dst, timeout_ms)
            .map_err(|err| err.to_string())?;
    }
    let (decoded, _consumed) =
        decode_mgh1_frame(packet.as_slice()).map_err(|err| err.to_string())?;
    Ok(decoded)
}

#[cfg(target_os = "windows")]
fn read_mgh1_frame_from_client(
    client: &HandoffPipeClient,
    timeout_ms: u32,
) -> Result<HandoffFrame, String> {
    let mut header = [0_u8; MGH1_HEADER_LEN];
    client
        .read_exact_blocking(&mut header, timeout_ms)
        .map_err(|err| err.to_string())?;
    let (_frame_type, payload_len) = decode_mgh1_header(&header).map_err(|err| err.to_string())?;
    let mut packet = Zeroizing::new(vec![0_u8; MGH1_HEADER_LEN + payload_len]);
    if let Some(hdr_dst) = packet.get_mut(..MGH1_HEADER_LEN) {
        hdr_dst.copy_from_slice(&header);
    }
    if let Some(body_dst) = packet.get_mut(MGH1_HEADER_LEN..) {
        client
            .read_exact_blocking(body_dst, timeout_ms)
            .map_err(|err| err.to_string())?;
    }
    let (decoded, _consumed) =
        decode_mgh1_frame(packet.as_slice()).map_err(|err| err.to_string())?;
    Ok(decoded)
}

/// Entrypoint for `MeshVPN.exe --elevated-worker --pipe <\\.\pipe\mesh-gui-handoff-...>`.
#[cfg(target_os = "windows")]
pub(crate) fn run_elevated_worker_mode(pipe_name: &str) -> Result<(), String> {
    if !is_current_process_elevated().map_err(|err| err.to_string())? {
        return Err("elevated worker must run with Administrator token".to_owned());
    }
    let timeout_ms = u32::try_from(HANDOFF_PIPE_CONNECT_TIMEOUT.as_millis()).unwrap_or(15_000);
    let client = HandoffPipeClient::connect_and_send_hello(pipe_name, timeout_ms)
        .map_err(|e| e.to_string())?;

    let req_timeout_ms = u32::try_from(HANDOFF_WORKER_HELLO_TIMEOUT.as_millis()).unwrap_or(5_000);
    let req_frame = read_mgh1_frame_from_client(&client, req_timeout_ms)?;
    let req = match req_frame {
        HandoffFrame::HandoffRequest(mut bytes) => {
            let parsed = parse_handoff_request_payload(bytes.as_slice());
            zeroize_handoff_payload(&mut bytes);
            parsed.map_err(|err| err.to_string())?
        }
        other => return Err(format!("expected HandoffRequest frame, got {other:?}")),
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed initializing worker runtime: {err}"))?;

    match req {
        HandoffRequest::ExportBugreportStream => {
            let res = rt.block_on(execute_bugreport_stream_over_worker(&client));
            if let Err(err) = res {
                let err_resp = HandoffResponse::from_error(&err);
                send_worker_response(&client, &err_resp)?;
            }
            Ok(())
        }
        ref other => {
            let resp = match rt.block_on(execute_handoff_request_async(other)) {
                Ok(r) => r,
                Err(err) => HandoffResponse::from_error(&err),
            };
            send_worker_response(&client, &resp)
        }
    }
}

#[cfg(target_os = "windows")]
fn send_worker_response(client: &HandoffPipeClient, resp: &HandoffResponse) -> Result<(), String> {
    let json = serde_json::to_vec(resp).map_err(|err| err.to_string())?;
    let frame =
        encode_mgh1_frame(&HandoffFrame::HandoffResponse(json)).map_err(|err| err.to_string())?;
    client
        .write_all_blocking(frame.as_slice())
        .map_err(|err| err.to_string())
}

#[cfg(target_os = "windows")]
fn execute_request_direct_sync(req: &HandoffRequest) -> Result<HandoffResponse, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed initializing direct runtime: {err}"))?;
    rt.block_on(execute_handoff_request_async(req))
        .map_err(|err| err.to_string())
}

#[cfg(target_os = "windows")]
async fn execute_handoff_request_async(req: &HandoffRequest) -> AppResult<HandoffResponse> {
    match req {
        HandoffRequest::UpWithSecret { .. } => {
            let up_req = handoff_request_to_agent_up(req)?;
            let pipe = connect_agent_named_pipe(WINDOWS_AGENT_ADMIN_PIPE, true).await?;
            let action: AgentActionResponse = send_ipc_json_request_with_timeout(
                pipe,
                Method::POST,
                "/v1/agent/up",
                Some(&up_req),
                MAX_ADMIN_IPC_BODY_BYTES,
                IPC_ADMIN_MUTATION_TIMEOUT,
            )
            .await?;
            Ok(HandoffResponse::from_action(action))
        }
        HandoffRequest::RotateKeyWithSecret { .. } => {
            let rotate_req = handoff_request_to_agent_rotate_key(req)?;
            let pipe = connect_agent_named_pipe(WINDOWS_AGENT_ADMIN_PIPE, true).await?;
            let action: AgentActionResponse = send_ipc_json_request_with_timeout(
                pipe,
                Method::POST,
                "/v1/agent/rotate-key",
                Some(&rotate_req),
                MAX_ADMIN_IPC_BODY_BYTES,
                IPC_ADMIN_MUTATION_TIMEOUT,
            )
            .await?;
            Ok(HandoffResponse::from_action(action))
        }
        HandoffRequest::Down => {
            let pipe = connect_agent_named_pipe(WINDOWS_AGENT_ADMIN_PIPE, true).await?;
            let action: AgentActionResponse = send_ipc_json_request_with_timeout::<_, (), _>(
                pipe,
                Method::POST,
                "/v1/agent/down",
                None,
                MAX_ADMIN_IPC_BODY_BYTES,
                IPC_ADMIN_MUTATION_TIMEOUT,
            )
            .await?;
            Ok(HandoffResponse::from_action(action))
        }
        HandoffRequest::Cleanup => execute_cleanup_with_offline_fallback().await,
        HandoffRequest::Set {
            server_endpoint,
            server_pin,
        } => {
            let parsed_pin = server_pin.as_deref().map(SpkiPin::parse).transpose()?;
            let set_req = AgentSetRequest {
                server_endpoint: server_endpoint.clone(),
                server_pin: parsed_pin,
            };
            let pipe = connect_agent_named_pipe(WINDOWS_AGENT_ADMIN_PIPE, true).await?;
            let action: AgentActionResponse = send_ipc_json_request_with_timeout(
                pipe,
                Method::POST,
                "/v1/agent/set",
                Some(&set_req),
                MAX_ADMIN_IPC_BODY_BYTES,
                IPC_ADMIN_MUTATION_TIMEOUT,
            )
            .await?;
            Ok(HandoffResponse::from_action(action))
        }
        HandoffRequest::ResetIdentity => {
            let body = AgentResetIdentityRequest {};
            let pipe = connect_agent_named_pipe(WINDOWS_AGENT_ADMIN_PIPE, true).await?;
            let action: AgentActionResponse = send_ipc_json_request_with_timeout(
                pipe,
                Method::POST,
                "/v1/agent/reset-identity",
                Some(&body),
                MAX_ADMIN_IPC_BODY_BYTES,
                IPC_ADMIN_MUTATION_TIMEOUT,
            )
            .await?;
            Ok(HandoffResponse::from_action(action))
        }
        HandoffRequest::InstallOrStartService {
            source_dir,
            start_only,
        } => execute_install_or_start_service(source_dir, *start_only).await,
        HandoffRequest::UpdateService {
            source_dir,
            old_gui_pid,
        } => execute_update_service(source_dir, *old_gui_pid).await,
        HandoffRequest::UninstallService { purge_keys } => {
            execute_uninstall_service(*purge_keys).await
        }
        HandoffRequest::ExportBugreportStream => Err(AppError::invalid_argument(
            "ExportBugreportStream must follow streaming handler",
        )),
    }
}

#[cfg(target_os = "windows")]
async fn execute_cleanup_with_offline_fallback() -> AppResult<HandoffResponse> {
    if let Ok(pipe) = connect_agent_named_pipe(WINDOWS_AGENT_ADMIN_PIPE, true).await {
        let action: AgentActionResponse = send_ipc_json_request_with_timeout::<_, (), _>(
            pipe,
            Method::POST,
            "/v1/agent/cleanup",
            None,
            MAX_ADMIN_IPC_BODY_BYTES,
            IPC_ADMIN_MUTATION_TIMEOUT,
        )
        .await?;
        return Ok(HandoffResponse::from_action(action));
    }

    run_offline_ledger_cleanup()?;
    Ok(HandoffResponse::from_action(AgentActionResponse {
        state: DaemonState::Stopped,
        message: "Offline ResourceLedger cleanup completed".to_owned(),
    }))
}

#[cfg(target_os = "windows")]
fn run_offline_ledger_cleanup() -> AppResult<()> {
    let ledger_path = ResourceLedger::default_ledger_path();
    if !ledger_path.exists() {
        return Ok(());
    }
    let mut ledger = ResourceLedger::load_or_init(ledger_path)?;
    let ops = WindowsCleanupOps::new();
    ledger.cleanup_all(&ops)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn format_service_bin_cmd(meshd_path: &Path) -> String {
    format!("\"{}\" --service", meshd_path.display())
}

#[cfg(target_os = "windows")]
async fn execute_install_or_start_service(
    source_dir: &str,
    start_only: bool,
) -> AppResult<HandoffResponse> {
    let program_files_env = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let install_dir = resolve_program_files_mesh_dir(program_files_env.as_deref());
    let src_path = if source_dir.trim().is_empty() {
        install_dir.clone()
    } else {
        PathBuf::from(source_dir)
    };

    if start_only {
        verify_and_optionally_copy_wintun(&install_dir, &install_dir, true)?;
    } else {
        fs::create_dir_all(&install_dir).map_err(|err| {
            AppError::internal(format!(
                "failed creating install directory {}: {err}",
                install_dir.display()
            ))
        })?;
        set_directory_sddl_acl(&install_dir, INSTALL_DIR_SDDL)
            .map_err(|err| AppError::internal(err.to_string()))?;
        stop_and_optionally_delete_windows_service(WINDOWS_SERVICE_NAME, false)
            .map_err(|err| AppError::unavailable(err.to_string()))?;
        verify_and_optionally_copy_wintun(&src_path, &install_dir, false)?;
        install_or_stage_bundle_exes(&src_path, &install_dir)?;
    }

    let data_dir = Path::new(ADMIN_DATA_DIR);
    fs::create_dir_all(data_dir)
        .map_err(|err| AppError::internal(format!("failed creating {ADMIN_DATA_DIR}: {err}")))?;
    set_directory_sddl_acl(data_dir, PROGRAM_DATA_DIR_SDDL)
        .map_err(|err| AppError::internal(err.to_string()))?;

    let meshd_cmd = format_service_bin_cmd(&install_dir.join("meshd.exe"));
    ensure_and_start_windows_service(
        WINDOWS_SERVICE_NAME,
        "Mesh VPN Agent",
        "Mesh VPN WireGuard data plane and control plane agent",
        &meshd_cmd,
    )
    .map_err(|err| AppError::unavailable(err.to_string()))?;

    wait_for_ro_pipe_ready().await;

    Ok(HandoffResponse::from_action(AgentActionResponse {
        state: DaemonState::Stopped,
        message: "MeshVpnAgent Windows service started".to_owned(),
    }))
}

#[cfg(target_os = "windows")]
fn install_or_stage_bundle_exes(src_path: &Path, install_dir: &Path) -> AppResult<()> {
    for exe in ["meshd.exe", "mesh.exe", "MeshVPN.exe"] {
        let src_file = src_path.join(exe);
        let dst_file = install_dir.join(exe);
        if !src_file.exists() || windows_paths_equivalent(&src_file, &dst_file) {
            continue;
        }
        if let Err((err, raw_code)) = copy_file_anti_toctou_with_os_code(&src_file, &dst_file) {
            if exe == "MeshVPN.exe" && is_locked_binary_replace_error(raw_code, &err.to_string()) {
                let pending = install_dir.join("MeshVPN.exe.new");
                copy_file_anti_toctou(&src_file, &pending)?;
            } else {
                return Err(err);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn execute_update_service(
    source_dir: &str,
    old_gui_pid: Option<u32>,
) -> AppResult<HandoffResponse> {
    if let Some(pid) = old_gui_pid
        && pid != std::process::id()
    {
        std::thread::park_timeout(Duration::from_millis(200));
    }

    let src_path = PathBuf::from(source_dir);
    let program_files_env = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let install_dir = resolve_program_files_mesh_dir(program_files_env.as_deref());
    fs::create_dir_all(&install_dir)
        .map_err(|err| AppError::internal(format!("failed creating install dir: {err}")))?;
    set_directory_sddl_acl(&install_dir, INSTALL_DIR_SDDL)
        .map_err(|err| AppError::internal(err.to_string()))?;

    verify_and_optionally_copy_wintun(&src_path, &install_dir, false)?;
    stop_and_optionally_delete_windows_service(WINDOWS_SERVICE_NAME, false)
        .map_err(|err| AppError::unavailable(err.to_string()))?;

    install_or_stage_bundle_exes(&src_path, &install_dir)?;

    let meshd_cmd = format_service_bin_cmd(&install_dir.join("meshd.exe"));
    ensure_and_start_windows_service(
        WINDOWS_SERVICE_NAME,
        "Mesh VPN Agent",
        "Mesh VPN WireGuard data plane and control plane agent",
        &meshd_cmd,
    )
    .map_err(|err| AppError::unavailable(err.to_string()))?;
    wait_for_ro_pipe_ready().await;

    Ok(HandoffResponse::from_action(AgentActionResponse {
        state: DaemonState::Stopped,
        message: "Mesh VPN service and binaries updated cleanly".to_owned(),
    }))
}

#[cfg(target_os = "windows")]
async fn execute_uninstall_service(purge_keys: bool) -> AppResult<HandoffResponse> {
    let _cleanup_res = execute_cleanup_with_offline_fallback().await;
    stop_and_optionally_delete_windows_service(WINDOWS_SERVICE_NAME, true)
        .map_err(|err| AppError::unavailable(err.to_string()))?;
    let _ledger_res = run_offline_ledger_cleanup();

    let program_files_env = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let install_dir = resolve_program_files_mesh_dir(program_files_env.as_deref());
    for file_name in WINDOWS_BUNDLE_REMOVAL_LIST {
        let target = install_dir.join(file_name);
        if let Err(err) = fs::remove_file(&target) {
            if err.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            if matches!(err.raw_os_error(), Some(5 | 32)) {
                let _scheduled = schedule_delete_on_reboot(&target);
            } else {
                return Err(AppError::internal(format!(
                    "failed removing {}: {err}",
                    target.display()
                )));
            }
        }
    }
    let _rm_install_dir = fs::remove_dir(&install_dir);

    let data_dir = Path::new(ADMIN_DATA_DIR);
    if purge_keys {
        for file_name in PROGRAM_DATA_PURGE_FILES {
            let target = data_dir.join(file_name);
            if let Err(err) = fs::remove_file(&target)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(
                    component = "mesh-gui-worker",
                    event = "purge_file_failed",
                    path = %target.display(),
                    error = %err
                );
            }
        }
        for subdir in ["logs", "bugreports"] {
            let sub_path = data_dir.join(subdir);
            if let Err(err) = fs::remove_dir_all(&sub_path)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(
                    component = "mesh-gui-worker",
                    event = "purge_dir_failed",
                    path = %sub_path.display(),
                    error = %err
                );
            }
        }
        if let Err(err) = fs::remove_dir_all(data_dir)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                component = "mesh-gui-worker",
                event = "purge_data_dir_failed",
                path = %data_dir.display(),
                error = %err
            );
        }
    } else {
        for file_name in PROGRAM_DATA_EPHEMERAL_FILES {
            let target = data_dir.join(file_name);
            if let Err(err) = fs::remove_file(&target)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(
                    component = "mesh-gui-worker",
                    event = "uninstall_ephemeral_cleanup_failed",
                    path = %target.display(),
                    error = %err
                );
            }
        }
    }

    Ok(HandoffResponse::from_action(AgentActionResponse {
        state: DaemonState::Stopped,
        message: if purge_keys {
            "Service uninstalled and identity keys purged".to_owned()
        } else {
            "Service uninstalled (keys.json preserved for reinstall)".to_owned()
        },
    }))
}

#[cfg(target_os = "windows")]
fn verify_and_optionally_copy_wintun(
    src_dir: &Path,
    dst_dir: &Path,
    verify_only_existing: bool,
) -> AppResult<()> {
    let src_wintun = src_dir.join("wintun.dll");
    let sidecar_path = src_dir.join("wintun.dll.sha256");
    let expected_hex = resolve_expected_wintun_sha256(
        option_env!("MESH_WINTUN_SHA256"),
        &sidecar_path,
        verify_only_existing,
    )
    .map_err(AppError::invalid_argument)?;

    let mut locked_src = open_anti_toctou_read_locked(&src_wintun).map_err(|err| {
        AppError::unavailable(format!(
            "failed opening {} with anti-TOCTOU lock: {err}",
            src_wintun.display()
        ))
    })?;
    // Holds `FILE_SHARE_READ` exclusive write/delete lock continuously across digest verification
    // and stream copy, preventing TOCTOU substitution (`ADR-026`).
    verify_wintun_path_sha256(&src_wintun, &expected_hex).map_err(AppError::invalid_argument)?;

    if !verify_only_existing && !windows_paths_equivalent(src_dir, dst_dir) {
        let dst_wintun = dst_dir.join("wintun.dll");
        let tmp_dst = dst_dir.join("wintun.dll.part");
        let mut out = File::create(&tmp_dst).map_err(|err| {
            AppError::internal(format!("failed creating {}: {err}", tmp_dst.display()))
        })?;
        std::io::copy(&mut locked_src, &mut out)
            .map_err(|err| AppError::internal(format!("failed copying wintun.dll: {err}")))?;
        out.sync_all()
            .map_err(|err| AppError::internal(format!("failed syncing wintun.dll: {err}")))?;
        drop(out);
        fs::rename(&tmp_dst, &dst_wintun).map_err(|err| {
            let _rm = fs::remove_file(&tmp_dst);
            AppError::internal(format!("failed installing wintun.dll: {err}"))
        })?;
        let sidecar_dst = dst_dir.join("wintun.dll.sha256");
        let _wrote_sidecar = fs::write(&sidecar_dst, format!("{expected_hex}  wintun.dll\n"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn copy_file_anti_toctou(src: &Path, dst: &Path) -> AppResult<()> {
    copy_file_anti_toctou_with_os_code(src, dst).map_err(|(app_err, _code)| app_err)
}

#[cfg(target_os = "windows")]
fn copy_file_anti_toctou_with_os_code(
    src: &Path,
    dst: &Path,
) -> Result<(), (AppError, Option<i32>)> {
    if windows_paths_equivalent(src, dst) {
        return Ok(());
    }
    let mut locked = open_anti_toctou_read_locked(src).map_err(|err| {
        (
            AppError::unavailable(format!("failed locking {}: {err}", src.display())),
            None,
        )
    })?;
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let file_name = dst.file_name().and_then(|s| s.to_str()).unwrap_or("binary");
    let tmp = parent.join(format!("{file_name}.part"));
    let mut out = File::create(&tmp).map_err(|err| {
        let code = err.raw_os_error();
        (
            AppError::internal(format!("failed creating {}: {err}", tmp.display())),
            code,
        )
    })?;
    std::io::copy(&mut locked, &mut out).map_err(|err| {
        let code = err.raw_os_error();
        let _rm = fs::remove_file(&tmp);
        (
            AppError::internal(format!("failed copying {}: {err}", src.display())),
            code,
        )
    })?;
    out.sync_all().map_err(|err| {
        let code = err.raw_os_error();
        let _rm = fs::remove_file(&tmp);
        (
            AppError::internal(format!("failed syncing {}: {err}", tmp.display())),
            code,
        )
    })?;
    drop(out);
    fs::rename(&tmp, dst).map_err(|err| {
        let code = err.raw_os_error();
        let _rm = fs::remove_file(&tmp);
        (
            AppError::internal(format!("failed replacing {}: {err}", dst.display())),
            code,
        )
    })?;
    Ok(())
}

#[cfg(target_os = "windows")]
async fn wait_for_ro_pipe_ready() {
    for _ in 0..10_u32 {
        if let Ok(pipe) = connect_agent_named_pipe(WINDOWS_AGENT_RO_PIPE, false).await {
            drop(pipe);
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ro_timeout = IPC_RO_QUERY_TIMEOUT;
}

#[cfg(target_os = "windows")]
enum StreamCallbackEvent<'a> {
    Header(HandoffStreamHeaderPayload),
    Chunk(&'a [u8]),
}

/// Pure safe HTTP/1.1 streaming client over `\\.\pipe\mesh-agent-admin` for
/// `POST /v1/agent/bugreport/stream` emitting headers BEFORE chunks without 20 MiB buffering
/// and with ZERO `unsafe` (`ADR-021`, `ADR-023`).
#[cfg(target_os = "windows")]
async fn stream_bugreport_headers_and_chunks<F>(mut on_event: F) -> AppResult<(u32, u64)>
where
    F: FnMut(StreamCallbackEvent<'_>) -> AppResult<()>,
{
    let pipe = connect_agent_named_pipe(WINDOWS_AGENT_ADMIN_PIPE, true).await?;
    let mut reader = BufReader::with_capacity(MGH1_MAX_BUGREPORT_CHUNK_BYTES, pipe);
    let started = Instant::now();
    let total_timeout = IPC_ADMIN_MUTATION_TIMEOUT;

    let req_bytes = concat!(
        "POST /v1/agent/bugreport/stream HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Connection: close\r\n",
        "Content-Length: 0\r\n\r\n"
    )
    .as_bytes();
    tokio::time::timeout(total_timeout, reader.get_mut().write_all(req_bytes))
        .await
        .map_err(|_| AppError::unavailable("bugreport request write timed out"))?
        .map_err(|err| AppError::unavailable(format!("bugreport request write error: {err}")))?;
    tokio::time::timeout(total_timeout, reader.get_mut().flush())
        .await
        .map_err(|_| AppError::unavailable("bugreport request flush timed out"))?
        .map_err(|err| AppError::unavailable(format!("bugreport request flush error: {err}")))?;

    let (status_code, total_bytes, scrubbed_items, is_chunked) =
        read_bugreport_http_headers(&mut reader, total_timeout).await?;

    if !(200..300).contains(&status_code) {
        let mut err_buf = vec![0_u8; MAX_ADMIN_IPC_BODY_BYTES];
        let n = tokio::time::timeout(IPC_STREAM_CHUNK_IDLE_TIMEOUT, reader.read(&mut err_buf))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(0);
        let slice = err_buf.get(..n).unwrap_or(&[]);
        if let Ok(env) = serde_json::from_slice::<ErrorResponse>(slice) {
            return Err(AppError::new(env.error.kind, env.error.message));
        }
        return Err(AppError::unavailable(format!(
            "bugreport IPC returned HTTP {status_code}"
        )));
    }

    let header_payload = HandoffStreamHeaderPayload {
        total_bytes,
        scrubbed_items,
    };
    header_payload.validate()?;
    on_event(StreamCallbackEvent::Header(header_payload))?;

    let cumulative = if is_chunked {
        stream_chunked_http_body(
            &mut reader,
            total_bytes,
            started,
            total_timeout,
            &mut on_event,
        )
        .await?
    } else {
        stream_fixed_http_body(
            &mut reader,
            total_bytes,
            started,
            total_timeout,
            &mut on_event,
        )
        .await?
    };

    if cumulative == 0 || cumulative != total_bytes {
        return Err(AppError::unavailable(format!(
            "bugreport stream truncated: {cumulative}/{total_bytes} bytes"
        )));
    }
    Ok((scrubbed_items, cumulative))
}

#[cfg(target_os = "windows")]
async fn read_bugreport_http_headers<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    timeout: Duration,
) -> AppResult<(u16, u64, u32, bool)> {
    let mut header_bytes = 0usize;
    let mut status_line = String::new();
    let n = tokio::time::timeout(timeout, reader.read_line(&mut status_line))
        .await
        .map_err(|_| AppError::unavailable("timed out reading HTTP status line"))?
        .map_err(|err| AppError::unavailable(format!("failed reading HTTP status line: {err}")))?;
    if n == 0 {
        return Err(AppError::unavailable(
            "unexpected EOF reading bugreport response",
        ));
    }
    header_bytes += n;

    let mut parts = status_line.split_whitespace();
    let _proto = parts.next();
    let status_code: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::internal("malformed HTTP status code from daemon"))?;

    let mut archive_len: Option<u64> = None;
    let mut content_len: Option<u64> = None;
    let mut scrubbed: u32 = 0;
    let mut is_chunked = false;

    loop {
        let mut line = String::new();
        let read_n = tokio::time::timeout(timeout, reader.read_line(&mut line))
            .await
            .map_err(|_| AppError::unavailable("timed out reading bugreport headers"))?
            .map_err(|err| AppError::unavailable(format!("failed reading header line: {err}")))?;
        header_bytes = header_bytes.saturating_add(read_n);
        if read_n == 0 || header_bytes > MAX_HTTP_HEADER_BLOCK_BYTES {
            return Err(AppError::invalid_argument(
                "bugreport response header block truncated or exceeded 8 KiB",
            ));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, val)) = trimmed.split_once(':') {
            let lname = name.trim().to_ascii_lowercase();
            let v = val.trim();
            if lname == HEADER_MESH_ARCHIVE_BYTES {
                archive_len = v.parse::<u64>().ok();
            } else if lname == "content-length" {
                content_len = v.parse::<u64>().ok();
            } else if lname == HEADER_MESH_SCRUBBED_ITEMS {
                scrubbed = v.parse::<u32>().unwrap_or(0);
            } else if lname == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
        }
    }

    let total_bytes = if (200..300).contains(&status_code) {
        let len = archive_len
            .or(content_len)
            .ok_or_else(|| AppError::invalid_argument("missing X-Mesh-Archive-Bytes header"))?;
        crate::diagnostics_view::validate_bugreport_archive_size(len)
            .map_err(AppError::invalid_argument)?;
        len
    } else {
        0
    };

    Ok((status_code, total_bytes, scrubbed, is_chunked))
}

#[cfg(target_os = "windows")]
async fn stream_fixed_http_body<R, F>(
    reader: &mut R,
    expected_total_bytes: u64,
    started: Instant,
    total_timeout: Duration,
    on_event: &mut F,
) -> AppResult<u64>
where
    R: AsyncReadExt + Unpin,
    F: FnMut(StreamCallbackEvent<'_>) -> AppResult<()>,
{
    let mut cumulative: u64 = 0;
    let mut buf = vec![0_u8; MGH1_MAX_BUGREPORT_CHUNK_BYTES];
    while cumulative < expected_total_bytes {
        let rem_total = total_timeout
            .checked_sub(started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| AppError::unavailable("bugreport stream exceeded total timeout"))?;
        let step_timeout = IPC_STREAM_CHUNK_IDLE_TIMEOUT.min(rem_total);
        let remaining_bytes = expected_total_bytes - cumulative;
        let to_read = usize::try_from(remaining_bytes)
            .unwrap_or(buf.len())
            .min(buf.len());
        let Some(slice) = buf.get_mut(..to_read) else {
            return Err(AppError::internal("invalid read slice length"));
        };
        let n = tokio::time::timeout(step_timeout, reader.read(slice))
            .await
            .map_err(|_| AppError::unavailable("bugreport stream stalled waiting for next chunk"))?
            .map_err(|err| AppError::unavailable(format!("bugreport stream read error: {err}")))?;
        if n == 0 {
            break;
        }
        if let Some(chunk) = buf.get(..n) {
            on_event(StreamCallbackEvent::Chunk(chunk))?;
        }
        cumulative = cumulative
            .checked_add(u64::try_from(n).unwrap_or(u64::MAX))
            .ok_or_else(|| AppError::invalid_argument("bugreport size overflow"))?;
    }
    Ok(cumulative)
}

#[cfg(target_os = "windows")]
async fn stream_chunked_http_body<R, F>(
    reader: &mut R,
    expected_total_bytes: u64,
    started: Instant,
    total_timeout: Duration,
    on_event: &mut F,
) -> AppResult<u64>
where
    R: AsyncBufReadExt + AsyncReadExt + Unpin,
    F: FnMut(StreamCallbackEvent<'_>) -> AppResult<()>,
{
    let mut cumulative: u64 = 0;
    let mut buf = vec![0_u8; MGH1_MAX_BUGREPORT_CHUNK_BYTES];

    loop {
        let rem_total = total_timeout
            .checked_sub(started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                AppError::unavailable("bugreport chunked stream exceeded total timeout")
            })?;
        let step_timeout = IPC_STREAM_CHUNK_IDLE_TIMEOUT.min(rem_total);

        let mut len_line = String::new();
        let line_n = tokio::time::timeout(step_timeout, reader.read_line(&mut len_line))
            .await
            .map_err(|_| AppError::unavailable("bugreport stream stalled on chunk header"))?
            .map_err(|err| AppError::unavailable(format!("bugreport chunk header error: {err}")))?;
        if line_n == 0 || line_n > 64 {
            return Err(AppError::unavailable(
                "malformed chunked response from daemon",
            ));
        }
        let hex_part = len_line.trim().split(';').next().unwrap_or("").trim();
        let mut chunk_rem = usize::from_str_radix(hex_part, 16).map_err(|_| {
            AppError::invalid_argument("invalid hex chunk size in bugreport stream")
        })?;
        if chunk_rem == 0 {
            break;
        }

        while chunk_rem > 0 {
            let take = chunk_rem.min(buf.len());
            let next_total = cumulative
                .checked_add(u64::try_from(take).unwrap_or(u64::MAX))
                .ok_or_else(|| AppError::invalid_argument("bugreport size overflow"))?;
            if next_total > expected_total_bytes {
                return Err(AppError::invalid_argument(
                    "bugreport stream exceeded declared archive size",
                ));
            }
            let Some(slice) = buf.get_mut(..take) else {
                return Err(AppError::internal("invalid chunk read slice length"));
            };
            tokio::time::timeout(step_timeout, reader.read_exact(slice))
                .await
                .map_err(|_| AppError::unavailable("bugreport chunk read timed out"))?
                .map_err(|err| {
                    AppError::unavailable(format!("bugreport chunk read error: {err}"))
                })?;
            on_event(StreamCallbackEvent::Chunk(slice))?;
            cumulative = next_total;
            chunk_rem -= take;
        }

        let mut crlf = [0_u8; 2];
        tokio::time::timeout(step_timeout, reader.read_exact(&mut crlf))
            .await
            .map_err(|_| AppError::unavailable("bugreport chunk trailer timed out"))?
            .map_err(|err| {
                AppError::unavailable(format!("bugreport chunk trailer error: {err}"))
            })?;
    }

    let _unused = Component::Normal(std::ffi::OsStr::new(""));
    Ok(cumulative)
}

#[cfg(target_os = "windows")]
async fn execute_bugreport_stream_over_worker(client: &HandoffPipeClient) -> AppResult<()> {
    let (scrubbed_items, total_bytes) = stream_bugreport_headers_and_chunks(|ev| match ev {
        StreamCallbackEvent::Header(header) => {
            let encoded = encode_mgh1_frame(&HandoffFrame::HandoffStreamHeader(header))?;
            client
                .write_all_blocking(encoded.as_slice())
                .map_err(|err| AppError::unavailable(err.to_string()))
        }
        StreamCallbackEvent::Chunk(chunk) => {
            let encoded = encode_mgh1_frame(&HandoffFrame::BugreportChunk(chunk.to_vec()))?;
            client
                .write_all_blocking(encoded.as_slice())
                .map_err(|err| AppError::unavailable(err.to_string()))
        }
    })
    .await?;

    let resp = HandoffResponse::from_bugreport(scrubbed_items, total_bytes);
    let json = serde_json::to_vec(&resp)
        .map_err(|err| AppError::internal(format!("failed serializing bugreport resp: {err}")))?;
    let frame = encode_mgh1_frame(&HandoffFrame::HandoffResponse(json))?;
    client
        .write_all_blocking(frame.as_slice())
        .map_err(|err| AppError::unavailable(err.to_string()))
}

#[cfg(target_os = "windows")]
fn execute_direct_bugreport_export(dest_path: &Path) -> Result<(u32, u64), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed initializing direct export runtime: {err}"))?;

    rt.block_on(async move {
        let mut sink_opt: Option<UnprivilegedSinkWriter> = None;
        let (scrubbed, _total) = stream_bugreport_headers_and_chunks(|ev| match ev {
            StreamCallbackEvent::Header(header) => {
                let sink = UnprivilegedSinkWriter::create(dest_path, header.total_bytes)
                    .map_err(|err| AppError::internal(err.to_string()))?;
                sink_opt = Some(sink);
                Ok(())
            }
            StreamCallbackEvent::Chunk(chunk) => {
                let sink = sink_opt
                    .as_mut()
                    .ok_or_else(|| AppError::internal("sink not initialized"))?;
                sink.write_chunk(chunk)
                    .map_err(|err| AppError::internal(err.to_string()))
            }
        })
        .await
        .map_err(|err| err.to_string())?;

        let sink = sink_opt.ok_or_else(|| "bugreport stream yielded no data".to_owned())?;
        let finalized_bytes = sink.finalize().map_err(|err| err.to_string())?;
        Ok((scrubbed, finalized_bytes))
    })
}
