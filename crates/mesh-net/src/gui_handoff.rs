//! Ephemeral Authenticated Named Pipe Handoff framing (`MGH1`), typed request/response
//! schemas, and secret-redacted payload builders (`ADR-020`, `ADR-021`, `ADR-023`).
//!
//! Workspace static checks (`SEC-01`) permit `.expose_secret()` inside `mesh-net`, so
//! `crates/mesh-gui` delegates all pre-auth key unwrapping to [`build_up_handoff_payload`]
//! and [`build_rotate_key_handoff_payload`] here without exposing raw strings in the GUI crate.

use std::fmt;
use std::time::Duration;

use mesh_core::defaults::{MAX_ADMIN_IPC_BODY_BYTES, MAX_BUGREPORT_ARCHIVE_BYTES};
use mesh_core::error::ErrorEnvelope;
use mesh_core::{AppError, AppResult, NodeName, Port, SpkiPin, validate_preauth_key};
use mesh_crypto::secret::{Secret, Zeroize, Zeroizing};
use mesh_crypto::{mask_preauth_token, random_bytes};
use mesh_proto::agent_ipc::{
    AgentActionResponse, AgentRotateKeyRequest, AgentUpRequest, DaemonState,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Fixed 4-byte binary framing magic prefix (`"MGH1"`).
pub const MGH1_MAGIC: [u8; 4] = *b"MGH1";

/// Fixed 9-byte `MGH1` frame header length (`magic[4] + frame_type[1] + len_le[4]`).
pub const MGH1_HEADER_LEN: usize = 9;

/// Active `MGH1` handoff protocol version sent inside Frame `0x00 WorkerHello`.
pub const MGH1_PROTOCOL_VERSION: u32 = 1;

/// Exact byte length of Frame `0x00 WorkerHello` (`9 + 4 = 13` bytes).
pub const MGH1_WORKER_HELLO_LEN: usize = 13;

/// Maximum JSON payload length for `0x01 HandoffRequest` and `0x04 HandoffResponse` (`64 KiB`).
pub const MGH1_MAX_CONTROL_FRAME_BYTES: usize = MAX_ADMIN_IPC_BODY_BYTES;

/// Maximum JSON payload length for `0x02 HandoffStreamHeader` (`4 KiB`).
pub const MGH1_MAX_STREAM_HEADER_BYTES: usize = 4_096;

/// Maximum raw `.tar` chunk length for `0x03 BugreportChunk` (`64 KiB`).
pub const MGH1_MAX_BUGREPORT_CHUNK_BYTES: usize = 65_536;

/// Canonical Windows Named Pipe prefix for ephemeral UAC handoff channels (`ADR-021`).
pub const HANDOFF_PIPE_PREFIX: &str = r"\\.\pipe\mesh-gui-handoff-";

/// Maximum wait for elevated worker `0x00 WorkerHello` after connection (`5_000 ms`, `BLK-DGUI-G2-04`).
pub const HANDOFF_WORKER_HELLO_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Maximum wait for elevated worker connection after UAC prompt returns (`15_000 ms`).
pub const HANDOFF_PIPE_CONNECT_TIMEOUT: Duration = Duration::from_millis(15_000);

/// Maximum time waiting for user confirmation in the Windows UAC prompt (`120_000 ms`).
pub const HANDOFF_UAC_WAIT_TIMEOUT: Duration = Duration::from_millis(120_000);

/// Generates a 128-bit CSPRNG ephemeral Windows Named Pipe path (`\\.\pipe\mesh-gui-handoff-<32_hex>`).
#[must_use]
pub fn generate_handoff_pipe_name() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = random_bytes::<16>();
    let mut out = String::with_capacity(HANDOFF_PIPE_PREFIX.len() + 32);
    out.push_str(HANDOFF_PIPE_PREFIX);
    for b in bytes {
        if let (Some(&hi), Some(&lo)) =
            (HEX.get(usize::from(b >> 4)), HEX.get(usize::from(b & 0x0f)))
        {
            out.push(char::from(hi));
            out.push(char::from(lo));
        }
    }
    out
}

/// Validates strict `\\.\pipe\mesh-gui-handoff-<32_lowercase_hex>` syntax (`ADR-021`).
pub fn validate_handoff_pipe_name(pipe_name: &str) -> AppResult<()> {
    let Some(hex_suffix) = pipe_name.strip_prefix(HANDOFF_PIPE_PREFIX) else {
        return Err(AppError::invalid_argument(
            "handoff pipe name must begin with `\\\\.\\pipe\\mesh-gui-handoff-`",
        ));
    };
    if hex_suffix.len() != 32
        || !hex_suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AppError::invalid_argument(
            "handoff pipe name suffix must be 32 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

/// Wire frame type discriminants for `MGH1` (`ADR-021`, `ADR-023`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HandoffFrameType {
    /// `0x00`: Elevated worker -> GUI greeting (`len == 4`, `protocol_version = 1`).
    WorkerHello = 0x00,
    /// `0x01`: GUI -> Elevated worker command JSON (`<= 64 KiB`, zeroized).
    HandoffRequest = 0x01,
    /// `0x02`: Elevated worker -> GUI bugreport stream metadata (`<= 4 KiB`).
    HandoffStreamHeader = 0x02,
    /// `0x03`: Elevated worker -> GUI raw `.tar` archive chunk (`1..=65_536 B`).
    BugreportChunk = 0x03,
    /// `0x04`: Elevated worker -> GUI action completion / error JSON (`<= 64 KiB`).
    HandoffResponse = 0x04,
}

impl HandoffFrameType {
    /// Parses a wire `u8` discriminant into a known [`HandoffFrameType`].
    pub fn from_u8(raw: u8) -> AppResult<Self> {
        match raw {
            0x00 => Ok(Self::WorkerHello),
            0x01 => Ok(Self::HandoffRequest),
            0x02 => Ok(Self::HandoffStreamHeader),
            0x03 => Ok(Self::BugreportChunk),
            0x04 => Ok(Self::HandoffResponse),
            other => Err(AppError::invalid_argument(format!(
                "unknown MGH1 handoff frame type 0x{other:02x}"
            ))),
        }
    }
}

/// JSON payload carried inside Frame `0x02 HandoffStreamHeader` (`ADR-023`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffStreamHeaderPayload {
    /// Exact total `.tar` archive size in bytes (`1..=MAX_BUGREPORT_ARCHIVE_BYTES`).
    pub total_bytes: u64,
    /// Number of secret tokens scrubbed during generation.
    pub scrubbed_items: u32,
}

impl HandoffStreamHeaderPayload {
    /// Validates non-empty archive length within `MAX_BUGREPORT_ARCHIVE_BYTES` (`20 MiB`).
    pub fn validate(self) -> AppResult<()> {
        let max_bytes = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX);
        if self.total_bytes == 0 || self.total_bytes > max_bytes {
            return Err(AppError::invalid_argument(format!(
                "handoff bugreport stream size {} outside 1..={max_bytes} bytes",
                self.total_bytes
            )));
        }
        Ok(())
    }
}

/// Decoded `MGH1` binary frame (`0x00..=0x04`).
#[derive(Clone, PartialEq, Eq)]
pub enum HandoffFrame {
    /// `0x00` Worker greeting enabling kernel `ImpersonateNamedPipeClient(SecurityIdentification)`.
    WorkerHello {
        /// Protocol version (`MGH1_PROTOCOL_VERSION = 1`).
        protocol_version: u32,
    },
    /// `0x01` Zeroized JSON bytes of [`HandoffRequest`] (may contain `mpk_*`).
    HandoffRequest(Zeroizing<Vec<u8>>),
    /// `0x02` Metadata header preceding `0x03` bugreport archive chunks.
    HandoffStreamHeader(HandoffStreamHeaderPayload),
    /// `0x03` Raw `.tar` bugreport chunk (`1..=65_536 B`).
    BugreportChunk(Vec<u8>),
    /// `0x04` Serialized JSON [`HandoffResponse`] (`<= 64 KiB`).
    HandoffResponse(Vec<u8>),
}

impl fmt::Debug for HandoffFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerHello { protocol_version } => f
                .debug_struct("WorkerHello")
                .field("protocol_version", protocol_version)
                .finish(),
            Self::HandoffRequest(bytes) => f
                .debug_tuple("HandoffRequest")
                .field(&format!("[REDACTED; {} bytes]", bytes.len()))
                .finish(),
            Self::HandoffStreamHeader(meta) => {
                f.debug_tuple("HandoffStreamHeader").field(meta).finish()
            }
            Self::BugreportChunk(bytes) => f
                .debug_tuple("BugreportChunk")
                .field(&format!("<{} bytes>", bytes.len()))
                .finish(),
            Self::HandoffResponse(bytes) => f
                .debug_tuple("HandoffResponse")
                .field(&format!("<{} bytes>", bytes.len()))
                .finish(),
        }
    }
}

/// Canonical `MGH1` Frame `0x01` request payload sent from `MeshVPN.exe` GUI to `--elevated-worker`
/// (`desktop-gui-ipc-and-ui-contracts.md` §2.3).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandoffRequest {
    /// Enroll or 1-click reconnect via `POST /v1/agent/up` (`preauth_key: None` preserves `next_pin`).
    UpWithSecret {
        /// Normalized `<host>:<effective_port>` Control endpoint.
        server_endpoint: String,
        /// Optional explicit port override.
        port_override: Option<u16>,
        /// Optional SPKI pin (`sha256:<64hex>`).
        server_pin: Option<String>,
        /// Optional pre-authentication key (`mpk_*`).
        preauth_key: Option<String>,
        /// Optional RFC 1123 node name.
        node_name: Option<String>,
    },
    /// Rotate node WireGuard identity key via `POST /v1/agent/rotate-key`.
    RotateKeyWithSecret {
        /// Scoped pre-auth key (`mpk_*`).
        preauth_key: String,
    },
    /// Tear down active tunnel via `POST /v1/agent/down`.
    Down,
    /// Idempotent cleanup via `POST /v1/agent/cleanup` (with offline `ResourceLedger` fallback).
    Cleanup,
    /// Update Control endpoint / pins via `POST /v1/agent/set`.
    Set {
        /// Normalized `<host>:<effective_port>` Control endpoint.
        server_endpoint: String,
        /// Optional SPKI pin (`sha256:<64hex>`).
        server_pin: Option<String>,
    },
    /// Reset local identity via `POST /v1/agent/reset-identity` (keeps `meshd` alive).
    ResetIdentity,
    /// Stream redacted bugreport `.tar` (`<= 20 MiB`) back via `0x02` + `0x03*` + `0x04` (never carries save path).
    ExportBugreportStream,
    /// Verify `MESH_WINTUN_SHA256`, install binaries if `!start_only`, and start `MeshVpnAgent`.
    InstallOrStartService {
        /// Source bundle directory containing binaries and `wintun.dll`.
        source_dir: String,
        /// When `true`, only starts the existing installed `MeshVpnAgent` service.
        start_only: bool,
    },
    /// Gracefully shut down older Tray if needed, stop `MeshVpnAgent`, and upgrade binaries.
    UpdateService {
        /// Source bundle directory containing updated binaries.
        source_dir: String,
        /// Optional older Tray PID to wait on before replacing files.
        old_gui_pid: Option<u32>,
    },
    /// Stop/delete `MeshVpnAgent`, run cleanup, remove 8 binaries; keep `keys.json` unless `purge_keys`.
    UninstallService {
        /// When `true`, also removes `C:\ProgramData\Mesh` identity keys.
        purge_keys: bool,
    },
}

impl Drop for HandoffRequest {
    fn drop(&mut self) {
        match self {
            Self::UpWithSecret { preauth_key, .. } => {
                if let Some(key) = preauth_key {
                    key.zeroize();
                }
            }
            Self::RotateKeyWithSecret { preauth_key } => {
                preauth_key.zeroize();
            }
            Self::Down
            | Self::Cleanup
            | Self::Set { .. }
            | Self::ResetIdentity
            | Self::ExportBugreportStream
            | Self::InstallOrStartService { .. }
            | Self::UpdateService { .. }
            | Self::UninstallService { .. } => {}
        }
    }
}

impl fmt::Debug for HandoffRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpWithSecret {
                server_endpoint,
                port_override,
                server_pin,
                preauth_key,
                node_name,
            } => f
                .debug_struct("UpWithSecret")
                .field("server_endpoint", server_endpoint)
                .field("port_override", port_override)
                .field("server_pin", server_pin)
                .field("preauth_key", &preauth_key.as_ref().map(|_| "[REDACTED]"))
                .field("node_name", node_name)
                .finish(),
            Self::RotateKeyWithSecret { .. } => f
                .debug_struct("RotateKeyWithSecret")
                .field("preauth_key", &"[REDACTED]")
                .finish(),
            Self::Down => f.write_str("Down"),
            Self::Cleanup => f.write_str("Cleanup"),
            Self::Set {
                server_endpoint,
                server_pin,
            } => f
                .debug_struct("Set")
                .field("server_endpoint", server_endpoint)
                .field("server_pin", server_pin)
                .finish(),
            Self::ResetIdentity => f.write_str("ResetIdentity"),
            Self::ExportBugreportStream => f.write_str("ExportBugreportStream"),
            Self::InstallOrStartService {
                source_dir,
                start_only,
            } => f
                .debug_struct("InstallOrStartService")
                .field("source_dir", source_dir)
                .field("start_only", start_only)
                .finish(),
            Self::UpdateService {
                source_dir,
                old_gui_pid,
            } => f
                .debug_struct("UpdateService")
                .field("source_dir", source_dir)
                .field("old_gui_pid", old_gui_pid)
                .finish(),
            Self::UninstallService { purge_keys } => f
                .debug_struct("UninstallService")
                .field("purge_keys", purge_keys)
                .finish(),
        }
    }
}

/// Canonical `MGH1` Frame `0x04` response sent by `--elevated-worker` back to `MeshVPN.exe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffResponse {
    /// `true` when the elevated operation succeeded.
    pub ok: bool,
    /// Resulting daemon state when available.
    pub daemon_state: Option<DaemonState>,
    /// Concise status summary message.
    pub message: Option<String>,
    /// Number of redacted log/config items (for `export_bugreport_stream`).
    pub scrubbed_items: Option<u32>,
    /// Total archive byte length streamed (for `export_bugreport_stream`).
    pub archive_bytes: Option<u64>,
    /// Wire error envelope when `ok == false`.
    pub error: Option<ErrorEnvelope>,
}

impl HandoffResponse {
    /// Constructs a success response from an [`AgentActionResponse`].
    #[must_use]
    pub fn from_action(action: AgentActionResponse) -> Self {
        Self {
            ok: true,
            daemon_state: Some(action.state),
            message: Some(action.message),
            scrubbed_items: None,
            archive_bytes: None,
            error: None,
        }
    }

    /// Constructs a success response for `export_bugreport_stream`.
    #[must_use]
    pub fn from_bugreport(scrubbed_items: u32, archive_bytes: u64) -> Self {
        Self {
            ok: true,
            daemon_state: None,
            message: Some("bugreport archive streamed".to_owned()),
            scrubbed_items: Some(scrubbed_items),
            archive_bytes: Some(archive_bytes),
            error: None,
        }
    }

    /// Constructs a failure response preserving [`AppError::to_envelope`] sanitization (`SEC-05`).
    #[must_use]
    pub fn from_error(err: &AppError) -> Self {
        Self {
            ok: false,
            daemon_state: None,
            message: None,
            scrubbed_items: None,
            archive_bytes: None,
            error: Some(err.to_envelope("handoff")),
        }
    }

    /// Converts this handoff response back into `AppResult<AgentActionResponse>`.
    pub fn into_action_result(self) -> AppResult<AgentActionResponse> {
        if self.ok {
            let state = self.daemon_state.unwrap_or(DaemonState::Stopped);
            let message = self.message.unwrap_or_else(|| "ok".to_owned());
            return Ok(AgentActionResponse { state, message });
        }
        if let Some(env) = self.error {
            return Err(AppError::new(env.kind, env.message));
        }
        Err(AppError::unavailable("elevated worker operation failed"))
    }
}

/// Validates framing payload length invariants for `(frame_type, payload_len)` before allocation.
pub fn validate_mgh1_payload_len(
    frame_type: HandoffFrameType,
    payload_len: usize,
) -> AppResult<()> {
    match frame_type {
        HandoffFrameType::WorkerHello => {
            if payload_len != 4 {
                return Err(AppError::invalid_argument(format!(
                    "MGH1 WorkerHello payload length must be 4 bytes, got {payload_len}"
                )));
            }
        }
        HandoffFrameType::HandoffRequest | HandoffFrameType::HandoffResponse => {
            if payload_len == 0 || payload_len > MGH1_MAX_CONTROL_FRAME_BYTES {
                return Err(AppError::invalid_argument(format!(
                    "MGH1 control frame length {payload_len} outside 1..={MGH1_MAX_CONTROL_FRAME_BYTES}"
                )));
            }
        }
        HandoffFrameType::HandoffStreamHeader => {
            if payload_len == 0 || payload_len > MGH1_MAX_STREAM_HEADER_BYTES {
                return Err(AppError::invalid_argument(format!(
                    "MGH1 stream header length {payload_len} outside 1..={MGH1_MAX_STREAM_HEADER_BYTES}"
                )));
            }
        }
        HandoffFrameType::BugreportChunk => {
            if payload_len == 0 || payload_len > MGH1_MAX_BUGREPORT_CHUNK_BYTES {
                return Err(AppError::invalid_argument(format!(
                    "MGH1 bugreport chunk length {payload_len} outside 1..={MGH1_MAX_BUGREPORT_CHUNK_BYTES}"
                )));
            }
        }
    }
    Ok(())
}

/// Encodes one [`HandoffFrame`] into a bounded `MGH1` packet inside [`Zeroizing<Vec<u8>>`].
pub fn encode_mgh1_frame(frame: &HandoffFrame) -> AppResult<Zeroizing<Vec<u8>>> {
    let (frame_type, payload): (HandoffFrameType, Zeroizing<Vec<u8>>) = match frame {
        HandoffFrame::WorkerHello { protocol_version } => (
            HandoffFrameType::WorkerHello,
            Zeroizing::new(protocol_version.to_le_bytes().to_vec()),
        ),
        HandoffFrame::HandoffRequest(bytes) => (
            HandoffFrameType::HandoffRequest,
            Zeroizing::new(bytes.as_slice().to_vec()),
        ),
        HandoffFrame::HandoffStreamHeader(header) => {
            header.validate()?;
            let encoded = serde_json::to_vec(header).map_err(|err| {
                AppError::invalid_argument(format!("failed serializing stream header: {err}"))
            })?;
            (
                HandoffFrameType::HandoffStreamHeader,
                Zeroizing::new(encoded),
            )
        }
        HandoffFrame::BugreportChunk(chunk) => (
            HandoffFrameType::BugreportChunk,
            Zeroizing::new(chunk.clone()),
        ),
        HandoffFrame::HandoffResponse(bytes) => (
            HandoffFrameType::HandoffResponse,
            Zeroizing::new(bytes.clone()),
        ),
    };

    validate_mgh1_payload_len(frame_type, payload.len())?;
    let payload_len_u32 = u32::try_from(payload.len())
        .map_err(|_| AppError::invalid_argument("MGH1 frame payload length overflows u32"))?;

    let mut out = Zeroizing::new(Vec::with_capacity(MGH1_HEADER_LEN + payload.len()));
    out.extend_from_slice(&MGH1_MAGIC);
    out.push(frame_type as u8);
    out.extend_from_slice(&payload_len_u32.to_le_bytes());
    out.extend_from_slice(payload.as_slice());
    Ok(out)
}

/// Decodes and validates a 9-byte `MGH1` frame header without allocating payload memory.
pub fn decode_mgh1_header(header: &[u8; MGH1_HEADER_LEN]) -> AppResult<(HandoffFrameType, usize)> {
    let Some((magic, rest)) = header.split_at_checked(4) else {
        return Err(AppError::invalid_argument("truncated MGH1 header"));
    };
    if magic != MGH1_MAGIC {
        return Err(AppError::invalid_argument(
            "invalid MGH1 binary framing magic prefix",
        ));
    }
    let Some((&type_byte, len_slice)) = rest.split_first() else {
        return Err(AppError::invalid_argument("missing MGH1 frame type byte"));
    };
    let len_bytes: [u8; 4] = len_slice
        .try_into()
        .map_err(|_| AppError::invalid_argument("invalid MGH1 payload length field"))?;
    let frame_type = HandoffFrameType::from_u8(type_byte)?;
    let payload_len = usize::try_from(u32::from_le_bytes(len_bytes))
        .map_err(|_| AppError::invalid_argument("MGH1 frame length exceeds usize"))?;
    validate_mgh1_payload_len(frame_type, payload_len)?;
    Ok((frame_type, payload_len))
}

/// Decodes one `MGH1` frame from the beginning of `raw`, returning `(frame, consumed_bytes)`.
pub fn decode_mgh1_frame(raw: &[u8]) -> AppResult<(HandoffFrame, usize)> {
    let Some((hdr_slice, after_hdr)) = raw.split_at_checked(MGH1_HEADER_LEN) else {
        return Err(AppError::invalid_argument("truncated MGH1 frame header"));
    };
    let hdr_arr: [u8; MGH1_HEADER_LEN] = hdr_slice
        .try_into()
        .map_err(|_| AppError::invalid_argument("invalid MGH1 header slice"))?;
    let (frame_type, payload_len) = decode_mgh1_header(&hdr_arr)?;
    let Some((payload, _tail)) = after_hdr.split_at_checked(payload_len) else {
        return Err(AppError::invalid_argument("truncated MGH1 frame payload"));
    };
    let frame = parse_mgh1_payload(frame_type, payload)?;
    Ok((frame, MGH1_HEADER_LEN + payload_len))
}

fn parse_mgh1_payload(frame_type: HandoffFrameType, payload: &[u8]) -> AppResult<HandoffFrame> {
    match frame_type {
        HandoffFrameType::WorkerHello => {
            let ver_arr: [u8; 4] = payload.try_into().map_err(|_| {
                AppError::invalid_argument("MGH1 WorkerHello payload must be 4 bytes")
            })?;
            let protocol_version = u32::from_le_bytes(ver_arr);
            if protocol_version != MGH1_PROTOCOL_VERSION {
                return Err(AppError::invalid_argument(format!(
                    "unsupported MGH1 WorkerHello protocol_version {protocol_version}"
                )));
            }
            Ok(HandoffFrame::WorkerHello { protocol_version })
        }
        HandoffFrameType::HandoffRequest => Ok(HandoffFrame::HandoffRequest(Zeroizing::new(
            payload.to_vec(),
        ))),
        HandoffFrameType::HandoffStreamHeader => {
            let parsed: HandoffStreamHeaderPayload =
                serde_json::from_slice(payload).map_err(|err| {
                    AppError::invalid_argument(format!("invalid MGH1 stream header JSON: {err}"))
                })?;
            parsed.validate()?;
            Ok(HandoffFrame::HandoffStreamHeader(parsed))
        }
        HandoffFrameType::BugreportChunk => Ok(HandoffFrame::BugreportChunk(payload.to_vec())),
        HandoffFrameType::HandoffResponse => Ok(HandoffFrame::HandoffResponse(payload.to_vec())),
    }
}

/// Writes one `MGH1` frame asynchronously and flushes the stream, zeroizing encoded bytes on drop.
pub async fn write_mgh1_frame<W>(writer: &mut W, frame: &HandoffFrame) -> AppResult<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_mgh1_frame(frame)?;
    writer
        .write_all(encoded.as_slice())
        .await
        .map_err(|err| AppError::unavailable(format!("failed writing MGH1 frame: {err}")))?;
    writer
        .flush()
        .await
        .map_err(|err| AppError::unavailable(format!("failed flushing MGH1 frame: {err}")))?;
    Ok(())
}

/// Reads and validates one bounded `MGH1` frame asynchronously from `reader`.
pub async fn read_mgh1_frame<R>(reader: &mut R) -> AppResult<HandoffFrame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; MGH1_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|err| AppError::unavailable(format!("failed reading MGH1 header: {err}")))?;
    let (frame_type, payload_len) = decode_mgh1_header(&header)?;

    if frame_type == HandoffFrameType::HandoffRequest {
        let mut payload = Zeroizing::new(vec![0_u8; payload_len]);
        reader
            .read_exact(payload.as_mut_slice())
            .await
            .map_err(|err| {
                AppError::unavailable(format!("failed reading MGH1 request payload: {err}"))
            })?;
        return Ok(HandoffFrame::HandoffRequest(payload));
    }

    let mut payload = vec![0_u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|err| AppError::unavailable(format!("failed reading MGH1 payload: {err}")))?;
    parse_mgh1_payload(frame_type, &payload)
}

/// Unwraps `preauth_key` strictly inside `mesh-net` (`SEC-01` allowlist) and serializes a
/// [`HandoffRequest::UpWithSecret`] JSON payload inside [`Zeroizing<Vec<u8>>`] (`ADR-020`).
pub fn build_up_handoff_payload(
    server_endpoint: &str,
    port_override: Option<Port>,
    server_pin: Option<SpkiPin>,
    preauth_key: Option<&Secret<String>>,
    node_name: Option<NodeName>,
) -> AppResult<Zeroizing<Vec<u8>>> {
    let raw_key = match preauth_key {
        Some(secret) => {
            let value = secret.expose_secret();
            validate_preauth_key(value)?;
            Some(value.clone())
        }
        None => None,
    };
    let req = HandoffRequest::UpWithSecret {
        server_endpoint: server_endpoint.to_owned(),
        port_override: port_override.map(Port::get),
        server_pin: server_pin.map(|p| p.to_string()),
        preauth_key: raw_key,
        node_name: node_name.map(|n| n.as_str().to_owned()),
    };
    serialize_handoff_request_zeroizing(&req)
}

/// Unwraps `preauth_key` strictly inside `mesh-net` (`SEC-01` allowlist) and serializes a
/// [`HandoffRequest::RotateKeyWithSecret`] JSON payload inside [`Zeroizing<Vec<u8>>`] (`ADR-020`).
pub fn build_rotate_key_handoff_payload(
    preauth_key: &Secret<String>,
) -> AppResult<Zeroizing<Vec<u8>>> {
    let value = preauth_key.expose_secret();
    validate_preauth_key(value)?;
    let req = HandoffRequest::RotateKeyWithSecret {
        preauth_key: value.clone(),
    };
    serialize_handoff_request_zeroizing(&req)
}

/// Serializes any [`HandoffRequest`] variant inside a zeroized byte buffer (`<= 64 KiB`).
pub fn serialize_handoff_request_zeroizing(req: &HandoffRequest) -> AppResult<Zeroizing<Vec<u8>>> {
    let encoded = Zeroizing::new(serde_json::to_vec(req).map_err(|err| {
        AppError::invalid_argument(format!("failed serializing handoff request: {err}"))
    })?);
    validate_mgh1_payload_len(HandoffFrameType::HandoffRequest, encoded.len())?;
    Ok(encoded)
}

/// Parses a `0x01` frame's JSON bytes into [`HandoffRequest`].
pub fn parse_handoff_request_payload(payload: &[u8]) -> AppResult<HandoffRequest> {
    validate_mgh1_payload_len(HandoffFrameType::HandoffRequest, payload.len())?;
    serde_json::from_slice(payload).map_err(|err| {
        AppError::invalid_argument(format!("invalid MGH1 HandoffRequest JSON: {err}"))
    })
}

/// Converts a [`HandoffRequest::UpWithSecret`] into [`AgentUpRequest`] for `POST /v1/agent/up`.
pub fn handoff_request_to_agent_up(req: &HandoffRequest) -> AppResult<AgentUpRequest> {
    let HandoffRequest::UpWithSecret {
        server_endpoint,
        port_override,
        server_pin,
        preauth_key,
        node_name,
    } = req
    else {
        return Err(AppError::invalid_argument(
            "expected up_with_secret handoff request",
        ));
    };
    let port_override = port_override.map(Port::from_u16).transpose()?;
    let server_pin = server_pin.as_deref().map(SpkiPin::parse).transpose()?;
    if let Some(key) = preauth_key.as_deref() {
        validate_preauth_key(key)?;
    }
    let node_name = node_name.as_deref().map(NodeName::parse).transpose()?;

    Ok(AgentUpRequest {
        server_endpoint: server_endpoint.clone(),
        port_override,
        server_pin,
        preauth_key: preauth_key.clone(),
        node_name,
    })
}

/// Converts a [`HandoffRequest::RotateKeyWithSecret`] into [`AgentRotateKeyRequest`].
pub fn handoff_request_to_agent_rotate_key(
    req: &HandoffRequest,
) -> AppResult<AgentRotateKeyRequest> {
    let HandoffRequest::RotateKeyWithSecret { preauth_key } = req else {
        return Err(AppError::invalid_argument(
            "expected rotate_key_with_secret handoff request",
        ));
    };
    validate_preauth_key(preauth_key)?;
    Ok(AgentRotateKeyRequest {
        preauth_key: preauth_key.clone(),
    })
}

/// Explicitly wipes a zeroizing handoff buffer (e.g. immediately upon UAC `ERROR_CANCELLED`).
pub fn zeroize_handoff_payload(buf: &mut Zeroizing<Vec<u8>>) {
    buf.zeroize();
}

/// Formats a redacted preview of a [`Secret<String>`] pre-auth key for confirmation modals without
/// exposing the full key to `mesh-gui` (`SEC-01`).
#[must_use]
pub fn masked_preauth_preview_from_secret(preauth_key: &Secret<String>) -> String {
    mask_preauth_token(preauth_key.expose_secret())
}

#[cfg(test)]
mod tests {
    use mesh_core::brand::PREAUTH_KEY_PREFIX;
    use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
    use mesh_core::{AppError, NodeName, Port, SpkiPin};
    use mesh_crypto::{PreAuthToken, Secret};
    use mesh_proto::agent_ipc::{AgentActionResponse, DaemonState};
    use proptest::prelude::*;

    use super::{
        HandoffFrame, HandoffFrameType, HandoffRequest, HandoffResponse,
        HandoffStreamHeaderPayload, MGH1_HEADER_LEN, MGH1_MAX_BUGREPORT_CHUNK_BYTES,
        MGH1_MAX_CONTROL_FRAME_BYTES, MGH1_PROTOCOL_VERSION, MGH1_WORKER_HELLO_LEN,
        build_rotate_key_handoff_payload, build_up_handoff_payload, decode_mgh1_frame,
        decode_mgh1_header, encode_mgh1_frame, generate_handoff_pipe_name,
        handoff_request_to_agent_rotate_key, handoff_request_to_agent_up,
        masked_preauth_preview_from_secret, parse_handoff_request_payload, read_mgh1_frame,
        validate_handoff_pipe_name, write_mgh1_frame, zeroize_handoff_payload,
    };

    fn sample_preauth() -> String {
        PreAuthToken::generate().as_secret().expose_secret().clone()
    }

    #[test]
    fn test_gui_handoff_pipe_name_and_secret_redaction_and_conversion() {
        // Arrange
        let pipe = generate_handoff_pipe_name();
        let raw_key = sample_preauth();
        let secret = Secret::new(raw_key.clone());
        let pin = SpkiPin::from_sha256_bytes([0x12_u8; 32]);
        let port = Port::from_u16(8443).ok();
        let node = NodeName::parse("win-laptop").ok();

        // Act
        let valid_pipe = validate_handoff_pipe_name(&pipe);
        let payload = build_up_handoff_payload(
            "203.0.113.10:8443",
            port,
            Some(pin),
            Some(&secret),
            node.clone(),
        );
        let rot_payload = build_rotate_key_handoff_payload(&secret);
        let preview = masked_preauth_preview_from_secret(&secret);

        // Assert
        assert!(valid_pipe.is_ok());
        assert!(validate_handoff_pipe_name(r"\\.\pipe\mesh-agent-admin").is_err());
        assert!(preview.starts_with("mpk_"));
        assert!(!preview.contains(&raw_key));

        if let Ok(mut buf) = payload {
            let parsed_req = parse_handoff_request_payload(buf.as_slice());
            assert!(parsed_req.is_ok());
            if let Ok(req) = parsed_req {
                let dbg = format!("{req:?}");
                assert!(!dbg.contains(&raw_key));
                assert!(dbg.contains("[REDACTED]"));
                let agent_up = handoff_request_to_agent_up(&req);
                assert!(agent_up.is_ok());
                if let Ok(up) = agent_up {
                    assert_eq!(up.server_endpoint, "203.0.113.10:8443");
                    assert_eq!(up.port_override, port);
                    assert_eq!(up.server_pin, Some(pin));
                    assert_eq!(up.node_name, node);
                    assert_eq!(up.preauth_key.as_deref(), Some(raw_key.as_str()));
                }
            }
            zeroize_handoff_payload(&mut buf);
            assert!(buf.is_empty());
        }

        if let Ok(rot_buf) = rot_payload {
            let parsed_rot = parse_handoff_request_payload(rot_buf.as_slice());
            assert!(parsed_rot.is_ok());
            if let Ok(req) = parsed_rot {
                assert!(!format!("{req:?}").contains(&raw_key));
                let agent_rot = handoff_request_to_agent_rotate_key(&req);
                assert!(agent_rot.is_ok());
            }
        }
    }

    #[tokio::test]
    async fn test_gui_handoff_mgh1_async_framing_worker_hello_and_unauthenticated_response() {
        // Arrange
        let (mut client_io, mut server_io) = tokio::io::duplex(8192);
        let hello = HandoffFrame::WorkerHello {
            protocol_version: MGH1_PROTOCOL_VERSION,
        };
        let encoded_hello = encode_mgh1_frame(&hello);
        assert_eq!(
            encoded_hello.as_ref().ok().map(|v| v.len()),
            Some(MGH1_WORKER_HELLO_LEN)
        );

        let stream_hdr = HandoffFrame::HandoffStreamHeader(HandoffStreamHeaderPayload {
            total_bytes: 1024,
            scrubbed_items: 4,
        });
        let chunk = HandoffFrame::BugreportChunk(vec![0xab_u8; 512]);
        let auth_err = HandoffResponse::from_error(&AppError::unauthenticated("bad preauth token"));
        let err_json = serde_json::to_vec(&auth_err).unwrap_or_default();
        let resp_frame = HandoffFrame::HandoffResponse(err_json);

        // Act
        let write_fut = async {
            write_mgh1_frame(&mut client_io, &hello).await?;
            write_mgh1_frame(&mut client_io, &stream_hdr).await?;
            write_mgh1_frame(&mut client_io, &chunk).await?;
            write_mgh1_frame(&mut client_io, &resp_frame).await?;
            Ok::<_, AppError>(())
        };
        let read_fut = async {
            let f0 = read_mgh1_frame(&mut server_io).await?;
            let f2 = read_mgh1_frame(&mut server_io).await?;
            let f3 = read_mgh1_frame(&mut server_io).await?;
            let f4 = read_mgh1_frame(&mut server_io).await?;
            Ok::<_, AppError>((f0, f2, f3, f4))
        };
        let (w_res, r_res) = tokio::join!(write_fut, read_fut);

        // Assert
        assert!(w_res.is_ok());
        assert!(r_res.is_ok());
        if let Ok((f0, f2, f3, f4)) = r_res {
            assert_eq!(f0, hello);
            assert_eq!(f2, stream_hdr);
            assert_eq!(f3, chunk);
            if let HandoffFrame::HandoffResponse(bytes) = f4 {
                let parsed: Result<HandoffResponse, _> = serde_json::from_slice(&bytes);
                assert!(parsed.is_ok());
                if let Ok(resp) = parsed {
                    let act_res = resp.into_action_result();
                    assert_eq!(
                        act_res.err().map(|e| e.to_string()),
                        Some("authentication failed".to_owned())
                    );
                }
            }
        }

        let ok_action = HandoffResponse::from_action(AgentActionResponse {
            state: DaemonState::Connected,
            message: "tunnel up".to_owned(),
        });
        assert!(ok_action.into_action_result().is_ok());
    }

    #[test]
    fn test_gui_handoff_rejects_oversized_and_invalid_mgh1_headers() {
        // Arrange
        let mut bad_magic = [0_u8; MGH1_HEADER_LEN];
        if let Some(dst) = bad_magic.get_mut(..4) {
            dst.copy_from_slice(b"BAD!");
        }
        let mut bad_hello_len = [0_u8; MGH1_HEADER_LEN];
        if let Some(dst) = bad_hello_len.get_mut(..4) {
            dst.copy_from_slice(b"MGH1");
        }
        if let Some(len_dst) = bad_hello_len.get_mut(5..9) {
            len_dst.copy_from_slice(&8_u32.to_le_bytes());
        }
        let mut oversized_ctrl = [0_u8; MGH1_HEADER_LEN];
        if let Some(dst) = oversized_ctrl.get_mut(..5) {
            dst.copy_from_slice(b"MGH1\x01");
        }
        if let Some(len_dst) = oversized_ctrl.get_mut(5..9) {
            let over = u32::try_from(MGH1_MAX_CONTROL_FRAME_BYTES + 1).unwrap_or(u32::MAX);
            len_dst.copy_from_slice(&over.to_le_bytes());
        }
        let oversized_stream_hdr = HandoffStreamHeaderPayload {
            total_bytes: u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES + 1).unwrap_or(u64::MAX),
            scrubbed_items: 0,
        };

        // Act & Assert
        assert!(decode_mgh1_header(&bad_magic).is_err());
        assert!(decode_mgh1_header(&bad_hello_len).is_err());
        assert!(decode_mgh1_header(&oversized_ctrl).is_err());
        assert!(oversized_stream_hdr.validate().is_err());
        assert!(
            encode_mgh1_frame(&HandoffFrame::BugreportChunk(vec![
                1_u8;
                MGH1_MAX_BUGREPORT_CHUNK_BYTES
                    + 1
            ]))
            .is_err()
        );
        assert!(HandoffFrameType::from_u8(0xff).is_err());
    }

    proptest! {
        #[test]
        fn proptest_mgh1_roundtrip_and_arbitrary_bytes_never_panic(
            chunk_bytes in prop::collection::vec(any::<u8>(), 1..=1024),
            total_bytes in 1_u64..=20_971_520_u64,
            scrubbed in any::<u32>(),
            arbitrary in prop::collection::vec(any::<u8>(), 0..=256),
        ) {
            let chunk_frame = HandoffFrame::BugreportChunk(chunk_bytes.clone());
            let encoded = encode_mgh1_frame(&chunk_frame);
            prop_assert!(encoded.is_ok());
            if let Ok(bytes) = encoded {
                let decoded = decode_mgh1_frame(bytes.as_slice());
                prop_assert!(decoded.is_ok());
                if let Ok((frame, consumed)) = decoded {
                    prop_assert_eq!(consumed, bytes.len());
                    prop_assert_eq!(frame, chunk_frame);
                }
            }

            let hdr_frame = HandoffFrame::HandoffStreamHeader(HandoffStreamHeaderPayload {
                total_bytes,
                scrubbed_items: scrubbed,
            });
            let enc_hdr = encode_mgh1_frame(&hdr_frame);
            prop_assert!(enc_hdr.is_ok());
            if let Ok(bytes) = enc_hdr {
                let dec_hdr = decode_mgh1_frame(bytes.as_slice());
                prop_assert!(dec_hdr.is_ok());
            }

            let _ignored = decode_mgh1_frame(&arbitrary);
        }

        #[test]
        fn proptest_handoff_request_roundtrip_and_redacts_arbitrary_token(
            token_suffix in "[A-Za-z0-9_-]{43,64}",
        ) {
            let raw_key = format!("{PREAUTH_KEY_PREFIX}{token_suffix}");
            let req = HandoffRequest::RotateKeyWithSecret {
                preauth_key: raw_key.clone(),
            };
            let dbg = format!("{req:?}");
            prop_assert!(!dbg.contains(&raw_key));
            prop_assert!(dbg.contains("[REDACTED]"));

            let frame = HandoffFrame::HandoffRequest(
                super::serialize_handoff_request_zeroizing(&req)
                    .unwrap_or_else(|_| Default::default())
            );
            let frame_dbg = format!("{frame:?}");
            prop_assert!(!frame_dbg.contains(&raw_key));
        }
    }
}
