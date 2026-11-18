//! Cross-OS Desktop GUI Security Audit Suite (`WP-D-C2`, `US-116`).
//!
//! Enforces static and behavioral security invariants across Windows (`MeshVPN.exe`),
//! macOS (`Mesh VPN.app`), `crates/mesh-sys`, `crates/mesh-net`, and packaging scripts:
//! 1. `0` `expose_secret` calls and `0` `unsafe` keywords in `crates/mesh-gui/src/*.rs`, `0` direct
//!    `sha2`/`subtle` imports in `crates/mesh-gui/Cargo.toml`, and `100%` `// SAFETY:`
//!    coverage on every `unsafe` block/impl in `crates/mesh-sys/src/{gui_windows,process_windows}.rs`.
//! 2. `MGH1` framing security: `0x00 WorkerHello` (`13 B`) protocol version check, strict
//!    `\\.\pipe\mesh-gui-handoff-<32_lowercase_hex>` allowlist, `Zeroizing` payload wipe,
//!    and `ErrorKind::Unauthenticated` -> `"authentication failed"` (`SEC-05`).
//! 3. Zero-TOFU on IPv4 & IPv6 literals + `validate_preauth_key` (`mpk_` + `>= 32 B`
//!    `BASE64URL_NOPAD`, `<= 256` chars) parity across Rust (`onboarding.rs` / `mesh-core`)
//!    and macOS Swift (`EndpointNormalizer.swift` / `JoinUriParser.swift`).
//! 4. Atomic clipboard sequence + SHA-256 guard (`IG-DGUI-WA-01`) and post-dialog
//!    `PollingSuspensionGuard` ordering (`IG-DGUI-WA-03`).
//! 5. macOS & packaging invariants (`0` `app-sandbox`, `0` `CFBundleURLTypes`,
//!    `0` `NSAllowsArbitraryLoads`, `0` `import UIKit`, single `Window(..., id: "dashboard")`,
//!    `startMonitoring()` in `MeshApp.init()`, `.regular`/`.accessory` policy, `0` Gatekeeper
//!    master-disable, ADR-026 3-step signing order without `--deep`).
//! 6. Windows installer & shutdown event alignment (`scripts/install-windows.ps1` matches
//!    `Local\MeshVpnGuiShutdownEvent`, `MeshVpnAgent`, `mesh.exe cleanup`, and preserves
//!    `keys.json` unless `-PurgeData`).

#[path = "../src/app.rs"]
mod app;
#[path = "../src/clipboard.rs"]
mod clipboard;
#[path = "../src/onboarding.rs"]
mod onboarding;

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use mesh_core::{
    AppError, ErrorKind, MobileJoinTlsAuth, NodeId, NodeName, OverlayCidr, OverlayIp, Port,
    SpkiPin, format_join_uri, normalize_control_endpoint, validate_desktop_tls_policy,
    validate_preauth_key,
};
use mesh_crypto::Secret;
use mesh_net::gui_handoff::{
    HANDOFF_PIPE_PREFIX, HandoffFrame, HandoffFrameType, HandoffRequest, HandoffResponse,
    HandoffStreamHeaderPayload, MGH1_HEADER_LEN, MGH1_PROTOCOL_VERSION, MGH1_WORKER_HELLO_LEN,
    build_rotate_key_handoff_payload, build_up_handoff_payload, decode_mgh1_frame,
    decode_mgh1_header, encode_mgh1_frame, generate_handoff_pipe_name,
    handoff_request_to_agent_rotate_key, handoff_request_to_agent_up,
    masked_preauth_preview_from_secret, parse_handoff_request_payload, validate_handoff_pipe_name,
    zeroize_handoff_payload,
};
use mesh_net::ipc::AgentVersionStatus;
use mesh_proto::agent_ipc::{
    AgentStatusResponse, DaemonState, SelfNetworkStatus, ServerConnectionStatus, TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;
use proptest::prelude::*;

use crate::app::{
    AgentVersionIndicator, DesktopUiState, ServiceProbeKind, StateProbeInputs, TunnelSubState,
    derive_desktop_ui_state, derive_version_indicator, format_user_facing_error,
    is_status_enrolled, sanitize_gui_log_text,
};
use crate::clipboard::{CLIPBOARD_WIPE_DELAY_MS, ClipboardSecretGuard, looks_like_sensitive_paste};
use crate::onboarding::{
    ConfirmActionKind, OnboardingFormInput, OnboardingTlsMode, parse_mesh_join_uri_to_draft,
    should_lock_system_ca_for_endpoint, validate_manual_onboarding_to_draft,
    validate_rotate_key_to_draft, validate_update_server_payload,
};

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "failed resolving workspace root from CARGO_MANIFEST_DIR".to_owned())
}

fn read_repo_file(rel_path: &str) -> Result<String, String> {
    let root = workspace_root()?;
    let full = root.join(rel_path);
    fs::read_to_string(&full).map_err(|err| format!("failed reading {}: {err}", full.display()))
}

fn collect_files_with_ext(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|err| format!("failed reading dir {}: {err}", dir.display()))?;
    for entry_res in entries {
        let entry = entry_res.map_err(|err| err.to_string())?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name == ".build" || name == "DerivedData" || name.ends_with(".xcodeproj") {
            continue;
        }
        let file_type = entry.file_type().map_err(|err| err.to_string())?;
        if file_type.is_dir() {
            collect_files_with_ext(&path, ext, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case(ext))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Strips `//` line comments and `/* ... */` block comments while preserving line structure
/// so static source audits never false-positive on doc comments.
fn strip_comments_preserving_lines(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut string_escape = false;

    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                out.push('\n');
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                let _slash = chars.next();
                in_block_comment = false;
                out.push(' ');
            } else if ch == '\n' {
                out.push('\n');
            }
            continue;
        }
        if in_string {
            out.push(ch);
            if string_escape {
                string_escape = false;
            } else if ch == '\\' {
                string_escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            let _slash = chars.next();
            in_line_comment = true;
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            let _star = chars.next();
            in_block_comment = true;
            continue;
        }
        if ch == '"' {
            in_string = true;
        }
        out.push(ch);
    }
    out
}

fn contains_unsafe_token(code_line: &str) -> bool {
    let unsafe_kw = concat!("un", "safe");
    let trimmed = code_line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let tokens: Vec<&str> = trimmed
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty())
        .collect();
    tokens.contains(&unsafe_kw)
}

#[test]
fn test_rust_gui_zero_expose_secret_zero_unsafe_and_mesh_sys_safety_comments() -> Result<(), String>
{
    let root = workspace_root()?;
    let gui_src_dir = root.join("crates/mesh-gui/src");
    let mut gui_rs_files = Vec::new();
    collect_files_with_ext(&gui_src_dir, "rs", &mut gui_rs_files)?;
    gui_rs_files.sort();
    assert!(
        gui_rs_files.len() >= 11,
        "expected >= 11 source files in crates/mesh-gui/src, found {}",
        gui_rs_files.len()
    );

    let expose_needle = concat!(".expose", "_secret");
    let allow_attr_needle = concat!("#[", "allow(");
    let unwrap_needle = concat!(".un", "wrap(");
    let expect_needle = concat!(".ex", "pect(");
    let panic_needle = concat!("pa", "nic!(");
    let println_needle = concat!("print", "ln!(");
    let eprintln_needle = concat!("eprint", "ln!(");

    for path in &gui_rs_files {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let raw = fs::read_to_string(path).map_err(|e| format!("{rel}: {e}"))?;
        let prod_section = raw.split("#[cfg(all(test,").next().unwrap_or(&raw);
        let prod_section = prod_section
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(prod_section);
        let stripped = strip_comments_preserving_lines(&raw);
        let stripped_prod = strip_comments_preserving_lines(prod_section);

        assert!(
            !stripped.contains(expose_needle),
            "SEC-01 violation: forbidden {expose_needle} in {rel}"
        );
        assert!(
            !stripped.contains(allow_attr_needle),
            "coding-standards violation: forbidden {allow_attr_needle} in {rel}"
        );
        for (line_idx, line) in stripped.lines().enumerate() {
            assert!(
                !contains_unsafe_token(line),
                "ADR-020 violation: forbidden unsafe keyword in {rel}:{}",
                line_idx + 1
            );
        }
        for forbidden in [
            unwrap_needle,
            expect_needle,
            panic_needle,
            println_needle,
            eprintln_needle,
        ] {
            assert!(
                !stripped_prod.contains(forbidden),
                "forbidden `{forbidden}` in production GUI source {rel}"
            );
        }
        assert!(
            !stripped_prod.contains(":443") && !stripped_prod.contains(":3478"),
            "GNFR-11 violation: hardcoded default port in {rel}"
        );
        assert!(
            !stripped_prod.contains(r"Software\Classes\mesh"),
            "DGUI-SEC-02 violation: forbidden mesh: URL protocol registration in {rel}"
        );
    }

    // Verify crates/mesh-gui/Cargo.toml uses workspace lints and mesh-crypto (0 sha2 / subtle)
    let gui_cargo_toml = read_repo_file("crates/mesh-gui/Cargo.toml")?;
    assert!(gui_cargo_toml.contains("[lints]"));
    assert!(gui_cargo_toml.contains("workspace = true"));
    assert!(gui_cargo_toml.contains("mesh-crypto"));
    assert!(!gui_cargo_toml.contains("sha2"));
    assert!(!gui_cargo_toml.contains("subtle"));
    assert!(!gui_cargo_toml.contains("embed-resource"));
    assert!(!gui_cargo_toml.contains("winres"));

    // Verify every `unsafe` block and `unsafe` impl in `gui_windows.rs` and `process_windows.rs`
    // is preceded by a `// SAFETY:` justification comment.
    let unsafe_block_kw = concat!("un", "safe {");
    let unsafe_impl_kw = concat!("un", "safe impl");
    for sys_rel in [
        "crates/mesh-sys/src/gui_windows.rs",
        "crates/mesh-sys/src/process_windows.rs",
    ] {
        let sys_src = read_repo_file(sys_rel)?;
        let lines: Vec<&str> = sys_src.lines().collect();
        let mut verified_blocks = 0usize;
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains(unsafe_block_kw) || trimmed.contains(unsafe_impl_kw) {
                let start = idx.saturating_sub(8);
                let window = lines.get(start..=idx).unwrap_or(&[]);
                let has_safety = window.iter().any(|prev| prev.contains("// SAFETY:"));
                assert!(
                    has_safety,
                    "missing `// SAFETY:` comment before unsafe block at {sys_rel}:{}",
                    idx + 1
                );
                verified_blocks += 1;
            }
        }
        assert!(
            verified_blocks >= 10,
            "expected >= 10 verified unsafe blocks in {sys_rel}, found {verified_blocks}"
        );
    }

    // Verify `process_windows.rs` never uses `CREATE_BREAKAWAY_FROM_JOB` (`HR-DGUI-G2-01`)
    let proc_win =
        strip_comments_preserving_lines(&read_repo_file("crates/mesh-sys/src/process_windows.rs")?);
    assert!(!proc_win.contains("CREATE_BREAKAWAY_FROM_JOB"));
    assert!(proc_win.contains("CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS"));

    // Verify `ADMIN_PIPE_SDDL` in `crates/mesh-net/src/ipc_windows.rs` remains strict SY+BA
    let ipc_win = read_repo_file("crates/mesh-net/src/ipc_windows.rs")?;
    assert!(ipc_win.contains(r#"ADMIN_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)""#));

    Ok(())
}

#[test]
fn test_mgh1_framing_security_worker_hello_pipe_allowlist_zeroize_and_sec05() -> Result<(), String>
{
    // 1. Frame 0x00 WorkerHello must be exactly 13 bytes with protocol_version == 1
    assert_eq!(MGH1_HEADER_LEN, 9);
    assert_eq!(MGH1_WORKER_HELLO_LEN, 13);
    assert_eq!(MGH1_PROTOCOL_VERSION, 1);

    let valid_hello = HandoffFrame::WorkerHello {
        protocol_version: MGH1_PROTOCOL_VERSION,
    };
    let encoded_hello = encode_mgh1_frame(&valid_hello).map_err(|e| e.to_string())?;
    assert_eq!(encoded_hello.len(), MGH1_WORKER_HELLO_LEN);
    let (decoded_hello, consumed) =
        decode_mgh1_frame(encoded_hello.as_slice()).map_err(|e| e.to_string())?;
    assert_eq!(consumed, MGH1_WORKER_HELLO_LEN);
    assert_eq!(decoded_hello, valid_hello);

    // Unsupported WorkerHello protocol_version (0 or 2) must fail closed
    for bad_ver in [0_u32, 2_u32, u32::MAX] {
        let bad_frame = HandoffFrame::WorkerHello {
            protocol_version: bad_ver,
        };
        let raw = encode_mgh1_frame(&bad_frame).map_err(|e| e.to_string())?;
        assert!(
            decode_mgh1_frame(raw.as_slice()).is_err(),
            "WorkerHello version {bad_ver} must be rejected"
        );
    }

    // WorkerHello with non-4-byte length in header must fail closed before allocation
    let mut bad_hdr = [0_u8; MGH1_HEADER_LEN];
    if let Some(m) = bad_hdr.get_mut(..4) {
        m.copy_from_slice(b"MGH1");
    }
    if let Some(len_slice) = bad_hdr.get_mut(5..9) {
        len_slice.copy_from_slice(&12_u32.to_le_bytes());
    }
    assert!(decode_mgh1_header(&bad_hdr).is_err());
    assert_eq!(
        HandoffFrameType::from_u8(0x00).ok(),
        Some(HandoffFrameType::WorkerHello)
    );
    assert!(HandoffFrameType::from_u8(0x05).is_err());

    // 2. Ephemeral pipe name allowlist (`\\.\pipe\mesh-gui-handoff-<32_lowercase_hex>`)
    let generated_pipe = generate_handoff_pipe_name();
    assert!(generated_pipe.starts_with(HANDOFF_PIPE_PREFIX));
    assert!(validate_handoff_pipe_name(&generated_pipe).is_ok());

    for forbidden_pipe in [
        "",
        r"\\.\pipe\mesh-agent-admin",
        r"\\.\pipe\mesh-agent-ro",
        r"\\.\pipe\mesh-gui-handoff-",
        r"\\.\pipe\mesh-gui-handoff-0123456789abcdef",
        r"\\.\pipe\mesh-gui-handoff-0123456789abcdef0123456789ABCDEF",
        r"\\.\pipe\mesh-gui-handoff-0123456789abcdef0123456789abcdeg",
        r"\\.\pipe\mesh-gui-handoff-..\..\Windows\System32\cmd.exe",
        r"\\192.168.1.1\pipe\mesh-gui-handoff-0123456789abcdef0123456789abcdef",
    ] {
        assert!(
            validate_handoff_pipe_name(forbidden_pipe).is_err(),
            "forbidden pipe name `{forbidden_pipe}` must be rejected"
        );
    }

    // 3. Zeroizing handoff wipe & 0 secret exposure in Debug/outputs (`SEC-01`)
    let canary_token = "mpk_QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODk";
    let secret = Secret::new(canary_token.to_owned());
    let pin =
        SpkiPin::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .map_err(|e| e.to_string())?;
    let port = Port::from_u16(8443).map_err(|e| e.to_string())?;
    let node_name = NodeName::parse("audit-win-node").map_err(|e| e.to_string())?;

    let mut up_payload = build_up_handoff_payload(
        "198.51.100.10:8443",
        Some(port),
        Some(pin),
        Some(&secret),
        Some(node_name),
    )
    .map_err(|e| e.to_string())?;
    let req_frame = HandoffFrame::HandoffRequest(up_payload.clone());
    assert!(!format!("{req_frame:?}").contains(canary_token));

    let parsed_up =
        parse_handoff_request_payload(up_payload.as_slice()).map_err(|e| e.to_string())?;
    assert!(!format!("{parsed_up:?}").contains(canary_token));
    let agent_up = handoff_request_to_agent_up(&parsed_up).map_err(|e| e.to_string())?;
    assert!(!format!("{agent_up:?}").contains(canary_token));

    zeroize_handoff_payload(&mut up_payload);
    assert!(up_payload.is_empty());

    let mut rot_payload = build_rotate_key_handoff_payload(&secret).map_err(|e| e.to_string())?;
    let parsed_rot =
        parse_handoff_request_payload(rot_payload.as_slice()).map_err(|e| e.to_string())?;
    assert!(!format!("{parsed_rot:?}").contains(canary_token));
    let agent_rot = handoff_request_to_agent_rotate_key(&parsed_rot).map_err(|e| e.to_string())?;
    assert!(!format!("{agent_rot:?}").contains(canary_token));
    zeroize_handoff_payload(&mut rot_payload);
    assert!(rot_payload.is_empty());

    // 4. SEC-05: ErrorKind::Unauthenticated always maps to exact `"authentication failed"`
    let raw_unauth = AppError::unauthenticated(format!("rejected token {canary_token}"));
    assert_eq!(raw_unauth.kind(), ErrorKind::Unauthenticated);
    assert_eq!(raw_unauth.to_string(), "authentication failed");
    let handoff_err = HandoffResponse::from_error(&raw_unauth);
    let action_err = handoff_err
        .into_action_result()
        .err()
        .ok_or_else(|| "expected Err from unauthenticated HandoffResponse".to_owned())?;
    assert_eq!(action_err.kind(), ErrorKind::Unauthenticated);
    assert_eq!(action_err.to_string(), "authentication failed");
    assert_eq!(
        format_user_facing_error(&format!("Unauthenticated: key={canary_token}")),
        "authentication failed"
    );
    assert!(
        format_user_facing_error("UAC prompt cancelled by user").contains("Elevation cancelled")
    );

    let stream_hdr = HandoffStreamHeaderPayload {
        total_bytes: 4096,
        scrubbed_items: 2,
    };
    assert!(stream_hdr.validate().is_ok());
    let export_req = HandoffRequest::ExportBugreportStream;
    assert_eq!(format!("{export_req:?}"), "ExportBugreportStream");
    let ok_bug = HandoffResponse::from_bugreport(2, 4096);
    assert!(ok_bug.ok);

    Ok(())
}

#[test]
fn test_zero_tofu_and_preauth_key_parity_across_rust_and_macos_swift() -> Result<(), String> {
    let valid_pin_raw = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let valid_pin = SpkiPin::parse(valid_pin_raw).map_err(|e| e.to_string())?;
    let valid_key = "mpk_QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";

    // 1. Rust Zero-TOFU & endpoint normalization (`mesh_core` + `onboarding.rs`)
    for ip_endpoint in [
        "198.51.100.10",
        "198.51.100.10:8443",
        "2001:db8::1",
        "[2001:db8::1]",
        "[2001:db8::1]:8443",
    ] {
        assert!(
            should_lock_system_ca_for_endpoint(ip_endpoint),
            "System CA must be locked for IP literal `{ip_endpoint}`"
        );
        assert!(
            validate_desktop_tls_policy(ip_endpoint, None, MobileJoinTlsAuth::SystemCa).is_err(),
            "validate_desktop_tls_policy must reject IP + SystemCa for `{ip_endpoint}`"
        );
        assert!(
            validate_manual_onboarding_to_draft(&OnboardingFormInput {
                endpoint_raw: ip_endpoint.to_owned(),
                tls_mode: OnboardingTlsMode::SystemCa,
                spki_pin_raw: String::new(),
                preauth_key_raw: valid_key.to_owned(),
                node_name_raw: "node-1".to_owned(),
            })
            .is_err()
        );
        assert!(
            validate_update_server_payload(ip_endpoint, OnboardingTlsMode::SystemCa, "").is_err()
        );
    }

    assert!(!should_lock_system_ca_for_endpoint("vpn.example.com:8443"));
    assert!(!should_lock_system_ca_for_endpoint(""));
    assert!(normalize_control_endpoint("999.999.999.999:8443", None).is_err());
    assert!(normalize_control_endpoint("vpn.example.com:0443", None).is_err());

    // 2. Rust `validate_preauth_key` boundary rules (`mpk_` + `>= 32 B` base64url, `<= 256` chars)
    assert!(validate_preauth_key(valid_key).is_ok());
    let short_key = "mpk_QUFBQUFBQUFBQUFBQUFBQQ"; // < 32 bytes decoded
    let no_prefix = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";
    let padded_key = "mpk_QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";
    let overlong_key = format!("mpk_{}", "A".repeat(260));
    for bad_key in [short_key, no_prefix, padded_key, overlong_key.as_str(), ""] {
        assert!(
            validate_preauth_key(bad_key).is_err(),
            "invalid preauth key `{bad_key}` must be rejected"
        );
    }

    // Exercise onboarding draft builders & confirmation summary redaction
    let manual_draft = validate_manual_onboarding_to_draft(&OnboardingFormInput {
        endpoint_raw: "[2001:db8::1]".to_owned(),
        tls_mode: OnboardingTlsMode::SpkiPin,
        spki_pin_raw: valid_pin_raw.to_owned(),
        preauth_key_raw: valid_key.to_owned(),
        node_name_raw: "win-audit".to_owned(),
    })?;
    assert_eq!(manual_draft.action_kind, ConfirmActionKind::EnrollNewNode);
    assert_eq!(manual_draft.normalized_endpoint, "[2001:db8::1]:443");
    assert_eq!(manual_draft.tls_mode, OnboardingTlsMode::SpkiPin);
    assert_eq!(manual_draft.server_pin, Some(valid_pin));
    assert_eq!(
        manual_draft.node_name.as_ref().map(NodeName::as_str),
        Some("win-audit")
    );
    assert!(manual_draft.port_override.is_some());
    assert!(!manual_draft.masked_preauth_preview.contains(valid_key));
    assert!(
        !manual_draft
            .format_confirmation_summary()
            .contains(valid_key)
    );
    assert!(!format!("{manual_draft:?}").contains(valid_key));
    assert!(manual_draft.build_handoff_payload().is_ok());

    let join_uri = format_join_uri(
        "198.51.100.10:8443",
        &MobileJoinTlsAuth::SpkiPin(valid_pin),
        valid_key,
        Some(&NodeName::parse("uri-node").map_err(|e| e.to_string())?),
    )
    .map_err(|e| e.to_string())?;
    let (parsed_form, uri_draft) = parse_mesh_join_uri_to_draft(&join_uri, "")?;
    assert!(!format!("{parsed_form:?}").contains(valid_key));
    assert!(!uri_draft.format_confirmation_summary().contains(valid_key));

    let rot_draft = validate_rotate_key_to_draft(
        "198.51.100.10:8443",
        OnboardingTlsMode::SpkiPin,
        Some(valid_pin),
        valid_key,
    )?;
    assert_eq!(rot_draft.action_kind, ConfirmActionKind::RotateKey);
    assert!(!rot_draft.format_confirmation_summary().contains(valid_key));
    assert!(rot_draft.build_handoff_payload().is_ok());

    let (norm_ep, set_payload) = validate_update_server_payload(
        "198.51.100.10:8443",
        OnboardingTlsMode::SpkiPin,
        valid_pin_raw,
    )?;
    assert_eq!(norm_ep, "198.51.100.10:8443");
    assert!(!set_payload.is_empty());

    // 3. macOS Swift `EndpointNormalizer.swift` & `JoinUriParser.swift` parity audit (`IG-DGUI-WA-02`)
    let swift_normalizer = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Validation/EndpointNormalizer.swift",
    )?;
    assert!(swift_normalizer.contains("normalized.isIpLiteral && tlsAuthMode == .systemCa"));
    assert!(swift_normalizer.contains("portStr.hasPrefix(\"0\")"));
    assert!(swift_normalizer.contains("lastLabelHasAlpha"));
    assert!(swift_normalizer.contains("parseStrictIPv4"));
    assert!(swift_normalizer.contains("parseCanonicalIPv6"));

    let swift_uri_parser = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Validation/JoinUriParser.swift",
    )?;
    assert!(swift_uri_parser.contains("public static func validatePreauthKey"));
    assert!(swift_uri_parser.contains("AgentDefaults.maxPreauthKeyLen"));
    assert!(swift_uri_parser.contains("AgentDefaults.preauthKeyPrefix"));
    assert!(swift_uri_parser.contains("JoinUriCodec.decodeBase64UrlNoPad"));
    assert!(swift_uri_parser.contains("decoded.resetBytes(in: 0..<byteCount)"));
    assert!(swift_uri_parser.contains("guard byteCount >= 32 else"));

    Ok(())
}

#[test]
fn test_atomic_clipboard_guard_and_post_dialog_polling_suspension_contracts() -> Result<(), String>
{
    // 1. Behavioral test of `ClipboardSecretGuard` (`IG-DGUI-WA-01`)
    assert_eq!(CLIPBOARD_WIPE_DELAY_MS, 30_000);
    let secret_paste = "mpk_R0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkwMTI";
    assert!(looks_like_sensitive_paste(secret_paste));
    assert!(looks_like_sensitive_paste(
        "mesh://join?v=1&ep=198.51.100.10:8443&key=mpk_abc"
    ));
    assert!(!looks_like_sensitive_paste("normal text with spaces"));

    let mut guard = ClipboardSecretGuard::arm(700, secret_paste);
    assert!(guard.is_armed());
    assert_eq!(guard.expected_seq(), 700);
    assert!(!format!("{guard:?}").contains(secret_paste));
    assert!(guard.matches_text(secret_paste));
    assert!(!guard.matches_text("other_clipboard_text"));

    // Sequence mismatch does not clear
    let mut seq_mismatch = guard.clone();
    assert!(!seq_mismatch.evaluate_clear(701, Some(secret_paste)));
    assert!(!seq_mismatch.is_armed());

    // Exact (seq, sha256) match clears and disarms
    assert!(guard.evaluate_clear(700, Some(secret_paste)));
    assert!(!guard.is_armed());
    guard.disarm();
    assert!(!guard.is_armed());

    #[cfg(target_os = "windows")]
    {
        let mut disarmed = ClipboardSecretGuard::arm(1, secret_paste);
        disarmed.disarm();
        assert_eq!(
            crate::clipboard::attempt_atomic_clipboard_clear(&mut disarmed).ok(),
            Some(false)
        );
    }

    // 2. Static verification of single-lock `ClipboardGuard` in `gui_windows.rs` (`IG-DGUI-WA-01`)
    let gui_win_src = read_repo_file("crates/mesh-sys/src/gui_windows.rs")?;
    assert!(gui_win_src.contains("pub fn clear_clipboard_if_seq_and_predicate"));
    assert!(gui_win_src.contains("let _guard = open_clipboard_with_retry(OP)?;"));
    assert!(gui_win_src.contains("GetClipboardSequenceNumber()"));
    assert!(gui_win_src.contains("EmptyClipboard()"));

    // 3. Static verification of macOS `ClipboardAutoClear.swift` & `OnboardingSheetView.swift`
    let mac_clip_src = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Security/ClipboardAutoClear.swift",
    )?;
    assert!(mac_clip_src.contains("pasteboard.changeCount == target.recordedChangeCount"));
    assert!(mac_clip_src.contains("SHA256.hash"));
    let mac_onboarding_src =
        read_repo_file("desktop/macos/MeshVPNApp/Sources/OnboardingSheetView.swift")?;
    assert!(mac_onboarding_src.contains("PasteButton(payloadType: String.self)"));
    assert!(mac_onboarding_src.contains("scheduleWipeIfClipboardMatchesFieldText"));

    // 4. Post-dialog `PollingSuspensionGuard` ordering (`IG-DGUI-WA-03`):
    //    - Windows: `save_tar_file_dialog` runs in `window.rs` BEFORE `spawn_bugreport_export`,
    //      and `poll_control.suspend()` is only invoked inside `spawn_bugreport_export`.
    let win_window_src = read_repo_file("crates/mesh-gui/src/window.rs")?;
    let save_dlg_pos = win_window_src
        .find("save_tar_file_dialog(")
        .ok_or_else(|| "missing save_tar_file_dialog in window.rs".to_owned())?;
    let spawn_export_pos = win_window_src
        .find("spawn_bugreport_export(")
        .ok_or_else(|| "missing spawn_bugreport_export in window.rs".to_owned())?;
    assert!(
        save_dlg_pos < spawn_export_pos,
        "save_tar_file_dialog must precede spawn_bugreport_export in window.rs"
    );
    assert!(
        !win_window_src.contains(".suspend()"),
        "window.rs must not suspend polling while SaveFileDialog modal is open"
    );
    let win_poller_src = read_repo_file("crates/mesh-gui/src/ipc_poller.rs")?;
    assert!(win_poller_src.contains("let _pause_guard = poll_control.suspend();"));

    //    - macOS: `panel.runModal()` runs in `DiagnosticsSheetView.swift` BEFORE
    //      `store.exportBugreport(to: destinationURL)`, which enters `withSuspendedPolling`.
    let mac_diag_sheet =
        read_repo_file("desktop/macos/MeshVPNApp/Sources/DiagnosticsSheetView.swift")?;
    let modal_pos = mac_diag_sheet
        .find("panel.runModal()")
        .ok_or_else(|| "missing panel.runModal() in DiagnosticsSheetView.swift".to_owned())?;
    let export_call_pos = mac_diag_sheet
        .find("store.exportBugreport(to: destinationURL)")
        .ok_or_else(|| "missing store.exportBugreport in DiagnosticsSheetView.swift".to_owned())?;
    assert!(
        modal_pos < export_call_pos,
        "NSSavePanel.runModal() must precede store.exportBugreport(to:)"
    );
    assert!(!mac_diag_sheet.contains("withSuspendedPolling"));

    Ok(())
}

#[test]
fn test_macos_bundle_swift_packaging_and_windows_installer_invariants() -> Result<(), String> {
    let root = workspace_root()?;
    let macos_dir = root.join("desktop/macos");

    // 1. Scan `desktop/macos/**` for forbidden entitlements, URL schemes, ATS bypass, and UIKit
    let project_yml = read_repo_file("desktop/macos/project.yml")?;
    assert!(project_yml.contains("ENABLE_APP_SANDBOX: \"NO\""));
    assert!(project_yml.contains("SWIFT_VERSION: \"6.0\""));
    assert!(project_yml.contains("SWIFT_STRICT_CONCURRENCY: complete"));
    assert!(project_yml.contains("MARKETING_VERSION: \"0.3.0\""));

    let info_plist = read_repo_file("desktop/macos/MeshVPNApp/Resources/Info.plist")?;
    assert!(info_plist.contains("<key>LSUIElement</key>"));
    assert!(info_plist.contains("<true/>"));
    assert!(!info_plist.contains("CFBundleURLTypes"));
    assert!(!info_plist.contains("NSAllowsArbitraryLoads"));
    assert!(!info_plist.contains("com.apple.security.app-sandbox"));

    let entitlements = read_repo_file("desktop/macos/MeshVPNApp/Resources/MeshVPN.entitlements")?;
    assert!(!entitlements.contains("com.apple.security.app-sandbox"));

    let mut swift_files = Vec::new();
    collect_files_with_ext(&macos_dir, "swift", &mut swift_files)?;
    swift_files.sort();
    assert!(!swift_files.is_empty());

    let spctl_disable = concat!("spctl", " --master-disable");
    for sf in &swift_files {
        let rel = sf
            .strip_prefix(&root)
            .unwrap_or(sf)
            .to_string_lossy()
            .replace('\\', "/");
        let raw = fs::read_to_string(sf).map_err(|e| format!("{rel}: {e}"))?;
        let stripped = strip_comments_preserving_lines(&raw);
        for line in stripped.lines() {
            let t = line.trim_start();
            assert!(
                !t.starts_with("import UIKit"),
                "ADR-025 violation: forbidden `import UIKit` in {rel}"
            );
        }
        assert!(
            !raw.contains(spctl_disable),
            "forbidden Gatekeeper bypass in {rel}"
        );
    }

    // 2. Verify `MeshApp.swift` single-window scene, `startMonitoring()`, and `.regular`/`.accessory`
    let mesh_app_swift = read_repo_file("desktop/macos/MeshVPNApp/Sources/MeshApp.swift")?;
    assert_eq!(
        mesh_app_swift
            .matches("Window(\"Mesh VPN\", id: \"dashboard\")")
            .count(),
        1,
        "MeshApp.swift must declare exactly one single-instance Dashboard Window scene"
    );
    assert!(mesh_app_swift.contains("initialStore.startMonitoring()"));
    assert!(mesh_app_swift.contains("NSApp.setActivationPolicy(.regular)"));
    assert!(mesh_app_swift.contains("NSApp.setActivationPolicy(.accessory)"));
    assert!(mesh_app_swift.contains("CommandGroup(replacing: .newItem) {}"));

    // 3. Verify `scripts/package-macos-app.sh` & `scripts/install-macos.sh` ADR-026 invariants
    let pkg_macos = read_repo_file("scripts/package-macos-app.sh")?;
    assert!(!pkg_macos.contains(spctl_disable));
    let has_deep_codesign_call = pkg_macos.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#')
            && !trimmed.starts_with("echo ")
            && trimmed.contains("codesign")
            && trimmed.contains("--deep")
    });
    assert!(
        !has_deep_codesign_call,
        "ADR-026 violation: package-macos-app.sh must never pass `--deep` to codesign"
    );
    let step1_pos = pkg_macos
        .find("STEP 1 (ADR-026 Immutable Order): Sign inner binaries FIRST")
        .ok_or_else(|| "missing STEP 1 marker in package-macos-app.sh".to_owned())?;
    let step2_pos = pkg_macos
        .find("STEP 2 (ADR-026 Immutable Order): Generate SHA256SUMS & embed Resources")
        .ok_or_else(|| "missing STEP 2 marker in package-macos-app.sh".to_owned())?;
    let step3_pos = pkg_macos
        .find("STEP 3 (ADR-026 Immutable Order): Sign outer Mesh VPN.app WITHOUT --deep")
        .ok_or_else(|| "missing STEP 3 marker in package-macos-app.sh".to_owned())?;
    assert!(step1_pos < step2_pos && step2_pos < step3_pos);

    let install_macos = read_repo_file("scripts/install-macos.sh")?;
    assert!(!install_macos.contains(spctl_disable));
    assert!(install_macos.contains("if /usr/bin/codesign -v \"${target_path}\""));
    assert!(install_macos.contains("DAEMON_DIR=\"/usr/local/libexec/mesh\""));
    assert!(install_macos.contains("--uninstall"));
    assert!(install_macos.contains("--purge"));

    // 4. Verify `scripts/install-windows.ps1` matches `gui_windows.rs` constants & cleanup contract
    let install_win = read_repo_file("scripts/install-windows.ps1")?;
    let gui_win = read_repo_file("crates/mesh-sys/src/gui_windows.rs")?;
    assert!(
        gui_win
            .contains(r#"pub const GUI_SHUTDOWN_EVENT: &str = r"Local\MeshVpnGuiShutdownEvent";"#)
    );
    assert!(gui_win.contains(r#"pub const WINDOWS_SERVICE_NAME: &str = "MeshVpnAgent";"#));
    assert!(install_win.contains(r#"$GuiShutdownEventName = "Local\MeshVpnGuiShutdownEvent""#));
    assert!(install_win.contains(r#"$ServiceName = "MeshVpnAgent""#));
    assert!(install_win.contains("cleanup"));
    for required_file in [
        "MeshVPN.exe",
        "meshd.exe",
        "mesh.exe",
        "mesh-server.exe",
        "wintun.dll",
        "wintun.dll.sha256",
        "WINTUN-LICENSE.txt",
        "README-WINTUN.md",
    ] {
        assert!(
            install_win.contains(required_file),
            "install-windows.ps1 missing bundle file `{required_file}`"
        );
    }
    assert!(install_win.contains("keys.json"));
    assert!(install_win.contains("PurgeData"));

    // 5. Verify `.github/workflows/release.yml` lists `MeshVPN.exe` explicitly in `SHA256SUMS`
    let release_yml = read_repo_file(".github/workflows/release.yml")?;
    assert!(release_yml.contains(
        "sha256sum MeshVPN.exe mesh.exe meshd.exe mesh-server.exe wintun.dll > SHA256SUMS"
    ));

    Ok(())
}

#[test]
fn test_gate3_remediation_sddl_oici_keep_app_darwin_rename_swift6_and_poller_suspend()
-> Result<(), String> {
    // 1. `Package.swift` uses Swift 6.0 without redundant `StrictConcurrency` upcoming feature
    let package_swift = read_repo_file("desktop/macos/MeshDesktopCore/Package.swift")?;
    assert!(package_swift.contains("// swift-tools-version: 6.0"));
    assert!(
        !package_swift.contains("StrictConcurrency"),
        "Package.swift must not pass .enableUpcomingFeature(\"StrictConcurrency\") under Swift 6.0"
    );

    // 2. `AdminPrivilegeHelper.swift` passes `--keep-app` on service uninstall (`ADR-026`)
    let admin_helper = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Security/AdminPrivilegeHelper.swift",
    )?;
    assert!(
        admin_helper.contains("--uninstall --keep-app"),
        "AdminPrivilegeHelper.swift must pass --keep-app when uninstalling background service"
    );

    // 3. `BugreportStreamWriter.swift` commits via atomic POSIX `Darwin.rename` (`ADR-023`)
    let bug_writer = read_repo_file(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/Storage/BugreportStreamWriter.swift",
    )?;
    assert!(bug_writer.contains("Darwin.rename(partURL.path, destURL.path)"));
    assert!(!bug_writer.contains("replaceItemAt("));

    // 4. `DesktopStore+DiagnosticsAndErrors.swift` refreshes outside `withSuspendedPolling`
    let store_diag_path = concat!(
        "desktop/macos/MeshDesktopCore/Sources/MeshDesktopCore/",
        "ViewModels/DesktopStore+DiagnosticsAndErrors.swift",
    );
    let store_diag = read_repo_file(store_diag_path)?;
    let suspend_start = store_diag
        .find("let succeeded = await withSuspendedPolling")
        .ok_or_else(|| "missing withSuspendedPolling result binding".to_owned())?;
    let refresh_after = store_diag
        .get(suspend_start..)
        .and_then(|s| s.find("await self.refreshStatus(probeVersionIfNeeded: true)"))
        .ok_or_else(|| "missing post-suspend refreshStatus".to_owned())?;
    let try_exec = store_diag
        .get(suspend_start..)
        .and_then(|s| s.find("try await self.privilegeHelper.execute(action)"))
        .ok_or_else(|| "missing privilegeHelper.execute".to_owned())?;
    assert!(try_exec < refresh_after);

    // 5. `scripts/run-desktop-qa.sh` invokes `swiftlint` inside `desktop/macos`
    let qa_sh = read_repo_file("scripts/run-desktop-qa.sh")?;
    assert!(qa_sh.contains("cd \"$REPO_ROOT/desktop/macos\" && swiftlint lint --strict"));

    // 6. Windows `elevation_worker.rs` enforces OICI SDDL, self-copy guard, and bundle list
    let worker_rs = read_repo_file("crates/mesh-gui/src/elevation_worker.rs")?;
    assert!(worker_rs.contains(r#""D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)""#));
    assert!(worker_rs.contains(r#""D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)""#));
    assert!(worker_rs.contains("windows_paths_equivalent"));
    assert!(worker_rs.contains("Some(5 | 32)"));
    for asset in [
        "\"MeshVPN.exe.new\"",
        "\"mesh-server.exe\"",
        "\"WINTUN-LICENSE.txt\"",
        "\"README-WINTUN.md\"",
        "\"netmap-cache.json\"",
        "\"bugreports\"",
    ] {
        assert!(
            worker_rs.contains(asset),
            "elevation_worker.rs missing uninstall/purge asset {asset}"
        );
    }

    // 7. `ipc_poller.rs` suspends RO polling in both handoff and bugreport spawns
    let poller_rs = read_repo_file("crates/mesh-gui/src/ipc_poller.rs")?;
    assert_eq!(
        poller_rs
            .matches("let _pause_guard = poll_control.suspend();")
            .count(),
        2,
        "ipc_poller.rs must acquire PollingSuspensionGuard in both handoff & bugreport spawns"
    );

    // 8. `release.yml` generates randomized ephemeral keychain password
    let rel_yml = read_repo_file(".github/workflows/release.yml")?;
    assert!(rel_yml.contains("openssl rand -hex 24"));
    assert!(!rel_yml.contains("mesh-ephemeral-kc-pass"));

    Ok(())
}

#[test]
fn test_ui_state_machine_and_no_secrets_in_outputs_comprehensive() {
    let canary = "mpk_U0VDVVJJVFlfQVVESVRfQ0FOQVJZXzAxMjM0NTY3ODkw";
    let secret = Secret::new(canary.to_owned());
    assert!(!format!("{secret:?}").contains(canary));
    assert!(!format!("{secret}").contains(canary));
    assert!(!masked_preauth_preview_from_secret(&secret).contains(canary));

    let scrubbed = sanitize_gui_log_text(&format!(
        "uri=mesh://join?v=1&ep=198.51.100.10:8443&key={canary} \
         json={{\"preauth_key\": \"{canary}\"}} preauth={canary} token={canary}"
    ));
    assert!(!scrubbed.contains(canary));

    let self_net = SelfNetworkStatus {
        local_udp_port: 51820,
        bound_physical_interface: Some("Ethernet".to_owned()),
        nat_type: NatMappingKind::EimOrAdm,
        nat_classification_note: None,
        overlay_conflict_warning: None,
        macos_firewall_warning: None,
        candidates: Vec::new(),
    };
    let srv_conn = ServerConnectionStatus {
        control_endpoint: "198.51.100.10:8443".to_owned(),
        relay_endpoint: "198.51.100.10:8443".to_owned(),
        stun_endpoints: vec!["198.51.100.10:3478".to_owned()],
        tls_auth_mode: TlsAuthMode::SpkiPin,
        active_pin: SpkiPin::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .ok(),
        next_pin: None,
        control_connected: true,
        relay_connected: true,
        relay_rtt_ms: Some(12),
        migration_pending_endpoint: None,
        last_error: Some(format!("preauth_key={canary}")),
    };
    let status = AgentStatusResponse {
        daemon_state: DaemonState::Stopped,
        node_id: Some(NodeId::from_bytes([3_u8; 16])),
        node_name: NodeName::parse("audit-node").ok(),
        fqdn: Some("audit-node.mesh.internal".to_owned()),
        overlay_ip: OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 9)).ok(),
        overlay_cidr: OverlayCidr::parse("100.64.0.0/10").ok(),
        tun_interface_name: Some("MeshVPN".to_owned()),
        tun_mtu: 1420,
        netmap_version: 2,
        key_expires_at_ms: None,
        server_connection: Some(srv_conn),
        self_network: self_net,
        peers: Vec::new(),
    };
    assert!(is_status_enrolled(&status));

    let snap = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&status),
        version_status: Some(&AgentVersionStatus::Version("0.2.0".to_owned())),
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(snap.ui_state, DesktopUiState::ErrorRecoverable);
    assert_eq!(snap.tunnel_sub_state, TunnelSubState::Disconnected);
    assert!(snap.enrolled);
    assert!(snap.legacy_banner.is_none());
    assert!(snap.version_mismatch_banner.is_some());
    assert!(!snap.ui_state.label().is_empty());
    assert!(!snap.ui_state.headline(snap.tunnel_sub_state).is_empty());
    assert!(
        !snap
            .ui_state
            .tray_tooltip_summary(snap.tunnel_sub_state)
            .is_empty()
    );
    assert!(
        snap.recoverable_error
            .as_deref()
            .is_some_and(|msg| !msg.contains(canary))
    );

    // Exercise remaining variants of `ServiceProbeKind`, `DesktopUiState`, `TunnelSubState`,
    // and `AgentVersionIndicator` so all `pub(crate)` items in `app.rs` are covered.
    for probe in [
        ServiceProbeKind::Stopped,
        ServiceProbeKind::NotInstalled,
        ServiceProbeKind::Unknown,
    ] {
        let s = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.3.0",
            service_probe: probe,
            ipc_connected: false,
            status: None,
            version_status: Some(&AgentVersionStatus::LegacyPre030),
            ipc_error: Some("offline"),
            active_action_error: None,
        });
        assert!(!s.ui_state.label().is_empty());
        assert_eq!(s.version_indicator, AgentVersionIndicator::LegacyPre030);
        assert!(s.legacy_banner.is_some());
    }
    for daemon_st in [
        DaemonState::Connecting,
        DaemonState::Connected,
        DaemonState::Degraded,
        DaemonState::ReauthRequired,
        DaemonState::Revoked,
    ] {
        let mut st = status.clone();
        st.daemon_state = daemon_st;
        let derived = derive_desktop_ui_state(StateProbeInputs {
            gui_version: "0.3.0",
            service_probe: ServiceProbeKind::Running,
            ipc_connected: true,
            status: Some(&st),
            version_status: Some(&AgentVersionStatus::Version("0.3.0".to_owned())),
            ipc_error: None,
            active_action_error: None,
        });
        assert_eq!(
            derived.version_indicator,
            AgentVersionIndicator::Compatible("0.3.0".to_owned())
        );
        assert!(
            !derived
                .ui_state
                .headline(derived.tunnel_sub_state)
                .is_empty()
        );
        assert!(
            !derived
                .ui_state
                .tray_tooltip_summary(derived.tunnel_sub_state)
                .is_empty()
        );
    }
    let mut unenrolled = status;
    unenrolled.node_id = None;
    unenrolled.overlay_ip = None;
    unenrolled.server_connection = None;
    let s_unenrolled = derive_desktop_ui_state(StateProbeInputs {
        gui_version: "0.3.0",
        service_probe: ServiceProbeKind::Running,
        ipc_connected: true,
        status: Some(&unenrolled),
        version_status: None,
        ipc_error: None,
        active_action_error: None,
    });
    assert_eq!(s_unenrolled.ui_state, DesktopUiState::NotEnrolled);
    assert_eq!(s_unenrolled.tunnel_sub_state, TunnelSubState::NotEnrolled);
    assert_eq!(
        derive_version_indicator("0.3.0", None),
        AgentVersionIndicator::Unknown
    );

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        let base = if cfg!(windows) {
            Path::new(r"C:\Users\Test\AppData\Local")
        } else {
            Path::new("/home/alice/.local/share")
        };
        let log_dir = crate::app::gui_log_directory(Some(base));
        assert!(log_dir.is_some_and(|d| {
            d.ends_with(
                Path::new(crate::app::GUI_APP_DATA_DIR_NAME).join(crate::app::GUI_LOG_SUBDIR),
            )
        }));
    }
}

proptest! {
    #[test]
    fn prop_audit_log_sanitizer_redacts_all_mpk_and_join_uris(
        suffix in "[A-Za-z0-9_-]{43,64}",
        host in "[a-z0-9]{3,12}\\.example\\.com",
    ) {
        let token = format!("mpk_{suffix}");
        let uri = format!("mesh://join?v=1&ep={host}:8443&pin=system-ca&key={token}");
        let dirty = format!("err uri={uri} key={token} json={{\"preauth_key\":\"{token}\"}}");
        let clean = sanitize_gui_log_text(&dirty);
        prop_assert!(!clean.contains(&token));
        prop_assert!(!clean.contains(&suffix));
    }

    #[test]
    fn prop_audit_mgh1_decoder_never_panics_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..=512)
    ) {
        let _res = decode_mgh1_frame(&raw);
    }
}
