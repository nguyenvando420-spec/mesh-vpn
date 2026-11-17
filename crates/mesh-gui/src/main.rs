#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
//! Native Windows System Tray & Dashboard binary skeleton (`MeshVPN.exe`, `ADR-020`, `WP-D-A0`).
//!
//! Full Win32 UI, Tray, UAC worker, and Dashboard implementation is delivered by `WP-D-B1`.
//! This crate enforces `unsafe_code = "forbid"`, zero raw secret exposure calls (`SEC-01`), and
//! zero direct `sha2`/`subtle` imports (delegating hashing/constant-time equality to
//! `mesh-crypto` and handoff secret unwrapping to `mesh_net::gui_handoff`).

use std::process::ExitCode;

#[cfg(target_os = "windows")]
fn run_desktop_gui() -> ExitCode {
    if mesh_sys::gui_windows::enable_per_monitor_v2_dpi().is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "windows"))]
fn run_desktop_gui() -> ExitCode {
    tracing::warn!(
        component = "mesh-gui",
        event = "unsupported_platform_stub",
        "MeshVPN GUI binary is supported only on Windows"
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    run_desktop_gui()
}

#[cfg(test)]
mod tests {
    use mesh_core::brand::PREAUTH_KEY_PREFIX;
    use mesh_core::{
        MobileJoinTlsAuth, Port, SpkiPin, validate_desktop_tls_policy, validate_preauth_key,
    };
    use mesh_crypto::{Secret, ct_eq_bytes, sha256_digest};
    use mesh_net::gui_handoff::{build_up_handoff_payload, parse_handoff_request_payload};

    #[test]
    fn test_mesh_gui_skeleton_uses_mesh_crypto_and_handoff_without_exposing_secrets() {
        // Arrange: 43 base64url chars ('A' = 0x00 -> zero trailing bits, 32 decoded bytes = 256 bits)
        let raw_token = format!("{PREAUTH_KEY_PREFIX}{}", "A".repeat(43));
        let secret_token = Secret::new(raw_token.clone());
        let pin = SpkiPin::from_sha256_bytes([0x21_u8; 32]);
        let port = Port::from_u16(8443).ok();

        // Act
        let normalized =
            validate_desktop_tls_policy("203.0.113.10", port, MobileJoinTlsAuth::SpkiPin(pin));
        let token_ok = validate_preauth_key(&raw_token);
        let payload = build_up_handoff_payload(
            "203.0.113.10:8443",
            port,
            Some(pin),
            Some(&secret_token),
            None,
        );
        let digest_a = sha256_digest(b"mesh-gui-canary");
        let digest_b = sha256_digest(b"mesh-gui-canary");

        // Assert
        assert!(normalized.is_ok());
        assert!(token_ok.is_ok());
        assert!(payload.is_ok());
        assert!(ct_eq_bytes(&digest_a, &digest_b));
        if let Ok(bytes) = payload {
            let parsed = parse_handoff_request_payload(bytes.as_slice());
            assert!(parsed.is_ok());
        }
        assert_eq!(format!("{secret_token:?}"), "[REDACTED]");
    }
}
