//! Zero-TOFU endpoint/TLS validation, `mesh://` URI parsing, Pre-Auth confirmation drafting,
//! and Re-auth / Update Server input validation (`US-105`, `US-108`, `SEC-01`, `SEC-04`).

use std::fmt;

use mesh_core::{
    MobileJoinTlsAuth, NodeName, Port, SpkiPin, is_ip_literal_host, normalize_control_endpoint,
    parse_join_uri, validate_desktop_tls_policy, validate_preauth_key,
};
use mesh_crypto::Secret;
use mesh_net::gui_handoff::{
    HandoffRequest, build_rotate_key_handoff_payload, build_up_handoff_payload,
    masked_preauth_preview_from_secret, serialize_handoff_request_zeroizing,
};
use zeroize::Zeroizing;

/// Selected TLS trust policy in the Setup & Onboarding / Update Server UI (`SEC-04`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OnboardingTlsMode {
    /// Leaf SPKI SHA-256 pin (`sha256:<64_hex>`), mandatory for IPv4/IPv6 literals (Zero-TOFU).
    SpkiPin,
    /// Public CA trust via OS certificate store (domain hostnames only; blocked on IP literals).
    SystemCa,
}

/// Raw operator inputs collected from Setup & Onboarding form fields.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OnboardingFormInput {
    pub(crate) endpoint_raw: String,
    pub(crate) tls_mode: OnboardingTlsMode,
    pub(crate) spki_pin_raw: String,
    pub(crate) preauth_key_raw: String,
    pub(crate) node_name_raw: String,
}

impl fmt::Debug for OnboardingFormInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnboardingFormInput")
            .field("endpoint_raw", &self.endpoint_raw)
            .field("tls_mode", &self.tls_mode)
            .field("spki_pin_raw", &self.spki_pin_raw)
            .field("preauth_key_raw", &"[REDACTED]")
            .field("node_name_raw", &self.node_name_raw)
            .finish()
    }
}

/// Distinguishes full initial enrollment (`UpWithSecret`) from expired-key rotation
/// (`RotateKeyWithSecret`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ConfirmActionKind {
    EnrollNewNode,
    RotateKey,
}

/// Validated enrollment or key-rotation draft awaiting user confirmation before UAC handoff.
///
/// Never prints the plaintext `preauth_key` in `Debug` (`SEC-01`, `test_no_secrets_in_outputs`).
pub(crate) struct EnrollmentConfirmationDraft {
    pub(crate) action_kind: ConfirmActionKind,
    pub(crate) normalized_endpoint: String,
    pub(crate) port_override: Option<Port>,
    pub(crate) tls_mode: OnboardingTlsMode,
    pub(crate) server_pin: Option<SpkiPin>,
    pub(crate) node_name: Option<NodeName>,
    pub(crate) masked_preauth_preview: String,
    preauth_key: Option<Secret<String>>,
}

impl fmt::Debug for EnrollmentConfirmationDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentConfirmationDraft")
            .field("action_kind", &self.action_kind)
            .field("normalized_endpoint", &self.normalized_endpoint)
            .field("port_override", &self.port_override)
            .field("tls_mode", &self.tls_mode)
            .field("server_pin", &self.server_pin)
            .field("node_name", &self.node_name)
            .field("masked_preauth_preview", &self.masked_preauth_preview)
            .field("preauth_key", &"[REDACTED]")
            .finish()
    }
}

impl EnrollmentConfirmationDraft {
    /// Builds a clean `MGH1` `0x01` payload wrapped in `Zeroizing<Vec<u8>>` while keeping raw
    /// key unwrapping inside `mesh-net` (`ADR-020`).
    pub(crate) fn build_handoff_payload(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        match self.action_kind {
            ConfirmActionKind::EnrollNewNode => build_up_handoff_payload(
                &self.normalized_endpoint,
                self.port_override,
                self.server_pin,
                self.preauth_key.as_ref(),
                self.node_name.clone(),
            )
            .map_err(|err| err.to_string()),
            ConfirmActionKind::RotateKey => {
                let secret = self
                    .preauth_key
                    .as_ref()
                    .ok_or_else(|| "Pre-Auth Key is required for key rotation".to_owned())?;
                build_rotate_key_handoff_payload(secret).map_err(|err| err.to_string())
            }
        }
    }

    /// Formats the confirmation modal message shown before launching UAC (`US-105`).
    #[must_use]
    pub(crate) fn format_confirmation_summary(&self) -> String {
        let tls_summary = match self.server_pin {
            Some(pin) => format!("Pinned Leaf SPKI ({pin})"),
            None => "System CA Trust (Domain Only)".to_owned(),
        };
        let node_summary = self
            .node_name
            .as_ref()
            .map_or("<OS Hostname>", NodeName::as_str);
        match self.action_kind {
            ConfirmActionKind::EnrollNewNode => format!(
                "Confirm Mesh Node Enrollment\r\n\r\n\
                 Control Server : {}\r\n\
                 TLS Trust Mode : {}\r\n\
                 Pre-Auth Key   : {}\r\n\
                 Node Name      : {}\r\n\r\n\
                 Proceeding requests Administrator elevation (UAC) to write node \
                 configuration and start the tunnel.",
                self.normalized_endpoint, tls_summary, self.masked_preauth_preview, node_summary
            ),
            ConfirmActionKind::RotateKey => format!(
                "Confirm Pre-Auth Key Rotation\r\n\r\n\
                 Control Server : {}\r\n\
                 Pre-Auth Key   : {}\r\n\r\n\
                 Proceeding requests Administrator elevation (UAC) to re-authenticate this node.",
                self.normalized_endpoint, self.masked_preauth_preview
            ),
        }
    }
}

/// Evaluates whether the System CA radio button must be disabled (Zero-TOFU lock on IP literals).
#[must_use]
pub(crate) fn should_lock_system_ca_for_endpoint(endpoint_raw: &str) -> bool {
    let trimmed = endpoint_raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Ok(norm) = normalize_control_endpoint(trimmed, None) {
        return norm.is_ip_literal;
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
    let stripped = host_part
        .strip_prefix('[')
        .and_then(|s| s.split(']').next())
        .unwrap_or_else(|| host_part.split(':').next().unwrap_or(host_part));
    is_ip_literal_host(stripped)
}

/// Parses a `mesh://` onboarding URI and converts it directly into both pre-filled form values
/// (with `preauth_key` wrapped in `Secret<String>`) and a ready confirmation draft (`US-105`).
pub(crate) fn parse_mesh_join_uri_to_draft(
    raw_uri: &str,
    node_name_override: &str,
) -> Result<(OnboardingFormInput, EnrollmentConfirmationDraft), String> {
    let parsed = parse_join_uri(raw_uri.trim()).map_err(|err| err.to_string())?;
    let (tls_mode, spki_pin_raw) = match &parsed.tls_auth {
        MobileJoinTlsAuth::SpkiPin(pin) => (OnboardingTlsMode::SpkiPin, pin.to_string()),
        MobileJoinTlsAuth::SystemCa => (OnboardingTlsMode::SystemCa, String::new()),
    };
    let effective_node_name = if !node_name_override.trim().is_empty() {
        node_name_override.trim().to_owned()
    } else {
        parsed
            .node_name
            .as_ref()
            .map_or_else(String::new, |n| n.as_str().to_owned())
    };
    let form = OnboardingFormInput {
        endpoint_raw: parsed.control_endpoint.clone(),
        tls_mode,
        spki_pin_raw,
        preauth_key_raw: parsed.preauth_key().to_owned(),
        node_name_raw: effective_node_name,
    };
    let draft = validate_manual_onboarding_to_draft(&form)?;
    Ok((form, draft))
}

/// Normalizes and validates Manual Setup fields, enforcing Zero-TOFU, SPKI pin syntax, RFC 1123
/// node naming, and Pre-Auth Key rules before creating a secret-safe `EnrollmentConfirmationDraft`.
pub(crate) fn validate_manual_onboarding_to_draft(
    input: &OnboardingFormInput,
) -> Result<EnrollmentConfirmationDraft, String> {
    let parsed_pin = match input.tls_mode {
        OnboardingTlsMode::SpkiPin => {
            let pin_trimmed = input.spki_pin_raw.trim();
            if pin_trimmed.is_empty() {
                return Err(
                    "SPKI Pin (`sha256:<64 hex>`) is required when Pinned SPKI mode is selected."
                        .to_owned(),
                );
            }
            Some(SpkiPin::parse(pin_trimmed).map_err(|err| err.to_string())?)
        }
        OnboardingTlsMode::SystemCa => None,
    };

    let tls_auth = match parsed_pin {
        Some(pin) => MobileJoinTlsAuth::SpkiPin(pin),
        None => MobileJoinTlsAuth::SystemCa,
    };
    let normalized = validate_desktop_tls_policy(input.endpoint_raw.trim(), None, tls_auth)
        .map_err(|err| err.to_string())?;

    let preauth_trimmed = input.preauth_key_raw.trim();
    validate_preauth_key(preauth_trimmed).map_err(|err| err.to_string())?;
    let secret = Secret::new(preauth_trimmed.to_owned());
    let masked = masked_preauth_preview_from_secret(&secret);

    let node_name_trimmed = input.node_name_raw.trim();
    let validated_node_name = if node_name_trimmed.is_empty() {
        None
    } else {
        Some(NodeName::parse(node_name_trimmed).map_err(|err| err.to_string())?)
    };

    Ok(EnrollmentConfirmationDraft {
        action_kind: ConfirmActionKind::EnrollNewNode,
        normalized_endpoint: normalized.endpoint,
        port_override: Some(normalized.port),
        tls_mode: input.tls_mode,
        server_pin: parsed_pin,
        node_name: validated_node_name,
        masked_preauth_preview: masked,
        preauth_key: Some(secret),
    })
}

/// Validates a new Pre-Auth Key for `ReauthRequired` recovery (`US-105`, `US-031`).
pub(crate) fn validate_rotate_key_to_draft(
    current_endpoint: &str,
    tls_mode: OnboardingTlsMode,
    current_pin: Option<SpkiPin>,
    preauth_key_raw: &str,
) -> Result<EnrollmentConfirmationDraft, String> {
    let trimmed = preauth_key_raw.trim();
    validate_preauth_key(trimmed).map_err(|err| err.to_string())?;
    let secret = Secret::new(trimmed.to_owned());
    let masked = masked_preauth_preview_from_secret(&secret);
    Ok(EnrollmentConfirmationDraft {
        action_kind: ConfirmActionKind::RotateKey,
        normalized_endpoint: current_endpoint.trim().to_owned(),
        port_override: None,
        tls_mode,
        server_pin: current_pin,
        node_name: None,
        masked_preauth_preview: masked,
        preauth_key: Some(secret),
    })
}

/// Validates `Update Server / Pin` inputs (`US-108`) and serializes `HandoffRequest::Set` into a
/// zeroizing payload ready for Direct Admin IPC or UAC handoff.
pub(crate) fn validate_update_server_payload(
    endpoint_raw: &str,
    tls_mode: OnboardingTlsMode,
    primary_pin_raw: &str,
) -> Result<(String, Zeroizing<Vec<u8>>), String> {
    let parsed_pin = match tls_mode {
        OnboardingTlsMode::SpkiPin => {
            let primary_trimmed = primary_pin_raw.trim();
            if primary_trimmed.is_empty() {
                return Err(
                    "Primary SPKI Pin (`sha256:<64 hex>`) is required in SPKI Pin mode.".to_owned(),
                );
            }
            Some(SpkiPin::parse(primary_trimmed).map_err(|err| err.to_string())?)
        }
        OnboardingTlsMode::SystemCa => None,
    };

    let tls_auth = match parsed_pin {
        Some(pin) => MobileJoinTlsAuth::SpkiPin(pin),
        None => MobileJoinTlsAuth::SystemCa,
    };
    let normalized = validate_desktop_tls_policy(endpoint_raw.trim(), None, tls_auth)
        .map_err(|err| err.to_string())?;

    let req = HandoffRequest::Set {
        server_endpoint: normalized.endpoint.clone(),
        server_pin: parsed_pin.map(|p| p.to_string()),
    };
    let payload = serialize_handoff_request_zeroizing(&req).map_err(|err| err.to_string())?;
    Ok((normalized.endpoint, payload))
}
