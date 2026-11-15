//! Strict parser, validator, and formatter for mobile onboarding URIs (`ADR-019`, `US-076`).
//!
//! Grammar: `mesh://join?v=1&ep=<urlenc_endpoint>&pin=<sha256%3A64hex|system-ca>&key=<mpk_...>[&name=<node_name>]`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use data_encoding::BASE64URL_NOPAD;
use zeroize::{Zeroize as _, Zeroizing};

use crate::brand::PREAUTH_KEY_PREFIX;
use crate::error::{AppError, AppResult};
use crate::types::{NodeName, Port, SpkiPin};

/// Custom URI scheme accepted by Mesh mobile onboarding flows.
pub const MOBILE_JOIN_URI_SCHEME: &str = "mesh";

/// Custom URI host/authority identifying an enrollment join URI.
pub const MOBILE_JOIN_URI_HOST: &str = "join";

/// Supported `mesh://join` schema version (`v=1`).
pub const MOBILE_JOIN_URI_VERSION: u8 = 1;

/// Hard upper bound on raw `mesh://join` URI input length in bytes.
pub const MAX_MOBILE_JOIN_URI_LEN: usize = 1_024;

/// Sentinel pin value selecting OS WebPKI / system root verification on DNS endpoints.
pub const MOBILE_SYSTEM_CA_PIN: &str = "system-ca";

const URI_PREFIX: &str = "mesh://join?";
const MAX_DNS_HOSTNAME_LEN: usize = 253;
const MAX_PREAUTH_KEY_LEN: usize = 256;

/// Validated TLS verification policy encoded inside a [`MobileJoinUri`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MobileJoinTlsAuth {
    /// Fail-closed SHA-256 SPKI pin (`sha256:<64_lowercase_hex>`).
    SpkiPin(SpkiPin),
    /// Standard OS system root CA verification (restricted strictly to DNS endpoints).
    SystemCa,
}

/// Validated, secret-redacting parsed representation of a `mesh://join?v=1&...` onboarding URI.
#[derive(Clone, PartialEq, Eq)]
pub struct MobileJoinUri {
    /// URI schema version (always [`MOBILE_JOIN_URI_VERSION`]).
    pub version: u8,
    /// Validated `host:port` (or `[ipv6]:port`) Control endpoint.
    pub control_endpoint: String,
    /// Parsed TLS authentication policy.
    pub tls_auth: MobileJoinTlsAuth,
    /// Secret pre-authentication token zeroized on drop (`SEC-01`).
    preauth_key: Zeroizing<String>,
    /// Optional suggested RFC 1123 node hostname.
    pub node_name: Option<NodeName>,
}

impl MobileJoinUri {
    /// Parses and validates a `mesh://join?v=1&...` onboarding URI fail-closed.
    pub fn parse(raw: &str) -> AppResult<Self> {
        parse_join_uri(raw)
    }

    /// Returns the validated `mpk_*` pre-authentication key.
    #[must_use]
    pub fn preauth_key(&self) -> &str {
        self.preauth_key.as_str()
    }

    /// Returns `true` when [`Self::control_endpoint`] uses a raw IPv4/IPv6 literal host.
    #[must_use]
    pub fn is_ip_endpoint(&self) -> bool {
        split_endpoint_host_port(&self.control_endpoint)
            .map(|(host, _)| host.parse::<IpAddr>().is_ok())
            .unwrap_or(false)
    }

    /// Renders a shareable `mesh://join` representation with the secret `key` redacted (`SEC-01`).
    #[must_use]
    pub fn to_redacted_string(&self) -> String {
        let ep_enc = percent_encode_component(&self.control_endpoint);
        let pin_raw = match &self.tls_auth {
            MobileJoinTlsAuth::SpkiPin(pin) => pin.to_string(),
            MobileJoinTlsAuth::SystemCa => MOBILE_SYSTEM_CA_PIN.to_owned(),
        };
        let pin_enc = percent_encode_component(&pin_raw);
        let mut out = format!(
            "{MOBILE_JOIN_URI_SCHEME}://{MOBILE_JOIN_URI_HOST}?v={}&ep={ep_enc}&pin={pin_enc}&key=[REDACTED]",
            self.version
        );
        if let Some(ref name) = self.node_name {
            out.push_str("&name=");
            out.push_str(name.as_str());
        }
        out
    }
}

impl fmt::Debug for MobileJoinUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileJoinUri")
            .field("version", &self.version)
            .field("control_endpoint", &self.control_endpoint)
            .field("tls_auth", &self.tls_auth)
            .field("preauth_key", &"[REDACTED]")
            .field("node_name", &self.node_name)
            .finish()
    }
}

impl fmt::Display for MobileJoinUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_redacted_string())
    }
}

/// Parses and strictly validates a `mesh://join?v=1&...` mobile onboarding URI (`ADR-019`).
pub fn parse_join_uri(raw: &str) -> AppResult<MobileJoinUri> {
    if raw.len() > MAX_MOBILE_JOIN_URI_LEN {
        return Err(AppError::invalid_argument(format!(
            "mobile join URI exceeds maximum {MAX_MOBILE_JOIN_URI_LEN} bytes"
        )));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::invalid_argument(
            "mobile join URI must not be empty",
        ));
    }
    if trimmed.len() != raw.len() {
        return Err(AppError::invalid_argument(
            "mobile join URI must not contain leading or trailing whitespace",
        ));
    }
    if trimmed
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(AppError::invalid_argument(
            "mobile join URI contains invalid whitespace or control characters",
        ));
    }
    if trimmed.contains('#') {
        return Err(AppError::invalid_argument(
            "mobile join URI must not contain URL fragments",
        ));
    }

    let Some(query) = trimmed.strip_prefix(URI_PREFIX) else {
        return Err(AppError::invalid_argument(
            "mobile join URI must begin with `mesh://join?`",
        ));
    };
    if query.is_empty() {
        return Err(AppError::invalid_argument(
            "mobile join URI query parameters must not be empty",
        ));
    }

    let mut version_raw: Option<String> = None;
    let mut ep_raw: Option<String> = None;
    let mut pin_raw: Option<String> = None;
    let mut key_raw: Option<Zeroizing<String>> = None;
    let mut name_raw: Option<String> = None;

    for segment in query.split('&') {
        if segment.is_empty() {
            return Err(AppError::invalid_argument(
                "mobile join URI contains empty query parameter segment",
            ));
        }
        let Some((raw_k, raw_v)) = segment.split_once('=') else {
            return Err(AppError::invalid_argument(
                "mobile join URI query parameter missing `=`",
            ));
        };
        let key = percent_decode_component(raw_k, "query key")?;
        let val = Zeroizing::new(percent_decode_component(raw_v, "query value")?);
        if key.is_empty() || val.is_empty() {
            return Err(AppError::invalid_argument(
                "mobile join URI query parameter key and value must not be empty",
            ));
        }

        match key.as_str() {
            "v" => {
                if version_raw.is_some() {
                    return Err(AppError::invalid_argument(
                        "duplicate `v` query parameter in mobile join URI",
                    ));
                }
                version_raw = Some((*val).clone());
            }
            "ep" => {
                if ep_raw.is_some() {
                    return Err(AppError::invalid_argument(
                        "duplicate `ep` query parameter in mobile join URI",
                    ));
                }
                ep_raw = Some((*val).clone());
            }
            "pin" => {
                if pin_raw.is_some() {
                    return Err(AppError::invalid_argument(
                        "duplicate `pin` query parameter in mobile join URI",
                    ));
                }
                pin_raw = Some((*val).clone());
            }
            "key" => {
                if key_raw.is_some() {
                    return Err(AppError::invalid_argument(
                        "duplicate `key` query parameter in mobile join URI",
                    ));
                }
                key_raw = Some(val);
            }
            "name" => {
                if name_raw.is_some() {
                    return Err(AppError::invalid_argument(
                        "duplicate `name` query parameter in mobile join URI",
                    ));
                }
                name_raw = Some((*val).clone());
            }
            other => {
                return Err(AppError::invalid_argument(format!(
                    "unsupported query parameter `{other}` in mobile join URI"
                )));
            }
        }
    }

    let version_str = version_raw.ok_or_else(|| {
        AppError::invalid_argument("mobile join URI missing required `v` parameter")
    })?;
    if version_str != "1" {
        return Err(AppError::invalid_argument(format!(
            "unsupported mobile join URI version `{version_str}` (expected `1`)"
        )));
    }

    let endpoint = ep_raw.ok_or_else(|| {
        AppError::invalid_argument("mobile join URI missing required `ep` parameter")
    })?;
    let (host_is_ip, canonical_ep) = validate_control_endpoint(&endpoint)?;

    let pin_str = pin_raw.ok_or_else(|| {
        AppError::invalid_argument("mobile join URI missing required `pin` parameter")
    })?;
    let tls_auth = if pin_str == MOBILE_SYSTEM_CA_PIN {
        if host_is_ip {
            return Err(AppError::invalid_argument(
                "system-ca TLS mode cannot be paired with an IP literal control endpoint (SEC-04)",
            ));
        }
        MobileJoinTlsAuth::SystemCa
    } else {
        let pin = SpkiPin::parse(&pin_str)?;
        MobileJoinTlsAuth::SpkiPin(pin)
    };

    let key = key_raw.ok_or_else(|| {
        AppError::invalid_argument("mobile join URI missing required `key` parameter")
    })?;
    validate_preauth_key(key.as_str())?;

    let node_name = match name_raw {
        Some(raw_name) => Some(NodeName::parse(&raw_name)?),
        None => None,
    };

    Ok(MobileJoinUri {
        version: MOBILE_JOIN_URI_VERSION,
        control_endpoint: canonical_ep,
        tls_auth,
        preauth_key: key,
        node_name,
    })
}

/// Formats and validates a `mesh://join?v=1&...` URI suitable for QR/copy export.
pub fn format_join_uri(
    control_endpoint: &str,
    tls_auth: &MobileJoinTlsAuth,
    preauth_key: &str,
    node_name: Option<&NodeName>,
) -> AppResult<String> {
    let (host_is_ip, canonical_ep) = validate_control_endpoint(control_endpoint)?;
    if matches!(tls_auth, MobileJoinTlsAuth::SystemCa) && host_is_ip {
        return Err(AppError::invalid_argument(
            "system-ca TLS mode cannot be paired with an IP literal control endpoint (SEC-04)",
        ));
    }
    validate_preauth_key(preauth_key)?;

    let ep_enc = percent_encode_component(&canonical_ep);
    let pin_raw = match tls_auth {
        MobileJoinTlsAuth::SpkiPin(pin) => pin.to_string(),
        MobileJoinTlsAuth::SystemCa => MOBILE_SYSTEM_CA_PIN.to_owned(),
    };
    let pin_enc = percent_encode_component(&pin_raw);
    let key_enc = percent_encode_component(preauth_key);

    let mut uri = format!(
        "{MOBILE_JOIN_URI_SCHEME}://{MOBILE_JOIN_URI_HOST}?v={MOBILE_JOIN_URI_VERSION}&ep={ep_enc}&pin={pin_enc}&key={key_enc}"
    );
    if let Some(name) = node_name {
        uri.push_str("&name=");
        uri.push_str(&percent_encode_component(name.as_str()));
    }
    if uri.len() > MAX_MOBILE_JOIN_URI_LEN {
        return Err(AppError::invalid_argument(format!(
            "formatted mobile join URI exceeds maximum {MAX_MOBILE_JOIN_URI_LEN} bytes"
        )));
    }
    Ok(uri)
}

fn validate_control_endpoint(raw: &str) -> AppResult<(bool, String)> {
    if raw.is_empty()
        || raw.contains('/')
        || raw.contains('\\')
        || raw.contains('@')
        || raw.contains('?')
        || raw.contains('#')
        || raw.contains("://")
        || raw
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(AppError::invalid_argument(
            "invalid `ep` control endpoint syntax",
        ));
    }

    let (host, port_str) = split_endpoint_host_port(raw)?;
    if host.is_empty() || host.len() > MAX_DNS_HOSTNAME_LEN {
        return Err(AppError::invalid_argument(
            "control endpoint hostname must be 1..=253 bytes",
        ));
    }
    if port_str.is_empty()
        || !port_str.bytes().all(|b| b.is_ascii_digit())
        || port_str.starts_with('0')
    {
        return Err(AppError::invalid_argument(
            "control endpoint port must be a decimal number 1..=65535 without leading zeros",
        ));
    }
    let port_num: u16 = port_str
        .parse()
        .map_err(|_| AppError::invalid_argument("control endpoint port out of range 1..=65535"))?;
    let port = Port::from_u16(port_num)?;

    if raw.starts_with('[') {
        let ipv6 = Ipv6Addr::from_str(host)
            .map_err(|_| AppError::invalid_argument("invalid bracketed IPv6 literal in `ep`"))?;
        return Ok((true, format!("[{ipv6}]:{port}")));
    }
    if host.contains(':') {
        return Err(AppError::invalid_argument(
            "unbracketed IPv6 or extra colon in `ep` host",
        ));
    }
    if let Ok(ipv4) = Ipv4Addr::from_str(host) {
        return Ok((true, format!("{ipv4}:{port}")));
    }

    validate_dns_hostname(host)?;
    Ok((false, format!("{host}:{port}")))
}

fn split_endpoint_host_port(raw: &str) -> AppResult<(&str, &str)> {
    if let Some(after_open) = raw.strip_prefix('[') {
        let Some((host, rest)) = after_open.split_once(']') else {
            return Err(AppError::invalid_argument(
                "missing closing `]` in IPv6 `ep` control endpoint",
            ));
        };
        let Some(port_str) = rest.strip_prefix(':') else {
            return Err(AppError::invalid_argument(
                "missing `:port` after bracketed IPv6 `ep` host",
            ));
        };
        return Ok((host, port_str));
    }

    raw.rsplit_once(':')
        .ok_or_else(|| AppError::invalid_argument("control endpoint `ep` must have `:port`"))
}

fn validate_dns_hostname(host: &str) -> AppResult<()> {
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(AppError::invalid_argument(
            "control endpoint DNS hostname contains invalid dot placement",
        ));
    }
    let mut last_label_has_alpha = false;
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(AppError::invalid_argument(
                "control endpoint DNS label must be 1..=63 characters",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AppError::invalid_argument(
                "control endpoint DNS label must not start or end with `-`",
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(AppError::invalid_argument(
                "control endpoint DNS hostname contains invalid characters",
            ));
        }
        last_label_has_alpha = label.bytes().any(|b| b.is_ascii_alphabetic());
    }
    if !last_label_has_alpha {
        return Err(AppError::invalid_argument(
            "control endpoint host is neither a valid IP address nor a valid DNS hostname",
        ));
    }
    Ok(())
}

fn validate_preauth_key(key: &str) -> AppResult<()> {
    if key.len() > MAX_PREAUTH_KEY_LEN
        || key
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(AppError::invalid_argument(
            "invalid pre-auth key syntax in mobile join URI",
        ));
    }
    let Some(body) = key.strip_prefix(PREAUTH_KEY_PREFIX) else {
        return Err(AppError::invalid_argument(
            "invalid pre-auth key format: missing `mpk_` prefix",
        ));
    };
    let mut decoded = BASE64URL_NOPAD
        .decode(body.as_bytes())
        .map_err(|_| AppError::invalid_argument("invalid pre-auth key base64url payload"))?;
    let valid_len = decoded.len() >= 32;
    decoded.zeroize();
    if !valid_len {
        return Err(AppError::invalid_argument(
            "invalid pre-auth key entropy: must be >= 256 bits",
        ));
    }
    Ok(())
}

fn percent_decode_component(raw: &str, label: &str) -> AppResult<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0_usize;
    while let Some(&b) = bytes.get(idx) {
        if b == b'%' {
            let (Some(&hi), Some(&lo)) = (bytes.get(idx + 1), bytes.get(idx + 2)) else {
                return Err(AppError::invalid_argument(format!(
                    "truncated percent-escape in mobile join URI {label}"
                )));
            };
            let decoded_byte = (hex_nibble(hi, label)? << 4) | hex_nibble(lo, label)?;
            if decoded_byte == 0 || decoded_byte.is_ascii_control() {
                return Err(AppError::invalid_argument(format!(
                    "disallowed control character in mobile join URI {label}"
                )));
            }
            out.push(decoded_byte);
            idx += 3;
        } else {
            if b.is_ascii_control() || b.is_ascii_whitespace() {
                return Err(AppError::invalid_argument(format!(
                    "disallowed unescaped control/whitespace character in mobile join URI {label}"
                )));
            }
            out.push(b);
            idx += 1;
        }
    }
    String::from_utf8(out).map_err(|_| {
        AppError::invalid_argument(format!("invalid UTF-8 sequence in mobile join URI {label}"))
    })
}

fn hex_nibble(b: u8, label: &str) -> AppResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(AppError::invalid_argument(format!(
            "invalid hex escape in mobile join URI {label}"
        ))),
    }
}

fn percent_encode_component(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        let is_unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if is_unreserved {
            out.push(char::from(b));
        } else {
            out.push('%');
            let hi = usize::from(b >> 4);
            let lo = usize::from(b & 0x0f);
            if let (Some(&c_hi), Some(&c_lo)) = (HEX.get(hi), HEX.get(lo)) {
                out.push(char::from(c_hi));
                out.push(char::from(c_lo));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use proptest::prelude::*;

    use super::{
        MAX_MOBILE_JOIN_URI_LEN, MobileJoinTlsAuth, MobileJoinUri, format_join_uri, parse_join_uri,
        percent_encode_component,
    };
    use crate::brand::PREAUTH_KEY_PREFIX;
    use crate::types::{NodeName, SpkiPin};

    fn sample_pin() -> SpkiPin {
        SpkiPin::from_sha256_bytes([0xab_u8; 32])
    }

    fn sample_key() -> String {
        let mut raw = [0_u8; 32];
        for (idx, byte) in raw.iter_mut().enumerate() {
            *byte = u8::try_from(idx + 1).unwrap_or(1);
        }
        format!("{PREAUTH_KEY_PREFIX}{}", BASE64URL_NOPAD.encode(&raw))
    }

    #[test]
    fn test_mobile_uri_parses_ip_pin_and_dns_system_ca_and_redacts_secrets() {
        // Arrange
        let pin = sample_pin();
        let key = sample_key();
        let name = NodeName::parse("pixel-8").ok();
        let ip_uri = format_join_uri(
            "198.51.100.10:443",
            &MobileJoinTlsAuth::SpkiPin(pin),
            &key,
            name.as_ref(),
        )
        .unwrap_or_default();
        let dns_uri = format_join_uri(
            "vpn.example.com:8443",
            &MobileJoinTlsAuth::SystemCa,
            &key,
            None,
        )
        .unwrap_or_default();

        // Act
        let parsed_ip = parse_join_uri(&ip_uri);
        let parsed_dns = parse_join_uri(&dns_uri);

        // Assert
        assert!(parsed_ip.is_ok());
        if let Ok(parsed) = parsed_ip {
            assert_eq!(parsed.control_endpoint, "198.51.100.10:443");
            assert_eq!(parsed.tls_auth, MobileJoinTlsAuth::SpkiPin(pin));
            assert_eq!(parsed.preauth_key(), key);
            assert_eq!(parsed.node_name, name);
            assert!(parsed.is_ip_endpoint());
            let dbg_out = format!("{parsed:?}");
            let disp_out = format!("{parsed}");
            assert!(!dbg_out.contains(&key));
            assert!(!disp_out.contains(&key));
            assert!(dbg_out.contains("[REDACTED]"));
            assert!(disp_out.contains("[REDACTED]"));
        }

        assert!(parsed_dns.is_ok());
        if let Ok(parsed) = parsed_dns {
            assert_eq!(parsed.control_endpoint, "vpn.example.com:8443");
            assert_eq!(parsed.tls_auth, MobileJoinTlsAuth::SystemCa);
            assert!(!parsed.is_ip_endpoint());
        }
    }

    #[test]
    fn test_mobile_uri_rejects_invalid_variants() {
        // Arrange
        let pin = sample_pin();
        let key = sample_key();
        let pin_enc = percent_encode_component(&pin.to_string());

        // Act & Assert
        assert!(parse_join_uri("").is_err());
        assert!(parse_join_uri(&"a".repeat(MAX_MOBILE_JOIN_URI_LEN + 1)).is_err());
        assert!(
            parse_join_uri(&format!(
                "https://join?v=1&ep=198.51.100.10:443&pin={pin_enc}&key={key}"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://enroll?v=1&ep=198.51.100.10:443&pin={pin_enc}&key={key}"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=2&ep=198.51.100.10:443&pin={pin_enc}&key={key}"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=198.51.100.10:443&pin=system-ca&key={key}"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=[2001:db8::1]:443&pin=system-ca&key={key}"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=198.51.100.10:443&pin={pin_enc}&key=mpk_short"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=198.51.100.10:443&pin={pin_enc}&key={key}&extra=1"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=198.51.100.10:443&v=1&pin={pin_enc}&key={key}"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=198.51.100.10:443&pin={pin_enc}&key={key}#frag"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=https://evil.com:443&pin={pin_enc}&key={key}"
            ))
            .is_err()
        );
        assert!(
            parse_join_uri(&format!(
                "mesh://join?v=1&ep=198.51.100.10:443&pin={pin_enc}&key={key}&name=localhost"
            ))
            .is_err()
        );
    }

    proptest! {
        #[test]
        fn proptest_mobile_uri_roundtrip_and_never_panics(
            octet1 in 1_u8..=223,
            octet2 in 0_u8..=255,
            octet3 in 0_u8..=255,
            octet4 in 1_u8..=254,
            port in 1_u16..=65535,
            pin_seed in any::<[u8; 32]>(),
            key_seed in any::<[u8; 32]>(),
            label in "[a-z][a-z0-9]{1,12}",
        ) {
            let ep = format!("{octet1}.{octet2}.{octet3}.{octet4}:{port}");
            let pin = SpkiPin::from_sha256_bytes(pin_seed);
            let key = format!("{PREAUTH_KEY_PREFIX}{}", BASE64URL_NOPAD.encode(&key_seed));
            let node_name = NodeName::parse(&label).ok();

            let formatted = format_join_uri(
                &ep,
                &MobileJoinTlsAuth::SpkiPin(pin),
                &key,
                node_name.as_ref(),
            );
            prop_assert!(formatted.is_ok());
            if let Ok(uri_str) = formatted {
                let parsed = MobileJoinUri::parse(&uri_str);
                prop_assert!(parsed.is_ok());
                if let Ok(parsed_uri) = parsed {
                    prop_assert_eq!(&parsed_uri.control_endpoint, &ep);
                    prop_assert_eq!(parsed_uri.tls_auth, MobileJoinTlsAuth::SpkiPin(pin));
                    prop_assert_eq!(parsed_uri.preauth_key(), key.as_str());
                    prop_assert_eq!(&parsed_uri.node_name, &node_name);
                    let dbg_str = format!("{parsed_uri:?}");
                    prop_assert!(!dbg_str.contains(&key));
                }
            }
        }

        #[test]
        fn proptest_mobile_uri_arbitrary_input_never_panics(arbitrary in "\\PC{0,1200}") {
            if let Ok(parsed) = parse_join_uri(&arbitrary) {
                prop_assert_eq!(parsed.version, 1);
            }
        }
    }
}
