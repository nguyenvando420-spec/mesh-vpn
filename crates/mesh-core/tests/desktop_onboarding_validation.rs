//! Unit and property tests for Desktop onboarding validation (`US-102`, `ADR-025`).

use data_encoding::BASE64URL_NOPAD;
use proptest::prelude::*;

use mesh_core::brand::{DEFAULT_DOMAIN_SUFFIX, PREAUTH_KEY_PREFIX, RESERVED_HOSTNAMES};
use mesh_core::defaults::{DEFAULT_CONTROL_TCP_PORT, MAX_BUGREPORT_ARCHIVE_BYTES};
use mesh_core::{
    ErrorKind, MobileJoinTlsAuth, NodeName, Port, SpkiPin, is_ip_literal_host,
    normalize_control_endpoint, validate_desktop_tls_policy, validate_preauth_key,
};

#[test]
fn test_defaults_max_bugreport_archive_bytes_is_twenty_mib() {
    // Arrange & Act
    let limit = MAX_BUGREPORT_ARCHIVE_BYTES;

    // Assert
    assert_eq!(limit, 20 * 1024 * 1024);
    assert_eq!(limit, 20_971_520);
}

#[test]
fn test_normalize_control_endpoint_handles_ipv4_ipv6_dns_and_port_override() {
    // Arrange
    let custom_port = Port::from_u16(8443).ok();
    let alt_port = Port::from_u16(9443).ok();

    // Act
    let bare_ipv4 = normalize_control_endpoint("203.0.113.10", None);
    let ipv4_override = normalize_control_endpoint("203.0.113.10", custom_port);
    let ipv4_replace = normalize_control_endpoint("203.0.113.10:8443", alt_port);
    let bare_ipv6 = normalize_control_endpoint("2001:db8::1", None);
    let bracket_ipv6 = normalize_control_endpoint("[2001:db8::1]", custom_port);
    let bracket_ipv6_port = normalize_control_endpoint("[2001:db8::1]:8443", None);
    let dns_default = normalize_control_endpoint("VPN.Example.COM", None);
    let dns_explicit = normalize_control_endpoint("vpn.example.com:8443", None);

    // Assert
    assert_eq!(
        bare_ipv4.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some(format!("203.0.113.10:{DEFAULT_CONTROL_TCP_PORT}").as_str())
    );
    assert_eq!(bare_ipv4.as_ref().ok().map(|e| e.is_ip_literal), Some(true));
    assert_eq!(
        ipv4_override.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some("203.0.113.10:8443")
    );
    assert_eq!(
        ipv4_replace.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some("203.0.113.10:9443")
    );
    assert_eq!(
        bare_ipv6.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some(format!("[2001:db8::1]:{DEFAULT_CONTROL_TCP_PORT}").as_str())
    );
    assert_eq!(bare_ipv6.as_ref().ok().map(|e| e.is_ip_literal), Some(true));
    assert_eq!(
        bracket_ipv6.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some("[2001:db8::1]:8443")
    );
    assert_eq!(
        bracket_ipv6_port.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some("[2001:db8::1]:8443")
    );
    assert_eq!(
        dns_default.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some(format!("vpn.example.com:{DEFAULT_CONTROL_TCP_PORT}").as_str())
    );
    assert_eq!(
        dns_default.as_ref().ok().map(|e| e.is_ip_literal),
        Some(false)
    );
    assert_eq!(
        dns_explicit.as_ref().ok().map(|e| e.endpoint.as_str()),
        Some("vpn.example.com:8443")
    );
    assert!(is_ip_literal_host("203.0.113.10"));
    assert!(is_ip_literal_host("[2001:db8::1]"));
    assert!(is_ip_literal_host("2001:db8::1"));
    assert!(!is_ip_literal_host("vpn.example.com"));
}

#[test]
fn test_validate_desktop_tls_policy_locks_system_ca_on_ip_and_rejects_injection() {
    // Arrange
    let pin = SpkiPin::from_sha256_bytes([0x11_u8; 32]);

    // Act
    let ipv4_ca = validate_desktop_tls_policy("203.0.113.10", None, MobileJoinTlsAuth::SystemCa);
    let ipv6_ca = validate_desktop_tls_policy("2001:db8::1", None, MobileJoinTlsAuth::SystemCa);
    let ipv4_pin =
        validate_desktop_tls_policy("203.0.113.10", None, MobileJoinTlsAuth::SpkiPin(pin));
    let dns_ca = validate_desktop_tls_policy("vpn.example.com", None, MobileJoinTlsAuth::SystemCa);
    let scheme_err = normalize_control_endpoint("https://vpn.example.com:8443", None);
    let shell_err = normalize_control_endpoint("vpn.example.com;id", None);
    let crlf_err = normalize_control_endpoint("vpn.example.com\r\n", None);
    let nul_err = normalize_control_endpoint("vpn.example.com\0", None);

    // Assert
    assert_eq!(
        ipv4_ca.err().map(|e| e.kind()),
        Some(ErrorKind::InvalidArgument)
    );
    assert_eq!(
        ipv6_ca.err().map(|e| e.kind()),
        Some(ErrorKind::InvalidArgument)
    );
    assert!(ipv4_pin.is_ok());
    assert!(dns_ca.is_ok());
    assert!(scheme_err.is_err());
    assert!(shell_err.is_err());
    assert!(crlf_err.is_err());
    assert!(nul_err.is_err());
}

#[test]
fn test_validate_preauth_key_and_node_name_enforce_security_boundaries() {
    // Arrange
    let valid_token = format!(
        "{PREAUTH_KEY_PREFIX}{}",
        BASE64URL_NOPAD.encode(&[0x42_u8; 32])
    );
    let short_token = format!(
        "{PREAUTH_KEY_PREFIX}{}",
        BASE64URL_NOPAD.encode(&[0x42_u8; 31])
    );
    let too_long_token = format!("{PREAUTH_KEY_PREFIX}{}", "A".repeat(260));

    // Act & Assert
    assert!(validate_preauth_key(&valid_token).is_ok());
    assert!(validate_preauth_key(&short_token).is_err());
    assert!(validate_preauth_key(&too_long_token).is_err());
    assert!(validate_preauth_key("bad_prefix_1234").is_err());
    assert!(validate_preauth_key(&format!("{valid_token}\n")).is_err());

    for reserved in RESERVED_HOSTNAMES {
        assert!(NodeName::parse(reserved).is_err());
    }
    if let Ok(node) = NodeName::parse("desktop-01") {
        assert!(
            node.validate_against_public_host("desktop-01", DEFAULT_DOMAIN_SUFFIX)
                .is_err()
        );
        assert!(
            node.validate_against_public_host("vpn.example.com", DEFAULT_DOMAIN_SUFFIX)
                .is_ok()
        );
    } else {
        assert!(NodeName::parse("desktop-01").is_ok());
    }
}

proptest! {
    #[test]
    fn proptest_normalize_control_endpoint_never_panics_and_preserves_ip_lock(
        octet1 in 1_u8..=223,
        octet2 in 0_u8..=255,
        octet3 in 0_u8..=255,
        octet4 in 1_u8..=254,
        port in prop::option::of(1_u16..=65535),
        arbitrary in "\\PC{0,200}",
    ) {
        let port_override = port.and_then(|p| Port::from_u16(p).ok());
        let ip_input = format!("{octet1}.{octet2}.{octet3}.{octet4}");
        let res = validate_desktop_tls_policy(&ip_input, port_override, MobileJoinTlsAuth::SystemCa);
        prop_assert!(res.is_err());

        let pin = SpkiPin::from_sha256_bytes([0x5a_u8; 32]);
        let ok_res = validate_desktop_tls_policy(&ip_input, port_override, MobileJoinTlsAuth::SpkiPin(pin));
        prop_assert!(ok_res.is_ok());
        if let Ok(ep) = ok_res {
            let expected_port = port.unwrap_or(DEFAULT_CONTROL_TCP_PORT);
            prop_assert_eq!(ep.port.get(), expected_port);
            prop_assert!(ep.is_ip_literal);
            prop_assert_eq!(ep.endpoint, format!("{ip_input}:{expected_port}"));
        }

        if let Ok(arb_ep) = normalize_control_endpoint(&arbitrary, port_override) {
            prop_assert!(!arb_ep.endpoint.is_empty());
            prop_assert!(!arb_ep.endpoint.contains("://"));
        }
    }

    #[test]
    fn proptest_validate_preauth_key_arbitrary_input_never_panics(
        seed in any::<[u8; 32]>(),
        arbitrary in "\\PC{0,300}",
    ) {
        let valid = format!("{PREAUTH_KEY_PREFIX}{}", BASE64URL_NOPAD.encode(&seed));
        prop_assert!(validate_preauth_key(&valid).is_ok());
        let _ignored = validate_preauth_key(&arbitrary);
    }

    #[test]
    fn proptest_node_name_rfc1123_rules(arbitrary in "\\PC{0,100}") {
        if let Ok(name) = NodeName::parse(&arbitrary) {
            prop_assert!((1..=63).contains(&name.as_str().len()));
            prop_assert!(!name.as_str().starts_with('-'));
            prop_assert!(!name.as_str().ends_with('-'));
            prop_assert!(!RESERVED_HOSTNAMES.contains(&name.as_str()));
        }
    }
}
