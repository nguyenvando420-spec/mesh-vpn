//! Self-signed IP-pinned certificate generation, SPKI-preserving renewal (`US-047 AC5`), and
//! safe `Secret<T>` bridges to construct `rustls::ServerConfig` without downstream crates
//! ever touching `.expose_secret()`.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rcgen::{
    CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    date_time_ymd,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};
use zeroize::{Zeroize as _, Zeroizing};

use mesh_core::{AppError, AppResult, SpkiPin};

use crate::hash::sha256_digest;
use crate::secret::Secret;
use crate::tlspin::extract_spki_pin_from_der;

/// Newly generated or reissued TLS certificate + protected private key + derived SPKI pin.
#[derive(Debug)]
pub struct GeneratedTlsIdentity {
    /// PEM-encoded leaf X.509 certificate.
    pub cert_pem: String,
    /// DER-encoded leaf X.509 certificate.
    pub cert_der: Vec<u8>,
    /// PEM-encoded PKCS#8 ECDSA private key inside [`Secret`].
    pub key_pkcs8_pem: Secret<String>,
    /// DER-encoded PKCS#8 ECDSA private key inside [`Secret`].
    pub key_pkcs8_der: Secret<Vec<u8>>,
    /// Derived SPKI SHA-256 fingerprint matching `x509_cert` extraction.
    pub spki_pin: SpkiPin,
}

/// Generates a fresh ECDSA P-256 self-signed certificate bound to `san_ips_and_hosts`.
pub fn generate_ip_pinned_cert(
    san_ips_and_hosts: &[String],
    valid_days: u32,
    now_unix_secs: u64,
) -> AppResult<GeneratedTlsIdentity> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|err| {
        AppError::internal(format!("failed generating ECDSA P-256 keypair: {err}"))
    })?;
    issue_with_key_pair(&key_pair, san_ips_and_hosts, valid_days, now_unix_secs)
}

/// Re-issues a leaf TLS certificate reusing `existing_key_pkcs8_der` so the peer `SpkiPin`
/// stays identical across automatic renewals (`US-047 AC5`).
pub fn reissue_cert_preserving_key(
    existing_key_pkcs8_der: &Secret<Vec<u8>>,
    san_ips_and_hosts: &[String],
    valid_days: u32,
    now_unix_secs: u64,
) -> AppResult<GeneratedTlsIdentity> {
    let key_der = PrivatePkcs8KeyDer::from(existing_key_pkcs8_der.expose_secret().as_slice());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|err| AppError::internal(format!("failed loading PKCS#8 ECDSA key: {err}")))?;
    issue_with_key_pair(&key_pair, san_ips_and_hosts, valid_days, now_unix_secs)
}

fn issue_with_key_pair(
    key_pair: &KeyPair,
    san_ips_and_hosts: &[String],
    valid_days: u32,
    now_unix_secs: u64,
) -> AppResult<GeneratedTlsIdentity> {
    let mut params = CertificateParams::new(san_ips_and_hosts.to_vec())
        .map_err(|err| AppError::invalid_argument(format!("invalid SAN list: {err}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, "mesh-server");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let epoch = date_time_ymd(1970, 1, 1);
    let backdate_secs = now_unix_secs.saturating_sub(3_600);
    let expiry_secs =
        now_unix_secs.saturating_add(u64::from(valid_days.max(1)).saturating_mul(86_400));
    params.not_before = epoch + Duration::from_secs(backdate_secs);
    params.not_after = epoch + Duration::from_secs(expiry_secs);

    let cert = params
        .self_signed(key_pair)
        .map_err(|err| AppError::internal(format!("failed signing X.509 certificate: {err}")))?;
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let spki_pin = extract_spki_pin_from_der(&cert_der)?;

    Ok(GeneratedTlsIdentity {
        cert_pem,
        cert_der,
        key_pkcs8_pem: Secret::new(key_pair.serialize_pem()),
        key_pkcs8_der: Secret::new(key_pair.serialize_der()),
        spki_pin,
    })
}

/// Parses one or more X.509 certificates from PEM using `rustls-pki-types` (`PemObject`).
pub fn load_certs_from_pem(pem_bytes: &[u8]) -> AppResult<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem_bytes) {
        let cert = item
            .map_err(|err| AppError::invalid_argument(format!("invalid certificate PEM: {err}")))?;
        certs.push(cert);
    }
    if certs.is_empty() {
        return Err(AppError::invalid_argument(
            "certificate PEM contains no CERTIFICATE blocks",
        ));
    }
    Ok(certs)
}

/// Parses a single private key PEM (`PRIVATE KEY`, `EC PRIVATE KEY`, or `RSA PRIVATE KEY`) into
/// [`Secret<Vec<u8>>`] PKCS#8/DER bytes using `rustls-pki-types`.
pub fn parse_private_key_from_pem(key_pem: &Secret<String>) -> AppResult<Secret<Vec<u8>>> {
    let parsed = PrivateKeyDer::from_pem_slice(key_pem.expose_secret().as_bytes())
        .map_err(|err| AppError::invalid_argument(format!("invalid private key PEM: {err}")))?;
    let owned_der = parsed.secret_der().to_vec();
    Ok(Secret::new(owned_der))
}

/// Builds a `rustls::ServerConfig` (`ring` provider) directly from DER certs and a [`Secret<Vec<u8>>`]
/// PKCS#8 private key so caller crates never invoke `.expose_secret()`.
pub fn build_rustls_server_config_from_der(
    cert_chain_der: Vec<Vec<u8>>,
    key_pkcs8_der: &Secret<Vec<u8>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> AppResult<ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = cert_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let key_der = PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(key_pkcs8_der.expose_secret().as_slice()).clone_key(),
    );

    build_server_config_inner(certs, key_der, alpn_protocols)
}

/// Builds a `rustls::ServerConfig` (`ring` provider) directly from PEM certs and a protected key PEM.
pub fn build_rustls_server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &Secret<String>,
    alpn_protocols: Vec<Vec<u8>>,
) -> AppResult<ServerConfig> {
    let certs = load_certs_from_pem(cert_pem)?;
    let key_der = PrivateKeyDer::from_pem_slice(key_pem.expose_secret().as_bytes())
        .map_err(|err| AppError::invalid_argument(format!("invalid TLS private key PEM: {err}")))?;
    build_server_config_inner(certs, key_der, alpn_protocols)
}

/// Generated ACME ECDSA P-256 PKCS#10 CSR DER and matching protected private key (`US-047`, `BLK-02`).
#[derive(Debug)]
pub struct GeneratedAcmeCsr {
    /// DER-encoded PKCS#10 Certificate Signing Request (`instant-acme::Order::finalize`).
    pub csr_der: Vec<u8>,
    /// Protected PKCS#8 DER ECDSA P-256 private key paired with the CSR.
    pub key_pkcs8_der: Secret<Vec<u8>>,
    /// Protected PKCS#8 PEM ECDSA P-256 private key paired with the CSR.
    pub key_pkcs8_pem: Secret<String>,
    /// Derived SPKI SHA-256 fingerprint matching certificates issued from this CSR.
    pub spki_pin: SpkiPin,
}

/// Encodes PKCS#8 DER private key bytes into standard Base64 inside [`Zeroizing<String>`]
/// so `mesh-store` can persist keys without invoking `.expose_secret()`.
#[must_use]
pub fn encode_pkcs8_der_for_keystore(secret: &Secret<Vec<u8>>) -> Zeroizing<String> {
    Zeroizing::new(STANDARD.encode(secret.expose_secret().as_slice()))
}

/// Decodes standard Base64 PKCS#8 DER key material from keystore storage into a [`Secret`],
/// zeroizing any temporary buffers and rejecting empty inputs.
pub fn decode_pkcs8_der_from_keystore(encoded: &str) -> AppResult<Secret<Vec<u8>>> {
    let trimmed = encoded.trim();
    if trimmed.is_empty() {
        return Err(AppError::invalid_argument(
            "keystore encoded private key must not be empty",
        ));
    }
    let mut decoded = STANDARD.decode(trimmed).map_err(|err| {
        AppError::invalid_argument(format!("invalid keystore private key base64: {err}"))
    })?;
    if decoded.is_empty() {
        decoded.zeroize();
        return Err(AppError::invalid_argument(
            "decoded keystore private key must not be empty",
        ));
    }
    Ok(Secret::new(decoded))
}

/// Generates a PKCS#10 DER Certificate Signing Request for ACME DNS domains using `rcgen`.
///
/// Reuses `existing_key_pkcs8_der` when supplied so peer `SpkiPin` stays stable across
/// renewals (`US-047 AC5`), or generates a fresh ECDSA P-256 keypair when `None`.
pub fn generate_acme_csr_der(
    domains: &[String],
    existing_key_pkcs8_der: Option<&Secret<Vec<u8>>>,
) -> AppResult<GeneratedAcmeCsr> {
    if domains.is_empty() {
        return Err(AppError::invalid_argument(
            "ACME CSR requires at least one DNS domain",
        ));
    }
    let key_pair = match existing_key_pkcs8_der {
        Some(existing) => {
            let key_der = PrivatePkcs8KeyDer::from(existing.expose_secret().as_slice());
            KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(|err| {
                    AppError::invalid_argument(format!(
                        "failed loading PKCS#8 ECDSA key for ACME CSR: {err}"
                    ))
                })?
        }
        None => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|err| {
            AppError::internal(format!("failed generating ECDSA P-256 ACME keypair: {err}"))
        })?,
    };
    let params = CertificateParams::new(domains.to_vec()).map_err(|err| {
        AppError::invalid_argument(format!("invalid ACME CSR domain list: {err}"))
    })?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|err| AppError::internal(format!("failed serializing ACME PKCS#10 CSR: {err}")))?;
    let spki_pin = SpkiPin::from_sha256_bytes(sha256_digest(&key_pair.public_key_der()));
    Ok(GeneratedAcmeCsr {
        csr_der: csr.der().to_vec(),
        key_pkcs8_der: Secret::new(key_pair.serialize_der()),
        key_pkcs8_pem: Secret::new(key_pair.serialize_pem()),
        spki_pin,
    })
}

/// Generates a short-lived RFC 8737 `tls-alpn-01` validation certificate carrying the
/// critical `id-pe-acmeIdentifier` (`1.3.6.1.5.5.7.1.31`) extension for `domain`.
pub fn generate_tls_alpn_01_challenge_cert(
    domain: &str,
    key_auth_sha256: [u8; 32],
    now_unix_secs: u64,
) -> AppResult<GeneratedTlsIdentity> {
    let trimmed_domain = domain.trim();
    if trimmed_domain.is_empty() {
        return Err(AppError::invalid_argument(
            "TLS-ALPN-01 challenge certificate requires non-empty DNS domain",
        ));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|err| {
        AppError::internal(format!(
            "failed generating TLS-ALPN-01 ECDSA P-256 keypair: {err}"
        ))
    })?;
    let mut params = CertificateParams::new(vec![trimmed_domain.to_owned()])
        .map_err(|err| AppError::invalid_argument(format!("invalid ACME SAN domain: {err}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, trimmed_domain);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(&key_auth_sha256));

    let epoch = date_time_ymd(1970, 1, 1);
    let backdate_secs = now_unix_secs.saturating_sub(3_600);
    let expiry_secs = now_unix_secs.saturating_add(7 * 86_400);
    params.not_before = epoch + Duration::from_secs(backdate_secs);
    params.not_after = epoch + Duration::from_secs(expiry_secs);

    let cert = params.self_signed(&key_pair).map_err(|err| {
        AppError::internal(format!("failed signing TLS-ALPN-01 certificate: {err}"))
    })?;
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let spki_pin = extract_spki_pin_from_der(&cert_der)?;

    Ok(GeneratedTlsIdentity {
        cert_pem,
        cert_der,
        key_pkcs8_pem: Secret::new(key_pair.serialize_pem()),
        key_pkcs8_der: Secret::new(key_pair.serialize_der()),
        spki_pin,
    })
}

/// Parses a DER-encoded X.509 certificate via `x509-cert` and extracts its `NotAfter` UTC
/// timestamp in milliseconds (`BLK-S1-03`).
pub fn extract_cert_not_after_ms_from_der(cert_der: &[u8]) -> AppResult<u64> {
    let cert = Certificate::from_der(cert_der).map_err(|err| {
        AppError::invalid_argument(format!("invalid X.509 DER certificate: {err}"))
    })?;
    let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration();
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
    if not_before > not_after {
        return Err(AppError::invalid_argument(
            "certificate has inverted validity dates",
        ));
    }
    let not_after_ms = not_after.as_millis();
    u64::try_from(not_after_ms).map_err(|_| {
        AppError::invalid_argument("certificate NotAfter timestamp overflows u64 milliseconds")
    })
}

/// Constructs a `rustls::sign::CertifiedKey` for RFC 8737 `tls-alpn-01` challenge certificates.
///
/// `rustls::ServerConfig::with_single_cert` uses `webpki` certificate validation which rejects
/// unknown critical extensions (`id-pe-acmeIdentifier`). Building [`CertifiedKey::new`] directly
/// after validating key/SPKI consistency via `x509-cert` lets `acme-tls/1` handshakes succeed.
pub fn build_tls_alpn_certified_key_from_der(
    cert_chain_der: Vec<Vec<u8>>,
    key_pkcs8_der: &Secret<Vec<u8>>,
) -> AppResult<Arc<CertifiedKey>> {
    let leaf_der = cert_chain_der.first().ok_or_else(|| {
        AppError::invalid_argument("TLS-ALPN-01 certificate chain must not be empty")
    })?;
    let parsed = Certificate::from_der(leaf_der).map_err(|err| {
        AppError::invalid_argument(format!("invalid TLS-ALPN-01 leaf X.509 DER: {err}"))
    })?;
    let cert_spki_der = parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|err| {
            AppError::internal(format!("failed encoding TLS-ALPN-01 SPKI DER: {err}"))
        })?;

    let key_der = PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(key_pkcs8_der.expose_secret().as_slice()).clone_key(),
    );
    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .map_err(|err| {
            AppError::invalid_argument(format!("invalid TLS-ALPN-01 private key DER: {err}"))
        })?;
    let key_spki = signing_key.public_key().ok_or_else(|| {
        AppError::invalid_argument("TLS-ALPN-01 signing key did not expose SPKI bytes")
    })?;
    if key_spki.as_ref() != cert_spki_der.as_slice() {
        return Err(AppError::invalid_argument(
            "TLS-ALPN-01 certificate SPKI does not match private key",
        ));
    }

    let certs: Vec<CertificateDer<'static>> = cert_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

fn build_server_config_inner(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn_protocols: Vec<Vec<u8>>,
) -> AppResult<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| {
            AppError::internal(format!("failed configuring server TLS 1.3 versions: {err}"))
        })?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| AppError::invalid_argument(format!("invalid TLS cert/key pair: {err}")))?;
    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use x509_cert::Certificate;
    use x509_cert::der::Decode as _;

    use super::{
        build_rustls_server_config_from_der, build_rustls_server_config_from_pem,
        build_tls_alpn_certified_key_from_der, decode_pkcs8_der_from_keystore,
        encode_pkcs8_der_for_keystore, extract_cert_not_after_ms_from_der, generate_acme_csr_der,
        generate_ip_pinned_cert, generate_tls_alpn_01_challenge_cert, load_certs_from_pem,
        parse_private_key_from_pem, reissue_cert_preserving_key,
    };

    #[test]
    fn test_reissue_cert_preserves_exact_spki_pin() {
        // Arrange
        let now = 1_762_958_151_u64;
        let sans = vec!["203.0.113.10".to_owned(), "vps.example.com".to_owned()];
        let initial_res = generate_ip_pinned_cert(&sans, 30, now);
        assert!(initial_res.is_ok());
        let Ok(initial) = initial_res else {
            return;
        };

        // Act
        let renewed_res =
            reissue_cert_preserving_key(&initial.key_pkcs8_der, &sans, 60, now + 86_400);
        assert!(renewed_res.is_ok());
        let Ok(renewed) = renewed_res else {
            return;
        };

        // Assert: certificate bytes differ, SPKI pin stays identical!
        assert_ne!(initial.cert_der, renewed.cert_der);
        assert_eq!(initial.spki_pin, renewed.spki_pin);

        // Verify PEM parsing and rustls ServerConfig bridges succeed
        let parsed_certs = load_certs_from_pem(renewed.cert_pem.as_bytes());
        assert_eq!(parsed_certs.map(|v| v.len()).ok(), Some(1));
        assert!(parse_private_key_from_pem(&renewed.key_pkcs8_pem).is_ok());
        assert!(
            build_rustls_server_config_from_der(
                vec![renewed.cert_der.clone()],
                &renewed.key_pkcs8_der,
                vec![b"http/1.1".to_vec()],
            )
            .is_ok()
        );
        assert!(
            build_rustls_server_config_from_pem(
                renewed.cert_pem.as_bytes(),
                &renewed.key_pkcs8_pem,
                vec![b"http/1.1".to_vec()],
            )
            .is_ok()
        );
    }

    #[test]
    fn test_keystore_pkcs8_der_roundtrip_and_acme_csr_generation() {
        // Arrange
        let domains = vec!["vpn.example.com".to_owned()];

        // Act
        let first_csr = generate_acme_csr_der(&domains, None);
        assert!(first_csr.is_ok());
        let Ok(first) = first_csr else {
            return;
        };

        let encoded = encode_pkcs8_der_for_keystore(&first.key_pkcs8_der);
        let decoded = decode_pkcs8_der_from_keystore(&encoded);
        assert!(decoded.is_ok());
        let Ok(restored_key) = decoded else {
            return;
        };
        let second_csr = generate_acme_csr_der(&domains, Some(&restored_key));

        // Assert
        assert!(!first.csr_der.is_empty());
        assert_eq!(
            restored_key.expose_secret().as_slice(),
            first.key_pkcs8_der.expose_secret().as_slice()
        );
        assert!(second_csr.is_ok());
        if let Ok(second) = second_csr {
            assert_eq!(second.spki_pin, first.spki_pin);
            assert!(!second.csr_der.is_empty());
        }
        assert!(decode_pkcs8_der_from_keystore("").is_err());
        assert!(decode_pkcs8_der_from_keystore("not!base64").is_err());
        assert!(generate_acme_csr_der(&[], None).is_err());
    }

    #[test]
    fn test_tls_alpn_01_challenge_cert_and_extract_not_after_ms() {
        // Arrange
        let now_secs = 1_762_958_151_u64;
        let digest = [0x5A_u8; 32];

        // Act
        let alpn_res = generate_tls_alpn_01_challenge_cert("vpn.example.com", digest, now_secs);
        assert!(alpn_res.is_ok());
        let Ok(alpn) = alpn_res else {
            return;
        };
        let not_after_ms = extract_cert_not_after_ms_from_der(&alpn.cert_der);

        // Assert: id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31) critical extension contains OCTET STRING(digest)
        let parsed = Certificate::from_der(&alpn.cert_der);
        assert!(parsed.is_ok());
        if let Ok(cert) = parsed {
            let acme_ext = cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
                exts.iter()
                    .find(|e| e.extn_id.to_string() == "1.3.6.1.5.5.7.1.31")
            });
            assert!(acme_ext.is_some());
            if let Some(ext) = acme_ext {
                assert!(ext.critical);
                let mut expected_der_val = Vec::with_capacity(34);
                expected_der_val.extend_from_slice(&[0x04, 0x20]);
                expected_der_val.extend_from_slice(&digest);
                assert_eq!(ext.extn_value.as_bytes(), expected_der_val.as_slice());
            }
        }
        assert_eq!(not_after_ms.ok(), Some((now_secs + 7 * 86_400) * 1_000));
        let cert_key_res =
            build_tls_alpn_certified_key_from_der(vec![alpn.cert_der.clone()], &alpn.key_pkcs8_der);
        assert!(cert_key_res.is_ok(), "unexpected error: {cert_key_res:?}");
        if let Ok(cert_key) = cert_key_res {
            assert_eq!(cert_key.cert.len(), 1);
        }
        let wrong_res = generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 30, now_secs);
        assert!(wrong_res.is_ok(), "unexpected error: {wrong_res:?}");
        if let Ok(wrong) = wrong_res {
            assert!(
                build_tls_alpn_certified_key_from_der(vec![alpn.cert_der], &wrong.key_pkcs8_der)
                    .is_err()
            );
        }
        assert!(generate_tls_alpn_01_challenge_cert("  ", digest, now_secs).is_err());
        assert!(extract_cert_not_after_ms_from_der(b"not-der").is_err());
    }
}
