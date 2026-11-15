//! SPKI Pin TLS certificate verification and CA client config builders (`SEC-04`, `US-003`, `US-047`).

use std::fmt;
use std::sync::Arc;

#[cfg(all(
    feature = "desktop-certs",
    not(all(
        feature = "mobile-platform-verifier",
        any(target_os = "android", target_os = "ios")
    ))
))]
use rustls::RootCertStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, OtherError, SignatureScheme,
};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

use mesh_core::{AppError, AppResult, SpkiPin};

use crate::hash::{ct_eq_bytes, sha256_digest};

/// Strongly-typed verification failure attached to [`rustls::Error`] without shared mutable state.
#[derive(Debug, Clone)]
enum TlsVerifyFailure {
    ClockSkew(String),
    PinMismatch(String),
}

impl fmt::Display for TlsVerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockSkew(msg) | Self::PinMismatch(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for TlsVerifyFailure {}

/// Active and optional staged backup SPKI pins accepted during TLS rotation (`US-047 AC5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinSet {
    /// Currently primary expected SPKI SHA-256 fingerprint.
    pub active_pin: SpkiPin,
    /// Optional secondary SPKI fingerprint trusted simultaneously during rotation.
    pub next_pin: Option<SpkiPin>,
}

impl PinSet {
    /// Creates a [`PinSet`] trusting only `active_pin`.
    #[must_use]
    pub const fn single(active_pin: SpkiPin) -> Self {
        Self {
            active_pin,
            next_pin: None,
        }
    }

    /// Creates a [`PinSet`] trusting both `active_pin` and `next_pin`.
    #[must_use]
    pub const fn dual(active_pin: SpkiPin, next_pin: SpkiPin) -> Self {
        Self {
            active_pin,
            next_pin: Some(next_pin),
        }
    }

    /// Returns `true` if `observed` equals either `active_pin` or `next_pin` in constant time.
    #[must_use]
    pub fn matches(self, observed: &SpkiPin) -> bool {
        let active_ok = ct_eq_bytes(self.active_pin.as_bytes(), observed.as_bytes());
        let next_ok = self
            .next_pin
            .is_some_and(|next| ct_eq_bytes(next.as_bytes(), observed.as_bytes()));
        active_ok || next_ok
    }
}

/// Parses an X.509 DER certificate via `x509-cert` and computes SHA-256 over
/// `tbs_certificate.subject_public_key_info` DER bytes (`api-design.md` §1).
pub fn extract_spki_pin_from_der(cert_der: &[u8]) -> AppResult<SpkiPin> {
    let cert = Certificate::from_der(cert_der).map_err(|err| {
        AppError::invalid_argument(format!("invalid X.509 DER certificate: {err}"))
    })?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|err| AppError::internal(format!("failed to encode SPKI DER slice: {err}")))?;
    Ok(SpkiPin::from_sha256_bytes(sha256_digest(&spki_der)))
}

/// Zero-TOFU `rustls` certificate verifier enforcing leaf certificate validity window and
/// constant-time SPKI SHA-256 pinning (`SEC-04(c)`, `US-003`, `US-047`).
#[derive(Debug)]
pub struct SpkiPinVerifier {
    pins: PinSet,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl SpkiPinVerifier {
    /// Creates a stateless pinned verifier backed by `rustls::crypto::ring`.
    #[must_use]
    pub fn new(pins: PinSet) -> Self {
        Self {
            pins,
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

fn embedded_cert_error(failure: TlsVerifyFailure) -> Error {
    Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(failure))))
}

/// Converts a [`rustls::Error`] from a TLS handshake or stream into a categorized [`AppError`],
/// extracting stateless clock-skew and SPKI-pin mismatch causes without shared verifier locks.
#[must_use]
pub fn classify_rustls_error(err: &Error) -> AppError {
    if let Error::InvalidCertificate(cert_err) = err {
        return match cert_err {
            CertificateError::Other(other) => {
                if let Some(failure) = other.0.downcast_ref::<TlsVerifyFailure>() {
                    match failure {
                        TlsVerifyFailure::ClockSkew(msg) => AppError::clock_skew(msg.clone()),
                        TlsVerifyFailure::PinMismatch(msg) => AppError::pin_mismatch(msg.clone()),
                    }
                } else {
                    AppError::unavailable(format!("TLS certificate verification failed: {err}"))
                }
            }
            CertificateError::NotValidYet
            | CertificateError::Expired
            | CertificateError::NotValidYetContext { .. }
            | CertificateError::ExpiredContext { .. } => AppError::clock_skew(format!(
                "TLS certificate validity check failed; possible system clock skew: {err}"
            )),
            CertificateError::ApplicationVerificationFailure => {
                AppError::pin_mismatch(format!("TLS certificate verification rejected: {err}"))
            }
            _ => AppError::unavailable(format!("TLS certificate rejected: {err}")),
        };
    }
    AppError::unavailable(format!("TLS connection error: {err}"))
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = Certificate::from_der(end_entity.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;

        let now_secs = now.as_secs();
        let not_before_secs = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after_secs = cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();

        if not_before_secs > not_after_secs {
            return Err(embedded_cert_error(TlsVerifyFailure::ClockSkew(
                "certificate has inverted validity dates".to_owned(),
            )));
        }
        if now_secs < not_before_secs {
            return Err(embedded_cert_error(TlsVerifyFailure::ClockSkew(
                "TLS certificate validity check failed; possible system clock skew".to_owned(),
            )));
        }
        if now_secs > not_after_secs {
            return Err(embedded_cert_error(TlsVerifyFailure::ClockSkew(
                "TLS certificate validity check failed; certificate expired or clock skewed"
                    .to_owned(),
            )));
        }

        let spki_der = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let observed_pin = SpkiPin::from_sha256_bytes(sha256_digest(&spki_der));

        if !self.pins.matches(&observed_pin) {
            return Err(embedded_cert_error(TlsVerifyFailure::PinMismatch(format!(
                "server SPKI pin mismatch (expected {}, got {observed_pin})",
                self.pins.active_pin
            ))));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Builds a TLS 1.3 `rustls::ClientConfig` using the `ring` provider and strict SPKI pinning (no TOFU).
pub fn build_pinned_client_config(pins: PinSet) -> AppResult<Arc<ClientConfig>> {
    let verifier = Arc::new(SpkiPinVerifier::new(pins));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| AppError::internal(format!("failed configuring TLS 1.3 versions: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Builds a TLS 1.3 standard WebPKI `rustls::ClientConfig` trusting OS root certificates (`ring` provider).
///
/// Fails closed if the OS trust store yields zero usable root certificates (`HR-01`) or if the
/// Android JNI verifier context has not been initialized yet (`ADR-014`).
pub fn build_system_ca_client_config() -> AppResult<Arc<ClientConfig>> {
    #[cfg(all(
        feature = "mobile-platform-verifier",
        any(target_os = "android", target_os = "ios")
    ))]
    {
        build_platform_verifier_client_config()
    }
    #[cfg(all(
        feature = "desktop-certs",
        not(all(
            feature = "mobile-platform-verifier",
            any(target_os = "android", target_os = "ios")
        ))
    ))]
    {
        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        for cert in native.certs {
            let _ignored = roots.add(cert);
        }
        build_client_config_from_root_store(roots)
    }
    #[cfg(not(any(
        feature = "desktop-certs",
        all(
            feature = "mobile-platform-verifier",
            any(target_os = "android", target_os = "ios")
        )
    )))]
    {
        Err(AppError::unavailable(
            "system CA verification is unavailable in this build configuration",
        ))
    }
}

#[cfg(all(feature = "mobile-platform-verifier", target_os = "android"))]
fn ensure_android_platform_verifier_initialized() -> AppResult<()> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    static ANDROID_VERIFIER_INITIALIZED: AtomicBool = AtomicBool::new(false);
    static ANDROID_VERIFIER_INIT_LOCK: Mutex<()> = Mutex::new(());

    if ANDROID_VERIFIER_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }
    let _guard = ANDROID_VERIFIER_INIT_LOCK
        .lock()
        .map_err(|_| AppError::internal("Android platform verifier init lock poisoned"))?;
    if ANDROID_VERIFIER_INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }

    mesh_sys::jni_android::with_attached_env_and_context(|env, context| {
        let local_ctx = env.new_local_ref(context).map_err(|err| {
            mesh_sys::error::SysError::io(
                "ensure_android_platform_verifier_initialized",
                std::io::Error::other(format!("failed creating local JNI context ref: {err}")),
            )
        })?;
        rustls_platform_verifier::android::init_hosted(env, local_ctx).map_err(|err| {
            mesh_sys::error::SysError::io(
                "ensure_android_platform_verifier_initialized",
                std::io::Error::other(format!(
                    "failed initializing rustls_platform_verifier Android runtime: {err}"
                )),
            )
        })
    })
    .map_err(AppError::from)?;

    ANDROID_VERIFIER_INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(all(
    feature = "mobile-platform-verifier",
    any(target_os = "android", target_os = "ios")
))]
fn build_platform_verifier_client_config() -> AppResult<Arc<ClientConfig>> {
    use rustls_platform_verifier::BuilderVerifierExt as _;

    #[cfg(target_os = "android")]
    ensure_android_platform_verifier_initialized()?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| AppError::internal(format!("failed configuring TLS 1.3 versions: {err}")))?
        .with_platform_verifier()
        .map_err(|err| {
            AppError::unavailable(format!("failed initializing platform TLS verifier: {err}"))
        })?
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(all(
    feature = "desktop-certs",
    not(all(
        feature = "mobile-platform-verifier",
        any(target_os = "android", target_os = "ios")
    ))
))]
fn build_client_config_from_root_store(roots: RootCertStore) -> AppResult<Arc<ClientConfig>> {
    if roots.is_empty() {
        return Err(AppError::unavailable(
            "system trust store contains zero root certificates",
        ));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| AppError::internal(format!("failed configuring TLS 1.3 versions: {err}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "certgen")]
    use std::time::Duration;

    #[cfg(all(
        feature = "desktop-certs",
        not(all(
            feature = "mobile-platform-verifier",
            any(target_os = "android", target_os = "ios")
        ))
    ))]
    use rustls::RootCertStore;
    #[cfg(feature = "certgen")]
    use rustls::client::danger::ServerCertVerifier as _;
    #[cfg(feature = "certgen")]
    use rustls::pki_types::{CertificateDer, IpAddr, ServerName, UnixTime};
    use rustls::{CertificateError, Error};

    use mesh_core::ErrorKind;
    #[cfg(feature = "certgen")]
    use mesh_core::SpkiPin;

    #[cfg(feature = "certgen")]
    use crate::certgen::generate_ip_pinned_cert;

    #[cfg(all(
        feature = "desktop-certs",
        not(all(
            feature = "mobile-platform-verifier",
            any(target_os = "android", target_os = "ios")
        ))
    ))]
    use super::build_client_config_from_root_store;
    #[cfg(not(any(
        feature = "desktop-certs",
        all(
            feature = "mobile-platform-verifier",
            any(target_os = "android", target_os = "ios")
        )
    )))]
    use super::build_system_ca_client_config;
    use super::classify_rustls_error;
    #[cfg(feature = "certgen")]
    use super::{PinSet, SpkiPinVerifier, build_pinned_client_config, extract_spki_pin_from_der};

    #[cfg(feature = "certgen")]
    #[test]
    fn test_spki_pin_verifier_enforces_pin_dual_rotation_and_clock_bounds() {
        // Arrange
        let base_secs = 1_762_958_151_u64;
        let id = generate_ip_pinned_cert(&["127.0.0.1".to_owned()], 30, base_secs);
        assert!(id.is_ok());
        let Ok(identity) = id else {
            return;
        };

        let cert_der = CertificateDer::from(identity.cert_der.clone());
        let extracted = extract_spki_pin_from_der(cert_der.as_ref());
        assert_eq!(extracted.ok(), Some(identity.spki_pin));

        let server_name = ServerName::IpAddress(IpAddr::from(std::net::Ipv4Addr::LOCALHOST));
        let valid_now = UnixTime::since_unix_epoch(Duration::from_secs(base_secs + 3_600));
        let verifier = SpkiPinVerifier::new(PinSet::single(identity.spki_pin));

        // Act & Assert: matching pin + valid time succeeds
        assert!(
            verifier
                .verify_server_cert(&cert_der, &[], &server_name, &[], valid_now)
                .is_ok()
        );

        // Act & Assert: future cert (`now < not_before`) -> embedded ClockSkew
        let too_early =
            UnixTime::since_unix_epoch(Duration::from_secs(base_secs.saturating_sub(7_200)));
        let early_res = verifier.verify_server_cert(&cert_der, &[], &server_name, &[], too_early);
        assert_eq!(
            early_res.err().map(|e| classify_rustls_error(&e).kind()),
            Some(ErrorKind::ClockSkew)
        );

        // Act & Assert: expired cert (`now > not_after`) -> embedded ClockSkew
        let too_late = UnixTime::since_unix_epoch(Duration::from_secs(base_secs + 40 * 86_400));
        let late_res = verifier.verify_server_cert(&cert_der, &[], &server_name, &[], too_late);
        assert_eq!(
            late_res.err().map(|e| classify_rustls_error(&e).kind()),
            Some(ErrorKind::ClockSkew)
        );

        // Act & Assert: wrong pin -> embedded PinMismatch
        let wrong_pin = SpkiPin::from_sha256_bytes([0xff_u8; 32]);
        let wrong_verifier = SpkiPinVerifier::new(PinSet::single(wrong_pin));
        let bad_pin =
            wrong_verifier.verify_server_cert(&cert_der, &[], &server_name, &[], valid_now);
        assert_eq!(
            bad_pin.err().map(|e| classify_rustls_error(&e).kind()),
            Some(ErrorKind::PinMismatch)
        );

        // Dual pin rotation allows next_pin match
        let dual_verifier = SpkiPinVerifier::new(PinSet::dual(wrong_pin, identity.spki_pin));
        assert!(
            dual_verifier
                .verify_server_cert(&cert_der, &[], &server_name, &[], valid_now)
                .is_ok()
        );
        assert!(build_pinned_client_config(PinSet::single(identity.spki_pin)).is_ok());
    }

    #[cfg(all(
        feature = "desktop-certs",
        not(all(
            feature = "mobile-platform-verifier",
            any(target_os = "android", target_os = "ios")
        ))
    ))]
    #[test]
    fn test_system_ca_fails_closed_when_empty_and_webpki_expiry_maps_clock_skew() {
        // Arrange & Act
        let empty_roots_res = build_client_config_from_root_store(RootCertStore::empty());
        let expired_webpki =
            classify_rustls_error(&Error::InvalidCertificate(CertificateError::Expired));

        // Assert
        assert_eq!(
            empty_roots_res.err().map(|e| e.kind()),
            Some(ErrorKind::Unavailable)
        );
        assert_eq!(expired_webpki.kind(), ErrorKind::ClockSkew);
    }

    #[cfg(not(any(
        feature = "desktop-certs",
        all(
            feature = "mobile-platform-verifier",
            any(target_os = "android", target_os = "ios")
        )
    )))]
    #[test]
    fn test_system_ca_unavailable_without_cert_features() {
        // Arrange & Act
        let res = build_system_ca_client_config();

        // Assert
        assert_eq!(res.err().map(|e| e.kind()), Some(ErrorKind::Unavailable));
    }

    #[test]
    fn test_classify_rustls_errors_cover_clock_skew_and_pin_rejection() {
        // Arrange
        let not_yet = Error::InvalidCertificate(CertificateError::NotValidYet);
        let expired = Error::InvalidCertificate(CertificateError::Expired);
        let app_rejected =
            Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
        let revoked = Error::InvalidCertificate(CertificateError::Revoked);

        // Act & Assert
        assert_eq!(classify_rustls_error(&not_yet).kind(), ErrorKind::ClockSkew);
        assert_eq!(classify_rustls_error(&expired).kind(), ErrorKind::ClockSkew);
        assert_eq!(
            classify_rustls_error(&app_rejected).kind(),
            ErrorKind::PinMismatch
        );
        assert_eq!(
            classify_rustls_error(&revoked).kind(),
            ErrorKind::Unavailable
        );
    }
}
