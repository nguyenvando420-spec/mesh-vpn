//! TLS server identity management, hot certificate resolver, and zero-port-80 ACME coordinator
//! (`tls-alpn-01` on default control port / `dns-01` on custom port, `US-047`, `WP-S1-01`).

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, HttpClient, Identifier,
    NewAccount, NewOrder, OrderStatus,
};
use rustls::ServerConfig as RustlsServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Serialize;

use mesh_core::{AppError, AppResult, SpkiPin};
use mesh_crypto::{
    GeneratedAcmeCsr, Secret, build_rustls_server_config_from_der,
    build_tls_alpn_certified_key_from_der, extract_cert_not_after_ms_from_der,
    generate_acme_csr_der, generate_tls_alpn_01_challenge_cert, load_certs_from_pem,
};
use mesh_store::{ControlStore, ServerIdentity};

use crate::config::{AcmeChallengeKind, ServerConfig, TlsMode};

/// RFC 8737 `tls-alpn-01` ALPN protocol identifier allowing validation without port 80.
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// ACME certificate renewal window (`30 days` prior to expiration per `US-047 AC2`).
pub const ACME_RENEW_BEFORE_MS: u64 = 30 * 86_400 * 1_000;

/// Operational alert threshold (`< 14 days` remaining until expiration per `US-047 AC2`).
pub const CERT_ALERT_THRESHOLD_MS: u64 = 14 * 86_400 * 1_000;

/// Default Let's Encrypt ACME v2 directory endpoint.
pub const LETS_ENCRYPT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Installs the process-global `rustls` `ring` crypto provider once so HTTPS clients (`reqwest`)
/// work reliably under `"rustls-tls-native-roots-no-provider"`.
pub(crate) fn ensure_rustls_ring_provider() {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::trace!(
            component = "acme",
            event = "rustls_provider_already_set",
            "rustls default crypto provider already installed"
        );
    }
}

/// Hot-swappable TLS certificate resolver supporting standard HTTPS and `acme-tls/1` handshakes.
pub struct MeshCertResolver {
    primary_resolver: RwLock<Option<Arc<dyn ResolvesServerCert>>>,
    acme_alpn_key: RwLock<Option<Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for MeshCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_primary = self.primary_resolver.read().is_ok_and(|g| g.is_some());
        let has_alpn = self.acme_alpn_key.read().is_ok_and(|g| g.is_some());
        f.debug_struct("MeshCertResolver")
            .field("has_primary", &has_primary)
            .field("has_alpn_challenge", &has_alpn)
            .finish()
    }
}

impl Default for MeshCertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshCertResolver {
    /// Creates an empty certificate resolver pending identity installation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            primary_resolver: RwLock::new(None),
            acme_alpn_key: RwLock::new(None),
        }
    }

    /// Atomically installs the active TLS identity into the resolver without copying raw key bytes.
    pub fn install_identity(&self, identity: &ServerIdentity) -> AppResult<()> {
        let built = build_rustls_server_config_from_der(
            identity.cert_chain_der.clone(),
            &identity.private_key_der,
            Vec::new(),
        )?;
        let mut guard = self
            .primary_resolver
            .write()
            .map_err(|_| AppError::internal("primary TLS resolver rwlock poisoned"))?;
        *guard = Some(built.cert_resolver);
        Ok(())
    }

    /// Temporarily serves an `acme-tls/1` validation certificate on TLS connections carrying ALPN `acme-tls/1`.
    pub fn set_acme_alpn_challenge(
        &self,
        cert_chain_der: Vec<Vec<u8>>,
        key_pkcs8_der: &Secret<Vec<u8>>,
    ) -> AppResult<()> {
        let certified_key = build_tls_alpn_certified_key_from_der(cert_chain_der, key_pkcs8_der)?;
        let mut guard = self
            .acme_alpn_key
            .write()
            .map_err(|_| AppError::internal("ACME ALPN resolver rwlock poisoned"))?;
        *guard = Some(certified_key);
        Ok(())
    }

    /// Removes the temporary `acme-tls/1` validation certificate after challenge completion.
    pub fn clear_acme_alpn_challenge(&self) {
        if let Ok(mut guard) = self.acme_alpn_key.write() {
            *guard = None;
        }
    }

    /// Returns `true` when an ephemeral `acme-tls/1` challenge certificate is currently armed.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn has_acme_alpn_challenge(&self) -> bool {
        self.acme_alpn_key.read().is_ok_and(|guard| guard.is_some())
    }
}

impl ResolvesServerCert for MeshCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wants_acme_tls_alpn = client_hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|proto| proto == ACME_TLS_ALPN_PROTOCOL));
        if wants_acme_tls_alpn
            && let Ok(guard) = self.acme_alpn_key.read()
            && let Some(ref alpn_key) = *guard
        {
            return Some(Arc::clone(alpn_key));
        }
        let guard = self.primary_resolver.read().ok()?;
        guard.as_ref()?.resolve(client_hello)
    }
}

/// Runtime certificate health & renewal metadata reported via Admin/Metrics/Alert workers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsLifecycleStatus {
    /// Active SPKI SHA-256 fingerprint pin.
    pub active_pin: SpkiPin,
    /// Optional staged or grace-period secondary SPKI pin.
    pub next_pin: Option<SpkiPin>,
    /// Active certificate `NotAfter` UTC timestamp in milliseconds.
    pub cert_not_after_ms: u64,
    /// `true` once a CA-issued certificate has been installed and verified; `false` on self-signed bootstrap.
    pub ca_verified: bool,
    /// Last automatic renewal attempt UTC timestamp in milliseconds.
    pub last_renewal_attempt_ms: Option<u64>,
    /// Non-secret summary of latest renewal error when renewal failed.
    pub last_renewal_error: Option<String>,
    /// Active `_acme-challenge` DNS-01 `(fqdn, txt_value)` awaiting external DNS propagation.
    pub pending_dns_challenge_txt: Option<(String, String)>,
}

/// Manages TLS certificates, SPKI-preserving renewals, and ACME zero-port-80 workflows.
#[derive(Debug)]
pub struct AcmeManager {
    config: ServerConfig,
    store: Arc<ControlStore>,
    resolver: Arc<MeshCertResolver>,
    status: Mutex<TlsLifecycleStatus>,
}

impl AcmeManager {
    /// Initializes server TLS identity from `ControlStore` and activates hot `MeshCertResolver`.
    pub fn initialize(config: &ServerConfig, store: Arc<ControlStore>) -> AppResult<Arc<Self>> {
        let sans = build_san_list(config);
        let identity = store.ensure_or_init_identity(&sans, 90)?;
        let now_ms = store.clock().now_unix_ms();
        let pin_set = identity.to_pin_set_dto(now_ms);
        let resolver = Arc::new(MeshCertResolver::new());
        resolver.install_identity(&identity)?;

        let status = TlsLifecycleStatus {
            active_pin: pin_set.active_pin,
            next_pin: pin_set.next_pin,
            cert_not_after_ms: identity.not_after_ms,
            ca_verified: identity.ca_verified,
            last_renewal_attempt_ms: None,
            last_renewal_error: None,
            pending_dns_challenge_txt: None,
        };

        Ok(Arc::new(Self {
            config: config.clone(),
            store,
            resolver,
            status: Mutex::new(status),
        }))
    }

    /// Status label reported during subsystem verification.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "acme_tls_manager:ready"
    }

    /// Returns the shared hot-swappable certificate resolver.
    #[must_use]
    pub fn resolver(&self) -> Arc<MeshCertResolver> {
        Arc::clone(&self.resolver)
    }

    /// Builds a strict TLS 1.3 `rustls::ServerConfig` bound to [`MeshCertResolver`].
    pub fn build_rustls_config(&self) -> AppResult<Arc<RustlsServerConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_cfg = RustlsServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| AppError::internal(format!("failed configuring TLS 1.3: {err}")))?
            .with_no_client_auth()
            .with_cert_resolver(self.resolver());

        let mut alpns = vec![b"http/1.1".to_vec()];
        if self.config.tls_mode == TlsMode::Acme
            && self.config.acme.challenge == AcmeChallengeKind::TlsAlpn01
        {
            alpns.push(ACME_TLS_ALPN_PROTOCOL.to_vec());
        }
        tls_cfg.alpn_protocols = alpns;
        Ok(Arc::new(tls_cfg))
    }

    /// Reloads active TLS identity from `ControlStore` and swaps it live in [`MeshCertResolver`].
    pub fn reload_from_store(&self) -> AppResult<TlsLifecycleStatus> {
        let identity = self.store.load_active_identity()?;
        let now_ms = self.store.clock().now_unix_ms();
        let pin_set = identity.to_pin_set_dto(now_ms);
        self.resolver.install_identity(&identity)?;

        let mut guard = self
            .status
            .lock()
            .map_err(|_| AppError::internal("TLS lifecycle status mutex poisoned"))?;
        guard.active_pin = pin_set.active_pin;
        guard.next_pin = pin_set.next_pin;
        guard.cert_not_after_ms = identity.not_after_ms;
        guard.ca_verified = identity.ca_verified;
        Ok(guard.clone())
    }

    /// Persists a CA-issued leaf/chain certificate and marks TLS lifecycle as CA-verified.
    pub fn install_ca_issued_cert(
        &self,
        cert_chain_der: Vec<Vec<u8>>,
        ca_not_after_ms: u64,
        reason: &str,
    ) -> AppResult<TlsLifecycleStatus> {
        let updated = self
            .store
            .save_ca_issued_cert(cert_chain_der, ca_not_after_ms, reason)?;
        self.resolver.install_identity(&updated)?;
        let pin_set = updated.to_pin_set_dto(self.store.clock().now_unix_ms());
        let mut guard = self
            .status
            .lock()
            .map_err(|_| AppError::internal("TLS lifecycle status mutex poisoned"))?;
        guard.active_pin = pin_set.active_pin;
        guard.next_pin = pin_set.next_pin;
        guard.cert_not_after_ms = updated.not_after_ms;
        guard.ca_verified = updated.ca_verified;
        guard.last_renewal_error = None;
        Ok(guard.clone())
    }

    /// Generates a PKCS#10 ACME CSR reusing the server's active private key so peer SPKI pins
    /// do not break upon ACME certificate renewal (`US-047 AC5`).
    pub fn prepare_key_preserving_csr(&self) -> AppResult<GeneratedAcmeCsr> {
        let domains = build_san_list(&self.config);
        self.prepare_key_preserving_csr_for_domains(&domains)
    }

    fn prepare_key_preserving_csr_for_domains(
        &self,
        domains: &[String],
    ) -> AppResult<GeneratedAcmeCsr> {
        let identity = self.store.load_active_identity()?;
        generate_acme_csr_der(domains, Some(&identity.private_key_der))
    }

    /// Returns `true` when remaining certificate validity is within the 30-day renewal window
    /// or when `TlsMode::Acme` is still running on an unverified self-signed bootstrap certificate.
    #[must_use]
    pub fn needs_renewal(&self, now_unix_ms: u64) -> bool {
        self.status
            .lock()
            .map(|s| {
                (self.config.tls_mode == TlsMode::Acme && !s.ca_verified)
                    || s.cert_not_after_ms <= now_unix_ms.saturating_add(ACME_RENEW_BEFORE_MS)
            })
            .unwrap_or(false)
    }

    /// Returns `true` when certificate expires in less than 14 days (`US-047 AC2`, `US-049`).
    #[must_use]
    pub fn cert_expires_within_14_days(&self, now_unix_ms: u64) -> bool {
        self.status
            .lock()
            .map(|s| s.cert_not_after_ms <= now_unix_ms.saturating_add(CERT_ALERT_THRESHOLD_MS))
            .unwrap_or(false)
    }

    /// Snapshot of current TLS lifecycle status.
    #[must_use]
    pub fn status(&self) -> Option<TlsLifecycleStatus> {
        self.status.lock().ok().map(|s| s.clone())
    }

    /// Executes a periodic certificate renewal check (`IpPinned` re-issue preserving key;
    /// `Acme` key-preserving ACME directory order / DNS-01 webhook trigger).
    pub async fn run_renewal_check(&self) -> AppResult<bool> {
        self.run_renewal_check_internal(None, Duration::from_secs(2))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn run_renewal_check_with_http(
        &self,
        http_client: Box<dyn HttpClient>,
        poll_interval: Duration,
    ) -> AppResult<bool> {
        self.run_renewal_check_internal(Some(http_client), poll_interval)
            .await
    }

    async fn run_renewal_check_internal(
        &self,
        http_client: Option<Box<dyn HttpClient>>,
        poll_interval: Duration,
    ) -> AppResult<bool> {
        let now_ms = self.store.clock().now_unix_ms();
        if !self.needs_renewal(now_ms) {
            return Ok(false);
        }

        match self.config.tls_mode {
            TlsMode::IpPinned => {
                let sans = build_san_list(&self.config);
                let updated = self
                    .store
                    .reissue_cert_same_key(&sans, 90, "system:cert_renew")?;
                self.resolver.install_identity(&updated)?;
                if let Ok(mut guard) = self.status.lock() {
                    guard.cert_not_after_ms = updated.not_after_ms;
                    guard.last_renewal_attempt_ms = Some(now_ms);
                    guard.last_renewal_error = None;
                }
                Ok(true)
            }
            TlsMode::Acme => {
                self.attempt_acme_renewal_with_http(now_ms, http_client, poll_interval)
                    .await
            }
            TlsMode::ReverseProxy => Ok(false),
        }
    }

    async fn attempt_acme_renewal_with_http(
        &self,
        now_unix_ms: u64,
        http_client: Option<Box<dyn HttpClient>>,
        poll_interval: Duration,
    ) -> AppResult<bool> {
        const ACME_ORDER_TIMEOUT: Duration = Duration::from_secs(90);

        let result = match tokio::time::timeout(
            ACME_ORDER_TIMEOUT,
            self.execute_acme_order(now_unix_ms, http_client, poll_interval),
        )
        .await
        {
            Ok(inner) => inner,
            Err(_) => Err(AppError::unavailable(
                "ACME certificate issuance timed out after 90s",
            )),
        };

        if let Err(ref err) = result
            && let Ok(mut guard) = self.status.lock()
        {
            guard.last_renewal_attempt_ms = Some(now_unix_ms);
            guard.last_renewal_error = Some(err.to_string());
        }
        result
    }

    async fn execute_acme_order(
        &self,
        now_unix_ms: u64,
        http_client: Option<Box<dyn HttpClient>>,
        poll_interval: Duration,
    ) -> AppResult<bool> {
        ensure_rustls_ring_provider();
        let domain = self
            .config
            .acme
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::invalid_argument("acme mode requires non-empty acme.domain"))?
            .to_owned();
        let directory_url = self
            .config
            .acme
            .directory_url
            .as_deref()
            .unwrap_or(LETS_ENCRYPT_DIRECTORY_URL);

        let csr = self.prepare_key_preserving_csr_for_domains(std::slice::from_ref(&domain))?;
        let account = self
            .load_or_create_acme_account(directory_url, http_client)
            .await?;

        let identifiers = [Identifier::Dns(domain.clone())];
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|err| AppError::unavailable(format!("ACME new_order failed: {err}")))?;

        let authorizations = order
            .authorizations()
            .await
            .map_err(|err| AppError::unavailable(format!("ACME authorizations failed: {err}")))?;

        let mut alpn_guard = AcmeAlpnCleanupGuard::new(&self.resolver);
        for authz in authorizations {
            if self
                .drive_acme_authorization(&mut order, authz, &domain, now_unix_ms)
                .await?
            {
                alpn_guard.mark_armed();
            }
        }

        poll_order_ready(&mut order, poll_interval).await?;
        drop(alpn_guard);

        if order.state().status != OrderStatus::Valid {
            order.finalize(&csr.csr_der).await.map_err(|err| {
                AppError::unavailable(format!("ACME order finalize failed: {err}"))
            })?;
        }

        let cert_pem = poll_order_certificate(&mut order, poll_interval).await?;
        let parsed_certs = load_certs_from_pem(cert_pem.as_bytes())?;
        let chain_der: Vec<Vec<u8>> = parsed_certs
            .into_iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect();
        let leaf_der = chain_der
            .first()
            .ok_or_else(|| AppError::unavailable("ACME returned empty certificate chain"))?;
        let not_after_ms = extract_cert_not_after_ms_from_der(leaf_der)?;

        self.install_ca_issued_cert(chain_der, not_after_ms, "system:acme_renew")?;
        if let Ok(mut guard) = self.status.lock() {
            guard.last_renewal_attempt_ms = Some(now_unix_ms);
            guard.last_renewal_error = None;
            guard.pending_dns_challenge_txt = None;
        }
        Ok(true)
    }

    async fn load_or_create_acme_account(
        &self,
        directory_url: &str,
        http_client: Option<Box<dyn HttpClient>>,
    ) -> AppResult<Account> {
        if let Some(stored) = self.store.load_acme_account()? {
            let creds: AccountCredentials = stored.parse_with(|raw| {
                serde_json::from_str(raw).map_err(|err| {
                    AppError::internal(format!(
                        "failed deserializing persisted ACME account credentials: {err}"
                    ))
                })
            })?;
            let account = match http_client {
                Some(http) => Account::from_credentials_and_http(creds, http).await,
                None => Account::from_credentials(creds).await,
            }
            .map_err(|err| {
                AppError::unavailable(format!("failed restoring ACME account: {err}"))
            })?;
            return Ok(account);
        }

        let contact_uri = self
            .config
            .acme
            .contact_email
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|email| {
                if email.starts_with("mailto:") {
                    email.to_owned()
                } else {
                    format!("mailto:{email}")
                }
            });
        let contact_refs: Vec<&str> = contact_uri.iter().map(String::as_str).collect();
        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, creds) = match http_client {
            Some(http) => Account::create_with_http(&new_account, directory_url, None, http).await,
            None => Account::create(&new_account, directory_url, None).await,
        }
        .map_err(|err| AppError::unavailable(format!("ACME account creation failed: {err}")))?;

        let creds_json = serde_json::to_string(&creds).map_err(|err| {
            AppError::internal(format!(
                "failed serializing ACME account credentials: {err}"
            ))
        })?;
        self.store.save_acme_account_json(&creds_json)?;
        Ok(account)
    }

    async fn drive_acme_authorization(
        &self,
        order: &mut instant_acme::Order,
        authz: instant_acme::Authorization,
        domain: &str,
        now_unix_ms: u64,
    ) -> AppResult<bool> {
        match authz.status {
            AuthorizationStatus::Valid => return Ok(false),
            AuthorizationStatus::Invalid
            | AuthorizationStatus::Revoked
            | AuthorizationStatus::Expired => {
                return Err(AppError::unavailable(format!(
                    "ACME authorization failed with status {:?}",
                    authz.status
                )));
            }
            AuthorizationStatus::Pending => {}
        }

        let target_type = match self.config.acme.challenge {
            AcmeChallengeKind::TlsAlpn01 => ChallengeType::TlsAlpn01,
            AcmeChallengeKind::Dns01 => ChallengeType::Dns01,
        };
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == target_type)
            .ok_or_else(|| {
                AppError::unavailable(format!(
                    "ACME authorization missing {:?} challenge",
                    self.config.acme.challenge
                ))
            })?;

        let mut armed_alpn = false;
        match self.config.acme.challenge {
            AcmeChallengeKind::TlsAlpn01 => {
                let key_auth = order.key_authorization(challenge);
                let digest_arr: [u8; 32] = key_auth.digest().as_ref().try_into().map_err(|_| {
                    AppError::internal("ACME TLS-ALPN-01 key_authorization digest not 32 bytes")
                })?;
                let alpn_cert =
                    generate_tls_alpn_01_challenge_cert(domain, digest_arr, now_unix_ms / 1_000)?;
                self.resolver
                    .set_acme_alpn_challenge(vec![alpn_cert.cert_der], &alpn_cert.key_pkcs8_der)?;
                armed_alpn = true;
            }
            AcmeChallengeKind::Dns01 => {
                let dns_val = order.key_authorization(challenge).dns_value();
                let fqdn = format!("_acme-challenge.{domain}");
                if let Ok(mut guard) = self.status.lock() {
                    guard.pending_dns_challenge_txt = Some((fqdn.clone(), dns_val.clone()));
                }
                if let Some(ref webhook_url) = self.config.acme.dns_webhook_url {
                    dispatch_dns01_webhook(webhook_url, domain, &fqdn, &dns_val).await?;
                } else {
                    tracing::info!(
                        component = "acme",
                        event = "dns01_challenge_txt_ready",
                        fqdn = %fqdn,
                        txt_value = %dns_val,
                        "publish _acme-challenge TXT record for DNS-01 validation"
                    );
                }
            }
        }

        order
            .set_challenge_ready(&challenge.url)
            .await
            .map_err(|err| {
                AppError::unavailable(format!("ACME set_challenge_ready failed: {err}"))
            })?;
        Ok(armed_alpn)
    }
}

struct AcmeAlpnCleanupGuard<'a> {
    resolver: &'a MeshCertResolver,
    armed: bool,
}

impl<'a> AcmeAlpnCleanupGuard<'a> {
    const fn new(resolver: &'a MeshCertResolver) -> Self {
        Self {
            resolver,
            armed: false,
        }
    }

    const fn mark_armed(&mut self) {
        self.armed = true;
    }
}

impl Drop for AcmeAlpnCleanupGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.resolver.clear_acme_alpn_challenge();
        }
    }
}

const MAX_ACME_POLL_ATTEMPTS: usize = 30;

async fn poll_order_ready(
    order: &mut instant_acme::Order,
    poll_interval: Duration,
) -> AppResult<()> {
    let mut attempts = 0_usize;
    loop {
        match order.state().status {
            OrderStatus::Ready | OrderStatus::Valid => return Ok(()),
            OrderStatus::Invalid => {
                let detail = order
                    .state()
                    .error
                    .as_ref()
                    .map_or_else(|| "order rejected by CA".to_owned(), ToString::to_string);
                return Err(AppError::unavailable(format!(
                    "ACME order invalid: {detail}"
                )));
            }
            OrderStatus::Pending | OrderStatus::Processing => {
                attempts = attempts.saturating_add(1);
                if attempts > MAX_ACME_POLL_ATTEMPTS {
                    return Err(AppError::unavailable(
                        "ACME order validation timed out before reaching ready state",
                    ));
                }
                tokio::time::sleep(poll_interval).await;
                order.refresh().await.map_err(|err| {
                    AppError::unavailable(format!("ACME order refresh failed: {err}"))
                })?;
            }
        }
    }
}

async fn poll_order_certificate(
    order: &mut instant_acme::Order,
    poll_interval: Duration,
) -> AppResult<String> {
    for _ in 0..MAX_ACME_POLL_ATTEMPTS {
        match order.certificate().await {
            Ok(Some(pem)) => return Ok(pem),
            Ok(None) => tokio::time::sleep(poll_interval).await,
            Err(err) => {
                return Err(AppError::unavailable(format!(
                    "ACME certificate retrieval failed: {err}"
                )));
            }
        }
    }
    Err(AppError::unavailable(
        "ACME certificate issuance timed out in processing state",
    ))
}

#[derive(Serialize)]
struct Dns01WebhookPayload<'a> {
    domain: &'a str,
    fqdn: &'a str,
    txt_value: &'a str,
}

async fn dispatch_dns01_webhook(
    webhook_url: &str,
    domain: &str,
    fqdn: &str,
    txt_value: &str,
) -> AppResult<()> {
    ensure_rustls_ring_provider();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| {
            AppError::internal(format!(
                "failed constructing DNS-01 webhook HTTP client: {err}"
            ))
        })?;
    let payload = Dns01WebhookPayload {
        domain,
        fqdn,
        txt_value,
    };
    let resp = client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| {
            AppError::unavailable(format!(
                "DNS-01 webhook request failed ({webhook_url}): {err}"
            ))
        })?;
    if !resp.status().is_success() {
        return Err(AppError::unavailable(format!(
            "DNS-01 webhook returned HTTP {}",
            resp.status()
        )));
    }
    Ok(())
}

fn build_san_list(config: &ServerConfig) -> Vec<String> {
    if config.tls_mode == TlsMode::Acme {
        let mut sans = Vec::new();
        if let Some(ref domain) = config.acme.domain {
            sans.push(domain.clone());
        }
        if !sans.contains(&config.public_host) {
            sans.push(config.public_host.clone());
        }
        sans
    } else {
        config.default_tls_sans()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::extract::State;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, head, post};
    use axum::{Json, Router};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use mesh_core::{Clock as _, FakeClock, SystemClock};
    use mesh_store::{ControlStore, ControlStoreConfig};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::{AcmeManager, MeshCertResolver};
    use crate::config::{AcmeChallengeKind, AcmeSettings, ServerConfig, TlsMode};

    #[derive(Clone)]
    struct MockAcmeState {
        base_url: String,
        resolver: Arc<MeshCertResolver>,
        issued_cert_pem: String,
        new_account_calls: Arc<AtomicUsize>,
        order_calls: Arc<AtomicUsize>,
        saw_alpn_armed: Arc<AtomicBool>,
        saw_finalize_csr: Arc<AtomicBool>,
        order_stage: Arc<AtomicU8>,
    }

    async fn mock_directory(State(st): State<MockAcmeState>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "newNonce": format!("{}/new-nonce", st.base_url),
            "newAccount": format!("{}/new-account", st.base_url),
            "newOrder": format!("{}/new-order", st.base_url),
        }))
    }

    async fn mock_new_nonce() -> (StatusCode, HeaderMap) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-head".parse().expect("header value"),
        );
        (StatusCode::OK, headers)
    }

    async fn mock_new_account(
        State(st): State<MockAcmeState>,
    ) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
        st.new_account_calls.fetch_add(1, Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        headers.insert(
            "Location",
            format!("{}/acct/1", st.base_url)
                .parse()
                .expect("location header"),
        );
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-acct".parse().expect("nonce header"),
        );
        (
            StatusCode::CREATED,
            headers,
            Json(serde_json::json!({ "status": "valid" })),
        )
    }

    async fn mock_new_order(
        State(st): State<MockAcmeState>,
    ) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
        st.order_calls.fetch_add(1, Ordering::SeqCst);
        st.order_stage.store(0, Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        headers.insert(
            "Location",
            format!("{}/order/1", st.base_url)
                .parse()
                .expect("location header"),
        );
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-order".parse().expect("nonce header"),
        );
        (
            StatusCode::CREATED,
            headers,
            Json(serde_json::json!({
                "status": "pending",
                "authorizations": [format!("{}/authz/1", st.base_url)],
                "finalize": format!("{}/order/1/finalize", st.base_url),
            })),
        )
    }

    async fn mock_authz(
        State(st): State<MockAcmeState>,
    ) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-authz".parse().expect("nonce header"),
        );
        (
            StatusCode::OK,
            headers,
            Json(serde_json::json!({
                "status": "pending",
                "identifier": { "type": "dns", "value": "vpn.example.com" },
                "challenges": [{
                    "type": "tls-alpn-01",
                    "url": format!("{}/chall/1", st.base_url),
                    "status": "pending",
                    "token": "mock-alpn-token-01"
                }]
            })),
        )
    }

    async fn mock_challenge_ready(
        State(st): State<MockAcmeState>,
    ) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
        if st.resolver.has_acme_alpn_challenge() {
            st.saw_alpn_armed.store(true, Ordering::SeqCst);
        }
        st.order_stage.store(1, Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-chall".parse().expect("nonce header"),
        );
        (
            StatusCode::OK,
            headers,
            Json(serde_json::json!({
                "type": "tls-alpn-01",
                "url": format!("{}/chall/1", st.base_url),
                "status": "valid",
                "token": "mock-alpn-token-01"
            })),
        )
    }

    async fn mock_order_status(
        State(st): State<MockAcmeState>,
    ) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
        let stage = st.order_stage.load(Ordering::SeqCst);
        let body = match stage {
            1 => {
                st.order_stage.store(2, Ordering::SeqCst);
                serde_json::json!({
                    "status": "processing",
                    "authorizations": [format!("{}/authz/1", st.base_url)],
                    "finalize": format!("{}/order/1/finalize", st.base_url),
                })
            }
            2 => serde_json::json!({
                "status": "ready",
                "authorizations": [format!("{}/authz/1", st.base_url)],
                "finalize": format!("{}/order/1/finalize", st.base_url),
            }),
            _ => serde_json::json!({
                "status": "valid",
                "authorizations": [format!("{}/authz/1", st.base_url)],
                "finalize": format!("{}/order/1/finalize", st.base_url),
                "certificate": format!("{}/cert/1", st.base_url),
            }),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-poll".parse().expect("nonce header"),
        );
        (StatusCode::OK, headers, Json(body))
    }

    async fn mock_finalize(
        State(st): State<MockAcmeState>,
        Json(jws): Json<serde_json::Value>,
    ) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
        if let Some(payload_b64) = jws.get("payload").and_then(serde_json::Value::as_str)
            && let Ok(decoded) = URL_SAFE_NO_PAD.decode(payload_b64)
            && let Ok(payload_json) = serde_json::from_slice::<serde_json::Value>(&decoded)
            && payload_json
                .get("csr")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| !s.is_empty())
        {
            st.saw_finalize_csr.store(true, Ordering::SeqCst);
        }
        st.order_stage.store(3, Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-final".parse().expect("nonce header"),
        );
        (
            StatusCode::OK,
            headers,
            Json(serde_json::json!({
                "status": "valid",
                "authorizations": [format!("{}/authz/1", st.base_url)],
                "finalize": format!("{}/order/1/finalize", st.base_url),
                "certificate": format!("{}/cert/1", st.base_url),
            })),
        )
    }

    async fn mock_certificate(State(st): State<MockAcmeState>) -> (StatusCode, HeaderMap, String) {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/pem-certificate-chain"
                .parse()
                .expect("content type"),
        );
        headers.insert(
            "Replay-Nonce",
            "mock-nonce-cert".parse().expect("nonce header"),
        );
        (StatusCode::OK, headers, st.issued_cert_pem.clone())
    }

    fn build_plain_test_http_client() -> Box<dyn instant_acme::HttpClient> {
        let client: hyper_util::client::legacy::Client<
            hyper_util::client::legacy::connect::HttpConnector,
            _,
        > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
        Box::new(client)
    }

    #[tokio::test]
    async fn test_acme_csr_preserves_spki_pin_and_alerts_under_14_days() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/16",
                clock.clone(),
            )
            .expect("open store"),
        );
        let cfg = ServerConfig {
            tls_mode: TlsMode::Acme,
            public_host: "vpn.example.com".to_owned(),
            control_tcp_port: 8443,
            acme: AcmeSettings {
                domain: Some("vpn.example.com".to_owned()),
                contact_email: Some("ops@example.com".to_owned()),
                challenge: AcmeChallengeKind::Dns01,
                directory_url: None,
                dns_webhook_url: None,
            },
            ..ServerConfig::default()
        };
        let mgr = AcmeManager::initialize(&cfg, store.clone()).expect("init acme manager");
        let initial_pin = mgr.status().expect("status").active_pin;

        // Act: CSR reuses stored private key -> identical SPKI pin (`US-047 AC5`)
        let csr = mgr.prepare_key_preserving_csr().expect("csr");
        let tls_cfg = mgr.build_rustls_config().expect("rustls cfg");

        // Assert
        assert_eq!(csr.spki_pin, initial_pin);
        assert!(tls_cfg.alpn_protocols.contains(&b"http/1.1".to_vec()));
        assert!(!mgr.cert_expires_within_14_days(now_ms));
        assert!(mgr.cert_expires_within_14_days(now_ms + 80 * 86_400 * 1_000));

        // Verify reload from store retains identical active SPKI pin
        mgr.reload_from_store().expect("reload from store");
        assert_eq!(mgr.status().expect("status").active_pin, initial_pin);
    }

    #[tokio::test]
    async fn test_acme_full_tls_alpn_01_order_lifecycle_preserves_pin_and_reuses_account() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/16",
                clock.clone(),
            )
            .expect("open store"),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock acme listener");
        let mock_port = listener.local_addr().expect("mock addr").port();
        let base_url = format!("http://127.0.0.1:{mock_port}");

        let cfg = ServerConfig {
            tls_mode: TlsMode::Acme,
            public_host: "vpn.example.com".to_owned(),
            acme: AcmeSettings {
                domain: Some("vpn.example.com".to_owned()),
                contact_email: Some("ops@example.com".to_owned()),
                challenge: AcmeChallengeKind::TlsAlpn01,
                directory_url: Some(format!("{base_url}/directory")),
                dns_webhook_url: None,
            },
            ..ServerConfig::default()
        };
        let mgr = AcmeManager::initialize(&cfg, store.clone()).expect("init acme manager");
        let initial_status = mgr.status().expect("initial status");
        assert!(!initial_status.ca_verified);
        assert!(mgr.needs_renewal(now_ms));

        let active_identity = store.load_active_identity().expect("load active identity");
        let ca_issued = mesh_crypto::reissue_cert_preserving_key(
            &active_identity.private_key_der,
            &["vpn.example.com".to_owned()],
            90,
            now_ms / 1_000,
        )
        .expect("build key-preserving CA cert");
        let expected_not_after_ms =
            mesh_crypto::extract_cert_not_after_ms_from_der(&ca_issued.cert_der)
                .expect("extract expected notAfter");

        let mock_state = MockAcmeState {
            base_url,
            resolver: mgr.resolver(),
            issued_cert_pem: ca_issued.cert_pem,
            new_account_calls: Arc::new(AtomicUsize::new(0)),
            order_calls: Arc::new(AtomicUsize::new(0)),
            saw_alpn_armed: Arc::new(AtomicBool::new(false)),
            saw_finalize_csr: Arc::new(AtomicBool::new(false)),
            order_stage: Arc::new(AtomicU8::new(0)),
        };

        let app = Router::new()
            .route("/directory", get(mock_directory))
            .route("/new-nonce", head(mock_new_nonce))
            .route("/new-account", post(mock_new_account))
            .route("/new-order", post(mock_new_order))
            .route("/authz/1", post(mock_authz))
            .route("/chall/1", post(mock_challenge_ready))
            .route("/order/1", post(mock_order_status))
            .route("/order/1/finalize", post(mock_finalize))
            .route("/cert/1", post(mock_certificate))
            .with_state(mock_state.clone());

        let shutdown = CancellationToken::new();
        let shutdown_srv = shutdown.clone();
        let server_task = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app)
                .with_graceful_shutdown(async move { shutdown_srv.cancelled().await })
                .await
            {
                tracing::debug!(error = %err, "mock ACME server exited");
            }
        });

        // Act 1: First issuance creates ACME account, arms TLS-ALPN-01 cert, finalizes CSR, installs CA cert
        let renewed_first = mgr
            .run_renewal_check_with_http(build_plain_test_http_client(), Duration::from_millis(5))
            .await
            .expect("first ACME order should succeed");

        // Assert 1
        assert!(renewed_first);
        assert_eq!(mock_state.new_account_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock_state.order_calls.load(Ordering::SeqCst), 1);
        assert!(mock_state.saw_alpn_armed.load(Ordering::SeqCst));
        assert!(mock_state.saw_finalize_csr.load(Ordering::SeqCst));
        assert!(!mgr.resolver().has_acme_alpn_challenge());
        assert!(
            store
                .load_acme_account()
                .expect("load acme account")
                .is_some()
        );

        let after_first = mgr.status().expect("status after first ACME issuance");
        assert!(after_first.ca_verified);
        assert_eq!(after_first.active_pin, initial_status.active_pin);
        assert_eq!(after_first.cert_not_after_ms, expected_not_after_ms);
        assert!(after_first.last_renewal_error.is_none());
        assert!(!mgr.needs_renewal(now_ms));

        // Act 2: Advance clock into < 30-day renewal window -> reuses persisted ACME account (no second /new-account)
        clock.advance(65 * 86_400 * 1_000);
        assert!(mgr.needs_renewal(clock.now_unix_ms()));
        let renewed_second = mgr
            .run_renewal_check_with_http(build_plain_test_http_client(), Duration::from_millis(5))
            .await
            .expect("second ACME renewal reusing persisted account should succeed");

        // Assert 2
        assert!(renewed_second);
        assert_eq!(mock_state.new_account_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mock_state.order_calls.load(Ordering::SeqCst), 2);
        assert!(!mgr.resolver().has_acme_alpn_challenge());

        shutdown.cancel();
        assert!(server_task.await.is_ok());
    }

    #[tokio::test]
    async fn test_acme_unreachable_directory_records_error_and_retains_unverified_status() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let clock = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/16",
                clock,
            )
            .expect("open store"),
        );
        let cfg = ServerConfig {
            tls_mode: TlsMode::Acme,
            public_host: "vpn.example.com".to_owned(),
            acme: AcmeSettings {
                domain: Some("vpn.example.com".to_owned()),
                contact_email: Some("ops@example.com".to_owned()),
                challenge: AcmeChallengeKind::TlsAlpn01,
                directory_url: Some("http://127.0.0.1:1/directory".to_owned()),
                dns_webhook_url: None,
            },
            ..ServerConfig::default()
        };
        let mgr = AcmeManager::initialize(&cfg, store).expect("init acme manager");

        // Act
        let renew_err = mgr
            .run_renewal_check_with_http(build_plain_test_http_client(), Duration::from_millis(5))
            .await
            .expect_err("unreachable ACME directory must fail loudly");

        // Assert
        assert!(!renew_err.to_string().is_empty());
        let status = mgr.status().expect("status");
        assert!(!status.ca_verified);
        assert!(status.last_renewal_error.is_some());
        assert!(!mgr.resolver().has_acme_alpn_challenge());
    }
}
