//! Server ECDSA P-256 identity persistence keeping raw private keys wrapped in `Secret<Vec<u8>>`
//! (`SEC-01`, `US-047`, `REL-12`, `WP-S1-01`).

use std::fmt;

use mesh_core::{AppError, AppResult, SpkiPin};
use mesh_crypto::{
    Secret, decode_pkcs8_der_from_keystore, encode_pkcs8_der_for_keystore,
    extract_spki_pin_from_der, generate_ip_pinned_cert, reissue_cert_preserving_key,
};
use mesh_proto::netmap::PinSetDto;
use redb::{Database, WriteTransaction};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::audit_repo::{AuditEventInput, AuditRepository};
use crate::schema::{
    SERVER_IDENTITY_KEY_ACTIVE, TABLE_SERVER_IDENTITY, decode_envelope, encode_envelope,
    map_store_err,
};

const ACME_ACCOUNT_KEY: &str = "acme_account";

/// Zeroized container for serialized ACME account credentials (`SEC-01`, `BLK-S1-03`).
/// Decodes via [`Self::parse_with`] so `mesh-server` never accesses raw secret bytes directly.
pub struct AcmeAccountCredentialsBox(Zeroizing<String>);

impl AcmeAccountCredentialsBox {
    /// Parses stored ACME credentials JSON without exposing secret text in logs or errors.
    pub fn parse_with<T>(&self, decoder: impl FnOnce(&str) -> AppResult<T>) -> AppResult<T> {
        decoder(self.0.as_str())
    }
}

impl fmt::Debug for AcmeAccountCredentialsBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcmeAccountCredentialsBox([REDACTED])")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAcmeAccountDto {
    credentials_json: String,
    updated_at_ms: u64,
}

impl Drop for StoredAcmeAccountDto {
    fn drop(&mut self) {
        self.credentials_json.zeroize();
    }
}

/// Staged replacement identity awaiting promotion after online clients receive the dual pin set.
#[derive(Debug)]
pub struct StagedServerIdentity {
    /// SPKI SHA-256 pin of the staged replacement key.
    pub spki_pin: SpkiPin,
    /// Replacement ECDSA P-256 PKCS#8 private key DER inside [`Secret`].
    pub private_key_der: Secret<Vec<u8>>,
    /// Replacement X.509 DER certificate chain.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Certificate `NotAfter` UTC timestamp in milliseconds.
    pub not_after_ms: u64,
}

impl StagedServerIdentity {
    /// Clones this staged identity preserving secret protection via `.clone_secret()`.
    #[must_use]
    pub fn clone_identity(&self) -> Self {
        Self {
            spki_pin: self.spki_pin,
            private_key_der: self.private_key_der.clone_secret(),
            cert_chain_der: self.cert_chain_der.clone(),
            not_after_ms: self.not_after_ms,
        }
    }
}

/// Loaded server identity holding DER-encoded key material inside [`Secret`].
#[derive(Debug)]
pub struct ServerIdentity {
    /// Active SPKI SHA-256 pin derived from the signing public key.
    pub spki_pin: SpkiPin,
    /// DER private key bytes automatically zeroized on drop.
    pub private_key_der: Secret<Vec<u8>>,
    /// DER X.509 certificate chain.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// True once a public CA-issued chain (ACME) has replaced the self-signed bootstrap cert.
    pub ca_verified: bool,
    /// Previous SPKI pin retained inside grace window immediately after planned rotation.
    pub previous_spki_pin: Option<SpkiPin>,
    /// Optional grace window deadline (`unix_ms`) for `previous_spki_pin`.
    pub pin_grace_until_ms: Option<u64>,
    /// Optional pre-generated replacement keypair announced ahead of planned rotation (`US-047 AC5`).
    pub staged_next: Option<StagedServerIdentity>,
    /// Certificate `NotAfter` UTC timestamp in milliseconds.
    pub not_after_ms: u64,
    /// UTC epoch milliseconds when the active identity was first created.
    pub created_at_ms: u64,
    /// UTC epoch milliseconds of the latest rotation or re-issuance.
    pub updated_at_ms: u64,
}

impl ServerIdentity {
    /// Clones this identity safely preserving [`Secret`] wrappers.
    #[must_use]
    pub fn clone_identity(&self) -> Self {
        Self {
            spki_pin: self.spki_pin,
            private_key_der: self.private_key_der.clone_secret(),
            cert_chain_der: self.cert_chain_der.clone(),
            ca_verified: self.ca_verified,
            previous_spki_pin: self.previous_spki_pin,
            pin_grace_until_ms: self.pin_grace_until_ms,
            staged_next: self
                .staged_next
                .as_ref()
                .map(StagedServerIdentity::clone_identity),
            not_after_ms: self.not_after_ms,
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
        }
    }

    /// Projects the currently valid pin set for Netmap distribution (`US-047 AC5`, `US-074`).
    #[must_use]
    pub fn to_pin_set_dto(&self, now_unix_ms: u64) -> PinSetDto {
        let next_pin = if let Some(ref staged) = self.staged_next {
            Some(staged.spki_pin)
        } else if let (Some(prev), Some(until)) = (self.previous_spki_pin, self.pin_grace_until_ms)
            && now_unix_ms <= until
            && prev != self.spki_pin
        {
            Some(prev)
        } else {
            None
        };
        PinSetDto {
            active_pin: self.spki_pin,
            next_pin,
        }
    }
}

/// Private persistence DTO serialized inside `redb`; intentionally omits `Debug` and `Clone`
/// so secret key base64 material cannot be copied or logged accidentally (`SEC-01`).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredServerIdentityDto {
    active_spki_pin: String,
    private_key_pkcs8_b64: String,
    cert_chain_der: Vec<Vec<u8>>,
    #[serde(default)]
    ca_verified: bool,
    previous_spki_pin: Option<String>,
    pin_grace_until_ms: Option<u64>,
    staged_spki_pin: Option<String>,
    staged_private_key_pkcs8_b64: Option<String>,
    staged_cert_chain_der: Option<Vec<Vec<u8>>>,
    staged_not_after_ms: Option<u64>,
    not_after_ms: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
}

impl Drop for StoredServerIdentityDto {
    fn drop(&mut self) {
        self.private_key_pkcs8_b64.zeroize();
        if let Some(ref mut staged_b64) = self.staged_private_key_pkcs8_b64 {
            staged_b64.zeroize();
        }
    }
}

impl StoredServerIdentityDto {
    fn from_domain(identity: &ServerIdentity) -> Self {
        let active_b64 = encode_pkcs8_der_for_keystore(&identity.private_key_der);
        let staged_b64 = identity
            .staged_next
            .as_ref()
            .map(|s| encode_pkcs8_der_for_keystore(&s.private_key_der));

        Self {
            active_spki_pin: identity.spki_pin.to_string(),
            private_key_pkcs8_b64: (*active_b64).clone(),
            cert_chain_der: identity.cert_chain_der.clone(),
            ca_verified: identity.ca_verified,
            previous_spki_pin: identity.previous_spki_pin.map(|p| p.to_string()),
            pin_grace_until_ms: identity.pin_grace_until_ms,
            staged_spki_pin: identity
                .staged_next
                .as_ref()
                .map(|s| s.spki_pin.to_string()),
            staged_private_key_pkcs8_b64: staged_b64.map(|z| (*z).clone()),
            staged_cert_chain_der: identity
                .staged_next
                .as_ref()
                .map(|s| s.cert_chain_der.clone()),
            staged_not_after_ms: identity.staged_next.as_ref().map(|s| s.not_after_ms),
            not_after_ms: identity.not_after_ms,
            created_at_ms: identity.created_at_ms,
            updated_at_ms: identity.updated_at_ms,
        }
    }

    fn into_domain(mut self) -> AppResult<ServerIdentity> {
        let parsed_pin = SpkiPin::parse(&self.active_spki_pin)?;
        let private_key_der = decode_pkcs8_der_from_keystore(&self.private_key_pkcs8_b64)?;
        self.private_key_pkcs8_b64.zeroize();

        let leaf_der = self.cert_chain_der.first().ok_or_else(|| {
            AppError::internal("stored server identity has empty certificate chain")
        })?;
        let derived_pin = extract_spki_pin_from_der(leaf_der)?;
        if derived_pin != parsed_pin {
            return Err(AppError::internal(
                "stored server identity active_spki_pin mismatches certificate leaf SPKI",
            ));
        }

        let previous_spki_pin = self
            .previous_spki_pin
            .as_deref()
            .map(SpkiPin::parse)
            .transpose()?;

        let staged_next = decode_staged_identity(&mut self)?;

        Ok(ServerIdentity {
            spki_pin: parsed_pin,
            private_key_der,
            cert_chain_der: self.cert_chain_der.clone(),
            ca_verified: self.ca_verified,
            previous_spki_pin,
            pin_grace_until_ms: self.pin_grace_until_ms,
            staged_next,
            not_after_ms: self.not_after_ms,
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
        })
    }
}

fn decode_staged_identity(
    dto: &mut StoredServerIdentityDto,
) -> AppResult<Option<StagedServerIdentity>> {
    let Some(ref pin_str) = dto.staged_spki_pin else {
        return Ok(None);
    };
    let spki_pin = SpkiPin::parse(pin_str)?;
    let b64 = dto
        .staged_private_key_pkcs8_b64
        .as_deref()
        .ok_or_else(|| AppError::internal("staged server identity missing private key"))?;
    let private_key_der = decode_pkcs8_der_from_keystore(b64)?;
    if let Some(ref mut raw_b64) = dto.staged_private_key_pkcs8_b64 {
        raw_b64.zeroize();
    }
    let cert_chain_der = dto
        .staged_cert_chain_der
        .clone()
        .ok_or_else(|| AppError::internal("staged server identity missing certificate chain"))?;
    let leaf = cert_chain_der
        .first()
        .ok_or_else(|| AppError::internal("staged server identity has empty certificate chain"))?;
    if extract_spki_pin_from_der(leaf)? != spki_pin {
        return Err(AppError::internal(
            "staged server identity pin mismatches staged leaf certificate SPKI",
        ));
    }
    let not_after_ms = dto
        .staged_not_after_ms
        .ok_or_else(|| AppError::internal("staged server identity missing expiry timestamp"))?;
    Ok(Some(StagedServerIdentity {
        spki_pin,
        private_key_der,
        cert_chain_der,
        not_after_ms,
    }))
}

/// Repository managing the server's durable TLS / SPKI identity (`US-047`, `US-045`).
#[derive(Debug, Default)]
pub struct IdentityRepository;

impl IdentityRepository {
    /// Loads the active server identity if already provisioned in `redb`.
    pub fn load_active_opt(db: &Database) -> AppResult<Option<ServerIdentity>> {
        let tx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read server_identity", e))?;
        let table = tx
            .open_table(TABLE_SERVER_IDENTITY)
            .map_err(|e| map_store_err("open read server_identity", e))?;
        let Some(guard) = table
            .get(SERVER_IDENTITY_KEY_ACTIVE)
            .map_err(|e| map_store_err("get server_identity active", e))?
        else {
            return Ok(None);
        };
        let dto: StoredServerIdentityDto = decode_envelope(guard.value())?;
        Ok(Some(dto.into_domain()?))
    }

    /// Loads the active server identity or fails with `ErrorKind::NotFound` if unprovisioned.
    pub fn load_active(db: &Database) -> AppResult<ServerIdentity> {
        Self::load_active_opt(db)?
            .ok_or_else(|| AppError::not_found("active server TLS identity not initialized"))
    }

    /// Saves `identity` inside an existing write transaction.
    pub fn save_identity_in_tx(tx: &WriteTransaction, identity: &ServerIdentity) -> AppResult<()> {
        let dto = StoredServerIdentityDto::from_domain(identity);
        let encoded = encode_envelope(&dto)?;
        drop(dto);
        let mut table = tx
            .open_table(TABLE_SERVER_IDENTITY)
            .map_err(|e| map_store_err("open write server_identity", e))?;
        table
            .insert(SERVER_IDENTITY_KEY_ACTIVE, encoded.as_slice())
            .map_err(|e| map_store_err("insert active server_identity", e))?;
        Ok(())
    }

    /// Idempotently loads or generates the initial IP-pinned ECDSA P-256 identity (`US-047 AC3`,
    /// `US-051 AC5`: re-running install keeps the exact same identity & SPKI pin).
    pub fn ensure_or_init_identity(
        db: &Database,
        san_ips_and_hosts: &[String],
        valid_days: u32,
        now_unix_ms: u64,
    ) -> AppResult<ServerIdentity> {
        if let Some(existing) = Self::load_active_opt(db)? {
            return Ok(existing);
        }

        let now_secs = now_unix_ms / 1_000;
        let effective_days = valid_days.max(1);
        let generated = generate_ip_pinned_cert(san_ips_and_hosts, effective_days, now_secs)?;
        let not_after_ms =
            now_unix_ms.saturating_add(u64::from(effective_days).saturating_mul(86_400_000));
        let identity = ServerIdentity {
            spki_pin: generated.spki_pin,
            private_key_der: generated.key_pkcs8_der,
            cert_chain_der: vec![generated.cert_der],
            ca_verified: false,
            previous_spki_pin: None,
            pin_grace_until_ms: None,
            staged_next: None,
            not_after_ms,
            created_at_ms: now_unix_ms,
            updated_at_ms: now_unix_ms,
        };

        let tx = db
            .begin_write()
            .map_err(|e| map_store_err("begin write ensure_identity", e))?;
        Self::save_identity_in_tx(&tx, &identity)?;
        let audit_input = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor: "system",
            action: "server_identity_initialized",
            target: "server",
            outcome: "success",
            metadata: serde_json::json!({ "active_pin": identity.spki_pin.to_string() }),
        };
        AuditRepository::append_audit_in_tx(&tx, &audit_input)?;
        tx.commit()
            .map_err(|e| map_store_err("commit ensure_identity", e))?;

        Ok(identity)
    }

    /// Re-issues the serving certificate while preserving the exact same keypair and SPKI pin
    /// (`US-047 AC3`: connected agents stay pinned with zero manual steps).
    pub fn reissue_cert_same_key(
        db: &Database,
        san_ips_and_hosts: &[String],
        valid_days: u32,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<ServerIdentity> {
        let mut current = Self::load_active(db)?;
        let effective_days = valid_days.max(1);
        let reissued = reissue_cert_preserving_key(
            &current.private_key_der,
            san_ips_and_hosts,
            effective_days,
            now_unix_ms / 1_000,
        )?;
        current.cert_chain_der = vec![reissued.cert_der];
        current.ca_verified = false;
        current.not_after_ms =
            now_unix_ms.saturating_add(u64::from(effective_days).saturating_mul(86_400_000));
        current.updated_at_ms = now_unix_ms;

        let tx = db
            .begin_write()
            .map_err(|e| map_store_err("begin write reissue_cert", e))?;
        Self::save_identity_in_tx(&tx, &current)?;
        let audit_input = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "server_cert_reissued",
            target: "server",
            outcome: "success",
            metadata: serde_json::json!({
                "spki_pin": current.spki_pin.to_string(),
                "not_after_ms": current.not_after_ms,
            }),
        };
        AuditRepository::append_audit_in_tx(&tx, &audit_input)?;
        tx.commit()
            .map_err(|e| map_store_err("commit reissue_cert", e))?;
        Ok(current)
    }

    /// Stages a new keypair & certificate alongside the active identity (`US-047 AC5` Step 1)
    /// so connected clients receive `[active_pin, staged_pin]` over `/v1/netmap/stream`.
    pub fn stage_next_identity(
        db: &Database,
        san_ips_and_hosts: &[String],
        valid_days: u32,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<ServerIdentity> {
        let mut current = Self::load_active(db)?;
        let effective_days = valid_days.max(1);
        let generated =
            generate_ip_pinned_cert(san_ips_and_hosts, effective_days, now_unix_ms / 1_000)?;
        let next_not_after_ms =
            now_unix_ms.saturating_add(u64::from(effective_days).saturating_mul(86_400_000));
        let next_pin_str = generated.spki_pin.to_string();
        current.staged_next = Some(StagedServerIdentity {
            spki_pin: generated.spki_pin,
            private_key_der: generated.key_pkcs8_der,
            cert_chain_der: vec![generated.cert_der],
            not_after_ms: next_not_after_ms,
        });
        current.updated_at_ms = now_unix_ms;

        let tx = db
            .begin_write()
            .map_err(|e| map_store_err("begin write stage_next_identity", e))?;
        Self::save_identity_in_tx(&tx, &current)?;
        let audit_input = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "server_key_staged",
            target: "server",
            outcome: "success",
            metadata: serde_json::json!({
                "active_pin": current.spki_pin.to_string(),
                "staged_pin": next_pin_str,
            }),
        };
        AuditRepository::append_audit_in_tx(&tx, &audit_input)?;
        tx.commit()
            .map_err(|e| map_store_err("commit stage_next_identity", e))?;
        Ok(current)
    }

    /// Promotes the staged replacement identity to active while preserving `previous_spki_pin`
    /// for the specified grace duration (`US-047 AC5` Step 2).
    pub fn activate_staged_identity(
        db: &Database,
        grace_window_ms: u64,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<ServerIdentity> {
        let mut current = Self::load_active(db)?;
        let staged = current
            .staged_next
            .take()
            .ok_or_else(|| AppError::conflict("no staged replacement server identity to commit"))?;
        let old_pin = current.spki_pin;
        current.previous_spki_pin = Some(old_pin);
        current.pin_grace_until_ms = Some(now_unix_ms.saturating_add(grace_window_ms));
        current.spki_pin = staged.spki_pin;
        current.private_key_der = staged.private_key_der;
        current.cert_chain_der = staged.cert_chain_der;
        current.ca_verified = false;
        current.not_after_ms = staged.not_after_ms;
        current.updated_at_ms = now_unix_ms;

        let tx = db
            .begin_write()
            .map_err(|e| map_store_err("begin write activate_staged_identity", e))?;
        Self::save_identity_in_tx(&tx, &current)?;
        let audit_input = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "server_key_rotated",
            target: "server",
            outcome: "success",
            metadata: serde_json::json!({
                "old_pin": old_pin.to_string(),
                "new_pin": current.spki_pin.to_string(),
                "grace_until_ms": current.pin_grace_until_ms,
            }),
        };
        AuditRepository::append_audit_in_tx(&tx, &audit_input)?;
        tx.commit()
            .map_err(|e| map_store_err("commit activate_staged_identity", e))?;
        Ok(current)
    }

    /// Installs an ACME public CA-issued DER certificate chain verifying that the leaf SPKI
    /// preserves the server's active `spki_pin` (`BLK-S1-03`, `US-047`).
    pub fn save_ca_issued_cert(
        db: &Database,
        cert_chain_der: Vec<Vec<u8>>,
        not_after_ms: u64,
        now_unix_ms: u64,
        actor: &str,
    ) -> AppResult<ServerIdentity> {
        let leaf = cert_chain_der.first().ok_or_else(|| {
            AppError::invalid_argument("CA-issued certificate chain must not be empty")
        })?;
        let mut current = Self::load_active(db)?;
        let leaf_pin = extract_spki_pin_from_der(leaf)?;
        if leaf_pin != current.spki_pin {
            return Err(AppError::conflict(format!(
                "CA certificate leaf pin {leaf_pin} mismatches active pin {}",
                current.spki_pin
            )));
        }
        current.cert_chain_der = cert_chain_der;
        current.ca_verified = true;
        current.not_after_ms = not_after_ms;
        current.updated_at_ms = now_unix_ms;

        let tx = db
            .begin_write()
            .map_err(|e| map_store_err("begin write save_ca_issued_cert", e))?;
        Self::save_identity_in_tx(&tx, &current)?;
        let audit_input = AuditEventInput {
            occurred_at_ms: now_unix_ms,
            actor,
            action: "server_acme_cert_installed",
            target: "server",
            outcome: "success",
            metadata: serde_json::json!({
                "spki_pin": current.spki_pin.to_string(),
                "not_after_ms": current.not_after_ms,
                "chain_len": current.cert_chain_der.len(),
            }),
        };
        AuditRepository::append_audit_in_tx(&tx, &audit_input)?;
        tx.commit()
            .map_err(|e| map_store_err("commit save_ca_issued_cert", e))?;
        Ok(current)
    }

    /// Persists serialized ACME account credentials durably in `redb` (`BLK-S1-03`).
    pub fn save_acme_account_json(
        db: &Database,
        credentials_json: &str,
        now_unix_ms: u64,
    ) -> AppResult<()> {
        let dto = StoredAcmeAccountDto {
            credentials_json: credentials_json.to_owned(),
            updated_at_ms: now_unix_ms,
        };
        let encoded = encode_envelope(&dto)?;
        drop(dto);
        let tx = db
            .begin_write()
            .map_err(|e| map_store_err("begin write save_acme_account", e))?;
        {
            let mut table = tx
                .open_table(TABLE_SERVER_IDENTITY)
                .map_err(|e| map_store_err("open write acme_account", e))?;
            table
                .insert(ACME_ACCOUNT_KEY, encoded.as_slice())
                .map_err(|e| map_store_err("insert acme_account", e))?;
        }
        tx.commit()
            .map_err(|e| map_store_err("commit save_acme_account", e))?;
        Ok(())
    }

    /// Loads stored ACME account credentials wrapped in a zeroized container (`BLK-S1-03`).
    pub fn load_acme_account(db: &Database) -> AppResult<Option<AcmeAccountCredentialsBox>> {
        let rtx = db
            .begin_read()
            .map_err(|e| map_store_err("begin read load_acme_account", e))?;
        let table = rtx
            .open_table(TABLE_SERVER_IDENTITY)
            .map_err(|e| map_store_err("open read acme_account", e))?;
        let Some(guard) = table
            .get(ACME_ACCOUNT_KEY)
            .map_err(|e| map_store_err("get acme_account", e))?
        else {
            return Ok(None);
        };
        let dto: StoredAcmeAccountDto = decode_envelope(guard.value())?;
        let boxed = AcmeAccountCredentialsBox(Zeroizing::new(dto.credentials_json.clone()));
        drop(dto);
        Ok(Some(boxed))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::schema::ensure_all_tables;

    fn open_test_db() -> Option<(TempDir, Database)> {
        let dir = TempDir::new().ok()?;
        let db = Database::create(dir.path().join("id.redb")).ok()?;
        let tx = db.begin_write().ok()?;
        ensure_all_tables(&tx).ok()?;
        tx.commit().ok()?;
        Some((dir, db))
    }

    #[test]
    fn test_identity_init_is_idempotent_and_reissue_preserves_spki_pin() {
        // Arrange
        let Some((_dir, db)) = open_test_db() else {
            return;
        };
        let sans = vec!["127.0.0.1".to_owned(), "mesh.internal".to_owned()];
        let now_ms = 1_731_480_000_000;

        // Act
        let first = IdentityRepository::ensure_or_init_identity(&db, &sans, 365, now_ms);
        let second = IdentityRepository::ensure_or_init_identity(&db, &sans, 365, now_ms + 5_000);
        let reissued = IdentityRepository::reissue_cert_same_key(
            &db,
            &sans,
            365,
            now_ms + 10_000,
            "admin:uid=0",
        );

        // Assert
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert!(reissued.is_ok());
        if let (Ok(f), Ok(s), Ok(r)) = (first, second, reissued) {
            assert_eq!(f.spki_pin, s.spki_pin);
            assert_eq!(f.spki_pin, r.spki_pin);
            assert!(format!("{f:?}").contains("[REDACTED]"));
        }
    }

    #[test]
    fn test_identity_staged_rotation_exposes_dual_pins_then_activates_new_pin() {
        // Arrange
        let Some((_dir, db)) = open_test_db() else {
            return;
        };
        let sans = vec!["127.0.0.1".to_owned()];
        let now_ms = 1_731_480_000_000;
        let Ok(initial) = IdentityRepository::ensure_or_init_identity(&db, &sans, 365, now_ms)
        else {
            return;
        };

        // Act
        let Ok(staged) =
            IdentityRepository::stage_next_identity(&db, &sans, 365, now_ms + 1_000, "admin:uid=0")
        else {
            return;
        };
        let staged_dto = staged.to_pin_set_dto(now_ms + 1_000);
        let Ok(activated) = IdentityRepository::activate_staged_identity(
            &db,
            86_400_000,
            now_ms + 2_000,
            "admin:uid=0",
        ) else {
            return;
        };
        let post_dto = activated.to_pin_set_dto(now_ms + 5_000);

        // Assert
        assert_eq!(staged_dto.active_pin, initial.spki_pin);
        assert!(staged_dto.next_pin.is_some());
        assert_ne!(activated.spki_pin, initial.spki_pin);
        assert_eq!(post_dto.active_pin, activated.spki_pin);
        assert_eq!(post_dto.next_pin, Some(initial.spki_pin));
    }

    #[test]
    fn test_acme_account_persistence_and_ca_verified_cert_install() {
        // Arrange
        let Some((_dir, db)) = open_test_db() else {
            return;
        };
        let sans = vec!["127.0.0.1".to_owned(), "vpn.example.com".to_owned()];
        let now_ms = 1_731_480_000_000;
        let Ok(initial) = IdentityRepository::ensure_or_init_identity(&db, &sans, 90, now_ms)
        else {
            return;
        };
        assert!(!initial.ca_verified);

        // Act: store ACME account credentials without exposing raw secret in Debug
        let fake_creds = r#"{"id":"https://acme.example/acct/1","key_pkcs8":"secret-test"}"#;
        assert!(IdentityRepository::save_acme_account_json(&db, fake_creds, now_ms).is_ok());
        let loaded_box = IdentityRepository::load_acme_account(&db)
            .expect("load acme account")
            .expect("acme account present");
        assert!(!format!("{loaded_box:?}").contains("secret-test"));
        assert!(
            loaded_box
                .parse_with(|s| Ok(s.contains("acct/1")))
                .unwrap_or(false)
        );

        // Same-key CA cert installation marks ca_verified = true and preserves SPKI pin
        let reissued =
            reissue_cert_preserving_key(&initial.private_key_der, &sans, 90, now_ms / 1_000)
                .expect("reissue cert");
        let installed = IdentityRepository::save_ca_issued_cert(
            &db,
            vec![reissued.cert_der],
            now_ms + 90 * 86_400_000,
            now_ms + 1_000,
            "system:acme",
        )
        .expect("install ca cert");

        // Assert
        assert!(installed.ca_verified);
        assert_eq!(installed.spki_pin, initial.spki_pin);
        let reloaded = IdentityRepository::load_active(&db).expect("reload identity");
        assert!(reloaded.ca_verified);
    }
}
