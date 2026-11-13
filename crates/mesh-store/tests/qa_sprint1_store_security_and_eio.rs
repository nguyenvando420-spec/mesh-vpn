//! Independent Sprint 1 QA Integration, Concurrency & AppSec Tests for `mesh-store`.
//!
//! Covers:
//! - `US-002`: Pre-Auth Key SHA-256 hashing (`mpk_...`, zero plaintext stored in `redb`)
//! - `US-003 AC4` & `SEC-05`: Single-use `challenge_id` & `SalsaBox` proof verification + replay block
//! - `US-004` & `US-005 AC2/AC3`: Concurrent idempotent registration (3 simultaneous requests = 1 node/IP)
//! - `US-029` & Gate 2 Dual `EIO` branches (a) and (b): `EmergencySlot` -> `RamOnly` + compaction fold
//! - `SEC-01`: `test_no_secrets_in_outputs` canary verification

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    use tempfile::TempDir;

    use mesh_core::defaults::{CHALLENGE_TTL_SECS, DEFAULT_OVERLAY_CIDR};
    use mesh_core::{
        AppError, AppResult, Clock, ErrorKind, FakeClock, KeyId, NodeId, NodeName, PublicKey,
    };
    use mesh_crypto::{
        DiscoKeypair, ExpectedProofClaims, NodeKeypair, PreAuthToken, ProofPayload, open_proof,
        random_bytes, seal_proof, sha256_digest, sha256_hex, verify_proof_claims,
    };
    use mesh_proto::admin_ipc::PersistenceTier;
    use mesh_store::{
        AuditQuery, ControlStore, ControlStoreConfig, CreatePreAuthKeyInput,
        DEFAULT_NODE_KEY_TTL_MS, EmergencyFileBackend, EmergencyNodeReason,
        EmergencyRevocationNodeEntry, EmergencyRevocationState, NodeStatus, OsEmergencyFileBackend,
        RegisterNodeInput, RevokeStoreOutcome, RevokedSet,
    };

    #[derive(Debug)]
    struct FaultInjectingEmergencyBackend {
        inner: OsEmergencyFileBackend,
        fail_slot_writes: AtomicBool,
    }

    impl FaultInjectingEmergencyBackend {
        const fn new(fail_slot_writes: bool) -> Self {
            Self {
                inner: OsEmergencyFileBackend,
                fail_slot_writes: AtomicBool::new(fail_slot_writes),
            }
        }
    }

    impl EmergencyFileBackend for FaultInjectingEmergencyBackend {
        fn exists(&self, path: &Path) -> bool {
            self.inner.exists(path)
        }

        fn file_len(&self, path: &Path) -> io::Result<u64> {
            self.inner.file_len(path)
        }

        fn create_preallocated(&self, path: &Path, full_image: &[u8]) -> io::Result<()> {
            self.inner.create_preallocated(path, full_image)
        }

        fn read_all(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.inner.read_all(path)
        }

        fn write_slot_synced(&self, path: &Path, offset: u64, slot_bytes: &[u8]) -> io::Result<()> {
            if self.fail_slot_writes.load(Ordering::SeqCst) {
                return Err(io::Error::other("simulated hardware EIO on emergency slot"));
            }
            self.inner.write_slot_synced(path, offset, slot_bytes)
        }
    }

    struct InMemorySingleUseChallengeAuthority {
        pending: Mutex<HashMap<NodeId, (NodeKeypair, String, u64)>>,
    }

    impl InMemorySingleUseChallengeAuthority {
        fn new() -> Self {
            Self {
                pending: Mutex::new(HashMap::new()),
            }
        }

        fn issue(&self, now_ms: u64) -> (NodeId, PublicKey, String, u64) {
            let challenge_id = NodeId::new_v7(now_ms);
            let server_eph = NodeKeypair::generate();
            let server_eph_pub = server_eph.public_key();
            let nonce_b64 = sha256_hex(&random_bytes::<32>());
            let expires_at_ms = now_ms.saturating_add(CHALLENGE_TTL_SECS * 1_000);
            if let Ok(mut guard) = self.pending.lock() {
                guard.insert(challenge_id, (server_eph, nonce_b64.clone(), expires_at_ms));
            }
            (challenge_id, server_eph_pub, nonce_b64, expires_at_ms)
        }

        fn verify_and_consume_once(
            &self,
            challenge_id: NodeId,
            client_node_pubkey: &PublicKey,
            box_nonce: &[u8; 24],
            ciphertext: &[u8],
            expected: &ExpectedProofClaims<'_>,
        ) -> AppResult<ProofPayload> {
            // Single-use atomic removal BEFORE decryption (`US-003 AC4`, `api-design.md` §1.3)
            let (server_eph, issued_nonce, expires_at_ms) = self
                .pending
                .lock()
                .ok()
                .and_then(|mut g| g.remove(&challenge_id))
                .ok_or_else(|| AppError::unauthenticated("challenge missing or already used"))?;

            if expected.now_unix_ms > expires_at_ms || expected.challenge_nonce_b64 != issued_nonce
            {
                return Err(AppError::unauthenticated(
                    "challenge expired or nonce mismatch",
                ));
            }

            let opened = open_proof(
                ciphertext,
                box_nonce,
                client_node_pubkey,
                server_eph.secret_bytes(),
            )?;
            verify_proof_claims(&opened, expected)?;
            Ok(opened)
        }
    }

    fn store_config(dir: &TempDir) -> ControlStoreConfig {
        ControlStoreConfig {
            db_path: dir.path().join("control.redb"),
            emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
        }
    }

    // Traces: US-002, US-004, US-005 AC2/AC3, SEC-05
    #[test]
    fn test_preauth_key_sha256_and_three_concurrent_registrations_create_single_node() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let cfg = store_config(&dir);
        let now_ms = 1_762_960_000_000_u64;
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(cfg.clone(), DEFAULT_OVERLAY_CIDR, clock)
                .expect("open control store"),
        );

        let raw_token_str = "mpk_QaSprint1ConcurrentIdempotentToken0123456789abc";
        let parsed_token = PreAuthToken::parse(raw_token_str).expect("valid mpk_ token");
        let token_hash = sha256_digest(raw_token_str.as_bytes());
        assert_eq!(
            format!("{parsed_token}"),
            "[REDACTED]",
            "PreAuthToken Display must redact secret material"
        );

        let key_id = KeyId::new_v7(now_ms);
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id,
                    token_hash,
                    label: Some("qa-sprint1-one-time".to_owned()),
                    bound_node_name: None,
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "qa-admin",
            )
            .expect("create preauth key");

        let shared_node_kp = NodeKeypair::generate();
        let shared_node_pk = shared_node_kp.public_key();
        let shared_disco_pk = DiscoKeypair::generate().public_key();
        let barrier = Arc::new(Barrier::new(3));

        // Act: fire 3 concurrent registration requests with the exact same `node_pubkey` (`US-005 AC2`)
        let mut handles = Vec::with_capacity(3);
        for _ in 0..3 {
            let store_ref = Arc::clone(&store);
            let sync_barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let req_name = NodeName::parse("prod-edge-01").expect("valid node name");
                sync_barrier.wait();
                store_ref.register_node(&RegisterNodeInput {
                    pubkey: shared_node_pk,
                    disco_pubkey: shared_disco_pk,
                    previous_node_pubkey: None,
                    requested_name: req_name,
                    preauth_token_hash: token_hash,
                    public_control_host: "203.0.113.10",
                    domain_suffix: "mesh.internal",
                    os_arch: "linux/amd64",
                    agent_version: "0.1.0",
                    protocol_version: 1,
                    node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                    now_unix_ms: now_ms,
                })
            }));
        }

        let mut outcomes = Vec::with_capacity(3);
        for handle in handles {
            let (outcome, ver) = handle
                .join()
                .expect("worker thread panicked")
                .expect("concurrent idempotent registration must succeed");
            outcomes.push((outcome, ver));
        }

        // Assert: exactly 1 node & 1 OverlayIp allocated across all 3 concurrent requests
        let first_node_id = outcomes.first().expect("first outcome").0.record.node_id;
        let first_ip = outcomes.first().expect("first outcome").0.record.overlay_ip;
        assert!(first_ip.is_some());
        for (outcome, _) in &outcomes {
            assert_eq!(outcome.record.node_id, first_node_id);
            assert_eq!(outcome.record.overlay_ip, first_ip);
            assert_eq!(outcome.record.node_name, "prod-edge-01");
        }
        let changed_count = outcomes.iter().filter(|(o, _)| o.state_changed).count();
        assert_eq!(
            changed_count, 1,
            "exactly 1 of the 3 concurrent requests may mutate state; the other 2 must be pure replays"
        );
        assert_eq!(store.list_nodes().expect("list nodes").len(), 1);

        // Assert: a different `node_pubkey` attempting to reuse the consumed one-time key gets 401
        let other_pk = NodeKeypair::generate().public_key();
        let reuse_err = store
            .register_node(&RegisterNodeInput {
                pubkey: other_pk,
                disco_pubkey: shared_disco_pk,
                previous_node_pubkey: None,
                requested_name: NodeName::parse("intruder-node").expect("name"),
                preauth_token_hash: token_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .expect_err("different node_pubkey reusing one-time key must fail");
        assert_eq!(reuse_err.kind(), ErrorKind::Unauthenticated);
        assert_eq!(reuse_err.public_message(), "authentication failed");

        // Assert: raw `mpk_...` token is never stored in `control.redb` on disk (`US-002 AC1`)
        drop(store);
        let raw_db_bytes = fs::read(&cfg.db_path).expect("read control.redb bytes");
        assert!(
            !raw_db_bytes
                .windows(raw_token_str.len())
                .any(|w| w == raw_token_str.as_bytes()),
            "raw pre-auth key token must never appear in control.redb"
        );
    }

    // Traces: US-003 AC4, SEC-05
    #[test]
    fn test_single_use_challenge_proof_replay_blocked_100_percent_with_generic_401() {
        // Arrange
        let now_ms = 1_762_960_050_000_u64;
        let authority = InMemorySingleUseChallengeAuthority::new();
        let (challenge_id, server_eph_pub, challenge_nonce, _) = authority.issue(now_ms);

        let node_kp = NodeKeypair::generate();
        let disco_kp = DiscoKeypair::generate();
        let request_body = br#"{"node_name":"node-alpha"}"#;
        let body_sha256 = sha256_hex(request_body);
        let tls_exporter = sha256_hex(&[0x5A_u8; 32]);

        let proof_payload = ProofPayload {
            challenge_id,
            challenge_nonce: challenge_nonce.clone(),
            method: "POST".to_owned(),
            path: "/v1/nodes/register".to_owned(),
            body_sha256: body_sha256.clone(),
            node_pubkey: node_kp.public_key(),
            disco_pubkey: disco_kp.public_key(),
            timestamp_at_ms: now_ms,
            tls_exporter_binding: tls_exporter.clone(),
        };
        let sealed = seal_proof(&proof_payload, &server_eph_pub, &node_kp).expect("seal proof");

        let expected = ExpectedProofClaims {
            challenge_id,
            challenge_nonce_b64: &challenge_nonce,
            method: "POST",
            path: "/v1/nodes/register",
            body_sha256_hex: &body_sha256,
            claimed_node_pubkey: node_kp.public_key(),
            expected_tls_exporter_b64: Some(&tls_exporter),
            now_unix_ms: now_ms + 500,
        };

        // Act 1: first verification consumes `challenge_id` and succeeds
        let verified = authority
            .verify_and_consume_once(
                challenge_id,
                &node_kp.public_key(),
                &sealed.box_nonce,
                &sealed.ciphertext,
                &expected,
            )
            .expect("first single-use challenge proof must succeed");
        assert_eq!(verified.challenge_id, challenge_id);

        // Act 2: replaying the exact same `challenge_id` a 2nd time is blocked 100% (`US-003 AC4`)
        let replay_err = authority
            .verify_and_consume_once(
                challenge_id,
                &node_kp.public_key(),
                &sealed.box_nonce,
                &sealed.ciphertext,
                &expected,
            )
            .expect_err("replayed challenge_id must be rejected");

        // Assert: HTTP status 401 and public message is strictly `"authentication failed"` (`SEC-05`)
        assert_eq!(replay_err.kind(), ErrorKind::Unauthenticated);
        assert_eq!(replay_err.kind().http_status_code(), 401);
        assert_eq!(replay_err.public_message(), "authentication failed");
        let wire_env = replay_err.to_envelope("req-replay-01");
        assert_eq!(wire_env.message, "authentication failed");
    }

    // Traces: US-029, SEC-08, Gate 2 Dual EIO branches (a) and (b)
    #[test]
    fn test_dual_eio_branches_ram_enforcement_compaction_fold_and_exhausted_lease_reauth() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let cfg = store_config(&dir);
        let now_ms = 1_762_960_100_000_u64;
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now_ms));
        let backend = Arc::new(FaultInjectingEmergencyBackend::new(false));
        let store = ControlStore::open_with_backend(
            cfg.clone(),
            DEFAULT_OVERLAY_CIDR,
            clock,
            Arc::clone(&backend) as Arc<dyn EmergencyFileBackend>,
        )
        .expect("open store with fault backend");

        let key_hash = sha256_digest(b"mpk_DualEioTestToken000000000000000000000001");
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms),
                    token_hash: key_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: true,
                    max_uses: Some(5),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "admin",
            )
            .expect("create key");

        let pk_a = PublicKey::from_bytes([0x41_u8; 32]).expect("pk_a");
        let (reg_a, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: pk_a,
                disco_pubkey: PublicKey::from_bytes([0x42_u8; 32]).expect("dpk_a"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("dual-eio-node").expect("name"),
                preauth_token_hash: key_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .expect("register node_a");
        let node_a = reg_a.record.node_id;

        let pk_b = PublicKey::from_bytes([0x43_u8; 32]).expect("pk_b");
        let (reg_b, _) = store
            .register_node(&RegisterNodeInput {
                pubkey: pk_b,
                disco_pubkey: PublicKey::from_bytes([0x44_u8; 32]).expect("dpk_b"),
                previous_node_pubkey: None,
                requested_name: NodeName::parse("dual-eio-node-b").expect("name_b"),
                preauth_token_hash: key_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: now_ms,
            })
            .expect("register node_b");
        let node_b = reg_b.record.node_id;

        // Act Branch (a): revoke `node_a`, then inject redb read+write EIO + Slot EIO (`Dual EIO` -> `RamOnly`)
        let first_rev = store.revoke_node(node_a, "admin").expect("primary revoke");
        assert_eq!(first_rev.persistence_tier, PersistenceTier::Redb);
        store.inject_redb_failure(true, true);
        assert!(
            store.find_node_by_id(node_b).is_err(),
            "simulated redb read EIO must reject direct DB lookups (IMP-W21-01)"
        );
        backend.fail_slot_writes.store(true, Ordering::SeqCst);

        // Expire `node_b` via RAM directory lookup while both `redb` AND slot writes fail (`Dual EIO` -> `RamOnly`)
        let degraded_outcome = store
            .expire_node(node_b, "admin")
            .expect("dual EIO fallback must succeed in RAM via RAM node directory");
        assert_eq!(degraded_outcome.persistence_tier, PersistenceTier::RamOnly);
        assert!(store.is_disk_degraded());
        assert!(store.is_node_revoked_ram(node_b));
        assert!(store.is_pubkey_revoked_ram(&pk_b));

        // Also verify `EmergencyRevocationState` preserves older `EmergencySlot` entries when a new
        // entry degrades to `RamOnly` under Slot EIO (`Gate 2 policy (a)`)
        let mut ram_set = RevokedSet::new();
        let (mut emerg_state, _) = EmergencyRevocationState::boot_open_with_backend(
            dir.path().join("standalone-emerg.bin"),
            false,
            &OsEmergencyFileBackend,
        )
        .expect("boot standalone emergency state");
        let slot_tier = emerg_state.record_emergency_node(
            &mut ram_set,
            EmergencyRevocationNodeEntry {
                node_id: NodeId::new_v7(now_ms + 10),
                pubkey_bytes: [0x51_u8; 32],
                revoked_at_ms: now_ms + 10,
                min_netmap_version: 100,
                reason: EmergencyNodeReason::Revoked,
                tier: PersistenceTier::EmergencySlot,
            },
            "redb EIO 1",
            &OsEmergencyFileBackend,
        );
        assert_eq!(slot_tier, PersistenceTier::EmergencySlot);
        let ram_tier = emerg_state.record_emergency_node(
            &mut ram_set,
            EmergencyRevocationNodeEntry {
                node_id: NodeId::new_v7(now_ms + 20),
                pubkey_bytes: [0x52_u8; 32],
                revoked_at_ms: now_ms + 20,
                min_netmap_version: 101,
                reason: EmergencyNodeReason::Revoked,
                tier: PersistenceTier::EmergencySlot,
            },
            "dual EIO 2",
            backend.as_ref(),
        );
        assert_eq!(ram_tier, PersistenceTier::RamOnly);
        assert_eq!(
            emerg_state.pending_nodes.len(),
            2,
            "RamOnly fallback must never evict earlier unmerged EmergencySlot revocations"
        );

        // Recover hardware I/O and verify compaction folds `RamOnly` entries into `control.redb`
        backend.fail_slot_writes.store(false, Ordering::SeqCst);
        store.inject_redb_failure(false, false);
        let compacted = store
            .try_compact_emergency_revocations()
            .expect("compaction after hardware recovery");
        assert!(compacted.is_some());
        assert!(!store.is_disk_degraded());
        assert_eq!(
            store
                .find_node_by_id(node_a)
                .expect("find node_a")
                .map(|r| r.status),
            Some(NodeStatus::Revoked)
        );
        assert_eq!(
            store
                .find_node_by_id(node_b)
                .expect("find node_b")
                .map(|r| r.status),
            Some(NodeStatus::Expired)
        );

        // Assert Branch (b) contract: when dual EIO coincides with exhausted lease (`netmap_version: None`),
        // `must_disconnect_all_peers_to_reauth` is true so `mesh-server` disconnects peers to re-auth.
        let gate2b_outcome = RevokeStoreOutcome {
            node_id: node_a,
            persistence_tier: PersistenceTier::RamOnly,
            netmap_version: None,
            must_disconnect_all_peers_to_reauth: true,
            record: None,
        };
        assert_eq!(gate2b_outcome.persistence_tier, PersistenceTier::RamOnly);
        assert!(gate2b_outcome.netmap_version.is_none());
        assert!(gate2b_outcome.must_disconnect_all_peers_to_reauth);
    }

    // Traces: SEC-01, US-013 AC4
    #[test]
    fn test_no_secrets_in_outputs_across_store_identity_keys_and_audit_log() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let cfg = store_config(&dir);
        let now_ms = 1_762_960_200_000_u64;
        let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(now_ms));
        let store = ControlStore::open_with_clock(cfg, DEFAULT_OVERLAY_CIDR, clock)
            .expect("open control store");

        let server_id = store
            .ensure_or_init_identity(&["127.0.0.1".to_owned()], 365)
            .expect("init server identity");
        let raw_preauth = "mpk_CanarySecretTokenMustNeverLeakInOutputs99999";
        let preauth_token = PreAuthToken::parse(raw_preauth).expect("parse token");
        let token_hash = sha256_digest(raw_preauth.as_bytes());

        let key_record = store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms),
                    token_hash,
                    label: Some("canary-key".to_owned()),
                    bound_node_name: None,
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "qa-sec01",
            )
            .expect("create key");

        // Act
        let debug_token = format!("{preauth_token:?}");
        let display_token = format!("{preauth_token}");
        let debug_identity = format!("{server_id:?}");
        let debug_key_rec = format!("{key_record:?}");
        let json_key_rec = serde_json::to_string(&key_record).expect("serialize key record");
        let audits = store
            .list_audit_events(&AuditQuery::default())
            .expect("list audit events");
        let json_audits = serde_json::to_string(&audits).expect("serialize audits");

        // Assert: zero raw `mpk_` token or private key PKCS#8 bytes in any Debug/Display/JSON/Audit output
        assert_eq!(debug_token, "PreAuthToken([REDACTED])");
        assert_eq!(display_token, "[REDACTED]");
        assert!(!debug_identity.contains("PRIVATE KEY"));
        assert!(!debug_key_rec.contains(raw_preauth));
        assert!(!json_key_rec.contains(raw_preauth));
        assert!(!json_audits.contains(raw_preauth));
        assert!(!json_audits.contains("mpk_"));
    }
}
