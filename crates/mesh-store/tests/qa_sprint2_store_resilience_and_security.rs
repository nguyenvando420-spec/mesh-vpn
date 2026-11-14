//! Independent Sprint 2 QA Integration, Resilience & AppSec Tests for `mesh-store`.
//!
//! Covers:
//! - `US-031 AC2/AC5`, `US-032` & `HR-W21-02`: Node key expiry, `--never`, scoped `--for <node>`
//!   key rotation retaining `NodeId`/`OverlayIp`, clearing RAM expired state, and blocking old key
//! - `US-029 AC1/AC5`, `US-013 AC4`, `HR-W21-04` & `IMP-W21-01`: `revoke_node_with_hook` pre-disk
//!   RAM lock under Dual-`EIO`, 24-hour IP quarantine (`QUARANTINE_DURATION_MS`), and compaction
//! - `US-005` & `US-006 AC1/AC2/AC4`: Reusable Pre-Auth Key `max_uses` cap + offline ephemeral
//!   node reaping while preserving online ephemeral nodes
//! - `US-045`, `US-047 AC5` & `HR-W21-06`: Dual TLS SPKI pin staging, hot MVCC backup folding
//!   unmerged emergency revocations, SHA-256 tamper rejection, and `--min-netmap-version` floor

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tempfile::TempDir;

    use mesh_core::defaults::DEFAULT_OVERLAY_CIDR;
    use mesh_core::{Clock, ErrorKind, FakeClock, KeyId, NodeName, PublicKey};
    use mesh_crypto::{DiscoKeypair, NodeKeypair, PreAuthToken, sha256_digest};
    use mesh_proto::admin_ipc::PersistenceTier;
    use mesh_proto::netmap::{CandidateEndpoint, CandidateSource};
    use mesh_store::{
        AuditQuery, ControlStore, ControlStoreConfig, CreatePreAuthKeyInput,
        DEFAULT_NODE_KEY_TTL_MS, EmergencyFileBackend, NodeStatus, OsEmergencyFileBackend,
        QUARANTINE_DURATION_MS, RESTORE_WATERMARK_JUMP, RegisterNodeInput, RegisterNodeOutcome,
        RestoreOptions,
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

        fn set_fail_slot_writes(&self, fail: bool) {
            self.fail_slot_writes.store(fail, Ordering::SeqCst);
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
                return Err(io::Error::other(
                    "simulated hardware EIO on emergency slot write",
                ));
            }
            self.inner.write_slot_synced(path, offset, slot_bytes)
        }
    }

    struct KeySpec {
        seed_char: char,
        bound_node_name: Option<NodeName>,
        reusable: bool,
        max_uses: Option<u32>,
        ephemeral_timeout_secs: Option<u32>,
    }

    fn open_test_store(
        dir: &TempDir,
        clock: Arc<FakeClock>,
        backend: Arc<dyn EmergencyFileBackend>,
    ) -> ControlStore {
        let cfg = ControlStoreConfig {
            db_path: dir.path().join("control.redb"),
            emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
        };
        ControlStore::open_with_backend(cfg, DEFAULT_OVERLAY_CIDR, clock, backend)
            .expect("open ControlStore")
    }

    fn create_preauth_token(store: &ControlStore, spec: KeySpec, now_ms: u64) -> [u8; 32] {
        let raw = format!("mpk_{}A", spec.seed_char.to_string().repeat(42));
        assert!(PreAuthToken::parse(&raw).is_ok());
        let hash = sha256_digest(raw.as_bytes());
        store
            .create_preauth_key(
                &CreatePreAuthKeyInput {
                    key_id: KeyId::new_v7(now_ms),
                    token_hash: hash,
                    label: Some("qa-s2-key".to_owned()),
                    bound_node_name: spec.bound_node_name,
                    reusable: spec.reusable,
                    max_uses: spec.max_uses,
                    ephemeral: spec.ephemeral_timeout_secs.is_some(),
                    ephemeral_timeout_secs: spec.ephemeral_timeout_secs,
                    ttl_secs: 3_600,
                    now_unix_ms: now_ms,
                },
                "qa-s2",
            )
            .expect("create preauth key");
        hash
    }

    fn register_test_node(
        store: &ControlStore,
        name: &str,
        token_hash: [u8; 32],
        pubkey: PublicKey,
        previous_node_pubkey: Option<PublicKey>,
        now_ms: u64,
    ) -> mesh_core::AppResult<(RegisterNodeOutcome, u64)> {
        store.register_node(&RegisterNodeInput {
            pubkey,
            disco_pubkey: DiscoKeypair::generate().public_key(),
            previous_node_pubkey,
            requested_name: NodeName::parse(name).expect("valid node name"),
            preauth_token_hash: token_hash,
            public_control_host: "203.0.113.10",
            domain_suffix: "mesh.internal",
            os_arch: "linux/amd64",
            agent_version: "0.1.0",
            protocol_version: 1,
            node_key_ttl_ms: DEFAULT_NODE_KEY_TTL_MS,
            now_unix_ms: now_ms,
        })
    }

    #[test]
    fn test_store_expire_node_and_scoped_for_node_reregistration_clears_ram_and_blocks_old_key() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let clock = Arc::new(FakeClock::new(1_762_970_000_000));
        let backend = Arc::new(FaultInjectingEmergencyBackend::new(false));
        let store = open_test_store(&dir, Arc::clone(&clock), backend);

        let token_hash_initial = create_preauth_token(
            &store,
            KeySpec {
                seed_char: 'A',
                bound_node_name: None,
                reusable: false,
                max_uses: None,
                ephemeral_timeout_secs: None,
            },
            clock.now_unix_ms(),
        );
        let old_node_kp = NodeKeypair::generate();
        let (initial_out, v1) = register_test_node(
            &store,
            "prod-api-01",
            token_hash_initial,
            old_node_kp.public_key(),
            None,
            clock.now_unix_ms(),
        )
        .expect("initial registration");
        let node_id = initial_out.record.node_id;
        let assigned_ip = initial_out.record.overlay_ip.expect("assigned overlay ip");

        // Act 1: Set expiry to --never (US-031 AC2), then force immediate expiry (US-031 AC1)
        clock.advance(1_000);
        let (never_rec, v2) = store
            .set_node_expiry_never(node_id, "admin:cli")
            .expect("set expiry never");
        assert!(never_rec.key_expires_at_ms.is_none() && v2 > v1);

        clock.advance(1_000);
        let expire_out = store
            .expire_node(node_id, "admin:cli")
            .expect("expire node");
        assert_eq!(expire_out.persistence_tier, PersistenceTier::Redb);
        assert!(store.is_node_revoked_ram(node_id) && store.is_node_expired_ram(node_id));

        // Act 2: Re-register using a scoped `--for prod-api-01` key with a new keypair (US-031 AC5, HR-W21-02)
        clock.advance(1_000);
        let scoped_hash = create_preauth_token(
            &store,
            KeySpec {
                seed_char: 'B',
                bound_node_name: Some(NodeName::parse("prod-api-01").expect("name")),
                reusable: false,
                max_uses: None,
                ephemeral_timeout_secs: None,
            },
            clock.now_unix_ms(),
        );
        let new_node_kp = NodeKeypair::generate();
        assert!(
            register_test_node(
                &store,
                "other-node",
                scoped_hash,
                new_node_kp.public_key(),
                None,
                clock.now_unix_ms(),
            )
            .is_err()
        );

        let (renewed_out, v3) = register_test_node(
            &store,
            "prod-api-01",
            scoped_hash,
            new_node_kp.public_key(),
            Some(old_node_kp.public_key()),
            clock.now_unix_ms(),
        )
        .expect("scoped re-registration must succeed");

        // Assert
        assert_eq!(renewed_out.record.node_id, node_id);
        assert_eq!(renewed_out.record.overlay_ip, Some(assigned_ip));
        assert_eq!(renewed_out.record.status, NodeStatus::Active);
        assert!(v3 > expire_out.netmap_version.unwrap_or(0));
        assert!(!store.is_node_revoked_ram(node_id) && !store.is_node_expired_ram(node_id));
        assert!(store.is_pubkey_revoked_ram(&old_node_kp.public_key()));

        let ep = CandidateEndpoint {
            addr: "198.51.100.25:51820".parse().expect("endpoint"),
            source: CandidateSource::Reflexive,
        };
        let (_updated_rec, maybe_ver) = store
            .update_node_endpoints(node_id, vec![ep])
            .expect("renewed node must be allowed to update endpoints");
        assert!(maybe_ver.is_some());
    }

    #[test]
    fn test_store_revoke_node_with_hook_under_dual_eio_severs_before_disk_and_quarantines_ip_24h() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let clock = Arc::new(FakeClock::new(1_762_971_000_000));
        let backend = Arc::new(FaultInjectingEmergencyBackend::new(false));
        let store = open_test_store(
            &dir,
            Arc::clone(&clock),
            Arc::clone(&backend) as Arc<dyn EmergencyFileBackend>,
        );

        let reusable_hash = create_preauth_token(
            &store,
            KeySpec {
                seed_char: 'C',
                bound_node_name: None,
                reusable: true,
                max_uses: Some(10),
                ephemeral_timeout_secs: None,
            },
            clock.now_unix_ms(),
        );
        let node1_kp = NodeKeypair::generate();
        let (out1, _) = register_test_node(
            &store,
            "victim-node",
            reusable_hash,
            node1_kp.public_key(),
            None,
            clock.now_unix_ms(),
        )
        .expect("register node 1");
        let node1_id = out1.record.node_id;
        let quarantined_ip = out1.record.overlay_ip.expect("ip 1");

        // Inject simultaneous redb read+write failure AND emergency slot write failure (Dual-EIO)
        store.inject_redb_failure(true, true);
        backend.set_fail_slot_writes(true);

        // Act 1: Revoke with pre-disk hook (HR-W21-04 & IMP-W21-01)
        let ram_locked_inside_hook = Arc::new(AtomicBool::new(false));
        let hook_flag = Arc::clone(&ram_locked_inside_hook);
        let outcome = store
            .revoke_node_with_hook(node1_id, "admin:secops", |hook_id, hook_pk| {
                assert_eq!(hook_id, node1_id);
                assert_eq!(hook_pk, Some(node1_kp.public_key()));
                hook_flag.store(store.is_node_revoked_ram(node1_id), Ordering::SeqCst);
            })
            .expect("revoke under dual EIO must succeed in RAM");

        // Assert 1: Hook observed RAM lock before disk I/O and degraded to RamOnly
        assert!(ram_locked_inside_hook.load(Ordering::SeqCst));
        assert_eq!(outcome.persistence_tier, PersistenceTier::RamOnly);
        assert!(store.is_disk_degraded());

        // Restore disk health and compact emergency revocations (HR-W21-12)
        store.inject_redb_failure(false, false);
        backend.set_fail_slot_writes(false);
        let compacted_ver = store
            .try_compact_emergency_revocations()
            .expect("compact emergency revocations")
            .expect("compaction must emit a new netmap_version");
        assert!(compacted_ver > 0 && !store.is_disk_degraded());

        // Act 2: Verify 24h IP quarantine (`US-029 AC5`)
        clock.advance(QUARANTINE_DURATION_MS.saturating_sub(1_000));
        assert!(
            store
                .reclaim_expired_quarantines()
                .expect("premature reclaim check")
                .is_empty()
        );

        clock.advance(2_000);
        let reclaimed_ips = store
            .reclaim_expired_quarantines()
            .expect("reclaim after 24h");
        assert_eq!(reclaimed_ips, vec![quarantined_ip]);
    }

    #[test]
    fn test_store_reusable_max_uses_and_ephemeral_offline_reap_frees_ip_and_bumps_netmap() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let clock = Arc::new(FakeClock::new(1_762_972_000_000));
        let backend = Arc::new(FaultInjectingEmergencyBackend::new(false));
        let store = open_test_store(&dir, Arc::clone(&clock), backend);

        let eph_hash = create_preauth_token(
            &store,
            KeySpec {
                seed_char: 'D',
                bound_node_name: None,
                reusable: true,
                max_uses: Some(2),
                ephemeral_timeout_secs: Some(60),
            },
            clock.now_unix_ms(),
        );

        // Act 1: Register 2 ephemeral CI runner nodes (`ci-runner-1`, `ci-runner-2`)
        let (runner1, _) = register_test_node(
            &store,
            "ci-runner-1",
            eph_hash,
            NodeKeypair::generate().public_key(),
            None,
            clock.now_unix_ms(),
        )
        .expect("register runner 1");
        let (runner2, v_before_reap) = register_test_node(
            &store,
            "ci-runner-2",
            eph_hash,
            NodeKeypair::generate().public_key(),
            None,
            clock.now_unix_ms(),
        )
        .expect("register runner 2");
        assert_eq!(runner2.record.node_name.as_str(), "ci-runner-2");

        // 3rd registration with exhausted max_uses = 2 must fail with Unauthenticated ("authentication failed")
        let err = register_test_node(
            &store,
            "ci-runner-3",
            eph_hash,
            NodeKeypair::generate().public_key(),
            None,
            clock.now_unix_ms(),
        )
        .expect_err("3rd registration must fail max_uses");
        assert_eq!(err.kind(), ErrorKind::Unauthenticated);
        assert_eq!(err.public_message(), "authentication failed");

        // Act 2: Advance clock past 60s; runner1 stays online, runner2 is offline (`US-006 AC2`)
        clock.advance(65_000);
        let online_id = runner1.record.node_id;
        let (reaped, maybe_ver) = store
            .reap_expired_ephemeral_nodes(60, |id| id == online_id, "system:ephemeral_reaper")
            .expect("reap offline ephemeral nodes");

        // Assert
        assert_eq!(reaped.len(), 1);
        assert_eq!(
            reaped.first().map(|r| r.node_id),
            Some(runner2.record.node_id)
        );
        assert!(maybe_ver.unwrap_or(0) > v_before_reap);
        assert!(
            store
                .find_node_by_id(runner2.record.node_id)
                .expect("query runner 2")
                .is_none()
        );
        assert!(
            store
                .find_node_by_id(online_id)
                .expect("query runner 1")
                .is_some()
        );
    }

    #[test]
    fn test_store_hot_backup_folds_emergency_revocations_and_restore_enforces_min_netmap_version_floor()
     {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let backup_dir = dir.path().join("backups");
        let clock = Arc::new(FakeClock::new(1_762_973_000_000));
        let backend = Arc::new(FaultInjectingEmergencyBackend::new(false));
        let store = open_test_store(&dir, Arc::clone(&clock), backend);

        // Initialize TLS identity and execute two-step SPKI pin rotation (`US-047 AC5`)
        let initial_id = store
            .ensure_or_init_identity(&["203.0.113.10".to_owned()], 365)
            .expect("init identity");
        let (staged_id, _) = store
            .stage_next_identity(&["203.0.113.10".to_owned()], 365, "admin:cli")
            .expect("stage next identity");
        assert!(staged_id.staged_next.is_some());
        let (activated_id, _) = store
            .activate_staged_identity(3_600_000, "admin:cli")
            .expect("activate staged identity");
        assert_ne!(activated_id.spki_pin, initial_id.spki_pin);

        // Register a node, then revoke it while primary redb writes fail so it sits in EmergencySlot
        let token_hash = create_preauth_token(
            &store,
            KeySpec {
                seed_char: 'E',
                bound_node_name: None,
                reusable: true,
                max_uses: Some(5),
                ephemeral_timeout_secs: None,
            },
            clock.now_unix_ms(),
        );
        let (reg_out, _) = register_test_node(
            &store,
            "backup-fold-node",
            token_hash,
            NodeKeypair::generate().public_key(),
            None,
            clock.now_unix_ms(),
        )
        .expect("register node");
        let revoked_node_id = reg_out.record.node_id;

        store.inject_redb_failure(false, true);
        let rev_out = store
            .revoke_node(revoked_node_id, "admin:cli")
            .expect("revoke into emergency slot");
        assert_eq!(rev_out.persistence_tier, PersistenceTier::EmergencySlot);
        store.inject_redb_failure(false, false);

        // Act 1: Create hot backup BEFORE compaction (`BLK-S1-04`)
        let artifact = store
            .create_backup(&backup_dir, "admin:cli")
            .expect("create hot backup");
        assert!(artifact.contains_server_identity && artifact.snapshot_path.exists());

        // Act 2: Verify SHA-256 tamper detection fails closed (`US-045 AC4`)
        let original_sidecar = fs::read_to_string(&artifact.sha256_path).expect("read sidecar");
        fs::write(&artifact.sha256_path, "0".repeat(64)).expect("tamper sidecar");
        assert!(
            store
                .restore_backup(RestoreOptions {
                    snapshot_path: artifact.snapshot_path.clone(),
                    target_db_path: Path::new("").to_path_buf(),
                    target_emergency_path: Path::new("").to_path_buf(),
                    expected_published_pin: Some(activated_id.spki_pin),
                    allow_pin_change: false,
                    verify_sha256: true,
                    min_netmap_version: 0,
                    min_required_snapshot_version: None,
                })
                .is_err()
        );
        fs::write(&artifact.sha256_path, original_sidecar).expect("restore sidecar");

        // Act 3: Restore with `--min-netmap-version 5_000_000` (`HR-W21-06`, `US-045`)
        let restore_out = store
            .restore_backup(RestoreOptions {
                snapshot_path: artifact.snapshot_path,
                target_db_path: Path::new("").to_path_buf(),
                target_emergency_path: Path::new("").to_path_buf(),
                expected_published_pin: Some(activated_id.spki_pin),
                allow_pin_change: false,
                verify_sha256: true,
                min_netmap_version: 5_000_000,
                min_required_snapshot_version: None,
            })
            .expect("restore valid snapshot");

        // Assert
        assert_eq!(restore_out.restored_spki_pin, Some(activated_id.spki_pin));
        assert!(restore_out.new_netmap_watermark >= 5_000_000 + RESTORE_WATERMARK_JUMP);
        let restored_node = store
            .find_node_by_id(revoked_node_id)
            .expect("query restored node")
            .expect("node exists in restored DB");
        assert_eq!(restored_node.status, NodeStatus::Revoked);
        assert!(
            !store
                .list_audit_events(&AuditQuery {
                    limit: 20,
                    before_seq: None,
                    actor: None,
                    action: None,
                })
                .expect("list audits")
                .is_empty()
        );
    }
}
