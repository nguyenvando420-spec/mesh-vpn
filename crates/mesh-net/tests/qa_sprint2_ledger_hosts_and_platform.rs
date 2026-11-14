//! Independent Sprint 2 QA Integration, Platform Safety & AppSec Tests for `mesh-net`.
//!
//! Covers:
//! - `US-055`, `US-060`, `US-073` & `G4`: `ResourceLedger` write-before-create persistence,
//!   crash recovery (`cleanly_stopped = false`), ordered cleanup (`routes -> linux_policy ->
//!   hosts -> firewall -> tun`), and idempotent no-op when already clean
//! - `US-038`, `US-056` & `PLAT-04`: `FileHostsEditor` and `render_hosts_with_block` preserving
//!   user entries & CRLF/LF line endings, blocking reserved names & `public_server_host` collisions,
//!   and failing closed on malformed `# BEGIN mesh` markers
//! - `US-020`, `US-036 AC4`, `US-037` & `REL-09`: CGNAT `100.64.0.0/10` physical subnet conflict
//!   detection (`apply_overlay_route_checked`), DHCP wait after sleep/wake (`wait_for_usable_ip_with_backoff`),
//!   and TCP vs UDP candidate endpoint port distinction (`Codex R2 #4`)
//! - `US-001 AC4`, `US-052`, `US-073`, `SEC-01` & `SEC-14`: `KeysFileStore` fail-closed on corrupt
//!   `keys.json`, secret redaction in `Debug`, `DefaultPrivilegeIpc` authorization matrix across
//!   Linux/macOS/Windows, and `CommandSpec::new` NUL-byte rejection

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    use mesh_core::brand::{HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
    use mesh_core::defaults::MACOS_ADMIN_GID;
    use mesh_core::{ErrorKind, NodeName, OverlayCidr, OverlayIp};
    use mesh_net::{
        AllowedBinary, CallerPrivilege, CandidateFilterContext, CommandSpec, DefaultPrivilegeIpc,
        DhcpWaitConfig, FakeLedgerCleanupOps, FakePhysicalNetworkProbe, FileHostsEditor,
        HostsEditor, HostsEntry, InterfaceSubnetSnapshot, IpcChannelKind, KeysFileStore,
        LedgerIpRuleEntry, LedgerRouteEntry, PeerIdentity, PhysicalInterface, PrivilegeIpc,
        ResourceLedger, RouteSpec, apply_overlay_route_checked, is_valid_candidate_endpoint,
        reject_non_overlay_cidr, render_hosts_with_block, wait_for_usable_ip_with_backoff,
    };

    fn make_subnet_snapshot(
        if_index: u32,
        name: &str,
        ip: Ipv4Addr,
        prefix_len: u8,
        is_virtual: bool,
    ) -> InterfaceSubnetSnapshot {
        InterfaceSubnetSnapshot {
            if_index,
            interface_name: name.to_owned(),
            ip: IpAddr::V4(ip),
            prefix_len,
            is_up: true,
            is_virtual,
            has_gateway: !is_virtual,
        }
    }

    #[test]
    fn test_ledger_crash_recovery_cleans_only_recorded_resources_and_preserves_foreign_interfaces()
    {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let ledger_path = dir.path().join("ledger.json");
        let mut ledger = ResourceLedger::load_or_init(ledger_path.clone()).expect("init ledger");
        assert!(!ledger.needs_stale_recovery());

        ledger
            .record_tun_before_create(
                "utun7".to_owned(),
                Some("01234567-89ab-cdef-0123-456789abcdef".to_owned()),
                4242,
                1_762_978_000_000,
            )
            .expect("record tun");
        ledger
            .record_linux_policy_before_apply(
                51820,
                vec![LedgerIpRuleEntry {
                    priority: 51820,
                    not_fwmark: Some(0x5d56),
                    lookup_table: 51820,
                    suppress_prefixlength: None,
                    family: "inet".to_owned(),
                }],
            )
            .expect("record linux policy");
        ledger
            .record_route_before_add(LedgerRouteEntry {
                destination_cidr: "10.100.0.0/16".to_owned(),
                interface_name: "utun7".to_owned(),
                table: Some(51820),
            })
            .expect("record route");
        ledger
            .record_hosts_before_activate("/private/etc/hosts".to_owned())
            .expect("record hosts");
        ledger
            .record_firewall_before_apply(
                Some("com.meshvpn".to_owned()),
                vec!["MeshVPN-UDP-In".to_owned()],
            )
            .expect("record firewall");

        // Act: Simulate daemon crash by reopening `ledger.json` without calling `cleanup_all`
        drop(ledger);
        let mut crashed_ledger =
            ResourceLedger::load_or_init(ledger_path).expect("reload crashed ledger");
        assert!(crashed_ledger.needs_stale_recovery() && !crashed_ledger.data().cleanly_stopped);

        let ops = FakeLedgerCleanupOps::new();
        crashed_ledger
            .cleanup_all(&ops)
            .expect("cleanup crashed resources");

        // Assert: Strictly ordered cleanup and only `utun7` closed (never wildcard `utun*`)
        let steps = ops.recorded_steps().expect("recorded steps");
        assert_eq!(
            steps,
            vec![
                "remove_route:utun7:10.100.0.0/16".to_owned(),
                "remove_linux_policy:table=51820:rules=1".to_owned(),
                "remove_hosts:/private/etc/hosts".to_owned(),
                "remove_firewall:anchor=com.meshvpn:rules=1".to_owned(),
                "close_tun:utun7:01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            ]
        );
        assert!(!crashed_ledger.needs_stale_recovery() && crashed_ledger.data().cleanly_stopped);

        crashed_ledger
            .cleanup_all(&ops)
            .expect("idempotent second cleanup");
        assert_eq!(ops.recorded_steps().expect("steps").len(), 5);
    }

    #[test]
    fn test_hosts_editor_preserves_custom_lines_crlf_and_blocks_reserved_and_public_server_names() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let hosts_path = dir.path().join("hosts");
        let initial_crlf = "127.0.0.1 localhost\r\n192.168.1.50 nas.local\r\n";
        fs::write(&hosts_path, initial_crlf).expect("write initial CRLF hosts");
        let editor = FileHostsEditor::new(hosts_path.clone());

        let ip1 = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 10)).expect("ip1");
        let entry1 = HostsEntry::new(
            ip1,
            NodeName::parse("db-primary").expect("valid name"),
            "mesh.internal",
            Some("vpn.example.com"),
        )
        .expect("valid hosts entry");

        // Act 1: Apply block and verify CRLF + user lines are preserved (`US-038 AC2`)
        editor
            .apply(std::slice::from_ref(&entry1), Some("vpn.example.com"))
            .expect("apply hosts block");
        let after_apply = fs::read_to_string(&hosts_path).expect("read hosts");
        assert!(after_apply.starts_with(initial_crlf));
        assert!(after_apply.contains(&format!("\r\n{HOSTS_BEGIN_MARKER}\r\n")));
        assert!(after_apply.contains(&format!("\r\n{HOSTS_END_MARKER}\r\n")));
        assert!(after_apply.contains("10.100.0.10 db-primary.mesh.internal db-primary\r\n"));

        editor.clear().expect("clear hosts block");
        assert_eq!(
            fs::read_to_string(&hosts_path).expect("read cleared hosts"),
            initial_crlf
        );

        // Act 2: Reserved names, public server collisions, and malformed markers fail closed (`PLAT-04`)
        for reserved in ["localhost", "broadcasthost", "wpad", "isatap", "local"] {
            assert!(NodeName::parse(reserved).is_err());
        }
        assert!(
            HostsEntry::new(
                ip1,
                NodeName::parse("vpn").expect("name"),
                "example.com",
                Some("vpn.example.com"),
            )
            .is_err()
        );
        let server_ip_overlay = OverlayIp::from_ipv4(Ipv4Addr::new(10, 100, 0, 99)).expect("ip");
        assert!(
            HostsEntry::new(
                server_ip_overlay,
                NodeName::parse("worker-1").expect("name"),
                "mesh.internal",
                Some("10.100.0.99"),
            )
            .is_err()
        );
        assert!(
            render_hosts_with_block(
                &format!("127.0.0.1 localhost\n{HOSTS_BEGIN_MARKER}\n10.100.0.2 orphan\n"),
                &[entry1],
                None
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn test_endpoint_filter_and_cgnat_subnet_conflict_detection_blocks_overlapping_route() {
        // Arrange
        let cgnat_overlay: OverlayCidr = "100.64.0.0/10".parse().expect("valid cgnat cidr");
        let route_mgr = mesh_net::FakeRouteManager::new();
        let spec = RouteSpec::new(cgnat_overlay, cgnat_overlay, "utun7", None).expect("route spec");

        let non_conflicting = vec![
            make_subnet_snapshot(2, "utun3", Ipv4Addr::new(100, 64, 1, 5), 10, true),
            make_subnet_snapshot(3, "en0", Ipv4Addr::new(192, 168, 1, 20), 24, false),
        ];
        apply_overlay_route_checked(&route_mgr, &spec, &non_conflicting)
            .expect("virtual utun3 in 100.64/10 must not block overlay route");

        // Act 1: Active physical ISP CGNAT interface (`en0` on `100.64.10.2/24`) must block route (`US-037`)
        let conflicting = vec![make_subnet_snapshot(
            3,
            "en0",
            Ipv4Addr::new(100, 64, 10, 2),
            24,
            false,
        )];
        let err = apply_overlay_route_checked(&route_mgr, &spec, &conflicting)
            .expect_err("physical CGNAT collision must refuse overlay route");
        assert_eq!(err.kind(), ErrorKind::Conflict);
        assert!(reject_non_overlay_cidr("0.0.0.0/0", cgnat_overlay).is_err());

        // Act 2: DHCP wait after sleep/wake ignores APIPA `169.254.x.x` until routable IP arrives (`US-036 AC4`)
        let primary = PhysicalInterface {
            name: "en0".to_owned(),
            if_index: 3,
        };
        let probe = FakePhysicalNetworkProbe::with_snapshot(
            primary.clone(),
            vec![make_subnet_snapshot(
                3,
                "en0",
                Ipv4Addr::new(169, 254, 10, 5),
                16,
                false,
            )],
        );
        probe.push_observation(
            Ok(primary),
            Ok(vec![make_subnet_snapshot(
                3,
                "en0",
                Ipv4Addr::new(192, 168, 1, 44),
                24,
                false,
            )]),
        );
        let shutdown = CancellationToken::new();
        let ready = wait_for_usable_ip_with_backoff(
            &probe,
            DhcpWaitConfig {
                initial_delay_ms: 10,
                max_delay_ms: 20,
                max_wait_ms: 500,
            },
            &shutdown,
        )
        .await
        .expect("DHCP wait must resolve once routable IP arrives");
        assert_eq!(ready.name, "en0");
        assert_eq!(ready.if_index, 3);

        // Act 3: Candidate filter allows UDP candidate sharing Control TCP port (`Codex R2 #4`)
        let filter_ctx = CandidateFilterContext {
            overlay_cidr: "10.100.0.0/16".parse().expect("cidr"),
            control_tcp_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 443))),
            stun_udp_endpoint: Some(SocketAddr::from(([203, 0, 113, 10], 3478))),
        };
        assert!(is_valid_candidate_endpoint(
            SocketAddr::from(([203, 0, 113, 10], 443)),
            Some("en0"),
            &filter_ctx
        ));
        assert!(!is_valid_candidate_endpoint(
            SocketAddr::from(([203, 0, 113, 10], 3478)),
            Some("en0"),
            &filter_ctx
        ));
    }

    #[test]
    fn test_keystore_fail_closed_on_corrupt_file_and_ipc_privilege_authorization_matrix() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let keys_path = dir.path().join("keys.json");
        let keystore = KeysFileStore::new(keys_path.clone());

        // Act 1: Generate fresh identity, verify Debug redaction, then corrupt file (`US-001 AC4`, `SEC-01`)
        let identity = keystore
            .load_or_create(1_762_979_000_000)
            .expect("create keys.json");
        assert!(format!("{identity:?}").contains("[REDACTED]"));

        fs::write(&keys_path, b"{corrupt-json").expect("write corrupt keys.json");
        assert!(keystore.load_or_create(1_762_979_005_000).is_err());
        assert_eq!(
            fs::read(&keys_path).expect("read corrupt file"),
            b"{corrupt-json"
        );

        // Act 2: Verify `DefaultPrivilegeIpc` authorization matrix across OSes (`SEC-14`)
        let policy = DefaultPrivilegeIpc::new();
        let macos_admin = PeerIdentity::Unix {
            uid: 501,
            primary_gid: 20,
            supplementary_gids: vec![20, MACOS_ADMIN_GID],
            mesh_admin_gid: None,
            is_macos: true,
        };
        assert!(matches!(
            policy
                .authorize(IpcChannelKind::AgentAdmin, &macos_admin)
                .expect("macOS gid 80 admin"),
            CallerPrivilege::Admin { .. }
        ));

        let unpriv_win = PeerIdentity::Windows {
            is_builtin_admin: false,
            is_local_system: false,
            principal: "S-1-5-21-1001".to_owned(),
        };
        assert_eq!(
            policy
                .authorize(IpcChannelKind::AgentAdmin, &unpriv_win)
                .expect_err("unprivileged Windows user must be denied on AgentAdmin")
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert!(matches!(
            policy
                .authorize(IpcChannelKind::AgentReadOnly, &unpriv_win)
                .expect("unprivileged Windows user allowed on AgentReadOnly"),
            CallerPrivilege::ReadOnly { .. }
        ));

        // Act 3: Verify `CommandSpec::new` rejects NUL bytes (`US-073`)
        assert!(
            CommandSpec::new(
                AllowedBinary::LinuxIpUsrSbin,
                vec!["addr\0inject".to_owned()],
            )
            .is_err()
        );
    }
}
