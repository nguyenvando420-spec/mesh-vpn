//! Thin desktop control-plane re-exports plus OS-specific `/etc/hosts` and interface discovery (`US-003`, `US-099`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::warn;

pub(crate) use mesh_client::control_loop::{ControlLoop, probe_udp_routing_candidates_protected};
#[cfg(test)]
pub(crate) use mesh_client::control_loop::{ControlWakeSignal, filter_local_candidate_list};
pub(crate) use mesh_client::state::ClientRuntimeState as DaemonRuntimeState;
#[cfg(test)]
pub(crate) use mesh_client::state::merge_local_and_reflexive_candidates;
use mesh_net::DiscoveredInterfaceEndpoint;
use mesh_net::hosts::HostsEntry;
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
use mesh_net::hosts::{FileHostsEditor, HostsEditor as _};
use mesh_net::ledger::ResourceLedger;
use mesh_net::nat64::NoopSocketProtector;
use mesh_net::sysexec::{AllowedBinary, CommandExecutor as _, CommandSpec, StdCommandExecutor};

/// Synchronizes desktop OS hosts file managed blocks (`# BEGIN mesh ... # END mesh`).
#[cfg(target_os = "windows")]
pub(crate) async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = match mesh_net::hosts_windows::WindowsHostsEditor::system_default() {
        Ok(e) => e,
        Err(err) => {
            warn!(
                component = "meshd.control_loop",
                event = "windows_hosts_init_failed",
                error = %err,
                "failed resolving Windows hosts file path"
            );
            return;
        }
    };
    if let Ok(path) = mesh_net::hosts_windows::windows_hosts_path() {
        let mut guard = ledger.lock().await;
        if let Err(err) = guard.record_hosts_before_activate(path.display().to_string()) {
            warn!(
                component = "meshd.control_loop",
                event = "windows_hosts_ledger_record_failed",
                error = %err,
                "failed recording Windows hosts path into ResourceLedger"
            );
        }
    }
    if let Err(err) = editor
        .apply_with_public_host_async(entries, public_host)
        .await
    {
        warn!(
            component = "meshd.control_loop",
            event = "windows_hosts_sync_failed",
            error = %err,
            "failed syncing Windows hosts managed block"
        );
    }
}

/// Synchronizes macOS `/etc/hosts` managed block while preserving symlink integrity.
#[cfg(target_os = "macos")]
pub(crate) async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = mesh_net::hosts_macos::macos_hosts_editor();
    let mut guard = ledger.lock().await;
    if let Err(err) = mesh_net::hosts_macos::apply_macos_hosts_with_ledger(
        &editor,
        entries,
        public_host,
        &mut guard,
    ) {
        warn!(
            component = "meshd.control_loop",
            event = "macos_hosts_sync_failed",
            error = %err,
            "failed syncing macOS hosts managed block"
        );
    }
}

/// Synchronizes Linux `/etc/hosts` managed block via `ResourceLedger`.
#[cfg(target_os = "linux")]
pub(crate) async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = mesh_net::hosts_linux::linux_hosts_editor();
    let mut guard = ledger.lock().await;
    if let Err(err) = mesh_net::hosts_linux::apply_linux_hosts_with_ledger(
        &editor,
        entries,
        public_host,
        &mut guard,
    ) {
        warn!(
            component = "meshd.control_loop",
            event = "linux_hosts_sync_failed",
            error = %err,
            "failed syncing Linux hosts managed block"
        );
    }
}

/// Fallback POSIX `/etc/hosts` synchronizer.
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub(crate) async fn sync_platform_hosts_entries(
    entries: &[HostsEntry],
    public_host: Option<&str>,
    ledger: &Arc<Mutex<ResourceLedger>>,
) {
    let editor = FileHostsEditor::default_system();
    let mut guard = ledger.lock().await;
    if let Ok(Some(real)) = editor.canonical_real_path()
        && let Err(err) = guard.record_hosts_before_activate(real.display().to_string())
    {
        warn!(
            component = "meshd.control_loop",
            event = "hosts_ledger_record_failed",
            error = %err,
            "failed recording hosts file path into ResourceLedger"
        );
    }
    if let Err(err) = editor.apply(entries, public_host) {
        warn!(
            component = "meshd.control_loop",
            event = "hosts_sync_failed",
            error = %err,
            "failed syncing managed hosts entries"
        );
    }
}

/// Discovers local physical interface endpoint candidates using sanitized `sysexec` + UDP probing.
pub(crate) fn discover_desktop_local_interface_endpoints(
    udp_port: u16,
) -> Vec<DiscoveredInterfaceEndpoint> {
    let mut items = Vec::new();
    let exec = StdCommandExecutor::new();
    if cfg!(target_os = "linux") {
        let args = [
            "-o".to_owned(),
            "addr".to_owned(),
            "show".to_owned(),
            "scope".to_owned(),
            "global".to_owned(),
        ];
        for bin in [AllowedBinary::LinuxIpUsrSbin, AllowedBinary::LinuxIpSbin] {
            if let Ok(spec) = CommandSpec::new(bin, args.clone())
                && let Ok(out) = exec.execute(&spec)
                && out.success()
            {
                items.extend(parse_linux_ip_addr_output(&out.stdout, udp_port));
                break;
            }
        }
    } else if cfg!(target_os = "macos")
        && let Ok(spec) =
            CommandSpec::new(AllowedBinary::MacOsIfconfig, std::iter::empty::<String>())
        && let Ok(out) = exec.execute(&spec)
        && out.success()
    {
        items.extend(parse_macos_ifconfig_output(&out.stdout, udp_port));
    }

    if let Ok(probed) = probe_udp_routing_candidates_protected(udp_port, None, &NoopSocketProtector)
    {
        items.extend(probed);
    }
    items
}

fn parse_linux_ip_addr_output(stdout: &str, udp_port: u16) -> Vec<DiscoveredInterfaceEndpoint> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(raw_iface) = parts.get(1) else {
            continue;
        };
        let Some(family) = parts.get(2) else {
            continue;
        };
        let Some(cidr_token) = parts.get(3) else {
            continue;
        };
        if *family != "inet" && *family != "inet6" {
            continue;
        }
        let iface = raw_iface.split('@').next().unwrap_or(raw_iface).trim();
        let Some(ip_str) = cidr_token.split('/').next() else {
            continue;
        };
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            out.push(DiscoveredInterfaceEndpoint {
                interface_name: Some(iface.to_owned()),
                endpoint: SocketAddr::new(ip, udp_port),
            });
        }
    }
    out
}

fn parse_macos_ifconfig_output(stdout: &str, udp_port: u16) -> Vec<DiscoveredInterfaceEndpoint> {
    let mut out = Vec::new();
    let mut current_iface: Option<String> = None;
    for raw_line in stdout.lines() {
        if !raw_line.starts_with(char::is_whitespace) && !raw_line.is_empty() {
            current_iface = raw_line
                .split(':')
                .next()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty());
            continue;
        }
        let trimmed = raw_line.trim_start();
        let candidate_token = trimmed
            .strip_prefix("inet ")
            .or_else(|| trimmed.strip_prefix("inet6 "))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|tok| tok.split('%').next());
        if let Some(ip_str) = candidate_token
            && let Ok(ip) = ip_str.parse::<IpAddr>()
        {
            out.push(DiscoveredInterfaceEndpoint {
                interface_name: current_iface.clone(),
                endpoint: SocketAddr::new(ip, udp_port),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use mesh_core::OverlayCidr;
    use mesh_core::defaults::{
        DEFAULT_CONTROL_TCP_PORT, DEFAULT_OVERLAY_CIDR, DEFAULT_STUN_UDP_PORT,
    };
    use mesh_net::endpoint_filter::CandidateFilterContext;
    use mesh_proto::netmap::{CandidateEndpoint, CandidateSource};

    use super::{
        filter_local_candidate_list, merge_local_and_reflexive_candidates,
        parse_linux_ip_addr_output, parse_macos_ifconfig_output,
    };

    #[test]
    fn test_parse_and_filter_local_candidates_excludes_virtual_and_overlay_ips() {
        // Arrange
        let linux_out = "\
1: lo    inet 127.0.0.1/8 scope host lo\\ valid_lft forever preferred_lft forever
2: eth0    inet 192.168.10.25/24 brd 192.168.10.255 scope global eth0\\ valid_lft forever
3: mesh0    inet 100.115.0.5/16 scope global mesh0\\ valid_lft forever
4: docker0    inet 172.17.0.1/16 scope global docker0\\ valid_lft forever
5: eth0    inet6 2001:db8::5/64 scope global dynamic\\ valid_lft forever
";
        let mac_out = "\
lo0: flags=8049<UP,LOOPBACK> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
utun4: flags=8051<UP,POINTOPOINT> mtu 1280
\tinet 100.115.0.9 --> 100.115.0.9 netmask 0xffff0000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING> mtu 1500
\tinet 10.20.30.40 netmask 0xffffff00 broadcast 10.20.30.255
\tinet6 fe80::1234%en0 prefixlen 64 secured scopeid 0x4
";
        let Ok(overlay_cidr) = DEFAULT_OVERLAY_CIDR.parse::<OverlayCidr>() else {
            return;
        };
        let filter_ctx = CandidateFilterContext {
            overlay_cidr,
            control_tcp_endpoint: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                DEFAULT_CONTROL_TCP_PORT,
            )),
            stun_udp_endpoint: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                DEFAULT_STUN_UDP_PORT,
            )),
        };

        // Act
        let mut raw = parse_linux_ip_addr_output(linux_out, 51820);
        raw.extend(parse_macos_ifconfig_output(mac_out, 51820));
        let filtered = filter_local_candidate_list(&raw, Some("mesh0"), &filter_ctx);
        let merged = merge_local_and_reflexive_candidates(
            &filtered,
            &[
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 41234),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 25)), 51820),
            ],
        );

        // Assert
        let expected_local = vec![
            CandidateEndpoint {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 25)), 51820),
                source: CandidateSource::Lan,
            },
            CandidateEndpoint {
                addr: SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 5)),
                    51820,
                ),
                source: CandidateSource::Ipv6,
            },
            CandidateEndpoint {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)), 51820),
                source: CandidateSource::Lan,
            },
        ];
        assert_eq!(filtered, expected_local);
        assert_eq!(merged.len(), 4);
        assert_eq!(
            merged.last().map(|c| c.source),
            Some(CandidateSource::Reflexive)
        );
    }
}
