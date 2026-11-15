//! Desktop network-roaming runtime re-export and OS monitor factory (`US-035`, `US-036`).

use std::sync::Arc;

#[cfg(target_os = "windows")]
use tokio::sync::mpsc;
use tracing::warn;

use mesh_net::netmon::NetMonitor;

pub(crate) use mesh_client::roaming_loop::RoamingLoop;

/// Windows power-notification handle returned alongside the platform monitor on Windows.
#[cfg(target_os = "windows")]
pub(crate) type WindowsPowerSender = mpsc::Sender<mesh_net::netmon_windows::WindowsPowerEvent>;

/// Starts the best-effort OS [`NetMonitor`] for the current target platform.
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<WindowsPowerSender>) {
    match mesh_net::netmon_windows::WindowsNetMonitor::start_live() {
        Ok(mon) => {
            let pwr = mon.power_event_sender();
            (Arc::new(mon), Some(pwr))
        }
        Err(err) => {
            warn!(
                component = "meshd.roaming_loop",
                event = "windows_netmon_fallback",
                error = %err,
                "failed subscribing Windows NotifyIpInterfaceChange; using SCM PowerEvent fallback monitor"
            );
            let fallback = mesh_net::netmon_windows::WindowsNetMonitor::start_power_monitor_only();
            let pwr = fallback.power_event_sender();
            (Arc::new(fallback), Some(pwr))
        }
    }
}

/// Starts the Linux Netlink [`NetMonitor`], falling back gracefully in restricted containers.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<()>) {
    match mesh_net::netmon_linux::LinuxNetMonitor::start() {
        Ok(mon) => (Arc::new(mon), None),
        Err(err) => {
            warn!(
                component = "meshd.roaming_loop",
                event = "linux_netmon_fallback",
                error = %err,
                "failed starting Linux Netlink monitor; continuing with clock-jump detector"
            );
            (Arc::new(mesh_net::netmon::FakeNetMonitor::new()), None)
        }
    }
}

/// Starts the macOS `PF_ROUTE` [`NetMonitor`], falling back cleanly if restricted.
#[cfg(target_os = "macos")]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<()>) {
    match mesh_net::netmon_macos::MacOsNetMonitor::start() {
        Ok(mon) => (Arc::new(mon), None),
        Err(err) => {
            warn!(
                component = "meshd.roaming_loop",
                event = "macos_netmon_fallback",
                error = %err,
                "failed starting macOS PF_ROUTE monitor; continuing with clock-jump detector"
            );
            (Arc::new(mesh_net::netmon::FakeNetMonitor::new()), None)
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<()>) {
    (Arc::new(mesh_net::netmon::FakeNetMonitor::new()), None)
}
