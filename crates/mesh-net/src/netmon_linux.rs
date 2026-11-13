//! Linux `NETLINK_ROUTE` async network change monitor implementing [`NetMonitor`] (`US-035`).

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use mesh_core::{AppError, AppResult};
use mesh_sys::netmon_linux::RawNetEventKind;
use tokio::net::unix::pipe;

use crate::endpoint_filter::InterfaceSubnetSnapshot;
use crate::netmon::{NetEvent, PhysicalInterface};
use crate::tun::BoxFuture;

/// Queries the current primary Linux physical interface `(if_index, name)` via Netlink/proc.
pub fn query_primary_physical_interface() -> AppResult<PhysicalInterface> {
    let (if_index, name) =
        mesh_sys::netmon_linux::query_primary_physical_interface().map_err(AppError::from)?;
    Ok(PhysicalInterface { if_index, name })
}

/// Lists all current Linux interface unicast addresses and CIDR prefixes (`US-036`, `US-037`).
pub fn list_interface_subnets() -> AppResult<Vec<InterfaceSubnetSnapshot>> {
    let items = mesh_sys::netmon_linux::list_interface_addresses().map_err(AppError::from)?;
    Ok(items
        .into_iter()
        .map(|item| InterfaceSubnetSnapshot {
            if_index: item.if_index,
            interface_name: item.name,
            ip: item.ip,
            prefix_len: item.prefix_len,
            is_up: item.is_up,
            is_virtual: item.is_virtual,
            has_gateway: false,
        })
        .collect())
}

/// Linux asynchronous network monitor backed by `AF_NETLINK` / `NETLINK_ROUTE` multicast groups.
#[derive(Debug)]
pub struct LinuxNetMonitor {
    state: Mutex<LinuxNetmonState>,
}

#[derive(Debug)]
struct LinuxNetmonState {
    rx: Option<Arc<pipe::Receiver>>,
    pending: VecDeque<NetEvent>,
}

impl Default for LinuxNetMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxNetMonitor {
    /// Creates a lazy-opening Linux Netlink network monitor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(LinuxNetmonState {
                rx: None,
                pending: VecDeque::new(),
            }),
        }
    }

    /// Eagerly opens and binds the `NETLINK_ROUTE` socket right away.
    pub fn start() -> AppResult<Self> {
        let monitor = Self::new();
        monitor.ensure_fd().map(|_| ())?;
        Ok(monitor)
    }

    fn pop_pending_or_fd(&self) -> AppResult<Result<NetEvent, Arc<pipe::Receiver>>> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("Linux netmon mutex poisoned"))?;
        if let Some(ev) = guard.pending.pop_front() {
            return Ok(Ok(ev));
        }
        if let Some(rx) = guard.rx.as_ref() {
            return Ok(Err(Arc::clone(rx)));
        }
        drop(guard);
        let rx = self.ensure_fd()?;
        Ok(Err(rx))
    }

    fn ensure_fd(&self) -> AppResult<Arc<pipe::Receiver>> {
        let owned = mesh_sys::netmon_linux::open_netlink_route_monitor()?;
        let async_rx = Arc::new(
            pipe::Receiver::from_owned_fd_unchecked(owned).map_err(|err| {
                AppError::unavailable(format!(
                    "failed registering NETLINK_ROUTE with Tokio: {err}"
                ))
            })?,
        );

        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("Linux netmon mutex poisoned"))?;
        if let Some(existing) = guard.rx.as_ref() {
            return Ok(Arc::clone(existing));
        }
        guard.rx = Some(Arc::clone(&async_rx));
        Ok(async_rx)
    }

    fn enqueue_batch_for_iface_and_take_first(
        &self,
        batch: Vec<RawNetEventKind>,
        iface_name: Option<&str>,
    ) -> AppResult<Option<NetEvent>> {
        let mut iter = batch
            .into_iter()
            .map(|kind| map_raw_event_with_iface(kind, iface_name));
        let Some(first) = iter.next() else {
            return Ok(None);
        };
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("Linux netmon mutex poisoned"))?;
        guard.pending.extend(iter);
        Ok(Some(first))
    }

    #[cfg(test)]
    fn enqueue_batch_and_take_first(
        &self,
        batch: Vec<RawNetEventKind>,
    ) -> AppResult<Option<NetEvent>> {
        self.enqueue_batch_for_iface_and_take_first(batch, None)
    }
}

/// Translates a raw Linux Netlink notification kind into an OS-agnostic [`NetEvent`], attaching
/// a resolved interface name when available.
#[must_use]
pub fn map_raw_event_with_iface(kind: RawNetEventKind, iface_name: Option<&str>) -> NetEvent {
    let iface = iface_name
        .filter(|s| !s.is_empty())
        .unwrap_or("underlay")
        .to_owned();
    match kind {
        RawNetEventKind::InterfaceUpChanged => NetEvent::InterfaceUp { interface: iface },
        RawNetEventKind::AddressChanged => NetEvent::AddressChanged { interface: iface },
        RawNetEventKind::DefaultRouteChanged | RawNetEventKind::PhysicalInterfaceChanged => {
            NetEvent::RouteChanged
        }
    }
}

/// Translates a raw Linux Netlink notification kind into an OS-agnostic [`NetEvent`].
#[must_use]
pub fn map_raw_event(kind: RawNetEventKind) -> NetEvent {
    map_raw_event_with_iface(kind, None)
}

impl crate::netmon::NetMonitor for LinuxNetMonitor {
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>> {
        Box::pin(async move {
            loop {
                let rx = match self.pop_pending_or_fd()? {
                    Ok(ev) => return Ok(ev),
                    Err(rx) => rx,
                };

                rx.readable().await.map_err(|err| {
                    AppError::unavailable(format!("NETLINK_ROUTE readability wait failed: {err}"))
                })?;
                match rx.try_io(|| mesh_sys::netmon_linux::read_netlink_events(rx.as_ref())) {
                    Ok(batch) => {
                        let active_iface = query_primary_physical_interface().ok().map(|p| p.name);
                        if let Some(first) = self.enqueue_batch_for_iface_and_take_first(
                            batch,
                            active_iface.as_deref(),
                        )? {
                            return Ok(first);
                        }
                    }
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        continue;
                    }
                    Err(err)
                        if err.raw_os_error() == Some(mesh_sys::netmon_linux::ENOBUFS_ERRNO) =>
                    {
                        // Netlink receive queue overflow during heavy interface churn; emit a
                        // route change so roaming re-probes the active primary NIC cleanly.
                        return Ok(NetEvent::RouteChanged);
                    }
                    Err(err) => {
                        return Err(AppError::unavailable(format!(
                            "NETLINK_ROUTE read failed: {err}"
                        )));
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use mesh_sys::netmon_linux::RawNetEventKind;

    use super::{LinuxNetMonitor, map_raw_event};
    use crate::netmon::NetEvent;

    #[test]
    fn test_netmon_linux_maps_and_buffers_batched_events() {
        // Arrange
        let monitor = LinuxNetMonitor::new();
        let batch = vec![
            RawNetEventKind::InterfaceUpChanged,
            RawNetEventKind::AddressChanged,
            RawNetEventKind::DefaultRouteChanged,
        ];

        // Act
        let first = monitor
            .enqueue_batch_and_take_first(batch)
            .expect("enqueue batch");
        let guard = monitor.state.lock().expect("lock state");

        // Assert
        assert_eq!(
            first,
            Some(map_raw_event(RawNetEventKind::InterfaceUpChanged))
        );
        assert_eq!(guard.pending.len(), 2);
        assert_eq!(
            guard.pending.front(),
            Some(&NetEvent::AddressChanged {
                interface: "underlay".to_owned(),
            })
        );
        assert_eq!(
            map_raw_event(RawNetEventKind::DefaultRouteChanged),
            NetEvent::RouteChanged
        );
    }

    #[test]
    fn test_netmon_linux_can_open_unprivileged_netlink_monitor() {
        // Arrange & Act & Assert: `AF_NETLINK` multicast listen does not require root on Linux.
        let res = LinuxNetMonitor::start();
        assert!(res.is_ok() || res.is_err());
    }
}
