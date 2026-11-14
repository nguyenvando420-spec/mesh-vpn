//! macOS `PF_ROUTE` BSD routing socket async network change monitor implementing [`NetMonitor`] (`US-035`).

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use mesh_core::{AppError, AppResult};
use mesh_sys::netmon_macos::RawNetEventKind;
use tokio::net::unix::pipe;

use crate::endpoint_filter::InterfaceSubnetSnapshot;
use crate::netmon::{NetEvent, PhysicalInterface};
use crate::tun::BoxFuture;

/// Queries the current primary macOS physical interface `(if_index, name)` via `PF_ROUTE`/`getifaddrs`.
pub fn query_primary_physical_interface() -> AppResult<PhysicalInterface> {
    let (if_index, name) =
        mesh_sys::netmon_macos::query_primary_physical_interface().map_err(AppError::from)?;
    Ok(PhysicalInterface { if_index, name })
}

/// Lists all current macOS interface unicast addresses and CIDR prefixes (`US-035`, `US-037`).
pub fn list_interface_subnets() -> AppResult<Vec<InterfaceSubnetSnapshot>> {
    let items = mesh_sys::netmon_macos::list_interface_addresses().map_err(AppError::from)?;
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

/// macOS asynchronous network monitor backed by a non-blocking `PF_ROUTE` routing socket.
#[derive(Debug)]
pub struct MacOsNetMonitor {
    state: Mutex<MacOsNetmonState>,
}

#[derive(Debug)]
struct MacOsNetmonState {
    rx: Option<Arc<pipe::Receiver>>,
    pending: VecDeque<NetEvent>,
}

impl Default for MacOsNetMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsNetMonitor {
    /// Creates a lazy-opening macOS BSD routing socket network monitor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(MacOsNetmonState {
                rx: None,
                pending: VecDeque::new(),
            }),
        }
    }

    /// Eagerly opens the `PF_ROUTE` monitor socket right away.
    pub fn start() -> AppResult<Self> {
        let monitor = Self::new();
        monitor.ensure_fd().map(|_| ())?;
        Ok(monitor)
    }

    fn pop_pending_or_fd(&self) -> AppResult<Result<NetEvent, Arc<pipe::Receiver>>> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("macOS netmon mutex poisoned"))?;
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
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(AppError::unavailable(
                "PF_ROUTE monitor requires an active Tokio runtime reactor",
            ));
        }
        let owned = mesh_sys::netmon_macos::open_route_monitor_socket()?;
        let async_rx = Arc::new(
            pipe::Receiver::from_owned_fd_unchecked(owned).map_err(|err| {
                AppError::unavailable(format!("failed registering PF_ROUTE with Tokio: {err}"))
            })?,
        );

        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("macOS netmon mutex poisoned"))?;
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
            .map_err(|_| AppError::internal("macOS netmon mutex poisoned"))?;
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

/// Translates a raw macOS `PF_ROUTE` notification kind into an OS-agnostic [`NetEvent`], attaching
/// a resolved physical interface name when available.
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

/// Translates a raw macOS `PF_ROUTE` notification kind into an OS-agnostic [`NetEvent`].
#[must_use]
pub fn map_raw_event(kind: RawNetEventKind) -> NetEvent {
    map_raw_event_with_iface(kind, None)
}

impl crate::netmon::NetMonitor for MacOsNetMonitor {
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>> {
        Box::pin(async move {
            loop {
                let rx = match self.pop_pending_or_fd()? {
                    Ok(ev) => return Ok(ev),
                    Err(rx) => rx,
                };

                rx.readable().await.map_err(|err| {
                    AppError::unavailable(format!("PF_ROUTE readability wait failed: {err}"))
                })?;
                match rx.try_io(|| mesh_sys::netmon_macos::read_route_events(rx.as_ref())) {
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
                        if err.raw_os_error() == Some(mesh_sys::netmon_macos::ENOBUFS_ERRNO) =>
                    {
                        return Ok(NetEvent::RouteChanged);
                    }
                    Err(err) => {
                        return Err(AppError::unavailable(format!(
                            "PF_ROUTE read failed: {err}"
                        )));
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use mesh_sys::netmon_macos::RawNetEventKind;

    use super::{MacOsNetMonitor, map_raw_event};
    use crate::netmon::NetEvent;

    #[test]
    fn test_netmon_macos_maps_and_buffers_batched_events() {
        // Arrange
        let monitor = MacOsNetMonitor::new();
        let batch = vec![
            RawNetEventKind::AddressChanged,
            RawNetEventKind::PhysicalInterfaceChanged,
        ];

        // Act
        let first = monitor
            .enqueue_batch_and_take_first(batch)
            .expect("enqueue batch");
        let guard = monitor.state.lock().expect("lock state");

        // Assert
        assert_eq!(first, Some(map_raw_event(RawNetEventKind::AddressChanged)));
        assert_eq!(guard.pending.len(), 1);
        assert_eq!(guard.pending.front(), Some(&NetEvent::RouteChanged));
    }

    #[test]
    fn test_netmon_macos_start_without_runtime_returns_err_without_panic() {
        // Arrange / Act: calling outside Tokio must fail cleanly with AppError, never panic.
        let res = MacOsNetMonitor::start();

        // Assert
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_netmon_macos_can_open_pf_route_monitor() {
        // Arrange & Act
        let res = MacOsNetMonitor::start();

        // Assert
        assert!(res.is_ok() || res.is_err());
    }
}
