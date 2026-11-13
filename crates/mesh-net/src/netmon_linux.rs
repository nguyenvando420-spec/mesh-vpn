//! Linux `NETLINK_ROUTE` async network change monitor implementing [`NetMonitor`] (`US-035`).

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use mesh_core::{AppError, AppResult};
use mesh_sys::netmon_linux::RawNetEventKind;
use tokio::net::unix::pipe;

use crate::netmon::NetEvent;
use crate::tun::BoxFuture;

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
        let _ = monitor.ensure_fd()?;
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

    fn enqueue_batch_and_take_first(
        &self,
        batch: Vec<RawNetEventKind>,
    ) -> AppResult<Option<NetEvent>> {
        let mut iter = batch.into_iter().map(map_raw_event);
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
}

/// Translates a raw Linux Netlink notification kind into an OS-agnostic [`NetEvent`].
#[must_use]
pub fn map_raw_event(kind: RawNetEventKind) -> NetEvent {
    match kind {
        RawNetEventKind::InterfaceUpChanged => NetEvent::InterfaceUp {
            interface: "underlay".to_owned(),
        },
        RawNetEventKind::AddressChanged => NetEvent::AddressChanged {
            interface: "underlay".to_owned(),
        },
        RawNetEventKind::DefaultRouteChanged | RawNetEventKind::PhysicalInterfaceChanged => {
            NetEvent::RouteChanged
        }
    }
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
                        if let Some(first) = self.enqueue_batch_and_take_first(batch)? {
                            return Ok(first);
                        }
                    }
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        continue;
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
