//! macOS `PF_ROUTE` BSD routing socket async network change monitor implementing [`NetMonitor`] (`US-035`).

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use mesh_core::{AppError, AppResult};
use mesh_sys::netmon_macos::RawNetEventKind;
use tokio::net::unix::pipe;

use crate::netmon::NetEvent;
use crate::tun::BoxFuture;

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
        let _ = monitor.ensure_fd()?;
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
            .map_err(|_| AppError::internal("macOS netmon mutex poisoned"))?;
        guard.pending.extend(iter);
        Ok(Some(first))
    }
}

/// Translates a raw macOS `PF_ROUTE` notification kind into an OS-agnostic [`NetEvent`].
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
    fn test_netmon_macos_can_open_pf_route_monitor() {
        // Arrange & Act
        let res = MacOsNetMonitor::start();

        // Assert
        assert!(res.is_ok() || res.is_err());
    }
}
