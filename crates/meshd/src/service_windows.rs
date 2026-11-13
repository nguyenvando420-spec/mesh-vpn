//! Windows Service Control Manager (`windows-service`) & `PowerEvent` bridge (`US-036`, `WP-S1-05`).

use std::sync::Mutex;
use std::time::Duration;

use tokio::runtime::Builder;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use windows_service::service::{
    PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

use mesh_core::clock::SystemClock;
use mesh_core::{AppError, AppResult};
use mesh_net::netmon_windows::WindowsPowerEvent;

use crate::config::DaemonRuntimePaths;
use crate::roaming_loop::{WindowsPowerSender, create_platform_net_monitor};
use crate::supervisor::{DaemonSupervisor, ProductionPlatformAdapters};

/// Windows service name registered with SCM.
pub(crate) const WINDOWS_SERVICE_NAME: &str = "MeshVpnAgent";

/// Win32 `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (`1063`): binary was started from a console,
/// not launched by Windows SCM.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
const STOP_PENDING_WAIT_HINT: Duration = Duration::from_secs(5);
const START_PENDING_WAIT_HINT: Duration = Duration::from_secs(5);

static SCM_PATHS: Mutex<Option<DaemonRuntimePaths>> = Mutex::new(None);
static SCM_RUN_RESULT: Mutex<Option<AppResult<()>>> = Mutex::new(None);

/// Summary label for Windows SCM subsystem initialization.
#[must_use]
pub(crate) fn status_label() -> String {
    format!("windows_scm:{WINDOWS_SERVICE_NAME}")
}

/// Outcome of attempting to attach the current process to Windows Service Control Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceDispatchOutcome {
    /// Executed full service lifecycle under SCM until Stop/Shutdown completed.
    RanAsService,
    /// Process was started interactively (console / `launch`-like test), not under SCM (`1063`).
    NotLaunchedByScm,
}

/// Attempts to register and run `meshd` as a Windows SCM service.
///
/// Falls back cleanly with [`ServiceDispatchOutcome::NotLaunchedByScm`] when invoked directly
/// from a user console instead of SCM.
pub(crate) fn try_run_as_service(paths: &DaemonRuntimePaths) -> AppResult<ServiceDispatchOutcome> {
    if let Ok(mut guard) = SCM_PATHS.lock() {
        *guard = Some(paths.clone());
    }
    if let Ok(mut guard) = SCM_RUN_RESULT.lock() {
        *guard = None;
    }

    match service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main) {
        Ok(()) => {
            let service_outcome = SCM_RUN_RESULT
                .lock()
                .map_err(|err| AppError::internal(format!("SCM result lock poisoned: {err}")))?
                .take()
                .unwrap_or(Ok(()));
            service_outcome?;
            Ok(ServiceDispatchOutcome::RanAsService)
        }
        Err(err) if is_not_service_process_error(&err) => {
            Ok(ServiceDispatchOutcome::NotLaunchedByScm)
        }
        Err(err) => Err(AppError::internal(format!(
            "failed starting Windows SCM dispatcher: {err}"
        ))),
    }
}

/// Runs `meshd` strictly as a Windows SCM service and fails closed if started outside SCM.
pub(crate) fn run_as_service(paths: &DaemonRuntimePaths) -> AppResult<()> {
    match try_run_as_service(paths)? {
        ServiceDispatchOutcome::RanAsService => Ok(()),
        ServiceDispatchOutcome::NotLaunchedByScm => Err(AppError::invalid_argument(
            "meshd --service must be launched by Windows Service Control Manager (SCM)",
        )),
    }
}

/// Maps Windows SCM `PowerEventParam` notifications into `mesh-net`'s `WindowsPowerEvent`.
#[must_use]
pub(crate) fn map_power_event(param: &PowerEventParam) -> Option<WindowsPowerEvent> {
    match param {
        PowerEventParam::Suspend => Some(WindowsPowerEvent::Suspend),
        PowerEventParam::ResumeAutomatic => Some(WindowsPowerEvent::ResumeAutomatic),
        PowerEventParam::ResumeSuspend | PowerEventParam::ResumeCritical => {
            Some(WindowsPowerEvent::ResumeSuspend)
        }
        PowerEventParam::PowerStatusChange
        | PowerEventParam::PowerSettingChange(_)
        | PowerEventParam::BatteryLow
        | PowerEventParam::OemEvent
        | PowerEventParam::QuerySuspend
        | PowerEventParam::QuerySuspendFailed => None,
        _ => None,
    }
}

/// Translates an incoming Windows SCM control event into daemon shutdown / wake signals.
#[must_use]
pub(crate) fn handle_control_event(
    control: &ServiceControl,
    shutdown: &CancellationToken,
    power_tx: Option<&WindowsPowerSender>,
) -> ServiceControlHandlerResult {
    match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            info!(
                component = "meshd.service_windows",
                event = "scm_stop_requested",
                "Windows SCM requested service stop; triggering <= 5 s graceful shutdown"
            );
            shutdown.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::PowerEvent(param) => {
            if let Some(power_ev) = map_power_event(param) {
                if matches!(
                    power_ev,
                    WindowsPowerEvent::ResumeAutomatic | WindowsPowerEvent::ResumeSuspend
                ) {
                    info!(
                        component = "meshd.service_windows",
                        event = "scm_power_resume_received",
                        power_event = ?power_ev,
                        "Windows SCM reported system resume from sleep/hibernate"
                    );
                }
                if let Some(tx) = power_tx
                    && let Err(err) = tx.try_send(power_ev)
                {
                    warn!(
                        component = "meshd.service_windows",
                        event = "scm_power_event_dropped",
                        error = %err,
                        "failed forwarding Windows PowerEvent to monitor channel"
                    );
                }
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Continue
        | ServiceControl::NetBindAdd
        | ServiceControl::NetBindDisable
        | ServiceControl::NetBindEnable
        | ServiceControl::NetBindRemove
        | ServiceControl::ParamChange
        | ServiceControl::Pause
        | ServiceControl::Preshutdown
        | ServiceControl::HardwareProfileChange(_)
        | ServiceControl::SessionChange(_)
        | ServiceControl::TimeChange
        | ServiceControl::UserEvent(_) => ServiceControlHandlerResult::NotImplemented,
        _ => ServiceControlHandlerResult::NotImplemented,
    }
}

/// Pure safe C-ABI entry invoked by Windows SCM without invoking `unsafe` macro wrappers.
extern "system" fn ffi_service_main(_num_args: u32, _args: *mut *mut u16) {
    let paths = SCM_PATHS
        .lock()
        .ok()
        .and_then(|mut guard| guard.take())
        .unwrap_or_else(DaemonRuntimePaths::system_default);
    let result = run_scm_service(paths);
    if let Err(ref err) = result {
        error!(
            component = "meshd.service_windows",
            event = "scm_service_failed",
            error = %err,
            "Windows service exited with error"
        );
    }
    if let Ok(mut guard) = SCM_RUN_RESULT.lock() {
        *guard = Some(result);
    }
}

fn run_scm_service(paths: DaemonRuntimePaths) -> AppResult<()> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()
        .map_err(|err| AppError::internal(format!("failed building Tokio runtime: {err}")))?;

    let root_shutdown = CancellationToken::new();
    let (monitor, power_tx) = create_platform_net_monitor();

    let handler_shutdown = root_shutdown.clone();
    let handler_power = power_tx;
    let status_handle =
        service_control_handler::register(WINDOWS_SERVICE_NAME, move |control_event| {
            handle_control_event(&control_event, &handler_shutdown, handler_power.as_ref())
        })
        .map_err(|err| {
            AppError::internal(format!("failed registering SCM control handler: {err}"))
        })?;

    report_scm_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        START_PENDING_WAIT_HINT,
    );

    let adapters =
        std::sync::Arc::new(ProductionPlatformAdapters::new(paths.wintun_sha256.clone()));
    let supervisor =
        match DaemonSupervisor::boot(paths, std::sync::Arc::new(SystemClock::new()), adapters) {
            Ok(sup) => sup,
            Err(err) => {
                report_scm_status(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(1),
                    Duration::ZERO,
                );
                return Err(err);
            }
        };

    status_handle
        .set_service_status(make_service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::POWER_EVENT,
            ServiceExitCode::Win32(0),
            Duration::ZERO,
        ))
        .map_err(|err| AppError::internal(format!("failed reporting Running state: {err}")))?;

    let run_res = runtime.block_on(supervisor.run(monitor, root_shutdown));

    report_scm_status(
        &status_handle,
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
        STOP_PENDING_WAIT_HINT,
    );

    let exit_code = if run_res.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    report_scm_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::ZERO,
    );

    run_res
}

fn report_scm_status(
    status_handle: &ServiceStatusHandle,
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) {
    if let Err(err) = status_handle.set_service_status(make_service_status(
        current_state,
        controls_accepted,
        exit_code,
        wait_hint,
    )) {
        warn!(
            component = "meshd.service_windows",
            event = "scm_status_report_failed",
            error = %err,
            "failed reporting Windows service status transition"
        );
    }
}

fn make_service_status(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}

fn is_not_service_process_error(err: &windows_service::Error) -> bool {
    matches!(
        err,
        windows_service::Error::Winapi(io_err)
            if io_err.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
    )
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;
    use windows_service::service::{PowerEventParam, ServiceControl};
    use windows_service::service_control_handler::ServiceControlHandlerResult;

    use mesh_net::netmon_windows::WindowsPowerEvent;

    use super::{WINDOWS_SERVICE_NAME, handle_control_event, map_power_event, status_label};

    #[test]
    fn test_windows_scm_power_events_map_and_trigger_handlers() {
        // Arrange
        let (tx, mut rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();

        // Act
        assert_eq!(
            map_power_event(&PowerEventParam::Suspend),
            Some(WindowsPowerEvent::Suspend)
        );
        assert_eq!(
            map_power_event(&PowerEventParam::ResumeAutomatic),
            Some(WindowsPowerEvent::ResumeAutomatic)
        );
        assert_eq!(
            map_power_event(&PowerEventParam::ResumeSuspend),
            Some(WindowsPowerEvent::ResumeSuspend)
        );
        assert_eq!(map_power_event(&PowerEventParam::BatteryLow), None);

        let resume_res = handle_control_event(
            &ServiceControl::PowerEvent(PowerEventParam::ResumeAutomatic),
            &shutdown,
            Some(&tx),
        );
        let stop_res = handle_control_event(&ServiceControl::Stop, &shutdown, Some(&tx));

        // Assert
        assert_eq!(WINDOWS_SERVICE_NAME, "MeshVpnAgent");
        assert!(status_label().contains("MeshVpnAgent"));
        assert!(matches!(resume_res, ServiceControlHandlerResult::NoError));
        assert_eq!(rx.try_recv().ok(), Some(WindowsPowerEvent::ResumeAutomatic));
        assert!(matches!(stop_res, ServiceControlHandlerResult::NoError));
        assert!(shutdown.is_cancelled());
    }
}
