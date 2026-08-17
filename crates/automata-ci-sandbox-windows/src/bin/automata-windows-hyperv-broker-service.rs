#![forbid(unsafe_code)]

use std::process::ExitCode;

#[cfg(windows)]
fn main() -> ExitCode {
    windows_main()
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    ExitCode::FAILURE
}

#[cfg(windows)]
fn windows_main() -> ExitCode {
    use std::{env, ffi::OsStr, path::PathBuf, sync::Arc, sync::atomic::AtomicBool};

    use automata_ci_sandbox_windows::{
        install_windows_hyperv_broker_state_root, run_windows_hyperv_broker_service,
    };

    let mut arguments = env::args_os().skip(1);
    let Some(mode) = arguments.next() else {
        return ExitCode::FAILURE;
    };
    let Some(config_path) = arguments.next().map(PathBuf::from) else {
        return ExitCode::FAILURE;
    };
    if arguments.next().is_some() {
        return ExitCode::FAILURE;
    }
    if mode == OsStr::new("console-v1") {
        return run_windows_hyperv_broker_service(&config_path, Arc::new(AtomicBool::new(false)))
            .map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS);
    }
    if mode == OsStr::new("install-root-v1") {
        return install_windows_hyperv_broker_state_root(&config_path)
            .map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS);
    }
    if mode == OsStr::new("service-v1") {
        return service_entry::run(config_path).map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS);
    }
    ExitCode::FAILURE
}

#[cfg(windows)]
mod service_entry {
    use std::{
        ffi::OsString,
        path::PathBuf,
        sync::{
            Arc, OnceLock,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use automata_ci_sandbox_windows::{
        WindowsHyperVBrokerServiceError, run_windows_hyperv_broker_service_with_ready,
    };
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "AutomataWindowsHyperVBroker";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

    pub(super) fn run(config_path: PathBuf) -> windows_service::Result<()> {
        CONFIG_PATH.set(config_path).map_err(|_| {
            windows_service::Error::Winapi(std::io::Error::other("config already set"))
        })?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> windows_service::Result<()> {
        let stop = Arc::new(AtomicBool::new(false));
        let handler_stop = Arc::clone(&stop);
        let handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                handler_stop.store(true, Ordering::Release);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status = service_control_handler::register(SERVICE_NAME, handler)?;
        status.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })?;
        let config_path = CONFIG_PATH.get().cloned();
        let result = config_path.map_or(Err(()), |path| {
            run_windows_hyperv_broker_service_with_ready(&path, stop, || {
                status
                    .set_service_status(ServiceStatus {
                        service_type: SERVICE_TYPE,
                        current_state: ServiceState::Running,
                        controls_accepted: ServiceControlAccept::STOP,
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint: 0,
                        wait_hint: Duration::ZERO,
                        process_id: None,
                    })
                    .map_err(|_| WindowsHyperVBrokerServiceError::Ipc)
            })
            .map_err(|_| ())
        });
        status.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(u32::from(result.is_err())),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        })?;
        Ok(())
    }
}
