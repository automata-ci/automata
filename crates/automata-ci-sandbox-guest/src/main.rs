#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        return ExitCode::FAILURE;
    };
    match command.to_string_lossy().as_ref() {
        "install" => {
            let Some(target) = arguments.next().map(PathBuf::from) else {
                return ExitCode::FAILURE;
            };
            let Ok(source) = env::current_exe() else {
                return ExitCode::FAILURE;
            };
            if std::fs::copy(source, target).is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "serve" => {
            let Some(socket) = arguments.next().map(PathBuf::from) else {
                return ExitCode::FAILURE;
            };
            runtime()
                .and_then(|runtime| {
                    runtime
                        .block_on(automata_ci_sandbox_guest::serve(&socket))
                        .ok()
                })
                .map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS)
        }
        "client" => {
            let Some(socket) = arguments.next().map(PathBuf::from) else {
                return ExitCode::FAILURE;
            };
            runtime()
                .and_then(|runtime| {
                    runtime
                        .block_on(automata_ci_sandbox_guest::forward_stdio(&socket))
                        .ok()
                })
                .map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS)
        }
        "probe" => {
            let Some(socket) = arguments.next().map(PathBuf::from) else {
                return ExitCode::FAILURE;
            };
            if automata_ci_sandbox_guest::probe(&socket) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        _ => ExitCode::FAILURE,
    }
}

fn runtime() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
}
