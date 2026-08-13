#![forbid(unsafe_code)]

use std::{env, path::PathBuf, process::ExitCode};

#[cfg(target_os = "macos")]
use std::fmt::Write as _;

#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};

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
        "serve-vm" => {
            let Some(socket) = arguments.next().map(PathBuf::from) else {
                return ExitCode::FAILURE;
            };
            let Some(identity_path) = arguments.next().map(PathBuf::from) else {
                return ExitCode::FAILURE;
            };
            let identity = std::fs::read(identity_path)
                .ok()
                .filter(|bytes| !bytes.is_empty() && bytes.len() <= 16 * 1024)
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .filter(valid_vm_identity);
            let Some(identity) = identity else {
                return ExitCode::FAILURE;
            };
            runtime()
                .and_then(|runtime| {
                    runtime
                        .block_on(automata_ci_sandbox_guest::serve_vm(&socket, identity))
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

#[cfg(target_os = "macos")]
fn valid_vm_identity(identity: &automata_ci_sandbox_guest::GuestIdentity) -> bool {
    let executable_digest = env::current_exe()
        .ok()
        .and_then(|path| std::fs::read(path).ok())
        .map(|bytes| {
            Sha256::digest(bytes)
                .iter()
                .fold(String::with_capacity(64), |mut encoded, byte| {
                    write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
                    encoded
                })
        });
    let product_version = command_output("/usr/bin/sw_vers", &["-productVersion"]);
    let build_version = command_output("/usr/bin/sw_vers", &["-buildVersion"]);
    identity.architecture == "arm64"
        && std::env::consts::ARCH == "aarch64"
        && executable_digest.as_deref() == Some(identity.guest_agent_sha256.as_str())
        && product_version.as_deref() == Some(identity.macos_version.as_str())
        && build_version.as_deref() == Some(identity.macos_build.as_str())
        && rustix::process::getuid().as_raw() == identity.job_uid
        && rustix::process::getgid().as_raw() == identity.job_gid
        && process_limit() == Some(identity.process_limit)
}

#[cfg(not(target_os = "macos"))]
fn valid_vm_identity(_identity: &automata_ci_sandbox_guest::GuestIdentity) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .env_clear()
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn process_limit() -> Option<u32> {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nproc);
    (limit.current == limit.maximum)
        .then_some(limit.current)
        .flatten()
        .and_then(|limit| u32::try_from(limit).ok())
}

fn runtime() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
}
