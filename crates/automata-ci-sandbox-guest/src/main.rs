#![forbid(unsafe_code)]

use std::{env, ffi::OsString, future::Future, path::PathBuf, process::ExitCode};

#[cfg(target_os = "macos")]
use std::fmt::Write as _;

#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(command) = arguments.next() else {
        return ExitCode::FAILURE;
    };
    dispatch(&command.to_string_lossy(), &mut arguments)
}

fn dispatch(command: &str, arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    match command {
        "install" => install(arguments),
        "serve" => serve(arguments),
        #[cfg(target_os = "linux")]
        "serve-local" => serve_local(arguments),
        #[cfg(target_os = "linux")]
        "bootstrap-local-client" => bootstrap_local_client(arguments),
        #[cfg(target_os = "linux")]
        "seal-local-client" => seal_local_client(arguments),
        "serve-vm" => serve_vm(arguments),
        "client" => client(arguments),
        #[cfg(target_os = "linux")]
        "local-client" => local_client(arguments),
        "stdio-once" => stdio_once(arguments),
        "keepalive" => keepalive(arguments),
        "probe" => probe(arguments),
        _ => ExitCode::FAILURE,
    }
}

fn install(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let Some(target) = path_argument(arguments) else {
        return ExitCode::FAILURE;
    };
    success(env::current_exe().is_ok_and(|source| std::fs::copy(source, target).is_ok()))
}

fn serve(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let Some(socket) = path_argument(arguments) else {
        return ExitCode::FAILURE;
    };
    run_future(automata_ci_sandbox_guest::serve(&socket))
}

#[cfg(target_os = "linux")]
fn serve_local(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    no_argument_future(arguments, automata_ci_sandbox_guest::serve_local_broker())
}

#[cfg(target_os = "linux")]
fn bootstrap_local_client(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    no_argument_future(
        arguments,
        automata_ci_sandbox_guest::bootstrap_local_client(),
    )
}

#[cfg(target_os = "linux")]
fn seal_local_client(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    no_argument_future(arguments, automata_ci_sandbox_guest::seal_local_client())
}

fn serve_vm(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let Some(socket) = arguments.next().map(PathBuf::from) else {
        return ExitCode::FAILURE;
    };
    let Some(identity_path) = path_argument(arguments) else {
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
    run_future(automata_ci_sandbox_guest::serve_vm(&socket, identity))
}

fn client(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let Some(socket) = path_argument(arguments) else {
        return ExitCode::FAILURE;
    };
    run_future(automata_ci_sandbox_guest::forward_stdio(&socket))
}

#[cfg(target_os = "linux")]
fn local_client(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    no_argument_future(arguments, automata_ci_sandbox_guest::forward_local_stdio())
}

fn stdio_once(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let _ = arguments;
    run_future(automata_ci_sandbox_guest::serve_stdio_once())
}

fn keepalive(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let _ = arguments;
    loop {
        std::thread::park();
    }
}

fn probe(arguments: &mut impl Iterator<Item = OsString>) -> ExitCode {
    let Some(socket) = path_argument(arguments) else {
        return ExitCode::FAILURE;
    };
    success(automata_ci_sandbox_guest::probe(&socket))
}

fn path_argument(arguments: &mut impl Iterator<Item = OsString>) -> Option<PathBuf> {
    arguments.next().map(PathBuf::from)
}

#[cfg(target_os = "linux")]
fn no_argument_future<F, E>(arguments: &mut impl Iterator<Item = OsString>, future: F) -> ExitCode
where
    F: Future<Output = Result<(), E>>,
{
    if arguments.next().is_some() {
        return ExitCode::FAILURE;
    }
    run_future(future)
}

fn run_future<F, E>(future: F) -> ExitCode
where
    F: Future<Output = Result<(), E>>,
{
    success(runtime().is_some_and(|runtime| runtime.block_on(future).is_ok()))
}

const fn success(success: bool) -> ExitCode {
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
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
