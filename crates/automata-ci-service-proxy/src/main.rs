#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("automata-ci-service-proxy requires Linux");

mod config;
mod error;
mod limit;
mod proxy;
mod status;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use error::ProxyError;

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {
        write_sanitized_error("runtime-failed");
    }));
    match run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            write_sanitized_error(error.code());
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), ProxyError> {
    let mappings = config::parse_command_line(arguments)?;
    let mut proxy = proxy::PreparedProxy::prepare(&mappings)?;
    let status = status::encode_startup_status(&proxy.ports()?);
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(status.as_bytes())
        .map_err(|_| ProxyError::Status)?;
    stdout.flush().map_err(|_| ProxyError::Status)?;
    drop(stdout);
    proxy.run()
}

fn write_sanitized_error(code: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(b"automata-ci-service-proxy: ");
    let _ = stderr.write_all(code.as_bytes());
    let _ = stderr.write_all(b"\n");
}
