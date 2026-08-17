#![forbid(unsafe_code)]

use std::{env, process::ExitCode};

#[cfg(windows)]
use std::io::Read as _;

// A 16 MiB execution/copy body expands beyond 20 MiB under base64 plus the
// ordered-record envelope. Keep one fixed bounded frame large enough for the
// provider contract without permitting streaming or unbounded allocation.
#[cfg(windows)]
const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("request-v1"))
        || arguments.next().is_some()
    {
        return ExitCode::FAILURE;
    }
    forward_one().map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS)
}

#[cfg(windows)]
fn forward_one() -> Option<()> {
    use std::{fs::OpenOptions, io::Write as _};

    const BROKER_PIPE: &str = r"\\.\pipe\automata-windows-hyperv-broker-v1";
    let request = read_bounded(std::io::stdin().lock())?;
    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(BROKER_PIPE)
        .ok()?;
    let length = u32::try_from(request.len()).ok()?.to_be_bytes();
    pipe.write_all(&length).ok()?;
    pipe.write_all(&request).ok()?;
    pipe.flush().ok()?;
    let mut response_length = [0_u8; 4];
    pipe.read_exact(&mut response_length).ok()?;
    let response_length = usize::try_from(u32::from_be_bytes(response_length)).ok()?;
    if response_length == 0 || response_length > MAX_FRAME_BYTES {
        return None;
    }
    let mut response = vec![0_u8; response_length];
    pipe.read_exact(&mut response).ok()?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&response).ok()?;
    stdout.flush().ok()
}

#[cfg(not(windows))]
fn forward_one() -> Option<()> {
    None
}

#[cfg(windows)]
fn read_bounded(mut reader: impl std::io::Read) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(u64::try_from(MAX_FRAME_BYTES).ok()?.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (!bytes.is_empty() && bytes.len() <= MAX_FRAME_BYTES).then_some(bytes)
}
