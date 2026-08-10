use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};

use super::ProbeCancellation;

const EXPECTED_BODY: &str = "automata-podman-network-ready\n";
const MAX_RESPONSE_BYTES: u64 = 16 * 1024;
const RETRY_INTERVAL: Duration = Duration::from_millis(100);
const CONNECTION_TIMEOUT: Duration = Duration::from_millis(500);

/// Adapter for verifying a loopback-only probe-container readiness response.
pub trait ReadinessProbe: Send + Sync {
    /// Waits for the isolated readiness endpoint to respond correctly.
    ///
    /// # Errors
    ///
    /// Returns a bounded diagnostic if the endpoint is not reachable before
    /// the deadline or returns an unexpected response.
    fn wait_until_ready(
        &self,
        address: SocketAddr,
        token: &str,
        timeout: Duration,
        cancellation: &ProbeCancellation,
    ) -> Result<(), String>;
}

/// Production readiness adapter using bounded HTTP/1.1 over a loopback TCP socket.
///
/// It requires the exact opaque-token path, status line, and response body and
/// rejects responses over 16 KiB.
#[derive(Debug, Default)]
pub struct SystemReadinessProbe;

impl ReadinessProbe for SystemReadinessProbe {
    fn wait_until_ready(
        &self,
        address: SocketAddr,
        token: &str,
        timeout: Duration,
        cancellation: &ProbeCancellation,
    ) -> Result<(), String> {
        if !address.ip().is_loopback() {
            return Err(format!("refusing non-loopback readiness address {address}"));
        }

        let deadline = Instant::now() + timeout;
        let mut last_error = "readiness endpoint was not attempted".to_owned();
        while Instant::now() < deadline {
            if cancellation.is_cancelled() {
                return Err("shutdown was requested during readiness verification".to_owned());
            }
            match check_once(address, token) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = error,
            }
            if cancellation.is_cancelled() {
                return Err("shutdown was requested during readiness verification".to_owned());
            }
            thread::sleep(RETRY_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
        Err(last_error)
    }
}

fn check_once(address: SocketAddr, token: &str) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&address, CONNECTION_TIMEOUT)
        .map_err(|error| format!("failed to connect to {address}: {error}"))?;
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .map_err(|error| format!("failed to set readiness read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(CONNECTION_TIMEOUT))
        .map_err(|error| format!("failed to set readiness write timeout: {error}"))?;

    let request =
        format!("GET /ready/{token} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to write readiness request: {error}"))?;

    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|error| format!("failed to read readiness response: {error}"))?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("readiness response exceeded 16384 bytes".to_owned());
    }
    let response = String::from_utf8(response)
        .map_err(|_| "readiness response was not valid UTF-8".to_owned())?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "readiness response was not valid HTTP".to_owned())?;
    let status_ok = headers
        .lines()
        .next()
        .is_some_and(|line| line == "HTTP/1.1 200 OK");
    if !status_ok {
        return Err("readiness endpoint did not return HTTP 200".to_owned());
    }
    if body != EXPECTED_BODY {
        return Err("readiness endpoint returned an unexpected body".to_owned());
    }
    Ok(())
}
