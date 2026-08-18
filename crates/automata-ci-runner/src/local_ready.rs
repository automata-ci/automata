//! Fixed loopback-only readiness check for the sealed local runner service.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    time::Duration,
};

use anyhow::{Result, bail};
use automata_ci_local::{
    LOCAL_RUNNER_READY_LISTEN as LISTEN,
    LOCAL_RUNNER_READY_MAXIMUM_RESPONSE_BYTES as MAXIMUM_RESPONSE_BYTES, LOCAL_RUNNER_READY_METRIC,
    LOCAL_RUNNER_READY_PATH, LOCAL_RUNNER_READY_TIMEOUT_SECONDS as TIMEOUT_SECONDS,
    LOCAL_RUNNER_SESSION_CONNECTED_METRIC,
};

const TIMEOUT: Duration = Duration::from_secs(TIMEOUT_SECONDS);

pub(crate) fn check(config_path: &std::path::Path) -> Result<()> {
    let config = crate::product::RunnerProductConfig::load(config_path)?;
    crate::enrollment::observe_current_custody(&config)?;
    let address = LISTEN.parse()?;
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let request = format!(
        "GET {LOCAL_RUNNER_READY_PATH} HTTP/1.1\r\nHost: {LISTEN}\r\nAccept: application/openmetrics-text; version=1.0.0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream
        .take(u64::try_from(MAXIMUM_RESPONSE_BYTES + 1).expect("response bound fits u64"))
        .read_to_end(&mut response)?;
    validate_response(&response)
}

fn validate_response(response: &[u8]) -> Result<()> {
    if response.is_empty() || response.len() > MAXIMUM_RESPONSE_BYTES {
        bail!("local runner readiness response is outside its fixed bound");
    }
    let Some(separator) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        bail!("local runner readiness response has no HTTP header boundary");
    };
    let (head, body_with_boundary) = response.split_at(separator);
    let body = &body_with_boundary[4..];
    if !head.starts_with(b"HTTP/1.1 200 ") || !body.ends_with(b"# EOF\n") {
        bail!("local runner readiness response is not a complete OpenMetrics success");
    }
    let mut ready = 0_u8;
    let mut connected = 0_u8;
    for line in body.split(|byte| *byte == b'\n') {
        if line == LOCAL_RUNNER_READY_METRIC.as_bytes() {
            ready = ready.saturating_add(1);
        } else if line == LOCAL_RUNNER_SESSION_CONNECTED_METRIC.as_bytes() {
            connected = connected.saturating_add(1);
        } else if line.starts_with(b"automata_ci_runner_ready ")
            || line.starts_with(b"automata_ci_runner_session_connected ")
        {
            bail!("local runner readiness metric has a noncanonical value");
        }
    }
    if ready != 1 || connected != 1 {
        bail!("local runner is not both admitted and connected");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_response;

    fn response(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\ncontent-type: application/openmetrics-text\r\n\r\n{body}")
            .into_bytes()
    }

    #[test]
    fn readiness_requires_one_exact_ready_and_connected_sample() {
        validate_response(&response(
            "# TYPE automata_ci_runner_ready gauge\nautomata_ci_runner_ready 1\n# TYPE automata_ci_runner_session_connected gauge\nautomata_ci_runner_session_connected 1\n# EOF\n",
        ))
        .unwrap();

        for body in [
            "automata_ci_runner_ready 0\nautomata_ci_runner_session_connected 1\n# EOF\n",
            "automata_ci_runner_ready 1\nautomata_ci_runner_session_connected 0\n# EOF\n",
            "automata_ci_runner_ready 1\nautomata_ci_runner_ready 1\nautomata_ci_runner_session_connected 1\n# EOF\n",
            "automata_ci_runner_ready 1\n# EOF\n",
        ] {
            assert!(validate_response(&response(body)).is_err());
        }
    }
}
