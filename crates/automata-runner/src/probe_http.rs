use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::cli::InternalProbeHttpArgs;

const LISTENER_LIFETIME: Duration = Duration::from_secs(20);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const READY_BODY: &str = "automata-podman-network-ready\n";

pub async fn serve(args: InternalProbeHttpArgs) -> Result<()> {
    validate_token(&args.token)?;
    let address = SocketAddr::from(([0, 0, 0, 0], args.port));
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind internal readiness listener on {address}"))?;

    timeout(LISTENER_LIFETIME, serve_one(listener, &args.token))
        .await
        .context("internal readiness listener expired")?
}

async fn serve_one(listener: TcpListener, token: &str) -> Result<()> {
    let (mut stream, _) = listener
        .accept()
        .await
        .context("failed to accept readiness connection")?;
    timeout(CONNECTION_TIMEOUT, respond(&mut stream, token))
        .await
        .context("internal readiness connection timed out")?
}

async fn respond(stream: &mut TcpStream, token: &str) -> Result<()> {
    let request = read_request(stream).await?;
    let expected_http_10 = format!("GET /ready/{token} HTTP/1.0");
    let expected_http_11 = format!("GET /ready/{token} HTTP/1.1");
    let ready = request
        .lines()
        .next()
        .is_some_and(|line| line == expected_http_10 || line == expected_http_11);
    let (status, body) = if ready {
        ("200 OK", READY_BODY)
    } else {
        ("404 Not Found", "not found\n")
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write readiness response")?;
    stream
        .shutdown()
        .await
        .context("failed to close readiness response")?;

    if ready {
        Ok(())
    } else {
        bail!("readiness request used an invalid path")
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<String> {
    let mut request = Vec::with_capacity(1024);
    loop {
        let remaining = MAX_REQUEST_BYTES.saturating_sub(request.len());
        if remaining == 0 {
            bail!("readiness request exceeded {MAX_REQUEST_BYTES} bytes");
        }
        let mut buffer = [0_u8; 1024];
        let read_limit = remaining.min(buffer.len());
        let read = stream
            .read(&mut buffer[..read_limit])
            .await
            .context("failed to read readiness request")?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(request).context("readiness request was not UTF-8")
}

fn validate_token(token: &str) -> Result<()> {
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("internal readiness token must be a 32-character hexadecimal value");
    }
    Ok(())
}
