//! Bounded enrollment HTTP response handling.

use anyhow::{Context as _, Result, bail};
use zeroize::Zeroizing;

pub(super) const MAX_RESPONSE_BYTES: usize = 512 * 1_024;
const MAX_RESPONSE_BYTES_U64: u64 = 512 * 1_024;

pub(super) async fn read_bounded_response(
    mut response: reqwest::Response,
) -> Result<Zeroizing<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES_U64)
    {
        bail!("runner enrollment response exceeded its size limit");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        response
            .content_length()
            .and_then(|size| usize::try_from(size).ok())
            .unwrap_or(0)
            .min(MAX_RESPONSE_BYTES),
    ));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)
        .context("runner enrollment response could not be read")?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > MAX_RESPONSE_BYTES)
        {
            bail!("runner enrollment response exceeded its size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    use super::{MAX_RESPONSE_BYTES, read_bounded_response};

    #[tokio::test]
    async fn chunked_enrollment_response_is_rejected_at_the_streaming_bound() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut request = [0_u8; 1_024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                .await
                .expect("headers");
            let chunk = vec![b'x'; MAX_RESPONSE_BYTES / 2 + 1];
            for _ in 0..2 {
                if stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .is_err()
                    || stream.write_all(&chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("loopback client")
            .get(format!("http://{address}/redeem"))
            .send()
            .await
            .expect("response headers");
        let error = read_bounded_response(response)
            .await
            .expect_err("oversized chunked body must fail");
        assert!(error.to_string().contains("exceeded its size limit"));
        server.await.expect("server task");
    }
}
