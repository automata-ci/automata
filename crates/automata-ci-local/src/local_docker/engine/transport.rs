use std::{collections::BTreeMap, fmt, io, marker::PhantomData, sync::Arc, time::Duration};

use bytes::Bytes;
use http::header::UPGRADE;
use http::{
    Method, Request, StatusCode,
    header::{
        ACCEPT, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, TRANSFER_ENCODING,
    },
};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body as _, Incoming};
use hyper_util::rt::TokioIo;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::ApiVersion;

const REQUEST_BYTES: usize = 512 * 1024;
const ERROR_BYTES: usize = 8 * 1024;
const ERROR_MESSAGE_BYTES: usize = 2 * 1024;
const MAX_RESPONSE_HEADERS: usize = 32;
const MAX_RESPONSE_HEADER_BYTES: usize = 8 * 1024;
const MAX_IN_FLIGHT_REQUESTS: usize = 8;

type RequestBody = Full<Bytes>;

#[derive(Clone)]
pub(super) struct DockerHttpTransport {
    socket: std::path::PathBuf,
    api_prefix: String,
    in_flight: Arc<tokio::sync::Semaphore>,
}

impl fmt::Debug for DockerHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerHttpTransport")
            .field("socket", &"[fixed-relay-socket]")
            .field("api_prefix", &self.api_prefix)
            .finish_non_exhaustive()
    }
}

impl DockerHttpTransport {
    pub(super) fn connect_unix_socket(
        socket: &std::path::Path,
        api: ApiVersion,
    ) -> Result<Self, TransportError> {
        if !socket.is_absolute() {
            return Err(TransportError::InvalidRequest);
        }
        Ok(Self {
            socket: socket.to_owned(),
            api_prefix: format!("/v{}.{}", api.major, api.minor),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
        })
    }

    pub(super) async fn json<T, B>(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<&B>,
        expected: StatusCode,
        response_limit: usize,
    ) -> Result<T, TransportError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let request = self.request(method, path_and_query, body)?;
        let response = self.exchange(request, response_limit).await?;
        if response.status() != expected {
            return Err(error_response(&response));
        }
        require_json(response.headers())?;
        if response.body().len() > response_limit {
            return Err(TransportError::ResponseTooLarge);
        }
        serde_json::from_slice(response.body()).map_err(|_| TransportError::InvalidResponse)
    }

    pub(super) async fn optional_json<T>(
        &self,
        path_and_query: &str,
        response_limit: usize,
    ) -> Result<Option<T>, TransportError>
    where
        T: DeserializeOwned,
    {
        let request = self.request::<()>(Method::GET, path_and_query, None)?;
        let response = self.exchange(request, response_limit).await?;
        match response.status() {
            StatusCode::OK => {
                require_json(response.headers())?;
                if response.body().len() > response_limit {
                    return Err(TransportError::ResponseTooLarge);
                }
                serde_json::from_slice(response.body())
                    .map(Some)
                    .map_err(|_| TransportError::InvalidResponse)
            }
            StatusCode::NOT_FOUND => {
                validate_error(&response)?;
                Ok(None)
            }
            _ => Err(error_response(&response)),
        }
    }

    #[cfg(any(unix, test))]
    pub(super) async fn empty_or_not_found(
        &self,
        method: Method,
        path_and_query: &str,
        expected: StatusCode,
    ) -> Result<(), TransportError> {
        let request = self.request::<()>(method, path_and_query, None)?;
        let response = self.exchange(request, 1).await?;
        if response.status() == StatusCode::NOT_FOUND {
            validate_error(&response)?;
            return Ok(());
        }
        if response.status() != expected {
            return Err(error_response(&response));
        }
        if response.body().is_empty() {
            Ok(())
        } else {
            Err(TransportError::InvalidResponse)
        }
    }

    #[cfg(unix)]
    pub(super) async fn empty(
        &self,
        method: Method,
        path_and_query: &str,
        expected: StatusCode,
    ) -> Result<(), TransportError> {
        let request = self.request::<()>(method, path_and_query, None)?;
        let response = self.exchange(request, 1).await?;
        if response.status() != expected {
            return Err(error_response(&response));
        }
        if response.body().is_empty() {
            Ok(())
        } else {
            Err(TransportError::InvalidResponse)
        }
    }

    #[cfg(unix)]
    pub(super) async fn bytes(
        &self,
        path_and_query: &str,
        expected_content_type: &'static str,
        response_limit: usize,
    ) -> Result<Vec<u8>, TransportError> {
        let request = self.request::<()>(Method::GET, path_and_query, None)?;
        let response = self.exchange(request, response_limit).await?;
        if response.status() != StatusCode::OK {
            return Err(error_response(&response));
        }
        require_content_type(response.headers(), expected_content_type)?;
        Ok(response.body)
    }

    #[cfg(unix)]
    pub(super) async fn empty_bytes(
        &self,
        method: Method,
        path_and_query: &str,
        content_type: &'static str,
        body: &[u8],
        request_limit: usize,
        expected: StatusCode,
    ) -> Result<(), TransportError> {
        if body.len() > request_limit {
            return Err(TransportError::InvalidRequest);
        }
        let request = self.raw_request(method, path_and_query, content_type, body)?;
        let response = self.exchange(request, 1).await?;
        if response.status() != expected {
            return Err(error_response(&response));
        }
        if response.body.is_empty() {
            Ok(())
        } else {
            Err(TransportError::InvalidResponse)
        }
    }

    pub(super) async fn hijack_json<B>(
        &self,
        path_and_query: &str,
        body: &B,
        stdin: &[u8],
        response_limit: usize,
    ) -> Result<Vec<u8>, TransportError>
    where
        B: Serialize + ?Sized,
    {
        let _permit = Arc::clone(&self.in_flight)
            .acquire_owned()
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        let mut request = self.request(Method::POST, path_and_query, Some(body))?;
        request
            .headers_mut()
            .insert(CONNECTION, http::HeaderValue::from_static("Upgrade"));
        request
            .headers_mut()
            .insert(UPGRADE, http::HeaderValue::from_static("tcp"));
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        hijack_on(TokioIo::new(stream), request, stdin, response_limit).await
    }

    fn request<B>(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<&B>,
    ) -> Result<Request<RequestBody>, TransportError>
    where
        B: Serialize + ?Sized,
    {
        if !path_and_query.starts_with('/') || path_and_query.bytes().any(|byte| byte == b'\0') {
            return Err(TransportError::InvalidRequest);
        }
        let uri = format!("{}{path_and_query}", self.api_prefix)
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| TransportError::InvalidRequest)?;
        let bytes = body.map_or_else(|| Ok(Vec::new()), encode_json)?;
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, "localhost")
            .header(ACCEPT, "application/json")
            .header(CONNECTION, "close")
            .header(CONTENT_LENGTH, bytes.len().to_string());
        if body.is_some() {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        request
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|_| TransportError::InvalidRequest)
    }

    fn raw_request(
        &self,
        method: Method,
        path_and_query: &str,
        content_type: &'static str,
        body: &[u8],
    ) -> Result<Request<RequestBody>, TransportError> {
        if !path_and_query.starts_with('/') || path_and_query.bytes().any(|byte| byte == b'\0') {
            return Err(TransportError::InvalidRequest);
        }
        let uri = format!("{}{path_and_query}", self.api_prefix)
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| TransportError::InvalidRequest)?;
        Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, "localhost")
            .header(ACCEPT, "application/json")
            .header(CONNECTION, "close")
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, body.len().to_string())
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|_| TransportError::InvalidRequest)
    }

    async fn exchange(
        &self,
        request: Request<RequestBody>,
        response_limit: usize,
    ) -> Result<WireResponse, TransportError> {
        let _permit = Arc::clone(&self.in_flight)
            .acquire_owned()
            .await
            .map_err(|_| TransportError::RequestFailed)?;

        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        exchange_on(TokioIo::new(stream), request, response_limit).await
    }
}

struct WireResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl WireResponse {
    const fn status(&self) -> StatusCode {
        self.status
    }

    const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        &self.body
    }
}

struct ConnectionDriver(Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>);

impl ConnectionDriver {
    fn spawn<F>(connection: F) -> Self
    where
        F: std::future::Future<Output = Result<(), hyper::Error>> + Send + 'static,
    {
        Self(Some(tokio::spawn(connection)))
    }

    async fn finish(mut self) -> Result<(), TransportError> {
        let result = self.0.as_mut().ok_or(TransportError::RequestFailed)?.await;
        let _completed = self.0.take().ok_or(TransportError::RequestFailed)?;
        result
            .map_err(|_| TransportError::RequestFailed)?
            .map_err(|_| TransportError::RequestFailed)
    }
}

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

async fn exchange_on<T>(
    io: T,
    request: Request<RequestBody>,
    response_limit: usize,
) -> Result<WireResponse, TransportError>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder
        .max_headers(MAX_RESPONSE_HEADERS)
        .max_buf_size(MAX_RESPONSE_HEADER_BYTES);
    let (mut sender, connection) = builder
        .handshake(io)
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    let driver = ConnectionDriver::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    validate_response_headers(response.headers())?;
    let body_limit = if response.status().is_success() {
        response_limit
    } else {
        ERROR_BYTES
    };
    let (parts, body) = response.into_parts();
    let body = collect(body, body_limit).await?;
    driver.finish().await?;
    Ok(WireResponse {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

#[cfg(unix)]
async fn hijack_on<T>(
    io: T,
    request: Request<RequestBody>,
    stdin: &[u8],
    response_limit: usize,
) -> Result<Vec<u8>, TransportError>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut builder = hyper::client::conn::http1::Builder::new();
    builder
        .max_headers(MAX_RESPONSE_HEADERS)
        .max_buf_size(MAX_RESPONSE_HEADER_BYTES);
    let (mut sender, connection) = builder
        .handshake(io)
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    let driver = ConnectionDriver::spawn(connection.with_upgrades());
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    validate_response_headers(response.headers())?;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS
        || !header_contains_token(response.headers(), CONNECTION, "upgrade")
        || !header_contains_token(response.headers(), UPGRADE, "tcp")
    {
        return Err(error_response_from_incoming(response, driver).await);
    }
    let upgraded = hyper::upgrade::on(&mut response)
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    driver.finish().await?;
    let mut stream = TokioIo::new(upgraded);
    stream
        .write_all(stdin)
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    stream
        .shutdown()
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    let mut bytes = Vec::with_capacity(response_limit.min(64 * 1024));
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| TransportError::RequestFailed)?;
        if read == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(read)
            .is_none_or(|length| length > response_limit)
        {
            return Err(TransportError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn header_contains_token(
    headers: &HeaderMap,
    name: http::header::HeaderName,
    expected: &str,
) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

#[cfg(unix)]
async fn error_response_from_incoming(
    response: http::Response<Incoming>,
    driver: ConnectionDriver,
) -> TransportError {
    let (parts, body) = response.into_parts();
    let body = match collect(body, ERROR_BYTES).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    if driver.finish().await.is_err() {
        return TransportError::RequestFailed;
    }
    error_response(&WireResponse {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

fn encode_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, TransportError> {
    let mut writer = BoundedWriter::new(REQUEST_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|_| TransportError::InvalidRequest)?;
    Ok(writer.finish())
}

async fn collect(mut body: Incoming, limit: usize) -> Result<Vec<u8>, TransportError> {
    if body
        .size_hint()
        .upper()
        .is_some_and(|length| length > u64::try_from(limit).expect("body limit fits in u64"))
    {
        return Err(TransportError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| TransportError::RequestFailed)?;
        let data = frame
            .into_data()
            .map_err(|_| TransportError::InvalidResponse)?;
        if bytes
            .len()
            .checked_add(data.len())
            .is_none_or(|length| length > limit)
        {
            return Err(TransportError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&data);
    }
    Ok(bytes)
}

fn require_json(headers: &http::HeaderMap) -> Result<(), TransportError> {
    require_content_type(headers, "application/json")
}

fn require_content_type(
    headers: &http::HeaderMap,
    expected: &'static str,
) -> Result<(), TransportError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let content_type = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(TransportError::InvalidResponse)?;
    if values.next().is_none()
        && content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
    {
        Ok(())
    } else {
        Err(TransportError::InvalidResponse)
    }
}

fn error_response(response: &WireResponse) -> TransportError {
    let status = response.status();
    match validate_error(response) {
        Ok(()) => TransportError::Rejected(status),
        Err(error) => error,
    }
}

fn validate_error(response: &WireResponse) -> Result<(), TransportError> {
    require_json(response.headers())?;
    let error: DockerError =
        serde_json::from_slice(response.body()).map_err(|_| TransportError::InvalidResponse)?;
    if error.message.is_empty() || error.message.len() > ERROR_MESSAGE_BYTES {
        return Err(TransportError::InvalidResponse);
    }
    Ok(())
}

fn validate_response_headers(headers: &HeaderMap) -> Result<(), TransportError> {
    if headers.len() > MAX_RESPONSE_HEADERS {
        return Err(TransportError::InvalidResponse);
    }
    let header_bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())?
            .checked_add(value.as_bytes().len())?
            .checked_add(4)
    });
    if header_bytes.is_none_or(|bytes| bytes > MAX_RESPONSE_HEADER_BYTES) {
        return Err(TransportError::InvalidResponse);
    }
    let content_lengths = headers.get_all(CONTENT_LENGTH).iter().count();
    let transfer_encodings = headers.get_all(TRANSFER_ENCODING).iter().count();
    if content_lengths > 1
        || transfer_encodings > 1
        || content_lengths != 0 && transfer_encodings != 0
        || transfer_encodings == 1
            && !headers
                .get(TRANSFER_ENCODING)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        return Err(TransportError::InvalidResponse);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct DockerError {
    message: String,
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.limit)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bounded Docker request exceeded its limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransportError {
    InvalidRequest,
    RequestFailed,
    Rejected(StatusCode),
    ResponseTooLarge,
    InvalidResponse,
}

pub(super) async fn deadline<T>(
    duration: Duration,
    future: impl std::future::Future<Output = Result<T, TransportError>>,
) -> Result<T, TransportError> {
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| TransportError::RequestFailed)?
}

pub(super) fn encode_path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BoundedVec<T, const LIMIT: usize>(Vec<T>);

impl<T, const LIMIT: usize> BoundedVec<T, LIMIT> {
    pub(super) fn into_inner(self) -> Vec<T> {
        self.0
    }

    #[cfg(unix)]
    pub(super) fn as_slice(&self) -> &[T] {
        &self.0
    }

    #[cfg(unix)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de, T, const LIMIT: usize> Deserialize<'de> for BoundedVec<T, LIMIT>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedVecVisitor<T, const LIMIT: usize>(PhantomData<T>);

        impl<'de, T, const LIMIT: usize> Visitor<'de> for BoundedVecVisitor<T, LIMIT>
        where
            T: Deserialize<'de>,
        {
            type Value = BoundedVec<T, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array with at most {LIMIT} entries")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(LIMIT));
                while values.len() < LIMIT {
                    let Some(value) = sequence.next_element()? else {
                        return Ok(BoundedVec(values));
                    };
                    values.push(value);
                }
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("array cardinality exceeded"));
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVecVisitor::<T, LIMIT>(PhantomData))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BoundedMap<K, V, const LIMIT: usize>(BTreeMap<K, V>);

impl<K: Ord, V, const LIMIT: usize> BoundedMap<K, V, LIMIT> {
    pub(super) fn into_inner(self) -> BTreeMap<K, V> {
        self.0
    }

    #[cfg(unix)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de, K, V, const LIMIT: usize> Deserialize<'de> for BoundedMap<K, V, LIMIT>
where
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedMapVisitor<K, V, const LIMIT: usize>(PhantomData<(K, V)>);

        impl<'de, K, V, const LIMIT: usize> Visitor<'de> for BoundedMapVisitor<K, V, LIMIT>
        where
            K: Deserialize<'de> + Ord,
            V: Deserialize<'de>,
        {
            type Value = BoundedMap<K, V, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an object with at most {LIMIT} entries")
            }

            fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some(key) = object.next_key()? {
                    if values.len() == LIMIT {
                        let _: IgnoredAny = object.next_value()?;
                        return Err(A::Error::custom("object cardinality exceeded"));
                    }
                    let value = object.next_value()?;
                    if values.insert(key, value).is_some() {
                        return Err(A::Error::custom("duplicate object key"));
                    }
                }
                Ok(BoundedMap(values))
            }
        }

        deserializer.deserialize_map(BoundedMapVisitor::<K, V, LIMIT>(PhantomData))
    }
}
