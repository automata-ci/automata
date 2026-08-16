use std::{collections::BTreeMap, fmt, io, marker::PhantomData, sync::Arc, time::Duration};

use bytes::Bytes;
#[cfg(unix)]
use http::header::UPGRADE;
use http::{
    Method, Request, StatusCode,
    header::{
        ACCEPT, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, TRANSFER_ENCODING,
    },
};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body as _, Incoming};
#[cfg(any(unix, windows))]
use hyper_util::rt::TokioIo;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::{ApiVersion, DockerConnection, EngineEndpoint};

const REQUEST_BYTES: usize = 512 * 1024;
const ERROR_BYTES: usize = 8 * 1024;
const ERROR_MESSAGE_BYTES: usize = 2 * 1024;
const MAX_RESPONSE_HEADERS: usize = 32;
const MAX_RESPONSE_HEADER_BYTES: usize = 8 * 1024;
const MAX_IN_FLIGHT_REQUESTS: usize = 8;

type RequestBody = Full<Bytes>;

#[derive(Clone)]
pub(super) struct DockerHttpTransport {
    endpoint: EndpointAddress,
    api_prefix: String,
    in_flight: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
enum EndpointAddress {
    #[cfg(unix)]
    Unix(std::path::PathBuf),
    #[cfg(windows)]
    NamedPipe(String),
}

impl fmt::Debug for DockerHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DockerHttpTransport")
            .field("endpoint", &"[validated-local-endpoint]")
            .field("api_prefix", &self.api_prefix)
            .finish_non_exhaustive()
    }
}

impl DockerHttpTransport {
    pub(super) fn connect(
        connection: &DockerConnection,
        api: ApiVersion,
    ) -> Result<Self, TransportError> {
        let endpoint = endpoint_address(connection)?;
        Ok(Self {
            endpoint,
            api_prefix: format!("/v{}.{}", api.major, api.minor),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
        })
    }

    #[cfg(unix)]
    pub(super) fn connect_unix_socket(
        socket: &std::path::Path,
        api: ApiVersion,
    ) -> Result<Self, TransportError> {
        if !socket.is_absolute() {
            return Err(TransportError::InvalidRequest);
        }
        Ok(Self {
            endpoint: EndpointAddress::Unix(socket.to_owned()),
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

    #[cfg(unix)]
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
        let EndpointAddress::Unix(socket) = &self.endpoint;
        let stream = tokio::net::UnixStream::connect(socket)
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

    #[cfg(unix)]
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

        #[cfg(unix)]
        {
            let EndpointAddress::Unix(socket) = &self.endpoint;
            let stream = tokio::net::UnixStream::connect(socket)
                .await
                .map_err(|_| TransportError::RequestFailed)?;
            exchange_on(TokioIo::new(stream), request, response_limit).await
        }

        #[cfg(windows)]
        {
            let EndpointAddress::NamedPipe(path) = &self.endpoint;
            let stream = open_named_pipe_once(path).map_err(|_| TransportError::RequestFailed)?;
            exchange_on(TokioIo::new(stream), request, response_limit).await
        }
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

#[cfg(unix)]
fn endpoint_address(connection: &DockerConnection) -> Result<EndpointAddress, TransportError> {
    if connection.endpoint() != EngineEndpoint::UnixSocket {
        return Err(TransportError::InvalidRequest);
    }
    let path = connection
        .host()
        .strip_prefix("unix://")
        .ok_or(TransportError::InvalidRequest)?;
    Ok(EndpointAddress::Unix(path.into()))
}

#[cfg(windows)]
fn endpoint_address(connection: &DockerConnection) -> Result<EndpointAddress, TransportError> {
    if connection.endpoint() != EngineEndpoint::WindowsNamedPipe {
        return Err(TransportError::InvalidRequest);
    }
    Ok(EndpointAddress::NamedPipe(named_pipe_path(
        connection.host(),
    )?))
}

#[cfg(windows)]
fn open_named_pipe_once(
    path: &str,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(path)
}

#[cfg(any(windows, test))]
fn named_pipe_path(host: &str) -> Result<String, TransportError> {
    let name = host
        .strip_prefix("npipe:////./pipe/")
        .filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        .ok_or(TransportError::InvalidRequest)?;
    Ok(format!(r"\\.\pipe\{name}"))
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

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use std::time::Duration;

    use serde::Serialize;

    use super::{
        BoundedMap, BoundedVec, REQUEST_BYTES, TransportError, encode_json, encode_path_component,
        named_pipe_path,
    };
    #[cfg(unix)]
    use super::{ERROR_BYTES, MAX_IN_FLIGHT_REQUESTS, MAX_RESPONSE_HEADERS, deadline};

    #[test]
    fn path_components_are_encoded_without_query_or_path_injection() {
        assert_eq!(
            encode_path_component("name/with?filters={\"x\":1}&nul=\0"),
            "name%2Fwith%3Ffilters%3D%7B%22x%22%3A1%7D%26nul%3D%00"
        );
        assert_eq!(encode_path_component("AZaz09-._~"), "AZaz09-._~");
    }

    #[test]
    fn named_pipe_endpoint_has_one_canonical_unescaped_mapping() {
        assert_eq!(
            named_pipe_path("npipe:////./pipe/docker_engine"),
            Ok(r"\\.\pipe\docker_engine".to_owned())
        );
        for invalid in [
            "npipe:////./pipe/",
            "npipe:////./pipe/other/pipe",
            "npipe:////./pipe/%2e%2e",
            "npipe://./pipe/docker_engine",
        ] {
            assert_eq!(
                named_pipe_path(invalid),
                Err(TransportError::InvalidRequest)
            );
        }
    }

    #[test]
    fn bounded_arrays_reject_the_first_excess_entry() {
        type Two = BoundedVec<u8, 2>;
        assert_eq!(
            serde_json::from_str::<Two>("[1,2]")
                .expect("at-limit array")
                .into_inner(),
            vec![1, 2]
        );
        assert!(serde_json::from_str::<Two>("[1,2,3]").is_err());
    }

    #[test]
    fn bounded_objects_reject_excess_and_duplicate_keys() {
        type One = BoundedMap<String, u8, 1>;
        type Two = BoundedMap<String, u8, 2>;

        assert_eq!(
            serde_json::from_str::<One>(r#"{"a":1}"#)
                .expect("at-limit object")
                .into_inner(),
            std::collections::BTreeMap::from([("a".to_owned(), 1)])
        );
        assert!(serde_json::from_str::<One>(r#"{"a":1,"b":2}"#).is_err());

        assert!(serde_json::from_str::<Two>(r#"{"a":1,"a":2}"#).is_err());
    }

    #[derive(Serialize)]
    struct Request<'a> {
        value: &'a str,
    }

    #[test]
    fn request_serialization_refuses_growth_past_the_wire_limit() {
        let oversized = "x".repeat(REQUEST_BYTES);
        assert_eq!(
            encode_json(&Request { value: &oversized }),
            Err(TransportError::InvalidRequest)
        );
    }

    #[cfg(unix)]
    fn transport_with_one_response(
        status: &str,
        content_type: &str,
        body: &[u8],
        declared_length: usize,
    ) -> (
        super::DockerHttpTransport,
        std::path::PathBuf,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let socket = std::env::temp_dir().join(format!(
            "automata-docker-transport-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind fake Docker socket");
        let response = [
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
            body.to_vec(),
        ]
        .concat();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fake request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.expect("read fake request");
                assert_ne!(read, 0, "request ended before its headers");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() <= 16 * 1024, "request headers are bounded");
            }
            stream
                .write_all(&response)
                .await
                .expect("write fake response");
            stream.shutdown().await.expect("close fake response");
        });
        let connection = crate::DockerConnection {
            context_name: "transport-test".to_owned(),
            host: format!("unix://{}", socket.display()),
            endpoint: crate::EngineEndpoint::UnixSocket,
        };
        let transport = super::DockerHttpTransport::connect(
            &connection,
            crate::ApiVersion {
                major: 1,
                minor: 53,
            },
        )
        .expect("fake Docker transport");
        (transport, socket, server)
    }

    #[cfg(unix)]
    async fn finish_fake_response(socket: &std::path::Path, server: tokio::task::JoinHandle<()>) {
        server.await.expect("fake Docker server");
        std::fs::remove_file(socket).expect("remove exact fake socket");
    }

    #[cfg(unix)]
    fn transport_with_raw_response(
        response: Vec<u8>,
    ) -> (
        super::DockerHttpTransport,
        std::path::PathBuf,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::AsyncWriteExt as _;

        let socket = std::env::temp_dir().join(format!(
            "automata-docker-transport-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind fake Docker socket");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fake request");
            read_request_headers(&mut stream).await;
            let _ignored = stream.write_all(&response).await;
            let _ignored = stream.shutdown().await;
        });
        (fake_transport(&socket), socket, server)
    }

    #[cfg(unix)]
    fn fake_transport(socket: &std::path::Path) -> super::DockerHttpTransport {
        let connection = crate::DockerConnection {
            context_name: "transport-test".to_owned(),
            host: format!("unix://{}", socket.display()),
            endpoint: crate::EngineEndpoint::UnixSocket,
        };
        super::DockerHttpTransport::connect(
            &connection,
            crate::ApiVersion {
                major: 1,
                minor: 53,
            },
        )
        .expect("fake Docker transport")
    }

    #[cfg(unix)]
    async fn read_request_headers(stream: &mut tokio::net::UnixStream) {
        use tokio::io::AsyncReadExt as _;

        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).await.expect("read fake request");
            assert_ne!(read, 0, "request ended before its headers");
            request.extend_from_slice(&chunk[..read]);
            assert!(request.len() <= 16 * 1024, "request headers are bounded");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn response_content_length_is_rejected_before_body_collection() {
        let (transport, socket, server) =
            transport_with_one_response("200 OK", "application/json", b"{}", 4096);
        let result = transport
            .json::<serde_json::Value, ()>(
                http::Method::GET,
                "/bounded",
                None,
                http::StatusCode::OK,
                16,
            )
            .await;
        assert_eq!(result, Err(TransportError::ResponseTooLarge));
        finish_fake_response(&socket, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn optional_responses_require_a_bounded_structured_docker_error() {
        let body = br#"{"message":"missing"}"#;
        let (transport, socket, server) =
            transport_with_one_response("404 Not Found", "application/json", body, body.len());
        assert_eq!(
            transport
                .optional_json::<serde_json::Value>("/missing", 16)
                .await,
            Ok(None)
        );
        finish_fake_response(&socket, server).await;

        let body = b"{}";
        let (transport, socket, server) =
            transport_with_one_response("404 Not Found", "application/json", body, body.len());
        assert_eq!(
            transport
                .optional_json::<serde_json::Value>("/malformed-error", 16)
                .await,
            Err(TransportError::InvalidResponse)
        );
        finish_fake_response(&socket, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn endpoint_json_cardinality_is_enforced() {
        let body = b"[1,2,3]";
        let (transport, socket, server) =
            transport_with_one_response("200 OK", "application/json", body, body.len());
        let result = transport
            .json::<BoundedVec<u8, 2>, ()>(
                http::Method::GET,
                "/cardinality",
                None,
                http::StatusCode::OK,
                body.len(),
            )
            .await;
        assert_eq!(result, Err(TransportError::InvalidResponse));
        finish_fake_response(&socket, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn chunked_success_and_error_bodies_are_bounded_while_streaming() {
        let payload = "x".repeat(32);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
            payload.len(),
            payload
        )
        .into_bytes();
        let (transport, socket, server) = transport_with_raw_response(response);
        assert_eq!(
            transport
                .json::<serde_json::Value, ()>(
                    http::Method::GET,
                    "/chunked-success-overflow",
                    None,
                    http::StatusCode::OK,
                    16,
                )
                .await,
            Err(TransportError::ResponseTooLarge)
        );
        finish_fake_response(&socket, server).await;

        let payload = "x".repeat(ERROR_BYTES + 1);
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
            payload.len(),
            payload
        )
        .into_bytes();
        let (transport, socket, server) = transport_with_raw_response(response);
        assert_eq!(
            transport
                .optional_json::<serde_json::Value>("/chunked-error-overflow", 16)
                .await,
            Err(TransportError::ResponseTooLarge)
        );
        finish_fake_response(&socket, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn response_header_count_bytes_and_duplicate_content_type_fail_closed() {
        use std::fmt::Write as _;

        let mut many_headers = String::new();
        for index in 0..MAX_RESPONSE_HEADERS {
            write!(many_headers, "X-Test-{index}: x\r\n").expect("write response header");
        }
        for response in [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{many_headers}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .into_bytes(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Wide: {}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
                "x".repeat(super::MAX_RESPONSE_HEADER_BYTES)
            )
            .into_bytes(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
        ] {
            let (transport, socket, server) = transport_with_raw_response(response);
            assert!(
                transport
                    .json::<serde_json::Value, ()>(
                        http::Method::GET,
                        "/invalid-headers",
                        None,
                        http::StatusCode::OK,
                        16,
                    )
                    .await
                    .is_err()
            );
            finish_fake_response(&socket, server).await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ambiguous_response_framing_is_never_accepted() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\nConnection: close\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec(),
        ] {
            let (transport, socket, server) = transport_with_raw_response(response);
            assert!(
                transport
                    .json::<serde_json::Value, ()>(
                        http::Method::GET,
                        "/ambiguous-framing",
                        None,
                        http::StatusCode::OK,
                        16,
                    )
                    .await
                    .is_err()
            );
            finish_fake_response(&socket, server).await;
        }
    }

    #[cfg(unix)]
    async fn assert_stalled_response_is_cancelled(prefix: &'static [u8]) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let socket = std::env::temp_dir().join(format!(
            "automata-docker-transport-stall-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind stalled Docker socket");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept stalled request");
            read_request_headers(&mut stream).await;
            stream
                .write_all(prefix)
                .await
                .expect("write stalled prefix");
            let mut byte = [0_u8; 1];
            let closed = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .expect("cancelled client closes its exact socket")
                .expect("read client close");
            assert_eq!(closed, 0, "cancelled connection must not remain detached");
        });
        let transport = fake_transport(&socket);
        assert_eq!(
            deadline(
                Duration::from_millis(25),
                transport.json::<serde_json::Value, ()>(
                    http::Method::GET,
                    "/stalled",
                    None,
                    http::StatusCode::OK,
                    16,
                ),
            )
            .await,
            Err(TransportError::RequestFailed)
        );
        finish_fake_response(&socket, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stalled_headers_and_bodies_are_cancelled_without_detached_connections() {
        assert_stalled_response_is_cancelled(b"").await;
        assert_stalled_response_is_cancelled(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 8\r\nConnection: close\r\n\r\n{",
        )
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_during_driver_finish_aborts_the_task_and_closes_its_socket() {
        use tokio::io::AsyncReadExt as _;

        let (client, mut peer) = tokio::net::UnixStream::pair().expect("Unix socket pair");
        let task = tokio::spawn(async move {
            let result = std::future::pending::<Result<(), hyper::Error>>().await;
            drop(client);
            result
        });
        let driver = super::ConnectionDriver(Some(task));

        assert!(
            tokio::time::timeout(Duration::from_millis(25), driver.finish())
                .await
                .is_err(),
            "the test driver remains pending until cancellation"
        );
        let mut byte = [0_u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
            .await
            .expect("cancelled finish closes the driver socket")
            .expect("read driver socket close");
        assert_eq!(
            closed, 0,
            "driver task must not detach on finish cancellation"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn every_request_reconnects_to_the_exact_rebound_unix_socket() {
        use tokio::io::AsyncWriteExt as _;

        let socket = std::env::temp_dir().join(format!(
            "automata-docker-transport-rebind-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let transport = fake_transport(&socket);
        for expected in [1_u8, 2] {
            let listener = tokio::net::UnixListener::bind(&socket).expect("bind rebound socket");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept rebound request");
                read_request_headers(&mut stream).await;
                let body = format!("{{\"server\":{expected}}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write rebound response");
            });
            let observed: serde_json::Value = transport
                .json(
                    http::Method::GET,
                    "/rebind",
                    None::<&()>,
                    http::StatusCode::OK,
                    64,
                )
                .await
                .expect("request reaches current listener");
            assert_eq!(observed["server"], expected);
            server.await.expect("rebound server");
            std::fs::remove_file(&socket).expect("remove rebound socket name");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_connection_is_not_implicitly_retried() {
        let socket = std::env::temp_dir().join(format!(
            "automata-docker-transport-no-retry-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind no-retry socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept first request");
            drop(stream);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "one operation must open exactly one connection"
            );
        });
        let transport = fake_transport(&socket);
        assert_eq!(
            transport
                .json::<serde_json::Value, ()>(
                    http::Method::GET,
                    "/no-retry",
                    None,
                    http::StatusCode::OK,
                    16,
                )
                .await,
            Err(TransportError::RequestFailed)
        );
        finish_fake_response(&socket, server).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_connection_cardinality_is_hard_bounded() {
        let socket = std::env::temp_dir().join(format!(
            "automata-docker-transport-cardinality-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind cardinality socket");
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(MAX_IN_FLIGHT_REQUESTS);
        let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut streams = Vec::with_capacity(MAX_IN_FLIGHT_REQUESTS);
            for _ in 0..MAX_IN_FLIGHT_REQUESTS {
                let (mut stream, _) = listener.accept().await.expect("accept bounded request");
                read_request_headers(&mut stream).await;
                streams.push(stream);
                accepted_tx.send(()).await.expect("report accepted request");
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "request cardinality exceeded the transport bound"
            );
            drop(listener);
            checked_tx.send(()).expect("report cardinality check");
            drop(streams);
        });
        let transport = fake_transport(&socket);
        let mut requests = Vec::new();
        for _ in 0..=MAX_IN_FLIGHT_REQUESTS {
            let transport = transport.clone();
            requests.push(tokio::spawn(async move {
                transport
                    .json::<serde_json::Value, ()>(
                        http::Method::GET,
                        "/cardinality",
                        None,
                        http::StatusCode::OK,
                        16,
                    )
                    .await
            }));
        }
        for _ in 0..MAX_IN_FLIGHT_REQUESTS {
            tokio::time::timeout(Duration::from_secs(1), accepted_rx.recv())
                .await
                .expect("bounded request connects")
                .expect("server reports bounded request");
        }
        checked_rx
            .await
            .expect("server completes cardinality check");
        for request in requests {
            request.abort();
            let _ignored = request.await;
        }
        finish_fake_response(&socket, server).await;
    }

    #[cfg(unix)]
    #[test]
    fn unix_transport_rejects_an_endpoint_class_mismatch() {
        for connection in [
            crate::DockerConnection {
                context_name: "wrong-class".to_owned(),
                host: "unix:///tmp/automata-mismatch.sock".to_owned(),
                endpoint: crate::EngineEndpoint::WindowsNamedPipe,
            },
            crate::DockerConnection {
                context_name: "wrong-host".to_owned(),
                host: "npipe:////./pipe/docker_engine".to_owned(),
                endpoint: crate::EngineEndpoint::UnixSocket,
            },
        ] {
            assert_eq!(
                super::DockerHttpTransport::connect(
                    &connection,
                    crate::ApiVersion {
                        major: 1,
                        minor: 53,
                    },
                )
                .expect_err("endpoint mismatch must fail closed"),
                TransportError::InvalidRequest
            );
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn busy_named_pipe_is_opened_once_without_waiting_or_retrying() {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

        const ERROR_PIPE_BUSY: i32 = 231;
        let name = format!(
            "automata-docker-transport-busy-{}",
            uuid::Uuid::new_v4().simple()
        );
        let pipe = format!(r"\\.\pipe\{name}");
        let occupied_server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe)
            .expect("create occupied named pipe");
        let occupied_client = ClientOptions::new()
            .open(&pipe)
            .expect("occupy named-pipe instance");
        occupied_server
            .connect()
            .await
            .expect("connect occupied named pipe");
        assert_eq!(
            super::open_named_pipe_once(&pipe)
                .expect_err("no named-pipe instance is available")
                .raw_os_error(),
            Some(ERROR_PIPE_BUSY),
            "fixture must exercise the native busy-pipe result"
        );

        let connection = crate::DockerConnection {
            context_name: "named-pipe-busy".to_owned(),
            host: format!("npipe:////./pipe/{name}"),
            endpoint: crate::EngineEndpoint::WindowsNamedPipe,
        };
        let transport = super::DockerHttpTransport::connect(
            &connection,
            crate::ApiVersion {
                major: 1,
                minor: 53,
            },
        )
        .expect("named-pipe transport");
        let result = tokio::time::timeout(
            Duration::from_millis(25),
            transport.json::<serde_json::Value, ()>(
                http::Method::GET,
                "/busy",
                None,
                http::StatusCode::OK,
                64,
            ),
        )
        .await
        .expect("one-shot busy-pipe open returns without a retry sleep");
        assert_eq!(result, Err(TransportError::RequestFailed));

        drop(occupied_client);
        drop(occupied_server);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn every_request_reconnects_to_the_exact_rebound_named_pipe() {
        use tokio::{
            io::{AsyncReadExt as _, AsyncWriteExt as _},
            net::windows::named_pipe::ServerOptions,
        };

        let name = format!(
            "automata-docker-transport-{}",
            uuid::Uuid::new_v4().simple()
        );
        let pipe = format!(r"\\.\pipe\{name}");
        let connection = crate::DockerConnection {
            context_name: "named-pipe-rebind".to_owned(),
            host: format!("npipe:////./pipe/{name}"),
            endpoint: crate::EngineEndpoint::WindowsNamedPipe,
        };
        let transport = super::DockerHttpTransport::connect(
            &connection,
            crate::ApiVersion {
                major: 1,
                minor: 53,
            },
        )
        .expect("named-pipe transport");

        for expected in [1_u8, 2] {
            let server = ServerOptions::new()
                .create(&pipe)
                .expect("create rebound named pipe");
            let task = tokio::spawn(async move {
                server.connect().await.expect("connect named-pipe client");
                let mut server = server;
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = server
                        .read(&mut chunk)
                        .await
                        .expect("read named-pipe request");
                    assert_ne!(read, 0, "request ended before its headers");
                    request.extend_from_slice(&chunk[..read]);
                    assert!(request.len() <= 16 * 1024, "request headers are bounded");
                }
                let body = format!("{{\"server\":{expected}}}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                server
                    .write_all(response.as_bytes())
                    .await
                    .expect("write named-pipe response");
                server.shutdown().await.expect("close named-pipe response");
            });
            let observed: serde_json::Value = transport
                .json(
                    http::Method::GET,
                    "/rebind",
                    None::<&()>,
                    http::StatusCode::OK,
                    64,
                )
                .await
                .expect("request reaches current named-pipe instance");
            assert_eq!(observed["server"], expected);
            task.await.expect("named-pipe server");
        }
    }
}
