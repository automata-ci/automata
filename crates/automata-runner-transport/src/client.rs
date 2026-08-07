use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use automata_protocol::{ProtocolLimits, RunnerToServer, ServerToRunner};
use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, Version,
    header::{
        ACCEPT, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING,
    },
    uri::Scheme,
};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use tokio::{sync::Semaphore, time::timeout};
use tokio_util::sync::CancellationToken;
use tower_service::Service;

use crate::{
    ClientError, ClientErrorKind, ClientFuture, ClientTlsConfig, ConfigurationError, ControlReply,
    ControlRoute, PROTOBUF_CONTENT_TYPE, PreparedRequest, RetryClass, RunnerControlClient,
    TransportLimits,
};

type RustlsConnector = HttpsConnector<HttpConnector>;
type ConnectorResponse = <RustlsConnector as Service<Uri>>::Response;
type ConnectorError = <RustlsConnector as Service<Uri>>::Error;
type InnerClient = Client<H2OnlyConnector, Full<Bytes>>;

/// Rejects a successful TLS handshake unless the peer selected exactly `h2`.
///
/// Merely offering one ALPN value is insufficient because TLS permits a server
/// to select no ALPN at all. Keeping this check inside the connector prevents
/// the HTTP/2 client from sending a prior-knowledge preface on such a channel.
#[derive(Clone)]
struct H2OnlyConnector {
    inner: RustlsConnector,
}

impl Service<Uri> for H2OnlyConnector {
    type Response = ConnectorResponse;
    type Error = ConnectorError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let connecting = self.inner.call(destination);
        Box::pin(async move {
            let stream = connecting.await?;
            let selected_h2 = match &stream {
                MaybeHttpsStream::Https(tls) => {
                    tls.inner().get_ref().1.alpn_protocol() == Some(b"h2")
                }
                MaybeHttpsStream::Http(_) => false,
            };
            if !selected_h2 {
                return Err(io::Error::other("runner control TLS ALPN mismatch").into());
            }
            Ok(stream)
        })
    }
}

/// Outbound rustls/hyper HTTP/2 client used by the runner.
pub struct HyperRunnerControlClient {
    inner: InnerClient,
    handshake_uri: Uri,
    sync_uri: Uri,
    protocol_limits: ProtocolLimits,
    transport_limits: TransportLimits,
    admission: Arc<Semaphore>,
}

impl HyperRunnerControlClient {
    /// Creates an h2-only client for one HTTPS control-plane origin.
    ///
    /// The endpoint must be a simple HTTPS origin such as
    /// `https://control.example:8443/`, without credentials, query, fragment,
    /// or a non-root path. Redirects and proxy discovery are not implemented.
    /// Roots and client identity come exclusively from `tls`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] for an invalid endpoint or when response
    /// limits exceed the protobuf adapter's hard frame budget.
    pub fn new(
        endpoint: &Uri,
        tls: &ClientTlsConfig,
        protocol_limits: ProtocolLimits,
        transport_limits: TransportLimits,
    ) -> Result<Self, ConfigurationError> {
        if transport_limits.request_body_bytes() > protocol_limits.max_frame_bytes()
            || transport_limits.response_body_bytes() > protocol_limits.max_frame_bytes()
        {
            return Err(ConfigurationError::ProtocolLimitMismatch);
        }
        validate_endpoint(endpoint)?;
        let authority = endpoint
            .authority()
            .cloned()
            .ok_or(ConfigurationError::InvalidEndpoint)?;
        let handshake_uri = route_uri(authority.clone(), ControlRoute::Handshake)?;
        let sync_uri = route_uri(authority, ControlRoute::Sync)?;

        let mut tcp = HttpConnector::new();
        tcp.enforce_http(false);
        tcp.set_connect_timeout(Some(transport_limits.connect_timeout()));
        tcp.set_nodelay(true);
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls.config())
            .https_only()
            .enable_http2()
            .wrap_connector(tcp);
        let connector = H2OnlyConnector { inner: https };

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .http2_only(true)
            .http2_max_header_list_size(transport_limits.header_list_bytes())
            .http2_max_send_buf_size(transport_limits.send_buffer_bytes())
            .http2_keep_alive_interval(Some(transport_limits.h2_keep_alive_interval()))
            .http2_keep_alive_timeout(transport_limits.h2_keep_alive_timeout())
            .http2_keep_alive_while_idle(true)
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())
            .pool_max_idle_per_host(1)
            .retry_canceled_requests(false);
        let inner = builder.build(connector);

        Ok(Self {
            inner,
            handshake_uri,
            sync_uri,
            protocol_limits,
            transport_limits,
            admission: Arc::new(Semaphore::new(
                transport_limits.concurrent_client_requests(),
            )),
        })
    }

    async fn exchange_bounded(
        &self,
        prepared: &PreparedRequest,
    ) -> Result<ControlReply, ClientError> {
        if prepared.canonical_bytes().len() > self.transport_limits.request_body_bytes() {
            return Err(ClientError::new(
                ClientErrorKind::Transport,
                RetryClass::Never,
            ));
        }
        let admission = timeout(
            self.transport_limits.admission_timeout(),
            Arc::clone(&self.admission).acquire_owned(),
        )
        .await;
        let _admission = match admission {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(ClientError::new(
                    ClientErrorKind::Transport,
                    RetryClass::RetrySameRequest,
                ));
            }
            Err(_) => {
                return Err(ClientError::new(
                    ClientErrorKind::Timeout,
                    RetryClass::RetrySameRequest,
                ));
            }
        };

        let request = self.http_request(prepared);
        let response = self.inner.request(request).await.map_err(|_| {
            ClientError::new(ClientErrorKind::Transport, RetryClass::RetrySameRequest)
        })?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status()));
        }
        let declared_length = validate_response_head(&response, &self.transport_limits)?;
        let (_, body) = response.into_parts();
        let body = timeout(
            self.transport_limits.response_body_timeout(),
            read_response_body(
                body,
                declared_length,
                self.transport_limits.response_body_bytes(),
            ),
        )
        .await
        .map_err(|_| ClientError::new(ClientErrorKind::Timeout, RetryClass::RetrySameRequest))??;

        let decoded = automata_protocol_protobuf::decode_server_frame(&body, &self.protocol_limits)
            .map_err(|_| ClientError::new(ClientErrorKind::InvalidProtobuf, RetryClass::Never))?;
        if !response_matches_request(prepared, decoded.message()) {
            return Err(ClientError::new(
                ClientErrorKind::InvalidResponse,
                RetryClass::Never,
            ));
        }
        let canonical = automata_protocol_protobuf::encode_server_frame(
            decoded.message(),
            &self.protocol_limits,
        )
        .map(Bytes::from)
        .map_err(|_| ClientError::new(ClientErrorKind::InvalidProtobuf, RetryClass::Never))?;
        Ok(ControlReply::new(decoded, canonical))
    }

    fn http_request(&self, prepared: &PreparedRequest) -> Request<Full<Bytes>> {
        let uri = match prepared.route() {
            ControlRoute::Handshake => self.handshake_uri.clone(),
            ControlRoute::Sync => self.sync_uri.clone(),
        };
        let mut request = Request::new(Full::new(prepared.canonical_bytes().clone()));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = uri;
        *request.version_mut() = Version::HTTP_2;
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static(PROTOBUF_CONTENT_TYPE),
        );
        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static(PROTOBUF_CONTENT_TYPE));
        request.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from(prepared.canonical_bytes().len()),
        );
        request
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        request
    }
}

impl RunnerControlClient for HyperRunnerControlClient {
    fn exchange<'a>(
        &'a self,
        request: &'a PreparedRequest,
        cancellation: CancellationToken,
    ) -> ClientFuture<'a> {
        Box::pin(async move {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => Err(ClientError::new(
                    ClientErrorKind::Cancelled,
                    RetryClass::Never,
                )),
                result = timeout(
                    self.transport_limits.total_request_timeout(),
                    self.exchange_bounded(request),
                ) => result.unwrap_or_else(|_| Err(ClientError::new(
                    ClientErrorKind::Timeout,
                    RetryClass::RetrySameRequest,
                ))),
            }
        })
    }
}

impl fmt::Debug for HyperRunnerControlClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HyperRunnerControlClient")
            .field("protocol_limits", &self.protocol_limits)
            .field("transport_limits", &self.transport_limits)
            .field("http_version", &"h2")
            .finish_non_exhaustive()
    }
}

fn validate_endpoint(endpoint: &Uri) -> Result<(), ConfigurationError> {
    if endpoint.scheme() != Some(&Scheme::HTTPS)
        || endpoint.authority().is_none()
        || endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(ConfigurationError::InvalidEndpoint);
    }
    Ok(())
}

fn route_uri(
    authority: http::uri::Authority,
    route: ControlRoute,
) -> Result<Uri, ConfigurationError> {
    Uri::builder()
        .scheme(Scheme::HTTPS)
        .authority(authority)
        .path_and_query(route.path())
        .build()
        .map_err(|_| ConfigurationError::InvalidEndpoint)
}

fn validate_response_head(
    response: &http::Response<Incoming>,
    limits: &TransportLimits,
) -> Result<usize, ClientError> {
    if response.version() != Version::HTTP_2
        || response.headers().contains_key(CONTENT_ENCODING)
        || response.headers().contains_key(TRANSFER_ENCODING)
    {
        return Err(ClientError::new(
            ClientErrorKind::InvalidResponse,
            RetryClass::Never,
        ));
    }
    validate_exact_content_type(response.headers())?;
    let length = strict_content_length(response.headers())?;
    if length > limits.response_body_bytes() {
        return Err(ClientError::new(
            ClientErrorKind::ResponseTooLarge,
            RetryClass::Never,
        ));
    }
    Ok(length)
}

fn validate_exact_content_type(headers: &HeaderMap) -> Result<(), ClientError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(ClientError::new(
            ClientErrorKind::InvalidResponse,
            RetryClass::Never,
        ));
    };
    if values.next().is_some() || value.as_bytes() != PROTOBUF_CONTENT_TYPE.as_bytes() {
        return Err(ClientError::new(
            ClientErrorKind::InvalidResponse,
            RetryClass::Never,
        ));
    }
    Ok(())
}

fn strict_content_length(headers: &HeaderMap) -> Result<usize, ClientError> {
    let invalid = || ClientError::new(ClientErrorKind::InvalidResponse, RetryClass::Never);
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let value = values.next().ok_or_else(invalid)?;
    if values.next().is_some() {
        return Err(invalid());
    }
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    text.parse().map_err(|_| invalid())
}

async fn read_response_body(
    mut body: Incoming,
    declared_length: usize,
    maximum: usize,
) -> Result<Bytes, ClientError> {
    let mut collected = BytesMut::with_capacity(declared_length.min(maximum));
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            ClientError::new(ClientErrorKind::Transport, RetryClass::RetrySameRequest)
        })?;
        let data = frame
            .into_data()
            .map_err(|_| ClientError::new(ClientErrorKind::InvalidResponse, RetryClass::Never))?;
        let next = collected.len().checked_add(data.len()).ok_or_else(|| {
            ClientError::new(ClientErrorKind::ResponseTooLarge, RetryClass::Never)
        })?;
        if next > maximum || next > declared_length {
            return Err(ClientError::new(
                ClientErrorKind::ResponseTooLarge,
                RetryClass::Never,
            ));
        }
        collected.extend_from_slice(&data);
    }
    if collected.len() != declared_length {
        return Err(ClientError::new(
            ClientErrorKind::InvalidResponse,
            RetryClass::Never,
        ));
    }
    Ok(collected.freeze())
}

fn response_matches_request(prepared: &PreparedRequest, response: &ServerToRunner) -> bool {
    let request = prepared.message();
    match (request, response) {
        (RunnerToServer::Hello(hello), ServerToRunner::Hello(reply)) => {
            reply.validate_for(hello).is_ok()
        }
        (RunnerToServer::Hello(hello), ServerToRunner::HandshakeRejected(reply)) => {
            reply.validate_for(hello).is_ok()
        }
        (RunnerToServer::Hello(_), _) => false,
        (_, _) => sync_response_matches(prepared, response),
    }
}

fn sync_response_matches(prepared: &PreparedRequest, response: &ServerToRunner) -> bool {
    let Some(binding) = prepared.session_binding() else {
        return false;
    };
    let Some(request_header) = runner_request_header(prepared.message()) else {
        return false;
    };
    match response {
        ServerToRunner::Hello(_) | ServerToRunner::HandshakeRejected(_) => false,
        ServerToRunner::LeaseOffer(offer) => {
            offer
                .header()
                .validate_for(binding.protocol_version(), binding.session_id())
                .is_ok()
                && offer.job().version() == binding.job_ir_version()
        }
        ServerToRunner::CancelJob(cancel) => cancel
            .header()
            .validate_for(binding.protocol_version(), binding.session_id())
            .is_ok(),
        ServerToRunner::LeaseRenewal(renewal) => {
            renewal.header().validate_reply_for(request_header).is_ok()
        }
        ServerToRunner::LogAck(ack) => ack.header().validate_reply_for(request_header).is_ok(),
        ServerToRunner::OperationAck(ack) => {
            ack.header().validate_reply_for(request_header).is_ok()
        }
        ServerToRunner::NoWork(no_work) => {
            no_work.header().validate_reply_for(request_header).is_ok()
        }
        ServerToRunner::Error(error) => error.header().validate_reply_for(request_header).is_ok(),
    }
}

fn runner_request_header(message: &RunnerToServer) -> Option<automata_protocol::MessageHeader> {
    match message {
        RunnerToServer::Hello(_) => None,
        RunnerToServer::LeaseRequest(value) => Some(value.header()),
        RunnerToServer::LeaseResponse(value) => Some(value.header()),
        RunnerToServer::Heartbeat(value) => Some(value.header()),
        RunnerToServer::JobState(value) => Some(value.header()),
        RunnerToServer::JobResult(value) => Some(value.header()),
        RunnerToServer::LogBatch(value) => Some(value.header()),
        RunnerToServer::CommandAck(value) => Some(value.header()),
    }
}

fn status_error(status: StatusCode) -> ClientError {
    let retry = if status.is_server_error()
        || matches!(
            status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
        ) {
        RetryClass::RetrySameRequest
    } else {
        RetryClass::Never
    };
    ClientError::new(ClientErrorKind::HttpStatus(status), retry)
}
