use std::{convert::Infallible, fmt, net::SocketAddr, sync::Arc};

use automata_auth::machine::{
    MachineAuthenticationError, MachineAuthenticationEvidence, MachineIdentityVerifier,
};
use automata_protocol::{ProtocolLimits, RunnerToServer, ServerToRunner};
use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version,
    header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
};
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Incoming, server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::{timeout, timeout_at},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_util::sync::CancellationToken;

use crate::{
    ApplicationErrorKind, AuthenticatedRunnerRequest, ConfigurationError, ControlRoute,
    PROTOBUF_CONTENT_TYPE, RunnerControlHandler, ServeError, ServerTlsConfig, TransportLimits,
};

type HttpResponse = Response<Full<Bytes>>;

/// Dedicated runner-control listener using mandatory mTLS and HTTP/2 only.
pub struct RunnerControlServer {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Arc<dyn RunnerControlHandler>,
    protocol_limits: ProtocolLimits,
    transport_limits: TransportLimits,
    connection_admission: Arc<Semaphore>,
    request_admission: Arc<Semaphore>,
}

impl RunnerControlServer {
    /// Creates a listener around a pre-bound TCP socket.
    ///
    /// Passing a pre-bound listener keeps address/socket policy in product
    /// wiring while this crate owns the separate mTLS and HTTP/2 boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] when transport body limits exceed the
    /// protocol adapter's hard frame ceiling.
    pub fn new(
        listener: TcpListener,
        tls: &ServerTlsConfig,
        verifier: Arc<dyn MachineIdentityVerifier>,
        handler: Arc<dyn RunnerControlHandler>,
        protocol_limits: ProtocolLimits,
        transport_limits: TransportLimits,
    ) -> Result<Self, ConfigurationError> {
        if transport_limits.request_body_bytes() > protocol_limits.max_frame_bytes()
            || transport_limits.response_body_bytes() > protocol_limits.max_frame_bytes()
        {
            return Err(ConfigurationError::ProtocolLimitMismatch);
        }
        Ok(Self {
            listener,
            tls_acceptor: tls.acceptor(),
            verifier,
            handler,
            protocol_limits,
            transport_limits,
            connection_admission: Arc::new(Semaphore::new(
                transport_limits.concurrent_connections(),
            )),
            request_admission: Arc::new(Semaphore::new(
                transport_limits.concurrent_server_requests(),
            )),
        })
    }

    /// Returns the local address of the pre-bound listener.
    ///
    /// # Errors
    ///
    /// Returns [`ServeError::Listener`] if the socket cannot report its address.
    pub fn local_addr(&self) -> Result<SocketAddr, ServeError> {
        self.listener.local_addr().map_err(|_| ServeError::Listener)
    }

    /// Serves connections until cancellation and then drains them gracefully.
    ///
    /// TLS/HTTP failures on individual untrusted connections are isolated to
    /// those connections. Only failure of the listener accept loop is fatal.
    ///
    /// # Errors
    ///
    /// Returns [`ServeError::Listener`] if accepting a TCP connection fails.
    pub async fn serve(self, shutdown: CancellationToken) -> Result<(), ServeError> {
        let connection_shutdown = shutdown.child_token();
        let mut tasks = JoinSet::new();
        let mut fatal = None;

        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    let _ = joined;
                }
                accepted = self.listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        fatal = Some(ServeError::Listener);
                        break;
                    };
                    let Ok(connection_permit) = Arc::clone(&self.connection_admission)
                        .try_acquire_owned()
                    else {
                        drop(stream);
                        continue;
                    };
                    let state = ConnectionState {
                        tls_acceptor: self.tls_acceptor.clone(),
                        verifier: Arc::clone(&self.verifier),
                        handler: Arc::clone(&self.handler),
                        protocol_limits: self.protocol_limits,
                        transport_limits: self.transport_limits,
                        request_admission: Arc::clone(&self.request_admission),
                        shutdown: connection_shutdown.child_token(),
                    };
                    tasks.spawn(async move {
                        let _connection_permit = connection_permit;
                        serve_connection(stream, state).await;
                    });
                }
            }
        }

        connection_shutdown.cancel();
        let drain = async { while tasks.join_next().await.is_some() {} };
        if timeout(self.transport_limits.graceful_shutdown_timeout(), drain)
            .await
            .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }

        fatal.map_or(Ok(()), Err)
    }
}

impl fmt::Debug for RunnerControlServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerControlServer")
            .field("protocol_limits", &self.protocol_limits)
            .field("transport_limits", &self.transport_limits)
            .finish_non_exhaustive()
    }
}

struct ConnectionState {
    tls_acceptor: TlsAcceptor,
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Arc<dyn RunnerControlHandler>,
    protocol_limits: ProtocolLimits,
    transport_limits: TransportLimits,
    request_admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

async fn serve_connection(stream: TcpStream, state: ConnectionState) {
    let Ok(Ok(tls)) = timeout(
        state.transport_limits.tls_handshake_timeout(),
        state.tls_acceptor.accept(stream),
    )
    .await
    else {
        return;
    };

    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return;
    }

    let Some(evidence) = peer_evidence(&tls) else {
        return;
    };
    let evidence = Arc::new(evidence);
    let request_state = Arc::new(RequestState {
        verifier: state.verifier,
        handler: state.handler,
        evidence,
        protocol_limits: state.protocol_limits,
        transport_limits: state.transport_limits,
        admission: state.request_admission,
        shutdown: state.shutdown.clone(),
    });
    let service = service_fn(move |request| {
        let request_state = Arc::clone(&request_state);
        async move { Ok::<_, Infallible>(handle_request(request, request_state).await) }
    });

    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(state.transport_limits.concurrent_streams_per_connection())
        .max_header_list_size(state.transport_limits.header_list_bytes())
        .max_send_buf_size(state.transport_limits.send_buffer_bytes())
        .keep_alive_interval(state.transport_limits.h2_keep_alive_interval())
        .keep_alive_timeout(state.transport_limits.h2_keep_alive_timeout());

    let connection = builder.serve_connection(TokioIo::new(tls), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => return,
        () = state.shutdown.cancelled() => {}
        () = tokio::time::sleep(state.transport_limits.connection_lifetime()) => {}
    }
    connection.as_mut().graceful_shutdown();
    let _ = timeout(
        state.transport_limits.graceful_shutdown_timeout(),
        &mut connection,
    )
    .await;
}

fn peer_evidence(tls: &TlsStream<TcpStream>) -> Option<MachineAuthenticationEvidence> {
    let chain = tls
        .get_ref()
        .1
        .peer_certificates()?
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    MachineAuthenticationEvidence::new(chain).ok()
}

struct RequestState {
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Arc<dyn RunnerControlHandler>,
    evidence: Arc<MachineAuthenticationEvidence>,
    protocol_limits: ProtocolLimits,
    transport_limits: TransportLimits,
    admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

async fn handle_request(request: Request<Incoming>, state: Arc<RequestState>) -> HttpResponse {
    let admission = timeout(
        state.transport_limits.admission_timeout(),
        Arc::clone(&state.admission).acquire_owned(),
    )
    .await;
    let Ok(Ok(_admission)) = admission else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE);
    };

    let (route, declared_length) = match validate_request_head(&request, &state.transport_limits) {
        Ok(value) => value,
        Err(status) => return error_response(status),
    };

    let machine = match timeout(
        state.transport_limits.authentication_timeout(),
        state.verifier.authenticate(state.evidence.as_ref()),
    )
    .await
    {
        Ok(Ok(machine)) => machine,
        Ok(Err(MachineAuthenticationError::Untrusted | MachineAuthenticationError::Expired)) => {
            return error_response(StatusCode::UNAUTHORIZED);
        }
        Ok(Err(MachineAuthenticationError::Unavailable)) | Err(_) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let (_, body) = request.into_parts();
    let body = match timeout(
        state.transport_limits.request_body_timeout(),
        read_body(
            body,
            declared_length,
            state.transport_limits.request_body_bytes(),
        ),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(BodyReadError::TooLarge)) => {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Ok(Err(BodyReadError::Invalid | BodyReadError::Transport)) => {
            return error_response(StatusCode::BAD_REQUEST);
        }
        Err(_) => return error_response(StatusCode::REQUEST_TIMEOUT),
    };

    let Ok(decoded) =
        automata_protocol_protobuf::decode_runner_frame(&body, &state.protocol_limits)
    else {
        return error_response(StatusCode::BAD_REQUEST);
    };
    if !request_matches_route(route, decoded.message()) {
        return error_response(StatusCode::BAD_REQUEST);
    }
    let canonical = match automata_protocol_protobuf::encode_runner_frame(
        decoded.message(),
        &state.protocol_limits,
    ) {
        Ok(bytes) => Bytes::from(bytes),
        Err(_) => return error_response(StatusCode::BAD_REQUEST),
    };

    let request_message = decoded.message().clone();
    let request_cancellation = state.shutdown.child_token();
    let _cancel_on_drop = request_cancellation.clone().drop_guard();
    let handler_request =
        AuthenticatedRunnerRequest::new(machine, decoded, canonical, request_cancellation);
    let handler_timeout = match handler_request.message().message() {
        RunnerToServer::LeaseRequest(_) => state.transport_limits.long_poll_timeout(),
        _ => state.transport_limits.handler_timeout(),
    };
    let deadline = tokio::time::Instant::now() + handler_timeout;
    let handled = match route {
        ControlRoute::Handshake => {
            timeout_at(deadline, state.handler.handshake(handler_request)).await
        }
        ControlRoute::Sync => timeout_at(deadline, state.handler.sync(handler_request)).await,
    };
    let response_message = match handled {
        Ok(Ok(message)) => message,
        Ok(Err(error)) => return error_response(application_status(error.kind())),
        Err(_) => return error_response(StatusCode::GATEWAY_TIMEOUT),
    };
    if !response_matches_request(route, &request_message, &response_message) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let Ok(encoded) =
        automata_protocol_protobuf::encode_server_frame(&response_message, &state.protocol_limits)
    else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if encoded.len() > state.transport_limits.response_body_bytes() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR);
    }
    protobuf_response(Bytes::from(encoded))
}

fn validate_request_head(
    request: &Request<Incoming>,
    limits: &TransportLimits,
) -> Result<(ControlRoute, usize), StatusCode> {
    if request.version() != Version::HTTP_2 {
        return Err(StatusCode::HTTP_VERSION_NOT_SUPPORTED);
    }
    if request.method() != Method::POST {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if request.uri().query().is_some() {
        return Err(StatusCode::NOT_FOUND);
    }
    let route = match request.uri().path() {
        crate::HANDSHAKE_PATH => ControlRoute::Handshake,
        crate::SYNC_PATH => ControlRoute::Sync,
        _ => return Err(StatusCode::NOT_FOUND),
    };
    validate_exact_content_type(request.headers())?;
    if request.headers().contains_key(CONTENT_ENCODING)
        || request.headers().contains_key(TRANSFER_ENCODING)
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let declared_length = strict_content_length(request.headers())?;
    if declared_length > limits.request_body_bytes() {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    Ok((route, declared_length))
}

fn validate_exact_content_type(headers: &HeaderMap) -> Result<(), StatusCode> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    };
    if values.next().is_some() || value.as_bytes() != PROTOBUF_CONTENT_TYPE.as_bytes() {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    Ok(())
}

fn strict_content_length(headers: &HeaderMap) -> Result<usize, StatusCode> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Err(StatusCode::LENGTH_REQUIRED);
    };
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    text.parse().map_err(|_| StatusCode::BAD_REQUEST)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyReadError {
    TooLarge,
    Invalid,
    Transport,
}

async fn read_body(
    mut body: Incoming,
    declared_length: usize,
    maximum: usize,
) -> Result<Bytes, BodyReadError> {
    let mut collected = BytesMut::with_capacity(declared_length.min(maximum));
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyReadError::Transport)?;
        let data = frame.into_data().map_err(|_| BodyReadError::Invalid)?;
        let next = collected
            .len()
            .checked_add(data.len())
            .ok_or(BodyReadError::TooLarge)?;
        if next > maximum || next > declared_length {
            return Err(BodyReadError::TooLarge);
        }
        collected.extend_from_slice(&data);
    }
    if collected.len() != declared_length {
        return Err(BodyReadError::Invalid);
    }
    Ok(collected.freeze())
}

const fn request_matches_route(route: ControlRoute, message: &RunnerToServer) -> bool {
    matches!(
        (route, message),
        (ControlRoute::Handshake, RunnerToServer::Hello(_))
            | (
                ControlRoute::Sync,
                RunnerToServer::LeaseRequest(_)
                    | RunnerToServer::LeaseResponse(_)
                    | RunnerToServer::Heartbeat(_)
                    | RunnerToServer::JobState(_)
                    | RunnerToServer::JobResult(_)
                    | RunnerToServer::LogBatch(_)
                    | RunnerToServer::CommandAck(_)
            )
    )
}

fn response_matches_request(
    route: ControlRoute,
    request: &RunnerToServer,
    response: &ServerToRunner,
) -> bool {
    match (route, request, response) {
        (ControlRoute::Handshake, RunnerToServer::Hello(hello), ServerToRunner::Hello(reply)) => {
            reply.validate_for(hello).is_ok()
        }
        (
            ControlRoute::Handshake,
            RunnerToServer::Hello(hello),
            ServerToRunner::HandshakeRejected(reply),
        ) => reply.validate_for(hello).is_ok(),
        (ControlRoute::Sync, request, response) => sync_response_matches_request(request, response),
        _ => false,
    }
}

fn sync_response_matches_request(request: &RunnerToServer, response: &ServerToRunner) -> bool {
    let Some(header) = runner_request_header(request) else {
        return false;
    };
    match response {
        ServerToRunner::Hello(_) | ServerToRunner::HandshakeRejected(_) => false,
        ServerToRunner::LeaseOffer(offer) => offer
            .header()
            .validate_for(header.protocol_version(), header.session_id())
            .is_ok(),
        ServerToRunner::CancelJob(cancel) => cancel
            .header()
            .validate_for(header.protocol_version(), header.session_id())
            .is_ok(),
        ServerToRunner::LeaseRenewal(renewal) => {
            renewal.header().validate_reply_for(header).is_ok()
        }
        ServerToRunner::LogAck(ack) => ack.header().validate_reply_for(header).is_ok(),
        ServerToRunner::OperationAck(ack) => ack.header().validate_reply_for(header).is_ok(),
        ServerToRunner::NoWork(no_work) => no_work.header().validate_reply_for(header).is_ok(),
        ServerToRunner::Error(error) => error.header().validate_reply_for(header).is_ok(),
    }
}

const fn runner_request_header(
    message: &RunnerToServer,
) -> Option<automata_protocol::MessageHeader> {
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

const fn application_status(kind: ApplicationErrorKind) -> StatusCode {
    match kind {
        ApplicationErrorKind::Forbidden => StatusCode::FORBIDDEN,
        ApplicationErrorKind::StaleSession | ApplicationErrorKind::Conflict => StatusCode::CONFLICT,
        ApplicationErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ApplicationErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn protobuf_response(body: Bytes) -> HttpResponse {
    let content_length = HeaderValue::from(body.len());
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(PROTOBUF_CONTENT_TYPE),
    );
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, content_length);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error_response(status: StatusCode) -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
