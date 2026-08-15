use std::{convert::Infallible, fmt, net::SocketAddr, sync::Arc, time::Instant};

use automata_ci_auth::machine::{
    AuthenticatedMachine, MachineAuthenticationError, MachineAuthenticationEvidence,
    MachineIdentityVerifier,
};
use automata_ci_protocol::{ProtocolLimits, RunnerToServer, ServerToRunner};
use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version,
    header::{
        ACCEPT, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING,
    },
    uri::{Authority, Scheme},
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
use zeroize::Zeroizing;

use crate::{
    ApplicationErrorKind, AuthenticatedRunnerEphemeralRequest, AuthenticatedRunnerRequest,
    ConfigurationError, ControlRoute, EPHEMERAL_SECRETS_CONTENT_TYPE, EPHEMERAL_SECRETS_PATH,
    MAX_EPHEMERAL_REQUEST_BYTES, MAX_EPHEMERAL_RESPONSE_BYTES, NoopRunnerTransportObserver,
    PROTOBUF_CONTENT_TYPE, RunnerControlHandler, RunnerEphemeralHandler,
    RunnerTransportApplicationRejection, RunnerTransportAuthenticationRejection,
    RunnerTransportBodyRejection, RunnerTransportByteDirection, RunnerTransportConnectionEvent,
    RunnerTransportDecodeRejection, RunnerTransportHeadRejection, RunnerTransportObserver,
    RunnerTransportRequestObservation, RunnerTransportResponseRejection, RunnerTransportRoute,
    RunnerTransportTlsOutcome, ServeError, ServerTlsConfig, TransportLimits,
};

type HttpResponse = Response<Full<ResponseBytes>>;

struct ResponseBytes {
    storage: ResponseStorage,
    position: usize,
}

enum ResponseStorage {
    Ordinary(Bytes),
    Sensitive(Zeroizing<Vec<u8>>),
}

impl ResponseBytes {
    const fn ordinary(bytes: Bytes) -> Self {
        Self {
            storage: ResponseStorage::Ordinary(bytes),
            position: 0,
        }
    }

    const fn sensitive(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            storage: ResponseStorage::Sensitive(bytes),
            position: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        match &self.storage {
            ResponseStorage::Ordinary(bytes) => bytes,
            ResponseStorage::Sensitive(bytes) => bytes,
        }
    }
}

impl bytes::Buf for ResponseBytes {
    fn remaining(&self) -> usize {
        self.bytes().len().saturating_sub(self.position)
    }

    fn chunk(&self) -> &[u8] {
        &self.bytes()[self.position..]
    }

    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining(), "response cursor overflow");
        self.position += count;
    }
}

/// Dedicated runner-control listener using mandatory mTLS and HTTP/2 only.
pub struct RunnerControlServer {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    verifier: Arc<dyn MachineIdentityVerifier>,
    handler: Arc<dyn RunnerControlHandler>,
    ephemeral_route: Option<EphemeralRouteConfig>,
    observer: Arc<dyn RunnerTransportObserver>,
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
            ephemeral_route: None,
            observer: Arc::new(NoopRunnerTransportObserver),
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

    /// Installs an infallible observer for the physical server boundary.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn RunnerTransportObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Installs the only value-bearing route on this dedicated mTLS listener.
    ///
    /// The route is absent unless explicitly composed. It reauthenticates the
    /// peer certificate for every request and receives no connection-cached
    /// session authority.
    #[must_use]
    pub fn with_ephemeral_handler(
        mut self,
        expected_authority: Authority,
        handler: Arc<dyn RunnerEphemeralHandler>,
    ) -> Self {
        self.ephemeral_route = Some(EphemeralRouteConfig {
            expected_authority,
            handler,
        });
        self
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
    /// Panics are not a recoverable connection outcome: the workspace release
    /// profile aborts the process, so verifier and handler implementations must
    /// report expected failures through their typed results instead of panicking.
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
                    if let Some(Ok(Some(event))) = joined {
                        self.observer.observe_connection(event);
                    }
                }
                accepted = self.listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        fatal = Some(ServeError::Listener);
                        break;
                    };
                    let Ok(connection_permit) = Arc::clone(&self.connection_admission)
                        .try_acquire_owned()
                    else {
                        self.observer.observe_connection(
                            RunnerTransportConnectionEvent::Overloaded,
                        );
                        drop(stream);
                        continue;
                    };
                    self.observer
                        .observe_connection(RunnerTransportConnectionEvent::Admitted);
                    let state = ConnectionState {
                        tls_acceptor: self.tls_acceptor.clone(),
                        verifier: Arc::clone(&self.verifier),
                        handler: Arc::clone(&self.handler),
                        ephemeral_route: self.ephemeral_route.clone(),
                        observer: Arc::clone(&self.observer),
                        protocol_limits: self.protocol_limits,
                        transport_limits: self.transport_limits,
                        request_admission: Arc::clone(&self.request_admission),
                        shutdown: connection_shutdown.child_token(),
                    };
                    tasks.spawn(async move {
                        let _connection_permit = connection_permit;
                        serve_connection(stream, state).await
                    });
                }
            }
        }

        connection_shutdown.cancel();
        let drain = async {
            while let Some(joined) = tasks.join_next().await {
                if let Ok(Some(event)) = joined {
                    self.observer.observe_connection(event);
                }
            }
        };
        if timeout(self.transport_limits.graceful_shutdown_timeout(), drain)
            .await
            .is_err()
        {
            tasks.abort_all();
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok(Some(event)) => self.observer.observe_connection(event),
                    Err(error) if error.is_cancelled() => self
                        .observer
                        .observe_connection(RunnerTransportConnectionEvent::DrainAborted),
                    _ => {}
                }
            }
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
    ephemeral_route: Option<EphemeralRouteConfig>,
    observer: Arc<dyn RunnerTransportObserver>,
    protocol_limits: ProtocolLimits,
    transport_limits: TransportLimits,
    request_admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

async fn serve_connection(
    stream: TcpStream,
    state: ConnectionState,
) -> Option<RunnerTransportConnectionEvent> {
    let tls_started = Instant::now();
    let tls = match timeout(
        state.transport_limits.tls_handshake_timeout(),
        state.tls_acceptor.accept(stream),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(_)) => {
            state
                .observer
                .observe_tls(RunnerTransportTlsOutcome::Rejected, tls_started.elapsed());
            return None;
        }
        Err(_) => {
            state
                .observer
                .observe_tls(RunnerTransportTlsOutcome::Timeout, tls_started.elapsed());
            return None;
        }
    };

    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        state.observer.observe_tls(
            RunnerTransportTlsOutcome::InvalidProtocol,
            tls_started.elapsed(),
        );
        return None;
    }

    let Some(evidence) = peer_evidence(&tls) else {
        state.observer.observe_tls(
            RunnerTransportTlsOutcome::InvalidPeerIdentity,
            tls_started.elapsed(),
        );
        return None;
    };
    state
        .observer
        .observe_tls(RunnerTransportTlsOutcome::Accepted, tls_started.elapsed());
    let evidence = Arc::new(evidence);
    let request_state = Arc::new(RequestState {
        verifier: state.verifier,
        handler: state.handler,
        ephemeral_route: state.ephemeral_route,
        observer: Arc::clone(&state.observer),
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
    let terminal_event = tokio::select! {
        result = &mut connection => {
            if result.is_ok() {
                RunnerTransportConnectionEvent::Http2Closed
            } else {
                RunnerTransportConnectionEvent::Http2Error
            }
        },
        () = state.shutdown.cancelled() => RunnerTransportConnectionEvent::Shutdown,
        () = tokio::time::sleep(state.transport_limits.connection_lifetime()) => {
            RunnerTransportConnectionEvent::LifetimeExpired
        }
    };
    if matches!(
        terminal_event,
        RunnerTransportConnectionEvent::Http2Closed | RunnerTransportConnectionEvent::Http2Error
    ) {
        return Some(terminal_event);
    }
    connection.as_mut().graceful_shutdown();
    if terminal_event == RunnerTransportConnectionEvent::LifetimeExpired {
        let _ = timeout(
            state.transport_limits.graceful_shutdown_timeout(),
            &mut connection,
        )
        .await;
    } else {
        let _ = (&mut connection).await;
    }
    Some(terminal_event)
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
    ephemeral_route: Option<EphemeralRouteConfig>,
    observer: Arc<dyn RunnerTransportObserver>,
    evidence: Arc<MachineAuthenticationEvidence>,
    protocol_limits: ProtocolLimits,
    transport_limits: TransportLimits,
    admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

async fn handle_request(request: Request<Incoming>, state: Arc<RequestState>) -> HttpResponse {
    let mut request_observation = RequestObservationGuard::new(Arc::clone(&state.observer));
    let admission = timeout(
        state.transport_limits.server_admission_timeout(),
        Arc::clone(&state.admission).acquire_owned(),
    )
    .await;
    let Ok(Ok(_admission)) = admission else {
        return observed_error(
            &mut request_observation,
            RunnerTransportRequestObservation::AdmissionOverloaded,
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };

    if request.uri().path() == EPHEMERAL_SECRETS_PATH && state.ephemeral_route.is_some() {
        return handle_ephemeral_request(request, &state, &mut request_observation).await;
    }

    let (route, declared_length) = match validate_request_head(&request, &state.transport_limits) {
        Ok(value) => value,
        Err(rejection) => {
            return RequestFailure::new(
                RunnerTransportRequestObservation::HeadRejected {
                    route: rejection.route,
                    reason: rejection.reason,
                },
                rejection.status,
            )
            .respond(&mut request_observation);
        }
    };
    let route_label = transport_route(route);
    request_observation.set_route(route_label);
    let _in_flight = RequestInFlight::new(Arc::clone(&state.observer), route_label);

    let machine = match authenticate_request(&state, route_label).await {
        Ok(machine) => machine,
        Err(failure) => return failure.respond(&mut request_observation),
    };

    let (_, body) = request.into_parts();
    let body = match receive_request_body(body, declared_length, &state, route_label).await {
        Ok(body) => body,
        Err(failure) => return failure.respond(&mut request_observation),
    };
    state.observer.observe_bytes(
        route_label,
        RunnerTransportByteDirection::Request,
        u64::try_from(body.len()).unwrap_or(u64::MAX),
    );

    let (decoded, canonical) = match decode_request(&body, route, &state, route_label) {
        Ok(decoded) => decoded,
        Err(failure) => return failure.respond(&mut request_observation),
    };

    let request_cancellation = state.shutdown.child_token();
    let _cancel_on_drop = request_cancellation.clone().drop_guard();
    let handler_request =
        AuthenticatedRunnerRequest::new(machine, decoded, canonical, request_cancellation);
    let response_message = match dispatch_request(handler_request, route, &state, route_label).await
    {
        Ok(message) => message,
        Err(failure) => return failure.respond(&mut request_observation),
    };
    let encoded = match encode_response(&response_message, &state, route_label) {
        Ok(encoded) => encoded,
        Err(failure) => return failure.respond(&mut request_observation),
    };
    state.observer.observe_bytes(
        route_label,
        RunnerTransportByteDirection::Response,
        u64::try_from(encoded.len()).unwrap_or(u64::MAX),
    );
    request_observation.finish(RunnerTransportRequestObservation::Succeeded { route: route_label });
    protobuf_response(encoded)
}

async fn handle_ephemeral_request(
    request: Request<Incoming>,
    state: &RequestState,
    request_observation: &mut RequestObservationGuard,
) -> HttpResponse {
    let route = RunnerTransportRoute::EphemeralSecrets;
    request_observation.set_route(route);
    let Some(route_config) = state.ephemeral_route.as_ref() else {
        return RequestFailure::new(
            RunnerTransportRequestObservation::ApplicationRejected {
                route,
                reason: RunnerTransportApplicationRejection::Unavailable,
            },
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .respond(request_observation);
    };
    let declared_length = match validate_ephemeral_request_head(
        &request,
        &state.transport_limits,
        &route_config.expected_authority,
    ) {
        Ok(length) => length,
        Err((reason, status)) => {
            return RequestFailure::new(
                RunnerTransportRequestObservation::HeadRejected { route, reason },
                status,
            )
            .respond(request_observation);
        }
    };
    let _in_flight = RequestInFlight::new(Arc::clone(&state.observer), route);
    let machine = match authenticate_request(state, route).await {
        Ok(machine) => machine,
        Err(failure) => return failure.respond(request_observation),
    };
    let (_, body) = request.into_parts();
    let body = match receive_ephemeral_request_body(body, declared_length, state, route).await {
        Ok(body) => body,
        Err(failure) => return failure.respond(request_observation),
    };
    state.observer.observe_bytes(
        route,
        RunnerTransportByteDirection::Request,
        u64::try_from(body.len()).unwrap_or(u64::MAX),
    );
    let cancellation = state.shutdown.child_token();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let request = AuthenticatedRunnerEphemeralRequest::new(machine, body, cancellation);
    let reply = match timeout(
        state.transport_limits.handler_timeout(),
        route_config.handler.handle(request),
    )
    .await
    {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => {
            return RequestFailure::new(
                RunnerTransportRequestObservation::ApplicationRejected {
                    route,
                    reason: transport_application_rejection(error.kind()),
                },
                application_status(error.kind()),
            )
            .respond(request_observation);
        }
        Err(_) => {
            return RequestFailure::new(
                RunnerTransportRequestObservation::ApplicationRejected {
                    route,
                    reason: RunnerTransportApplicationRejection::Timeout,
                },
                StatusCode::GATEWAY_TIMEOUT,
            )
            .respond(request_observation);
        }
    };
    let body = reply.into_body();
    if body.len() > MAX_EPHEMERAL_RESPONSE_BYTES
        || body.len() > state.transport_limits.response_body_bytes()
    {
        return RequestFailure::response_rejected(
            route,
            RunnerTransportResponseRejection::TooLarge,
        )
        .respond(request_observation);
    }
    state.observer.observe_bytes(
        route,
        RunnerTransportByteDirection::Response,
        u64::try_from(body.len()).unwrap_or(u64::MAX),
    );
    request_observation.finish(RunnerTransportRequestObservation::Succeeded { route });
    ephemeral_response(body)
}

fn validate_ephemeral_request_head<B>(
    request: &Request<B>,
    limits: &TransportLimits,
    expected_authority: &Authority,
) -> Result<usize, (RunnerTransportHeadRejection, StatusCode)> {
    if request.version() != Version::HTTP_2 {
        return Err((
            RunnerTransportHeadRejection::HttpVersion,
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
        ));
    }
    if request.method() != Method::POST {
        return Err((
            RunnerTransportHeadRejection::Method,
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }
    if request.uri().scheme() != Some(&Scheme::HTTPS)
        || request.uri().authority() != Some(expected_authority)
        || request.uri().query().is_some()
        || request.uri().path() != EPHEMERAL_SECRETS_PATH
    {
        return Err((
            RunnerTransportHeadRejection::NotFound,
            StatusCode::NOT_FOUND,
        ));
    }
    validate_exact_media_type(request.headers(), EPHEMERAL_SECRETS_CONTENT_TYPE)
        .map_err(|status| (RunnerTransportHeadRejection::UnsupportedMediaType, status))?;
    validate_exact_header(
        request.headers(),
        ACCEPT,
        EPHEMERAL_SECRETS_CONTENT_TYPE.as_bytes(),
    )
    .map_err(|status| (RunnerTransportHeadRejection::UnsupportedMediaType, status))?;
    validate_exact_header(request.headers(), CACHE_CONTROL, b"no-store")
        .map_err(|status| (RunnerTransportHeadRejection::UnsupportedMediaType, status))?;
    if request.headers().contains_key(CONTENT_ENCODING)
        || request.headers().contains_key(TRANSFER_ENCODING)
    {
        return Err((
            RunnerTransportHeadRejection::UnsupportedMediaType,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ));
    }
    let length = strict_content_length(request.headers()).map_err(|status| {
        (
            if status == StatusCode::LENGTH_REQUIRED {
                RunnerTransportHeadRejection::LengthRequired
            } else {
                RunnerTransportHeadRejection::InvalidContentLength
            },
            status,
        )
    })?;
    if length == 0 || length > MAX_EPHEMERAL_REQUEST_BYTES || length > limits.request_body_bytes() {
        return Err((
            RunnerTransportHeadRejection::BodyTooLarge,
            StatusCode::PAYLOAD_TOO_LARGE,
        ));
    }
    Ok(length)
}

#[derive(Clone)]
struct EphemeralRouteConfig {
    expected_authority: Authority,
    handler: Arc<dyn RunnerEphemeralHandler>,
}

async fn receive_ephemeral_request_body(
    body: Incoming,
    declared_length: usize,
    state: &RequestState,
    route: RunnerTransportRoute,
) -> Result<Zeroizing<Vec<u8>>, RequestFailure> {
    let maximum = MAX_EPHEMERAL_REQUEST_BYTES.min(state.transport_limits.request_body_bytes());
    let result = timeout(
        state.transport_limits.request_body_timeout(),
        read_secret_body(body, declared_length, maximum),
    )
    .await;
    let (reason, status) = match result {
        Ok(Ok(body)) => return Ok(body),
        Ok(Err(BodyReadError::TooLarge)) => (
            RunnerTransportBodyRejection::TooLarge,
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        Ok(Err(BodyReadError::Invalid)) => (
            RunnerTransportBodyRejection::Invalid,
            StatusCode::BAD_REQUEST,
        ),
        Ok(Err(BodyReadError::Transport)) => (
            RunnerTransportBodyRejection::Transport,
            StatusCode::BAD_REQUEST,
        ),
        Err(_) => (
            RunnerTransportBodyRejection::Timeout,
            StatusCode::REQUEST_TIMEOUT,
        ),
    };
    Err(RequestFailure::new(
        RunnerTransportRequestObservation::BodyRejected { route, reason },
        status,
    ))
}

async fn authenticate_request(
    state: &RequestState,
    route: RunnerTransportRoute,
) -> Result<AuthenticatedMachine, RequestFailure> {
    let result = timeout(
        state.transport_limits.authentication_timeout(),
        state.verifier.authenticate(state.evidence.as_ref()),
    )
    .await;
    let (reason, status) = match result {
        Ok(Ok(machine)) => return Ok(machine),
        Ok(Err(MachineAuthenticationError::Untrusted)) => (
            RunnerTransportAuthenticationRejection::Untrusted,
            StatusCode::UNAUTHORIZED,
        ),
        Ok(Err(MachineAuthenticationError::Expired)) => (
            RunnerTransportAuthenticationRejection::Expired,
            StatusCode::UNAUTHORIZED,
        ),
        Ok(Err(MachineAuthenticationError::Unavailable)) => (
            RunnerTransportAuthenticationRejection::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        Err(_) => (
            RunnerTransportAuthenticationRejection::Timeout,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    };
    Err(RequestFailure::new(
        RunnerTransportRequestObservation::AuthenticationRejected { route, reason },
        status,
    ))
}

async fn receive_request_body(
    body: Incoming,
    declared_length: usize,
    state: &RequestState,
    route: RunnerTransportRoute,
) -> Result<Bytes, RequestFailure> {
    let result = timeout(
        state.transport_limits.request_body_timeout(),
        read_body(
            body,
            declared_length,
            state.transport_limits.request_body_bytes(),
        ),
    )
    .await;
    let (reason, status) = match result {
        Ok(Ok(body)) => return Ok(body),
        Ok(Err(BodyReadError::TooLarge)) => (
            RunnerTransportBodyRejection::TooLarge,
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        Ok(Err(BodyReadError::Invalid)) => (
            RunnerTransportBodyRejection::Invalid,
            StatusCode::BAD_REQUEST,
        ),
        Ok(Err(BodyReadError::Transport)) => (
            RunnerTransportBodyRejection::Transport,
            StatusCode::BAD_REQUEST,
        ),
        Err(_) => (
            RunnerTransportBodyRejection::Timeout,
            StatusCode::REQUEST_TIMEOUT,
        ),
    };
    Err(RequestFailure::new(
        RunnerTransportRequestObservation::BodyRejected { route, reason },
        status,
    ))
}

fn decode_request(
    body: &Bytes,
    route: ControlRoute,
    state: &RequestState,
    route_label: RunnerTransportRoute,
) -> Result<(automata_ci_protocol::ValidatedRunnerToServer, Bytes), RequestFailure> {
    let Ok(decoded) =
        automata_ci_protocol_protobuf::decode_runner_frame(body, &state.protocol_limits)
    else {
        return Err(RequestFailure::bad_request_decode(
            route_label,
            RunnerTransportDecodeRejection::InvalidProtobuf,
        ));
    };
    if !request_matches_route(route, decoded.message()) {
        return Err(RequestFailure::bad_request_decode(
            route_label,
            RunnerTransportDecodeRejection::RouteMismatch,
        ));
    }
    let Ok(canonical) = automata_ci_protocol_protobuf::encode_runner_frame(
        decoded.message(),
        &state.protocol_limits,
    ) else {
        return Err(RequestFailure::bad_request_decode(
            route_label,
            RunnerTransportDecodeRejection::Canonicalization,
        ));
    };
    Ok((decoded, Bytes::from(canonical)))
}

async fn dispatch_request(
    request: AuthenticatedRunnerRequest,
    route: ControlRoute,
    state: &RequestState,
    route_label: RunnerTransportRoute,
) -> Result<ServerToRunner, RequestFailure> {
    let request_message = request.message().message().clone();
    let handler_timeout = match request.message().message() {
        RunnerToServer::LeaseRequest(_) => state.transport_limits.long_poll_timeout(),
        _ => state.transport_limits.handler_timeout(),
    };
    let deadline = tokio::time::Instant::now() + handler_timeout;
    let handled = match route {
        ControlRoute::Handshake => timeout_at(deadline, state.handler.handshake(request)).await,
        ControlRoute::Sync => timeout_at(deadline, state.handler.sync(request)).await,
    };
    let response = match handled {
        Ok(Ok(message)) => message,
        Ok(Err(error)) => {
            return Err(RequestFailure::new(
                RunnerTransportRequestObservation::ApplicationRejected {
                    route: route_label,
                    reason: transport_application_rejection(error.kind()),
                },
                application_status(error.kind()),
            ));
        }
        Err(_) => {
            return Err(RequestFailure::new(
                RunnerTransportRequestObservation::ApplicationRejected {
                    route: route_label,
                    reason: RunnerTransportApplicationRejection::Timeout,
                },
                StatusCode::GATEWAY_TIMEOUT,
            ));
        }
    };
    if !response_matches_request(route, &request_message, &response) {
        return Err(RequestFailure::response_rejected(
            route_label,
            RunnerTransportResponseRejection::InvalidCorrelation,
        ));
    }
    Ok(response)
}

fn encode_response(
    response: &ServerToRunner,
    state: &RequestState,
    route: RunnerTransportRoute,
) -> Result<Bytes, RequestFailure> {
    let Ok(encoded) =
        automata_ci_protocol_protobuf::encode_server_frame(response, &state.protocol_limits)
    else {
        return Err(RequestFailure::response_rejected(
            route,
            RunnerTransportResponseRejection::Encoding,
        ));
    };
    if encoded.len() > state.transport_limits.response_body_bytes() {
        return Err(RequestFailure::response_rejected(
            route,
            RunnerTransportResponseRejection::TooLarge,
        ));
    }
    Ok(Bytes::from(encoded))
}

struct RequestFailure {
    observation: RunnerTransportRequestObservation,
    status: StatusCode,
}

impl RequestFailure {
    const fn new(observation: RunnerTransportRequestObservation, status: StatusCode) -> Self {
        Self {
            observation,
            status,
        }
    }

    const fn bad_request_decode(
        route: RunnerTransportRoute,
        reason: RunnerTransportDecodeRejection,
    ) -> Self {
        Self::new(
            RunnerTransportRequestObservation::DecodeRejected { route, reason },
            StatusCode::BAD_REQUEST,
        )
    }

    const fn response_rejected(
        route: RunnerTransportRoute,
        reason: RunnerTransportResponseRejection,
    ) -> Self {
        Self::new(
            RunnerTransportRequestObservation::ResponseRejected { route, reason },
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }

    fn respond(self, guard: &mut RequestObservationGuard) -> HttpResponse {
        observed_error(guard, self.observation, self.status)
    }
}

fn validate_request_head(
    request: &Request<Incoming>,
    limits: &TransportLimits,
) -> Result<(ControlRoute, usize), RequestHeadRejection> {
    if request.version() != Version::HTTP_2 {
        return Err(RequestHeadRejection::unknown(
            RunnerTransportHeadRejection::HttpVersion,
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
        ));
    }
    if request.method() != Method::POST {
        return Err(RequestHeadRejection::unknown(
            RunnerTransportHeadRejection::Method,
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }
    if request.uri().query().is_some() {
        return Err(RequestHeadRejection::unknown(
            RunnerTransportHeadRejection::NotFound,
            StatusCode::NOT_FOUND,
        ));
    }
    let route = match request.uri().path() {
        crate::HANDSHAKE_PATH => ControlRoute::Handshake,
        crate::SYNC_PATH => ControlRoute::Sync,
        _ => {
            return Err(RequestHeadRejection::unknown(
                RunnerTransportHeadRejection::NotFound,
                StatusCode::NOT_FOUND,
            ));
        }
    };
    let route_label = transport_route(route);
    validate_exact_content_type(request.headers()).map_err(|status| RequestHeadRejection {
        route: route_label,
        reason: RunnerTransportHeadRejection::UnsupportedMediaType,
        status,
    })?;
    if request.headers().contains_key(CONTENT_ENCODING)
        || request.headers().contains_key(TRANSFER_ENCODING)
    {
        return Err(RequestHeadRejection {
            route: route_label,
            reason: RunnerTransportHeadRejection::UnsupportedMediaType,
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
        });
    }
    let declared_length =
        strict_content_length(request.headers()).map_err(|status| RequestHeadRejection {
            route: route_label,
            reason: if status == StatusCode::LENGTH_REQUIRED {
                RunnerTransportHeadRejection::LengthRequired
            } else {
                RunnerTransportHeadRejection::InvalidContentLength
            },
            status,
        })?;
    if declared_length > limits.request_body_bytes() {
        return Err(RequestHeadRejection {
            route: route_label,
            reason: RunnerTransportHeadRejection::BodyTooLarge,
            status: StatusCode::PAYLOAD_TOO_LARGE,
        });
    }
    Ok((route, declared_length))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestHeadRejection {
    route: RunnerTransportRoute,
    reason: RunnerTransportHeadRejection,
    status: StatusCode,
}

impl RequestHeadRejection {
    const fn unknown(reason: RunnerTransportHeadRejection, status: StatusCode) -> Self {
        Self {
            route: RunnerTransportRoute::Unknown,
            reason,
            status,
        }
    }
}

fn validate_exact_content_type(headers: &HeaderMap) -> Result<(), StatusCode> {
    validate_exact_media_type(headers, PROTOBUF_CONTENT_TYPE)
}

fn validate_exact_media_type(headers: &HeaderMap, media_type: &str) -> Result<(), StatusCode> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    };
    if values.next().is_some() || value.as_bytes() != media_type.as_bytes() {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    Ok(())
}

fn validate_exact_header(
    headers: &HeaderMap,
    name: http::header::HeaderName,
    expected: &[u8],
) -> Result<(), StatusCode> {
    let mut values = headers.get_all(name).iter();
    if values
        .next()
        .is_some_and(|value| value.as_bytes() == expected)
        && values.next().is_none()
    {
        Ok(())
    } else {
        Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)
    }
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

async fn read_secret_body(
    mut body: Incoming,
    declared_length: usize,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, BodyReadError> {
    let mut collected = Zeroizing::new(Vec::with_capacity(declared_length.min(maximum)));
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
    Ok(collected)
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
        ServerToRunner::RuntimeAuthorityGrant(grant) => {
            grant.header().validate_reply_for(header).is_ok()
        }
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
) -> Option<automata_ci_protocol::MessageHeader> {
    match message {
        RunnerToServer::Hello(_) => None,
        RunnerToServer::LeaseRequest(value) => Some(value.header()),
        RunnerToServer::LeaseResponse(value) => Some(value.header()),
        RunnerToServer::RuntimeAuthorityRequest(value) => Some(value.header()),
        RunnerToServer::RuntimeAuthorityAck(value) => Some(value.header()),
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

const fn transport_application_rejection(
    kind: ApplicationErrorKind,
) -> RunnerTransportApplicationRejection {
    match kind {
        ApplicationErrorKind::Forbidden => RunnerTransportApplicationRejection::Forbidden,
        ApplicationErrorKind::StaleSession | ApplicationErrorKind::Conflict => {
            RunnerTransportApplicationRejection::Conflict
        }
        ApplicationErrorKind::Unavailable => RunnerTransportApplicationRejection::Unavailable,
        ApplicationErrorKind::Internal => RunnerTransportApplicationRejection::Internal,
    }
}

const fn transport_route(route: ControlRoute) -> RunnerTransportRoute {
    match route {
        ControlRoute::Handshake => RunnerTransportRoute::Handshake,
        ControlRoute::Sync => RunnerTransportRoute::Sync,
    }
}

struct RequestInFlight {
    observer: Arc<dyn RunnerTransportObserver>,
    route: RunnerTransportRoute,
}

impl RequestInFlight {
    fn new(observer: Arc<dyn RunnerTransportObserver>, route: RunnerTransportRoute) -> Self {
        observer.request_started(route);
        Self { observer, route }
    }
}

impl Drop for RequestInFlight {
    fn drop(&mut self) {
        self.observer.request_finished(self.route);
    }
}

struct RequestObservationGuard {
    observer: Arc<dyn RunnerTransportObserver>,
    route: RunnerTransportRoute,
    started: Instant,
    completed: bool,
}

impl RequestObservationGuard {
    fn new(observer: Arc<dyn RunnerTransportObserver>) -> Self {
        Self {
            observer,
            route: RunnerTransportRoute::Unknown,
            started: Instant::now(),
            completed: false,
        }
    }

    const fn set_route(&mut self, route: RunnerTransportRoute) {
        self.route = route;
    }

    fn finish(&mut self, observation: RunnerTransportRequestObservation) {
        self.completed = true;
        self.observer
            .observe_request(observation, self.started.elapsed());
    }
}

impl Drop for RequestObservationGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.observer.observe_request(
                RunnerTransportRequestObservation::Cancelled { route: self.route },
                self.started.elapsed(),
            );
        }
    }
}

fn observed_error(
    guard: &mut RequestObservationGuard,
    observation: RunnerTransportRequestObservation,
    status: StatusCode,
) -> HttpResponse {
    guard.finish(observation);
    error_response(status)
}

fn protobuf_response(body: Bytes) -> HttpResponse {
    let content_length = HeaderValue::from(body.len());
    let mut response = Response::new(Full::new(ResponseBytes::ordinary(body)));
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

fn ephemeral_response(body: Zeroizing<Vec<u8>>) -> HttpResponse {
    let content_length = HeaderValue::from(body.len());
    let mut response = Response::new(Full::new(ResponseBytes::sensitive(body)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static(EPHEMERAL_SECRETS_CONTENT_TYPE),
    );
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, content_length);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
    response
}

fn error_response(status: StatusCode) -> HttpResponse {
    let mut response = Response::new(Full::new(ResponseBytes::ordinary(Bytes::new())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str) -> Request<()> {
        let mut request = Request::new(());
        *request.method_mut() = Method::POST;
        *request.version_mut() = Version::HTTP_2;
        *request.uri_mut() = uri.parse().expect("test URI");
        for (name, value) in [
            (CONTENT_TYPE, EPHEMERAL_SECRETS_CONTENT_TYPE),
            (ACCEPT, EPHEMERAL_SECRETS_CONTENT_TYPE),
            (CACHE_CONTROL, "no-store"),
            (CONTENT_LENGTH, "1"),
        ] {
            request
                .headers_mut()
                .insert(name, HeaderValue::from_static(value));
        }
        request
    }

    #[test]
    fn ephemeral_head_requires_one_canonical_content_length() {
        let authority: Authority = "runner.example:8443".parse().expect("authority");
        let mut request = request(&format!("https://{authority}{EPHEMERAL_SECRETS_PATH}"));
        assert!(
            validate_ephemeral_request_head(&request, &TransportLimits::default(), &authority)
                .is_ok()
        );

        request
            .headers_mut()
            .append(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert_eq!(
            validate_ephemeral_request_head(&request, &TransportLimits::default(), &authority),
            Err((
                RunnerTransportHeadRejection::InvalidContentLength,
                StatusCode::BAD_REQUEST
            ))
        );
    }

    #[test]
    fn ephemeral_head_forbids_content_and_transfer_encodings() {
        let authority: Authority = "runner.example:8443".parse().expect("authority");
        for header in [CONTENT_ENCODING, TRANSFER_ENCODING] {
            let mut request = request(&format!("https://{authority}{EPHEMERAL_SECRETS_PATH}"));
            request
                .headers_mut()
                .insert(header, HeaderValue::from_static("identity"));
            assert_eq!(
                validate_ephemeral_request_head(&request, &TransportLimits::default(), &authority),
                Err((
                    RunnerTransportHeadRejection::UnsupportedMediaType,
                    StatusCode::UNSUPPORTED_MEDIA_TYPE
                ))
            );
        }
    }

    #[test]
    fn ephemeral_head_requires_exact_https_authority_and_absolute_form() {
        let authority: Authority = "runner.example:8443".parse().expect("authority");
        for uri in [
            EPHEMERAL_SECRETS_PATH.to_owned(),
            format!("https://other.example:8443{EPHEMERAL_SECRETS_PATH}"),
            format!("https://runner.example:9443{EPHEMERAL_SECRETS_PATH}"),
            format!("http://{authority}{EPHEMERAL_SECRETS_PATH}"),
        ] {
            assert_eq!(
                validate_ephemeral_request_head(
                    &request(&uri),
                    &TransportLimits::default(),
                    &authority
                ),
                Err((
                    RunnerTransportHeadRejection::NotFound,
                    StatusCode::NOT_FOUND
                )),
                "URI unexpectedly accepted: {uri}"
            );
        }
    }
}
