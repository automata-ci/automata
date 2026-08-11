mod support;

use automata_ci_core::{JobIrVersion, OperationId, RunnerSessionId};
use automata_ci_protocol::{
    CommandCursor, LeaseRequest, MessageHeader, NegotiatedSession, ProtocolLimits, RemoteErrorCode,
    RunnerSlotOrdinal, RunnerToServer, SUPPORTED_PROTOCOL_RANGE, ServerToRunner,
    SessionDisposition,
};
use automata_ci_runner_transport::{
    AuthenticatedRunnerEphemeralRequest, ClientErrorKind, PrepareError, PreparedEphemeralRequest,
    PreparedRequest, RetryClass, RunnerControlClient, RunnerControlClientObserver,
    RunnerControlHandler, RunnerEphemeralClient, RunnerEphemeralHandler, RunnerEphemeralReply,
    RunnerEphemeralResponse, TransportLimits,
};
use static_assertions::{assert_not_impl_any, assert_obj_safe};
use tokio_util::sync::CancellationToken;

use support::{
    HandlerMode, RecordingVerifier, TestHandler, TestPki, client, hello_request, poll_request,
    spawn_server,
};

assert_obj_safe!(RunnerControlHandler);
assert_obj_safe!(RunnerControlClient);
assert_obj_safe!(RunnerControlClientObserver);
assert_obj_safe!(RunnerEphemeralHandler);
assert_obj_safe!(RunnerEphemeralClient);
assert_not_impl_any!(AuthenticatedRunnerEphemeralRequest: Clone);
assert_not_impl_any!(PreparedEphemeralRequest: Clone);
assert_not_impl_any!(RunnerEphemeralReply: Clone);
assert_not_impl_any!(RunnerEphemeralResponse: Clone);

#[test]
fn sync_preparation_rejects_a_cross_session_header() {
    let negotiated = NegotiatedSession::new(
        SUPPORTED_PROTOCOL_RANGE.max(),
        JobIrVersion::current(),
        RunnerSessionId::new(),
        SessionDisposition::Opened,
        CommandCursor::initial(),
    );
    let request = RunnerToServer::LeaseRequest(LeaseRequest::first(
        MessageHeader::request(
            SUPPORTED_PROTOCOL_RANGE.max(),
            RunnerSessionId::new(),
            OperationId::new(),
        ),
        RunnerSlotOrdinal::new(1).expect("slot"),
    ));
    assert!(matches!(
        PreparedRequest::for_session(request, negotiated, &ProtocolLimits::default()),
        Err(PrepareError::SessionMismatch)
    ));
}

#[tokio::test]
async fn valid_handshake_exposes_only_rustls_peer_chain_and_canonical_reply() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Reply);
    let running = spawn_server(
        &pki,
        verifier.clone(),
        handler.clone(),
        &TransportLimits::default(),
    )
    .await;
    let client = client(&running, &pki, &TransportLimits::default());
    let prepared = hello_request();

    let reply = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect("valid handshake response");
    assert!(matches!(
        reply.message().message(),
        ServerToRunner::Hello(_)
    ));
    assert_eq!(
        automata_ci_protocol_protobuf::encode_server_frame(
            reply.message().message(),
            &ProtocolLimits::default(),
        )
        .expect("canonical re-encode"),
        reply.canonical_bytes().as_ref()
    );
    assert_eq!(verifier.calls(), 1);
    assert_eq!(verifier.chains(), vec![pki.client.chain_bytes()]);
    assert_eq!(handler.calls(), 1);

    running.stop().await;
}

#[tokio::test]
async fn semantic_application_4xx_is_never_retryable() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::Fail(
        automata_ci_runner_transport::ApplicationErrorKind::Forbidden,
    ));
    let running = spawn_server(&pki, verifier, handler, &TransportLimits::default()).await;
    let client = client(&running, &pki, &TransportLimits::default());

    let error = client
        .exchange(&hello_request(), CancellationToken::new())
        .await
        .expect_err("forbidden response");
    assert!(matches!(
        error.kind(),
        ClientErrorKind::HttpStatus(http::StatusCode::FORBIDDEN)
    ));
    assert_eq!(error.retry_class(), RetryClass::Never);

    running.stop().await;
}

#[tokio::test]
async fn correlated_stale_session_is_a_successful_protocol_response() {
    let pki = TestPki::new();
    let verifier = RecordingVerifier::accepting();
    let handler = TestHandler::new(HandlerMode::ReplyStaleSession);
    let running = spawn_server(&pki, verifier, handler, &TransportLimits::default()).await;
    let client = client(&running, &pki, &TransportLimits::default());
    let prepared = poll_request();
    let RunnerToServer::LeaseRequest(request) = prepared.message() else {
        panic!("expected lease request")
    };

    let reply = client
        .exchange(&prepared, CancellationToken::new())
        .await
        .expect("stale session must use the success transport");
    let ServerToRunner::Error(error) = reply.message().message() else {
        panic!("expected stale-session protocol response")
    };
    assert_eq!(error.code(), RemoteErrorCode::StaleSession);
    assert!(!error.is_retryable());
    error
        .header()
        .validate_reply_for(request.header())
        .expect("stale-session correlation");

    running.stop().await;
}
