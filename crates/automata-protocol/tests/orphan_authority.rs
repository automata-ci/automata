use automata_core::{
    Architecture, IsolationLevel, JobIrVersionRange, OperatingSystem, OperationId,
    RunnerCapabilities, RunnerId, RunnerPlatform, RunnerSessionId, SandboxCapabilities, UnixMillis,
};
use automata_protocol::{
    CommandCursor, HandshakeErrorCode, HandshakeRejected, MessageValidationError,
    OrphanDeliveryPermissions, RunnerHello, SUPPORTED_PROTOCOL_RANGE, SessionOrphanAuthorization,
    SessionResume,
};

fn hello(resume: Option<RunnerSessionId>) -> RunnerHello {
    let capabilities = RunnerCapabilities::new(
        RunnerId::new(),
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_sandbox(SandboxCapabilities::new(IsolationLevel::SharedKernel, []));
    let hello = RunnerHello::new(
        OperationId::new(),
        SUPPORTED_PROTOCOL_RANGE,
        JobIrVersionRange::current(),
        capabilities,
        UnixMillis::new(10),
    );
    match resume {
        Some(session_id) => {
            hello.with_resume(SessionResume::new(session_id, CommandCursor::initial()))
        }
        None => hello,
    }
}

fn authorization(session_id: RunnerSessionId) -> SessionOrphanAuthorization {
    SessionOrphanAuthorization::new(
        session_id,
        OrphanDeliveryPermissions::new(true, true, false),
    )
}

#[test]
fn non_resumable_authority_is_bound_to_the_exact_correlated_resume() {
    let session_id = RunnerSessionId::new();
    let hello = hello(Some(session_id));
    let rejection = HandshakeRejected::session_not_resumable(
        OperationId::new(),
        hello.operation_id(),
        SUPPORTED_PROTOCOL_RANGE,
        authorization(session_id),
        "session is definitively no longer resumable",
    );

    assert_eq!(rejection.validate_for(&hello), Ok(()));
    let permissions = rejection
        .orphan_recovery()
        .expect("recovery authority")
        .permissions();
    assert!(permissions.terminal_result());
    assert!(permissions.log_delivery());
    assert!(!permissions.lease_rejection());
}

#[test]
fn only_explicit_session_authority_can_authorize_orphan_recovery() {
    let session_id = RunnerSessionId::new();
    let hello = hello(Some(session_id));
    let missing = HandshakeRejected::new(
        OperationId::new(),
        hello.operation_id(),
        HandshakeErrorCode::SessionNotResumable,
        SUPPORTED_PROTOCOL_RANGE,
        "missing authority",
    );
    assert_eq!(missing.validate_for(&hello), Ok(()));
    assert_eq!(missing.orphan_recovery(), None);

    let unauthorized = HandshakeRejected::new(
        OperationId::new(),
        hello.operation_id(),
        HandshakeErrorCode::Unauthorized,
        SUPPORTED_PROTOCOL_RANGE,
        "not authorized",
    )
    .with_orphan_recovery(authorization(session_id));
    assert_eq!(
        unauthorized.validate_for(&hello),
        Err(MessageValidationError::UnexpectedOrphanRecoveryAuthorization),
    );
}

#[test]
fn orphan_authority_rejects_missing_or_different_resume_claims() {
    let authorized_session = RunnerSessionId::new();
    let without_resume = hello(None);
    let rejection = HandshakeRejected::session_not_resumable(
        OperationId::new(),
        without_resume.operation_id(),
        SUPPORTED_PROTOCOL_RANGE,
        authorization(authorized_session),
        "invalidated",
    );
    assert_eq!(
        rejection.validate_for(&without_resume),
        Err(MessageValidationError::OrphanRecoveryWithoutResume),
    );

    let different = hello(Some(RunnerSessionId::new()));
    let rejection = HandshakeRejected::session_not_resumable(
        OperationId::new(),
        different.operation_id(),
        SUPPORTED_PROTOCOL_RANGE,
        authorization(authorized_session),
        "invalidated",
    );
    assert!(matches!(
        rejection.validate_for(&different),
        Err(MessageValidationError::OrphanRecoverySessionMismatch { .. }),
    ));
}
