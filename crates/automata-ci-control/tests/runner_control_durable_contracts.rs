use automata_ci_control::{
    lease::{
        repository::{
            RunnableAttemptRepository, RunnerClaimRepository, RunnerLeaseRequestRepository,
        },
        routing::{RunnerRoutingRepository, RunnerSlotAvailabilityRepository},
    },
    runner_control::{
        durable::{
            CurrentRunnerSessionRepository, RunnerControlTransactionRepository,
            RunnerLeaseOfferRepository, RunnerLogAdmissionRequest,
        },
        repository::{
            RunnerCommandOutbox, RunnerOperationReceiptRepository, RunnerSessionRepository,
        },
    },
};
use automata_ci_core::{
    AttemptId, FencingToken, LeaseGuard, LeaseId, LogSequence, LogStreamId, OperationId, RunnerId,
    RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    DocumentSchema, RunnerGeneration, RunnerOperationKind, RunnerOperationRequest,
    RunnerSessionFence, SessionEpoch,
};

#[test]
fn control_owned_repository_ports_are_object_safe() {
    #[allow(clippy::too_many_arguments)]
    fn accepts_ports(
        _: &dyn RunnerClaimRepository,
        _: &dyn RunnerLeaseRequestRepository,
        _: &dyn RunnerRoutingRepository,
        _: &dyn RunnerSlotAvailabilityRepository,
        _: &dyn RunnableAttemptRepository,
        _: &dyn RunnerSessionRepository,
        _: &dyn CurrentRunnerSessionRepository,
        _: &dyn RunnerLeaseOfferRepository,
        _: &dyn RunnerControlTransactionRepository,
        _: &dyn RunnerCommandOutbox,
        _: &dyn RunnerOperationReceiptRepository,
    ) {
    }

    let _ = accepts_ports;
}

#[test]
fn durable_log_sequence_stays_within_signed_storage_range() {
    let request = RunnerOperationRequest::new(
        RunnerSessionFence::new(
            RunnerSessionId::new(),
            RunnerId::new(),
            RunnerGeneration::new(1).expect("generation"),
            SessionEpoch::new(1).expect("epoch"),
        ),
        OperationId::new(),
        RunnerOperationKind::new("automata.runner.log-batch.v1").expect("kind"),
        Sha256Digest::from_bytes([5; 32]),
    );

    assert!(
        RunnerLogAdmissionRequest::new(
            request,
            AttemptId::new(),
            LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("fencing token")),
            LogStreamId::new(),
            DocumentSchema::new(1).expect("schema"),
            LogSequence::new(0),
            LogSequence::new(i64::MAX as u64 + 1),
            UnixMillis::new(1),
            false,
        )
        .is_err()
    );
}
