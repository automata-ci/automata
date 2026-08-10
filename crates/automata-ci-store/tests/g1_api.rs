use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, Lease, LeaseGuard, LeaseId, LogSequence,
    LogStreamId, OperationId, RunId, RunnerId, RunnerRequirements, RunnerSessionId, Sha256Digest,
    UnixMillis,
};
use automata_ci_store::{
    AttemptAssignment, BeginLeaseRequest, CancelJobCommandPayload, CancellationRepository,
    CommandCursor, CommandReplayDisposition, CommandReplayLimit, CommandReplayPage,
    CommandSequence, CompleteLeaseRequest, CurrentRunnerSessionRepository, DocumentSchema,
    JobDependency, JobIrMetadata, LeaseOfferCommandIdentity, LeaseRequestKey, MAX_JOB_IR_BYTES,
    ObjectKey, RevokedLeaseOfferFallback, RoutingDocument, RoutingLabel, RunnableAttempt,
    RunnableAttemptRepository, RunnableScanLimit, RunnerClaimRepository, RunnerCommandOutbox,
    RunnerControlTransactionRepository, RunnerGeneration, RunnerLeaseOfferRepository,
    RunnerLeaseRequestRepository, RunnerLogAdmissionRequest, RunnerOperationKind,
    RunnerOperationReceiptRepository, RunnerProtocolVersion, RunnerRoutingRepository,
    RunnerSessionFence, RunnerSessionRepository, RunnerSlotCount, SessionEpoch, StableRunnerSlot,
    WorkflowPlanRepository,
};

#[test]
fn durable_scalar_types_match_wire_ranges_and_core_digest_identity() {
    assert!(StableRunnerSlot::new(0).is_err());
    let first = StableRunnerSlot::new(1).expect("first slot");
    let last = StableRunnerSlot::new(u16::MAX).expect("last slot");
    assert_eq!(first.ordinal(), 1);
    assert_eq!(last.get(), u16::MAX);
    assert!(RunnerSlotCount::new(1).expect("capacity").contains(first));
    assert!(
        !RunnerSlotCount::new(1)
            .expect("capacity")
            .contains(StableRunnerSlot::new(2).expect("second slot"))
    );

    assert!(RunnerProtocolVersion::new(0).is_err());
    assert_eq!(
        RunnerProtocolVersion::new(u16::MAX)
            .expect("maximum protocol")
            .get(),
        u16::MAX
    );
    assert!(DocumentSchema::new(0).is_err());
    assert!(CommandSequence::new(0).is_err());
    assert!(CommandSequence::new(i64::MAX as u64).is_ok());
    assert!(CommandSequence::new(i64::MAX as u64 + 1).is_err());
    assert!(CommandReplayLimit::new(0).is_err());
    assert!(CommandReplayLimit::new(257).is_err());
    assert_eq!(CommandReplayLimit::new(256).expect("limit").get(), 256);

    let store_digest = automata_ci_store::Sha256Digest::from_bytes([9; 32]);
    let core_digest: Sha256Digest = store_digest;
    assert_eq!(core_digest.as_bytes(), &[9; 32]);
}

#[test]
fn replay_page_distinguishes_empty_exhaustion_from_saturation() {
    let exhausted = CommandReplayPage::new(Vec::new(), CommandReplayDisposition::Exhausted);
    let saturated = CommandReplayPage::new(Vec::new(), CommandReplayDisposition::Saturated);
    assert!(exhausted.is_empty());
    assert_eq!(exhausted.disposition(), CommandReplayDisposition::Exhausted);
    assert!(saturated.is_empty());
    assert_eq!(saturated.disposition(), CommandReplayDisposition::Saturated);
}

#[test]
fn durable_command_and_receipt_debug_never_expose_payload_bytes() {
    let secret = "job-scoped-runtime-token-fixture";
    let command = automata_ci_store::RunnerCommandPayload::new(
        DocumentSchema::new(2).expect("schema"),
        secret.as_bytes().to_vec(),
    )
    .expect("command payload");
    let response = automata_ci_store::RunnerOperationResponse::new(
        DocumentSchema::new(3).expect("schema"),
        secret.as_bytes().to_vec(),
    )
    .expect("receipt response");
    assert!(!format!("{command:?}").contains(secret));
    assert!(!format!("{response:?}").contains(secret));
}

#[test]
fn cancel_job_command_payload_is_exact_versioned_and_closed_to_extensions() {
    let payload = CancelJobCommandPayload::new(
        AttemptId::new(),
        LeaseGuard::new(LeaseId::new(), FencingToken::new(7).expect("fencing token")),
        RunnerProtocolVersion::new(1).expect("protocol"),
        "superseded by a newer run",
        UnixMillis::new(42),
    )
    .expect("typed cancellation");
    let encoded = payload.encode_json().expect("canonical JSON");
    assert_eq!(
        CancelJobCommandPayload::decode_json(&encoded).expect("round trip"),
        payload
    );

    let mut extended: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON value");
    extended
        .as_object_mut()
        .expect("JSON object")
        .insert("future_field".to_owned(), serde_json::json!(true));
    assert!(
        CancelJobCommandPayload::decode_json(
            &serde_json::to_vec(&extended).expect("extended JSON")
        )
        .is_err()
    );

    extended
        .as_object_mut()
        .expect("JSON object")
        .remove("future_field");
    extended["schema"] = serde_json::json!(2);
    assert!(
        CancelJobCommandPayload::decode_json(
            &serde_json::to_vec(&extended).expect("wrong-schema JSON")
        )
        .is_err()
    );
}

#[test]
fn lease_request_chain_values_bind_predecessor_and_exact_rpc_digest() {
    let fence = RunnerSessionFence::new(
        RunnerSessionId::new(),
        RunnerId::new(),
        RunnerGeneration::new(1).expect("generation"),
        SessionEpoch::new(1).expect("epoch"),
    );
    let slot = StableRunnerSlot::new(1).expect("slot");
    let first_operation = OperationId::new();
    let first = LeaseRequestKey::first(fence, first_operation, slot);
    let successor = LeaseRequestKey::successor(fence, OperationId::new(), slot, first_operation)
        .expect("successor");
    assert_eq!(first.acknowledges_operation_id(), None);
    assert_eq!(successor.acknowledges_operation_id(), Some(first_operation));
    assert_ne!(first.request_digest(), successor.request_digest());
    assert!(LeaseRequestKey::successor(fence, first_operation, slot, first_operation).is_err());

    let begin = BeginLeaseRequest::new(successor, Sha256Digest::from_bytes([8; 32]));
    assert_eq!(begin.request_key(), successor);
    assert_eq!(begin.request_digest(), Sha256Digest::from_bytes([8; 32]));
    let response = automata_ci_store::RunnerOperationResponse::new(
        DocumentSchema::new(1).expect("schema"),
        vec![1],
    )
    .expect("response");
    let complete =
        CompleteLeaseRequest::without_lease_offer(begin, response.clone(), UnixMillis::new(9));
    assert_eq!(complete.request(), begin);
    assert_eq!(complete.response(), &response);
    assert_eq!(complete.completed_at(), UnixMillis::new(9));
    assert!(complete.lease_offer_command().is_none());
    assert!(complete.revoked_lease_offer_response().is_none());

    let offer_identity = LeaseOfferCommandIdentity::new(
        fence,
        OperationId::new(),
        CommandSequence::new(1).expect("sequence"),
    );
    let revoked_response = automata_ci_store::RunnerOperationResponse::new(
        DocumentSchema::new(1).expect("schema"),
        vec![2],
    )
    .expect("revoked response");
    let fallback = RevokedLeaseOfferFallback::new(
        OperationId::new(),
        1_000,
        revoked_response.schema(),
        revoked_response.digest(),
    )
    .expect("typed fallback");
    let complete = CompleteLeaseRequest::for_lease_offer_with_fallback(
        begin,
        response,
        revoked_response.clone(),
        fallback,
        UnixMillis::new(10),
        offer_identity,
    )
    .expect("lease-offer completion");
    assert_eq!(complete.lease_offer_command(), Some(offer_identity));
    assert_eq!(
        complete.revoked_lease_offer_response(),
        Some(&revoked_response)
    );
    assert_eq!(complete.revoked_lease_offer_fallback(), Some(fallback));
}

#[test]
fn immutable_scheduler_metadata_is_bounded_and_fenced() {
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();
    let run_id = RunId::new();
    let runner_id = RunnerId::new();
    let session = RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        RunnerGeneration::new(1).expect("generation"),
        SessionEpoch::new(1).expect("epoch"),
    );
    let assignment = AttemptAssignment::new(session, StableRunnerSlot::new(1).expect("slot"));
    let lease_id = LeaseId::new();
    let fence = FencingToken::new(1).expect("fence");
    let lease = Lease::new(
        lease_id,
        attempt_id,
        runner_id,
        fence,
        UnixMillis::new(10),
        UnixMillis::new(100),
    )
    .expect("lease");
    assignment.validate_lease(&lease).expect("matching runner");

    let digest = Sha256Digest::from_bytes([3; 32]);
    assert!(
        JobIrMetadata::new(
            job_id,
            run_id,
            JobIrVersion::current(),
            0,
            digest,
            ObjectKey::new("jobs/ir").expect("key"),
        )
        .is_err()
    );
    assert!(
        JobIrMetadata::new(
            job_id,
            run_id,
            JobIrVersion::current(),
            MAX_JOB_IR_BYTES + 1,
            digest,
            ObjectKey::new("jobs/ir").expect("key"),
        )
        .is_err()
    );
    assert!(JobDependency::new(run_id, job_id, job_id).is_err());
    assert!(ObjectKey::new("../secret").is_err());
    assert!(RoutingDocument::new("[]").is_err());

    assert_eq!(
        RoutingLabel::new("LiNuX")
            .expect("case-insensitive routing label")
            .as_str(),
        "linux"
    );
}

#[test]
fn scheduler_and_durability_ports_remain_backend_neutral_and_dyn_compatible() {
    #[allow(clippy::too_many_arguments)]
    fn assert_ports(
        _: &dyn RunnerSessionRepository,
        _: &dyn RunnerRoutingRepository,
        _: &dyn RunnerCommandOutbox,
        _: &dyn RunnerOperationReceiptRepository,
        _: &dyn RunnerLeaseRequestRepository,
        _: &dyn RunnerClaimRepository,
        _: &dyn WorkflowPlanRepository,
        _: &dyn RunnableAttemptRepository,
        _: &dyn CancellationRepository,
        _: &dyn CurrentRunnerSessionRepository,
        _: &dyn RunnerLeaseOfferRepository,
        _: &dyn RunnerControlTransactionRepository,
    ) {
    }
    let _ = assert_ports;

    assert!(RunnableScanLimit::new(0).is_err());
    assert!(RunnableScanLimit::new(1001).is_err());
    assert!(RunnerOperationKind::new("Automata.Invalid").is_err());

    let ingress_request = automata_ci_store::RunnerOperationRequest::new(
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
            ingress_request,
            AttemptId::new(),
            LeaseGuard::new(LeaseId::new(), FencingToken::new(1).expect("fencing token")),
            LogStreamId::new(),
            DocumentSchema::new(1).expect("schema"),
            LogSequence::new(0),
            LogSequence::new(9_223_372_036_854_775_808),
            UnixMillis::new(1),
            false,
        )
        .is_err()
    );

    let candidate_job_id = JobId::new();
    let candidate_run_id = RunId::new();
    let candidate = RunnableAttempt::try_new(
        AttemptId::new(),
        candidate_job_id,
        candidate_run_id,
        UnixMillis::new(1),
        RunnerRequirements::default(),
        JobIrMetadata::new(
            candidate_job_id,
            candidate_run_id,
            JobIrVersion::current(),
            1,
            Sha256Digest::from_bytes([1; 32]),
            ObjectKey::new("job-ir").expect("key"),
        )
        .expect("metadata"),
    )
    .expect("candidate");
    assert_eq!(candidate.requirements(), &RunnerRequirements::default());
    assert_eq!(CommandCursor::initial().durable_value(), 0);
}
