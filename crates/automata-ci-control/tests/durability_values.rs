use automata_ci_control::{
    cancellation::{CancelJobCommandPayload, CancellationRepository},
    lease::{
        BeginLeaseRequest, CompleteLeaseRequest, LeaseRequestKey, RevokedLeaseOfferFallback,
        RunnableAttempt, RunnableScanLimit,
    },
};
use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, LeaseGuard, LeaseId, OperationId, RunId,
    RunnerId, RunnerRequirements, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    CommandSequence, DocumentSchema, JobIrMetadata, LeaseOfferCommandIdentity, ObjectKey,
    RunnerGeneration, RunnerOperationResponse, RunnerProtocolVersion, RunnerSessionFence,
    SessionEpoch, StableRunnerSlot,
};

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
    let response = RunnerOperationResponse::new(DocumentSchema::new(1).expect("schema"), vec![1])
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
    let revoked_response =
        RunnerOperationResponse::new(DocumentSchema::new(1).expect("schema"), vec![2])
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
fn control_values_and_ports_remain_backend_neutral_and_dyn_compatible() {
    fn assert_port(_: &dyn CancellationRepository) {}
    let _ = assert_port;

    assert!(RunnableScanLimit::new(0).is_err());
    assert!(RunnableScanLimit::new(1001).is_err());

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
}
