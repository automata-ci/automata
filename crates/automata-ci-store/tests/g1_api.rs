use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, Lease, LeaseId, RunId, RunnerId, RunnerSessionId,
    Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    AttemptAssignment, CommandCursor, CommandReplayDisposition, CommandReplayLimit,
    CommandReplayPage, CommandSequence, DocumentSchema, JobDependency, JobIrMetadata,
    MAX_JOB_IR_BYTES, ObjectKey, RoutingDocument, RoutingLabel, RunnerGeneration,
    RunnerOperationKind, RunnerProtocolVersion, RunnerSessionFence, RunnerSlotCount, SessionEpoch,
    StableRunnerSlot, WorkflowPlanRepository,
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
fn store_values_and_ports_remain_backend_neutral_and_dyn_compatible() {
    fn assert_port(_: &dyn WorkflowPlanRepository) {}
    let _ = assert_port;

    assert!(RunnerOperationKind::new("Automata.Invalid").is_err());
    assert_eq!(CommandCursor::initial().durable_value(), 0);
}
