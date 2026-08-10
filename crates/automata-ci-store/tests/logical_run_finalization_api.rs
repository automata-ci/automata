use automata_ci_core::{JobConclusion, RunId, Sha256Digest, UnixMillis, WorkflowJobKey};
use automata_ci_store::{
    ClaimedLogicalRunFinalization, CommitLogicalRunFinalization, LogicalRunFinalizationClaimFence,
    LogicalRunFinalizationDescriptor, LogicalRunFinalizationGeneration,
    LogicalRunFinalizationOpenState, LogicalRunFinalizationTarget,
    LogicalRunFinalizationValueError, LogicalRunFinalizationWorkerId,
    LogicalRunFinalizationWorkflowStatus, LogicalRunJobResultEvidence, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, TenantScope,
};
use uuid::Uuid;

#[test]
fn aggregate_precedence_and_all_skipped_are_closed() {
    for (conclusions, expected) in [
        (vec![JobConclusion::Skipped], JobConclusion::Skipped),
        (
            vec![JobConclusion::Skipped, JobConclusion::Success],
            JobConclusion::Success,
        ),
        (
            vec![JobConclusion::Cancelled, JobConclusion::Success],
            JobConclusion::Cancelled,
        ),
        (
            vec![JobConclusion::TimedOut, JobConclusion::Cancelled],
            JobConclusion::TimedOut,
        ),
        (
            vec![JobConclusion::Failure, JobConclusion::TimedOut],
            JobConclusion::Failure,
        ),
    ] {
        let claimed = claimed(conclusions);
        let commit = CommitLogicalRunFinalization::new(&claimed, UnixMillis::new(300))
            .expect("live exact commit");
        assert_eq!(commit.conclusion(), expected);
    }
}

#[test]
fn preterminal_server_cancellation_overrides_job_precedence() {
    let descriptor = descriptor_with_status(
        vec![evidence(0, JobConclusion::Failure)],
        LogicalRunFinalizationWorkflowStatus::Cancelled,
    );
    let fence = LogicalRunFinalizationClaimFence::new(
        descriptor.target().clone(),
        worker(),
        LogicalRunFinalizationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(250),
        UnixMillis::new(400),
    )
    .expect("bounded fence");
    let claimed =
        ClaimedLogicalRunFinalization::new(descriptor, fence).expect("cancelled run claim");
    let commit = CommitLogicalRunFinalization::new(&claimed, UnixMillis::new(300))
        .expect("cancelled run commit");
    assert_eq!(commit.conclusion(), JobConclusion::Cancelled);
}

#[test]
fn zero_jobs_are_corruption_not_vacuous_skips() {
    let error = LogicalRunFinalizationDescriptor::new(
        target(),
        digest(1),
        LogicalRunFinalizationOpenState::Pending,
        1,
        UnixMillis::new(100),
        LogicalRunFinalizationOpenState::Pending,
        1,
        UnixMillis::new(100),
        LogicalRunFinalizationWorkflowStatus::Queued,
        UnixMillis::new(100),
        Vec::new(),
    )
    .expect_err("current logical admission cannot create a zero-job run");
    assert_eq!(error, LogicalRunFinalizationValueError::EmptyJobSet);
}

#[test]
fn descriptor_order_is_canonical_and_every_evidence_field_is_bound() {
    let current = descriptor(vec![
        evidence(1, JobConclusion::Success),
        evidence(0, JobConclusion::Skipped),
    ]);
    assert_eq!(current.jobs()[0].source_order(), 0);
    assert_eq!(current.jobs()[1].source_order(), 1);
    let same = descriptor(vec![
        evidence(0, JobConclusion::Skipped),
        evidence(1, JobConclusion::Success),
    ]);
    assert_eq!(current.evidence_digest(), same.evidence_digest());
    assert_eq!(current.descriptor_digest(), same.descriptor_digest());

    let changed = descriptor(vec![
        evidence(0, JobConclusion::Skipped),
        evidence(1, JobConclusion::Cancelled),
    ]);
    assert_ne!(current.evidence_digest(), changed.evidence_digest());
    assert_ne!(current.descriptor_digest(), changed.descriptor_digest());
}

#[test]
fn stale_or_mismatched_claims_fail_before_persistence() {
    let descriptor = descriptor(vec![evidence(0, JobConclusion::Success)]);
    let wrong = LogicalRunFinalizationClaimFence::new(
        descriptor.target().clone(),
        worker(),
        LogicalRunFinalizationGeneration::new(1).expect("generation"),
        digest(99),
        UnixMillis::new(200),
        UnixMillis::new(400),
    )
    .expect("bounded fence");
    assert_eq!(
        ClaimedLogicalRunFinalization::new(descriptor.clone(), wrong).expect_err("digest mismatch"),
        LogicalRunFinalizationValueError::ClaimDescriptorMismatch
    );

    let early = LogicalRunFinalizationClaimFence::new(
        descriptor.target().clone(),
        worker(),
        LogicalRunFinalizationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(150),
        UnixMillis::new(400),
    )
    .expect("bounded fence");
    assert_eq!(
        ClaimedLogicalRunFinalization::new(descriptor, early).expect_err("early claim"),
        LogicalRunFinalizationValueError::ClaimBeforeEvidence
    );

    let claimed = claimed(vec![JobConclusion::Success]);
    assert_eq!(
        CommitLogicalRunFinalization::new(&claimed, claimed.claim().expires_at())
            .expect_err("expiration is exclusive"),
        LogicalRunFinalizationValueError::CommitOutsideClaim
    );
}

fn claimed(conclusions: Vec<JobConclusion>) -> ClaimedLogicalRunFinalization {
    let descriptor = descriptor(
        conclusions
            .into_iter()
            .enumerate()
            .map(|(index, conclusion)| {
                evidence(u16::try_from(index).expect("small fixture"), conclusion)
            })
            .collect(),
    );
    let fence = LogicalRunFinalizationClaimFence::new(
        descriptor.target().clone(),
        worker(),
        LogicalRunFinalizationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(250),
        UnixMillis::new(400),
    )
    .expect("bounded fence");
    ClaimedLogicalRunFinalization::new(descriptor, fence).expect("exact claimed descriptor")
}

fn descriptor(jobs: Vec<LogicalRunJobResultEvidence>) -> LogicalRunFinalizationDescriptor {
    descriptor_with_status(jobs, LogicalRunFinalizationWorkflowStatus::Queued)
}

fn descriptor_with_status(
    jobs: Vec<LogicalRunJobResultEvidence>,
    workflow_status: LogicalRunFinalizationWorkflowStatus,
) -> LogicalRunFinalizationDescriptor {
    LogicalRunFinalizationDescriptor::new(
        target(),
        digest(1),
        LogicalRunFinalizationOpenState::Pending,
        1,
        UnixMillis::new(100),
        LogicalRunFinalizationOpenState::Pending,
        1,
        UnixMillis::new(100),
        workflow_status,
        UnixMillis::new(100),
        jobs,
    )
    .expect("complete canonical descriptor")
}

fn evidence(source_order: u16, conclusion: JobConclusion) -> LogicalRunJobResultEvidence {
    LogicalRunJobResultEvidence::new(
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(100 + u128::from(source_order)))
            .expect("logical job"),
        WorkflowJobKey::new(format!("job-{source_order}")).expect("logical key"),
        source_order,
        digest(10 + u8::try_from(source_order).expect("small fixture")),
        conclusion,
        matches!(conclusion, JobConclusion::Failure | JobConclusion::TimedOut),
        conclusion == JobConclusion::Cancelled,
        conclusion == JobConclusion::Skipped,
        1,
        digest(20 + u8::try_from(source_order).expect("small fixture")),
        0,
        digest(30 + u8::try_from(source_order).expect("small fixture")),
        0,
        digest(40 + u8::try_from(source_order).expect("small fixture")),
        digest(50 + u8::try_from(source_order).expect("small fixture")),
        UnixMillis::new(200 + i64::from(source_order)),
    )
    .expect("valid immutable evidence")
}

fn target() -> LogicalRunFinalizationTarget {
    LogicalRunFinalizationTarget::new(
        TenantScope::from_authenticated_tenant_id("run-finalization-api").expect("tenant"),
        RunId::from_uuid(Uuid::from_u128(1)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
    )
    .expect("target")
}

fn worker() -> LogicalRunFinalizationWorkerId {
    LogicalRunFinalizationWorkerId::from_uuid(Uuid::from_u128(3)).expect("worker")
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
