use automata_ci_core::{
    AttemptId, AttemptNumber, AttemptStateError, FenceError, JobAttemptState, JobId, JobLifecycle,
    Lease, LeaseError, LeaseId, RunnerId, UnixMillis,
};

fn queued_attempt() -> JobAttemptState {
    JobAttemptState::new(
        AttemptId::new(),
        JobId::new(),
        AttemptNumber::new(1).expect("valid attempt number"),
    )
}

#[test]
fn attempt_and_lease_schemas_reject_noncurrent_versions() {
    let attempt = queued_attempt();
    let mut encoded_attempt = serde_json::to_value(&attempt).expect("serialize attempt");
    encoded_attempt["schema_version"] = serde_json::json!(u16::MAX);
    let decoded_attempt: JobAttemptState =
        serde_json::from_value(encoded_attempt).expect("decode structurally valid attempt");
    assert_eq!(
        decoded_attempt.validate(),
        Err(AttemptStateError::UnsupportedSchema {
            supported: 1,
            received: u16::MAX,
        })
    );

    let lease = JobAttemptState::new(
        AttemptId::new(),
        JobId::new(),
        AttemptNumber::new(1).expect("valid attempt number"),
    )
    .acquire_lease(
        LeaseId::new(),
        RunnerId::new(),
        UnixMillis::new(1_000),
        UnixMillis::new(2_000),
    )
    .expect("lease");
    let mut encoded_lease = serde_json::to_value(&lease).expect("serialize lease");
    encoded_lease["schema_version"] = serde_json::json!(u16::MAX);
    let decoded_lease: Lease =
        serde_json::from_value(encoded_lease).expect("decode structurally valid lease");
    assert_eq!(
        decoded_lease.validate(),
        Err(LeaseError::UnsupportedSchema {
            supported: 1,
            received: u16::MAX,
        })
    );
}

#[test]
fn superseded_lease_is_rejected_by_stale_fencing_token() {
    let mut attempt = queued_attempt();
    let first = attempt
        .acquire_lease(
            LeaseId::new(),
            RunnerId::new(),
            UnixMillis::new(1_000),
            UnixMillis::new(2_000),
        )
        .expect("first lease");
    attempt
        .apply_transition(first.guard(), JobLifecycle::Preparing)
        .expect("prepare first lease");
    attempt
        .apply_transition(first.guard(), JobLifecycle::Running)
        .expect("run first lease");
    attempt
        .apply_transition(first.guard(), JobLifecycle::Queued)
        .expect("requeue expired lease");

    let second = attempt
        .acquire_lease(
            LeaseId::new(),
            RunnerId::new(),
            UnixMillis::new(2_001),
            UnixMillis::new(3_000),
        )
        .expect("replacement lease");
    assert!(second.fencing_token() > first.fencing_token());
    assert_eq!(
        attempt.verify_fence(first.guard()),
        Err(FenceError::StaleFencingToken {
            expected: second.fencing_token(),
            received: first.fencing_token(),
        }),
    );
    attempt
        .verify_fence(second.guard())
        .expect("current lease remains authorized");
}

#[test]
fn preparing_job_can_skip_without_inventing_running_and_revokes_lease() {
    let mut attempt = queued_attempt();
    let lease = attempt
        .acquire_lease(
            LeaseId::new(),
            RunnerId::new(),
            UnixMillis::new(1_000),
            UnixMillis::new(2_000),
        )
        .expect("lease");
    attempt
        .apply_transition(lease.guard(), JobLifecycle::Preparing)
        .expect("prepare leased job");
    attempt
        .apply_transition(lease.guard(), JobLifecycle::Skipped)
        .expect("resolve false job condition");

    assert_eq!(attempt.lifecycle(), JobLifecycle::Skipped);
    assert!(attempt.active_lease().is_none());
    assert_eq!(
        attempt.verify_fence(lease.guard()),
        Err(FenceError::NoActiveLease)
    );
}

#[test]
fn lease_interval_and_renewal_must_advance() {
    let mut attempt = queued_attempt();
    assert!(matches!(
        attempt.acquire_lease(
            LeaseId::new(),
            RunnerId::new(),
            UnixMillis::new(10),
            UnixMillis::new(10),
        ),
        Err(AttemptStateError::Lease(LeaseError::InvalidInterval { .. }))
    ));

    let lease = attempt
        .acquire_lease(
            LeaseId::new(),
            RunnerId::new(),
            UnixMillis::new(10),
            UnixMillis::new(20),
        )
        .expect("valid lease");
    assert!(matches!(
        attempt.renew_lease(lease.guard(), UnixMillis::new(20)),
        Err(AttemptStateError::Lease(
            LeaseError::RenewalDoesNotExtend { .. }
        ))
    ));
}
