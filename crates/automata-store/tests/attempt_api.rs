use automata_core::{
    AttemptId, AttemptNumber, FencingToken, JobId, JobLifecycle, LeaseGuard, LeaseId, RunnerId,
    RunnerSessionId, UnixMillis,
};
use automata_store::{
    AcquireLease, AttemptCommandError, ConcludeQueuedAttempt, InternalAttemptRepository,
    QueuedAttempt, RenewLease, RunnerGeneration, RunnerSessionFence, SessionEpoch,
    StableRunnerSlot, TenantAttemptQuery, TransitionAttempt,
};

fn session(runner_id: RunnerId) -> RunnerSessionFence {
    RunnerSessionFence::new(
        RunnerSessionId::new(),
        runner_id,
        RunnerGeneration::new(1).expect("generation"),
        SessionEpoch::new(1).expect("epoch"),
    )
}

#[test]
fn commands_are_constructed_through_validated_read_only_apis() {
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();
    let runner_id = RunnerId::new();
    let session = session(runner_id);
    let slot = StableRunnerSlot::new(1).expect("slot");
    let lease_id = LeaseId::new();
    let guard = LeaseGuard::new(lease_id, FencingToken::new(1).expect("fence"));

    let queued = QueuedAttempt::new(
        attempt_id,
        job_id,
        AttemptNumber::new(2).expect("attempt number"),
        UnixMillis::new(10),
    );
    assert_eq!(queued.attempt_id(), attempt_id);
    assert_eq!(queued.job_id(), job_id);
    assert_eq!(queued.attempt_number().get(), 2);
    assert_eq!(queued.queued_at(), UnixMillis::new(10));

    let acquisition = AcquireLease::new(
        attempt_id,
        lease_id,
        session,
        slot,
        UnixMillis::new(20),
        UnixMillis::new(30),
    )
    .expect("valid acquisition");
    assert_eq!(acquisition.attempt_id(), attempt_id);
    assert_eq!(acquisition.lease_id(), lease_id);
    assert_eq!(acquisition.runner_id(), runner_id);
    assert_eq!(acquisition.session(), session);
    assert_eq!(acquisition.slot(), slot);
    assert_eq!(acquisition.observed_at(), UnixMillis::new(20));
    assert_eq!(acquisition.expires_at(), UnixMillis::new(30));

    let renewal = RenewLease::new(
        attempt_id,
        session,
        guard,
        UnixMillis::new(21),
        UnixMillis::new(40),
    )
    .expect("valid renewal");
    assert_eq!(renewal.attempt_id(), attempt_id);
    assert_eq!(renewal.runner_id(), runner_id);
    assert_eq!(renewal.guard(), guard);
    assert_eq!(renewal.observed_at(), UnixMillis::new(21));
    assert_eq!(renewal.expires_at(), UnixMillis::new(40));

    let transition = TransitionAttempt::new(
        attempt_id,
        session,
        guard,
        JobLifecycle::Preparing,
        UnixMillis::new(22),
    );
    assert_eq!(transition.attempt_id(), attempt_id);
    assert_eq!(transition.runner_id(), runner_id);
    assert_eq!(transition.guard(), guard);
    assert_eq!(transition.next(), JobLifecycle::Preparing);
    assert_eq!(transition.observed_at(), UnixMillis::new(22));

    let conclusion =
        ConcludeQueuedAttempt::new(attempt_id, JobLifecycle::Skipped, UnixMillis::new(23))
            .expect("valid conclusion");
    assert_eq!(conclusion.attempt_id(), attempt_id);
    assert_eq!(conclusion.conclusion(), JobLifecycle::Skipped);
    assert_eq!(conclusion.observed_at(), UnixMillis::new(23));
}

#[test]
fn invariant_bearing_commands_reject_invalid_construction() {
    let attempt_id = AttemptId::new();
    let runner_id = RunnerId::new();
    let session = session(runner_id);
    let lease_id = LeaseId::new();
    let guard = LeaseGuard::new(lease_id, FencingToken::new(1).expect("fence"));

    for expiration in [UnixMillis::new(20), UnixMillis::new(19)] {
        assert_eq!(
            AcquireLease::new(
                attempt_id,
                lease_id,
                session,
                StableRunnerSlot::new(1).expect("slot"),
                UnixMillis::new(20),
                expiration,
            ),
            Err(AttemptCommandError::InvalidLeaseInterval)
        );
        assert_eq!(
            RenewLease::new(attempt_id, session, guard, UnixMillis::new(20), expiration,),
            Err(AttemptCommandError::InvalidLeaseInterval)
        );
    }

    assert_eq!(
        ConcludeQueuedAttempt::new(attempt_id, JobLifecycle::Succeeded, UnixMillis::new(20),),
        Err(AttemptCommandError::InvalidQueuedConclusion(
            JobLifecycle::Succeeded
        ))
    );
}

#[test]
fn async_ports_remain_dyn_compatible() {
    fn require_send_sync<T: ?Sized + Send + Sync>() {}

    require_send_sync::<dyn InternalAttemptRepository>();
    require_send_sync::<dyn TenantAttemptQuery>();
}
