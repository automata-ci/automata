use automata_core::{
    AttemptId, AttemptNumber, CORE_SCHEMA_VERSION, FencingToken, JobId, JobLifecycle, Lease,
    LeaseError, LeaseId, RunnerId, RunnerSessionId, UnixMillis,
};
use automata_store::{
    AttemptAssignment, AttemptSnapshot, AttemptSnapshotError, RunnerGeneration, RunnerSessionFence,
    SessionEpoch, StableRunnerSlot,
};

fn attempt_number() -> AttemptNumber {
    AttemptNumber::new(1).expect("positive attempt number")
}

fn lease(attempt_id: AttemptId, issued_at: i64, expires_at: i64) -> Lease {
    Lease::new(
        LeaseId::new(),
        attempt_id,
        runner_id(),
        FencingToken::new(7).expect("positive fence"),
        UnixMillis::new(issued_at),
        UnixMillis::new(expires_at),
    )
    .expect("valid lease")
}

fn runner_id() -> RunnerId {
    RunnerId::from_uuid(uuid::Uuid::from_u128(1))
}

fn assignment() -> AttemptAssignment {
    AttemptAssignment::new(
        RunnerSessionFence::new(
            RunnerSessionId::from_uuid(uuid::Uuid::from_u128(2)),
            runner_id(),
            RunnerGeneration::new(1).expect("generation"),
            SessionEpoch::new(1).expect("epoch"),
        ),
        StableRunnerSlot::new(1).expect("slot"),
    )
}

#[test]
fn builder_constructs_complete_inactive_and_active_snapshots() {
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();
    let fence = FencingToken::new(6).expect("positive fence");
    let inactive = AttemptSnapshot::builder(
        attempt_id,
        job_id,
        attempt_number(),
        JobLifecycle::Queued,
        UnixMillis::new(10),
        UnixMillis::new(10),
    )
    .with_retained_fencing_token(fence)
    .with_lease_failures(2)
    .build()
    .expect("valid inactive snapshot");

    assert_eq!(inactive.attempt_id(), attempt_id);
    assert_eq!(inactive.job_id(), job_id);
    assert_eq!(inactive.attempt_number(), attempt_number());
    assert_eq!(inactive.lifecycle(), JobLifecycle::Queued);
    assert_eq!(inactive.fencing_token(), Some(fence));
    assert_eq!(inactive.lease_id(), None);
    assert_eq!(inactive.runner_id(), None);
    assert_eq!(inactive.lease_issued_at(), None);
    assert_eq!(inactive.lease_expires_at(), None);
    assert_eq!(inactive.lease_failures(), 2);
    assert_eq!(inactive.queued_at(), UnixMillis::new(10));
    assert_eq!(inactive.changed_at(), UnixMillis::new(10));

    let active_lease = lease(attempt_id, 20, 40);
    let active = AttemptSnapshot::builder(
        attempt_id,
        job_id,
        attempt_number(),
        JobLifecycle::Running,
        UnixMillis::new(10),
        UnixMillis::new(30),
    )
    .with_active_lease(active_lease.clone(), assignment())
    .build()
    .expect("valid active snapshot");

    assert_eq!(active.fencing_token(), Some(active_lease.fencing_token()));
    assert_eq!(active.lease_id(), Some(active_lease.lease_id()));
    assert_eq!(active.runner_id(), Some(active_lease.runner_id()));
    assert_eq!(active.lease_issued_at(), Some(active_lease.issued_at()));
    assert_eq!(active.lease_expires_at(), Some(active_lease.expires_at()));
}

#[test]
fn builder_enforces_lifecycle_lease_consistency() {
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();

    for lifecycle in [
        JobLifecycle::Leased,
        JobLifecycle::Preparing,
        JobLifecycle::Running,
        JobLifecycle::Cancelling,
        JobLifecycle::Finalizing,
    ] {
        assert_eq!(
            AttemptSnapshot::builder(
                attempt_id,
                job_id,
                attempt_number(),
                lifecycle,
                UnixMillis::new(10),
                UnixMillis::new(20),
            )
            .build(),
            Err(AttemptSnapshotError::ActiveLifecycleMissingLease(lifecycle))
        );
    }

    for lifecycle in [
        JobLifecycle::Queued,
        JobLifecycle::Succeeded,
        JobLifecycle::Failed,
        JobLifecycle::Cancelled,
        JobLifecycle::TimedOut,
        JobLifecycle::Skipped,
        JobLifecycle::Lost,
    ] {
        assert_eq!(
            AttemptSnapshot::builder(
                attempt_id,
                job_id,
                attempt_number(),
                lifecycle,
                UnixMillis::new(10),
                UnixMillis::new(20),
            )
            .with_active_lease(lease(attempt_id, 15, 30), assignment())
            .build(),
            Err(AttemptSnapshotError::InactiveLifecycleHasLease(lifecycle))
        );
    }
}

#[test]
fn builder_enforces_state_and_lease_timestamps() {
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();

    assert_eq!(
        AttemptSnapshot::builder(
            attempt_id,
            job_id,
            attempt_number(),
            JobLifecycle::Running,
            UnixMillis::new(11),
            UnixMillis::new(12),
        )
        .with_active_lease(lease(attempt_id, 10, 20), assignment())
        .build(),
        Err(AttemptSnapshotError::LeaseIssuedBeforeQueued {
            queued_at: UnixMillis::new(11),
            issued_at: UnixMillis::new(10),
        })
    );

    assert_eq!(
        AttemptSnapshot::builder(
            attempt_id,
            job_id,
            attempt_number(),
            JobLifecycle::Queued,
            UnixMillis::new(11),
            UnixMillis::new(10),
        )
        .build(),
        Err(AttemptSnapshotError::ChangedBeforeQueued {
            queued_at: UnixMillis::new(11),
            changed_at: UnixMillis::new(10),
        })
    );

    assert_eq!(
        AttemptSnapshot::builder(
            attempt_id,
            job_id,
            attempt_number(),
            JobLifecycle::Running,
            UnixMillis::new(0),
            UnixMillis::new(9),
        )
        .with_active_lease(lease(attempt_id, 10, 20), assignment())
        .build(),
        Err(AttemptSnapshotError::ChangedBeforeLeaseIssuance {
            issued_at: UnixMillis::new(10),
            changed_at: UnixMillis::new(9),
        })
    );

    for changed_at in [20, 21] {
        assert_eq!(
            AttemptSnapshot::builder(
                attempt_id,
                job_id,
                attempt_number(),
                JobLifecycle::Running,
                UnixMillis::new(0),
                UnixMillis::new(changed_at),
            )
            .with_active_lease(lease(attempt_id, 10, 20), assignment())
            .build(),
            Err(AttemptSnapshotError::ChangedOutsideLease {
                changed_at: UnixMillis::new(changed_at),
                expires_at: UnixMillis::new(20),
            })
        );
    }
}

#[test]
fn builder_rejects_foreign_and_invalid_leases() {
    let attempt_id = AttemptId::new();
    let other_attempt_id = AttemptId::new();
    let job_id = JobId::new();
    let foreign_lease = lease(other_attempt_id, 10, 20);

    assert_eq!(
        AttemptSnapshot::builder(
            attempt_id,
            job_id,
            attempt_number(),
            JobLifecycle::Running,
            UnixMillis::new(0),
            UnixMillis::new(10),
        )
        .with_active_lease(foreign_lease, assignment())
        .build(),
        Err(AttemptSnapshotError::LeaseAttemptMismatch {
            snapshot_attempt_id: attempt_id,
            lease_attempt_id: other_attempt_id,
        })
    );

    let valid_lease = lease(attempt_id, 10, 20);
    let mut serialized = serde_json::to_value(valid_lease).expect("serialize lease");
    serialized["schema_version"] = serde_json::json!(0);
    let invalid_lease: Lease = serde_json::from_value(serialized).expect("deserialize lease");
    assert_eq!(
        AttemptSnapshot::builder(
            attempt_id,
            job_id,
            attempt_number(),
            JobLifecycle::Running,
            UnixMillis::new(0),
            UnixMillis::new(10),
        )
        .with_active_lease(invalid_lease, assignment())
        .build(),
        Err(AttemptSnapshotError::InvalidLease(
            LeaseError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: 0,
            }
        ))
    );
}
