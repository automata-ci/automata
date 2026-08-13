use std::time::Duration;

use automata_ci_core::{
    Architecture, AttemptId, JobId, JobLifecycle, OperatingSystem, RunnerCapabilities, RunnerId,
    RunnerPlatform, RunnerRequirements, RunnerSessionId, UnixMillis,
};
use automata_ci_store::{
    ArtifactCounts, ArtifactReservationKind, ArtifactReservations, ArtifactState,
    BuiltinSecretCleanupCounts, BuiltinSecretCleanupStatus, ControlPlaneCapacityCandidate,
    ControlPlaneCapacityRunner, ControlPlaneCapacitySnapshot, ControlPlaneStateSnapshot,
    ControlPlaneStateSnapshotRequest, ControlPlaneStateValueError, DatabasePoolSnapshot,
    JobAttemptCounts, LeaseCounts, LeaseState, LogicalActivationCounts, LogicalActivationState,
    LogicalJobCounts, LogicalJobState, LogicalWorkflowRunCounts, LogicalWorkflowRunState,
    MAX_CONTROL_PLANE_CAPACITY_CANDIDATES, MAX_CONTROL_PLANE_CAPACITY_RUNNERS,
    MAX_CONTROL_PLANE_CAPACITY_SLOTS_PER_RUNNER, RunnerCounts, RunnerDesiredState,
    RunnerGeneration, RunnerObservedState, RunnerSessionCounts, RunnerSessionFence,
    RunnerSessionState, RunnerSlotCount, SessionEpoch, WorkflowRunCounts, WorkflowRunStatus,
};

#[test]
fn closed_snapshot_model_preserves_every_aggregate_without_identifiers() {
    let snapshot = populated_control_plane_snapshot();

    assert_eq!(
        snapshot.workflow_runs().get(WorkflowRunStatus::InProgress),
        2
    );
    assert_eq!(snapshot.job_attempts().get(JobLifecycle::Queued), 3);
    assert_eq!(snapshot.job_attempts().get(JobLifecycle::Running), 5);
    assert_eq!(
        snapshot
            .runners()
            .get(RunnerObservedState::Online, RunnerDesiredState::Draining),
        7
    );
    assert_eq!(snapshot.runner_sessions().get(RunnerSessionState::Live), 11);
    assert_eq!(snapshot.queue_depth(), 3);
    assert_eq!(snapshot.queue_oldest_at(), Some(UnixMillis::new(1_000)));
    assert_eq!(
        snapshot
            .logical_workflow_runs()
            .get(LogicalWorkflowRunState::Active),
        41
    );
    assert_eq!(snapshot.logical_jobs().get(LogicalJobState::Pending), 43);
    assert_eq!(
        snapshot
            .logical_activations()
            .oldest_at(LogicalActivationState::Pending),
        Some(UnixMillis::new(500))
    );
    assert_eq!(snapshot.activation_publications(), 47);
    assert_eq!(snapshot.materialized_instances(), 53);
    assert_eq!(snapshot.leases().get(LeaseState::NearExpiry), 13);
    assert_eq!(snapshot.pending_commands(), 17);
    assert_eq!(
        snapshot.pending_commands_oldest_at(),
        Some(UnixMillis::new(2_000))
    );
    assert_eq!(snapshot.pending_cancellation_intents(), 18);
    assert_eq!(
        snapshot.pending_cancellation_intents_oldest_at(),
        Some(UnixMillis::new(2_500))
    );
    assert_eq!(
        snapshot
            .builtin_secret_cleanup()
            .get(BuiltinSecretCleanupStatus::Pending),
        59
    );
    assert_eq!(
        snapshot
            .builtin_secret_cleanup()
            .oldest_created_at(BuiltinSecretCleanupStatus::DeadLetter),
        Some(UnixMillis::new(7_000))
    );
    assert_eq!(snapshot.artifacts().get(ArtifactState::PendingUpload), 19);
    assert_eq!(
        snapshot.artifacts().get(ArtifactState::PublicationReserved),
        23
    );
    assert_eq!(snapshot.artifacts().get(ArtifactState::Finalized), 29);
    assert_eq!(
        snapshot
            .artifact_reservations()
            .get(ArtifactReservationKind::Block),
        31
    );
    assert_eq!(
        snapshot
            .artifact_reservations()
            .oldest_at(ArtifactReservationKind::Manifest),
        Some(UnixMillis::new(4_000))
    );
}

fn populated_control_plane_snapshot() -> ControlPlaneStateSnapshot {
    let mut runs = WorkflowRunCounts::default();
    runs.set(WorkflowRunStatus::InProgress, 2);
    let mut attempts = JobAttemptCounts::default();
    attempts.set(JobLifecycle::Queued, 3);
    attempts.set(JobLifecycle::Running, 5);
    let mut runners = RunnerCounts::default();
    runners.set(RunnerObservedState::Online, RunnerDesiredState::Draining, 7);
    let mut sessions = RunnerSessionCounts::default();
    sessions.set(RunnerSessionState::Live, 11);
    let mut leases = LeaseCounts::default();
    leases.set(LeaseState::NearExpiry, 13);
    let mut artifacts = ArtifactCounts::default();
    artifacts.set(ArtifactState::PendingUpload, 19);
    artifacts.set(ArtifactState::PublicationReserved, 23);
    artifacts.set(ArtifactState::Finalized, 29);
    let mut reservations = ArtifactReservations::default();
    reservations
        .set(
            ArtifactReservationKind::Block,
            31,
            Some(UnixMillis::new(3_000)),
        )
        .expect("consistent block reservations");
    reservations
        .set(
            ArtifactReservationKind::Manifest,
            37,
            Some(UnixMillis::new(4_000)),
        )
        .expect("consistent manifest reservations");
    let mut builtin_secret_cleanup = BuiltinSecretCleanupCounts::default();
    for (status, count, oldest_created_at) in [
        (
            BuiltinSecretCleanupStatus::Pending,
            59,
            UnixMillis::new(5_000),
        ),
        (
            BuiltinSecretCleanupStatus::InProgress,
            61,
            UnixMillis::new(6_000),
        ),
        (
            BuiltinSecretCleanupStatus::DeadLetter,
            67,
            UnixMillis::new(7_000),
        ),
    ] {
        builtin_secret_cleanup
            .set(status, count, Some(oldest_created_at))
            .expect("consistent built-in secret cleanup aggregate");
    }

    let mut logical_runs = LogicalWorkflowRunCounts::default();
    logical_runs.set(LogicalWorkflowRunState::Active, 41);
    let mut logical_jobs = LogicalJobCounts::default();
    logical_jobs.set(LogicalJobState::Pending, 43);
    let mut logical_activations = LogicalActivationCounts::default();
    logical_activations
        .set(
            LogicalActivationState::Pending,
            43,
            Some(UnixMillis::new(500)),
        )
        .expect("consistent logical activation backlog");

    ControlPlaneStateSnapshot::new(
        runs,
        attempts,
        runners,
        sessions,
        3,
        Some(UnixMillis::new(1_000)),
        leases,
        17,
        Some(UnixMillis::new(2_000)),
        18,
        Some(UnixMillis::new(2_500)),
        artifacts,
        reservations,
    )
    .expect("consistent aggregate snapshot")
    .with_builtin_secret_cleanup(builtin_secret_cleanup)
    .with_logical_orchestration(
        logical_runs,
        logical_jobs,
        logical_activations,
        47,
        53,
        0,
        None,
        Vec::new(),
        Vec::new(),
    )
    .expect("consistent logical aggregate snapshot")
}

#[test]
fn snapshot_rejects_oldest_timestamp_count_mismatches() {
    assert_control_plane_oldest_timestamp_mismatches_reject();

    let mut reservations = ArtifactReservations::default();
    assert!(
        reservations
            .set(ArtifactReservationKind::Block, 1, None)
            .is_err()
    );
    assert!(
        reservations
            .set(
                ArtifactReservationKind::Manifest,
                0,
                Some(UnixMillis::new(1)),
            )
            .is_err()
    );

    let mut logical_activations = LogicalActivationCounts::default();
    assert!(
        logical_activations
            .set(LogicalActivationState::Pending, 1, None)
            .is_err()
    );

    let mut builtin_secret_cleanup = BuiltinSecretCleanupCounts::default();
    assert!(
        builtin_secret_cleanup
            .set(BuiltinSecretCleanupStatus::Pending, 1, None)
            .is_err()
    );
    assert!(
        builtin_secret_cleanup
            .set(
                BuiltinSecretCleanupStatus::DeadLetter,
                0,
                Some(UnixMillis::new(1)),
            )
            .is_err()
    );
    assert!(
        logical_activations
            .set(LogicalActivationState::Expired, 0, Some(UnixMillis::new(1)),)
            .is_err()
    );

    assert!(
        ControlPlaneStateSnapshot::empty()
            .with_logical_orchestration(
                LogicalWorkflowRunCounts::default(),
                LogicalJobCounts::default(),
                LogicalActivationCounts::default(),
                0,
                0,
                1,
                None,
                Vec::new(),
                Vec::new(),
            )
            .is_err()
    );
    assert!(
        ControlPlaneStateSnapshot::empty()
            .with_logical_orchestration(
                LogicalWorkflowRunCounts::default(),
                LogicalJobCounts::default(),
                LogicalActivationCounts::default(),
                0,
                0,
                1,
                Some(UnixMillis::new(1)),
                Vec::new(),
                Vec::new(),
            )
            .is_err()
    );
}

fn assert_control_plane_oldest_timestamp_mismatches_reject() {
    let common = (
        WorkflowRunCounts::default(),
        JobAttemptCounts::default(),
        RunnerCounts::default(),
        RunnerSessionCounts::default(),
        LeaseCounts::default(),
    );
    assert!(
        ControlPlaneStateSnapshot::new(
            common.0,
            common.1,
            common.2,
            common.3,
            0,
            Some(UnixMillis::new(1)),
            common.4,
            0,
            None,
            0,
            None,
            ArtifactCounts::default(),
            ArtifactReservations::default(),
        )
        .is_err()
    );
    assert!(
        ControlPlaneStateSnapshot::new(
            common.0,
            common.1,
            common.2,
            common.3,
            0,
            None,
            common.4,
            1,
            None,
            0,
            None,
            ArtifactCounts::default(),
            ArtifactReservations::default(),
        )
        .is_err()
    );
    assert!(
        ControlPlaneStateSnapshot::new(
            common.0,
            common.1,
            common.2,
            common.3,
            0,
            None,
            common.4,
            0,
            None,
            1,
            None,
            ArtifactCounts::default(),
            ArtifactReservations::default(),
        )
        .is_err()
    );
}

#[test]
fn request_cutoff_and_database_pool_math_are_exact() {
    let request =
        ControlPlaneStateSnapshotRequest::new(UnixMillis::new(10_000), Duration::from_mins(1))
            .expect("bounded observation request");
    assert_eq!(request.observed_at(), UnixMillis::new(10_000));
    assert_eq!(request.near_expiry_at(), UnixMillis::new(70_000));
    assert!(ControlPlaneStateSnapshotRequest::new(UnixMillis::new(0), Duration::ZERO).is_err());
    assert!(
        ControlPlaneStateSnapshotRequest::new(UnixMillis::new(0), Duration::from_micros(1_500))
            .is_err()
    );

    let pool = DatabasePoolSnapshot::new(20, 12, 7).expect("consistent pool occupancy");
    assert_eq!(pool.maximum(), 20);
    assert_eq!(pool.open(), 12);
    assert_eq!(pool.idle(), 7);
    assert_eq!(pool.in_use(), 5);
    assert!(DatabasePoolSnapshot::new(20, 12, 13).is_err());
    assert!(DatabasePoolSnapshot::new(10, 12, 7).is_err());
}

#[test]
fn capacity_inputs_enforce_hard_bounds_and_redact_internal_identity() {
    let attempt_id = AttemptId::new();
    let job_id = JobId::new();
    let candidate = ControlPlaneCapacityCandidate::new(
        "private-tenant".to_owned(),
        attempt_id,
        job_id,
        UnixMillis::new(1),
        RunnerRequirements::default(),
    );
    let candidate_debug = format!("{candidate:?}");
    assert!(!candidate_debug.contains("private-tenant"));
    assert!(!candidate_debug.contains(&attempt_id.to_string()));
    assert!(!candidate_debug.contains(&job_id.to_string()));

    let excessive_candidates = vec![candidate; MAX_CONTROL_PLANE_CAPACITY_CANDIDATES + 1];
    assert_eq!(
        ControlPlaneCapacitySnapshot::try_new(
            u64::try_from(excessive_candidates.len()).expect("bounded test length"),
            excessive_candidates,
            Vec::new(),
        )
        .expect_err("candidate sentinel row must reject the snapshot"),
        ControlPlaneStateValueError::CapacitySnapshotTooLarge
    );

    let runner_id = RunnerId::new();
    let session_id = RunnerSessionId::new();
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    );
    let runner = ControlPlaneCapacityRunner::try_new(
        "private-tenant".to_owned(),
        RunnerSessionFence::new(
            session_id,
            runner_id,
            RunnerGeneration::new(1).expect("generation"),
            SessionEpoch::new(1).expect("session epoch"),
        ),
        None,
        [],
        capabilities.clone(),
        capabilities,
        RunnerSlotCount::new(1).expect("slot count"),
        [],
    )
    .expect("bounded runner");
    let runner_debug = format!("{runner:?}");
    assert!(!runner_debug.contains("private-tenant"));
    assert!(!runner_debug.contains(&runner_id.to_string()));
    assert!(!runner_debug.contains(&session_id.to_string()));

    assert_eq!(
        ControlPlaneCapacitySnapshot::try_new(
            0,
            Vec::new(),
            vec![runner; MAX_CONTROL_PLANE_CAPACITY_RUNNERS + 1],
        )
        .expect_err("runner sentinel row must reject the snapshot"),
        ControlPlaneStateValueError::CapacitySnapshotTooLarge
    );

    let oversized_runner_id = RunnerId::new();
    let oversized_capabilities = RunnerCapabilities::new(
        oversized_runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    );
    assert_eq!(
        ControlPlaneCapacityRunner::try_new(
            "private-tenant".to_owned(),
            RunnerSessionFence::new(
                RunnerSessionId::new(),
                oversized_runner_id,
                RunnerGeneration::new(1).expect("generation"),
                SessionEpoch::new(1).expect("session epoch"),
            ),
            None,
            [],
            oversized_capabilities.clone(),
            oversized_capabilities,
            RunnerSlotCount::new(MAX_CONTROL_PLANE_CAPACITY_SLOTS_PER_RUNNER + 1)
                .expect("domain permits the sentinel slot count"),
            [],
        )
        .expect_err("slot sentinel row must reject the runner"),
        ControlPlaneStateValueError::InvalidCapacityRunner
    );
}
