use std::{fs, path::Path, sync::Arc};

use automata_ci_core::{JobLifecycle, LeaseGuard, OperationId, UnixMillis};
use automata_ci_execution::MAX_ENDPOINT_OPERATIONS_PER_JOB;
use automata_ci_runner_journal::{
    CancellationRecord, CommitFault, CommitFaultInjector, CommitStage, ContentKind,
    ENDPOINT_REQUEST_COMMITMENT_BYTES, EndpointOperation, EndpointOperationKind,
    EndpointOperationState, EndpointRequestContentRef, EndpointResultContentRef, FileJournal,
    FileJournalOptions, JournalError, JournalInvariantError, JournalSnapshot,
    MAX_ENDPOINT_CONTENT_BYTES_PER_SLOT, MAX_ENDPOINT_CONTENT_REFS_PER_SLOT,
    MAX_ENDPOINT_RESULT_ALLOCATION_BYTES, MAX_ENDPOINT_RESULT_CONTENT_BYTES, MAX_JOURNAL_BYTES,
    MIN_ENDPOINT_RESULT_ALLOCATION_BYTES, ProviderName, ProviderOperation, ProviderOperationKind,
    RunnerJournal, SandboxHandle, SandboxIdentity,
};

use crate::support::{Fixture, Scratch, record_and_ack_runtime_authority, record_and_ack_terminal};

fn accepted_operation(
    operation_id: OperationId,
    kind: EndpointOperationKind,
    marker: u8,
    reservation: u64,
) -> EndpointOperation {
    EndpointOperation::accepted(
        operation_id,
        kind,
        EndpointRequestContentRef::new(Fixture::content(ContentKind::EndpointRequest, 32, marker))
            .expect("valid request commitment"),
        reservation,
    )
    .expect("valid accepted operation")
}

fn accepted_operation_with_protection_id(
    operation_id: OperationId,
    kind: EndpointOperationKind,
    marker: u8,
    reservation: u64,
    protection_id: &str,
) -> EndpointOperation {
    EndpointOperation::accepted(
        operation_id,
        kind,
        EndpointRequestContentRef::new(Fixture::content_with_protection_id(
            ContentKind::EndpointRequest,
            32,
            marker,
            protection_id,
        ))
        .expect("valid request commitment"),
        reservation,
    )
    .expect("valid accepted operation")
}

fn result(marker: u8, size: u64) -> EndpointResultContentRef {
    EndpointResultContentRef::new(Fixture::content(ContentKind::EndpointResult, size, marker))
        .expect("valid endpoint result")
}

fn result_with_protection_id(
    marker: u8,
    size: u64,
    protection_id: &str,
) -> EndpointResultContentRef {
    EndpointResultContentRef::new(Fixture::content_with_protection_id(
        ContentKind::EndpointResult,
        size,
        marker,
        protection_id,
    ))
    .expect("valid endpoint result")
}

fn accepted_journal(label: &str) -> (Scratch, Fixture, FileJournal) {
    let scratch = Scratch::new(label);
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("record offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept offer");
    (scratch, fixture, journal)
}

fn accepted_journal_with_sandbox(label: &str) -> (Scratch, Fixture, FileJournal) {
    let (scratch, fixture, journal) = accepted_journal(label);
    let guard = fixture.lease.guard();
    record_and_ack_runtime_authority(&journal, &fixture);
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Preparing,
        )
        .expect("prepare");
    let create = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            guard,
            ProviderOperation::intent(create, ProviderOperationKind::CreateSandbox),
        )
        .expect("create intent");
    journal
        .record_sandbox_created(
            fixture.session_id,
            fixture.slot,
            guard,
            create,
            SandboxIdentity::new(
                ProviderName::new("test-provider").expect("provider"),
                SandboxHandle::new("generation-7").expect("handle"),
            ),
        )
        .expect("sandbox identity");
    (scratch, fixture, journal)
}

#[derive(Clone, Copy, Debug)]
struct FailAt(CommitStage);

impl CommitFaultInjector for FailAt {
    fn check(&self, stage: CommitStage) -> Result<(), CommitFault> {
        if stage == self.0 {
            Err(CommitFault)
        } else {
            Ok(())
        }
    }
}

fn faulting_journal(scratch: &Scratch, fixture: &Fixture, stage: CommitStage) -> FileJournal {
    FileJournal::open_with_options(
        scratch.state_root(),
        fixture.runner_id,
        FileJournalOptions::new().with_fault_injector(Arc::new(FailAt(stage))),
    )
    .expect("open faulting journal")
}

#[derive(Clone, Copy, Debug)]
enum EndpointTransition {
    Accept,
    CommitInvocation,
    Cancel,
    CompleteCancellation,
    Abandon,
    Result,
}

fn apply_transition(
    journal: &FileJournal,
    fixture: &Fixture,
    guard: LeaseGuard,
    transition: EndpointTransition,
    operation: EndpointOperation,
) -> Result<JournalSnapshot, JournalError> {
    let operation_id = operation.operation_id();
    match transition {
        EndpointTransition::Accept => {
            journal.accept_endpoint_operation(fixture.session_id, fixture.slot, guard, operation)
        }
        EndpointTransition::CommitInvocation => journal.commit_endpoint_invocation(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
        ),
        EndpointTransition::Cancel => journal.record_endpoint_cancellation(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
        ),
        EndpointTransition::CompleteCancellation => journal.complete_endpoint_cancellation(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
        ),
        EndpointTransition::Abandon => journal.abandon_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
        ),
        EndpointTransition::Result => journal.record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
            result(0x71, 64),
        ),
    }
}

fn seed_transition_predecessor(
    journal: &FileJournal,
    fixture: &Fixture,
    transition: EndpointTransition,
    operation: &EndpointOperation,
) {
    let guard = fixture.lease.guard();
    let operation_id = operation.operation_id();
    if !matches!(transition, EndpointTransition::Accept) {
        journal
            .accept_endpoint_operation(fixture.session_id, fixture.slot, guard, operation.clone())
            .expect("seed accepted operation");
    }
    if matches!(
        transition,
        EndpointTransition::Cancel
            | EndpointTransition::CompleteCancellation
            | EndpointTransition::Abandon
            | EndpointTransition::Result
    ) {
        journal
            .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
            .expect("seed invocation commitment");
    }
    if matches!(transition, EndpointTransition::CompleteCancellation) {
        journal
            .record_endpoint_cancellation(fixture.session_id, fixture.slot, guard, operation_id)
            .expect("seed cancellation request");
    }
}

fn assert_recovered_transition_state(
    transition: EndpointTransition,
    applied: bool,
    recovered: &EndpointOperation,
) {
    let expected = match (transition, applied) {
        (EndpointTransition::Accept, _) | (EndpointTransition::CommitInvocation, false) => {
            EndpointOperationState::Accepted
        }
        (EndpointTransition::CommitInvocation, true) | (EndpointTransition::Abandon, false) => {
            EndpointOperationState::InvocationCommitted
        }
        (EndpointTransition::Cancel, true) | (EndpointTransition::CompleteCancellation, false) => {
            EndpointOperationState::CancellationRequested
        }
        (EndpointTransition::Cancel, false) => EndpointOperationState::InvocationCommitted,
        (EndpointTransition::CompleteCancellation, true) => EndpointOperationState::Cancelled,
        (EndpointTransition::Abandon, true) => EndpointOperationState::Abandoned,
        (EndpointTransition::Result, _) => {
            assert_eq!(recovered.result().is_some(), applied);
            return;
        }
    };
    assert_eq!(recovered.state(), &expected);
}

fn assert_transition_recovery(transition: EndpointTransition, stage: CommitStage) {
    let (scratch, fixture, journal) =
        accepted_journal(&format!("endpoint-{transition:?}-{stage:?}"));
    let guard = fixture.lease.guard();
    let operation = accepted_operation(OperationId::new(), EndpointOperationKind::Exec, 0x70, 128);
    seed_transition_predecessor(&journal, &fixture, transition, &operation);
    drop(journal);

    let faulting = faulting_journal(&scratch, &fixture, stage);
    let mutation = apply_transition(&faulting, &fixture, guard, transition, operation);
    let applied = matches!(stage, CommitStage::Renamed | CommitStage::DirectorySynced);
    if applied {
        assert!(matches!(mutation, Err(JournalError::CommitOutcomeUnknown)));
    } else {
        assert!(matches!(
            mutation,
            Err(JournalError::InjectedFault(received)) if received == stage
        ));
    }
    drop(faulting);

    let recovered = fixture.open(&scratch).snapshot().expect("recover journal");
    let operations = recovered
        .slot(fixture.slot)
        .expect("durable slot")
        .endpoint_operations();
    if matches!(transition, EndpointTransition::Accept) && !applied {
        assert!(operations.is_empty());
    } else {
        assert_recovered_transition_state(
            transition,
            applied,
            operations.first().expect("accepted endpoint operation"),
        );
    }
}

#[test]
fn every_endpoint_transition_recovers_exactly_at_every_physical_commit_boundary() {
    let stages = [
        CommitStage::StagingCreated,
        CommitStage::DataWritten,
        CommitStage::FileSynced,
        CommitStage::Renamed,
        CommitStage::DirectorySynced,
    ];
    for transition in [
        EndpointTransition::Accept,
        EndpointTransition::CommitInvocation,
        EndpointTransition::Cancel,
        EndpointTransition::CompleteCancellation,
        EndpointTransition::Abandon,
        EndpointTransition::Result,
    ] {
        for stage in stages {
            assert_transition_recovery(transition, stage);
        }
    }
}

#[test]
fn endpoint_operations_linearize_result_and_cancellation_without_eviction() {
    let (_scratch, fixture, journal) = accepted_journal("endpoint-linearization");
    let guard = fixture.lease.guard();
    let first_id = OperationId::new();
    let first = accepted_operation(first_id, EndpointOperationKind::Exec, 0x10, 128);
    let accepted = journal
        .accept_endpoint_operation(fixture.session_id, fixture.slot, guard, first.clone())
        .expect("accept first endpoint operation");
    let accepted_revision = accepted.revision();
    assert_eq!(
        accepted.slot(fixture.slot).unwrap().endpoint_operations(),
        std::slice::from_ref(&first)
    );
    assert_eq!(
        journal
            .accept_endpoint_operation(fixture.session_id, fixture.slot, guard, first)
            .expect("exact acceptance replay")
            .revision(),
        accepted_revision
    );

    let pending = accepted_operation(
        OperationId::new(),
        EndpointOperationKind::CopyFrom,
        0x11,
        128,
    );
    assert!(matches!(
        journal.accept_endpoint_operation(fixture.session_id, fixture.slot, guard, pending.clone()),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationPending
        ))
    ));
    assert!(matches!(
        journal.record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            first_id,
            result(0x20, 64)
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointInvocationNotCommitted
        ))
    ));

    journal
        .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, first_id)
        .expect("commit invocation");
    let first_result = result(0x21, 64);
    let completed = journal
        .record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            first_id,
            first_result.clone(),
        )
        .expect("record exact result");
    let result_revision = completed.revision();
    assert_eq!(
        journal
            .record_endpoint_cancellation(fixture.session_id, fixture.slot, guard, first_id)
            .expect("result wins later cancellation")
            .revision(),
        result_revision
    );

    let second_id = pending.operation_id();
    journal
        .accept_endpoint_operation(fixture.session_id, fixture.slot, guard, pending)
        .expect("resolved predecessor permits successor");
    journal
        .record_endpoint_cancellation(fixture.session_id, fixture.slot, guard, second_id)
        .expect("cancellation wins");
    assert!(matches!(
        journal.commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, second_id),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationCancelled
        ))
    ));
    assert!(matches!(
        journal.record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            second_id,
            result(0x22, 64)
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationCancelled
        ))
    ));

    let snapshot = journal.snapshot().expect("snapshot endpoint ledger");
    let operations = snapshot.slot(fixture.slot).unwrap().endpoint_operations();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0].result(), Some(&first_result));
    assert_eq!(operations[1].state(), &EndpointOperationState::Cancelled);
    let retained: Vec<_> = snapshot.content_references().collect();
    assert!(retained.contains(&operations[0].request().content()));
    assert!(retained.contains(&first_result.content()));
    assert!(retained.contains(&operations[1].request().content()));
}

#[test]
fn durable_job_cancellation_atomically_resolves_the_pending_endpoint_race() {
    let (_scratch, fixture, journal) = accepted_journal("endpoint-job-cancellation");
    let guard = fixture.lease.guard();
    let operation_id = OperationId::new();
    let accepted = accepted_operation(operation_id, EndpointOperationKind::Exec, 0x19, 128);
    journal
        .accept_endpoint_operation(fixture.session_id, fixture.slot, guard, accepted.clone())
        .expect("accept endpoint operation");
    journal
        .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("commit invocation");
    let cancelled = journal
        .record_cancellation(
            fixture.session_id,
            fixture.slot,
            guard,
            CancellationRecord::new(Fixture::command(2), UnixMillis::new(4_000)),
        )
        .expect("durably cancel job and endpoint operation");
    let operation = &cancelled
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(
        operation.state(),
        &EndpointOperationState::CancellationRequested
    );
    assert_eq!(
        journal
            .accept_endpoint_operation(fixture.session_id, fixture.slot, guard, accepted)
            .expect("exact acceptance replay remains idempotent")
            .revision(),
        cancelled.revision()
    );
    assert!(matches!(
        journal.record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
            result(0x1a, 64),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationCancelled
        ))
    ));
    assert!(matches!(
        journal.accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(OperationId::new(), EndpointOperationKind::Wait, 0x1b, 32,),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationsClosed
        ))
    ));

    let (_scratch, fixture, journal) = accepted_journal("endpoint-job-result-first");
    let guard = fixture.lease.guard();
    let operation_id = OperationId::new();
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(operation_id, EndpointOperationKind::Exec, 0x1c, 128),
        )
        .expect("accept result-first operation");
    journal
        .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("commit result-first invocation");
    let expected_result = result(0x1d, 64);
    journal
        .record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
            expected_result.clone(),
        )
        .expect("result wins");
    let cancelled = journal
        .record_cancellation(
            fixture.session_id,
            fixture.slot,
            guard,
            CancellationRecord::new(Fixture::command(2), UnixMillis::new(4_000)),
        )
        .expect("record later job cancellation");
    let operation = &cancelled
        .slot(fixture.slot)
        .expect("slot")
        .endpoint_operations()[0];
    assert_eq!(operation.result(), Some(&expected_result));
    assert!(matches!(
        operation.state(),
        EndpointOperationState::Completed { .. }
    ));
}

#[test]
fn unresolved_endpoint_operation_structurally_fences_finalization_and_release() {
    let (_scratch, fixture, journal) = accepted_journal("endpoint-release");
    let guard = fixture.lease.guard();
    let operation_id = OperationId::new();
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(operation_id, EndpointOperationKind::Wait, 0x30, 32),
        )
        .expect("accept endpoint operation");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Preparing,
        )
        .expect("prepare");
    assert!(matches!(
        journal.record_terminal_result(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Failed,
            Fixture::terminal_result(),
            Fixture::delivery_time(),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointRecoveryPending
        ))
    ));
    journal
        .record_endpoint_cancellation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("resolve operation by cancellation");
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
    let released = journal
        .release_slot(fixture.session_id, fixture.slot, guard)
        .expect("release exact slot");
    assert!(released.slot(fixture.slot).is_none());
    assert!(released.content_references().all(|content| {
        !matches!(
            content.kind(),
            ContentKind::EndpointRequest | ContentKind::EndpointResult
        )
    }));
}

#[test]
fn invoked_cancellation_requires_exact_sandbox_absence() {
    let (_scratch, fixture, journal) =
        accepted_journal_with_sandbox("endpoint-cancellation-resolution");
    let guard = fixture.lease.guard();
    let operation_id = OperationId::new();
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(operation_id, EndpointOperationKind::Exec, 0x35, 128),
        )
        .expect("accept operation");
    journal
        .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("commit invocation");
    assert!(matches!(
        journal.abandon_endpoint_operation(fixture.session_id, fixture.slot, guard, operation_id),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointSandboxStillPresent
        ))
    ));
    journal
        .record_endpoint_cancellation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("request cancellation");
    assert!(matches!(
        journal.complete_endpoint_cancellation(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointSandboxStillPresent
        ))
    ));
    assert!(matches!(
        journal.record_terminal_result(
            fixture.session_id,
            fixture.slot,
            guard,
            JobLifecycle::Failed,
            Fixture::terminal_result(),
            Fixture::delivery_time(),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointRecoveryPending
        ))
    ));
    let destroy = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            guard,
            ProviderOperation::intent(destroy, ProviderOperationKind::DestroySandbox),
        )
        .expect("destroy exact generation intent");
    journal
        .complete_provider_operation(fixture.session_id, fixture.slot, guard, destroy)
        .expect("exact generation absent");
    journal
        .complete_endpoint_cancellation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("resolve cancellation only after absence proof");
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
}

#[test]
fn ambiguous_invocation_abandonment_requires_exact_sandbox_absence() {
    let (_scratch, fixture, journal) =
        accepted_journal_with_sandbox("endpoint-abandonment-resolution");
    let guard = fixture.lease.guard();
    let ambiguous_id = OperationId::new();
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(ambiguous_id, EndpointOperationKind::Wait, 0x36, 32),
        )
        .expect("accept ambiguous successor");
    journal
        .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, ambiguous_id)
        .expect("commit ambiguous invocation");
    assert!(matches!(
        journal.abandon_endpoint_operation(fixture.session_id, fixture.slot, guard, ambiguous_id),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointSandboxStillPresent
        ))
    ));
    let destroy = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            guard,
            ProviderOperation::intent(destroy, ProviderOperationKind::DestroySandbox),
        )
        .expect("destroy exact generation intent");
    journal
        .complete_provider_operation(fixture.session_id, fixture.slot, guard, destroy)
        .expect("exact generation absent");
    journal
        .abandon_endpoint_operation(fixture.session_id, fixture.slot, guard, ambiguous_id)
        .expect("resolve ambiguity only after absence proof");
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
}

#[test]
fn endpoint_replay_conflicts_and_result_reservations_fail_closed() {
    let (_scratch, fixture, journal) = accepted_journal("endpoint-conflicts");
    let guard = fixture.lease.guard();
    let operation_id = OperationId::new();
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(operation_id, EndpointOperationKind::CopyTo, 0x40, 64),
        )
        .expect("accept exact operation");
    assert!(matches!(
        journal.accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(operation_id, EndpointOperationKind::CopyTo, 0x41, 64),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationReplayConflict
        ))
    ));
    journal
        .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("commit invocation");
    assert!(matches!(
        journal.record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
            result(0x42, MIN_ENDPOINT_RESULT_ALLOCATION_BYTES),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointResultExceedsReservation
        ))
    ));
}

#[test]
fn reservation_bounds_are_overflow_safe_and_cancelled_capacity_shrinks_to_retained_bytes() {
    for invalid in [0, MAX_ENDPOINT_RESULT_CONTENT_BYTES + 1, u64::MAX] {
        assert_eq!(
            EndpointOperation::accepted(
                OperationId::new(),
                EndpointOperationKind::Exec,
                EndpointRequestContentRef::new(Fixture::content(
                    ContentKind::EndpointRequest,
                    32,
                    0x48,
                ))
                .expect("request commitment"),
                invalid,
            ),
            Err(JournalInvariantError::InvalidEndpointResultReservation)
        );
    }

    let (_scratch, fixture, journal) = accepted_journal("endpoint-reservation-shrink");
    let guard = fixture.lease.guard();
    let first_id = OperationId::new();
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(
                first_id,
                EndpointOperationKind::CopyFrom,
                0x49,
                MAX_ENDPOINT_RESULT_CONTENT_BYTES,
            ),
        )
        .expect("reserve worst-case output");
    let cancelled = journal
        .record_endpoint_cancellation(fixture.session_id, fixture.slot, guard, first_id)
        .expect("cancel before backend invocation");
    let operation = &cancelled.slot(fixture.slot).unwrap().endpoint_operations()[0];
    assert_eq!(operation.state(), &EndpointOperationState::Cancelled);
    assert_eq!(
        operation
            .accounted_content_bytes()
            .expect("bounded retained content"),
        ENDPOINT_REQUEST_COMMITMENT_BYTES
    );
    assert_eq!(operation.accounted_content_refs(), 1);

    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(
                OperationId::new(),
                EndpointOperationKind::CopyFrom,
                0x4a,
                MAX_ENDPOINT_RESULT_CONTENT_BYTES,
            ),
        )
        .expect("released reservation admits the successor before any backend call");
}

#[test]
fn completed_results_charge_actual_bytes_and_reject_before_the_next_invocation() {
    let (_scratch, fixture, journal) = accepted_journal("endpoint-byte-capacity");
    let guard = fixture.lease.guard();
    let per_full_operation =
        ENDPOINT_REQUEST_COMMITMENT_BYTES + MAX_ENDPOINT_RESULT_ALLOCATION_BYTES;
    let full = MAX_ENDPOINT_CONTENT_BYTES_PER_SLOT / per_full_operation;
    for ordinal in 0..full {
        let operation_id = OperationId::new();
        journal
            .accept_endpoint_operation(
                fixture.session_id,
                fixture.slot,
                guard,
                accepted_operation(
                    operation_id,
                    EndpointOperationKind::Exec,
                    u8::try_from(ordinal % 251).expect("bounded marker"),
                    MAX_ENDPOINT_RESULT_CONTENT_BYTES,
                ),
            )
            .expect("reserve full endpoint result object");
        journal
            .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
            .expect("commit capacity fixture");
        journal
            .record_endpoint_result(
                fixture.session_id,
                fixture.slot,
                guard,
                operation_id,
                result(
                    u8::try_from((ordinal + 1) % 251).expect("bounded marker"),
                    MAX_ENDPOINT_RESULT_CONTENT_BYTES,
                ),
            )
            .expect("retain full endpoint result object");
    }
    let retained_full = full * per_full_operation;
    let remaining = MAX_ENDPOINT_CONTENT_BYTES_PER_SLOT - retained_full;
    let per_small_operation =
        ENDPOINT_REQUEST_COMMITMENT_BYTES + MIN_ENDPOINT_RESULT_ALLOCATION_BYTES;
    let small = remaining / per_small_operation;
    for ordinal in 0..small {
        let operation_id = OperationId::new();
        journal
            .accept_endpoint_operation(
                fixture.session_id,
                fixture.slot,
                guard,
                accepted_operation(
                    operation_id,
                    EndpointOperationKind::Exec,
                    u8::try_from((ordinal + full) % 251).expect("bounded marker"),
                    1,
                ),
            )
            .expect("reserve minimum endpoint result class");
        journal
            .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
            .expect("commit minimum capacity fixture");
        journal
            .record_endpoint_result(
                fixture.session_id,
                fixture.slot,
                guard,
                operation_id,
                result(
                    u8::try_from((ordinal + full + 1) % 251).expect("bounded marker"),
                    1,
                ),
            )
            .expect("retain minimum endpoint result class");
    }
    let rejected = OperationId::new();
    assert!(matches!(
        journal.accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(rejected, EndpointOperationKind::Wait, 0xfb, 1),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointContentBytesLimit
        ))
    ));
    assert!(matches!(
        journal.commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, rejected),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationMissing
        ))
    ));
}

#[test]
fn non_evicting_entry_ceiling_rejects_the_next_operation() {
    let (scratch, fixture, journal) = accepted_journal("endpoint-entry-capacity");
    let guard = fixture.lease.guard();
    let operation_id = OperationId::new();
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(operation_id, EndpointOperationKind::Wait, 0x51, 1),
        )
        .expect("seed operation");
    journal
        .record_endpoint_cancellation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("resolve seed operation");
    drop(journal);
    expand_only_endpoint_operation(
        &scratch.child("state").join("runner-journal.json"),
        operation_id,
        MAX_ENDPOINT_OPERATIONS_PER_JOB,
    );
    let journal = fixture.open(&scratch);
    assert_eq!(
        journal
            .snapshot()
            .expect("maximum entry snapshot")
            .slot(fixture.slot)
            .unwrap()
            .endpoint_operations()
            .len(),
        MAX_ENDPOINT_OPERATIONS_PER_JOB
    );
    let replayed = journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(operation_id, EndpointOperationKind::Wait, 0x51, 1),
        )
        .expect("exact replay remains admissible at the entry ceiling");
    assert_eq!(
        replayed
            .slot(fixture.slot)
            .expect("slot")
            .endpoint_operations()
            .len(),
        MAX_ENDPOINT_OPERATIONS_PER_JOB
    );
    assert!(matches!(
        journal.accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(OperationId::new(), EndpointOperationKind::Wait, 0x52, 1),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationLimit
        ))
    ));
}

#[test]
fn reference_ceiling_is_aligned_with_the_shared_endpoint_execution_bound() {
    assert_eq!(
        MAX_ENDPOINT_CONTENT_REFS_PER_SLOT,
        MAX_ENDPOINT_OPERATIONS_PER_JOB * 2
    );
    let (scratch, fixture, journal) = accepted_journal("endpoint-reference-capacity");
    let guard = fixture.lease.guard();
    let operation_id = OperationId::new();
    let protection_id = "p".repeat(64);
    journal
        .accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation_with_protection_id(
                operation_id,
                EndpointOperationKind::CopyFrom,
                0x61,
                MAX_ENDPOINT_RESULT_CONTENT_BYTES,
                &protection_id,
            ),
        )
        .expect("seed operation");
    journal
        .commit_endpoint_invocation(fixture.session_id, fixture.slot, guard, operation_id)
        .expect("seed invocation");
    journal
        .record_endpoint_result(
            fixture.session_id,
            fixture.slot,
            guard,
            operation_id,
            result_with_protection_id(0x62, 1, &protection_id),
        )
        .expect("seed result");
    drop(journal);
    let path = scratch.child("state").join("runner-journal.json");
    expand_only_endpoint_operation(&path, operation_id, MAX_ENDPOINT_OPERATIONS_PER_JOB);
    assert!(
        usize::try_from(fs::metadata(&path).expect("journal metadata").len())
            .is_ok_and(|bytes| bytes <= MAX_JOURNAL_BYTES),
        "the maximum admitted current-schema endpoint journal must fit its hard read bound"
    );
    let journal = fixture.open(&scratch);
    assert!(matches!(
        journal.accept_endpoint_operation(
            fixture.session_id,
            fixture.slot,
            guard,
            accepted_operation(OperationId::new(), EndpointOperationKind::Wait, 0x63, 1),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::EndpointOperationLimit
        ))
    ));
}

fn expand_only_endpoint_operation(path: &Path, original_id: OperationId, count: usize) {
    let mut journal = fs::read_to_string(path).expect("read canonical journal");
    let marker = "\"endpoint_operations\":[";
    let start = journal.find(marker).expect("endpoint operation array") + marker.len();
    let bytes = journal.as_bytes();
    assert_eq!(bytes[start], b'{');
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut end = None;
    for (offset, byte) in bytes[start..].iter().copied().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(start + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end.expect("complete endpoint operation");
    assert_eq!(journal.as_bytes()[end], b']');
    let operation = journal[start..end].to_owned();
    let original_id = original_id.to_string();
    let expanded = (0..count)
        .map(|index| {
            if index == 0 {
                operation.clone()
            } else {
                operation.replacen(&original_id, &OperationId::new().to_string(), 1)
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    journal.replace_range(start..end, &expanded);
    fs::write(path, journal).expect("write expanded canonical journal");
}
