mod support;

use std::sync::Arc;

use automata_core::{JobLifecycle, OperationId};
use automata_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, JournalError,
    JournalInvariantError, MAX_PROVIDER_OPERATIONS_PER_SLOT, ProviderFailureKind,
    ProviderFailureOutcome, ProviderName, ProviderOperation, ProviderOperationKind,
    ProviderOperationOutcome, RunnerJournal, SandboxHandle, SandboxIdentity,
};
use support::{Fixture, Scratch, record_and_ack_terminal};

#[derive(Debug)]
struct FailAfterRename;

impl CommitFaultInjector for FailAfterRename {
    fn check(&self, stage: CommitStage) -> Result<(), CommitFault> {
        if stage == CommitStage::Renamed {
            Err(CommitFault)
        } else {
            Ok(())
        }
    }
}

fn sandbox() -> SandboxIdentity {
    SandboxIdentity::new(
        ProviderName::new("podman").expect("provider name"),
        SandboxHandle::new("sandbox:provider-failure").expect("sandbox handle"),
    )
}

fn prepare_accepted(journal: &dyn RunnerJournal, fixture: &Fixture) {
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("record offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept offer");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Preparing,
        )
        .expect("begin preparation");
}

fn create_sandbox(journal: &dyn RunnerJournal, fixture: &Fixture) {
    let operation_id = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(operation_id, ProviderOperationKind::CreateSandbox),
        )
        .expect("create intent");
    journal
        .record_sandbox_created(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            operation_id,
            sandbox(),
        )
        .expect("create applied");
}

fn start_sandbox(journal: &dyn RunnerJournal, fixture: &Fixture) {
    let operation_id = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(operation_id, ProviderOperationKind::StartSandbox),
        )
        .expect("start intent");
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            operation_id,
        )
        .expect("start applied");
}

fn record_intent(
    journal: &dyn RunnerJournal,
    fixture: &Fixture,
    kind: ProviderOperationKind,
) -> OperationId {
    let operation_id = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(operation_id, kind),
        )
        .expect("provider intent");
    operation_id
}

fn recover_failed_operation(
    scratch: &Scratch,
    fixture: &Fixture,
    operation_id: OperationId,
    failure: ProviderFailureOutcome,
) -> FileJournal {
    let options = FileJournalOptions::new().with_fault_injector(Arc::new(FailAfterRename));
    let faulting = FileJournal::open_with_options(scratch.state_root(), fixture.runner_id, options)
        .expect("open faulting journal");
    assert!(matches!(
        faulting.fail_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            operation_id,
            failure,
        ),
        Err(JournalError::CommitOutcomeUnknown)
    ));
    assert!(matches!(faulting.snapshot(), Err(JournalError::Poisoned)));
    drop(faulting);

    let recovered = fixture.open(scratch);
    let before_replay = recovered.snapshot().expect("recovered failure");
    let operation = before_replay
        .slot(fixture.slot)
        .expect("slot")
        .provider_operations()
        .last()
        .expect("provider operation");
    assert_eq!(operation.operation_id(), operation_id);
    assert_eq!(
        operation.outcome(),
        ProviderOperationOutcome::Failed(failure)
    );
    let replay = recovered
        .fail_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            operation_id,
            failure,
        )
        .expect("idempotent failure replay");
    assert_eq!(replay.revision(), before_replay.revision());
    recovered
}

fn assert_release_is_blocked(journal: &dyn RunnerJournal, fixture: &Fixture) {
    assert!(matches!(
        journal.release_slot(fixture.session_id, fixture.slot, fixture.lease.guard()),
        Err(JournalError::Invariant(
            JournalInvariantError::SlotNotTerminal
        ))
    ));
}

#[test]
fn failed_create_recovers_idempotently_and_can_release_without_a_sandbox() {
    let scratch = Scratch::new("failed-create");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_accepted(&journal, &fixture);
    let operation_id = record_intent(&journal, &fixture, ProviderOperationKind::CreateSandbox);
    drop(journal);

    let journal = recover_failed_operation(
        &scratch,
        &fixture,
        operation_id,
        ProviderFailureOutcome::KnownNoEffect(ProviderFailureKind::ResourceExhausted),
    );
    assert!(
        journal
            .snapshot()
            .expect("snapshot")
            .slot(fixture.slot)
            .expect("slot")
            .sandbox()
            .is_none()
    );
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
    let released = journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release without sandbox");
    assert!(released.slot(fixture.slot).is_none());
}

#[test]
fn failed_start_recovers_with_its_sandbox_and_requires_destroy() {
    let scratch = Scratch::new("failed-start");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_accepted(&journal, &fixture);
    create_sandbox(&journal, &fixture);
    let operation_id = record_intent(&journal, &fixture, ProviderOperationKind::StartSandbox);
    drop(journal);

    let journal = recover_failed_operation(
        &scratch,
        &fixture,
        operation_id,
        ProviderFailureOutcome::KnownNoEffect(ProviderFailureKind::Unavailable),
    );
    assert!(
        journal
            .snapshot()
            .expect("snapshot")
            .slot(fixture.slot)
            .expect("slot")
            .sandbox()
            .is_some()
    );
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
    assert_release_is_blocked(&journal, &fixture);
    let destroy = record_intent(&journal, &fixture, ProviderOperationKind::DestroySandbox);
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            destroy,
        )
        .expect("destroy applied");
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release after destroy");
}

#[test]
fn failed_stop_can_retry_but_an_uncertain_retry_fences_new_operations() {
    let scratch = Scratch::new("failed-stop");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_accepted(&journal, &fixture);
    create_sandbox(&journal, &fixture);
    start_sandbox(&journal, &fixture);
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Running,
        )
        .expect("running");
    let operation_id = record_intent(&journal, &fixture, ProviderOperationKind::StopSandbox);
    drop(journal);

    let journal = recover_failed_operation(
        &scratch,
        &fixture,
        operation_id,
        ProviderFailureOutcome::KnownNoEffect(ProviderFailureKind::TimedOut),
    );
    let retry = record_intent(&journal, &fixture, ProviderOperationKind::StopSandbox);
    journal
        .fail_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            retry,
            ProviderFailureOutcome::Uncertain(ProviderFailureKind::Internal),
        )
        .expect("record uncertain stop");
    drop(journal);

    let journal = fixture.open(&scratch);
    let before_replay = journal.snapshot().expect("recover uncertainty");
    assert!(
        before_replay
            .slot(fixture.slot)
            .expect("slot")
            .provider_operations()
            .last()
            .expect("operation")
            .is_pending()
    );
    let replay = journal
        .fail_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            retry,
            ProviderFailureOutcome::Uncertain(ProviderFailureKind::Internal),
        )
        .expect("uncertain replay");
    assert_eq!(replay.revision(), before_replay.revision());
    assert!(matches!(
        journal.record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(OperationId::new(), ProviderOperationKind::StopSandbox),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::ProviderOperationPending
        ))
    ));
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            retry,
        )
        .expect("reconcile retry as applied");
}

#[test]
fn failed_destroy_retains_identity_until_a_retry_is_proven_applied() {
    let scratch = Scratch::new("failed-destroy");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_accepted(&journal, &fixture);
    create_sandbox(&journal, &fixture);
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
    let operation_id = record_intent(&journal, &fixture, ProviderOperationKind::DestroySandbox);
    drop(journal);

    let journal = recover_failed_operation(
        &scratch,
        &fixture,
        operation_id,
        ProviderFailureOutcome::KnownNoEffect(ProviderFailureKind::Conflict),
    );
    assert_release_is_blocked(&journal, &fixture);
    let retry = record_intent(&journal, &fixture, ProviderOperationKind::DestroySandbox);
    journal
        .fail_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            retry,
            ProviderFailureOutcome::Uncertain(ProviderFailureKind::Unavailable),
        )
        .expect("uncertain destroy");
    drop(journal);

    let journal = fixture.open(&scratch);
    assert_release_is_blocked(&journal, &fixture);
    assert!(matches!(
        journal.record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(OperationId::new(), ProviderOperationKind::DestroySandbox),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::ProviderOperationPending
        ))
    ));
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            retry,
        )
        .expect("destroy reconciliation");
    let cleaned = journal.snapshot().expect("cleaned snapshot");
    assert!(
        cleaned
            .slot(fixture.slot)
            .expect("slot")
            .sandbox()
            .is_none()
    );
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release after proven destroy");
}

#[test]
fn more_than_one_history_window_of_failed_destroys_can_then_succeed_and_release() {
    let scratch = Scratch::new("provider-history-bound");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_accepted(&journal, &fixture);
    create_sandbox(&journal, &fixture);
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);

    let mut latest_failure = None;
    for _ in 0..(MAX_PROVIDER_OPERATIONS_PER_SLOT + 8) {
        let operation_id = record_intent(&journal, &fixture, ProviderOperationKind::DestroySandbox);
        journal
            .fail_provider_operation(
                fixture.session_id,
                fixture.slot,
                fixture.lease.guard(),
                operation_id,
                ProviderFailureOutcome::KnownNoEffect(ProviderFailureKind::Conflict),
            )
            .expect("resolve failed destroy");
        latest_failure = Some(operation_id);
    }
    let before_replay = journal.snapshot().expect("bounded snapshot");
    let slot = before_replay.slot(fixture.slot).expect("slot");
    assert_eq!(
        slot.provider_operations().len(),
        MAX_PROVIDER_OPERATIONS_PER_SLOT
    );
    assert!(slot.compacted_provider_operations() > 0);
    assert!(slot.sandbox().is_some());

    let replay = journal
        .fail_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            latest_failure.expect("latest failure"),
            ProviderFailureOutcome::KnownNoEffect(ProviderFailureKind::Conflict),
        )
        .expect("exact recent failure replay");
    assert_eq!(replay.revision(), before_replay.revision());

    let success = record_intent(&journal, &fixture, ProviderOperationKind::DestroySandbox);
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            success,
        )
        .expect("destroy succeeds after bounded failure history");
    drop(journal);

    let journal = fixture.open(&scratch);
    let recovered = journal.snapshot().expect("recover success");
    assert!(
        recovered
            .slot(fixture.slot)
            .expect("slot")
            .sandbox()
            .is_none()
    );
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release after successful destroy");
}
