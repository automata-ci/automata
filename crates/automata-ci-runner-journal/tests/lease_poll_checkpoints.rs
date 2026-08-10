mod support;

use std::sync::Arc;

use automata_ci_core::{JobIrVersion, JobLifecycle, OperationId, RunnerSessionId};
use automata_ci_protocol::{PROTOCOL_MAX_VERSION, RunnerSlotOrdinal};
use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, JournalError,
    JournalInvariantError, RunnerJournal, SessionBinding,
};
use support::{Fixture, Scratch, record_and_ack_terminal};

#[derive(Debug)]
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

fn options(stage: CommitStage) -> FileJournalOptions {
    FileJournalOptions::new().with_fault_injector(Arc::new(FailAt(stage)))
}

fn checkpoint(
    journal: &dyn RunnerJournal,
    slot: RunnerSlotOrdinal,
) -> automata_ci_runner_journal::LeasePollCheckpoint {
    *journal
        .snapshot()
        .expect("snapshot")
        .session()
        .expect("session")
        .lease_poll_checkpoint(slot)
        .expect("lease-poll checkpoint")
}

#[test]
fn prepare_resume_advance_and_new_session_preserve_exact_chain() {
    let scratch = Scratch::new("lease-poll-chain");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    let first = OperationId::new();
    let discarded = OperationId::new();
    journal
        .prepare_lease_poll(fixture.session_id, fixture.slot, first)
        .expect("prepare first poll");
    journal
        .prepare_lease_poll(fixture.session_id, fixture.slot, discarded)
        .expect("resume exact first poll");
    assert_eq!(
        checkpoint(&journal, fixture.slot).current_operation_id(),
        first
    );

    journal
        .begin_session(fixture.binding())
        .expect("resume session");
    assert_eq!(
        checkpoint(&journal, fixture.slot).current_operation_id(),
        first
    );

    let successor = OperationId::new();
    journal
        .advance_lease_poll(fixture.session_id, fixture.slot, first, successor)
        .expect("advance poll");
    let durable = checkpoint(&journal, fixture.slot);
    assert_eq!(durable.current_operation_id(), successor);
    assert_eq!(durable.acknowledges_operation_id(), Some(first));

    let discarded_replay_successor = OperationId::new();
    journal
        .advance_lease_poll(
            fixture.session_id,
            fixture.slot,
            first,
            discarded_replay_successor,
        )
        .expect("replay completed advance");
    assert_eq!(
        checkpoint(&journal, fixture.slot),
        durable,
        "a recovery retry returns the already durable successor"
    );

    let fresh_session = RunnerSessionId::new();
    journal
        .begin_session(SessionBinding::new(
            fresh_session,
            PROTOCOL_MAX_VERSION,
            JobIrVersion::current(),
        ))
        .expect("replace empty session");
    assert!(
        journal
            .snapshot()
            .expect("fresh snapshot")
            .session()
            .expect("fresh session")
            .lease_poll_checkpoints()
            .is_empty(),
        "a genuinely new session cannot acknowledge an old-session poll"
    );
}

#[test]
fn checkpoints_are_per_slot_unique_and_survive_slot_release() {
    let scratch = Scratch::new("lease-poll-slots");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    let slot_two = RunnerSlotOrdinal::new(2).expect("slot two");
    let slot_one_operation = OperationId::new();
    let slot_two_operation = OperationId::new();
    journal
        .prepare_lease_poll(fixture.session_id, fixture.slot, slot_one_operation)
        .expect("slot one poll");
    journal
        .prepare_lease_poll(fixture.session_id, slot_two, slot_two_operation)
        .expect("slot two poll");
    assert_ne!(slot_one_operation, slot_two_operation);
    assert!(matches!(
        journal.prepare_lease_poll(
            fixture.session_id,
            RunnerSlotOrdinal::new(3).expect("slot three"),
            slot_one_operation,
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::LeasePollOperationConflict
        ))
    ));

    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
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
        .expect("prepare offer");
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Skipped);
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release terminal slot");
    assert_eq!(
        checkpoint(&journal, fixture.slot).current_operation_id(),
        slot_one_operation,
        "slot lifecycle cleanup must not erase its poll chain"
    );
}

#[test]
fn checkpoint_commits_recover_on_both_sides_of_atomic_rename() {
    for (stage, committed) in [
        (CommitStage::FileSynced, false),
        (CommitStage::Renamed, true),
    ] {
        let scratch = Scratch::new(&format!("lease-poll-fault-{stage:?}"));
        let fixture = Fixture::new();
        let journal = fixture.open(&scratch);
        journal.begin_session(fixture.binding()).expect("session");
        drop(journal);
        let operation_id = OperationId::new();
        let faulting =
            FileJournal::open_with_options(scratch.state_root(), fixture.runner_id, options(stage))
                .expect("faulting journal");
        let result = faulting.prepare_lease_poll(fixture.session_id, fixture.slot, operation_id);
        if committed {
            assert!(matches!(result, Err(JournalError::CommitOutcomeUnknown)));
        } else {
            assert!(
                matches!(result, Err(JournalError::InjectedFault(received)) if received == stage)
            );
        }
        drop(faulting);

        let recovered = fixture.open(&scratch);
        let recovered_checkpoint = recovered
            .snapshot()
            .expect("recovered snapshot")
            .session()
            .expect("session")
            .lease_poll_checkpoint(fixture.slot)
            .copied();
        assert_eq!(
            recovered_checkpoint
                .map(automata_ci_runner_journal::LeasePollCheckpoint::current_operation_id,),
            committed.then_some(operation_id)
        );
    }
}
