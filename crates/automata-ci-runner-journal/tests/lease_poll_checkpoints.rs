use super::support;

use std::sync::Arc;

use automata_ci_core::{JobIrVersion, JobLifecycle, OperationId, RunnerSessionId, Sha256Digest};
use automata_ci_protocol::{
    LeaseAuthorityName, LeaseAuthorityPollReceipt, PROTOCOL_MAX_VERSION, RunnerSlotOrdinal,
};
use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, JournalError,
    JournalInvariantError, JournalSnapshot, LeaseOfferRecord, LeasePollCommandRecord,
    LeasePollCompletion, RunnerJournal, SessionBinding,
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
    journal
        .snapshot()
        .expect("snapshot")
        .session()
        .expect("session")
        .lease_poll_checkpoint(slot)
        .expect("lease-poll checkpoint")
        .clone()
}

fn authority_receipt(name: &str, digest_byte: u8) -> LeaseAuthorityPollReceipt {
    LeaseAuthorityPollReceipt::from_parts(
        LeaseAuthorityName::new(name).expect("authority name"),
        1,
        Sha256Digest::from_bytes([digest_byte; 32]),
    )
    .expect("authority receipt")
}

fn assert_fault_recovery(
    recovered: &JournalSnapshot,
    fixture: &Fixture,
    carrier: RunnerSlotOrdinal,
    operations: (OperationId, OperationId),
    receipt: &LeaseAuthorityPollReceipt,
    offer: &LeaseOfferRecord,
    committed: bool,
) {
    let (predecessor, successor) = operations;
    let recovered_checkpoint = recovered
        .session()
        .expect("session")
        .lease_poll_checkpoint(carrier)
        .expect("carrier checkpoint");
    assert_eq!(recovered.slot(fixture.slot).is_some(), committed);
    assert_eq!(
        recovered_checkpoint.current_operation_id(),
        if committed { successor } else { predecessor }
    );
    assert_eq!(
        recovered_checkpoint.pending_authority_receipts(),
        if committed {
            std::slice::from_ref(receipt)
        } else {
            &[]
        }
    );
    assert_eq!(
        recovered
            .session()
            .expect("session")
            .command_cursor()
            .acknowledged_through(),
        committed.then_some(offer.command().sequence())
    );
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
    let pending_authority_receipts = vec![authority_receipt("test-authority", 0x44)];
    journal
        .complete_lease_poll(
            fixture.session_id,
            LeasePollCompletion::new(
                fixture.slot,
                first,
                successor,
                pending_authority_receipts.clone(),
                LeasePollCommandRecord::NoCommand,
            ),
        )
        .expect("advance poll");
    let durable = checkpoint(&journal, fixture.slot);
    assert_eq!(durable.current_operation_id(), successor);
    assert_eq!(durable.acknowledges_operation_id(), Some(first));
    assert_eq!(
        durable.pending_authority_receipts(),
        pending_authority_receipts
    );

    let discarded_replay_successor = OperationId::new();
    journal
        .complete_lease_poll(
            fixture.session_id,
            LeasePollCompletion::new(
                fixture.slot,
                first,
                discarded_replay_successor,
                pending_authority_receipts.clone(),
                LeasePollCommandRecord::NoCommand,
            ),
        )
        .expect("replay completed advance");
    assert_eq!(
        checkpoint(&journal, fixture.slot),
        durable,
        "a recovery retry returns the already durable successor"
    );

    journal
        .acknowledge_lease_authority_receipts(
            fixture.session_id,
            fixture.slot,
            &pending_authority_receipts,
        )
        .expect("acknowledge durable authority receipts");
    assert!(
        checkpoint(&journal, fixture.slot)
            .pending_authority_receipts()
            .is_empty(),
        "source acknowledgement clears the exact durable receipt set"
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
fn cross_slot_poll_command_and_receipts_recover_as_one_commit() {
    for (stage, committed) in [
        (CommitStage::FileSynced, false),
        (CommitStage::Renamed, true),
    ] {
        let scratch = Scratch::new(&format!("lease-poll-cross-slot-{stage:?}"));
        let fixture = Fixture::new();
        let carrier = RunnerSlotOrdinal::new(2).expect("carrier slot");
        let journal = fixture.open(&scratch);
        journal.begin_session(fixture.binding()).expect("session");
        let predecessor = OperationId::new();
        journal
            .prepare_lease_poll(fixture.session_id, carrier, predecessor)
            .expect("prepare carrier poll");
        drop(journal);

        let offer = fixture.offer(1);
        let receipt = authority_receipt("test-authority", 0x55);
        let first_successor = OperationId::new();
        let faulting =
            FileJournal::open_with_options(scratch.state_root(), fixture.runner_id, options(stage))
                .expect("faulting journal");
        let result = faulting.complete_lease_poll(
            fixture.session_id,
            LeasePollCompletion::new(
                carrier,
                predecessor,
                first_successor,
                vec![receipt.clone()],
                LeasePollCommandRecord::LeaseOffer(Box::new(offer.clone())),
            ),
        );
        if committed {
            assert!(matches!(result, Err(JournalError::CommitOutcomeUnknown)));
        } else {
            assert!(
                matches!(result, Err(JournalError::InjectedFault(received)) if received == stage)
            );
        }
        drop(faulting);

        let reopened = fixture.open(&scratch);
        let recovered = reopened.snapshot().expect("recovered snapshot");
        assert_fault_recovery(
            &recovered,
            &fixture,
            carrier,
            (predecessor, first_successor),
            &receipt,
            &offer,
            committed,
        );

        let replay_successor = OperationId::new();
        reopened
            .complete_lease_poll(
                fixture.session_id,
                LeasePollCompletion::new(
                    carrier,
                    predecessor,
                    replay_successor,
                    vec![receipt.clone()],
                    LeasePollCommandRecord::LeaseOffer(Box::new(offer.clone())),
                ),
            )
            .expect("recover exact atomic poll completion");
        let completed = reopened.snapshot().expect("completed snapshot");
        assert_eq!(
            completed.slot(fixture.slot).expect("target offer").offer(),
            &offer
        );
        let completed_checkpoint = completed
            .session()
            .expect("session")
            .lease_poll_checkpoint(carrier)
            .expect("carrier checkpoint");
        assert_eq!(
            completed_checkpoint.current_operation_id(),
            if committed {
                first_successor
            } else {
                replay_successor
            },
            "an exact uncertain replay retains the already committed successor"
        );
        assert_eq!(
            completed_checkpoint.acknowledges_operation_id(),
            Some(predecessor)
        );
        assert_eq!(
            completed_checkpoint.pending_authority_receipts(),
            std::slice::from_ref(&receipt)
        );
    }
}

#[test]
fn retired_poll_cannot_introduce_a_new_command() {
    let scratch = Scratch::new("lease-poll-retired-command");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    let predecessor = OperationId::new();
    journal
        .prepare_lease_poll(fixture.session_id, fixture.slot, predecessor)
        .expect("prepare poll");
    let receipt = authority_receipt("test-authority", 0x66);
    journal
        .complete_lease_poll(
            fixture.session_id,
            LeasePollCompletion::new(
                fixture.slot,
                predecessor,
                OperationId::new(),
                vec![receipt.clone()],
                LeasePollCommandRecord::NoCommand,
            ),
        )
        .expect("complete poll without a command");
    journal
        .acknowledge_lease_authority_receipts(
            fixture.session_id,
            fixture.slot,
            std::slice::from_ref(&receipt),
        )
        .expect("clear poll receipt");
    let before_replay = journal.snapshot().expect("snapshot before stale replay");

    let result = journal.complete_lease_poll(
        fixture.session_id,
        LeasePollCompletion::new(
            fixture.slot,
            predecessor,
            OperationId::new(),
            Vec::new(),
            LeasePollCommandRecord::LeaseOffer(Box::new(fixture.offer(1))),
        ),
    );

    assert!(matches!(
        result,
        Err(JournalError::Invariant(
            JournalInvariantError::CommandReplayConflict
        ))
    ));
    assert_eq!(
        journal.snapshot().expect("snapshot after stale replay"),
        before_replay,
        "a retired poll cannot advance the command cursor or create a slot"
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
            .cloned();
        assert_eq!(
            recovered_checkpoint
                .as_ref()
                .map(automata_ci_runner_journal::LeasePollCheckpoint::current_operation_id),
            committed.then_some(operation_id)
        );
    }
}
