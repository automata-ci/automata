use super::support;

use std::sync::Arc;

use automata_ci_core::{JobIrVersion, RunnerSessionId};
use automata_ci_protocol::{LeaseRejectionReason, PROTOCOL_MAX_VERSION};
use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions, JournalError,
    LeaseOfferStatus, RunnerJournal, SessionBinding,
};
use support::{Fixture, Scratch};

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

#[test]
fn faults_before_rename_preserve_the_previous_commit_and_reopen_cleans_staging() {
    for stage in [
        CommitStage::StagingCreated,
        CommitStage::DataWritten,
        CommitStage::FileSynced,
    ] {
        let scratch = Scratch::new(&format!("pre-rename-{stage:?}"));
        let fixture = Fixture::new();
        drop(fixture.open(&scratch));
        let journal =
            FileJournal::open_with_options(scratch.state_root(), fixture.runner_id, options(stage))
                .expect("open with fault injector");
        let session = RunnerSessionId::new();
        assert!(matches!(
            journal.begin_session(SessionBinding::new(
                session,
                PROTOCOL_MAX_VERSION,
                JobIrVersion::current(),
            )),
            Err(JournalError::InjectedFault(received)) if received == stage
        ));
        assert_eq!(journal.snapshot().expect("old snapshot").revision(), 0);
        assert!(
            journal
                .snapshot()
                .expect("old snapshot")
                .session()
                .is_none()
        );
        drop(journal);

        let recovered = fixture.open(&scratch);
        assert_eq!(recovered.snapshot().expect("recovered").revision(), 0);
        assert!(recovered.snapshot().expect("recovered").session().is_none());
        assert!(
            std::fs::read_dir(scratch.state_root().as_path())
                .expect("read root")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".runner-journal.stage-"))
        );
    }
}

#[test]
fn faults_after_rename_poison_the_handle_and_reopen_recovers_the_new_commit() {
    for stage in [CommitStage::Renamed, CommitStage::DirectorySynced] {
        let scratch = Scratch::new(&format!("post-rename-{stage:?}"));
        let fixture = Fixture::new();
        drop(fixture.open(&scratch));
        let session = RunnerSessionId::new();
        let journal =
            FileJournal::open_with_options(scratch.state_root(), fixture.runner_id, options(stage))
                .expect("open with fault injector");
        assert!(matches!(
            journal.begin_session(SessionBinding::new(
                session,
                PROTOCOL_MAX_VERSION,
                JobIrVersion::current(),
            )),
            Err(JournalError::CommitOutcomeUnknown)
        ));
        assert!(matches!(journal.snapshot(), Err(JournalError::Poisoned)));
        drop(journal);

        let recovered = fixture.open(&scratch).snapshot().expect("recover");
        assert_eq!(recovered.revision(), 1);
        assert_eq!(
            recovered.session().expect("new session").session_id(),
            session
        );
    }
}

#[test]
fn interrupted_initialization_is_recoverable_at_every_commit_boundary() {
    for stage in [
        CommitStage::StagingCreated,
        CommitStage::DataWritten,
        CommitStage::FileSynced,
        CommitStage::Renamed,
        CommitStage::DirectorySynced,
    ] {
        let scratch = Scratch::new(&format!("initialization-{stage:?}"));
        let fixture = Fixture::new();
        assert!(FileJournal::open_with_options(
            scratch.state_root(),
            fixture.runner_id,
            options(stage),
        )
        .is_err());
        let recovered = fixture.open(&scratch);
        assert_eq!(recovered.snapshot().expect("snapshot").revision(), 0);
        assert_eq!(
            recovered.snapshot().expect("snapshot").runner_id(),
            fixture.runner_id
        );
    }
}

#[test]
fn rejected_offer_response_recovers_on_both_sides_of_atomic_rename() {
    let before_rename = Scratch::new("rejection-before-rename");
    let fixture = Fixture::new();
    let journal = fixture.open(&before_rename);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    drop(journal);
    let journal = FileJournal::open_with_options(
        before_rename.state_root(),
        fixture.runner_id,
        options(CommitStage::FileSynced),
    )
    .expect("faulting journal");
    assert!(matches!(
        journal.reject_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LeaseRejectionReason::ShuttingDown,
            automata_ci_core::OperationId::new(),
            Fixture::delivery_time(),
        ),
        Err(JournalError::InjectedFault(CommitStage::FileSynced))
    ));
    drop(journal);
    let recovered_before_rename = fixture
        .open(&before_rename)
        .snapshot()
        .expect("recover old state");
    assert_eq!(
        recovered_before_rename
            .slot(fixture.slot)
            .expect("slot")
            .offer_status(),
        LeaseOfferStatus::Recorded
    );
    assert_eq!(
        recovered_before_rename
            .pending_delivery_timestamps()
            .lease_rejection(),
        None
    );

    let after_rename = Scratch::new("rejection-after-rename");
    let fixture = Fixture::new();
    let journal = fixture.open(&after_rename);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    drop(journal);
    let response_operation = automata_ci_core::OperationId::new();
    let journal = FileJournal::open_with_options(
        after_rename.state_root(),
        fixture.runner_id,
        options(CommitStage::Renamed),
    )
    .expect("faulting journal");
    assert!(matches!(
        journal.reject_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LeaseRejectionReason::ShuttingDown,
            response_operation,
            Fixture::delivery_time(),
        ),
        Err(JournalError::CommitOutcomeUnknown)
    ));
    drop(journal);
    let recovered = fixture
        .open(&after_rename)
        .snapshot()
        .expect("recover new state");
    let rejection = recovered
        .slot(fixture.slot)
        .expect("slot")
        .rejection()
        .expect("rejection");
    assert_eq!(
        recovered.pending_delivery_timestamps().lease_rejection(),
        Some(Fixture::delivery_time())
    );
    assert_eq!(rejection.reason(), &LeaseRejectionReason::ShuttingDown);
    assert_eq!(rejection.response_operation_id(), response_operation);
}
