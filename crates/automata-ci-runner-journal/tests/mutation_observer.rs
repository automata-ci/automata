mod support;

use std::sync::{Arc, Mutex};

use automata_ci_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions,
    JournalMutationDomain, JournalMutationObservation, JournalMutationOutcome, JournalObserver,
    RunnerJournal,
};
use support::{Fixture, Scratch};

#[derive(Default)]
struct RecordingObserver {
    opened_sizes: Mutex<Vec<u64>>,
    mutations: Mutex<Vec<JournalMutationObservation>>,
}

impl JournalObserver for RecordingObserver {
    fn observe_opened(&self, encoded_bytes: u64) {
        self.opened_sizes
            .lock()
            .expect("observer size lock")
            .push(encoded_bytes);
    }

    fn observe_mutation(&self, observation: JournalMutationObservation) {
        self.mutations
            .lock()
            .expect("observer mutation lock")
            .push(observation);
    }
}

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

#[test]
fn observer_distinguishes_commit_noop_and_semantic_rejection() {
    let scratch = Scratch::new("mutation-observer-semantics");
    let fixture = Fixture::new();
    let observer = Arc::new(RecordingObserver::default());
    let journal = FileJournal::open_with_options(
        scratch.state_root(),
        fixture.runner_id,
        FileJournalOptions::new().with_observer(observer.clone()),
    )
    .expect("open observed journal");

    journal
        .begin_session(fixture.binding())
        .expect("commit session");
    journal
        .begin_session(fixture.binding())
        .expect("exact session replay");
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect_err("missing slot must be rejected");

    let sizes = observer.opened_sizes.lock().expect("observer size lock");
    assert_eq!(sizes.len(), 1);
    assert!(sizes[0] > 0);
    drop(sizes);

    let observations = observer.mutations.lock().expect("observer mutation lock");
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].domain(), JournalMutationDomain::Session);
    assert_eq!(observations[0].outcome(), JournalMutationOutcome::Committed);
    assert!(observations[0].encoded_bytes().is_some());
    assert_eq!(observations[1].domain(), JournalMutationDomain::Session);
    assert_eq!(observations[1].outcome(), JournalMutationOutcome::Noop);
    assert_eq!(observations[1].encoded_bytes(), None);
    assert_eq!(observations[2].domain(), JournalMutationDomain::Slot);
    assert_eq!(observations[2].outcome(), JournalMutationOutcome::Rejected);
}

#[test]
fn observer_distinguishes_known_failure_uncertainty_and_poisoning() {
    let known_scratch = Scratch::new("mutation-observer-known-failure");
    let known_fixture = Fixture::new();
    FileJournal::open(known_scratch.state_root(), known_fixture.runner_id)
        .expect("initialize known-failure journal");
    let known_observer = Arc::new(RecordingObserver::default());
    let known = FileJournal::open_with_options(
        known_scratch.state_root(),
        known_fixture.runner_id,
        FileJournalOptions::new()
            .with_fault_injector(Arc::new(FailAt(CommitStage::DataWritten)))
            .with_observer(known_observer.clone()),
    )
    .expect("reopen known-failure journal");
    known
        .begin_session(known_fixture.binding())
        .expect_err("pre-rename fault must fail");
    assert_eq!(
        known_observer.mutations.lock().expect("observer lock")[0].outcome(),
        JournalMutationOutcome::IoError
    );

    let uncertain_scratch = Scratch::new("mutation-observer-uncertain");
    let uncertain_fixture = Fixture::new();
    FileJournal::open(uncertain_scratch.state_root(), uncertain_fixture.runner_id)
        .expect("initialize uncertain journal");
    let uncertain_observer = Arc::new(RecordingObserver::default());
    let uncertain = FileJournal::open_with_options(
        uncertain_scratch.state_root(),
        uncertain_fixture.runner_id,
        FileJournalOptions::new()
            .with_fault_injector(Arc::new(FailAt(CommitStage::Renamed)))
            .with_observer(uncertain_observer.clone()),
    )
    .expect("reopen uncertain journal");
    uncertain
        .begin_session(uncertain_fixture.binding())
        .expect_err("post-rename fault must be uncertain");
    uncertain
        .begin_session(uncertain_fixture.binding())
        .expect_err("uncertain handle must remain poisoned");

    let observations = uncertain_observer
        .mutations
        .lock()
        .expect("observer mutation lock");
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].outcome(), JournalMutationOutcome::Uncertain);
    assert_eq!(observations[1].outcome(), JournalMutationOutcome::Poisoned);
}
