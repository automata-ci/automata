use super::support;

use std::sync::{Arc, Barrier};

use automata_ci_core::JobIrVersion;
use automata_ci_runner_journal::{
    JobIrContentRef, JournalContentRetainSet, LeaseOfferRecord, RunnerJournal,
};
use automata_ci_runner_spool::{
    ContentKind, DurableContentRef, DurableContentStore, FileSpool, RetainedContentError,
    RetainedContentSource, SpoolError,
};
use support::{Fixture, Scratch, TestProtector};

struct BlockingRetainSet<'a> {
    journal: JournalContentRetainSet<'a>,
    captured: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl RetainedContentSource for BlockingRetainSet<'_> {
    fn retained_content(&self) -> Result<Vec<DurableContentRef>, RetainedContentError> {
        let retained = self.journal.retained_content()?;
        self.captured.wait();
        self.release.wait();
        Ok(retained)
    }
}

fn offer(fixture: &Fixture, content: DurableContentRef) -> LeaseOfferRecord {
    LeaseOfferRecord::new(
        fixture.slot,
        fixture.lease.clone(),
        JobIrContentRef::new(JobIrVersion::current(), content).expect("JobIR content"),
        Fixture::runtime_authority(),
        Fixture::command(1),
    )
    .expect("lease offer")
}

#[test]
fn publication_starting_after_retain_snapshot_cannot_race_reconciliation() {
    let scratch = Scratch::new("concurrent-reconciliation-fence");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    let spool =
        FileSpool::open(scratch.spool_root(), Arc::new(TestProtector::new())).expect("spool");
    let captured = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let source = BlockingRetainSet {
        journal: JournalContentRetainSet::new(&journal),
        captured: captured.clone(),
        release: release.clone(),
    };

    std::thread::scope(|scope| {
        let reconciliation = scope.spawn(|| spool.reconcile(&source));
        captured.wait();
        assert!(matches!(
            spool.persist(ContentKind::JobIr, b"concurrent canonical JobIR"),
            Err(SpoolError::ReconciliationInProgress)
        ));
        release.wait();
        reconciliation
            .join()
            .expect("reconciliation thread")
            .expect("empty reconciliation");
    });

    let snapshot = spool
        .persist(ContentKind::JobIr, b"concurrent canonical JobIR")
        .expect("retry after reconciliation")
        .commit_with(|content| {
            journal.record_lease_offer(fixture.session_id, offer(&fixture, content.clone()))
        })
        .expect("publish after reconciliation");
    let reference = snapshot
        .slot(fixture.slot)
        .expect("slot")
        .offer()
        .job_ir()
        .content();
    assert_eq!(
        spool.load(reference).expect("published content"),
        b"concurrent canonical JobIR"
    );
}
