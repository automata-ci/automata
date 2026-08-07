mod support;

use std::sync::Arc;

use automata_core::{JobIrVersion, JobLifecycle, LogSequence, LogStreamId, OperationId};
use automata_protocol::ProtocolVersion;
use automata_runner_journal::{
    CommitFault, CommitFaultInjector, CommitStage, FileJournal, FileJournalOptions,
    JobIrContentRef, JournalContentRetainSet, JournalError, JournalInvariantError, JournalSnapshot,
    LeaseOfferRecord, LogProductionRecord, RunnerJournal, RuntimeAuthorityContentRef,
    SessionBinding, TerminalResultRecord,
};
use automata_runner_spool::{
    ContentCommitFault, ContentCommitFaultInjector, ContentCommitStage, ContentKind,
    DurableContentPublication, DurableContentRef, DurableContentStore, FileSpool, FileSpoolOptions,
    SpoolError,
};
use support::{Fixture, Scratch, TestProtector, record_and_ack_terminal};

#[derive(Debug)]
struct FailJournalAt(CommitStage);

impl CommitFaultInjector for FailJournalAt {
    fn check(&self, stage: CommitStage) -> Result<(), CommitFault> {
        if stage == self.0 {
            Err(CommitFault)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct FailContentAt(ContentCommitStage);

impl ContentCommitFaultInjector for FailContentAt {
    fn check(&self, stage: ContentCommitStage) -> Result<(), ContentCommitFault> {
        if stage == self.0 {
            Err(ContentCommitFault)
        } else {
            Ok(())
        }
    }
}

fn faulting_journal(scratch: &Scratch, fixture: &Fixture, stage: CommitStage) -> FileJournal {
    FileJournal::open_with_options(
        scratch.state_root(),
        fixture.runner_id,
        FileJournalOptions::new().with_fault_injector(Arc::new(FailJournalAt(stage))),
    )
    .expect("open faulting journal")
}

fn offer_with_job_content(
    fixture: &Fixture,
    job_ir: automata_runner_spool::DurableContentRef,
) -> LeaseOfferRecord {
    LeaseOfferRecord::new(
        fixture.slot,
        fixture.lease.clone(),
        JobIrContentRef::new(JobIrVersion::current(), job_ir).expect("JobIR reference"),
        Fixture::runtime_authority(),
        Fixture::command(1),
    )
    .expect("lease offer")
}

fn offer_with_contents(
    fixture: &Fixture,
    job_ir: automata_runner_spool::DurableContentRef,
    runtime_authority: automata_runner_spool::DurableContentRef,
) -> LeaseOfferRecord {
    LeaseOfferRecord::new(
        fixture.slot,
        fixture.lease.clone(),
        JobIrContentRef::new(JobIrVersion::current(), job_ir).expect("JobIR reference"),
        RuntimeAuthorityContentRef::new(runtime_authority).expect("runtime-authority reference"),
        Fixture::command(1),
    )
    .expect("lease offer")
}

fn journal_failed_terminal(
    journal: &dyn RunnerJournal,
    fixture: &Fixture,
    operation_id: OperationId,
    content: &DurableContentRef,
) -> Result<TerminalResultRecord, JournalError> {
    let result = TerminalResultRecord::new(operation_id, content.clone()).expect("result record");
    journal.record_terminal_result(
        fixture.session_id,
        fixture.slot,
        fixture.lease.guard(),
        JobLifecycle::Failed,
        result.clone(),
    )?;
    Ok(result)
}

fn record_log_publication(
    publication: DurableContentPublication<'_>,
    journal: &dyn RunnerJournal,
    fixture: &Fixture,
    stream: LogStreamId,
    sequence: u64,
    end_of_stream: bool,
) -> (JournalSnapshot, LogProductionRecord) {
    publication
        .commit_with(|content| {
            let production = LogProductionRecord::new(
                stream,
                LogSequence::new(sequence),
                end_of_stream,
                content.clone(),
            )
            .expect("log production");
            journal
                .record_log_produced(
                    fixture.session_id,
                    fixture.slot,
                    fixture.lease.guard(),
                    production.clone(),
                )
                .map(|snapshot| (snapshot, production))
        })
        .expect("journal cumulative log content")
}

fn assert_session_negotiation_is_recovered(journal: &dyn RunnerJournal, fixture: &Fixture) {
    let session = journal
        .snapshot()
        .expect("reopen")
        .session()
        .expect("session")
        .clone();
    assert_eq!(
        session.selected_protocol(),
        fixture.binding().selected_protocol()
    );
    assert_eq!(session.selected_job_ir(), JobIrVersion::current());
    let different_protocol = ProtocolVersion::new(fixture.binding().selected_protocol().get() + 1)
        .expect("positive protocol version");
    assert!(matches!(
        journal.begin_session(SessionBinding::new(
            fixture.session_id,
            different_protocol,
            JobIrVersion::current(),
        )),
        Err(JournalError::Invariant(
            JournalInvariantError::SessionNegotiationMismatch
        ))
    ));
}

fn inject_result_ack_fault(scratch: &Scratch, fixture: &Fixture, result: &TerminalResultRecord) {
    let faulting = faulting_journal(scratch, fixture, CommitStage::FileSynced);
    assert!(matches!(
        faulting.acknowledge_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            result.operation_id(),
        ),
        Err(JournalError::InjectedFault(CommitStage::FileSynced))
    ));
}

fn inject_result_ack_unknown(scratch: &Scratch, fixture: &Fixture, result: &TerminalResultRecord) {
    let faulting = faulting_journal(scratch, fixture, CommitStage::Renamed);
    assert!(matches!(
        faulting.acknowledge_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            result.operation_id(),
        ),
        Err(JournalError::CommitOutcomeUnknown)
    ));
}

fn record_and_fence_unacknowledged_result(
    journal: &dyn RunnerJournal,
    fixture: &Fixture,
    result: &TerminalResultRecord,
) {
    let recorded = journal
        .record_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Failed,
            result.clone(),
        )
        .expect("record result outbox");
    let replay = journal
        .record_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Failed,
            result.clone(),
        )
        .expect("exact replay");
    assert_eq!(recorded.revision(), replay.revision());
    assert_eq!(
        replay
            .slot(fixture.slot)
            .expect("slot")
            .terminal_result()
            .expect("result"),
        result
    );
    assert!(matches!(
        journal.release_slot(fixture.session_id, fixture.slot, fixture.lease.guard()),
        Err(JournalError::Invariant(
            JournalInvariantError::TerminalResultNotAcknowledged
        ))
    ));
    assert!(matches!(
        journal.acknowledge_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            OperationId::new(),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::TerminalResultOperationMismatch
        ))
    ));
}

fn acknowledge_replay_and_release_result(
    journal: &dyn RunnerJournal,
    fixture: &Fixture,
    result: TerminalResultRecord,
) {
    journal
        .acknowledge_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            result.operation_id(),
        )
        .expect("ack exact outbox operation");
    let replay = journal
        .record_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Failed,
            result,
        )
        .expect("exact payload replay after ack");
    assert!(
        replay
            .slot(fixture.slot)
            .expect("slot")
            .terminal_result()
            .expect("result")
            .is_acknowledged()
    );
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release after exact result ack");
}

#[test]
fn payload_fsync_precedes_offer_cursor_and_exact_session_negotiation_survives_reopen() {
    let scratch = Scratch::new("payload-before-offer");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin negotiated session");

    let protector = Arc::new(TestProtector::new());
    let faulting_spool = FileSpool::open_with_options(
        scratch.spool_root(),
        protector.clone(),
        FileSpoolOptions::new()
            .with_fault_injector(Arc::new(FailContentAt(ContentCommitStage::FileSynced))),
    )
    .expect("open faulting spool");
    assert!(matches!(
        faulting_spool.persist(ContentKind::JobIr, b"canonical JobIR v3"),
        Err(SpoolError::InjectedFault(ContentCommitStage::FileSynced))
    ));
    assert!(
        journal
            .snapshot()
            .expect("journal unchanged")
            .session()
            .expect("session")
            .command_cursor()
            .acknowledged_through()
            .is_none()
    );
    drop(faulting_spool);

    let spool = FileSpool::open(scratch.spool_root(), protector).expect("recover spool");
    let job_bytes = b"canonical JobIR v3";
    let job_publication = spool
        .persist(ContentKind::JobIr, job_bytes)
        .expect("commit verified JobIR bytes first");
    drop(journal);

    let faulting = faulting_journal(&scratch, &fixture, CommitStage::FileSynced);
    let failed = job_publication
        .commit_with(|job_content| {
            faulting.record_lease_offer(
                fixture.session_id,
                offer_with_job_content(&fixture, job_content.clone()),
            )
        })
        .expect_err("journal fault must retain publication");
    let (error, job_publication) = failed.into_parts();
    assert!(matches!(
        error,
        JournalError::InjectedFault(CommitStage::FileSynced)
    ));
    drop(faulting);

    let journal = fixture.open(&scratch);
    let before_offer = journal.snapshot().expect("recover old journal state");
    assert!(before_offer.slots().is_empty());
    assert!(
        before_offer
            .session()
            .expect("session")
            .command_cursor()
            .acknowledged_through()
            .is_none()
    );
    let (recorded, job_content) = job_publication
        .commit_with(|job_content| {
            assert_eq!(
                spool.load(job_content).expect("payload retained"),
                job_bytes
            );
            journal
                .record_lease_offer(
                    fixture.session_id,
                    offer_with_job_content(&fixture, job_content.clone()),
                )
                .map(|snapshot| (snapshot, job_content.clone()))
        })
        .expect("commit offer after payload");
    let durable_offer = recorded.slot(fixture.slot).expect("slot").offer();
    assert_eq!(durable_offer.job_ir().version(), JobIrVersion::current());
    assert_eq!(durable_offer.job_ir().content(), &job_content);
    assert_eq!(
        durable_offer.job_ir().content().size(),
        job_bytes.len() as u64
    );
    drop(journal);

    let journal = fixture.open(&scratch);
    assert_session_negotiation_is_recovered(&journal, &fixture);
}

#[test]
fn terminal_result_outbox_replays_exact_bytes_and_ack_is_a_release_fence() {
    let scratch = Scratch::new("terminal-result-outbox");
    let fixture = Fixture::new();
    let protector = Arc::new(TestProtector::new());
    let spool = FileSpool::open(scratch.spool_root(), protector).expect("open spool");
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    spool
        .persist(ContentKind::JobIr, b"job")
        .expect("persist JobIR")
        .commit_with(|job_content| {
            journal.record_lease_offer(
                fixture.session_id,
                offer_with_job_content(&fixture, job_content.clone()),
            )
        })
        .expect("journal JobIR reference");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");

    let result_bytes = b"exact canonical terminal result";
    let result_publication = spool
        .persist(ContentKind::TerminalResult, result_bytes)
        .expect("persist result first");
    let result_operation_id = OperationId::new();
    drop(journal);

    let faulting = faulting_journal(&scratch, &fixture, CommitStage::FileSynced);
    let failed = result_publication
        .commit_with(|result_content| {
            journal_failed_terminal(&faulting, &fixture, result_operation_id, result_content)
        })
        .expect_err("pre-rename journal fault");
    let (error, result_publication) = failed.into_parts();
    assert!(matches!(
        error,
        JournalError::InjectedFault(CommitStage::FileSynced)
    ));
    drop(faulting);

    let journal = fixture.open(&scratch);
    assert!(
        !journal
            .snapshot()
            .expect("old state")
            .slot(fixture.slot)
            .expect("slot")
            .lifecycle()
            .is_terminal()
    );
    drop(journal);

    let faulting = faulting_journal(&scratch, &fixture, CommitStage::Renamed);
    let failed = result_publication
        .commit_with(|result_content| {
            assert_eq!(
                spool.load(result_content).expect("result retained"),
                result_bytes
            );
            journal_failed_terminal(&faulting, &fixture, result_operation_id, result_content)
        })
        .expect_err("post-rename journal fault");
    let (error, result_publication) = failed.into_parts();
    assert!(matches!(error, JournalError::CommitOutcomeUnknown));
    drop(faulting);

    let journal = fixture.open(&scratch);
    let result = result_publication
        .commit_with(|result_content| {
            journal_failed_terminal(&journal, &fixture, result_operation_id, result_content)
        })
        .expect("recover exact result publication");
    record_and_fence_unacknowledged_result(&journal, &fixture, &result);
    drop(journal);

    inject_result_ack_fault(&scratch, &fixture, &result);

    let journal = fixture.open(&scratch);
    assert!(
        !journal
            .snapshot()
            .expect("unacknowledged recovery")
            .slot(fixture.slot)
            .expect("slot")
            .terminal_result()
            .expect("result")
            .is_acknowledged()
    );
    drop(journal);
    inject_result_ack_unknown(&scratch, &fixture, &result);

    let journal = fixture.open(&scratch);
    assert!(
        journal
            .snapshot()
            .expect("acknowledged recovery")
            .slot(fixture.slot)
            .expect("slot")
            .terminal_result()
            .expect("result")
            .is_acknowledged()
    );
    acknowledge_replay_and_release_result(&journal, &fixture, result);
}

#[test]
fn log_cursor_is_bound_to_cumulative_durable_content_and_eos_ack() {
    let scratch = Scratch::new("durable-log-spool");
    let fixture = Fixture::new();
    let spool =
        FileSpool::open(scratch.spool_root(), Arc::new(TestProtector::new())).expect("open spool");
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let stream = LogStreamId::new();
    spool
        .persist(ContentKind::LogSpool, b"")
        .expect("persist empty spool")
        .commit_with(|empty| {
            journal.open_log_stream(
                fixture.session_id,
                fixture.slot,
                fixture.lease.guard(),
                stream,
                empty.clone(),
            )
        })
        .expect("open log stream");
    let first_publication = spool
        .persist(ContentKind::LogSpool, b"frame-zero")
        .expect("persist first cumulative spool");
    let (produced, first_production) =
        record_log_publication(first_publication, &journal, &fixture, stream, 0, false);
    let replay = journal
        .record_log_produced(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            first_production,
        )
        .expect("exact frame replay");
    assert_eq!(produced.revision(), replay.revision());

    let final_publication = spool
        .persist(ContentKind::LogSpool, b"frame-zero\nframe-one-eos")
        .expect("persist terminal cumulative spool");
    let (_, final_production) =
        record_log_publication(final_publication, &journal, &fixture, stream, 1, true);
    let final_content = final_production.spool_content().clone();
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
    assert!(matches!(
        journal.release_slot(fixture.session_id, fixture.slot, fixture.lease.guard()),
        Err(JournalError::Invariant(
            JournalInvariantError::LogDeliveryIncomplete
        ))
    ));
    drop(journal);

    let journal = fixture.open(&scratch);
    let recovered_log = journal
        .snapshot()
        .expect("recover")
        .slot(fixture.slot)
        .expect("slot")
        .log_delivery()
        .expect("log")
        .clone();
    assert_eq!(
        journal
            .snapshot()
            .expect("complete retain set")
            .content_references()
            .count(),
        4
    );
    assert_eq!(recovered_log.spool_content(), &final_content);
    assert_eq!(
        spool.load(&final_content).expect("load spool"),
        b"frame-zero\nframe-one-eos"
    );
    journal
        .acknowledge_log(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
            LogSequence::new(1),
        )
        .expect("ack EOS");
    journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release after EOS ack");
}

#[test]
fn reconciliation_is_fenced_until_payload_publication_is_journaled() {
    let scratch = Scratch::new("publication-reconciliation-fence");
    let fixture = Fixture::new();
    let spool =
        FileSpool::open(scratch.spool_root(), Arc::new(TestProtector::new())).expect("open spool");
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");

    let publication = spool
        .persist(ContentKind::JobIr, b"race-free canonical JobIR")
        .expect("persist payload first");
    assert!(matches!(
        spool.reconcile(&JournalContentRetainSet::new(&journal)),
        Err(SpoolError::PublicationsInFlight)
    ));
    assert_eq!(spool.usage().expect("payload remains in flight").0, 1);

    let snapshot = publication
        .commit_with(|job_content| {
            let authority_publication = spool
                .persist(ContentKind::RuntimeAuthority, b"exact protected authority")
                .expect("persist protected authority");
            let committed = authority_publication.commit_with(|authority_content| {
                journal.record_lease_offer(
                    fixture.session_id,
                    offer_with_contents(&fixture, job_content.clone(), authority_content.clone()),
                )
            });
            match committed {
                Ok(snapshot) => Ok(snapshot),
                Err(failure) => {
                    let (error, publication) = failure.into_parts();
                    publication.abort();
                    Err(error)
                }
            }
        })
        .expect("journal publication");
    let offer = snapshot.slot(fixture.slot).expect("slot").offer();
    let reference = offer.job_ir().content().clone();
    let authority_reference = offer.runtime_authorities().content().clone();
    spool
        .reconcile(&JournalContentRetainSet::new(&journal))
        .expect("snapshot captured under publication exclusion");
    assert_eq!(
        spool.load(&reference).expect("retained payload"),
        b"race-free canonical JobIR"
    );
    assert_eq!(
        spool
            .load(&authority_reference)
            .expect("retained protected authority"),
        b"exact protected authority"
    );
    drop(journal);
    drop(spool);

    let journal = fixture.open(&scratch);
    let spool = FileSpool::open(scratch.spool_root(), Arc::new(TestProtector::new()))
        .expect("reopen spool");
    spool
        .reconcile(&JournalContentRetainSet::new(&journal))
        .expect("reconcile after crash boundary");
    assert_eq!(
        spool.load(&reference).expect("reopened retained payload"),
        b"race-free canonical JobIR"
    );
    assert_eq!(
        spool
            .load(&authority_reference)
            .expect("reopened protected authority"),
        b"exact protected authority"
    );
}

#[test]
fn explicitly_aborted_payload_is_reclaimed_after_reopen() {
    let scratch = Scratch::new("aborted-publication-recovery");
    let fixture = Fixture::new();
    let spool =
        FileSpool::open(scratch.spool_root(), Arc::new(TestProtector::new())).expect("open spool");
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    spool
        .persist(
            ContentKind::TerminalResult,
            b"payload whose journal mutation was known not committed",
        )
        .expect("persist payload first")
        .abort();
    assert_eq!(spool.usage().expect("orphan remains durable").0, 1);
    drop(journal);
    drop(spool);

    let journal = fixture.open(&scratch);
    let spool = FileSpool::open(scratch.spool_root(), Arc::new(TestProtector::new()))
        .expect("reopen spool");
    spool
        .reconcile(&JournalContentRetainSet::new(&journal))
        .expect("reclaim payload-first orphan");
    assert_eq!(spool.usage().expect("orphan reclaimed"), (0, 0));
}
