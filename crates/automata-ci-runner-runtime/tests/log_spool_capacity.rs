use super::support;

use std::{sync::Arc, time::Duration};

use automata_ci_core::{AttemptId, JobConclusion, RunnerId};
use automata_ci_runner_journal::{FileJournal, RunnerJournal};
use automata_ci_runner_runtime::{
    RetryPolicy, RunnerRuntimePorts, RunnerSessionSupervisor, SystemRuntimeIds,
};
use automata_ci_runner_spool::{DurableContentStore, FileSpool, FileSpoolOptions, SpoolLimits};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn sealed_head_ack_succeeds_while_spool_rejects_every_persist() {
    let scratch = support::Scratch::new("log-ack-at-full-capacity");
    let runner_id = RunnerId::new();
    let journal = Arc::new(
        FileJournal::open(scratch.journal_root(), runner_id).expect("open runtime journal"),
    );
    let spool = Arc::new(support::AckCapacitySpool::new(
        FileSpool::open(
            scratch.spool_root(),
            Arc::new(support::TestProtector::new()),
        )
        .expect("open runtime spool"),
    ));
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool.clone(),
            Arc::new(support::BurstLogExecutor::new(0)),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(5), client.wait_for_released_slot_poll())
        .await
        .expect("payload-free ACK releases the full-capacity slot");
    assert_eq!(spool.persist_attempts_during_ack(), 0);
    assert_eq!(spool.reclaimed_heads(), 1);
    assert!(
        journal
            .snapshot()
            .expect("snapshot")
            .slot(fixture.slot)
            .is_none()
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("runner shutdown")
        .expect("runtime task")
        .expect("clean shutdown");
}

#[tokio::test]
async fn capacity_reclamation_terminalizes_missing_eos_without_stopping_sibling() {
    const DATA_FRAMES: usize = 64;
    const FRAME_PAYLOAD_BYTES: u64 = 1024;
    const MAX_OBJECT_BYTES: u64 = 128 * 1024;
    const MAX_TOTAL_BYTES: u64 = 300 * 1024;

    // The small store plus deterministic injected full-capacity responses
    // exercises reconciliation around terminal publication while immutable
    // log heads are acknowledged and reclaimed without replacement objects.
    const { assert!(MAX_TOTAL_BYTES > MAX_OBJECT_BYTES) };

    let scratch = support::Scratch::new("log-spool-capacity-reclamation");
    let runner_id = RunnerId::new();
    let journal = Arc::new(
        FileJournal::open(scratch.journal_root(), runner_id).expect("open runtime journal"),
    );
    let limits = SpoolLimits::new(MAX_OBJECT_BYTES, MAX_TOTAL_BYTES, 512, 64)
        .expect("coherent tiny spool limits");
    let spool = Arc::new(support::TerminalCapacityProbeSpool::new(
        FileSpool::open_with_options(
            scratch.spool_root(),
            Arc::new(support::TestProtector::new()),
            FileSpoolOptions::new().with_limits(limits),
        )
        .expect("open capacity-limited runtime spool"),
    ));
    let fixture = support::seed_accepted_offer(journal.as_ref(), spool.as_ref(), runner_id);
    let sibling = support::seed_additional_accepted_offer(
        journal.as_ref(),
        spool.as_ref(),
        runner_id,
        fixture.session_id,
        2,
        2,
    );
    let shutdown = CancellationToken::new();
    let client = Arc::new(support::FailureIsolationClient::new(fixture.session_id));
    let executor = Arc::new(support::CapacityFailureIsolationExecutor::new(
        DATA_FRAMES,
        usize::try_from(FRAME_PAYLOAD_BYTES).expect("payload size"),
    ));
    let retry = RetryPolicy::new(2, Duration::from_millis(1), Duration::from_millis(2))
        .expect("short exact-log retry");
    let runtime = RunnerSessionSupervisor::new(
        support::config_with_slots_and_retry(runner_id, 2, retry),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool.clone(),
            executor.clone(),
            Arc::new(support::FixedClock::new(10_000, 50)),
            Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
            Arc::new(SystemRuntimeIds),
        ),
    );

    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });
    tokio::time::timeout(
        Duration::from_secs(15),
        client.wait_for_released_slot_poll(),
    )
    .await
    .expect("capacity-limited job does not stall");

    assert!(executor.survivor_started());
    assert!(
        !task.is_finished(),
        "one full slot must not stop its sibling"
    );

    assert_terminal_delivery(&client, fixture.lease.attempt_id(), DATA_FRAMES);

    assert!(spool.completed_fault_cycle());
    assert_eq!(spool.terminal_reconciliations(), 1);
    assert_eq!(spool.eos_reconciliations(), 1);
    let snapshot = journal.snapshot().expect("released capacity journal");
    assert!(
        snapshot.slot(fixture.slot).is_none(),
        "terminal result and EOS are acknowledged before slot release",
    );
    let sibling = snapshot
        .slot(sibling.slot)
        .expect("sibling remains durable");
    spool
        .load(sibling.offer().job_ir().content())
        .expect("reconciliation retains sibling JobIR");
    spool
        .load(
            sibling
                .runtime_authority_delivery()
                .expect("sibling post-accept authority delivery")
                .content()
                .content(),
        )
        .expect("reconciliation retains sibling runtime authorities");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("capacity runner shutdown")
        .expect("capacity runtime task")
        .expect("clean shutdown after isolated capacity recovery");
}

fn assert_terminal_delivery(
    client: &support::FailureIsolationClient,
    attempt_id: AttemptId,
    data_frames: usize,
) {
    let frames = client.log_frames();
    assert_eq!(
        frames.last().expect("terminal log frame").sequence().get(),
        u64::try_from(data_frames).expect("EOS sequence"),
        "the empty EOS immediately follows every data frame",
    );
    assert_eq!(
        frames
            .iter()
            .filter(|frame| frame.is_end_of_stream())
            .count(),
        1,
        "the runtime owns and emits exactly one EOS after executor failure",
    );
    assert_eq!(client.terminal_results_after_eos(), vec![true]);
    assert_eq!(
        client.terminal_results(),
        vec![(attempt_id, JobConclusion::Failure)]
    );
}
