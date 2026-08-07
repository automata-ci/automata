mod support;

use std::{sync::Arc, time::Duration};

use automata_core::{JobConclusion, RunnerId};
use automata_runner_journal::RunnerJournal;
use automata_runner_runtime::{
    RetryPolicy, RunnerRuntimePorts, RunnerSessionSupervisor, SystemRuntimeIds,
};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_slot_waits_for_sibling_payload_publication_before_reconciliation() {
    let harness = RaceHarness::start(support::ContentRaceMode::PublicationFirst);

    tokio::time::timeout(Duration::from_secs(2), harness.probe.wait_for_publication())
        .await
        .expect("sibling holds a payload-first publication");
    tokio::time::timeout(Duration::from_secs(2), harness.client.wait_for_cancel())
        .await
        .expect("preparing slot receives cancellation while publication is active");
    assert!(
        !harness.task.is_finished(),
        "a valid spool publication fence must not stop the supervisor"
    );

    harness.probe.release_publication();
    harness.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sibling_payload_publication_waits_while_cancelled_slot_reconciles() {
    let harness = RaceHarness::start(support::ContentRaceMode::ReconciliationFirst);

    tokio::time::timeout(Duration::from_secs(2), harness.client.wait_for_cancel())
        .await
        .expect("preparing slot receives cancellation");
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.probe.wait_for_reconciliation(),
    )
    .await
    .expect("cancelled slot enters terminal reconciliation");
    if tokio::time::timeout(Duration::from_secs(2), harness.probe.wait_for_log_attempt())
        .await
        .is_err()
    {
        harness.probe.release_reconciliation();
        harness.shutdown.cancel();
        panic!("sibling attempts a payload publication");
    }
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        !harness.probe.persist_entered_during_reconciliation(),
        "runtime coordination must stop publication before the spool's fail-fast fence"
    );
    assert!(
        !harness.task.is_finished(),
        "an active reconciliation must not isolate the publishing sibling"
    );

    harness.probe.release_reconciliation();
    harness.finish().await;
}

struct RaceHarness {
    cancelled_attempt: automata_core::AttemptId,
    cancelled_slot: automata_protocol::RunnerSlotOrdinal,
    survivor_slot: automata_protocol::RunnerSlotOrdinal,
    journal: Arc<automata_runner_journal::FileJournal>,
    probe: support::ContentRaceProbe,
    client: Arc<support::CancellationContentRaceClient>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), automata_runner_runtime::RunnerRuntimeError>>,
    _scratch: support::Scratch,
}

impl RaceHarness {
    fn start(mode: support::ContentRaceMode) -> Self {
        let scratch = support::Scratch::new(match mode {
            support::ContentRaceMode::PublicationFirst => "publication-before-reconciliation",
            support::ContentRaceMode::ReconciliationFirst => "reconciliation-before-publication",
        });
        let runner_id = RunnerId::new();
        let (journal, file_spool) = support::durable_ports(&scratch, runner_id);
        let cancelled =
            support::seed_accepted_offer(journal.as_ref(), file_spool.as_ref(), runner_id);
        let survivor = support::seed_additional_accepted_offer(
            journal.as_ref(),
            file_spool.as_ref(),
            runner_id,
            cancelled.session_id,
            2,
            2,
        );
        let probe = support::ContentRaceProbe::new(mode);
        let spool = Arc::new(support::ContentRaceSpool::new(file_spool, probe.clone()));
        let executor = Arc::new(support::CancellationContentRaceExecutor::new(probe.clone()));
        let client = Arc::new(support::CancellationContentRaceClient::new(
            cancelled.session_id,
            &cancelled.lease,
            executor.clone(),
            probe.clone(),
        ));
        let shutdown = CancellationToken::new();
        let runtime = RunnerSessionSupervisor::new(
            support::config_with_slots_and_retry(runner_id, 2, RetryPolicy::default()),
            RunnerRuntimePorts::new(
                client.clone(),
                journal.clone(),
                spool,
                executor.clone(),
                Arc::new(support::FixedClock::new(10_000, 50)),
                Arc::new(automata_runner_runtime::TokioRuntimeSleeper),
                Arc::new(SystemRuntimeIds),
            ),
        );
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { runtime.run(task_shutdown).await });
        Self {
            cancelled_attempt: cancelled.lease.attempt_id(),
            cancelled_slot: cancelled.slot,
            survivor_slot: survivor.slot,
            journal,
            probe,
            client,
            shutdown,
            task,
            _scratch: scratch,
        }
    }

    async fn finish(self) {
        tokio::time::timeout(
            Duration::from_secs(2),
            self.probe.wait_for_log_publication_finished(),
        )
        .await
        .expect("sibling publication commits after coordination releases it");
        tokio::time::timeout(
            Duration::from_secs(2),
            self.client.wait_for_released_slot_poll(),
        )
        .await
        .expect("cancelled terminal slot releases and resumes polling");
        assert_eq!(
            self.client.terminal_results(),
            vec![(self.cancelled_attempt, JobConclusion::Cancelled)]
        );
        let snapshot = self.journal.snapshot().expect("post-race journal snapshot");
        assert!(snapshot.slot(self.cancelled_slot).is_none());
        assert!(snapshot.slot(self.survivor_slot).is_some());
        assert!(
            !self.task.is_finished(),
            "the healthy sibling and supervisor continue after cancellation"
        );

        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("runner shutdown")
            .expect("runtime task")
            .expect("content fence races remain locally coordinated");
    }
}
