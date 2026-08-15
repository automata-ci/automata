use super::support;

use std::{sync::Arc, time::Duration};

use automata_ci_core::{JobConclusion, LogSequence, RunnerId};
use automata_ci_protocol::{ProtocolLimits, RunnerToServer};
use automata_ci_runner_journal::RunnerJournal;
use automata_ci_runner_runtime::{
    RetryPolicy, RunnerRuntimePorts, RunnerSessionSupervisor, SystemRuntimeIds,
};
use automata_ci_runner_spool::DurableContentStore;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_slot_waits_for_sibling_payload_publication_before_reconciliation() {
    let harness = RaceHarness::start(support::ContentRaceMode::PublicationFirst);

    tokio::time::timeout(Duration::from_secs(5), harness.probe.wait_for_publication())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sealed_head_ack_and_concurrent_tail_append_remain_disjoint() {
    let scratch = support::Scratch::new("log-seal-append-race");
    let runner_id = RunnerId::new();
    let (journal, file_spool) = support::durable_ports(&scratch, runner_id);
    let fixture = support::seed_accepted_offer(journal.as_ref(), file_spool.as_ref(), runner_id);
    let spool = Arc::new(support::BlockingSegmentLoadSpool::new(file_spool));
    let executor = Arc::new(support::LogSegmentRaceExecutor::new());
    let client = Arc::new(support::LogSegmentRaceClient::new(
        fixture.session_id,
        fixture.lease,
    ));
    let clock = Arc::new(support::ManualClock::new(10_000, 50));
    let sleeper = Arc::new(support::ManualDeadlineSleeper::new(Arc::clone(&clock)));
    let runtime = RunnerSessionSupervisor::new(
        support::config(runner_id),
        RunnerRuntimePorts::new(
            client.clone(),
            journal.clone(),
            spool.clone(),
            executor.clone(),
            clock,
            sleeper.clone(),
            Arc::new(SystemRuntimeIds),
        ),
    );
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { runtime.run(task_shutdown).await });

    tokio::time::timeout(Duration::from_secs(2), executor.wait_for_first_emit())
        .await
        .expect("executor emits frame zero");
    spool.arm_next_log_load();
    sleeper.advance(10_000);
    tokio::time::timeout(Duration::from_secs(2), spool.wait_for_blocked_load())
        .await
        .expect("sealed head is copied inside the snapshot/load fence");

    executor.trigger_second_emit();
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        !executor.second_emit_finished(),
        "tail append waits outside the atomic sealed-head snapshot/load fence"
    );
    spool.release_blocked_load();
    tokio::time::timeout(Duration::from_secs(2), client.wait_for_log_batches(1))
        .await
        .expect("client captures frame zero before withholding its acknowledgement");
    assert_eq!(client.log_batches(), vec![(0, 0)]);

    tokio::time::timeout(Duration::from_secs(2), executor.wait_for_second_emit())
        .await
        .expect("frame one appends while the sealed head awaits ACK");

    client.release_first_ack();
    tokio::time::timeout(Duration::from_secs(2), client.wait_for_first_ack_returned())
        .await
        .expect("frame-zero acknowledgement is returned while frame one remains blocked");
    assert!(executor.second_emit_finished());
    sleeper.advance(10_000);
    tokio::time::timeout(Duration::from_secs(2), client.wait_for_log_batches(2))
        .await
        .expect("client captures frame one and withholds its acknowledgement");
    assert_eq!(client.log_batches(), vec![(0, 0), (1, 1)]);

    let segment_content = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = journal.snapshot().expect("post-race journal snapshot");
            let delivery = snapshot
                .slot(fixture.slot)
                .and_then(|slot| slot.log_delivery())
                .expect("active log delivery");
            if delivery.acknowledged_through().map(LogSequence::get) == Some(0)
                && delivery.produced_through().map(LogSequence::get) == Some(1)
            {
                break delivery
                    .head_segment()
                    .expect("unacknowledged segment")
                    .content()
                    .clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("frame zero is removed while frame one remains durable and unacknowledged");
    let durable = spool
        .load(&segment_content)
        .expect("load final durable segment");
    assert_eq!(
        decode_log_spool(&durable),
        vec![(1, b"race-frame-1".to_vec())],
        "a new immutable tail cannot reintroduce the acknowledged head"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("runner shutdown")
        .expect("runtime task")
        .expect("log sealing, append, and ACK remain coordinated");
}

fn decode_log_spool(encoded: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let limits = ProtocolLimits::default();
    let mut remaining = encoded;
    let mut frames = Vec::new();
    while !remaining.is_empty() {
        let (prefix, payload) = remaining.split_at(4);
        let length = usize::try_from(u32::from_be_bytes(
            prefix.try_into().expect("four-byte record length"),
        ))
        .expect("record length fits usize");
        let (record, suffix) = payload.split_at(length);
        let message = automata_ci_protocol_protobuf::decode_runner_frame(record, &limits)
            .expect("canonical durable runner frame")
            .into_message();
        let RunnerToServer::LogBatch(batch) = message else {
            panic!("log spool contains only log batches");
        };
        frames.extend(
            batch
                .frames()
                .iter()
                .map(|frame| (frame.sequence().get(), frame.payload().to_vec())),
        );
        remaining = suffix;
    }
    frames
}

struct RaceHarness {
    cancelled_attempt: automata_ci_core::AttemptId,
    cancelled_slot: automata_ci_protocol::RunnerSlotOrdinal,
    survivor_slot: automata_ci_protocol::RunnerSlotOrdinal,
    journal: Arc<automata_ci_runner_journal::FileJournal>,
    probe: support::ContentRaceProbe,
    client: Arc<support::CancellationContentRaceClient>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), automata_ci_runner_runtime::RunnerRuntimeError>>,
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
                Arc::new(automata_ci_runner_runtime::TokioRuntimeSleeper),
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
            Duration::from_secs(5),
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
