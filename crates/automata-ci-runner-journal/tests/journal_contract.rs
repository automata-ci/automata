use super::support;

use automata_ci_core::{
    JobLifecycle, LeaseGuard, LogSequence, LogStreamId, OperationId, RunnerSessionId, UnixMillis,
};
use automata_ci_protocol::{CommandSequence, LeaseRejectionReason, RunnerSlotOrdinal};
use automata_ci_runner_journal::{
    CancellationRecord, JournalError, JournalInvariantError, JournalSnapshot, LeaseOfferStatus,
    LogSegment, LogSegmentAcknowledgement, LogSegmentPublication, OutboundOperationSequence,
    ProviderName, ProviderOperation, ProviderOperationKind, ProviderOperationOutcome,
    RunnerJournal, SandboxHandle, SandboxIdentity,
};
use static_assertions::assert_obj_safe;
use support::{Fixture, Scratch, record_and_ack_runtime_authority, record_and_ack_terminal};

assert_obj_safe!(RunnerJournal);

fn acknowledge_log_head(
    journal: &dyn RunnerJournal,
    fixture: &Fixture,
    stream: LogStreamId,
    sequence: u64,
) {
    let head = journal
        .snapshot()
        .expect("log snapshot")
        .slot(fixture.slot)
        .expect("slot")
        .log_delivery()
        .expect("log")
        .head_segment()
        .expect("head")
        .clone();
    journal
        .acknowledge_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LogSegmentAcknowledgement::new(
                stream,
                LogSequence::new(sequence),
                head.content().clone(),
            )
            .expect("head acknowledgement"),
        )
        .expect("acknowledge sealed head");
}

#[test]
fn offer_is_durable_before_acceptance_and_survives_reopen() {
    let scratch = Scratch::new("offer-recovery");
    let fixture = Fixture::new();
    let offer = fixture.offer(1);
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    let recorded = journal
        .record_lease_offer(fixture.session_id, offer.clone())
        .expect("record offer");
    assert_eq!(recorded.revision(), 2);
    assert_eq!(
        recorded
            .session()
            .expect("session")
            .command_cursor()
            .acknowledged_through(),
        Some(CommandSequence::new(1).expect("sequence"))
    );
    assert_eq!(
        recorded.slot(fixture.slot).expect("slot").offer_status(),
        LeaseOfferStatus::Recorded
    );
    drop(journal);

    let reopened = fixture.open(&scratch);
    let recovered = reopened.snapshot().expect("snapshot");
    assert_eq!(recovered, recorded);
    let accepted = reopened
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept lease");
    assert_eq!(
        accepted.slot(fixture.slot).expect("slot").offer_status(),
        LeaseOfferStatus::Accepted
    );
}

#[test]
fn preparing_job_condition_can_terminalize_directly_as_skipped() {
    let scratch = Scratch::new("preparing-skipped");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("record offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept lease");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Preparing,
        )
        .expect("enter preparing");

    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Skipped);
    let skipped = journal.snapshot().expect("skipped snapshot");
    let slot = skipped.slot(fixture.slot).expect("durable skipped slot");
    assert_eq!(slot.lifecycle(), JobLifecycle::Skipped);
    assert!(
        slot.terminal_result()
            .expect("terminal result")
            .is_acknowledged()
    );
    drop(journal);

    let recovered = fixture
        .open(&scratch)
        .snapshot()
        .expect("recover skipped slot");
    assert_eq!(recovered, skipped);
}

#[test]
fn stale_session_guard_and_command_gaps_are_rejected_without_mutation() {
    let scratch = Scratch::new("fences");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    let before = journal.snapshot().expect("snapshot");
    let error = journal
        .record_lease_offer(fixture.session_id, fixture.offer(2))
        .expect_err("gap must fail");
    assert!(matches!(
        error,
        JournalError::Invariant(JournalInvariantError::CommandSequenceMismatch { .. })
    ));
    assert_eq!(journal.snapshot().expect("snapshot"), before);

    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("record offer");
    let stale_session = RunnerSessionId::new();
    assert!(matches!(
        journal.accept_lease(stale_session, fixture.slot, fixture.lease.guard()),
        Err(JournalError::Invariant(
            JournalInvariantError::SessionMismatch { .. }
        ))
    ));
    let stale_guard = LeaseGuard::new(
        automata_ci_core::LeaseId::new(),
        fixture.lease.guard().fencing_token(),
    );
    assert!(matches!(
        journal.accept_lease(fixture.session_id, fixture.slot, stale_guard),
        Err(JournalError::Invariant(
            JournalInvariantError::LeaseGuardMismatch { .. }
        ))
    ));
}

#[test]
fn deserialized_offer_with_invalid_lease_interval_cannot_enter_journal() {
    let scratch = Scratch::new("invalid-lease-interval");
    let fixture = Fixture::new();
    let mut value = serde_json::to_value(fixture.offer(1)).expect("serialize offer");
    value["lease"]["expires_at"] = serde_json::json!(39_999);
    let invalid: automata_ci_runner_journal::LeaseOfferRecord =
        serde_json::from_value(value).expect("deserialize untrusted offer boundary");
    assert!(matches!(
        automata_ci_runner_journal::LeaseOfferRecord::new(
            invalid.slot(),
            invalid.lease().clone(),
            invalid.job_ir().clone(),
            invalid.command(),
        ),
        Err(JournalInvariantError::InvalidLease)
    ));
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    let before = journal.snapshot().expect("before");
    assert!(matches!(
        journal.record_lease_offer(fixture.session_id, invalid),
        Err(JournalError::Invariant(JournalInvariantError::InvalidLease))
    ));
    assert_eq!(journal.snapshot().expect("unchanged"), before);
}

#[test]
fn current_lease_offer_record_requires_explicit_managed_secret_bindings() {
    let fixture = Fixture::new();
    let mut incomplete = serde_json::to_value(fixture.offer(1)).expect("serialize offer");
    incomplete
        .as_object_mut()
        .expect("lease-offer record")
        .remove("managed_secret_bindings");

    assert!(
        serde_json::from_value::<automata_ci_runner_journal::LeaseOfferRecord>(incomplete).is_err()
    );
}

#[test]
fn exact_replays_are_noops_and_lease_expiration_only_moves_forward() {
    let scratch = Scratch::new("idempotent-replays");
    let fixture = Fixture::new();
    let offer = fixture.offer(1);
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    let recorded = journal
        .record_lease_offer(fixture.session_id, offer.clone())
        .expect("record offer");
    let replayed = journal
        .record_lease_offer(fixture.session_id, offer)
        .expect("exact replay");
    assert_eq!(recorded.revision(), replayed.revision());
    let renewed = journal
        .renew_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            UnixMillis::new(60_000),
        )
        .expect("renew");
    assert_eq!(
        renewed.slot(fixture.slot).expect("slot").expires_at(),
        UnixMillis::new(60_000)
    );
    assert!(matches!(
        journal.renew_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            UnixMillis::new(55_000),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::LeaseExpiryRegression
        ))
    ));
}

#[test]
fn session_replacement_is_fenced_while_recoverable_work_exists() {
    let scratch = Scratch::new("session-replacement");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("record offer");
    assert!(matches!(
        journal.begin_session(automata_ci_runner_journal::SessionBinding::new(
            RunnerSessionId::new(),
            automata_ci_protocol::PROTOCOL_MAX_VERSION,
            automata_ci_core::JobIrVersion::current(),
        )),
        Err(JournalError::Invariant(
            JournalInvariantError::SessionHasActiveSlots
        ))
    ));
}

fn assert_capacity_rejection(
    snapshot: &JournalSnapshot,
    fixture: &Fixture,
    response_operation: OperationId,
    acknowledged: bool,
) {
    let rejection = snapshot
        .slot(fixture.slot)
        .expect("slot")
        .rejection()
        .expect("rejection");
    assert_eq!(rejection.reason(), &LeaseRejectionReason::CapacityChanged);
    assert_eq!(rejection.response_operation_id(), response_operation);
    assert_eq!(rejection.is_response_acknowledged(), acknowledged);
}

fn assert_rejected_offer_cannot_be_renewed(journal: &dyn RunnerJournal, fixture: &Fixture) {
    assert!(matches!(
        journal.renew_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            UnixMillis::new(60_000),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::OfferAlreadyRejected
        ))
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn rejected_offer_survives_reopen_and_cannot_be_cleared_before_exact_ack() {
    let scratch = Scratch::new("rejected-offer");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    let response_operation = OperationId::new();
    let rejected = journal
        .reject_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LeaseRejectionReason::CapacityChanged,
            response_operation,
            Fixture::delivery_time(),
        )
        .expect("reject durably");
    assert_capacity_rejection(&rejected, &fixture, response_operation, false);
    assert_eq!(
        rejected.pending_delivery_timestamps().lease_rejection(),
        Some(Fixture::delivery_time())
    );
    assert_rejected_offer_cannot_be_renewed(&journal, &fixture);
    assert!(matches!(
        journal.release_rejected_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            response_operation,
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::LeaseRejectionNotAcknowledged
        ))
    ));
    drop(journal);

    let journal = fixture.open(&scratch);
    let before_replay = journal.snapshot().expect("recovered rejection");
    let replay = journal
        .reject_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LeaseRejectionReason::CapacityChanged,
            response_operation,
            UnixMillis::new(46_000),
        )
        .expect("exact rejection replay");
    assert_eq!(before_replay.revision(), replay.revision());
    assert_eq!(
        replay.pending_delivery_timestamps().lease_rejection(),
        Some(Fixture::delivery_time())
    );
    assert!(matches!(
        journal.acknowledge_lease_rejection(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            OperationId::new(),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::LeaseRejectionOperationMismatch
        ))
    ));
    let acknowledged = journal
        .acknowledge_lease_rejection(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            response_operation,
        )
        .expect("ack exact response");
    assert_eq!(
        acknowledged.pending_delivery_timestamps().lease_rejection(),
        None
    );
    let replay_after_ack = journal
        .reject_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LeaseRejectionReason::CapacityChanged,
            response_operation,
            UnixMillis::new(47_000),
        )
        .expect("replay after acknowledgement");
    assert_eq!(acknowledged.revision(), replay_after_ack.revision());
    drop(journal);

    let journal = fixture.open(&scratch);
    assert_capacity_rejection(
        &journal.snapshot().expect("recovered ack"),
        &fixture,
        response_operation,
        true,
    );
    let released = journal
        .release_rejected_lease(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            response_operation,
        )
        .expect("release acknowledged rejection");
    assert!(released.slot(fixture.slot).is_none());
}

#[test]
fn pending_delivery_snapshot_selects_the_oldest_timestamp_without_identities() {
    let scratch = Scratch::new("oldest-delivery-aggregate");
    let fixture = Fixture::new();
    let second_slot = RunnerSlotOrdinal::new(2).expect("second slot");
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("first offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept first");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer_for(second_slot, 2))
        .expect("second offer");
    journal
        .accept_lease(fixture.session_id, second_slot, fixture.lease.guard())
        .expect("accept second");

    let later = Fixture::terminal_result();
    journal
        .record_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Failed,
            later.clone(),
            UnixMillis::new(50_000),
        )
        .expect("later result");
    let earlier = Fixture::terminal_result();
    let both = journal
        .record_terminal_result(
            fixture.session_id,
            second_slot,
            fixture.lease.guard(),
            JobLifecycle::Failed,
            earlier.clone(),
            Fixture::delivery_time(),
        )
        .expect("earlier result");
    assert_eq!(
        both.pending_delivery_timestamps().terminal_result(),
        Some(Fixture::delivery_time())
    );

    let only_later = journal
        .acknowledge_terminal_result(
            fixture.session_id,
            second_slot,
            fixture.lease.guard(),
            earlier.operation_id(),
        )
        .expect("ack earlier result");
    assert_eq!(
        only_later.pending_delivery_timestamps().terminal_result(),
        Some(UnixMillis::new(50_000))
    );
    let none = journal
        .acknowledge_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            later.operation_id(),
        )
        .expect("ack later result");
    assert_eq!(none.pending_delivery_timestamps().terminal_result(), None);
}

#[test]
fn provider_saga_requires_intent_and_preserves_recovery_identity() {
    let scratch = Scratch::new("provider-saga");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("record offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    record_and_ack_runtime_authority(&journal, &fixture);

    let create_id = OperationId::new();
    let sandbox = SandboxIdentity::new(
        ProviderName::new("podman").expect("provider"),
        SandboxHandle::new("container:6f3a2").expect("handle"),
    );
    assert!(matches!(
        journal.record_sandbox_created(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            create_id,
            sandbox.clone(),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::SandboxWithoutCreateIntent
        ))
    ));
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(create_id, ProviderOperationKind::CreateSandbox),
        )
        .expect("record create intent");
    let after_create = journal
        .record_sandbox_created(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            create_id,
            sandbox.clone(),
        )
        .expect("record created sandbox");
    let slot = after_create.slot(fixture.slot).expect("slot");
    assert_eq!(slot.sandbox(), Some(&sandbox));
    assert_eq!(
        slot.provider_operations()
            .last()
            .expect("operation")
            .outcome(),
        ProviderOperationOutcome::Applied
    );
    drop(journal);

    let recovered = fixture.open(&scratch).snapshot().expect("recover");
    assert_eq!(
        recovered.slot(fixture.slot).expect("slot").sandbox(),
        Some(&sandbox)
    );
}

fn prepare_running_sandbox(journal: &dyn RunnerJournal, fixture: &Fixture) {
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    record_and_ack_runtime_authority(journal, fixture);
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Preparing,
        )
        .expect("preparing");
    let create = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(create, ProviderOperationKind::CreateSandbox),
        )
        .expect("create intent");
    journal
        .record_sandbox_created(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            create,
            SandboxIdentity::new(
                ProviderName::new("podman").expect("provider"),
                SandboxHandle::new("sandbox:42").expect("handle"),
            ),
        )
        .expect("created");
    let start = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(start, ProviderOperationKind::StartSandbox),
        )
        .expect("start intent");
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            start,
        )
        .expect("start applied");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Running,
        )
        .expect("running");
}

#[test]
fn lifecycle_provider_cleanup_and_terminal_release_are_ordered() {
    let scratch = Scratch::new("cleanup-order");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    prepare_running_sandbox(&journal, &fixture);
    let stop = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(stop, ProviderOperationKind::StopSandbox),
        )
        .expect("stop intent");
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stop,
        )
        .expect("stop applied");
    journal
        .transition_lifecycle(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Finalizing,
        )
        .expect("finalizing");
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Succeeded);
    assert!(matches!(
        journal.release_slot(fixture.session_id, fixture.slot, fixture.lease.guard()),
        Err(JournalError::Invariant(
            JournalInvariantError::SlotNotTerminal
        ))
    ));
    let destroy = OperationId::new();
    journal
        .record_provider_intent(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            ProviderOperation::intent(destroy, ProviderOperationKind::DestroySandbox),
        )
        .expect("destroy intent after terminal result");
    journal
        .complete_provider_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            destroy,
        )
        .expect("destroy applied");
    let released = journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release terminal clean slot");
    assert!(released.slot(fixture.slot).is_none());
}

#[test]
fn cancellation_and_outbound_cursors_are_contiguous_and_replay_safe() {
    let scratch = Scratch::new("cursors");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal
        .begin_session(fixture.binding())
        .expect("begin session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let cancel = CancellationRecord::new(Fixture::command(2), UnixMillis::new(4_000));
    let cancelled = journal
        .record_cancellation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            cancel,
        )
        .expect("cancel");
    assert_eq!(
        cancelled
            .session()
            .expect("session")
            .command_cursor()
            .acknowledged_through(),
        Some(CommandSequence::new(2).expect("sequence"))
    );
    journal
        .advance_outbound_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            OutboundOperationSequence::new(1).expect("sequence"),
        )
        .expect("outbound");
    assert!(matches!(
        journal.advance_outbound_operation(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            OutboundOperationSequence::new(3).expect("sequence"),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::OutboundOperationSequenceMismatch { .. }
        ))
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn log_segments_replace_only_the_open_tail_and_ack_exact_sealed_heads() {
    let scratch = Scratch::new("log-segments");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let stream = LogStreamId::new();
    journal
        .open_log_stream(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
        )
        .expect("open stream");

    let first = Fixture::content(automata_ci_runner_journal::ContentKind::LogSpool, 32, 0x72);
    journal
        .record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LogSegmentPublication::new(
                stream,
                None,
                LogSegment::new(
                    LogSequence::new(0),
                    LogSequence::new(0),
                    1,
                    10,
                    first.clone(),
                    false,
                    false,
                )
                .expect("first segment"),
            )
            .expect("first publication"),
            Fixture::delivery_time(),
        )
        .expect("publish first frame");
    let replacement = Fixture::content(automata_ci_runner_journal::ContentKind::LogSpool, 64, 0x73);
    journal
        .record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LogSegmentPublication::new(
                stream,
                Some(first),
                LogSegment::new(
                    LogSequence::new(0),
                    LogSequence::new(1),
                    2,
                    20,
                    replacement.clone(),
                    false,
                    false,
                )
                .expect("replacement segment"),
            )
            .expect("replacement publication"),
            UnixMillis::new(46_000),
        )
        .expect("append within open segment");
    let sealed = journal
        .seal_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
            replacement.clone(),
        )
        .expect("seal segment");
    let seal_replay = journal
        .seal_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
            replacement.clone(),
        )
        .expect("exact seal replay");
    assert_eq!(sealed.revision(), seal_replay.revision());
    assert_eq!(
        seal_replay.pending_delivery_timestamps().log_stream(),
        Some(Fixture::delivery_time())
    );

    let second = Fixture::content(automata_ci_runner_journal::ContentKind::LogSpool, 32, 0x74);
    let with_second = journal
        .record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LogSegmentPublication::new(
                stream,
                None,
                LogSegment::new(
                    LogSequence::new(2),
                    LogSequence::new(2),
                    1,
                    10,
                    second.clone(),
                    true,
                    false,
                )
                .expect("second segment"),
            )
            .expect("second publication"),
            UnixMillis::new(47_000),
        )
        .expect("publish second head");
    assert_eq!(
        with_second.pending_delivery_timestamps().log_stream(),
        Some(Fixture::delivery_time())
    );

    let acknowledgement =
        LogSegmentAcknowledgement::new(stream, LogSequence::new(1), replacement.clone())
            .expect("acknowledgement");
    let acknowledged = journal
        .acknowledge_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            acknowledgement.clone(),
        )
        .expect("ack whole head");
    assert_eq!(
        acknowledged.pending_delivery_timestamps().log_stream(),
        Some(UnixMillis::new(47_000))
    );
    assert_eq!(
        acknowledged
            .slot(fixture.slot)
            .expect("slot")
            .log_delivery()
            .expect("log")
            .head_segment()
            .expect("second head")
            .content(),
        &second
    );
    let replay = journal
        .acknowledge_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            acknowledgement,
        )
        .expect("exact ACK replay");
    assert_eq!(acknowledged.revision(), replay.revision());
    assert!(matches!(
        journal.acknowledge_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LogSegmentAcknowledgement::new(
                stream,
                LogSequence::new(1),
                Fixture::content(automata_ci_runner_journal::ContentKind::LogSpool, 64, 0x74,),
            )
            .expect("divergent ACK"),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::LogAcknowledgementConflict
        ))
    ));
    let fully_acknowledged = journal
        .acknowledge_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            LogSegmentAcknowledgement::new(stream, LogSequence::new(2), second)
                .expect("second acknowledgement"),
        )
        .expect("ack second head");
    assert_eq!(
        fully_acknowledged
            .pending_delivery_timestamps()
            .log_stream(),
        None
    );
}

#[test]
fn terminal_slot_retains_segment_until_eos_head_is_acknowledged() {
    let scratch = Scratch::new("log-release-fence");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let stream = LogStreamId::new();
    journal
        .open_log_stream(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            stream,
        )
        .expect("stream");
    journal
        .record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            Fixture::log_segment(stream, 0, true, 32, 0x75),
            Fixture::delivery_time(),
        )
        .expect("terminal segment");
    record_and_ack_terminal(&journal, &fixture, JobLifecycle::Failed);
    assert!(matches!(
        journal.release_slot(fixture.session_id, fixture.slot, fixture.lease.guard()),
        Err(JournalError::Invariant(
            JournalInvariantError::LogDeliveryIncomplete
        ))
    ));
    assert!(matches!(
        journal.record_log_segment(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            Fixture::log_segment(stream, 1, false, 32, 0x76),
            UnixMillis::new(46_000),
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::LogStreamClosed
        ))
    ));
    drop(journal);

    let journal = fixture.open(&scratch);
    acknowledge_log_head(&journal, &fixture, stream, 0);
    let released = journal
        .release_slot(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("release fully delivered logs");
    assert!(released.slot(fixture.slot).is_none());
}

#[test]
fn public_identifiers_reject_connection_strings_and_redact_handle_debug() {
    assert!(ProviderName::new("Podman").is_err());
    for value in [
        "scheme://host/path",
        "key=value",
        "opaque?credential=x",
        "contains space",
        "../escape",
    ] {
        assert!(SandboxHandle::new(value).is_err(), "accepted {value}");
    }
    let handle = SandboxHandle::new("pod:abc-123").expect("valid handle");
    assert!(!format!("{handle:?}").contains(handle.as_str()));
}
