mod support;

use automata_core::{JobIrVersion, JobLifecycle, OperationId, Sha256Digest};
use automata_protocol::RunnerSlotOrdinal;
use automata_runner_journal::{
    ContentKind, DurableContentRef, JobIrContentRef, JournalError, JournalInvariantError,
    LeaseOfferRecord, MAX_JOB_IR_CONTENT_BYTES, MAX_JOURNALED_SLOTS, MAX_LOG_SPOOL_CONTENT_BYTES,
    MAX_PROVIDER_OPERATIONS_PER_SLOT, MAX_RUNTIME_AUTHORITY_CONTENT_BYTES,
    MAX_TERMINAL_RESULT_CONTENT_BYTES, RunnerJournal, RuntimeAuthorityContentRef,
    TerminalResultRecord, clamp_registration_slots,
};
use automata_runner_spool::{MAX_CONTENT_OBJECT_BYTES, ProtectionId, SpoolLimits};
use support::{Fixture, Scratch};

const _: () = {
    assert!(MAX_JOURNALED_SLOTS <= 65_535);
    assert!(MAX_PROVIDER_OPERATIONS_PER_SLOT > 0);
    assert!(MAX_JOB_IR_CONTENT_BYTES <= MAX_CONTENT_OBJECT_BYTES);
    assert!(MAX_RUNTIME_AUTHORITY_CONTENT_BYTES <= MAX_CONTENT_OBJECT_BYTES);
    assert!(MAX_TERMINAL_RESULT_CONTENT_BYTES <= MAX_CONTENT_OBJECT_BYTES);
    assert!(MAX_LOG_SPOOL_CONTENT_BYTES <= MAX_CONTENT_OBJECT_BYTES);
};

fn reference(kind: ContentKind, size: u64) -> DurableContentRef {
    DurableContentRef::after_commit(
        kind,
        size,
        Sha256Digest::from_bytes([0x99; 32]),
        ProtectionId::new("limits-test-aead-v1").expect("protection identifier"),
    )
    .expect("content within spool hard limit")
}

#[test]
fn a_sparse_slot_ordinal_cannot_bypass_the_registration_clamp() {
    let scratch = Scratch::new("slot-ordinal-limit");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    let outside = u16::try_from(MAX_JOURNALED_SLOTS + 1).expect("test slot fits protocol");
    let offer = LeaseOfferRecord::new(
        RunnerSlotOrdinal::new(outside).expect("one-based slot"),
        fixture.lease.clone(),
        JobIrContentRef::new(JobIrVersion::current(), reference(ContentKind::JobIr, 64))
            .expect("JobIR reference"),
        Fixture::runtime_authority(),
        Fixture::command(1),
    )
    .expect("offer model");
    assert!(matches!(
        journal.record_lease_offer(fixture.session_id, offer),
        Err(JournalError::Invariant(
            JournalInvariantError::SlotLimitReached
        ))
    ));
    assert!(journal.snapshot().expect("unchanged").slots().is_empty());
}

#[test]
fn registration_and_per_slot_bounds_are_coherent_with_aggregate_storage_limits() {
    assert!(MAX_LOG_SPOOL_CONTENT_BYTES <= SpoolLimits::default().max_object_bytes());
    assert_eq!(clamp_registration_slots(0), 0);
    assert_eq!(clamp_registration_slots(1), 1);
    assert_eq!(
        usize::from(clamp_registration_slots(u16::MAX)),
        MAX_JOURNALED_SLOTS
    );
    assert!(
        JobIrContentRef::new(JobIrVersion::current(), reference(ContentKind::JobIr, 0)).is_err()
    );
    assert!(
        JobIrContentRef::new(
            JobIrVersion::current(),
            reference(ContentKind::JobIr, MAX_JOB_IR_CONTENT_BYTES + 1),
        )
        .is_err()
    );
    assert!(RuntimeAuthorityContentRef::new(reference(ContentKind::RuntimeAuthority, 0)).is_err());
    assert!(
        RuntimeAuthorityContentRef::new(reference(
            ContentKind::RuntimeAuthority,
            MAX_RUNTIME_AUTHORITY_CONTENT_BYTES + 1,
        ))
        .is_err()
    );
    assert!(RuntimeAuthorityContentRef::new(reference(ContentKind::JobIr, 64)).is_err());
    assert!(
        TerminalResultRecord::new(
            OperationId::new(),
            reference(
                ContentKind::TerminalResult,
                MAX_TERMINAL_RESULT_CONTENT_BYTES + 1,
            ),
        )
        .is_err()
    );
}

#[test]
fn untrusted_acknowledged_result_cannot_skip_the_outbox_ack_transition() {
    let scratch = Scratch::new("forged-result-ack");
    let fixture = Fixture::new();
    let journal = fixture.open(&scratch);
    journal.begin_session(fixture.binding()).expect("session");
    journal
        .record_lease_offer(fixture.session_id, fixture.offer(1))
        .expect("offer");
    journal
        .accept_lease(fixture.session_id, fixture.slot, fixture.lease.guard())
        .expect("accept");
    let mut encoded = serde_json::to_value(Fixture::terminal_result()).expect("serialize result");
    encoded["acknowledged"] = serde_json::json!(true);
    let forged: TerminalResultRecord =
        serde_json::from_value(encoded).expect("decode public model");
    assert!(matches!(
        journal.record_terminal_result(
            fixture.session_id,
            fixture.slot,
            fixture.lease.guard(),
            JobLifecycle::Failed,
            forged,
        ),
        Err(JournalError::Invariant(
            JournalInvariantError::TerminalResultAlreadyAcknowledgedInput
        ))
    ));
    assert!(
        journal
            .snapshot()
            .expect("unchanged")
            .slot(fixture.slot)
            .expect("slot")
            .terminal_result()
            .is_none()
    );
}
