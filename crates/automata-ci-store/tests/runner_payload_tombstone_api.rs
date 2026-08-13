use automata_ci_core::{RunnerSessionId, UnixMillis};
use automata_ci_store::{RunnerPayloadTombstone, RunnerPayloadTombstoneReason, StoreError};

const MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");
const OBSERVABILITY: &str = include_str!("../src/postgres/observability.rs");

#[test]
fn tombstone_reasons_are_closed_stable_and_sanitized() {
    for (reason, durable) in [
        (RunnerPayloadTombstoneReason::Acknowledged, "acknowledged"),
        (
            RunnerPayloadTombstoneReason::SessionClosed,
            "session_closed",
        ),
        (
            RunnerPayloadTombstoneReason::SessionSuperseded,
            "session_superseded",
        ),
    ] {
        assert_eq!(reason.as_str(), durable);
        let tombstone = RunnerPayloadTombstone::new(reason, UnixMillis::new(42));
        assert_eq!(tombstone.reason(), reason);
        assert_eq!(tombstone.tombstoned_at(), UnixMillis::new(42));
        let display = StoreError::RunnerPayloadUnavailable {
            session_id: RunnerSessionId::new(),
            tombstone,
        }
        .to_string();
        assert!(
            display
                .to_ascii_lowercase()
                .contains(durable.split('_').next().expect("reason word"))
        );
        assert!(!display.contains("ciphertext"));
        assert!(!display.contains("token"));
    }
}

#[test]
fn migration_is_one_way_bounded_and_preserves_delivery_rows() {
    assert!(MIGRATION.contains("payload_tombstone_reason IN ("));
    assert!(MIGRATION.contains("'acknowledged', 'session_closed', 'session_superseded'"));
    assert!(MIGRATION.contains("payload_tombstoned_at_ms >= created_at_ms"));
    assert!(MIGRATION.contains("payload_tombstoned_at_ms >= committed_at_ms"));
    assert!(MIGRATION.contains("runner_command_outbox_tombstone_immutable"));
    assert!(MIGRATION.contains("runner_rpc_receipts_tombstone_immutable"));
    assert!(MIGRATION.contains("runner_session_payload_retention"));
    assert!(MIGRATION.contains("runner_cancellation_payload_retention"));
    assert!(MIGRATION.contains("attempt_cancellation_intents IN ACCESS EXCLUSIVE MODE"));
    assert!(MIGRATION.contains("runner_payload_tombstones_preexisting_expired_payloads"));
    assert!(!MIGRATION.contains("DELETE FROM runner_command_outbox"));
    assert!(!MIGRATION.contains("DELETE FROM runner_rpc_receipts"));
    assert!(!MIGRATION.contains("DROP CONSTRAINT attempt_cancellation_delivery_command"));
    assert!(!MIGRATION.contains("DROP CONSTRAINT runner_lease_offer_publications_command"));
    assert!(OBSERVABILITY.contains("WHERE command.payload_tombstone_reason IS NULL"));
}
