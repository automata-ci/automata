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
fn initial_schema_defines_bounded_tombstones_without_rewrite_paths() {
    let normalized = MIGRATION.to_ascii_lowercase();
    assert!(normalized.contains("runner_command_outbox_payload_lifecycle"));
    assert!(normalized.contains("runner_rpc_receipts_payload_lifecycle"));
    assert!(normalized.contains("payload_tombstone_reason = any (array["));
    for reason in ["acknowledged", "session_closed", "session_superseded"] {
        assert!(normalized.contains(&format!("'{reason}'::text")));
    }
    assert!(normalized.contains("payload_tombstoned_at_ms >= created_at_ms"));
    assert!(normalized.contains("payload_tombstoned_at_ms >= committed_at_ms"));
    assert!(normalized.contains("runner_command_outbox_tombstone_immutable"));
    assert!(normalized.contains("runner_rpc_receipts_tombstone_immutable"));
    assert!(normalized.contains("runner_session_payload_retention"));
    assert!(normalized.contains("runner_cancellation_payload_retention"));
    assert!(!normalized.contains("delete from runner_command_outbox"));
    assert!(!normalized.contains("delete from runner_rpc_receipts"));
    assert!(!normalized.contains("drop constraint attempt_cancellation_delivery_command"));
    assert!(!normalized.contains("drop constraint runner_lease_offer_publications_command"));
    assert!(OBSERVABILITY.contains("WHERE command.payload_tombstone_reason IS NULL"));
}
