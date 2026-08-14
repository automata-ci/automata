use automata_ci_core::{RunnerSessionId, UnixMillis};
use automata_ci_store::{RunnerPayloadTombstone, RunnerPayloadTombstoneReason, StoreError};

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
