use automata_ci_core::{RunnerSessionId, UnixMillis};
use automata_ci_store::{RunnerPayloadTombstone, RunnerPayloadTombstoneReason, StoreError};

#[test]
fn tombstone_errors_are_sanitized() {
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
        let tombstone = RunnerPayloadTombstone::new(reason, UnixMillis::new(42));
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
