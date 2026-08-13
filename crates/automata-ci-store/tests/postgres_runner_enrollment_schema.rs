const MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

#[test]
fn runner_enrollment_tokens_are_digest_only_bounded_and_write_once() {
    let normalized = MIGRATION.to_ascii_lowercase();
    assert!(normalized.contains("create table runner_enrollment_tokens"));
    assert!(normalized.contains("octet_length(token_sha256) = 32"));
    assert!(normalized.contains("(expires_at_ms - issued_at_ms) >= 60000"));
    assert!(normalized.contains("(expires_at_ms - issued_at_ms) <= 3600000"));
    assert!(normalized.contains("runner_enrollment_tokens_digest_unique"));
    assert!(normalized.contains("runner_enrollment_tokens_consume_once"));
    assert!(normalized.contains("consumed_at_ms is null"));
    assert!(normalized.contains("consumed_runner_id is not null"));
    assert!(!normalized.contains("runner_enrollment_tokens (\n    token text"));
}
