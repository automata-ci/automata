const PROVIDER_TOKEN_MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

#[test]
fn provider_token_vault_schema_is_ciphertext_only_fail_closed_and_one_way() {
    let normalized = PROVIDER_TOKEN_MIGRATION.to_ascii_lowercase();
    assert!(normalized.contains("create table human_provider_tokens"));
    assert!(normalized.contains("envelope_record_id uuid not null"));
    assert!(normalized.contains("primary key (envelope_record_id)"));
    assert!(normalized.contains("human_provider_tokens_one_active_identity"));
    assert!(normalized.contains("encrypted_payload bytea"));
    assert!(!normalized.contains("access_token text"));
    assert!(!normalized.contains("refresh_token text"));
    assert!(!normalized.contains("delete from human_provider_tokens"));
    assert!(normalized.contains("encrypted_payload is null"));
    assert!(normalized.contains("wrapped_data_key is null"));
    assert!(normalized.contains("human_provider_tokens_tombstone_immutable"));
    assert!(normalized.contains("revoked_at_ms is null) and (access_expires_at_ms is not null"));
    assert!(!normalized.contains("'refresh'"));
}
