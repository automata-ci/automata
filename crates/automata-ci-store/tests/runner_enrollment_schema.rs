const MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

fn runner_enrollment_token_table() -> &'static str {
    MIGRATION
        .split_once("CREATE TABLE runner_enrollment_tokens (")
        .expect("runner enrollment token table must exist")
        .1
        .split_once("\n);")
        .expect("runner enrollment token table must be terminated")
        .0
}

#[test]
fn enrollment_tokens_store_only_a_unique_fixed_length_digest() {
    let table = runner_enrollment_token_table();
    let token_columns = table
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("CONSTRAINT "))
        .filter_map(|line| line.split_whitespace().next())
        .map(|column| column.trim_end_matches(','))
        .filter(|column| column.contains("token"))
        .collect::<Vec<_>>();

    assert_eq!(token_columns, ["token_sha256"]);
    assert!(table.contains("token_sha256 bytea NOT NULL"));
    assert!(table.contains(
        "CONSTRAINT runner_enrollment_tokens_digest CHECK ((octet_length(token_sha256) = 32))"
    ));
    assert!(MIGRATION.contains(
        "ADD CONSTRAINT runner_enrollment_tokens_digest_unique UNIQUE (token_sha256)"
    ));
}

#[test]
fn enrollment_tokens_have_bounded_lifetime_and_write_once_consumption() {
    let table = runner_enrollment_token_table();

    assert!(table.contains("(expires_at_ms - issued_at_ms) >= 60000"));
    assert!(table.contains("(expires_at_ms - issued_at_ms) <= 3600000"));
    assert!(table.contains("CONSTRAINT runner_enrollment_tokens_consumption_shape CHECK"));
    assert!(table.contains(
        "(consumed_at_ms IS NULL) AND (consumed_runner_id IS NULL) AND (redeem_operation_id IS NULL) AND (redeem_request_sha256 IS NULL) AND (redeem_response IS NULL) AND (redeem_certificate_expires_at_seconds IS NULL)"
    ));
    assert!(table.contains(
        "(consumed_at_ms >= issued_at_ms) AND (consumed_at_ms < expires_at_ms) AND (consumed_runner_id IS NOT NULL) AND (redeem_operation_id IS NOT NULL)"
    ));
    assert!(MIGRATION.contains(
        "CREATE TRIGGER runner_enrollment_tokens_consume_once BEFORE UPDATE ON runner_enrollment_tokens FOR EACH ROW EXECUTE FUNCTION automata_runner_enrollment_token_consume_once()"
    ));
}

#[test]
fn enrollment_authority_and_consumption_are_tenant_scoped() {
    for constraint in [
        "FOREIGN KEY (tenant_id, issued_by_principal_id) REFERENCES tenant_human_memberships(tenant_id, principal_id)",
        "FOREIGN KEY (tenant_id, issued_by_principal_id, issued_by_session_id) REFERENCES human_sessions(tenant_id, principal_id, id)",
        "FOREIGN KEY (tenant_id, consumed_runner_id) REFERENCES runners(tenant_id, id)",
    ] {
        assert!(
            MIGRATION.contains(constraint),
            "missing constraint: {constraint}"
        );
    }
}

#[test]
fn exact_replay_receipt_carries_its_certificate_expiry() {
    assert!(MIGRATION.contains("redeem_certificate_expires_at_seconds bigint"));
    assert!(
        MIGRATION
            .contains("(redeem_certificate_expires_at_seconds - (consumed_at_ms / 1000)) >= 300")
    );
}
