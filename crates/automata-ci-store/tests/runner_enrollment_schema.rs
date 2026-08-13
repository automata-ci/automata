const MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

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
    assert!(MIGRATION.contains(
        "(redeem_certificate_expires_at_seconds - (consumed_at_ms / 1000)) >= 300"
    ));
}
