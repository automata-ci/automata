static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
const MIGRATION: &str = include_str!("../migrations/0067_protected_environment_review.sql");
const DOMAIN: &str = include_str!("../src/protected_environment.rs");
const POSTGRES_ADAPTER: &str = include_str!("../src/postgres/protected_environment.rs");
const HTTP_ADAPTER: &str =
    include_str!("../../automata-ci/src/app/protected_environment_review_api.rs");

#[test]
fn migration_0067_is_embedded_after_gate_evidence() {
    let migrations = MIGRATOR.iter().collect::<Vec<_>>();
    let review = migrations
        .iter()
        .position(|migration| migration.version == 67)
        .expect("migration 0067 is embedded");
    let evidence = migrations
        .iter()
        .position(|migration| migration.version == 66)
        .expect("migration 0066 is embedded");
    assert!(review > evidence);
}

#[test]
fn unknown_requester_can_never_satisfy_self_review_separation() {
    for required in [
        "security_audit_events_workflow_dispatch_target",
        "protected_environment_approval_requester_required",
        "status <> 'approved'",
        "OR requested_by_principal_id IS NOT NULL",
        "AND NEW.decision = 'approve'",
        "AND request.requested_by_principal_id IS NULL",
        "OR request.requested_by_principal_id IS NOT NULL",
        "OR decision.principal_id <> request.requested_by_principal_id",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing fail-closed requester invariant: {required}"
        );
    }
    for prohibited in [
        "OR request.requested_by_principal_id IS NULL\n                OR decision.principal_id",
        "OR OLD.requested_by_principal_id IS NULL",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "0067 must not retain the NULL self-review bypass: {prohibited}"
        );
    }
}

#[test]
fn requester_and_reviewer_authority_are_store_derived() {
    for required in [
        "derive_requester_principal(&mut transaction",
        "workflow_rerun_requests AS rerun",
        "workflow_rerun_audit_evidence AS evidence",
        "audit.action = 'workflow.dispatch'",
        "run_actor.as_deref() == expected_actor.as_deref()",
        "run.created_at_ms",
        "authorize_human_repository_action(",
        "PROTECTED_ENVIRONMENT_REVIEW_PERMISSION",
        ".bind(actor.principal_id)",
        ".bind(database_now_ms)",
        "ON CONFLICT (tenant_id, request_id, principal_id) DO NOTHING",
        "existing.as_deref() != Some(decision)",
    ] {
        assert!(
            POSTGRES_ADAPTER.contains(required),
            "missing derived review authority guard: {required}"
        );
    }
    assert!(
        !POSTGRES_ADAPTER.contains("provider_login"),
        "mutable provider logins must not become requester identity"
    );
    assert!(DOMAIN.contains("actor: ManagementActor"));
    assert!(!DOMAIN.contains("decided_at: UnixMillis"));
}

#[test]
fn scheduler_inspection_expires_one_waiting_gate_at_database_time() {
    for required in [
        "let mut transaction = pool.begin()",
        "FOR UPDATE OF gate, attempt",
        "SELECT status, expires_at_ms",
        "FOR UPDATE",
        "let database_now_ms = database_now(&mut transaction).await?;",
        "if database_now_ms >= expires_at_ms",
        "expire_gate(",
        "state = \"expired\".to_owned();",
    ] {
        assert!(
            POSTGRES_ADAPTER.contains(required),
            "missing bounded expiry re-evaluation: {required}"
        );
    }
}

#[test]
fn review_http_boundary_is_cli_only_bounded_and_value_free() {
    for required in [
        "MAX_REQUEST_BYTES: usize = 1_024",
        "identity.kind() != SessionKind::Cli",
        "request.uri().query().is_some()",
        "header::CONTENT_ENCODING",
        "#[serde(deny_unknown_fields)]",
        "EnvironmentReviewDecision",
        "header::CACHE_CONTROL, \"no-store\"",
        "dependency_unavailable",
    ] {
        assert!(
            HTTP_ADAPTER.contains(required),
            "missing HTTP review boundary: {required}"
        );
    }
    for prohibited in ["secret_value", "credential_value", "reason: String"] {
        assert!(
            !HTTP_ADAPTER.contains(prohibited),
            "review API must not accept or expose {prohibited}"
        );
    }
}
