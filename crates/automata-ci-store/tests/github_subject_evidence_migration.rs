#[allow(dead_code)]
mod common;

use sqlx::migrate::Migrate as _;
use uuid::Uuid;

use common::{TestResult, run_with_unmigrated_database};

const MIGRATION: &str = include_str!("../migrations/0037_github_subject_evidence.sql");
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[test]
fn migration_replaces_both_interim_guards_with_one_atomic_current_only_boundary() {
    for required in [
        "LOCK TABLE provider_delivery_inbox IN SHARE ROW EXCLUSIVE MODE",
        "LOCK TABLE github_check_subjects IN SHARE ROW EXCLUSIVE MODE",
        "github_subject_evidence_current_only",
        "github_subject_evidence_required BOOLEAN NOT NULL DEFAULT FALSE",
        "workflow_admission_github_evidence_flag_immutable",
        "CREATE TABLE github_provider_delivery_evidence",
        "github_repository_owner_id BIGINT NOT NULL",
        "authenticated_webhook_verifier_fingerprint_sha256 BYTEA NOT NULL",
        "authenticated_webhook_verifier_revision BIGINT NOT NULL",
        "github_provider_delivery_evidence_manifest",
        "MATCH FULL ON DELETE RESTRICT",
        "checks_authority_id UUID NOT NULL",
        "checks_authority_identity_digest BYTEA NOT NULL",
        "private_source_authority_id UUID",
        "repository_visibility = 'public'",
        "private_source_authority_id IS NULL",
        "repository_visibility = 'private'",
        "private_source_authority_id IS NOT NULL",
        "github_check_subject_id UUID NOT NULL",
        "github_check_head_sha BYTEA NOT NULL",
        "github_provider_delivery_evidence_authority_exact",
        "FOR SHARE OF manifest_source, current_source",
        "CREATE CONSTRAINT TRIGGER provider_delivery_inbox_require_atomic_github_check",
        "DEFERRABLE INITIALLY DEFERRED",
        "github_delivery_atomic_queued_check_required",
        "github_check_subjects_delivery_evidence_exact",
        "github_check_projection_outbox",
        "DROP TRIGGER provider_delivery_inbox_00_require_github_manifest_pin",
        "DROP TRIGGER github_check_subjects_00_00_require_manifest_pin",
        "DROP FUNCTION automata_github_provider_manifest_reject_unpinned_delivery()",
        "DROP FUNCTION automata_github_provider_manifest_reject_unpinned_check()",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing atomic ingress invariant: {required}"
        );
    }

    let replacement = MIGRATION
        .find("CREATE CONSTRAINT TRIGGER provider_delivery_inbox_require_atomic_github_check")
        .expect("replacement trigger");
    let first_drop = MIGRATION
        .find("DROP TRIGGER provider_delivery_inbox_00_require_github_manifest_pin")
        .expect("paired guard drop");
    assert!(
        replacement < first_drop,
        "replacement must precede both drops"
    );

    for prohibited in [
        "ALTER TABLE provider_delivery_inbox\n    ADD COLUMN",
        "UPDATE provider_delivery_inbox SET",
        "UPDATE github_check_subjects SET",
        "    provider_repository_owner_id BIGINT NOT NULL",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "generic inbox/backfill surface is forbidden: {prohibited}"
        );
    }
}

#[test]
fn run_receipt_is_immutable_and_digests_every_exact_signed_source_coordinate() {
    for required in [
        "CREATE TABLE github_workflow_run_subject_evidence",
        "PRIMARY KEY (repository_id, run_id)",
        "github_workflow_run_subject_evidence_delivery",
        "github_workflow_run_subject_evidence_check",
        "github_workflow_run_subject_evidence_immutable",
        "automata.store.github-workflow-run-subject-evidence.v1",
        "pg_catalog.convert_to(tenant_id, 'UTF8')",
        "pg_catalog.uuid_send(repository_id)",
        "pg_catalog.uuid_send(workflow_id)",
        "pg_catalog.uuid_send(snapshot_id)",
        "pg_catalog.uuid_send(run_id)",
        "pg_catalog.uuid_send(root_invocation_id)",
        "pg_catalog.uuid_send(provider_delivery_id)",
        "pg_catalog.convert_to(provider_delivery_idempotency_key, 'UTF8')",
        "pg_catalog.uuid_send(admission_claim_owner_id)",
        "pg_catalog.int8send(admission_claim_attempt::BIGINT)",
        "pg_catalog.int8send(admission_claim_fence)",
        "pg_catalog.int8send(admission_claimed_at_ms)",
        "pg_catalog.int8send(admission_claim_expires_at_ms)",
        "pg_catalog.uuid_send(github_check_subject_id)",
        "automata_github_provider_manifest_digest_part(github_check_head_sha)",
        "pg_catalog.uuid_send(provider_connection_id)",
        "pg_catalog.int8send(provider_installation_id)",
        "pg_catalog.int8send(github_repository_id)",
        "pg_catalog.int8send(github_repository_owner_id)",
        "pg_catalog.convert_to(github_repository_name, 'UTF8')",
        "pg_catalog.convert_to(repository_visibility, 'UTF8')",
        "pg_catalog.int8send(provider_manifest_revision)",
        "automata_github_provider_manifest_digest_part(provider_manifest_digest)",
        "authenticated_webhook_verifier_fingerprint_sha256",
        "pg_catalog.int8send(authenticated_webhook_verifier_revision)",
        "pg_catalog.uuid_send(checks_authority_id)",
        "automata_github_provider_manifest_digest_part(checks_authority_identity_digest)",
        "private_source_authority_id IS NULL",
        "automata_github_provider_manifest_digest_part(request_digest)",
        "automata_github_provider_manifest_digest_part(raw_event_digest)",
        "pg_catalog.convert_to(workflow_path, 'UTF8')",
        "automata_github_provider_manifest_digest_part(source_digest)",
        "pg_catalog.convert_to(event_name, 'UTF8')",
        "automata_github_provider_manifest_digest_part(event_digest)",
        "pg_catalog.convert_to(git_ref, 'UTF8')",
        "automata_github_provider_manifest_digest_part(plan_digest)",
        "automata_github_provider_manifest_digest_part(logical_admission_digest)",
        "source_evidence.subject_run_id <> NEW.run_id",
        "source_evidence.repository_scm_provider <> 'github'",
        "source_evidence.repository_provider_id <>",
        "repository.owner <> split_part(NEW.github_repository_name, '/', 1)",
        "run_evidence.receipt_repository_id IS DISTINCT FROM NEW.repository_id",
        "source_evidence.subject_desired_state <> 'in_progress'",
        "source_evidence.subject_desired_revision <> 2",
        "source_evidence.inbox_state <> 'claimed'",
        "source_evidence.inbox_claim_fence <> NEW.admission_claim_fence",
        "receipt_github_evidence_required",
        "CREATE CONSTRAINT TRIGGER workflow_admission_require_github_evidence",
        "workflow_admission_required_github_evidence_exact",
        "NEW.github_check_head_sha <> run_evidence.head_sha",
        "NEW.admitted_at_ms <> run_evidence.created_at_ms",
        "run_evidence.admission_epoch <> 4",
        "workflow_plan_schema = 2",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing run-evidence invariant: {required}"
        );
    }
    for prohibited in [
        "access_token",
        "webhook_secret",
        "private_key",
        "raw_event_bytes",
        "COALESCE",
    ] {
        assert!(
            !MIGRATION.contains(prohibited),
            "forbidden value/fallback surface: {prohibited}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn pre_evidence_github_inbox_fails_without_owner_or_manifest_backfill() -> TestResult {
    run_with_unmigrated_database(|database| async move {
        let mut connection = database.pool().acquire().await?;
        connection
            .ensure_migrations_table(MIGRATOR.table_name.as_ref())
            .await?;
        for migration in MIGRATOR.iter().filter(|migration| migration.version < 37) {
            connection
                .apply(MIGRATOR.table_name.as_ref(), migration)
                .await?;
        }

        // Simulate prerelease state created by a bypassed 0035 interim gate.
        // 0037 must audit and refuse it, never derive an owner or manifest pin.
        sqlx::query(
            "DROP TRIGGER provider_delivery_inbox_00_require_github_manifest_pin \
             ON provider_delivery_inbox",
        )
        .execute(&mut *connection)
        .await?;
        let tenant = format!("pre-evidence-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) \
             VALUES ($1, 'Pre evidence', 1, 1)",
        )
        .bind(&tenant)
        .execute(&mut *connection)
        .await?;
        sqlx::query(
            r"
            INSERT INTO provider_delivery_inbox (
                id, tenant_id, provider, connection_id, installation_id,
                provider_repository_id, repository_visibility,
                repository_identity, delivery_id, request_digest,
                raw_event_digest, raw_event_object_key, raw_event_size_bytes,
                raw_event_media_type, accepted_at_ms, state_updated_at_ms
            ) VALUES (
                $1, $2, 'github', $3, 101, 202, 'public',
                'automata-ci/automata', 'pre-evidence-delivery', $4, $5,
                'github/events/pre-evidence', 512, 'application/json', 10, 10
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant)
        .bind(Uuid::new_v4())
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 32])
        .execute(&mut *connection)
        .await?;

        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 37)
            .expect("migration 0037");
        let error = connection
            .apply(MIGRATOR.table_name.as_ref(), migration)
            .await
            .expect_err("pre-evidence GitHub inbox must fail closed");
        match error {
            sqlx::migrate::MigrateError::ExecuteMigration(error, 37) => {
                assert_eq!(
                    error
                        .as_database_error()
                        .and_then(sqlx::error::DatabaseError::constraint),
                    Some("github_subject_evidence_current_only")
                );
            }
            other => panic!("unexpected migration error: {other}"),
        }

        let rollback: (i64, Option<String>, Option<String>, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM provider_delivery_inbox),
                to_regclass('github_provider_delivery_evidence')::TEXT,
                to_regclass('github_workflow_run_subject_evidence')::TEXT,
                (SELECT count(*) FROM _sqlx_migrations WHERE success)
            ",
        )
        .fetch_one(&mut *connection)
        .await?;
        assert_eq!(rollback, (1, None, None, 36));
        Ok(())
    })
    .await
}
