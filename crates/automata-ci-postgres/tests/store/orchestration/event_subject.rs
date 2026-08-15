use automata_ci_core::{OperationId, RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    EventControlSubject, EventControlSubjectId, EventSubjectId, EventSubjectOrigin,
    EventSubjectProgress, EventSubjectRepository as _, EventSubjectSelection,
    EventSubjectStoreError, EventSubjectTerminalOutcome, GithubScheduleFireId, ProviderDeliveryId,
    RegisterEventSubject, RepositoryId, TenantScope,
};
use uuid::Uuid;

use crate::support::{TestResult, run_with_database};

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn registration_progress_replay_conflict_and_tenant_scope_are_exact() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant_scope("event-subject-adapter");
        let other_tenant = tenant_scope("event-subject-other");
        let repository_id = RepositoryId::from_uuid(Uuid::from_u128(0xe001));
        seed_repository(database.pool(), &tenant, repository_id).await?;

        let selected = selection(
            tenant.clone(),
            repository_id,
            EventSubjectOrigin::ProviderDelivery(
                ProviderDeliveryId::from_uuid(Uuid::from_u128(0xe101))?,
            ),
            "push",
            ".ci/workflows/build.yml",
            "0123456789abcdef",
            [0x42; 32],
            1_000,
        );
        let control = EventControlSubject::new(
            EventControlSubjectId::derive(selected.id()),
            &selected,
            UnixMillis::new(1_001),
        )?;
        let request = RegisterEventSubject::new(selected.clone(), control.clone())?;

        let first = database
            .store()
            .register_event_subject(request.clone())
            .await?;
        assert!(!first.is_replay());
        assert_eq!(first.selection(), &selected);
        assert_eq!(first.control(), &control);

        let replay = database.store().register_event_subject(request).await?;
        assert!(replay.is_replay());
        assert_eq!(replay.selection(), &selected);
        assert_eq!(replay.control(), &control);
        assert_eq!(
            database
                .store()
                .load_event_subject_selection(&tenant, selected.id())
                .await?,
            selected
        );
        assert_eq!(
            database
                .store()
                .load_event_control_subject(&tenant, selected.id())
                .await?,
            control
        );
        assert_eq!(
            database
                .store()
                .load_event_subject_progress(&tenant, selected.id())
                .await?,
            None
        );

        for result in [
            database
                .store()
                .load_event_subject_selection(&other_tenant, selected.id())
                .await
                .map(|_| ()),
            database
                .store()
                .load_event_control_subject(&other_tenant, selected.id())
                .await
                .map(|_| ()),
            database
                .store()
                .load_event_subject_progress(&other_tenant, selected.id())
                .await
                .map(|_| ()),
        ] {
            assert!(matches!(result, Err(EventSubjectStoreError::NotFound)));
        }

        let changed_selection = selection(
            tenant.clone(),
            repository_id,
            selected.origin(),
            "push",
            selected.workflow_path(),
            "fedcba9876543210",
            [0x43; 32],
            1_002,
        );
        assert_eq!(changed_selection.id(), selected.id());
        let changed_control = EventControlSubject::new(
            EventControlSubjectId::derive(changed_selection.id()),
            &changed_selection,
            UnixMillis::new(1_003),
        )?;
        assert!(matches!(
            database
                .store()
                .register_event_subject(RegisterEventSubject::new(
                    changed_selection,
                    changed_control,
                )?)
                .await,
            Err(EventSubjectStoreError::Conflict)
        ));

        let progress = EventSubjectProgress::new(
            &selected,
            EventSubjectTerminalOutcome::skipped("github.workflow.disabled")?,
            UnixMillis::new(2_000),
        )?;
        let progress_first = database
            .store()
            .record_event_subject_progress(progress.clone())
            .await?;
        assert!(!progress_first.is_replay());
        assert_eq!(progress_first.progress(), &progress);
        let progress_replay = database
            .store()
            .record_event_subject_progress(progress.clone())
            .await?;
        assert!(progress_replay.is_replay());
        assert_eq!(progress_replay.progress(), &progress);
        assert_eq!(
            database
                .store()
                .load_event_subject_progress(&tenant, selected.id())
                .await?,
            Some(progress.clone())
        );

        for changed in [
            EventSubjectProgress::new(
                &selected,
                EventSubjectTerminalOutcome::failed("github.source.unavailable")?,
                UnixMillis::new(2_000),
            )?,
            EventSubjectProgress::new(
                &selected,
                EventSubjectTerminalOutcome::skipped("github.workflow.disabled")?,
                UnixMillis::new(2_001),
            )?,
        ] {
            assert!(matches!(
                database.store().record_event_subject_progress(changed).await,
                Err(EventSubjectStoreError::Conflict)
            ));
        }

        let canonical: (bool, bool, bool) = sqlx::query_as(
            r"
            SELECT
                subject_id = automata_event_subject_id(
                    tenant_id, repository_id, origin_kind_code, origin_id, workflow_path
                ),
                selection.selection_digest = automata_event_subject_selection_digest(
                    selection_schema, origin_registry_version, origin_registry_digest,
                    subject_id, tenant_id, repository_id, origin_kind_code, origin_id,
                    event_name, workflow_path, source_revision, source_digest,
                    authority_digest, selected_at_ms
                ),
                progress_digest = automata_event_subject_progress_digest(
                    progress_schema, progress.subject_id, progress.selection_digest,
                    outcome_kind, run_id, reason, recorded_at_ms
                )
            FROM event_subject_selections AS selection
            JOIN event_subject_progress AS progress USING (subject_id, tenant_id)
            WHERE subject_id = $1
            ",
        )
        .bind(selected.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(canonical, (true, true, true));

        let counts: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM event_subject_selections),
                (SELECT count(*) FROM event_control_subjects),
                (SELECT count(*) FROM event_subject_progress)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1, 1));

        for statement in [
            "UPDATE event_subject_selections SET selected_at_ms = selected_at_ms WHERE subject_id = $1",
            "UPDATE event_control_subjects SET registered_at_ms = registered_at_ms WHERE subject_id = $1",
            "DELETE FROM event_subject_progress WHERE subject_id = $1",
        ] {
            let error = sqlx::query(statement)
                .bind(selected.id().as_uuid())
                .execute(database.pool())
                .await
                .expect_err("event-subject rows are immutable");
            assert_eq!(
                error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::constraint),
                Some("event_subject_records_immutable")
            );
        }
        let orphan = sqlx::query(
            r"
            WITH prior AS (
                SELECT * FROM event_subject_selections WHERE subject_id = $1
            ), desired AS (
                SELECT prior.*,
                       $2::uuid AS next_origin_id,
                       $3::text AS next_workflow_path,
                       automata_event_subject_id(
                           prior.tenant_id, prior.repository_id,
                           prior.origin_kind_code, $2::uuid, $3::text
                       ) AS next_subject_id
                  FROM prior
            )
            INSERT INTO event_subject_selections (
                subject_id, tenant_id, repository_id, selection_schema,
                origin_registry_version, origin_registry_digest,
                origin_kind_code, origin_kind_name, origin_id,
                event_name, workflow_path, source_revision, source_digest,
                authority_digest, selected_at_ms, selection_digest
            )
            SELECT next_subject_id, tenant_id, repository_id, selection_schema,
                   origin_registry_version, origin_registry_digest,
                   origin_kind_code, origin_kind_name, next_origin_id,
                   event_name, next_workflow_path, source_revision, source_digest,
                   authority_digest, 3_000,
                   automata_event_subject_selection_digest(
                       selection_schema, origin_registry_version,
                       origin_registry_digest, next_subject_id, tenant_id,
                       repository_id, origin_kind_code, next_origin_id,
                       event_name, next_workflow_path, source_revision,
                       source_digest, authority_digest, 3_000
                   )
              FROM desired
            ",
        )
        .bind(selected.id().as_uuid())
        .bind(Uuid::from_u128(0xe199))
        .bind(".ci/workflows/orphan.yml")
        .execute(database.pool())
        .await
        .expect_err("an event selection cannot commit without its canonical control");
        assert_eq!(
            orphan
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("event_subject_selection_control_required")
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn every_closed_origin_kind_round_trips_with_exact_code_and_name() -> TestResult {
    run_with_database(|database| async move {
        let tenant = tenant_scope("event-subject-origins");
        let repository_id = RepositoryId::from_uuid(Uuid::from_u128(0xe002));
        seed_repository(database.pool(), &tenant, repository_id).await?;
        let origins = [
            EventSubjectOrigin::ProviderDelivery(ProviderDeliveryId::from_uuid(Uuid::from_u128(
                0xe201,
            ))?),
            EventSubjectOrigin::ScheduleFire(GithubScheduleFireId::from_uuid(Uuid::from_u128(
                0xe202,
            ))?),
            EventSubjectOrigin::ManualOperation(OperationId::from_uuid(Uuid::from_u128(0xe203))),
            EventSubjectOrigin::WorkflowRun(RunId::from_uuid(Uuid::from_u128(0xe204))),
        ];

        for (index, origin) in origins.into_iter().enumerate() {
            let selected = selection(
                tenant.clone(),
                repository_id,
                origin,
                "workflow_dispatch",
                &format!(".ci/workflows/origin-{index}.yml"),
                &format!("revision-{index}"),
                [u8::try_from(index + 1)?; 32],
                1_000 + i64::try_from(index)?,
            );
            let control = EventControlSubject::new(
                EventControlSubjectId::derive(selected.id()),
                &selected,
                UnixMillis::new(1_100 + i64::try_from(index)?),
            )?;
            database
                .store()
                .register_event_subject(RegisterEventSubject::new(selected.clone(), control)?)
                .await?;
            let loaded = database
                .store()
                .load_event_subject_selection(&tenant, selected.id())
                .await?;
            assert_eq!(loaded, selected);
            assert_eq!(loaded.origin(), origin);
        }

        let durable: Vec<(i16, String)> = sqlx::query_as(
            r"
            SELECT origin_kind_code, origin_kind_name
            FROM event_subject_selections
            ORDER BY origin_kind_code
            ",
        )
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            durable,
            vec![
                (1, "provider_delivery".into()),
                (2, "schedule_fire".into()),
                (3, "manual_operation".into()),
                (4, "workflow_run".into()),
            ]
        );

        let operation_id = OperationId::from_uuid(Uuid::from_u128(0xe203));
        let reused_operation = selection(
            tenant.clone(),
            repository_id,
            EventSubjectOrigin::ManualOperation(operation_id),
            "workflow_dispatch",
            ".ci/workflows/different-disabled-workflow.yml",
            "different-revision",
            [0xee; 32],
            2_000,
        );
        let reused_control = EventControlSubject::new(
            EventControlSubjectId::derive(reused_operation.id()),
            &reused_operation,
            UnixMillis::new(2_001),
        )?;
        assert!(matches!(
            database
                .store()
                .register_event_subject(RegisterEventSubject::new(
                    reused_operation,
                    reused_control,
                )?)
                .await,
            Err(EventSubjectStoreError::Conflict)
        ));
        Ok(())
    })
    .await
}

#[allow(clippy::too_many_arguments)]
fn selection(
    tenant: TenantScope,
    repository_id: RepositoryId,
    origin: EventSubjectOrigin,
    event_name: &str,
    workflow_path: &str,
    source_revision: &str,
    source_digest: [u8; 32],
    selected_at_ms: i64,
) -> EventSubjectSelection {
    let id = EventSubjectId::derive(&tenant, repository_id, origin, workflow_path)
        .expect("canonical event-subject ID");
    EventSubjectSelection::new(
        id,
        tenant,
        repository_id,
        origin,
        event_name,
        workflow_path,
        source_revision,
        Sha256Digest::from_bytes(source_digest),
        Sha256Digest::from_bytes([0x24; 32]),
        UnixMillis::new(selected_at_ms),
    )
    .expect("valid event-subject selection")
}

async fn seed_repository(
    pool: &sqlx::PgPool,
    tenant: &TenantScope,
    repository_id: RepositoryId,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, $1, 1, 1)
        ",
    )
    .bind(tenant.as_str())
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id,
            owner, name, created_at_ms, updated_at_ms
        ) VALUES ($1, $2, 'synthetic', $3, 'automata-ci', 'event-subject', 1, 1)
        ",
    )
    .bind(repository_id.as_uuid())
    .bind(tenant.as_str())
    .bind(repository_id.as_uuid().to_string())
    .execute(pool)
    .await?;
    Ok(())
}

fn tenant_scope(value: &str) -> TenantScope {
    TenantScope::from_authenticated_tenant_id(value).expect("tenant")
}
