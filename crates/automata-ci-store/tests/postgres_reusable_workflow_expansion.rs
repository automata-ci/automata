#[allow(dead_code)]
mod common;

use common::{TestResult, run_with_database};

const RUN_ID: &str = "10000000-0000-0000-0000-000000000004";

// The reusable-ledger test starts from an already admitted and sealed root.
// Provider-admission triggers are disabled only while constructing that base
// fixture; all 0051 triggers are enabled before any ledger row is written.
const SEALED_ROOT_SQL: &str = r"
ALTER TABLE repositories DISABLE TRIGGER USER;
ALTER TABLE workflow_definitions DISABLE TRIGGER USER;
ALTER TABLE workflow_snapshots DISABLE TRIGGER USER;
ALTER TABLE workflow_runs DISABLE TRIGGER USER;
ALTER TABLE workflow_plan_v2_runs DISABLE TRIGGER USER;
ALTER TABLE workflow_plan_v2_invocations DISABLE TRIGGER USER;
ALTER TABLE workflow_plan_v2_jobs DISABLE TRIGGER USER;
BEGIN;
SET CONSTRAINTS ALL DEFERRED;
INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
VALUES ('tenant-reusable-probe', 'Reusable workflow probe', 1, 1);
INSERT INTO repositories (
    id, tenant_id, scm_provider, provider_repository_id, owner, name,
    created_at_ms, updated_at_ms
) VALUES (
    '10000000-0000-0000-0000-000000000001', 'tenant-reusable-probe',
    'github', 'synthetic-1001', 'synthetic-owner', 'synthetic-repository', 1, 1
);
INSERT INTO workflow_definitions (
    id, repository_id, path, created_at_ms, updated_at_ms
) VALUES (
    '10000000-0000-0000-0000-000000000002',
    '10000000-0000-0000-0000-000000000001',
    '.github/workflows/root.yml', 1, 1
);
INSERT INTO workflow_snapshots (
    id, workflow_id, source_digest, source_object_key, frontend_schema,
    created_at_ms, admission_epoch, source_size_bytes, source_media_type
) VALUES (
    '10000000-0000-0000-0000-000000000003',
    '10000000-0000-0000-0000-000000000002',
    decode(repeat('01', 32), 'hex'), 'reusable/root-source.yml', 1,
    1, 4, 128, 'application/yaml'
);
INSERT INTO workflow_runs (
    id, repository_id, workflow_id, snapshot_id, run_number, run_attempt,
    event_name, event_object_key, head_sha, status, created_at_ms, updated_at_ms,
    admission_epoch, event_digest, event_size_bytes, event_media_type,
    plan_digest, plan_object_key, plan_size_bytes, plan_media_type, plan_schema,
    workflow_name, git_ref, actor
) VALUES (
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000002',
    '10000000-0000-0000-0000-000000000003',
    1, 1, 'push', 'reusable/event.json', decode(repeat('09', 20), 'hex'),
    'in_progress', 1, 1, 4, decode(repeat('02', 32), 'hex'), 128,
    'application/json', decode(repeat('03', 32), 'hex'),
    'reusable/root-plan.json', 128,
    'application/vnd.automata.workflow-plan+json', 2,
    'Root', 'refs/heads/main', 'synthetic-actor'
);
INSERT INTO workflow_plan_v2_runs (
    run_id, root_invocation_id, admission_digest, state, admitted_at_ms,
    updated_at_ms, admission_graph_sealed_at_ms
) VALUES (
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    decode(repeat('04', 32), 'hex'), 'active', 1, 1, 1
);
INSERT INTO workflow_plan_v2_invocations (
    id, run_id, plan_digest, plan_object_key, plan_size_bytes,
    plan_media_type, plan_schema, state, created_at_ms, updated_at_ms
) VALUES (
    '10000000-0000-0000-0000-000000000005',
    '10000000-0000-0000-0000-000000000004',
    decode(repeat('03', 32), 'hex'), 'reusable/root-plan.json', 128,
    'application/vnd.automata.workflow-plan+json', 2, 'active', 1, 1
);
INSERT INTO workflow_plan_v2_jobs (
    id, run_id, invocation_id, logical_key, source_order, execution_kind,
    state, activation_fence, created_at_ms, updated_at_ms,
    runtime_policy_revision, runtime_policy_digest
) VALUES (
    '10000000-0000-0000-0000-000000000006',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    'call-child', 0, 'reusable_workflow', 'pending', 0, 1, 1,
    1, decode(repeat('05', 32), 'hex')
);
COMMIT;
ALTER TABLE repositories ENABLE TRIGGER USER;
ALTER TABLE workflow_definitions ENABLE TRIGGER USER;
ALTER TABLE workflow_snapshots ENABLE TRIGGER USER;
ALTER TABLE workflow_runs ENABLE TRIGGER USER;
ALTER TABLE workflow_plan_v2_runs ENABLE TRIGGER USER;
ALTER TABLE workflow_plan_v2_invocations ENABLE TRIGGER USER;
ALTER TABLE workflow_plan_v2_jobs ENABLE TRIGGER USER;
";

const COMPLETE_EXPANSION_SQL: &str = r"
BEGIN;
INSERT INTO workflow_plan_v2_reusable_workflow_runs (
    tenant_id, repository_id, run_id, root_invocation_id, expansion_digest,
    catalog_entry_count, invocation_count, expanded_job_count, maximum_depth,
    planned_at_ms
) VALUES (
    'tenant-reusable-probe', '10000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005', decode(repeat('10', 32), 'hex'),
    2, 2, 3, 1, 2
);
INSERT INTO workflow_plan_v2_reusable_workflow_catalog (
    run_id, catalog_entry_id, workflow_path, source_revision, source_digest,
    source_object_key, source_size_bytes, source_media_type, plan_digest,
    plan_object_key, plan_size_bytes, plan_media_type, plan_schema,
    invocation_contract_digest, descriptor_digest, logical_job_count,
    reusable_call_count, created_at_ms
) VALUES
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000011',
    '.github/workflows/root.yml', repeat('09', 20), decode(repeat('01', 32), 'hex'),
    'reusable/root-source.yml', 128, 'application/yaml',
    decode(repeat('03', 32), 'hex'), 'reusable/root-plan.json', 128,
    'application/vnd.automata.workflow-plan+json', 2,
    NULL, decode(repeat('11', 32), 'hex'), 1, 1, 2
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000012',
    '.github/workflows/child.yml', repeat('09', 20), decode(repeat('12', 32), 'hex'),
    'reusable/child-source.yml', 128, 'application/yaml',
    decode(repeat('13', 32), 'hex'), 'reusable/child-plan.json', 128,
    'application/vnd.automata.workflow-plan+json', 2,
    decode(repeat('14', 32), 'hex'), decode(repeat('15', 32), 'hex'), 2, 0, 2
);
INSERT INTO workflow_plan_v2_reusable_invocation_expansions (
    run_id, invocation_id, parent_invocation_id, caller_logical_job_id,
    catalog_entry_id, depth, call_path, workflow_path, source_digest, plan_digest,
    call_reference_digest, input_bindings_digest, secret_bindings_digest,
    output_contract_digest, permission_digest, descriptor_digest,
    input_binding_count, secret_binding_count, output_count,
    permission_grant_count, dependency_count, created_at_ms
) VALUES
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005', NULL, NULL,
    '10000000-0000-0000-0000-000000000011', 0,
    ARRAY['.github/workflows/root.yml'], '.github/workflows/root.yml',
    decode(repeat('01', 32), 'hex'), decode(repeat('03', 32), 'hex'), NULL,
    decode(repeat('20', 32), 'hex'), decode(repeat('21', 32), 'hex'),
    decode(repeat('22', 32), 'hex'), decode(repeat('23', 32), 'hex'),
    decode(repeat('24', 32), 'hex'), 0, 0, 0, 0, 0, 2
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000007',
    '10000000-0000-0000-0000-000000000005',
    '10000000-0000-0000-0000-000000000006',
    '10000000-0000-0000-0000-000000000012', 1,
    ARRAY['.github/workflows/root.yml', '.github/workflows/child.yml'],
    '.github/workflows/child.yml', decode(repeat('12', 32), 'hex'),
    decode(repeat('13', 32), 'hex'), decode(repeat('25', 32), 'hex'),
    decode(repeat('26', 32), 'hex'), decode(repeat('27', 32), 'hex'),
    decode(repeat('28', 32), 'hex'), decode(repeat('29', 32), 'hex'),
    decode(repeat('2a', 32), 'hex'), 0, 0, 0, 0, 1, 2
);
INSERT INTO workflow_plan_v2_reusable_expanded_jobs (
    run_id, invocation_id, logical_job_id, logical_key, source_order,
    execution_kind, descriptor_digest
) VALUES
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    '10000000-0000-0000-0000-000000000006', 'call-child', 0,
    'reusable_workflow', decode(repeat('30', 32), 'hex')
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000007',
    '10000000-0000-0000-0000-000000000008', 'child-step', 0,
    'steps', decode(repeat('31', 32), 'hex')
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000007',
    '10000000-0000-0000-0000-000000000009', 'child-final', 1,
    'steps', decode(repeat('32', 32), 'hex')
);
INSERT INTO workflow_plan_v2_reusable_expanded_dependencies (
    run_id, invocation_id, logical_job_id, prerequisite_job_id
) VALUES (
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000007',
    '10000000-0000-0000-0000-000000000009',
    '10000000-0000-0000-0000-000000000008'
);
INSERT INTO workflow_plan_v2_reusable_permission_snapshots (
    run_id, invocation_id, default_level, permission_digest
) VALUES
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005', 'read',
    decode(repeat('23', 32), 'hex')
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000007', 'none',
    decode(repeat('29', 32), 'hex')
);
COMMIT;
";

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn complete_expansion_commits_once_and_is_one_way_sealed() -> TestResult {
    run_with_database(|database| async move {
        sqlx::raw_sql(SEALED_ROOT_SQL)
            .execute(database.pool())
            .await?;
        sqlx::raw_sql(COMPLETE_EXPANSION_SQL)
            .execute(database.pool())
            .await?;

        let counts: (i32, i32, i32, i16, i64) = sqlx::query_as(
            r"
            SELECT catalog_entry_count, invocation_count, expanded_job_count,
                   maximum_depth,
                   (SELECT count(*)
                    FROM workflow_plan_v2_reusable_expanded_dependencies
                    WHERE run_id = reusable.run_id)
            FROM workflow_plan_v2_reusable_workflow_runs AS reusable
            WHERE run_id = $1::uuid
            ",
        )
        .bind(RUN_ID)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (2, 2, 3, 1, 1));

        let late_input = sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_reusable_input_bindings (
                run_id, invocation_id, input_key, input_type, binding_kind,
                value_digest, source_order
            ) VALUES (
                $1::uuid, '10000000-0000-0000-0000-000000000007',
                'late', 'string', 'caller', decode(repeat('40', 32), 'hex'), 0
            )
            ",
        )
        .bind(RUN_ID)
        .execute(database.pool())
        .await
        .expect_err("a committed receipt must reject later typed evidence");
        assert_eq!(
            constraint_name(&late_input),
            Some("workflow_plan_v2_reusable_expansion_contract_counts_exact")
        );

        let late_dependency = sqlx::query(
            r"
            INSERT INTO workflow_plan_v2_reusable_expanded_dependencies (
                run_id, invocation_id, logical_job_id, prerequisite_job_id
            ) VALUES (
                $1::uuid,
                '10000000-0000-0000-0000-000000000007',
                '10000000-0000-0000-0000-000000000008',
                '10000000-0000-0000-0000-000000000009'
            )
            ",
        )
        .bind(RUN_ID)
        .execute(database.pool())
        .await
        .expect_err("a committed receipt must reject later dependency evidence");
        assert_eq!(
            constraint_name(&late_dependency),
            Some("workflow_plan_v2_reusable_expansion_contract_counts_exact")
        );

        let mutation = sqlx::query(
            r"
            UPDATE workflow_plan_v2_reusable_workflow_catalog
            SET descriptor_digest = decode(repeat('ff', 32), 'hex')
            WHERE run_id = $1::uuid
            ",
        )
        .bind(RUN_ID)
        .execute(database.pool())
        .await
        .expect_err("catalog evidence must be immutable");
        assert_eq!(
            constraint_name(&mutation),
            Some("workflow_plan_v2_reusable_expansion_immutable")
        );

        let leaked_rows: i64 = sqlx::query_scalar(
            r"
            SELECT
                (SELECT count(*) FROM workflow_plan_v2_reusable_input_bindings
                 WHERE run_id = $1::uuid)
              + (SELECT count(*) FROM workflow_plan_v2_reusable_expanded_dependencies
                 WHERE run_id = $1::uuid) - 1
            ",
        )
        .bind(RUN_ID)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(leaked_rows, 0, "failed appends must roll back atomically");
        Ok(())
    })
    .await
}

fn constraint_name(error: &sqlx::Error) -> Option<&str> {
    error.as_database_error()?.constraint()
}
