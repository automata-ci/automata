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
    workflow_name, git_ref, actor, runner_requirements_schema
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
    'Root', 'refs/heads/main', 'synthetic-actor', 3
);
INSERT INTO workflow_plan_v2_runs (
    run_id, root_invocation_id, admission_digest, state, admitted_at_ms,
    updated_at_ms, admission_graph_sealed_at_ms, runner_requirements_schema
) VALUES (
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    decode(repeat('04', 32), 'hex'), 'active', 1, 1, 1, 3
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

// The ordinary expansion fixture has one root call job. The identity-chain
// matrix exercises seven independent callsites, so seed the other six exact
// durable root jobs before sealing its 0051 expansion ledger.
const IDENTITY_ROOT_JOBS_SQL: &str = r"
ALTER TABLE workflow_plan_v2_jobs DISABLE TRIGGER USER;
INSERT INTO workflow_plan_v2_jobs (
    id, run_id, invocation_id, logical_key, source_order, execution_kind,
    state, activation_fence, created_at_ms, updated_at_ms,
    runtime_policy_revision, runtime_policy_digest
) VALUES
(
    '20000000-0000-0000-0000-000000000102',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    'call-102', 1, 'reusable_workflow', 'pending', 0, 1, 1,
    1, decode(repeat('05', 32), 'hex')
),
(
    '20000000-0000-0000-0000-000000000103',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    'call-103', 2, 'reusable_workflow', 'pending', 0, 1, 1,
    1, decode(repeat('05', 32), 'hex')
),
(
    '20000000-0000-0000-0000-000000000104',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    'call-104', 3, 'reusable_workflow', 'pending', 0, 1, 1,
    1, decode(repeat('05', 32), 'hex')
),
(
    '20000000-0000-0000-0000-000000000106',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    'call-106', 4, 'reusable_workflow', 'pending', 0, 1, 1,
    1, decode(repeat('05', 32), 'hex')
),
(
    '20000000-0000-0000-0000-000000000108',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    'call-108', 5, 'reusable_workflow', 'pending', 0, 1, 1,
    1, decode(repeat('05', 32), 'hex')
),
(
    '20000000-0000-0000-0000-000000000109',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005',
    'call-109', 6, 'reusable_workflow', 'pending', 0, 1, 1,
    1, decode(repeat('05', 32), 'hex')
);
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

const IDENTITY_CHAIN_MATRIX_SQL: &str = r"
SET CONSTRAINTS ALL DEFERRED;
INSERT INTO workflow_plan_v2_reusable_workflow_runs (
    tenant_id, repository_id, run_id, root_invocation_id, expansion_digest,
    catalog_entry_count, invocation_count, expanded_job_count, maximum_depth,
    planned_at_ms
) VALUES (
    'tenant-reusable-probe', '10000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005', decode(repeat('50', 32), 'hex'),
    3, 15, 21, 2, 2
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
    NULL, decode(repeat('51', 32), 'hex'), 7, 7, 2
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000012',
    '.github/workflows/child.yml', repeat('09', 20), decode(repeat('12', 32), 'hex'),
    'reusable/child-source.yml', 128, 'application/yaml',
    decode(repeat('13', 32), 'hex'), 'reusable/child-plan.json', 128,
    'application/vnd.automata.workflow-plan+json', 2,
    decode(repeat('52', 32), 'hex'), decode(repeat('53', 32), 'hex'), 1, 1, 2
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000013',
    '.github/workflows/grandchild.yml', repeat('09', 20),
    decode(repeat('16', 32), 'hex'), 'reusable/grandchild-source.yml', 128,
    'application/yaml', decode(repeat('17', 32), 'hex'),
    'reusable/grandchild-plan.json', 128,
    'application/vnd.automata.workflow-plan+json', 2,
    decode(repeat('54', 32), 'hex'), decode(repeat('55', 32), 'hex'), 1, 0, 2
);
INSERT INTO workflow_plan_v2_reusable_invocation_expansions (
    run_id, invocation_id, parent_invocation_id, caller_logical_job_id,
    catalog_entry_id, depth, call_path, workflow_path, source_digest, plan_digest,
    call_reference_digest, input_bindings_digest, secret_bindings_digest,
    output_contract_digest, permission_digest, descriptor_digest,
    input_binding_count, secret_binding_count, output_count,
    permission_grant_count, dependency_count, created_at_ms
) VALUES (
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000005', NULL, NULL,
    '10000000-0000-0000-0000-000000000011', 0,
    ARRAY['.github/workflows/root.yml'], '.github/workflows/root.yml',
    decode(repeat('01', 32), 'hex'), decode(repeat('03', 32), 'hex'), NULL,
    decode(repeat('56', 32), 'hex'), decode(repeat('57', 32), 'hex'),
    decode(repeat('58', 32), 'hex'), decode(repeat('59', 32), 'hex'),
    decode(repeat('5a', 32), 'hex'), 0, 0, 0, 0, 0, 2
);
INSERT INTO workflow_plan_v2_reusable_invocation_expansions (
    run_id, invocation_id, parent_invocation_id, caller_logical_job_id,
    catalog_entry_id, depth, call_path, workflow_path, source_digest, plan_digest,
    call_reference_digest, input_bindings_digest, secret_bindings_digest,
    output_contract_digest, permission_digest, descriptor_digest,
    input_binding_count, secret_binding_count, output_count,
    permission_grant_count, dependency_count, created_at_ms
)
SELECT
    '10000000-0000-0000-0000-000000000004', fixture.invocation_id,
    fixture.parent_invocation_id, fixture.caller_logical_job_id,
    CASE fixture.depth
        WHEN 1 THEN '10000000-0000-0000-0000-000000000012'::uuid
        ELSE '10000000-0000-0000-0000-000000000013'::uuid
    END,
    fixture.depth,
    CASE fixture.depth
        WHEN 1 THEN ARRAY[
            '.github/workflows/root.yml',
            '.github/workflows/child.yml'
        ]
        ELSE ARRAY[
            '.github/workflows/root.yml',
            '.github/workflows/child.yml',
            '.github/workflows/grandchild.yml'
        ]
    END,
    CASE fixture.depth
        WHEN 1 THEN '.github/workflows/child.yml'
        ELSE '.github/workflows/grandchild.yml'
    END,
    decode(repeat(CASE fixture.depth WHEN 1 THEN '12' ELSE '16' END, 32), 'hex'),
    decode(repeat(CASE fixture.depth WHEN 1 THEN '13' ELSE '17' END, 32), 'hex'),
    decode(repeat('5b', 32), 'hex'), decode(repeat('5c', 32), 'hex'),
    decode(repeat('5d', 32), 'hex'), decode(repeat('5e', 32), 'hex'),
    decode(repeat('5f', 32), 'hex'), decode(repeat('60', 32), 'hex'),
    0, fixture.secret_binding_count, 0, 0, 0, 2
FROM (VALUES
    (
        '10000000-0000-0000-0000-000000000101'::uuid,
        '10000000-0000-0000-0000-000000000005'::uuid,
        '10000000-0000-0000-0000-000000000006'::uuid, 1::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000102'::uuid,
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000102'::uuid, 1::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000103'::uuid,
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000103'::uuid, 1::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000104'::uuid,
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000104'::uuid, 1::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000106'::uuid,
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000106'::uuid, 1::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000108'::uuid,
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000108'::uuid, 1::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000109'::uuid,
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000109'::uuid, 1::smallint, 2
    ),
    (
        '10000000-0000-0000-0000-000000000110'::uuid,
        '10000000-0000-0000-0000-000000000101'::uuid,
        '30000000-0000-0000-0000-000000000101'::uuid, 2::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000111'::uuid,
        '10000000-0000-0000-0000-000000000102'::uuid,
        '30000000-0000-0000-0000-000000000102'::uuid, 2::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000112'::uuid,
        '10000000-0000-0000-0000-000000000103'::uuid,
        '30000000-0000-0000-0000-000000000103'::uuid, 2::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000105'::uuid,
        '10000000-0000-0000-0000-000000000104'::uuid,
        '30000000-0000-0000-0000-000000000104'::uuid, 2::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000107'::uuid,
        '10000000-0000-0000-0000-000000000106'::uuid,
        '30000000-0000-0000-0000-000000000106'::uuid, 2::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000113'::uuid,
        '10000000-0000-0000-0000-000000000108'::uuid,
        '30000000-0000-0000-0000-000000000108'::uuid, 2::smallint, 1
    ),
    (
        '10000000-0000-0000-0000-000000000114'::uuid,
        '10000000-0000-0000-0000-000000000109'::uuid,
        '30000000-0000-0000-0000-000000000109'::uuid, 2::smallint, 1
    )
) AS fixture(
    invocation_id, parent_invocation_id, caller_logical_job_id, depth,
    secret_binding_count
);
INSERT INTO workflow_plan_v2_reusable_expanded_jobs (
    run_id, invocation_id, logical_job_id, logical_key, source_order,
    execution_kind, descriptor_digest
)
SELECT
    '10000000-0000-0000-0000-000000000004', fixture.invocation_id,
    fixture.logical_job_id, fixture.logical_key, fixture.source_order,
    fixture.execution_kind,
    decode(repeat('61', 32), 'hex')
FROM (VALUES
    (
        '10000000-0000-0000-0000-000000000005'::uuid,
        '10000000-0000-0000-0000-000000000006'::uuid,
        'call-child', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000102'::uuid,
        'call-102', 1, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000103'::uuid,
        'call-103', 2, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000104'::uuid,
        'call-104', 3, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000106'::uuid,
        'call-106', 4, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000108'::uuid,
        'call-108', 5, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000005'::uuid,
        '20000000-0000-0000-0000-000000000109'::uuid,
        'call-109', 6, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000101'::uuid,
        '30000000-0000-0000-0000-000000000101'::uuid,
        'call-grandchild', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000102'::uuid,
        '30000000-0000-0000-0000-000000000102'::uuid,
        'call-grandchild', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000103'::uuid,
        '30000000-0000-0000-0000-000000000103'::uuid,
        'call-grandchild', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000104'::uuid,
        '30000000-0000-0000-0000-000000000104'::uuid,
        'call-grandchild', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000106'::uuid,
        '30000000-0000-0000-0000-000000000106'::uuid,
        'call-grandchild', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000108'::uuid,
        '30000000-0000-0000-0000-000000000108'::uuid,
        'call-grandchild', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000109'::uuid,
        '30000000-0000-0000-0000-000000000109'::uuid,
        'call-grandchild', 0, 'reusable_workflow'
    ),
    (
        '10000000-0000-0000-0000-000000000110'::uuid,
        '40000000-0000-0000-0000-000000000110'::uuid,
        'leaf', 0, 'steps'
    ),
    (
        '10000000-0000-0000-0000-000000000111'::uuid,
        '40000000-0000-0000-0000-000000000111'::uuid,
        'leaf', 0, 'steps'
    ),
    (
        '10000000-0000-0000-0000-000000000112'::uuid,
        '40000000-0000-0000-0000-000000000112'::uuid,
        'leaf', 0, 'steps'
    ),
    (
        '10000000-0000-0000-0000-000000000105'::uuid,
        '40000000-0000-0000-0000-000000000105'::uuid,
        'leaf', 0, 'steps'
    ),
    (
        '10000000-0000-0000-0000-000000000107'::uuid,
        '40000000-0000-0000-0000-000000000107'::uuid,
        'leaf', 0, 'steps'
    ),
    (
        '10000000-0000-0000-0000-000000000113'::uuid,
        '40000000-0000-0000-0000-000000000113'::uuid,
        'leaf', 0, 'steps'
    ),
    (
        '10000000-0000-0000-0000-000000000114'::uuid,
        '40000000-0000-0000-0000-000000000114'::uuid,
        'leaf', 0, 'steps'
    )
) AS fixture(
    invocation_id, logical_job_id, logical_key, source_order, execution_kind
);
INSERT INTO workflow_plan_v2_reusable_secret_bindings (
    run_id, invocation_id, target_name, source_name, source_order
) VALUES
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000101', 'token', 'ToKeN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000102',
    'INHERITED_TOKEN', 'INHERITED_TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000103', 'TOKEN', 'ROOT_TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000104', 'TOKEN', 'ROOT_TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000105', 'TOKEN', 'TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000106', 'TOKEN', 'TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000107', 'TOKEN', 'MIDDLE_TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000108', 'OTHER', 'OTHER', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000109', 'Token', 'TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000109', 'TOKEN', 'TOKEN', 1
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000110', 'TOKEN', 'TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000111',
    'INHERITED_TOKEN', 'INHERITED_TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000112', 'TOKEN', 'TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000113', 'TOKEN', 'TOKEN', 0
),
(
    '10000000-0000-0000-0000-000000000004',
    '10000000-0000-0000-0000-000000000114', 'TOKEN', 'TOKEN', 0
);
INSERT INTO workflow_plan_v2_reusable_permission_snapshots (
    run_id, invocation_id, default_level, permission_digest
)
SELECT
    '10000000-0000-0000-0000-000000000004', invocation_id, 'none',
    CASE
        WHEN invocation_id = '10000000-0000-0000-0000-000000000005'::uuid
            THEN decode(repeat('59', 32), 'hex')
        ELSE decode(repeat('5f', 32), 'hex')
    END
FROM workflow_plan_v2_reusable_invocation_expansions
WHERE run_id = '10000000-0000-0000-0000-000000000004';
SET CONSTRAINTS ALL IMMEDIATE;
";

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn reusable_secret_identity_chain_accepts_only_unambiguous_same_name_forwarding() -> TestResult
{
    run_with_database(|database| async move {
        sqlx::raw_sql(SEALED_ROOT_SQL)
            .execute(database.pool())
            .await?;
        sqlx::raw_sql(IDENTITY_ROOT_JOBS_SQL)
            .execute(database.pool())
            .await?;

        let mut transaction = database.pool().begin().await?;
        sqlx::raw_sql(IDENTITY_CHAIN_MATRIX_SQL)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        let cases: Vec<(String, bool, bool)> = sqlx::query_as(
            r"
            SELECT fixture.label::TEXT,
                   automata_reusable_secret_identity_chain_is_exact(
                       $1::uuid, fixture.invocation_id, fixture.canonical_name
                   ),
                   fixture.expected
            FROM (VALUES
                (
                    'root/direct',
                    '10000000-0000-0000-0000-000000000005'::uuid,
                    'TOKEN', TRUE
                ),
                (
                    'one-hop/identity',
                    '10000000-0000-0000-0000-000000000101'::uuid,
                    'TOKEN', TRUE
                ),
                (
                    'one-hop/inherit-equivalent',
                    '10000000-0000-0000-0000-000000000102'::uuid,
                    'INHERITED_TOKEN', TRUE
                ),
                (
                    'one-hop/renamed',
                    '10000000-0000-0000-0000-000000000103'::uuid,
                    'TOKEN', FALSE
                ),
                (
                    'two-hop/parent-renamed',
                    '10000000-0000-0000-0000-000000000105'::uuid,
                    'TOKEN', FALSE
                ),
                (
                    'two-hop/child-renamed',
                    '10000000-0000-0000-0000-000000000107'::uuid,
                    'TOKEN', FALSE
                ),
                (
                    'two-hop/identity',
                    '10000000-0000-0000-0000-000000000110'::uuid,
                    'TOKEN', TRUE
                ),
                (
                    'two-hop/inherit-equivalent',
                    '10000000-0000-0000-0000-000000000111'::uuid,
                    'INHERITED_TOKEN', TRUE
                ),
                (
                    'two-hop/omitted-parent',
                    '10000000-0000-0000-0000-000000000113'::uuid,
                    'TOKEN', FALSE
                ),
                (
                    'two-hop/parent-casefold-ambiguity',
                    '10000000-0000-0000-0000-000000000114'::uuid,
                    'TOKEN', FALSE
                ),
                (
                    'one-hop/unrelated-target',
                    '10000000-0000-0000-0000-000000000108'::uuid,
                    'TOKEN', FALSE
                ),
                (
                    'one-hop/casefold-ambiguity',
                    '10000000-0000-0000-0000-000000000109'::uuid,
                    'TOKEN', FALSE
                )
            ) AS fixture(label, invocation_id, canonical_name, expected)
            ORDER BY fixture.label
            ",
        )
        .bind(RUN_ID)
        .fetch_all(database.pool())
        .await?;

        for (label, actual, expected) in cases {
            assert_eq!(actual, expected, "identity-chain matrix case {label}");
        }
        Ok(())
    })
    .await
}

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
