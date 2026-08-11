-- Repository-local reusable workflows are planned as an exact-source catalog
-- and an immutable call graph before any child graph can become executable.
-- This migration installs that durable seam and removes the historical
-- one-invocation-per-run shape without making planned jobs scheduler-visible.

ALTER TABLE workflow_plan_v2_invocations
    ADD COLUMN invocation_kind TEXT NOT NULL DEFAULT 'root',
    ADD CONSTRAINT workflow_plan_v2_invocations_kind CHECK (
        invocation_kind IN ('root', 'reusable')
    );

ALTER TABLE workflow_plan_v2_invocations
    DROP CONSTRAINT workflow_plan_v2_invocations_run_id_key;

CREATE UNIQUE INDEX workflow_plan_v2_invocations_one_root_per_run
    ON workflow_plan_v2_invocations (run_id)
    WHERE invocation_kind = 'root';

CREATE INDEX workflow_plan_v2_invocations_by_run
    ON workflow_plan_v2_invocations (run_id, id);

-- Optional extension marker. Runs without reusable call jobs retain their
-- existing orchestration schema and behavior. The counts and expansion digest
-- form the replay receipt for a complete planned graph.
CREATE TABLE workflow_plan_v2_reusable_workflow_runs (
    tenant_id TEXT COLLATE "C" NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID PRIMARY KEY,
    root_invocation_id UUID NOT NULL,
    reusable_schema SMALLINT NOT NULL DEFAULT 1,
    expansion_digest BYTEA NOT NULL,
    catalog_entry_count INTEGER NOT NULL,
    invocation_count INTEGER NOT NULL,
    expanded_job_count INTEGER NOT NULL,
    maximum_depth SMALLINT NOT NULL,
    planned_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_runs_repository_fk
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_runs_run_fk
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_runs_root_fk
        FOREIGN KEY (run_id, root_invocation_id)
        REFERENCES workflow_plan_v2_invocations(run_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_runs_schema_exact CHECK (
        reusable_schema = 1
    ),
    CONSTRAINT workflow_plan_v2_reusable_runs_digest_sha256 CHECK (
        octet_length(expansion_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_reusable_runs_catalog_limit CHECK (
        catalog_entry_count BETWEEN 1 AND 50
    ),
    CONSTRAINT workflow_plan_v2_reusable_runs_invocation_limit CHECK (
        invocation_count BETWEEN 1 AND 256
    ),
    CONSTRAINT workflow_plan_v2_reusable_runs_job_limit CHECK (
        expanded_job_count BETWEEN 1 AND 4096
    ),
    CONSTRAINT workflow_plan_v2_reusable_runs_depth_limit CHECK (
        maximum_depth BETWEEN 0 AND 9
    ),
    CONSTRAINT workflow_plan_v2_reusable_runs_time CHECK (planned_at_ms >= 0),
    CONSTRAINT workflow_plan_v2_reusable_runs_root_non_nil CHECK (
        root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
    )
);

-- The catalog binds every canonical path to exact source and canonical plan
-- objects at one immutable repository revision. It intentionally stores no
-- source body and no secret value.
CREATE TABLE workflow_plan_v2_reusable_workflow_catalog (
    run_id UUID NOT NULL,
    catalog_entry_id UUID NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    source_revision TEXT COLLATE "C" NOT NULL,
    source_digest BYTEA NOT NULL,
    source_object_key TEXT COLLATE "C" NOT NULL,
    source_size_bytes BIGINT NOT NULL,
    source_media_type TEXT COLLATE "C" NOT NULL,
    plan_digest BYTEA NOT NULL,
    plan_object_key TEXT COLLATE "C" NOT NULL,
    plan_size_bytes BIGINT NOT NULL,
    plan_media_type TEXT COLLATE "C" NOT NULL,
    plan_schema SMALLINT NOT NULL,
    invocation_contract_digest BYTEA,
    descriptor_digest BYTEA NOT NULL,
    logical_job_count INTEGER NOT NULL,
    reusable_call_count INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_catalog_pk
        PRIMARY KEY (run_id, catalog_entry_id),
    CONSTRAINT workflow_plan_v2_reusable_catalog_path_unique
        UNIQUE (run_id, workflow_path),
    CONSTRAINT workflow_plan_v2_reusable_catalog_exact_unique
        UNIQUE (run_id, catalog_entry_id, source_digest, plan_digest),
    CONSTRAINT workflow_plan_v2_reusable_catalog_run_fk
        FOREIGN KEY (run_id)
        REFERENCES workflow_plan_v2_reusable_workflow_runs(run_id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_catalog_id_non_nil CHECK (
        catalog_entry_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_reusable_catalog_path_canonical CHECK (
        octet_length(workflow_path) BETWEEN 23 AND 1024
        AND workflow_path ~ '^\.github/workflows/[^/]+\.ya?ml$'
        AND workflow_path !~ '[[:cntrl:]]'
        AND position(E'\\' in workflow_path) = 0
    ),
    CONSTRAINT workflow_plan_v2_reusable_catalog_revision_shape CHECK (
        source_revision ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    CONSTRAINT workflow_plan_v2_reusable_catalog_digests_sha256 CHECK (
        octet_length(source_digest) = 32
        AND octet_length(plan_digest) = 32
        AND octet_length(descriptor_digest) = 32
        AND (
            invocation_contract_digest IS NULL
            OR octet_length(invocation_contract_digest) = 32
        )
    ),
    CONSTRAINT workflow_plan_v2_reusable_catalog_source_object CHECK (
        octet_length(source_object_key) BETWEEN 1 AND 1024
        AND source_object_key !~ '[[:cntrl:]]'
        AND left(source_object_key, 1) <> '/'
        AND source_object_key !~ '(^|/)\.\.(/|$)'
        AND source_size_bytes BETWEEN 1 AND 16777216
        AND octet_length(source_media_type) BETWEEN 3 AND 128
        AND source_media_type LIKE '%/%'
        AND source_media_type !~ '[[:space:][:cntrl:];]'
    ),
    CONSTRAINT workflow_plan_v2_reusable_catalog_plan_object CHECK (
        octet_length(plan_object_key) BETWEEN 1 AND 1024
        AND plan_object_key !~ '[[:cntrl:]]'
        AND left(plan_object_key, 1) <> '/'
        AND plan_object_key !~ '(^|/)\.\.(/|$)'
        AND plan_size_bytes BETWEEN 1 AND 16777216
        AND plan_media_type = 'application/vnd.automata.workflow-plan+json'
        AND plan_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_reusable_catalog_job_bounds CHECK (
        logical_job_count BETWEEN 1 AND 1024
        AND reusable_call_count BETWEEN 0 AND logical_job_count
    ),
    CONSTRAINT workflow_plan_v2_reusable_catalog_time CHECK (created_at_ms >= 0)
);

-- Invocation occurrences are static call-graph nodes, not rows in the active
-- orchestration graph. A repeated call to the same catalog entry receives a
-- distinct deterministic invocation identity and parent call-job identity.
CREATE TABLE workflow_plan_v2_reusable_invocation_expansions (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    parent_invocation_id UUID,
    caller_logical_job_id UUID,
    catalog_entry_id UUID NOT NULL,
    depth SMALLINT NOT NULL,
    call_path TEXT[] NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    source_digest BYTEA NOT NULL,
    plan_digest BYTEA NOT NULL,
    call_reference_digest BYTEA,
    input_bindings_digest BYTEA NOT NULL,
    secret_bindings_digest BYTEA NOT NULL,
    output_contract_digest BYTEA NOT NULL,
    permission_digest BYTEA NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    input_binding_count INTEGER NOT NULL,
    secret_binding_count INTEGER NOT NULL,
    output_count INTEGER NOT NULL,
    permission_grant_count INTEGER NOT NULL,
    dependency_count INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_expansions_pk
        PRIMARY KEY (run_id, invocation_id),
    CONSTRAINT workflow_plan_v2_reusable_expansions_callsite_unique
        UNIQUE (run_id, parent_invocation_id, caller_logical_job_id),
    CONSTRAINT workflow_plan_v2_reusable_expansions_catalog_exact_fk
        FOREIGN KEY (run_id, catalog_entry_id, source_digest, plan_digest)
        REFERENCES workflow_plan_v2_reusable_workflow_catalog(
            run_id, catalog_entry_id, source_digest, plan_digest
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_expansions_parent_fk
        FOREIGN KEY (run_id, parent_invocation_id)
        REFERENCES workflow_plan_v2_reusable_invocation_expansions(run_id, invocation_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT workflow_plan_v2_reusable_expansions_id_non_nil CHECK (
        invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_reusable_expansions_parent_non_nil CHECK (
        parent_invocation_id IS NULL
        OR parent_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_reusable_expansions_caller_non_nil CHECK (
        caller_logical_job_id IS NULL
        OR caller_logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_reusable_expansions_depth CHECK (
        depth BETWEEN 0 AND 9
    ),
    CONSTRAINT workflow_plan_v2_reusable_expansions_root_child_shape CHECK ((
        (
            depth = 0
            AND parent_invocation_id IS NULL
            AND caller_logical_job_id IS NULL
            AND call_reference_digest IS NULL
        ) OR (
            depth > 0
            AND parent_invocation_id IS NOT NULL
            AND caller_logical_job_id IS NOT NULL
            AND octet_length(call_reference_digest) = 32
        )
    ) IS TRUE),
    CONSTRAINT workflow_plan_v2_reusable_expansions_path_shape CHECK (
        cardinality(call_path) = depth + 1
        AND call_path[depth + 1] = workflow_path
        AND array_position(call_path, NULL) IS NULL
    ),
    CONSTRAINT workflow_plan_v2_reusable_expansions_digests_sha256 CHECK (
        octet_length(source_digest) = 32
        AND octet_length(plan_digest) = 32
        AND octet_length(input_bindings_digest) = 32
        AND octet_length(secret_bindings_digest) = 32
        AND octet_length(output_contract_digest) = 32
        AND octet_length(permission_digest) = 32
        AND octet_length(descriptor_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_reusable_expansions_contract_counts CHECK (
        input_binding_count BETWEEN 0 AND 256
        AND secret_binding_count BETWEEN 0 AND 256
        AND output_count BETWEEN 0 AND 256
        AND permission_grant_count BETWEEN 0 AND 256
        AND dependency_count BETWEEN 0 AND 1047552
    ),
    CONSTRAINT workflow_plan_v2_reusable_expansions_time CHECK (created_at_ms >= 0)
);

CREATE UNIQUE INDEX workflow_plan_v2_reusable_expansions_one_root
    ON workflow_plan_v2_reusable_invocation_expansions (run_id)
    WHERE depth = 0;

CREATE INDEX workflow_plan_v2_reusable_expansions_parent
    ON workflow_plan_v2_reusable_invocation_expansions (
        run_id, parent_invocation_id, caller_logical_job_id
    ) WHERE depth > 0;

-- Static child jobs remain outside workflow_plan_v2_jobs until a future
-- instance-fenced composition transaction. IDs and dependencies are already
-- fixed here so retries cannot choose a different graph.
CREATE TABLE workflow_plan_v2_reusable_expanded_jobs (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    execution_kind TEXT NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_pk
        PRIMARY KEY (run_id, invocation_id, logical_job_id),
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_key_unique
        UNIQUE (run_id, invocation_id, logical_key),
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_order_unique
        UNIQUE (run_id, invocation_id, source_order),
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_invocation_fk
        FOREIGN KEY (run_id, invocation_id)
        REFERENCES workflow_plan_v2_reusable_invocation_expansions(run_id, invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_id_non_nil CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_key_shape CHECK (
        octet_length(logical_key) BETWEEN 1 AND 256
        AND btrim(logical_key) = logical_key
        AND logical_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_order_bound CHECK (
        source_order BETWEEN 0 AND 1023
    ),
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_kind CHECK (
        execution_kind IN ('steps', 'reusable_workflow')
    ),
    CONSTRAINT workflow_plan_v2_reusable_expanded_jobs_digest_sha256 CHECK (
        octet_length(descriptor_digest) = 32
    )
);

ALTER TABLE workflow_plan_v2_reusable_invocation_expansions
    ADD CONSTRAINT workflow_plan_v2_reusable_expansions_caller_job_fk
        FOREIGN KEY (run_id, parent_invocation_id, caller_logical_job_id)
        REFERENCES workflow_plan_v2_reusable_expanded_jobs(
            run_id, invocation_id, logical_job_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE workflow_plan_v2_reusable_expanded_dependencies (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    prerequisite_job_id UUID NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_expanded_dependencies_pk PRIMARY KEY (
        run_id, invocation_id, logical_job_id, prerequisite_job_id
    ),
    CONSTRAINT workflow_plan_v2_reusable_expanded_dependencies_no_self CHECK (
        logical_job_id <> prerequisite_job_id
    ),
    CONSTRAINT workflow_plan_v2_reusable_expanded_dependencies_job_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_reusable_expanded_jobs(
            run_id, invocation_id, logical_job_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_expanded_dependencies_prerequisite_fk
        FOREIGN KEY (run_id, invocation_id, prerequisite_job_id)
        REFERENCES workflow_plan_v2_reusable_expanded_jobs(
            run_id, invocation_id, logical_job_id
        ) ON DELETE RESTRICT
);

CREATE TABLE workflow_plan_v2_reusable_input_bindings (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    input_key TEXT COLLATE "C" NOT NULL,
    input_type TEXT NOT NULL,
    binding_kind TEXT NOT NULL,
    value_digest BYTEA,
    source_order INTEGER NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_pk
        PRIMARY KEY (run_id, invocation_id, input_key),
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_order_unique
        UNIQUE (run_id, invocation_id, source_order),
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_invocation_fk
        FOREIGN KEY (run_id, invocation_id)
        REFERENCES workflow_plan_v2_reusable_invocation_expansions(run_id, invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_key_shape CHECK (
        octet_length(input_key) BETWEEN 1 AND 256
        AND btrim(input_key) = input_key
        AND input_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_type CHECK (
        input_type IN ('boolean', 'number', 'string')
    ),
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_kind CHECK (
        binding_kind IN ('caller', 'default', 'implicit_default')
    ),
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_value_shape CHECK ((
        (
            binding_kind = 'implicit_default'
            AND value_digest IS NULL
        ) OR (
            binding_kind IN ('caller', 'default')
            AND octet_length(value_digest) = 32
        )
    ) IS TRUE),
    CONSTRAINT workflow_plan_v2_reusable_input_bindings_order CHECK (
        source_order BETWEEN 0 AND 255
    )
);

CREATE TABLE workflow_plan_v2_reusable_secret_bindings (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    target_name TEXT COLLATE "C" NOT NULL,
    source_name TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_secret_bindings_pk
        PRIMARY KEY (run_id, invocation_id, target_name),
    CONSTRAINT workflow_plan_v2_reusable_secret_bindings_order_unique
        UNIQUE (run_id, invocation_id, source_order),
    CONSTRAINT workflow_plan_v2_reusable_secret_bindings_invocation_fk
        FOREIGN KEY (run_id, invocation_id)
        REFERENCES workflow_plan_v2_reusable_invocation_expansions(run_id, invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_secret_bindings_name_only CHECK (
        octet_length(target_name) BETWEEN 1 AND 256
        AND octet_length(source_name) BETWEEN 1 AND 256
        AND btrim(target_name) = target_name
        AND btrim(source_name) = source_name
        AND target_name !~ '[[:cntrl:]]'
        AND source_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_reusable_secret_bindings_order CHECK (
        source_order BETWEEN 0 AND 255
    )
);

CREATE TABLE workflow_plan_v2_reusable_outputs (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    output_key TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    source_order INTEGER NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_outputs_pk
        PRIMARY KEY (run_id, invocation_id, output_key),
    CONSTRAINT workflow_plan_v2_reusable_outputs_order_unique
        UNIQUE (run_id, invocation_id, source_order),
    CONSTRAINT workflow_plan_v2_reusable_outputs_invocation_fk
        FOREIGN KEY (run_id, invocation_id)
        REFERENCES workflow_plan_v2_reusable_invocation_expansions(run_id, invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_outputs_key_shape CHECK (
        octet_length(output_key) BETWEEN 1 AND 256
        AND btrim(output_key) = output_key
        AND output_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_reusable_outputs_sensitivity CHECK (
        sensitivity IN ('public', 'secret_derived')
    ),
    CONSTRAINT workflow_plan_v2_reusable_outputs_order CHECK (
        source_order BETWEEN 0 AND 255
    )
);

CREATE TABLE workflow_plan_v2_reusable_permission_snapshots (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    default_level TEXT NOT NULL,
    permission_digest BYTEA NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_permission_snapshots_pk
        PRIMARY KEY (run_id, invocation_id),
    CONSTRAINT workflow_plan_v2_reusable_permission_snapshots_invocation_fk
        FOREIGN KEY (run_id, invocation_id)
        REFERENCES workflow_plan_v2_reusable_invocation_expansions(run_id, invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_permission_snapshots_level CHECK (
        default_level IN ('none', 'read', 'write')
    ),
    CONSTRAINT workflow_plan_v2_reusable_permission_snapshots_digest CHECK (
        octet_length(permission_digest) = 32
    )
);

CREATE TABLE workflow_plan_v2_reusable_permission_grants (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    permission_name TEXT COLLATE "C" NOT NULL,
    permission_level TEXT NOT NULL,
    CONSTRAINT workflow_plan_v2_reusable_permission_grants_pk
        PRIMARY KEY (run_id, invocation_id, permission_name),
    CONSTRAINT workflow_plan_v2_reusable_permission_grants_snapshot_fk
        FOREIGN KEY (run_id, invocation_id)
        REFERENCES workflow_plan_v2_reusable_permission_snapshots(run_id, invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_reusable_permission_grants_name_shape CHECK (
        octet_length(permission_name) BETWEEN 1 AND 256
        AND btrim(permission_name) = permission_name
        AND permission_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_reusable_permission_grants_level CHECK (
        permission_level IN ('none', 'read', 'write')
    )
);

-- Serialize planning against terminal aggregation. The planner never reopens
-- the admission graph; it may only attach immutable evidence while the run and
-- root orchestration aggregate are still live and unclaimed for finalization.
CREATE FUNCTION automata_lock_reusable_workflow_expansion_window()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN workflow_plan_v2_invocations AS root
      ON root.run_id = marker.run_id
     AND root.id = marker.root_invocation_id
    WHERE marker.run_id = NEW.run_id
      AND marker.root_invocation_id = NEW.root_invocation_id
      AND marker.state IN ('pending', 'active')
      AND marker.admission_graph_sealed_at_ms IS NOT NULL
      AND run.status IN ('queued', 'in_progress')
      AND root.invocation_kind = 'root'
      AND root.state IN ('pending', 'active')
      AND NOT EXISTS (
          SELECT 1
          FROM workflow_plan_v2_run_result_claims AS claim
          WHERE claim.run_id = marker.run_id
      )
    FOR UPDATE OF marker, run, root;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable workflow expansion requires a live unfinalized root'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_window';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_runs_lock_expansion_window
BEFORE INSERT ON workflow_plan_v2_reusable_workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_lock_reusable_workflow_expansion_window();

-- The deferred aggregate check sees the complete transaction and rejects
-- partial catalogs, call graphs, cycles, non-reusable callsites, or count drift.
CREATE FUNCTION automata_validate_reusable_workflow_expansion()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_catalog_count BIGINT;
    expected_invocation_count BIGINT;
    expected_job_count BIGINT;
    expected_maximum_depth SMALLINT;
    expected_root_invocation_id UUID;
    durable_catalog_count BIGINT;
    durable_invocation_count BIGINT;
    durable_job_count BIGINT;
    durable_maximum_depth SMALLINT;
BEGIN
    SELECT catalog_entry_count,
           invocation_count,
           expanded_job_count,
           maximum_depth,
           root_invocation_id
      INTO expected_catalog_count,
           expected_invocation_count,
           expected_job_count,
           expected_maximum_depth,
           expected_root_invocation_id
    FROM workflow_plan_v2_reusable_workflow_runs
    WHERE run_id = NEW.run_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks its replay receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_receipt_required';
    END IF;

    SELECT count(*) INTO durable_catalog_count
    FROM workflow_plan_v2_reusable_workflow_catalog
    WHERE run_id = NEW.run_id;

    SELECT count(*) INTO durable_invocation_count
    FROM workflow_plan_v2_reusable_invocation_expansions
    WHERE run_id = NEW.run_id;

    SELECT count(*) INTO durable_job_count
    FROM workflow_plan_v2_reusable_expanded_jobs
    WHERE run_id = NEW.run_id;

    SELECT COALESCE(max(depth), 0) INTO durable_maximum_depth
    FROM workflow_plan_v2_reusable_invocation_expansions
    WHERE run_id = NEW.run_id;

    IF durable_catalog_count <> expected_catalog_count
        OR durable_invocation_count <> expected_invocation_count
        OR durable_job_count <> expected_job_count
        OR durable_maximum_depth <> expected_maximum_depth
    THEN
        RAISE EXCEPTION 'reusable workflow expansion counts disagree with its replay receipt'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_counts_exact';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_definitions AS workflow ON workflow.id = run.workflow_id
        JOIN workflow_snapshots AS snapshot ON snapshot.id = run.snapshot_id
        JOIN workflow_plan_v2_reusable_invocation_expansions AS root
          ON root.run_id = marker.run_id
         AND root.invocation_id = marker.root_invocation_id
         AND root.depth = 0
        JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
          ON catalog.run_id = root.run_id
         AND catalog.catalog_entry_id = root.catalog_entry_id
        WHERE marker.run_id = NEW.run_id
          AND marker.root_invocation_id = expected_root_invocation_id
          AND marker.admission_graph_sealed_at_ms IS NOT NULL
          AND catalog.workflow_path = workflow.path
          AND catalog.source_digest = snapshot.source_digest
          AND catalog.source_revision = encode(run.head_sha, 'hex')
          AND catalog.source_object_key = snapshot.source_object_key
          AND catalog.source_size_bytes = snapshot.source_size_bytes
          AND catalog.source_media_type = snapshot.source_media_type
          AND catalog.plan_digest = run.plan_digest
          AND catalog.plan_object_key = run.plan_object_key
          AND catalog.plan_size_bytes = run.plan_size_bytes
          AND catalog.plan_media_type = run.plan_media_type
          AND catalog.plan_schema = run.plan_schema
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks its exact sealed root'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_root_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_invocation_expansions AS child
        LEFT JOIN workflow_plan_v2_reusable_invocation_expansions AS parent
          ON parent.run_id = child.run_id
         AND parent.invocation_id = child.parent_invocation_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND (
              parent.invocation_id IS NULL
              OR child.depth <> parent.depth + 1
              OR child.call_path[1:parent.depth + 1] <> parent.call_path
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion parent lineage is inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_parent_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_invocation_expansions AS invocation
        JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
          ON catalog.run_id = invocation.run_id
         AND catalog.catalog_entry_id = invocation.catalog_entry_id
        JOIN workflow_runs AS run ON run.id = invocation.run_id
        WHERE invocation.run_id = NEW.run_id
          AND (
              invocation.workflow_path <> catalog.workflow_path
              OR catalog.source_revision <> encode(run.head_sha, 'hex')
              OR (
                  invocation.depth > 0
                  AND catalog.invocation_contract_digest IS NULL
              )
              OR (
                  SELECT count(*)
                  FROM workflow_plan_v2_reusable_expanded_jobs AS job
                  WHERE job.run_id = invocation.run_id
                    AND job.invocation_id = invocation.invocation_id
              ) <> catalog.logical_job_count
              OR (
                  SELECT count(*)
                  FROM workflow_plan_v2_reusable_expanded_jobs AS job
                  WHERE job.run_id = invocation.run_id
                    AND job.invocation_id = invocation.invocation_id
                    AND job.execution_kind = 'reusable_workflow'
              ) <> catalog.reusable_call_count
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow catalog and expanded invocation disagree'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_catalog_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_invocation_expansions AS invocation
        CROSS JOIN LATERAL unnest(invocation.call_path) AS path(value)
        WHERE invocation.run_id = NEW.run_id
        GROUP BY invocation.invocation_id
        HAVING count(*) <> count(DISTINCT path.value)
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion contains a call cycle'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_acyclic';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_invocation_expansions AS child
        JOIN workflow_plan_v2_reusable_expanded_jobs AS caller
          ON caller.run_id = child.run_id
         AND caller.invocation_id = child.parent_invocation_id
         AND caller.logical_job_id = child.caller_logical_job_id
        WHERE child.run_id = NEW.run_id
          AND child.depth > 0
          AND caller.execution_kind <> 'reusable_workflow'
    ) OR EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_expanded_jobs AS caller
        WHERE caller.run_id = NEW.run_id
          AND caller.execution_kind = 'reusable_workflow'
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_reusable_invocation_expansions AS child
              WHERE child.run_id = caller.run_id
                AND child.parent_invocation_id = caller.invocation_id
                AND child.caller_logical_job_id = caller.logical_job_id
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow callsites and child invocations disagree'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_callsites_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_invocation_expansions AS invocation
        LEFT JOIN workflow_plan_v2_reusable_permission_snapshots AS permissions
          ON permissions.run_id = invocation.run_id
         AND permissions.invocation_id = invocation.invocation_id
         AND permissions.permission_digest = invocation.permission_digest
        WHERE invocation.run_id = NEW.run_id
          AND permissions.invocation_id IS NULL
    ) THEN
        RAISE EXCEPTION 'reusable workflow expansion lacks an exact permission reduction'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_permissions_exact';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_invocation_expansions AS invocation
        WHERE invocation.run_id = NEW.run_id
          AND (
              invocation.input_binding_count <> (
                  SELECT count(*)
                  FROM workflow_plan_v2_reusable_input_bindings AS input
                  WHERE input.run_id = invocation.run_id
                    AND input.invocation_id = invocation.invocation_id
              )
              OR invocation.secret_binding_count <> (
                  SELECT count(*)
                  FROM workflow_plan_v2_reusable_secret_bindings AS secret
                  WHERE secret.run_id = invocation.run_id
                    AND secret.invocation_id = invocation.invocation_id
              )
              OR invocation.output_count <> (
                  SELECT count(*)
                  FROM workflow_plan_v2_reusable_outputs AS output
                  WHERE output.run_id = invocation.run_id
                    AND output.invocation_id = invocation.invocation_id
              )
              OR invocation.permission_grant_count <> (
                  SELECT count(*)
                  FROM workflow_plan_v2_reusable_permission_grants AS permission_grant
                  WHERE permission_grant.run_id = invocation.run_id
                    AND permission_grant.invocation_id = invocation.invocation_id
              )
              OR invocation.dependency_count <> (
                  SELECT count(*)
                  FROM workflow_plan_v2_reusable_expanded_dependencies AS dependency
                  WHERE dependency.run_id = invocation.run_id
                    AND dependency.invocation_id = invocation.invocation_id
              )
          )
    ) THEN
        RAISE EXCEPTION 'reusable workflow typed boundary counts are inexact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_expansion_contract_counts_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_runs_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_workflow_runs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();

-- Every evidence insert revalidates the immutable receipt at COMMIT. This is
-- the one-way seal: the initial transaction may assemble the complete graph,
-- while any later append necessarily disagrees with the already-fixed counts.
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_catalog_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_workflow_catalog
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_invocations_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_invocation_expansions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_jobs_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_expanded_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_dependencies_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_expanded_dependencies
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_inputs_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_input_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_secrets_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_secret_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_outputs_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_outputs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_permission_snapshots_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_permission_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();
CREATE CONSTRAINT TRIGGER workflow_plan_v2_reusable_permission_grants_validate_expansion
AFTER INSERT ON workflow_plan_v2_reusable_permission_grants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_validate_reusable_workflow_expansion();

-- Existing roots remain exact. A future composition phase may add an active
-- reusable invocation only when an immutable planned node already binds the
-- same run and exact plan descriptor.
CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_root()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.invocation_kind = 'root' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_runs AS marker
            JOIN workflow_runs AS run ON run.id = marker.run_id
            WHERE marker.run_id = NEW.run_id
              AND marker.root_invocation_id = NEW.id
              AND run.admission_epoch = 4
              AND run.plan_schema = 2
              AND run.plan_digest = NEW.plan_digest
              AND run.plan_object_key = NEW.plan_object_key
              AND run.plan_size_bytes = NEW.plan_size_bytes
              AND run.plan_media_type = NEW.plan_media_type
              AND run.created_at_ms = NEW.created_at_ms
        ) THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 root descriptor does not match its admitted run'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_plan_v2_invocation_root_exact';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_reusable_invocation_expansions AS expansion
        JOIN workflow_plan_v2_reusable_workflow_catalog AS catalog
          ON catalog.run_id = expansion.run_id
         AND catalog.catalog_entry_id = expansion.catalog_entry_id
        WHERE expansion.run_id = NEW.run_id
          AND expansion.invocation_id = NEW.id
          AND expansion.depth > 0
          AND catalog.plan_digest = NEW.plan_digest
          AND catalog.plan_object_key = NEW.plan_object_key
          AND catalog.plan_size_bytes = NEW.plan_size_bytes
          AND catalog.plan_media_type = NEW.plan_media_type
          AND catalog.plan_schema = NEW.plan_schema
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 reusable invocation lacks exact planned evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_reusable_invocation_plan_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_enforce_workflow_plan_v2_invocation_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_kind IS DISTINCT FROM OLD.invocation_kind
        OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
        OR NEW.plan_object_key IS DISTINCT FROM OLD.plan_object_key
        OR NEW.plan_size_bytes IS DISTINCT FROM OLD.plan_size_bytes
        OR NEW.plan_media_type IS DISTINCT FROM OLD.plan_media_type
        OR NEW.plan_schema IS DISTINCT FROM OLD.plan_schema
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 invocation descriptor is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_invocation_descriptor_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_reject_reusable_workflow_ledger_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'reusable workflow catalog and expansion evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'workflow_plan_v2_reusable_expansion_immutable';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_reusable_runs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_catalog_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_workflow_catalog
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_expansions_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_invocation_expansions
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_jobs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_expanded_jobs
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_dependencies_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_expanded_dependencies
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_inputs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_input_bindings
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_secrets_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_secret_bindings
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_outputs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_outputs
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_permission_snapshots_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_permission_snapshots
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_permission_grants_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_reusable_permission_grants
FOR EACH ROW EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();

CREATE TRIGGER workflow_plan_v2_reusable_runs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_workflow_runs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_catalog_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_workflow_catalog
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_expansions_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_invocation_expansions
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_jobs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_expanded_jobs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_dependencies_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_expanded_dependencies
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_inputs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_input_bindings
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_secrets_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_secret_bindings
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_outputs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_outputs
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_permission_snapshots_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_permission_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
CREATE TRIGGER workflow_plan_v2_reusable_permission_grants_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_reusable_permission_grants
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_reusable_workflow_ledger_mutation();
