-- Current WorkflowPlan-v2 admission retains the source-level logical DAG and
-- publishes no concrete jobs. Later activation may claim logical jobs and
-- publish JobIR in separately fenced transactions; this migration only lays
-- down the immutable admission aggregate and strict claim shape.

ALTER TABLE workflow_snapshots
    DROP CONSTRAINT workflow_snapshots_admission_epoch,
    DROP CONSTRAINT workflow_snapshots_current_object_metadata,
    ADD CONSTRAINT workflow_snapshots_admission_epoch CHECK (
        admission_epoch BETWEEN 1 AND 4
    ),
    ADD CONSTRAINT workflow_snapshots_current_object_metadata CHECK (
        (
            admission_epoch = 1
            AND source_size_bytes IS NULL
            AND source_media_type IS NULL
        ) OR (
            admission_epoch IN (2, 3, 4)
            AND source_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(source_media_type) BETWEEN 3 AND 128
            AND source_media_type LIKE '%/%'
            AND source_media_type !~ '[[:space:][:cntrl:];]'
        )
    );

ALTER TABLE workflow_runs
    DROP CONSTRAINT workflow_runs_admission_epoch,
    DROP CONSTRAINT workflow_runs_current_event_metadata,
    ADD CONSTRAINT workflow_runs_admission_epoch CHECK (
        admission_epoch BETWEEN 1 AND 4
    ),
    ADD CONSTRAINT workflow_runs_current_event_metadata CHECK (
        (
            admission_epoch = 1
            AND event_digest IS NULL
            AND event_size_bytes IS NULL
            AND event_media_type IS NULL
            AND plan_digest IS NULL
            AND plan_object_key IS NULL
            AND plan_size_bytes IS NULL
            AND plan_media_type IS NULL
            AND plan_schema IS NULL
        ) OR (
            admission_epoch IN (2, 3)
            AND octet_length(event_digest) = 32
            AND event_size_bytes BETWEEN 1 AND 26214400
            AND octet_length(event_media_type) BETWEEN 3 AND 128
            AND event_media_type LIKE '%/%'
            AND event_media_type !~ '[[:space:][:cntrl:];]'
            AND octet_length(plan_digest) = 32
            AND octet_length(plan_object_key) BETWEEN 1 AND 1024
            AND plan_object_key !~ '[[:cntrl:]]'
            AND plan_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(plan_media_type) BETWEEN 3 AND 128
            AND plan_media_type LIKE '%/%'
            AND plan_media_type !~ '[[:space:][:cntrl:];]'
            AND plan_schema = 1
        ) OR (
            admission_epoch = 4
            AND octet_length(event_digest) = 32
            AND event_size_bytes BETWEEN 1 AND 26214400
            AND octet_length(event_media_type) BETWEEN 3 AND 128
            AND event_media_type LIKE '%/%'
            AND event_media_type !~ '[[:space:][:cntrl:];]'
            AND octet_length(plan_digest) = 32
            AND octet_length(plan_object_key) BETWEEN 1 AND 1024
            AND plan_object_key !~ '[[:cntrl:]]'
            AND plan_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(plan_media_type) BETWEEN 3 AND 128
            AND plan_media_type LIKE '%/%'
            AND plan_media_type !~ '[[:space:][:cntrl:];]'
            AND plan_schema = 2
        )
    );

CREATE TABLE workflow_plan_v2_runs (
    run_id UUID PRIMARY KEY
        REFERENCES workflow_runs(id) ON DELETE CASCADE,
    root_invocation_id UUID NOT NULL,
    orchestration_schema SMALLINT NOT NULL DEFAULT 1,
    admission_digest BYTEA NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    revision BIGINT NOT NULL DEFAULT 1,
    admitted_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_runs_run_non_nil CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_runs_root_non_nil CHECK (
        root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_runs_schema_exact CHECK (
        orchestration_schema = 1
    ),
    CONSTRAINT workflow_plan_v2_runs_digest_sha256 CHECK (
        octet_length(admission_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_runs_state CHECK (
        state IN ('pending', 'active', 'completed', 'cancelled', 'failed')
    ),
    CONSTRAINT workflow_plan_v2_runs_revision_positive CHECK (revision > 0),
    CONSTRAINT workflow_plan_v2_runs_time_monotonic CHECK (
        admitted_at_ms >= 0 AND updated_at_ms >= admitted_at_ms
    )
);

CREATE TABLE workflow_plan_v2_invocations (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL UNIQUE
        REFERENCES workflow_plan_v2_runs(run_id) ON DELETE CASCADE,
    plan_digest BYTEA NOT NULL,
    plan_object_key TEXT COLLATE "C" NOT NULL,
    plan_size_bytes BIGINT NOT NULL,
    plan_media_type TEXT COLLATE "C" NOT NULL,
    plan_schema SMALLINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_invocations_run_id_unique UNIQUE (run_id, id),
    CONSTRAINT workflow_plan_v2_invocations_id_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_invocations_plan_sha256 CHECK (
        octet_length(plan_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_invocations_object_key_shape CHECK (
        octet_length(plan_object_key) BETWEEN 1 AND 1024
        AND plan_object_key !~ '[[:cntrl:]]'
        AND left(plan_object_key, 1) <> '/'
        AND plan_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_invocations_plan_size CHECK (
        plan_size_bytes BETWEEN 1 AND 16777216
    ),
    CONSTRAINT workflow_plan_v2_invocations_media_type_shape CHECK (
        octet_length(plan_media_type) BETWEEN 3 AND 128
        AND plan_media_type LIKE '%/%'
        AND plan_media_type !~ '[[:space:][:cntrl:];]'
    ),
    CONSTRAINT workflow_plan_v2_invocations_schema_exact CHECK (plan_schema = 2),
    CONSTRAINT workflow_plan_v2_invocations_state CHECK (
        state IN ('pending', 'active', 'completed', 'cancelled', 'failed')
    ),
    CONSTRAINT workflow_plan_v2_invocations_revision_positive CHECK (revision > 0),
    CONSTRAINT workflow_plan_v2_invocations_time_monotonic CHECK (
        created_at_ms >= 0 AND updated_at_ms >= created_at_ms
    )
);

ALTER TABLE workflow_plan_v2_runs
    ADD CONSTRAINT workflow_plan_v2_runs_root_invocation
        FOREIGN KEY (run_id, root_invocation_id)
        REFERENCES workflow_plan_v2_invocations(run_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE workflow_plan_v2_jobs (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    execution_kind TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    activation_fence BIGINT NOT NULL DEFAULT 0,
    activation_owner_id UUID,
    activation_claimed_at_ms BIGINT,
    activation_expires_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_jobs_run_invocation_id_unique
        UNIQUE (run_id, invocation_id, id),
    CONSTRAINT workflow_plan_v2_jobs_run_key_unique
        UNIQUE (run_id, invocation_id, logical_key),
    CONSTRAINT workflow_plan_v2_jobs_run_order_unique
        UNIQUE (run_id, invocation_id, source_order),
    CONSTRAINT workflow_plan_v2_jobs_invocation_fk
        FOREIGN KEY (run_id, invocation_id)
        REFERENCES workflow_plan_v2_invocations(run_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_jobs_id_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_jobs_key_shape CHECK (
        octet_length(logical_key) BETWEEN 1 AND 256
        AND btrim(logical_key) = logical_key
        AND logical_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_jobs_source_order_bound CHECK (
        source_order BETWEEN 0 AND 1023
    ),
    CONSTRAINT workflow_plan_v2_jobs_execution_kind CHECK (
        execution_kind IN ('steps', 'reusable_workflow')
    ),
    CONSTRAINT workflow_plan_v2_jobs_state CHECK (
        state IN (
            'pending', 'activating', 'activated', 'completed', 'skipped',
            'cancelled', 'failed'
        )
    ),
    CONSTRAINT workflow_plan_v2_jobs_fence_nonnegative CHECK (
        activation_fence >= 0
    ),
    CONSTRAINT workflow_plan_v2_jobs_owner_non_nil CHECK (
        activation_owner_id IS NULL
        OR activation_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_jobs_time_monotonic CHECK (
        created_at_ms >= 0 AND updated_at_ms >= created_at_ms
    ),
    CONSTRAINT workflow_plan_v2_jobs_claim_shape CHECK ((
        (
            activation_owner_id IS NULL
            AND activation_claimed_at_ms IS NULL
            AND activation_expires_at_ms IS NULL
            AND state <> 'activating'
            AND (activation_fence > 0 OR state = 'pending')
        ) OR (
            activation_owner_id IS NOT NULL
            AND activation_fence > 0
            AND state = 'activating'
            AND activation_claimed_at_ms >= created_at_ms
            AND activation_expires_at_ms > activation_claimed_at_ms
            AND activation_expires_at_ms - activation_claimed_at_ms <= 900000
            AND updated_at_ms = activation_claimed_at_ms
        )
    ) IS TRUE)
);

CREATE INDEX workflow_plan_v2_jobs_pending
    ON workflow_plan_v2_jobs (created_at_ms, run_id, source_order, id)
    WHERE state = 'pending';

CREATE INDEX workflow_plan_v2_jobs_expired_claim
    ON workflow_plan_v2_jobs (activation_expires_at_ms, run_id, id)
    WHERE state = 'activating';

CREATE TABLE workflow_plan_v2_dependencies (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    prerequisite_job_id UUID NOT NULL,
    CONSTRAINT workflow_plan_v2_dependencies_primary_key PRIMARY KEY (
        run_id, invocation_id, logical_job_id, prerequisite_job_id
    ),
    CONSTRAINT workflow_plan_v2_dependencies_no_self_edge CHECK (
        logical_job_id <> prerequisite_job_id
    ),
    CONSTRAINT workflow_plan_v2_dependencies_job_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_dependencies_prerequisite_fk
        FOREIGN KEY (run_id, invocation_id, prerequisite_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE CASCADE
);

CREATE INDEX workflow_plan_v2_dependencies_prerequisites
    ON workflow_plan_v2_dependencies (
        run_id, invocation_id, prerequisite_job_id, logical_job_id
    );

CREATE FUNCTION automata_validate_workflow_plan_v2_root()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
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
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_invocations_validate_root
BEFORE INSERT OR UPDATE ON workflow_plan_v2_invocations
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_plan_v2_root();

CREATE FUNCTION automata_enforce_workflow_plan_v2_run_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1 FROM workflow_plan_v2_runs WHERE run_id = OLD.id
    ) AND (
        NEW.id IS DISTINCT FROM OLD.id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id
        OR NEW.snapshot_id IS DISTINCT FROM OLD.snapshot_id
        OR NEW.run_number IS DISTINCT FROM OLD.run_number
        OR NEW.run_attempt IS DISTINCT FROM OLD.run_attempt
        OR NEW.event_name IS DISTINCT FROM OLD.event_name
        OR NEW.event_object_key IS DISTINCT FROM OLD.event_object_key
        OR NEW.head_sha IS DISTINCT FROM OLD.head_sha
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.concurrency_group_key IS DISTINCT FROM OLD.concurrency_group_key
        OR NEW.admission_epoch IS DISTINCT FROM OLD.admission_epoch
        OR NEW.event_digest IS DISTINCT FROM OLD.event_digest
        OR NEW.event_size_bytes IS DISTINCT FROM OLD.event_size_bytes
        OR NEW.event_media_type IS DISTINCT FROM OLD.event_media_type
        OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
        OR NEW.plan_object_key IS DISTINCT FROM OLD.plan_object_key
        OR NEW.plan_size_bytes IS DISTINCT FROM OLD.plan_size_bytes
        OR NEW.plan_media_type IS DISTINCT FROM OLD.plan_media_type
        OR NEW.plan_schema IS DISTINCT FROM OLD.plan_schema
        OR NEW.workflow_name IS DISTINCT FROM OLD.workflow_name
        OR NEW.git_ref IS DISTINCT FROM OLD.git_ref
        OR NEW.actor IS DISTINCT FROM OLD.actor
        OR NEW.display_title IS DISTINCT FROM OLD.display_title
        OR NEW.commit_subject IS DISTINCT FROM OLD.commit_subject
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 admitted run descriptor is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_enforce_plan_v2_immutable
BEFORE UPDATE ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_plan_v2_run_immutable();

CREATE FUNCTION automata_enforce_workflow_plan_v2_marker_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.root_invocation_id IS DISTINCT FROM OLD.root_invocation_id
        OR NEW.orchestration_schema IS DISTINCT FROM OLD.orchestration_schema
        OR NEW.admission_digest IS DISTINCT FROM OLD.admission_digest
        OR NEW.admitted_at_ms IS DISTINCT FROM OLD.admitted_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 admission marker is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runs_enforce_immutable
BEFORE UPDATE ON workflow_plan_v2_runs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_plan_v2_marker_immutable();

CREATE FUNCTION automata_enforce_workflow_plan_v2_invocation_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
        OR NEW.plan_object_key IS DISTINCT FROM OLD.plan_object_key
        OR NEW.plan_size_bytes IS DISTINCT FROM OLD.plan_size_bytes
        OR NEW.plan_media_type IS DISTINCT FROM OLD.plan_media_type
        OR NEW.plan_schema IS DISTINCT FROM OLD.plan_schema
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 invocation descriptor is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_invocations_enforce_immutable
BEFORE UPDATE ON workflow_plan_v2_invocations
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_plan_v2_invocation_immutable();

CREATE FUNCTION automata_enforce_workflow_plan_v2_job_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.logical_key IS DISTINCT FROM OLD.logical_key
        OR NEW.source_order IS DISTINCT FROM OLD.source_order
        OR NEW.execution_kind IS DISTINCT FROM OLD.execution_kind
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 logical-job descriptor is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_enforce_immutable
BEFORE UPDATE ON workflow_plan_v2_jobs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_plan_v2_job_immutable();

CREATE FUNCTION automata_reject_workflow_plan_v2_dependency_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 dependency edges are immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_dependencies_reject_update
BEFORE UPDATE ON workflow_plan_v2_dependencies
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_plan_v2_dependency_update();
