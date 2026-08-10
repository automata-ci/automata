-- Current-only logical activation coordination. Workers perform plan/context
-- reads and immutable blob writes outside SQL transactions, then publish only
-- exact JobIR-v5/runtime-context-v2 descriptors under a live activation fence.
-- This phase deliberately creates no concrete jobs or runnable attempts.

-- Serialize the current-contract cut against every older writer. Obsolete
-- concrete execution state is not converted: operators must recreate that
-- state before this greenfield migration can proceed.
LOCK TABLE automata_cluster_compatibility, runners, runner_sessions, jobs,
    runner_operation_receipts, runner_lease_offer_publications
    IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM jobs
        WHERE admission_epoch <> 4
           OR job_ir_schema <> 5
           OR job_ir_size_bytes IS NULL
    ) THEN
        RAISE EXCEPTION 'obsolete concrete JobIR state must be recreated before v5 activation'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM runner_operation_receipts
        WHERE outcome = 'claimed'
          AND claimed_job_ir_schema <> 5
    ) THEN
        RAISE EXCEPTION 'obsolete claimed JobIR receipts must be recreated before v5 activation'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM runner_lease_offer_publications
        WHERE job_ir_schema <> 5
    ) THEN
        RAISE EXCEPTION 'obsolete JobIR lease publications must be recreated before v5 activation'
            USING ERRCODE = '23514';
    END IF;
END;
$automata$;

ALTER TABLE automata_cluster_compatibility
    DROP CONSTRAINT automata_cluster_compatibility_job_ir_v4;

UPDATE automata_cluster_compatibility
SET minimum_admission_epoch = 4,
    job_ir_schema = 5;

ALTER TABLE automata_cluster_compatibility
    ADD CONSTRAINT automata_cluster_compatibility_job_ir_v5 CHECK (
        minimum_admission_epoch = 4
        AND job_ir_schema = 5
        AND runner_requirements_schema = 2
    );

-- A v4 session cannot execute JobIR v5. Retain its audit row but revoke its
-- live authority before installing the exact current live-session constraint.
UPDATE runners AS runner
SET status = 'offline',
    updated_at_ms = greatest(runner.updated_at_ms, incompatible.heartbeat_at_ms)
FROM (
    SELECT runner_id, max(heartbeat_at_ms) AS heartbeat_at_ms
    FROM runner_sessions
    WHERE disconnected_at_ms IS NULL AND job_ir_schema <> 5
    GROUP BY runner_id
) AS incompatible
WHERE runner.id = incompatible.runner_id
  AND runner.status = 'online';

UPDATE runner_sessions
SET disconnected_at_ms = heartbeat_at_ms
WHERE disconnected_at_ms IS NULL AND job_ir_schema <> 5;

ALTER TABLE runner_sessions
    DROP CONSTRAINT runner_sessions_live_job_ir_v4,
    ADD CONSTRAINT runner_sessions_live_job_ir_v5 CHECK (
        disconnected_at_ms IS NOT NULL OR job_ir_schema = 5
    );

ALTER TABLE jobs
    DROP CONSTRAINT jobs_admission_epoch_range,
    DROP CONSTRAINT jobs_current_admission_metadata,
    ADD CONSTRAINT jobs_admission_epoch_exact CHECK (
        admission_epoch = 4
    ),
    ADD CONSTRAINT jobs_current_admission_metadata CHECK (
        admission_epoch = 4
        AND job_ir_schema = 5
        AND job_ir_size_bytes BETWEEN 1 AND 16777216
        AND requirements @> '{"schema_version": 2}'::jsonb
    );

ALTER TABLE runner_operation_receipts
    DROP CONSTRAINT runner_operation_receipts_job_ir_shape,
    ADD CONSTRAINT runner_operation_receipts_job_ir_shape CHECK (
        (
            outcome = 'claimed'
            AND claimed_job_id IS NOT NULL
            AND claimed_run_id IS NOT NULL
            AND claimed_job_ir_schema = 5
            AND claimed_job_ir_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(claimed_job_ir_digest) = 32
            AND octet_length(claimed_job_ir_object_key) BETWEEN 1 AND 1024
            AND claimed_job_ir_object_key !~ '[[:cntrl:]]'
        ) OR (
            outcome <> 'claimed'
            AND claimed_job_id IS NULL
            AND claimed_run_id IS NULL
            AND claimed_job_ir_schema IS NULL
            AND claimed_job_ir_size_bytes IS NULL
            AND claimed_job_ir_digest IS NULL
            AND claimed_job_ir_object_key IS NULL
        )
    );

ALTER TABLE runner_lease_offer_publications
    DROP CONSTRAINT runner_lease_offer_publications_job_ir_shape,
    ADD CONSTRAINT runner_lease_offer_publications_job_ir_shape CHECK (
        job_ir_schema = 5
        AND job_ir_size_bytes BETWEEN 1 AND 16777216
        AND octet_length(job_ir_digest) = 32
        AND octet_length(job_ir_object_key) BETWEEN 1 AND 1024
        AND job_ir_object_key !~ '[[:cntrl:]]'
    );

ALTER TABLE workflow_plan_v2_jobs
    ADD COLUMN activation_input_digest BYTEA,
    ADD CONSTRAINT workflow_plan_v2_jobs_activation_input_digest CHECK (
        activation_input_digest IS NULL
        OR octet_length(activation_input_digest) = 32
    );

CREATE TABLE workflow_plan_v2_activation_publications (
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    activation_input_digest BYTEA NOT NULL,
    activation_output_digest BYTEA NOT NULL,
    activation_owner_id UUID NOT NULL,
    activation_generation BIGINT NOT NULL,
    activation_claimed_at_ms BIGINT NOT NULL,
    activation_expires_at_ms BIGINT NOT NULL,
    condition_matched BOOLEAN NOT NULL,
    instance_count INTEGER NOT NULL,
    job_ir_version SMALLINT NOT NULL,
    runtime_context_schema SMALLINT NOT NULL,
    published_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_activation_publications_primary_key PRIMARY KEY (
        run_id, invocation_id, logical_job_id
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_job_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_activation_publications_input_sha256 CHECK (
        octet_length(activation_input_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_output_sha256 CHECK (
        octet_length(activation_output_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_owner_non_nil CHECK (
        activation_owner_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_generation_positive CHECK (
        activation_generation > 0
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_claim_interval CHECK (
        activation_claimed_at_ms >= 0
        AND activation_expires_at_ms > activation_claimed_at_ms
        AND activation_expires_at_ms - activation_claimed_at_ms <= 900000
        AND published_at_ms >= activation_claimed_at_ms
        AND published_at_ms < activation_expires_at_ms
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_instance_bound CHECK (
        instance_count BETWEEN 0 AND 256
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_condition_shape CHECK (
        condition_matched OR instance_count = 0
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_job_ir_exact CHECK (
        job_ir_version = 5
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_context_exact CHECK (
        runtime_context_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_activation_publications_time_nonnegative CHECK (
        published_at_ms >= 0
    )
);

CREATE TABLE workflow_plan_v2_instances (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    matrix_index INTEGER NOT NULL,
    matrix_total INTEGER NOT NULL,
    matrix_digest BYTEA NOT NULL,
    workspace TEXT COLLATE "C" NOT NULL,
    job_ir_digest BYTEA NOT NULL,
    job_ir_object_key TEXT COLLATE "C" NOT NULL,
    job_ir_size_bytes BIGINT NOT NULL,
    job_ir_media_type TEXT COLLATE "C" NOT NULL,
    job_ir_version SMALLINT NOT NULL,
    runtime_context_digest BYTEA NOT NULL,
    runtime_context_object_key TEXT COLLATE "C" NOT NULL,
    runtime_context_size_bytes BIGINT NOT NULL,
    runtime_context_media_type TEXT COLLATE "C" NOT NULL,
    runtime_context_schema SMALLINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_instances_job_index_unique UNIQUE (
        run_id, invocation_id, logical_job_id, matrix_index
    ),
    CONSTRAINT workflow_plan_v2_instances_publication_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_activation_publications(
            run_id, invocation_id, logical_job_id
        ) ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_instances_id_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_instances_matrix_shape CHECK (
        matrix_index BETWEEN 0 AND 255
        AND matrix_total BETWEEN 1 AND 256
        AND matrix_index < matrix_total
        AND octet_length(matrix_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_instances_workspace_shape CHECK (
        octet_length(workspace) BETWEEN 2 AND 1024
        AND workspace !~ '[[:cntrl:]]'
        AND (
            left(workspace, 1) = '/'
            OR workspace ~ '^[A-Za-z]:\\'
        )
    ),
    CONSTRAINT workflow_plan_v2_instances_job_ir_sha256 CHECK (
        octet_length(job_ir_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_instances_job_ir_key_shape CHECK (
        octet_length(job_ir_object_key) BETWEEN 1 AND 1024
        AND job_ir_object_key !~ '[[:cntrl:]]'
        AND left(job_ir_object_key, 1) <> '/'
        AND job_ir_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_instances_job_ir_size CHECK (
        job_ir_size_bytes BETWEEN 1 AND 16777216
    ),
    CONSTRAINT workflow_plan_v2_instances_job_ir_media_exact CHECK (
        job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'
        AND job_ir_version = 5
    ),
    CONSTRAINT workflow_plan_v2_instances_context_sha256 CHECK (
        octet_length(runtime_context_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_instances_context_key_shape CHECK (
        octet_length(runtime_context_object_key) BETWEEN 1 AND 1024
        AND runtime_context_object_key !~ '[[:cntrl:]]'
        AND left(runtime_context_object_key, 1) <> '/'
        AND runtime_context_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_instances_context_size CHECK (
        runtime_context_size_bytes BETWEEN 1 AND 16777216
    ),
    CONSTRAINT workflow_plan_v2_instances_context_media_exact CHECK (
        runtime_context_media_type =
            'application/vnd.automata.job-runtime-context.protobuf'
        AND runtime_context_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_instances_time_nonnegative CHECK (
        created_at_ms >= 0
    )
);

CREATE INDEX workflow_plan_v2_instances_logical_job
    ON workflow_plan_v2_instances (
        run_id, invocation_id, logical_job_id, matrix_index
    );

CREATE FUNCTION automata_enforce_workflow_plan_v2_activation_input()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.activation_input_digest IS NOT NULL
        AND NEW.activation_input_digest IS DISTINCT FROM
            OLD.activation_input_digest
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation input digest is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.activation_input_digest IS NULL
        AND NEW.activation_input_digest IS NOT NULL
        AND NOT (
            NEW.state = 'activating'
            AND NEW.activation_fence > OLD.activation_fence
            AND octet_length(NEW.activation_input_digest) = 32
        )
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation input requires a new claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_enforce_activation_input
BEFORE UPDATE ON workflow_plan_v2_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_activation_input();

CREATE FUNCTION automata_validate_workflow_plan_v2_activation_publication()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state = 'activating'
          AND job.activation_owner_id = NEW.activation_owner_id
          AND job.activation_fence = NEW.activation_generation
          AND job.activation_input_digest = NEW.activation_input_digest
          AND job.activation_claimed_at_ms = NEW.activation_claimed_at_ms
          AND job.activation_expires_at_ms = NEW.activation_expires_at_ms
          AND job.activation_claimed_at_ms <= NEW.published_at_ms
          AND job.activation_expires_at_ms > NEW.published_at_ms
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          -- Durable prerequisite result/output snapshots are intentionally a
          -- later phase. Until then, only root jobs have authenticated inputs.
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_dependencies AS dependency
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 publication lacks a live current claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_publications_validate
BEFORE INSERT ON workflow_plan_v2_activation_publications
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_activation_publication();

CREATE FUNCTION automata_validate_workflow_plan_v2_instance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_count INTEGER;
    expected_time BIGINT;
BEGIN
    SELECT publication.instance_count, publication.published_at_ms
      INTO expected_count, expected_time
    FROM workflow_plan_v2_activation_publications AS publication
    WHERE publication.run_id = NEW.run_id
      AND publication.invocation_id = NEW.invocation_id
      AND publication.logical_job_id = NEW.logical_job_id;
    IF NOT FOUND
        OR expected_count = 0
        OR NEW.matrix_total <> expected_count
        OR NEW.matrix_index >= expected_count
        OR NEW.created_at_ms <> expected_time
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 instance disagrees with its publication'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instances_validate
BEFORE INSERT ON workflow_plan_v2_instances
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_plan_v2_instance();

CREATE FUNCTION automata_validate_workflow_plan_v2_instance_count()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    target_run UUID;
    target_invocation UUID;
    target_job UUID;
    expected_count INTEGER;
    actual_count BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_run := OLD.run_id;
        target_invocation := OLD.invocation_id;
        target_job := OLD.logical_job_id;
    ELSE
        target_run := NEW.run_id;
        target_invocation := NEW.invocation_id;
        target_job := NEW.logical_job_id;
    END IF;
    SELECT publication.instance_count
      INTO expected_count
    FROM workflow_plan_v2_activation_publications AS publication
    WHERE publication.run_id = target_run
      AND publication.invocation_id = target_invocation
      AND publication.logical_job_id = target_job;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    SELECT count(*) INTO actual_count
    FROM workflow_plan_v2_instances AS instance
    WHERE instance.run_id = target_run
      AND instance.invocation_id = target_invocation
      AND instance.logical_job_id = target_job;
    IF actual_count <> expected_count THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 publication instance count is incomplete'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_publication_count_exact
AFTER INSERT ON workflow_plan_v2_activation_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_instance_count();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_instance_count_exact
AFTER INSERT OR UPDATE OR DELETE ON workflow_plan_v2_instances
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_instance_count();

CREATE FUNCTION automata_validate_workflow_plan_v2_activation_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IN ('activated', 'skipped')
        AND NEW.state IS DISTINCT FROM OLD.state
        AND NOT (
            OLD.state = 'activating'
            AND NEW.activation_owner_id IS NULL
            AND NEW.activation_claimed_at_ms IS NULL
            AND NEW.activation_expires_at_ms IS NULL
            AND EXISTS (
                SELECT 1
                FROM workflow_plan_v2_activation_publications AS publication
                WHERE publication.run_id = NEW.run_id
                  AND publication.invocation_id = NEW.invocation_id
                  AND publication.logical_job_id = NEW.id
                  AND publication.activation_owner_id =
                      OLD.activation_owner_id
                  AND publication.activation_generation =
                      OLD.activation_fence
                  AND publication.activation_input_digest =
                      OLD.activation_input_digest
                  AND publication.activation_claimed_at_ms =
                      OLD.activation_claimed_at_ms
                  AND publication.activation_expires_at_ms =
                      OLD.activation_expires_at_ms
                  AND publication.published_at_ms = NEW.updated_at_ms
                  AND (
                      (NEW.state = 'activated'
                       AND publication.condition_matched)
                      OR (NEW.state = 'skipped'
                          AND NOT publication.condition_matched
                          AND publication.instance_count = 0)
                  )
            )
        )
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation transition lacks exact publication'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_validate_activation_transition
BEFORE UPDATE ON workflow_plan_v2_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_activation_transition();

CREATE FUNCTION automata_reject_workflow_plan_v2_publication_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 activation publication is immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_publications_reject_update
BEFORE UPDATE ON workflow_plan_v2_activation_publications
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_publication_update();

CREATE FUNCTION automata_reject_workflow_plan_v2_publication_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_jobs AS job
        WHERE job.run_id = OLD.run_id
          AND job.invocation_id = OLD.invocation_id
          AND job.id = OLD.logical_job_id
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 activation publication is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_publications_reject_delete
BEFORE DELETE ON workflow_plan_v2_activation_publications
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_publication_delete();

CREATE FUNCTION automata_reject_workflow_plan_v2_instance_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 instance descriptor is immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instances_reject_update
BEFORE UPDATE ON workflow_plan_v2_instances
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_instance_update();
