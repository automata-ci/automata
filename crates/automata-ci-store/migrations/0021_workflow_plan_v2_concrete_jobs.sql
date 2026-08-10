-- Fenced current-only publication of runnable jobs from immutable activated
-- WorkflowPlan-v2 instances. Workers load and decode JobIR-v5 blobs outside
-- SQL, then commit only exact verified routing evidence under a live claim.

ALTER TABLE workflow_plan_v2_instances
    ADD CONSTRAINT workflow_plan_v2_instances_full_identity_unique UNIQUE (
        run_id, invocation_id, logical_job_id, id
    );

CREATE TABLE workflow_plan_v2_materialization_claims (
    instance_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    expected_job_id UUID NOT NULL UNIQUE,
    expected_attempt_id UUID NOT NULL UNIQUE,
    state TEXT NOT NULL,
    owner_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_materialization_claims_full_identity_unique
        UNIQUE (run_id, invocation_id, logical_job_id, instance_id),
    CONSTRAINT workflow_plan_v2_materialization_claims_instance_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id, instance_id)
        REFERENCES workflow_plan_v2_instances(
            run_id, invocation_id, logical_job_id, id
        ) ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_materialization_claims_ids_non_nil CHECK (
        instance_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND expected_job_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND expected_attempt_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_materialization_claims_descriptor_sha256 CHECK (
        octet_length(descriptor_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_materialization_claims_state CHECK (
        state IN ('materializing', 'materialized')
    ),
    CONSTRAINT workflow_plan_v2_materialization_claims_generation_positive CHECK (
        generation > 0
    ),
    CONSTRAINT workflow_plan_v2_materialization_claims_interval CHECK (
        claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND expires_at_ms - claimed_at_ms <= 900000
    ),
    CONSTRAINT workflow_plan_v2_materialization_claims_time_monotonic CHECK (
        created_at_ms >= 0
        AND claimed_at_ms >= created_at_ms
        AND updated_at_ms >= claimed_at_ms
    )
);

CREATE INDEX workflow_plan_v2_materialization_claims_expired
    ON workflow_plan_v2_materialization_claims (
        expires_at_ms, run_id, invocation_id, logical_job_id, instance_id
    ) WHERE state = 'materializing';

CREATE TABLE workflow_plan_v2_concrete_jobs (
    instance_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    job_id UUID NOT NULL UNIQUE
        REFERENCES jobs(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    initial_attempt_id UUID NOT NULL UNIQUE
        REFERENCES job_attempts(id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    job_key TEXT COLLATE "C" NOT NULL,
    display_name TEXT COLLATE "C" NOT NULL,
    requirements JSONB NOT NULL,
    requirements_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    event_digest BYTEA NOT NULL,
    event_object_key TEXT COLLATE "C" NOT NULL,
    event_size_bytes BIGINT NOT NULL,
    event_media_type TEXT COLLATE "C" NOT NULL,
    runtime_context_digest BYTEA NOT NULL,
    runtime_context_object_key TEXT COLLATE "C" NOT NULL,
    runtime_context_size_bytes BIGINT NOT NULL,
    runtime_context_media_type TEXT COLLATE "C" NOT NULL,
    runtime_context_schema SMALLINT NOT NULL,
    claim_owner_id UUID NOT NULL,
    claim_generation BIGINT NOT NULL,
    claim_started_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    committed_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_concrete_jobs_claim_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id, instance_id)
        REFERENCES workflow_plan_v2_materialization_claims(
            run_id, invocation_id, logical_job_id, instance_id
        ) ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_concrete_jobs_ids_non_nil CHECK (
        instance_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND initial_attempt_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_owner_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_digests_sha256 CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(requirements_digest) = 32
        AND octet_length(commit_digest) = 32
        AND octet_length(event_digest) = 32
        AND octet_length(runtime_context_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_job_key_shape CHECK (
        octet_length(job_key) BETWEEN 1 AND 512
        AND btrim(job_key) = job_key
        AND job_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_display_name_shape CHECK (
        octet_length(display_name) BETWEEN 1 AND 1024
        AND btrim(display_name) <> ''
        AND display_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_requirements_current CHECK (
        requirements @> '{"schema_version": 2}'::jsonb
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_event_key_shape CHECK (
        octet_length(event_object_key) BETWEEN 1 AND 1024
        AND event_object_key !~ '[[:cntrl:]]'
        AND left(event_object_key, 1) <> '/'
        AND event_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_event_size CHECK (
        event_size_bytes BETWEEN 1 AND 26214400
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_event_media_shape CHECK (
        octet_length(event_media_type) BETWEEN 3 AND 128
        AND event_media_type LIKE '%/%'
        AND event_media_type !~ '[[:space:][:cntrl:];]'
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_runtime_key_shape CHECK (
        octet_length(runtime_context_object_key) BETWEEN 1 AND 1024
        AND runtime_context_object_key !~ '[[:cntrl:]]'
        AND left(runtime_context_object_key, 1) <> '/'
        AND runtime_context_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_runtime_size CHECK (
        runtime_context_size_bytes BETWEEN 1 AND 16777216
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_runtime_exact CHECK (
        runtime_context_media_type =
            'application/vnd.automata.job-runtime-context.protobuf'
        AND runtime_context_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_concrete_jobs_claim_shape CHECK (
        claim_generation > 0
        AND claim_started_at_ms >= 0
        AND claim_expires_at_ms > claim_started_at_ms
        AND claim_expires_at_ms - claim_started_at_ms <= 900000
        AND committed_at_ms >= claim_started_at_ms
        AND committed_at_ms < claim_expires_at_ms
    )
);

CREATE FUNCTION automata_validate_workflow_plan_v2_materialization_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instances AS instance
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = instance.run_id
         AND logical_job.invocation_id = instance.invocation_id
         AND logical_job.id = instance.logical_job_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = logical_job.run_id
         AND invocation.id = logical_job.invocation_id
        JOIN workflow_plan_v2_runs AS marker
          ON marker.run_id = instance.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE instance.id = NEW.instance_id
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
          AND instance.job_ir_version = 5
          AND instance.job_ir_media_type =
              'application/vnd.automata.job-ir.protobuf'
          AND instance.runtime_context_schema = 2
          AND instance.runtime_context_media_type =
              'application/vnd.automata.job-runtime-context.protobuf'
          AND publication.condition_matched
          AND publication.instance_count > 0
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 materialization lacks an activated current instance'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_materialization_claims_validate
BEFORE INSERT ON workflow_plan_v2_materialization_claims
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_materialization_claim();

CREATE FUNCTION automata_enforce_workflow_plan_v2_materialization_claim_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.expected_job_id IS DISTINCT FROM OLD.expected_job_id
        OR NEW.expected_attempt_id IS DISTINCT FROM OLD.expected_attempt_id
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 materialization claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materializing' THEN
        IF NOT (
            NEW.generation = OLD.generation + 1
            AND NEW.claimed_at_ms >= OLD.expires_at_ms
            AND NEW.expires_at_ms > NEW.claimed_at_ms
            AND NEW.expires_at_ms - NEW.claimed_at_ms <= 900000
            AND NEW.updated_at_ms = NEW.claimed_at_ms
        ) THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 materialization takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'materializing' AND NEW.state = 'materialized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_concrete_jobs AS concrete
                WHERE concrete.instance_id = NEW.instance_id
                  AND concrete.run_id = NEW.run_id
                  AND concrete.invocation_id = NEW.invocation_id
                  AND concrete.logical_job_id = NEW.logical_job_id
                  AND concrete.descriptor_digest = NEW.descriptor_digest
                  AND concrete.job_id = NEW.expected_job_id
                  AND concrete.initial_attempt_id = NEW.expected_attempt_id
                  AND concrete.claim_owner_id = OLD.owner_id
                  AND concrete.claim_generation = OLD.generation
                  AND concrete.claim_started_at_ms = OLD.claimed_at_ms
                  AND concrete.claim_expires_at_ms = OLD.expires_at_ms
                  AND concrete.committed_at_ms = NEW.updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 materialization transition lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'WorkflowPlan-v2 materialization claim transition is invalid'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_materialization_claims_enforce_transition
BEFORE UPDATE ON workflow_plan_v2_materialization_claims
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_materialization_claim_transition();

CREATE FUNCTION automata_validate_workflow_plan_v2_concrete_job()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_materialization_claims AS claim
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = claim.instance_id
         AND instance.run_id = claim.run_id
         AND instance.invocation_id = claim.invocation_id
         AND instance.logical_job_id = claim.logical_job_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = instance.run_id
         AND logical_job.invocation_id = instance.invocation_id
         AND logical_job.id = instance.logical_job_id
        JOIN workflow_runs AS run ON run.id = instance.run_id
        JOIN jobs AS job ON job.id = NEW.job_id
        JOIN job_attempts AS attempt ON attempt.id = NEW.initial_attempt_id
        WHERE claim.instance_id = NEW.instance_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.state = 'materializing'
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.expected_job_id = NEW.job_id
          AND claim.expected_attempt_id = NEW.initial_attempt_id
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.committed_at_ms >= claim.claimed_at_ms
          AND NEW.committed_at_ms < claim.expires_at_ms
          AND logical_job.state = 'activated'
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.event_digest = NEW.event_digest
          AND run.event_object_key = NEW.event_object_key
          AND run.event_size_bytes = NEW.event_size_bytes
          AND run.event_media_type = NEW.event_media_type
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND instance.job_ir_version = job.job_ir_schema
          AND instance.runtime_context_digest = NEW.runtime_context_digest
          AND instance.runtime_context_object_key =
              NEW.runtime_context_object_key
          AND instance.runtime_context_size_bytes =
              NEW.runtime_context_size_bytes
          AND instance.runtime_context_media_type =
              NEW.runtime_context_media_type
          AND instance.runtime_context_schema = NEW.runtime_context_schema
          AND job.run_id = NEW.run_id
          AND job.job_key = NEW.job_key
          AND job.display_name = NEW.display_name
          AND job.requirements = NEW.requirements
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND attempt.job_id = job.id
          AND attempt.attempt_number = 1
          AND attempt.lifecycle = 'queued'
          AND attempt.fencing_token = 0
          AND attempt.lease_id IS NULL
          AND attempt.runner_id IS NULL
          AND attempt.lease_issued_at_ms IS NULL
          AND attempt.lease_expires_at_ms IS NULL
          AND attempt.lease_failures = 0
          AND attempt.queued_at_ms = NEW.committed_at_ms
          AND attempt.changed_at_ms = NEW.committed_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 concrete job lacks exact live materialization evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_concrete_jobs_validate
BEFORE INSERT ON workflow_plan_v2_concrete_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_concrete_job();

CREATE FUNCTION automata_reject_workflow_plan_v2_concrete_job_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 concrete materialization evidence is immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_concrete_jobs_reject_update
BEFORE UPDATE ON workflow_plan_v2_concrete_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_concrete_job_update();

CREATE FUNCTION automata_require_workflow_plan_v2_concrete_job_link()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1 FROM workflow_plan_v2_runs WHERE run_id = NEW.run_id
    ) AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_concrete_jobs AS concrete
        JOIN workflow_plan_v2_materialization_claims AS claim
          ON claim.instance_id = concrete.instance_id
        WHERE concrete.run_id = NEW.run_id
          AND concrete.job_id = NEW.id
          AND claim.state = 'materialized'
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 concrete job is not linked to materialized instance'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_jobs_require_instance_link
AFTER INSERT ON jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_workflow_plan_v2_concrete_job_link();

CREATE FUNCTION automata_reject_workflow_plan_v2_legacy_dependency()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1 FROM workflow_plan_v2_runs WHERE run_id = NEW.run_id
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 jobs do not use legacy job dependencies'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_dependencies_reject
BEFORE INSERT OR UPDATE ON job_dependencies
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_legacy_dependency();

CREATE FUNCTION automata_fence_workflow_plan_v2_run_completion()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.status = 'completed'
        AND NEW.status IS DISTINCT FROM OLD.status
        AND EXISTS (
            SELECT 1
            FROM workflow_plan_v2_runs AS marker
            WHERE marker.run_id = NEW.id
              AND marker.state NOT IN ('completed', 'failed')
        )
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run cannot complete before orchestration finalization'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_fence_plan_v2_completion
BEFORE UPDATE ON workflow_runs
FOR EACH ROW
EXECUTE FUNCTION automata_fence_workflow_plan_v2_run_completion();
