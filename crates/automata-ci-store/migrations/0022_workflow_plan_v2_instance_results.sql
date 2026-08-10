-- Fenced current-only projection of one terminal epoch-4/JobIR-v5 concrete
-- attempt into an immutable WorkflowPlan-v2 instance result. Blob loading and
-- decoding remain outside SQL; only exact credential-free descriptors and
-- sensitivity-safe output values/markers cross this transaction boundary.

CREATE TABLE workflow_plan_v2_instance_result_claims (
    attempt_id UUID PRIMARY KEY
        REFERENCES attempt_terminal_results(attempt_id) ON DELETE CASCADE,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    instance_id UUID NOT NULL UNIQUE
        REFERENCES workflow_plan_v2_concrete_jobs(instance_id) ON DELETE CASCADE,
    job_id UUID NOT NULL UNIQUE,
    descriptor_digest BYTEA NOT NULL,
    state TEXT NOT NULL,
    owner_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_instance_result_claims_ids_non_nil CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND instance_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_instance_result_claims_digest_sha256 CHECK (
        octet_length(descriptor_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_instance_result_claims_state CHECK (
        state IN ('projecting', 'finalized')
    ),
    CONSTRAINT workflow_plan_v2_instance_result_claims_generation CHECK (
        generation > 0
    ),
    CONSTRAINT workflow_plan_v2_instance_result_claims_interval CHECK (
        claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND expires_at_ms - claimed_at_ms <= 900000
    ),
    CONSTRAINT workflow_plan_v2_instance_result_claims_time_monotonic CHECK (
        created_at_ms >= 0
        AND claimed_at_ms >= created_at_ms
        AND updated_at_ms >= claimed_at_ms
    )
);

CREATE INDEX workflow_plan_v2_instance_result_claims_expired
    ON workflow_plan_v2_instance_result_claims (
        expires_at_ms, run_id, invocation_id, logical_job_id, instance_id
    ) WHERE state = 'projecting';

CREATE TABLE workflow_plan_v2_instance_results (
    instance_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_instance_result_claims(instance_id)
        ON DELETE CASCADE,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    job_id UUID NOT NULL UNIQUE,
    attempt_id UUID NOT NULL UNIQUE
        REFERENCES workflow_plan_v2_instance_result_claims(attempt_id)
        ON DELETE CASCADE,
    descriptor_digest BYTEA NOT NULL,
    result_digest BYTEA NOT NULL,
    result_object_key TEXT COLLATE "C" NOT NULL,
    result_size_bytes BIGINT NOT NULL,
    result_media_type TEXT COLLATE "C" NOT NULL,
    result_schema SMALLINT NOT NULL,
    job_ir_digest BYTEA NOT NULL,
    job_ir_object_key TEXT COLLATE "C" NOT NULL,
    job_ir_size_bytes BIGINT NOT NULL,
    job_ir_media_type TEXT COLLATE "C" NOT NULL,
    job_ir_schema SMALLINT NOT NULL,
    raw_conclusion TEXT NOT NULL,
    effective_conclusion TEXT NOT NULL,
    continue_on_error BOOLEAN NOT NULL,
    secret_exposure_class TEXT NOT NULL,
    result_completed_at_ms BIGINT NOT NULL,
    result_committed_at_ms BIGINT NOT NULL,
    output_count INTEGER NOT NULL,
    outputs_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    claim_owner_id UUID NOT NULL,
    claim_generation BIGINT NOT NULL,
    claim_started_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    finalized_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_instance_results_ids_non_nil CHECK (
        instance_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_instance_results_digests_sha256 CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(result_digest) = 32
        AND octet_length(job_ir_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_instance_results_result_key_shape CHECK (
        octet_length(result_object_key) BETWEEN 1 AND 1024
        AND result_object_key !~ '[[:cntrl:]]'
        AND left(result_object_key, 1) <> '/'
        AND result_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_instance_results_result_current CHECK (
        result_size_bytes BETWEEN 1 AND 16777216
        AND result_media_type = 'application/vnd.automata.job-result+json'
        AND result_schema = 1
    ),
    CONSTRAINT workflow_plan_v2_instance_results_job_ir_key_shape CHECK (
        octet_length(job_ir_object_key) BETWEEN 1 AND 1024
        AND job_ir_object_key !~ '[[:cntrl:]]'
        AND left(job_ir_object_key, 1) <> '/'
        AND job_ir_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_instance_results_job_ir_current CHECK (
        job_ir_size_bytes BETWEEN 1 AND 16777216
        AND job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'
        AND job_ir_schema = 5
    ),
    CONSTRAINT workflow_plan_v2_instance_results_conclusions CHECK (
        raw_conclusion IN ('success', 'failure', 'cancelled', 'timed_out', 'skipped')
        AND effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
    ),
    CONSTRAINT workflow_plan_v2_instance_results_coe_mapping CHECK (
        (
            continue_on_error
            AND raw_conclusion = 'failure'
            AND effective_conclusion = 'success'
        ) OR (
            NOT (continue_on_error AND raw_conclusion = 'failure')
            AND effective_conclusion = raw_conclusion
        )
    ),
    CONSTRAINT workflow_plan_v2_instance_results_secret_exposure CHECK (
        secret_exposure_class IN (
            'secretless', 'capability_only', 'readable_secret'
        )
    ),
    CONSTRAINT workflow_plan_v2_instance_results_output_count CHECK (
        output_count BETWEEN 0 AND 1024
    ),
    CONSTRAINT workflow_plan_v2_instance_results_claim_shape CHECK (
        claim_generation > 0
        AND claim_started_at_ms >= result_committed_at_ms
        AND claim_expires_at_ms > claim_started_at_ms
        AND claim_expires_at_ms - claim_started_at_ms <= 900000
        AND finalized_at_ms >= claim_started_at_ms
        AND finalized_at_ms < claim_expires_at_ms
    ),
    CONSTRAINT workflow_plan_v2_instance_results_result_time CHECK (
        result_completed_at_ms >= 0
        AND result_committed_at_ms >= result_completed_at_ms
    )
);

CREATE TABLE workflow_plan_v2_instance_result_outputs (
    instance_id UUID NOT NULL
        REFERENCES workflow_plan_v2_instance_results(instance_id)
        ON DELETE CASCADE,
    output_name TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    public_value TEXT,
    PRIMARY KEY (instance_id, output_name),
    CONSTRAINT workflow_plan_v2_instance_result_outputs_name_shape CHECK (
        octet_length(output_name) BETWEEN 1 AND 256
        AND btrim(output_name) = output_name
        AND output_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_instance_result_outputs_classification CHECK (
        (sensitivity = 'public' AND public_value IS NOT NULL
            AND public_value <> '' AND octet_length(public_value) <= 2097152)
        OR (sensitivity = 'secret_derived' AND public_value IS NULL)
    )
);

CREATE FUNCTION automata_validate_workflow_plan_v2_instance_result_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM attempt_terminal_results AS terminal
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.job_id = job.id
         AND concrete.initial_attempt_id = attempt.id
        JOIN workflow_plan_v2_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = logical_job.run_id
         AND invocation.id = logical_job.invocation_id
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = concrete.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE terminal.attempt_id = NEW.attempt_id
          AND concrete.run_id = NEW.run_id
          AND concrete.invocation_id = NEW.invocation_id
          AND concrete.logical_job_id = NEW.logical_job_id
          AND concrete.instance_id = NEW.instance_id
          AND concrete.job_id = NEW.job_id
          AND materialization.state = 'materialized'
          AND job.run_id = concrete.run_id
          AND job.admission_epoch = 4
          AND job.job_ir_schema = 5
          AND job.job_ir_digest = instance.job_ir_digest
          AND job.job_ir_object_key = instance.job_ir_object_key
          AND job.job_ir_size_bytes = instance.job_ir_size_bytes
          AND instance.job_ir_version = 5
          AND instance.job_ir_media_type =
              'application/vnd.automata.job-ir.protobuf'
          AND terminal.result_schema = 1
          AND terminal.completed_at_ms >= 0
          AND terminal.committed_at_ms >= terminal.completed_at_ms
          AND NEW.claimed_at_ms >= terminal.committed_at_ms
          AND (
              (terminal.conclusion = 'success' AND attempt.lifecycle = 'succeeded')
              OR (terminal.conclusion = 'failure' AND attempt.lifecycle = 'failed')
              OR (terminal.conclusion = 'cancelled' AND attempt.lifecycle = 'cancelled')
              OR (terminal.conclusion = 'timed_out' AND attempt.lifecycle = 'timed_out')
              OR (terminal.conclusion = 'skipped' AND attempt.lifecycle = 'skipped')
          )
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 result claim lacks one exact current terminal attempt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_claims_validate
BEFORE INSERT ON workflow_plan_v2_instance_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_instance_result_claim();

CREATE FUNCTION automata_enforce_workflow_plan_v2_instance_result_claim_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 instance-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'projecting' AND NEW.state = 'projecting' THEN
        IF NOT (
            NEW.generation = OLD.generation + 1
            AND NEW.claimed_at_ms >= OLD.expires_at_ms
            AND NEW.expires_at_ms > NEW.claimed_at_ms
            AND NEW.expires_at_ms - NEW.claimed_at_ms <= 900000
            AND NEW.updated_at_ms = NEW.claimed_at_ms
        ) THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 instance-result takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'projecting' AND NEW.state = 'finalized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_instance_results AS result
                WHERE result.attempt_id = NEW.attempt_id
                  AND result.run_id = NEW.run_id
                  AND result.invocation_id = NEW.invocation_id
                  AND result.logical_job_id = NEW.logical_job_id
                  AND result.instance_id = NEW.instance_id
                  AND result.job_id = NEW.job_id
                  AND result.descriptor_digest = NEW.descriptor_digest
                  AND result.claim_owner_id = OLD.owner_id
                  AND result.claim_generation = OLD.generation
                  AND result.claim_started_at_ms = OLD.claimed_at_ms
                  AND result.claim_expires_at_ms = OLD.expires_at_ms
                  AND result.finalized_at_ms = NEW.updated_at_ms
                  AND result.output_count = (
                      SELECT count(*)
                      FROM workflow_plan_v2_instance_result_outputs AS output
                      WHERE output.instance_id = result.instance_id
                  )
            )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 instance-result transition lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'WorkflowPlan-v2 instance-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_claims_enforce_transition
BEFORE UPDATE ON workflow_plan_v2_instance_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_instance_result_claim_transition();

CREATE FUNCTION automata_validate_workflow_plan_v2_instance_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instance_result_claims AS claim
        JOIN attempt_terminal_results AS terminal
          ON terminal.attempt_id = claim.attempt_id
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.instance_id = claim.instance_id
         AND concrete.job_id = claim.job_id
         AND concrete.initial_attempt_id = claim.attempt_id
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = concrete.instance_id
        JOIN workflow_runs AS run ON run.id = concrete.run_id
        WHERE claim.attempt_id = NEW.attempt_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.instance_id = NEW.instance_id
          AND claim.job_id = NEW.job_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'projecting'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.finalized_at_ms >= claim.claimed_at_ms
          AND NEW.finalized_at_ms < claim.expires_at_ms
          AND terminal.result_digest = NEW.result_digest
          AND terminal.result_object_key = NEW.result_object_key
          AND terminal.result_size_bytes = NEW.result_size_bytes
          AND terminal.result_schema = NEW.result_schema
          AND terminal.conclusion = NEW.raw_conclusion
          AND terminal.completed_at_ms = NEW.result_completed_at_ms
          AND terminal.committed_at_ms = NEW.result_committed_at_ms
          AND job.run_id = NEW.run_id
          AND job.job_ir_digest = NEW.job_ir_digest
          AND job.job_ir_object_key = NEW.job_ir_object_key
          AND job.job_ir_size_bytes = NEW.job_ir_size_bytes
          AND job.job_ir_schema = NEW.job_ir_schema
          AND job.admission_epoch = 4
          AND (
              (attempt.secret_exposure_class = 'secretless'
               AND NEW.secret_exposure_class = 'secretless')
              OR (attempt.secret_exposure_class = 'capability_only'
                  AND NEW.secret_exposure_class IN (
                      'secretless', 'capability_only'
                  ))
              OR (attempt.secret_exposure_class = 'readable_secret'
                  AND NEW.secret_exposure_class = 'readable_secret')
          )
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
          AND instance.job_ir_digest = NEW.job_ir_digest
          AND instance.job_ir_object_key = NEW.job_ir_object_key
          AND instance.job_ir_size_bytes = NEW.job_ir_size_bytes
          AND instance.job_ir_media_type = NEW.job_ir_media_type
          AND instance.job_ir_version = NEW.job_ir_schema
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 instance result lacks exact terminal/blob/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_results_validate
BEFORE INSERT ON workflow_plan_v2_instance_results
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_instance_result();

CREATE FUNCTION automata_validate_workflow_plan_v2_instance_result_output()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instance_results AS result
        JOIN workflow_plan_v2_instance_result_claims AS claim
          ON claim.instance_id = result.instance_id
        WHERE result.instance_id = NEW.instance_id
          AND claim.state = 'projecting'
          AND result.claim_owner_id = claim.owner_id
          AND result.claim_generation = claim.generation
          AND result.claim_started_at_ms = claim.claimed_at_ms
          AND result.claim_expires_at_ms = claim.expires_at_ms
          AND (
              result.secret_exposure_class <> 'readable_secret'
              OR NEW.sensitivity = 'secret_derived'
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 output lacks a live instance-result fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_outputs_validate
BEFORE INSERT ON workflow_plan_v2_instance_result_outputs
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_instance_result_output();

CREATE FUNCTION automata_reject_workflow_plan_v2_instance_result_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 instance-result evidence is immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_results_reject_update
BEFORE UPDATE ON workflow_plan_v2_instance_results
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_instance_result_update();

CREATE TRIGGER workflow_plan_v2_instance_result_outputs_reject_update
BEFORE UPDATE ON workflow_plan_v2_instance_result_outputs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_instance_result_update();
