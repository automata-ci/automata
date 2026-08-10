-- Current-only logical-job finalization for WorkflowPlan v2. Terminal order is
-- assigned by the server, while plan decoding and output aggregation remain
-- outside SQL under an exact immutable descriptor and live claim fence.

-- Do not invent ordering for pre-existing logical terminal state. This is a
-- greenfield contract and obsolete local state must be recreated.
DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM attempt_terminal_results AS terminal
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.initial_attempt_id = terminal.attempt_id
    ) OR EXISTS (
        SELECT 1 FROM workflow_plan_v2_instance_results
    ) THEN
        RAISE EXCEPTION 'logical terminal state must be recreated before server ordering'
            USING ERRCODE = '23514';
    END IF;
END;
$automata$;

ALTER TABLE attempt_terminal_results
    ADD COLUMN workflow_plan_v2_logical_job_id UUID,
    ADD COLUMN workflow_plan_v2_terminal_ordinal BIGINT,
    ADD CONSTRAINT attempt_terminal_results_workflow_plan_v2_order_shape CHECK ((
        (workflow_plan_v2_logical_job_id IS NULL
         AND workflow_plan_v2_terminal_ordinal IS NULL)
        OR
        (workflow_plan_v2_logical_job_id IS NOT NULL
         AND workflow_plan_v2_terminal_ordinal > 0)
    ) IS TRUE);

CREATE UNIQUE INDEX attempt_terminal_results_workflow_plan_v2_order_unique
    ON attempt_terminal_results (
        workflow_plan_v2_logical_job_id, workflow_plan_v2_terminal_ordinal
    )
    WHERE workflow_plan_v2_logical_job_id IS NOT NULL;

CREATE TABLE workflow_plan_v2_job_terminal_counters (
    logical_job_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_jobs(id) ON DELETE CASCADE,
    last_ordinal BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_job_terminal_counters_positive CHECK (
        last_ordinal > 0
    )
);

CREATE FUNCTION automata_enforce_workflow_plan_v2_terminal_counter()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF pg_trigger_depth() <= 1 THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal counter is trigger-authoritative'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' AND NEW.last_ordinal <> 1 THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal counter must begin at one'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.last_ordinal <> OLD.last_ordinal + 1
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal counter must advance exactly once'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_terminal_counters_enforce
BEFORE INSERT OR UPDATE ON workflow_plan_v2_job_terminal_counters
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_terminal_counter();

CREATE FUNCTION automata_assign_workflow_plan_v2_terminal_ordinal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    target_logical_job UUID;
    assigned_ordinal BIGINT;
BEGIN
    IF NEW.workflow_plan_v2_logical_job_id IS NOT NULL
        OR NEW.workflow_plan_v2_terminal_ordinal IS NOT NULL
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal order must not be supplied by a writer'
            USING ERRCODE = '23514';
    END IF;

    SELECT concrete.logical_job_id
      INTO target_logical_job
    FROM job_attempts AS attempt
    JOIN workflow_plan_v2_concrete_jobs AS concrete
      ON concrete.job_id = attempt.job_id
     AND concrete.initial_attempt_id = attempt.id
    WHERE attempt.id = NEW.attempt_id;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    INSERT INTO workflow_plan_v2_job_terminal_counters (
        logical_job_id, last_ordinal
    ) VALUES (target_logical_job, 1)
    ON CONFLICT (logical_job_id) DO UPDATE
    SET last_ordinal = workflow_plan_v2_job_terminal_counters.last_ordinal + 1
    WHERE workflow_plan_v2_job_terminal_counters.last_ordinal < 9223372036854775807
    RETURNING last_ordinal INTO assigned_ordinal;

    IF assigned_ordinal IS NULL THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal ordinal is exhausted'
            USING ERRCODE = '22003';
    END IF;

    UPDATE attempt_terminal_results
    SET workflow_plan_v2_logical_job_id = target_logical_job,
        workflow_plan_v2_terminal_ordinal = assigned_ordinal
    WHERE attempt_id = NEW.attempt_id
      AND workflow_plan_v2_logical_job_id IS NULL
      AND workflow_plan_v2_terminal_ordinal IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal ordinal assignment lost its row'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE TRIGGER attempt_terminal_results_assign_workflow_plan_v2_order
AFTER INSERT ON attempt_terminal_results
FOR EACH ROW
EXECUTE FUNCTION automata_assign_workflow_plan_v2_terminal_ordinal();

CREATE FUNCTION automata_protect_workflow_plan_v2_terminal_ordinal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.workflow_plan_v2_logical_job_id IS DISTINCT FROM
           OLD.workflow_plan_v2_logical_job_id
       OR NEW.workflow_plan_v2_terminal_ordinal IS DISTINCT FROM
           OLD.workflow_plan_v2_terminal_ordinal
    THEN
        IF OLD.workflow_plan_v2_logical_job_id IS NULL
            AND OLD.workflow_plan_v2_terminal_ordinal IS NULL
            AND NEW.workflow_plan_v2_logical_job_id IS NOT NULL
            AND NEW.workflow_plan_v2_terminal_ordinal > 0
            AND pg_trigger_depth() > 1
        THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal ordinal evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER attempt_terminal_results_protect_workflow_plan_v2_order
BEFORE UPDATE ON attempt_terminal_results
FOR EACH ROW
EXECUTE FUNCTION automata_protect_workflow_plan_v2_terminal_ordinal();

ALTER TABLE workflow_plan_v2_instance_results
    ADD COLUMN terminal_ordinal BIGINT NOT NULL,
    ADD CONSTRAINT workflow_plan_v2_instance_results_terminal_ordinal_positive
        CHECK (terminal_ordinal > 0),
    ADD CONSTRAINT workflow_plan_v2_instance_results_terminal_order_unique
        UNIQUE (logical_job_id, terminal_ordinal);

CREATE TABLE workflow_plan_v2_job_result_claims (
    logical_job_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    state TEXT NOT NULL,
    owner_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_job_result_claims_full_identity_unique
        UNIQUE (run_id, invocation_id, logical_job_id),
    CONSTRAINT workflow_plan_v2_job_result_claims_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_job_result_claims_ids_non_nil CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_job_result_claims_digest_sha256 CHECK (
        octet_length(descriptor_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_job_result_claims_state CHECK (
        state IN ('aggregating', 'finalized')
    ),
    CONSTRAINT workflow_plan_v2_job_result_claims_generation CHECK (
        generation > 0
    ),
    CONSTRAINT workflow_plan_v2_job_result_claims_interval CHECK (
        claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND expires_at_ms - claimed_at_ms <= 900000
        AND created_at_ms <= claimed_at_ms
        AND updated_at_ms >= claimed_at_ms
    )
);

CREATE INDEX workflow_plan_v2_job_result_claims_expired
    ON workflow_plan_v2_job_result_claims (
        expires_at_ms, run_id, invocation_id, logical_job_id
    ) WHERE state = 'aggregating';

CREATE TABLE workflow_plan_v2_job_results (
    logical_job_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_job_result_claims(logical_job_id)
        ON DELETE CASCADE,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    plan_digest BYTEA NOT NULL,
    plan_object_key TEXT COLLATE "C" NOT NULL,
    plan_size_bytes BIGINT NOT NULL,
    plan_media_type TEXT COLLATE "C" NOT NULL,
    plan_schema SMALLINT NOT NULL,
    activation_output_digest BYTEA NOT NULL,
    condition_matched BOOLEAN NOT NULL,
    instance_count INTEGER NOT NULL,
    instances_digest BYTEA NOT NULL,
    prerequisite_count INTEGER NOT NULL,
    prerequisites_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    closure_has_failure BOOLEAN NOT NULL,
    closure_has_cancelled BOOLEAN NOT NULL,
    closure_has_skipped BOOLEAN NOT NULL,
    output_count INTEGER NOT NULL,
    outputs_digest BYTEA NOT NULL,
    commit_digest BYTEA NOT NULL,
    claim_owner_id UUID NOT NULL,
    claim_generation BIGINT NOT NULL,
    claim_started_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    finalized_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_job_results_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_job_result_claims(
            run_id, invocation_id, logical_job_id
        ) ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_job_results_ids_non_nil CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_job_results_digests_sha256 CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(plan_digest) = 32
        AND octet_length(activation_output_digest) = 32
        AND octet_length(instances_digest) = 32
        AND octet_length(prerequisites_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_job_results_key_shape CHECK (
        octet_length(logical_key) BETWEEN 1 AND 256
        AND btrim(logical_key) = logical_key
        AND logical_key !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
    ),
    CONSTRAINT workflow_plan_v2_job_results_plan_key_shape CHECK (
        octet_length(plan_object_key) BETWEEN 1 AND 1024
        AND plan_object_key !~ '[[:cntrl:]]'
        AND left(plan_object_key, 1) <> '/'
        AND plan_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT workflow_plan_v2_job_results_plan_current CHECK (
        plan_size_bytes BETWEEN 1 AND 16777216
        AND plan_media_type = 'application/vnd.automata.workflow-plan+json'
        AND plan_schema = 2
    ),
    CONSTRAINT workflow_plan_v2_job_results_counts CHECK (
        instance_count BETWEEN 0 AND 256
        AND prerequisite_count BETWEEN 0 AND 128
        AND output_count BETWEEN 0 AND 256
        AND (condition_matched OR instance_count = 0)
    ),
    CONSTRAINT workflow_plan_v2_job_results_conclusion CHECK (
        effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
    ),
    CONSTRAINT workflow_plan_v2_job_results_claim_shape CHECK (
        claim_generation > 0
        AND claim_started_at_ms >= 0
        AND claim_expires_at_ms > claim_started_at_ms
        AND claim_expires_at_ms - claim_started_at_ms <= 900000
        AND finalized_at_ms >= claim_started_at_ms
        AND finalized_at_ms < claim_expires_at_ms
    )
);

CREATE TABLE workflow_plan_v2_job_result_instances (
    logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_job_results(logical_job_id) ON DELETE CASCADE,
    instance_id UUID NOT NULL,
    matrix_index INTEGER NOT NULL,
    terminal_ordinal BIGINT NOT NULL,
    instance_descriptor_digest BYTEA NOT NULL,
    instance_outputs_digest BYTEA NOT NULL,
    instance_commit_digest BYTEA NOT NULL,
    raw_conclusion TEXT NOT NULL,
    effective_conclusion TEXT NOT NULL,
    PRIMARY KEY (logical_job_id, matrix_index),
    UNIQUE (logical_job_id, instance_id),
    UNIQUE (logical_job_id, terminal_ordinal),
    CONSTRAINT workflow_plan_v2_job_result_instances_shape CHECK (
        instance_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND matrix_index BETWEEN 0 AND 255
        AND terminal_ordinal > 0
        AND octet_length(instance_descriptor_digest) = 32
        AND octet_length(instance_outputs_digest) = 32
        AND octet_length(instance_commit_digest) = 32
        AND raw_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
        AND effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
    )
);

CREATE TABLE workflow_plan_v2_job_result_prerequisites (
    logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_job_results(logical_job_id) ON DELETE CASCADE,
    prerequisite_job_id UUID NOT NULL,
    prerequisite_source_order INTEGER NOT NULL,
    prerequisite_commit_digest BYTEA NOT NULL,
    prerequisite_outputs_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    closure_has_failure BOOLEAN NOT NULL,
    closure_has_cancelled BOOLEAN NOT NULL,
    closure_has_skipped BOOLEAN NOT NULL,
    PRIMARY KEY (logical_job_id, prerequisite_job_id),
    UNIQUE (logical_job_id, prerequisite_source_order),
    CONSTRAINT workflow_plan_v2_job_result_prerequisites_shape CHECK (
        prerequisite_job_id <>
            '00000000-0000-0000-0000-000000000000'::uuid
        AND prerequisite_source_order BETWEEN 0 AND 1023
        AND octet_length(prerequisite_commit_digest) = 32
        AND octet_length(prerequisite_outputs_digest) = 32
        AND effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
    )
);

CREATE TABLE workflow_plan_v2_job_result_outputs (
    logical_job_id UUID NOT NULL
        REFERENCES workflow_plan_v2_job_results(logical_job_id) ON DELETE CASCADE,
    output_name TEXT COLLATE "C" NOT NULL,
    sensitivity TEXT NOT NULL,
    public_value TEXT,
    PRIMARY KEY (logical_job_id, output_name),
    CONSTRAINT workflow_plan_v2_job_result_outputs_name_shape CHECK (
        octet_length(output_name) BETWEEN 1 AND 256
        AND btrim(output_name) = output_name
        AND output_name !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_plan_v2_job_result_outputs_classification CHECK (
        (sensitivity = 'public' AND public_value IS NOT NULL
            AND octet_length(public_value) <= 2097152)
        OR (sensitivity = 'secret_derived' AND public_value IS NULL)
    )
);

CREATE FUNCTION automata_validate_workflow_plan_v2_job_result_claim()
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
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE job.run_id = NEW.run_id
          AND job.invocation_id = NEW.invocation_id
          AND job.id = NEW.logical_job_id
          AND job.execution_kind = 'steps'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_schema = 2
          AND invocation.plan_media_type =
              'application/vnd.automata.workflow-plan+json'
          AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND NEW.claimed_at_ms >= publication.published_at_ms
          AND (
              (publication.instance_count = 0 AND NOT EXISTS (
                  SELECT 1 FROM workflow_plan_v2_instances AS instance
                  WHERE instance.run_id = job.run_id
                    AND instance.invocation_id = job.invocation_id
                    AND instance.logical_job_id = job.id
              )) OR (
                  publication.instance_count > 0
                  AND publication.instance_count = (
                      SELECT count(*)
                      FROM workflow_plan_v2_instances AS instance
                      JOIN workflow_plan_v2_instance_results AS result
                        ON result.instance_id = instance.id
                       AND result.run_id = instance.run_id
                       AND result.invocation_id = instance.invocation_id
                       AND result.logical_job_id = instance.logical_job_id
                      JOIN workflow_plan_v2_instance_result_claims AS claim
                        ON claim.instance_id = result.instance_id
                       AND claim.state = 'finalized'
                      WHERE instance.run_id = job.run_id
                        AND instance.invocation_id = job.invocation_id
                        AND instance.logical_job_id = job.id
                  )
                  AND NEW.claimed_at_ms >= COALESCE((
                      SELECT max(result.finalized_at_ms)
                      FROM workflow_plan_v2_instance_results AS result
                      WHERE result.run_id = job.run_id
                        AND result.invocation_id = job.invocation_id
                        AND result.logical_job_id = job.id
                  ), 0)
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_dependencies AS dependency
              LEFT JOIN workflow_plan_v2_job_results AS prerequisite
                ON prerequisite.logical_job_id = dependency.prerequisite_job_id
               AND prerequisite.run_id = dependency.run_id
               AND prerequisite.invocation_id = dependency.invocation_id
              LEFT JOIN workflow_plan_v2_job_result_claims AS prerequisite_claim
                ON prerequisite_claim.logical_job_id =
                    dependency.prerequisite_job_id
               AND prerequisite_claim.state = 'finalized'
              WHERE dependency.run_id = job.run_id
                AND dependency.invocation_id = job.invocation_id
                AND dependency.logical_job_id = job.id
                AND (prerequisite.logical_job_id IS NULL
                     OR prerequisite_claim.logical_job_id IS NULL
                     OR NEW.claimed_at_ms < prerequisite.finalized_at_ms)
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 job-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_claims_validate
BEFORE INSERT ON workflow_plan_v2_job_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_job_result_claim();

CREATE FUNCTION automata_enforce_workflow_plan_v2_job_result_claim_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    expected_conclusion TEXT;
BEGIN
    IF NEW.logical_job_id IS DISTINCT FROM OLD.logical_job_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 job-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'aggregating' AND NEW.state = 'aggregating' THEN
        IF NOT (
            NEW.generation = OLD.generation + 1
            AND NEW.claimed_at_ms >= OLD.expires_at_ms
            AND NEW.expires_at_ms > NEW.claimed_at_ms
            AND NEW.expires_at_ms - NEW.claimed_at_ms <= 900000
            AND NEW.updated_at_ms = NEW.claimed_at_ms
        ) THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 job-result takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'aggregating' AND NEW.state = 'finalized' THEN
        SELECT CASE
            WHEN result.instance_count = 0 THEN 'skipped'
            WHEN bool_or(instance.effective_conclusion = 'failure') THEN 'failure'
            WHEN bool_or(instance.effective_conclusion = 'timed_out') THEN 'timed_out'
            WHEN bool_or(instance.effective_conclusion = 'cancelled') THEN 'cancelled'
            WHEN bool_or(instance.effective_conclusion = 'success') THEN 'success'
            ELSE 'skipped'
        END
        INTO expected_conclusion
        FROM workflow_plan_v2_job_results AS result
        LEFT JOIN workflow_plan_v2_job_result_instances AS instance
          ON instance.logical_job_id = result.logical_job_id
        WHERE result.logical_job_id = NEW.logical_job_id
        GROUP BY result.logical_job_id, result.instance_count;

        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_job_results AS result
                JOIN workflow_plan_v2_jobs AS job
                  ON job.id = result.logical_job_id
                 AND job.run_id = result.run_id
                 AND job.invocation_id = result.invocation_id
                WHERE result.logical_job_id = NEW.logical_job_id
                  AND result.descriptor_digest = NEW.descriptor_digest
                  AND result.claim_owner_id = OLD.owner_id
                  AND result.claim_generation = OLD.generation
                  AND result.claim_started_at_ms = OLD.claimed_at_ms
                  AND result.claim_expires_at_ms = OLD.expires_at_ms
                  AND result.finalized_at_ms = NEW.updated_at_ms
                  AND result.effective_conclusion = expected_conclusion
                  AND result.instance_count = (
                      SELECT count(*)
                      FROM workflow_plan_v2_job_result_instances AS instance
                      WHERE instance.logical_job_id = result.logical_job_id
                  )
                  AND result.prerequisite_count = (
                      SELECT count(*)
                      FROM workflow_plan_v2_job_result_prerequisites AS prerequisite
                      WHERE prerequisite.logical_job_id = result.logical_job_id
                  )
                  AND result.output_count = (
                      SELECT count(*)
                      FROM workflow_plan_v2_job_result_outputs AS output
                      WHERE output.logical_job_id = result.logical_job_id
                  )
                  AND result.closure_has_failure = (
                      result.effective_conclusion IN ('failure', 'timed_out')
                      OR EXISTS (
                          SELECT 1
                          FROM workflow_plan_v2_job_result_prerequisites AS prerequisite
                          WHERE prerequisite.logical_job_id = result.logical_job_id
                            AND prerequisite.closure_has_failure
                      )
                  )
                  AND result.closure_has_cancelled = (
                      result.effective_conclusion = 'cancelled'
                      OR EXISTS (
                          SELECT 1
                          FROM workflow_plan_v2_job_result_prerequisites AS prerequisite
                          WHERE prerequisite.logical_job_id = result.logical_job_id
                            AND prerequisite.closure_has_cancelled
                      )
                  )
                  AND result.closure_has_skipped = (
                      result.effective_conclusion = 'skipped'
                      OR EXISTS (
                          SELECT 1
                          FROM workflow_plan_v2_job_result_prerequisites AS prerequisite
                          WHERE prerequisite.logical_job_id = result.logical_job_id
                            AND prerequisite.closure_has_skipped
                      )
                  )
                  AND job.updated_at_ms = result.finalized_at_ms
                  AND job.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'failure' THEN 'failed'
                      WHEN 'timed_out' THEN 'failed'
                      WHEN 'cancelled' THEN 'cancelled'
                      WHEN 'skipped' THEN 'skipped'
                  END
            )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 job-result finalization lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'WorkflowPlan-v2 job-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_claims_enforce_transition
BEFORE UPDATE ON workflow_plan_v2_job_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_job_result_claim_transition();

CREATE FUNCTION automata_validate_workflow_plan_v2_job_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_result_claims AS claim
        JOIN workflow_plan_v2_jobs AS job
          ON job.id = claim.logical_job_id
         AND job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = job.run_id
         AND invocation.id = job.invocation_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = job.run_id
         AND publication.invocation_id = job.invocation_id
         AND publication.logical_job_id = job.id
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND NEW.finalized_at_ms >= claim.claimed_at_ms
          AND NEW.finalized_at_ms < claim.expires_at_ms
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND job.execution_kind = 'steps'
          AND job.state IN ('activated', 'skipped')
          AND invocation.plan_digest = NEW.plan_digest
          AND invocation.plan_object_key = NEW.plan_object_key
          AND invocation.plan_size_bytes = NEW.plan_size_bytes
          AND invocation.plan_media_type = NEW.plan_media_type
          AND invocation.plan_schema = NEW.plan_schema
          AND publication.activation_output_digest = NEW.activation_output_digest
          AND publication.condition_matched = NEW.condition_matched
          AND publication.instance_count = NEW.instance_count
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 job result lacks exact plan/publication/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_results_validate
BEFORE INSERT ON workflow_plan_v2_job_results
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_job_result();

CREATE FUNCTION automata_validate_workflow_plan_v2_job_result_instance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_results AS logical_result
        JOIN workflow_plan_v2_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN workflow_plan_v2_instance_results AS instance_result
          ON instance_result.logical_job_id = logical_result.logical_job_id
         AND instance_result.instance_id = NEW.instance_id
        JOIN workflow_plan_v2_instances AS instance
          ON instance.id = instance_result.instance_id
         AND instance.logical_job_id = instance_result.logical_job_id
        JOIN workflow_plan_v2_instance_result_claims AS instance_claim
          ON instance_claim.instance_id = instance_result.instance_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND logical_result.claim_owner_id = logical_claim.owner_id
          AND logical_result.claim_generation = logical_claim.generation
          AND instance.matrix_index = NEW.matrix_index
          AND instance_result.terminal_ordinal = NEW.terminal_ordinal
          AND instance_result.descriptor_digest = NEW.instance_descriptor_digest
          AND instance_result.outputs_digest = NEW.instance_outputs_digest
          AND instance_result.commit_digest = NEW.instance_commit_digest
          AND instance_result.raw_conclusion = NEW.raw_conclusion
          AND instance_result.effective_conclusion = NEW.effective_conclusion
          AND instance_claim.state = 'finalized'
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 logical result instance evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_instances_validate
BEFORE INSERT ON workflow_plan_v2_job_result_instances
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_job_result_instance();

CREATE FUNCTION automata_validate_workflow_plan_v2_job_result_prerequisite()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_results AS logical_result
        JOIN workflow_plan_v2_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        JOIN workflow_plan_v2_dependencies AS dependency
          ON dependency.logical_job_id = logical_result.logical_job_id
         AND dependency.run_id = logical_result.run_id
         AND dependency.invocation_id = logical_result.invocation_id
         AND dependency.prerequisite_job_id = NEW.prerequisite_job_id
        JOIN workflow_plan_v2_jobs AS prerequisite_job
          ON prerequisite_job.id = dependency.prerequisite_job_id
        JOIN workflow_plan_v2_job_results AS prerequisite
          ON prerequisite.logical_job_id = dependency.prerequisite_job_id
        JOIN workflow_plan_v2_job_result_claims AS prerequisite_claim
          ON prerequisite_claim.logical_job_id = prerequisite.logical_job_id
        WHERE logical_result.logical_job_id = NEW.logical_job_id
          AND logical_claim.state = 'aggregating'
          AND prerequisite_claim.state = 'finalized'
          AND prerequisite_job.source_order = NEW.prerequisite_source_order
          AND prerequisite.commit_digest = NEW.prerequisite_commit_digest
          AND prerequisite.outputs_digest = NEW.prerequisite_outputs_digest
          AND prerequisite.effective_conclusion = NEW.effective_conclusion
          AND prerequisite.closure_has_failure = NEW.closure_has_failure
          AND prerequisite.closure_has_cancelled = NEW.closure_has_cancelled
          AND prerequisite.closure_has_skipped = NEW.closure_has_skipped
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 prerequisite closure evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_prerequisites_validate
BEFORE INSERT ON workflow_plan_v2_job_result_prerequisites
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_job_result_prerequisite();

CREATE FUNCTION automata_validate_workflow_plan_v2_job_result_output()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_results AS result
        JOIN workflow_plan_v2_job_result_claims AS claim
          ON claim.logical_job_id = result.logical_job_id
        WHERE result.logical_job_id = NEW.logical_job_id
          AND claim.state = 'aggregating'
          AND result.claim_owner_id = claim.owner_id
          AND result.claim_generation = claim.generation
          AND result.claim_started_at_ms = claim.claimed_at_ms
          AND result.claim_expires_at_ms = claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 logical output lacks a live result fence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_outputs_validate
BEFORE INSERT ON workflow_plan_v2_job_result_outputs
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_job_result_output();

-- The existing activation transition remains authoritative while adding the
-- exact finalized-result path from activated/skipped to a terminal state.
CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_activation_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IN ('completed', 'failed', 'cancelled', 'skipped')
        AND NEW.state IS DISTINCT FROM OLD.state
        AND OLD.state IN ('activated', 'skipped')
        AND EXISTS (
            SELECT 1
            FROM workflow_plan_v2_job_results AS result
            WHERE result.run_id = NEW.run_id
              AND result.invocation_id = NEW.invocation_id
              AND result.logical_job_id = NEW.id
              AND result.finalized_at_ms = NEW.updated_at_ms
              AND NEW.state = CASE result.effective_conclusion
                  WHEN 'success' THEN 'completed'
                  WHEN 'failure' THEN 'failed'
                  WHEN 'timed_out' THEN 'failed'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'skipped' THEN 'skipped'
              END
        )
    THEN
        RETURN NEW;
    END IF;

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
                  AND publication.activation_owner_id = OLD.activation_owner_id
                  AND publication.activation_generation = OLD.activation_fence
                  AND publication.activation_input_digest = OLD.activation_input_digest
                  AND publication.activation_claimed_at_ms = OLD.activation_claimed_at_ms
                  AND publication.activation_expires_at_ms = OLD.activation_expires_at_ms
                  AND publication.published_at_ms = NEW.updated_at_ms
                  AND (
                      (NEW.state = 'activated' AND publication.condition_matched)
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

CREATE FUNCTION automata_reject_workflow_plan_v2_job_result_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 logical-job result evidence is immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_results_reject_update
BEFORE UPDATE ON workflow_plan_v2_job_results
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_job_result_update();

CREATE TRIGGER workflow_plan_v2_job_result_instances_reject_update
BEFORE UPDATE ON workflow_plan_v2_job_result_instances
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_job_result_update();

CREATE TRIGGER workflow_plan_v2_job_result_prerequisites_reject_update
BEFORE UPDATE ON workflow_plan_v2_job_result_prerequisites
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_job_result_update();

CREATE TRIGGER workflow_plan_v2_job_result_outputs_reject_update
BEFORE UPDATE ON workflow_plan_v2_job_result_outputs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_job_result_update();

-- Extend the settled instance-result checks with the server ordinal that the
-- Rust descriptor, immutable row, receipt, and replay digest all carry.
CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_instance_result()
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
          AND terminal.workflow_plan_v2_logical_job_id = NEW.logical_job_id
          AND terminal.workflow_plan_v2_terminal_ordinal = NEW.terminal_ordinal
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
                  AND NEW.secret_exposure_class IN ('secretless', 'capability_only'))
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
