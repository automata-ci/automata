ALTER TABLE attempt_terminal_results
    DROP CONSTRAINT attempt_terminal_results_terminal_authority_shape;

ALTER TABLE attempt_terminal_results
    ADD CONSTRAINT attempt_terminal_results_terminal_authority_shape CHECK ((
        terminal_authority = 'runner'
        AND runner_session_id IS NOT NULL AND operation_id IS NOT NULL
        AND runner_id IS NOT NULL AND runner_session_epoch IS NOT NULL
        AND runner_generation IS NOT NULL AND runner_slot IS NOT NULL
        AND lease_id IS NOT NULL AND fencing_token IS NOT NULL
        AND result_schema IS NOT NULL AND result_size_bytes IS NOT NULL
        AND result_digest IS NOT NULL AND result_object_key IS NOT NULL
        AND server_cancellation_operation_id IS NULL
        AND server_cancellation_digest IS NULL
    ) OR (
        terminal_authority = 'server_cancellation'
        AND runner_session_id IS NULL AND operation_id IS NULL
        AND runner_id IS NULL AND runner_session_epoch IS NULL
        AND runner_generation IS NULL AND runner_slot IS NULL
        AND lease_id IS NULL AND fencing_token IS NULL
        AND result_schema IS NULL AND result_size_bytes IS NULL
        AND result_digest IS NULL AND result_object_key IS NULL
        AND server_cancellation_operation_id IS NOT NULL
        AND server_cancellation_operation_id <> '00000000-0000-0000-0000-000000000000'
        AND server_cancellation_digest IS NOT NULL
        AND conclusion = 'cancelled'
    ) OR (
        terminal_authority = 'server_lease_expiry'
        AND runner_session_id IS NULL AND operation_id IS NULL
        AND runner_id IS NULL AND runner_session_epoch IS NULL
        AND runner_generation IS NULL AND runner_slot IS NULL
        AND lease_id IS NULL AND fencing_token IS NULL
        AND result_schema IS NULL AND result_size_bytes IS NULL
        AND result_digest IS NULL AND result_object_key IS NULL
        AND server_cancellation_operation_id IS NULL
        AND server_cancellation_digest IS NULL
        AND conclusion = 'failure'
    ));

ALTER TABLE logical_workflow_instance_results
    DROP CONSTRAINT logical_workflow_instance_results_terminal_authority_shape;

ALTER TABLE logical_workflow_instance_results
    ADD CONSTRAINT logical_workflow_instance_results_terminal_authority_shape CHECK ((
        terminal_authority = 'runner'
        AND octet_length(result_digest) = 32
        AND octet_length(result_object_key) BETWEEN 1 AND 1024
        AND result_object_key !~ '[[:cntrl:]]'
        AND left(result_object_key, 1) <> '/'
        AND result_object_key !~ '(^|/)\.\.(/|$)'
        AND result_size_bytes BETWEEN 1 AND 16777216
        AND result_media_type = 'application/vnd.automata.job-result+json'
        AND result_schema = 1
        AND server_cancellation_operation_id IS NULL
        AND server_cancellation_digest IS NULL
    ) OR (
        terminal_authority = 'server_cancellation'
        AND result_digest IS NULL AND result_object_key IS NULL
        AND result_size_bytes IS NULL AND result_media_type IS NULL
        AND result_schema IS NULL
        AND server_cancellation_operation_id IS NOT NULL
        AND server_cancellation_digest IS NOT NULL
        AND raw_conclusion = 'cancelled' AND effective_conclusion = 'cancelled'
        AND secret_exposure_class = 'secretless' AND output_count = 0
    ) OR (
        terminal_authority = 'server_lease_expiry'
        AND result_digest IS NULL AND result_object_key IS NULL
        AND result_size_bytes IS NULL AND result_media_type IS NULL
        AND result_schema IS NULL
        AND server_cancellation_operation_id IS NULL
        AND server_cancellation_digest IS NULL
        AND raw_conclusion = 'failure' AND effective_conclusion = 'failure'
        AND output_count = 0
    ));

CREATE OR REPLACE FUNCTION automata_validate_server_lease_expiry_terminal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    attempt job_attempts%ROWTYPE;
BEGIN
    IF NEW.terminal_authority IS DISTINCT FROM 'server_lease_expiry' THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT attempt FROM job_attempts WHERE id = NEW.attempt_id;
    IF attempt.lifecycle <> 'lost'
       OR attempt.lease_failures <= 0
       OR attempt.lease_id IS NOT NULL OR attempt.runner_id IS NOT NULL
       OR attempt.runner_session_id IS NOT NULL
       OR attempt.runner_session_epoch IS NOT NULL
       OR attempt.runner_generation IS NOT NULL OR attempt.runner_slot IS NOT NULL
       OR attempt.lease_issued_at_ms IS NOT NULL
       OR attempt.lease_expires_at_ms IS NOT NULL
       OR NEW.conclusion <> 'failure'
       OR NEW.completed_at_ms <> attempt.changed_at_ms
       OR NEW.committed_at_ms <> attempt.changed_at_ms
    THEN
        RAISE EXCEPTION 'server lease-expiry terminal lacks exact lost-attempt authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
        RAISE EXCEPTION 'server lease-expiry terminal lacks exact lost-attempt authority'
            USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER attempt_terminal_results_validate_server_lease_expiry
    BEFORE INSERT OR UPDATE ON attempt_terminal_results
    FOR EACH ROW EXECUTE FUNCTION automata_validate_server_lease_expiry_terminal();

CREATE OR REPLACE FUNCTION automata_refresh_logical_workflow_instance_result_due(target_attempt_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO logical_workflow_instance_result_due (
        attempt_id, tenant_id, run_id, invocation_id, logical_job_id,
        source_order, ready_at_ms, available_at_ms
    )
    SELECT terminal.attempt_id, repository.tenant_id,
           concrete.run_id, concrete.invocation_id, concrete.logical_job_id,
           logical_job.source_order, terminal.committed_at_ms,
           COALESCE(claim.expires_at_ms, terminal.committed_at_ms)
    FROM attempt_terminal_results AS terminal
    JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
    JOIN jobs AS job ON job.id = attempt.job_id
    JOIN logical_workflow_concrete_jobs AS concrete
      ON concrete.job_id = job.id AND concrete.initial_attempt_id = attempt.id
    JOIN logical_workflow_materialization_claims AS materialization
      ON materialization.instance_id = concrete.instance_id
    JOIN logical_workflow_instances AS instance
      ON instance.id = concrete.instance_id AND instance.run_id = concrete.run_id
     AND instance.invocation_id = concrete.invocation_id
     AND instance.logical_job_id = concrete.logical_job_id
    JOIN logical_workflow_jobs AS logical_job
      ON logical_job.run_id = concrete.run_id
     AND logical_job.invocation_id = concrete.invocation_id
     AND logical_job.id = concrete.logical_job_id
    JOIN logical_workflow_invocations AS invocation
      ON invocation.run_id = logical_job.run_id
     AND invocation.id = logical_job.invocation_id
    JOIN logical_workflow_runs AS marker ON marker.run_id = concrete.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    LEFT JOIN logical_workflow_instance_result_claims AS claim
      ON claim.attempt_id = terminal.attempt_id
    WHERE terminal.attempt_id = target_attempt_id
      AND materialization.state = 'materialized'
      AND job.run_id = concrete.run_id
      AND job.admission_epoch = 1 AND job.job_ir_schema = 1
      AND job.job_ir_digest = instance.job_ir_digest
      AND job.job_ir_object_key = instance.job_ir_object_key
      AND job.job_ir_size_bytes = instance.job_ir_size_bytes
      AND instance.job_ir_version = 1
      AND instance.job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'
      AND ((terminal.terminal_authority = 'runner' AND terminal.result_schema = 1)
           OR terminal.terminal_authority IN ('server_cancellation', 'server_lease_expiry'))
      AND terminal.logical_workflow_logical_job_id = concrete.logical_job_id
      AND terminal.logical_workflow_terminal_ordinal > 0
      AND terminal.completed_at_ms >= 0
      AND terminal.committed_at_ms >= terminal.completed_at_ms
      AND ((terminal.conclusion = 'success' AND attempt.lifecycle = 'succeeded')
        OR (terminal.conclusion = 'failure' AND attempt.lifecycle IN ('failed', 'lost'))
        OR (terminal.conclusion = 'cancelled' AND attempt.lifecycle = 'cancelled')
        OR (terminal.conclusion = 'timed_out' AND attempt.lifecycle = 'timed_out')
        OR (terminal.conclusion = 'skipped' AND attempt.lifecycle = 'skipped'))
      AND logical_job.execution_kind = 'steps' AND logical_job.state = 'activated'
      AND invocation.plan_schema = 1 AND invocation.state IN ('pending', 'active')
      AND marker.orchestration_schema = 1 AND marker.state IN ('pending', 'active')
      AND run.admission_epoch = 1 AND run.plan_schema = 1
      AND (claim.attempt_id IS NULL OR claim.state = 'projecting')
    ON CONFLICT (attempt_id) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id, run_id = EXCLUDED.run_id,
        invocation_id = EXCLUDED.invocation_id,
        logical_job_id = EXCLUDED.logical_job_id,
        source_order = EXCLUDED.source_order,
        ready_at_ms = EXCLUDED.ready_at_ms,
        available_at_ms = EXCLUDED.available_at_ms;

    IF NOT FOUND THEN
        DELETE FROM logical_workflow_instance_result_due
        WHERE attempt_id = target_attempt_id;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION automata_validate_logical_workflow_instance_result_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM attempt_terminal_results AS terminal
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.job_id = job.id AND concrete.initial_attempt_id = attempt.id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = logical_job.run_id
         AND invocation.id = logical_job.invocation_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = concrete.run_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE terminal.attempt_id = NEW.attempt_id
          AND concrete.run_id = NEW.run_id
          AND concrete.invocation_id = NEW.invocation_id
          AND concrete.logical_job_id = NEW.logical_job_id
          AND concrete.instance_id = NEW.instance_id
          AND concrete.job_id = NEW.job_id
          AND materialization.state = 'materialized'
          AND job.run_id = concrete.run_id
          AND job.admission_epoch = 1 AND job.job_ir_schema = 1
          AND job.job_ir_digest = instance.job_ir_digest
          AND job.job_ir_object_key = instance.job_ir_object_key
          AND job.job_ir_size_bytes = instance.job_ir_size_bytes
          AND instance.job_ir_version = 1
          AND instance.job_ir_media_type = 'application/vnd.automata.job-ir.protobuf'
          AND ((terminal.terminal_authority = 'runner' AND terminal.result_schema = 1)
               OR terminal.terminal_authority IN ('server_cancellation', 'server_lease_expiry'))
          AND terminal.completed_at_ms >= 0
          AND terminal.committed_at_ms >= terminal.completed_at_ms
          AND NEW.claimed_at_ms >= terminal.committed_at_ms
          AND ((terminal.conclusion = 'success' AND attempt.lifecycle = 'succeeded')
            OR (terminal.conclusion = 'failure' AND attempt.lifecycle IN ('failed', 'lost'))
            OR (terminal.conclusion = 'cancelled' AND attempt.lifecycle = 'cancelled')
            OR (terminal.conclusion = 'timed_out' AND attempt.lifecycle = 'timed_out')
            OR (terminal.conclusion = 'skipped' AND attempt.lifecycle = 'skipped'))
          AND logical_job.execution_kind = 'steps' AND logical_job.state = 'activated'
          AND invocation.plan_schema = 1 AND invocation.state IN ('pending', 'active')
          AND marker.orchestration_schema = 1 AND marker.state IN ('pending', 'active')
          AND run.admission_epoch = 1 AND run.plan_schema = 1
    ) THEN
        RAISE EXCEPTION 'logical workflow result claim lacks one exact current terminal attempt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION automata_validate_logical_workflow_instance_result() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM logical_workflow_instance_result_claims AS claim
        JOIN attempt_terminal_results AS terminal ON terminal.attempt_id = claim.attempt_id
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN logical_workflow_concrete_jobs AS concrete
          ON concrete.instance_id = claim.instance_id
         AND concrete.job_id = claim.job_id
         AND concrete.initial_attempt_id = claim.attempt_id
        JOIN logical_workflow_instances AS instance ON instance.id = concrete.instance_id
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
          AND terminal.terminal_authority = NEW.terminal_authority
          AND (
              (terminal.terminal_authority = 'runner'
               AND terminal.result_digest = NEW.result_digest
               AND terminal.result_object_key = NEW.result_object_key
               AND terminal.result_size_bytes = NEW.result_size_bytes
               AND terminal.result_schema = NEW.result_schema
               AND NEW.server_cancellation_operation_id IS NULL
               AND NEW.server_cancellation_digest IS NULL
               AND ((attempt.secret_exposure_class = 'secretless'
                     AND NEW.secret_exposure_class = 'secretless')
                 OR (attempt.secret_exposure_class = 'capability_only'
                     AND NEW.secret_exposure_class IN ('secretless', 'capability_only'))
                 OR (attempt.secret_exposure_class = 'readable_secret'
                     AND NEW.secret_exposure_class = 'readable_secret')))
           OR (terminal.terminal_authority = 'server_cancellation'
               AND terminal.server_cancellation_operation_id =
                   NEW.server_cancellation_operation_id
               AND terminal.server_cancellation_digest = NEW.server_cancellation_digest
               AND NEW.result_digest IS NULL AND NEW.result_object_key IS NULL
               AND NEW.result_size_bytes IS NULL AND NEW.result_schema IS NULL
               AND NEW.secret_exposure_class = 'secretless' AND NEW.output_count = 0)
           OR (terminal.terminal_authority = 'server_lease_expiry'
               AND NEW.result_digest IS NULL AND NEW.result_object_key IS NULL
               AND NEW.result_size_bytes IS NULL AND NEW.result_schema IS NULL
               AND NEW.server_cancellation_operation_id IS NULL
               AND NEW.server_cancellation_digest IS NULL
               AND NEW.output_count = 0
               AND ((attempt.secret_exposure_class = 'secretless'
                     AND NEW.secret_exposure_class = 'secretless')
                 OR (attempt.secret_exposure_class = 'capability_only'
                     AND NEW.secret_exposure_class IN ('secretless', 'capability_only'))
                 OR (attempt.secret_exposure_class = 'readable_secret'
                     AND NEW.secret_exposure_class = 'readable_secret')))
          )
          AND terminal.conclusion = NEW.raw_conclusion
          AND terminal.completed_at_ms = NEW.result_completed_at_ms
          AND terminal.committed_at_ms = NEW.result_committed_at_ms
          AND terminal.logical_workflow_logical_job_id = NEW.logical_job_id
          AND terminal.logical_workflow_terminal_ordinal = NEW.terminal_ordinal
          AND job.run_id = NEW.run_id
          AND job.job_ir_digest = NEW.job_ir_digest
          AND job.job_ir_object_key = NEW.job_ir_object_key
          AND job.job_ir_size_bytes = NEW.job_ir_size_bytes
          AND job.job_ir_schema = NEW.job_ir_schema
          AND job.admission_epoch = 1
          AND instance.run_id = NEW.run_id
          AND instance.invocation_id = NEW.invocation_id
          AND instance.logical_job_id = NEW.logical_job_id
          AND instance.job_ir_digest = NEW.job_ir_digest
          AND instance.job_ir_object_key = NEW.job_ir_object_key
          AND instance.job_ir_size_bytes = NEW.job_ir_size_bytes
          AND instance.job_ir_media_type = NEW.job_ir_media_type
          AND instance.job_ir_version = NEW.job_ir_schema
          AND run.admission_epoch = 1 AND run.plan_schema = 1
    ) THEN
        RAISE EXCEPTION 'logical workflow instance result lacks exact terminal authority/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

INSERT INTO attempt_terminal_results (
    attempt_id, terminal_authority, conclusion, completed_at_ms, committed_at_ms
)
SELECT attempt.id, 'server_lease_expiry', 'failure',
       attempt.changed_at_ms, attempt.changed_at_ms
FROM job_attempts AS attempt
WHERE attempt.lifecycle = 'lost'
  AND attempt.lease_failures > 0
  AND NOT EXISTS (
      SELECT 1 FROM attempt_terminal_results AS terminal
      WHERE terminal.attempt_id = attempt.id
  );
