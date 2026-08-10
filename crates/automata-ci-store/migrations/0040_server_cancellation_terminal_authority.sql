-- Current-only terminal authority for a queued attempt cancelled by the
-- server. Runner terminal evidence remains runner/session/lease/blob-bound;
-- this distinct authority never invents a runner or JobResult object.

LOCK TABLE attempt_cancellation_intents, attempt_terminal_results,
    job_attempts, workflow_plan_v2_instance_result_claims,
    workflow_plan_v2_instance_results IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION automata_server_cancellation_terminal_digest(
    target_attempt_id UUID,
    target_operation_id UUID,
    requested_by TEXT,
    reason TEXT,
    requested_at_ms BIGINT
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    convert_to('automata.store.server-cancellation-terminal.v1', 'UTF8')
    || decode('00', 'hex')
    || uuid_send($1)
    || uuid_send($2)
    || int4send(octet_length(convert_to($3, 'UTF8')))
    || convert_to($3, 'UTF8')
    || CASE
        WHEN $4 IS NULL THEN int4send(-1)
        ELSE int4send(octet_length(convert_to($4, 'UTF8')))
             || convert_to($4, 'UTF8')
       END
    || int8send($5)
    || convert_to('cancelled', 'UTF8')
);
$automata$;

ALTER TABLE attempt_cancellation_intents
    ADD CONSTRAINT attempt_cancellation_intents_attempt_operation_unique
        UNIQUE (attempt_id, operation_id);

ALTER TABLE attempt_terminal_results
    ADD COLUMN terminal_authority TEXT NOT NULL DEFAULT 'runner',
    ADD COLUMN server_cancellation_operation_id UUID,
    ADD COLUMN server_cancellation_digest BYTEA;

ALTER TABLE attempt_terminal_results
    ALTER COLUMN terminal_authority DROP DEFAULT,
    ALTER COLUMN runner_session_id DROP NOT NULL,
    ALTER COLUMN operation_id DROP NOT NULL,
    ALTER COLUMN runner_id DROP NOT NULL,
    ALTER COLUMN runner_session_epoch DROP NOT NULL,
    ALTER COLUMN runner_generation DROP NOT NULL,
    ALTER COLUMN runner_slot DROP NOT NULL,
    ALTER COLUMN lease_id DROP NOT NULL,
    ALTER COLUMN fencing_token DROP NOT NULL,
    ALTER COLUMN result_schema DROP NOT NULL,
    ALTER COLUMN result_size_bytes DROP NOT NULL,
    ALTER COLUMN result_digest DROP NOT NULL,
    ALTER COLUMN result_object_key DROP NOT NULL,
    ADD CONSTRAINT attempt_terminal_results_server_cancellation_digest_sha256
        CHECK (
            server_cancellation_digest IS NULL
            OR octet_length(server_cancellation_digest) = 32
        ),
    ADD CONSTRAINT attempt_terminal_results_server_cancellation_intent_fk
        FOREIGN KEY (attempt_id, server_cancellation_operation_id)
        REFERENCES attempt_cancellation_intents (attempt_id, operation_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT attempt_terminal_results_terminal_authority_shape CHECK ((
        (
            terminal_authority = 'runner'
            AND runner_session_id IS NOT NULL
            AND operation_id IS NOT NULL
            AND runner_id IS NOT NULL
            AND runner_session_epoch IS NOT NULL
            AND runner_generation IS NOT NULL
            AND runner_slot IS NOT NULL
            AND lease_id IS NOT NULL
            AND fencing_token IS NOT NULL
            AND result_schema IS NOT NULL
            AND result_size_bytes IS NOT NULL
            AND result_digest IS NOT NULL
            AND result_object_key IS NOT NULL
            AND server_cancellation_operation_id IS NULL
            AND server_cancellation_digest IS NULL
        ) OR (
            terminal_authority = 'server_cancellation'
            AND runner_session_id IS NULL
            AND operation_id IS NULL
            AND runner_id IS NULL
            AND runner_session_epoch IS NULL
            AND runner_generation IS NULL
            AND runner_slot IS NULL
            AND lease_id IS NULL
            AND fencing_token IS NULL
            AND result_schema IS NULL
            AND result_size_bytes IS NULL
            AND result_digest IS NULL
            AND result_object_key IS NULL
            AND server_cancellation_operation_id IS NOT NULL
            AND server_cancellation_operation_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND server_cancellation_digest IS NOT NULL
            AND conclusion = 'cancelled'
        )
    ) IS TRUE);

-- A committed queued cancellation cannot coexist with a still-queued attempt.
-- Such state could only predate this atomic contract and cannot be repaired by
-- guessing which transaction won.
DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM job_attempts AS attempt
        JOIN attempt_cancellation_intents AS cancellation
          ON cancellation.attempt_id = attempt.id
        WHERE attempt.lifecycle = 'queued'
    ) THEN
        RAISE EXCEPTION 'queued cancellation state must be recreated before terminal authority'
            USING ERRCODE = '23514';
    END IF;
END;
$automata$;

-- Backfill only the one shape that proves a queued attempt was cancelled
-- before leasing: no delivery command, no lease/session evidence, fence zero,
-- exact request/change time, and no runner terminal result.
INSERT INTO attempt_terminal_results (
    attempt_id, terminal_authority, server_cancellation_operation_id,
    server_cancellation_digest, conclusion, completed_at_ms, committed_at_ms
)
SELECT attempt.id, 'server_cancellation', cancellation.operation_id,
       automata_server_cancellation_terminal_digest(
           attempt.id, cancellation.operation_id, cancellation.requested_by,
           cancellation.reason, cancellation.requested_at_ms
       ),
       'cancelled', cancellation.requested_at_ms, cancellation.requested_at_ms
FROM job_attempts AS attempt
JOIN attempt_cancellation_intents AS cancellation
  ON cancellation.attempt_id = attempt.id
LEFT JOIN attempt_terminal_results AS terminal
  ON terminal.attempt_id = attempt.id
WHERE terminal.attempt_id IS NULL
  AND attempt.lifecycle = 'cancelled'
  AND attempt.fencing_token = 0
  AND attempt.lease_id IS NULL
  AND attempt.runner_id IS NULL
  AND attempt.runner_session_id IS NULL
  AND attempt.runner_session_epoch IS NULL
  AND attempt.runner_generation IS NULL
  AND attempt.runner_slot IS NULL
  AND attempt.lease_issued_at_ms IS NULL
  AND attempt.lease_expires_at_ms IS NULL
  AND cancellation.delivery_session_id IS NULL
  AND cancellation.delivery_command_sequence IS NULL
  AND cancellation.acknowledged_at_ms IS NULL
  AND cancellation.requested_at_ms = attempt.changed_at_ms;

-- A logical cancellation without either exact runner evidence or the provable
-- queued shape above is ambiguous. Current-only state must be recreated rather
-- than silently manufacturing an authority.
DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_concrete_jobs AS concrete
        JOIN job_attempts AS attempt
          ON attempt.id = concrete.initial_attempt_id
        LEFT JOIN attempt_terminal_results AS terminal
          ON terminal.attempt_id = attempt.id
        WHERE attempt.lifecycle = 'cancelled'
          AND terminal.attempt_id IS NULL
    ) THEN
        RAISE EXCEPTION 'unmatched logical cancellation must be recreated'
            USING ERRCODE = '23514';
    END IF;
END;
$automata$;

CREATE FUNCTION automata_validate_server_cancellation_terminal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    cancellation attempt_cancellation_intents%ROWTYPE;
    attempt job_attempts%ROWTYPE;
    expected_digest BYTEA;
BEGIN
    IF NEW.terminal_authority IS DISTINCT FROM 'server_cancellation' THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT cancellation
    FROM attempt_cancellation_intents
    WHERE attempt_id = NEW.attempt_id
      AND operation_id = NEW.server_cancellation_operation_id;

    SELECT * INTO STRICT attempt
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    expected_digest := automata_server_cancellation_terminal_digest(
        cancellation.attempt_id,
        cancellation.operation_id,
        cancellation.requested_by,
        cancellation.reason,
        cancellation.requested_at_ms
    );
    IF cancellation.delivery_session_id IS NOT NULL
       OR cancellation.delivery_command_sequence IS NOT NULL
       OR cancellation.acknowledged_at_ms IS NOT NULL
       OR attempt.lifecycle <> 'queued'
       OR attempt.fencing_token <> 0
       OR attempt.lease_id IS NOT NULL
       OR attempt.runner_id IS NOT NULL
       OR attempt.runner_session_id IS NOT NULL
       OR attempt.runner_session_epoch IS NOT NULL
       OR attempt.runner_generation IS NOT NULL
       OR attempt.runner_slot IS NOT NULL
       OR attempt.lease_issued_at_ms IS NOT NULL
       OR attempt.lease_expires_at_ms IS NOT NULL
       OR NEW.server_cancellation_digest IS DISTINCT FROM expected_digest
       OR NEW.conclusion <> 'cancelled'
       OR NEW.completed_at_ms <> cancellation.requested_at_ms
       OR NEW.committed_at_ms <> cancellation.requested_at_ms
    THEN
        RAISE EXCEPTION 'server cancellation terminal lacks exact queued intent authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
        RAISE EXCEPTION 'server cancellation terminal lacks exact queued intent authority'
            USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER attempt_terminal_results_validate_server_cancellation
BEFORE INSERT OR UPDATE ON attempt_terminal_results
FOR EACH ROW
EXECUTE FUNCTION automata_validate_server_cancellation_terminal();

CREATE FUNCTION automata_protect_server_cancellation_intent()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM attempt_terminal_results AS terminal
        WHERE terminal.attempt_id = OLD.attempt_id
          AND terminal.terminal_authority = 'server_cancellation'
    ) AND ROW(
        NEW.attempt_id, NEW.operation_id, NEW.requested_by, NEW.reason,
        NEW.requested_at_ms, NEW.delivery_session_id,
        NEW.delivery_command_sequence, NEW.acknowledged_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.attempt_id, OLD.operation_id, OLD.requested_by, OLD.reason,
        OLD.requested_at_ms, OLD.delivery_session_id,
        OLD.delivery_command_sequence, OLD.acknowledged_at_ms
    ) THEN
        RAISE EXCEPTION 'server cancellation intent authority is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER attempt_cancellation_intents_protect_server_terminal
BEFORE UPDATE ON attempt_cancellation_intents
FOR EACH ROW
EXECUTE FUNCTION automata_protect_server_cancellation_intent();

CREATE OR REPLACE FUNCTION automata_protect_attempt_terminal_result_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF ROW(
        NEW.attempt_id, NEW.terminal_authority,
        NEW.runner_session_id, NEW.operation_id,
        NEW.runner_id, NEW.runner_session_epoch, NEW.runner_generation,
        NEW.runner_slot, NEW.lease_id, NEW.fencing_token, NEW.result_schema,
        NEW.result_size_bytes, NEW.result_digest, NEW.result_object_key,
        NEW.server_cancellation_operation_id, NEW.server_cancellation_digest,
        NEW.conclusion, NEW.completed_at_ms, NEW.committed_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.attempt_id, OLD.terminal_authority,
        OLD.runner_session_id, OLD.operation_id,
        OLD.runner_id, OLD.runner_session_epoch, OLD.runner_generation,
        OLD.runner_slot, OLD.lease_id, OLD.fencing_token, OLD.result_schema,
        OLD.result_size_bytes, OLD.result_digest, OLD.result_object_key,
        OLD.server_cancellation_operation_id, OLD.server_cancellation_digest,
        OLD.conclusion, OLD.completed_at_ms, OLD.committed_at_ms
    ) THEN
        RAISE EXCEPTION 'attempt terminal result evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

ALTER TABLE workflow_plan_v2_instance_results
    ADD COLUMN terminal_authority TEXT NOT NULL DEFAULT 'runner',
    ADD COLUMN server_cancellation_operation_id UUID,
    ADD COLUMN server_cancellation_digest BYTEA;

ALTER TABLE workflow_plan_v2_instance_results
    ALTER COLUMN terminal_authority DROP DEFAULT,
    ALTER COLUMN result_digest DROP NOT NULL,
    ALTER COLUMN result_object_key DROP NOT NULL,
    ALTER COLUMN result_size_bytes DROP NOT NULL,
    ALTER COLUMN result_media_type DROP NOT NULL,
    ALTER COLUMN result_schema DROP NOT NULL,
    DROP CONSTRAINT workflow_plan_v2_instance_results_digests_sha256,
    DROP CONSTRAINT workflow_plan_v2_instance_results_result_key_shape,
    DROP CONSTRAINT workflow_plan_v2_instance_results_result_current,
    ADD CONSTRAINT workflow_plan_v2_instance_results_common_digests_sha256 CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(job_ir_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(commit_digest) = 32
    ),
    ADD CONSTRAINT workflow_plan_v2_instance_results_server_digest_sha256 CHECK (
        server_cancellation_digest IS NULL
        OR octet_length(server_cancellation_digest) = 32
    ),
    ADD CONSTRAINT workflow_plan_v2_instance_results_server_intent_fk
        FOREIGN KEY (attempt_id, server_cancellation_operation_id)
        REFERENCES attempt_cancellation_intents (attempt_id, operation_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT workflow_plan_v2_instance_results_terminal_authority_shape CHECK ((
        (
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
            AND result_digest IS NULL
            AND result_object_key IS NULL
            AND result_size_bytes IS NULL
            AND result_media_type IS NULL
            AND result_schema IS NULL
            AND server_cancellation_operation_id IS NOT NULL
            AND server_cancellation_digest IS NOT NULL
            AND raw_conclusion = 'cancelled'
            AND effective_conclusion = 'cancelled'
            AND secret_exposure_class = 'secretless'
            AND output_count = 0
        )
    ) IS TRUE);

CREATE OR REPLACE FUNCTION automata_validate_workflow_plan_v2_instance_result_claim()
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
          AND (
              (terminal.terminal_authority = 'runner'
               AND terminal.result_schema = 1)
              OR terminal.terminal_authority = 'server_cancellation'
          )
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
          AND terminal.terminal_authority = NEW.terminal_authority
          AND (
              (
                  terminal.terminal_authority = 'runner'
                  AND terminal.result_digest = NEW.result_digest
                  AND terminal.result_object_key = NEW.result_object_key
                  AND terminal.result_size_bytes = NEW.result_size_bytes
                  AND terminal.result_schema = NEW.result_schema
                  AND NEW.server_cancellation_operation_id IS NULL
                  AND NEW.server_cancellation_digest IS NULL
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
              ) OR (
                  terminal.terminal_authority = 'server_cancellation'
                  AND terminal.server_cancellation_operation_id =
                      NEW.server_cancellation_operation_id
                  AND terminal.server_cancellation_digest =
                      NEW.server_cancellation_digest
                  AND NEW.result_digest IS NULL
                  AND NEW.result_object_key IS NULL
                  AND NEW.result_size_bytes IS NULL
                  AND NEW.result_schema IS NULL
                  AND NEW.secret_exposure_class = 'secretless'
                  AND NEW.output_count = 0
              )
          )
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
        RAISE EXCEPTION 'WorkflowPlan-v2 instance result lacks exact terminal authority/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_refresh_workflow_plan_v2_instance_result_due(
    target_attempt_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $automata$
BEGIN
    INSERT INTO workflow_plan_v2_instance_result_due (
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
    JOIN repositories AS repository ON repository.id = run.repository_id
    LEFT JOIN workflow_plan_v2_instance_result_claims AS claim
      ON claim.attempt_id = terminal.attempt_id
    WHERE terminal.attempt_id = target_attempt_id
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
      AND (
          (terminal.terminal_authority = 'runner'
           AND terminal.result_schema = 1)
          OR terminal.terminal_authority = 'server_cancellation'
      )
      AND terminal.workflow_plan_v2_logical_job_id = concrete.logical_job_id
      AND terminal.workflow_plan_v2_terminal_ordinal > 0
      AND terminal.completed_at_ms >= 0
      AND terminal.committed_at_ms >= terminal.completed_at_ms
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
      AND (claim.attempt_id IS NULL OR claim.state = 'projecting')
    ON CONFLICT (attempt_id) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        run_id = EXCLUDED.run_id,
        invocation_id = EXCLUDED.invocation_id,
        logical_job_id = EXCLUDED.logical_job_id,
        source_order = EXCLUDED.source_order,
        ready_at_ms = EXCLUDED.ready_at_ms,
        available_at_ms = EXCLUDED.available_at_ms;

    IF NOT FOUND THEN
        DELETE FROM workflow_plan_v2_instance_result_due
        WHERE attempt_id = target_attempt_id;
    END IF;
END;
$automata$;
