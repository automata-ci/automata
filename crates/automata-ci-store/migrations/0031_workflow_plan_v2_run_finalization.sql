-- Current-only WorkflowPlan-v2 run finalization. A bounded global worker may
-- claim only a non-empty exact root invocation after every logical job has an
-- immutable 0025 result. The aggregate evidence and conclusion are immutable;
-- invocation, orchestration marker, and workflow-run status close atomically.

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        WHERE marker.state IN ('completed', 'cancelled', 'failed')
           OR invocation.state IN ('completed', 'cancelled', 'failed')
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal runs must be recreated with aggregate evidence'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_run_results_current_only';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        WHERE NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_jobs AS job
            WHERE job.run_id = marker.run_id
              AND job.invocation_id = marker.root_invocation_id
        )
    ) THEN
        RAISE EXCEPTION 'current WorkflowPlan-v2 admission cannot contain zero jobs'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_run_results_nonempty_current_run';
    END IF;
END;
$automata$;

CREATE TABLE workflow_plan_v2_run_result_claims (
    run_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_runs(run_id) ON DELETE RESTRICT,
    root_invocation_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    state TEXT NOT NULL,
    owner_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_run_result_claims_target_unique
        UNIQUE (run_id, root_invocation_id),
    CONSTRAINT workflow_plan_v2_run_result_claims_target_fk
        FOREIGN KEY (run_id, root_invocation_id)
        REFERENCES workflow_plan_v2_invocations(run_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_run_result_claims_non_nil CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_run_result_claims_digest CHECK (
        octet_length(descriptor_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_run_result_claims_state CHECK (
        state IN ('aggregating', 'finalized')
    ),
    CONSTRAINT workflow_plan_v2_run_result_claims_generation CHECK (
        generation > 0
    ),
    CONSTRAINT workflow_plan_v2_run_result_claims_interval CHECK (
        claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND expires_at_ms - claimed_at_ms <= 900000
        AND created_at_ms <= claimed_at_ms
        AND updated_at_ms >= claimed_at_ms
    )
);

CREATE INDEX workflow_plan_v2_run_result_claims_expired
    ON workflow_plan_v2_run_result_claims (expires_at_ms, run_id)
    WHERE state = 'aggregating';

CREATE TABLE workflow_plan_v2_run_results (
    run_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_run_result_claims(run_id) ON DELETE RESTRICT,
    root_invocation_id UUID NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    admission_digest BYTEA NOT NULL,
    marker_state TEXT NOT NULL,
    marker_revision BIGINT NOT NULL,
    marker_updated_at_ms BIGINT NOT NULL,
    invocation_state TEXT NOT NULL,
    invocation_revision BIGINT NOT NULL,
    invocation_updated_at_ms BIGINT NOT NULL,
    workflow_status TEXT NOT NULL,
    workflow_updated_at_ms BIGINT NOT NULL,
    job_count INTEGER NOT NULL,
    evidence_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    commit_digest BYTEA NOT NULL,
    claim_owner_id UUID NOT NULL,
    claim_generation BIGINT NOT NULL,
    claim_started_at_ms BIGINT NOT NULL,
    claim_expires_at_ms BIGINT NOT NULL,
    finalized_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_run_results_target_unique
        UNIQUE (run_id, root_invocation_id),
    CONSTRAINT workflow_plan_v2_run_results_target_fk
        FOREIGN KEY (run_id, root_invocation_id)
        REFERENCES workflow_plan_v2_run_result_claims(run_id, root_invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_run_results_non_nil CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND root_invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_run_results_digest_shape CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(admission_digest) = 32
        AND octet_length(evidence_digest) = 32
        AND octet_length(commit_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_run_results_open_shape CHECK (
        marker_state IN ('pending', 'active')
        AND invocation_state IN ('pending', 'active')
        AND workflow_status IN ('queued', 'in_progress', 'cancelled')
        AND marker_revision > 0
        AND marker_revision < 9223372036854775807
        AND invocation_revision > 0
        AND invocation_revision < 9223372036854775807
        AND marker_updated_at_ms >= 0
        AND invocation_updated_at_ms >= 0
        AND workflow_updated_at_ms >= 0
    ),
    CONSTRAINT workflow_plan_v2_run_results_job_count CHECK (
        job_count BETWEEN 1 AND 1024
    ),
    CONSTRAINT workflow_plan_v2_run_results_conclusion CHECK (
        effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
    ),
    CONSTRAINT workflow_plan_v2_run_results_claim_shape CHECK (
        claim_generation > 0
        AND claim_started_at_ms >= 0
        AND claim_expires_at_ms > claim_started_at_ms
        AND claim_expires_at_ms - claim_started_at_ms <= 900000
        AND finalized_at_ms >= claim_started_at_ms
        AND finalized_at_ms < claim_expires_at_ms
    )
);

CREATE TABLE workflow_plan_v2_run_result_jobs (
    run_id UUID NOT NULL,
    root_invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    logical_key TEXT COLLATE "C" NOT NULL,
    source_order INTEGER NOT NULL,
    descriptor_digest BYTEA NOT NULL,
    effective_conclusion TEXT NOT NULL,
    closure_has_failure BOOLEAN NOT NULL,
    closure_has_cancelled BOOLEAN NOT NULL,
    closure_has_skipped BOOLEAN NOT NULL,
    instance_count INTEGER NOT NULL,
    instances_digest BYTEA NOT NULL,
    prerequisite_count INTEGER NOT NULL,
    prerequisites_digest BYTEA NOT NULL,
    output_count INTEGER NOT NULL,
    outputs_digest BYTEA NOT NULL,
    job_commit_digest BYTEA NOT NULL,
    job_finalized_at_ms BIGINT NOT NULL,
    PRIMARY KEY (run_id, logical_job_id),
    UNIQUE (run_id, source_order),
    UNIQUE (run_id, logical_key),
    CONSTRAINT workflow_plan_v2_run_result_jobs_result_fk
        FOREIGN KEY (run_id, root_invocation_id)
        REFERENCES workflow_plan_v2_run_results(run_id, root_invocation_id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_run_result_jobs_logical_job_fk
        FOREIGN KEY (run_id, root_invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_run_result_jobs_non_nil CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workflow_plan_v2_run_result_jobs_key_shape CHECK (
        octet_length(logical_key) BETWEEN 1 AND 256
        AND btrim(logical_key) = logical_key
        AND logical_key !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
    ),
    CONSTRAINT workflow_plan_v2_run_result_jobs_digest_shape CHECK (
        octet_length(descriptor_digest) = 32
        AND octet_length(instances_digest) = 32
        AND octet_length(prerequisites_digest) = 32
        AND octet_length(outputs_digest) = 32
        AND octet_length(job_commit_digest) = 32
    ),
    CONSTRAINT workflow_plan_v2_run_result_jobs_conclusion CHECK (
        effective_conclusion IN (
            'success', 'failure', 'cancelled', 'timed_out', 'skipped'
        )
        AND (
            effective_conclusion NOT IN ('failure', 'timed_out')
            OR closure_has_failure
        )
        AND (effective_conclusion <> 'cancelled' OR closure_has_cancelled)
        AND (effective_conclusion <> 'skipped' OR closure_has_skipped)
    ),
    CONSTRAINT workflow_plan_v2_run_result_jobs_counts CHECK (
        instance_count BETWEEN 0 AND 256
        AND prerequisite_count BETWEEN 0 AND 128
        AND output_count BETWEEN 0 AND 256
        AND job_finalized_at_ms >= 0
    )
);

-- Admission already rejects empty logical plans. Preserve that current-only
-- fact as a deferred database invariant without breaking the aggregate insert
-- order (marker, invocation, then jobs) in one admission transaction.
CREATE FUNCTION automata_require_workflow_plan_v2_nonempty_root()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    target_run UUID;
BEGIN
    target_run := CASE WHEN TG_OP = 'DELETE' THEN OLD.run_id ELSE NEW.run_id END;
    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        WHERE marker.run_id = target_run
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_jobs AS job
              WHERE job.run_id = marker.run_id
                AND job.invocation_id = marker.root_invocation_id
          )
    ) THEN
        RAISE EXCEPTION 'current WorkflowPlan-v2 admission requires at least one job'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_plan_v2_run_results_nonempty_current_run';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE CONSTRAINT TRIGGER workflow_plan_v2_runs_require_nonempty_root
AFTER INSERT OR UPDATE ON workflow_plan_v2_runs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_workflow_plan_v2_nonempty_root();

CREATE CONSTRAINT TRIGGER workflow_plan_v2_jobs_preserve_nonempty_root
AFTER DELETE ON workflow_plan_v2_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_require_workflow_plan_v2_nonempty_root();

-- Once a run-result claim exists, the exact source-level job graph is frozen.
-- Locking the marker in shared mode serializes this check with the worker's
-- exclusive SKIP-LOCKED marker claim.
CREATE FUNCTION automata_freeze_workflow_plan_v2_run_graph()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    target_run UUID;
BEGIN
    target_run := CASE WHEN TG_OP = 'DELETE' THEN OLD.run_id ELSE NEW.run_id END;

    PERFORM 1
    FROM workflow_plan_v2_runs AS marker
    WHERE marker.run_id = target_run
    FOR SHARE;

    IF FOUND AND EXISTS (
        SELECT 1
        FROM workflow_plan_v2_run_result_claims AS claim
        WHERE claim.run_id = target_run
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run graph is frozen by result aggregation'
            USING ERRCODE = '23514';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();

CREATE TRIGGER workflow_plan_v2_dependencies_freeze_for_run_result
BEFORE INSERT OR DELETE ON workflow_plan_v2_dependencies
FOR EACH ROW
EXECUTE FUNCTION automata_freeze_workflow_plan_v2_run_graph();

CREATE FUNCTION automata_validate_workflow_plan_v2_run_result_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state <> 'aggregating' THEN
        RETURN NEW;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_runs AS marker
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE marker.run_id = NEW.run_id
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.orchestration_schema = 1
          AND marker.state IN ('pending', 'active')
          AND marker.revision < 9223372036854775807
          AND invocation.plan_schema = 2
          AND invocation.state IN ('pending', 'active')
          AND invocation.revision < 9223372036854775807
          AND run.admission_epoch = 4
          AND run.plan_schema = 2
          AND run.status IN ('queued', 'in_progress', 'cancelled')
          AND NEW.claimed_at_ms >= greatest(
              marker.updated_at_ms,
              invocation.updated_at_ms,
              run.updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM workflow_plan_v2_job_results AS result
                  WHERE result.run_id = marker.run_id
                    AND result.invocation_id = marker.root_invocation_id
              ), 0)
          )
          AND (SELECT count(*)
               FROM workflow_plan_v2_jobs AS job
               WHERE job.run_id = marker.run_id
                 AND job.invocation_id = marker.root_invocation_id)
              BETWEEN 1 AND 1024
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_plan_v2_jobs AS job
              LEFT JOIN workflow_plan_v2_job_results AS result
                ON result.run_id = job.run_id
               AND result.invocation_id = job.invocation_id
               AND result.logical_job_id = job.id
              LEFT JOIN workflow_plan_v2_job_result_claims AS result_claim
                ON result_claim.logical_job_id = result.logical_job_id
              WHERE job.run_id = marker.run_id
                AND job.invocation_id = marker.root_invocation_id
                AND (
                    result.logical_job_id IS NULL
                    OR result_claim.state IS DISTINCT FROM 'finalized'
                    OR result.logical_key IS DISTINCT FROM job.logical_key
                    OR result.source_order IS DISTINCT FROM job.source_order
                    OR job.state IS DISTINCT FROM CASE result.effective_conclusion
                        WHEN 'success' THEN 'completed'
                        WHEN 'failure' THEN 'failed'
                        WHEN 'timed_out' THEN 'failed'
                        WHEN 'cancelled' THEN 'cancelled'
                        WHEN 'skipped' THEN 'skipped'
                    END
                    OR result.prerequisite_count IS DISTINCT FROM (
                        SELECT count(*)::INTEGER
                        FROM workflow_plan_v2_dependencies AS dependency
                        WHERE dependency.run_id = job.run_id
                          AND dependency.invocation_id = job.invocation_id
                          AND dependency.logical_job_id = job.id
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM (
                  SELECT job.source_order,
                         row_number() OVER (ORDER BY job.source_order) - 1 AS expected_order
                  FROM workflow_plan_v2_jobs AS job
                  WHERE job.run_id = marker.run_id
                    AND job.invocation_id = marker.root_invocation_id
              ) AS ordered
              WHERE ordered.source_order <> ordered.expected_order
          )
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim is not exactly ready'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_run_result_claims_validate
BEFORE INSERT OR UPDATE ON workflow_plan_v2_run_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_run_result_claim();

CREATE FUNCTION automata_enforce_workflow_plan_v2_run_result_claim_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.root_invocation_id IS DISTINCT FROM OLD.root_invocation_id
        OR NEW.descriptor_digest IS DISTINCT FROM OLD.descriptor_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim identity is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.state = 'aggregating' AND NEW.state = 'aggregating' THEN
        IF NEW.generation <> OLD.generation + 1
            OR NEW.claimed_at_ms < OLD.expires_at_ms
            OR NEW.expires_at_ms <= NEW.claimed_at_ms
            OR NEW.expires_at_ms - NEW.claimed_at_ms > 900000
            OR NEW.updated_at_ms <> NEW.claimed_at_ms
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 run-result takeover is not fenced'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state = 'aggregating' AND NEW.state = 'finalized' THEN
        IF NEW.owner_id IS DISTINCT FROM OLD.owner_id
            OR NEW.generation IS DISTINCT FROM OLD.generation
            OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
            OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
            OR NOT EXISTS (
                SELECT 1
                FROM workflow_plan_v2_run_results AS result
                JOIN workflow_plan_v2_invocations AS invocation
                  ON invocation.run_id = result.run_id
                 AND invocation.id = result.root_invocation_id
                JOIN workflow_plan_v2_runs AS marker ON marker.run_id = result.run_id
                JOIN workflow_runs AS run ON run.id = result.run_id
                WHERE result.run_id = NEW.run_id
                  AND result.root_invocation_id = NEW.root_invocation_id
                  AND result.descriptor_digest = NEW.descriptor_digest
                  AND result.claim_owner_id = OLD.owner_id
                  AND result.claim_generation = OLD.generation
                  AND result.claim_started_at_ms = OLD.claimed_at_ms
                  AND result.claim_expires_at_ms = OLD.expires_at_ms
                  AND result.finalized_at_ms = NEW.updated_at_ms
                  AND result.job_count = (
                      SELECT count(*)::INTEGER
                      FROM workflow_plan_v2_run_result_jobs AS evidence
                      WHERE evidence.run_id = result.run_id
                  )
                  AND result.job_count = (
                      SELECT count(*)::INTEGER
                      FROM workflow_plan_v2_jobs AS job
                      WHERE job.run_id = result.run_id
                        AND job.invocation_id = result.root_invocation_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM workflow_plan_v2_jobs AS job
                      LEFT JOIN workflow_plan_v2_run_result_jobs AS evidence
                        ON evidence.run_id = job.run_id
                       AND evidence.root_invocation_id = job.invocation_id
                       AND evidence.logical_job_id = job.id
                      LEFT JOIN workflow_plan_v2_job_results AS logical_result
                        ON logical_result.run_id = job.run_id
                       AND logical_result.invocation_id = job.invocation_id
                       AND logical_result.logical_job_id = job.id
                      WHERE job.run_id = result.run_id
                        AND job.invocation_id = result.root_invocation_id
                        AND (
                            evidence.logical_job_id IS NULL
                            OR logical_result.logical_job_id IS NULL
                            OR evidence.logical_key IS DISTINCT FROM job.logical_key
                            OR evidence.source_order IS DISTINCT FROM job.source_order
                            OR evidence.descriptor_digest IS DISTINCT FROM logical_result.descriptor_digest
                            OR evidence.effective_conclusion IS DISTINCT FROM logical_result.effective_conclusion
                            OR evidence.closure_has_failure IS DISTINCT FROM logical_result.closure_has_failure
                            OR evidence.closure_has_cancelled IS DISTINCT FROM logical_result.closure_has_cancelled
                            OR evidence.closure_has_skipped IS DISTINCT FROM logical_result.closure_has_skipped
                            OR evidence.instance_count IS DISTINCT FROM logical_result.instance_count
                            OR evidence.instances_digest IS DISTINCT FROM logical_result.instances_digest
                            OR evidence.prerequisite_count IS DISTINCT FROM logical_result.prerequisite_count
                            OR evidence.prerequisites_digest IS DISTINCT FROM logical_result.prerequisites_digest
                            OR evidence.output_count IS DISTINCT FROM logical_result.output_count
                            OR evidence.outputs_digest IS DISTINCT FROM logical_result.outputs_digest
                            OR evidence.job_commit_digest IS DISTINCT FROM logical_result.commit_digest
                            OR evidence.job_finalized_at_ms IS DISTINCT FROM logical_result.finalized_at_ms
                        )
                  )
                  AND result.effective_conclusion = CASE
                      WHEN result.workflow_status = 'cancelled' THEN 'cancelled'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'failure'
                      ) THEN 'failure'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'timed_out'
                      ) THEN 'timed_out'
                      WHEN EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion = 'cancelled'
                      ) THEN 'cancelled'
                      WHEN NOT EXISTS (
                          SELECT 1 FROM workflow_plan_v2_run_result_jobs AS evidence
                          WHERE evidence.run_id = result.run_id
                            AND evidence.effective_conclusion <> 'skipped'
                      ) THEN 'skipped'
                      ELSE 'success'
                  END
                  AND invocation.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'skipped' THEN 'completed'
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'failed'
                  END
                  AND invocation.revision = result.invocation_revision + 1
                  AND invocation.updated_at_ms = result.finalized_at_ms
                  AND marker.state = CASE result.effective_conclusion
                      WHEN 'success' THEN 'completed'
                      WHEN 'skipped' THEN 'completed'
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'failed'
                  END
                  AND marker.revision = result.marker_revision + 1
                  AND marker.updated_at_ms = result.finalized_at_ms
                  AND run.status = CASE result.effective_conclusion
                      WHEN 'cancelled' THEN 'cancelled'
                      ELSE 'completed'
                  END
                  AND run.updated_at_ms = result.finalized_at_ms
            )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 run-result finalization lacks exact evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'WorkflowPlan-v2 run-result claim transition is invalid'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_run_result_claims_enforce_transition
BEFORE UPDATE ON workflow_plan_v2_run_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_run_result_claim_transition();

CREATE FUNCTION automata_validate_workflow_plan_v2_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_run_result_claims AS claim
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = claim.run_id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS run ON run.id = marker.run_id
        WHERE claim.run_id = NEW.run_id
          AND claim.root_invocation_id = NEW.root_invocation_id
          AND claim.descriptor_digest = NEW.descriptor_digest
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_started_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.admission_digest = NEW.admission_digest
          AND marker.state = NEW.marker_state
          AND marker.revision = NEW.marker_revision
          AND marker.updated_at_ms = NEW.marker_updated_at_ms
          AND invocation.state = NEW.invocation_state
          AND invocation.revision = NEW.invocation_revision
          AND invocation.updated_at_ms = NEW.invocation_updated_at_ms
          AND run.status = NEW.workflow_status
          AND run.updated_at_ms = NEW.workflow_updated_at_ms
          AND NEW.job_count = (
              SELECT count(*)::INTEGER
              FROM workflow_plan_v2_jobs AS job
              WHERE job.run_id = NEW.run_id
                AND job.invocation_id = NEW.root_invocation_id
          )
          AND NEW.finalized_at_ms >= greatest(
              NEW.marker_updated_at_ms,
              NEW.invocation_updated_at_ms,
              NEW.workflow_updated_at_ms,
              COALESCE((
                  SELECT max(result.finalized_at_ms)
                  FROM workflow_plan_v2_job_results AS result
                  WHERE result.run_id = NEW.run_id
                    AND result.invocation_id = NEW.root_invocation_id
              ), 0)
          )
          AND NEW.finalized_at_ms < claim.expires_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run result lacks exact descriptor/fence evidence'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_run_results_validate
BEFORE INSERT ON workflow_plan_v2_run_results
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_run_result();

CREATE FUNCTION automata_validate_workflow_plan_v2_run_result_job()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_run_results AS run_result
        JOIN workflow_plan_v2_run_result_claims AS run_claim
          ON run_claim.run_id = run_result.run_id
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = run_result.run_id
         AND job.invocation_id = run_result.root_invocation_id
         AND job.id = NEW.logical_job_id
        JOIN workflow_plan_v2_job_results AS logical_result
          ON logical_result.run_id = job.run_id
         AND logical_result.invocation_id = job.invocation_id
         AND logical_result.logical_job_id = job.id
        JOIN workflow_plan_v2_job_result_claims AS logical_claim
          ON logical_claim.logical_job_id = logical_result.logical_job_id
        WHERE run_result.run_id = NEW.run_id
          AND run_result.root_invocation_id = NEW.root_invocation_id
          AND run_claim.state = 'aggregating'
          AND job.logical_key = NEW.logical_key
          AND job.source_order = NEW.source_order
          AND logical_claim.state = 'finalized'
          AND logical_result.descriptor_digest = NEW.descriptor_digest
          AND logical_result.effective_conclusion = NEW.effective_conclusion
          AND logical_result.closure_has_failure = NEW.closure_has_failure
          AND logical_result.closure_has_cancelled = NEW.closure_has_cancelled
          AND logical_result.closure_has_skipped = NEW.closure_has_skipped
          AND logical_result.instance_count = NEW.instance_count
          AND logical_result.instances_digest = NEW.instances_digest
          AND logical_result.prerequisite_count = NEW.prerequisite_count
          AND logical_result.prerequisites_digest = NEW.prerequisites_digest
          AND logical_result.output_count = NEW.output_count
          AND logical_result.outputs_digest = NEW.outputs_digest
          AND logical_result.commit_digest = NEW.job_commit_digest
          AND logical_result.finalized_at_ms = NEW.job_finalized_at_ms
    ) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 run-result job evidence is not exact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_run_result_jobs_validate
BEFORE INSERT ON workflow_plan_v2_run_result_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_run_result_job();

-- A terminal invocation/marker transition is valid only beside the aggregate
-- row inserted earlier in the same finalization transaction.
CREATE FUNCTION automata_guard_workflow_plan_v2_invocation_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state IN ('completed', 'cancelled', 'failed') THEN
        IF OLD.state NOT IN ('pending', 'active')
           OR NEW.revision <> OLD.revision + 1
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NOT EXISTS (
               SELECT 1
               FROM workflow_plan_v2_run_results AS result
               JOIN workflow_plan_v2_run_result_claims AS claim
                 ON claim.run_id = result.run_id
               WHERE result.run_id = NEW.run_id
                 AND result.root_invocation_id = NEW.id
                 AND claim.state = 'aggregating'
                 AND result.invocation_state = OLD.state
                 AND result.invocation_revision = OLD.revision
                 AND result.invocation_updated_at_ms = OLD.updated_at_ms
                 AND result.finalized_at_ms = NEW.updated_at_ms
                 AND NEW.state = CASE result.effective_conclusion
                     WHEN 'success' THEN 'completed'
                     WHEN 'skipped' THEN 'completed'
                     WHEN 'cancelled' THEN 'cancelled'
                     ELSE 'failed'
                 END
           )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 invocation terminal transition lacks run result'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state IN ('completed', 'cancelled', 'failed')
          AND (NEW.state IS DISTINCT FROM OLD.state
               OR NEW.revision IS DISTINCT FROM OLD.revision
               OR NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal invocation is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_invocations_guard_run_result
BEFORE UPDATE ON workflow_plan_v2_invocations
FOR EACH ROW
EXECUTE FUNCTION automata_guard_workflow_plan_v2_invocation_run_result();

CREATE FUNCTION automata_guard_workflow_plan_v2_marker_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state IN ('completed', 'cancelled', 'failed') THEN
        IF OLD.state NOT IN ('pending', 'active')
           OR NEW.revision <> OLD.revision + 1
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NOT EXISTS (
               SELECT 1
               FROM workflow_plan_v2_run_results AS result
               JOIN workflow_plan_v2_run_result_claims AS claim
                 ON claim.run_id = result.run_id
               WHERE result.run_id = NEW.run_id
                 AND claim.state = 'aggregating'
                 AND result.marker_state = OLD.state
                 AND result.marker_revision = OLD.revision
                 AND result.marker_updated_at_ms = OLD.updated_at_ms
                 AND result.finalized_at_ms = NEW.updated_at_ms
                 AND NEW.state = CASE result.effective_conclusion
                     WHEN 'success' THEN 'completed'
                     WHEN 'skipped' THEN 'completed'
                     WHEN 'cancelled' THEN 'cancelled'
                     ELSE 'failed'
                 END
           )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 marker terminal transition lacks run result'
                USING ERRCODE = '23514';
        END IF;
    ELSIF OLD.state IN ('completed', 'cancelled', 'failed')
          AND (NEW.state IS DISTINCT FROM OLD.state
               OR NEW.revision IS DISTINCT FROM OLD.revision
               OR NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms) THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 terminal marker is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runs_guard_run_result
BEFORE UPDATE ON workflow_plan_v2_runs
FOR EACH ROW
EXECUTE FUNCTION automata_guard_workflow_plan_v2_marker_run_result();

CREATE FUNCTION automata_guard_workflow_run_plan_v2_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF (NEW.status IS DISTINCT FROM OLD.status
        OR (OLD.status = 'cancelled'
            AND NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms))
       AND EXISTS (
           SELECT 1 FROM workflow_plan_v2_runs AS marker
           WHERE marker.run_id = OLD.id
       )
       AND (
           NEW.status = 'completed'
           OR (OLD.status = 'cancelled'
               AND NEW.status = 'cancelled'
               AND NEW.updated_at_ms IS DISTINCT FROM OLD.updated_at_ms)
           OR EXISTS (
               SELECT 1
               FROM workflow_plan_v2_run_result_claims AS claim
               WHERE claim.run_id = OLD.id AND claim.state = 'aggregating'
           )
       )
    THEN
        IF OLD.status NOT IN ('queued', 'in_progress', 'cancelled')
           OR NEW.updated_at_ms < OLD.updated_at_ms
           OR NOT EXISTS (
               SELECT 1
               FROM workflow_plan_v2_run_results AS result
               JOIN workflow_plan_v2_run_result_claims AS claim
                 ON claim.run_id = result.run_id
               WHERE result.run_id = OLD.id
                 AND claim.state = 'aggregating'
                 AND result.workflow_status = OLD.status
                 AND result.workflow_updated_at_ms = OLD.updated_at_ms
                 AND result.finalized_at_ms = NEW.updated_at_ms
                 AND NEW.status = CASE result.effective_conclusion
                     WHEN 'cancelled' THEN 'cancelled'
                     ELSE 'completed'
                 END
           )
        THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 workflow status transition lacks run result'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_guard_plan_v2_result
BEFORE UPDATE ON workflow_runs
FOR EACH ROW
EXECUTE FUNCTION automata_guard_workflow_run_plan_v2_result();

CREATE FUNCTION automata_reject_workflow_plan_v2_run_result_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 run-result evidence is immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_run_results_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_run_results
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_run_result_mutation();

CREATE TRIGGER workflow_plan_v2_run_result_jobs_reject_mutation
BEFORE UPDATE OR DELETE ON workflow_plan_v2_run_result_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_run_result_mutation();
