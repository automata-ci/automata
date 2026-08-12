-- Advance runner requirements independently from JobIR. Existing schema-v2
-- rows are immutable terminal history, so they cannot be rewritten without
-- invalidating their materialization digests. Drain live work, retain that
-- history, and require every new runnable/materialized row to use schema v3.

LOCK TABLE automata_cluster_compatibility, workflow_runs, jobs, job_attempts,
    runners, runner_sessions, workflow_plan_v2_runs,
    workflow_plan_v2_concrete_jobs
    IN ACCESS EXCLUSIVE MODE;

ALTER TABLE workflow_runs
    ADD COLUMN runner_requirements_schema SMALLINT NOT NULL DEFAULT 2,
    ADD CONSTRAINT workflow_runs_runner_requirements_schema CHECK (
        runner_requirements_schema IN (2, 3)
    );

DO $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM automata_cluster_compatibility
        WHERE singleton
          AND minimum_admission_epoch = 4
          AND job_ir_schema = 5
          AND runner_requirements_schema = 2
    ) THEN
        RAISE EXCEPTION 'runner-requirements v3 requires the exact v2 cluster contract'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_requirements_v3_cluster_precondition';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jobs AS job
        JOIN job_attempts AS attempt ON attempt.job_id = job.id
        WHERE job.requirements @> '{"schema_version": 2}'::jsonb
          AND attempt.lifecycle IN (
              'queued', 'leased', 'preparing', 'running',
              'cancelling', 'finalizing'
          )
    ) THEN
        RAISE EXCEPTION 'runner-requirements v3 migration requires schema-v2 attempts to be drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_requirements_v3_live_attempts_refused';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM workflow_runs
        WHERE runner_requirements_schema = 2
          AND status IN ('queued', 'in_progress')
    ) THEN
        RAISE EXCEPTION 'runner-requirements v3 migration requires schema-v2 workflow runs to be drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_requirements_v3_live_runs_refused';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM runner_sessions
        WHERE disconnected_at_ms IS NULL
    ) THEN
        RAISE EXCEPTION 'runner-requirements v3 migration requires every runner session to be disconnected'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_requirements_v3_live_sessions_refused';
    END IF;
END;
$automata$;

ALTER TABLE runner_sessions
    DROP CONSTRAINT runner_sessions_live_protocol_v4,
    ADD CONSTRAINT runner_sessions_live_protocol_v5 CHECK (
        disconnected_at_ms IS NOT NULL OR protocol_version = 5
    );

ALTER TABLE automata_cluster_compatibility
    DROP CONSTRAINT automata_cluster_compatibility_job_ir_v5;

UPDATE automata_cluster_compatibility
SET runner_requirements_schema = 3
WHERE singleton;

ALTER TABLE automata_cluster_compatibility
    ADD CONSTRAINT automata_cluster_compatibility_job_ir_v5 CHECK (
        minimum_admission_epoch = 4
        AND job_ir_schema = 5
        AND runner_requirements_schema = 3
    );

ALTER TABLE jobs
    DROP CONSTRAINT jobs_current_admission_metadata,
    ADD CONSTRAINT jobs_current_admission_metadata CHECK (
        admission_epoch = 4
        AND job_ir_schema = 5
        AND job_ir_size_bytes BETWEEN 1 AND 16777216
        AND (
            requirements @> '{"schema_version": 2}'::jsonb
            OR (
                requirements @> '{"schema_version": 3}'::jsonb
                AND requirements ? 'resource_allocation'
            )
        )
    );

ALTER TABLE workflow_plan_v2_concrete_jobs
    DROP CONSTRAINT workflow_plan_v2_concrete_jobs_requirements_current,
    ADD CONSTRAINT workflow_plan_v2_concrete_jobs_requirements_current CHECK (
        requirements @> '{"schema_version": 2}'::jsonb
        OR (
            requirements @> '{"schema_version": 3}'::jsonb
            AND requirements ? 'resource_allocation'
        )
    );

ALTER TABLE workflow_plan_v2_runs
    ADD COLUMN runner_requirements_schema SMALLINT NOT NULL DEFAULT 2,
    ADD CONSTRAINT workflow_plan_v2_runs_runner_requirements_schema CHECK (
        runner_requirements_schema IN (2, 3)
    );

COMMENT ON COLUMN workflow_plan_v2_runs.runner_requirements_schema IS
    'Immutable runner-requirements schema authenticated by this admitted plan; v2 is terminal history only after migration 0054.';

ALTER TABLE workflow_plan_v2_runs
    ALTER COLUMN runner_requirements_schema DROP DEFAULT;

ALTER TABLE workflow_runs
    ALTER COLUMN runner_requirements_schema DROP DEFAULT;

CREATE FUNCTION automata_require_workflow_run_runner_requirements_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.runner_requirements_schema <> 3 THEN
        RAISE EXCEPTION 'new workflow runs require runner-requirements schema v3'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_runs_runner_requirements_v3_new_only';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_00_require_runner_requirements_v3
BEFORE INSERT ON workflow_runs
FOR EACH ROW
EXECUTE FUNCTION automata_require_workflow_run_runner_requirements_v3();

CREATE FUNCTION automata_enforce_workflow_run_requirements_schema_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.runner_requirements_schema IS DISTINCT FROM
       OLD.runner_requirements_schema
    THEN
        RAISE EXCEPTION 'workflow-run runner-requirements schema is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_runs_runner_requirements_schema_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_runner_requirements_schema_immutable
BEFORE UPDATE OF runner_requirements_schema ON workflow_runs
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_run_requirements_schema_immutable();

CREATE FUNCTION automata_enforce_workflow_plan_v2_requirements_schema_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.runner_requirements_schema IS DISTINCT FROM
       OLD.runner_requirements_schema
    THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 runner-requirements schema is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'workflow_plan_v2_runs_runner_requirements_schema_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runs_runner_requirements_schema_immutable
BEFORE UPDATE OF runner_requirements_schema ON workflow_plan_v2_runs
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_requirements_schema_immutable();

CREATE FUNCTION automata_require_runner_requirements_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT (
        NEW.requirements @> '{"schema_version": 3}'::jsonb
        AND NEW.requirements ? 'resource_allocation'
    ) OR NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS run
        WHERE run.id = NEW.run_id
          AND run.runner_requirements_schema = 3
    ) THEN
        RAISE EXCEPTION 'new executable rows require runner-requirements schema v3'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_requirements_v3_new_rows_only';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER jobs_00_require_runner_requirements_v3
BEFORE INSERT ON jobs
FOR EACH ROW
EXECUTE FUNCTION automata_require_runner_requirements_v3();

CREATE TRIGGER workflow_plan_v2_concrete_jobs_00_require_runner_requirements_v3
BEFORE INSERT ON workflow_plan_v2_concrete_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_require_runner_requirements_v3();

CREATE FUNCTION automata_require_runner_requirements_v3_attempt()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM jobs AS job
        WHERE job.id = NEW.job_id
          AND job.requirements @> '{"schema_version": 3}'::jsonb
          AND job.requirements ? 'resource_allocation'
    ) THEN
        RAISE EXCEPTION 'new attempts require runner-requirements schema v3'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'job_attempts_runner_requirements_v3_new_only';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_00_require_runner_requirements_v3
BEFORE INSERT ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_require_runner_requirements_v3_attempt();

CREATE FUNCTION automata_require_workflow_plan_v2_runner_requirements_v3()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.runner_requirements_schema <> 3
       OR NOT EXISTS (
           SELECT 1
           FROM workflow_runs AS run
           WHERE run.id = NEW.run_id
             AND run.runner_requirements_schema = 3
       )
    THEN
        RAISE EXCEPTION 'new WorkflowPlan-v2 runs require runner-requirements schema v3'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_runs_runner_requirements_v3_new_only';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_runs_00_require_runner_requirements_v3
BEFORE INSERT ON workflow_plan_v2_runs
FOR EACH ROW
EXECUTE FUNCTION automata_require_workflow_plan_v2_runner_requirements_v3();
