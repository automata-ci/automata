-- Add one provider-compatible numeric identity without replacing the UUID
-- primary key or the per-workflow run number.

LOCK TABLE workflow_runs IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_runs
        WHERE status IN ('queued', 'in_progress')
    ) THEN
        RAISE EXCEPTION 'workflow run ID alias upgrade requires drained active runs'
            USING ERRCODE = '55000';
    END IF;
END;
$automata$;

ALTER TABLE workflow_runs
    ADD COLUMN run_id_alias BIGINT GENERATED ALWAYS AS IDENTITY (
        START WITH 1
        INCREMENT BY 1
        MINVALUE 1
        MAXVALUE 9007199254740991
        NO CYCLE
    ),
    ADD CONSTRAINT workflow_runs_id_alias_exact_positive CHECK (
        run_id_alias BETWEEN 1 AND 9007199254740991
    ),
    ADD CONSTRAINT workflow_runs_id_alias_unique UNIQUE (run_id_alias);

CREATE FUNCTION automata_reject_workflow_run_id_alias_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.run_id_alias IS DISTINCT FROM OLD.run_id_alias THEN
        RAISE EXCEPTION 'workflow run ID alias is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'workflow_runs_id_alias_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_id_alias_immutable
BEFORE UPDATE OF run_id_alias ON workflow_runs
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_run_id_alias_mutation();
