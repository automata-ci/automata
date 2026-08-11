-- Replace the single pending-run slot with an ordered, bounded-by-policy queue.
-- Existing groups retain GitHub's one-pending-run semantics; current admissions
-- may explicitly opt into the extended max queue policy.

ALTER TABLE workflow_runs
    ADD COLUMN concurrency_queue_policy TEXT;

UPDATE workflow_runs
SET concurrency_queue_policy = 'single'
WHERE concurrency_group_key IS NOT NULL;

ALTER TABLE workflow_runs
    ADD CONSTRAINT workflow_runs_concurrency_queue_policy_shape CHECK (
        (concurrency_group_key IS NULL AND concurrency_queue_policy IS NULL)
        OR (
            concurrency_group_key IS NOT NULL
            AND concurrency_queue_policy IN ('single', 'max')
        )
    );

CREATE TABLE concurrency_group_pending_runs (
    repository_id UUID NOT NULL,
    normalized_key TEXT NOT NULL,
    run_id UUID NOT NULL,
    enqueued_at_ms BIGINT NOT NULL,
    CONSTRAINT concurrency_group_pending_runs_primary_key PRIMARY KEY (
        repository_id, normalized_key, run_id
    ),
    CONSTRAINT concurrency_group_pending_runs_run_unique UNIQUE (run_id),
    CONSTRAINT concurrency_group_pending_runs_group_fk
        FOREIGN KEY (repository_id, normalized_key)
        REFERENCES concurrency_groups(repository_id, normalized_key)
        ON DELETE CASCADE,
    CONSTRAINT concurrency_group_pending_runs_run_fk
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT concurrency_group_pending_runs_time_nonnegative CHECK (
        enqueued_at_ms >= 0
    )
);

INSERT INTO concurrency_group_pending_runs (
    repository_id, normalized_key, run_id, enqueued_at_ms
)
SELECT concurrency.repository_id, concurrency.normalized_key,
       concurrency.pending_run_id, concurrency.updated_at_ms
FROM concurrency_groups AS concurrency
WHERE concurrency.pending_run_id IS NOT NULL;

CREATE INDEX concurrency_group_pending_runs_order
    ON concurrency_group_pending_runs (
        repository_id, normalized_key, enqueued_at_ms, run_id
    );

ALTER TABLE concurrency_groups
    DROP CONSTRAINT concurrency_groups_pending_run_matches_repository,
    DROP CONSTRAINT concurrency_groups_distinct_slots,
    DROP COLUMN pending_run_id;

CREATE FUNCTION automata_validate_concurrency_pending_run()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM concurrency_groups AS concurrency
        WHERE concurrency.repository_id = NEW.repository_id
          AND concurrency.normalized_key = NEW.normalized_key
          AND concurrency.running_run_id = NEW.run_id
    ) THEN
        RAISE EXCEPTION 'Concurrency run cannot occupy running and pending positions'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER concurrency_group_pending_runs_validate_distinct
BEFORE INSERT OR UPDATE ON concurrency_group_pending_runs
FOR EACH ROW EXECUTE FUNCTION automata_validate_concurrency_pending_run();

CREATE FUNCTION automata_validate_concurrency_running_run()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.running_run_id IS NOT NULL AND EXISTS (
        SELECT 1
        FROM concurrency_group_pending_runs AS pending
        WHERE pending.repository_id = NEW.repository_id
          AND pending.normalized_key = NEW.normalized_key
          AND pending.run_id = NEW.running_run_id
    ) THEN
        RAISE EXCEPTION 'Concurrency run cannot occupy running and pending positions'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER concurrency_groups_validate_running_distinct
BEFORE INSERT OR UPDATE ON concurrency_groups
FOR EACH ROW EXECUTE FUNCTION automata_validate_concurrency_running_run();

CREATE FUNCTION automata_enforce_workflow_concurrency_policy_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.concurrency_queue_policy IS DISTINCT FROM OLD.concurrency_queue_policy THEN
        RAISE EXCEPTION 'Workflow concurrency queue policy is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_runs_enforce_concurrency_policy_immutable
BEFORE UPDATE ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION automata_enforce_workflow_concurrency_policy_immutable();
