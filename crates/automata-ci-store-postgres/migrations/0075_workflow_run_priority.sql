-- Persist one bounded effective priority on each workflow run. Existing work
-- remains at the ordinary level. Level 100 is reserved for authenticated
-- merge-queue admission; human updates are limited to 0..99 in the store port.

ALTER TABLE workflow_runs
    ADD COLUMN scheduling_priority SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE workflow_runs
    ADD CONSTRAINT workflow_runs_scheduling_priority
        CHECK (scheduling_priority BETWEEN 0 AND 100);

ALTER TABLE workflow_runs
    ALTER COLUMN scheduling_priority DROP DEFAULT;

ALTER TABLE runner_queue_cursors
    ADD COLUMN after_scheduling_priority SMALLINT,
    ADD COLUMN cycle_upper_scheduling_priority SMALLINT;

UPDATE runner_queue_cursors
SET after_scheduling_priority = 0
WHERE after_queued_at_ms IS NOT NULL;

UPDATE runner_queue_cursors
SET cycle_upper_scheduling_priority = 0
WHERE cycle_upper_queued_at_ms IS NOT NULL;

ALTER TABLE runner_queue_cursors
    DROP CONSTRAINT runner_queue_cursors_after_complete,
    DROP CONSTRAINT runner_queue_cursors_after_within_cycle,
    DROP CONSTRAINT runner_queue_cursors_upper_complete;

ALTER TABLE runner_queue_cursors
    ADD CONSTRAINT runner_queue_cursors_after_complete CHECK (
        (after_scheduling_priority IS NULL)
            = (after_queued_at_ms IS NULL)
            AND (after_queued_at_ms IS NULL)
            = (after_attempt_id IS NULL)
    ),
    ADD CONSTRAINT runner_queue_cursors_after_priority CHECK (
        after_scheduling_priority IS NULL
            OR after_scheduling_priority BETWEEN 0 AND 100
    ),
    ADD CONSTRAINT runner_queue_cursors_after_within_cycle CHECK (
        after_scheduling_priority IS NULL
            OR cycle_upper_scheduling_priority IS NULL
            OR ROW(
                100 - after_scheduling_priority,
                after_queued_at_ms,
                after_attempt_id
            ) <= ROW(
                100 - cycle_upper_scheduling_priority,
                cycle_upper_queued_at_ms,
                cycle_upper_attempt_id
            )
    ),
    ADD CONSTRAINT runner_queue_cursors_upper_complete CHECK (
        (cycle_upper_scheduling_priority IS NULL)
            = (cycle_upper_queued_at_ms IS NULL)
            AND (cycle_upper_queued_at_ms IS NULL)
            = (cycle_upper_attempt_id IS NULL)
    ),
    ADD CONSTRAINT runner_queue_cursors_upper_priority CHECK (
        cycle_upper_scheduling_priority IS NULL
            OR cycle_upper_scheduling_priority BETWEEN 0 AND 100
    );

CREATE INDEX workflow_runs_scheduling_priority_idx
    ON workflow_runs (scheduling_priority DESC, created_at_ms, id)
    WHERE status IN ('queued', 'in_progress');

INSERT INTO rbac_permissions (name, description, critical, created_at_ms)
VALUES (
    'runs:priority:update',
    'Change the scheduling priority of queued workflow runs.',
    false,
    0
);
