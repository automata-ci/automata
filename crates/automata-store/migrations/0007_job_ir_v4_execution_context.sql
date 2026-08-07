-- JobIR v4 binds the immutable execution context, canonical workspace, and
-- event-content identity before a job can be admitted. Admission epoch 3
-- fences binaries that can only produce the incomplete v3 envelope.

ALTER TABLE automata_cluster_compatibility
    DROP CONSTRAINT automata_cluster_compatibility_g1;

UPDATE automata_cluster_compatibility
SET minimum_admission_epoch = 3,
    job_ir_schema = 4;

ALTER TABLE automata_cluster_compatibility
    ADD CONSTRAINT automata_cluster_compatibility_job_ir_v4 CHECK (
        minimum_admission_epoch = 3
        AND job_ir_schema = 4
        AND runner_requirements_schema = 2
    );

-- A v3 connection cannot execute a v4 job. Retain it for audit, but revoke
-- its live authority before installing the exact selected-schema constraint.
UPDATE runners AS runner
SET status = 'offline',
    updated_at_ms = greatest(runner.updated_at_ms, incompatible.heartbeat_at_ms)
FROM (
    SELECT runner_id, max(heartbeat_at_ms) AS heartbeat_at_ms
    FROM runner_sessions
    WHERE disconnected_at_ms IS NULL AND job_ir_schema <> 4
    GROUP BY runner_id
) AS incompatible
WHERE runner.id = incompatible.runner_id
  AND runner.status = 'online';

UPDATE runner_sessions
SET disconnected_at_ms = heartbeat_at_ms
WHERE disconnected_at_ms IS NULL AND job_ir_schema <> 4;

ALTER TABLE runner_sessions
    DROP CONSTRAINT runner_sessions_live_job_ir_v3,
    ADD CONSTRAINT runner_sessions_live_job_ir_v4 CHECK (
        disconnected_at_ms IS NOT NULL OR job_ir_schema = 4
    );

-- Epoch-2 rows remain truthful historical v3 admissions. Only epoch 3 is a
-- current admission and therefore must carry the exact v4 schema.
ALTER TABLE jobs
    DROP CONSTRAINT jobs_admission_epoch_range,
    DROP CONSTRAINT jobs_current_admission_metadata,
    ADD CONSTRAINT jobs_admission_epoch_range CHECK (
        admission_epoch BETWEEN 1 AND 3
    ),
    ADD CONSTRAINT jobs_current_admission_metadata CHECK (
        (
            admission_epoch = 1
            AND job_ir_schema IS NULL
            AND job_ir_size_bytes IS NULL
        ) OR (
            admission_epoch = 2
            AND job_ir_schema = 3
            AND job_ir_size_bytes BETWEEN 1 AND 16777216
            AND requirements @> '{"schema_version": 2}'::jsonb
        ) OR (
            admission_epoch = 3
            AND job_ir_schema = 4
            AND job_ir_size_bytes BETWEEN 1 AND 16777216
            AND requirements @> '{"schema_version": 2}'::jsonb
        )
    );

ALTER TABLE workflow_snapshots
    DROP CONSTRAINT workflow_snapshots_admission_epoch,
    DROP CONSTRAINT workflow_snapshots_current_object_metadata,
    ADD CONSTRAINT workflow_snapshots_admission_epoch CHECK (
        admission_epoch BETWEEN 1 AND 3
    ),
    ADD CONSTRAINT workflow_snapshots_current_object_metadata CHECK (
        (
            admission_epoch = 1
            AND source_size_bytes IS NULL
            AND source_media_type IS NULL
        ) OR (
            admission_epoch IN (2, 3)
            AND source_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(source_media_type) BETWEEN 3 AND 128
            AND source_media_type !~ '[[:space:][:cntrl:];]'
        )
    );

ALTER TABLE workflow_runs
    DROP CONSTRAINT workflow_runs_admission_epoch,
    DROP CONSTRAINT workflow_runs_current_event_metadata,
    ADD CONSTRAINT workflow_runs_admission_epoch CHECK (
        admission_epoch BETWEEN 1 AND 3
    ),
    ADD CONSTRAINT workflow_runs_current_event_metadata CHECK (
        (
            admission_epoch = 1
            AND event_digest IS NULL
            AND event_size_bytes IS NULL
            AND event_media_type IS NULL
            AND plan_digest IS NULL
            AND plan_object_key IS NULL
            AND plan_size_bytes IS NULL
            AND plan_media_type IS NULL
            AND plan_schema IS NULL
        ) OR (
            admission_epoch IN (2, 3)
            AND octet_length(event_digest) = 32
            AND event_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(event_media_type) BETWEEN 3 AND 128
            AND event_media_type !~ '[[:space:][:cntrl:];]'
            AND octet_length(plan_digest) = 32
            AND octet_length(plan_object_key) BETWEEN 1 AND 1024
            AND plan_object_key !~ '[[:cntrl:]]'
            AND plan_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(plan_media_type) BETWEEN 3 AND 128
            AND plan_media_type !~ '[[:space:][:cntrl:];]'
            AND plan_schema = 1
        )
    );

-- These immutable records may already contain v3 history. Live session
-- fencing above prevents any new v3 claim/publication after this migration.
ALTER TABLE runner_operation_receipts
    DROP CONSTRAINT runner_operation_receipts_job_ir_shape,
    ADD CONSTRAINT runner_operation_receipts_job_ir_shape CHECK (
        (
            outcome = 'claimed'
            AND claimed_job_id IS NOT NULL
            AND claimed_run_id IS NOT NULL
            AND claimed_job_ir_schema IN (3, 4)
            AND claimed_job_ir_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(claimed_job_ir_digest) = 32
            AND octet_length(claimed_job_ir_object_key) BETWEEN 1 AND 1024
        ) OR (
            outcome <> 'claimed'
            AND claimed_job_id IS NULL
            AND claimed_run_id IS NULL
            AND claimed_job_ir_schema IS NULL
            AND claimed_job_ir_size_bytes IS NULL
            AND claimed_job_ir_digest IS NULL
            AND claimed_job_ir_object_key IS NULL
        )
    );

ALTER TABLE runner_lease_offer_publications
    DROP CONSTRAINT runner_lease_offer_publications_job_ir_shape,
    ADD CONSTRAINT runner_lease_offer_publications_job_ir_shape CHECK (
        job_ir_schema IN (3, 4)
        AND job_ir_size_bytes BETWEEN 1 AND 16777216
        AND octet_length(job_ir_digest) = 32
        AND octet_length(job_ir_object_key) BETWEEN 1 AND 1024
        AND job_ir_object_key !~ '[[:cntrl:]]'
    );
