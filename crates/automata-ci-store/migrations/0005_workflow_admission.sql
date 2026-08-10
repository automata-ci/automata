-- Durable, idempotent workflow admission. Immutable objects are published
-- before this transaction; these columns retain the complete verified object
-- identities needed to audit or reconstruct an admitted run.

ALTER TABLE repositories
    ADD CONSTRAINT repositories_tenant_id_unique UNIQUE (tenant_id, id);

ALTER TABLE workflow_snapshots
    ADD COLUMN admission_epoch INTEGER,
    ADD COLUMN source_size_bytes BIGINT,
    ADD COLUMN source_media_type TEXT;

UPDATE workflow_snapshots SET admission_epoch = 1;

ALTER TABLE workflow_snapshots
    ALTER COLUMN admission_epoch SET NOT NULL,
    ALTER COLUMN admission_epoch SET DEFAULT 1,
    ADD CONSTRAINT workflow_snapshots_admission_epoch CHECK (
        admission_epoch BETWEEN 1 AND 2
    ),
    ADD CONSTRAINT workflow_snapshots_current_object_metadata CHECK (
        (
            admission_epoch = 1
            AND source_size_bytes IS NULL
            AND source_media_type IS NULL
        ) OR (
            admission_epoch = 2
            AND source_size_bytes BETWEEN 1 AND 16777216
            AND octet_length(source_media_type) BETWEEN 3 AND 128
            AND source_media_type !~ '[[:space:][:cntrl:];]'
        )
    );

ALTER TABLE workflow_runs
    ADD COLUMN admission_epoch INTEGER,
    ADD COLUMN event_digest BYTEA,
    ADD COLUMN event_size_bytes BIGINT,
    ADD COLUMN event_media_type TEXT,
    ADD COLUMN plan_digest BYTEA,
    ADD COLUMN plan_object_key TEXT,
    ADD COLUMN plan_size_bytes BIGINT,
    ADD COLUMN plan_media_type TEXT,
    ADD COLUMN plan_schema INTEGER;

UPDATE workflow_runs SET admission_epoch = 1;

ALTER TABLE workflow_runs
    ALTER COLUMN admission_epoch SET NOT NULL,
    ALTER COLUMN admission_epoch SET DEFAULT 1,
    ADD CONSTRAINT workflow_runs_admission_epoch CHECK (
        admission_epoch BETWEEN 1 AND 2
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
            admission_epoch = 2
            AND octet_length(event_digest) = 32
            AND event_size_bytes BETWEEN 1 AND 26214400
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

-- The next value is retained instead of deriving max(run_number), avoiding a
-- race and preserving monotonicity when old runs are deleted in the future.
CREATE TABLE workflow_run_number_counters (
    workflow_id UUID PRIMARY KEY
        REFERENCES workflow_definitions(id) ON DELETE CASCADE,
    next_run_number BIGINT NOT NULL,
    CONSTRAINT workflow_run_number_counters_positive CHECK (next_run_number > 1)
);

INSERT INTO workflow_run_number_counters (workflow_id, next_run_number)
SELECT workflow.id, coalesce(max(run.run_number), 0) + 1
FROM workflow_definitions AS workflow
LEFT JOIN workflow_runs AS run ON run.workflow_id = workflow.id
GROUP BY workflow.id
HAVING coalesce(max(run.run_number), 0) + 1 > 1;

-- A pending receipt is inserted first in the admission transaction. A unique
-- conflict waits for its owner to commit or roll back, providing a durable
-- idempotency lock without advisory-lock hash collisions.
CREATE TABLE workflow_admission_receipts (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    idempotency_kind TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest BYTEA NOT NULL,
    repository_id UUID,
    run_id UUID,
    committed_at_ms BIGINT,
    CONSTRAINT workflow_admission_receipts_primary_key PRIMARY KEY (
        tenant_id, idempotency_kind, idempotency_key
    ),
    CONSTRAINT workflow_admission_receipts_kind CHECK (
        idempotency_kind IN ('provider_delivery', 'operation')
    ),
    CONSTRAINT workflow_admission_receipts_key_shape CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 1024
        AND idempotency_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_admission_receipts_sha256 CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT workflow_admission_receipts_completion_shape CHECK (
        (repository_id IS NULL AND run_id IS NULL AND committed_at_ms IS NULL)
        OR
        (repository_id IS NOT NULL AND run_id IS NOT NULL AND committed_at_ms IS NOT NULL)
    ),
    CONSTRAINT workflow_admission_receipts_repository_tenant
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_admission_receipts_run_repository
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX workflow_admission_receipts_run
    ON workflow_admission_receipts (run_id)
    WHERE run_id IS NOT NULL;
