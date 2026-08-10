-- Durable idempotency boundaries for autonomous result selection. A request
-- row is reserved before SKIP LOCKED selection, so overlapping equal-ID calls
-- serialize and every committed outcome, including Idle, replays exactly.

CREATE TABLE workflow_plan_v2_result_selection_replay_horizons (
    queue_name TEXT PRIMARY KEY,
    replay_floor_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_result_selection_replay_horizons_queue CHECK (
        queue_name IN ('instance', 'job')
    ),
    CONSTRAINT workflow_plan_v2_result_selection_replay_horizons_time CHECK (
        replay_floor_ms >= 0 AND updated_at_ms >= replay_floor_ms
    )
);

-- The migration refuses every pre-existing projection source below, so no
-- selection receipt can predate this boundary. Seed both queues from one
-- authoritative database-clock observation: starting at the Unix epoch would
-- make a bounded first advancement impossible.
WITH authoritative_clock AS MATERIALIZED (
    SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
)
INSERT INTO workflow_plan_v2_result_selection_replay_horizons (
    queue_name, replay_floor_ms, updated_at_ms
)
SELECT queue.queue_name, authoritative_clock.now_ms, authoritative_clock.now_ms
FROM authoritative_clock
CROSS JOIN (VALUES ('instance'), ('job')) AS queue(queue_name);

-- Current-only queue state is not inferred from an unbounded historical scan.
-- A deployment that accumulated logical terminal/publication state before this
-- migration must recreate that pre-release state under the current contract.
DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM attempt_terminal_results AS terminal
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.initial_attempt_id = terminal.attempt_id
    ) OR EXISTS (
        SELECT 1 FROM workflow_plan_v2_activation_publications
    ) THEN
        RAISE EXCEPTION 'logical projection state must be recreated before due queues'
            USING ERRCODE = '23514';
    END IF;
END;
$automata$;

CREATE TABLE workflow_plan_v2_instance_result_selections (
    selection_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    outcome TEXT NOT NULL,
    tenant_id TEXT COLLATE "C",
    attempt_id UUID
        REFERENCES attempt_terminal_results(attempt_id),
    generation BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_instance_result_selections_generation_unique
        UNIQUE (attempt_id, generation),
    CONSTRAINT workflow_plan_v2_instance_result_selections_ids_non_nil CHECK (
        selection_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (attempt_id IS NULL
             OR attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid)
    ),
    CONSTRAINT workflow_plan_v2_instance_result_selections_tenant CHECK (
        tenant_id IS NULL
        OR (octet_length(tenant_id) BETWEEN 1 AND 255
            AND tenant_id !~ '[[:cntrl:]]')
    ),
    CONSTRAINT workflow_plan_v2_instance_result_selections_interval CHECK (
        claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND expires_at_ms - claimed_at_ms <= 900000
        AND created_at_ms = claimed_at_ms
        AND updated_at_ms >= created_at_ms
    ),
    CONSTRAINT workflow_plan_v2_instance_result_selections_outcome CHECK (
        (outcome IN ('selecting', 'idle')
         AND tenant_id IS NULL AND attempt_id IS NULL AND generation IS NULL)
        OR (outcome = 'claimed'
            AND tenant_id IS NOT NULL AND attempt_id IS NOT NULL
            AND generation > 0)
        OR (outcome = 'quarantined'
            AND tenant_id IS NOT NULL AND attempt_id IS NOT NULL
            AND generation IS NULL)
    )
);

CREATE TABLE workflow_plan_v2_job_result_selections (
    selection_id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    claimed_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    outcome TEXT NOT NULL,
    tenant_id TEXT COLLATE "C",
    run_id UUID,
    invocation_id UUID,
    logical_job_id UUID,
    generation BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_job_result_selections_generation_unique
        UNIQUE (logical_job_id, generation),
    CONSTRAINT workflow_plan_v2_job_result_selections_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id) MATCH FULL,
    CONSTRAINT workflow_plan_v2_job_result_selections_ids_non_nil CHECK (
        selection_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (run_id IS NULL
             OR run_id <> '00000000-0000-0000-0000-000000000000'::uuid)
        AND (invocation_id IS NULL
             OR invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid)
        AND (logical_job_id IS NULL
             OR logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid)
    ),
    CONSTRAINT workflow_plan_v2_job_result_selections_tenant CHECK (
        tenant_id IS NULL
        OR (octet_length(tenant_id) BETWEEN 1 AND 255
            AND tenant_id !~ '[[:cntrl:]]')
    ),
    CONSTRAINT workflow_plan_v2_job_result_selections_interval CHECK (
        claimed_at_ms >= 0
        AND expires_at_ms > claimed_at_ms
        AND expires_at_ms - claimed_at_ms <= 900000
        AND created_at_ms = claimed_at_ms
        AND updated_at_ms >= created_at_ms
    ),
    CONSTRAINT workflow_plan_v2_job_result_selections_outcome CHECK (
        (outcome IN ('selecting', 'idle')
         AND tenant_id IS NULL AND run_id IS NULL AND invocation_id IS NULL
         AND logical_job_id IS NULL AND generation IS NULL)
        OR (outcome = 'claimed'
            AND tenant_id IS NOT NULL AND run_id IS NOT NULL
            AND invocation_id IS NOT NULL AND logical_job_id IS NOT NULL
            AND generation > 0)
        OR (outcome = 'quarantined'
            AND tenant_id IS NOT NULL AND run_id IS NOT NULL
            AND invocation_id IS NOT NULL AND logical_job_id IS NOT NULL
            AND generation IS NULL)
    )
);

CREATE INDEX workflow_plan_v2_instance_result_selections_expired_receipts
    ON workflow_plan_v2_instance_result_selections (expires_at_ms, selection_id);

CREATE INDEX workflow_plan_v2_job_result_selections_expired_receipts
    ON workflow_plan_v2_job_result_selections (expires_at_ms, selection_id);

CREATE FUNCTION automata_enforce_workflow_plan_v2_instance_result_selection()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
        OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR OLD.outcome <> 'selecting'
        OR NEW.updated_at_ms <> OLD.updated_at_ms
    THEN
        RAISE EXCEPTION 'instance-result selection transition is not exact'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'idle' THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome = 'quarantined' AND EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instance_result_quarantines AS quarantine
        WHERE quarantine.attempt_id = NEW.attempt_id
          AND quarantine.tenant_id = NEW.tenant_id
    ) THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome <> 'claimed' OR NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instance_result_claims AS claim
        JOIN attempt_terminal_results AS terminal ON terminal.attempt_id = claim.attempt_id
        JOIN job_attempts AS attempt ON attempt.id = terminal.attempt_id
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE claim.attempt_id = NEW.attempt_id
          AND repository.tenant_id = NEW.tenant_id
          AND claim.owner_id = NEW.owner_id
          AND claim.generation = NEW.generation
          AND claim.claimed_at_ms = NEW.claimed_at_ms
          AND claim.expires_at_ms = NEW.expires_at_ms
          AND claim.state = 'projecting'
    ) THEN
        RAISE EXCEPTION 'instance-result selection lacks its exact live claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_selections_enforce
BEFORE UPDATE ON workflow_plan_v2_instance_result_selections
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_instance_result_selection();

CREATE FUNCTION automata_enforce_workflow_plan_v2_job_result_selection()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.selection_id IS DISTINCT FROM OLD.selection_id
        OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
        OR NEW.claimed_at_ms IS DISTINCT FROM OLD.claimed_at_ms
        OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR OLD.outcome <> 'selecting'
        OR NEW.updated_at_ms <> OLD.updated_at_ms
    THEN
        RAISE EXCEPTION 'job-result selection transition is not exact'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'idle' THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome = 'quarantined' AND EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_result_quarantines AS quarantine
        WHERE quarantine.logical_job_id = NEW.logical_job_id
          AND quarantine.tenant_id = NEW.tenant_id
          AND quarantine.run_id = NEW.run_id
          AND quarantine.invocation_id = NEW.invocation_id
    ) THEN
        RETURN NEW;
    END IF;
    IF NEW.outcome <> 'claimed' OR NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_result_claims AS claim
        JOIN workflow_plan_v2_jobs AS job
          ON job.run_id = claim.run_id
         AND job.invocation_id = claim.invocation_id
         AND job.id = claim.logical_job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        WHERE claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND repository.tenant_id = NEW.tenant_id
          AND claim.owner_id = NEW.owner_id
          AND claim.generation = NEW.generation
          AND claim.claimed_at_ms = NEW.claimed_at_ms
          AND claim.expires_at_ms = NEW.expires_at_ms
          AND claim.state = 'aggregating'
    ) THEN
        RAISE EXCEPTION 'job-result selection lacks its exact live claim'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_selections_enforce
BEFORE UPDATE ON workflow_plan_v2_job_result_selections
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_job_result_selection();

CREATE FUNCTION automata_reject_workflow_plan_v2_result_selection_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    target_queue_name TEXT;
    replay_floor BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_queue_name := CASE TG_TABLE_NAME
            WHEN 'workflow_plan_v2_instance_result_selections' THEN 'instance'
            WHEN 'workflow_plan_v2_job_result_selections' THEN 'job'
            ELSE NULL
        END;
        SELECT horizon.replay_floor_ms INTO replay_floor
        FROM workflow_plan_v2_result_selection_replay_horizons AS horizon
        WHERE horizon.queue_name = target_queue_name;
        IF OLD.expires_at_ms <= replay_floor THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'logical result selection receipts are immutable'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_selections_reject_delete
BEFORE DELETE ON workflow_plan_v2_instance_result_selections
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_selection_mutation();

CREATE TRIGGER workflow_plan_v2_job_result_selections_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_result_selections
FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_selection_mutation();

CREATE TRIGGER workflow_plan_v2_instance_result_selections_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_instance_result_selections
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_selection_mutation();

CREATE TRIGGER workflow_plan_v2_job_result_selections_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_result_selections
FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_selection_mutation();

CREATE FUNCTION automata_enforce_workflow_plan_v2_result_replay_horizon()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    authoritative_now_ms BIGINT;
BEGIN
    authoritative_now_ms :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF NEW.queue_name IS DISTINCT FROM OLD.queue_name
        OR NEW.replay_floor_ms < OLD.replay_floor_ms
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.replay_floor_ms > NEW.updated_at_ms
        OR NEW.updated_at_ms > authoritative_now_ms
        OR NEW.replay_floor_ms - OLD.replay_floor_ms > GREATEST(
            60000, NEW.updated_at_ms - OLD.updated_at_ms
        )
    THEN
        RAISE EXCEPTION 'logical result replay horizon advancement is not authoritative and bounded'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'workflow_plan_v2_result_selection_replay_horizons_advance';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_result_selection_replay_horizons_enforce
BEFORE UPDATE ON workflow_plan_v2_result_selection_replay_horizons
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_result_replay_horizon();

-- These two operational queues contain only unfinished projection work.
-- Claim insertion/takeover moves available_at_ms to the exact fence expiry;
-- finalization removes the row. The worker therefore locks one indexed due
-- row instead of scanning immutable terminal/publication history.
CREATE TABLE workflow_plan_v2_instance_result_due (
    attempt_id UUID PRIMARY KEY
        REFERENCES attempt_terminal_results(attempt_id) ON DELETE CASCADE,
    tenant_id TEXT COLLATE "C" NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    source_order INTEGER NOT NULL,
    ready_at_ms BIGINT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_instance_result_due_shape CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(tenant_id) BETWEEN 1 AND 255
        AND tenant_id !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
        AND ready_at_ms >= 0
        AND available_at_ms >= ready_at_ms
    )
);

CREATE INDEX workflow_plan_v2_instance_result_due_next
    ON workflow_plan_v2_instance_result_due (
        available_at_ms, ready_at_ms, run_id, invocation_id,
        source_order, logical_job_id, attempt_id
    );

CREATE TABLE workflow_plan_v2_job_result_due (
    logical_job_id UUID PRIMARY KEY,
    tenant_id TEXT COLLATE "C" NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    source_order INTEGER NOT NULL,
    ready_at_ms BIGINT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_job_result_due_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE CASCADE,
    CONSTRAINT workflow_plan_v2_job_result_due_shape CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(tenant_id) BETWEEN 1 AND 255
        AND tenant_id !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
        AND ready_at_ms >= 0
        AND available_at_ms >= ready_at_ms
    )
);

CREATE INDEX workflow_plan_v2_job_result_due_next
    ON workflow_plan_v2_job_result_due (
        available_at_ms, ready_at_ms, run_id, invocation_id,
        source_order, logical_job_id
    );

-- A malformed target must not starve every newer due item. Quarantine retains
-- the exact trigger-authoritative due snapshot and, for a failure discovered
-- after claiming, the exact live claim fence. It never removes or terminalizes
-- the due target: targeted repair can still finish it while global selectors
-- permanently skip the target-keyed immutable ledger row.
CREATE TABLE workflow_plan_v2_instance_result_quarantines (
    attempt_id UUID PRIMARY KEY
        REFERENCES attempt_terminal_results(attempt_id) ON DELETE RESTRICT,
    tenant_id TEXT COLLATE "C" NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    logical_job_id UUID NOT NULL,
    source_order INTEGER NOT NULL,
    ready_at_ms BIGINT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    failure_kind TEXT NOT NULL,
    quarantined_at_ms BIGINT NOT NULL,
    claim_owner_id UUID,
    claim_generation BIGINT,
    claim_claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    claim_descriptor_digest BYTEA,
    CONSTRAINT workflow_plan_v2_instance_result_quarantines_job_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_instance_result_quarantines_shape CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(tenant_id) BETWEEN 1 AND 255
        AND tenant_id !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
        AND ready_at_ms >= 0
        AND available_at_ms >= ready_at_ms
        AND quarantined_at_ms >= ready_at_ms
    ),
    CONSTRAINT workflow_plan_v2_instance_result_quarantines_failure CHECK (
        failure_kind IN (
            'relational_evidence', 'object_evidence', 'payload_evidence'
        )
    ),
    CONSTRAINT workflow_plan_v2_instance_result_quarantines_claim CHECK ((
        (
            claim_owner_id IS NULL
            AND claim_generation IS NULL
            AND claim_claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND claim_descriptor_digest IS NULL
            AND quarantined_at_ms >= available_at_ms
        ) OR (
            claim_owner_id IS NOT NULL
            AND claim_owner_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND claim_generation > 0
            AND claim_claimed_at_ms >= 0
            AND quarantined_at_ms >= claim_claimed_at_ms
            AND claim_expires_at_ms > claim_claimed_at_ms
            AND quarantined_at_ms < claim_expires_at_ms
            AND claim_expires_at_ms - claim_claimed_at_ms <= 900000
            AND octet_length(claim_descriptor_digest) = 32
        )
    ) IS TRUE)
);

CREATE TABLE workflow_plan_v2_job_result_quarantines (
    logical_job_id UUID PRIMARY KEY,
    tenant_id TEXT COLLATE "C" NOT NULL,
    run_id UUID NOT NULL,
    invocation_id UUID NOT NULL,
    source_order INTEGER NOT NULL,
    ready_at_ms BIGINT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    failure_kind TEXT NOT NULL,
    quarantined_at_ms BIGINT NOT NULL,
    claim_owner_id UUID,
    claim_generation BIGINT,
    claim_claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    claim_descriptor_digest BYTEA,
    CONSTRAINT workflow_plan_v2_job_result_quarantines_target_fk
        FOREIGN KEY (run_id, invocation_id, logical_job_id)
        REFERENCES workflow_plan_v2_jobs(run_id, invocation_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_job_result_quarantines_shape CHECK (
        logical_job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND invocation_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND octet_length(tenant_id) BETWEEN 1 AND 255
        AND tenant_id !~ '[[:cntrl:]]'
        AND source_order BETWEEN 0 AND 1023
        AND ready_at_ms >= 0
        AND available_at_ms >= ready_at_ms
        AND quarantined_at_ms >= ready_at_ms
    ),
    CONSTRAINT workflow_plan_v2_job_result_quarantines_failure CHECK (
        failure_kind IN (
            'relational_evidence', 'object_evidence', 'payload_evidence'
        )
    ),
    CONSTRAINT workflow_plan_v2_job_result_quarantines_claim CHECK ((
        (
            claim_owner_id IS NULL
            AND claim_generation IS NULL
            AND claim_claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND claim_descriptor_digest IS NULL
            AND quarantined_at_ms >= available_at_ms
        ) OR (
            claim_owner_id IS NOT NULL
            AND claim_owner_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
            AND claim_generation > 0
            AND claim_claimed_at_ms >= 0
            AND quarantined_at_ms >= claim_claimed_at_ms
            AND claim_expires_at_ms > claim_claimed_at_ms
            AND quarantined_at_ms < claim_expires_at_ms
            AND claim_expires_at_ms - claim_claimed_at_ms <= 900000
            AND octet_length(claim_descriptor_digest) = 32
        )
    ) IS TRUE)
);

CREATE FUNCTION automata_validate_workflow_plan_v2_instance_result_quarantine()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_due workflow_plan_v2_instance_result_due%ROWTYPE;
BEGIN
    SELECT due.* INTO current_due
    FROM workflow_plan_v2_instance_result_due AS due
    WHERE due.attempt_id = NEW.attempt_id
    FOR UPDATE;
    IF NOT FOUND OR ROW(
        NEW.tenant_id, NEW.run_id, NEW.invocation_id, NEW.logical_job_id,
        NEW.source_order, NEW.ready_at_ms, NEW.available_at_ms
    ) IS DISTINCT FROM ROW(
        current_due.tenant_id, current_due.run_id, current_due.invocation_id,
        current_due.logical_job_id, current_due.source_order,
        current_due.ready_at_ms, current_due.available_at_ms
    ) THEN
        RAISE EXCEPTION 'instance-result quarantine lacks its exact current due target'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'workflow_plan_v2_instance_result_quarantines_due_exact';
    END IF;

    IF NEW.claim_owner_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_instance_result_claims AS claim
        WHERE claim.attempt_id = NEW.attempt_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.logical_job_id = NEW.logical_job_id
          AND claim.state = 'projecting'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_claimed_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND claim.descriptor_digest = NEW.claim_descriptor_digest
    ) THEN
        RAISE EXCEPTION 'instance-result quarantine lacks its exact live claim'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'workflow_plan_v2_instance_result_quarantines_claim_exact';
    END IF;

    NEW.quarantined_at_ms :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_quarantines_validate
BEFORE INSERT ON workflow_plan_v2_instance_result_quarantines
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_instance_result_quarantine();

CREATE FUNCTION automata_validate_workflow_plan_v2_job_result_quarantine()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_due workflow_plan_v2_job_result_due%ROWTYPE;
BEGIN
    SELECT due.* INTO current_due
    FROM workflow_plan_v2_job_result_due AS due
    WHERE due.logical_job_id = NEW.logical_job_id
    FOR UPDATE;
    IF NOT FOUND OR ROW(
        NEW.tenant_id, NEW.run_id, NEW.invocation_id, NEW.source_order,
        NEW.ready_at_ms, NEW.available_at_ms
    ) IS DISTINCT FROM ROW(
        current_due.tenant_id, current_due.run_id, current_due.invocation_id,
        current_due.source_order, current_due.ready_at_ms,
        current_due.available_at_ms
    ) THEN
        RAISE EXCEPTION 'job-result quarantine lacks its exact current due target'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'workflow_plan_v2_job_result_quarantines_due_exact';
    END IF;

    IF NEW.claim_owner_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM workflow_plan_v2_job_result_claims AS claim
        WHERE claim.logical_job_id = NEW.logical_job_id
          AND claim.run_id = NEW.run_id
          AND claim.invocation_id = NEW.invocation_id
          AND claim.state = 'aggregating'
          AND claim.owner_id = NEW.claim_owner_id
          AND claim.generation = NEW.claim_generation
          AND claim.claimed_at_ms = NEW.claim_claimed_at_ms
          AND claim.expires_at_ms = NEW.claim_expires_at_ms
          AND claim.descriptor_digest = NEW.claim_descriptor_digest
    ) THEN
        RAISE EXCEPTION 'job-result quarantine lacks its exact live claim'
            USING ERRCODE = '23514',
                  CONSTRAINT =
                      'workflow_plan_v2_job_result_quarantines_claim_exact';
    END IF;

    NEW.quarantined_at_ms :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_quarantines_validate
BEFORE INSERT ON workflow_plan_v2_job_result_quarantines
FOR EACH ROW
EXECUTE FUNCTION automata_validate_workflow_plan_v2_job_result_quarantine();

CREATE FUNCTION automata_refresh_workflow_plan_v2_instance_result_due(
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
      AND terminal.result_schema = 1
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

CREATE FUNCTION automata_refresh_workflow_plan_v2_job_result_due(
    target_run_id UUID,
    target_invocation_id UUID,
    target_logical_job_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $automata$
BEGIN
    INSERT INTO workflow_plan_v2_job_result_due (
        logical_job_id, tenant_id, run_id, invocation_id, source_order,
        ready_at_ms, available_at_ms
    )
    SELECT job.id, repository.tenant_id, job.run_id, job.invocation_id,
           job.source_order, ready.ready_at_ms,
           GREATEST(ready.ready_at_ms,
                    COALESCE(claim.expires_at_ms, ready.ready_at_ms))
    FROM workflow_plan_v2_jobs AS job
    JOIN workflow_plan_v2_invocations AS invocation
      ON invocation.run_id = job.run_id AND invocation.id = job.invocation_id
    JOIN workflow_plan_v2_runs AS marker ON marker.run_id = job.run_id
    JOIN workflow_runs AS run ON run.id = marker.run_id
    JOIN repositories AS repository ON repository.id = run.repository_id
    JOIN workflow_plan_v2_activation_publications AS publication
      ON publication.run_id = job.run_id
     AND publication.invocation_id = job.invocation_id
     AND publication.logical_job_id = job.id
    LEFT JOIN workflow_plan_v2_job_result_claims AS claim
      ON claim.logical_job_id = job.id
    CROSS JOIN LATERAL (
        SELECT GREATEST(
            publication.published_at_ms,
            COALESCE((
                SELECT max(result.finalized_at_ms)
                FROM workflow_plan_v2_instances AS instance
                JOIN workflow_plan_v2_instance_results AS result
                  ON result.instance_id = instance.id
                WHERE instance.run_id = job.run_id
                  AND instance.invocation_id = job.invocation_id
                  AND instance.logical_job_id = job.id
            ), 0),
            COALESCE((
                SELECT max(result.finalized_at_ms)
                FROM workflow_plan_v2_dependencies AS dependency
                JOIN workflow_plan_v2_job_results AS result
                  ON result.logical_job_id = dependency.prerequisite_job_id
                WHERE dependency.run_id = job.run_id
                  AND dependency.invocation_id = job.invocation_id
                  AND dependency.logical_job_id = job.id
            ), 0)
        ) AS ready_at_ms
    ) AS ready
    WHERE job.run_id = target_run_id
      AND job.invocation_id = target_invocation_id
      AND job.id = target_logical_job_id
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
      AND (claim.logical_job_id IS NULL OR claim.state = 'aggregating')
      AND publication.instance_count = (
          SELECT count(*)
          FROM workflow_plan_v2_instances AS instance
          WHERE instance.run_id = job.run_id
            AND instance.invocation_id = job.invocation_id
            AND instance.logical_job_id = job.id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM workflow_plan_v2_instances AS instance
          LEFT JOIN workflow_plan_v2_instance_results AS result
            ON result.instance_id = instance.id
           AND result.run_id = instance.run_id
           AND result.invocation_id = instance.invocation_id
           AND result.logical_job_id = instance.logical_job_id
          LEFT JOIN workflow_plan_v2_instance_result_claims AS instance_claim
            ON instance_claim.instance_id = result.instance_id
          WHERE instance.run_id = job.run_id
            AND instance.invocation_id = job.invocation_id
            AND instance.logical_job_id = job.id
            AND (result.instance_id IS NULL
                 OR instance_claim.state IS DISTINCT FROM 'finalized')
      )
      AND NOT EXISTS (
          SELECT 1
          FROM workflow_plan_v2_dependencies AS dependency
          LEFT JOIN workflow_plan_v2_job_results AS prerequisite_result
            ON prerequisite_result.run_id = dependency.run_id
           AND prerequisite_result.invocation_id = dependency.invocation_id
           AND prerequisite_result.logical_job_id =
               dependency.prerequisite_job_id
          LEFT JOIN workflow_plan_v2_job_result_claims AS prerequisite_claim
            ON prerequisite_claim.logical_job_id =
               prerequisite_result.logical_job_id
          WHERE dependency.run_id = job.run_id
            AND dependency.invocation_id = job.invocation_id
            AND dependency.logical_job_id = job.id
            AND (prerequisite_result.logical_job_id IS NULL
                 OR prerequisite_claim.state IS DISTINCT FROM 'finalized')
      )
    ON CONFLICT (logical_job_id) DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        run_id = EXCLUDED.run_id,
        invocation_id = EXCLUDED.invocation_id,
        source_order = EXCLUDED.source_order,
        ready_at_ms = EXCLUDED.ready_at_ms,
        available_at_ms = EXCLUDED.available_at_ms;

    IF NOT FOUND THEN
        DELETE FROM workflow_plan_v2_job_result_due
        WHERE logical_job_id = target_logical_job_id
          AND run_id = target_run_id
          AND invocation_id = target_invocation_id;
    END IF;
END;
$automata$;

CREATE FUNCTION automata_refresh_workflow_plan_v2_terminal_result_due_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM automata_refresh_workflow_plan_v2_instance_result_due(NEW.attempt_id);
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER attempt_terminal_results_refresh_result_projection_due
AFTER INSERT OR UPDATE ON attempt_terminal_results
FOR EACH ROW
EXECUTE FUNCTION automata_refresh_workflow_plan_v2_terminal_result_due_trigger();

-- Production terminal commit inserts the immutable result before it advances
-- the attempt lifecycle. The terminal-row hook above consequently observes a
-- still-active attempt and must not publish it. Refresh again after the exact
-- terminal lifecycle transition, when the result row and its assigned ordinal
-- are both visible in the same transaction.
CREATE FUNCTION automata_refresh_workflow_plan_v2_attempt_lifecycle_due_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.lifecycle IS DISTINCT FROM OLD.lifecycle
       AND NEW.lifecycle IN (
           'succeeded', 'failed', 'cancelled', 'timed_out', 'skipped'
       )
    THEN
        PERFORM automata_refresh_workflow_plan_v2_instance_result_due(NEW.id);
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER job_attempts_refresh_result_projection_due_after_terminal
AFTER UPDATE OF lifecycle ON job_attempts
FOR EACH ROW
EXECUTE FUNCTION automata_refresh_workflow_plan_v2_attempt_lifecycle_due_trigger();

CREATE FUNCTION automata_refresh_workflow_plan_v2_instance_claim_due_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM automata_refresh_workflow_plan_v2_instance_result_due(NEW.attempt_id);
    PERFORM 1
    FROM workflow_plan_v2_jobs AS job
    WHERE job.run_id = NEW.run_id
      AND job.invocation_id = NEW.invocation_id
      AND job.id = NEW.logical_job_id
    FOR UPDATE;
    PERFORM automata_refresh_workflow_plan_v2_job_result_due(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_claims_refresh_due
AFTER INSERT OR UPDATE ON workflow_plan_v2_instance_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_refresh_workflow_plan_v2_instance_claim_due_trigger();

CREATE FUNCTION automata_refresh_workflow_plan_v2_activation_due_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    PERFORM automata_refresh_workflow_plan_v2_job_result_due(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id
    );
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_activation_publications_refresh_result_due
AFTER INSERT ON workflow_plan_v2_activation_publications
FOR EACH ROW
EXECUTE FUNCTION automata_refresh_workflow_plan_v2_activation_due_trigger();

CREATE TRIGGER workflow_plan_v2_instances_refresh_result_due
AFTER INSERT ON workflow_plan_v2_instances
FOR EACH ROW
EXECUTE FUNCTION automata_refresh_workflow_plan_v2_activation_due_trigger();

CREATE FUNCTION automata_refresh_workflow_plan_v2_job_state_due_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        PERFORM automata_refresh_workflow_plan_v2_job_result_due(
            NEW.run_id, NEW.invocation_id, NEW.id
        );
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_jobs_refresh_result_due
AFTER UPDATE OF state ON workflow_plan_v2_jobs
FOR EACH ROW
EXECUTE FUNCTION automata_refresh_workflow_plan_v2_job_state_due_trigger();

CREATE FUNCTION automata_refresh_workflow_plan_v2_job_claim_due_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    dependent RECORD;
BEGIN
    PERFORM automata_refresh_workflow_plan_v2_job_result_due(
        NEW.run_id, NEW.invocation_id, NEW.logical_job_id
    );
    IF NEW.state = 'finalized' THEN
        FOR dependent IN
            SELECT dependency.run_id, dependency.invocation_id,
                   dependency.logical_job_id
            FROM workflow_plan_v2_dependencies AS dependency
            JOIN workflow_plan_v2_jobs AS job
              ON job.run_id = dependency.run_id
             AND job.invocation_id = dependency.invocation_id
             AND job.id = dependency.logical_job_id
            WHERE dependency.run_id = NEW.run_id
              AND dependency.invocation_id = NEW.invocation_id
              AND dependency.prerequisite_job_id = NEW.logical_job_id
            ORDER BY job.source_order, dependency.logical_job_id
            FOR UPDATE OF job
        LOOP
            PERFORM automata_refresh_workflow_plan_v2_job_result_due(
                dependent.run_id,
                dependent.invocation_id,
                dependent.logical_job_id
            );
        END LOOP;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_job_result_claims_refresh_due
AFTER INSERT OR UPDATE ON workflow_plan_v2_job_result_claims
FOR EACH ROW
EXECUTE FUNCTION automata_refresh_workflow_plan_v2_job_claim_due_trigger();

CREATE FUNCTION automata_enforce_workflow_plan_v2_result_due_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP = 'TRUNCATE' OR pg_trigger_depth() <= 1 THEN
        RAISE EXCEPTION 'WorkflowPlan-v2 result due queues are trigger-authoritative'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instance_result_due_enforce_rows
BEFORE INSERT OR UPDATE OR DELETE ON workflow_plan_v2_instance_result_due
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_result_due_mutation();
CREATE TRIGGER workflow_plan_v2_job_result_due_enforce_rows
BEFORE INSERT OR UPDATE OR DELETE ON workflow_plan_v2_job_result_due
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_result_due_mutation();
CREATE TRIGGER workflow_plan_v2_instance_result_due_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_instance_result_due
FOR EACH STATEMENT
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_result_due_mutation();
CREATE TRIGGER workflow_plan_v2_job_result_due_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_result_due
FOR EACH STATEMENT
EXECUTE FUNCTION automata_enforce_workflow_plan_v2_result_due_mutation();

-- Finalized roots, fences, and their child evidence are append-only. These
-- guards also reject a parent cascade that would otherwise erase evidence.
CREATE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'WorkflowPlan-v2 logical result evidence cannot be removed'
        USING ERRCODE = '23514';
END;
$automata$;

CREATE FUNCTION automata_protect_attempt_terminal_result_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF ROW(
        NEW.attempt_id, NEW.runner_session_id, NEW.operation_id,
        NEW.runner_id, NEW.runner_session_epoch, NEW.runner_generation,
        NEW.runner_slot, NEW.lease_id, NEW.fencing_token, NEW.result_schema,
        NEW.result_size_bytes, NEW.result_digest, NEW.result_object_key,
        NEW.conclusion, NEW.completed_at_ms, NEW.committed_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.attempt_id, OLD.runner_session_id, OLD.operation_id,
        OLD.runner_id, OLD.runner_session_epoch, OLD.runner_generation,
        OLD.runner_slot, OLD.lease_id, OLD.fencing_token, OLD.result_schema,
        OLD.result_size_bytes, OLD.result_digest, OLD.result_object_key,
        OLD.conclusion, OLD.completed_at_ms, OLD.committed_at_ms
    ) THEN
        RAISE EXCEPTION 'attempt terminal result evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_reject_retained_attempt_terminal_result_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1 FROM job_attempts AS attempt WHERE attempt.id = OLD.attempt_id
    ) THEN
        RAISE EXCEPTION 'retained attempt terminal result evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER attempt_terminal_results_protect_result_evidence
BEFORE UPDATE ON attempt_terminal_results FOR EACH ROW
EXECUTE FUNCTION automata_protect_attempt_terminal_result_evidence();
CREATE TRIGGER attempt_terminal_results_reject_retained_delete
BEFORE DELETE ON attempt_terminal_results FOR EACH ROW
EXECUTE FUNCTION automata_reject_retained_attempt_terminal_result_delete();
CREATE TRIGGER attempt_terminal_results_reject_truncate
BEFORE TRUNCATE ON attempt_terminal_results FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();

CREATE FUNCTION automata_reject_retained_workflow_plan_v2_instance_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM workflow_plan_v2_activation_publications AS publication
        WHERE publication.run_id = OLD.run_id
          AND publication.invocation_id = OLD.invocation_id
          AND publication.logical_job_id = OLD.logical_job_id
    ) THEN
        RAISE EXCEPTION 'retained WorkflowPlan-v2 instance evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_instances_reject_retained_delete
BEFORE DELETE ON workflow_plan_v2_instances FOR EACH ROW
EXECUTE FUNCTION automata_reject_retained_workflow_plan_v2_instance_delete();
CREATE TRIGGER workflow_plan_v2_instances_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_instances FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_activation_publications_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_activation_publications FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();

CREATE TRIGGER workflow_plan_v2_instance_result_claims_reject_delete
BEFORE DELETE ON workflow_plan_v2_instance_result_claims FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_instance_results_reject_delete
BEFORE DELETE ON workflow_plan_v2_instance_results FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_instance_result_outputs_reject_delete
BEFORE DELETE ON workflow_plan_v2_instance_result_outputs FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_claims_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_result_claims FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_results_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_results FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_instances_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_result_instances FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_prerequisites_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_result_prerequisites FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_outputs_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_result_outputs FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();

CREATE TRIGGER workflow_plan_v2_instance_result_claims_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_instance_result_claims FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_instance_results_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_instance_results FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_instance_result_outputs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_instance_result_outputs FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_claims_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_result_claims FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_results_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_results FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_instances_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_result_instances FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_prerequisites_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_result_prerequisites FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_outputs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_result_outputs FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();

CREATE TRIGGER workflow_plan_v2_result_selection_replay_horizons_reject_delete
BEFORE DELETE ON workflow_plan_v2_result_selection_replay_horizons FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_result_selection_replay_horizons_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_result_selection_replay_horizons FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();

-- Projection source identity is retained together with the immutable result
-- evidence. Row guards stop both direct DELETE and parent-driven cascades;
-- statement guards also stop TRUNCATE and TRUNCATE ... CASCADE from bypassing
-- row triggers. UPDATE remains governed by each source table's existing exact
-- transition/immutability trigger.
CREATE TRIGGER workflow_plan_v2_job_terminal_counters_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_terminal_counters FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_materialization_claims_reject_delete
BEFORE DELETE ON workflow_plan_v2_materialization_claims FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_concrete_jobs_reject_delete
BEFORE DELETE ON workflow_plan_v2_concrete_jobs FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_dependencies_reject_delete
BEFORE DELETE ON workflow_plan_v2_dependencies FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_jobs_reject_result_source_delete
BEFORE DELETE ON workflow_plan_v2_jobs FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_invocations_reject_result_source_delete
BEFORE DELETE ON workflow_plan_v2_invocations FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_runs_reject_result_source_delete
BEFORE DELETE ON workflow_plan_v2_runs FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();

CREATE TRIGGER workflow_plan_v2_job_terminal_counters_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_terminal_counters FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_materialization_claims_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_materialization_claims FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_concrete_jobs_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_concrete_jobs FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_dependencies_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_dependencies FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_jobs_reject_result_source_truncate
BEFORE TRUNCATE ON workflow_plan_v2_jobs FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_invocations_reject_result_source_truncate
BEFORE TRUNCATE ON workflow_plan_v2_invocations FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_runs_reject_result_source_truncate
BEFORE TRUNCATE ON workflow_plan_v2_runs FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();

CREATE TRIGGER workflow_plan_v2_instance_result_quarantines_reject_update
BEFORE UPDATE ON workflow_plan_v2_instance_result_quarantines FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_instance_result_quarantines_reject_delete
BEFORE DELETE ON workflow_plan_v2_instance_result_quarantines FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_instance_result_quarantines_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_instance_result_quarantines FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_quarantines_reject_update
BEFORE UPDATE ON workflow_plan_v2_job_result_quarantines FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_quarantines_reject_delete
BEFORE DELETE ON workflow_plan_v2_job_result_quarantines FOR EACH ROW
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
CREATE TRIGGER workflow_plan_v2_job_result_quarantines_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_job_result_quarantines FOR EACH STATEMENT
EXECUTE FUNCTION automata_reject_workflow_plan_v2_result_evidence_removal();
