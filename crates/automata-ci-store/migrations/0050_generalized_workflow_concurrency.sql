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
    queue_sequence BIGINT GENERATED ALWAYS AS IDENTITY,
    enqueued_at_ms BIGINT NOT NULL,
    CONSTRAINT concurrency_group_pending_runs_primary_key PRIMARY KEY (
        repository_id, normalized_key, run_id
    ),
    CONSTRAINT concurrency_group_pending_runs_run_unique UNIQUE (run_id),
    CONSTRAINT concurrency_group_pending_runs_sequence_unique UNIQUE (queue_sequence),
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
        repository_id, normalized_key, queue_sequence
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

-- A concurrency preemption may arrive before a logical job has produced the
-- ordinary per-job/run result aggregate. Retain a distinct exact cancellation
-- witness so every logical phase can be fenced and terminalized atomically.
CREATE TABLE workflow_plan_v2_concurrency_cancellations (
    run_id UUID PRIMARY KEY
        REFERENCES workflow_plan_v2_runs(run_id) ON DELETE RESTRICT,
    root_invocation_id UUID NOT NULL,
    preempting_run_id UUID NOT NULL
        REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    prior_workflow_status TEXT NOT NULL,
    prior_workflow_updated_at_ms BIGINT NOT NULL,
    prior_marker_state TEXT NOT NULL,
    prior_marker_revision BIGINT NOT NULL,
    prior_marker_updated_at_ms BIGINT NOT NULL,
    prior_invocation_state TEXT NOT NULL,
    prior_invocation_revision BIGINT NOT NULL,
    prior_invocation_updated_at_ms BIGINT NOT NULL,
    cancelled_at_ms BIGINT NOT NULL,
    CONSTRAINT workflow_plan_v2_concurrency_cancellations_invocation_fk
        FOREIGN KEY (run_id, root_invocation_id)
        REFERENCES workflow_plan_v2_invocations(run_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_plan_v2_concurrency_cancellations_identity CHECK (
        run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND root_invocation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND preempting_run_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND preempting_run_id <> run_id
    ),
    CONSTRAINT workflow_plan_v2_concurrency_cancellations_prior_state CHECK (
        prior_workflow_status IN ('queued', 'in_progress')
        AND prior_marker_state IN ('pending', 'active')
        AND prior_invocation_state IN ('pending', 'active')
        AND prior_marker_revision > 0
        AND prior_invocation_revision > 0
    ),
    CONSTRAINT workflow_plan_v2_concurrency_cancellations_time CHECK (
        prior_workflow_updated_at_ms >= 0
        AND prior_marker_updated_at_ms >= 0
        AND prior_invocation_updated_at_ms >= 0
        AND cancelled_at_ms >= greatest(
            prior_workflow_updated_at_ms,
            prior_marker_updated_at_ms,
            prior_invocation_updated_at_ms
        )
    )
);

CREATE FUNCTION automata_validate_workflow_plan_v2_concurrency_cancellation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM workflow_runs AS target
        JOIN workflow_plan_v2_runs AS marker ON marker.run_id = target.id
        JOIN workflow_plan_v2_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        JOIN workflow_runs AS preempting ON preempting.id = NEW.preempting_run_id
        WHERE target.id = NEW.run_id
          AND target.repository_id = preempting.repository_id
          AND target.concurrency_group_key IS NOT NULL
          AND target.concurrency_group_key = preempting.concurrency_group_key
          AND target.status = NEW.prior_workflow_status
          AND target.updated_at_ms = NEW.prior_workflow_updated_at_ms
          AND marker.root_invocation_id = NEW.root_invocation_id
          AND marker.state = NEW.prior_marker_state
          AND marker.revision = NEW.prior_marker_revision
          AND marker.updated_at_ms = NEW.prior_marker_updated_at_ms
          AND invocation.state = NEW.prior_invocation_state
          AND invocation.revision = NEW.prior_invocation_revision
          AND invocation.updated_at_ms = NEW.prior_invocation_updated_at_ms
          AND preempting.status IN ('queued', 'in_progress')
          AND preempting.created_at_ms <= NEW.cancelled_at_ms
        FOR KEY SHARE OF target, marker, invocation, preempting
    ) THEN
        RAISE EXCEPTION 'Logical concurrency cancellation lacks exact active-run evidence'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_plan_v2_concurrency_cancellation_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_concurrency_cancellations_validate
BEFORE INSERT ON workflow_plan_v2_concurrency_cancellations
FOR EACH ROW EXECUTE FUNCTION automata_validate_workflow_plan_v2_concurrency_cancellation();

CREATE FUNCTION automata_reject_workflow_plan_v2_concurrency_cancellation_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'Logical concurrency cancellation evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'workflow_plan_v2_concurrency_cancellation_immutable';
END;
$automata$;

CREATE TRIGGER workflow_plan_v2_concurrency_cancellations_reject_update
BEFORE UPDATE ON workflow_plan_v2_concurrency_cancellations
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_plan_v2_concurrency_cancellation_mutation();
CREATE TRIGGER workflow_plan_v2_concurrency_cancellations_reject_delete
BEFORE DELETE ON workflow_plan_v2_concurrency_cancellations
FOR EACH ROW EXECUTE FUNCTION automata_reject_workflow_plan_v2_concurrency_cancellation_mutation();
CREATE TRIGGER workflow_plan_v2_concurrency_cancellations_reject_truncate
BEFORE TRUNCATE ON workflow_plan_v2_concurrency_cancellations
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_workflow_plan_v2_concurrency_cancellation_mutation();

ALTER TABLE workflow_plan_v2_jobs
    DROP CONSTRAINT workflow_plan_v2_jobs_claim_shape,
    ADD CONSTRAINT workflow_plan_v2_jobs_claim_shape CHECK ((
        (
            activation_owner_id IS NULL
            AND activation_claimed_at_ms IS NULL
            AND activation_expires_at_ms IS NULL
            AND state <> 'activating'
            AND (activation_fence > 0 OR state IN ('pending', 'cancelled'))
        ) OR (
            activation_owner_id IS NOT NULL
            AND activation_fence > 0
            AND state = 'activating'
            AND activation_claimed_at_ms >= created_at_ms
            AND activation_expires_at_ms > activation_claimed_at_ms
            AND activation_expires_at_ms - activation_claimed_at_ms <= 900000
            AND updated_at_ms = activation_claimed_at_ms
        )
    ) IS TRUE);

CREATE OR REPLACE FUNCTION automata_enforce_activation_claim_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now BIGINT :=
        floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    claim_duration BIGINT;
    is_takeover BOOLEAN;
BEGIN
    IF OLD.state IN ('pending', 'activating', 'activated', 'skipped')
       AND NEW.state = 'cancelled'
       AND NEW.activation_fence = OLD.activation_fence
       AND NEW.activation_owner_id IS NULL
       AND NEW.activation_claimed_at_ms IS NULL
       AND NEW.activation_expires_at_ms IS NULL
       AND NEW.activation_input_digest IS NOT DISTINCT FROM OLD.activation_input_digest
       AND NEW.activation_origin_selection_id IS NOT DISTINCT FROM
           OLD.activation_origin_selection_id
       AND EXISTS (
           SELECT 1
           FROM workflow_plan_v2_concurrency_cancellations AS cancellation
           WHERE cancellation.run_id = NEW.run_id
             AND cancellation.root_invocation_id = NEW.invocation_id
             AND cancellation.cancelled_at_ms = NEW.updated_at_ms
       )
    THEN
        RETURN NEW;
    END IF;

    IF OLD.state = 'pending' AND NEW.state = 'activating' THEN
        claim_duration :=
            NEW.activation_expires_at_ms - NEW.activation_claimed_at_ms;
        IF NEW.activation_origin_selection_id IS NULL
            OR NEW.activation_fence <> OLD.activation_fence + 1
            OR NEW.activation_claimed_at_ms > database_now
            OR database_now - NEW.activation_claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
        THEN
            RAISE EXCEPTION 'initial activation authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF OLD.state = 'activating' AND NEW.state = 'activating' THEN
        claim_duration :=
            NEW.activation_expires_at_ms - NEW.activation_claimed_at_ms;
        is_takeover := NEW.activation_origin_selection_id IS DISTINCT FROM
                       OLD.activation_origin_selection_id;
        IF NEW.activation_fence <> OLD.activation_fence + 1
            OR NEW.activation_origin_selection_id IS NULL
            OR NEW.updated_at_ms <> NEW.activation_claimed_at_ms
            OR (NOT is_takeover AND NEW.activation_owner_id IS DISTINCT FROM
                OLD.activation_owner_id)
            OR (is_takeover AND NEW.activation_claimed_at_ms <
                OLD.activation_expires_at_ms)
            OR (NOT is_takeover AND NEW.activation_claimed_at_ms >=
                OLD.activation_expires_at_ms)
            OR (NOT is_takeover
                AND database_now >= OLD.activation_expires_at_ms)
            OR NEW.activation_claimed_at_ms > database_now
            OR database_now - NEW.activation_claimed_at_ms > 60000
            OR claim_duration NOT BETWEEN 2000 AND 900000
            OR NEW.activation_expires_at_ms <= OLD.activation_expires_at_ms
            OR NEW.activation_input_digest IS DISTINCT FROM
               OLD.activation_input_digest
        THEN
            RAISE EXCEPTION 'activation authority successor is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF OLD.state = 'activating'
        AND NEW.state IN ('activated', 'skipped')
    THEN
        IF NEW.activation_fence <> OLD.activation_fence
            OR NEW.activation_origin_selection_id IS DISTINCT FROM
               OLD.activation_origin_selection_id
            OR NEW.activation_input_digest IS DISTINCT FROM
               OLD.activation_input_digest
            OR NEW.activation_owner_id IS NOT NULL
            OR NEW.activation_claimed_at_ms IS NOT NULL
            OR NEW.activation_expires_at_ms IS NOT NULL
            OR database_now < OLD.activation_claimed_at_ms
            OR database_now >= OLD.activation_expires_at_ms
        THEN
            RAISE EXCEPTION 'activation terminal authority is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'workflow_activation_claim_transition';
        END IF;
        PERFORM automata_require_active_unquarantined_workflow_phase(
            NEW.run_id, NEW.invocation_id, NEW.id, NULL
        );
    ELSIF (NEW.activation_fence, NEW.activation_owner_id,
           NEW.activation_claimed_at_ms, NEW.activation_expires_at_ms,
           NEW.activation_input_digest, NEW.activation_origin_selection_id)
          IS DISTINCT FROM
          (OLD.activation_fence, OLD.activation_owner_id,
           OLD.activation_claimed_at_ms, OLD.activation_expires_at_ms,
           OLD.activation_input_digest, OLD.activation_origin_selection_id)
    THEN
        RAISE EXCEPTION 'activation retained authority is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'workflow_activation_claim_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_guard_workflow_plan_v2_invocation_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state = 'cancelled'
       AND OLD.state IN ('pending', 'active')
       AND NEW.revision = OLD.revision + 1
       AND NEW.updated_at_ms >= OLD.updated_at_ms
       AND EXISTS (
           SELECT 1
           FROM workflow_plan_v2_concurrency_cancellations AS cancellation
           WHERE cancellation.run_id = NEW.run_id
             AND cancellation.root_invocation_id = NEW.id
             AND cancellation.prior_invocation_state = OLD.state
             AND cancellation.prior_invocation_revision = OLD.revision
             AND cancellation.prior_invocation_updated_at_ms = OLD.updated_at_ms
             AND cancellation.cancelled_at_ms = NEW.updated_at_ms
       )
    THEN
        RETURN NEW;
    END IF;
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

CREATE OR REPLACE FUNCTION automata_guard_workflow_plan_v2_marker_run_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NEW.state = 'cancelled'
       AND OLD.state IN ('pending', 'active')
       AND NEW.revision = OLD.revision + 1
       AND NEW.updated_at_ms >= OLD.updated_at_ms
       AND EXISTS (
           SELECT 1
           FROM workflow_plan_v2_concurrency_cancellations AS cancellation
           WHERE cancellation.run_id = NEW.run_id
             AND cancellation.root_invocation_id = NEW.root_invocation_id
             AND cancellation.prior_marker_state = OLD.state
             AND cancellation.prior_marker_revision = OLD.revision
             AND cancellation.prior_marker_updated_at_ms = OLD.updated_at_ms
             AND cancellation.cancelled_at_ms = NEW.updated_at_ms
       )
    THEN
        RETURN NEW;
    END IF;
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

CREATE OR REPLACE FUNCTION automata_guard_workflow_run_plan_v2_result()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.status IN ('queued', 'in_progress')
       AND NEW.status = 'cancelled'
       AND EXISTS (
           SELECT 1 FROM workflow_plan_v2_runs AS marker
           WHERE marker.run_id = OLD.id
       )
    THEN
        IF NOT EXISTS (
            SELECT 1
            FROM workflow_plan_v2_concurrency_cancellations AS cancellation
            WHERE cancellation.run_id = OLD.id
              AND cancellation.prior_workflow_status = OLD.status
              AND cancellation.prior_workflow_updated_at_ms = OLD.updated_at_ms
              AND cancellation.cancelled_at_ms = NEW.updated_at_ms
        ) THEN
            RAISE EXCEPTION 'WorkflowPlan-v2 cancellation lacks concurrency evidence'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
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
