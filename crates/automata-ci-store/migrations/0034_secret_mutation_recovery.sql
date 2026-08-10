-- Current-only bounded recovery for repository-secret provider mutations.
--
-- A reservation now fixes its exact provider version ordinal, hard confirmation
-- deadline, and reserving session/revision before provider I/O.  Expiry is
-- cancellation-only: it can never promote a staged candidate and hands any
-- encrypted winner to the existing cryptographic-erasure queue.

-- There is no trustworthy way to infer a deadline, reserving session, or an
-- attempt ordinal for an older receipt.  Refuse the upgrade without deleting
-- or rewriting terminal receipts; operators must explicitly drain pre-release
-- state and rerun the migration.
DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM secret_version_mutations) THEN
        RAISE EXCEPTION 'pre-recovery secret mutation receipts must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_mutation_recovery_current_only';
    END IF;
    IF EXISTS (SELECT 1 FROM secret_cleanup_outbox) THEN
        RAISE EXCEPTION 'pre-fence secret cleanup tasks must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_cleanup_generation_current_only';
    END IF;
END;
$automata$;

ALTER TABLE secret_version_mutations
    ADD COLUMN reserved_version_number BIGINT NOT NULL,
    ADD COLUMN confirmation_deadline_ms BIGINT NOT NULL,
    ADD COLUMN reserved_by_session_id UUID NOT NULL,
    ADD COLUMN reserved_authorization_revision BIGINT NOT NULL,
    ADD COLUMN terminal_actor_kind TEXT,
    ADD COLUMN confirmed_by_session_id UUID,
    ADD COLUMN confirmed_authorization_revision BIGINT,
    ADD COLUMN expiration_authority TEXT,
    ADD COLUMN abandoned_version_id UUID,
    ADD COLUMN abandoned_version_number BIGINT,
    ADD CONSTRAINT secret_version_mutations_reserver_session
        FOREIGN KEY (
            tenant_id, reserved_by_principal_id, reserved_by_session_id
        ) REFERENCES human_sessions(tenant_id, principal_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT secret_version_mutations_confirmer_session
        FOREIGN KEY (
            tenant_id, confirmed_by_principal_id, confirmed_by_session_id
        ) REFERENCES human_sessions(tenant_id, principal_id, id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT secret_version_mutations_abandoned_version
        FOREIGN KEY (
            tenant_id, abandoned_version_id, secret_id,
            abandoned_version_number
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number
        ) ON DELETE RESTRICT,
    ADD CONSTRAINT secret_version_mutations_reserved_version_unique
        UNIQUE (tenant_id, secret_id, reserved_version_number),
    ADD CONSTRAINT secret_version_mutations_reserved_authorization_positive
        CHECK (reserved_authorization_revision > 0),
    ADD CONSTRAINT secret_version_mutations_confirmed_authorization_positive
        CHECK (
            confirmed_authorization_revision IS NULL
            OR confirmed_authorization_revision > 0
        ),
    ADD CONSTRAINT secret_version_mutations_deadline_exact CHECK (
        confirmation_deadline_ms = reserved_at_ms + 600000
    ),
    ADD CONSTRAINT secret_version_mutations_terminal_actor CHECK (
        terminal_actor_kind IS NULL OR terminal_actor_kind IN ('human', 'system')
    ),
    ADD CONSTRAINT secret_version_mutations_expiration_authority CHECK (
        expiration_authority IS NULL
        OR expiration_authority IN ('current', 'lost')
    );

ALTER TABLE secret_version_mutations
    DROP CONSTRAINT secret_version_mutations_expectation_shape,
    DROP CONSTRAINT secret_version_mutations_completion_kind,
    DROP CONSTRAINT secret_version_mutations_state_shape;

ALTER TABLE secret_version_mutations
    ADD CONSTRAINT secret_version_mutations_expectation_shape CHECK ((
        (
            mutation_kind = 'create'
            AND expected_secret_revision IS NULL
            AND reserved_secret_revision = 1
            AND reserved_version_number = 1
            AND expected_predecessor_version_id IS NULL
            AND expected_predecessor_version_number IS NULL
            AND (requested_provider_id IS NULL OR requested_provider_id = provider_id)
        ) OR (
            mutation_kind = 'replace'
            AND expected_secret_revision > 0
            AND reserved_secret_revision = expected_secret_revision
            AND reserved_version_number > expected_predecessor_version_number
            AND expected_predecessor_version_id IS NOT NULL
            AND expected_predecessor_version_number > 0
            AND requested_provider_id IS NULL
        )
    ) IS TRUE),
    ADD CONSTRAINT secret_version_mutations_completion_kind CHECK (
        completion_kind IS NULL OR completion_kind IN (
            'builtin_created', 'cas_lost', 'system_cancelled',
            'reservation_expired'
        )
    ),
    ADD CONSTRAINT secret_version_mutations_state_shape CHECK ((
        (
            state = 'reserved'
            AND completion_kind IS NULL
            AND committed_version_id IS NULL
            AND committed_version_number IS NULL
            AND confirmed_secret_revision IS NULL
            AND confirmed_by_principal_id IS NULL
            AND confirmed_by_session_id IS NULL
            AND confirmed_authorization_revision IS NULL
            AND confirmed_at_ms IS NULL
            AND terminal_actor_kind IS NULL
            AND terminal_reason IS NULL
            AND expiration_authority IS NULL
            AND abandoned_version_id IS NULL
            AND abandoned_version_number IS NULL
        ) OR (
            state = 'confirmed'
            AND completion_kind = 'builtin_created'
            AND committed_version_id IS NOT NULL
            AND committed_version_number = reserved_version_number
            AND confirmed_secret_revision = reserved_secret_revision + 1
            AND confirmed_by_principal_id IS NOT NULL
            AND confirmed_by_session_id IS NOT NULL
            AND confirmed_authorization_revision IS NOT NULL
            AND confirmed_at_ms >= reserved_at_ms
            AND confirmed_at_ms < confirmation_deadline_ms
            AND terminal_actor_kind = 'human'
            AND terminal_reason IS NULL
            AND expiration_authority IS NULL
            AND abandoned_version_id IS NULL
            AND abandoned_version_number IS NULL
        ) OR (
            state = 'superseded'
            AND completion_kind = 'builtin_created'
            AND committed_version_id IS NOT NULL
            AND committed_version_number = reserved_version_number
            AND confirmed_secret_revision = reserved_secret_revision + 1
            AND confirmed_by_principal_id IS NOT NULL
            AND confirmed_by_session_id IS NOT NULL
            AND confirmed_authorization_revision IS NOT NULL
            AND confirmed_at_ms >= reserved_at_ms
            AND confirmed_at_ms < confirmation_deadline_ms
            AND terminal_actor_kind = 'human'
            AND terminal_reason IN (
                'applied_then_superseded', 'applied_then_deleted'
            )
            AND expiration_authority IS NULL
            AND abandoned_version_id IS NULL
            AND abandoned_version_number IS NULL
        ) OR (
            state = 'cancelled'
            AND completion_kind IN ('cas_lost', 'system_cancelled')
            AND committed_version_id IS NULL
            AND committed_version_number IS NULL
            AND confirmed_secret_revision IS NULL
            AND confirmed_by_principal_id IS NOT NULL
            AND confirmed_by_session_id IS NOT NULL
            AND confirmed_authorization_revision IS NOT NULL
            AND confirmed_at_ms >= reserved_at_ms
            AND terminal_actor_kind = 'human'
            AND (
                (
                    completion_kind = 'cas_lost'
                    AND confirmed_at_ms < confirmation_deadline_ms
                    AND terminal_reason = 'cas_lost'
                ) OR (
                    completion_kind = 'system_cancelled'
                    AND terminal_reason = 'secret_deleted'
                )
            )
            AND expiration_authority IS NULL
            AND abandoned_version_id IS NULL
            AND abandoned_version_number IS NULL
        ) OR (
            state = 'cancelled'
            AND completion_kind = 'reservation_expired'
            AND committed_version_id IS NULL
            AND committed_version_number IS NULL
            AND confirmed_secret_revision IS NULL
            AND confirmed_by_principal_id IS NULL
            AND confirmed_by_session_id IS NULL
            AND confirmed_authorization_revision IS NULL
            AND confirmed_at_ms >= confirmation_deadline_ms
            AND terminal_actor_kind = 'system'
            AND expiration_authority IN ('current', 'lost')
            AND (
                (
                    terminal_reason = 'reservation_expired_no_stage'
                    AND abandoned_version_id IS NULL
                    AND abandoned_version_number IS NULL
                ) OR (
                    terminal_reason = 'reservation_expired_staged'
                    AND abandoned_version_id IS NOT NULL
                    AND abandoned_version_number = reserved_version_number
                )
            )
        )
    ) IS TRUE);

-- The application and database independently derive the same domain-separated
-- UUIDv8 so a direct writer cannot substitute a second recovery identity for
-- one immutable mutation.
CREATE FUNCTION automata_secret_mutation_recovery_operation_id(TEXT, UUID)
RETURNS UUID
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
WITH raw(bytes) AS (
    SELECT substring(
        sha256(
            convert_to('automata.store.secret-mutation-recovery.v1', 'UTF8')
            || decode('00', 'hex')
            || int8send(octet_length(convert_to($1, 'UTF8'))::BIGINT)
            || convert_to($1, 'UTF8')
            || uuid_send($2)
        )
        FROM 1 FOR 16
    )
), shaped(bytes) AS (
    SELECT set_byte(
        set_byte(bytes, 6, (get_byte(bytes, 6) & 15) | 128),
        8,
        (get_byte(bytes, 8) & 63) | 128
    )
    FROM raw
), encoded(hex) AS (
    SELECT encode(bytes, 'hex') FROM shaped
)
SELECT (
    substring(hex FROM 1 FOR 8) || '-' ||
    substring(hex FROM 9 FOR 4) || '-' ||
    substring(hex FROM 13 FOR 4) || '-' ||
    substring(hex FROM 17 FOR 4) || '-' ||
    substring(hex FROM 21 FOR 12)
)::UUID
FROM encoded
$automata$;

CREATE TABLE secret_mutation_recovery_outbox (
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation_id UUID NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    mutation_id UUID NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_ms BIGINT NOT NULL,
    claim_generation BIGINT NOT NULL DEFAULT 0,
    locked_by TEXT,
    locked_at_ms BIGINT,
    completed_by TEXT,
    completed_claim_generation BIGINT,
    completed_locked_at_ms BIGINT,
    resolution TEXT,
    created_at_ms BIGINT NOT NULL,
    completed_at_ms BIGINT,
    CONSTRAINT secret_mutation_recovery_outbox_mutation
        FOREIGN KEY (tenant_id, mutation_id)
        REFERENCES secret_version_mutations(tenant_id, mutation_id)
        ON DELETE RESTRICT,
    CONSTRAINT secret_mutation_recovery_outbox_mutation_unique
        UNIQUE (tenant_id, mutation_id),
    CONSTRAINT secret_mutation_recovery_outbox_non_nil CHECK (
        operation_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT secret_mutation_recovery_outbox_operation_exact CHECK (
        operation_id = automata_secret_mutation_recovery_operation_id(
            tenant_id, mutation_id
        )
    ),
    CONSTRAINT secret_mutation_recovery_outbox_status CHECK (
        status IN ('pending', 'in_progress', 'completed')
    ),
    CONSTRAINT secret_mutation_recovery_outbox_time CHECK (
        next_attempt_at_ms >= created_at_ms
    ),
    CONSTRAINT secret_mutation_recovery_outbox_attempts CHECK (
        attempts BETWEEN 0 AND 1
    ),
    CONSTRAINT secret_mutation_recovery_outbox_generation CHECK (
        claim_generation >= 0
        AND (completed_claim_generation IS NULL OR completed_claim_generation > 0)
    ),
    CONSTRAINT secret_mutation_recovery_outbox_lock_shape CHECK ((
        (
            status = 'in_progress'
            AND attempts = 1
            AND claim_generation > 0
            AND octet_length(locked_by) BETWEEN 1 AND 255
            AND locked_by !~ '[[:cntrl:]]'
            AND locked_at_ms >= next_attempt_at_ms
            AND completed_at_ms IS NULL
            AND completed_by IS NULL
            AND completed_claim_generation IS NULL
            AND completed_locked_at_ms IS NULL
            AND resolution IS NULL
        ) OR (
            status = 'pending'
            AND attempts = 0
            AND claim_generation = 0
            AND locked_by IS NULL
            AND locked_at_ms IS NULL
            AND completed_at_ms IS NULL
            AND completed_by IS NULL
            AND completed_claim_generation IS NULL
            AND completed_locked_at_ms IS NULL
            AND resolution IS NULL
        ) OR (
            status = 'completed'
            AND completed_at_ms >= created_at_ms
            AND (
                (
                    resolution = 'human_terminal'
                    AND claim_generation >= 0
                    AND locked_by IS NULL
                    AND locked_at_ms IS NULL
                    AND completed_by IS NULL
                    AND completed_claim_generation IS NULL
                    AND completed_locked_at_ms IS NULL
                ) OR (
                    resolution IN (
                        'expired_without_stage', 'expired_with_cleanup'
                    )
                    AND attempts = 1
                    AND claim_generation > 0
                    AND locked_by IS NULL
                    AND locked_at_ms IS NULL
                    AND octet_length(completed_by) BETWEEN 1 AND 255
                    AND completed_by !~ '[[:cntrl:]]'
                    AND completed_claim_generation = claim_generation
                    AND completed_locked_at_ms >= next_attempt_at_ms
                )
            )
        )
    ) IS TRUE)
);

CREATE INDEX secret_mutation_recovery_outbox_ready
    ON secret_mutation_recovery_outbox (next_attempt_at_ms, sequence)
    WHERE status IN ('pending', 'in_progress');

ALTER TABLE secret_cleanup_outbox
    ADD COLUMN claim_generation BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT secret_cleanup_outbox_claim_generation CHECK (
        claim_generation >= 0
        AND claim_generation >= attempts
        AND (
            (attempts = 0 AND claim_generation = 0)
            OR (attempts > 0 AND claim_generation > 0)
        )
    ),
    ADD CONSTRAINT secret_cleanup_outbox_time_order CHECK (
        next_attempt_at_ms >= created_at_ms
    );

-- Outbox rows are durable receipts. They may only advance through the exact
-- application fence protocol; direct deletion, truncation, identity rewrites,
-- generation jumps, and completion without the owning claim are rejected.
CREATE FUNCTION automata_secret_mutation_recovery_transition_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    mutation_state TEXT;
    mutation_completion TEXT;
    mutation_reason TEXT;
    mutation_completed_at BIGINT;
    expected_resolution TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending'
           OR NEW.attempts <> 0
           OR NEW.claim_generation <> 0
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.completed_by IS NOT NULL
           OR NEW.completed_claim_generation IS NOT NULL
           OR NEW.completed_locked_at_ms IS NOT NULL
           OR NEW.resolution IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret mutation recovery must begin pending'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_initial_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.mutation_id IS DISTINCT FROM OLD.mutation_id
       OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'secret mutation recovery identity and timing are immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_mutation_recovery_identity_immutable';
    END IF;

    IF OLD.status = 'pending' AND NEW.status = 'in_progress' THEN
        IF OLD.attempts <> 0
           OR OLD.claim_generation <> 0
           OR NEW.attempts <> 1
           OR NEW.claim_generation <> 1
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms < OLD.next_attempt_at_ms
           OR NEW.completed_by IS NOT NULL
           OR NEW.completed_claim_generation IS NOT NULL
           OR NEW.completed_locked_at_ms IS NOT NULL
           OR NEW.resolution IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret mutation recovery initial claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_claim_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status = 'in_progress' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation + 1
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms <= OLD.locked_at_ms
           OR NEW.completed_by IS DISTINCT FROM OLD.completed_by
           OR NEW.completed_claim_generation IS DISTINCT FROM OLD.completed_claim_generation
           OR NEW.completed_locked_at_ms IS DISTINCT FROM OLD.completed_locked_at_ms
           OR NEW.resolution IS DISTINCT FROM OLD.resolution
           OR NEW.completed_at_ms IS DISTINCT FROM OLD.completed_at_ms THEN
            RAISE EXCEPTION 'secret mutation recovery takeover is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_takeover_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status IN ('pending', 'in_progress') AND NEW.status = 'completed' THEN
        SELECT state, completion_kind, terminal_reason, confirmed_at_ms
        INTO mutation_state, mutation_completion, mutation_reason, mutation_completed_at
        FROM secret_version_mutations
        WHERE tenant_id = OLD.tenant_id AND mutation_id = OLD.mutation_id;

        IF mutation_state IS NULL OR mutation_state = 'reserved'
           OR NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.completed_at_ms IS DISTINCT FROM mutation_completed_at THEN
            RAISE EXCEPTION 'secret mutation recovery completion has no exact terminal receipt'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_completion_exact';
        END IF;

        IF mutation_completion = 'reservation_expired' THEN
            expected_resolution := CASE mutation_reason
                WHEN 'reservation_expired_no_stage' THEN 'expired_without_stage'
                WHEN 'reservation_expired_staged' THEN 'expired_with_cleanup'
                ELSE NULL
            END;
            IF OLD.status <> 'in_progress'
               OR expected_resolution IS NULL
               OR NEW.resolution IS DISTINCT FROM expected_resolution
               OR NEW.completed_by IS DISTINCT FROM OLD.locked_by
               OR NEW.completed_claim_generation IS DISTINCT FROM OLD.claim_generation
               OR NEW.completed_locked_at_ms IS DISTINCT FROM OLD.locked_at_ms THEN
                RAISE EXCEPTION 'secret mutation recovery expiry is not fence-bound'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_mutation_recovery_expiry_fence_exact';
            END IF;
        ELSIF NEW.resolution IS DISTINCT FROM 'human_terminal'
              OR NEW.completed_by IS NOT NULL
              OR NEW.completed_claim_generation IS NOT NULL
              OR NEW.completed_locked_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'human terminal recovery closure is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_mutation_recovery_human_terminal_exact';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid secret mutation recovery transition'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_mutation_recovery_transition_exact';
END;
$automata$;

CREATE TRIGGER secret_mutation_recovery_transition_guard
BEFORE INSERT OR UPDATE ON secret_mutation_recovery_outbox
FOR EACH ROW
EXECUTE FUNCTION automata_secret_mutation_recovery_transition_guard();

CREATE FUNCTION automata_secret_mutation_recovery_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret mutation recovery receipts cannot be deleted'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_mutation_recovery_delete_forbidden';
END;
$automata$;

CREATE TRIGGER secret_mutation_recovery_delete_guard
BEFORE DELETE ON secret_mutation_recovery_outbox
FOR EACH ROW
EXECUTE FUNCTION automata_secret_mutation_recovery_delete_guard();

CREATE TRIGGER secret_mutation_recovery_truncate_guard
BEFORE TRUNCATE ON secret_mutation_recovery_outbox
FOR EACH STATEMENT
EXECUTE FUNCTION automata_secret_mutation_recovery_delete_guard();

CREATE FUNCTION automata_secret_cleanup_transition_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.operation_id = '00000000-0000-0000-0000-000000000000'::UUID
           OR NEW.status <> 'pending'
           OR NEW.attempts <> 0
           OR NEW.claim_generation <> 0
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.last_failure_kind IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL
           OR NEW.next_attempt_at_ms < NEW.created_at_ms THEN
            RAISE EXCEPTION 'secret cleanup must begin as an unfenced pending task'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_initial_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.cleanup_kind IS DISTINCT FROM OLD.cleanup_kind
       OR NEW.provider_lease_record_id IS DISTINCT FROM OLD.provider_lease_record_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.secret_version_id IS DISTINCT FROM OLD.secret_version_id
       OR NEW.version_number IS DISTINCT FROM OLD.version_number
       OR NEW.envelope_generation IS DISTINCT FROM OLD.envelope_generation
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'secret cleanup task identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_cleanup_identity_immutable';
    END IF;

    IF OLD.status = 'pending' AND NEW.status = 'in_progress' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts + 1
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation + 1
           OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
           OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms < OLD.next_attempt_at_ms
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret cleanup claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_claim_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status = 'in_progress' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation + 1
           OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
           OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
           OR octet_length(NEW.locked_by) NOT BETWEEN 1 AND 255
           OR NEW.locked_by ~ '[[:cntrl:]]'
           OR NEW.locked_at_ms <= OLD.locked_at_ms
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret cleanup takeover is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_takeover_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status IN ('pending', 'dead_letter') THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
           OR NEW.next_attempt_at_ms <= OLD.locked_at_ms
           OR NEW.next_attempt_at_ms > OLD.locked_at_ms + 86400000
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.last_failure_kind IS NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'secret cleanup retry is not fence-bound'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_retry_exact';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status = 'in_progress' AND NEW.status = 'completed' THEN
        IF NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
           OR NEW.next_attempt_at_ms IS DISTINCT FROM OLD.next_attempt_at_ms
           OR NEW.locked_by IS NOT NULL
           OR NEW.locked_at_ms IS NOT NULL
           OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
           OR NEW.completed_at_ms < OLD.locked_at_ms THEN
            RAISE EXCEPTION 'secret cleanup completion is not fence-bound'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_cleanup_completion_exact';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'invalid secret cleanup transition'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_cleanup_transition_exact';
END;
$automata$;

CREATE TRIGGER secret_cleanup_transition_guard
BEFORE INSERT OR UPDATE ON secret_cleanup_outbox
FOR EACH ROW
EXECUTE FUNCTION automata_secret_cleanup_transition_guard();

CREATE FUNCTION automata_secret_cleanup_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret cleanup receipts cannot be deleted'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_cleanup_delete_forbidden';
END;
$automata$;

CREATE TRIGGER secret_cleanup_delete_guard
BEFORE DELETE ON secret_cleanup_outbox
FOR EACH ROW
EXECUTE FUNCTION automata_secret_cleanup_delete_guard();

CREATE TRIGGER secret_cleanup_truncate_guard
BEFORE TRUNCATE ON secret_cleanup_outbox
FOR EACH STATEMENT
EXECUTE FUNCTION automata_secret_cleanup_delete_guard();

-- Every reservation must commit with exactly one recovery schedule, and every
-- terminal receipt must close that schedule.  The check is deferred so the
-- management transaction may insert/update the two rows in canonical order.
CREATE FUNCTION automata_secret_mutation_recovery_deferred_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    mutation_row secret_version_mutations%ROWTYPE;
    recovery_row secret_mutation_recovery_outbox%ROWTYPE;
BEGIN
    SELECT * INTO mutation_row
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id;

    SELECT * INTO recovery_row
    FROM secret_mutation_recovery_outbox
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id;

    IF mutation_row.mutation_id IS NULL
       OR recovery_row.mutation_id IS NULL
       OR recovery_row.created_at_ms <> mutation_row.reserved_at_ms
       OR recovery_row.next_attempt_at_ms <> mutation_row.confirmation_deadline_ms
       OR (
           mutation_row.state = 'reserved'
           AND recovery_row.status NOT IN ('pending', 'in_progress')
       )
       OR (
           mutation_row.state <> 'reserved'
           AND recovery_row.status <> 'completed'
       ) THEN
        RAISE EXCEPTION 'secret mutation recovery schedule is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_mutation_recovery_schedule_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER secret_mutation_recovery_mutation_guard
AFTER INSERT OR UPDATE ON secret_version_mutations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_secret_mutation_recovery_deferred_guard();

CREATE CONSTRAINT TRIGGER secret_mutation_recovery_outbox_guard
AFTER INSERT OR UPDATE ON secret_mutation_recovery_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_secret_mutation_recovery_deferred_guard();

CREATE FUNCTION automata_complete_secret_mutation_recovery()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    recovery_resolution TEXT;
BEGIN
    IF OLD.state <> 'reserved' OR NEW.state = 'reserved' THEN
        RETURN NEW;
    END IF;

    recovery_resolution := CASE
        WHEN NEW.completion_kind = 'reservation_expired'
             AND NEW.abandoned_version_id IS NULL
            THEN 'expired_without_stage'
        WHEN NEW.completion_kind = 'reservation_expired'
            THEN 'expired_with_cleanup'
        ELSE 'human_terminal'
    END;

    UPDATE secret_mutation_recovery_outbox
    SET status = 'completed',
        completed_by = CASE
            WHEN recovery_resolution = 'human_terminal' THEN NULL ELSE locked_by
        END,
        completed_claim_generation = CASE
            WHEN recovery_resolution = 'human_terminal' THEN NULL ELSE claim_generation
        END,
        completed_locked_at_ms = CASE
            WHEN recovery_resolution = 'human_terminal' THEN NULL ELSE locked_at_ms
        END,
        locked_by = NULL, locked_at_ms = NULL,
        resolution = recovery_resolution,
        completed_at_ms = NEW.confirmed_at_ms
    WHERE tenant_id = NEW.tenant_id
      AND mutation_id = NEW.mutation_id
      AND status IN ('pending', 'in_progress');

    IF NOT FOUND THEN
        RAISE EXCEPTION 'terminal secret mutation has no open recovery schedule'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_mutation_recovery_terminal_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_mutation_recovery_complete_on_terminal
AFTER UPDATE ON secret_version_mutations
FOR EACH ROW
EXECUTE FUNCTION automata_complete_secret_mutation_recovery();

-- Allocate immutable attempt ordinals under the logical-secret lock.  Failed
-- or erased attempts remain in the ledger, so later attempts deliberately
-- leave gaps instead of trying to reuse an abandoned `secret_versions` key.
CREATE FUNCTION automata_secret_mutation_recovery_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    greatest_reserved_number BIGINT;
    session_revision BIGINT;
    session_principal UUID;
BEGIN
    SELECT authorization_revision, principal_id
    INTO session_revision, session_principal
    FROM human_sessions
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.reserved_by_session_id
    FOR SHARE;

    IF session_principal IS DISTINCT FROM NEW.reserved_by_principal_id
       OR session_revision IS DISTINCT FROM NEW.reserved_authorization_revision THEN
        RAISE EXCEPTION 'secret mutation reserver evidence is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_reserver_exact';
    END IF;

    SELECT max(reserved_version_number)
    INTO greatest_reserved_number
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id;

    IF (
        NEW.mutation_kind = 'create'
        AND (greatest_reserved_number IS NOT NULL OR NEW.reserved_version_number <> 1)
    ) OR (
        NEW.mutation_kind = 'replace'
        AND (
            greatest_reserved_number < NEW.expected_predecessor_version_number
            OR NEW.reserved_version_number IS DISTINCT FROM CASE
                WHEN greatest_reserved_number < 9223372036854775807
                    THEN greatest_reserved_number + 1
                ELSE NULL
            END
        )
    ) THEN
        RAISE EXCEPTION 'secret mutation version reservation is not the next attempt ordinal'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_reserved_version_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_mutation_recovery_insert_guard
BEFORE INSERT ON secret_version_mutations
FOR EACH ROW
EXECUTE FUNCTION automata_secret_mutation_recovery_insert_guard();

-- A provider winner is accepted only at the preallocated ordinal.  For a
-- replacement the current predecessor remains an exact identity, but no
-- adjacency assumption is made because erased attempts leave durable gaps.
CREATE OR REPLACE FUNCTION automata_secret_version_lifecycle_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
    version_row secret_versions%ROWTYPE;
    predecessor_status TEXT;
    predecessor_receipt_count BIGINT;
BEGIN
    IF NEW.mutation_id IS NULL OR NEW.status <> 'staged' THEN
        RAISE EXCEPTION 'new secret versions must begin as a staged mutation candidate'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_initial_staged';
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
    FOR UPDATE;

    SELECT * INTO mutation_row
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id
    FOR SHARE;

    SELECT * INTO version_row
    FROM secret_versions
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_version_id
    FOR SHARE;

    IF secret_row.id IS NULL
       OR mutation_row.mutation_id IS NULL
       OR version_row.id IS NULL
       OR mutation_row.state <> 'reserved'
       OR mutation_row.secret_id <> NEW.secret_id
       OR mutation_row.provider_id <> NEW.provider_id
       OR mutation_row.reserved_version_number <> NEW.version_number
       OR mutation_row.provider_create_request_id <> version_row.create_request_id
       OR version_row.secret_id <> NEW.secret_id
       OR version_row.version_number <> NEW.version_number
       OR version_row.provider_id <> NEW.provider_id
       OR version_row.storage_kind <> 'built_in_ciphertext'
       OR secret_row.scope_kind <> mutation_row.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM mutation_row.repository_id
       OR secret_row.environment_id IS DISTINCT FROM mutation_row.environment_id
       OR secret_row.canonical_name <> mutation_row.canonical_name
       OR secret_row.provider_id <> mutation_row.provider_id THEN
        RAISE EXCEPTION 'staged secret version is not joined to its exact intent'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_staged_intent_exact';
    END IF;

    IF mutation_row.mutation_kind = 'create' THEN
        IF NEW.version_number <> 1
           OR secret_row.status <> 'provisioning'
           OR secret_row.revision <> mutation_row.reserved_secret_revision
           OR secret_row.current_version_id IS NOT NULL
           OR secret_row.current_version_number IS NOT NULL THEN
            RAISE EXCEPTION 'staged creation candidate has a stale descriptor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_staged_head';
        END IF;
    ELSE
        SELECT status INTO predecessor_status
        FROM secret_version_lifecycle
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = mutation_row.expected_predecessor_version_id
        FOR SHARE;

        SELECT count(*) INTO predecessor_receipt_count
        FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id
          AND secret_id = NEW.secret_id
          AND state = 'confirmed'
          AND completion_kind = 'builtin_created'
          AND committed_version_id = mutation_row.expected_predecessor_version_id
          AND committed_version_number = mutation_row.expected_predecessor_version_number;

        IF secret_row.status <> 'active'
           OR secret_row.revision <> mutation_row.reserved_secret_revision
           OR secret_row.current_version_id IS DISTINCT FROM mutation_row.expected_predecessor_version_id
           OR secret_row.current_version_number IS DISTINCT FROM mutation_row.expected_predecessor_version_number
           OR NEW.version_number <> mutation_row.reserved_version_number
           OR NEW.version_number <= mutation_row.expected_predecessor_version_number
           OR predecessor_status IS DISTINCT FROM 'active'
           OR predecessor_receipt_count <> 1 THEN
            RAISE EXCEPTION 'staged replacement candidate has a stale predecessor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_staged_head';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

-- Terminal receipts retain their exact human actor evidence.  Recovery is the
-- sole system terminal and may only cancel; it records whether the original
-- authority was still current without changing the outcome.
CREATE OR REPLACE FUNCTION automata_secret_version_mutation_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    winner_row secret_versions%ROWTYPE;
    winner_lifecycle secret_version_lifecycle%ROWTYPE;
    builtin_head_count BIGINT;
    external_reference_count BIGINT;
    confirmer_principal UUID;
    confirmer_revision BIGINT;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.mutation_id IS DISTINCT FROM OLD.mutation_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
       OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
       OR NEW.canonical_name IS DISTINCT FROM OLD.canonical_name
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.requested_provider_id IS DISTINCT FROM OLD.requested_provider_id
       OR NEW.mutation_kind IS DISTINCT FROM OLD.mutation_kind
       OR NEW.expected_secret_revision IS DISTINCT FROM OLD.expected_secret_revision
       OR NEW.reserved_secret_revision IS DISTINCT FROM OLD.reserved_secret_revision
       OR NEW.reserved_version_number IS DISTINCT FROM OLD.reserved_version_number
       OR NEW.confirmation_deadline_ms IS DISTINCT FROM OLD.confirmation_deadline_ms
       OR NEW.expected_predecessor_version_id IS DISTINCT FROM OLD.expected_predecessor_version_id
       OR NEW.expected_predecessor_version_number IS DISTINCT FROM OLD.expected_predecessor_version_number
       OR NEW.provider_create_request_id IS DISTINCT FROM OLD.provider_create_request_id
       OR NEW.reserved_by_principal_id IS DISTINCT FROM OLD.reserved_by_principal_id
       OR NEW.reserved_by_session_id IS DISTINCT FROM OLD.reserved_by_session_id
       OR NEW.reserved_authorization_revision IS DISTINCT FROM OLD.reserved_authorization_revision
       OR NEW.reserved_at_ms IS DISTINCT FROM OLD.reserved_at_ms THEN
        RAISE EXCEPTION 'secret version mutation intent is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_intent_immutable';
    END IF;

    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'secret version mutation updates require exact CAS'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_revision_cas';
    END IF;

    IF NOT (
        (OLD.state = 'reserved' AND NEW.state IN ('confirmed', 'cancelled'))
        OR (OLD.state = 'confirmed' AND NEW.state = 'superseded')
    ) THEN
        RAISE EXCEPTION 'invalid secret version mutation transition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_transition';
    END IF;

    IF OLD.state = 'confirmed' AND (
        NEW.completion_kind IS DISTINCT FROM OLD.completion_kind
        OR NEW.committed_version_id IS DISTINCT FROM OLD.committed_version_id
        OR NEW.committed_version_number IS DISTINCT FROM OLD.committed_version_number
        OR NEW.confirmed_secret_revision IS DISTINCT FROM OLD.confirmed_secret_revision
        OR NEW.confirmed_by_principal_id IS DISTINCT FROM OLD.confirmed_by_principal_id
        OR NEW.confirmed_by_session_id IS DISTINCT FROM OLD.confirmed_by_session_id
        OR NEW.confirmed_authorization_revision IS DISTINCT FROM OLD.confirmed_authorization_revision
        OR NEW.confirmed_at_ms IS DISTINCT FROM OLD.confirmed_at_ms
        OR NEW.terminal_actor_kind IS DISTINCT FROM OLD.terminal_actor_kind
        OR NEW.expiration_authority IS DISTINCT FROM OLD.expiration_authority
        OR NEW.abandoned_version_id IS DISTINCT FROM OLD.abandoned_version_id
        OR NEW.abandoned_version_number IS DISTINCT FROM OLD.abandoned_version_number
    ) THEN
        RAISE EXCEPTION 'confirmed secret version receipt is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_receipt_immutable';
    END IF;

    IF OLD.state = 'reserved' AND NEW.terminal_actor_kind = 'human' THEN
        SELECT principal_id, authorization_revision
        INTO confirmer_principal, confirmer_revision
        FROM human_sessions
        WHERE tenant_id = NEW.tenant_id
          AND id = NEW.confirmed_by_session_id
        FOR SHARE;
        IF confirmer_principal IS DISTINCT FROM NEW.confirmed_by_principal_id
           OR confirmer_revision IS DISTINCT FROM NEW.confirmed_authorization_revision THEN
            RAISE EXCEPTION 'secret mutation confirmer evidence is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_confirmer_exact';
        END IF;
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
    FOR UPDATE;

    IF secret_row.id IS NULL
       OR secret_row.scope_kind <> NEW.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM NEW.repository_id
       OR secret_row.environment_id IS DISTINCT FROM NEW.environment_id
       OR secret_row.canonical_name <> NEW.canonical_name
       OR secret_row.provider_id <> NEW.provider_id THEN
        RAISE EXCEPTION 'secret version mutation lost its exact descriptor'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_descriptor_exact';
    END IF;

    IF NEW.completion_kind = 'builtin_created' THEN
        IF NEW.provider_id <> 'builtin'
           OR NEW.committed_version_id IS NULL
           OR NEW.committed_version_id =
              '00000000-0000-0000-0000-000000000000'::UUID THEN
            RAISE EXCEPTION 'built-in mutation receipt has no exact winner'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_winner_exact';
        END IF;

        SELECT * INTO winner_row
        FROM secret_versions
        WHERE tenant_id = NEW.tenant_id
          AND provider_id = NEW.provider_id
          AND create_request_id = NEW.provider_create_request_id
        FOR SHARE;
        SELECT * INTO winner_lifecycle
        FROM secret_version_lifecycle
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = NEW.committed_version_id
        FOR SHARE;

        SELECT count(*) INTO builtin_head_count
        FROM secret_version_envelope_heads AS head
        JOIN secret_version_envelopes AS envelope
          ON envelope.tenant_id = head.tenant_id
         AND envelope.secret_version_id = head.secret_version_id
         AND envelope.envelope_generation = head.envelope_generation
        WHERE head.tenant_id = NEW.tenant_id
          AND head.secret_version_id = NEW.committed_version_id;

        SELECT
            (SELECT count(*) FROM secret_provider_locator_envelopes
             WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
          + (SELECT count(*) FROM secret_provider_locator_envelope_heads
             WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
          + (SELECT count(*) FROM secret_provider_version_envelopes
             WHERE tenant_id = NEW.tenant_id
               AND secret_version_id = NEW.committed_version_id)
          + (SELECT count(*) FROM secret_provider_version_envelope_heads
             WHERE tenant_id = NEW.tenant_id
               AND secret_version_id = NEW.committed_version_id)
        INTO external_reference_count;

        IF winner_row.id IS NULL
           OR winner_row.id IS DISTINCT FROM NEW.committed_version_id
           OR winner_row.secret_id <> NEW.secret_id
           OR winner_row.version_number IS DISTINCT FROM NEW.reserved_version_number
           OR NEW.committed_version_number IS DISTINCT FROM NEW.reserved_version_number
           OR winner_row.storage_kind <> 'built_in_ciphertext'
           OR winner_lifecycle.secret_version_id IS NULL
           OR winner_lifecycle.mutation_id IS DISTINCT FROM NEW.mutation_id
           OR builtin_head_count <> 1
           OR external_reference_count <> 0 THEN
            RAISE EXCEPTION 'secret version mutation winner is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_winner_exact';
        END IF;

        IF NEW.mutation_kind = 'create' THEN
            IF winner_row.version_number <> 1 THEN
                RAISE EXCEPTION 'secret creation winner has a predecessor'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_predecessor';
            END IF;
        ELSIF winner_row.version_number <= NEW.expected_predecessor_version_number THEN
            RAISE EXCEPTION 'secret replacement winner has the wrong predecessor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_winner_predecessor';
        END IF;

        IF NEW.state = 'confirmed' THEN
            IF secret_row.status <> 'active'
               OR secret_row.current_version_id IS DISTINCT FROM winner_row.id
               OR secret_row.current_version_number IS DISTINCT FROM winner_row.version_number
               OR secret_row.revision <> NEW.reserved_secret_revision + 1
               OR NEW.confirmed_secret_revision <> NEW.reserved_secret_revision + 1
               OR winner_lifecycle.status <> 'active' THEN
                RAISE EXCEPTION 'confirmed mutation winner is not current'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_head';
            END IF;
        ELSIF NEW.terminal_reason = 'applied_then_superseded' THEN
            IF secret_row.status NOT IN ('active', 'disabled')
               OR secret_row.current_version_number <= winner_row.version_number
               OR winner_lifecycle.status <> 'superseded' THEN
                RAISE EXCEPTION 'superseded mutation winner has the wrong head'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_head';
            END IF;
        ELSIF NEW.terminal_reason = 'applied_then_deleted' THEN
            IF secret_row.status <> 'deleted'
               OR winner_lifecycle.status NOT IN (
                    'active', 'superseded', 'disabled',
                    'destroy_pending', 'destroyed'
               ) THEN
                RAISE EXCEPTION 'deleted mutation winner has the wrong lifecycle'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_head';
            END IF;
        END IF;
    ELSIF NEW.completion_kind = 'cas_lost' THEN
        IF EXISTS (
            SELECT 1 FROM secret_versions
            WHERE tenant_id = NEW.tenant_id
              AND provider_id = NEW.provider_id
              AND create_request_id = NEW.provider_create_request_id
        ) OR secret_row.status = 'deleted' OR NOT (
            (NEW.mutation_kind = 'create' AND (
                secret_row.status <> 'provisioning'
                OR secret_row.revision <> NEW.reserved_secret_revision
                OR secret_row.current_version_id IS NOT NULL
                OR secret_row.current_version_number IS NOT NULL
            )) OR
            (NEW.mutation_kind = 'replace' AND (
                secret_row.status <> 'active'
                OR secret_row.revision <> NEW.reserved_secret_revision
                OR secret_row.current_version_id IS DISTINCT FROM NEW.expected_predecessor_version_id
                OR secret_row.current_version_number IS DISTINCT FROM NEW.expected_predecessor_version_number
            ))
        ) THEN
            RAISE EXCEPTION 'secret version mutation has not definitively lost CAS'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_cas_lost';
        END IF;
    ELSIF NEW.completion_kind = 'system_cancelled' THEN
        IF EXISTS (
            SELECT 1
            FROM secret_versions AS version
            LEFT JOIN secret_version_lifecycle AS lifecycle
              ON lifecycle.tenant_id = version.tenant_id
             AND lifecycle.secret_version_id = version.id
            WHERE version.tenant_id = NEW.tenant_id
              AND version.provider_id = NEW.provider_id
              AND version.create_request_id = NEW.provider_create_request_id
              AND (
                  lifecycle.mutation_id IS DISTINCT FROM NEW.mutation_id
                  OR lifecycle.status NOT IN ('staged', 'destroy_pending', 'destroyed')
              )
        ) THEN
            RAISE EXCEPTION 'applied mutation cannot be recorded as cancelled'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_cancelled_unapplied';
        END IF;
    ELSIF NEW.completion_kind = 'reservation_expired' THEN
        IF NEW.confirmed_at_ms < NEW.confirmation_deadline_ms THEN
            RAISE EXCEPTION 'secret mutation cannot expire before its hard deadline'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_expiry_deadline';
        END IF;
        IF NEW.abandoned_version_id IS NULL THEN
            IF EXISTS (
                SELECT 1 FROM secret_versions
                WHERE tenant_id = NEW.tenant_id
                  AND provider_id = NEW.provider_id
                  AND create_request_id = NEW.provider_create_request_id
            ) THEN
                RAISE EXCEPTION 'expired mutation omitted its staged candidate'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_candidate';
            END IF;
        ELSE
            SELECT * INTO winner_row
            FROM secret_versions
            WHERE tenant_id = NEW.tenant_id
              AND provider_id = NEW.provider_id
              AND create_request_id = NEW.provider_create_request_id
            FOR SHARE;
            SELECT * INTO winner_lifecycle
            FROM secret_version_lifecycle
            WHERE tenant_id = NEW.tenant_id
              AND secret_version_id = NEW.abandoned_version_id
            FOR SHARE;
            IF winner_row.id IS NULL
               OR winner_row.id IS DISTINCT FROM NEW.abandoned_version_id
               OR winner_row.secret_id <> NEW.secret_id
               OR winner_row.version_number IS DISTINCT FROM NEW.reserved_version_number
               OR winner_lifecycle.mutation_id IS DISTINCT FROM NEW.mutation_id
               OR winner_lifecycle.status <> 'staged' THEN
                RAISE EXCEPTION 'expired mutation candidate is not exact and staged'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_candidate';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE OR REPLACE FUNCTION automata_secret_version_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
    cleanup_is_valid BOOLEAN;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.secret_version_id IS DISTINCT FROM OLD.secret_version_id
       OR NEW.secret_id IS DISTINCT FROM OLD.secret_id
       OR NEW.version_number IS DISTINCT FROM OLD.version_number
       OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR NEW.mutation_id IS DISTINCT FROM OLD.mutation_id THEN
        RAISE EXCEPTION 'secret version lifecycle identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_identity_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1
       OR NEW.changed_at_ms < OLD.changed_at_ms THEN
        RAISE EXCEPTION 'secret version lifecycle updates require monotonic CAS'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_cas';
    END IF;
    IF OLD.destroy_request_id IS NOT NULL
       AND NEW.destroy_request_id IS DISTINCT FROM OLD.destroy_request_id THEN
        RAISE EXCEPTION 'secret version destroy request identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_destroy_request_immutable';
    END IF;
    IF NOT (
        (OLD.status = 'staged' AND NEW.status IN ('active', 'destroy_pending'))
        OR (OLD.status = 'active' AND NEW.status IN ('superseded', 'disabled', 'destroy_pending'))
        OR (OLD.status = 'superseded' AND NEW.status IN ('disabled', 'destroy_pending'))
        OR (OLD.status = 'disabled' AND NEW.status IN ('active', 'destroy_pending'))
        OR (OLD.status = 'destroy_pending' AND NEW.status = 'destroyed')
    ) THEN
        RAISE EXCEPTION 'invalid secret version lifecycle transition'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_transition';
    END IF;

    IF OLD.status = 'staged' THEN
        SELECT * INTO secret_row
        FROM secrets
        WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
        FOR UPDATE;
        SELECT * INTO mutation_row
        FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id
        FOR SHARE;

        IF NEW.status = 'active' THEN
            IF mutation_row.state <> 'reserved'
               OR NEW.version_number <> mutation_row.reserved_version_number
               OR secret_row.status <> (CASE mutation_row.mutation_kind
                   WHEN 'create' THEN 'provisioning' ELSE 'active' END)
               OR secret_row.revision <> mutation_row.reserved_secret_revision
               OR secret_row.current_version_id IS DISTINCT FROM mutation_row.expected_predecessor_version_id
               OR secret_row.current_version_number IS DISTINCT FROM mutation_row.expected_predecessor_version_number THEN
                RAISE EXCEPTION 'staged candidate promotion lost its reservation CAS'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_lifecycle_staged_promotion';
            END IF;
        ELSE
            cleanup_is_valid := (
                mutation_row.state = 'cancelled'
                AND (
                    (
                        mutation_row.completion_kind = 'system_cancelled'
                        AND mutation_row.terminal_reason = 'secret_deleted'
                        AND secret_row.status = 'deleted'
                    ) OR (
                        mutation_row.completion_kind = 'reservation_expired'
                        AND mutation_row.terminal_reason = 'reservation_expired_staged'
                        AND mutation_row.abandoned_version_id = NEW.secret_version_id
                        AND mutation_row.abandoned_version_number = NEW.version_number
                        AND (
                            (
                                mutation_row.mutation_kind = 'create'
                                AND secret_row.status = 'deleted'
                                AND secret_row.current_version_id IS NULL
                                AND secret_row.current_version_number IS NULL
                            ) OR (
                                mutation_row.mutation_kind = 'replace'
                                AND secret_row.status IN ('active', 'disabled')
                                AND secret_row.current_version_id IS DISTINCT FROM NEW.secret_version_id
                            )
                        )
                    )
                )
            );
            IF cleanup_is_valid IS NOT TRUE THEN
                RAISE EXCEPTION 'staged candidate cleanup requires exact cancellation'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_lifecycle_staged_cleanup';
            END IF;
        END IF;
    END IF;

    IF NEW.status = 'destroyed'
       AND (
           EXISTS (
               SELECT 1 FROM secret_version_envelopes
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_version_envelope_heads
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_provider_version_envelopes
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
           OR EXISTS (
               SELECT 1 FROM secret_provider_version_envelope_heads
               WHERE tenant_id = NEW.tenant_id
                 AND secret_version_id = NEW.secret_version_id
           )
       ) THEN
        RAISE EXCEPTION 'cryptographic material must be removed before destroy completes'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_crypto_destroyed';
    END IF;
    RETURN NEW;
END;
$automata$;

-- Deletion callers must first close every reservation with the exact current
-- human session.  This trigger prevents a direct descriptor update from
-- fabricating that missing authority evidence.
CREATE OR REPLACE FUNCTION automata_cancel_secret_version_mutations_on_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.status = 'deleted' OR NEW.status <> 'deleted' THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1 FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id
          AND secret_id = NEW.id
          AND state = 'reserved'
    ) THEN
        RAISE EXCEPTION 'secret deletion requires exact terminal mutation receipts'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_delete_terminal';
    END IF;

    UPDATE secret_version_mutations
    SET state = 'superseded',
        terminal_reason = 'applied_then_deleted',
        revision = revision + 1
    WHERE tenant_id = NEW.tenant_id
      AND secret_id = NEW.id
      AND state = 'confirmed';
    RETURN NEW;
END;
$automata$;

CREATE FUNCTION automata_secret_mutation_terminal_deferred_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    lifecycle_status TEXT;
BEGIN
    IF NEW.state <> 'cancelled' THEN
        RETURN NULL;
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id;

    IF NEW.completion_kind = 'system_cancelled' THEN
        IF secret_row.status IS DISTINCT FROM 'deleted' THEN
            RAISE EXCEPTION 'deletion cancellation committed without deleted descriptor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_delete_terminal';
        END IF;
    ELSIF NEW.completion_kind = 'reservation_expired' THEN
        IF NEW.abandoned_version_id IS NOT NULL THEN
            SELECT status INTO lifecycle_status
            FROM secret_version_lifecycle
            WHERE tenant_id = NEW.tenant_id
              AND secret_version_id = NEW.abandoned_version_id;
            IF lifecycle_status NOT IN ('destroy_pending', 'destroyed') THEN
                RAISE EXCEPTION 'expired staged candidate was not handed to erasure'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_cleanup';
            END IF;
        END IF;

        IF NEW.mutation_kind = 'create' THEN
            IF secret_row.status IS DISTINCT FROM 'deleted'
               OR secret_row.current_version_id IS NOT NULL
               OR secret_row.current_version_number IS NOT NULL THEN
                RAISE EXCEPTION 'expired creation retained a live descriptor'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_expiry_descriptor';
            END IF;
        ELSIF secret_row.status NOT IN ('active', 'disabled')
              OR (
                  NEW.abandoned_version_id IS NOT NULL
                  AND secret_row.current_version_id = NEW.abandoned_version_id
              ) THEN
            RAISE EXCEPTION 'expired replacement changed the logical head'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_expiry_descriptor';
        END IF;
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER secret_version_mutations_terminal_deferred_guard
AFTER UPDATE ON secret_version_mutations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_secret_mutation_terminal_deferred_guard();

CREATE OR REPLACE FUNCTION automata_secret_version_lifecycle_deferred_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
    builtin_head_count BIGINT;
    external_reference_count BIGINT;
    expired_cleanup BOOLEAN;
BEGIN
    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id;
    SELECT * INTO mutation_row
    FROM secret_version_mutations
    WHERE tenant_id = NEW.tenant_id AND mutation_id = NEW.mutation_id;

    SELECT count(*) INTO builtin_head_count
    FROM secret_version_envelope_heads AS head
    JOIN secret_version_envelopes AS envelope
      ON envelope.tenant_id = head.tenant_id
     AND envelope.secret_version_id = head.secret_version_id
     AND envelope.envelope_generation = head.envelope_generation
    WHERE head.tenant_id = NEW.tenant_id
      AND head.secret_version_id = NEW.secret_version_id;

    SELECT
        (SELECT count(*) FROM secret_provider_locator_envelopes
         WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
      + (SELECT count(*) FROM secret_provider_locator_envelope_heads
         WHERE tenant_id = NEW.tenant_id AND secret_id = NEW.secret_id)
      + (SELECT count(*) FROM secret_provider_version_envelopes
         WHERE tenant_id = NEW.tenant_id
           AND secret_version_id = NEW.secret_version_id)
      + (SELECT count(*) FROM secret_provider_version_envelope_heads
         WHERE tenant_id = NEW.tenant_id
           AND secret_version_id = NEW.secret_version_id)
    INTO external_reference_count;

    IF secret_row.id IS NULL
       OR mutation_row.mutation_id IS NULL
       OR mutation_row.secret_id <> NEW.secret_id
       OR mutation_row.provider_id <> NEW.provider_id
       OR mutation_row.reserved_version_number <> NEW.version_number
       OR secret_row.scope_kind <> mutation_row.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM mutation_row.repository_id
       OR secret_row.environment_id IS DISTINCT FROM mutation_row.environment_id
       OR secret_row.canonical_name <> mutation_row.canonical_name
       OR builtin_head_count <> (CASE WHEN NEW.status = 'destroyed' THEN 0 ELSE 1 END)
       OR external_reference_count <> 0 THEN
        RAISE EXCEPTION 'secret lifecycle lost its exact encrypted mutation join'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_lifecycle_deferred_exact';
    END IF;

    IF NEW.status = 'staged' THEN
        IF mutation_row.state <> 'reserved'
           OR secret_row.revision <> mutation_row.reserved_secret_revision
           OR secret_row.current_version_id IS DISTINCT FROM mutation_row.expected_predecessor_version_id
           OR secret_row.current_version_number IS DISTINCT FROM mutation_row.expected_predecessor_version_number THEN
            RAISE EXCEPTION 'staged lifecycle committed without its reservation'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    ELSIF NEW.status IN ('active', 'disabled') THEN
        IF mutation_row.state <> 'confirmed'
           OR mutation_row.committed_version_id IS DISTINCT FROM NEW.secret_version_id
           OR mutation_row.committed_version_number IS DISTINCT FROM NEW.version_number
           OR mutation_row.confirmed_secret_revision <> mutation_row.reserved_secret_revision + 1
           OR secret_row.status IS DISTINCT FROM NEW.status
           OR secret_row.current_version_id IS DISTINCT FROM NEW.secret_version_id
           OR secret_row.current_version_number IS DISTINCT FROM NEW.version_number THEN
            RAISE EXCEPTION 'active lifecycle committed without its exact receipt'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    ELSIF NEW.status = 'superseded' THEN
        IF mutation_row.state <> 'superseded'
           OR mutation_row.committed_version_id IS DISTINCT FROM NEW.secret_version_id
           OR mutation_row.committed_version_number IS DISTINCT FROM NEW.version_number
           OR mutation_row.terminal_reason NOT IN (
                'applied_then_superseded', 'applied_then_deleted'
           )
           OR (
               mutation_row.terminal_reason = 'applied_then_superseded'
               AND (
                   secret_row.status NOT IN ('active', 'disabled')
                   OR secret_row.current_version_number <= NEW.version_number
               )
           )
           OR (
               mutation_row.terminal_reason = 'applied_then_deleted'
               AND secret_row.status <> 'deleted'
           ) THEN
            RAISE EXCEPTION 'superseded lifecycle committed without its exact receipt'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    ELSIF NEW.status IN ('destroy_pending', 'destroyed') THEN
        expired_cleanup := (
            mutation_row.state = 'cancelled'
            AND mutation_row.completion_kind = 'reservation_expired'
            AND mutation_row.terminal_reason = 'reservation_expired_staged'
            AND mutation_row.abandoned_version_id = NEW.secret_version_id
            AND mutation_row.abandoned_version_number = NEW.version_number
            AND (
                (
                    mutation_row.mutation_kind = 'create'
                    AND secret_row.status = 'deleted'
                    AND secret_row.current_version_id IS NULL
                    AND secret_row.current_version_number IS NULL
                ) OR (
                    mutation_row.mutation_kind = 'replace'
                    AND secret_row.status IN ('active', 'disabled')
                    AND secret_row.current_version_id IS DISTINCT FROM NEW.secret_version_id
                )
            )
        );
        IF NOT (
            (
                secret_row.status = 'deleted'
                AND (
                    (
                        mutation_row.state = 'cancelled'
                        AND mutation_row.completion_kind = 'system_cancelled'
                        AND mutation_row.terminal_reason = 'secret_deleted'
                    ) OR (
                        mutation_row.state = 'superseded'
                        AND mutation_row.completion_kind = 'builtin_created'
                        AND mutation_row.terminal_reason IN (
                            'applied_then_superseded', 'applied_then_deleted'
                        )
                    )
                )
            ) OR expired_cleanup
        ) THEN
            RAISE EXCEPTION 'destroy lifecycle committed without exact terminalization'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    END IF;
    RETURN NULL;
END;
$automata$;
