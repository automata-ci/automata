-- Provider webhook acknowledgements precede parsing, workflow discovery, blob
-- reads, and admission. This inbox retains exact immutable request/object
-- evidence while expiring fences ensure only one live worker may commit a
-- transition. No transaction in this schema is intended to cross network or
-- object-store I/O.

CREATE TABLE provider_delivery_inbox (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    provider TEXT COLLATE "C" NOT NULL,
    connection_id UUID NOT NULL,
    installation_id BIGINT NOT NULL,
    provider_repository_id BIGINT NOT NULL,
    repository_visibility TEXT COLLATE "C" NOT NULL,
    repository_identity TEXT COLLATE "C" NOT NULL,
    delivery_id TEXT COLLATE "C" NOT NULL,
    request_digest BYTEA NOT NULL,
    raw_event_digest BYTEA NOT NULL,
    raw_event_object_key TEXT COLLATE "C" NOT NULL,
    raw_event_size_bytes BIGINT NOT NULL,
    raw_event_media_type TEXT COLLATE "C" NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    attempt_count SMALLINT NOT NULL DEFAULT 0,
    claim_fence BIGINT NOT NULL DEFAULT 0,
    claim_owner_id UUID,
    claimed_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    renewal_predecessor_expires_at_ms BIGINT,
    next_attempt_at_ms BIGINT,
    last_failure_kind TEXT COLLATE "C",
    terminal_claim_owner_id UUID,
    terminal_claim_fence BIGINT,
    completion_digest BYTEA,
    completion_outcome_count SMALLINT,
    completed_at_ms BIGINT,
    rejected_at_ms BIGINT,
    accepted_at_ms BIGINT NOT NULL,
    state_updated_at_ms BIGINT NOT NULL,
    CONSTRAINT provider_delivery_inbox_tenant_id_unique UNIQUE (id, tenant_id),
    CONSTRAINT provider_delivery_inbox_replay_unique UNIQUE (
        provider, connection_id, delivery_id
    ),
    CONSTRAINT provider_delivery_inbox_id_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT provider_delivery_inbox_connection_non_nil CHECK (
        connection_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT provider_delivery_inbox_provider_shape CHECK (
        octet_length(provider) BETWEEN 1 AND 128
        AND provider ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT provider_delivery_inbox_numeric_authority_positive CHECK (
        installation_id > 0
        AND provider_repository_id > 0
    ),
    CONSTRAINT provider_delivery_inbox_repository_visibility CHECK (
        repository_visibility IN ('public', 'private')
    ),
    CONSTRAINT provider_delivery_inbox_repository_identity_shape CHECK (
        octet_length(repository_identity) BETWEEN 1 AND 1024
        AND btrim(repository_identity) = repository_identity
        AND repository_identity !~ '[[:cntrl:]]'
    ),
    CONSTRAINT provider_delivery_inbox_delivery_id_shape CHECK (
        octet_length(delivery_id) BETWEEN 1 AND 255
        AND btrim(delivery_id) = delivery_id
        AND delivery_id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT provider_delivery_inbox_request_sha256 CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT provider_delivery_inbox_raw_event_sha256 CHECK (
        octet_length(raw_event_digest) = 32
    ),
    CONSTRAINT provider_delivery_inbox_raw_object_key_shape CHECK (
        octet_length(raw_event_object_key) BETWEEN 1 AND 1024
        AND raw_event_object_key !~ '[[:cntrl:]]'
        AND left(raw_event_object_key, 1) <> '/'
        AND raw_event_object_key !~ '(^|/)\.\.(/|$)'
    ),
    CONSTRAINT provider_delivery_inbox_raw_size_bounded CHECK (
        raw_event_size_bytes BETWEEN 1 AND 26214400
    ),
    CONSTRAINT provider_delivery_inbox_raw_media_type_shape CHECK (
        octet_length(raw_event_media_type) BETWEEN 3 AND 128
        AND raw_event_media_type LIKE '%/%'
        AND raw_event_media_type !~ '[[:space:][:cntrl:];]'
    ),
    CONSTRAINT provider_delivery_inbox_state CHECK (
        state IN ('pending', 'claimed', 'retry', 'completed', 'rejected')
    ),
    CONSTRAINT provider_delivery_inbox_attempt_bound CHECK (
        attempt_count BETWEEN 0 AND 16
    ),
    CONSTRAINT provider_delivery_inbox_fence_nonnegative CHECK (
        claim_fence >= 0
    ),
    CONSTRAINT provider_delivery_inbox_claim_owner_non_nil CHECK (
        claim_owner_id IS NULL
        OR claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT provider_delivery_inbox_terminal_owner_non_nil CHECK (
        terminal_claim_owner_id IS NULL
        OR terminal_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT provider_delivery_inbox_failure_kind_shape CHECK (
        last_failure_kind IS NULL OR (
            octet_length(last_failure_kind) BETWEEN 1 AND 128
            AND last_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    CONSTRAINT provider_delivery_inbox_time_monotonic CHECK (
        accepted_at_ms >= 0 AND state_updated_at_ms >= accepted_at_ms
    ),
    CONSTRAINT provider_delivery_inbox_state_shape CHECK ((
        (
            state = 'pending'
            AND attempt_count = 0
            AND claim_fence = 0
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND renewal_predecessor_expires_at_ms IS NULL
            AND next_attempt_at_ms IS NULL
            AND last_failure_kind IS NULL
            AND terminal_claim_owner_id IS NULL
            AND terminal_claim_fence IS NULL
            AND completion_digest IS NULL
            AND completion_outcome_count IS NULL
            AND completed_at_ms IS NULL
            AND rejected_at_ms IS NULL
            AND state_updated_at_ms = accepted_at_ms
        ) OR (
            state = 'claimed'
            AND attempt_count BETWEEN 1 AND 16
            AND claim_fence > 0
            AND claim_owner_id IS NOT NULL
            AND claimed_at_ms >= accepted_at_ms
            AND state_updated_at_ms >= claimed_at_ms
            AND claim_expires_at_ms > state_updated_at_ms
            AND claim_expires_at_ms - state_updated_at_ms <= 900000
            AND claim_expires_at_ms - claimed_at_ms <= 3600000
            AND (
                (state_updated_at_ms = claimed_at_ms
                    AND renewal_predecessor_expires_at_ms IS NULL)
                OR (state_updated_at_ms > claimed_at_ms
                    AND renewal_predecessor_expires_at_ms > state_updated_at_ms
                    AND renewal_predecessor_expires_at_ms < claim_expires_at_ms)
            )
            AND next_attempt_at_ms IS NULL
            AND terminal_claim_owner_id IS NULL
            AND terminal_claim_fence IS NULL
            AND completion_digest IS NULL
            AND completion_outcome_count IS NULL
            AND completed_at_ms IS NULL
            AND rejected_at_ms IS NULL
        ) OR (
            state = 'retry'
            AND attempt_count BETWEEN 1 AND 15
            AND claim_fence > 0
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND renewal_predecessor_expires_at_ms IS NULL
            AND next_attempt_at_ms > state_updated_at_ms
            AND next_attempt_at_ms - state_updated_at_ms <= 86400000
            AND last_failure_kind IS NOT NULL
            AND terminal_claim_owner_id IS NULL
            AND terminal_claim_fence IS NULL
            AND completion_digest IS NULL
            AND completion_outcome_count IS NULL
            AND completed_at_ms IS NULL
            AND rejected_at_ms IS NULL
        ) OR (
            state = 'completed'
            AND attempt_count BETWEEN 1 AND 16
            AND claim_fence > 0
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND renewal_predecessor_expires_at_ms IS NULL
            AND next_attempt_at_ms IS NULL
            AND terminal_claim_owner_id IS NOT NULL
            AND terminal_claim_fence = claim_fence
            AND octet_length(completion_digest) = 32
            AND completion_outcome_count BETWEEN 0 AND 256
            AND completed_at_ms = state_updated_at_ms
            AND rejected_at_ms IS NULL
        ) OR (
            state = 'rejected'
            AND attempt_count BETWEEN 1 AND 16
            AND claim_fence > 0
            AND claim_owner_id IS NULL
            AND claimed_at_ms IS NULL
            AND claim_expires_at_ms IS NULL
            AND renewal_predecessor_expires_at_ms IS NULL
            AND next_attempt_at_ms IS NULL
            AND last_failure_kind IS NOT NULL
            AND terminal_claim_owner_id IS NOT NULL
            AND terminal_claim_fence = claim_fence
            AND completion_digest IS NULL
            AND completion_outcome_count IS NULL
            AND completed_at_ms IS NULL
            AND rejected_at_ms = state_updated_at_ms
        )
    ) IS TRUE)
);

CREATE INDEX provider_delivery_inbox_ready
    ON provider_delivery_inbox (
        coalesce(next_attempt_at_ms, accepted_at_ms), accepted_at_ms, id
    )
    WHERE state IN ('pending', 'retry');

CREATE INDEX provider_delivery_inbox_expired_claim
    ON provider_delivery_inbox (claim_expires_at_ms, accepted_at_ms, id)
    WHERE state = 'claimed';

CREATE FUNCTION automata_enforce_provider_delivery_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.provider IS DISTINCT FROM OLD.provider
        OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
        OR NEW.installation_id IS DISTINCT FROM OLD.installation_id
        OR NEW.provider_repository_id IS DISTINCT FROM OLD.provider_repository_id
        OR NEW.repository_visibility IS DISTINCT FROM OLD.repository_visibility
        OR NEW.repository_identity IS DISTINCT FROM OLD.repository_identity
        OR NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
        OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
        OR NEW.raw_event_digest IS DISTINCT FROM OLD.raw_event_digest
        OR NEW.raw_event_object_key IS DISTINCT FROM OLD.raw_event_object_key
        OR NEW.raw_event_size_bytes IS DISTINCT FROM OLD.raw_event_size_bytes
        OR NEW.raw_event_media_type IS DISTINCT FROM OLD.raw_event_media_type
        OR NEW.accepted_at_ms IS DISTINCT FROM OLD.accepted_at_ms
    THEN
        RAISE EXCEPTION 'provider delivery immutable evidence cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_evidence_immutable';
    END IF;

    IF NEW.state_updated_at_ms < OLD.state_updated_at_ms THEN
        RAISE EXCEPTION 'provider delivery state time cannot regress'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_time_regression';
    END IF;

    IF OLD.state IN ('pending', 'retry') AND NEW.state = 'claimed' THEN
        IF NEW.claim_fence <> OLD.claim_fence + 1
            OR NEW.attempt_count <> OLD.attempt_count + 1
            OR NEW.claimed_at_ms < OLD.state_updated_at_ms
            OR NEW.state_updated_at_ms IS DISTINCT FROM NEW.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR (
                OLD.state = 'retry'
                AND NEW.claimed_at_ms < OLD.next_attempt_at_ms
            )
            OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
        THEN
            RAISE EXCEPTION 'provider delivery claim must advance exact retry state'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_claim_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'claimed' THEN
        IF NEW.claim_fence = OLD.claim_fence + 1
            AND NEW.claimed_at_ms IS NOT DISTINCT FROM OLD.claimed_at_ms
        THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
                OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
                OR NEW.claim_expires_at_ms <= OLD.claim_expires_at_ms
                OR NEW.state_updated_at_ms <= OLD.state_updated_at_ms
                OR NEW.state_updated_at_ms >= OLD.claim_expires_at_ms
                OR NEW.renewal_predecessor_expires_at_ms
                    IS DISTINCT FROM OLD.claim_expires_at_ms
            THEN
                RAISE EXCEPTION 'provider delivery renewal must rotate and strictly extend the live exact claim'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'provider_delivery_inbox_renewal_transition';
            END IF;
        ELSIF NEW.claim_fence = OLD.claim_fence + 1 THEN
            IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                OR NEW.claimed_at_ms < OLD.claim_expires_at_ms
                OR NEW.state_updated_at_ms IS DISTINCT FROM NEW.claimed_at_ms
                OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
                OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
            THEN
                RAISE EXCEPTION 'provider delivery crash reclaim must advance only its fence'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'provider_delivery_inbox_reclaim_transition';
            END IF;
        ELSE
            RAISE EXCEPTION 'provider delivery claimed-state transition has an invalid fence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_claimed_fence_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'retry' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
        THEN
            RAISE EXCEPTION 'provider delivery retry must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_retry_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'completed' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.last_failure_kind IS DISTINCT FROM OLD.last_failure_kind
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR NEW.terminal_claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
            OR NEW.terminal_claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'provider delivery completion must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_completion_transition';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'rejected' THEN
        IF NEW.claim_fence <> OLD.claim_fence
            OR NEW.attempt_count <> OLD.attempt_count
            OR NEW.state_updated_at_ms < OLD.claimed_at_ms
            OR NEW.renewal_predecessor_expires_at_ms IS NOT NULL
            OR NEW.terminal_claim_owner_id IS DISTINCT FROM OLD.claim_owner_id
            OR NEW.terminal_claim_fence IS DISTINCT FROM OLD.claim_fence
        THEN
            RAISE EXCEPTION 'provider delivery rejection must close the exact claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'provider_delivery_inbox_rejection_transition';
        END IF;
    ELSE
        RAISE EXCEPTION 'provider delivery lifecycle transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_inbox_lifecycle_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER provider_delivery_inbox_lifecycle_guard
BEFORE UPDATE ON provider_delivery_inbox
FOR EACH ROW EXECUTE FUNCTION automata_enforce_provider_delivery_lifecycle();

CREATE FUNCTION automata_reject_provider_delivery_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'provider delivery evidence cannot be removed'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'provider_delivery_inbox_removal_forbidden';
END;
$automata$;

CREATE TRIGGER provider_delivery_inbox_no_delete
BEFORE DELETE ON provider_delivery_inbox
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_delivery_removal();

CREATE TRIGGER provider_delivery_inbox_no_truncate
BEFORE TRUNCATE ON provider_delivery_inbox
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_provider_delivery_removal();

CREATE TABLE provider_delivery_workflow_outcomes (
    inbox_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    ordinal SMALLINT NOT NULL,
    workflow_path TEXT COLLATE "C" NOT NULL,
    outcome_kind TEXT NOT NULL,
    repository_id UUID,
    run_id UUID,
    failure_kind TEXT COLLATE "C",
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT provider_delivery_workflow_outcomes_primary_key PRIMARY KEY (
        inbox_id, workflow_path
    ),
    CONSTRAINT provider_delivery_workflow_outcomes_ordinal_unique UNIQUE (
        inbox_id, ordinal
    ),
    CONSTRAINT provider_delivery_workflow_outcomes_inbox_tenant
        FOREIGN KEY (inbox_id, tenant_id)
        REFERENCES provider_delivery_inbox(id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT provider_delivery_workflow_outcomes_repository_tenant
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT provider_delivery_workflow_outcomes_run_repository
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT provider_delivery_workflow_outcomes_ordinal_bound CHECK (
        ordinal BETWEEN 0 AND 255
    ),
    CONSTRAINT provider_delivery_workflow_outcomes_path_shape CHECK (
        octet_length(workflow_path) BETWEEN 1 AND 1024
        AND btrim(workflow_path) = workflow_path
        AND workflow_path !~ '[[:cntrl:]\\]'
        AND left(workflow_path, 1) <> '/'
        AND workflow_path !~ '(^|/)(\.|\.\.)(/|$)'
        AND workflow_path !~ '//'
    ),
    CONSTRAINT provider_delivery_workflow_outcomes_kind CHECK (
        outcome_kind IN ('admitted', 'skipped', 'failed')
    ),
    CONSTRAINT provider_delivery_workflow_outcomes_failure_shape CHECK (
        failure_kind IS NULL OR (
            octet_length(failure_kind) BETWEEN 1 AND 128
            AND failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    CONSTRAINT provider_delivery_workflow_outcomes_shape CHECK ((
        (outcome_kind = 'admitted'
            AND repository_id IS NOT NULL
            AND run_id IS NOT NULL
            AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND failure_kind IS NULL)
        OR (outcome_kind IN ('skipped', 'failed')
            AND repository_id IS NULL
            AND run_id IS NULL
            AND failure_kind IS NOT NULL)
    ) IS TRUE),
    CONSTRAINT provider_delivery_workflow_outcomes_time_nonnegative CHECK (
        created_at_ms >= 0
    )
);

CREATE FUNCTION automata_enforce_provider_delivery_outcome_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    durable_state TEXT;
    durable_count SMALLINT;
    durable_completed_at BIGINT;
BEGIN
    SELECT state, completion_outcome_count, completed_at_ms
    INTO durable_state, durable_count, durable_completed_at
    FROM provider_delivery_inbox
    WHERE id = NEW.inbox_id AND tenant_id = NEW.tenant_id;

    IF durable_state IS DISTINCT FROM 'completed'
        OR NEW.ordinal >= durable_count
        OR NEW.created_at_ms IS DISTINCT FROM durable_completed_at
        OR EXISTS (
            SELECT 1
            FROM provider_delivery_workflow_outcomes AS outcome
            WHERE outcome.inbox_id = NEW.inbox_id
              AND (
                (outcome.ordinal < NEW.ordinal
                    AND outcome.workflow_path >= NEW.workflow_path)
                OR (outcome.ordinal > NEW.ordinal
                    AND outcome.workflow_path <= NEW.workflow_path)
              )
        )
    THEN
        RAISE EXCEPTION 'provider delivery outcome does not match terminal ordering'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'provider_delivery_workflow_outcomes_terminal_order';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER provider_delivery_workflow_outcomes_insert_guard
BEFORE INSERT ON provider_delivery_workflow_outcomes
FOR EACH ROW EXECUTE FUNCTION automata_enforce_provider_delivery_outcome_insert();

CREATE FUNCTION automata_reject_provider_delivery_outcome_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'provider delivery terminal outcomes are immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'provider_delivery_workflow_outcomes_immutable';
END;
$automata$;

CREATE TRIGGER provider_delivery_workflow_outcomes_no_update_delete
BEFORE UPDATE OR DELETE ON provider_delivery_workflow_outcomes
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_delivery_outcome_mutation();

CREATE TRIGGER provider_delivery_workflow_outcomes_no_truncate
BEFORE TRUNCATE ON provider_delivery_workflow_outcomes
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_provider_delivery_outcome_mutation();
