-- Crash-safe, value-free intent ledger for tenant, repository, and environment
-- secret creation and replacement. Provider calls happen outside the management
-- transaction. The independent mutation UUID fixes the exact scope descriptor,
-- predecessor, provider, and provider idempotency key before plaintext crosses
-- that trust boundary.

-- There is no trustworthy way to invent immutable mutation receipts for
-- pre-ledger logical secrets or provider versions. Require an explicit
-- operator drain instead of silently treating old rows as mutation-backed.
DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM secrets)
       OR EXISTS (SELECT 1 FROM secret_versions)
       OR EXISTS (SELECT 1 FROM secret_version_lifecycle) THEN
        RAISE EXCEPTION 'pre-ledger secret state must be explicitly drained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_version_mutations_legacy_state';
    END IF;
END;
$automata$;

CREATE TABLE secret_version_mutations (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    mutation_id UUID NOT NULL,
    secret_id UUID NOT NULL,
    scope_kind TEXT NOT NULL,
    repository_id UUID,
    environment_id UUID,
    canonical_name TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    requested_provider_id TEXT,
    mutation_kind TEXT NOT NULL,
    expected_secret_revision BIGINT,
    reserved_secret_revision BIGINT NOT NULL,
    expected_predecessor_version_id UUID,
    expected_predecessor_version_number BIGINT,
    provider_create_request_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'reserved',
    completion_kind TEXT,
    committed_version_id UUID,
    committed_version_number BIGINT,
    confirmed_secret_revision BIGINT,
    reserved_by_principal_id UUID NOT NULL,
    reserved_at_ms BIGINT NOT NULL,
    confirmed_by_principal_id UUID,
    confirmed_at_ms BIGINT,
    terminal_reason TEXT,
    revision BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT secret_version_mutations_primary_key PRIMARY KEY (
        tenant_id, mutation_id
    ),
    CONSTRAINT secret_version_mutations_lifecycle_identity UNIQUE (
        tenant_id, mutation_id, secret_id, provider_id
    ),
    CONSTRAINT secret_version_mutations_provider_request_unique UNIQUE (
        tenant_id, provider_id, provider_create_request_id
    ),
    CONSTRAINT secret_version_mutations_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_environment
        FOREIGN KEY (tenant_id, repository_id, environment_id)
        REFERENCES repository_environments(tenant_id, repository_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_provider
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_requested_provider
        FOREIGN KEY (tenant_id, requested_provider_id)
        REFERENCES secret_providers(tenant_id, provider_id) ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_reserver_membership
        FOREIGN KEY (tenant_id, reserved_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_confirmer_membership
        FOREIGN KEY (tenant_id, confirmed_by_principal_id)
        REFERENCES tenant_human_memberships(tenant_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_predecessor
        FOREIGN KEY (
            tenant_id, expected_predecessor_version_id, secret_id,
            expected_predecessor_version_number
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_committed_version
        FOREIGN KEY (
            tenant_id, committed_version_id, secret_id,
            committed_version_number
        ) REFERENCES secret_versions(
            tenant_id, id, secret_id, version_number
        ) ON DELETE RESTRICT,
    CONSTRAINT secret_version_mutations_non_nil_ids CHECK (
        mutation_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND secret_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND mutation_id <> secret_id
        AND (
            repository_id IS NULL
            OR repository_id <> '00000000-0000-0000-0000-000000000000'::UUID
        )
        AND (
            environment_id IS NULL
            OR environment_id <> '00000000-0000-0000-0000-000000000000'::UUID
        )
        AND (
            expected_predecessor_version_id IS NULL
            OR expected_predecessor_version_id <>
               '00000000-0000-0000-0000-000000000000'::UUID
        )
        AND (
            committed_version_id IS NULL
            OR committed_version_id <>
               '00000000-0000-0000-0000-000000000000'::UUID
        )
    ),
    CONSTRAINT secret_version_mutations_name_shape CHECK (
        octet_length(canonical_name) BETWEEN 1 AND 255
        AND canonical_name ~ '^[A-Z_][A-Z0-9_]*$'
        AND canonical_name !~ '^(GITHUB_|ACTIONS_|RUNNER_|AUTOMATA_)'
    ),
    CONSTRAINT secret_version_mutations_scope_kind CHECK (
        scope_kind IN ('tenant', 'repository', 'environment')
    ),
    CONSTRAINT secret_version_mutations_scope_shape CHECK ((
        (
            scope_kind = 'tenant'
            AND repository_id IS NULL
            AND environment_id IS NULL
        ) OR (
            scope_kind = 'repository'
            AND repository_id IS NOT NULL
            AND environment_id IS NULL
        ) OR (
            scope_kind = 'environment'
            AND repository_id IS NOT NULL
            AND environment_id IS NOT NULL
        )
    ) IS TRUE),
    CONSTRAINT secret_version_mutations_kind CHECK (
        mutation_kind IN ('create', 'replace')
    ),
    CONSTRAINT secret_version_mutations_expectation_shape CHECK ((
        (
            mutation_kind = 'create'
            AND expected_secret_revision IS NULL
            AND reserved_secret_revision = 1
            AND expected_predecessor_version_id IS NULL
            AND expected_predecessor_version_number IS NULL
            AND (requested_provider_id IS NULL OR requested_provider_id = provider_id)
        ) OR (
            mutation_kind = 'replace'
            AND expected_secret_revision > 0
            AND reserved_secret_revision = expected_secret_revision
            AND expected_predecessor_version_id IS NOT NULL
            AND expected_predecessor_version_number > 0
            AND requested_provider_id IS NULL
        )
    ) IS TRUE),
    CONSTRAINT secret_version_mutations_provider_request_shape CHECK (
        octet_length(provider_create_request_id) BETWEEN 1 AND 255
        AND provider_create_request_id = 'secret-version:' || mutation_id::TEXT
    ),
    CONSTRAINT secret_version_mutations_state CHECK (
        state IN ('reserved', 'confirmed', 'superseded', 'cancelled')
    ),
    CONSTRAINT secret_version_mutations_completion_kind CHECK (
        completion_kind IS NULL OR completion_kind IN (
            'builtin_created', 'cas_lost', 'system_cancelled'
        )
    ),
    CONSTRAINT secret_version_mutations_state_shape CHECK ((
        (
            state = 'reserved'
            AND completion_kind IS NULL
            AND committed_version_id IS NULL
            AND committed_version_number IS NULL
            AND confirmed_secret_revision IS NULL
            AND confirmed_by_principal_id IS NULL
            AND confirmed_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'confirmed'
            AND completion_kind = 'builtin_created'
            AND committed_version_id IS NOT NULL
            AND committed_version_number > 0
            AND confirmed_secret_revision = reserved_secret_revision + 1
            AND confirmed_by_principal_id IS NOT NULL
            AND confirmed_at_ms >= reserved_at_ms
            AND terminal_reason IS NULL
        ) OR (
            state = 'superseded'
            AND completion_kind = 'builtin_created'
            AND committed_version_id IS NOT NULL
            AND committed_version_number > 0
            AND confirmed_secret_revision = reserved_secret_revision + 1
            AND confirmed_by_principal_id IS NOT NULL
            AND confirmed_at_ms >= reserved_at_ms
            AND terminal_reason IN (
                'applied_then_superseded', 'applied_then_deleted'
            )
        ) OR (
            state = 'cancelled'
            AND completion_kind IN ('cas_lost', 'system_cancelled')
            AND committed_version_id IS NULL
            AND committed_version_number IS NULL
            AND confirmed_secret_revision IS NULL
            AND confirmed_by_principal_id IS NOT NULL
            AND confirmed_at_ms >= reserved_at_ms
            AND (
                (completion_kind = 'cas_lost' AND terminal_reason = 'cas_lost')
                OR (
                    completion_kind = 'system_cancelled'
                    AND terminal_reason = 'secret_deleted'
                )
            )
        )
    ) IS TRUE),
    CONSTRAINT secret_version_mutations_revision_positive CHECK (revision > 0),
    CONSTRAINT secret_version_mutations_time_nonnegative CHECK (reserved_at_ms >= 0)
);

-- A logical descriptor has exactly one creation intent for its lifetime. Exact
-- replay uses its mutation UUID; replacements may be concurrently reserved,
-- while every immutable provider winner belongs to exactly one receipt.
CREATE UNIQUE INDEX secret_version_mutations_one_create
    ON secret_version_mutations (tenant_id, secret_id)
    WHERE mutation_kind = 'create';

CREATE UNIQUE INDEX secret_version_mutations_one_committed_version
    ON secret_version_mutations (tenant_id, committed_version_id)
    WHERE committed_version_id IS NOT NULL;

CREATE INDEX secret_version_mutations_reserved
    ON secret_version_mutations (tenant_id, secret_id, reserved_at_ms, mutation_id)
    WHERE state = 'reserved';

-- A provider may durably stage encrypted bytes, but it may not make them the
-- logical head. Staged rows remain unresolvable until the management
-- confirmation transaction promotes them. The mutation identity is retained
-- after promotion so every winner stays joined to its immutable intent.
ALTER TABLE secret_version_lifecycle
    ADD COLUMN mutation_id UUID NOT NULL;

ALTER TABLE secret_version_lifecycle
    DROP CONSTRAINT secret_version_lifecycle_status,
    DROP CONSTRAINT secret_version_lifecycle_destroy_shape;

ALTER TABLE secret_version_lifecycle
    ADD CONSTRAINT secret_version_lifecycle_status CHECK (
        status IN (
            'staged', 'active', 'superseded', 'disabled',
            'destroy_pending', 'destroyed'
        )
    ),
    ADD CONSTRAINT secret_version_lifecycle_destroy_shape CHECK ((
        (
            status IN ('staged', 'active', 'superseded', 'disabled')
            AND destroy_request_id IS NULL
            AND destroyed_at_ms IS NULL
        ) OR (
            status = 'destroy_pending'
            AND octet_length(destroy_request_id) BETWEEN 1 AND 255
            AND destroy_request_id !~ '[[:cntrl:]]'
            AND destroyed_at_ms IS NULL
        ) OR (
            status = 'destroyed'
            AND octet_length(destroy_request_id) BETWEEN 1 AND 255
            AND destroy_request_id !~ '[[:cntrl:]]'
            AND destroyed_at_ms >= changed_at_ms
        )
    ) IS TRUE),
    ADD CONSTRAINT secret_version_lifecycle_mutation
        FOREIGN KEY (tenant_id, mutation_id, secret_id, provider_id)
        REFERENCES secret_version_mutations(
            tenant_id, mutation_id, secret_id, provider_id
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT secret_version_lifecycle_staged_mutation CHECK (
        status <> 'staged' OR mutation_id IS NOT NULL
    ),
    ADD CONSTRAINT secret_version_lifecycle_mutation_unique UNIQUE (
        tenant_id, mutation_id
    );

CREATE UNIQUE INDEX secret_version_lifecycle_one_staged_candidate
    ON secret_version_lifecycle (tenant_id, secret_id)
    WHERE status = 'staged';

-- A deleted provisioning descriptor is retained as the durable cancellation
-- anchor. It may have no current head even if an encrypted staged candidate is
-- awaiting cryptographic erasure.
ALTER TABLE secrets DROP CONSTRAINT secrets_status_shape;

ALTER TABLE secrets ADD CONSTRAINT secrets_status_shape CHECK ((
    (
        status = 'provisioning'
        AND current_version_id IS NULL
        AND current_version_number IS NULL
        AND deleted_at_ms IS NULL
    ) OR (
        status IN ('active', 'disabled')
        AND current_version_id IS NOT NULL
        AND current_version_number > 0
        AND deleted_at_ms IS NULL
    ) OR (
        status = 'deleted'
        AND (
            (
                current_version_id IS NULL
                AND current_version_number IS NULL
            ) OR (
                current_version_id IS NOT NULL
                AND current_version_number > 0
            )
        )
        AND deleted_at_ms >= created_at_ms
    )
) IS TRUE);

-- Directly inserted terminal receipts, stale reservation snapshots, and rows
-- detached from a logical descriptor are rejected even if a writer bypasses
-- the store adapter. Replacements additionally require the exact active head
-- to have a confirmed mutation receipt of its own.
CREATE FUNCTION automata_secret_version_mutation_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    predecessor_lifecycle TEXT;
    predecessor_receipt_count BIGINT;
BEGIN
    IF NEW.state <> 'reserved' OR NEW.revision <> 1 THEN
        RAISE EXCEPTION 'secret version mutations must begin reserved at revision one'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_initial_state';
    END IF;

    SELECT * INTO secret_row
    FROM secrets
    WHERE tenant_id = NEW.tenant_id AND id = NEW.secret_id
    FOR UPDATE;
    IF NOT FOUND
       OR secret_row.scope_kind <> NEW.scope_kind
       OR secret_row.repository_id IS DISTINCT FROM NEW.repository_id
       OR secret_row.environment_id IS DISTINCT FROM NEW.environment_id
       OR secret_row.canonical_name <> NEW.canonical_name
       OR secret_row.provider_id <> NEW.provider_id THEN
        RAISE EXCEPTION 'secret version mutation descriptor is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_descriptor_exact';
    END IF;

    IF NEW.mutation_kind = 'create' THEN
        IF secret_row.status <> 'provisioning'
           OR secret_row.revision <> 1
           OR secret_row.current_version_id IS NOT NULL
           OR secret_row.current_version_number IS NOT NULL THEN
            RAISE EXCEPTION 'secret creation mutation does not name a fresh descriptor'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_create_head';
        END IF;
    ELSE
        IF secret_row.status <> 'active'
           OR secret_row.revision <> NEW.expected_secret_revision
           OR secret_row.revision <> NEW.reserved_secret_revision
           OR secret_row.current_version_id IS DISTINCT FROM NEW.expected_predecessor_version_id
           OR secret_row.current_version_number IS DISTINCT FROM NEW.expected_predecessor_version_number THEN
            RAISE EXCEPTION 'secret replacement mutation predecessor is not current'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_replace_head';
        END IF;

        SELECT status INTO predecessor_lifecycle
        FROM secret_version_lifecycle
        WHERE tenant_id = NEW.tenant_id
          AND secret_version_id = NEW.expected_predecessor_version_id
          AND secret_id = NEW.secret_id
          AND version_number = NEW.expected_predecessor_version_number
          AND provider_id = NEW.provider_id
        FOR SHARE;

        SELECT count(*) INTO predecessor_receipt_count
        FROM secret_version_mutations
        WHERE tenant_id = NEW.tenant_id
          AND secret_id = NEW.secret_id
          AND provider_id = NEW.provider_id
          AND state = 'confirmed'
          AND completion_kind = 'builtin_created'
          AND committed_version_id = NEW.expected_predecessor_version_id
          AND committed_version_number = NEW.expected_predecessor_version_number
          AND confirmed_secret_revision = reserved_secret_revision + 1;

        IF predecessor_lifecycle IS DISTINCT FROM 'active'
           OR predecessor_receipt_count <> 1 THEN
            RAISE EXCEPTION 'secret replacement predecessor is not confirmed and active'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_mutations_predecessor_confirmed';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_version_mutations_insert_guard
BEFORE INSERT ON secret_version_mutations
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_mutation_insert_guard();

-- Only the exact reserved intent may acquire a staged immutable candidate.
-- Lock order is descriptor then intent, matching management confirmation.
CREATE FUNCTION automata_secret_version_lifecycle_insert_guard()
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
           OR NEW.version_number <> mutation_row.expected_predecessor_version_number + 1
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

CREATE TRIGGER secret_version_lifecycle_insert_guard
BEFORE INSERT ON secret_version_lifecycle
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_lifecycle_insert_guard();

CREATE FUNCTION automata_secret_version_lifecycle_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret version lifecycle rows are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_version_lifecycle_append_only';
END;
$automata$;

CREATE TRIGGER secret_version_lifecycle_delete_guard
BEFORE DELETE ON secret_version_lifecycle
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_lifecycle_delete_guard();

CREATE TRIGGER secret_version_lifecycle_truncate_guard
BEFORE TRUNCATE ON secret_version_lifecycle
FOR EACH STATEMENT
EXECUTE FUNCTION automata_secret_version_lifecycle_delete_guard();

-- An immutable request-ID winner cannot be committed without its exact staged
-- lifecycle/intent join. This prevents an orphan version from occupying the
-- provider idempotency key and permanently wedging a reserved mutation.
CREATE FUNCTION automata_secret_version_deferred_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    exact_stage_count BIGINT;
BEGIN
    IF NEW.provider_id <> 'builtin'
       OR NEW.storage_kind <> 'built_in_ciphertext' THEN
        RAISE EXCEPTION 'secret versions require the composed built-in mutation path'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_versions_mutation_stage_exact';
    END IF;

    SELECT count(*) INTO exact_stage_count
    FROM secret_version_lifecycle AS lifecycle
    JOIN secret_version_mutations AS mutation
      ON mutation.tenant_id = lifecycle.tenant_id
     AND mutation.mutation_id = lifecycle.mutation_id
     AND mutation.secret_id = lifecycle.secret_id
     AND mutation.provider_id = lifecycle.provider_id
    WHERE lifecycle.tenant_id = NEW.tenant_id
      AND lifecycle.secret_version_id = NEW.id
      AND lifecycle.secret_id = NEW.secret_id
      AND lifecycle.version_number = NEW.version_number
      AND lifecycle.provider_id = NEW.provider_id
      AND mutation.provider_create_request_id = NEW.create_request_id;

    IF exact_stage_count <> 1 THEN
        RAISE EXCEPTION 'secret version has no exact mutation stage'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_versions_mutation_stage_exact';
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER secret_versions_deferred_mutation_stage
AFTER INSERT ON secret_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_deferred_guard();

-- Lifecycle updates retain the mutation join. Promotion is allowed only while
-- the reservation and exact logical predecessor are still current; staged
-- candidates may otherwise move only into deletion cleanup.
CREATE OR REPLACE FUNCTION automata_secret_version_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
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
               OR secret_row.status <> (CASE mutation_row.mutation_kind
                   WHEN 'create' THEN 'provisioning' ELSE 'active' END)
               OR secret_row.revision <> mutation_row.reserved_secret_revision
               OR secret_row.current_version_id IS DISTINCT FROM mutation_row.expected_predecessor_version_id
               OR secret_row.current_version_number IS DISTINCT FROM mutation_row.expected_predecessor_version_number THEN
                RAISE EXCEPTION 'staged candidate promotion lost its reservation CAS'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_lifecycle_staged_promotion';
            END IF;
        ELSIF mutation_row.state <> 'cancelled'
              OR mutation_row.completion_kind <> 'system_cancelled'
              OR mutation_row.terminal_reason <> 'secret_deleted'
              OR secret_row.status <> 'deleted' THEN
            RAISE EXCEPTION 'staged candidate cleanup requires deletion cancellation'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_staged_cleanup';
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

-- Every provider-success receipt is independently checked against the exact
-- staged request-ID winner, predecessor, built-in envelope head, and logical
-- head. Provider-reference ciphertext and heads are prohibited for a built-in
-- winner. Confirmation fixes the applied revision at reserved + 1 forever.
CREATE FUNCTION automata_secret_version_mutation_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    winner_row secret_versions%ROWTYPE;
    winner_lifecycle secret_version_lifecycle%ROWTYPE;
    predecessor_id UUID;
    builtin_head_count BIGINT;
    external_reference_count BIGINT;
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
       OR NEW.expected_predecessor_version_id IS DISTINCT FROM OLD.expected_predecessor_version_id
       OR NEW.expected_predecessor_version_number IS DISTINCT FROM OLD.expected_predecessor_version_number
       OR NEW.provider_create_request_id IS DISTINCT FROM OLD.provider_create_request_id
       OR NEW.reserved_by_principal_id IS DISTINCT FROM OLD.reserved_by_principal_id
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
        OR NEW.confirmed_at_ms IS DISTINCT FROM OLD.confirmed_at_ms
    ) THEN
        RAISE EXCEPTION 'confirmed secret version receipt is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'secret_version_mutations_receipt_immutable';
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
           OR winner_row.version_number IS DISTINCT FROM NEW.committed_version_number
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
        ELSE
            SELECT id INTO predecessor_id
            FROM secret_versions
            WHERE tenant_id = NEW.tenant_id
              AND secret_id = NEW.secret_id
              AND version_number = winner_row.version_number - 1
            FOR SHARE;
            IF predecessor_id IS DISTINCT FROM NEW.expected_predecessor_version_id
               OR winner_row.version_number <> NEW.expected_predecessor_version_number + 1 THEN
                RAISE EXCEPTION 'secret replacement winner has the wrong predecessor'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'secret_version_mutations_winner_predecessor';
            END IF;
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
        IF secret_row.status <> 'deleted' OR EXISTS (
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
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_version_mutations_transition
BEFORE UPDATE ON secret_version_mutations
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_mutation_transition();

CREATE FUNCTION automata_secret_version_mutation_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret version mutation receipts are append-only'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_version_mutations_append_only';
END;
$automata$;

CREATE TRIGGER secret_version_mutations_delete_guard
BEFORE DELETE ON secret_version_mutations
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_mutation_delete_guard();

CREATE TRIGGER secret_version_mutations_truncate_guard
BEFORE TRUNCATE ON secret_version_mutations
FOR EACH STATEMENT
EXECUTE FUNCTION automata_secret_version_mutation_delete_guard();

-- Deletion preserves already-applied receipts and cancels every still-reserved
-- intent. A staged provider winner is never misclassified as applied: it stays
-- joined to a cancelled receipt and is subsequently sent through erasure.
CREATE FUNCTION automata_cancel_secret_version_mutations_on_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.status = 'deleted' OR NEW.status <> 'deleted' THEN
        RETURN NEW;
    END IF;

    UPDATE secret_version_mutations
    SET state = 'superseded',
        terminal_reason = 'applied_then_deleted',
        revision = revision + 1
    WHERE tenant_id = NEW.tenant_id
      AND secret_id = NEW.id
      AND state = 'confirmed';

    UPDATE secret_version_mutations
    SET state = 'cancelled',
        completion_kind = 'system_cancelled',
        confirmed_by_principal_id = NEW.updated_by_principal_id,
        confirmed_at_ms = NEW.updated_at_ms,
        terminal_reason = 'secret_deleted',
        revision = revision + 1
    WHERE tenant_id = NEW.tenant_id
      AND secret_id = NEW.id
      AND state = 'reserved';

    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secrets_cancel_version_mutations_on_update_delete
AFTER UPDATE ON secrets
FOR EACH ROW
EXECUTE FUNCTION automata_cancel_secret_version_mutations_on_delete();

-- Deferred validation makes partial SQL promotion impossible: a transaction
-- may transiently promote a staged row while advancing its descriptor and
-- receipts, but no promoted/cancelled lifecycle can commit without the exact
-- terminal ledger state and encrypted-at-rest shape.
CREATE FUNCTION automata_secret_version_lifecycle_deferred_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
DECLARE
    secret_row secrets%ROWTYPE;
    mutation_row secret_version_mutations%ROWTYPE;
    builtin_head_count BIGINT;
    external_reference_count BIGINT;
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
        IF secret_row.status <> 'deleted' OR NOT (
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
        ) THEN
            RAISE EXCEPTION 'destroy lifecycle committed without deletion terminalization'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'secret_version_lifecycle_deferred_state';
        END IF;
    END IF;
    RETURN NULL;
END;
$automata$;

CREATE CONSTRAINT TRIGGER secret_version_lifecycle_deferred_guard
AFTER INSERT OR UPDATE ON secret_version_lifecycle
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION automata_secret_version_lifecycle_deferred_guard();
