-- Frozen greenfield baseline. Add a new migration instead of editing this stage.
SET check_function_bodies = false;

CREATE FUNCTION automata_github_server_service_handoff_update_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.authority_id IS DISTINCT FROM OLD.authority_id
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.consumer_id IS DISTINCT FROM OLD.consumer_id
        OR NEW.consumer_owner_id IS DISTINCT FROM OLD.consumer_owner_id
        OR NEW.consumer_claim_fence IS DISTINCT FROM OLD.consumer_claim_fence
        OR NEW.consumer_action IS DISTINCT FROM OLD.consumer_action
        OR NEW.consumer_revision IS DISTINCT FROM OLD.consumer_revision
        OR NEW.required_through_ms IS DISTINCT FROM OLD.required_through_ms
        OR NEW.granted_at_ms IS DISTINCT FROM OLD.granted_at_ms
        OR OLD.released_at_ms IS NOT NULL
            AND NEW.released_at_ms IS DISTINCT FROM OLD.released_at_ms
    THEN
        RAISE EXCEPTION 'GitHub server-service handoff evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE github_server_service_authorities (
    id uuid NOT NULL,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    provider_connection_id uuid CONSTRAINT github_server_service_authoriti_provider_connection_id_not_null NOT NULL,
    provider_installation_id bigint CONSTRAINT github_server_service_authori_provider_installation_id_not_null NOT NULL,
    github_app_id bigint NOT NULL,
    github_app_client_id text NOT NULL COLLATE pg_catalog."C",
    github_app_jwt_issuer_kind text CONSTRAINT github_server_service_autho_github_app_jwt_issuer_kind_not_null NOT NULL COLLATE pg_catalog."C",
    github_repository_id bigint NOT NULL,
    github_repository_name text CONSTRAINT github_server_service_authoriti_github_repository_name_not_null NOT NULL COLLATE pg_catalog."C",
    service_scope text NOT NULL COLLATE pg_catalog."C",
    permission_policy jsonb NOT NULL,
    policy_digest bytea NOT NULL,
    policy_revision bigint NOT NULL,
    app_key_spki_sha256 bytea NOT NULL,
    app_configuration_revision bigint CONSTRAINT github_server_service_autho_app_configuration_revision_not_null NOT NULL,
    configuration_fingerprint bytea CONSTRAINT github_server_service_author_configuration_fingerprint_not_null NOT NULL,
    identity_digest bytea NOT NULL,
    state text DEFAULT 'active'::text NOT NULL COLLATE pg_catalog."C",
    current_issuance_generation bigint,
    refresh_issuance_generation bigint,
    next_issuance_generation bigint DEFAULT 1 CONSTRAINT github_server_service_authori_next_issuance_generation_not_null NOT NULL,
    consecutive_generation_failures smallint DEFAULT 0 CONSTRAINT github_server_service_autho_consecutive_generation_fai_not_null NOT NULL,
    next_mint_not_before_ms bigint,
    mint_gate_generation bigint,
    failure_budget_rearm_at_ms bigint,
    created_at_ms bigint NOT NULL,
    state_updated_at_ms bigint NOT NULL,
    retired_at_ms bigint,
    CONSTRAINT github_server_service_authorities_app_client_shape CHECK ((((octet_length(github_app_client_id) >= 1) AND (octet_length(github_app_client_id) <= 128)) AND (github_app_client_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$'::text))),
    CONSTRAINT github_server_service_authorities_digest_shape CHECK (((octet_length(policy_digest) = 32) AND (octet_length(app_key_spki_sha256) = 32) AND (octet_length(configuration_fingerprint) = 32) AND (octet_length(identity_digest) = 32))),
    CONSTRAINT github_server_service_authorities_generation_failure_shape CHECK (((((consecutive_generation_failures >= 0) AND (consecutive_generation_failures <= 32)) AND (((consecutive_generation_failures = 0) AND (next_mint_not_before_ms IS NULL) AND (mint_gate_generation IS NULL) AND (failure_budget_rearm_at_ms IS NULL)) OR (((consecutive_generation_failures >= 1) AND (consecutive_generation_failures <= 31)) AND (next_mint_not_before_ms IS NOT NULL) AND (next_mint_not_before_ms >= created_at_ms) AND (mint_gate_generation IS NOT NULL) AND (mint_gate_generation > 0) AND (mint_gate_generation < next_issuance_generation) AND (failure_budget_rearm_at_ms IS NULL)) OR ((consecutive_generation_failures = 32) AND (next_mint_not_before_ms IS NOT NULL) AND (next_mint_not_before_ms >= created_at_ms) AND (mint_gate_generation IS NOT NULL) AND (mint_gate_generation > 0) AND (mint_gate_generation < next_issuance_generation) AND (failure_budget_rearm_at_ms IS NOT NULL) AND (failure_budget_rearm_at_ms >= created_at_ms)))) IS TRUE)),
    CONSTRAINT github_server_service_authorities_generation_shape CHECK (((next_issuance_generation > 0) AND ((current_issuance_generation IS NULL) OR ((current_issuance_generation > 0) AND (current_issuance_generation < next_issuance_generation))))),
    CONSTRAINT github_server_service_authorities_jwt_issuer_kind CHECK ((github_app_jwt_issuer_kind = ANY (ARRAY['app_client_id'::text, 'app_id'::text]))),
    CONSTRAINT github_server_service_authorities_non_nil CHECK (((id <> '00000000-0000-0000-0000-000000000000'::uuid) AND (provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT github_server_service_authorities_numeric_positive CHECK (((provider_installation_id > 0) AND (github_app_id > 0) AND (github_repository_id > 0) AND (policy_revision > 0) AND (app_configuration_revision > 0))),
    CONSTRAINT github_server_service_authorities_permission_exact CHECK ((((service_scope = 'checks_write'::text) AND (permission_policy = '{"checks": "write"}'::jsonb) AND (policy_digest = decode('6acf4ef0f49f5935d65a42dacb8ffcd49718dfd847d802d96038d81cea869a9c'::text, 'hex'::text))) OR ((service_scope = 'private_repository_source_read'::text) AND (permission_policy = '{"contents": "read"}'::jsonb) AND (policy_digest = decode('3c2516eac095f5bda3e7d20265497325e91030d1abe5907d4fb7fefcd0aa7f57'::text, 'hex'::text))))),
    CONSTRAINT github_server_service_authorities_refresh_shape CHECK (((refresh_issuance_generation IS NULL) OR ((refresh_issuance_generation > 0) AND (refresh_issuance_generation < next_issuance_generation) AND (refresh_issuance_generation IS DISTINCT FROM current_issuance_generation)))),
    CONSTRAINT github_server_service_authorities_repository_name_shape CHECK ((((octet_length(github_repository_name) >= 3) AND (octet_length(github_repository_name) <= 140)) AND (github_repository_name ~ '^[^/]+/[^/]+$'::text) AND ((octet_length(split_part(github_repository_name, '/'::text, 1)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 1)) <= 39)) AND ((octet_length(split_part(github_repository_name, '/'::text, 2)) >= 1) AND (octet_length(split_part(github_repository_name, '/'::text, 2)) <= 100)) AND ((split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9]$'::text) OR (split_part(github_repository_name, '/'::text, 1) ~ '^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$'::text)) AND (split_part(github_repository_name, '/'::text, 1) !~ '--'::text) AND (split_part(github_repository_name, '/'::text, 2) ~ '^[A-Za-z0-9._-]+$'::text) AND (split_part(github_repository_name, '/'::text, 2) <> ALL (ARRAY['.'::text, '..'::text])) AND (split_part(github_repository_name, '/'::text, 2) !~* '[.]git$'::text))),
    CONSTRAINT github_server_service_authorities_service_scope CHECK ((service_scope = ANY (ARRAY['checks_write'::text, 'private_repository_source_read'::text]))),
    CONSTRAINT github_server_service_authorities_state CHECK ((state = ANY (ARRAY['active'::text, 'retiring'::text, 'retired'::text]))),
    CONSTRAINT github_server_service_authorities_time_shape CHECK (((created_at_ms >= 0) AND (state_updated_at_ms >= created_at_ms) AND (((state = 'active'::text) AND (retired_at_ms IS NULL)) OR ((state = 'retiring'::text) AND (retired_at_ms IS NULL) AND (current_issuance_generation IS NULL) AND (refresh_issuance_generation IS NULL)) OR ((state = 'retired'::text) AND (current_issuance_generation IS NULL) AND (refresh_issuance_generation IS NULL) AND (retired_at_ms IS NOT NULL) AND (retired_at_ms = state_updated_at_ms)))))
);

CREATE FUNCTION automata_github_server_service_identity_digest(github_server_service_authorities) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    AS $_$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-server-service.identity.v1', 'UTF8'
    ) || pg_catalog.decode('00', 'hex')
    || automata_digest_part(
        pg_catalog.convert_to(($1).tenant_id, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.uuid_send(($1).id)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(($1).repository_id)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(($1).provider_connection_id)
    )
    || automata_digest_part(
        pg_catalog.int8send(($1).provider_installation_id)
    )
    || automata_digest_part(
        pg_catalog.int8send(($1).github_app_id)
    )
    || automata_digest_part(
        pg_catalog.int8send(($1).github_repository_id)
    )
    || automata_digest_part(
        pg_catalog.convert_to(($1).github_repository_name, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.convert_to(($1).service_scope, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.convert_to(($1).github_app_client_id, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.convert_to(($1).github_app_jwt_issuer_kind, 'UTF8')
    )
    || automata_digest_part(($1).app_key_spki_sha256)
    || automata_digest_part(
        pg_catalog.int8send(($1).app_configuration_revision)
    )
    || automata_digest_part(
        pg_catalog.int8send(($1).policy_revision)
    )
    || automata_digest_part(($1).configuration_fingerprint)
)
$_$;

CREATE FUNCTION automata_github_server_service_issuance_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    authority github_server_service_authorities%ROWTYPE;
    expected_generation BIGINT;
    current_state TEXT;
    current_provider_expires_at_ms BIGINT;
BEGIN
    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.authority_id
    FOR UPDATE;
    expected_generation := authority.next_issuance_generation;
    IF authority.current_issuance_generation IS NOT NULL THEN
        SELECT state, provider_expires_at_ms
        INTO current_state, current_provider_expires_at_ms
        FROM github_server_service_authority_issuances
        WHERE authority_id = authority.id
          AND generation = authority.current_issuance_generation
        FOR UPDATE;
    END IF;
    IF authority.id IS NULL
        OR authority.state <> 'active'
        OR authority.refresh_issuance_generation IS NOT NULL
        OR authority.consecutive_generation_failures >= 32
        OR authority.next_mint_not_before_ms IS NOT NULL
            AND authority.next_mint_not_before_ms > NEW.requested_at_ms
        OR authority.current_issuance_generation IS NOT NULL
            AND (
                current_state IS DISTINCT FROM 'ready'
                OR current_provider_expires_at_ms IS NULL
                OR current_provider_expires_at_ms::NUMERIC - 60000
                    > NEW.requested_at_ms::NUMERIC + 1620000
            )
        OR NEW.generation <> expected_generation
        OR NEW.state <> 'claimed'
        OR NEW.mint_attempt_count <> 1
        OR NEW.mint_claim_fence <> 1
        OR NEW.state_updated_at_ms <> NEW.requested_at_ms
    THEN
        RAISE EXCEPTION 'GitHub server-service issuance initial claim is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_initial_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_server_service_issuance_pointer_exact() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    authority github_server_service_authorities%ROWTYPE;
    current_state TEXT;
    refresh_state TEXT;
    target_authority_id UUID;
BEGIN
    target_authority_id := (
        to_jsonb(NEW) ->> CASE
            WHEN TG_TABLE_NAME = 'github_server_service_authorities' THEN 'id'
            ELSE 'authority_id'
        END
    )::UUID;
    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE id = target_authority_id;
    IF authority.id IS NULL THEN
        RAISE EXCEPTION 'GitHub server-service issuance lost its descriptor'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_authority_pointer_exact';
    END IF;
    IF authority.current_issuance_generation IS NOT NULL THEN
        SELECT state INTO current_state
        FROM github_server_service_authority_issuances
        WHERE authority_id = authority.id
          AND generation = authority.current_issuance_generation;
    END IF;
    IF authority.refresh_issuance_generation IS NOT NULL THEN
        SELECT state INTO refresh_state
        FROM github_server_service_authority_issuances
        WHERE authority_id = authority.id
          AND generation = authority.refresh_issuance_generation;
    END IF;
    IF (authority.current_issuance_generation IS NOT NULL
            AND current_state IS DISTINCT FROM 'ready')
        OR (authority.refresh_issuance_generation IS NOT NULL
            AND (
                refresh_state IS NULL
                OR refresh_state NOT IN ('claimed', 'minting', 'mint_retry')
            ))
        OR EXISTS (
            SELECT 1
            FROM github_server_service_authority_issuances AS issuance
            WHERE issuance.authority_id = authority.id
              AND (
                  issuance.state = 'ready'
                      AND authority.current_issuance_generation
                          IS DISTINCT FROM issuance.generation
                  OR issuance.state IN ('claimed', 'minting', 'mint_retry')
                      AND authority.refresh_issuance_generation
                          IS DISTINCT FROM issuance.generation
              )
        )
        OR authority.next_issuance_generation::NUMERIC IS DISTINCT FROM (
            SELECT COALESCE(MAX(issuance.generation), 0)::NUMERIC + 1
            FROM github_server_service_authority_issuances AS issuance
            WHERE issuance.authority_id = authority.id
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service issuance is outside its exact descriptor slot'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_authority_pointer_exact';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION automata_github_server_service_issuance_update_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    live_handoff BOOLEAN;
    authority_state TEXT;
    authority_identity_digest BYTEA;
BEGIN
    SELECT state, identity_digest
    INTO authority_state, authority_identity_digest
    FROM github_server_service_authorities
    WHERE id = NEW.authority_id;
    IF authority_identity_digest IS NULL THEN
        RAISE EXCEPTION 'GitHub server-service issuance lacks its authority identity'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_authority_identity_exact';
    END IF;
    IF NEW.aad_digest IS NOT NULL
        AND NEW.aad_digest IS DISTINCT FROM
            automata_github_server_service_aad_digest(
                authority_identity_digest,
                NEW.generation,
                NEW.requested_at_ms,
                NEW.request_deadline_at_ms,
                NEW.provider_expires_at_ms,
                NEW.safe_erase_after_ms,
                NEW.plaintext_schema,
                NEW.plaintext_size_bytes,
                NEW.plaintext_digest
            )
        AND NOT (
            NEW.state = 'quarantined'
            AND NEW.revoke_failure_kind = 'protected_custody_corrupt'
            AND NEW.aad_digest IS NOT DISTINCT FROM OLD.aad_digest
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service protected AAD digest is non-canonical'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_aad_digest_canonical';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.authority_id IS DISTINCT FROM OLD.authority_id
        OR NEW.generation IS DISTINCT FROM OLD.generation
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.request_deadline_at_ms IS DISTINCT FROM OLD.request_deadline_at_ms
        OR NEW.conservative_expiry_at_ms IS DISTINCT FROM OLD.conservative_expiry_at_ms
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.state_updated_at_ms < OLD.state_updated_at_ms
        OR NEW.mint_attempt_count < OLD.mint_attempt_count
        OR NEW.mint_claim_fence < OLD.mint_claim_fence
        OR NEW.revoke_attempt_count < OLD.revoke_attempt_count
        OR NEW.revoke_claim_fence < OLD.revoke_claim_fence
    THEN
        RAISE EXCEPTION 'GitHub server-service issuance evidence regressed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_monotonic';
    END IF;
    IF NOT (
        OLD.state = 'claimed' AND NEW.state IN ('minting', 'rejected')
        OR OLD.state = 'minting' AND NEW.state IN (
            'ready', 'revoke_pending', 'mint_retry', 'indeterminate', 'rejected'
        )
        OR OLD.state = 'mint_retry' AND NEW.state IN ('claimed', 'rejected')
        OR OLD.state = 'ready' AND NEW.state IN ('revoke_pending', 'quarantined', 'revoked')
        OR OLD.state = 'revoke_pending'
            AND NEW.state IN ('revoke_claimed', 'quarantined', 'revoked')
        OR OLD.state = 'revoke_claimed' AND NEW.state IN ('revoke_claimed', 'revoke_retry', 'quarantined', 'revoked')
        OR OLD.state = 'revoke_retry'
            AND NEW.state IN ('revoke_claimed', 'quarantined', 'revoked')
        OR OLD.state = 'indeterminate' AND NEW.state IN ('revoke_pending', 'revoked')
        OR OLD.state = 'quarantined' AND NEW.state = 'revoked'
    ) THEN
        RAISE EXCEPTION 'GitHub server-service issuance transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_state_transition';
    END IF;
    IF OLD.state = 'mint_retry' AND NEW.state = 'claimed' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence + 1
            OR NEW.mint_attempt_count <> OLD.mint_attempt_count + 1
            OR OLD.next_mint_at_ms IS NULL
            OR OLD.next_mint_at_ms > NEW.mint_claimed_at_ms
            OR NEW.mint_started_at_ms IS NOT NULL
            OR NEW.mint_started_owner_id IS NOT NULL
            OR NEW.mint_started_claim_fence IS NOT NULL
            OR NEW.mint_started_claimed_at_ms IS NOT NULL
            OR NEW.mint_started_claim_expires_at_ms IS NOT NULL
            OR NEW.next_mint_at_ms IS NOT NULL
            OR NEW.mint_failure_kind IS NOT NULL
        THEN
            RAISE EXCEPTION 'GitHub server-service mint retry claim is not next and exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_issuances_mint_retry_claim_exact';
        END IF;
    ELSIF NEW.mint_claim_fence IS DISTINCT FROM OLD.mint_claim_fence
        OR NEW.mint_attempt_count IS DISTINCT FROM OLD.mint_attempt_count
    THEN
        RAISE EXCEPTION 'GitHub server-service mint fence changed outside proven retry'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_mint_fence_exact';
    END IF;
    IF OLD.state = 'claimed' AND NEW.state = 'minting' AND (
        NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
        OR NEW.mint_claimed_at_ms IS DISTINCT FROM OLD.mint_claimed_at_ms
        OR NEW.mint_claim_expires_at_ms IS DISTINCT FROM OLD.mint_claim_expires_at_ms
        OR NEW.mint_started_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
        OR NEW.mint_started_claim_fence IS DISTINCT FROM OLD.mint_claim_fence
        OR NEW.mint_started_claimed_at_ms IS DISTINCT FROM OLD.mint_claimed_at_ms
        OR NEW.mint_started_claim_expires_at_ms IS DISTINCT FROM OLD.mint_claim_expires_at_ms
    ) THEN
        RAISE EXCEPTION 'GitHub server-service mint start rewrote claim evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_mint_start_exact';
    END IF;
    IF (
        NEW.mint_started_at_ms IS DISTINCT FROM OLD.mint_started_at_ms
        OR NEW.mint_started_owner_id IS DISTINCT FROM OLD.mint_started_owner_id
        OR NEW.mint_started_claim_fence IS DISTINCT FROM OLD.mint_started_claim_fence
        OR NEW.mint_started_claimed_at_ms IS DISTINCT FROM OLD.mint_started_claimed_at_ms
        OR NEW.mint_started_claim_expires_at_ms IS DISTINCT FROM OLD.mint_started_claim_expires_at_ms
    ) AND NOT (
        OLD.state = 'claimed' AND NEW.state = 'minting'
        OR OLD.state = 'mint_retry' AND NEW.state = 'claimed'
    ) THEN
        RAISE EXCEPTION 'GitHub server-service begun mint provenance changed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_mint_started_immutable';
    END IF;
    IF NEW.ready_at_ms IS DISTINCT FROM OLD.ready_at_ms
        AND NOT (
            OLD.state = 'minting'
            AND NEW.state = 'ready'
            AND OLD.ready_at_ms IS NULL
            AND NEW.ready_at_ms = NEW.state_updated_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service Ready evidence changed outside exact promotion'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_ready_evidence_exact';
    END IF;
    IF NEW.generation_failure_gate_at_ms
        IS DISTINCT FROM OLD.generation_failure_gate_at_ms
        AND NOT (
            (
                OLD.generation_failure_gate_at_ms IS NULL
                AND (
                    NEW.state = 'rejected'
                        AND NEW.generation_failure_gate_at_ms
                            = NEW.state_updated_at_ms + 60000
                    OR NEW.state = 'indeterminate'
                        AND NEW.generation_failure_gate_at_ms = NEW.safe_erase_after_ms
                    OR NEW.state = 'revoke_pending'
                        AND OLD.state = 'minting'
                        AND NEW.generation_failure_gate_at_ms = NEW.safe_erase_after_ms
                    OR NEW.state = 'quarantined'
                        AND OLD.state = 'ready'
                        AND NEW.generation_failure_gate_at_ms = NEW.safe_erase_after_ms
                )
            ) OR (
                OLD.state = 'indeterminate'
                AND NEW.state = 'revoke_pending'
                AND OLD.generation_failure_gate_at_ms IS NOT NULL
                AND NEW.generation_failure_gate_at_ms = NEW.safe_erase_after_ms
                AND NEW.generation_failure_gate_at_ms
                    <= OLD.generation_failure_gate_at_ms
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service generation failure gate changed outside exact failure evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_generation_failure_gate_exact';
    END IF;
    IF OLD.state = 'mint_retry' AND NEW.state = 'rejected'
        AND NEW.mint_failure_kind IS DISTINCT FROM OLD.mint_failure_kind
    THEN
        RAISE EXCEPTION 'GitHub server-service terminal retry rewrote provider evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_mint_retry_failure_exact';
    END IF;
    IF NEW.state = 'rejected' THEN
        IF NEW.terminal_reason = 'request_expired' THEN
            IF NOT (
                OLD.state = 'claimed'
                    AND NEW.mint_started_at_ms IS NULL
                    AND NEW.state_updated_at_ms >= LEAST(
                        OLD.mint_claim_expires_at_ms,
                        OLD.request_deadline_at_ms
                    )
                OR OLD.state = 'mint_retry'
                    AND NEW.state_updated_at_ms >= OLD.request_deadline_at_ms
                OR OLD.state = 'minting'
                    AND NEW.state_updated_at_ms + 1 >= OLD.request_deadline_at_ms
            ) THEN
                RAISE EXCEPTION 'GitHub server-service request-expired terminal reason lacks exact timing evidence'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_issuances_rejected_reason_exact';
            END IF;
        ELSIF NEW.terminal_reason = 'provider_rejected' THEN
            IF OLD.state <> 'minting' THEN
                RAISE EXCEPTION 'GitHub server-service provider rejection lacks a begun mint'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_issuances_rejected_reason_exact';
            END IF;
        ELSIF NEW.terminal_reason = 'retry_exhausted' THEN
            IF OLD.state <> 'minting' OR OLD.mint_attempt_count <> 32 THEN
                RAISE EXCEPTION 'GitHub server-service retry exhaustion lacks the exact attempt bound'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_issuances_rejected_reason_exact';
            END IF;
        ELSIF NEW.terminal_reason = 'authority_retired_before_mint' THEN
            IF authority_state NOT IN ('retiring', 'retired')
                OR OLD.state NOT IN ('claimed', 'mint_retry')
            THEN
                RAISE EXCEPTION 'GitHub server-service retirement rejection lacks retiring authority evidence'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_issuances_rejected_reason_exact';
            END IF;
        ELSE
            RAISE EXCEPTION 'GitHub server-service rejection reason is unknown'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_issuances_rejected_reason_exact';
        END IF;
    END IF;
    IF OLD.state = 'minting'
        AND NEW.state IN ('ready', 'mint_retry', 'rejected')
        AND (
            NEW.state_updated_at_ms < OLD.mint_started_at_ms
            OR NEW.state_updated_at_ms >= OLD.mint_claim_expires_at_ms
            OR NEW.state_updated_at_ms >= OLD.request_deadline_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service mint result lacks a live claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_mint_result_claim_exact';
    END IF;
    IF NEW.state = 'ready'
        AND NEW.provider_expires_at_ms::NUMERIC - 60000
            < NEW.state_updated_at_ms::NUMERIC + 1500000
    THEN
        RAISE EXCEPTION 'GitHub server-service credential lacks its fixed usable horizon'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_ready_expiry_exact';
    END IF;
    IF OLD.state IN ('revoke_pending', 'revoke_retry', 'revoke_claimed')
        AND NEW.state = 'revoke_claimed'
    THEN
        IF NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
            OR NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
            OR OLD.state = 'revoke_retry'
                AND (OLD.next_revoke_at_ms IS NULL
                    OR OLD.next_revoke_at_ms > NEW.revoke_claimed_at_ms)
            OR OLD.state = 'revoke_claimed'
                AND (OLD.revoke_claim_expires_at_ms IS NULL
                    OR OLD.revoke_claim_expires_at_ms > NEW.revoke_claimed_at_ms)
        THEN
            RAISE EXCEPTION 'GitHub server-service revoke claim is not next and exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_issuances_revoke_claim_exact';
        END IF;
        SELECT EXISTS (
            SELECT 1 FROM github_server_service_authority_handoffs
            WHERE authority_id = NEW.authority_id
              AND generation = NEW.generation
              AND released_at_ms IS NULL
              AND required_through_ms > NEW.revoke_claimed_at_ms
        ) INTO live_handoff;
        IF live_handoff THEN
            RAISE EXCEPTION 'GitHub server-service credential still has a live handoff'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_issuances_handoff_live';
        END IF;
    ELSIF NEW.revoke_claim_fence IS DISTINCT FROM OLD.revoke_claim_fence
        OR NEW.revoke_attempt_count IS DISTINCT FROM OLD.revoke_attempt_count
    THEN
        RAISE EXCEPTION 'GitHub server-service revoke fence changed outside claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_revoke_fence_exact';
    END IF;
    IF OLD.state = 'revoke_claimed'
        AND (
            NEW.state IN ('revoke_retry', 'quarantined')
            OR NEW.state = 'revoked'
                AND NEW.terminal_reason = 'provider_revoked'
        )
        AND (
            NEW.state_updated_at_ms < OLD.revoke_claimed_at_ms
            OR NEW.state_updated_at_ms >= OLD.revoke_claim_expires_at_ms
        )
        AND NOT (
            NEW.state = 'quarantined'
            AND NEW.revoke_failure_kind = 'protected_custody_corrupt'
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service revocation result lacks a live claim'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_revoke_result_claim_exact';
    END IF;
    IF (
        NEW.revoke_result_owner_id IS DISTINCT FROM OLD.revoke_result_owner_id
        OR NEW.revoke_result_claim_fence IS DISTINCT FROM OLD.revoke_result_claim_fence
        OR NEW.revoke_result_claimed_at_ms IS DISTINCT FROM OLD.revoke_result_claimed_at_ms
        OR NEW.revoke_result_claim_expires_at_ms
            IS DISTINCT FROM OLD.revoke_result_claim_expires_at_ms
    ) AND NOT (
        OLD.state = 'revoke_claimed'
        AND NEW.state IN ('revoke_retry', 'quarantined', 'revoked')
        AND NEW.revoke_result_owner_id IS NOT DISTINCT FROM OLD.revoke_claim_owner_id
        AND NEW.revoke_result_claim_fence IS NOT DISTINCT FROM OLD.revoke_claim_fence
        AND NEW.revoke_result_claimed_at_ms IS NOT DISTINCT FROM OLD.revoke_claimed_at_ms
        AND NEW.revoke_result_claim_expires_at_ms
            IS NOT DISTINCT FROM OLD.revoke_claim_expires_at_ms
        OR OLD.state = 'revoke_retry'
        AND NEW.state = 'revoke_claimed'
        AND NEW.revoke_result_owner_id IS NULL
        AND NEW.revoke_result_claim_fence IS NULL
        AND NEW.revoke_result_claimed_at_ms IS NULL
        AND NEW.revoke_result_claim_expires_at_ms IS NULL
    ) THEN
        RAISE EXCEPTION 'GitHub server-service revocation result provenance changed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_revoke_result_provenance_exact';
    END IF;
    IF NEW.state = 'revoked'
        AND NEW.terminal_reason = 'provider_revoked'
        AND OLD.state <> 'revoke_claimed'
    THEN
        RAISE EXCEPTION 'GitHub server-service provider revocation lacks claim evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_provider_revocation_exact';
    END IF;
    IF (
        NEW.provider_expires_at_ms IS DISTINCT FROM OLD.provider_expires_at_ms
        OR NEW.safe_erase_after_ms IS DISTINCT FROM OLD.safe_erase_after_ms
    ) AND NOT (
        OLD.state IN ('minting', 'indeterminate')
        AND NEW.state IN ('ready', 'revoke_pending')
        AND OLD.provider_expires_at_ms IS NULL
        AND NEW.provider_expires_at_ms IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'GitHub server-service provider expiry evidence changed'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_provider_expiry_immutable';
    END IF;
    IF (
        NEW.plaintext_schema IS DISTINCT FROM OLD.plaintext_schema
        OR NEW.plaintext_size_bytes IS DISTINCT FROM OLD.plaintext_size_bytes
        OR NEW.plaintext_digest IS DISTINCT FROM OLD.plaintext_digest
        OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
        OR NEW.envelope_schema IS DISTINCT FROM OLD.envelope_schema
        OR NEW.wrapping_key_id IS DISTINCT FROM OLD.wrapping_key_id
        OR NEW.wrapped_data_key IS DISTINCT FROM OLD.wrapped_data_key
        OR NEW.nonce IS DISTINCT FROM OLD.nonce
        OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
    ) AND NOT (
        OLD.state IN ('minting', 'indeterminate')
            AND NEW.state IN ('ready', 'revoke_pending')
            AND OLD.envelope_schema IS NULL
            AND NEW.envelope_schema IS NOT NULL
        OR NEW.state = 'revoked'
            AND OLD.envelope_schema IS NOT NULL
            AND NEW.envelope_schema IS NULL
    ) THEN
        RAISE EXCEPTION 'GitHub server-service protected credential changed outside commit/erasure'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_protected_immutable';
    END IF;
    IF OLD.envelope_schema IS NOT NULL
        AND NEW.envelope_schema IS NOT NULL
        AND (
            NEW.plaintext_schema IS DISTINCT FROM OLD.plaintext_schema
            OR NEW.plaintext_size_bytes IS DISTINCT FROM OLD.plaintext_size_bytes
            OR NEW.plaintext_digest IS DISTINCT FROM OLD.plaintext_digest
            OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
            OR NEW.envelope_schema IS DISTINCT FROM OLD.envelope_schema
            OR NEW.wrapping_key_id IS DISTINCT FROM OLD.wrapping_key_id
            OR NEW.wrapped_data_key IS DISTINCT FROM OLD.wrapped_data_key
            OR NEW.nonce IS DISTINCT FROM OLD.nonce
            OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service protected credential is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_protected_immutable';
    END IF;
    IF OLD.state IN ('minting', 'indeterminate')
        AND NEW.state = 'revoke_pending'
        AND (
            NEW.state_updated_at_ms < OLD.mint_started_at_ms
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub server-service revoke-only commit lacks begun mint evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_revoke_only_exact';
    END IF;
    IF NEW.state = 'revoked'
        AND NEW.terminal_reason IS DISTINCT FROM 'provider_revoked'
        AND NEW.state_updated_at_ms < OLD.safe_erase_after_ms
    THEN
        RAISE EXCEPTION 'GitHub server-service custody erased before safe horizon'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_issuances_safe_erase_horizon';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_github_server_service_reject_removal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub server-service authority evidence cannot be removed'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_server_service_authority_removal_forbidden';
END;
$$;

CREATE FUNCTION automata_github_workflow_rerun_subject_evidence_digest(operation_id uuid, tenant_id text, repository_id uuid, workflow_id uuid, snapshot_id uuid, run_id uuid, source_run_id uuid, root_invocation_id uuid, github_repository_owner_id bigint, github_check_subject_id uuid, github_check_head_sha bytea, workflow_path text, source_digest bytea, event_name text, event_digest bytea, git_ref text, workflow_plan_schema smallint, plan_digest bytea, logical_admission_digest bytea, admitted_at_ms bigint) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-workflow-rerun-subject-evidence.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || automata_digest_part(
        pg_catalog.uuid_send(operation_id)
    )
    || automata_digest_part(
        pg_catalog.convert_to(tenant_id, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.uuid_send(repository_id)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(workflow_id)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(snapshot_id)
    )
    || automata_digest_part(pg_catalog.uuid_send(run_id))
    || automata_digest_part(
        pg_catalog.uuid_send(source_run_id)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(root_invocation_id)
    )
    || automata_digest_part(
        pg_catalog.int8send(github_repository_owner_id)
    )
    || automata_digest_part(
        pg_catalog.uuid_send(github_check_subject_id)
    )
    || automata_digest_part(github_check_head_sha)
    || automata_digest_part(
        pg_catalog.convert_to(workflow_path, 'UTF8')
    )
    || automata_digest_part(source_digest)
    || automata_digest_part(
        pg_catalog.convert_to(event_name, 'UTF8')
    )
    || automata_digest_part(event_digest)
    || automata_digest_part(
        pg_catalog.convert_to(git_ref, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.int8send(workflow_plan_schema::BIGINT)
    )
    || automata_digest_part(plan_digest)
    || automata_digest_part(logical_admission_digest)
    || automata_digest_part(
        pg_catalog.int8send(admitted_at_ms)
    )
)
$$;

CREATE FUNCTION automata_github_workflow_run_subject_evidence_digest(tenant_id text, repository_id uuid, workflow_id uuid, snapshot_id uuid, run_id uuid, root_invocation_id uuid, provider_delivery_id uuid, provider_delivery_idempotency_key text, admission_claim_owner_id uuid, admission_claim_attempt smallint, admission_claim_fence bigint, admission_claimed_at_ms bigint, admission_claim_expires_at_ms bigint, github_check_subject_id uuid, github_check_head_sha bytea, provider_connection_id uuid, provider_installation_id bigint, github_repository_id bigint, github_repository_owner_id bigint, github_repository_name text, repository_visibility text, provider_manifest_revision bigint, provider_manifest_digest bytea, authenticated_webhook_verifier_fingerprint_sha256 bytea, authenticated_webhook_verifier_revision bigint, checks_authority_id uuid, checks_authority_identity_digest bytea, checks_authority_app_configuration_revision bigint, checks_authority_policy_revision bigint, private_source_authority_id uuid, private_source_authority_identity_digest bytea, private_source_authority_app_configuration_revision bigint, private_source_authority_policy_revision bigint, request_digest bytea, raw_event_digest bytea, accepted_at_ms bigint, workflow_path text, source_digest bytea, event_name text, event_digest bytea, git_ref text, workflow_plan_schema smallint, plan_digest bytea, logical_admission_digest bytea, admitted_at_ms bigint) RETURNS bytea
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-workflow-run-subject-evidence.v1', 'UTF8'
    )
    || pg_catalog.decode('00', 'hex')
    || automata_digest_part(
        pg_catalog.convert_to(tenant_id, 'UTF8')
    )
    || automata_digest_part(pg_catalog.uuid_send(repository_id))
    || automata_digest_part(pg_catalog.uuid_send(workflow_id))
    || automata_digest_part(pg_catalog.uuid_send(snapshot_id))
    || automata_digest_part(pg_catalog.uuid_send(run_id))
    || automata_digest_part(pg_catalog.uuid_send(root_invocation_id))
    || automata_digest_part(pg_catalog.uuid_send(provider_delivery_id))
    || automata_digest_part(
        pg_catalog.convert_to(provider_delivery_idempotency_key, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.uuid_send(admission_claim_owner_id)
    )
    || automata_digest_part(
        pg_catalog.int8send(admission_claim_attempt::BIGINT)
    )
    || automata_digest_part(
        pg_catalog.int8send(admission_claim_fence)
    )
    || automata_digest_part(
        pg_catalog.int8send(admission_claimed_at_ms)
    )
    || automata_digest_part(
        pg_catalog.int8send(admission_claim_expires_at_ms)
    )
    || automata_digest_part(pg_catalog.uuid_send(github_check_subject_id))
    || automata_digest_part(github_check_head_sha)
    || automata_digest_part(pg_catalog.uuid_send(provider_connection_id))
    || automata_digest_part(
        pg_catalog.int8send(provider_installation_id)
    )
    || automata_digest_part(pg_catalog.int8send(github_repository_id))
    || automata_digest_part(
        pg_catalog.int8send(github_repository_owner_id)
    )
    || automata_digest_part(
        pg_catalog.convert_to(github_repository_name, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.convert_to(repository_visibility, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.int8send(provider_manifest_revision)
    )
    || automata_digest_part(provider_manifest_digest)
    || automata_digest_part(
        authenticated_webhook_verifier_fingerprint_sha256
    )
    || automata_digest_part(
        pg_catalog.int8send(authenticated_webhook_verifier_revision)
    )
    || automata_digest_part(pg_catalog.uuid_send(checks_authority_id))
    || automata_digest_part(checks_authority_identity_digest)
    || automata_digest_part(
        pg_catalog.int8send(checks_authority_app_configuration_revision)
    )
    || automata_digest_part(
        pg_catalog.int8send(checks_authority_policy_revision)
    )
    || automata_digest_part(
        CASE WHEN private_source_authority_id IS NULL
            THEN pg_catalog.decode('00', 'hex')
            ELSE pg_catalog.decode('01', 'hex')
        END
    )
    || CASE WHEN private_source_authority_id IS NULL THEN ''::BYTEA ELSE
        automata_digest_part(
            pg_catalog.uuid_send(private_source_authority_id)
        )
        || automata_digest_part(
            private_source_authority_identity_digest
        )
        || automata_digest_part(
            pg_catalog.int8send(private_source_authority_app_configuration_revision)
        )
        || automata_digest_part(
            pg_catalog.int8send(private_source_authority_policy_revision)
        )
       END
    || automata_digest_part(request_digest)
    || automata_digest_part(raw_event_digest)
    || automata_digest_part(pg_catalog.int8send(accepted_at_ms))
    || automata_digest_part(
        pg_catalog.convert_to(workflow_path, 'UTF8')
    )
    || automata_digest_part(source_digest)
    || automata_digest_part(
        pg_catalog.convert_to(event_name, 'UTF8')
    )
    || automata_digest_part(event_digest)
    || automata_digest_part(
        pg_catalog.convert_to(git_ref, 'UTF8')
    )
    || automata_digest_part(
        pg_catalog.int8send(workflow_plan_schema::BIGINT)
    )
    || automata_digest_part(plan_digest)
    || automata_digest_part(logical_admission_digest)
    || automata_digest_part(pg_catalog.int8send(admitted_at_ms))
)
$$;

CREATE FUNCTION automata_github_workflow_run_subject_evidence_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub workflow-run subject evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_workflow_run_subject_evidence_immutable';
END;
$$;

CREATE FUNCTION automata_github_workflow_run_subject_evidence_insert_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    source_evidence RECORD;
    source_evidence_found BOOLEAN;
    run_evidence RECORD;
    run_evidence_found BOOLEAN;
    expected_digest BYTEA;
BEGIN
    SELECT evidence_source.*,
           inbox_source.request_digest,
           inbox_source.raw_event_digest,
           inbox_source.accepted_at_ms,
           inbox_source.state AS inbox_state,
           inbox_source.attempt_count AS inbox_attempt_count,
           inbox_source.claim_fence AS inbox_claim_fence,
           inbox_source.claim_owner_id AS inbox_claim_owner_id,
           inbox_source.claimed_at_ms AS inbox_claimed_at_ms,
           inbox_source.claim_expires_at_ms AS inbox_claim_expires_at_ms,
           manifest_source.workflow_path AS manifest_workflow_path,
           manifest_source.workflow_selection_kind AS manifest_workflow_selection_kind,
           manifest_source.event_name AS manifest_event_name,
           manifest_source.git_ref AS manifest_git_ref,
           subject_source.id AS subject_id,
           subject_source.provider_delivery_id AS subject_delivery_id,
           subject_source.repository_id AS subject_repository_id,
           subject_source.head_sha AS subject_head_sha,
           subject_source.subject_key AS subject_key,
           subject_source.workflow_run_id AS subject_run_id,
           subject_source.linked_at_ms AS subject_linked_at_ms,
           subject_source.desired_state AS subject_desired_state,
           subject_source.desired_conclusion AS subject_desired_conclusion,
           subject_source.terminal_cause AS subject_terminal_cause,
           subject_source.desired_revision AS subject_desired_revision,
           subject_source.desired_updated_at_ms AS subject_desired_updated_at_ms,
           repository_source.scm_provider AS repository_scm_provider,
           repository_source.provider_repository_id AS repository_provider_id,
           repository_source.owner AS repository_owner,
           repository_source.name AS repository_name
      INTO source_evidence
    FROM github_provider_delivery_evidence AS evidence_source
    JOIN provider_delivery_inbox AS inbox_source
      ON inbox_source.id = evidence_source.provider_delivery_id
     AND inbox_source.tenant_id = evidence_source.tenant_id
    JOIN github_provider_manifest_revisions AS manifest_source
      ON manifest_source.tenant_id = evidence_source.tenant_id
     AND manifest_source.repository_id = evidence_source.repository_id
     AND manifest_source.provider_connection_id = evidence_source.provider_connection_id
     AND manifest_source.manifest_revision = evidence_source.provider_manifest_revision
     AND manifest_source.manifest_digest = evidence_source.provider_manifest_digest
     AND manifest_source.webhook_verifier_fingerprint_sha256 =
         evidence_source.authenticated_webhook_verifier_fingerprint_sha256
     AND manifest_source.webhook_verifier_revision =
         evidence_source.authenticated_webhook_verifier_revision
    JOIN repositories AS repository_source
      ON repository_source.tenant_id = evidence_source.tenant_id
     AND repository_source.id = evidence_source.repository_id
    JOIN github_check_subjects AS subject_source
      ON subject_source.id = NEW.github_check_subject_id
     AND subject_source.tenant_id = evidence_source.tenant_id
     AND subject_source.provider_delivery_id = evidence_source.provider_delivery_id
     AND subject_source.repository_id = evidence_source.repository_id
    WHERE evidence_source.provider_delivery_id = NEW.provider_delivery_id
      AND evidence_source.tenant_id = NEW.tenant_id
      AND evidence_source.repository_id = NEW.repository_id
    FOR SHARE OF evidence_source, inbox_source, manifest_source, subject_source,
                 repository_source;
    source_evidence_found = FOUND;

    SELECT run_source.repository_id,
           run_source.workflow_id,
           run_source.snapshot_id,
           run_source.head_sha,
           run_source.event_name,
           run_source.event_digest,
           run_source.git_ref,
           run_source.plan_schema,
           run_source.plan_digest,
           run_source.admission_epoch,
           run_source.created_at_ms,
           workflow_source.path AS workflow_path,
           snapshot_source.source_digest,
           marker_source.root_invocation_id,
           marker_source.admission_digest,
           marker_source.admitted_at_ms AS marker_admitted_at_ms,
           invocation_source.plan_schema AS invocation_plan_schema,
           invocation_source.plan_digest AS invocation_plan_digest,
           admission_receipt_source.repository_id AS receipt_repository_id,
           admission_receipt_source.run_id AS receipt_run_id,
           admission_receipt_source.committed_at_ms AS receipt_committed_at_ms,
           admission_receipt_source.github_subject_evidence_required AS
               receipt_github_evidence_required
      INTO run_evidence
    FROM workflow_runs AS run_source
    JOIN workflow_definitions AS workflow_source
      ON workflow_source.id = run_source.workflow_id
     AND workflow_source.repository_id = run_source.repository_id
    JOIN workflow_snapshots AS snapshot_source
      ON snapshot_source.id = run_source.snapshot_id
     AND snapshot_source.workflow_id = run_source.workflow_id
    JOIN logical_workflow_runs AS marker_source
      ON marker_source.run_id = run_source.id
    JOIN logical_workflow_invocations AS invocation_source
      ON invocation_source.run_id = run_source.id
     AND invocation_source.id = marker_source.root_invocation_id
    JOIN github_provider_delivery_evidence AS admission_evidence_source
      ON admission_evidence_source.tenant_id = NEW.tenant_id
     AND admission_evidence_source.repository_id = NEW.repository_id
     AND admission_evidence_source.provider_delivery_id = NEW.provider_delivery_id
    JOIN provider_delivery_inbox AS admission_inbox_source
      ON admission_inbox_source.id = admission_evidence_source.provider_delivery_id
     AND admission_inbox_source.tenant_id = admission_evidence_source.tenant_id
    JOIN workflow_admission_receipts AS admission_receipt_source
     ON admission_receipt_source.tenant_id = admission_evidence_source.tenant_id
     AND admission_receipt_source.idempotency_kind = 'provider_delivery'
     AND admission_receipt_source.idempotency_key =
         NEW.provider_delivery_idempotency_key
     AND admission_receipt_source.request_digest = marker_source.admission_digest
    WHERE run_source.repository_id = NEW.repository_id
      AND run_source.id = NEW.run_id
    FOR SHARE OF run_source, workflow_source, snapshot_source,
                 marker_source, invocation_source, admission_evidence_source,
                 admission_inbox_source, admission_receipt_source;
    run_evidence_found = FOUND;

    IF NOT source_evidence_found
        OR NOT run_evidence_found
        OR NEW.workflow_id <> run_evidence.workflow_id
        OR NEW.snapshot_id <> run_evidence.snapshot_id
        OR NEW.root_invocation_id <> run_evidence.root_invocation_id
        OR NEW.github_check_subject_id <> source_evidence.subject_id
        OR NEW.github_check_head_sha <> source_evidence.github_check_head_sha
        OR NEW.github_check_head_sha <> source_evidence.subject_head_sha
        OR NEW.github_check_head_sha <> run_evidence.head_sha
        OR source_evidence.repository_scm_provider <> 'github'
        OR source_evidence.repository_provider_id <>
            source_evidence.github_repository_id::TEXT
        OR source_evidence.repository_owner <>
            split_part(source_evidence.github_repository_name, '/', 1)
        OR source_evidence.repository_name <>
            split_part(source_evidence.github_repository_name, '/', 2)
        OR run_evidence.receipt_repository_id IS DISTINCT FROM NEW.repository_id
        OR run_evidence.receipt_run_id IS DISTINCT FROM NEW.run_id
        OR run_evidence.receipt_committed_at_ms IS DISTINCT FROM NEW.admitted_at_ms
        OR run_evidence.receipt_github_evidence_required IS DISTINCT FROM TRUE
        OR source_evidence.inbox_state <> 'claimed'
        OR source_evidence.inbox_attempt_count <> NEW.admission_claim_attempt
        OR source_evidence.inbox_claim_fence <> NEW.admission_claim_fence
        OR source_evidence.inbox_claim_owner_id <> NEW.admission_claim_owner_id
        OR source_evidence.inbox_claimed_at_ms <> NEW.admission_claimed_at_ms
        OR source_evidence.inbox_claim_expires_at_ms <>
            NEW.admission_claim_expires_at_ms
        OR NEW.admitted_at_ms < NEW.admission_claimed_at_ms
        OR NEW.admitted_at_ms >= NEW.admission_claim_expires_at_ms
        OR source_evidence.subject_delivery_id <> NEW.provider_delivery_id
        OR source_evidence.subject_repository_id <> NEW.repository_id
        OR source_evidence.subject_run_id <> NEW.run_id
        OR source_evidence.subject_linked_at_ms <> NEW.admitted_at_ms
        OR source_evidence.subject_desired_state <> 'in_progress'
        OR source_evidence.subject_desired_conclusion IS NOT NULL
        OR source_evidence.subject_terminal_cause IS NOT NULL
        OR source_evidence.subject_desired_revision <> 2
        OR source_evidence.subject_desired_updated_at_ms <> NEW.admitted_at_ms
        OR source_evidence.subject_key <> NEW.workflow_path
        OR NOT (
            source_evidence.manifest_workflow_selection_kind = 'all_direct'
            AND EXISTS (
                SELECT 1
                FROM provider_delivery_workflow_inventories AS inventory
                JOIN provider_delivery_workflow_inventory_entries AS entry
                  ON entry.inbox_id = inventory.inbox_id
                 AND entry.tenant_id = inventory.tenant_id
                WHERE inventory.inbox_id = NEW.provider_delivery_id
                  AND inventory.tenant_id = NEW.tenant_id
                  AND inventory.manifest_digest =
                      source_evidence.provider_manifest_digest
                  AND entry.workflow_path = NEW.workflow_path
                  AND entry.source_state = 'ready'
                  AND entry.source_digest = NEW.source_digest
            )
        )
        OR NEW.workflow_path <> run_evidence.workflow_path
        OR NEW.source_digest <> run_evidence.source_digest
        OR NEW.event_name <> COALESCE(source_evidence.authenticated_event_name, source_evidence.manifest_event_name)
        OR NEW.event_name <> run_evidence.event_name
        OR NEW.event_digest <> run_evidence.event_digest
        OR NEW.event_digest <> source_evidence.raw_event_digest
        OR NEW.git_ref <> COALESCE(source_evidence.authenticated_event_git_ref, source_evidence.manifest_git_ref)
        OR NEW.git_ref <> run_evidence.git_ref
        OR NEW.workflow_plan_schema <> run_evidence.plan_schema
        OR NEW.workflow_plan_schema <> run_evidence.invocation_plan_schema
        OR NEW.plan_digest <> run_evidence.plan_digest
        OR NEW.plan_digest <> run_evidence.invocation_plan_digest
        OR NEW.logical_admission_digest <> run_evidence.admission_digest
        OR run_evidence.admission_epoch <> 1
        OR NEW.admitted_at_ms <> run_evidence.created_at_ms
        OR NEW.admitted_at_ms <> run_evidence.marker_admitted_at_ms
        OR NEW.admitted_at_ms < source_evidence.accepted_at_ms
    THEN
        RAISE EXCEPTION 'GitHub workflow-run subject evidence authority is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_run_subject_evidence_authority_exact';
    END IF;

    expected_digest = automata_github_workflow_run_subject_evidence_digest(
        NEW.tenant_id,
        NEW.repository_id,
        NEW.workflow_id,
        NEW.snapshot_id,
        NEW.run_id,
        NEW.root_invocation_id,
        NEW.provider_delivery_id,
        NEW.provider_delivery_idempotency_key,
        NEW.admission_claim_owner_id,
        NEW.admission_claim_attempt,
        NEW.admission_claim_fence,
        NEW.admission_claimed_at_ms,
        NEW.admission_claim_expires_at_ms,
        NEW.github_check_subject_id,
        NEW.github_check_head_sha,
        source_evidence.provider_connection_id,
        source_evidence.provider_installation_id,
        source_evidence.github_repository_id,
        source_evidence.github_repository_owner_id,
        source_evidence.github_repository_name,
        source_evidence.repository_visibility,
        source_evidence.provider_manifest_revision,
        source_evidence.provider_manifest_digest,
        source_evidence.authenticated_webhook_verifier_fingerprint_sha256,
        source_evidence.authenticated_webhook_verifier_revision,
        source_evidence.checks_authority_id,
        source_evidence.checks_authority_identity_digest,
        source_evidence.checks_authority_app_configuration_revision,
        source_evidence.checks_authority_policy_revision,
        source_evidence.private_source_authority_id,
        source_evidence.private_source_authority_identity_digest,
        source_evidence.private_source_authority_app_configuration_revision,
        source_evidence.private_source_authority_policy_revision,
        source_evidence.request_digest,
        source_evidence.raw_event_digest,
        source_evidence.accepted_at_ms,
        NEW.workflow_path,
        NEW.source_digest,
        NEW.event_name,
        NEW.event_digest,
        NEW.git_ref,
        NEW.workflow_plan_schema,
        NEW.plan_digest,
        NEW.logical_admission_digest,
        NEW.admitted_at_ms
    );

    IF NEW.subject_evidence_sha256 IS DISTINCT FROM expected_digest THEN
        RAISE EXCEPTION 'GitHub workflow-run subject evidence digest is not canonical'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_workflow_run_subject_evidence_canonical';
    END IF;

    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_runtime_authority_mint_begin() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR pg_trigger_depth() <> 2 THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint begins are trigger-owned and immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_begin_immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        JOIN github_runtime_authority_mint_claims AS claim
          ON claim.attempt_id = authority.attempt_id
         AND claim.fencing_token = authority.fencing_token
         AND claim.claim_fence = authority.mint_claim_fence
         AND claim.tenant_id = authority.tenant_id
         AND claim.claim_owner_id = authority.mint_claim_owner_id
         AND claim.claimed_at_ms = NEW.claimed_at_ms
         AND claim.expires_at_ms = NEW.expires_at_ms
        WHERE authority.attempt_id = NEW.attempt_id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.tenant_id = NEW.tenant_id
          AND authority.state = 'minting'
          AND authority.mint_claim_fence = NEW.claim_fence
          AND authority.mint_claim_owner_id = NEW.claim_owner_id
          AND authority.mint_claimed_at_ms = NEW.claimed_at_ms
          AND authority.mint_started_at_ms = NEW.started_at_ms
          AND authority.mint_provider_request_millis =
              NEW.provider_request_millis
          AND NEW.started_at_ms::NUMERIC +
              NEW.provider_request_millis::NUMERIC
              <= authority.request_deadline_at_ms::NUMERIC
        FOR KEY SHARE OF authority, claim
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint begin is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_begin_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_runtime_authority_mint_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint claims are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_claim_immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = NEW.attempt_id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.tenant_id = NEW.tenant_id
          AND authority.state = 'claimed'
          AND authority.mint_claim_fence = NEW.claim_fence
          AND authority.mint_claim_owner_id = NEW.claim_owner_id
          AND authority.mint_claimed_at_ms = NEW.claimed_at_ms
          AND authority.mint_claim_expires_at_ms = NEW.expires_at_ms
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority mint claim is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_claim_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_runtime_authority_operation_receipt() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'GitHub runtime-authority operation evidence is immutable'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_operation_receipt_immutable';
END;
$$;

CREATE FUNCTION automata_guard_github_runtime_authority_operation_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR pg_trigger_depth() <> 2 THEN
        RAISE EXCEPTION 'GitHub runtime-authority operation transitions are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_operation_transition_immutable';
    END IF;
    NEW.operation_digest := automata_github_runtime_authority_operation_digest(
        NEW.request_kind, NEW.attempt_id, NEW.fencing_token,
        NEW.claim_fence, NEW.claim_owner_id, NEW.claim_claimed_at_ms,
        NEW.claim_expires_at_ms, NEW.request_observed_at_ms,
        NEW.request_retry_at_ms, NEW.request_failure_kind,
        NEW.request_commit_disposition, NEW.request_provider_expires_at_ms,
        NEW.request_safe_erase_after_ms, NEW.request_plaintext_schema,
        NEW.request_plaintext_size_bytes, NEW.request_plaintext_digest,
        NEW.request_aad_digest, NEW.request_envelope_digest
    );
    IF NEW.operation_digest IS NULL THEN
        RAISE EXCEPTION 'GitHub runtime-authority operation digest is not canonical'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_operation_digest_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_runtime_authority_revocation_claim() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'GitHub runtime-authority revocation claims are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_revocation_claim_immutable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM github_runtime_authority_issuances AS authority
        WHERE authority.attempt_id = NEW.attempt_id
          AND authority.fencing_token = NEW.fencing_token
          AND authority.tenant_id = NEW.tenant_id
          AND authority.state = 'revoke_pending'
          AND authority.revoke_claim_fence = NEW.claim_fence
          AND authority.revoke_claim_owner_id = NEW.claim_owner_id
          AND authority.revoke_claimed_at_ms = NEW.claimed_at_ms
          AND authority.revoke_claim_expires_at_ms = NEW.expires_at_ms
          AND authority.aad_digest = NEW.aad_digest
          AND authority.safe_erase_after_ms = NEW.safe_erase_after_ms
        FOR KEY SHARE
    ) THEN
        RAISE EXCEPTION 'GitHub runtime-authority revocation claim is not exact'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_revocation_claim_exact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION automata_guard_github_runtime_authority_database_time() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    database_now BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    IF NEW.state_updated_at_ms > database_now THEN
        RAISE EXCEPTION 'GitHub runtime-authority state time is ahead of PostgreSQL time'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_database_time';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'claimed'
            OR NEW.mint_claimed_at_ms > database_now
            OR NEW.mint_claim_expires_at_ms <= database_now
            OR NEW.state_updated_at_ms <> NEW.mint_claimed_at_ms
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority claim is not current at PostgreSQL time'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_insert_database_time';
        END IF;
        RETURN NEW;
    END IF;

    -- A terminal receipt observation does not advance lifecycle time.  Its
    -- exact database-time eligibility is re-proved by the trigger-owned
    -- operation transition after the lifecycle guard proves it is otherwise
    -- a byte-for-byte self transition.
    IF OLD.state = NEW.state
        AND NEW.operation_request_kind IS NOT NULL
        AND automata_github_runtime_authority_same_non_operation_state(
            OLD, NEW
        )
    THEN
        RETURN NEW;
    END IF;

    IF NEW.state = 'claimed' AND OLD.state IN ('claimed', 'mint_retry_pending') THEN
        IF NEW.mint_claimed_at_ms > database_now
            OR NEW.mint_claim_expires_at_ms <= database_now
            OR (
                OLD.state = 'claimed'
                AND OLD.mint_claim_expires_at_ms > database_now
            )
            OR (
                OLD.state = 'mint_retry_pending'
                AND OLD.next_mint_at_ms > database_now
            )
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority mint claim is not due and live'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_claim_database_time';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'minting' THEN
        IF OLD.mint_claimed_at_ms > database_now
            OR OLD.mint_claim_expires_at_ms <= database_now
            OR NEW.mint_started_at_ms > database_now
            OR NEW.mint_provider_request_millis NOT BETWEEN 1 AND 120000
            OR database_now::NUMERIC + NEW.mint_provider_request_millis::NUMERIC
                > OLD.mint_claim_expires_at_ms::NUMERIC
            OR database_now::NUMERIC + NEW.mint_provider_request_millis::NUMERIC
                > NEW.request_deadline_at_ms::NUMERIC
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority mint begin lacks a live database claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_begin_database_time';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'mint_retry_pending' THEN
        IF NEW.next_mint_at_ms <= database_now
            OR NEW.request_deadline_at_ms <= NEW.next_mint_at_ms
            OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority retry is not current at PostgreSQL time'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_retry_database_time';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'indeterminate' THEN
        IF NEW.indeterminate_at_ms > database_now
            OR NEW.conservative_expiry_at_ms <= database_now
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority indeterminate boundary is expired'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_indeterminate_database_time';
        END IF;
    ELSIF OLD.state IN ('minting', 'indeterminate')
          AND NEW.state IN ('ready', 'revoke_pending') THEN
        IF NEW.safe_erase_after_ms <= database_now
            OR (
                NEW.state = 'ready'
                AND (
                    OLD.state <> 'minting'
                    OR NEW.ready_at_ms > database_now
                    OR NEW.provider_expires_at_ms::NUMERIC
                        <= database_now::NUMERIC + 60000
                    OR NOT automata_github_runtime_authority_is_current(NEW, database_now)
                )
            )
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority finalization is stale at PostgreSQL time'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_finalize_database_time';
        END IF;
    ELSIF OLD.state = 'ready' AND NEW.state = 'revoke_pending' THEN
        IF NEW.safe_erase_after_ms <= database_now
            OR automata_github_runtime_authority_is_current(OLD, database_now)
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority revocation transition is not due'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_pending_database_time';
        END IF;
    ELSIF OLD.state IN ('ready', 'revoke_pending') AND NEW.state = 'quarantined' THEN
        IF NEW.quarantine_at_ms > database_now
            OR NEW.safe_erase_after_ms <= database_now
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority quarantine is past safe custody'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_quarantine_database_time';
        END IF;
    ELSIF OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending' THEN
        IF OLD.revoke_claim_owner_id IS NULL AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF OLD.next_revoke_at_ms > database_now
                OR NEW.revoke_claimed_at_ms > database_now
                OR NEW.revoke_claim_expires_at_ms <= database_now
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub runtime-authority revoke claim is not due and live'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_claim_database_time';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
              AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF OLD.revoke_claim_expires_at_ms > database_now
                OR NEW.revoke_claimed_at_ms > database_now
                OR NEW.revoke_claim_expires_at_ms <= database_now
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
            THEN
                RAISE EXCEPTION 'GitHub runtime-authority revoke takeover is not due and live'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_takeover_database_time';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
              AND NEW.revoke_claim_owner_id IS NULL THEN
            IF NEW.last_revoke_failure_kind = 'claim_budget_exhausted' THEN
                IF OLD.revoke_claim_expires_at_ms > database_now
                    OR NOT (
                        OLD.revoke_attempt_count = 64
                        OR OLD.revoke_claim_fence = 9223372036854775807
                    )
                THEN
                    RAISE EXCEPTION 'GitHub runtime-authority revoke budget is not exhausted'
                        USING ERRCODE = 'check_violation',
                              CONSTRAINT =
                                  'github_runtime_authority_revoke_budget_database_time';
                END IF;
            ELSIF OLD.revoke_claimed_at_ms > database_now
                OR OLD.revoke_claim_expires_at_ms <= database_now
            THEN
                RAISE EXCEPTION 'GitHub runtime-authority revoke outcome lacks a live claim'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_outcome_database_time';
            END IF;
        END IF;
    ELSIF NEW.state = 'revoked' THEN
        IF NEW.terminal_reason = 'provider_revocation_confirmed' AND (
                OLD.revoke_claimed_at_ms > database_now
                OR OLD.revoke_claim_expires_at_ms <= database_now
            )
            OR NEW.terminal_reason IN (
                'provider_authority_expired', 'conservative_authority_expired',
                'quarantined_authority_expired'
            ) AND OLD.safe_erase_after_ms > database_now
            OR NEW.terminal_reason = 'indeterminate_authority_expired'
                AND OLD.conservative_expiry_at_ms > database_now
            OR NEW.terminal_reason = 'superseded_before_mint'
                AND automata_github_runtime_authority_is_current(OLD, database_now)
            OR NEW.terminal_reason = 'request_expired_before_mint'
                AND OLD.request_deadline_at_ms > database_now
        THEN
            RAISE EXCEPTION 'GitHub runtime-authority terminal transition is not due'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_terminal_database_time';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
