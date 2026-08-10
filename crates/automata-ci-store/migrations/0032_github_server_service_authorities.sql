-- Current-only durable GitHub server-service credential authority. This state
-- is intentionally disjoint from workload runtime authority: one immutable
-- descriptor binds one internal repository, GitHub App installation, exact
-- repository spelling, fixed least-authority service policy, and App key/config
-- revision. Provider and KMS calls never occur in these transactions.

-- Check subjects predate this authority and did not retain the exact canonical
-- repository spelling needed to bind a server credential. This is a greenfield
-- contract: never guess/backfill existing Check state. Fresh inserts derive the
-- value from the already authenticated delivery and require exact agreement
-- with the configured internal repository.
DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM github_check_subjects)
        OR EXISTS (SELECT 1 FROM github_check_projection_outbox)
    THEN
        RAISE EXCEPTION 'existing GitHub Check state lacks canonical repository evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_canonical_name_current_only';
    END IF;
END;
$automata$;

ALTER TABLE github_check_subjects
    ADD COLUMN github_repository_name TEXT COLLATE "C" NOT NULL,
    ADD CONSTRAINT github_check_subjects_repository_name_shape CHECK (
        octet_length(github_repository_name) BETWEEN 3 AND 140
        AND github_repository_name ~ '^[^/]+/[^/]+$'
        AND octet_length(split_part(github_repository_name, '/', 1)) BETWEEN 1 AND 39
        AND octet_length(split_part(github_repository_name, '/', 2)) BETWEEN 1 AND 100
        AND (
            split_part(github_repository_name, '/', 1) ~ '^[A-Za-z0-9]$'
            OR split_part(github_repository_name, '/', 1)
                ~ '^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$'
        )
        AND split_part(github_repository_name, '/', 1) !~ '--'
        AND split_part(github_repository_name, '/', 2) ~ '^[A-Za-z0-9._-]+$'
        AND split_part(github_repository_name, '/', 2) NOT IN ('.', '..')
        AND split_part(github_repository_name, '/', 2) !~* '[.]git$'
    );

CREATE FUNCTION automata_github_check_subject_canonical_name()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
BEGIN
    SELECT * INTO delivery
    FROM provider_delivery_inbox
    WHERE id = NEW.provider_delivery_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    SELECT * INTO repository
    FROM repositories
    WHERE id = NEW.repository_id
      AND tenant_id = NEW.tenant_id
    FOR SHARE;
    IF delivery.id IS NULL
        OR repository.id IS NULL
        OR delivery.provider <> 'github'
        OR delivery.provider_repository_id <> NEW.github_repository_id
        OR delivery.repository_identity <> repository.owner || '/' || repository.name
    THEN
        RAISE EXCEPTION 'GitHub Check canonical repository identity is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_canonical_name_exact';
    END IF;
    NEW.github_repository_name := delivery.repository_identity;
    RETURN NEW;
END;
$automata$;

-- Trigger names order lexically; this derivation therefore runs before the
-- preexisting generic subject insert guard.
CREATE TRIGGER github_check_subjects_00_canonical_name
BEFORE INSERT ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_github_check_subject_canonical_name();

CREATE FUNCTION automata_github_check_subject_canonical_name_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.github_repository_name IS DISTINCT FROM OLD.github_repository_name THEN
        RAISE EXCEPTION 'GitHub Check canonical repository identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_check_subjects_canonical_name_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_check_subjects_canonical_name_immutable
BEFORE UPDATE ON github_check_subjects
FOR EACH ROW EXECUTE FUNCTION automata_github_check_subject_canonical_name_immutable();

CREATE TABLE github_server_service_authorities (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    provider_connection_id UUID NOT NULL,
    provider_installation_id BIGINT NOT NULL,
    github_app_id BIGINT NOT NULL,
    github_app_client_id TEXT COLLATE "C" NOT NULL,
    github_app_jwt_issuer_kind TEXT COLLATE "C" NOT NULL,
    github_repository_id BIGINT NOT NULL,
    github_repository_name TEXT COLLATE "C" NOT NULL,
    service_scope TEXT COLLATE "C" NOT NULL,
    permission_policy JSONB NOT NULL,
    policy_digest BYTEA NOT NULL,
    policy_revision BIGINT NOT NULL,
    app_key_spki_sha256 BYTEA NOT NULL,
    app_configuration_revision BIGINT NOT NULL,
    configuration_fingerprint BYTEA NOT NULL,
    identity_digest BYTEA NOT NULL,
    state TEXT COLLATE "C" NOT NULL DEFAULT 'active',
    current_issuance_generation BIGINT,
    refresh_issuance_generation BIGINT,
    next_issuance_generation BIGINT NOT NULL DEFAULT 1,
    consecutive_generation_failures SMALLINT NOT NULL DEFAULT 0,
    next_mint_not_before_ms BIGINT,
    mint_gate_generation BIGINT,
    failure_budget_rearm_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    state_updated_at_ms BIGINT NOT NULL,
    retired_at_ms BIGINT,
    CONSTRAINT github_server_service_authorities_tenant_id_unique
        UNIQUE (tenant_id, id),
    CONSTRAINT github_server_service_authorities_exact_config_unique UNIQUE (
        tenant_id, repository_id, provider_connection_id,
        provider_installation_id, service_scope, configuration_fingerprint
    ),
    CONSTRAINT github_server_service_authorities_repository_scope_revision_unique UNIQUE (
        tenant_id, repository_id, service_scope, app_configuration_revision,
        policy_revision
    ),
    CONSTRAINT github_server_service_authorities_repository_tenant
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_server_service_authorities_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_server_service_authorities_numeric_positive CHECK (
        provider_installation_id > 0
        AND github_app_id > 0
        AND github_repository_id > 0
        AND policy_revision > 0
        AND app_configuration_revision > 0
    ),
    CONSTRAINT github_server_service_authorities_app_client_shape CHECK (
        octet_length(github_app_client_id) BETWEEN 1 AND 128
        AND github_app_client_id ~ '^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$'
    ),
    CONSTRAINT github_server_service_authorities_jwt_issuer_kind CHECK (
        github_app_jwt_issuer_kind IN ('app_client_id', 'app_id')
    ),
    CONSTRAINT github_server_service_authorities_repository_name_shape CHECK (
        octet_length(github_repository_name) BETWEEN 3 AND 140
        AND github_repository_name ~ '^[^/]+/[^/]+$'
        AND octet_length(split_part(github_repository_name, '/', 1)) BETWEEN 1 AND 39
        AND octet_length(split_part(github_repository_name, '/', 2)) BETWEEN 1 AND 100
        AND (
            split_part(github_repository_name, '/', 1) ~ '^[A-Za-z0-9]$'
            OR split_part(github_repository_name, '/', 1)
                ~ '^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$'
        )
        AND split_part(github_repository_name, '/', 1) !~ '--'
        AND split_part(github_repository_name, '/', 2) ~ '^[A-Za-z0-9._-]+$'
        AND split_part(github_repository_name, '/', 2) NOT IN ('.', '..')
        AND split_part(github_repository_name, '/', 2) !~* '[.]git$'
    ),
    CONSTRAINT github_server_service_authorities_service_scope CHECK (
        service_scope IN ('checks_write', 'private_repository_source_read')
    ),
    CONSTRAINT github_server_service_authorities_permission_exact CHECK (
        (
            service_scope = 'checks_write'
            AND permission_policy = '{"checks":"write"}'::JSONB
            AND policy_digest = decode('6acf4ef0f49f5935d65a42dacb8ffcd49718dfd847d802d96038d81cea869a9c', 'hex')
        ) OR (
            service_scope = 'private_repository_source_read'
            AND permission_policy = '{"contents":"read"}'::JSONB
            AND policy_digest = decode('3c2516eac095f5bda3e7d20265497325e91030d1abe5907d4fb7fefcd0aa7f57', 'hex')
        )
    ),
    CONSTRAINT github_server_service_authorities_digest_shape CHECK (
        octet_length(policy_digest) = 32
        AND octet_length(app_key_spki_sha256) = 32
        AND octet_length(configuration_fingerprint) = 32
        AND octet_length(identity_digest) = 32
    ),
    CONSTRAINT github_server_service_authorities_state CHECK (
        state IN ('active', 'retiring', 'retired')
    ),
    CONSTRAINT github_server_service_authorities_generation_shape CHECK (
        next_issuance_generation > 0
        AND (
            current_issuance_generation IS NULL
            OR current_issuance_generation > 0
                AND current_issuance_generation < next_issuance_generation
        )
    ),
    CONSTRAINT github_server_service_authorities_generation_failure_shape CHECK ((
        consecutive_generation_failures BETWEEN 0 AND 32
        AND (
            consecutive_generation_failures = 0
                AND next_mint_not_before_ms IS NULL
                AND mint_gate_generation IS NULL
                AND failure_budget_rearm_at_ms IS NULL
            OR consecutive_generation_failures BETWEEN 1 AND 31
                AND next_mint_not_before_ms IS NOT NULL
                AND next_mint_not_before_ms >= created_at_ms
                AND mint_gate_generation IS NOT NULL
                AND mint_gate_generation > 0
                AND mint_gate_generation < next_issuance_generation
                AND failure_budget_rearm_at_ms IS NULL
            OR consecutive_generation_failures = 32
                AND next_mint_not_before_ms IS NOT NULL
                AND next_mint_not_before_ms >= created_at_ms
                AND mint_gate_generation IS NOT NULL
                AND mint_gate_generation > 0
                AND mint_gate_generation < next_issuance_generation
                AND failure_budget_rearm_at_ms IS NOT NULL
                AND failure_budget_rearm_at_ms >= created_at_ms
        )
    ) IS TRUE),
    CONSTRAINT github_server_service_authorities_refresh_shape CHECK (
        refresh_issuance_generation IS NULL OR (
            refresh_issuance_generation > 0
            AND refresh_issuance_generation < next_issuance_generation
            AND refresh_issuance_generation IS DISTINCT FROM current_issuance_generation
        )
    ),
    CONSTRAINT github_server_service_authorities_time_shape CHECK (
        created_at_ms >= 0
        AND state_updated_at_ms >= created_at_ms
        AND (
            state = 'active' AND retired_at_ms IS NULL
            OR state = 'retiring'
                AND retired_at_ms IS NULL
                AND current_issuance_generation IS NULL
                AND refresh_issuance_generation IS NULL
            OR state = 'retired'
                AND current_issuance_generation IS NULL
                AND refresh_issuance_generation IS NULL
                AND retired_at_ms IS NOT NULL
                AND retired_at_ms = state_updated_at_ms
        )
    )
);

-- Rust's canonical digest framing is an unsigned 64-bit big-endian length
-- followed by the exact bytes. PostgreSQL BIGINT send format is the same
-- two's-complement network representation for every admitted nonnegative
-- length/value.
CREATE FUNCTION automata_github_server_service_digest_part(BYTEA)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.int8send(pg_catalog.octet_length($1)::BIGINT) || $1
$automata$;

CREATE FUNCTION automata_github_server_service_identity_digest(
    github_server_service_authorities
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to(
        'automata.store.github-server-service.identity.v1', 'UTF8'
    ) || pg_catalog.decode('00', 'hex')
    || automata_github_server_service_digest_part(
        pg_catalog.convert_to(($1).tenant_id, 'UTF8')
    )
    || automata_github_server_service_digest_part(
        pg_catalog.uuid_send(($1).id)
    )
    || automata_github_server_service_digest_part(
        pg_catalog.uuid_send(($1).repository_id)
    )
    || automata_github_server_service_digest_part(
        pg_catalog.uuid_send(($1).provider_connection_id)
    )
    || automata_github_server_service_digest_part(
        pg_catalog.int8send(($1).provider_installation_id)
    )
    || automata_github_server_service_digest_part(
        pg_catalog.int8send(($1).github_app_id)
    )
    || automata_github_server_service_digest_part(
        pg_catalog.int8send(($1).github_repository_id)
    )
    || automata_github_server_service_digest_part(
        pg_catalog.convert_to(($1).github_repository_name, 'UTF8')
    )
    || automata_github_server_service_digest_part(
        pg_catalog.convert_to(($1).service_scope, 'UTF8')
    )
    || automata_github_server_service_digest_part(
        pg_catalog.convert_to(($1).github_app_client_id, 'UTF8')
    )
    || automata_github_server_service_digest_part(
        pg_catalog.convert_to(($1).github_app_jwt_issuer_kind, 'UTF8')
    )
    || automata_github_server_service_digest_part(($1).app_key_spki_sha256)
    || automata_github_server_service_digest_part(
        pg_catalog.int8send(($1).app_configuration_revision)
    )
    || automata_github_server_service_digest_part(
        pg_catalog.int8send(($1).policy_revision)
    )
    || automata_github_server_service_digest_part(($1).configuration_fingerprint)
)
$automata$;

ALTER TABLE github_server_service_authorities
ADD CONSTRAINT github_server_service_authorities_identity_digest_canonical CHECK (
    identity_digest = automata_github_server_service_identity_digest(
        github_server_service_authorities
    )
);

CREATE UNIQUE INDEX github_server_service_authorities_one_active_scope
    ON github_server_service_authorities (tenant_id, repository_id, service_scope)
    WHERE state = 'active';

CREATE TABLE github_server_service_authority_issuances (
    tenant_id TEXT NOT NULL,
    authority_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    state TEXT COLLATE "C" NOT NULL,
    mint_attempt_count SMALLINT NOT NULL,
    mint_claim_fence BIGINT NOT NULL,
    mint_claim_owner_id UUID,
    mint_claimed_at_ms BIGINT,
    mint_claim_expires_at_ms BIGINT,
    mint_started_at_ms BIGINT,
    mint_started_owner_id UUID,
    mint_started_claim_fence BIGINT,
    mint_started_claimed_at_ms BIGINT,
    mint_started_claim_expires_at_ms BIGINT,
    ready_at_ms BIGINT,
    generation_failure_gate_at_ms BIGINT,
    next_mint_at_ms BIGINT,
    mint_failure_kind TEXT COLLATE "C",
    requested_at_ms BIGINT NOT NULL,
    request_deadline_at_ms BIGINT NOT NULL,
    conservative_expiry_at_ms BIGINT NOT NULL,
    provider_expires_at_ms BIGINT,
    safe_erase_after_ms BIGINT NOT NULL,
    plaintext_schema SMALLINT,
    plaintext_size_bytes BIGINT,
    plaintext_digest BYTEA,
    aad_digest BYTEA,
    envelope_schema SMALLINT,
    wrapping_key_id TEXT COLLATE "C",
    wrapped_data_key BYTEA,
    nonce BYTEA,
    ciphertext BYTEA,
    revoke_attempt_count SMALLINT NOT NULL DEFAULT 0,
    revoke_claim_fence BIGINT NOT NULL DEFAULT 0,
    revoke_claim_owner_id UUID,
    revoke_claimed_at_ms BIGINT,
    revoke_claim_expires_at_ms BIGINT,
    revoke_result_owner_id UUID,
    revoke_result_claim_fence BIGINT,
    revoke_result_claimed_at_ms BIGINT,
    revoke_result_claim_expires_at_ms BIGINT,
    next_revoke_at_ms BIGINT,
    revoke_failure_kind TEXT COLLATE "C",
    terminal_reason TEXT COLLATE "C",
    created_at_ms BIGINT NOT NULL,
    state_updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (authority_id, generation),
    CONSTRAINT github_server_service_issuances_tenant_key_unique
        UNIQUE (tenant_id, authority_id, generation),
    CONSTRAINT github_server_service_issuances_authority_tenant
        FOREIGN KEY (tenant_id, authority_id)
        REFERENCES github_server_service_authorities(tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT github_server_service_issuances_generation_positive CHECK (generation > 0),
    CONSTRAINT github_server_service_issuances_state CHECK (
        state IN (
            'claimed', 'minting', 'mint_retry', 'indeterminate', 'ready',
            'revoke_pending', 'revoke_claimed', 'revoke_retry',
            'quarantined', 'rejected', 'revoked'
        )
    ),
    CONSTRAINT github_server_service_issuances_mint_attempt_bound CHECK (
        mint_attempt_count BETWEEN 1 AND 32
        AND mint_claim_fence BETWEEN 1 AND 9223372036854775807
        AND mint_claim_fence = mint_attempt_count
    ),
    CONSTRAINT github_server_service_issuances_revoke_attempt_bound CHECK (
        revoke_attempt_count BETWEEN 0 AND 64
        AND revoke_claim_fence BETWEEN 0 AND 9223372036854775807
        AND revoke_claim_fence = revoke_attempt_count
    ),
    CONSTRAINT github_server_service_issuances_claim_owner_non_nil CHECK (
        (mint_claim_owner_id IS NULL OR mint_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID)
        AND (mint_started_owner_id IS NULL OR mint_started_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID)
        AND (revoke_claim_owner_id IS NULL OR revoke_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID)
        AND (revoke_result_owner_id IS NULL OR revoke_result_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID)
    ),
    CONSTRAINT github_server_service_issuances_mint_started_provenance_shape CHECK (
        (
            mint_started_at_ms IS NULL
            AND mint_started_owner_id IS NULL
            AND mint_started_claim_fence IS NULL
            AND mint_started_claimed_at_ms IS NULL
            AND mint_started_claim_expires_at_ms IS NULL
        ) OR (
            mint_started_at_ms IS NOT NULL
            AND mint_started_owner_id IS NOT NULL
            AND mint_started_claim_fence IS NOT NULL
            AND mint_started_claimed_at_ms IS NOT NULL
            AND mint_started_claim_expires_at_ms IS NOT NULL
            AND mint_started_claim_fence = mint_claim_fence
            AND mint_started_claimed_at_ms >= requested_at_ms
            AND mint_started_at_ms >= mint_started_claimed_at_ms
            AND mint_started_claim_expires_at_ms > mint_started_at_ms
            AND mint_started_claim_expires_at_ms - mint_started_claimed_at_ms <= 120000
            AND mint_started_claim_expires_at_ms <= request_deadline_at_ms
        )
    ),
    CONSTRAINT github_server_service_issuances_request_horizon_exact CHECK (
        requested_at_ms >= 0
        AND request_deadline_at_ms > requested_at_ms
        AND request_deadline_at_ms - requested_at_ms <= 120000
        AND conservative_expiry_at_ms::NUMERIC
            = request_deadline_at_ms::NUMERIC + 3780000
        AND safe_erase_after_ms <= conservative_expiry_at_ms
        AND created_at_ms = requested_at_ms
        AND state_updated_at_ms >= created_at_ms
        AND (
            mint_started_at_ms IS NULL
            OR mint_started_at_ms >= requested_at_ms
                AND mint_started_at_ms < request_deadline_at_ms
        )
    ),
    CONSTRAINT github_server_service_issuances_provider_expiry_exact CHECK ((
        (
            provider_expires_at_ms IS NULL
            AND safe_erase_after_ms = conservative_expiry_at_ms
        ) OR (
            provider_expires_at_ms IS NOT NULL
            AND provider_expires_at_ms > requested_at_ms
            AND provider_expires_at_ms::NUMERIC
                <= request_deadline_at_ms::NUMERIC + 3660000
            AND safe_erase_after_ms::NUMERIC
                = provider_expires_at_ms::NUMERIC + 120000
            AND safe_erase_after_ms <= conservative_expiry_at_ms
        )
    ) IS TRUE),
    CONSTRAINT github_server_service_issuances_ready_evidence_exact CHECK ((
        (
            ready_at_ms IS NULL
            OR mint_started_at_ms IS NOT NULL
                AND ready_at_ms >= mint_started_at_ms
                AND ready_at_ms <= state_updated_at_ms
        )
        AND (
            state = 'ready' AND ready_at_ms = state_updated_at_ms
            OR state IN (
                'claimed', 'minting', 'mint_retry', 'indeterminate', 'rejected'
            ) AND ready_at_ms IS NULL
            OR state IN (
                'revoke_pending', 'revoke_claimed', 'revoke_retry',
                'quarantined', 'revoked'
            )
        )
    ) IS TRUE),
    CONSTRAINT github_server_service_issuances_generation_failure_gate_shape CHECK ((
        generation_failure_gate_at_ms IS NULL
            AND state IN ('claimed', 'minting', 'mint_retry', 'ready')
        OR state = 'rejected'
            AND generation_failure_gate_at_ms IS NOT NULL
            AND generation_failure_gate_at_ms >= created_at_ms
        OR state = 'indeterminate'
            AND generation_failure_gate_at_ms IS NOT NULL
            AND generation_failure_gate_at_ms >= created_at_ms
            AND generation_failure_gate_at_ms <= safe_erase_after_ms
        OR state IN (
            'revoke_pending', 'revoke_claimed', 'revoke_retry',
            'quarantined', 'revoked'
        ) AND (
            generation_failure_gate_at_ms IS NULL
            OR generation_failure_gate_at_ms >= created_at_ms
                AND generation_failure_gate_at_ms <= safe_erase_after_ms
        )
    ) IS TRUE),
    CONSTRAINT github_server_service_issuances_revoke_result_provenance_shape CHECK (
        (
            revoke_result_owner_id IS NULL
            AND revoke_result_claim_fence IS NULL
            AND revoke_result_claimed_at_ms IS NULL
            AND revoke_result_claim_expires_at_ms IS NULL
        ) OR (
            revoke_result_owner_id IS NOT NULL
            AND revoke_result_claim_fence IS NOT NULL
            AND revoke_result_claimed_at_ms IS NOT NULL
            AND revoke_result_claim_expires_at_ms IS NOT NULL
            AND revoke_result_claim_fence = revoke_claim_fence
            AND revoke_result_claim_fence > 0
            AND revoke_result_claimed_at_ms >= requested_at_ms
            AND revoke_result_claim_expires_at_ms > revoke_result_claimed_at_ms
            AND revoke_result_claim_expires_at_ms - revoke_result_claimed_at_ms <= 120000
            AND revoke_result_claim_expires_at_ms <= safe_erase_after_ms
            AND state IN ('revoke_retry', 'quarantined', 'revoked')
        )
        AND (state <> 'revoke_retry' OR revoke_result_owner_id IS NOT NULL)
        AND (
            state <> 'quarantined'
            OR revoke_attempt_count = 0 AND revoke_result_owner_id IS NULL
            OR revoke_attempt_count > 0 AND revoke_result_owner_id IS NOT NULL
        )
        AND (
            state <> 'revoked'
            OR terminal_reason <> 'provider_revoked'
            OR revoke_result_owner_id IS NOT NULL
        )
    ),
    CONSTRAINT github_server_service_issuances_failure_shape CHECK (
        (mint_failure_kind IS NULL OR (
            octet_length(mint_failure_kind) BETWEEN 1 AND 128
            AND (
                mint_failure_kind ~ '^[a-z0-9]$'
                OR mint_failure_kind ~ '^[a-z0-9][a-z0-9_.:-]*[a-z0-9]$'
            )
        ))
        AND (revoke_failure_kind IS NULL OR (
            octet_length(revoke_failure_kind) BETWEEN 1 AND 128
            AND (
                revoke_failure_kind ~ '^[a-z0-9]$'
                OR revoke_failure_kind ~ '^[a-z0-9][a-z0-9_.:-]*[a-z0-9]$'
            )
        ))
    ),
    CONSTRAINT github_server_service_issuances_protected_shape CHECK (
        (
            plaintext_schema IS NULL
            AND plaintext_size_bytes IS NULL
            AND plaintext_digest IS NULL
            AND aad_digest IS NULL
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
        ) OR (
            plaintext_schema IS NOT NULL
            AND plaintext_size_bytes IS NOT NULL
            AND plaintext_digest IS NOT NULL
            AND aad_digest IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND wrapping_key_id IS NOT NULL
            AND wrapped_data_key IS NOT NULL
            AND nonce IS NOT NULL
            AND ciphertext IS NOT NULL
            AND plaintext_schema = 1
            AND plaintext_size_bytes BETWEEN 1 AND 16384
            AND octet_length(plaintext_digest) = 32
            AND octet_length(aad_digest) = 32
            AND envelope_schema = 1
            AND octet_length(wrapping_key_id) BETWEEN 1 AND 64
            AND wrapping_key_id ~ '^[a-z0-9][a-z0-9._-]*[a-z0-9]$|^[a-z0-9]$'
            AND octet_length(wrapped_data_key) BETWEEN 1 AND 65536
            AND octet_length(nonce) = 12
            AND octet_length(ciphertext) = plaintext_size_bytes + 16
        )
    ),
    CONSTRAINT github_server_service_issuances_state_shape CHECK ((
        (
            state = 'claimed'
            AND mint_claim_owner_id IS NOT NULL
            AND mint_claimed_at_ms IS NOT NULL
            AND mint_claim_expires_at_ms IS NOT NULL
            AND mint_claimed_at_ms >= requested_at_ms
            AND mint_claimed_at_ms = state_updated_at_ms
            AND mint_claim_expires_at_ms > mint_claimed_at_ms
            AND mint_claim_expires_at_ms - mint_claimed_at_ms <= 120000
            AND mint_claim_expires_at_ms <= request_deadline_at_ms
            AND mint_started_at_ms IS NULL
            AND next_mint_at_ms IS NULL
            AND mint_failure_kind IS NULL
            AND provider_expires_at_ms IS NULL
            AND plaintext_schema IS NULL
            AND plaintext_size_bytes IS NULL
            AND plaintext_digest IS NULL
            AND aad_digest IS NULL
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'minting'
            AND mint_claim_owner_id IS NOT NULL
            AND mint_claimed_at_ms IS NOT NULL
            AND mint_claim_expires_at_ms IS NOT NULL
            AND mint_started_at_ms IS NOT NULL
            AND mint_claimed_at_ms >= requested_at_ms
            AND mint_claim_expires_at_ms > mint_started_at_ms
            AND mint_claim_expires_at_ms - mint_claimed_at_ms <= 120000
            AND mint_started_at_ms >= mint_claimed_at_ms
            AND mint_started_at_ms < request_deadline_at_ms
            AND state_updated_at_ms = mint_started_at_ms
            AND next_mint_at_ms IS NULL
            AND mint_failure_kind IS NULL
            AND provider_expires_at_ms IS NULL
            AND plaintext_schema IS NULL
            AND plaintext_size_bytes IS NULL
            AND plaintext_digest IS NULL
            AND aad_digest IS NULL
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'mint_retry'
            AND mint_attempt_count BETWEEN 1 AND 31
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NOT NULL
            AND next_mint_at_ms > state_updated_at_ms
            AND next_mint_at_ms - state_updated_at_ms <= 120000
            AND next_mint_at_ms < request_deadline_at_ms
            AND mint_failure_kind IS NOT NULL
            AND provider_expires_at_ms IS NULL
            AND plaintext_schema IS NULL
            AND plaintext_size_bytes IS NULL
            AND plaintext_digest IS NULL
            AND aad_digest IS NULL
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'indeterminate'
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NULL
            AND mint_failure_kind IS NOT NULL
            AND provider_expires_at_ms IS NULL
            AND plaintext_schema IS NULL
            AND plaintext_size_bytes IS NULL
            AND plaintext_digest IS NULL
            AND aad_digest IS NULL
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state IN ('ready', 'revoke_pending')
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NULL
            AND (
                state = 'ready'
                    AND mint_failure_kind IS NULL
                    AND provider_expires_at_ms IS NOT NULL
                OR state = 'revoke_pending'
                    AND (
                        provider_expires_at_ms IS NOT NULL
                            AND mint_failure_kind IS NULL
                        OR provider_expires_at_ms IS NULL
                            AND mint_failure_kind = 'provider_expiry_unknown'
                    )
            )
            AND plaintext_schema IS NOT NULL
            AND plaintext_size_bytes IS NOT NULL
            AND plaintext_digest IS NOT NULL
            AND aad_digest IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND wrapping_key_id IS NOT NULL
            AND wrapped_data_key IS NOT NULL
            AND nonce IS NOT NULL
            AND ciphertext IS NOT NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'revoke_claimed'
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NULL
            AND (
                provider_expires_at_ms IS NOT NULL
                    AND mint_failure_kind IS NULL
                OR provider_expires_at_ms IS NULL
                    AND mint_failure_kind = 'provider_expiry_unknown'
            )
            AND plaintext_schema IS NOT NULL
            AND plaintext_size_bytes IS NOT NULL
            AND plaintext_digest IS NOT NULL
            AND aad_digest IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND wrapping_key_id IS NOT NULL
            AND wrapped_data_key IS NOT NULL
            AND nonce IS NOT NULL
            AND ciphertext IS NOT NULL
            AND revoke_attempt_count BETWEEN 1 AND 64
            AND revoke_claim_fence > 0
            AND revoke_claim_owner_id IS NOT NULL
            AND revoke_claimed_at_ms IS NOT NULL
            AND revoke_claim_expires_at_ms IS NOT NULL
            AND revoke_claimed_at_ms = state_updated_at_ms
            AND revoke_claim_expires_at_ms > revoke_claimed_at_ms
            AND revoke_claim_expires_at_ms - revoke_claimed_at_ms <= 120000
            AND revoke_claim_expires_at_ms <= safe_erase_after_ms
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'revoke_retry'
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NULL
            AND (
                provider_expires_at_ms IS NOT NULL
                    AND mint_failure_kind IS NULL
                OR provider_expires_at_ms IS NULL
                    AND mint_failure_kind = 'provider_expiry_unknown'
            )
            AND plaintext_schema IS NOT NULL
            AND plaintext_size_bytes IS NOT NULL
            AND plaintext_digest IS NOT NULL
            AND aad_digest IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND wrapping_key_id IS NOT NULL
            AND wrapped_data_key IS NOT NULL
            AND nonce IS NOT NULL
            AND ciphertext IS NOT NULL
            AND revoke_attempt_count BETWEEN 1 AND 63
            AND revoke_claim_fence > 0
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NOT NULL
            AND next_revoke_at_ms > state_updated_at_ms
            AND next_revoke_at_ms - state_updated_at_ms <= 86400000
            AND next_revoke_at_ms < safe_erase_after_ms
            AND revoke_failure_kind IS NOT NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'quarantined'
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NULL
            AND (
                provider_expires_at_ms IS NOT NULL
                    AND mint_failure_kind IS NULL
                OR provider_expires_at_ms IS NULL
                    AND mint_failure_kind = 'provider_expiry_unknown'
            )
            AND plaintext_schema IS NOT NULL
            AND plaintext_size_bytes IS NOT NULL
            AND plaintext_digest IS NOT NULL
            AND aad_digest IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND wrapping_key_id IS NOT NULL
            AND wrapped_data_key IS NOT NULL
            AND nonce IS NOT NULL
            AND ciphertext IS NOT NULL
            AND revoke_attempt_count BETWEEN 0 AND 64
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NOT NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'rejected'
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND (
                mint_started_at_ms IS NULL
                OR mint_started_at_ms >= requested_at_ms
                    AND mint_started_at_ms < request_deadline_at_ms
            )
            AND next_mint_at_ms IS NULL
            AND mint_failure_kind IS NOT NULL
            AND provider_expires_at_ms IS NULL
            AND plaintext_schema IS NULL
            AND plaintext_size_bytes IS NULL
            AND plaintext_digest IS NULL
            AND aad_digest IS NULL
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NOT NULL
            AND terminal_reason IN (
                'request_expired', 'provider_rejected', 'retry_exhausted',
                'authority_retired_before_mint'
            )
            AND (
                terminal_reason IN ('request_expired', 'authority_retired_before_mint')
                OR terminal_reason IN ('provider_rejected', 'retry_exhausted')
                    AND mint_started_at_ms IS NOT NULL
            )
        ) OR (
            state = 'revoked'
            AND mint_claim_owner_id IS NULL
            AND mint_claimed_at_ms IS NULL
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NULL
            AND (
                terminal_reason = 'conservative_expiry'
                    AND provider_expires_at_ms IS NULL
                    AND mint_failure_kind IS NOT NULL
                OR terminal_reason = 'provider_expired'
                    AND provider_expires_at_ms IS NOT NULL
                    AND mint_failure_kind IS NULL
                OR terminal_reason = 'provider_revoked'
                    AND (
                        provider_expires_at_ms IS NOT NULL
                            AND mint_failure_kind IS NULL
                        OR provider_expires_at_ms IS NULL
                            AND mint_failure_kind = 'provider_expiry_unknown'
                    )
            )
            AND plaintext_schema IS NULL
            AND plaintext_size_bytes IS NULL
            AND plaintext_digest IS NULL
            AND aad_digest IS NULL
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
            AND revoke_claim_owner_id IS NULL
            AND revoke_claimed_at_ms IS NULL
            AND revoke_claim_expires_at_ms IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoke_failure_kind IS NULL
            AND terminal_reason IS NOT NULL
            AND terminal_reason IN (
                'provider_revoked', 'provider_expired', 'conservative_expiry'
            )
        )
    ) IS TRUE)
);

CREATE FUNCTION automata_github_server_service_aad_digest(
    BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    SMALLINT, BIGINT, BYTEA
)
RETURNS BYTEA
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $automata$
SELECT pg_catalog.sha256(
    pg_catalog.convert_to('automata.store.github-server-service.aad.v1', 'UTF8')
    || pg_catalog.decode('00', 'hex')
    || automata_github_server_service_digest_part($1)
    || automata_github_server_service_digest_part(pg_catalog.int8send($2))
    || automata_github_server_service_digest_part(pg_catalog.int8send($3))
    || automata_github_server_service_digest_part(pg_catalog.int8send($4))
    || automata_github_server_service_digest_part(
        CASE WHEN $5 IS NULL
            THEN pg_catalog.decode('00', 'hex')
            ELSE pg_catalog.decode('01', 'hex')
        END
    )
    || CASE WHEN $5 IS NULL THEN ''::BYTEA
        ELSE automata_github_server_service_digest_part(pg_catalog.int8send($5))
    END
    || automata_github_server_service_digest_part(pg_catalog.int8send($6))
    || automata_github_server_service_digest_part(pg_catalog.int2send($7))
    || automata_github_server_service_digest_part(pg_catalog.int8send($8))
    || automata_github_server_service_digest_part($9)
)
$automata$;

-- Maintenance discovery reads only bounded live heads. Terminal issuance
-- history remains immutable without making scheduler polls proportional to
-- that retained history.
CREATE INDEX github_server_service_issuances_erase_due
    ON github_server_service_authority_issuances (
        tenant_id, safe_erase_after_ms, authority_id, generation
    ) WHERE state IN (
        'ready', 'indeterminate', 'revoke_pending', 'revoke_claimed',
        'revoke_retry', 'quarantined'
    );

CREATE INDEX github_server_service_issuances_mint_claim_due
    ON github_server_service_authority_issuances (
        tenant_id,
        (LEAST(mint_claim_expires_at_ms, request_deadline_at_ms)),
        authority_id, generation
    ) WHERE state IN ('claimed', 'minting');

CREATE INDEX github_server_service_issuances_mint_retry_deadline_due
    ON github_server_service_authority_issuances (
        tenant_id, request_deadline_at_ms, authority_id, generation
    ) WHERE state = 'mint_retry';

CREATE INDEX github_server_service_issuances_mint_retry_due
    ON github_server_service_authority_issuances (
        tenant_id, next_mint_at_ms, authority_id, generation
    ) WHERE state = 'mint_retry';

CREATE INDEX github_server_service_issuances_revoke_pending_due
    ON github_server_service_authority_issuances (
        tenant_id, state_updated_at_ms, authority_id, generation
    ) WHERE state = 'revoke_pending';

CREATE INDEX github_server_service_issuances_revoke_retry_due
    ON github_server_service_authority_issuances (
        tenant_id, next_revoke_at_ms, authority_id, generation
    ) WHERE state = 'revoke_retry';

CREATE INDEX github_server_service_issuances_revoke_claim_due
    ON github_server_service_authority_issuances (
        tenant_id, revoke_claim_expires_at_ms, authority_id, generation
    ) WHERE state = 'revoke_claimed';

CREATE INDEX github_server_service_issuances_ready_refresh_due
    ON github_server_service_authority_issuances (
        tenant_id, ((provider_expires_at_ms::NUMERIC - 1680000)),
        authority_id, generation
    ) WHERE state = 'ready';

CREATE INDEX github_server_service_authorities_bootstrap_due
    ON github_server_service_authorities (
        tenant_id, state_updated_at_ms, id, next_issuance_generation
    ) WHERE state = 'active'
        AND current_issuance_generation IS NULL
        AND refresh_issuance_generation IS NULL;

ALTER TABLE github_server_service_authorities
    ADD CONSTRAINT github_server_service_authorities_current_generation_fk
        FOREIGN KEY (tenant_id, id, current_issuance_generation)
        REFERENCES github_server_service_authority_issuances(
            tenant_id, authority_id, generation
        ) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT github_server_service_authorities_refresh_generation_fk
        FOREIGN KEY (tenant_id, id, refresh_issuance_generation)
        REFERENCES github_server_service_authority_issuances(
            tenant_id, authority_id, generation
        ) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE github_server_service_authority_handoffs (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    authority_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    consumer_id UUID NOT NULL,
    consumer_owner_id UUID NOT NULL,
    consumer_claim_fence BIGINT NOT NULL,
    consumer_action TEXT COLLATE "C" NOT NULL,
    consumer_revision BIGINT NOT NULL,
    required_through_ms BIGINT NOT NULL,
    granted_at_ms BIGINT NOT NULL,
    released_at_ms BIGINT,
    CONSTRAINT github_server_service_handoffs_exact_consumer_unique UNIQUE (
        authority_id, consumer_id, consumer_owner_id,
        consumer_claim_fence, consumer_action, consumer_revision
    ),
    CONSTRAINT github_server_service_handoffs_issuance_fk
        FOREIGN KEY (tenant_id, authority_id, generation)
        REFERENCES github_server_service_authority_issuances(
            tenant_id, authority_id, generation
        ) ON DELETE RESTRICT,
    CONSTRAINT github_server_service_handoffs_non_nil CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND consumer_id <> '00000000-0000-0000-0000-000000000000'::UUID
        AND consumer_owner_id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT github_server_service_handoffs_positive CHECK (
        generation > 0
        AND consumer_claim_fence > 0
        AND consumer_revision > 0
    ),
    CONSTRAINT github_server_service_handoffs_action CHECK (
        consumer_action IN (
            'ensure_check_suite', 'create_check_run', 'reconcile_check_run',
            'publish_check_run', 'fetch_private_repository_revision',
            'fetch_private_repository_changed_files'
        )
    ),
    CONSTRAINT github_server_service_handoffs_time_shape CHECK (
        granted_at_ms >= 0
        AND required_through_ms > granted_at_ms
        AND required_through_ms - granted_at_ms <= CASE consumer_action
            WHEN 'publish_check_run' THEN 1500000
            ELSE 1200000
        END
        AND (released_at_ms IS NULL OR released_at_ms >= granted_at_ms)
    )
);

CREATE INDEX github_server_service_handoffs_live_issuance
    ON github_server_service_authority_handoffs (
        authority_id, generation, required_through_ms
    ) WHERE released_at_ms IS NULL;

CREATE FUNCTION automata_github_server_service_authority_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    repository repositories%ROWTYPE;
BEGIN
    SELECT * INTO repository
    FROM repositories
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.repository_id
    FOR SHARE;
    IF repository.id IS NULL
        OR repository.scm_provider <> 'github'
        OR repository.provider_repository_id <> NEW.github_repository_id::TEXT
        OR repository.owner || '/' || repository.name <> NEW.github_repository_name
        OR NEW.state <> 'active'
        OR NEW.current_issuance_generation IS NOT NULL
        OR NEW.refresh_issuance_generation IS NOT NULL
        OR NEW.next_issuance_generation <> 1
        OR NEW.consecutive_generation_failures <> 0
        OR NEW.next_mint_not_before_ms IS NOT NULL
        OR NEW.mint_gate_generation IS NOT NULL
        OR NEW.failure_budget_rearm_at_ms IS NOT NULL
        OR NEW.state_updated_at_ms <> NEW.created_at_ms
        OR NEW.retired_at_ms IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub server-service authority descriptor is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_initial_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_server_service_authorities_insert_guard
BEFORE INSERT ON github_server_service_authorities
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_authority_insert_guard();

CREATE FUNCTION automata_github_server_service_authority_update_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    current_state TEXT;
    refresh_state TEXT;
    refresh_updated_at_ms BIGINT;
    transition_state TEXT;
    transition_safe_erase_after_ms BIGINT;
    transition_updated_at_ms BIGINT;
    previous_current_state TEXT;
    previous_current_updated_at_ms BIGINT;
    gate_state TEXT;
    gate_terminal_reason TEXT;
    gate_generation_failure_gate_at_ms BIGINT;
    expected_gate_generation BIGINT;
    expected_gate_at_ms BIGINT;
    failure_gate_advanced BOOLEAN := FALSE;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.provider_installation_id IS DISTINCT FROM OLD.provider_installation_id
        OR NEW.github_app_id IS DISTINCT FROM OLD.github_app_id
        OR NEW.github_app_client_id IS DISTINCT FROM OLD.github_app_client_id
        OR NEW.github_app_jwt_issuer_kind IS DISTINCT FROM OLD.github_app_jwt_issuer_kind
        OR NEW.github_repository_id IS DISTINCT FROM OLD.github_repository_id
        OR NEW.github_repository_name IS DISTINCT FROM OLD.github_repository_name
        OR NEW.service_scope IS DISTINCT FROM OLD.service_scope
        OR NEW.permission_policy IS DISTINCT FROM OLD.permission_policy
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
        OR NEW.app_key_spki_sha256 IS DISTINCT FROM OLD.app_key_spki_sha256
        OR NEW.app_configuration_revision IS DISTINCT FROM OLD.app_configuration_revision
        OR NEW.configuration_fingerprint IS DISTINCT FROM OLD.configuration_fingerprint
        OR NEW.identity_digest IS DISTINCT FROM OLD.identity_digest
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.state_updated_at_ms < OLD.state_updated_at_ms
        OR NEW.next_issuance_generation < OLD.next_issuance_generation
    THEN
        RAISE EXCEPTION 'GitHub server-service authority identity is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_identity_immutable';
    END IF;
    IF NEW.state = 'active' AND OLD.state = 'active' THEN
        IF OLD.refresh_issuance_generation IS NOT NULL
            AND NEW.refresh_issuance_generation IS NULL
        THEN
            SELECT state, safe_erase_after_ms, state_updated_at_ms
            INTO transition_state, transition_safe_erase_after_ms,
                 transition_updated_at_ms
            FROM github_server_service_authority_issuances
            WHERE authority_id = NEW.id
              AND generation = OLD.refresh_issuance_generation;
            IF NEW.state_updated_at_ms IS DISTINCT FROM transition_updated_at_ms THEN
                RAISE EXCEPTION 'GitHub server-service refresh pointer time is not exact'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_pointer_time_exact';
            END IF;
            IF NEW.current_issuance_generation
                IS NOT DISTINCT FROM OLD.refresh_issuance_generation
            THEN
                IF OLD.current_issuance_generation IS NOT NULL THEN
                    SELECT state, state_updated_at_ms
                    INTO previous_current_state, previous_current_updated_at_ms
                    FROM github_server_service_authority_issuances
                    WHERE authority_id = NEW.id
                      AND generation = OLD.current_issuance_generation;
                END IF;
                IF transition_state IS DISTINCT FROM 'ready'
                    OR NEW.consecutive_generation_failures <> 0
                    OR NEW.next_mint_not_before_ms IS NOT NULL
                    OR NEW.mint_gate_generation IS NOT NULL
                    OR NEW.failure_budget_rearm_at_ms IS NOT NULL
                    OR OLD.current_issuance_generation IS NOT NULL
                        AND (
                            previous_current_state IS DISTINCT FROM 'revoke_pending'
                            OR previous_current_updated_at_ms
                                IS DISTINCT FROM transition_updated_at_ms
                        )
                THEN
                    RAISE EXCEPTION 'GitHub server-service ready generation did not reset its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
            ELSIF NEW.current_issuance_generation
                IS NOT DISTINCT FROM OLD.current_issuance_generation
            THEN
                IF transition_state IS NULL
                    OR NEW.consecutive_generation_failures <> LEAST(
                        OLD.consecutive_generation_failures + 1, 32
                    )
                    OR NEW.failure_budget_rearm_at_ms::NUMERIC
                        IS DISTINCT FROM (CASE
                            WHEN OLD.consecutive_generation_failures = 31
                                THEN transition_updated_at_ms::NUMERIC + 86400000
                            ELSE OLD.failure_budget_rearm_at_ms::NUMERIC
                        END)
                    OR (
                        transition_state = 'rejected'
                        AND NEW.next_mint_not_before_ms
                            IS DISTINCT FROM GREATEST(
                                COALESCE(
                                    OLD.next_mint_not_before_ms,
                                    transition_updated_at_ms + 60000
                                ),
                                transition_updated_at_ms + 60000
                            )
                    )
                    OR (
                        transition_state = 'rejected'
                        AND NEW.mint_gate_generation IS DISTINCT FROM (CASE
                            WHEN OLD.next_mint_not_before_ms IS NULL
                                OR transition_updated_at_ms + 60000
                                    > OLD.next_mint_not_before_ms
                                THEN OLD.refresh_issuance_generation
                            ELSE OLD.mint_gate_generation
                        END)
                    )
                    OR (
                        transition_state IN ('indeterminate', 'revoke_pending')
                        AND NEW.next_mint_not_before_ms
                            IS DISTINCT FROM GREATEST(
                                COALESCE(
                                    OLD.next_mint_not_before_ms,
                                    transition_safe_erase_after_ms
                                ),
                                transition_safe_erase_after_ms
                            )
                    )
                    OR (
                        transition_state IN ('indeterminate', 'revoke_pending')
                        AND NEW.mint_gate_generation IS DISTINCT FROM (CASE
                            WHEN OLD.next_mint_not_before_ms IS NULL
                                OR transition_safe_erase_after_ms
                                    > OLD.next_mint_not_before_ms
                                THEN OLD.refresh_issuance_generation
                            ELSE OLD.mint_gate_generation
                        END)
                    )
                    OR transition_state NOT IN (
                        'rejected', 'indeterminate', 'revoke_pending'
                    )
                THEN
                    RAISE EXCEPTION 'GitHub server-service failed generation did not advance its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
            ELSE
                RAISE EXCEPTION 'GitHub server-service refresh result changed an unrelated current generation'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
            END IF;
        ELSIF OLD.current_issuance_generation IS NOT NULL
            AND NEW.current_issuance_generation IS NULL
            AND NEW.refresh_issuance_generation
                IS NOT DISTINCT FROM OLD.refresh_issuance_generation
        THEN
            SELECT state, safe_erase_after_ms, state_updated_at_ms
            INTO transition_state, transition_safe_erase_after_ms,
                 transition_updated_at_ms
            FROM github_server_service_authority_issuances
            WHERE authority_id = NEW.id
              AND generation = OLD.current_issuance_generation;
            IF transition_state IS NULL
                OR NEW.state_updated_at_ms IS DISTINCT FROM transition_updated_at_ms
            THEN
                RAISE EXCEPTION 'GitHub server-service current reduction lacks its issuance'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
            ELSIF transition_state = 'quarantined' THEN
                IF NEW.consecutive_generation_failures <> LEAST(
                        OLD.consecutive_generation_failures + 1, 32
                    )
                    OR NEW.failure_budget_rearm_at_ms::NUMERIC
                        IS DISTINCT FROM (CASE
                            WHEN OLD.consecutive_generation_failures = 31
                                THEN transition_updated_at_ms::NUMERIC + 86400000
                            ELSE OLD.failure_budget_rearm_at_ms::NUMERIC
                        END)
                    OR NEW.next_mint_not_before_ms
                        IS DISTINCT FROM GREATEST(
                            COALESCE(
                                OLD.next_mint_not_before_ms,
                                transition_safe_erase_after_ms
                            ),
                            transition_safe_erase_after_ms
                        )
                    OR NEW.mint_gate_generation IS DISTINCT FROM (CASE
                        WHEN OLD.next_mint_not_before_ms IS NULL
                            OR transition_safe_erase_after_ms
                                > OLD.next_mint_not_before_ms
                            THEN OLD.current_issuance_generation
                        ELSE OLD.mint_gate_generation
                    END)
                THEN
                    RAISE EXCEPTION 'GitHub server-service quarantined current did not advance its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
            ELSIF NEW.consecutive_generation_failures
                    IS DISTINCT FROM OLD.consecutive_generation_failures
                OR NEW.next_mint_not_before_ms
                    IS DISTINCT FROM OLD.next_mint_not_before_ms
                OR NEW.mint_gate_generation
                    IS DISTINCT FROM OLD.mint_gate_generation
                OR NEW.failure_budget_rearm_at_ms
                    IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
            THEN
                RAISE EXCEPTION 'GitHub server-service current reduction rewrote its failure budget'
                    USING ERRCODE = 'integrity_constraint_violation',
                          CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
            END IF;
        ELSIF NEW.consecutive_generation_failures
                IS DISTINCT FROM OLD.consecutive_generation_failures
            OR NEW.next_mint_not_before_ms
                IS DISTINCT FROM OLD.next_mint_not_before_ms
            OR NEW.mint_gate_generation
                IS DISTINCT FROM OLD.mint_gate_generation
            OR NEW.failure_budget_rearm_at_ms
                IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
        THEN
            IF OLD.consecutive_generation_failures = 32
                AND OLD.refresh_issuance_generation IS NULL
                AND NEW.consecutive_generation_failures = 31
                AND NEW.next_mint_not_before_ms
                    IS NOT DISTINCT FROM OLD.next_mint_not_before_ms
                AND NEW.mint_gate_generation
                    IS NOT DISTINCT FROM OLD.mint_gate_generation
                AND NEW.failure_budget_rearm_at_ms IS NULL
                AND OLD.next_mint_not_before_ms <= NEW.state_updated_at_ms
                AND OLD.failure_budget_rearm_at_ms <= NEW.state_updated_at_ms
                AND NEW.current_issuance_generation
                    IS NOT DISTINCT FROM OLD.current_issuance_generation
                AND NEW.refresh_issuance_generation
                    IS NOT DISTINCT FROM OLD.refresh_issuance_generation
                AND NEW.next_issuance_generation
                    IS NOT DISTINCT FROM OLD.next_issuance_generation
            THEN
                failure_gate_advanced := TRUE;
            ELSE
                SELECT state, terminal_reason, state_updated_at_ms,
                       generation_failure_gate_at_ms
                INTO gate_state, gate_terminal_reason, transition_updated_at_ms,
                     gate_generation_failure_gate_at_ms
                FROM github_server_service_authority_issuances
                WHERE authority_id = NEW.id
                  AND generation = OLD.mint_gate_generation;
                IF gate_state = 'revoked'
                    AND gate_terminal_reason = 'provider_revoked'
                THEN
                    NULL;
                ELSIF gate_state = 'revoke_pending'
                    AND gate_generation_failure_gate_at_ms IS NOT NULL
                    AND gate_generation_failure_gate_at_ms
                        < OLD.next_mint_not_before_ms
                THEN
                    NULL;
                ELSE
                    RAISE EXCEPTION 'GitHub server-service failure gate lacks exact reduction evidence'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
                SELECT generation, effective_gate_at_ms
                INTO expected_gate_generation, expected_gate_at_ms
                FROM (
                    SELECT generation,
                           CASE
                               WHEN state = 'revoked'
                                    AND terminal_reason = 'provider_revoked'
                                   THEN LEAST(
                                       generation_failure_gate_at_ms::NUMERIC,
                                       state_updated_at_ms::NUMERIC + 60000
                                   )::BIGINT
                               ELSE generation_failure_gate_at_ms
                           END AS effective_gate_at_ms
                    FROM github_server_service_authority_issuances
                    WHERE authority_id = NEW.id
                      AND generation_failure_gate_at_ms IS NOT NULL
                ) AS failure_gate
                ORDER BY effective_gate_at_ms DESC, generation DESC
                LIMIT 1;
                IF expected_gate_generation IS NULL
                    OR OLD.mint_gate_generation IS NULL
                    OR NEW.current_issuance_generation
                        IS DISTINCT FROM OLD.current_issuance_generation
                    OR NEW.refresh_issuance_generation
                        IS DISTINCT FROM OLD.refresh_issuance_generation
                    OR NEW.next_issuance_generation
                        IS DISTINCT FROM OLD.next_issuance_generation
                    OR NEW.consecutive_generation_failures
                        IS DISTINCT FROM OLD.consecutive_generation_failures
                    OR NEW.next_mint_not_before_ms
                        IS DISTINCT FROM expected_gate_at_ms
                    OR NEW.mint_gate_generation
                        IS DISTINCT FROM expected_gate_generation
                    OR NEW.failure_budget_rearm_at_ms
                        IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
                    OR NEW.state_updated_at_ms
                        IS DISTINCT FROM transition_updated_at_ms
                THEN
                    RAISE EXCEPTION 'GitHub server-service lifecycle rewrote its failure budget'
                        USING ERRCODE = 'integrity_constraint_violation',
                              CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
                END IF;
                failure_gate_advanced := TRUE;
            END IF;
        END IF;
    ELSIF NEW.consecutive_generation_failures
            IS DISTINCT FROM OLD.consecutive_generation_failures
        OR NEW.next_mint_not_before_ms
            IS DISTINCT FROM OLD.next_mint_not_before_ms
        OR NEW.mint_gate_generation
            IS DISTINCT FROM OLD.mint_gate_generation
        OR NEW.failure_budget_rearm_at_ms
            IS DISTINCT FROM OLD.failure_budget_rearm_at_ms
    THEN
        RAISE EXCEPTION 'GitHub server-service non-active lifecycle rewrote its failure budget'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_generation_failure_exact';
    END IF;
    IF NEW.next_issuance_generation IS DISTINCT FROM OLD.next_issuance_generation THEN
        IF OLD.state <> 'active'
            OR OLD.refresh_issuance_generation IS NOT NULL
            OR NEW.next_issuance_generation <> OLD.next_issuance_generation + 1
            OR NEW.refresh_issuance_generation
                IS DISTINCT FROM OLD.next_issuance_generation
        THEN
            RAISE EXCEPTION 'GitHub server-service next generation was not reserved exactly'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_authorities_next_generation_exact';
        END IF;
    ELSIF OLD.refresh_issuance_generation IS NULL
        AND NEW.refresh_issuance_generation IS NOT NULL
    THEN
        RAISE EXCEPTION 'GitHub server-service refresh lacks generation reservation'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_next_generation_exact';
    END IF;
    IF NOT (
        NEW.state = OLD.state
        OR OLD.state = 'active' AND NEW.state = 'retiring'
        OR OLD.state = 'retiring' AND NEW.state = 'retired'
    ) THEN
        RAISE EXCEPTION 'GitHub server-service authority state transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_state_transition';
    END IF;
    IF NEW.state = OLD.state AND NOT failure_gate_advanced AND (
        OLD.state <> 'active'
        OR (
            NEW.current_issuance_generation
                IS NOT DISTINCT FROM OLD.current_issuance_generation
            AND NEW.refresh_issuance_generation
                IS NOT DISTINCT FROM OLD.refresh_issuance_generation
        )
    ) THEN
        RAISE EXCEPTION 'GitHub server-service authority replay rewrote lifecycle evidence'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_same_state_exact';
    END IF;
    IF OLD.state = 'retiring' AND NEW.state = 'retired' AND EXISTS (
        SELECT 1
        FROM github_server_service_authority_issuances
        WHERE authority_id = NEW.id
          AND (
              state NOT IN ('rejected', 'revoked')
              OR envelope_schema IS NOT NULL
          )
    ) THEN
        RAISE EXCEPTION 'GitHub server-service authority retired with retained custody'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_authorities_retired_terminal_exact';
    END IF;
    IF NEW.current_issuance_generation IS NOT NULL THEN
        SELECT state INTO current_state
        FROM github_server_service_authority_issuances
        WHERE authority_id = NEW.id
          AND generation = NEW.current_issuance_generation;
        IF current_state IS DISTINCT FROM 'ready' THEN
            RAISE EXCEPTION 'GitHub server-service current generation is not ready'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_authorities_current_ready';
        END IF;
    END IF;
    IF NEW.refresh_issuance_generation IS NOT NULL THEN
        SELECT state, state_updated_at_ms
        INTO refresh_state, refresh_updated_at_ms
        FROM github_server_service_authority_issuances
        WHERE authority_id = NEW.id
          AND generation = NEW.refresh_issuance_generation;
        IF refresh_state NOT IN ('claimed', 'minting', 'mint_retry')
            OR (
                NEW.refresh_issuance_generation
                    IS DISTINCT FROM OLD.refresh_issuance_generation
                AND NEW.state_updated_at_ms IS DISTINCT FROM refresh_updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub server-service refresh generation is not mintable'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_authorities_refresh_mintable';
        END IF;
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_server_service_authorities_update_guard
BEFORE UPDATE ON github_server_service_authorities
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_authority_update_guard();

CREATE FUNCTION automata_github_server_service_issuance_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER github_server_service_issuances_insert_guard
BEFORE INSERT ON github_server_service_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_issuance_insert_guard();

CREATE FUNCTION automata_github_server_service_issuance_update_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER github_server_service_issuances_update_guard
BEFORE UPDATE ON github_server_service_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_issuance_update_guard();

-- Pointer/state agreement spans two rows and several lifecycle updates. Keep
-- the check deferred so a transaction can atomically rotate current/refresh,
-- while direct or partially committed SQL can never strand a ready or
-- mintable generation outside its sole descriptor slot.
CREATE FUNCTION automata_github_server_service_issuance_pointer_exact()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE CONSTRAINT TRIGGER github_server_service_issuances_authority_pointer_exact
AFTER INSERT OR UPDATE ON github_server_service_authority_issuances
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_issuance_pointer_exact();

CREATE CONSTRAINT TRIGGER github_server_service_authorities_issuance_pointer_exact
AFTER INSERT OR UPDATE ON github_server_service_authorities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_issuance_pointer_exact();

CREATE FUNCTION automata_github_server_service_handoff_insert_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    issuance github_server_service_authority_issuances%ROWTYPE;
    authority github_server_service_authorities%ROWTYPE;
    check_outbox github_check_projection_outbox%ROWTYPE;
    check_subject github_check_subjects%ROWTYPE;
    delivery provider_delivery_inbox%ROWTYPE;
    repository repositories%ROWTYPE;
BEGIN
    SELECT * INTO issuance
    FROM github_server_service_authority_issuances
    WHERE tenant_id = NEW.tenant_id
      AND authority_id = NEW.authority_id
      AND generation = NEW.generation
    FOR SHARE;
    SELECT * INTO authority
    FROM github_server_service_authorities
    WHERE tenant_id = NEW.tenant_id
      AND id = NEW.authority_id
    FOR SHARE;
    IF issuance.authority_id IS NULL
        OR authority.id IS NULL
        OR authority.state <> 'active'
        OR authority.current_issuance_generation IS DISTINCT FROM NEW.generation
        OR issuance.state <> 'ready'
        OR issuance.state_updated_at_ms > NEW.granted_at_ms
        OR authority.state_updated_at_ms > NEW.granted_at_ms
        OR NEW.required_through_ms
            > issuance.provider_expires_at_ms - 60000
    THEN
        RAISE EXCEPTION 'GitHub server-service handoff authority is not exact'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_authority_exact';
    END IF;

    IF authority.service_scope = 'checks_write' THEN
        SELECT * INTO check_outbox
        FROM github_check_projection_outbox
        WHERE subject_id = NEW.consumer_id
        FOR SHARE;
        SELECT * INTO check_subject
        FROM github_check_subjects
        WHERE id = NEW.consumer_id
        FOR SHARE;
        IF check_outbox.subject_id IS NULL
            OR check_subject.id IS NULL
            OR check_outbox.state <> 'claimed'
            OR check_outbox.claim_owner_id <> NEW.consumer_owner_id
            OR check_outbox.claim_fence <> NEW.consumer_claim_fence
            OR check_outbox.claimed_desired_revision <> NEW.consumer_revision
            OR check_outbox.claimed_at_ms IS NULL
            OR check_outbox.claim_expires_at_ms IS NULL
            OR check_outbox.claimed_at_ms > NEW.granted_at_ms
            OR check_outbox.state_updated_at_ms > NEW.granted_at_ms
            OR check_outbox.claim_expires_at_ms <= NEW.granted_at_ms
            OR NEW.required_through_ms::NUMERIC
                > check_outbox.claim_expires_at_ms::NUMERIC
                    + (CASE NEW.consumer_action
                        WHEN 'publish_check_run' THEN 600000
                        ELSE 300000
                    END)
            OR (CASE NEW.consumer_action
                WHEN 'ensure_check_suite' THEN check_outbox.claim_action <> 'ensure_suite'
                WHEN 'create_check_run' THEN check_outbox.claim_action <> 'prepare_run_create'
                WHEN 'reconcile_check_run' THEN check_outbox.claim_action <> 'reconcile_run_create'
                WHEN 'publish_check_run' THEN check_outbox.claim_action <> 'publish'
                ELSE TRUE
            END)
            OR check_subject.tenant_id <> authority.tenant_id
            OR check_subject.repository_id <> authority.repository_id
            OR check_subject.provider_connection_id <> authority.provider_connection_id
            OR check_subject.provider_installation_id <> authority.provider_installation_id
            OR check_subject.github_app_id <> authority.github_app_id
            OR check_subject.github_repository_id <> authority.github_repository_id
            OR check_subject.github_repository_name <> authority.github_repository_name
        THEN
            RAISE EXCEPTION 'GitHub Checks handoff consumer claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_handoffs_checks_claim_exact';
        END IF;
    ELSIF authority.service_scope = 'private_repository_source_read' THEN
        SELECT * INTO delivery
        FROM provider_delivery_inbox
        WHERE id = NEW.consumer_id
        FOR SHARE;
        SELECT * INTO repository
        FROM repositories
        WHERE id = authority.repository_id
          AND tenant_id = authority.tenant_id
        FOR SHARE;
        IF delivery.id IS NULL
            OR repository.id IS NULL
            OR delivery.state IS DISTINCT FROM 'claimed'
            OR delivery.claim_owner_id IS DISTINCT FROM NEW.consumer_owner_id
            OR delivery.claim_fence IS DISTINCT FROM NEW.consumer_claim_fence
            OR delivery.attempt_count IS DISTINCT FROM NEW.consumer_revision
            OR delivery.claimed_at_ms IS NULL
            OR delivery.claim_expires_at_ms IS NULL
            OR delivery.claimed_at_ms > NEW.granted_at_ms
            OR delivery.state_updated_at_ms > NEW.granted_at_ms
            OR delivery.claim_expires_at_ms <= NEW.granted_at_ms
            OR NEW.required_through_ms::NUMERIC
                > delivery.claim_expires_at_ms::NUMERIC + 300000
            OR NEW.consumer_action NOT IN (
                'fetch_private_repository_revision',
                'fetch_private_repository_changed_files'
            )
            OR delivery.tenant_id IS DISTINCT FROM authority.tenant_id
            OR delivery.provider IS DISTINCT FROM 'github'
            OR delivery.repository_visibility IS DISTINCT FROM 'private'
            OR delivery.connection_id IS DISTINCT FROM authority.provider_connection_id
            OR delivery.installation_id IS DISTINCT FROM authority.provider_installation_id
            OR delivery.provider_repository_id IS DISTINCT FROM authority.github_repository_id
            OR delivery.repository_identity IS DISTINCT FROM authority.github_repository_name
            OR repository.scm_provider IS DISTINCT FROM 'github'
            OR repository.provider_repository_id
                IS DISTINCT FROM authority.github_repository_id::TEXT
            OR repository.owner || '/' || repository.name
                IS DISTINCT FROM authority.github_repository_name
        THEN
            RAISE EXCEPTION 'private GitHub source handoff consumer claim is not exact'
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'github_server_service_handoffs_source_claim_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub server-service handoff scope is unknown'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'github_server_service_handoffs_scope_exact';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_server_service_handoffs_insert_guard
BEFORE INSERT ON github_server_service_authority_handoffs
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_handoff_insert_guard();

CREATE FUNCTION automata_github_server_service_handoff_update_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
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
$automata$;

CREATE TRIGGER github_server_service_handoffs_update_guard
BEFORE UPDATE ON github_server_service_authority_handoffs
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_handoff_update_guard();

CREATE FUNCTION automata_github_server_service_reject_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub server-service authority evidence cannot be removed'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'github_server_service_authority_removal_forbidden';
END;
$automata$;

CREATE TRIGGER github_server_service_authorities_no_delete
BEFORE DELETE ON github_server_service_authorities
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_reject_removal();
CREATE TRIGGER github_server_service_authorities_no_truncate
BEFORE TRUNCATE ON github_server_service_authorities
FOR EACH STATEMENT EXECUTE FUNCTION automata_github_server_service_reject_removal();
CREATE TRIGGER github_server_service_issuances_no_delete
BEFORE DELETE ON github_server_service_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_reject_removal();
CREATE TRIGGER github_server_service_issuances_no_truncate
BEFORE TRUNCATE ON github_server_service_authority_issuances
FOR EACH STATEMENT EXECUTE FUNCTION automata_github_server_service_reject_removal();
CREATE TRIGGER github_server_service_handoffs_no_delete
BEFORE DELETE ON github_server_service_authority_handoffs
FOR EACH ROW EXECUTE FUNCTION automata_github_server_service_reject_removal();
CREATE TRIGGER github_server_service_handoffs_no_truncate
BEFORE TRUNCATE ON github_server_service_authority_handoffs
FOR EACH STATEMENT EXECUTE FUNCTION automata_github_server_service_reject_removal();
