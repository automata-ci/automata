-- Durable single-winner GitHub runtime authority. Provider and KMS I/O happen
-- strictly outside these transactions. The minting boundary is irreversible:
-- only an expired pre-mint claim can be taken over, while an ambiguous mint is
-- retained until a known token can be revoked or its conservative horizon has
-- passed. This migration deliberately does not perform the separately owned
-- JobIR-v5 admission cutover; its insert/current-state guards require schema 5
-- and therefore fail closed until that later migration is installed.

CREATE TABLE github_runtime_authority_issuances (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    lease_id UUID NOT NULL,
    lease_issued_at_ms BIGINT NOT NULL,
    lease_expires_at_ms BIGINT NOT NULL,
    run_id UUID NOT NULL,
    job_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    runner_slot INTEGER NOT NULL,
    job_ir_schema INTEGER NOT NULL,
    job_ir_size_bytes BIGINT NOT NULL,
    job_ir_digest BYTEA NOT NULL,
    repository_id UUID NOT NULL,
    github_repository_id BIGINT NOT NULL,
    github_repository_name TEXT COLLATE "C" NOT NULL,
    authority_namespace TEXT COLLATE "C" NOT NULL,
    policy_digest BYTEA NOT NULL,
    issuer_fingerprint BYTEA NOT NULL,
    configuration_fingerprint BYTEA NOT NULL,
    requested_at_ms BIGINT NOT NULL,
    request_deadline_at_ms BIGINT NOT NULL,
    conservative_expiry_at_ms BIGINT NOT NULL,

    state TEXT NOT NULL DEFAULT 'claimed',
    mint_attempt_count SMALLINT NOT NULL DEFAULT 1,
    mint_claim_fence BIGINT NOT NULL DEFAULT 1,
    mint_claim_owner_id UUID NOT NULL,
    mint_claimed_at_ms BIGINT NOT NULL,
    mint_claim_expires_at_ms BIGINT,
    mint_started_at_ms BIGINT,
    indeterminate_at_ms BIGINT,

    provider_expires_at_ms BIGINT,
    safe_erase_after_ms BIGINT,
    plaintext_schema INTEGER,
    plaintext_size_bytes BIGINT,
    plaintext_digest BYTEA,
    aad_digest BYTEA,
    envelope_schema INTEGER,
    wrapping_key_id TEXT COLLATE "C",
    wrapped_data_key BYTEA,
    nonce BYTEA,
    ciphertext BYTEA,
    ready_at_ms BIGINT,
    revoke_pending_at_ms BIGINT,

    revoke_attempt_count SMALLINT NOT NULL DEFAULT 0,
    revoke_claim_fence BIGINT NOT NULL DEFAULT 0,
    revoke_claim_owner_id UUID,
    revoke_claimed_at_ms BIGINT,
    revoke_claim_expires_at_ms BIGINT,
    next_revoke_at_ms BIGINT,
    last_revoke_failure_kind TEXT COLLATE "C",

    revoked_at_ms BIGINT,
    terminal_reason TEXT,
    state_updated_at_ms BIGINT NOT NULL,

    CONSTRAINT github_runtime_authority_primary_key PRIMARY KEY (
        attempt_id, fencing_token
    ),
    CONSTRAINT github_runtime_authority_tenant_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_run_job
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_job_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_tenant_runner
        FOREIGN KEY (tenant_id, runner_id)
        REFERENCES runners(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT github_runtime_authority_runner_session
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions(
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,

    CONSTRAINT github_runtime_authority_non_nil_identity CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND lease_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND runner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND runner_session_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND mint_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (
            revoke_claim_owner_id IS NULL
            OR revoke_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        )
    ),
    CONSTRAINT github_runtime_authority_execution_numbers CHECK (
        fencing_token > 0
        AND runner_session_epoch > 0
        AND runner_generation > 0
        AND runner_slot BETWEEN 1 AND 65535
    ),
    CONSTRAINT github_runtime_authority_current_job_ir_v5 CHECK (
        job_ir_schema = 5
        AND job_ir_size_bytes BETWEEN 1 AND 16777216
        AND octet_length(job_ir_digest) = 32
    ),
    CONSTRAINT github_runtime_authority_github_repository_id_positive CHECK (
        github_repository_id > 0
    ),
    CONSTRAINT github_runtime_authority_github_repository_name_shape CHECK (
        octet_length(github_repository_name) BETWEEN 3 AND 140
        AND github_repository_name ~ '^[^/]+/[^/]+$'
        AND octet_length(split_part(github_repository_name, '/', 1)) BETWEEN 1 AND 39
        AND split_part(github_repository_name, '/', 1)
            ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$'
        AND split_part(github_repository_name, '/', 1) NOT LIKE '%--%'
        AND octet_length(split_part(github_repository_name, '/', 2)) BETWEEN 1 AND 100
        AND split_part(github_repository_name, '/', 2) ~ '^[A-Za-z0-9._-]+$'
        AND split_part(github_repository_name, '/', 2) NOT IN ('.', '..')
        AND lower(split_part(github_repository_name, '/', 2)) NOT LIKE '%.git'
    ),
    CONSTRAINT github_runtime_authority_namespace_shape CHECK (
        octet_length(authority_namespace) BETWEEN 1 AND 128
        AND authority_namespace ~ '^[a-z0-9]([a-z0-9._:/-]*[a-z0-9])?$'
    ),
    CONSTRAINT github_runtime_authority_identity_digests CHECK (
        octet_length(policy_digest) = 32
        AND octet_length(issuer_fingerprint) = 32
        AND octet_length(configuration_fingerprint) = 32
    ),
    CONSTRAINT github_runtime_authority_request_time_shape CHECK (
        lease_issued_at_ms >= 0
        AND lease_expires_at_ms > lease_issued_at_ms
        AND requested_at_ms >= lease_issued_at_ms
        AND requested_at_ms < lease_expires_at_ms
        AND request_deadline_at_ms > requested_at_ms
        AND request_deadline_at_ms <= lease_expires_at_ms
        AND request_deadline_at_ms - requested_at_ms <= 120000
        AND conservative_expiry_at_ms::NUMERIC
            = request_deadline_at_ms::NUMERIC + 3720000
    ),
    CONSTRAINT github_runtime_authority_state CHECK (
        state IN ('claimed', 'minting', 'indeterminate', 'ready', 'revoke_pending', 'revoked')
    ),
    CONSTRAINT github_runtime_authority_mint_claim_bounds CHECK (
        mint_attempt_count BETWEEN 1 AND 32
        AND mint_claim_fence > 0
        AND mint_claimed_at_ms >= requested_at_ms
        AND (
            mint_claim_expires_at_ms IS NULL
            OR (
                mint_claim_expires_at_ms > mint_claimed_at_ms
                AND mint_claim_expires_at_ms <= request_deadline_at_ms
                AND mint_claim_expires_at_ms - mint_claimed_at_ms <= 120000
            )
        )
    ),
    CONSTRAINT github_runtime_authority_protected_metadata_complete CHECK (
        (provider_expires_at_ms IS NULL)
            = (safe_erase_after_ms IS NULL)
        AND (provider_expires_at_ms IS NULL)
            = (plaintext_schema IS NULL)
        AND (provider_expires_at_ms IS NULL)
            = (plaintext_size_bytes IS NULL)
        AND (provider_expires_at_ms IS NULL)
            = (plaintext_digest IS NULL)
        AND (provider_expires_at_ms IS NULL)
            = (aad_digest IS NULL)
    ),
    CONSTRAINT github_runtime_authority_protected_metadata_shape CHECK (
        provider_expires_at_ms IS NULL OR (
            provider_expires_at_ms > requested_at_ms
            AND provider_expires_at_ms::NUMERIC
                <= request_deadline_at_ms::NUMERIC + 3600000
            AND safe_erase_after_ms::NUMERIC
                = provider_expires_at_ms::NUMERIC + 120000
            AND safe_erase_after_ms <= conservative_expiry_at_ms
            AND plaintext_schema = 1
            AND plaintext_size_bytes BETWEEN 1 AND 65536
            AND octet_length(plaintext_digest) = 32
            AND octet_length(aad_digest) = 32
        )
    ),
    CONSTRAINT github_runtime_authority_envelope_complete CHECK (
        (envelope_schema IS NULL) = (wrapping_key_id IS NULL)
        AND (envelope_schema IS NULL) = (wrapped_data_key IS NULL)
        AND (envelope_schema IS NULL) = (nonce IS NULL)
        AND (envelope_schema IS NULL) = (ciphertext IS NULL)
    ),
    CONSTRAINT github_runtime_authority_envelope_shape CHECK (
        envelope_schema IS NULL OR (
            provider_expires_at_ms IS NOT NULL
            AND envelope_schema = 1
            AND octet_length(wrapping_key_id) BETWEEN 1 AND 64
            AND wrapping_key_id ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
            AND octet_length(wrapped_data_key) BETWEEN 1 AND 65536
            AND octet_length(nonce) = 12
            AND octet_length(ciphertext)::NUMERIC
                = plaintext_size_bytes::NUMERIC + 16
            AND octet_length(ciphertext) <= 65552
        )
    ),
    CONSTRAINT github_runtime_authority_revoke_claim_bounds CHECK (
        revoke_attempt_count BETWEEN 0 AND 64
        AND revoke_claim_fence >= 0
        AND (revoke_claim_owner_id IS NULL) = (revoke_claimed_at_ms IS NULL)
        AND (revoke_claim_owner_id IS NULL) = (revoke_claim_expires_at_ms IS NULL)
        AND (
            revoke_claim_owner_id IS NULL OR (
                revoke_claim_fence > 0
                AND revoke_attempt_count > 0
                AND revoke_claim_expires_at_ms > revoke_claimed_at_ms
                AND revoke_claim_expires_at_ms - revoke_claimed_at_ms <= 120000
            )
        )
    ),
    CONSTRAINT github_runtime_authority_revoke_failure_shape CHECK (
        last_revoke_failure_kind IS NULL OR (
            octet_length(last_revoke_failure_kind) BETWEEN 1 AND 128
            AND last_revoke_failure_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    CONSTRAINT github_runtime_authority_terminal_reason CHECK (
        terminal_reason IS NULL OR terminal_reason IN (
            'superseded_before_mint', 'request_expired_before_mint',
            'provider_revocation_confirmed', 'provider_authority_expired',
            'indeterminate_authority_expired'
        )
    ),
    CONSTRAINT github_runtime_authority_state_time_monotonic CHECK (
        state_updated_at_ms >= requested_at_ms
        AND (mint_started_at_ms IS NULL OR mint_started_at_ms >= mint_claimed_at_ms)
        AND (indeterminate_at_ms IS NULL OR indeterminate_at_ms >= mint_started_at_ms)
        AND (ready_at_ms IS NULL OR ready_at_ms >= mint_started_at_ms)
        AND (revoke_pending_at_ms IS NULL OR revoke_pending_at_ms >= mint_started_at_ms)
        AND (revoked_at_ms IS NULL OR revoked_at_ms >= requested_at_ms)
    ),
    CONSTRAINT github_runtime_authority_state_shape CHECK ((
        (
            state = 'claimed'
            AND mint_claim_expires_at_ms IS NOT NULL
            AND mint_started_at_ms IS NULL
            AND indeterminate_at_ms IS NULL
            AND provider_expires_at_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND last_revoke_failure_kind IS NULL
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
            AND state_updated_at_ms = mint_claimed_at_ms
        ) OR (
            state = 'minting'
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms = state_updated_at_ms
            AND indeterminate_at_ms IS NULL
            AND provider_expires_at_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND last_revoke_failure_kind IS NULL
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'indeterminate'
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND indeterminate_at_ms = state_updated_at_ms
            AND provider_expires_at_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND last_revoke_failure_kind IS NULL
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'ready'
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND provider_expires_at_ms IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND ready_at_ms = state_updated_at_ms
            AND revoke_pending_at_ms IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND last_revoke_failure_kind IS NULL
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'revoke_pending'
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND provider_expires_at_ms IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND revoke_pending_at_ms IS NOT NULL
            AND (
                (
                    revoke_claim_owner_id IS NULL
                    AND next_revoke_at_ms IS NOT NULL
                    AND next_revoke_at_ms >= revoke_pending_at_ms
                ) OR (
                    revoke_claim_owner_id IS NOT NULL
                    AND next_revoke_at_ms IS NULL
                )
            )
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'revoked'
            AND mint_claim_expires_at_ms IS NULL
            AND envelope_schema IS NULL
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoked_at_ms = state_updated_at_ms
            AND terminal_reason IS NOT NULL
            AND (
                (
                    terminal_reason IN (
                        'superseded_before_mint', 'request_expired_before_mint'
                    )
                    AND mint_started_at_ms IS NULL
                    AND indeterminate_at_ms IS NULL
                    AND ready_at_ms IS NULL
                    AND revoke_pending_at_ms IS NULL
                    AND provider_expires_at_ms IS NULL
                    AND revoke_attempt_count = 0
                    AND revoke_claim_fence = 0
                    AND last_revoke_failure_kind IS NULL
                ) OR (
                    terminal_reason = 'indeterminate_authority_expired'
                    AND mint_started_at_ms IS NOT NULL
                    AND ready_at_ms IS NULL
                    AND revoke_pending_at_ms IS NULL
                    AND provider_expires_at_ms IS NULL
                    AND revoke_attempt_count = 0
                    AND revoke_claim_fence = 0
                    AND last_revoke_failure_kind IS NULL
                ) OR (
                    terminal_reason IN (
                        'provider_revocation_confirmed', 'provider_authority_expired'
                    )
                    AND mint_started_at_ms IS NOT NULL
                    AND provider_expires_at_ms IS NOT NULL
                    AND (ready_at_ms IS NOT NULL OR revoke_pending_at_ms IS NOT NULL)
                )
            )
        )
    ) IS TRUE)
);

CREATE INDEX github_runtime_authority_expired_mint_claims
    ON github_runtime_authority_issuances (mint_claim_expires_at_ms, requested_at_ms, attempt_id)
    WHERE state = 'claimed';

CREATE INDEX github_runtime_authority_mint_deadlines
    ON github_runtime_authority_issuances (request_deadline_at_ms, attempt_id)
    WHERE state = 'minting';

CREATE INDEX github_runtime_authority_revoke_ready
    ON github_runtime_authority_issuances (
        coalesce(next_revoke_at_ms, revoke_claim_expires_at_ms),
        revoke_pending_at_ms,
        attempt_id
    )
    WHERE state = 'revoke_pending';

CREATE UNIQUE INDEX github_runtime_authority_revoke_owner_unique
    ON github_runtime_authority_issuances (revoke_claim_owner_id)
    WHERE revoke_claim_owner_id IS NOT NULL;

CREATE INDEX github_runtime_authority_safe_erasure
    ON github_runtime_authority_issuances (
        coalesce(safe_erase_after_ms, conservative_expiry_at_ms), attempt_id
    )
    WHERE state IN ('minting', 'indeterminate', 'ready', 'revoke_pending');

CREATE FUNCTION automata_github_runtime_authority_is_current(
    authority github_runtime_authority_issuances,
    observed_at BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $automata$
    SELECT EXISTS (
        SELECT 1
        FROM job_attempts AS attempt
        JOIN jobs AS job
          ON job.id = attempt.job_id
         AND job.id = authority.job_id
         AND job.run_id = authority.run_id
        JOIN workflow_runs AS run
          ON run.id = job.run_id
         AND run.id = authority.run_id
         AND run.repository_id = authority.repository_id
        JOIN repositories AS repository
          ON repository.id = run.repository_id
         AND repository.id = authority.repository_id
         AND repository.tenant_id = authority.tenant_id
        JOIN runners AS runner
          ON runner.id = attempt.runner_id
         AND runner.id = authority.runner_id
         AND runner.tenant_id = authority.tenant_id
         AND runner.generation = authority.runner_generation
         AND runner.session_epoch = authority.runner_session_epoch
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.id = authority.runner_session_id
         AND session.runner_id = authority.runner_id
         AND session.session_epoch = authority.runner_session_epoch
         AND session.runner_generation = authority.runner_generation
        WHERE attempt.id = authority.attempt_id
          AND attempt.job_id = authority.job_id
          AND attempt.fencing_token = authority.fencing_token
          AND attempt.lease_id = authority.lease_id
          AND attempt.lease_issued_at_ms = authority.lease_issued_at_ms
          AND attempt.lease_expires_at_ms >= authority.lease_expires_at_ms
          AND attempt.lease_expires_at_ms > observed_at
          AND attempt.runner_id = authority.runner_id
          AND attempt.runner_session_id = authority.runner_session_id
          AND attempt.runner_session_epoch = authority.runner_session_epoch
          AND attempt.runner_generation = authority.runner_generation
          AND attempt.runner_slot = authority.runner_slot
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND attempt.changed_at_ms <= observed_at
          AND job.job_ir_schema = 5
          AND job.job_ir_schema = authority.job_ir_schema
          AND job.job_ir_size_bytes = authority.job_ir_size_bytes
          AND job.job_ir_digest = authority.job_ir_digest
          AND run.status IN ('queued', 'in_progress')
          AND repository.scm_provider = 'github'
          AND repository.provider_repository_id = authority.github_repository_id::TEXT
          AND repository.owner || '/' || repository.name = authority.github_repository_name
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND session.job_ir_schema = 5
          AND session.disconnected_at_ms IS NULL
    )
$automata$;

CREATE FUNCTION automata_validate_github_runtime_authority_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.state <> 'claimed'
        OR NEW.mint_attempt_count <> 1
        OR NEW.mint_claim_fence <> 1
        OR NOT automata_github_runtime_authority_is_current(
            NEW, NEW.mint_claimed_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority does not match current JobIR-v5 attempt authority'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_current_attempt_insert';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_insert_guard
BEFORE INSERT ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_validate_github_runtime_authority_insert();

CREATE FUNCTION automata_enforce_github_runtime_authority_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
        OR NEW.fencing_token IS DISTINCT FROM OLD.fencing_token
        OR NEW.lease_id IS DISTINCT FROM OLD.lease_id
        OR NEW.lease_issued_at_ms IS DISTINCT FROM OLD.lease_issued_at_ms
        OR NEW.lease_expires_at_ms IS DISTINCT FROM OLD.lease_expires_at_ms
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.job_id IS DISTINCT FROM OLD.job_id
        OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
        OR NEW.runner_session_id IS DISTINCT FROM OLD.runner_session_id
        OR NEW.runner_session_epoch IS DISTINCT FROM OLD.runner_session_epoch
        OR NEW.runner_generation IS DISTINCT FROM OLD.runner_generation
        OR NEW.runner_slot IS DISTINCT FROM OLD.runner_slot
        OR NEW.job_ir_schema IS DISTINCT FROM OLD.job_ir_schema
        OR NEW.job_ir_size_bytes IS DISTINCT FROM OLD.job_ir_size_bytes
        OR NEW.job_ir_digest IS DISTINCT FROM OLD.job_ir_digest
        OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
        OR NEW.github_repository_id IS DISTINCT FROM OLD.github_repository_id
        OR NEW.github_repository_name IS DISTINCT FROM OLD.github_repository_name
        OR NEW.authority_namespace IS DISTINCT FROM OLD.authority_namespace
        OR NEW.policy_digest IS DISTINCT FROM OLD.policy_digest
        OR NEW.issuer_fingerprint IS DISTINCT FROM OLD.issuer_fingerprint
        OR NEW.configuration_fingerprint IS DISTINCT FROM OLD.configuration_fingerprint
        OR NEW.requested_at_ms IS DISTINCT FROM OLD.requested_at_ms
        OR NEW.request_deadline_at_ms IS DISTINCT FROM OLD.request_deadline_at_ms
        OR NEW.conservative_expiry_at_ms IS DISTINCT FROM OLD.conservative_expiry_at_ms
    THEN
        RAISE EXCEPTION 'GitHub runtime authority immutable identity cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_identity_immutable';
    END IF;

    IF NEW.state_updated_at_ms < OLD.state_updated_at_ms THEN
        RAISE EXCEPTION 'GitHub runtime authority state time cannot regress'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_time_regression';
    END IF;

    IF OLD.provider_expires_at_ms IS NOT NULL AND (
        NEW.provider_expires_at_ms IS DISTINCT FROM OLD.provider_expires_at_ms
        OR NEW.safe_erase_after_ms IS DISTINCT FROM OLD.safe_erase_after_ms
        OR NEW.plaintext_schema IS DISTINCT FROM OLD.plaintext_schema
        OR NEW.plaintext_size_bytes IS DISTINCT FROM OLD.plaintext_size_bytes
        OR NEW.plaintext_digest IS DISTINCT FROM OLD.plaintext_digest
        OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority protected metadata cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_protected_metadata_immutable';
    END IF;

    IF NOT (OLD.state = 'claimed' AND NEW.state = 'claimed') AND (
        NEW.mint_attempt_count IS DISTINCT FROM OLD.mint_attempt_count
        OR NEW.mint_claim_fence IS DISTINCT FROM OLD.mint_claim_fence
        OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
        OR NEW.mint_claimed_at_ms IS DISTINCT FROM OLD.mint_claimed_at_ms
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority mint history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_history_immutable';
    END IF;

    IF (
            NEW.mint_started_at_ms IS DISTINCT FROM OLD.mint_started_at_ms
            AND NOT (OLD.state = 'claimed' AND NEW.state = 'minting')
        ) OR (
            NEW.indeterminate_at_ms IS DISTINCT FROM OLD.indeterminate_at_ms
            AND NOT (OLD.state = 'minting' AND NEW.state = 'indeterminate')
        ) OR (
            NEW.ready_at_ms IS DISTINCT FROM OLD.ready_at_ms
            AND NOT (OLD.state = 'minting' AND NEW.state = 'ready')
        ) OR (
            NEW.revoke_pending_at_ms IS DISTINCT FROM OLD.revoke_pending_at_ms
            AND NOT (
                OLD.state IN ('minting', 'indeterminate', 'ready')
                AND NEW.state = 'revoke_pending'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority lifecycle history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_lifecycle_history_immutable';
    END IF;

    IF NOT (OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending') AND (
        NEW.revoke_attempt_count IS DISTINCT FROM OLD.revoke_attempt_count
        OR NEW.revoke_claim_fence IS DISTINCT FROM OLD.revoke_claim_fence
        OR NEW.last_revoke_failure_kind IS DISTINCT FROM OLD.last_revoke_failure_kind
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority revocation history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_revoke_history_immutable';
    END IF;

    IF OLD.envelope_schema IS NOT NULL AND NEW.state <> 'revoked' AND (
        NEW.envelope_schema IS DISTINCT FROM OLD.envelope_schema
        OR NEW.wrapping_key_id IS DISTINCT FROM OLD.wrapping_key_id
        OR NEW.wrapped_data_key IS DISTINCT FROM OLD.wrapped_data_key
        OR NEW.nonce IS DISTINCT FROM OLD.nonce
        OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority envelope cannot change before erasure'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_envelope_immutable';
    END IF;

    IF OLD.state = 'claimed' AND NEW.state = 'claimed' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count + 1
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence + 1
            OR NEW.mint_claimed_at_ms < OLD.mint_claim_expires_at_ms
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_claimed_at_ms
            )
        THEN
            RAISE EXCEPTION 'expired GitHub authority mint claim takeover is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_reclaim';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'minting' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_claimed_at_ms <> OLD.mint_claimed_at_ms
            OR NEW.mint_started_at_ms < OLD.mint_claimed_at_ms
            OR NEW.mint_started_at_ms >= OLD.mint_claim_expires_at_ms
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_started_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub authority mint must begin under the exact live claim'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_begin';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'indeterminate' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_started_at_ms <> OLD.mint_started_at_ms
            OR NEW.indeterminate_at_ms < OLD.mint_started_at_ms
            OR NEW.indeterminate_at_ms >= OLD.conservative_expiry_at_ms
        THEN
            RAISE EXCEPTION 'ambiguous GitHub mint must retain its irreversible fence'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_indeterminate';
        END IF;
    ELSIF OLD.state IN ('minting', 'indeterminate')
          AND NEW.state IN ('ready', 'revoke_pending') THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_started_at_ms <> OLD.mint_started_at_ms
            OR NEW.provider_expires_at_ms IS NULL
            OR NEW.envelope_schema IS NULL
            OR (OLD.state = 'indeterminate' AND NEW.state = 'ready')
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
            OR (
                NEW.state = 'revoke_pending'
                AND (
                    NEW.ready_at_ms IS NOT NULL
                    OR NEW.revoke_pending_at_ms <> NEW.state_updated_at_ms
                    OR NEW.next_revoke_at_ms <> NEW.state_updated_at_ms
                )
            )
            OR (
                NEW.state = 'ready'
                AND (
                    NEW.provider_expires_at_ms <= NEW.state_updated_at_ms
                    OR NOT automata_github_runtime_authority_is_current(
                        NEW, NEW.state_updated_at_ms
                    )
                )
            )
        THEN
            RAISE EXCEPTION 'minted GitHub authority finalization is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_finalize';
        END IF;
    ELSIF OLD.state = 'ready' AND NEW.state = 'revoke_pending' THEN
        IF NEW.revoke_pending_at_ms < OLD.ready_at_ms
            OR NEW.revoke_pending_at_ms >= OLD.safe_erase_after_ms
            OR NEW.revoke_pending_at_ms <> NEW.state_updated_at_ms
            OR NEW.next_revoke_at_ms <> NEW.state_updated_at_ms
            OR NEW.provider_expires_at_ms IS DISTINCT FROM OLD.provider_expires_at_ms
            OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
        THEN
            RAISE EXCEPTION 'ready GitHub authority revocation transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_pending';
        END IF;
    ELSIF OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending' THEN
        IF OLD.revoke_claim_owner_id IS NULL
            AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
                OR NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
                OR NEW.revoke_claimed_at_ms < OLD.next_revoke_at_ms
                OR NEW.revoke_claimed_at_ms <> NEW.state_updated_at_ms
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
                OR NEW.last_revoke_failure_kind IS DISTINCT FROM OLD.last_revoke_failure_kind
            THEN
                RAISE EXCEPTION 'GitHub authority revoke claim is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_claim';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
            AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
                OR NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
                OR NEW.revoke_claimed_at_ms < OLD.revoke_claim_expires_at_ms
                OR NEW.revoke_claimed_at_ms <> NEW.state_updated_at_ms
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
                OR NEW.last_revoke_failure_kind IS DISTINCT FROM OLD.last_revoke_failure_kind
            THEN
                RAISE EXCEPTION 'expired GitHub authority revoke claim takeover is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_reclaim';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
            AND NEW.revoke_claim_owner_id IS NULL THEN
            IF NOT (
                (
                    NEW.revoke_attempt_count = OLD.revoke_attempt_count
                    AND NEW.revoke_claim_fence = OLD.revoke_claim_fence
                    AND NEW.next_revoke_at_ms > NEW.state_updated_at_ms
                    AND NEW.next_revoke_at_ms < NEW.safe_erase_after_ms
                    AND NEW.last_revoke_failure_kind IS NOT NULL
                    AND NEW.state_updated_at_ms >= OLD.revoke_claimed_at_ms
                    AND NEW.state_updated_at_ms < OLD.revoke_claim_expires_at_ms
                ) OR (
                    NEW.revoke_attempt_count = OLD.revoke_attempt_count
                    AND NEW.revoke_claim_fence = OLD.revoke_claim_fence
                    AND NEW.next_revoke_at_ms = NEW.safe_erase_after_ms
                    AND NEW.last_revoke_failure_kind = 'claim_budget_exhausted'
                    AND NEW.state_updated_at_ms >= OLD.revoke_claim_expires_at_ms
                    AND (
                        OLD.revoke_attempt_count = 64
                        OR OLD.revoke_claim_fence = 9223372036854775807
                    )
                )
            )
            THEN
                RAISE EXCEPTION 'GitHub authority revoke retry is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_retry';
            END IF;
        ELSE
            RAISE EXCEPTION 'GitHub authority revoke self-transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_self_transition';
        END IF;
    ELSIF OLD.state IN ('claimed', 'minting', 'indeterminate', 'ready', 'revoke_pending')
          AND NEW.state = 'revoked' THEN
        IF NEW.envelope_schema IS NOT NULL
            OR NEW.wrapping_key_id IS NOT NULL
            OR NEW.wrapped_data_key IS NOT NULL
            OR NEW.nonce IS NOT NULL
            OR NEW.ciphertext IS NOT NULL
            OR (
                NEW.terminal_reason = 'provider_revocation_confirmed'
                AND (
                    OLD.state <> 'revoke_pending'
                    OR OLD.revoke_claim_owner_id IS NULL
                    OR NEW.revoked_at_ms < OLD.revoke_claimed_at_ms
                    OR NEW.revoked_at_ms >= OLD.revoke_claim_expires_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'provider_authority_expired'
                AND (
                    OLD.state NOT IN ('ready', 'revoke_pending')
                    OR OLD.safe_erase_after_ms IS NULL
                    OR NEW.revoked_at_ms < OLD.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'indeterminate_authority_expired'
                AND (
                    OLD.state NOT IN ('minting', 'indeterminate')
                    OR NEW.revoked_at_ms < OLD.conservative_expiry_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'superseded_before_mint'
                AND (
                    OLD.state <> 'claimed'
                    OR automata_github_runtime_authority_is_current(
                        OLD, NEW.revoked_at_ms
                    )
                )
            )
            OR (
                NEW.terminal_reason = 'request_expired_before_mint'
                AND (
                    OLD.state <> 'claimed'
                    OR NEW.revoked_at_ms < OLD.request_deadline_at_ms
                )
            )
        THEN
            RAISE EXCEPTION 'GitHub authority terminal erasure is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_terminal_erasure';
        END IF;
    ELSE
        RAISE EXCEPTION 'GitHub runtime authority lifecycle transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_lifecycle_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER github_runtime_authority_lifecycle_guard
BEFORE UPDATE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_enforce_github_runtime_authority_lifecycle();

CREATE FUNCTION automata_reject_github_runtime_authority_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'GitHub runtime authority audit identity cannot be removed'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'github_runtime_authority_removal_forbidden';
END;
$automata$;

CREATE TRIGGER github_runtime_authority_no_delete
BEFORE DELETE ON github_runtime_authority_issuances
FOR EACH ROW EXECUTE FUNCTION automata_reject_github_runtime_authority_removal();

CREATE TRIGGER github_runtime_authority_no_truncate
BEFORE TRUNCATE ON github_runtime_authority_issuances
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_github_runtime_authority_removal();
