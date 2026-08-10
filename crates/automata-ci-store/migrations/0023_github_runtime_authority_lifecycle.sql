-- Current-only completion of GitHub runtime-authority custody. Migration 0018
-- was deliberately released before its coordinator; no issuance from that
-- incomplete contract may be converted. Recreate obsolete local state rather
-- than guessing provider installation, token disposition, or erasure bounds.

LOCK TABLE github_runtime_authority_issuances IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM github_runtime_authority_issuances LIMIT 1) THEN
        RAISE EXCEPTION
            'obsolete GitHub runtime-authority state exists; recreate the current-only store'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_current_only_empty_upgrade';
    END IF;
END;
$automata$;

DROP TRIGGER github_runtime_authority_lifecycle_guard
    ON github_runtime_authority_issuances;
DROP FUNCTION automata_enforce_github_runtime_authority_lifecycle();

DROP INDEX github_runtime_authority_safe_erasure;

ALTER TABLE github_runtime_authority_issuances
    DROP CONSTRAINT github_runtime_authority_non_nil_identity,
    DROP CONSTRAINT github_runtime_authority_request_time_shape,
    DROP CONSTRAINT github_runtime_authority_state,
    DROP CONSTRAINT github_runtime_authority_mint_claim_bounds,
    DROP CONSTRAINT github_runtime_authority_protected_metadata_complete,
    DROP CONSTRAINT github_runtime_authority_protected_metadata_shape,
    DROP CONSTRAINT github_runtime_authority_envelope_shape,
    DROP CONSTRAINT github_runtime_authority_revoke_claim_bounds,
    DROP CONSTRAINT github_runtime_authority_terminal_reason,
    DROP CONSTRAINT github_runtime_authority_state_time_monotonic,
    DROP CONSTRAINT github_runtime_authority_state_shape,
    ADD COLUMN provider_connection_id UUID NOT NULL,
    ADD COLUMN provider_installation_id BIGINT NOT NULL,
    ADD COLUMN commit_disposition TEXT COLLATE "C",
    ADD COLUMN next_mint_at_ms BIGINT,
    ADD COLUMN last_mint_rejection_kind TEXT COLLATE "C",
    ADD COLUMN rejected_at_ms BIGINT,
    ADD COLUMN quarantine_at_ms BIGINT,
    ADD COLUMN quarantine_kind TEXT COLLATE "C";

ALTER TABLE github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_non_nil_identity CHECK (
        attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND lease_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND job_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND runner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND runner_session_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND provider_connection_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND mint_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND (
            revoke_claim_owner_id IS NULL
            OR revoke_claim_owner_id <> '00000000-0000-0000-0000-000000000000'::uuid
        )
    ),
    ADD CONSTRAINT github_runtime_authority_provider_installation_positive CHECK (
        provider_installation_id > 0
    ),
    ADD CONSTRAINT github_runtime_authority_request_time_shape CHECK (
        lease_issued_at_ms >= 0
        AND lease_expires_at_ms > lease_issued_at_ms
        AND requested_at_ms >= lease_issued_at_ms
        AND requested_at_ms < lease_expires_at_ms
        AND request_deadline_at_ms > requested_at_ms
        AND request_deadline_at_ms <= lease_expires_at_ms
        AND request_deadline_at_ms - requested_at_ms <= 120000
        AND conservative_expiry_at_ms::NUMERIC
            = request_deadline_at_ms::NUMERIC + 3780000
    ),
    ADD CONSTRAINT github_runtime_authority_state CHECK (
        state IN (
            'claimed', 'minting', 'mint_retry_pending', 'indeterminate',
            'ready', 'revoke_pending', 'quarantined', 'rejected', 'revoked'
        )
    ),
    ADD CONSTRAINT github_runtime_authority_mint_claim_bounds CHECK (
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
        AND (
            next_mint_at_ms IS NULL
            OR (
                next_mint_at_ms > state_updated_at_ms
                AND next_mint_at_ms < request_deadline_at_ms
                AND next_mint_at_ms - state_updated_at_ms <= 120000
            )
        )
    ),
    ADD CONSTRAINT github_runtime_authority_mint_failure_shape CHECK (
        last_mint_rejection_kind IS NULL OR (
            octet_length(last_mint_rejection_kind) BETWEEN 1 AND 128
            AND last_mint_rejection_kind ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        )
    ),
    ADD CONSTRAINT github_runtime_authority_protected_metadata_complete CHECK (
        (safe_erase_after_ms IS NULL) = (commit_disposition IS NULL)
        AND (safe_erase_after_ms IS NULL) = (plaintext_schema IS NULL)
        AND (safe_erase_after_ms IS NULL) = (plaintext_size_bytes IS NULL)
        AND (safe_erase_after_ms IS NULL) = (plaintext_digest IS NULL)
        AND (safe_erase_after_ms IS NULL) = (aad_digest IS NULL)
        AND (provider_expires_at_ms IS NULL OR safe_erase_after_ms IS NOT NULL)
    ),
    ADD CONSTRAINT github_runtime_authority_protected_metadata_shape CHECK (
        safe_erase_after_ms IS NULL OR (
            commit_disposition IN ('deliverable', 'revoke_only')
            AND plaintext_schema = 1
            AND plaintext_size_bytes BETWEEN 1 AND 65536
            AND octet_length(plaintext_digest) = 32
            AND octet_length(aad_digest) = 32
            AND (
                (
                    provider_expires_at_ms IS NULL
                    AND safe_erase_after_ms = conservative_expiry_at_ms
                ) OR (
                    provider_expires_at_ms > requested_at_ms
                    AND provider_expires_at_ms::NUMERIC
                        <= request_deadline_at_ms::NUMERIC + 3660000
                    AND safe_erase_after_ms::NUMERIC
                        = provider_expires_at_ms::NUMERIC + 120000
                    AND safe_erase_after_ms <= conservative_expiry_at_ms
                )
            )
        )
    ),
    ADD CONSTRAINT github_runtime_authority_envelope_shape CHECK (
        envelope_schema IS NULL OR (
            safe_erase_after_ms IS NOT NULL
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
    ADD CONSTRAINT github_runtime_authority_revoke_claim_bounds CHECK (
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
                AND revoke_claim_expires_at_ms < safe_erase_after_ms
            )
        )
    ),
    ADD CONSTRAINT github_runtime_authority_terminal_reason CHECK (
        terminal_reason IS NULL OR terminal_reason IN (
            'superseded_before_mint', 'request_expired_before_mint',
            'provider_mint_rejected', 'provider_mint_retry_expired',
            'provider_revocation_confirmed', 'provider_authority_expired',
            'conservative_authority_expired', 'indeterminate_authority_expired',
            'quarantined_authority_expired'
        )
    ),
    ADD CONSTRAINT github_runtime_authority_quarantine_shape CHECK (
        (quarantine_at_ms IS NULL) = (quarantine_kind IS NULL)
        AND (
            quarantine_kind IS NULL OR quarantine_kind IN (
                'invalid_envelope', 'unsupported_envelope_schema',
                'envelope_authentication_failed', 'invalid_wrapped_data_key',
                'unknown_wrapping_key', 'retired_wrapping_key',
                'cryptographic_failure'
            )
        )
    ),
    ADD CONSTRAINT github_runtime_authority_state_time_monotonic CHECK (
        state_updated_at_ms >= requested_at_ms
        AND (mint_started_at_ms IS NULL OR mint_started_at_ms >= mint_claimed_at_ms)
        AND (indeterminate_at_ms IS NULL OR indeterminate_at_ms >= mint_started_at_ms)
        AND (ready_at_ms IS NULL OR ready_at_ms >= mint_started_at_ms)
        AND (revoke_pending_at_ms IS NULL OR revoke_pending_at_ms >= mint_started_at_ms)
        AND (rejected_at_ms IS NULL OR rejected_at_ms >= mint_started_at_ms)
        AND (quarantine_at_ms IS NULL OR quarantine_at_ms >= mint_started_at_ms)
        AND (revoked_at_ms IS NULL OR revoked_at_ms >= requested_at_ms)
    );

ALTER TABLE github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_state_shape CHECK ((
        (
            state = 'claimed'
            AND mint_claim_expires_at_ms IS NOT NULL
            AND mint_started_at_ms IS NULL
            AND next_mint_at_ms IS NULL
            AND indeterminate_at_ms IS NULL
            AND safe_erase_after_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND rejected_at_ms IS NULL
            AND quarantine_at_ms IS NULL
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
            AND next_mint_at_ms IS NULL
            AND indeterminate_at_ms IS NULL
            AND safe_erase_after_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND rejected_at_ms IS NULL
            AND quarantine_at_ms IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND last_revoke_failure_kind IS NULL
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'mint_retry_pending'
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NOT NULL
            AND last_mint_rejection_kind IS NOT NULL
            AND indeterminate_at_ms IS NULL
            AND safe_erase_after_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND rejected_at_ms IS NULL
            AND quarantine_at_ms IS NULL
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
            AND next_mint_at_ms IS NULL
            AND indeterminate_at_ms = state_updated_at_ms
            AND safe_erase_after_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND rejected_at_ms IS NULL
            AND quarantine_at_ms IS NULL
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
            AND next_mint_at_ms IS NULL
            AND commit_disposition = 'deliverable'
            AND provider_expires_at_ms IS NOT NULL
            AND provider_expires_at_ms::NUMERIC
                > state_updated_at_ms::NUMERIC + 60000
            AND envelope_schema IS NOT NULL
            AND ready_at_ms = state_updated_at_ms
            AND revoke_pending_at_ms IS NULL
            AND rejected_at_ms IS NULL
            AND quarantine_at_ms IS NULL
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
            AND next_mint_at_ms IS NULL
            AND safe_erase_after_ms IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND revoke_pending_at_ms IS NOT NULL
            AND rejected_at_ms IS NULL
            AND quarantine_at_ms IS NULL
            AND (
                (
                    revoke_claim_owner_id IS NULL
                    AND next_revoke_at_ms IS NOT NULL
                    AND next_revoke_at_ms >= revoke_pending_at_ms
                    AND next_revoke_at_ms <= safe_erase_after_ms
                ) OR (
                    revoke_claim_owner_id IS NOT NULL
                    AND next_revoke_at_ms IS NULL
                )
            )
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'quarantined'
            AND mint_claim_expires_at_ms IS NULL
            AND safe_erase_after_ms IS NOT NULL
            AND envelope_schema IS NOT NULL
            AND quarantine_at_ms = state_updated_at_ms
            AND state_updated_at_ms < safe_erase_after_ms
            AND rejected_at_ms IS NULL
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND revoked_at_ms IS NULL
            AND terminal_reason IS NULL
        ) OR (
            state = 'rejected'
            AND mint_claim_expires_at_ms IS NULL
            AND mint_started_at_ms IS NOT NULL
            AND next_mint_at_ms IS NULL
            AND last_mint_rejection_kind IS NOT NULL
            AND indeterminate_at_ms IS NULL
            AND safe_erase_after_ms IS NULL
            AND envelope_schema IS NULL
            AND ready_at_ms IS NULL
            AND revoke_pending_at_ms IS NULL
            AND rejected_at_ms = state_updated_at_ms
            AND quarantine_at_ms IS NULL
            AND revoke_attempt_count = 0
            AND revoke_claim_fence = 0
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND last_revoke_failure_kind IS NULL
            AND revoked_at_ms IS NULL
            AND terminal_reason IN (
                'provider_mint_rejected', 'provider_mint_retry_expired'
            )
        ) OR (
            state = 'revoked'
            AND mint_claim_expires_at_ms IS NULL
            AND envelope_schema IS NULL
            AND revoke_claim_owner_id IS NULL
            AND next_revoke_at_ms IS NULL
            AND rejected_at_ms IS NULL
            AND revoked_at_ms = state_updated_at_ms
            AND terminal_reason IS NOT NULL
            AND (
                (
                    terminal_reason IN (
                        'superseded_before_mint', 'request_expired_before_mint'
                    )
                    AND mint_started_at_ms IS NULL
                    AND indeterminate_at_ms IS NULL
                    AND safe_erase_after_ms IS NULL
                    AND ready_at_ms IS NULL
                    AND revoke_pending_at_ms IS NULL
                    AND quarantine_at_ms IS NULL
                ) OR (
                    terminal_reason = 'indeterminate_authority_expired'
                    AND mint_started_at_ms IS NOT NULL
                    AND safe_erase_after_ms IS NULL
                    AND ready_at_ms IS NULL
                    AND revoke_pending_at_ms IS NULL
                    AND quarantine_at_ms IS NULL
                ) OR (
                    terminal_reason IN (
                        'provider_revocation_confirmed', 'provider_authority_expired',
                        'conservative_authority_expired'
                    )
                    AND mint_started_at_ms IS NOT NULL
                    AND safe_erase_after_ms IS NOT NULL
                    AND (ready_at_ms IS NOT NULL OR revoke_pending_at_ms IS NOT NULL)
                    AND quarantine_at_ms IS NULL
                ) OR (
                    terminal_reason = 'quarantined_authority_expired'
                    AND mint_started_at_ms IS NOT NULL
                    AND safe_erase_after_ms IS NOT NULL
                    AND quarantine_at_ms IS NOT NULL
                )
            )
        )
    ) IS TRUE);

CREATE INDEX github_runtime_authority_mint_retry_ready
    ON github_runtime_authority_issuances (next_mint_at_ms, attempt_id, fencing_token)
    WHERE state = 'mint_retry_pending';

CREATE INDEX github_runtime_authority_safe_erasure
    ON github_runtime_authority_issuances (safe_erase_after_ms, attempt_id, fencing_token)
    WHERE state IN ('ready', 'revoke_pending', 'quarantined');

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
        OR NEW.provider_connection_id IS DISTINCT FROM OLD.provider_connection_id
        OR NEW.provider_installation_id IS DISTINCT FROM OLD.provider_installation_id
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

    IF OLD.safe_erase_after_ms IS NOT NULL AND (
        NEW.provider_expires_at_ms IS DISTINCT FROM OLD.provider_expires_at_ms
        OR NEW.safe_erase_after_ms IS DISTINCT FROM OLD.safe_erase_after_ms
        OR NEW.commit_disposition IS DISTINCT FROM OLD.commit_disposition
        OR NEW.plaintext_schema IS DISTINCT FROM OLD.plaintext_schema
        OR NEW.plaintext_size_bytes IS DISTINCT FROM OLD.plaintext_size_bytes
        OR NEW.plaintext_digest IS DISTINCT FROM OLD.plaintext_digest
        OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
    ) THEN
        RAISE EXCEPTION 'GitHub runtime authority protected metadata cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_protected_metadata_immutable';
    END IF;

    IF NOT (
            OLD.state IN ('claimed', 'mint_retry_pending')
            AND NEW.state = 'claimed'
        ) AND (
            NEW.mint_attempt_count IS DISTINCT FROM OLD.mint_attempt_count
            OR NEW.mint_claim_fence IS DISTINCT FROM OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.mint_claimed_at_ms IS DISTINCT FROM OLD.mint_claimed_at_ms
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority mint claim history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_history_immutable';
    END IF;

    IF NEW.mint_started_at_ms IS DISTINCT FROM OLD.mint_started_at_ms
        AND NOT (
            (OLD.state = 'claimed' AND NEW.state = 'minting')
            OR (
                OLD.state = 'mint_retry_pending'
                AND NEW.state = 'claimed'
                AND NEW.mint_started_at_ms IS NULL
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority mint boundary history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_mint_boundary_immutable';
    END IF;

    IF (
            NEW.next_mint_at_ms IS DISTINCT FROM OLD.next_mint_at_ms
            AND NOT (
                (OLD.state = 'minting' AND NEW.state = 'mint_retry_pending')
                OR (
                    OLD.state = 'mint_retry_pending'
                    AND NEW.state IN ('claimed', 'rejected')
                )
            )
        ) OR (
            NEW.last_mint_rejection_kind
                IS DISTINCT FROM OLD.last_mint_rejection_kind
            AND NOT (
                OLD.state = 'minting'
                AND NEW.state IN ('mint_retry_pending', 'rejected')
            )
        ) OR (
            NEW.rejected_at_ms IS DISTINCT FROM OLD.rejected_at_ms
            AND NOT (
                OLD.state IN ('minting', 'mint_retry_pending')
                AND NEW.state = 'rejected'
            )
        )
    THEN
        RAISE EXCEPTION 'GitHub runtime authority rejection history cannot change'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'github_runtime_authority_rejection_history_immutable';
    END IF;

    IF (
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
        ) OR (
            (
                NEW.quarantine_at_ms IS DISTINCT FROM OLD.quarantine_at_ms
                OR NEW.quarantine_kind IS DISTINCT FROM OLD.quarantine_kind
            )
            AND NOT (
                OLD.state IN ('ready', 'revoke_pending')
                AND NEW.state = 'quarantined'
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
    ELSIF OLD.state = 'mint_retry_pending' AND NEW.state = 'claimed' THEN
        IF NEW.mint_attempt_count <> OLD.mint_attempt_count + 1
            OR NEW.mint_claim_fence <> OLD.mint_claim_fence + 1
            OR NEW.mint_claimed_at_ms < OLD.next_mint_at_ms
            OR NEW.last_mint_rejection_kind IS DISTINCT FROM OLD.last_mint_rejection_kind
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.mint_claimed_at_ms
            )
        THEN
            RAISE EXCEPTION 'definitive no-token GitHub mint retry claim is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_retry_claim';
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
    ELSIF OLD.state = 'minting' AND NEW.state = 'mint_retry_pending' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.next_mint_at_ms <= NEW.state_updated_at_ms
            OR NEW.next_mint_at_ms >= NEW.request_deadline_at_ms
            OR NEW.last_mint_rejection_kind IS NULL
            OR NOT automata_github_runtime_authority_is_current(
                NEW, NEW.state_updated_at_ms
            )
        THEN
            RAISE EXCEPTION 'GitHub no-token mint retry scheduling is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_retry_schedule';
        END IF;
    ELSIF OLD.state IN ('minting', 'mint_retry_pending') AND NEW.state = 'rejected' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
            OR NEW.last_mint_rejection_kind IS NULL
            OR NEW.rejected_at_ms <> NEW.state_updated_at_ms
            OR NEW.terminal_reason NOT IN (
                'provider_mint_rejected', 'provider_mint_retry_expired'
            )
            OR (
                OLD.state = 'mint_retry_pending'
                AND NEW.terminal_reason <> 'provider_mint_retry_expired'
            )
        THEN
            RAISE EXCEPTION 'definitive GitHub mint rejection is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_mint_rejection';
        END IF;
    ELSIF OLD.state = 'minting' AND NEW.state = 'indeterminate' THEN
        IF NEW.mint_claim_fence <> OLD.mint_claim_fence
            OR NEW.mint_claim_owner_id IS DISTINCT FROM OLD.mint_claim_owner_id
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
            OR NEW.safe_erase_after_ms IS NULL
            OR NEW.envelope_schema IS NULL
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
            OR (
                NEW.state = 'ready' AND (
                    OLD.state <> 'minting'
                    OR NEW.commit_disposition <> 'deliverable'
                    OR NEW.provider_expires_at_ms IS NULL
                    OR NEW.provider_expires_at_ms::NUMERIC
                        <= NEW.state_updated_at_ms::NUMERIC + 60000
                    OR NOT automata_github_runtime_authority_is_current(
                        NEW, NEW.state_updated_at_ms
                    )
                )
            )
            OR (
                NEW.state = 'revoke_pending' AND (
                    NEW.ready_at_ms IS NOT NULL
                    OR NEW.revoke_pending_at_ms <> NEW.state_updated_at_ms
                    OR NEW.next_revoke_at_ms <> NEW.state_updated_at_ms
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
        THEN
            RAISE EXCEPTION 'ready GitHub authority revocation transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_pending';
        END IF;
    ELSIF OLD.state IN ('ready', 'revoke_pending') AND NEW.state = 'quarantined' THEN
        IF NEW.quarantine_at_ms <> NEW.state_updated_at_ms
            OR NEW.quarantine_kind IS NULL
            OR NEW.state_updated_at_ms >= NEW.safe_erase_after_ms
            OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
        THEN
            RAISE EXCEPTION 'GitHub authority quarantine observation is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_quarantine';
        END IF;
    ELSIF OLD.state = 'revoke_pending' AND NEW.state = 'revoke_pending' THEN
        IF OLD.revoke_claim_owner_id IS NULL
            AND NEW.revoke_claim_owner_id IS NOT NULL THEN
            IF NEW.revoke_attempt_count <> OLD.revoke_attempt_count + 1
                OR NEW.revoke_claim_fence <> OLD.revoke_claim_fence + 1
                OR NEW.revoke_claimed_at_ms < OLD.next_revoke_at_ms
                OR NEW.revoke_claimed_at_ms <> NEW.state_updated_at_ms
                OR NEW.revoke_claim_expires_at_ms >= NEW.safe_erase_after_ms
                OR NEW.last_revoke_failure_kind
                    IS DISTINCT FROM OLD.last_revoke_failure_kind
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
                OR NEW.last_revoke_failure_kind
                    IS DISTINCT FROM OLD.last_revoke_failure_kind
            THEN
                RAISE EXCEPTION 'expired GitHub authority revoke claim takeover is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_reclaim';
            END IF;
        ELSIF OLD.revoke_claim_owner_id IS NOT NULL
            AND NEW.revoke_claim_owner_id IS NULL THEN
            IF NOT (
                NEW.revoke_attempt_count = OLD.revoke_attempt_count
                AND NEW.revoke_claim_fence = OLD.revoke_claim_fence
                AND NEW.last_revoke_failure_kind IS NOT NULL
                AND NEW.state_updated_at_ms >= OLD.revoke_claimed_at_ms
                AND (
                    (
                        NEW.state_updated_at_ms < OLD.revoke_claim_expires_at_ms
                        AND (
                            (
                                NEW.next_revoke_at_ms > NEW.state_updated_at_ms
                                AND NEW.next_revoke_at_ms < NEW.safe_erase_after_ms
                            ) OR NEW.next_revoke_at_ms = NEW.safe_erase_after_ms
                        )
                    ) OR (
                        NEW.state_updated_at_ms >= OLD.revoke_claim_expires_at_ms
                        AND NEW.state_updated_at_ms < NEW.safe_erase_after_ms
                        AND NEW.next_revoke_at_ms = NEW.safe_erase_after_ms
                        AND NEW.last_revoke_failure_kind = 'claim_budget_exhausted'
                        AND (
                            OLD.revoke_attempt_count = 64
                            OR OLD.revoke_claim_fence = 9223372036854775807
                        )
                    )
                )
            )
            THEN
                RAISE EXCEPTION 'GitHub authority revoke retry/defer is invalid'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'github_runtime_authority_revoke_retry';
            END IF;
        ELSE
            RAISE EXCEPTION 'GitHub authority revoke self-transition is invalid'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'github_runtime_authority_revoke_self_transition';
        END IF;
    ELSIF OLD.state IN (
              'claimed', 'minting', 'indeterminate', 'ready',
              'revoke_pending', 'quarantined'
          ) AND NEW.state = 'revoked' THEN
        IF NEW.envelope_schema IS NOT NULL
            OR (
                NEW.terminal_reason = 'provider_revocation_confirmed' AND (
                    OLD.state <> 'revoke_pending'
                    OR OLD.revoke_claim_owner_id IS NULL
                    OR NEW.revoked_at_ms < OLD.revoke_claimed_at_ms
                    OR NEW.revoked_at_ms >= OLD.revoke_claim_expires_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'provider_authority_expired' AND (
                    OLD.state NOT IN ('ready', 'revoke_pending')
                    OR OLD.provider_expires_at_ms IS NULL
                    OR NEW.revoked_at_ms < OLD.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'conservative_authority_expired' AND (
                    OLD.state NOT IN ('ready', 'revoke_pending')
                    OR OLD.provider_expires_at_ms IS NOT NULL
                    OR NEW.revoked_at_ms < OLD.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'quarantined_authority_expired' AND (
                    OLD.state <> 'quarantined'
                    OR NEW.revoked_at_ms < OLD.safe_erase_after_ms
                )
            )
            OR (
                NEW.terminal_reason = 'indeterminate_authority_expired' AND (
                    OLD.state NOT IN ('minting', 'indeterminate')
                    OR NEW.revoked_at_ms < OLD.conservative_expiry_at_ms
                )
            )
            OR (
                NEW.terminal_reason = 'superseded_before_mint' AND (
                    OLD.state <> 'claimed'
                    OR automata_github_runtime_authority_is_current(
                        OLD, NEW.revoked_at_ms
                    )
                )
            )
            OR (
                NEW.terminal_reason = 'request_expired_before_mint' AND (
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
