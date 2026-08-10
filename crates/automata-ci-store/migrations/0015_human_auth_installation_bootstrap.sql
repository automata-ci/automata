-- Setup is armed by operator configuration before any anonymous request. A
-- proof-authorized request may bind one durable installation-login transaction;
-- only that consumed transaction and the exact stable provider subject can
-- complete configuration.

LOCK TABLE human_auth_installation_state IN ACCESS EXCLUSIVE MODE;

DO $automata$
DECLARE
    installation_rows BIGINT;
BEGIN
    SELECT count(*) INTO installation_rows
    FROM human_auth_installation_state;
    IF installation_rows <> 1 THEN
        RAISE EXCEPTION
            'installation singleton must exist exactly once before hardening'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_singleton_missing';
    END IF;
    IF EXISTS (
        SELECT 1 FROM human_auth_installation_state
        WHERE state <> 'unconfigured'
    ) THEN
        RAISE EXCEPTION
            'legacy pending/configured installation state requires explicit offline review'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_legacy_active';
    END IF;
END;
$automata$;

ALTER TABLE human_auth_installation_state
    DROP CONSTRAINT human_auth_installation_state_shape,
    ADD COLUMN target_tenant_id TEXT,
    ADD COLUMN target_tenant_display_name TEXT,
    ADD COLUMN setup_transaction_id UUID,
    ADD CONSTRAINT human_auth_installation_state_target_tenant_shape CHECK (
        target_tenant_id IS NULL OR (
            octet_length(target_tenant_id) BETWEEN 1 AND 255
            AND target_tenant_id !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT human_auth_installation_state_target_display_name_shape CHECK (
        target_tenant_display_name IS NULL OR (
            octet_length(target_tenant_display_name) BETWEEN 1 AND 255
            AND target_tenant_display_name !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT human_auth_installation_state_setup_transaction
        FOREIGN KEY (setup_transaction_id)
        REFERENCES human_login_transactions(id) ON DELETE RESTRICT,
    ADD CONSTRAINT human_auth_installation_state_shape CHECK ((
        (
            state = 'unconfigured'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND expected_provider_id IS NULL
            AND expected_provider_subject IS NULL
            AND challenge_expires_at_ms IS NULL
            AND target_tenant_id IS NULL
            AND target_tenant_display_name IS NULL
            AND setup_transaction_id IS NULL
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
        ) OR (
            state = 'pending'
            AND octet_length(bootstrap_token_hash) = 32
            AND octet_length(bootstrap_hash_key_id) BETWEEN 1 AND 128
            AND bootstrap_hash_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND expected_provider_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND expected_provider_subject !~ '[[:cntrl:]]'
            AND target_tenant_id IS NOT NULL
            AND target_tenant_display_name IS NOT NULL
            AND challenge_expires_at_ms > updated_at_ms
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
        ) OR (
            state = 'configured'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND challenge_expires_at_ms IS NULL
            AND target_tenant_id = configured_tenant_id
            AND target_tenant_display_name IS NOT NULL
            AND setup_transaction_id IS NOT NULL
            AND configured_tenant_id IS NOT NULL
            AND configured_principal_id IS NOT NULL
            AND configured_at_ms >= created_at_ms
        )
    ) IS TRUE);

CREATE FUNCTION automata_enforce_installation_state_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'installation singleton identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_identity_immutable';
    END IF;
    IF OLD.state = 'configured' THEN
        RAISE EXCEPTION 'configured installation state is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_configured_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'installation state updates require the next CAS revision'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_update_cas';
    END IF;
    IF OLD.state = 'unconfigured' THEN
        IF NEW.state <> 'pending' OR NEW.setup_transaction_id IS NOT NULL THEN
            RAISE EXCEPTION 'installation must be armed before login binding'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'human_auth_installation_state_transition';
        END IF;
    ELSIF OLD.state = 'pending' AND NEW.state = 'pending' THEN
        IF OLD.setup_transaction_id IS NULL
            AND NEW.setup_transaction_id IS NOT NULL
        THEN
            IF NEW.bootstrap_token_hash IS DISTINCT FROM OLD.bootstrap_token_hash
                OR NEW.bootstrap_hash_key_id IS DISTINCT FROM OLD.bootstrap_hash_key_id
                OR NEW.expected_provider_id IS DISTINCT FROM OLD.expected_provider_id
                OR NEW.expected_provider_subject IS DISTINCT FROM OLD.expected_provider_subject
                OR NEW.challenge_expires_at_ms IS DISTINCT FROM OLD.challenge_expires_at_ms
                OR NEW.target_tenant_id IS DISTINCT FROM OLD.target_tenant_id
                OR NEW.target_tenant_display_name IS DISTINCT FROM OLD.target_tenant_display_name
                OR NOT EXISTS (
                    SELECT 1
                    FROM human_login_transactions AS login
                    WHERE login.id = NEW.setup_transaction_id
                      AND login.purpose = 'installation_setup'
                      AND login.tenant_id IS NULL
                      AND login.provider_id = OLD.expected_provider_id
                      AND login.status = 'pending'
                      AND login.created_at_ms >= OLD.updated_at_ms
                      AND login.created_at_ms <= NEW.updated_at_ms
                      AND login.expires_at_ms > NEW.updated_at_ms
                )
            THEN
                RAISE EXCEPTION 'login binding cannot rewrite the armed setup'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'human_auth_installation_state_bind_exact';
            END IF;
        ELSIF OLD.challenge_expires_at_ms <= NEW.updated_at_ms
            AND NEW.setup_transaction_id IS NULL
        THEN
            NULL;
        ELSE
            RAISE EXCEPTION 'pending setup may only bind once or be rearmed after expiry'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'human_auth_installation_state_pending_exact';
        END IF;
    ELSIF OLD.state = 'pending' AND NEW.state = 'configured' THEN
        IF OLD.setup_transaction_id IS NULL
            OR OLD.challenge_expires_at_ms <= NEW.updated_at_ms
            OR NEW.expected_provider_id IS DISTINCT FROM OLD.expected_provider_id
            OR NEW.expected_provider_subject IS DISTINCT FROM OLD.expected_provider_subject
            OR NEW.target_tenant_id IS DISTINCT FROM OLD.target_tenant_id
            OR NEW.target_tenant_display_name IS DISTINCT FROM OLD.target_tenant_display_name
            OR NEW.setup_transaction_id IS DISTINCT FROM OLD.setup_transaction_id
            OR NOT EXISTS (
                SELECT 1
                FROM human_login_transactions AS login
                WHERE login.id = OLD.setup_transaction_id
                  AND login.purpose = 'installation_setup'
                  AND login.tenant_id IS NULL
                  AND login.provider_id = OLD.expected_provider_id
                  AND login.status = 'succeeded'
                  AND login.completed_principal_id = NEW.configured_principal_id
            )
        THEN
            RAISE EXCEPTION 'installation completion is not bound to a succeeded setup login'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'human_auth_installation_state_completion_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'installation state transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_auth_installation_state_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER human_auth_installation_state_lifecycle_guard
BEFORE UPDATE ON human_auth_installation_state
FOR EACH ROW EXECUTE FUNCTION automata_enforce_installation_state_lifecycle();

CREATE FUNCTION automata_reject_installation_singleton_replacement()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'installation singleton cannot be inserted, deleted, or truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'human_auth_installation_state_singleton_immutable';
END;
$automata$;

CREATE TRIGGER human_auth_installation_state_no_insert_delete
BEFORE INSERT OR DELETE ON human_auth_installation_state
FOR EACH ROW EXECUTE FUNCTION automata_reject_installation_singleton_replacement();

CREATE TRIGGER human_auth_installation_state_no_truncate
BEFORE TRUNCATE ON human_auth_installation_state
FOR EACH STATEMENT EXECUTE FUNCTION automata_reject_installation_singleton_replacement();

-- Login identity, lookup proofs, purpose, provider, and lifetime are immutable.
-- A setup completion may only advance an already-consumed transaction to a
-- succeeded tombstone in the same transaction as installation configuration.
CREATE FUNCTION automata_enforce_human_login_transaction_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.purpose IS DISTINCT FROM OLD.purpose
        OR NEW.flow_kind IS DISTINCT FROM OLD.flow_kind
        OR NEW.provider_id IS DISTINCT FROM OLD.provider_id
        OR NEW.return_path IS DISTINCT FROM OLD.return_path
        OR NEW.state_hash IS DISTINCT FROM OLD.state_hash
        OR NEW.state_hash_key_id IS DISTINCT FROM OLD.state_hash_key_id
        OR NEW.browser_binding_hash IS DISTINCT FROM OLD.browser_binding_hash
        OR NEW.browser_binding_hash_key_id IS DISTINCT FROM OLD.browser_binding_hash_key_id
        OR NEW.poll_proof_hash IS DISTINCT FROM OLD.poll_proof_hash
        OR NEW.poll_proof_hash_key_id IS DISTINCT FROM OLD.poll_proof_hash_key_id
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
        OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
    THEN
        RAISE EXCEPTION 'login transaction identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_login_transactions_identity_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
        OR NEW.poll_attempts < OLD.poll_attempts
        OR (
            OLD.consumed_at_ms IS NOT NULL
            AND NEW.consumed_at_ms IS DISTINCT FROM OLD.consumed_at_ms
        )
    THEN
        RAISE EXCEPTION 'login transaction updates require the next monotonic revision'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_login_transactions_update_cas';
    END IF;
    IF NOT (
        (OLD.status = 'pending' AND NEW.status IN ('pending', 'consumed', 'denied', 'expired'))
        OR (OLD.status = 'consumed' AND NEW.status = 'succeeded')
    ) THEN
        RAISE EXCEPTION 'login transaction status transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_login_transactions_status_transition';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER human_login_transactions_lifecycle_guard
BEFORE UPDATE ON human_login_transactions
FOR EACH ROW EXECUTE FUNCTION automata_enforce_human_login_transaction_lifecycle();
