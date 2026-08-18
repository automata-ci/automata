ALTER TABLE human_auth_installation_state
    RENAME TO installation_state;

ALTER TABLE installation_state
    RENAME COLUMN target_tenant_id TO tenant_id;

ALTER TABLE installation_state
    RENAME COLUMN target_tenant_display_name TO tenant_display_name;

DROP TRIGGER human_auth_installation_state_lifecycle_guard
    ON installation_state;

ALTER TRIGGER human_auth_installation_state_no_insert_delete
    ON installation_state
    RENAME TO installation_state_no_insert_delete;

ALTER TRIGGER human_auth_installation_state_no_truncate
    ON installation_state
    RENAME TO installation_state_no_truncate;

ALTER TABLE installation_state
    DROP CONSTRAINT human_auth_installation_state_shape,
    DROP CONSTRAINT human_auth_installation_state_state,
    DROP CONSTRAINT human_auth_installation_state_target_display_name_shape,
    DROP CONSTRAINT human_auth_installation_state_target_tenant_shape;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_pkey
    TO installation_state_pkey;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_revision_positive
    TO installation_state_revision_positive;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_singleton
    TO installation_state_singleton;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_time_monotonic
    TO installation_state_time_monotonic;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_identity
    TO installation_state_human_identity;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_membership
    TO installation_state_human_membership;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_setup_transaction
    TO installation_state_human_setup_transaction;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_created_at_ms_not_null
    TO installation_state_created_at_ms_not_null;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_revision_not_null
    TO installation_state_revision_not_null;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_singleton_not_null
    TO installation_state_singleton_not_null;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_state_not_null
    TO installation_state_state_not_null;

ALTER TABLE installation_state
    RENAME CONSTRAINT human_auth_installation_state_updated_at_ms_not_null
    TO installation_state_updated_at_ms_not_null;

ALTER TABLE installation_state
    ADD COLUMN configuration_mode text COLLATE pg_catalog."C",
    ADD COLUMN deployment_authority_sha256 bytea,
    ADD COLUMN deployment_bootstrap_operation_id uuid,
    ADD COLUMN deployment_bootstrap_audit_event_id uuid;

UPDATE installation_state
SET configuration_mode = 'human'
WHERE state IN ('pending', 'configured');

ALTER TABLE tenants
    ADD CONSTRAINT tenants_exact_id_display_name
    UNIQUE (id, display_name);

COMMENT ON COLUMN installation_state.configured_tenant_id IS
    'Post-transition tenant FK projection; NULL while a human target is pending and equal to tenant_id once configured.';

ALTER TABLE installation_state
    ADD CONSTRAINT installation_state_configuration_mode CHECK (
        configuration_mode IS NULL
        OR configuration_mode IN ('human', 'deployment')
    ),
    ADD CONSTRAINT installation_state_state CHECK (
        state IN ('unconfigured', 'pending', 'configured')
    ),
    ADD CONSTRAINT installation_state_tenant_shape CHECK (
        tenant_id IS NULL
        OR (
            octet_length(tenant_id) BETWEEN 1 AND 255
            AND tenant_id !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT installation_state_tenant_display_name_shape CHECK (
        tenant_display_name IS NULL
        OR (
            octet_length(tenant_display_name) BETWEEN 1 AND 255
            AND tenant_display_name !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT installation_state_deployment_authority_digest CHECK (
        deployment_authority_sha256 IS NULL
        OR (
            octet_length(deployment_authority_sha256) = 32
            AND deployment_authority_sha256 <>
                decode(repeat('00', 32), 'hex')
        )
    ),
    ADD CONSTRAINT installation_state_deployment_ids_non_nil CHECK (
        (
            deployment_bootstrap_operation_id IS NULL
            OR deployment_bootstrap_operation_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
        )
        AND (
            deployment_bootstrap_audit_event_id IS NULL
            OR deployment_bootstrap_audit_event_id <>
                '00000000-0000-0000-0000-000000000000'::uuid
        )
    ),
    ADD CONSTRAINT installation_state_shape CHECK ((
        (
            state = 'unconfigured'
            AND configuration_mode IS NULL
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND expected_provider_id IS NULL
            AND expected_provider_subject IS NULL
            AND challenge_expires_at_ms IS NULL
            AND tenant_id IS NULL
            AND tenant_display_name IS NULL
            AND setup_transaction_id IS NULL
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
            AND deployment_authority_sha256 IS NULL
            AND deployment_bootstrap_operation_id IS NULL
            AND deployment_bootstrap_audit_event_id IS NULL
        )
        OR
        (
            state = 'pending'
            AND configuration_mode = 'human'
            AND octet_length(bootstrap_token_hash) = 32
            AND octet_length(bootstrap_hash_key_id) BETWEEN 1 AND 128
            AND bootstrap_hash_key_id ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND expected_provider_id ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND expected_provider_subject !~ '[[:cntrl:]]'
            AND challenge_expires_at_ms > updated_at_ms
            AND tenant_id IS NOT NULL
            AND tenant_display_name IS NOT NULL
            AND configured_tenant_id IS NULL
            AND configured_principal_id IS NULL
            AND configured_at_ms IS NULL
            AND deployment_authority_sha256 IS NULL
            AND deployment_bootstrap_operation_id IS NULL
            AND deployment_bootstrap_audit_event_id IS NULL
        )
        OR
        (
            state = 'configured'
            AND configuration_mode = 'human'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND octet_length(expected_provider_id) BETWEEN 1 AND 128
            AND expected_provider_id ~
                '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND octet_length(expected_provider_subject) BETWEEN 1 AND 255
            AND expected_provider_subject !~ '[[:cntrl:]]'
            AND challenge_expires_at_ms IS NULL
            AND tenant_id IS NOT NULL
            AND tenant_display_name IS NOT NULL
            AND setup_transaction_id IS NOT NULL
            AND configured_tenant_id = tenant_id
            AND configured_principal_id IS NOT NULL
            AND configured_at_ms >= created_at_ms
            AND deployment_authority_sha256 IS NULL
            AND deployment_bootstrap_operation_id IS NULL
            AND deployment_bootstrap_audit_event_id IS NULL
        )
        OR
        (
            state = 'configured'
            AND configuration_mode = 'deployment'
            AND bootstrap_token_hash IS NULL
            AND bootstrap_hash_key_id IS NULL
            AND expected_provider_id IS NULL
            AND expected_provider_subject IS NULL
            AND challenge_expires_at_ms IS NULL
            AND tenant_id IS NOT NULL
            AND tenant_display_name IS NOT NULL
            AND setup_transaction_id IS NULL
            AND configured_tenant_id = tenant_id
            AND configured_principal_id IS NULL
            AND configured_at_ms >= created_at_ms
            AND deployment_authority_sha256 IS NOT NULL
            AND deployment_bootstrap_operation_id IS NOT NULL
            AND deployment_bootstrap_audit_event_id IS NOT NULL
        )
    ) IS TRUE),
    ADD CONSTRAINT installation_state_exact_configured_tenant_fkey
        FOREIGN KEY (configured_tenant_id, tenant_display_name)
        REFERENCES tenants(id, display_name) ON DELETE RESTRICT,
    ADD CONSTRAINT installation_state_deployment_audit_fkey
        FOREIGN KEY (deployment_bootstrap_audit_event_id)
        REFERENCES security_audit_events(event_id) ON DELETE RESTRICT,
    ADD CONSTRAINT installation_state_deployment_authority_unique
        UNIQUE (configured_tenant_id, deployment_authority_sha256);

CREATE OR REPLACE FUNCTION automata_reject_installation_singleton_replacement()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'installation singleton cannot be inserted, deleted, or truncated'
        USING ERRCODE = 'check_violation',
              CONSTRAINT = 'installation_state_singleton_immutable';
END;
$$;

CREATE OR REPLACE FUNCTION automata_enforce_installation_state_lifecycle()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton
        OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms
    THEN
        RAISE EXCEPTION 'installation singleton identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'installation_state_identity_immutable';
    END IF;
    IF OLD.state = 'configured' THEN
        RAISE EXCEPTION 'configured installation state is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'installation_state_configured_immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1
        OR NEW.updated_at_ms < OLD.updated_at_ms
    THEN
        RAISE EXCEPTION 'installation state updates require the next CAS revision'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'installation_state_update_cas';
    END IF;
    IF OLD.state = 'unconfigured' THEN
        IF NEW.state = 'pending'
            AND NEW.configuration_mode = 'human'
            AND NEW.setup_transaction_id IS NULL
        THEN
            NULL;
        ELSIF NEW.state = 'configured'
            AND NEW.configuration_mode = 'deployment'
        THEN
            IF NOT EXISTS (
                SELECT 1
                FROM tenants AS tenant
                WHERE tenant.id = NEW.configured_tenant_id
                  AND tenant.id = NEW.tenant_id
                  AND tenant.display_name = NEW.tenant_display_name
            ) OR NOT EXISTS (
                SELECT 1
                FROM security_audit_events AS audit
                WHERE audit.event_id =
                        NEW.deployment_bootstrap_audit_event_id
                  AND audit.tenant_id = NEW.configured_tenant_id
                  AND audit.occurred_at_ms = NEW.configured_at_ms
                  AND audit.actor_kind = 'system'
                  AND audit.actor_principal_id IS NULL
                  AND audit.actor_session_id IS NULL
                  AND audit.authorization_revision IS NULL
                  AND audit.action =
                        'auth.installation.deployment_configured'
                  AND audit.outcome = 'succeeded'
                  AND audit.resource_kind = 'installation'
                  AND audit.resource_id = 'singleton'
                  AND audit.request_id =
                        NEW.deployment_bootstrap_operation_id::text
            ) THEN
                RAISE EXCEPTION 'deployment installation lacks exact tenant and audit evidence'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT =
                              'installation_state_deployment_completion_exact';
            END IF;
        ELSE
            RAISE EXCEPTION 'installation state transition is not permitted'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'installation_state_transition';
        END IF;
    ELSIF OLD.state = 'pending'
        AND OLD.configuration_mode = 'human'
        AND NEW.state = 'pending'
        AND NEW.configuration_mode = 'human'
    THEN
        IF OLD.setup_transaction_id IS NULL
            AND NEW.setup_transaction_id IS NOT NULL
        THEN
            IF NEW.bootstrap_token_hash IS DISTINCT FROM OLD.bootstrap_token_hash
                OR NEW.bootstrap_hash_key_id IS DISTINCT FROM OLD.bootstrap_hash_key_id
                OR NEW.expected_provider_id IS DISTINCT FROM OLD.expected_provider_id
                OR NEW.expected_provider_subject IS DISTINCT FROM OLD.expected_provider_subject
                OR NEW.challenge_expires_at_ms IS DISTINCT FROM OLD.challenge_expires_at_ms
                OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.tenant_display_name IS DISTINCT FROM OLD.tenant_display_name
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
                          CONSTRAINT = 'installation_state_bind_exact';
            END IF;
        ELSIF OLD.challenge_expires_at_ms <= NEW.updated_at_ms
            AND NEW.setup_transaction_id IS NULL
        THEN
            NULL;
        ELSE
            RAISE EXCEPTION 'pending setup may only bind once or be rearmed after expiry'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'installation_state_pending_exact';
        END IF;
    ELSIF OLD.state = 'pending'
        AND OLD.configuration_mode = 'human'
        AND NEW.state = 'configured'
        AND NEW.configuration_mode = 'human'
    THEN
        IF OLD.setup_transaction_id IS NULL
            OR OLD.challenge_expires_at_ms <= NEW.updated_at_ms
            OR NEW.expected_provider_id IS DISTINCT FROM OLD.expected_provider_id
            OR NEW.expected_provider_subject IS DISTINCT FROM OLD.expected_provider_subject
            OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
            OR NEW.tenant_display_name IS DISTINCT FROM OLD.tenant_display_name
            OR NEW.setup_transaction_id IS DISTINCT FROM OLD.setup_transaction_id
            OR NOT EXISTS (
                SELECT 1
                FROM human_login_transactions AS login
                WHERE login.id = OLD.setup_transaction_id
                  AND login.purpose = 'installation_setup'
                  AND login.tenant_id IS NULL
                  AND login.provider_id = OLD.expected_provider_id
                  AND login.status = 'succeeded'
                  AND login.completed_principal_id =
                        NEW.configured_principal_id
            )
        THEN
            RAISE EXCEPTION 'installation completion is not bound to a succeeded setup login'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'installation_state_human_completion_exact';
        END IF;
    ELSE
        RAISE EXCEPTION 'installation state transition is not permitted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'installation_state_transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER installation_state_lifecycle_guard
    BEFORE UPDATE ON installation_state
    FOR EACH ROW EXECUTE FUNCTION automata_enforce_installation_state_lifecycle();

ALTER TABLE runner_enrollment_tokens
    ADD COLUMN issuer_kind text COLLATE pg_catalog."C",
    ADD COLUMN installation_authority_sha256 bytea,
    ADD COLUMN last_refreshed_at_ms bigint,
    DROP CONSTRAINT runner_enrollment_tokens_lifetime,
    DROP CONSTRAINT runner_enrollment_tokens_consumption_shape,
    ALTER COLUMN issued_by_principal_id DROP NOT NULL,
    ALTER COLUMN issued_by_session_id DROP NOT NULL,
    ALTER COLUMN issued_authorization_revision DROP NOT NULL;

UPDATE runner_enrollment_tokens
SET issuer_kind = 'human';

ALTER TABLE runner_enrollment_tokens
    ALTER COLUMN issuer_kind SET NOT NULL,
    ADD CONSTRAINT runner_enrollment_tokens_issuer_kind CHECK (
        issuer_kind IN ('human', 'installation_bootstrap')
    ),
    ADD CONSTRAINT runner_enrollment_tokens_installation_authority_digest CHECK (
        installation_authority_sha256 IS NULL
        OR (
            octet_length(installation_authority_sha256) = 32
            AND installation_authority_sha256 <>
                decode(repeat('00', 32), 'hex')
        )
    ),
    ADD CONSTRAINT runner_enrollment_tokens_issuer_shape CHECK ((
        (
            issuer_kind = 'human'
            AND issued_by_principal_id IS NOT NULL
            AND issued_by_session_id IS NOT NULL
            AND issued_authorization_revision IS NOT NULL
            AND installation_authority_sha256 IS NULL
            AND last_refreshed_at_ms IS NULL
        )
        OR
        (
            issuer_kind = 'installation_bootstrap'
            AND issued_by_principal_id IS NULL
            AND issued_by_session_id IS NULL
            AND issued_authorization_revision IS NULL
            AND installation_authority_sha256 IS NOT NULL
        )
    ) IS TRUE),
    ADD CONSTRAINT runner_enrollment_tokens_active_lifetime CHECK ((
        (
            issuer_kind = 'human'
            AND last_refreshed_at_ms IS NULL
            AND issued_at_ms >= 0
            AND (expires_at_ms - issued_at_ms) BETWEEN 60000 AND 3600000
        )
        OR
        (
            issuer_kind = 'installation_bootstrap'
            AND issued_at_ms >= 0
            AND (
                last_refreshed_at_ms IS NULL
                OR last_refreshed_at_ms > issued_at_ms
            )
            AND (
                expires_at_ms
                - COALESCE(last_refreshed_at_ms, issued_at_ms)
            ) = 3600000
        )
    ) IS TRUE),
    ADD CONSTRAINT runner_enrollment_tokens_consumption_shape CHECK ((
        (
            consumed_at_ms IS NULL
            AND consumed_runner_id IS NULL
            AND redeem_operation_id IS NULL
            AND redeem_request_sha256 IS NULL
            AND redeem_response IS NULL
            AND redeem_certificate_expires_at_seconds IS NULL
        )
        OR
        (
            consumed_at_ms >=
                COALESCE(last_refreshed_at_ms, issued_at_ms)
            AND consumed_at_ms < expires_at_ms
            AND consumed_runner_id IS NOT NULL
            AND redeem_operation_id IS NOT NULL
            AND octet_length(redeem_request_sha256) = 32
            AND octet_length(redeem_response) BETWEEN 1 AND 524288
            AND (
                redeem_certificate_expires_at_seconds
                - consumed_at_ms / 1000
            ) >= 300
        )
    ) IS TRUE),
    ADD CONSTRAINT runner_enrollment_tokens_installation_authority_fkey
        FOREIGN KEY (tenant_id, installation_authority_sha256)
        REFERENCES installation_state(
            configured_tenant_id,
            deployment_authority_sha256
        ) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION automata_runner_enrollment_token_consume_once()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    refreshing boolean;
BEGIN
    refreshing :=
        NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms
        OR NEW.last_refreshed_at_ms IS DISTINCT FROM OLD.last_refreshed_at_ms;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.runner_group_id IS DISTINCT FROM OLD.runner_group_id
       OR NEW.token_sha256 IS DISTINCT FROM OLD.token_sha256
       OR NEW.issuer_kind IS DISTINCT FROM OLD.issuer_kind
       OR NEW.issued_by_principal_id IS DISTINCT FROM OLD.issued_by_principal_id
       OR NEW.issued_by_session_id IS DISTINCT FROM OLD.issued_by_session_id
       OR NEW.issued_authorization_revision IS DISTINCT FROM OLD.issued_authorization_revision
       OR NEW.installation_authority_sha256 IS DISTINCT FROM OLD.installation_authority_sha256
       OR NEW.issued_at_ms IS DISTINCT FROM OLD.issued_at_ms
       OR (
           refreshing
           AND NOT (
               OLD.issuer_kind = 'installation_bootstrap'
               AND OLD.consumed_at_ms IS NULL
               AND NEW.consumed_at_ms IS NULL
               AND NEW.consumed_runner_id IS NULL
               AND NEW.redeem_operation_id IS NULL
               AND NEW.redeem_request_sha256 IS NULL
               AND NEW.redeem_response IS NULL
               AND NEW.redeem_certificate_expires_at_seconds IS NULL
               AND OLD.expires_at_ms <=
                   floor(extract(epoch FROM clock_timestamp()))::bigint * 1000
               AND NEW.last_refreshed_at_ms IS NOT NULL
               AND NEW.last_refreshed_at_ms >= OLD.expires_at_ms
               AND NEW.last_refreshed_at_ms >
                   COALESCE(OLD.last_refreshed_at_ms, OLD.issued_at_ms)
               AND NEW.last_refreshed_at_ms <=
                   floor(extract(epoch FROM clock_timestamp()))::bigint * 1000
               AND NEW.expires_at_ms - NEW.last_refreshed_at_ms = 3600000
           )
       )
       OR (OLD.consumed_at_ms IS NOT NULL AND (
           NEW.consumed_at_ms IS DISTINCT FROM OLD.consumed_at_ms
           OR NEW.consumed_runner_id IS DISTINCT FROM OLD.consumed_runner_id
           OR NEW.redeem_operation_id IS DISTINCT FROM OLD.redeem_operation_id
           OR NEW.redeem_request_sha256 IS DISTINCT FROM OLD.redeem_request_sha256
           OR NEW.redeem_response IS DISTINCT FROM OLD.redeem_response
           OR NEW.redeem_certificate_expires_at_seconds IS DISTINCT FROM OLD.redeem_certificate_expires_at_seconds
       )) THEN
        RAISE EXCEPTION 'runner enrollment token authority is immutable and consumption is write-once'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'runner_enrollment_tokens_consume_once';
    END IF;
    RETURN NEW;
END;
$$;
