-- Provider OAuth credentials are recoverable secrets. Bind each envelope to an
-- immutable random record identity and a CAS version, keep only closed safe
-- metadata in clear columns, and make revocation a one-way cryptographic erase.

LOCK TABLE human_provider_tokens IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM human_provider_tokens LIMIT 1) THEN
        RAISE EXCEPTION
            'legacy provider-token envelopes require an explicit offline re-encryption before this migration'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_legacy_envelope_rows';
    END IF;
END;
$automata$;

DROP INDEX human_provider_tokens_refresh_due;

ALTER TABLE human_provider_tokens
    DROP CONSTRAINT human_provider_tokens_primary_key,
    DROP CONSTRAINT human_provider_tokens_grant_kind,
    DROP CONSTRAINT human_provider_tokens_scopes_bounded,
    DROP CONSTRAINT human_provider_tokens_envelope_shape,
    DROP CONSTRAINT human_provider_tokens_lifetime,
    ALTER COLUMN access_expires_at_ms DROP NOT NULL,
    ADD COLUMN envelope_record_id UUID NOT NULL,
    ADD COLUMN token_type TEXT NOT NULL,
    ADD CONSTRAINT human_provider_tokens_primary_key
        PRIMARY KEY (envelope_record_id),
    ADD CONSTRAINT human_provider_tokens_grant_kind CHECK (
        grant_kind IN ('browser_authorization_code', 'device_authorization')
    ),
    ADD CONSTRAINT human_provider_tokens_token_type_shape CHECK (
        octet_length(token_type) BETWEEN 1 AND 255
        AND token_type ~ '^[!-~]+$'
    ),
    ADD CONSTRAINT human_provider_tokens_envelope_shape CHECK ((
        (
            revoked_at_ms IS NULL
            AND revocation_reason IS NULL
            AND octet_length(encrypted_payload) BETWEEN 17 AND 1048592
            AND octet_length(payload_nonce) = 12
            AND octet_length(wrapped_data_key) BETWEEN 1 AND 65536
            AND octet_length(encryption_key_id) BETWEEN 1 AND 64
            AND encryption_key_id ~ '^[a-z0-9][a-z0-9._-]*$'
            AND right(encryption_key_id, 1) ~ '^[a-z0-9]$'
            AND encryption_schema = 1
        ) OR (
            revoked_at_ms >= issued_at_ms
            AND revocation_reason IN (
                'explicit',
                'provider_authorization_revoked',
                'refresh_rejected',
                'principal_disabled',
                'provider_identity_unlinked'
            )
            AND encrypted_payload IS NULL
            AND payload_nonce IS NULL
            AND wrapped_data_key IS NULL
            AND encryption_key_id IS NULL
            AND encryption_schema IS NULL
        )
    ) IS TRUE),
    ADD CONSTRAINT human_provider_tokens_lifetime CHECK (
        issued_at_ms >= 0
        AND (access_expires_at_ms IS NULL OR access_expires_at_ms > issued_at_ms)
        AND (refresh_expires_at_ms IS NULL OR refresh_expires_at_ms > issued_at_ms)
        AND created_at_ms >= 0
        AND updated_at_ms >= created_at_ms
    );

CREATE FUNCTION automata_provider_token_scopes_are_canonical(candidate TEXT[])
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $automata$
    SELECT
        cardinality(candidate) <= 256
        AND array_position(candidate, NULL) IS NULL
        AND COALESCE((
            SELECT bool_and(
                octet_length(scope) BETWEEN 1 AND 255
                AND scope ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]*$'
            )
            FROM unnest(candidate) AS scope
        ), TRUE)
        AND cardinality(candidate) = (
            SELECT count(DISTINCT scope) FROM unnest(candidate) AS scope
        )
        AND candidate = ARRAY(
            SELECT scope FROM unnest(candidate) AS scope ORDER BY scope COLLATE "C"
        );
$automata$;

ALTER TABLE human_provider_tokens
    ADD CONSTRAINT human_provider_tokens_scopes_canonical CHECK (
        automata_provider_token_scopes_are_canonical(scopes)
    );

CREATE UNIQUE INDEX human_provider_tokens_one_active_identity
    ON human_provider_tokens (tenant_id, provider_id, provider_subject)
    WHERE revoked_at_ms IS NULL;

CREATE INDEX human_provider_tokens_refresh_due
    ON human_provider_tokens (
        access_expires_at_ms, tenant_id, provider_id, provider_subject
    )
    WHERE revoked_at_ms IS NULL AND access_expires_at_ms IS NOT NULL;

CREATE FUNCTION automata_enforce_provider_token_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'provider-token tombstones cannot be deleted'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_tombstone_immutable';
    END IF;

    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
        OR OLD.principal_id IS DISTINCT FROM NEW.principal_id
        OR OLD.provider_id IS DISTINCT FROM NEW.provider_id
        OR OLD.provider_subject IS DISTINCT FROM NEW.provider_subject
        OR OLD.envelope_record_id IS DISTINCT FROM NEW.envelope_record_id
        OR OLD.created_at_ms IS DISTINCT FROM NEW.created_at_ms
    THEN
        RAISE EXCEPTION 'provider-token identity is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_identity_immutable';
    END IF;

    IF OLD.revoked_at_ms IS NOT NULL THEN
        RAISE EXCEPTION 'revoked provider-token tombstones are immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_tombstone_immutable';
    END IF;

    IF NEW.version <> OLD.version + 1 OR NEW.updated_at_ms < OLD.updated_at_ms THEN
        RAISE EXCEPTION 'provider-token updates require the next CAS version and monotonic time'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'human_provider_tokens_update_cas';
    END IF;

    RETURN NEW;
END;
$automata$;

CREATE TRIGGER human_provider_tokens_lifecycle_guard
BEFORE UPDATE OR DELETE ON human_provider_tokens
FOR EACH ROW EXECUTE FUNCTION automata_enforce_provider_token_lifecycle();
