-- Current-only authenticated key-material attestation for repository-secret
-- custody. A key ID is metadata, not proof that two replicas loaded the same
-- key bytes. The first configured writer for a previously unreferenced key ID
-- seals the fixed v1 canary; every later check that declares or requires that
-- key must open the exact immutable envelope. Referenced pre-canary IDs fail
-- closed instead of using trust-on-first-use against already encrypted state.

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM secret_version_envelopes) THEN
        RAISE EXCEPTION 'pre-canary built-in secret state must be recreated'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_custody_pre_canary_builtin_state';
    END IF;
END;
$automata$;

CREATE TABLE secret_custody_key_canaries (
    wrapping_key_id TEXT COLLATE "C" PRIMARY KEY,
    canary_generation BIGINT NOT NULL DEFAULT 1,
    canary_schema INTEGER NOT NULL DEFAULT 1,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    wrapped_data_key BYTEA NOT NULL,
    envelope_schema INTEGER NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT secret_custody_key_canaries_key_id_shape CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 64
        AND wrapping_key_id ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
    ),
    CONSTRAINT secret_custody_key_canaries_generation CHECK (
        canary_generation = 1
    ),
    CONSTRAINT secret_custody_key_canaries_canary_schema CHECK (
        canary_schema = 1
    ),
    -- The fixed v1 36-byte canary plus the AES-256-GCM 16-byte tag.
    CONSTRAINT secret_custody_key_canaries_ciphertext_shape CHECK (
        octet_length(ciphertext) = 52
    ),
    CONSTRAINT secret_custody_key_canaries_nonce_shape CHECK (
        octet_length(nonce) = 12
    ),
    CONSTRAINT secret_custody_key_canaries_wrapped_key_shape CHECK (
        octet_length(wrapped_data_key) BETWEEN 1 AND 4096
    ),
    CONSTRAINT secret_custody_key_canaries_envelope_schema CHECK (
        envelope_schema = 1
    ),
    CONSTRAINT secret_custody_key_canaries_time_nonnegative CHECK (
        created_at_ms >= 0
    )
);

-- Built-in ciphertext may only name a canonical, already-attested key. The
-- migration-time refusal above keeps this new foreign key fully validated;
-- there is no invented compatibility canary for old ciphertext.
ALTER TABLE secret_version_envelopes
    DROP CONSTRAINT secret_version_envelopes_key_id_shape,
    ALTER COLUMN wrapping_key_id TYPE TEXT COLLATE "C"
        USING wrapping_key_id::TEXT,
    ADD CONSTRAINT secret_version_envelopes_key_id_shape CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 64
        AND wrapping_key_id ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
    ),
    ADD CONSTRAINT secret_version_envelopes_custody_canary
        FOREIGN KEY (wrapping_key_id)
        REFERENCES secret_custody_key_canaries(wrapping_key_id)
        ON DELETE RESTRICT;

-- Exact key-first and head-tuple indexes let the bounded readiness query walk
-- live heads without an unindexed historical-envelope join.
CREATE INDEX secret_custody_configuration_key_scan
    ON secret_provider_configuration_envelopes (
        wrapping_key_id COLLATE "C", tenant_id, provider_id,
        envelope_generation
    );
CREATE INDEX secret_custody_configuration_head_scan
    ON secret_provider_configuration_envelope_heads (
        tenant_id, provider_id, envelope_generation
    );

CREATE INDEX secret_custody_locator_key_scan
    ON secret_provider_locator_envelopes (
        wrapping_key_id COLLATE "C", tenant_id, secret_id,
        envelope_generation
    );
CREATE INDEX secret_custody_locator_head_scan
    ON secret_provider_locator_envelope_heads (
        tenant_id, secret_id, envelope_generation
    );

CREATE INDEX secret_custody_provider_version_key_scan
    ON secret_provider_version_envelopes (
        wrapping_key_id COLLATE "C", tenant_id, secret_version_id,
        envelope_generation
    );
CREATE INDEX secret_custody_provider_version_head_scan
    ON secret_provider_version_envelope_heads (
        tenant_id, secret_version_id, envelope_generation
    );

CREATE INDEX secret_custody_builtin_version_key_scan
    ON secret_version_envelopes (
        wrapping_key_id COLLATE "C", tenant_id, secret_version_id,
        envelope_generation
    );
CREATE INDEX secret_custody_builtin_version_head_scan
    ON secret_version_envelope_heads (
        tenant_id, secret_version_id, envelope_generation
    );

CREATE INDEX secret_custody_lease_key_scan
    ON secret_provider_lease_envelopes (
        wrapping_key_id COLLATE "C", tenant_id, provider_lease_record_id,
        envelope_generation
    );
CREATE INDEX secret_custody_lease_head_scan
    ON secret_provider_lease_envelope_heads (
        tenant_id, provider_lease_record_id, envelope_generation
    );

CREATE INDEX secret_custody_rotation_from_key_scan
    ON secret_key_rotations (
        from_wrapping_key_id COLLATE "C", tenant_id, id
    );
CREATE INDEX secret_custody_rotation_to_key_scan
    ON secret_key_rotations (
        to_wrapping_key_id COLLATE "C", tenant_id, id
    );

-- Closed-state partial indexes make global readiness existence probes stop at
-- the first relevant row instead of scanning terminal history.
CREATE INDEX secret_custody_active_provider_scan
    ON secret_providers (tenant_id, provider_id)
    WHERE status = 'active';
CREATE INDEX secret_custody_open_mutation_scan
    ON secret_version_mutations (tenant_id, mutation_id)
    WHERE state = 'reserved';
CREATE INDEX secret_custody_open_lease_scan
    ON secret_provider_leases (tenant_id, id)
    WHERE status IN ('active', 'revocation_pending');
CREATE INDEX secret_custody_open_cleanup_scan
    ON secret_cleanup_outbox (sequence)
    WHERE status IN ('pending', 'in_progress', 'dead_letter');
CREATE INDEX secret_custody_open_recovery_scan
    ON secret_mutation_recovery_outbox (sequence)
    WHERE status IN ('pending', 'in_progress');
CREATE INDEX secret_custody_open_rotation_scan
    ON secret_key_rotations (tenant_id, id)
    WHERE status IN ('pending', 'running', 'failed');
CREATE INDEX secret_custody_open_rotation_item_scan
    ON secret_key_rotation_items (tenant_id, rotation_id)
    WHERE status IN ('pending', 'failed');

CREATE FUNCTION automata_secret_custody_canary_require_fresh_key()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    -- A concurrent exact first writer is resolved by the primary key. Do not
    -- reject that replay merely because a write composed after its winner has
    -- already begun using the now-attested identity.
    IF EXISTS (
        SELECT 1 FROM secret_custody_key_canaries
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) THEN
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1 FROM secret_provider_configuration_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_provider_locator_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_provider_version_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_version_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_provider_lease_envelopes
        WHERE wrapping_key_id = NEW.wrapping_key_id
    ) OR EXISTS (
        SELECT 1 FROM secret_key_rotations
        WHERE from_wrapping_key_id = NEW.wrapping_key_id
           OR to_wrapping_key_id = NEW.wrapping_key_id
    ) THEN
        RAISE EXCEPTION 'referenced secret custody keys require a prior canary'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'secret_custody_key_canaries_fresh_key';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER secret_custody_key_canaries_fresh_key
BEFORE INSERT ON secret_custody_key_canaries
FOR EACH ROW
EXECUTE FUNCTION automata_secret_custody_canary_require_fresh_key();

CREATE FUNCTION automata_secret_custody_key_canaries_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    RAISE EXCEPTION 'secret custody key canaries are immutable'
        USING ERRCODE = 'integrity_constraint_violation',
              CONSTRAINT = 'secret_custody_key_canaries_immutable';
END;
$automata$;

CREATE TRIGGER secret_custody_key_canaries_update_forbidden
BEFORE UPDATE ON secret_custody_key_canaries
FOR EACH ROW
EXECUTE FUNCTION automata_secret_custody_key_canaries_immutable();

CREATE TRIGGER secret_custody_key_canaries_delete_forbidden
BEFORE DELETE ON secret_custody_key_canaries
FOR EACH ROW
EXECUTE FUNCTION automata_secret_custody_key_canaries_immutable();

CREATE TRIGGER secret_custody_key_canaries_truncate_forbidden
BEFORE TRUNCATE ON secret_custody_key_canaries
FOR EACH STATEMENT
EXECUTE FUNCTION automata_secret_custody_key_canaries_immutable();
