-- Durable runner machine authority. TLS validation remains in runner-transport;
-- this schema maps an exact validated leaf digest to server-owned identity and
-- lifecycle state without deriving either from certificate contents.

ALTER TABLE runners
    ADD COLUMN external_identity TEXT,
    ADD COLUMN desired_state TEXT;

-- Preserve administrator intent before narrowing `status` to observed
-- connectivity only.
UPDATE runners
SET desired_state = CASE status
    WHEN 'draining' THEN 'draining'
    WHEN 'disabled' THEN 'disabled'
    ELSE 'active'
END;

-- A legacy draining runner may still own a live session. Preserve that
-- connection as online so it can drain; all other draining runners and every
-- disabled runner become observably offline. Desired state controls admission.
UPDATE runners AS runner
SET status = CASE
    WHEN runner.status = 'online' THEN 'online'
    WHEN runner.status = 'draining' AND EXISTS (
        SELECT 1
        FROM runner_sessions AS session
        WHERE session.runner_id = runner.id
          AND session.runner_generation = runner.generation
          AND session.session_epoch = runner.session_epoch
          AND session.disconnected_at_ms IS NULL
    ) THEN 'online'
    ELSE 'offline'
END;

ALTER TABLE runners
    ALTER COLUMN desired_state SET NOT NULL,
    DROP CONSTRAINT runners_status,
    ADD CONSTRAINT runners_status CHECK (status IN ('offline', 'online')),
    ADD CONSTRAINT runners_desired_state CHECK (
        desired_state IN ('active', 'draining', 'disabled')
    ),
    ADD CONSTRAINT runners_external_identity_shape CHECK (
        external_identity IS NULL OR (
            octet_length(external_identity) BETWEEN 1 AND 255
            AND external_identity !~ '[[:cntrl:]]'
        )
    ),
    ADD CONSTRAINT runners_external_identity_unique UNIQUE (external_identity);

-- A desired-state race rejects a poll before consuming its scan cursor. Keep
-- that authority rejection distinct from routing rejection after a cursor CAS.
ALTER TABLE runner_operation_receipts
    DROP CONSTRAINT runner_operation_receipts_outcome,
    DROP CONSTRAINT runner_operation_receipts_result_shape,
    ADD CONSTRAINT runner_operation_receipts_outcome CHECK (
        outcome IN (
            'pending', 'claimed', 'no_work', 'attempt_not_found', 'not_queued',
            'not_routable', 'not_runnable', 'slot_out_of_range', 'slot_occupied',
            'scan_superseded', 'authority_rejected'
        )
    ),
    ADD CONSTRAINT runner_operation_receipts_result_shape CHECK (
        (
            outcome = 'pending'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NULL
            AND completed_at_ms IS NULL
        ) OR (
            outcome = 'no_work'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome = 'claimed'
            AND claimed_fencing_token IS NOT NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome = 'not_queued'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NOT NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome = 'slot_occupied'
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NOT NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome IN (
                'attempt_not_found', 'not_routable', 'not_runnable', 'slot_out_of_range'
            )
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NOT NULL
            AND completed_at_ms IS NOT NULL
        ) OR (
            outcome IN ('scan_superseded', 'authority_rejected')
            AND claimed_fencing_token IS NULL
            AND rejection_lifecycle IS NULL
            AND occupied_attempt_id IS NULL
            AND committed_cursor_version IS NULL
            AND completed_at_ms IS NOT NULL
        )
    );

CREATE TABLE runner_machine_certificates (
    leaf_sha256 BYTEA PRIMARY KEY,
    runner_id UUID NOT NULL REFERENCES runners(id) ON DELETE CASCADE,
    expires_at_seconds BIGINT NOT NULL,
    revoked_at_seconds BIGINT,
    CONSTRAINT runner_machine_certificates_leaf_sha256 CHECK (
        octet_length(leaf_sha256) = 32
    ),
    CONSTRAINT runner_machine_certificates_expiration_positive CHECK (
        expires_at_seconds > 0
    ),
    CONSTRAINT runner_machine_certificates_revocation_monotonic CHECK (
        revoked_at_seconds IS NULL OR (
            revoked_at_seconds > 0
            AND revoked_at_seconds <= expires_at_seconds
        )
    )
);

-- Rotation permits several unrevoked leaves for one runner. The digest primary
-- key prevents one leaf from authorizing two runners, including across tenants.
CREATE INDEX runner_machine_certificates_active_by_runner
    ON runner_machine_certificates (runner_id, expires_at_seconds)
    WHERE revoked_at_seconds IS NULL;

CREATE INDEX runner_machine_certificates_revoked_at
    ON runner_machine_certificates (revoked_at_seconds)
    WHERE revoked_at_seconds IS NOT NULL;

-- Leaf identity, owner, and certificate lifetime are immutable. Rotation is a
-- new row followed by one-way revocation of the old row.
CREATE FUNCTION automata_runner_certificate_authority_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.leaf_sha256 IS DISTINCT FROM OLD.leaf_sha256
       OR NEW.runner_id IS DISTINCT FROM OLD.runner_id
       OR NEW.expires_at_seconds IS DISTINCT FROM OLD.expires_at_seconds THEN
        RAISE EXCEPTION 'runner machine certificate authority is immutable'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'runner_machine_certificates_authority_immutable';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER runner_machine_certificates_authority_immutable
BEFORE UPDATE OF leaf_sha256, runner_id, expires_at_seconds
ON runner_machine_certificates
FOR EACH ROW
EXECUTE FUNCTION automata_runner_certificate_authority_immutable();

-- Revocation is a one-way authority reduction. A compromised or stale writer
-- cannot clear or rewrite an already committed revocation timestamp.
CREATE FUNCTION automata_runner_certificate_revocation_write_once()
RETURNS trigger
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.revoked_at_seconds IS NOT NULL
       AND NEW.revoked_at_seconds IS DISTINCT FROM OLD.revoked_at_seconds THEN
        RAISE EXCEPTION 'runner machine certificate revocation is write-once'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'runner_machine_certificates_revocation_write_once';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER runner_machine_certificates_revocation_write_once
BEFORE UPDATE OF revoked_at_seconds ON runner_machine_certificates
FOR EACH ROW
EXECUTE FUNCTION automata_runner_certificate_revocation_write_once();
