-- Bind every durable runner lease offer to the earliest expiry among its lease and
-- encrypted runtime authorities. Existing encrypted offer payloads cannot be
-- authenticated or decoded inside PostgreSQL, so this current-contract migration
-- refuses an ambiguous backfill instead of defaulting authority-bearing offers to
-- the later lease expiry.

LOCK TABLE runners, runner_sessions, job_attempts, runner_command_outbox,
    runner_rpc_receipts, runner_lease_offer_publications
    IN ACCESS EXCLUSIVE MODE;

DO $automata$
DECLARE
    database_now_ms BIGINT := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runners
        WHERE updated_at_ms > database_now_ms + 60000
           OR last_seen_at_ms > database_now_ms + 60000
    ) OR EXISTS (
        SELECT 1
        FROM runner_sessions
        WHERE connected_at_ms > database_now_ms + 60000
           OR heartbeat_at_ms > database_now_ms + 60000
           OR disconnected_at_ms > database_now_ms + 60000
    ) THEN
        RAISE EXCEPTION
            'future runner session timestamps must be reconciled before database-time migration'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_database_time_upgrade';
    END IF;
END
$automata$;

DO $automata$
BEGIN
    IF EXISTS (SELECT 1 FROM runner_lease_offer_publications) THEN
        RAISE EXCEPTION
            'runner lease-offer publications must be recreated before authority-horizon migration'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_authority_horizon_upgrade';
    END IF;
END
$automata$;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runner_command_outbox
        WHERE command_kind = 'automata.runner.lease-offer.v2'
          AND payload_tombstone_reason IS NULL
    ) THEN
        RAISE EXCEPTION
            'live runner lease-offer commands must be recreated before authority-horizon migration'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_command_authority_horizon_upgrade';
    END IF;
END
$automata$;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runner_rpc_receipts
        WHERE operation_kind = 'automata.runner.lease-request.v1'
          AND payload_tombstone_reason IS NULL
    ) THEN
        RAISE EXCEPTION
            'live runner lease-request receipts must be recreated before authority-horizon migration'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_request_receipt_authority_horizon_upgrade';
    END IF;
END
$automata$;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM job_attempts
        WHERE lifecycle IN (
                  'leased', 'preparing', 'running', 'cancelling', 'finalizing'
              )
           OR lease_id IS NOT NULL
           OR runner_id IS NOT NULL
           OR lease_issued_at_ms IS NOT NULL
           OR lease_expires_at_ms IS NOT NULL
           OR runner_session_id IS NOT NULL
           OR runner_session_epoch IS NOT NULL
           OR runner_generation IS NOT NULL
           OR runner_slot IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'active runner leases must be reconciled before database-time migration'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_active_lease_database_time_upgrade';
    END IF;
END
$automata$;

ALTER TABLE runner_lease_offer_publications
    ADD COLUMN offer_valid_until_ms BIGINT NOT NULL,
    ADD COLUMN delivery_revoked_at_ms BIGINT,
    ADD COLUMN delivery_revocation_reason TEXT,
    ADD CONSTRAINT runner_lease_offer_publications_receipt_binding_unique UNIQUE (
        runner_session_id, request_operation_id, command_sequence
    ),
    ADD CONSTRAINT runner_lease_offer_publications_command_unique UNIQUE (
        runner_session_id, command_sequence
    ),
    ADD CONSTRAINT runner_lease_offer_publications_authority_horizon CHECK (
        created_at_ms >= lease_issued_at_ms
        AND offer_valid_until_ms > created_at_ms
        AND offer_valid_until_ms <= lease_expires_at_ms
    ),
    ADD CONSTRAINT runner_lease_offer_publications_delivery_revocation CHECK (
        (
            delivery_revoked_at_ms IS NULL
            AND delivery_revocation_reason IS NULL
        ) OR (
            delivery_revoked_at_ms >= created_at_ms
            AND delivery_revocation_reason IN (
                'attempt_superseded', 'authority_expired'
            )
            AND (
                delivery_revocation_reason <> 'authority_expired'
                OR delivery_revoked_at_ms >= offer_valid_until_ms
            )
        )
    );

ALTER TABLE runner_rpc_receipts
    ADD COLUMN lease_offer_request_operation_id UUID,
    ADD COLUMN lease_offer_command_sequence BIGINT,
    ADD COLUMN lease_offer_response_disposition TEXT,
    ADD COLUMN lease_offer_primary_response_schema INTEGER,
    ADD COLUMN lease_offer_primary_response_digest BYTEA,
    ADD COLUMN lease_offer_fallback_version INTEGER,
    ADD COLUMN lease_offer_fallback_operation_id UUID,
    ADD COLUMN lease_offer_fallback_retry_after_millis BIGINT,
    ADD COLUMN lease_offer_fallback_response_schema INTEGER,
    ADD COLUMN lease_offer_fallback_response_digest BYTEA,
    ADD CONSTRAINT runner_rpc_receipts_lease_offer_binding_shape CHECK (
        (
            lease_offer_request_operation_id IS NULL
            AND lease_offer_command_sequence IS NULL
        ) OR (
            operation_kind = 'automata.runner.lease-request.v1'
            AND lease_offer_request_operation_id = operation_id
            AND lease_offer_command_sequence > 0
        )
    ),
    ADD CONSTRAINT runner_rpc_receipts_lease_offer_completion_shape CHECK (
        (
            lease_offer_request_operation_id IS NULL
            AND lease_offer_command_sequence IS NULL
            AND lease_offer_response_disposition IS NULL
            AND lease_offer_primary_response_schema IS NULL
            AND lease_offer_primary_response_digest IS NULL
            AND lease_offer_fallback_version IS NULL
            AND lease_offer_fallback_operation_id IS NULL
            AND lease_offer_fallback_retry_after_millis IS NULL
            AND lease_offer_fallback_response_schema IS NULL
            AND lease_offer_fallback_response_digest IS NULL
        ) OR (
            lease_offer_request_operation_id IS NOT NULL
            AND lease_offer_command_sequence IS NOT NULL
            AND lease_offer_response_disposition IS NOT NULL
            AND lease_offer_primary_response_schema IS NOT NULL
            AND lease_offer_primary_response_digest IS NOT NULL
            AND lease_offer_fallback_version IS NOT NULL
            AND lease_offer_fallback_operation_id IS NOT NULL
            AND lease_offer_fallback_retry_after_millis IS NOT NULL
            AND lease_offer_fallback_response_schema IS NOT NULL
            AND lease_offer_fallback_response_digest IS NOT NULL
            AND lease_offer_response_disposition IN (
                'primary', 'revoked_fallback'
            )
            AND lease_offer_primary_response_schema BETWEEN 1 AND 65535
            AND octet_length(lease_offer_primary_response_digest) = 32
            AND lease_offer_fallback_version = 1
            AND lease_offer_fallback_operation_id
                <> '00000000-0000-0000-0000-000000000000'::UUID
            AND lease_offer_fallback_retry_after_millis BETWEEN 1 AND 4294967295
            AND lease_offer_fallback_response_schema BETWEEN 1 AND 65535
            AND octet_length(lease_offer_fallback_response_digest) = 32
            AND (
                (
                    lease_offer_response_disposition = 'primary'
                    AND response_schema = lease_offer_primary_response_schema
                    AND response_digest = lease_offer_primary_response_digest
                ) OR (
                    lease_offer_response_disposition = 'revoked_fallback'
                    AND response_schema = lease_offer_fallback_response_schema
                    AND response_digest = lease_offer_fallback_response_digest
                )
            )
        )
    ),
    ADD CONSTRAINT runner_rpc_receipts_lease_offer_publication
        FOREIGN KEY (
            runner_session_id,
            lease_offer_request_operation_id,
            lease_offer_command_sequence
        )
        REFERENCES runner_lease_offer_publications (
            runner_session_id, request_operation_id, command_sequence
        ) ON DELETE RESTRICT;

CREATE FUNCTION automata_enforce_runner_lease_offer_authority_horizon()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.offer_valid_until_ms IS DISTINCT FROM OLD.offer_valid_until_ms THEN
        RAISE EXCEPTION 'runner lease-offer authority horizon is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_authority_horizon_immutable';
    END IF;
    RETURN NEW;
END
$automata$;

CREATE TRIGGER runner_lease_offer_authority_horizon_guard
BEFORE UPDATE OF offer_valid_until_ms ON runner_lease_offer_publications
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_runner_lease_offer_authority_horizon();

CREATE FUNCTION automata_enforce_runner_lease_offer_delivery_revocation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    database_now_ms BIGINT;
    exact_active_attempt BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.delivery_revoked_at_ms IS NOT NULL
           OR OLD.delivery_revocation_reason IS NOT NULL THEN
            IF NEW.delivery_revoked_at_ms
                    IS DISTINCT FROM OLD.delivery_revoked_at_ms
               OR NEW.delivery_revocation_reason
                    IS DISTINCT FROM OLD.delivery_revocation_reason THEN
                RAISE EXCEPTION 'runner lease-offer delivery revocation is immutable'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runner_lease_offer_delivery_revocation_immutable';
            END IF;
            RETURN NEW;
        END IF;
    END IF;

    IF NEW.delivery_revoked_at_ms IS NULL
       AND NEW.delivery_revocation_reason IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.delivery_revoked_at_ms IS NULL
       OR NEW.delivery_revocation_reason IS NULL THEN
        RAISE EXCEPTION 'runner lease-offer delivery revocation evidence is incomplete'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_publications_delivery_revocation';
    END IF;

    SELECT COALESCE(
               attempt.lifecycle IN (
                   'leased', 'preparing', 'running', 'cancelling', 'finalizing'
               )
               AND attempt.job_id = NEW.job_id
               AND attempt.runner_id = NEW.runner_id
               AND attempt.runner_session_id = NEW.runner_session_id
               AND attempt.runner_session_epoch = NEW.runner_session_epoch
               AND attempt.runner_generation = NEW.runner_generation
               AND attempt.runner_slot = NEW.runner_slot
               AND attempt.lease_id = NEW.lease_id
               AND attempt.fencing_token = NEW.fencing_token
               AND attempt.lease_issued_at_ms = NEW.lease_issued_at_ms
               AND attempt.lease_expires_at_ms >= NEW.lease_expires_at_ms,
               FALSE
           )
    INTO exact_active_attempt
    FROM job_attempts AS attempt
    WHERE attempt.id = NEW.attempt_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runner lease-offer delivery authority is missing'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_lease_offer_delivery_revocation_authority';
    END IF;

    database_now_ms := floor(
        extract(epoch FROM clock_timestamp()) * 1000
    )::BIGINT;
    CASE NEW.delivery_revocation_reason
        WHEN 'attempt_superseded' THEN
            IF exact_active_attempt THEN
                RAISE EXCEPTION 'live runner lease offer cannot be revoked as superseded'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runner_lease_offer_delivery_revocation_authority';
            END IF;
        WHEN 'authority_expired' THEN
            IF NOT exact_active_attempt
               OR database_now_ms < NEW.offer_valid_until_ms THEN
                RAISE EXCEPTION 'runner lease offer lacks expired delivery authority'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'runner_lease_offer_delivery_revocation_authority';
            END IF;
        ELSE
            RAISE EXCEPTION 'runner lease-offer delivery revocation reason is invalid'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'runner_lease_offer_publications_delivery_revocation';
    END CASE;

    -- The marker is authority evidence, so its observation time is always issued
    -- by PostgreSQL after the exact attempt lock rather than accepted from a caller.
    NEW.delivery_revoked_at_ms := database_now_ms;
    RETURN NEW;
END
$automata$;

CREATE TRIGGER runner_lease_offer_delivery_revocation_guard
BEFORE INSERT OR UPDATE ON runner_lease_offer_publications
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_runner_lease_offer_delivery_revocation();

CREATE FUNCTION automata_enforce_runner_rpc_receipt_lease_offer_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.lease_offer_request_operation_id
            IS DISTINCT FROM OLD.lease_offer_request_operation_id
       OR NEW.lease_offer_command_sequence
            IS DISTINCT FROM OLD.lease_offer_command_sequence
       OR NEW.lease_offer_response_disposition
            IS DISTINCT FROM OLD.lease_offer_response_disposition
       OR NEW.lease_offer_primary_response_schema
            IS DISTINCT FROM OLD.lease_offer_primary_response_schema
       OR NEW.lease_offer_primary_response_digest
            IS DISTINCT FROM OLD.lease_offer_primary_response_digest
       OR NEW.lease_offer_fallback_version
            IS DISTINCT FROM OLD.lease_offer_fallback_version
       OR NEW.lease_offer_fallback_operation_id
            IS DISTINCT FROM OLD.lease_offer_fallback_operation_id
       OR NEW.lease_offer_fallback_retry_after_millis
            IS DISTINCT FROM OLD.lease_offer_fallback_retry_after_millis
       OR NEW.lease_offer_fallback_response_schema
            IS DISTINCT FROM OLD.lease_offer_fallback_response_schema
       OR NEW.lease_offer_fallback_response_digest
            IS DISTINCT FROM OLD.lease_offer_fallback_response_digest THEN
        RAISE EXCEPTION 'runner lease-request receipt offer binding is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'runner_rpc_receipt_lease_offer_binding_immutable';
    END IF;
    RETURN NEW;
END
$automata$;

CREATE TRIGGER runner_rpc_receipt_lease_offer_binding_guard
BEFORE UPDATE OF lease_offer_request_operation_id, lease_offer_command_sequence,
    lease_offer_response_disposition, lease_offer_primary_response_schema,
    lease_offer_primary_response_digest, lease_offer_fallback_version,
    lease_offer_fallback_operation_id, lease_offer_fallback_retry_after_millis,
    lease_offer_fallback_response_schema, lease_offer_fallback_response_digest
ON runner_rpc_receipts
FOR EACH ROW
EXECUTE FUNCTION automata_enforce_runner_rpc_receipt_lease_offer_binding();
