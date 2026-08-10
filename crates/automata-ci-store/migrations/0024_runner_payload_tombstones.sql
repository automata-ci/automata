-- Runner command and RPC-response envelopes are retry state, not an archive.
-- A cumulative ACK or terminal session transition erases the wrapping material
-- and ciphertext in the same transaction while retaining authenticated
-- metadata, digests, sizes, and rows referenced by delivery ledgers.

LOCK TABLE runners, runner_sessions, runner_command_outbox, runner_rpc_receipts,
    attempt_cancellation_intents IN ACCESS EXCLUSIVE MODE;

DO $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runner_command_outbox AS command
        JOIN runner_sessions AS session ON session.id = command.runner_session_id
        WHERE session.disconnected_at_ms IS NOT NULL
           OR command.command_sequence <= session.acknowledged_command_sequence
        LIMIT 1
    ) OR EXISTS (
        SELECT 1
        FROM runner_rpc_receipts AS receipt
        JOIN runner_sessions AS session ON session.id = receipt.runner_session_id
        WHERE session.disconnected_at_ms IS NOT NULL
        LIMIT 1
    ) OR EXISTS (
        SELECT 1
        FROM attempt_cancellation_intents AS cancellation
        JOIN runner_command_outbox AS command
          ON command.runner_session_id = cancellation.delivery_session_id
         AND command.command_sequence = cancellation.delivery_command_sequence
        WHERE cancellation.acknowledged_at_ms IS NOT NULL
        LIMIT 1
    ) THEN
        RAISE EXCEPTION
            'runner payloads already eligible for erasure predate tombstone authority; recreate current retry state before migration'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_payload_tombstones_preexisting_expired_payloads';
    END IF;
END;
$automata$;

ALTER TABLE runner_command_outbox
    ALTER COLUMN envelope_schema DROP NOT NULL,
    ALTER COLUMN wrapping_key_id DROP NOT NULL,
    ALTER COLUMN wrapped_data_key DROP NOT NULL,
    ALTER COLUMN nonce DROP NOT NULL,
    ALTER COLUMN ciphertext DROP NOT NULL,
    ADD COLUMN payload_tombstone_reason TEXT,
    ADD COLUMN payload_tombstoned_at_ms BIGINT,
    ADD CONSTRAINT runner_command_outbox_payload_lifecycle CHECK (
        (
            payload_tombstone_reason IS NULL
            AND payload_tombstoned_at_ms IS NULL
            AND envelope_schema IS NOT NULL
            AND wrapping_key_id IS NOT NULL
            AND wrapped_data_key IS NOT NULL
            AND nonce IS NOT NULL
            AND ciphertext IS NOT NULL
        ) OR (
            payload_tombstone_reason IN (
                'acknowledged', 'session_closed', 'session_superseded'
            )
            AND payload_tombstoned_at_ms IS NOT NULL
            AND payload_tombstoned_at_ms >= created_at_ms
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
        )
    );

ALTER TABLE runner_rpc_receipts
    ALTER COLUMN envelope_schema DROP NOT NULL,
    ALTER COLUMN wrapping_key_id DROP NOT NULL,
    ALTER COLUMN wrapped_data_key DROP NOT NULL,
    ALTER COLUMN nonce DROP NOT NULL,
    ALTER COLUMN ciphertext DROP NOT NULL,
    ADD COLUMN payload_tombstone_reason TEXT,
    ADD COLUMN payload_tombstoned_at_ms BIGINT,
    ADD CONSTRAINT runner_rpc_receipts_payload_lifecycle CHECK (
        (
            payload_tombstone_reason IS NULL
            AND payload_tombstoned_at_ms IS NULL
            AND envelope_schema IS NOT NULL
            AND wrapping_key_id IS NOT NULL
            AND wrapped_data_key IS NOT NULL
            AND nonce IS NOT NULL
            AND ciphertext IS NOT NULL
        ) OR (
            payload_tombstone_reason IN ('session_closed', 'session_superseded')
            AND payload_tombstoned_at_ms IS NOT NULL
            AND payload_tombstoned_at_ms >= committed_at_ms
            AND envelope_schema IS NULL
            AND wrapping_key_id IS NULL
            AND wrapped_data_key IS NULL
            AND nonce IS NULL
            AND ciphertext IS NULL
        )
    );

CREATE FUNCTION automata_guard_runner_command_payload()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    session_acknowledged BIGINT;
    session_disconnected_at BIGINT;
    session_generation BIGINT;
    session_epoch_value BIGINT;
    current_generation BIGINT;
    current_epoch BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.payload_tombstone_reason IS NOT NULL
            OR NEW.payload_tombstoned_at_ms IS NOT NULL
            OR NEW.envelope_schema IS NULL
            OR NEW.wrapping_key_id IS NULL
            OR NEW.wrapped_data_key IS NULL
            OR NEW.nonce IS NULL
            OR NEW.ciphertext IS NULL
        THEN
            RAISE EXCEPTION 'runner command payloads must be inserted live'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_payload_insert_live';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        NEW.runner_session_id, NEW.command_sequence, NEW.operation_id,
        NEW.runner_id, NEW.runner_session_epoch, NEW.runner_generation,
        NEW.command_kind, NEW.command_schema, NEW.command_digest,
        NEW.created_at_ms, NEW.tenant_id, NEW.command_plaintext_size_bytes
    ) IS DISTINCT FROM ROW(
        OLD.runner_session_id, OLD.command_sequence, OLD.operation_id,
        OLD.runner_id, OLD.runner_session_epoch, OLD.runner_generation,
        OLD.command_kind, OLD.command_schema, OLD.command_digest,
        OLD.created_at_ms, OLD.tenant_id, OLD.command_plaintext_size_bytes
    ) THEN
        RAISE EXCEPTION 'runner command authenticated metadata is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_command_outbox_metadata_immutable';
    END IF;

    IF OLD.payload_tombstone_reason IS NOT NULL THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'runner command payload tombstones are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_tombstone_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstone_reason IS NULL THEN
        IF ROW(
            NEW.envelope_schema, NEW.wrapping_key_id, NEW.wrapped_data_key,
            NEW.nonce, NEW.ciphertext, NEW.payload_tombstoned_at_ms
        ) IS DISTINCT FROM ROW(
            OLD.envelope_schema, OLD.wrapping_key_id, OLD.wrapped_data_key,
            OLD.nonce, OLD.ciphertext, OLD.payload_tombstoned_at_ms
        ) THEN
            RAISE EXCEPTION 'live runner command envelopes are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_envelope_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstoned_at_ms IS NULL
        OR NEW.envelope_schema IS NOT NULL
        OR NEW.wrapping_key_id IS NOT NULL
        OR NEW.wrapped_data_key IS NOT NULL
        OR NEW.nonce IS NOT NULL
        OR NEW.ciphertext IS NOT NULL
    THEN
        RAISE EXCEPTION 'runner command tombstone must erase the complete envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_command_outbox_payload_lifecycle';
    END IF;

    SELECT session.acknowledged_command_sequence,
           session.disconnected_at_ms,
           session.runner_generation,
           session.session_epoch,
           runner.generation,
           runner.session_epoch
    INTO session_acknowledged, session_disconnected_at,
         session_generation, session_epoch_value,
         current_generation, current_epoch
    FROM runner_sessions AS session
    JOIN runners AS runner ON runner.id = session.runner_id
    WHERE session.id = OLD.runner_session_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runner command session authority is missing'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'runner_command_outbox_session_fence';
    END IF;

    CASE NEW.payload_tombstone_reason
        WHEN 'acknowledged' THEN
            IF session_disconnected_at IS NOT NULL
                OR (
                    OLD.command_sequence > session_acknowledged
                    AND NOT EXISTS (
                        SELECT 1
                        FROM attempt_cancellation_intents AS cancellation
                        WHERE cancellation.delivery_session_id = OLD.runner_session_id
                          AND cancellation.delivery_command_sequence = OLD.command_sequence
                          AND cancellation.acknowledged_at_ms IS NOT NULL
                          AND cancellation.acknowledged_at_ms <= NEW.payload_tombstoned_at_ms
                    )
                )
            THEN
                RAISE EXCEPTION 'runner command is not acknowledged by a live session'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_command_outbox_ack_tombstone_authority';
            END IF;
        WHEN 'session_closed' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR session_generation <> current_generation
                OR session_epoch_value <> current_epoch
            THEN
                RAISE EXCEPTION 'runner command session-close tombstone lacks current authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_command_outbox_close_tombstone_authority';
            END IF;
        WHEN 'session_superseded' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR current_generation < session_generation
                OR (
                    current_generation = session_generation
                    AND current_epoch <= session_epoch_value
                )
            THEN
                RAISE EXCEPTION 'runner command supersession tombstone lacks newer authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_command_outbox_superseded_tombstone_authority';
            END IF;
        ELSE
            RAISE EXCEPTION 'unknown runner command payload tombstone reason'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_command_outbox_payload_lifecycle';
    END CASE;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER runner_command_outbox_payload_guard
AFTER INSERT OR UPDATE ON runner_command_outbox
FOR EACH ROW EXECUTE FUNCTION automata_guard_runner_command_payload();

CREATE FUNCTION automata_guard_runner_rpc_payload()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    session_disconnected_at BIGINT;
    session_generation BIGINT;
    session_epoch_value BIGINT;
    current_generation BIGINT;
    current_epoch BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.payload_tombstone_reason IS NOT NULL
            OR NEW.payload_tombstoned_at_ms IS NOT NULL
            OR NEW.envelope_schema IS NULL
            OR NEW.wrapping_key_id IS NULL
            OR NEW.wrapped_data_key IS NULL
            OR NEW.nonce IS NULL
            OR NEW.ciphertext IS NULL
        THEN
            RAISE EXCEPTION 'runner RPC payloads must be inserted live'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_payload_insert_live';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        NEW.runner_session_id, NEW.operation_id, NEW.runner_id,
        NEW.runner_session_epoch, NEW.runner_generation, NEW.operation_kind,
        NEW.request_digest, NEW.response_schema, NEW.response_digest,
        NEW.committed_at_ms, NEW.tenant_id,
        NEW.response_plaintext_size_bytes
    ) IS DISTINCT FROM ROW(
        OLD.runner_session_id, OLD.operation_id, OLD.runner_id,
        OLD.runner_session_epoch, OLD.runner_generation, OLD.operation_kind,
        OLD.request_digest, OLD.response_schema, OLD.response_digest,
        OLD.committed_at_ms, OLD.tenant_id,
        OLD.response_plaintext_size_bytes
    ) THEN
        RAISE EXCEPTION 'runner RPC authenticated metadata is immutable'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_rpc_receipts_metadata_immutable';
    END IF;

    IF OLD.payload_tombstone_reason IS NOT NULL THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'runner RPC payload tombstones are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_tombstone_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstone_reason IS NULL THEN
        IF ROW(
            NEW.envelope_schema, NEW.wrapping_key_id, NEW.wrapped_data_key,
            NEW.nonce, NEW.ciphertext, NEW.payload_tombstoned_at_ms
        ) IS DISTINCT FROM ROW(
            OLD.envelope_schema, OLD.wrapping_key_id, OLD.wrapped_data_key,
            OLD.nonce, OLD.ciphertext, OLD.payload_tombstoned_at_ms
        ) THEN
            RAISE EXCEPTION 'live runner RPC envelopes are immutable'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_envelope_immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.payload_tombstoned_at_ms IS NULL
        OR NEW.envelope_schema IS NOT NULL
        OR NEW.wrapping_key_id IS NOT NULL
        OR NEW.wrapped_data_key IS NOT NULL
        OR NEW.nonce IS NOT NULL
        OR NEW.ciphertext IS NOT NULL
    THEN
        RAISE EXCEPTION 'runner RPC tombstone must erase the complete envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_rpc_receipts_payload_lifecycle';
    END IF;

    SELECT session.disconnected_at_ms,
           session.runner_generation,
           session.session_epoch,
           runner.generation,
           runner.session_epoch
    INTO session_disconnected_at, session_generation, session_epoch_value,
         current_generation, current_epoch
    FROM runner_sessions AS session
    JOIN runners AS runner ON runner.id = session.runner_id
    WHERE session.id = OLD.runner_session_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'runner RPC session authority is missing'
            USING ERRCODE = 'foreign_key_violation',
                  CONSTRAINT = 'runner_rpc_receipts_session_fence';
    END IF;

    CASE NEW.payload_tombstone_reason
        WHEN 'session_closed' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR session_generation <> current_generation
                OR session_epoch_value <> current_epoch
            THEN
                RAISE EXCEPTION 'runner RPC session-close tombstone lacks current authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_rpc_receipts_close_tombstone_authority';
            END IF;
        WHEN 'session_superseded' THEN
            IF session_disconnected_at IS NULL
                OR NEW.payload_tombstoned_at_ms < session_disconnected_at
                OR current_generation < session_generation
                OR (
                    current_generation = session_generation
                    AND current_epoch <= session_epoch_value
                )
            THEN
                RAISE EXCEPTION 'runner RPC supersession tombstone lacks newer authority'
                    USING ERRCODE = 'check_violation',
                          CONSTRAINT = 'runner_rpc_receipts_superseded_tombstone_authority';
            END IF;
        ELSE
            RAISE EXCEPTION 'unknown runner RPC payload tombstone reason'
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'runner_rpc_receipts_payload_lifecycle';
    END CASE;
    RETURN NEW;
END;
$automata$;

CREATE TRIGGER runner_rpc_receipts_payload_guard
AFTER INSERT OR UPDATE ON runner_rpc_receipts
FOR EACH ROW EXECUTE FUNCTION automata_guard_runner_rpc_payload();

CREATE FUNCTION automata_assert_runner_session_payload_retention()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM runner_command_outbox AS command
        WHERE command.runner_session_id = NEW.id
          AND command.payload_tombstone_reason IS NULL
          AND (
              NEW.disconnected_at_ms IS NOT NULL
              OR command.command_sequence <= NEW.acknowledged_command_sequence
          )
        LIMIT 1
    ) OR (
        NEW.disconnected_at_ms IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM runner_rpc_receipts AS receipt
            WHERE receipt.runner_session_id = NEW.id
              AND receipt.payload_tombstone_reason IS NULL
            LIMIT 1
        )
    ) THEN
        RAISE EXCEPTION 'runner session transition retained an expired payload envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_session_payload_retention';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE CONSTRAINT TRIGGER runner_session_payload_retention
AFTER INSERT OR UPDATE ON runner_sessions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_assert_runner_session_payload_retention();

CREATE FUNCTION automata_assert_runner_payload_row_retention()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
DECLARE
    retained_live BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'runner_command_outbox' THEN
        SELECT command.payload_tombstone_reason IS NULL
               AND (
                   session.disconnected_at_ms IS NOT NULL
                   OR command.command_sequence <= session.acknowledged_command_sequence
               )
        INTO retained_live
        FROM runner_command_outbox AS command
        JOIN runner_sessions AS session ON session.id = command.runner_session_id
        WHERE command.runner_session_id = NEW.runner_session_id
          AND command.command_sequence = NEW.command_sequence;
    ELSE
        SELECT receipt.payload_tombstone_reason IS NULL
               AND session.disconnected_at_ms IS NOT NULL
        INTO retained_live
        FROM runner_rpc_receipts AS receipt
        JOIN runner_sessions AS session ON session.id = receipt.runner_session_id
        WHERE receipt.runner_session_id = NEW.runner_session_id
          AND receipt.operation_id = NEW.operation_id;
    END IF;
    IF coalesce(retained_live, FALSE) THEN
        RAISE EXCEPTION 'expired runner payload envelope must be tombstoned before commit'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_payload_row_retention';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE CONSTRAINT TRIGGER runner_command_outbox_payload_retention
AFTER INSERT OR UPDATE ON runner_command_outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_assert_runner_payload_row_retention();

CREATE CONSTRAINT TRIGGER runner_rpc_receipts_payload_retention
AFTER INSERT OR UPDATE ON runner_rpc_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_assert_runner_payload_row_retention();

CREATE FUNCTION automata_assert_cancellation_payload_retention()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF NEW.acknowledged_at_ms IS NOT NULL
        AND NEW.delivery_session_id IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM runner_command_outbox AS command
            WHERE command.runner_session_id = NEW.delivery_session_id
              AND command.command_sequence = NEW.delivery_command_sequence
              AND command.payload_tombstone_reason IS NULL
            LIMIT 1
        )
    THEN
        RAISE EXCEPTION 'acknowledged cancellation retained its command envelope'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'runner_cancellation_payload_retention';
    END IF;
    RETURN NEW;
END;
$automata$;

CREATE CONSTRAINT TRIGGER runner_cancellation_payload_retention
AFTER INSERT OR UPDATE ON attempt_cancellation_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION automata_assert_cancellation_payload_retention();

CREATE FUNCTION automata_retain_runner_payload_tombstone()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $automata$
BEGIN
    IF OLD.payload_tombstone_reason IS NOT NULL THEN
        RAISE EXCEPTION 'runner payload tombstone metadata must be retained'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = TG_TABLE_NAME || '_tombstone_retained';
    END IF;
    RETURN OLD;
END;
$automata$;

CREATE TRIGGER runner_command_outbox_tombstone_retain
BEFORE DELETE ON runner_command_outbox
FOR EACH ROW EXECUTE FUNCTION automata_retain_runner_payload_tombstone();

CREATE TRIGGER runner_rpc_receipts_tombstone_retain
BEFORE DELETE ON runner_rpc_receipts
FOR EACH ROW EXECUTE FUNCTION automata_retain_runner_payload_tombstone();
