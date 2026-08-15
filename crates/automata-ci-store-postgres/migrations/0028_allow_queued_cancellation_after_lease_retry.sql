CREATE OR REPLACE FUNCTION automata_validate_server_cancellation_terminal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    cancellation attempt_cancellation_intents%ROWTYPE;
    attempt job_attempts%ROWTYPE;
    expected_digest BYTEA;
BEGIN
    IF NEW.terminal_authority IS DISTINCT FROM 'server_cancellation' THEN
        RETURN NEW;
    END IF;

    SELECT * INTO STRICT cancellation
    FROM attempt_cancellation_intents
    WHERE attempt_id = NEW.attempt_id
      AND operation_id = NEW.server_cancellation_operation_id;

    SELECT * INTO STRICT attempt
    FROM job_attempts
    WHERE id = NEW.attempt_id;

    expected_digest := automata_server_cancellation_terminal_digest(
        cancellation.attempt_id,
        cancellation.operation_id,
        cancellation.requested_by,
        cancellation.reason,
        cancellation.requested_at_ms
    );
    IF cancellation.delivery_session_id IS NOT NULL
       OR cancellation.delivery_command_sequence IS NOT NULL
       OR cancellation.acknowledged_at_ms IS NOT NULL
       OR attempt.lifecycle <> 'queued'
       OR attempt.lease_id IS NOT NULL
       OR attempt.runner_id IS NOT NULL
       OR attempt.runner_session_id IS NOT NULL
       OR attempt.runner_session_epoch IS NOT NULL
       OR attempt.runner_generation IS NOT NULL
       OR attempt.runner_slot IS NOT NULL
       OR attempt.lease_issued_at_ms IS NOT NULL
       OR attempt.lease_expires_at_ms IS NOT NULL
       OR NEW.server_cancellation_digest IS DISTINCT FROM expected_digest
       OR NEW.conclusion <> 'cancelled'
       OR NEW.completed_at_ms <> cancellation.requested_at_ms
       OR NEW.committed_at_ms <> cancellation.requested_at_ms
    THEN
        RAISE EXCEPTION 'server cancellation terminal lacks exact queued intent authority'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
EXCEPTION
    WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
        RAISE EXCEPTION 'server cancellation terminal lacks exact queued intent authority'
            USING ERRCODE = '23514';
END;
$$;

COMMENT ON FUNCTION automata_validate_server_cancellation_terminal() IS
    'Validates blob-free server cancellation authority for any unleased queued attempt, including attempts returned to the queue after a fenced lease failure.';
