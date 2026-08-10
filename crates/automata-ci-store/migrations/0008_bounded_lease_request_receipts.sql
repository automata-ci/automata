-- Protocol-v4 lease polls form one durable, bounded request chain per live
-- session slot. Older live sessions cannot supply the predecessor carrier and
-- are fenced before the new head invariant becomes authoritative.

UPDATE runners AS runner
SET status = 'offline',
    updated_at_ms = greatest(runner.updated_at_ms, incompatible.heartbeat_at_ms)
FROM (
    SELECT runner_id, max(heartbeat_at_ms) AS heartbeat_at_ms
    FROM runner_sessions
    WHERE disconnected_at_ms IS NULL AND protocol_version <> 4
    GROUP BY runner_id
) AS incompatible
WHERE runner.id = incompatible.runner_id
  AND runner.status = 'online';

UPDATE runner_sessions
SET disconnected_at_ms = heartbeat_at_ms
WHERE disconnected_at_ms IS NULL AND protocol_version <> 4;

ALTER TABLE runner_sessions
    ADD CONSTRAINT runner_sessions_live_protocol_v4 CHECK (
        disconnected_at_ms IS NOT NULL OR protocol_version = 4
    );

-- Closed-session retry state has no authority and only consumed unbounded
-- space in the pre-v4 ledgers. Queue cursors are deliberately retained: they
-- are runner-generation scheduling progress, not session retry state.
DELETE FROM runner_operation_receipts AS receipt
USING runner_sessions AS session
WHERE receipt.runner_session_id = session.id
  AND session.disconnected_at_ms IS NOT NULL;

DELETE FROM runner_rpc_receipts AS receipt
USING runner_sessions AS session
WHERE receipt.runner_session_id = session.id
  AND receipt.operation_kind = 'automata.runner.lease-request.v1'
  AND session.disconnected_at_ms IS NOT NULL;

CREATE TABLE runner_lease_request_heads (
    runner_session_id UUID NOT NULL,
    runner_slot INTEGER NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    operation_id UUID NOT NULL,
    request_digest BYTEA NOT NULL,
    acknowledges_operation_id UUID,
    CONSTRAINT runner_lease_request_heads_primary_key PRIMARY KEY (
        runner_session_id, runner_slot
    ),
    CONSTRAINT runner_lease_request_heads_operation_unique UNIQUE (
        runner_session_id, operation_id
    ),
    CONSTRAINT runner_lease_request_heads_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT runner_lease_request_heads_slot_range CHECK (
        runner_slot BETWEEN 1 AND 65535
    ),
    CONSTRAINT runner_lease_request_heads_request_sha256 CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT runner_lease_request_heads_predecessor_distinct CHECK (
        acknowledges_operation_id IS NULL
        OR acknowledges_operation_id <> operation_id
    )
);
