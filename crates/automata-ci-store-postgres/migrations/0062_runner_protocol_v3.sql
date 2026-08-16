ALTER TABLE runner_sessions
    DROP CONSTRAINT runner_sessions_protocol_known;

ALTER TABLE runner_sessions
    ADD CONSTRAINT runner_sessions_protocol_known
    CHECK (protocol_version IN (1, 2, 3));

ALTER TABLE runner_runtime_authority_deliveries
    DROP CONSTRAINT runner_runtime_authority_deliveries_protocol_v2;

ALTER TABLE runner_runtime_authority_deliveries
    ADD CONSTRAINT runner_runtime_authority_deliveries_protocol_known
    CHECK (protocol_version IN (2, 3));
