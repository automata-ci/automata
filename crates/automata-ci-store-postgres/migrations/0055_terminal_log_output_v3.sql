ALTER TABLE human_live_log_tickets
    DROP CONSTRAINT human_live_log_tickets_protocol_current;

DELETE FROM human_live_log_tickets;

DELETE FROM attempt_log_streams;

ALTER TABLE attempt_log_streams
    DROP CONSTRAINT attempt_log_streams_schema_current;

ALTER TABLE attempt_log_streams
    ADD CONSTRAINT attempt_log_streams_schema_current
    CHECK (log_schema = 3);

ALTER TABLE human_live_log_tickets
    ADD CONSTRAINT human_live_log_tickets_protocol_current
    CHECK (protocol_version = 3);
