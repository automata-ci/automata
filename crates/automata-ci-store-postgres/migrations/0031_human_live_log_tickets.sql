CREATE TABLE human_live_log_tickets (
    token_sha256 bytea PRIMARY KEY,
    tenant_id text NOT NULL,
    repository_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    stream_id uuid NOT NULL,
    browser_origin text NOT NULL,
    protocol_version smallint NOT NULL,
    issued_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    consumed_at_ms bigint,
    CONSTRAINT human_live_log_tickets_digest_shape
        CHECK (octet_length(token_sha256) = 32),
    CONSTRAINT human_live_log_tickets_ids_non_nil
        CHECK (
            repository_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND run_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND job_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND stream_id <> '00000000-0000-0000-0000-000000000000'::uuid
        ),
    CONSTRAINT human_live_log_tickets_origin_shape
        CHECK (
            octet_length(browser_origin) BETWEEN 1 AND 2048
            AND browser_origin !~ '[[:cntrl:]]'
        ),
    CONSTRAINT human_live_log_tickets_protocol_current
        CHECK (protocol_version = 1),
    CONSTRAINT human_live_log_tickets_lifetime_bounded
        CHECK (
            issued_at_ms >= 0
            AND expires_at_ms > issued_at_ms
            AND expires_at_ms - issued_at_ms <= 60000
        ),
    CONSTRAINT human_live_log_tickets_consumption_shape
        CHECK (
            consumed_at_ms IS NULL
            OR (consumed_at_ms >= issued_at_ms AND consumed_at_ms < expires_at_ms)
        ),
    CONSTRAINT human_live_log_tickets_tenant_repository_fkey
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT human_live_log_tickets_stream_fkey
        FOREIGN KEY (attempt_id, stream_id)
        REFERENCES attempt_log_streams(attempt_id, id)
        ON DELETE CASCADE
);

CREATE INDEX human_live_log_tickets_expiry
    ON human_live_log_tickets (expires_at_ms, token_sha256);
