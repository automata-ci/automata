-- Atomic runner-control delivery metadata. A claim remains an internal lease until a
-- corresponding typed offer and outbox command commit together in this table.

CREATE TABLE runner_lease_offer_publications (
    runner_session_id UUID NOT NULL,
    request_operation_id UUID NOT NULL,
    runner_id UUID NOT NULL,
    runner_session_epoch BIGINT NOT NULL,
    runner_generation BIGINT NOT NULL,
    operation_kind TEXT NOT NULL,
    request_digest BYTEA NOT NULL,
    protocol_version INTEGER NOT NULL,
    runner_slot INTEGER NOT NULL,
    attempt_id UUID NOT NULL REFERENCES job_attempts(id) ON DELETE RESTRICT,
    lease_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    lease_issued_at_ms BIGINT NOT NULL,
    lease_expires_at_ms BIGINT NOT NULL,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
    run_id UUID NOT NULL REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    job_ir_schema INTEGER NOT NULL,
    job_ir_size_bytes BIGINT NOT NULL,
    job_ir_digest BYTEA NOT NULL,
    job_ir_object_key TEXT NOT NULL,
    command_sequence BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    CONSTRAINT runner_lease_offer_publications_primary_key PRIMARY KEY (
        runner_session_id, request_operation_id
    ),
    CONSTRAINT runner_lease_offer_publications_session_fence
        FOREIGN KEY (
            runner_id, runner_session_id, runner_session_epoch, runner_generation
        )
        REFERENCES runner_sessions (
            runner_id, id, session_epoch, runner_generation
        ) ON DELETE RESTRICT,
    CONSTRAINT runner_lease_offer_publications_command
        FOREIGN KEY (runner_session_id, command_sequence)
        REFERENCES runner_command_outbox (runner_session_id, command_sequence)
        ON DELETE RESTRICT,
    CONSTRAINT runner_lease_offer_publications_request_sha256 CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT runner_lease_offer_publications_kind_shape CHECK (
        octet_length(operation_kind) BETWEEN 1 AND 128
        AND operation_kind ~ '^[a-z0-9][a-z0-9._/-]*$'
    ),
    CONSTRAINT runner_lease_offer_publications_protocol_range CHECK (
        protocol_version BETWEEN 1 AND 65535
    ),
    CONSTRAINT runner_lease_offer_publications_slot_range CHECK (
        runner_slot BETWEEN 1 AND 65535
    ),
    CONSTRAINT runner_lease_offer_publications_fence_positive CHECK (fencing_token > 0),
    CONSTRAINT runner_lease_offer_publications_lease_interval CHECK (
        lease_expires_at_ms > lease_issued_at_ms
    ),
    CONSTRAINT runner_lease_offer_publications_job_ir_shape CHECK (
        job_ir_schema = 3
        AND job_ir_size_bytes BETWEEN 1 AND 16777216
        AND octet_length(job_ir_digest) = 32
        AND octet_length(job_ir_object_key) BETWEEN 1 AND 1024
        AND job_ir_object_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT runner_lease_offer_publications_command_sequence_positive CHECK (
        command_sequence > 0
    )
);

CREATE UNIQUE INDEX runner_lease_offer_publications_lease
    ON runner_lease_offer_publications (attempt_id, lease_id, fencing_token);
