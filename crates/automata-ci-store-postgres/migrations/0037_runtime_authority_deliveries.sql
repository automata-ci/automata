-- AUTH-03: metadata-only custody for post-accept runtime-authority delivery.
-- Plaintext credentials and encoded grant responses are intentionally absent.

ALTER TABLE runner_sessions
    DROP CONSTRAINT runner_sessions_protocol_current;

ALTER TABLE runner_sessions
    ADD CONSTRAINT runner_sessions_protocol_known
    CHECK (protocol_version IN (1, 2));

ALTER TABLE runner_lease_offer_publications
    ADD CONSTRAINT lease_offer_publications_runtime_authority_binding_unique
    UNIQUE (
        runner_session_id,
        command_sequence,
        runner_id,
        runner_session_epoch,
        runner_generation,
        protocol_version,
        runner_slot,
        attempt_id,
        lease_id,
        fencing_token,
        job_id,
        run_id,
        job_ir_schema,
        job_ir_size_bytes,
        job_ir_digest,
        job_ir_object_key
    );

ALTER TABLE runner_command_outbox
    ADD CONSTRAINT runner_command_outbox_authority_binding_unique
    UNIQUE (runner_session_id, command_sequence, operation_id);

CREATE TABLE runner_runtime_authority_deliveries (
    attempt_id uuid NOT NULL,
    fencing_token bigint NOT NULL,
    delivery_generation integer NOT NULL,
    runner_id uuid NOT NULL,
    runner_session_id uuid NOT NULL,
    runner_session_epoch bigint NOT NULL,
    runner_generation bigint NOT NULL,
    protocol_version integer NOT NULL,
    runner_slot integer NOT NULL,
    lease_id uuid NOT NULL,
    offer_operation_id uuid NOT NULL,
    offer_command_sequence bigint NOT NULL,
    job_id uuid NOT NULL,
    run_id uuid NOT NULL,
    job_ir_schema integer NOT NULL,
    job_ir_size_bytes bigint NOT NULL,
    job_ir_digest bytea NOT NULL,
    job_ir_object_key text NOT NULL,
    request_operation_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    bundle_digest bytea NOT NULL,
    committed_at_ms bigint NOT NULL,
    acknowledgement_operation_id uuid,
    acknowledgement_digest bytea,
    acknowledged_at_ms bigint,
    CONSTRAINT runner_runtime_authority_deliveries_pkey
        PRIMARY KEY (attempt_id, fencing_token, delivery_generation),
    CONSTRAINT runner_runtime_authority_deliveries_request_unique
        UNIQUE (runner_session_id, request_operation_id),
    CONSTRAINT runner_runtime_authority_deliveries_fence_positive
        CHECK (fencing_token > 0),
    CONSTRAINT runner_runtime_authority_deliveries_generation_initial
        CHECK (delivery_generation = 1),
    CONSTRAINT runner_runtime_authority_deliveries_protocol_v2
        CHECK (protocol_version = 2),
    CONSTRAINT runner_runtime_authority_deliveries_slot_range
        CHECK (runner_slot BETWEEN 1 AND 65535),
    CONSTRAINT runner_runtime_authority_deliveries_command_sequence_positive
        CHECK (offer_command_sequence > 0),
    CONSTRAINT runner_runtime_authority_deliveries_digests
        CHECK (
            octet_length(job_ir_digest) = 32
            AND octet_length(request_digest) = 32
            AND octet_length(bundle_digest) = 32
        ),
    CONSTRAINT runner_runtime_authority_deliveries_ack_complete
        CHECK (
            (
                acknowledgement_operation_id IS NULL
                AND acknowledgement_digest IS NULL
                AND acknowledged_at_ms IS NULL
            )
            OR (
                acknowledgement_operation_id IS NOT NULL
                AND octet_length(acknowledgement_digest) = 32
                AND acknowledged_at_ms >= committed_at_ms
            )
        ),
    CONSTRAINT runtime_authority_deliveries_exact_offer_publication
        FOREIGN KEY (
            runner_session_id,
            offer_command_sequence,
            runner_id,
            runner_session_epoch,
            runner_generation,
            protocol_version,
            runner_slot,
            attempt_id,
            lease_id,
            fencing_token,
            job_id,
            run_id,
            job_ir_schema,
            job_ir_size_bytes,
            job_ir_digest,
            job_ir_object_key
        ) REFERENCES runner_lease_offer_publications (
            runner_session_id,
            command_sequence,
            runner_id,
            runner_session_epoch,
            runner_generation,
            protocol_version,
            runner_slot,
            attempt_id,
            lease_id,
            fencing_token,
            job_id,
            run_id,
            job_ir_schema,
            job_ir_size_bytes,
            job_ir_digest,
            job_ir_object_key
        ) ON DELETE RESTRICT,
    CONSTRAINT runtime_authority_deliveries_exact_offer_command
        FOREIGN KEY (
            runner_session_id,
            offer_command_sequence,
            offer_operation_id
        ) REFERENCES runner_command_outbox (
            runner_session_id,
            command_sequence,
            operation_id
        ) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX runner_runtime_authority_deliveries_ack_unique
    ON runner_runtime_authority_deliveries(
        runner_session_id,
        acknowledgement_operation_id
    )
    WHERE acknowledgement_operation_id IS NOT NULL;

CREATE INDEX runner_runtime_authority_deliveries_session_slot
    ON runner_runtime_authority_deliveries(
        runner_session_id,
        runner_slot,
        delivery_generation
    );

COMMENT ON TABLE runner_runtime_authority_deliveries IS
    'Value-free request, exact offer/JobIR binding, bundle-digest, and runner custody evidence; never stores authority credentials or grant payloads.';
