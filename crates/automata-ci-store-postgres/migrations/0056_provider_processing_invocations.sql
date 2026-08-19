-- Forward-only greenfield cutover from the combined delivery queue to immutable
-- provider evidence and independently retryable processing invocations.

DROP TABLE provider_delivery_records;
DROP FUNCTION automata_enforce_provider_delivery_transition();

CREATE TABLE provider_deliveries (
    delivery_id UUID PRIMARY KEY,
    provider_instance_id UUID NOT NULL,
    external_delivery_id TEXT NOT NULL,
    replay_fingerprint BYTEA NOT NULL,
    endpoint_id UUID NOT NULL,
    endpoint_revision BIGINT NOT NULL,
    provider_type TEXT NOT NULL,
    provider_revision BIGINT NOT NULL,
    connection_id UUID NOT NULL,
    connection_revision BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    received_at_ms BIGINT NOT NULL,
    raw_object_key TEXT NOT NULL,
    raw_body_digest BYTEA NOT NULL,
    raw_body_size BIGINT NOT NULL,
    raw_media_type TEXT NOT NULL,
    raw_retain_until_ms BIGINT NOT NULL,
    signature_scheme TEXT NOT NULL,
    signature_configuration_revision BIGINT NOT NULL,
    signature_secret_name TEXT NOT NULL,
    signature_secret_generation BIGINT NOT NULL,
    disposition TEXT NOT NULL,
    repository_external_id TEXT,
    normalized_payload BYTEA,
    normalized_payload_digest BYTEA,
    control_kind TEXT,
    control_object_id BYTEA,
    control_actor_kind TEXT,
    control_actor_external_id TEXT,
    control_document_schema BIGINT,
    rejection_reason TEXT,
    observations BYTEA NOT NULL,
    observations_digest BYTEA NOT NULL,
    accepted_at_ms BIGINT NOT NULL,
    UNIQUE (provider_instance_id, external_delivery_id),
    UNIQUE (delivery_id, disposition),
    FOREIGN KEY (
        endpoint_id, endpoint_revision, provider_type,
        provider_instance_id, provider_revision,
        connection_id, connection_revision
    ) REFERENCES provider_webhook_endpoint_revisions (
        endpoint_id, revision, provider_type,
        provider_instance_id, provider_revision,
        connection_id, connection_revision
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        provider_instance_id, signature_configuration_revision,
        signature_secret_name, signature_secret_generation
    ) REFERENCES provider_instance_secret_bindings (
        instance_id, revision, secret_name, secret_generation
    ) ON DELETE RESTRICT,
    CHECK (octet_length(external_delivery_id) BETWEEN 1 AND 512),
    CHECK (octet_length(replay_fingerprint) = 32),
    CHECK (octet_length(event_type) BETWEEN 1 AND 128),
    CHECK (received_at_ms >= 0),
    CHECK (octet_length(raw_object_key) BETWEEN 1 AND 1024),
    CHECK (octet_length(raw_body_digest) = 32),
    CHECK (raw_body_size BETWEEN 0 AND 33554432),
    CHECK (octet_length(raw_media_type) BETWEEN 1 AND 128),
    CHECK (raw_retain_until_ms > received_at_ms),
    CHECK (octet_length(signature_scheme) BETWEEN 1 AND 64),
    CHECK (octet_length(signature_secret_name) BETWEEN 1 AND 64),
    CHECK (disposition IN ('trigger', 'control', 'rejected')),
    CHECK (
        repository_external_id IS NULL
        OR octet_length(repository_external_id) BETWEEN 1 AND 512
    ),
    CHECK (
        (disposition = 'trigger'
            AND repository_external_id IS NOT NULL
            AND octet_length(normalized_payload) BETWEEN 1 AND 65536
            AND octet_length(normalized_payload_digest) = 32
            AND control_kind IS NULL
            AND control_object_id IS NULL
            AND control_actor_kind IS NULL
            AND control_actor_external_id IS NULL
            AND control_document_schema IS NULL
            AND rejection_reason IS NULL)
        OR
        (disposition = 'control'
            AND repository_external_id IS NOT NULL
            AND octet_length(normalized_payload) BETWEEN 1 AND 16384
            AND octet_length(normalized_payload_digest) = 32
            AND control_kind = 'rerun'
            AND octet_length(control_object_id) IN (20, 32)
            AND (control_actor_kind IS NULL) = (control_actor_external_id IS NULL)
            AND (control_actor_kind IS NULL OR control_actor_kind IN (
                'user', 'organization', 'team', 'service-account'
            ))
            AND (control_actor_external_id IS NULL OR
                octet_length(control_actor_external_id) BETWEEN 1 AND 512)
            AND control_document_schema > 0
            AND rejection_reason IS NULL)
        OR
        (disposition = 'rejected'
            AND normalized_payload IS NULL
            AND normalized_payload_digest IS NULL
            AND control_kind IS NULL
            AND control_object_id IS NULL
            AND control_actor_kind IS NULL
            AND control_actor_external_id IS NULL
            AND control_document_schema IS NULL
            AND rejection_reason IN (
                'unknown-event', 'unsupported-event', 'incomplete-event',
                'payload-identity-mismatch', 'invalid-payload'
            ))
    ),
    CHECK (octet_length(observations) <= 16384),
    CHECK (octet_length(observations_digest) = 32),
    CHECK (accepted_at_ms >= received_at_ms)
);

CREATE TABLE provider_processing_invocations (
    invocation_id UUID PRIMARY KEY,
    cause_delivery_id UUID NOT NULL UNIQUE,
    source_delivery_id UUID,
    source_disposition TEXT,
    state TEXT NOT NULL,
    attempts SMALLINT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    claim_worker_id UUID,
    claim_fence BIGINT,
    claim_started_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    completed_at_ms BIGINT,
    failure_kind TEXT,
    FOREIGN KEY (cause_delivery_id)
        REFERENCES provider_deliveries (delivery_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_delivery_id, source_disposition)
        REFERENCES provider_deliveries (delivery_id, disposition) ON DELETE RESTRICT,
    CHECK (
        (source_delivery_id IS NULL AND source_disposition IS NULL)
        OR (source_delivery_id IS NOT NULL AND source_disposition = 'trigger')
    ),
    CHECK (state IN (
        'pending', 'retry-pending', 'claimed', 'completed', 'failed'
    )),
    CHECK (attempts BETWEEN 0 AND 16),
    CHECK (available_at_ms >= created_at_ms),
    CHECK (created_at_ms >= 0),
    CHECK (
        (state = 'pending' AND attempts = 0)
        OR (state <> 'pending' AND attempts > 0)
    ),
    CHECK (
        (state = 'claimed'
            AND claim_worker_id IS NOT NULL
            AND claim_fence > 0
            AND claim_started_at_ms >= created_at_ms
            AND claim_expires_at_ms > claim_started_at_ms)
        OR (state <> 'claimed'
            AND claim_worker_id IS NULL
            AND claim_started_at_ms IS NULL
            AND claim_expires_at_ms IS NULL)
    ),
    CHECK (
        (state IN ('completed', 'failed') AND completed_at_ms IS NOT NULL)
        OR (state NOT IN ('completed', 'failed') AND completed_at_ms IS NULL)
    ),
    CHECK (
        (state IN ('retry-pending', 'failed') AND failure_kind IN (
            'dependency-unavailable', 'policy-rejected', 'invalid-evidence'
        ))
        OR (state NOT IN ('retry-pending', 'failed') AND failure_kind IS NULL)
    )
);

CREATE INDEX provider_processing_invocations_ready
    ON provider_processing_invocations (
        available_at_ms, created_at_ms, invocation_id
    )
    WHERE state IN ('pending', 'retry-pending', 'claimed');

CREATE FUNCTION automata_reject_provider_delivery_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'provider delivery evidence is immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER provider_deliveries_immutable
BEFORE UPDATE OR DELETE ON provider_deliveries
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_delivery_mutation();

CREATE FUNCTION automata_enforce_provider_processing_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE'
       OR NEW.invocation_id IS DISTINCT FROM OLD.invocation_id
       OR NEW.cause_delivery_id IS DISTINCT FROM OLD.cause_delivery_id
       OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms THEN
        RAISE EXCEPTION 'provider processing invocation evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF (NEW.source_delivery_id IS DISTINCT FROM OLD.source_delivery_id
        OR NEW.source_disposition IS DISTINCT FROM OLD.source_disposition)
       AND NOT (
           OLD.state = 'claimed'
           AND NEW.state = 'claimed'
           AND OLD.source_delivery_id IS NULL
           AND OLD.source_disposition IS NULL
           AND NEW.source_delivery_id IS NOT NULL
           AND NEW.source_disposition = 'trigger'
       ) THEN
        RAISE EXCEPTION 'provider processing source binding is invalid'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF OLD.state = 'claimed'
       AND NEW.state = 'claimed'
       AND OLD.source_delivery_id IS NULL
       AND NEW.source_delivery_id IS NOT NULL THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.available_at_ms <> OLD.available_at_ms
           OR NEW.claim_worker_id IS DISTINCT FROM OLD.claim_worker_id
           OR NEW.claim_fence IS DISTINCT FROM OLD.claim_fence
           OR NEW.claim_started_at_ms IS DISTINCT FROM OLD.claim_started_at_ms
           OR NEW.claim_expires_at_ms IS DISTINCT FROM OLD.claim_expires_at_ms
           OR NEW.completed_at_ms IS DISTINCT FROM OLD.completed_at_ms
           OR NEW.failure_kind IS DISTINCT FROM OLD.failure_kind THEN
            RAISE EXCEPTION 'provider processing source binding changed lifecycle state'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state IN ('pending', 'retry-pending') AND NEW.state = 'claimed' THEN
        IF NEW.attempts <> OLD.attempts + 1
           OR NEW.claim_fence <> COALESCE(OLD.claim_fence, 0) + 1
           OR NEW.available_at_ms <> OLD.available_at_ms
           OR NEW.failure_kind IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'provider processing initial claim transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'claimed' THEN
        IF NEW.attempts <> OLD.attempts + 1
           OR NEW.claim_fence <> OLD.claim_fence + 1
           OR NEW.claim_started_at_ms < OLD.claim_expires_at_ms
           OR NEW.claim_expires_at_ms <= OLD.claim_expires_at_ms
           OR NEW.available_at_ms <> OLD.available_at_ms
           OR NEW.failure_kind IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'provider processing reclaim transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'retry-pending' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.claim_fence <> OLD.claim_fence
           OR NEW.available_at_ms <= OLD.available_at_ms
           OR NEW.failure_kind IS NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'provider processing retry transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'completed' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.claim_fence <> OLD.claim_fence
           OR NEW.completed_at_ms IS DISTINCT FROM NEW.available_at_ms
           OR NEW.completed_at_ms >= OLD.claim_expires_at_ms
           OR NEW.failure_kind IS NOT NULL THEN
            RAISE EXCEPTION 'provider processing completion transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'failed' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.claim_fence <> OLD.claim_fence
           OR NEW.completed_at_ms IS DISTINCT FROM NEW.available_at_ms
           OR NEW.completed_at_ms >= OLD.claim_expires_at_ms
           OR NEW.failure_kind IS NULL THEN
            RAISE EXCEPTION 'provider processing failure transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSE
        RAISE EXCEPTION 'provider processing lifecycle transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER provider_processing_invocations_transition
BEFORE UPDATE OR DELETE ON provider_processing_invocations
FOR EACH ROW EXECUTE FUNCTION automata_enforce_provider_processing_transition();
