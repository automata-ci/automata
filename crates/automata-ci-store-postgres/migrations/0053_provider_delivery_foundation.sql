-- Final provider-neutral webhook endpoint and delivery inbox foundation.
-- GitHub-specific delivery tables are cut over and removed in Stage B; this
-- schema is deliberately independent and has no compatibility triggers.

ALTER TABLE provider_instance_revisions
    ADD CONSTRAINT provider_instance_revision_type_unique
    UNIQUE (instance_id, revision, provider_type);

ALTER TABLE provider_instance_secret_bindings
    ADD CONSTRAINT provider_instance_secret_generation_unique
    UNIQUE (instance_id, revision, secret_name, secret_generation);

ALTER TABLE provider_connection_revisions
    ADD CONSTRAINT provider_connection_provider_revision_unique
    UNIQUE (
        connection_id, revision, provider_instance_id, provider_revision
    );

CREATE TABLE provider_webhook_endpoint_revisions (
    endpoint_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    provider_instance_id UUID NOT NULL,
    provider_revision BIGINT NOT NULL,
    body_limit BIGINT NOT NULL,
    raw_retention_millis BIGINT NOT NULL,
    candidate_count SMALLINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    retired_at_ms BIGINT,
    PRIMARY KEY (endpoint_id, revision),
    UNIQUE (
        endpoint_id, revision, provider_type, provider_instance_id,
        provider_revision
    ),
    FOREIGN KEY (provider_instance_id, provider_revision, provider_type)
        REFERENCES provider_instance_revisions (
            instance_id, revision, provider_type
        ) ON DELETE RESTRICT,
    CHECK (revision > 0),
    CHECK (lifecycle_state IN ('active', 'disabled', 'retired')),
    CHECK (octet_length(provider_type) BETWEEN 1 AND 64),
    CHECK (body_limit BETWEEN 1 AND 33554432),
    CHECK (raw_retention_millis BETWEEN 1 AND 31536000000),
    CHECK (candidate_count BETWEEN 1 AND 4),
    CHECK (created_at_ms >= 0),
    CHECK (retired_at_ms IS NULL OR retired_at_ms >= created_at_ms),
    CHECK (
        (lifecycle_state = 'retired') = (retired_at_ms IS NOT NULL)
    )
);

CREATE TABLE provider_webhook_endpoint_secret_candidates (
    endpoint_id UUID NOT NULL,
    endpoint_revision BIGINT NOT NULL,
    ordinal SMALLINT NOT NULL,
    provider_instance_id UUID NOT NULL,
    configuration_revision BIGINT NOT NULL,
    secret_name TEXT NOT NULL,
    secret_generation BIGINT NOT NULL,
    PRIMARY KEY (endpoint_id, endpoint_revision, ordinal),
    UNIQUE (
        endpoint_id, endpoint_revision, configuration_revision,
        secret_name, secret_generation
    ),
    FOREIGN KEY (endpoint_id, endpoint_revision)
        REFERENCES provider_webhook_endpoint_revisions (endpoint_id, revision)
        ON DELETE RESTRICT,
    FOREIGN KEY (
        provider_instance_id, configuration_revision,
        secret_name, secret_generation
    ) REFERENCES provider_instance_secret_bindings (
        instance_id, revision, secret_name, secret_generation
    ) ON DELETE RESTRICT,
    CHECK (ordinal BETWEEN 1 AND 4)
);

CREATE TABLE provider_webhook_endpoint_current (
    endpoint_id UUID PRIMARY KEY,
    revision BIGINT NOT NULL,
    FOREIGN KEY (endpoint_id, revision)
        REFERENCES provider_webhook_endpoint_revisions (endpoint_id, revision)
        ON DELETE RESTRICT
);

CREATE TABLE provider_delivery_records (
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
    normalized_trigger BYTEA,
    normalized_trigger_digest BYTEA,
    rejection_reason TEXT,
    observations BYTEA NOT NULL,
    observations_digest BYTEA NOT NULL,
    state TEXT NOT NULL,
    attempts SMALLINT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    accepted_at_ms BIGINT NOT NULL,
    claim_worker_id UUID,
    claim_fence BIGINT,
    claim_started_at_ms BIGINT,
    claim_expires_at_ms BIGINT,
    completed_at_ms BIGINT,
    failure_kind TEXT,
    UNIQUE (provider_instance_id, external_delivery_id),
    FOREIGN KEY (
        endpoint_id, endpoint_revision, provider_type,
        provider_instance_id, provider_revision
    ) REFERENCES provider_webhook_endpoint_revisions (
        endpoint_id, revision, provider_type,
        provider_instance_id, provider_revision
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        connection_id, connection_revision,
        provider_instance_id, provider_revision
    ) REFERENCES provider_connection_revisions (
        connection_id, revision, provider_instance_id, provider_revision
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
    CHECK (disposition IN ('trigger', 'rejected')),
    CHECK (
        repository_external_id IS NULL
        OR octet_length(repository_external_id) BETWEEN 1 AND 512
    ),
    CHECK (
        (disposition = 'trigger'
            AND repository_external_id IS NOT NULL
            AND octet_length(normalized_trigger) BETWEEN 1 AND 65536
            AND octet_length(normalized_trigger_digest) = 32
            AND rejection_reason IS NULL)
        OR
        (disposition = 'rejected'
            AND normalized_trigger IS NULL
            AND normalized_trigger_digest IS NULL
            AND rejection_reason IN (
                'unknown-event', 'unsupported-event', 'incomplete-event',
                'payload-identity-mismatch', 'invalid-payload'
            ))
    ),
    CHECK (octet_length(observations) <= 16384),
    CHECK (octet_length(observations_digest) = 32),
    CHECK (state IN (
        'pending', 'retry-pending', 'claimed', 'completed', 'failed', 'discarded'
    )),
    CHECK (attempts BETWEEN 0 AND 16),
    CHECK (available_at_ms >= accepted_at_ms),
    CHECK (accepted_at_ms >= 0),
    CHECK (
        (state IN ('pending', 'discarded') AND attempts = 0)
        OR (state NOT IN ('pending', 'discarded') AND attempts > 0)
    ),
    CHECK (
        (state = 'claimed'
            AND claim_worker_id IS NOT NULL
            AND claim_fence > 0
            AND claim_started_at_ms >= accepted_at_ms
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
    ),
    CHECK (
        (disposition = 'trigger' AND state <> 'discarded')
        OR (disposition = 'rejected' AND state = 'discarded')
    )
);

CREATE INDEX provider_delivery_records_ready
    ON provider_delivery_records (available_at_ms, accepted_at_ms, delivery_id)
    WHERE state IN ('pending', 'retry-pending', 'claimed');

CREATE FUNCTION automata_reject_provider_webhook_revision_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'provider webhook endpoint revisions and candidates are immutable'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER provider_webhook_endpoint_revisions_immutable
BEFORE UPDATE OR DELETE ON provider_webhook_endpoint_revisions
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_webhook_revision_mutation();

CREATE TRIGGER provider_webhook_endpoint_candidates_immutable
BEFORE UPDATE OR DELETE ON provider_webhook_endpoint_secret_candidates
FOR EACH ROW EXECUTE FUNCTION automata_reject_provider_webhook_revision_mutation();

CREATE FUNCTION automata_enforce_provider_webhook_current_advance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'provider webhook endpoint current revision must advance contiguously'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER provider_webhook_endpoint_current_contiguous
BEFORE UPDATE ON provider_webhook_endpoint_current
FOR EACH ROW EXECUTE FUNCTION automata_enforce_provider_webhook_current_advance();

CREATE FUNCTION automata_enforce_provider_delivery_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'provider delivery evidence is immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF ROW(
        NEW.delivery_id, NEW.provider_instance_id, NEW.external_delivery_id,
        NEW.replay_fingerprint, NEW.endpoint_id, NEW.endpoint_revision,
        NEW.provider_type, NEW.provider_revision, NEW.connection_id,
        NEW.connection_revision, NEW.event_type, NEW.received_at_ms,
        NEW.raw_object_key, NEW.raw_body_digest, NEW.raw_body_size,
        NEW.raw_media_type, NEW.raw_retain_until_ms, NEW.signature_scheme,
        NEW.signature_configuration_revision, NEW.signature_secret_name,
        NEW.signature_secret_generation, NEW.disposition,
        NEW.repository_external_id, NEW.normalized_trigger,
        NEW.normalized_trigger_digest, NEW.rejection_reason,
        NEW.observations, NEW.observations_digest, NEW.accepted_at_ms
    ) IS DISTINCT FROM ROW(
        OLD.delivery_id, OLD.provider_instance_id, OLD.external_delivery_id,
        OLD.replay_fingerprint, OLD.endpoint_id, OLD.endpoint_revision,
        OLD.provider_type, OLD.provider_revision, OLD.connection_id,
        OLD.connection_revision, OLD.event_type, OLD.received_at_ms,
        OLD.raw_object_key, OLD.raw_body_digest, OLD.raw_body_size,
        OLD.raw_media_type, OLD.raw_retain_until_ms, OLD.signature_scheme,
        OLD.signature_configuration_revision, OLD.signature_secret_name,
        OLD.signature_secret_generation, OLD.disposition,
        OLD.repository_external_id, OLD.normalized_trigger,
        OLD.normalized_trigger_digest, OLD.rejection_reason,
        OLD.observations, OLD.observations_digest, OLD.accepted_at_ms
    ) THEN
        RAISE EXCEPTION 'provider delivery immutable evidence changed'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    IF OLD.state IN ('pending', 'retry-pending') AND NEW.state = 'claimed' THEN
        IF NEW.attempts <> OLD.attempts + 1
           OR NEW.claim_fence <> COALESCE(OLD.claim_fence, 0) + 1
           OR NEW.available_at_ms <> OLD.available_at_ms
           OR NEW.failure_kind IS NOT NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'provider delivery initial claim transition is invalid'
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
            RAISE EXCEPTION 'provider delivery reclaim transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'retry-pending' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.claim_fence <> OLD.claim_fence
           OR NEW.available_at_ms <= OLD.available_at_ms
           OR NEW.failure_kind IS NULL
           OR NEW.completed_at_ms IS NOT NULL THEN
            RAISE EXCEPTION 'provider delivery retry transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'completed' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.claim_fence <> OLD.claim_fence
           OR NEW.completed_at_ms IS DISTINCT FROM NEW.available_at_ms
           OR NEW.completed_at_ms >= OLD.claim_expires_at_ms
           OR NEW.failure_kind IS NOT NULL THEN
            RAISE EXCEPTION 'provider delivery completion transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF OLD.state = 'claimed' AND NEW.state = 'failed' THEN
        IF NEW.attempts <> OLD.attempts
           OR NEW.claim_fence <> OLD.claim_fence
           OR NEW.completed_at_ms IS DISTINCT FROM NEW.available_at_ms
           OR NEW.completed_at_ms >= OLD.claim_expires_at_ms
           OR NEW.failure_kind IS NULL THEN
            RAISE EXCEPTION 'provider delivery failure transition is invalid'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSE
        RAISE EXCEPTION 'provider delivery lifecycle transition is invalid'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER provider_delivery_records_transition
BEFORE UPDATE OR DELETE ON provider_delivery_records
FOR EACH ROW EXECUTE FUNCTION automata_enforce_provider_delivery_transition();
