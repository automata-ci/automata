ALTER TABLE provider_result_outbox
    ADD COLUMN projection_digest BYTEA NOT NULL,
    ADD CONSTRAINT provider_result_projection_digest_shape CHECK (
        octet_length(projection_digest) = 32
    );
