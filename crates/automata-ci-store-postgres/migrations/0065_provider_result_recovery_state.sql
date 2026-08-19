ALTER TABLE provider_result_outbox
    ADD COLUMN binding_external_result_id TEXT,
    ADD COLUMN continuation_schema SMALLINT,
    ADD COLUMN continuation_bytes BYTEA,
    ADD COLUMN continuation_digest BYTEA;

ALTER TABLE provider_result_subjects
    ADD COLUMN result_name TEXT NOT NULL,
    ADD COLUMN result_details_url TEXT NOT NULL,
    ADD CONSTRAINT provider_result_name_shape CHECK (
        octet_length(result_name) BETWEEN 1 AND 255
    ),
    ADD CONSTRAINT provider_result_details_url_shape CHECK (
        octet_length(result_details_url) BETWEEN 1 AND 8192
    );

ALTER TABLE provider_result_outbox
    DROP COLUMN details_url;

ALTER TABLE provider_result_outbox
    ADD CONSTRAINT provider_result_binding_shape CHECK (
        binding_external_result_id IS NULL
        OR octet_length(binding_external_result_id) BETWEEN 1 AND 512
    ),
    ADD CONSTRAINT provider_result_continuation_shape CHECK (
        (
            continuation_schema IS NULL
            AND continuation_bytes IS NULL
            AND continuation_digest IS NULL
        ) OR (
            state IN ('pending', 'claimed')
            AND continuation_schema IS NOT NULL
            AND continuation_bytes IS NOT NULL
            AND continuation_digest IS NOT NULL
            AND continuation_schema > 0
            AND octet_length(continuation_bytes) BETWEEN 1 AND 65536
            AND octet_length(continuation_digest) = 32
        )
    );
