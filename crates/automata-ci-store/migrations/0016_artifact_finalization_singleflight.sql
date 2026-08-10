-- Fence artifact verification and manifest publication before any object read.
-- This is a greenfield baseline migration: no prior artifact rows are accepted.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM workflow_artifacts LIMIT 1) THEN
        RAISE EXCEPTION
            'artifact finalization single-flight requires an empty greenfield artifact table';
    END IF;
END
$$;

ALTER TABLE workflow_artifacts
    DROP CONSTRAINT workflow_artifacts_publication_shape,
    ADD COLUMN finalization_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN finalization_claimed_size_bytes BIGINT,
    ADD COLUMN finalization_claimed_digest BYTEA,
    ADD COLUMN finalization_claim_expires_at_seconds BIGINT,
    ADD COLUMN manifest_bytes BYTEA,
    ADD CONSTRAINT workflow_artifacts_finalization_claim CHECK ((
        (
            finalization_generation = 0
            AND finalization_claimed_size_bytes IS NULL
            AND finalization_claimed_digest IS NULL
            AND finalization_claim_expires_at_seconds IS NULL
        ) OR (
            finalization_generation > 0
            AND finalization_claimed_size_bytes >= 0
            AND (
                finalization_claimed_digest IS NULL
                OR octet_length(finalization_claimed_digest) = 32
            )
            AND finalization_claim_expires_at_seconds >= created_at_seconds
        )
    ) IS TRUE),
    ADD CONSTRAINT workflow_artifacts_publication_shape CHECK ((
        (
            state = 'pending'
            AND manifest_state IS NULL
            AND content_digest IS NULL
            AND content_size_bytes IS NULL
            AND manifest_object_key IS NULL
            AND manifest_digest IS NULL
            AND manifest_size_bytes IS NULL
            AND manifest_media_type IS NULL
            AND manifest_bytes IS NULL
            AND manifest_reserved_at_seconds IS NULL
            AND finalized_at_seconds IS NULL
        ) OR (
            state = 'pending'
            AND manifest_state = 'reserved'
            AND finalization_generation > 0
            AND finalization_claimed_size_bytes = content_size_bytes
            AND (
                finalization_claimed_digest IS NULL
                OR finalization_claimed_digest = content_digest
            )
            AND octet_length(content_digest) = 32
            AND content_size_bytes >= 0
            AND octet_length(manifest_object_key) BETWEEN 1 AND 1024
            AND manifest_object_key !~ '[[:cntrl:]]'
            AND octet_length(manifest_digest) = 32
            AND manifest_size_bytes BETWEEN 1 AND 1048576
            AND octet_length(manifest_bytes) = manifest_size_bytes
            AND octet_length(manifest_media_type) BETWEEN 3 AND 128
            AND manifest_media_type !~ '[[:space:][:cntrl:];]'
            AND manifest_reserved_at_seconds >= created_at_seconds
            AND finalized_at_seconds IS NULL
        ) OR (
            state = 'finalized'
            AND manifest_state = 'ready'
            AND finalization_generation > 0
            AND finalization_claimed_size_bytes = content_size_bytes
            AND (
                finalization_claimed_digest IS NULL
                OR finalization_claimed_digest = content_digest
            )
            AND octet_length(content_digest) = 32
            AND content_size_bytes >= 0
            AND octet_length(manifest_object_key) BETWEEN 1 AND 1024
            AND manifest_object_key !~ '[[:cntrl:]]'
            AND octet_length(manifest_digest) = 32
            AND manifest_size_bytes BETWEEN 1 AND 1048576
            AND octet_length(manifest_bytes) = manifest_size_bytes
            AND octet_length(manifest_media_type) BETWEEN 3 AND 128
            AND manifest_media_type !~ '[[:space:][:cntrl:];]'
            AND manifest_reserved_at_seconds >= created_at_seconds
            AND finalized_at_seconds >= manifest_reserved_at_seconds
        )
    ) IS TRUE);
