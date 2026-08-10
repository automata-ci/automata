-- Reserve immutable artifact object identities before object publication.
-- Commit visibility is explicit so failed or interrupted uploads remain
-- durably attributable and cannot bypass aggregate admission limits.

ALTER TABLE workflow_artifact_blocks
    ADD COLUMN state TEXT NOT NULL DEFAULT 'ready',
    ADD COLUMN ready_at_seconds BIGINT;

UPDATE workflow_artifact_blocks
SET ready_at_seconds = staged_at_seconds;

ALTER TABLE workflow_artifact_blocks
    ADD CONSTRAINT workflow_artifact_blocks_state
        CHECK (state IN ('reserved', 'ready')),
    ADD CONSTRAINT workflow_artifact_blocks_readiness
        CHECK ((
            (state = 'reserved' AND ready_at_seconds IS NULL)
            OR (state = 'ready' AND ready_at_seconds >= staged_at_seconds)
        ) IS TRUE);

-- A manifest descriptor is likewise admitted before its immutable object is
-- written. Existing finalized artifacts are backfilled as completed.
ALTER TABLE workflow_artifacts
    ADD COLUMN manifest_state TEXT,
    ADD COLUMN manifest_reserved_at_seconds BIGINT;

UPDATE workflow_artifacts
SET manifest_state = 'ready',
    manifest_reserved_at_seconds = finalized_at_seconds
WHERE state = 'finalized';

ALTER TABLE workflow_artifacts
    DROP CONSTRAINT workflow_artifacts_publication_shape,
    ADD CONSTRAINT workflow_artifacts_manifest_state
        CHECK (manifest_state IS NULL OR manifest_state IN ('reserved', 'ready')),
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
            AND manifest_reserved_at_seconds IS NULL
            AND finalized_at_seconds IS NULL
        ) OR (
            state = 'pending'
            AND manifest_state = 'reserved'
            AND octet_length(content_digest) = 32
            AND content_size_bytes >= 0
            AND octet_length(manifest_object_key) BETWEEN 1 AND 1024
            AND manifest_object_key !~ '[[:cntrl:]]'
            AND octet_length(manifest_digest) = 32
            AND manifest_size_bytes BETWEEN 1 AND 1048576
            AND octet_length(manifest_media_type) BETWEEN 3 AND 128
            AND manifest_media_type !~ '[[:space:][:cntrl:];]'
            AND manifest_reserved_at_seconds >= created_at_seconds
            AND finalized_at_seconds IS NULL
        ) OR (
            state = 'finalized'
            AND manifest_state = 'ready'
            AND octet_length(content_digest) = 32
            AND content_size_bytes >= 0
            AND octet_length(manifest_object_key) BETWEEN 1 AND 1024
            AND manifest_object_key !~ '[[:cntrl:]]'
            AND octet_length(manifest_digest) = 32
            AND manifest_size_bytes BETWEEN 1 AND 1048576
            AND octet_length(manifest_media_type) BETWEEN 3 AND 128
            AND manifest_media_type !~ '[[:space:][:cntrl:];]'
            AND manifest_reserved_at_seconds >= created_at_seconds
            AND finalized_at_seconds >= manifest_reserved_at_seconds
        )
    ) IS TRUE);
