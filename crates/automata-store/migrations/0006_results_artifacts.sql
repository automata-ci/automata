-- GitHub Actions Results v7 artifact publication. PostgreSQL coordinates
-- pending uploads, exact staged descriptors, ordered block-list commits, and
-- immutable manifest publication. S3-compatible object listing is never state.

ALTER TABLE jobs
    ADD CONSTRAINT jobs_run_id_artifact_unique UNIQUE (run_id, id);

ALTER TABLE job_attempts
    ADD CONSTRAINT attempts_job_id_artifact_unique UNIQUE (job_id, id);

CREATE TABLE workflow_artifacts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    upload_id UUID NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID NOT NULL,
    job_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    name TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    expires_at_seconds BIGINT,
    block_id_encoded_length INTEGER,
    state TEXT NOT NULL DEFAULT 'pending',
    content_digest BYTEA,
    content_size_bytes BIGINT,
    manifest_object_key TEXT,
    manifest_digest BYTEA,
    manifest_size_bytes BIGINT,
    manifest_media_type TEXT,
    created_at_seconds BIGINT NOT NULL,
    finalized_at_seconds BIGINT,
    CONSTRAINT workflow_artifacts_run_name_unique UNIQUE (run_id, name),
    CONSTRAINT workflow_artifacts_tenant_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_artifacts_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_artifacts_run_job
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE CASCADE,
    CONSTRAINT workflow_artifacts_job_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT,
    CONSTRAINT workflow_artifacts_fence_positive CHECK (fencing_token > 0),
    CONSTRAINT workflow_artifacts_name_shape CHECK (
        octet_length(name) BETWEEN 1 AND 255
        AND name !~ '[[:cntrl:]"/:<>|*?\\]'
    ),
    CONSTRAINT workflow_artifacts_protocol_version CHECK (protocol_version = 7),
    CONSTRAINT workflow_artifacts_mime_type_shape CHECK (
        octet_length(mime_type) BETWEEN 3 AND 128
        AND mime_type !~ '[[:space:][:cntrl:];]'
    ),
    CONSTRAINT workflow_artifacts_expiry_positive CHECK (
        expires_at_seconds IS NULL OR expires_at_seconds > created_at_seconds
    ),
    CONSTRAINT workflow_artifacts_block_id_length CHECK (
        block_id_encoded_length IS NULL
        OR block_id_encoded_length BETWEEN 4 AND 128
    ),
    CONSTRAINT workflow_artifacts_state CHECK (state IN ('pending', 'finalized')),
    CONSTRAINT workflow_artifacts_publication_shape CHECK (
        (
            state = 'pending'
            AND content_digest IS NULL
            AND content_size_bytes IS NULL
            AND manifest_object_key IS NULL
            AND manifest_digest IS NULL
            AND manifest_size_bytes IS NULL
            AND manifest_media_type IS NULL
            AND finalized_at_seconds IS NULL
        ) OR (
            state = 'finalized'
            AND octet_length(content_digest) = 32
            AND content_size_bytes >= 0
            AND octet_length(manifest_object_key) BETWEEN 1 AND 1024
            AND manifest_object_key !~ '[[:cntrl:]]'
            AND octet_length(manifest_digest) = 32
            AND manifest_size_bytes BETWEEN 1 AND 1048576
            AND octet_length(manifest_media_type) BETWEEN 3 AND 128
            AND manifest_media_type !~ '[[:space:][:cntrl:];]'
            AND finalized_at_seconds >= created_at_seconds
        )
    )
);

CREATE INDEX workflow_artifacts_job_attempt
    ON workflow_artifacts (job_id, attempt_id, fencing_token);

CREATE INDEX workflow_artifacts_expiry
    ON workflow_artifacts (expires_at_seconds, id)
    WHERE expires_at_seconds IS NOT NULL;

CREATE TABLE workflow_artifact_blocks (
    artifact_id BIGINT NOT NULL
        REFERENCES workflow_artifacts(id) ON DELETE CASCADE,
    block_id TEXT NOT NULL,
    object_key TEXT NOT NULL,
    digest BYTEA NOT NULL,
    size_bytes BIGINT NOT NULL,
    media_type TEXT NOT NULL,
    staged_at_seconds BIGINT NOT NULL,
    CONSTRAINT workflow_artifact_blocks_primary_key PRIMARY KEY (artifact_id, block_id),
    CONSTRAINT workflow_artifact_blocks_id_shape CHECK (
        octet_length(block_id) BETWEEN 4 AND 128
        AND block_id !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT workflow_artifact_blocks_key_shape CHECK (
        octet_length(object_key) BETWEEN 1 AND 1024
        AND object_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT workflow_artifact_blocks_digest CHECK (octet_length(digest) = 32),
    CONSTRAINT workflow_artifact_blocks_size CHECK (
        size_bytes BETWEEN 0 AND 4294967296
    ),
    CONSTRAINT workflow_artifact_blocks_media_type CHECK (
        octet_length(media_type) BETWEEN 3 AND 128
        AND media_type !~ '[[:space:][:cntrl:];]'
    )
);

CREATE TABLE workflow_artifact_block_commits (
    artifact_id BIGINT PRIMARY KEY
        REFERENCES workflow_artifacts(id) ON DELETE CASCADE,
    list_digest BYTEA NOT NULL,
    block_ids TEXT[] NOT NULL,
    size_bytes BIGINT NOT NULL,
    committed_at_seconds BIGINT NOT NULL,
    CONSTRAINT workflow_artifact_commits_digest CHECK (octet_length(list_digest) = 32),
    CONSTRAINT workflow_artifact_commits_count CHECK (
        cardinality(block_ids) BETWEEN 0 AND 100000
        AND array_position(block_ids, NULL) IS NULL
    ),
    CONSTRAINT workflow_artifact_commits_size CHECK (size_bytes >= 0)
);
