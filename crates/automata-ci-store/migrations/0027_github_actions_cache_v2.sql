-- Current GitHub Actions CacheService v2 coordination. Cache entries are
-- repository/ref scoped and immutable after finalization. PostgreSQL is the
-- only lifecycle, matching, fencing, last-access, retention, and quota authority;
-- object-store listing never participates in state.

CREATE TABLE github_actions_cache_entries (
    id UUID PRIMARY KEY,
    protocol_entry_id BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    tenant_id TEXT NOT NULL,
    repository_id UUID NOT NULL,
    run_id UUID NOT NULL,
    job_id UUID NOT NULL,
    attempt_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL,
    cache_ref TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    cache_version TEXT NOT NULL,
    block_id_encoded_length INTEGER,
    state TEXT NOT NULL DEFAULT 'pending',
    content_digest BYTEA,
    content_size_bytes BIGINT,
    created_at_seconds BIGINT NOT NULL,
    finalized_at_seconds BIGINT,
    last_accessed_at_seconds BIGINT NOT NULL,
    CONSTRAINT gha_cache_exact_entry_unique
        UNIQUE (repository_id, cache_ref, cache_key, cache_version),
    CONSTRAINT gha_cache_tenant_repository
        FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE RESTRICT,
    CONSTRAINT gha_cache_repository_run
        FOREIGN KEY (repository_id, run_id)
        REFERENCES workflow_runs(repository_id, id) ON DELETE RESTRICT,
    CONSTRAINT gha_cache_run_job
        FOREIGN KEY (run_id, job_id)
        REFERENCES jobs(run_id, id) ON DELETE RESTRICT,
    CONSTRAINT gha_cache_job_attempt
        FOREIGN KEY (job_id, attempt_id)
        REFERENCES job_attempts(job_id, id) ON DELETE RESTRICT,
    CONSTRAINT gha_cache_fence_positive CHECK (fencing_token > 0),
    CONSTRAINT gha_cache_ref_shape CHECK (
        octet_length(cache_ref) BETWEEN 6 AND 1024
        AND cache_ref LIKE 'refs/%'
        AND cache_ref !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT gha_cache_key_shape CHECK (
        octet_length(cache_key) BETWEEN 1 AND 512
        AND cache_key !~ '[,[:cntrl:]]'
    ),
    CONSTRAINT gha_cache_version_shape CHECK (
        octet_length(cache_version) BETWEEN 1 AND 512
        AND cache_version !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT gha_cache_block_id_length CHECK (
        block_id_encoded_length IS NULL
        OR block_id_encoded_length BETWEEN 4 AND 128
    ),
    CONSTRAINT gha_cache_state CHECK (state IN ('pending', 'finalized')),
    CONSTRAINT gha_cache_times CHECK (
        created_at_seconds >= 0
        AND last_accessed_at_seconds >= created_at_seconds
        AND (
            finalized_at_seconds IS NULL
            OR finalized_at_seconds >= created_at_seconds
        )
    ),
    CONSTRAINT gha_cache_publication_shape CHECK ((
        state = 'pending'
        AND content_digest IS NULL
        AND content_size_bytes IS NULL
        AND finalized_at_seconds IS NULL
    ) OR (
        state = 'finalized'
        AND octet_length(content_digest) = 32
        AND content_size_bytes >= 0
        AND finalized_at_seconds IS NOT NULL
        AND last_accessed_at_seconds >= finalized_at_seconds
    ))
);

CREATE INDEX gha_cache_lookup
    ON github_actions_cache_entries (
        repository_id, cache_ref, cache_version,
        cache_key text_pattern_ops, finalized_at_seconds DESC, id
    )
    WHERE state = 'finalized';

CREATE INDEX gha_cache_retention
    ON github_actions_cache_entries (
        repository_id, state, last_accessed_at_seconds, finalized_at_seconds, id
    );

CREATE INDEX gha_cache_attempt
    ON github_actions_cache_entries (job_id, attempt_id, fencing_token);

CREATE TABLE github_actions_cache_blocks (
    entry_id UUID NOT NULL
        REFERENCES github_actions_cache_entries(id) ON DELETE CASCADE,
    block_id TEXT NOT NULL,
    object_key TEXT NOT NULL,
    digest BYTEA NOT NULL,
    size_bytes BIGINT NOT NULL,
    media_type TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'reserved',
    staged_at_seconds BIGINT NOT NULL,
    ready_at_seconds BIGINT,
    CONSTRAINT gha_cache_blocks_primary_key PRIMARY KEY (entry_id, block_id),
    CONSTRAINT gha_cache_blocks_id_shape CHECK (
        octet_length(block_id) BETWEEN 4 AND 128
        AND block_id !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT gha_cache_blocks_key_shape CHECK (
        octet_length(object_key) BETWEEN 1 AND 1024
        AND object_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT gha_cache_blocks_digest CHECK (octet_length(digest) = 32),
    CONSTRAINT gha_cache_blocks_size CHECK (
        size_bytes BETWEEN 0 AND 134217728
    ),
    CONSTRAINT gha_cache_blocks_media_type CHECK (
        octet_length(media_type) BETWEEN 3 AND 128
        AND media_type !~ '[[:space:][:cntrl:];]'
    ),
    CONSTRAINT gha_cache_blocks_state CHECK (state IN ('reserved', 'ready')),
    CONSTRAINT gha_cache_blocks_readiness CHECK ((
        state = 'reserved' AND ready_at_seconds IS NULL
    ) OR (
        state = 'ready' AND ready_at_seconds >= staged_at_seconds
    ))
);

CREATE TABLE github_actions_cache_block_commits (
    entry_id UUID PRIMARY KEY
        REFERENCES github_actions_cache_entries(id) ON DELETE CASCADE,
    list_digest BYTEA NOT NULL,
    block_ids TEXT[] NOT NULL,
    size_bytes BIGINT NOT NULL,
    committed_at_seconds BIGINT NOT NULL,
    CONSTRAINT gha_cache_commits_digest CHECK (octet_length(list_digest) = 32),
    CONSTRAINT gha_cache_commits_count CHECK (
        cardinality(block_ids) BETWEEN 0 AND 50000
        AND array_position(block_ids, NULL) IS NULL
    ),
    CONSTRAINT gha_cache_commits_size CHECK (
        size_bytes BETWEEN 0 AND 10737418240
    )
);
