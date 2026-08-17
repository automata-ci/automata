CREATE TABLE github_actions_cache_garbage (
    object_key text PRIMARY KEY,
    digest bytea NOT NULL,
    size_bytes bigint NOT NULL,
    media_type text NOT NULL,
    queued_at_seconds bigint NOT NULL,
    CONSTRAINT gha_cache_garbage_digest CHECK (octet_length(digest) = 32),
    CONSTRAINT gha_cache_garbage_key_shape CHECK (
        octet_length(object_key) BETWEEN 1 AND 1024
        AND object_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT gha_cache_garbage_media_type CHECK (
        octet_length(media_type) BETWEEN 3 AND 128
        AND media_type !~ '[[:space:][:cntrl:];]'
    ),
    CONSTRAINT gha_cache_garbage_size CHECK (
        size_bytes BETWEEN 0 AND 134217728
    ),
    CONSTRAINT gha_cache_garbage_time CHECK (queued_at_seconds >= 0)
);

CREATE INDEX gha_cache_garbage_order
    ON github_actions_cache_garbage (queued_at_seconds, object_key);
