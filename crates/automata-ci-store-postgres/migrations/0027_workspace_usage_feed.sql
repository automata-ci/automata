CREATE TABLE workspace_usage_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    authority_id text NOT NULL,
    shard_id text NOT NULL,
    workspace_id text NOT NULL,
    attempt_id uuid NOT NULL,
    entitlement_revision bigint NOT NULL,
    interval_start_ms bigint NOT NULL,
    interval_end_ms bigint NOT NULL,
    consumed_compute_ms bigint NOT NULL,
    recorded_at_ms bigint NOT NULL,
    CONSTRAINT workspace_usage_events_binding
        FOREIGN KEY (workspace_id, authority_id, shard_id)
        REFERENCES workspace_management_bindings(workspace_id, authority_id, shard_id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_usage_events_entitlement_revision
        FOREIGN KEY (workspace_id, entitlement_revision)
        REFERENCES workspace_entitlement_operations(workspace_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_usage_events_ids_non_nil CHECK (
        event_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    CONSTRAINT workspace_usage_events_authority_shape CHECK (
        octet_length(authority_id) BETWEEN 1 AND 255
        AND authority_id !~ '[[:space:][:cntrl:]]'
    ),
    CONSTRAINT workspace_usage_events_shard_shape CHECK (
        octet_length(shard_id) BETWEEN 1 AND 63
        AND shard_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    ),
    CONSTRAINT workspace_usage_events_workspace_shape CHECK (
        workspace_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        AND workspace_id <> '00000000-0000-0000-0000-000000000000'
    ),
    CONSTRAINT workspace_usage_events_revision_positive CHECK (entitlement_revision > 0),
    CONSTRAINT workspace_usage_events_interval CHECK (
        interval_start_ms >= 0
        AND interval_end_ms > interval_start_ms
        AND interval_end_ms <= 253402300799999
    ),
    CONSTRAINT workspace_usage_events_compute_positive CHECK (consumed_compute_ms > 0),
    CONSTRAINT workspace_usage_events_recorded_after_interval CHECK (
        recorded_at_ms >= interval_end_ms
        AND recorded_at_ms <= 253402300799999
    ),
    CONSTRAINT workspace_usage_events_interval_unique UNIQUE (
        workspace_id,
        attempt_id,
        entitlement_revision,
        interval_start_ms,
        interval_end_ms
    )
);

CREATE INDEX workspace_usage_events_authority_feed_idx
    ON workspace_usage_events(authority_id, shard_id, sequence);
